"""The public client surface, sync and async.

Every operation is defined once in :mod:`hippius_drive._ops`; the two clients
differ only in whether they await the transport. Namespaces (``folders``,
``files``, ``summary``) group the endpoints the way a caller thinks about them.
"""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from tempfile import SpooledTemporaryFile
from types import TracebackType
from typing import IO, Any, TypeVar

import httpx
from pydantic import ValidationError

from hippius_drive import _ops, _session, _upload, errors, models
from hippius_drive._ops import Op
from hippius_drive._transport import (
    DEFAULT_TIMEOUT,
    PROBE_TIMEOUT,
    REGIONS,
    AsyncTransport,
    Transport,
    pick_region,
)
from hippius_drive._upload import UploadSpec
from hippius_drive._wire import parse_envelope
from hippius_drive.crypto import file_cipher, hashes
from hippius_drive.identity import Identity
from hippius_drive.models import (
    MAX_LISTING_PAGE_SIZE,
    BrowseOptions,
    RenameSpec,
    SearchFilters,
)

T = TypeVar("T")

DEFAULT_PAGE_SIZE = 100
"""Page size ``iter_state`` uses; large enough to keep round trips down."""


HTTP_ERROR_FLOOR = 400
"""Statuses at or above this carry a JSON error body, not ciphertext."""


def _headers_info(response: httpx.Response) -> models.DownloadInfo:
    """Read the metadata headers that ride along with a successful download."""
    try:
        return models.DownloadInfo(
            size_bytes=int(response.headers.get("X-Size-Bytes", 0)),
            revision_id=response.headers.get("X-Revision-Id"),
            revision_seq=int(response.headers.get("X-Revision-Seq", 0)),
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise errors.InvalidResponse(
            f"malformed download headers: {exc}", response.status_code
        ) from exc


def _open_private(path: Path) -> IO[bytes]:
    """Create ``path`` owner-only, matching the mnemonic store."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        return os.fdopen(fd, "wb")
    except BaseException:
        os.close(fd)
        raise


def _raise_download_error(status: int, body: bytes, content_type: str) -> None:
    """Turn an error body read off a download stream into the typed exception."""
    if content_type.startswith("application/json"):
        try:
            parsed: Any = json.loads(body)
        except ValueError:
            parsed = body.decode(errors="replace")
    else:
        parsed = body.decode(errors="replace")
    parse_envelope(status, parsed)


def _download_info(response: httpx.Response) -> models.DownloadInfo:
    """Return the download metadata, or raise the typed error the body carries.

    The error has to be handled before anything tries to decrypt: a 404's body
    is JSON, and feeding it to the frame decoder would report a corrupt file
    instead of a missing one.

    Args:
        response: An open streaming response.

    Returns:
        The size and revision the server reported.

    Raises:
        DriveError: For any error status.
    """
    if response.status_code >= HTTP_ERROR_FLOOR:
        response.read()
        _raise_download_error(
            response.status_code, response.content, response.headers.get("content-type", "")
        )
    return _headers_info(response)


async def _download_info_async(response: httpx.Response) -> models.DownloadInfo:
    """Async twin of :func:`_download_info`.

    Separate because reading an error body off an async response needs
    ``aread``; the sync ``read`` raises on an async stream, which would have
    turned every async 404 into an unrelated runtime error.

    Args:
        response: An open streaming response.

    Returns:
        The size and revision the server reported.

    Raises:
        DriveError: For any error status.
    """
    if response.status_code >= HTTP_ERROR_FLOOR:
        await response.aread()
        _raise_download_error(
            response.status_code, response.content, response.headers.get("content-type", "")
        )
    return _headers_info(response)


async def _spool_body(response: httpx.Response) -> IO[bytes]:
    """Drain an async streaming body into a spooled file, rewound for reading.

    The frame decoder is a plain generator and cannot await, so the body has
    to land somewhere the decoder can pull from synchronously. A spooled file
    keeps small downloads in memory and caps large ones at one temp file
    rather than one heap copy.
    """
    # Closed by the caller once the decode finishes.
    spool: IO[bytes] = SpooledTemporaryFile(max_size=_upload.SPOOL_MAX)  # noqa: SIM115
    try:
        async for chunk in response.aiter_bytes():
            spool.write(chunk)
    except BaseException:
        spool.close()
        raise
    spool.seek(0)
    return spool


def _rename_entry(identity: Identity, spec: RenameSpec) -> models.SingleRename:
    """Turn a caller's paths into the hashes and ciphertext the server wants."""
    old = hashes.normalize_relative_path(spec.old_relative_path)
    new = hashes.normalize_relative_path(spec.new_relative_path)
    return models.SingleRename(
        old_path_hash=hashes.path_hash(old),
        new_path_hash=hashes.path_hash(new),
        new_encrypted_path=file_cipher.encrypt_bytes(new.encode(), identity.encryption_key),
        new_file_name=new.rsplit("/", 1)[-1],
        new_relative_path=new,
        base_revision_id=spec.base_revision_id,
    )


class FolderOps:
    """Folder registry operations for one account."""

    def __init__(self, client: Client) -> None:
        """Bind to the client that runs the requests.

        Args:
            client: The owning client.
        """
        self._client = client

    def register(
        self, label: str | None = None, device_name: str | None = None
    ) -> models.RegisterFolderResult:
        """Declare a folder.

        The server upserts on ``(account, folder_hash)``, so a second device
        registering the same label is a 200, not a 409.

        Args:
            label: The folder to register; the client's own label when omitted.
            device_name: Which device registered it, for display.

        Returns:
            The result. Status is ``registered`` on success.
        """
        return self._client.run(_ops.register_folder(self._client.identity, label, device_name))

    def list(self) -> models.ListFoldersResult:
        """Enumerate every folder the account has registered."""
        return self._client.run(_ops.list_folders(self._client.identity))

    def unregister(self, label: str | None = None) -> models.UnregisterFolderResult:
        """Remove a folder and every file it owns. Irreversible.

        Args:
            label: The folder to remove; the client's own label when omitted.

        Returns:
            The result, including how many file rows went with it.
        """
        return self._client.run(_ops.unregister_folder(self._client.identity, label))

    def entries(self) -> models.ListFolderEntriesResult:
        """List the registered empty-directory paths for this folder."""
        return self._client.run(_ops.list_folder_entries(self._client.identity))


class SummaryOps:
    """Account-level storage summaries.

    Every byte count is plaintext. The server coalesces summary writes about
    once a second, so a read right after an upload can lag it: poll rather
    than asserting on a single read.
    """

    def __init__(self, client: Client) -> None:
        """Bind to the client that runs the requests.

        Args:
            client: The owning client.
        """
        self._client = client

    def user(self) -> models.UserSummaryResult:
        """Account totals, including S3-gateway uploads."""
        return self._client.run(_ops.user_summary(self._client.identity))

    def file_types(self) -> models.FileTypeSummary:
        """Per-type counts and bytes for HCFS-originated files."""
        return self._client.run(_ops.file_type_summary(self._client.identity))

    def sources(self) -> models.SourceSummary:
        """Per-client-family counts and bytes."""
        return self._client.run(_ops.source_summary(self._client.identity))


class FileOps:
    """File listing, search, transfer, and lifecycle for one folder."""

    def __init__(self, client: Client) -> None:
        """Bind to the client that runs the requests.

        Args:
            client: The owning client.
        """
        self._client = client

    def state(self, offset: int = 0, limit: int | None = None) -> models.GetStateResult:
        """Return one page of every file in the folder.

        Args:
            offset: Starting index into the ordered result set.
            limit: Results per page; the server default when omitted.

        Returns:
            The page.
        """
        return self._client.run(_ops.get_state(self._client.identity, offset, limit))

    def iter_state(self, page_size: int = DEFAULT_PAGE_SIZE) -> Iterator[models.RemoteFileEntry]:
        """Walk every file in the folder, paging until the server says stop.

        Pages on ``has_more`` rather than ``total_count``: the total is a
        maintained counter that can lag a just-completed write.

        Args:
            page_size: Files to request per round trip.

        Yields:
            Each file in the folder.
        """
        offset = 0
        while True:
            page = self.state(offset=offset, limit=page_size)
            yield from page.files
            if not page.has_more or not page.files:
                return
            offset += len(page.files)

    def browse(
        self,
        path: str = "",
        options: BrowseOptions | None = None,
        offset: int = 0,
        limit: int | None = None,
    ) -> models.BrowseResult:
        """List one directory level.

        Files with no ``relative_path`` (rows uploaded before the field
        existed) are invisible here but still appear in :meth:`state`.

        Args:
            path: Directory relative to the folder root; "" is the root.
            options: Sort and filter options; ``path`` here wins over theirs.
            offset: Starting index into the combined folders-then-files stream.
            limit: Results per page; the server defaults to 50 and caps it at
                200. Use :meth:`iter_browse` to list a whole directory.

        Returns:
            The page.
        """
        opts = _browse_options(path, options)
        return self._client.run(_ops.browse(self._client.identity, opts, offset, limit))

    def iter_browse(
        self,
        path: str = "",
        options: BrowseOptions | None = None,
        page_size: int = MAX_LISTING_PAGE_SIZE,
    ) -> Iterator[models.BrowseFolderEntry | models.RemoteFileEntry]:
        """Walk one directory level, paging until the server says stop.

        Pages on ``has_more`` rather than ``total_count``: the total is
        approximate. The offset advances by the entries a page returned, not
        by ``page_size``, because the server coerces a larger request down to
        its own cap and folders and files share one offset space.

        Args:
            path: Directory relative to the folder root; "" is the root.
            options: Sort and filter options; ``path`` here wins over theirs.
            page_size: Entries to request per round trip; the server caps it
                at 200.

        Yields:
            Each subfolder, then each file, in the server's order.
        """
        offset = 0
        while True:
            page = self.browse(path, options, offset=offset, limit=page_size)
            yield from page.folders
            yield from page.files

            returned = len(page.folders) + len(page.files)
            if not page.has_more or not returned:
                return
            offset += returned

    def search(
        self, filters: SearchFilters | None = None, offset: int = 0, limit: int | None = None
    ) -> models.SearchResult:
        """Search across every folder the account owns.

        Args:
            filters: The filter and sort set; every filter ANDs with the rest.
                A ``q`` shorter than 3 characters after trimming returns no
                hits by server policy: an empty page, not an error.
            offset: Starting index into the result set. For the next page,
                add the number of hits returned, not ``limit``.
            limit: Results per page; the server defaults to 25 and caps it
                at 200.

        Returns:
            The page.
        """
        return self._client.run(_ops.search(self._client.identity, filters, offset, limit))

    def file_id(self, relative_path: str) -> str:
        """Return the ``file_id`` for a relative path, without a round trip.

        The id is ``hex(BLAKE3(NFC path))``. The desktop client hashes raw OS
        bytes, so a macOS-created file with an accented name can carry an NFD
        id this will not reproduce; find those through :meth:`state` instead.

        Args:
            relative_path: Folder-relative POSIX path.

        Returns:
            The 64-char hex id.
        """
        return hashes.path_hash(relative_path).hex()

    def put(
        self,
        local_path: Path,
        relative_path: str,
        *,
        base_revision_id: bytes | None = None,
        revision_seq: int | None = None,
    ) -> models.UploadResult:
        """Encrypt and upload a local file.

        Routes by ciphertext size the way hcfs-client does: a blob that fits
        one 8 MiB transport chunk goes as a single multipart request, and
        anything larger goes through a chunked session.

        Args:
            local_path: The file to upload.
            relative_path: Where it lands in the folder.
            base_revision_id: The revision being replaced, or None for a new file.
            revision_seq: The current sequence plus one; required with a base.

        Returns:
            The upload result, carrying the new ``revision_id``.

        Raises:
            Conflict: If ``base_revision_id`` does not match the server.
            QuotaExceeded: If the write is over the account's allowance.
            ValueError: Before any request, if ``relative_path`` is not a
                clean POSIX relative path or the source changed size while
                it was being read.
        """
        spec = UploadSpec(relative_path, base_revision_id, revision_seq)
        return self._put(_upload.PlaintextSource.from_path(local_path), spec)

    def put_bytes(
        self,
        data: bytes,
        relative_path: str,
        *,
        base_revision_id: bytes | None = None,
        revision_seq: int | None = None,
    ) -> models.UploadResult:
        """Encrypt and upload an in-memory buffer.

        Args:
            data: The plaintext to upload.
            relative_path: Where it lands in the folder.
            base_revision_id: The revision being replaced, or None for a new file.
            revision_seq: The current sequence plus one; required with a base.

        Returns:
            The upload result.
        """
        spec = UploadSpec(relative_path, base_revision_id, revision_seq)
        return self._put(_upload.PlaintextSource.from_bytes(data), spec)

    def _put(self, source: _upload.PlaintextSource, spec: UploadSpec) -> models.UploadResult:
        client = self._client
        with _upload.prepare(client.identity, source, spec) as prepared:
            if prepared.transport_chunk_count() > 1:
                return _session.upload_via_session(client, prepared)
            return client.run(_ops.upload(prepared))

    def get(self, file_id: str, dest: Path) -> models.DownloadInfo:
        """Download and decrypt a file to ``dest``.

        Plaintext goes to a sibling ``.part`` file and is renamed into place
        only after the last frame authenticates, so a failed download never
        leaves a half-decrypted file where the real one should be.

        Args:
            file_id: 64-char hex ``path_hash``.
            dest: Where to write the plaintext.

        Returns:
            The size and revision the server reported.

        Raises:
            NotFound: If no file exists at that id.
            DecryptError: If any frame fails authentication.
        """
        part = dest.with_name(dest.name + ".part")
        dest.parent.mkdir(parents=True, exist_ok=True)
        key = self._client.identity.encryption_key
        with self._client.transport.stream(
            _ops.download(self._client.identity, file_id)
        ) as response:
            info = _download_info(response)
            try:
                with _open_private(part) as out:
                    reader = _upload.reader_over(response.iter_bytes())
                    for chunk in file_cipher.decrypt_stream(reader, key):
                        out.write(chunk)
            except BaseException:
                part.unlink(missing_ok=True)
                raise
        part.replace(dest)
        return info

    def get_bytes(self, file_id: str) -> bytes:
        """Download and decrypt a file into memory.

        Use :meth:`get` for anything large; this holds the whole plaintext.

        Args:
            file_id: 64-char hex ``path_hash``.

        Returns:
            The plaintext.
        """
        key = self._client.identity.encryption_key
        with self._client.transport.stream(
            _ops.download(self._client.identity, file_id)
        ) as response:
            _download_info(response)
            reader = _upload.reader_over(response.iter_bytes())
            return b"".join(file_cipher.decrypt_stream(reader, key))

    def delete(self, file_id: str) -> models.DeleteResult:
        """Remove one file. Immediate, with no undo.

        Args:
            file_id: 64-char hex ``path_hash``.

        Returns:
            The result.

        Raises:
            NotFound: If the file was already gone.
        """
        return self._client.run(_ops.delete_file(self._client.identity, file_id))

    def delete_many(self, file_ids: list[str], quiet: bool = False) -> models.BatchDeleteResult:
        """Remove up to 1000 files in one transaction.

        The server answers 200 even when individual ids fail, so inspect
        ``errors`` rather than trusting the status.

        Args:
            file_ids: Hex path hashes to remove.
            quiet: Omit successful entries from the response.

        Returns:
            The result.

        Raises:
            ValueError: If the batch exceeds the server cap of 1000.
        """
        return self._client.run(_ops.delete_files(self._client.identity, file_ids, quiet))

    def rename(self, renames: list[RenameSpec]) -> models.BatchRenameResult:
        """Re-key files without re-uploading ciphertext, under one signature.

        The server answers 200 even when individual entries fail, so inspect
        ``failures``.

        Args:
            renames: One spec per file to move.

        Returns:
            The result.

        Raises:
            ValueError: If the batch is empty or a path is invalid.
        """
        identity = self._client.identity
        entries = [_rename_entry(identity, spec) for spec in renames]
        return self._client.run(_ops.rename_files(identity, entries))


def _browse_options(path: str, options: BrowseOptions | None) -> BrowseOptions:
    """NFC-normalise the path that will actually be sent."""
    opts = options if options is not None else BrowseOptions()
    sent = path if path else opts.path
    if not sent:
        return opts
    sent = hashes.normalize_relative_path(sent)
    return BrowseOptions(
        path=sent,
        sort_by=opts.sort_by,
        sort_order=opts.sort_order,
        file_type=opts.file_type,
        uploaded_by=opts.uploaded_by,
    )


def _probe_timeout(timeout: float | httpx.Timeout) -> float:
    """Bound the region probe by a float client timeout, never above the default."""
    if isinstance(timeout, httpx.Timeout):
        return PROBE_TIMEOUT
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
        raise ValueError("timeout must be a positive number of seconds, or an httpx.Timeout")
    return min(PROBE_TIMEOUT, timeout)


class Client:
    """Synchronous Hippius Drive client scoped to one account and folder.

    Attributes:
        identity: The account address and folder keys in use.
        folders: Folder registry operations.
        files: File listing, search, transfer, and lifecycle.
        summary: Account-level storage summaries.
    """

    def __init__(
        self,
        *,
        token: str,
        identity: Identity,
        server_url: str | None = None,
        timeout: float | httpx.Timeout = DEFAULT_TIMEOUT,
        transport: Transport | None = None,
    ) -> None:
        """Build the client.

        Args:
            token: The bearer token the Hippius auth service issued. It must
                resolve to ``identity.account_ss58``.
            identity: The account address and folder keys.
            server_url: A specific server; otherwise the first healthy region
                in ``REGIONS`` order is probed once, here, rather than on
                every request.
            timeout: Per-phase budget in seconds, or a full ``httpx.Timeout``.
                A float also bounds the region probe, at most ``PROBE_TIMEOUT``.
            transport: A pre-built transport, mainly for tests.
        """
        self.identity = identity
        if transport is None:
            if not token or not token.strip():
                raise ValueError("token is required")
            if server_url is None:
                server_url = pick_region(timeout=_probe_timeout(timeout))
            transport = Transport(server_url, token, timeout)
        self._transport = transport
        self.folders = FolderOps(self)
        self.files = FileOps(self)
        self.summary = SummaryOps(self)

    @property
    def transport(self) -> Transport:
        """The transport this client sends through."""
        return self._transport

    @property
    def server_url(self) -> str:
        """The server this client is talking to."""
        return self._transport.base_url

    def run(self, op: Op[T]) -> T:
        """Send an operation and parse its result.

        Args:
            op: The operation to run.

        Returns:
            The parsed result.

        Raises:
            DriveError: For any error status or transport failure.
        """
        return op.parse(self._transport.call(op.request))

    def can_upload(self, size_bytes: int) -> models.CanUploadResult:
        """Ask whether a write of ``size_bytes`` plaintext would be allowed.

        Advisory only: the write endpoints charge just the growth over the row
        a manifest replaces, so a refusal here can still succeed on upload.

        Args:
            size_bytes: Plaintext bytes the caller intends to write.

        Returns:
            The verdict, with a reason when it is negative.
        """
        return self.run(_ops.can_upload(self.identity, size_bytes))

    def health(self) -> models.HealthResult:
        """Probe the server: liveness, build version, and capability list.

        Returns:
            What the server reported.
        """
        return self.run(_ops.health())

    def close(self) -> None:
        """Close the underlying connection pool."""
        self._transport.close()

    def __enter__(self) -> Client:
        """Return self so the client can be used as a context manager."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Close the connection pool on the way out."""
        self.close()


class AsyncFolderOps:
    """Folder registry operations for one account, async."""

    def __init__(self, client: AsyncClient) -> None:
        """Bind to the client that runs the requests.

        Args:
            client: The owning client.
        """
        self._client = client

    async def register(
        self, label: str | None = None, device_name: str | None = None
    ) -> models.RegisterFolderResult:
        """Declare a folder. The server upserts; a second device is also 200.

        Args:
            label: The folder to register; the client's own label when omitted.
            device_name: Which device registered it, for display.

        Returns:
            The result.
        """
        return await self._client.run(
            _ops.register_folder(self._client.identity, label, device_name)
        )

    async def list(self) -> models.ListFoldersResult:
        """Enumerate every folder the account has registered."""
        return await self._client.run(_ops.list_folders(self._client.identity))

    async def unregister(self, label: str | None = None) -> models.UnregisterFolderResult:
        """Remove a folder and every file it owns. Irreversible.

        Args:
            label: The folder to remove; the client's own label when omitted.

        Returns:
            The result.
        """
        return await self._client.run(_ops.unregister_folder(self._client.identity, label))

    async def entries(self) -> models.ListFolderEntriesResult:
        """List the registered empty-directory paths for this folder."""
        return await self._client.run(_ops.list_folder_entries(self._client.identity))


class AsyncSummaryOps:
    """Account-level storage summaries, async."""

    def __init__(self, client: AsyncClient) -> None:
        """Bind to the client that runs the requests.

        Args:
            client: The owning client.
        """
        self._client = client

    async def user(self) -> models.UserSummaryResult:
        """Account totals, including S3-gateway uploads."""
        return await self._client.run(_ops.user_summary(self._client.identity))

    async def file_types(self) -> models.FileTypeSummary:
        """Per-type counts and bytes for HCFS-originated files."""
        return await self._client.run(_ops.file_type_summary(self._client.identity))

    async def sources(self) -> models.SourceSummary:
        """Per-client-family counts and bytes."""
        return await self._client.run(_ops.source_summary(self._client.identity))


class AsyncFileOps:
    """File listing, search, transfer, and lifecycle for one folder, async."""

    def __init__(self, client: AsyncClient) -> None:
        """Bind to the client that runs the requests.

        Args:
            client: The owning client.
        """
        self._client = client

    async def state(self, offset: int = 0, limit: int | None = None) -> models.GetStateResult:
        """Return one page of every file in the folder.

        Args:
            offset: Starting index into the ordered result set.
            limit: Results per page.

        Returns:
            The page.
        """
        return await self._client.run(_ops.get_state(self._client.identity, offset, limit))

    async def iter_state(
        self, page_size: int = DEFAULT_PAGE_SIZE
    ) -> AsyncIterator[models.RemoteFileEntry]:
        """Walk every file in the folder, paging until the server says stop.

        Args:
            page_size: Files to request per round trip.

        Yields:
            Each file in the folder.
        """
        offset = 0
        while True:
            page = await self.state(offset=offset, limit=page_size)
            for entry in page.files:
                yield entry
            if not page.has_more or not page.files:
                return
            offset += len(page.files)

    async def browse(
        self,
        path: str = "",
        options: BrowseOptions | None = None,
        offset: int = 0,
        limit: int | None = None,
    ) -> models.BrowseResult:
        """List one directory level.

        Args:
            path: Directory relative to the folder root; "" is the root.
            options: Sort and filter options; ``path`` here wins over theirs.
            offset: Starting index into the combined stream.
            limit: Results per page; the server defaults to 50 and caps it at
                200. Use :meth:`iter_browse` to list a whole directory.

        Returns:
            The page.
        """
        opts = _browse_options(path, options)
        return await self._client.run(_ops.browse(self._client.identity, opts, offset, limit))

    async def iter_browse(
        self,
        path: str = "",
        options: BrowseOptions | None = None,
        page_size: int = MAX_LISTING_PAGE_SIZE,
    ) -> AsyncIterator[models.BrowseFolderEntry | models.RemoteFileEntry]:
        """Walk one directory level, paging until the server says stop.

        Args:
            path: Directory relative to the folder root; "" is the root.
            options: Sort and filter options; ``path`` here wins over theirs.
            page_size: Entries to request per round trip; the server caps it
                at 200.

        Yields:
            Each subfolder, then each file, in the server's order.
        """
        offset = 0
        while True:
            page = await self.browse(path, options, offset=offset, limit=page_size)
            for folder in page.folders:
                yield folder
            for entry in page.files:
                yield entry

            returned = len(page.folders) + len(page.files)
            if not page.has_more or not returned:
                return
            offset += returned

    async def search(
        self, filters: SearchFilters | None = None, offset: int = 0, limit: int | None = None
    ) -> models.SearchResult:
        """Search across every folder the account owns.

        Args:
            filters: The filter and sort set. A ``q`` shorter than 3
                characters after trimming returns no hits by server policy.
            offset: Starting index into the result set.
            limit: Results per page; the server defaults to 25 and caps it
                at 200.

        Returns:
            The page.
        """
        return await self._client.run(_ops.search(self._client.identity, filters, offset, limit))

    def file_id(self, relative_path: str) -> str:
        """Return the ``file_id`` for a relative path, without a round trip.

        Args:
            relative_path: Folder-relative POSIX path.

        Returns:
            The 64-char hex id.
        """
        return hashes.path_hash(relative_path).hex()

    async def put(
        self,
        local_path: Path,
        relative_path: str,
        *,
        base_revision_id: bytes | None = None,
        revision_seq: int | None = None,
    ) -> models.UploadResult:
        """Encrypt and upload a local file.

        Args:
            local_path: The file to upload.
            relative_path: Where it lands in the folder.
            base_revision_id: The revision being replaced, or None for a new file.
            revision_seq: The current sequence plus one; required with a base.

        Returns:
            The upload result.
        """
        spec = UploadSpec(relative_path, base_revision_id, revision_seq)
        return await self._put(_upload.PlaintextSource.from_path(local_path), spec)

    async def put_bytes(
        self,
        data: bytes,
        relative_path: str,
        *,
        base_revision_id: bytes | None = None,
        revision_seq: int | None = None,
    ) -> models.UploadResult:
        """Encrypt and upload an in-memory buffer.

        Args:
            data: The plaintext to upload.
            relative_path: Where it lands in the folder.
            base_revision_id: The revision being replaced, or None for a new file.
            revision_seq: The current sequence plus one; required with a base.

        Returns:
            The upload result.
        """
        spec = UploadSpec(relative_path, base_revision_id, revision_seq)
        return await self._put(_upload.PlaintextSource.from_bytes(data), spec)

    async def _put(self, source: _upload.PlaintextSource, spec: UploadSpec) -> models.UploadResult:
        client = self._client
        with _upload.prepare(client.identity, source, spec) as prepared:
            if prepared.transport_chunk_count() > 1:
                return await _session.upload_via_session_async(client, prepared)
            return await client.run(_ops.upload(prepared))

    async def get(self, file_id: str, dest: Path) -> models.DownloadInfo:
        """Download and decrypt a file to ``dest``.

        Args:
            file_id: 64-char hex ``path_hash``.
            dest: Where to write the plaintext.

        Returns:
            The size and revision the server reported.
        """
        part = dest.with_name(dest.name + ".part")
        dest.parent.mkdir(parents=True, exist_ok=True)
        key = self._client.identity.encryption_key
        async with self._client.transport.stream(
            _ops.download(self._client.identity, file_id)
        ) as response:
            info = await _download_info_async(response)
            spool = await _spool_body(response)
        try:
            with _open_private(part) as out:
                for chunk in file_cipher.decrypt_stream(spool, key):
                    out.write(chunk)
        except BaseException:
            part.unlink(missing_ok=True)
            raise
        finally:
            spool.close()
        part.replace(dest)
        return info

    async def get_bytes(self, file_id: str) -> bytes:
        """Download and decrypt a file into memory.

        Use :meth:`get` for anything large; this holds the whole plaintext.

        Args:
            file_id: 64-char hex ``path_hash``.

        Returns:
            The plaintext.
        """
        key = self._client.identity.encryption_key
        async with self._client.transport.stream(
            _ops.download(self._client.identity, file_id)
        ) as response:
            await _download_info_async(response)
            spool = await _spool_body(response)
        try:
            return b"".join(file_cipher.decrypt_stream(spool, key))
        finally:
            spool.close()

    async def delete(self, file_id: str) -> models.DeleteResult:
        """Remove one file. Immediate, with no undo.

        Args:
            file_id: 64-char hex ``path_hash``.

        Returns:
            The result.
        """
        return await self._client.run(_ops.delete_file(self._client.identity, file_id))

    async def delete_many(
        self, file_ids: list[str], quiet: bool = False
    ) -> models.BatchDeleteResult:
        """Remove up to 1000 files in one transaction.

        Args:
            file_ids: Hex path hashes to remove.
            quiet: Omit successful entries from the response.

        Returns:
            The result.
        """
        return await self._client.run(_ops.delete_files(self._client.identity, file_ids, quiet))

    async def rename(self, renames: list[RenameSpec]) -> models.BatchRenameResult:
        """Re-key files without re-uploading ciphertext, under one signature.

        Args:
            renames: One spec per file to move.

        Returns:
            The result.
        """
        identity = self._client.identity
        entries = [_rename_entry(identity, spec) for spec in renames]
        return await self._client.run(_ops.rename_files(identity, entries))


class AsyncClient:
    """Asynchronous Hippius Drive client; same surface as :class:`Client`.

    Attributes:
        identity: The account address and folder keys in use.
        folders: Folder registry operations.
        files: File listing, search, transfer, and lifecycle.
        summary: Account-level storage summaries.
    """

    def __init__(
        self,
        *,
        token: str,
        identity: Identity,
        server_url: str | None = None,
        timeout: float | httpx.Timeout = DEFAULT_TIMEOUT,
        transport: AsyncTransport | None = None,
    ) -> None:
        """Build the client.

        Unlike :class:`Client`, a region is not probed in the constructor,
        because that would need a running event loop. Pass ``server_url``, or
        ``server_url=await pick_region_async()`` from
        :mod:`hippius_drive._transport` (it returns a URL, not a transport).

        Args:
            token: The bearer token the Hippius auth service issued.
            identity: The account address and folder keys.
            server_url: The server to talk to; the first region by default.
            timeout: Connect/read/pool budget in seconds, or a full
                ``httpx.Timeout``. A float leaves the write side uncapped,
                because anyio applies it to the whole request body.
            transport: A pre-built transport, mainly for tests.
        """
        self.identity = identity
        self._transport = transport or AsyncTransport(
            server_url if server_url is not None else REGIONS[0], token, timeout
        )
        self.folders = AsyncFolderOps(self)
        self.files = AsyncFileOps(self)
        self.summary = AsyncSummaryOps(self)

    @property
    def transport(self) -> AsyncTransport:
        """The transport this client sends through."""
        return self._transport

    @property
    def server_url(self) -> str:
        """The server this client is talking to."""
        return self._transport.base_url

    async def run(self, op: Op[T]) -> T:
        """Send an operation and parse its result.

        Args:
            op: The operation to run.

        Returns:
            The parsed result.

        Raises:
            DriveError: For any error status or transport failure.
        """
        return op.parse(await self._transport.call(op.request))

    async def can_upload(self, size_bytes: int) -> models.CanUploadResult:
        """Ask whether a write of ``size_bytes`` plaintext would be allowed.

        Advisory only: the write endpoints charge just the growth over the row
        a manifest replaces, so a refusal here can still succeed on upload.

        Args:
            size_bytes: Plaintext bytes the caller intends to write.

        Returns:
            The verdict, with a reason when it is negative.
        """
        return await self.run(_ops.can_upload(self.identity, size_bytes))

    async def health(self) -> models.HealthResult:
        """Probe the server: liveness, build version, and capability list.

        Returns:
            What the server reported.
        """
        return await self.run(_ops.health())

    async def aclose(self) -> None:
        """Close the underlying connection pool."""
        await self._transport.aclose()

    async def __aenter__(self) -> AsyncClient:
        """Return self so the client can be used as an async context manager."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Close the connection pool on the way out."""
        await self.aclose()
