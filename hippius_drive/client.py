"""The public client surface, sync and async.

Every operation is defined once in :mod:`hippius_drive._ops`; the two clients
differ only in whether they await the transport. Namespaces (``folders``,
``files``, ``summary``) group the endpoints the way a caller thinks about them.
"""

from __future__ import annotations

from collections.abc import Iterator
from types import TracebackType
from typing import Any, TypeVar

from hippius_drive import _ops, errors, models
from hippius_drive._ops import Op
from hippius_drive._transport import (
    DEFAULT_TIMEOUT,
    REGIONS,
    AsyncTransport,
    Transport,
    pick_region,
)
from hippius_drive.identity import Identity
from hippius_drive.models import BrowseOptions, SearchFilters

T = TypeVar("T")

DEFAULT_PAGE_SIZE = 100
"""Page size ``iter_state`` uses; large enough to keep round trips down."""


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
        """Declare a folder, treating "already registered" as success.

        ``folder_hash`` is deterministic from the label, so two devices can
        register the same folder without coordinating; the second one gets a
        409 that means "it exists", which is what the caller wanted.

        Args:
            label: The folder to register; the client's own label when omitted.
            device_name: Which device registered it, for display.

        Returns:
            The result, with status ``already_registered`` when a 409 was
            absorbed.
        """
        try:
            return self._client.run(_ops.register_folder(self._client.identity, label, device_name))
        except errors.Conflict:
            return models.RegisterFolderResult(status="already_registered")

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
            limit: Results per page.

        Returns:
            The page.
        """
        opts = options if options is not None else BrowseOptions()
        if path:
            opts = BrowseOptions(
                path=path,
                sort_by=opts.sort_by,
                sort_order=opts.sort_order,
                file_type=opts.file_type,
                uploaded_by=opts.uploaded_by,
            )
        return self._client.run(_ops.browse(self._client.identity, opts, offset, limit))

    def search(
        self, filters: SearchFilters | None = None, offset: int = 0, limit: int | None = None
    ) -> models.SearchResult:
        """Search across every folder the account owns.

        Args:
            filters: The filter and sort set; every filter ANDs with the rest.
            offset: Starting index into the result set.
            limit: Results per page; the server defaults to 25.

        Returns:
            The page.
        """
        return self._client.run(_ops.search(self._client.identity, filters, offset, limit))


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
        timeout: float = DEFAULT_TIMEOUT,
        transport: Transport | None = None,
    ) -> None:
        """Build the client.

        Args:
            token: The bearer token the Hippius auth service issued. It must
                resolve to ``identity.account_ss58``.
            identity: The account address and folder keys.
            server_url: A specific server; otherwise the fastest healthy region
                is probed once, here, rather than on every request.
            timeout: Per-request timeout in seconds.
            transport: A pre-built transport, mainly for tests.
        """
        self.identity = identity
        self._transport = transport or Transport(
            server_url if server_url is not None else pick_region(), token, timeout
        )
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
        """Declare a folder, treating "already registered" as success.

        Args:
            label: The folder to register; the client's own label when omitted.
            device_name: Which device registered it, for display.

        Returns:
            The result.
        """
        try:
            return await self._client.run(
                _ops.register_folder(self._client.identity, label, device_name)
            )
        except errors.Conflict:
            return models.RegisterFolderResult(status="already_registered")

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

    async def iter_state(self, page_size: int = DEFAULT_PAGE_SIZE) -> Any:
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
            limit: Results per page.

        Returns:
            The page.
        """
        opts = options if options is not None else BrowseOptions()
        if path:
            opts = BrowseOptions(
                path=path,
                sort_by=opts.sort_by,
                sort_order=opts.sort_order,
                file_type=opts.file_type,
                uploaded_by=opts.uploaded_by,
            )
        return await self._client.run(_ops.browse(self._client.identity, opts, offset, limit))

    async def search(
        self, filters: SearchFilters | None = None, offset: int = 0, limit: int | None = None
    ) -> models.SearchResult:
        """Search across every folder the account owns.

        Args:
            filters: The filter and sort set.
            offset: Starting index into the result set.
            limit: Results per page.

        Returns:
            The page.
        """
        return await self._client.run(_ops.search(self._client.identity, filters, offset, limit))


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
        timeout: float = DEFAULT_TIMEOUT,
        transport: AsyncTransport | None = None,
    ) -> None:
        """Build the client.

        Unlike :class:`Client`, a region is not probed in the constructor,
        because that would need a running event loop. Pass ``server_url``, or
        build the transport yourself after awaiting ``pick_region_async``.

        Args:
            token: The bearer token the Hippius auth service issued.
            identity: The account address and folder keys.
            server_url: The server to talk to; the first region by default.
            timeout: Per-request timeout in seconds.
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

        Args:
            size_bytes: Plaintext bytes the caller intends to write.

        Returns:
            The verdict.
        """
        return await self.run(_ops.can_upload(self.identity, size_bytes))

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
