"""Sans-I/O wire layer: envelope parsing and request building, no sockets.

Keeping this pure is what lets the sync and async clients share one
implementation and lets the tests pin request shapes without a server.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import IO, Any
from urllib.parse import quote

from hippius_drive import errors
from hippius_drive.models import BrowseOptions, SearchFilters

BAD_REQUEST = 400
PAYMENT_REQUIRED = 402
CONFLICT = 409
TOO_MANY_REQUESTS = 429
INTERNAL_SERVER_ERROR = 500

_STATUS_ERRORS: dict[int, type[errors.DriveError]] = {
    400: errors.InvalidRequest,
    401: errors.Unauthorized,
    403: errors.Forbidden,
    404: errors.NotFound,
    409: errors.Conflict,
    413: errors.PayloadTooLarge,
    429: errors.RateLimited,
}


def _int_list_to_bytes(value: object) -> bytes | None:
    """Convert a JSON array of ints to bytes; hcfs sends byte fields that way."""
    if not isinstance(value, list):
        return None
    try:
        return bytes(value)
    except (TypeError, ValueError):
        return None


def _optional_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _raise_conflict(fields: dict[str, Any], status: int) -> None:
    raise errors.Conflict(
        str(fields.get("error", "conflict")),
        str(fields.get("message", "")),
        status,
        current_revision_id=_int_list_to_bytes(fields.get("current_revision_id")),
        current_revision_seq=_optional_int(fields.get("current_revision_seq")),
    )


def _raise_for(status: int, fields: dict[str, Any], retry_after: int | None) -> None:
    """Raise the exception that matches ``status``, carrying the server's fields."""
    code = str(fields.get("error", "unknown"))
    message = str(fields.get("message", ""))

    if status == PAYMENT_REQUIRED:
        raise errors.QuotaExceeded(
            code,
            message,
            status,
            balance_cents=_optional_int(fields.get("balance_cents")),
            required_cents=_optional_int(fields.get("required_cents")),
        )
    if status == CONFLICT:
        _raise_conflict(fields, status)
    if status == TOO_MANY_REQUESTS:
        raise errors.RateLimited(code, message, status, retry_after=retry_after)

    fallback = errors.ServerError if status >= INTERNAL_SERVER_ERROR else errors.DriveError
    raise _STATUS_ERRORS.get(status, fallback)(code, message, status)


def parse_envelope(status: int, body: Any, *, retry_after: int | None = None) -> Any:
    """Unwrap a ``NetworkResponse`` body, or raise the matching typed error.

    Handles all three envelope variants plus the endpoints that answer with a
    flat body instead: ``/can_upload``, ``/list_folder_entries``, and the 402
    and some 403 error bodies.

    Args:
        status: The HTTP status code.
        body: The parsed JSON body, or any object if it did not parse.
        retry_after: Seconds from a ``Retry-After`` header, when present.

    Returns:
        The ``Success`` payload, or the flat body for unenveloped endpoints.

    Raises:
        DriveError: The subclass matching the status and envelope variant.
    """
    if isinstance(body, dict):
        if "Success" in body:
            if status >= BAD_REQUEST:
                raise errors.InvalidResponse(f"Success envelope with HTTP {status}", status)
            return body["Success"]
        if "Conflict" in body:
            conflict = body["Conflict"]
            _raise_conflict(conflict if isinstance(conflict, dict) else {}, status)
        if "Error" in body:
            error = body["Error"]
            _raise_for(status, error if isinstance(error, dict) else {}, retry_after)

    if status < BAD_REQUEST:
        if isinstance(body, dict):
            return body
        raise errors.InvalidResponse(f"expected a JSON object, got {type(body).__name__}", status)

    _raise_for(status, body if isinstance(body, dict) else {}, retry_after)
    raise AssertionError("unreachable: _raise_for always raises")  # pragma: no cover


MultipartField = tuple[str, tuple[str | None, bytes | IO[bytes], str]]
"""An httpx multipart entry: ``(name, (filename, content, content_type))``."""


@dataclass(frozen=True)
class Request:
    """One HTTP call, fully described and not yet made.

    Attributes:
        method: The HTTP verb.
        path: Server-relative path, already percent-encoded.
        params: Query string; ``None`` values are dropped by the builders.
        json: A JSON body.
        content: A raw body. ``b""`` is meaningful: it makes httpx emit
            ``Content-Length: 0``, which the arion ingress requires on finalize.
        files: Multipart fields, in the order the server must see them.
        headers: Extra headers beyond auth, which the transport adds.
        replayable: Override the transport retry heuristic. ``False`` for
            finalize: hcfs-client does not retry it, and a 502 after commit
            must not POST again. ``None`` uses body shape (JSON/bytes yes,
            streamed or file-handle bodies no).
    """

    method: str
    path: str
    params: dict[str, str | int] | None = None
    json: dict[str, Any] | None = None
    content: bytes | Iterable[bytes] | None = None
    files: list[MultipartField] | None = None
    headers: dict[str, str] | None = None
    replayable: bool | None = None


def _segment(value: str) -> str:
    """Percent-encode one path segment so a value can never smuggle a slash."""
    return quote(value, safe="")


def _params(**values: Any) -> dict[str, str | int]:
    """Drop unset query parameters; the server treats absent and empty alike."""
    return {key: value for key, value in values.items() if value is not None}


def _file_type(value: list[str] | str | None) -> str | None:
    """Join a file-type list into the comma-separated form the server parses."""
    if value is None or isinstance(value, str):
        return value
    return ",".join(value)


class RequestBuilders:
    """One builder per endpoint in the v1 scope. Pure: no I/O, no client state."""

    @staticmethod
    def health() -> Request:
        """Build ``GET /health``. Unauthenticated liveness and version probe."""
        return Request("GET", "/health")

    @staticmethod
    def can_upload(ss58: str, folder_hash: str, size_bytes: int) -> Request:
        """Build ``POST /can_upload``.

        Args:
            ss58: The account address.
            folder_hash: The target folder, or "" for the S3 rail.
            size_bytes: Plaintext bytes the caller intends to write.

        Returns:
            The request.
        """
        return Request(
            "POST",
            "/can_upload",
            json={"ss58_address": ss58, "folder_hash": folder_hash, "size_bytes": size_bytes},
        )

    @staticmethod
    def register_folder(
        ss58: str, folder_hash: str, label: str, device_name: str | None = None
    ) -> Request:
        """Build ``POST /register_folder``.

        Args:
            ss58: The account address.
            folder_hash: ``hex(SHA-256(label))[:16]``, computed by the client.
            label: The human-readable folder name.
            device_name: Which device registered it, for display.

        Returns:
            The request.
        """
        return Request(
            "POST",
            "/register_folder",
            json={
                "ss58_address": ss58,
                "folder_hash": folder_hash,
                "label": label,
                "device_name": device_name,
            },
        )

    @staticmethod
    def list_folders(ss58: str) -> Request:
        """Build ``GET /list_folders/{base_address}``.

        Args:
            ss58: The account address.

        Returns:
            The request.
        """
        return Request("GET", f"/list_folders/{_segment(ss58)}")

    @staticmethod
    def unregister_folder(ss58: str, folder_hash: str) -> Request:
        """Build ``DELETE /unregister_folder``. Destructive: takes every file with it.

        Args:
            ss58: The account address.
            folder_hash: The folder to remove.

        Returns:
            The request.
        """
        return Request(
            "DELETE",
            "/unregister_folder",
            json={"ss58_address": ss58, "folder_hash": folder_hash},
        )

    @staticmethod
    def list_folder_entries(ss58: str, folder_hash: str) -> Request:
        """Build ``GET /list_folder_entries/{ss58}/{folder_hash}``.

        Args:
            ss58: The account address.
            folder_hash: The folder to list directory rows for.

        Returns:
            The request.
        """
        return Request("GET", f"/list_folder_entries/{_segment(ss58)}/{_segment(folder_hash)}")

    @staticmethod
    def get_state(
        ss58: str, folder_hash: str, offset: int = 0, limit: int | None = None
    ) -> Request:
        """Build ``GET /get_state/{ss58}/{folder_hash}``.

        Args:
            ss58: The account address.
            folder_hash: The folder to list.
            offset: Starting index into the ordered result set.
            limit: Results per page; the server default when omitted.

        Returns:
            The request.
        """
        return Request(
            "GET",
            f"/get_state/{_segment(ss58)}/{_segment(folder_hash)}",
            params=_params(offset=offset, limit=limit),
        )

    @staticmethod
    def browse(
        ss58: str,
        folder_hash: str,
        options: BrowseOptions | None = None,
        offset: int = 0,
        limit: int | None = None,
    ) -> Request:
        """Build ``GET /browse/{ss58}/{folder_hash}``.

        Args:
            ss58: The account address.
            folder_hash: The folder to browse.
            options: Path, sort, and filter options.
            offset: Starting index into the combined folders-then-files stream.
            limit: Results per page.

        Returns:
            The request.
        """
        opts = options if options is not None else BrowseOptions()
        return Request(
            "GET",
            f"/browse/{_segment(ss58)}/{_segment(folder_hash)}",
            params=_params(
                path=opts.path,
                offset=offset,
                limit=limit,
                sort_by=opts.sort_by,
                sort_order=opts.sort_order,
                file_type=_file_type(opts.file_type),
                uploaded_by=opts.uploaded_by,
            ),
        )

    @staticmethod
    def search_files(
        ss58: str,
        filters: SearchFilters | None = None,
        offset: int = 0,
        limit: int | None = None,
    ) -> Request:
        """Build ``GET /search_files/{ss58}``.

        Args:
            ss58: The account address.
            filters: The filter and sort set; all-AND.
            offset: Starting index into the result set.
            limit: Results per page; the server defaults to 25.

        Returns:
            The request.
        """
        f = filters if filters is not None else SearchFilters()
        return Request(
            "GET",
            f"/search_files/{_segment(ss58)}",
            params=_params(
                q=f.q,
                file_type=_file_type(f.file_type),
                size_min=f.size_min,
                size_max=f.size_max,
                date_from=f.date_from,
                date_to=f.date_to,
                uploaded_by=f.uploaded_by,
                sort_by=f.sort_by,
                sort_order=f.sort_order,
                offset=offset,
                limit=limit,
            ),
        )

    @staticmethod
    def get_user_summary(ss58: str) -> Request:
        """Build ``GET /get_user_summary/{ss58}``.

        Args:
            ss58: The account address.

        Returns:
            The request.
        """
        return Request("GET", f"/get_user_summary/{_segment(ss58)}")

    @staticmethod
    def get_file_type_summary(ss58: str) -> Request:
        """Build ``GET /get_file_type_summary/{ss58}``.

        Args:
            ss58: The account address.

        Returns:
            The request.
        """
        return Request("GET", f"/get_file_type_summary/{_segment(ss58)}")

    @staticmethod
    def get_source_summary(ss58: str) -> Request:
        """Build ``GET /get_source_summary/{ss58}``.

        Args:
            ss58: The account address.

        Returns:
            The request.
        """
        return Request("GET", f"/get_source_summary/{_segment(ss58)}")

    @staticmethod
    def upload(manifest_json: bytes, ciphertext: bytes | IO[bytes]) -> Request:
        """Build the multipart ``POST /upload``.

        The ``manifest`` field must come first: the server peeks the first field
        name to pick a handler, and a reordered body is rejected.

        Args:
            manifest_json: The serialised manifest.
            ciphertext: The blob, in memory or as a readable file.

        Returns:
            The request.
        """
        return Request(
            "POST",
            "/upload",
            files=[
                ("manifest", (None, manifest_json, "application/json")),
                ("ciphertext", (None, ciphertext, "application/octet-stream")),
            ],
        )

    @staticmethod
    def download(ss58: str, folder_hash: str, file_id: str) -> Request:
        """Build ``GET /download/{ss58}/{folder_hash}/{file_id}``.

        Args:
            ss58: The account address.
            folder_hash: The folder the file lives in.
            file_id: 64-char hex ``path_hash``.

        Returns:
            The request.
        """
        return Request(
            "GET",
            f"/download/{_segment(ss58)}/{_segment(folder_hash)}/{_segment(file_id)}",
        )

    @staticmethod
    def delete(ss58: str, folder_hash: str, file_id: str) -> Request:
        """Build ``DELETE /delete/{ss58}/{folder_hash}/{file_id}``.

        Args:
            ss58: The account address.
            folder_hash: The folder the file lives in.
            file_id: 64-char hex ``path_hash``.

        Returns:
            The request.
        """
        return Request(
            "DELETE",
            f"/delete/{_segment(ss58)}/{_segment(folder_hash)}/{_segment(file_id)}",
        )

    @staticmethod
    def delete_files(
        ss58: str, folder_hash: str, file_ids: list[str], quiet: bool = False
    ) -> Request:
        """Build ``POST /delete_files``. Returns 200 even on partial failure.

        Args:
            ss58: The account address.
            folder_hash: The folder the files live in.
            file_ids: Up to 1000 hex path hashes.
            quiet: Omit successful entries and return only errors.

        Returns:
            The request.
        """
        return Request(
            "POST",
            "/delete_files",
            json={
                "ss58_address": ss58,
                "folder_hash": folder_hash,
                "file_ids": file_ids,
                "quiet": quiet,
            },
        )

    @staticmethod
    def rename_files(
        ss58: str,
        folder_hash: str,
        renames: list[dict[str, Any]],
        signature: bytes,
        signing_key: bytes,
    ) -> Request:
        """Build ``POST /rename_files``.

        Args:
            ss58: The account address.
            folder_hash: The folder whose files are moving.
            renames: Serialised ``SingleRename`` entries, already sorted by
                ``old_path_hash`` to match what the signature covers.
            signature: Ed25519 over the rename declaration.
            signing_key: The verifying key.

        Returns:
            The request.
        """
        return Request(
            "POST",
            "/rename_files",
            json={
                "ss58_address": ss58,
                "folder_hash": folder_hash,
                "renames": renames,
                "signature": list(signature),
                "signing_key": list(signing_key),
            },
        )

    @staticmethod
    def create_session(
        manifest: dict[str, Any], chunk_count: int, chunk_size: int, ciphertext_size: int
    ) -> Request:
        """Build ``POST /upload/session``.

        Args:
            manifest: The full signed manifest, as JSON-ready fields.
            chunk_count: How many transport chunks the client will send.
            chunk_size: Bytes per chunk; the last one may be shorter.
            ciphertext_size: Total blob size, framing included.

        Returns:
            The request.
        """
        return Request(
            "POST",
            "/upload/session",
            json={
                "manifest": manifest,
                "chunk_count": chunk_count,
                "chunk_size": chunk_size,
                "ciphertext_size": ciphertext_size,
            },
        )

    @staticmethod
    def upload_chunk(session_id: str, index: int, data: bytes) -> Request:
        """Build ``PUT /upload/session/{id}/chunk/{index}``. Idempotent per index.

        Args:
            session_id: The session to write into.
            index: Zero-based chunk index, below the session's ``chunk_count``.
            data: The raw chunk bytes.

        Returns:
            The request.
        """
        return Request(
            "PUT",
            f"/upload/session/{_segment(session_id)}/chunk/{index}",
            content=data,
            headers={"Content-Type": "application/octet-stream"},
        )

    @staticmethod
    def session_status(session_id: str) -> Request:
        """Build ``GET /upload/session/{id}/status``.

        Args:
            session_id: The session to inspect.

        Returns:
            The request.
        """
        return Request("GET", f"/upload/session/{_segment(session_id)}/status")

    @staticmethod
    def finalize_session(session_id: str) -> Request:
        """Build ``POST /upload/session/{id}/finalize``.

        The body is explicitly empty rather than absent: the proxy in front of
        the service rejects a POST with no ``Content-Length`` before it reaches
        hcfs-server, which once broke every upload at the finalize step.

        Args:
            session_id: The session to commit.

        Returns:
            The request.
        """
        return Request(
            "POST",
            f"/upload/session/{_segment(session_id)}/finalize",
            content=b"",
            replayable=False,
        )

    @staticmethod
    def delete_session(session_id: str) -> Request:
        """Build ``DELETE /upload/session/{id}``. Safe at any point; idempotent.

        Args:
            session_id: The session to abort.

        Returns:
            The request.
        """
        return Request("DELETE", f"/upload/session/{_segment(session_id)}")


build = RequestBuilders()
"""The request builders, as a namespace: ``build.get_state(...)``."""
