"""Pydantic models mirroring the hcfs-shared network types.

Byte fields cross the wire as JSON arrays of integers (serde's default for
``[u8; N]``), so :data:`Bytes` validates from a list and serialises back to
one. ``model_dump(mode="json")`` therefore produces exactly what the server
reads, and Python code still sees ``bytes``.

Models are ``extra="ignore"``: the server adds fields (``member_count``,
``uploaded_by``) without a version bump, and an SDK that refused them would
break on a deploy it had nothing to do with.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, ConfigDict, PlainSerializer


def _to_bytes(value: Any) -> Any:
    """Accept a JSON int array, hex string, or bytes for a byte field."""
    if isinstance(value, list):
        return bytes(value)
    if isinstance(value, str):
        return bytes.fromhex(value)
    return value


Bytes = Annotated[
    bytes,
    BeforeValidator(_to_bytes),
    PlainSerializer(list, return_type=list, when_used="json"),
]
"""A byte field that round-trips through the JSON int-array wire form."""


MAX_LISTING_PAGE_SIZE = 200
"""Largest ``limit`` ``/browse`` and ``/search_files`` honour.

The server coerces anything larger down to this rather than rejecting it, so
a walk must advance by the rows a page actually returned, never by the limit
it asked for. ``/get_state`` is a separate, larger cap (5000).
"""

MIN_SEARCH_QUERY_LENGTH = 3
"""Shortest ``q``, after trimming, that ``/search_files`` will match on.

A shorter term is not an error: the server answers 200 with an empty page.
"""


class _Wire(BaseModel):
    """Base for every wire model: tolerate unknown fields, keep byte semantics."""

    model_config = ConfigDict(extra="ignore")


@dataclass(frozen=True)
class BrowseOptions:
    """Non-paging options for ``/browse``.

    Grouped rather than spread across the call so both the request builder and
    the client method stay within the argument budget, and so a caller can
    build one options object and page it.

    Attributes:
        path: Directory relative to the folder root; "" is the root.
        sort_by: ``file_name``, ``size_bytes``, ``created_at``, ``updated_at``,
            ``extension``, or ``uploaded_by``. Reorders files only.
        sort_order: ``asc`` or ``desc``; consulted only when ``sort_by`` is set.
        file_type: Categories and explicit extensions; a file matches any of
            them. Setting it empties ``folders``.
        uploaded_by: Exact uploader match. Setting it empties ``folders``.
    """

    path: str = ""
    sort_by: str | None = None
    sort_order: str | None = None
    file_type: list[str] | str | None = None
    uploaded_by: str | None = None


@dataclass(frozen=True)
class RenameSpec:
    """One move, in the terms a caller has: paths, not hashes.

    The client turns this into a :class:`SingleRename` by hashing both paths
    and re-encrypting the new one.

    Attributes:
        old_relative_path: Where the file is now.
        new_relative_path: Where it should be. Must not already exist.
        base_revision_id: The revision the caller believes is current; read it
            from ``files.state()``. Checked per entry, so one stale entry does
            not fail the rest of the batch.
    """

    old_relative_path: str
    new_relative_path: str
    base_revision_id: bytes


@dataclass(frozen=True)
class SearchFilters:
    """Filters for ``/search_files``. Every filter that is set ANDs with the rest.

    Attributes:
        q: Case-insensitive substring of the name or path; max 256 chars.
            A term shorter than :data:`MIN_SEARCH_QUERY_LENGTH` characters
            after trimming matches nothing: the server returns an empty page
            rather than an error.
        file_type: Categories and explicit extensions; a file matches any.
        size_min: Inclusive lower bound on plaintext size.
        size_max: Inclusive upper bound on plaintext size.
        date_from: Inclusive lower bound on ``created_at``, Unix seconds.
        date_to: Inclusive upper bound on ``created_at``, Unix seconds.
        uploaded_by: Exact uploader match.
        sort_by: ``file_name``, ``size_bytes``, ``created_at``, ``updated_at``,
            or ``uploaded_by``.
        sort_order: ``asc`` or ``desc``.
    """

    q: str | None = None
    file_type: list[str] | str | None = None
    size_min: int | None = None
    size_max: int | None = None
    date_from: int | None = None
    date_to: int | None = None
    uploaded_by: str | None = None
    sort_by: str | None = None
    sort_order: str | None = None


class Manifest(_Wire):
    """The signed metadata envelope that accompanies every upload.

    ``size_bytes`` is the **plaintext** size: it is what the quota gate charges
    and what the summaries report. The signature covers only the ToS text built
    from ``ciphertext_hash``, not the rest of these fields.

    Attributes:
        ss58_address: The account namespace; must match the token's identity.
        folder_hash: ``hex(SHA-256(label))[:16]``.
        ciphertext_hash: Hex BLAKE3 of the whole blob.
        size_bytes: Plaintext size.
        timestamp: Client-supplied Unix seconds.
        signature: Ed25519 over the ToS declaration.
        signing_key: Ed25519 verifying key.
        path_hash: ``BLAKE3(relative_path)``.
        salted_hash: ``BLAKE3(ss58_address || plaintext)``.
        revision_seq: Strictly greater than the row's current value; 1 is new.
        base_revision_id: The revision this write replaces, or None for new.
        encrypted_path: The relative path under the same framed format.
        file_name: Plaintext file name, for download progress UI.
        relative_path: Plaintext relative path, which enables browse and search.
        source: Free-text client family; unknown values land in "other".
    """

    ss58_address: str
    folder_hash: str
    ciphertext_hash: str
    size_bytes: int
    timestamp: int
    signature: Bytes
    signing_key: Bytes
    path_hash: Bytes
    salted_hash: Bytes
    revision_seq: int
    base_revision_id: Bytes | None = None
    encrypted_path: Bytes = b""
    file_name: str | None = None
    relative_path: str | None = None
    source: str | None = None


class UploadResult(_Wire):
    """What ``/upload`` and session finalize return.

    Attributes:
        upload_id: Opaque server id for the write.
        timestamp: Server Unix seconds.
        revision_id: The new revision; send it as the next ``base_revision_id``.
        created_at: Row creation time.
        updated_at: Row update time.
    """

    upload_id: str
    timestamp: int
    revision_id: Bytes
    created_at: int | None = None
    updated_at: int | None = None


class RemoteFileEntry(_Wire):
    """One file as the server sees it.

    Attributes:
        path_hash: Stable file identifier; its hex is the ``file_id``.
        salted_hash: Content equality check that does not depend on the nonce.
        size_bytes: Plaintext size.
        revision_seq: Monotonic revision counter.
        revision_id: Opaque version identifier.
        encrypted_path: The encrypted relative path; may be empty.
        file_name: Plaintext name, or None on pre-backfill rows.
        relative_path: Plaintext path, or None on pre-backfill rows.
        arion_hash: Storage-backend content hash, when available.
        chunk_hashes: Per-chunk storage hashes, when available.
        uploaded_by: Verified uploader. The key is absent, not null, on rows
            that predate attribution: render a dash, never a guess.
        created_at: Unix seconds.
        updated_at: Unix seconds.
    """

    path_hash: Bytes
    salted_hash: Bytes
    size_bytes: int
    revision_seq: int
    revision_id: Bytes
    encrypted_path: Bytes = b""
    file_name: str | None = None
    relative_path: str | None = None
    arion_hash: str | None = None
    chunk_hashes: list[str] | None = None
    uploaded_by: str | None = None
    created_at: int | None = None
    updated_at: int | None = None

    @property
    def file_id(self) -> str:
        """The 64-char hex ``path_hash`` used in download and delete paths."""
        return self.path_hash.hex()


class _Page(_Wire):
    """Shared pagination tail. Page on ``has_more``, never on ``total_count``.

    ``has_more`` is exact. ``total_count`` is approximate and can lag a write,
    so a walk that stops on it can stop early. ``limit`` and ``offset`` echo
    what the server applied, which is not always what was asked for:
    ``/browse`` and ``/search_files`` coerce ``limit`` down to
    :data:`MAX_LISTING_PAGE_SIZE`.
    """

    total_count: int | None = None
    has_more: bool = False
    offset: int = 0
    limit: int = 0


class GetStateResult(_Page):
    """A page of ``/get_state``.

    Attributes:
        ss58_address: Echo of the requested account.
        folder_hash: Echo of the requested folder.
        files: The files on this page.
    """

    ss58_address: str = ""
    folder_hash: str = ""
    files: list[RemoteFileEntry] = []


class BrowseFolderEntry(_Wire):
    """A subfolder in a ``/browse`` listing.

    ``file_count`` and ``total_bytes`` are recursive over every descendant.

    Attributes:
        name: The subfolder's own name, not a path.
        file_count: Files anywhere beneath it.
        total_bytes: Plaintext bytes anywhere beneath it.
    """

    name: str
    file_count: int = 0
    total_bytes: int = 0


class BrowseResult(_Page):
    """A page of ``/browse``.

    At most :data:`MAX_LISTING_PAGE_SIZE` entries, and 50 when the request
    names no ``limit``. Folders and files share one offset space, so the next
    page starts at ``offset + len(folders) + len(files)``.

    Attributes:
        ss58_address: Echo of the requested account.
        folder_hash: Echo of the requested folder.
        path: Echo of the requested directory path.
        folders: Immediate subfolders, alphabetical and always first.
        files: Files at exactly this path.
    """

    ss58_address: str = ""
    folder_hash: str = ""
    path: str = ""
    folders: list[BrowseFolderEntry] = []
    files: list[RemoteFileEntry] = []


class SearchHit(RemoteFileEntry):
    """A ``/search_files`` result: a file plus which folder it came from.

    Attributes:
        folder_hash: The folder the file lives in.
        folder_label: The registered label, or "" if never registered.
    """

    folder_hash: str = ""
    folder_label: str = ""


class SearchResult(_Page):
    """A page of ``/search_files``.

    At most :data:`MAX_LISTING_PAGE_SIZE` hits, and 25 when the request names
    no ``limit``.

    Attributes:
        ss58_address: Echo of the requested account.
        files: The hits on this page.
    """

    ss58_address: str = ""
    files: list[SearchHit] = []


class RemoteFolderInfo(_Wire):
    """One registered folder.

    Attributes:
        label: Human-readable name from registration.
        folder_hash: Use this in the path parameters of other endpoints.
        file_count: Files currently in the folder.
        total_bytes: Sum of plaintext sizes.
        created_at: Registration time, Unix seconds.
        updated_at: Last file change, Unix seconds.
        device_name: "" when registered without one.
        member_count: Shared-drive invitees; omitted when zero.
    """

    label: str = ""
    folder_hash: str = ""
    file_count: int = 0
    total_bytes: int = 0
    created_at: int | None = None
    updated_at: int | None = None
    device_name: str = ""
    member_count: int = 0


class ListFoldersResult(_Wire):
    """What ``/list_folders`` returns.

    Attributes:
        base_address: Echo of the requested account.
        folders: Every folder the account has registered.
    """

    base_address: str = ""
    folders: list[RemoteFolderInfo] = []


class RegisterFolderResult(_Wire):
    """What ``/register_folder`` returns.

    Attributes:
        status: ``registered``. The server upserts, so a second device
            registering the same label is also this status.
    """

    status: str


class UnregisterFolderResult(_Wire):
    """What ``/unregister_folder`` returns.

    Attributes:
        status: ``unregistered``.
        files_deleted: How many file rows went with the folder.
    """

    status: str
    files_deleted: int = 0


class ListFolderEntriesResult(_Wire):
    """Registered empty-directory paths for a drive.

    Attributes:
        relative_paths: Directory paths, drive-relative.
    """

    relative_paths: list[str] = []


class DeleteResult(_Wire):
    """What ``DELETE /delete/...`` returns.

    Attributes:
        status: ``deleted``.
        file_id: Echo of the deleted file id.
        ss58_address: Echo of the account.
        folder_hash: Echo of the folder.
    """

    status: str
    file_id: str = ""
    ss58_address: str = ""
    folder_hash: str = ""


class BatchDeleteEntry(_Wire):
    """One id's outcome in a batch delete.

    Attributes:
        file_id: The id this entry is about.
        status: ``deleted``, or ``already_deleted`` when no row matched.
    """

    file_id: str
    status: str


class BatchDeleteError(_Wire):
    """One id's failure in a batch delete.

    Attributes:
        file_id: The id that failed.
        error: Why it failed.
    """

    file_id: str = ""
    error: str = ""


class BatchDeleteResult(_Wire):
    """What ``/delete_files`` returns. HTTP is 200 even on partial failure.

    Attributes:
        deleted: Per-id successes; omitted when the caller asked for quiet.
        errors: Per-id failures; always inspect this.
        files_deleted: Count of entries whose status was ``deleted``.
    """

    deleted: list[BatchDeleteEntry] = []
    errors: list[BatchDeleteError] = []
    files_deleted: int = 0


class SingleRename(_Wire):
    """One entry of a ``/rename_files`` batch.

    Attributes:
        old_path_hash: Current path hash; must exist in this folder.
        new_path_hash: Target path hash; must not already exist.
        new_encrypted_path: New encrypted path; empty is allowed.
        new_file_name: Plaintext name for UI.
        new_relative_path: Plaintext path, which keeps browse and search working.
        base_revision_id: Per-entry optimistic concurrency check.
    """

    old_path_hash: Bytes
    new_path_hash: Bytes
    new_encrypted_path: Bytes = b""
    new_file_name: str | None = None
    new_relative_path: str | None = None
    base_revision_id: Bytes


class RenameSuccess(_Wire):
    """One successful rename.

    Attributes:
        old_path_hash: Where the file was.
        new_path_hash: Where it is now.
        new_revision_id: Server-assigned; store it for the next write.
        new_revision_seq: Server-assigned sequence.
    """

    old_path_hash: Bytes
    new_path_hash: Bytes
    new_revision_id: Bytes
    new_revision_seq: int = 0


class RenameFailure(_Wire):
    """One failed rename.

    Attributes:
        old_path_hash: The entry that failed.
        reason: ``not_found``, ``target_exists``, ``revision_mismatch``, or
            ``database_error``.
    """

    old_path_hash: Bytes
    reason: str


class BatchRenameResult(_Wire):
    """What ``/rename_files`` returns. Always 200; inspect ``failures``.

    Attributes:
        status: ``ok``.
        renamed_count: Number of entries that succeeded.
        successes: Per-entry results with new revisions.
        failures: Per-entry failures with reason codes.
    """

    status: str = "ok"
    renamed_count: int = 0
    successes: list[RenameSuccess] = []
    failures: list[RenameFailure] = []


class CreateSessionResult(_Wire):
    """What ``POST /upload/session`` returns.

    Attributes:
        session_id: Needed by every other session endpoint.
        expires_at: Unix seconds; chunk PUTs and status refresh it.
    """

    session_id: str
    expires_at: int | None = None


class UploadChunkResult(_Wire):
    """What a chunk PUT returns.

    Attributes:
        chunk_index: Echo of the index that landed.
    """

    chunk_index: int


class SessionStatusResult(_Wire):
    """What ``GET /upload/session/{id}/status`` returns.

    Attributes:
        session_id: Echo of the session.
        state: ``receiving`` or ``finalized``.
        total_chunks: How many chunks the session expects.
        chunks_received: Indices that have landed; the rest are the resume set.
        expires_at: Unix seconds.
        ciphertext_hash: Mirror of the session manifest's hash.
    """

    session_id: str = ""
    state: str = ""
    total_chunks: int = 0
    chunks_received: list[int] = []
    expires_at: int | None = None
    ciphertext_hash: str = ""


class DeleteSessionResult(_Wire):
    """What ``DELETE /upload/session/{id}`` returns.

    Attributes:
        deleted: Always true on success; the call is idempotent.
    """

    deleted: bool = True


class UserSummaryResult(_Wire):
    """Account storage totals, including S3-gateway uploads.

    Attributes:
        ss58_address: Echo of the account.
        total_bytes: Plaintext bytes stored.
        file_count: Files stored; can exceed the type and source charts.
        created_at: Unix seconds.
        updated_at: Unix seconds.
    """

    ss58_address: str = ""
    total_bytes: int = 0
    file_count: int = 0
    created_at: int | None = None
    updated_at: int | None = None


class FileTypeSummary(_Wire):
    """Per-type counts and plaintext bytes for HCFS-originated files."""

    image: int = 0
    image_bytes: int = 0
    video: int = 0
    video_bytes: int = 0
    audio: int = 0
    audio_bytes: int = 0
    document: int = 0
    document_bytes: int = 0
    pdf: int = 0
    pdf_bytes: int = 0
    archive: int = 0
    archive_bytes: int = 0
    code: int = 0
    code_bytes: int = 0
    other: int = 0
    other_bytes: int = 0


class SourceSummary(_Wire):
    """Per-client-family counts and plaintext bytes.

    ``other`` is mostly rows uploaded before source tracking existed.
    """

    desktop: int = 0
    desktop_bytes: int = 0
    console: int = 0
    console_bytes: int = 0
    mobile: int = 0
    mobile_bytes: int = 0
    other: int = 0
    other_bytes: int = 0


class CanUploadResult(_Wire):
    """What ``/can_upload`` returns. Never enveloped; HTTP stays 200 on refusal.

    Attributes:
        result: Whether the write would be allowed right now.
        error: The rejection reason when ``result`` is false. A value
            containing "billing" means a transient backend failure worth
            retrying, not a quota verdict.
    """

    result: bool
    error: str | None = None


class HealthResult(_Wire):
    """What ``/health`` returns. Unauthenticated.

    Attributes:
        status: ``healthy``.
        version: The hcfs-server crate version.
        capabilities: Informational; upload routing does not consult it.
    """

    status: str = ""
    version: str = ""
    capabilities: list[str] = []


class DownloadInfo(_Wire):
    """Metadata that came back with a download, read from response headers.

    Attributes:
        size_bytes: Plaintext size, from ``X-Size-Bytes``.
        revision_id: Current revision, from ``X-Revision-Id``.
        revision_seq: Current sequence, from ``X-Revision-Seq``.
    """

    size_bytes: int = 0
    revision_id: Bytes | None = None
    revision_seq: int = 0
