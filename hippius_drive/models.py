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

from dataclasses import dataclass, field
from enum import Enum
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
        ss58_address: The drive namespace. The token's account, or the owner
            when a member writes into a shared drive.
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


class ShareTtl(str, Enum):
    """How long a share link stays reachable. The server applies the clock.

    The wire values are a closed set shared with hcfs. An unknown value is a
    400 rather than a lifetime nobody chose.
    """

    HOURS_24 = "24h"
    DAYS_7 = "7d"
    DAYS_30 = "30d"
    NEVER = "never"


class Capabilities(_Wire):
    """``GET /v1/capabilities``. Absent flags mean false.

    Attributes:
        shares: File-share routes are mounted.
        folder_shares: Folder-share routes are mounted.
        folder_share_revoke_by_hash: Revoke and expiry by ``token_hash``.
        share_owner_wrap: Owner-wrap upload is mounted.
        member_folder_shares: A member may mint a folder share on a shared drive.
    """

    shares: bool = False
    folder_shares: bool = False
    folder_share_revoke_by_hash: bool = False
    share_owner_wrap: bool = False
    member_folder_shares: bool = False


class ExpiryResult(_Wire):
    """Expiry returned by a folder-share TTL update. The token is not repeated.

    Attributes:
        expires_at: RFC 3339, or None when the share does not expire.
    """

    expires_at: str | None = None


class MintedShare(_Wire):
    """Token returned once by share create, init, and chunked complete.

    Attributes:
        share_token: The plaintext capability. The server stores only its hash
            for folder shares; file-share listings do echo this token.
        expires_at: RFC 3339, or None when the share does not expire.
    """

    share_token: str
    expires_at: str | None = None


class ShareSummary(_Wire):
    """One row of ``GET /v1/shares``.

    Attributes:
        share_token: Plaintext token. File-share listings return it.
        filename: Plaintext name, for the owner's own list.
        plaintext_size: Declared plaintext bytes.
        ciphertext_size: Stored blob bytes.
        mime_type: The type sent at mint time.
        created_at: RFC 3339.
        expires_at: None when the share does not expire.
        owner_wrap: Standard base64 of the mnemonic-sealed secret, when uploaded.
    """

    share_token: str
    filename: str = ""
    plaintext_size: int = 0
    ciphertext_size: int = 0
    mime_type: str = ""
    created_at: str = ""
    expires_at: str | None = None
    owner_wrap: str | None = None


class ShareMeta(_Wire):
    """Anonymous ``GET /v1/shares/{token}/meta``. The filename stays encrypted.

    Attributes:
        ciphertext_size: Stored blob bytes.
        plaintext_size: Declared plaintext bytes.
        filename_ct: Standard base64 of the encrypted filename.
        filename_nonce: Standard base64 of the 24-byte nonce.
        mime_type: The type sent at mint time.
        expires_at: None when the share does not expire.
    """

    ciphertext_size: int = 0
    plaintext_size: int = 0
    filename_ct: str = ""
    filename_nonce: str = ""
    mime_type: str = ""
    expires_at: str | None = None


class OwnerWrapsResult(_Wire):
    """How many owner-wrap rows the server stored. Unknown tokens are skipped.

    Attributes:
        applied: Rows updated.
    """

    applied: int = 0


class FolderShare(_Wire):
    """One row of ``GET /v1/folder-shares``. The listing has no plaintext token.

    Attributes:
        token_hash: Blake3 hex of the token.
        folder_hash: The drive the share scopes.
        path_prefix: "" shares the whole drive.
        display_name: Name shown to the recipient.
        created_at: RFC 3339.
        expires_at: None when the share does not expire.
        revoked_at: Set once the owner has revoked it.
        owner_wrap: Present only for the account that minted the share.
        owner_ss58: Whose drive the share reads.
        minted_by_ss58: Who published the link.
    """

    token_hash: str
    folder_hash: str = ""
    path_prefix: str = ""
    display_name: str = ""
    created_at: str = ""
    expires_at: str | None = None
    revoked_at: str | None = None
    owner_wrap: str | None = None
    owner_ss58: str = ""
    minted_by_ss58: str = ""


class FolderShareMeta(_Wire):
    """Anonymous folder-share header.

    Attributes:
        display_name: Name shown to the recipient.
        expires_at: None when the share does not expire.
    """

    display_name: str = ""
    expires_at: str | None = None


class FolderShareFile(_Wire):
    """One file in a folder-share listing.

    Attributes:
        name: The last path segment.
        path: Path relative to the share prefix.
        size_bytes: Plaintext size.
        uploaded_at: RFC 3339.
    """

    name: str = ""
    path: str = ""
    size_bytes: int = 0
    uploaded_at: str = ""


class FolderShareDir(_Wire):
    """One directory in a folder-share listing.

    Attributes:
        name: The last path segment.
        file_count: Files anywhere beneath this directory.
        total_bytes: Recursive plaintext bytes.
        created_at: RFC 3339, or None when the server has no date.
    """

    name: str = ""
    file_count: int = 0
    total_bytes: int = 0
    created_at: str | None = None


class FolderSharePage(_Wire):
    """One page of ``GET /v1/folder-shares/{token}/browse``.

    Attributes:
        directories: Child directories. Empty on continuation pages.
        files: Files on this page.
        total_count: Entries represented by this response.
        has_more: Another file page follows. Page on this, not ``total_count``.
        offset: Echo of the requested offset.
        limit: Echo of the page size.
    """

    directories: list[FolderShareDir] = []
    files: list[FolderShareFile] = []
    total_count: int = 0
    has_more: bool = False
    offset: int = 0
    limit: int = 0


class InviteMint(_Wire):
    """The one response that contains a plaintext invite token.

    Attributes:
        invite_token: The join capability. The server stores blake3 of it.
        invite_id: That blake3 hex, when the server returns it.
    """

    invite_token: str
    invite_id: str | None = None


class InviteMeta(_Wire):
    """Anonymous preview of an invite, shown before the recipient accepts.

    Attributes:
        owner_ss58: The drive owner.
        owner_name: Display name, when the owner has one.
        folder_hash: The drive id.
        display_label: The owner's registry label, or the hash.
        expires_at: RFC 3339.
        role: The role an accept would grant.
        valid: False when an accept would return 410.
    """

    owner_ss58: str = ""
    owner_name: str | None = None
    folder_hash: str = ""
    display_label: str = ""
    expires_at: str = ""
    role: str = "writer"
    valid: bool = False


class AcceptResult(_Wire):
    """What ``POST /v1/drive-invites/{token}/accept`` returns.

    Attributes:
        owner_ss58: The drive owner.
        folder_hash: The drive id.
        role: The role granted.
        already_owner: True when the owner opened their own invite.
    """

    owner_ss58: str
    folder_hash: str
    role: str = "writer"
    already_owner: bool = False


class DriveMember(_Wire):
    """One member of a drive. The grant blob is not in this listing.

    Attributes:
        member_ss58: The member's account.
        role: ``reader``, ``writer``, or ``manager``.
        created_at: RFC 3339.
        member_name: Display name, when known.
        member_email: Shown to the owner and managers only.
    """

    member_ss58: str
    role: str = "writer"
    created_at: str = ""
    member_name: str | None = None
    member_email: str | None = None


class DriveMembers(_Wire):
    """``GET /v1/drives/{folder_hash}/members``.

    Attributes:
        members: The drive's members. The owner is not a row.
    """

    members: list[DriveMember] = []


class DriveInvite(_Wire):
    """One invite row. ``sealed_token`` is absent unless this caller may read it.

    Attributes:
        invite_id: Blake3 hex of the token.
        sealed_token: Standard base64 of the client-sealed token.
        role: The role the invite grants.
        minted_by: Who minted it.
        expires_at: RFC 3339.
        max_uses: How many distinct members may join.
        use_count: How many have joined.
        revoked: The owner has revoked it.
        valid: False when revoked, expired, or exhausted.
        created_at: RFC 3339.
    """

    invite_id: str
    sealed_token: str | None = None
    role: str = "writer"
    minted_by: str = ""
    expires_at: str = ""
    max_uses: int = 0
    use_count: int = 0
    revoked: bool = False
    valid: bool = False
    created_at: str = ""


class DriveInvites(_Wire):
    """``GET /v1/drives/{folder_hash}/invites``.

    Attributes:
        invites: Newest first, including spent rows.
        truncated: True when the server returned only the newest 500.
    """

    invites: list[DriveInvite] = []
    truncated: bool = False


class DriveMembershipWire(_Wire):
    """One drive the caller belongs to, grant still sealed.

    Attributes:
        owner_ss58: The drive owner.
        folder_hash: The drive id.
        role: The caller's role.
        grant_blob: Standard base64 of the sealed folder phrase. Empty when absent.
        display_label: The owner's label for the drive.
        created_at: RFC 3339.
        frozen: The owner's account is limited. Reads still work.
        frozen_until: RFC 3339 end of a grace window, when recorded.
        member_count: Invitees. The owner is not counted.
        owner_name: The owner's display name.
    """

    owner_ss58: str
    folder_hash: str
    role: str = "writer"
    grant_blob: str = ""
    display_label: str = ""
    created_at: str = ""
    frozen: bool = False
    frozen_until: str | None = None
    member_count: int = 0
    owner_name: str | None = None


class DriveMembershipsWire(_Wire):
    """``GET /v1/drive-memberships``.

    Attributes:
        memberships: Drives the caller has joined.
    """

    memberships: list[DriveMembershipWire] = []


@dataclass(frozen=True)
class CreatedShare:
    """A share link. ``share_url`` already contains the key fragment.

    Attributes:
        share_token: The plaintext token. Store it; folder-share listings will not.
        share_url: The console URL to hand to the recipient.
        expires_at: RFC 3339, or None when the share does not expire.
    """

    share_token: str
    share_url: str
    expires_at: str | None = None


@dataclass(frozen=True)
class OpenedShare:
    """Plaintext read back from a file-share URL.

    Attributes:
        filename: Decrypted from the share metadata.
        mime_type: The type stored with the share.
        data: The file contents.
        expires_at: RFC 3339, or None when the share does not expire.
    """

    filename: str
    mime_type: str
    data: bytes = field(repr=False)
    expires_at: str | None = None


@dataclass(frozen=True)
class CreatedInvite:
    """An invite link. The fragment is the drive key and is not stored server-side.

    Attributes:
        invite_token: The plaintext join capability.
        invite_url: ``{console}/invite/{token}#k={entropy}``.
        invite_id: Blake3 hex of the token.
    """

    invite_token: str
    invite_url: str
    invite_id: str


@dataclass(frozen=True)
class AcceptedInvite:
    """A drive the caller just joined, plus the folder phrase the link carried.

    Attributes:
        owner_ss58: The drive owner. Paths and ``salted_hash`` use this.
        folder_hash: The owner's folder id.
        role: The role granted.
        folder_mnemonic: The owner's folder phrase. Pass it to
            ``Identity.for_shared_drive``.
        already_owner: True when the owner opened their own invite.
    """

    owner_ss58: str
    folder_hash: str
    role: str
    folder_mnemonic: str = field(repr=False)
    already_owner: bool = False


@dataclass(frozen=True)
class DriveMembership:
    """A joined drive with the folder phrase opened from its grant.

    Attributes:
        owner_ss58: The drive owner.
        folder_hash: The owner's folder id.
        role: The caller's role.
        display_label: The owner's label for the drive.
        folder_mnemonic: Opened phrase, or None when the row has no grant.
        frozen: The owner's account is limited.
    """

    owner_ss58: str
    folder_hash: str
    role: str
    display_label: str
    folder_mnemonic: str | None = field(default=None, repr=False)
    frozen: bool = False
