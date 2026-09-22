"""Each operation written once: identity plus arguments to a request and a parser.

The sync and async clients differ only in how they await the transport, so
every endpoint's shape and result type lives here and neither client repeats
it. An :class:`Op` is inert; nothing happens until a transport runs it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ValidationError

from hippius_drive import errors, models
from hippius_drive._upload import TRANSPORT_CHUNK, PreparedUpload
from hippius_drive._wire import Request, build
from hippius_drive.crypto import kdf
from hippius_drive.identity import Identity, rename_text
from hippius_drive.models import BrowseOptions, SearchFilters

T = TypeVar("T")

MAX_BATCH_DELETE = 1000
"""Server cap on ``/delete_files`` (``MAX_BATCH_DELETE_FILES``)."""


@dataclass(frozen=True)
class Op(Generic[T]):
    """A request plus the function that turns its payload into a model.

    Attributes:
        request: The request to send.
        parse: Maps the unwrapped ``Success`` payload to a typed result.
    """

    request: Request
    parse: Callable[[Any], T]


M = TypeVar("M", bound=BaseModel)


def _parser(model: type[M]) -> Callable[[Any], M]:
    """Bind a model class into a payload parser, so ops read as one expression."""

    def parse(payload: Any) -> M:
        try:
            return model.model_validate(payload)
        except ValidationError as exc:
            raise errors.InvalidResponse(f"could not parse {model.__name__}: {exc}") from exc

    return parse


def _folder_hash_for(identity: Identity, label: str | None) -> tuple[str, str]:
    """Resolve a label to its name and folder hash, defaulting to the identity's own."""
    name = label if label is not None else identity.label
    if name == identity.label:
        return name, identity.folder_hash
    return name, kdf.folder_hash(name)


def register_folder(
    identity: Identity, label: str | None = None, device_name: str | None = None
) -> Op[models.RegisterFolderResult]:
    """Declare a folder under the account.

    Args:
        identity: The account and folder identity.
        label: The folder to register; the identity's own label when omitted.
        device_name: Which device registered it, for display.

    Returns:
        The operation.

    Raises:
        ValueError: If ``identity`` is a shared-drive member.
    """
    identity.require_owner()
    name, folder_hash = _folder_hash_for(identity, label)
    return Op(
        build.register_folder(identity.account_ss58, folder_hash, name, device_name),
        _parser(models.RegisterFolderResult),
    )


def list_folders(identity: Identity) -> Op[models.ListFoldersResult]:
    """Enumerate every folder the account has registered.

    Args:
        identity: The account and folder identity.

    Returns:
        The operation.

    Raises:
        ValueError: If ``identity`` is a shared-drive member.
    """
    identity.require_owner()
    return Op(build.list_folders(identity.account_ss58), _parser(models.ListFoldersResult))


def unregister_folder(
    identity: Identity, label: str | None = None
) -> Op[models.UnregisterFolderResult]:
    """Remove a folder and every file it owns. Irreversible.

    Args:
        identity: The account and folder identity.
        label: The folder to remove; the identity's own label when omitted.

    Returns:
        The operation.

    Raises:
        ValueError: If ``identity`` is a shared-drive member.
    """
    identity.require_owner()
    _, folder_hash = _folder_hash_for(identity, label)
    return Op(
        build.unregister_folder(identity.account_ss58, folder_hash),
        _parser(models.UnregisterFolderResult),
    )


def health() -> Op[models.HealthResult]:
    """Probe the service: liveness, build version, and its capability list.

    Unauthenticated. The capability list is informational; upload routing is
    decided by size, not by asking the server.

    Returns:
        The operation.
    """
    return Op(build.health(), _parser(models.HealthResult))


def list_folder_entries(identity: Identity) -> Op[models.ListFolderEntriesResult]:
    """List the registered empty-directory paths for this folder.

    Args:
        identity: The account and folder identity.

    Returns:
        The operation.
    """
    return Op(
        build.list_folder_entries(identity.account_ss58, identity.folder_hash),
        _parser(models.ListFolderEntriesResult),
    )


def get_state(
    identity: Identity, offset: int = 0, limit: int | None = None
) -> Op[models.GetStateResult]:
    """List every file in the folder, one page at a time.

    Args:
        identity: The account and folder identity.
        offset: Starting index into the ordered result set.
        limit: Results per page.

    Returns:
        The operation.
    """
    return Op(
        build.get_state(identity.account_ss58, identity.folder_hash, offset, limit),
        _parser(models.GetStateResult),
    )


def browse(
    identity: Identity,
    options: BrowseOptions | None = None,
    offset: int = 0,
    limit: int | None = None,
) -> Op[models.BrowseResult]:
    """List one directory level: subfolders first, then the files at that path.

    Args:
        identity: The account and folder identity.
        options: Path, sort, and filter options.
        offset: Starting index into the combined stream.
        limit: Results per page.

    Returns:
        The operation.
    """
    return Op(
        build.browse(identity.account_ss58, identity.folder_hash, options, offset, limit),
        _parser(models.BrowseResult),
    )


def search(
    identity: Identity,
    filters: SearchFilters | None = None,
    offset: int = 0,
    limit: int | None = None,
) -> Op[models.SearchResult]:
    """Search across every folder the account owns.

    Args:
        identity: The account and folder identity.
        filters: The filter and sort set.
        offset: Starting index into the result set.
        limit: Results per page.

    Returns:
        The operation.
    """
    return Op(
        build.search_files(
            identity.account_ss58,
            filters,
            offset,
            limit,
            identity.scoped_folder_hash(),
        ),
        _parser(models.SearchResult),
    )


def user_summary(identity: Identity) -> Op[models.UserSummaryResult]:
    """Account storage totals, including S3-gateway uploads.

    Args:
        identity: The account and folder identity.

    Returns:
        The operation.
    """
    scope = identity.scoped_folder_hash()
    return Op(
        build.get_user_summary(identity.account_ss58, scope),
        _parser(models.UserSummaryResult),
    )


def file_type_summary(identity: Identity) -> Op[models.FileTypeSummary]:
    """Per-type counts and plaintext bytes for HCFS-originated files.

    Args:
        identity: The account and folder identity.

    Returns:
        The operation.
    """
    scope = identity.scoped_folder_hash()
    return Op(
        build.get_file_type_summary(identity.account_ss58, scope),
        _parser(models.FileTypeSummary),
    )


def source_summary(identity: Identity) -> Op[models.SourceSummary]:
    """Per-client-family counts and plaintext bytes.

    Args:
        identity: The account and folder identity.

    Returns:
        The operation.
    """
    scope = identity.scoped_folder_hash()
    return Op(build.get_source_summary(identity.account_ss58, scope), _parser(models.SourceSummary))


def can_upload(identity: Identity, size_bytes: int) -> Op[models.CanUploadResult]:
    """Ask whether a write of ``size_bytes`` plaintext would be allowed.

    The answer is advisory: the write endpoints charge only the growth over a
    replaced row, so a refusal here can still succeed on ``/upload``.

    Args:
        identity: The account and folder identity.
        size_bytes: Plaintext bytes the caller intends to write.

    Returns:
        The operation.
    """
    return Op(
        build.can_upload(identity.account_ss58, identity.folder_hash, size_bytes),
        _parser(models.CanUploadResult),
    )


def upload(prepared: PreparedUpload) -> Op[models.UploadResult]:
    """Send a manifest and its blob in one multipart request.

    Args:
        prepared: The signed manifest and encrypted blob.

    Returns:
        The operation.
    """
    return Op(
        build.upload(prepared.manifest.model_dump_json().encode(), prepared.blob),
        _parser(models.UploadResult),
    )


def download(identity: Identity, file_id: str) -> Request:
    """Build the download request; the body is streamed, so there is no parser.

    Args:
        identity: The account and folder identity.
        file_id: 64-char hex ``path_hash``.

    Returns:
        The request.
    """
    return build.download(identity.account_ss58, identity.folder_hash, file_id)


def delete_file(identity: Identity, file_id: str) -> Op[models.DeleteResult]:
    """Remove one file. Immediate and with no undo.

    Args:
        identity: The account and folder identity.
        file_id: 64-char hex ``path_hash``.

    Returns:
        The operation.

    Raises:
        ValueError: If ``identity`` is a reader.
    """
    identity.require_writer()
    return Op(
        build.delete(identity.account_ss58, identity.folder_hash, file_id),
        _parser(models.DeleteResult),
    )


def delete_files(
    identity: Identity, file_ids: list[str], quiet: bool = False
) -> Op[models.BatchDeleteResult]:
    """Remove up to 1000 files in one transaction.

    Args:
        identity: The account and folder identity.
        file_ids: Hex path hashes to remove.
        quiet: Omit successful entries from the response.

    Returns:
        The operation.

    Raises:
        ValueError: If the batch exceeds the server cap, which would otherwise
            cost a round trip to learn, or if ``identity`` is a reader.
    """
    identity.require_writer()
    if len(file_ids) > MAX_BATCH_DELETE:
        raise ValueError(f"batch delete takes at most {MAX_BATCH_DELETE} ids, got {len(file_ids)}")
    return Op(
        build.delete_files(identity.account_ss58, identity.folder_hash, file_ids, quiet),
        _parser(models.BatchDeleteResult),
    )


def rename_files(
    identity: Identity, renames: list[models.SingleRename]
) -> Op[models.BatchRenameResult]:
    """Re-key files without moving ciphertext, under one signature.

    The entries are sorted by ``old_path_hash`` before signing because the
    server sorts the same way before it rebuilds the text to verify.

    Args:
        identity: The account and folder identity.
        renames: One entry per file to move.

    Returns:
        The operation.

    Raises:
        ValueError: If the batch is empty, or if ``identity`` is a reader.
    """
    identity.require_writer()
    if not renames:
        raise ValueError("rename needs at least one entry")
    ordered = sorted(renames, key=lambda r: r.old_path_hash)
    signature = identity.sign(
        rename_text([(r.old_path_hash, r.new_path_hash) for r in ordered]).encode()
    )
    return Op(
        build.rename_files(
            identity.account_ss58,
            identity.folder_hash,
            [r.model_dump(mode="json") for r in ordered],
            signature,
            identity.verifying_key,
        ),
        _parser(models.BatchRenameResult),
    )


def create_session(
    prepared: PreparedUpload, chunk_size: int = TRANSPORT_CHUNK
) -> Op[models.CreateSessionResult]:
    """Open a chunked upload session for a blob too large for one request.

    Args:
        prepared: The signed manifest and encrypted blob.
        chunk_size: Bytes per transport chunk.

    Returns:
        The operation.
    """
    return Op(
        build.create_session(
            prepared.manifest.model_dump(mode="json"),
            prepared.transport_chunk_count(chunk_size),
            chunk_size,
            prepared.ciphertext_size,
        ),
        _parser(models.CreateSessionResult),
    )


def upload_chunk(session_id: str, index: int, data: bytes) -> Op[models.UploadChunkResult]:
    """Send one chunk. Idempotent per index; order does not matter.

    Args:
        session_id: The session to write into.
        index: Zero-based chunk index.
        data: The raw chunk bytes.

    Returns:
        The operation.
    """
    return Op(build.upload_chunk(session_id, index, data), _parser(models.UploadChunkResult))


def session_status(session_id: str) -> Op[models.SessionStatusResult]:
    """Ask which chunks have landed, to decide what to resend.

    Args:
        session_id: The session to inspect.

    Returns:
        The operation.
    """
    return Op(build.session_status(session_id), _parser(models.SessionStatusResult))


def finalize_session(session_id: str) -> Op[models.UploadResult]:
    """Assemble the chunks and commit the file.

    Args:
        session_id: The session to commit.

    Returns:
        The operation.
    """
    return Op(build.finalize_session(session_id), _parser(models.UploadResult))


def delete_session(session_id: str) -> Op[models.DeleteSessionResult]:
    """Abort a session and release its temporary storage. Idempotent.

    Args:
        session_id: The session to abort.

    Returns:
        The operation.
    """
    return Op(build.delete_session(session_id), _parser(models.DeleteSessionResult))


def _rows(model: type[M]) -> Callable[[Any], list[M]]:
    """Parse a bare JSON array into ``model`` rows."""

    def parse(payload: Any) -> list[M]:
        rows = payload if payload is not None else []
        if not isinstance(rows, list):
            raise errors.InvalidResponse(f"expected a list of {model.__name__}")
        try:
            return [model.model_validate(item) for item in rows]
        except ValidationError as exc:
            raise errors.InvalidResponse(f"could not parse {model.__name__}: {exc}") from exc

    return parse


def _ignored(payload: Any) -> None:
    """Accept an empty 204. The body carries nothing the caller needs."""
    del payload


def capabilities() -> Op[models.Capabilities]:
    """Read share and shared-drive feature flags."""
    return Op(build.capabilities(), _parser(models.Capabilities))


def create_share(metadata_json: bytes, ciphertext: bytes) -> Op[models.MintedShare]:
    """Upload one file share in a single multipart request.

    Args:
        metadata_json: The metadata field.
        ciphertext: The framed blob.
    """
    return Op(build.create_share(metadata_json, ciphertext), _parser(models.MintedShare))


def init_share(body: dict[str, Any]) -> Op[models.MintedShare]:
    """Open a chunked file share.

    Args:
        body: Sizes, filename fields, chunk count, and ttl.
    """
    return Op(build.init_share(body), _parser(models.MintedShare))


def put_share_chunk(token: str, index: int, data: bytes) -> Op[models.UploadChunkResult]:
    """Send one share ciphertext chunk.

    Args:
        token: The token from init.
        index: Zero-based chunk index.
        data: The ciphertext slice.
    """
    return Op(build.put_share_chunk(token, index, data), _parser(models.UploadChunkResult))


def complete_share(token: str) -> Op[models.MintedShare]:
    """Finish a chunked file share.

    Args:
        token: The token from init.
    """
    return Op(build.complete_share(token), _parser(models.MintedShare))


def list_shares() -> Op[list[models.ShareSummary]]:
    """List the caller's file shares."""
    return Op(build.list_shares(), _rows(models.ShareSummary))


def revoke_share(token: str) -> Op[None]:
    """Revoke a file share.

    Args:
        token: The plaintext share token.
    """
    return Op(build.revoke_share(token), _ignored)


def update_share_ttl(token: str, ttl: str) -> Op[models.MintedShare]:
    """Change a file share's expiry.

    Args:
        token: The plaintext share token.
        ttl: ``24h``, ``7d``, ``30d``, or ``never``.
    """
    return Op(build.update_share_ttl(token, ttl), _parser(models.MintedShare))


def share_meta(token: str) -> Op[models.ShareMeta]:
    """Read anonymous file-share metadata.

    Args:
        token: The plaintext share token.
    """
    return Op(build.share_meta(token), _parser(models.ShareMeta))


def share_blob(token: str) -> Request:
    """The anonymous file-share download. The body is streamed.

    Args:
        token: The plaintext share token.
    """
    return build.share_blob(token)


def put_file_owner_wraps(wraps: list[dict[str, str]]) -> Op[models.OwnerWrapsResult]:
    """Store mnemonic-sealed file-share secrets.

    Args:
        wraps: ``{"token", "wrap"}`` entries.
    """
    return Op(build.put_file_owner_wraps(wraps), _parser(models.OwnerWrapsResult))


def create_folder_share(body: dict[str, Any]) -> Op[models.MintedShare]:
    """Mint a folder share. Nothing is uploaded.

    Args:
        body: Drive, prefix, display name, and ttl.
    """
    return Op(build.create_folder_share(body), _parser(models.MintedShare))


def list_folder_shares() -> Op[list[models.FolderShare]]:
    """List folder shares the caller controls."""
    return Op(build.list_folder_shares(), _rows(models.FolderShare))


def revoke_folder_share(token: str) -> Op[None]:
    """Revoke a folder share by its plaintext token.

    Args:
        token: The plaintext token.
    """
    return Op(build.revoke_folder_share(token), _ignored)


def revoke_folder_share_by_hash(token_hash: str) -> Op[None]:
    """Revoke a folder share by the hash the listing returns.

    Args:
        token_hash: 64 lowercase hex characters.
    """
    return Op(build.revoke_folder_share_by_hash(token_hash), _ignored)


def update_folder_share_ttl(token: str, ttl: str) -> Op[models.ExpiryResult]:
    """Change a folder share's expiry by plaintext token.

    Args:
        token: The plaintext token.
        ttl: ``24h``, ``7d``, ``30d``, or ``never``.
    """
    return Op(build.update_folder_share_ttl(token, ttl), _parser(models.ExpiryResult))


def update_folder_share_ttl_by_hash(token_hash: str, ttl: str) -> Op[models.ExpiryResult]:
    """Change a folder share's expiry by ``token_hash``.

    Args:
        token_hash: 64 lowercase hex characters.
        ttl: ``24h``, ``7d``, ``30d``, or ``never``.
    """
    return Op(
        build.update_folder_share_ttl_by_hash(token_hash, ttl),
        _parser(models.ExpiryResult),
    )


def put_folder_owner_wraps(wraps: list[dict[str, str]]) -> Op[models.OwnerWrapsResult]:
    """Store mnemonic-sealed folder-share secrets.

    Args:
        wraps: ``{"token_hash", "wrap"}`` entries.
    """
    return Op(build.put_folder_owner_wraps(wraps), _parser(models.OwnerWrapsResult))


def folder_share_meta(token: str) -> Op[models.FolderShareMeta]:
    """Read anonymous folder-share metadata.

    Args:
        token: The plaintext token.
    """
    return Op(build.folder_share_meta(token), _parser(models.FolderShareMeta))


def folder_share_browse(
    token: str, path: str = "", offset: int = 0, limit: int | None = None
) -> Op[models.FolderSharePage]:
    """List one directory inside a folder share.

    Args:
        token: The plaintext token.
        path: Directory relative to the share prefix.
        offset: Starting file index.
        limit: Page size.
    """
    return Op(
        build.folder_share_browse(token, path, offset, limit),
        _parser(models.FolderSharePage),
    )


def folder_share_blob(token: str, path: str) -> Request:
    """The anonymous folder-share download. The body is streamed.

    Args:
        token: The plaintext token.
        path: File path relative to the share prefix.
    """
    return build.folder_share_blob(token, path)


def create_drive_invite(body: dict[str, Any]) -> Op[models.InviteMint]:
    """Mint a shared-drive invite.

    Args:
        body: Folder hash, role, and optional lifetime and owner.
    """
    return Op(build.create_drive_invite(body), _parser(models.InviteMint))


def seal_drive_invite(
    folder_hash: str, invite_id: str, sealed_token: str, owner: str | None
) -> Op[None]:
    """Attach the client-sealed invite token. A failure does not unmint the invite.

    Args:
        folder_hash: The drive id.
        invite_id: Blake3 hex of the token.
        sealed_token: Standard base64 of the sealed JSON.
        owner: Set when a manager seals on someone else's drive.
    """
    request = build.seal_drive_invite(folder_hash, invite_id, sealed_token, owner)
    return Op(request, _ignored)


def list_drive_invites(folder_hash: str, owner: str | None) -> Op[models.DriveInvites]:
    """List a drive's invites.

    Args:
        folder_hash: The drive id.
        owner: Set when a manager lists someone else's drive.
    """
    return Op(build.list_drive_invites(folder_hash, owner), _parser(models.DriveInvites))


def revoke_drive_invite(folder_hash: str, invite_id: str, owner: str | None) -> Op[None]:
    """Revoke an invite by its id.

    Args:
        folder_hash: The drive id.
        invite_id: Blake3 hex of the token.
        owner: Set when a manager revokes someone else's invite.
    """
    return Op(build.revoke_drive_invite(folder_hash, invite_id, owner), _ignored)


def list_drive_members(folder_hash: str, owner: str | None) -> Op[models.DriveMembers]:
    """List a drive's members.

    Args:
        folder_hash: The drive id.
        owner: Set when the caller is a member rather than the owner.
    """
    return Op(build.list_drive_members(folder_hash, owner), _parser(models.DriveMembers))


def remove_drive_member(folder_hash: str, member_ss58: str, owner: str | None) -> Op[None]:
    """Remove a member, or leave when ``member_ss58`` is the caller.

    Args:
        folder_hash: The drive id.
        member_ss58: The member to remove.
        owner: Set for self-leave and for a manager.
    """
    return Op(build.remove_drive_member(folder_hash, member_ss58, owner), _ignored)


def change_member_role(
    folder_hash: str, member_ss58: str, role: str, owner: str | None
) -> Op[models.DriveMember]:
    """Change a member's role in place.

    Args:
        folder_hash: The drive id.
        member_ss58: The member to change.
        role: ``reader``, ``writer``, or ``manager``.
        owner: Set when a manager changes a role on someone else's drive.
    """
    request = build.change_member_role(folder_hash, member_ss58, role, owner)
    return Op(request, _parser(models.DriveMember))


def invite_meta(token: str) -> Op[models.InviteMeta]:
    """Read an invite preview without sending the bearer token.

    Args:
        token: The plaintext invite token.
    """
    return Op(build.invite_meta(token), _parser(models.InviteMeta))


def accept_invite(token: str, grant_blob: str) -> Op[models.AcceptResult]:
    """Join a drive.

    Args:
        token: The plaintext invite token.
        grant_blob: Standard padded base64 of the sealed folder phrase.
    """
    return Op(build.accept_invite(token, grant_blob), _parser(models.AcceptResult))


def list_memberships() -> Op[models.DriveMembershipsWire]:
    """List drives the caller has joined, grants still sealed."""
    return Op(build.list_memberships(), _parser(models.DriveMembershipsWire))
