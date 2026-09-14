"""Each operation written once: identity plus arguments to a request and a parser.

The sync and async clients differ only in how they await the transport, so
every endpoint's shape and result type lives here and neither client repeats
it. An :class:`Op` is inert; nothing happens until a transport runs it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

from hippius_drive import models
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
        return model.model_validate(payload)

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
    """
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
    """
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
    """
    _, folder_hash = _folder_hash_for(identity, label)
    return Op(
        build.unregister_folder(identity.account_ss58, folder_hash),
        _parser(models.UnregisterFolderResult),
    )


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
        build.search_files(identity.account_ss58, filters, offset, limit),
        _parser(models.SearchResult),
    )


def user_summary(identity: Identity) -> Op[models.UserSummaryResult]:
    """Account storage totals, including S3-gateway uploads.

    Args:
        identity: The account and folder identity.

    Returns:
        The operation.
    """
    return Op(build.get_user_summary(identity.account_ss58), _parser(models.UserSummaryResult))


def file_type_summary(identity: Identity) -> Op[models.FileTypeSummary]:
    """Per-type counts and plaintext bytes for HCFS-originated files.

    Args:
        identity: The account and folder identity.

    Returns:
        The operation.
    """
    return Op(build.get_file_type_summary(identity.account_ss58), _parser(models.FileTypeSummary))


def source_summary(identity: Identity) -> Op[models.SourceSummary]:
    """Per-client-family counts and plaintext bytes.

    Args:
        identity: The account and folder identity.

    Returns:
        The operation.
    """
    return Op(build.get_source_summary(identity.account_ss58), _parser(models.SourceSummary))


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
        build.upload(
            prepared.manifest.model_dump_json().encode(),
            prepared.blob,
            prepared.ciphertext_size,
        ),
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
    """
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
            cost a round trip to learn.
    """
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
        ValueError: If the batch is empty.
    """
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
