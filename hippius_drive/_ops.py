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
from hippius_drive._wire import Request, build
from hippius_drive.crypto import kdf
from hippius_drive.identity import Identity
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
