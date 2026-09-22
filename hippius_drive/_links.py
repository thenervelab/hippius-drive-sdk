"""Share and invite flows shared by the sync and async clients.

Encryption and URL building happen here. Each client only decides whether to
await the operations this module returns.
"""

from __future__ import annotations

import base64
import math
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from tempfile import SpooledTemporaryFile
from typing import IO, Any

import blake3

from hippius_drive import _ops, errors
from hippius_drive._ops import Op
from hippius_drive._upload import SPOOL_MAX, TRANSPORT_CHUNK, PlaintextSource
from hippius_drive.crypto import file_cipher, grant, hashes, owner_wrap, sharing
from hippius_drive.crypto.sharing import ShareSecret
from hippius_drive.errors import DecryptError, NotFound
from hippius_drive.identity import MANAGER, OWNER, Identity
from hippius_drive.models import (
    AcceptedInvite,
    AcceptResult,
    Capabilities,
    CreatedInvite,
    CreatedShare,
    DriveMembership,
    DriveMembershipsWire,
    InviteMint,
    MintedShare,
    ShareTtl,
)

DEFAULT_CONSOLE = "https://console.hippius.com"
"""Console origin used when a caller does not pass one. The fragment stays local."""

_MAX_WRAPS = 64
_TOKEN_HASH_LEN = 64
_ROLES = frozenset({"reader", "writer", "manager"})
Runner = Callable[[Op[Any]], Any]


@dataclass(frozen=True)
class FileShareSpec:
    """What the caller chose about a file share, apart from the bytes.

    Attributes:
        filename: Plaintext name shown to the owner and, once decrypted, the recipient.
        mime_type: Stored for the recipient's download.
        ttl: How long the link stays reachable.
        password: When set, the URL is a ``#p=`` link.
        console_base_url: Origin the recipient URL is built against.
    """

    filename: str
    mime_type: str = "application/octet-stream"
    ttl: ShareTtl | str = ShareTtl.HOURS_24
    password: str | None = None
    console_base_url: str = DEFAULT_CONSOLE


@dataclass(frozen=True)
class FolderShareSpec:
    """What the caller chose about a folder share.

    Attributes:
        path_prefix: Drive-relative directory. "" shares the whole drive.
        display_name: Name shown on the recipient page.
        ttl: How long the link stays reachable.
        password: When set, the URL is a ``#p=`` link.
        console_base_url: Origin the recipient URL is built against.
    """

    path_prefix: str
    display_name: str
    ttl: ShareTtl | str = ShareTtl.HOURS_24
    password: str | None = None
    console_base_url: str = DEFAULT_CONSOLE


@dataclass(frozen=True)
class InviteSpec:
    """What the caller chose about a drive invite.

    Attributes:
        folder_mnemonic: The owner's folder phrase. It becomes the ``#k=`` fragment.
        role: ``reader``, ``writer``, or ``manager``.
        expires_in_secs: Lifetime. None uses the server default.
        max_uses: Distinct members who may join. None uses the server default.
        console_base_url: Origin the invite URL is built against.
    """

    folder_mnemonic: str
    role: str = "writer"
    expires_in_secs: int | None = None
    max_uses: int | None = None
    console_base_url: str = DEFAULT_CONSOLE


@dataclass
class ShareBlob:
    """An encrypted share blob that still has to be uploaded."""

    key: bytes
    secret: ShareSecret
    filename_ct: str
    filename_nonce: str
    plaintext_size: int
    ciphertext_size: int
    body: IO[bytes]

    def close(self) -> None:
        """Close the spooled ciphertext."""
        self.body.close()

    def read_all(self) -> bytes:
        """Return the whole ciphertext. Only used under the 8 MiB cap."""
        self.body.seek(0)
        return self.body.read()

    def chunks(self) -> Iterator[bytes]:
        """Yield transport chunks in order."""
        self.body.seek(0)
        while True:
            block = self.body.read(TRANSPORT_CHUNK)
            if not block:
                return
            yield block


def prepare_file_share(source: PlaintextSource, spec: FileShareSpec) -> ShareBlob:
    """Encrypt a file share. No network.

    Args:
        source: The plaintext. Its size is binding.
        spec: Filename, ttl, and optional password.

    Returns:
        The encrypted blob and the fragment secret.

    Raises:
        ValueError: If the filename or password is unusable, or the source
            does not hold ``source.size`` bytes.
    """
    if not spec.filename or "/" in spec.filename or "\\" in spec.filename:
        raise ValueError("filename must be a single path segment")
    if spec.password is not None:
        sharing.check_share_password(spec.password)
    key = sharing.generate_share_key()
    filename_ct, filename_nonce = sharing.encrypt_filename(spec.filename, key)
    secret = _fragment(key, spec.password)
    body, size = _encrypt(source, key)
    return ShareBlob(
        key=key,
        secret=secret,
        filename_ct=base64.b64encode(filename_ct).decode(),
        filename_nonce=base64.b64encode(filename_nonce).decode(),
        plaintext_size=source.size,
        ciphertext_size=size,
        body=body,
    )


def file_share_metadata(
    prepared: ShareBlob, spec: FileShareSpec, total_chunks: int | None
) -> dict[str, Any]:
    """The JSON object both the single-shot and init requests carry."""
    body: dict[str, Any] = {
        "ciphertext_size": prepared.ciphertext_size,
        "plaintext_size": prepared.plaintext_size,
        "filename_ct": prepared.filename_ct,
        "filename_nonce": prepared.filename_nonce,
        "filename": spec.filename,
        "mime_type": spec.mime_type,
        "ttl": wire_ttl(spec.ttl),
    }
    if total_chunks is not None:
        body["total_chunks"] = total_chunks
    return body


def finish_file_share(
    minted: MintedShare, prepared: ShareBlob, spec: FileShareSpec
) -> CreatedShare:
    """Build the recipient URL from a mint response. The fragment is not uploaded."""
    url = sharing.share_url(
        spec.console_base_url, minted.share_token, prepared.secret, folder=False
    )
    return CreatedShare(minted.share_token, url, minted.expires_at)


def single_shot(prepared: ShareBlob, spec: FileShareSpec) -> bool:
    """True when the ciphertext fits one 8 MiB share request."""
    return prepared.ciphertext_size <= TRANSPORT_CHUNK


def chunk_count(ciphertext_size: int) -> int:
    """How many 8 MiB transport chunks a share blob occupies."""
    return max(1, math.ceil(ciphertext_size / TRANSPORT_CHUNK))


def folder_share_body(identity: Identity, spec: FolderShareSpec) -> dict[str, Any]:
    """The folder-share mint body. A member names the drive owner.

    Args:
        identity: The drive the share reads.
        spec: Prefix, name, and ttl.

    Returns:
        The JSON body. It contains no key.

    Raises:
        ValueError: If the caller is a reader, or the prefix or name is unusable.
    """
    identity.require_writer()
    if not spec.display_name:
        raise ValueError("display_name is required")
    prefix = "" if spec.path_prefix == "" else hashes.normalize_relative_path(spec.path_prefix)
    if spec.password is not None:
        sharing.check_share_password(spec.password)
    body: dict[str, Any] = {
        "folder_hash": identity.folder_hash,
        "path_prefix": prefix,
        "display_name": spec.display_name,
        "ttl": wire_ttl(spec.ttl),
    }
    if identity.role != OWNER:
        body["owner_ss58"] = identity.account_ss58
    return body


def folder_share_secret(identity: Identity, spec: FolderShareSpec) -> ShareSecret:
    """The fragment secret for a folder share: the drive file key, possibly wrapped."""
    return _fragment(identity.encryption_key, spec.password)


def finish_folder_share(
    minted: MintedShare, secret: ShareSecret, spec: FolderShareSpec
) -> CreatedShare:
    """Build a folder-share URL. A private secret only produces ``#p=``."""
    url = sharing.share_url(spec.console_base_url, minted.share_token, secret, folder=True)
    return CreatedShare(minted.share_token, url, minted.expires_at)


def file_owner_wrap_entries(
    master_mnemonic: str, account_ss58: str, secrets: Sequence[tuple[str, ShareSecret]]
) -> list[dict[str, str]]:
    """Seal file-share secrets for ``PUT /v1/shares/owner-wraps``.

    Args:
        master_mnemonic: The minter's master phrase.
        account_ss58: The account the token resolves to. It is the wrap's AAD.
        secrets: ``(share_token, fragment secret)`` pairs.

    Returns:
        The request entries.
    """
    _check_wrap_batch(secrets)
    entries = []
    for token, secret in secrets:
        sealed = owner_wrap.seal_file_secret(master_mnemonic, account_ss58, token, secret)
        entries.append({"token": token, "wrap": base64.b64encode(sealed).decode()})
    return entries


def folder_owner_wrap_entries(
    master_mnemonic: str, account_ss58: str, secrets: Sequence[tuple[str, ShareSecret]]
) -> list[dict[str, str]]:
    """Seal folder-share tokens and secrets for the folder-share wrap route.

    Args:
        master_mnemonic: The minter's master phrase.
        account_ss58: The account the token resolves to.
        secrets: ``(plaintext token, fragment secret)`` pairs.

    Returns:
        Entries addressed by ``token_hash``.
    """
    _check_wrap_batch(secrets)
    entries = []
    for token, secret in secrets:
        sealed = owner_wrap.seal_folder_secret(master_mnemonic, account_ss58, token, secret)
        digest = owner_wrap.folder_token_hash(token)
        entries.append({"token_hash": digest, "wrap": base64.b64encode(sealed).decode()})
    return entries


def invite_body(identity: Identity, spec: InviteSpec) -> dict[str, Any]:
    """The invite mint body. A manager names the drive owner.

    Raises:
        ValueError: If the caller cannot mint, or the role is unknown.
    """
    if identity.role not in {OWNER, MANAGER}:
        raise ValueError("only the owner or a manager can mint an invite")
    if spec.role not in _ROLES:
        raise ValueError("role must be reader, writer, or manager")
    body: dict[str, Any] = {"folder_hash": identity.folder_hash, "role": spec.role}
    if spec.expires_in_secs is not None:
        body["expires_in_secs"] = spec.expires_in_secs
    if spec.max_uses is not None:
        body["max_uses"] = spec.max_uses
    if identity.role == MANAGER:
        body["owner_ss58"] = identity.account_ss58
    return body


def finish_invite(minted: InviteMint, spec: InviteSpec) -> tuple[CreatedInvite, str]:
    """Build the invite URL and the standard-base64 sealed token for seal-back.

    Args:
        minted: The mint response.
        spec: Carries the folder phrase that becomes the fragment.

    Returns:
        The link, and the wire ``sealed_token``. An empty string means seal-back
        should be skipped because the server's id does not match the token.
    """
    entropy = grant.entropy_from_phrase(spec.folder_mnemonic)
    digest = blake3.blake3(minted.invite_token.encode()).hexdigest()
    url = grant.invite_url(spec.console_base_url, minted.invite_token, entropy)
    invite_id = minted.invite_id or digest
    if invite_id != digest:
        return CreatedInvite(minted.invite_token, url, invite_id), ""
    sealed = grant.seal_invite_token(entropy, digest, minted.invite_token)
    wire = base64.b64encode(sealed).decode()
    return CreatedInvite(minted.invite_token, url, digest), wire


def accept_grant(member_master: str, member_ss58: str, folder_phrase: str) -> str:
    """Seal a folder phrase and return the padded base64 grant body field."""
    blob = grant.seal_grant(member_master, member_ss58, folder_phrase)
    return base64.b64encode(blob).decode()


def accepted_invite(result: AcceptResult, folder_phrase: str) -> AcceptedInvite:
    """Pair an accept response with the phrase the link carried."""
    return AcceptedInvite(
        owner_ss58=result.owner_ss58,
        folder_hash=result.folder_hash,
        role=result.role,
        folder_mnemonic=folder_phrase,
        already_owner=result.already_owner,
    )


def open_memberships(
    member_master: str, member_ss58: str, page: DriveMembershipsWire
) -> list[DriveMembership]:
    """Open each grant. An empty grant stays unopened rather than failing the list."""
    opened: list[DriveMembership] = []
    for row in page.memberships:
        phrase = _open_one_grant(member_master, member_ss58, row.grant_blob)
        opened.append(
            DriveMembership(
                owner_ss58=row.owner_ss58,
                folder_hash=row.folder_hash,
                role=row.role,
                display_label=row.display_label,
                folder_mnemonic=phrase,
                frozen=row.frozen,
            )
        )
    return opened


def share_key_from_url(url: str, password: str | None, *, folder: bool) -> tuple[str, bytes]:
    """Return ``(token, raw key)`` from a recipient URL.

    Raises:
        ValueError: If the URL is the wrong kind, or a password link has no password.
        DecryptError: If the password does not open the link.
    """
    parsed = sharing.parse_share_url(url)
    if parsed.folder != folder:
        kind = "folder" if folder else "file"
        raise ValueError(f"this URL is not a {kind} share")
    if parsed.secret.private:
        if password is None:
            raise ValueError("password is required to open this share")
        return parsed.token, sharing.unwrap_share_key(password, parsed.secret.material)
    return parsed.token, parsed.secret.material


def decode_share_filename(filename_ct: str, filename_nonce: str, key: bytes) -> str:
    """Decrypt the filename fields from anonymous share metadata."""
    try:
        ciphertext = base64.b64decode(filename_ct, validate=True)
        nonce = base64.b64decode(filename_nonce, validate=True)
    except ValueError as exc:
        raise DecryptError("share filename is malformed") from exc
    return sharing.decrypt_filename(ciphertext, nonce, key)


def wrap_account(identity: Identity, account_ss58: str | None) -> str:
    """The account a wrap is sealed for: the token's account, not the drive owner.

    Args:
        identity: The client's identity.
        account_ss58: Explicit account. Required when ``identity`` is a member.

    Returns:
        The SS58 bound into the wrap.

    Raises:
        ValueError: If a member omits ``account_ss58``.
    """
    if account_ss58 is not None:
        return account_ss58
    if identity.role != OWNER:
        raise ValueError("pass account_ss58: the account the token resolves to")
    return identity.account_ss58


def delegate_owner(identity: Identity) -> str | None:
    """The ``owner`` query a non-owner sends. An owner omits it."""
    if identity.role == OWNER:
        return None
    return identity.account_ss58


def manager_owner(identity: Identity) -> str | None:
    """The ``owner`` query for a management call.

    Raises:
        ValueError: If the caller is a reader or writer.
    """
    if identity.role == OWNER:
        return None
    if identity.role != MANAGER:
        raise ValueError("only the owner or a manager can do that")
    return identity.account_ss58


def folder_target_is_hash(value: str) -> bool:
    """True when ``value`` is a listing ``token_hash`` rather than a plaintext token."""
    return len(value) == _TOKEN_HASH_LEN and all(char in "0123456789abcdef" for char in value)


def require_owner_wraps(caps: Capabilities) -> None:
    """Stop before a PUT the server would answer with an ambiguous 404.

    Raises:
        ValueError: If ``share_owner_wrap`` is false.
    """
    if not caps.share_owner_wrap:
        raise ValueError("this server does not accept owner wraps")


def require_member_folder_shares(caps: Capabilities) -> None:
    """Stop a member mint when the server would answer ``folder_not_found``.

    Raises:
        ValueError: If ``member_folder_shares`` is false.
    """
    if not caps.member_folder_shares:
        raise ValueError("this server does not accept folder shares on a shared drive")


def capabilities_or_disabled(run: Runner) -> Capabilities:
    """Read capabilities. A 404 means every flag is false."""
    try:
        found = run(_ops.capabilities())
    except NotFound:
        return Capabilities()
    return _as_capabilities(found)


async def capabilities_or_disabled_async(run: Runner) -> Capabilities:
    """Async twin of :func:`capabilities_or_disabled`."""
    try:
        found = await run(_ops.capabilities())
    except NotFound:
        return Capabilities()
    return _as_capabilities(found)


def _as_capabilities(found: Any) -> Capabilities:
    if not isinstance(found, Capabilities):
        raise errors.InvalidResponse("capabilities response had the wrong shape")
    return found


def _fragment(key: bytes, password: str | None) -> ShareSecret:
    if password is None:
        return ShareSecret(key)
    return ShareSecret(sharing.wrap_share_key(password, key), private=True)


def wire_ttl(value: ShareTtl | str) -> str:
    if isinstance(value, ShareTtl):
        return value.value
    allowed = {item.value for item in ShareTtl}
    if value not in allowed:
        raise ValueError("ttl must be 24h, 7d, 30d, or never")
    return value


def _encrypt(source: PlaintextSource, key: bytes) -> tuple[IO[bytes], int]:
    blob: IO[bytes] = SpooledTemporaryFile(max_size=SPOOL_MAX)  # noqa: SIM115
    written = 0
    try:
        with source.open() as reader:
            for frame in file_cipher.encrypt_stream(reader, key, source.size):
                blob.write(frame)
                written += len(frame)
    except BaseException:
        blob.close()
        raise
    expected = file_cipher.ciphertext_size(source.size)
    if written != expected:
        blob.close()
        raise ValueError(
            f"ciphertext framing disagrees with the plaintext size: "
            f"expected {expected} bytes, encrypted {written}"
        )
    blob.seek(0)
    return blob, written


def _check_wrap_batch(secrets: Sequence[tuple[str, ShareSecret]]) -> None:
    if not secrets:
        raise ValueError("owner wrap needs at least one share")
    if len(secrets) > _MAX_WRAPS:
        raise ValueError(f"owner wrap takes at most {_MAX_WRAPS} shares, got {len(secrets)}")


def _open_one_grant(member_master: str, member_ss58: str, grant_blob: str) -> str | None:
    if not grant_blob:
        return None
    try:
        raw = base64.b64decode(grant_blob, validate=True)
    except ValueError as exc:
        raise DecryptError("grant blob is not standard base64") from exc
    return grant.open_grant(member_master, member_ss58, raw)
