"""Share, folder-share, and shared-drive namespaces for both clients.

The sync and async classes call the same operations. They differ only in
whether they await, including the multi-step file-share upload.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from tempfile import SpooledTemporaryFile
from typing import Any

import httpx

from hippius_drive import _links, _ops, errors
from hippius_drive._upload import SPOOL_MAX, PlaintextSource, reader_over
from hippius_drive._wire import parse_envelope
from hippius_drive.crypto import file_cipher
from hippius_drive.crypto.sharing import ShareSecret
from hippius_drive.models import (
    AcceptedInvite,
    CreatedInvite,
    CreatedShare,
    DriveInvites,
    DriveMember,
    DriveMembers,
    DriveMembership,
    FolderShare,
    FolderSharePage,
    InviteMeta,
    MintedShare,
    OpenedShare,
    OwnerWrapsResult,
    ShareSummary,
    ShareTtl,
)

_HTTP_ERROR = 400
_MEMBER_ROLES = frozenset({"reader", "writer", "manager"})


def _plain(source: Path | bytes) -> PlaintextSource:
    if isinstance(source, Path):
        return PlaintextSource.from_path(source)
    if isinstance(source, bytes):
        return PlaintextSource.from_bytes(source)
    raise ValueError("source must be a path or bytes")


def _read_error(response: httpx.Response) -> None:
    """Raise the typed error for a failed download before any decrypt."""
    if response.status_code < _HTTP_ERROR:
        return
    response.read()
    raw = response.content
    parsed: Any
    if response.headers.get("content-type", "").startswith("application/json") and raw:
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = raw.decode(errors="replace")
    else:
        parsed = raw.decode(errors="replace") if raw else ""
    parse_envelope(response.status_code, parsed)


def _decrypt(response: httpx.Response, key: bytes) -> bytes:
    _read_error(response)
    reader = reader_over(response.iter_bytes())
    return b"".join(file_cipher.decrypt_stream(reader, key))


def _upload_share(run: Any, prepared: _links.ShareBlob, spec: _links.FileShareSpec) -> MintedShare:
    if _links.single_shot(prepared, spec):
        metadata = json.dumps(_links.file_share_metadata(prepared, spec, None)).encode()
        return run(_ops.create_share(metadata, prepared.read_all()))
    return _upload_share_chunks(run, prepared, spec)


def _upload_share_chunks(
    run: Any, prepared: _links.ShareBlob, spec: _links.FileShareSpec
) -> MintedShare:
    total = _links.chunk_count(prepared.ciphertext_size)
    body = _links.file_share_metadata(prepared, spec, total)
    minted = run(_ops.init_share(body))
    for index, chunk in enumerate(prepared.chunks()):
        run(_ops.put_share_chunk(minted.share_token, index, chunk))
    return run(_ops.complete_share(minted.share_token))


def _check_role(role: str) -> str:
    if role not in _MEMBER_ROLES:
        raise ValueError("role must be reader, writer, or manager")
    return role


class ShareOps:
    """File shares: a fresh ciphertext and a console URL."""

    def __init__(self, client: Any) -> None:
        """Bind to the client that runs the requests.

        Args:
            client: The owning client.
        """
        self._client = client

    def create(self, source: Path | bytes, spec: _links.FileShareSpec) -> CreatedShare:
        """Encrypt ``source`` under a new key and return a recipient URL.

        A password is checked before any upload. The URL's fragment is the key
        (``#k=``) or its wrap (``#p=``) and is not sent to the server.

        Args:
            source: A file path or the plaintext bytes.
            spec: Filename, ttl, mime type, and optional password.

        Returns:
            The token, the URL, and the expiry.
        """
        prepared = _links.prepare_file_share(_plain(source), spec)
        try:
            minted = _upload_share(self._client.run, prepared, spec)
            return _links.finish_file_share(minted, prepared, spec)
        finally:
            prepared.close()

    def list(self) -> Sequence[ShareSummary]:
        """List this account's file shares."""
        return self._client.run(_ops.list_shares())

    def revoke(self, token: str) -> None:
        """Revoke a file share. Unknown tokens are ``NotFound``.

        Args:
            token: The plaintext share token.
        """
        self._client.run(_ops.revoke_share(token))

    def update_ttl(self, token: str, ttl: ShareTtl | str) -> str | None:
        """Change when a file share expires, without re-uploading it.

        Args:
            token: The plaintext share token.
            ttl: ``24h``, ``7d``, ``30d``, or ``never``.

        Returns:
            The new expiry, or None when the share does not expire.
        """
        minted = self._client.run(_ops.update_share_ttl(token, _links.wire_ttl(ttl)))
        return minted.expires_at

    def put_owner_wraps(
        self,
        master_mnemonic: str,
        secrets: Sequence[tuple[str, ShareSecret]],
        *,
        account_ss58: str | None = None,
    ) -> OwnerWrapsResult:
        """Upload wraps so another device can rebuild these file-share URLs.

        Args:
            master_mnemonic: The minter's master phrase.
            secrets: ``(share_token, fragment secret)`` pairs from create.
            account_ss58: The account the token resolves to. Required when this
                client is a member of someone else's drive.

        Returns:
            How many rows the server stored.
        """
        caps = _links.capabilities_or_disabled(self._client.run)
        _links.require_owner_wraps(caps)
        account = _links.wrap_account(self._client.identity, account_ss58)
        entries = _links.file_owner_wrap_entries(master_mnemonic, account, secrets)
        return self._client.run(_ops.put_file_owner_wraps(entries))

    def open(self, share_url: str, *, password: str | None = None) -> OpenedShare:
        """Download and decrypt a file-share URL. No bearer token is sent.

        Args:
            share_url: A URL returned by :meth:`create`.
            password: Required when the URL is a ``#p=`` link.

        Returns:
            The filename and plaintext.
        """
        token, key = _links.share_key_from_url(share_url, password, folder=False)
        meta = self._client.run(_ops.share_meta(token))
        with self._client.transport.stream(_ops.share_blob(token)) as response:
            data = _decrypt(response, key)
        filename = _links.decode_share_filename(meta.filename_ct, meta.filename_nonce, key)
        return OpenedShare(filename, meta.mime_type, data, meta.expires_at)


class FolderShareOps:
    """Folder shares: a token scoped to a drive prefix, no upload."""

    def __init__(self, client: Any) -> None:
        """Bind to the client that runs the requests.

        Args:
            client: The owning client.
        """
        self._client = client

    def create(self, spec: _links.FolderShareSpec) -> CreatedShare:
        """Mint a link to an existing drive prefix.

        The fragment key is this drive's file key. A member names the owner and
        checks ``member_folder_shares`` first, so a flag-off server is not
        confused with a missing drive.

        Args:
            spec: Prefix, display name, ttl, and optional password.

        Returns:
            The token, the URL, and the expiry.
        """
        identity = self._client.identity
        body = _links.folder_share_body(identity, spec)
        if identity.role != "owner":
            caps = _links.capabilities_or_disabled(self._client.run)
            _links.require_member_folder_shares(caps)
        secret = _links.folder_share_secret(identity, spec)
        minted = self._client.run(_ops.create_folder_share(body))
        return _links.finish_folder_share(minted, secret, spec)

    def list(self) -> Sequence[FolderShare]:
        """List folder shares this account controls."""
        return self._client.run(_ops.list_folder_shares())

    def revoke(self, token_or_hash: str) -> None:
        """Revoke a folder share by plaintext token or by ``token_hash``.

        Args:
            token_or_hash: The token from create, or the 64-hex hash from list.
        """
        if _links.folder_target_is_hash(token_or_hash):
            self._require_hash_routes()
            self._client.run(_ops.revoke_folder_share_by_hash(token_or_hash))
            return
        self._client.run(_ops.revoke_folder_share(token_or_hash))

    def update_ttl(self, token_or_hash: str, ttl: ShareTtl | str) -> str | None:
        """Change a folder share's expiry.

        Args:
            token_or_hash: The token from create, or the 64-hex hash from list.
            ttl: ``24h``, ``7d``, ``30d``, or ``never``.

        Returns:
            The new expiry, or None when the share does not expire.
        """
        wire = _links.wire_ttl(ttl)
        if _links.folder_target_is_hash(token_or_hash):
            self._require_hash_routes()
            minted = self._client.run(_ops.update_folder_share_ttl_by_hash(token_or_hash, wire))
        else:
            minted = self._client.run(_ops.update_folder_share_ttl(token_or_hash, wire))
        return minted.expires_at

    def put_owner_wraps(
        self,
        master_mnemonic: str,
        secrets: Sequence[tuple[str, ShareSecret]],
        *,
        account_ss58: str | None = None,
    ) -> OwnerWrapsResult:
        """Upload wraps so another device can rebuild these folder-share URLs.

        The wrap carries the plaintext token, because the listing returns only
        ``token_hash``.

        Args:
            master_mnemonic: The minter's master phrase.
            secrets: ``(plaintext token, fragment secret)`` pairs.
            account_ss58: The account the token resolves to.

        Returns:
            How many rows the server stored.
        """
        caps = _links.capabilities_or_disabled(self._client.run)
        _links.require_owner_wraps(caps)
        account = _links.wrap_account(self._client.identity, account_ss58)
        entries = _links.folder_owner_wrap_entries(master_mnemonic, account, secrets)
        return self._client.run(_ops.put_folder_owner_wraps(entries))

    def browse(
        self,
        share_url: str,
        path: str = "",
        *,
        password: str | None = None,
        offset: int = 0,
        limit: int | None = None,
    ) -> FolderSharePage:
        """List one directory inside a folder share. No bearer token is sent.

        Args:
            share_url: A URL returned by :meth:`create`.
            path: Directory relative to the share prefix.
            password: Required when the URL is a ``#p=`` link.
            offset: Starting file index.
            limit: Page size.

        Returns:
            The page. Page on ``has_more``.
        """
        token, _key = _links.share_key_from_url(share_url, password, folder=True)
        relative = _links.recipient_path(path)
        return self._client.run(_ops.folder_share_browse(token, relative, offset, limit))

    def get(self, share_url: str, path: str, *, password: str | None = None) -> bytes:
        """Download and decrypt one file inside a folder share.

        Args:
            share_url: A URL returned by :meth:`create`.
            path: File path relative to the share prefix.
            password: Required when the URL is a ``#p=`` link.

        Returns:
            The plaintext.
        """
        token, key = _links.share_key_from_url(share_url, password, folder=True)
        request = _ops.folder_share_blob(token, _links.recipient_path(path))
        with self._client.transport.stream(request) as response:
            return _decrypt(response, key)

    def _require_hash_routes(self) -> None:
        caps = _links.capabilities_or_disabled(self._client.run)
        if not caps.folder_share_revoke_by_hash:
            raise ValueError("this server does not address folder shares by token_hash")


class DriveOps:
    """Shared-drive invites and membership."""

    def __init__(self, client: Any) -> None:
        """Bind to the client that runs the requests.

        Args:
            client: The owning client.
        """
        self._client = client

    def create_invite(self, spec: _links.InviteSpec) -> CreatedInvite:
        """Mint an invite URL. Seal-back is best-effort and does not unmint.

        Args:
            spec: Folder phrase, role, lifetime, and console origin.

        Returns:
            The token, the URL, and the invite id.
        """
        body = _links.invite_body(self._client.identity, spec)
        minted = self._client.run(_ops.create_drive_invite(body))
        created, sealed = _links.finish_invite(minted, spec)
        self._seal(created, sealed)
        return created

    def invites(self) -> DriveInvites:
        """List this drive's invites. Readers and writers cannot."""
        owner = _links.manager_owner(self._client.identity)
        return self._client.run(_ops.list_drive_invites(self._client.identity.folder_hash, owner))

    def revoke_invite(self, invite_id: str) -> None:
        """Revoke an invite by the id from :meth:`invites` or :meth:`create_invite`.

        Args:
            invite_id: Blake3 hex of the invite token.
        """
        owner = _links.manager_owner(self._client.identity)
        folder = self._client.identity.folder_hash
        self._client.run(_ops.revoke_drive_invite(folder, invite_id, owner))

    def members(self) -> DriveMembers:
        """List members. A member's request names the owner so the drive is unique."""
        owner = _links.delegate_owner(self._client.identity)
        return self._client.run(_ops.list_drive_members(self._client.identity.folder_hash, owner))

    def remove_member(self, member_ss58: str) -> None:
        """Remove a member. Self-leave is :meth:`leave`.

        Args:
            member_ss58: The member to remove.
        """
        owner = _links.manager_owner(self._client.identity)
        folder = self._client.identity.folder_hash
        self._client.run(_ops.remove_drive_member(folder, member_ss58, owner))

    def leave(self, member_ss58: str) -> None:
        """Leave this drive. ``owner`` is always sent, even for a manager.

        Args:
            member_ss58: The caller's own account, the one the token resolves to.
        """
        folder = self._client.identity.folder_hash
        owner = self._client.identity.account_ss58
        self._client.run(_ops.remove_drive_member(folder, member_ss58, owner))

    def change_role(self, member_ss58: str, role: str) -> DriveMember:
        """Change a member's role. The new role applies on their next request.

        Args:
            member_ss58: The member to change.
            role: ``reader``, ``writer``, or ``manager``.

        Returns:
            The updated member.
        """
        owner = _links.manager_owner(self._client.identity)
        folder = self._client.identity.folder_hash
        return self._client.run(
            _ops.change_member_role(folder, member_ss58, _check_role(role), owner)
        )

    def invite_meta(self, token: str) -> InviteMeta:
        """Preview an invite. The bearer token is not sent.

        Args:
            token: The plaintext invite token, or a full invite URL.
        """
        return self._client.run(_ops.invite_meta(_plain_invite_token(token)))

    def accept(self, invite_url: str, member_master: str, *, member_ss58: str) -> AcceptedInvite:
        """Join a drive and seal its folder phrase under the member's master.

        Args:
            invite_url: The URL from :meth:`create_invite`.
            member_master: The member's master phrase. It is not the drive key.
            member_ss58: The account ``member_master``'s token resolves to.

        Returns:
            The drive identity and the folder phrase for ``Identity.for_shared_drive``.
        """
        token, entropy = _links.grant.parse_invite_url(invite_url)
        phrase = _links.grant.phrase_from_entropy(entropy)
        blob = _links.accept_grant(member_master, member_ss58, phrase)
        result = self._client.run(_ops.accept_invite(token, blob))
        return _links.accepted_invite(result, phrase)

    def memberships(self, member_master: str, *, member_ss58: str) -> Sequence[DriveMembership]:
        """List joined drives and open each grant with the member's master phrase.

        Args:
            member_master: The member's master phrase.
            member_ss58: The account that phrase's token resolves to.

        Returns:
            One entry per drive, with the folder phrase when a grant was stored.
        """
        page = self._client.run(_ops.list_memberships())
        return _links.open_memberships(member_master, member_ss58, page)

    def _seal(self, created: CreatedInvite, sealed: str) -> None:
        if not sealed:
            return
        owner = _links.manager_owner(self._client.identity)
        folder = self._client.identity.folder_hash
        try:
            self._client.run(_ops.seal_drive_invite(folder, created.invite_id, sealed, owner))
        except errors.DriveError:
            return


def _plain_invite_token(token: str) -> str:
    if token.startswith("https://"):
        parsed, _entropy = _links.grant.parse_invite_url(token)
        return parsed
    return token


class AsyncShareOps:
    """Async twin of :class:`ShareOps`."""

    def __init__(self, client: Any) -> None:
        """Bind to the client that runs the requests.

        Args:
            client: The owning client.
        """
        self._client = client

    async def create(self, source: Path | bytes, spec: _links.FileShareSpec) -> CreatedShare:
        """Async twin of :meth:`ShareOps.create`."""
        prepared = _links.prepare_file_share(_plain(source), spec)
        try:
            minted = await _upload_share_async(self._client.run, prepared, spec)
            return _links.finish_file_share(minted, prepared, spec)
        finally:
            prepared.close()

    async def list(self) -> Sequence[ShareSummary]:
        """Async twin of :meth:`ShareOps.list`."""
        return await self._client.run(_ops.list_shares())

    async def revoke(self, token: str) -> None:
        """Async twin of :meth:`ShareOps.revoke`."""
        await self._client.run(_ops.revoke_share(token))

    async def update_ttl(self, token: str, ttl: ShareTtl | str) -> str | None:
        """Async twin of :meth:`ShareOps.update_ttl`."""
        minted = await self._client.run(_ops.update_share_ttl(token, _links.wire_ttl(ttl)))
        return minted.expires_at

    async def put_owner_wraps(
        self,
        master_mnemonic: str,
        secrets: Sequence[tuple[str, ShareSecret]],
        *,
        account_ss58: str | None = None,
    ) -> OwnerWrapsResult:
        """Async twin of :meth:`ShareOps.put_owner_wraps`."""
        caps = await _links.capabilities_or_disabled_async(self._client.run)
        _links.require_owner_wraps(caps)
        account = _links.wrap_account(self._client.identity, account_ss58)
        entries = _links.file_owner_wrap_entries(master_mnemonic, account, secrets)
        return await self._client.run(_ops.put_file_owner_wraps(entries))

    async def open(self, share_url: str, *, password: str | None = None) -> OpenedShare:
        """Async twin of :meth:`ShareOps.open`."""
        token, key = _links.share_key_from_url(share_url, password, folder=False)
        meta = await self._client.run(_ops.share_meta(token))
        async with self._client.transport.stream(_ops.share_blob(token)) as response:
            data = await _decrypt_async(response, key)
        filename = _links.decode_share_filename(meta.filename_ct, meta.filename_nonce, key)
        return OpenedShare(filename, meta.mime_type, data, meta.expires_at)


class AsyncFolderShareOps:
    """Async twin of :class:`FolderShareOps`."""

    def __init__(self, client: Any) -> None:
        """Bind to the client that runs the requests.

        Args:
            client: The owning client.
        """
        self._client = client

    async def create(self, spec: _links.FolderShareSpec) -> CreatedShare:
        """Async twin of :meth:`FolderShareOps.create`."""
        identity = self._client.identity
        body = _links.folder_share_body(identity, spec)
        if identity.role != "owner":
            caps = await _links.capabilities_or_disabled_async(self._client.run)
            _links.require_member_folder_shares(caps)
        secret = _links.folder_share_secret(identity, spec)
        minted = await self._client.run(_ops.create_folder_share(body))
        return _links.finish_folder_share(minted, secret, spec)

    async def list(self) -> Sequence[FolderShare]:
        """Async twin of :meth:`FolderShareOps.list`."""
        return await self._client.run(_ops.list_folder_shares())

    async def revoke(self, token_or_hash: str) -> None:
        """Async twin of :meth:`FolderShareOps.revoke`."""
        if _links.folder_target_is_hash(token_or_hash):
            await self._require_hash_routes_async()
            await self._client.run(_ops.revoke_folder_share_by_hash(token_or_hash))
            return
        await self._client.run(_ops.revoke_folder_share(token_or_hash))

    async def update_ttl(self, token_or_hash: str, ttl: ShareTtl | str) -> str | None:
        """Async twin of :meth:`FolderShareOps.update_ttl`."""
        wire = _links.wire_ttl(ttl)
        if _links.folder_target_is_hash(token_or_hash):
            await self._require_hash_routes_async()
            op = _ops.update_folder_share_ttl_by_hash(token_or_hash, wire)
        else:
            op = _ops.update_folder_share_ttl(token_or_hash, wire)
        minted = await self._client.run(op)
        return minted.expires_at

    async def put_owner_wraps(
        self,
        master_mnemonic: str,
        secrets: Sequence[tuple[str, ShareSecret]],
        *,
        account_ss58: str | None = None,
    ) -> OwnerWrapsResult:
        """Async twin of :meth:`FolderShareOps.put_owner_wraps`."""
        caps = await _links.capabilities_or_disabled_async(self._client.run)
        _links.require_owner_wraps(caps)
        account = _links.wrap_account(self._client.identity, account_ss58)
        entries = _links.folder_owner_wrap_entries(master_mnemonic, account, secrets)
        return await self._client.run(_ops.put_folder_owner_wraps(entries))

    async def browse(
        self,
        share_url: str,
        path: str = "",
        *,
        password: str | None = None,
        offset: int = 0,
        limit: int | None = None,
    ) -> FolderSharePage:
        """Async twin of :meth:`FolderShareOps.browse`."""
        token, _key = _links.share_key_from_url(share_url, password, folder=True)
        relative = _links.recipient_path(path)
        return await self._client.run(_ops.folder_share_browse(token, relative, offset, limit))

    async def get(self, share_url: str, path: str, *, password: str | None = None) -> bytes:
        """Async twin of :meth:`FolderShareOps.get`."""
        token, key = _links.share_key_from_url(share_url, password, folder=True)
        request = _ops.folder_share_blob(token, _links.recipient_path(path))
        async with self._client.transport.stream(request) as response:
            return await _decrypt_async(response, key)

    async def _require_hash_routes_async(self) -> None:
        caps = await _links.capabilities_or_disabled_async(self._client.run)
        if not caps.folder_share_revoke_by_hash:
            raise ValueError("this server does not address folder shares by token_hash")


class AsyncDriveOps:
    """Async twin of :class:`DriveOps`."""

    def __init__(self, client: Any) -> None:
        """Bind to the client that runs the requests.

        Args:
            client: The owning client.
        """
        self._client = client

    async def create_invite(self, spec: _links.InviteSpec) -> CreatedInvite:
        """Async twin of :meth:`DriveOps.create_invite`."""
        body = _links.invite_body(self._client.identity, spec)
        minted = await self._client.run(_ops.create_drive_invite(body))
        created, sealed = _links.finish_invite(minted, spec)
        await self._seal_async(created, sealed)
        return created

    async def invites(self) -> DriveInvites:
        """Async twin of :meth:`DriveOps.invites`."""
        owner = _links.manager_owner(self._client.identity)
        folder = self._client.identity.folder_hash
        return await self._client.run(_ops.list_drive_invites(folder, owner))

    async def revoke_invite(self, invite_id: str) -> None:
        """Async twin of :meth:`DriveOps.revoke_invite`."""
        owner = _links.manager_owner(self._client.identity)
        folder = self._client.identity.folder_hash
        await self._client.run(_ops.revoke_drive_invite(folder, invite_id, owner))

    async def members(self) -> DriveMembers:
        """Async twin of :meth:`DriveOps.members`."""
        owner = _links.delegate_owner(self._client.identity)
        folder = self._client.identity.folder_hash
        return await self._client.run(_ops.list_drive_members(folder, owner))

    async def remove_member(self, member_ss58: str) -> None:
        """Async twin of :meth:`DriveOps.remove_member`."""
        owner = _links.manager_owner(self._client.identity)
        folder = self._client.identity.folder_hash
        await self._client.run(_ops.remove_drive_member(folder, member_ss58, owner))

    async def leave(self, member_ss58: str) -> None:
        """Async twin of :meth:`DriveOps.leave`."""
        folder = self._client.identity.folder_hash
        owner = self._client.identity.account_ss58
        await self._client.run(_ops.remove_drive_member(folder, member_ss58, owner))

    async def change_role(self, member_ss58: str, role: str) -> DriveMember:
        """Async twin of :meth:`DriveOps.change_role`."""
        owner = _links.manager_owner(self._client.identity)
        folder = self._client.identity.folder_hash
        return await self._client.run(
            _ops.change_member_role(folder, member_ss58, _check_role(role), owner)
        )

    async def invite_meta(self, token: str) -> InviteMeta:
        """Async twin of :meth:`DriveOps.invite_meta`."""
        return await self._client.run(_ops.invite_meta(_plain_invite_token(token)))

    async def accept(
        self, invite_url: str, member_master: str, *, member_ss58: str
    ) -> AcceptedInvite:
        """Async twin of :meth:`DriveOps.accept`."""
        token, entropy = _links.grant.parse_invite_url(invite_url)
        phrase = _links.grant.phrase_from_entropy(entropy)
        blob = _links.accept_grant(member_master, member_ss58, phrase)
        result = await self._client.run(_ops.accept_invite(token, blob))
        return _links.accepted_invite(result, phrase)

    async def memberships(
        self, member_master: str, *, member_ss58: str
    ) -> Sequence[DriveMembership]:
        """Async twin of :meth:`DriveOps.memberships`."""
        page = await self._client.run(_ops.list_memberships())
        return _links.open_memberships(member_master, member_ss58, page)

    async def _seal_async(self, created: CreatedInvite, sealed: str) -> None:
        if not sealed:
            return
        owner = _links.manager_owner(self._client.identity)
        folder = self._client.identity.folder_hash
        try:
            await self._client.run(_ops.seal_drive_invite(folder, created.invite_id, sealed, owner))
        except errors.DriveError:
            return


async def _upload_share_async(
    run: Any, prepared: _links.ShareBlob, spec: _links.FileShareSpec
) -> MintedShare:
    if _links.single_shot(prepared, spec):
        metadata = json.dumps(_links.file_share_metadata(prepared, spec, None)).encode()
        return await run(_ops.create_share(metadata, prepared.read_all()))
    total = _links.chunk_count(prepared.ciphertext_size)
    body = _links.file_share_metadata(prepared, spec, total)
    minted = await run(_ops.init_share(body))
    for index, chunk in enumerate(prepared.chunks()):
        await run(_ops.put_share_chunk(minted.share_token, index, chunk))
    return await run(_ops.complete_share(minted.share_token))


async def _decrypt_async(response: httpx.Response, key: bytes) -> bytes:
    if response.status_code >= _HTTP_ERROR:
        await response.aread()
        _read_error(response)
    spool = await _spool(response)
    try:
        return b"".join(file_cipher.decrypt_stream(spool, key))
    finally:
        spool.close()


async def _spool(response: httpx.Response) -> Any:
    spool = SpooledTemporaryFile(max_size=SPOOL_MAX)  # noqa: SIM115
    try:
        async for chunk in response.aiter_bytes():
            spool.write(chunk)
    except BaseException:
        spool.close()
        raise
    spool.seek(0)
    return spool
