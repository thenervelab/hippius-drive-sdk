"""Share, folder-share, and shared-drive namespaces for both clients.

The sync and async classes call the same operations. They differ only in
whether they await, including the multi-step file-share upload.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Sequence
from pathlib import Path
from tempfile import SpooledTemporaryFile
from typing import Any, NoReturn

import httpx

from hippius_drive import _links, _ops, _share_insights, errors
from hippius_drive._upload import SPOOL_MAX, PlaintextSource, reader_over
from hippius_drive._wire import check_comment_id, parse_envelope
from hippius_drive.crypto import file_cipher, invite_link
from hippius_drive.crypto.comments import CommentMention
from hippius_drive.crypto.sharing import ShareSecret
from hippius_drive.models import (
    AcceptedInvite,
    CommentAuthor,
    CreatedInvite,
    CreatedShare,
    DriveInvites,
    DriveMember,
    DriveMembers,
    DriveMembership,
    FolderShare,
    FolderSharePage,
    InviteMeta,
    InviteMint,
    MintedShare,
    OpenedShare,
    OwnerWrapsResult,
    PostedComment,
    ReactionMoment,
    ShareComment,
    ShareInsights,
    ShareReactions,
    ShareSettings,
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
        token, key = _links.share_key_from_url(share_url, password)
        meta = self._client.run(_ops.share_meta(token))
        with self._client.transport.stream(_ops.share_blob(token)) as response:
            data = _decrypt(response, key)
        filename = _links.decode_share_filename(meta.filename_ct, meta.filename_nonce, key)
        return OpenedShare(filename, meta.mime_type, data, meta.expires_at)

    def recover_url(
        self,
        token: str,
        master_mnemonic: str,
        *,
        account_ss58: str | None = None,
        console_base_url: str = _links.DEFAULT_CONSOLE,
    ) -> str:
        """Rebuild one of this account's file-share URLs from its owner wrap.

        The console stores an owner wrap with every link it mints; a link
        minted by :meth:`create` has one only after :meth:`put_owner_wraps`.
        A ``#p=`` link comes back as ``#p=`` and still needs its password.

        Args:
            token: The plaintext share token, from :meth:`list`.
            master_mnemonic: The minter's master phrase.
            account_ss58: The account the token resolves to. Required when this
                client is a member of someone else's drive.
            console_base_url: Origin for the rebuilt URL.

        Returns:
            The recipient URL. It is the key: do not log it.
        """
        account = _links.wrap_account(self._client.identity, account_ss58)
        return _share_insights.owner_share_url(
            self.list(),
            token,
            master_mnemonic,
            account_ss58=account,
            console_base_url=console_base_url,
        )

    def update_settings(
        self,
        token: str,
        *,
        insights: bool | None = None,
        comments: bool | None = None,
        reactions: bool | None = None,
    ) -> ShareSettings:
        """Turn a file share's insights, comments, or reactions on or off.

        The current switches are on each :meth:`list` row (``settings``).
        Turning one on can raise :class:`~hippius_drive.errors.PaidPlanRequired`
        on the Free Drive plan, and ``ServerError`` ``billing_unavailable``
        when the server cannot read the plan; retry that one later.

        Args:
            token: The plaintext share token.
            insights: Record views.
            comments: Let viewers post comments.
            reactions: Let viewers react.

        Returns:
            All three switches as they now stand.

        Raises:
            ValueError: If no switch is named, or the server has ``share_insights`` off.
        """
        body = _share_insights.settings_body(
            insights=insights, comments=comments, reactions=reactions
        )
        _share_insights.require_insights(_links.capabilities_or_disabled(self._client.run))
        return self._client.run(_ops.update_share_settings(token, body))

    def insights(self, token: str) -> ShareInsights:
        """Read a file share's views and watch time. Owner only.

        Viewer names stay sealed; open them with :meth:`viewer_names`.

        Args:
            token: The plaintext share token.

        Returns:
            The free-plan counts, or the paid-plan detail.

        Raises:
            ValueError: If the server has ``share_insights`` off.
        """
        _share_insights.require_insights(_links.capabilities_or_disabled(self._client.run))
        return self._client.run(_ops.share_insights(token))

    def viewer_names(
        self, insights: ShareInsights, share_url: str, *, password: str | None = None
    ) -> dict[str, str]:
        """Decrypt the viewer names in :meth:`insights` with the link's key. No request.

        Args:
            insights: From :meth:`insights` on the same share.
            share_url: The share's recipient URL; its fragment is the key.
            password: Required when the URL is a ``#p=`` link.

        Returns:
            Names by ``viewer_id``. A viewer without a name, or whose name
            does not open, is absent.
        """
        token, key = _share_insights.link_key(share_url, password)
        return _share_insights.viewer_names(insights, token, key)

    def comments(self, share_url: str, *, password: str | None = None) -> Sequence[ShareComment]:
        """Read and decrypt every comment on a file share, oldest first.

        Readable by anyone with the link, whatever the ``comments`` switch.
        A comment that does not open under the link's key comes back with
        ``text=None`` rather than failing the whole listing.

        Args:
            share_url: The recipient URL; its fragment is the key.
            password: Required when the URL is a ``#p=`` link.

        Returns:
            Comments and replies; group replies by ``parent_id``. A comment
            that tags this account has ``mentions_me``. When one tags the
            owner and the thread does not show whether you are the owner,
            the share listing is read once to tell; if this account may not
            list shares (``Forbidden``), owner mentions are left unmarked.

        Raises:
            ValueError: If the server has ``share_comments`` off.
        """
        token, key = _share_insights.link_key(share_url, password)
        thread = self._thread(token, key)
        owns = _share_insights.mentions_owner(thread) and self._owns_or_unknown(thread, token)
        return _share_insights.mark_mentions(thread, reader_owns_link=owns)

    def _owns_or_unknown(self, thread: Sequence[ShareComment], token: str) -> bool:
        """Whether this account owns the link; False when it may not list its shares."""
        if _share_insights.thread_shows_owner(thread):
            return True
        try:
            return _share_insights.owns_link(self.list(), token)
        except errors.Forbidden:
            return False

    def mention_candidates(
        self, share_url: str, *, password: str | None = None
    ) -> Sequence[CommentMention]:
        """Who this account can tag in a comment on a file share, as the console offers them.

        The owner first (unless you are the owner), then everyone else who
        commented under a name, newest first. Pass the ones you tag to
        :meth:`post_comment` as ``mentions``, with ``@`` and their ``name``
        in the text. Reads the comments and the share listing.

        Args:
            share_url: The recipient URL; its fragment is the key.
            password: Required when the URL is a ``#p=`` link.

        Raises:
            ValueError: If the server has ``share_comments`` off.
        """
        token, key = _share_insights.link_key(share_url, password)
        thread = self._thread(token, key)
        owns = _share_insights.thread_shows_owner(thread) or _share_insights.owns_link(
            self.list(), token
        )
        return _share_insights.mention_candidates(thread, reader_owns_link=owns)

    def _thread(self, token: str, key: bytes) -> Sequence[ShareComment]:
        _share_insights.require_comments(_links.capabilities_or_disabled(self._client.run))
        found: list[ShareComment] = []
        seen: set[str] = set()
        after: str | None = None
        while True:
            page = self._client.run(_ops.share_comments(token, after))
            found.extend(_share_insights.open_rows(page.comments, token, key))
            after = _share_insights.next_cursor(page, seen)
            if after is None:
                return _share_insights.mark_claimed_names(found)

    # Each option is independent and keyword-only, and the common call is
    # post_comment(url, "text"); a spec object would make that two lines.
    def post_comment(  # noqa: PLR0913
        self,
        share_url: str,
        text: str,
        *,
        password: str | None = None,
        parent_id: str | None = None,
        at_ms: int | None = None,
        author: CommentAuthor | None = None,
        mentions: Sequence[CommentMention] = (),
    ) -> PostedComment:
        """Post a comment, encrypted under the link's key. Anonymous without ``author``.

        Never retried: a lost response could otherwise post it twice. The
        owner turning comments off is ``Forbidden`` ``comments-off``; an
        account the owner blocked gets ``Forbidden`` ``blocked``.

        Args:
            share_url: The recipient URL; its fragment is the key.
            text: Up to 2,000 characters.
            password: Required when the URL is a ``#p=`` link.
            parent_id: Reply to this top-level comment.
            at_ms: The moment of the video the comment points at. Not on a reply.
            author: Post under this name, counted in the owner's insights
                under a viewer id derived from its secret.
            mentions: Who the text tags, from :meth:`mention_candidates`.
                Each one's ``@`` and ``name`` must be in ``text``.

        Returns:
            The new comment's id.

        Raises:
            ValueError: For bad input, or a server without the needed capability.
        """
        token, key = _share_insights.link_key(share_url, password)
        draft = _share_insights.CommentDraft(
            text=text, parent_id=parent_id, at_ms=at_ms, author=author, mentions=mentions
        )
        body = _share_insights.comment_body(token, key, draft)
        caps = _links.capabilities_or_disabled(self._client.run)
        _share_insights.require_comments(caps)
        _share_insights.require_replies(caps, parent_id)
        return self._client.run(_ops.post_share_comment(token, body))

    def delete_comment(self, token: str, comment_id: str) -> None:
        """Delete a comment: any on this account's link, or this account's own.

        A timeout or 502 is retried; if the first attempt had already deleted
        the comment, the retry answers ``NotFound``.

        Args:
            token: The plaintext share token.
            comment_id: The comment's ``id``.

        Raises:
            ValueError: If the id is not a comment id, or the server has
                ``share_comments`` off.
        """
        check_comment_id(comment_id)
        _share_insights.require_comments(_links.capabilities_or_disabled(self._client.run))
        self._client.run(_ops.delete_share_comment(token, comment_id))

    def reactions(self, token: str) -> ShareReactions:
        """Read a file share's reaction counts and this account's own.

        Args:
            token: The plaintext share token.

        Raises:
            ValueError: If the server has ``share_comments`` off.
        """
        _share_insights.require_comments(_links.capabilities_or_disabled(self._client.run))
        return self._client.run(_ops.share_reactions(token))

    def react(self, token: str, emoji: str) -> None:
        """Add this account's reaction. Adding it again changes nothing.

        The owner turning reactions off is ``Forbidden`` ``reactions-off``;
        an author the owner blocked gets ``Forbidden`` ``blocked``.

        Args:
            token: The plaintext share token.
            emoji: One of :data:`hippius_drive.REACTIONS`.

        Raises:
            ValueError: For another emoji, or a server with ``share_comments`` off.
        """
        emoji = _share_insights.check_reaction(emoji)
        _share_insights.require_comments(_links.capabilities_or_disabled(self._client.run))
        self._client.run(_ops.put_share_reaction(token, emoji))

    def unreact(self, token: str, emoji: str) -> None:
        """Take this account's reaction back, with every moment sent with it.

        Works with reactions off and for a blocked author.

        Args:
            token: The plaintext share token.
            emoji: One of :data:`hippius_drive.REACTIONS`.

        Raises:
            ValueError: For another emoji, or a server with ``share_comments`` off.
        """
        emoji = _share_insights.check_reaction(emoji)
        _share_insights.require_comments(_links.capabilities_or_disabled(self._client.run))
        self._client.run(_ops.delete_share_reaction(token, emoji))

    def react_at(self, token: str, emoji: str, at_ms: int) -> None:
        """Send this account's reaction at a moment of the video.

        Each call stores one more moment, so it is never retried. It also
        adds the reaction, as :meth:`react` does. :meth:`unreact` takes the
        reaction and all its moments back; one moment cannot be removed.
        Once the link holds 5,000 moments, or this account holds 200 on it
        (all emoji together), it is ``Conflict`` ``moment-limit`` and nothing
        is stored, not even the reaction.

        Args:
            token: The plaintext share token.
            emoji: One of :data:`hippius_drive.REACTIONS`.
            at_ms: The moment, from 0 to seven days in milliseconds.

        Raises:
            ValueError: For bad input, or a server with ``share_reaction_moments`` off.
        """
        emoji = _share_insights.check_reaction(emoji)
        _share_insights.check_moment(at_ms)
        _share_insights.require_moments(_links.capabilities_or_disabled(self._client.run))
        self._client.run(_ops.post_reaction_moment(token, emoji, at_ms))

    def reaction_moments(self, token: str) -> Sequence[ReactionMoment]:
        """Read every reaction moment of a file share, by moment. Anonymous.

        Args:
            token: The plaintext share token.

        Raises:
            ValueError: If the server has ``share_reaction_moments`` off.
        """
        _share_insights.require_moments(_links.capabilities_or_disabled(self._client.run))
        return self._client.run(_ops.share_reaction_moments(token)).moments

    def block_author(self, token: str, comment_id: str) -> None:
        """Stop the author of a comment on this account's link from commenting and reacting.

        The server never says who the author is. What they wrote stays until
        it is deleted. The block lasts after the comment is deleted, and can
        only be lifted through a comment of theirs still on the link.

        Args:
            token: The plaintext share token.
            comment_id: A comment by that author.

        Raises:
            ValueError: If the id is not a comment id, or the server has
                ``share_comments`` off.
        """
        check_comment_id(comment_id)
        _share_insights.require_comments(_links.capabilities_or_disabled(self._client.run))
        self._client.run(_ops.block_comment_author(token, comment_id))

    def unblock_author(self, token: str, comment_id: str) -> None:
        """Lift a block through any comment of that author still on the link.

        It clears the ``blocked`` mark of ``comment_id`` only: a second
        comment the same author was blocked through keeps its mark.

        Args:
            token: The plaintext share token.
            comment_id: A comment by that author.

        Raises:
            ValueError: If the id is not a comment id, or the server has
                ``share_comments`` off.
        """
        check_comment_id(comment_id)
        _share_insights.require_comments(_links.capabilities_or_disabled(self._client.run))
        self._client.run(_ops.unblock_comment_author(token, comment_id))

    def mark_insights_seen(self, token: str) -> None:
        """Restart the link's ``new_views`` and ``new_comments`` in :meth:`list` from now.

        The console sends this when the owner opens a link's Insights;
        :meth:`insights` does not, so reading stays free of side effects.

        Args:
            token: The plaintext share token.

        Raises:
            ValueError: If the server has ``share_listing_counts`` off.
        """
        caps = _links.capabilities_or_disabled(self._client.run)
        _share_insights.require_listing_counts(caps)
        self._client.run(_ops.mark_share_insights_seen(token))


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

        The fragment is a fresh link secret (``#s=``, ``#sp=`` with a
        password), never the drive key; the server keeps the drive key sealed
        under it. A member names the owner and checks ``member_folder_shares``
        first, so a flag-off server is not confused with a missing drive.

        Args:
            spec: Prefix, display name, ttl, and optional password.

        Returns:
            The token, the URL, and the expiry.

        Raises:
            InvalidResponse: If the server did not store the link's envelope.
                The share is revoked first.
        """
        identity = self._client.identity
        body, secret = _links.prepare_folder_share(identity, spec)
        if identity.role != "owner":
            caps = _links.capabilities_or_disabled(self._client.run)
            _links.require_member_folder_shares(caps)
        minted = self._client.run(_ops.create_folder_share(body))
        if not minted.link_envelope:
            self._revoke_unopenable(minted.share_token)
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
        ``token_hash``. Take each secret from the minted URL,
        ``sharing.parse_share_url(created.share_url).secret``: a secret built
        from the drive key would rebuild as a ``#k=`` URL that carries it.

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
            password: Required when the URL is a ``#p=`` or ``#sp=`` link.
            offset: Starting file index.
            limit: Page size.

        Returns:
            The page. Page on ``has_more``.
        """
        link = _links.folder_link_from_url(share_url, password)
        relative = _links.recipient_path(path)
        return self._client.run(_ops.folder_share_browse(link.token, relative, offset, limit))

    def get(self, share_url: str, path: str, *, password: str | None = None) -> bytes:
        """Download and decrypt one file inside a folder share.

        Args:
            share_url: A URL returned by :meth:`create`.
            path: File path relative to the share prefix.
            password: Required when the URL is a ``#p=`` or ``#sp=`` link.

        Returns:
            The plaintext.
        """
        link = _links.folder_link_from_url(share_url, password)
        key = self._file_key(link)
        request = _ops.folder_share_blob(link.token, _links.recipient_path(path))
        with self._client.transport.stream(request) as response:
            return _decrypt(response, key)

    def _require_hash_routes(self) -> None:
        caps = _links.capabilities_or_disabled(self._client.run)
        if not caps.folder_share_revoke_by_hash:
            raise ValueError("this server does not address folder shares by token_hash")

    def _revoke_unopenable(self, token: str) -> NoReturn:
        try:
            self._client.run(_ops.revoke_folder_share(token))
        except errors.DriveError as exc:
            raise _links.envelope_not_stored() from exc
        raise _links.envelope_not_stored()

    def _file_key(self, link: _links.FolderLinkUrl) -> bytes:
        if not link.link_secret:
            return link.material
        proof = _links.folder_link_proof(link)
        found = self._client.run(_ops.folder_link_key(link.token, proof))
        return _links.open_folder_link_key(link, found)


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

        A server that opens link-secret invites gets a ``#i=`` link, whose
        envelope is stored right after the mint; if that fails the invite is
        revoked and the error raised, so a dead link is never returned. An
        older server gets a ``#k=`` link, which carries the drive key itself.

        Args:
            spec: Folder phrase, role, lifetime, and console origin.

        Returns:
            The token, the URL, and the invite id.
        """
        body = _links.invite_body(self._client.identity, spec)
        caps = _links.capabilities_or_disabled(self._client.run)
        if not caps.drive_invite_link_envelopes:
            minted = self._client.run(_ops.create_drive_invite(body))
            created, sealed = _links.finish_invite(minted, spec)
            self._seal(created, sealed)
            return created
        minted = self._client.run(_ops.create_drive_invite(_links.mark_link_secret(body)))
        try:
            created, sealed, envelope = _links.finish_link_invite(minted, spec)
            self._seal(created, sealed)
            stored = self._client.run(self._envelope_op(created, envelope))
            _links.require_stored(stored)
        except (errors.DriveError, ValueError):
            # Without its envelope the link never opens. Revoking is
            # best-effort: an invite left behind expires on its own.
            with contextlib.suppress(errors.DriveError, ValueError):
                self._client.run(self._revoke_op(minted))
            raise
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
            invite_url: An invite URL, ``#k=`` or ``#i=``, whole drive or one
                folder. The anonymous preview is read first; a ``#i=`` link
                then fetches its sealed key.
            member_master: The member's master phrase. It is not the drive key.
            member_ss58: The account ``member_master``'s token resolves to.

        Returns:
            The drive identity and the grant phrase. ``path_prefix`` says which
            ``Identity`` constructor takes it.
        """
        fragment = invite_link.parse_invite_link(invite_url)
        meta = self._client.run(_ops.invite_meta(fragment.token))
        key = fragment.material
        if _links.needs_link_key(fragment):
            proof = _links.link_proof(fragment)
            found = self._client.run(_ops.invite_link_key(fragment.token, proof))
            key = _links.open_link_key(fragment, meta, found)
        phrase = _links.grant.phrase_from_entropy(key)
        blob = _links.accept_grant(member_master, member_ss58, phrase)
        op = _ops.accept_invite(fragment.token, blob, _links.invite_folder(meta))
        result = self._client.run(op)
        return _links.accepted_invite(result, phrase, meta)

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

    def _envelope_op(self, created: CreatedInvite, envelope: dict[str, str]) -> Any:
        owner = _links.manager_owner(self._client.identity)
        folder = self._client.identity.folder_hash
        return _ops.put_invite_link_envelope(folder, created.invite_id, envelope, owner)

    def _revoke_op(self, minted: InviteMint) -> Any:
        owner = _links.manager_owner(self._client.identity)
        folder = self._client.identity.folder_hash
        return _ops.revoke_drive_invite(folder, _links.minted_invite_id(minted), owner)

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
        return invite_link.parse_invite_link(token).token
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
        token, key = _links.share_key_from_url(share_url, password)
        meta = await self._client.run(_ops.share_meta(token))
        async with self._client.transport.stream(_ops.share_blob(token)) as response:
            data = await _decrypt_async(response, key)
        filename = _links.decode_share_filename(meta.filename_ct, meta.filename_nonce, key)
        return OpenedShare(filename, meta.mime_type, data, meta.expires_at)

    async def recover_url(
        self,
        token: str,
        master_mnemonic: str,
        *,
        account_ss58: str | None = None,
        console_base_url: str = _links.DEFAULT_CONSOLE,
    ) -> str:
        """Async twin of :meth:`ShareOps.recover_url`."""
        account = _links.wrap_account(self._client.identity, account_ss58)
        return _share_insights.owner_share_url(
            await self.list(),
            token,
            master_mnemonic,
            account_ss58=account,
            console_base_url=console_base_url,
        )

    async def update_settings(
        self,
        token: str,
        *,
        insights: bool | None = None,
        comments: bool | None = None,
        reactions: bool | None = None,
    ) -> ShareSettings:
        """Async twin of :meth:`ShareOps.update_settings`."""
        body = _share_insights.settings_body(
            insights=insights, comments=comments, reactions=reactions
        )
        caps = await _links.capabilities_or_disabled_async(self._client.run)
        _share_insights.require_insights(caps)
        return await self._client.run(_ops.update_share_settings(token, body))

    async def insights(self, token: str) -> ShareInsights:
        """Async twin of :meth:`ShareOps.insights`."""
        caps = await _links.capabilities_or_disabled_async(self._client.run)
        _share_insights.require_insights(caps)
        return await self._client.run(_ops.share_insights(token))

    def viewer_names(
        self, insights: ShareInsights, share_url: str, *, password: str | None = None
    ) -> dict[str, str]:
        """Same as :meth:`ShareOps.viewer_names`; it makes no request, so it is not async."""
        token, key = _share_insights.link_key(share_url, password)
        return _share_insights.viewer_names(insights, token, key)

    async def comments(
        self, share_url: str, *, password: str | None = None
    ) -> Sequence[ShareComment]:
        """Async twin of :meth:`ShareOps.comments`."""
        token, key = _share_insights.link_key(share_url, password)
        thread = await self._thread(token, key)
        owns = _share_insights.mentions_owner(thread) and await self._owns_or_unknown(thread, token)
        return _share_insights.mark_mentions(thread, reader_owns_link=owns)

    async def _owns_or_unknown(self, thread: Sequence[ShareComment], token: str) -> bool:
        if _share_insights.thread_shows_owner(thread):
            return True
        try:
            return _share_insights.owns_link(await self.list(), token)
        except errors.Forbidden:
            return False

    async def mention_candidates(
        self, share_url: str, *, password: str | None = None
    ) -> Sequence[CommentMention]:
        """Async twin of :meth:`ShareOps.mention_candidates`."""
        token, key = _share_insights.link_key(share_url, password)
        thread = await self._thread(token, key)
        owns = _share_insights.thread_shows_owner(thread) or _share_insights.owns_link(
            await self.list(), token
        )
        return _share_insights.mention_candidates(thread, reader_owns_link=owns)

    async def _thread(self, token: str, key: bytes) -> Sequence[ShareComment]:
        caps = await _links.capabilities_or_disabled_async(self._client.run)
        _share_insights.require_comments(caps)
        found: list[ShareComment] = []
        seen: set[str] = set()
        after: str | None = None
        while True:
            page = await self._client.run(_ops.share_comments(token, after))
            found.extend(_share_insights.open_rows(page.comments, token, key))
            after = _share_insights.next_cursor(page, seen)
            if after is None:
                return _share_insights.mark_claimed_names(found)

    async def post_comment(  # noqa: PLR0913 - see ShareOps.post_comment
        self,
        share_url: str,
        text: str,
        *,
        password: str | None = None,
        parent_id: str | None = None,
        at_ms: int | None = None,
        author: CommentAuthor | None = None,
        mentions: Sequence[CommentMention] = (),
    ) -> PostedComment:
        """Async twin of :meth:`ShareOps.post_comment`."""
        token, key = _share_insights.link_key(share_url, password)
        draft = _share_insights.CommentDraft(
            text=text, parent_id=parent_id, at_ms=at_ms, author=author, mentions=mentions
        )
        body = _share_insights.comment_body(token, key, draft)
        caps = await _links.capabilities_or_disabled_async(self._client.run)
        _share_insights.require_comments(caps)
        _share_insights.require_replies(caps, parent_id)
        return await self._client.run(_ops.post_share_comment(token, body))

    async def delete_comment(self, token: str, comment_id: str) -> None:
        """Async twin of :meth:`ShareOps.delete_comment`."""
        check_comment_id(comment_id)
        caps = await _links.capabilities_or_disabled_async(self._client.run)
        _share_insights.require_comments(caps)
        await self._client.run(_ops.delete_share_comment(token, comment_id))

    async def reactions(self, token: str) -> ShareReactions:
        """Async twin of :meth:`ShareOps.reactions`."""
        caps = await _links.capabilities_or_disabled_async(self._client.run)
        _share_insights.require_comments(caps)
        return await self._client.run(_ops.share_reactions(token))

    async def react(self, token: str, emoji: str) -> None:
        """Async twin of :meth:`ShareOps.react`."""
        emoji = _share_insights.check_reaction(emoji)
        caps = await _links.capabilities_or_disabled_async(self._client.run)
        _share_insights.require_comments(caps)
        await self._client.run(_ops.put_share_reaction(token, emoji))

    async def unreact(self, token: str, emoji: str) -> None:
        """Async twin of :meth:`ShareOps.unreact`."""
        emoji = _share_insights.check_reaction(emoji)
        caps = await _links.capabilities_or_disabled_async(self._client.run)
        _share_insights.require_comments(caps)
        await self._client.run(_ops.delete_share_reaction(token, emoji))

    async def react_at(self, token: str, emoji: str, at_ms: int) -> None:
        """Async twin of :meth:`ShareOps.react_at`."""
        emoji = _share_insights.check_reaction(emoji)
        _share_insights.check_moment(at_ms)
        caps = await _links.capabilities_or_disabled_async(self._client.run)
        _share_insights.require_moments(caps)
        await self._client.run(_ops.post_reaction_moment(token, emoji, at_ms))

    async def reaction_moments(self, token: str) -> Sequence[ReactionMoment]:
        """Async twin of :meth:`ShareOps.reaction_moments`."""
        caps = await _links.capabilities_or_disabled_async(self._client.run)
        _share_insights.require_moments(caps)
        return (await self._client.run(_ops.share_reaction_moments(token))).moments

    async def block_author(self, token: str, comment_id: str) -> None:
        """Async twin of :meth:`ShareOps.block_author`."""
        check_comment_id(comment_id)
        caps = await _links.capabilities_or_disabled_async(self._client.run)
        _share_insights.require_comments(caps)
        await self._client.run(_ops.block_comment_author(token, comment_id))

    async def unblock_author(self, token: str, comment_id: str) -> None:
        """Async twin of :meth:`ShareOps.unblock_author`."""
        check_comment_id(comment_id)
        caps = await _links.capabilities_or_disabled_async(self._client.run)
        _share_insights.require_comments(caps)
        await self._client.run(_ops.unblock_comment_author(token, comment_id))

    async def mark_insights_seen(self, token: str) -> None:
        """Async twin of :meth:`ShareOps.mark_insights_seen`."""
        caps = await _links.capabilities_or_disabled_async(self._client.run)
        _share_insights.require_listing_counts(caps)
        await self._client.run(_ops.mark_share_insights_seen(token))


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
        body, secret = _links.prepare_folder_share(identity, spec)
        if identity.role != "owner":
            caps = await _links.capabilities_or_disabled_async(self._client.run)
            _links.require_member_folder_shares(caps)
        minted = await self._client.run(_ops.create_folder_share(body))
        if not minted.link_envelope:
            await self._revoke_unopenable(minted.share_token)
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
        link = _links.folder_link_from_url(share_url, password)
        relative = _links.recipient_path(path)
        return await self._client.run(_ops.folder_share_browse(link.token, relative, offset, limit))

    async def get(self, share_url: str, path: str, *, password: str | None = None) -> bytes:
        """Async twin of :meth:`FolderShareOps.get`."""
        link = _links.folder_link_from_url(share_url, password)
        key = await self._file_key(link)
        request = _ops.folder_share_blob(link.token, _links.recipient_path(path))
        async with self._client.transport.stream(request) as response:
            return await _decrypt_async(response, key)

    async def _require_hash_routes_async(self) -> None:
        caps = await _links.capabilities_or_disabled_async(self._client.run)
        if not caps.folder_share_revoke_by_hash:
            raise ValueError("this server does not address folder shares by token_hash")

    async def _revoke_unopenable(self, token: str) -> NoReturn:
        try:
            await self._client.run(_ops.revoke_folder_share(token))
        except errors.DriveError as exc:
            raise _links.envelope_not_stored() from exc
        raise _links.envelope_not_stored()

    async def _file_key(self, link: _links.FolderLinkUrl) -> bytes:
        if not link.link_secret:
            return link.material
        proof = _links.folder_link_proof(link)
        found = await self._client.run(_ops.folder_link_key(link.token, proof))
        return _links.open_folder_link_key(link, found)


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
        caps = await _links.capabilities_or_disabled_async(self._client.run)
        if not caps.drive_invite_link_envelopes:
            minted = await self._client.run(_ops.create_drive_invite(body))
            created, sealed = _links.finish_invite(minted, spec)
            await self._seal_async(created, sealed)
            return created
        minted = await self._client.run(_ops.create_drive_invite(_links.mark_link_secret(body)))
        try:
            created, sealed, envelope = _links.finish_link_invite(minted, spec)
            await self._seal_async(created, sealed)
            stored = await self._client.run(self._envelope_op(created, envelope))
            _links.require_stored(stored)
        except (errors.DriveError, ValueError):
            with contextlib.suppress(errors.DriveError, ValueError):
                await self._client.run(self._revoke_op(minted))
            raise
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
        fragment = invite_link.parse_invite_link(invite_url)
        meta = await self._client.run(_ops.invite_meta(fragment.token))
        key = fragment.material
        if _links.needs_link_key(fragment):
            proof = _links.link_proof(fragment)
            found = await self._client.run(_ops.invite_link_key(fragment.token, proof))
            key = _links.open_link_key(fragment, meta, found)
        phrase = _links.grant.phrase_from_entropy(key)
        blob = _links.accept_grant(member_master, member_ss58, phrase)
        op = _ops.accept_invite(fragment.token, blob, _links.invite_folder(meta))
        result = await self._client.run(op)
        return _links.accepted_invite(result, phrase, meta)

    async def memberships(
        self, member_master: str, *, member_ss58: str
    ) -> Sequence[DriveMembership]:
        """Async twin of :meth:`DriveOps.memberships`."""
        page = await self._client.run(_ops.list_memberships())
        return _links.open_memberships(member_master, member_ss58, page)

    def _envelope_op(self, created: CreatedInvite, envelope: dict[str, str]) -> Any:
        owner = _links.manager_owner(self._client.identity)
        folder = self._client.identity.folder_hash
        return _ops.put_invite_link_envelope(folder, created.invite_id, envelope, owner)

    def _revoke_op(self, minted: InviteMint) -> Any:
        owner = _links.manager_owner(self._client.identity)
        folder = self._client.identity.folder_hash
        return _ops.revoke_drive_invite(folder, _links.minted_invite_id(minted), owner)

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
