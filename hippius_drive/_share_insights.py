"""Pure steps behind a file share's settings, insights, comments, and reactions.

The sync and async share namespaces call these between requests, so the
request bodies, the capability checks, and the decryption are written once.
"""

from __future__ import annotations

import base64
from collections.abc import Sequence
from typing import Any

from hippius_drive import _links, errors
from hippius_drive._wire import check_comment_id
from hippius_drive.crypto import comments, owner_wrap, sharing
from hippius_drive.models import (
    Capabilities,
    CommentPage,
    CommentRow,
    ShareComment,
    ShareInsights,
    ShareSummary,
)


def require_insights(caps: Capabilities) -> None:
    """Stop before a request the server would answer with a bodiless 404.

    Raises:
        ValueError: If ``share_insights`` is off.
    """
    if not caps.share_insights:
        raise ValueError(
            "this server has share_insights off: link settings and insights are not available"
        )


def require_comments(caps: Capabilities) -> None:
    """Stop before a request the server would answer with a bodiless 404.

    Raises:
        ValueError: If ``share_comments`` is off.
    """
    if not caps.share_comments:
        raise ValueError(
            "this server has share_comments off: link comments and reactions are not available"
        )


def settings_body(
    *, insights: bool | None, comments: bool | None, reactions: bool | None
) -> dict[str, bool]:
    """The ``PATCH .../settings`` body: only the switches the caller named.

    Raises:
        ValueError: If no switch is named.
    """
    named = {"insights": insights, "comments": comments, "reactions": reactions}
    body = {key: value for key, value in named.items() if value is not None}
    if not body:
        raise ValueError("name at least one of insights, comments, reactions")
    return body


def link_key(share_url: str, password: str | None) -> tuple[str, bytes]:
    """Return ``(token, comment key)`` from a file-share URL.

    Raises:
        ValueError: If the URL is not a file share, or a ``#p=`` link has no password.
        DecryptError: If the password does not open the link.
    """
    token, share_key = _links.share_key_from_url(share_url, password, folder=False)
    return token, comments.comment_key(share_key)


def token_and_key(share_url_or_token: str, password: str | None) -> tuple[str, bytes | None]:
    """Accept a plain token (no key) or a share URL (token and comment key)."""
    if share_url_or_token.startswith("https://"):
        return link_key(share_url_or_token, password)
    return share_url_or_token, None


def name_viewers(insights: ShareInsights, token: str, key: bytes | None) -> ShareInsights:
    """Fill each viewer's ``name`` from its sealed name, when the key is known."""
    if key is None:
        return insights
    viewers = [
        viewer.model_copy(
            update={
                "name": comments.open_viewer_name(key, token, viewer.name_ct, viewer.name_nonce)
            }
        )
        for viewer in insights.viewers
    ]
    return insights.model_copy(update={"viewers": viewers})


def comment_body(
    token: str, key: bytes, text: str, *, parent_id: str | None, at_ms: int | None
) -> dict[str, Any]:
    """Seal an anonymous comment into the ``POST .../comments`` body.

    Only anonymous comments are posted. A named one needs the page's
    per-link viewer id, which the console derives from a secret kept in the
    browser; an id made up here would count as a new viewer in the owner's
    insights on every post.

    Raises:
        ValueError: If the text is empty or too long, the parent id is not a
            comment id, ``at_ms`` is negative, or a reply names a moment.
    """
    body: dict[str, Any] = {"anonymous": True}
    if parent_id is not None:
        if at_ms is not None:
            raise ValueError("a reply takes its parent's moment: leave at_ms out")
        body["parent_id"] = check_comment_id(parent_id)
    if at_ms is not None:
        if at_ms < 0:
            raise ValueError("at_ms must be zero or more")
        body["at_ms"] = at_ms
    sealed = comments.seal_comment(key, token, text)
    body["ciphertext"] = sealed.ciphertext
    body["nonce"] = sealed.nonce
    return body


def require_replies(caps: Capabilities, parent_id: str | None) -> None:
    """Refuse a reply the server would silently store as a top-level comment.

    Raises:
        ValueError: If ``parent_id`` is set and ``share_comment_replies`` is off.
    """
    if parent_id is not None and not caps.share_comment_replies:
        raise ValueError("this server has share_comment_replies off: it cannot take a reply")


def next_cursor(page: CommentPage, previous: str | None) -> str | None:
    """The cursor for the next page, or None after the last.

    Raises:
        InvalidResponse: If the server hands back the cursor it was given,
            which would page forever.
    """
    if page.next_after is not None and page.next_after == previous:
        raise errors.InvalidResponse("comment listing returned the same cursor twice")
    return page.next_after


def open_rows(rows: Sequence[CommentRow], token: str, key: bytes) -> list[ShareComment]:
    """Decrypt a page of comments. One that does not open keeps ``text=None``."""
    return [_open_row(row, token, key) for row in rows]


def owner_share_url(
    rows: Sequence[ShareSummary],
    token: str,
    master_mnemonic: str,
    *,
    account_ss58: str,
    console_base_url: str,
) -> str:
    """Rebuild a file share's URL from the owner wrap in the listing.

    Raises:
        ValueError: If the listing has no such share, or the share has no
            owner wrap (it was minted without one; use the URL from the mint).
        DecryptError: If the wrap does not open with this phrase and account.
    """
    row = next((row for row in rows if row.share_token == token), None)
    if row is None:
        raise ValueError("this account has no file share with that token")
    if not row.owner_wrap:
        raise ValueError("that share has no owner wrap; use the URL it was minted with")
    try:
        wrap = base64.b64decode(row.owner_wrap, validate=True)
    except ValueError as exc:
        raise errors.DecryptError("the share's owner wrap is not base64") from exc
    secret = owner_wrap.open_file_secret(master_mnemonic, account_ss58, token, wrap)
    return sharing.share_url(console_base_url, token, secret, folder=False)


def _open_row(row: CommentRow, token: str, key: bytes) -> ShareComment:
    text: str | None = None
    name: str | None = None
    if not row.deleted and row.ciphertext and row.nonce:
        try:
            opened = comments.open_comment(key, token, row.ciphertext, row.nonce)
        except errors.DecryptError:
            # Any signed-in account can post bytes this key cannot read; one
            # such comment must not hide the rest of the thread.
            opened = None
        if opened is not None:
            text, name = opened.text, opened.name
    return ShareComment(
        id=row.id,
        parent_id=row.parent_id,
        at_ms=row.at_ms,
        created_at=row.created_at,
        text=text,
        name=name,
        anonymous=row.anonymous,
        mine=row.mine,
        owner=row.owner,
        blocked=row.blocked,
        deleted=row.deleted,
    )
