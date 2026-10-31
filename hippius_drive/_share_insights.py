"""Pure steps behind a file share's settings, insights, comments, and reactions.

The sync and async share namespaces call these between requests, so the
request bodies, the capability checks, and the decryption are written once.
"""

from __future__ import annotations

import base64
import dataclasses
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from hippius_drive import _links, errors
from hippius_drive._wire import check_comment_id
from hippius_drive.crypto import comments, owner_wrap, sharing
from hippius_drive.crypto.comments import CommentMention
from hippius_drive.models import (
    Capabilities,
    CommentAuthor,
    CommentPage,
    CommentRow,
    ShareComment,
    ShareInsights,
    ShareSummary,
)

REACTIONS = (
    "\U0001f44d",
    "\u2764\ufe0f",
    "\U0001f602",
    "\U0001f62e",
    "\U0001f389",
    "\U0001f44f",
    "\U0001f525",
    "\U0001f64c",
)
"""The reactions a link takes, in the order the share page shows them (hcfs ``REACTIONS``)."""

OWNER_MENTION_NAME = "Owner"
"""How the owner is tagged before they have commented under a name (the console's)."""


MAX_MOMENT_MS = 604_800_000
"""Seven days: the longest a view may report, and the latest moment hcfs takes."""


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


def require_moments(caps: Capabilities) -> None:
    """Stop before a moment route an older server answers with 404 or 405.

    Raises:
        ValueError: If ``share_reaction_moments`` is off.
    """
    if not caps.share_reaction_moments:
        raise ValueError(
            "this server has share_reaction_moments off: reactions at a moment are not available"
        )


def require_listing_counts(caps: Capabilities) -> None:
    """Stop before ``PUT .../insights/seen`` on a server that answers it with a bodiless 404.

    Raises:
        ValueError: If ``share_listing_counts`` is off.
    """
    if not caps.share_listing_counts:
        raise ValueError(
            "this server has share_listing_counts off: it keeps no 'new since seen' counts"
        )


def check_reaction(emoji: str) -> str:
    """The reaction as the server stores it. A heart without U+FE0F is the same heart.

    Raises:
        ValueError: If ``emoji`` is not one of :data:`REACTIONS`.
    """
    if emoji == "\u2764":
        return REACTIONS[1]
    if emoji not in REACTIONS:
        raise ValueError(f"reaction must be one of {' '.join(REACTIONS)}")
    return emoji


def check_moment(at_ms: int) -> None:
    """Refuse a moment the server would refuse.

    Raises:
        ValueError: If ``at_ms`` is not a whole number from 0 to seven days.
    """
    # bool is an int subclass: True would go out as {"at_ms": true}, a 400.
    if isinstance(at_ms, bool) or not 0 <= at_ms <= MAX_MOMENT_MS:
        raise ValueError(f"at_ms must be from 0 to {MAX_MOMENT_MS} (seven days)")


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
    token, share_key = _links.share_key_from_url(share_url, password)
    return token, comments.comment_key(share_key)


def viewer_names(insights: ShareInsights, token: str, key: bytes) -> dict[str, str]:
    """Each viewer's name by ``viewer_id``, for the names that open under ``key``."""
    names: dict[str, str] = {}
    for viewer in insights.viewers:
        opened = comments.open_viewer_name(key, token, viewer.name_ct, viewer.name_nonce)
        name = comments.present_name(opened)
        if name is not None:
            names[viewer.viewer_id] = name
    return names


@dataclass(frozen=True)
class CommentDraft:
    """A comment to post, as the namespaces hand it over.

    Attributes:
        text: The comment.
        parent_id: The top-level comment it answers, or None.
        at_ms: The moment of the video, or None. Not on a reply.
        author: Who it is posted as; None posts anonymously.
        mentions: Who it tags; each one's ``@Name`` must be in ``text``.
    """

    text: str
    parent_id: str | None = None
    at_ms: int | None = None
    author: CommentAuthor | None = None
    mentions: Sequence[CommentMention] = ()


def comment_body(token: str, key: bytes, draft: CommentDraft) -> dict[str, Any]:
    """Seal a comment into the ``POST .../comments`` body, as the console's ``buildCommentPost``.

    A named comment carries its name twice, sealed differently: inside the
    comment, and on its own (``name_ct``) for the owner's viewer list, beside
    the viewer id it is counted under. An anonymous one sends neither.

    Raises:
        ValueError: If the text is empty or too long, the parent id is not a
            comment id, ``at_ms`` is negative, a reply names a moment, the
            name is blank, or a mention's ``@Name`` is not in the text.
    """
    body: dict[str, Any] = {}
    if draft.parent_id is not None:
        if draft.at_ms is not None:
            raise ValueError("a reply takes its parent's moment: leave at_ms out")
        body["parent_id"] = check_comment_id(draft.parent_id)
    if draft.at_ms is not None:
        if draft.at_ms < 0:
            raise ValueError("at_ms must be zero or more")
        body["at_ms"] = draft.at_ms
    text = comments.comment_text(draft.text)
    mentions = collect_mentions(text, draft.mentions)
    name = _author_name(draft.author)
    sealed = comments.seal_comment(key, token, text, name=name, mentions=mentions)
    body["ciphertext"] = sealed.ciphertext
    body["nonce"] = sealed.nonce
    if draft.author is None or name is None:
        body["anonymous"] = True
        return body
    sealed_name = comments.seal_viewer_name(key, token, name)
    body["anonymous"] = False
    body["viewer_id"] = comments.viewer_id(draft.author.viewer_secret, token)
    body["name_ct"] = sealed_name.ciphertext
    body["name_nonce"] = sealed_name.nonce
    return body


def _author_name(author: CommentAuthor | None) -> str | None:
    """The name a comment is posted under; the console posts a blank one anonymously.

    Raises:
        ValueError: If the author's name is blank: posting it anonymously
            instead would surprise a caller who named one.
    """
    if author is None:
        return None
    name = comments.clean_name(comments.present_name(author.name))
    if name is None:
        raise ValueError("the comment author's name is blank")
    return name


def collect_mentions(text: str, picked: Sequence[CommentMention]) -> list[CommentMention]:
    """The mentions to seal, as the console's ``collectMentions``.

    Every ``@Name`` in the text for someone picked, in the order they stand,
    at most ten. Where two overlap (``@Ada`` inside ``@Ada Lovelace``) the
    longer wins. Duplicate picks count once.

    Raises:
        ValueError: If a pick has another kind, a name that is not clean
            (it would be sealed changed and not read back as a tag), or no
            whole-word ``@Name`` in the text, or there are more than ten
            distinct picks. The console drops such a pick; here it is a
            caller's mistake.
    """
    distinct = list(dict.fromkeys(picked))
    if len(distinct) > comments.MAX_MENTIONS:
        raise ValueError(f"a comment tags at most {comments.MAX_MENTIONS} people")
    found: list[tuple[int, int, CommentMention]] = []
    for mention in distinct:
        _check_pick(mention)
        at = _find_tag(text, mention.name, 0)
        if at == -1:
            raise ValueError(f"@{mention.name} is not in the comment text")
        while at != -1:
            end = at + 1 + len(mention.name)
            found.append((at, end, mention))
            at = _find_tag(text, mention.name, end)
    found.sort(key=lambda item: (item[0], -item[1]))
    chosen: list[CommentMention] = []
    last_end = 0
    for at, end, mention in found:
        if at < last_end:
            continue
        chosen.append(mention)
        last_end = end
        if len(chosen) >= comments.MAX_MENTIONS:
            break
    return chosen


def _check_pick(mention: CommentMention) -> None:
    if mention.kind not in ("owner", "commenter"):
        raise ValueError(f"mention kind must be owner or commenter, not {mention.kind!r}")
    if comments.clean_name(mention.name) != mention.name:
        raise ValueError(f"mention name {mention.name!r} is not clean: take it from the candidates")


def _find_tag(text: str, name: str, start: int) -> int:
    """Where ``@name`` next stands as a whole word in ``text``, from ``start``; -1 if nowhere."""
    needle = f"@{name}"
    at = text.find(needle, start)
    while at != -1:
        end = at + len(needle)
        if not _word_char(text[at - 1 : at]) and not _word_char(text[end : end + 1]):
            return at
        at = text.find(needle, at + 1)
    return -1


def _word_char(char: str) -> bool:
    """The console's ``WORD``: a letter, digit, mark or underscore may not touch a mention."""
    return char == "_" or (char != "" and unicodedata.category(char)[0] in "LNM")


def mention_candidates(
    thread: Sequence[ShareComment], *, reader_owns_link: bool
) -> list[CommentMention]:
    """Who the reader can tag, as the console's ``mentionCandidates``.

    The owner first (unless the reader is the owner), under the name of
    their newest named comment or ``Owner``; then everyone else who
    commented under a name, newest first, each pointing at their newest
    comment. Anonymous comments, unreadable ones and the reader's own offer
    nobody.
    """
    newest_first = sorted(thread, key=lambda item: item.created_at or "", reverse=True)
    owner_name: str | None = None
    commenters: dict[str, CommentMention] = {}
    for item in newest_first:
        if item.anonymous or item.text is None:
            continue
        name = comments.clean_name(comments.present_name(item.name))
        if name is None:
            continue
        if item.owner:
            owner_name = owner_name or name
        elif not item.mine and name not in commenters:
            commenters[name] = CommentMention("commenter", name, item.id)
    if reader_owns_link:
        return list(commenters.values())
    owner = CommentMention("owner", owner_name or OWNER_MENTION_NAME)
    return [owner, *(c for c in commenters.values() if c.name != owner_name)]


def mark_mentions(thread: Sequence[ShareComment], *, reader_owns_link: bool) -> list[ShareComment]:
    """Set ``mentions_me`` where a comment tags the reader, as the console's ``mentionsYou``."""
    mine = {item.id for item in thread if item.mine}
    return [
        dataclasses.replace(item, mentions_me=True)
        if any(_is_reader(m, mine, reader_owns_link) for m in item.mentions)
        else item
        for item in thread
    ]


def mentions_owner(thread: Sequence[ShareComment]) -> bool:
    """Whether any comment tags the owner, so whether ownership must be looked up."""
    return any(m.kind == "owner" for item in thread for m in item.mentions)


def _is_reader(mention: CommentMention, mine: set[str], reader_owns_link: bool) -> bool:
    if mention.kind == "owner":
        return reader_owns_link
    return mention.comment is not None and mention.comment in mine


def thread_shows_owner(thread: Sequence[ShareComment]) -> bool:
    """Whether the reader's own comments include the owner's: then the reader owns the link."""
    return any(item.owner and item.mine for item in thread)


def owns_link(rows: Sequence[ShareSummary], token: str) -> bool:
    """Whether ``token`` is one of this account's shares."""
    return any(row.share_token == token for row in rows)


def require_replies(caps: Capabilities, parent_id: str | None) -> None:
    """Refuse a reply the server would silently store as a top-level comment.

    Raises:
        ValueError: If ``parent_id`` is set and ``share_comment_replies`` is off.
    """
    if parent_id is not None and not caps.share_comment_replies:
        raise ValueError("this server has share_comment_replies off: it cannot take a reply")


def next_cursor(page: CommentPage, seen: set[str]) -> str | None:
    """The cursor for the next page, or None after the last. Adds it to ``seen``.

    Raises:
        InvalidResponse: If the server hands back a cursor it already gave,
            which would page forever.
    """
    cursor = page.next_after
    if cursor is None:
        return None
    if cursor in seen:
        raise errors.InvalidResponse("comment listing returned a cursor it already gave")
    seen.add(cursor)
    return cursor


def open_rows(rows: Sequence[CommentRow], token: str, key: bytes) -> list[ShareComment]:
    """Decrypt a page of comments. One that does not open keeps ``text=None``."""
    return [_open_row(row, token, key) for row in rows]


def mark_claimed_names(thread: Sequence[ShareComment]) -> list[ShareComment]:
    """Set ``name_claimed`` on each comment whose name is a claim it cannot back.

    The console's ``markClaimedNames``: not the owner's comment, yet the name
    is reserved or is a name the owner's own comments carry. It reads the
    owner's names from the same thread, so it runs on the whole listing.
    """
    owner_names = {
        comments.claim_key(item.name)
        for item in thread
        if item.owner and not item.anonymous and item.name
    }
    owner_names.discard("")
    return [
        dataclasses.replace(item, name_claimed=True) if _claims(item, owner_names) else item
        for item in thread
    ]


def _claims(item: ShareComment, owner_names: set[str]) -> bool:
    if item.owner or item.anonymous or not item.name:
        return False
    return comments.is_reserved_name(item.name) or comments.claim_key(item.name) in owner_names


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
    opened: comments.CommentText | None = None
    if not row.deleted and row.ciphertext and row.nonce:
        try:
            opened = comments.open_comment(key, token, row.ciphertext, row.nonce)
        except errors.DecryptError:
            # Any signed-in account can post bytes this key cannot read; one
            # such comment must not hide the rest of the thread.
            opened = None
    text = None if opened is None else opened.text
    # The console shows no name on an anonymous comment whatever it sealed,
    # and shortens a name posted before access-key names were shortened.
    name = None if opened is None or row.anonymous else comments.present_name(opened.name)
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
        mentions=() if opened is None else opened.mentions,
    )
