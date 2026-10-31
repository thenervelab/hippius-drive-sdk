"""Named comments, mentions and mention candidates, over a mocked HTTP boundary.

Every scenario runs on both clients: the namespaces are written twice and
must behave the same.
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from hippius_drive import CommentAuthor, CommentMention, ShareInsights
from hippius_drive._links import DEFAULT_CONSOLE
from hippius_drive._transport import AsyncTransport, Transport
from hippius_drive.client import AsyncClient, Client
from hippius_drive.crypto import comments, sharing
from hippius_drive.identity import Identity

BASE = "https://example.test"
MASTER = " ".join(["abandon"] * 23 + ["art"])
SS58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
VECTORS: dict[str, Any] = json.loads(
    (Path(__file__).parent / "vectors" / "share-comments-vectors.json").read_text("utf-8")
)
TOKEN: str = VECTORS["token"]
SHARE_KEY = bytes.fromhex(VECTORS["share_key_hex"])
KEY = comments.comment_key(SHARE_KEY)
URL = sharing.file_share_url(DEFAULT_CONSOLE, TOKEN, SHARE_KEY)
SHARE = f"{BASE}/v1/shares/{TOKEN}"
SECRET = bytes(range(32))
# comments.viewer_id(SECRET, TOKEN), computed with Node's crypto.createHmac.
VIEWER_ID = "AmkdIsFzxJuP1hjmJ79zGQ"
GRACE = CommentAuthor("Grace", SECRET)
ALL_ON = {"share_insights": True, "share_comments": True, "share_comment_replies": True}
MODES = pytest.mark.parametrize("mode", ["sync", "async"])


async def _on_shares(mode: str, call: Callable[[Any], Any]) -> Any:
    """Run ``call`` against ``client.shares`` of the sync or the async client."""
    identity = Identity.from_master(MASTER, "default", account_ss58=SS58)
    if mode == "sync":
        transport = Transport(BASE, "tok", sleep=lambda _seconds: None)
        with Client(token="tok", identity=identity, transport=transport) as client:
            return call(client.shares)

    async def nosleep(_seconds: float) -> None:
        return None

    async_transport = AsyncTransport(BASE, "tok", sleep=nosleep)
    async with AsyncClient(token="tok", identity=identity, transport=async_transport) as client:
        result = call(client.shares)
        return await result if inspect.isawaitable(result) else result


def _capabilities() -> respx.Route:
    return respx.get(f"{BASE}/v1/capabilities").mock(
        return_value=httpx.Response(200, json={"shares": True, **ALL_ON})
    )


def _posted() -> respx.Route:
    return respx.post(f"{SHARE}/comments").mock(
        return_value=httpx.Response(201, json={"id": "50", "created_at": "2026-10-31T10:00:00Z"})
    )


def _sent(route: respx.Route) -> dict[str, Any]:
    return json.loads(route.calls.last.request.content)


def _opened(body: dict[str, Any]) -> comments.CommentText:
    return comments.open_comment(KEY, TOKEN, body["ciphertext"], body["nonce"])


def _row(comment_id: str, text: str, **extra: Any) -> dict[str, Any]:
    name = extra.pop("name", None)
    mentions = extra.pop("mentions", ())
    sealed = comments.seal_comment(KEY, TOKEN, text, name=name, mentions=mentions)
    return {
        "id": comment_id,
        "parent_id": None,
        "ciphertext": sealed.ciphertext,
        "nonce": sealed.nonce,
        "created_at": f"2026-10-13T10:00:{int(comment_id):02}Z",
        "anonymous": name is None,
        "mine": False,
        "owner": False,
        **extra,
    }


def _thread(*rows: dict[str, Any]) -> respx.Route:
    body = {"comments": list(rows), "next_after": None}
    return respx.get(f"{SHARE}/comments").mock(return_value=httpx.Response(200, json=body))


def _listing(*tokens: str) -> respx.Route:
    body = [{"share_token": token, "filename": "clip.mp4"} for token in tokens]
    return respx.get(f"{BASE}/v1/shares").mock(return_value=httpx.Response(200, json=body))


# =============================================================================
# Named comments
# =============================================================================


@respx.mock
@pytest.mark.anyio
@MODES
async def test_a_named_comment_carries_the_viewer_id_and_the_name_twice(mode: str) -> None:
    _capabilities()
    route = _posted()

    posted = await _on_shares(mode, lambda s: s.post_comment(URL, "hi", author=GRACE))

    body = _sent(route)
    assert posted.id == "50"
    assert body["anonymous"] is False
    assert body["viewer_id"] == VIEWER_ID
    assert _opened(body) == comments.CommentText("hi", "Grace")
    name = comments.open_viewer_name(KEY, TOKEN, body["name_ct"], body["name_nonce"])
    assert name == "Grace"
    assert set(body) == {"anonymous", "viewer_id", "ciphertext", "nonce", "name_ct", "name_nonce"}


@respx.mock
@pytest.mark.anyio
@MODES
async def test_an_anonymous_comment_sends_no_viewer_and_no_name(mode: str) -> None:
    _capabilities()
    route = _posted()

    await _on_shares(mode, lambda s: s.post_comment(URL, "hi"))

    body = _sent(route)
    assert set(body) == {"anonymous", "ciphertext", "nonce"}
    assert body["anonymous"] is True
    assert _opened(body).name is None


@respx.mock
@pytest.mark.anyio
@MODES
async def test_an_address_as_a_name_is_posted_shortened(mode: str) -> None:
    _capabilities()
    route = _posted()

    author = CommentAuthor(f"user_{SS58.lower()}", SECRET)
    await _on_shares(mode, lambda s: s.post_comment(URL, "hi", author=author))

    body = _sent(route)
    assert _opened(body).name == "5grwva…utqy"
    shown = comments.open_viewer_name(KEY, TOKEN, body["name_ct"], body["name_nonce"])
    assert shown == "5grwva…utqy"


@respx.mock
@pytest.mark.anyio
@MODES
async def test_a_blank_name_is_refused_before_any_request(mode: str) -> None:
    caps = _capabilities()

    author = CommentAuthor(" \u200b ", SECRET)
    with pytest.raises(ValueError, match="name is blank"):
        await _on_shares(mode, lambda s: s.post_comment(URL, "hi", author=author))

    assert not caps.called


def test_an_author_needs_a_32_byte_secret() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        CommentAuthor("Grace", bytes(16))
    assert "viewer_secret" not in repr(GRACE)


@respx.mock
@pytest.mark.anyio
@MODES
async def test_a_named_reply_names_its_parent(mode: str) -> None:
    _capabilities()
    route = _posted()

    await _on_shares(mode, lambda s: s.post_comment(URL, "yes", author=GRACE, parent_id="41"))

    body = _sent(route)
    assert (body["parent_id"], body["anonymous"], "at_ms" in body) == ("41", False, False)


# =============================================================================
# Mentions on post
# =============================================================================

ADA = CommentMention("commenter", "Ada", "41")
ADA_L = CommentMention("commenter", "Ada Lovelace", "42")
OWNER = CommentMention("owner", "Owner")


@respx.mock
@pytest.mark.anyio
@MODES
async def test_mentions_are_sealed_in_the_order_they_stand_in_the_text(mode: str) -> None:
    _capabilities()
    route = _posted()

    text = "@Owner see @Ada, and @Ada again"
    await _on_shares(mode, lambda s: s.post_comment(URL, text, mentions=[ADA, OWNER, ADA]))

    assert _opened(_sent(route)).mentions == (OWNER, ADA, ADA)


@respx.mock
@pytest.mark.anyio
@MODES
async def test_the_longer_of_two_overlapping_mentions_wins(mode: str) -> None:
    _capabilities()
    route = _posted()

    text = "thanks @Ada Lovelace"
    await _on_shares(mode, lambda s: s.post_comment(URL, text, mentions=[ADA, ADA_L]))

    assert _opened(_sent(route)).mentions == (ADA_L,)


@respx.mock
@pytest.mark.anyio
@MODES
async def test_at_most_ten_mentions_are_sealed(mode: str) -> None:
    _capabilities()
    route = _posted()

    text = " ".join(["@Ada"] * 12)
    await _on_shares(mode, lambda s: s.post_comment(URL, text, mentions=[ADA]))

    assert _opened(_sent(route)).mentions == (ADA,) * 10


@respx.mock
@pytest.mark.anyio
@MODES
@pytest.mark.parametrize("text", ["hi Ada", "hi @Adam", "mail x@Ada", "hi @Ada_", "hi @Adaé"])
async def test_a_mention_not_in_the_text_as_a_whole_word_is_refused(mode: str, text: str) -> None:
    caps = _capabilities()

    with pytest.raises(ValueError, match="@Ada is not in the comment text"):
        await _on_shares(mode, lambda s: s.post_comment(URL, text, mentions=[ADA]))

    assert not caps.called


@respx.mock
@pytest.mark.anyio
@MODES
@pytest.mark.parametrize("text", ["@Ada", "(@Ada)", "hi @Ada.", "1 @Ada\U0001f44d"])
async def test_a_mention_may_touch_punctuation_and_the_ends(mode: str, text: str) -> None:
    _capabilities()
    route = _posted()

    await _on_shares(mode, lambda s: s.post_comment(URL, text, mentions=[ADA]))

    assert _opened(_sent(route)).mentions == (ADA,)


# =============================================================================
# Reading mentions
# =============================================================================


@respx.mock
@pytest.mark.anyio
@MODES
async def test_a_mention_of_one_of_my_comments_mentions_me(mode: str) -> None:
    _capabilities()
    _thread(
        _row("41", "first", name="Ada", mine=True),
        _row("42", "@Ada yes", name="Bo", mentions=[ADA]),
        _row("43", "@Cy no", name="Bo", mentions=[CommentMention("commenter", "Cy", "9")]),
    )
    listing = _listing()

    found = await _on_shares(mode, lambda s: s.comments(URL))

    assert [c.mentions_me for c in found] == [False, True, False]
    assert found[1].mentions == (ADA,)
    # No comment tags the owner, so whether you own the link is never asked.
    assert not listing.called


@respx.mock
@pytest.mark.anyio
@MODES
@pytest.mark.parametrize(("tokens", "me"), [((TOKEN,), True), (("other",), False)])
async def test_an_owner_mention_mentions_me_only_on_my_own_link(
    mode: str, tokens: tuple[str, ...], me: bool
) -> None:
    _capabilities()
    _thread(_row("41", "@Owner hi", name="Bo", mentions=[OWNER]))
    _listing(*tokens)

    found = await _on_shares(mode, lambda s: s.comments(URL))

    assert found[0].mentions_me is me


@respx.mock
@pytest.mark.anyio
@MODES
async def test_listed_names_show_as_the_console_shows_them(mode: str) -> None:
    _capabilities()
    _thread(
        _row("41", "a", name=SS58),
        # Sealed with a name, but listed as anonymous: the console shows none.
        {**_row("42", "b", name="Bo"), "anonymous": True},
    )

    found = await _on_shares(mode, lambda s: s.comments(URL))

    assert [c.name for c in found] == ["5Grwva…utQY", None]


@respx.mock
@pytest.mark.anyio
@MODES
async def test_viewer_names_show_as_the_console_shows_them(mode: str) -> None:
    sealed = comments.seal_viewer_name(KEY, TOKEN, SS58)
    insights = ShareInsights.model_validate(
        {
            "plan": "paid",
            "viewers": [
                {"viewer_id": "v1", "name_ct": sealed.ciphertext, "name_nonce": sealed.nonce}
            ],
        }
    )

    found = await _on_shares(mode, lambda s: s.viewer_names(insights, URL))

    assert found == {"v1": "5Grwva…utQY"}


# =============================================================================
# Mention candidates
# =============================================================================


def _candidates_thread() -> None:
    _thread(
        _row("41", "a", name="Ada"),
        _row("42", "b", name="Bo", mine=True),
        _row("43", "c", name="Ada"),
        _row("44", "d"),
        {**_row("45", "e", name="Cy"), "ciphertext": _row("1", "x")["nonce"]},
        _row("46", "f", name="Dee", owner=True),
        _row("47", "g", name="Dee"),
        _row("48", "h", name="Eve"),
        # Named, but the name it sealed is blank: nobody to tag.
        {**_row("49", "i"), "anonymous": False},
    )


@respx.mock
@pytest.mark.anyio
@MODES
async def test_a_viewer_is_offered_the_owner_first_then_named_commenters(mode: str) -> None:
    _capabilities()
    _candidates_thread()
    _listing("other")

    found = await _on_shares(mode, lambda s: s.mention_candidates(URL))

    # Newest first, one per name pointing at their newest comment; not your
    # own, not anonymous, not unreadable; nobody under the owner's name.
    assert list(found) == [
        CommentMention("owner", "Dee"),
        CommentMention("commenter", "Eve", "48"),
        CommentMention("commenter", "Ada", "43"),
    ]


@respx.mock
@pytest.mark.anyio
@MODES
async def test_the_owner_is_offered_commenters_only(mode: str) -> None:
    _capabilities()
    _candidates_thread()
    _listing(TOKEN)

    found = await _on_shares(mode, lambda s: s.mention_candidates(URL))

    assert list(found) == [
        CommentMention("commenter", "Eve", "48"),
        CommentMention("commenter", "Dee", "47"),
        CommentMention("commenter", "Ada", "43"),
    ]


@respx.mock
@pytest.mark.anyio
@MODES
async def test_an_owner_who_never_commented_by_name_is_offered_as_owner(mode: str) -> None:
    _capabilities()
    _thread(_row("41", "a", name="Ada"))
    _listing()

    found = await _on_shares(mode, lambda s: s.mention_candidates(URL))

    assert list(found) == [OWNER, ADA]
