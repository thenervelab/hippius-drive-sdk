"""File-share settings, insights, comments, and reactions, over a mocked HTTP boundary.

Every scenario runs on both clients: the namespaces are written twice and
must behave the same.
"""

from __future__ import annotations

import base64
import inspect
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from hippius_drive import PaidPlanRequired, ShareComment, errors
from hippius_drive._links import DEFAULT_CONSOLE
from hippius_drive._transport import AsyncTransport, Transport
from hippius_drive.client import AsyncClient, Client
from hippius_drive.crypto import comments, owner_wrap, sharing
from hippius_drive.crypto.sharing import ShareSecret
from hippius_drive.identity import Identity
from hippius_drive.models import ShareSummary

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
ALL_ON = {"share_insights": True, "share_comments": True, "share_comment_replies": True}
MODES = pytest.mark.parametrize("mode", ["sync", "async"])


def _vector(kind: str) -> dict[str, str]:
    return next(v for v in VECTORS["vectors"] if v["kind"] == kind)


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


def _capabilities(**flags: bool) -> respx.Route:
    return respx.get(f"{BASE}/v1/capabilities").mock(
        return_value=httpx.Response(200, json={"shares": True, **flags})
    )


# =============================================================================
# Settings
# =============================================================================


@respx.mock
@pytest.mark.anyio
@MODES
async def test_update_settings_sends_only_the_named_switches(mode: str) -> None:
    _capabilities(**ALL_ON)
    route = respx.patch(f"{SHARE}/settings").mock(
        return_value=httpx.Response(
            200, json={"insights": True, "comments": False, "reactions": False}
        )
    )

    found = await _on_shares(mode, lambda s: s.update_settings(TOKEN, insights=True))

    assert json.loads(route.calls.last.request.content) == {"insights": True}
    assert route.calls.last.request.headers["Authorization"] == "Bearer tok"
    assert (found.insights, found.comments, found.reactions) == (True, False, False)


@respx.mock
@pytest.mark.anyio
@MODES
async def test_update_settings_needs_a_switch(mode: str) -> None:
    with pytest.raises(ValueError, match="at least one"):
        await _on_shares(mode, lambda s: s.update_settings(TOKEN))


@respx.mock
@pytest.mark.anyio
@MODES
async def test_update_settings_stops_when_the_server_has_insights_off(mode: str) -> None:
    _capabilities(share_comments=True)
    route = respx.patch(f"{SHARE}/settings")

    with pytest.raises(ValueError, match="share_insights off"):
        await _on_shares(mode, lambda s: s.update_settings(TOKEN, comments=True))

    assert not route.called


@respx.mock
@pytest.mark.anyio
@MODES
async def test_a_server_without_capabilities_counts_as_every_flag_off(mode: str) -> None:
    respx.get(f"{BASE}/v1/capabilities").mock(return_value=httpx.Response(404))

    with pytest.raises(ValueError, match="share_comments off"):
        await _on_shares(mode, lambda s: s.reactions(TOKEN))


@respx.mock
@pytest.mark.anyio
@MODES
async def test_a_free_plan_switch_on_is_paid_plan_required(mode: str) -> None:
    _capabilities(**ALL_ON)
    respx.patch(f"{SHARE}/settings").mock(
        return_value=httpx.Response(
            403, json={"error": "paid_plan_required", "message": "upgrade your Drive plan"}
        )
    )

    with pytest.raises(PaidPlanRequired) as caught:
        await _on_shares(mode, lambda s: s.update_settings(TOKEN, comments=True))

    assert isinstance(caught.value, errors.Forbidden)
    assert caught.value.code == "paid_plan_required"
    assert not caught.value.retryable


@respx.mock
@pytest.mark.anyio
@MODES
async def test_an_unreachable_plan_source_is_a_retryable_server_error(mode: str) -> None:
    _capabilities(**ALL_ON)
    respx.patch(f"{SHARE}/settings").mock(
        return_value=httpx.Response(502, json={"error": "billing_unavailable", "message": "x"})
    )

    with pytest.raises(errors.ServerError) as caught:
        await _on_shares(mode, lambda s: s.update_settings(TOKEN, reactions=True))

    assert caught.value.code == "billing_unavailable"
    assert caught.value.retryable


def test_the_listing_carries_settings_and_counts() -> None:
    row = ShareSummary.model_validate(
        {
            "share_token": "t",
            "settings": {"insights": True, "comments": True, "reactions": False},
            "counts": {"views": 12, "unique_viewers": 7, "new_comments": 1},
        }
    )
    assert row.settings is not None
    assert row.settings.comments
    assert row.counts is not None
    assert (row.counts.views, row.counts.new_comments, row.counts.reactions) == (12, 1, 0)
    assert ShareSummary.model_validate({"share_token": "t"}).settings is None


# =============================================================================
# Insights
# =============================================================================

PAID: dict[str, Any] = {
    "plan": "paid",
    "total_views": 2,
    "unique_viewers": 1,
    "completion_rate": 0.25,
    "retention": [100, 98],
    "viewers": [
        {
            "viewer_id": "AQEBAQEBAQEBAQEBAQEBAQ",
            "visits": 2,
            "watched_ms": 78000,
            "completion": 0.25,
            "last_viewed_at": "2026-10-13T10:00:00Z",
            "comments": 1,
            "reactions": 0,
            "name_ct": _vector("viewer-name")["ciphertext_b64"],
            "name_nonce": _vector("viewer-name")["nonce_b64"],
        },
        {"viewer_id": "AgICAgICAgICAgICAgICAg", "name_ct": None, "name_nonce": None},
    ],
    "locked": [],
}


@respx.mock
@pytest.mark.anyio
@MODES
async def test_insights_from_the_url_decrypt_viewer_names(mode: str) -> None:
    _capabilities(**ALL_ON)
    route = respx.get(f"{SHARE}/insights").mock(return_value=httpx.Response(200, json=PAID))

    found = await _on_shares(mode, lambda s: s.insights(URL))

    assert route.calls.last.request.headers["Authorization"] == "Bearer tok"
    assert found.plan == "paid"
    assert found.completion_rate == 0.25
    assert [v.name for v in found.viewers] == ["Ahmad", None]
    assert found.viewers[0].watched_ms == 78000


@respx.mock
@pytest.mark.anyio
@MODES
async def test_insights_from_a_token_leave_names_sealed(mode: str) -> None:
    _capabilities(**ALL_ON)
    respx.get(f"{SHARE}/insights").mock(return_value=httpx.Response(200, json=PAID))

    found = await _on_shares(mode, lambda s: s.insights(TOKEN))

    assert [v.name for v in found.viewers] == [None, None]
    assert found.viewers[0].name_ct == PAID["viewers"][0]["name_ct"]


@respx.mock
@pytest.mark.anyio
@MODES
async def test_free_plan_insights_name_what_is_locked(mode: str) -> None:
    _capabilities(**ALL_ON)
    free = {
        "plan": "free",
        "total_views": 2,
        "unique_viewers": 1,
        "locked": ["completion_rate", "viewers", "retention"],
    }
    respx.get(f"{SHARE}/insights").mock(return_value=httpx.Response(200, json=free))

    found = await _on_shares(mode, lambda s: s.insights(URL))

    assert found.plan == "free"
    assert found.total_views == 2
    assert found.viewers == []
    assert found.completion_rate is None
    assert found.locked == ["completion_rate", "viewers", "retention"]


@respx.mock
@pytest.mark.anyio
@MODES
async def test_insights_stop_when_the_server_has_them_off(mode: str) -> None:
    _capabilities(share_comments=True)
    with pytest.raises(ValueError, match="share_insights off"):
        await _on_shares(mode, lambda s: s.insights(TOKEN))


# =============================================================================
# Comments
# =============================================================================


def _row(comment_id: str, kind: str, **extra: Any) -> dict[str, Any]:
    vector = _vector(kind)
    return {
        "id": comment_id,
        "parent_id": None,
        "ciphertext": vector["ciphertext_b64"],
        "nonce": vector["nonce_b64"],
        "at_ms": 83000,
        "created_at": "2026-10-13T10:00:00Z",
        "anonymous": False,
        "mine": False,
        "owner": False,
        **extra,
    }


@respx.mock
@pytest.mark.anyio
@MODES
async def test_comments_page_through_and_decrypt(mode: str) -> None:
    _capabilities(**ALL_ON)
    first = {
        "comments": [
            {"id": "40", "parent_id": None, "at_ms": 83000, "deleted": True},
            _row("41", "comment", parent_id="40", owner=True),
        ],
        "next_after": "41",
    }
    second = {
        "comments": [
            _row("42", "comment-anonymous", anonymous=True, mine=True, blocked=True),
            _row("43", "comment", ciphertext=_vector("viewer-name")["ciphertext_b64"]),
        ],
        "next_after": None,
    }
    route = respx.get(f"{SHARE}/comments").mock(
        side_effect=[httpx.Response(200, json=first), httpx.Response(200, json=second)]
    )

    found = await _on_shares(mode, lambda s: s.comments(URL))

    assert [dict(c.request.url.params) for c in route.calls] == [{}, {"after": "41"}]
    assert route.calls.last.request.headers["Authorization"] == "Bearer tok"
    assert found[0] == ShareComment(
        id="40",
        parent_id=None,
        at_ms=83000,
        created_at=None,
        text=None,
        name=None,
        anonymous=False,
        mine=False,
        owner=False,
        blocked=False,
        deleted=True,
    )
    assert (found[1].parent_id, found[1].text, found[1].name, found[1].owner) == (
        "40",
        "Looks great at 1:23!",
        "Ahmad",
        True,
    )
    assert (found[2].text, found[2].name, found[2].mine, found[2].blocked) == (
        "Nice",
        None,
        True,
        True,
    )
    # Sealed for a viewer name, so it does not open as a comment.
    assert (found[3].id, found[3].text, found[3].deleted) == ("43", None, False)


@respx.mock
@pytest.mark.anyio
@MODES
async def test_a_repeated_cursor_is_an_invalid_response(mode: str) -> None:
    _capabilities(**ALL_ON)
    page = {"comments": [], "next_after": "7"}
    respx.get(f"{SHARE}/comments").mock(return_value=httpx.Response(200, json=page))

    with pytest.raises(errors.InvalidResponse, match="same cursor"):
        await _on_shares(mode, lambda s: s.comments(URL))


@respx.mock
@pytest.mark.anyio
@MODES
async def test_comments_stop_when_the_server_has_them_off(mode: str) -> None:
    _capabilities(share_insights=True)
    route = respx.get(f"{SHARE}/comments")

    with pytest.raises(ValueError, match="share_comments off"):
        await _on_shares(mode, lambda s: s.comments(URL))

    assert not route.called


@respx.mock
@pytest.mark.anyio
@MODES
async def test_comments_need_a_file_share_url(mode: str) -> None:
    folder_url = sharing.folder_share_url(DEFAULT_CONSOLE, TOKEN, SHARE_KEY)
    with pytest.raises(ValueError, match="not a file share"):
        await _on_shares(mode, lambda s: s.comments(folder_url))


@respx.mock
@pytest.mark.anyio
@MODES
async def test_a_password_link_opens_comments_with_its_password(mode: str) -> None:
    _capabilities(**ALL_ON)
    wrapped = sharing.wrap_share_key("hunter22", SHARE_KEY)
    private = sharing.file_share_url_private(DEFAULT_CONSOLE, TOKEN, wrapped)
    page = {"comments": [_row("41", "comment")], "next_after": None}
    respx.get(f"{SHARE}/comments").mock(return_value=httpx.Response(200, json=page))

    found = await _on_shares(mode, lambda s: s.comments(private, password="hunter22"))

    assert found[0].text == "Looks great at 1:23!"
    with pytest.raises(ValueError, match="password is required"):
        await _on_shares(mode, lambda s: s.comments(private))


@respx.mock
@pytest.mark.anyio
@MODES
async def test_post_comment_sends_an_anonymous_comment_sealed_for_the_link(mode: str) -> None:
    _capabilities(**ALL_ON)
    route = respx.post(f"{SHARE}/comments").mock(
        return_value=httpx.Response(201, json={"id": "44", "created_at": "2026-10-13T10:00:00Z"})
    )

    posted = await _on_shares(mode, lambda s: s.post_comment(URL, " see 0:42 ", at_ms=42000))

    body = json.loads(route.calls.last.request.content)
    assert posted.id == "44"
    assert set(body) == {"anonymous", "at_ms", "ciphertext", "nonce"}
    assert (body["anonymous"], body["at_ms"]) == (True, 42000)
    opened = comments.open_comment(KEY, TOKEN, body["ciphertext"], body["nonce"])
    assert opened == comments.CommentText("see 0:42", None)


@respx.mock
@pytest.mark.anyio
@MODES
async def test_a_reply_names_its_parent_and_no_moment(mode: str) -> None:
    _capabilities(**ALL_ON)
    route = respx.post(f"{SHARE}/comments").mock(
        return_value=httpx.Response(201, json={"id": "45"})
    )

    await _on_shares(mode, lambda s: s.post_comment(URL, "agreed", parent_id="41"))

    body = json.loads(route.calls.last.request.content)
    assert body["parent_id"] == "41"
    assert "at_ms" not in body


@respx.mock
@pytest.mark.anyio
@MODES
async def test_a_reply_is_refused_on_a_server_without_replies(mode: str) -> None:
    _capabilities(share_insights=True, share_comments=True)
    route = respx.post(f"{SHARE}/comments")

    with pytest.raises(ValueError, match="share_comment_replies off"):
        await _on_shares(mode, lambda s: s.post_comment(URL, "agreed", parent_id="41"))

    assert not route.called


@pytest.mark.anyio
@MODES
@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"parent_id": "41", "at_ms": 5}, "parent's moment"),
        ({"parent_id": "4a"}, "comment id"),
        ({"parent_id": "0"}, "comment id"),
        ({"at_ms": -1}, "zero or more"),
    ],
)
async def test_bad_comment_fields_fail_before_any_request(
    mode: str, kwargs: dict[str, Any], error: str
) -> None:
    with respx.mock(assert_all_called=False) as router:
        with pytest.raises(ValueError, match=error):
            await _on_shares(mode, lambda s: s.post_comment(URL, "hi", **kwargs))
        assert not router.calls


@respx.mock
@pytest.mark.anyio
@MODES
async def test_comments_off_is_forbidden_and_never_retried(mode: str) -> None:
    _capabilities(**ALL_ON)
    route = respx.post(f"{SHARE}/comments").mock(
        return_value=httpx.Response(403, json={"error": "comments-off"})
    )

    with pytest.raises(errors.Forbidden) as caught:
        await _on_shares(mode, lambda s: s.post_comment(URL, "hi"))

    assert caught.value.code == "comments-off"
    assert route.call_count == 1


@respx.mock
@pytest.mark.anyio
@MODES
async def test_a_lost_post_is_not_posted_twice(mode: str) -> None:
    _capabilities(**ALL_ON)
    route = respx.post(f"{SHARE}/comments").mock(return_value=httpx.Response(502))

    with pytest.raises(errors.ServerError):
        await _on_shares(mode, lambda s: s.post_comment(URL, "hi"))

    assert route.call_count == 1


@respx.mock
@pytest.mark.anyio
@MODES
async def test_delete_comment_names_the_comment(mode: str) -> None:
    _capabilities(**ALL_ON)
    route = respx.delete(f"{SHARE}/comments/41").mock(return_value=httpx.Response(204))

    await _on_shares(mode, lambda s: s.delete_comment(TOKEN, "41"))

    assert route.called
    with pytest.raises(ValueError, match="comment id"):
        await _on_shares(mode, lambda s: s.delete_comment(TOKEN, "../41"))


@respx.mock
@pytest.mark.anyio
@MODES
async def test_reactions_read_counts_and_mine(mode: str) -> None:
    _capabilities(**ALL_ON)
    body = {"counts": {"\U0001f44d": 3, "\u2764\ufe0f": 1}, "mine": ["\U0001f44d"]}
    respx.get(f"{SHARE}/reactions").mock(return_value=httpx.Response(200, json=body))

    found = await _on_shares(mode, lambda s: s.reactions(TOKEN))

    assert found.counts == {"\U0001f44d": 3, "\u2764\ufe0f": 1}
    assert found.mine == ["\U0001f44d"]


# =============================================================================
# Owner wrap
# =============================================================================


def _listing(wrap: bytes | None) -> httpx.Response:
    row: dict[str, Any] = {"share_token": TOKEN, "filename": "clip.mp4"}
    if wrap is not None:
        row["owner_wrap"] = base64.b64encode(wrap).decode()
    return httpx.Response(200, json=[row])


@respx.mock
@pytest.mark.anyio
@MODES
async def test_recover_url_rebuilds_the_link_from_the_owner_wrap(mode: str) -> None:
    wrap = owner_wrap.seal_file_secret(MASTER, SS58, TOKEN, ShareSecret(SHARE_KEY))
    respx.get(f"{BASE}/v1/shares").mock(return_value=_listing(wrap))

    found = await _on_shares(mode, lambda s: s.recover_url(TOKEN, MASTER))

    assert found == URL


@respx.mock
@pytest.mark.anyio
@MODES
async def test_recover_url_needs_a_wrap_and_a_known_token(mode: str) -> None:
    respx.get(f"{BASE}/v1/shares").mock(return_value=_listing(None))

    with pytest.raises(ValueError, match="no owner wrap"):
        await _on_shares(mode, lambda s: s.recover_url(TOKEN, MASTER))
    with pytest.raises(ValueError, match="no file share with that token"):
        await _on_shares(mode, lambda s: s.recover_url("other", MASTER))


@respx.mock
@pytest.mark.anyio
@MODES
async def test_a_wrap_that_is_not_base64_is_a_decrypt_error(mode: str) -> None:
    row = {"share_token": TOKEN, "owner_wrap": "!!"}
    respx.get(f"{BASE}/v1/shares").mock(return_value=httpx.Response(200, json=[row]))

    with pytest.raises(errors.DecryptError, match="not base64"):
        await _on_shares(mode, lambda s: s.recover_url(TOKEN, MASTER))
