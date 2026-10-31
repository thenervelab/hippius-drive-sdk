"""Reaction writes, reaction moments, comment blocks, and marking insights seen.

Over a mocked HTTP boundary, and on both clients: the namespaces are written
twice and must behave the same.
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest
import respx

from hippius_drive import REACTIONS, ReactionMoment, errors
from hippius_drive._transport import AsyncTransport, Transport
from hippius_drive.client import AsyncClient, Client
from hippius_drive.identity import Identity

BASE = "https://example.test"
MASTER = " ".join(["abandon"] * 23 + ["art"])
SS58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
TOKEN = "sx5QIbv8AjPlxin1kZs0jw"
SHARE = f"{BASE}/v1/shares/{TOKEN}"
THUMBS = "\U0001f44d"
HEART = "❤️"
ALL_ON = {
    "share_insights": True,
    "share_comments": True,
    "share_reaction_moments": True,
    "share_listing_counts": True,
}
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


def _capabilities(**flags: bool) -> respx.Route:
    return respx.get(f"{BASE}/v1/capabilities").mock(
        return_value=httpx.Response(200, json={"shares": True, **flags})
    )


def _path(request: httpx.Request) -> str:
    return request.url.raw_path.decode()


# =============================================================================
# Reactions
# =============================================================================


def test_the_reactions_are_the_servers_eight_in_its_order() -> None:
    # hcfs-server/src/shares/comments.rs REACTIONS, and the console's REACTION_EMOJI.
    assert REACTIONS == (
        "\U0001f44d",
        "❤️",
        "\U0001f602",
        "\U0001f62e",
        "\U0001f389",
        "\U0001f44f",
        "\U0001f525",
        "\U0001f64c",
    )


@respx.mock
@pytest.mark.anyio
@MODES
async def test_react_puts_the_percent_encoded_emoji_with_no_body(mode: str) -> None:
    _capabilities(**ALL_ON)
    route = respx.put(url__regex=rf"{SHARE}/reactions/.+").mock(return_value=httpx.Response(204))

    await _on_shares(mode, lambda s: s.react(TOKEN, THUMBS))

    request = route.calls.last.request
    assert _path(request) == f"/v1/shares/{TOKEN}/reactions/%F0%9F%91%8D"
    assert request.content == b""
    assert request.headers["Authorization"] == "Bearer tok"


@respx.mock
@pytest.mark.anyio
@MODES
async def test_a_bare_heart_is_sent_as_the_heart_the_server_stores(mode: str) -> None:
    _capabilities(**ALL_ON)
    route = respx.put(url__regex=rf"{SHARE}/reactions/.+").mock(return_value=httpx.Response(204))

    await _on_shares(mode, lambda s: s.react(TOKEN, "❤"))

    assert _path(route.calls.last.request).endswith("/reactions/%E2%9D%A4%EF%B8%8F")


@respx.mock
@pytest.mark.anyio
@MODES
async def test_unreact_deletes_the_reaction(mode: str) -> None:
    _capabilities(**ALL_ON)
    route = respx.delete(url__regex=rf"{SHARE}/reactions/.+").mock(return_value=httpx.Response(204))

    await _on_shares(mode, lambda s: s.unreact(TOKEN, HEART))

    assert _path(route.calls.last.request).endswith("/reactions/%E2%9D%A4%EF%B8%8F")


@respx.mock
@pytest.mark.anyio
@MODES
@pytest.mark.parametrize("method", ["react", "unreact"])
async def test_an_emoji_outside_the_set_fails_before_any_request(mode: str, method: str) -> None:
    caps = _capabilities(**ALL_ON)

    with pytest.raises(ValueError, match="reaction must be one of"):
        await _on_shares(mode, lambda s: getattr(s, method)(TOKEN, "\U0001f4a9"))

    assert not caps.called


@respx.mock
@pytest.mark.anyio
@MODES
async def test_reactions_off_and_blocked_are_forbidden_with_their_codes(mode: str) -> None:
    _capabilities(**ALL_ON)
    route = respx.put(url__regex=rf"{SHARE}/reactions/.+")
    route.side_effect = [
        httpx.Response(403, json={"error": "reactions-off"}),
        httpx.Response(403, json={"error": "blocked"}),
    ]

    codes = []
    for _ in range(2):
        with pytest.raises(errors.Forbidden) as caught:
            await _on_shares(mode, lambda s: s.react(TOKEN, THUMBS))
        codes.append(caught.value.code)

    assert codes == ["reactions-off", "blocked"]


@respx.mock
@pytest.mark.anyio
@MODES
async def test_reaction_writes_stop_when_the_server_has_comments_off(mode: str) -> None:
    _capabilities(share_insights=True)
    route = respx.put(url__regex=rf"{SHARE}/reactions/.+")

    with pytest.raises(ValueError, match="share_comments off"):
        await _on_shares(mode, lambda s: s.react(TOKEN, THUMBS))
    with pytest.raises(ValueError, match="share_comments off"):
        await _on_shares(mode, lambda s: s.unreact(TOKEN, THUMBS))

    assert not route.called


# =============================================================================
# Reaction moments
# =============================================================================


@respx.mock
@pytest.mark.anyio
@MODES
async def test_react_at_posts_the_moment_once(mode: str) -> None:
    _capabilities(**ALL_ON)
    route = respx.post(url__regex=rf"{SHARE}/reactions/.+/moments").mock(
        return_value=httpx.Response(204)
    )

    await _on_shares(mode, lambda s: s.react_at(TOKEN, "\U0001f525", 98_000))

    request = route.calls.last.request
    assert _path(request) == f"/v1/shares/{TOKEN}/reactions/%F0%9F%94%A5/moments"
    assert json.loads(request.content) == {"at_ms": 98_000}


@respx.mock
@pytest.mark.anyio
@MODES
async def test_a_lost_moment_is_not_sent_twice(mode: str) -> None:
    _capabilities(**ALL_ON)
    route = respx.post(url__regex=rf"{SHARE}/reactions/.+/moments").mock(
        return_value=httpx.Response(502)
    )

    with pytest.raises(errors.ServerError):
        await _on_shares(mode, lambda s: s.react_at(TOKEN, THUMBS, 0))

    assert route.call_count == 1


@respx.mock
@pytest.mark.anyio
@MODES
async def test_the_moment_limit_is_a_conflict(mode: str) -> None:
    _capabilities(**ALL_ON)
    respx.post(url__regex=rf"{SHARE}/reactions/.+/moments").mock(
        return_value=httpx.Response(409, json={"error": "moment-limit"})
    )

    with pytest.raises(errors.Conflict) as caught:
        await _on_shares(mode, lambda s: s.react_at(TOKEN, THUMBS, 5))

    assert caught.value.code == "moment-limit"


@respx.mock
@pytest.mark.anyio
@MODES
@pytest.mark.parametrize("at_ms", [-1, 604_800_001])
async def test_a_moment_outside_seven_days_fails_before_any_request(mode: str, at_ms: int) -> None:
    caps = _capabilities(**ALL_ON)

    with pytest.raises(ValueError, match="at_ms must be from 0"):
        await _on_shares(mode, lambda s: s.react_at(TOKEN, THUMBS, at_ms))

    assert not caps.called


@respx.mock
@pytest.mark.anyio
@MODES
async def test_the_last_moment_of_seven_days_is_taken(mode: str) -> None:
    _capabilities(**ALL_ON)
    route = respx.post(url__regex=rf"{SHARE}/reactions/.+/moments").mock(
        return_value=httpx.Response(204)
    )

    await _on_shares(mode, lambda s: s.react_at(TOKEN, THUMBS, 604_800_000))

    assert json.loads(route.calls.last.request.content) == {"at_ms": 604_800_000}


@respx.mock
@pytest.mark.anyio
@MODES
async def test_reaction_moments_are_read_anonymously_in_order(mode: str) -> None:
    _capabilities(**ALL_ON)
    body = {
        "moments": [
            {"emoji": THUMBS, "at_ms": 5000},
            {"emoji": "\U0001f525", "at_ms": 98000},
        ]
    }
    route = respx.get(f"{SHARE}/reactions/moments").mock(
        return_value=httpx.Response(200, json=body)
    )

    found = await _on_shares(mode, lambda s: s.reaction_moments(TOKEN))

    assert list(found) == [
        ReactionMoment(emoji=THUMBS, at_ms=5000),
        ReactionMoment(emoji="\U0001f525", at_ms=98000),
    ]
    assert "Authorization" not in route.calls.last.request.headers


@respx.mock
@pytest.mark.anyio
@MODES
async def test_moments_stop_when_the_server_does_not_have_them(mode: str) -> None:
    _capabilities(share_insights=True, share_comments=True)
    post = respx.post(url__regex=rf"{SHARE}/reactions/.+/moments")
    get = respx.get(f"{SHARE}/reactions/moments")

    with pytest.raises(ValueError, match="share_reaction_moments off"):
        await _on_shares(mode, lambda s: s.react_at(TOKEN, THUMBS, 0))
    with pytest.raises(ValueError, match="share_reaction_moments off"):
        await _on_shares(mode, lambda s: s.reaction_moments(TOKEN))

    assert not post.called
    assert not get.called


# =============================================================================
# Blocks
# =============================================================================


@respx.mock
@pytest.mark.anyio
@MODES
async def test_block_and_unblock_go_through_the_comment(mode: str) -> None:
    _capabilities(**ALL_ON)
    block = respx.post(f"{SHARE}/comments/41/block").mock(return_value=httpx.Response(204))
    unblock = respx.delete(f"{SHARE}/comments/41/block").mock(return_value=httpx.Response(204))

    await _on_shares(mode, lambda s: s.block_author(TOKEN, "41"))
    await _on_shares(mode, lambda s: s.unblock_author(TOKEN, "41"))

    assert block.calls.last.request.headers["Authorization"] == "Bearer tok"
    assert block.calls.last.request.content == b""
    assert unblock.called


@respx.mock
@pytest.mark.anyio
@MODES
@pytest.mark.parametrize("method", ["block_author", "unblock_author"])
async def test_a_block_needs_a_comment_id_before_any_request(mode: str, method: str) -> None:
    caps = _capabilities(**ALL_ON)

    with pytest.raises(ValueError, match="comment id"):
        await _on_shares(mode, lambda s: getattr(s, method)(TOKEN, "41/../42"))

    assert not caps.called


@respx.mock
@pytest.mark.anyio
@MODES
async def test_a_block_is_retried_after_a_lost_response(mode: str) -> None:
    # Blocking twice is the same as once, so a 502 may be retried.
    _capabilities(**ALL_ON)
    route = respx.post(f"{SHARE}/comments/41/block")
    route.side_effect = [httpx.Response(502), httpx.Response(204)]

    await _on_shares(mode, lambda s: s.block_author(TOKEN, "41"))

    assert route.call_count == 2


@respx.mock
@pytest.mark.anyio
@MODES
@pytest.mark.parametrize("method", ["block_author", "unblock_author"])
async def test_blocks_stop_when_the_server_has_comments_off(mode: str, method: str) -> None:
    _capabilities(share_insights=True)
    route = respx.route(url__regex=rf"{SHARE}/comments/41/block")

    with pytest.raises(ValueError, match="share_comments off"):
        await _on_shares(mode, lambda s: getattr(s, method)(TOKEN, "41"))

    assert not route.called


# =============================================================================
# Insights seen
# =============================================================================


@respx.mock
@pytest.mark.anyio
@MODES
async def test_mark_insights_seen_puts_with_no_body(mode: str) -> None:
    _capabilities(**ALL_ON)
    route = respx.put(f"{SHARE}/insights/seen").mock(return_value=httpx.Response(204))

    await _on_shares(mode, lambda s: s.mark_insights_seen(TOKEN))

    assert route.calls.last.request.content == b""
    assert route.calls.last.request.headers["Authorization"] == "Bearer tok"


@respx.mock
@pytest.mark.anyio
@MODES
async def test_seen_stops_when_the_server_keeps_no_listing_counts(mode: str) -> None:
    # share_insights alone is true on servers that predate the counts.
    _capabilities(share_insights=True, share_comments=True)
    route = respx.put(f"{SHARE}/insights/seen")

    with pytest.raises(ValueError, match="share_listing_counts off"):
        await _on_shares(mode, lambda s: s.mark_insights_seen(TOKEN))

    assert not route.called
