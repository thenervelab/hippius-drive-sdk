"""The ``share`` react, unreact, moments, block, unblock and seen commands."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from click.testing import CliRunner, Result

from hippius_drive.cli import main
from hippius_drive.crypto import mnemonic_store

BASE = "https://example.test"
MASTER = " ".join(["abandon"] * 23 + ["art"])
SS58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
PASSWORD = "pw-123456"
TOKEN = "sx5QIbv8AjPlxin1kZs0jw"
SHARE = f"{BASE}/v1/shares/{TOKEN}"
FIRE = "\U0001f525"
CAPS = {
    "share_insights": True,
    "share_comments": True,
    "share_reaction_moments": True,
    "share_listing_counts": True,
}


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    path = tmp_path / "enc_mnemonic.json"
    mnemonic_store.save(path, MASTER, PASSWORD)
    return {
        "HIPPIUS_TOKEN": "tok",
        "HIPPIUS_ACCOUNT_SS58": SS58,
        "HIPPIUS_SERVER_URL": BASE,
        "HIPPIUS_MNEMONIC_FILE": str(path),
        "HIPPIUS_PASSWORD": PASSWORD,
    }


def run(args: list[str], env: dict[str, str]) -> Result:
    return CliRunner().invoke(main, args, env=env, catch_exceptions=False)


@pytest.fixture(autouse=True)
def _caps() -> None:
    respx.get(f"{BASE}/v1/capabilities").mock(return_value=httpx.Response(200, json=CAPS))


@respx.mock
def test_react_adds_the_reaction(env: dict[str, str]) -> None:
    route = respx.put(url__regex=rf"{SHARE}/reactions/.+").mock(return_value=httpx.Response(204))

    result = run(["share", "react", FIRE, TOKEN], env)

    assert result.exit_code == 0
    assert result.output == "reacted\n"
    assert route.calls.last.request.url.raw_path.endswith(b"/reactions/%F0%9F%94%A5")


@respx.mock
def test_react_at_ms_sends_a_moment(env: dict[str, str]) -> None:
    put = respx.put(url__regex=rf"{SHARE}/reactions/.+")
    post = respx.post(url__regex=rf"{SHARE}/reactions/.+/moments").mock(
        return_value=httpx.Response(204)
    )

    result = run(["share", "react", FIRE, TOKEN, "--at-ms", "98000"], env)

    assert result.exit_code == 0
    assert json.loads(post.calls.last.request.content) == {"at_ms": 98000}
    assert not put.called


@respx.mock
def test_react_with_an_unknown_emoji_names_the_set(env: dict[str, str]) -> None:
    result = run(["share", "react", "x", TOKEN], env)

    assert result.exit_code == 1
    assert "reaction must be one of" in result.output


@respx.mock
def test_react_when_blocked_says_so(env: dict[str, str]) -> None:
    respx.put(url__regex=rf"{SHARE}/reactions/.+").mock(
        return_value=httpx.Response(403, json={"error": "blocked"})
    )

    result = run(["share", "react", FIRE, TOKEN], env)

    assert result.exit_code == 1
    assert "blocked" in result.output


@respx.mock
def test_unreact_removes_the_reaction(env: dict[str, str]) -> None:
    route = respx.delete(url__regex=rf"{SHARE}/reactions/.+").mock(return_value=httpx.Response(204))

    result = run(["share", "unreact", FIRE, TOKEN], env)

    assert result.exit_code == 0
    assert result.output == "removed\n"
    assert route.called


@respx.mock
def test_moments_lists_each_moment_as_a_player_shows_it(env: dict[str, str]) -> None:
    body = {"moments": [{"emoji": FIRE, "at_ms": 98000}, {"emoji": FIRE, "at_ms": 3_723_000}]}
    respx.get(f"{SHARE}/reactions/moments").mock(return_value=httpx.Response(200, json=body))

    plain = run(["share", "moments", TOKEN], env)
    as_json = run(["share", "moments", TOKEN, "--json"], env)

    assert plain.exit_code == 0
    assert plain.output.splitlines() == [f"    1:38  {FIRE}", f" 1:02:03  {FIRE}"]
    assert json.loads(as_json.output) == body["moments"]


@respx.mock
def test_block_and_unblock(env: dict[str, str]) -> None:
    block = respx.post(f"{SHARE}/comments/41/block").mock(return_value=httpx.Response(204))
    unblock = respx.delete(f"{SHARE}/comments/41/block").mock(return_value=httpx.Response(204))

    blocked = run(["share", "block", TOKEN, "41"], env)
    unblocked = run(["share", "unblock", TOKEN, "41"], env)

    assert (blocked.output, unblocked.output) == ("blocked\n", "unblocked\n")
    assert block.called
    assert unblock.called


@respx.mock
def test_seen_marks_the_insights_seen(env: dict[str, str]) -> None:
    route = respx.put(f"{SHARE}/insights/seen").mock(return_value=httpx.Response(204))

    result = run(["share", "seen", TOKEN], env)

    assert result.exit_code == 0
    assert result.output == "marked seen\n"
    assert route.called
