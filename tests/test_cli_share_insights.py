"""The ``share`` settings, insights, comments, and reactions commands."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from click.testing import CliRunner, Result

from hippius_drive._links import DEFAULT_CONSOLE
from hippius_drive.cli import main
from hippius_drive.crypto import comments, mnemonic_store, owner_wrap, sharing
from hippius_drive.crypto.sharing import ShareSecret

BASE = "https://example.test"
MASTER = " ".join(["abandon"] * 23 + ["art"])
SS58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
PASSWORD = "pw-123456"

VECTORS: dict[str, Any] = json.loads(
    (Path(__file__).parent / "vectors" / "share-comments-vectors.json").read_text("utf-8")
)
TOKEN: str = VECTORS["token"]
SHARE_KEY = bytes.fromhex(VECTORS["share_key_hex"])
URL = sharing.file_share_url(DEFAULT_CONSOLE, TOKEN, SHARE_KEY)
SHARE = f"{BASE}/v1/shares/{TOKEN}"
CAPS = {"share_insights": True, "share_comments": True, "share_comment_replies": True}


def _vector(kind: str) -> dict[str, str]:
    return next(v for v in VECTORS["vectors"] if v["kind"] == kind)


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
        # Blank, so values exported in the shell running the tests are ignored.
        "HIPPIUS_SHARE_URL": "",
        "HIPPIUS_SHARE_PASSWORD": "",
    }


def run(args: list[str], env: dict[str, str]) -> Result:
    return CliRunner().invoke(main, args, env=env, catch_exceptions=False)


def _url_file(tmp_path: Path, url: str = URL) -> Path:
    path = tmp_path / "link.txt"
    path.write_text(url)
    path.chmod(0o600)
    return path


def _listing(**row: Any) -> None:
    body = [{"share_token": TOKEN, "filename": "clip.mp4", **row}]
    respx.get(f"{BASE}/v1/shares").mock(return_value=httpx.Response(200, json=body))


def _caps() -> None:
    respx.get(f"{BASE}/v1/capabilities").mock(return_value=httpx.Response(200, json=CAPS))


@respx.mock
def test_settings_without_switches_reads_the_listing(env: dict[str, str]) -> None:
    _listing(settings={"insights": True, "comments": False, "reactions": True})

    result = run(["share", "settings", TOKEN], env)

    assert result.exit_code == 0
    assert result.output.split() == ["insights", "on", "comments", "off", "reactions", "on"]
    as_json = json.loads(run(["share", "settings", TOKEN, "--json"], env).output)
    assert as_json == {"insights": True, "comments": False, "reactions": True}


@respx.mock
def test_settings_from_a_server_that_predates_them_say_so(env: dict[str, str]) -> None:
    _listing()
    result = run(["share", "settings", TOKEN], env)
    assert result.exit_code == 1
    assert "does not report link settings" in result.output


@respx.mock
def test_settings_of_an_unknown_share_fail(env: dict[str, str]) -> None:
    _listing()
    result = run(["share", "settings", "other"], env)
    assert result.exit_code == 1
    assert "no file share with that token" in result.output


@respx.mock
def test_settings_switches_patch_only_what_was_named(env: dict[str, str]) -> None:
    _caps()
    route = respx.patch(f"{SHARE}/settings").mock(
        return_value=httpx.Response(
            200, json={"insights": True, "comments": False, "reactions": False}
        )
    )

    result = run(["share", "settings", TOKEN, "--insights", "on", "--comments", "off"], env)

    assert result.exit_code == 0
    assert json.loads(route.calls.last.request.content) == {"insights": True, "comments": False}


@respx.mock
def test_a_free_plan_gets_an_upgrade_message(env: dict[str, str]) -> None:
    _caps()
    respx.patch(f"{SHARE}/settings").mock(
        return_value=httpx.Response(403, json={"error": "paid_plan_required", "message": "free"})
    )

    result = run(["share", "settings", TOKEN, "--comments", "on"], env)

    assert result.exit_code == 1
    assert "paid_plan_required" in result.output
    assert "needs a paid Drive plan" in result.output


@respx.mock
def test_an_unreachable_plan_source_says_to_retry(env: dict[str, str]) -> None:
    _caps()
    respx.patch(f"{SHARE}/settings").mock(
        return_value=httpx.Response(502, json={"error": "billing_unavailable", "message": "x"})
    )

    result = run(["share", "settings", TOKEN, "--comments", "on"], env)

    assert result.exit_code == 1
    assert "try again in a minute" in result.output


@respx.mock
def test_a_server_with_insights_off_is_named(env: dict[str, str]) -> None:
    respx.get(f"{BASE}/v1/capabilities").mock(return_value=httpx.Response(200, json={}))
    result = run(["share", "settings", TOKEN, "--insights", "off"], env)
    assert result.exit_code == 1
    assert "share_insights off" in result.output


def _paid(name_ct: str | None) -> dict[str, Any]:
    return {
        "plan": "paid",
        "total_views": 3,
        "unique_viewers": 1,
        "completion_rate": 0.5,
        "retention": [100],
        "viewers": [
            {
                "viewer_id": "AQEBAQEBAQEBAQEBAQEBAQ",
                "visits": 3,
                "watched_ms": 61000,
                "name_ct": name_ct,
                "name_nonce": _vector("viewer-name")["nonce_b64"],
            }
        ],
        "locked": [],
    }


@respx.mock
def test_insights_read_names_through_the_owner_wrap(env: dict[str, str]) -> None:
    wrap = owner_wrap.seal_file_secret(MASTER, SS58, TOKEN, ShareSecret(SHARE_KEY))
    _listing(owner_wrap=base64.b64encode(wrap).decode())
    _caps()
    paid = _paid(_vector("viewer-name")["ciphertext_b64"])
    respx.get(f"{SHARE}/insights").mock(return_value=httpx.Response(200, json=paid))

    result = run(["share", "insights", TOKEN], env)

    assert result.exit_code == 0
    assert "views           3" in result.output
    assert "completion      50%" in result.output
    assert "3 visits  61s  Ahmad" in result.output
    assert "hidden" not in result.output


@respx.mock
def test_insights_without_a_key_say_names_are_hidden(env: dict[str, str]) -> None:
    _listing()
    _caps()
    paid = _paid(_vector("viewer-name")["ciphertext_b64"])
    respx.get(f"{SHARE}/insights").mock(return_value=httpx.Response(200, json=paid))

    result = run(["share", "insights", TOKEN], env)

    assert result.exit_code == 0
    assert "61s  -" in result.output
    assert "names are hidden" in result.output


@respx.mock
def test_free_insights_name_what_is_locked_and_emit_json(env: dict[str, str]) -> None:
    _listing()
    _caps()
    free = {"plan": "free", "total_views": 2, "unique_viewers": 1, "locked": ["viewers"]}
    respx.get(f"{SHARE}/insights").mock(return_value=httpx.Response(200, json=free))

    result = run(["share", "insights", TOKEN], env)
    as_json = json.loads(run(["share", "insights", TOKEN, "--json"], env).output)

    assert "locked          viewers (paid Drive plan)" in result.output
    assert "completion" not in result.output
    assert as_json["plan"] == "free"
    assert as_json["total_views"] == 2


def _comments_page() -> dict[str, Any]:
    named = _vector("comment")
    return {
        "comments": [
            {"id": "40", "parent_id": None, "at_ms": 83000, "deleted": True},
            {
                "id": "41",
                "parent_id": "40",
                "ciphertext": named["ciphertext_b64"],
                "nonce": named["nonce_b64"],
                "at_ms": 83000,
                "created_at": "2026-10-13T10:00:00Z",
                "owner": True,
            },
            {
                "id": "42",
                "parent_id": None,
                "ciphertext": _vector("viewer-name")["ciphertext_b64"],
                "nonce": named["nonce_b64"],
                "at_ms": None,
                "created_at": "2026-10-13T10:01:00Z",
                "anonymous": True,
            },
        ],
        "next_after": None,
    }


@respx.mock
def test_comments_from_a_url_file_are_decrypted(env: dict[str, str], tmp_path: Path) -> None:
    _caps()
    route = respx.get(f"{SHARE}/comments").mock(
        return_value=httpx.Response(200, json=_comments_page())
    )

    result = run(["share", "comments", "--url-file", str(_url_file(tmp_path))], env)

    assert result.exit_code == 0
    assert route.called
    lines = result.output.splitlines()
    assert "1:23  anonymous: (deleted)" in lines[0]
    assert "re 40  Ahmad (owner): Looks great at 1:23!" in lines[1]
    assert "-  anonymous: (does not open with this link's key)" in lines[2]
    assert URL not in result.output


@respx.mock
def test_comments_json_carries_every_field(env: dict[str, str]) -> None:
    _caps()
    respx.get(f"{SHARE}/comments").mock(return_value=httpx.Response(200, json=_comments_page()))

    result = run(["share", "comments", "--json"], {**env, "HIPPIUS_SHARE_URL": URL})

    rows = json.loads(result.output)
    assert rows[1]["text"] == "Looks great at 1:23!"
    assert rows[1]["name"] == "Ahmad"
    assert rows[0]["deleted"]


@respx.mock
def test_comments_on_your_own_share_use_the_owner_wrap(env: dict[str, str]) -> None:
    wrap = owner_wrap.seal_file_secret(MASTER, SS58, TOKEN, ShareSecret(SHARE_KEY))
    _listing(owner_wrap=base64.b64encode(wrap).decode())
    _caps()
    respx.get(f"{SHARE}/comments").mock(return_value=httpx.Response(200, json=_comments_page()))

    result = run(["share", "comments", TOKEN], env)

    assert result.exit_code == 0
    assert "Looks great at 1:23!" in result.output


@respx.mock
def test_comments_without_a_key_explain_where_to_get_one(env: dict[str, str]) -> None:
    _listing()
    for args in (["share", "comments", TOKEN], ["share", "comments"]):
        result = run(args, env)
        assert result.exit_code == 1
        assert "--url-file" in result.output


@respx.mock
def test_a_link_for_another_share_is_refused(env: dict[str, str], tmp_path: Path) -> None:
    result = run(["share", "comments", "other", "--url-file", str(_url_file(tmp_path))], env)
    assert result.exit_code == 1
    assert "different share" in result.output


def test_a_link_given_twice_is_refused(env: dict[str, str], tmp_path: Path) -> None:
    both = {**env, "HIPPIUS_SHARE_URL": URL}
    result = run(["share", "comments", "--url-file", str(_url_file(tmp_path))], both)
    assert result.exit_code == 1
    assert "give the link once" in result.output


@respx.mock
def test_comment_text_cannot_drive_the_terminal(env: dict[str, str]) -> None:
    _caps()
    key = comments.comment_key(SHARE_KEY)
    sealed = comments.seal_comment(key, TOKEN, "hi\x1b[2Jthere\nnext")
    row = {"id": "9", "ciphertext": sealed.ciphertext, "nonce": sealed.nonce}
    page = {"comments": [row], "next_after": None}
    respx.get(f"{SHARE}/comments").mock(return_value=httpx.Response(200, json=page))

    result = run(["share", "comments"], {**env, "HIPPIUS_SHARE_URL": URL})

    assert "\x1b" not in result.output
    assert "hi?[2Jthere next" in result.output


@respx.mock
def test_comment_post_seals_for_the_link(env: dict[str, str], tmp_path: Path) -> None:
    _caps()
    route = respx.post(f"{SHARE}/comments").mock(
        return_value=httpx.Response(201, json={"id": "50", "created_at": "now"})
    )

    args = ["share", "comment-post", "agreed", TOKEN, "--reply-to", "41"]
    result = run([*args, "--url-file", str(_url_file(tmp_path))], env)

    assert result.exit_code == 0
    assert result.output.strip() == "posted 50"
    body = json.loads(route.calls.last.request.content)
    assert body["parent_id"] == "41"
    key = comments.comment_key(SHARE_KEY)
    assert comments.open_comment(key, TOKEN, body["ciphertext"], body["nonce"]).text == "agreed"


@respx.mock
def test_comment_post_with_a_password_link(env: dict[str, str]) -> None:
    _caps()
    wrapped = sharing.wrap_share_key("hunter22", SHARE_KEY)
    private = sharing.file_share_url_private(DEFAULT_CONSOLE, TOKEN, wrapped)
    route = respx.post(f"{SHARE}/comments").mock(
        return_value=httpx.Response(201, json={"id": "51"})
    )

    linked = {**env, "HIPPIUS_SHARE_URL": private, "HIPPIUS_SHARE_PASSWORD": "hunter22"}
    result = run(["share", "comment-post", "hi", "--at-ms", "5000"], linked)

    assert result.exit_code == 0
    assert json.loads(route.calls.last.request.content)["at_ms"] == 5000


@respx.mock
def test_comments_off_is_reported(env: dict[str, str]) -> None:
    _caps()
    respx.post(f"{SHARE}/comments").mock(
        return_value=httpx.Response(403, json={"error": "comments-off"})
    )
    result = run(["share", "comment-post", "hi"], {**env, "HIPPIUS_SHARE_URL": URL})
    assert result.exit_code == 1
    assert "comments-off" in result.output


@respx.mock
def test_comment_rm_and_reactions(env: dict[str, str]) -> None:
    _caps()
    route = respx.delete(f"{SHARE}/comments/41").mock(return_value=httpx.Response(204))
    body = {"counts": {"\U0001f44d": 3, "\U0001f525": 1}, "mine": ["\U0001f525"]}
    respx.get(f"{SHARE}/reactions").mock(return_value=httpx.Response(200, json=body))

    removed = run(["share", "comment-rm", TOKEN, "41"], env)
    reacted = run(["share", "reactions", TOKEN], env)
    as_json = json.loads(run(["share", "reactions", TOKEN, "--json"], env).output)

    assert removed.output.strip() == "deleted"
    assert route.called
    assert reacted.output.splitlines() == ["\U0001f44d  3", "\U0001f525  1  (mine)"]
    assert as_json[1] == {"emoji": "\U0001f525", "count": 1, "mine": True}
