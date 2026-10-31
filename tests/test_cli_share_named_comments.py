"""``share comment-post --name / --mention``, the viewer secret file, and mentions in listings."""

from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from click.testing import CliRunner, Result

from hippius_drive._links import DEFAULT_CONSOLE
from hippius_drive.cli import main
from hippius_drive.crypto import comments, mnemonic_store, sharing
from hippius_drive.crypto.comments import CommentMention

BASE = "https://example.test"
MASTER = " ".join(["abandon"] * 23 + ["art"])
SS58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
PASSWORD = "pw-123456"
VECTORS: dict[str, Any] = json.loads(
    (Path(__file__).parent / "vectors" / "share-comments-vectors.json").read_text("utf-8")
)
TOKEN: str = VECTORS["token"]
SHARE_KEY = bytes.fromhex(VECTORS["share_key_hex"])
KEY = comments.comment_key(SHARE_KEY)
URL = sharing.file_share_url(DEFAULT_CONSOLE, TOKEN, SHARE_KEY)
SHARE = f"{BASE}/v1/shares/{TOKEN}"
CAPS = {"share_insights": True, "share_comments": True, "share_comment_replies": True}


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    path = tmp_path / "keys" / "enc_mnemonic.json"
    path.parent.mkdir(mode=0o700)
    mnemonic_store.save(path, MASTER, PASSWORD)
    return {
        "HIPPIUS_TOKEN": "tok",
        "HIPPIUS_ACCOUNT_SS58": SS58,
        "HIPPIUS_SERVER_URL": BASE,
        "HIPPIUS_MNEMONIC_FILE": str(path),
        "HIPPIUS_PASSWORD": PASSWORD,
        "HIPPIUS_SHARE_URL": URL,
        "HIPPIUS_SHARE_PASSWORD": "",
    }


def _secret_file(env: dict[str, str]) -> Path:
    return Path(env["HIPPIUS_MNEMONIC_FILE"]).parent / "viewer-secret"


def run(args: list[str], env: dict[str, str]) -> Result:
    return CliRunner().invoke(main, args, env=env, catch_exceptions=False)


@pytest.fixture(autouse=True)
def _caps() -> None:
    respx.get(f"{BASE}/v1/capabilities").mock(return_value=httpx.Response(200, json=CAPS))


def _posted() -> respx.Route:
    return respx.post(f"{SHARE}/comments").mock(
        return_value=httpx.Response(201, json={"id": "50", "created_at": "2026-10-31T10:00:00Z"})
    )


def _sent(route: respx.Route) -> dict[str, Any]:
    return json.loads(route.calls.last.request.content)


def _row(comment_id: str, text: str, **extra: Any) -> dict[str, Any]:
    name = extra.pop("name", None)
    mentions = extra.pop("mentions", ())
    sealed = comments.seal_comment(KEY, TOKEN, text, name=name, mentions=mentions)
    return {
        "id": comment_id,
        "ciphertext": sealed.ciphertext,
        "nonce": sealed.nonce,
        "created_at": f"2026-10-13T10:00:{int(comment_id):02}Z",
        "anonymous": name is None,
        **extra,
    }


def _thread(*rows: dict[str, Any]) -> None:
    body = {"comments": list(rows), "next_after": None}
    respx.get(f"{SHARE}/comments").mock(return_value=httpx.Response(200, json=body))


def _listing(*tokens: str) -> None:
    body = [{"share_token": token, "filename": "clip.mp4"} for token in tokens]
    respx.get(f"{BASE}/v1/shares").mock(return_value=httpx.Response(200, json=body))


@respx.mock
def test_a_named_comment_makes_a_secret_once_and_keeps_its_viewer_id(
    env: dict[str, str],
) -> None:
    route = _posted()

    first = run(["share", "comment-post", "hi", "--name", "Grace"], env)
    first_id = _sent(route)["viewer_id"]
    second = run(["share", "comment-post", "again", "--name", "Grace"], env)

    assert (first.exit_code, second.exit_code) == (0, 0)
    assert first.output == "posted 50\n"
    assert _sent(route)["viewer_id"] == first_id
    path = _secret_file(env)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    raw = path.read_text().strip()
    secret = base64.urlsafe_b64decode(raw + "=")
    assert len(raw) == 43
    assert first_id == comments.viewer_id(secret, TOKEN)
    opened = comments.open_comment(KEY, TOKEN, _sent(route)["ciphertext"], _sent(route)["nonce"])
    assert opened.name == "Grace"


@respx.mock
def test_an_anonymous_comment_makes_no_secret(env: dict[str, str]) -> None:
    route = _posted()

    result = run(["share", "comment-post", "hi"], env)

    assert result.exit_code == 0
    assert _sent(route)["anonymous"] is True
    assert not _secret_file(env).exists()


@respx.mock
def test_a_secret_other_users_can_read_is_refused(env: dict[str, str]) -> None:
    path = _secret_file(env)
    path.write_text(base64.urlsafe_b64encode(bytes(32)).decode().rstrip("=") + "\n")
    os.chmod(path, 0o644)
    route = _posted()

    result = run(["share", "comment-post", "hi", "--name", "Grace"], env)

    assert result.exit_code == 1
    assert "readable by other users" in result.output
    assert not route.called


@respx.mock
@pytest.mark.parametrize("content", ["short", "!!!!", ""])
def test_a_damaged_secret_is_refused_with_how_to_fix(env: dict[str, str], content: str) -> None:
    path = _secret_file(env)
    path.write_text(content)
    os.chmod(path, 0o600)
    route = _posted()

    result = run(["share", "comment-post", "hi", "--name", "Grace"], env)

    assert result.exit_code == 1
    assert "is not a viewer secret; delete it" in result.output
    assert not route.called


@respx.mock
def test_a_mention_is_picked_from_the_comments_by_name(env: dict[str, str]) -> None:
    _thread(_row("41", "a", name="Ada"), _row("42", "b", name="Dee", owner=True))
    _listing()
    route = _posted()

    text = "@Dee and @Ada"
    result = run(["share", "comment-post", text, "--mention", "Ada", "--mention", "owner"], env)

    assert result.exit_code == 0
    body = _sent(route)
    opened = comments.open_comment(KEY, TOKEN, body["ciphertext"], body["nonce"])
    assert opened.mentions == (
        CommentMention("owner", "Dee"),
        CommentMention("commenter", "Ada", "41"),
    )


@respx.mock
def test_a_mention_nobody_matches_lists_who_can_be_tagged(env: dict[str, str]) -> None:
    _thread(_row("41", "a", name="Ada"))
    _listing()
    route = _posted()

    result = run(["share", "comment-post", "@Bo hi", "--mention", "Bo"], env)

    assert result.exit_code == 1
    assert 'nobody to tag as "Bo"; offered: "Owner", "Ada"' in result.output
    assert not route.called


@respx.mock
def test_comments_mark_the_ones_that_mention_you(env: dict[str, str]) -> None:
    ada = CommentMention("commenter", "Ada", "41")
    _thread(
        _row("41", "mine", name="Ada", mine=True), _row("42", "@Ada hi", name="Bo", mentions=[ada])
    )

    plain = run(["share", "comments"], env)
    as_json = json.loads(run(["share", "comments", "--json"], env).output)

    lines = plain.output.splitlines()
    assert not lines[0].endswith("(mentions you)")
    assert lines[1].endswith('"Bo": @Ada hi  (mentions you)')
    assert as_json[1]["mentions"] == [{"kind": "commenter", "name": "Ada", "comment": "41"}]
    assert (as_json[0]["mentions_me"], as_json[1]["mentions_me"]) == (False, True)


@respx.mock
def test_a_secret_that_cannot_be_written_says_where(env: dict[str, str]) -> None:
    folder = _secret_file(env).parent
    os.chmod(folder, 0o500)
    route = _posted()
    try:
        result = run(["share", "comment-post", "hi", "--name", "Grace"], env)
    finally:
        os.chmod(folder, 0o700)

    assert result.exit_code == 1
    assert f"cannot write {_secret_file(env)}" in result.output
    assert not route.called
