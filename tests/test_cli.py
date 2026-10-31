import ast
import base64
import json
import os
from pathlib import Path
from typing import Any

import blake3
import click
import httpx
import pytest
import respx
from click.testing import CliRunner, Result

from hippius_drive import __version__, _config, _links, cli
from hippius_drive._transport import Transport
from hippius_drive.cli import main
from hippius_drive.client import Client
from hippius_drive.crypto import (
    file_cipher,
    folder_link,
    grant,
    hashes,
    invite_link,
    kdf,
    mnemonic_store,
    sharing,
)
from hippius_drive.identity import Identity
from tests.helpers import manifest_from, multipart_parts

BASE = "https://example.test"
MASTER = " ".join(["abandon"] * 23 + ["art"])
SS58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
FOLDER = "37a8eec1ce19687d"
PASSWORD = "pw-123456"

FILE_JSON = {
    "path_hash": list(hashes.path_hash("a.bin")),
    "salted_hash": [7] * 32,
    "size_bytes": 1024,
    "revision_seq": 1,
    "revision_id": [9] * 32,
    "encrypted_path": [],
    "file_name": "a.bin",
    "relative_path": "a.bin",
    "created_at": 1,
    "updated_at": 1,
}


@pytest.fixture
def mnemonic_file(tmp_path: Path) -> Path:
    path = tmp_path / "enc_mnemonic.json"
    mnemonic_store.save(path, MASTER, PASSWORD)
    return path


@pytest.fixture
def env(mnemonic_file: Path) -> dict[str, str]:
    return {
        "HIPPIUS_TOKEN": "tok",
        "HIPPIUS_ACCOUNT_SS58": SS58,
        "HIPPIUS_SERVER_URL": BASE,
        "HIPPIUS_MNEMONIC_FILE": str(mnemonic_file),
        "HIPPIUS_PASSWORD": PASSWORD,
        # Blank, so an invite exported in the shell running the tests is ignored.
        "HIPPIUS_INVITE_URL": "",
    }


def run(args: list[str], env: dict[str, str] | None = None) -> Result:
    return CliRunner().invoke(main, args, env=env or {}, catch_exceptions=False)


def key() -> bytes:
    return Identity.from_master(MASTER, "default", account_ss58=SS58).encryption_key


def test_version_is_reported() -> None:
    assert __version__ in run(["--version"]).output


def test_init_generates_a_phrase_and_writes_the_store(tmp_path: Path) -> None:
    path = tmp_path / "enc.json"
    env = {"HIPPIUS_MNEMONIC_FILE": str(path), "HIPPIUS_PASSWORD": PASSWORD}
    result = run(["init"], env)
    assert result.exit_code == 0
    phrase = result.output.strip().splitlines()[-1]
    assert len(phrase.split()) == 24
    assert mnemonic_store.load(path, PASSWORD) == phrase


def test_init_imports_an_existing_phrase_and_never_echoes_it(tmp_path: Path) -> None:
    path = tmp_path / "enc.json"
    env = {"HIPPIUS_MNEMONIC_FILE": str(path), "HIPPIUS_PASSWORD": PASSWORD}
    result = run(["init", "--mnemonic", MASTER], env)
    assert result.exit_code == 0
    assert MASTER not in result.output
    assert mnemonic_store.load(path, PASSWORD) == MASTER


def test_init_refuses_to_clobber_without_force(mnemonic_file: Path) -> None:
    env = {"HIPPIUS_MNEMONIC_FILE": str(mnemonic_file), "HIPPIUS_PASSWORD": PASSWORD}
    result = run(["init"], env)
    assert result.exit_code != 0
    assert "--force" in result.output


def test_init_rejects_an_invalid_phrase(tmp_path: Path) -> None:
    env = {"HIPPIUS_MNEMONIC_FILE": str(tmp_path / "e.json"), "HIPPIUS_PASSWORD": PASSWORD}
    result = run(["init", "--mnemonic", "not a phrase"], env)
    assert result.exit_code != 0
    assert "invalid recovery phrase" in result.output


@respx.mock
def test_whoami_reports_the_derived_identity(env: dict[str, str]) -> None:
    route = respx.get(f"{BASE}/list_folders/{SS58}").mock(
        return_value=httpx.Response(200, json={"Success": {"folders": []}})
    )
    output = run(["whoami"], env).output
    assert SS58 in output
    assert FOLDER in output
    assert kdf.folder_hash("default") in output
    assert "accepted for this account" in output
    assert route.call_count == 1


@respx.mock
def test_whoami_surfaces_a_403(env: dict[str, str]) -> None:
    respx.get(f"{BASE}/list_folders/{SS58}").mock(
        return_value=httpx.Response(
            403, json={"Error": {"error": "forbidden", "message": "wrong account"}}
        )
    )
    result = run(["whoami"], env)
    assert result.exit_code == 1
    assert "forbidden" in result.output


@respx.mock
def test_whoami_unlocks_the_mnemonic_once(
    env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    respx.get(f"{BASE}/list_folders/{SS58}").mock(
        return_value=httpx.Response(200, json={"Success": {"folders": []}})
    )
    loads: list[int] = []
    real = mnemonic_store.load

    def counting(path: Path, password: str) -> str:
        loads.append(1)
        return real(path, password)

    monkeypatch.setattr("hippius_drive.cli.mnemonic_store.load", counting)
    assert run(["whoami"], env).exit_code == 0
    assert loads == [1]


def test_whoami_without_an_account_explains_where_it_comes_from(
    env: dict[str, str],
) -> None:
    env.pop("HIPPIUS_ACCOUNT_SS58")
    result = run(["whoami"], env)
    assert result.exit_code != 0
    assert "not something derived from your phrase" in result.output


def test_a_wrong_password_is_a_clean_message(env: dict[str, str]) -> None:
    env["HIPPIUS_PASSWORD"] = "wrong"
    result = run(["whoami"], env)
    assert result.exit_code != 0
    assert "wrong password" in result.output.lower()


def test_invite_put_without_a_mnemonic_points_at_init(env: dict[str, str], tmp_path: Path) -> None:
    env["HIPPIUS_MNEMONIC_FILE"] = str(tmp_path / "nope.json")
    result = run(["invite", "put"], env)
    assert result.exit_code != 0
    assert "hippius-drive init" in result.output


def test_a_missing_mnemonic_file_points_at_init(env: dict[str, str], tmp_path: Path) -> None:
    env["HIPPIUS_MNEMONIC_FILE"] = str(tmp_path / "nope.json")
    result = run(["whoami"], env)
    assert result.exit_code != 0
    assert "hippius-drive init" in result.output


@respx.mock
def test_folders_lists_one_line_per_folder(env: dict[str, str]) -> None:
    respx.get(f"{BASE}/list_folders/{SS58}").mock(
        return_value=httpx.Response(
            200,
            json={
                "Success": {
                    "folders": [
                        {
                            "label": "My Docs",
                            "folder_hash": FOLDER,
                            "file_count": 3,
                            "total_bytes": 99,
                        }
                    ]
                }
            },
        )
    )
    output = run(["folders"], env).output
    assert FOLDER in output
    assert "My Docs" in output


@respx.mock
def test_folders_json_is_machine_readable(env: dict[str, str]) -> None:
    respx.get(f"{BASE}/list_folders/{SS58}").mock(
        return_value=httpx.Response(
            200, json={"Success": {"folders": [{"label": "L", "folder_hash": FOLDER}]}}
        )
    )
    rows = json.loads(run(["folders", "--json"], env).output)
    assert rows[0]["folder_hash"] == FOLDER


@respx.mock
def test_register_reports_the_status(env: dict[str, str]) -> None:
    respx.post(f"{BASE}/register_folder").mock(
        return_value=httpx.Response(200, json={"Success": {"status": "registered"}})
    )
    assert run(["register"], env).output.strip() == "registered"


@respx.mock
def test_ls_shows_folders_before_files(env: dict[str, str]) -> None:
    respx.get(f"{BASE}/browse/{SS58}/{FOLDER}").mock(
        return_value=httpx.Response(
            200,
            json={
                "Success": {
                    "folders": [{"name": "sub", "file_count": 1, "total_bytes": 5}],
                    "files": [FILE_JSON],
                }
            },
        )
    )
    lines = run(["ls"], env).output.strip().splitlines()
    assert lines[0].startswith("dir")
    assert lines[0].endswith("sub/")
    assert lines[1].startswith("file")
    assert lines[1].endswith("a.bin")


@respx.mock
def test_ls_names_who_added_each_file(env: dict[str, str]) -> None:
    named = {**FILE_JSON, "uploaded_by": "5Fmember", "uploaded_by_name": "agent-jack"}
    unnamed = {**FILE_JSON, "relative_path": "b.bin", "uploaded_by": "5Fother"}
    legacy = {**FILE_JSON, "relative_path": "c.bin"}
    respx.get(f"{BASE}/browse/{SS58}/{FOLDER}").mock(
        return_value=httpx.Response(200, json={"Success": {"files": [named, unnamed, legacy]}})
    )
    lines = run(["ls"], env).output.strip().splitlines()
    assert lines[0].endswith("a.bin  (by agent-jack)")
    assert lines[1].endswith("b.bin  (by 5Fother)")
    assert lines[2].endswith("c.bin")
    rows = json.loads(run(["ls", "--json"], env).output)
    assert rows[0]["uploaded_by_name"] == "agent-jack"
    assert rows[0]["uploaded_by"] == "5Fmember"
    assert rows[0]["uploaded_by_email"] is None
    assert rows[2]["uploaded_by"] is None


@respx.mock
def test_ls_all_walks_get_state(env: dict[str, str]) -> None:
    route = respx.get(f"{BASE}/get_state/{SS58}/{FOLDER}").mock(
        return_value=httpx.Response(
            200, json={"Success": {"files": [FILE_JSON], "has_more": False}}
        )
    )
    assert "a.bin" in run(["ls", "--all"], env).output
    assert route.call_count == 1


def test_ls_all_rejects_a_path(env: dict[str, str]) -> None:
    result = run(["ls", "work", "--all"], env)
    assert result.exit_code != 0
    assert "--all" in result.output


def _ls_page(folders: int, files: int, has_more: bool) -> httpx.Response:
    body = {
        "folders": [{"name": "sub", "file_count": 1, "total_bytes": 5}] * folders,
        "files": [FILE_JSON] * files,
        "has_more": has_more,
    }
    return httpx.Response(200, json={"Success": body})


@respx.mock
def test_ls_walks_every_page_of_a_directory(env: dict[str, str]) -> None:
    # The server default page is 50 entries, so a bare `ls` that read one page
    # would silently hide the rest of a large directory.
    route = respx.get(f"{BASE}/browse/{SS58}/{FOLDER}")
    route.side_effect = [
        _ls_page(folders=1, files=2, has_more=True),
        _ls_page(folders=0, files=2, has_more=False),
    ]

    result = run(["ls", "work"], env)

    assert result.exit_code == 0
    lines = result.output.strip().splitlines()
    assert [line.split()[0] for line in lines] == ["dir", "file", "file", "file", "file"]
    assert "more entries" not in result.output

    sent = [dict(call.request.url.params) for call in route.calls]
    assert [params["offset"] for params in sent] == ["0", "3"]
    assert {params["limit"] for params in sent} == {"200"}
    assert {params["path"] for params in sent} == {"work"}


@respx.mock
def test_ls_json_holds_every_page_in_one_document(env: dict[str, str]) -> None:
    route = respx.get(f"{BASE}/browse/{SS58}/{FOLDER}")
    route.side_effect = [
        _ls_page(folders=1, files=0, has_more=True),
        _ls_page(folders=0, files=1, has_more=False),
    ]

    rows = json.loads(run(["ls", "--json"], env).output)

    assert [row["kind"] for row in rows] == ["dir", "file"]


@respx.mock
def test_ls_limit_fetches_one_page_and_names_the_next_offset(env: dict[str, str]) -> None:
    # Asked for 500, got 3 back: the next offset follows what came back.
    route = respx.get(f"{BASE}/browse/{SS58}/{FOLDER}").mock(
        return_value=_ls_page(folders=1, files=2, has_more=True)
    )

    result = run(["ls", "--limit", "500", "--offset", "10"], env)

    assert result.exit_code == 0
    assert route.call_count == 1
    params = dict(route.calls.last.request.url.params)
    assert params["limit"] == "500"
    assert params["offset"] == "10"
    assert "more entries not shown; pass --offset 13" in result.output


@respx.mock
def test_ls_offset_alone_is_still_a_single_page(env: dict[str, str]) -> None:
    route = respx.get(f"{BASE}/browse/{SS58}/{FOLDER}").mock(
        return_value=_ls_page(folders=0, files=1, has_more=False)
    )

    result = run(["ls", "--offset", "50"], env)

    assert route.call_count == 1
    params = dict(route.calls.last.request.url.params)
    assert params["offset"] == "50"
    assert "limit" not in params
    assert "more entries" not in result.output


@respx.mock
def test_ls_page_with_no_entries_offers_no_next_offset(env: dict[str, str]) -> None:
    respx.get(f"{BASE}/browse/{SS58}/{FOLDER}").mock(
        return_value=_ls_page(folders=0, files=0, has_more=True)
    )

    assert "--offset" not in run(["ls", "--limit", "5"], env).output


@pytest.mark.parametrize("flag", [["--limit", "5"], ["--offset", "5"]])
def test_ls_all_rejects_paging_flags(env: dict[str, str], flag: list[str]) -> None:
    result = run(["ls", "--all", *flag], env)
    assert result.exit_code != 0
    assert "--limit and --offset" in result.output


@respx.mock
def test_ls_strips_a_trailing_slash(env: dict[str, str]) -> None:
    route = respx.get(f"{BASE}/browse/{SS58}/{FOLDER}").mock(
        return_value=httpx.Response(200, json={"Success": {"folders": [], "files": []}})
    )
    assert run(["ls", "docs/"], env).exit_code == 0
    assert dict(route.calls.last.request.url.params)["path"] == "docs"


@respx.mock
def test_put_prints_the_file_id_and_revision(env: dict[str, str], tmp_path: Path) -> None:
    respx.post(f"{BASE}/upload").mock(
        return_value=httpx.Response(
            200,
            json={"Success": {"upload_id": "u", "timestamp": 1, "revision_id": [2] * 32}},
        )
    )
    local = tmp_path / "a.bin"
    local.write_bytes(b"hello")
    output = run(["put", str(local), "a.bin"], env).output
    assert hashes.path_hash("a.bin").hex() in output
    assert bytes([2] * 32).hex() in output


@respx.mock
def test_get_accepts_a_relative_path(env: dict[str, str], tmp_path: Path) -> None:
    blob = file_cipher.encrypt_bytes(b"payload", key())
    file_id = hashes.path_hash("a.bin").hex()
    respx.get(f"{BASE}/download/{SS58}/{FOLDER}/{file_id}").mock(
        return_value=httpx.Response(200, content=blob, headers={"X-Size-Bytes": "7"})
    )
    dest = tmp_path / "out.bin"
    result = run(["get", "a.bin", str(dest)], env)
    assert result.exit_code == 0
    assert dest.read_bytes() == b"payload"


@respx.mock
def test_get_accepts_a_hex_file_id(env: dict[str, str], tmp_path: Path) -> None:
    blob = file_cipher.encrypt_bytes(b"payload", key())
    file_id = hashes.path_hash("a.bin").hex()
    respx.get(f"{BASE}/download/{SS58}/{FOLDER}/{file_id}").mock(
        return_value=httpx.Response(200, content=blob)
    )
    dest = tmp_path / "out.bin"
    assert run(["get", file_id.upper(), str(dest)], env).exit_code == 0
    assert dest.read_bytes() == b"payload"


@respx.mock
def test_rm_deletes_a_single_file(env: dict[str, str]) -> None:
    file_id = hashes.path_hash("a.bin").hex()
    respx.delete(f"{BASE}/delete/{SS58}/{FOLDER}/{file_id}").mock(
        return_value=httpx.Response(200, json={"Success": {"status": "deleted"}})
    )
    assert run(["rm", "a.bin"], env).output.strip() == "deleted"


@respx.mock
def test_rm_batches_more_than_one_target(env: dict[str, str]) -> None:
    route = respx.post(f"{BASE}/delete_files").mock(
        return_value=httpx.Response(
            200, json={"Success": {"deleted": [], "errors": [], "files_deleted": 2}}
        )
    )
    assert "deleted 2" in run(["rm", "a.bin", "b.bin"], env).output
    assert json.loads(route.calls.last.request.content)["file_ids"] == [
        hashes.path_hash("a.bin").hex(),
        hashes.path_hash("b.bin").hex(),
    ]


@respx.mock
def test_mv_looks_up_the_current_revision_first(env: dict[str, str]) -> None:
    state = respx.get(f"{BASE}/get_state/{SS58}/{FOLDER}").mock(
        return_value=httpx.Response(
            200, json={"Success": {"files": [FILE_JSON], "has_more": False}}
        )
    )
    rename = respx.post(f"{BASE}/rename_files").mock(
        return_value=httpx.Response(
            200,
            json={
                "Success": {
                    "status": "ok",
                    "renamed_count": 1,
                    "successes": [
                        {
                            "old_path_hash": [1] * 32,
                            "new_path_hash": [2] * 32,
                            "new_revision_id": [3] * 32,
                            "new_revision_seq": 2,
                        }
                    ],
                    "failures": [],
                }
            },
        )
    )
    output = run(["mv", "a.bin", "b.bin"], env).output
    assert state.call_count == 1
    assert bytes([3] * 32).hex() in output
    entry = json.loads(rename.calls.last.request.content)["renames"][0]
    assert bytes(entry["base_revision_id"]) == bytes([9] * 32)


@respx.mock
def test_mv_reports_a_per_entry_failure(env: dict[str, str]) -> None:
    respx.get(f"{BASE}/get_state/{SS58}/{FOLDER}").mock(
        return_value=httpx.Response(
            200, json={"Success": {"files": [FILE_JSON], "has_more": False}}
        )
    )
    respx.post(f"{BASE}/rename_files").mock(
        return_value=httpx.Response(
            200,
            json={
                "Success": {
                    "renamed_count": 0,
                    "successes": [],
                    "failures": [{"old_path_hash": [1] * 32, "reason": "target_exists"}],
                }
            },
        )
    )
    result = run(["mv", "a.bin", "b.bin"], env)
    assert result.exit_code != 0
    assert "target_exists" in result.output


@respx.mock
def test_mv_empty_successes_is_a_failure(env: dict[str, str]) -> None:
    respx.get(f"{BASE}/get_state/{SS58}/{FOLDER}").mock(
        return_value=httpx.Response(
            200, json={"Success": {"files": [FILE_JSON], "has_more": False}}
        )
    )
    respx.post(f"{BASE}/rename_files").mock(
        return_value=httpx.Response(
            200, json={"Success": {"renamed_count": 0, "successes": [], "failures": []}}
        )
    )
    result = run(["mv", "a.bin", "b.bin"], env)
    assert result.exit_code != 0
    assert "no successes" in result.output


@respx.mock
def test_mv_on_an_unknown_path_says_so(env: dict[str, str]) -> None:
    respx.get(f"{BASE}/get_state/{SS58}/{FOLDER}").mock(
        return_value=httpx.Response(200, json={"Success": {"files": [], "has_more": False}})
    )
    result = run(["mv", "missing.bin", "b.bin"], env)
    assert result.exit_code != 0
    assert "no file at missing.bin" in result.output


@respx.mock
def test_search_passes_the_filters(env: dict[str, str]) -> None:
    route = respx.get(f"{BASE}/search_files/{SS58}").mock(
        return_value=httpx.Response(
            200,
            json={"Success": {"files": [{**FILE_JSON, "folder_label": "Docs"}], "has_more": False}},
        )
    )
    output = run(["search", "report", "--type", "image,.pdf", "--limit", "5"], env).output
    params = dict(route.calls.last.request.url.params)
    assert params["q"] == "report"
    assert params["file_type"] == "image,.pdf"
    assert params["limit"] == "5"
    assert "Docs" in output


@respx.mock
def test_search_points_at_the_next_offset_when_results_are_truncated(
    env: dict[str, str],
) -> None:
    # "pass --limit" stops being true at the server cap; the next page is the
    # only thing that always works, and it starts after the hits that came back.
    hit = {**FILE_JSON, "folder_label": "Docs"}
    route = respx.get(f"{BASE}/search_files/{SS58}").mock(
        return_value=httpx.Response(200, json={"Success": {"files": [hit, hit], "has_more": True}})
    )

    result = run(["search", "report", "--offset", "200", "--limit", "500"], env)

    assert result.exit_code == 0
    params = dict(route.calls.last.request.url.params)
    assert params["offset"] == "200"
    assert params["limit"] == "500"
    assert "more hits not shown; pass --offset 202" in result.output
    assert "--limit" not in result.output


@respx.mock
def test_search_without_offset_starts_at_zero(env: dict[str, str]) -> None:
    hit = {**FILE_JSON, "folder_label": "Docs"}
    route = respx.get(f"{BASE}/search_files/{SS58}").mock(
        return_value=httpx.Response(200, json={"Success": {"files": [hit], "has_more": True}})
    )

    result = run(["search", "report"], env)

    assert dict(route.calls.last.request.url.params)["offset"] == "0"
    assert "pass --offset 1" in result.output


@respx.mock
@pytest.mark.parametrize("term", ["a", "ab", "  ab  "])
def test_search_refuses_a_term_the_server_would_not_match(env: dict[str, str], term: str) -> None:
    # The server answers a 1-2 character term with an empty page. Printing
    # nothing would read as "no such file", so say why and send nothing.
    route = respx.get(f"{BASE}/search_files/{SS58}")

    result = run(["search", term], env)

    assert result.exit_code == 1
    assert "too short" in result.output
    assert "3 or more characters" in result.output
    assert route.call_count == 0


@respx.mock
def test_search_with_no_term_still_lists(env: dict[str, str]) -> None:
    # No term is a filter-only listing, not a short query.
    route = respx.get(f"{BASE}/search_files/{SS58}").mock(
        return_value=httpx.Response(200, json={"Success": {"files": [], "has_more": False}})
    )

    assert run(["search", "--type", "image"], env).exit_code == 0
    assert route.call_count == 1


def test_listing_help_states_the_server_cap() -> None:
    assert "200" in run(["search", "--help"]).output
    assert "200" in run(["ls", "--help"]).output


@respx.mock
def test_quota_probes_can_upload_when_asked(env: dict[str, str]) -> None:
    respx.get(f"{BASE}/get_user_summary/{SS58}").mock(
        return_value=httpx.Response(200, json={"Success": {"total_bytes": 10, "file_count": 2}})
    )
    probe = respx.post(f"{BASE}/can_upload").mock(
        return_value=httpx.Response(200, json={"result": False, "error": "drive_quota_exceeded"})
    )
    output = run(["quota", "--size", "1024"], env).output
    assert "file_count" not in output  # plain text, not a dump
    assert "drive_quota_exceeded" in output
    assert probe.call_count == 1


@respx.mock
def test_quota_without_size_does_not_probe(env: dict[str, str]) -> None:
    respx.get(f"{BASE}/get_user_summary/{SS58}").mock(
        return_value=httpx.Response(200, json={"Success": {"total_bytes": 10, "file_count": 2}})
    )
    probe = respx.post(f"{BASE}/can_upload")
    assert "total_bytes  10" in run(["quota"], env).output
    assert probe.call_count == 0


@respx.mock
def test_a_401_exits_one_with_no_traceback(env: dict[str, str]) -> None:
    respx.get(f"{BASE}/list_folders/{SS58}").mock(
        return_value=httpx.Response(
            401, json={"Error": {"error": "unauthorized", "message": "bad token"}}
        )
    )
    result = CliRunner().invoke(main, ["folders"], env=env)
    assert result.exit_code == 1
    assert "Traceback" not in result.output
    assert "unauthorized" in result.output


def test_the_cli_only_imports_the_public_surface() -> None:
    # The CLI is the reference example: if it needs a private module, the
    # public API is missing something. Parse the AST so `from hippius_drive._ops
    # import X` cannot sneak past a line-oriented grep.
    tree = ast.parse(Path("hippius_drive/cli.py").read_text(encoding="utf-8"))
    allowed_private_modules = {"hippius_drive._config"}
    allowed_private_names = {"_config", "__version__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.startswith("hippius_drive._"):
                assert node.module in allowed_private_modules, node.module
            if node.module == "hippius_drive":
                leaked = {
                    alias.name
                    for alias in node.names
                    if alias.name.startswith("_") and alias.name not in allowed_private_names
                }
                assert not leaked
        if isinstance(node, ast.Import):
            leaked_mods = [
                alias.name
                for alias in node.names
                if alias.name.startswith("hippius_drive._")
                and alias.name not in allowed_private_modules
            ]
            assert not leaked_mods


def test_init_prompts_for_a_password_when_the_env_does_not_supply_one(tmp_path: Path) -> None:
    path = tmp_path / "enc.json"
    result = CliRunner().invoke(
        main,
        ["init"],
        env={"HIPPIUS_MNEMONIC_FILE": str(path)},
        input="hunter22\nhunter22\n",
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    phrase = result.output.strip().splitlines()[-1]
    assert mnemonic_store.load(path, "hunter22") == phrase


def test_init_rejects_an_empty_password(tmp_path: Path) -> None:
    path = tmp_path / "enc.json"
    result = CliRunner().invoke(
        main,
        ["init"],
        env={"HIPPIUS_MNEMONIC_FILE": str(path)},
        input=" \n \n",
        catch_exceptions=False,
    )
    assert result.exit_code != 0
    assert "empty" in result.output.lower()
    assert not path.exists()


def test_init_reprompts_when_confirmation_does_not_match(tmp_path: Path) -> None:
    path = tmp_path / "enc.json"
    result = CliRunner().invoke(
        main,
        ["init"],
        env={"HIPPIUS_MNEMONIC_FILE": str(path)},
        input="hunter22\ntypo\nhunter22\nhunter22\n",
        catch_exceptions=False,
    )
    assert "do not match" in result.output.lower()
    assert result.exit_code == 0


def test_no_password_and_no_tty_names_the_env_var(
    env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # The shape of a CI run with the mnemonic file present but no password:
    # it must say which variable to set, not hang waiting on stdin.
    env.pop("HIPPIUS_PASSWORD")
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    result = run(["whoami"], env)
    assert result.exit_code != 0
    assert "HIPPIUS_PASSWORD" in result.output


def test_a_rejected_input_becomes_a_message_not_a_traceback(
    env: dict[str, str], tmp_path: Path
) -> None:
    # ValueError from the SDK (here: a traversing relative path) is translated
    # by DriveGroup rather than reaching the user as a stack trace.
    local = tmp_path / "a.bin"
    local.write_bytes(b"x")
    result = CliRunner().invoke(main, ["put", str(local), "../escape.bin"], env=env)
    assert result.exit_code == 1
    assert "Traceback" not in result.output
    assert "relative_path" in result.output


@respx.mock
def test_rm_reports_per_id_failures_on_stderr(env: dict[str, str]) -> None:
    respx.post(f"{BASE}/delete_files").mock(
        return_value=httpx.Response(
            200,
            json={
                "Success": {
                    "deleted": [{"file_id": "aa", "status": "deleted"}],
                    "errors": [{"file_id": "bb", "error": "database_error"}],
                    "files_deleted": 1,
                }
            },
        )
    )
    result = run(["rm", "a.bin", "b.bin"], env)
    assert result.exit_code == 1
    assert "deleted 1" in result.output
    assert "database_error" in result.output
    assert "Traceback" not in result.output


def test_run_is_the_console_script_entry_point() -> None:
    assert cli.run.__module__ == "hippius_drive.cli"
    # pyproject points the console script here; a rename would break the
    # installed `hippius-drive` command without failing any other test.
    text = Path("pyproject.toml").read_text(encoding="utf-8")
    assert 'hippius-drive = "hippius_drive.cli:run"' in text


@respx.mock
def test_mv_finds_the_right_file_among_several(env: dict[str, str]) -> None:
    other = {**FILE_JSON, "path_hash": list(hashes.path_hash("z.bin")), "relative_path": "z.bin"}
    respx.get(f"{BASE}/get_state/{SS58}/{FOLDER}").mock(
        return_value=httpx.Response(
            200, json={"Success": {"files": [other, FILE_JSON], "has_more": False}}
        )
    )
    rename = respx.post(f"{BASE}/rename_files").mock(
        return_value=httpx.Response(
            200,
            json={
                "Success": {
                    "renamed_count": 1,
                    "successes": [
                        {
                            "old_path_hash": [1] * 32,
                            "new_path_hash": [2] * 32,
                            "new_revision_id": [3] * 32,
                            "new_revision_seq": 2,
                        }
                    ],
                    "failures": [],
                }
            },
        )
    )
    assert run(["mv", "a.bin", "b.bin"], env).exit_code == 0
    entry = json.loads(rename.calls.last.request.content)["renames"][0]
    assert bytes(entry["old_path_hash"]) == hashes.path_hash("a.bin")


CONSOLE = "https://console.hippius.com"
OWNER = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"


def _report(tmp_path: Path, payload: bytes = b"hello") -> Path:
    path = tmp_path / "report.txt"
    path.write_bytes(payload)
    return path


@respx.mock
def test_share_put_prints_a_url_the_library_can_open(env: dict[str, str], tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        parts = multipart_parts(request)
        captured["meta"] = json.loads(parts[0][2])
        captured["blob"] = parts[1][2]
        return httpx.Response(201, json={"share_token": "tok", "expires_at": None})

    respx.post(f"{BASE}/v1/shares").mock(side_effect=capture)
    local = _report(tmp_path)
    result = run(["share", "put", str(local), "--name", "report.txt", "--ttl", "7d"], env)
    assert result.exit_code == 0, result.output
    url = result.output.strip()
    assert url.startswith(f"{CONSOLE}/share/tok#k=")
    assert "example.test" not in url
    assert MASTER not in result.output

    meta = captured["meta"]
    blob = captured["blob"]
    assert isinstance(meta, dict)
    assert isinstance(blob, bytes)
    assert meta["filename"] == "report.txt"
    assert meta["ttl"] == "7d"
    assert meta["plaintext_size"] == len(b"hello")
    respx.get(f"{BASE}/v1/shares/tok/meta").mock(
        return_value=httpx.Response(
            200,
            json={
                "filename_ct": meta["filename_ct"],
                "filename_nonce": meta["filename_nonce"],
                "mime_type": meta["mime_type"],
                "plaintext_size": 5,
                "ciphertext_size": len(blob),
            },
        )
    )
    respx.get(f"{BASE}/v1/shares/tok/blob").mock(return_value=httpx.Response(200, content=blob))
    identity = Identity.from_master(MASTER, "default", account_ss58=SS58)
    with Client(token="tok", identity=identity, transport=Transport(BASE, "tok")) as client:
        opened = client.shares.open(url)
    assert opened.data == b"hello"
    assert opened.filename == "report.txt"


@respx.mock
def test_share_put_password_hides_the_key(env: dict[str, str], tmp_path: Path) -> None:
    respx.post(f"{BASE}/v1/shares").mock(
        return_value=httpx.Response(201, json={"share_token": "pw", "expires_at": None})
    )
    result = run(
        ["share", "put", str(_report(tmp_path, b"x")), "--name", "a.txt", "--password", "hunter22"],
        env,
    )
    assert result.exit_code == 0, result.output
    url = result.output.strip()
    assert url.startswith(f"{CONSOLE}/share/pw#p=")
    assert "#k=" not in url
    assert sharing.parse_share_url(url).secret.private


def test_share_put_rejects_a_short_password(env: dict[str, str], tmp_path: Path) -> None:
    result = run(
        ["share", "put", str(_report(tmp_path, b"x")), "--name", "a.txt", "--password", "short"],
        env,
    )
    assert result.exit_code != 0
    assert "8" in result.output


def test_share_put_rejects_a_name_with_a_slash(env: dict[str, str], tmp_path: Path) -> None:
    result = run(["share", "put", str(_report(tmp_path, b"x")), "--name", "a/b.txt"], env)
    assert result.exit_code != 0
    assert "filename" in result.output


@respx.mock
def test_share_ls_omits_the_owner_wrap_and_rm_revokes(env: dict[str, str]) -> None:
    respx.get(f"{BASE}/v1/shares").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "share_token": "abc",
                    "filename": "a.txt",
                    "plaintext_size": 4,
                    "expires_at": None,
                    "owner_wrap": "sealed-secret",
                }
            ],
        )
    )
    listed = run(["share", "ls"], env)
    assert listed.exit_code == 0
    assert "abc" in listed.output
    assert "a.txt" in listed.output
    assert "sealed-secret" not in listed.output
    rows = json.loads(run(["share", "ls", "--json"], env).output)
    assert rows[0]["share_token"] == "abc"
    assert "owner_wrap" not in rows[0]

    route = respx.delete(f"{BASE}/v1/shares/abc").mock(return_value=httpx.Response(204))
    removed = run(["share", "rm", "abc"], env)
    assert removed.exit_code == 0
    assert removed.output.strip() == "revoked"
    assert route.called


@respx.mock
def test_folder_share_put_prints_a_link_secret_url(env: dict[str, str]) -> None:
    respx.post(f"{BASE}/v1/folder-shares").mock(
        return_value=httpx.Response(
            201, json={"share_token": "fold", "expires_at": "later", "link_envelope": True}
        )
    )
    result = run(
        [
            "folder-share",
            "put",
            "--prefix",
            "work",
            "--name",
            "Work",
            "--console",
            "https://console.example",
        ],
        env,
    )
    assert result.exit_code == 0, result.output
    url = result.output.strip()
    assert url.startswith("https://console.example/share/folder/fold#s=")
    parsed = sharing.parse_share_url(url)
    assert parsed.folder
    assert parsed.secret.link_secret
    assert parsed.secret.material != key()
    body = json.loads(respx.calls.last.request.content)
    envelope = base64.b64decode(body["link_envelope"])
    assert folder_link.open_envelope(parsed.secret.material, envelope) == key()
    assert base64.b64decode(body["link_fetch_digest"]) == folder_link.fetch_digest(
        parsed.secret.material
    )
    assert body["path_prefix"] == "work"
    assert body["display_name"] == "Work"
    assert body["ttl"] == "24h"
    assert "owner_ss58" not in body


@respx.mock
def test_folder_share_ls_prints_the_hash_and_rm_revokes(env: dict[str, str]) -> None:
    digest = "ab" * 32
    respx.get(f"{BASE}/v1/folder-shares").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "token_hash": digest,
                    "path_prefix": "",
                    "display_name": "Whole",
                    "expires_at": None,
                }
            ],
        )
    )
    listed = run(["folder-share", "ls"], env)
    assert digest in listed.output
    assert "Whole" in listed.output
    route = respx.delete(f"{BASE}/v1/folder-shares/fold").mock(return_value=httpx.Response(204))
    removed = run(["folder-share", "rm", "fold"], env)
    assert removed.exit_code == 0
    assert route.called


@respx.mock
def test_invite_put_prints_a_link_secret_url_and_not_the_phrase(env: dict[str, str]) -> None:
    token = "inviteTok"
    invite_id = blake3.blake3(token.encode()).hexdigest()
    respx.get(f"{BASE}/v1/capabilities").mock(
        return_value=httpx.Response(200, json={"drive_invite_link_envelopes": True})
    )
    mint = respx.post(f"{BASE}/v1/drive-invites").mock(
        return_value=httpx.Response(200, json={"invite_token": token, "invite_id": invite_id})
    )
    seal = respx.put(url__regex=r".*/sealed-token$").mock(return_value=httpx.Response(204))
    stored = respx.put(f"{BASE}/v1/drives/{FOLDER}/invites/{invite_id}/link-envelope").mock(
        return_value=httpx.Response(200, json={"stored": True})
    )
    result = run(["invite", "put", "--role", "reader", "--days", "2"], env)
    assert result.exit_code == 0, result.output
    phrase = kdf.derive_folder_mnemonic(MASTER, "default")
    assert phrase not in result.output
    assert MASTER not in result.output
    link = invite_link.parse_invite_link(result.output.strip())
    assert link.token == token
    entropy = kdf.folder_entropy(MASTER, "default")
    raw_id = invite_link.invite_id_for_token(token)
    assert link.material == invite_link.derive_link_secret(entropy, raw_id)
    body = json.loads(mint.calls.last.request.content)
    assert body == {
        "folder_hash": FOLDER,
        "role": "reader",
        "expires_in_secs": 2 * 86400,
        "link_secret": True,
    }
    assert seal.called
    assert stored.called


@respx.mock
def test_invite_put_unlocks_once_and_omits_the_lifetime(
    env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    token = "inviteTok"
    invite_id = blake3.blake3(token.encode()).hexdigest()
    respx.post(f"{BASE}/v1/drive-invites").mock(
        return_value=httpx.Response(200, json={"invite_token": token, "invite_id": invite_id})
    )
    respx.put(url__regex=r".*/sealed-token$").mock(return_value=httpx.Response(204))
    respx.get(f"{BASE}/v1/capabilities").mock(return_value=httpx.Response(200, json={}))
    loads: list[int] = []
    real = mnemonic_store.load

    def counting(path: Path, password: str) -> str:
        loads.append(1)
        return real(path, password)

    monkeypatch.setattr("hippius_drive.cli.mnemonic_store.load", counting)
    assert run(["invite", "put"], env).exit_code == 0
    assert loads == [1]
    mint = next(call for call in respx.calls if call.request.method == "POST")
    assert json.loads(mint.request.content) == {"folder_hash": FOLDER, "role": "writer"}


@respx.mock
def test_drives_lists_memberships_without_the_phrase(env: dict[str, str]) -> None:
    respx.get(f"{BASE}/v1/drive-memberships").mock(
        return_value=httpx.Response(
            200,
            json={
                "memberships": [
                    {
                        "owner_ss58": OWNER,
                        "folder_hash": FOLDER,
                        "role": "writer",
                        "grant_blob": "",
                        "display_label": "Docs",
                        "frozen": True,
                    }
                ],
                "folder_grants": [
                    {
                        "owner_ss58": OWNER,
                        "folder_hash": "0123456789abcdef",
                        "path_prefix": "Clients/ACME",
                        "grant_blob": "",
                        "display_label": "Team",
                    }
                ],
            },
        )
    )
    output = run(["drives"], env).output
    assert "Team / Clients/ACME" in output
    assert "Docs" in output
    assert "frozen" in output
    assert "writer" in output
    assert MASTER not in output
    rows = json.loads(run(["drives", "--json"], env).output)
    assert rows[0]["display_label"] == "Docs"
    assert rows[0]["frozen"] is True
    assert rows[0]["path_prefix"] is None
    assert rows[1]["path_prefix"] == "Clients/ACME"
    assert "folder_mnemonic" not in rows[0]


@respx.mock
def test_drives_leave_works_on_a_folder_grant(
    env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    built: list[str] = []
    real = Identity.for_folder_grant

    def spy(*args: Any, **kwargs: Any) -> Identity:
        built.append(kwargs["folder_hash"])
        return real(*args, **kwargs)

    monkeypatch.setattr(Identity, "for_folder_grant", spy)
    file_key_phrase = grant.phrase_from_entropy(bytes([0x44]) * 32)
    monkeypatch.setattr(_links, "_open_one_grant", lambda *_args: file_key_phrase)
    respx.get(f"{BASE}/v1/drive-memberships").mock(
        return_value=httpx.Response(
            200,
            json={
                "folder_grants": [
                    {
                        "owner_ss58": OWNER,
                        "folder_hash": FOLDER,
                        "path_prefix": "Work",
                        "grant_blob": "sealed",
                    }
                ]
            },
        )
    )
    route = respx.delete(f"{BASE}/v1/drives/{FOLDER}/members/{SS58}").mock(
        return_value=httpx.Response(204)
    )
    result = run(["drives", "leave", OWNER, FOLDER], env)
    assert result.exit_code == 0, result.output
    assert built == [FOLDER]
    assert route.calls.last.request.url.params["owner"] == OWNER


@respx.mock
def test_drives_leave_reports_a_missing_membership(env: dict[str, str]) -> None:
    respx.get(f"{BASE}/v1/drive-memberships").mock(
        return_value=httpx.Response(200, json={"memberships": []})
    )
    result = run(["drives", "leave", OWNER, FOLDER], env)
    assert result.exit_code != 0
    assert "no membership" in result.output


@respx.mock
def test_drives_leave_reports_a_missing_grant(env: dict[str, str]) -> None:
    respx.get(f"{BASE}/v1/drive-memberships").mock(
        return_value=httpx.Response(
            200,
            json={
                "memberships": [
                    {
                        "owner_ss58": SS58,
                        "folder_hash": "ab" * 8,
                        "role": "reader",
                        "grant_blob": "",
                        "display_label": "Other",
                    },
                    {
                        "owner_ss58": OWNER,
                        "folder_hash": FOLDER,
                        "role": "reader",
                        "grant_blob": "",
                        "display_label": "Docs",
                    },
                ]
            },
        )
    )
    result = run(["drives", "leave", OWNER, FOLDER], env)
    assert result.exit_code != 0
    assert "no grant" in result.output


@pytest.fixture(scope="module")
def sealed_grant() -> str:
    # Production Argon2id (128 MiB). One seal, reused by the leave command test.
    phrase = kdf.derive_folder_mnemonic(MASTER, "default")
    return base64.b64encode(grant.seal_grant(MASTER, SS58, phrase)).decode()


@respx.mock
def test_invite_accept_prints_the_drive_and_not_the_phrase(env: dict[str, str]) -> None:
    # Seals a grant under the production Argon2id parameters.
    phrase = kdf.derive_folder_mnemonic(MASTER, "default")
    entropy = kdf.folder_entropy(MASTER, "default")
    url = grant.invite_url(CONSOLE, "joinme", entropy)
    respx.get(f"{BASE}/v1/drive-invites/joinme/meta").mock(
        return_value=httpx.Response(200, json={"owner_ss58": OWNER, "folder_hash": FOLDER})
    )
    respx.post(f"{BASE}/v1/drive-invites/joinme/accept").mock(
        return_value=httpx.Response(
            200,
            json={
                "owner_ss58": OWNER,
                "folder_hash": FOLDER,
                "role": "writer",
                "already_owner": False,
            },
        )
    )
    result = run(["invite", "accept", url], env)
    assert result.exit_code == 0, result.output
    assert f"owner        {OWNER}" in result.output
    assert f"folder_hash  {FOLDER}" in result.output
    assert "role         writer" in result.output
    assert "folder" not in result.output.replace("folder_hash", "")
    assert phrase not in result.output
    assert MASTER not in result.output


@respx.mock
def test_invite_accept_names_the_folder_of_a_folder_invite(
    env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_links, "accept_grant", lambda *_args: "e30=")
    url = grant.invite_url(CONSOLE, "joinme", bytes([0x44]) * 32)
    respx.get(f"{BASE}/v1/drive-invites/joinme/meta").mock(
        return_value=httpx.Response(
            200, json={"owner_ss58": OWNER, "folder_hash": FOLDER, "path_prefix": "Work"}
        )
    )
    accepted = {"owner_ss58": OWNER, "folder_hash": FOLDER, "role": "reader", "path_prefix": "Work"}
    respx.post(f"{BASE}/v1/drive-invites/joinme/accept").mock(
        return_value=httpx.Response(200, json=accepted)
    )
    result = run(["invite", "accept", url], env)
    assert result.exit_code == 0, result.output
    assert "folder       Work" in result.output


@respx.mock
def test_drives_leave_uses_the_opened_grant(env: dict[str, str], sealed_grant: str) -> None:
    respx.get(f"{BASE}/v1/drive-memberships").mock(
        return_value=httpx.Response(
            200,
            json={
                "memberships": [
                    {
                        "owner_ss58": OWNER,
                        "folder_hash": FOLDER,
                        "role": "writer",
                        "grant_blob": sealed_grant,
                        "display_label": "Docs",
                    }
                ]
            },
        )
    )
    route = respx.delete(f"{BASE}/v1/drives/{FOLDER}/members/{SS58}").mock(
        return_value=httpx.Response(204)
    )
    result = run(["drives", "leave", OWNER, FOLDER], env)
    assert result.exit_code == 0, result.output
    assert result.output.strip() == "left"
    assert route.calls.last.request.url.params["owner"] == OWNER
    phrase = kdf.derive_folder_mnemonic(MASTER, "default")
    assert phrase not in result.output


UPLOADED = {"Success": {"upload_id": "u", "timestamp": 1, "revision_id": [2] * 32}}


def _browse_with(files: list[dict[str, Any]], path: str = "") -> respx.Route:
    return respx.get(f"{BASE}/browse/{SS58}/{FOLDER}").mock(
        return_value=httpx.Response(200, json={"Success": {"folders": [], "files": files}})
    )


def _local(tmp_path: Path) -> Path:
    local = tmp_path / "a.bin"
    local.write_bytes(b"hello")
    return local


@respx.mock
def test_put_overwrite_quotes_the_revision_it_read(env: dict[str, str], tmp_path: Path) -> None:
    browse = _browse_with([{**FILE_JSON, "revision_seq": 4, "revision_id": [8] * 32}])
    upload = respx.post(f"{BASE}/upload").mock(return_value=httpx.Response(200, json=UPLOADED))
    result = run(["put", str(_local(tmp_path)), "a.bin", "--overwrite"], env)
    assert result.exit_code == 0, result.output
    assert "replaced     yes" in result.output
    manifest = manifest_from(upload.calls.last.request)
    assert manifest["base_revision_id"] == [8] * 32
    assert manifest["revision_seq"] == 5
    assert browse.calls.last.request.url.params.get("path", "") == ""


@respx.mock
def test_put_overwrite_of_a_missing_file_is_a_new_file(env: dict[str, str], tmp_path: Path) -> None:
    _browse_with([])
    upload = respx.post(f"{BASE}/upload").mock(return_value=httpx.Response(200, json=UPLOADED))
    result = run(["put", str(_local(tmp_path)), "a.bin", "--overwrite"], env)
    assert result.exit_code == 0, result.output
    assert "replaced     no, new file" in result.output
    assert manifest_from(upload.calls.last.request).get("base_revision_id") is None


def _conflict(revision: list[int] | None = None, seq: int | None = 4) -> httpx.Response:
    body: dict[str, Any] = {"error": "conflict", "message": "Sync required."}
    if revision is not None:
        body["current_revision_id"] = revision
        body["current_revision_seq"] = seq
    return httpx.Response(409, json={"Conflict": body})


@respx.mock
def test_put_onto_an_existing_file_exits_3_and_names_overwrite(
    env: dict[str, str], tmp_path: Path
) -> None:
    respx.post(f"{BASE}/upload").mock(return_value=_conflict([5] * 32))
    result = run(["put", str(_local(tmp_path)), "a.bin"], env)
    assert result.exit_code == 3
    assert "already exists; pass --overwrite" in result.output


@respx.mock
def test_put_overwrite_that_loses_a_race_exits_3(env: dict[str, str], tmp_path: Path) -> None:
    _browse_with([FILE_JSON])
    respx.post(f"{BASE}/upload").mock(return_value=_conflict([5] * 32))
    result = run(["put", str(_local(tmp_path)), "a.bin", "--overwrite"], env)
    assert result.exit_code == 3
    assert "changed since it was read" in result.output


@respx.mock
def test_put_overwrite_of_a_file_deleted_since_the_read_says_so(
    env: dict[str, str], tmp_path: Path
) -> None:
    _browse_with([FILE_JSON])
    respx.post(f"{BASE}/upload").mock(return_value=_conflict([0] * 32, seq=None))
    result = run(["put", str(_local(tmp_path)), "a.bin", "--overwrite"], env)
    assert result.exit_code == 3
    assert "moved or deleted" in result.output


@respx.mock
def test_put_overwrite_of_an_unlisted_row_quotes_the_revision_the_409_names(
    env: dict[str, str], tmp_path: Path
) -> None:
    _browse_with([])
    upload = respx.post(f"{BASE}/upload").mock(
        side_effect=[_conflict([6] * 32, seq=7), httpx.Response(200, json=UPLOADED)]
    )
    result = run(["put", str(_local(tmp_path)), "a.bin", "--overwrite"], env)
    assert result.exit_code == 0, result.output
    assert "replaced     yes" in result.output
    second = manifest_from(upload.calls[1].request)
    assert (second["base_revision_id"], second["revision_seq"]) == ([6] * 32, 8)


@respx.mock
def test_put_overwrite_gives_up_after_the_second_conflict(
    env: dict[str, str], tmp_path: Path
) -> None:
    _browse_with([])
    respx.post(f"{BASE}/upload").mock(
        side_effect=[_conflict([6] * 32, seq=7), _conflict([7] * 32, seq=8)]
    )
    result = run(["put", str(_local(tmp_path)), "a.bin", "--overwrite"], env)
    assert result.exit_code == 3
    assert "changed since it was read" in result.output


@respx.mock
def test_put_overwrite_refuses_a_desktop_nfd_row(env: dict[str, str], tmp_path: Path) -> None:
    nfd = "cafe\u0301.txt"
    row = {**FILE_JSON, "path_hash": [3] * 32, "relative_path": nfd}
    _browse_with([row])
    upload = respx.post(f"{BASE}/upload")
    result = run(["put", str(_local(tmp_path)), "caf\u00e9.txt", "--overwrite"], env)
    assert result.exit_code == 1
    assert "another id" in result.output
    assert upload.calls == []


def test_put_overwrite_refuses_an_explicit_base(env: dict[str, str], tmp_path: Path) -> None:
    args = ["put", str(_local(tmp_path)), "a.bin", "--overwrite", "--base-revision", "ab" * 32]
    result = run(args, env)
    assert result.exit_code != 0
    assert "drop --base-revision" in result.output


@respx.mock
def test_mkdir_registers_the_named_directories(env: dict[str, str]) -> None:
    route = respx.post(f"{BASE}/register_folder_entries").mock(
        return_value=httpx.Response(200, json={"Success": {"status": "registered"}})
    )
    result = run(["mkdir", "docs", "docs/2026", "docs"], env)
    assert result.exit_code == 0, result.output
    assert result.output.strip() == "registered"
    assert json.loads(route.calls.last.request.content) == {
        "ss58_address": SS58,
        "folder_hash": FOLDER,
        "relative_paths": ["docs", "docs/2026"],
    }


def test_mkdir_refuses_a_bad_path(env: dict[str, str]) -> None:
    result = run(["mkdir", "../escape"], env)
    assert result.exit_code == 1


@respx.mock
def test_a_409_about_an_upload_session_is_reported_as_is(
    env: dict[str, str], tmp_path: Path
) -> None:
    body = {"Error": {"error": "session_exists", "message": "an upload is already running"}}
    respx.post(f"{BASE}/upload").mock(return_value=httpx.Response(409, json=body))
    result = run(["put", str(_local(tmp_path)), "a.bin"], env)
    assert result.exit_code == 3
    assert "session_exists" in result.output
    assert "moved or deleted" not in result.output


@respx.mock
def test_a_revisionless_conflict_is_not_called_gone(env: dict[str, str], tmp_path: Path) -> None:
    _browse_with([FILE_JSON])
    respx.post(f"{BASE}/upload").mock(return_value=_conflict())
    result = run(["put", str(_local(tmp_path)), "a.bin", "--overwrite"], env)
    assert result.exit_code == 3
    assert "moved or deleted" not in result.output
    assert "refused the upload" in result.output


@respx.mock
def test_target_gone_is_called_gone(env: dict[str, str], tmp_path: Path) -> None:
    body = {"Error": {"error": "target_gone", "message": "moved or deleted"}}
    respx.post(f"{BASE}/upload").mock(return_value=httpx.Response(409, json=body))
    result = run(
        [
            "put",
            str(_local(tmp_path)),
            "a.bin",
            "--base-revision",
            "ab" * 32,
            "--revision-seq",
            "2",
        ],
        env,
    )
    assert result.exit_code == 3
    assert "was moved or deleted since it was read" in result.output


ACCESS_KEY = " ".join(["abandon"] * 11 + ["about"])
ACCESS_SS58 = "5EPCUjPxiHAcNooYipQFWr9NmmXJKpNG5RhcntXwbtUySrgH"
API = "https://api.example.test"


@pytest.fixture
def config_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "home" / "config.toml"
    monkeypatch.setattr("hippius_drive._config.CONFIG_PATH", path)
    return path


def _phrase_file(tmp_path: Path, mode: int = 0o600) -> Path:
    path = tmp_path / "access-key.txt"
    path.write_text(ACCESS_KEY + "\n")
    path.chmod(mode)
    return path


def _mock_api() -> respx.Route:
    message = "Please sign this message to verify your ownership: " + "cd" * 32
    respx.post(f"{API}/api/auth/mnemonic/").mock(
        return_value=httpx.Response(200, json={"challenge": "cd" * 32, "message": message})
    )
    return respx.post(f"{API}/api/auth/verify/").mock(
        return_value=httpx.Response(
            200,
            json={"token": "tok-secret", "username": "agent", "substrate_address": ACCESS_SS58},
        )
    )


@respx.mock
def test_auth_login_saves_the_token_and_account_and_prints_neither_secret(
    tmp_path: Path, config_path: Path
) -> None:
    verify = _mock_api()
    phrase = _phrase_file(tmp_path)
    result = run(["auth", "login", "--phrase-file", str(phrase), "--api", API], {})
    assert result.exit_code == 0, result.output
    assert verify.called
    assert f"account   {ACCESS_SS58}" in result.output
    assert f"token     saved to {config_path}" in result.output
    assert "tok-secret" not in result.output
    assert ACCESS_KEY not in result.output
    cfg = _config.load({}, environ={}, config_path=config_path)
    assert (cfg.token, cfg.account_ss58) == ("tok-secret", ACCESS_SS58)


@respx.mock
def test_auth_login_reads_the_phrase_from_stdin(config_path: Path) -> None:
    _mock_api()
    result = CliRunner().invoke(
        main,
        ["auth", "login", "--phrase-file", "-"],
        input=ACCESS_KEY + "\n",
        env={"HIPPIUS_API_URL": API},
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert ACCESS_KEY not in result.output


@respx.mock
def test_auth_login_can_write_the_token_to_its_own_file(tmp_path: Path, config_path: Path) -> None:
    _mock_api()
    token_file = tmp_path / "token"
    args = ["auth", "login", "--phrase-file", str(_phrase_file(tmp_path)), "--api", API]
    result = run([*args, "--token-file", str(token_file)], {})
    assert result.exit_code == 0, result.output
    assert token_file.read_text().strip() == "tok-secret"
    if os.name == "posix":
        assert token_file.stat().st_mode & 0o777 == 0o600
    cfg = _config.load({}, environ={}, config_path=config_path)
    assert (cfg.token, cfg.account_ss58) == (None, ACCESS_SS58)
    assert f"account   saved to {config_path}" in result.output


@respx.mock
def test_auth_login_defaults_to_the_encrypted_mnemonic(
    mnemonic_file: Path, config_path: Path
) -> None:
    # MASTER is a valid phrase too; the API mock only checks the flow.
    message = "Please sign this message to verify your ownership: " + "cd" * 32
    respx.post(f"{API}/api/auth/mnemonic/").mock(
        return_value=httpx.Response(200, json={"challenge": "cd" * 32, "message": message})
    )
    respx.post(f"{API}/api/auth/verify/").mock(
        return_value=httpx.Response(200, json={"token": "t2"})
    )
    env = {"HIPPIUS_MNEMONIC_FILE": str(mnemonic_file), "HIPPIUS_PASSWORD": PASSWORD}
    result = run(["auth", "login", "--api", API], env)
    assert result.exit_code == 0, result.output
    assert MASTER not in result.output


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_auth_login_refuses_a_phrase_file_others_can_read(
    tmp_path: Path, config_path: Path
) -> None:
    phrase = _phrase_file(tmp_path, mode=0o644)
    result = run(["auth", "login", "--phrase-file", str(phrase), "--api", API], {})
    assert result.exit_code != 0
    assert "chmod 600" in result.output
    assert not config_path.exists()


def test_auth_login_reports_an_unreadable_phrase_file(tmp_path: Path, config_path: Path) -> None:
    result = run(["auth", "login", "--phrase-file", str(tmp_path / "missing"), "--api", API], {})
    assert result.exit_code != 0
    assert "cannot read" in result.output


@respx.mock
def test_auth_login_turns_a_refusal_into_one_line(tmp_path: Path, config_path: Path) -> None:
    respx.post(f"{API}/api/auth/mnemonic/").mock(
        return_value=httpx.Response(401, json={"error": "Invalid signature", "code": "x"})
    )
    result = run(["auth", "login", "--phrase-file", str(_phrase_file(tmp_path)), "--api", API], {})
    assert result.exit_code == 1
    assert "401" in result.output
    assert "Traceback" not in result.output


def test_auth_login_names_the_extra_when_it_is_missing(
    tmp_path: Path, config_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def missing(*_args: Any, **_kwargs: Any) -> None:
        raise ImportError("access-key login needs the login extra")

    monkeypatch.setattr(cli.api_auth, "login", missing)
    result = run(["auth", "login", "--phrase-file", str(_phrase_file(tmp_path)), "--api", API], {})
    assert result.exit_code != 0
    assert "login extra" in result.output


def test_init_imports_from_a_phrase_file_and_never_echoes_it(tmp_path: Path) -> None:
    path = tmp_path / "enc.json"
    env = {"HIPPIUS_MNEMONIC_FILE": str(path), "HIPPIUS_PASSWORD": PASSWORD}
    result = run(["init", "--phrase-file", str(_phrase_file(tmp_path))], env)
    assert result.exit_code == 0, result.output
    assert ACCESS_KEY not in result.output
    assert mnemonic_store.load(path, PASSWORD) == ACCESS_KEY


def test_init_takes_one_phrase_source(tmp_path: Path) -> None:
    env = {"HIPPIUS_MNEMONIC_FILE": str(tmp_path / "e.json"), "HIPPIUS_PASSWORD": PASSWORD}
    args = ["init", "--mnemonic", MASTER, "--phrase-file", str(_phrase_file(tmp_path))]
    result = run(args, env)
    assert result.exit_code != 0
    assert "not both" in result.output


def test_a_secret_from_a_terminal_is_prompted_without_echo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    prompts: list[bool] = []

    def fake_prompt(_text: str, *, hide_input: bool) -> str:
        prompts.append(hide_input)
        return f" {ACCESS_KEY} "

    monkeypatch.setattr(cli.click, "prompt", fake_prompt)
    assert cli._read_secret(Path("-")) == ACCESS_KEY
    assert prompts == [True]


def test_a_secret_must_come_from_a_regular_file(tmp_path: Path) -> None:
    # POSIX opens a directory and fstat refuses it; Windows refuses the open.
    with pytest.raises(click.ClickException, match=r"not a regular file|cannot read"):
        cli._read_secret(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="O_NOFOLLOW")
def test_a_symlinked_secret_file_is_not_followed(tmp_path: Path) -> None:
    real = _phrase_file(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(click.ClickException, match="cannot read"):
        cli._read_secret(link)


@pytest.mark.skipif(os.name != "posix", reason="symlinks")
def test_a_token_file_symlink_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.write_text("keep")
    link = tmp_path / "token"
    link.symlink_to(target)
    with pytest.raises(click.ClickException, match="symlink"):
        cli._write_secret(link, "tok")
    assert target.read_text() == "keep"


def test_a_token_file_in_a_missing_directory_is_one_line(tmp_path: Path) -> None:
    with pytest.raises(click.ClickException, match="cannot write"):
        cli._write_secret(tmp_path / "missing" / "token", "tok")


def test_a_failed_token_replace_leaves_no_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_args: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(cli.os, "replace", refuse)
    with pytest.raises(click.ClickException, match="cannot write"):
        cli._write_secret(tmp_path / "token", "tok")
    assert list(tmp_path.iterdir()) == []


@respx.mock
def test_a_token_file_login_drops_a_stale_config_token(tmp_path: Path, config_path: Path) -> None:
    _mock_api()
    _config.save({"token": "old-account-token", "account_ss58": "5Old"}, config_path=config_path)
    args = ["auth", "login", "--phrase-file", str(_phrase_file(tmp_path)), "--api", API]
    result = run([*args, "--token-file", str(tmp_path / "token")], {})
    assert result.exit_code == 0, result.output
    cfg = _config.load({}, environ={}, config_path=config_path)
    assert (cfg.token, cfg.account_ss58) == (None, ACCESS_SS58)


def test_a_secret_typed_as_the_file_name_is_not_echoed(config_path: Path) -> None:
    result = run(["auth", "login", "--phrase-file", ACCESS_KEY, "--api", API], {})
    assert result.exit_code != 0
    assert "cannot read the given path" in result.output
    assert "abandon" not in result.output


def _mock_join(monkeypatch: pytest.MonkeyPatch, path_prefix: str | None = None) -> str:
    monkeypatch.setattr(_links, "accept_grant", lambda *_args: "e30=")
    url = grant.invite_url(CONSOLE, "joinme", kdf.folder_entropy(MASTER, "default"))
    meta: dict[str, Any] = {"owner_ss58": OWNER, "folder_hash": FOLDER}
    accepted: dict[str, Any] = {"owner_ss58": OWNER, "folder_hash": FOLDER, "role": "writer"}
    if path_prefix:
        meta["path_prefix"] = accepted["path_prefix"] = path_prefix
    respx.get(f"{BASE}/v1/drive-invites/joinme/meta").mock(
        return_value=httpx.Response(200, json=meta)
    )
    respx.post(f"{BASE}/v1/drive-invites/joinme/accept").mock(
        return_value=httpx.Response(200, json=accepted)
    )
    return url


def _invite_file(tmp_path: Path, url: str, mode: int = 0o600) -> Path:
    path = tmp_path / "invite.txt"
    path.write_text(url + "\n")
    path.chmod(mode)
    return path


@respx.mock
def test_drives_join_reads_the_invite_from_a_file(
    env: dict[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = _mock_join(monkeypatch)
    result = run(["drives", "join", "--invite-file", str(_invite_file(tmp_path, url))], env)
    assert result.exit_code == 0, result.output
    assert f"owner        {OWNER}" in result.output
    assert "role         writer" in result.output
    assert url.split("#")[1][2:] not in result.output


@respx.mock
def test_drives_join_reads_stdin_and_emits_json(
    env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    url = _mock_join(monkeypatch, path_prefix="Work")
    result = CliRunner().invoke(
        main, ["drives", "join", "--invite-file", "-", "--json"], input=url, env=env
    )
    assert result.exit_code == 0, result.output
    row = json.loads(result.output)
    assert row == {
        "owner_ss58": OWNER,
        "folder_hash": FOLDER,
        "role": "writer",
        "path_prefix": "Work",
        "already_owner": False,
    }


@respx.mock
def test_drives_join_reads_the_environment(
    env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    url = _mock_join(monkeypatch)
    result = run(["drives", "join"], {**env, "HIPPIUS_INVITE_URL": url})
    assert result.exit_code == 0, result.output


def test_drives_join_needs_exactly_one_invite_source(env: dict[str, str], tmp_path: Path) -> None:
    missing = run(["drives", "join"], env)
    assert missing.exit_code != 0
    assert "--invite-file" in missing.output
    path = _invite_file(tmp_path, "https://x.io/invite/t#k=" + "A" * 43)
    both = run(["drives", "join", "--invite-file", str(path)], {**env, "HIPPIUS_INVITE_URL": "x"})
    assert both.exit_code != 0
    assert "once" in both.output


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_drives_join_refuses_an_invite_file_others_can_read(
    env: dict[str, str], tmp_path: Path
) -> None:
    path = _invite_file(tmp_path, "https://x.io/invite/t#k=" + "A" * 43, mode=0o644)
    result = run(["drives", "join", "--invite-file", str(path)], env)
    assert result.exit_code != 0
    assert "chmod 600" in result.output


@respx.mock
def test_invite_accept_takes_an_invite_file_too(
    env: dict[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = _mock_join(monkeypatch)
    path = _invite_file(tmp_path, url)
    result = run(["invite", "accept", "--invite-file", str(path)], env)
    assert result.exit_code == 0, result.output
    assert "folder_hash" in result.output


def test_drives_join_refuses_a_url_argument_without_echoing_it(env: dict[str, str]) -> None:
    secret = "B" * 43
    result = run(["drives", "join", f"https://x.io/invite/t#i={secret}"], env)
    assert result.exit_code != 0
    assert "no URL argument" in result.output
    assert secret not in result.output


@respx.mock
def test_a_blank_invite_environment_is_not_a_source(
    env: dict[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = _mock_join(monkeypatch)
    path = _invite_file(tmp_path, url)
    result = run(
        ["drives", "join", "--invite-file", str(path)], {**env, "HIPPIUS_INVITE_URL": "  "}
    )
    assert result.exit_code == 0, result.output
    blank = run(["drives", "join"], {**env, "HIPPIUS_INVITE_URL": " \n"})
    assert blank.exit_code != 0
    assert "once" in blank.output


@respx.mock
def test_a_dead_link_secret_invite_errors_without_its_secret(
    env: dict[str, str], tmp_path: Path
) -> None:
    secret = invite_link.derive_link_secret(bytes(32), invite_link.invite_id_for_token("deadtok"))
    fragment = base64.urlsafe_b64encode(secret).rstrip(b"=").decode()
    respx.get(f"{BASE}/v1/drive-invites/deadtok/meta").mock(return_value=httpx.Response(404))
    path = _invite_file(tmp_path, f"{CONSOLE}/invite/deadtok#i={fragment}")
    result = run(["drives", "join", "--invite-file", str(path)], env)
    assert result.exit_code == 1
    assert fragment not in result.output
    assert "Traceback" not in result.output


def test_an_invite_url_given_as_the_file_is_not_echoed(env: dict[str, str]) -> None:
    secret = "C" * 43
    result = run(["drives", "join", "--invite-file", f"https://x.io/invite/t#i={secret}"], env)
    assert result.exit_code != 0
    assert secret not in result.output
