import ast
import json
from pathlib import Path

import httpx
import pytest
import respx
from click.testing import CliRunner, Result

from hippius_drive import __version__, cli
from hippius_drive.cli import main
from hippius_drive.crypto import file_cipher, hashes, kdf, mnemonic_store
from hippius_drive.identity import Identity

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


@respx.mock
def test_ls_notes_when_a_page_is_truncated(env: dict[str, str]) -> None:
    respx.get(f"{BASE}/browse/{SS58}/{FOLDER}").mock(
        return_value=httpx.Response(
            200,
            json={"Success": {"folders": [], "files": [FILE_JSON], "has_more": True}},
        )
    )
    result = run(["ls"], env)
    assert result.exit_code == 0
    assert "more entries not shown" in result.output


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
def test_search_notes_when_results_are_truncated(env: dict[str, str]) -> None:
    respx.get(f"{BASE}/search_files/{SS58}").mock(
        return_value=httpx.Response(
            200,
            json={"Success": {"files": [{**FILE_JSON, "folder_label": "Docs"}], "has_more": True}},
        )
    )
    result = run(["search", "report"], env)
    assert result.exit_code == 0
    assert "more hits not shown" in result.output
    assert "offset" not in result.output


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
