import json

import httpx
import pytest
import respx
from nacl.signing import VerifyKey

from hippius_drive import errors
from hippius_drive._transport import Transport
from hippius_drive.client import Client
from hippius_drive.crypto import file_cipher, hashes
from hippius_drive.identity import Identity, rename_text
from hippius_drive.models import RenameSpec

BASE = "https://example.test"
MASTER = " ".join(["abandon"] * 23 + ["art"])
SS58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
FOLDER = "37a8eec1ce19687d"


@pytest.fixture
def identity() -> Identity:
    return Identity.from_master(MASTER, "default", account_ss58=SS58)


@pytest.fixture
def client(identity: Identity) -> Client:
    return Client(token="tok", identity=identity, transport=Transport(BASE, "tok"))


@respx.mock
def test_delete_one_file(client: Client) -> None:
    file_id = client.files.file_id("a.bin")
    route = respx.delete(f"{BASE}/delete/{SS58}/{FOLDER}/{file_id}").mock(
        return_value=httpx.Response(
            200,
            json={
                "Success": {
                    "status": "deleted",
                    "file_id": file_id,
                    "ss58_address": SS58,
                    "folder_hash": FOLDER,
                }
            },
        )
    )
    assert client.files.delete(file_id).status == "deleted"
    assert route.calls.last.request.method == "DELETE"


@respx.mock
def test_deleting_a_gone_file_is_not_found(client: Client) -> None:
    file_id = client.files.file_id("a.bin")
    respx.delete(f"{BASE}/delete/{SS58}/{FOLDER}/{file_id}").mock(
        return_value=httpx.Response(404, json={"Error": {"error": "not_found", "message": "no"}})
    )
    with pytest.raises(errors.NotFound):
        client.files.delete(file_id)


@respx.mock
def test_delete_many_reports_per_id_outcomes(client: Client) -> None:
    route = respx.post(f"{BASE}/delete_files").mock(
        return_value=httpx.Response(
            200,
            json={
                "Success": {
                    "deleted": [
                        {"file_id": "aa", "status": "deleted"},
                        {"file_id": "bb", "status": "already_deleted"},
                    ],
                    "errors": [{"file_id": "cc", "error": "database_error"}],
                    "files_deleted": 1,
                }
            },
        )
    )
    result = client.files.delete_many(["aa", "bb", "cc"])
    assert result.files_deleted == 1
    assert result.errors[0].file_id == "cc"
    body = json.loads(route.calls.last.request.content)
    assert body == {
        "ss58_address": SS58,
        "folder_hash": FOLDER,
        "file_ids": ["aa", "bb", "cc"],
        "quiet": False,
    }


@respx.mock
def test_delete_many_rejects_an_over_cap_batch_without_a_round_trip(client: Client) -> None:
    route = respx.post(f"{BASE}/delete_files")
    with pytest.raises(ValueError, match="1000"):
        client.files.delete_many(["aa"] * 1001)
    assert route.call_count == 0


@respx.mock
def test_delete_many_quiet_flag(client: Client) -> None:
    route = respx.post(f"{BASE}/delete_files").mock(
        return_value=httpx.Response(200, json={"Success": {"errors": [], "files_deleted": 0}})
    )
    client.files.delete_many(["aa"], quiet=True)
    assert json.loads(route.calls.last.request.content)["quiet"] is True


def rename_ok() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "Success": {
                "status": "ok",
                "renamed_count": 2,
                "successes": [
                    {
                        "old_path_hash": [1] * 32,
                        "new_path_hash": [2] * 32,
                        "new_revision_id": [3] * 32,
                        "new_revision_seq": 5,
                    }
                ],
                "failures": [{"old_path_hash": [4] * 32, "reason": "revision_mismatch"}],
            }
        },
    )


@respx.mock
def test_rename_signature_verifies_over_the_documented_text(
    client: Client, identity: Identity
) -> None:
    route = respx.post(f"{BASE}/rename_files").mock(return_value=rename_ok())
    # Passed in reverse of the signing order on purpose: the server sorts by
    # old_path_hash before it rebuilds the text, so the client must too.
    specs = [
        RenameSpec("z.bin", "z2.bin", bytes([9] * 32)),
        RenameSpec("a.bin", "a2.bin", bytes([8] * 32)),
    ]
    client.files.rename(specs)

    body = json.loads(route.calls.last.request.content)
    pairs = [(bytes(r["old_path_hash"]), bytes(r["new_path_hash"])) for r in body["renames"]]
    assert [old for old, _ in pairs] == sorted(old for old, _ in pairs)
    VerifyKey(bytes(body["signing_key"])).verify(
        rename_text(pairs).encode(), bytes(body["signature"])
    )
    assert bytes(body["signing_key"]) == identity.verifying_key


@respx.mock
def test_rename_is_invariant_to_the_order_the_caller_passes(client: Client) -> None:
    route = respx.post(f"{BASE}/rename_files").mock(return_value=rename_ok())
    specs = [
        RenameSpec("z.bin", "z2.bin", bytes([9] * 32)),
        RenameSpec("a.bin", "a2.bin", bytes([8] * 32)),
    ]
    client.files.rename(specs)
    first = json.loads(route.calls.last.request.content)
    client.files.rename(list(reversed(specs)))
    second = json.loads(route.calls.last.request.content)

    # new_encrypted_path carries a fresh random nonce per call, so compare the
    # parts the server actually verifies: the signature and the hash pairs.
    assert first["signature"] == second["signature"]
    keys = ("old_path_hash", "new_path_hash", "new_relative_path", "base_revision_id")
    assert [{k: r[k] for k in keys} for r in first["renames"]] == [
        {k: r[k] for k in keys} for r in second["renames"]
    ]


@respx.mock
def test_rename_carries_the_new_path_metadata(client: Client, identity: Identity) -> None:
    route = respx.post(f"{BASE}/rename_files").mock(return_value=rename_ok())
    client.files.rename([RenameSpec("docs/a.bin", "docs/2026/b.bin", bytes([7] * 32))])

    entry = json.loads(route.calls.last.request.content)["renames"][0]
    assert bytes(entry["old_path_hash"]) == hashes.path_hash("docs/a.bin")
    assert bytes(entry["new_path_hash"]) == hashes.path_hash("docs/2026/b.bin")
    assert entry["new_relative_path"] == "docs/2026/b.bin"
    assert entry["new_file_name"] == "b.bin"
    assert bytes(entry["base_revision_id"]) == bytes([7] * 32)
    decrypted = file_cipher.decrypt_bytes(
        bytes(entry["new_encrypted_path"]), identity.encryption_key
    )
    assert decrypted == b"docs/2026/b.bin"


@respx.mock
def test_rename_surfaces_per_entry_failures(client: Client) -> None:
    respx.post(f"{BASE}/rename_files").mock(return_value=rename_ok())
    result = client.files.rename([RenameSpec("a.bin", "b.bin", bytes(32))])
    assert result.renamed_count == 2
    assert result.failures[0].reason == "revision_mismatch"
    assert result.successes[0].new_revision_id == bytes([3] * 32)


@respx.mock
def test_rename_rejects_an_empty_batch_without_a_round_trip(client: Client) -> None:
    route = respx.post(f"{BASE}/rename_files")
    with pytest.raises(ValueError, match="at least one"):
        client.files.rename([])
    assert route.call_count == 0


@respx.mock
def test_rename_rejects_a_traversing_path_before_any_request(client: Client) -> None:
    route = respx.post(f"{BASE}/rename_files")
    with pytest.raises(ValueError, match="relative_path"):
        client.files.rename([RenameSpec("a.bin", "../b.bin", bytes(32))])
    assert route.call_count == 0


@respx.mock
def test_rename_bad_signature_is_a_400(client: Client) -> None:
    respx.post(f"{BASE}/rename_files").mock(
        return_value=httpx.Response(
            400, json={"Error": {"error": "invalid_manifest", "message": "bad signature"}}
        )
    )
    with pytest.raises(errors.InvalidRequest) as exc:
        client.files.rename([RenameSpec("a.bin", "b.bin", bytes(32))])
    assert exc.value.code == "invalid_manifest"
