"""A member writes as the owner on the wire, and a reader does not write at all."""

from __future__ import annotations

import httpx
import pytest
import respx

from hippius_drive._transport import Transport
from hippius_drive.client import Client
from hippius_drive.crypto import hashes, kdf
from hippius_drive.identity import Identity
from hippius_drive.models import Manifest, SearchFilters
from tests.helpers import multipart_parts

BASE = "https://example.test"
MASTER = " ".join(["abandon"] * 23 + ["art"])
OWNER = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
FOLDER = "ab" * 8


def _member(role: str) -> Identity:
    phrase = kdf.derive_folder_mnemonic(MASTER, "default")
    return Identity.for_shared_drive(phrase, owner_ss58=OWNER, folder_hash=FOLDER, role=role)


def _client(role: str) -> Client:
    return Client(token="member-token", identity=_member(role), transport=Transport(BASE, "member"))


@respx.mock
def test_a_member_upload_salts_and_addresses_the_owner() -> None:
    route = respx.post(f"{BASE}/upload").mock(
        return_value=httpx.Response(
            200,
            json={
                "Success": {
                    "upload_id": "u1",
                    "timestamp": 1,
                    "revision_id": [1] * 32,
                }
            },
        )
    )
    _client("writer").files.put_bytes(b"report", "work/report.pdf")
    manifest = Manifest.model_validate_json(multipart_parts(route.calls.last.request)[0][2])
    assert route.calls.last.request.url.path == "/upload"
    assert manifest.ss58_address == OWNER
    assert manifest.folder_hash == FOLDER
    assert manifest.salted_hash == hashes.salted_hash(OWNER, b"report")
    assert "member" not in manifest.ss58_address


@respx.mock
def test_a_reader_put_and_a_member_unregister_send_nothing() -> None:
    route = respx.post(f"{BASE}/upload").mock(return_value=httpx.Response(500))
    unregister = respx.post(f"{BASE}/unregister_folder").mock(return_value=httpx.Response(500))
    with pytest.raises(ValueError, match="reader"):
        _client("reader").files.put_bytes(b"x", "a.bin")
    with pytest.raises(ValueError, match="owner"):
        _client("writer").folders.unregister()
    assert route.calls == []
    assert unregister.calls == []


@respx.mock
def test_member_search_names_the_drive_and_an_owner_search_does_not() -> None:
    body = {
        "Success": {
            "files": [],
            "total_count": 0,
            "has_more": False,
            "offset": 0,
            "limit": 25,
        }
    }
    route = respx.get(url__regex=r".*/search_files/.*").mock(
        return_value=httpx.Response(200, json=body)
    )
    _client("writer").files.search(SearchFilters(q="report"))
    assert route.calls.last.request.url.params["folder_hash"] == FOLDER
    assert route.calls.last.request.url.path == f"/search_files/{OWNER}"

    owner = Identity.from_master(MASTER, "default", account_ss58=OWNER)
    owned = Client(token="owner-token", identity=owner, transport=Transport(BASE, "owner"))
    owned.files.search(SearchFilters(q="report"))
    assert "folder_hash" not in route.calls.last.request.url.params
