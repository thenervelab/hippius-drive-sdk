"""File and folder share requests, including the recipient URL."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from hippius_drive._links import DEFAULT_CONSOLE, FileShareSpec, FolderShareSpec
from hippius_drive._transport import Transport
from hippius_drive._upload import TRANSPORT_CHUNK
from hippius_drive.client import Client
from hippius_drive.crypto import file_cipher, kdf
from hippius_drive.identity import Identity
from tests.helpers import multipart_parts

BASE = "https://example.test"
MASTER = " ".join(["abandon"] * 23 + ["art"])
SS58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
FOLDER = "37a8eec1ce19687d"


@pytest.fixture
def client() -> Client:
    identity = Identity.from_master(MASTER, "default", account_ss58=SS58)
    return Client(token="tok", identity=identity, transport=Transport(BASE, "tok"))


def _minted(token: str) -> httpx.Response:
    return httpx.Response(201, json={"share_token": token, "expires_at": None})


def _ok() -> httpx.Response:
    return _minted("tok")


@respx.mock
def test_file_share_posts_metadata_then_ciphertext_and_opens_without_a_bearer(
    client: Client,
) -> None:
    captured: dict[str, object] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        parts = multipart_parts(request)
        captured["parts"] = [name for name, _, _ in parts]
        captured["meta"] = json.loads(parts[0][2])
        captured["blob"] = parts[1][2]
        return _ok()

    respx.post(f"{BASE}/v1/shares").mock(side_effect=capture)
    spec = FileShareSpec("report.pdf", mime_type="application/pdf")
    created = client.shares.create(b"hello", spec)

    assert captured["parts"] == ["metadata", "ciphertext"]
    meta = captured["meta"]
    assert isinstance(meta, dict)
    assert meta["filename"] == "report.pdf"
    assert meta["plaintext_size"] == 5
    assert meta["ttl"] == "24h"
    assert meta["mime_type"] == "application/pdf"
    assert created.share_url.startswith(f"{DEFAULT_CONSOLE}/share/tok#k=")
    assert "#p=" not in created.share_url

    blob = captured["blob"]
    assert isinstance(blob, bytes)
    respx.get(f"{BASE}/v1/shares/tok/meta").mock(
        return_value=httpx.Response(
            200,
            json={
                "filename_ct": meta["filename_ct"],
                "filename_nonce": meta["filename_nonce"],
                "mime_type": "application/pdf",
                "plaintext_size": 5,
                "ciphertext_size": len(blob),
                "expires_at": None,
            },
        )
    )
    blob_route = respx.get(f"{BASE}/v1/shares/tok/blob").mock(
        return_value=httpx.Response(200, content=blob)
    )
    opened = client.shares.open(created.share_url)
    assert opened.data == b"hello"
    assert opened.filename == "report.pdf"
    assert blob_route.calls.last.request.headers.get("Authorization") is None


@respx.mock
def test_a_password_share_url_has_no_raw_key(client: Client) -> None:
    respx.post(f"{BASE}/v1/shares").mock(return_value=_minted("pw"))
    created = client.shares.create(b"x", FileShareSpec("a.txt", password="hunter22"))
    assert "#p=" in created.share_url
    assert "#k=" not in created.share_url
    opened_key = created.share_url.split("#p=", 1)[1]
    assert opened_key
    with pytest.raises(ValueError, match="password"):
        client.shares.open(created.share_url)


@respx.mock
def test_a_large_share_uses_the_chunked_routes(client: Client) -> None:
    assert file_cipher.ciphertext_size(TRANSPORT_CHUNK) > TRANSPORT_CHUNK
    respx.post(f"{BASE}/v1/shares/init").mock(return_value=_minted("big"))
    chunk_route = respx.put(url__regex=r".*/v1/shares/big/chunks/\d+").mock(
        return_value=httpx.Response(200, json={"chunk_index": 0})
    )
    done = respx.post(f"{BASE}/v1/shares/big/complete").mock(return_value=_minted("big"))
    single = respx.post(f"{BASE}/v1/shares").mock(return_value=_minted("nope"))

    created = client.shares.create(b"y" * TRANSPORT_CHUNK, FileShareSpec("big.bin"))

    assert created.share_token == "big"
    assert single.calls == []
    assert len(chunk_route.calls) >= 2
    assert done.called
    assert chunk_route.calls[0].request.headers["content-type"] == "application/octet-stream"


@respx.mock
def test_folder_share_omits_the_owner_and_a_member_names_them(client: Client) -> None:
    route = respx.post(f"{BASE}/v1/folder-shares").mock(return_value=_minted("fold"))
    created = client.folder_shares.create(FolderShareSpec("", "Reports"))
    body = json.loads(route.calls.last.request.content)
    assert "owner_ss58" not in body
    assert body["path_prefix"] == ""
    assert body["display_name"] == "Reports"
    assert created.share_url.startswith(f"{DEFAULT_CONSOLE}/share/folder/fold#k=")

    member = Identity.for_shared_drive(
        kdf.derive_folder_mnemonic(MASTER, "default"),
        owner_ss58=SS58,
        folder_hash=FOLDER,
        role="writer",
    )
    member_client = Client(token="member", identity=member, transport=Transport(BASE, "member"))
    respx.get(f"{BASE}/v1/capabilities").mock(
        return_value=httpx.Response(200, json={"member_folder_shares": True})
    )
    member_client.folder_shares.create(FolderShareSpec("work", "Work"))
    sent = json.loads(route.calls.last.request.content)
    assert sent["owner_ss58"] == SS58
    assert sent["path_prefix"] == "work"


@respx.mock
def test_a_member_mint_stops_when_the_capability_is_absent(client: Client) -> None:
    del client
    member = Identity.for_shared_drive(
        kdf.derive_folder_mnemonic(MASTER, "default"),
        owner_ss58=SS58,
        folder_hash=FOLDER,
        role="manager",
    )
    member_client = Client(token="member", identity=member, transport=Transport(BASE, "member"))
    respx.get(f"{BASE}/v1/capabilities").mock(return_value=httpx.Response(404))
    post = respx.post(f"{BASE}/v1/folder-shares").mock(return_value=_ok())
    with pytest.raises(ValueError, match="shared drive"):
        member_client.folder_shares.create(FolderShareSpec("", "Reports"))
    assert post.calls == []


@respx.mock
def test_a_reader_cannot_mint_a_folder_share() -> None:
    member = Identity.for_shared_drive(
        kdf.derive_folder_mnemonic(MASTER, "default"),
        owner_ss58=SS58,
        folder_hash=FOLDER,
        role="reader",
    )
    member_client = Client(token="member", identity=member, transport=Transport(BASE, "member"))
    post = respx.post(f"{BASE}/v1/folder-shares").mock(return_value=_ok())
    with pytest.raises(ValueError, match="reader"):
        member_client.folder_shares.create(FolderShareSpec("", "Reports"))
    assert post.calls == []


@respx.mock
def test_revoke_by_hash_checks_the_capability_first(client: Client) -> None:
    respx.get(f"{BASE}/v1/capabilities").mock(
        return_value=httpx.Response(200, json={"folder_share_revoke_by_hash": False})
    )
    route = respx.delete(url__regex=r".*/by-hash/.*").mock(return_value=httpx.Response(204))
    with pytest.raises(ValueError, match="token_hash"):
        client.folder_shares.revoke("ab" * 32)
    assert route.calls == []


@respx.mock
def test_listing_a_share_array_and_revoking_returns_no_body(client: Client) -> None:
    respx.get(f"{BASE}/v1/shares").mock(
        return_value=httpx.Response(
            200,
            json=[{"share_token": "tok", "filename": "a.txt", "plaintext_size": 1}],
        )
    )
    listed = client.shares.list()
    assert listed[0].share_token == "tok"
    respx.delete(f"{BASE}/v1/shares/tok").mock(return_value=httpx.Response(204))
    assert client.shares.revoke("tok") is None
