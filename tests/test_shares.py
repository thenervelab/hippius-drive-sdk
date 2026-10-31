"""File and folder share requests, including the recipient URL."""

from __future__ import annotations

import base64
import json

import httpx
import pytest
import respx

from hippius_drive._links import DEFAULT_CONSOLE, FileShareSpec, FolderShareSpec
from hippius_drive._transport import AsyncTransport, Transport
from hippius_drive._upload import TRANSPORT_CHUNK
from hippius_drive.client import AsyncClient, Client
from hippius_drive.crypto import file_cipher, folder_link, kdf, sharing
from hippius_drive.errors import InvalidResponse, NotFound, ServerError
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


def _folder_minted() -> httpx.Response:
    return httpx.Response(
        201, json={"share_token": "fold", "expires_at": None, "link_envelope": True}
    )


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
    route = respx.post(f"{BASE}/v1/folder-shares").mock(return_value=_folder_minted())
    created = client.folder_shares.create(FolderShareSpec("", "Reports"))
    body = json.loads(route.calls.last.request.content)
    assert "owner_ss58" not in body
    assert body["path_prefix"] == ""
    assert body["display_name"] == "Reports"
    assert created.share_url.startswith(f"{DEFAULT_CONSOLE}/share/folder/fold#s=")

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


def _sent_body(route: respx.Route) -> dict[str, str]:
    return json.loads(route.calls.last.request.content)


@respx.mock
def test_a_folder_link_carries_a_link_secret_and_the_body_seals_the_drive_key(
    client: Client,
) -> None:
    route = respx.post(f"{BASE}/v1/folder-shares").mock(return_value=_folder_minted())
    created = client.folder_shares.create(FolderShareSpec("work", "Work"))

    secret = sharing.parse_share_url(created.share_url).secret
    assert secret.link_secret
    assert not secret.private
    drive_key = client.identity.encryption_key
    assert secret.material != drive_key
    assert base64.urlsafe_b64encode(drive_key).rstrip(b"=").decode() not in created.share_url

    body = _sent_body(route)
    envelope = base64.b64decode(body["link_envelope"], validate=True)
    digest = base64.b64decode(body["link_fetch_digest"], validate=True)
    assert len(envelope) == folder_link.ENVELOPE_LEN
    assert folder_link.open_envelope(secret.material, envelope) == drive_key
    assert digest == folder_link.fetch_digest(secret.material)

    again = client.folder_shares.create(FolderShareSpec("work", "Work"))
    assert sharing.parse_share_url(again.share_url).secret.material != secret.material


@respx.mock
def test_a_password_folder_link_wraps_the_link_secret(client: Client) -> None:
    route = respx.post(f"{BASE}/v1/folder-shares").mock(return_value=_folder_minted())
    created = client.folder_shares.create(FolderShareSpec("", "All", password="hunter2-hunter2"))

    assert created.share_url.startswith(f"{DEFAULT_CONSOLE}/share/folder/fold#sp=")
    secret = sharing.parse_share_url(created.share_url).secret
    assert secret.private
    assert secret.link_secret
    link_secret = sharing.unwrap_share_key("hunter2-hunter2", secret.material)
    envelope = base64.b64decode(_sent_body(route)["link_envelope"])
    assert folder_link.open_envelope(link_secret, envelope) == client.identity.encryption_key


@respx.mock
def test_a_mint_without_a_stored_envelope_is_revoked_and_raises(client: Client) -> None:
    respx.post(f"{BASE}/v1/folder-shares").mock(return_value=_minted("fold"))
    revoke = respx.delete(f"{BASE}/v1/folder-shares/fold").mock(return_value=httpx.Response(204))
    with pytest.raises(InvalidResponse, match="envelope"):
        client.folder_shares.create(FolderShareSpec("", "All"))
    assert revoke.called


@respx.mock
def test_a_failed_revoke_still_reports_the_missing_envelope(client: Client) -> None:
    respx.post(f"{BASE}/v1/folder-shares").mock(return_value=_minted("fold"))
    respx.delete(f"{BASE}/v1/folder-shares/fold").mock(return_value=httpx.Response(500))
    with pytest.raises(InvalidResponse, match="envelope") as raised:
        client.folder_shares.create(FolderShareSpec("", "All"))
    assert isinstance(raised.value.__cause__, ServerError)


def _link_url(client: Client, link_secret: bytes) -> tuple[str, bytes]:
    envelope = folder_link.seal_envelope(link_secret, client.identity.encryption_key)
    secret = sharing.ShareSecret(link_secret, link_secret=True)
    return sharing.share_url(DEFAULT_CONSOLE, "fold", secret, folder=True), envelope


@respx.mock
def test_a_link_secret_url_fetches_the_envelope_with_a_proof_and_decrypts(
    client: Client,
) -> None:
    link_secret = bytes(range(32))
    url, envelope = _link_url(client, link_secret)
    link_key = respx.get(f"{BASE}/v1/folder-shares/fold/link-key").mock(
        return_value=httpx.Response(200, json={"envelope": base64.b64encode(envelope).decode()})
    )
    blob = file_cipher.encrypt_bytes(b"doc", client.identity.encryption_key)
    respx.get(url__regex=r".*/folder-shares/fold/blob").mock(
        return_value=httpx.Response(200, content=blob)
    )

    assert client.folder_shares.get(url, "a.txt") == b"doc"
    sent = link_key.calls.last.request
    assert sent.headers["x-hcfs-link-proof"] == folder_link.fetch_proof(link_secret)
    assert "authorization" not in sent.headers


@respx.mock
def test_browse_on_a_link_secret_url_does_not_fetch_the_key(client: Client) -> None:
    url, _envelope = _link_url(client, bytes(32))
    link_key = respx.get(f"{BASE}/v1/folder-shares/fold/link-key")
    respx.get(url__regex=r".*/folder-shares/fold/browse").mock(
        return_value=httpx.Response(200, json={"files": [], "directories": [], "has_more": False})
    )
    assert client.folder_shares.browse(url).has_more is False
    assert not link_key.called


@respx.mock
def test_a_revoked_link_secret_url_is_not_found(client: Client) -> None:
    url, _envelope = _link_url(client, bytes(32))
    respx.get(f"{BASE}/v1/folder-shares/fold/link-key").mock(return_value=httpx.Response(404))
    blob = respx.get(url__regex=r".*/folder-shares/fold/blob")
    with pytest.raises(NotFound):
        client.folder_shares.get(url, "a.txt")
    assert not blob.called


@respx.mock
def test_an_envelope_that_is_not_base64_is_an_invalid_response(client: Client) -> None:
    url, _envelope = _link_url(client, bytes(32))
    respx.get(f"{BASE}/v1/folder-shares/fold/link-key").mock(
        return_value=httpx.Response(200, json={"envelope": "%%%"})
    )
    with pytest.raises(InvalidResponse, match="base64"):
        client.folder_shares.get(url, "a.txt")


@respx.mock
@pytest.mark.anyio
async def test_async_folder_link_mint_and_open_match_the_sync_client(client: Client) -> None:
    identity = client.identity
    aclient = AsyncClient(token="tok", identity=identity, transport=AsyncTransport(BASE, "tok"))
    route = respx.post(f"{BASE}/v1/folder-shares").mock(return_value=_folder_minted())
    created = await aclient.folder_shares.create(FolderShareSpec("work", "Work"))
    link_secret = sharing.parse_share_url(created.share_url).secret.material
    envelope = _sent_body(route)["link_envelope"]
    respx.get(f"{BASE}/v1/folder-shares/fold/link-key").mock(
        return_value=httpx.Response(200, json={"envelope": envelope})
    )
    blob = file_cipher.encrypt_bytes(b"doc", identity.encryption_key)
    respx.get(url__regex=r".*/folder-shares/fold/blob").mock(
        return_value=httpx.Response(200, content=blob)
    )
    assert await aclient.folder_shares.get(created.share_url, "a.txt") == b"doc"
    assert folder_link.open_envelope(link_secret, base64.b64decode(envelope)) == (
        identity.encryption_key
    )

    respx.post(f"{BASE}/v1/folder-shares").mock(return_value=_minted("old"))
    revoke = respx.delete(f"{BASE}/v1/folder-shares/old").mock(return_value=httpx.Response(204))
    with pytest.raises(InvalidResponse, match="envelope"):
        await aclient.folder_shares.create(FolderShareSpec("", "All"))
    assert revoke.called

    respx.post(f"{BASE}/v1/folder-shares").mock(return_value=_minted("old2"))
    respx.delete(f"{BASE}/v1/folder-shares/old2").mock(return_value=httpx.Response(500))
    with pytest.raises(InvalidResponse, match="envelope"):
        await aclient.folder_shares.create(FolderShareSpec("", "All"))
    await aclient.aclose()
