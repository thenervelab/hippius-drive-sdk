"""Shared-drive invites: the member's token, the owner's namespace."""

from __future__ import annotations

import base64
import json

import blake3
import httpx
import pytest
import respx

from hippius_drive._links import DEFAULT_CONSOLE, InviteSpec
from hippius_drive._transport import Transport
from hippius_drive.client import Client
from hippius_drive.crypto import kdf
from hippius_drive.identity import Identity

BASE = "https://example.test"
MASTER = " ".join(["abandon"] * 23 + ["art"])
SS58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
FOLDER = "37a8eec1ce19687d"
TOKEN = "inviteTok"


@pytest.fixture
def client() -> Client:
    identity = Identity.from_master(MASTER, "default", account_ss58=SS58)
    return Client(token="tok", identity=identity, transport=Transport(BASE, "tok"))


def _phrase() -> str:
    return kdf.derive_folder_mnemonic(MASTER, "default")


@respx.mock
def test_create_invite_seals_the_token_and_returns_a_fragment_url(client: Client) -> None:
    invite_id = blake3.blake3(TOKEN.encode()).hexdigest()
    respx.post(f"{BASE}/v1/drive-invites").mock(
        return_value=httpx.Response(200, json={"invite_token": TOKEN, "invite_id": invite_id})
    )
    seal = respx.put(f"{BASE}/v1/drives/{FOLDER}/invites/{invite_id}/sealed-token").mock(
        return_value=httpx.Response(200)
    )
    created = client.drives.create_invite(InviteSpec(_phrase(), role="writer"))
    mint = json.loads(respx.calls[0].request.content)
    assert mint == {"folder_hash": FOLDER, "role": "writer"}
    prefix = f"{DEFAULT_CONSOLE}/invite/{TOKEN}#k="
    assert created.invite_url.startswith(prefix)
    assert len(created.invite_url) > len(prefix)
    assert seal.called
    body = json.loads(seal.calls.last.request.content)
    raw = base64.b64decode(body["sealed_token"])
    assert json.loads(raw)["v"] == 1
    assert "owner" not in seal.calls.last.request.url.params


@respx.mock
def test_a_failed_seal_back_still_returns_the_invite_url(client: Client) -> None:
    invite_id = blake3.blake3(TOKEN.encode()).hexdigest()
    respx.post(f"{BASE}/v1/drive-invites").mock(
        return_value=httpx.Response(200, json={"invite_token": TOKEN, "invite_id": invite_id})
    )
    respx.put(url__regex=r".*/sealed-token$").mock(
        return_value=httpx.Response(500, json={"error": "unavailable", "message": "later"})
    )
    created = client.drives.create_invite(InviteSpec(_phrase()))
    assert created.invite_token == TOKEN
    assert created.invite_url.startswith(f"{DEFAULT_CONSOLE}/invite/{TOKEN}#k=")


@respx.mock
def test_leave_always_names_the_owner() -> None:
    member = Identity.for_shared_drive(
        _phrase(), owner_ss58=SS58, folder_hash=FOLDER, role="writer"
    )
    client = Client(token="member", identity=member, transport=Transport(BASE, "member"))
    route = respx.delete(f"{BASE}/v1/drives/{FOLDER}/members/member-ss58").mock(
        return_value=httpx.Response(204)
    )
    client.drives.leave("member-ss58")
    assert route.calls.last.request.url.params["owner"] == SS58


@respx.mock
def test_a_reader_cannot_mint_an_invite() -> None:
    member = Identity.for_shared_drive(
        _phrase(), owner_ss58=SS58, folder_hash=FOLDER, role="reader"
    )
    client = Client(token="member", identity=member, transport=Transport(BASE, "member"))
    post = respx.post(f"{BASE}/v1/drive-invites").mock(return_value=httpx.Response(500))
    with pytest.raises(ValueError, match="owner or a manager"):
        client.drives.create_invite(InviteSpec(_phrase()))
    assert post.calls == []


@respx.mock
def test_invite_meta_does_not_send_the_bearer(client: Client) -> None:
    route = respx.get(f"{BASE}/v1/drive-invites/{TOKEN}/meta").mock(
        return_value=httpx.Response(
            200,
            json={
                "owner_ss58": SS58,
                "folder_hash": FOLDER,
                "display_label": "default",
                "expires_at": "2026-01-01T00:00:00+00:00",
                "role": "writer",
                "valid": True,
            },
        )
    )
    meta = client.drives.invite_meta(f"{DEFAULT_CONSOLE}/invite/{TOKEN}#k={'A' * 43}")
    assert meta.owner_ss58 == SS58
    assert meta.valid is True
    assert route.calls.last.request.headers.get("Authorization") is None
