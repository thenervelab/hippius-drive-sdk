"""Shared-drive invites: the member's token, the owner's namespace."""

from __future__ import annotations

import base64
import json

import blake3
import httpx
import pytest
import respx

from hippius_drive import _links
from hippius_drive._links import DEFAULT_CONSOLE, InviteSpec
from hippius_drive._transport import AsyncTransport, Transport
from hippius_drive._wire import build
from hippius_drive.client import AsyncClient, Client
from hippius_drive.crypto import grant, invite_link, kdf
from hippius_drive.crypto.invite_link import InviteLinkKind
from hippius_drive.errors import (
    DecryptError,
    Forbidden,
    InvalidResponse,
    MemberLimitReached,
    NotFound,
)
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
def test_a_bad_invite_is_rejected_before_the_mint(client: Client) -> None:
    post = respx.post(f"{BASE}/v1/drive-invites").mock(return_value=httpx.Response(500))
    with pytest.raises(ValueError, match="BIP-39"):
        client.drives.create_invite(InviteSpec("not a phrase"))
    with pytest.raises(ValueError, match="https"):
        client.drives.create_invite(
            InviteSpec(_phrase(), console_base_url="http://console.example")
        )
    assert post.calls == []


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


def _link_secret() -> bytes:
    entropy = kdf.folder_entropy(MASTER, "default")
    return invite_link.derive_link_secret(entropy, invite_link.invite_id_for_token(TOKEN))


def _link_url() -> str:
    fragment = base64.urlsafe_b64encode(_link_secret()).rstrip(b"=").decode()
    return f"{DEFAULT_CONSOLE}/invite/{TOKEN}#i={fragment}"


def _mock_link_invite(
    *, path_prefix: str | None = None, kind: str = "drive", envelope: bytes | None = None
) -> tuple[respx.Route, respx.Route]:
    meta: dict[str, object] = {"owner_ss58": SS58, "folder_hash": FOLDER, "valid": True}
    if path_prefix is not None:
        meta["path_prefix"] = path_prefix
    meta_route = respx.get(f"{BASE}/v1/drive-invites/{TOKEN}/meta").mock(
        return_value=httpx.Response(200, json=meta)
    )
    if envelope is None:
        entropy = kdf.folder_entropy(MASTER, "default")
        envelope = invite_link.seal_envelope(_link_secret(), entropy, InviteLinkKind.DRIVE)
    key_route = respx.get(f"{BASE}/v1/drive-invites/{TOKEN}/link-key").mock(
        return_value=httpx.Response(
            200, json={"envelope": base64.b64encode(envelope).decode(), "kind": kind}
        )
    )
    return meta_route, key_route


def _accepted() -> httpx.Response:
    return httpx.Response(200, json={"owner_ss58": SS58, "folder_hash": FOLDER, "role": "writer"})


@respx.mock
def test_a_link_secret_invite_opens_its_envelope_and_joins(client: Client) -> None:
    # Seals a grant under the production Argon2id parameters.
    meta_route, key_route = _mock_link_invite()
    accept = respx.post(f"{BASE}/v1/drive-invites/{TOKEN}/accept").mock(return_value=_accepted())
    accepted = client.drives.accept(_link_url(), MASTER, member_ss58=SS58)
    assert accepted.folder_mnemonic == _phrase()
    assert accepted.role == "writer"
    assert meta_route.calls.last.request.headers.get("Authorization") is None
    sent = key_route.calls.last.request.headers
    assert sent["x-hcfs-link-proof"] == invite_link.fetch_proof(_link_secret())
    assert sent["Authorization"] == "Bearer tok"
    assert accept.called


@pytest.fixture
def quick_grant(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Stand in for the Argon2id grant seal and record what it was asked to seal."""
    sealed: list[str] = []

    def fake_grant(member_master: str, member_ss58: str, folder_phrase: str) -> str:
        sealed.append(folder_phrase)
        return base64.b64encode(b"{}").decode()

    monkeypatch.setattr(_links, "accept_grant", fake_grant)
    return sealed


def _folder_accepted(path_prefix: str | None) -> httpx.Response:
    body: dict[str, object] = {"owner_ss58": SS58, "folder_hash": FOLDER, "role": "reader"}
    if path_prefix is not None:
        body["path_prefix"] = path_prefix
    return httpx.Response(200, json=body)


FILE_KEY = bytes([0x44]) * 32


@respx.mock
def test_a_link_secret_folder_invite_opens_as_a_folder_and_echoes_its_prefix(
    client: Client, quick_grant: list[str]
) -> None:
    folder = invite_link.seal_envelope(_link_secret(), FILE_KEY, InviteLinkKind.FOLDER)
    _mock_link_invite(path_prefix="Clients/ACME", kind="folder", envelope=folder)
    accept = respx.post(f"{BASE}/v1/drive-invites/{TOKEN}/accept").mock(
        return_value=_folder_accepted("Clients/ACME")
    )
    accepted = client.drives.accept(_link_url(), MASTER, member_ss58=SS58)
    assert json.loads(accept.calls.last.request.content)["path_prefix"] == "Clients/ACME"
    assert accepted.path_prefix == "Clients/ACME"
    assert quick_grant == [grant.phrase_from_entropy(FILE_KEY)]
    member = Identity.for_folder_grant(
        accepted.folder_mnemonic, owner_ss58=SS58, folder_hash=FOLDER, role=accepted.role
    )
    assert member.encryption_key == FILE_KEY
    assert member.keys.signing_seed == FILE_KEY


@respx.mock
def test_a_legacy_folder_invite_echoes_its_prefix(client: Client, quick_grant: list[str]) -> None:
    respx.get(f"{BASE}/v1/drive-invites/{TOKEN}/meta").mock(
        return_value=httpx.Response(
            200, json={"owner_ss58": SS58, "folder_hash": FOLDER, "path_prefix": "Work"}
        )
    )
    accept = respx.post(f"{BASE}/v1/drive-invites/{TOKEN}/accept").mock(
        return_value=_folder_accepted("Work")
    )
    url = grant.invite_url(DEFAULT_CONSOLE, TOKEN, FILE_KEY)
    accepted = client.drives.accept(url, MASTER, member_ss58=SS58)
    assert json.loads(accept.calls.last.request.content) == {
        "grant_blob": base64.b64encode(b"{}").decode(),
        "path_prefix": "Work",
    }
    assert accepted.path_prefix == "Work"


@respx.mock
def test_a_whole_drive_accept_sends_no_prefix(client: Client, quick_grant: list[str]) -> None:
    _mock_link_invite()
    accept = respx.post(f"{BASE}/v1/drive-invites/{TOKEN}/accept").mock(return_value=_accepted())
    accepted = client.drives.accept(_link_url(), MASTER, member_ss58=SS58)
    assert "path_prefix" not in json.loads(accept.calls.last.request.content)
    assert accepted.path_prefix is None


@respx.mock
def test_an_accept_that_drops_the_folder_is_refused(client: Client, quick_grant: list[str]) -> None:
    respx.get(f"{BASE}/v1/drive-invites/{TOKEN}/meta").mock(
        return_value=httpx.Response(
            200, json={"owner_ss58": SS58, "folder_hash": FOLDER, "path_prefix": "Work"}
        )
    )
    respx.post(f"{BASE}/v1/drive-invites/{TOKEN}/accept").mock(return_value=_folder_accepted(None))
    url = grant.invite_url(DEFAULT_CONSOLE, TOKEN, FILE_KEY)
    with pytest.raises(InvalidResponse, match="echo"):
        client.drives.accept(url, MASTER, member_ss58=SS58)


@respx.mock
def test_an_owner_opening_their_own_folder_invite_gets_the_echo_too(
    client: Client, quick_grant: list[str]
) -> None:
    respx.get(f"{BASE}/v1/drive-invites/{TOKEN}/meta").mock(
        return_value=httpx.Response(
            200, json={"owner_ss58": SS58, "folder_hash": FOLDER, "path_prefix": "Work"}
        )
    )
    respx.post(f"{BASE}/v1/drive-invites/{TOKEN}/accept").mock(
        return_value=httpx.Response(
            200,
            json={
                "owner_ss58": SS58,
                "folder_hash": FOLDER,
                "role": "writer",
                "already_owner": True,
                "path_prefix": "Work",
            },
        )
    )
    url = grant.invite_url(DEFAULT_CONSOLE, TOKEN, FILE_KEY)
    assert client.drives.accept(url, MASTER, member_ss58=SS58).already_owner is True


@respx.mock
def test_an_owner_accept_without_the_echo_is_refused_too(
    client: Client, quick_grant: list[str]
) -> None:
    respx.get(f"{BASE}/v1/drive-invites/{TOKEN}/meta").mock(
        return_value=httpx.Response(
            200, json={"owner_ss58": SS58, "folder_hash": FOLDER, "path_prefix": "Work"}
        )
    )
    respx.post(f"{BASE}/v1/drive-invites/{TOKEN}/accept").mock(
        return_value=httpx.Response(
            200,
            json={"owner_ss58": SS58, "folder_hash": FOLDER, "already_owner": True},
        )
    )
    url = grant.invite_url(DEFAULT_CONSOLE, TOKEN, FILE_KEY)
    with pytest.raises(InvalidResponse, match="echo"):
        client.drives.accept(url, MASTER, member_ss58=SS58)


def test_a_folder_grant_identity_is_never_a_manager() -> None:
    phrase = grant.phrase_from_entropy(FILE_KEY)
    with pytest.raises(ValueError, match="reader or writer"):
        Identity.for_folder_grant(phrase, owner_ss58=SS58, folder_hash=FOLDER, role="manager")


@respx.mock
def test_a_link_kind_that_disagrees_with_the_preview_is_refused(client: Client) -> None:
    _mock_link_invite(kind="folder")
    accept = respx.post(f"{BASE}/v1/drive-invites/{TOKEN}/accept")
    with pytest.raises(InvalidResponse, match="does not match"):
        client.drives.accept(_link_url(), MASTER, member_ss58=SS58)
    assert accept.calls == []


@respx.mock
def test_an_envelope_sealed_as_a_folder_does_not_open_as_a_drive(client: Client) -> None:
    folder = invite_link.seal_envelope(_link_secret(), bytes(32), InviteLinkKind.FOLDER)
    _mock_link_invite(envelope=folder)
    with pytest.raises(DecryptError):
        client.drives.accept(_link_url(), MASTER, member_ss58=SS58)


@respx.mock
def test_an_envelope_that_is_not_base64_is_an_invalid_response(client: Client) -> None:
    respx.get(f"{BASE}/v1/drive-invites/{TOKEN}/meta").mock(
        return_value=httpx.Response(200, json={"owner_ss58": SS58, "folder_hash": FOLDER})
    )
    respx.get(f"{BASE}/v1/drive-invites/{TOKEN}/link-key").mock(
        return_value=httpx.Response(200, json={"envelope": "***", "kind": "drive"})
    )
    with pytest.raises(InvalidResponse, match="base64"):
        client.drives.accept(_link_url(), MASTER, member_ss58=SS58)


@respx.mock
def test_a_full_drive_is_a_retryable_member_limit_not_a_forbidden(client: Client) -> None:
    respx.get(f"{BASE}/v1/drive-invites/{TOKEN}/meta").mock(
        return_value=httpx.Response(200, json={"owner_ss58": SS58, "folder_hash": FOLDER})
    )
    body = {"error": "drive_member_limit_reached", "message": "full", "member_limit": 3}
    respx.get(f"{BASE}/v1/drive-invites/{TOKEN}/link-key").mock(
        return_value=httpx.Response(403, json=body)
    )
    with pytest.raises(MemberLimitReached) as caught:
        client.drives.accept(_link_url(), MASTER, member_ss58=SS58)
    assert caught.value.member_limit == 3
    assert caught.value.retryable is True
    assert isinstance(caught.value, Forbidden)


def test_the_link_proof_stays_out_of_the_request_repr() -> None:
    proof = invite_link.fetch_proof(_link_secret())
    assert proof not in repr(build.invite_link_key(TOKEN, proof))


@respx.mock
def test_a_dead_link_is_a_bodiless_not_found(client: Client) -> None:
    respx.get(f"{BASE}/v1/drive-invites/{TOKEN}/meta").mock(
        return_value=httpx.Response(200, json={"owner_ss58": SS58, "folder_hash": FOLDER})
    )
    respx.get(f"{BASE}/v1/drive-invites/{TOKEN}/link-key").mock(return_value=httpx.Response(404))
    with pytest.raises(NotFound):
        client.drives.accept(_link_url(), MASTER, member_ss58=SS58)


@respx.mock
def test_invite_meta_takes_a_link_secret_url(client: Client) -> None:
    route = respx.get(f"{BASE}/v1/drive-invites/{TOKEN}/meta").mock(
        return_value=httpx.Response(200, json={"owner_ss58": SS58, "path_prefix": "Work"})
    )
    meta = client.drives.invite_meta(_link_url())
    assert meta.path_prefix == "Work"
    assert route.called


@pytest.mark.anyio
@respx.mock
async def test_the_async_client_accepts_a_link_secret_invite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sealed: list[str] = []

    def fake_grant(member_master: str, member_ss58: str, folder_phrase: str) -> str:
        sealed.append(folder_phrase)
        return base64.b64encode(b"{}").decode()

    monkeypatch.setattr(_links, "accept_grant", fake_grant)
    identity = Identity.from_master(MASTER, "default", account_ss58=SS58)
    client = AsyncClient(token="tok", identity=identity, transport=AsyncTransport(BASE, "tok"))
    _meta, key_route = _mock_link_invite()
    respx.post(f"{BASE}/v1/drive-invites/{TOKEN}/accept").mock(return_value=_accepted())
    accepted = await client.drives.accept(_link_url(), MASTER, member_ss58=SS58)
    assert accepted.folder_mnemonic == _phrase()
    assert sealed == [_phrase()]
    proof = key_route.calls.last.request.headers["x-hcfs-link-proof"]
    assert proof == invite_link.fetch_proof(_link_secret())
    await client.aclose()


@respx.mock
def test_memberships_list_folder_grants_with_their_folder(
    client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_links, "_open_one_grant", lambda _m, _s, blob: blob or None)
    respx.get(f"{BASE}/v1/drive-memberships").mock(
        return_value=httpx.Response(
            200,
            json={
                "memberships": [{"owner_ss58": SS58, "folder_hash": FOLDER, "grant_blob": "drive"}],
                "folder_grants": [
                    {
                        "owner_ss58": SS58,
                        "folder_hash": "0123456789abcdef",
                        "path_prefix": "Clients/ACME",
                        "grant_blob": "folder",
                    }
                ],
            },
        )
    )
    rows = client.drives.memberships(MASTER, member_ss58=SS58)
    assert [(r.folder_mnemonic, r.path_prefix, r.role) for r in rows] == [
        ("drive", None, "writer"),
        ("folder", "Clients/ACME", "reader"),
    ]


@pytest.mark.anyio
@respx.mock
async def test_the_async_client_echoes_a_folder_invites_prefix(quick_grant: list[str]) -> None:
    identity = Identity.from_master(MASTER, "default", account_ss58=SS58)
    client = AsyncClient(token="tok", identity=identity, transport=AsyncTransport(BASE, "tok"))
    folder = invite_link.seal_envelope(_link_secret(), FILE_KEY, InviteLinkKind.FOLDER)
    _mock_link_invite(path_prefix="Work", kind="folder", envelope=folder)
    accept = respx.post(f"{BASE}/v1/drive-invites/{TOKEN}/accept").mock(
        return_value=_folder_accepted("Work")
    )
    accepted = await client.drives.accept(_link_url(), MASTER, member_ss58=SS58)
    assert accepted.path_prefix == "Work"
    assert json.loads(accept.calls.last.request.content)["path_prefix"] == "Work"
    assert quick_grant == [grant.phrase_from_entropy(FILE_KEY)]
    await client.aclose()
