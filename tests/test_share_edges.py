"""Edges for share and drive helpers, and the async client methods."""

from __future__ import annotations

import base64
import io
import json
import unicodedata
from typing import cast

import blake3
import httpx
import pytest
import respx

from hippius_drive import _links
from hippius_drive._links import FileShareSpec, FolderShareSpec, InviteSpec
from hippius_drive._transport import AsyncTransport, Transport
from hippius_drive._upload import PlaintextSource
from hippius_drive._wire import build
from hippius_drive.client import AsyncClient, Client
from hippius_drive.crypto import file_cipher, kdf, sharing
from hippius_drive.crypto.grant import entropy_from_phrase, phrase_from_entropy
from hippius_drive.crypto.owner_wrap import open_file_secret, seal_file_secret
from hippius_drive.crypto.sharing import ShareSecret
from hippius_drive.errors import DecryptError, InvalidResponse, NotFound
from hippius_drive.identity import Identity
from hippius_drive.models import (
    Capabilities,
    DriveMembershipsWire,
    DriveMembershipWire,
    InviteMint,
    ShareTtl,
)

BASE = "https://example.test"
MASTER = " ".join(["abandon"] * 23 + ["art"])
SS58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
FOLDER = "37a8eec1ce19687d"
TOKEN = "inviteTok"


def _owner() -> Client:
    identity = Identity.from_master(MASTER, "default", account_ss58=SS58)
    return Client(token="tok", identity=identity, transport=Transport(BASE, "tok"))


def _async_owner() -> AsyncClient:
    identity = Identity.from_master(MASTER, "default", account_ss58=SS58)
    return AsyncClient(token="tok", identity=identity, transport=AsyncTransport(BASE, "tok"))


def _phrase() -> str:
    return kdf.derive_folder_mnemonic(MASTER, "default")


def test_rejected_share_inputs() -> None:
    source = PlaintextSource.from_bytes(b"x")
    with pytest.raises(ValueError, match="path segment"):
        _links.prepare_file_share(source, FileShareSpec("a/b"))
    with pytest.raises(ValueError, match="8"):
        _links.prepare_file_share(source, FileShareSpec("a.txt", password="short"))
    with pytest.raises(ValueError, match="ttl"):
        _links.wire_ttl("forever")
    assert _links.wire_ttl("7d") == "7d"
    assert _links.wire_ttl(ShareTtl.NEVER) == "never"
    identity = Identity.from_master(MASTER, "default", account_ss58=SS58)
    with pytest.raises(ValueError, match="display_name"):
        _links.folder_share_body(identity, FolderShareSpec("work", ""))
    with pytest.raises(ValueError, match="role"):
        _links.invite_body(identity, InviteSpec(_phrase(), role="guest"))
    spec = InviteSpec(_phrase(), expires_in_secs=60, max_uses=2)
    assert _links.invite_body(identity, spec)["max_uses"] == 2
    member = Identity.for_shared_drive(
        _phrase(), owner_ss58=SS58, folder_hash=FOLDER, role="manager"
    )
    assert _links.invite_body(member, InviteSpec(_phrase()))["owner_ss58"] == SS58
    assert _links.delegate_owner(member) == SS58
    assert _links.manager_owner(identity) is None
    with pytest.raises(ValueError, match="manager"):
        writer = Identity.for_shared_drive(
            _phrase(), owner_ss58=SS58, folder_hash=FOLDER, role="writer"
        )
        _links.manager_owner(writer)
    with pytest.raises(ValueError, match="account_ss58"):
        _links.wrap_account(member, None)
    assert _links.wrap_account(member, "explicit") == "explicit"
    with pytest.raises(ValueError, match="at least one"):
        _links.file_owner_wrap_entries(MASTER, SS58, [])
    secret = ShareSecret(bytes(32))
    with pytest.raises(ValueError, match="64"):
        _links.file_owner_wrap_entries(MASTER, SS58, [("t", secret)] * 65)
    minted = InviteMint(invite_token=TOKEN, invite_id="0" * 64)
    created, sealed = _links.finish_invite(minted, InviteSpec(_phrase()))
    assert sealed == ""
    assert created.invite_id == "0" * 64
    file_url = sharing.file_share_url("https://x.io", "tok", bytes(32))
    with pytest.raises(ValueError, match="folder"):
        _links.share_key_from_url(file_url, None, folder=True)
    with pytest.raises(DecryptError):
        _links.decode_share_filename("%%%", "%%%", bytes(32))
    with pytest.raises(ValueError, match="bytes"):
        _owner().shares.create(cast(bytes, 1), FileShareSpec("a.txt"))


def test_owner_wrap_and_grant_reject_bad_inputs() -> None:
    with pytest.raises(ValueError, match="nonce"):
        seal_file_secret(MASTER, SS58, "tok", ShareSecret(bytes(32)), nonce=b"short")
    wrap = seal_file_secret(MASTER, SS58, "tok", ShareSecret(bytes(32)), nonce=bytes(24))
    with pytest.raises(DecryptError):
        open_file_secret(MASTER, SS58, "tok", wrap[:10])
    with pytest.raises(ValueError):
        entropy_from_phrase("abandon abandon abandon about")
    with pytest.raises(ValueError, match="32"):
        phrase_from_entropy(b"short")
    assert not _links.folder_target_is_hash("abc")
    assert _links.folder_target_is_hash("ab" * 32)
    with pytest.raises(ValueError):
        _links.require_owner_wraps(Capabilities())
    _links.require_owner_wraps(Capabilities(share_owner_wrap=True))
    _links.require_member_folder_shares(Capabilities(member_folder_shares=True))
    with pytest.raises(DecryptError):
        page = DriveMembershipsWire(
            memberships=[
                DriveMembershipWire(
                    owner_ss58=SS58,
                    folder_hash=FOLDER,
                    grant_blob="%%%",
                )
            ]
        )
        _links.open_memberships(MASTER, SS58, page)
    with pytest.raises(_links.errors.InvalidResponse):
        _links._as_capabilities(object())


def _mount_management() -> None:
    respx.post(f"{BASE}/v1/shares").mock(
        return_value=httpx.Response(201, json={"share_token": "tok", "expires_at": "t"})
    )
    respx.get(f"{BASE}/v1/shares").mock(return_value=httpx.Response(200, json=[]))
    respx.delete(f"{BASE}/v1/shares/tok").mock(return_value=httpx.Response(204))
    respx.patch(f"{BASE}/v1/shares/tok").mock(
        return_value=httpx.Response(200, json={"share_token": "tok", "expires_at": None})
    )
    respx.get(f"{BASE}/v1/capabilities").mock(
        return_value=httpx.Response(
            200,
            json={"share_owner_wrap": True, "folder_share_revoke_by_hash": True},
        )
    )
    respx.put(f"{BASE}/v1/shares/owner-wraps").mock(
        return_value=httpx.Response(200, json={"applied": 1})
    )
    respx.post(f"{BASE}/v1/folder-shares").mock(
        return_value=httpx.Response(201, json={"share_token": "fold", "expires_at": None})
    )
    respx.get(f"{BASE}/v1/folder-shares").mock(return_value=httpx.Response(200, json=[]))
    respx.delete(f"{BASE}/v1/folder-shares/fold").mock(return_value=httpx.Response(204))
    respx.patch(f"{BASE}/v1/folder-shares/fold").mock(
        return_value=httpx.Response(200, json={"expires_at": None})
    )
    digest = "ab" * 32
    respx.delete(f"{BASE}/v1/folder-shares/by-hash/{digest}").mock(return_value=httpx.Response(204))
    respx.patch(f"{BASE}/v1/folder-shares/by-hash/{digest}").mock(
        return_value=httpx.Response(200, json={"expires_at": "later"})
    )
    respx.put(f"{BASE}/v1/folder-shares/owner-wraps").mock(
        return_value=httpx.Response(200, json={"applied": 1})
    )
    respx.get(url__regex=r".*/folder-shares/fold/browse").mock(
        return_value=httpx.Response(200, json={"files": [], "directories": [], "has_more": False})
    )
    invite_id = blake3.blake3(TOKEN.encode()).hexdigest()
    respx.post(f"{BASE}/v1/drive-invites").mock(
        return_value=httpx.Response(200, json={"invite_token": TOKEN, "invite_id": invite_id})
    )
    respx.put(url__regex=r".*/sealed-token$").mock(return_value=httpx.Response(200))
    respx.get(f"{BASE}/v1/drives/{FOLDER}/invites").mock(
        return_value=httpx.Response(200, json={"invites": [], "truncated": False})
    )
    respx.delete(f"{BASE}/v1/drives/{FOLDER}/invites/{invite_id}").mock(
        return_value=httpx.Response(204)
    )
    respx.get(f"{BASE}/v1/drives/{FOLDER}/members").mock(
        return_value=httpx.Response(200, json={"members": []})
    )
    respx.delete(f"{BASE}/v1/drives/{FOLDER}/members/other").mock(return_value=httpx.Response(204))
    respx.delete(f"{BASE}/v1/drives/{FOLDER}/members/{SS58}").mock(return_value=httpx.Response(204))
    respx.patch(f"{BASE}/v1/drives/{FOLDER}/members/other").mock(
        return_value=httpx.Response(200, json={"member_ss58": "other", "role": "reader"})
    )
    respx.get(f"{BASE}/v1/drive-invites/{TOKEN}/meta").mock(
        return_value=httpx.Response(
            200,
            json={
                "owner_ss58": SS58,
                "folder_hash": FOLDER,
                "display_label": "default",
                "expires_at": "t",
                "role": "writer",
                "valid": True,
            },
        )
    )


def _exercise(client: Client) -> None:
    created = client.shares.create(b"hi", FileShareSpec("a.txt", ttl="7d"))
    assert created.share_token == "tok"
    assert client.shares.list() == []
    assert client.shares.update_ttl("tok", ShareTtl.DAYS_30) is None
    client.shares.revoke("tok")
    secret = ShareSecret(bytes(32))
    applied = client.shares.put_owner_wraps(MASTER, [("tok", secret)])
    assert applied.applied == 1
    folder = client.folder_shares.create(FolderShareSpec("work", "Work", ttl=ShareTtl.DAYS_7))
    assert folder.share_token == "fold"
    assert client.folder_shares.list() == []
    client.folder_shares.revoke("fold")
    assert client.folder_shares.update_ttl("ab" * 32, "never") == "later"
    client.folder_shares.revoke("ab" * 32)
    client.folder_shares.put_owner_wraps(MASTER, [("foldtok", secret)])
    key = client.identity.encryption_key
    url = sharing.folder_share_url("https://console.hippius.com", "fold", key)
    blob = file_cipher.encrypt_bytes(b"doc", key)
    respx.get(url__regex=r".*/folder-shares/fold/blob").mock(
        return_value=httpx.Response(200, content=blob)
    )
    page = client.folder_shares.browse(url, "work")
    assert page.files == []
    assert client.folder_shares.get(url, "a.txt") == b"doc"
    invite = client.drives.create_invite(InviteSpec(_phrase(), role="reader"))
    assert invite.invite_token == TOKEN
    assert client.drives.invites().invites == []
    client.drives.revoke_invite(blake3.blake3(TOKEN.encode()).hexdigest())
    assert client.drives.members().members == []
    client.drives.remove_member("other")
    assert client.drives.change_role("other", "reader").role == "reader"
    assert client.drives.invite_meta(TOKEN).valid is True
    client.drives.leave(SS58)
    with pytest.raises(ValueError, match="role"):
        client.drives.change_role("other", "guest")


@respx.mock
def test_owner_management_routes() -> None:
    _mount_management()
    _exercise(_owner())


@respx.mock
@pytest.mark.anyio
async def test_async_owner_management_routes() -> None:
    _mount_management()
    client = _async_owner()
    created = await client.shares.create(b"hi", FileShareSpec("a.txt", ttl="7d"))
    assert created.share_token == "tok"
    assert await client.shares.list() == []
    assert await client.shares.update_ttl("tok", ShareTtl.DAYS_30) is None
    await client.shares.revoke("tok")
    secret = ShareSecret(bytes(32))
    applied = await client.shares.put_owner_wraps(MASTER, [("tok", secret)])
    assert applied.applied == 1
    folder = await client.folder_shares.create(FolderShareSpec("work", "Work"))
    assert folder.share_token == "fold"
    assert await client.folder_shares.list() == []
    await client.folder_shares.revoke("fold")
    assert await client.folder_shares.update_ttl("ab" * 32, "never") == "later"
    await client.folder_shares.revoke("ab" * 32)
    await client.folder_shares.put_owner_wraps(MASTER, [("foldtok", secret)])
    key = client.identity.encryption_key
    url = sharing.folder_share_url("https://console.hippius.com", "fold", key)
    blob = file_cipher.encrypt_bytes(b"doc", key)
    respx.get(url__regex=r".*/folder-shares/fold/blob").mock(
        return_value=httpx.Response(200, content=blob)
    )
    assert (await client.folder_shares.browse(url)).has_more is False
    assert await client.folder_shares.get(url, "a.txt") == b"doc"
    invite = await client.drives.create_invite(InviteSpec(_phrase()))
    assert invite.invite_token == TOKEN
    assert (await client.drives.invites()).truncated is False
    await client.drives.revoke_invite(blake3.blake3(TOKEN.encode()).hexdigest())
    assert (await client.drives.members()).members == []
    await client.drives.remove_member("other")
    changed = await client.drives.change_role("other", "reader")
    assert changed.role == "reader"
    assert (await client.drives.invite_meta(TOKEN)).folder_hash == FOLDER
    await client.drives.leave(SS58)
    key = bytes(range(32))
    filename_ct, filename_nonce = sharing.encrypt_filename("a.txt", key, nonce=bytes(24))
    blob = file_cipher.encrypt_bytes(b"hi", key)
    url = sharing.file_share_url("https://console.hippius.com", "opentok", key)
    respx.get(f"{BASE}/v1/shares/opentok/meta").mock(
        return_value=httpx.Response(
            200,
            json={
                "filename_ct": base64.b64encode(filename_ct).decode(),
                "filename_nonce": base64.b64encode(filename_nonce).decode(),
                "mime_type": "text/plain",
                "plaintext_size": 2,
                "ciphertext_size": len(blob),
                "expires_at": None,
            },
        )
    )
    respx.get(f"{BASE}/v1/shares/opentok/blob").mock(return_value=httpx.Response(200, content=blob))
    opened = await client.shares.open(url)
    assert opened.data == b"hi"
    assert opened.filename == "a.txt"
    await client.aclose()


@pytest.mark.anyio
async def test_async_capabilities_treat_404_as_disabled() -> None:
    async def missing(op: object) -> Capabilities:
        del op
        raise NotFound("not_found", "no", 404)

    disabled = await _links.capabilities_or_disabled_async(missing)
    assert disabled.shares is False

    async def present(op: object) -> Capabilities:
        del op
        return Capabilities(shares=True)

    assert (await _links.capabilities_or_disabled_async(present)).shares is True


@respx.mock
@pytest.mark.anyio
async def test_async_member_can_mint_and_update_by_token() -> None:
    member = Identity.for_shared_drive(
        _phrase(), owner_ss58=SS58, folder_hash=FOLDER, role="writer"
    )
    client = AsyncClient(token="member", identity=member, transport=AsyncTransport(BASE, "member"))
    respx.get(f"{BASE}/v1/capabilities").mock(
        return_value=httpx.Response(200, json={"member_folder_shares": True})
    )
    respx.post(f"{BASE}/v1/folder-shares").mock(
        return_value=httpx.Response(201, json={"share_token": "fold", "expires_at": None})
    )
    respx.patch(f"{BASE}/v1/folder-shares/fold").mock(
        return_value=httpx.Response(200, json={"expires_at": "soon"})
    )
    created = await client.folder_shares.create(FolderShareSpec("work", "Work"))
    assert created.share_token == "fold"
    assert await client.folder_shares.update_ttl("fold", "24h") == "soon"
    await client.aclose()


@respx.mock
def test_membership_round_trip_opens_the_frozen_grant() -> None:
    # One Argon2id seal and one open, both the production 128 MiB parameters.
    phrase = _phrase()
    identity = Identity.from_master(MASTER, "default", account_ss58=SS58)
    client = Client(token="tok", identity=identity, transport=Transport(BASE, "tok"))
    respx.post(url__regex=r".*/accept$").mock(
        return_value=httpx.Response(
            200,
            json={
                "owner_ss58": SS58,
                "folder_hash": FOLDER,
                "role": "writer",
                "already_owner": False,
            },
        )
    )
    entropy = kdf.folder_entropy(MASTER, "default")
    fragment = base64.urlsafe_b64encode(entropy).rstrip(b"=").decode()
    url = f"https://console.hippius.com/invite/joinme#k={fragment}"
    accepted = client.drives.accept(url, MASTER, member_ss58=SS58)
    assert accepted.folder_mnemonic == phrase
    assert accepted.owner_ss58 == SS58
    sent = json.loads(respx.calls.last.request.content)
    assert base64.b64decode(sent["grant_blob"])[:1] == b"{"

    sealed = base64.b64decode(sent["grant_blob"])
    respx.get(f"{BASE}/v1/drive-memberships").mock(
        return_value=httpx.Response(
            200,
            json={
                "memberships": [
                    {
                        "owner_ss58": SS58,
                        "folder_hash": FOLDER,
                        "role": "writer",
                        "grant_blob": base64.b64encode(sealed).decode(),
                        "display_label": "default",
                        "frozen": False,
                    },
                    {
                        "owner_ss58": "other",
                        "folder_hash": FOLDER,
                        "role": "reader",
                        "grant_blob": "",
                        "display_label": "empty",
                    },
                ]
            },
        )
    )
    rows = client.drives.memberships(MASTER, member_ss58=SS58)
    assert rows[0].folder_mnemonic == phrase
    assert rows[1].folder_mnemonic is None


def test_a_share_that_grows_past_a_full_frame_is_rejected() -> None:
    grown = b"x" * (file_cipher.CHUNK_SIZE + 50)
    source = PlaintextSource(open=lambda: io.BytesIO(grown), size=file_cipher.CHUNK_SIZE)
    with pytest.raises(ValueError, match="file grew"):
        _links.prepare_file_share(source, FileShareSpec("a.bin"))


def test_an_empty_share_that_gains_bytes_is_rejected() -> None:
    source = PlaintextSource(open=lambda: io.BytesIO(b"now"), size=0)
    with pytest.raises(ValueError, match="file grew"):
        _links.prepare_file_share(source, FileShareSpec("a.bin"))


def test_a_frame_aligned_share_that_did_not_grow_encrypts() -> None:
    payload = b"y" * file_cipher.CHUNK_SIZE
    source = PlaintextSource(open=lambda: io.BytesIO(payload), size=len(payload))
    prepared = _links.prepare_file_share(source, FileShareSpec("a.bin"))
    try:
        assert prepared.plaintext_size == len(payload)
        assert prepared.ciphertext_size == file_cipher.ciphertext_size(len(payload))
    finally:
        prepared.close()


@respx.mock
def test_folder_share_reads_send_nfc_and_refuse_traversal() -> None:
    client = _owner()
    nfd = "caf\u0301"
    nfc = unicodedata.normalize("NFC", nfd)
    key = client.identity.encryption_key
    url = sharing.folder_share_url("https://console.hippius.com", "fold", key)
    browse = respx.get(url__regex=r".*/folder-shares/fold/browse").mock(
        return_value=httpx.Response(200, json={"files": [], "directories": [], "has_more": False})
    )
    assert client.folder_shares.browse(url, nfd).files == []
    assert browse.calls.last.request.url.params["path"] == nfc
    blob = file_cipher.encrypt_bytes(b"z", key)
    download = respx.get(url__regex=r".*/folder-shares/fold/blob").mock(
        return_value=httpx.Response(200, content=blob)
    )
    assert client.folder_shares.get(url, nfd) == b"z"
    assert download.calls.last.request.url.params["path"] == nfc
    with pytest.raises(ValueError, match="relative_path"):
        client.folder_shares.browse(url, "a/../b")
    with pytest.raises(ValueError, match="relative_path"):
        client.folder_shares.get(url, "..")
    assert len(browse.calls) == 1
    assert len(download.calls) == 1


@respx.mock
def test_download_errors_and_a_path_source(tmp_path) -> None:
    client = _owner()
    local = tmp_path / "a.txt"
    local.write_bytes(b"z")
    respx.post(f"{BASE}/v1/shares").mock(
        return_value=httpx.Response(201, json={"share_token": "tok", "expires_at": None})
    )
    created = client.shares.create(local, FileShareSpec("a.txt"))
    assert created.share_token == "tok"
    respx.patch(f"{BASE}/v1/folder-shares/fold").mock(
        return_value=httpx.Response(200, json={"expires_at": "soon"})
    )
    respx.post(f"{BASE}/v1/folder-shares").mock(
        return_value=httpx.Response(201, json={"share_token": "fold", "expires_at": None})
    )
    client.folder_shares.create(FolderShareSpec("", "All"))
    assert client.folder_shares.update_ttl("fold", "24h") == "soon"
    key = bytes(32)
    url = sharing.file_share_url("https://console.hippius.com", "missing", key)
    respx.get(f"{BASE}/v1/shares/missing/meta").mock(
        return_value=httpx.Response(
            200,
            json={
                "filename_ct": "YQ==",
                "filename_nonce": "YQ==",
                "mime_type": "text/plain",
                "plaintext_size": 1,
                "ciphertext_size": 1,
            },
        )
    )
    respx.get(f"{BASE}/v1/shares/missing/blob").mock(
        return_value=httpx.Response(404, json={"error": "not_found", "message": "gone"})
    )
    with pytest.raises(NotFound):
        client.shares.open(url)
    respx.get(f"{BASE}/v1/shares/missing/blob").mock(
        return_value=httpx.Response(404, content=b"{", headers={"content-type": "application/json"})
    )
    with pytest.raises(NotFound):
        client.shares.open(url)
    respx.get(f"{BASE}/v1/shares/missing/blob").mock(
        return_value=httpx.Response(404, content=b"nope", headers={"content-type": "text/plain"})
    )
    with pytest.raises(NotFound):
        client.shares.open(url)
    respx.get(f"{BASE}/v1/shares").mock(return_value=httpx.Response(200, json={"nope": True}))
    with pytest.raises(InvalidResponse):
        client.shares.list()
    with pytest.raises(ValueError, match="segment"):
        client.shares.revoke("a/b")
    respx.get(f"{BASE}/v1/shares").mock(return_value=httpx.Response(200, json=[{"nope": True}]))
    with pytest.raises(InvalidResponse):
        client.shares.list()
    with pytest.raises(ValueError, match="hex"):
        build.revoke_folder_share_by_hash("not-a-hash")
    build.folder_share_meta("tok")
    respx.post(f"{BASE}/v1/drive-invites").mock(
        return_value=httpx.Response(200, json={"invite_token": TOKEN, "invite_id": "0" * 64})
    )
    created_invite = client.drives.create_invite(InviteSpec(_phrase()))
    assert created_invite.invite_id == "0" * 64
