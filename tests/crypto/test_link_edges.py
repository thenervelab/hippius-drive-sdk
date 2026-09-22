"""Error branches in the share, wrap, and invite crypto."""

from __future__ import annotations

import base64
import json

import blake3
import pytest
from nacl import bindings

from hippius_drive import _links
from hippius_drive._links import FolderShareSpec
from hippius_drive.crypto import grant, kdf, owner_wrap, sharing
from hippius_drive.crypto.owner_wrap import _decode, _encode, _take_secret, _take_token
from hippius_drive.crypto.sharing import ShareSecret
from hippius_drive.errors import DecryptError
from hippius_drive.identity import Identity

MASTER = " ".join(["abandon"] * 23 + ["art"])
SS58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
KEY = bytes(32)


def test_share_helpers_reject_malformed_inputs() -> None:
    with pytest.raises(ValueError, match="32"):
        sharing.wrap_share_key("hunter22", b"short", salt=bytes(16), nonce=bytes(24))
    with pytest.raises(ValueError, match="salt"):
        sharing.wrap_share_key("hunter22", KEY, salt=b"short", nonce=bytes(24))
    with pytest.raises(ValueError, match="32"):
        sharing.encrypt_filename("a", b"short")
    with pytest.raises(ValueError, match="nonce"):
        sharing.encrypt_filename("a", KEY, nonce=b"short")
    with pytest.raises(DecryptError):
        sharing.decrypt_filename(b"short", bytes(24), KEY)
    with pytest.raises(ValueError, match="32"):
        sharing.file_share_url("https://x.io", "tok", b"short")
    sharing.folder_share_url_private("https://x.io", "tok", bytes(89))
    nonce = bytes(24)
    sealed = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(b"\xff", b"", nonce, KEY)
    with pytest.raises(DecryptError, match="UTF-8"):
        sharing.decrypt_filename(sealed, nonce, KEY)
    with pytest.raises(ValueError, match="89"):
        sharing.file_share_url_private("https://x.io", "tok", b"short")
    with pytest.raises(ValueError, match="segment"):
        sharing.file_share_url("https://x.io", "a/b", KEY)
    with pytest.raises(ValueError, match="https"):
        sharing.parse_share_url("http://x.io/share/tok#k=" + "A" * 43)
    with pytest.raises(ValueError, match="fragment"):
        sharing.parse_share_url("https://x.io/share/tok#nope")
    with pytest.raises(ValueError):
        ShareSecret(b"short", private=True)
    wrapped = bytes(89)
    wrapped = bytes([1]) + wrapped[1:]
    with pytest.raises(DecryptError):
        sharing.unwrap_share_key("hunter22", b"nope")
    random_name, nonce = sharing.encrypt_filename("a", KEY)
    assert sharing.decrypt_filename(random_name, nonce, KEY) == "a"
    wrapped = sharing.wrap_share_key("hunter22", KEY, salt=bytes(16), nonce=bytes(24))
    url = sharing.file_share_url_private("https://x.io", "tok", wrapped)
    token, opened = _links.share_key_from_url(url, "hunter22", folder=False)
    assert token == "tok"
    assert opened == KEY


def test_invite_and_grant_reject_malformed_inputs() -> None:
    with pytest.raises(ValueError, match="BIP-39"):
        grant.grant_passphrase("not a phrase", SS58)
    with pytest.raises(ValueError, match="32"):
        grant.invite_url("https://x.io", "tok", b"short")
    with pytest.raises(ValueError, match="https"):
        grant.invite_url("http://x.io", "tok", KEY)
    with pytest.raises(ValueError, match="segment"):
        grant.invite_url("https://x.io", "a/b", KEY)
    with pytest.raises(ValueError, match="https"):
        grant.parse_invite_url("http://x.io/invite/tok#k=" + "A" * 43)
    with pytest.raises(ValueError, match="path"):
        grant.parse_invite_url("https://x.io/share/tok#k=" + "A" * 43)
    with pytest.raises(ValueError, match="fragment"):
        grant.parse_invite_url("https://x.io/invite/tok")
    with pytest.raises(ValueError, match="32"):
        grant.parse_invite_url("https://x.io/invite/tok#k=****")
    with pytest.raises(ValueError, match="32"):
        grant.parse_invite_url("https://x.io/invite/tok#k=AAAA")
    with pytest.raises(ValueError, match="invite_id"):
        grant.seal_invite_token(KEY, "0" * 64, "tok")
    with pytest.raises(DecryptError):
        grant.open_invite_token(KEY, "0" * 64, b"not-json")
    with pytest.raises(DecryptError):
        grant.open_invite_token(KEY, "0" * 64, json.dumps({"v": 2}).encode())
    with pytest.raises(ValueError, match="nonce"):
        grant.seal_invite_token(KEY, grant_id("tok"), "tok", nonce=b"short")
    with pytest.raises(DecryptError):
        grant.open_grant(MASTER, SS58, b"not json")
    short_nonce = json.dumps(
        {
            "v": 1,
            "nonce": base64.b64encode(b"short").decode(),
            "ciphertext": base64.b64encode(b"x" * 16).decode(),
        }
    ).encode()
    with pytest.raises(DecryptError):
        grant.open_invite_token(KEY, grant_id("tok"), short_nonce)
    bad_tag = json.dumps(
        {
            "v": 1,
            "nonce": base64.b64encode(bytes(24)).decode(),
            "ciphertext": base64.b64encode(b"x" * 17).decode(),
        }
    ).encode()
    with pytest.raises(DecryptError):
        grant.open_invite_token(KEY, grant_id("tok"), bad_tag)
    with pytest.raises(ValueError, match="32"):
        grant.seal_invite_token(b"short", grant_id("tok"), "tok")


def grant_id(token: str) -> str:
    return blake3.blake3(token.encode()).hexdigest()


def test_owner_wrap_rejects_a_bad_plaintext() -> None:
    with pytest.raises(ValueError, match="mnemonic"):
        owner_wrap.seal_file_secret("nope", SS58, "tok", ShareSecret(KEY))
    with pytest.raises(ValueError, match="length"):
        _encode(ShareSecret(KEY), "x" * 65)
    file_wrap = owner_wrap.seal_file_secret(MASTER, SS58, "tok", ShareSecret(KEY))
    with pytest.raises(DecryptError, match="token"):
        owner_wrap.open_folder_secret(MASTER, SS58, "tok", file_wrap)
    with pytest.raises(DecryptError):
        _decode(b"")
    with pytest.raises(DecryptError):
        _decode(bytes([0x04, 0]))
    random = owner_wrap.seal_file_secret(MASTER, SS58, "tok", ShareSecret(KEY))
    assert len(random) > 16
    ident = Identity.from_master(MASTER, "default", account_ss58=SS58)
    with pytest.raises(ValueError, match="role"):
        Identity(ident.account_ss58, ident.label, ident.folder_hash, ident.keys, role="guest")
    with pytest.raises(ValueError, match="8"):
        _links.folder_share_body(ident, FolderShareSpec("work", "Name", password="short"))
    manager = Identity.for_shared_drive(
        kdf.derive_folder_mnemonic(MASTER, "default"),
        owner_ss58=SS58,
        folder_hash="ab" * 8,
        role="manager",
    )
    assert _links.manager_owner(manager) == SS58
    with pytest.raises(DecryptError):
        _take_token(b"")
    with pytest.raises(DecryptError):
        _take_token(bytes([0]))
    with pytest.raises(DecryptError):
        _take_token(bytes([1, 0xFF]))
    with pytest.raises(DecryptError):
        _take_secret(0, b"short")
