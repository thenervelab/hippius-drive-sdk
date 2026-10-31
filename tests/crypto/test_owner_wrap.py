"""Owner-wrap round trips. A folder wrap must not open as a raw file key."""

from __future__ import annotations

import pytest
from nacl import bindings

from hippius_drive.crypto import owner_wrap
from hippius_drive.crypto.owner_wrap import (
    folder_token_hash,
    open_file_secret,
    open_folder_secret,
    seal_file_secret,
    seal_folder_secret,
)
from hippius_drive.crypto.sharing import SHARE_WRAP_BLOB_LEN, ShareSecret
from hippius_drive.errors import DecryptError

MASTER = " ".join(["abandon"] * 23 + ["art"])
SS58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
OTHER = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
FILE_TOKEN = "abcdefghijabcdefghijab"
FOLDER_TOKEN = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
NONCE = bytes(range(24))
KEY = bytes(range(32))


def test_public_file_secret_round_trips() -> None:
    secret = ShareSecret(KEY)
    wrap = seal_file_secret(MASTER, SS58, FILE_TOKEN, secret, nonce=NONCE)
    assert open_file_secret(MASTER, SS58, FILE_TOKEN, wrap) == secret


def test_private_file_secret_stays_private() -> None:
    secret = ShareSecret(bytes(range(SHARE_WRAP_BLOB_LEN)), private=True)
    wrap = seal_file_secret(MASTER, SS58, FILE_TOKEN, secret, nonce=NONCE)
    opened = open_file_secret(MASTER, SS58, FILE_TOKEN, wrap)
    assert opened.private
    assert opened == secret


def test_folder_secret_round_trips_the_token() -> None:
    secret = ShareSecret(KEY)
    wrap = seal_folder_secret(MASTER, SS58, FOLDER_TOKEN, secret, nonce=NONCE)
    token, opened = open_folder_secret(MASTER, SS58, folder_token_hash(FOLDER_TOKEN), wrap)
    assert token == FOLDER_TOKEN
    assert opened == secret


def test_a_folder_wrap_does_not_open_as_a_file_key() -> None:
    secret = ShareSecret(KEY)
    wrap = seal_folder_secret(MASTER, SS58, FOLDER_TOKEN, secret, nonce=NONCE)
    with pytest.raises(DecryptError):
        open_file_secret(MASTER, SS58, folder_token_hash(FOLDER_TOKEN), wrap)


def test_wrong_address_fails_closed() -> None:
    secret = ShareSecret(KEY)
    wrap = seal_file_secret(MASTER, SS58, FILE_TOKEN, secret, nonce=NONCE)
    with pytest.raises(DecryptError):
        open_file_secret(MASTER, OTHER, FILE_TOKEN, wrap)


def test_token_hash_is_64_lowercase_hex() -> None:
    digest = folder_token_hash("some-token")
    assert len(digest) == 64
    assert digest == digest.lower()
    assert folder_token_hash("") != digest


# Frozen in hcfs ``client/share_wrap.rs`` (frozen_vector_folder_link and
# frozen_vector_folder_link_private). Inputs: abandon...art mnemonic, SS58,
# FOLDER_TOKEN, nonce 0x22 x 24, and link secret 0x11 x 32 or blob 0x33 x 89.
FROZEN_FOLDER_LINK_WRAP = (
    "012222222222222222222222222222222222222222222222226151162b6b8cd5"
    "cb35ec9a17e5d65208b81c63247cbea5bed41093336a91f80a7e4121d094030b"
    "c9dd2ed175cddf9baa2361676210b7f4e34c659feed9f8fcfde056e463b4fc88"
    "7db5c95beea63cf98a4dbbce951d4121c805d72881df"
)
FROZEN_FOLDER_LINK_PRIVATE_WRAP = (
    "012222222222222222222222222222222222222222222222226051162b6b8cd5"
    "cb35ec9a17e5d65208b81c63247cbea5bed41093336a91f80a7e4121d094030b"
    "c9dd2ed175cdfdb988014345403295d6c16e47bdccfbdadedfc274c64196deaa"
    "5f97eb79cc841c5f6ce9c179b37f7bdd6aa7356dfe0cbcedabcf305709643c1c"
    "579d073be2555a9013882b8b21a28c9a1019bc4afda1e80cb8f2aa63572635dd"
    "902cd3cb118c36216bb25565872128"
)
FROZEN_NONCE = bytes([0x22]) * 24


@pytest.mark.parametrize(
    ("secret", "frozen"),
    [
        (ShareSecret(bytes([0x11]) * 32, link_secret=True), FROZEN_FOLDER_LINK_WRAP),
        (
            ShareSecret(bytes([0x33]) * SHARE_WRAP_BLOB_LEN, private=True, link_secret=True),
            FROZEN_FOLDER_LINK_PRIVATE_WRAP,
        ),
    ],
)
def test_a_link_secret_wrap_matches_the_frozen_vector(secret: ShareSecret, frozen: str) -> None:
    wrap = seal_folder_secret(MASTER, SS58, FOLDER_TOKEN, secret, nonce=FROZEN_NONCE)
    assert wrap.hex() == frozen
    token, opened = open_folder_secret(MASTER, SS58, folder_token_hash(FOLDER_TOKEN), wrap)
    assert token == FOLDER_TOKEN
    assert opened == secret


def test_a_link_secret_cannot_be_sealed_as_a_file_share() -> None:
    with pytest.raises(ValueError, match="file share"):
        seal_file_secret(MASTER, SS58, FILE_TOKEN, ShareSecret(KEY, link_secret=True))


def test_the_link_flag_without_a_folder_token_does_not_open() -> None:
    # Hand-sealed plaintext no encoder produces: flags LINK_SECRET alone.
    key = owner_wrap._derive_key(MASTER)
    aad = SS58.encode() + b"\x00" + FILE_TOKEN.encode()
    sealed = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        bytes([0x04]) + KEY, aad, NONCE, key
    )
    with pytest.raises(DecryptError):
        open_file_secret(MASTER, SS58, FILE_TOKEN, bytes([1]) + NONCE + sealed)
