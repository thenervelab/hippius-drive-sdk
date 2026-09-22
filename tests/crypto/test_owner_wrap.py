"""Owner-wrap round trips. A folder wrap must not open as a raw file key."""

from __future__ import annotations

import pytest

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
