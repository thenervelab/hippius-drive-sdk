"""Known-answer tests for share URLs, filename AEAD, and the password wrap.

URL shapes are copied from hcfs-client ``client/share.rs`` and
``client/folder_share.rs``. A password link must never be rebuildable as ``#k=``.
"""

from __future__ import annotations

import pytest

from hippius_drive.crypto.sharing import (
    PASSWORD_MIN_LEN,
    SHARE_WRAP_BLOB_LEN,
    ShareSecret,
    decrypt_filename,
    encrypt_filename,
    file_share_url,
    file_share_url_private,
    folder_share_url,
    parse_share_url,
    share_url,
    unwrap_share_key,
    wrap_share_key,
)
from hippius_drive.errors import DecryptError

ZEROS = bytes(32)
KEY_B64 = "A" * 43
SALT = bytes(range(16))
NONCE = bytes(range(24))


def test_public_file_url_strips_a_trailing_slash_and_pins_the_zero_key() -> None:
    url = file_share_url("https://x.io/", "tok", ZEROS)
    assert url == f"https://x.io/share/tok#k={KEY_B64}"
    again = file_share_url("https://console.example.com", "abc123", ZEROS)
    assert again.startswith("https://console.example.com/share/abc123#k=")


def test_public_folder_url_uses_the_folder_path() -> None:
    url = folder_share_url("https://x.io", "tok", ZEROS)
    assert url == f"https://x.io/share/folder/tok#k={KEY_B64}"


def test_parse_share_url_round_trips_both_kinds() -> None:
    file_url = file_share_url("https://x.io", "tok", ZEROS)
    folder_url = folder_share_url("https://x.io", "tok", ZEROS)
    parsed_file = parse_share_url(file_url)
    parsed_folder = parse_share_url(folder_url)
    assert parsed_file.token == "tok" and not parsed_file.folder
    assert parsed_file.secret.material == ZEROS and not parsed_file.secret.private
    assert parsed_folder.folder and parsed_folder.secret.material == ZEROS


def test_password_url_never_contains_a_raw_key_fragment() -> None:
    wrapped = wrap_share_key("hunter22", ZEROS, salt=SALT, nonce=NONCE)
    assert len(wrapped) == SHARE_WRAP_BLOB_LEN
    url = file_share_url_private("https://x.io/", "tok", wrapped)
    assert url.startswith("https://x.io/share/tok#p=")
    assert "#k=" not in url
    secret = ShareSecret(wrapped, private=True)
    rebuilt = share_url("https://x.io", "tok", secret, folder=False)
    assert rebuilt == url
    assert unwrap_share_key("hunter22", wrapped) == ZEROS


def test_a_private_secret_cannot_be_parsed_back_into_a_raw_key() -> None:
    wrapped = wrap_share_key("hunter22", ZEROS, salt=SALT, nonce=NONCE)
    parsed = parse_share_url(file_share_url_private("https://x.io", "tok", wrapped))
    assert parsed.secret.private
    assert parsed.secret.material != ZEROS


def test_short_password_is_rejected_before_argon2() -> None:
    with pytest.raises(ValueError, match=str(PASSWORD_MIN_LEN)):
        wrap_share_key("short", ZEROS)
    eight_chars = "é" * PASSWORD_MIN_LEN
    blob = wrap_share_key(eight_chars, ZEROS, salt=SALT, nonce=NONCE)
    assert unwrap_share_key(eight_chars, blob) == ZEROS


def test_wrong_password_and_a_tampered_blob_fail_closed() -> None:
    wrapped = bytearray(wrap_share_key("hunter22", ZEROS, salt=SALT, nonce=NONCE))
    with pytest.raises(DecryptError):
        unwrap_share_key("hunter23", bytes(wrapped))
    wrapped[-1] ^= 0x01
    with pytest.raises(DecryptError):
        unwrap_share_key("hunter22", bytes(wrapped))


def test_filename_round_trips_and_a_bad_tag_fails() -> None:
    ciphertext, nonce = encrypt_filename("report.pdf", ZEROS, nonce=NONCE)
    assert decrypt_filename(ciphertext, nonce, ZEROS) == "report.pdf"
    damaged = bytearray(ciphertext)
    damaged[-1] ^= 0x01
    with pytest.raises(DecryptError):
        decrypt_filename(bytes(damaged), nonce, ZEROS)


def test_share_secret_repr_hides_the_key() -> None:
    secret = ShareSecret(ZEROS)
    assert ZEROS.hex() not in repr(secret)


def test_malformed_urls_are_rejected() -> None:
    with pytest.raises(ValueError):
        file_share_url("http://x.io", "tok", ZEROS)
    with pytest.raises(ValueError):
        parse_share_url("https://x.io/share/tok")
    with pytest.raises(ValueError):
        parse_share_url("https://x.io/other/tok#k=" + KEY_B64)
    with pytest.raises(ValueError):
        ShareSecret(b"short")
