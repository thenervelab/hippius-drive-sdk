"""Link-secret folder-link vectors, frozen in hcfs ``client/folder_link.rs``.

hcfs-client, its wasm build (the console) and the desktop all mint and open
``#s=`` links with those functions. A drift here means a link minted by the
SDK will not open in the console, or the reverse.
"""

from __future__ import annotations

import base64

import pytest
from hypothesis import given
from hypothesis import strategies as st

from hippius_drive.crypto import sharing
from hippius_drive.crypto.folder_link import (
    ENVELOPE_AAD,
    ENVELOPE_LEN,
    fetch_digest,
    fetch_key,
    fetch_proof,
    generate_link_secret,
    open_envelope,
    seal_envelope,
    wrap_key,
)
from hippius_drive.errors import DecryptError

SECRET = bytes([0x11]) * 32
FILE_KEY = bytes([0x44]) * 32
NONCE = bytes([0x22]) * 24

FROZEN_FETCH_KEY = "27fd2cac4824591f7910c80f20258577825a1ab6774ad2b0fca919c4cf37d8fc"
FROZEN_WRAP_KEY = "31c38962de63b6788db33961750babcd0065bbc07d1e0f1274ca680f383117b5"
FROZEN_FETCH_DIGEST = "3e6cc2f3ce785d0372c6d3d5d420c5e2f11fea905fa88a46fc7ea964c6e2a7fc"
FROZEN_ENVELOPE = (
    "012222222222222222222222222222222222222222222222229a02691d845825"
    "0517872835c8c89f58c33785251e97b53ace4b6365c440c6493a2f9dd3b5dfba"
    "2186f452b628fb0d2f"
)


def test_derived_keys_match_the_frozen_vector() -> None:
    assert fetch_key(SECRET).hex() == FROZEN_FETCH_KEY
    assert wrap_key(SECRET).hex() == FROZEN_WRAP_KEY
    assert fetch_digest(SECRET).hex() == FROZEN_FETCH_DIGEST
    proof = base64.urlsafe_b64encode(bytes.fromhex(FROZEN_FETCH_KEY)).rstrip(b"=").decode()
    assert fetch_proof(SECRET) == proof


def test_envelope_matches_the_frozen_vector() -> None:
    envelope = seal_envelope(SECRET, FILE_KEY, nonce=NONCE)
    assert envelope.hex() == FROZEN_ENVELOPE
    assert open_envelope(SECRET, bytes.fromhex(FROZEN_ENVELOPE)) == FILE_KEY


def test_the_aad_ends_with_the_envelope_version_byte() -> None:
    assert ENVELOPE_AAD.removesuffix(bytes([1])) == b"hippius.hcfs.folder-link-envelope.v1"
    assert ENVELOPE_AAD.endswith(bytes([1]))


def test_a_fresh_seal_round_trips_and_never_contains_the_key() -> None:
    secret = generate_link_secret()
    envelope = seal_envelope(secret, FILE_KEY)
    assert len(envelope) == ENVELOPE_LEN
    assert FILE_KEY not in envelope
    assert open_envelope(secret, envelope) == FILE_KEY
    assert seal_envelope(secret, FILE_KEY) != envelope, "a fresh nonce per seal"
    assert generate_link_secret() != secret


def test_a_wrong_secret_does_not_open() -> None:
    envelope = seal_envelope(SECRET, FILE_KEY, nonce=NONCE)
    with pytest.raises(DecryptError):
        open_envelope(bytes([0x12]) * 32, envelope)


@pytest.mark.parametrize("index", [0, 1, 24, 25, 56, 57, ENVELOPE_LEN - 1])
def test_a_flipped_byte_anywhere_fails(index: int) -> None:
    tampered = bytearray(seal_envelope(SECRET, FILE_KEY, nonce=NONCE))
    tampered[index] ^= 0x01
    with pytest.raises(DecryptError):
        open_envelope(SECRET, bytes(tampered))


def test_wrong_lengths_fail() -> None:
    envelope = seal_envelope(SECRET, FILE_KEY, nonce=NONCE)
    for bad in (envelope[:-1], envelope + b"\x00", b"", FILE_KEY):
        with pytest.raises(DecryptError):
            open_envelope(SECRET, bad)
    with pytest.raises(ValueError, match="link secret"):
        fetch_key(bytes(31))
    with pytest.raises(ValueError, match="file key"):
        seal_envelope(SECRET, bytes(33))
    with pytest.raises(ValueError, match="nonce"):
        seal_envelope(SECRET, FILE_KEY, nonce=bytes(23))


@given(secret=st.binary(min_size=32, max_size=32), key=st.binary(min_size=32, max_size=32))
def test_any_secret_and_key_round_trip(secret: bytes, key: bytes) -> None:
    assert open_envelope(secret, seal_envelope(secret, key)) == key


@pytest.mark.parametrize(
    ("private", "prefix"),
    [(False, "#s="), (True, "#sp=")],
)
def test_link_secret_urls_round_trip_through_the_parser(private: bool, prefix: str) -> None:
    material = bytes(range(89)) if private else SECRET
    secret = sharing.ShareSecret(material, private=private, link_secret=True)
    url = sharing.share_url("https://console.hippius.com", "fold", secret, folder=True)
    assert url.startswith(f"https://console.hippius.com/share/folder/fold{prefix}")
    parsed = sharing.parse_share_url(url)
    assert parsed.folder
    assert parsed.token == "fold"
    assert parsed.secret == secret


def test_a_link_secret_never_builds_or_parses_as_a_file_share() -> None:
    secret = sharing.ShareSecret(SECRET, link_secret=True)
    with pytest.raises(ValueError, match="file-share"):
        sharing.share_url("https://console.hippius.com", "tok", secret, folder=False)
    with pytest.raises(ValueError, match="#k= or #p="):
        sharing.parse_share_url("https://console.hippius.com/share/tok#s=" + "A" * 43)
    with pytest.raises(ValueError, match="32 bytes"):
        sharing.parse_share_url("https://console.hippius.com/share/folder/tok#s=AAAA")
