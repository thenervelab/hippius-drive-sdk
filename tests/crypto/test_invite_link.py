"""Link-secret invite vectors, frozen in hcfs ``client/invite_link.rs``.

The console, desktop, and wasm clients are written against the same values.
A drift here means a ``#i=`` link minted by any of them will not open here.
"""

from __future__ import annotations

import base64

import pytest

from hippius_drive.crypto import grant
from hippius_drive.crypto.invite_link import (
    ENVELOPE_LEN,
    FragmentForm,
    InviteLinkKind,
    derive_link_secret,
    fetch_digest,
    fetch_key,
    fetch_proof,
    invite_id_for_token,
    open_envelope,
    parse_invite_link,
    seal_envelope,
    wrap_key,
)
from hippius_drive.errors import DecryptError

ENTROPY = bytes([0x11]) * 32
FILE_KEY = bytes([0x44]) * 32
NONCE = bytes([0x22]) * 24
TOKEN = "tok_abc"

FROZEN_INVITE_ID = "c85bcb38976678e46d304b41ef4088fb4709437d83a5d4bd115bdab25627ea57"
FROZEN_SECRET = "1f9f011892e2fca674aa6193f4bc026be0707a0815df003907b9577314807169"
FROZEN_FETCH_KEY = "cd05313893e36e1ea1c289f0651e23722ec5e5b68c1b27f279621be69214da31"
FROZEN_WRAP_KEY = "c799c84a8ed7d2a54d08be8e2b64d023a28931eef910fb7b555e9bbe480b6266"
FROZEN_FETCH_DIGEST = "45037018df624ba2d042e9b8793b98a0d35d5525702f022c81cd68dab84d7726"
FROZEN_DRIVE_ENVELOPE = (
    "01222222222222222222222222222222222222222222222222feb30a29458737"
    "9983a89aad51f0e944c9db6d16fc77b6a7bc7534cac0bbe7a0e33f8423bd841c"
    "b1af83f5887849a74e"
)
FROZEN_FOLDER_ENVELOPE = (
    "01222222222222222222222222222222222222222222222222abe65f7c10d262"
    "ccd6fdcff804a5bc119c8e3843a922e3f2e920619f95eeb2f55152b97ab101fb"
    "f0e061e592d1aa9c1f"
)


def _secret() -> bytes:
    return derive_link_secret(ENTROPY, invite_id_for_token(TOKEN))


def test_derivation_matches_the_frozen_vector() -> None:
    secret = _secret()
    assert invite_id_for_token(TOKEN).hex() == FROZEN_INVITE_ID
    assert secret.hex() == FROZEN_SECRET
    assert fetch_key(secret).hex() == FROZEN_FETCH_KEY
    assert wrap_key(secret).hex() == FROZEN_WRAP_KEY
    assert fetch_digest(secret).hex() == FROZEN_FETCH_DIGEST
    proof = base64.urlsafe_b64encode(bytes.fromhex(FROZEN_FETCH_KEY)).rstrip(b"=").decode()
    assert fetch_proof(secret) == proof


def test_the_secret_takes_the_raw_id_not_its_hex() -> None:
    with pytest.raises(ValueError, match="invite id must be 32 bytes"):
        derive_link_secret(ENTROPY, FROZEN_INVITE_ID.encode())


def test_envelopes_match_the_frozen_vectors() -> None:
    secret = _secret()
    drive = seal_envelope(secret, ENTROPY, InviteLinkKind.DRIVE, nonce=NONCE)
    folder = seal_envelope(secret, FILE_KEY, InviteLinkKind.FOLDER, nonce=NONCE)
    assert drive.hex() == FROZEN_DRIVE_ENVELOPE
    assert folder.hex() == FROZEN_FOLDER_ENVELOPE
    assert len(drive) == ENVELOPE_LEN
    assert open_envelope(secret, drive, InviteLinkKind.DRIVE) == ENTROPY
    assert open_envelope(secret, folder, InviteLinkKind.FOLDER) == FILE_KEY


def test_an_envelope_never_opens_as_the_other_kind() -> None:
    secret = _secret()
    drive = bytes.fromhex(FROZEN_DRIVE_ENVELOPE)
    folder = bytes.fromhex(FROZEN_FOLDER_ENVELOPE)
    with pytest.raises(DecryptError):
        open_envelope(secret, drive, InviteLinkKind.FOLDER)
    with pytest.raises(DecryptError):
        open_envelope(secret, folder, InviteLinkKind.DRIVE)


def test_a_wrong_secret_or_a_bad_shape_does_not_open() -> None:
    drive = bytes.fromhex(FROZEN_DRIVE_ENVELOPE)
    other = derive_link_secret(ENTROPY, invite_id_for_token("tok_other"))
    with pytest.raises(DecryptError, match="did not open"):
        open_envelope(other, drive, InviteLinkKind.DRIVE)
    with pytest.raises(DecryptError, match="malformed"):
        open_envelope(_secret(), drive[:-1], InviteLinkKind.DRIVE)
    with pytest.raises(DecryptError, match="malformed"):
        open_envelope(_secret(), b"\x02" + drive[1:], InviteLinkKind.DRIVE)


def test_a_random_nonce_still_round_trips() -> None:
    secret = _secret()
    first = seal_envelope(secret, ENTROPY, InviteLinkKind.DRIVE)
    second = seal_envelope(secret, ENTROPY, InviteLinkKind.DRIVE)
    assert first != second
    assert open_envelope(secret, first, InviteLinkKind.DRIVE) == ENTROPY


def test_seal_refuses_bad_lengths() -> None:
    with pytest.raises(ValueError, match="envelope key"):
        seal_envelope(_secret(), b"short", InviteLinkKind.DRIVE)
    with pytest.raises(ValueError, match="nonce"):
        seal_envelope(_secret(), ENTROPY, InviteLinkKind.DRIVE, nonce=b"short")
    with pytest.raises(ValueError, match="link secret"):
        fetch_key(b"short")


def test_parse_reads_both_fragment_forms() -> None:
    fragment = base64.urlsafe_b64encode(_secret()).rstrip(b"=").decode()
    link = parse_invite_link(f"https://console.hippius.com/invite/{TOKEN}#i={fragment}")
    assert (link.token, link.form, link.material) == (TOKEN, FragmentForm.LINK_SECRET, _secret())
    legacy = parse_invite_link(grant.invite_url("https://console.hippius.com", TOKEN, ENTROPY))
    assert (legacy.form, legacy.material) == (FragmentForm.LEGACY_KEY, ENTROPY)
    assert fragment not in repr(link)


def test_parse_refuses_anything_else() -> None:
    body = "A" * 43
    with pytest.raises(ValueError, match="#k= or #i="):
        parse_invite_link(f"https://x.io/invite/tok#s={body}")
    with pytest.raises(ValueError, match="32"):
        parse_invite_link("https://x.io/invite/tok#i=AAAA")
    with pytest.raises(ValueError, match="base64url"):
        parse_invite_link("https://x.io/invite/tok#i=A")


def test_parse_takes_only_canonical_unpadded_base64url() -> None:
    material = bytes([0xFB]) * 32
    canonical = base64.urlsafe_b64encode(material).rstrip(b"=").decode()
    assert "-" in canonical or "_" in canonical
    assert parse_invite_link(f"https://x.io/invite/tok#i={canonical}").material == material
    standard = base64.b64encode(material).rstrip(b"=").decode()
    for fragment in (f"{canonical}=", standard, canonical[:-1] + "B"):
        with pytest.raises(ValueError, match="unpadded base64url"):
            parse_invite_link(f"https://x.io/invite/tok#i={fragment}")


def test_the_legacy_parser_points_a_link_secret_elsewhere() -> None:
    fragment = base64.urlsafe_b64encode(_secret()).rstrip(b"=").decode()
    with pytest.raises(ValueError, match="#k="):
        grant.parse_invite_url(f"https://x.io/invite/{TOKEN}#i={fragment}")
