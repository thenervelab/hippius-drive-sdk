"""Grant and invite-link vectors copied from the console and desktop clients.

The passphrase and the frozen blob are the cross-client contract. A drift
here means a grant sealed by the console will not open in this SDK.
"""

from __future__ import annotations

import base64

import blake3
import pytest

from hippius_drive.crypto import kdf
from hippius_drive.crypto.grant import (
    entropy_from_phrase,
    grant_passphrase,
    invite_url,
    open_grant,
    open_invite_token,
    parse_invite_url,
    phrase_from_entropy,
    seal_invite_token,
)
from hippius_drive.errors import DecryptError

# The published BIP-39 12-word test vector. Not a wallet.
TWELVE = " ".join(["abandon"] * 11 + ["about"])
MEMBER = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
OTHER = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
PASSPHRASE = "dab4e54d8424eb9dc05396035ad64cea593542b8b6abf4f64d499e4e9a2a1fb6"
FRAGMENT = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
ALPHA = (
    "charge random negative trouble surprise sample suffer company unusual sound "
    "code rhythm prize much reveal link local morning clarify one cigar spare paddle hat"
)

# seal_grant(TWELVE, MEMBER, phrase(bytes(range(32)))) captured by desktop grant.rs.
FROZEN_GRANT_BLOB_HEX = (
    "7b2263697068657274657874223a222f6367384b77726f733441726d4b572b357846324e6d7543415970"
    "4d706543366b5338796766627651716339474e744b355158596e336f4149786c633945764f624d33547a"
    "4573645355563558463672556c7642516261676647325a6c70382b62694662534b52385550476469585a"
    "4a6a627a59446e45627836512b6b49514a6b57487971616e72745a474a744e7a74384258524142564e77"
    "755362754a6b7a4f6b4f56677034544d4b2b6b41535236396548695534716e785774486f466b57456163"
    "6f3278544247753736643264534d58742f74584e323755374b222c2273616c74223a22487a4d69397872"
    "43434c4879775034564d7154566a513d3d222c226e6f6e6365223a22784355725431546a4242597a7462"
    "646a74794e434454792f7058487a795a4d2b222c22616164223a224e55647964335a6852555931656c68"
    "694d6a5a47656a6c7959314677524664544e546444644556535348424f5a5768595131426a546d394952"
    "3074316446465a222c226b6466223a7b22616c676f726974686d223a226172676f6e326964222c226d65"
    "6d6f72795f6b6962223a3133313037322c2274696d655f636f7374223a332c22706172616c6c656c6973"
    "6d223a317d7d"
)


def test_grant_passphrase_is_pinned() -> None:
    assert grant_passphrase(TWELVE, MEMBER) == PASSPHRASE
    assert grant_passphrase(TWELVE, OTHER) != PASSPHRASE


def test_folder_mnemonic_for_the_twelve_word_vector_is_pinned() -> None:
    assert kdf.derive_folder_mnemonic(TWELVE, "alpha") == ALPHA


def test_invite_fragment_of_incrementing_bytes_is_pinned() -> None:
    entropy = bytes(range(32))
    url = invite_url("https://console.hippius.com/", "tok", entropy)
    assert url == f"https://console.hippius.com/invite/tok#k={FRAGMENT}"
    token, opened = parse_invite_url(url)
    assert token == "tok"
    assert opened == entropy
    assert phrase_from_entropy(bytes(32)) == " ".join(["abandon"] * 23 + ["art"])
    assert entropy_from_phrase(phrase_from_entropy(entropy)) == entropy


def test_frozen_grant_blob_opens_to_the_pinned_entropy() -> None:
    phrase = open_grant(TWELVE, MEMBER, bytes.fromhex(FROZEN_GRANT_BLOB_HEX))
    assert entropy_from_phrase(phrase) == bytes(range(32))


def test_wrong_member_does_not_open_the_frozen_grant() -> None:
    with pytest.raises(DecryptError):
        open_grant(TWELVE, OTHER, bytes.fromhex(FROZEN_GRANT_BLOB_HEX))


def test_invite_token_seal_round_trips_and_rejects_a_swapped_token() -> None:
    entropy = bytes(range(32))
    token = "invite-token"
    invite_id = blake3.blake3(token.encode()).hexdigest()
    sealed = seal_invite_token(entropy, invite_id, token, nonce=bytes(range(24)))
    assert open_invite_token(entropy, invite_id, sealed) == token
    wire = base64.b64encode(sealed)
    assert base64.b64decode(wire) == sealed
    other = blake3.blake3(b"other-token").hexdigest()
    with pytest.raises(DecryptError):
        open_invite_token(entropy, other, sealed)
