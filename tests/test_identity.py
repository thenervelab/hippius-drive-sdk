import pytest
from nacl.signing import VerifyKey

from hippius_drive.identity import Identity, rename_text, tos_text

MASTER = " ".join(["abandon"] * 23 + ["art"])
TWELVE = " ".join(["abandon"] * 11 + ["about"])
SS58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"


def test_from_master_derives_folder_and_hash() -> None:
    ident = Identity.from_master(MASTER, "default", account_ss58=SS58)
    assert ident.folder_hash == "37a8eec1ce19687d"  # hex(SHA256("default"))[:16]
    assert ident.account_ss58 == SS58
    assert ident.label == "default"


def test_verifying_key_matches_the_frozen_rust_vector() -> None:
    # hcfs-client/src/auth.rs:298-313 pins this key for the 12-word phrase.
    ident = Identity.from_folder_mnemonic(TWELVE, "default", account_ss58=SS58)
    assert ident.verifying_key.hex() == (
        "c5785e1865b708938aff8161d573006496663b1aa10834e396dc566869a2c66a"
    )


def test_signature_verifies_over_tos_text() -> None:
    ident = Identity.from_master(MASTER, "default", account_ss58=SS58)
    sig = ident.sign_ciphertext_hash("ab" * 32)
    VerifyKey(ident.verifying_key).verify(tos_text("ab" * 32).encode(), sig)
    assert len(sig) == 64


def test_signing_is_deterministic() -> None:
    ident = Identity.from_master(MASTER, "default", account_ss58=SS58)
    assert ident.sign(b"m") == ident.sign(b"m")


def test_tos_text_is_byte_exact() -> None:
    # hcfs-shared/src/network.rs Manifest::generate_text.
    assert tos_text("X") == (
        "I here by declare that the file with hash X that i am uploading is in par "
        "with the ToS of the provider"
    )


def test_rename_text_sorts_by_old_hash_and_is_byte_exact() -> None:
    low, high = bytes([0x01] * 32), bytes([0xFF] * 32)
    new_a, new_b = bytes([0x02] * 32), bytes([0x03] * 32)
    text = rename_text([(high, new_b), (low, new_a)])
    assert text == (
        "I hereby declare that I am renaming the following files on HCFS with the "
        "understanding that I have read and agree to the Terms of Service: "
        f"{low.hex()}:{new_a.hex()},{high.hex()}:{new_b.hex()}"
    )


def test_rename_text_is_invariant_under_input_order() -> None:
    pairs = [(bytes([i] * 32), bytes([i + 1] * 32)) for i in (5, 2, 9)]
    assert rename_text(pairs) == rename_text(list(reversed(pairs)))


def test_encryption_key_is_the_signing_seed() -> None:
    ident = Identity.from_master(MASTER, "default", account_ss58=SS58)
    assert ident.encryption_key == ident.keys.signing_seed
    assert len(ident.encryption_key) == 32


def test_repr_does_not_leak_key_material() -> None:
    ident = Identity.from_master(MASTER, "default", account_ss58=SS58)
    assert ident.keys.signing_seed.hex() not in repr(ident)
    assert ident.keys.signing_seed.hex() not in repr(ident.keys)


def test_empty_account_ss58_is_rejected() -> None:
    with pytest.raises(ValueError):
        Identity.from_master(MASTER, "default", account_ss58="")
