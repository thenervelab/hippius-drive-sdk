import hashlib

import pytest

from hippius_drive.crypto import kdf

MASTER = " ".join(["abandon"] * 23 + ["art"])


def test_folder_mnemonic_matches_frozen_rust_vector() -> None:
    # hcfs-client/src/drive/keys.rs:130-148 (FROZEN 2026-08).
    folder = kdf.derive_folder_mnemonic(MASTER, "default")
    assert folder == (
        "brain morning wheel series benefit dumb retire winner method truck hollow "
        "scatter long local truly fancy yard cost diamond lawn wise rural echo fluid"
    )


def test_folder_entropy_matches_frozen_rust_vectors() -> None:
    # The label is hashed as a SUFFIX of the seed prefix; a second label pins that.
    assert kdf.folder_entropy(MASTER, "default").hex() == (
        "1af1ffe862015287edffdf8c3d25b3e0383d06ba5a97fec614f4bf0fc77b117a"
    )
    assert kdf.folder_entropy(MASTER, "photos").hex() == (
        "84c7627812a74d808f733e43ab8a811329d7e63ccbb3a6bd6d2312ff4cfb8df8"
    )


def test_folder_mnemonic_is_24_words() -> None:
    assert len(kdf.derive_folder_mnemonic(MASTER, "test").split()) == 24


def test_folder_hash_is_16_hex_of_sha256_label() -> None:
    assert kdf.folder_hash("default") == hashlib.sha256(b"default").hexdigest()[:16]
    assert kdf.folder_hash("default") == "37a8eec1ce19687d"
    assert len(kdf.folder_hash("any_label")) == 16


def test_key_from_12_word_vector() -> None:
    # hcfs-client/src/auth.rs:298-313 pins the VERIFYING key for this phrase
    # (asserted in tests/test_identity.py); the seed prefix below is the
    # published BIP-39 test-vector seed that keys.rs:122 cross-checks against.
    twelve = " ".join(["abandon"] * 11 + ["about"])
    keys = kdf.folder_keys(twelve)
    assert keys.signing_seed.hex() == (
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
    )
    assert keys.encryption_key == keys.signing_seed
    assert len(keys.signing_seed) == 32


def test_invalid_mnemonic_raises() -> None:
    with pytest.raises(ValueError):
        kdf.derive_folder_mnemonic("not a phrase", "x")
    with pytest.raises(ValueError):
        kdf.folder_keys("not a phrase")


def test_bad_checksum_raises() -> None:
    # All-abandon with the wrong last word is a valid wordlist but a bad checksum.
    with pytest.raises(ValueError):
        kdf.folder_keys(" ".join(["abandon"] * 12))


def test_generate_master_mnemonic_is_valid_and_24_words() -> None:
    phrase = kdf.generate_master_mnemonic()
    assert len(phrase.split()) == 24
    assert kdf.folder_keys(phrase).signing_seed != kdf.folder_keys(MASTER).signing_seed
