import unicodedata

import blake3
import pytest

from hippius_drive.crypto import hashes


def test_path_hash_is_blake3_of_nfc_utf8() -> None:
    nfd = unicodedata.normalize("NFD", "docs/Résumé.pdf")
    nfc = unicodedata.normalize("NFC", "docs/Résumé.pdf")
    assert nfd != nfc
    assert hashes.path_hash(nfd) == hashes.path_hash(nfc)
    assert hashes.path_hash(nfc) == blake3.blake3(nfc.encode()).digest()
    assert len(hashes.path_hash("a.txt")) == 32


def test_salted_hash_prefixes_the_account() -> None:
    expected = blake3.blake3(b"5Grw" + b"hello").digest()
    assert hashes.salted_hash("5Grw", b"hello") == expected


def test_salted_hasher_streams_to_the_same_digest() -> None:
    hasher = hashes.salted_hasher("5Grw")
    hasher.update(b"hel")
    hasher.update(b"lo")
    assert hasher.digest() == hashes.salted_hash("5Grw", b"hello")


def test_blake3_hex_matches_digest() -> None:
    assert hashes.blake3_hex(b"hello") == blake3.blake3(b"hello").hexdigest()


@pytest.mark.parametrize("bad", ["../x", "a/../b", "a\\b", "/abs", "", "a//b", "a/./b", "."])
def test_relative_path_rejects_traversal_and_backslash(bad: str) -> None:
    with pytest.raises(ValueError):
        hashes.normalize_relative_path(bad)


def test_relative_path_normalizes_to_nfc() -> None:
    nfd = unicodedata.normalize("NFD", "docs/Résumé.pdf")
    assert hashes.normalize_relative_path(nfd) == unicodedata.normalize("NFC", nfd)
