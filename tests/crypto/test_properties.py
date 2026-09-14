"""Property tests for the file cipher, path rules, and rename text."""

import unicodedata

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from hippius_drive.crypto import file_cipher as fc
from hippius_drive.crypto import hashes
from hippius_drive.identity import rename_text

KEY = bytes(range(32))

# A few chunks past the boundary is enough to exercise multi-frame framing
# without making every example a megabyte of entropy.
PLAINTEXT = st.binary(max_size=2 * fc.CHUNK_SIZE + 5)
SLOW = settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
FAST = settings(max_examples=200, deadline=None)


@SLOW
@given(PLAINTEXT)
def test_round_trip_and_size_formula(plaintext: bytes) -> None:
    blob = fc.encrypt_bytes(plaintext, KEY)
    assert fc.decrypt_bytes(blob, KEY) == plaintext
    assert len(blob) == fc.ciphertext_size(len(plaintext))


@SLOW
@given(PLAINTEXT, st.data())
def test_flipping_any_byte_after_the_header_is_detected(
    plaintext: bytes, data: st.DataObject
) -> None:
    blob = bytearray(fc.encrypt_bytes(plaintext, KEY))
    # The base nonce and chunk_count are authenticated only indirectly: a
    # flipped nonce byte changes every frame nonce, so every frame fails.
    index = data.draw(st.integers(min_value=0, max_value=len(blob) - 1))
    blob[index] ^= data.draw(st.integers(min_value=1, max_value=255))
    with pytest.raises(fc.DecryptError):
        fc.decrypt_bytes(bytes(blob), KEY)


@SLOW
@given(st.binary(min_size=1, max_size=fc.CHUNK_SIZE + 5), st.data())
def test_any_proper_prefix_is_rejected(plaintext: bytes, data: st.DataObject) -> None:
    blob = fc.encrypt_bytes(plaintext, KEY)
    cut = data.draw(st.integers(min_value=0, max_value=len(blob) - 1))
    with pytest.raises(fc.DecryptError):
        fc.decrypt_bytes(blob[:cut], KEY)


@SLOW
@given(PLAINTEXT, st.binary(min_size=1, max_size=8))
def test_any_suffix_is_rejected(plaintext: bytes, extra: bytes) -> None:
    blob = fc.encrypt_bytes(plaintext, KEY)
    with pytest.raises(fc.DecryptError):
        fc.decrypt_bytes(blob + extra, KEY)


@FAST
@given(st.binary(min_size=24, max_size=24), st.integers(min_value=0, max_value=2**64 - 1))
def test_chunk_nonce_keeps_the_high_bytes_and_is_reversible(base: bytes, index: int) -> None:
    derived = fc.chunk_nonce(base, index)
    assert len(derived) == fc.NONCE_LEN
    assert derived[8:] == base[8:]
    # XOR is an involution, so re-applying the same index restores the base.
    assert fc.chunk_nonce(derived, index) == base


@FAST
@given(st.integers(min_value=0, max_value=10 * fc.CHUNK_SIZE))
def test_chunk_count_brackets_the_size(size: int) -> None:
    frames = fc.chunk_count(size)
    assert frames >= 1
    assert (frames - 1) * fc.CHUNK_SIZE < max(size, 1) <= frames * fc.CHUNK_SIZE


# Segments that normalize_relative_path accepts: no separators, no dot-only
# segments, no NUL, and nothing that NFC folds away to nothing.
_SEGMENT = st.text(min_size=1, max_size=12).filter(
    lambda s: not any(c in s for c in "/\\\x00") and s not in (".", "..")
)


@FAST
@given(st.lists(_SEGMENT, min_size=1, max_size=4))
def test_normalize_relative_path_is_idempotent(segments: list[str]) -> None:
    path = "/".join(segments)
    assume(all(unicodedata.normalize("NFC", s) not in ("", ".", "..") for s in segments))
    once = hashes.normalize_relative_path(path)
    assert hashes.normalize_relative_path(once) == once
    assert hashes.path_hash(path) == hashes.path_hash(once)


@FAST
@given(st.lists(_SEGMENT, min_size=1, max_size=4))
def test_path_hash_ignores_unicode_composition(segments: list[str]) -> None:
    path = "/".join(segments)
    assume(all(unicodedata.normalize("NFC", s) not in ("", ".", "..") for s in segments))
    # Decomposition never introduces a separator, so the NFD form is still a
    # valid relative path and must land on the same file_id.
    assert hashes.path_hash(unicodedata.normalize("NFD", path)) == hashes.path_hash(path)


_HASH = st.binary(min_size=32, max_size=32)


@FAST
@given(st.lists(st.tuples(_HASH, _HASH), min_size=1, max_size=6, unique_by=lambda p: p[0]))
def test_rename_text_is_invariant_under_permutation(pairs: list[tuple[bytes, bytes]]) -> None:
    assert rename_text(pairs) == rename_text(sorted(pairs, key=lambda p: p[1]))
    assert rename_text(pairs) == rename_text(list(reversed(pairs)))


@FAST
@given(st.lists(st.tuples(_HASH, _HASH), min_size=1, max_size=6, unique_by=lambda p: p[0]))
def test_rename_text_lists_pairs_in_old_hash_order(pairs: list[tuple[bytes, bytes]]) -> None:
    body = rename_text(pairs).rsplit(": ", 1)[1]
    olds = [entry.split(":")[0] for entry in body.split(",")]
    assert olds == sorted(olds)
