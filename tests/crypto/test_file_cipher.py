import io
import os

import pytest

from hippius_drive.crypto import file_cipher as fc

KEY = bytes(range(32))
NONCE = bytes(range(24))


def test_layout_of_empty_plaintext() -> None:
    blob = fc.encrypt_bytes(b"", KEY, base_nonce=NONCE)
    assert blob[:24] == NONCE
    assert int.from_bytes(blob[24:28], "little") == 1
    assert int.from_bytes(blob[28:32], "little") == 16
    assert len(blob) == 24 + 4 + 4 + 16
    assert fc.decrypt_bytes(blob, KEY) == b""


def test_chunk_nonce_xors_low_8_bytes_little_endian() -> None:
    n = fc.chunk_nonce(NONCE, 0x0102)
    assert n[8:] == NONCE[8:]
    index = (0x0102).to_bytes(8, "little")
    assert n[:8] == bytes(a ^ b for a, b in zip(NONCE[:8], index, strict=True))


def test_chunk_nonce_is_identity_at_index_zero() -> None:
    assert fc.chunk_nonce(NONCE, 0) == NONCE


@pytest.mark.parametrize(
    "size",
    [0, 1, 5, fc.CHUNK_SIZE - 1, fc.CHUNK_SIZE, fc.CHUNK_SIZE + 1, 3 * fc.CHUNK_SIZE],
)
def test_round_trip(size: int) -> None:
    pt = os.urandom(size)
    blob = fc.encrypt_bytes(pt, KEY)
    assert fc.decrypt_bytes(blob, KEY) == pt
    assert len(blob) == fc.ciphertext_size(size)


def test_chunk_count_never_zero() -> None:
    assert fc.chunk_count(0) == 1
    assert fc.chunk_count(1) == 1
    assert fc.chunk_count(fc.CHUNK_SIZE) == 1
    assert fc.chunk_count(fc.CHUNK_SIZE + 1) == 2


def test_ciphertext_size_matches_the_rust_estimate() -> None:
    # hcfs-client/src/drive/upload.rs:589-596.
    assert fc.ciphertext_size(0) == 28 + 4 + 16
    assert fc.ciphertext_size(5) == 28 + 20 + 5
    assert fc.ciphertext_size(3 * fc.CHUNK_SIZE) == 28 + 3 * 20 + 3 * fc.CHUNK_SIZE


def test_tamper_is_detected() -> None:
    blob = bytearray(fc.encrypt_bytes(b"hello", KEY))
    blob[-1] ^= 0xFF
    with pytest.raises(fc.DecryptError):
        fc.decrypt_bytes(bytes(blob), KEY)


def test_truncated_frame_is_rejected() -> None:
    blob = fc.encrypt_bytes(b"hello", KEY)
    with pytest.raises(fc.DecryptError):
        fc.decrypt_bytes(blob[:-3], KEY)


def test_trailing_bytes_are_rejected() -> None:
    blob = fc.encrypt_bytes(b"hello", KEY)
    with pytest.raises(fc.DecryptError):
        fc.decrypt_bytes(blob + b"\x00", KEY)


def test_zero_chunk_count_is_rejected() -> None:
    blob = fc.encrypt_bytes(b"hello", KEY)
    forged = blob[:24] + (0).to_bytes(4, "little") + blob[28:]
    with pytest.raises(fc.DecryptError):
        fc.decrypt_bytes(forged, KEY)


def test_oversize_frame_length_is_rejected_before_reading() -> None:
    blob = fc.encrypt_bytes(b"hello", KEY)
    forged = blob[:28] + (fc.MAX_FRAME_LEN + 1).to_bytes(4, "little") + blob[32:]
    with pytest.raises(fc.DecryptError):
        fc.decrypt_bytes(forged, KEY)


def test_frame_shorter_than_the_tag_is_rejected() -> None:
    blob = fc.encrypt_bytes(b"hello", KEY)
    forged = blob[:28] + (15).to_bytes(4, "little") + blob[32:]
    with pytest.raises(fc.DecryptError):
        fc.decrypt_bytes(forged, KEY)


def test_encrypt_stream_rejects_a_size_that_disagrees_with_the_reader() -> None:
    with pytest.raises(ValueError):
        b"".join(fc.encrypt_stream(io.BytesIO(b"ab"), KEY, plaintext_size=fc.CHUNK_SIZE + 1))


def test_encrypt_stream_rejects_a_short_nonce() -> None:
    with pytest.raises(ValueError):
        b"".join(fc.encrypt_stream(io.BytesIO(b"ab"), KEY, 2, base_nonce=b"\x00" * 23))


def test_random_nonce_is_used_when_none_is_given() -> None:
    first = fc.encrypt_bytes(b"hello", KEY)
    second = fc.encrypt_bytes(b"hello", KEY)
    assert first[:24] != second[:24]
    assert fc.decrypt_bytes(second, KEY) == b"hello"


def test_streaming_round_trip_over_a_file(tmp_path: object) -> None:
    pt = os.urandom(fc.CHUNK_SIZE * 2 + 17)
    blob = b"".join(fc.encrypt_stream(io.BytesIO(pt), KEY, len(pt)))
    chunks = list(fc.decrypt_stream(io.BytesIO(blob), KEY))
    assert b"".join(chunks) == pt
    assert len(chunks) == 3
