"""HCFS framed XChaCha20-Poly1305 file format (hcfs-client ``crypto.rs``).

Layout::

    [base_nonce 24][chunk_count u32 LE] then per chunk [len u32 LE][ct][tag 16]

``len`` includes the 16-byte Poly1305 tag. Each chunk uses
``chunk_nonce(base, index)``, so one stored nonce covers the whole file. A
zero-byte file is one empty frame, not zero frames.

Both directions are generators so a multi-gigabyte file never has to be
resident: the upload path streams frames into the request body and the
download path writes plaintext out frame by frame, authenticating each one
before it yields.
"""

from __future__ import annotations

import io
import os
from collections.abc import Iterator
from typing import BinaryIO

from nacl import bindings
from nacl.exceptions import CryptoError

CHUNK_SIZE = 256 * 1024
"""Plaintext bytes per frame. Fixed by the wire format; never tune it."""

TAG_LEN = 16
NONCE_LEN = 24
HEADER_LEN = NONCE_LEN + 4
FRAME_HEADER_LEN = 4
MAX_FRAME_LEN = CHUNK_SIZE + TAG_LEN


class DecryptError(ValueError):
    """Ciphertext is malformed, truncated, or fails authentication."""


def chunk_nonce(base_nonce: bytes, index: int) -> bytes:
    """XOR the u64 little-endian chunk index into the first 8 nonce bytes.

    Args:
        base_nonce: The 24-byte nonce stored in the blob header.
        index: Zero-based frame index.

    Returns:
        The 24-byte nonce for that frame.
    """
    idx = index.to_bytes(8, "little")
    head = bytes(a ^ b for a, b in zip(base_nonce[:8], idx, strict=True))
    return head + base_nonce[8:]


def chunk_count(plaintext_size: int) -> int:
    """Return the number of frames for ``plaintext_size`` bytes; never zero.

    Args:
        plaintext_size: Size of the plaintext in bytes.

    Returns:
        The frame count, at least 1.
    """
    return max(1, -(-plaintext_size // CHUNK_SIZE))


def ciphertext_size(plaintext_size: int) -> int:
    """Return the exact blob length for ``plaintext_size`` bytes.

    Upload sessions declare this up front, so it must be exact rather than an
    upper bound.

    Args:
        plaintext_size: Size of the plaintext in bytes.

    Returns:
        The length of the encrypted blob in bytes.
    """
    frames = chunk_count(plaintext_size)
    return HEADER_LEN + frames * (FRAME_HEADER_LEN + TAG_LEN) + plaintext_size


def _read_upto(reader: BinaryIO, size: int) -> bytes:
    """Read up to ``size`` bytes, looping over short reads until EOF."""
    parts: list[bytes] = []
    remaining = size
    while remaining > 0:
        block = reader.read(remaining)
        if not block:
            break
        parts.append(block)
        remaining -= len(block)
    return b"".join(parts)


def encrypt_stream(
    reader: BinaryIO,
    key: bytes,
    plaintext_size: int,
    base_nonce: bytes | None = None,
) -> Iterator[bytes]:
    """Yield the blob in wire order: header first, then one framed chunk at a time.

    ``plaintext_size`` fixes ``chunk_count`` before any plaintext is read, which
    is what lets the header go out ahead of the body. The caller must pass the
    true size; a reader that disagrees raises rather than emitting a blob the
    server would reject.

    Args:
        reader: Binary stream positioned at the start of the plaintext.
        key: The 32-byte folder encryption key.
        plaintext_size: Exact size of the plaintext in bytes.
        base_nonce: 24-byte nonce; drawn from ``os.urandom`` when omitted.

    Yields:
        The header, then each framed chunk.

    Raises:
        ValueError: If ``base_nonce`` is not 24 bytes or the reader's length
            does not match ``plaintext_size``.
    """
    nonce = base_nonce if base_nonce is not None else os.urandom(NONCE_LEN)
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"base_nonce must be {NONCE_LEN} bytes, got {len(nonce)}")
    frames = chunk_count(plaintext_size)
    yield nonce + frames.to_bytes(4, "little")

    read_total = 0
    for index in range(frames):
        chunk = _read_upto(reader, CHUNK_SIZE) if plaintext_size else b""
        read_total += len(chunk)
        frame = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
            chunk, None, chunk_nonce(nonce, index), key
        )
        yield len(frame).to_bytes(4, "little") + frame

    if read_total != plaintext_size:
        raise ValueError(f"declared plaintext_size {plaintext_size}, read {read_total} bytes")


def encrypt_bytes(plaintext: bytes, key: bytes, base_nonce: bytes | None = None) -> bytes:
    """Encrypt an in-memory buffer, as used for the ``encrypted_path`` field.

    Args:
        plaintext: The bytes to encrypt.
        key: The 32-byte folder encryption key.
        base_nonce: 24-byte nonce; drawn from ``os.urandom`` when omitted.

    Returns:
        The complete blob.
    """
    return b"".join(encrypt_stream(io.BytesIO(plaintext), key, len(plaintext), base_nonce))


def _read_exact(reader: BinaryIO, size: int) -> bytes:
    data = _read_upto(reader, size)
    if len(data) != size:
        raise DecryptError(f"truncated ciphertext: wanted {size} bytes, got {len(data)}")
    return data


def decrypt_stream(reader: BinaryIO, key: bytes) -> Iterator[bytes]:
    """Yield plaintext frame by frame, authenticating each before it is yielded.

    Nothing unauthenticated ever reaches the caller, so a partially written
    output file can only ever hold verified bytes.

    Args:
        reader: Binary stream positioned at the start of the blob.
        key: The 32-byte folder encryption key.

    Yields:
        One plaintext chunk per frame.

    Raises:
        DecryptError: If the blob is malformed, truncated, has trailing bytes,
            or any frame fails authentication.
    """
    header = _read_exact(reader, HEADER_LEN)
    nonce = header[:NONCE_LEN]
    frames = int.from_bytes(header[NONCE_LEN:], "little")
    if frames == 0:
        raise DecryptError("invalid ciphertext: chunk_count is 0")

    for index in range(frames):
        frame_len = int.from_bytes(_read_exact(reader, FRAME_HEADER_LEN), "little")
        if frame_len < TAG_LEN or frame_len > MAX_FRAME_LEN:
            raise DecryptError(f"frame {index} length {frame_len} out of range")
        frame = _read_exact(reader, frame_len)
        try:
            yield bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
                frame, None, chunk_nonce(nonce, index), key
            )
        except CryptoError as exc:
            raise DecryptError(f"frame {index} failed authentication") from exc

    # A lowered chunk_count leaves the dropped frames' bytes behind, so the
    # header would disagree with the body. hcfs rejects that; so do we.
    if reader.read(1):
        raise DecryptError(f"trailing bytes after {frames} declared chunks")


def decrypt_bytes(blob: bytes, key: bytes) -> bytes:
    """Decrypt an in-memory blob, as used for the ``encrypted_path`` field.

    Args:
        blob: The complete encrypted blob.
        key: The 32-byte folder encryption key.

    Returns:
        The plaintext.

    Raises:
        DecryptError: If the blob is malformed or fails authentication.
    """
    return b"".join(decrypt_stream(io.BytesIO(blob), key))
