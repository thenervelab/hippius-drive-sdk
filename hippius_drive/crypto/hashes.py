"""Content and path hashes shared with hcfs-client (BLAKE3 everywhere)."""

from __future__ import annotations

import unicodedata

import blake3

_BAD_SEGMENTS = frozenset({"", ".", ".."})


def normalize_relative_path(path: str) -> str:
    """Return the NFC, POSIX-style relative path the server accepts.

    Mirrors hcfs-client's path validation: no empty, ``.`` or ``..`` segments,
    no backslashes, no leading slash. macOS hands back NFD names and the server
    rejects non-NFC paths, so recompose here before anything hashes the string.

    Args:
        path: A folder-relative POSIX path such as ``docs/report.pdf``.

    Returns:
        The same path in NFC form.

    Raises:
        ValueError: If the path is absolute, empty, or has a bad segment.
    """
    if not path or path.startswith("/") or "\\" in path:
        raise ValueError(f"relative_path must be a non-empty POSIX relative path: {path!r}")
    if any(segment in _BAD_SEGMENTS for segment in path.split("/")):
        raise ValueError(f"relative_path has an empty, '.' or '..' segment: {path!r}")
    return unicodedata.normalize("NFC", path)


MAX_PATH_DEPTH = 64
MAX_SEGMENT_BYTES = 255
MAX_PATH_BYTES = 1024
_FORMAT_CHARS = frozenset(
    "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
    "\u00ad\u034f\u180e\u200b\u200c\u200d\u2060\ufeff"
)


def validate_stored_path(path: str) -> str:
    """Normalise ``path`` and apply the rest of hcfs's stored-path rules.

    Mirrors ``hcfs_shared::path_validator::validate``: on top of
    :func:`normalize_relative_path` (which already refuses a trailing slash), no control or
    bidi / zero-width characters, at most 64 segments, 255 bytes per segment
    and 1024 bytes in all (UTF-8). Uploads let the server judge; calls whose
    contract promises a local error use this.

    Args:
        path: A folder-relative POSIX path.

    Returns:
        The path in NFC form.

    Raises:
        ValueError: Naming the first rule the path breaks.
    """
    normalized = normalize_relative_path(path)
    if any(unicodedata.category(char) == "Cc" for char in normalized):
        raise ValueError(f"relative_path has a control character: {path!r}")
    if any(char in _FORMAT_CHARS for char in normalized):
        raise ValueError(f"relative_path has a bidi-control or zero-width character: {path!r}")
    if len(normalized.encode()) > MAX_PATH_BYTES:
        raise ValueError(f"relative_path is over {MAX_PATH_BYTES} bytes")
    segments = normalized.split("/")
    if len(segments) > MAX_PATH_DEPTH:
        raise ValueError(f"relative_path is deeper than {MAX_PATH_DEPTH} segments")
    if any(len(segment.encode()) > MAX_SEGMENT_BYTES for segment in segments):
        raise ValueError(f"relative_path has a segment over {MAX_SEGMENT_BYTES} bytes")
    return normalized


def path_hash(relative_path: str) -> bytes:
    """Return ``BLAKE3`` of the NFC UTF-8 relative path; its hex is the ``file_id``.

    Args:
        relative_path: A folder-relative POSIX path.

    Returns:
        The 32-byte digest.
    """
    return blake3.blake3(normalize_relative_path(relative_path).encode()).digest()


def salted_hasher(account_ss58: str) -> blake3.blake3:
    """Start a ``salted_hash`` over ``account_ss58 || plaintext``.

    Feed the plaintext with ``update`` and read ``digest()``. Used by the upload
    path so a large file is hashed in one streaming pass.

    Args:
        account_ss58: The account address that salts the hash.

    Returns:
        A BLAKE3 hasher already primed with the salt.
    """
    hasher = blake3.blake3()
    hasher.update(account_ss58.encode())
    return hasher


def salted_hash(account_ss58: str, plaintext: bytes) -> bytes:
    """Return ``BLAKE3(account_ss58 || plaintext)`` for in-memory content.

    Args:
        account_ss58: The account address that salts the hash.
        plaintext: The unencrypted file bytes.

    Returns:
        The 32-byte digest.
    """
    hasher = salted_hasher(account_ss58)
    hasher.update(plaintext)
    return hasher.digest()


def blake3_hex(data: bytes) -> str:
    """Return the hex BLAKE3 of ``data``, the ``ciphertext_hash`` form.

    Args:
        data: The bytes to hash, normally a whole ciphertext blob.

    Returns:
        The 64-character lowercase hex digest.
    """
    return blake3.blake3(data).hexdigest()
