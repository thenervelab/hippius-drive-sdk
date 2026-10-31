"""Link-secret folder links (``#s=`` / ``#sp=``), matching hcfs ``client/folder_link.rs``.

A legacy folder link put the drive file key in its fragment, so everyone who
ever received one held the key to the whole drive, and the server now refuses
to mint one (``link_envelope_required``). A link-secret link carries a random
32-byte secret instead; the server stores the drive key sealed under it and
releases it only to a caller that proves the secret:

* fetch_key = derive_key("hippius.hcfs.folder-link-fetch.v1", link_secret)
* wrap_key = derive_key("hippius.hcfs.folder-link-wrap.v1", link_secret)
* fetch_digest = blake3(fetch_key), stored by the server
* envelope = 0x01 || nonce(24) || XChaCha20-Poly1305(wrap_key, file_key,
  aad = "hippius.hcfs.folder-link-envelope.v1" || 0x01), 73 bytes

The console and the desktop build these links with the same functions
(hcfs-client and its wasm build), so a link minted here opens there.
"""

from __future__ import annotations

import base64
import os

import blake3
from nacl import bindings
from nacl.exceptions import CryptoError

from hippius_drive.errors import DecryptError

FETCH_CONTEXT = "hippius.hcfs.folder-link-fetch.v1"
WRAP_CONTEXT = "hippius.hcfs.folder-link-wrap.v1"
ENVELOPE_VERSION = 1
ENVELOPE_AAD = b"hippius.hcfs.folder-link-envelope.v1\x01"
ENVELOPE_LEN = 73
_KEY_LEN = 32
_NONCE_LEN = 24


def generate_link_secret() -> bytes:
    """Return a fresh 32-byte link secret from the OS CSPRNG."""
    return os.urandom(_KEY_LEN)


def fetch_key(link_secret: bytes) -> bytes:
    """The key a recipient proves to ``GET /v1/folder-shares/{token}/link-key``."""
    _check_len("link secret", link_secret)
    return blake3.blake3(link_secret, derive_key_context=FETCH_CONTEXT).digest()


def wrap_key(link_secret: bytes) -> bytes:
    """The key that seals and opens the envelope."""
    _check_len("link secret", link_secret)
    return blake3.blake3(link_secret, derive_key_context=WRAP_CONTEXT).digest()


def fetch_proof(link_secret: bytes) -> str:
    """Return the ``x-hcfs-link-proof`` header value: unpadded base64url of the fetch key."""
    return base64.urlsafe_b64encode(fetch_key(link_secret)).rstrip(b"=").decode()


def fetch_digest(link_secret: bytes) -> bytes:
    """Return ``blake3(fetch_key)``, the create body's ``link_fetch_digest``."""
    return blake3.blake3(fetch_key(link_secret)).digest()


def seal_envelope(link_secret: bytes, file_key: bytes, *, nonce: bytes | None = None) -> bytes:
    """Seal the drive file key into a version-1 envelope.

    Args:
        link_secret: The link's 32-byte secret.
        file_key: The drive's 32-byte file key.
        nonce: 24 bytes; random when omitted. Fixed only in tests.

    Returns:
        The 73-byte envelope.

    Raises:
        ValueError: If a length is wrong.
    """
    _check_len("file key", file_key)
    used = os.urandom(_NONCE_LEN) if nonce is None else nonce
    if len(used) != _NONCE_LEN:
        raise ValueError(f"envelope nonce must be {_NONCE_LEN} bytes, got {len(used)}")
    sealed = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        file_key, ENVELOPE_AAD, used, wrap_key(link_secret)
    )
    return bytes([ENVELOPE_VERSION]) + used + sealed


def open_envelope(link_secret: bytes, envelope: bytes) -> bytes:
    """Open a version-1 envelope and return the drive file key.

    Args:
        link_secret: The link's 32-byte secret.
        envelope: The 73 bytes ``link-key`` returned.

    Returns:
        The 32-byte drive file key.

    Raises:
        DecryptError: For a wrong length or version, a wrong secret, or
            tampering. The cases are not told apart.
    """
    if len(envelope) != ENVELOPE_LEN or envelope[0] != ENVELOPE_VERSION:
        raise DecryptError("folder link envelope did not open")
    nonce, ciphertext = envelope[1 : 1 + _NONCE_LEN], envelope[1 + _NONCE_LEN :]
    try:
        return bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, ENVELOPE_AAD, nonce, wrap_key(link_secret)
        )
    except CryptoError as exc:
        raise DecryptError("folder link envelope did not open") from exc


def _check_len(name: str, value: bytes) -> None:
    if len(value) != _KEY_LEN:
        raise ValueError(f"{name} must be {_KEY_LEN} bytes, got {len(value)}")
