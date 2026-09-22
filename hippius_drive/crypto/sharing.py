"""File and folder share links, matching hcfs-client ``client/share.rs``.

A public link carries the raw 32-byte key in the ``#k=`` fragment. A password
link carries an Argon2id wrap in ``#p=`` and never the raw key. The fragment
is not sent to the server. The filename is a separate XChaCha20-Poly1305
ciphertext; file bytes use the framed cipher in :mod:`hippius_drive.crypto.file_cipher`.
"""

from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from argon2.low_level import Type, hash_secret_raw
from nacl import bindings
from nacl.exceptions import CryptoError

from hippius_drive.errors import DecryptError

PASSWORD_MIN_LEN = 8
"""Minimum share-password length, counted in characters. Matches hcfs-client."""

SHARE_WRAP_BLOB_LEN = 89
"""``version(1) || salt(16) || nonce(24) || key(32) || tag(16)``."""

_KEY_LEN = 32
_SALT_LEN = 16
_NONCE_LEN = 24
_TAG_LEN = 16
_WRAP_VERSION = 1
_ARGON2_MEMORY_KIB = 19_456
_ARGON2_TIME = 2
_ARGON2_PARALLELISM = 1
_ARGON2_VERSION = 19
_TOKEN = re.compile(r"^[A-Za-z0-9_-]+$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_FILE_PATH_LEN = 2
_FOLDER_PATH_LEN = 3


@dataclass(frozen=True)
class ShareSecret:
    """The fragment secret for one share.

    ``private`` is the whole distinction between a ``#k=`` link and a ``#p=``
    link. A wrap blob read back as a raw key would publish a password-free URL.

    Attributes:
        material: 32-byte key, or an 89-byte password wrap.
        private: True when ``material`` is a password wrap.
    """

    material: bytes = field(repr=False)
    private: bool = False

    def __post_init__(self) -> None:
        """Reject a secret whose length does not match its kind."""
        expected = SHARE_WRAP_BLOB_LEN if self.private else _KEY_LEN
        if len(self.material) != expected:
            kind = "password wrap" if self.private else "share key"
            raise ValueError(f"{kind} must be {expected} bytes, got {len(self.material)}")


@dataclass(frozen=True)
class ParsedShareUrl:
    """A share URL split into the token and the fragment secret.

    Attributes:
        folder: True for ``/share/folder/{token}``.
        token: The plaintext capability.
        secret: The key or password wrap from the fragment.
    """

    folder: bool
    token: str
    secret: ShareSecret


def generate_share_key() -> bytes:
    """Return a fresh 32-byte share key from the OS CSPRNG."""
    return os.urandom(_KEY_LEN)


def file_share_url(console_base_url: str, token: str, key: bytes) -> str:
    """Build ``{base}/share/{token}#k={key}``.

    Args:
        console_base_url: Console origin, trailing slash ignored.
        token: The plaintext share token.
        key: The 32-byte share key.

    Returns:
        The recipient URL.
    """
    return _public_url(console_base_url, token, key, folder=False)


def file_share_url_private(console_base_url: str, token: str, wrapped: bytes) -> str:
    """Build ``{base}/share/{token}#p={wrap}``.

    Args:
        console_base_url: Console origin, trailing slash ignored.
        token: The plaintext share token.
        wrapped: The 89-byte password wrap.

    Returns:
        The recipient URL.
    """
    return _private_url(console_base_url, token, wrapped, folder=False)


def folder_share_url(console_base_url: str, token: str, file_key: bytes) -> str:
    """Build ``{base}/share/folder/{token}#k={file_key}``.

    Args:
        console_base_url: Console origin, trailing slash ignored.
        token: The plaintext share token.
        file_key: The drive's 32-byte file key.

    Returns:
        The recipient URL.
    """
    return _public_url(console_base_url, token, file_key, folder=True)


def folder_share_url_private(console_base_url: str, token: str, wrapped: bytes) -> str:
    """Build ``{base}/share/folder/{token}#p={wrap}``.

    Args:
        console_base_url: Console origin, trailing slash ignored.
        token: The plaintext share token.
        wrapped: The 89-byte password wrap of the drive file key.

    Returns:
        The recipient URL.
    """
    return _private_url(console_base_url, token, wrapped, folder=True)


def share_url(console_base_url: str, token: str, secret: ShareSecret, *, folder: bool) -> str:
    """Build the recipient URL for ``secret``.

    A private secret only ever produces a ``#p=`` link.

    Args:
        console_base_url: Console origin.
        token: The plaintext share token.
        secret: The fragment secret.
        folder: True for a folder share.

    Returns:
        The recipient URL.
    """
    if secret.private:
        return _private_url(console_base_url, token, secret.material, folder=folder)
    return _public_url(console_base_url, token, secret.material, folder=folder)


def parse_share_url(url: str) -> ParsedShareUrl:
    """Split a recipient URL into its token and fragment secret.

    Args:
        url: A file or folder share URL.

    Returns:
        The parsed link.

    Raises:
        ValueError: If the URL is not a share link, or the fragment is malformed.
    """
    parts = urlsplit(url)
    token, folder = _share_path(parts.scheme, parts.netloc, parts.path)
    secret = _fragment_secret(parts.fragment)
    return ParsedShareUrl(folder=folder, token=token, secret=secret)


def check_share_password(password: str) -> None:
    """Reject a share password shorter than :data:`PASSWORD_MIN_LEN` characters.

    Args:
        password: The caller-supplied password.

    Raises:
        ValueError: If the password is too short.
    """
    if len(password) < PASSWORD_MIN_LEN:
        raise ValueError(f"share password must be at least {PASSWORD_MIN_LEN} characters")


def wrap_share_key(
    password: str,
    key: bytes,
    *,
    salt: bytes | None = None,
    nonce: bytes | None = None,
) -> bytes:
    """Wrap ``key`` under ``password``.

    Production draws a fresh salt and nonce. Tests pass both to pin a vector.
    The Argon2id parameters are fixed (19 MiB, t=2, p=1) and are not stored
    in the blob: a share link is unwrapped in a browser, so this is lighter
    than the mnemonic blob's 128 MiB.

    Args:
        password: The share password.
        key: The 32-byte key to wrap.
        salt: 16-byte salt; random when omitted.
        nonce: 24-byte nonce; random when omitted.

    Returns:
        The 89-byte wrap blob.

    Raises:
        ValueError: If the password, key, salt, or nonce has the wrong shape.
    """
    check_share_password(password)
    if len(key) != _KEY_LEN:
        raise ValueError(f"share key must be {_KEY_LEN} bytes, got {len(key)}")
    used_salt = os.urandom(_SALT_LEN) if salt is None else salt
    used_nonce = os.urandom(_NONCE_LEN) if nonce is None else nonce
    if len(used_salt) != _SALT_LEN or len(used_nonce) != _NONCE_LEN:
        raise ValueError(f"salt must be {_SALT_LEN} bytes and nonce {_NONCE_LEN}")
    wrap_key = _derive_wrap_key(password, used_salt)
    sealed = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(key, b"", used_nonce, wrap_key)
    return bytes([_WRAP_VERSION]) + used_salt + used_nonce + sealed


def unwrap_share_key(password: str, blob: bytes) -> bytes:
    """Recover the 32-byte key from a :func:`wrap_share_key` blob.

    A wrong password, a bad version, and a bad length all fail the same way,
    so the error is not a format oracle.

    Args:
        password: The share password.
        blob: The 89-byte wrap.

    Returns:
        The 32-byte key.

    Raises:
        DecryptError: If the blob does not open.
    """
    if len(blob) != SHARE_WRAP_BLOB_LEN or blob[0] != _WRAP_VERSION:
        raise DecryptError("share link did not open")
    salt = blob[1 : 1 + _SALT_LEN]
    nonce_at = 1 + _SALT_LEN
    nonce = blob[nonce_at : nonce_at + _NONCE_LEN]
    wrapped = blob[nonce_at + _NONCE_LEN :]
    wrap_key = _derive_wrap_key(password, salt)
    try:
        return bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(wrapped, b"", nonce, wrap_key)
    except CryptoError as exc:
        raise DecryptError("share link did not open") from exc


def encrypt_filename(
    filename: str, key: bytes, *, nonce: bytes | None = None
) -> tuple[bytes, bytes]:
    """Encrypt a share filename. Returns ``(ciphertext_and_tag, nonce)``.

    Args:
        filename: The plaintext name sent to the recipient.
        key: The 32-byte share key.
        nonce: 24-byte nonce; random when omitted.

    Returns:
        The ciphertext (including the tag) and the nonce.

    Raises:
        ValueError: If the key or nonce has the wrong length.
    """
    if len(key) != _KEY_LEN:
        raise ValueError(f"share key must be {_KEY_LEN} bytes, got {len(key)}")
    used = os.urandom(_NONCE_LEN) if nonce is None else nonce
    if len(used) != _NONCE_LEN:
        raise ValueError(f"filename nonce must be {_NONCE_LEN} bytes, got {len(used)}")
    sealed = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(filename.encode(), b"", used, key)
    return sealed, used


def decrypt_filename(ciphertext: bytes, nonce: bytes, key: bytes) -> str:
    """Decrypt a filename sealed by :func:`encrypt_filename`.

    Args:
        ciphertext: Ciphertext including the Poly1305 tag.
        nonce: The 24-byte nonce.
        key: The 32-byte share key.

    Returns:
        The plaintext filename.

    Raises:
        DecryptError: If the tag fails or the plaintext is not UTF-8.
    """
    if len(ciphertext) < _TAG_LEN or len(nonce) != _NONCE_LEN or len(key) != _KEY_LEN:
        raise DecryptError("filename ciphertext is malformed")
    try:
        plain = bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, b"", nonce, key)
    except CryptoError as exc:
        raise DecryptError("filename did not decrypt") from exc
    try:
        return plain.decode()
    except UnicodeDecodeError as exc:
        raise DecryptError("filename is not valid UTF-8") from exc


def _derive_wrap_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=_ARGON2_TIME,
        memory_cost=_ARGON2_MEMORY_KIB,
        parallelism=_ARGON2_PARALLELISM,
        hash_len=_KEY_LEN,
        type=Type.ID,
        version=_ARGON2_VERSION,
    )


def _public_url(base: str, token: str, key: bytes, *, folder: bool) -> str:
    if len(key) != _KEY_LEN:
        raise ValueError(f"share key must be {_KEY_LEN} bytes, got {len(key)}")
    return _url(base, token, "k", _b64url(key), folder=folder)


def _private_url(base: str, token: str, wrapped: bytes, *, folder: bool) -> str:
    if len(wrapped) != SHARE_WRAP_BLOB_LEN:
        raise ValueError(f"password wrap must be {SHARE_WRAP_BLOB_LEN} bytes, got {len(wrapped)}")
    return _url(base, token, "p", _b64url(wrapped), folder=folder)


def _url(base: str, token: str, kind: str, fragment: str, *, folder: bool) -> str:
    _check_token(token)
    trimmed = base.rstrip("/")
    if not trimmed.startswith("https://"):
        raise ValueError("console_base_url must be an https origin")
    path = f"/share/folder/{token}" if folder else f"/share/{token}"
    return f"{trimmed}{path}#{kind}={fragment}"


def _check_token(token: str) -> None:
    if not _TOKEN.fullmatch(token):
        raise ValueError("share token must be a base64url path segment")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(value: str) -> bytes:
    if not _B64URL.fullmatch(value):
        raise ValueError("fragment is not base64url")
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def _share_path(scheme: str, netloc: str, path: str) -> tuple[str, bool]:
    if scheme != "https" or not netloc:
        raise ValueError("share URL must be an absolute https URL")
    parts = [segment for segment in path.split("/") if segment]
    if len(parts) == _FILE_PATH_LEN and parts[0] == "share":
        _check_token(parts[1])
        return parts[1], False
    if len(parts) == _FOLDER_PATH_LEN and parts[0] == "share" and parts[1] == "folder":
        _check_token(parts[2])
        return parts[2], True
    raise ValueError("share URL path must be /share/{token} or /share/folder/{token}")


def _fragment_secret(fragment: str) -> ShareSecret:
    if fragment.startswith("k="):
        raw = _b64url_decode(fragment[2:])
        return ShareSecret(raw, private=False)
    if fragment.startswith("p="):
        raw = _b64url_decode(fragment[2:])
        return ShareSecret(raw, private=True)
    raise ValueError("share URL needs a #k= or #p= fragment")
