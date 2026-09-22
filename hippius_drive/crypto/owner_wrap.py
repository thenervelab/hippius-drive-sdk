"""Owner-only seal of a share secret, matching hcfs-client ``share_wrap.rs``.

The server stores these bytes and returns them to the account that minted the
share. It cannot open them. Any device with the master phrase can rebuild the
recipient URL. The key is

``BLAKE3::derive_key("hippius.hcfs.share-wrap.v1", master_seed[:32])``

and the AAD is ``owner_ss58 || 0x00 || row_key``, so a blob swapped onto
another row fails the tag. For a file share ``row_key`` is the plaintext
token. For a folder share it is ``blake3(token)`` hex, because that is all
the listing returns.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import blake3
from mnemonic import Mnemonic
from nacl import bindings
from nacl.exceptions import CryptoError

from hippius_drive.crypto.sharing import SHARE_WRAP_BLOB_LEN, ShareSecret
from hippius_drive.errors import DecryptError

OWNER_WRAP_CONTEXT = "hippius.hcfs.share-wrap.v1"
"""BLAKE3 derive_key context. Never reuse it as a folder label."""

_VERSION = 1
_NONCE_LEN = 24
_TAG_LEN = 16
_KEY_LEN = 32
_FLAG_PRIVATE = 0x01
_FLAG_FOLDER_TOKEN = 0x02
_MAX_FOLDER_TOKEN = 64
_MIN_LEN = 1 + _NONCE_LEN + _TAG_LEN
_BIP39 = Mnemonic("english")


def folder_token_hash(token: str) -> str:
    """Return the blake3 hex of a folder-share token, the listing's row key.

    Args:
        token: The plaintext folder-share token.

    Returns:
        64 lowercase hex characters.
    """
    return blake3.blake3(token.encode()).hexdigest()


def seal_file_secret(
    master_mnemonic: str,
    owner_ss58: str,
    share_token: str,
    secret: ShareSecret,
    *,
    nonce: bytes | None = None,
) -> bytes:
    """Seal a file-share secret. The listing already returns the token.

    Args:
        master_mnemonic: The minter's master phrase.
        owner_ss58: Bound into the AAD. For a file share this is the minter.
        share_token: The row key.
        secret: The fragment secret.
        nonce: 24-byte nonce; random when omitted.

    Returns:
        ``version || nonce || ciphertext``.
    """
    spec = _Seal(master_mnemonic, owner_ss58, share_token, secret, None, nonce)
    return _seal(spec)


def seal_folder_secret(
    master_mnemonic: str,
    owner_ss58: str,
    token: str,
    secret: ShareSecret,
    *,
    nonce: bytes | None = None,
) -> bytes:
    """Seal a folder-share token and its fragment secret together.

    Args:
        master_mnemonic: The minter's master phrase.
        owner_ss58: Bound into the AAD.
        token: The plaintext token. The AAD row key is its blake3 hex.
        secret: The fragment secret.
        nonce: 24-byte nonce; random when omitted.

    Returns:
        ``version || nonce || ciphertext``.
    """
    row_key = folder_token_hash(token)
    spec = _Seal(master_mnemonic, owner_ss58, row_key, secret, token, nonce)
    return _seal(spec)


def open_file_secret(
    master_mnemonic: str, owner_ss58: str, share_token: str, wrap: bytes
) -> ShareSecret:
    """Open a file-share wrap.

    Args:
        master_mnemonic: The minter's master phrase.
        owner_ss58: The AAD address.
        share_token: The row key the wrap was sealed under.
        wrap: The blob from the listing.

    Returns:
        The fragment secret.

    Raises:
        DecryptError: If the wrap does not open, or it was sealed as a folder share.
    """
    opened = _open(master_mnemonic, owner_ss58, share_token, wrap)
    if opened[0] is not None:
        raise DecryptError("file wrap opened as a folder share")
    return opened[1]


def open_folder_secret(
    master_mnemonic: str, owner_ss58: str, token_hash: str, wrap: bytes
) -> tuple[str, ShareSecret]:
    """Open a folder-share wrap.

    Args:
        master_mnemonic: The minter's master phrase.
        owner_ss58: The AAD address.
        token_hash: Blake3 hex of the token, the listing row key.
        wrap: The blob from the listing.

    Returns:
        The plaintext token and the fragment secret.

    Raises:
        DecryptError: If the wrap does not open or carries no token.
    """
    token, secret = _open(master_mnemonic, owner_ss58, token_hash, wrap)
    if token is None:
        raise DecryptError("folder wrap missing token")
    return token, secret


@dataclass(frozen=True)
class _Seal:
    """The values that go into one owner wrap, kept together so the sealer stays narrow."""

    master_mnemonic: str
    owner_ss58: str
    row_key: str
    secret: ShareSecret
    folder_token: str | None
    nonce: bytes | None


def _seal(spec: _Seal) -> bytes:
    used = os.urandom(_NONCE_LEN) if spec.nonce is None else spec.nonce
    if len(used) != _NONCE_LEN:
        raise ValueError(f"owner-wrap nonce must be {_NONCE_LEN} bytes, got {len(used)}")
    key = _derive_key(spec.master_mnemonic)
    plaintext = _encode(spec.secret, spec.folder_token)
    sealed = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, _aad(spec.owner_ss58, spec.row_key), used, key
    )
    return bytes([_VERSION]) + used + sealed


def _open(
    master_mnemonic: str, owner_ss58: str, row_key: str, wrap: bytes
) -> tuple[str | None, ShareSecret]:
    if len(wrap) < _MIN_LEN or wrap[0] != _VERSION:
        raise DecryptError("owner wrap did not open")
    nonce = wrap[1 : 1 + _NONCE_LEN]
    ciphertext = wrap[1 + _NONCE_LEN :]
    key = _derive_key(master_mnemonic)
    try:
        plain = bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, _aad(owner_ss58, row_key), nonce, key
        )
    except CryptoError as exc:
        raise DecryptError("owner wrap did not open") from exc
    return _decode(plain)


def _derive_key(master_mnemonic: str) -> bytes:
    if not _BIP39.check(master_mnemonic):
        raise ValueError("invalid BIP-39 mnemonic (bad word or checksum)")
    seed = _BIP39.to_seed(master_mnemonic, passphrase="")
    return blake3.blake3(seed[:_KEY_LEN], derive_key_context=OWNER_WRAP_CONTEXT).digest()


def _aad(owner_ss58: str, row_key: str) -> bytes:
    return owner_ss58.encode() + b"\x00" + row_key.encode()


def _encode(secret: ShareSecret, folder_token: str | None) -> bytes:
    flags = 0
    if secret.private:
        flags |= _FLAG_PRIVATE
    token_bytes = b""
    if folder_token is not None:
        flags |= _FLAG_FOLDER_TOKEN
        token_bytes = folder_token.encode()
        if not token_bytes or len(token_bytes) > _MAX_FOLDER_TOKEN:
            raise ValueError("folder token length out of range")
    body = bytes([len(token_bytes)]) + token_bytes if folder_token is not None else b""
    return bytes([flags]) + body + secret.material


def _decode(plaintext: bytes) -> tuple[str | None, ShareSecret]:
    if not plaintext:
        raise DecryptError("owner wrap did not open")
    flags = plaintext[0]
    if flags & ~(_FLAG_PRIVATE | _FLAG_FOLDER_TOKEN):
        raise DecryptError("owner wrap did not open")
    rest = plaintext[1:]
    token: str | None = None
    if flags & _FLAG_FOLDER_TOKEN:
        token, rest = _take_token(rest)
    return token, _take_secret(flags, rest)


def _take_token(rest: bytes) -> tuple[str, bytes]:
    if not rest:
        raise DecryptError("owner wrap did not open")
    length = rest[0]
    if length == 0 or length > _MAX_FOLDER_TOKEN or len(rest) < 1 + length:
        raise DecryptError("owner wrap did not open")
    try:
        token = rest[1 : 1 + length].decode()
    except UnicodeDecodeError as exc:
        raise DecryptError("owner wrap did not open") from exc
    return token, rest[1 + length :]


def _take_secret(flags: int, secret_bytes: bytes) -> ShareSecret:
    private = bool(flags & _FLAG_PRIVATE)
    expected = SHARE_WRAP_BLOB_LEN if private else _KEY_LEN
    if len(secret_bytes) != expected:
        raise DecryptError("owner wrap did not open")
    return ShareSecret(secret_bytes, private=private)
