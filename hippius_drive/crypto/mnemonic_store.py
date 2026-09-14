"""The desktop ``enc_mnemonic.json`` format (hcfs-client ``auth.rs``).

``{salt: b64(16), iv: b64(12), data: b64(ct||tag), iterations: 600000}``, where
the key is PBKDF2-HMAC-SHA256 of the password over ``salt`` to 32 bytes and the
payload is AES-256-GCM with an empty AAD. A file with no ``iterations`` key is
a legacy 10,000-iteration blob and still opens.

This file is normally the only local copy of a master mnemonic, so writes are
atomic: a temp sibling is fsynced, the previous blob is copied to ``.bak``, and
only then does the rename land.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITERATIONS = 600_000
"""PBKDF2 iterations written by current clients."""

LEGACY_ITERATIONS = 10_000
"""What a blob with no ``iterations`` key was written with."""

SALT_LEN = 16
IV_LEN = 12
KEY_LEN = 32
_FILE_MODE = 0o600


class MnemonicStoreError(Exception):
    """The store file is malformed, or the password does not open it."""


def _derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    if iterations <= 0:
        raise MnemonicStoreError("PBKDF2 iteration count must be non-zero")
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, KEY_LEN)


def _atomic_write(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` durably, keeping the previous blob as ``.bak``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    backup = path.with_name(path.name + ".bak")

    # Create owner-only from the first instant rather than create-then-chmod,
    # so the ciphertext is never briefly readable under a permissive umask.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _FILE_MODE)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())

    if path.exists():
        # Best-effort, exactly as hcfs-client does: a failed backup must not
        # block writing a blob that is valid and durable on its own.
        try:
            backup.write_bytes(path.read_bytes())
            if os.name == "posix":
                os.chmod(backup, _FILE_MODE)
        except OSError:
            pass

    os.replace(tmp, path)

    if os.name == "posix":
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


@dataclass(frozen=True)
class StoreParams:
    """The values that make a store write deterministic.

    Attributes:
        salt: 16-byte PBKDF2 salt.
        iv: 12-byte AES-GCM nonce.
        iterations: PBKDF2 iteration count.
    """

    salt: bytes
    iv: bytes
    iterations: int = ITERATIONS


def save_with(path: Path, mnemonic: str, password: str, params: StoreParams) -> None:
    """Write the store with caller-supplied salt and IV.

    Deterministic, so a known-answer vector can pin the exact file. Production
    callers want :func:`save`.

    Args:
        path: Destination file, normally ``enc_mnemonic.json``.
        mnemonic: The BIP-39 phrase to seal.
        password: The unlock password.
        params: The salt, IV, and iteration count to use.

    Raises:
        MnemonicStoreError: If any of ``params`` is invalid.
    """
    if len(params.salt) != SALT_LEN:
        raise MnemonicStoreError(f"salt must be {SALT_LEN} bytes, got {len(params.salt)}")
    if len(params.iv) != IV_LEN:
        raise MnemonicStoreError(f"IV must be {IV_LEN} bytes, got {len(params.iv)}")

    key = _derive_key(password, params.salt, params.iterations)
    data = AESGCM(key).encrypt(params.iv, mnemonic.encode(), None)
    body = {
        "salt": base64.b64encode(params.salt).decode(),
        "iv": base64.b64encode(params.iv).decode(),
        "data": base64.b64encode(data).decode(),
        "iterations": params.iterations,
    }
    _atomic_write(path, json.dumps(body, indent=2))


def save(path: Path, mnemonic: str, password: str, *, iterations: int = ITERATIONS) -> None:
    """Seal ``mnemonic`` under ``password`` and write it to ``path``.

    Args:
        path: Destination file, normally ``enc_mnemonic.json``.
        mnemonic: The BIP-39 phrase to seal.
        password: The unlock password.
        iterations: PBKDF2 iteration count; lower it only to write a legacy blob.
    """
    params = StoreParams(salt=os.urandom(SALT_LEN), iv=os.urandom(IV_LEN), iterations=iterations)
    save_with(path, mnemonic, password, params)


def _decode_field(body: dict[str, object], name: str) -> bytes:
    value = body.get(name)
    if not isinstance(value, str):
        raise MnemonicStoreError(f"encrypted mnemonic is missing the {name!r} field")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MnemonicStoreError(f"{name!r} is not valid base64") from exc


def load(path: Path, password: str) -> str:
    """Open the store at ``path`` and return the mnemonic.

    Args:
        path: The store file.
        password: The unlock password.

    Returns:
        The BIP-39 phrase.

    Raises:
        MnemonicStoreError: If the file is unreadable or malformed, or the
            password does not open it.
    """
    try:
        body = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MnemonicStoreError(f"cannot read encrypted mnemonic at {path}: {exc}") from exc
    if not isinstance(body, dict):
        raise MnemonicStoreError("encrypted mnemonic must be a JSON object")

    salt = _decode_field(body, "salt")
    iv = _decode_field(body, "iv")
    data = _decode_field(body, "data")
    # `iterations` is corruption-controlled; a missing key means the legacy
    # 10k blob, but a present non-integer is a malformed file, not a default.
    raw_iterations = body.get("iterations", LEGACY_ITERATIONS)
    if raw_iterations is None:
        raw_iterations = LEGACY_ITERATIONS
    if not isinstance(raw_iterations, int) or isinstance(raw_iterations, bool):
        raise MnemonicStoreError("'iterations' must be an integer")
    if len(iv) != IV_LEN:
        raise MnemonicStoreError(f"IV must be {IV_LEN} bytes, got {len(iv)}")

    key = _derive_key(password, salt, raw_iterations)
    try:
        return AESGCM(key).decrypt(iv, data, None).decode()
    except (InvalidTag, UnicodeDecodeError) as exc:
        raise MnemonicStoreError("decryption failed - wrong password?") from exc
