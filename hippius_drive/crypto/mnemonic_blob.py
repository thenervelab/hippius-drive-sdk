"""Passphrase-sealed mnemonic blob (hcfs-client ``mnemonic_blob.rs``).

Argon2id derives a 32-byte key from the passphrase and salt; XChaCha20-Poly1305
seals the mnemonic with the account SS58 as AAD, so a server-side blob swap is
detectable on unlock rather than silently installing someone else's seed.

Every byte field is base64 in the JSON wire form the console reads.
"""

from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass

from argon2.exceptions import Argon2Error
from argon2.low_level import Type, hash_secret_raw
from nacl import bindings
from nacl.exceptions import CryptoError
from pydantic import BaseModel, ConfigDict

SALT_LEN = 16
NONCE_LEN = 24
KEY_LEN = 32
_ARGON2_VERSION = 19  # 0x13


class MnemonicBlobError(Exception):
    """The blob is malformed, or the passphrase or SS58 does not open it."""


class KdfParams(BaseModel):
    """Argon2id parameters stored with the blob so the opener can re-derive.

    The defaults match hcfs-client. A blob written elsewhere may carry weaker
    parameters; they are read from the blob, never assumed.

    Attributes:
        algorithm: Always ``argon2id``.
        memory_kib: Memory cost in KiB.
        time_cost: Number of passes.
        parallelism: Lanes.
    """

    model_config = ConfigDict(extra="ignore")

    algorithm: str = "argon2id"
    memory_kib: int = 131_072
    time_cost: int = 3
    parallelism: int = 1


class SealedBlob(BaseModel):
    """An encrypted mnemonic plus everything needed to open it.

    Attributes:
        ciphertext: Base64 of ``ct||tag``.
        salt: Base64 of the 16-byte Argon2id salt.
        nonce: Base64 of the 24-byte XChaCha20-Poly1305 nonce.
        aad: Base64 of the account SS58 bytes bound into the AEAD.
        kdf: The Argon2id parameters used.
    """

    model_config = ConfigDict(extra="ignore")

    ciphertext: str
    salt: str
    nonce: str
    aad: str
    kdf: KdfParams


@dataclass(frozen=True)
class SealInputs:
    """The values that make a seal deterministic.

    Attributes:
        salt: 16-byte Argon2id salt.
        nonce: 24-byte XChaCha20-Poly1305 nonce.
        kdf: The Argon2id parameters to use.
    """

    salt: bytes
    nonce: bytes
    kdf: KdfParams


def _derive_key(passphrase: str, salt: bytes, kdf: KdfParams) -> bytes:
    try:
        return hash_secret_raw(
            secret=passphrase.encode(),
            salt=salt,
            time_cost=kdf.time_cost,
            memory_cost=kdf.memory_kib,
            parallelism=kdf.parallelism,
            hash_len=KEY_LEN,
            type=Type.ID,
            version=_ARGON2_VERSION,
        )
    except (Argon2Error, ValueError) as exc:
        raise MnemonicBlobError(f"Argon2 key derivation failed: {exc}") from exc


def seal_with(mnemonic: str, passphrase: str, ss58: str, inputs: SealInputs) -> SealedBlob:
    """Seal ``mnemonic`` with caller-supplied salt and nonce.

    Deterministic, so a known-answer vector can pin the exact blob. Production
    callers want :func:`seal`.

    Args:
        mnemonic: The BIP-39 phrase to seal.
        passphrase: The passphrase that protects the blob.
        ss58: The account address, bound in as AAD.
        inputs: The salt, nonce, and KDF parameters to use.

    Returns:
        The sealed blob.

    Raises:
        MnemonicBlobError: If the salt or nonce has the wrong length, or the
            KDF rejects the parameters.
    """
    if len(inputs.salt) != SALT_LEN:
        raise MnemonicBlobError(f"salt must be {SALT_LEN} bytes, got {len(inputs.salt)}")
    if len(inputs.nonce) != NONCE_LEN:
        raise MnemonicBlobError(f"nonce must be {NONCE_LEN} bytes, got {len(inputs.nonce)}")

    key = _derive_key(passphrase, inputs.salt, inputs.kdf)
    ciphertext = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        mnemonic.encode(), ss58.encode(), inputs.nonce, key
    )
    return SealedBlob(
        ciphertext=base64.b64encode(ciphertext).decode(),
        salt=base64.b64encode(inputs.salt).decode(),
        nonce=base64.b64encode(inputs.nonce).decode(),
        aad=base64.b64encode(ss58.encode()).decode(),
        kdf=inputs.kdf,
    )


def seal(mnemonic: str, passphrase: str, ss58: str, *, kdf: KdfParams | None = None) -> SealedBlob:
    """Seal ``mnemonic`` under ``passphrase`` with a fresh salt and nonce.

    Args:
        mnemonic: The BIP-39 phrase to seal.
        passphrase: The passphrase that protects the blob.
        ss58: The account address, bound in as AAD.
        kdf: Argon2id parameters; the hcfs defaults when omitted.

    Returns:
        The sealed blob.
    """
    inputs = SealInputs(
        salt=os.urandom(SALT_LEN),
        nonce=os.urandom(NONCE_LEN),
        kdf=kdf if kdf is not None else KdfParams(),
    )
    return seal_with(mnemonic, passphrase, ss58, inputs)


def _b64(value: str, name: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MnemonicBlobError(f"{name!r} is not valid base64") from exc


def open_blob(blob: SealedBlob, passphrase: str, expected_ss58: str) -> str:
    """Open ``blob`` and return the mnemonic.

    ``expected_ss58`` must be the address the caller believes owns the blob. A
    blob sealed under a different address fails the AEAD tag check, which is
    reported as authentication failure rather than "wrong passphrase".

    Args:
        blob: The sealed blob.
        passphrase: The passphrase that protects it.
        expected_ss58: The account address the caller expects.

    Returns:
        The BIP-39 phrase.

    Raises:
        MnemonicBlobError: If the blob is malformed, or the passphrase or
            address does not open it.
    """
    salt = _b64(blob.salt, "salt")
    nonce = _b64(blob.nonce, "nonce")
    ciphertext = _b64(blob.ciphertext, "ciphertext")
    # Checked before the KDF: a corrupt nonce should not cost a 128 MiB Argon2
    # pass, and libsodium would raise an opaque error on the wrong length.
    if len(nonce) != NONCE_LEN:
        raise MnemonicBlobError(f"nonce must be {NONCE_LEN} bytes, got {len(nonce)}")

    key = _derive_key(passphrase, salt, blob.kdf)
    try:
        plaintext = bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, expected_ss58.encode(), nonce, key
        )
    except CryptoError as exc:
        raise MnemonicBlobError(
            "AEAD authentication failed - wrong passphrase or SS58 mismatch"
        ) from exc
    try:
        return plaintext.decode()
    except UnicodeDecodeError as exc:
        raise MnemonicBlobError("decrypted mnemonic is not valid UTF-8") from exc
