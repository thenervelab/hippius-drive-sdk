"""Master mnemonic to per-folder keys, mirroring hcfs-client ``drive/keys.rs``.

The chain is frozen: changing any step orphans every folder already stored
under the old derivation, because the server namespace is derived from it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from mnemonic import Mnemonic

_BIP39 = Mnemonic("english")

MASTER_ENTROPY_BYTES = 32
"""Entropy for a generated master phrase; 32 bytes is the 24-word size."""


@dataclass(frozen=True)
class FolderKeys:
    """The two 32-byte secrets a folder identity uses.

    Both are ``folder_seed[:32]``. Ed25519 consumes only a seed and
    XChaCha20-Poly1305 is a separate primitive, so hcfs shares the bytes
    between them. Do not generalise this pattern to new key material.

    Attributes:
        signing_seed: Ed25519 secret seed.
        encryption_key: XChaCha20-Poly1305 key, equal to ``signing_seed``.
    """

    signing_seed: bytes
    encryption_key: bytes


def _seed(phrase: str) -> bytes:
    if not _BIP39.check(phrase):
        raise ValueError("invalid BIP-39 mnemonic (bad word or checksum)")
    # The empty passphrase is load-bearing: the same words must give the same
    # keys on every device, so key derivation never sees the unlock password.
    return _BIP39.to_seed(phrase, passphrase="")


def folder_entropy(master_mnemonic: str, label: str) -> bytes:
    """Return ``SHA256(master_seed[:32] || label)``, the folder mnemonic's entropy.

    Args:
        master_mnemonic: The account's master BIP-39 phrase.
        label: The human-readable folder name.

    Returns:
        32 bytes of entropy.

    Raises:
        ValueError: If ``master_mnemonic`` is not a valid BIP-39 phrase.
    """
    return hashlib.sha256(_seed(master_mnemonic)[:32] + label.encode()).digest()


def derive_folder_mnemonic(master_mnemonic: str, label: str) -> str:
    """Derive the 24-word folder mnemonic for ``label`` from the master phrase.

    Args:
        master_mnemonic: The account's master BIP-39 phrase.
        label: The human-readable folder name.

    Returns:
        The 24-word folder phrase.

    Raises:
        ValueError: If ``master_mnemonic`` is not a valid BIP-39 phrase.
    """
    return _BIP39.to_mnemonic(folder_entropy(master_mnemonic, label))


def folder_hash(label: str) -> str:
    """Return the first 16 hex chars of ``SHA-256(label)``, the server folder id.

    Args:
        label: The human-readable folder name.

    Returns:
        A 16-character lowercase hex string.
    """
    return hashlib.sha256(label.encode()).hexdigest()[:16]


def folder_keys(folder_mnemonic: str) -> FolderKeys:
    """Return the signing seed and encryption key for a folder mnemonic.

    Args:
        folder_mnemonic: A folder BIP-39 phrase from ``derive_folder_mnemonic``.

    Returns:
        The folder's key pair material.

    Raises:
        ValueError: If ``folder_mnemonic`` is not a valid BIP-39 phrase.
    """
    head = _seed(folder_mnemonic)[:32]
    return FolderKeys(signing_seed=head, encryption_key=head)


def generate_master_mnemonic() -> str:
    """Generate a fresh 24-word master phrase from the OS entropy source.

    Returns:
        The new phrase. The caller is responsible for showing it exactly once
        and for storing it encrypted.
    """
    return _BIP39.generate(strength=MASTER_ENTROPY_BYTES * 8)
