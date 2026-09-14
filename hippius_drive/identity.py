"""Who is talking to the server: account namespace plus per-folder keys."""

from __future__ import annotations

from dataclasses import dataclass, field

from nacl.signing import SigningKey

from hippius_drive.crypto import kdf

_TOS = (
    "I here by declare that the file with hash {} that i am uploading is in par "
    "with the ToS of the provider"
)
_RENAME = (
    "I hereby declare that I am renaming the following files on HCFS with the "
    "understanding that I have read and agree to the Terms of Service: "
)


def tos_text(ciphertext_hash: str) -> str:
    """Return the exact string hcfs signs for an upload.

    The server rebuilds this text and verifies the signature against it, so the
    wording is wire format rather than a message: never reword it.

    Args:
        ciphertext_hash: Hex BLAKE3 of the whole ciphertext blob.

    Returns:
        The declaration to sign.
    """
    return _TOS.format(ciphertext_hash)


def rename_text(pairs: list[tuple[bytes, bytes]]) -> str:
    """Return the rename declaration over ``(old_path_hash, new_path_hash)`` pairs.

    The server sorts by ``old_path_hash`` in lexicographic byte order before it
    verifies, so the client must sort before it signs.

    Args:
        pairs: One ``(old_path_hash, new_path_hash)`` tuple per rename.

    Returns:
        The declaration to sign.
    """
    ordered = sorted(pairs, key=lambda pair: pair[0])
    return _RENAME + ",".join(f"{old.hex()}:{new.hex()}" for old, new in ordered)


@dataclass(frozen=True)
class Identity:
    """Account address (the server namespace) plus one folder's keys.

    ``account_ss58`` is the Hippius account the bearer token resolves to. It is
    configuration, not derived from the mnemonic: no code path SS58-encodes a
    key, and the server refuses any request whose path address does not match
    the token's own.

    Attributes:
        account_ss58: The account address the bearer token resolves to.
        label: The human-readable folder name.
        folder_hash: ``hex(SHA-256(label))[:16]``, the server folder id.
        keys: The folder's signing seed and encryption key.
    """

    account_ss58: str
    label: str
    folder_hash: str
    keys: kdf.FolderKeys = field(repr=False)

    def __post_init__(self) -> None:
        """Reject an empty namespace up front rather than at the first 403."""
        if not self.account_ss58:
            raise ValueError("account_ss58 is required; it is the account the token resolves to")

    @classmethod
    def from_master(cls, master_mnemonic: str, label: str, *, account_ss58: str) -> Identity:
        """Derive the folder identity for ``label`` from a master phrase.

        Args:
            master_mnemonic: The account's master BIP-39 phrase.
            label: The human-readable folder name.
            account_ss58: The account address the bearer token resolves to.

        Returns:
            The identity for that folder.
        """
        folder = kdf.derive_folder_mnemonic(master_mnemonic, label)
        return cls.from_folder_mnemonic(folder, label, account_ss58=account_ss58)

    @classmethod
    def from_folder_mnemonic(
        cls, folder_mnemonic: str, label: str, *, account_ss58: str
    ) -> Identity:
        """Build an identity from an already-derived folder mnemonic.

        Args:
            folder_mnemonic: The folder's own BIP-39 phrase.
            label: The human-readable folder name.
            account_ss58: The account address the bearer token resolves to.

        Returns:
            The identity for that folder.
        """
        return cls(
            account_ss58=account_ss58,
            label=label,
            folder_hash=kdf.folder_hash(label),
            keys=kdf.folder_keys(folder_mnemonic),
        )

    @property
    def encryption_key(self) -> bytes:
        """The 32-byte XChaCha20-Poly1305 key for this folder."""
        return self.keys.encryption_key

    @property
    def verifying_key(self) -> bytes:
        """The 32-byte Ed25519 public key sent as ``signing_key`` in manifests."""
        return bytes(SigningKey(self.keys.signing_seed).verify_key)

    def sign(self, message: bytes) -> bytes:
        """Return a detached 64-byte Ed25519 signature over ``message``.

        Args:
            message: The bytes to sign.

        Returns:
            The signature.
        """
        return SigningKey(self.keys.signing_seed).sign(message).signature

    def sign_ciphertext_hash(self, ciphertext_hash: str) -> bytes:
        """Return the signature that goes into ``Manifest.signature``.

        Args:
            ciphertext_hash: Hex BLAKE3 of the whole ciphertext blob.

        Returns:
            The signature over the ToS declaration.
        """
        return self.sign(tos_text(ciphertext_hash).encode())
