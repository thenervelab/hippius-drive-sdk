"""Who is talking to the server: account namespace plus per-folder keys."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from nacl.signing import SigningKey

from hippius_drive.crypto import kdf

OWNER = "owner"
READER = "reader"
WRITER = "writer"
MANAGER = "manager"
_ROLES = frozenset({OWNER, READER, WRITER, MANAGER})
_MEMBER_ROLES = frozenset({READER, WRITER, MANAGER})
_FOLDER_HASH = re.compile(r"^[0-9a-f]{16}$")

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
    """Account namespace plus one folder's keys.

    ``account_ss58`` is the address that appears in request paths and salts
    ``salted_hash``. For a folder this account owns, that is the account the
    bearer token resolves to. For a shared drive it is the **owner's** address:
    the token belongs to the member, and the folder keys come from the owner's
    folder mnemonic. It is configuration, not derived from the mnemonic: no
    code path SS58-encodes a key.

    Attributes:
        account_ss58: The wire namespace. The token's account, or the drive owner.
        label: The human-readable folder name. Display-only on a shared drive.
        folder_hash: The server folder id. ``hex(SHA-256(label))[:16]`` when
            this account owns the folder; the owner's hash on a shared drive.
        keys: The folder's signing seed and encryption key.
        role: ``owner``, ``reader``, ``writer``, or ``manager``.
    """

    account_ss58: str
    label: str
    folder_hash: str
    keys: kdf.FolderKeys = field(repr=False)
    role: str = OWNER

    def __post_init__(self) -> None:
        """Reject an empty namespace or an unknown role before any request."""
        if not self.account_ss58:
            raise ValueError("account_ss58 is required; it is the account the token resolves to")
        if self.role not in _ROLES:
            raise ValueError("role must be owner, reader, writer, or manager")
        if self.role != OWNER and not _FOLDER_HASH.fullmatch(self.folder_hash):
            raise ValueError("folder_hash must be 16 lowercase hex characters")

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

    @classmethod
    def for_shared_drive(
        cls,
        folder_mnemonic: str,
        *,
        owner_ss58: str,
        folder_hash: str,
        role: str,
        label: str = "",
    ) -> Identity:
        """Build a member identity for someone else's drive.

        The encryption key is the owner's folder mnemonic, not a derivation
        from the member's master phrase. ``folder_hash`` is the owner's id
        from the invite; it is not recomputed from ``label``, because the
        display label can fall back to the hash when the registry row is gone.

        Args:
            folder_mnemonic: The owner's folder phrase, from the invite fragment.
            owner_ss58: The drive owner's account. Paths and ``salted_hash`` use it.
            folder_hash: The owner's 16-character lowercase hex folder id.
            role: ``reader``, ``writer``, or ``manager``.
            label: The owner's display label, when the invite meta has one.

        Returns:
            An identity a member's bearer token can use.

        Raises:
            ValueError: If the role, hash, or phrase is unusable.
        """
        if role not in _MEMBER_ROLES:
            raise ValueError("role must be reader, writer, or manager")
        return cls(
            account_ss58=owner_ss58,
            label=label,
            folder_hash=folder_hash,
            keys=kdf.folder_keys(folder_mnemonic),
            role=role,
        )

    def require_owner(self) -> None:
        """Refuse registry changes from a member.

        Raises:
            ValueError: If this identity is not the drive owner.
        """
        if self.role != OWNER:
            raise ValueError("only the drive owner can register or unregister a folder")

    def require_writer(self) -> None:
        """Refuse a modification from a reader.

        Raises:
            ValueError: If this identity's role is ``reader``.
        """
        if self.role == READER:
            raise ValueError("a reader cannot modify a shared drive")

    def scoped_folder_hash(self) -> str | None:
        """The folder a member's account-wide read must name.

        An owner omits it and the server searches the whole account. A member
        is admitted on those routes only when the query names the drive.

        Returns:
            The folder hash for a member, or None for an owner.
        """
        if self.role == OWNER:
            return None
        return self.folder_hash

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
