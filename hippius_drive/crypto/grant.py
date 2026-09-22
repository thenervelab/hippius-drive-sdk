"""Shared-drive grant and invite-link crypto.

The grant passphrase and the sealed blob match the console
``shared-drives/grant.ts`` contract, which copies desktop ``grant.rs``:

* passphrase = hex(HKDF-SHA256(bip39_seed(member_master)[:64],
  salt = member_ss58, info = "hippius-drive-grant-v1"))
* the sealed payload is the owner's folder-mnemonic phrase, in the
  Argon2id mnemonic-blob format, AAD = the member's SS58
* the invite fragment is base64url of the 32-byte folder entropy

The invite token stored for the owner's panel is a separate HKDF seal.
The folder entropy is already uniform, so that seal does not run Argon2.
Opening it checks ``blake3(token) == invite_id``.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from urllib.parse import quote, unquote, urlsplit

import blake3
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from mnemonic import Mnemonic
from nacl import bindings
from nacl.exceptions import CryptoError

from hippius_drive.crypto import mnemonic_blob
from hippius_drive.crypto.mnemonic_blob import SealedBlob
from hippius_drive.errors import DecryptError

GRANT_INFO = b"hippius-drive-grant-v1"
INVITE_TOKEN_INFO = b"hippius-drive-invite-token-v1"
_KEY_LEN = 32
_NONCE_LEN = 24
_SEED_LEN = 64
_INVITE_VERSION = 1
_INVITE_PATH_LEN = 2
_BIP39 = Mnemonic("english")


def grant_passphrase(member_master: str, member_ss58: str) -> str:
    """Return the hex passphrase that seals this member's grant blobs.

    Args:
        member_master: The member's master BIP-39 phrase.
        member_ss58: The member's account address. It salts the HKDF.

    Returns:
        64 lowercase hex characters.

    Raises:
        ValueError: If ``member_master`` is not a valid BIP-39 phrase.
    """
    if not _BIP39.check(member_master):
        raise ValueError("invalid BIP-39 mnemonic (bad word or checksum)")
    seed = _BIP39.to_seed(member_master, passphrase="")
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=member_ss58.encode(),
        info=GRANT_INFO,
    ).derive(seed[:_SEED_LEN])
    return okm.hex()


def phrase_from_entropy(entropy: bytes) -> str:
    """Encode 32 bytes of folder entropy as a 24-word phrase.

    Args:
        entropy: The folder mnemonic's entropy.

    Returns:
        The BIP-39 phrase.

    Raises:
        ValueError: If ``entropy`` is not 32 bytes.
    """
    if len(entropy) != _KEY_LEN:
        raise ValueError(f"folder-key entropy must be {_KEY_LEN} bytes, got {len(entropy)}")
    return _BIP39.to_mnemonic(entropy)


def entropy_from_phrase(phrase: str) -> bytes:
    """Return the 32-byte entropy a folder phrase encodes.

    Args:
        phrase: A 24-word BIP-39 phrase.

    Returns:
        The entropy.

    Raises:
        ValueError: If ``phrase`` is not a valid 24-word BIP-39 phrase.
    """
    if not _BIP39.check(phrase):
        raise ValueError("invalid BIP-39 mnemonic (bad word or checksum)")
    entropy = bytes(_BIP39.to_entropy(phrase))
    if len(entropy) != _KEY_LEN:
        raise ValueError(f"folder-key entropy must be {_KEY_LEN} bytes, got {len(entropy)}")
    return entropy


def console_origin(console_base_url: str) -> str:
    """Return ``console_base_url`` without a trailing slash.

    Checked before an invite is minted. A bad origin must not leave a live
    invite whose token the caller never sees.

    Args:
        console_base_url: Console origin the recipient URL is built against.

    Returns:
        The origin.

    Raises:
        ValueError: If the origin is not https.
    """
    trimmed = console_base_url.rstrip("/")
    if not trimmed.startswith("https://"):
        raise ValueError("console_base_url must be an https origin")
    return trimmed


def invite_url(console_base_url: str, token: str, entropy: bytes) -> str:
    """Build ``{base}/invite/{token}#k={entropy}``.

    Args:
        console_base_url: Console origin, trailing slash ignored.
        token: The plaintext invite token.
        entropy: 32-byte folder entropy. This is the drive key.

    Returns:
        The invite URL. The fragment is not sent to the server.

    Raises:
        ValueError: If the origin, token, or entropy is unusable.
    """
    if len(entropy) != _KEY_LEN:
        raise ValueError(f"folder-key entropy must be {_KEY_LEN} bytes, got {len(entropy)}")
    trimmed = console_origin(console_base_url)
    if not token or "/" in token or "#" in token:
        raise ValueError("invite token must be a single path segment")
    fragment = base64.urlsafe_b64encode(entropy).rstrip(b"=").decode()
    return f"{trimmed}/invite/{quote(token, safe='')}#k={fragment}"


def parse_invite_url(url: str) -> tuple[str, bytes]:
    """Split an invite URL into its token and folder entropy.

    Args:
        url: An invite URL.

    Returns:
        ``(token, entropy)``.

    Raises:
        ValueError: If the URL is not an invite link or the fragment is short.
    """
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.netloc:
        raise ValueError("invite URL must be an absolute https URL")
    segments = [segment for segment in parts.path.split("/") if segment]
    if len(segments) != _INVITE_PATH_LEN or segments[0] != "invite":
        raise ValueError("invite URL path must be /invite/{token}")
    if not parts.fragment.startswith("k="):
        raise ValueError("invite URL needs a #k= fragment")
    raw = parts.fragment[2:]
    pad = "=" * (-len(raw) % 4)
    try:
        entropy = base64.urlsafe_b64decode(raw + pad)
    except binascii.Error as exc:
        raise ValueError("invite fragment is not base64url") from exc
    if len(entropy) != _KEY_LEN:
        raise ValueError(f"folder-key entropy must be {_KEY_LEN} bytes, got {len(entropy)}")
    return unquote(segments[1]), entropy


def seal_grant(member_master: str, member_ss58: str, folder_phrase: str) -> bytes:
    """Seal ``folder_phrase`` for ``member_ss58``.

    Args:
        member_master: The member's master phrase. It derives the passphrase.
        member_ss58: The member's account. It salts HKDF and is the AEAD AAD.
        folder_phrase: The owner's folder mnemonic.

    Returns:
        The SealedBlob JSON bytes. The HTTP field is their standard base64.
    """
    passphrase = grant_passphrase(member_master, member_ss58)
    blob = mnemonic_blob.seal(folder_phrase, passphrase, member_ss58)
    return blob.model_dump_json().encode()


def open_grant(member_master: str, member_ss58: str, blob_json: bytes) -> str:
    """Open a grant blob and return the folder mnemonic phrase.

    Args:
        member_master: The member's master phrase.
        member_ss58: The member the blob was sealed for.
        blob_json: The SealedBlob JSON bytes (not the base64 wire form).

    Returns:
        The folder mnemonic phrase.

    Raises:
        DecryptError: If the blob is malformed or does not open.
    """
    try:
        blob = SealedBlob.model_validate_json(blob_json)
        return mnemonic_blob.open_blob(
            blob, grant_passphrase(member_master, member_ss58), member_ss58
        )
    except (ValueError, mnemonic_blob.MnemonicBlobError) as exc:
        raise DecryptError("grant blob did not open") from exc


def seal_invite_token(
    folder_entropy: bytes,
    invite_id: str,
    token: str,
    *,
    nonce: bytes | None = None,
) -> bytes:
    """Seal an invite token under the drive key.

    Args:
        folder_entropy: 32-byte folder entropy, the HKDF input.
        invite_id: Blake3 hex of ``token``. Salt and AAD.
        token: The plaintext invite token.
        nonce: 24-byte nonce; random when omitted.

    Returns:
        JSON bytes ``{"v", "nonce", "ciphertext"}``. The wire field is their
        standard base64.

    Raises:
        ValueError: If the entropy or nonce has the wrong length, or
            ``blake3(token)`` is not ``invite_id``.
    """
    if blake3.blake3(token.encode()).hexdigest() != invite_id:
        raise ValueError("invite_id must be blake3 hex of the invite token")
    used = os.urandom(_NONCE_LEN) if nonce is None else nonce
    if len(used) != _NONCE_LEN:
        raise ValueError(f"invite nonce must be {_NONCE_LEN} bytes, got {len(used)}")
    key = _invite_key(folder_entropy, invite_id)
    sealed = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        token.encode(), invite_id.encode(), used, key
    )
    body = {
        "v": _INVITE_VERSION,
        "nonce": base64.b64encode(used).decode(),
        "ciphertext": base64.b64encode(sealed).decode(),
    }
    return json.dumps(body, separators=(",", ":")).encode()


def open_invite_token(folder_entropy: bytes, invite_id: str, sealed_json: bytes) -> str:
    """Open an invite-token seal and check it against ``invite_id``.

    A mismatch is treated as a blob that did not open. The salt binds the
    blob to a row, not to the token that row stands for, so the check is
    what stops a swapped plaintext from being copied out under this invite.

    Args:
        folder_entropy: 32-byte folder entropy.
        invite_id: The row the blob was opened against.
        sealed_json: The JSON bytes (not the base64 wire form).

    Returns:
        The plaintext invite token.

    Raises:
        DecryptError: If the blob does not open or names a different token.
    """
    try:
        parsed = json.loads(sealed_json)
        if not isinstance(parsed, dict) or parsed.get("v") != _INVITE_VERSION:
            raise DecryptError("invite seal did not open")
        nonce = base64.b64decode(parsed["nonce"], validate=True)
        ciphertext = base64.b64decode(parsed["ciphertext"], validate=True)
    except (KeyError, ValueError, binascii.Error, json.JSONDecodeError) as exc:
        raise DecryptError("invite seal did not open") from exc
    if len(nonce) != _NONCE_LEN:
        raise DecryptError("invite seal did not open")
    key = _invite_key(folder_entropy, invite_id)
    try:
        token = bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, invite_id.encode(), nonce, key
        ).decode()
    except (CryptoError, UnicodeDecodeError) as exc:
        raise DecryptError("invite seal did not open") from exc
    if blake3.blake3(token.encode()).hexdigest() != invite_id:
        raise DecryptError("invite seal did not open")
    return token


def _invite_key(folder_entropy: bytes, invite_id: str) -> bytes:
    if len(folder_entropy) != _KEY_LEN:
        raise ValueError(f"folder-key entropy must be {_KEY_LEN} bytes, got {len(folder_entropy)}")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=invite_id.encode(),
        info=INVITE_TOKEN_INFO,
    ).derive(folder_entropy)
