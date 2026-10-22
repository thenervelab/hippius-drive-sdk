"""Link-secret (``#i=``) invite crypto, matching hcfs ``client/invite_link.rs``.

A ``#k=`` invite carries the drive key in its fragment. A ``#i=`` invite
carries a link secret instead; the key sits on the server, sealed under that
secret, and is released only to a signed-in account that proves it holds it:

* link_secret = derive_key("hippius.hcfs.invite-link-secret.v1",
  drive_entropy || blake3(token))
* k_fetch = derive_key("hippius.hcfs.invite-link-fetch.v1", link_secret)
* k_wrap = derive_key("hippius.hcfs.invite-link-wrap.v1", link_secret)
* envelope = 0x01 || nonce(24) || XChaCha20-Poly1305(k_wrap, key32,
  aad = "hippius.hcfs.invite-link-envelope.v1" || 0x01 || kind)

``kind`` is 0x01 for a whole drive (key32 is the drive entropy) and 0x02 for
a folder (key32 is the drive's derived file key). It is in the AAD, so an
envelope never opens as the other kind.
"""

from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import quote, unquote, urlsplit

import blake3
from nacl import bindings
from nacl.exceptions import CryptoError

from hippius_drive.errors import DecryptError

SECRET_CONTEXT = "hippius.hcfs.invite-link-secret.v1"  # noqa: S105 - a KDF context, not a secret
FETCH_CONTEXT = "hippius.hcfs.invite-link-fetch.v1"
WRAP_CONTEXT = "hippius.hcfs.invite-link-wrap.v1"
ENVELOPE_AAD_PREFIX = b"hippius.hcfs.invite-link-envelope.v1\x01"
ENVELOPE_VERSION = 1
ENVELOPE_LEN = 73
_KEY_LEN = 32
_NONCE_LEN = 24
_INVITE_PATH_LEN = 2


class InviteLinkKind(Enum):
    """What an envelope seals. The value is the server's ``kind`` string."""

    DRIVE = "drive"
    FOLDER = "folder"

    @property
    def aad_byte(self) -> int:
        """The kind byte that ends the envelope AAD."""
        return 0x01 if self is InviteLinkKind.DRIVE else 0x02


class FragmentForm(Enum):
    """Which fragment an invite URL carries."""

    LEGACY_KEY = "k"
    LINK_SECRET = "i"  # noqa: S105 - the fragment prefix


@dataclass(frozen=True)
class InviteFragment:
    """A parsed invite URL. ``material`` is a key either way and stays out of repr.

    Attributes:
        token: The plaintext invite token from the path.
        form: ``LEGACY_KEY`` for ``#k=``, ``LINK_SECRET`` for ``#i=``.
        material: The 32 fragment bytes: the key itself for ``#k=``, the
            link secret for ``#i=``.
    """

    token: str
    form: FragmentForm
    material: bytes = field(repr=False)


def parse_invite_link(url: str) -> InviteFragment:
    """Split an invite URL into its token and fragment, either form.

    Args:
        url: ``https://{origin}/invite/{token}#k=...`` or ``#i=...``.

    Returns:
        The token, the fragment form, and its 32 bytes.

    Raises:
        ValueError: If the URL is not an https invite link, or the fragment
            is not ``k=`` or ``i=`` followed by 32 bytes of base64url.
    """
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.netloc:
        raise ValueError("invite URL must be an absolute https URL")
    segments = [segment for segment in parts.path.split("/") if segment]
    if len(segments) != _INVITE_PATH_LEN or segments[0] != "invite":
        raise ValueError("invite URL path must be /invite/{token}")
    form = _fragment_form(parts.fragment)
    raw = parts.fragment[2:]
    pad = "=" * (-len(raw) % 4)
    try:
        material = base64.urlsafe_b64decode(raw + pad)
    except binascii.Error as exc:
        raise ValueError("invite fragment is not base64url") from exc
    if len(material) != _KEY_LEN:
        raise ValueError(f"invite fragment must be {_KEY_LEN} bytes, got {len(material)}")
    # hcfs decodes with URL_SAFE_NO_PAD: no padding, no "+" or "/", no
    # stray trailing bits. Only the canonical encoding round-trips.
    if base64.urlsafe_b64encode(material).rstrip(b"=").decode() != raw:
        raise ValueError("invite fragment is not unpadded base64url")
    return InviteFragment(unquote(segments[1]), form, material)


def invite_link_url(console_origin: str, token: str, link_secret: bytes) -> str:
    """Build ``{origin}/invite/{token}#i={b64url(link_secret)}``.

    Args:
        console_origin: An https console origin without a trailing slash.
        token: The plaintext invite token, a single base64url path segment.
        link_secret: The invite's 32-byte link secret.

    Returns:
        The invite URL. The fragment is not sent to the server.

    Raises:
        ValueError: If the origin is not https, the token is not one path
            segment, or the secret is not 32 bytes.
    """
    _check_len("link secret", link_secret)
    if not console_origin.startswith("https://") or console_origin.endswith("/"):
        raise ValueError("console origin must be https with no trailing slash")
    if not token or "/" in token or "#" in token:
        raise ValueError("invite token must be a single path segment")
    fragment = base64.urlsafe_b64encode(link_secret).rstrip(b"=").decode()
    return f"{console_origin}/invite/{quote(token, safe='')}#i={fragment}"


def invite_id_for_token(token: str) -> bytes:
    """Return ``blake3(token)``, raw. The server's ``invite_id`` is its hex."""
    return blake3.blake3(token.encode()).digest()


def derive_link_secret(drive_entropy: bytes, invite_id: bytes) -> bytes:
    """Derive an invite's link secret.

    Always from the drive entropy, folder invites included: a folder-grant
    member holds only the file key and so cannot derive any invite's secret.

    Args:
        drive_entropy: The 32-byte drive entropy.
        invite_id: The 32 raw bytes of ``blake3(token)``, not their hex.

    Returns:
        The 32-byte link secret.

    Raises:
        ValueError: If either input is not 32 bytes.
    """
    _check_len("drive entropy", drive_entropy)
    _check_len("invite id", invite_id)
    return _derive(SECRET_CONTEXT, drive_entropy + invite_id)


def fetch_key(link_secret: bytes) -> bytes:
    """The key whose unpadded base64url is the ``x-hcfs-link-proof`` header."""
    _check_len("link secret", link_secret)
    return _derive(FETCH_CONTEXT, link_secret)


def wrap_key(link_secret: bytes) -> bytes:
    """The key that seals and opens the envelope."""
    _check_len("link secret", link_secret)
    return _derive(WRAP_CONTEXT, link_secret)


def fetch_proof(link_secret: bytes) -> str:
    """Return the ``x-hcfs-link-proof`` header value: unpadded base64url of ``k_fetch``."""
    return base64.urlsafe_b64encode(fetch_key(link_secret)).rstrip(b"=").decode()


def fetch_digest(link_secret: bytes) -> bytes:
    """Return ``blake3(k_fetch)``, what the server stores to check the proof."""
    return blake3.blake3(fetch_key(link_secret)).digest()


def seal_envelope(
    link_secret: bytes, key: bytes, kind: InviteLinkKind, *, nonce: bytes | None = None
) -> bytes:
    """Seal ``key`` into a version-1 envelope.

    Args:
        link_secret: The invite's link secret.
        key: The drive entropy for ``DRIVE``, the derived file key for ``FOLDER``.
        kind: What ``key`` is. It is bound into the AAD.
        nonce: 24 bytes; random when omitted. Fixed only in tests.

    Returns:
        The 73-byte envelope.

    Raises:
        ValueError: If a length is wrong.
    """
    _check_len("envelope key", key)
    used = os.urandom(_NONCE_LEN) if nonce is None else nonce
    if len(used) != _NONCE_LEN:
        raise ValueError(f"envelope nonce must be {_NONCE_LEN} bytes, got {len(used)}")
    sealed = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        key, _aad(kind), used, wrap_key(link_secret)
    )
    return bytes([ENVELOPE_VERSION]) + used + sealed


def open_envelope(link_secret: bytes, envelope: bytes, kind: InviteLinkKind) -> bytes:
    """Open a version-1 envelope as ``kind`` and return the sealed key.

    Args:
        link_secret: The invite's link secret.
        envelope: The 73 envelope bytes.
        kind: The kind the caller expects. Any other kind fails to open.

    Returns:
        The 32-byte key.

    Raises:
        DecryptError: For a wrong length or version, a wrong secret, the
            other kind, or tampering.
    """
    if len(envelope) != ENVELOPE_LEN or envelope[0] != ENVELOPE_VERSION:
        raise DecryptError("invite link envelope is malformed")
    nonce, ciphertext = envelope[1 : 1 + _NONCE_LEN], envelope[1 + _NONCE_LEN :]
    try:
        key = bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, _aad(kind), nonce, wrap_key(link_secret)
        )
    except CryptoError as exc:
        raise DecryptError("invite link envelope did not open") from exc
    return key  # 73 bytes = version + nonce + 32-byte key + 16-byte tag


def _fragment_form(fragment: str) -> FragmentForm:
    for form in FragmentForm:
        if fragment.startswith(f"{form.value}="):
            return form
    raise ValueError("invite URL needs a #k= or #i= fragment")


def _aad(kind: InviteLinkKind) -> bytes:
    return ENVELOPE_AAD_PREFIX + bytes([kind.aad_byte])


def _derive(context: str, material: bytes) -> bytes:
    return blake3.blake3(material, derive_key_context=context).digest()


def _check_len(name: str, value: bytes) -> None:
    if len(value) != _KEY_LEN:
        raise ValueError(f"{name} must be {_KEY_LEN} bytes, got {len(value)}")
