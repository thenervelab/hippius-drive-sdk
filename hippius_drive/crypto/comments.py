"""Share-link comment and viewer-name encryption, byte for byte the console's.

The scheme (hcfs ``docs/public/api/shares.md``, "Encryption"; the console's
``comment-crypto.ts`` at
https://github.com/thenervelab/hippius-console/blob/ebae2d8e5f8c347d65a7530a668f8a85196bbe2e/src/lib/files/share/insights/comment-crypto.ts):

``key = HKDF-SHA256(ikm=the 32-byte share key, salt=empty,
info="hippius-share-comments-v1", L=32)``, then AES-256-GCM with a 12-byte
nonce and the 16-byte tag appended. The AAD is ``<token>:comment`` or
``<token>:viewer-name``, so a ciphertext copied onto another link does not
open. A comment's plaintext is the compact JSON ``{"text":...,"name":...}``;
a viewer name's is ``{"name":...}``. The server stores the bytes and cannot
read them. ``tests/vectors/share-comments-vectors.json`` is the console's
vector file, copied verbatim.
"""

from __future__ import annotations

import base64
import json
import os
import unicodedata
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from hippius_drive.errors import DecryptError

COMMENT_KEY_INFO = b"hippius-share-comments-v1"
"""HKDF info string. Changing it orphans every comment already posted."""

MAX_COMMENT_CHARS = 2000
"""The console's limit, in code points. The server caps the ciphertext instead."""

MAX_COMMENT_CIPHERTEXT = 4096
"""hcfs refuses a larger ciphertext with ``413``."""

MAX_NAME_CHARS = 80
"""Names are cut to this many code points, as the console does."""

_SHARE_KEY_LEN = 32
_NONCE_LEN = 12

# ECMAScript String.prototype.trim: WhiteSpace plus LineTerminator. Python's
# str.strip() also strips U+0085 and U+001C-U+001F, which JS keeps, and the
# shared vectors pin that ("next line is not trimmed").
_JS_TRIM = (
    "\t\n\v\f\r \xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008"
    "\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)

# Bidi embedding, override and isolate controls. Inside a name they reorder
# it (U+202E before "Eve" shows "evE"), so they are removed. LRM, RLM and ALM stay:
# mixed-direction names need them.
_BIDI_CONTROLS = {cp: None for cp in (*range(0x202A, 0x202F), *range(0x2066, 0x206A))}

# Unicode White_Space (PropList.txt). unicodedata has no property lookup.
_WHITE_SPACE = frozenset(
    (
        *range(0x09, 0x0E),
        *(0x20, 0x85, 0xA0, 0x1680),
        *range(0x2000, 0x200B),
        *(0x2028, 0x2029, 0x202F, 0x205F, 0x3000),
    )
)

# Unicode Default_Ignorable_Code_Point (DerivedCoreProperties.txt), inclusive
# ranges. unicodedata does not expose it either.
_DEFAULT_IGNORABLE = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)

# Prepended concatenation marks are Cf but draw a glyph, so they never make
# a name blank.
_PREPENDED_MARKS = frozenset(
    (*range(0x0600, 0x0606), 0x06DD, 0x070F, 0x0890, 0x0891, 0x08E2, 0x110BD, 0x110CD)
)

# The console's RESERVED_NAMES (claimed-names.ts): only the owner's badge or
# Hippius itself could carry these, so a commenter using one is marked.
_RESERVED_NAMES = frozenset(
    {"owner", "theowner", "linkowner", "fileowner", "support", "admin", "administrator"}
)

_BRAILLE_BLANK = 0x2800
_SURROGATES = range(0xD800, 0xE000)


@dataclass(frozen=True)
class SealedText:
    """A sealed comment as the wire carries it.

    Attributes:
        ciphertext: Standard base64, tag appended.
        nonce: Standard base64 of the 12-byte nonce.
    """

    ciphertext: str
    nonce: str


@dataclass(frozen=True)
class CommentText:
    """An opened comment.

    Attributes:
        text: What the commenter wrote.
        name: The name they posted under, cleaned; None when anonymous or blank.
    """

    text: str
    name: str | None


def comment_key(share_key: bytes) -> bytes:
    """Derive the comment key from a link's 32-byte share key.

    Args:
        share_key: The ``#k=`` key, or a ``#p=`` link's key after unlocking.

    Returns:
        The 32-byte AES-256-GCM key.

    Raises:
        ValueError: If ``share_key`` is not 32 bytes.
    """
    if len(share_key) != _SHARE_KEY_LEN:
        raise ValueError(f"share key must be {_SHARE_KEY_LEN} bytes, got {len(share_key)}")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=COMMENT_KEY_INFO)
    return hkdf.derive(share_key)


def seal_comment(key: bytes, token: str, text: str) -> SealedText:
    """Encrypt an anonymous comment (``"name": null``) under a fresh nonce.

    Args:
        key: From :func:`comment_key`.
        token: The share token, bound into the AAD.
        text: The comment. Trimmed; lone surrogates become U+FFFD.

    Returns:
        The ciphertext and nonce to post.

    Raises:
        ValueError: If the text is empty, over 2,000 characters, or seals to
            more than 4,096 bytes.
    """
    clean = _well_formed(text).strip(_JS_TRIM)
    if not clean:
        raise ValueError("comment is empty")
    if len(clean) > MAX_COMMENT_CHARS:
        raise ValueError(f"comment is over {MAX_COMMENT_CHARS} characters")
    plaintext = comment_plaintext(clean, None)
    sealed = _seal(key, _aad(token, "comment"), plaintext, os.urandom(_NONCE_LEN))
    if len(base64.b64decode(sealed.ciphertext)) > MAX_COMMENT_CIPHERTEXT:
        raise ValueError(f"comment seals to more than {MAX_COMMENT_CIPHERTEXT} bytes")
    return sealed


def comment_plaintext(text: str, name: str | None) -> bytes:
    """The exact bytes the console seals for a comment without mentions.

    ``JSON.stringify`` output: no spaces, non-ASCII written as UTF-8, not
    escaped. ``text`` and ``name`` must already be well formed.
    """
    return json.dumps(
        {"text": text, "name": name}, ensure_ascii=False, separators=(",", ":")
    ).encode()


def open_comment(key: bytes, token: str, ciphertext: str, nonce: str) -> CommentText:
    """Decrypt a comment from the listing.

    Fields this SDK does not know (the console's ``mentions``) are ignored;
    the text still reads ``@Name``.

    Args:
        key: From :func:`comment_key`.
        token: The share token the comment was posted on.
        ciphertext: Standard base64 from the listing.
        nonce: Standard base64 from the listing.

    Returns:
        The text and the cleaned name.

    Raises:
        DecryptError: If it does not open under this key and link, or is not
            a comment.
    """
    value = _open(key, _aad(token, "comment"), ciphertext, nonce)
    text = value.get("text") if isinstance(value, dict) else None
    name = value.get("name") if isinstance(value, dict) else None
    if not isinstance(text, str) or (name is not None and not isinstance(name, str)):
        raise DecryptError("share comment is not a comment")
    return CommentText(_well_formed(text), clean_name(name))


def open_viewer_name(
    key: bytes, token: str, ciphertext: str | None, nonce: str | None
) -> str | None:
    """Decrypt a viewer's name from insights, or None when it is absent or will not open.

    A name that does not open is shown as no name, as the console does: any
    signed-in account can post bytes the owner's key cannot read, and that
    must not hide the rest of the insights.

    Args:
        key: From :func:`comment_key`.
        token: The share token.
        ciphertext: ``name_ct`` from insights.
        nonce: ``name_nonce`` from insights.

    Returns:
        The cleaned name, or None.
    """
    if not ciphertext or not nonce:
        return None
    try:
        value = _open(key, _aad(token, "viewer-name"), ciphertext, nonce)
    except DecryptError:
        return None
    name = value.get("name") if isinstance(value, dict) else None
    return clean_name(name if isinstance(name, str) else None)


def clean_name(name: str | None) -> str | None:
    """Clean a name by the console's ``cleanName`` rule, or None when nothing visible is left.

    Lone surrogates become U+FFFD, bidi controls are removed, the name is
    trimmed and cut to 80 code points. The console cuts between graphemes
    where the browser can; this cuts between code points, as the console does
    in a browser without ``Intl.Segmenter``. The two differ only for a name
    over 80 code points whose cut falls inside a grapheme of several code
    points (an emoji sequence, a letter with a combining mark, a Hangul or
    Indic cluster).

    Args:
        name: A decrypted name.

    Returns:
        The name to show, or None.
    """
    if name is None:
        return None
    stripped = _well_formed(name).translate(_BIDI_CONTROLS).strip(_JS_TRIM)
    kept = stripped[:MAX_NAME_CHARS].rstrip(_JS_TRIM)
    if all(_invisible(char) for char in kept):
        return None
    return kept


def claim_key(name: str) -> str:
    """A name as a reader takes it: NFKC, lower case, no spaces or format characters.

    The console's ``normalizeClaimedName``: "Hippius  Support" and
    "hippiussupport" are the same claim.
    """
    folded = unicodedata.normalize("NFKC", name).lower()
    return "".join(c for c in folded if c not in _JS_TRIM and unicodedata.category(c) != "Cf")


def is_reserved_name(name: str) -> bool:
    """Whether a name passes itself off as Hippius, or as the owner by title."""
    key = claim_key(name)
    return "hippius" in key or key in _RESERVED_NAMES


def _invisible(char: str) -> bool:
    point = ord(char)
    if point in _PREPENDED_MARKS:
        return False
    if point in _WHITE_SPACE or point == _BRAILLE_BLANK:
        return True
    if unicodedata.category(char) in ("Cc", "Cf"):
        return True
    return any(low <= point <= high for low, high in _DEFAULT_IGNORABLE)


def _well_formed(value: str) -> str:
    """Replace lone surrogates with U+FFFD.

    ``json.loads`` joins an escaped pair into one code point, so any
    surrogate left in a Python string has no partner.
    """
    return "".join("\ufffd" if ord(char) in _SURROGATES else char for char in value)


def _aad(token: str, kind: str) -> bytes:
    return f"{token}:{kind}".encode()


def _seal(key: bytes, aad: bytes, plaintext: bytes, nonce: bytes) -> SealedText:
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return SealedText(_b64(ciphertext), _b64(nonce))


def _open(key: bytes, aad: bytes, ciphertext: str, nonce: str) -> object:
    try:
        sealed = base64.b64decode(ciphertext, validate=True)
        iv = base64.b64decode(nonce, validate=True)
    except ValueError as exc:
        raise DecryptError("share comment is not base64") from exc
    if len(iv) != _NONCE_LEN:
        raise DecryptError(f"share comment nonce must be {_NONCE_LEN} bytes")
    try:
        plaintext = AESGCM(key).decrypt(iv, sealed, aad)
    except InvalidTag as exc:
        raise DecryptError("share comment does not open under this link's key") from exc
    try:
        # TextDecoder, which the console reads with, drops one leading BOM.
        return json.loads(plaintext.decode("utf-8-sig"))
    except ValueError as exc:
        raise DecryptError("share comment is not JSON") from exc


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()
