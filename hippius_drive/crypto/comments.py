"""Share-link comment and viewer-name encryption, byte for byte the console's.

The scheme (hcfs ``docs/public/api/shares.md``, "Encryption"; the console's
``comment-crypto.ts`` at
https://github.com/thenervelab/hippius-console/blob/ebae2d8e5f8c347d65a7530a668f8a85196bbe2e/src/lib/files/share/insights/comment-crypto.ts):

``key = HKDF-SHA256(ikm=the 32-byte share key, salt=empty,
info="hippius-share-comments-v1", L=32)``, then AES-256-GCM with a 12-byte
nonce and the 16-byte tag appended. The AAD is ``<token>:comment`` or
``<token>:viewer-name``, so a ciphertext copied onto another link does not
open. A comment's plaintext is the compact JSON ``{"text":...,"name":...}``,
with ``"mentions"`` after them when it tags anyone; a viewer name's is
``{"name":...}``. The server stores the bytes and cannot read them.
``tests/vectors/share-comments-vectors.json`` is the console's vector file,
copied verbatim.

A named comment also sends a viewer id, so the owner's insights count it
under one viewer. It is the console's ``viewer-id.ts`` scheme:
``base64url(HMAC-SHA256(secret, token))[:16 bytes]``, unpadded, where the
secret is 32 random bytes the poster keeps. One secret gives one id per
link, and ids on two links cannot be tied together without it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

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

MAX_MENTIONS = 10
"""The console's limit on mentions in one comment; any past it are dropped."""

VIEWER_SECRET_LEN = 32
"""Bytes in a viewer secret, as the console's ``SECRET_BYTES``."""

_SHARE_KEY_LEN = 32
_NONCE_LEN = 12
_VIEWER_ID_LEN = 16

# The console's MAX_MENTION_REF_CHARS, in UTF-16 code units: comment ids
# are short server ids, and a longer reference is not one.
_MAX_MENTION_REF_UNITS = 128

# The console's display-name.ts: an access-key account's generated username
# is "user_" and its whole address, lowercased; a bare address is base58.
_GENERATED_USERNAME = re.compile(r"user_([1-9A-Za-z]{40,64})")
_BARE_ADDRESS = re.compile(r"[1-9A-HJ-NP-Za-km-z]{40,64}")

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
class CommentMention:
    """Someone a comment tags, sealed inside it so the server never learns who.

    The text carries the tag as ``@`` and ``name``; this says which ``@``
    is a mention and who it points at. A client without mentions still
    reads ``@Ada`` in the text.

    Attributes:
        kind: ``owner`` tags the link's owner. ``commenter`` tags someone
            who commented under a name.
        name: The name after the ``@`` in the text.
        comment: For ``commenter``, the id of one of their comments on this
            link, which is how their own client knows the mention is them.
    """

    kind: Literal["owner", "commenter"]
    name: str
    comment: str | None = None


@dataclass(frozen=True)
class CommentText:
    """An opened comment.

    Attributes:
        text: What the commenter wrote.
        name: The name they posted under, cleaned; None when anonymous or blank.
        mentions: Who it tags, cleaned as the console does; empty when nobody.
    """

    text: str
    name: str | None
    mentions: tuple[CommentMention, ...] = field(default=())


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


def comment_text(text: str) -> str:
    """The text as it will be sealed: lone surrogates as U+FFFD, trimmed.

    Raises:
        ValueError: If nothing is left, or it is over 2,000 characters.
    """
    clean = _well_formed(text).strip(_JS_TRIM)
    if not clean:
        raise ValueError("comment is empty")
    if len(clean) > MAX_COMMENT_CHARS:
        raise ValueError(f"comment is over {MAX_COMMENT_CHARS} characters")
    return clean


def seal_comment(
    key: bytes,
    token: str,
    text: str,
    *,
    name: str | None = None,
    mentions: Sequence[CommentMention] = (),
) -> SealedText:
    """Encrypt a comment under a fresh nonce, as the console's ``encryptComment``.

    Args:
        key: From :func:`comment_key`.
        token: The share token, bound into the AAD.
        text: The comment. Trimmed; lone surrogates become U+FFFD.
        name: The name to post under, cleaned by :func:`clean_name`; None
            seals ``"name": null``.
        mentions: Who it tags, in the order their ``@`` stands in the text.
            Cleaned and capped as :func:`parse_mentions` does.

    Returns:
        The ciphertext and nonce to post.

    Raises:
        ValueError: If the text is empty, over 2,000 characters, or seals to
            more than 4,096 bytes.
    """
    clean = comment_text(text)
    wire = [mention_wire(mention) for mention in mentions]
    plaintext = comment_plaintext(clean, clean_name(name), parse_mentions(wire))
    sealed = _seal(key, _aad(token, "comment"), plaintext, os.urandom(_NONCE_LEN))
    if len(base64.b64decode(sealed.ciphertext)) > MAX_COMMENT_CIPHERTEXT:
        raise ValueError(f"comment seals to more than {MAX_COMMENT_CIPHERTEXT} bytes")
    return sealed


def seal_viewer_name(key: bytes, token: str, name: str) -> SealedText:
    """Encrypt the name the owner's insights list a viewer under.

    Args:
        key: From :func:`comment_key`.
        token: The share token, bound into the AAD.
        name: Cleaned by :func:`clean_name` first.

    Raises:
        ValueError: If the name cleans to nothing.
    """
    clean = clean_name(name)
    if clean is None:
        raise ValueError("name is blank")
    plaintext = json.dumps({"name": clean}, ensure_ascii=False, separators=(",", ":")).encode()
    return _seal(key, _aad(token, "viewer-name"), plaintext, os.urandom(_NONCE_LEN))


def comment_plaintext(
    text: str, name: str | None, mentions: Sequence[CommentMention] = ()
) -> bytes:
    """The exact bytes the console seals for a comment.

    ``JSON.stringify`` output: no spaces, non-ASCII written as UTF-8, not
    escaped. ``mentions`` is left out when empty, so a comment without them
    seals to the bytes it always did. ``text``, ``name`` and the mentions
    must already be clean.
    """
    value: dict[str, object] = {"text": text, "name": name}
    if mentions:
        value["mentions"] = [mention_wire(mention) for mention in mentions]
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def mention_wire(mention: CommentMention) -> dict[str, str]:
    """A mention as the plaintext JSON holds it: ``comment`` only when set."""
    wire = {"kind": mention.kind, "name": mention.name}
    if mention.comment is not None:
        wire["comment"] = mention.comment
    return wire


def parse_mentions(raw: object) -> tuple[CommentMention, ...]:
    """The mentions a comment carries, cleaned, as the console's ``parseMentions``.

    Lenient on purpose: a malformed entry (another client's, or a newer
    kind) is dropped on its own and never makes the comment unreadable.
    Names are cleaned by :func:`clean_name`; past ten the rest are dropped.
    """
    if not isinstance(raw, list):
        return ()
    found: list[CommentMention] = []
    for item in raw:
        if len(found) >= MAX_MENTIONS:
            break
        mention = _one_mention(item)
        if mention is not None:
            found.append(mention)
    return tuple(found)


def _one_mention(item: object) -> CommentMention | None:
    if not isinstance(item, dict):
        return None
    kind = item.get("kind")
    raw_name = item.get("name")
    name = clean_name(raw_name if isinstance(raw_name, str) else None)
    if name is None:
        return None
    if kind == "owner":
        return CommentMention("owner", name)
    if kind != "commenter":
        return None
    comment = item.get("comment")
    if isinstance(comment, str) and 0 < _utf16_units(comment) <= _MAX_MENTION_REF_UNITS:
        return CommentMention("commenter", name, comment)
    return CommentMention("commenter", name)


def viewer_id(secret: bytes, token: str) -> str:
    """The viewer id a named comment on ``token`` is counted under.

    ``base64url(HMAC-SHA256(secret, token))[:16 bytes]``, unpadded: the
    console's ``getViewerId``. The same secret gives the same id on one
    link and unrelated ids on two.

    Args:
        secret: 32 random bytes the poster keeps.
        token: The share token.

    Raises:
        ValueError: If ``secret`` is not 32 bytes.
    """
    if len(secret) != VIEWER_SECRET_LEN:
        raise ValueError(f"viewer secret must be {VIEWER_SECRET_LEN} bytes, got {len(secret)}")
    mac = hmac.new(secret, token.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac[:_VIEWER_ID_LEN]).decode().rstrip("=")


def present_name(name: str | None) -> str | None:
    """A name as the console shows it: an access-key account's address shortened.

    The console's ``presentName``: a generated ``user_<address>`` username,
    or a whole SS58 address standing alone, shows as its first 6 and last 4
    characters; any other name is only trimmed. None for no name.
    """
    if name is None:
        return None
    trimmed = name.strip(_JS_TRIM)
    if not trimmed:
        return None
    generated = _GENERATED_USERNAME.fullmatch(trimmed)
    if generated:
        return short_address(generated.group(1))
    if _BARE_ADDRESS.fullmatch(trimmed):
        return short_address(trimmed)
    return trimmed


def short_address(ss58: str) -> str:
    """An address as the console shortens it: first 6, an ellipsis, last 4."""
    head, tail = 6, 4
    if len(ss58) <= head + tail + 2:
        return ss58
    return f"{ss58[:head]}\u2026{ss58[-tail:]}"


def open_comment(key: bytes, token: str, ciphertext: str, nonce: str) -> CommentText:
    """Decrypt a comment from the listing.

    Fields this SDK does not know are ignored. A malformed mention is
    dropped on its own, as the console does.

    Args:
        key: From :func:`comment_key`.
        token: The share token the comment was posted on.
        ciphertext: Standard base64 from the listing.
        nonce: Standard base64 from the listing.

    Returns:
        The text, the cleaned name, and the mentions that parse.

    Raises:
        DecryptError: If it does not open under this key and link, or is not
            a comment.
    """
    value = _open(key, _aad(token, "comment"), ciphertext, nonce)
    text = value.get("text") if isinstance(value, dict) else None
    name = value.get("name") if isinstance(value, dict) else None
    if not isinstance(text, str) or (name is not None and not isinstance(name, str)):
        raise DecryptError("share comment is not a comment")
    mentions = parse_mentions(value.get("mentions")) if isinstance(value, dict) else ()
    return CommentText(_well_formed(text), clean_name(name), mentions)


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


def _utf16_units(value: str) -> int:
    """The length JavaScript's ``String.length`` reports."""
    return len(value.encode("utf-16-le")) // 2


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
