"""Share-link comments against the console's own vector file.

``tests/vectors/share-comments-vectors.json`` is the console's
``share-comments-vectors.json``, copied verbatim; the desktop app replays the
same file. A failure here means this SDK would post comments the console
cannot read, or misread the console's.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hypothesis import given
from hypothesis import strategies as st

from hippius_drive.crypto import comments
from hippius_drive.errors import DecryptError

VECTORS: dict[str, Any] = json.loads(
    (Path(__file__).parent.parent / "vectors" / "share-comments-vectors.json").read_text("utf-8")
)
SHARE_KEY = bytes.fromhex(VECTORS["share_key_hex"])
TOKEN: str = VECTORS["token"]
KEY = comments.comment_key(SHARE_KEY)


def _vector(kind: str) -> dict[str, str]:
    return next(v for v in VECTORS["vectors"] if v["kind"] == kind)


def test_the_comment_key_matches_the_console() -> None:
    assert KEY.hex() == VECTORS["comment_key_hex"]


def test_a_share_key_of_the_wrong_length_is_refused() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        comments.comment_key(b"\x00" * 31)


@pytest.mark.parametrize("kind", ["comment", "comment-anonymous"])
def test_the_plaintext_and_ciphertext_match_the_console(kind: str) -> None:
    vector = _vector(kind)
    parsed = json.loads(vector["plaintext"])

    plaintext = comments.comment_plaintext(parsed["text"], parsed["name"])
    assert plaintext.decode() == vector["plaintext"]

    nonce = base64.b64decode(vector["nonce_b64"])
    sealed = AESGCM(KEY).encrypt(nonce, plaintext, vector["aad"].encode())
    assert base64.b64encode(sealed).decode() == vector["ciphertext_b64"]


@pytest.mark.parametrize("kind", ["comment", "comment-anonymous", "comment-mentions"])
def test_console_comments_open(kind: str) -> None:
    vector = _vector(kind)
    expected = json.loads(vector["plaintext"])

    opened = comments.open_comment(KEY, TOKEN, vector["ciphertext_b64"], vector["nonce_b64"])

    mentions = comments.parse_mentions(expected.get("mentions"))
    assert opened == comments.CommentText(expected["text"], expected["name"], mentions)


def test_a_console_viewer_name_opens() -> None:
    vector = _vector("viewer-name")
    name = comments.open_viewer_name(KEY, TOKEN, vector["ciphertext_b64"], vector["nonce_b64"])
    assert name == "Ahmad"


def test_a_comment_does_not_open_as_a_viewer_name_or_on_another_link() -> None:
    vector = _vector("comment")
    ct, nonce = vector["ciphertext_b64"], vector["nonce_b64"]

    assert comments.open_viewer_name(KEY, TOKEN, ct, nonce) is None
    with pytest.raises(DecryptError, match="does not open"):
        comments.open_comment(KEY, "another-token", ct, nonce)


def test_a_sealed_comment_round_trips_anonymously() -> None:
    sealed = comments.seal_comment(KEY, TOKEN, "  see 0:42 \n")

    opened = comments.open_comment(KEY, TOKEN, sealed.ciphertext, sealed.nonce)

    assert opened == comments.CommentText("see 0:42", None)
    assert len(base64.b64decode(sealed.nonce)) == 12


def test_two_seals_of_one_comment_use_different_nonces() -> None:
    first = comments.seal_comment(KEY, TOKEN, "hi")
    second = comments.seal_comment(KEY, TOKEN, "hi")
    assert first.nonce != second.nonce


@pytest.mark.parametrize(
    ("text", "error"),
    [
        (" \t\n", "empty"),
        ("a" * 2001, "over 2000"),
        ("\U0001f600" * 1100, "4096"),
    ],
)
def test_comments_the_console_refuses_are_refused(text: str, error: str) -> None:
    with pytest.raises(ValueError, match=error):
        comments.seal_comment(KEY, TOKEN, text)


def test_the_longest_comment_is_accepted() -> None:
    sealed = comments.seal_comment(KEY, TOKEN, "a" * 2000)
    assert comments.open_comment(KEY, TOKEN, sealed.ciphertext, sealed.nonce).text == "a" * 2000


def test_a_lone_surrogate_in_a_comment_is_sealed_as_u_fffd() -> None:
    sealed = comments.seal_comment(KEY, TOKEN, "a\ud800b")
    assert comments.open_comment(KEY, TOKEN, sealed.ciphertext, sealed.nonce).text == "a\ufffdb"


@pytest.mark.parametrize("case", VECTORS["lone_surrogates"]["cases"], ids=lambda c: c["label"])
def test_lone_surrogate_plaintexts_open_like_the_console(case: dict[str, Any]) -> None:
    nonce = b"\x01" * 12
    sealed = AESGCM(KEY).encrypt(nonce, case["plaintext"].encode(), f"{TOKEN}:comment".encode())

    opened = comments.open_comment(
        KEY, TOKEN, base64.b64encode(sealed).decode(), base64.b64encode(nonce).decode()
    )

    assert opened == comments.CommentText(case["text"], case["name"])


@pytest.mark.parametrize(
    ("plaintext", "error"),
    [
        (b"not json", "not JSON"),
        (b"\xff", "not JSON"),
        (b"[]", "not a comment"),
        (b'{"name":"x"}', "not a comment"),
        (b'{"text":"x","name":3}', "not a comment"),
    ],
)
def test_plaintexts_that_are_not_comments_are_refused(plaintext: bytes, error: str) -> None:
    nonce = b"\x02" * 12
    sealed = AESGCM(KEY).encrypt(nonce, plaintext, f"{TOKEN}:comment".encode())
    with pytest.raises(DecryptError, match=error):
        comments.open_comment(
            KEY, TOKEN, base64.b64encode(sealed).decode(), base64.b64encode(nonce).decode()
        )


@pytest.mark.parametrize(
    ("ciphertext", "nonce", "error"),
    [("!!", "AAAAAAAAAAAAAAAA", "not base64"), ("AAAA", "AAAA", "nonce must be 12")],
)
def test_malformed_fields_are_decrypt_errors(ciphertext: str, nonce: str, error: str) -> None:
    with pytest.raises(DecryptError, match=error):
        comments.open_comment(KEY, TOKEN, ciphertext, nonce)


def test_a_missing_or_unreadable_viewer_name_is_no_name() -> None:
    assert comments.open_viewer_name(KEY, TOKEN, None, None) is None
    assert comments.open_viewer_name(KEY, TOKEN, "AAAA", None) is None
    assert comments.open_viewer_name(KEY, TOKEN, "!!", "AAAA") is None


def test_a_viewer_name_that_is_not_a_string_is_no_name() -> None:
    nonce = b"\x03" * 12
    sealed = AESGCM(KEY).encrypt(nonce, b'{"name":7}', f"{TOKEN}:viewer-name".encode())
    name = comments.open_viewer_name(
        KEY, TOKEN, base64.b64encode(sealed).decode(), base64.b64encode(nonce).decode()
    )
    assert name is None


@pytest.mark.parametrize("entry", VECTORS["names"]["blank"], ids=lambda e: e["label"])
def test_blank_names_clean_to_none(entry: dict[str, str]) -> None:
    assert comments.clean_name(entry["name"]) is None


@pytest.mark.parametrize("entry", VECTORS["names"]["visible"], ids=lambda e: e["label"])
def test_visible_names_survive_with_spaces_around_them(entry: dict[str, str]) -> None:
    assert comments.clean_name(f" {entry['name']} ") == entry["name"]


@pytest.mark.parametrize("entry", VECTORS["names"]["cleaned"], ids=lambda e: e["label"])
def test_names_clean_like_the_console(entry: dict[str, str]) -> None:
    assert comments.clean_name(entry["name"]) == entry["cleaned"]


def test_no_name_stays_no_name() -> None:
    assert comments.clean_name(None) is None


@given(st.text(max_size=200))
def test_cleaning_is_idempotent(name: str) -> None:
    once = comments.clean_name(name)
    assert comments.clean_name(once) == once
    assert once is None or len(once) <= comments.MAX_NAME_CHARS


@pytest.mark.parametrize("separator", ["\u2028", "\u2029", "\x85", "\u1680"])
def test_white_space_between_zero_width_characters_is_blank(separator: str) -> None:
    # The trim cannot reach a separator that zero-width characters fence in;
    # only the White_Space check makes this name blank.
    assert comments.clean_name(f"\u200b{separator}\u200b") is None


def test_the_plaintext_escapes_like_json_stringify() -> None:
    # Pinned from Node: Buffer.from(JSON.stringify({text, name})).toString("hex")
    # with the same text and name. JSON.stringify escapes only quote,
    # backslash and U+0000-U+001F; DEL, C1 controls, U+2028/U+2029 and every
    # other character go out as raw UTF-8.
    text = 'q"b\\s\x01\x08\x0c\n\r\t\x1f\x7f\x85\x9b\xe9\u2028\u2029\U0001f600/<>&'
    expected = (
        "7b2274657874223a22715c22625c5c735c75303030315c625c665c6e5c725c745c75303031667fc285c2"
        "9bc3a9e280a8e280a9f09f98802f3c3e26222c226e616d65223a225a6fc3ab20e280ae227d"
    )
    assert comments.comment_plaintext(text, "Zo\xeb \u202e").hex() == expected


def test_a_plaintext_with_a_byte_order_mark_opens_as_in_the_console() -> None:
    nonce = b"\x04" * 12
    plaintext = b"\xef\xbb\xbf" + comments.comment_plaintext("hi", None)
    sealed = AESGCM(KEY).encrypt(nonce, plaintext, f"{TOKEN}:comment".encode())

    opened = comments.open_comment(
        KEY, TOKEN, base64.b64encode(sealed).decode(), base64.b64encode(nonce).decode()
    )

    assert opened == comments.CommentText("hi", None)


@pytest.mark.parametrize(
    ("name", "reserved"),
    [
        ("Hippius Support", True),
        ("hippiussupport", True),
        ("The Owner", True),
        ("ad\u200bmin", True),
        ("\uff33\uff35\uff30\uff30\uff2f\uff32\uff34", True),
        ("Ownerly", False),
        ("Grace", False),
    ],
)
def test_reserved_names_match_the_console(name: str, reserved: bool) -> None:
    assert comments.is_reserved_name(name) is reserved
