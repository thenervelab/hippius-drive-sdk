"""Named comments, mentions, viewer ids and shown names, against the console.

The mention plaintext is pinned by the console's vector file. The console
has no viewer-id vector; the expected ids were computed with Node's
``crypto.createHmac`` (an implementation independent of this one) for the
secret ``00 01 .. 1f``.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from hippius_drive.crypto import comments
from hippius_drive.crypto.comments import CommentMention

VECTORS: dict[str, Any] = json.loads(
    (Path(__file__).parent.parent / "vectors" / "share-comments-vectors.json").read_text("utf-8")
)
TOKEN: str = VECTORS["token"]
KEY = comments.comment_key(bytes.fromhex(VECTORS["share_key_hex"]))
SECRET = bytes(range(32))
ADDRESS = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"


def _vector(kind: str) -> dict[str, str]:
    return next(v for v in VECTORS["vectors"] if v["kind"] == kind)


def test_a_comment_with_mentions_seals_to_the_consoles_bytes() -> None:
    vector = _vector("comment-mentions")
    parsed = json.loads(vector["plaintext"])

    mentions = comments.parse_mentions(parsed["mentions"])
    plaintext = comments.comment_plaintext(parsed["text"], parsed["name"], mentions)

    assert plaintext.decode() == vector["plaintext"]
    nonce = base64.b64decode(vector["nonce_b64"])
    sealed = AESGCM(KEY).encrypt(nonce, plaintext, vector["aad"].encode())
    assert base64.b64encode(sealed).decode() == vector["ciphertext_b64"]


def test_a_console_comment_with_mentions_opens_with_them() -> None:
    vector = _vector("comment-mentions")

    opened = comments.open_comment(KEY, TOKEN, vector["ciphertext_b64"], vector["nonce_b64"])

    assert opened.mentions == (
        CommentMention("owner", "Owner"),
        CommentMention("commenter", "Grace Liu", "c-17"),
    )


def test_a_named_comment_round_trips_with_its_mentions() -> None:
    ada = CommentMention("commenter", "Ada", "41")
    sealed = comments.seal_comment(KEY, TOKEN, " hi @Ada ", name=" Grace ", mentions=[ada])

    opened = comments.open_comment(KEY, TOKEN, sealed.ciphertext, sealed.nonce)

    assert opened == comments.CommentText("hi @Ada", "Grace", (ada,))


def test_no_mentions_leaves_the_field_out() -> None:
    assert comments.comment_plaintext("x", None, ()) == b'{"text":"x","name":null}'


def test_a_blank_author_name_seals_as_no_name() -> None:
    sealed = comments.seal_comment(KEY, TOKEN, "x", name="\u200b ")
    assert comments.open_comment(KEY, TOKEN, sealed.ciphertext, sealed.nonce).name is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, ()),
        ({"kind": "owner", "name": "A"}, ()),
        ([None, 3, "x", {"kind": "group", "name": "A"}], ()),
        ([{"kind": "owner", "name": " \u200b "}], ()),
        ([{"kind": "owner", "name": 7}], ()),
        ([{"kind": "owner", "name": " Ada ", "comment": "41"}], (CommentMention("owner", "Ada"),)),
        ([{"kind": "commenter", "name": "Ada"}], (CommentMention("commenter", "Ada"),)),
        (
            [{"kind": "commenter", "name": "Ada", "comment": ""}],
            (CommentMention("commenter", "Ada"),),
        ),
        (
            [{"kind": "commenter", "name": "Ada", "comment": 41}],
            (CommentMention("commenter", "Ada"),),
        ),
    ],
)
def test_mentions_parse_leniently_like_the_console(raw: object, expected: tuple[Any, ...]) -> None:
    assert comments.parse_mentions(raw) == expected


def test_a_mention_reference_is_measured_in_utf16_units_as_the_console_does() -> None:
    # 64 astral characters are 128 UTF-16 units, the console's limit; 65 are over.
    at_limit = "\U0001f600" * 64
    over = "\U0001f600" * 65

    kept = comments.parse_mentions([{"kind": "commenter", "name": "A", "comment": at_limit}])
    dropped = comments.parse_mentions([{"kind": "commenter", "name": "A", "comment": over}])

    assert kept[0].comment == at_limit
    assert dropped[0].comment is None


def test_past_ten_mentions_the_rest_are_dropped() -> None:
    raw = [{"kind": "commenter", "name": f"n{i}"} for i in range(12)]
    assert [m.name for m in comments.parse_mentions(raw)] == [f"n{i}" for i in range(10)]


def test_a_viewer_name_round_trips_cleaned() -> None:
    sealed = comments.seal_viewer_name(KEY, TOKEN, "  Grace\u202e ")
    assert comments.open_viewer_name(KEY, TOKEN, sealed.ciphertext, sealed.nonce) == "Grace"


def test_a_viewer_name_seals_to_the_consoles_plaintext() -> None:
    vector = _vector("viewer-name")
    sealed = comments.seal_viewer_name(KEY, TOKEN, "Ahmad")
    opened = AESGCM(KEY).decrypt(
        base64.b64decode(sealed.nonce),
        base64.b64decode(sealed.ciphertext),
        vector["aad"].encode(),
    )
    assert opened.decode() == vector["plaintext"]


def test_a_blank_viewer_name_is_refused() -> None:
    with pytest.raises(ValueError, match="blank"):
        comments.seal_viewer_name(KEY, TOKEN, "\u2800")


def test_the_viewer_id_matches_an_independent_hmac() -> None:
    assert comments.viewer_id(SECRET, TOKEN) == "AmkdIsFzxJuP1hjmJ79zGQ"
    assert comments.viewer_id(SECRET, "Qw9pLm3nZx7cVb2Hk4Jt8A") == "EhaOF1ynAmoeD6Y7es77yQ"


@pytest.mark.parametrize("size", [0, 31, 33])
def test_a_viewer_secret_of_the_wrong_size_is_refused(size: int) -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        comments.viewer_id(bytes(size), TOKEN)


@pytest.mark.parametrize(
    ("name", "shown"),
    [
        # The console's display-name.test.ts cases.
        (f"user_{ADDRESS.lower()}", "5grwva…utqy"),
        (ADDRESS, "5Grwva…utQY"),
        (f"  {ADDRESS} ", "5Grwva…utQY"),
        ("Grace Liu", "Grace Liu"),
        ("user_ada", "user_ada"),
        (" Ada ", "Ada"),
        # 0, O, I and l are not base58: not an address, shown as typed.
        ("0" * 48, "0" * 48),
        (None, None),
        ("   ", None),
    ],
)
def test_names_are_shown_as_the_console_shows_them(name: str | None, shown: str | None) -> None:
    assert comments.present_name(name) == shown


def test_a_short_address_is_not_shortened() -> None:
    assert comments.short_address("123456789012") == "123456789012"
    assert comments.short_address("1234567890123") == "123456…0123"
