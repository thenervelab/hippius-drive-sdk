import base64

import pytest
from nacl import bindings

from hippius_drive.crypto import mnemonic_blob as mb

PHRASE = " ".join(["abandon"] * 23 + ["art"])
SS58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
# OWASP second-choice Argon2id parameters; the suite would be slow at the
# 128 MiB production default and the format does not depend on the values.
FAST = mb.KdfParams(memory_kib=19456, time_cost=2, parallelism=1)


def test_round_trip() -> None:
    blob = mb.seal(PHRASE, "pass", SS58, kdf=FAST)
    assert mb.open_blob(blob, "pass", SS58) == PHRASE


def test_blob_shape() -> None:
    blob = mb.seal(PHRASE, "pass", SS58, kdf=FAST)
    assert blob.kdf.algorithm == "argon2id"
    assert len(base64.b64decode(blob.salt)) == mb.SALT_LEN
    assert len(base64.b64decode(blob.nonce)) == mb.NONCE_LEN
    assert base64.b64decode(blob.aad).decode() == SS58
    dumped = blob.model_dump()
    assert set(dumped) == {"ciphertext", "salt", "nonce", "aad", "kdf"}
    assert set(dumped["kdf"]) == {"algorithm", "memory_kib", "time_cost", "parallelism"}


def test_default_kdf_matches_the_rust_defaults() -> None:
    assert mb.KdfParams() == mb.KdfParams(
        algorithm="argon2id", memory_kib=131_072, time_cost=3, parallelism=1
    )


def test_wrong_passphrase_raises() -> None:
    blob = mb.seal(PHRASE, "pass", SS58, kdf=FAST)
    with pytest.raises(mb.MnemonicBlobError):
        mb.open_blob(blob, "nope", SS58)


def test_wrong_ss58_raises_because_it_is_the_aad() -> None:
    blob = mb.seal(PHRASE, "pass", SS58, kdf=FAST)
    with pytest.raises(mb.MnemonicBlobError, match="authentication"):
        mb.open_blob(blob, "pass", "5Other")


def test_short_nonce_is_rejected_before_the_kdf() -> None:
    blob = mb.seal(PHRASE, "pass", SS58, kdf=FAST)
    forged = blob.model_copy(update={"nonce": base64.b64encode(b"\x00" * 23).decode()})
    with pytest.raises(mb.MnemonicBlobError, match="nonce"):
        mb.open_blob(forged, "pass", SS58)


def test_seal_with_is_deterministic() -> None:
    salt, nonce = bytes(range(mb.SALT_LEN)), bytes(range(mb.NONCE_LEN))
    first = mb.seal_with(PHRASE, "pass", SS58, mb.SealInputs(salt=salt, nonce=nonce, kdf=FAST))
    second = mb.seal_with(PHRASE, "pass", SS58, mb.SealInputs(salt=salt, nonce=nonce, kdf=FAST))
    assert first.model_dump() == second.model_dump()
    assert mb.open_blob(first, "pass", SS58) == PHRASE


def test_seal_with_rejects_wrong_length_material() -> None:
    good_kdf = FAST
    with pytest.raises(mb.MnemonicBlobError):
        mb.seal_with(
            PHRASE, "p", SS58, mb.SealInputs(salt=b"\x00" * 15, nonce=bytes(24), kdf=good_kdf)
        )
    with pytest.raises(mb.MnemonicBlobError):
        mb.seal_with(
            PHRASE, "p", SS58, mb.SealInputs(salt=bytes(16), nonce=b"\x00" * 23, kdf=good_kdf)
        )


def test_blob_survives_a_json_round_trip() -> None:
    blob = mb.seal(PHRASE, "pass", SS58, kdf=FAST)
    restored = mb.SealedBlob.model_validate_json(blob.model_dump_json())
    assert mb.open_blob(restored, "pass", SS58) == PHRASE


# Every field below is attacker- or corruption-controlled: the blob is fetched
# from a server, so a malformed one must fail loudly rather than panic the
# process or silently produce the wrong seed.


@pytest.mark.parametrize("field", ["salt", "nonce", "ciphertext"])
def test_non_base64_fields_are_rejected(field: str) -> None:
    blob = mb.seal(PHRASE, "pass", SS58, kdf=FAST)
    forged = blob.model_copy(update={field: "not!base64!"})
    with pytest.raises(mb.MnemonicBlobError, match="base64"):
        mb.open_blob(forged, "pass", SS58)


@pytest.mark.parametrize(
    "params",
    [
        mb.KdfParams(memory_kib=1, time_cost=1, parallelism=1),
        mb.KdfParams(memory_kib=19456, time_cost=0, parallelism=1),
        mb.KdfParams(memory_kib=19456, time_cost=2, parallelism=0),
    ],
    ids=["memory-too-low", "zero-time-cost", "zero-parallelism"],
)
def test_impossible_kdf_parameters_are_reported_not_raised_raw(params: mb.KdfParams) -> None:
    blob = mb.seal(PHRASE, "pass", SS58, kdf=FAST)
    forged = blob.model_copy(update={"kdf": params})
    with pytest.raises(mb.MnemonicBlobError, match="Argon2"):
        mb.open_blob(forged, "pass", SS58)


def test_a_sealed_non_utf8_payload_is_reported_as_such() -> None:
    # Decrypts cleanly but is not text: a hand-rolled blob, or a format change
    # on the other side, must not surface as a UnicodeDecodeError.
    salt, nonce = bytes(range(mb.SALT_LEN)), bytes(range(mb.NONCE_LEN))
    key = mb._derive_key("pass", salt, FAST)
    ciphertext = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        b"\xff\xfe not text", SS58.encode(), nonce, key
    )
    forged = mb.SealedBlob(
        ciphertext=base64.b64encode(ciphertext).decode(),
        salt=base64.b64encode(salt).decode(),
        nonce=base64.b64encode(nonce).decode(),
        aad=base64.b64encode(SS58.encode()).decode(),
        kdf=FAST,
    )
    with pytest.raises(mb.MnemonicBlobError, match="UTF-8"):
        mb.open_blob(forged, "pass", SS58)


def test_seal_rejects_kdf_parameters_it_cannot_use() -> None:
    impossible = mb.KdfParams(memory_kib=1, time_cost=1, parallelism=1)
    inputs = mb.SealInputs(salt=bytes(16), nonce=bytes(24), kdf=impossible)
    with pytest.raises(mb.MnemonicBlobError, match="Argon2"):
        mb.seal_with(PHRASE, "pass", SS58, inputs)


def test_unknown_kdf_algorithm_is_rejected() -> None:
    blob = mb.seal(PHRASE, "pass", SS58, kdf=FAST)
    forged = blob.model_copy(update={"kdf": FAST.model_copy(update={"algorithm": "argon2i"})})
    with pytest.raises(mb.MnemonicBlobError, match="unsupported KDF"):
        mb.open_blob(forged, "pass", SS58)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("memory_kib", mb.MAX_MEMORY_KIB + 1),
        ("time_cost", mb.MAX_TIME_COST + 1),
        ("parallelism", mb.MAX_PARALLELISM + 1),
    ],
)
def test_oversized_kdf_costs_are_rejected_before_argon2(field: str, value: int) -> None:
    blob = mb.seal(PHRASE, "pass", SS58, kdf=FAST)
    too_much = FAST.model_copy(update={field: value})
    forged = blob.model_copy(update={"kdf": too_much})
    with pytest.raises(mb.MnemonicBlobError, match=field):
        mb.open_blob(forged, "pass", SS58)


@pytest.mark.parametrize("field", ["memory_kib", "time_cost", "parallelism"])
def test_a_negative_kdf_cost_is_a_blob_error_not_an_overflow(field: str) -> None:
    # argon2-cffi takes uint32 costs, so -1 raises OverflowError, which is
    # neither Argon2Error nor ValueError and would escape open_blob's contract.
    blob = mb.seal(PHRASE, "pass", SS58, kdf=FAST)
    forged = blob.model_copy(update={"kdf": FAST.model_copy(update={field: -1})})
    with pytest.raises(mb.MnemonicBlobError, match="positive"):
        mb.open_blob(forged, "pass", SS58)


def test_short_salt_is_rejected_before_the_kdf() -> None:
    blob = mb.seal(PHRASE, "pass", SS58, kdf=FAST)
    forged = blob.model_copy(update={"salt": base64.b64encode(b"\x00" * 7).decode()})
    with pytest.raises(mb.MnemonicBlobError, match="salt"):
        mb.open_blob(forged, "pass", SS58)
