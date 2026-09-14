import base64

import pytest

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
