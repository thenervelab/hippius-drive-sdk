import base64
import json
import os
import re
import stat
from pathlib import Path

import pytest

from hippius_drive.crypto import mnemonic_store as ms

PHRASE = " ".join(["abandon"] * 23 + ["art"])


def test_round_trip_and_file_mode(tmp_path: Path) -> None:
    path = tmp_path / "enc_mnemonic.json"
    ms.save(path, PHRASE, "pw-123456")
    assert ms.load(path, "pw-123456") == PHRASE
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    body = json.loads(path.read_text())
    assert body["iterations"] == 600_000
    assert set(body) == {"salt", "iv", "data", "iterations"}
    assert len(base64.b64decode(body["salt"])) == 16
    assert len(base64.b64decode(body["iv"])) == 12


def test_wrong_password_raises(tmp_path: Path) -> None:
    path = tmp_path / "e.json"
    ms.save(path, PHRASE, "right")
    with pytest.raises(ms.MnemonicStoreError):
        ms.load(path, "wrong")


def test_missing_iterations_means_legacy_10k(tmp_path: Path) -> None:
    path = tmp_path / "e.json"
    ms.save(path, PHRASE, "pw", iterations=10_000)
    body = json.loads(path.read_text())
    del body["iterations"]
    path.write_text(json.dumps(body))
    assert ms.load(path, "pw") == PHRASE


def test_overwrite_keeps_backup(tmp_path: Path) -> None:
    path = tmp_path / "e.json"
    ms.save(path, PHRASE, "pw")
    first = path.read_text()
    ms.save(path, PHRASE, "pw")
    assert (tmp_path / "e.json.bak").read_text() == first
    assert not (tmp_path / "e.json.tmp").exists()


def test_zero_iterations_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "e.json"
    ms.save(path, PHRASE, "pw")
    body = json.loads(path.read_text())
    body["iterations"] = 0
    path.write_text(json.dumps(body))
    with pytest.raises(ms.MnemonicStoreError, match="non-zero"):
        ms.load(path, "pw")


def test_wrong_length_iv_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "e.json"
    ms.save(path, PHRASE, "pw")
    body = json.loads(path.read_text())
    body["iv"] = base64.b64encode(b"\x00" * 11).decode()
    path.write_text(json.dumps(body))
    with pytest.raises(ms.MnemonicStoreError, match="IV"):
        ms.load(path, "pw")


def test_malformed_json_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "e.json"
    path.write_text("{not json")
    with pytest.raises(ms.MnemonicStoreError):
        ms.load(path, "pw")


def test_missing_field_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "e.json"
    path.write_text(json.dumps({"salt": "AA==", "iv": "AA=="}))
    with pytest.raises(ms.MnemonicStoreError):
        ms.load(path, "pw")


def test_save_creates_the_parent_directory(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "dir" / "enc_mnemonic.json"
    ms.save(path, PHRASE, "pw")
    assert ms.load(path, "pw") == PHRASE


def test_save_with_explicit_material_is_deterministic(tmp_path: Path) -> None:
    params = ms.StoreParams(salt=bytes(range(16)), iv=bytes(range(12)), iterations=10_000)
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    ms.save_with(first, PHRASE, "pw", params)
    ms.save_with(second, PHRASE, "pw", params)
    assert first.read_text() == second.read_text()
    assert ms.load(first, "pw") == PHRASE


# The store is normally the only local copy of a master mnemonic, so every
# corruption a disk or an attacker can produce must give a clear error rather
# than a crash, a wrong key, or a silent fallback.


def test_save_with_rejects_a_wrong_length_salt(tmp_path: Path) -> None:
    params = ms.StoreParams(salt=b"\x00" * 15, iv=bytes(12))
    with pytest.raises(ms.MnemonicStoreError, match="salt must be 16 bytes"):
        ms.save_with(tmp_path / "e.json", PHRASE, "pw", params)


def test_save_with_rejects_a_wrong_length_iv(tmp_path: Path) -> None:
    params = ms.StoreParams(salt=bytes(16), iv=b"\x00" * 11)
    with pytest.raises(ms.MnemonicStoreError, match="IV must be 12 bytes"):
        ms.save_with(tmp_path / "e.json", PHRASE, "pw", params)


def test_save_with_a_bad_length_writes_nothing(tmp_path: Path) -> None:
    path = tmp_path / "e.json"
    params = ms.StoreParams(salt=b"\x00" * 15, iv=bytes(12))
    with pytest.raises(ms.MnemonicStoreError):
        ms.save_with(path, PHRASE, "pw", params)
    assert not path.exists()
    assert not path.with_name("e.json.tmp").exists()


@pytest.mark.parametrize("field", ["salt", "iv", "data"])
def test_non_base64_fields_are_rejected(tmp_path: Path, field: str) -> None:
    path = tmp_path / "e.json"
    ms.save(path, PHRASE, "pw")
    body = json.loads(path.read_text())
    body[field] = "not!base64!"
    path.write_text(json.dumps(body))
    with pytest.raises(ms.MnemonicStoreError, match="base64"):
        ms.load(path, "pw")


@pytest.mark.parametrize("field", ["salt", "iv", "data"])
def test_a_missing_field_names_the_field(tmp_path: Path, field: str) -> None:
    path = tmp_path / "e.json"
    ms.save(path, PHRASE, "pw")
    body = json.loads(path.read_text())
    del body[field]
    path.write_text(json.dumps(body))
    with pytest.raises(ms.MnemonicStoreError, match=field):
        ms.load(path, "pw")


@pytest.mark.parametrize("body", ["[1, 2, 3]", '"a string"', "42", "null"])
def test_a_non_object_document_is_rejected(tmp_path: Path, body: str) -> None:
    path = tmp_path / "e.json"
    path.write_text(body)
    with pytest.raises(ms.MnemonicStoreError):
        ms.load(path, "pw")


def test_a_null_iterations_means_legacy_rather_than_an_error(tmp_path: Path) -> None:
    path = tmp_path / "e.json"
    ms.save(path, PHRASE, "pw", iterations=10_000)
    body = json.loads(path.read_text())
    body["iterations"] = None
    path.write_text(json.dumps(body))
    assert ms.load(path, "pw") == PHRASE


@pytest.mark.parametrize("value", ["600000", 6.0, True, [600000]])
def test_a_non_integer_iterations_is_rejected(tmp_path: Path, value: object) -> None:
    # A string or a bool here would otherwise reach the KDF and derive the
    # wrong key, which reads to the user as "wrong password".
    path = tmp_path / "e.json"
    ms.save(path, PHRASE, "pw")
    body = json.loads(path.read_text())
    body["iterations"] = value
    path.write_text(json.dumps(body))
    with pytest.raises(ms.MnemonicStoreError, match="integer"):
        ms.load(path, "pw")


def test_a_negative_iterations_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "e.json"
    ms.save(path, PHRASE, "pw")
    body = json.loads(path.read_text())
    body["iterations"] = -1
    path.write_text(json.dumps(body))
    with pytest.raises(ms.MnemonicStoreError, match="non-zero"):
        ms.load(path, "pw")


def test_a_failed_backup_does_not_block_the_write(tmp_path: Path, monkeypatch) -> None:
    # The backup is best-effort, exactly as in hcfs-client: a new blob that is
    # valid and durable on its own must still land.
    path = tmp_path / "e.json"
    ms.save(path, PHRASE, "pw")

    real_write_bytes = Path.write_bytes

    def refuse_backup(self: Path, data: bytes) -> int:
        if self.name.endswith(".bak"):
            raise OSError("backup device full")
        return real_write_bytes(self, data)

    monkeypatch.setattr(Path, "write_bytes", refuse_backup)
    ms.save(path, "  ".join([PHRASE]), "pw2")
    assert ms.load(path, "pw2") is not None


def test_an_unreadable_file_is_reported_with_its_path(tmp_path: Path) -> None:
    missing = tmp_path / "nope.json"
    with pytest.raises(ms.MnemonicStoreError, match=re.escape("nope.json")):
        ms.load(missing, "pw")
