import base64
import json
import os
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
