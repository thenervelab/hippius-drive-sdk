import json

import pytest
from pydantic import ValidationError

from hippius_drive import models

# Verbatim from docs/public/api/get-state.md.
GET_STATE_FILE = {
    "path_hash": list(range(32)),
    "salted_hash": [7] * 32,
    "size_bytes": 1048576,
    "revision_seq": 1,
    "revision_id": [9] * 32,
    "encrypted_path": [1, 2, 3],
    "file_name": "report.pdf",
    "relative_path": "Work/report.pdf",
    "arion_hash": "Qm...",
    "chunk_hashes": ["Qm...", "Qm..."],
    "uploaded_by": "5Fmember...",
    "created_at": 1713139200,
    "updated_at": 1713139200,
}


def manifest() -> models.Manifest:
    return models.Manifest(
        ss58_address="5Grw",
        folder_hash="37a8eec1ce19687d",
        ciphertext_hash="ab" * 32,
        size_bytes=5,
        timestamp=1700000000,
        signature=bytes(64),
        signing_key=bytes(32),
        path_hash=bytes(32),
        salted_hash=bytes(32),
        revision_seq=1,
        encrypted_path=b"\x01\x02",
        file_name="a.txt",
        relative_path="a.txt",
        source="python-sdk",
    )


def test_manifest_json_dump_uses_int_arrays() -> None:
    dumped = json.loads(manifest().model_dump_json())
    assert dumped["signature"] == [0] * 64
    assert dumped["signing_key"] == [0] * 32
    assert dumped["path_hash"] == [0] * 32
    assert dumped["salted_hash"] == [0] * 32
    assert dumped["encrypted_path"] == [1, 2]
    assert dumped["base_revision_id"] is None
    assert dumped["size_bytes"] == 5


def test_manifest_round_trips_through_the_wire_form() -> None:
    original = manifest()
    restored = models.Manifest.model_validate_json(original.model_dump_json())
    assert restored == original


def test_manifest_accepts_a_base_revision_id_int_array() -> None:
    body = json.loads(manifest().model_dump_json())
    body["base_revision_id"] = [3] * 32
    assert models.Manifest.model_validate(body).base_revision_id == bytes([3] * 32)


def test_manifest_python_dump_keeps_bytes() -> None:
    assert manifest().model_dump()["signature"] == bytes(64)


def test_remote_file_entry_accepts_the_documented_block() -> None:
    entry = models.RemoteFileEntry.model_validate(GET_STATE_FILE)
    assert entry.path_hash == bytes(range(32))
    assert entry.file_id == bytes(range(32)).hex()
    assert entry.uploaded_by == "5Fmember..."
    assert entry.chunk_hashes == ["Qm...", "Qm..."]


def test_missing_uploaded_by_stays_none() -> None:
    body = {k: v for k, v in GET_STATE_FILE.items() if k != "uploaded_by"}
    assert models.RemoteFileEntry.model_validate(body).uploaded_by is None


def test_unknown_fields_are_ignored_not_rejected() -> None:
    body = {**GET_STATE_FILE, "field_the_server_added_later": 1}
    assert models.RemoteFileEntry.model_validate(body).size_bytes == 1048576


def test_get_state_result_paginates() -> None:
    result = models.GetStateResult.model_validate(
        {
            "ss58_address": "5Grw",
            "folder_hash": "abc1234567890def",
            "files": [GET_STATE_FILE],
            "total_count": 142,
            "has_more": True,
            "offset": 0,
            "limit": 25,
        }
    )
    assert result.has_more
    assert result.files[0].relative_path == "Work/report.pdf"


def test_browse_result_keeps_folders_and_files() -> None:
    result = models.BrowseResult.model_validate(
        {
            "ss58_address": "5Grw",
            "folder_hash": "abc",
            "path": "Documents/2026",
            "folders": [{"name": "taxes", "file_count": 12, "total_bytes": 54321}],
            "files": [GET_STATE_FILE],
            "total_count": 8,
            "has_more": False,
        }
    )
    assert result.folders[0].name == "taxes"
    assert result.files[0].file_name == "report.pdf"


def test_search_hit_adds_folder_columns() -> None:
    hit = models.SearchHit.model_validate(
        {**GET_STATE_FILE, "folder_hash": "abc", "folder_label": ""}
    )
    assert hit.folder_label == ""
    assert hit.file_id == bytes(range(32)).hex()


def test_can_upload_result_is_flat() -> None:
    assert models.CanUploadResult.model_validate({"result": True, "error": None}).result
    refused = models.CanUploadResult.model_validate(
        {"result": False, "error": "drive_quota_exceeded"}
    )
    assert refused.error == "drive_quota_exceeded"


def test_folder_info_defaults_member_count_to_zero() -> None:
    info = models.RemoteFolderInfo.model_validate(
        {"label": "My Documents", "folder_hash": "abc", "file_count": 1, "total_bytes": 2}
    )
    assert info.member_count == 0
    assert info.device_name == ""


def test_batch_rename_result_parses_failures() -> None:
    result = models.BatchRenameResult.model_validate(
        {
            "status": "ok",
            "renamed_count": 1,
            "successes": [
                {
                    "old_path_hash": [1] * 32,
                    "new_path_hash": [2] * 32,
                    "new_revision_id": [3] * 32,
                    "new_revision_seq": 5,
                }
            ],
            "failures": [{"old_path_hash": [4] * 32, "reason": "revision_mismatch"}],
        }
    )
    assert result.failures[0].reason == "revision_mismatch"
    assert result.successes[0].new_revision_seq == 5


def test_single_rename_serialises_bytes_as_int_arrays() -> None:
    rename = models.SingleRename(
        old_path_hash=bytes(32),
        new_path_hash=bytes([1] * 32),
        new_encrypted_path=b"\x09",
        new_relative_path="b.txt",
        base_revision_id=bytes([2] * 32),
    )
    dumped = json.loads(rename.model_dump_json())
    assert dumped["old_path_hash"] == [0] * 32
    assert dumped["new_encrypted_path"] == [9]
    assert dumped["new_file_name"] is None


def test_session_status_parses_the_resume_set() -> None:
    status = models.SessionStatusResult.model_validate(
        {
            "session_id": "s1",
            "state": "receiving",
            "total_chunks": 4,
            "chunks_received": [0, 2],
            "expires_at": 1713225600,
            "ciphertext_hash": "ab",
        }
    )
    assert sorted(set(range(status.total_chunks)) - set(status.chunks_received)) == [1, 3]


def test_upload_result_exposes_revision_id_as_bytes() -> None:
    result = models.UploadResult.model_validate(
        {
            "upload_id": "u1",
            "timestamp": 1713139200,
            "revision_id": [5] * 32,
            "created_at": 1,
            "updated_at": 2,
        }
    )
    assert result.revision_id == bytes([5] * 32)


def test_a_missing_required_field_is_a_validation_error() -> None:
    with pytest.raises(ValidationError):
        models.UploadResult.model_validate({"timestamp": 1})


def test_bytes_field_accepts_hex_for_header_derived_values() -> None:
    info = models.DownloadInfo.model_validate(
        {"size_bytes": 1024, "revision_id": "ab" * 32, "revision_seq": 3}
    )
    assert info.revision_id == bytes.fromhex("ab" * 32)
