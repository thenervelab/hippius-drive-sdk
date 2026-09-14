"""Live round trips against the real Hippius service.

Ordered: later tests read what earlier ones wrote. Each asserts on data this
run created, never on account-wide state, so a shared test account stays
usable and a stale row cannot make the suite flap.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

import pytest

from hippius_drive import errors
from hippius_drive._upload import TRANSPORT_CHUNK
from hippius_drive.client import Client
from hippius_drive.models import RenameSpec, SearchFilters

pytestmark = pytest.mark.e2e

SMALL = b"hippius-drive e2e " * 57  # 1026 bytes, not a round number
LARGE_SIZE = TRANSPORT_CHUNK * 2 + 4096


@pytest.fixture(scope="module")
def small_path() -> str:
    return f"e2e/{secrets.token_hex(4)}-small.bin"


@pytest.fixture(scope="module")
def large_path() -> str:
    return f"e2e/{secrets.token_hex(4)}-large.bin"


def test_register_then_the_folder_is_listed(client: Client, label: str) -> None:
    labels = [folder.label for folder in client.folders.list().folders]
    assert label in labels


def test_can_upload_answers_for_a_small_write(client: Client) -> None:
    verdict = client.can_upload(len(SMALL))
    # A false verdict is a real account state, not a test failure; assert only
    # that the endpoint answered in the documented shape.
    assert isinstance(verdict.result, bool)
    if not verdict.result:
        pytest.skip(f"account cannot accept writes right now: {verdict.error}")


def test_put_then_get_bytes_round_trips(client: Client, small_path: str) -> None:
    result = client.files.put_bytes(SMALL, small_path)
    assert len(result.revision_id) == 32
    assert client.files.get_bytes(client.files.file_id(small_path)) == SMALL


def test_get_to_disk_reports_the_plaintext_size(
    client: Client, small_path: str, tmp_path: Path
) -> None:
    dest = tmp_path / "small.bin"
    info = client.files.get(client.files.file_id(small_path), dest)
    assert dest.read_bytes() == SMALL
    assert info.size_bytes == len(SMALL)
    assert info.revision_seq >= 1


def test_state_lists_the_file_with_its_plaintext_size(client: Client, small_path: str) -> None:
    wanted = client.files.file_id(small_path)
    entry = next(f for f in client.files.iter_state() if f.file_id == wanted)
    assert entry.size_bytes == len(SMALL)
    assert entry.relative_path == small_path


def test_browse_finds_the_file_in_its_directory(client: Client, small_path: str) -> None:
    directory, name = small_path.rsplit("/", 1)
    listing = client.files.browse(directory, limit=1000)
    assert name in [f.file_name for f in listing.files]


def test_search_finds_the_file_with_its_folder_label(
    client: Client, small_path: str, label: str
) -> None:
    name = small_path.rsplit("/", 1)[1]
    hits = client.files.search(SearchFilters(q=name)).files
    assert [hit.folder_label for hit in hits if hit.relative_path == small_path] == [label]


def test_a_stale_base_revision_is_a_conflict(client: Client, small_path: str) -> None:
    with pytest.raises(errors.Conflict) as exc:
        client.files.put_bytes(SMALL + b"!", small_path, base_revision_id=bytes(32), revision_seq=2)
    assert exc.value.current_revision_seq is not None


def test_replacing_with_the_current_revision_succeeds(client: Client, small_path: str) -> None:
    wanted = client.files.file_id(small_path)
    entry = next(f for f in client.files.iter_state() if f.file_id == wanted)
    updated = SMALL + b"-v2"
    client.files.put_bytes(
        updated,
        small_path,
        base_revision_id=entry.revision_id,
        revision_seq=entry.revision_seq + 1,
    )
    assert client.files.get_bytes(wanted) == updated


def test_rename_moves_the_file_and_frees_the_old_id(client: Client, small_path: str) -> None:
    wanted = client.files.file_id(small_path)
    entry = next(f for f in client.files.iter_state() if f.file_id == wanted)
    moved = small_path.replace("-small.bin", "-moved.bin")

    result = client.files.rename([RenameSpec(small_path, moved, entry.revision_id)])
    assert result.failures == []
    assert result.renamed_count == 1

    assert client.files.get_bytes(client.files.file_id(moved)) == SMALL + b"-v2"
    with pytest.raises(errors.NotFound):
        client.files.get_bytes(wanted)

    client.files.delete(client.files.file_id(moved))


def test_deleting_a_gone_file_is_not_found(client: Client, small_path: str) -> None:
    with pytest.raises(errors.NotFound):
        client.files.delete(client.files.file_id(small_path))


@pytest.mark.skipif(
    os.environ.get("HIPPIUS_TEST_SKIP_LARGE") == "1",
    reason="HIPPIUS_TEST_SKIP_LARGE=1 set; the session test moves ~16 MiB",
)
def test_a_large_file_goes_through_a_session_and_comes_back_intact(
    client: Client, large_path: str, tmp_path: Path
) -> None:
    plaintext = secrets.token_bytes(LARGE_SIZE)
    local = tmp_path / "large.bin"
    local.write_bytes(plaintext)

    client.files.put(local, large_path)

    dest = tmp_path / "large-out.bin"
    info = client.files.get(client.files.file_id(large_path), dest)
    assert dest.read_bytes() == plaintext
    assert info.size_bytes == LARGE_SIZE

    client.files.delete(client.files.file_id(large_path))


def test_summaries_answer_in_the_documented_shape(client: Client) -> None:
    # The server coalesces summary writes about once a second and a read can
    # reach a different instance, so assert the shape, not a just-written total.
    summary = client.summary.user()
    assert summary.total_bytes >= 0
    assert summary.file_count >= 0
    assert client.summary.file_types().other >= 0
    assert client.summary.sources().other >= 0
