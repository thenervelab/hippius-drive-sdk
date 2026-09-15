"""Failure paths in upload preparation that leave nothing behind."""

from __future__ import annotations

import io
from collections.abc import Iterator
from pathlib import Path
from tempfile import SpooledTemporaryFile
from typing import IO

import httpx
import pytest
import respx

from hippius_drive import _upload, errors
from hippius_drive._transport import Transport
from hippius_drive._upload import PlaintextSource, UploadSpec
from hippius_drive.client import Client
from hippius_drive.crypto import file_cipher
from hippius_drive.identity import Identity

BASE = "https://example.test"
MASTER = " ".join(["abandon"] * 23 + ["art"])
SS58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
FOLDER = "37a8eec1ce19687d"


@pytest.fixture
def identity() -> Identity:
    return Identity.from_master(MASTER, "default", account_ss58=SS58)


def test_a_source_that_shrinks_mid_read_fails_and_releases_the_spool(
    identity: Identity,
) -> None:
    # A file truncated while it is being read would otherwise produce a blob
    # whose frame count disagrees with its body, which the server rejects at
    # finalize with a hash mismatch rather than anything actionable. The temp
    # file must not survive the failure either.
    class Shrinking(io.BytesIO):
        def read(self, size: int | None = -1, /) -> bytes:
            return b""  # claims EOF immediately

    source = PlaintextSource(open=Shrinking, size=4096)
    with pytest.raises(ValueError, match="declared plaintext_size"):
        _upload.prepare(identity, source, UploadSpec("a.bin"))


def test_a_source_that_grows_past_a_full_frame_is_rejected(identity: Identity) -> None:
    # encrypt_stream reads CHUNK_SIZE per full frame. If the file grew and the
    # declared size is a multiple of that, a to-EOF hash would cover extra
    # bytes the ciphertext does not. Both passes must see the same prefix.
    grown = b"x" * (file_cipher.CHUNK_SIZE + 50)
    source = PlaintextSource(open=lambda: io.BytesIO(grown), size=file_cipher.CHUNK_SIZE)
    with pytest.raises(ValueError, match="declared plaintext_size"):
        _upload.prepare(identity, source, UploadSpec("a.bin"))


def test_prepare_closes_the_spool_when_encryption_fails(
    identity: Identity, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A failure part-way through encryption must not strand the temp file: on
    # a large upload that is a full encrypted copy of the plaintext on disk.
    spools: list[IO[bytes]] = []
    real_spool = SpooledTemporaryFile

    def capture(max_size: int = 0) -> IO[bytes]:
        handle: IO[bytes] = real_spool(max_size=max_size)
        spools.append(handle)
        return handle

    def explode(*args: object, **kwargs: object) -> Iterator[bytes]:
        yield b"header"
        raise RuntimeError("disk gone")

    monkeypatch.setattr(_upload, "SpooledTemporaryFile", capture)
    monkeypatch.setattr(file_cipher, "encrypt_stream", explode)

    with pytest.raises(RuntimeError, match="disk gone"):
        _upload.prepare(identity, PlaintextSource.from_bytes(b"x" * 32), UploadSpec("a.bin"))

    assert spools, "prepare should have opened a spool"
    assert spools[0].closed, "the spool must be released when encryption fails"


def test_prepared_upload_releases_its_spool_on_exit(identity: Identity) -> None:
    with _upload.prepare(
        identity, PlaintextSource.from_bytes(b"x" * 64), UploadSpec("a.bin")
    ) as prepared:
        assert prepared.ciphertext_size == file_cipher.ciphertext_size(64)
        handle = prepared.blob
    assert handle.closed


@respx.mock
def test_a_download_error_with_an_html_body_still_raises_typed(
    identity: Identity, tmp_path: Path
) -> None:
    # A proxy or load balancer can answer with HTML rather than the service's
    # JSON; that must not reach the frame decoder and read as a corrupt file.
    file_id = "ff" * 32
    respx.get(f"{BASE}/download/{SS58}/{FOLDER}/{file_id}").mock(
        return_value=httpx.Response(502, text="<html>bad gateway</html>")
    )
    with (
        Client(token="tok", identity=identity, transport=Transport(BASE, "tok")) as client,
        pytest.raises(errors.ServerError),
    ):
        client.files.get(file_id, tmp_path / "a.bin")
    assert not (tmp_path / "a.bin").exists()


@respx.mock
def test_a_download_error_with_malformed_json_still_raises_typed(
    identity: Identity, tmp_path: Path
) -> None:
    file_id = "ff" * 32
    respx.get(f"{BASE}/download/{SS58}/{FOLDER}/{file_id}").mock(
        return_value=httpx.Response(
            500, headers={"content-type": "application/json"}, content=b"{not json"
        )
    )
    with (
        Client(token="tok", identity=identity, transport=Transport(BASE, "tok")) as client,
        pytest.raises(errors.ServerError),
    ):
        client.files.get(file_id, tmp_path / "a.bin")
