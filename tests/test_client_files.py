import json
import os
import stat
from pathlib import Path

import httpx
import pytest
import respx
from nacl.signing import VerifyKey

from hippius_drive import errors
from hippius_drive._transport import AsyncTransport, Transport
from hippius_drive._upload import TRANSPORT_CHUNK
from hippius_drive.client import AsyncClient, Client
from hippius_drive.crypto import file_cipher, hashes
from hippius_drive.identity import Identity, tos_text
from hippius_drive.models import Manifest
from tests.helpers import multipart_parts

BASE = "https://example.test"
MASTER = " ".join(["abandon"] * 23 + ["art"])
SS58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
FOLDER = "37a8eec1ce19687d"


@pytest.fixture
def identity() -> Identity:
    return Identity.from_master(MASTER, "default", account_ss58=SS58)


@pytest.fixture
def client(identity: Identity) -> Client:
    return Client(token="tok", identity=identity, transport=Transport(BASE, "tok"))


def upload_ok(revision: int = 1) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "Success": {
                "upload_id": "u1",
                "timestamp": 1713139200,
                "revision_id": [revision] * 32,
                "created_at": 1,
                "updated_at": 1,
            }
        },
    )


@respx.mock
def test_put_sends_manifest_first_with_the_documented_content_types(
    client: Client, tmp_path: Path
) -> None:
    route = respx.post(f"{BASE}/upload").mock(return_value=upload_ok())
    local = tmp_path / "a.bin"
    local.write_bytes(b"x" * 65536)

    result = client.files.put(local, "docs/a.bin")

    assert result.revision_id == bytes([1] * 32)
    parts = multipart_parts(route.calls.last.request)
    assert [name for name, _, _ in parts] == ["manifest", "ciphertext"]
    assert parts[0][1] == "application/json"
    assert parts[1][1] == "application/octet-stream"


@respx.mock
def test_put_builds_a_manifest_the_server_would_accept(client: Client, tmp_path: Path) -> None:
    route = respx.post(f"{BASE}/upload").mock(return_value=upload_ok())
    plaintext = b"x" * 65536
    local = tmp_path / "a.bin"
    local.write_bytes(plaintext)

    client.files.put(local, "docs/a.bin")

    name, _, body = multipart_parts(route.calls.last.request)[0]
    manifest = Manifest.model_validate_json(body)
    assert name == "manifest"
    assert manifest.size_bytes == 65536  # plaintext, not ciphertext
    assert manifest.ss58_address == SS58
    assert manifest.folder_hash == FOLDER
    assert manifest.revision_seq == 1
    assert manifest.base_revision_id is None
    assert manifest.relative_path == "docs/a.bin"
    assert manifest.file_name == "a.bin"
    assert manifest.source == "python-sdk"
    assert manifest.path_hash == hashes.path_hash("docs/a.bin")
    assert manifest.salted_hash == hashes.salted_hash(SS58, plaintext)
    VerifyKey(manifest.signing_key).verify(
        tos_text(manifest.ciphertext_hash).encode(), manifest.signature
    )


@respx.mock
def test_put_ciphertext_matches_the_manifest_hash_and_decrypts(
    client: Client, identity: Identity, tmp_path: Path
) -> None:
    route = respx.post(f"{BASE}/upload").mock(return_value=upload_ok())
    plaintext = b"hello hippius"
    local = tmp_path / "a.bin"
    local.write_bytes(plaintext)

    client.files.put(local, "a.bin")

    parts = multipart_parts(route.calls.last.request)
    manifest = Manifest.model_validate_json(parts[0][2])
    blob = parts[1][2]
    assert hashes.blake3_hex(blob) == manifest.ciphertext_hash
    assert len(blob) == file_cipher.ciphertext_size(len(plaintext))
    assert file_cipher.decrypt_bytes(blob, identity.encryption_key) == plaintext
    assert file_cipher.decrypt_bytes(manifest.encrypted_path, identity.encryption_key) == b"a.bin"


@respx.mock
def test_put_bytes_handles_a_zero_byte_file(client: Client, identity: Identity) -> None:
    route = respx.post(f"{BASE}/upload").mock(return_value=upload_ok())
    client.files.put_bytes(b"", "empty.bin")
    parts = multipart_parts(route.calls.last.request)
    manifest = Manifest.model_validate_json(parts[0][2])
    assert manifest.size_bytes == 0
    assert len(parts[1][2]) == 24 + 4 + 4 + 16  # one empty frame
    assert file_cipher.decrypt_bytes(parts[1][2], identity.encryption_key) == b""


@respx.mock
def test_put_with_a_base_revision_requires_a_revision_seq(client: Client) -> None:
    with pytest.raises(ValueError, match="revision_seq"):
        client.files.put_bytes(b"x", "a.bin", base_revision_id=bytes(32))


@respx.mock
def test_put_replacement_sends_the_base_revision(client: Client) -> None:
    route = respx.post(f"{BASE}/upload").mock(return_value=upload_ok(2))
    client.files.put_bytes(b"x", "a.bin", base_revision_id=bytes([7] * 32), revision_seq=2)
    manifest = Manifest.model_validate_json(multipart_parts(route.calls.last.request)[0][2])
    assert manifest.base_revision_id == bytes([7] * 32)
    assert manifest.revision_seq == 2


@respx.mock
def test_put_surfaces_a_stale_revision_as_conflict(client: Client) -> None:
    respx.post(f"{BASE}/upload").mock(
        return_value=httpx.Response(
            409,
            json={
                "Conflict": {
                    "error": "conflict",
                    "message": "stale",
                    "current_revision_id": [3] * 32,
                    "current_revision_seq": 9,
                }
            },
        )
    )
    with pytest.raises(errors.Conflict) as exc:
        client.files.put_bytes(b"x", "a.bin", base_revision_id=bytes(32), revision_seq=2)
    assert exc.value.current_revision_seq == 9
    assert exc.value.current_revision_id == bytes([3] * 32)


@respx.mock
def test_a_success_body_missing_required_fields_is_invalid_response(client: Client) -> None:
    respx.post(f"{BASE}/upload").mock(return_value=httpx.Response(200, json={"Success": {}}))
    with pytest.raises(errors.InvalidResponse, match="UploadResult"):
        client.files.put_bytes(b"x", "a.bin")


@respx.mock
def test_put_rejects_a_traversing_path_before_any_request(client: Client) -> None:
    route = respx.post(f"{BASE}/upload")
    with pytest.raises(ValueError, match="relative_path"):
        client.files.put_bytes(b"x", "../escape.bin")
    assert route.call_count == 0


@respx.mock
def test_get_rejects_malformed_size_headers(
    client: Client, identity: Identity, tmp_path: Path
) -> None:
    blob = file_cipher.encrypt_bytes(b"y", identity.encryption_key)
    file_id = client.files.file_id("a.bin")
    respx.get(f"{BASE}/download/{SS58}/{FOLDER}/{file_id}").mock(
        return_value=httpx.Response(200, content=blob, headers={"X-Size-Bytes": "not-a-number"})
    )
    with pytest.raises(errors.InvalidResponse, match="download headers"):
        client.files.get(file_id, tmp_path / "a.bin")
    assert not (tmp_path / "a.bin").exists()


def test_file_id_is_the_hex_path_hash(client: Client) -> None:
    assert client.files.file_id("docs/a.bin") == hashes.path_hash("docs/a.bin").hex()
    assert len(client.files.file_id("a")) == 64


@respx.mock
def test_get_writes_the_plaintext_and_reports_the_headers(
    client: Client, identity: Identity, tmp_path: Path
) -> None:
    plaintext = b"y" * 4096
    blob = file_cipher.encrypt_bytes(plaintext, identity.encryption_key)
    file_id = client.files.file_id("a.bin")
    respx.get(f"{BASE}/download/{SS58}/{FOLDER}/{file_id}").mock(
        return_value=httpx.Response(
            200,
            content=blob,
            headers={
                "X-Size-Bytes": "4096",
                "X-Revision-Id": "ab" * 32,
                "X-Revision-Seq": "3",
            },
        )
    )
    dest = tmp_path / "out" / "a.bin"
    info = client.files.get(file_id, dest)

    assert dest.read_bytes() == plaintext
    assert info.size_bytes == 4096
    assert info.revision_id == bytes.fromhex("ab" * 32)
    assert info.revision_seq == 3
    assert not (tmp_path / "out" / "a.bin.part").exists()
    if os.name == "posix":
        assert stat.S_IMODE(dest.stat().st_mode) == 0o600


@respx.mock
def test_get_forces_0600_on_a_preexisting_part_file(
    client: Client, identity: Identity, tmp_path: Path
) -> None:
    plaintext = b"y" * 64
    blob = file_cipher.encrypt_bytes(plaintext, identity.encryption_key)
    file_id = client.files.file_id("a.bin")
    respx.get(f"{BASE}/download/{SS58}/{FOLDER}/{file_id}").mock(
        return_value=httpx.Response(200, content=blob, headers={"X-Size-Bytes": "64"})
    )
    dest = tmp_path / "a.bin"
    part = dest.with_name("a.bin.part")
    part.write_bytes(b"stale")
    part.chmod(0o644)
    client.files.get(file_id, dest)
    assert dest.read_bytes() == plaintext
    if os.name == "posix":
        assert stat.S_IMODE(dest.stat().st_mode) == 0o600


@respx.mock
def test_get_leaves_nothing_behind_when_a_frame_is_tampered(
    client: Client, identity: Identity, tmp_path: Path
) -> None:
    blob = bytearray(file_cipher.encrypt_bytes(b"y" * 1024, identity.encryption_key))
    blob[-1] ^= 0xFF
    file_id = client.files.file_id("a.bin")
    respx.get(f"{BASE}/download/{SS58}/{FOLDER}/{file_id}").mock(
        return_value=httpx.Response(200, content=bytes(blob))
    )
    dest = tmp_path / "a.bin"
    with pytest.raises(errors.DecryptError):
        client.files.get(file_id, dest)
    assert not dest.exists()
    assert not dest.with_name("a.bin.part").exists()


@respx.mock
def test_get_bytes_round_trips(client: Client, identity: Identity) -> None:
    plaintext = b"z" * (file_cipher.CHUNK_SIZE + 17)
    blob = file_cipher.encrypt_bytes(plaintext, identity.encryption_key)
    file_id = client.files.file_id("a.bin")
    respx.get(f"{BASE}/download/{SS58}/{FOLDER}/{file_id}").mock(
        return_value=httpx.Response(200, content=blob)
    )
    assert client.files.get_bytes(file_id) == plaintext


@respx.mock
def test_get_raises_the_typed_error_rather_than_decrypting_a_json_body(
    client: Client, tmp_path: Path
) -> None:
    file_id = client.files.file_id("a.bin")
    respx.get(f"{BASE}/download/{SS58}/{FOLDER}/{file_id}").mock(
        return_value=httpx.Response(404, json={"Error": {"error": "not_found", "message": "no"}})
    )
    with pytest.raises(errors.NotFound):
        client.files.get(file_id, tmp_path / "a.bin")


@respx.mock
def test_a_large_file_goes_through_a_session(client: Client, identity: Identity) -> None:
    plaintext_size = TRANSPORT_CHUNK * 2 + 1024
    create = respx.post(f"{BASE}/upload/session").mock(
        return_value=httpx.Response(
            200, json={"Success": {"session_id": "s1", "expires_at": 1713225600}}
        )
    )
    chunks = respx.put(url__regex=rf"{BASE}/upload/session/s1/chunk/\d+").mock(
        side_effect=lambda request: httpx.Response(200, json={"Success": {"chunk_index": 0}})
    )
    status = respx.get(f"{BASE}/upload/session/s1/status").mock(
        return_value=httpx.Response(
            200,
            json={
                "Success": {
                    "session_id": "s1",
                    "state": "receiving",
                    "total_chunks": 3,
                    "chunks_received": [0, 1, 2],
                }
            },
        )
    )
    finalize = respx.post(f"{BASE}/upload/session/s1/finalize").mock(return_value=upload_ok(4))
    single = respx.post(f"{BASE}/upload")

    result = client.files.put_bytes(b"q" * plaintext_size, "big.bin")

    assert result.revision_id == bytes([4] * 32)
    assert single.call_count == 0
    assert create.call_count == 1
    assert chunks.call_count == 3
    assert status.call_count == 1
    assert finalize.call_count == 1

    body = json.loads(create.calls.last.request.content)
    assert body["chunk_count"] == 3
    assert body["chunk_size"] == TRANSPORT_CHUNK
    assert body["ciphertext_size"] == file_cipher.ciphertext_size(plaintext_size)
    assert body["manifest"]["size_bytes"] == plaintext_size


@respx.mock
def test_finalize_carries_content_length_zero(client: Client) -> None:
    respx.post(f"{BASE}/upload/session").mock(
        return_value=httpx.Response(200, json={"Success": {"session_id": "s1"}})
    )
    respx.put(url__regex=rf"{BASE}/upload/session/s1/chunk/\d+").mock(
        return_value=httpx.Response(200, json={"Success": {"chunk_index": 0}})
    )
    respx.get(f"{BASE}/upload/session/s1/status").mock(
        return_value=httpx.Response(
            200, json={"Success": {"total_chunks": 2, "chunks_received": [0, 1]}}
        )
    )
    finalize = respx.post(f"{BASE}/upload/session/s1/finalize").mock(return_value=upload_ok())

    client.files.put_bytes(b"q" * (TRANSPORT_CHUNK + 1), "big.bin")
    assert finalize.calls.last.request.headers["content-length"] == "0"


@respx.mock
@pytest.mark.anyio
async def test_async_get_round_trips_to_disk(identity: Identity, tmp_path: Path) -> None:
    plaintext = b"y" * (file_cipher.CHUNK_SIZE + 9)
    blob = file_cipher.encrypt_bytes(plaintext, identity.encryption_key)
    file_id = hashes.path_hash("a.bin").hex()
    respx.get(f"{BASE}/download/{SS58}/{FOLDER}/{file_id}").mock(
        return_value=httpx.Response(200, content=blob, headers={"X-Size-Bytes": "262153"})
    )
    dest = tmp_path / "out" / "a.bin"
    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as client:
        info = await client.files.get(file_id, dest)
        assert await client.files.get_bytes(file_id) == plaintext

    assert dest.read_bytes() == plaintext
    assert info.size_bytes == 262153
    assert not dest.with_name("a.bin.part").exists()


@respx.mock
@pytest.mark.anyio
async def test_async_get_raises_the_typed_error_for_a_json_body(
    identity: Identity, tmp_path: Path
) -> None:
    # Reading an error body off an async stream needs aread(); the sync read()
    # raises, which would turn every async 404 into an unrelated RuntimeError.
    file_id = hashes.path_hash("a.bin").hex()
    respx.get(f"{BASE}/download/{SS58}/{FOLDER}/{file_id}").mock(
        return_value=httpx.Response(404, json={"Error": {"error": "not_found", "message": "no"}})
    )
    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as client:
        with pytest.raises(errors.NotFound):
            await client.files.get(file_id, tmp_path / "a.bin")
        with pytest.raises(errors.NotFound):
            await client.files.get_bytes(file_id)


@respx.mock
@pytest.mark.anyio
async def test_async_get_leaves_nothing_behind_when_a_frame_is_tampered(
    identity: Identity, tmp_path: Path
) -> None:
    blob = bytearray(file_cipher.encrypt_bytes(b"y" * 1024, identity.encryption_key))
    blob[-1] ^= 0xFF
    file_id = hashes.path_hash("a.bin").hex()
    respx.get(f"{BASE}/download/{SS58}/{FOLDER}/{file_id}").mock(
        return_value=httpx.Response(200, content=bytes(blob))
    )
    dest = tmp_path / "a.bin"
    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as client:
        with pytest.raises(errors.DecryptError):
            await client.files.get(file_id, dest)
    assert not dest.exists()
    assert not dest.with_name("a.bin.part").exists()


@respx.mock
@pytest.mark.anyio
async def test_async_put_and_delete(identity: Identity) -> None:
    respx.post(f"{BASE}/upload").mock(return_value=upload_ok(6))
    file_id = hashes.path_hash("a.bin").hex()
    respx.delete(f"{BASE}/delete/{SS58}/{FOLDER}/{file_id}").mock(
        return_value=httpx.Response(200, json={"Success": {"status": "deleted"}})
    )
    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as client:
        result = await client.files.put_bytes(b"hello", "a.bin")
        assert result.revision_id == bytes([6] * 32)
        assert (await client.files.delete(file_id)).status == "deleted"


@respx.mock
@pytest.mark.anyio
async def test_async_put_from_a_path(identity: Identity, tmp_path: Path) -> None:
    route = respx.post(f"{BASE}/upload").mock(return_value=upload_ok(8))
    local = tmp_path / "a.bin"
    local.write_bytes(b"from disk")
    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as client:
        result = await client.files.put(local, "docs/a.bin")
    assert result.revision_id == bytes([8] * 32)
    manifest = Manifest.model_validate_json(multipart_parts(route.calls.last.request)[0][2])
    assert manifest.size_bytes == len(b"from disk")


@respx.mock
@pytest.mark.anyio
async def test_async_browse_defaults_to_the_folder_root(identity: Identity) -> None:
    route = respx.get(f"{BASE}/browse/{SS58}/{FOLDER}").mock(
        return_value=httpx.Response(200, json={"Success": {"folders": [], "files": []}})
    )
    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as client:
        await client.files.browse()
    assert dict(route.calls.last.request.url.params)["path"] == ""


@respx.mock
@pytest.mark.anyio
async def test_async_download_that_dies_mid_body_leaves_no_part_file(
    identity: Identity, tmp_path: Path
) -> None:
    # A stream that dies must surface as TransportError and leave no .part
    # file behind for the next run to trip over.
    respx.get(f"{BASE}/download/{SS58}/{FOLDER}/{'ff' * 32}").mock(
        side_effect=httpx.ReadError("connection reset")
    )
    dest = tmp_path / "a.bin"
    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as client:
        with pytest.raises(errors.TransportError):
            await client.files.get("ff" * 32, dest)
    assert not dest.exists()
    assert not dest.with_name("a.bin.part").exists()


def test_async_client_reports_its_server_url(identity: Identity) -> None:
    client = AsyncClient(token="tok", identity=identity, transport=AsyncTransport(BASE, "tok"))
    assert client.server_url == BASE
    assert client.transport.base_url == BASE
