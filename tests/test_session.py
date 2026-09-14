from collections.abc import Iterable

import httpx
import pytest
import respx

from hippius_drive import _session, _upload, errors
from hippius_drive._transport import AsyncTransport, Transport
from hippius_drive._upload import TRANSPORT_CHUNK, PlaintextSource, UploadSpec
from hippius_drive.client import AsyncClient, Client
from hippius_drive.crypto import file_cipher
from hippius_drive.identity import Identity

BASE = "https://example.test"
MASTER = " ".join(["abandon"] * 23 + ["art"])
SS58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
# Small enough to cut a modest blob into several chunks without allocating
# megabytes per test; the real value is 8 MiB.
SMALL_CHUNK = 4096
PLAINTEXT_SIZE = SMALL_CHUNK * 3


@pytest.fixture
def identity() -> Identity:
    return Identity.from_master(MASTER, "default", account_ss58=SS58)


@pytest.fixture
def client(identity: Identity) -> Client:
    return Client(token="tok", identity=identity, transport=Transport(BASE, "tok"))


def prepared(identity: Identity, size: int = PLAINTEXT_SIZE) -> _upload.PreparedUpload:
    return _upload.prepare(identity, PlaintextSource.from_bytes(b"p" * size), UploadSpec("big.bin"))


def created(session_id: str = "s1") -> httpx.Response:
    return httpx.Response(200, json={"Success": {"session_id": session_id}})


def finalized() -> httpx.Response:
    return httpx.Response(
        200, json={"Success": {"upload_id": "u1", "timestamp": 1, "revision_id": [5] * 32}}
    )


def chunk_ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200, json={"Success": {"chunk_index": int(request.url.path.rsplit("/", 1)[1])}}
    )


def chunk_route() -> respx.Route:
    return respx.put(url__regex=rf"{BASE}/upload/session/s1/chunk/\d+")


def mock_status(total: int, received: list[int]) -> respx.Route:
    return respx.get(f"{BASE}/upload/session/s1/status").mock(
        return_value=httpx.Response(
            200, json={"Success": {"total_chunks": total, "chunks_received": received}}
        )
    )


def sent_indices(route: respx.Route) -> list[int]:
    return [int(call.request.url.path.rsplit("/", 1)[1]) for call in route.calls]


def test_plan_splits_the_blob_into_exact_chunks(identity: Identity) -> None:
    with prepared(identity) as up:
        plan = _session.SessionPlan(up, chunk_size=SMALL_CHUNK)
        assert plan.total_chunks == -(-up.ciphertext_size // SMALL_CHUNK)
        payloads = plan.payloads(range(plan.total_chunks))
        assert b"".join(data for _, data in payloads) == up.blob.read()
        assert all(len(data) == SMALL_CHUNK for _, data in payloads[:-1])
        assert 0 < len(payloads[-1][1]) <= SMALL_CHUNK


def test_a_blob_of_exactly_one_chunk_needs_no_session(identity: Identity) -> None:
    with prepared(identity, 1024) as up:
        assert up.transport_chunk_count() == 1
        assert up.ciphertext_size <= TRANSPORT_CHUNK


def test_the_assembled_chunks_reconstruct_a_decryptable_blob(identity: Identity) -> None:
    with prepared(identity) as up:
        plan = _session.SessionPlan(up, chunk_size=SMALL_CHUNK)
        assembled = b"".join(data for _, data in plan.payloads(range(plan.total_chunks)))
    assert file_cipher.decrypt_bytes(assembled, identity.encryption_key) == b"p" * PLAINTEXT_SIZE


@respx.mock
def test_every_chunk_is_put_once_with_its_own_index(client: Client, identity: Identity) -> None:
    respx.post(f"{BASE}/upload/session").mock(return_value=created())
    chunks = chunk_route().mock(side_effect=chunk_ok)
    respx.post(f"{BASE}/upload/session/s1/finalize").mock(return_value=finalized())

    with prepared(identity) as up:
        plan = _session.SessionPlan(up, chunk_size=SMALL_CHUNK, parallel=2)
        total = plan.total_chunks
        mock_status(total, list(range(total)))
        result = _session.upload_via_session(client, up, plan)
        expected = up.blob.read()

    assert result.revision_id == bytes([5] * 32)
    assert sorted(sent_indices(chunks)) == list(range(total))
    by_index = sorted(chunks.calls, key=lambda c: int(c.request.url.path.rsplit("/", 1)[1]))
    assert b"".join(call.request.content for call in by_index) == expected


@respx.mock
def test_a_chunk_that_503s_once_is_retried_by_the_transport(
    client: Client, identity: Identity
) -> None:
    respx.post(f"{BASE}/upload/session").mock(return_value=created())
    route = chunk_route()
    failures = [httpx.Response(503, json={"Error": {"error": "x", "message": ""}})]

    def flaky(request: httpx.Request) -> httpx.Response:
        return failures.pop() if failures else chunk_ok(request)

    route.side_effect = flaky
    respx.post(f"{BASE}/upload/session/s1/finalize").mock(return_value=finalized())

    with prepared(identity) as up:
        plan = _session.SessionPlan(up, chunk_size=SMALL_CHUNK, parallel=1)
        total = plan.total_chunks
        mock_status(total, list(range(total)))
        assert _session.upload_via_session(client, up, plan).upload_id == "u1"

    assert route.call_count == total + 1  # every chunk, plus the one retry


@respx.mock
def test_a_chunk_the_status_says_is_missing_is_resent(client: Client, identity: Identity) -> None:
    respx.post(f"{BASE}/upload/session").mock(return_value=created())
    chunks = chunk_route().mock(side_effect=chunk_ok)
    respx.post(f"{BASE}/upload/session/s1/finalize").mock(return_value=finalized())

    with prepared(identity) as up:
        plan = _session.SessionPlan(up, chunk_size=SMALL_CHUNK, parallel=1)
        total = plan.total_chunks
        # The server acknowledged everything but the last chunk, so it goes
        # again even though its own PUT already answered 200.
        mock_status(total, list(range(total - 1)))
        _session.upload_via_session(client, up, plan)

    assert sorted(sent_indices(chunks)) == [*range(total), total - 1]


@respx.mock
def test_a_failed_finalize_deletes_the_session(client: Client, identity: Identity) -> None:
    respx.post(f"{BASE}/upload/session").mock(return_value=created())
    chunk_route().mock(side_effect=chunk_ok)
    respx.post(f"{BASE}/upload/session/s1/finalize").mock(
        return_value=httpx.Response(
            400, json={"Error": {"error": "invalid_manifest", "message": "hash"}}
        )
    )
    deleted = respx.delete(f"{BASE}/upload/session/s1").mock(
        return_value=httpx.Response(200, json={"Success": {"deleted": True}})
    )

    with prepared(identity) as up:
        plan = _session.SessionPlan(up, chunk_size=SMALL_CHUNK, parallel=1)
        mock_status(plan.total_chunks, list(range(plan.total_chunks)))
        with pytest.raises(errors.InvalidRequest):
            _session.upload_via_session(client, up, plan)

    assert deleted.call_count == 1


@respx.mock
def test_a_failed_cleanup_does_not_mask_the_real_error(client: Client, identity: Identity) -> None:
    respx.post(f"{BASE}/upload/session").mock(return_value=created())
    chunk_route().mock(
        return_value=httpx.Response(403, json={"Error": {"error": "forbidden", "message": ""}})
    )
    respx.delete(f"{BASE}/upload/session/s1").mock(
        return_value=httpx.Response(404, json={"Error": {"error": "not_found", "message": ""}})
    )

    with prepared(identity) as up:
        plan = _session.SessionPlan(up, chunk_size=SMALL_CHUNK, parallel=1)
        with pytest.raises(errors.Forbidden):
            _session.upload_via_session(client, up, plan)


@respx.mock
def test_a_session_limit_429_reaches_the_caller(client: Client, identity: Identity) -> None:
    respx.post(f"{BASE}/upload/session").mock(
        return_value=httpx.Response(
            429,
            headers={"Retry-After": "30"},
            json={"Error": {"error": "session_limit", "message": "busy"}},
        )
    )
    with prepared(identity) as up:
        plan = _session.SessionPlan(up, chunk_size=SMALL_CHUNK)
        with pytest.raises(errors.RateLimited) as exc:
            _session.upload_via_session(client, up, plan)
    assert exc.value.retry_after == 30


@respx.mock
@pytest.mark.anyio
async def test_async_session_uploads_every_chunk(identity: Identity) -> None:
    respx.post(f"{BASE}/upload/session").mock(return_value=created())
    chunks = chunk_route().mock(side_effect=chunk_ok)
    respx.post(f"{BASE}/upload/session/s1/finalize").mock(return_value=finalized())

    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as client:
        with prepared(identity) as up:
            plan = _session.SessionPlan(up, chunk_size=SMALL_CHUNK, parallel=2)
            total = plan.total_chunks
            mock_status(total, list(range(total)))
            result = await _session.upload_via_session_async(client, up, plan)

    assert result.revision_id == bytes([5] * 32)
    assert sorted(sent_indices(chunks)) == list(range(total))


@respx.mock
@pytest.mark.anyio
async def test_async_failed_finalize_deletes_the_session(identity: Identity) -> None:
    respx.post(f"{BASE}/upload/session").mock(return_value=created())
    chunk_route().mock(side_effect=chunk_ok)
    respx.post(f"{BASE}/upload/session/s1/finalize").mock(
        return_value=httpx.Response(500, json={"Error": {"error": "database_error", "message": ""}})
    )
    deleted = respx.delete(f"{BASE}/upload/session/s1").mock(
        return_value=httpx.Response(200, json={"Success": {"deleted": True}})
    )

    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as client:
        with prepared(identity) as up:
            plan = _session.SessionPlan(up, chunk_size=SMALL_CHUNK, parallel=1)
            mock_status(plan.total_chunks, list(range(plan.total_chunks)))
            with pytest.raises(errors.ServerError):
                await _session.upload_via_session_async(client, up, plan)

    assert deleted.call_count == 1


@respx.mock
@pytest.mark.anyio
async def test_async_resends_a_chunk_the_status_says_is_missing(identity: Identity) -> None:
    respx.post(f"{BASE}/upload/session").mock(return_value=created())
    chunks = chunk_route().mock(side_effect=chunk_ok)
    respx.post(f"{BASE}/upload/session/s1/finalize").mock(return_value=finalized())

    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as client:
        with prepared(identity) as up:
            plan = _session.SessionPlan(up, chunk_size=SMALL_CHUNK, parallel=1)
            total = plan.total_chunks
            mock_status(total, list(range(total - 1)))
            await _session.upload_via_session_async(client, up, plan)

    assert sorted(sent_indices(chunks)) == [*range(total), total - 1]


@respx.mock
def test_send_reads_one_chunk_per_free_worker(
    client: Client, identity: Identity, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A batch of `parallel` would call payloads with 2 indices; loading the
    # whole blob would call it once with every index. One index per call is
    # the sliding window.
    respx.post(f"{BASE}/upload/session").mock(return_value=created())
    chunk_route().mock(side_effect=chunk_ok)
    respx.post(f"{BASE}/upload/session/s1/finalize").mock(return_value=finalized())
    widths: list[int] = []
    original = _session.SessionPlan.payloads

    def tracking(self: _session.SessionPlan, indices: Iterable[int]) -> list[tuple[int, bytes]]:
        items = list(indices)
        widths.append(len(items))
        return original(self, items)

    monkeypatch.setattr(_session.SessionPlan, "payloads", tracking)
    with prepared(identity) as up:
        plan = _session.SessionPlan(up, chunk_size=SMALL_CHUNK, parallel=2)
        mock_status(plan.total_chunks, list(range(plan.total_chunks)))
        _session.upload_via_session(client, up, plan)

    assert widths
    assert max(widths) == 1


def test_sending_no_chunks_is_a_no_op_rather_than_a_crash(
    client: Client, identity: Identity
) -> None:
    # An empty index set reaches ThreadPoolExecutor(0), which raises. The guard
    # is unreachable from upload_via_session today; this pins the contract so a
    # future caller cannot trip over it.
    with prepared(identity) as up:
        plan = _session.SessionPlan(up, chunk_size=SMALL_CHUNK)
        _session._send(client, plan, "s1", [])


@pytest.mark.anyio
async def test_async_sending_no_chunks_is_a_no_op(identity: Identity) -> None:
    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as client:
        with prepared(identity) as up:
            plan = _session.SessionPlan(up, chunk_size=SMALL_CHUNK)
            await _session._send_async(client, plan, "s1", [])


@respx.mock
@pytest.mark.anyio
async def test_async_send_reads_one_chunk_per_free_worker(
    identity: Identity, monkeypatch: pytest.MonkeyPatch
) -> None:
    respx.post(f"{BASE}/upload/session").mock(return_value=created())
    chunk_route().mock(side_effect=chunk_ok)
    respx.post(f"{BASE}/upload/session/s1/finalize").mock(return_value=finalized())
    widths: list[int] = []
    original = _session.SessionPlan.payloads

    def tracking(self: _session.SessionPlan, indices: Iterable[int]) -> list[tuple[int, bytes]]:
        items = list(indices)
        widths.append(len(items))
        return original(self, items)

    monkeypatch.setattr(_session.SessionPlan, "payloads", tracking)
    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as client:
        with prepared(identity) as up:
            plan = _session.SessionPlan(up, chunk_size=SMALL_CHUNK, parallel=2)
            mock_status(plan.total_chunks, list(range(plan.total_chunks)))
            await _session.upload_via_session_async(client, up, plan)

    assert widths
    assert max(widths) == 1


@pytest.mark.anyio
async def test_async_send_releases_the_slot_if_the_read_fails(
    identity: Identity, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(self: _session.SessionPlan, indices: Iterable[int]) -> list[tuple[int, bytes]]:
        raise RuntimeError("spool gone")

    monkeypatch.setattr(_session.SessionPlan, "payloads", boom)
    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as client:
        with prepared(identity) as up:
            plan = _session.SessionPlan(up, chunk_size=SMALL_CHUNK, parallel=2)
            with pytest.raises(RuntimeError, match="spool gone"):
                await _session._send_async(client, plan, "s1", [0, 1])
