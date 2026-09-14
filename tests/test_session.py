import asyncio
import threading
import time
from collections.abc import Callable

import httpx
import pytest
import respx

from hippius_drive import _session, _upload, errors
from hippius_drive._ops import Op
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
        payloads = [plan.payload(index) for index in range(plan.total_chunks)]
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
        assembled = b"".join(plan.payload(index)[1] for index in range(plan.total_chunks))
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


def _chunk_index(op: Op[object]) -> int:
    return int(op.request.path.rsplit("/", 1)[1])


def _track_reads(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    reads: list[int] = []
    original = _session.SessionPlan.payload

    def tracking(self: _session.SessionPlan, index: int) -> tuple[int, bytes]:
        reads.append(index)
        return original(self, index)

    monkeypatch.setattr(_session.SessionPlan, "payload", tracking)
    return reads


def _wait_until(condition: Callable[[], bool], timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("condition never held")
        time.sleep(0.005)


class _GatedRunner:
    """Every PUT blocks until the test releases it, so the window is visible."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._gates: dict[int, threading.Event] = {}

    def gate(self, index: int) -> threading.Event:
        with self._lock:
            return self._gates.setdefault(index, threading.Event())

    def run(self, op: Op[object]) -> None:
        assert self.gate(_chunk_index(op)).wait(timeout=5)


def test_send_reads_a_chunk_only_when_a_worker_is_free(
    identity: Identity, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The RAM bound on top of the spool is `parallel` chunks: no read happens
    # until a PUT has finished, and one finished PUT lets exactly one more in.
    reads = _track_reads(monkeypatch)
    runner = _GatedRunner()
    with prepared(identity, SMALL_CHUNK * 6) as up:
        plan = _session.SessionPlan(up, chunk_size=SMALL_CHUNK, parallel=2)
        total = plan.total_chunks
        worker = threading.Thread(
            target=_session._send, args=(runner, plan, "s1", range(total)), daemon=True
        )
        worker.start()
        _wait_until(lambda: len(reads) == 2)
        time.sleep(0.05)
        assert reads == [0, 1]

        runner.gate(0).set()
        _wait_until(lambda: len(reads) == 3)
        time.sleep(0.05)
        assert reads == [0, 1, 2]

        for index in range(1, total):
            runner.gate(index).set()
        worker.join(timeout=5)
        assert not worker.is_alive()
    assert reads == list(range(total))


@respx.mock
def test_sync_failure_stops_the_window_and_still_deletes_the_session(
    client: Client, identity: Identity
) -> None:
    # Chunk 0 is rejected while chunk 1 is in flight. The window must not be
    # topped up after the failure, and the cleanup must still run.
    respx.post(f"{BASE}/upload/session").mock(return_value=created())
    chunks = chunk_route()

    def reject_first(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/0"):
            return httpx.Response(
                401, json={"Error": {"error": "unauthorized", "message": "token rejected"}}
            )
        return chunk_ok(request)

    chunks.side_effect = reject_first
    deleted = respx.delete(f"{BASE}/upload/session/s1").mock(
        return_value=httpx.Response(200, json={"Success": None})
    )
    with prepared(identity, SMALL_CHUNK * 8) as up:
        plan = _session.SessionPlan(up, chunk_size=SMALL_CHUNK, parallel=2)
        with pytest.raises(errors.Unauthorized):
            _session.upload_via_session(client, up, plan)

    # At most the in-flight sibling, plus one top-up if it finished first.
    assert len(chunks.calls) <= plan.parallel + 1
    assert deleted.called


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


class _AsyncGatedRunner:
    """Async twin of :class:`_GatedRunner`."""

    def __init__(self) -> None:
        self._gates: dict[int, asyncio.Event] = {}

    def gate(self, index: int) -> asyncio.Event:
        return self._gates.setdefault(index, asyncio.Event())

    async def run(self, op: Op[object]) -> None:
        await self.gate(_chunk_index(op)).wait()


async def _settle(condition: Callable[[], bool], timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("condition never held")
        await asyncio.sleep(0.005)
    await asyncio.sleep(0.05)


@pytest.mark.anyio
async def test_async_send_reads_a_chunk_only_when_a_slot_is_free(
    identity: Identity, monkeypatch: pytest.MonkeyPatch
) -> None:
    reads = _track_reads(monkeypatch)
    runner = _AsyncGatedRunner()
    with prepared(identity, SMALL_CHUNK * 6) as up:
        plan = _session.SessionPlan(up, chunk_size=SMALL_CHUNK, parallel=2)
        total = plan.total_chunks
        sender = asyncio.create_task(_session._send_async(runner, plan, "s1", range(total)))
        await _settle(lambda: len(reads) == 2)
        assert reads == [0, 1]

        runner.gate(0).set()
        await _settle(lambda: len(reads) == 3)
        assert reads == [0, 1, 2]

        for index in range(1, total):
            runner.gate(index).set()
        await asyncio.wait_for(sender, timeout=5)
    assert reads == list(range(total))


@pytest.mark.anyio
async def test_async_send_releases_the_slot_if_the_read_fails(
    identity: Identity, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(self: _session.SessionPlan, index: int) -> tuple[int, bytes]:
        raise RuntimeError("spool gone")

    monkeypatch.setattr(_session.SessionPlan, "payload", boom)
    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as client:
        with prepared(identity) as up:
            plan = _session.SessionPlan(up, chunk_size=SMALL_CHUNK, parallel=2)
            with pytest.raises(RuntimeError, match="spool gone"):
                await _session._send_async(client, plan, "s1", [0, 1])


class _StallingRunner:
    """Fails the first chunk; every other chunk blocks until cancelled."""

    def __init__(self) -> None:
        self.started: list[int] = []
        self.cancelled: list[int] = []

    async def run(self, op: Op[object]) -> None:
        index = _chunk_index(op)
        self.started.append(index)
        if index == 0:
            raise errors.Unauthorized("unauthorized", "token rejected", 401)
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled.append(index)
            raise


@pytest.mark.anyio
async def test_async_send_stops_launching_chunks_after_one_fails(identity: Identity) -> None:
    # Once a PUT has failed the session is doomed, so reading and sending the
    # rest of the spool is wasted bandwidth. Any sibling already in flight
    # must be cancelled before the error propagates, or it would race the
    # delete_session cleanup and the transport close.
    runner = _StallingRunner()
    tasks_before = asyncio.all_tasks()
    with prepared(identity, SMALL_CHUNK * 8) as up:
        plan = _session.SessionPlan(up, chunk_size=SMALL_CHUNK, parallel=2)
        with pytest.raises(errors.Unauthorized):
            await asyncio.wait_for(
                _session._send_async(runner, plan, "s1", range(plan.total_chunks)), timeout=5
            )

    assert runner.started[0] == 0
    assert len(runner.started) <= plan.parallel
    assert runner.cancelled == runner.started[1:]
    assert asyncio.all_tasks() == tasks_before
