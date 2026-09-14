"""Chunked upload sessions for blobs too large for one request.

Routing matches hcfs-client: a ciphertext that occupies more than one 8 MiB
transport chunk goes through a session. The single-shot path buffers the whole
multipart body and fails entirely on a network blip, whereas a session takes
chunks in any order and lets a failed one be resent on its own.

There is no per-chunk signature. The server verifies the assembled blob against
``manifest.ciphertext_hash`` at finalize, so a chunk corrupted in transit fails
the finalize rather than its own PUT.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Protocol, TypeVar

from hippius_drive import _ops, models
from hippius_drive._ops import Op
from hippius_drive._upload import TRANSPORT_CHUNK, PreparedUpload

T = TypeVar("T")

DEFAULT_PARALLEL = 4
"""Concurrent chunk uploads. Bounded so a client cannot self-DoS the service."""


class Runner(Protocol):
    """The one thing a session needs from a client: run an operation."""

    def run(self, op: Op[T]) -> T:
        """Send an operation and parse its result."""
        ...


class AsyncRunner(Protocol):
    """Async twin of :class:`Runner`."""

    async def run(self, op: Op[T]) -> T:
        """Send an operation and parse its result."""
        ...


@dataclass(frozen=True)
class SessionPlan:
    """How one blob is cut up and pushed.

    Attributes:
        prepared: The signed manifest and encrypted blob.
        chunk_size: Bytes per transport chunk.
        parallel: Concurrent chunk uploads.
    """

    prepared: PreparedUpload
    chunk_size: int = TRANSPORT_CHUNK
    parallel: int = DEFAULT_PARALLEL

    @property
    def total_chunks(self) -> int:
        """How many transport chunks the blob occupies; never zero."""
        return self.prepared.transport_chunk_count(self.chunk_size)

    def payloads(self, indices: Iterable[int]) -> list[tuple[int, bytes]]:
        """Read the given chunks off the blob, in this thread.

        The spooled blob has a single file position, so reading here rather
        than inside the workers keeps concurrent seeks from interleaving and
        handing a worker the wrong bytes.

        Args:
            indices: The chunk indices to read.

        Returns:
            One ``(index, bytes)`` pair per chunk.
        """
        return [(index, self.prepared.read_chunk(index, self.chunk_size)) for index in indices]


def _missing(status: models.SessionStatusResult, total: int) -> list[int]:
    """Indices the server has not acknowledged yet."""
    return sorted(set(range(total)) - set(status.chunks_received))


def upload_via_session(
    client: Runner, prepared: PreparedUpload, plan: SessionPlan | None = None
) -> models.UploadResult:
    """Upload ``prepared`` in chunks and commit it.

    On any failure after the session opens, the session is deleted on a
    best-effort basis before the error propagates: an abandoned session holds
    temporary storage and counts against the drive's live-session limit until
    it expires.

    Args:
        client: Something that can run operations.
        prepared: The signed manifest and encrypted blob.
        plan: Chunk size and concurrency; the hcfs defaults when omitted.

    Returns:
        The upload result, carrying the new ``revision_id``.

    Raises:
        DriveError: Whatever the service reported, after the cleanup attempt.
    """
    plan = plan if plan is not None else SessionPlan(prepared)
    session = client.run(_ops.create_session(prepared, plan.chunk_size))
    try:
        _send(client, plan, session.session_id, range(plan.total_chunks))

        # One status read catches a chunk the server never committed, which a
        # 200 on the PUT does not rule out behind a retrying proxy.
        status = client.run(_ops.session_status(session.session_id))
        retry = _missing(status, plan.total_chunks)
        if retry:
            _send(client, plan, session.session_id, retry)

        return client.run(_ops.finalize_session(session.session_id))
    except BaseException:
        # Cleanup must never mask the failure the caller needs to see.
        with contextlib.suppress(Exception):
            client.run(_ops.delete_session(session.session_id))
        raise


def _send(client: Runner, plan: SessionPlan, session_id: str, indices: Iterable[int]) -> None:
    """Send the given chunk indices, up to ``plan.parallel`` at a time.

    Chunks are read in batches of ``parallel`` rather than all at once, so a
    multi-gigabyte blob is not duplicated into RAM on top of the spool.
    """
    pending = list(indices)
    if not pending:
        return
    workers = min(plan.parallel, len(pending))

    def put(item: tuple[int, bytes]) -> None:
        client.run(_ops.upload_chunk(session_id, *item))

    with ThreadPoolExecutor(workers) as pool:
        for offset in range(0, len(pending), plan.parallel):
            payloads = plan.payloads(pending[offset : offset + plan.parallel])
            list(pool.map(put, payloads))


async def upload_via_session_async(
    client: AsyncRunner, prepared: PreparedUpload, plan: SessionPlan | None = None
) -> models.UploadResult:
    """Async twin of :func:`upload_via_session`.

    Args:
        client: Something that can run operations.
        prepared: The signed manifest and encrypted blob.
        plan: Chunk size and concurrency; the hcfs defaults when omitted.

    Returns:
        The upload result.

    Raises:
        DriveError: Whatever the service reported, after the cleanup attempt.
    """
    plan = plan if plan is not None else SessionPlan(prepared)
    session: models.CreateSessionResult = await client.run(
        _ops.create_session(prepared, plan.chunk_size)
    )
    try:
        await _send_async(client, plan, session.session_id, range(plan.total_chunks))

        status: models.SessionStatusResult = await client.run(
            _ops.session_status(session.session_id)
        )
        retry = _missing(status, plan.total_chunks)
        if retry:
            await _send_async(client, plan, session.session_id, retry)

        result: models.UploadResult = await client.run(_ops.finalize_session(session.session_id))
    except BaseException:
        with contextlib.suppress(Exception):
            await client.run(_ops.delete_session(session.session_id))
        raise
    return result


async def _send_async(
    client: AsyncRunner, plan: SessionPlan, session_id: str, indices: Iterable[int]
) -> None:
    """Send the given chunk indices, up to ``plan.parallel`` in flight."""
    pending = list(indices)
    if not pending:
        return
    limit = asyncio.Semaphore(plan.parallel)

    async def send(index: int, data: bytes) -> None:
        async with limit:
            await client.run(_ops.upload_chunk(session_id, index, data))

    for offset in range(0, len(pending), plan.parallel):
        payloads = plan.payloads(pending[offset : offset + plan.parallel])
        await asyncio.gather(*(send(index, data) for index, data in payloads))
