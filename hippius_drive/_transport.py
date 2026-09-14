"""httpx adapters that run the sans-I/O requests, sync and async.

Both share :func:`prepare` and the retry policy, so a change to either lands
in both at once. The policy is deliberately narrow: retry only failures that
say nothing about the request itself (connect, read timeout, 502/503/504), and
never a 4xx, which would just fail again.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import AsyncIterator, Callable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager, contextmanager
from typing import Any

import httpx

from hippius_drive import errors
from hippius_drive._version import __version__
from hippius_drive._wire import Request, parse_envelope

USER_AGENT = f"hippius-drive/{__version__}"
"""Identifies this SDK on the wire so a server can tell clients apart."""

EU_BASE_URL = "https://eu-central-1-arion.hippius.com"
US_BASE_URL = "https://us-east-1-arion.hippius.com"
REGIONS: tuple[str, ...] = (EU_BASE_URL, US_BASE_URL)
"""Regional endpoints, in the order hcfs-client probes them."""

PROBE_TIMEOUT = 5.0
"""Seconds to wait for a region's ``/health`` before giving up on it."""

DEFAULT_TIMEOUT = 60.0
"""Per-attempt connect/read/pool budget in seconds. Writes are uncapped: an
8 MiB session chunk on a slow uplink would otherwise die at 60s."""

MAX_ATTEMPTS = 3
_BACKOFF_SECONDS = (0.5, 1.0, 2.0)
_RETRYABLE_STATUSES = frozenset({502, 503, 504})
_MIN_RETRY_AFTER = 1
_MAX_RETRY_AFTER = 120


def _jittered(delay: float) -> float:
    """Spread retries so a fleet of clients does not resynchronise on an outage."""
    return delay * (0.5 + random.random())  # noqa: S311 - backoff jitter, not crypto


def _http_timeout(timeout: float | httpx.Timeout) -> httpx.Timeout:
    """Apply ``timeout`` to connect/read/pool, never to the request body write."""
    if isinstance(timeout, httpx.Timeout):
        return timeout
    return httpx.Timeout(timeout, write=None)


def prepare(request: Request, token: str) -> dict[str, Any]:
    """Turn a :class:`Request` into httpx keyword arguments.

    Args:
        request: The sans-I/O request.
        token: The bearer token.

    Returns:
        Keyword arguments for ``httpx.Client.request``.
    """
    headers = {"Authorization": f"Bearer {token}", "User-Agent": USER_AGENT}
    if request.headers:
        headers.update(request.headers)

    kwargs: dict[str, Any] = {"method": request.method, "url": request.path, "headers": headers}
    if request.params is not None:
        kwargs["params"] = request.params
    if request.json is not None:
        kwargs["json"] = request.json
    if request.content is not None:
        kwargs["content"] = request.content
    if request.files is not None:
        kwargs["files"] = request.files
    return kwargs


def _retry_after(response: httpx.Response) -> int | None:
    raw = response.headers.get("Retry-After")
    if raw is None:
        return None
    try:
        seconds = int(raw)
    except ValueError:
        return None
    return max(_MIN_RETRY_AFTER, min(_MAX_RETRY_AFTER, seconds))


def unwrap(response: httpx.Response) -> Any:
    """Parse an httpx response into the ``Success`` payload, or raise.

    Args:
        response: The response to read.

    Returns:
        The unwrapped payload.

    Raises:
        DriveError: For any error status or unparseable body.
    """
    try:
        body: Any = response.json()
    except ValueError:
        body = response.text
    return parse_envelope(response.status_code, body, retry_after=_retry_after(response))


def _attempts_for(request: Request) -> int:
    """How many times ``request`` may be sent.

    A file handle or generator body is consumed by the first attempt, so
    replaying it would put a truncated body on the wire. Only bytes and JSON
    bodies get the full ladder.
    """
    if request.files is not None:
        replayable = all(isinstance(content, bytes) for _, (_, content, _) in request.files)
    else:
        replayable = not isinstance(request.content, Iterator)
    return MAX_ATTEMPTS if replayable else 1


def _transport_error(exc: Exception) -> errors.TransportError:
    return errors.TransportError(f"{type(exc).__name__}: {exc}")


_RETRYABLE_EXCEPTIONS = (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout)


class Transport:
    """Synchronous httpx adapter with bounded retry.

    Attributes:
        base_url: The server this transport talks to.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        timeout: float | httpx.Timeout = DEFAULT_TIMEOUT,
        *,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Build the transport.

        Args:
            base_url: The server root, without a trailing slash.
            token: The bearer token.
            timeout: Connect/read/pool budget in seconds, or a full
                ``httpx.Timeout``. A float leaves the write side uncapped.
            sleep: Injected so tests do not actually wait out the backoff.
        """
        self.base_url = base_url.rstrip("/")
        self._token = token
        self._sleep = sleep
        self._client = httpx.Client(base_url=self.base_url, timeout=_http_timeout(timeout))

    def send(self, request: Request) -> httpx.Response:
        """Send ``request``, retrying only failures that say nothing about it.

        Args:
            request: The sans-I/O request.

        Returns:
            The final response, whatever its status.

        Raises:
            TransportError: If every attempt failed before a response arrived.
        """
        kwargs = prepare(request, self._token)
        attempts = _attempts_for(request)
        last: Exception | None = None
        for attempt in range(1, attempts + 1):
            try:
                response = self._client.request(**kwargs)
            except _RETRYABLE_EXCEPTIONS as exc:
                last = exc
            except httpx.HTTPError as exc:
                # A write error, protocol error or pool timeout may have landed
                # a partial request, so it is not replayed.
                raise _transport_error(exc) from exc
            else:
                if attempt == attempts or response.status_code not in _RETRYABLE_STATUSES:
                    return response
                last = None
            if attempt < attempts:
                self._sleep(_jittered(_BACKOFF_SECONDS[attempt - 1]))
        assert last is not None  # noqa: S101 - the loop returns on any response
        raise _transport_error(last)

    def call(self, request: Request) -> Any:
        """Send ``request`` and unwrap the envelope.

        Args:
            request: The sans-I/O request.

        Returns:
            The ``Success`` payload.

        Raises:
            DriveError: For any error status.
        """
        return unwrap(self.send(request))

    @contextmanager
    def stream(self, request: Request) -> Iterator[httpx.Response]:
        """Open ``request`` as a streaming response, for downloads.

        Args:
            request: The sans-I/O request.

        Yields:
            The open response; the body has not been read.

        Raises:
            TransportError: If the connection failed.
        """
        kwargs = prepare(request, self._token)
        try:
            with self._client.stream(**kwargs) as response:
                yield response
        except httpx.HTTPError as exc:
            raise _transport_error(exc) from exc

    def close(self) -> None:
        """Close the underlying connection pool."""
        self._client.close()


class AsyncTransport:
    """Asynchronous httpx adapter; same policy as :class:`Transport`.

    Attributes:
        base_url: The server this transport talks to.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        timeout: float | httpx.Timeout = DEFAULT_TIMEOUT,
        *,
        sleep: Callable[[float], Any] = asyncio.sleep,
    ) -> None:
        """Build the transport.

        Args:
            base_url: The server root, without a trailing slash.
            token: The bearer token.
            timeout: Connect/read/pool budget in seconds, or a full
                ``httpx.Timeout``. A float leaves the write side uncapped.
            sleep: Injected so tests do not actually wait out the backoff.
        """
        self.base_url = base_url.rstrip("/")
        self._token = token
        self._sleep = sleep
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=_http_timeout(timeout))

    async def send(self, request: Request) -> httpx.Response:
        """Send ``request``, retrying only failures that say nothing about it.

        Args:
            request: The sans-I/O request.

        Returns:
            The final response, whatever its status.

        Raises:
            TransportError: If every attempt failed before a response arrived.
        """
        kwargs = prepare(request, self._token)
        attempts = _attempts_for(request)
        last: Exception | None = None
        for attempt in range(1, attempts + 1):
            try:
                response = await self._client.request(**kwargs)
            except _RETRYABLE_EXCEPTIONS as exc:
                last = exc
            except httpx.HTTPError as exc:
                raise _transport_error(exc) from exc
            else:
                if attempt == attempts or response.status_code not in _RETRYABLE_STATUSES:
                    return response
                last = None
            if attempt < attempts:
                await self._sleep(_jittered(_BACKOFF_SECONDS[attempt - 1]))
        assert last is not None  # noqa: S101 - the loop returns on any response
        raise _transport_error(last)

    async def call(self, request: Request) -> Any:
        """Send ``request`` and unwrap the envelope.

        Args:
            request: The sans-I/O request.

        Returns:
            The ``Success`` payload.

        Raises:
            DriveError: For any error status.
        """
        return unwrap(await self.send(request))

    @asynccontextmanager
    async def stream(self, request: Request) -> AsyncIterator[httpx.Response]:
        """Open ``request`` as a streaming response, for downloads.

        Args:
            request: The sans-I/O request.

        Yields:
            The open response; the body has not been read.

        Raises:
            TransportError: If the connection failed.
        """
        kwargs = prepare(request, self._token)
        try:
            async with self._client.stream(**kwargs) as response:
                yield response
        except httpx.HTTPError as exc:
            raise _transport_error(exc) from exc

    async def aclose(self) -> None:
        """Close the underlying connection pool."""
        await self._client.aclose()


def _probe(client: httpx.Client, base_url: str, timeout: float) -> bool:
    try:
        response = client.get(f"{base_url.rstrip('/')}/health", timeout=timeout)
    except httpx.HTTPError:
        return False
    return response.is_success


def pick_region(candidates: Sequence[str] = REGIONS, timeout: float = PROBE_TIMEOUT) -> str:
    """Return the first candidate whose ``/health`` answers, else the first.

    Falling back to ``candidates[0]`` rather than raising is deliberate: a
    probe can fail for reasons the real request would not hit, and the caller
    gets a better error from the real request than from the probe.

    Args:
        candidates: Region base URLs, in preference order.
        timeout: Budget in seconds for each phase (connect, then read) of
            each probe; probes run in parallel.

    Returns:
        The chosen base URL.
    """
    if not candidates:
        raise ValueError("pick_region needs at least one candidate")
    headers = {"User-Agent": USER_AGENT}
    with (
        httpx.Client(timeout=timeout, headers=headers) as client,
        ThreadPoolExecutor(len(candidates)) as pool,
    ):
        healthy = list(pool.map(lambda url: _probe(client, url, timeout), candidates))
    for url, ok in zip(candidates, healthy, strict=True):
        if ok:
            return url
    return candidates[0]


async def pick_region_async(
    candidates: Sequence[str] = REGIONS, timeout: float = PROBE_TIMEOUT
) -> str:
    """Async twin of :func:`pick_region`.

    Args:
        candidates: Region base URLs, in preference order.
        timeout: Budget in seconds for each phase (connect, then read) of
            each probe; probes run in parallel.

    Returns:
        The chosen base URL.
    """
    if not candidates:
        raise ValueError("pick_region_async needs at least one candidate")

    async def probe(client: httpx.AsyncClient, base_url: str) -> bool:
        try:
            response = await client.get(f"{base_url.rstrip('/')}/health", timeout=timeout)
        except httpx.HTTPError:
            return False
        return response.is_success

    headers = {"User-Agent": USER_AGENT}
    async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
        healthy = await asyncio.gather(*(probe(client, url) for url in candidates))
    for url, ok in zip(candidates, healthy, strict=True):
        if ok:
            return url
    return candidates[0]
