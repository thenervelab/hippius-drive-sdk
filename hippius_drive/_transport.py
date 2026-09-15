"""httpx adapters that run the sans-I/O requests, sync and async.

Both share :func:`prepare` and the retry policy, so a change to either lands
in both at once. The policy is deliberately narrow: retry only failures that
say nothing about the request itself (connect, read timeout, 502/503/504), and
never a 4xx, which would just fail again.
"""

from __future__ import annotations

import asyncio
import random
import sys
import time
from collections.abc import AsyncIterator, Callable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager, contextmanager
from typing import Any
from urllib.parse import urlparse

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
"""Per-attempt budget in seconds for each phase httpx times separately."""

MAX_ATTEMPTS = 3
_BACKOFF_SECONDS = (0.5, 1.0, 2.0)
_RETRYABLE_STATUSES = frozenset({502, 503, 504})
_MIN_RETRY_AFTER = 1
_MAX_RETRY_AFTER = 120


def _jittered(delay: float) -> float:
    """Spread retries so a fleet of clients does not resynchronise on an outage."""
    return delay * (0.5 + random.random())  # noqa: S311 - backoff jitter, not crypto


_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})


def _require_https_server(base_url: str) -> None:
    """Reject cleartext URLs except loopback, used for local hcfs."""
    parsed = urlparse(base_url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme == "https" and host:
        return
    if parsed.scheme == "http" and host in _LOOPBACK:
        return
    raise ValueError(f"server_url must be https:// (or http:// on localhost), got {base_url!r}")


def _http_timeout(timeout: float | httpx.Timeout, *, cap_write: bool) -> httpx.Timeout:
    """Spread a float over the phases httpx times separately.

    The sync backend re-arms the write timeout on every socket send, so there
    it is an idle limit a live uplink never trips and the float caps it too.
    The anyio backend holds one deadline over the whole body, which would kill
    an 8 MiB session chunk at 60s on a link under ~140 KB/s, so the async
    transport leaves writes uncapped.

    ``None`` and non-positive floats are rejected: ``httpx.Timeout(None)``
    means "wait forever", which is not a useful default for a missing value.
    Pass an explicit ``httpx.Timeout`` to control phases individually.
    """
    if isinstance(timeout, httpx.Timeout):
        return timeout
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
        raise ValueError("timeout must be a positive number of seconds, or an httpx.Timeout")
    return httpx.Timeout(timeout) if cap_write else httpx.Timeout(timeout, write=None)


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
    bodies get the full ladder, unless ``request.replayable`` overrides.
    """
    if request.replayable is False:
        return 1
    if request.replayable is True:
        return MAX_ATTEMPTS
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
            timeout: Per-phase budget in seconds, or a full ``httpx.Timeout``.
            sleep: Injected so tests do not actually wait out the backoff.
        """
        if not token or not token.strip():
            raise ValueError("token is required")
        _require_https_server(base_url)
        self.base_url = base_url.rstrip("/")
        self._token = token
        self._sleep = sleep
        self._client = httpx.Client(
            base_url=self.base_url, timeout=_http_timeout(timeout, cap_write=True)
        )

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

        Retries the same connect/timeout/502-504 set as :meth:`send` until
        the body is yielded. After the first byte, the stream is not replayed.

        Args:
            request: The sans-I/O request.

        Yields:
            The open response; the body has not been read.

        Raises:
            TransportError: If the connection failed.
        """
        kwargs = prepare(request, self._token)
        cm, response = _acquire_sync_stream(self._client, kwargs, self._sleep, request)
        try:
            yield response
        except httpx.HTTPError as exc:
            cm.__exit__(*sys.exc_info())
            raise _transport_error(exc) from exc
        except BaseException:
            cm.__exit__(*sys.exc_info())
            raise
        else:
            cm.__exit__(None, None, None)

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
                ``httpx.Timeout``. A float leaves the write side uncapped,
                because anyio applies it to the whole request body.
            sleep: Injected so tests do not actually wait out the backoff.
        """
        if not token or not token.strip():
            raise ValueError("token is required")
        _require_https_server(base_url)
        self.base_url = base_url.rstrip("/")
        self._token = token
        self._sleep = sleep
        self._client = httpx.AsyncClient(
            base_url=self.base_url, timeout=_http_timeout(timeout, cap_write=False)
        )

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

        Same retry policy as :meth:`Transport.stream`: connect/timeout/502-504
        before the body is yielded, never after.

        Args:
            request: The sans-I/O request.

        Yields:
            The open response; the body has not been read.

        Raises:
            TransportError: If the connection failed.
        """
        kwargs = prepare(request, self._token)
        cm, response = await _acquire_async_stream(self._client, kwargs, self._sleep, request)
        try:
            yield response
        except httpx.HTTPError as exc:
            await cm.__aexit__(*sys.exc_info())
            raise _transport_error(exc) from exc
        except BaseException:
            await cm.__aexit__(*sys.exc_info())
            raise
        else:
            await cm.__aexit__(None, None, None)

    async def aclose(self) -> None:
        """Close the underlying connection pool."""
        await self._client.aclose()


def _keep_stream(attempt: int, attempts: int, status: int) -> bool:
    return attempt == attempts or status not in _RETRYABLE_STATUSES


def _acquire_sync_stream(
    client: httpx.Client,
    kwargs: dict[str, Any],
    sleep: Callable[[float], None],
    request: Request,
) -> tuple[Any, httpx.Response]:
    """Open a stream, retrying connect/timeout/502-504 before the body is read."""
    attempts = _attempts_for(request)
    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            cm = client.stream(**kwargs)
            response = cm.__enter__()
        except _RETRYABLE_EXCEPTIONS as exc:
            last = exc
        except httpx.HTTPError as exc:
            raise _transport_error(exc) from exc
        else:
            if _keep_stream(attempt, attempts, response.status_code):
                return cm, response
            cm.__exit__(None, None, None)
        if attempt < attempts:
            sleep(_jittered(_BACKOFF_SECONDS[attempt - 1]))
    assert last is not None  # noqa: S101 - a kept stream returns
    raise _transport_error(last)


async def _acquire_async_stream(
    client: httpx.AsyncClient,
    kwargs: dict[str, Any],
    sleep: Callable[[float], Any],
    request: Request,
) -> tuple[Any, httpx.Response]:
    """Async twin of :func:`_acquire_sync_stream`."""
    attempts = _attempts_for(request)
    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            cm = client.stream(**kwargs)
            response = await cm.__aenter__()
        except _RETRYABLE_EXCEPTIONS as exc:
            last = exc
        except httpx.HTTPError as exc:
            raise _transport_error(exc) from exc
        else:
            if _keep_stream(attempt, attempts, response.status_code):
                return cm, response
            await cm.__aexit__(None, None, None)
        if attempt < attempts:
            await sleep(_jittered(_BACKOFF_SECONDS[attempt - 1]))
    assert last is not None  # noqa: S101 - a kept stream returns
    raise _transport_error(last)


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
