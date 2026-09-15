from contextlib import asynccontextmanager, contextmanager
from typing import Any, cast

import httpx
import pytest
import respx

from hippius_drive import errors
from hippius_drive._transport import (
    MAX_ATTEMPTS,
    REGIONS,
    USER_AGENT,
    AsyncTransport,
    Transport,
    _attempts_for,
    _http_timeout,
    pick_region,
    pick_region_async,
    prepare,
)
from hippius_drive._wire import Request, build

BASE = "https://example.test"


def transport() -> tuple[Transport, list[float]]:
    """A transport whose backoff is recorded instead of slept through."""
    slept: list[float] = []
    return Transport(BASE, "tok", sleep=slept.append), slept


def test_none_and_non_positive_timeouts_are_rejected() -> None:
    with pytest.raises(ValueError, match="positive"):
        Transport(BASE, "tok", timeout=0)
    with pytest.raises(ValueError, match="positive"):
        AsyncTransport(BASE, "tok", timeout=-1)
    with pytest.raises(ValueError, match="positive"):
        Transport(BASE, "tok", timeout=False)  # bool is not a duration
    with pytest.raises(ValueError, match="positive"):
        Transport(BASE, "tok", timeout=cast(Any, None))


def test_cleartext_server_urls_are_rejected_except_loopback() -> None:
    with pytest.raises(ValueError, match="https"):
        Transport("http://eu-central-1-arion.hippius.com", "tok")
    for url in ("http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:8080"):
        loopback = Transport(url, "tok")
        loopback.close()


def test_an_empty_token_is_rejected() -> None:
    with pytest.raises(ValueError, match="token"):
        Transport(BASE, "")
    with pytest.raises(ValueError, match="token"):
        AsyncTransport(BASE, "")
    with pytest.raises(ValueError, match="token"):
        Transport(BASE, "   ")


def test_replayable_override_wins_over_body_shape() -> None:
    streamed = Request("PUT", "/x", content=iter([b"a"]), replayable=True)
    assert _attempts_for(streamed) == MAX_ATTEMPTS
    assert _attempts_for(Request("POST", "/x", content=b"", replayable=False)) == 1


def test_prepare_adds_the_bearer_token() -> None:
    kwargs = prepare(build.list_folders("5G"), "tok")
    assert kwargs["headers"]["Authorization"] == "Bearer tok"
    assert kwargs["headers"]["User-Agent"] == USER_AGENT
    assert USER_AGENT.startswith("hippius-drive/")
    assert kwargs["method"] == "GET"
    assert kwargs["url"] == "/list_folders/5G"


def test_a_float_timeout_caps_every_phase_unless_told_otherwise() -> None:
    assert _http_timeout(60.0, cap_write=True) == httpx.Timeout(60.0)
    assert _http_timeout(60.0, cap_write=False) == httpx.Timeout(60.0, write=None)


def test_an_explicit_timeout_is_kept() -> None:
    given = httpx.Timeout(3.0, write=5.0)
    assert _http_timeout(given, cap_write=True) is given
    assert _http_timeout(given, cap_write=False) is given


def test_only_the_async_transport_leaves_writes_uncapped() -> None:
    # httpcore's sync backend re-arms the write timeout per socket send, so a
    # live uplink never trips it and it stays as stall detection. anyio holds
    # one deadline over the whole body, so the async side leaves it open.
    t = Transport(BASE, "tok", timeout=7.0)
    a = AsyncTransport(BASE, "tok", timeout=7.0)
    explicit = AsyncTransport(BASE, "tok", timeout=httpx.Timeout(3.0, write=5.0))
    assert t._client.timeout == httpx.Timeout(7.0)
    assert a._client.timeout == httpx.Timeout(7.0, write=None)
    assert explicit._client.timeout == httpx.Timeout(3.0, write=5.0)
    t.close()


@respx.mock
@pytest.mark.parametrize(
    "failure",
    [httpx.WriteError("reset mid-body"), httpx.RemoteProtocolError("eof"), httpx.PoolTimeout("")],
)
def test_a_non_retryable_httpx_failure_is_a_transport_error(failure: httpx.HTTPError) -> None:
    # A partial request may have landed, so it is not replayed; but the caller
    # still gets the SDK's error type, never a raw httpx exception.
    route = respx.get(f"{BASE}/list_folders/5G")
    route.side_effect = failure
    t, slept = transport()
    with pytest.raises(errors.TransportError, match=type(failure).__name__):
        t.call(build.list_folders("5G"))
    assert route.call_count == 1
    assert slept == []
    t.close()


def test_prepare_keeps_an_explicit_empty_body() -> None:
    kwargs = prepare(build.finalize_session("s1"), "tok")
    assert kwargs["content"] == b""


def test_prepare_merges_request_headers() -> None:
    kwargs = prepare(build.upload_chunk("s1", 0, b"x"), "tok")
    assert kwargs["headers"]["Content-Type"] == "application/octet-stream"
    assert kwargs["headers"]["Authorization"] == "Bearer tok"


@respx.mock
def test_success_is_unwrapped() -> None:
    respx.get(f"{BASE}/list_folders/5G").mock(
        return_value=httpx.Response(200, json={"Success": {"folders": []}})
    )
    t, _slept = transport()
    assert t.call(build.list_folders("5G")) == {"folders": []}
    t.close()


@respx.mock
def test_connect_error_then_success_retries() -> None:
    route = respx.get(f"{BASE}/list_folders/5G")
    route.side_effect = [
        httpx.ConnectError("boom"),
        httpx.Response(200, json={"Success": {"folders": []}}),
    ]
    t, slept = transport()
    assert t.call(build.list_folders("5G")) == {"folders": []}
    assert route.call_count == 2
    assert len(slept) == 1
    t.close()


@respx.mock
def test_connect_error_exhausts_the_ladder_then_raises_transport_error() -> None:
    route = respx.get(f"{BASE}/list_folders/5G")
    route.side_effect = httpx.ConnectError("boom")
    t, _slept = transport()
    with pytest.raises(errors.TransportError):
        t.call(build.list_folders("5G"))
    assert route.call_count == 3
    t.close()


@respx.mock
def test_503_is_retried_and_then_surfaces_as_server_error() -> None:
    route = respx.get(f"{BASE}/list_folders/5G")
    route.return_value = httpx.Response(503, json={"Error": {"error": "x", "message": "m"}})
    t, _slept = transport()
    with pytest.raises(errors.ServerError) as exc:
        t.call(build.list_folders("5G"))
    assert route.call_count == 3
    assert exc.value.retryable
    t.close()


@respx.mock
def test_500_is_not_retried() -> None:
    # 500 means the server processed and failed; replaying it is not free.
    route = respx.get(f"{BASE}/list_folders/5G")
    route.return_value = httpx.Response(500, json={"Error": {"error": "db", "message": "m"}})
    t, _slept = transport()
    with pytest.raises(errors.ServerError):
        t.call(build.list_folders("5G"))
    assert route.call_count == 1
    t.close()


@respx.mock
def test_4xx_is_never_retried() -> None:
    route = respx.get(f"{BASE}/list_folders/5G")
    route.return_value = httpx.Response(403, json={"Error": {"error": "forbidden", "message": ""}})
    t, _slept = transport()
    with pytest.raises(errors.Forbidden):
        t.call(build.list_folders("5G"))
    assert route.call_count == 1
    t.close()


@respx.mock
def test_429_carries_a_clamped_retry_after() -> None:
    respx.post(f"{BASE}/upload/session").mock(
        return_value=httpx.Response(
            429,
            headers={"Retry-After": "7"},
            json={"Error": {"error": "session_limit", "message": "m"}},
        )
    )
    t, _slept = transport()
    with pytest.raises(errors.RateLimited) as exc:
        t.call(build.create_session({}, 1, 1, 1))
    assert exc.value.retry_after == 7
    t.close()


@respx.mock
@pytest.mark.parametrize(("header", "expected"), [("0", 1), ("9999", 120), ("soon", None)])
def test_retry_after_clamping(header: str, expected: int | None) -> None:
    respx.post(f"{BASE}/upload/session").mock(
        return_value=httpx.Response(
            429, headers={"Retry-After": header}, json={"Error": {"error": "x", "message": ""}}
        )
    )
    t, _slept = transport()
    with pytest.raises(errors.RateLimited) as exc:
        t.call(build.create_session({}, 1, 1, 1))
    assert exc.value.retry_after == expected
    t.close()


@respx.mock
def test_a_streaming_body_is_never_replayed() -> None:
    route = respx.put(f"{BASE}/upload/session/s1/chunk/0")
    route.side_effect = httpx.ConnectError("boom")
    t, _slept = transport()
    streamed = Request("PUT", "/upload/session/s1/chunk/0", content=iter([b"a", b"b"]))
    with pytest.raises(errors.TransportError):
        t.send(streamed)
    assert route.call_count == 1
    t.close()


@respx.mock
def test_non_json_error_body_still_raises_typed() -> None:
    respx.get(f"{BASE}/list_folders/5G").mock(return_value=httpx.Response(500, text="<html>"))
    t, _slept = transport()
    with pytest.raises(errors.ServerError):
        t.call(build.list_folders("5G"))
    t.close()


@respx.mock
def test_stream_yields_the_open_response() -> None:
    respx.get(f"{BASE}/download/5G/abc/{'ff' * 32}").mock(
        return_value=httpx.Response(200, content=b"blob", headers={"X-Size-Bytes": "4"})
    )
    t, _slept = transport()
    with t.stream(build.download("5G", "abc", "ff" * 32)) as response:
        assert response.headers["X-Size-Bytes"] == "4"
        assert b"".join(response.iter_bytes()) == b"blob"
    t.close()


@respx.mock
def test_stream_retries_a_503_then_yields() -> None:
    route = respx.get(f"{BASE}/download/5G/abc/{'ff' * 32}")
    route.side_effect = [
        httpx.Response(503, json={"Error": {"error": "x", "message": ""}}),
        httpx.Response(200, content=b"blob"),
    ]
    t, slept = transport()
    with t.stream(build.download("5G", "abc", "ff" * 32)) as response:
        assert b"".join(response.iter_bytes()) == b"blob"
    assert route.call_count == 2
    assert slept
    t.close()


@respx.mock
def test_stream_does_not_retry_a_write_error() -> None:
    route = respx.get(f"{BASE}/download/5G/abc/{'ff' * 32}")
    route.side_effect = httpx.WriteError("reset")
    t, slept = transport()
    with (
        pytest.raises(errors.TransportError, match="WriteError"),
        t.stream(build.download("5G", "abc", "ff" * 32)),
    ):
        pass
    assert route.call_count == 1
    assert slept == []
    t.close()


@respx.mock
@pytest.mark.anyio
async def test_async_stream_retries_a_503_then_yields() -> None:
    route = respx.get(f"{BASE}/download/5G/abc/{'ff' * 32}")
    route.side_effect = [
        httpx.Response(503, json={"Error": {"error": "x", "message": ""}}),
        httpx.Response(200, content=b"blob"),
    ]
    slept: list[float] = []

    async def sleep(seconds: float) -> None:
        slept.append(seconds)

    t = AsyncTransport(BASE, "tok", sleep=sleep)
    async with t.stream(build.download("5G", "abc", "ff" * 32)) as response:
        assert b"".join([chunk async for chunk in response.aiter_bytes()]) == b"blob"
    assert route.call_count == 2
    assert slept
    await t.aclose()


@respx.mock
def test_create_session_json_is_retried_on_503() -> None:
    # hcfs-client retries 5xx on create_session; the server resumes a live row.
    route = respx.post(f"{BASE}/upload/session").mock(
        return_value=httpx.Response(503, json={"Error": {"error": "x", "message": ""}})
    )
    t, slept = transport()
    with pytest.raises(errors.ServerError):
        t.call(build.create_session({}, 1, 1, 1))
    assert route.call_count == 3
    assert slept
    t.close()


@respx.mock
def test_a_read_timeout_after_the_stream_opens_is_not_retried() -> None:
    # Retry is only for opening the stream. A timeout while reading the body
    # must become TransportError without a second GET (yielding twice after
    # contextlib.throw raises RuntimeError).
    opened = {"n": 0}

    @contextmanager
    def boom_stream(**_kwargs: object) -> Any:
        opened["n"] += 1

        class Resp:
            status_code = 200

            def iter_bytes(self) -> Any:
                raise httpx.ReadTimeout("stalled")

        yield Resp()

    t, slept = transport()
    object.__setattr__(t._client, "stream", boom_stream)
    with (
        pytest.raises(errors.TransportError, match="ReadTimeout"),
        t.stream(build.download("5G", "abc", "ff" * 32)) as response,
    ):
        list(response.iter_bytes())
    assert opened["n"] == 1
    assert slept == []
    t.close()


@respx.mock
@pytest.mark.anyio
async def test_async_read_timeout_after_the_stream_opens_is_not_retried() -> None:
    opened = {"n": 0}

    @asynccontextmanager
    async def boom_stream(**_kwargs: object) -> Any:
        opened["n"] += 1

        class Resp:
            status_code = 200

            def iter_bytes(self) -> Any:
                raise httpx.ReadTimeout("stalled")

        yield Resp()

    async def nosleep(_seconds: float) -> None:
        return None

    t = AsyncTransport(BASE, "tok", sleep=nosleep)
    object.__setattr__(t._client, "stream", boom_stream)
    with pytest.raises(errors.TransportError, match="ReadTimeout"):
        async with t.stream(build.download("5G", "abc", "ff" * 32)) as response:
            list(response.iter_bytes())
    assert opened["n"] == 1
    await t.aclose()


@respx.mock
def test_finalize_is_not_retried_on_502() -> None:
    # hcfs-client does not retry finalize. A 502 after commit must not POST twice.
    route = respx.post(f"{BASE}/upload/session/s1/finalize").mock(
        return_value=httpx.Response(502, json={"Error": {"error": "x", "message": ""}})
    )
    t, slept = transport()
    with pytest.raises(errors.ServerError):
        t.call(build.finalize_session("s1"))
    assert route.call_count == 1
    assert slept == []
    t.close()


@respx.mock
def test_pick_region_forwards_timeout_into_each_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[object] = []

    def recording_get(self: httpx.Client, url: object, **kwargs: object) -> httpx.Response:
        seen.append(kwargs.get("timeout"))
        assert self.headers["user-agent"] == USER_AGENT
        raise httpx.ConnectError("down")

    monkeypatch.setattr(httpx.Client, "get", recording_get)
    assert pick_region(timeout=0.01) == REGIONS[0]
    assert seen == [0.01, 0.01]


@respx.mock
def test_pick_region_skips_an_unhealthy_region() -> None:
    respx.get(f"{REGIONS[0]}/health").mock(return_value=httpx.Response(503))
    respx.get(f"{REGIONS[1]}/health").mock(return_value=httpx.Response(200, json={}))
    assert pick_region() == REGIONS[1]


@respx.mock
def test_pick_region_prefers_the_first_healthy_region() -> None:
    respx.get(f"{REGIONS[0]}/health").mock(return_value=httpx.Response(200, json={}))
    respx.get(f"{REGIONS[1]}/health").mock(return_value=httpx.Response(200, json={}))
    assert pick_region() == REGIONS[0]


@respx.mock
def test_pick_region_falls_back_to_the_first_when_all_fail() -> None:
    for region in REGIONS:
        respx.get(f"{region}/health").mock(side_effect=httpx.ConnectError("down"))
    assert pick_region() == REGIONS[0]


def test_pick_region_rejects_an_empty_candidate_list() -> None:
    with pytest.raises(ValueError, match="at least one"):
        pick_region([])


@respx.mock
@pytest.mark.anyio
async def test_async_transport_retries_and_unwraps() -> None:
    route = respx.get(f"{BASE}/list_folders/5G")
    route.side_effect = [
        httpx.ConnectError("boom"),
        httpx.Response(200, json={"Success": {"folders": []}}),
    ]
    slept: list[float] = []

    async def sleep(seconds: float) -> None:
        slept.append(seconds)

    t = AsyncTransport(BASE, "tok", sleep=sleep)
    assert await t.call(build.list_folders("5G")) == {"folders": []}
    assert route.call_count == 2
    assert len(slept) == 1
    await t.aclose()


@respx.mock
@pytest.mark.anyio
async def test_async_pick_region_skips_an_unhealthy_region() -> None:
    respx.get(f"{REGIONS[0]}/health").mock(return_value=httpx.Response(503))
    respx.get(f"{REGIONS[1]}/health").mock(return_value=httpx.Response(200, json={}))
    assert await pick_region_async() == REGIONS[1]


# The async transport shares the retry policy but not the code path, so each
# branch needs its own exercise; the sync tests above do not reach it.


@respx.mock
@pytest.mark.anyio
async def test_async_write_error_is_a_transport_error_and_not_replayed() -> None:
    route = respx.get(f"{BASE}/list_folders/5G")
    route.side_effect = httpx.WriteError("reset mid-body")
    t = AsyncTransport(BASE, "tok")
    with pytest.raises(errors.TransportError, match="WriteError"):
        await t.call(build.list_folders("5G"))
    assert route.call_count == 1
    await t.aclose()


@respx.mock
@pytest.mark.anyio
async def test_async_connect_error_exhausts_the_ladder() -> None:
    route = respx.get(f"{BASE}/list_folders/5G")
    route.side_effect = httpx.ConnectError("boom")
    slept: list[float] = []

    async def sleep(seconds: float) -> None:
        slept.append(seconds)

    t = AsyncTransport(BASE, "tok", sleep=sleep)
    with pytest.raises(errors.TransportError):
        await t.call(build.list_folders("5G"))
    assert route.call_count == 3
    assert len(slept) == 2
    await t.aclose()


@respx.mock
@pytest.mark.anyio
async def test_async_503_is_retried_then_surfaces_as_server_error() -> None:
    route = respx.get(f"{BASE}/list_folders/5G")
    route.return_value = httpx.Response(503, json={"Error": {"error": "x", "message": "m"}})

    async def sleep(seconds: float) -> None:
        return None

    t = AsyncTransport(BASE, "tok", sleep=sleep)
    with pytest.raises(errors.ServerError):
        await t.call(build.list_folders("5G"))
    assert route.call_count == 3
    await t.aclose()


@respx.mock
@pytest.mark.anyio
async def test_async_4xx_is_never_retried() -> None:
    route = respx.get(f"{BASE}/list_folders/5G")
    route.return_value = httpx.Response(404, json={"Error": {"error": "not_found", "message": ""}})
    t = AsyncTransport(BASE, "tok")
    with pytest.raises(errors.NotFound):
        await t.call(build.list_folders("5G"))
    assert route.call_count == 1
    await t.aclose()


@respx.mock
@pytest.mark.anyio
async def test_async_stream_connect_failure_is_a_transport_error() -> None:
    respx.get(f"{BASE}/download/5G/abc/{'ff' * 32}").mock(side_effect=httpx.ConnectError("down"))
    t = AsyncTransport(BASE, "tok")
    with pytest.raises(errors.TransportError):
        async with t.stream(build.download("5G", "abc", "ff" * 32)):
            pass
    await t.aclose()


@respx.mock
def test_sync_stream_connect_failure_is_a_transport_error() -> None:
    respx.get(f"{BASE}/download/5G/abc/{'ff' * 32}").mock(side_effect=httpx.ConnectError("down"))
    t, _ = transport()
    with pytest.raises(errors.TransportError), t.stream(build.download("5G", "abc", "ff" * 32)):
        pass
    t.close()


@respx.mock
@pytest.mark.anyio
async def test_async_pick_region_falls_back_to_the_first_when_all_fail() -> None:
    for region in REGIONS:
        respx.get(f"{region}/health").mock(side_effect=httpx.ConnectError("down"))
    assert await pick_region_async() == REGIONS[0]


@respx.mock
@pytest.mark.anyio
async def test_async_pick_region_prefers_the_first_healthy_region() -> None:
    for region in REGIONS:
        respx.get(f"{region}/health").mock(return_value=httpx.Response(200, json={}))
    assert await pick_region_async() == REGIONS[0]


@respx.mock
@pytest.mark.anyio
async def test_async_pick_region_forwards_timeout_into_each_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[object] = []

    async def recording_get(
        self: httpx.AsyncClient, url: object, **kwargs: object
    ) -> httpx.Response:
        seen.append(kwargs.get("timeout"))
        assert self.headers["user-agent"] == USER_AGENT
        raise httpx.ConnectError("down")

    monkeypatch.setattr(httpx.AsyncClient, "get", recording_get)
    assert await pick_region_async(timeout=0.01) == REGIONS[0]
    assert seen == [0.01, 0.01]


@pytest.mark.anyio
async def test_async_pick_region_rejects_an_empty_candidate_list() -> None:
    with pytest.raises(ValueError, match="at least one"):
        await pick_region_async([])
