import httpx
import pytest
import respx

from hippius_drive import errors
from hippius_drive._transport import (
    REGIONS,
    AsyncTransport,
    Transport,
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


def test_prepare_adds_the_bearer_token() -> None:
    kwargs = prepare(build.list_folders("5G"), "tok")
    assert kwargs["headers"]["Authorization"] == "Bearer tok"
    assert kwargs["method"] == "GET"
    assert kwargs["url"] == "/list_folders/5G"


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
