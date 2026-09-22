import hashlib

import httpx
import pytest
import respx

from hippius_drive import errors
from hippius_drive._transport import PROBE_TIMEOUT, AsyncTransport, Transport
from hippius_drive.client import AsyncClient, Client
from hippius_drive.identity import Identity
from hippius_drive.models import BrowseOptions, SearchFilters

BASE = "https://example.test"
MASTER = " ".join(["abandon"] * 23 + ["art"])
SS58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
FOLDER = "37a8eec1ce19687d"

FILE_JSON = {
    "path_hash": list(range(32)),
    "salted_hash": [7] * 32,
    "size_bytes": 1048576,
    "revision_seq": 1,
    "revision_id": [9] * 32,
    "encrypted_path": [],
    "file_name": "report.pdf",
    "relative_path": "Work/report.pdf",
    "arion_hash": "Qm...",
    "chunk_hashes": None,
    "uploaded_by": "5Fmember...",
    "created_at": 1713139200,
    "updated_at": 1713139200,
}


@pytest.fixture
def identity() -> Identity:
    return Identity.from_master(MASTER, "default", account_ss58=SS58)


@pytest.fixture
def client(identity: Identity) -> Client:
    return Client(token="tok", identity=identity, transport=Transport(BASE, "tok"))


def test_empty_token_is_rejected_before_region_probe(
    identity: Identity, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(**_kwargs: object) -> str:
        raise AssertionError("must not probe")

    monkeypatch.setattr("hippius_drive.client.pick_region", boom)
    with pytest.raises(ValueError, match="token"):
        Client(token="", identity=identity)
    with pytest.raises(ValueError, match="token"):
        Client(token="   ", identity=identity)


def test_client_rejects_a_non_positive_timeout(identity: Identity) -> None:
    with pytest.raises(ValueError, match="positive"):
        Client(token="tok", identity=identity, timeout=0)


def test_client_never_probes_a_region_when_given_a_server(identity: Identity) -> None:
    # A constructor that reached the network would make offline use impossible.
    with Client(token="tok", identity=identity, server_url=BASE) as c:
        assert c.server_url == BASE
        assert c.identity.folder_hash == FOLDER


@pytest.mark.parametrize(
    ("timeout", "probe"),
    [(2.0, 2.0), (120.0, PROBE_TIMEOUT), (httpx.Timeout(2.0), PROBE_TIMEOUT)],
)
def test_a_float_client_timeout_bounds_the_region_probe(
    identity: Identity,
    monkeypatch: pytest.MonkeyPatch,
    timeout: float | httpx.Timeout,
    probe: float,
) -> None:
    # A caller who asked for a 2s budget should not sit through a 5s probe per
    # region, but a generous budget must not stretch the probe past its default.
    seen: list[float] = []

    def fake_pick_region(*, timeout: float) -> str:
        seen.append(timeout)
        return BASE

    monkeypatch.setattr("hippius_drive.client.pick_region", fake_pick_region)
    with Client(token="tok", identity=identity, timeout=timeout) as c:
        assert c.server_url == BASE
    assert seen == [probe]


@respx.mock
def test_register_folder_sends_the_label_hash(client: Client) -> None:
    route = respx.post(f"{BASE}/register_folder").mock(
        return_value=httpx.Response(200, json={"Success": {"status": "registered"}})
    )
    assert client.folders.register(device_name="laptop").status == "registered"
    assert route.calls.last.request.url.path == "/register_folder"
    assert b'"folder_hash":"37a8eec1ce19687d"' in route.calls.last.request.content
    assert b'"device_name":"laptop"' in route.calls.last.request.content


@respx.mock
def test_register_folder_does_not_absorb_a_409(client: Client) -> None:
    # hcfs-server upserts register_folder and returns 200. hcfs-client treats
    # a 409 as an unexpected conflict, not "already registered".
    respx.post(f"{BASE}/register_folder").mock(
        return_value=httpx.Response(
            409, json={"Error": {"error": "conflict", "message": "already"}}
        )
    )
    with pytest.raises(errors.Conflict):
        client.folders.register()


@respx.mock
def test_register_folder_does_not_absorb_a_403(client: Client) -> None:
    respx.post(f"{BASE}/register_folder").mock(
        return_value=httpx.Response(403, json={"Error": {"error": "forbidden", "message": ""}})
    )
    with pytest.raises(errors.Forbidden):
        client.folders.register()


@respx.mock
def test_register_another_label_uses_that_labels_hash(client: Client) -> None:
    route = respx.post(f"{BASE}/register_folder").mock(
        return_value=httpx.Response(200, json={"Success": {"status": "registered"}})
    )
    client.folders.register("photos")
    expected = hashlib.sha256(b"photos").hexdigest()[:16]
    assert f'"folder_hash":"{expected}"'.encode() in route.calls.last.request.content


@respx.mock
def test_list_folders_parses_the_documented_body(client: Client) -> None:
    respx.get(f"{BASE}/list_folders/{SS58}").mock(
        return_value=httpx.Response(
            200,
            json={
                "Success": {
                    "base_address": SS58,
                    "folders": [
                        {
                            "label": "My Documents",
                            "folder_hash": "abc1234567890def",
                            "file_count": 142,
                            "total_bytes": 943718400,
                            "created_at": 1713139200,
                            "updated_at": 1713225600,
                            "device_name": "laptop-home",
                        }
                    ],
                }
            },
        )
    )
    result = client.folders.list()
    assert result.folders[0].label == "My Documents"
    assert result.folders[0].total_bytes == 943718400


@respx.mock
def test_unregister_folder(client: Client) -> None:
    route = respx.delete(f"{BASE}/unregister_folder").mock(
        return_value=httpx.Response(
            200, json={"Success": {"status": "unregistered", "files_deleted": 142}}
        )
    )
    assert client.folders.unregister().files_deleted == 142
    assert route.calls.last.request.method == "DELETE"


@respx.mock
def test_get_state_builds_the_query_string(client: Client) -> None:
    route = respx.get(f"{BASE}/get_state/{SS58}/{FOLDER}").mock(
        return_value=httpx.Response(
            200,
            json={
                "Success": {
                    "ss58_address": SS58,
                    "folder_hash": FOLDER,
                    "files": [FILE_JSON],
                    "total_count": 142,
                    "has_more": True,
                    "offset": 0,
                    "limit": 25,
                }
            },
        )
    )
    result = client.files.state(offset=0, limit=25)
    assert result.files[0].file_name == "report.pdf"
    assert dict(route.calls.last.request.url.params) == {"offset": "0", "limit": "25"}


@respx.mock
def test_iter_state_pages_until_has_more_is_false(client: Client) -> None:
    route = respx.get(f"{BASE}/get_state/{SS58}/{FOLDER}")
    route.side_effect = [
        httpx.Response(200, json={"Success": {"files": [FILE_JSON, FILE_JSON], "has_more": True}}),
        httpx.Response(200, json={"Success": {"files": [FILE_JSON], "has_more": False}}),
    ]
    assert len(list(client.files.iter_state(page_size=2))) == 3
    assert dict(route.calls[1].request.url.params)["offset"] == "2"


@respx.mock
def test_iter_state_stops_on_an_empty_page_even_if_has_more_lies(client: Client) -> None:
    route = respx.get(f"{BASE}/get_state/{SS58}/{FOLDER}")
    route.return_value = httpx.Response(200, json={"Success": {"files": [], "has_more": True}})
    assert list(client.files.iter_state()) == []
    assert route.call_count == 1


@respx.mock
def test_browse_root_and_subdirectory(client: Client) -> None:
    route = respx.get(f"{BASE}/browse/{SS58}/{FOLDER}").mock(
        return_value=httpx.Response(
            200,
            json={
                "Success": {
                    "ss58_address": SS58,
                    "folder_hash": FOLDER,
                    "path": "Documents/2026",
                    "folders": [{"name": "taxes", "file_count": 12, "total_bytes": 54321}],
                    "files": [FILE_JSON],
                    "total_count": 8,
                    "has_more": False,
                    "offset": 0,
                    "limit": 25,
                }
            },
        )
    )
    result = client.files.browse("Documents/2026", limit=100)
    assert result.folders[0].name == "taxes"
    params = dict(route.calls.last.request.url.params)
    assert params["path"] == "Documents/2026"
    assert params["limit"] == "100"


FOLDER_JSON = {"name": "taxes", "file_count": 12, "total_bytes": 54321}


def _browse_page(folders: int, files: int, has_more: bool) -> httpx.Response:
    body = {
        "folders": [FOLDER_JSON] * folders,
        "files": [FILE_JSON] * files,
        "has_more": has_more,
        # Deliberately too low: a walk that trusted it would stop after page one.
        "total_count": 1,
    }
    return httpx.Response(200, json={"Success": body})


@respx.mock
def test_iter_browse_advances_by_entries_returned_not_by_page_size(client: Client) -> None:
    # The server clamps a page below what was asked for. Folders and files
    # share one offset space, so both count towards the next offset.
    route = respx.get(f"{BASE}/browse/{SS58}/{FOLDER}")
    route.side_effect = [
        _browse_page(folders=2, files=1, has_more=True),
        _browse_page(folders=0, files=2, has_more=False),
    ]

    entries = list(client.files.iter_browse("Docs", page_size=1000))

    assert [type(entry).__name__ for entry in entries] == [
        "BrowseFolderEntry",
        "BrowseFolderEntry",
        "RemoteFileEntry",
        "RemoteFileEntry",
        "RemoteFileEntry",
    ]
    sent = [dict(call.request.url.params) for call in route.calls]
    assert [params["offset"] for params in sent] == ["0", "3"]
    assert {params["path"] for params in sent} == {"Docs"}


@respx.mock
def test_iter_browse_asks_for_the_server_maximum_by_default(client: Client) -> None:
    # Omitting the limit would fall back to the server default of 50 and cost
    # four times the round trips.
    route = respx.get(f"{BASE}/browse/{SS58}/{FOLDER}")
    route.return_value = _browse_page(folders=0, files=1, has_more=False)

    assert len(list(client.files.iter_browse())) == 1
    assert dict(route.calls.last.request.url.params)["limit"] == "200"


@respx.mock
def test_iter_browse_keeps_sort_options_on_every_page(client: Client) -> None:
    route = respx.get(f"{BASE}/browse/{SS58}/{FOLDER}")
    route.side_effect = [
        _browse_page(folders=0, files=1, has_more=True),
        _browse_page(folders=0, files=1, has_more=False),
    ]

    list(client.files.iter_browse(options=BrowseOptions(sort_by="size_bytes")))

    assert [dict(call.request.url.params)["sort_by"] for call in route.calls] == [
        "size_bytes",
        "size_bytes",
    ]


@respx.mock
def test_iter_browse_stops_on_an_empty_page_even_if_has_more_lies(client: Client) -> None:
    route = respx.get(f"{BASE}/browse/{SS58}/{FOLDER}")
    route.return_value = _browse_page(folders=0, files=0, has_more=True)

    assert list(client.files.iter_browse()) == []
    assert route.call_count == 1


@respx.mock
def test_browse_path_argument_wins_over_the_options_object(client: Client) -> None:
    route = respx.get(f"{BASE}/browse/{SS58}/{FOLDER}").mock(
        return_value=httpx.Response(200, json={"Success": {"folders": [], "files": []}})
    )
    client.files.browse("Docs", BrowseOptions(path="ignored", sort_by="size_bytes"))
    params = dict(route.calls.last.request.url.params)
    assert params["path"] == "Docs"
    assert params["sort_by"] == "size_bytes"


@respx.mock
def test_browse_rejects_a_traversing_path_before_any_request(client: Client) -> None:
    route = respx.get(f"{BASE}/browse/{SS58}/{FOLDER}")
    with pytest.raises(ValueError, match="relative_path"):
        client.files.browse("..")
    assert route.call_count == 0


@respx.mock
def test_browse_validates_options_path_when_positional_is_empty(client: Client) -> None:
    route = respx.get(f"{BASE}/browse/{SS58}/{FOLDER}")
    with pytest.raises(ValueError, match="relative_path"):
        client.files.browse(options=BrowseOptions(path=".."))
    assert route.call_count == 0


def test_client_does_not_read_hippius_token_from_the_environment(
    identity: Identity, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HIPPIUS_TOKEN", "from-env")
    with Client(token="tok", identity=identity, server_url=BASE) as client:
        assert client.transport._token == "tok"


@respx.mock
def test_search_sends_every_filter(client: Client) -> None:
    route = respx.get(f"{BASE}/search_files/{SS58}").mock(
        return_value=httpx.Response(
            200,
            json={
                "Success": {
                    "ss58_address": SS58,
                    "files": [{**FILE_JSON, "folder_hash": FOLDER, "folder_label": "Docs"}],
                    "total_count": 1,
                    "has_more": False,
                    "offset": 0,
                    "limit": 25,
                }
            },
        )
    )
    filters = SearchFilters(
        q="report", file_type=["image", ".pdf"], size_min=1, date_from=2, sort_by="size_bytes"
    )
    result = client.files.search(filters)
    assert result.files[0].folder_label == "Docs"
    params = dict(route.calls.last.request.url.params)
    assert params == {
        "q": "report",
        "file_type": "image,.pdf",
        "size_min": "1",
        "date_from": "2",
        "sort_by": "size_bytes",
        "offset": "0",
    }


@respx.mock
def test_summaries(client: Client) -> None:
    respx.get(f"{BASE}/get_user_summary/{SS58}").mock(
        return_value=httpx.Response(
            200,
            json={
                "Success": {
                    "ss58_address": SS58,
                    "total_bytes": 943718400,
                    "file_count": 142,
                    "created_at": 1713139200,
                    "updated_at": 1713225600,
                }
            },
        )
    )
    respx.get(f"{BASE}/get_file_type_summary/{SS58}").mock(
        return_value=httpx.Response(200, json={"Success": {"pdf": 3, "pdf_bytes": 99}})
    )
    respx.get(f"{BASE}/get_source_summary/{SS58}").mock(
        return_value=httpx.Response(200, json={"Success": {"desktop": 2, "other": 1}})
    )
    assert client.summary.user().file_count == 142
    assert client.summary.file_types().pdf_bytes == 99
    assert client.summary.sources().other == 1


@respx.mock
def test_can_upload_reads_the_flat_body(client: Client) -> None:
    route = respx.post(f"{BASE}/can_upload").mock(
        return_value=httpx.Response(200, json={"result": True, "error": None})
    )
    assert client.can_upload(1048576).result
    assert b'"size_bytes":1048576' in route.calls.last.request.content


@respx.mock
def test_can_upload_refusal_is_a_200_not_an_exception(client: Client) -> None:
    respx.post(f"{BASE}/can_upload").mock(
        return_value=httpx.Response(200, json={"result": False, "error": "drive_quota_exceeded"})
    )
    verdict = client.can_upload(1)
    assert not verdict.result
    assert verdict.error == "drive_quota_exceeded"


@respx.mock
def test_a_402_on_upload_raises_quota_exceeded(client: Client) -> None:
    respx.post(f"{BASE}/upload").mock(
        return_value=httpx.Response(
            402,
            json={
                "error": "insufficient_balance",
                "message": "m",
                "balance_cents": 1,
                "required_cents": 5,
            },
        )
    )
    with pytest.raises(errors.QuotaExceeded) as exc:
        client.files.put_bytes(b"x", "a.bin")
    assert exc.value.required_cents == 5


@respx.mock
def test_folder_entries(client: Client) -> None:
    # This endpoint answers with the payload directly, not the envelope.
    respx.get(f"{BASE}/list_folder_entries/{SS58}/{FOLDER}").mock(
        return_value=httpx.Response(200, json={"relative_paths": ["documents", "documents/2026"]})
    )
    assert client.folders.entries().relative_paths == ["documents", "documents/2026"]


@respx.mock
def test_the_bearer_token_is_sent_on_every_request(client: Client) -> None:
    route = respx.get(f"{BASE}/list_folders/{SS58}").mock(
        return_value=httpx.Response(200, json={"Success": {"folders": []}})
    )
    client.folders.list()
    assert route.calls.last.request.headers["Authorization"] == "Bearer tok"


@respx.mock
@pytest.mark.anyio
async def test_async_client_mirrors_the_sync_surface(identity: Identity) -> None:
    respx.get(f"{BASE}/list_folders/{SS58}").mock(
        return_value=httpx.Response(200, json={"Success": {"folders": []}})
    )
    respx.post(f"{BASE}/can_upload").mock(
        return_value=httpx.Response(200, json={"result": True, "error": None})
    )
    respx.get(f"{BASE}/get_state/{SS58}/{FOLDER}").mock(
        return_value=httpx.Response(
            200, json={"Success": {"files": [FILE_JSON], "has_more": False}}
        )
    )
    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as client:
        assert (await client.folders.list()).folders == []
        assert (await client.can_upload(1)).result
        assert [entry.file_name async for entry in client.files.iter_state()] == ["report.pdf"]


@respx.mock
@pytest.mark.anyio
async def test_async_iter_browse_stops_on_an_empty_page_even_if_has_more_lies(
    identity: Identity,
) -> None:
    route = respx.get(f"{BASE}/browse/{SS58}/{FOLDER}")
    route.return_value = _browse_page(folders=0, files=0, has_more=True)

    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as client:
        assert [entry async for entry in client.files.iter_browse()] == []
    assert route.call_count == 1


@respx.mock
@pytest.mark.anyio
async def test_async_register_does_not_absorb_a_409(identity: Identity) -> None:
    respx.post(f"{BASE}/register_folder").mock(
        return_value=httpx.Response(409, json={"Error": {"error": "conflict", "message": ""}})
    )
    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as client:
        with pytest.raises(errors.Conflict):
            await client.folders.register()


@respx.mock
def test_health_reports_the_version_and_capabilities(client: Client) -> None:
    respx.get(f"{BASE}/health").mock(
        return_value=httpx.Response(
            200,
            json={"status": "healthy", "version": "1.2.3", "capabilities": ["chunked_upload"]},
        )
    )
    result = client.health()
    assert result.status == "healthy"
    assert result.version == "1.2.3"
    assert result.capabilities == ["chunked_upload"]
