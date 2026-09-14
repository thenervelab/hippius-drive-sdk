import hashlib

import httpx
import pytest
import respx

from hippius_drive import errors
from hippius_drive._transport import AsyncTransport, Transport
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


def test_client_never_probes_a_region_when_given_a_server(identity: Identity) -> None:
    # A constructor that reached the network would make offline use impossible.
    with Client(token="tok", identity=identity, server_url=BASE) as c:
        assert c.server_url == BASE
        assert c.identity.folder_hash == FOLDER


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
def test_register_folder_absorbs_a_409(client: Client) -> None:
    # Deterministic folder_hash means a second device's 409 says "it exists",
    # which is exactly the state the caller asked for.
    respx.post(f"{BASE}/register_folder").mock(
        return_value=httpx.Response(
            409, json={"Error": {"error": "conflict", "message": "already"}}
        )
    )
    assert client.folders.register().status == "already_registered"


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
def test_a_402_on_a_real_write_raises_quota_exceeded(client: Client) -> None:
    respx.get(f"{BASE}/get_state/{SS58}/{FOLDER}").mock(
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
        client.files.state()
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
async def test_async_register_absorbs_a_409(identity: Identity) -> None:
    respx.post(f"{BASE}/register_folder").mock(
        return_value=httpx.Response(409, json={"Error": {"error": "conflict", "message": ""}})
    )
    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as client:
        assert (await client.folders.register()).status == "already_registered"


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
