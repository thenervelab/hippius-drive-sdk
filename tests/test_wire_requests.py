from hippius_drive._wire import Request, build
from hippius_drive.models import BrowseOptions, SearchFilters


def params(request: Request) -> dict:
    assert request.params is not None
    return request.params


def body(request: Request) -> dict:
    assert request.json is not None
    return request.json


def test_health_is_unauthenticated_get() -> None:
    assert build.health() == Request("GET", "/health")


def test_get_state_request() -> None:
    r = build.get_state("5G", "abc", offset=50, limit=100)
    assert r == Request("GET", "/get_state/5G/abc", params={"offset": 50, "limit": 100})


def test_query_params_drop_none() -> None:
    r = build.get_state("5G", "abc", offset=0, limit=None)
    assert r.params == {"offset": 0}


def test_browse_defaults_to_the_folder_root() -> None:
    r = build.browse("5G", "abc")
    assert r.path == "/browse/5G/abc"
    assert r.params == {"path": "", "offset": 0}


def test_browse_passes_sort_and_filters() -> None:
    options = BrowseOptions(path="Docs", sort_by="size_bytes", sort_order="asc")
    r = build.browse("5G", "abc", options, limit=10)
    assert r.params == {
        "path": "Docs",
        "offset": 0,
        "limit": 10,
        "sort_by": "size_bytes",
        "sort_order": "asc",
    }


def test_browse_joins_file_types_with_commas() -> None:
    r = build.browse("5G", "abc", BrowseOptions(file_type=["image", ".pdf"]))
    assert params(r)["file_type"] == "image,.pdf"


def test_search_joins_file_types_with_commas() -> None:
    filters = SearchFilters(q="report", file_type=["image", ".pdf"], size_min=1)
    r = build.search_files("5G", filters)
    assert r.path == "/search_files/5G"
    assert params(r)["file_type"] == "image,.pdf"
    assert params(r)["q"] == "report"
    assert params(r)["size_min"] == 1


def test_search_accepts_a_plain_string_file_type() -> None:
    r = build.search_files("5G", SearchFilters(file_type="image"))
    assert params(r)["file_type"] == "image"


def test_search_with_no_filters_only_pages() -> None:
    assert build.search_files("5G").params == {"offset": 0}


def test_can_upload_body() -> None:
    r = build.can_upload("5G", "abc", 1048576)
    assert r == Request(
        "POST",
        "/can_upload",
        json={"ss58_address": "5G", "folder_hash": "abc", "size_bytes": 1048576},
    )


def test_register_folder_body() -> None:
    r = build.register_folder("5G", "abc", "My Docs", device_name="laptop")
    assert r.method == "POST"
    assert r.path == "/register_folder"
    assert r.json == {
        "ss58_address": "5G",
        "folder_hash": "abc",
        "label": "My Docs",
        "device_name": "laptop",
    }


def test_register_folder_sends_null_device_name() -> None:
    assert body(build.register_folder("5G", "abc", "My Docs"))["device_name"] is None


def test_list_and_unregister_folders() -> None:
    assert build.list_folders("5G") == Request("GET", "/list_folders/5G")
    assert build.unregister_folder("5G", "abc") == Request(
        "DELETE", "/unregister_folder", json={"ss58_address": "5G", "folder_hash": "abc"}
    )


def test_summaries() -> None:
    assert build.get_user_summary("5G").path == "/get_user_summary/5G"
    assert build.get_file_type_summary("5G").path == "/get_file_type_summary/5G"
    assert build.get_source_summary("5G").path == "/get_source_summary/5G"


def test_upload_multipart_puts_manifest_first() -> None:
    r = build.upload(manifest_json=b"{}", ciphertext=b"\x00")
    assert r.method == "POST"
    assert r.path == "/upload"
    assert r.files is not None
    assert [name for name, *_ in r.files] == ["manifest", "ciphertext"]
    assert r.files[0][1][2] == "application/json"
    assert r.files[1][1][2] == "application/octet-stream"


def test_download_and_delete_paths() -> None:
    assert build.download("5G", "abc", "ff" * 32).path == f"/download/5G/abc/{'ff' * 32}"
    assert build.delete("5G", "abc", "ff" * 32) == Request("DELETE", f"/delete/5G/abc/{'ff' * 32}")


def test_delete_files_body() -> None:
    r = build.delete_files("5G", "abc", ["aa", "bb"], quiet=True)
    assert r.json == {
        "ss58_address": "5G",
        "folder_hash": "abc",
        "file_ids": ["aa", "bb"],
        "quiet": True,
    }


def test_rename_files_body_carries_signature_and_key() -> None:
    renames = [{"old_path_hash": [1]}]
    r = build.rename_files("5G", "abc", renames, signature=bytes(64), signing_key=bytes(32))
    assert body(r)["renames"] == renames
    assert body(r)["signature"] == [0] * 64
    assert body(r)["signing_key"] == [0] * 32


def test_session_endpoints() -> None:
    created = build.create_session({"a": 1}, chunk_count=3, chunk_size=8, ciphertext_size=20)
    assert created.json == {
        "manifest": {"a": 1},
        "chunk_count": 3,
        "chunk_size": 8,
        "ciphertext_size": 20,
    }
    chunk = build.upload_chunk("s1", 7, b"xy")
    assert chunk.method == "PUT"
    assert chunk.path == "/upload/session/s1/chunk/7"
    assert chunk.content == b"xy"
    assert chunk.headers == {"Content-Type": "application/octet-stream"}
    assert build.session_status("s1").path == "/upload/session/s1/status"
    assert build.delete_session("s1") == Request("DELETE", "/upload/session/s1")


def test_finalize_sends_an_explicit_empty_body() -> None:
    # The arion ingress 411s a POST with no Content-Length, so the body must
    # be present-and-empty rather than absent.
    r = build.finalize_session("s1")
    assert r.method == "POST"
    assert r.path == "/upload/session/s1/finalize"
    assert r.content == b""
    assert r.replayable is False


def test_path_segments_are_percent_encoded() -> None:
    # A label-derived hash is hex, but an account id is server-supplied and
    # must never be able to smuggle a path segment.
    assert build.get_state("a/b", "abc").path == "/get_state/a%2Fb/abc"
