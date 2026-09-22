"""The two clients must put the same bytes on the wire.

`Client` and `AsyncClient` exist so callers can pick a concurrency model, not
so they can get different behaviour. The design says they "differ only in
whether they await"; these tests are what makes that a checked claim rather
than a comment, and they are why the async half does not need every sync test
duplicated against it.

A divergence here is the class of bug that is otherwise invisible: the async
path once read an error body with the sync `read()`, which turned every async
404 into an unrelated RuntimeError.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

import blake3
import httpx
import pytest
import respx
from nacl.signing import VerifyKey

from hippius_drive import FileShareSpec, InviteSpec, errors
from hippius_drive._transport import AsyncTransport, Transport
from hippius_drive._upload import TRANSPORT_CHUNK
from hippius_drive.client import AsyncClient, Client
from hippius_drive.crypto import file_cipher, kdf
from hippius_drive.identity import Identity, tos_text
from hippius_drive.models import BrowseOptions, RenameSpec, SearchFilters
from tests.helpers import manifest_from, multipart_parts

BASE = "https://example.test"
MASTER = " ".join(["abandon"] * 23 + ["art"])
SS58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
FOLDER = "37a8eec1ce19687d"

FILE_JSON = {
    "path_hash": list(range(32)),
    "salted_hash": [7] * 32,
    "size_bytes": 1024,
    "revision_seq": 1,
    "revision_id": [9] * 32,
    "encrypted_path": [],
    "file_name": "a.bin",
    "relative_path": "a.bin",
}

# One body that satisfies every model under test: enveloped endpoints read
# "Success", and /can_upload reads the same dict flat, so it needs "result".
OK = {
    "Success": {
        "files": [],
        "folders": [],
        "status": "ok",
        "relative_paths": [],
        "result": True,
    }
}


@pytest.fixture
def identity() -> Identity:
    return Identity.from_master(MASTER, "default", account_ss58=SS58)


def seen(route: respx.Route) -> dict[str, Any]:
    """The parts of a request that must match, as comparable values."""
    request = route.calls.last.request
    return {
        "method": request.method,
        "path": request.url.path,
        "params": dict(request.url.params),
        "body": request.content.decode() if request.content else "",
        "auth": request.headers.get("Authorization"),
    }


# Each case names the operation once for both clients. Anything with a random
# nonce in its body is covered separately, below.
PARITY_CASES: list[tuple[str, Callable[[Client], Any], Callable[[AsyncClient], Awaitable[Any]]]] = [
    ("list_folders", lambda c: c.folders.list(), lambda c: c.folders.list()),
    (
        "register_folder",
        lambda c: c.folders.register("photos", "laptop"),
        lambda c: c.folders.register("photos", "laptop"),
    ),
    ("unregister_folder", lambda c: c.folders.unregister(), lambda c: c.folders.unregister()),
    ("folder_entries", lambda c: c.folders.entries(), lambda c: c.folders.entries()),
    ("get_state", lambda c: c.files.state(offset=5, limit=7), lambda c: c.files.state(5, 7)),
    (
        "browse",
        lambda c: c.files.browse("Docs", BrowseOptions(sort_by="size_bytes")),
        lambda c: c.files.browse("Docs", BrowseOptions(sort_by="size_bytes")),
    ),
    (
        "search",
        lambda c: c.files.search(SearchFilters(q="x", file_type=["image", ".pdf"]), limit=3),
        lambda c: c.files.search(SearchFilters(q="x", file_type=["image", ".pdf"]), limit=3),
    ),
    ("user_summary", lambda c: c.summary.user(), lambda c: c.summary.user()),
    ("file_type_summary", lambda c: c.summary.file_types(), lambda c: c.summary.file_types()),
    ("source_summary", lambda c: c.summary.sources(), lambda c: c.summary.sources()),
    ("can_upload", lambda c: c.can_upload(4096), lambda c: c.can_upload(4096)),
    ("health", lambda c: c.health(), lambda c: c.health()),
    (
        "delete",
        lambda c: c.files.delete("ff" * 32),
        lambda c: c.files.delete("ff" * 32),
    ),
    (
        "delete_many",
        lambda c: c.files.delete_many(["aa", "bb"], quiet=True),
        lambda c: c.files.delete_many(["aa", "bb"], quiet=True),
    ),
]


@respx.mock
@pytest.mark.anyio
@pytest.mark.parametrize(
    ("name", "run_sync", "run_async"), PARITY_CASES, ids=[c[0] for c in PARITY_CASES]
)
async def test_sync_and_async_send_the_same_request(
    name: str,
    run_sync: Callable[[Client], Any],
    run_async: Callable[[AsyncClient], Awaitable[Any]],
    identity: Identity,
) -> None:
    route = respx.route(host="example.test").mock(return_value=httpx.Response(200, json=OK))

    with Client(token="tok", identity=identity, transport=Transport(BASE, "tok")) as client:
        run_sync(client)
    sync_request = seen(route)

    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as aclient:
        await run_async(aclient)
    async_request = seen(route)

    assert async_request == sync_request, f"{name} diverges between the clients"
    assert sync_request["auth"] == "Bearer tok"


@respx.mock
@pytest.mark.anyio
async def test_file_id_agrees_across_clients(identity: Identity) -> None:
    with Client(token="tok", identity=identity, transport=Transport(BASE, "tok")) as client:
        sync_id = client.files.file_id("docs/Résumé.pdf")
    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as aclient:
        assert aclient.files.file_id("docs/Résumé.pdf") == sync_id


@respx.mock
@pytest.mark.anyio
async def test_upload_manifests_agree_except_for_the_random_nonce(identity: Identity) -> None:
    # encrypted_path and ciphertext_hash both ride a fresh nonce per upload, so
    # they cannot match; everything the server authenticates must.
    uploaded = httpx.Response(
        200, json={"Success": {"upload_id": "u", "timestamp": 1, "revision_id": [1] * 32}}
    )
    route = respx.post(f"{BASE}/upload").mock(return_value=uploaded)

    with Client(token="tok", identity=identity, transport=Transport(BASE, "tok")) as client:
        client.files.put_bytes(b"payload", "docs/a.bin")
    sync_manifest = manifest_from(route.calls.last.request)

    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as aclient:
        await aclient.files.put_bytes(b"payload", "docs/a.bin")
    async_manifest = manifest_from(route.calls.last.request)

    stable = (
        "ss58_address",
        "folder_hash",
        "size_bytes",
        "path_hash",
        "salted_hash",
        "revision_seq",
        "base_revision_id",
        "signing_key",
        "relative_path",
        "file_name",
        "source",
    )
    assert {k: async_manifest[k] for k in stable} == {k: sync_manifest[k] for k in stable}
    for manifest in (sync_manifest, async_manifest):
        VerifyKey(bytes(manifest["signing_key"])).verify(
            tos_text(manifest["ciphertext_hash"]).encode(), bytes(manifest["signature"])
        )


@respx.mock
@pytest.mark.anyio
async def test_rename_signature_agrees_across_clients(identity: Identity) -> None:
    # The signature covers only the sorted hash pairs, so it is deterministic
    # even though new_encrypted_path carries a fresh nonce.
    renamed = httpx.Response(
        200, json={"Success": {"renamed_count": 1, "successes": [], "failures": []}}
    )
    route = respx.post(f"{BASE}/rename_files").mock(return_value=renamed)
    specs = [
        RenameSpec("z.bin", "z2.bin", bytes([9] * 32)),
        RenameSpec("a.bin", "a2.bin", bytes([8] * 32)),
    ]

    with Client(token="tok", identity=identity, transport=Transport(BASE, "tok")) as client:
        client.files.rename(specs)
    sync_body = json.loads(route.calls.last.request.content)

    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as aclient:
        await aclient.files.rename(specs)
    async_body = json.loads(route.calls.last.request.content)

    assert async_body["signature"] == sync_body["signature"]
    assert async_body["signing_key"] == sync_body["signing_key"]
    keys = ("old_path_hash", "new_path_hash", "new_relative_path", "base_revision_id")
    assert [{k: r[k] for k in keys} for r in async_body["renames"]] == [
        {k: r[k] for k in keys} for r in sync_body["renames"]
    ]


@respx.mock
@pytest.mark.anyio
async def test_both_clients_page_iter_state_identically(identity: Identity) -> None:
    pages = [
        httpx.Response(200, json={"Success": {"files": [FILE_JSON, FILE_JSON], "has_more": True}}),
        httpx.Response(200, json={"Success": {"files": [FILE_JSON], "has_more": False}}),
    ]
    route = respx.get(f"{BASE}/get_state/{SS58}/{FOLDER}")

    route.side_effect = list(pages)
    with Client(token="tok", identity=identity, transport=Transport(BASE, "tok")) as client:
        sync_count = len(list(client.files.iter_state(page_size=2)))
    sync_offsets = [dict(call.request.url.params)["offset"] for call in route.calls]

    route.reset()
    route.side_effect = list(pages)
    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as aclient:
        async_count = len([entry async for entry in aclient.files.iter_state(page_size=2)])
    async_offsets = [dict(call.request.url.params)["offset"] for call in route.calls]

    assert async_count == sync_count == 3
    assert async_offsets == sync_offsets == ["0", "2"]


@respx.mock
@pytest.mark.anyio
async def test_both_clients_route_a_large_file_through_a_session(identity: Identity) -> None:
    respx.post(f"{BASE}/upload/session").mock(
        return_value=httpx.Response(200, json={"Success": {"session_id": "s1"}})
    )
    chunks = respx.put(url__regex=rf"{BASE}/upload/session/s1/chunk/\d+").mock(
        side_effect=lambda request: httpx.Response(
            200, json={"Success": {"chunk_index": int(request.url.path.rsplit("/", 1)[1])}}
        )
    )
    respx.get(f"{BASE}/upload/session/s1/status").mock(
        return_value=httpx.Response(
            200, json={"Success": {"total_chunks": 3, "chunks_received": [0, 1, 2]}}
        )
    )
    respx.post(f"{BASE}/upload/session/s1/finalize").mock(
        return_value=httpx.Response(
            200, json={"Success": {"upload_id": "u", "timestamp": 1, "revision_id": [4] * 32}}
        )
    )
    single = respx.post(f"{BASE}/upload")
    payload = b"q" * (TRANSPORT_CHUNK * 2 + 1024)

    with Client(token="tok", identity=identity, transport=Transport(BASE, "tok")) as client:
        client.files.put_bytes(payload, "big.bin")
    sync_chunks = chunks.call_count

    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as aclient:
        result = await aclient.files.put_bytes(payload, "big.bin")

    assert single.call_count == 0, "neither client may use the single-shot path here"
    assert chunks.call_count - sync_chunks == sync_chunks == 3
    assert result.revision_id == bytes([4] * 32)

    def assembled(offset: int) -> bytes:
        calls = chunks.calls[offset : offset + sync_chunks]
        by_index = sorted(calls, key=lambda c: int(c.request.url.path.rsplit("/", 1)[1]))
        return b"".join(call.request.content for call in by_index)

    assert file_cipher.decrypt_bytes(assembled(0), identity.encryption_key) == payload
    assert file_cipher.decrypt_bytes(assembled(sync_chunks), identity.encryption_key) == payload


@respx.mock
@pytest.mark.anyio
async def test_both_clients_raise_the_same_typed_error(identity: Identity) -> None:
    respx.route(host="example.test").mock(
        return_value=httpx.Response(
            403, json={"Error": {"error": "forbidden", "message": "wrong account"}}
        )
    )
    with (
        Client(token="tok", identity=identity, transport=Transport(BASE, "tok")) as client,
        pytest.raises(errors.Forbidden) as sync_exc,
    ):
        client.files.state()

    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as aclient:
        with pytest.raises(errors.Forbidden) as async_exc:
            await aclient.files.state()

    assert str(async_exc.value) == str(sync_exc.value)
    assert async_exc.value.code == sync_exc.value.code == "forbidden"


def _share_metadata(request: httpx.Request) -> dict[str, Any]:
    payload = multipart_parts(request)[0][2]
    parsed = json.loads(payload)
    assert isinstance(parsed, dict)
    return parsed


@respx.mock
@pytest.mark.anyio
async def test_file_share_metadata_agrees_across_clients(identity: Identity) -> None:
    route = respx.post(f"{BASE}/v1/shares").mock(
        return_value=httpx.Response(201, json={"share_token": "s", "expires_at": None})
    )
    spec = FileShareSpec("a.txt", mime_type="text/plain", ttl="7d")

    with Client(token="tok", identity=identity, transport=Transport(BASE, "tok")) as client:
        sync_created = client.shares.create(b"hello", spec)
    sync_meta = _share_metadata(route.calls[0].request)

    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as aclient:
        async_created = await aclient.shares.create(b"hello", spec)
    async_meta = _share_metadata(route.calls[1].request)

    for field in ("filename", "plaintext_size", "ciphertext_size", "mime_type", "ttl"):
        assert sync_meta[field] == async_meta[field], field
    assert sync_meta["plaintext_size"] == 5
    assert sync_meta["ttl"] == "7d"
    prefix = "https://console.hippius.com/share/s#k="
    assert sync_created.share_url.startswith(prefix)
    assert async_created.share_url.startswith(prefix)


@respx.mock
@pytest.mark.anyio
async def test_invite_mint_agrees_across_clients(identity: Identity) -> None:
    token = "inviteTok"
    invite_id = blake3.blake3(token.encode()).hexdigest()
    respx.post(f"{BASE}/v1/drive-invites").mock(
        return_value=httpx.Response(200, json={"invite_token": token, "invite_id": invite_id})
    )
    sealed = respx.put(url__regex=r".*/sealed-token$").mock(return_value=httpx.Response(204))
    spec = InviteSpec(kdf.derive_folder_mnemonic(MASTER, "default"), role="manager", max_uses=3)

    with Client(token="tok", identity=identity, transport=Transport(BASE, "tok")) as client:
        sync_created = client.drives.create_invite(spec)
    sync_post = respx.calls[0].request.content

    async with AsyncClient(
        token="tok", identity=identity, transport=AsyncTransport(BASE, "tok")
    ) as aclient:
        async_created = await aclient.drives.create_invite(spec)
    async_post = respx.calls[2].request.content

    assert sync_post == async_post
    assert json.loads(sync_post) == {"folder_hash": FOLDER, "role": "manager", "max_uses": 3}
    prefix = f"https://console.hippius.com/invite/{token}#k="
    assert sync_created.invite_url.startswith(prefix)
    assert async_created.invite_url == sync_created.invite_url
    assert sealed.call_count == 2
