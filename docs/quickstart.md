# Quickstart

## What you need

| | Where it comes from |
|---|---|
| API token | [Hippius console](https://console.hippius.com) |
| Account address (SS58) | The same console account — the one your token belongs to |
| Recovery phrase | Generated locally; never sent anywhere |

The token and address go together. The phrase is separate and is the only thing
that can decrypt your files.

## Generating a phrase

```python
from hippius_drive.crypto import kdf

phrase = kdf.generate_master_mnemonic()  # 24 words, from the OS entropy source
```

Store it offline. To keep it on disk encrypted, in the same format the desktop
client reads:

```python
from pathlib import Path
from hippius_drive.crypto import mnemonic_store

mnemonic_store.save(Path("enc_mnemonic.json"), phrase, "your-password")
phrase = mnemonic_store.load(Path("enc_mnemonic.json"), "your-password")
```

The file is written atomically with mode `0600`, keeping the previous version
as `.bak` — it is usually the only local copy of the phrase, so a torn write
would be unrecoverable.

## An identity

An `Identity` is one account plus one folder's keys:

```python
from hippius_drive import Identity

identity = Identity.from_master(phrase, "default", account_ss58=account)
```

`"default"` is the folder label. Its hash (`hex(SHA-256(label))[:16]`) is the
folder's server-side name, so the same label always addresses the same folder —
that is how two devices reach the same files without coordinating.

Different folders need different identities, because each label derives its own
keys.

## Uploading and downloading

```python
from pathlib import Path
from hippius_drive import Client

with Client(token=token, identity=identity) as client:
    client.folders.register()  # upsert; a second device is also 200

    result = client.files.put(Path("report.pdf"), "work/report.pdf")
    print(result.revision_id.hex())

    file_id = client.files.file_id("work/report.pdf")
    info = client.files.get(file_id, Path("downloaded.pdf"))
    print(info.size_bytes)
```

`put` routes by size on its own: a blob that fits one 8 MiB transport chunk goes
as a single request, anything larger through a resumable chunked session.

`file_id` is `hex(BLAKE3(NFC path))` and needs no round trip. One caveat: the
desktop client hashes raw OS bytes, so a macOS-created file with an accented
name can carry a decomposed (NFD) id this will not reproduce. Find those through
`files.state()` instead.

Downloads are written to a `.part` file and renamed into place only after the
last frame authenticates, so a failed transfer never leaves a half-decrypted
file where the real one should be.

## Updating a file

Writes use optimistic concurrency. To replace a file you must say which revision
you believe you are replacing:

```python
wanted = client.files.file_id("work/report.pdf")
entry = next(f for f in client.files.iter_state() if f.file_id == wanted)

client.files.put(
    Path("report-v2.pdf"),
    "work/report.pdf",
    base_revision_id=entry.revision_id,
    revision_seq=entry.revision_seq + 1,
)
```

If someone else wrote first, this raises `Conflict`, which carries the server's
current revision so you can re-read and retry. The SDK will not guess
`revision_seq` for you — guessing either fails validation or silently clobbers a
concurrent write.

## Listing

```python
from hippius_drive import SearchFilters

for entry in client.files.iter_state():  # pages until the server stops
    print(entry.relative_path, entry.size_bytes)

listing = client.files.browse("work")  # one page of one directory level
for folder in listing.folders:
    print(folder.name, folder.total_bytes)  # recursive totals

for entry in client.files.iter_browse("work"):  # the whole level, every page
    print(entry)

hits = client.files.search(SearchFilters(q="report", file_type=["pdf"]))
```

`browse` and `search` are paged by the server: at most 200 entries per request,
and 50 (`browse`) or 25 (`search`) when you pass no `limit`. A larger `limit`
is reduced to 200, not rejected, so continue from `offset + entries returned`
while `has_more` is true. `iter_browse` does that for you. A search `q` shorter
than 3 characters returns no hits by server policy: an empty page, not an error.

`browse` and `search` only see files that carry a plaintext `relative_path`.
Rows written before that field existed are visible in `state()` and in sync, but
not in those two.

## Moving and deleting

```python
from hippius_drive import RenameSpec

client.files.rename([RenameSpec("work/report.pdf", "archive/report.pdf", entry.revision_id)])

client.files.delete(file_id)
client.files.delete_many([id_a, id_b])  # up to 1000
```

Rename re-keys the record without moving ciphertext — cheaper than upload plus
delete, and atomic. Both batch calls answer `200` even when individual entries
fail, so inspect `failures` and `errors` rather than trusting the status.

## Quota

```python
verdict = client.can_upload(10 * 1024 * 1024)
if not verdict.result:
    print(verdict.error)
```

Advisory only. The write endpoints charge just the growth over the row a
manifest replaces, so a refusal here can still succeed on upload. An `error`
mentioning billing means a transient backend failure worth retrying, not a quota
verdict.

## Async

```python
from hippius_drive import AsyncClient

async with AsyncClient(
    token=token, identity=identity, server_url="https://eu-central-1-arion.hippius.com"
) as client:
    await client.folders.register()
    await client.files.put_bytes(b"hello", "greeting.txt")
    async for entry in client.files.iter_state():
        print(entry.relative_path)
```

One difference: `Client` probes `/health` on each region in `REGIONS` order
(EU, then US) and uses the first that answers, which `AsyncClient` cannot do
without a running event loop. Pass `server_url`, or
`server_url=await pick_region_async()` from `hippius_drive._transport` (it
returns a URL, not a transport).

## Errors

Every failure the service, the transport or the decrypt step reports is a
`DriveError` subclass carrying `code`, `message` and `status`:

| Exception | Status | Meaning |
|---|---|---|
| `Unauthorized` | 401 | Token missing, malformed or rejected |
| `Forbidden` | 403 | Token resolves to a different account than the request names |
| `QuotaExceeded` | 402 | Over the plan allowance; carries the credit figures when given |
| `NotFound` | 404 | No such file, folder or session |
| `Conflict` | 409 | Stale `base_revision_id`; carries the current revision |
| `PayloadTooLarge` | 413 | A multipart field exceeded its cap |
| `RateLimited` | 429 | Too many live sessions; carries `retry_after` |
| `ServerError` | 5xx | Retryable |
| `TransportError` | — | No response arrived at all |
| `DecryptError` | — | A downloaded blob is malformed or fails authentication; not retryable |

`Conflict` during sync is an expected event, not a fault. The transport already
retries connect failures, read timeouts and 502/503/504 with capped backoff; it
never retries a 4xx, and never replays a body it has already streamed.

Invalid input is a `ValueError`, raised before any request is made: a bad
relative path, an over-cap batch delete, a rename with no entries, or a source
file whose size changed while it was being read.
