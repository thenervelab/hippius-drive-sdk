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

listing = client.files.browse("work")  # one directory level
for folder in listing.folders:
    print(folder.name, folder.total_bytes)  # recursive totals

hits = client.files.search(SearchFilters(q="report", file_type=["pdf"]))
```

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

## Sharing a file

A file share is a fresh ciphertext under a new key. The console URL's fragment
is that key. Hand the URL to the recipient; opening it needs no account.

```python
from hippius_drive import FileShareSpec

created = client.shares.create(Path("report.pdf"), FileShareSpec("report.pdf"))
print(created.share_url)

opened = client.shares.open(created.share_url)
```

`FileShareSpec` takes a ttl (`24h`, `7d`, `30d`, `never`) and an optional
password of at least 8 characters. A password link uses `#p=` and the raw key
is not in the URL. `open` then needs that password.

The same client lists and revokes with `shares.list()` and `shares.revoke(token)`.
A file larger than one 8 MiB ciphertext uses the chunked share routes on its own.

## Sharing a folder

A folder share does not upload anything. The fragment is this drive's file key,
so anyone holding the link can decrypt the files the token's prefix allows the
server to serve.

```python
from hippius_drive import FolderShareSpec

created = client.folder_shares.create(FolderShareSpec("work", "Work"))
print(created.share_url)
```

An empty `path_prefix` shares the whole drive. The listing returns `token_hash`,
not the plaintext token. `revoke` and `update_ttl` accept either the token from
`create` or that 64-character hash.

## A shared drive

A shared drive is one folder on the owner's account. Members use their own API
token. `Identity.account_ss58` on a member client is the **owner's** address:
paths and `salted_hash` are salted with it. The member's token is the bearer.

```python
from hippius_drive import Identity, InviteSpec
from hippius_drive.crypto import kdf

folder_phrase = kdf.derive_folder_mnemonic(phrase, "default")
invite = client.drives.create_invite(InviteSpec(folder_phrase, role="writer"))
print(invite.invite_url)
```

The recipient joins with their own master phrase and the account their token
resolves to. That address is not derived from the phrase.

```python
accepted = member.drives.accept(invite.invite_url, member_phrase, member_ss58=member_account)
member_identity = Identity.for_shared_drive(
    accepted.folder_mnemonic,
    owner_ss58=accepted.owner_ss58,
    folder_hash=accepted.folder_hash,
    role=accepted.role,
)
```

`folder_hash` is the owner's id from the invite. It is not recomputed from a
label the member invented. A reader cannot upload. Registering and unregistering
the folder stay with the owner. The owner pays for bytes members write. Losing
the owner's phrase loses the drive, including files members uploaded.

`drives.memberships(member_phrase, member_ss58=member_account)` lists drives
this account has joined and opens each grant. `Client(..., identity=member_identity)`
then calls `files`, `folder_shares`, and `drives.leave(member_account)` the
same way an owner calls them.

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
| `NotFound` | 404 | No such file, folder, share, or session |
| `Gone` | 410 | Invite revoked, expired, or exhausted |
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
