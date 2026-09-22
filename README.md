# hippius-drive

Python SDK and CLI for Hippius Drive (HCFS), an end-to-end encrypted file store.
Files are encrypted and signed on your machine; the server only ever holds
ciphertext and cannot read your data.

Pure Python — no Rust toolchain, no compiled extension, and the crypto is
readable in this repository rather than shipped as a binary.

```bash
pip install hippius-drive
```

Python 3.10 to 3.13.

## Quickstart

You need two things from the [Hippius console](https://console.hippius.com): an
API token and the account address it belongs to. You also need a recovery
phrase, which the SDK can generate for you and which never leaves your machine.

```python
from pathlib import Path
from hippius_drive import Client, Identity

identity = Identity.from_master(master_phrase, "default", account_ss58=account)

with Client(token=token, identity=identity) as client:
    client.folders.register()
    client.files.put(Path("report.pdf"), "work/report.pdf")
    client.files.get(client.files.file_id("work/report.pdf"), Path("out.pdf"))
```

`AsyncClient` mirrors the same surface with `async`/`await`. Shared operations
put the same bytes on the wire; the clients still differ in region selection
(`Client` probes, `AsyncClient` defaults to EU unless you pass `server_url`)
and in how a float timeout applies to request-body writes.

See [docs/quickstart.md](docs/quickstart.md) for the full walkthrough, and
[docs/cli.md](docs/cli.md) for the `hippius-drive` command line.

**Agents:** read [AGENTS.md](AGENTS.md). It is the instruction set for using
this SDK and for changing this repository. Point an agent at that file.

## Where the account address comes from

`account_ss58` is the Hippius account your **token** belongs to. It is *not*
derived from your recovery phrase — the server resolves the token to an address
and refuses any request naming a different one. The phrase supplies encryption
and signing keys only.

Getting this wrong produces a `403 forbidden` on the first request, so it is
worth stating plainly: **token and address come from the console together; the
phrase is separate.**

## What is in v1

Identity and folders, file upload (single-shot and resumable chunked sessions),
streaming download, listing, directory browse, cross-folder search, account
summaries, quota pre-flight, rename, and delete. File shares and folder shares
mint a console link whose fragment is the decryption key. Shared drives let a
second account join a folder with its own token; the member receives that
folder's file key, and the owner's recovery phrase stays with the owner.

Listing endpoints are paged by the server: `browse` and `search` return at most
200 entries per request (50 and 25 when no `limit` is given), so use
`files.iter_browse()` / `files.iter_state()` to walk everything, and page on
`has_more`, never on `total_count`. A search term shorter than 3 characters
returns no hits by server policy: an empty page, not an error.

**Not in v1:** the sync engine, recovery bindings, mnemonic-blob server
endpoints, admin endpoints, and S3-gateway variants. The `crypto/` module does
implement both mnemonic-at-rest formats (the desktop `enc_mnemonic.json` and
the console's Argon2id sealed blob), since the CLI needs the first and
interoperability needs the second.

## Security

The server stores ciphertext and never receives your recovery phrase or
encryption key. What that does and does not protect is written out in
[docs/security.md](docs/security.md), including the metadata the server does
see — file sizes, timestamps, and (when you send them) plaintext paths.

**Your recovery phrase is the only thing that can decrypt your files.** Nobody
can recover it for you, and changing it orphans everything already stored under
it.

## How this stays correct

hcfs is the oracle. Wire bytes, crypto, path rules, and error mapping come from
the Rust client. Known-answer vectors (`tests/vectors/hcfs-vectors-v1.json`)
are replayed when that file is committed; until the hcfs exporter lands, the
interim oracle is the hex and strings pinned in the unit tests (see
`tests/vectors/README.md`).

This repository's live suite (`pytest -m e2e`) runs in CI when
`HIPPIUS_TEST_*` secrets are present. It covers registration, upload
(single-shot and chunked session), download, listing, browse, search,
optimistic-concurrency conflicts, rename, delete, and a file-share round trip
when that route is mounted. A shared-drive round trip runs only when
`HIPPIUS_TEST_TOKEN_2` and `HIPPIUS_TEST_ACCOUNT_SS58_2` are set.

## Development

```bash
uv sync --all-groups
uv run pytest          # unit, property and respx tests; enforces a coverage floor
uv run ruff check .
uv run ty check
```

`uv run pytest -m e2e` runs the live suite, which skips unless
`HIPPIUS_TEST_TOKEN`, `HIPPIUS_TEST_ACCOUNT_SS58` and `HIPPIUS_TEST_MNEMONIC`
are set. Use a throwaway account: those tests create and delete real files, and
the phrase is real key material.

## Licence

MIT.
