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

`AsyncClient` mirrors the same surface with `async`/`await`. Both are kept
byte-identical on the wire by a parity test, so picking one is purely a
concurrency decision.

See [docs/quickstart.md](docs/quickstart.md) for the full walkthrough, and
[docs/cli.md](docs/cli.md) for the `hippius-drive` command line.

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
summaries, quota pre-flight, rename, and delete.

**Not in v1:** the sync engine, file and folder shares, shared drives, recovery
bindings, mnemonic-blob server endpoints, admin endpoints, and S3-gateway
variants. The `crypto/` module does implement both mnemonic-at-rest formats
(the desktop `enc_mnemonic.json` and the console's Argon2id sealed blob), since
the CLI needs the first and interoperability needs the second.

## Security

The server stores ciphertext and never receives your recovery phrase or
encryption key. What that does and does not protect is written out in
[docs/security.md](docs/security.md), including the metadata the server does
see — file sizes, timestamps, and (when you send them) plaintext paths.

**Your recovery phrase is the only thing that can decrypt your files.** Nobody
can recover it for you, and changing it orphans everything already stored under
it.

## How this stays correct

hcfs is the oracle. Every wire and crypto fact here was read from the Rust
client's source, and the SDK's live suite runs inside hcfs's own CI against a
real server on every change to it — so a server or client change that would
break Python users fails in the pull request that makes it.

That covers registration, upload (both the single-shot and chunked-session
paths), download, listing, browse, search, optimistic-concurrency conflicts,
rename, and delete.

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
