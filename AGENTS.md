# AGENTS.md

Instruction set for agents using or changing this repository. Point an agent
at this file when the task is "talk to Hippius Drive" or "change the Python
SDK". Humans: the same facts live in [README.md](README.md),
[docs/quickstart.md](docs/quickstart.md), [docs/cli.md](docs/cli.md), and
[docs/security.md](docs/security.md); this file is the operational subset.

PyPI name: `hippius-drive`. Import: `hippius_drive`. Python 3.10–3.13.

---

## Using the SDK

### Credentials (the usual 403)

You need **three** things, and they are not interchangeable:

| Thing | Where it comes from | What it does |
|---|---|---|
| API token | [Hippius console](https://console.hippius.com) | Bearer auth |
| Account SS58 | The same console account the token belongs to | Server namespace |
| Recovery phrase | Generated locally; never sent anywhere | Encryption and signing keys |

The server resolves the token to an address and refuses any request naming a
different one. **The phrase does not produce the account address.** A 403 on
the first call almost always means token and `account_ss58` were paired from
different accounts.

`Client(token=..., identity=...)` does **not** read `HIPPIUS_TOKEN` or friends.
Those environment variables are CLI-only. Pass credentials in code, or use the
`hippius-drive` command.

### Minimal library use

```python
from pathlib import Path
from hippius_drive import Client, Identity
from hippius_drive.crypto import kdf, mnemonic_store

phrase = kdf.generate_master_mnemonic()  # 24 words; show once, store offline
mnemonic_store.save(Path("enc_mnemonic.json"), phrase, password)
# later: phrase = mnemonic_store.load(Path("enc_mnemonic.json"), password)

identity = Identity.from_master(phrase, "default", account_ss58=account)

with Client(token=token, identity=identity) as client:
    client.folders.register()  # upsert; a second device is also 200
    result = client.files.put(Path("report.pdf"), "work/report.pdf")
    file_id = client.files.file_id("work/report.pdf")
    client.files.get(file_id, Path("out.pdf"))
```

Public names are re-exported from the package root. Prefer
`from hippius_drive import Client, Identity, ...`. `__all__` is the contract;
a test fails if a name in it is missing. `hippius_drive.crypto` is an intended
subpackage (KDF, mnemonic store/blob, hashes, file cipher) even though it is
not in `__all__` — the CLI and the quickstart both import it.

### Task map

| Want | Call |
|---|---|
| Register this folder | `client.folders.register()` — server upserts; 200 even on a second device |
| List registered folders | `client.folders.list()` |
| Delete a folder and every file in it | `client.folders.unregister()` — irreversible |
| Upload a new file | `client.files.put(path, "dir/name.ext")` |
| Upload bytes | `client.files.put_bytes(data, "dir/name.ext")` |
| Replace an existing file | `put(..., base_revision_id=entry.revision_id, revision_seq=entry.revision_seq + 1)` |
| Download to disk | `client.files.get(file_id, dest)` |
| Download to memory | `client.files.get_bytes(file_id)` — not for large files |
| Path → id, no network | `client.files.file_id("dir/name.ext")` |
| Every file in this folder | `client.files.iter_state()` (pages on `has_more`) |
| One directory level | `client.files.browse("work")` |
| Search every folder on the account | `client.files.search(SearchFilters(q="report"))` |
| Rename without re-upload | `client.files.rename([RenameSpec(old, new, revision_id)])` |
| Delete one | `client.files.delete(file_id)` |
| Delete many (≤1000) | `client.files.delete_many(ids)` — inspect `errors` |
| Quota preflight | `client.can_upload(n)` — advisory; a refusal can still succeed on write |
| Account totals | `client.summary.user()` — can lag a just-finished upload by ~1s |
| Mint a file-share link | `client.shares.create(path_or_bytes, FileShareSpec(filename))` — URL fragment is a fresh key |
| Open a file share | `client.shares.open(share_url)` — anonymous; password links need `password=` |
| List / revoke file shares | `client.shares.list()` / `client.shares.revoke(token)` |
| Mint a folder-share link | `client.folder_shares.create(FolderShareSpec(prefix, name))` — fragment is the drive file key |
| Revoke a folder share | `client.folder_shares.revoke(token_or_hash)` — list returns `token_hash` only |
| Invite someone to this drive | `client.drives.create_invite(InviteSpec(folder_mnemonic, role="writer"))` |
| Join a drive | `client.drives.accept(url, member_master, member_ss58=account)` |
| List joined drives | `client.drives.memberships(member_master, member_ss58=account)` |
| Act as a member | `Identity.for_shared_drive(phrase, owner_ss58=..., folder_hash=..., role=...)` then `Client(token=member_token, identity=that)` |
| Leave a drive | `member_client.drives.leave(member_account)` — always sends `?owner=` the drive owner |

`put` picks the wire path by ciphertext size: a blob that fits one 8 MiB
transport chunk is a single request; anything larger is a resumable session.
Callers do not choose.

### Replacing a file

Writes are optimistic-concurrency. A new file omits `base_revision_id`. A
replacement **must** send both the revision you believe is current and
`revision_seq = current + 1`. The SDK will not guess: guessing either 400s or
clobbers a concurrent write.

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

A lost race raises `Conflict` with `current_revision_id` / `current_revision_seq`.
Re-read, re-classify, retry. That is expected during sync, not a defect.

### Paths and ids

- Relative POSIX only: `work/report.pdf`. No leading `/`, no `\`, no empty /
  `.` / `..` segments. Invalid input is `ValueError` before any request.
- The SDK NFC-normalises before hashing. `file_id` is `hex(BLAKE3(NFC path))`.
- The desktop client hashes raw OS bytes. A macOS-created file with an
  accented name can carry an NFD id this will not reproduce — find those
  through `files.state()` / `iter_state()`, not `file_id()`.
- `browse` and `search` only see rows that carry a plaintext `relative_path`.
  Older rows still appear in `state()`.

### Async

`AsyncClient` is the same surface with `async`/`await`. A parity test requires
the two clients to put the same bytes on the wire; pick one for concurrency,
not behaviour.

`Client` probes `/health` on each region in `REGIONS` order (EU, then US) and
uses the first that answers, falling back to EU if every probe fails. That is
preference order, not latency. `AsyncClient` cannot probe in the constructor
(no running loop): pass `server_url`, or
`server_url=await pick_region_async()` from `hippius_drive._transport` (it
returns a URL, not a transport). With no `server_url`, async defaults to EU.

### Errors

Catch `DriveError`. Service, transport, and decrypt failures are subclasses
carrying `code`, `message`, `status`, and `retryable`. Invalid caller input
is `ValueError`, raised locally.

| Exception | When |
|---|---|
| `Unauthorized` | 401 — token missing, malformed, or rejected |
| `Forbidden` | 403 — token resolves to a different account than the request names |
| `QuotaExceeded` | 402 — over plan/credits; may carry `balance_cents` / `required_cents` |
| `NotFound` | 404 — no such file, folder, share, or session. An empty 404 is still `NotFound` |
| `Gone` | 410 — invite revoked, expired, or exhausted |
| `Conflict` | 409 — stale `base_revision_id` |
| `PayloadTooLarge` | 413 — a multipart field exceeded its cap |
| `RateLimited` | 429 — back off; may carry `retry_after` |
| `ServerError` | 5xx — retryable |
| `TransportError` | no HTTP response (DNS/TLS/connect/timeout) |
| `DecryptError` | blob malformed or tag fails; not retryable |
| `InvalidRequest` | 400 |
| `InvalidResponse` | body is not something this SDK can parse |

The transport already retries connect failures, read timeouts, and 502/503/504
with capped backoff. It never retries a 4xx and never replays a body it has
already streamed. Batch delete and rename answer **200** even when individual
entries fail — inspect `errors` / `failures`.

### CLI

Installed as `hippius-drive`. Built only on the public `Client` (plus
`_config`); a test forbids new private imports. Anything the CLI can do is
reachable from the library.

Resolution order: flags, then environment, then
`~/.config/hippius-drive/config.toml`.

| Flag | Environment |
|---|---|
| `--token` | `HIPPIUS_TOKEN` |
| `--account` | `HIPPIUS_ACCOUNT_SS58` |
| `--server` | `HIPPIUS_SERVER_URL` |
| `--mnemonic-file` | `HIPPIUS_MNEMONIC_FILE` |
| `--label` | `HIPPIUS_FOLDER_LABEL` |
| — | `HIPPIUS_PASSWORD` (prompted on a TTY otherwise) |

```bash
hippius-drive init                          # prints the phrase once
hippius-drive whoami                        # first check on a 403
hippius-drive register
hippius-drive put report.pdf work/report.pdf
hippius-drive get work/report.pdf out.pdf   # path or 64-char file id
hippius-drive ls work
hippius-drive ls --all                      # includes rows with no plaintext path
hippius-drive mv work/a.pdf archive/a.pdf   # looks up the revision for you
hippius-drive rm work/a.pdf
hippius-drive share put report.pdf --name report.pdf
hippius-drive folder-share put --prefix work --name Work
hippius-drive invite put --role writer --days 7
hippius-drive invite accept URL
hippius-drive drives
hippius-drive drives leave OWNER_SS58 FOLDER_HASH
```

Replacing via CLI still needs `--base-revision` and `--revision-seq`. Share and
invite commands print the URL once; that URL is the key. Failures print one
line and exit 1 — no traceback. Full flag list: [docs/cli.md](docs/cli.md).

A member client's `account_ss58` is the drive **owner**. The bearer token is
the member's. Do not recompute `folder_hash` from a label the member chose;
use the hash from the invite or the membership row.

### Not in v1 — do not invent these

The sync engine, recovery bindings, mnemonic-blob **server** endpoints, admin
endpoints, and S3-gateway variants are out of scope. The `crypto/` module does
implement both local mnemonic-at-rest formats (`enc_mnemonic.json` and the
console Argon2id sealed blob), plus the share-link, owner-wrap, and grant
formats the console and desktop client already use.

### Security rules for agents

- Never log, commit, or echo a recovery phrase, folder mnemonic, unlock
  password, share URL, invite URL, or grant blob. `init --mnemonic` does not
  print the phrase; keep that property. `share put` and `invite put` print the
  URL because that is the key the recipient needs.
- The phrase is the only way to decrypt an owned folder. Losing it loses the
  data, including files members uploaded into a shared drive. It cannot be
  rotated without orphaning everything already stored.
- A folder-share `#k=` is the drive file key. A shared-drive invite gives the
  member that same file key. It does not give them the owner's master phrase.
- File **contents** are encrypted on the machine (XChaCha20-Poly1305 frames).
  Paths, names, sizes, and timestamps are visible to the server. Use opaque
  names for anything sensitive. Full model: [docs/security.md](docs/security.md).
- Do not "helpfully" derive `account_ss58` from the phrase. On a member client
  the wire address is the owner's, passed in explicitly.

---

## Working in this repository

### Commands

```bash
uv sync --all-groups
uv run pytest                 # unit/property/respx; coverage floor 98%; skips e2e
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv run pip-audit
uv run pytest -m e2e --no-cov # live; needs HIPPIUS_TEST_TOKEN,
                              # HIPPIUS_TEST_ACCOUNT_SS58, HIPPIUS_TEST_MNEMONIC
```

`addopts` already excludes `e2e` and enables coverage. A live run must pass
`--no-cov` or the floor fails because that job does not exercise the whole
package. Use a throwaway account: e2e creates and deletes real files, and the
phrase is real key material. Each run registers a unique `sdk-e2e-<uuid>`
folder and unregisters it afterwards.

CI (`.github/workflows/ci.yml`): ruff + format + ty + pytest on py3.10–3.13
across Ubuntu/macOS/Windows, `pip-audit`, `zizmor` on workflows, then e2e when
secrets are present. Fork PRs skip e2e. The required check is the `ci` job.

### Layout

| Path | Role |
|---|---|
| `hippius_drive/__init__.py` | Public re-exports (`__all__` is the API) |
| `client.py` | `Client` / `AsyncClient`: `folders`, `files`, `summary`, `shares`, `folder_shares`, `drives` |
| `identity.py` | Account + per-folder keys; member role; ToS / rename signing text |
| `models.py` | Pydantic wire types; byte fields as JSON int arrays |
| `errors.py` | `DriveError` tree, including `Gone` |
| `crypto/` | Hashes, KDF, framed cipher, mnemonic-at-rest, share links, owner wrap, grants |
| `_links.py` | Share and invite specs, URL finish, grant open. Re-exported specs are public |
| `_namespaces.py` | Sync and async namespace objects. Not subclasses of each other |
| `_ops.py` | One `Op` (request + parser) per endpoint |
| `_wire.py` | Sans-I/O requests and envelope parsing |
| `_transport.py` | httpx adapters, region probe, retry policy |
| `_upload.py` / `_session.py` | Encrypt + single-shot / chunked upload |
| `_config.py` | CLI settings: flags, then env, then config file |
| `cli.py` | Reference consumer of the public client |
| `tests/` | Mirrors the package; `tests/e2e/` is the live suite |
| `tests/vectors/` | Handshake with hcfs; file not present yet |

Modules named `_foo` are private. Callers (and the CLI, except `_config`) stay
on the public surface. The other documented private helper is
`pick_region_async` in `_transport`; pass its URL as `server_url=`, do not
inject it as `transport=`.

### Invariants — do not break these

1. **hcfs is the oracle.** Wire bytes, crypto, path rules, and error mapping
   come from the Rust client. Do not invent a friendlier format, reword the
   ToS/rename declaration strings, or change KDF / folder-hash derivation:
   any of those orphans stored data.
2. **Public API is `__all__`, plus `hippius_drive.crypto`.** New caller-facing
   types are re-exported from the package root and added to `__all__`. Prefer
   that import path in docs and examples. Do not hide `crypto/` — generating
   and unlocking a phrase has no other public entry point.
3. **One operation, two clients.** Logic lives in `_ops` / `_upload` /
   `_session`. `Client` and `AsyncClient` differ only in whether they await.
   `tests/test_client_parity.py` is the check.
4. **CLI tracks the library.** If a command needs a private helper, the
   public API is missing it (`tests/test_cli.py::test_the_cli_only_imports_the_public_surface`).
5. **Version lives in `hippius_drive/_version.py` only.** Hatch reads it;
   `User-Agent` is `hippius-drive/{version}`; `tests/test_package.py` checks
   the installed distribution matches. Do not also put a static version in
   `pyproject.toml`.
6. **Models are `extra="ignore"`.** The server adds fields without a version
   bump. Refusing unknown keys breaks on a deploy this repo did not make.
7. **Page on `has_more`, never on `total_count`.** The total is a maintained
   counter that can lag a write.
8. **Do not guess `revision_seq`.**
9. **Warnings are errors** (`filterwarnings = ["error"]` in pytest).

Known-answer vectors: `tests/vectors/hcfs-vectors-v1.json` is produced by
hcfs (`HCFS_WRITE_VECTORS=1 cargo test -p hcfs-client --test export_sdk_vectors`)
and copied here byte-identical. Until that file exists, `tests/test_vectors.py`
skips at module level. Schema and pinned interim values:
[tests/vectors/README.md](tests/vectors/README.md). If the exporter lands with
different field names, fix the replay in the same PR that commits the file.

### Style

- Formatter/linter: ruff (line length 100, Google docstrings). Types: ty,
  `error-on-warning`.
- Small functions, few positional args (ruff pylint cap is 5; CLI flags are
  exempt). No relative imports.
- Comments explain invariants and tradeoffs, not what the code already says.
- Behaviour changes need tests next to the change. Do not weaken the coverage
  floor to land a branch; add the test in the same commit.
- New dependencies: pin exact versions (`==`), then `uv run pip-audit`.
  GitHub Actions: pin to SHA with a version comment;
  `persist-credentials: false` on checkout.

### What not to do

- Do not add v1-excluded features (sync, recovery, admin, S3-gateway) unless
  the task explicitly is that work.
- Do not SS58-encode a key and call it `account_ss58`.
- Do not log phrases, tokens, or folder keys in tests beyond the already-public
  BIP-39 fixtures (`abandon`…`art` and friends).
- Do not treat a 200 from `delete_many` / `rename` as "every entry succeeded".
- Do not "fix" desktop NFD ids by hashing NFC and hoping — look the row up.
- Do not rewrite tests to match a behaviour change that is actually a bug.
