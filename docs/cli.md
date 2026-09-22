# The `hippius-drive` command line

Installed with the package. It is built only on the public `Client`, so anything
it can do is reachable from the library — and if a command ever needs something
the library cannot express, that is a gap in the library. A test enforces it.

Output is plain text, one record per line, so it pipes into `awk` and friends.
Read commands take `--json` when you want structure.

## Configuration

Resolved in this order, first match winning:

1. Command-line flags
2. Environment variables
3. `~/.config/hippius-drive/config.toml`

| Flag | Environment | Config key | Meaning |
|---|---|---|---|
| `--token` | `HIPPIUS_TOKEN` | `token` | API token from the console |
| `--account` | `HIPPIUS_ACCOUNT_SS58` | `account_ss58` | The account that token belongs to |
| `--server` | `HIPPIUS_SERVER_URL` | `server_url` | A specific server; otherwise the first healthy region in REGIONS order (EU, then US) |
| `--mnemonic-file` | `HIPPIUS_MNEMONIC_FILE` | `mnemonic_file` | Encrypted phrase; defaults to `~/.config/hippius-drive/enc_mnemonic.json` |
| `--label` | `HIPPIUS_FOLDER_LABEL` | `label` | Folder to act on; defaults to `default` |
| — | `HIPPIUS_PASSWORD` | `password` | Unlock password; prompted when unset and on a terminal |

An unset flag does not shadow the environment, so `--label` alone is fine
alongside `HIPPIUS_TOKEN`.

```toml
# ~/.config/hippius-drive/config.toml
token = "..."
account_ss58 = "5Grw..."
label = "default"
```

Without a password in the environment, commands prompt. In CI, where there is no
terminal, the error names `HIPPIUS_PASSWORD` rather than hanging on stdin.

## Getting started

```bash
hippius-drive init
```

Generates a 24-word phrase, writes it encrypted, and **prints it once**. That is
the only time it is shown. Store it offline.

`--mnemonic "word word ..."` imports an existing phrase instead — and does not
echo it. `--force` overwrites an existing file; without it, `init` refuses
rather than destroying the only copy of a phrase.

```bash
hippius-drive whoami
```

Shows the account, folder label, folder hash and public signing key the current
configuration resolves to, then lists folders with the configured token so a
token/account mismatch surfaces here as a 403.

## Folders

```bash
hippius-drive folders                       # label, file count, hash
hippius-drive folders --json
hippius-drive register                      # register the configured label
hippius-drive register --device-name laptop
```

`register` is an upsert on the server: a second device registering the same
label is 200, not a conflict.

## Files

```bash
hippius-drive ls                            # one directory level
hippius-drive ls work                       # a subdirectory
hippius-drive ls --all                      # every file in the folder
hippius-drive ls --json

hippius-drive put report.pdf work/report.pdf
hippius-drive get work/report.pdf out.pdf   # accepts a path or a 64-char file id
hippius-drive rm work/report.pdf            # several arguments batch into one call
hippius-drive mv work/report.pdf archive/report.pdf
```

`put` prints the `file_id` and the new `revision_id`. Replacing a file needs
both the revision you are replacing and its successor sequence:

```bash
hippius-drive put report-v2.pdf work/report.pdf \
  --base-revision <hex> --revision-seq 2
```

`mv` looks the current revision up for you, so it needs no flags.

`ls` shows directories first with recursive byte totals, then files. Note that
files with no stored plaintext path do not appear in `ls` — use `ls --all`,
which lists everything.

## Search and quota

```bash
hippius-drive search report
hippius-drive search --type image,.pdf --sort size_bytes --limit 50
hippius-drive search invoice --json

hippius-drive quota
hippius-drive quota --size 10485760         # would this many bytes fit?
```

Search spans every folder on the account, not just the configured one, and each
hit names the folder it came from.

## Shares

```bash
hippius-drive share put report.pdf --name report.pdf
hippius-drive share put report.pdf --name report.pdf --ttl 7d --password 'at-least-8'
hippius-drive share ls
hippius-drive share ls --json
hippius-drive share rm TOKEN

hippius-drive folder-share put --prefix work --name Work
hippius-drive folder-share put --name "Whole drive"          # empty prefix
hippius-drive folder-share ls
hippius-drive folder-share rm TOKEN                          # token or 64-hex token_hash
```

`share put` and `folder-share put` print one console URL. That URL is the
decryption key. `--console` changes the origin; it defaults to
`https://console.hippius.com` and is separate from `--server`. A `--password`
of at least 8 characters produces a `#p=` link.

File-share `ls` prints the plaintext token. Folder-share `ls` prints
`token_hash`, because the listing does not contain the token.

## Shared drives

```bash
hippius-drive invite put                         # writer, server-default lifetime
hippius-drive invite put --role reader --days 7
hippius-drive invite accept 'https://console.hippius.com/invite/TOKEN#k=...'

hippius-drive drives
hippius-drive drives --json
hippius-drive drives leave OWNER_SS58 FOLDER_HASH
```

`invite put` prints the invite URL and performs the seal-back itself. It does
not print the folder phrase. `invite accept` uses this configuration's mnemonic
file and `--account`, and prints the owner, folder hash, and role.

`drives` lists memberships opened from this account's grants: owner, folder
hash, role, and label. `drives leave` looks that row up and leaves as the
configured account. Changing a member's role, and uploading owner-wraps, are
library calls.

## Errors

Failures print one line and exit 1 — no traceback. That includes a batch `rm`
where some ids failed (HTTP 200 with per-id `errors`). A rejected input (a path
containing `..`, a batch over the 1000-id cap, a replacement missing its
`revision_seq`) is reported the same way, because from the command line those
are user errors rather than defects.
