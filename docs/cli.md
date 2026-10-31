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

`--phrase-file PATH` imports an existing phrase from an owner-only file (`-`
reads stdin) and does not echo it. `--mnemonic "word word ..."` does the same
from the command line, where the phrase lands in shell history and `ps`; prefer
the file. `--force` overwrites an existing file; without it, `init` refuses
rather than destroying the only copy of a phrase.

For an account that signs in with a 12-word access key, import the access key
itself: the console uses it as that account's Drive phrase too.

## Signing in without a browser

```bash
pip install "hippius-drive[login] @ git+https://github.com/thenervelab/hippius-drive-sdk"
hippius-drive auth login --phrase-file ~/.secrets/access-key   # or: --phrase-file - < file
hippius-drive auth login                                       # unlock the encrypted mnemonic file
hippius-drive auth login --phrase-file - --token-file ~/.secrets/hippius-token
```

`auth login` signs the API's challenge with the two keys an access key stands
for (sr25519 and secp256k1, exactly as the console's access-key sign-in does)
and saves the account's API token and address to the config file, written
owner-only (0600). With `--token-file` the token goes to that file instead,
also 0600. Neither the phrase nor the token is ever printed. A phrase file that
other users can read is refused.

The first sign-in with a new access key creates the account. That account has
no Drive plan of its own; it can still join a shared drive, whose owner pays.
The token does not expire, but it is the account's only token: signing out in
the console deletes it. On a 401, run `auth login` again. `--api` (or
`HIPPIUS_API_URL`) points it at another API origin.

The signing libraries are native wheels, so they ship as the `login` extra
rather than with every install.

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
hippius-drive ls                            # one directory level, every entry
hippius-drive ls work                       # a subdirectory
hippius-drive ls work --limit 50            # one page only
hippius-drive ls work --limit 50 --offset 50
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

`put` never replaces an existing file silently. Onto an existing path it fails
with exit code 3 and says to pass `--overwrite`. `--overwrite` reads the file's
current revision and quotes it, so the upload is a compare-and-swap: if another
writer (another agent, say) changed the file in between, the upload fails with
exit code 3 instead of clobbering their version, and you can rerun. A file
that was moved or deleted after the read also exits 3, with a message saying
so: rerunning would recreate it, so look first. A file the desktop app stored
under an NFD name has another id and is refused rather than duplicated. There
is no version history on the server, so the replaced revision is gone.

```bash
hippius-drive put report.pdf work/report.pdf --overwrite
hippius-drive mkdir work/drafts work/archive    # empty directories; existing ones are fine
```

`mkdir` is only needed for a directory that should show while empty: an upload
into a path whose directory does not exist yet creates it implicitly.

`mv` looks the current revision up for you, so it needs no flags.

## Directories

```bash
hippius-drive put -r ./reports work/reports         # upload a tree; refuses existing files
hippius-drive put -r ./reports work/reports --overwrite
hippius-drive sync ./reports work/reports           # upload only new and changed files
hippius-drive sync ./reports work/reports --delete  # and delete remote files gone locally
hippius-drive get -r work/reports ./reports         # download every file under a directory
```

The remote directory is the second argument; `""` is the folder root. Paths
below it are the paths below the local directory. Every local name is checked
against the server's path rules before any request, so a name the server would
refuse (a control or zero-width character, a segment over 255 bytes), or two
names that differ only in Unicode normalisation, stop the command up front.

`put -r` treats every file the way `put` does. A file that already exists is
reported on stderr and not uploaded, the other files still are, and the command
exits 3 at the end; `--overwrite` replaces each one by compare-and-swap. Any
other error (quota, auth, network after retries) stops at that file with exit
code 1: it would fail every remaining file too. Files uploaded before the stop
stay, so rerun with `sync` to finish. Symlinks and other non-regular files are
skipped and named on stderr; they are never followed. A local directory with
nothing to upload below it is created remotely, as `mkdir` would.

`sync` is one way, local to remote, and keeps no state between runs. It lists
the remote folder once and compares each local file's content hash with the
listed one: a new file is uploaded, a changed file replaces the remote copy by
compare-and-swap, an identical one is left alone. A remote change made since the
last run is replaced, not merged; for a folder edited in more than one place use
the desktop app, which keeps the history a two-way sync needs.

Remote files are deleted only with `--delete`, and only those under the remote
directory with no local file at the same path. Each delete quotes the revision
the listing showed, so a file edited after the listing stays. Remote files at
or below a skipped local path (a symlink) are kept. Remote empty directories
are not deleted.

Whatever someone else does between the listing and the write is left alone:
a file created or edited in that window is reported on stderr, the rest
continue, and the command exits 3. A file the desktop app stored under an NFD
name is reported the same way. A failed delete exits 1 after the summary line.

`get -r` writes each listed file under the remote directory to the local
directory, replacing local files of the same name, and refuses a path that
would land outside it. Files with no stored plaintext path cannot be placed
and are not downloaded; empty directories are not recreated. Remote names are
case-sensitive, but the default macOS and Windows disks are not, and Windows
also drops trailing dots and spaces: remote files that would land on one local
file (`A.txt` and `a.txt`, `x.` and `x`) are reported on stderr and none of
them is written. The other files are, and the command exits 3; `mv` one of
them remotely and rerun. The check follows the operating system, not the disk:
a case-sensitive macOS volume is refused all the same, and a case-insensitive
disk mounted on Linux is not checked. The same report and exit 3 cover a remote file
whose name is also a directory of other files (`a` next to `a/b`; only `a` is
refused), and, on Windows, a name Windows cannot hold: one with `<>:"|?*`, a
segment of only dots and spaces, or a device name such as `CON` or `aux.txt`.

`ls` shows directories first with recursive byte totals, then files. With no
paging flags it lists the whole directory, fetching as many pages as that
takes. `--limit` and `--offset` ask for a single page instead; the server
returns at most 200 entries per page whatever `--limit` says, and when more
remain `ls` prints the `--offset` that continues the listing. Note that
files with no stored plaintext path do not appear in `ls` — use `ls --all`,
which lists everything.

On a shared drive, each file line ends with who added it: `(by NAME)`, or
`(by SS58)` when the uploader's account has no display name. Files that
predate attribution have no suffix. `--json` carries `uploaded_by`,
`uploaded_by_name`, and `uploaded_by_email`, each `null` when the server
omitted it.

## Search and quota

```bash
hippius-drive search report
hippius-drive search --type image,.pdf --sort size_bytes --limit 50
hippius-drive search report --limit 200 --offset 200   # the next page
hippius-drive search invoice --json

hippius-drive quota
hippius-drive quota --size 10485760         # would this many bytes fit?
```

Search spans every folder on the account, not just the configured one, and each
hit names the folder it came from. A page holds at most 200 hits (25 when
`--limit` is omitted). When more remain, `search` prints the `--offset` of the
next page; raising `--limit` past 200 reveals nothing further. A term of one or
two characters is refused locally with an explanation and no request is sent,
because the server matches nothing on a term that short and an empty result
would read as "no such file".

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
hippius-drive drives join --invite-file ~/.secrets/invite.txt   # or - for stdin
HIPPIUS_INVITE_URL="$(cat invite.txt)" hippius-drive drives join --json
hippius-drive invite accept --invite-file invite.txt             # the same command

hippius-drive drives
hippius-drive drives --json
hippius-drive drives leave OWNER_SS58 FOLDER_HASH
```

`drives join` (and `invite accept`) reads the invite from an owner-only file,
stdin, or `HIPPIUS_INVITE_URL`, exactly one of them. `invite accept URL` still
takes the URL as an argument, but that puts the link's key in shell history and
`ps`; use the file. The output names the owner, drive, role, and folder; the
invite's key is never printed.

`invite put` prints the invite URL and performs the seal-back itself. It does
not print the folder phrase. On a server that opens link-secret invites (all of
production today) the URL is a `#i=` link: the drive key stays on the server,
sealed, and is released only to a signed-in account that can still accept the
invite. If that sealed key cannot be stored, the invite is revoked and the
command fails rather than print a link that would never open. `invite accept` uses this configuration's mnemonic
file and `--account`, and prints the owner, folder hash, and role. It takes both
link forms: a `#k=` link carries the drive key, a `#i=` link carries a secret that
fetches the key sealed on the server. A folder invite also prints the folder it
admits to; the server keeps that account inside it.

`drives` lists memberships opened from this account's grants: owner, folder
hash, role, and label. Folder grants follow, shown as `label / folder`. `drives leave` looks that row up and leaves as the
configured account. Changing a member's role, and uploading owner-wraps, are
library calls.

## Errors

Failures print one line and exit 1 — no traceback; a `put` that loses to the
server's current revision exits 3. That includes a batch `rm`
where some ids failed (HTTP 200 with per-id `errors`). A rejected input (a path
containing `..`, a batch over the 1000-id cap, a replacement missing its
`revision_seq`) is reported the same way, because from the command line those
are user errors rather than defects.
