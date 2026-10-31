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

### Share link insights, comments and reactions

```bash
hippius-drive share settings TOKEN                        # insights / comments / reactions on or off
hippius-drive share settings TOKEN --insights on --comments on --reactions off
hippius-drive share insights TOKEN                        # views, viewers, watch time
hippius-drive share comments TOKEN                        # your own share with an owner wrap
hippius-drive share comments --url-file link.txt          # any share: the URL is the key
HIPPIUS_SHARE_URL="$(cat link.txt)" hippius-drive share comments --json
hippius-drive share comment-post "see 0:42" TOKEN --at-ms 42000
hippius-drive share comment-post - TOKEN < comment.txt   # text from stdin
hippius-drive share comment-post "agreed" TOKEN --reply-to 41
hippius-drive share comment-rm TOKEN 41
hippius-drive share reactions TOKEN
hippius-drive share react 👍 TOKEN                        # one of 👍 ❤️ 😂 😮 🎉 👏 🔥 🙌
hippius-drive share react 🔥 TOKEN --at-ms 98000          # at a moment of the video
hippius-drive share unreact 👍 TOKEN                      # also drops its moments
hippius-drive share moments TOKEN                         # every reaction moment, by time
hippius-drive share block TOKEN 41                        # stop the author of comment 41
hippius-drive share unblock TOKEN 41
hippius-drive share seen TOKEN                            # restart the "new" counts
```

Comments and viewer names are encrypted under the link's key, so the commands
that read or post them need the share URL. They take it from `--url-file`
(an owner-only file, or `-` for stdin) or `HIPPIUS_SHARE_URL`, never from the
command line. For your own share, `TOKEN` alone is enough when the share has an
owner wrap (links minted in the console do; `share put` links do not): the URL
is rebuilt from it with your recovery phrase. A `#p=` link's password comes
from `HIPPIUS_SHARE_PASSWORD` only; there is no flag, because argv is visible
to other processes. `insights` reads the numbers without the key and shows
viewer names only when it has one; otherwise it says why they are hidden.

Posted comments are anonymous. Reading is open to anyone with the link;
posting needs a signed-in account and the owner's `comments` switch on.
Comment text and names come from anyone with the link. Plain output prints a
name as a quoted string, so it cannot pass for the `[owner]` badge the server
vouches for, and adds ` (viewer)` after a name that claims to be the owner or
Hippius, as the console does. Control characters, line separators and bidi
controls become `?`; `--json` has the exact text.

Switches start off. Turning one on needs a paid Drive plan: on the Free plan
the server refuses with `403 paid_plan_required` and the command says to
upgrade. `502 billing_unavailable` means the plan service did not answer;
run it again later. Insights on the Free plan show the counts and list the
rest as locked. Each command reads `GET /v1/capabilities` first; when
`share_insights` or `share_comments` is off it stops with a message naming the
flag instead of calling the feature's route.

Reactions are per account: `react` again changes nothing, and `unreact`
works even with reactions off or after a block. `react --at-ms` stores one
more moment on every call and also adds the reaction; `unreact` takes the
reaction and all its moments back. It is never retried, so a lost response
does not store a moment twice. The moment commands need `share_reaction_moments`.

`block` stops the author of a comment on your link from commenting and
reacting there. The server never says who they are, and what they wrote
stays until it is deleted. Unblock through a comment of theirs that is still
on the link: once their last one is deleted, the block lasts as long as the
link. A blocked account gets `403 blocked`.

`seen` is what the console sends when you open a link's Insights: the
`new_views` and `new_comments` counts in `share ls --json` start again from 0.
`share insights` does not send it. It needs `share_listing_counts`.

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
