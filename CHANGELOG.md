# Changelog

## 0.3.0

First release on PyPI.

- Shared drives: accept `#i=` link-secret invites, where the link carries a
  secret that fetches the drive key sealed on the server instead of the key
  itself, and mint them when the server supports it (all of production).
  Folder invites (`path_prefix`), with `Identity.for_folder_grant`, and folder
  grants in `drives.memberships()`.
- `MemberLimitReached`: a full drive is a retryable `Forbidden`, not a plain one.
- Listings carry `uploaded_by_name` / `uploaded_by_email`; `ls` shows who
  added each file.
- `hippius_drive.login(access_key)` and `hippius-drive auth login`: sign in
  with a 12-word access key, no browser (`pip install 'hippius-drive[login]'`).
- `drives join --invite-file`, `init --phrase-file`, `auth login
  --phrase-file`: secrets come from owner-only files or stdin, never argv.
- `put --overwrite`: replace by compare-and-swap on the current revision; a
  conflict exits 3. `files.lookup(path)`, `folders.make_dirs(paths)` and `mkdir`.

## 0.2.0

Not published. Files, folders, search, shares, folder shares, and shared-drive
invites (`#k=`).
