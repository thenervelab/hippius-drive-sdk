"""The ``hippius-drive`` command line, built only on the public client surface.

This is the reference example for the library: if a command needs something
the public API cannot express, the API is missing it. Output is plain text,
one record per line, with ``--json`` on the read commands for scripts.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import click

from hippius_drive import FileShareSpec, FolderShareSpec, InviteSpec, __version__, _config, errors
from hippius_drive import auth as api_auth
from hippius_drive._config import Config
from hippius_drive.client import Client
from hippius_drive.crypto import hashes, kdf, mnemonic_store
from hippius_drive.identity import Identity
from hippius_drive.models import (
    MAX_BATCH_DELETE,
    MAX_FOLDER_ENTRIES_BATCH,
    MAX_LISTING_PAGE_SIZE,
    MIN_SEARCH_QUERY_LENGTH,
    BrowseFolderEntry,
    RemoteFileEntry,
    RenameSpec,
    SearchFilters,
)

FILE_ID_HEX_LEN = 64
"""Length of a hex-encoded path_hash, which is how a file id is spelled."""

_CONSOLE = "https://console.hippius.com"
"""Console origin a minted link uses unless ``--console`` says otherwise."""

ENV_INVITE_URL = "HIPPIUS_INVITE_URL"
"""Environment variable ``drives join`` reads the invite URL from."""

_DAY_SECONDS = 86_400
"""Seconds in a day, for ``invite put --days``."""


@dataclass
class Context:
    """What every command needs: the resolved settings.

    Attributes:
        config: The resolved configuration.
    """

    config: Config
    # Unlocked at most once per command, and kept off ``repr``.
    _phrase: str | None = field(default=None, repr=False)

    def identity(self) -> Identity:
        """Unlock the mnemonic file and derive the folder identity.

        Returns:
            The identity for the configured label.

        Raises:
            ClickException: If the file is missing or will not open.
        """
        cfg = self.config
        account = _checked(cfg.require_account)
        if not cfg.mnemonic_file.exists():
            raise click.ClickException(
                f"no mnemonic at {cfg.mnemonic_file}; run 'hippius-drive init' first"
            )
        return Identity.from_master(self.master(), cfg.label, account_ss58=account)

    def master(self) -> str:
        """Unlock the mnemonic file and return the master phrase.

        Returns:
            The master BIP-39 phrase. The caller must not print or log it.

        Raises:
            ClickException: If the file is missing or will not open.
        """
        if self._phrase is not None:
            return self._phrase
        cfg = self.config
        if not cfg.mnemonic_file.exists():
            raise click.ClickException(
                f"no mnemonic at {cfg.mnemonic_file}; run 'hippius-drive init' first"
            )
        password = cfg.password if cfg.password is not None else _prompt_password()
        try:
            self._phrase = mnemonic_store.load(cfg.mnemonic_file, password)
        except mnemonic_store.MnemonicStoreError as exc:
            raise click.ClickException(str(exc)) from exc
        return self._phrase

    def client(self) -> Client:
        """Build a client for the configured account, folder, and server.

        Returns:
            The client. Close it, or use it as a context manager.
        """
        token = _checked(self.config.require_token)
        return Client(token=token, identity=self.identity(), server_url=self.config.server_url)


def _checked(getter: Any) -> Any:
    try:
        return getter()
    except _config.ConfigError as exc:
        raise click.ClickException(str(exc)) from exc


_SECRET_FILE_MAX = 64 * 1024


def _read_secret(path: Path) -> str:
    """Read a phrase or link from a file, or from stdin for ``-``. Never echoed.

    The file is opened once, without following a symlink, and judged by what
    was opened: it must be a regular file, and on POSIX one other users cannot
    read. On a terminal, ``-`` prompts with echo off instead of reading raw.
    """
    if str(path) == "-":
        if sys.stdin.isatty():
            return str(click.prompt("Secret", hide_input=True)).strip()
        return sys.stdin.read(_SECRET_FILE_MAX).strip()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        # A path that is not there may be the secret itself, typed where the
        # file name belongs; only an existing path is named in the error.
        shown = str(path) if os.path.lexists(path) else "the given path"
        raise click.ClickException(f"cannot read {shown}: {exc.strerror}") from exc
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise click.ClickException(f"{path} is not a regular file")
    if os.name == "posix" and info.st_mode & 0o077:
        os.close(fd)
        raise click.ClickException(f"{path} is readable by other users; chmod 600 it first")
    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        return handle.read(_SECRET_FILE_MAX).strip()


def _write_secret(path: Path, value: str) -> None:
    """Write a secret to an owner-only file (0600 from creation), atomically.

    A symlink at ``path`` is refused rather than followed, so the token can
    neither land somewhere else nor sit briefly in a file others can read.
    """
    if path.is_symlink():
        raise click.ClickException(f"{path} is a symlink; give the real path")
    try:
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".token-")
    except OSError as exc:
        raise click.ClickException(f"cannot write {path}: {exc.strerror}") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(value + "\n")
        os.replace(tmp, path)
    except BaseException as exc:
        Path(tmp).unlink(missing_ok=True)
        if isinstance(exc, OSError):
            raise click.ClickException(f"cannot write {path}: {exc.strerror}") from exc
        raise


def _prompt_password() -> str:
    if not sys.stdin.isatty():
        raise click.ClickException(
            f"no password: set {_config.ENV_PASSWORD} or run this from a terminal"
        )
    return click.prompt("Password", hide_input=True)


def _emit(rows: list[dict[str, Any]], as_json: bool, line: Any) -> None:
    """Print rows as JSON or as one plain-text line each."""
    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return
    for row in rows:
        click.echo(line(row))


class DriveGroup(click.Group):
    """A group that turns SDK failures into messages rather than tracebacks.

    The translation lives here rather than in the process entry point so that
    anything invoking the group directly, including the tests, sees the same
    behaviour a user does.
    """

    def invoke(self, ctx: click.Context) -> Any:
        """Run the chosen command, rewriting SDK errors as click errors.

        Args:
            ctx: The click context.

        Returns:
            Whatever the command returned.

        Raises:
            ClickException: For any service error or rejected input.
        """
        try:
            return super().invoke(ctx)
        except errors.DriveError as exc:
            raise click.ClickException(str(exc)) from exc
        except ValueError as exc:
            # Bad relative path, missing revision_seq, over-cap batch.
            raise click.ClickException(str(exc)) from exc


@click.group(cls=DriveGroup, context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__)
@click.option("--token", envvar=_config.ENV_TOKEN, default=None, help="Bearer token.")
@click.option("--account", envvar=_config.ENV_ACCOUNT, default=None, help="Account SS58 address.")
@click.option("--server", envvar=_config.ENV_SERVER, default=None, help="Server URL.")
@click.option(
    "--mnemonic-file",
    envvar=_config.ENV_MNEMONIC_FILE,
    default=None,
    type=click.Path(path_type=Path),
    help="Encrypted master mnemonic.",
)
@click.option("--label", envvar=_config.ENV_LABEL, default=None, help="Folder label.")
@click.pass_context
def main(
    ctx: click.Context,
    token: str | None,
    account: str | None,
    server: str | None,
    mnemonic_file: Path | None,
    label: str | None,
) -> None:
    """Work with Hippius Drive: end-to-end encrypted file storage."""
    overrides = {
        "token": token,
        "account_ss58": account,
        "server_url": server,
        "mnemonic_file": mnemonic_file,
        "label": label,
    }
    ctx.obj = Context(_checked(lambda: _config.load(overrides)))


@main.command()
@click.option(
    "--mnemonic",
    default=None,
    help="Import this phrase. It lands in shell history; prefer --phrase-file.",
)
@click.option(
    "--phrase-file",
    type=click.Path(path_type=Path, allow_dash=True),
    default=None,
    help="Import the phrase from this owner-only file, or - for stdin.",
)
@click.option("--force", is_flag=True, help="Overwrite an existing mnemonic file.")
@click.pass_obj
def init(obj: Context, mnemonic: str | None, phrase_file: Path | None, force: bool) -> None:
    """Create or import a master mnemonic and store it encrypted.

    A generated phrase is printed once. It is the only way to decrypt your
    files: the server never sees it, and nobody can recover it for you. An
    imported phrase is never printed. For an access-key account, import the
    access key itself: the console uses it as the Drive phrase too.
    """
    if mnemonic is not None and phrase_file is not None:
        raise click.ClickException("pass --mnemonic or --phrase-file, not both")
    path = obj.config.mnemonic_file
    if path.exists() and not force:
        raise click.ClickException(f"{path} already exists; pass --force to replace it")

    if phrase_file is not None:
        mnemonic = _read_secret(phrase_file)
    phrase = mnemonic if mnemonic is not None else kdf.generate_master_mnemonic()
    try:
        kdf.folder_keys(phrase)
    except ValueError as exc:
        raise click.ClickException(f"invalid recovery phrase: {exc}") from exc

    password = obj.config.password
    if password is None:
        password = click.prompt("New password", hide_input=True, confirmation_prompt=True)
    if not password.strip():
        raise click.ClickException("password must not be empty")
    mnemonic_store.save(path, phrase, password)

    click.echo(f"Wrote {path}")
    if mnemonic is None:
        click.echo("Recovery phrase (store it offline; it is shown only once):")
        click.echo(phrase)


@main.group()
def auth() -> None:
    """Sign in to the Hippius API with an access key, no browser."""


@auth.command("login")
@click.option(
    "--phrase-file",
    type=click.Path(path_type=Path, allow_dash=True),
    default=None,
    help="Plain-text access key in an owner-only file, or - for stdin. "
    "Default: unlock the encrypted mnemonic file.",
)
@click.option(
    "--api",
    "api_url",
    envvar=_config.ENV_API_URL,
    default=api_auth.DEFAULT_API_URL,
    show_default=True,
    help="Hippius API origin.",
)
@click.option(
    "--token-file",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="Write the token to this owner-only file instead of the config file.",
)
@click.pass_obj
def auth_login(
    obj: Context, phrase_file: Path | None, api_url: str, token_file: Path | None
) -> None:
    """Sign in with an access key and keep the API token for later commands.

    Signs the API's challenge with the two keys the access key stands for,
    the same as the console's access-key sign-in; the first sign-in creates
    the account. The token and account go to the config file (0600), or the
    token to --token-file. Neither the phrase nor the token is printed.
    """
    phrase = _read_secret(phrase_file) if phrase_file is not None else obj.master()
    try:
        session = api_auth.login(phrase, api_url=api_url)
    except ImportError as exc:
        raise click.ClickException(str(exc)) from exc
    if token_file is not None:
        _write_secret(token_file, session.token)
        # Drop a token the config held for another account: it would pair
        # with this account and fail every call.
        dropped: dict[str, str | None] = {"account_ss58": session.account_ss58, "token": None}
        saved = _checked(lambda: _config.save(dropped))
        where = token_file
    else:
        updates = {"token": session.token, "account_ss58": session.account_ss58}
        saved = _checked(lambda: _config.save(updates))
        where = saved
    click.echo(f"account   {session.account_ss58}")
    click.echo(f"username  {session.username}")
    click.echo(f"created   {'yes' if session.is_new else 'no'}")
    click.echo(f"token     saved to {where}")
    if saved != where:
        click.echo(f"account   saved to {saved}")


@main.command()
@click.pass_obj
def whoami(obj: Context) -> None:
    """Show the account, folder, and public key, then confirm the token matches.

    The local dump is not enough to diagnose a 403: that is a token/account
    pairing error, so this also lists folders with the configured token.
    """
    identity = obj.identity()
    click.echo(f"account      {identity.account_ss58}")
    click.echo(f"label        {identity.label}")
    click.echo(f"folder_hash  {identity.folder_hash}")
    click.echo(f"signing_key  {identity.verifying_key.hex()}")
    token = _checked(obj.config.require_token)
    with Client(token=token, identity=identity, server_url=obj.config.server_url) as client:
        client.folders.list()
    click.echo("token        accepted for this account")


@main.command()
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_obj
def folders(obj: Context, as_json: bool) -> None:
    """List every folder registered under the account."""
    with obj.client() as client:
        result = client.folders.list()
    rows = [f.model_dump(mode="json") for f in result.folders]
    _emit(rows, as_json, lambda r: f"{r['folder_hash']}  {r['file_count']:>8}  {r['label']}")


@main.command()
@click.argument("label", required=False)
@click.option("--device-name", default=None, help="Record which device registered it.")
@click.pass_obj
def register(obj: Context, label: str | None, device_name: str | None) -> None:
    """Register a folder so its label shows up in listings and search."""
    with obj.client() as client:
        result = client.folders.register(label, device_name)
    click.echo(result.status)


@main.command()
@click.argument("path", default="")
@click.option("--all", "walk", is_flag=True, help="List every file, not one directory.")
@click.option(
    "--limit",
    type=click.IntRange(min=1),
    default=None,
    help=f"Show one page of at most this many entries (server max {MAX_LISTING_PAGE_SIZE}).",
)
@click.option(
    "--offset",
    type=click.IntRange(min=0),
    default=None,
    help="Show one page starting at this entry.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_obj
def ls(
    obj: Context, path: str, walk: bool, limit: int | None, offset: int | None, as_json: bool
) -> None:
    """List one directory, or every file in the folder with --all.

    With neither --limit nor --offset the whole directory is listed, however
    many pages that takes. Either flag asks for a single page instead.
    """
    if path.endswith("/") and not path.startswith("/"):
        path = path.rstrip("/")
    if walk and path:
        raise click.ClickException("ls --all lists the whole folder; omit PATH or drop --all")

    one_page = limit is not None or offset is not None
    if walk and one_page:
        raise click.ClickException("ls --all lists the whole folder; drop --limit and --offset")

    next_offset = None
    with obj.client() as client:
        if walk:
            rows = [f.model_dump(mode="json") for f in client.files.iter_state()]
        elif one_page:
            rows, next_offset = _ls_page(client, path, offset or 0, limit)
        else:
            rows = [_ls_row(entry) for entry in client.files.iter_browse(path)]

    _emit(rows, as_json, _ls_line)
    if next_offset is not None:
        click.echo(f"more entries not shown; pass --offset {next_offset}", err=True)


def _ls_page(
    client: Client, path: str, offset: int, limit: int | None
) -> tuple[list[dict[str, Any]], int | None]:
    """Fetch one explicit page and say where the next one starts, if there is one.

    The next offset counts the entries that came back, not ``limit``: the
    server may return fewer than were asked for.
    """
    result = client.files.browse(path, offset=offset, limit=limit)
    entries = [*result.folders, *result.files]
    rows = [_ls_row(entry) for entry in entries]

    # An empty page has nowhere further to point, whatever has_more claims.
    next_offset = offset + len(entries) if result.has_more and entries else None
    return rows, next_offset


def _ls_row(entry: BrowseFolderEntry | RemoteFileEntry) -> dict[str, Any]:
    kind = "dir" if isinstance(entry, BrowseFolderEntry) else "file"
    return {"kind": kind, **entry.model_dump(mode="json")}


def _ls_line(row: dict[str, Any]) -> str:
    if row.get("kind") == "dir":
        return f"dir   {row['total_bytes']:>12}  {row['name']}/"
    name = row.get("relative_path") or row.get("file_name") or "-"
    line = f"file  {row['size_bytes']:>12}  {name}"
    uploader = row.get("uploaded_by_name") or row.get("uploaded_by")
    return f"{line}  (by {uploader})" if uploader else line


class ConflictExit(click.ClickException):
    """A write lost to the server's current revision. Exit code 3, so scripts can tell."""

    exit_code = 3


@main.command()
@click.argument("local", type=click.Path(exists=True, path_type=Path))
@click.argument("remote")
@click.option(
    "-r",
    "--recursive",
    is_flag=True,
    help="LOCAL is a directory: upload every file under it to REMOTE/<relative path>.",
)
@click.option(
    "--overwrite",
    is_flag=True,
    help="Replace REMOTE if it exists, quoting the revision just read. A write "
    "that lands in between still fails rather than being clobbered.",
)
@click.option("--base-revision", default=None, help="Hex revision this write replaces.")
@click.option("--revision-seq", type=int, default=None, help="Current revision_seq plus one.")
@click.pass_obj
def put(
    obj: Context,
    local: Path,
    remote: str,
    recursive: bool,
    overwrite: bool,
    base_revision: str | None,
    revision_seq: int | None,
) -> None:
    """Encrypt and upload LOCAL to the folder-relative path REMOTE.

    An existing REMOTE is never replaced silently: without --overwrite (or an
    explicit --base-revision) the upload fails with exit code 3. With it, the
    write is a compare-and-swap on the revision it read, so two writers racing
    on one path cannot clobber each other; the loser exits 3 and can rerun.

    With -r, LOCAL is a directory and REMOTE the directory it lands in ("" for
    the folder root). Each file follows the rules above; a file that already
    exists is reported and the rest still upload, then the command exits 3.
    Symlinks and other non-regular files are skipped and named on stderr.
    Empty directories are created. Any other error stops the upload at that
    file and exits 1; files uploaded before it stay.
    """
    explicit = base_revision is not None or revision_seq is not None
    if overwrite and explicit:
        raise click.ClickException("--overwrite looks the revision up; drop --base-revision")
    if recursive:
        if explicit:
            raise click.ClickException("put -r cannot take --base-revision; use --overwrite")
        _put_tree(obj, local, remote, "replace" if overwrite else "refuse")
        return
    if local.is_dir():
        raise click.ClickException(f"{local} is a directory; pass -r to upload it")
    base = bytes.fromhex(base_revision) if base_revision else None
    with obj.client() as client:
        if overwrite:
            result, replaced = _overwrite(client, local, remote, client.files.lookup(remote))
        else:
            result, replaced = _put_once(client, local, remote, base, revision_seq), base
        file_id = client.files.file_id(remote)
    click.echo(f"file_id      {file_id}")
    click.echo(f"revision_id  {result.revision_id.hex()}")
    if overwrite:
        click.echo(f"replaced     {'yes' if replaced is not None else 'no, new file'}")


def _overwrite(
    client: Client, local: Path, remote: str, current: RemoteFileEntry | None
) -> tuple[Any, bytes | None]:
    """Replace ``remote`` by compare-and-swap; returns the result and the replaced revision.

    The base is ``current``, the row a listing showed at that path. A path whose row the listing
    does not show (no stored path) or that someone created since answers the
    create with a 409 naming its current revision; that revision is quoted
    once more, still as a compare-and-swap. Anything after that is a race the
    caller has to look at.
    """
    base, seq = None, None
    if current is not None:
        if current.file_id != client.files.file_id(remote):
            raise click.ClickException(
                f"{remote} was stored by the desktop app under another id (an NFD name); "
                "replace it there, or rm it first"
            )
        base, seq = current.revision_id, current.revision_seq + 1
    try:
        return client.files.put(local, remote, base_revision_id=base, revision_seq=seq), base
    except errors.Conflict as exc:
        if base is not None or not _names_a_revision(exc):
            raise ConflictExit(_conflict_message(remote, exc, replacing=base is not None)) from exc
        base, seq = exc.current_revision_id, (exc.current_revision_seq or 0) + 1
    return _put_once(client, local, remote, base, seq), base


def _put_once(client: Client, local: Path, remote: str, base: bytes | None, seq: int | None) -> Any:
    try:
        return client.files.put(local, remote, base_revision_id=base, revision_seq=seq)
    except errors.Conflict as exc:
        raise ConflictExit(_conflict_message(remote, exc, replacing=base is not None)) from exc


def _names_a_revision(exc: errors.Conflict) -> bool:
    """True when the 409 reports a live row: a non-zero revision and its sequence."""
    revision = exc.current_revision_id
    return revision is not None and any(revision) and exc.current_revision_seq is not None


def _says_gone(exc: errors.Conflict) -> bool:
    """True for hcfs's gone-file answers: ``target_gone``, or the all-zero revision.

    A 409 with no revision at all is not one of them: hcfs sends that when it
    could not re-read the row, which says nothing about the file being gone.
    """
    revision = exc.current_revision_id
    return exc.code == "target_gone" or (revision is not None and not any(revision))


def _conflict_message(remote: str, exc: errors.Conflict, *, replacing: bool) -> str:
    if _names_a_revision(exc):
        if replacing:
            return f"{remote} changed since it was read; rerun to replace the newer version"
        return f"{remote} already exists; pass --overwrite to replace it"
    if _says_gone(exc):
        return f"{remote} was moved or deleted since it was read; check before uploading again"
    # Session-state 409s (a chunked upload already running, say) are not
    # about the file's revision at all.
    return f"{remote}: the server refused the upload: {exc}"


@main.command()
@click.argument("paths", nargs=-1, required=True)
@click.pass_obj
def mkdir(obj: Context, paths: tuple[str, ...]) -> None:
    """Create directories, so they show in listings while still empty.

    Existing directories are fine. A file can also be uploaded straight into a
    directory that does not exist yet; mkdir is for empty ones.
    """
    with obj.client() as client:
        result = client.folders.make_dirs(list(paths))
    click.echo(result.status)


@main.command()
@click.argument("local", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.argument("remote")
@click.option(
    "--delete",
    is_flag=True,
    help="Also delete remote files under REMOTE that are not in LOCAL. There is no undo.",
)
@click.pass_obj
def sync(obj: Context, local: Path, remote: str, delete: bool) -> None:
    """Make the directory REMOTE ("" for the root) match the local directory LOCAL.

    One way, local to remote. A file missing remotely is uploaded; one whose
    content differs (by the salted content hash the listing carries) replaces
    the remote copy by compare-and-swap; an identical one is left alone.
    Remote files are never deleted unless --delete is given. A remote change
    made since the last sync is replaced by the local copy, not merged: keep
    a folder edited in two places in sync with the desktop app instead.

    A file someone writes or edits between the listing and the write is left
    alone: it is reported, the rest continue, and the command exits 3.
    Symlinks are skipped (and with --delete, the remote files at their paths
    are kept), empty directories are created, and any other error stops at
    that file with exit 1.
    """
    prefix = _tree_prefix(remote)
    tree = _walk_tree(local, prefix)
    with obj.client() as client:
        listing = _list_remote(client, prefix)
        tally = _upload_tree(client, tree, listing, "replace_changed")
        if delete:
            _delete_missing(client, tree, listing, tally)
    _finish_tree(tally)


ExistingRemote = Literal["refuse", "replace", "replace_changed"]
"""What a tree upload does with a file that is already listed at its path.

``refuse``: report it and upload nothing (``put -r``). ``replace``: replace it
by compare-and-swap (``put -r --overwrite``). ``replace_changed``: replace it
only when the content differs (``sync``).
"""


@dataclass(frozen=True)
class _Tree:
    """A local directory as a tree upload sees it. Every remote path is valid and unique.

    Attributes:
        files: Each regular file and the remote path it goes to, in walk order.
        empty_dirs: Remote paths of directories with nothing to upload below them.
        skipped: Symlinks and other non-regular entries, with the remote path
            each would have had.
    """

    files: list[tuple[Path, str]]
    empty_dirs: list[str]
    skipped: list[tuple[Path, str]]


@dataclass(frozen=True)
class _Listing:
    """The remote side of a tree command, from one ``/get_state`` walk.

    Attributes:
        by_id: Every file in the folder by ``file_id``, including rows with no
            stored path, which only an id can place.
        by_path: Files under the prefix by NFC path. Where the desktop app also
            stored a path under an NFD id, the row whose id this SDK computes
            wins, as in ``lookup``.
    """

    by_id: dict[str, RemoteFileEntry]
    by_path: dict[str, RemoteFileEntry]


@dataclass
class _Tally:
    """What a tree command did, for the summary line and the exit code."""

    total: int = 0
    uploaded: int = 0
    replaced: int = 0
    unchanged: int = 0
    deleted: int = 0
    refused: int = 0
    failed: int = 0


def _tree_prefix(remote: str) -> str:
    """The remote directory a tree goes under, without a trailing slash; "" is the root."""
    return hashes.validate_stored_path(remote.removesuffix("/")) if remote else ""


def _remote_path(prefix: str, relative: str) -> str:
    return f"{prefix}/{relative}" if prefix else relative


def _raise(exc: OSError) -> None:
    raise click.ClickException(f"cannot read {exc.filename}: {exc.strerror}") from exc


def _walk_tree(root: Path, prefix: str) -> _Tree:
    """List what uploading ``root`` to ``prefix`` means; refuse names that cannot be stored.

    Symlinks are skipped rather than followed: following one can leave the
    tree, upload a file twice under two names, or loop. A directory whose only
    content was skipped counts as empty. Only directories with nothing below
    them are listed as empty: the server shows ``a`` once ``a/b`` exists.
    """
    tree = _Tree(files=[], empty_dirs=[], skipped=[])
    # os.walk swallows a directory it cannot list unless told otherwise.
    for here, dirnames, filenames in os.walk(root, onerror=_raise):
        base = Path(here)
        skipped = [base / n for n in dirnames + filenames if not _is_plain(base / n)]
        tree.skipped.extend((path, _target(root, prefix, path)) for path in sorted(skipped))
        dirnames[:] = sorted(n for n in dirnames if base / n not in skipped)
        kept = [base / n for n in sorted(filenames) if base / n not in skipped]
        tree.files.extend((path, _target(root, prefix, path)) for path in kept)
        if not dirnames and not kept and (base != root or prefix):
            tree.empty_dirs.append(_target(root, prefix, base))
    _check_targets(tree)
    return tree


def _is_plain(path: Path) -> bool:
    """True for a real directory or regular file, never for a symlink to one."""
    return not path.is_symlink() and (path.is_dir() or path.is_file())


def _target(root: Path, prefix: str, path: Path) -> str:
    """The remote path for ``path`` under ``root``; ``prefix`` itself for ``root``."""
    relative = path.relative_to(root).as_posix()
    return prefix if relative == "." else _remote_path(prefix, relative)


def _check_targets(tree: _Tree) -> None:
    """Refuse the tree if a remote path is invalid, or two local names share one.

    Done before any request, so a bad name deep in the tree cannot stop the
    upload halfway. Two names can share a path when they differ only in
    Unicode normalisation, which the server stores as NFC.
    """
    seen: dict[str, Path] = {}
    for local, remote in [*tree.files, *((Path(d), d) for d in tree.empty_dirs)]:
        try:
            path = hashes.validate_stored_path(remote)
        except ValueError as exc:
            raise click.ClickException(f"{local} cannot be stored: {exc}; rename it") from exc
        if path in seen:
            raise click.ClickException(f"{seen[path]} and {local} both map to {path}; rename one")
        seen[path] = local


def _list_remote(client: Client, prefix: str) -> _Listing:
    under = f"{prefix}/" if prefix else ""
    listing = _Listing(by_id={}, by_path={})
    for entry in client.files.iter_state():
        listing.by_id[entry.file_id] = entry
        if entry.relative_path is None:
            continue
        path = unicodedata.normalize("NFC", entry.relative_path)
        if path.startswith(under) and (
            path not in listing.by_path or entry.file_id == client.files.file_id(path)
        ):
            listing.by_path[path] = entry
    return listing


def _put_tree(obj: Context, local: Path, remote: str, existing: ExistingRemote) -> None:
    if not local.is_dir():
        raise click.ClickException(f"put -r takes a directory; {local} is a file")
    prefix = _tree_prefix(remote)
    tree = _walk_tree(local, prefix)
    with obj.client() as client:
        tally = _upload_tree(client, tree, _list_remote(client, prefix), existing)
    _finish_tree(tally)


def _upload_tree(
    client: Client, tree: _Tree, listing: _Listing, existing: ExistingRemote
) -> _Tally:
    """Upload every file in ``tree``, then create its empty directories.

    A refusal is about one file, so it is reported and the walk goes on. Any
    other failure (auth, quota, network after the transport's own retries) is
    about every file still to go, so it propagates and stops the walk.
    """
    for path, _ in tree.skipped:
        click.echo(f"skipped   {path} (not a regular file or directory)", err=True)
    tally = _Tally(total=len(tree.files))
    for local, remote in tree.files:
        # By id first: it also places rows with no stored path. By path second:
        # a desktop row stored under an NFD id.
        current = listing.by_id.get(client.files.file_id(remote)) or listing.by_path.get(
            hashes.normalize_relative_path(remote)
        )
        try:
            outcome = _upload_entry(client, local, remote, current, existing)
        except ConflictExit as exc:
            click.echo(f"refused   {exc.message}", err=True)
            tally.refused += 1
            continue
        click.echo(f"{outcome:<9} {remote}")
        tally.uploaded += outcome == "put"
        tally.replaced += outcome == "replaced"
        tally.unchanged += outcome == "unchanged"
    for start in range(0, len(tree.empty_dirs), MAX_FOLDER_ENTRIES_BATCH):
        client.folders.make_dirs(tree.empty_dirs[start : start + MAX_FOLDER_ENTRIES_BATCH])
    return tally


def _upload_entry(
    client: Client,
    local: Path,
    remote: str,
    current: RemoteFileEntry | None,
    existing: ExistingRemote,
) -> str:
    """Upload one file of a tree; returns ``put``, ``replaced`` or ``unchanged``.

    Raises:
        ConflictExit: For a refusal that is about this file only.
    """
    if current is None:
        _create(client, local, remote, existing)
        return "put"
    if existing == "refuse":
        raise ConflictExit(f"{remote} already exists; pass --overwrite to replace it")
    if existing == "replace_changed" and _same_content(client, local, current):
        return "unchanged"
    if current.file_id != client.files.file_id(remote):
        raise ConflictExit(
            f"{remote} was stored by the desktop app under another id (an NFD name); "
            "replace it there, or rm it first"
        )
    _overwrite(client, local, remote, current)
    return "replaced"


def _create(client: Client, local: Path, remote: str, existing: ExistingRemote) -> None:
    """Upload a file the listing did not show; never replaces one that appeared since.

    Unlike ``put --overwrite``, a 409 is not retried with the revision it
    names: the listing is the whole remote state the tree was compared with,
    so a file created after it has never been compared and is not ours to
    replace.
    """
    try:
        client.files.put(local, remote)
    except errors.Conflict as exc:
        if existing != "refuse" and _names_a_revision(exc):
            message = f"{remote} was created since it was listed; rerun to compare it"
            raise ConflictExit(message) from exc
        raise ConflictExit(_conflict_message(remote, exc, replacing=False)) from exc


def _same_content(client: Client, local: Path, current: RemoteFileEntry) -> bool:
    """True when ``local`` hashes to the listed ``salted_hash``, which salts with the account."""
    if local.stat().st_size != current.size_bytes:
        return False
    hasher = hashes.salted_hasher(client.identity.account_ss58)
    hasher.update_mmap(local)
    return hasher.digest() == current.salted_hash


def _delete_missing(client: Client, tree: _Tree, listing: _Listing, tally: _Tally) -> None:
    """Delete listed files under the prefix that have no local file, by compare-and-swap.

    Each delete quotes the revision the listing showed, so a file someone
    edited after the listing stays and is reported. Remote files at or under
    a skipped local path are kept: the local side has something there.
    """
    present = {hashes.normalize_relative_path(remote) for _, remote in tree.files}
    kept = [remote for _, remote in tree.skipped]
    gone = {
        entry.file_id: path
        for path, entry in listing.by_path.items()
        if path not in present and not any(path == k or path.startswith(f"{k}/") for k in kept)
    }
    ids = list(gone)
    for start in range(0, len(ids), MAX_BATCH_DELETE):
        batch = ids[start : start + MAX_BATCH_DELETE]
        expected = {file_id: listing.by_id[file_id].revision_id for file_id in batch}
        result = client.files.delete_many(batch, expected_revisions=expected)
        for done in result.deleted:
            click.echo(f"deleted   {gone.get(done.file_id, done.file_id)}")
        tally.deleted += result.files_deleted
        for failure in result.errors:
            path = gone.get(failure.file_id, failure.file_id)
            if failure.code == "conflict":
                click.echo(f"refused   {path} changed since it was listed; not deleted", err=True)
                tally.refused += 1
            else:
                click.echo(f"failed    {path}  {failure.code}: {failure.message}", err=True)
                tally.failed += 1


def _finish_tree(tally: _Tally) -> None:
    click.echo(
        f"uploaded {tally.uploaded}, replaced {tally.replaced}, unchanged {tally.unchanged}, "
        f"deleted {tally.deleted}, refused {tally.refused}, failed {tally.failed}"
    )
    if tally.failed:
        raise click.ClickException(f"{tally.failed} deletes failed; see the lines above")
    if tally.refused:
        raise ConflictExit(f"{tally.refused} files were left as they are; see the lines above")


def _get_tree(client: Client, target: str, dest: Path) -> None:
    """Download every listed file under ``target`` into ``dest``, keeping relative paths."""
    prefix = _tree_prefix(target)
    if dest.exists() and not dest.is_dir():
        raise click.ClickException(f"{dest} is a file; get -r writes into a directory")
    listed = _list_remote(client, prefix).by_path
    if not listed:
        raise click.ClickException(f"no files under {prefix or 'the folder root'}")
    root = dest.resolve()
    clashes = _local_clashes(list(listed))
    for path in sorted(clashes):
        others = ", ".join(p for p in clashes[path] if p != path)
        click.echo(
            f"refused   {path} is one local file with {others}; mv one to download it", err=True
        )
    for path, entry in sorted(listed.items()):
        if path in clashes:
            continue
        out = _inside(root, path[len(prefix) + 1 :] if prefix else path)
        try:
            client.files.get(entry.file_id, out)
        except OSError as exc:
            # A remote "a" next to "a/b", or a local directory where a file goes.
            raise click.ClickException(f"cannot write {out}: {exc.strerror}") from exc
        click.echo(f"wrote     {out}")
    click.echo(f"downloaded {len(listed) - len(clashes)}, refused {len(clashes)}")
    if clashes:
        raise ConflictExit(f"{len(clashes)} files were not downloaded; see the lines above")


def _local_clashes(paths: list[str]) -> dict[str, list[str]]:
    """Map each remote path that shares a local file with another to all paths sharing it.

    Remote paths are case-sensitive, so ``A.txt`` and ``a.txt`` can both
    exist. The default macOS and Windows disks fold case, and Windows also
    drops trailing dots and spaces (``x.`` is ``x``), so writing both would
    leave one file holding whichever came last. None of a clashing group is
    written: picking one would be a silent guess. A case-sensitive macOS
    volume gets the same refusal; ``mv`` on one of the remote files fixes
    either.
    """
    groups: dict[str, list[str]] = {}
    for path in sorted(paths):
        groups.setdefault(_local_name(path), []).append(path)
    return {path: group for group in groups.values() if len(group) > 1 for path in group}


def _local_name(path: str) -> str:
    """``path`` as the default disk of this platform compares names."""
    if sys.platform == "win32":
        path = "/".join(part.rstrip(". ") for part in path.split("/"))
    if sys.platform in ("darwin", "win32"):
        return path.casefold()
    return path


def _inside(root: Path, relative: str) -> Path:
    """``root / relative``, refused unless it resolves inside ``root``.

    A listed path comes from whoever wrote the row, which in a shared drive is
    any member. The server validates paths, but a name that is safe on the
    server (``C:/x`` on Windows, or a local symlink already under ``root``)
    can still point elsewhere once joined to a local path.
    """
    out = (root / relative).resolve()
    if not out.is_relative_to(root) or out == root:
        raise click.ClickException(f"refusing to write {relative!r}: it lands outside {root}")
    return out


@main.command()
@click.argument("target")
@click.argument("dest", type=click.Path(path_type=Path))
@click.option(
    "-r",
    "--recursive",
    is_flag=True,
    help='TARGET is a directory ("" for the root): download every file under it into DEST.',
)
@click.pass_obj
def get(obj: Context, target: str, dest: Path, recursive: bool) -> None:
    """Download and decrypt TARGET, a relative path or a 64-char file id.

    With -r, every listed file under the directory TARGET is written to
    DEST/<path below TARGET>, replacing local files of the same name. Empty
    directories are not recreated. Remote files whose names this disk treats
    as one (A.txt and a.txt on macOS and Windows) are reported and none of
    them is written; the rest are, and the command exits 3. Any other error
    stops the download.
    """
    if recursive:
        with obj.client() as client:
            _get_tree(client, target, dest)
        return
    if dest.is_dir():
        raise click.ClickException(f"{dest} is a directory; give the file path to write")
    with obj.client() as client:
        info = client.files.get(_as_file_id(client, target), dest)
    click.echo(f"wrote {dest} ({info.size_bytes} bytes)")


@main.command()
@click.argument("targets", nargs=-1, required=True)
@click.pass_obj
def rm(obj: Context, targets: tuple[str, ...]) -> None:
    """Delete files by relative path or file id. There is no undo."""
    with obj.client() as client:
        ids = [_as_file_id(client, target) for target in targets]
        if len(ids) == 1:
            click.echo(client.files.delete(ids[0]).status)
            return
        result = client.files.delete_many(ids)
        for failure in result.errors:
            click.echo(f"failed  {failure.file_id}  {failure.code}: {failure.message}", err=True)
        if result.errors:
            raise click.ClickException(
                f"deleted {result.files_deleted}, {len(result.errors)} failed"
            )
        click.echo(f"deleted {result.files_deleted}")


@main.command()
@click.argument("old")
@click.argument("new")
@click.pass_obj
def mv(obj: Context, old: str, new: str) -> None:
    """Move OLD to NEW without re-uploading the ciphertext."""
    with obj.client() as client:
        base = _current_revision(client, old)
        result = client.files.rename([RenameSpec(old, new, base)])
        for failure in result.failures:
            raise click.ClickException(f"rename failed: {failure.reason}")
        if not result.successes:
            raise click.ClickException("rename returned no successes")
        click.echo(result.successes[0].new_revision_id.hex())


@main.command()
@click.argument("query", required=False)
@click.option("--type", "file_type", default=None, help="Comma-separated categories or extensions.")
@click.option("--sort", "sort_by", default=None, help="Sort column.")
@click.option(
    "--limit",
    type=click.IntRange(min=1),
    default=None,
    help=f"Hits per page; the server defaults to 25 and caps it at {MAX_LISTING_PAGE_SIZE}.",
)
@click.option(
    "--offset",
    type=click.IntRange(min=0),
    default=0,
    help="Skip this many hits; use the value the previous page printed.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_obj
def search(
    obj: Context,
    query: str | None,
    file_type: str | None,
    sort_by: str | None,
    limit: int | None,
    offset: int,
    as_json: bool,
) -> None:
    """Search every folder on the account.

    QUERY needs at least 3 characters; the server matches nothing on less.
    """
    _require_searchable(query)

    filters = SearchFilters(q=query, file_type=file_type, sort_by=sort_by)
    with obj.client() as client:
        result = client.files.search(filters, offset=offset, limit=limit)

    rows = [hit.model_dump(mode="json") for hit in result.files]
    _emit(
        rows,
        as_json,
        lambda r: f"{r['size_bytes']:>12}  {r['folder_label'] or '-'}  {r['relative_path'] or '-'}",
    )
    if result.has_more and rows:
        # A larger --limit stops helping at the server cap, so point at the next page instead.
        click.echo(f"more hits not shown; pass --offset {offset + len(rows)}", err=True)


def _require_searchable(query: str | None) -> None:
    """Refuse a term the server would answer with an empty page.

    Sending it would print nothing, which reads as "no such file" when the
    truth is "the server did not search". An absent or blank term is a
    different request (list without a name filter) and goes through.
    """
    term = (query or "").strip()
    if term and len(term) < MIN_SEARCH_QUERY_LENGTH:
        raise click.ClickException(
            f"search term {term!r} is too short: the server only matches terms of "
            f"{MIN_SEARCH_QUERY_LENGTH} or more characters"
        )


@main.command()
@click.option("--size", type=int, default=None, help="Probe whether this many bytes would fit.")
@click.pass_obj
def quota(obj: Context, size: int | None) -> None:
    """Show account storage totals, and optionally pre-flight an upload."""
    with obj.client() as client:
        summary = client.summary.user()
        click.echo(f"files        {summary.file_count}")
        click.echo(f"total_bytes  {summary.total_bytes}")
        if size is not None:
            verdict = client.can_upload(size)
            click.echo(f"can_upload   {verdict.result}  {verdict.error or ''}".rstrip())


@main.group()
def share() -> None:
    """Mint, list, and revoke file-share links."""


@share.command("put")
@click.argument("local", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--name", required=True, help="Filename the recipient sees.")
@click.option(
    "--ttl",
    type=click.Choice(["24h", "7d", "30d", "never"]),
    default="24h",
    show_default=True,
    help="How long the link stays reachable.",
)
@click.option("--password", default=None, help="Password-wrap the link. At least 8 characters.")
@click.option("--console", default=_CONSOLE, show_default=True, help="Console origin for the link.")
@click.pass_obj
def share_put(
    obj: Context, local: Path, name: str, ttl: str, password: str | None, console: str
) -> None:
    """Encrypt LOCAL under a fresh key and print a console link."""
    spec = FileShareSpec(name, ttl=ttl, password=password, console_base_url=console)
    with obj.client() as client:
        created = client.shares.create(local, spec)
    click.echo(created.share_url)


@share.command("ls")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_obj
def share_ls(obj: Context, as_json: bool) -> None:
    """List this account's file shares."""
    with obj.client() as client:
        rows = [_share_row(item) for item in client.shares.list()]
    _emit(rows, as_json, _share_line)


@share.command("rm")
@click.argument("token")
@click.pass_obj
def share_rm(obj: Context, token: str) -> None:
    """Revoke a file share by its plaintext token."""
    with obj.client() as client:
        client.shares.revoke(token)
    click.echo("revoked")


@main.group("folder-share")
def folder_share() -> None:
    """Mint, list, and revoke folder-share links."""


@folder_share.command("put")
@click.option(
    "--prefix",
    default="",
    help="Drive-relative directory. Empty shares the whole drive.",
)
@click.option("--name", required=True, help="Name shown to the recipient.")
@click.option(
    "--ttl",
    type=click.Choice(["24h", "7d", "30d", "never"]),
    default="24h",
    show_default=True,
    help="How long the link stays reachable.",
)
@click.option("--password", default=None, help="Password-wrap the link. At least 8 characters.")
@click.option("--console", default=_CONSOLE, show_default=True, help="Console origin for the link.")
@click.pass_obj
def folder_share_put(
    obj: Context, prefix: str, name: str, ttl: str, password: str | None, console: str
) -> None:
    """Mint a link to an existing drive prefix and print it."""
    spec = FolderShareSpec(prefix, name, ttl=ttl, password=password, console_base_url=console)
    with obj.client() as client:
        created = client.folder_shares.create(spec)
    click.echo(created.share_url)


@folder_share.command("ls")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_obj
def folder_share_ls(obj: Context, as_json: bool) -> None:
    """List folder shares this account controls."""
    with obj.client() as client:
        rows = [_folder_row(item) for item in client.folder_shares.list()]
    _emit(rows, as_json, _folder_line)


@folder_share.command("rm")
@click.argument("token")
@click.pass_obj
def folder_share_rm(obj: Context, token: str) -> None:
    """Revoke a folder share by plaintext token or by token_hash."""
    with obj.client() as client:
        client.folder_shares.revoke(token)
    click.echo("revoked")


@main.group()
def invite() -> None:
    """Mint and accept shared-drive invites."""


@invite.command("put")
@click.option(
    "--role",
    type=click.Choice(["reader", "writer", "manager"]),
    default="writer",
    show_default=True,
    help="Role the invite grants.",
)
@click.option("--days", type=click.IntRange(min=1), default=None, help="Lifetime in days.")
@click.option("--console", default=_CONSOLE, show_default=True, help="Console origin for the link.")
@click.pass_obj
def invite_put(obj: Context, role: str, days: int | None, console: str) -> None:
    """Mint an invite to the configured folder and print the URL."""
    phrase = kdf.derive_folder_mnemonic(obj.master(), obj.config.label)
    expires = None if days is None else days * _DAY_SECONDS
    spec = InviteSpec(phrase, role=role, expires_in_secs=expires, console_base_url=console)
    with obj.client() as client:
        created = client.drives.create_invite(spec)
    click.echo(created.invite_url)


@invite.command("accept")
@click.argument("url", required=False)
@click.option(
    "--invite-file",
    type=click.Path(path_type=Path, allow_dash=True),
    default=None,
    help="Read the invite URL from this owner-only file, or - for stdin.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_obj
def invite_accept(obj: Context, url: str | None, invite_file: Path | None, as_json: bool) -> None:
    """Join a drive. Same as ``drives join``; prefer --invite-file over URL.

    A URL on the command line lands in shell history and ``ps``, and its
    fragment is the key (``#k=``) or the secret that fetches it (``#i=``).
    """
    _join(obj, _invite_url(url, invite_file), as_json)


def _invite_url(url: str | None, invite_file: Path | None) -> str:
    """The invite URL from exactly one source: argument, file, or environment.

    Blank values do not count as a source, so an exported but empty
    ``HIPPIUS_INVITE_URL`` neither supplies an invite nor conflicts with a file.
    """
    from_arg = (url or "").strip()
    from_env = os.environ.get(ENV_INVITE_URL, "").strip()
    given = [bool(from_arg), invite_file is not None, bool(from_env)]
    if sum(given) != 1:
        raise click.ClickException(
            f"give the invite once: --invite-file FILE (or -), {ENV_INVITE_URL}, or a URL"
        )
    if invite_file is not None:
        return _read_secret(invite_file)
    return from_arg or from_env


def _join(obj: Context, url: str, as_json: bool) -> None:
    account = _account(obj)
    with obj.client() as client:
        accepted = client.drives.accept(url, obj.master(), member_ss58=account)
    row = {
        "owner_ss58": accepted.owner_ss58,
        "folder_hash": accepted.folder_hash,
        "role": accepted.role,
        "path_prefix": accepted.path_prefix,
        "already_owner": accepted.already_owner,
    }
    if as_json:
        click.echo(json.dumps(row, indent=2))
        return
    click.echo(f"owner        {accepted.owner_ss58}")
    click.echo(f"folder_hash  {accepted.folder_hash}")
    click.echo(f"role         {accepted.role}")
    if accepted.path_prefix:
        click.echo(f"folder       {accepted.path_prefix}")


@main.group(invoke_without_command=True)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def drives(ctx: click.Context, as_json: bool) -> None:
    """List drives this account has joined."""
    if ctx.invoked_subcommand is not None:
        return
    _print_drives(ctx.obj, as_json)


@drives.command("join")
@click.argument("stray", nargs=-1, required=False, metavar="")
@click.option(
    "--invite-file",
    type=click.Path(path_type=Path, allow_dash=True),
    default=None,
    help="Read the invite URL from this owner-only file, or - for stdin.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_obj
def drives_join(
    obj: Context, stray: tuple[str, ...], invite_file: Path | None, as_json: bool
) -> None:
    """Join a shared drive from an invite, ``#i=`` or ``#k=``, drive or folder.

    The invite comes from --invite-file, or from the HIPPIUS_INVITE_URL
    environment variable; never from the command line. Prints the owner,
    drive id, role, and, for a folder invite, the folder. The invite's key
    is never printed.
    """
    if stray:
        # Taken and refused here, without echoing it: click's own "unexpected
        # extra argument" error would print the URL, key and all.
        raise click.ClickException(
            "drives join takes no URL argument (it would sit in shell history); "
            "use --invite-file FILE or HIPPIUS_INVITE_URL"
        )
    _join(obj, _invite_url(None, invite_file), as_json)


@drives.command("leave")
@click.argument("owner_ss58")
@click.argument("folder_hash")
@click.pass_obj
def drives_leave(obj: Context, owner_ss58: str, folder_hash: str) -> None:
    """Leave a joined drive. OWNER_SS58 and FOLDER_HASH come from ``drives``."""
    account = _account(obj)
    with obj.client() as client:
        rows = client.drives.memberships(obj.master(), member_ss58=account)
    row = _joined(rows, owner_ss58, folder_hash)
    build = Identity.for_folder_grant if row.path_prefix else Identity.for_shared_drive
    identity = build(
        row.phrase,
        owner_ss58=row.owner,
        folder_hash=row.folder,
        role=row.role,
        label=row.label,
    )
    token = _checked(obj.config.require_token)
    with Client(token=token, identity=identity, server_url=obj.config.server_url) as member:
        member.drives.leave(account)
    click.echo("left")


def _account(obj: Context) -> str:
    account: str = _checked(obj.config.require_account)
    return account


def _print_drives(obj: Context, as_json: bool) -> None:
    account = _account(obj)
    with obj.client() as client:
        memberships = client.drives.memberships(obj.master(), member_ss58=account)
    rows = [_drive_row(row) for row in memberships]
    _emit(rows, as_json, _drive_line)


def _share_row(item: Any) -> dict[str, Any]:
    return {
        "share_token": item.share_token,
        "filename": item.filename,
        "plaintext_size": item.plaintext_size,
        "expires_at": item.expires_at,
    }


def _folder_row(item: Any) -> dict[str, Any]:
    return {
        "token_hash": item.token_hash,
        "path_prefix": item.path_prefix,
        "display_name": item.display_name,
        "expires_at": item.expires_at,
    }


def _drive_row(item: Any) -> dict[str, Any]:
    return {
        "owner_ss58": item.owner_ss58,
        "folder_hash": item.folder_hash,
        "role": item.role,
        "display_label": item.display_label,
        "frozen": item.frozen,
        "path_prefix": item.path_prefix,
    }


def _share_line(row: dict[str, Any]) -> str:
    expiry = row["expires_at"] or "never"
    return f"{row['plaintext_size']:>12}  {expiry:<20}  {row['share_token']}  {row['filename']}"


def _folder_line(row: dict[str, Any]) -> str:
    expiry = row["expires_at"] or "never"
    prefix = row["path_prefix"] or "."
    return f"{expiry:<20}  {row['token_hash']}  {prefix}  {row['display_name']}"


def _drive_line(row: dict[str, Any]) -> str:
    frozen = "  frozen" if row["frozen"] else ""
    label = row["display_label"] or row["folder_hash"]
    folder = f" / {row['path_prefix']}" if row.get("path_prefix") else ""
    return f"{row['role']:<8}  {row['owner_ss58']}  {row['folder_hash']}  {label}{folder}{frozen}"


@dataclass(frozen=True)
class _Joined:
    """One joined drive or folder grant, as ``drives leave`` needs it."""

    phrase: str = field(repr=False)
    owner: str
    folder: str
    role: str
    label: str
    path_prefix: str | None


def _joined(rows: Sequence[Any], owner: str, folder: str) -> _Joined:
    """Return the opened grant and the fields of one joined drive or folder grant."""
    for row in rows:
        if row.owner_ss58 != owner or row.folder_hash != folder:
            continue
        phrase = row.folder_mnemonic
        if not isinstance(phrase, str) or not phrase:
            raise click.ClickException("this drive has no grant; it cannot be opened")
        label = row.display_label if isinstance(row.display_label, str) else ""
        role = row.role if isinstance(row.role, str) else ""
        prefix = row.path_prefix if isinstance(row.path_prefix, str) else None
        return _Joined(phrase, owner, folder, role, label, prefix)
    raise click.ClickException("no membership for that owner and folder")


def _as_file_id(client: Client, target: str) -> str:
    """Accept either a 64-char hex id or a relative path."""
    if len(target) == FILE_ID_HEX_LEN and all(c in "0123456789abcdefABCDEF" for c in target):
        return target.lower()
    return client.files.file_id(target)


def _current_revision(client: Client, relative_path: str) -> bytes:
    """Look up the revision a rename must quote, so the caller need not."""
    wanted = client.files.file_id(relative_path)
    for entry in client.files.iter_state():
        if entry.file_id == wanted:
            return entry.revision_id
    raise click.ClickException(f"no file at {relative_path}")


def run() -> None:
    """Console-script entry point. Error handling lives in :class:`DriveGroup`."""
    main()


if __name__ == "__main__":  # pragma: no cover
    run()
