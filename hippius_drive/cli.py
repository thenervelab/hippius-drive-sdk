"""The ``hippius-drive`` command line, built only on the public client surface.

This is the reference example for the library: if a command needs something
the public API cannot express, the API is missing it. Output is plain text,
one record per line, with ``--json`` on the read commands for scripts.
"""

from __future__ import annotations

import base64
import json
import os
import stat
import sys
import tempfile
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import click

from hippius_drive import (
    CommentAuthor,
    FileShareSpec,
    FolderShareSpec,
    InviteSpec,
    __version__,
    _config,
    errors,
)
from hippius_drive import auth as api_auth
from hippius_drive._config import Config
from hippius_drive.client import Client
from hippius_drive.crypto import kdf, mnemonic_store, sharing
from hippius_drive.crypto.comments import VIEWER_SECRET_LEN, CommentMention, mention_wire
from hippius_drive.identity import Identity
from hippius_drive.models import (
    MAX_LISTING_PAGE_SIZE,
    MIN_SEARCH_QUERY_LENGTH,
    BrowseFolderEntry,
    RemoteFileEntry,
    RenameSpec,
    SearchFilters,
    ShareComment,
    ShareInsights,
    ShareSettings,
    ShareSummary,
)

FILE_ID_HEX_LEN = 64
"""Length of a hex-encoded path_hash, which is how a file id is spelled."""

_CONSOLE = "https://console.hippius.com"
"""Console origin a minted link uses unless ``--console`` says otherwise."""

ENV_INVITE_URL = "HIPPIUS_INVITE_URL"
"""Environment variable ``drives join`` reads the invite URL from."""

ENV_SHARE_URL = "HIPPIUS_SHARE_URL"
"""Environment variable the share comment and insights commands read a link from."""

VIEWER_SECRET_FILE = "viewer-secret"  # noqa: S105 - a file name, not a secret
"""File beside the mnemonic file holding the secret named comments derive a viewer id from."""

ENV_SHARE_PASSWORD = "HIPPIUS_SHARE_PASSWORD"  # noqa: S105 - a variable name, not a secret
"""Environment variable holding a ``#p=`` link's password. There is no flag: argv is visible."""

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
            raise click.ClickException(_explain(exc)) from exc
        except ValueError as exc:
            # Bad relative path, missing revision_seq, over-cap batch.
            raise click.ClickException(str(exc)) from exc


def _explain(exc: errors.DriveError) -> str:
    """The error, plus what to do for the two plan refusals a user can act on."""
    if isinstance(exc, errors.PaidPlanRequired):
        return f"{exc}\nthis needs a paid Drive plan: upgrade in {_CONSOLE}, then run it again"
    if isinstance(exc, errors.ServerError) and exc.code == "billing_unavailable":
        return f"{exc}\nthe Drive plan service did not answer: try again in a minute"
    return str(exc)


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
@click.argument("local", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("remote")
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
    overwrite: bool,
    base_revision: str | None,
    revision_seq: int | None,
) -> None:
    """Encrypt and upload LOCAL to the folder-relative path REMOTE.

    An existing REMOTE is never replaced silently: without --overwrite (or an
    explicit --base-revision) the upload fails with exit code 3. With it, the
    write is a compare-and-swap on the revision it read, so two writers racing
    on one path cannot clobber each other; the loser exits 3 and can rerun.
    """
    if overwrite and (base_revision or revision_seq is not None):
        raise click.ClickException("--overwrite looks the revision up; drop --base-revision")
    base = bytes.fromhex(base_revision) if base_revision else None
    with obj.client() as client:
        if overwrite:
            result, replaced = _overwrite(client, local, remote)
        else:
            result, replaced = _put_once(client, local, remote, base, revision_seq), base
        file_id = client.files.file_id(remote)
    click.echo(f"file_id      {file_id}")
    click.echo(f"revision_id  {result.revision_id.hex()}")
    if overwrite:
        click.echo(f"replaced     {'yes' if replaced is not None else 'no, new file'}")


def _overwrite(client: Client, local: Path, remote: str) -> tuple[Any, bytes | None]:
    """Replace ``remote`` by compare-and-swap; returns the result and the replaced revision.

    The base is the revision the listing shows. A path whose row the listing
    does not show (no stored path) or that someone created since answers the
    create with a 409 naming its current revision; that revision is quoted
    once more, still as a compare-and-swap. Anything after that is a race the
    caller has to look at.
    """
    current = client.files.lookup(remote)
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
@click.argument("target")
@click.argument("dest", type=click.Path(dir_okay=False, path_type=Path))
@click.pass_obj
def get(obj: Context, target: str, dest: Path) -> None:
    """Download and decrypt TARGET, a relative path or a 64-char file id."""
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
            click.echo(f"failed  {failure.file_id}  {failure.error}", err=True)
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


_URL_FILE = click.option(
    "--url-file",
    type=click.Path(path_type=Path, allow_dash=True),
    default=None,
    help=f"Read the share URL from this owner-only file, or - for stdin. Or set {ENV_SHARE_URL}.",
)
_SWITCH = click.Choice(["on", "off"])


@share.command("settings")
@click.argument("token")
@click.option("--insights", type=_SWITCH, default=None, help="Record views.")
@click.option("--comments", type=_SWITCH, default=None, help="Let viewers comment.")
@click.option("--reactions", type=_SWITCH, default=None, help="Let viewers react.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_obj
def share_settings(
    obj: Context,
    token: str,
    insights: str | None,
    comments: str | None,
    reactions: str | None,
    as_json: bool,
) -> None:
    """Show a file share's insights, comments and reactions switches, or change them.

    Turning one on needs a paid Drive plan.
    """
    with obj.client() as client:
        if insights is None and comments is None and reactions is None:
            row = _own_share(client, token)
            if row is None:
                raise click.ClickException("this account has no file share with that token")
            if row.settings is None:
                raise click.ClickException("this server does not report link settings")
            found = row.settings
        else:
            found = client.shares.update_settings(
                token,
                insights=_on(insights),
                comments=_on(comments),
                reactions=_on(reactions),
            )
    _print_settings(found, as_json)


@share.command("insights")
@click.argument("token")
@_URL_FILE
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_obj
def share_insights(obj: Context, token: str, url_file: Path | None, as_json: bool) -> None:
    """Show a file share's views and watch time.

    The numbers need no key. Viewer names are encrypted under the link's key:
    they are shown when the link is given with --url-file or HIPPIUS_SHARE_URL,
    or when the share has an owner wrap (links minted in the console do).
    """
    with obj.client() as client:
        found = client.shares.insights(token)
        names, hidden = _viewer_names(obj, client, token, found, url_file)
    if as_json:
        data = found.model_dump(mode="json")
        for viewer in data["viewers"]:
            viewer["name"] = names.get(viewer["viewer_id"])
        click.echo(json.dumps(data, indent=2))
        return
    _print_insights(found, names, hidden)


@share.command("comments")
@click.argument("token", required=False)
@_URL_FILE
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_obj
def share_comments(obj: Context, token: str | None, url_file: Path | None, as_json: bool) -> None:
    """List a file share's comments, decrypted with the link's key.

    The link comes from --url-file or HIPPIUS_SHARE_URL; for your own share,
    TOKEN alone works when the share has an owner wrap. A #p= link's password
    comes from HIPPIUS_SHARE_PASSWORD.
    """
    with obj.client() as client:
        link = _require_link(obj, client, token, url_file)
        found = client.shares.comments(link, password=_link_password(link))
    rows = [_comment_row(item) for item in found]
    _emit(rows, as_json, _comment_line)


@share.command("comment-post")
@click.argument("text")
@click.argument("token", required=False)
@_URL_FILE
@click.option("--reply-to", default=None, help="Id of the top-level comment to answer.")
@click.option("--at-ms", type=int, default=None, help="Moment of the video, in milliseconds.")
@click.option("--name", default=None, help="Post under this name instead of anonymously.")
@click.option(
    "--mention",
    "mentions",
    multiple=True,
    help="Tag someone the comments offer (repeatable); TEXT must contain @ and the name.",
)
@click.pass_obj
def share_comment_post(
    obj: Context,
    text: str,
    token: str | None,
    url_file: Path | None,
    reply_to: str | None,
    at_ms: int | None,
    name: str | None,
    mentions: tuple[str, ...],
) -> None:
    """Post TEXT as a comment on a file share, anonymously unless --name. Prints its id.

    TEXT ``-`` reads the comment from stdin, so it stays out of shell history.
    A named comment is counted in the owner's insights under a viewer id
    derived from a secret kept in ``viewer-secret`` beside the mnemonic file.
    """
    if text == "-":
        text = sys.stdin.read()
    with obj.client() as client:
        link = _require_link(obj, client, token, url_file)
        password = _link_password(link)
        tagged = _pick_mentions(client, link, password, mentions)
        author = None if name is None else CommentAuthor(name, _viewer_secret(obj))
        posted = client.shares.post_comment(
            link,
            text,
            password=password,
            parent_id=reply_to,
            at_ms=at_ms,
            author=author,
            mentions=tagged,
        )
    click.echo(f"posted {posted.id}")


@share.command("comment-rm")
@click.argument("token")
@click.argument("comment_id")
@click.pass_obj
def share_comment_rm(obj: Context, token: str, comment_id: str) -> None:
    """Delete a comment: any on your own share, or your own on another."""
    with obj.client() as client:
        client.shares.delete_comment(token, comment_id)
    click.echo("deleted")


@share.command("reactions")
@click.argument("token")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_obj
def share_reactions(obj: Context, token: str, as_json: bool) -> None:
    """Show a file share's reaction counts. ``mine`` marks your own."""
    with obj.client() as client:
        found = client.shares.reactions(token)
    mine = set(found.mine)
    rows = [
        {"emoji": emoji, "count": count, "mine": emoji in mine}
        for emoji, count in found.counts.items()
    ]
    _emit(rows, as_json, _reaction_line)


@share.command("react")
@click.argument("emoji")
@click.argument("token")
@click.option(
    "--at-ms",
    type=click.IntRange(min=0),
    default=None,
    help="Send it at this moment of the video, in milliseconds. Each call adds one more.",
)
@click.pass_obj
def share_react(obj: Context, emoji: str, token: str, at_ms: int | None) -> None:
    """React to a file share with EMOJI, one of the link's eight reactions."""
    with obj.client() as client:
        if at_ms is None:
            client.shares.react(token, emoji)
        else:
            client.shares.react_at(token, emoji, at_ms)
    click.echo("reacted")


@share.command("unreact")
@click.argument("emoji")
@click.argument("token")
@click.pass_obj
def share_unreact(obj: Context, emoji: str, token: str) -> None:
    """Take your EMOJI reaction back, with every moment you sent it at."""
    with obj.client() as client:
        client.shares.unreact(token, emoji)
    click.echo("removed")


@share.command("moments")
@click.argument("token")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_obj
def share_moments(obj: Context, token: str, as_json: bool) -> None:
    """List every reaction sent at a moment of a file share's video."""
    with obj.client() as client:
        found = client.shares.reaction_moments(token)
    rows = [item.model_dump() for item in found]
    _emit(rows, as_json, _moment_line)


@share.command("block")
@click.argument("token")
@click.argument("comment_id")
@click.pass_obj
def share_block(obj: Context, token: str, comment_id: str) -> None:
    """Stop the author of COMMENT_ID commenting and reacting on your share.

    Unblock through a comment of theirs still on the link: once their last
    one is deleted, the block cannot be undone.
    """
    with obj.client() as client:
        client.shares.block_author(token, comment_id)
    click.echo("blocked")


@share.command("unblock")
@click.argument("token")
@click.argument("comment_id")
@click.pass_obj
def share_unblock(obj: Context, token: str, comment_id: str) -> None:
    """Lift a block through COMMENT_ID, a comment by the blocked author."""
    with obj.client() as client:
        client.shares.unblock_author(token, comment_id)
    click.echo("unblocked")


@share.command("seen")
@click.argument("token")
@click.pass_obj
def share_seen(obj: Context, token: str) -> None:
    """Mark your share's insights seen: its new views and comments start again from 0."""
    with obj.client() as client:
        client.shares.mark_insights_seen(token)
    click.echo("marked seen")


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


def _on(value: str | None) -> bool | None:
    return None if value is None else value == "on"


def _own_share(client: Client, token: str) -> ShareSummary | None:
    for row in client.shares.list():
        if row.share_token == token:
            return row
    return None


def _link_given(url_file: Path | None) -> str | None:
    """The share URL from --url-file or the environment; never both."""
    from_env = os.environ.get(ENV_SHARE_URL, "").strip()
    if url_file is not None and from_env:
        raise click.ClickException(f"give the link once: --url-file or {ENV_SHARE_URL}")
    if url_file is not None:
        return _read_secret(url_file)
    return from_env or None


def _find_link(
    obj: Context, client: Client, token: str | None, url_file: Path | None
) -> str | None:
    """The share URL: given, or rebuilt from your own share's owner wrap, or None."""
    given = _link_given(url_file)
    if given is not None:
        if token is not None and sharing.parse_share_url(given).token != token:
            raise click.ClickException("the link is for a different share than TOKEN")
        return given
    if token is None:
        return None
    row = _own_share(client, token)
    if row is None or not row.owner_wrap:
        return None
    # recover_url lists the shares again; one more GET keeps the CLI on the
    # public method instead of reopening the wrap here.
    return client.shares.recover_url(token, obj.master())


def _require_link(obj: Context, client: Client, token: str | None, url_file: Path | None) -> str:
    link = _find_link(obj, client, token, url_file)
    if link is None:
        raise click.ClickException(
            f"comments need the link's key: pass --url-file FILE or set {ENV_SHARE_URL} "
            "(TOKEN alone works only for your own share with an owner wrap)"
        )
    return link


def _link_password(link: str) -> str | None:
    """A ``#p=`` link's password, from the environment only: never argv."""
    password = os.environ.get(ENV_SHARE_PASSWORD) or None
    if password is None and sharing.parse_share_url(link).secret.private:
        raise click.ClickException(f"this is a password link: set {ENV_SHARE_PASSWORD}")
    return password


def _pick_mentions(
    client: Client, link: str, password: str | None, names: tuple[str, ...]
) -> list[CommentMention]:
    """The candidates named on the command line; ``owner`` also names the owner."""
    if not names:
        return []
    offered = client.shares.mention_candidates(link, password=password)
    picked: list[CommentMention] = []
    for wanted in names:
        match = next((c for c in offered if _names_candidate(wanted, c)), None)
        if match is None:
            shown = ", ".join(json.dumps(c.name, ensure_ascii=False) for c in offered) or "none"
            raise click.ClickException(
                f"nobody to tag as {json.dumps(wanted, ensure_ascii=False)}; offered: {shown}"
            )
        picked.append(match)
    return picked


def _names_candidate(wanted: str, candidate: CommentMention) -> bool:
    if candidate.kind == "owner" and wanted.casefold() == "owner":
        return True
    return wanted == candidate.name


def _viewer_secret(obj: Context) -> bytes:
    """This install's viewer secret, made on first use: the console's per-browser secret.

    32 random bytes, unpadded base64url as the console stores it, in an
    owner-only file beside the mnemonic file. Created with O_EXCL, so two
    commands racing on first use keep one secret.
    """
    path = obj.config.mnemonic_file.parent / VIEWER_SECRET_FILE
    _create_viewer_secret(path)
    raw = _read_secret(path)
    try:
        secret = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except ValueError as exc:
        raise click.ClickException(f"{path} is not a viewer secret; delete it") from exc
    if len(secret) != VIEWER_SECRET_LEN:
        raise click.ClickException(f"{path} is not a viewer secret; delete it")
    return secret


def _create_viewer_secret(path: Path) -> None:
    """Write a fresh secret at ``path`` unless something is already there."""
    value = base64.urlsafe_b64encode(os.urandom(VIEWER_SECRET_LEN)).decode().rstrip("=")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        return
    except OSError as exc:
        raise click.ClickException(f"cannot write {path}: {exc.strerror}") from exc
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(value + "\n")


def _viewer_names(
    obj: Context, client: Client, token: str, found: ShareInsights, url_file: Path | None
) -> tuple[dict[str, str], str | None]:
    """Viewer names by id, and why names are hidden when they are."""
    if not any(viewer.name_ct for viewer in found.viewers):
        return {}, None
    link = _find_link(obj, client, token, url_file)
    if link is None:
        return {}, f"pass --url-file or set {ENV_SHARE_URL} to read them"
    try:
        password = _link_password(link)
    except click.ClickException as exc:
        # The numbers are already here; a missing password only hides names.
        return {}, exc.message
    return client.shares.viewer_names(found, link, password=password), None


def _print_settings(found: ShareSettings, as_json: bool) -> None:
    if as_json:
        click.echo(found.model_dump_json(indent=2))
        return
    for name, value in found.model_dump().items():
        click.echo(f"{name:<10} {'on' if value else 'off'}")


def _print_insights(found: ShareInsights, names: dict[str, str], hidden: str | None) -> None:
    click.echo(f"plan            {found.plan}")
    click.echo(f"views           {found.total_views}")
    click.echo(f"unique_viewers  {found.unique_viewers}")
    if found.completion_rate is not None:
        click.echo(f"completion      {found.completion_rate:.0%}")
    if found.locked:
        click.echo(f"locked          {', '.join(found.locked)} (paid Drive plan)")
    for viewer in found.viewers:
        name = names.get(viewer.viewer_id)
        shown = _terminal_safe(json.dumps(name, ensure_ascii=False)) if name else "-"
        seconds = viewer.watched_ms // 1000
        click.echo(f"viewer  {viewer.viewer_id}  {viewer.visits} visits  {seconds}s  {shown}")
    if hidden is not None:
        click.echo(f"names are hidden: {hidden}")


def _comment_row(item: ShareComment) -> dict[str, Any]:
    return {
        "id": item.id,
        "parent_id": item.parent_id,
        "at_ms": item.at_ms,
        "created_at": item.created_at,
        "name": item.name,
        "name_claimed": item.name_claimed,
        "text": item.text,
        "anonymous": item.anonymous,
        "mine": item.mine,
        "owner": item.owner,
        "blocked": item.blocked,
        "deleted": item.deleted,
        "mentions": [mention_wire(mention) for mention in item.mentions],
        "mentions_me": item.mentions_me,
    }


def _comment_line(row: dict[str, Any]) -> str:
    if row["deleted"]:
        text = "(deleted)"
    elif row["text"] is None:
        text = "(does not open with this link's key)"
    else:
        text = _terminal_safe(row["text"])
    when = f"{row['created_at'] or '-':<20}  {_moment(row['at_ms']):>8}"
    you = "  (mentions you)" if row["mentions_me"] else ""
    return f"{row['id']:>6}  {when}  {_author(row)}: {text}{you}"


def _author(row: dict[str, Any]) -> str:
    """Who posted, with the server-vouched owner badge where no name can reach it.

    A name is whatever its poster sealed, so it is printed as a JSON string:
    nothing in it can land outside the quotes and pass for ``[owner]``.
    """
    name = row["name"]
    who = _terminal_safe(json.dumps(name, ensure_ascii=False)) if name else "anonymous"
    if row["name_claimed"]:
        who += " (viewer)"
    if row["owner"]:
        who = f"[owner] {who}"
    if row["parent_id"]:
        who = f"re {row['parent_id']}  {who}"
    return who


def _moment(at_ms: int | None) -> str:
    """The video moment as the console's ``formatMoment``: m:ss, or h:mm:ss from an hour."""
    if at_ms is None:
        return "-"
    hours, rest = divmod(at_ms // 1000, 3600)
    minutes, seconds = divmod(rest, 60)
    if hours:
        return f"{hours}:{minutes:02}:{seconds:02}"
    return f"{minutes}:{seconds:02}"


def _moment_line(row: dict[str, Any]) -> str:
    return f"{_moment(row['at_ms']):>8}  {row['emoji']}"


def _reaction_line(row: dict[str, Any]) -> str:
    mine = "  (mine)" if row["mine"] else ""
    return f"{row['emoji']}  {row['count']}{mine}"


# Bidi embedding, override and isolate controls reorder the rest of the line.
_BIDI_CONTROLS = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


def _terminal_safe(value: str) -> str:
    """Comment text and names come from anyone with the link: drop terminal controls.

    Control characters, line and paragraph separators and bidi controls
    become ``?``. Joiners and other format characters stay, so emoji
    sequences and Persian or Indic text still read right.
    """
    flat = value.replace("\r\n", " ").replace("\n", " ")
    return "".join("?" if _unsafe(char) else char for char in flat)


def _unsafe(char: str) -> bool:
    return char in _BIDI_CONTROLS or unicodedata.category(char) in ("Cc", "Zl", "Zp")


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
