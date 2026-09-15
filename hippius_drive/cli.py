"""The ``hippius-drive`` command line, built only on the public client surface.

This is the reference example for the library: if a command needs something
the public API cannot express, the API is missing it. Output is plain text,
one record per line, with ``--json`` on the read commands for scripts.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import click

from hippius_drive import __version__, _config, errors
from hippius_drive._config import Config
from hippius_drive.client import Client
from hippius_drive.crypto import kdf, mnemonic_store
from hippius_drive.identity import Identity
from hippius_drive.models import RenameSpec, SearchFilters

FILE_ID_HEX_LEN = 64
"""Length of a hex-encoded path_hash, which is how a file id is spelled."""


@dataclass
class Context:
    """What every command needs: the resolved settings.

    Attributes:
        config: The resolved configuration.
    """

    config: Config

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
        password = cfg.password if cfg.password is not None else _prompt_password()
        try:
            master = mnemonic_store.load(cfg.mnemonic_file, password)
        except mnemonic_store.MnemonicStoreError as exc:
            raise click.ClickException(str(exc)) from exc
        return Identity.from_master(master, cfg.label, account_ss58=account)

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
@click.option("--mnemonic", default=None, help="Import this phrase instead of generating one.")
@click.option("--force", is_flag=True, help="Overwrite an existing mnemonic file.")
@click.pass_obj
def init(obj: Context, mnemonic: str | None, force: bool) -> None:
    """Create or import a master mnemonic and store it encrypted.

    The phrase is printed once. It is the only way to decrypt your files: the
    server never sees it, and nobody can recover it for you.
    """
    path = obj.config.mnemonic_file
    if path.exists() and not force:
        raise click.ClickException(f"{path} already exists; pass --force to replace it")

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
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_obj
def ls(obj: Context, path: str, walk: bool, as_json: bool) -> None:
    """List one directory, or every file in the folder with --all."""
    if path.endswith("/") and not path.startswith("/"):
        path = path.rstrip("/")
    if walk and path:
        raise click.ClickException("ls --all lists the whole folder; omit PATH or drop --all")
    with obj.client() as client:
        if walk:
            rows = [f.model_dump(mode="json") for f in client.files.iter_state()]
            has_more = False
        else:
            result = client.files.browse(path)
            rows = [{"kind": "dir", **f.model_dump(mode="json")} for f in result.folders]
            rows += [{"kind": "file", **f.model_dump(mode="json")} for f in result.files]
            has_more = result.has_more
    _emit(rows, as_json, _ls_line)
    if has_more:
        click.echo("more entries not shown", err=True)


def _ls_line(row: dict[str, Any]) -> str:
    if row.get("kind") == "dir":
        return f"dir   {row['total_bytes']:>12}  {row['name']}/"
    name = row.get("relative_path") or row.get("file_name") or "-"
    return f"file  {row['size_bytes']:>12}  {name}"


@main.command()
@click.argument("local", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("remote")
@click.option("--base-revision", default=None, help="Hex revision this write replaces.")
@click.option("--revision-seq", type=int, default=None, help="Current revision_seq plus one.")
@click.pass_obj
def put(
    obj: Context, local: Path, remote: str, base_revision: str | None, revision_seq: int | None
) -> None:
    """Encrypt and upload LOCAL to the folder-relative path REMOTE."""
    base = bytes.fromhex(base_revision) if base_revision else None
    with obj.client() as client:
        result = client.files.put(local, remote, base_revision_id=base, revision_seq=revision_seq)
        file_id = client.files.file_id(remote)
    click.echo(f"file_id      {file_id}")
    click.echo(f"revision_id  {result.revision_id.hex()}")


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
@click.option("--limit", type=int, default=None, help="Results to return.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_obj
def search(
    obj: Context,
    query: str | None,
    file_type: str | None,
    sort_by: str | None,
    limit: int | None,
    as_json: bool,
) -> None:
    """Search every folder on the account."""
    filters = SearchFilters(q=query, file_type=file_type, sort_by=sort_by)
    with obj.client() as client:
        result = client.files.search(filters, limit=limit)
    rows = [hit.model_dump(mode="json") for hit in result.files]
    _emit(
        rows,
        as_json,
        lambda r: f"{r['size_bytes']:>12}  {r['folder_label'] or '-'}  {r['relative_path'] or '-'}",
    )
    if result.has_more:
        click.echo("more hits not shown; pass --limit", err=True)


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
