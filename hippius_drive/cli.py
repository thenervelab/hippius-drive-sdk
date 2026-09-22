"""The ``hippius-drive`` command line, built only on the public client surface.

This is the reference example for the library: if a command needs something
the public API cannot express, the API is missing it. Output is plain text,
one record per line, with ``--json`` on the read commands for scripts.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import click

from hippius_drive import FileShareSpec, FolderShareSpec, InviteSpec, __version__, _config, errors
from hippius_drive._config import Config
from hippius_drive.client import Client
from hippius_drive.crypto import kdf, mnemonic_store
from hippius_drive.identity import Identity
from hippius_drive.models import RenameSpec, SearchFilters

FILE_ID_HEX_LEN = 64
"""Length of a hex-encoded path_hash, which is how a file id is spelled."""

_CONSOLE = "https://console.hippius.com"
"""Console origin a minted link uses unless ``--console`` says otherwise."""

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
@click.argument("url")
@click.pass_obj
def invite_accept(obj: Context, url: str) -> None:
    """Join a drive. Prints the drive id and role."""
    account = _account(obj)
    with obj.client() as client:
        accepted = client.drives.accept(url, obj.master(), member_ss58=account)
    click.echo(f"owner        {accepted.owner_ss58}")
    click.echo(f"folder_hash  {accepted.folder_hash}")
    click.echo(f"role         {accepted.role}")


@main.group(invoke_without_command=True)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def drives(ctx: click.Context, as_json: bool) -> None:
    """List drives this account has joined."""
    if ctx.invoked_subcommand is not None:
        return
    _print_drives(ctx.obj, as_json)


@drives.command("leave")
@click.argument("owner_ss58")
@click.argument("folder_hash")
@click.pass_obj
def drives_leave(obj: Context, owner_ss58: str, folder_hash: str) -> None:
    """Leave a joined drive. OWNER_SS58 and FOLDER_HASH come from ``drives``."""
    account = _account(obj)
    with obj.client() as client:
        rows = client.drives.memberships(obj.master(), member_ss58=account)
    phrase, owner, folder, role, label = _joined(rows, owner_ss58, folder_hash)
    identity = Identity.for_shared_drive(
        phrase,
        owner_ss58=owner,
        folder_hash=folder,
        role=role,
        label=label,
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
    return f"{row['role']:<8}  {row['owner_ss58']}  {row['folder_hash']}  {label}{frozen}"


def _joined(rows: Sequence[Any], owner: str, folder: str) -> tuple[str, str, str, str, str]:
    """Return the phrase, owner, hash, role, and label for one joined drive."""
    for row in rows:
        if row.owner_ss58 != owner or row.folder_hash != folder:
            continue
        phrase = row.folder_mnemonic
        if not isinstance(phrase, str) or not phrase:
            raise click.ClickException("this drive has no grant; it cannot be opened")
        label = row.display_label if isinstance(row.display_label, str) else ""
        role = row.role if isinstance(row.role, str) else ""
        return phrase, owner, folder, role, label
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
