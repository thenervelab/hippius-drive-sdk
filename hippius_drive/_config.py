"""Where the CLI gets its settings: flags, then environment, then a config file.

Nothing here reads a key. The mnemonic stays in ``enc_mnemonic.json`` and is
only opened when a command actually needs to encrypt or sign.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on the 3.10 matrix leg
    import tomli as tomllib

ENV_TOKEN = "HIPPIUS_TOKEN"  # noqa: S105 - the variable name, not a token
ENV_ACCOUNT = "HIPPIUS_ACCOUNT_SS58"
ENV_SERVER = "HIPPIUS_SERVER_URL"
ENV_MNEMONIC_FILE = "HIPPIUS_MNEMONIC_FILE"
ENV_LABEL = "HIPPIUS_FOLDER_LABEL"
ENV_PASSWORD = "HIPPIUS_PASSWORD"  # noqa: S105 - the variable name, not a password

DEFAULT_LABEL = "default"
CONFIG_DIR = Path.home() / ".config" / "hippius-drive"
CONFIG_PATH = CONFIG_DIR / "config.toml"
DEFAULT_MNEMONIC_PATH = CONFIG_DIR / "enc_mnemonic.json"

_FIELDS = ("token", "account_ss58", "server_url", "mnemonic_file", "label", "password")


class ConfigError(Exception):
    """A setting is missing or the config file cannot be read."""


@dataclass(frozen=True)
class Config:
    """Resolved CLI settings.

    Attributes:
        token: The bearer token the auth service issued.
        account_ss58: The account the token resolves to; the server namespace.
        server_url: A specific server, or None to probe for the first healthy region.
        mnemonic_file: Where the encrypted master mnemonic lives.
        label: Which folder to act on.
        password: The mnemonic-file password, if it came from the environment.
    """

    token: str | None = None
    account_ss58: str | None = None
    server_url: str | None = None
    mnemonic_file: Path = DEFAULT_MNEMONIC_PATH
    label: str = DEFAULT_LABEL
    password: str | None = None

    def require_token(self) -> str:
        """Return the token, or explain how to set it.

        Returns:
            The bearer token.

        Raises:
            ConfigError: If no token was configured.
        """
        if not self.token:
            raise ConfigError(
                f"no API token: pass --token, set {ENV_TOKEN}, or add token to {CONFIG_PATH}"
            )
        return self.token

    def require_account(self) -> str:
        """Return the account address, or explain how to set it.

        The address is not derived from the mnemonic: the server resolves the
        bearer token to an account and refuses any path naming a different one.

        Returns:
            The account SS58 address.

        Raises:
            ConfigError: If no account was configured.
        """
        if not self.account_ss58:
            raise ConfigError(
                f"no account address: pass --account, set {ENV_ACCOUNT}, or add "
                f"account_ss58 to {CONFIG_PATH}. It is the Hippius account your "
                "token belongs to, not something derived from your phrase"
            )
        return self.account_ss58


def _kept(value: Any) -> bool:
    """Drop blank strings so they cannot shadow a lower layer."""
    return not (isinstance(value, str) and not value.strip())


def _from_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("rb") as handle:
            body = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    return {key: value for key, value in body.items() if key in _FIELDS}


def _from_env(environ: dict[str, str]) -> dict[str, Any]:
    mapping = {
        "token": ENV_TOKEN,
        "account_ss58": ENV_ACCOUNT,
        "server_url": ENV_SERVER,
        "mnemonic_file": ENV_MNEMONIC_FILE,
        "label": ENV_LABEL,
        "password": ENV_PASSWORD,
    }
    return {field: environ[var] for field, var in mapping.items() if environ.get(var)}


def load(
    overrides: dict[str, Any] | None = None,
    *,
    environ: dict[str, str] | None = None,
    config_path: Path | None = None,
) -> Config:
    """Resolve settings from flags, then environment, then the config file.

    Args:
        overrides: Values from CLI flags; ``None`` entries are ignored so an
            unset flag does not shadow the environment.
        environ: The environment to read; ``os.environ`` by default.
        config_path: The config file; ``~/.config/hippius-drive/config.toml``
            by default.

    Returns:
        The resolved configuration.

    Raises:
        ConfigError: If the config file exists but cannot be parsed.
    """
    env = environ if environ is not None else dict(os.environ)
    path = config_path if config_path is not None else CONFIG_PATH

    merged: dict[str, Any] = {key: value for key, value in _from_file(path).items() if _kept(value)}
    merged.update({key: value for key, value in _from_env(env).items() if _kept(value)})
    merged.update(
        {
            key: value
            for key, value in (overrides or {}).items()
            if value is not None and key in _FIELDS and _kept(value)
        }
    )

    if "mnemonic_file" in merged:
        merged["mnemonic_file"] = Path(merged["mnemonic_file"]).expanduser()
    return replace(Config(), **merged)
