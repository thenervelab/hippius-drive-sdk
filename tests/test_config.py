import os
import re
from pathlib import Path

import pytest

from hippius_drive import _config
from hippius_drive._config import Config, ConfigError


def write_config(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(body, encoding="utf-8")
    return path


def test_defaults_when_nothing_is_set(tmp_path: Path) -> None:
    cfg = _config.load({}, environ={}, config_path=tmp_path / "missing.toml")
    assert cfg == Config()
    assert cfg.label == "default"


def test_config_file_is_read(tmp_path: Path) -> None:
    path = write_config(tmp_path, 'token = "from-file"\nlabel = "photos"\n')
    cfg = _config.load({}, environ={}, config_path=path)
    assert cfg.token == "from-file"
    assert cfg.label == "photos"


def test_env_overrides_the_file(tmp_path: Path) -> None:
    path = write_config(tmp_path, 'token = "from-file"\n')
    cfg = _config.load({}, environ={"HIPPIUS_TOKEN": "from-env"}, config_path=path)
    assert cfg.token == "from-env"


def test_flags_override_the_env(tmp_path: Path) -> None:
    cfg = _config.load(
        {"token": "from-flag"},
        environ={"HIPPIUS_TOKEN": "from-env"},
        config_path=tmp_path / "missing.toml",
    )
    assert cfg.token == "from-flag"


def test_an_unset_flag_does_not_shadow_the_env(tmp_path: Path) -> None:
    cfg = _config.load(
        {"token": None, "label": "cli"},
        environ={"HIPPIUS_TOKEN": "from-env"},
        config_path=tmp_path / "missing.toml",
    )
    assert cfg.token == "from-env"
    assert cfg.label == "cli"


def test_unknown_file_keys_are_ignored(tmp_path: Path) -> None:
    path = write_config(tmp_path, 'token = "t"\nnot_a_setting = 1\n')
    assert _config.load({}, environ={}, config_path=path).token == "t"


def test_mnemonic_file_is_expanded(tmp_path: Path) -> None:
    cfg = _config.load(
        {}, environ={"HIPPIUS_MNEMONIC_FILE": "~/keys/enc.json"}, config_path=tmp_path / "x.toml"
    )
    assert cfg.mnemonic_file == Path.home() / "keys" / "enc.json"


def test_malformed_config_is_reported_with_its_path(tmp_path: Path) -> None:
    path = write_config(tmp_path, "token = = =")
    # `match` is a regex, and a Windows path is full of backslash escapes.
    with pytest.raises(ConfigError, match=re.escape(str(path))):
        _config.load({}, environ={}, config_path=path)


def test_missing_token_names_the_env_var() -> None:
    with pytest.raises(ConfigError, match="HIPPIUS_TOKEN"):
        Config().require_token()


def test_missing_account_explains_it_is_not_derived() -> None:
    with pytest.raises(ConfigError, match="not something derived from your phrase"):
        Config().require_account()


def test_present_values_are_returned() -> None:
    cfg = Config(token="t", account_ss58="5Grw")
    assert cfg.require_token() == "t"
    assert cfg.require_account() == "5Grw"


def test_empty_env_values_are_treated_as_unset(tmp_path: Path) -> None:
    cfg = _config.load({}, environ={"HIPPIUS_TOKEN": ""}, config_path=tmp_path / "x.toml")
    assert cfg.token is None


def test_password_comes_from_the_environment(tmp_path: Path) -> None:
    cfg = _config.load({}, environ={"HIPPIUS_PASSWORD": "pw"}, config_path=tmp_path / "x.toml")
    assert cfg.password == "pw"


def test_empty_strings_in_the_file_and_flags_are_treated_as_unset(tmp_path: Path) -> None:
    path = write_config(tmp_path, 'token = "from-file"\npassword = ""\n')
    cfg = _config.load({"token": "  "}, environ={}, config_path=path)
    assert cfg.token == "from-file"
    assert cfg.password is None


def test_save_merges_into_the_file_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "conf" / "config.toml"
    path.parent.mkdir()
    path.write_text('label = "photos"\nserver_url = "https://s.example"\n')
    written = _config.save(
        {"token": 'quote"back\\slash', "account_ss58": "5Acct"}, config_path=path
    )
    assert written == path
    cfg = _config.load({}, environ={}, config_path=path)
    assert (cfg.token, cfg.account_ss58, cfg.label) == ('quote"back\\slash', "5Acct", "photos")
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
    assert [p.name for p in path.parent.iterdir()] == ["config.toml"]


def test_save_creates_the_directory(tmp_path: Path) -> None:
    path = tmp_path / "new" / "config.toml"
    _config.save({"token": "t"}, config_path=path)
    assert _config.load({}, environ={}, config_path=path).token == "t"


def test_save_refuses_unknown_keys_and_control_characters(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    with pytest.raises(_config.ConfigError, match="not a config setting"):
        _config.save({"nope": "x"}, config_path=path)
    with pytest.raises(_config.ConfigError, match="control"):
        _config.save({"token": "a\nb"}, config_path=path)
    assert not path.exists()
    assert list(tmp_path.iterdir()) == []


def test_a_failed_write_leaves_no_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_args: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", refuse)
    with pytest.raises(OSError, match="disk full"):
        _config.save({"token": "t"}, config_path=tmp_path / "config.toml")
    assert list(tmp_path.iterdir()) == []
