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
    with pytest.raises(ConfigError, match=str(path)):
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
