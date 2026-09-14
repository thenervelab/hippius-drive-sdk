import sys
from pathlib import Path

import hippius_drive
from hippius_drive.client import (
    AsyncFileOps,
    AsyncFolderOps,
    AsyncSummaryOps,
    FileOps,
    FolderOps,
    SummaryOps,
)

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

_ROOT = Path(__file__).resolve().parents[1]


def test_version_matches_pyproject() -> None:
    data = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert hippius_drive.__version__ == data["project"]["version"]


def test_public_names_are_imported_from_the_package() -> None:
    assert hippius_drive.Client.__name__ == "Client"
    assert hippius_drive.AsyncClient.__name__ == "AsyncClient"
    assert hippius_drive.Identity.__name__ == "Identity"
    assert issubclass(hippius_drive.DecryptError, hippius_drive.DriveError)
    for name in hippius_drive.__all__:
        assert hasattr(hippius_drive, name)


def _public(cls: type) -> set[str]:
    return {name for name in dir(cls) if not name.startswith("_")}


def test_async_namespaces_mirror_the_sync_surface() -> None:
    assert _public(FileOps) == _public(AsyncFileOps)
    assert _public(FolderOps) == _public(AsyncFolderOps)
    assert _public(SummaryOps) == _public(AsyncSummaryOps)
