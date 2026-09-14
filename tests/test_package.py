from importlib import metadata

import hippius_drive
from hippius_drive.client import (
    AsyncFileOps,
    AsyncFolderOps,
    AsyncSummaryOps,
    FileOps,
    FolderOps,
    SummaryOps,
)


def test_the_installed_distribution_carries_the_package_version() -> None:
    # hatch reads the version out of _version.py; a drift here means the
    # wheel, the User-Agent and --version would disagree.
    assert hippius_drive.__version__ == metadata.version("hippius-drive")


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
