"""Fixtures for the live suite.

These tests hit the real Hippius service. They skip cleanly when the
credentials are absent so a fork pull request stays green, and every run uses
a throwaway folder label that is unregistered afterwards, so production never
accumulates test data.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest

from hippius_drive.client import Client
from hippius_drive.identity import Identity

ENV_TOKEN = "HIPPIUS_TEST_TOKEN"
ENV_ACCOUNT = "HIPPIUS_TEST_ACCOUNT_SS58"
ENV_MNEMONIC = "HIPPIUS_TEST_MNEMONIC"
ENV_SERVER = "HIPPIUS_TEST_SERVER_URL"

_REQUIRED = (ENV_TOKEN, ENV_ACCOUNT, ENV_MNEMONIC)

if not all(os.environ.get(name) for name in _REQUIRED):
    pytest.skip(
        "live credentials not set; export " + ", ".join(_REQUIRED),
        allow_module_level=True,
    )


@pytest.fixture(scope="session")
def label() -> str:
    """A folder label unique to this run, so parallel runs cannot collide."""
    return f"sdk-e2e-{uuid.uuid4()}"


@pytest.fixture(scope="session")
def identity(label: str) -> Identity:
    """The identity under test, derived from the test mnemonic."""
    return Identity.from_master(
        os.environ[ENV_MNEMONIC], label, account_ss58=os.environ[ENV_ACCOUNT]
    )


@pytest.fixture(scope="session")
def client(identity: Identity) -> Iterator[Client]:
    """A client on a freshly registered folder, unregistered when the run ends.

    Unregistering is destructive by design: it takes every file in the folder
    with it, which is exactly the cleanup this suite wants.
    """
    with Client(
        token=os.environ[ENV_TOKEN],
        identity=identity,
        server_url=os.environ.get(ENV_SERVER) or None,
    ) as live:
        live.folders.register(device_name="hippius-drive-sdk-e2e")
        try:
            yield live
        finally:
            live.folders.unregister()
