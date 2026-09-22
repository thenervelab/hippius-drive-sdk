"""Live share and shared-drive round trips.

File shares skip when that route is not mounted. The shared-drive flow needs a
second account (``HIPPIUS_TEST_TOKEN_2`` and ``HIPPIUS_TEST_ACCOUNT_SS58_2``)
because one account cannot accept its own invite as a second member. The
member phrase is generated in the test: the grant is sealed under it, and the
account address still comes from the environment.
"""

from __future__ import annotations

import os

import pytest

from hippius_drive import Client, FileShareSpec, Identity, InviteSpec, errors
from hippius_drive.crypto import kdf

pytestmark = pytest.mark.e2e

ENV_TOKEN_2 = "HIPPIUS_TEST_TOKEN_2"
ENV_ACCOUNT_2 = "HIPPIUS_TEST_ACCOUNT_SS58_2"
_PAYLOAD = b"hippius-drive share e2e"


def test_file_share_round_trip_and_revoke(client: Client) -> None:
    created = None
    try:
        try:
            created = client.shares.create(
                _PAYLOAD, FileShareSpec("e2e.txt", mime_type="text/plain")
            )
        except errors.NotFound:
            pytest.skip("file shares are not mounted")
        opened = client.shares.open(created.share_url)
        assert opened.data == _PAYLOAD
        assert opened.filename == "e2e.txt"
        client.shares.revoke(created.share_token)
        with pytest.raises(errors.NotFound):
            client.shares.open(created.share_url)
        created = None
    finally:
        if created is not None:
            client.shares.revoke(created.share_token)


@pytest.mark.skipif(
    not os.environ.get(ENV_TOKEN_2) or not os.environ.get(ENV_ACCOUNT_2),
    reason="needs HIPPIUS_TEST_TOKEN_2 and HIPPIUS_TEST_ACCOUNT_SS58_2",
)
def test_shared_drive_invite_accept_and_leave(
    client: Client, identity: Identity, label: str
) -> None:
    member_master = kdf.generate_master_mnemonic()
    folder_phrase = kdf.derive_folder_mnemonic(os.environ["HIPPIUS_TEST_MNEMONIC"], label)
    try:
        created = client.drives.create_invite(InviteSpec(folder_phrase, role="reader"))
    except errors.NotFound:
        pytest.skip("shared drives are not mounted")
    except errors.Forbidden as exc:
        if exc.code == "shared_drives_not_entitled":
            pytest.skip("this account cannot create a shared drive")
        raise

    account = os.environ[ENV_ACCOUNT_2]
    member_identity = Identity.from_master(member_master, "member", account_ss58=account)
    with Client(
        token=os.environ[ENV_TOKEN_2],
        identity=member_identity,
        server_url=client.server_url,
    ) as member:
        accepted = member.drives.accept(created.invite_url, member_master, member_ss58=account)
        assert accepted.owner_ss58 == identity.account_ss58
        assert accepted.folder_hash == identity.folder_hash
        assert accepted.role == "reader"
        _leave_opened_drive(member, member_master, account, identity)


def _leave_opened_drive(member: Client, member_master: str, account: str, owner: Identity) -> None:
    rows = [
        row
        for row in member.drives.memberships(member_master, member_ss58=account)
        if row.owner_ss58 == owner.account_ss58 and row.folder_hash == owner.folder_hash
    ]
    assert len(rows) == 1
    phrase = rows[0].folder_mnemonic
    assert phrase
    joined = Identity.for_shared_drive(
        phrase,
        owner_ss58=rows[0].owner_ss58,
        folder_hash=rows[0].folder_hash,
        role=rows[0].role,
        label=rows[0].display_label,
    )
    with Client(
        token=os.environ[ENV_TOKEN_2], identity=joined, server_url=member.server_url
    ) as drive:
        drive.drives.leave(account)
    remaining = member.drives.memberships(member_master, member_ss58=account)
    assert all(
        row.folder_hash != owner.folder_hash or row.owner_ss58 != owner.account_ss58
        for row in remaining
    )
