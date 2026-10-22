"""Access-key sign-in against a mocked API: the bodies, and every refusal."""

from __future__ import annotations

import importlib
import json
from typing import Any

import httpx
import pytest
import respx

from hippius_drive import auth, errors
from hippius_drive.crypto import wallet

API = "https://api.example.test"
ABANDON = " ".join(["abandon"] * 11 + ["about"])
SS58 = "5EPCUjPxiHAcNooYipQFWr9NmmXJKpNG5RhcntXwbtUySrgH"
EVM = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
CHALLENGE = "cd" * 32
MESSAGE = f"Please sign this message to verify your ownership: {CHALLENGE}"
sr25519: Any = importlib.import_module("sr25519")


def _mock(verify: httpx.Response | None = None) -> tuple[respx.Route, respx.Route]:
    challenge = respx.post(f"{API}/api/auth/mnemonic/").mock(
        return_value=httpx.Response(
            200, json={"challenge": CHALLENGE, "message": MESSAGE, "expires_in": 300}
        )
    )
    body = {"token": "tok-secret", "user_id": 7, "username": "user_x", "substrate_address": SS58}
    verified = respx.post(f"{API}/api/auth/verify/").mock(
        return_value=verify or httpx.Response(200, json={**body, "is_new": True})
    )
    return challenge, verified


@respx.mock
def test_login_signs_the_challenge_with_both_keys() -> None:
    challenge, verified = _mock()
    session = auth.login(ABANDON, api_url=API)
    assert (session.token, session.account_ss58, session.username, session.is_new) == (
        "tok-secret",
        SS58,
        "user_x",
        True,
    )
    assert json.loads(challenge.calls.last.request.content) == {
        "address": EVM,
        "substrate_address": SS58,
    }
    sent = json.loads(verified.calls.last.request.content)
    assert sent["challenge"] == CHALLENGE
    assert sent["signature"] == wallet.wallet_keys(ABANDON).sign_evm(MESSAGE)
    public = wallet.wallet_keys(ABANDON)._sr25519[0]
    assert sr25519.verify(bytes.fromhex(sent["substrate_signature"][2:]), MESSAGE.encode(), public)
    assert ABANDON not in verified.calls.last.request.content.decode()
    assert verified.calls.last.request.headers["User-Agent"].startswith("hippius-drive/")
    assert "tok-secret" not in repr(session)


@pytest.mark.parametrize(
    ("status", "body", "error"),
    [
        (401, {"error": "Invalid signature", "code": "evm_key_mismatch"}, errors.Unauthorized),
        (403, {"error": "New account registration is currently disabled"}, errors.Forbidden),
        (400, {"error": "Invalid or expired challenge"}, errors.InvalidRequest),
        (502, {}, errors.ServerError),
        (302, {}, errors.InvalidResponse),
    ],
)
@respx.mock
def test_refusals_map_to_typed_errors(
    status: int, body: dict[str, str], error: type[Exception]
) -> None:
    _mock(httpx.Response(status, json=body))
    with pytest.raises(error):
        auth.login(ABANDON, api_url=API)


@respx.mock
def test_a_refusal_keeps_the_apis_code() -> None:
    _mock(httpx.Response(401, json={"error": "Invalid signature", "code": "evm_key_mismatch"}))
    with pytest.raises(errors.Unauthorized) as caught:
        auth.login(ABANDON, api_url=API)
    assert caught.value.code == "evm_key_mismatch"


@respx.mock
def test_a_throttled_sign_in_carries_retry_after() -> None:
    respx.post(f"{API}/api/auth/mnemonic/").mock(
        return_value=httpx.Response(
            429, json={"detail": "slow down"}, headers={"Retry-After": "30"}
        )
    )
    with pytest.raises(errors.RateLimited) as caught:
        auth.login(ABANDON, api_url=API)
    assert caught.value.retry_after == 30


@respx.mock
def test_a_throttle_without_a_usable_retry_after_still_raises() -> None:
    respx.post(f"{API}/api/auth/mnemonic/").mock(
        return_value=httpx.Response(429, text="busy", headers={"Retry-After": "soon"})
    )
    with pytest.raises(errors.RateLimited) as caught:
        auth.login(ABANDON, api_url=API)
    assert caught.value.retry_after is None


@pytest.mark.parametrize(
    "challenge",
    [{"challenge": CHALLENGE}, {"message": MESSAGE}, {"challenge": CHALLENGE, "message": 3}],
)
@respx.mock
def test_a_challenge_without_a_message_is_an_invalid_response(challenge: dict[str, object]) -> None:
    respx.post(f"{API}/api/auth/mnemonic/").mock(return_value=httpx.Response(200, json=challenge))
    with pytest.raises(errors.InvalidResponse, match="message"):
        auth.login(ABANDON, api_url=API)


@pytest.mark.parametrize(
    ("verify", "match"),
    [
        ({"username": "u"}, "no token"),
        ({"token": "t", "substrate_address": "5Other"}, "different account"),
    ],
)
@respx.mock
def test_a_bad_verify_body_is_an_invalid_response(verify: dict[str, str], match: str) -> None:
    _mock(httpx.Response(200, json=verify))
    with pytest.raises(errors.InvalidResponse, match=match):
        auth.login(ABANDON, api_url=API)


@respx.mock
def test_a_non_json_200_is_an_invalid_response() -> None:
    respx.post(f"{API}/api/auth/mnemonic/").mock(return_value=httpx.Response(200, text="<html>"))
    with pytest.raises(errors.InvalidResponse):
        auth.login(ABANDON, api_url=API)


@respx.mock
def test_an_unreachable_api_is_a_transport_error() -> None:
    respx.post(f"{API}/api/auth/mnemonic/").mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(errors.TransportError, match="ConnectError"):
        auth.login(ABANDON, api_url=API)


def test_an_invalid_phrase_fails_before_any_request() -> None:
    with pytest.raises(ValueError, match="BIP-39"):
        auth.login("not a phrase", api_url=API)


@pytest.mark.anyio
@respx.mock
async def test_the_async_login_sends_the_same_requests() -> None:
    challenge, verified = _mock()
    session = await auth.login_async(ABANDON, api_url=API)
    assert session.account_ss58 == SS58
    assert json.loads(challenge.calls.last.request.content)["address"] == EVM
    sent = json.loads(verified.calls.last.request.content)
    assert sent["signature"] == wallet.wallet_keys(ABANDON).sign_evm(MESSAGE)


@pytest.mark.anyio
@respx.mock
async def test_the_async_login_maps_an_unreachable_api() -> None:
    respx.post(f"{API}/api/auth/mnemonic/").mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(errors.TransportError):
        await auth.login_async(ABANDON, api_url=API)
