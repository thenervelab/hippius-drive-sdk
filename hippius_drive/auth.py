"""Sign in to the Hippius API with an access key, no browser.

The same two calls the console's access-key sign-in makes:

1. ``POST {api}/api/auth/mnemonic/`` with both addresses returns a challenge
   message, valid for five minutes and single-use.
2. ``POST {api}/api/auth/verify/`` with an EIP-191 signature (required) and
   an sr25519 signature (sent always; the API can require it) returns the
   account's API token. The first verify creates the account.

The token is the account's one DRF token, shared with its console sessions,
and does not expire. A console logout deletes it: sign in again on a 401.
The phrase never leaves the process; only addresses and signatures are sent.

Needs the ``login`` extra: ``pip install 'hippius-drive[login]'``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from hippius_drive import errors
from hippius_drive._transport import USER_AGENT

DEFAULT_API_URL = "https://api.hippius.com"
_CHALLENGE = "/api/auth/mnemonic/"
_VERIFY = "/api/auth/verify/"
_TIMEOUT = 30.0
_HTTP_OK = 200
_HTTP_BAD_REQUEST = 400
_HTTP_UNAUTHORIZED = 401
_HTTP_FORBIDDEN = 403
_HTTP_TOO_MANY = 429
_HTTP_SERVER_ERROR = 500


@dataclass(frozen=True)
class ApiSession:
    """What a successful sign-in returns. The token stays out of ``repr``.

    Attributes:
        token: The API token: ``Authorization: Token <t>`` on the API,
            ``Bearer <t>`` on Drive.
        account_ss58: The account address. Drive's ``account_ss58``.
        username: The account's username.
        is_new: True when this sign-in created the account.
    """

    token: str = field(repr=False)
    account_ss58: str
    username: str = ""
    is_new: bool = False


def login(phrase: str, *, api_url: str = DEFAULT_API_URL, timeout: float = _TIMEOUT) -> ApiSession:
    """Sign in with an access key and return the account's API token.

    Args:
        phrase: The access key, a BIP-39 phrase. Never sent anywhere.
        api_url: The API origin.
        timeout: Seconds per request.

    Returns:
        The token and the account it belongs to.

    Raises:
        ValueError: If the phrase is not valid BIP-39.
        Unauthorized: If the API refused the signatures (``code`` says why).
        RateLimited: If the API throttled this address; see ``retry_after``.
        DriveError: For any other refusal, and TransportError when the API
            could not be reached.
    """
    from hippius_drive.crypto import wallet  # noqa: PLC0415 - the login extra is optional

    keys = wallet.wallet_keys(phrase)
    with httpx.Client(base_url=api_url, timeout=timeout, headers=_headers()) as http:
        challenge = _parse(
            _send(lambda: http.post("/api/auth/mnemonic/", json=_challenge_body(keys)))
        )
        message = _message(challenge)
        body = _verify_body(keys, challenge, message)
        verified = _parse(_send(lambda: http.post(_VERIFY, json=body)))
    return _session(verified, keys.ss58_address)


async def login_async(
    phrase: str, *, api_url: str = DEFAULT_API_URL, timeout: float = _TIMEOUT
) -> ApiSession:
    """Async twin of :func:`login`."""
    from hippius_drive.crypto import wallet  # noqa: PLC0415 - the login extra is optional

    keys = wallet.wallet_keys(phrase)
    async with httpx.AsyncClient(base_url=api_url, timeout=timeout, headers=_headers()) as http:
        challenge = _parse(
            await _send_async(http.post("/api/auth/mnemonic/", json=_challenge_body(keys)))
        )
        message = _message(challenge)
        body = _verify_body(keys, challenge, message)
        verified = _parse(await _send_async(http.post(_VERIFY, json=body)))
    return _session(verified, keys.ss58_address)


def _headers() -> dict[str, str]:
    # Some default client User-Agents are refused at the edge (403, error 1010).
    return {"User-Agent": USER_AGENT}


def _challenge_body(keys: Any) -> dict[str, str]:
    return {"address": keys.evm_address, "substrate_address": keys.ss58_address}


def _verify_body(keys: Any, challenge: dict[str, Any], message: str) -> dict[str, str]:
    return {
        "address": keys.evm_address,
        "substrate_address": keys.ss58_address,
        "challenge": str(challenge.get("challenge", "")),
        "signature": keys.sign_evm(message),
        "substrate_signature": keys.sign_sr25519(message),
    }


def _message(challenge: dict[str, Any]) -> str:
    message = challenge.get("message")
    if not isinstance(message, str) or not challenge.get("challenge"):
        raise errors.InvalidResponse("the challenge response has no message to sign")
    return message


def _session(body: dict[str, Any], expected_ss58: str) -> ApiSession:
    token = body.get("token")
    if not isinstance(token, str) or not token:
        raise errors.InvalidResponse("the verify response has no token")
    account = body.get("substrate_address") or expected_ss58
    if account != expected_ss58:
        raise errors.InvalidResponse("the API signed in a different account than the access key")
    return ApiSession(
        token=token,
        account_ss58=expected_ss58,
        username=str(body.get("username") or ""),
        is_new=bool(body.get("is_new")),
    )


def _send(call: Any) -> httpx.Response:
    try:
        return call()
    except httpx.HTTPError as exc:
        raise _unreachable(exc) from exc


async def _send_async(pending: Any) -> httpx.Response:
    try:
        return await pending
    except httpx.HTTPError as exc:
        raise _unreachable(exc) from exc


def _unreachable(exc: Exception) -> errors.TransportError:
    return errors.TransportError(f"could not reach the Hippius API: {type(exc).__name__}")


def _parse(response: httpx.Response) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError:
        body = None
    fields = body if isinstance(body, dict) else {}
    if response.status_code == _HTTP_OK and fields:
        return fields
    _raise(response, fields)
    raise AssertionError("unreachable: _raise always raises")  # pragma: no cover


def _raise(response: httpx.Response, fields: dict[str, Any]) -> None:
    status = response.status_code
    message = str(fields.get("error") or fields.get("detail") or "")
    code = str(fields.get("code") or "login_refused")
    if status == _HTTP_TOO_MANY:
        retry = response.headers.get("Retry-After", "")
        raise errors.RateLimited(
            code, message, status, retry_after=int(retry) if retry.isdigit() else None
        )
    if status == _HTTP_UNAUTHORIZED:
        raise errors.Unauthorized(code, message, status)
    if status == _HTTP_FORBIDDEN:
        raise errors.Forbidden(code, message, status)
    if status == _HTTP_BAD_REQUEST:
        raise errors.InvalidRequest(code, message, status)
    if status >= _HTTP_SERVER_ERROR:
        raise errors.ServerError(code, message, status)
    raise errors.InvalidResponse(f"unexpected HTTP {status} from the API", status)
