"""Sans-I/O wire layer: envelope parsing and request building, no sockets.

Keeping this pure is what lets the sync and async clients share one
implementation and lets the tests pin request shapes without a server.
"""

from __future__ import annotations

from typing import Any

from hippius_drive import errors

BAD_REQUEST = 400
PAYMENT_REQUIRED = 402
CONFLICT = 409
TOO_MANY_REQUESTS = 429
INTERNAL_SERVER_ERROR = 500

_STATUS_ERRORS: dict[int, type[errors.DriveError]] = {
    400: errors.InvalidRequest,
    401: errors.Unauthorized,
    403: errors.Forbidden,
    404: errors.NotFound,
    409: errors.Conflict,
    413: errors.PayloadTooLarge,
    429: errors.RateLimited,
}


def _int_list_to_bytes(value: object) -> bytes | None:
    """Convert a JSON array of ints to bytes; hcfs sends byte fields that way."""
    if not isinstance(value, list):
        return None
    try:
        return bytes(value)
    except (TypeError, ValueError):
        return None


def _optional_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _raise_conflict(fields: dict[str, Any], status: int) -> None:
    raise errors.Conflict(
        str(fields.get("error", "conflict")),
        str(fields.get("message", "")),
        status,
        current_revision_id=_int_list_to_bytes(fields.get("current_revision_id")),
        current_revision_seq=_optional_int(fields.get("current_revision_seq")),
    )


def _raise_for(status: int, fields: dict[str, Any], retry_after: int | None) -> None:
    """Raise the exception that matches ``status``, carrying the server's fields."""
    code = str(fields.get("error", "unknown"))
    message = str(fields.get("message", ""))

    if status == PAYMENT_REQUIRED:
        raise errors.QuotaExceeded(
            code,
            message,
            status,
            balance_cents=_optional_int(fields.get("balance_cents")),
            required_cents=_optional_int(fields.get("required_cents")),
        )
    if status == CONFLICT:
        _raise_conflict(fields, status)
    if status == TOO_MANY_REQUESTS:
        raise errors.RateLimited(code, message, status, retry_after=retry_after)

    fallback = errors.ServerError if status >= INTERNAL_SERVER_ERROR else errors.DriveError
    raise _STATUS_ERRORS.get(status, fallback)(code, message, status)


def parse_envelope(status: int, body: Any, *, retry_after: int | None = None) -> Any:
    """Unwrap a ``NetworkResponse`` body, or raise the matching typed error.

    Handles all three envelope variants plus the endpoints that answer with a
    flat body instead: ``/can_upload``, ``/list_folder_entries``, and the 402
    and some 403 error bodies.

    Args:
        status: The HTTP status code.
        body: The parsed JSON body, or any object if it did not parse.
        retry_after: Seconds from a ``Retry-After`` header, when present.

    Returns:
        The ``Success`` payload, or the flat body for unenveloped endpoints.

    Raises:
        DriveError: The subclass matching the status and envelope variant.
    """
    if isinstance(body, dict):
        if "Success" in body:
            return body["Success"]
        if "Conflict" in body:
            conflict = body["Conflict"]
            _raise_conflict(conflict if isinstance(conflict, dict) else {}, status)
        if "Error" in body:
            error = body["Error"]
            _raise_for(status, error if isinstance(error, dict) else {}, retry_after)

    if status < BAD_REQUEST:
        if isinstance(body, dict):
            return body
        raise errors.InvalidResponse(f"expected a JSON object, got {type(body).__name__}", status)

    _raise_for(status, body if isinstance(body, dict) else {}, retry_after)
    raise AssertionError("unreachable: _raise_for always raises")  # pragma: no cover
