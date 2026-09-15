import pytest

from hippius_drive import errors
from hippius_drive._wire import parse_envelope


def test_success_unwraps() -> None:
    assert parse_envelope(200, {"Success": {"a": 1}}) == {"a": 1}


def test_success_wins_even_on_an_odd_status() -> None:
    assert parse_envelope(201, {"Success": {"a": 1}}) == {"a": 1}


def test_success_envelope_on_an_error_status_is_invalid() -> None:
    with pytest.raises(errors.InvalidResponse, match="HTTP 409"):
        parse_envelope(409, {"Success": {"a": 1}})


def test_unenveloped_success_passes_through() -> None:
    # /list_folder_entries and /can_upload return the payload directly.
    assert parse_envelope(200, {"relative_paths": []}) == {"relative_paths": []}


def test_error_maps_status_and_code() -> None:
    with pytest.raises(errors.NotFound) as exc:
        parse_envelope(404, {"Error": {"error": "not_found", "message": "nope"}})
    assert exc.value.code == "not_found"
    assert exc.value.message == "nope"
    assert exc.value.status == 404
    assert not exc.value.retryable


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (400, errors.InvalidRequest),
        (401, errors.Unauthorized),
        (403, errors.Forbidden),
        (404, errors.NotFound),
        (413, errors.PayloadTooLarge),
        (429, errors.RateLimited),
        (500, errors.ServerError),
        (502, errors.ServerError),
        (418, errors.DriveError),
    ],
)
def test_status_to_exception(status: int, expected: type[errors.DriveError]) -> None:
    with pytest.raises(expected):
        parse_envelope(status, {"Error": {"error": "x", "message": "m"}})


def test_payload_too_large_is_an_invalid_request() -> None:
    assert issubclass(errors.PayloadTooLarge, errors.InvalidRequest)


def test_conflict_carries_current_revision() -> None:
    body = {
        "Conflict": {
            "error": "conflict",
            "message": "m",
            "current_revision_id": [1] * 32,
            "current_revision_seq": 7,
        }
    }
    with pytest.raises(errors.Conflict) as exc:
        parse_envelope(409, body)
    assert exc.value.current_revision_seq == 7
    assert exc.value.current_revision_id == bytes([1] * 32)
    assert exc.value.status == 409


def test_conflict_without_revision_fields() -> None:
    with pytest.raises(errors.Conflict) as exc:
        parse_envelope(409, {"Conflict": {"error": "conflict", "message": "m"}})
    assert exc.value.current_revision_id is None
    assert exc.value.current_revision_seq is None


def test_flat_402_body() -> None:
    with pytest.raises(errors.QuotaExceeded) as exc:
        parse_envelope(
            402,
            {
                "error": "insufficient_balance",
                "message": "m",
                "balance_cents": 1,
                "required_cents": 5,
            },
        )
    assert exc.value.required_cents == 5
    assert exc.value.balance_cents == 1
    assert exc.value.code == "insufficient_balance"


def test_flat_402_without_cents() -> None:
    with pytest.raises(errors.QuotaExceeded) as exc:
        parse_envelope(402, {"error": "drive_quota_exceeded", "message": "m"})
    assert exc.value.required_cents is None


def test_flat_403_body() -> None:
    with pytest.raises(errors.Forbidden) as exc:
        parse_envelope(403, {"error": "service_account_forbidden", "message": "m"})
    assert exc.value.code == "service_account_forbidden"


def test_5xx_is_retryable() -> None:
    with pytest.raises(errors.ServerError) as exc:
        parse_envelope(500, {"Error": {"error": "database_error", "message": "m"}})
    assert exc.value.retryable


def test_rate_limited_carries_retry_after() -> None:
    with pytest.raises(errors.RateLimited) as exc:
        parse_envelope(429, {"Error": {"error": "session_limit", "message": "m"}}, retry_after=7)
    assert exc.value.retry_after == 7
    assert exc.value.retryable


def test_non_dict_body_on_an_error_status_still_raises() -> None:
    with pytest.raises(errors.ServerError):
        parse_envelope(503, "gateway down")


def test_non_dict_body_on_a_success_status_raises_invalid_response() -> None:
    with pytest.raises(errors.InvalidResponse):
        parse_envelope(200, "not json")


def test_error_status_with_no_code_still_names_the_status() -> None:
    with pytest.raises(errors.NotFound) as exc:
        parse_envelope(404, {})
    assert exc.value.status == 404
    assert exc.value.code == "unknown"


def test_str_includes_status_and_code() -> None:
    with pytest.raises(errors.NotFound) as exc:
        parse_envelope(404, {"Error": {"error": "not_found", "message": "nope"}})
    assert "404" in str(exc.value)
    assert "not_found" in str(exc.value)
    assert "nope" in str(exc.value)


def test_every_error_is_a_drive_error() -> None:
    for name in errors.__all__:
        candidate = getattr(errors, name)
        assert issubclass(candidate, errors.DriveError)


def test_the_rendered_message_carries_the_status_only_when_there_is_one() -> None:
    # The CLI prints str(exc) verbatim, so this is user-facing.
    assert str(errors.NotFound("not_found", "no such file", 404)) == "404 not_found: no such file"
    assert str(errors.TransportError("ConnectError: boom")) == "transport_error: ConnectError: boom"


def test_decrypt_error_is_a_drive_error_with_a_local_code() -> None:
    exc = errors.DecryptError("frame 0 failed authentication")
    assert isinstance(exc, errors.DriveError)
    assert exc.code == "decrypt_error"
    assert exc.status is None
    assert not exc.retryable
    assert "frame 0" in str(exc)
    assert "transport " not in str(exc)


@pytest.mark.parametrize("value", [[1, "x"], [300], [1, None], [-1]])
def test_a_malformed_byte_array_becomes_none_rather_than_raising(value: object) -> None:
    # Byte fields arrive as JSON int arrays. A server sending something else
    # must not crash the conflict path, which is the one place the SDK reads
    # them straight off an error envelope.
    body = {"Conflict": {"error": "conflict", "message": "m", "current_revision_id": value}}
    with pytest.raises(errors.Conflict) as exc:
        parse_envelope(409, body)
    assert exc.value.current_revision_id is None
