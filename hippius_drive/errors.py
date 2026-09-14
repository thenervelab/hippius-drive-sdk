"""Typed exceptions, one per error the caller would branch on.

Mirrors the catalog in the HCFS public API docs (``docs/public/api/errors.md``).
Every exception keeps the raw ``code`` and ``message`` so an error the SDK has
not been taught about is still legible in logs rather than being flattened.
"""

from __future__ import annotations

__all__ = [
    "Conflict",
    "DecryptError",
    "DriveError",
    "Forbidden",
    "InvalidRequest",
    "InvalidResponse",
    "NotFound",
    "PayloadTooLarge",
    "QuotaExceeded",
    "RateLimited",
    "ServerError",
    "TransportError",
    "Unauthorized",
]


class DriveError(Exception):
    """Base class for everything this SDK raises that a caller should catch.

    Covers service errors and the local failures a client method can hit
    (transport, an unreadable body, a ciphertext that will not authenticate).

    Attributes:
        code: The machine-readable ``error`` string, or ``unknown``.
        message: The server's human-readable explanation.
        status: The HTTP status, or ``None`` when the request never landed
            or the failure was local (decrypt).
        retryable: Whether retrying the same request could succeed.
    """

    retryable = False

    def __init__(self, code: str, message: str, status: int | None = None) -> None:
        """Build the error.

        Args:
            code: The machine-readable ``error`` string.
            message: The server's explanation.
            status: The HTTP status, if the request reached the server.
        """
        rendered = f"{status} {code}: {message}" if status is not None else f"{code}: {message}"
        super().__init__(rendered)
        self.code = code
        self.message = message
        self.status = status


class DecryptError(DriveError):
    """Ciphertext is malformed, truncated, or fails authentication.

    Raised by download before any unauthenticated plaintext is yielded. Not
    retryable: the blob the server returned will fail again.
    """

    def __init__(self, message: str) -> None:
        """Build the error.

        Args:
            message: What was wrong with the blob.
        """
        super().__init__("decrypt_error", message, None)


class TransportError(DriveError):
    """The request never got an HTTP response: DNS, TLS, connect, or timeout."""

    retryable = True

    def __init__(self, message: str) -> None:
        """Build the error.

        Args:
            message: What the HTTP client reported.
        """
        super().__init__("transport_error", message, None)


class InvalidResponse(DriveError):
    """The server answered, but not with something this SDK can parse."""

    def __init__(self, message: str, status: int | None = None) -> None:
        """Build the error.

        Args:
            message: What was wrong with the body.
            status: The HTTP status the body arrived with.
        """
        super().__init__("invalid_response", message, status)


class InvalidRequest(DriveError):
    """400: malformed request, failed validation, or a stale ``revision_seq``."""


class PayloadTooLarge(InvalidRequest):
    """413: a multipart field exceeded its admission cap."""


class Unauthorized(DriveError):
    """401: the bearer token is missing, malformed, or rejected."""


class QuotaExceeded(DriveError):
    """402: the write is over the plan allowance or the account has no credits.

    Attributes:
        balance_cents: Credit balance, when the server reports one.
        required_cents: Credits the write would need, when reported.
    """

    def __init__(
        self,
        code: str,
        message: str,
        status: int | None = None,
        *,
        balance_cents: int | None = None,
        required_cents: int | None = None,
    ) -> None:
        """Build the error.

        Args:
            code: The machine-readable ``error`` string.
            message: The server's explanation.
            status: The HTTP status.
            balance_cents: Credit balance, when reported.
            required_cents: Credits the write would need, when reported.
        """
        super().__init__(code, message, status)
        self.balance_cents = balance_cents
        self.required_cents = required_cents


class Forbidden(DriveError):
    """403: the token is valid but resolves to a different account."""


class NotFound(DriveError):
    """404: no such file, folder, or session for this account."""


class Conflict(DriveError):
    """409: ``base_revision_id`` does not match the server's current revision.

    Expected during sync rather than exceptional: adopt the current revision,
    re-classify, and retry.

    Attributes:
        current_revision_id: The server's current revision, when reported.
        current_revision_seq: The server's current sequence, when reported.
    """

    def __init__(
        self,
        code: str,
        message: str,
        status: int | None = None,
        *,
        current_revision_id: bytes | None = None,
        current_revision_seq: int | None = None,
    ) -> None:
        """Build the error.

        Args:
            code: The machine-readable ``error`` string.
            message: The server's explanation.
            status: The HTTP status.
            current_revision_id: The server's current revision.
            current_revision_seq: The server's current sequence.
        """
        super().__init__(code, message, status)
        self.current_revision_id = current_revision_id
        self.current_revision_seq = current_revision_seq


class RateLimited(DriveError):
    """429: too many live sessions or requests; back off and retry.

    Attributes:
        retry_after: Seconds the server asked the caller to wait, when given.
    """

    retryable = True

    def __init__(
        self,
        code: str,
        message: str,
        status: int | None = None,
        *,
        retry_after: int | None = None,
    ) -> None:
        """Build the error.

        Args:
            code: The machine-readable ``error`` string.
            message: The server's explanation.
            status: The HTTP status.
            retry_after: Seconds to wait, from the ``Retry-After`` header.
        """
        super().__init__(code, message, status)
        self.retry_after = retry_after


class ServerError(DriveError):
    """5xx: a server-side failure that is safe to retry with backoff."""

    retryable = True
