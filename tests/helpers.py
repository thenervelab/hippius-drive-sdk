"""Shared test helpers."""

from __future__ import annotations

import json
from email.parser import BytesParser
from typing import Any

import httpx


def multipart_parts(request: httpx.Request) -> list[tuple[str, str, bytes]]:
    """Parse a multipart body into ``(field name, content type, payload)``, in order.

    Parsed properly rather than scanned for delimiters: the ciphertext part is
    arbitrary binary and will contain whatever byte you were searching for.
    """
    head = f"Content-Type: {request.headers['content-type']}\r\nMIME-Version: 1.0\r\n\r\n".encode()
    message = BytesParser().parsebytes(head + request.content)
    parts: list[tuple[str, str, bytes]] = []
    for part in message.walk():
        disposition = str(part.get("Content-Disposition", ""))
        if 'name="' not in disposition:
            continue
        name = disposition.split('name="', 1)[1].split('"', 1)[0]
        payload = part.get_payload(decode=True)
        assert isinstance(payload, bytes)
        parts.append((name, part.get_content_type(), payload))
    return parts


def manifest_from(request: httpx.Request) -> dict[str, Any]:
    """Return the manifest an upload carried, whichever request shape it used.

    A single-shot upload puts it in a multipart field; a session upload puts it
    in the create-session JSON body.
    """
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("application/json"):
        return dict(json.loads(request.content)["manifest"])
    for name, _, payload in multipart_parts(request):
        if name == "manifest":
            return dict(json.loads(payload))
    raise AssertionError("no manifest in this request")
