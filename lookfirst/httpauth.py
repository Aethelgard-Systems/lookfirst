"""HTTP entry guard (#668 P2): bearer token for the MCP HTTP transport, loopback-only without one.

The gate itself does not know who calls it. Over stdio the client process is the caller. Over HTTP
any local process (or, on a non-loopback address, any host) could call tools. Therefore:
- non-loopback host without ``http.token_file`` → refuse to start;
- with a token every request needs ``Authorization: Bearer <token>`` (constant-time compare), else 401.
"""
from __future__ import annotations

import hmac
import ipaddress
from pathlib import Path

MIN_TOKEN = 32


class HttpAuthError(ValueError):
    pass


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def load_token(path: Path | None) -> bytes | None:
    if path is None:
        return None
    try:
        raw = path.read_text(encoding="utf-8").strip().encode()
    except OSError as e:
        raise HttpAuthError(f"http.token_file not readable: {path} ({e.strerror})") from None
    if len(raw) < MIN_TOKEN:
        raise HttpAuthError(f"http.token_file: token needs at least {MIN_TOKEN} characters")
    return raw


def check_bind(host: str, token: bytes | None) -> None:
    if token is None and not is_loopback(host):
        raise HttpAuthError(f"HTTP on {host!r} needs http.token_file; without a token only loopback (127.0.0.1) is allowed")


def guard(app, token: bytes | None):
    """Wrap an ASGI app; without token the app is returned unchanged (loopback, see check_bind)."""
    if token is None:
        return app
    expected = b"Bearer " + token

    async def wrapped(scope, receive, send):
        if scope["type"] == "http":
            got = dict(scope.get("headers") or []).get(b"authorization", b"")
            if not hmac.compare_digest(got, expected):
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"application/json"), (b"www-authenticate", b"Bearer")]})
                await send({"type": "http.response.body", "body": b'{"error":"unauthorized"}'})
                return
        await app(scope, receive, send)
    return wrapped
