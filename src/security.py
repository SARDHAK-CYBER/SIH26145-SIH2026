"""
API-key authentication shared by the main API and the live sensor.

    STEALTHTAP_API_KEY=<long random string>      # >= 16 chars; docker-compose refuses to start without it

A request is authorised when it carries the key as `X-API-Key: <key>`, `Authorization: Bearer <key>`, or -- only because the
browser's EventSource cannot set headers -- `?api_key=<key>` on the SSE/download URLs. `/health` and CORS pre-flights
(`OPTIONS`) are open so orchestrators and browsers can probe. Comparison is constant-time.

With no key configured the API stays open (developer convenience on loopback) and `require_key_for_bind()` makes any
non-loopback bind refuse to start, so an open API can never be exposed by accident.

Pure ASGI (not BaseHTTPMiddleware) so Server-Sent-Events streams are not buffered.
"""
from __future__ import annotations

import hmac
import ipaddress
import os
import sys
from urllib.parse import parse_qs

MIN_KEY_LEN = 16
OPEN_PATHS = frozenset({"/health", "/docs", "/openapi.json"} if os.environ.get("STEALTHTAP_OPEN_DOCS") else {"/health"})


def configured_key() -> str | None:
    k = os.environ.get("STEALTHTAP_API_KEY", "").strip()
    return k or None


def _is_loopback(host: str) -> bool:
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def require_key_for_bind(host: str) -> None:
    """Exit unless the bind is loopback or a strong key is configured."""
    key = configured_key()
    if key is not None and len(key) < MIN_KEY_LEN:
        sys.exit(f"STEALTHTAP_API_KEY is too short (need >= {MIN_KEY_LEN} characters)")
    if key is None and not _is_loopback(host):
        sys.exit(f"refusing to listen on {host} without authentication: set STEALTHTAP_API_KEY "
                 f"(>= {MIN_KEY_LEN} chars) or bind to 127.0.0.1")


class ApiKeyMiddleware:
    def __init__(self, app, key: str | None = None):
        self.app = app
        self._key = (key if key is not None else configured_key())
        if self._key is not None:
            self._key = self._key.encode()

    def _authorised(self, scope) -> bool:
        presented: list[bytes] = []
        for name, value in scope.get("headers", ()):
            if name == b"x-api-key":
                presented.append(value.strip())
            elif name == b"authorization" and value[:7].lower() == b"bearer ":
                presented.append(value[7:].strip())
        qs = scope.get("query_string", b"")
        if qs:
            for v in parse_qs(qs.decode("latin-1")).get("api_key", []):
                presented.append(v.encode())
        return any(hmac.compare_digest(p, self._key) for p in presented)

    async def __call__(self, scope, receive, send):
        if self._key is None or scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        if scope["type"] == "http" and (scope["method"] == "OPTIONS" or scope["path"] in OPEN_PATHS):
            return await self.app(scope, receive, send)
        if self._authorised(scope):
            return await self.app(scope, receive, send)
        if scope["type"] == "websocket":
            return await send({"type": "websocket.close", "code": 1008})
        body = b'{"detail":"missing or invalid API key"}'
        await send({"type": "http.response.start", "status": 401, "headers": [
            (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
            (b"www-authenticate", b"Bearer")]})
        await send({"type": "http.response.body", "body": body})


def install(app) -> None:
    """Add auth to a FastAPI app. Call it BEFORE adding CORSMiddleware: the last-added middleware is outermost, and CORS
    must wrap the 401 so browsers can read it."""
    app.add_middleware(ApiKeyMiddleware)
