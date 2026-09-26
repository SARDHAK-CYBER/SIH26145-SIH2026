"""
API-key authentication shared by the main API and the live sensor.

    STEALTHTAP_API_KEY=<long random string>      # >= 16 chars; docker-compose refuses to start without it
    STEALTHTAP_TENANT_KEYS=acme=<key>,globex=<key>   # optional: one key per tenant (each >= 16 chars)

Every key belongs to a tenant ("default" for STEALTHTAP_API_KEY); the matching tenant is stored on the request
(`request.state.tenant`) and the API scopes stored alerts and uploaded captures to it.

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
import logging
import os
import re
import sys
from urllib.parse import parse_qs

MIN_KEY_LEN = 16
OPEN_PATHS = frozenset({"/health", "/docs", "/openapi.json"} if os.environ.get("STEALTHTAP_OPEN_DOCS") else {"/health"})


def configured_key() -> str | None:
    k = os.environ.get("STEALTHTAP_API_KEY", "").strip()
    return k or None


def tenant_keys() -> dict[str, str]:
    """{key: tenant}. STEALTHTAP_API_KEY -> "default"; STEALTHTAP_TENANT_KEYS="tenant=key,tenant=key"."""
    out: dict[str, str] = {}
    k = configured_key()
    if k:
        out[k] = "default"
    for item in os.environ.get("STEALTHTAP_TENANT_KEYS", "").split(","):
        name, sep, key = item.strip().partition("=")
        if sep and name.strip() and key.strip():
            out[key.strip()] = name.strip()
    return out


def any_key_configured() -> bool:
    return bool(tenant_keys())


def _is_loopback(host: str) -> bool:
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def require_key_for_bind(host: str) -> None:
    """Exit unless the bind is loopback or a strong key is configured."""
    keys = tenant_keys()
    if any(len(k) < MIN_KEY_LEN for k in keys):
        sys.exit(f"an API key is too short (need >= {MIN_KEY_LEN} characters)")
    if not keys and not _is_loopback(host):
        sys.exit(f"refusing to listen on {host} without authentication: set STEALTHTAP_API_KEY "
                 f"(>= {MIN_KEY_LEN} chars) or bind to 127.0.0.1")


class ApiKeyMiddleware:
    def __init__(self, app, key: str | None = None):
        self.app = app
        keys = {key: "default"} if key is not None else tenant_keys()
        self._key = bool(keys) or None
        self._keys = [(k.encode(), t) for k, t in keys.items()]

    def _tenant(self, scope) -> str | None:
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
        found = None
        for k, t in self._keys:                   # every key is compared (no early exit) so timing does not reveal which matched
            if any(hmac.compare_digest(p, k) for p in presented):
                found = t
        return found

    async def __call__(self, scope, receive, send):
        if self._key is None or scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        if scope["type"] == "http" and (scope["method"] == "OPTIONS" or scope["path"] in OPEN_PATHS):
            return await self.app(scope, receive, send)
        tenant = self._tenant(scope)
        if tenant is not None:
            scope.setdefault("state", {})["tenant"] = tenant
            return await self.app(scope, receive, send)
        if scope["type"] == "websocket":
            return await send({"type": "websocket.close", "code": 1008})
        body = b'{"detail":"missing or invalid API key"}'
        await send({"type": "http.response.start", "status": 401, "headers": [
            (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
            (b"www-authenticate", b"Bearer")]})
        await send({"type": "http.response.body", "body": body})


_KEY_IN_URL = re.compile(r"([?&]api_key=)[^&\s\"]+")


class _RedactApiKey(logging.Filter):
    """uvicorn's access log prints the request path including the query string, i.e. `?api_key=...` on SSE/download URLs."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(_KEY_IN_URL.sub(r"\g<1>REDACTED", a) if isinstance(a, str) else a for a in record.args)
        if isinstance(record.msg, str):
            record.msg = _KEY_IN_URL.sub(r"\g<1>REDACTED", record.msg)
        return True


def install(app) -> None:
    """Add auth to a FastAPI app. Call it BEFORE adding CORSMiddleware: the last-added middleware is outermost, and CORS
    must wrap the 401 so browsers can read it."""
    app.add_middleware(ApiKeyMiddleware)
    for name in ("uvicorn.access", "uvicorn"):
        logging.getLogger(name).addFilter(_RedactApiKey())
