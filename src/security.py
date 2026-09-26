"""
API-key authentication shared by the main API and the live sensor.

    STEALTHTAP_API_KEY=<long random string>      # >= 16 chars; docker-compose refuses to start without it
    STEALTHTAP_TENANT_KEYS=acme=<key>,globex/analyst=<key>,plant7/sensor=<key>   # optional: tenant[/role]=key (each >= 16 chars)

Every key belongs to a tenant and a role ("default"/admin for STEALTHTAP_API_KEY; role admin unless written `tenant/role`); the
tenant is stored on the request (`request.state.tenant`) and the API scopes stored alerts and uploaded captures to it. Named users
(src/accounts.py: passwords, login tokens, roles viewer/analyst/sensor/admin) authenticate through the same header. Every request
is role-checked (403), rate-limited per tenant (429, STEALTHTAP_RATE_LIMIT_PER_MIN, default 1200) and written to the audit log.

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

from src import accounts

MIN_KEY_LEN = 16
OPEN_PATHS = frozenset({"/health", "/auth/login", "/docs", "/openapi.json"} if os.environ.get("STEALTHTAP_OPEN_DOCS") else {"/health", "/auth/login"})


def configured_key() -> str | None:
    k = os.environ.get("STEALTHTAP_API_KEY", "").strip()
    return k or None


def tenant_keys() -> dict[str, tuple[str, str]]:
    """{key: (tenant, role)}. STEALTHTAP_API_KEY -> ("default","admin"); STEALTHTAP_TENANT_KEYS="tenant[/role]=key,..."."""
    out: dict[str, tuple[str, str]] = {}
    k = configured_key()
    if k:
        out[k] = ("default", "admin")
    for item in os.environ.get("STEALTHTAP_TENANT_KEYS", "").split(","):
        name, sep, key = item.strip().partition("=")
        if sep and name.strip() and key.strip():
            tenant, _, role = name.strip().partition("/")
            role = role.strip() or "admin"
            if role not in accounts.ROLES:
                sys.exit(f"STEALTHTAP_TENANT_KEYS: unknown role {role!r} (use one of {', '.join(accounts.ROLES)})")
            out[key.strip()] = (tenant.strip(), role)
    return out


def any_key_configured() -> bool:
    return bool(tenant_keys()) or accounts.users().any()


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
    if not keys and not accounts.users().any() and not _is_loopback(host):
        sys.exit(f"refusing to listen on {host} without authentication: set STEALTHTAP_API_KEY "
                 f"(>= {MIN_KEY_LEN} chars) or bind to 127.0.0.1")


class ApiKeyMiddleware:
    """Authenticates (API key or login token), authorises by role, rate-limits per tenant, and audits every request."""

    def __init__(self, app, key: str | None = None):
        self.app = app
        keys = {key: ("default", "admin")} if key is not None else tenant_keys()
        self._keys = [(k.encode(), t, r) for k, (t, r) in keys.items()]
        self._limiter = accounts.RateLimiter(int(os.environ.get("STEALTHTAP_RATE_LIMIT_PER_MIN", "1200")))
        self._enabled = bool(keys) or None            # user accounts are picked up per request (the file can appear later)
        self._explicit = key is not None

    def _identity(self, scope) -> dict | None:
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
        for k, t, r in self._keys:                # every key is compared (no early exit) so timing does not reveal which matched
            if any(hmac.compare_digest(p, k) for p in presented):
                found = {"name": f"key:{t}/{r}", "tenant": t, "role": r}
        if found is None:
            for p in presented:
                if p.startswith(b"st1."):
                    ident = accounts.verify_token(p.decode("latin-1"))
                    if ident:
                        return ident
        return found

    @staticmethod
    def _client(scope) -> str:
        c = scope.get("client")
        xff = next((v.decode("latin-1") for k, v in scope.get("headers", ()) if k == b"x-forwarded-for"), "")
        return accounts.client_ip(c[0] if c else "-", xff)

    @staticmethod
    async def _reply(send, status: int, detail: str, extra: list | None = None) -> None:
        body = ('{"detail":"%s"}' % detail).encode()
        await send({"type": "http.response.start", "status": status, "headers": [
            (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()), *(extra or [])]})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        auth_on = self._enabled or accounts.users().any()
        if not auth_on or scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        path = scope["path"]
        if scope["type"] == "http" and (scope["method"] == "OPTIONS" or path in OPEN_PATHS):
            return await self.app(scope, receive, send)
        ident = self._identity(scope)
        client = self._client(scope)
        if ident is None:
            if scope["type"] == "websocket":
                return await send({"type": "websocket.close", "code": 1008})
            accounts.audit(user="-", tenant="-", role="-", method=scope["method"], path=path, status=401, client=client)
            return await self._reply(send, 401, "missing or invalid credentials", [(b"www-authenticate", b"Bearer")])
        if scope["type"] == "websocket":
            scope.setdefault("state", {}).update(tenant=ident["tenant"], role=ident["role"], user=ident["name"])
            return await self.app(scope, receive, send)
        method = scope["method"]
        if not accounts.allowed(ident["role"], method, path):
            accounts.audit(user=ident["name"], tenant=ident["tenant"], role=ident["role"], method=method, path=path, status=403, client=client)
            return await self._reply(send, 403, f"role '{ident['role']}' may not {method} {path}")
        wait = self._limiter.take(ident["tenant"])
        if wait > 0:
            accounts.audit(user=ident["name"], tenant=ident["tenant"], role=ident["role"], method=method, path=path, status=429, client=client)
            return await self._reply(send, 429, "tenant request rate limit exceeded", [(b"retry-after", str(int(wait) + 1).encode())])
        scope.setdefault("state", {}).update(tenant=ident["tenant"], role=ident["role"], user=ident["name"])
        status_box = [0]

        async def send_wrapped(message):
            if message["type"] == "http.response.start":
                status_box[0] = message["status"]
            await send(message)
        try:
            await self.app(scope, receive, send_wrapped)
        finally:
            accounts.audit(user=ident["name"], tenant=ident["tenant"], role=ident["role"], method=method, path=path,
                           status=status_box[0], client=client)


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
