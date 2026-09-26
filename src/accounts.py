"""
Accounts for the API and the sensor: named users with hashed passwords, signed login tokens, roles, an audit log, and per-tenant
request limits. Pure standard library.

Users live in `config/users.json` (override STEALTHTAP_USERS; managed with scripts/manage_users.py, never edited by hand):
    {"users": [{"name": "alice", "role": "analyst", "tenant": "acme", "password_hash": "scrypt$..."}]}

Roles (least privilege first):
    viewer   read-only: every GET/HEAD
    analyst  viewer + upload/analyse captures (POST /analyze/*) and score flows (POST /score/*)
    sensor   machine role for a capture sensor: POST /alerts/ingest and /health only
    admin    everything, including starting/stopping capture and network discovery

Login: POST /auth/login {"username","password"} -> {"token","role","tenant","expires"}. The token is an HMAC-SHA256 signed
statement (user, role, tenant, expiry) signed with STEALTHTAP_TOKEN_SECRET (>= 32 chars; without it a random per-process secret is
used, so tokens die with the process). It is presented exactly like an API key (`X-API-Key` / `Authorization: Bearer`).
Passwords: scrypt (N=2^14, r=8, p=1) with a per-user salt; verification is constant-time and burns the same work for unknown
users. Five failed logins for one (address, user) within five minutes lock that pair for five minutes.

Audit log (STEALTHTAP_AUDIT_LOG, default data/audit/audit.jsonl, rotated at 10 MB x 5): one JSON line per request -- time, who
(user name or "key:<tenant>/<role>", never a secret), tenant, role, method, path WITHOUT the query string, status, client address --
plus login successes/failures.
"""
from __future__ import annotations

import base64
import collections
import hashlib
import hmac
import json
import logging
import logging.handlers
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Optional

ROLES = ("viewer", "analyst", "sensor", "admin")
TOKEN_TTL_S = int(os.environ.get("STEALTHTAP_TOKEN_TTL_S", str(8 * 3600)))
_SCRYPT = (2 ** 14, 8, 1)
_secret_lock = threading.Lock()
_secret: Optional[bytes] = None


# ---------------------------------------------------------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    n, r, p = _SCRYPT
    h = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return "scrypt$%d$%d$%d$%s$%s" % (n, r, p, base64.b64encode(salt).decode(), base64.b64encode(h).decode())


def verify_password(password: str, stored: Optional[str]) -> bool:
    """Constant-time; an unknown user (stored=None) still costs one scrypt so timing does not reveal which names exist."""
    try:
        _, n, r, p, salt_b, hash_b = (stored or "scrypt$16384$8$1$AAAAAAAAAAAAAAAAAAAAAA==$" + "A" * 43 + "=").split("$")
        salt, want = base64.b64decode(salt_b), base64.b64decode(hash_b)
        got = hashlib.scrypt(password.encode(), salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(want))
        return hmac.compare_digest(got, want) and stored is not None
    except Exception:
        return False


# ------------------------------------------------------------------------------------------------------------------- users
class Users:
    def __init__(self, path: Optional[str] = None):
        self.path = Path(path or os.environ.get("STEALTHTAP_USERS", "config/users.json"))
        self._mtime, self._users, self._checked = None, {}, 0.0

    def _load(self) -> None:
        now = time.monotonic()
        if now - self._checked < 2.0:
            return
        self._checked = now
        try:
            m = self.path.stat().st_mtime
        except OSError:
            self._mtime, self._users = None, {}
            return
        if m == self._mtime:
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self._users = {u["name"]: u for u in data.get("users", []) if u.get("role") in ROLES and u.get("password_hash")}
        except (OSError, ValueError, KeyError, AttributeError):
            self._users = {}                                   # unreadable file: nobody can log in, keys still work
        self._mtime = m

    def get(self, name: str) -> Optional[dict]:
        self._load()
        return self._users.get(name)

    def any(self) -> bool:
        self._load()
        return bool(self._users)


_users: Optional[Users] = None


def users() -> Users:
    global _users
    if _users is None:
        _users = Users()
    return _users


# ------------------------------------------------------------------------------------------------------------------ tokens
def _token_secret() -> bytes:
    global _secret
    with _secret_lock:
        if _secret is None:
            env = os.environ.get("STEALTHTAP_TOKEN_SECRET", "").strip()
            if env and len(env) < 32:
                raise SystemExit("STEALTHTAP_TOKEN_SECRET must be at least 32 characters")
            _secret = env.encode() if env else secrets.token_bytes(32)
            if not env:
                logging.getLogger("stealthtap.auth").warning("STEALTHTAP_TOKEN_SECRET not set: login tokens are valid only until this process restarts")
        return _secret


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign_token(user: str, role: str, tenant: str, ttl: int = TOKEN_TTL_S) -> tuple[str, int]:
    exp = int(time.time()) + ttl
    body = _b64(json.dumps({"u": user, "r": role, "t": tenant, "e": exp}, separators=(",", ":")).encode())
    sig = _b64(hmac.new(_token_secret(), body.encode(), hashlib.sha256).digest())
    return f"st1.{body}.{sig}", exp


def verify_token(token: str) -> Optional[dict]:
    """{"name","role","tenant"} for a valid, unexpired token whose user still exists with the same role; else None."""
    try:
        ver, body, sig = token.split(".")
        if ver != "st1" or not hmac.compare_digest(_b64(hmac.new(_token_secret(), body.encode(), hashlib.sha256).digest()), sig):
            return None
        d = json.loads(_unb64(body))
        if d["e"] < time.time():
            return None
        u = users().get(d["u"])
        if u is None or u["role"] != d["r"] or u.get("tenant", "default") != d["t"]:   # revoked / changed since login
            return None
        return {"name": d["u"], "role": d["r"], "tenant": d["t"]}
    except Exception:
        return None


# ------------------------------------------------------------------------------------------------------------ client address
import ipaddress as _ip

_TRUSTED = [_ip.ip_network(n) for n in os.environ.get(
    "STEALTHTAP_TRUSTED_PROXIES", "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128").split(",") if n.strip()]


def client_ip(peer: str, forwarded_for: str = "") -> str:
    """The real client behind the TLS proxy: the first X-Forwarded-For hop, but ONLY when the direct peer is a trusted proxy
    (a private/loopback address by default; STEALTHTAP_TRUSTED_PROXIES). Anything else is used as-is, so a remote client cannot
    spoof its address in the audit log or dodge the login lockout by sending its own header."""
    try:
        if forwarded_for and any(_ip.ip_address(peer) in n for n in _TRUSTED):
            first = forwarded_for.split(",")[0].strip()
            _ip.ip_address(first)
            return first
    except ValueError:
        pass
    return peer


# ----------------------------------------------------------------------------------------------------------- login throttle
class LoginThrottle:
    def __init__(self, limit: int = 5, window: float = 300.0):
        self.limit, self.window = limit, window
        self._fails: dict[tuple, list[float]] = collections.defaultdict(list)
        self._lock = threading.Lock()

    def locked(self, key: tuple) -> bool:
        with self._lock:
            now = time.time()
            self._fails[key] = [t for t in self._fails[key] if now - t < self.window]
            return len(self._fails[key]) >= self.limit

    def fail(self, key: tuple) -> None:
        with self._lock:
            self._fails[key].append(time.time())

    def ok(self, key: tuple) -> None:
        with self._lock:
            self._fails.pop(key, None)


throttle = LoginThrottle()


def login(username: str, password: str, client: str) -> Optional[dict]:
    key = (client, username)
    if throttle.locked(key):
        audit(user=username, tenant="-", role="-", method="LOGIN", path="/auth/login", status=429, client=client)
        return {"locked": True}
    u = users().get(username)
    if verify_password(password, u["password_hash"] if u else None):
        throttle.ok(key)
        tenant = u.get("tenant", "default")
        token, exp = sign_token(username, u["role"], tenant)
        audit(user=username, tenant=tenant, role=u["role"], method="LOGIN", path="/auth/login", status=200, client=client)
        return {"token": token, "role": u["role"], "tenant": tenant, "expires": exp, "user": username}
    throttle.fail(key)
    audit(user=username, tenant="-", role="-", method="LOGIN", path="/auth/login", status=401, client=client)
    return None


# ----------------------------------------------------------------------------------------------------------------- roles
def allowed(role: str, method: str, path: str) -> bool:
    m = method.upper()
    if role == "admin":
        return True
    if role == "sensor":
        return (m == "POST" and path == "/alerts/ingest") or (m in ("GET", "HEAD") and path == "/health")
    if m in ("GET", "HEAD", "OPTIONS"):
        return role in ("viewer", "analyst")
    if role == "analyst":
        return m == "POST" and (path.startswith("/analyze/") or path.startswith("/score/"))
    return False


# ------------------------------------------------------------------------------------------------------------------ limits
class RateLimiter:
    """Per-tenant token bucket: `per_minute` sustained, burst = per_minute / 6 (min 20). 0 disables."""

    def __init__(self, per_minute: int):
        self.rate = per_minute / 60.0
        self.cap = max(20.0, per_minute / 6.0)
        self._b: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def take(self, tenant: str) -> float:
        """0.0 if allowed, else seconds to wait."""
        if self.rate <= 0:
            return 0.0
        now = time.monotonic()
        with self._lock:
            tokens, last = self._b.get(tenant, (self.cap, now))
            tokens = min(self.cap, tokens + (now - last) * self.rate)
            if tokens >= 1.0:
                self._b[tenant] = [tokens - 1.0, now]
                return 0.0
            self._b[tenant] = [tokens, now]
            return (1.0 - tokens) / self.rate


# ------------------------------------------------------------------------------------------------------------------ audit
_audit_logger: Optional[logging.Logger] = None


def _audit() -> Optional[logging.Logger]:
    global _audit_logger
    if _audit_logger is None:
        path = os.environ.get("STEALTHTAP_AUDIT_LOG", "data/audit/audit.jsonl")
        if not path or path.lower() == "off":
            return None
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            h = logging.handlers.RotatingFileHandler(path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
            h.setFormatter(logging.Formatter("%(message)s"))
            lg = logging.getLogger("stealthtap.audit")
            lg.propagate = False
            lg.setLevel(logging.INFO)
            lg.addHandler(h)
            _audit_logger = lg
        except OSError:
            return None
    return _audit_logger


def audit(*, user: str, tenant: str, role: str, method: str, path: str, status: int, client: str) -> None:
    lg = _audit()
    if lg is not None:
        lg.info(json.dumps({"t": round(time.time(), 3), "user": user, "tenant": tenant, "role": role, "method": method,
                            "path": path, "status": status, "client": client}, separators=(",", ":")))
