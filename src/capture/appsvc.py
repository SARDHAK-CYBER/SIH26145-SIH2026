"""
Application-service attack decoders (plain-text services) -- the pure-Python twin of native/stealthtap_core/src/appsvc.rs.

parse_appsvc(payload, sport, dport) -> (function, detail, code) | None, one TCP payload at a time:
  smtp_vrfy / smtp_expn / smtp_rcpt   client -> server account-enumeration verbs (detail = local part)
  smtp_reject                          server -> client 55x (code = the reply code)
  http_401                             server -> client authentication challenge/refusal
  http_basic                           client request with Basic auth (detail = USER NAME; code 1 = vendor-default credential)
  http_admin_deploy                    POST/PUT to a code-deployment endpoint (Tomcat manager WAR upload, Jenkins script console)
  distcc:<argv0>                       distcc job (code 1 = argv[0] is not a compiler, i.e. remote command execution)
Passwords are never returned: Basic credentials are decoded in memory and only compared with a default-credential list.
"""
from __future__ import annotations

import base64
import binascii
from typing import Optional

SMTP_PORTS = (25, 587, 2525)
DEFAULT_CREDS = frozenset({
    "tomcat:tomcat", "tomcat:s3cret", "tomcat:admin", "admin:tomcat", "admin:admin", "admin:password", "admin:", "admin:1234",
    "admin:12345", "root:root", "root:toor", "root:password", "manager:manager", "role1:role1", "both:tomcat", "guest:guest",
    "cisco:cisco", "user:user", "test:test",
})
COMPILERS = frozenset({"gcc", "g++", "cc", "c++", "cpp", "clang", "clang++", "as", "ld", "cc1", "cc1plus"})
_SMTP_VERBS = ((b"VRFY ", "smtp_vrfy"), (b"EXPN ", "smtp_expn"), (b"RCPT TO:", "smtp_rcpt"))
_HTTP_METHODS = (b"GET", b"POST", b"PUT", b"HEAD", b"DELETE")


def _clean(b: bytes, n: int) -> str:
    s = "".join(ch for ch in b[:n].decode("utf-8", "replace") if ch >= " " and ch != "\x7f")
    return s.strip()


def _distcc(p: bytes) -> Optional[tuple[str, str, int]]:
    if len(p) < 24 or p[:4] != b"DIST" or p[12:16] != b"ARGC":
        return None
    try:
        int(p[4:12], 16)
        argc = int(p[16:24], 16)
    except ValueError:
        return None
    i, args = 24, []
    for _ in range(min(argc, 64)):
        if len(p) < i + 12 or p[i:i + 4] != b"ARGV":
            break
        try:
            n = int(p[i + 4:i + 12], 16)
        except ValueError:
            return None
        if not args and i + 12 + n > len(p):
            return None                      # argv[0] cut off: wait for the rest (segmented sends), never classify a fragment
        args.append(_clean(p[i + 12:i + 12 + n], 160))
        i += 12 + n
        if i >= len(p):
            break
    if not args:
        return None
    argv0 = args[0].rsplit("/", 1)[-1].lower()
    is_compiler = (argv0 in COMPILERS or argv0.endswith(("-gcc", "-g++")) or argv0.startswith(("gcc-", "g++-", "clang-")))
    return (f"distcc:{argv0}", " ".join(args[1:6])[:160], 0 if is_compiler else 1)


def _admin_deploy(method: bytes, path: str) -> bool:
    p = path.split("?", 1)[0].lower()
    return method in (b"POST", b"PUT") and (
        p.startswith(("/manager/html/upload", "/manager/text/deploy", "/manager/html/deploy"))
        or p in ("/manager/deploy", "/script", "/scripttext"))


def _request(p: bytes) -> Optional[tuple[str, str, int]]:
    end = p.find(b"\r\n\r\n")
    head = p[: (end + 2) if end >= 0 else min(len(p), 2048)]
    nl = head.find(b"\n")
    if nl < 0:
        return None
    parts = head[:nl].rstrip(b"\r").split(b" ", 2)
    if len(parts) < 3 or not parts[2].startswith(b"HTTP/1.") or parts[0] not in _HTTP_METHODS:
        return None
    try:
        path = parts[1].decode("ascii")
    except UnicodeDecodeError:
        return None
    auth = None
    for line in head[nl:].split(b"\n"):
        line = line.rstrip(b"\r")
        k, sep, v = line.partition(b":")
        if sep and k.strip().lower() == b"authorization" and k == k.strip():
            auth = v.strip()
            break
    cs = None
    if auth is not None and auth[:6].lower() == b"basic ":
        tok = auth[6:].strip().split(b"=", 1)[0]          # the Rust twin stops at the first '='
        try:
            cs = base64.b64decode(tok + b"=" * (-len(tok) % 4), validate=True).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            cs = None
    default = cs is not None and cs in DEFAULT_CREDS
    if _admin_deploy(parts[0], path):
        # code bit 0: deployment endpoint; bit 1: the same request presented a vendor-default credential
        return ("http_admin_deploy", _clean(path.encode(), 96), 1 | (int(default) << 1))
    if cs is None:
        return None
    return ("http_basic", "".join(c for c in cs.split(":", 1)[0] if c >= " ")[:64], int(default))


def parse_appsvc(p: bytes, sport: int, dport: int) -> Optional[tuple[str, str, int]]:
    if not p:
        return None
    first = p[0]
    if first in b"VvEeRr":
        for verb, name in _SMTP_VERBS:
            if p[:len(verb)].upper() == verb and len(p) < 300 and p.endswith(b"\n"):
                arg = _clean(p[len(verb):], 80)
                return (name, arg.strip("<> ").split("@", 1)[0], 0)
        return None
    if first == 0x35 and sport in SMTP_PORTS and len(p) >= 4 and p[1] == 0x35 and 0x30 <= p[2] <= 0x39 and p[3] in b" -":
        return ("smtp_reject", "", 550 + (p[2] - 0x30))
    if first == 0x44 and p.startswith(b"DIST"):
        return _distcc(p)
    if first == 0x48:                       # 'H'
        if p[:7] == b"HTTP/1." and p[8:12] == b" 401":
            return ("http_401", "", 401)
        if p[:5].upper() == b"HEAD ":
            return _request(p)
        return None
    if first in b"GPD":
        return _request(p)
    return None
