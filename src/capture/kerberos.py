"""
Kerberos KDC replies (AS-REP / TGS-REP) from raw port-88 payloads -- the pure-Python twin of
native/stealthtap_core/src/krb.rs (same fields, same fail-closed rules), used when the native
module isn't built and as an independent cross-check of the Rust parser.

Only cleartext is read: crealm/cname (who asked), ticket.sname (for which service) and
ticket.enc-part.etype (the cipher the ticket is sealed with). Kerberoasting = a TGS ticket for a
service account sealed with RC4; see src/engines/eng11_kerberos.py. Field semantics follow Zeek's
KRB::Info (`client`, `service`, `cipher`, `request_type`).
"""
from __future__ import annotations

from typing import Optional

_CIPHERS = {
    1: "des-cbc-crc", 2: "des-cbc-md4", 3: "des-cbc-md5", 16: "des3-cbc-sha1",
    17: "aes128-cts-hmac-sha1-96", 18: "aes256-cts-hmac-sha1-96",
    19: "aes128-cts-hmac-sha256-128", 20: "aes256-cts-hmac-sha384-192",
    23: "rc4-hmac", 24: "rc4-hmac-exp",
}


def _tlv(b: bytes):
    """(tag, value, rest) of one DER TLV at the start of b, or None."""
    if len(b) < 2:
        return None
    tag = b[0]
    if b[1] & 0x80 == 0:
        length, hdr = b[1], 2
    else:
        n = b[1] & 0x7F
        if n == 0 or n > 4 or len(b) < 2 + n:
            return None
        length, hdr = int.from_bytes(b[2:2 + n], "big"), 2 + n
    if len(b) < hdr + length:
        return None
    return tag, b[hdr:hdr + length], b[hdr + length:]


def _fields(seq_body: bytes) -> dict[int, bytes]:
    out: dict[int, bytes] = {}
    rest = seq_body
    while True:
        t = _tlv(rest)
        if t is None:
            break
        tag, val, rest = t
        if tag & 0xE0 == 0xA0:
            out.setdefault(tag & 0x1F, val)
    return out


def _ascii(b: bytes) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "?" for c in b)


def _principal(v: bytes) -> Optional[list[str]]:
    t = _tlv(v)
    if t is None or t[0] != 0x30:
        return None
    names = _fields(t[1]).get(1)
    if names is None:
        return None
    t2 = _tlv(names)
    if t2 is None or t2[0] != 0x30:
        return None
    out, rest = [], t2[1]
    while True:
        s = _tlv(rest)
        if s is None:
            break
        out.append(_ascii(s[1]))
        rest = s[2]
    return out


def _etype(v: bytes) -> Optional[int]:
    t = _tlv(v)
    if t is None or t[0] != 0x30:
        return None
    e = _fields(t[1]).get(0)
    if e is None:
        return None
    ti = _tlv(e)
    if ti is None or ti[0] != 0x02 or not (1 <= len(ti[1]) <= 4):
        return None
    return int.from_bytes(ti[1], "big", signed=True)


def parse_kdc_reply(payload: bytes, tcp: bool) -> Optional[dict]:
    """payload: the TCP payload (with its 4-byte length prefix) or UDP payload of a packet FROM port 88.
    Returns {request_type, client, service, cipher} or None. A reply split across TCP segments -> None."""
    p = payload
    if tcp:
        if len(p) < 4:
            return None
        length = int.from_bytes(p[:4], "big")
        p = p[4:]
        if length == 0 or len(p) < length:
            return None
        p = p[:length]
    t = _tlv(p)
    if t is None:
        return None
    request_type = {0x6B: "AS", 0x6D: "TGS"}.get(t[0])
    if request_type is None:
        return None
    seq = _tlv(t[1])
    if seq is None or seq[0] != 0x30:
        return None
    fs = _fields(seq[1])
    realm = ""
    if 3 in fs:
        r = _tlv(fs[3])
        realm = _ascii(r[1]) if r else ""
    if 4 not in fs or 5 not in fs:
        return None
    cname = _principal(fs[4])
    if cname is None:
        return None
    tk = _tlv(fs[5])
    if tk is None or tk[0] != 0x61:
        return None
    ts = _tlv(tk[1])
    if ts is None or ts[0] != 0x30:
        return None
    tf = _fields(ts[1])
    if 2 not in tf or 3 not in tf:
        return None
    service = _principal(tf[2])
    et = _etype(tf[3])
    if service is None or et is None:
        return None
    cn = "/".join(cname)
    svc = (service[0].lower() if service else "") + "".join("/" + s for s in service[1:])
    return {
        "request_type": request_type,
        "client": f"{cn}/{realm}" if realm else cn,
        "service": svc,
        "cipher": _CIPHERS.get(et, f"unknown-{et}"),
    }
