"""
Real JA4 TLS client fingerprint (FoxIO spec, github.com/FoxIO-LLC/ja4),
computed from a raw TLS ClientHello -- metadata only, no decryption.

This replaces pcap_parser._placeholder_ja4's "PLACEHOLDER_<hash>" stub so
ENG-04 (encrypted-malware JA4 matching) has a real fingerprint to look up
against intel/ja4_threat_intel.json.

JA4 = ja4_a + "_" + ja4_b + "_" + ja4_c
  ja4_a : proto(t/q) + tls_ver(2) + sni(d/i) + cipher_count(2) + ext_count(2) + alpn(2)
  ja4_b : sha256(sorted non-GREASE cipher hex list)[:12]
  ja4_c : sha256(sorted non-GREASE ext hex list minus SNI/ALPN + "_" + sig_algs hex list)[:12]

Returns None when the bytes are not a parseable ClientHello (e.g. TLS
record split across TCP segments) -- the caller then simply omits `ja4`.
"""
from __future__ import annotations

import hashlib
import struct
from typing import Optional

_TLS_VERSIONS = {
    0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
    0x0300: "s3", 0x0002: "s2",
}
_EXT_SNI = 0x0000
_EXT_ALPN = 0x0010
_EXT_SUPPORTED_VERSIONS = 0x002B
_EXT_SIG_ALGS = 0x000D


def _is_grease(v: int) -> bool:
    # GREASE values: 0x0a0a, 0x1a1a, ... 0xfafa
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0x00FF)


def _u16(b: bytes, o: int) -> int:
    return struct.unpack_from(">H", b, o)[0]


def ja4_from_client_hello(payload: bytes, *, quic: bool = False) -> Optional[str]:
    try:
        return _parse(payload, quic)
    except (struct.error, IndexError, ValueError):
        return None


def _parse(payload: bytes, quic: bool) -> Optional[str]:
    if len(payload) < 6:
        return None

    # --- TLS record layer (skip if this is already handshake bytes) ---
    off = 0
    if payload[0] == 0x16:  # handshake record
        rec_len = _u16(payload, 3)
        off = 5
        hs = payload[off:off + rec_len] if rec_len else payload[off:]
    else:
        hs = payload
    if len(hs) < 4 or hs[0] != 0x01:  # ClientHello
        return None

    hs_len = int.from_bytes(hs[1:4], "big")
    body = hs[4:4 + hs_len] if hs_len else hs[4:]
    p = 0

    legacy_version = _u16(body, p); p += 2
    p += 32  # random
    sid_len = body[p]; p += 1 + sid_len

    cs_len = _u16(body, p); p += 2
    ciphers_raw = body[p:p + cs_len]; p += cs_len
    ciphers = [
        _u16(ciphers_raw, i) for i in range(0, len(ciphers_raw), 2)
    ]
    ciphers = [c for c in ciphers if not _is_grease(c)]

    comp_len = body[p]; p += 1 + comp_len

    exts: list[int] = []
    sni_present = False
    alpn_first = "00"
    sig_algs_hex: list[str] = []
    best_version = legacy_version

    if p + 2 <= len(body):
        ext_total = _u16(body, p); p += 2
        end = p + ext_total
        while p + 4 <= end:
            etype = _u16(body, p); esize = _u16(body, p + 2); p += 4
            edata = body[p:p + esize]; p += esize
            if _is_grease(etype):
                continue
            exts.append(etype)
            if etype == _EXT_SNI:
                sni_present = True
            elif etype == _EXT_ALPN and len(edata) >= 4:
                # ALPNProtocolNameList: 2b list len, then 1b str len + str
                first_len = edata[2]
                first = edata[3:3 + first_len]
                if first:
                    alpn_first = (chr(first[0]) + chr(first[-1])) if first[0:1].isalnum() else "99"
            elif etype == _EXT_SUPPORTED_VERSIONS and len(edata) >= 3:
                list_len = edata[0]
                for i in range(1, 1 + list_len, 2):
                    v = _u16(edata, i)
                    if _is_grease(v):
                        continue
                    if v in _TLS_VERSIONS and (best_version not in _TLS_VERSIONS or
                                               int(_TLS_VERSIONS[v]) > int(_TLS_VERSIONS.get(best_version, "0"))):
                        best_version = v
            elif etype == _EXT_SIG_ALGS and len(edata) >= 2:
                sa_len = _u16(edata, 0)
                for i in range(2, 2 + sa_len, 2):
                    sig_algs_hex.append(f"{_u16(edata, i):04x}")

    proto = "q" if quic else "t"
    tls_ver = _TLS_VERSIONS.get(best_version, "00")
    sni_flag = "d" if sni_present else "i"
    c_count = f"{min(len(ciphers), 99):02d}"
    e_count = f"{min(len(exts), 99):02d}"

    ja4_a = f"{proto}{tls_ver}{sni_flag}{c_count}{e_count}{alpn_first}"

    cipher_list = ",".join(f"{c:04x}" for c in sorted(ciphers))
    ja4_b = hashlib.sha256(cipher_list.encode()).hexdigest()[:12] if ciphers else "000000000000"

    ext_for_hash = sorted(e for e in exts if e not in (_EXT_SNI, _EXT_ALPN))
    ext_list = ",".join(f"{e:04x}" for e in ext_for_hash)
    sig_list = ",".join(sig_algs_hex)
    ja4_c_src = f"{ext_list}_{sig_list}"
    ja4_c = hashlib.sha256(ja4_c_src.encode()).hexdigest()[:12] if ext_for_hash else "000000000000"

    return f"{ja4_a}_{ja4_b}_{ja4_c}"
