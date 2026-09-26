"""
Wireshark-style single-packet detail: a layer tree (with the byte range each layer
covers, so the UI can highlight it in the hex pane) plus a hex/ASCII dump.

Used by both inspectors -- the live ring (`/capture/packet/{id}`) and uploaded
PCAP files (`/analyze/{analysis_id}/packet/{n}`). Dissection is done with scapy,
on demand and for ONE packet at a time (~0.1-1 ms), never on the capture path.
"""
from __future__ import annotations

import io
import struct
from typing import Any

_MAX_FIELD_CHARS = 200


def _repr(v: Any) -> str:
    if isinstance(v, (bytes, bytearray)):
        b = bytes(v)
        return (b[:48].hex() + (f"… ({len(b)} bytes)" if len(b) > 48 else "")) if b else "(empty)"
    s = str(v)
    return s if len(s) <= _MAX_FIELD_CHARS else s[:_MAX_FIELD_CHARS] + "…"


def hexdump(raw: bytes, width: int = 16) -> list[dict]:
    rows = []
    for off in range(0, len(raw), width):
        chunk = raw[off:off + width]
        rows.append({"off": off,
                     "hex": " ".join(f"{b:02x}" for b in chunk),
                     "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)})
    return rows


_LAYER_MODULES = ("inet", "inet6", "dns", "dhcp", "dhcp6", "netbios", "ntp", "snmp", "llmnr", "smb", "kerberos", "ldap")


def _load_layers() -> None:
    """Scapy only binds Ether->IP->TCP/UDP->DNS... once those layer modules are imported."""
    import importlib
    for m in _LAYER_MODULES:
        try:
            importlib.import_module(f"scapy.layers.{m}")
        except Exception:
            pass


def dissect(raw: bytes, ts: float = 0.0, wire_len: int | None = None) -> dict:
    from scapy.layers.l2 import Ether
    _load_layers()

    layers: list[dict] = []
    try:
        pkt = Ether(raw)
    except Exception as exc:  # malformed beyond scapy's tolerance -- still show the bytes
        return {"ts": ts, "wire_len": wire_len or len(raw), "captured": len(raw), "layers": [],
                "error": f"{type(exc).__name__}: {exc}", "hex": hexdump(raw)}

    off = 0
    p = pkt
    while p is not None and p.__class__.__name__ != "NoPayload":
        try:
            total = len(p)
            inner = len(p.payload) if p.payload.__class__.__name__ != "NoPayload" else 0
            hdr = max(0, total - inner)
        except Exception:
            hdr = 0
        fields = []
        for f in p.fields_desc:
            try:
                val = p.getfieldval(f.name)
                fields.append({"name": f.name, "value": _repr(f.i2repr(p, val))})
            except Exception:
                continue
        layers.append({"name": p.name, "start": off, "end": min(off + hdr, len(raw)), "fields": fields})
        off += hdr
        p = p.payload
    return {"ts": ts, "wire_len": wire_len or len(raw), "captured": len(raw),
            "truncated": bool(wire_len and wire_len > len(raw)),
            "layers": layers, "hex": hexdump(raw)}


def to_pcap_bytes(packets: list[tuple[float, bytes]]) -> bytes:
    """Classic little-endian pcap (Ethernet) from (ts, frame) pairs -- for 'export selection'."""
    out = io.BytesIO()
    out.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
    for ts, frame in packets:
        sec = int(ts)
        out.write(struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(frame), len(frame)))
        out.write(frame)
    return out.getvalue()
