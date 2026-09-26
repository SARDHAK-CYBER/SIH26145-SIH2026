"""
Minimal classic-pcap reader that yields (timestamp, raw_frame_bytes) without
building scapy packets -- used by LiveAgent.replay_pcap and the throughput
benchmark so a pcap replay exercises the SAME raw-frame path a real NIC feeds
(see RawFrame in native_flow_assembler.py for why that matters).

Only classic pcap with Ethernet link type (what real NIC capture is). Anything
else (pcapng, cooked/loopback link types) returns None from open_raw() and the
caller falls back to scapy's PcapReader.
"""
from __future__ import annotations

import struct
from typing import Iterator, Optional, Tuple

_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", False), b"\xa1\xb2\xc3\xd4": (">", False),
    b"\x4d\x3c\xb2\xa1": ("<", True), b"\xa1\xb2\x3c\x4d": (">", True),
}
LINKTYPE_ETHERNET = 1


def iter_raw_pcap(path: str) -> Optional[Iterator[Tuple[float, bytes]]]:
    """Generator of (ts, frame) or None if this file isn't classic-pcap Ethernet."""
    f = open(path, "rb")
    gh = f.read(24)
    if len(gh) < 24 or gh[:4] not in _MAGIC:
        f.close()
        return None
    endian, nano = _MAGIC[gh[:4]]
    if struct.unpack(endian + "I", gh[20:24])[0] != LINKTYPE_ETHERNET:
        f.close()
        return None
    div = 1e9 if nano else 1e6
    hdr = struct.Struct(endian + "IIII")

    def gen():
        try:
            while True:
                h = f.read(16)
                if len(h) < 16:
                    return
                sec, frac, incl, _orig = hdr.unpack(h)
                data = f.read(incl)
                if len(data) < incl:
                    return
                yield sec + frac / div, data
        finally:
            f.close()
    return gen()
