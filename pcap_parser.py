"""
Pure-Python pcap parser for the "Upload PCAP" analysis path.

Zeek remains the plan for live capture -- it's purpose-built for that.
For one-shot uploaded-file analysis, parsing directly in Python avoids
needing a Zeek process spun up per upload inside the API container. This
reconstructs BIDIRECTIONAL flow-level records in the exact shape
offline_engine.py already consumes, so the existing engines (eng01-eng08)
work unmodified against upload-derived flows too -- one detection
codebase, multiple ingestion paths (batch Zeek logs, live streaming,
uploaded pcap).
"""
from __future__ import annotations

import hashlib
from typing import Any

from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR

QTYPE_NAMES = {1: "A", 16: "TXT", 28: "AAAA", 10: "NULL", 5: "CNAME"}


def _flow_uid(a_ip: str, a_port: int, b_ip: str, b_port: int, proto: str) -> str:
    raw = f"{a_ip}:{a_port}-{b_ip}:{b_port}-{proto}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def _placeholder_ja4(tls_client_hello_bytes: bytes) -> str:
    """HONEST STUB: a real JA4 fingerprint requires parsing the
    ClientHello's exact cipher suite list and extension list (in order)
    per the JA4 spec (github.com/FoxIO-LLC/ja4). This returns a stable
    hash of the raw handshake bytes as a placeholder -- replace with a
    real JA4 implementation (or rely on Zeek's own, which computes it
    correctly) before trusting ENG04 results from pcap-upload analysis."""
    return "PLACEHOLDER_" + hashlib.sha256(tls_client_hello_bytes).hexdigest()[:24]


class _Flow:
    __slots__ = ("orig_ip", "orig_port", "resp_ip", "resp_port", "proto",
                 "first_ts", "last_ts", "orig_bytes", "resp_bytes", "uid")

    def __init__(self, orig_ip, orig_port, resp_ip, resp_port, proto, ts):
        self.orig_ip, self.orig_port = orig_ip, orig_port
        self.resp_ip, self.resp_port = resp_ip, resp_port
        self.proto = proto
        self.first_ts = self.last_ts = ts
        self.orig_bytes = self.resp_bytes = 0
        self.uid = _flow_uid(orig_ip, orig_port, resp_ip, resp_port, proto)

    def add(self, src_ip: str, src_port: int, payload_len: int, ts: float) -> None:
        self.last_ts = max(self.last_ts, ts)
        if src_ip == self.orig_ip and src_port == self.orig_port:
            self.orig_bytes += payload_len
        else:
            self.resp_bytes += payload_len

    def to_dict(self) -> dict:
        return {
            "uid": self.uid, "ts": self.first_ts,
            "id.orig_h": self.orig_ip, "id.orig_p": self.orig_port,
            "id.resp_h": self.resp_ip, "id.resp_p": self.resp_port,
            "proto": self.proto, "duration": self.last_ts - self.first_ts,
            "orig_bytes": self.orig_bytes, "resp_bytes": self.resp_bytes,
        }


def parse_pcap(path: str) -> dict[str, list[dict[str, Any]]]:
    """Returns {'conn': [...], 'dns': [...], 'ssl': [...], 'modbus': [...]}
    -- the same log-type buckets offline_engine.py already dispatches on."""
    packets = rdpcap(path)

    flows: dict[frozenset, _Flow] = {}
    dns_records: list[dict] = []
    ssl_records: list[dict] = []

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        ip = pkt[IP]
        ts = float(pkt.time)

        if pkt.haslayer(UDP) and pkt.haslayer(DNS) and pkt[DNS].qdcount and pkt[DNS].qd is not None:
            qname = pkt[DNS].qd.qname.decode(errors="ignore").rstrip(".")
            qtype_name = QTYPE_NAMES.get(pkt[DNS].qd.qtype, str(pkt[DNS].qd.qtype))
            dns_records.append({
                "uid": _flow_uid(ip.src, pkt[UDP].sport, ip.dst, pkt[UDP].dport, "udp"),
                "ts": ts, "id.orig_h": ip.src, "id.orig_p": pkt[UDP].sport,
                "id.resp_h": ip.dst, "id.resp_p": pkt[UDP].dport,
                "proto": "udp", "query": qname, "qtype_name": qtype_name,
            })
            continue  # DNS packets aren't also folded into the conn bucket

        if pkt.haslayer(TCP):
            l4, proto = pkt[TCP], "tcp"
        elif pkt.haslayer(UDP):
            l4, proto = pkt[UDP], "udp"
        else:
            continue

        # Canonical, direction-independent key so both halves of a
        # conversation land in the SAME flow record.
        key = frozenset([(ip.src, l4.sport), (ip.dst, l4.dport)]) | {proto}
        if key not in flows:
            # Whichever endpoint we see FIRST for this key becomes "orig" --
            # for TCP this is almost always the SYN sender, since that's
            # necessarily the first packet of the conversation.
            flows[key] = _Flow(ip.src, l4.sport, ip.dst, l4.dport, proto, ts)
        flows[key].add(ip.src, l4.sport, len(bytes(l4.payload)), ts)

        if proto == "tcp":
            raw = bytes(l4.payload)
            if raw[:1] == b"\x16" and len(raw) > 5:  # TLS handshake record header
                ssl_records.append({
                    "uid": flows[key].uid, "ts": ts,
                    "id.orig_h": ip.src, "id.orig_p": l4.sport,
                    "id.resp_h": ip.dst, "id.resp_p": l4.dport, "proto": "tcp",
                    "ja4": _placeholder_ja4(raw),
                })

    return {
        "conn": [f.to_dict() for f in flows.values()],
        "dns": dns_records,
        "ssl": ssl_records,
        "modbus": [],  # Modbus-over-pcap parsing not yet implemented -- OT
                       # PCAPs should still go through Zeek's ICSNPP path
    }
