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
import os
from typing import Any

import src  # noqa: F401  -- installs the scapy/Npcap import guard before scapy loads
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, DNS, DNSQR

from src.flow_orientation import sender_is_originator

try:
    # Native Rust parser (native/stealthtap_core) -- byte-for-byte validated
    # against this file's own logic on 26 real captures via
    # scripts/validate_native_parser.py (55x-540x faster; see native/README.md).
    # `conn`/`dns` come from it; `ssl`/`modbus` aren't ported yet, so this
    # module's own scapy pass still fills those in below when native is used.
    import stealthtap_core as _native
except ImportError:
    _native = None

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
                 "first_ts", "last_ts", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "uid")

    def __init__(self, orig_ip, orig_port, resp_ip, resp_port, proto, ts):
        self.orig_ip, self.orig_port = orig_ip, orig_port
        self.resp_ip, self.resp_port = resp_ip, resp_port
        self.proto = proto
        self.first_ts = self.last_ts = ts
        self.orig_bytes = self.resp_bytes = 0
        self.orig_pkts = self.resp_pkts = 0
        self.uid = _flow_uid(orig_ip, orig_port, resp_ip, resp_port, proto)

    def add(self, src_ip: str, src_port: int, payload_len: int, ts: float) -> None:
        self.last_ts = max(self.last_ts, ts)
        if src_ip == self.orig_ip and src_port == self.orig_port:
            self.orig_bytes += payload_len
            self.orig_pkts += 1
        else:
            self.resp_bytes += payload_len
            self.resp_pkts += 1

    def to_dict(self) -> dict:
        return {
            "uid": self.uid, "ts": self.first_ts,
            "id.orig_h": self.orig_ip, "id.orig_p": self.orig_port,
            "id.resp_h": self.resp_ip, "id.resp_p": self.resp_port,
            "proto": self.proto, "duration": self.last_ts - self.first_ts,
            "orig_bytes": self.orig_bytes, "resp_bytes": self.resp_bytes,
            "orig_pkts": self.orig_pkts, "resp_pkts": self.resp_pkts,
        }


_FORCE_PYTHON_PARSER = os.environ.get("STEALTHTAP_FORCE_PYTHON_PARSER") == "1"


def parse_pcap(path: str, max_packets: int | None = None) -> dict[str, list[dict[str, Any]]]:
    """Returns {'conn': [...], 'dns': [...], 'ssl': [...], 'modbus': [...]}
    -- the same log-type buckets offline_engine.py already dispatches on.

    Uses the native Rust parser (native/stealthtap_core) when it's built --
    validated byte-for-byte equivalent to this function's own conn/dns
    output on 26 real captures (scripts/validate_native_parser.py), 55x-540x
    faster. KNOWN LIMITATION of that fast path: it doesn't extract `ssl`
    (TLS ClientHello / JA4) records yet, so ENG-04 sees nothing on the
    upload path when native parses the file -- disclosed, not silent,
    and already a smaller loss than it sounds: this module's OWN `ssl`
    extraction only ever produced a placeholder, non-real JA4 for uploads
    (see `_placeholder_ja4`'s docstring) since real JA4 needs the live
    path's proper ClientHello parser. Set STEALTHTAP_FORCE_PYTHON_PARSER=1
    to always use the slower, full-fidelity scapy parser instead (e.g. if
    upload-path SSL visibility genuinely matters more than speed for a
    given deployment) or if the native module isn't built for this platform.
    """
    if _native is not None and not _FORCE_PYTHON_PARSER:
        try:
            result = _native.parse_pcap(path, max_packets)
            result["modbus"] = []  # not yet implemented on either path -- Zeek's ICSNPP path covers OT uploads
            return result
        except Exception as exc:  # native failed on this file -- fall back rather than error the upload
            print(f"[pcap_parser] native parser failed ({exc}); falling back to the Python parser")

    flows: dict[frozenset, _Flow] = {}
    dns_records: list[dict] = []
    ssl_records: list[dict] = []

    with PcapReader(path) as packets:
        _parse_packets(packets, flows, dns_records, ssl_records, max_packets)

    return {
        "conn": [f.to_dict() for f in flows.values()],
        "dns": dns_records,
        "ssl": ssl_records,
        "modbus": [],  # Modbus-over-pcap parsing not yet implemented -- OT
                       # PCAPs should still go through Zeek's ICSNPP path
    }


def _parse_packets(packets, flows, dns_records, ssl_records, max_packets) -> None:
    seen = 0
    for pkt in packets:
        seen += 1
        if max_packets is not None and seen > max_packets:
            break
        # IPv4 or IPv6 -- both expose the same .src/.dst string attributes,
        # so everything downstream is address-family-agnostic already.
        # Added after live-testing against this project's own real network
        # traffic found IPv6 was the MAJORITY protocol (76.6% of packets on
        # a real dual-stack Wi-Fi network, measured directly) -- silently
        # restricting to IPv4 silently dropped detection for most real
        # traffic, not an edge case.
        if pkt.haslayer(IP):
            ip = pkt[IP]
        elif pkt.haslayer(IPv6):
            ip = pkt[IPv6]
        else:
            continue
        ts = float(pkt.time)

        # qr == 0 -> a QUERY. Responses echo the question section too; without
        # this filter every answer was re-scored as a fresh query with the
        # resolver recorded as the originator, doubling DNS alerts.
        #
        # UDP or TCP: DNS-over-TCP (RFC 1035 4.2.2) is real, common traffic --
        # e.g. CHAOS-class version.bind/id.server fingerprinting queries,
        # which several real captures in this project's own eval set use --
        # and was silently missed here (UDP-only) even though
        # src/capture/flow_assembler.py's live path already handled it
        # correctly. Found via scripts/validate_native_live_assembler.py.
        dns_l4 = pkt[UDP] if pkt.haslayer(UDP) else (pkt[TCP] if pkt.haslayer(TCP) else None)
        dns_proto = "udp" if pkt.haslayer(UDP) else "tcp"
        if (dns_l4 is not None and pkt.haslayer(DNS) and pkt[DNS].qr == 0
                and pkt[DNS].qdcount and pkt[DNS].qd is not None):
            qname = pkt[DNS].qd.qname.decode(errors="ignore").rstrip(".")
            qtype_name = QTYPE_NAMES.get(pkt[DNS].qd.qtype, str(pkt[DNS].qd.qtype))
            dns_records.append({
                "uid": _flow_uid(ip.src, dns_l4.sport, ip.dst, dns_l4.dport, dns_proto),
                "ts": ts, "id.orig_h": ip.src, "id.orig_p": dns_l4.sport,
                "id.resp_h": ip.dst, "id.resp_p": dns_l4.dport,
                "proto": dns_proto, "query": qname, "qtype_name": qtype_name,
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
            # SYN / port-rank based, NOT "whoever spoke first" -- a capture
            # that starts mid-connection sees the server first (see
            # src/flow_orientation.py).
            flags = int(l4.flags) if proto == "tcp" else None
            if sender_is_originator(proto, l4.sport, l4.dport, flags):
                flows[key] = _Flow(ip.src, l4.sport, ip.dst, l4.dport, proto, ts)
            else:
                flows[key] = _Flow(ip.dst, l4.dport, ip.src, l4.sport, proto, ts)
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
