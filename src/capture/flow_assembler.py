"""
Streaming flow assembler: packets in (one at a time), flow/protocol
records out, in the exact raw-record shape src.flow_mapping.map_record
consumes. This is the live-capture counterpart to pcap_parser.parse_pcap
(which does the same thing in one batch over a file).

Emits immediately: dns, ssl (with a real JA4), modbus, dnp3.
Emits on idle-expiry / flush: conn (bidirectional byte totals + duration).

Deep payload is never inspected beyond what the PS allows -- DNS names,
the TLS ClientHello (for JA4), and OT function codes are all cleartext
protocol metadata, not decrypted content.
"""
from __future__ import annotations

import hashlib
import time
from typing import Any, Iterator, Optional

from src.capture.ja4 import ja4_from_client_hello

QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
               16: "TXT", 28: "AAAA", 33: "SRV", 10: "NULL", 43: "DS", 48: "DNSKEY"}

# Modbus function code -> the exact names ENG-07 / feature_extraction expect.
_MODBUS_FC = {
    0x01: "READ_COILS", 0x02: "READ_DISCRETE_INPUTS", 0x03: "READ_HOLDING_REGISTERS",
    0x04: "READ_INPUT_REGISTERS", 0x05: "WRITE_SINGLE_COIL", 0x06: "WRITE_SINGLE_REGISTER",
    0x07: "READ_EXCEPTION_STATUS", 0x08: "DIAGNOSTICS", 0x0B: "GET_COMM_EVENT_COUNTER",
    0x0F: "WRITE_MULTIPLE_COILS", 0x10: "WRITE_MULTIPLE_REGISTERS", 0x11: "REPORT_SLAVE_ID",
    0x16: "MASK_WRITE_REGISTER", 0x17: "READ_WRITE_MULTIPLE_REGISTERS",
}
# DNP3 application-layer function code -> name (IEEE 1815).
_DNP3_FC = {
    0x00: "CONFIRM", 0x01: "READ", 0x02: "WRITE", 0x03: "SELECT", 0x04: "OPERATE",
    0x05: "DIRECT_OPERATE", 0x06: "DIRECT_OPERATE_NR", 0x07: "IMMED_FREEZE",
    0x0D: "COLD_RESTART", 0x0E: "WARM_RESTART", 0x0F: "INITIALIZE_DATA",
    0x10: "INITIALIZE_APPLICATION", 0x11: "START_APPLICATION", 0x12: "STOP_APPLICATION",
    0x13: "SAVE_CONFIGURATION", 0x14: "ENABLE_UNSOLICITED", 0x15: "DISABLE_UNSOLICITED",
    0x18: "ASSIGN_CLASS", 0x1B: "DELETE_FILE",
}

FLOW_IDLE_TIMEOUT_S = 60.0
FLOW_HARD_TIMEOUT_S = 300.0


def _flow_uid(a_ip: str, a_port: int, b_ip: str, b_port: int, proto: str) -> str:
    raw = f"{a_ip}:{a_port}-{b_ip}:{b_port}-{proto}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def _seg_hash(*parts: Any) -> str:
    return "sha256:" + hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()


class _Flow:
    __slots__ = ("orig_ip", "orig_port", "resp_ip", "resp_port", "proto",
                 "first_ts", "last_ts", "orig_bytes", "resp_bytes", "orig_pkts",
                 "resp_pkts", "uid", "emitted_ssl")

    def __init__(self, o_ip, o_p, r_ip, r_p, proto, ts):
        self.orig_ip, self.orig_port = o_ip, o_p
        self.resp_ip, self.resp_port = r_ip, r_p
        self.proto = proto
        self.first_ts = self.last_ts = ts
        self.orig_bytes = self.resp_bytes = 0
        self.orig_pkts = self.resp_pkts = 0
        self.uid = _flow_uid(o_ip, o_p, r_ip, r_p, proto)
        self.emitted_ssl = False

    def add(self, src_ip, src_port, plen, ts):
        self.last_ts = max(self.last_ts, ts)
        if src_ip == self.orig_ip and src_port == self.orig_port:
            self.orig_bytes += plen
            self.orig_pkts += 1
        else:
            self.resp_bytes += plen
            self.resp_pkts += 1

    def to_conn(self) -> dict:
        return {
            "uid": self.uid, "ts": self.first_ts,
            "id.orig_h": self.orig_ip, "id.orig_p": self.orig_port,
            "id.resp_h": self.resp_ip, "id.resp_p": self.resp_port,
            "proto": self.proto, "duration": max(0.0, self.last_ts - self.first_ts),
            "orig_bytes": self.orig_bytes, "resp_bytes": self.resp_bytes,
            "orig_pkts": self.orig_pkts, "resp_pkts": self.resp_pkts,
            "segment_hash": _seg_hash(self.uid, self.orig_bytes, self.resp_bytes),
        }


class FlowAssembler:
    """Feed scapy packets via process(); collect (log_type, record) tuples."""

    def __init__(self, idle_timeout_s: float = FLOW_IDLE_TIMEOUT_S):
        self._flows: dict[tuple, _Flow] = {}
        self._dirty: set = set()   # flow keys that got new packets since the last snapshot()
        self._idle = idle_timeout_s
        self.stats = {"packets": 0, "non_ip": 0, "flows_seen": 0,
                      "dns": 0, "ssl": 0, "modbus": 0, "dnp3": 0, "conn": 0}

    # ---------------- packet ingest ----------------
    def process(self, pkt) -> list[tuple[str, dict]]:
        self.stats["packets"] += 1
        out: list[tuple[str, dict]] = []
        try:
            from scapy.layers.l2 import Ether
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.layers.inet6 import IPv6
            from scapy.layers.dns import DNS
        except Exception:
            return out

        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if ip is None:
            # Npcap on Windows often hands scapy raw bytes without decoding
            # the DLT_EN10MB link layer ("Unable to guess datalink type
            # linktype=1"). Re-parse as Ethernet before giving up.
            try:
                reparsed = Ether(bytes(pkt))
                ip = reparsed.getlayer(IP) or reparsed.getlayer(IPv6)
                if ip is not None:
                    pkt = reparsed
            except Exception:
                ip = None
        if ip is None:
            self.stats["non_ip"] += 1
            return out
        src_ip, dst_ip = ip.src, ip.dst
        ts = float(getattr(pkt, "time", None) or time.time())

        l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP)
        if l4 is None:
            return out
        proto = "tcp" if l4.name == "TCP" else "udp"
        sport, dport = int(l4.sport), int(l4.dport)
        payload = bytes(l4.payload) if l4.payload else b""

        key = frozenset(((src_ip, sport), (dst_ip, dport))) | {proto}
        flow = self._flows.get(key)
        if flow is None:
            flow = _Flow(src_ip, sport, dst_ip, dport, proto, ts)
            self._flows[key] = flow
            self.stats["flows_seen"] += 1
        flow.add(src_ip, sport, len(payload), ts)
        self._dirty.add(key)

        # ---- DNS (immediate) ----
        if pkt.haslayer(DNS):
            dns = pkt.getlayer(DNS)
            qd = getattr(dns, "qd", None)
            if isinstance(qd, (list, tuple)):
                qd = qd[0] if qd else None
            if getattr(dns, "qr", 0) in (0, None) and qd is not None:
                try:
                    qname = bytes(qd.qname).decode("utf-8", "ignore").rstrip(".")
                    qtype = QTYPE_NAMES.get(int(qd.qtype), str(qd.qtype))
                    out.append(("dns", {
                        "uid": flow.uid, "ts": ts, "id.orig_h": src_ip, "id.orig_p": sport,
                        "id.resp_h": dst_ip, "id.resp_p": dport, "proto": proto,
                        "query": qname, "qtype_name": qtype,
                        "segment_hash": _seg_hash(flow.uid, qname, qtype),
                    }))
                    self.stats["dns"] += 1
                except Exception:
                    pass

        # ---- TLS ClientHello -> JA4 (immediate, once per flow) ----
        if proto == "tcp" and payload[:1] == b"\x16" and not flow.emitted_ssl:
            ja4 = ja4_from_client_hello(payload)
            if ja4:
                flow.emitted_ssl = True
                out.append(("ssl", {
                    "uid": flow.uid, "ts": ts, "id.orig_h": src_ip, "id.orig_p": sport,
                    "id.resp_h": dst_ip, "id.resp_p": dport, "proto": proto,
                    "ja4": ja4, "segment_hash": _seg_hash(flow.uid, ja4),
                }))
                self.stats["ssl"] += 1

        # ---- Modbus / DNP3 (immediate) ----
        if proto == "tcp" and payload:
            rec = self._modbus(payload, src_ip, sport, dst_ip, dport, ts, flow.uid) if 502 in (sport, dport) else None
            if rec is None and 20000 in (sport, dport):
                rec = self._dnp3(payload, src_ip, sport, dst_ip, dport, ts, flow.uid)
            if rec is not None:
                out.append(rec)

        return out

    # ---------------- OT decoders ----------------
    def _modbus(self, p: bytes, s_ip, s_p, d_ip, d_p, ts, uid) -> Optional[tuple[str, dict]]:
        # MBAP: txn(2) proto(2) len(2) unit(1) | PDU: fc(1) ...
        if len(p) < 8 or p[2] != 0x00 or p[3] != 0x00:
            return None
        fc = p[7]
        name = _MODBUS_FC.get(fc)
        if name is None:
            return None
        register = 0
        if fc in (0x05, 0x06, 0x0F, 0x10) and len(p) >= 10:
            register = int.from_bytes(p[8:10], "big")
        self.stats["modbus"] += 1
        return ("modbus", {
            "uid": uid, "ts": ts, "id.orig_h": s_ip, "id.orig_p": s_p,
            "id.resp_h": d_ip, "id.resp_p": d_p, "proto": "tcp",
            "func": name, "register": register,
            "segment_hash": _seg_hash(uid, name, register),
        })

    def _dnp3(self, p: bytes, s_ip, s_p, d_ip, d_p, ts, uid) -> Optional[tuple[str, dict]]:
        # Data-link: 0x05 0x64 len ctrl dst(2) src(2) crc(2) | transport(1) | app: ctrl(1) fc(1)
        if len(p) < 12 or p[0] != 0x05 or p[1] != 0x64:
            return None
        # app layer starts after 10-byte link header + 1 transport byte + 1 app-ctrl byte
        if len(p) < 13:
            return None
        fc = p[12]
        name = _DNP3_FC.get(fc)
        if name is None:
            return None
        self.stats["dnp3"] += 1
        return ("dnp3", {
            "uid": uid, "ts": ts, "id.orig_h": s_ip, "id.orig_p": s_p,
            "id.resp_h": d_ip, "id.resp_p": d_p, "proto": "tcp",
            "fc_request": name, "segment_hash": _seg_hash(uid, name),
        })

    # ---------------- conn lifecycle ----------------
    def snapshot(self, now: Optional[float] = None, limit: int = 4000) -> list[tuple[str, dict]]:
        """A `conn` record for every flow that got NEW packets since the
        last snapshot -- a growing cumulative snapshot, WITHOUT evicting.
        Called on a short cadence (~2 s) so rate/ratio engines (DDoS
        burst, recon fan-out, exfil byte-ratio) see flows evolve in
        near-real-time instead of only when a flow finally goes idle.
        Only dirty flows are returned, so an idle-heavy capture costs
        almost nothing per tick. `limit` bounds the worst case."""
        out: list[tuple[str, dict]] = []
        dirty, self._dirty = self._dirty, set()
        for key in list(dirty)[:limit]:
            f = self._flows.get(key)
            if f is None:
                continue
            rec = f.to_conn()
            rec["_snapshot_ts"] = f.last_ts
            out.append(("conn", rec))
        return out

    def expire(self, now: Optional[float] = None) -> list[tuple[str, dict]]:
        now = now or time.time()
        out: list[tuple[str, dict]] = []
        for key in list(self._flows):
            f = self._flows[key]
            if (now - f.last_ts) >= self._idle or (now - f.first_ts) >= FLOW_HARD_TIMEOUT_S:
                out.append(("conn", f.to_conn()))
                self.stats["conn"] += 1
                del self._flows[key]
        return out

    def flush(self) -> list[tuple[str, dict]]:
        out = [("conn", f.to_conn()) for f in self._flows.values()]
        self.stats["conn"] += len(out)
        self._flows.clear()
        return out

    def active_flows(self) -> int:
        return len(self._flows)
