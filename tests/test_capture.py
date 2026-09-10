"""
Live-capture unit tests -- no NIC, no root, no Npcap required. Exercises
JA4 computation, the streaming FlowAssembler, ENG-07's new DNP3 branch,
interface enumeration, and that every capture/API module imports.
"""
import asyncio
import importlib
import struct

import pytest

from src.flow_mapping import map_record


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# --------------------------------------------------------------------------
# module import surface
# --------------------------------------------------------------------------
@pytest.mark.parametrize("mod", [
    "src.capture.interfaces", "src.capture.ja4", "src.capture.flow_assembler",
    "src.capture.backends", "src.capture.live_agent", "src.api.live_capture",
])
def test_capture_modules_import(mod):
    importlib.import_module(mod)


def test_interfaces_enumerate():
    from src.capture.interfaces import list_interfaces
    rows = list_interfaces(include_down=True, include_loopback=True)
    assert isinstance(rows, list) and len(rows) >= 1
    assert all(hasattr(r, "name") and hasattr(r, "capture_name") for r in rows)


def test_capabilities_shape():
    from src.capture.backends import capabilities
    caps = capabilities()
    assert "platform" in caps and "portable_backend" in caps


# --------------------------------------------------------------------------
# JA4 from a hand-built TLS 1.3 ClientHello
# --------------------------------------------------------------------------
def _client_hello() -> bytes:
    ciphers = struct.pack(">HH", 0x1301, 0x1302)
    cs = struct.pack(">H", len(ciphers)) + ciphers
    ext_sni = struct.pack(">HH", 0x0000, 0x0000)                       # server_name present, empty
    sv = b"\x02\x03\x04"                                               # list len 2 -> version 0x0304
    ext_sv = struct.pack(">HH", 0x002B, len(sv)) + sv
    sa = struct.pack(">H", 2) + struct.pack(">H", 0x0403)             # 1 sig alg
    ext_sa = struct.pack(">HH", 0x000D, len(sa)) + sa
    exts = ext_sni + ext_sv + ext_sa
    ext_block = struct.pack(">H", len(exts)) + exts
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + cs + b"\x01\x00" + ext_block
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    rec = b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs
    return rec


def test_ja4_structure():
    from src.capture.ja4 import ja4_from_client_hello
    ja4 = ja4_from_client_hello(_client_hello())
    assert ja4 is not None
    a, b, c = ja4.split("_")
    assert a == "t13d020300", a          # tcp, TLS1.3, SNI present, 02 ciphers, 03 exts, no ALPN
    assert len(b) == 12 and len(c) == 12
    assert ja4_from_client_hello(_client_hello()) == ja4   # deterministic


def test_ja4_rejects_non_clienthello():
    from src.capture.ja4 import ja4_from_client_hello
    assert ja4_from_client_hello(b"\x17\x03\x03\x00\x10rubbish") is None
    assert ja4_from_client_hello(b"") is None


# --------------------------------------------------------------------------
# FlowAssembler with synthetic scapy packets
# --------------------------------------------------------------------------
def test_flow_assembler_dns_and_conn():
    from scapy.layers.inet import IP, UDP
    from scapy.layers.dns import DNS, DNSQR
    from src.capture.flow_assembler import FlowAssembler

    fa = FlowAssembler()
    pkt = IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=40000, dport=53) / \
        DNS(rd=1, qd=DNSQR(qname="kqx3vwzptlmnbrx9.com", qtype="A"))
    recs = fa.process(pkt)
    kinds = {k for k, _ in recs}
    assert "dns" in kinds
    dns_rec = next(r for k, r in recs if k == "dns")
    assert dns_rec["query"] == "kqx3vwzptlmnbrx9.com"

    flushed = fa.flush()
    assert any(k == "conn" for k, _ in flushed)
    conn = next(r for k, r in flushed if k == "conn")
    assert conn["id.orig_h"] == "10.0.0.5" and conn["proto"] == "udp"


def test_flow_assembler_modbus_write():
    from scapy.layers.inet import IP, TCP
    from src.capture.flow_assembler import FlowAssembler

    fa = FlowAssembler()
    # MBAP(txn=1,proto=0,len=6,unit=1) + FC=0x10 WRITE_MULTIPLE_REGISTERS + start reg 0x9C41
    mb = struct_mbap() + b"\x10" + b"\x9c\x41" + b"\x00\x01\x02\x00\x0a"
    pkt = IP(src="10.0.0.9", dst="10.0.0.20") / TCP(sport=50000, dport=502) / mb
    recs = fa.process(pkt)
    mod = next((r for k, r in recs if k == "modbus"), None)
    assert mod is not None and mod["func"] == "WRITE_MULTIPLE_REGISTERS"
    assert mod["register"] == 0x9C41

    flow = map_record(mod, "modbus")
    assert flow["protocol_analyzed"] == "modbus" and flow["modbus_func"] == "WRITE_MULTIPLE_REGISTERS"


def struct_mbap() -> bytes:
    return struct.pack(">HHHB", 1, 0, 6, 1)


def test_flow_assembler_dnp3_operate():
    from scapy.layers.inet import IP, TCP
    from src.capture.flow_assembler import FlowAssembler

    fa = FlowAssembler()
    # link hdr: 05 64 len ctrl dst(2) src(2) crc(2) | transport(1) | app-ctrl(1) | fc(1)=0x04 OPERATE
    dnp3 = b"\x05\x64\x0b\xc4\x01\x00\x02\x00\x00\x00" + b"\xc0" + b"\xc0" + b"\x04"
    pkt = IP(src="10.0.0.9", dst="10.0.0.30") / TCP(sport=50001, dport=20000) / dnp3
    recs = fa.process(pkt)
    d = next((r for k, r in recs if k == "dnp3"), None)
    assert d is not None and d["fc_request"] == "OPERATE"


# --------------------------------------------------------------------------
# ENG-07 DNP3 branch
# --------------------------------------------------------------------------
def test_eng07_dnp3_operate_is_critical():
    from src.engines.eng07_ot_anomaly import OTIndustrialAnomalyDetector
    det = OTIndustrialAnomalyDetector()
    flow = map_record({"uid": "X1", "ts": 1.0, "id.orig_h": "10.0.0.9", "id.resp_h": "10.0.0.30",
                       "id.orig_p": 5, "id.resp_p": 20000, "fc_request": "OPERATE"}, "dnp3")
    a = _run(det.score(flow))
    assert a is not None and a.threat_class == "ICS_UNAUTHORIZED_CONTROL_COMMAND"
    assert a.severity == "CRITICAL"


def test_eng07_dnp3_read_is_benign():
    from src.engines.eng07_ot_anomaly import OTIndustrialAnomalyDetector
    det = OTIndustrialAnomalyDetector()
    flow = map_record({"uid": "X2", "ts": 1.0, "id.orig_h": "10.0.0.9", "id.resp_h": "10.0.0.30",
                       "id.orig_p": 5, "id.resp_p": 20000, "fc_request": "READ"}, "dnp3")
    assert _run(det.score(flow)) is None


# --------------------------------------------------------------------------
# LiveAgent constructs without starting a capture
# --------------------------------------------------------------------------
def test_live_agent_constructs():
    from src.capture.live_agent import LiveAgent
    ag = LiveAgent("nonexistent-iface", bpf="ip")
    st = ag.status()
    assert st["running"] is False and st["interface"] == "nonexistent-iface"
    assert "throughput" in st and "detection_latency" in st


def test_live_agent_phase_split_and_dedup():
    """A mid-flight conn snapshot must NOT run ENG-06 (byte-ratio) -- only
    the completed flow does -- and repeat alerts for the same
    (class, src, dst, discriminator) are suppressed by the cooldown."""
    from src.capture.live_agent import LiveAgent, _DISPATCH_CONN_SNAPSHOT, _DISPATCH_CONN_EXPIRE
    assert "eng06" not in _DISPATCH_CONN_SNAPSHOT           # exfil not scored mid-flight
    assert "eng06" in _DISPATCH_CONN_EXPIRE
    assert "eng01" in _DISPATCH_CONN_SNAPSHOT               # flood rate IS scored mid-flight

    ag = LiveAgent("x", bpf="ip")
    ag._build_engines()
    got = []
    ag.add_sink(got.append)

    exfil_rec = {"uid": "F1", "ts": 1.0, "id.orig_h": "10.0.0.9", "id.orig_p": 5000,
                 "id.resp_h": "9.9.9.9", "id.resp_p": 443, "proto": "tcp",
                 "duration": 4.0, "orig_bytes": 5_000_000, "resp_bytes": 100,
                 "segment_hash": "sha256:x"}
    # snapshot phase -> exfil engine not in the set -> no DATA_EXFILTRATION
    _run(ag._score_conn(exfil_rec, _DISPATCH_CONN_SNAPSHOT))
    assert not any(a["threat_class"] == "DATA_EXFILTRATION" for a in got)
    # expire phase -> fires once
    _run(ag._score_conn(exfil_rec, _DISPATCH_CONN_EXPIRE))
    exfil = [a for a in got if a["threat_class"] == "DATA_EXFILTRATION"]
    assert len(exfil) == 1
    # a second expire of the same flow within the cooldown -> still 1
    _run(ag._score_conn(exfil_rec, _DISPATCH_CONN_EXPIRE))
    assert len([a for a in got if a["threat_class"] == "DATA_EXFILTRATION"]) == 1


def test_forwarder_batches_without_blocking():
    from src.capture.forwarder import HttpAlertForwarder
    fwd = HttpAlertForwarder("http://127.0.0.1:59999", batch=3, flush_s=0.2)  # nothing listening
    for i in range(5):
        fwd({"alert_id": str(i)})
    import time as _t; _t.sleep(0.6)
    fwd.stop()
    assert fwd.dropped >= 3  # POSTs failed fast, alerts accounted for, no exception raised
