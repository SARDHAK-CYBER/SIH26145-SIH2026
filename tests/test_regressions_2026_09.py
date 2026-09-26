"""
Regression tests for the bugs found and fixed during the 2026-09 real-traffic
validation pass. Each test pins a specific failure that was observed on real
data, so it cannot silently come back:

  * native expire(): O(k*n) shift_remove -> single order-preserving retain()
  * IPv6 was silently dropped by both native parsers (76.6% of a real network)
  * native JA4 returned a WRONG fingerprint for a ClientHello split across
    TCP segments (Python failed closed; Rust failed open)
  * OnlineBaseline.warm_start compared file age instead of the batch's span
  * ENG-01 Redis-path pipeline consolidation must not change any alert
  * Kerberos requesting-user / HTTP response-size / file-type evidence
"""
from __future__ import annotations

import asyncio
import time

import pytest

scapy = pytest.importorskip("scapy")
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw

core = pytest.importorskip("stealthtap_core")


def _tcp(src, dst, sport, dport, ts, payload=b"", flags="PA"):
    p = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags) / Raw(payload)
    p.time = ts
    return p


# ------------------------------------------------------------------ expire()
def test_expire_returns_flows_in_first_seen_order_and_keeps_live_ones():
    a = core.LiveFlowAssembler(60.0)
    # 200 flows created in index order, INTERLEAVING stale (even) and fresh
    # (odd) ones, so a retain-based eviction has to preserve order across
    # kept entries, not just return a contiguous prefix.
    for i in range(200):
        ts = 1000.0 if i % 2 == 0 else 1450.0
        a.process(ts, bytes(_tcp("10.0.0.1", "10.0.0.2", 40000 + i, 80, ts, b"x", "S")))
    out = a.expire(now=1500.0)  # even: idle 500s (>60) -> evicted; odd: idle 50s, age 50s -> kept
    ports = [r[1]["id.orig_p"] for r in out]
    assert ports == [40000 + i for i in range(0, 200, 2)], "expire() must keep first-seen (insertion) order"
    assert a.active_flows() == 100
    assert [r[1]["id.orig_p"] for r in a.flush()] == [40000 + i for i in range(1, 200, 2)]


def test_expire_scales_linearly_not_quadratically():
    a = core.LiveFlowAssembler(60.0)
    for i in range(6000):
        a.process(1000.0, bytes(_tcp("10.1.0.1", "10.1.0.2", 1024 + (i % 60000), 80, 1000.0, b"x", "S")))
    t = time.perf_counter()
    out = a.expire(now=1e12)
    dt = time.perf_counter() - t
    assert len(out) > 5000
    assert dt < 0.5, f"expire() of {len(out)} flows took {dt:.2f}s -- O(k*n) shift_remove regression?"


# ------------------------------------------------------------------ IPv6
def _dns_v6(src, dst):
    p = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IPv6(src=src, dst=dst) / UDP(sport=54321, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
    p.time = 1000.0
    return p


@pytest.mark.parametrize("dst", ["2606:4700:4700::1111", "2001:4860:4860::8888", "fe80::1", "2001:db8:0:1:2:3:4:5"])
def test_ipv6_native_matches_python_including_flow_uid(dst):
    from src.capture.flow_assembler import FlowAssembler
    pkt = _dns_v6("2402:3a80:80f:922f:c509:29e4:4c4a:5cd3", dst)
    py = FlowAssembler().process(pkt)
    rs = core.LiveFlowAssembler(60.0).process(1000.0, bytes(pkt))
    assert len(py) == len(rs) == 1
    (pt, pr), (rt, rr) = py[0], rs[0]
    assert pt == rt == "dns"
    for k in ("uid", "id.orig_h", "id.resp_h", "id.orig_p", "id.resp_p", "query", "qtype_name"):
        assert pr[k] == rr[k], k


def test_ipv6_extension_headers_are_walked():
    from scapy.layers.inet6 import IPv6ExtHdrHopByHop
    p = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IPv6(src="2001:db8::1", dst="2001:db8::2") / IPv6ExtHdrHopByHop() / UDP(sport=5000, dport=53) / DNS(rd=1, qd=DNSQR(qname="ext.example.org"))
    rs = core.LiveFlowAssembler(60.0).process(1.0, bytes(p))
    assert [t for t, _ in rs] == ["dns"] and rs[0][1]["query"] == "ext.example.org"


def test_ipv4_still_works():
    p = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="10.0.0.9", dst="10.0.0.53") / UDP(sport=5555, dport=53) / DNS(rd=1, qd=DNSQR(qname="v4.example.org"))
    rs = core.LiveFlowAssembler(60.0).process(1.0, bytes(p))
    assert rs and rs[0][1]["id.orig_h"] == "10.0.0.9"


# ------------------------------------------------------------------ JA4
def _client_hello(n_extra_ext: int = 6) -> bytes:
    def ext(t, body):
        return t.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body
    host = b"example.org"
    sni = ext(0, (len(host) + 3).to_bytes(2, "big") + b"\x00" + len(host).to_bytes(2, "big") + host)
    alpn = ext(16, b"\x00\x0c\x02h2\x08http/1.1")
    sv = ext(43, b"\x04\x03\x04\x03\x03")
    sig = ext(13, b"\x00\x08\x04\x03\x08\x04\x04\x01\x05\x03")
    extra = b"".join(ext(0x0100 + i, b"\x00" * 24) for i in range(n_extra_ext))
    exts = sni + alpn + sv + sig + extra
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x06\x13\x01\x13\x02\xc0\x2b" + b"\x01\x00"
            + len(exts).to_bytes(2, "big") + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def test_ja4_complete_clienthello_native_equals_python():
    from src.capture.flow_assembler import FlowAssembler
    payload = _client_hello()
    pkt = _tcp("10.0.0.5", "93.184.216.34", 50000, 443, 1.0, payload)
    py = FlowAssembler().process(pkt)
    rs = core.LiveFlowAssembler(60.0).process(1.0, bytes(pkt))
    py_ssl = [r for t, r in py if t == "ssl"]
    rs_ssl = [r for t, r in rs if t == "ssl"]
    assert py_ssl and rs_ssl and py_ssl[0]["ja4"] == rs_ssl[0]["ja4"]


@pytest.mark.parametrize("cut", [5, 17, 41, 80])
def test_ja4_truncated_clienthello_fails_closed_in_native(cut):
    """A ClientHello split across TCP segments (only the first segment is
    visible) must yield NO fingerprint, never a wrong one -- exact-match
    threat-intel lookups make a wrong JA4 worse than none."""
    from src.capture.flow_assembler import FlowAssembler
    payload = _client_hello()
    truncated = payload[: len(payload) - cut]  # record header still claims the full length
    pkt = _tcp("10.0.0.5", "93.184.216.34", 50001, 443, 1.0, truncated)
    py = [r for t, r in FlowAssembler().process(pkt) if t == "ssl"]
    rs = [r for t, r in core.LiveFlowAssembler(60.0).process(1.0, bytes(pkt)) if t == "ssl"]
    assert py == [] and rs == [], f"truncated ClientHello (-{cut}B) produced py={py} native={rs}"


# ------------------------------------------------------------------ HTTP (live)
def test_live_http_request_parsed_identically_native_and_python():
    from src.capture.flow_assembler import FlowAssembler
    req = b"POST /upload/abc HTTP/1.1\r\nHost: x\r\nUser-Agent: python-requests/2.31\r\nContent-Length: 1234\r\n\r\n"
    pkt = _tcp("10.0.0.5", "1.2.3.4", 50002, 8080, 1.0, req)
    py = [r for t, r in FlowAssembler().process(pkt) if t == "http"]
    rs = [r for t, r in core.LiveFlowAssembler(60.0).process(1.0, bytes(pkt)) if t == "http"]
    assert py and rs
    for k in ("method", "uri", "user_agent", "request_body_len", "uid"):
        assert py[0][k] == rs[0][k] and py[0][k] not in (None, "")


# ------------------------------------------------------------------ baseline warm start
def test_baseline_warm_start_uses_batch_span_not_file_age():
    from src.inference.online_baseline import OnlineBaseline

    def rec(ts, i=0):
        return {"ts": ts, "proto": "tcp", "id.resp_p": 443, "orig_bytes": 500 + i, "orig_pkts": 5,
                "duration": 1.2, "resp_bytes": 2000, "resp_pkts": 8}
    old = time.time() - 100_000_000  # a years-old file

    narrow = OnlineBaseline(learn_min_flows=1500, learn_min_seconds=600.0)
    narrow.warm_start([rec(old + i * 0.001, i) for i in range(1600)])      # spans 1.6s of real time
    assert narrow.status()["phase"] == "learning", "an old-but-narrow pcap must NOT trivially arm"

    wide = OnlineBaseline(learn_min_flows=1500, learn_min_seconds=600.0)
    wide.warm_start([rec(old + i * 0.5, i) for i in range(1600)])          # spans 800s
    assert wide.status()["phase"] == "armed"

    few = OnlineBaseline(learn_min_flows=1500, learn_min_seconds=600.0)
    few.warm_start([rec(old + i * 10, i) for i in range(100)])
    assert few.status()["phase"] == "learning"


# ------------------------------------------------------------------ ENG-01 consolidated Redis path
def _flood_flows():
    flows = []
    for i in range(260):  # single-source flood -> one destination
        flows.append({"flow_uid": f"f{i}", "ts": 5000.0, "src_ip": "192.168.100.50", "src_port": 40000 + i,
                      "dst_ip": "10.0.0.5", "dst_port": 80, "proto": "TCP", "duration_s": 0.05,
                      "orig_bytes": 300, "resp_bytes": 40, "segment_hash": "h"})
    for i in range(200):  # spoofed: many distinct sources -> one destination
        flows.append({"flow_uid": f"s{i}", "ts": 5100.0, "src_ip": f"172.16.{i // 250}.{i % 250 + 1}", "src_port": 1000 + i,
                      "dst_ip": "10.0.0.9", "dst_port": 53, "proto": "UDP", "duration_s": 0.01,
                      "orig_bytes": 60, "resp_bytes": 0, "segment_hash": "h"})
    flows.append({"flow_uid": "slow", "ts": 5200.0, "src_ip": "192.168.100.51", "src_port": 51000,
                  "dst_ip": "10.0.0.5", "dst_port": 80, "proto": "TCP", "duration_s": 161.0,
                  "orig_bytes": 4, "resp_bytes": 0, "segment_hash": "h"})
    return flows


def test_eng01_redis_path_matches_native_reference():
    from src.engines.eng01_ddos import VolumetricDDoSDetector
    from src.memstore import MemoryStore

    async def run(eng):
        out = []
        for f in _flood_flows():
            a = await eng.score(dict(f))
            if a is not None:
                out.append((a.threat_class, round(a.confidence_score, 1), a.flow_identifier.src_ip))
        return out

    py = VolumetricDDoSDetector(redis_client=MemoryStore(), allow_native=False)
    assert py._native is None
    py_out = asyncio.run(run(py))
    classes = {c for c, _, _ in py_out}
    assert {"VOLUMETRIC_DDOS", "SLOWLORIS"} <= classes
    assert any(c == "VOLUMETRIC_DDOS" and conf >= 90 for c, conf, _ in py_out), "spoofed-source check must fire"
    native = VolumetricDDoSDetector(redis_client=MemoryStore())
    if native._native is not None:
        assert asyncio.run(run(native)) == py_out


def test_eng01_slowloris_never_touches_redis_state():
    from src.engines.eng01_ddos import VolumetricDDoSDetector

    class Boom:
        def __getattr__(self, name):
            raise AssertionError(f"slowloris path must not touch Redis ({name})")
    eng = VolumetricDDoSDetector(redis_client=Boom(), allow_native=False)
    f = {"flow_uid": "x", "ts": 1.0, "src_ip": "1.1.1.1", "src_port": 1, "dst_ip": "2.2.2.2", "dst_port": 80,
         "proto": "TCP", "duration_s": 200.0, "orig_bytes": 3, "resp_bytes": 0, "segment_hash": "h"}
    assert asyncio.run(eng.score(f)).threat_class == "SLOWLORIS"


# ------------------------------------------------------------------ evidence enrichment
def test_kerberos_alert_names_the_requesting_user():
    from src.engines.eng11_kerberos import KerberosAttackDetector
    from src.flow_mapping import map_record
    flow = map_record({"uid": "k", "ts": 1.0, "id.orig_h": "10.0.0.5", "id.orig_p": 50000, "id.resp_h": "10.0.0.1",
                       "id.resp_p": 88, "proto": "tcp", "request_type": "TGS", "service": "MSSQLSvc/db01:1433",
                       "cipher": "rc4-hmac", "client": "alice/CORP.LOCAL"}, "kerberos")
    alert = asyncio.run(KerberosAttackDetector().score(flow))
    assert alert is not None and alert.evidence["requesting_user"] == "alice/CORP.LOCAL"


def test_http_alert_carries_request_and_response_size():
    from src.engines.eng09_http_threats import HTTPThreatDetector
    from src.flow_mapping import map_record
    flow = map_record({"uid": "h", "ts": 1.0, "id.orig_h": "10.0.0.5", "id.orig_p": 1, "id.resp_h": "1.2.3.4", "id.resp_p": 80,
                       "proto": "tcp", "method": "GET", "uri": "/i0VpEBOWfbZAVaBSo63bbH6xnAbnBEoo",
                       "user_agent": "python-requests/2.31", "request_body_len": 0, "response_body_len": 524288}, "http")
    alert = asyncio.run(HTTPThreatDetector().score(flow))
    assert alert is not None and alert.evidence["response_body_len"] == 524288 and "request_body_len" in alert.evidence


@pytest.mark.parametrize("head,label", [(b"MZ\x90\x00", "pe_executable"), (b"\x7fELF\x02", "elf_executable"),
                                        (b"%PDF-1.7", "pdf"), (b"PK\x03\x04", "zip_or_office_ooxml"),
                                        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole_legacy_office"), (b"zzzz", "unknown")])
def test_file_type_sniffing(head, label):
    from src.engines.eng08_yara_scan import sniff_file_type
    assert sniff_file_type(head) == label


# ------------------------------------------------------------------ ENG-05 campaign dedup
def _probe_flows(src, n, t0=1000.0, step=0.01, base=0):
    return [{"flow_uid": f"{src}-{base + i}", "ts": t0 + i * step, "src_ip": src, "src_port": 40000 + (i % 1000),
             "dst_ip": f"10.9.{(base + i) // 250}.{(base + i) % 250 + 1}", "dst_port": 23, "proto": "TCP",
             "duration_s": 0.0, "orig_bytes": 0, "resp_bytes": 0, "segment_hash": "h"} for i in range(n)]


@pytest.mark.parametrize("native", [True, False])
def test_recon_one_alert_per_campaign_with_escalation(native):
    from src.engines.eng05_recon import ReconDetector

    async def run(flows):
        det = ReconDetector()
        if not native:
            det._native = None
        return [a for a in [await det.score(dict(f)) for f in flows] if a is not None]
    out = asyncio.run(run(_probe_flows("192.0.2.7", 3000)))
    # 3000 probes used to mean 120 alerts (one per 25 new targets). Now: 25 -> 250 -> 2,500 (10x milestones).
    assert 1 <= len(out) <= 4, f"{len(out)} alerts for one campaign"
    assert out[0].evidence["distinct_targets"] >= 25 and "escalation" not in out[0].evidence
    assert all(a.evidence.get("escalation") for a in out[1:])
    assert out[-1].evidence["distinct_targets"] >= 2500


def test_recon_new_campaign_after_silence_and_independent_sources():
    from src.engines.eng05_recon import ReconDetector, RECON_ALERT_COOLDOWN_S

    async def run():
        det = ReconDetector()
        a1 = [x for x in [await det.score(dict(f)) for f in _probe_flows("192.0.2.1", 60)] if x]
        late = 1000.0 + RECON_ALERT_COOLDOWN_S + 500
        a2 = [x for x in [await det.score(dict(f)) for f in _probe_flows("192.0.2.1", 60, t0=late, base=1000)] if x]
        other = [x for x in [await det.score(dict(f)) for f in _probe_flows("192.0.2.2", 60, base=2000)] if x]
        return a1, a2, other
    a1, a2, other = asyncio.run(run())
    assert len(a1) == 1 and len(a2) == 1 and len(other) == 1


# ------------------------------------------------------------------ ENG-06 real-data tuning
def _flow(orig, resp, uid="X1", src="10.0.0.9", dst="150.171.27.11", ts=1.0):
    from src.flow_mapping import map_record
    return map_record({"uid": uid, "ts": ts, "id.orig_h": src, "id.resp_h": dst, "id.orig_p": 5000,
                       "id.resp_p": 443, "proto": "tcp", "orig_bytes": orig, "resp_bytes": resp}, "conn")


def test_exfil_ordinary_desktop_upload_is_not_flagged():
    """Real benign capture (normal.pcap): one 601,527 B upload, 22,742 B back (26.5:1), to a Microsoft
    endpoint was flagged DATA_EXFILTRATION at the old 256 KB floor -- by both the single-flow and the
    accumulated check. Neither may fire for a single ordinary upload."""
    from src.engines.eng06_exfiltration import ExfiltrationDetector
    det = ExfiltrationDetector(redis_client=None)
    assert asyncio.run(det.score(_flow(601_527, 22_742))) is None


def test_exfil_still_catches_bulk_and_drip_feed():
    from src.engines.eng06_exfiltration import ExfiltrationDetector
    det = ExfiltrationDetector(redis_client=None)
    bulk = asyncio.run(det.score(_flow(5_000_000, 100)))
    assert bulk is not None and bulk.evidence["detection_type"] == "single_flow"
    drip = ExfiltrationDetector(redis_client=None)
    hit = None
    for i in range(60):       # 60 flows x 20 KB out, tiny replies, same destination, one window
        hit = asyncio.run(drip.score(_flow(20_000, 200, uid=f"D{i}", ts=1000.0 + i))) or hit
    assert hit is not None and hit.evidence["detection_type"] == "accumulated_low_and_slow"
    assert hit.evidence["contributing_flow_count"] >= 5


def test_beaconing_ignores_periodic_multicast():
    """Real Wi-Fi capture: a neighbour's 30 s-periodic LLMNR queries to 224.0.0.252 were flagged C2_BEACONING."""
    from src.engines.eng02_c2_beaconing import C2BeaconingDetector
    from src.flow_mapping import map_record
    from src.memstore import MemoryStore
    for dst in ("224.0.0.252", "239.255.255.250", "255.255.255.255", "ff02::fb"):
        det = C2BeaconingDetector(redis_client=MemoryStore())
        hit = None
        for i in range(30):
            f = map_record({"uid": f"L{i}", "ts": 1000.0 + 30 * i, "id.orig_h": "169.254.12.225", "id.resp_h": dst,
                            "id.orig_p": 5000 + i, "id.resp_p": 5355, "proto": "udp"}, "conn")
            hit = asyncio.run(det.score(f)) or hit
        assert hit is None, dst
    det = C2BeaconingDetector(redis_client=MemoryStore())
    hit = None
    for i in range(30):      # same cadence to an ordinary unicast host still alerts
        f = map_record({"uid": f"U{i}", "ts": 1000.0 + 30 * i, "id.orig_h": "10.0.0.5", "id.resp_h": "203.0.113.9",
                        "id.orig_p": 5000 + i, "id.resp_p": 443, "proto": "tcp"}, "conn")
        hit = asyncio.run(det.score(f)) or hit
    assert hit is not None
