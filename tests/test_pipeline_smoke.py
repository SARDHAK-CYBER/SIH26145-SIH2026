"""
Pipeline smoke tests -- exercise the shared mapping, feature extraction,
and every rule engine against synthetic fixtures without needing Docker,
Redis, OpenSearch, Postgres, or trained models.

Run: python -m pytest tests/test_pipeline_smoke.py -q
"""
import asyncio
import importlib

import pytest

from src.flow_mapping import map_record, compute_segment_hash
from src.features.feature_extraction import build_feature_vector


# --------------------------------------------------------------------------
# Shared record -> flow mapping
# --------------------------------------------------------------------------
def test_map_record_conn_shape():
    rec = {"uid": "C1", "ts": 100.0, "id.orig_h": "10.0.0.1", "id.orig_p": 4444,
           "id.resp_h": "10.0.0.2", "id.resp_p": 80, "proto": "tcp",
           "duration": 2.0, "orig_bytes": 500000, "resp_bytes": 10}
    flow = map_record(rec, "conn")
    assert flow["src_ip"] == "10.0.0.1"
    assert flow["proto"] == "TCP"
    assert flow["orig_bytes"] == 500000
    assert flow["segment_hash"].startswith("sha256:")


def test_map_record_modbus_uses_func_not_func_name():
    """The historical bug: engines read `modbus_func` but the mapper wrote
    it from Zeek key `func_name` on 2 of 3 paths -> OT detection no-oped.
    map_record must read `func`."""
    rec = {"uid": "M1", "ts": 1.0, "id.orig_h": "1.1.1.1", "id.resp_h": "2.2.2.2",
           "id.orig_p": 5, "id.resp_p": 502, "func": "WRITE_SINGLE_REGISTER", "register": 40001}
    flow = map_record(rec, "modbus")
    assert flow["modbus_func"] == "WRITE_SINGLE_REGISTER"
    assert flow["protocol_analyzed"] == "modbus"


def test_compute_segment_hash_deterministic():
    rec = {"b": 2, "a": 1}
    assert compute_segment_hash(rec) == compute_segment_hash({"a": 1, "b": 2})


# --------------------------------------------------------------------------
# Feature extraction contract (docs/MODEL_CONTRACT.md vector lengths)
# --------------------------------------------------------------------------
@pytest.mark.parametrize("family,expected_len,flow", [
    ("flow", 9, {"duration_s": 1.0, "orig_bytes": 100, "resp_bytes": 50, "proto": "TCP"}),
    ("dns", 262, {"dns_query": "kq3v9zx1p7w.example.com"}),
    ("tls", 3, {"ja4": "t13d1516h2_8daaf6152771_02713d6af862", "sni": "example.com"}),
    ("modbus", 4, {"modbus_func": "WRITE_SINGLE_REGISTER", "register_address": 5, "register_sweep_count": 3}),
])
def test_feature_vector_lengths(family, expected_len, flow):
    vec = build_feature_vector(flow, family)
    assert vec.shape == (expected_len,)
    assert vec.dtype.name == "float32"


# --------------------------------------------------------------------------
# Every engine module imports
# --------------------------------------------------------------------------
ENGINE_MODULES = [f"src.engines.eng{n:02d}_{name}" for n, name in [
    (1, "ddos"), (2, "c2_beaconing"), (3, "dga_dns"), (4, "encrypted_malware"),
    (5, "recon"), (6, "exfiltration"), (7, "ot_anomaly"), (8, "yara_scan"),
    (9, "http_threats"), (10, "suricata"), (11, "kerberos"), (12, "bzar_notices"),
    (13, "bruteforce"),
]]


@pytest.mark.parametrize("mod", ENGINE_MODULES)
def test_engine_module_imports(mod):
    importlib.import_module(mod)


def test_no_torch_dependency_in_eng03():
    import sys
    mod = importlib.import_module("src.engines.eng03_dga_dns")
    assert "torch" not in sys.modules, "eng03 must not pull in torch any more"
    assert not hasattr(mod, "DGAConvNet"), "the untrained CNN must be gone"


# --------------------------------------------------------------------------
# ENG-03: deterministic, model-free DGA heuristic
# --------------------------------------------------------------------------
def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_eng03_deterministic_and_fires_on_dga_lexical():
    from src.engines.eng03_dga_dns import DGADetector
    det = DGADetector(model_server=None)
    flow = map_record({"uid": "D1", "ts": 1.0, "id.orig_h": "10.0.0.5", "id.resp_h": "8.8.8.8",
                       "id.orig_p": 33333, "id.resp_p": 53,
                       "query": "kqx3vwzptlmnbrx9.com", "qtype_name": "A"}, "dns")
    a1 = _run(det.score(flow))
    a2 = _run(det.score(flow))
    assert a1 is not None and a2 is not None
    assert a1.threat_class == "DGA_DOMAIN"
    assert a1.detection_mode == "rule"
    assert a1.model_dump() == a2.model_dump()  # deterministic


def test_eng03_benign_domain_no_alert():
    from src.engines.eng03_dga_dns import DGADetector
    det = DGADetector(model_server=None)
    flow = map_record({"uid": "D2", "ts": 1.0, "id.orig_h": "10.0.0.5", "id.resp_h": "8.8.8.8",
                       "id.orig_p": 33333, "id.resp_p": 53,
                       "query": "www.google.com", "qtype_name": "A"}, "dns")
    assert _run(det.score(flow)) is None


def test_eng03_dns_tunnelling_fires():
    from src.engines.eng03_dga_dns import DGADetector
    det = DGADetector(model_server=None)
    flow = map_record({"uid": "D3", "ts": 1.0, "id.orig_h": "10.0.0.5", "id.resp_h": "8.8.8.8",
                       "id.orig_p": 33333, "id.resp_p": 53,
                       "query": "aGVsbG8gd29ybGQ.dGhpcyBpcyBhIGxvbmc.b64chunk.exfil.net",
                       "qtype_name": "TXT"}, "dns")
    a = _run(det.score(flow))
    assert a is not None and a.threat_class == "DNS_TUNNELING"


# --------------------------------------------------------------------------
# Rule engines that need no external state fire on their fixtures
# --------------------------------------------------------------------------
def test_eng04_ja4_match_or_clean():
    from src.engines.eng04_encrypted_malware import EncryptedMalwareDetector
    det = EncryptedMalwareDetector()
    # unknown ja4 -> no alert, no crash
    flow = map_record({"uid": "S1", "ts": 1.0, "id.orig_h": "1.1.1.1", "id.resp_h": "2.2.2.2",
                       "id.orig_p": 5, "id.resp_p": 443, "ja4": "t00000000000_000000000000_000000000000"}, "ssl")
    assert _run(det.score(flow)) is None


def test_eng05_recon_fanout_fires():
    from src.engines.eng05_recon import ReconDetector
    det = ReconDetector()
    alert = None
    for port in range(1, 40):
        flow = map_record({"uid": f"R{port}", "ts": 1.0 + port * 0.01,
                           "id.orig_h": "10.0.0.9", "id.resp_h": "10.0.0.50",
                           "id.orig_p": 40000, "id.resp_p": port, "proto": "tcp"}, "conn")
        alert = _run(det.score(flow)) or alert
    assert alert is not None and alert.threat_class == "RECONNAISSANCE"


def test_eng06_exfiltration_single_flow_ratio_fires():
    from src.engines.eng06_exfiltration import ExfiltrationDetector
    det = ExfiltrationDetector(redis_client=None)
    flow = map_record({"uid": "E1", "ts": 1.0, "id.orig_h": "10.0.0.9", "id.resp_h": "9.9.9.9",
                       "id.orig_p": 5000, "id.resp_p": 443, "proto": "tcp",
                       "orig_bytes": 5_000_000, "resp_bytes": 100}, "conn")
    a = _run(det.score(flow))
    assert a is not None and a.threat_class == "DATA_EXFILTRATION"


def test_eng07_ot_dangerous_modbus_fires():
    from src.engines.eng07_ot_anomaly import OTIndustrialAnomalyDetector
    det = OTIndustrialAnomalyDetector()
    flow = map_record({"uid": "O1", "ts": 1.0, "id.orig_h": "10.0.0.9", "id.resp_h": "10.0.0.20",
                       "id.orig_p": 5000, "id.resp_p": 502, "func": "WRITE_MULTIPLE_REGISTERS",
                       "register": 40001}, "modbus")
    a = _run(det.score(flow))
    assert a is not None and a.threat_class == "ICS_UNAUTHORIZED_CONTROL_COMMAND"


def test_eng09_http_suspicious_ua_high_entropy_fires():
    from src.engines.eng09_http_threats import HTTPThreatDetector
    det = HTTPThreatDetector()
    flow = map_record({"uid": "H1", "ts": 1.0, "id.orig_h": "10.0.0.9", "id.resp_h": "9.9.9.9",
                       "id.orig_p": 5000, "id.resp_p": 80, "method": "GET",
                       "uri": "/x9f3k2j1z8q7w4b6v5n0", "user_agent": "python-requests/2.31"}, "http")
    a = _run(det.score(flow))
    assert a is not None


def test_eng11_kerberoasting_fires():
    from src.engines.eng11_kerberos import KerberosAttackDetector
    det = KerberosAttackDetector()
    flow = map_record({"uid": "K1", "ts": 1.0, "id.orig_h": "10.0.0.9", "id.resp_h": "10.0.0.10",
                       "id.orig_p": 5000, "id.resp_p": 88, "request_type": "TGS",
                       "cipher": "rc4-hmac", "service": "MSSQLSvc/db01"}, "kerberos")
    a = _run(det.score(flow))
    assert a is not None and a.threat_class == "NETWORK_INTRUSION_ATTEMPT"


def test_eng12_bzar_notice_parses():
    from src.engines.eng12_bzar_notices import parse_bzar_notices
    alerts = parse_bzar_notices([{
        "ts": 1.0, "note": "BZAR::ATTACK::Lateral_Movement",
        "msg": "Detected T1021.002 Admin File Share activity", "src": "10.0.0.9", "dst": "10.0.0.10", "p": 445,
    }])
    assert len(alerts) == 1 and alerts[0]["mitre_attack"]["technique_id"] == "T1021.002"


def test_eng10_suricata_parse():
    from src.engines.eng10_suricata import parse_suricata_alerts
    alerts = parse_suricata_alerts([{
        "event_type": "alert", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2",
        "src_port": 1, "dest_port": 80, "proto": "TCP",
        "alert": {"signature": "ET MALWARE x", "category": "a network trojan was detected", "severity": 1},
    }])
    assert len(alerts) == 1 and alerts[0]["threat_class"] == "C2_BEACONING"


# --------------------------------------------------------------------------
# Shared ML alert builder (no onnxruntime needed -- fake a score result)
# --------------------------------------------------------------------------
def test_build_ml_alert_gating():
    from src.inference.ml_alerts import build_ml_alert
    flow = {"ts": 1.0, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "src_port": 1, "dst_port": 2, "proto": "TCP"}
    below = build_ml_alert(flow, "flow", {"threat_score": 0.3, "detection_mode": "xgboost",
                                          "model_scores": {"xgboost": 0.3}}, min_confidence=0.6)
    assert below is None
    above = build_ml_alert(flow, "flow", {"threat_score": 0.95, "detection_mode": "xgboost",
                                          "model_scores": {"xgboost": 0.95}}, min_confidence=0.6)
    assert above is not None and above.detection_mode == "xgboost" and above.severity == "HIGH"


# --------------------------------------------------------------------------
# Entry-point modules import (ML optional)
# --------------------------------------------------------------------------
def test_offline_engine_imports():
    importlib.import_module("src.offline_engine")


# --------------------------------------------------------------------------
# ML path (skipped unless onnxruntime + trained artifacts are present)
# --------------------------------------------------------------------------
onnxruntime = pytest.importorskip("onnxruntime", reason="onnxruntime not installed")


_MS_CACHE = []


def _model_server_or_skip():
    if not _MS_CACHE:
        from src.inference.model_server import HybridModelServer
        _MS_CACHE.append(HybridModelServer())
    ms = _MS_CACHE[0]
    if not ms.loaded_families():
        pytest.skip("no trained ONNX models in models/")
    return ms


def test_model_server_loads_expected_families():
    ms = _model_server_or_skip()
    for fam in ms.loaded_families():
        assert fam in ("flow", "dns", "tls", "modbus")


def test_degenerate_iforest_is_demoted_not_flooding():
    """A low-F1 Isolation Forest must not independently drive detections.
    Regression guard for the 252/572-benign-flows false-positive flood."""
    ms = _model_server_or_skip()
    if "flow" not in ms.loaded_families():
        pytest.skip("flow model not trained")
    fired = 0
    for orig, resp in [(200, 400), (300, 250), (120, 900), (80, 640), (1500, 1200)]:
        r = ms.score_flow({"duration_s": 1.0, "orig_bytes": orig, "resp_bytes": resp, "proto": "TCP"}, "flow")
        if r and r["threat_score"] >= 0.6 and r["detection_mode"] == "isolation_forest":
            fired += 1
    assert fired == 0, "isolation_forest fired on ordinary flows despite being demoted"


def test_eng03_uses_trained_dns_model_when_available():
    ms = _model_server_or_skip()
    if "dns" not in ms.loaded_families():
        pytest.skip("dns model not trained")
    from src.engines.eng03_dga_dns import DGADetector
    det = DGADetector(model_server=ms)
    flow = map_record({"uid": "D9", "ts": 1.0, "id.orig_h": "10.0.0.5", "id.resp_h": "8.8.8.8",
                       "id.orig_p": 33333, "id.resp_p": 53,
                       "query": "kqx3vwzptlmnbrx9.com", "qtype_name": "A"}, "dns")
    a = _run(det.score(flow))
    assert a is not None and a.threat_class == "DGA_DOMAIN"
    assert a.detection_mode in ("xgboost", "isolation_forest")
    assert a.model_scores and "xgboost" in a.model_scores


# --------------------------------------------------------------------------
# Redis-state isolation between separate pcap-upload analyses
#
# eng01/eng02/eng06/eng13 key their Redis-backed sliding-window state by
# (src_ip[, dst_ip][, dst_port]) and a bucket derived from the FLOW'S OWN
# embedded timestamp -- correct for live capture, which wants that state
# to persist across a whole run. Confirmed against the live stack
# (2026-09): re-uploading the SAME pcap three times through
# POST /analyze/pcap produced three DIFFERENT alert counts/compositions
# (VOLUMETRIC_DDOS and NETWORK_INTRUSION_ATTEMPT flickering in and out)
# because those four engines' Redis keys collided across the separate
# uploads. src/api/pcap_analysis.py now constructs each of them with a
# fresh key_prefix per call -- these tests pin the mechanism that fix
# depends on so it can't silently regress.
# --------------------------------------------------------------------------
def test_stateful_engine_keys_are_isolated_by_prefix():
    from src.engines.eng01_ddos import VolumetricDDoSDetector
    from src.engines.eng02_c2_beaconing import C2BeaconingDetector
    from src.engines.eng06_exfiltration import ExfiltrationDetector
    from src.engines.eng13_bruteforce import BruteForceDetector

    ts, src_ip, dst_ip, dst_port = 1000.0, "10.0.0.1", "10.0.0.2", 22
    prefix_a, prefix_b = "upload:aaa:", "upload:bbb:"

    ddos_a = VolumetricDDoSDetector(redis_client=None, key_prefix=prefix_a)
    ddos_b = VolumetricDDoSDetector(redis_client=None, key_prefix=prefix_b)
    assert ddos_a._bucket_key(ts) != ddos_b._bucket_key(ts)
    assert ddos_a._bucket_key(ts).startswith(prefix_a)

    c2_a = C2BeaconingDetector(redis_client=None, key_prefix=prefix_a)
    c2_b = C2BeaconingDetector(redis_client=None, key_prefix=prefix_b)
    assert c2_a._key(src_ip, dst_ip) != c2_b._key(src_ip, dst_ip)

    exfil_a = ExfiltrationDetector(redis_client=None, key_prefix=prefix_a)
    exfil_b = ExfiltrationDetector(redis_client=None, key_prefix=prefix_b)
    assert exfil_a._bucket_key(src_ip, dst_ip, ts) != exfil_b._bucket_key(src_ip, dst_ip, ts)

    bf_a = BruteForceDetector(redis_client=None, key_prefix=prefix_a)
    bf_b = BruteForceDetector(redis_client=None, key_prefix=prefix_b)
    assert bf_a._bucket_key(src_ip, dst_ip, dst_port, ts) != bf_b._bucket_key(src_ip, dst_ip, dst_port, ts)


def test_stateful_engine_key_prefix_defaults_to_empty():
    """The live-capture/streaming path constructs these engines with no
    key_prefix at all -- it WANTS state shared across the whole run.
    Pin the default so it can't silently start scoping (or fail to scope)
    without a deliberate change to every call site."""
    from src.engines.eng01_ddos import VolumetricDDoSDetector
    from src.engines.eng02_c2_beaconing import C2BeaconingDetector

    det = VolumetricDDoSDetector(redis_client=None)
    assert det.key_prefix == ""
    assert det._bucket_key(1000.0) == "eng01:src_ip_cms:100"

    det2 = C2BeaconingDetector(redis_client=None)
    assert det2.key_prefix == ""
    assert det2._key("1.2.3.4", "5.6.7.8") == "eng02:beacon_ts:1.2.3.4:5.6.7.8"


def test_pcap_analysis_uses_fresh_state_prefix_per_call(monkeypatch):
    """_run_engines must construct a NEW, unpredictable prefix on every
    call -- two calls (two uploads) must never end up sharing one."""
    import re
    from src.api import pcap_analysis

    seen_prefixes: list[str] = []
    real_ctor = pcap_analysis.VolumetricDDoSDetector

    class _Spy(real_ctor):  # type: ignore[misc,valid-type]
        def __init__(self, *a, **kw):
            seen_prefixes.append(kw.get("key_prefix", ""))
            super().__init__(*a, **kw)

    monkeypatch.setattr(pcap_analysis, "VolumetricDDoSDetector", _Spy)

    empty_parsed = {"conn": [], "dns": [], "ssl": [], "modbus": [], "cip": [], "dnp3": [], "http": [], "kerberos": [], "notice": []}
    _run(pcap_analysis._run_engines(empty_parsed, None, redis_client=None))
    _run(pcap_analysis._run_engines(empty_parsed, None, redis_client=None))

    assert len(seen_prefixes) == 2
    assert seen_prefixes[0] != seen_prefixes[1]
    assert all(re.match(r"^upload:[0-9a-f]{12}:$", p) for p in seen_prefixes)


# --------------------------------------------------------------------------
# Accuracy fixes found by scripts/eval_real_traffic.py on real captures
# --------------------------------------------------------------------------
def test_orientation_syn_and_midstream():
    from src.flow_orientation import sender_is_originator as so
    assert so("tcp", 54000, 443, 0x02) is True          # SYN -> client
    assert so("tcp", 443, 54000, 0x12) is False         # SYN+ACK -> server
    # capture began mid-connection: server->client data packet seen first
    assert so("tcp", 443, 15860, 0x18) is False
    assert so("tcp", 15860, 443, 0x18) is True
    assert so("udp", 53, 61636) is False                # DNS reply first
    assert so("udp", 61636, 53) is True
    assert so("tcp", 50000, 50001, 0x10) is True        # equal rank -> as seen


def test_pcap_parser_orients_midstream_flow_and_skips_dns_responses(tmp_path):
    scapy = pytest.importorskip("scapy.all")
    from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, wrpcap
    pkts = [
        # mid-stream: server (443) sends first -> must NOT be the originator
        Ether() / IP(src="93.184.216.34", dst="192.168.0.5") / TCP(sport=443, dport=51000, flags="PA") / (b"x" * 900),
        Ether() / IP(src="192.168.0.5", dst="93.184.216.34") / TCP(sport=51000, dport=443, flags="A"),
        # DNS query + its response: only the query may become a dns record
        Ether() / IP(src="192.168.0.5", dst="192.168.0.1") / UDP(sport=40000, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")),
        Ether() / IP(src="192.168.0.1", dst="192.168.0.5") / UDP(sport=53, dport=40000)
        / DNS(qr=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", rdata="93.184.216.34")),
    ]
    p = tmp_path / "t.pcap"
    wrpcap(str(p), pkts)
    from pcap_parser import parse_pcap
    parsed = parse_pcap(str(p))
    tcp = [c for c in parsed["conn"] if c["proto"] == "tcp"][0]
    assert tcp["id.orig_h"] == "192.168.0.5" and tcp["id.resp_h"] == "93.184.216.34"
    assert tcp["resp_bytes"] == 900 and tcp["orig_bytes"] == 0
    assert len(parsed["dns"]) == 1 and parsed["dns"][0]["id.orig_h"] == "192.168.0.5"


def test_eng05_answered_flows_do_not_count_as_a_scan():
    from src.engines.eng05_recon import ReconDetector
    det = ReconDetector()
    for i in range(60):          # a busy desktop: 60 distinct CDN endpoints, every one ANSWERED
        f = map_record({"uid": f"B{i}", "ts": 1.0 + i, "id.orig_h": "192.168.0.5", "id.resp_h": f"20.0.0.{i}",
                        "id.orig_p": 50000 + i, "id.resp_p": 443, "proto": "tcp",
                        "orig_bytes": 700, "resp_bytes": 5000}, "conn")
        assert _run(det.score(f)) is None
    det2 = ReconDetector()       # a real scan: 60 unanswered SYN probes
    hit = None
    for i in range(60):
        f = map_record({"uid": f"S{i}", "ts": 1.0 + i * 0.01, "id.orig_h": "10.0.0.9", "id.resp_h": "10.0.0.50",
                        "id.orig_p": 40000, "id.resp_p": 1000 + i, "proto": "tcp",
                        "orig_bytes": 0, "resp_bytes": 0}, "conn")
        hit = _run(det2.score(f)) or hit
    assert hit is not None and hit.threat_class == "RECONNAISSANCE"


def test_eng06_small_flows_are_not_exfiltration():
    from src.engines.eng06_exfiltration import ExfiltrationDetector
    det = ExfiltrationDetector(redis_client=None)
    small = map_record({"uid": "E2", "ts": 1.0, "id.orig_h": "10.0.0.9", "id.resp_h": "9.9.9.9",
                        "id.orig_p": 5000, "id.resp_p": 80, "proto": "tcp",
                        "orig_bytes": 654, "resp_bytes": 25}, "conn")   # 26:1 but 654 bytes
    assert _run(det.score(small)) is None


def test_registrable_domain():
    from src.engines.eng03_dga_dns import registrable_domain as rd
    assert rd("a-ring-fallback.msedge.net") == "msedge.net"
    assert rd("stream-production.avcdn.net") == "avcdn.net"
    assert rd("www.bbc.co.uk") == "bbc.co.uk"
    assert rd("kqx3vwzptlmnbrx9.com") == "kqx3vwzptlmnbrx9.com"
    assert rd("localhost") == "localhost"


def test_eng03_cdn_subdomain_not_dga_but_real_dga_still_fires():
    ms = _model_server_or_skip()
    if "dns" not in ms.loaded_families():
        pytest.skip("dns model not trained")
    from src.engines.eng03_dga_dns import DGADetector
    det = DGADetector(model_server=ms)
    def q(name):
        return map_record({"uid": "D", "ts": 1.0, "id.orig_h": "10.0.0.5", "id.resp_h": "8.8.8.8",
                           "id.orig_p": 33333, "id.resp_p": 53, "query": name, "qtype_name": "A"}, "dns")
    assert _run(det.score(q("a-ring-fallback.msedge.net"))) is None
    assert _run(det.score(q("stream-production.avcdn.net"))) is None
    a = _run(det.score(q("kqx3vwzptlmnbrx9.com")))
    assert a is not None and a.threat_class == "DGA_DOMAIN"


def test_fusion_policy_and_flow_mapping():
    from src.inference.fusion import standalone_threshold, effective_threshold
    from src.inference.model_server import MIN_ML_CONFIDENCE
    from src.inference.ml_alerts import ML_THREAT_MAPPING
    assert standalone_threshold("flow") >= 0.95 > MIN_ML_CONFIDENCE
    assert effective_threshold("flow", corroborated=True) == MIN_ML_CONFIDENCE
    assert effective_threshold("modbus", corroborated=False) == MIN_ML_CONFIDENCE
    assert ML_THREAT_MAPPING["flow"][0] == "VOLUMETRIC_DDOS"   # DDoS-trained model must not claim "scan"
