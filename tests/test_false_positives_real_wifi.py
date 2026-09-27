"""Regression tests for the false positives found by scoring a REAL 20-minute Wi-Fi capture (7.0M packets, 8,593 flows):

  * 15x C2_BEACONING on UDP broadcast heartbeats (flow oriented with 255.255.255.255 as the "source")
  * 2x C2_BEACONING on Windows CryptoAPI OCSP / CTL fetches (empty User-Agent, high-entropy base64 path)
  * 3x SLOWLORIS on idle push / peer-to-peer connections (ports 5228, 7680)
  * 1x VOLUMETRIC_DDOS on mDNS (150 hosts -> 224.0.0.251)
  * 1x DATA_EXFILTRATION on an ordinary 1.2 MB TLS upload

The capture itself is private (real payloads) and not in the repo; these tests use the shapes of those records."""
from __future__ import annotations

import asyncio
import base64

import pytest

from src.engines.eng01_ddos import VolumetricDDoSDetector
from src.engines.eng02_c2_beaconing import C2BeaconingDetector
from src.engines.eng06_exfiltration import ExfiltrationDetector
from src.engines.eng09_http_threats import HTTPThreatDetector, _is_pki_fetch
from src.memstore import MemoryStore


def run(coro):
    return asyncio.run(coro)


def flow(**kw):
    base = {"flow_uid": "u", "ts": 1_700_000_000.0, "src_ip": "10.0.0.5", "src_port": 40000, "dst_ip": "93.184.216.34", "dst_port": 443,
            "proto": "TCP", "duration_s": 1.0, "orig_bytes": 100, "resp_bytes": 100, "segment_hash": "h"}
    base.update(kw)
    return base


def test_eng02_ignores_broadcast_heartbeats_in_either_direction():
    async def go():
        eng = C2BeaconingDetector(redis_client=MemoryStore(), key_prefix="t:")
        out = []
        for i in range(12):
            for src, dst in (("255.255.255.255", "10.0.0.7"), ("10.0.0.7", "255.255.255.255"), ("10.0.0.7", "224.0.0.251")):
                out.append(await eng.score(flow(src_ip=src, dst_ip=dst, ts=1_700_000_000.0 + i * 60.0)))
        return out
    assert not any(run(go()))


@pytest.mark.parametrize("engine_force_python", [True, False])
def test_eng01_slowloris_is_a_web_service_attack(engine_force_python):
    eng = VolumetricDDoSDetector(redis_client=MemoryStore(), key_prefix="s:", allow_native=not engine_force_python)

    def idle(port):
        return flow(dst_port=port, duration_s=600.0, orig_bytes=20, resp_bytes=20, dst_ip=f"1.2.3.{port % 250}")
    for quiet in (5228, 5223, 7680, 22, 3389, 1883, 443, 8443):    # 443: idle TLS keepalives seen in a 2nd real capture
        assert run(eng.score(idle(quiet))) is None, quiet
    for web in (80, 8080):
        a = run(eng.score(idle(web)))
        assert a is not None and a.threat_class == "SLOWLORIS", web
    a = run(eng.score(idle(0)))                                   # unknown port keeps the original behaviour
    assert a is not None and a.threat_class == "SLOWLORIS"


def test_native_eng01_port_gate_matches_python():
    core = pytest.importorskip("stealthtap_core")
    n = core.NativeEng01()
    assert n.check("10.0.0.5", "1.1.1.1", 1_700_000_000.0, 600.0, 40.0, 5228) is None
    assert n.check("10.0.0.5", "1.1.1.2", 1_700_000_000.0, 600.0, 40.0, 80)["threat_class"] == "SLOWLORIS"
    assert n.check("10.0.0.5", "1.1.1.4", 1_700_000_000.0, 600.0, 40.0, 443) is None
    assert n.check("10.0.0.5", "1.1.1.3", 1_700_000_000.0, 600.0, 40.0)["threat_class"] == "SLOWLORIS"   # port omitted -> unknown


def test_eng01_mdns_many_sources_is_not_a_spoofed_flood():
    async def go():
        eng = VolumetricDDoSDetector(redis_client=MemoryStore(), key_prefix="m:", allow_native=False)
        hits = []
        for i in range(200):
            hits.append(await eng.score(flow(src_ip=f"10.0.{i // 250}.{i % 250 + 1}", dst_ip="224.0.0.251", dst_port=5353, proto="UDP")))
        # the same shape towards a unicast victim IS a flood
        for i in range(200):
            hits.append(await eng.score(flow(src_ip=f"10.1.{i // 250}.{i % 250 + 1}", dst_ip="10.9.9.9", dst_port=80, ts=1_700_000_100.0)))
        return hits
    hits = run(go())
    assert not any(h for h in hits[:200])
    assert any(h and h.threat_class == "VOLUMETRIC_DDOS" for h in hits[200:])


def test_native_eng01_mdns_group_is_not_spoofed():
    core = pytest.importorskip("stealthtap_core")
    n = core.NativeEng01()
    for i in range(300):
        assert n.check(f"10.2.{i // 250}.{i % 250 + 1}", "224.0.0.251", 1_700_000_000.0, 1.0, 100.0, 5353) is None


OCSP_DER = bytes.fromhex("3051304f304d304b3049300906052b0e03021a05000414") + bytes(range(20)) + bytes.fromhex("0414") + bytes(range(20, 40))


def test_pki_fetches_are_not_c2():
    ocsp_path = "/" + base64.b64encode(OCSP_DER).decode().replace("/", "%2F").replace("+", "%2B")
    assert _is_pki_fetch(ocsp_path)
    assert _is_pki_fetch("/msdownload/update/v3/static/trustedr/en/pinrulesstl.cab?6b1bbfab6cefb2ae")
    assert _is_pki_fetch("/pki/crl/products/MicRooCerAut_2010-06-23.crl")
    # a random-looking beacon path is NOT a PKI fetch
    assert not _is_pki_fetch("/" + base64.b64encode(bytes(range(7, 87))).decode().replace("/", "_").replace("+", "-").rstrip("="))
    assert not _is_pki_fetch("/gate.php?id=8f3a2b7c91d04e5fa6b1c0d9e8f7a6b5")

    eng = HTTPThreatDetector()
    ok = flow(http_method="GET", http_uri=ocsp_path, http_user_agent="")
    assert run(eng.score(ok)) is None
    bad = flow(http_method="GET", http_uri="/gate/" + "aZ9xQ2mK7pL4vB8nR3tY6wC1dF5hJ0sE" * 2, http_user_agent="")
    assert run(eng.score(bad)) is not None                        # the real C2-shaped case still fires


def test_ordinary_upload_below_the_exfil_floor_is_quiet_but_bulk_is_not():
    async def go():
        eng = ExfiltrationDetector(redis_client=MemoryStore(), key_prefix="x:")
        small = await eng.score(flow(orig_bytes=1_204_484, resp_bytes=46_293))
        bulk = await eng.score(flow(orig_bytes=60_000_000, resp_bytes=40_000, src_ip="10.0.0.9", ts=1_700_000_500.0))
        return small, bulk
    small, bulk = run(go())
    assert small is None
    assert bulk is not None and bulk.threat_class == "DATA_EXFILTRATION"


def test_os_connectivity_check_domain_is_not_a_dga():
    """A live soak on the real network flagged www.msftconnecttest.com (Windows' internet-reachability probe) as a DGA at 70%."""
    from src.engines.eng03_dga_dns import DGADetector
    f = flow(dns_query="www.msftconnecttest.com", dns_qtype="A", dst_port=53, proto="UDP")
    assert run(DGADetector(model_server=None).score(f)) is None
