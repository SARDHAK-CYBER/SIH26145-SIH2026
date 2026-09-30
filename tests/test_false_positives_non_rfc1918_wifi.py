"""Regression tests for false positives found on a live capture of a network
using a non-RFC1918 address block privately (a campus/enterprise-style
12.10.0.0/20 block, observed IP 12.10.5.5/255.255.240.0):

  * 9x C2_BEACONING on periodic UDP heartbeats to 12.10.15.255 -- the real
    directed-broadcast address of that /20 subnet (Sentinel HASP license
    manager on :1947, Spotify Connect discovery on :57621, and an unknown
    LAN service on :15600). ENG-02's _is_multicast_or_broadcast() only
    recognised .255 addresses inside the traditional RFC1918 ranges, so it
    had no way to know this network's real broadcast address.
  * 1x RECONNAISSANCE from ordinary SSDP discovery traffic to 239.255.255.250
    crossing ENG-05's fan-out threshold (many (dst_ip, dst_port) probe-shaped
    tuples to the same multicast group looked like a port scan).
"""
from __future__ import annotations

import asyncio

from src.engines.eng02_c2_beaconing import (
    C2BeaconingDetector,
    _is_multicast_or_broadcast,
    set_local_broadcast_addresses,
)
from src.engines.eng05_recon import ReconDetector
from src.memstore import MemoryStore


def run(coro):
    return asyncio.run(coro)


def flow(**kw):
    base = {"flow_uid": "u", "ts": 1_700_000_000.0, "src_ip": "12.10.2.50", "src_port": 40000,
            "dst_ip": "12.10.15.255", "dst_port": 15600, "proto": "UDP", "duration_s": 1.0,
            "orig_bytes": 60, "resp_bytes": 0, "segment_hash": "h"}
    base.update(kw)
    return base


def test_broadcast_helper_computes_the_real_subnet_broadcast(monkeypatch):
    class FakeInfo:
        def __init__(self, name, ipv4, ipv4_netmask):
            self.name, self.capture_name, self.description = name, "", ""
            self.ipv4, self.ipv4_netmask = ipv4, ipv4_netmask

    from src.capture import interfaces

    monkeypatch.setattr(interfaces, "list_interfaces",
                         lambda **_: [FakeInfo("Wi-Fi", ["12.10.5.5"], ["255.255.240.0"])])
    assert interfaces.local_broadcast_addresses("Wi-Fi") == ["12.10.15.255"]


def test_eng02_ignores_periodic_heartbeats_to_the_real_local_broadcast_address():
    try:
        set_local_broadcast_addresses(["12.10.15.255"])

        async def go():
            eng = C2BeaconingDetector(redis_client=MemoryStore(), key_prefix="lb:")
            out = []
            for i in range(12):
                out.append(await eng.score(flow(ts=1_700_000_000.0 + i * 6.0)))
            return out
        assert not any(run(go()))
    finally:
        set_local_broadcast_addresses([])


def test_eng02_still_catches_a_real_beacon_to_an_ordinary_unicast_host_on_the_same_network():
    """The fix must not go blind on this network -- only the true broadcast
    address is exempted, not every destination on it."""
    try:
        set_local_broadcast_addresses(["12.10.15.255"])

        async def go():
            eng = C2BeaconingDetector(redis_client=MemoryStore(), key_prefix="lb2:")
            out = []
            for i in range(12):
                out.append(await eng.score(flow(dst_ip="203.0.113.9", dst_port=4444, ts=1_700_000_000.0 + i * 6.0)))
            return out
        assert any(run(go()))
    finally:
        set_local_broadcast_addresses([])


def test_without_configured_broadcast_address_the_old_rfc1918_only_behaviour_holds():
    """No live-capture startup has run (e.g. offline pcap eval, unit tests) --
    a non-RFC1918 .255 address is NOT assumed to be a broadcast address,
    since guessing wrong would blind the detector on the public internet."""
    assert not _is_multicast_or_broadcast("12.10.15.255")
    assert _is_multicast_or_broadcast("10.1.2.255")           # still works for real RFC1918 broadcasts


def test_eng05_ignores_ssdp_discovery_fanout_to_a_multicast_group():
    async def go():
        eng = ReconDetector()
        hits = []
        for i in range(30):
            hits.append(await eng.score(flow(
                src_ip="12.10.2.25", dst_ip="239.255.255.250", dst_port=20000 + i,
                orig_bytes=80, resp_bytes=0, ts=1_700_000_000.0 + i * 0.2, flow_uid=f"s{i}")))
        return hits
    assert not any(run(go()))


def test_eng05_still_catches_a_real_scan_of_many_unicast_targets():
    async def go():
        eng = ReconDetector()
        hits = []
        for i in range(30):
            hits.append(await eng.score(flow(
                src_ip="12.10.2.99", dst_ip=f"12.10.9.{i + 1}", dst_port=445,
                orig_bytes=40, resp_bytes=0, ts=1_700_000_000.0 + i * 0.1, flow_uid=f"r{i}")))
        return hits
    assert any(h and h.threat_class == "RECONNAISSANCE" for h in run(go()))
