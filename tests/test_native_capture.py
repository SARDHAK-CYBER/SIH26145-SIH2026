"""
Native capture engine (native/stealthtap_core/src/capture.rs): file replay through the
same thread/assembler/ring/inventory code the live NIC path uses, plus the PCAP index
behind the packet inspector. (Opening a real NIC needs the OS capture driver, so that
part is covered by scripts/live_soak.py, not by unit tests.)
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

core = pytest.importorskip("stealthtap_core")
if not hasattr(core, "NativeCapture"):
    pytest.skip("native module built without the capture engine", allow_module_level=True)

ROOT = Path(__file__).resolve().parent.parent
PCAP = ROOT / "simulated_attack_traffic.pcap"
REAL = ROOT / "samples" / "netbios_ssn2.pcap"


def _replay(path, **kw):
    cap = core.NativeCapture(pcap=str(path), **kw)
    cap.start()
    recs = []
    deadline = time.time() + 60
    while time.time() < deadline:
        recs += cap.poll(50, 5000)
        if cap.finished() and cap.pending() == 0:
            break
    recs += cap.poll(0, 100000)
    return cap, recs


def test_replay_consumes_every_packet_and_matches_the_index():
    idx = core.PcapIndex(str(PCAP))
    cap, _ = _replay(PCAP)
    st = cap.stats()
    assert st["recv"] == len(idx) and st["packets"] == len(idx)
    assert st["finished"] and st["records_dropped"] == 0 and st["unsupported_frames"] == 0
    cap.stop()


def test_replay_records_equal_the_reference_assembler():
    ref = core.LiveFlowAssembler(60.0)
    from_ref = []
    idx = core.PcapIndex(str(PCAP))
    for n in range(1, len(idx) + 1):
        ts, _wire, raw = idx.packet(n)
        from_ref += [(t, r["uid"]) for t, r in ref.process(ts, bytes(raw))]
    cap, recs = _replay(PCAP)
    from_cap = [(t, r["uid"]) for t, r in recs]
    assert sorted(from_cap) == sorted(from_ref)
    assert all("_arr" in r for _t, r in recs)
    cap.stop()


def test_loops_advance_time_and_count_packets():
    idx = core.PcapIndex(str(PCAP))
    cap, _ = _replay(PCAP, loops=3)
    st = cap.stats()
    assert st["recv"] == 3 * len(idx) and st["loops_done"] == 3
    t0, t1 = idx.span()
    assert st["last_ts"] > t1 + (t1 - t0), "each loop must continue in time, not rewind"
    cap.stop()


def test_inventory_hosts_and_protocols():
    cap, _ = _replay(REAL)
    hosts = cap.hosts(1000)
    assert hosts and all(h["tx_pkts"] + h["rx_pkts"] > 0 for h in hosts)
    ips = {h["ip"] for h in hosts}
    assert len(ips) == len(hosts)
    by = sum(h["tx_bytes"] for h in hosts)
    assert by > 0
    protos = {p["name"]: p for p in cap.protocols()}
    assert sum(p["packets"] for p in protos.values()) >= cap.stats()["packets"] - cap.stats()["non_ip"] - 5
    cap.stop()


def test_packet_ring_summaries_filter_and_bytes():
    cap, _ = _replay(PCAP, ring_packets=100000)
    rows = cap.packets(0, 50)
    assert rows and rows == sorted(rows, key=lambda r: r["id"])
    dns = cap.packets(0, 20, "dns")
    assert dns and all("dns" in (r["proto"] + r["info"]).lower() for r in dns)
    not_dns = cap.packets(0, 500, "!dns")
    assert all("dns" not in (r["proto"] + r["info"]).lower() for r in not_dns)
    after = rows[0]["id"]
    nxt = cap.packets(after, 5)
    assert nxt and nxt[0]["id"] == after + 1
    ts, wire, raw = cap.packet(rows[0]["id"])
    assert wire >= len(raw) > 14
    assert cap.packet(10 ** 9) is None
    cap.stop()


def test_ring_is_bounded_and_ids_keep_increasing():
    cap, _ = _replay(PCAP, ring_packets=100)
    st = cap.stats()
    assert st["ring_len"] == 100 and st["ring_last_id"] == st["recv"]
    assert cap.packet(1) is None                      # scrolled out
    assert cap.packet(st["ring_last_id"]) is not None
    cap.stop()


def test_pcap_index_pages_filters_and_reads_back():
    idx = core.PcapIndex(str(REAL))
    n = len(idx)
    assert n > 1000 and idx.linktype() == 1
    rows, nxt = idx.page(0, 100)
    assert len(rows) == 100 and nxt == 100 and rows[0]["id"] == 1
    rows2, nxt2 = idx.page(nxt, 100)
    assert rows2[0]["id"] == 101
    tcp, _ = idx.page(0, 30, "tcp syn")
    assert tcp and all("syn" in r["info"].lower() for r in tcp)
    last, end = idx.page(n - 3, 50)
    assert len(last) == 3 and end == n
    ts, wire, raw = idx.packet(1)
    assert idx.packet(0) is None and idx.packet(n + 1) is None and len(raw) > 0


def test_pcap_index_rejects_non_pcap(tmp_path):
    bad = tmp_path / "x.pcap"
    bad.write_bytes(b"not a capture at all, definitely not")
    with pytest.raises(OSError):
        core.PcapIndex(str(bad))


def test_packet_detail_dissects_layers_and_hex():
    from src.api.packet_detail import dissect
    idx = core.PcapIndex(str(REAL))
    rows, _ = idx.page(0, 200, "dns")
    ts, wire, raw = idx.packet(rows[0]["id"])
    d = dissect(bytes(raw), ts, wire)
    names = [layer["name"] for layer in d["layers"]]
    assert names[0] == "Ethernet" and "IP" in names[1]
    assert d["hex"][0]["off"] == 0 and len(d["hex"][0]["hex"].split()) == 16
    assert d["layers"][0]["start"] == 0 and d["layers"][1]["start"] == 14
    ip = d["layers"][1]
    assert any(f["name"] == "src" for f in ip["fields"])


# ------------------------------------------------------------------ native flow engines
def _alert_signature(alerts):
    return sorted((a["threat_class"], a["flow_identifier"]["src_ip"], a["flow_identifier"]["dst_ip"]) for a in alerts)


@pytest.mark.parametrize("rel", ["samples/netbios_ssn2.pcap", "simulated_attack_traffic.pcap", "samples/modbus_iti_test.pcap"])
def test_native_flow_engines_match_the_python_engines(rel, monkeypatch):
    """The Rust batch runner (flow_engines.rs) must raise exactly the alerts the per-flow Python engines do."""
    import src  # noqa: F401
    from src.capture.live_agent import LiveAgent
    path = ROOT / rel
    if not path.exists():
        pytest.skip("sample capture not present")

    def run(py_engines):
        monkeypatch.setenv("STEALTHTAP_PY_FLOW_ENGINES", "1" if py_engines else "0")
        a = LiveAgent("pcap-replay", None)
        a.start_replay(str(path), loops=1, speed=0.0)
        a._loop_thread.join()
        assert a._native_flow_engines is (not py_engines)
        out = _alert_signature(a.recent_alerts(10_000))
        a.stop()
        return out

    assert run(py_engines=False) == run(py_engines=True)
