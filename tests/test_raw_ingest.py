"""
Raw-frame ingestion: scapy dissection capped the whole live pipeline at
~10,000 pps (100us/packet); raw bytes into the native assembler run ~41x
faster. These tests pin that the fast path is EQUIVALENT to the scapy path.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

core = pytest.importorskip("stealthtap_core")
from scapy.all import PcapReader

from src.capture.native_flow_assembler import NativeFlowAssemblerAdapter, RawFrame
from src.capture.rawpcap import iter_raw_pcap

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "samples" / "test.pcap"


def test_rawpcap_reader_matches_scapy_frame_for_frame():
    raw = list(iter_raw_pcap(str(SAMPLE)))
    with PcapReader(str(SAMPLE)) as rd:
        sc = [(float(p.time), bytes(p)) for p in rd]
    assert len(raw) == len(sc) > 0
    for (rts, rb), (sts, sb) in zip(raw, sc):
        assert rb == sb
        assert abs(rts - sts) < 1e-5


def test_rawpcap_returns_none_for_non_classic_or_non_ethernet(tmp_path):
    p = tmp_path / "x.pcapng"
    p.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 60)
    assert iter_raw_pcap(str(p)) is None


def test_rawframe_and_scapy_packet_produce_identical_records():
    a, b = NativeFlowAssemblerAdapter(), NativeFlowAssemblerAdapter()
    n = 0
    with PcapReader(str(SAMPLE)) as rd:
        for pkt in rd:
            via_scapy = a.process(pkt)
            via_raw = b.process(RawFrame(float(pkt.time), bytes(pkt)))
            assert via_scapy == via_raw
            n += 1
    assert n > 10
    assert a.flush() == b.flush()


def test_rawframe_len():
    assert len(RawFrame(1.0, b"abcd")) == 4


def test_agent_on_raw_uses_rawframe_with_native_and_dissects_with_python_fallback(monkeypatch):
    from src.capture import live_agent as la
    frame = next(iter(iter_raw_pcap(str(SAMPLE))))[1]

    native = la.LiveAgent("bench")
    assert native.raw_capable
    native.on_raw(time.time(), frame)
    _, item = native._q.get_nowait()
    assert isinstance(item, RawFrame)

    monkeypatch.setattr(la, "_FORCE_PYTHON_LIVE_ASSEMBLER", True)
    py = la.LiveAgent("bench")
    assert not py.raw_capable
    py.on_raw(time.time(), frame)
    _, item = py._q.get_nowait()
    assert not isinstance(item, RawFrame) and hasattr(item, "getlayer")


def test_backend_raw_sink_is_used_by_afpacket_worker_path():
    from src.capture.backends import BaseBackend
    assert BaseBackend.raw_sink is None
