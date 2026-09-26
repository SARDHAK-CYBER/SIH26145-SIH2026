"""
TLS SNI extraction (native == Python) and the ENG-03 SNI detector.

TLS has no trained model of its own (no labeled TLS data exists), so the SNI
-- a real domain name in every ClientHello -- is scored by the trained DNS/DGA
model. These tests pin: the SNI is extracted identically by both parsers, it
fails closed on a truncated ClientHello, benign names never fire, and a
DGA-looking SNI does.
"""
from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("scapy")
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

core = pytest.importorskip("stealthtap_core")


def _hello(host: bytes) -> bytes:
    def ext(t, body):
        return t.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body
    sni = ext(0, (len(host) + 3).to_bytes(2, "big") + b"\x00" + len(host).to_bytes(2, "big") + host)
    alpn = ext(16, b"\x00\x0c\x02h2\x08http/1.1")
    sv = ext(43, b"\x04\x03\x04\x03\x03")
    sig = ext(13, b"\x00\x08\x04\x03\x08\x04\x04\x01\x05\x03")
    exts = sni + alpn + sv + sig
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x06\x13\x01\x13\x02\xc0\x2b" + b"\x01\x00"
            + len(exts).to_bytes(2, "big") + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def _pkt(payload: bytes, sport=50000):
    p = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="10.0.0.5", dst="93.184.216.34") / TCP(sport=sport, dport=443, flags="PA", seq=1) / Raw(payload)
    p.time = 1.0
    return p


def _ssl(records):
    return [r for t, r in records if t == "ssl"]


@pytest.mark.parametrize("host", [b"example.org", b"Mixed.Case.Example.COM", b"a" * 60 + b".net"])
def test_sni_native_equals_python(host):
    from src.capture.flow_assembler import FlowAssembler
    pkt = _pkt(_hello(host))
    py = _ssl(FlowAssembler().process(pkt))
    rs = _ssl(core.LiveFlowAssembler(60.0).process(1.0, bytes(pkt)))
    assert py and rs
    assert py[0]["sni"] == rs[0]["sni"] == host.decode().lower()


def test_sni_truncated_clienthello_fails_closed():
    from src.capture.flow_assembler import FlowAssembler
    pkt = _pkt(_hello(b"example.org")[:-20])
    assert _ssl(FlowAssembler().process(pkt)) == []
    assert _ssl(core.LiveFlowAssembler(60.0).process(1.0, bytes(pkt))) == []


def _flow(sni):
    return {"flow_uid": "C1", "ts": 1.0, "src_ip": "10.0.0.5", "src_port": 50000,
            "dst_ip": "93.184.216.34", "dst_port": 443, "sni": sni, "ja4": "t13d0000h2_x_y"}


def _run(detector, flow):
    # not asyncio.run(): it clears the thread's current loop, which older
    # tests in this suite still fetch with get_event_loop()
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(detector.score(flow))
    finally:
        loop.close()


@pytest.mark.parametrize("sni", [
    "www.google.com", "github.com", "api.github.com", "login.microsoftonline.com",
    "fonts.gstatic.com", "d1.awsstatic.com", "en.wikipedia.org", "",
])
def test_benign_sni_does_not_fire(sni):
    from src.engines.eng03_dga_dns import TlsSniDetector
    assert _run(TlsSniDetector(model_server=None), _flow(sni)) is None


def test_dga_looking_sni_fires_with_tls_flow_identity():
    from src.engines.eng03_dga_dns import TlsSniDetector
    a = _run(TlsSniDetector(model_server=None), _flow("xkqzjvbnwpltrhgfdsmc.xyz"))
    assert a is not None and a.threat_class == "DGA_DOMAIN"
    assert a.evidence["source"] == "tls_sni" and a.evidence["sni"] == "xkqzjvbnwpltrhgfdsmc.xyz"
    assert a.flow_identifier.protocol == "TCP" and a.flow_identifier.dst_port == 443
