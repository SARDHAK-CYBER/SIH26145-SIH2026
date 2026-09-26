"""Kerberos / S7comm / IEC-104 decoders: Rust == Python, on REAL public captures (Wireshark sample set,
downloaded to data/public_samples -- tests skip when absent)."""
from __future__ import annotations

from pathlib import Path

import pytest

core = pytest.importorskip("stealthtap_core")
ROOT = Path(__file__).resolve().parent.parent
PUB = ROOT / "data" / "public_samples"


def _native_records(path, kinds):
    cap = core.NativeCapture(pcap=str(path), loops=1, speed=0.0)
    cap.start()
    out = []
    while True:
        out += [(t, r) for t, r in cap.poll(20, 5000) if t in kinds]
        if cap.finished() and cap.pending() == 0:
            break
    cap.stop()
    return out


def test_kerberos_native_equals_python_on_real_capture():
    f = PUB / "krb-816" / "krb-816.cap"
    if not f.exists():
        pytest.skip("public sample not downloaded")
    from scapy.utils import PcapReader
    from scapy.layers.inet import IP, TCP, UDP
    from src.capture.kerberos import parse_kdc_reply
    py = []
    for pkt in PcapReader(str(f)):
        l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP)
        if IP in pkt and l4 is not None and l4.sport == 88:
            r = parse_kdc_reply(bytes(l4.payload), pkt.haslayer(TCP))
            if r:
                py.append((r["request_type"], r["client"], r["service"], r["cipher"]))
    rs = [(r["request_type"], r["client"], r["service"], r["cipher"]) for _t, r in _native_records(f, {"kerberos"})]
    assert py and py == rs


def test_real_ad_capture_is_not_kerberoasting():
    """Every RC4 TGS reply in a real Windows-2003 domain login is for a host/cifs/ldap (machine) service."""
    f = PUB / "krb-816" / "krb-816.cap"
    if not f.exists():
        pytest.skip("public sample not downloaded")
    import asyncio
    from src.engines.eng11_kerberos import KerberosAttackDetector
    from src.flow_mapping import map_record
    det = KerberosAttackDetector()
    loop = asyncio.new_event_loop()
    hits = [r for _t, r in _native_records(f, {"kerberos"})
            if loop.run_until_complete(det.score(map_record(r, "kerberos")))]
    loop.close()
    assert hits == []


@pytest.mark.parametrize("name,kind,expect,quiet", [
    ("s7comm_downloading_block_db1.pcap", "s7comm", {"REQUEST_DOWNLOAD", "PLC_CONTROL"}, False),
    ("s7comm_reading_plc_status.pcap", "s7comm", set(), True),
    ("iec104.pcap", "iec104", {"C_SC_NA_1", "C_SE_NA_1"}, False),
])
def test_ot_decoders_native_equals_python(name, kind, expect, quiet):
    f = PUB / name
    if not f.exists():
        pytest.skip("public sample not downloaded")
    from scapy.utils import PcapReader
    from scapy.layers.inet import TCP
    from src.capture.ot import parse_iec104, parse_s7comm
    fn, port = (parse_s7comm, 102) if kind == "s7comm" else (parse_iec104, 2404)
    py = []
    for pkt in PcapReader(str(f)):
        if TCP in pkt and pkt[TCP].dport == port and bytes(pkt[TCP].payload):
            r = fn(bytes(pkt[TCP].payload))
            if r:
                py.append(r[0])
    rs = [r["function"] for _t, r in _native_records(f, {kind})]
    assert sorted(py) == sorted(rs)
    assert expect <= set(rs)


@pytest.mark.parametrize("name", ["CL5000EIP-Lock-PLC-Attempt.pcap", "CL5000EIP-Change-Date-Attempt.pcap", "CL5000EIP-View-Device-Status.pcap"])
def test_enip_cip_native_equals_python_on_real_digitalbond_captures(name):
    f = PUB / "ics" / name
    if not f.exists():
        pytest.skip("public sample not downloaded")
    from scapy.utils import PcapReader
    from scapy.layers.inet import TCP
    from src.capture.ot import parse_enip
    py = []
    for pkt in PcapReader(str(f)):
        if TCP in pkt and pkt[TCP].dport == 44818 and bytes(pkt[TCP].payload):
            r = parse_enip(bytes(pkt[TCP].payload))
            if r and not r[3]:
                py.append((r[0], r[1], r[2]))
    rs = [(r["service"], r["class_id"], r["instance_id"]) for _t, r in _native_records(f, {"cip"})]
    assert sorted(py) == sorted(rs)
    if "View-Device-Status" in name:
        assert rs == []                                   # benign polling raises no CIP request alerts
    else:
        assert any(s in (0x04, 0x10, 0x4B, 0x4F, 0x50) for s, _c, _i in rs)   # the dangerous set ENG-07 keys on
