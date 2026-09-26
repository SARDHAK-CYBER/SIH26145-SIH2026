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


@pytest.mark.parametrize("name", ["BACnet-MSTP-SNAP-Mixed.pcap", "BACnetIP-MSTP-Mix.pcap", "BACnetARRAY-element-0.pcap",
                                  "BACnet-BBMD-on-same-subnet.pcap", "BACnetARRAY-elements.pcap"])
def test_bacnet_native_equals_python_and_real_traffic_is_quiet(name):
    f = PUB / "bacnet" / name
    if not f.exists():
        pytest.skip("public sample not downloaded")
    from scapy.utils import PcapReader
    from scapy.layers.inet import UDP
    from src.capture.ot import parse_bacnet
    py = []
    for pkt in PcapReader(str(f)):
        if UDP in pkt and 47808 in (pkt[UDP].sport, pkt[UDP].dport):
            r = parse_bacnet(bytes(pkt[UDP].payload))
            if r:
                py.append(r[0])
    rs = [r["function"] for _t, r in _native_records(f, {"bacnet"})]
    assert sorted(py) == sorted(rs)
    from src.engines.eng07_ot_anomaly import BACNET_CRITICAL_SERVICES, BACNET_HIGH_SERVICES
    assert not (set(rs) & (BACNET_CRITICAL_SERVICES | BACNET_HIGH_SERVICES))     # real captures contain reads/discovery only


def test_bacnet_write_property_alerts():
    """CONSTRUCTED packet (the real captures hold no writes): WriteProperty must decode and alert in both twins."""
    import asyncio
    from src.capture.ot import parse_bacnet
    from src.engines.eng07_ot_anomaly import OTIndustrialAnomalyDetector
    from src.flow_mapping import map_record
    pkt = bytes([0x81, 0x0A, 0, 12, 0x01, 0x04, 0x00, 0x05, 0x01, 0x0F, 0x0C, 0x00, 0x00, 0x00, 0x01])   # conf-req, service 15
    assert parse_bacnet(pkt)[0] == "WRITE_PROPERTY"
    flow = map_record({"uid": "B1", "ts": 1.0, "id.orig_h": "10.0.0.9", "id.resp_h": "10.0.0.20", "id.orig_p": 47808,
                       "id.resp_p": 47808, "function": "WRITE_PROPERTY", "detail": "confirmed", "code": 15}, "bacnet")
    loop = asyncio.new_event_loop()
    a = loop.run_until_complete(OTIndustrialAnomalyDetector().score(flow))
    loop.close()
    assert a is not None and a.severity == "HIGH"


@pytest.mark.parametrize("name,expect", [("opcua-signed.pcap", {"READ", "CREATE_SESSION", "ACTIVATE_SESSION", "CLOSE_SESSION"}),
                                         ("opcua-encrypted.pcap", {"GET_ENDPOINTS"})])
def test_opcua_native_equals_python_on_real_wireshark_captures(name, expect):
    f = PUB / "opcua" / name
    if not f.exists():
        pytest.skip("public sample not downloaded")
    from scapy.utils import PcapReader
    from scapy.layers.inet import TCP
    from src.capture.ot import parse_opcua
    py = []
    for pkt in PcapReader(str(f)):
        if TCP in pkt and pkt[TCP].dport == 4840 and bytes(pkt[TCP].payload):
            r = parse_opcua(bytes(pkt[TCP].payload))
            if r:
                py.append(r[0])
    rs = [r["function"] for _t, r in _native_records(f, {"opcua"})]
    assert sorted(py) == sorted(rs) and expect <= set(rs)
    from src.engines.eng07_ot_anomaly import OPCUA_CRITICAL_SERVICES, OPCUA_HIGH_SERVICES
    assert not (set(rs) & (OPCUA_CRITICAL_SERVICES | OPCUA_HIGH_SERVICES))


def test_opcua_write_request_alerts():
    """CONSTRUCTED chunk (real captures hold no writes): WriteRequest (TypeId 673) must decode and alert."""
    import asyncio
    from src.capture.ot import parse_opcua
    from src.engines.eng07_ot_anomaly import OTIndustrialAnomalyDetector
    from src.flow_mapping import map_record
    chunk = b"MSG" + b"F" + (40).to_bytes(4, "little") + bytes(16) + bytes([0x01, 0x00, 0xA1, 0x02]) + bytes(12)
    assert parse_opcua(chunk)[0] == "WRITE"
    flow = map_record({"uid": "O1", "ts": 1.0, "id.orig_h": "10.0.0.9", "id.resp_h": "10.0.0.20", "id.orig_p": 50000,
                       "id.resp_p": 4840, "function": "WRITE", "detail": "plain", "code": 673}, "opcua")
    loop = asyncio.new_event_loop()
    a = loop.run_until_complete(OTIndustrialAnomalyDetector().score(flow))
    loop.close()
    assert a is not None and a.severity == "CRITICAL"


@pytest.mark.parametrize("name,expect_set", [("ChangeIPUsingDCP.pcap", True), ("profinet-wireshark-bug.pcap", True), ("PROFINET-RT.pcap", False)])
def test_profinet_dcp_native_equals_python_on_real_captures(name, expect_set):
    f = PUB / "profinet" / name
    if not f.exists():
        pytest.skip("public sample not downloaded")
    from scapy.utils import PcapReader
    from src.capture.ot import parse_profinet_dcp
    py = []
    for pkt in PcapReader(str(f)):
        r = parse_profinet_dcp(bytes(pkt))
        if r:
            py.append((r[0], r[1]))
    rs = [(r["function"], r["detail"]) for _t, r in _native_records(f, {"profinet"})]
    assert sorted(py) == sorted(rs) and rs
    assert any(fn == "DCP_SET" for fn, _ in rs) is expect_set


def test_real_cip_stop_plc_and_s7_stop_are_detected():
    """REAL command captures (ITI ICS-Security-Tools): a CIP Stop (0x07) and S7 PLC-stop requests must alert."""
    import asyncio
    from src.capture.live_agent import LiveAgent
    import src  # noqa: F401
    for name, expect in (("cip_stop_plc.pcap", "0x7"), ("snap7_s300_stop.pcapng", "PLC_STOP"), ("step7_s300_stop.pcapng", "PLC_STOP")):
        f = PUB / "more" / name
        if not f.exists():
            pytest.skip("public sample not downloaded")
        a = LiveAgent("pcap-replay", None)
        a.start_replay(str(f), loops=1, speed=0.0)
        a._loop_thread.join()
        got = {str(x["evidence"].get("function_code") or x["evidence"].get("cip_service_code")) for x in a.recent_alerts(20)}
        a.stop()
        assert expect in got, (name, got)


# ---- real-derived / independently-encoded checks for events no public capture contains -------------------------------
def _write_pcap(tmp_path, frames, name="x.pcap"):
    from src.api.packet_detail import to_pcap_bytes
    f = tmp_path / name
    f.write_bytes(to_pcap_bytes([(1000.0 + i, fr) for i, fr in enumerate(frames)]))
    return f


def test_dcp_factory_reset_decoded_from_scapy_independent_encoder(tmp_path):
    """PROFINET-DCP frames built by scapy's own pnio/pnio_dcp encoder (independent of our parser), Set with the
    Control option: reset-to-factory must be CRITICAL end to end (Rust replay + Python twin)."""
    pytest.importorskip("scapy.contrib.pnio_dcp")
    from scapy.contrib.pnio import ProfinetIO
    from scapy.contrib.pnio_dcp import ProfinetDCP
    from scapy.layers.l2 import Ether
    from src.capture.ot import parse_profinet_dcp

    def frame(**kw):
        return bytes(Ether(src="02:00:00:00:00:01", dst="01:0e:cf:00:00:00", type=0x8892) / ProfinetIO(frameID=0xFEFD)
                     / ProfinetDCP(service_id=4, service_type=0, xid=1, reserved=0, **kw))
    cases = {"CONTROL,FACTORY_RESET": dict(option=5, sub_option=6, dcp_block_length=4, block_qualifier=0),
             "CONTROL": dict(option=5, sub_option=3, dcp_block_length=4, block_qualifier=0)}
    frames = [frame(**kw) for kw in cases.values()]
    assert [parse_profinet_dcp(fr)[1] for fr in frames] == list(cases)
    rs = [r["detail"] for _t, r in _native_records(_write_pcap(tmp_path, frames), {"profinet"})]
    assert rs == list(cases)
    import asyncio
    from src.engines.eng07_ot_anomaly import OTIndustrialAnomalyDetector
    from src.flow_mapping import map_record
    det, loop = OTIndustrialAnomalyDetector(), asyncio.new_event_loop()
    sev = []
    for blocks in cases:
        f = map_record({"uid": "P", "ts": 1.0, "id.orig_h": "02:00:00:00:00:01", "id.resp_h": "01:0e:cf:00:00:00", "id.orig_p": 0,
                        "id.resp_p": 0, "function": "DCP_SET", "detail": blocks, "code": 0x204}, "profinet")
        sev.append(loop.run_until_complete(det.score(f)).severity)
    loop.close()
    assert sev == ["CRITICAL", "HIGH"]


def _mutate_first(path, dport, proto, patch):
    """Take a REAL captured request and change only the service byte."""
    from scapy.utils import PcapReader
    from scapy.layers.inet import IP, TCP, UDP
    for pkt in PcapReader(str(path)):
        l4 = pkt.getlayer(TCP) if proto == "tcp" else pkt.getlayer(UDP)
        if IP in pkt and l4 is not None and l4.dport == dport and bytes(l4.payload):
            payload = bytearray(bytes(l4.payload))
            if patch(payload):
                l4.remove_payload()
                pkt = pkt / bytes(payload)
                del pkt[IP].len, pkt[IP].chksum, l4.chksum
                return bytes(pkt.__class__(bytes(pkt)))
    return None


def test_bacnet_write_from_a_real_read_request(tmp_path):
    f = PUB / "bacnet" / "BACnetARRAY-element-0.pcap"
    if not f.exists():
        pytest.skip("public sample not downloaded")

    def patch(p):                                  # confirmed-request ReadProperty (12) -> WriteProperty (15)
        if p[:1] == b"\x81" and p[4] == 1 and (p[6] >> 4) == 0 and p[9] == 12:
            p[9] = 15
            return True
    fr = _mutate_first(f, 47808, "udp", patch)
    if fr is None:
        pytest.skip("no simple confirmed ReadProperty in this capture")
    got = [r["function"] for _t, r in _native_records(_write_pcap(tmp_path, [fr]), {"bacnet"})]
    assert got == ["WRITE_PROPERTY"]


def test_opcua_write_from_a_real_read_request(tmp_path):
    f = PUB / "opcua" / "opcua-signed.pcap"
    if not f.exists():
        pytest.skip("public sample not downloaded")

    def patch(p):                                  # ReadRequest TypeId 631 -> WriteRequest 673 (four-byte NodeId 0x01 ns id)
        if p[:3] == b"MSG" and len(p) > 28 and p[24] == 0x01 and int.from_bytes(p[26:28], "little") == 631:
            p[26:28] = (673).to_bytes(2, "little")
            return True
    fr = _mutate_first(f, 4840, "tcp", patch)
    if fr is None:
        pytest.skip("no plain ReadRequest in this capture")
    got = [r["function"] for _t, r in _native_records(_write_pcap(tmp_path, [fr]), {"opcua"})]
    assert got == ["WRITE"]


def test_real_global_ipv6_flows_and_hop_by_hop_are_assembled_natively():
    """REAL IPv6 captures from the tcpdump test-suite (global 2604:1380:... addresses, incl. a hop-by-hop jumbogram)."""
    d = PUB / "ipv6"
    if not (d / "bigtcp-ipv6.pcap").exists():
        pytest.skip("public sample not downloaded")

    def flows(name):
        idx = core.PcapIndex(str(d / name))
        a = core.LiveFlowAssembler(60.0)
        for i in range(1, len(idx) + 1):
            ts, _w, raw = idx.packet(i)
            a.process(ts, bytes(raw))
        return [r for _t, r in a.flush()]

    plain = flows("bigtcp-ipv6.pcap")
    hbh = flows("bigtcp-ipv6-hbh.pcap")
    assert len(plain) == len(hbh) == 1
    for r in plain + hbh:
        assert r["id.orig_h"].startswith("2604:1380:4091:ce00::") and r["id.resp_h"].startswith("2604:1380:4091:ce00::")
        assert r["orig_bytes"] >= 79_000                                     # the 80 KB payload was seen, not dropped
    assert hbh[0]["orig_bytes"] > 0                                          # extension header walked, TCP still found
