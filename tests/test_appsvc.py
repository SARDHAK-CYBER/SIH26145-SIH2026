"""Application-service decoders + ENG-14: Rust == Python, real-capture detections, and the benign look-alikes that must stay quiet.

Real captures (Metasploit sessions from the evaluation corpus) are used when present; every rule also has hand-built
payload tests so CI without the corpus still covers them."""
from __future__ import annotations

import asyncio
import base64
import os
from pathlib import Path

import pytest

core = pytest.importorskip("stealthtap_core")
from scapy.layers.inet import IP, TCP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402

from src.capture.appsvc import parse_appsvc  # noqa: E402
from src.engines.eng14_appsvc import AppServiceAttackDetector  # noqa: E402
from src.flow_mapping import map_record  # noqa: E402

CORPUS = Path(os.environ.get("STEALTHTAP_CORPUS", "C:/Users/admin/Downloads/archive (2)"))
CLIENT, SERVER = "10.9.0.5", "10.9.0.20"


def _frame(payload: bytes, sport: int, dport: int, src=CLIENT, dst=SERVER) -> bytes:
    return bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=src, dst=dst)
                 / TCP(sport=sport, dport=dport, flags="PA", seq=1, ack=1) / payload)


def _native(frames):
    asm = core.LiveFlowAssembler(60.0)
    out = []
    for i, f in enumerate(frames):
        out += [r for k, r in asm.process(1_700_000_000.0 + i, f) if k == "appsvc"]
    return out


CASES = {
    "vrfy": (b"VRFY root\r\n", 40000, 25, ("smtp_vrfy", "root", 0)),
    "expn": (b"EXPN admins\r\n", 40000, 25, ("smtp_expn", "admins", 0)),
    "rcpt": (b"RCPT TO: <bob@example.org>\r\n", 40000, 25, ("smtp_rcpt", "bob", 0)),
    "reject": (b"550 5.1.1 <x>: Recipient address rejected\r\n", 25, 40000, ("smtp_reject", "", 550)),
    "http401": (b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=x\r\n\r\n", 8180, 40000, ("http_401", "", 401)),
    "default_cred": (b"GET /manager/html HTTP/1.1\r\nHost: h\r\nAuthorization: Basic " + base64.b64encode(b"tomcat:tomcat") + b"\r\n\r\n",
                     40000, 8180, ("http_basic", "tomcat", 1)),
    "other_cred": (b"GET /x HTTP/1.1\r\nHost: h\r\nauthorization: basic " + base64.b64encode(b"alice:Tr0ub4dor&3") + b"\r\n\r\n",
                   40000, 8080, ("http_basic", "alice", 0)),
    "war_upload": (b"POST /manager/html/upload?path=x HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\n", 40000, 8180,
                   ("http_admin_deploy", "/manager/html/upload?path=x", 1)),
    "distcc_shell": (b"DIST00000001ARGC00000003ARGV00000002shARGV00000002-cARGV00000006id;ls\n", 40000, 3632,
                     ("distcc:sh", "-c id;ls", 1)),
    "distcc_gcc": (b"DIST00000001ARGC00000004ARGV00000003gccARGV00000002-cARGV00000006main.cARGV00000002-o", 40000, 3632,
                   ("distcc:gcc", "-c main.c -o", 0)),
}
NEGATIVE = {
    "plain_get": (b"GET /index.html HTTP/1.1\r\nHost: h\r\n\r\n", 40000, 80),
    "http200": (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 80, 40000),
    "smtp_hello": (b"HELO mail.example.org\r\n", 40000, 25),
    "reject_wrong_port": (b"550 not smtp\r\n", 9999, 40000),
    "tls": (b"\x16\x03\x01\x02\x00\x01", 40000, 443),
    "bad_b64": (b"GET /x HTTP/1.1\r\nAuthorization: Basic !!!!\r\n\r\n", 40000, 80),
    "bearer": (b"GET /x HTTP/1.1\r\nAuthorization: Bearer abc\r\n\r\n", 40000, 80),
}


@pytest.mark.parametrize("name", CASES)
def test_python_decoder(name):
    payload, sport, dport, expect = CASES[name]
    assert parse_appsvc(payload, sport, dport) == expect


@pytest.mark.parametrize("name", NEGATIVE)
def test_python_decoder_negatives(name):
    payload, sport, dport = NEGATIVE[name]
    assert parse_appsvc(payload, sport, dport) is None


@pytest.mark.parametrize("name", list(CASES) + list(NEGATIVE))
def test_rust_equals_python(name):
    payload, sport, dport = (CASES.get(name) or NEGATIVE[name])[:3]
    reply = name in ("reject", "http401")
    frame = _frame(payload, sport, dport, *( (SERVER, CLIENT) if reply else (CLIENT, SERVER) ))
    rust = _native([frame])
    py = parse_appsvc(payload, sport, dport)
    if py is None:
        assert rust == []
    else:
        assert len(rust) == 1
        assert (rust[0]["function"], rust[0]["detail"], rust[0]["code"]) == py
        # replies are oriented like Zeek: the originator is the client
        assert rust[0]["id.orig_h"] == CLIENT and rust[0]["id.resp_h"] == SERVER


def test_password_never_leaves_the_decoder():
    payload = CASES["other_cred"][0]
    r = _native([_frame(payload, 40000, 8080)])[0]
    assert "Tr0ub4dor" not in repr(r)


def _score(events):
    async def go():
        eng = AppServiceAttackDetector()
        return [a async for a in _iter(eng, events)]

    async def _iter(eng, evs):
        for e in evs:
            a = await eng.score(map_record(e, "appsvc"))
            if a:
                yield a
    return asyncio.run(go())


def _events(seq, t0=1_700_000_000.0, step=0.5):
    frames = []
    for payload, sport, dport in seq:
        reply = sport in (25, 8180) and dport > 1024
        frames.append(_frame(payload, sport, dport, *((SERVER, CLIENT) if reply else (CLIENT, SERVER))))
    asm = core.LiveFlowAssembler(60.0)
    out = []
    for i, f in enumerate(frames):
        out += [r for k, r in asm.process(t0 + i * step, f) if k == "appsvc"]
    return out


def test_distcc_command_execution_alerts_but_compile_job_does_not():
    bad = _score(_events([CASES["distcc_shell"][:3]]))
    assert [a.severity for a in bad] == ["CRITICAL"] and bad[0].mitre_attack.technique_id == "T1190"
    assert _score(_events([CASES["distcc_gcc"][:3]])) == []


def test_smtp_enumeration_and_legitimate_mail():
    enum = [(f"VRFY user{i}\r\n".encode(), 40000, 25) for i in range(3)]
    assert len(_score(_events(enum))) == 1                      # 3 distinct VRFY
    # a normal delivery: one recipient, replies OK
    ok = [(b"HELO a\r\n", 40000, 25), (b"RCPT TO:<a@b.c>\r\n", 40000, 25), (b"250 ok\r\n", 25, 40000)]
    assert _score(_events(ok)) == []
    # a bulk mailer: 30 recipients, all accepted -> no refusals -> not enumeration
    bulk = [(f"RCPT TO:<u{i}@b.c>\r\n".encode(), 40000, 25) for i in range(30)]
    assert _score(_events(bulk)) == []
    # a mailing list with ~10% stale addresses: 40 recipients, 4 refused -> not enumeration
    listy = []
    for i in range(40):
        listy.append((f"RCPT TO:<u{i}@b.c>\r\n".encode(), 40000, 25))
        if i % 10 == 0:
            listy.append((b"550 5.1.1 unknown\r\n", 25, 40000))
    assert _score(_events(listy)) == []
    # harvesting: 20 recipients with refusals
    harvest = []
    for i in range(20):
        harvest += [(f"RCPT TO:<u{i}@b.c>\r\n".encode(), 40000, 25), (b"550 5.1.1 unknown\r\n", 25, 40000)]
    assert len(_score(_events(harvest))) == 1


def test_http_default_credentials_and_deployment():
    seq = [CASES["default_cred"][:3], CASES["war_upload"][:3]]
    alerts = _score(_events(seq))
    kinds = sorted(a.mitre_attack.technique_id for a in alerts)
    assert kinds == ["T1078.001", "T1505.003"]
    assert next(a for a in alerts if a.mitre_attack.technique_id == "T1505.003").severity == "HIGH"
    # a deployment with no preceding default credential / refusal is reported but only MEDIUM
    lone = _score(_events([CASES["war_upload"][:3]]))
    assert [a.severity for a in lone] == ["MEDIUM"]
    # ordinary authenticated browsing with a non-default credential: silent, however many requests
    quiet = _score(_events([CASES["other_cred"][:3]] * 50))
    assert quiet == []


def test_http_credential_guessing_needs_repeated_refusals():
    seq = []
    for i in range(6):
        seq += [(b"GET /x HTTP/1.1\r\nAuthorization: Basic " + base64.b64encode(f"root:pw{i}".encode()) + b"\r\n\r\n", 40000, 8180),
                CASES["http401"][:3]]
    assert len(_score(_events(seq))) == 1
    one_challenge = [(b"GET /x HTTP/1.1\r\n\r\n", 40000, 8180), CASES["http401"][:3],
                     (b"GET /x HTTP/1.1\r\nAuthorization: Basic " + base64.b64encode(b"alice:ok") + b"\r\n\r\n", 40000, 8180)]
    assert _score(_events(one_challenge)) == []


# ---- real captures --------------------------------------------------------------------------------------------------
REAL = {
    "distcc_exec_backdoor.pcap": "T1190", "distcc_exec_backdoor2.pcap": "T1190",
    "smtp.pcap": "T1087", "smtp22.pcap": "T1087",
    "tomcat.pcap": "T1078.001", "tomcat2.pcap": "T1078.001",
}


def _real_alerts(name):
    from src.capture.rawpcap import iter_raw_pcap
    f = CORPUS / name
    if not f.exists():
        pytest.skip("evaluation corpus not present")
    asm = core.LiveFlowAssembler(60.0)
    evs = [r for ts, raw in iter_raw_pcap(str(f)) for k, r in asm.process(ts, raw) if k == "appsvc"]
    return _score(evs), evs


@pytest.mark.parametrize("name,technique", REAL.items())
def test_real_capture_detected(name, technique):
    alerts, _ = _real_alerts(name)
    assert technique in {a.mitre_attack.technique_id for a in alerts}


@pytest.mark.parametrize("name", ["normal.pcap", "normal2.pcap"])
def test_benign_real_captures_stay_clean(name):
    alerts, _ = _real_alerts(name)
    assert alerts == []


@pytest.mark.parametrize("name", ["distcc_exec_backdoor.pcap", "smtp.pcap", "tomcat.pcap"])
def test_rust_equals_python_on_real_capture(name):
    from src.capture.rawpcap import iter_raw_pcap
    f = CORPUS / name
    if not f.exists():
        pytest.skip("evaluation corpus not present")
    from scapy.utils import PcapReader
    py = []
    for pkt in PcapReader(str(f)):
        if IP in pkt and TCP in pkt and bytes(pkt[TCP].payload):
            r = parse_appsvc(bytes(pkt[TCP].payload), pkt[TCP].sport, pkt[TCP].dport)
            if r:
                py.append(r)
    _, evs = _real_alerts(name)
    assert sorted((e["function"], e["detail"], e["code"]) for e in evs) == sorted(py)
