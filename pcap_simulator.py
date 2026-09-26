"""
Synthetic attack PCAP generator for StealthTap's "Upload PCAP" analysis
mode.

Generates ONE pcap file containing packet-level traffic for all six
threat categories from the problem statement, plus benign baseline
traffic, so the Upload PCAP workflow has a single, realistic,
ground-truth-labeled file to test end to end. A companion
pcap_ground_truth.json records exactly what was generated and which
engine/alert each section should trigger, so results can be checked
automatically rather than by eye.

TIMESTAMP DESIGN NOTE: each threat category's *narrative start* advances
by only a few seconds from the previous one (so the story reads
naturally start to finish), but individual categories can internally
span much longer real durations where that matters for detection logic
-- e.g. the Slowloris connection's two packets are 150 seconds apart
(matching ENG01's actual duration threshold), and the C2 beacon spans
~20 minutes of periodic check-ins. All packets are sorted by embedded
timestamp before writing, so this produces a temporally correct pcap
despite categories being generated as separate, compact function calls.
"""
from __future__ import annotations

import ipaddress
import json
import random
import string
import time

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap, Ether
from scapy.layers.tls.all import TLS, TLSClientHello, TLS_Ext_ServerName, ServerName

random.seed(42)

OUT_PCAP = "simulated_attack_traffic.pcap"
GROUND_TRUTH = "pcap_ground_truth.json"

VICTIM_IP = "10.0.0.5"
INTERNAL_HOST = "192.168.100.10"
BASE_TIME = time.time() - 3600  # pretend this happened an hour ago

packets: list = []
ground_truth = {"generated_at": time.time(), "threats": []}


def _rand_ip() -> str:
    return str(ipaddress.IPv4Address(random.randint(0x0B000000, 0xDF000000)))


def _rand_high_entropy_label(min_len: int = 10, max_len: int = 20) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(min_len, max_len)))


def add_benign_traffic(start_ts: float) -> float:
    """A handful of ordinary flows and DNS lookups, so the file isn't
    100% malicious -- lets false-positive behavior be checked too."""
    ts = start_ts
    for domain in ["github.com", "python.org", "wikipedia.org"]:
        pkt = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=INTERNAL_HOST, dst="8.8.8.8") /
               UDP(sport=random.randint(40000, 60000), dport=53) / DNS(rd=1, qd=DNSQR(qname=domain)))
        pkt.time = ts
        packets.append(pkt)
        ts += random.uniform(1, 3)

    src_port = random.randint(40000, 60000)
    seq = random.randint(1000, 90000)
    syn = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=INTERNAL_HOST, dst="93.184.216.34") / TCP(sport=src_port, dport=443, flags="S", seq=seq)
    syn.time = ts; packets.append(syn); ts += 0.02
    synack = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="93.184.216.34", dst=INTERNAL_HOST) / TCP(sport=443, dport=src_port, flags="SA", seq=5000, ack=seq + 1)
    synack.time = ts; packets.append(synack); ts += 0.02
    ack = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=INTERNAL_HOST, dst="93.184.216.34") / TCP(sport=src_port, dport=443, flags="A", seq=seq + 1, ack=5001)
    ack.time = ts; packets.append(ack); ts += 0.05
    data = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=INTERNAL_HOST, dst="93.184.216.34") / TCP(sport=src_port, dport=443, flags="PA", seq=seq + 1, ack=5001) / Raw(b"A" * 300)
    data.time = ts; packets.append(data); ts += 0.05

    ground_truth["threats"].append({
        "category": "benign_baseline", "start_ts": start_ts, "end_ts": ts,
        "expected_alert": None, "note": "should NOT trigger any alert -- false-positive check",
    })
    return ts


def add_ddos_single_source_flood(start_ts: float) -> float:
    """(a) Volumetric DDoS -- single-source high-rate SYN flood. This is
    the pattern ENG01's per-source-IP counter is designed to catch."""
    ts = start_ts
    attacker = "192.168.100.50"
    n_packets = 250
    for _ in range(n_packets):
        pkt = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=attacker, dst=VICTIM_IP) / TCP(sport=random.randint(1024, 65535), dport=443, flags="S")
        pkt.time = ts
        packets.append(pkt)
        ts += 0.01  # 100 pkt/s -- well within a 10s detection bucket
    ground_truth["threats"].append({
        "category": "ddos_single_source_flood", "start_ts": start_ts, "end_ts": ts,
        "expected_alert": "VOLUMETRIC_DDOS", "engine": "ENG01",
        "note": f"{n_packets} SYNs from one source IP -- should trigger ENG01's flood threshold",
    })
    return ts


def add_ddos_spoofed_source_flood(start_ts: float) -> float:
    """(a) Volumetric DDoS -- spoofed multi-source flood.
    HONEST NOTE: ENG01 currently counts per-source-IP flow rate; a flood
    spread across many distinct spoofed source IPs (few packets each)
    will NOT trigger it as currently implemented -- this is a known,
    documented gap (source-IP-entropy detection is still open). Included
    deliberately so the gap is visible and testable, not hidden."""
    ts = start_ts
    n_packets = 250
    for _ in range(n_packets):
        pkt = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=_rand_ip(), dst=VICTIM_IP) / UDP(sport=random.randint(1024, 65535), dport=53) / Raw(b"\x00" * 20)
        pkt.time = ts
        packets.append(pkt)
        ts += 0.01
    ground_truth["threats"].append({
        "category": "ddos_spoofed_source_flood", "start_ts": start_ts, "end_ts": ts,
        "expected_alert": "VOLUMETRIC_DDOS", "engine": "ENG01",
        "note": "spoofed multi-source flood -- caught by ENG01's per-destination distinct-source (HyperLogLog uniqueness) check, not the per-source counter; this used to be labelled a known gap but the check exists and fires (92% confidence, spoofed_source_pattern=true)",
    })
    return ts


def add_slowloris(start_ts: float) -> float:
    """(a) Slowloris -- ONE established connection held open for 160s by a
    few bytes of partial header every ~40s, matching ENG01's check (duration
    > 120s, bytes < 50). A real handshake is required: an earlier version
    sent a bare SYN and one data packet 150s later with no handshake, which
    Zeek (correctly) logs as two unrelated records (S0 + OTH), so the real
    Zeek-backed pipeline could never see a long, low-byte connection there.
    A real Slowloris is a completed handshake plus trickled headers."""
    ts = start_ts
    attacker, sport = "192.168.100.51", 51000
    eth = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    seq_a, seq_v = 1000, 9000
    def add(pkt, t):
        pkt.time = t; packets.append(pkt)
    add(eth / IP(src=attacker, dst=VICTIM_IP) / TCP(sport=sport, dport=80, flags="S", seq=seq_a), ts)
    add(eth / IP(src=VICTIM_IP, dst=attacker) / TCP(sport=80, dport=sport, flags="SA", seq=seq_v, ack=seq_a + 1), ts + 0.01)
    add(eth / IP(src=attacker, dst=VICTIM_IP) / TCP(sport=sport, dport=80, flags="A", seq=seq_a + 1, ack=seq_v + 1), ts + 0.02)
    sent = 0
    for k in range(1, 5):
        t = ts + 40 * k
        add(eth / IP(src=attacker, dst=VICTIM_IP) / TCP(sport=sport, dport=80, flags="PA", seq=seq_a + 1 + sent, ack=seq_v + 1) / Raw(b"X"), t)
        sent += 1
        add(eth / IP(src=VICTIM_IP, dst=attacker) / TCP(sport=80, dport=sport, flags="A", seq=seq_v + 1, ack=seq_a + 1 + sent), t + 0.01)
    add(eth / IP(src=attacker, dst=VICTIM_IP) / TCP(sport=sport, dport=80, flags="FA", seq=seq_a + 1 + sent, ack=seq_v + 1), ts + 161)
    ground_truth["threats"].append({
        "category": "slowloris", "start_ts": start_ts, "end_ts": ts + 161,
        "expected_alert": "SLOWLORIS", "engine": "ENG01",
        "note": "one ESTABLISHED connection, 161s duration, 4 payload bytes total",
    })
    return ts + 1


def add_c2_beaconing(start_ts: float) -> float:
    """(b) C2 beaconing -- periodic small flows to one destination,
    40 iterations to satisfy ENG02's WINDOW_SIZE=32 buffer."""
    ts = start_ts
    c2_server = "203.0.113.99"
    interval, count = 30.0, 40
    for _ in range(count):
        jitter = random.uniform(-0.5, 0.5)
        src_port = random.randint(51000, 51999)
        syn = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=INTERNAL_HOST, dst=c2_server) / TCP(sport=src_port, dport=443, flags="S")
        syn.time = ts; packets.append(syn)
        data = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=INTERNAL_HOST, dst=c2_server) / TCP(sport=src_port, dport=443, flags="PA") / Raw(b"beacon" * 10)
        data.time = ts + 0.1; packets.append(data)
        ts += interval + jitter
    ground_truth["threats"].append({
        "category": "c2_beaconing", "start_ts": start_ts, "end_ts": ts,
        "expected_alert": "C2_BEACONING", "engine": "ENG02",
        "note": f"{count} periodic check-ins at ~{interval}s intervals",
    })
    return start_ts + 5


def add_dga_domains(start_ts: float) -> float:
    """(c) DGA domains -- high-entropy A-record queries."""
    ts = start_ts
    n = 15
    for _ in range(n):
        domain = f"{_rand_high_entropy_label()}.{random.choice(['ru', 'info', 'biz', 'xyz'])}"
        pkt = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=INTERNAL_HOST, dst="8.8.8.8") / UDP(sport=random.randint(40000, 60000), dport=53) / DNS(rd=1, qd=DNSQR(qname=domain, qtype="A"))
        pkt.time = ts; packets.append(pkt)
        ts += 0.3
    ground_truth["threats"].append({
        "category": "dga_domains", "start_ts": start_ts, "end_ts": ts,
        "expected_alert": "DGA_DOMAIN", "engine": "ENG03", "note": f"{n} high-entropy A-record queries",
    })
    return ts


def add_dns_tunneling(start_ts: float) -> float:
    """(c) DNS tunnelling -- long, high-entropy TXT-record queries."""
    ts = start_ts
    n = 8
    for i in range(n):
        payload = _rand_high_entropy_label(45, 55)
        domain = f"{payload}.chunk{i:02d}.exfil-test.net"
        pkt = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=INTERNAL_HOST, dst="8.8.8.8") / UDP(sport=random.randint(40000, 60000), dport=53) / DNS(rd=1, qd=DNSQR(qname=domain, qtype="TXT"))
        pkt.time = ts; packets.append(pkt)
        ts += 0.5
    ground_truth["threats"].append({
        "category": "dns_tunnelling", "start_ts": start_ts, "end_ts": ts,
        "expected_alert": "DNS_TUNNELING", "engine": "ENG03", "note": f"{n} long high-entropy TXT queries",
    })
    return ts


def add_encrypted_malware(start_ts: float) -> float:
    """(d) Malware in encrypted sessions -- a crafted TLS ClientHello.
    HONEST NOTE: reproducing an EXACT JA3/JA4 hash requires precise
    extension ordering that depends on the exact TLS library that
    generated the original fingerprint. This produces a real, valid
    ClientHello with a deliberately narrow/unusual cipher suite list,
    which Zeek's ssl.log WILL fingerprint -- but the resulting JA4 string
    may not exactly match any hardcoded value in
    eng04_encrypted_malware.py's allow-list. Check the actual ja4 Zeek
    computes and either add it to the allow-list or treat this as a JA4
    anomaly-model test case instead of a rule-engine exact-match case."""
    ts = start_ts
    attacker, dst = "192.168.100.25", "198.51.100.45"
    src_port = random.randint(50000, 60000)
    syn = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=attacker, dst=dst) / TCP(sport=src_port, dport=443, flags="S")
    syn.time = ts; packets.append(syn); ts += 0.02
    synack = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=dst, dst=attacker) / TCP(sport=443, dport=src_port, flags="SA")
    synack.time = ts; packets.append(synack); ts += 0.02

    client_hello = TLS(msg=[TLSClientHello(
        ciphers=[0x1301, 0x1302, 0xC02C],
        ext=[TLS_Ext_ServerName(servernames=[ServerName(servername=b"update-service.test")])],
    )])
    tls_pkt = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=attacker, dst=dst) / TCP(sport=src_port, dport=443, flags="PA") / client_hello
    tls_pkt.time = ts; packets.append(tls_pkt)
    ground_truth["threats"].append({
        "category": "encrypted_malware", "start_ts": start_ts, "end_ts": ts,
        "expected_alert": "ENCRYPTED_MALWARE (verify actual JA4 against allow-list -- see note)",
        "engine": "ENG04", "note": "crafted TLS ClientHello, narrow/unusual cipher suite list",
    })
    return ts + 0.1


def add_reconnaissance(start_ts: float) -> float:
    """(e) Port scan -- one source, 30 destination ports, over ENG05's
    FANOUT_THRESHOLD=25."""
    ts = start_ts
    attacker = "192.168.100.99"
    n_ports = 30
    for port in random.sample(range(1, 2000), n_ports):
        pkt = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=attacker, dst=VICTIM_IP) / TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
        pkt.time = ts; packets.append(pkt)
        ts += 0.05
    ground_truth["threats"].append({
        "category": "reconnaissance", "start_ts": start_ts, "end_ts": ts,
        "expected_alert": "RECONNAISSANCE", "engine": "ENG05",
        "note": f"{n_ports} distinct destination ports, threshold is 25",
    })
    return ts


def add_data_exfiltration(start_ts: float) -> float:
    """(f) Data exfiltration -- one flow, asymmetric byte ratio, over
    ENG06's 20:1 threshold AND its 1 MiB single-flow volume floor (the
    floor exists because a 654-byte request vs a 25-byte reply is a 26:1
    'ratio' on ordinary traffic). Real, advancing TCP sequence numbers are
    required: a version that reused seq=0 on every segment made Zeek count
    240 overlapping retransmissions as ~1.4KB of payload (orig_bytes=1399),
    so the Zeek-backed pipeline could never see the volume."""
    ts = start_ts
    attacker, dst = "192.168.100.15", "203.0.113.50"
    src_port = random.randint(50000, 60000)
    eth = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    seq_a, seq_v = 5000, 70000
    def add(pkt, t):
        pkt.time = t; packets.append(pkt)
    add(eth / IP(src=attacker, dst=dst) / TCP(sport=src_port, dport=443, flags="S", seq=seq_a), ts); ts += 0.02
    add(eth / IP(src=dst, dst=attacker) / TCP(sport=443, dport=src_port, flags="SA", seq=seq_v, ack=seq_a + 1), ts); ts += 0.02
    add(eth / IP(src=attacker, dst=dst) / TCP(sport=src_port, dport=443, flags="A", seq=seq_a + 1, ack=seq_v + 1), ts); ts += 0.01
    sent = 0
    for _ in range(900):
        add(eth / IP(src=attacker, dst=dst) / TCP(sport=src_port, dport=443, flags="PA", seq=seq_a + 1 + sent, ack=seq_v + 1) / Raw(b"D" * 1400), ts)
        sent += 1400; ts += 0.01
    add(eth / IP(src=dst, dst=attacker) / TCP(sport=443, dport=src_port, flags="PA", seq=seq_v + 1, ack=seq_a + 1 + sent) / Raw(b"ok"), ts)
    ground_truth["threats"].append({
        "category": "data_exfiltration", "start_ts": start_ts, "end_ts": ts,
        "expected_alert": "DATA_EXFILTRATION", "engine": "ENG06",
        "note": "~1.26 MB out, ~2 bytes back -- over both the 20:1 ratio and the 1 MiB single-flow volume floor",
    })
    return ts + 1


def _next_window_start(ts: float, window: float = 10.0) -> float:
    """Start of the next ENG-01 counting window (+0.5s). ENG-01 counts flows per
    fixed 10s wall-clock bucket, so a 2.5s flood that straddles a bucket boundary
    is split (e.g. 172 + 78) and never reaches the 200-flow threshold. The
    fixture must not depend on what second it happened to be generated in."""
    return (int(ts // window) + 1) * window + 0.5


def main() -> None:
    ts = BASE_TIME
    ts = add_benign_traffic(ts)
    ts = add_ddos_single_source_flood(_next_window_start(ts))
    ts = add_ddos_spoofed_source_flood(_next_window_start(ts))
    ts = add_slowloris(ts + 2)
    ts = add_c2_beaconing(ts + 2)
    ts = add_dga_domains(ts + 2)
    ts = add_dns_tunneling(ts + 2)
    ts = add_encrypted_malware(ts + 2)
    ts = add_reconnaissance(ts + 2)
    ts = add_data_exfiltration(ts + 2)

    packets.sort(key=lambda p: p.time)
    wrpcap(OUT_PCAP, packets)
    with open(GROUND_TRUTH, "w") as f:
        json.dump(ground_truth, f, indent=2)

    print(f"[pcap_simulator] wrote {len(packets)} packets to {OUT_PCAP}")
    print(f"[pcap_simulator] ground truth written to {GROUND_TRUTH}")
    for t in ground_truth["threats"]:
        print(f"  - {t['category']}: expect {t['expected_alert']}")


if __name__ == "__main__":
    main()