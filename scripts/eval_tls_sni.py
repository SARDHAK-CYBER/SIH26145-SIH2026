"""
Evaluate the TLS-SNI detector (ENG-03, SNI variant) on real captured traffic.

Extracts the SNI of every TLS ClientHello in each pcap through the native raw
path, scores each distinct SNI with the trained DNS/DGA model, and reports how
many distinct names would alert at several confidence floors -- so
TLS_SNI_MIN_CONFIDENCE is chosen from data, not guessed.

    python scripts/eval_tls_sni.py <pcap-or-dir> [...]
"""
from __future__ import annotations

import asyncio
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import stealthtap_core as core                         # noqa: E402
from src.capture.rawpcap import iter_raw_pcap          # noqa: E402
from src.engines.eng03_dga_dns import DGADetector      # noqa: E402
from src.inference.model_server import HybridModelServer  # noqa: E402

FLOORS = (60, 70, 80, 90, 95)


def collect(paths):
    snis = Counter()
    for p in paths:
        it = iter_raw_pcap(str(p))
        if it is None:
            print(f"  skip {p.name}: not a raw-readable pcap")
            continue
        asm = core.LiveFlowAssembler(60.0)
        n = 0
        for ts, frame in it:
            for t, r in asm.process(ts, frame):
                if t == "ssl" and r.get("sni"):
                    snis[r["sni"]] += 1
                    n += 1
        print(f"  {p.name}: {n} ClientHellos")
    return snis


def main():
    files = []
    for a in sys.argv[1:]:
        pa = Path(a)
        files += sorted(pa.glob("*.pcap*")) if pa.is_dir() else [pa]
    snis = collect(files)
    print(f"\n{sum(snis.values())} ClientHellos with SNI, {len(snis)} distinct names")
    if not snis:
        return
    det = DGADetector(model_server=HybridModelServer(skip_untrusted_iforest=True))
    loop = asyncio.new_event_loop()
    scored = []
    for name in snis:
        a = loop.run_until_complete(det.score(
            {"flow_uid": "x", "ts": 0.0, "dns_query": name, "dns_qtype": "A"}))
        if a is not None and a.threat_class == "DGA_DOMAIN":
            scored.append((a.confidence_score, name))
    scored.sort(reverse=True)
    print("\ndistinct SNIs that DGA-score above the model's own threshold:")
    for floor in FLOORS:
        print(f"  conf >= {floor}: {sum(1 for c, _ in scored if c >= floor)}")
    print("\ntop scored names (all real, all presumed benign unless the pcap is an attack):")
    for c, n in scored[:25]:
        print(f"  {c:6.2f}  {n}")


if __name__ == "__main__":
    main()
