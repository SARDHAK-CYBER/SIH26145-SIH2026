#!/usr/bin/env python3
"""
Measures the real sustained packets/sec (and equivalent Mbit/s) the LIVE
pipeline can process on one core: FlowAssembler + all 13 engines + ML,
exactly the code path a real capture backend feeds -- the only thing this
does NOT include is the NIC/kernel-ring layer itself, which every prior
analysis in this project (and the two external proposals reviewed) agrees
is not the bottleneck.

Method: replay a real pcap through LiveAgent as fast as Python can push it
(no real-time pacing), then measure wall-clock time from first packet fed
to the processing queue fully drained. If the feed outruns the consumer,
the bounded queue starts dropping (oldest-drop, same as production) --
`dropped` in the output makes that visible rather than silently inflating
the throughput number.

    python scripts/bench_throughput.py "C:/path/to/some.pcap" [--label x]

Report the packets actually ingested (fed - dropped), not fed, as the
numerator for pps/Mbps -- that is what real detection coverage got.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("SCAPY_USE_PCAPDNET", "1")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--label", default=None)
    ap.add_argument("--max-packets", type=int, default=None)
    args = ap.parse_args()

    from scapy.config import conf
    conf.use_pcap = True
    conf.manufdb = None
    from scapy.all import PcapReader

    from src.capture.live_agent import LiveAgent

    agent = LiveAgent(iface="bench", queue_size=500_000, cooldown_s=0.0)
    agent._build_engines()
    agent._running.set()
    agent._started_at = time.time()
    loop = asyncio.new_event_loop()
    agent._loop = loop

    def _run_loop():
        asyncio.set_event_loop(loop)
        loop.run_until_complete(agent._consume())

    t = threading.Thread(target=_run_loop, daemon=True)
    t.start()

    fed, fed_bytes = 0, 0
    t0 = time.time()
    with PcapReader(args.pcap) as rd:
        for pkt in rd:
            agent._on_packet(pkt)
            fed += 1
            fed_bytes += len(pkt)
            if args.max_packets and fed >= args.max_packets:
                break
    feed_s = time.time() - t0

    # wait for the processing queue to fully drain (the real end of work) --
    # with an engine pool active, work also queues inside worker processes
    # (see LiveAgent.pending_work()), not just the packet queue.
    stall_deadline = time.time() + 120
    while agent.pending_work() > 0 and time.time() < stall_deadline:
        time.sleep(0.05)
    time.sleep(0.3)  # let the last in-flight batch finish scoring
    total_s = time.time() - t0
    agent._running.clear()
    if agent._pool is not None:
        # final alert drain: workers may have pushed alerts after the last
        # in-process _consume() drain pass but before we stop them.
        deadline = time.time() + 5
        drained = []
        while time.time() < deadline:
            batch = agent._pool.drain_alerts()
            if not batch:
                break
            drained.extend(batch)
        for alert in drained:
            agent._emit(alert, alert.pop("_t_arr", None))
        agent._pool.stop()

    processed = agent._assembler.stats["packets"]
    dropped = agent.stats["dropped"]
    avg_size = fed_bytes / fed if fed else 0
    pps = processed / total_s if total_s else 0
    mbps = (processed * avg_size * 8 / 1e6) / total_s if total_s else 0

    label = args.label or Path(args.pcap).name
    print(f"\n=== {label} ===")
    print(f"  fed (read from pcap)      : {fed:,}")
    print(f"  processed (drained+scored): {processed:,}")
    print(f"  dropped (queue overflow)  : {dropped:,}  {'<-- feed outran processing' if dropped else ''}")
    print(f"  avg packet size           : {avg_size:.0f} bytes")
    print(f"  feed time                 : {feed_s:.2f}s   total (incl. drain) : {total_s:.2f}s")
    print(f"  SUSTAINED THROUGHPUT      : {pps:,.0f} pps   =  {mbps:,.1f} Mbit/s  ({mbps/1000:.3f} Gbit/s)")
    print(f"  alerts fired              : {agent.stats['alerts']:,}")
    print(f"  active flows at end       : {agent._assembler.active_flows():,}")


if __name__ == "__main__":
    main()
