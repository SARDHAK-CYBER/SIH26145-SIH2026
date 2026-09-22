from __future__ import annotations
from collections import defaultdict
from typing import Optional
from src.alert_schema import Alert, FlowIdentifier, MitreAttack
from src.engines.base import Detector

WINDOW_SECONDS = 300.0
FANOUT_THRESHOLD = 25
# A scan is defined by targets that DON'T answer with data: SYN probes to
# closed/filtered ports get a RST or nothing, never an application
# response. A normal desktop also touches 25+ distinct (ip, port) pairs in
# five minutes (CDNs, telemetry, DNS, mDNS) -- but every one of those
# carries a response. Counting only "probe-shaped" flows (no responder
# payload, at most a tiny originator payload) removed the false positives
# measured on benign captures (RECONNAISSANCE fired on a normal PC at
# distinct_targets=25) while leaving real scans untouched.
PROBE_MAX_ORIG_BYTES = 512
# In the live path this detector runs for the lifetime of the process,
# so its per-source history must not grow without bound. Every
# _PRUNE_EVERY scores, drop any source whose entire history has aged out
# of the window.
_PRUNE_EVERY = 5000

class ReconDetector(Detector):
    name = "ENG-05"

    def __init__(self):
        self._seen: dict[str, list[tuple[float, str, int]]] = defaultdict(list)
        self._since_prune = 0

    def _prune(self, now: float) -> None:
        cutoff = now - WINDOW_SECONDS
        stale = [ip for ip, entries in self._seen.items()
                 if not entries or entries[-1][0] < cutoff]
        for ip in stale:
            del self._seen[ip]

    async def score(self, flow: dict) -> Optional[Alert]:
        src_ip = flow["src_ip"]
        now = flow["ts"]
        is_probe = (float(flow.get("resp_bytes", 0) or 0) == 0
                    and float(flow.get("orig_bytes", 0) or 0) <= PROBE_MAX_ORIG_BYTES)

        # Global stale-SOURCE sweep (removes entire dead src_ip entries) --
        # kept unconditional, it's an O(1) counter check almost always.
        self._since_prune += 1
        if self._since_prune >= _PRUNE_EVERY:
            self._since_prune = 0
            self._prune(now)

        # A non-probe flow only ever shrinks/leaves-unchanged this source's
        # fan-out count -- it can never newly cross FANOUT_THRESHOLD, so
        # the per-entry window prune (list comp) and distinct-target
        # rebuild (set comp) below only need to run on a probe flow.
        # Profiling (scripts/bench_throughput.py, samples/netbios_ssn2.pcap):
        # these two O(len(entries)) rebuilds, run from scratch on EVERY
        # score() call regardless of whether anything changed, were ~20%
        # of total live-pipeline time combined. Deferred window-pruning on
        # non-probe calls is still bounded correctly -- the next probe call
        # re-prunes before checking, and the global sweep above independently
        # bounds _seen's total size.
        if not is_probe:
            return None

        entries = self._seen[src_ip]
        entries.append((now, flow["dst_ip"], flow["dst_port"]))
        cutoff = now - WINDOW_SECONDS
        entries[:] = [e for e in entries if e[0] >= cutoff]

        distinct_targets = {(dst_ip, dst_port) for _, dst_ip, dst_port in entries}
        if len(distinct_targets) >= FANOUT_THRESHOLD:
            confidence = min(95.0, 50.0 + len(distinct_targets))
            self._seen.pop(src_ip, None)  # reset state for this source after firing
            return self._build_alert(flow, len(distinct_targets), confidence)
        return None

    def _build_alert(self, flow: dict, fanout_count: int, confidence: float) -> Alert:
        return Alert(
            alert_id=flow["flow_uid"], timestamp=flow["ts"], severity="MEDIUM",
            confidence_score=confidence, threat_class="RECONNAISSANCE",
            flow_identifier=FlowIdentifier(
                src_ip=flow["src_ip"], src_port=flow.get("src_port", 0),
                dst_ip=flow["dst_ip"], dst_port=flow["dst_port"], protocol=flow["proto"],
            ),
            mitre_attack=MitreAttack(tactic="Discovery", technique_id="T1046", technique_name="Network Service Discovery"),
            evidence={"distinct_targets": fanout_count, "window_s": WINDOW_SECONDS},
            forensics={"raw_segment_hash_sha256": flow.get("segment_hash", "")},
        )