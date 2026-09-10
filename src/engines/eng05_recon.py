from __future__ import annotations
from collections import defaultdict
from typing import Optional
from src.alert_schema import Alert, FlowIdentifier, MitreAttack
from src.engines.base import Detector

WINDOW_SECONDS = 300.0
FANOUT_THRESHOLD = 25
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
        entries = self._seen[src_ip]
        entries.append((now, flow["dst_ip"], flow["dst_port"]))

        cutoff = now - WINDOW_SECONDS
        entries[:] = [e for e in entries if e[0] >= cutoff]

        self._since_prune += 1
        if self._since_prune >= _PRUNE_EVERY:
            self._since_prune = 0
            self._prune(now)

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