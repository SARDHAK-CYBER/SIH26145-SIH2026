"""
ENG-06 -- Data exfiltration: per-flow AND accumulated low-and-slow.

Two independent checks, because a sophisticated attacker deliberately
keeps each INDIVIDUAL flow's byte ratio below the per-flow threshold
specifically to stay under it -- exfiltrating the same total volume
through many small, individually-unremarkable flows instead of one
large one. No single flow reveals this; only the accumulated pattern
across a sequence of flows to the same destination does.

  1. Per-flow: the original, simple check -- if THIS flow alone has an
     outbound:inbound byte ratio at or above the threshold, fire
     immediately. Catches loud, obvious exfiltration.
  2. Accumulated (low-and-slow): tracks cumulative outbound/inbound
     bytes per (src_ip, dst_ip) pair in Redis over a longer window than
     any single flow. If the per-flow check never fires (each flow
     individually looks fine) but the ACCUMULATED ratio across many
     flows crosses the threshold, that's the low-and-slow pattern --
     fired with its own, distinct evidence showing it was the
     accumulation that triggered it, not any single flow.

State is per (src_ip, dst_ip) pair, tracked in Redis so it survives
across the whole sequence of flows to a destination, not just one.
"""
from __future__ import annotations
from typing import Optional
from redis import Redis
from src.alert_schema import Alert, FlowIdentifier, MitreAttack
from src.engines.base import Detector

PER_FLOW_RATIO_THRESHOLD = 20.0  # a single flow's own outbound:inbound ratio -- original, loud-exfil check

# Accumulated window: deliberately much longer than any single flow,
# since low-and-slow exfiltration is specifically designed to spread
# volume out over time to avoid per-flow detection.
ACCUMULATION_WINDOW_SECONDS = 300.0  # 5 minutes
ACCUMULATION_TTL_SECONDS = int(ACCUMULATION_WINDOW_SECONDS * 2)

# The accumulated ratio threshold is intentionally lower than the
# per-flow one -- if we're already tracking real cumulative volume
# over 5 minutes, we don't need as extreme a ratio to be confident,
# since sustained asymmetry over time is itself unusual regardless of
# how loud any single flow was.
ACCUMULATED_RATIO_THRESHOLD = 10.0
MIN_ACCUMULATED_OUTBOUND_BYTES = 500_000  # ignore trivial cumulative volume -- avoids false positives on small, normal sessions


class ExfiltrationDetector(Detector):
    name = "ENG-06"

    def __init__(self, redis_client: Optional[Redis] = None):
        self.redis = redis_client

    def _bucket_key(self, src_ip: str, dst_ip: str, ts: float) -> str:
        bucket_id = int(ts // ACCUMULATION_WINDOW_SECONDS)
        return f"eng06:accum:{src_ip}:{dst_ip}:{bucket_id}"

    async def score(self, flow: dict) -> Optional[Alert]:
        orig_bytes = float(flow.get("orig_bytes", 0))
        resp_bytes = float(flow.get("resp_bytes", 0))

        if resp_bytes > 0 and (orig_bytes / resp_bytes) >= PER_FLOW_RATIO_THRESHOLD:
            return self._build_alert(flow, confidence=90.0, evidence={
                "detection_type": "single_flow",
                "orig_bytes": orig_bytes, "resp_bytes": resp_bytes,
                "ratio": round(orig_bytes / resp_bytes, 1),
            })

        accumulated_evidence = await self._check_accumulated(flow, orig_bytes, resp_bytes)
        if accumulated_evidence:
            return self._build_alert(flow, confidence=82.0, evidence=accumulated_evidence)

        return None

    async def _check_accumulated(self, flow: dict, orig_bytes: float, resp_bytes: float) -> Optional[dict]:
        if self.redis is None:
            return None
        src_ip, dst_ip = flow.get("src_ip", ""), flow.get("dst_ip", "")
        ts = float(flow.get("ts", 0.0))
        key = self._bucket_key(src_ip, dst_ip, ts)

        try:
            pipe = self.redis.pipeline()
            pipe.hincrby(key, "orig_bytes", int(orig_bytes))
            pipe.hincrby(key, "resp_bytes", int(resp_bytes))
            pipe.hincrby(key, "flow_count", 1)
            pipe.expire(key, ACCUMULATION_TTL_SECONDS)
            results = pipe.execute()
            cumulative_orig, cumulative_resp, flow_count = results[0], results[1], results[2]
        except Exception:
            return None  # Redis unavailable -- fail open, same pattern as ENG-01/ENG-02

        if cumulative_orig < MIN_ACCUMULATED_OUTBOUND_BYTES:
            return None
        if cumulative_resp <= 0:
            return None

        cumulative_ratio = cumulative_orig / cumulative_resp
        if cumulative_ratio >= ACCUMULATED_RATIO_THRESHOLD:
            return {
                "detection_type": "accumulated_low_and_slow",
                "cumulative_orig_bytes": cumulative_orig,
                "cumulative_resp_bytes": cumulative_resp,
                "cumulative_ratio": round(cumulative_ratio, 1),
                "contributing_flow_count": flow_count,
                "window_seconds": ACCUMULATION_WINDOW_SECONDS,
            }
        return None

    def _build_alert(self, flow: dict, confidence: float, evidence: dict) -> Alert:
        return Alert(
            alert_id=flow.get("flow_uid", "unknown"), timestamp=float(flow.get("ts", 0.0)),
            severity="HIGH", confidence_score=confidence, threat_class="DATA_EXFILTRATION",
            flow_identifier=FlowIdentifier(
                src_ip=flow.get("src_ip", "0.0.0.0"), src_port=int(flow.get("src_port", 0)),
                dst_ip=flow.get("dst_ip", "0.0.0.0"), dst_port=int(flow.get("dst_port", 0)),
                protocol=flow.get("proto", "TCP"),
            ),
            mitre_attack=MitreAttack(tactic="Exfiltration", technique_id="T1041", technique_name="Exfiltration Over C2 Channel"),
            evidence=evidence,
            forensics={"raw_segment_hash_sha256": flow.get("segment_hash", "")},
        )