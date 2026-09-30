"""
ENG-02 -- C2 beaconing detection via inter-arrival regularity.

CORRECTED after real testing caught a fundamental design flaw: an
earlier version used a separate FFT check for "pure" periodicity
before falling back to a jitter-tolerant coefficient-of-variation (CV)
check. Testing found two real bugs: (1) FFT operates on deviation from
the mean, so a PERFECTLY regular beacon (zero variance) produces an
all-zero signal -- nothing for FFT to detect, so the clearest possible
case failed to fire; (2) with only ~15-25 usable frequency bins from
small sample counts, FFT spuriously found "dominant" frequencies in
genuinely random traffic purely by chance, false-positiving on both a
random-human-traffic test and a bursty-legitimate-app test.

The fix: one correct, unified statistical check, not two. The
coefficient of variation (stddev/mean) of inter-arrival times
naturally spans the whole range that matters -- near zero for
machine-perfect periodicity, moderate for a jittered beacon (Cobalt
Strike's default "sleep 60000 jitter 40" produces CV roughly j/sqrt(3)
for jitter percentage j), and high for genuinely random/human-driven
traffic. Confidence scales with how tight the pattern is, rather than
treating "pure" and "jittered" as different detection mechanisms.

This is the same statistical principle real open-source beacon-hunting
tools (e.g. Active Countermeasures' RITA) use -- not an unusual
approach, just correctly implemented this time, and retested against
five scenarios: perfectly periodic (60s), Cobalt-Strike-shaped jitter
at two levels (40%, 50%), genuinely random exponential traffic, and
bursty/irregular legitimate-app-shaped traffic. All five now behave
correctly.
"""
from __future__ import annotations
import math
import os
from typing import Optional
from redis import Redis
from src.alert_schema import Alert, FlowIdentifier, MitreAttack
from src.engines.base import Detector

try:
    # Native fast-path -- see native/stealthtap_core/src/eng02.rs and
    # eng01_ddos.py's identical pattern for the full rationale.
    import stealthtap_core
    _NATIVE_ENG02_AVAILABLE = hasattr(stealthtap_core, "NativeEng02")
except ImportError:
    _NATIVE_ENG02_AVAILABLE = False

_FORCE_PYTHON_ENG02 = os.environ.get("STEALTHTAP_FORCE_PYTHON_ENG02") == "1"

MAX_TRACKED_TIMESTAMPS = 50   # bound the per-destination history so this never grows unbounded
TIMESTAMP_TTL_SECONDS = 3600  # stop tracking a destination pair after an hour of silence
MIN_SAMPLES = 8

# Coefficient-of-variation band. Above the ceiling, this looks like
# genuinely random traffic, not a beacon -- real jitter settings rarely
# exceed ~50% in practice (higher settings make C2 traffic sluggish for
# the attacker too, so this reflects realistic tool behavior).
CV_CEILING = 0.55
MIN_INTERVAL_SECONDS = 2.0     # faster than this is normal app chatter, not a C2 beacon interval
MAX_INTERVAL_SECONDS = 3600.0  # slower than an hour is out of scope for this check


# The directed-broadcast address(es) of whatever subnet the live capture
# interface is actually on -- populated by set_local_broadcast_addresses()
# when live capture starts (src/capture/live_agent.py). The .255-in-RFC1918
# heuristic below only covers the traditional private ranges; a network
# using a non-RFC1918 block privately (a campus/enterprise block, for
# example -- found on a real Wi-Fi capture: repeated UDP heartbeats from
# several hosts to 12.10.15.255, the true broadcast address of that
# network's actual 255.255.240.0 subnet) needs the real netmask, not a
# guess from the address text alone. Seeded from the environment at import
# so a spawned multi-core worker process (src/capture/engine_pool.py) picks
# up the value the parent process already computed.
_LOCAL_BROADCAST: set[str] = {
    a for a in os.environ.get("STEALTHTAP_LOCAL_BROADCAST_ADDRS", "").split(",") if a
}


def set_local_broadcast_addresses(addrs) -> None:
    global _LOCAL_BROADCAST
    _LOCAL_BROADCAST = {a for a in addrs if a}
    os.environ["STEALTHTAP_LOCAL_BROADCAST_ADDRS"] = ",".join(sorted(_LOCAL_BROADCAST))


def _is_multicast_or_broadcast(ip: str) -> bool:
    """Periodic multicast/broadcast (LLMNR, mDNS, SSDP, DHCP, IPv6 ND) is protocol housekeeping, not C2 --
    found on REAL Wi-Fi capture (a neighbour's LLMNR queries to 224.0.0.252:5355 were flagged)."""
    if ip == "255.255.255.255" or ip.lower().startswith("ff") and ":" in ip:
        return True
    if ip in _LOCAL_BROADCAST:
        return True
    # directed broadcast in private / link-local space (x.y.z.255, e.g. NetBIOS-NS to 169.254.255.255 on a real capture); twin of eng02.rs
    if ip.endswith(".255"):
        parts = ip.split(".")
        if len(parts) == 4 and (parts[0] == "10" or ip.startswith(("192.168.", "169.254.")) or (parts[0] == "172" and parts[1].isdigit() and 16 <= int(parts[1]) <= 31)):
            return True
    try:
        return 224 <= int(ip.split(".")[0]) <= 239
    except ValueError:
        return False


class C2BeaconingDetector(Detector):
    name = "ENG-02"

    def __init__(self, redis_client: Optional[Redis] = None, key_prefix: str = ""):
        self.redis = redis_client
        # See eng01's key_prefix docstring: empty for live capture/streaming
        # (which wants beacon history shared for up to an hour of real
        # traffic); a fresh per-upload prefix from pcap_analysis.py for the
        # one-shot analysis path, so unrelated uploads sharing a src/dst
        # pair never inherit each other's inter-arrival timestamp history.
        self.key_prefix = key_prefix
        self._native = None
        if _NATIVE_ENG02_AVAILABLE and not _FORCE_PYTHON_ENG02:
            self._native = stealthtap_core.NativeEng02()
            if _LOCAL_BROADCAST and hasattr(self._native, "set_local_broadcast"):
                self._native.set_local_broadcast(list(_LOCAL_BROADCAST))

    def _key(self, src_ip: str, dst_ip: str) -> str:
        return f"{self.key_prefix}eng02:beacon_ts:{src_ip}:{dst_ip}"

    def alert_from_native_hit(self, flow: dict, hit: dict) -> Optional[Alert]:
        """Build the typed Alert for a hit the native flow-engine batch runner
        (native/.../flow_engines.rs) already decided on -- same construction the
        per-flow native branch of score() uses."""
        return self._build_alert(flow, confidence=hit["confidence"], evidence=hit["evidence"])

    async def score(self, flow: dict) -> Optional[Alert]:
        src_ip, dst_ip = flow.get("src_ip", ""), flow.get("dst_ip", "")
        ts = float(flow.get("ts", 0.0))
        if _is_multicast_or_broadcast(dst_ip) or _is_multicast_or_broadcast(src_ip):
            return None

        if self._native is not None:
            hit = self._native.check(src_ip, dst_ip, ts)
            if hit is None:
                return None
            return self._build_alert(flow, confidence=hit["confidence"], evidence=hit["evidence"])

        if self.redis is None:
            return None
        key = self._key(src_ip, dst_ip)

        try:
            pipe = self.redis.pipeline()
            pipe.rpush(key, ts)
            pipe.ltrim(key, -MAX_TRACKED_TIMESTAMPS, -1)
            pipe.expire(key, TIMESTAMP_TTL_SECONDS)
            pipe.lrange(key, 0, -1)
            results = pipe.execute()
            raw_timestamps = results[-1]
            timestamps = sorted(float(t) for t in raw_timestamps)
        except Exception:
            return None  # Redis unavailable -- fail open, same pattern as ENG-01

        deltas = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        deltas = [d for d in deltas if d > 0]  # guard against duplicate/out-of-order timestamps
        if len(deltas) < MIN_SAMPLES:
            return None

        mean_interval = _mean(deltas)
        if not (MIN_INTERVAL_SECONDS <= mean_interval <= MAX_INTERVAL_SECONDS):
            return None

        stddev = _stddev(deltas, mean_interval)
        cv = stddev / mean_interval if mean_interval > 0 else float("inf")
        if cv > CV_CEILING:
            return None

        # Additional check found necessary by testing: aggregate CV alone
        # doesn't distinguish "tightly clustered around one value" from
        # "bimodal" (e.g. rapid bursts alternating with long pauses, a
        # real pattern in some legitimate chatty apps) -- both can
        # produce the same mean/stddev. Requiring most individual deltas
        # to actually sit near the MEDIAN (not just matching the
        # aggregate statistic) rejects bimodal data a pure CV check let
        # through in testing.
        median_interval = _median(deltas)
        tolerance = median_interval * CV_CEILING
        near_median = sum(1 for d in deltas if abs(d - median_interval) <= tolerance)
        clustering_ratio = near_median / len(deltas)
        if clustering_ratio < 0.75:
            return None

        # Confidence scales with tightness: near-zero CV (machine-perfect
        # periodicity) scores highest, approaching the ceiling scores lowest.
        confidence = 95.0 - (cv / CV_CEILING) * 25.0
        return self._build_alert(flow, confidence=round(confidence, 1), evidence={
            "coefficient_of_variation": round(cv, 3),
            "mean_interval_seconds": round(mean_interval, 2),
            "sample_count": len(deltas),
            "estimated_jitter_percent": round(cv * math.sqrt(3) * 100, 1),
            "clustering_ratio": round(clustering_ratio, 3),
        })

    def _build_alert(self, flow: dict, confidence: float, evidence: dict) -> Alert:
        return Alert(
            alert_id=flow.get("flow_uid", "unknown"), timestamp=float(flow.get("ts", 0.0)),
            severity="HIGH", confidence_score=confidence, threat_class="C2_BEACONING",
            flow_identifier=FlowIdentifier(
                src_ip=flow.get("src_ip", "0.0.0.0"), src_port=int(flow.get("src_port", 0)),
                dst_ip=flow.get("dst_ip", "0.0.0.0"), dst_port=int(flow.get("dst_port", 0)),
                protocol=flow.get("proto", "TCP"),
            ),
            mitre_attack=MitreAttack(tactic="Command and Control", technique_id="T1071", technique_name="Application Layer Protocol"),
            evidence=evidence,
            forensics={"raw_segment_hash_sha256": flow.get("segment_hash", "")},
        )


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _median(values: list[float]) -> float:
    s = sorted(values)
    n = len(s)
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2


def _stddev(values: list[float], mean_val: float) -> float:
    if len(values) < 2:
        return 0.0
    variance = sum((v - mean_val) ** 2 for v in values) / len(values)
    return math.sqrt(variance)