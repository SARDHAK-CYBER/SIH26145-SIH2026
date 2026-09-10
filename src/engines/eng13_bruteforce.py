"""
ENG-13 -- Brute-force / credential-attack detection.

Built after real testing found a genuine, confirmed gap: hydra_ftp.pcap and
hydra_ssh.pcap (real THC-Hydra brute-force captures) produced ZERO alerts
anywhere in the pipeline -- not from Suricata's 20,829 rules, not from any
existing rule engine. Neither ENG-01's generic flood counter nor any
signature caught this, because brute-forcing has two shapes neither
existing mechanism targets:
  1. Slow and deliberate (hydra_ftp: real measured rate 1.7 attempts/sec,
     128 attempts over 75s) -- far too slow to trip a generic flood
     threshold (ENG-01's is 200 flows/10s), but 128 attempts to the same
     FTP port from one source is unambiguous credential-stuffing.
  2. Fast (hydra_ssh: real measured rate 210.7 attempts/sec) -- fast enough
     it might cross a generic flood threshold, but genuinely encrypted
     (SSH), so no signature can see the actual login attempts inside it;
     only the CONNECTION PATTERN itself is visible.

This tracks connection attempts per (src_ip, dst_ip, dst_port) specifically
for known authentication-service ports, over a window wide enough to catch
the slow case. Threshold (10 attempts / 60s) is set with real margin below
BOTH measured real attack rates above, not guessed.
"""
from __future__ import annotations
from typing import Optional
from redis import Redis
from src.alert_schema import Alert, FlowIdentifier, MitreAttack
from src.engines.base import Detector

# Standard authentication-service ports -- brute-forcing only makes sense
# against a service that actually authenticates.
AUTH_PORTS = {21, 22, 23, 25, 110, 143, 993, 995, 3389, 5900}

WINDOW_SECONDS = 60.0
BUCKET_TTL_SECONDS = int(WINDOW_SECONDS * 2)
# Real measured rates this needs to catch: hydra_ftp ~1.7/s (128 attempts/75s),
# hydra_ssh ~210.7/s (3090 attempts/14.66s). 10 attempts in 60s sits well
# below both -- reaches the threshold in ~6s for the slow case, near-instantly
# for the fast case -- while staying above a handful of legitimate mistyped
# passwords.
ATTEMPT_THRESHOLD = 10


class BruteForceDetector(Detector):
    name = "ENG-13"

    def __init__(self, redis_client: Optional[Redis] = None):
        self.redis = redis_client

    def _bucket_key(self, src_ip: str, dst_ip: str, dst_port: int, ts: float) -> str:
        bucket_id = int(ts // WINDOW_SECONDS)
        return f"eng13:auth_attempts:{src_ip}:{dst_ip}:{dst_port}:{bucket_id}"

    async def score(self, flow: dict) -> Optional[Alert]:
        if self.redis is None:
            return None
        dst_port = int(flow.get("dst_port", 0))
        if dst_port not in AUTH_PORTS:
            return None

        src_ip, dst_ip = flow.get("src_ip", ""), flow.get("dst_ip", "")
        ts = float(flow.get("ts", 0.0))
        key = self._bucket_key(src_ip, dst_ip, dst_port, ts)

        try:
            count = self.redis.incr(key)
            self.redis.expire(key, BUCKET_TTL_SECONDS)
        except Exception:
            return None  # Redis unavailable -- fail open, same pattern as other engines

        if count < ATTEMPT_THRESHOLD:
            return None

        # Dedup: one alert per (source, destination, port, window), not one
        # per subsequent connection attempt -- same reasoning as ENG-01's
        # flood dedup fix (a real user test caught that exact problem there).
        dedup_key = f"eng13:alerted:{src_ip}:{dst_ip}:{dst_port}:{int(ts // WINDOW_SECONDS)}"
        try:
            if not self.redis.set(dedup_key, "1", nx=True, ex=BUCKET_TTL_SECONDS):
                return None
        except Exception:
            pass

        confidence = min(97.0, 70.0 + (count - ATTEMPT_THRESHOLD) * 0.5)
        return Alert(
            alert_id=flow.get("flow_uid", "unknown"), timestamp=ts,
            severity="HIGH", confidence_score=round(confidence, 1),
            threat_class="NETWORK_INTRUSION_ATTEMPT",
            flow_identifier=FlowIdentifier(
                src_ip=src_ip, src_port=int(flow.get("src_port", 0)),
                dst_ip=dst_ip, dst_port=dst_port, protocol=flow.get("proto", "TCP"),
            ),
            mitre_attack=MitreAttack(
                tactic="Credential Access", technique_id="T1110",
                technique_name="Brute Force",
            ),
            evidence={
                "connection_attempts": count,
                "window_seconds": WINDOW_SECONDS,
                "target_port": dst_port,
                "threshold": ATTEMPT_THRESHOLD,
            },
            forensics={"raw_segment_hash_sha256": flow.get("segment_hash", "")},
        )
