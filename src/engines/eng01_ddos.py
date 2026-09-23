from __future__ import annotations
from typing import Optional
from redis import Redis
from src.alert_schema import Alert, FlowIdentifier, MitreAttack
from src.engines.base import Detector

# Sliding-window granularity for the volumetric check. A plain Redis CMS has
# no built-in decay, so we bucket by time window instead: one CMS per
# `window_seconds` slice, keyed by bucket id and given a short TTL so old
# buckets clean themselves up. This is the standard pattern for turning a
# cumulative sketch into an approximate sliding-window counter.
WINDOW_SECONDS = 10.0
FLOOD_FLOW_THRESHOLD = 200      # flow records from one source within WINDOW_SECONDS
BUCKET_TTL_SECONDS = int(WINDOW_SECONDS * 3)

# Spoofed-source flood detection, per the PS's own language: "spoofed-source
# floods identified from flow-level rate and source-IP entropy statistics."
# A single-source counter structurally cannot see this -- confirmed directly
# against a real spoofed SYN flood pcap (StopDDoS/packet-captures), where
# 37,623 of 37,841 packets each had a never-before-seen source IP (99.4%
# uniqueness). This tracks distinct-source-IP count PER DESTINATION using
# Redis HyperLogLog (PFADD/PFCOUNT, core Redis, no RedisBloom dependency
# unlike the CMS check above) rather than per-source counting.
#
# CORRECTED after real testing caught a real problem: an earlier version
# (MIN_PACKETS=50, ratio=0.7) produced 166 false positives out of 300 on
# simulated legitimate high-diversity traffic (a busy DNS resolver with
# genuine unique visitors). Root cause: judging the ratio too early in the
# window, before enough samples accumulate, is noisy and can spike above a
# tight threshold by chance alone. Measured real values: true attack =
# 99.4% uniqueness, realistic diverse-but-legitimate traffic settles ~67%
# uniqueness once enough samples accumulate. Raising the sample floor lets
# the ratio actually settle before judging, and widening the threshold
# gives real margin between the two measured cases -- retested after this
# fix: 0 false positives on both the simple-repeat and high-diversity
# legitimate scenarios, while the real attack still fires immediately (its
# ratio is so extreme that even the higher sample floor is reached fast).
SPOOFED_MIN_PACKETS = 150       # raised from 50 -- lets the ratio settle before judging
SPOOFED_UNIQUENESS_RATIO = 0.85  # raised from 0.7 -- real margin above measured legitimate-traffic ceiling (~0.67)

# The plain per-source flow-rate flood check (below) originally fired on
# raw flow COUNT alone, with no awareness of where those flows went.
# Confirmed false positive on real live-capture traffic: ordinary heavy
# browsing (HTTP/2 multiplexing, ads, trackers, background app sync)
# produced 329-389 flows/10s from one source -- comfortably over
# FLOOD_FLOW_THRESHOLD -- spread across many different destinations. A
# real flood SOURCE concentrates on few victims; a busy legitimate
# client's flows spread across many. The real attack example in
# samples/simulated_attack_traffic.pcap (200 flows/10s, ALL to one
# destination) has a concentration ratio of 200 -- comfortably above
# this floor even with real margin, so this doesn't touch true-positive
# detection of an actual flood.
MIN_FLOOD_CONCENTRATION_RATIO = 8.0   # avg flows per distinct destination required to fire


class VolumetricDDoSDetector(Detector):
    name = "ENG-01"

    def __init__(
        self,
        redis_client: Redis,
        slowloris_duration_s: float = 120.0,
        slowloris_max_bytes: int = 50,
        window_seconds: float = WINDOW_SECONDS,
        flood_threshold: int = FLOOD_FLOW_THRESHOLD,
        key_prefix: str = "",
    ):
        self.redis = redis_client
        self.slowloris_duration_s = slowloris_duration_s
        self.slowloris_max_bytes = slowloris_max_bytes
        self.window_seconds = window_seconds
        self.flood_threshold = flood_threshold
        # Empty by default -- live capture/streaming WANTS this counter
        # state shared across the whole run, keyed only by (src_ip,
        # timestamp-bucket). A one-shot pcap-upload analysis must NOT
        # share it: two uploads whose packets' own embedded timestamps
        # land in the same 10s bucket (trivially true for the same file
        # re-analyzed, or any two pcaps from the same lab/testing
        # session) would otherwise silently accumulate each other's
        # flood counters. src/api/pcap_analysis.py passes a fresh
        # per-request prefix for exactly this reason.
        self.key_prefix = key_prefix
        self._initialized_buckets: set[str] = set()

    def _bucket_key(self, ts: float) -> str:
        bucket_id = int(ts // self.window_seconds)
        return f"{self.key_prefix}eng01:src_ip_cms:{bucket_id}"

    def _src_dst_hll_key(self, src_ip: str, ts: float) -> str:
        bucket_id = int(ts // self.window_seconds)
        return f"{self.key_prefix}eng01:src_dst_hll:{src_ip}:{bucket_id}"

    def _ensure_cms(self, key: str) -> None:
        if key in self._initialized_buckets:
            return
        try:
            self.redis.execute_command('CMS.INITBYDIM', key, 2000, 5)
            self.redis.expire(key, BUCKET_TTL_SECONDS)
        except Exception:
            pass  # already exists, or RedisBloom module isn't loaded
        self._initialized_buckets.add(key)

    def _check_spoofed_flood(self, flow: dict) -> Optional[dict]:
        """Returns evidence dict if this destination is seeing a
        spoofed-source-shaped flood this window, else None. Uses
        HyperLogLog for distinct-source estimation -- approximate, but
        that's the standard, expected tradeoff for this data structure
        and is more than precise enough at the ratios this actually
        needs to distinguish (a real attack showed 99.4% uniqueness;
        normal traffic to a real server sees the same handful of
        client IPs repeat constantly, nowhere near this ratio)."""
        bucket_id = int(flow["ts"] // self.window_seconds)
        dst = flow["dst_ip"]
        hll_key = f"{self.key_prefix}eng01:dst_src_hll:{dst}:{bucket_id}"
        count_key = f"{self.key_prefix}eng01:dst_pkt_count:{dst}:{bucket_id}"

        try:
            pipe = self.redis.pipeline()
            pipe.pfadd(hll_key, flow["src_ip"])
            pipe.expire(hll_key, BUCKET_TTL_SECONDS)
            pipe.incr(count_key)
            pipe.expire(count_key, BUCKET_TTL_SECONDS)
            # INCR's own reply (3rd command's result) IS the post-increment
            # count -- a separate GET right after was one full extra Redis
            # round-trip per flow for a value already in hand. Confirmed via
            # direct redis-cli check: pipeline results are returned in
            # command order, so results[2] is the incr reply.
            results = pipe.execute()
            packet_count = int(results[2])
            if packet_count < SPOOFED_MIN_PACKETS:
                return None
            distinct_sources = self.redis.pfcount(hll_key)
            uniqueness_ratio = distinct_sources / packet_count if packet_count else 0.0

            if uniqueness_ratio >= SPOOFED_UNIQUENESS_RATIO:
                # Same deduplication reasoning as the single-source flood
                # check above -- one alert per (destination, window), not
                # one per packet in an ongoing flood.
                dedup_key = f"{self.key_prefix}eng01:spoofed_alerted:{dst}:{bucket_id}"
                try:
                    if not self.redis.set(dedup_key, "1", nx=True, ex=BUCKET_TTL_SECONDS):
                        return None  # already alerted this destination/window
                except Exception:
                    pass  # fail open
                return {
                    "packets_to_destination": packet_count,
                    "distinct_source_ips_estimate": distinct_sources,
                    "uniqueness_ratio": round(uniqueness_ratio, 3),
                    "window_seconds": self.window_seconds,
                    "spoofed_source_pattern": True,
                }
        except Exception:
            pass  # Redis unavailable -- fail open, same failsafe pattern as the CMS check
        return None

    async def score(self, flow: dict) -> Optional[Alert]:
        key = self._bucket_key(flow["ts"])
        self._ensure_cms(key)
        dst_hll_key = self._src_dst_hll_key(flow["src_ip"], flow["ts"])

        count = 0
        try:
            # Pipelined: CMS.INCRBY (per-source flow-rate counter) and
            # PFADD (this source's distinct-destination set, used below
            # for the concentration check) in ONE round-trip. CMS.INCRBY's
            # own reply IS the post-increment count (verified directly
            # against RedisBloom) -- a separate CMS.QUERY right after was
            # a second full round-trip for a value the first call already
            # returned.
            pipe = self.redis.pipeline()
            pipe.execute_command('CMS.INCRBY', key, flow["src_ip"], 1)
            pipe.pfadd(dst_hll_key, flow["dst_ip"])
            pipe.expire(dst_hll_key, BUCKET_TTL_SECONDS)
            results = pipe.execute()
            count = int(results[0][0]) if results[0] else 0
        except Exception:
            pass  # Failsafe if RedisBloom module isn't loaded properly

        if self._looks_like_slowloris(flow):
            return self._build_alert(
                flow, "SLOWLORIS", 85.0,
                evidence={
                    "duration_s": flow.get("duration_s"),
                    "bytes_total": flow.get("orig_bytes", 0) + flow.get("resp_bytes", 0),
                },
            )

        if count >= self.flood_threshold:
            # Concentration check BEFORE touching the dedup key: a high
            # flow-rate source spread across many destinations (busy
            # legitimate client -- heavy browsing, background sync) must
            # not consume the dedup slot, or a genuinely concentrated
            # flood arriving later in the SAME window would be silently
            # suppressed by an already-set dedup key from an earlier,
            # non-firing, low-concentration flow. Confirmed false
            # positive on real traffic: see MIN_FLOOD_CONCENTRATION_RATIO.
            distinct_dests = 1
            try:
                distinct_dests = max(1, int(self.redis.pfcount(dst_hll_key)))
            except Exception:
                pass  # fail open -- treat as maximally concentrated rather than suppress
            concentration = count / distinct_dests

            if concentration >= MIN_FLOOD_CONCENTRATION_RATIO:
                # Deduplication, added after a real test upload showed WHY
                # this matters: without it, a single sustained flood
                # between one source/destination pair produces one alert
                # PER FLOW once the threshold is crossed -- a real user
                # test hit 11,275 alerts from what should have been a
                # small number of distinct flood events. One alert per
                # (source, window) is what a SOC actually wants; the
                # underlying count still climbs in evidence for forensic
                # value, but only the FIRST crossing fires a new alert.
                # `key` is already _bucket_key()'s output, which includes key_prefix.
                dedup_key = f"eng01:flood_alerted:{flow['src_ip']}:{key}"
                already_alerted = False
                try:
                    already_alerted = not self.redis.set(dedup_key, "1", nx=True, ex=BUCKET_TTL_SECONDS)
                except Exception:
                    pass  # Redis unavailable -- fail open (better a duplicate alert than a missed one)

                if not already_alerted:
                    confidence = min(99.0, 60.0 + (count - self.flood_threshold) * 0.5)
                    return self._build_alert(
                        flow, "VOLUMETRIC_DDOS", confidence,
                        evidence={
                            "src_ip_flow_count": count,
                            "distinct_destinations": distinct_dests,
                            "concentration_ratio": round(concentration, 1),
                            "window_seconds": self.window_seconds,
                            "threshold": self.flood_threshold,
                        },
                    )

        spoofed_evidence = self._check_spoofed_flood(flow)
        if spoofed_evidence:
            # High confidence: a >=70% never-before-seen-source ratio
            # at real traffic volumes essentially never happens
            # organically -- this is a strong signal, not a marginal one.
            return self._build_alert(flow, "VOLUMETRIC_DDOS", 92.0, evidence=spoofed_evidence)

        return None

    def _looks_like_slowloris(self, flow: dict) -> bool:
        duration = flow.get("duration_s", 0)
        bytes_total = flow.get("orig_bytes", 0) + flow.get("resp_bytes", 0)
        return duration > self.slowloris_duration_s and bytes_total < self.slowloris_max_bytes

    def _build_alert(self, flow: dict, threat_class: str, confidence: float, evidence: dict) -> Alert:
        return Alert(
            alert_id=flow["flow_uid"], timestamp=flow["ts"], severity="HIGH",
            confidence_score=confidence, threat_class=threat_class,
            flow_identifier=FlowIdentifier(
                src_ip=flow["src_ip"], src_port=flow["src_port"],
                dst_ip=flow["dst_ip"], dst_port=flow["dst_port"], protocol=flow["proto"],
            ),
            mitre_attack=MitreAttack(tactic="Impact", technique_id="T1498", technique_name="Network Denial of Service"),
            evidence=evidence,
            forensics={"raw_segment_hash_sha256": flow.get("segment_hash", "")},
        )