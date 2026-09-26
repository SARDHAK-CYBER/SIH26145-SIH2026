from __future__ import annotations
from typing import Optional
from redis import Redis
from src.alert_schema import Alert, FlowIdentifier, MitreAttack
from src.engines.base import Detector

try:
    # Native fast-path: the exact same thresholds/formulas below, moved
    # into an in-process Rust counter so the per-flow cost that
    # profiling identified (Redis/MemoryStore round-trips, Python dict/
    # set overhead) drops out entirely -- see native/stealthtap_core/
    # src/eng01.rs and scripts/validate_native_eng01.py. Same graceful-
    # fallback pattern as every other native module in this codebase.
    import stealthtap_core
    _NATIVE_ENG01_AVAILABLE = hasattr(stealthtap_core, "NativeEng01")
except ImportError:
    _NATIVE_ENG01_AVAILABLE = False

import os
_FORCE_PYTHON_ENG01 = os.environ.get("STEALTHTAP_FORCE_PYTHON_ENG01") == "1"

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
        allow_native: bool = True,
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

        # Native fast-path: only safe when the caller uses this engine's
        # default thresholds (the Rust side hardcodes them, see
        # native/stealthtap_core/src/eng01.rs) -- every real call site
        # in this codebase does (verified: grep for VolumetricDDoSDetector
        # construction finds none overriding window_seconds/
        # flood_threshold/slowloris_*). key_prefix doesn't need special
        # native handling: a fresh NativeEng01() per Detector instance is
        # already isolated by construction, which is what key_prefix
        # exists to guarantee for the Redis path.
        #
        # allow_native=False is for src/capture/engine_pool.py's multi-
        # worker mode specifically: NativeEng01's spoofed-flood check
        # tracks distinct source IPs PER DESTINATION (self.dst in
        # eng01.rs), in-process. The pool shards records by SOURCE ip, so
        # a real spoofed flood's many distinct attacking sources land on
        # DIFFERENT workers -- each one's native counter would only ever
        # see a fraction of the true fan-in and could silently miss a
        # real attack. The Redis HLL path this falls back to is keyed by
        # dst_ip in a store every worker shares, which is exactly what
        # this cross-source check needs and per-worker in-process state
        # cannot provide. ENG-02/05/06/13's native state is entirely
        # src_ip-first-keyed (checked directly against their .rs source),
        # so worker-local state is already correct for them -- this is
        # not a generic multi-worker vs. native problem, just this one
        # engine's one dst_ip-keyed sub-check.
        self._native = None
        if (allow_native and _NATIVE_ENG01_AVAILABLE and not _FORCE_PYTHON_ENG01
                and window_seconds == WINDOW_SECONDS and flood_threshold == FLOOD_FLOW_THRESHOLD
                and slowloris_duration_s == 120.0 and slowloris_max_bytes == 50):
            self._native = stealthtap_core.NativeEng01()

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

    def _dst_pkt_count_key(self, dst_ip: str, ts: float) -> str:
        bucket_id = int(ts // self.window_seconds)
        return f"{self.key_prefix}eng01:dst_pkt_count:{dst_ip}:{bucket_id}"

    def _check_spoofed_flood(self, flow: dict, packet_count: int) -> Optional[dict]:
        """Returns evidence dict if this destination is seeing a
        spoofed-source-shaped flood this window, else None. Uses
        HyperLogLog for distinct-source estimation -- approximate, but
        that's the standard, expected tradeoff for this data structure
        and is more than precise enough at the ratios this actually
        needs to distinguish (a real attack showed 99.4% uniqueness;
        normal traffic to a real server sees the same handful of
        client IPs repeat constantly, nowhere near this ratio).

        `packet_count` is the post-INCR value for this (dst, window) --
        already computed by score()'s ONE combined pipeline (see there for
        why: this used to open its OWN separate pipeline for the same
        PFADD+EXPIRE+INCR+EXPIRE commands that pipeline already needed to
        send, doubling the mandatory Redis round-trips on EVERY flow.
        Measured directly, isolated from IPC/pool overhead: 24.3s of
        Redis-call time for 12,300 flows, ~98% of this engine's entire
        Redis-mode cost -- the two-pipelines-per-flow structure, not
        multi-core IPC, turned out to be the real reason pool mode was
        slow. This function now only makes the CONDITIONAL follow-up call
        (PFCOUNT), which is genuinely rare -- most flows never reach
        SPOOFED_MIN_PACKETS in one window)."""
        bucket_id = int(flow["ts"] // self.window_seconds)
        dst = flow["dst_ip"]
        hll_key = f"{self.key_prefix}eng01:dst_src_hll:{dst}:{bucket_id}"

        try:
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
        if self._native is not None:
            hit = self._native.check(
                flow["src_ip"], flow["dst_ip"], flow["ts"],
                float(flow.get("duration_s", 0) or 0),
                float(flow.get("orig_bytes", 0) or 0) + float(flow.get("resp_bytes", 0) or 0),
            )
            if hit is None:
                return None
            return self._build_alert(flow, hit["threat_class"], hit["confidence"], evidence=hit["evidence"])

        # Checked before any Redis call, not just before the alert build:
        # pure-Python, no Redis dependency, and the ORIGINAL code path
        # never touched the spoofed-flood HLL/counter state for a
        # slowloris-flagged flow either (that check ran after this one).
        # Keeping this ordering matters, not just for the free round-trip
        # it now also saves: moving the (newly merged, see below) pipeline
        # ahead of this check would have made slowloris flows silently
        # start counting toward the DESTINATION's spoofed-flood tracking,
        # a real behavior change this session's own standard doesn't allow
        # without validating it changes zero real alerts first -- simpler
        # and exactly equivalent to just keep the ordering as it was.
        if self._looks_like_slowloris(flow):
            return self._build_alert(
                flow, "SLOWLORIS", 85.0,
                evidence={
                    "duration_s": flow.get("duration_s"),
                    "bytes_total": flow.get("orig_bytes", 0) + flow.get("resp_bytes", 0),
                },
            )

        key = self._bucket_key(flow["ts"])
        self._ensure_cms(key)
        bucket_id = int(flow["ts"] // self.window_seconds)
        dst_hll_key = self._src_dst_hll_key(flow["src_ip"], flow["ts"])           # this SOURCE's distinct destinations
        src_hll_key = f"{self.key_prefix}eng01:dst_src_hll:{flow['dst_ip']}:{bucket_id}"  # this DESTINATION's distinct sources
        pkt_count_key = self._dst_pkt_count_key(flow["dst_ip"], flow["ts"])

        count = 0
        packet_count = 0
        try:
            # ONE combined pipeline for every command this method and
            # _check_spoofed_flood need on every flow -- CMS.INCRBY (this
            # source's flow-rate) + PFADD/EXPIRE (this source's distinct
            # destinations, for the concentration check) + PFADD/EXPIRE
            # (this destination's distinct sources) + INCR/EXPIRE (this
            # destination's packet count, for the spoofed-flood check).
            # These used to be TWO separate pipelines (one here, one inside
            # _check_spoofed_flood) even though both run on every single
            # flow unconditionally -- doubling the mandatory Redis
            # round-trips for no reason. Found by isolating this engine's
            # Redis cost from IPC/pool overhead entirely: 24.3s of the
            # 24.3s total was THIS, not multiprocessing -- see
            # _check_spoofed_flood's docstring for the measurement.
            # CMS.INCRBY's own reply IS the post-increment count (verified
            # directly against RedisBloom), and INCR's own reply IS the
            # post-increment packet_count -- neither needs a follow-up
            # query for a value the pipeline already returned.
            pipe = self.redis.pipeline()
            pipe.execute_command('CMS.INCRBY', key, flow["src_ip"], 1)
            pipe.pfadd(dst_hll_key, flow["dst_ip"])
            pipe.expire(dst_hll_key, BUCKET_TTL_SECONDS)
            pipe.pfadd(src_hll_key, flow["src_ip"])
            pipe.expire(src_hll_key, BUCKET_TTL_SECONDS)
            pipe.incr(pkt_count_key)
            pipe.expire(pkt_count_key, BUCKET_TTL_SECONDS)
            results = pipe.execute()
            count = int(results[0][0]) if results[0] else 0
            packet_count = int(results[5])
        except Exception:
            pass  # Failsafe if RedisBloom module isn't loaded properly

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

        spoofed_evidence = self._check_spoofed_flood(flow, packet_count)
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