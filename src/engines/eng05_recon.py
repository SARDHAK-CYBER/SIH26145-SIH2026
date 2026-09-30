from __future__ import annotations
import os
from collections import defaultdict
from typing import Optional
from src.alert_schema import Alert, FlowIdentifier, MitreAttack
from src.engines.base import Detector
from src.engines import eng02_c2_beaconing as _eng02
from src.engines.eng02_c2_beaconing import _is_multicast_or_broadcast

try:
    # Native fast-path -- see native/stealthtap_core/src/eng05.rs and
    # eng01_ddos.py's identical pattern for the full rationale. This
    # engine never had a Redis dependency (pure in-process state
    # already), so the native swap is purely about per-flow CPU cost.
    import stealthtap_core
    _NATIVE_ENG05_AVAILABLE = hasattr(stealthtap_core, "NativeEng05")
except ImportError:
    _NATIVE_ENG05_AVAILABLE = False

_FORCE_PYTHON_ENG05 = os.environ.get("STEALTHTAP_FORCE_PYTHON_ENG05") == "1"

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
# Legitimate services that are DESIGNED to fan out to many peers/targets
# and can look probe-shaped doing it -- confirmed false positive on real
# live-capture traffic: Windows Delivery Optimization (port 7680, P2P
# Windows Update chunk sharing) hit exactly FANOUT_THRESHOLD=25 distinct
# peers on ordinary background OS activity, no scan involved.
_EXCLUDED_FANOUT_PORTS = {7680}
# In the live path this detector runs for the lifetime of the process,
# so its per-source history must not grow without bound. Every
# _PRUNE_EVERY scores, drop any source whose entire history has aged out
# of the window.
_PRUNE_EVERY = 5000

# One alert per scanning CAMPAIGN, not one per 25 probes. After firing, this
# engine resets a source's fan-out state (correct for the detector: it needs
# 25 NEW distinct targets to fire again) -- so a single Mirai-style scanner
# probing 565,012 hosts produced 22,588 RECONNAISSANCE alerts from one
# capture, burying the analyst and bloating every API response. Now: the
# first crossing alerts; further probing from the same source stays one
# campaign (suppressed) for as long as it keeps probing, with an ESCALATION
# alert each time the campaign's cumulative distinct targets grows 10x
# (25 -> 250 -> 2,500 ...) so a scan that becomes a sweep is still surfaced.
# A source silent for RECON_ALERT_COOLDOWN_S starts a fresh campaign.
RECON_ALERT_COOLDOWN_S = float(os.environ.get("RECON_ALERT_COOLDOWN_S", str(WINDOW_SECONDS)))
_ESCALATION_FACTOR = 10
_MAX_CAMPAIGNS = 50_000

class ReconDetector(Detector):
    name = "ENG-05"

    def __init__(self):
        self._seen: dict[str, list[tuple[float, str, int]]] = defaultdict(list)
        self._since_prune = 0
        # src_ip -> [last_probe_ts, cumulative_distinct_targets, next_escalation_at]
        self._campaign: dict[str, list] = {}
        self._native = None
        if _NATIVE_ENG05_AVAILABLE and not _FORCE_PYTHON_ENG05:
            self._native = stealthtap_core.NativeEng05()
            if _eng02._LOCAL_BROADCAST and hasattr(self._native, "set_local_broadcast"):
                self._native.set_local_broadcast(list(_eng02._LOCAL_BROADCAST))

    def _prune(self, now: float) -> None:
        cutoff = now - WINDOW_SECONDS
        stale = [ip for ip, entries in self._seen.items()
                 if not entries or entries[-1][0] < cutoff]
        for ip in stale:
            del self._seen[ip]

    def _campaign_report(self, src_ip: str, ts: float, targets: int) -> Optional[tuple[int, bool]]:
        """None -> suppress (same campaign, no 10x growth). Else (cumulative
        targets to report, is_escalation)."""
        c = self._campaign.get(src_ip)
        if c is None or ts - c[0] > RECON_ALERT_COOLDOWN_S or ts < c[0] - RECON_ALERT_COOLDOWN_S:
            if len(self._campaign) >= _MAX_CAMPAIGNS:
                cutoff = ts - RECON_ALERT_COOLDOWN_S
                self._campaign = {k: v for k, v in self._campaign.items() if v[0] >= cutoff}
            self._campaign[src_ip] = [ts, targets, targets * _ESCALATION_FACTOR]
            return targets, False
        c[0] = max(c[0], ts)          # still probing -> the campaign stays alive
        c[1] += targets
        if c[1] >= c[2]:
            c[2] = c[1] * _ESCALATION_FACTOR
            return c[1], True
        return None

    def alert_from_native_hit(self, flow: dict, hit: dict) -> Optional[Alert]:
        """Build the typed Alert for a hit the native flow-engine batch runner
        (native/.../flow_engines.rs) already decided on -- same construction the
        per-flow native branch of score() uses."""
        rep = self._campaign_report(flow["src_ip"], flow["ts"], hit["distinct_targets"])
        if rep is None:
            return None
        return self._build_alert(flow, rep[0], hit["confidence"], escalation=rep[1])

    async def score(self, flow: dict) -> Optional[Alert]:
        src_ip = flow["src_ip"]
        now = flow["ts"]

        # SSDP/mDNS-style discovery bursts to a multicast/broadcast group
        # look exactly like a "probe" (no response payload, tiny originator
        # payload) and repeat to a NEW (dst_ip, dst_port) tuple often enough
        # to cross FANOUT_THRESHOLD on their own -- found on a real Wi-Fi
        # capture: ordinary SSDP announcements to 239.255.255.250 flagged as
        # RECONNAISSANCE. Checked before the native dispatch (like ENG-02)
        # so the exclusion applies regardless of which backend runs.
        if _is_multicast_or_broadcast(flow["dst_ip"]):
            return None

        if self._native is not None:
            hit = self._native.check(
                src_ip, flow["dst_ip"], int(flow.get("dst_port", 0) or 0), now,
                float(flow.get("orig_bytes", 0) or 0), float(flow.get("resp_bytes", 0) or 0),
            )
            if hit is None:
                return None
            rep = self._campaign_report(src_ip, now, hit["distinct_targets"])
            if rep is None:
                return None
            return self._build_alert(flow, rep[0], hit["confidence"], escalation=rep[1])

        if int(flow.get("dst_port", 0) or 0) in _EXCLUDED_FANOUT_PORTS:
            return None
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
            rep = self._campaign_report(src_ip, now, len(distinct_targets))
            if rep is None:
                return None
            return self._build_alert(flow, rep[0], confidence, escalation=rep[1])
        return None

    def _build_alert(self, flow: dict, fanout_count: int, confidence: float, escalation: bool = False) -> Alert:
        return Alert(
            alert_id=flow["flow_uid"], timestamp=flow["ts"], severity="MEDIUM",
            confidence_score=confidence, threat_class="RECONNAISSANCE",
            flow_identifier=FlowIdentifier(
                src_ip=flow["src_ip"], src_port=flow.get("src_port", 0),
                dst_ip=flow["dst_ip"], dst_port=flow["dst_port"], protocol=flow["proto"],
            ),
            mitre_attack=MitreAttack(tactic="Discovery", technique_id="T1046", technique_name="Network Service Discovery"),
            evidence=({"distinct_targets": fanout_count, "window_s": WINDOW_SECONDS}
                      if not escalation else
                      {"distinct_targets": fanout_count, "window_s": WINDOW_SECONDS,
                       "escalation": True, "note": "cumulative distinct targets in this scanning campaign grew 10x"}),
            forensics={"raw_segment_hash_sha256": flow.get("segment_hash", "")},
        )