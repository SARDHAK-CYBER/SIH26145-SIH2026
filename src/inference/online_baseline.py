"""
Live-learning behavioural baseline -- an AI detector with NO pre-trained data.

The supervised models shipped in models/ were trained on public captures
and (as scripts/eval_real_traffic.py measured) do not transfer to a new
network. This detector instead learns what "normal" looks like on THE
network it is attached to, from the flows it observes live, and only then
starts alerting:

  learning  -> collect completed flows for at least `learn_min_seconds` and
               `learn_min_flows`
  armed     -> flows are scored against the learned profile; an alert is
               raised only when the flow's *conformal p-value* is <= alpha

Model (numpy only, so it ships in the desktop build):
  * a per-service profile -- service = (proto, responder port) -- holding the
    median and MAD of six log-scaled flow features; the anomaly score is the
    largest robust z-score across features;
  * a service never seen during learning scores on a pooled global profile
    plus a novelty term (a brand-new service on a home LAN is itself
    information);
  * the last 30 % of the learning window is held out as a calibration set:
    the p-value of a new flow is the fraction of calibration scores at least
    as large (with the +1 correction), so `alpha` is an empirical, per-network
    false-alert-rate target rather than a hand-picked score cut-off.
    Under stationary traffic, at most ~alpha of benign flows alert.

`one_way=True` drops every responder-side feature, so the same detector works
from a uni-directional tap (where resp_bytes / resp_pkts are always 0).
"""
from __future__ import annotations

import math
import time
import uuid
from collections import defaultdict
from typing import Optional

import numpy as np

from src.alert_schema import Alert, FlowIdentifier, MitreAttack

_EPS = 1e-6
_MIN_SERVICE_FLOWS = 20       # below this a service borrows the pooled profile
_NOVEL_SERVICE_BONUS = 3.0    # added z-score for a service unseen in learning


def _service(rec: dict) -> tuple:
    return (str(rec.get("proto", "tcp")).lower(), int(rec.get("id.resp_p", 0) or 0))


def _features(rec: dict, one_way: bool) -> np.ndarray:
    ob = float(rec.get("orig_bytes", 0) or 0)
    op = float(rec.get("orig_pkts", 0) or 0)
    dur = float(rec.get("duration", 0.0) or 0.0)
    f = [math.log1p(ob), math.log1p(op), math.log1p(dur), math.log1p(ob / max(dur, 1e-3))]
    if not one_way:
        rb = float(rec.get("resp_bytes", 0) or 0)
        rp = float(rec.get("resp_pkts", 0) or 0)
        f += [math.log1p(rb), math.log1p(rp)]
    return np.asarray(f, dtype=np.float64)


class _Profile:
    __slots__ = ("med", "scale")

    def __init__(self, X: np.ndarray):
        self.med = np.median(X, axis=0)
        mad = np.median(np.abs(X - self.med), axis=0)
        # a MAD of 0 (a constant feature) would turn any deviation into an
        # infinite z-score; floor it at a fraction of the feature's range.
        self.scale = np.maximum(1.4826 * mad, 0.05 + 0.02 * (X.max(axis=0) - X.min(axis=0)))

    def z(self, x: np.ndarray) -> float:
        return float(np.max(np.abs(x - self.med) / self.scale))


class OnlineBaseline:
    def __init__(self, learn_min_flows: int = 1500, learn_min_seconds: float = 600.0,
                 alpha: float = 0.001, one_way: bool = False, max_learn_flows: int = 50_000):
        self.learn_min_flows = learn_min_flows
        self.learn_min_seconds = learn_min_seconds
        self.alpha = alpha
        self.one_way = one_way
        self.max_learn_flows = max_learn_flows
        self._t0: Optional[float] = None
        self._learn: list[tuple[tuple, np.ndarray]] = []
        self._profiles: dict[tuple, _Profile] = {}
        self._pooled: Optional[_Profile] = None
        self._cal: np.ndarray = np.empty(0)
        self.armed = False
        self.stats = {"learned_flows": 0, "scored": 0, "alerts": 0}

    # ------------------------------------------------------------ status
    def status(self) -> dict:
        elapsed = (time.time() - self._t0) if self._t0 else 0.0
        return {
            "phase": "armed" if self.armed else "learning",
            "learned_flows": self.stats["learned_flows"],
            "need_flows": self.learn_min_flows,
            "elapsed_s": round(elapsed, 1),
            "need_seconds": self.learn_min_seconds,
            "alpha": self.alpha,
            "one_way": self.one_way,
            "services": len(self._profiles),
            "scored": self.stats["scored"],
            "alerts": self.stats["alerts"],
        }

    # ------------------------------------------------------------ learn
    def _score(self, svc: tuple, x: np.ndarray) -> float:
        prof = self._profiles.get(svc)
        if prof is not None:
            return prof.z(x)
        return (self._pooled.z(x) if self._pooled else 0.0) + _NOVEL_SERVICE_BONUS

    def _fit(self) -> None:
        n = len(self._learn)
        cut = int(n * 0.7)
        train, cal = self._learn[:cut], self._learn[cut:]
        by_svc: dict[tuple, list[np.ndarray]] = defaultdict(list)
        for svc, x in train:
            by_svc[svc].append(x)
        allx = np.stack([x for _, x in train])
        self._pooled = _Profile(allx)
        self._profiles = {s: _Profile(np.stack(v)) for s, v in by_svc.items() if len(v) >= _MIN_SERVICE_FLOWS}
        # Calibration scores use the SAME scoring path a live flow will, incl.
        # the novel-service bonus for services that only appear in the hold-out.
        self._cal = np.sort(np.asarray([self._score(s, x) for s, x in cal]))
        self.armed = True
        self._learn = []

    def p_value(self, score: float) -> float:
        n = len(self._cal)
        ge = n - int(np.searchsorted(self._cal, score, side="left"))
        return (1 + ge) / (n + 1)

    # ------------------------------------------------------------ warm start
    def warm_start(self, records: list[dict]) -> None:
        """Seed the learning window from a batch of already-completed flows
        (e.g. a short historical pcap of this same network, parsed once at
        capture start) instead of only ever learning one flow at a time as
        live traffic trickles in -- a cold deployment otherwise sits in
        `learning` phase for a fixed ~10 minutes (`learn_min_seconds`) no
        matter how much traffic arrives, which is a long wait for a demo
        or a fresh install and was flagged directly as a real usability
        gap (not a bug -- the wait exists on purpose, see the module
        docstring) after live-testing this session.

        Does NOT bypass `learn_min_seconds`: what's compared against it is
        the batch's OWN internal time range (max(ts) - min(ts)), never
        "now minus the file's timestamp" -- an old pcap with a narrow
        internal span must not trivially satisfy the requirement just
        because it was captured long ago. (An earlier version of this got
        that wrong -- compared against the file's raw timestamp directly
        -- and was caught by testing against a real sample pcap through
        the real API: it armed instantly on a capture that only actually
        spans ~37 real seconds, years old.) A batch whose own span already
        covers `learn_min_seconds` arms immediately, correctly, since the
        traffic really does cover that much real diversity, just observed
        retroactively. A narrower batch is credited for the diversity it
        DOES have and waits out the rest against the real wall clock from
        here -- the statistical basis for the wait is never weakened by
        this method, only satisfied earlier when the data genuinely
        earns it.

        Safe to call more than once before arming (e.g. an initial warm
        start followed by early live flows); a no-op once already armed,
        so a stray resend can never silently reset learned profiles."""
        if self.armed or not records:
            return
        for rec in records:
            self._learn.append((_service(rec), _features(rec, self.one_way)))
        self.stats["learned_flows"] = len(self._learn)

        # The real-time-diversity requirement is about how much of a real
        # time RANGE the traffic covers, not how long ago the file was
        # captured -- an old pcap with a narrow internal span (e.g. 30
        # seconds of traffic recorded years ago) must NOT trivially satisfy
        # a 600-second requirement just because "now minus its timestamp"
        # is huge. Caught by testing this against a REAL sample pcap
        # through the real API, not assumed: an early version compared
        # against `min(timestamps)` directly and armed instantly on a
        # capture that only actually spans ~37 real seconds.
        timestamps = [float(r["ts"]) for r in records if r.get("ts")]
        batch_span = (max(timestamps) - min(timestamps)) if len(timestamps) >= 2 else 0.0
        if self._t0 is None:
            # A batch whose OWN span already covers learn_min_seconds needs
            # nothing further from the wall clock -- back-date _t0 so the
            # gate below is satisfied immediately, correctly. A narrower
            # batch gets credited for the diversity it DOES have; the rest
            # must still be earned against real elapsed time from now,
            # exactly as if these flows had simply arrived live.
            self._t0 = time.time() - min(batch_span, self.learn_min_seconds)

        now = time.time()
        if (len(self._learn) >= self.learn_min_flows and now - self._t0 >= self.learn_min_seconds) \
                or len(self._learn) >= self.max_learn_flows:
            self._fit()

    # ------------------------------------------------------------ observe
    def observe(self, rec: dict, now: Optional[float] = None) -> Optional[Alert]:
        """Feed ONE completed (expired) flow. Returns an Alert when armed and
        the flow is significantly anomalous, else None."""
        now = now if now is not None else time.time()
        if self._t0 is None:
            self._t0 = now
        svc, x = _service(rec), _features(rec, self.one_way)

        if not self.armed:
            self._learn.append((svc, x))
            self.stats["learned_flows"] = len(self._learn)
            if (len(self._learn) >= self.learn_min_flows and now - self._t0 >= self.learn_min_seconds) \
                    or len(self._learn) >= self.max_learn_flows:
                self._fit()
            return None

        self.stats["scored"] += 1
        s = self._score(svc, x)
        p = self.p_value(s)
        if p > self.alpha:
            return None
        self.stats["alerts"] += 1
        known = svc in self._profiles
        return Alert(
            alert_id=str(rec.get("uid") or uuid.uuid4()),
            timestamp=float(rec.get("ts", now)),
            severity="MEDIUM" if p > self.alpha / 10 else "HIGH",
            confidence_score=round(min(99.0, 100.0 * (1.0 - p)), 2),
            threat_class="BEHAVIORAL_ANOMALY",
            flow_identifier=FlowIdentifier(
                src_ip=str(rec.get("id.orig_h", "0.0.0.0")), src_port=int(rec.get("id.orig_p", 0) or 0),
                dst_ip=str(rec.get("id.resp_h", "0.0.0.0")), dst_port=int(rec.get("id.resp_p", 0) or 0),
                protocol="UDP" if svc[0] == "udp" else "TCP",
            ),
            mitre_attack=MitreAttack(tactic="Discovery", technique_id="T1046",
                                     technique_name="Network Service Discovery"),
            evidence={
                "anomaly_score": round(s, 3), "conformal_p_value": round(p, 5), "alpha": self.alpha,
                "service_seen_in_learning": known, "service": f"{svc[0]}/{svc[1]}",
                "calibration_flows": int(len(self._cal)), "one_way_features": self.one_way,
            },
            forensics={"raw_segment_hash_sha256": str(rec.get("segment_hash", ""))},
            detection_mode="baseline",
            model_scores={"baseline_anomaly": round(s, 4), "p_value": round(p, 6)},
        )
