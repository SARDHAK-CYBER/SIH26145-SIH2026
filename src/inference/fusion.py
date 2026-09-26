"""
How AI verdicts are allowed to become alerts.

Measured on real captures (scripts/eval_real_traffic.py): the AI-only
configuration had the weakest recall (36%) and the same benign false-
positive rate as the rule engines, because two of the trained families are
not strong enough to alert ON THEIR OWN:

  flow   -- trained on eight DDoS captures (SYN flood, amplification, ...)
            against 629 benign flows from two files, using four features.
            It is a DDoS-shape detector, not a general one; its random
            80/20 split came from the same source captures, so its
            published F1 0.999 overstates real-world performance.
  tls    -- no trained model at all.

Policy (per family):
  * standalone_threshold(family): the score an ML verdict needs to raise an
    alert by itself. High for the weak families.
  * corroborated: if a RULE engine already flagged the same flow, the ML
    score only needs the normal MIN_ML_CONFIDENCE -- two independent
    detectors agreeing is exactly when a weaker model is useful.
"""
from __future__ import annotations

import os

from src.inference.model_server import MIN_ML_CONFIDENCE

# > 1.0 means "never alert alone". Even at 0.98 the flow model flagged benign
# DNS-over-UDP flows that are in its OWN training set (0.99 "DDoS" on a
# 192.168.0.x -> 192.168.0.1:53 query) -- four features cannot separate a
# DNS query from a DNS-amplification packet. It stays available as
# corroboration for a rule alert; set ML_FLOW_STANDALONE_CONFIDENCE=0.98
# to re-enable standalone alerts after retraining on diverse labelled flows.
_STANDALONE = {
    "flow": float(os.environ.get("ML_FLOW_STANDALONE_CONFIDENCE", "2.0")),
    "tls": float(os.environ.get("ML_TLS_STANDALONE_CONFIDENCE", "2.0")),   # no trained model exists
    # Measured on 79,154 real Modbus records from 343 public ICS captures (many plants): the model flags exactly the WRITE
    # function codes -- 13.8% of requests, plus their echoed responses -- which ENG-07's rule already reports with the function
    # named. Standalone it only duplicates the rule (and alerts on the response direction too), so it is off by default.
    "modbus": float(os.environ.get("ML_MODBUS_STANDALONE_CONFIDENCE", "2.0")),
}


def standalone_threshold(family: str) -> float:
    return max(_STANDALONE.get(family, MIN_ML_CONFIDENCE), MIN_ML_CONFIDENCE)


def effective_threshold(family: str, corroborated: bool) -> float:
    return MIN_ML_CONFIDENCE if corroborated else standalone_threshold(family)
