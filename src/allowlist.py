"""
Operator allowlist: suppress alerts that a human has verified as benign FOR THIS SITE, without code changes and without losing
the audit trail.

    config/allowlist.json      (path override: STEALTHTAP_ALLOWLIST; re-read automatically when the file changes)

    {"rules": [
      {"id": "eng-ws-to-plc", "reason": "engineering workstation programs PLC 10.0.0.3 (ticket 4711)",
       "threat_class": "ICS_UNAUTHORIZED_CONTROL_COMMAND", "src": "10.0.0.9", "dst": "10.0.0.3", "dst_port": [502],
       "evidence": {"function_code": "WRITE_SINGLE_COIL"}, "expires": "2027-06-30"}
    ]}

A rule matches when EVERY field it names matches:  threat_class, severity, detection_mode, src / dst (address or CIDR, string or
list), src_port / dst_port (int or list), evidence (each key equals, or for a list value "is one of").
Guard rails, so a rule cannot quietly blind the sensor:
  * `reason` is required, and at least one of src / dst / dst_port / evidence must be present (no blanket "suppress a class");
  * CRITICAL alerts are never suppressed unless the rule says `"critical_ok": true`;
  * `expires` (YYYY-MM-DD) is honoured; a rule that no longer parses or has expired is ignored and reported by `status()`;
  * suppressed alerts are NOT dropped silently: they are counted per rule and the newest are kept for review (`recent()`).
"""
from __future__ import annotations

import collections
import ipaddress
import json
import os
import threading
import time
from datetime import date
from pathlib import Path
from typing import Any, Optional

DEFAULT_PATH = "config/allowlist.json"


def _as_list(v: Any) -> list:
    return v if isinstance(v, list) else [v]


class Allowlist:
    def __init__(self, path: Optional[str] = None, keep: int = 200):
        self.path = Path(path or os.environ.get("STEALTHTAP_ALLOWLIST", DEFAULT_PATH))
        self._lock = threading.Lock()
        self._mtime = None
        self._rules: list[dict] = []
        self._problems: list[str] = []
        self.hits: collections.Counter = collections.Counter()
        self._recent: collections.deque = collections.deque(maxlen=keep)
        self._checked = 0.0

    # ---- loading -------------------------------------------------------------------------------------------------------
    def _compile(self, r: dict) -> Optional[dict]:
        rid = str(r.get("id") or r.get("reason", "?"))[:60]
        if r.get("enabled", True) is False:
            return None
        if not str(r.get("reason", "")).strip():
            self._problems.append(f"{rid}: missing reason -- ignored")
            return None
        if not any(k in r for k in ("src", "dst", "dst_port", "src_port", "evidence")):
            self._problems.append(f"{rid}: needs at least one of src/dst/dst_port/src_port/evidence (no blanket suppression) -- ignored")
            return None
        if r.get("expires"):
            try:
                if date.fromisoformat(str(r["expires"])) < date.today():
                    self._problems.append(f"{rid}: expired {r['expires']} -- ignored")
                    return None
            except ValueError:
                self._problems.append(f"{rid}: bad expires date -- ignored")
                return None
        try:
            nets = {k: [ipaddress.ip_network(str(x), strict=False) for x in _as_list(r[k])] for k in ("src", "dst") if k in r}
        except ValueError as exc:
            self._problems.append(f"{rid}: bad address ({exc}) -- ignored")
            return None
        return {"id": rid, "raw": r, "nets": nets}

    def _maybe_reload(self) -> None:
        now = time.monotonic()
        if now - self._checked < 2.0:
            return
        self._checked = now
        try:
            m = self.path.stat().st_mtime
        except OSError:
            if self._mtime is not None:
                with self._lock:
                    self._rules, self._problems, self._mtime = [], [], None
            return
        if m == self._mtime:
            return
        with self._lock:
            self._problems = []
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                rules = [c for c in (self._compile(r) for r in data.get("rules", [])) if c]
            except (OSError, ValueError, AttributeError) as exc:
                self._problems.append(f"{self.path}: unreadable ({exc}) -- no rules active")
                rules = []
            self._rules, self._mtime = rules, m

    # ---- matching ------------------------------------------------------------------------------------------------------
    @staticmethod
    def _match(c: dict, a: dict) -> bool:
        r, fi, ev = c["raw"], a.get("flow_identifier", {}) or {}, a.get("evidence", {}) or {}
        if "threat_class" in r and a.get("threat_class") not in _as_list(r["threat_class"]):
            return False
        if "severity" in r and a.get("severity") not in _as_list(r["severity"]):
            return False
        if "detection_mode" in r and a.get("detection_mode", "rule") not in _as_list(r["detection_mode"]):
            return False
        for k in ("src", "dst"):
            if k in c["nets"]:
                try:
                    ip = ipaddress.ip_address(fi.get(f"{k}_ip", ""))
                except ValueError:
                    return False
                if not any(ip in n for n in c["nets"][k]):
                    return False
        for k in ("src_port", "dst_port"):
            if k in r and int(fi.get(k, -1)) not in [int(x) for x in _as_list(r[k])]:
                return False
        for k, want in (r.get("evidence") or {}).items():
            if ev.get(k) not in _as_list(want):
                return False
        if a.get("severity") == "CRITICAL" and not r.get("critical_ok"):
            return False
        return True

    def match(self, alert: dict) -> Optional[str]:
        """Rule id that suppresses this alert, or None. Cheap when no file exists."""
        self._maybe_reload()
        if not self._rules:
            return None
        for c in self._rules:
            if self._match(c, alert):
                self.hits[c["id"]] += 1
                self._recent.append({"rule": c["id"], "at": time.time(), "alert": alert})
                return c["id"]
        return None

    # ---- reporting -----------------------------------------------------------------------------------------------------
    def status(self) -> dict:
        self._maybe_reload()
        return {"path": str(self.path), "active_rules": [{"id": c["id"], "reason": c["raw"]["reason"], "expires": c["raw"].get("expires"),
                                                            "suppressed": self.hits.get(c["id"], 0)} for c in self._rules],
                "problems": list(self._problems), "suppressed_total": sum(self.hits.values())}

    def recent(self, limit: int = 100) -> list[dict]:
        return list(self._recent)[-limit:][::-1]


_default: Optional[Allowlist] = None


def default() -> Allowlist:
    global _default
    if _default is None:
        _default = Allowlist()
    return _default
