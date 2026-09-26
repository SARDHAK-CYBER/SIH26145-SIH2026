"""
ENG-14 -- attacks on plain-text application services, decided from decoded application-layer content.

Built after the real-capture evaluation showed three classes of Metasploit-style intrusion (distcc remote execution, SMTP
account enumeration, Tomcat manager login + WAR deployment) leaving no volumetric or flow-shape signature at all -- every
byte of evidence is in the payload, so flow engines cannot see it. Decoders: native/stealthtap_core/src/appsvc.rs and its
Python twin src/capture/appsvc.py; this engine only interprets their events.

Rules (each is a property of the PROTOCOL, not of a particular capture):
  distcc            a distcc job whose argv[0] is not a compiler (distcc exists to run compilers; `sh -c ...` is command execution)
  smtp enumeration  >= 3 distinct VRFY/EXPN arguments from one client to one server in 5 min (legitimate MTAs do not use VRFY),
                    or >= 15 distinct RCPT TO recipients with >= 3 "550" refusals in 5 min (address harvesting)
  default creds     HTTP Basic credentials equal to a vendor default (tomcat:tomcat, admin:admin, ...) sent in cleartext
  http auth guessing >= 5 Basic-auth requests AND >= 5 401 answers between one client and one server within 60 s
  web deployment    POST/PUT to a code-deployment endpoint (Tomcat manager WAR upload, Jenkins script console); HIGH when the same
                    client had just presented default credentials or been refused
Passwords never reach this engine (the decoder drops them); state is bounded and per (client, server).
"""
from __future__ import annotations

import time
import uuid
from collections import OrderedDict, deque
from typing import Optional

from src.alert_schema import Alert, FlowIdentifier, MitreAttack
from src.engines.base import Detector

ENUM_WINDOW_S = 300.0
GUESS_WINDOW_S = 60.0
VRFY_DISTINCT = 3
RCPT_DISTINCT = 15
RCPT_REJECTS = 3
GUESS_MIN = 5
MAX_KEYS = 50_000
REALERT_S = 600.0        # the same finding for the same pair is reported once per 10 minutes


class _Bounded(OrderedDict):
    def touch(self, key, factory):
        v = self.get(key)
        if v is None:
            v = factory()
            self[key] = v
            if len(self) > MAX_KEYS:
                self.popitem(last=False)
        else:
            self.move_to_end(key)
        return v


class AppServiceAttackDetector(Detector):
    name = "ENG-14"

    def __init__(self) -> None:
        self._enum = _Bounded()      # (client, server) -> {"vrfy": {user: ts}, "rcpt": {user: ts}, "rej": deque[ts]}
        self._auth = _Bounded()      # (client, server, port) -> {"basic": deque[ts], "r401": deque[ts], "default_ts": float}
        self._sent = _Bounded()      # (rule, client, server) -> last alert ts

    # ---- helpers -----------------------------------------------------------------------------
    @staticmethod
    def _trim(d: deque, now: float, window: float) -> None:
        while d and now - d[0] > window:
            d.popleft()

    def _once(self, rule: str, client: str, server: str, ts: float) -> bool:
        last = self._sent.get((rule, client, server))
        if last is not None and ts - last < REALERT_S:
            return False
        self._sent.touch((rule, client, server), lambda: 0.0)
        self._sent[(rule, client, server)] = ts
        return True

    @staticmethod
    def _alert(flow: dict, *, severity: str, conf: float, cls: str, tactic: str, tid: str, tname: str, evidence: dict) -> Alert:
        return Alert(
            alert_id=uuid.uuid4().hex, timestamp=float(flow.get("ts", 0.0)), severity=severity, confidence_score=conf,
            threat_class=cls,
            flow_identifier=FlowIdentifier(
                src_ip=flow.get("src_ip", "0.0.0.0"), src_port=int(flow.get("src_port", 0)),
                dst_ip=flow.get("dst_ip", "0.0.0.0"), dst_port=int(flow.get("dst_port", 0)), protocol="TCP"),
            mitre_attack=MitreAttack(tactic=tactic, technique_id=tid, technique_name=tname),
            evidence=evidence, forensics={"raw_segment_hash_sha256": flow.get("segment_hash", "")}, detection_mode="rule",
        )

    # ---- scoring -----------------------------------------------------------------------------
    async def score(self, flow: dict) -> Optional[Alert]:
        fn = str(flow.get("app_function", ""))
        if not fn:
            return None
        detail = str(flow.get("app_detail", ""))
        code = int(flow.get("app_code", 0) or 0)
        client, server = flow.get("src_ip", ""), flow.get("dst_ip", "")
        sport = int(flow.get("dst_port", 0))
        ts = float(flow.get("ts", 0.0)) or time.time()

        if fn.startswith("distcc:"):
            if code == 1 and self._once("distcc", client, server, ts):
                return self._alert(flow, severity="CRITICAL", conf=95.0, cls="NETWORK_INTRUSION_ATTEMPT", tactic="Initial Access",
                                   tid="T1190", tname="Exploit Public-Facing Application", evidence={
                                       "service": "distcc", "argv0": fn.split(":", 1)[1], "command": detail,
                                       "why": "distcc runs compilers; a non-compiler argv[0] is remote command execution"})
            return None

        if fn in ("smtp_vrfy", "smtp_expn", "smtp_rcpt", "smtp_reject"):
            # keyed by the unordered address pair: the server's refusals may be attributed to either side when a capture's
            # addressing is inconsistent (seen in the smtp22 sample), and evidence must still meet the client's probes
            st = self._enum.touch(tuple(sorted((client, server))), lambda: {"vrfy": {}, "rcpt": {}, "rej": deque()})
            if fn == "smtp_reject":
                st["rej"].append(ts)
                self._trim(st["rej"], ts, ENUM_WINDOW_S)
                return None                     # only the client's own commands trigger (so the alert names the attacker)
            elif fn == "smtp_rcpt":
                st["rcpt"][detail] = ts
            else:
                st["vrfy"][detail] = ts
            for k in ("vrfy", "rcpt"):
                for u in [u for u, t in st[k].items() if ts - t > ENUM_WINDOW_S]:
                    del st[k][u]
            self._trim(st["rej"], ts, ENUM_WINDOW_S)
            why = None
            if len(st["vrfy"]) >= VRFY_DISTINCT:
                why = f"{len(st['vrfy'])} distinct VRFY/EXPN account probes"
            elif len(st["rcpt"]) >= RCPT_DISTINCT and len(st["rej"]) >= RCPT_REJECTS:
                why = f"{len(st['rcpt'])} distinct RCPT recipients with {len(st['rej'])} refusals"
            if why and self._once("smtp_enum", client, server, ts):
                return self._alert(flow, severity="MEDIUM", conf=85.0, cls="RECONNAISSANCE", tactic="Discovery", tid="T1087",
                                   tname="Account Discovery", evidence={
                                       "service": "smtp", "finding": why, "sample_accounts": sorted({*st["vrfy"], *st["rcpt"]})[:8]})
            return None

        if fn in ("http_basic", "http_401", "http_admin_deploy"):
            st = self._auth.touch((client, server, sport), lambda: {"basic": deque(), "r401": deque(), "default_ts": -1e18})
            if fn == "http_basic":
                st["basic"].append(ts)
                if code == 1:
                    st["default_ts"] = ts
                    if self._once("default_cred", client, server, ts):
                        return self._alert(flow, severity="HIGH", conf=80.0, cls="NETWORK_INTRUSION_ATTEMPT", tactic="Initial Access",
                                           tid="T1078.001", tname="Valid Accounts: Default Accounts", evidence={
                                               "service": "http", "user": detail,
                                               "why": "vendor-default credentials presented in cleartext HTTP Basic authentication"})
            elif fn == "http_401":
                st["r401"].append(ts)
            else:
                self._trim(st["r401"], ts, ENUM_WINDOW_S)
                recent_bad = ts - st["default_ts"] < ENUM_WINDOW_S or len(st["r401"]) > 0
                if self._once("web_deploy", client, server, ts):
                    return self._alert(flow, severity="HIGH" if recent_bad else "MEDIUM", conf=85.0 if recent_bad else 65.0,
                                       cls="NETWORK_INTRUSION_ATTEMPT", tactic="Execution", tid="T1505.003",
                                       tname="Server Software Component: Web Shell", evidence={
                                           "service": "http", "endpoint": detail,
                                           "why": "request to a code-deployment endpoint (uploads server-side code)",
                                           "preceded_by_default_credentials_or_refusals": recent_bad})
                return None
            self._trim(st["basic"], ts, GUESS_WINDOW_S)
            self._trim(st["r401"], ts, GUESS_WINDOW_S)
            if len(st["basic"]) >= GUESS_MIN and len(st["r401"]) >= GUESS_MIN and self._once("http_guess", client, server, ts):
                return self._alert(flow, severity="HIGH", conf=85.0, cls="NETWORK_INTRUSION_ATTEMPT", tactic="Credential Access",
                                   tid="T1110", tname="Brute Force", evidence={
                                       "service": "http", "attempts_60s": len(st["basic"]), "refusals_60s": len(st["r401"])})
        return None
