"""Operator allowlist: matching, guard rails, expiry, reload, auditability, and the live-agent / upload integration."""
import json
import os
import time

import pytest

from src.allowlist import Allowlist


def alert(**kw):
    a = {"threat_class": "ICS_UNAUTHORIZED_CONTROL_COMMAND", "severity": "HIGH", "detection_mode": "rule",
         "flow_identifier": {"src_ip": "10.0.0.9", "src_port": 40000, "dst_ip": "10.0.0.3", "dst_port": 502, "protocol": "TCP"},
         "evidence": {"function_code": "WRITE_SINGLE_COIL"}}
    fi = kw.pop("fi", None)
    a.update(kw)
    if fi:
        a["flow_identifier"] = {**a["flow_identifier"], **fi}
    return a


def make(tmp_path, rules):
    p = tmp_path / "allowlist.json"
    p.write_text(json.dumps({"rules": rules}))
    al = Allowlist(str(p))
    al._checked = 0
    return al, p


GOOD = {"id": "ws-plc", "reason": "engineering workstation programs PLC", "threat_class": "ICS_UNAUTHORIZED_CONTROL_COMMAND",
        "src": "10.0.0.0/24", "dst": "10.0.0.3", "dst_port": [502], "evidence": {"function_code": ["WRITE_SINGLE_COIL", "WRITE_SINGLE_REGISTER"]}}


def test_matches_only_when_every_field_matches(tmp_path):
    al, _ = make(tmp_path, [GOOD])
    assert al.match(alert()) == "ws-plc"
    assert al.match(alert(fi={"src_ip": "10.9.9.9"})) is None            # outside the CIDR
    assert al.match(alert(fi={"dst_port": 503})) is None
    assert al.match(alert(evidence={"function_code": "PLC_STOP"})) is None
    assert al.match(alert(threat_class="C2_BEACONING")) is None


def test_no_blanket_rules_and_reason_required(tmp_path):
    al, _ = make(tmp_path, [{"id": "all", "reason": "x", "threat_class": "C2_BEACONING"},
                            {"id": "noreason", "dst": "10.0.0.3"}])
    assert al.match(alert(threat_class="C2_BEACONING")) is None and al.match(alert()) is None
    probs = " ".join(al.status()["problems"])
    assert "no blanket" in probs and "missing reason" in probs


def test_critical_is_never_suppressed_without_explicit_opt_in(tmp_path):
    al, _ = make(tmp_path, [GOOD, {**GOOD, "id": "ok-crit", "critical_ok": True, "dst": "10.0.0.4"}])
    assert al.match(alert(severity="CRITICAL")) is None
    assert al.match(alert(severity="CRITICAL", fi={"dst_ip": "10.0.0.4"})) == "ok-crit"


def test_expired_and_disabled_rules_are_ignored_and_reported(tmp_path):
    al, _ = make(tmp_path, [{**GOOD, "id": "old", "expires": "2020-01-01"}, {**GOOD, "id": "off", "enabled": False}])
    assert al.match(alert()) is None
    assert any("expired" in p for p in al.status()["problems"])
    al2, _ = make(tmp_path, [{**GOOD, "expires": "2999-01-01"}])
    assert al2.match(alert()) == "ws-plc"


def test_suppression_is_counted_and_auditable(tmp_path):
    al, _ = make(tmp_path, [GOOD])
    for _ in range(3):
        al.match(alert())
    st = al.status()
    assert st["suppressed_total"] == 3 and st["active_rules"][0]["suppressed"] == 3
    assert al.recent(2)[0]["rule"] == "ws-plc" and al.recent(2)[0]["alert"]["flow_identifier"]["dst_ip"] == "10.0.0.3"


def test_file_changes_are_picked_up_and_bad_json_fails_safe(tmp_path):
    al, p = make(tmp_path, [GOOD])
    assert al.match(alert()) == "ws-plc"
    p.write_text("{not json")
    os.utime(p, (time.time() + 5, time.time() + 5))
    al._checked = 0
    assert al.match(alert()) is None                                        # unreadable file -> nothing suppressed
    assert any("unreadable" in x for x in al.status()["problems"])
    p.write_text(json.dumps({"rules": [GOOD]}))
    os.utime(p, (time.time() + 10, time.time() + 10))
    al._checked = 0
    assert al.match(alert()) == "ws-plc"


def test_no_file_means_nothing_is_suppressed(tmp_path):
    assert Allowlist(str(tmp_path / "missing.json")).match(alert()) is None


def test_live_agent_suppresses_and_counts(tmp_path, monkeypatch):
    from src import allowlist
    from src.capture.live_agent import LiveAgent
    al, _ = make(tmp_path, [GOOD])
    monkeypatch.setattr(allowlist, "_default", al)
    agent = LiveAgent("pcap-replay", None)
    agent._emit(alert(), None)
    agent._emit(alert(fi={"dst_ip": "10.0.0.77"}, evidence={"function_code": "PLC_STOP"}), None)
    assert agent.stats["suppressed"] == 1 and agent.stats["alerts"] == 1
    agent.stop()
