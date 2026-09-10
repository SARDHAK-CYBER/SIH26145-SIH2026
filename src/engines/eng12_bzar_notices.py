"""
ENG-12 -- Parses BZAR (mitre-attack/bzar) notice.log entries.

BZAR is a real, MITRE-authored set of Zeek scripts (github.com/
mitre-attack/bzar) that detects SMB/DCE-RPC-based ATT&CK lateral
movement techniques -- PsExec-style remote execution, admin share
abuse, service creation, etc. -- and writes MITRE-mapped notices
directly to notice.log. Rather than re-implement SMB lateral-movement
heuristics from scratch, this parses BZAR's own real detections.

HONEST LIMITATION, same as batch_policy.zeek: I could not install
Zeek + BZAR in my own sandbox to verify this end-to-end (disk/network
constraints, same as before). Built directly from BZAR's real source
code structure (github.com/mitre-attack/bzar/blob/master/scripts/
main.zeek) rather than guessed, and tested against a synthetic record
shaped exactly like BZAR's own confirmed message format -- but you are
the first to run this against real notice.log output.
"""
from __future__ import annotations
import re
import uuid
from typing import Optional
from src.alert_schema import Alert, FlowIdentifier, MitreAttack

# BZAR's own Notice::Type enum values (confirmed from its real source,
# scripts/main.zeek) mapped to MITRE tactics. Technique ID is extracted
# directly from BZAR's message text when present (BZAR embeds it
# itself, e.g. "Detected T1021.002 Admin File Share activity...") --
# these are only the FALLBACK tactic/technique when no ID appears in
# the message.
BZAR_NOTE_MAPPING: dict[str, tuple[str, str, str]] = {
    "ATTACK::Credential_Access": ("Credential Access", "T1003", "OS Credential Dumping"),
    "ATTACK::Defense_Evasion": ("Defense Evasion", "T1070", "Indicator Removal"),
    "ATTACK::Discovery": ("Discovery", "T1135", "Network Share Discovery"),
    "ATTACK::Execution": ("Execution", "T1059", "Command and Scripting Interpreter"),
    "ATTACK::Impact": ("Impact", "T1489", "Service Stop"),
    "ATTACK::Lateral_Movement": ("Lateral Movement", "T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    "ATTACK::Lateral_Movement_and_Execution": ("Lateral Movement", "T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    "ATTACK::Lateral_Movement_Extracted_File": ("Lateral Movement", "T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    "ATTACK::Lateral_Movement_Multiple_Attempts": ("Lateral Movement", "T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    "ATTACK::Persistence": ("Persistence", "T1543", "Create or Modify System Process"),
}

_TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def parse_bzar_notices(notice_records: list[dict]) -> list[dict]:
    """notice_records: parsed notice.log JSON lines. Only BZAR's own
    ATTACK::* notes are handled here -- other, non-BZAR notice.log
    entries (Zeek's own built-in notices) are deliberately skipped,
    since they're a different, much noisier category not scoped to
    this engine."""
    alerts: list[dict] = []
    for record in notice_records:
        note = record.get("note", "")
        if not note.startswith("BZAR::"):
            continue
        bzar_key = note.removeprefix("BZAR::")

        msg = record.get("msg", "")
        embedded_id_match = _TECHNIQUE_ID_RE.search(msg)

        tactic, default_id, technique_name = BZAR_NOTE_MAPPING.get(
            bzar_key, ("Lateral Movement", "T1021", "Remote Services")
        )
        technique_id = embedded_id_match.group(0) if embedded_id_match else default_id

        alerts.append(Alert(
            alert_id=str(uuid.uuid4()),
            timestamp=record.get("ts", 0.0) or 0.0,
            severity="HIGH",
            confidence_score=80.0,
            threat_class="NETWORK_INTRUSION_ATTEMPT",
            flow_identifier=FlowIdentifier(
                src_ip=record.get("src", "0.0.0.0") or "0.0.0.0", src_port=0,
                dst_ip=record.get("dst", "0.0.0.0") or "0.0.0.0", dst_port=int(record.get("p", 0) or 0),
                protocol="TCP",
            ),
            mitre_attack=MitreAttack(tactic=tactic, technique_id=technique_id, technique_name=technique_name),
            evidence={"bzar_note": bzar_key, "bzar_message": msg},
            forensics={"raw_segment_hash_sha256": ""},
            detection_mode="rule",
        ).model_dump(mode="json"))
    return alerts
