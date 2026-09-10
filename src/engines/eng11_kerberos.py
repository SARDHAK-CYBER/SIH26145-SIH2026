"""
ENG-11 -- Kerberoasting detection via Kerberos ticket-encryption analysis.

Fields used (KRB::Info, kerberos.log) confirmed directly against Zeek's
own official documentation, not guessed: request_type, service, cipher.

Kerberoasting is a well-documented, specific technique: an attacker
requests a Ticket Granting Service (TGS) ticket for a service account,
then cracks it offline -- this only works if the ticket uses weak RC4
encryption rather than modern AES, since RC4-encrypted service tickets
are practically crackable while AES ones aren't. A TGS request for a
service account using RC4 is the textbook indicator; real, modern
Windows environments negotiate AES by default, so seeing RC4 at all is
itself unusual, not just the request pattern alone.
"""
from __future__ import annotations
import uuid
from typing import Optional
from src.alert_schema import Alert, FlowIdentifier, MitreAttack
from src.engines.base import Detector

# Confirmed from Zeek's own KRB::cipher_name const table -- these are
# the real RC4 cipher identifiers, not guessed strings.
WEAK_CIPHERS = {"rc4-hmac", "rc4-hmac-exp"}


class KerberosAttackDetector(Detector):
    name = "ENG-11"

    async def score(self, flow: dict) -> Optional[Alert]:
        request_type = flow.get("krb_request_type", "")
        cipher = flow.get("krb_cipher", "")
        service = flow.get("krb_service", "")

        if request_type != "TGS" or cipher not in WEAK_CIPHERS:
            return None
        # krbtgt is the ticket-granting service itself, not a "service
        # account" in the Kerberoasting sense -- excluding it avoids
        # flagging completely normal initial ticket-granting exchanges.
        if service.lower() in ("krbtgt", ""):
            return None

        return Alert(
            alert_id=str(uuid.uuid4()),
            timestamp=float(flow.get("ts", 0.0)),
            severity="HIGH",
            confidence_score=85.0,
            threat_class="NETWORK_INTRUSION_ATTEMPT",
            flow_identifier=FlowIdentifier(
                src_ip=flow.get("src_ip", "0.0.0.0"), src_port=int(flow.get("src_port", 0)),
                dst_ip=flow.get("dst_ip", "0.0.0.0"), dst_port=int(flow.get("dst_port", 88)),
                protocol="TCP",
            ),
            mitre_attack=MitreAttack(
                tactic="Credential Access", technique_id="T1558.003",
                technique_name="Steal or Forge Kerberos Tickets: Kerberoasting",
            ),
            evidence={"krb_service": service, "krb_cipher": cipher, "krb_request_type": request_type},
            forensics={"raw_segment_hash_sha256": flow.get("segment_hash", "")},
            detection_mode="rule",
        )
