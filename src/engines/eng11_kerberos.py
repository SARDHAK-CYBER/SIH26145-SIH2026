"""
ENG-11 -- Kerberoasting detection via Kerberos ticket-encryption analysis.

Fields used (KRB::Info, kerberos.log) confirmed directly against Zeek's
own official documentation, not guessed: request_type, service, cipher,
client.

`client` (the requesting principal, "username/realm") answers "which
user" for this alert type specifically -- a real, directly-observed
identity, not an inference: only the TICKET itself is encrypted, the
AS-REQ/TGS-REQ carrying the requester's name is cleartext, which is
exactly why Zeek can log it at all.

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
import os
import uuid
from typing import Optional
from src.alert_schema import Alert, FlowIdentifier, MitreAttack
from src.engines.base import Detector

# Confirmed from Zeek's own KRB::cipher_name const table -- these are
# the real RC4 cipher identifiers, not guessed strings.
WEAK_CIPHERS = {"rc4-hmac", "rc4-hmac-exp"}
MACHINE_SPN_CLASSES = set(os.environ.get("KRB_MACHINE_SPN_CLASSES",
                          "host,cifs,ldap,dns,gc,rpcss,wsman,termsrv,restrictedkrbhost,exchangemdb,exchangerfr,exchangeab,imap,smtp,pop,ftp").split(","))


class KerberosAttackDetector(Detector):
    name = "ENG-11"

    async def score(self, flow: dict) -> Optional[Alert]:
        request_type = flow.get("krb_request_type", "")
        cipher = flow.get("krb_cipher", "")
        service = flow.get("krb_service", "")
        client = flow.get("krb_client", "")

        if request_type != "TGS" or cipher not in WEAK_CIPHERS:
            return None
        # krbtgt is the ticket-granting service itself, not a "service
        # account" in the Kerberoasting sense -- excluding it avoids
        # flagging completely normal initial ticket-granting exchanges.
        # Zeek logs the TGT service as "krbtgt/REALM" (not bare "krbtgt"), so match on the principal's first
        # component -- the exact-string test let every ordinary RC4 TGT renewal through as "Kerberoasting".
        svc_class = service.lower().split("/")[0]
        if svc_class in ("krbtgt", ""):
            return None
        # SPNs of the built-in machine-service classes belong to COMPUTER accounts, whose passwords are
        # 120-character random values rotated automatically -- not crackable, so not Kerberoasting
        # targets. Measured on a REAL legacy-AD capture (Wireshark krb-816, Windows Server 2003): every
        # one of its RC4 TGS replies was for host/, cifs/ or ldap/ -- firing on them would flag every
        # ordinary login on any domain that still negotiates RC4. Kerberoasting targets SERVICE accounts
        # (MSSQLSvc/, http/, custom classes), which is what remains.
        if svc_class in MACHINE_SPN_CLASSES:
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
            evidence={
                "requesting_user": client or "(not observed)",
                "krb_service": service, "krb_cipher": cipher, "krb_request_type": request_type,
            },
            forensics={"raw_segment_hash_sha256": flow.get("segment_hash", "")},
            detection_mode="rule",
        )
