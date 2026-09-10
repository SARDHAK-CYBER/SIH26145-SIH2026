from __future__ import annotations
from typing import Optional
from src.alert_schema import Alert, FlowIdentifier, MitreAttack
from src.engines.base import Detector

DANGEROUS_MODBUS_FUNCTIONS = {
    "WRITE_SINGLE_REGISTER",
    "WRITE_MULTIPLE_REGISTERS",
    "WRITE_SINGLE_COIL",
    "DIAGNOSTICS"
}

# EtherNet/IP (CIP) dangerous service codes -- built from DIRECT byte-level
# verification against real, named attack captures (ITI/ICS-Security-Tools'
# openics + Digital Bond Quickdraw scenarios), using tshark's mature CIP
# dissector rather than guessed offsets. Real evidence per code:
#   0x04 (Create)              -- seen in ChangeDateAttempt, ChangeTimeAttempt,
#                                  SoftwareDownload, RebootorRestart
#   0x10 (Set_Attribute_Single) -- seen in ChangePortConfigurationAttempt;
#                                  also a standard, spec-documented CIP service
#                                  that modifies device configuration
#   0x4B (vendor-specific)      -- seen in LockPLCAttempt, UnlockPLCAttempt,
#                                  FirmwareChange, SoftwareUpload, RebootorRestart
#   0x4F (vendor-specific)      -- seen in SoftwareUpload
#   0x50 (vendor-specific)      -- seen in RebootorRestart specifically
# Cross-check: these codes were confirmed ABSENT from EIP-ViewDeviceStatus.pcap
# (30 packets of real benign device-status polling, zero matches) -- genuine
# evidence these are rare/attack-associated, not normal background traffic.
#
# HONEST LIMITATION: this cannot yet distinguish WHICH specific dangerous
# operation occurred (e.g. Lock vs Unlock use the identical service code and
# even identical payload bytes in the samples checked) -- the real
# differentiator is deeper in the CIP request path (class/instance routing)
# than was extracted here. This detects "a rare, PLC-control-family CIP
# service was used" reliably; it does not yet label which one.
DANGEROUS_CIP_SERVICES = {0x04, 0x10, 0x4B, 0x4F, 0x50}

# DNP3 (IEEE 1815) application-layer function codes that change outstation
# state or device availability -- the DNP3 analogue of a Modbus write.
# CRITICAL: actuator control + device/app restart (direct process impact).
DNP3_CRITICAL_FUNCTIONS = {
    "SELECT", "OPERATE", "DIRECT_OPERATE", "DIRECT_OPERATE_NR",
    "COLD_RESTART", "WARM_RESTART", "STOP_APPLICATION",
}
# HIGH: object writes, unsolicited-response suppression (blinds the master),
# app lifecycle, file deletion.
DNP3_HIGH_FUNCTIONS = {
    "WRITE", "DISABLE_UNSOLICITED", "ENABLE_UNSOLICITED",
    "INITIALIZE_APPLICATION", "START_APPLICATION", "INITIALIZE_DATA",
    "SAVE_CONFIGURATION", "DELETE_FILE", "ASSIGN_CLASS",
}


class OTIndustrialAnomalyDetector(Detector):
    name = "ENG-07-OT"

    async def score(self, flow: dict) -> Optional[Alert]:
        proto = flow.get("protocol_analyzed", "")

        if proto == "dnp3":
            fc = str(flow.get("dnp3_func", "")).upper()
            if fc in DNP3_CRITICAL_FUNCTIONS or fc in DNP3_HIGH_FUNCTIONS:
                critical = fc in DNP3_CRITICAL_FUNCTIONS
                return Alert(
                    alert_id=flow["flow_uid"], timestamp=flow["ts"],
                    severity="CRITICAL" if critical else "HIGH",
                    confidence_score=94.0 if critical else 80.0,
                    threat_class="ICS_UNAUTHORIZED_CONTROL_COMMAND",
                    flow_identifier=FlowIdentifier(
                        src_ip=flow["src_ip"], src_port=flow["src_port"],
                        dst_ip=flow["dst_ip"], dst_port=flow["dst_port"], protocol="TCP",
                    ),
                    mitre_attack=MitreAttack(
                        tactic="Impair Process Control", technique_id="T0855",
                        technique_name="Unauthorized Command Message",
                    ),
                    evidence={"protocol": "DNP3", "function_code": fc,
                              "impact": "actuator/device control" if critical else "outstation write / master blinding"},
                    forensics={"raw_segment_hash_sha256": flow.get("segment_hash", "")},
                )
            return None

        if proto == "modbus":
            func_code = flow.get("modbus_func", "")
            if func_code in DANGEROUS_MODBUS_FUNCTIONS:
                return Alert(
                    alert_id=flow["flow_uid"],
                    timestamp=flow["ts"],
                    severity="HIGH",
                    confidence_score=95.0,
                    threat_class="ICS_UNAUTHORIZED_CONTROL_COMMAND",
                    flow_identifier=FlowIdentifier(
                        src_ip=flow["src_ip"], src_port=flow["src_port"],
                        dst_ip=flow["dst_ip"], dst_port=flow["dst_port"], protocol="TCP"
                    ),
                    mitre_attack=MitreAttack(
                        tactic="Impair Process Control", technique_id="T0855",
                        technique_name="Unauthorized Command Message"
                    ),
                    evidence={"protocol": "Modbus", "function_code": func_code, "target_register": flow.get("register_address", 0)},
                    forensics={"raw_segment_hash_sha256": flow.get("segment_hash", "")}
                )

        elif proto == "enip":
            cip_service = flow.get("cip_service")
            is_response = flow.get("cip_response", False)
            # Only fire on the REQUEST, not its acknowledgment response --
            # matches the pattern of catching the command being issued.
            if cip_service in DANGEROUS_CIP_SERVICES and not is_response:
                return Alert(
                    alert_id=flow["flow_uid"],
                    timestamp=flow["ts"],
                    severity="HIGH",
                    confidence_score=85.0,  # slightly below Modbus's 95 -- real evidence exists, but can't yet name the exact operation
                    threat_class="ICS_UNAUTHORIZED_CONTROL_COMMAND",
                    flow_identifier=FlowIdentifier(
                        src_ip=flow["src_ip"], src_port=flow["src_port"],
                        dst_ip=flow["dst_ip"], dst_port=flow["dst_port"], protocol="TCP"
                    ),
                    mitre_attack=MitreAttack(
                        tactic="Impair Process Control", technique_id="T0855",
                        technique_name="Unauthorized Command Message"
                    ),
                    evidence={
                        "protocol": "EtherNet/IP (CIP)",
                        "cip_service_code": hex(cip_service),
                        "class_id": flow.get("cip_class_id"),
                        "instance_id": flow.get("cip_instance_id"),
                    },
                    forensics={"raw_segment_hash_sha256": flow.get("segment_hash", "")}
                )

        return None