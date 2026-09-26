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
# Standard CIP state-control services -- added after a REAL capture (ITI cip_stop_plc.pcap: service 0x07 Stop to the
# Program object, class 0x8E) went undetected: 0x05 Reset, 0x06 Start, 0x07 Stop change a controller's run state.
DANGEROUS_CIP_SERVICES = {0x04, 0x05, 0x06, 0x07, 0x10, 0x4B, 0x4F, 0x50}

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


# Siemens S7comm job functions (validated against real captures: Wireshark's s7comm_downloading_block_db1,
# s7comm_reading_plc_status, s7comm_varservice_libnodavedemo). Program download and PLC stop/control are the
# operations that change what a controller does or whether it runs; a variable WRITE changes a live value.
# READ_VAR / SETUP_COMMUNICATION / userdata SZL reads are ordinary engineering-station traffic and never alert.
S7_CRITICAL_FUNCTIONS = {"PLC_STOP", "PLC_CONTROL", "REQUEST_DOWNLOAD", "DOWNLOAD_BLOCK", "DOWNLOAD_ENDED"}
S7_HIGH_FUNCTIONS = {"WRITE_VAR", "START_UPLOAD", "UPLOAD", "END_UPLOAD"}
_S7_MITRE = {  # ATT&CK for ICS
    "PLC_STOP": ("T0858", "Change Operating Mode"), "PLC_CONTROL": ("T0858", "Change Operating Mode"),
    "REQUEST_DOWNLOAD": ("T0843", "Program Download"), "DOWNLOAD_BLOCK": ("T0843", "Program Download"),
    "DOWNLOAD_ENDED": ("T0843", "Program Download"), "WRITE_VAR": ("T0836", "Modify Parameter"),
    "START_UPLOAD": ("T0845", "Program Upload"), "UPLOAD": ("T0845", "Program Upload"), "END_UPLOAD": ("T0845", "Program Upload"),
}

# IEC 60870-5-104 control-direction ASDU types (IEC 60870-5-101 Table): commands that operate equipment or
# change setpoints are CRITICAL; reset-process and clock synchronisation are HIGH. Interrogation (100), read
# (102), counter interrogation (101) are ordinary master polling and never alert.
IEC104_CRITICAL_TYPES = set(range(45, 52)) | set(range(58, 65))   # C_SC/DC/RC/SE/BO (+ time-tagged)
IEC104_HIGH_TYPES = {103, 105}                                     # clock sync, reset process


# BACnet: reads, Who-Is/I-Am discovery and COV subscriptions are ordinary building-automation traffic (decoded and
# verified silent on real captures: BACnetARRAY-*, BACnetDeviceObjectReference, BACnetIP-MSTP-Mix). State-changing
# services are what an attacker uses to alter setpoints, silence a controller or wipe it.
BACNET_CRITICAL_SERVICES = {"REINITIALIZE_DEVICE", "DEVICE_COMMUNICATION_CONTROL", "DELETE_OBJECT", "ATOMIC_WRITE_FILE"}
BACNET_HIGH_SERVICES = {"WRITE_PROPERTY", "WRITE_PROPERTY_MULTIPLE", "CREATE_OBJECT", "ADD_LIST_ELEMENT", "REMOVE_LIST_ELEMENT",
                        "CONFIRMED_PRIVATE_TRANSFER", "UNCONFIRMED_PRIVATE_TRANSFER", "TIME_SYNCHRONIZATION", "UTC_TIME_SYNCHRONIZATION"}


# OPC UA services that change a server's address space or process values (decoded from the request TypeId; validated on
# Wireshark's real opcua-signed capture: READ / CREATE|ACTIVATE|CLOSE_SESSION only). Reads, browsing, subscriptions and
# session management are ordinary client traffic. Bodies in SignAndEncrypt mode are ciphertext and cannot be inspected.
OPCUA_CRITICAL_SERVICES = {"WRITE", "CALL", "HISTORY_UPDATE", "DELETE_NODES"}
OPCUA_HIGH_SERVICES = {"ADD_NODES", "ADD_REFERENCES", "DELETE_REFERENCES"}


class OTIndustrialAnomalyDetector(Detector):
    name = "ENG-07-OT"

    def _ics_alert(self, flow: dict, protocol: str, severity: str, confidence: float, mitre: tuple, evidence: dict,
                   transport: str = "TCP") -> Alert:
        return Alert(
            alert_id=flow["flow_uid"], timestamp=flow["ts"], severity=severity, confidence_score=confidence,
            threat_class="ICS_UNAUTHORIZED_CONTROL_COMMAND",
            flow_identifier=FlowIdentifier(src_ip=flow["src_ip"], src_port=flow["src_port"],
                                           dst_ip=flow["dst_ip"], dst_port=flow["dst_port"], protocol=transport),
            mitre_attack=MitreAttack(tactic="Impair Process Control", technique_id=mitre[0], technique_name=mitre[1]),
            evidence={"protocol": protocol, **evidence},
            forensics={"raw_segment_hash_sha256": flow.get("segment_hash", "")},
        )

    async def score(self, flow: dict) -> Optional[Alert]:
        proto = flow.get("protocol_analyzed", "")

        if proto == "s7comm":
            fn = str(flow.get("s7_function", "")).upper()
            if fn in S7_CRITICAL_FUNCTIONS or fn in S7_HIGH_FUNCTIONS:
                critical = fn in S7_CRITICAL_FUNCTIONS
                return self._ics_alert(flow, "S7comm", "CRITICAL" if critical else "HIGH", 92.0 if critical else 80.0,
                                       _S7_MITRE.get(fn, ("T0855", "Unauthorized Command Message")),
                                       {"function_code": fn, "impact": "controller program/mode change" if critical else "live value write / program upload"})
            return None

        if proto == "profinet":
            # PROFINET-DCP Set rewrites a device's IP / station name (or factory-resets it) with no authentication --
            # validated on real captures (ChangeIPUsingDCP, profinet-wireshark-bug). Identify/Get/Hello are discovery.
            if flow.get("pn_function") == "DCP_SET":
                blocks = str(flow.get("pn_blocks", ""))
                critical = "FACTORY_RESET" in blocks
                return self._ics_alert(flow, "PROFINET-DCP", "CRITICAL" if critical else "HIGH", 90.0 if critical else 80.0,
                                       ("T0836", "Modify Parameter"),
                                       {"function_code": "DCP_SET", "blocks": blocks, "link_layer": "ethernet (MAC addresses, no IP)"},
                                       transport="UDP")
            return None

        if proto == "opcua":
            svc = str(flow.get("opcua_service", "")).upper()
            if svc in OPCUA_CRITICAL_SERVICES or svc in OPCUA_HIGH_SERVICES:
                critical = svc in OPCUA_CRITICAL_SERVICES
                return self._ics_alert(flow, "OPC UA", "CRITICAL" if critical else "HIGH", 88.0 if critical else 76.0,
                                       ("T0836", "Modify Parameter") if svc == "WRITE" else ("T0855", "Unauthorized Command Message"),
                                       {"function_code": svc})
            return None

        if proto == "bacnet":
            svc = str(flow.get("bacnet_service", "")).upper()
            if svc in BACNET_CRITICAL_SERVICES or svc in BACNET_HIGH_SERVICES:
                critical = svc in BACNET_CRITICAL_SERVICES
                return self._ics_alert(flow, "BACnet", "CRITICAL" if critical else "HIGH", 90.0 if critical else 78.0,
                                       ("T0836", "Modify Parameter") if svc.startswith("WRITE") else ("T0855", "Unauthorized Command Message"),
                                       {"function_code": svc, "kind": flow.get("bacnet_kind", "")})
            return None

        if proto == "iec104":
            tid = int(flow.get("iec104_type_id", 0) or 0)
            if tid in IEC104_CRITICAL_TYPES or tid in IEC104_HIGH_TYPES:
                critical = tid in IEC104_CRITICAL_TYPES
                return self._ics_alert(flow, "IEC 60870-5-104", "CRITICAL" if critical else "HIGH", 92.0 if critical else 78.0,
                                       ("T0855", "Unauthorized Command Message"),
                                       {"function_code": flow.get("iec104_type", ""), "asdu_type_id": tid, "detail": flow.get("iec104_detail", "")})
            return None

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