"""
S7comm and IEC 60870-5-104 request decoding -- the pure-Python twin of parse_s7comm / parse_iec104 in
native/stealthtap_core/src/live.rs (same fields, same fail-closed rules). Used when the native module
isn't built and as an independent cross-check of the Rust decoders.

Both are CONTROL-direction only (client -> PLC on TCP/102, master -> outstation on TCP/2404): the
messages that command something. Responses and monitor-direction data are not what ENG-07 looks for.
"""
from __future__ import annotations

from typing import Optional

_S7_FUNCTIONS = {
    0x00: "CPU_SERVICES", 0xF0: "SETUP_COMMUNICATION", 0x04: "READ_VAR", 0x05: "WRITE_VAR",
    0x1A: "REQUEST_DOWNLOAD", 0x1B: "DOWNLOAD_BLOCK", 0x1C: "DOWNLOAD_ENDED",
    0x1D: "START_UPLOAD", 0x1E: "UPLOAD", 0x1F: "END_UPLOAD", 0x28: "PLC_CONTROL", 0x29: "PLC_STOP",
}
_S7_GROUPS = {1: "PROGRAMMER", 2: "CYCLIC_DATA", 3: "BLOCK_FUNCTIONS", 4: "CPU_FUNCTIONS", 5: "SECURITY", 7: "TIME"}

_IEC104_TYPES = {
    45: "C_SC_NA_1", 46: "C_DC_NA_1", 47: "C_RC_NA_1", 48: "C_SE_NA_1", 49: "C_SE_NB_1", 50: "C_SE_NC_1",
    51: "C_BO_NA_1", 58: "C_SC_TA_1", 59: "C_DC_TA_1", 60: "C_RC_TA_1", 61: "C_SE_TA_1", 62: "C_SE_TB_1",
    63: "C_SE_TC_1", 64: "C_BO_TA_1", 100: "C_IC_NA_1", 101: "C_CI_NA_1", 102: "C_RD_NA_1",
    103: "C_CS_NA_1", 104: "C_TS_NA_1", 105: "C_RP_NA_1", 106: "C_CD_NA_1", 107: "C_TS_TA_1",
}


def parse_s7comm(p: bytes) -> Optional[tuple[str, str, int]]:
    """(function, detail, code) of one S7comm Job/Userdata request in a TPKT/COTP-framed segment."""
    if len(p) < 17 or p[0] != 0x03 or p[1] != 0x00:
        return None
    cotp_len = p[4]
    if p[5] != 0xF0:                    # COTP DT only (not connection setup)
        return None
    s7 = p[5 + cotp_len:]
    if len(s7) < 10 or s7[0] != 0x32:
        return None
    rosctr = s7[1]
    if rosctr not in (0x01, 0x07):      # Job / Userdata are requests; acks are not
        return None
    plen = int.from_bytes(s7[6:8], "big")
    param = s7[10:10 + max(plen, 1)]
    if len(param) < max(plen, 1):
        return None
    if rosctr == 0x01:
        name = _S7_FUNCTIONS.get(param[0])
        return (name, "job", param[0]) if name else None
    if len(param) < 8:
        return None
    group, sub = param[5] & 0x0F, param[6]
    return "USERDATA", f"{_S7_GROUPS.get(group, 'OTHER')}/{sub}", 0x100 | (group << 4) | (sub & 0xF)


def parse_iec104(p: bytes) -> Optional[tuple[str, str, int]]:
    """(type name, 'type=.. cot=..', type id) of the most command-like I-frame ASDU in a segment."""
    off = 0
    best: Optional[tuple[int, int]] = None
    while off + 6 <= len(p) and p[off] == 0x68:
        length = p[off + 1]
        if length < 4 or off + 2 + length > len(p):
            break
        if p[off + 2] & 1 == 0 and length >= 4 + 6:          # I-format carrying an ASDU
            asdu = p[off + 6:off + 2 + length]
            tid, cot = asdu[0], asdu[2] & 0x3F
            is_cmd = 45 <= tid <= 64 or tid == 105
            if best is None or is_cmd:
                best = (tid, cot)
            if is_cmd:
                break
        off += 2 + length
    if best is None:
        return None
    tid, cot = best
    name = _IEC104_TYPES.get(tid)
    return (name, f"type={tid} cot={cot}", tid) if name else None
