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


def _epath(path: bytes) -> tuple[int, int]:
    cls = inst = i = 0
    while i < len(path):
        b = path[i]
        if b == 0x20 and i + 1 < len(path):
            cls = path[i + 1]; i += 2
        elif b == 0x21 and i + 3 < len(path):
            cls = int.from_bytes(path[i + 2:i + 4], "little"); i += 4
        elif b == 0x24 and i + 1 < len(path):
            inst = path[i + 1]; i += 2
        elif b == 0x25 and i + 3 < len(path):
            inst = int.from_bytes(path[i + 2:i + 4], "little"); i += 4
        elif b in (0x31, 0x29):
            i += 4
        else:
            i += 2
    return cls, inst


def _cip_message(m: bytes, unwrap: bool):
    if len(m) < 2:
        return None
    svc = m[0]
    if svc & 0x80:
        return svc & 0x7F, 0, 0, True
    words = m[1]
    path = m[2:2 + words * 2]
    if len(path) < words * 2:
        return None
    cls, inst = _epath(path)
    if svc == 0x52 and unwrap and cls == 6:                   # Unconnected Send -> embedded request
        d = m[2 + words * 2:]
        if len(d) >= 4:
            sz = int.from_bytes(d[2:4], "little")
            inner = d[4:4 + sz]
            if len(inner) == sz:
                return _cip_message(inner, False)
    return svc, cls, inst, False


def parse_enip(p: bytes):
    """(service, class, instance, is_response) of the first CIP message in an EtherNet/IP SendRRData/
    SendUnitData segment (TCP/44818). Twin of parse_enip in live.rs."""
    if len(p) < 24 or int.from_bytes(p[:2], "little") not in (0x6F, 0x70):
        return None
    body = p[24:]
    if len(body) < 8:
        return None
    count = int.from_bytes(body[6:8], "little")
    items = body[8:]
    for _ in range(min(count, 8)):
        if len(items) < 4:
            return None
        ty = int.from_bytes(items[0:2], "little")
        ln = int.from_bytes(items[2:4], "little")
        data = items[4:4 + ln]
        if len(data) < ln:
            return None
        if ty in (0x00B2, 0x00B1):
            return _cip_message(data[2:] if ty == 0x00B1 else data, True)
        items = items[4 + ln:]
    return None


_BACNET_CONFIRMED = {
    0: "ACKNOWLEDGE_ALARM", 5: "SUBSCRIBE_COV", 6: "ATOMIC_READ_FILE", 7: "ATOMIC_WRITE_FILE", 8: "ADD_LIST_ELEMENT",
    9: "REMOVE_LIST_ELEMENT", 10: "CREATE_OBJECT", 11: "DELETE_OBJECT", 12: "READ_PROPERTY", 14: "READ_PROPERTY_MULTIPLE",
    15: "WRITE_PROPERTY", 16: "WRITE_PROPERTY_MULTIPLE", 17: "DEVICE_COMMUNICATION_CONTROL",
    18: "CONFIRMED_PRIVATE_TRANSFER", 20: "REINITIALIZE_DEVICE", 26: "READ_RANGE",
}
_BACNET_UNCONFIRMED = {
    0: "I_AM", 1: "I_HAVE", 2: "UNCONFIRMED_COV_NOTIFICATION", 3: "UNCONFIRMED_EVENT_NOTIFICATION",
    4: "UNCONFIRMED_PRIVATE_TRANSFER", 5: "UNCONFIRMED_TEXT_MESSAGE", 6: "TIME_SYNCHRONIZATION", 7: "WHO_HAS",
    8: "WHO_IS", 9: "UTC_TIME_SYNCHRONIZATION",
}


def parse_bacnet(p: bytes) -> Optional[tuple[str, str, int]]:
    """(service, 'confirmed'|'unconfirmed', code) of a BACnet/IP request (UDP/47808). Twin of parse_bacnet in live.rs."""
    if len(p) < 8 or p[0] != 0x81:
        return None
    off = 10 if p[1] == 0x04 else 4                       # Forwarded-NPDU: 6-byte origin address
    if len(p) <= off + 2 or p[off] != 0x01:
        return None
    ctl = p[off + 1]
    off += 2
    if ctl & 0x80:
        return None
    if ctl & 0x20:
        if len(p) <= off + 2:
            return None
        off += 3 + p[off + 2]
    if ctl & 0x08:
        if len(p) <= off + 2:
            return None
        off += 3 + p[off + 2]
    if ctl & 0x20:
        off += 1
    apdu = p[off:]
    if len(apdu) < 2:
        return None
    t = apdu[0] >> 4
    if t == 0:
        idx = 5 if apdu[0] & 0x08 else 3
        if len(apdu) <= idx:
            return None
        name = _BACNET_CONFIRMED.get(apdu[idx])
        return (name, "confirmed", apdu[idx]) if name else None
    if t == 1:
        name = _BACNET_UNCONFIRMED.get(apdu[1])
        return (name, "unconfirmed", 0x100 | apdu[1]) if name else None
    return None


_OPCUA_SERVICES = {
    422: "FIND_SERVERS", 428: "GET_ENDPOINTS", 446: "OPEN_SECURE_CHANNEL", 461: "CREATE_SESSION", 467: "ACTIVATE_SESSION",
    473: "CLOSE_SESSION", 486: "ADD_NODES", 492: "ADD_REFERENCES", 498: "DELETE_NODES", 504: "DELETE_REFERENCES",
    527: "BROWSE", 554: "TRANSLATE_BROWSE_PATHS", 631: "READ", 664: "HISTORY_READ", 673: "WRITE", 700: "HISTORY_UPDATE",
    712: "CALL", 751: "CREATE_MONITORED_ITEMS", 787: "CREATE_SUBSCRIPTION", 826: "PUBLISH",
}


def parse_opcua(p: bytes) -> Optional[tuple[str, str, int]]:
    """(service, 'plain', request TypeId) of a client MSG chunk (TCP/4840) whose body is readable (security mode
    None/Sign). SignAndEncrypt bodies are ciphertext and yield None. Twin of parse_opcua in live.rs."""
    if len(p) < 28 or p[:3] != b"MSG":
        return None
    body = p[24:]
    f = body[0]
    try:
        if f == 0x00:
            tid = body[1]
        elif f == 0x01:
            tid = int.from_bytes(body[2:4], "little") if len(body) >= 4 else None
        elif f == 0x02:
            tid = int.from_bytes(body[3:7], "little") if len(body) >= 7 else None
        else:
            return None
    except IndexError:
        return None
    name = _OPCUA_SERVICES.get(tid) if tid is not None else None
    return (name, "plain", tid) if name else None


def parse_profinet_dcp(frame: bytes) -> Optional[tuple[str, str, int]]:
    """(function, option blocks touched, code) of a PROFINET-DCP REQUEST in a raw Ethernet frame (ethertype 0x8892).
    Twin of parse_profinet_dcp in live.rs."""
    if len(frame) < 26:
        return None
    off = 14
    et = int.from_bytes(frame[12:14], "big")
    while et in (0x8100, 0x88A8) and len(frame) >= off + 4:
        et = int.from_bytes(frame[off + 2:off + 4], "big")
        off += 4
    if et != 0x8892:
        return None
    d = frame[off:]
    if len(d) < 12 or not (0xFEFC <= int.from_bytes(d[:2], "big") <= 0xFEFF):
        return None
    svc, ty = d[2], d[3]
    name = {3: "DCP_GET", 4: "DCP_SET", 5: "DCP_IDENTIFY", 6: "DCP_HELLO"}.get(svc)
    if ty & 1 or name is None:
        return None
    dlen = int.from_bytes(d[10:12], "big")
    blocks, factory, p, end = [], False, 12, min(12 + dlen, len(d))
    while p + 4 <= end:
        opt, sub, bl = d[p], d[p + 1], int.from_bytes(d[p + 2:p + 4], "big")
        if opt == 1:
            blocks.append("IP")
        elif opt == 2:
            blocks.append("DEVICE")
        elif opt == 5:
            blocks.append("CONTROL")
            factory = factory or sub in (5, 6)
        p += 4 + bl + (bl & 1)
    if factory:
        blocks.append("FACTORY_RESET")
    return name, ",".join(blocks), 0x200 | svc


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
