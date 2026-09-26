//! Streaming (packet-at-a-time) flow assembler -- the live-capture
//! counterpart to parse.rs's whole-file parser, and a byte-for-byte port of
//! src/capture/flow_assembler.py's `FlowAssembler`: same flow orientation,
//! same flow UID, same immediate dns/ssl/modbus/dnp3/http emission, same
//! snapshot/expire/flush lifecycle for `conn`. That Python class is the
//! reference specification (already validated in production on real
//! traffic this session), not something to reinvent -- every field name,
//! every threshold below matches it on purpose.
//!
//! Reuses parse.rs's link-layer/L4/DNS parsing rather than duplicating it.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use indexmap::IndexMap;
use sha2::{Digest, Sha256};

use crate::inventory::{classify, Inventory};
use crate::ja4::ja4_and_sni;
use crate::parse::{flow_uid, parse_dns_query, parse_ip_header, parse_l4, qtype_name,
                   sender_is_originator, strip_link_layer, LINKTYPE_ETHERNET};

/// Default idle timeout -- matches flow_assembler.py's FLOW_IDLE_TIMEOUT_S;
/// the actual value used is always the caller-supplied `idle_timeout_s`
/// (LiveAgent passes its own), this is only the PyO3 constructor default.
pub const DEFAULT_IDLE_TIMEOUT_S: f64 = 60.0;
const FLOW_HARD_TIMEOUT_S: f64 = 300.0;

fn seg_hash(parts: &[String]) -> String {
    let joined = parts.join("|");
    let digest = Sha256::digest(joined.as_bytes());
    format!("sha256:{}", digest.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

pub fn now_unix() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

#[derive(Clone)]
pub struct FlowKey(pub String, pub u16, pub String, pub u16, pub &'static str);
impl std::hash::Hash for FlowKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state); self.1.hash(state); self.2.hash(state); self.3.hash(state); self.4.hash(state);
    }
}
impl PartialEq for FlowKey {
    fn eq(&self, o: &Self) -> bool { self.0 == o.0 && self.1 == o.1 && self.2 == o.2 && self.3 == o.3 && self.4 == o.4 }
}
impl Eq for FlowKey {}

pub struct LiveFlow {
    pub orig_ip: String, pub orig_port: u16,
    pub resp_ip: String, pub resp_port: u16,
    pub proto: &'static str,
    pub first_ts: f64, pub last_ts: f64,
    pub orig_bytes: u64, pub resp_bytes: u64,
    pub orig_pkts: u64, pub resp_pkts: u64,
    pub uid: String,
    pub emitted_ssl: bool,
    pub emitted_http: bool,
}

impl LiveFlow {
    fn add(&mut self, src_ip: &str, src_port: u16, plen: u64, ts: f64) {
        self.last_ts = self.last_ts.max(ts);
        if src_ip == self.orig_ip && src_port == self.orig_port {
            self.orig_bytes += plen; self.orig_pkts += 1;
        } else {
            self.resp_bytes += plen; self.resp_pkts += 1;
        }
    }

    pub fn to_conn(&self) -> LiveConnRecord {
        LiveConnRecord {
            uid: self.uid.clone(), ts: self.first_ts,
            orig_h: self.orig_ip.clone(), orig_p: self.orig_port,
            resp_h: self.resp_ip.clone(), resp_p: self.resp_port,
            proto: self.proto, duration: (self.last_ts - self.first_ts).max(0.0),
            orig_bytes: self.orig_bytes, resp_bytes: self.resp_bytes,
            orig_pkts: self.orig_pkts, resp_pkts: self.resp_pkts,
            segment_hash: seg_hash(&[self.uid.clone(), self.orig_bytes.to_string(), self.resp_bytes.to_string()]),
            snapshot_ts: None,
        }
    }
}

pub struct LiveConnRecord {
    pub uid: String, pub ts: f64,
    pub orig_h: String, pub orig_p: u16,
    pub resp_h: String, pub resp_p: u16,
    pub proto: &'static str, pub duration: f64,
    pub orig_bytes: u64, pub resp_bytes: u64,
    pub orig_pkts: u64, pub resp_pkts: u64,
    pub segment_hash: String,
    pub snapshot_ts: Option<f64>,
}

pub struct DnsOut { pub uid: String, pub ts: f64, pub orig_h: String, pub orig_p: u16,
    pub resp_h: String, pub resp_p: u16, pub proto: &'static str,
    pub query: String, pub qtype_name: String, pub segment_hash: String }
pub struct SslOut { pub uid: String, pub ts: f64, pub orig_h: String, pub orig_p: u16,
    pub resp_h: String, pub resp_p: u16, pub proto: &'static str,
    pub ja4: String, pub sni: String, pub segment_hash: String }
pub struct ModbusOut { pub uid: String, pub ts: f64, pub orig_h: String, pub orig_p: u16,
    pub resp_h: String, pub resp_p: u16, pub func: String, pub register: u16, pub segment_hash: String }
pub struct Dnp3Out { pub uid: String, pub ts: f64, pub orig_h: String, pub orig_p: u16,
    pub resp_h: String, pub resp_p: u16, pub fc_request: String, pub segment_hash: String }
pub struct HttpOut { pub uid: String, pub ts: f64, pub orig_h: String, pub orig_p: u16,
    pub resp_h: String, pub resp_p: u16, pub method: String, pub uri: String,
    pub user_agent: String, pub request_body_len: u64, pub segment_hash: String }

pub struct KerberosOut { pub uid: String, pub ts: f64, pub orig_h: String, pub orig_p: u16,
    pub resp_h: String, pub resp_p: u16, pub proto: &'static str, pub request_type: String,
    pub client: String, pub service: String, pub cipher: String, pub segment_hash: String }

/// Other OT protocols (S7comm, IEC 60870-5-104): `kind` is the log type Python dispatches on.
pub struct OtOut { pub kind: &'static str, pub uid: String, pub ts: f64, pub orig_h: String, pub orig_p: u16,
    pub resp_h: String, pub resp_p: u16, pub function: String, pub detail: String, pub code: u32, pub segment_hash: String,
    pub class_id: u32, pub instance_id: u32, pub response: bool }

pub enum Immediate { Dns(DnsOut), Ssl(SslOut), Modbus(ModbusOut), Dnp3(Dnp3Out), Http(HttpOut), Kerberos(KerberosOut), Ot(OtOut) }

#[derive(Default, Clone)]
pub struct Stats {
    pub packets: u64, pub non_ip: u64, pub flows_seen: u64,
    pub dns: u64, pub ssl: u64, pub modbus: u64, pub dnp3: u64, pub http: u64, pub kerberos: u64, pub s7comm: u64, pub iec104: u64, pub cip: u64, pub bacnet: u64, pub opcua: u64, pub profinet: u64, pub conn: u64,
}

// Function-code name tables -- identical to flow_assembler.py's _MODBUS_FC / _DNP3_FC.
fn modbus_fc_name(fc: u8) -> Option<&'static str> {
    Some(match fc {
        0x01 => "READ_COILS", 0x02 => "READ_DISCRETE_INPUTS", 0x03 => "READ_HOLDING_REGISTERS",
        0x04 => "READ_INPUT_REGISTERS", 0x05 => "WRITE_SINGLE_COIL", 0x06 => "WRITE_SINGLE_REGISTER",
        0x07 => "READ_EXCEPTION_STATUS", 0x08 => "DIAGNOSTICS", 0x0B => "GET_COMM_EVENT_COUNTER",
        0x0F => "WRITE_MULTIPLE_COILS", 0x10 => "WRITE_MULTIPLE_REGISTERS", 0x11 => "REPORT_SLAVE_ID",
        0x16 => "MASK_WRITE_REGISTER", 0x17 => "READ_WRITE_MULTIPLE_REGISTERS",
        _ => return None,
    })
}
fn dnp3_fc_name(fc: u8) -> Option<&'static str> {
    Some(match fc {
        0x00 => "CONFIRM", 0x01 => "READ", 0x02 => "WRITE", 0x03 => "SELECT", 0x04 => "OPERATE",
        0x05 => "DIRECT_OPERATE", 0x06 => "DIRECT_OPERATE_NR", 0x07 => "IMMED_FREEZE",
        0x0D => "COLD_RESTART", 0x0E => "WARM_RESTART", 0x0F => "INITIALIZE_DATA",
        0x10 => "INITIALIZE_APPLICATION", 0x11 => "START_APPLICATION", 0x12 => "STOP_APPLICATION",
        0x13 => "SAVE_CONFIGURATION", 0x14 => "ENABLE_UNSOLICITED", 0x15 => "DISABLE_UNSOLICITED",
        0x18 => "ASSIGN_CLASS", 0x1B => "DELETE_FILE",
        _ => return None,
    })
}

fn parse_modbus(p: &[u8], s_ip: &str, s_p: u16, d_ip: &str, d_p: u16, ts: f64, uid: &str) -> Option<ModbusOut> {
    if p.len() < 8 || p[2] != 0x00 || p[3] != 0x00 { return None; }
    let fc = p[7];
    let name = modbus_fc_name(fc)?;
    let register = if matches!(fc, 0x05 | 0x06 | 0x0F | 0x10) && p.len() >= 10 {
        u16::from_be_bytes([p[8], p[9]])
    } else { 0 };
    Some(ModbusOut {
        uid: uid.to_string(), ts, orig_h: s_ip.to_string(), orig_p: s_p, resp_h: d_ip.to_string(), resp_p: d_p,
        func: name.to_string(), register,
        segment_hash: seg_hash(&[uid.to_string(), name.to_string(), register.to_string()]),
    })
}

fn s7_function_name(code: u8) -> Option<&'static str> {
    Some(match code {
        0x00 => "CPU_SERVICES", 0xF0 => "SETUP_COMMUNICATION", 0x04 => "READ_VAR", 0x05 => "WRITE_VAR",
        0x1A => "REQUEST_DOWNLOAD", 0x1B => "DOWNLOAD_BLOCK", 0x1C => "DOWNLOAD_ENDED",
        0x1D => "START_UPLOAD", 0x1E => "UPLOAD", 0x1F => "END_UPLOAD",
        0x28 => "PLC_CONTROL", 0x29 => "PLC_STOP",
        _ => return None,
    })
}

/// S7comm request (client -> PLC, TCP/102): TPKT | COTP DT | S7 header | parameter (function code first).
/// Same shape as Zeek's ICSNPP s7comm `function`. Returns (function, detail, code).
fn parse_s7comm(p: &[u8]) -> Option<(String, String, u32)> {
    if p.len() < 17 || p[0] != 0x03 || p[1] != 0x00 { return None; }
    let cotp_len = p[4] as usize;
    if p[5] != 0xF0 { return None; }               // COTP DT (data) only, not connection setup
    let s7 = p.get(5 + cotp_len..)?;
    if s7.len() < 10 || s7[0] != 0x32 { return None; }
    let rosctr = s7[1];
    if rosctr != 0x01 && rosctr != 0x07 { return None; }    // Job / Userdata are requests; acks are not
    let plen = u16::from_be_bytes([s7[6], s7[7]]) as usize;
    let param = s7.get(10..10 + plen.max(1))?;
    if rosctr == 0x01 {
        let code = param[0];
        let name = s7_function_name(code)?;
        Some((name.to_string(), "job".to_string(), code as u32))
    } else {
        // userdata: 00 01 12 plen method | type/group | subfunction | seq
        if param.len() < 8 { return None; }
        let group = param[5] & 0x0f;
        let sub = param[6];
        let gname = match group { 1 => "PROGRAMMER", 2 => "CYCLIC_DATA", 3 => "BLOCK_FUNCTIONS", 4 => "CPU_FUNCTIONS", 5 => "SECURITY", 7 => "TIME", _ => "OTHER" };
        Some(("USERDATA".to_string(), format!("{gname}/{sub}"), 0x100 | (group as u32) << 4 | sub as u32 & 0xf))
    }
}

/// IEC 60870-5-104 I-frames in the CONTROL direction (client -> outstation, TCP/2404): the ASDU type id
/// says what is being commanded (45.. single/double command, 48-50 setpoints, 105 reset process ...).
fn parse_iec104(p: &[u8]) -> Option<(String, String, u32)> {
    let mut off = 0usize;
    let mut best: Option<(u8, u8)> = None;   // most severe (type_id, cot) among the APDUs in this segment
    while off + 6 <= p.len() && p[off] == 0x68 {
        let len = p[off + 1] as usize;
        if len < 4 || off + 2 + len > p.len() { break; }
        let ctrl1 = p[off + 2];
        if ctrl1 & 1 == 0 && len >= 4 + 6 {                    // I-format with an ASDU
            let asdu = &p[off + 6..off + 2 + len];
            let (tid, cot) = (asdu[0], asdu[2] & 0x3f);
            let is_cmd = (45..=64).contains(&tid) || tid == 105;
            if best.is_none() || is_cmd { best = Some((tid, cot)); }
            if is_cmd { break; }
        }
        off += 2 + len;
    }
    let (tid, cot) = best?;
    let name = match tid {
        45 => "C_SC_NA_1", 46 => "C_DC_NA_1", 47 => "C_RC_NA_1", 48 => "C_SE_NA_1", 49 => "C_SE_NB_1", 50 => "C_SE_NC_1",
        51 => "C_BO_NA_1", 58 => "C_SC_TA_1", 59 => "C_DC_TA_1", 60 => "C_RC_TA_1", 61 => "C_SE_TA_1", 62 => "C_SE_TB_1",
        63 => "C_SE_TC_1", 64 => "C_BO_TA_1", 100 => "C_IC_NA_1", 101 => "C_CI_NA_1", 102 => "C_RD_NA_1",
        103 => "C_CS_NA_1", 104 => "C_TS_NA_1", 105 => "C_RP_NA_1", 106 => "C_CD_NA_1", 107 => "C_TS_TA_1",
        _ => return None,
    };
    Some((name.to_string(), format!("type={tid} cot={cot}"), tid as u32))
}

/// EtherNet/IP encapsulation (TCP/44818) carrying a CIP request: SendRRData (0x6F) / SendUnitData (0x70) ->
/// common-packet-format items -> CIP message [service | path words | EPATH(class 0x20/0x21, instance 0x24/0x25)].
/// An Unconnected Send (service 0x52 to the Connection Manager) is unwrapped once to the embedded request.
/// Returns (service, class, instance, is_response).
fn parse_enip(p: &[u8]) -> Option<(u8, u32, u32, bool)> {
    if p.len() < 24 { return None; }
    let cmd = u16::from_le_bytes([p[0], p[1]]);
    if cmd != 0x6F && cmd != 0x70 { return None; }
    let body = p.get(24..)?;
    if body.len() < 8 { return None; }
    let count = u16::from_le_bytes([body[6], body[7]]) as usize;
    let mut items = &body[8..];
    for _ in 0..count.min(8) {
        if items.len() < 4 { return None; }
        let ty = u16::from_le_bytes([items[0], items[1]]);
        let len = u16::from_le_bytes([items[2], items[3]]) as usize;
        let data = items.get(4..4 + len)?;
        if ty == 0x00B2 || ty == 0x00B1 {
            let cip = if ty == 0x00B1 { data.get(2..)? } else { data };   // connected data starts with a 2-byte sequence
            return parse_cip_message(cip, true);
        }
        items = &items[4 + len..];
    }
    None
}

fn epath(path: &[u8]) -> (u32, u32) {
    let (mut class, mut inst) = (0u32, 0u32);
    let mut i = 0usize;
    while i < path.len() {
        match path[i] {
            0x20 => { if i + 1 < path.len() { class = path[i + 1] as u32; } i += 2; }
            0x21 => { if i + 3 < path.len() { class = u16::from_le_bytes([path[i + 2], path[i + 3]]) as u32; } i += 4; }
            0x24 => { if i + 1 < path.len() { inst = path[i + 1] as u32; } i += 2; }
            0x25 => { if i + 3 < path.len() { inst = u16::from_le_bytes([path[i + 2], path[i + 3]]) as u32; } i += 4; }
            0x30 | 0x28 => { i += 2; }
            0x31 | 0x29 => { i += 4; }
            _ => { i += 2; }
        }
    }
    (class, inst)
}

fn parse_cip_message(m: &[u8], unwrap: bool) -> Option<(u8, u32, u32, bool)> {
    if m.len() < 2 { return None; }
    let svc = m[0];
    if svc & 0x80 != 0 { return Some((svc & 0x7f, 0, 0, true)); }   // response: service echoed with the high bit set
    let words = m[1] as usize;
    let path = m.get(2..2 + words * 2)?;
    let (class, inst) = epath(path);
    if svc == 0x52 && unwrap && class == 6 {           // Unconnected Send -> embedded message request
        let d = m.get(2 + words * 2..)?;
        if d.len() >= 4 {
            let sz = u16::from_le_bytes([d[2], d[3]]) as usize;
            if let Some(inner) = d.get(4..4 + sz) { return parse_cip_message(inner, false); }
        }
    }
    Some((svc, class, inst, false))
}

/// BACnet/IP (UDP/47808): BVLC | NPDU | APDU. Returns (service name, detail, service code) for confirmed and
/// unconfirmed REQUESTS (Who-Is/ReadProperty polling is decoded too; ENG-07 only alerts on state-changing ones).
fn parse_bacnet(p: &[u8]) -> Option<(String, String, u32)> {
    if p.len() < 8 || p[0] != 0x81 { return None; }
    let mut off = match p[1] { 0x04 => 10usize, _ => 4usize };          // Forwarded-NPDU carries a 6-byte origin address
    if p.len() <= off + 2 || p[off] != 0x01 { return None; }
    let ctl = p[off + 1];
    off += 2;
    if ctl & 0x80 != 0 { return None; }                                  // network-layer message, no APDU
    if ctl & 0x20 != 0 { let dlen = *p.get(off + 2)? as usize; off += 3 + dlen; }   // DNET, DLEN, DADR
    if ctl & 0x08 != 0 { let slen = *p.get(off + 2)? as usize; off += 3 + slen; }   // SNET, SLEN, SADR
    if ctl & 0x20 != 0 { off += 1; }                                     // hop count
    let apdu = p.get(off..)?;
    if apdu.len() < 2 { return None; }
    match apdu[0] >> 4 {
        0 => {   // Confirmed-Request: type/flags | max-segs/resp | invoke id | [seq, window if segmented] | service
            let idx = if apdu[0] & 0x08 != 0 { 5 } else { 3 };
            let svc = *apdu.get(idx)?;
            let name = match svc {
                0 => "ACKNOWLEDGE_ALARM", 5 => "SUBSCRIBE_COV", 6 => "ATOMIC_READ_FILE", 7 => "ATOMIC_WRITE_FILE",
                8 => "ADD_LIST_ELEMENT", 9 => "REMOVE_LIST_ELEMENT", 10 => "CREATE_OBJECT", 11 => "DELETE_OBJECT",
                12 => "READ_PROPERTY", 14 => "READ_PROPERTY_MULTIPLE", 15 => "WRITE_PROPERTY", 16 => "WRITE_PROPERTY_MULTIPLE",
                17 => "DEVICE_COMMUNICATION_CONTROL", 18 => "CONFIRMED_PRIVATE_TRANSFER", 20 => "REINITIALIZE_DEVICE",
                26 => "READ_RANGE", _ => return None,
            };
            Some((name.to_string(), "confirmed".to_string(), svc as u32))
        }
        1 => {   // Unconfirmed-Request: type | service
            let svc = apdu[1];
            let name = match svc {
                0 => "I_AM", 1 => "I_HAVE", 2 => "UNCONFIRMED_COV_NOTIFICATION", 3 => "UNCONFIRMED_EVENT_NOTIFICATION",
                4 => "UNCONFIRMED_PRIVATE_TRANSFER", 5 => "UNCONFIRMED_TEXT_MESSAGE", 6 => "TIME_SYNCHRONIZATION",
                7 => "WHO_HAS", 8 => "WHO_IS", 9 => "UTC_TIME_SYNCHRONIZATION", _ => return None,
            };
            Some((name.to_string(), "unconfirmed".to_string(), 0x100 | svc as u32))
        }
        _ => None,
    }
}

/// OPC UA binary (TCP/4840), client -> server MSG chunk: `MSG` `F` size(4) | channel(4) token(4) | seq(4) req(4) | body,
/// where the body starts with the request's TypeId NodeId. In security mode None/Sign the body is readable and the
/// TypeId names the service; in SignAndEncrypt it is ciphertext and is (honestly) not inspected.
fn parse_opcua(p: &[u8]) -> Option<(String, String, u32)> {
    if p.len() < 28 || &p[0..3] != b"MSG" { return None; }
    let body = &p[24..];
    let id: u32 = match body[0] {
        0x00 => body[1] as u32,
        0x01 => u16::from_le_bytes([*body.get(2)?, *body.get(3)?]) as u32,
        0x02 => u32::from_le_bytes([*body.get(3)?, *body.get(4)?, *body.get(5)?, *body.get(6)?]),
        _ => return None,
    };
    let name = match id {
        422 => "FIND_SERVERS", 428 => "GET_ENDPOINTS", 446 => "OPEN_SECURE_CHANNEL", 461 => "CREATE_SESSION", 467 => "ACTIVATE_SESSION",
        473 => "CLOSE_SESSION", 486 => "ADD_NODES", 492 => "ADD_REFERENCES", 498 => "DELETE_NODES", 504 => "DELETE_REFERENCES",
        527 => "BROWSE", 554 => "TRANSLATE_BROWSE_PATHS", 631 => "READ", 664 => "HISTORY_READ", 673 => "WRITE", 700 => "HISTORY_UPDATE",
        712 => "CALL", 751 => "CREATE_MONITORED_ITEMS", 787 => "CREATE_SUBSCRIPTION", 826 => "PUBLISH", _ => return None,
    };
    Some((name.to_string(), "plain".to_string(), id))
}

/// PROFINET-DCP over raw Ethernet (ethertype 0x8892, no IP): FrameID 0xFEFC..0xFEFF | ServiceID | ServiceType | Xid |
/// delay | data length | option blocks. Only REQUESTS are decoded. Returns (function, detail, code); `detail` lists the
/// option blocks a Set touches (IP, DEVICE, CONTROL[+FACTORY_RESET]) -- the same block layout as the DCP spec.
fn parse_profinet_dcp(frame: &[u8]) -> Option<(String, String, u32)> {
    if frame.len() < 26 { return None; }
    let mut off = 12usize;
    let mut et = u16::from_be_bytes([frame[off], frame[off + 1]]);
    off += 2;
    while (et == 0x8100 || et == 0x88a8) && frame.len() >= off + 4 { et = u16::from_be_bytes([frame[off + 2], frame[off + 3]]); off += 4; }
    if et != 0x8892 { return None; }
    let d = frame.get(off..)?;
    if d.len() < 12 { return None; }
    let frame_id = u16::from_be_bytes([d[0], d[1]]);
    if !(0xFEFC..=0xFEFF).contains(&frame_id) { return None; }
    let (svc, ty) = (d[2], d[3]);
    if ty & 1 != 0 { return None; }                 // responses are not commands
    let name = match svc { 3 => "DCP_GET", 4 => "DCP_SET", 5 => "DCP_IDENTIFY", 6 => "DCP_HELLO", _ => return None };
    let dlen = u16::from_be_bytes([d[10], d[11]]) as usize;
    let mut blocks: Vec<&str> = Vec::new();
    let mut factory = false;
    let mut p = 12usize;
    let end = (12 + dlen).min(d.len());
    while p + 4 <= end {
        let (opt, sub) = (d[p], d[p + 1]);
        let bl = u16::from_be_bytes([d[p + 2], d[p + 3]]) as usize;
        match opt { 1 => blocks.push("IP"), 2 => blocks.push("DEVICE"), 5 => { blocks.push("CONTROL"); if sub == 5 || sub == 6 { factory = true; } } _ => {} }
        p += 4 + bl + (bl & 1);                      // blocks are padded to even length
    }
    if factory { blocks.push("FACTORY_RESET"); }
    Some((name.to_string(), blocks.join(","), 0x200 | svc as u32))
}

fn parse_dnp3(p: &[u8], s_ip: &str, s_p: u16, d_ip: &str, d_p: u16, ts: f64, uid: &str) -> Option<Dnp3Out> {
    if p.len() < 13 || p[0] != 0x05 || p[1] != 0x64 { return None; }
    let fc = p[12];
    let name = dnp3_fc_name(fc)?;
    Some(Dnp3Out {
        uid: uid.to_string(), ts, orig_h: s_ip.to_string(), orig_p: s_p, resp_h: d_ip.to_string(), resp_p: d_p,
        fc_request: name.to_string(),
        segment_hash: seg_hash(&[uid.to_string(), name.to_string()]),
    })
}

// Matches Zeek's base HTTP analyzer's own scope: HTTP/1.x request line +
// headers. HTTP/2 is a binary framing format Zeek's base analyzer doesn't
// parse either, so staying HTTP/1.x-only keeps this at parity, not behind
// it. Structural detection (valid method + " " + target + " HTTP/1.x"),
// not a port allowlist -- ENG-09's whole point is catching C2 that hides
// on non-standard ports, so gating on port 80/8080 would defeat it.
const HTTP_METHODS: [&str; 9] = ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE"];

fn split_line(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    for i in 0..buf.len() {
        if buf[i] == b'\n' {
            let end = if i > 0 && buf[i - 1] == b'\r' { i - 1 } else { i };
            return Some((&buf[..end], &buf[i + 1..]));
        }
    }
    None
}

fn parse_http_request(payload: &[u8]) -> Option<(String, String, String, u64)> {
    let (line1, mut rest) = split_line(payload)?;
    let line1 = std::str::from_utf8(line1).ok()?;
    let mut parts = line1.splitn(3, ' ');
    let method = parts.next()?;
    let uri = parts.next()?;
    let version = parts.next()?;
    if !HTTP_METHODS.contains(&method) || !version.starts_with("HTTP/1.") { return None; }

    let mut user_agent = String::new();
    let mut request_body_len: u64 = 0;
    while let Some((line, next)) = split_line(rest) {
        if line.is_empty() { break; } // end of headers
        rest = next;
        let Ok(line) = std::str::from_utf8(line) else { continue };
        let Some((name, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "user-agent" => user_agent = value.to_string(),
            "content-length" => request_body_len = value.parse().unwrap_or(0),
            _ => {}
        }
    }
    Some((method.to_string(), uri.to_string(), user_agent, request_body_len))
}

pub struct LiveFlowAssembler {
    flows: IndexMap<FlowKey, LiveFlow>,   // IndexMap: see parse.rs's Cargo.toml comment -- same reasoning applies here
    dirty: HashSet<FlowKey>,              // matches Python's plain `set` -- no order guarantee there either
    idle_timeout_s: f64,
    pub stats: Stats,
    pub inv: Inventory,                   // passive host/protocol inventory (see inventory.rs)
}

impl LiveFlowAssembler {
    pub fn new(idle_timeout_s: f64) -> Self {
        Self { flows: IndexMap::new(), dirty: HashSet::new(), idle_timeout_s, stats: Stats::default(), inv: Inventory::new() }
    }

    /// One packet's raw bytes (as scapy's `bytes(pkt)` produces -- INCLUDING
    /// the Ethernet header) plus its timestamp. Returns immediately-emitted
    /// records only; `conn` comes from snapshot()/expire()/flush().
    pub fn process(&mut self, ts: f64, data: &[u8]) -> Vec<Immediate> {
        self.stats.packets += 1;
        let mut out = Vec::new();

        let Some(l3) = strip_link_layer(LINKTYPE_ETHERNET, data) else {
            self.stats.non_ip += 1;
            if let Some((function, detail, code)) = parse_profinet_dcp(data) {
                // layer-2 protocol: the "endpoints" are MAC addresses
                let mac = |b: &[u8]| format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2], b[3], b[4], b[5]);
                let (dst, src) = (mac(&data[0..6]), mac(&data[6..12]));
                let uid = flow_uid(&src, 0, &dst, 0, "eth");
                self.stats.profinet += 1;
                out.push(Immediate::Ot(OtOut { kind: "profinet", uid: uid.clone(), ts, orig_h: src, orig_p: 0, resp_h: dst, resp_p: 0,
                    segment_hash: seg_hash(&[uid.clone(), function.clone(), detail.clone()]),
                    function, detail, code, class_id: 0, instance_id: 0, response: false }));
            }
            return out;
        };
        let Some((src_ip, dst_ip, proto_num, l4_payload)) = parse_ip_header(l3) else {
            self.stats.non_ip += 1;
            return out;
        };

        let src_mac = if data.len() >= 12 && data[6..12] != [0u8; 6] {
            let mut m = [0u8; 6]; m.copy_from_slice(&data[6..12]); Some(m)
        } else { None };
        let wire = data.len() as u64;
        let Some(l4) = parse_l4(proto_num, l4_payload) else {
            self.inv.observe_ip(&src_ip, &dst_ip, wire, ts, 2, src_mac);
            self.inv.observe_proto(if proto_num == 1 || proto_num == 58 { 24 } else if proto_num == 50 || proto_num == 51 { 30 } else { 29 }, wire);
            return out;
        };
        self.inv.observe_ip(&src_ip, &dst_ip, wire, ts, if l4.proto == "tcp" { 0 } else { 1 }, src_mac);
        self.inv.observe_proto(classify(l4.proto == "tcp", l4.sport, l4.dport), wire);

        // Unconditional: every TCP/UDP packet updates its flow's byte/packet
        // counters FIRST, exactly like flow_assembler.py's process() (which
        // calls flow.add() before any of the protocol-specific checks below
        // -- none of them are mutually exclusive with conn accounting there,
        // unlike the upload-path parser's DNS `continue`).
        let flow_key = canonical_key(&src_ip, l4.sport, &dst_ip, l4.dport, l4.proto);
        let uid = self.ensure_flow(&flow_key, &src_ip, l4.sport, &dst_ip, l4.dport, l4.proto, l4.tcp_flags, ts, l4.payload.len() as u64);

        // DNS query -- UDP port 53/5353 (unicast/mDNS), or TCP port 53
        // (DNS-over-TCP, RFC 1035 4.2.2 -- e.g. CHAOS-class
        // version.bind/id.server fingerprinting queries; real traffic in
        // this project's own eval set, found via
        // scripts/validate_native_live_assembler.py). Immediate emission.
        let dns_hit = if l4.proto == "udp" && ([53, 5353].contains(&l4.sport) || [53, 5353].contains(&l4.dport)) {
            parse_dns_query(l4.payload).map(|r| (r, "udp"))
        } else if l4.proto == "tcp" && (l4.sport == 53 || l4.dport == 53) {
            crate::parse::parse_dns_query_tcp(l4.payload).map(|r| (r, "tcp"))
        } else {
            None
        };
        if let Some(((qname, qtype), dns_proto)) = dns_hit {
            self.stats.dns += 1;
            out.push(Immediate::Dns(DnsOut {
                uid: uid.clone(), ts, orig_h: src_ip.clone(), orig_p: l4.sport,
                resp_h: dst_ip.clone(), resp_p: l4.dport, proto: dns_proto,
                query: qname.trim_end_matches('.').to_string(), qtype_name: qtype_name(qtype),
                segment_hash: seg_hash(&[uid.clone(), qname, qtype.to_string()]),
            }));
        }

        // TLS ClientHello -> JA4 (immediate, once per flow)
        if l4.proto == "tcp" && l4.payload.first() == Some(&0x16) {
            let already = self.flows.get(&flow_key).map(|f| f.emitted_ssl).unwrap_or(true);
            if !already {
                if let Some((ja4, sni)) = ja4_and_sni(l4.payload) {
                    if let Some(f) = self.flows.get_mut(&flow_key) { f.emitted_ssl = true; }
                    self.stats.ssl += 1;
                    out.push(Immediate::Ssl(SslOut {
                        uid: uid.clone(), ts, orig_h: src_ip.clone(), orig_p: l4.sport,
                        resp_h: dst_ip.clone(), resp_p: l4.dport, proto: "tcp",
                        segment_hash: seg_hash(&[uid.clone(), ja4.clone()]), ja4, sni,
                    }));
                }
            }
        }

        // HTTP/1.x request (immediate, once per flow) -- client side only.
        // Matches flow_assembler.py: parse the request line + a bounded
        // set of headers (User-Agent, Content-Length) that ENG-09 reads.
        if l4.proto == "tcp" && !l4.payload.is_empty() {
            let is_orig = self.flows.get(&flow_key)
                .map(|f| f.orig_ip == src_ip && f.orig_port == l4.sport)
                .unwrap_or(false);
            let already = self.flows.get(&flow_key).map(|f| f.emitted_http).unwrap_or(true);
            if is_orig && !already {
                if let Some((method, uri, user_agent, body_len)) = parse_http_request(l4.payload) {
                    if let Some(f) = self.flows.get_mut(&flow_key) { f.emitted_http = true; }
                    self.stats.http += 1;
                    out.push(Immediate::Http(HttpOut {
                        uid: uid.clone(), ts, orig_h: src_ip.clone(), orig_p: l4.sport,
                        resp_h: dst_ip.clone(), resp_p: l4.dport,
                        segment_hash: seg_hash(&[uid.clone(), method.clone(), uri.clone()]),
                        method, uri, user_agent, request_body_len: body_len,
                    }));
                }
            }
        }

        // Kerberos KDC reply (AS-REP / TGS-REP): who asked for a ticket, for which service, sealed
        // with which cipher -- the inputs ENG-11 (Kerberoasting) needs. Replies come FROM port 88.
        if l4.sport == 88 && !l4.payload.is_empty() {
            if let Some(k) = crate::krb::parse_kdc_reply(l4.payload, l4.proto == "tcp") {
                self.stats.kerberos += 1;
                // orient like Zeek: originator = the client (this packet's destination)
                out.push(Immediate::Kerberos(KerberosOut {
                    uid: uid.clone(), ts, orig_h: dst_ip.clone(), orig_p: l4.dport,
                    resp_h: src_ip.clone(), resp_p: l4.sport, proto: if l4.proto == "tcp" { "tcp" } else { "udp" },
                    segment_hash: seg_hash(&[uid.clone(), k.client.clone(), k.service.clone(), k.cipher.clone()]),
                    request_type: k.request_type.to_string(), client: k.client, service: k.service, cipher: k.cipher,
                }));
            }
        }

        // BACnet/IP (UDP): peers use 47808 on both sides, so either port qualifies
        if l4.proto == "udp" && (l4.dport == 47808 || l4.sport == 47808) && !l4.payload.is_empty() {
            if let Some((function, detail, code)) = parse_bacnet(l4.payload) {
                self.stats.bacnet += 1;
                out.push(Immediate::Ot(OtOut { kind: "bacnet", uid: uid.clone(), ts, orig_h: src_ip.clone(), orig_p: l4.sport,
                    resp_h: dst_ip.clone(), resp_p: l4.dport, segment_hash: seg_hash(&[uid.clone(), function.clone(), detail.clone()]),
                    function, detail, code, class_id: 0, instance_id: 0, response: false }));
            }
        }

        // Modbus / DNP3 (immediate)
        if l4.proto == "tcp" && !l4.payload.is_empty() {
            if l4.sport == 502 || l4.dport == 502 {
                if let Some(m) = parse_modbus(l4.payload, &src_ip, l4.sport, &dst_ip, l4.dport, ts, &uid) {
                    self.stats.modbus += 1;
                    out.push(Immediate::Modbus(m));
                }
            } else if l4.sport == 20000 || l4.dport == 20000 {
                if let Some(d) = parse_dnp3(l4.payload, &src_ip, l4.sport, &dst_ip, l4.dport, ts, &uid) {
                    self.stats.dnp3 += 1;
                    out.push(Immediate::Dnp3(d));
                }
            } else if l4.dport == 102 {
                if let Some((function, detail, code)) = parse_s7comm(l4.payload) {
                    self.stats.s7comm += 1;
                    out.push(Immediate::Ot(OtOut { kind: "s7comm", uid: uid.clone(), ts, orig_h: src_ip.clone(), orig_p: l4.sport,
                        resp_h: dst_ip.clone(), resp_p: l4.dport, segment_hash: seg_hash(&[uid.clone(), function.clone(), detail.clone()]),
                        function, detail, code, class_id: 0, instance_id: 0, response: false }));
                }
            } else if l4.dport == 44818 {
                if let Some((svc, class, inst, resp)) = parse_enip(l4.payload) {
                    if !resp {
                        self.stats.cip += 1;
                        let function = format!("0x{svc:02X}");
                        let detail = format!("class={class} instance={inst}");
                        out.push(Immediate::Ot(OtOut { kind: "cip", uid: uid.clone(), ts, orig_h: src_ip.clone(), orig_p: l4.sport,
                            resp_h: dst_ip.clone(), resp_p: l4.dport, segment_hash: seg_hash(&[uid.clone(), function.clone(), detail.clone()]),
                            function, detail, code: svc as u32, class_id: class, instance_id: inst, response: false }));
                    }
                }
            } else if l4.dport == 4840 {
                if let Some((function, detail, code)) = parse_opcua(l4.payload) {
                    self.stats.opcua += 1;
                    out.push(Immediate::Ot(OtOut { kind: "opcua", uid: uid.clone(), ts, orig_h: src_ip.clone(), orig_p: l4.sport,
                        resp_h: dst_ip.clone(), resp_p: l4.dport, segment_hash: seg_hash(&[uid.clone(), function.clone(), detail.clone()]),
                        function, detail, code, class_id: 0, instance_id: 0, response: false }));
                }
            } else if l4.dport == 2404 {
                if let Some((function, detail, code)) = parse_iec104(l4.payload) {
                    self.stats.iec104 += 1;
                    out.push(Immediate::Ot(OtOut { kind: "iec104", uid: uid.clone(), ts, orig_h: src_ip.clone(), orig_p: l4.sport,
                        resp_h: dst_ip.clone(), resp_p: l4.dport, segment_hash: seg_hash(&[uid.clone(), function.clone(), detail.clone()]),
                        function, detail, code, class_id: 0, instance_id: 0, response: false }));
                }
            }
        }

        out
    }

    fn ensure_flow(&mut self, key: &FlowKey, src_ip: &str, sport: u16, dst_ip: &str, dport: u16,
                   proto: &'static str, tcp_flags: Option<u8>, ts: f64, plen: u64) -> String {
        if !self.flows.contains_key(key) {
            let (orig_ip, orig_port, resp_ip, resp_port) =
                if sender_is_originator(proto, sport, dport, tcp_flags) {
                    (src_ip.to_string(), sport, dst_ip.to_string(), dport)
                } else {
                    (dst_ip.to_string(), dport, src_ip.to_string(), sport)
                };
            let uid = flow_uid(&orig_ip, orig_port, &resp_ip, resp_port, proto);
            self.flows.insert(key.clone(), LiveFlow {
                orig_ip, orig_port, resp_ip, resp_port, proto,
                first_ts: ts, last_ts: ts, orig_bytes: 0, resp_bytes: 0,
                orig_pkts: 0, resp_pkts: 0, uid, emitted_ssl: false, emitted_http: false,
            });
            self.stats.flows_seen += 1;
        }
        let flow = self.flows.get_mut(key).unwrap();
        flow.add(src_ip, sport, plen, ts);
        self.dirty.insert(key.clone());
        flow.uid.clone()
    }

    /// A `conn` record for every flow with new packets since the last call
    /// -- non-destructive, called on a short cadence so rate/fan-out
    /// engines see flows evolve near-real-time. Matches
    /// FlowAssembler.snapshot() exactly, including the `limit` bound.
    pub fn snapshot(&mut self, limit: usize) -> Vec<LiveConnRecord> {
        let dirty = std::mem::take(&mut self.dirty);
        let mut out = Vec::new();
        for key in dirty.into_iter().take(limit) {
            if let Some(f) = self.flows.get(&key) {
                let mut rec = f.to_conn();
                rec.snapshot_ts = Some(f.last_ts);
                out.push(rec);
            }
        }
        out
    }

    /// Evicts and returns every flow idle for >= idle_timeout_s, or whose
    /// total lifetime exceeds FLOW_HARD_TIMEOUT_S -- matches
    /// FlowAssembler.expire() exactly.
    pub fn expire(&mut self, now: f64) -> Vec<LiveConnRecord> {
        // ONE order-preserving pass (IndexMap::retain), not a shift_remove per
        // evicted flow. shift_remove keeps insertion order but is O(n) PER
        // REMOVAL (it shifts every later entry down), so evicting k flows
        // cost O(k*n) -- profiled as the single largest cost in the whole
        // live pipeline (46% of a 48k-packet run, in code that was already
        // Rust): the scan was never the problem, the per-key removal was.
        // retain() visits entries in insertion order and drops the expired
        // ones in the same pass, so the returned records keep EXACTLY the
        // order the old code produced -- which the order-sensitive engines
        // downstream (ENG-01's first-crossing dedup, ENG-02/06 windows)
        // depend on.
        let idle = self.idle_timeout_s;
        let mut out = Vec::new();
        self.flows.retain(|_, f| {
            if (now - f.last_ts) >= idle || (now - f.first_ts) >= FLOW_HARD_TIMEOUT_S {
                out.push(f.to_conn());
                false
            } else {
                true
            }
        });
        self.stats.conn += out.len() as u64;
        out
    }

    pub fn flush(&mut self) -> Vec<LiveConnRecord> {
        let out: Vec<LiveConnRecord> = self.flows.values().map(|f| f.to_conn()).collect();
        self.stats.conn += out.len() as u64;
        self.flows.clear();
        self.dirty.clear();
        out
    }

    pub fn active_flows(&self) -> usize { self.flows.len() }

    /// The `n` heaviest active flows by total bytes (live "conversations" view).
    pub fn top_flows(&self, n: usize) -> Vec<LiveConnRecord> {
        let mut v: Vec<&LiveFlow> = self.flows.values().collect();
        v.sort_by(|a, b| (b.orig_bytes + b.resp_bytes).cmp(&(a.orig_bytes + a.resp_bytes)));
        v.into_iter().take(n).map(|f| f.to_conn()).collect()
    }
}

fn canonical_key(src_ip: &str, sport: u16, dst_ip: &str, dport: u16, proto: &'static str) -> FlowKey {
    if (src_ip, sport) <= (dst_ip, dport) {
        FlowKey(src_ip.to_string(), sport, dst_ip.to_string(), dport, proto)
    } else {
        FlowKey(dst_ip.to_string(), dport, src_ip.to_string(), sport, proto)
    }
}
