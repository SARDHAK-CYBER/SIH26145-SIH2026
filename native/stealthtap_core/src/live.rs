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

use crate::ja4::ja4_from_client_hello;
use crate::parse::{flow_uid, ipv4_to_string, parse_dns_query, parse_l4, qtype_name,
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
    pub ja4: String, pub segment_hash: String }
pub struct ModbusOut { pub uid: String, pub ts: f64, pub orig_h: String, pub orig_p: u16,
    pub resp_h: String, pub resp_p: u16, pub func: String, pub register: u16, pub segment_hash: String }
pub struct Dnp3Out { pub uid: String, pub ts: f64, pub orig_h: String, pub orig_p: u16,
    pub resp_h: String, pub resp_p: u16, pub fc_request: String, pub segment_hash: String }
pub struct HttpOut { pub uid: String, pub ts: f64, pub orig_h: String, pub orig_p: u16,
    pub resp_h: String, pub resp_p: u16, pub method: String, pub uri: String,
    pub user_agent: String, pub request_body_len: u64, pub segment_hash: String }

pub enum Immediate { Dns(DnsOut), Ssl(SslOut), Modbus(ModbusOut), Dnp3(Dnp3Out), Http(HttpOut) }

#[derive(Default, Clone)]
pub struct Stats {
    pub packets: u64, pub non_ip: u64, pub flows_seen: u64,
    pub dns: u64, pub ssl: u64, pub modbus: u64, pub dnp3: u64, pub http: u64, pub conn: u64,
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
}

impl LiveFlowAssembler {
    pub fn new(idle_timeout_s: f64) -> Self {
        Self { flows: IndexMap::new(), dirty: HashSet::new(), idle_timeout_s, stats: Stats::default() }
    }

    /// One packet's raw bytes (as scapy's `bytes(pkt)` produces -- INCLUDING
    /// the Ethernet header) plus its timestamp. Returns immediately-emitted
    /// records only; `conn` comes from snapshot()/expire()/flush().
    pub fn process(&mut self, ts: f64, data: &[u8]) -> Vec<Immediate> {
        self.stats.packets += 1;
        let mut out = Vec::new();

        let Some(l3) = strip_link_layer(LINKTYPE_ETHERNET, data) else {
            self.stats.non_ip += 1;
            return out;
        };
        if l3.len() < 20 { self.stats.non_ip += 1; return out; }
        let ihl = ((l3[0] & 0x0f) as usize) * 4;
        if ihl < 20 || l3.len() < ihl { self.stats.non_ip += 1; return out; }
        let proto_num = l3[9];
        let src_ip = ipv4_to_string(&l3[12..16]);
        let dst_ip = ipv4_to_string(&l3[16..20]);
        let l4_payload = &l3[ihl..];

        let Some(l4) = parse_l4(proto_num, l4_payload) else { return out };

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
                if let Some(ja4) = ja4_from_client_hello(l4.payload) {
                    if let Some(f) = self.flows.get_mut(&flow_key) { f.emitted_ssl = true; }
                    self.stats.ssl += 1;
                    out.push(Immediate::Ssl(SslOut {
                        uid: uid.clone(), ts, orig_h: src_ip.clone(), orig_p: l4.sport,
                        resp_h: dst_ip.clone(), resp_p: l4.dport, proto: "tcp",
                        segment_hash: seg_hash(&[uid.clone(), ja4.clone()]), ja4,
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
        let mut out = Vec::new();
        let expired_keys: Vec<FlowKey> = self.flows.iter()
            .filter(|(_, f)| (now - f.last_ts) >= self.idle_timeout_s || (now - f.first_ts) >= FLOW_HARD_TIMEOUT_S)
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired_keys {
            if let Some(f) = self.flows.shift_remove(&key) {
                out.push(f.to_conn());
                self.stats.conn += 1;
            }
        }
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
}

fn canonical_key(src_ip: &str, sport: u16, dst_ip: &str, dport: u16, proto: &'static str) -> FlowKey {
    if (src_ip, sport) <= (dst_ip, dport) {
        FlowKey(src_ip.to_string(), sport, dst_ip.to_string(), dport, proto)
    } else {
        FlowKey(dst_ip.to_string(), dport, src_ip.to_string(), sport, proto)
    }
}
