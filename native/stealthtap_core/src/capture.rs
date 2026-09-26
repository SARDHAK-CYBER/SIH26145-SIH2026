//! Native live-capture engine.
//!
//! Why this exists: the Python capture path pays a ctypes call + GIL round trip
//! PER PACKET (scapy's `recv_raw`), and every packet then crosses into a Python
//! thread queue. Measured on a real Wi-Fi link that meant one full core for
//! ~12k pps. Here the whole hot path -- libpcap/Npcap read loop, link-layer
//! normalisation, flow assembly (live.rs), host inventory, packet ring -- runs
//! in ONE Rust thread that never touches the GIL. Python only receives the
//! (comparatively rare) protocol records and flow snapshots, in batches.
//!
//! libpcap/Npcap is loaded at RUNTIME (libloading): no SDK, no import-lib, and a
//! machine without Npcap gets a clear error instead of an unloadable module.
//!
//! The same thread can replay a classic pcap file (optionally many times, at
//! full speed or a chosen speed factor) through the IDENTICAL code path -- used
//! for soak/hardness tests on real captures.

use std::collections::VecDeque;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::io::{Read, Seek, SeekFrom};
use std::os::raw::c_long;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use libloading::Library;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::inventory::{mac_str, PROTO_NAMES};
use crate::live::Stats;
use crate::ja4::ja4_and_sni;
use crate::flow_engines::{hit_to_py as flow_hit_to_py, FlowEngines, Hit};
use crate::live::{now_unix, Immediate, LiveConnRecord, LiveFlowAssembler};
use crate::parse::{parse_dns_query, parse_ip_header, parse_l4};
use crate::pcap::PcapReader;

// ------------------------------------------------------------------ libpcap FFI
type PcapT = *mut c_void;

#[repr(C)]
struct PcapPkthdr {
    ts_sec: c_long,
    ts_usec: c_long,
    caplen: u32,
    len: u32,
}

#[repr(C)]
struct BpfProgram {
    bf_len: u32,
    bf_insns: *mut c_void,
}

struct PcapApi {
    _lib: Library,
    create: unsafe extern "C" fn(*const c_char, *mut c_char) -> PcapT,
    set_snaplen: unsafe extern "C" fn(PcapT, c_int) -> c_int,
    set_promisc: unsafe extern "C" fn(PcapT, c_int) -> c_int,
    set_timeout: unsafe extern "C" fn(PcapT, c_int) -> c_int,
    set_buffer_size: unsafe extern "C" fn(PcapT, c_int) -> c_int,
    activate: unsafe extern "C" fn(PcapT) -> c_int,
    datalink: unsafe extern "C" fn(PcapT) -> c_int,
    compile: unsafe extern "C" fn(PcapT, *mut BpfProgram, *const c_char, c_int, u32) -> c_int,
    setfilter: unsafe extern "C" fn(PcapT, *mut BpfProgram) -> c_int,
    freecode: unsafe extern "C" fn(*mut BpfProgram),
    next_ex: unsafe extern "C" fn(PcapT, *mut *mut PcapPkthdr, *mut *const u8) -> c_int,
    stats: unsafe extern "C" fn(PcapT, *mut u32) -> c_int,
    close: unsafe extern "C" fn(PcapT),
    geterr: unsafe extern "C" fn(PcapT) -> *const c_char,
}

unsafe impl Send for PcapApi {}
unsafe impl Sync for PcapApi {}

macro_rules! sym {
    ($lib:expr, $name:literal) => {{
        let s: libloading::Symbol<_> = unsafe { $lib.get(concat!($name, "\0").as_bytes()) }
            .map_err(|e| format!("{} missing in pcap library: {e}", $name))?;
        *s
    }};
}

fn load_pcap() -> Result<PcapApi, String> {
    let mut last = String::new();
    let mut candidates: Vec<String> = Vec::new();
    #[cfg(windows)]
    {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        candidates.push(format!("{root}\\System32\\Npcap\\wpcap.dll"));
        candidates.push("wpcap.dll".into());
    }
    #[cfg(target_os = "linux")]
    {
        candidates.extend(["libpcap.so.0.8", "libpcap.so.1", "libpcap.so"].map(String::from));
    }
    #[cfg(target_os = "macos")]
    {
        candidates.push("libpcap.dylib".into());
    }
    for c in &candidates {
        #[cfg(windows)]
        let lib = unsafe {
            // LOAD_WITH_ALTERED_SEARCH_PATH: resolve Packet.dll next to wpcap.dll
            libloading::os::windows::Library::load_with_flags(c, 0x8).map(Library::from)
        };
        #[cfg(not(windows))]
        let lib = unsafe { Library::new(c) };
        match lib {
            Ok(lib) => {
                return Ok(PcapApi {
                    create: sym!(lib, "pcap_create"),
                    set_snaplen: sym!(lib, "pcap_set_snaplen"),
                    set_promisc: sym!(lib, "pcap_set_promisc"),
                    set_timeout: sym!(lib, "pcap_set_timeout"),
                    set_buffer_size: sym!(lib, "pcap_set_buffer_size"),
                    activate: sym!(lib, "pcap_activate"),
                    datalink: sym!(lib, "pcap_datalink"),
                    compile: sym!(lib, "pcap_compile"),
                    setfilter: sym!(lib, "pcap_setfilter"),
                    freecode: sym!(lib, "pcap_freecode"),
                    next_ex: sym!(lib, "pcap_next_ex"),
                    stats: sym!(lib, "pcap_stats"),
                    close: sym!(lib, "pcap_close"),
                    geterr: sym!(lib, "pcap_geterr"),
                    _lib: lib,
                });
            }
            Err(e) => last = format!("{c}: {e}"),
        }
    }
    Err(format!("could not load libpcap/Npcap ({last}). Install Npcap (Windows) or libpcap (Linux)."))
}

struct Handle(PcapT);
unsafe impl Send for Handle {}

fn geterr(api: &PcapApi, h: PcapT) -> String {
    unsafe {
        let p = (api.geterr)(h);
        if p.is_null() { "unknown error".into() } else { CStr::from_ptr(p).to_string_lossy().into_owned() }
    }
}

fn open_live(api: &PcapApi, iface: &str, snaplen: i32, promisc: bool, timeout_ms: i32,
             buffer_bytes: i32, bpf: Option<&str>) -> Result<(PcapT, i32), String> {
    let name = CString::new(iface).map_err(|_| "interface name contains NUL".to_string())?;
    let mut err = [0 as c_char; 256];
    unsafe {
        let h = (api.create)(name.as_ptr(), err.as_mut_ptr());
        if h.is_null() {
            return Err(format!("pcap_create({iface}): {}", CStr::from_ptr(err.as_ptr()).to_string_lossy()));
        }
        (api.set_snaplen)(h, snaplen);
        (api.set_promisc)(h, promisc as c_int);
        (api.set_timeout)(h, timeout_ms);
        if buffer_bytes > 0 { (api.set_buffer_size)(h, buffer_bytes); }
        let rc = (api.activate)(h);
        if rc < 0 {
            let m = geterr(api, h);
            (api.close)(h);
            return Err(format!("pcap_activate({iface}): {m}"));
        }
        if let Some(f) = bpf.filter(|f| !f.trim().is_empty()) {
            let cf = CString::new(f).map_err(|_| "bpf contains NUL".to_string())?;
            let mut prog = BpfProgram { bf_len: 0, bf_insns: std::ptr::null_mut() };
            if (api.compile)(h, &mut prog, cf.as_ptr(), 1, 0xffff_ffff) != 0 {
                let m = geterr(api, h);
                (api.close)(h);
                return Err(format!("BPF compile failed for {f:?}: {m}"));
            }
            let rc = (api.setfilter)(h, &mut prog);
            (api.freecode)(&mut prog);
            if rc != 0 {
                let m = geterr(api, h);
                (api.close)(h);
                return Err(format!("pcap_setfilter: {m}"));
            }
        }
        let lt = (api.datalink)(h);
        Ok((h, lt))
    }
}

// --------------------------------------------------------- link-layer normalisation
/// Appends `data` to `arena` as an Ethernet frame; returns the number of bytes appended
/// (0 = unsupported/garbage). The assembler and inspector only understand Ethernet, so
/// loopback/raw-IP/Linux-cooked captures get a synthetic (zero-MAC) header.
fn append_ethernet(arena: &mut Vec<u8>, linktype: i32, data: &[u8]) -> usize {
    let start = arena.len();
    match linktype {
        1 => arena.extend_from_slice(data),
        0 => {  // BSD loopback / Npcap Loopback Adapter: 4-byte address family
            if data.len() < 5 { return 0; }
            let et: [u8; 2] = if data[4] >> 4 == 6 { [0x86, 0xdd] } else { [0x08, 0x00] };
            arena.extend_from_slice(&[0u8; 12]); arena.extend_from_slice(&et); arena.extend_from_slice(&data[4..]);
        }
        12 | 101 => {  // raw IP
            if data.is_empty() { return 0; }
            let et: [u8; 2] = if data[0] >> 4 == 6 { [0x86, 0xdd] } else { [0x08, 0x00] };
            arena.extend_from_slice(&[0u8; 12]); arena.extend_from_slice(&et); arena.extend_from_slice(data);
        }
        113 => {  // Linux cooked v1
            if data.len() < 17 { return 0; }
            arena.extend_from_slice(&[0u8; 12]); arena.extend_from_slice(&data[14..16]); arena.extend_from_slice(&data[16..]);
        }
        _ => return 0,
    }
    arena.len() - start
}

fn linktype_supported(lt: i32) -> bool { matches!(lt, 0 | 1 | 12 | 101 | 113) }

// ---------------------------------------------------------------------- packet ring
struct RingPkt { id: u64, ts: f64, wire: u32, data: Vec<u8> }

struct PacketRing { q: VecDeque<RingPkt>, next_id: u64, cap: usize, snap: usize }

impl PacketRing {
    fn push(&mut self, ts: f64, wire: u32, data: &[u8]) {
        if self.cap == 0 { return; }
        if self.q.len() >= self.cap { self.q.pop_front(); }
        let n = data.len().min(self.snap);
        self.next_id += 1;
        self.q.push_back(RingPkt { id: self.next_id, ts, wire, data: data[..n].to_vec() });
    }
    fn first_id(&self) -> u64 { self.q.front().map(|p| p.id).unwrap_or(self.next_id + 1) }
    fn get(&self, id: u64) -> Option<&RingPkt> {
        let f = self.q.front()?.id;
        if id < f { return None; }
        self.q.get((id - f) as usize)
    }
}

// -------------------------------------------------------------------- summaries
pub struct Summary { pub proto: String, pub src: String, pub dst: String, pub sport: u16, pub dport: u16, pub info: String }

fn be16(b: &[u8], i: usize) -> u16 { u16::from_be_bytes([b[i], b[i + 1]]) }
fn be32(b: &[u8], i: usize) -> u32 { u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]) }

fn ascii_line(b: &[u8], max: usize) -> String {
    let end = b.iter().position(|&c| c == b'\r' || c == b'\n').unwrap_or(b.len()).min(max);
    b[..end].iter().map(|&c| if (32..127).contains(&c) { c as char } else { '.' }).collect()
}

fn tcp_flag_str(f: u8) -> String {
    let names = [(0x02, "SYN"), (0x10, "ACK"), (0x08, "PSH"), (0x01, "FIN"), (0x04, "RST"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")];
    let v: Vec<&str> = names.iter().filter(|(m, _)| f & m != 0).map(|(_, n)| *n).collect();
    v.join(", ")
}

fn app_hint(is_tcp: bool, sport: u16, dport: u16, p: &[u8]) -> Option<String> {
    if p.is_empty() { return None; }
    if is_tcp {
        if p[0] == 0x16 && p.len() >= 6 {
            let hs = p[5];
            let name = match hs { 1 => "ClientHello", 2 => "ServerHello", 4 => "NewSessionTicket", 11 => "Certificate",
                                  12 => "ServerKeyExchange", 13 => "CertificateRequest", 14 => "ServerHelloDone", 16 => "ClientKeyExchange",
                                  20 => "Finished", _ => "Handshake" };
            if hs == 1 {
                if let Some((_, sni)) = ja4_and_sni(p) {
                    if !sni.is_empty() { return Some(format!("TLS ClientHello  SNI={sni}")); }
                }
            }
            return Some(format!("TLS {name}"));
        }
        if p[0] == 0x17 && p.len() >= 5 && p[1] == 3 { return Some("TLS Application Data".into()); }
        if p[0] == 0x14 && p.len() >= 5 && p[1] == 3 { return Some("TLS ChangeCipherSpec".into()); }
        if p[0] == 0x15 && p.len() >= 5 && p[1] == 3 { return Some("TLS Alert".into()); }
        if p.starts_with(b"HTTP/1.") || [&b"GET "[..], b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT "]
            .iter().any(|m| p.starts_with(m)) { return Some(ascii_line(p, 110)); }
        if p.starts_with(b"SSH-") { return Some(ascii_line(p, 60)); }
        if sport == 502 || dport == 502 { return Some("Modbus/TCP".into()); }
        if sport == 20000 || dport == 20000 { return Some("DNP3".into()); }
        if sport == 88 || dport == 88 { return Some("Kerberos".into()); }
        if sport == 53 || dport == 53 { return Some("DNS over TCP".into()); }
    } else {
        if [53, 5353, 5355].contains(&sport) || [53, 5353, 5355].contains(&dport) {
            if p.len() >= 12 {
                let is_resp = p[2] & 0x80 != 0;
                let mut q = p.to_vec(); q[2] &= 0x7f;
                let name = parse_dns_query(&q).map(|(n, t)| format!("{} {}", crate::parse::qtype_name(t), n.trim_end_matches('.')));
                return Some(format!("{} {}", if is_resp { "DNS response" } else { "DNS query" }, name.unwrap_or_default()));
            }
        }
        if (sport == 443 || dport == 443) && p[0] & 0x80 != 0 { return Some("QUIC".into()); }
        if [67, 68].contains(&sport) || [67, 68].contains(&dport) { return Some("DHCP".into()); }
        if sport == 123 || dport == 123 { return Some("NTP".into()); }
        if sport == 1900 || dport == 1900 { return Some(ascii_line(p, 60)); }
    }
    None
}

pub fn summarize(data: &[u8]) -> Summary {
    let empty = |proto: &str, info: String| Summary { proto: proto.into(), src: String::new(), dst: String::new(), sport: 0, dport: 0, info };
    if data.len() < 14 { return empty("?", "runt frame".into()); }
    let mut off = 12;
    let mut et = be16(data, off);
    off += 2;
    while (et == 0x8100 || et == 0x88a8) && data.len() >= off + 4 { et = be16(data, off + 2); off += 4; }
    let l3 = &data[off.min(data.len())..];
    match et {
        0x0806 => {
            if l3.len() >= 28 {
                let op = be16(l3, 6);
                let sip = format!("{}.{}.{}.{}", l3[14], l3[15], l3[16], l3[17]);
                let tip = format!("{}.{}.{}.{}", l3[24], l3[25], l3[26], l3[27]);
                let mut m = [0u8; 6]; m.copy_from_slice(&l3[8..14]);
                let info = if op == 1 { format!("Who has {tip}? Tell {sip}") } else { format!("{sip} is at {}", mac_str(&m)) };
                return Summary { proto: "ARP".into(), src: sip, dst: tip, sport: 0, dport: 0, info };
            }
            empty("ARP", "truncated".into())
        }
        0x0800 | 0x86dd => {
            let Some((src, dst, pn, payload)) = parse_ip_header(l3) else { return empty("IP", "unparsed header".into()); };
            match parse_l4(pn, payload) {
                Some(l4) => {
                    let is_tcp = l4.proto == "tcp";
                    let mut info = String::new();
                    if is_tcp && payload.len() >= 16 {
                        let f = payload[13];
                        info = format!("{} → {} [{}] Seq={} Ack={} Win={} Len={}", l4.sport, l4.dport, tcp_flag_str(f),
                                       be32(payload, 4), be32(payload, 8), be16(payload, 14), l4.payload.len());
                    } else if !is_tcp {
                        info = format!("{} → {} Len={}", l4.sport, l4.dport, l4.payload.len());
                    }
                    if let Some(h) = app_hint(is_tcp, l4.sport, l4.dport, l4.payload) { info = format!("{h}   |  {info}"); }
                    let proto = crate::inventory::PROTO_NAMES[crate::inventory::classify(is_tcp, l4.sport, l4.dport)];
                    let proto = if proto.starts_with("other") { if is_tcp { "TCP" } else { "UDP" } } else { proto };
                    Summary { proto: proto.into(), src, dst, sport: l4.sport, dport: l4.dport, info }
                }
                None => {
                    let (name, info) = match (pn, payload.first().copied()) {
                        (1, Some(t)) => ("ICMP", match t { 0 => "Echo reply", 3 => "Destination unreachable", 8 => "Echo request", 11 => "Time exceeded", _ => "ICMP" }.to_string()),
                        (58, Some(t)) => ("ICMPv6", match t { 128 => "Echo request", 129 => "Echo reply", 133 => "Router solicitation", 134 => "Router advertisement",
                                                              135 => "Neighbor solicitation", 136 => "Neighbor advertisement", 143 => "MLDv2 report", _ => "ICMPv6" }.to_string()),
                        (2, _) => ("IGMP", "IGMP".to_string()),
                        (n, _) => ("IP", format!("protocol {n}")),
                    };
                    Summary { proto: name.into(), src, dst, sport: 0, dport: 0, info }
                }
            }
        }
        other => empty("L2", format!("ethertype 0x{other:04x}")),
    }
}

fn matches_filter(line_lc: &str, terms: &[String]) -> bool {
    terms.iter().all(|t| if let Some(n) = t.strip_prefix('!') { !line_lc.contains(n) } else { line_lc.contains(t.as_str()) })
}

fn split_terms(filter: &str) -> Vec<String> {
    filter.split_whitespace().map(|s| s.to_ascii_lowercase()).collect()
}

fn summary_dict<'py>(py: Python<'py>, id: u64, ts: f64, wire: u32, s: &Summary) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new_bound(py);
    d.set_item("id", id)?; d.set_item("ts", ts)?; d.set_item("len", wire)?;
    d.set_item("proto", &s.proto)?; d.set_item("src", &s.src)?; d.set_item("dst", &s.dst)?;
    d.set_item("sport", s.sport)?; d.set_item("dport", s.dport)?; d.set_item("info", &s.info)?;
    Ok(d)
}

fn line_of(id: u64, s: &Summary) -> String {
    format!("{} {} {} {} {} {} {}", id, s.proto, s.src, s.dst, s.sport, s.dport, s.info).to_ascii_lowercase()
}

/// A batch handed to a shard worker: the shared frame arena plus the indices (into `batch.meta`) of the
/// packets whose flows hash to that shard.
struct Work { batch: Arc<Batch>, idx: Vec<u32>, arr: f64 }

/// What the capture thread hands to Python: a protocol record seen on the wire, or a flow
/// that ended (only produced at the end of each replay loop, so loops don't merge into one flow).
enum Item { Imm(Immediate), Conn(LiveConnRecord), Hit(Hit, LiveConnRecord) }

// ------------------------------------------------------------------- shared state
struct Shared {
    stop: AtomicBool,
    running: AtomicBool,
    finished: AtomicBool,
    asms: Vec<Mutex<LiveFlowAssembler>>,       // one assembler per shard (flow-hash partitioned)
    txs: Mutex<Option<Vec<SyncSender<Work>>>>,  // capture thread -> shard workers (None when unsharded / stopped)
    inflight: AtomicU64,                        // batches handed to workers and not yet processed
    out: Mutex<VecDeque<(f64, Item)>>,
    engines: Mutex<Option<FlowEngines>>,   // native flow engines (see flow_engines.rs); None = Python scores flows
    out_cv: Condvar,
    out_cap: usize,
    ring: Mutex<PacketRing>,
    err: Mutex<Option<String>>,
    recv: AtomicU64,
    bytes: AtomicU64,
    kern_recv: AtomicU64,
    kern_drop: AtomicU64,
    if_drop: AtomicU64,
    rec_dropped: AtomicU64,
    last_ts_bits: AtomicU64,
    loops_done: AtomicU64,
    linktype: AtomicU64,
    unsupported: AtomicU64,
}

enum SourceCfg {
    Live { iface: String, bpf: Option<String>, snaplen: i32, buffer_bytes: i32, promisc: bool, timeout_ms: i32 },
    File { path: String, loops: u64, speed: f64 },
}

const BATCH_PKTS: usize = 512;

struct Batch { arena: Vec<u8>, meta: Vec<(f64, usize, usize, u32)> }

impl Batch {
    fn new() -> Self { Batch { arena: Vec::with_capacity(1 << 20), meta: Vec::with_capacity(BATCH_PKTS) } }
    fn add(&mut self, linktype: i32, ts: f64, data: &[u8], wire: u32, sh: &Shared) {
        let off = self.arena.len();
        let n = append_ethernet(&mut self.arena, linktype, data);
        if n == 0 { sh.unsupported.fetch_add(1, Ordering::Relaxed); return; }
        self.meta.push((ts, off, n, wire));
    }
    fn full(&self) -> bool { self.meta.len() >= BATCH_PKTS || self.arena.len() > (1 << 20) - 70_000 }
}

/// Symmetric flow hash straight from the raw frame (no allocation): both directions of a flow land in
/// the same shard. Non-IP frames (ARP...) go to shard 0.
fn shard_of(f: &[u8], n: usize) -> usize {
    if n <= 1 || f.len() < 34 { return 0; }
    let mut et = u16::from_be_bytes([f[12], f[13]]);
    let mut off = 14usize;
    while (et == 0x8100 || et == 0x88a8) && f.len() >= off + 4 { et = u16::from_be_bytes([f[off + 2], f[off + 3]]); off += 4; }
    let word = |i: usize| u32::from_be_bytes([f[i], f[i + 1], f[i + 2], f[i + 3]]);
    let h: u32 = match et {
        0x0800 => {
            if f.len() < off + 20 { return 0; }
            let ihl = ((f[off] & 0x0f) as usize) * 4;
            let proto = f[off + 9];
            let mut x = word(off + 12) ^ word(off + 16);
            if (proto == 6 || proto == 17) && ihl >= 20 && f.len() >= off + ihl + 4 {
                let sp = u16::from_be_bytes([f[off + ihl], f[off + ihl + 1]]) as u32;
                let dp = u16::from_be_bytes([f[off + ihl + 2], f[off + ihl + 3]]) as u32;
                x ^= (sp ^ dp).wrapping_mul(0x9E37_79B1);
            }
            x
        }
        0x86dd => {
            if f.len() < off + 40 { return 0; }
            let mut x = 0u32;
            for i in 0..4 { x ^= word(off + 8 + 4 * i) ^ word(off + 24 + 4 * i); }
            let nh = f[off + 6];
            if (nh == 6 || nh == 17) && f.len() >= off + 44 {
                let sp = u16::from_be_bytes([f[off + 40], f[off + 41]]) as u32;
                let dp = u16::from_be_bytes([f[off + 42], f[off + 43]]) as u32;
                x ^= (sp ^ dp).wrapping_mul(0x9E37_79B1);
            }
            x
        }
        _ => return 0,
    };
    ((h.wrapping_mul(0x85EB_CA6B) >> 7) as usize) % n
}

/// One frame through one shard's assembler (ARP bookkeeping included).
fn process_frame(asm: &mut LiveFlowAssembler, ts: f64, frame: &[u8], arr: f64, recs: &mut Vec<(f64, Item)>) {
    if frame.len() >= 42 && frame[12] == 0x08 && frame[13] == 0x06 {   // ARP
        let mut m = [0u8; 6]; m.copy_from_slice(&frame[22..28]);
        let ip = format!("{}.{}.{}.{}", frame[28], frame[29], frame[30], frame[31]);
        asm.inv.observe_arp(&ip, m, ts, frame.len() as u64);
    }
    for r in asm.process(ts, frame) { recs.push((arr, Item::Imm(r))); }
}

fn push_records(sh: &Shared, recs: Vec<(f64, Item)>) {
    if recs.is_empty() { return; }
    let mut out = sh.out.lock().unwrap();
    for r in recs {
        if out.len() >= sh.out_cap { sh.rec_dropped.fetch_add(1, Ordering::Relaxed); continue; }
        out.push_back(r);
    }
    sh.out_cv.notify_all();
}

fn shard_worker(sh: Arc<Shared>, shard: usize, rx: Receiver<Work>) {
    while let Ok(w) = rx.recv() {
        let mut recs: Vec<(f64, Item)> = Vec::new();
        {
            let mut asm = sh.asms[shard].lock().unwrap();
            for &i in &w.idx {
                let (ts, off, n, _) = w.batch.meta[i as usize];
                process_frame(&mut asm, ts, &w.batch.arena[off..off + n], w.arr, &mut recs);
            }
        }
        push_records(&sh, recs);
        sh.inflight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Block until every batch handed to the shard workers has been processed.
fn wait_workers_idle(sh: &Shared) {
    while sh.inflight.load(Ordering::SeqCst) > 0 { std::thread::sleep(Duration::from_micros(200)); }
}

fn flush_batch(sh: &Shared, b: &mut Batch) {
    if b.meta.is_empty() { return; }
    let arr = now_unix();
    let mut bytes = 0u64;
    let mut last_ts = 0f64;
    for &(ts, _off, n, _wire) in &b.meta {
        bytes += n as u64;
        if ts > last_ts { last_ts = ts; }
    }
    {
        let mut ring = sh.ring.lock().unwrap();
        for &(ts, off, n, wire) in &b.meta { ring.push(ts, wire, &b.arena[off..off + n]); }
    }
    sh.recv.fetch_add(b.meta.len() as u64, Ordering::Relaxed);
    sh.bytes.fetch_add(bytes, Ordering::Relaxed);
    if last_ts > 0.0 {
        let prev = f64::from_bits(sh.last_ts_bits.load(Ordering::Relaxed));
        if last_ts > prev { sh.last_ts_bits.store(last_ts.to_bits(), Ordering::Relaxed); }
    }

    let n = sh.asms.len();
    let txs = if n > 1 { sh.txs.lock().unwrap().clone() } else { None };
    match txs {
        None => {
            let mut recs: Vec<(f64, Item)> = Vec::new();
            {
                let mut asm = sh.asms[0].lock().unwrap();
                for &(ts, off, len, _) in &b.meta { process_frame(&mut asm, ts, &b.arena[off..off + len], arr, &mut recs); }
            }
            push_records(sh, recs);
            b.arena.clear();
            b.meta.clear();
        }
        Some(txs) => {
            let mut idx: Vec<Vec<u32>> = vec![Vec::new(); n];
            for (i, &(_ts, off, len, _)) in b.meta.iter().enumerate() {
                idx[shard_of(&b.arena[off..off + len], n)].push(i as u32);
            }
            let cap = b.arena.capacity();
            let done = std::mem::replace(b, Batch { arena: Vec::with_capacity(cap), meta: Vec::with_capacity(BATCH_PKTS) });
            let shared = Arc::new(done);
            for (k, ix) in idx.into_iter().enumerate() {
                if ix.is_empty() { continue; }
                sh.inflight.fetch_add(1, Ordering::SeqCst);
                if txs[k].send(Work { batch: shared.clone(), idx: ix, arr }).is_err() { sh.inflight.fetch_sub(1, Ordering::SeqCst); }
            }
        }
    }
}

fn set_err(sh: &Shared, m: String) { *sh.err.lock().unwrap() = Some(m); }

fn run_live(sh: Arc<Shared>, api: Arc<PcapApi>, h: Handle, linktype: i32) {
    let mut batch = Batch::new();
    let mut hdr: *mut PcapPkthdr = std::ptr::null_mut();
    let mut data: *const u8 = std::ptr::null();
    let mut last_stats = Instant::now();
    let mut st = [0u32; 8];
    while !sh.stop.load(Ordering::Relaxed) {
        let rc = unsafe { (api.next_ex)(h.0, &mut hdr, &mut data) };
        match rc {
            1 => unsafe {
                let hd = &*hdr;
                let ts = hd.ts_sec as f64 + hd.ts_usec as f64 / 1e6;
                let sl = std::slice::from_raw_parts(data, hd.caplen as usize);
                batch.add(linktype, ts, sl, hd.len, &sh);
                if batch.full() { flush_batch(&sh, &mut batch); }
            },
            0 => flush_batch(&sh, &mut batch),
            _ => {
                flush_batch(&sh, &mut batch);
                if sh.stop.load(Ordering::Relaxed) { break; }
                set_err(&sh, format!("pcap_next_ex failed (rc={rc}): {}", geterr(&api, h.0)));
                break;
            }
        }
        if last_stats.elapsed() >= Duration::from_millis(500) {
            last_stats = Instant::now();
            if unsafe { (api.stats)(h.0, st.as_mut_ptr()) } == 0 {
                sh.kern_recv.store(st[0] as u64, Ordering::Relaxed);
                sh.kern_drop.store(st[1] as u64, Ordering::Relaxed);
                sh.if_drop.store(st[2] as u64, Ordering::Relaxed);
            }
        }
    }
    flush_batch(&sh, &mut batch);
    if unsafe { (api.stats)(h.0, st.as_mut_ptr()) } == 0 {
        sh.kern_recv.store(st[0] as u64, Ordering::Relaxed);
        sh.kern_drop.store(st[1] as u64, Ordering::Relaxed);
        sh.if_drop.store(st[2] as u64, Ordering::Relaxed);
    }
    unsafe { (api.close)(h.0) };
    wait_workers_idle(&sh);
    sh.running.store(false, Ordering::SeqCst);
}

const BASELINE_SAMPLE_MAX: usize = 2000;

/// Run the native flow engines over flows that just ended (when enabled) and return what Python
/// still needs: the hits, plus an evenly-strided sample of the records for the online baseline.
/// With the engines disabled every record is passed through unchanged (Python scores them).
fn score_ended(sh: &Shared, ended: Vec<LiveConnRecord>, sample_max: usize) -> Vec<Item> {
    let mut guard = sh.engines.lock().unwrap();
    let Some(eng) = guard.as_mut() else { return ended.into_iter().map(Item::Conn).collect(); };
    let mut hits: Vec<Hit> = Vec::new();
    let mut hit_idx: Vec<usize> = Vec::new();
    for (i, r) in ended.iter().enumerate() {
        let before = hits.len();
        eng.expire(r, &mut hits);
        for _ in before..hits.len() { hit_idx.push(i); }
    }
    let stride = (ended.len() / sample_max.max(1)).max(1);
    let mut out: Vec<Item> = Vec::new();
    let mut hit_iter = hits.into_iter().zip(hit_idx.into_iter()).peekable();
    for (i, r) in ended.into_iter().enumerate() {
        // a record can carry several hits; each hit owns a copy of its record (rare)
        let mut mine: Vec<Hit> = Vec::new();
        while let Some((_, hi)) = hit_iter.peek() {
            if *hi == i { mine.push(hit_iter.next().unwrap().0); } else { break; }
        }
        let keep_sample = i % stride == 0;
        let mut owned = Some(r);
        for h in mine {
            let rec = owned.as_ref().map(clone_conn).unwrap();
            out.push(Item::Hit(h, rec));
        }
        if keep_sample { out.push(Item::Conn(owned.take().unwrap())); }
    }
    out
}

fn clone_conn(r: &LiveConnRecord) -> LiveConnRecord {
    LiveConnRecord {
        uid: r.uid.clone(), ts: r.ts, orig_h: r.orig_h.clone(), orig_p: r.orig_p, resp_h: r.resp_h.clone(),
        resp_p: r.resp_p, proto: r.proto, duration: r.duration, orig_bytes: r.orig_bytes, resp_bytes: r.resp_bytes,
        orig_pkts: r.orig_pkts, resp_pkts: r.resp_pkts, segment_hash: r.segment_hash.clone(), snapshot_ts: r.snapshot_ts,
    }
}

fn run_file(sh: Arc<Shared>, path: String, loops: u64, speed: f64) {
    let mut batch = Batch::new();
    let mut span_offset = 0f64;
    let mut done = 0u64;
    let wall0 = Instant::now();
    let mut first_ts: Option<f64> = None;
    let mut rd = match PcapReader::open(&path) {
        Ok(r) => r,
        Err(e) => { set_err(&sh, format!("{path}: {e}")); sh.finished.store(true, Ordering::SeqCst); sh.running.store(false, Ordering::SeqCst); return; }
    };
    let lt = rd.linktype as i32;
    if !linktype_supported(lt) {
        set_err(&sh, format!("{path}: unsupported linktype {lt}"));
        sh.finished.store(true, Ordering::SeqCst); sh.running.store(false, Ordering::SeqCst);
        return;
    }
    sh.linktype.store(lt as u64, Ordering::Relaxed);
    'outer: loop {
        let mut loop_first: Option<f64> = None;
        let mut loop_last = 0f64;
        loop {
            if sh.stop.load(Ordering::Relaxed) { break 'outer; }
            match rd.next_packet() {
                Ok(Some(p)) => {
                    let lf = *loop_first.get_or_insert(p.ts);
                    loop_last = p.ts;
                    let ts = p.ts + span_offset;
                    if speed > 0.0 {
                        let f0 = *first_ts.get_or_insert(ts);
                        let target = Duration::from_secs_f64(((ts - f0) / speed).max(0.0));
                        let el = wall0.elapsed();
                        if target > el + Duration::from_millis(2) {
                            flush_batch(&sh, &mut batch);
                            std::thread::sleep(target - el);
                        }
                    }
                    let _ = lf;
                    batch.add(lt, ts, &p.data, p.data.len() as u32, &sh);
                    if batch.full() { flush_batch(&sh, &mut batch); }
                }
                _ => break,
            }
        }
        flush_batch(&sh, &mut batch);
        done += 1;
        sh.loops_done.store(done, Ordering::Relaxed);
        if loops != 0 && done >= loops { break; }
        // next pass continues in "time" right after this one so flows/windows keep advancing
        // Idle-timeout gap: the next pass starts >= idle_timeout after this one ended, and the
        // flows still open are expired right now, so consecutive loops are separate flows
        // (not one flow that never ends and eventually looks like a slow-loris).
        span_offset += (loop_last - loop_first.unwrap_or(loop_last)) + 61.0;
        {
            wait_workers_idle(&sh);
            let ended = sh.expire_all(f64::MAX / 4.0);   // far-future clock: everything still open has ended
            if !ended.is_empty() {
                let items = score_ended(&sh, ended, BASELINE_SAMPLE_MAX);
                let mut out = sh.out.lock().unwrap();
                let now = now_unix();
                for it in items {
                    if out.len() >= sh.out_cap { sh.rec_dropped.fetch_add(1, Ordering::Relaxed); continue; }
                    out.push_back((now, it));
                }
                sh.out_cv.notify_all();
            }
        }
        if rd.rewind().is_err() { set_err(&sh, format!("{path}: cannot rewind")); break; }
    }
    flush_batch(&sh, &mut batch);
    wait_workers_idle(&sh);
    sh.finished.store(true, Ordering::SeqCst);
    sh.running.store(false, Ordering::SeqCst);
}

impl Shared {
    /// Merge per-shard results back into first-seen (timestamp) order: the stateful engines are
    /// order-sensitive (ENG-05's windowed fan-out, ENG-01's first-crossing dedup), and shard-by-shard
    /// concatenation changed their alerts on a real capture.
    fn ordered(&self, mut v: Vec<LiveConnRecord>) -> Vec<LiveConnRecord> {
        if self.asms.len() > 1 { v.sort_by(|a, b| a.ts.partial_cmp(&b.ts).unwrap_or(std::cmp::Ordering::Equal)); }
        v
    }
    fn snapshot_all(&self, limit: usize) -> Vec<LiveConnRecord> {
        let per = (limit / self.asms.len()).max(1);
        self.ordered(self.asms.iter().flat_map(|a| a.lock().unwrap().snapshot(per)).collect())
    }
    fn expire_all(&self, now: f64) -> Vec<LiveConnRecord> {
        self.ordered(self.asms.iter().flat_map(|a| a.lock().unwrap().expire(now)).collect())
    }
    fn flush_all(&self) -> Vec<LiveConnRecord> {
        self.ordered(self.asms.iter().flat_map(|a| a.lock().unwrap().flush()).collect())
    }
    fn active_all(&self) -> usize { self.asms.iter().map(|a| a.lock().unwrap().active_flows()).sum() }
    fn top_flows_all(&self, n: usize) -> Vec<LiveConnRecord> {
        let mut v: Vec<LiveConnRecord> = self.asms.iter().flat_map(|a| a.lock().unwrap().top_flows(n)).collect();
        v.sort_by(|a, b| (b.orig_bytes + b.resp_bytes).cmp(&(a.orig_bytes + a.resp_bytes)));
        v.truncate(n);
        v
    }
    fn stats_all(&self) -> Stats {
        let mut t = Stats::default();
        for a in &self.asms {
            let s = a.lock().unwrap().stats.clone();
            t.packets += s.packets; t.non_ip += s.non_ip; t.flows_seen += s.flows_seen; t.dns += s.dns; t.ssl += s.ssl;
            t.modbus += s.modbus; t.dnp3 += s.dnp3; t.http += s.http; t.kerberos += s.kerberos; t.s7comm += s.s7comm;
            t.iec104 += s.iec104; t.cip += s.cip; t.bacnet += s.bacnet; t.opcua += s.opcua; t.opcua_encrypted += s.opcua_encrypted; t.opcua_unsecured += s.opcua_unsecured; t.profinet += s.profinet; t.appsvc += s.appsvc; t.conn += s.conn;
        }
        t
    }
}

struct MergedHost { first: f64, last: f64, tx_pkts: u64, rx_pkts: u64, tx_bytes: u64, rx_bytes: u64, tcp: u64, udp: u64, other: u64,
                    mac: Option<[u8; 6]>, via_arp: bool }

fn merged_hosts(sh: &Shared) -> std::collections::HashMap<String, MergedHost> {
    let mut m: std::collections::HashMap<String, MergedHost> = std::collections::HashMap::new();
    for a in &sh.asms {
        let a = a.lock().unwrap();
        for (ip, h) in a.inv.hosts.iter() {
            let e = m.entry(ip.clone()).or_insert(MergedHost { first: h.first, last: h.last, tx_pkts: 0, rx_pkts: 0, tx_bytes: 0,
                rx_bytes: 0, tcp: 0, udp: 0, other: 0, mac: None, via_arp: false });
            e.first = e.first.min(h.first); e.last = e.last.max(h.last);
            e.tx_pkts += h.tx_pkts; e.rx_pkts += h.rx_pkts; e.tx_bytes += h.tx_bytes; e.rx_bytes += h.rx_bytes;
            e.tcp += h.tcp; e.udp += h.udp; e.other += h.other;
            if e.mac.is_none() { e.mac = h.mac; }
            e.via_arp |= h.via_arp;
        }
    }
    m
}

fn hits_to_list(py: Python<'_>, hits: Vec<(Hit, LiveConnRecord)>) -> PyResult<PyObject> {
    let list = PyList::empty_bound(py);
    for (h, rec) in &hits {
        list.append((h.engine, crate::live_conn_to_dict(py, rec)?, flow_hit_to_py(py, h)?))?;
    }
    Ok(list.into())
}

// ------------------------------------------------------------------ Python class
#[pyclass]
pub struct NativeCapture {
    sh: Arc<Shared>,
    cfg: Mutex<Option<SourceCfg>>,
    th: Mutex<Option<JoinHandle<()>>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
}

#[pymethods]
impl NativeCapture {
    /// Live: `NativeCapture(iface="\\Device\\NPF_{...}", bpf="ip or ip6 or arp")`.
    /// File replay: `NativeCapture(pcap="x.pcap", loops=0 /*forever*/, speed=0.0 /*max*/)`.
    #[new]
    #[pyo3(signature = (iface=None, bpf=None, snaplen=65535, buffer_mb=64, promisc=true, timeout_ms=10,
                        pcap=None, loops=1, speed=0.0, ring_packets=50000, ring_snap=256,
                        idle_timeout_s=60.0, max_pending_records=1_000_000, shards=1))]
    fn new(iface: Option<String>, bpf: Option<String>, snaplen: i32, buffer_mb: i32, promisc: bool,
           timeout_ms: i32, pcap: Option<String>, loops: u64, speed: f64, ring_packets: usize,
           ring_snap: usize, idle_timeout_s: f64, max_pending_records: usize, shards: usize) -> PyResult<Self> {
        let cfg = match (iface, pcap) {
            (Some(i), None) => SourceCfg::Live { iface: i, bpf, snaplen, buffer_bytes: buffer_mb.saturating_mul(1024 * 1024),
                                                  promisc, timeout_ms },
            (None, Some(p)) => SourceCfg::File { path: p, loops, speed },
            _ => return Err(pyo3::exceptions::PyValueError::new_err("give exactly one of iface= or pcap=")),
        };
        let sh = Arc::new(Shared {
            stop: AtomicBool::new(false), running: AtomicBool::new(false), finished: AtomicBool::new(false),
            asms: (0..shards.max(1)).map(|_| Mutex::new(LiveFlowAssembler::new(idle_timeout_s))).collect(),
            txs: Mutex::new(None), inflight: AtomicU64::new(0),
            out: Mutex::new(VecDeque::new()), engines: Mutex::new(None), out_cv: Condvar::new(), out_cap: max_pending_records,
            ring: Mutex::new(PacketRing { q: VecDeque::new(), next_id: 0, cap: ring_packets, snap: ring_snap.max(64) }),
            err: Mutex::new(None),
            recv: AtomicU64::new(0), bytes: AtomicU64::new(0), kern_recv: AtomicU64::new(0), kern_drop: AtomicU64::new(0),
            if_drop: AtomicU64::new(0), rec_dropped: AtomicU64::new(0), last_ts_bits: AtomicU64::new(0),
            loops_done: AtomicU64::new(0), linktype: AtomicU64::new(0), unsupported: AtomicU64::new(0),
        });
        Ok(Self { sh, cfg: Mutex::new(Some(cfg)), th: Mutex::new(None), workers: Mutex::new(Vec::new()) })
    }

    /// Opens the source (raises OSError with the driver's message if that fails) and
    /// starts the capture thread.
    fn start(&self) -> PyResult<()> {
        let cfg = self.cfg.lock().unwrap().take()
            .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("already started"))?;
        let sh = self.sh.clone();
        if sh.asms.len() > 1 {
            let mut txs = Vec::new();
            let mut ws = self.workers.lock().unwrap();
            for k in 0..sh.asms.len() {
                let (tx, rx) = sync_channel::<Work>(256);
                txs.push(tx);
                let shc = sh.clone();
                ws.push(std::thread::Builder::new().name(format!("stealthtap-shard-{k}"))
                    .spawn(move || shard_worker(shc, k, rx))
                    .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))?);
            }
            *sh.txs.lock().unwrap() = Some(txs);
        }
        let handle = match cfg {
            SourceCfg::Live { iface, bpf, snaplen, buffer_bytes, promisc, timeout_ms } => {
                let api = Arc::new(load_pcap().map_err(pyo3::exceptions::PyOSError::new_err)?);
                let (h, lt) = open_live(&api, &iface, snaplen, promisc, timeout_ms, buffer_bytes, bpf.as_deref())
                    .map_err(pyo3::exceptions::PyOSError::new_err)?;
                if !linktype_supported(lt) {
                    unsafe { (api.close)(h) };
                    return Err(pyo3::exceptions::PyOSError::new_err(format!("unsupported data-link type {lt} on {iface}")));
                }
                sh.linktype.store(lt as u64, Ordering::Relaxed);
                sh.running.store(true, Ordering::SeqCst);
                let h = Handle(h);
                std::thread::Builder::new().name("stealthtap-capture".into())
                    .spawn(move || run_live(sh, api, h, lt))
                    .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))?
            }
            SourceCfg::File { path, loops, speed } => {
                PcapReader::open(&path).map_err(|e| pyo3::exceptions::PyOSError::new_err(format!("{path}: {e}")))?;
                sh.running.store(true, Ordering::SeqCst);
                std::thread::Builder::new().name("stealthtap-replay".into())
                    .spawn(move || run_file(sh, path, loops, speed))
                    .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))?
            }
        };
        *self.th.lock().unwrap() = Some(handle);
        Ok(())
    }

    fn stop(&self, py: Python<'_>) {
        self.sh.stop.store(true, Ordering::SeqCst);
        let th = self.th.lock().unwrap().take();
        let sh = self.sh.clone();
        let ws: Vec<JoinHandle<()>> = std::mem::take(&mut *self.workers.lock().unwrap());
        py.allow_threads(|| {
            if let Some(t) = th { let _ = t.join(); }
            *sh.txs.lock().unwrap() = None;      // closes the channels: workers drain and exit
            for w in ws { let _ = w.join(); }
        });
        self.sh.running.store(false, Ordering::SeqCst);
    }

    fn running(&self) -> bool { self.sh.running.load(Ordering::SeqCst) }
    fn finished(&self) -> bool { self.sh.finished.load(Ordering::SeqCst) }
    fn error(&self) -> Option<String> { self.sh.err.lock().unwrap().clone() }
    fn pending(&self) -> usize { self.sh.out.lock().unwrap().len() }

    /// Block (GIL released) up to `timeout_ms` for records, then return up to `max_records`
    /// as [(log_type, dict), ...]; each dict carries `_arr` (wall-clock arrival stamp).
    #[pyo3(signature = (timeout_ms=100, max_records=5000))]
    fn poll(&self, py: Python<'_>, timeout_ms: u64, max_records: usize) -> PyResult<PyObject> {
        let sh = self.sh.clone();
        let batch: Vec<(f64, Item)> = py.allow_threads(|| {
            let mut out = sh.out.lock().unwrap();
            if out.is_empty() && timeout_ms > 0 {
                out = sh.out_cv.wait_timeout(out, Duration::from_millis(timeout_ms)).unwrap().0;
            }
            let n = out.len().min(max_records);
            out.drain(..n).collect()
        });
        let list = PyList::empty_bound(py);
        for (arr, item) in &batch {
            match item {
                Item::Imm(rec) => {
                    let (lt, d) = crate::immediate_to_dict(py, rec)?;
                    d.set_item("_arr", *arr)?;
                    list.append((lt, d))?;
                }
                Item::Conn(rec) => {
                    let d = crate::live_conn_to_dict(py, rec)?;
                    list.append(("conn", d))?;
                }
                Item::Hit(h, rec) => {
                    let d = PyDict::new_bound(py);
                    d.set_item("engine", h.engine)?;
                    d.set_item("rec", crate::live_conn_to_dict(py, rec)?)?;
                    d.set_item("hit", flow_hit_to_py(py, h)?)?;
                    list.append(("hit", d))?;
                }
            }
        }
        Ok(list.into())
    }

    /// Turn the native flow engines on (ENG-01/02/05/06/13 evaluated in Rust). After this,
    /// `snapshot_scored` / `expire_scored` / `flush_scored` return only hits; the plain
    /// snapshot/expire/flush keep returning raw flow records for the Python path.
    #[pyo3(signature = (single_flow_min_bytes=1048576.0))]
    fn enable_flow_engines(&self, single_flow_min_bytes: f64) {
        *self.sh.engines.lock().unwrap() = Some(FlowEngines::new(single_flow_min_bytes));
    }

    /// Snapshot active flows through ENG-01/05/13 in Rust: -> [(engine, conn_dict, hit_dict), ...]
    #[pyo3(signature = (limit=4000))]
    fn snapshot_scored(&self, py: Python<'_>, limit: usize) -> PyResult<PyObject> {
        let recs = self.sh.snapshot_all(limit);
        let sh = self.sh.clone();
        let hits = py.allow_threads(move || {
            let mut guard = sh.engines.lock().unwrap();
            let mut out: Vec<(Hit, LiveConnRecord)> = Vec::new();
            if let Some(eng) = guard.as_mut() {
                for r in &recs {
                    let mut hs: Vec<Hit> = Vec::new();
                    eng.snapshot(r, &mut hs);
                    for h in hs { out.push((h, clone_conn(r))); }
                }
            }
            out
        });
        hits_to_list(py, hits)
    }

    /// Expire idle flows (or, with `flush=True`, every flow) through all five engines in Rust.
    /// -> (hits [(engine, conn_dict, hit_dict)], sample [conn_dict] for the baseline, total_ended)
    #[pyo3(signature = (now=None, sample_max=2000, flush=false))]
    fn expire_scored(&self, py: Python<'_>, now: Option<f64>, sample_max: usize, flush: bool) -> PyResult<PyObject> {
        let recs = if flush { self.sh.flush_all() } else { self.sh.expire_all(now.unwrap_or_else(now_unix)) };
        let total = recs.len();
        let sh = self.sh.clone();
        let items = py.allow_threads(move || score_ended(&sh, recs, sample_max));
        let hits = PyList::empty_bound(py);
        let sample = PyList::empty_bound(py);
        for it in &items {
            match it {
                Item::Hit(h, rec) => {
                    hits.append((h.engine, crate::live_conn_to_dict(py, rec)?, flow_hit_to_py(py, h)?))?;
                }
                Item::Conn(rec) => sample.append(crate::live_conn_to_dict(py, rec)?)?,
                Item::Imm(_) => {}
            }
        }
        Ok((hits, sample, total).into_py(py))
    }

    #[pyo3(signature = (limit=4000))]
    fn snapshot(&self, py: Python<'_>, limit: usize) -> PyResult<PyObject> {
        let recs = self.sh.snapshot_all(limit);
        crate::conn_batch_to_pylist(py, recs)
    }

    #[pyo3(signature = (now=None))]
    fn expire(&self, py: Python<'_>, now: Option<f64>) -> PyResult<PyObject> {
        let recs = self.sh.expire_all(now.unwrap_or_else(now_unix));
        crate::conn_batch_to_pylist(py, recs)
    }

    fn flush(&self, py: Python<'_>) -> PyResult<PyObject> {
        let recs = self.sh.flush_all();
        crate::conn_batch_to_pylist(py, recs)
    }

    fn active_flows(&self) -> usize { self.sh.active_all() }

    #[pyo3(signature = (n=50))]
    fn top_flows(&self, py: Python<'_>, n: usize) -> PyResult<PyObject> {
        let recs = self.sh.top_flows_all(n);
        crate::conn_batch_to_pylist(py, recs)
    }

    fn stats(&self, py: Python<'_>) -> PyResult<PyObject> {
        let d = PyDict::new_bound(py);
        {
            let s = self.sh.stats_all();
            d.set_item("packets", s.packets)?; d.set_item("non_ip", s.non_ip)?; d.set_item("flows_seen", s.flows_seen)?;
            d.set_item("dns", s.dns)?; d.set_item("ssl", s.ssl)?; d.set_item("modbus", s.modbus)?;
            d.set_item("dnp3", s.dnp3)?; d.set_item("http", s.http)?; d.set_item("kerberos", s.kerberos)?;
            d.set_item("s7comm", s.s7comm)?; d.set_item("iec104", s.iec104)?; d.set_item("cip", s.cip)?; d.set_item("bacnet", s.bacnet)?; d.set_item("opcua", s.opcua)?; d.set_item("opcua_encrypted", s.opcua_encrypted)?; d.set_item("opcua_unsecured", s.opcua_unsecured)?; d.set_item("profinet", s.profinet)?; d.set_item("appsvc", s.appsvc)?; d.set_item("conn", s.conn)?;
            d.set_item("active_flows", self.sh.active_all())?;
            let (hn, hd) = if self.sh.asms.len() == 1 {
                let a = self.sh.asms[0].lock().unwrap(); (a.inv.hosts.len(), a.inv.hosts_dropped)
            } else {
                let mut dropped = 0u64;
                for a in &self.sh.asms { dropped += a.lock().unwrap().inv.hosts_dropped; }
                (merged_hosts(&self.sh).len(), dropped)
            };
            d.set_item("hosts", hn)?; d.set_item("hosts_dropped", hd)?;
            d.set_item("shards", self.sh.asms.len())?;
        }
        {
            let r = self.sh.ring.lock().unwrap();
            d.set_item("ring_first_id", r.first_id())?; d.set_item("ring_last_id", r.next_id)?; d.set_item("ring_len", r.q.len())?;
        }
        d.set_item("recv", self.sh.recv.load(Ordering::Relaxed))?;
        d.set_item("bytes", self.sh.bytes.load(Ordering::Relaxed))?;
        d.set_item("kernel_recv", self.sh.kern_recv.load(Ordering::Relaxed))?;
        d.set_item("kernel_drop", self.sh.kern_drop.load(Ordering::Relaxed))?;
        d.set_item("if_drop", self.sh.if_drop.load(Ordering::Relaxed))?;
        d.set_item("records_dropped", self.sh.rec_dropped.load(Ordering::Relaxed))?;
        d.set_item("unsupported_frames", self.sh.unsupported.load(Ordering::Relaxed))?;
        d.set_item("pending_records", self.sh.out.lock().unwrap().len() + self.sh.inflight.load(Ordering::SeqCst) as usize)?;
        d.set_item("last_ts", f64::from_bits(self.sh.last_ts_bits.load(Ordering::Relaxed)))?;
        d.set_item("loops_done", self.sh.loops_done.load(Ordering::Relaxed))?;
        d.set_item("linktype", self.sh.linktype.load(Ordering::Relaxed))?;
        d.set_item("running", self.sh.running.load(Ordering::SeqCst))?;
        d.set_item("finished", self.sh.finished.load(Ordering::SeqCst))?;
        Ok(d.into())
    }

    /// Hosts seen so far, heaviest first.
    #[pyo3(signature = (limit=500))]
    fn hosts(&self, py: Python<'_>, limit: usize) -> PyResult<PyObject> {
        let m = merged_hosts(&self.sh);
        let mut v: Vec<(&String, &MergedHost)> = m.iter().collect();
        v.sort_by(|x, y| (y.1.tx_bytes + y.1.rx_bytes).cmp(&(x.1.tx_bytes + x.1.rx_bytes)));
        let list = PyList::empty_bound(py);
        for (ip, h) in v.into_iter().take(limit) {
            let d = PyDict::new_bound(py);
            d.set_item("ip", ip)?; d.set_item("first", h.first)?; d.set_item("last", h.last)?;
            d.set_item("tx_pkts", h.tx_pkts)?; d.set_item("rx_pkts", h.rx_pkts)?;
            d.set_item("tx_bytes", h.tx_bytes)?; d.set_item("rx_bytes", h.rx_bytes)?;
            d.set_item("tcp", h.tcp)?; d.set_item("udp", h.udp)?; d.set_item("other", h.other)?;
            d.set_item("mac", h.mac.as_ref().map(mac_str))?; d.set_item("via_arp", h.via_arp)?;
            list.append(d)?;
        }
        Ok(list.into())
    }

    fn protocols(&self, py: Python<'_>) -> PyResult<PyObject> {
        let mut pk = [0u64; 32];
        let mut by = [0u64; 32];
        for a in &self.sh.asms {
            let a = a.lock().unwrap();
            for i in 0..32 { pk[i] += a.inv.proto_pkts[i]; by[i] += a.inv.proto_bytes[i]; }
        }
        let list = PyList::empty_bound(py);
        for (i, n) in PROTO_NAMES.iter().enumerate() {
            if pk[i] == 0 { continue; }
            let d = PyDict::new_bound(py);
            d.set_item("name", n)?; d.set_item("packets", pk[i])?; d.set_item("bytes", by[i])?;
            list.append(d)?;
        }
        Ok(list.into())
    }

    /// Packet summaries from the ring. `after_id == 0` -> the newest `limit` packets (ascending);
    /// otherwise the first `limit` packets with id > after_id. `filter`: whitespace-separated
    /// case-insensitive terms that must all appear in the row ("tcp 10.0.0.5 !dns").
    #[pyo3(signature = (after_id=0, limit=200, filter=""))]
    fn packets(&self, py: Python<'_>, after_id: u64, limit: usize, filter: &str) -> PyResult<PyObject> {
        let terms = split_terms(filter);
        let ring = self.sh.ring.lock().unwrap();
        let list = PyList::empty_bound(py);
        let mut rows: Vec<Bound<PyDict>> = Vec::new();
        if after_id == 0 {
            for p in ring.q.iter().rev() {
                let s = summarize(&p.data);
                if !terms.is_empty() && !matches_filter(&line_of(p.id, &s), &terms) { continue; }
                rows.push(summary_dict(py, p.id, p.ts, p.wire, &s)?);
                if rows.len() >= limit { break; }
            }
            rows.reverse();
        } else {
            let first = ring.first_id();
            let start = after_id.saturating_add(1).max(first);
            let mut id = start;
            while id <= ring.next_id && rows.len() < limit {
                if let Some(p) = ring.get(id) {
                    let s = summarize(&p.data);
                    if terms.is_empty() || matches_filter(&line_of(p.id, &s), &terms) {
                        rows.push(summary_dict(py, p.id, p.ts, p.wire, &s)?);
                    }
                }
                id += 1;
            }
        }
        for r in rows { list.append(r)?; }
        Ok(list.into())
    }

    /// (ts, wire_len, captured_bytes) for one ring packet id, or None if it has scrolled out.
    fn packet(&self, py: Python<'_>, id: u64) -> Option<(f64, u32, PyObject)> {
        let ring = self.sh.ring.lock().unwrap();
        ring.get(id).map(|p| (p.ts, p.wire, pyo3::types::PyBytes::new_bound(py, &p.data).into()))
    }
}

// ------------------------------------------------------------ PCAP file inspector
/// Random-access index over a classic pcap file: `len()`, `page()`, `packet()`.
/// Built once (one sequential pass, no packet bodies kept) so a 100 MB / 500k-packet
/// capture pages in milliseconds.
#[pyclass]
pub struct PcapIndex {
    path: String,
    offsets: Vec<u64>,   // file offset of each packet's 16-byte record header
    little_endian: bool,
    nanosecond: bool,
    linktype: u32,
    span: (f64, f64),
}

impl PcapIndex {
    fn rd32(&self, b: &[u8]) -> u32 {
        if self.little_endian { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) } else { u32::from_be_bytes([b[0], b[1], b[2], b[3]]) }
    }
    fn read_at(&self, f: &mut std::fs::File, i: usize) -> Option<(f64, u32, Vec<u8>)> {
        let off = *self.offsets.get(i)?;
        f.seek(SeekFrom::Start(off)).ok()?;
        let mut h = [0u8; 16];
        f.read_exact(&mut h).ok()?;
        let sec = self.rd32(&h[0..4]); let sub = self.rd32(&h[4..8]);
        let incl = self.rd32(&h[8..12]) as usize; let orig = self.rd32(&h[12..16]);
        if incl > 262_144 { return None; }
        let mut data = vec![0u8; incl];
        f.read_exact(&mut data).ok()?;
        let ts = sec as f64 + sub as f64 / if self.nanosecond { 1e9 } else { 1e6 };
        let mut arena = Vec::new();
        let n = append_ethernet(&mut arena, self.linktype as i32, &data);
        if n == 0 { return Some((ts, orig, data)); }
        Some((ts, orig, arena))
    }
}

#[pymethods]
impl PcapIndex {
    #[new]
    fn new(py: Python<'_>, path: String) -> PyResult<Self> {
        let p2 = path.clone();
        let built = py.allow_threads(move || -> Result<PcapIndex, String> {
            let mut f = std::io::BufReader::with_capacity(1 << 20, std::fs::File::open(&p2).map_err(|e| e.to_string())?);
            let mut hdr = [0u8; 24];
            f.read_exact(&mut hdr).map_err(|e| e.to_string())?;
            let magic = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
            let (le, nano) = match magic {
                0xa1b2c3d4 => (true, false), 0xd4c3b2a1 => (false, false),
                0xa1b23c4d => (true, true), 0x4d3cb2a1 => (false, true),
                _ => return Err("not a classic pcap (pcapng is not indexable)".into()),
            };
            let rd = |b: &[u8]| if le { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) } else { u32::from_be_bytes([b[0], b[1], b[2], b[3]]) };
            let linktype = rd(&hdr[20..24]);
            let mut offsets = Vec::new();
            let mut pos = 24u64;
            let (mut t0, mut t1) = (f64::MAX, 0f64);
            let mut h = [0u8; 16];
            loop {
                if f.read_exact(&mut h).is_err() { break; }
                let incl = rd(&h[8..12]) as u64;
                if incl > 262_144 { break; }
                let ts = rd(&h[0..4]) as f64 + rd(&h[4..8]) as f64 / if nano { 1e9 } else { 1e6 };
                if ts < t0 { t0 = ts; } if ts > t1 { t1 = ts; }
                offsets.push(pos);
                if f.seek_relative(incl as i64).is_err() { break; }
                pos += 16 + incl;
            }
            if t0 == f64::MAX { t0 = 0.0; }
            Ok(PcapIndex { path: p2, offsets, little_endian: le, nanosecond: nano, linktype, span: (t0, t1) })
        }).map_err(pyo3::exceptions::PyOSError::new_err)?;
        Ok(built)
    }

    fn __len__(&self) -> usize { self.offsets.len() }
    fn count(&self) -> usize { self.offsets.len() }
    fn linktype(&self) -> u32 { self.linktype }
    fn span(&self) -> (f64, f64) { self.span }
    fn path(&self) -> String { self.path.clone() }

    /// Up to `limit` summaries for packets with index >= `start` matching `filter`.
    /// Returns (rows, next_start) -- next_start == count() when the file is exhausted.
    #[pyo3(signature = (start=0, limit=200, filter=""))]
    fn page(&self, py: Python<'_>, start: usize, limit: usize, filter: &str) -> PyResult<(PyObject, usize)> {
        let terms = split_terms(filter);
        let mut f = std::fs::File::open(&self.path).map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))?;
        let list = PyList::empty_bound(py);
        let mut i = start;
        let mut found = 0usize;
        let scan_cap = if terms.is_empty() { limit } else { 3_000_000 };
        let mut scanned = 0usize;
        while i < self.offsets.len() && found < limit && scanned < scan_cap {
            scanned += 1;
            if let Some((ts, wire, data)) = self.read_at(&mut f, i) {
                let s = summarize(&data);
                if terms.is_empty() || matches_filter(&line_of(i as u64 + 1, &s), &terms) {
                    list.append(summary_dict(py, i as u64 + 1, ts, wire, &s)?)?;
                    found += 1;
                }
            }
            i += 1;
        }
        Ok((list.into(), i))
    }

    /// (ts, wire_len, ethernet-framed bytes) for packet number `n` (1-based, as in `page`).
    fn packet(&self, py: Python<'_>, n: usize) -> PyResult<Option<(f64, u32, PyObject)>> {
        if n == 0 { return Ok(None); }
        let mut f = std::fs::File::open(&self.path).map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))?;
        Ok(self.read_at(&mut f, n - 1).map(|(ts, w, d)| (ts, w, pyo3::types::PyBytes::new_bound(py, &d).into())))
    }
}
