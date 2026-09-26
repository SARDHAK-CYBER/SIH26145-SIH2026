//! Native fast-path for ENG-01 (Volumetric DDoS / Slowloris / spoofed-flood).
//!
//! This is NOT a reimplementation of the detection logic -- it is the
//! EXACT same thresholds and formulas as src/engines/eng01_ddos.py,
//! moved from Python+Redis-round-trips into a native, in-process,
//! EXACT (not approximate) counter. src/memstore.py's CMS.INCRBY and
//! PFADD/PFCOUNT are already exact (real dict/set, not a sketch), so
//! matching them with plain HashMap/HashSet here is not an accuracy
//! downgrade -- it is what the default (Redis-less) deployment already
//! does today, just without the per-flow Python/Redis round-trip cost
//! that profiling identified as this engine's dominant expense.
//!
//! Python still builds the final typed Alert (MITRE mapping, Pydantic
//! validation) -- this only replaces the per-flow counting/threshold
//! check that runs on EVERY flow, returning a hit tuple on the rare
//! positive. See src/engines/eng01_ddos.py for the reference this must
//! stay byte-for-byte equivalent to, and
//! scripts/validate_native_eng01.py for the validation harness.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::{HashMap, HashSet};

const WINDOW_SECONDS: f64 = 10.0;
const FLOOD_THRESHOLD: u32 = 200;
const MIN_FLOOD_CONCENTRATION_RATIO: f64 = 8.0;
const SPOOFED_MIN_PACKETS: u32 = 150;
const SPOOFED_UNIQUENESS_RATIO: f64 = 0.85;
const SLOWLORIS_DURATION_S: f64 = 120.0;
const SLOWLORIS_MAX_BYTES: f64 = 50.0;

/// Slowloris holds HTTP connections open. Idle long-lived connections on other services are normal (push channels 5228/5223,
/// Windows Delivery Optimization 7680, SSH/RDP/VNC/MQTT sessions...), and flagging them was the top false positive on a real
/// 20-minute Wi-Fi capture. Port 0 = unknown (unit tests / sources without ports) keeps the old behaviour.
pub const SLOWLORIS_PORTS: [u16; 13] = [80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090];
pub fn slowloris_port(p: u16) -> bool { p == 0 || SLOWLORIS_PORTS.contains(&p) }
// How many old buckets to retain before sweeping -- generous margin
// above BUCKET_TTL_SECONDS/WINDOW_SECONDS=3 buckets, so a flow whose
// conn record arrives slightly late (snapshot/expire jitter) still
// finds its bucket's state intact, matching Redis EX's forgiving
// wall-clock (not bucket-count) expiry.
const KEEP_BUCKETS_BACK: i64 = 6;

fn bucket_of(ts: f64) -> i64 {
    (ts / WINDOW_SECONDS).floor() as i64
}

#[derive(Default)]
struct SrcBucket {
    flow_count: u32,
    dsts: HashSet<String>,
    flood_alerted: bool,
}

#[derive(Default)]
struct DstBucket {
    pkt_count: u32,
    srcs: HashSet<String>,
    spoofed_alerted: bool,
}

pub enum Eng01Hit {
    Slowloris { duration_s: f64, bytes_total: f64 },
    Flood { count: u32, distinct_destinations: u32, concentration_ratio: f64 },
    Spoofed { packets_to_destination: u32, distinct_source_ips: u32, uniqueness_ratio: f64 },
}

#[pyclass]
pub struct NativeEng01 {
    src: HashMap<(String, i64), SrcBucket>,
    dst: HashMap<(String, i64), DstBucket>,
    max_bucket_seen: i64,
}

impl NativeEng01 {
    fn sweep_if_needed(&mut self, bucket: i64) {
        if bucket <= self.max_bucket_seen {
            return;
        }
        self.max_bucket_seen = bucket;
        let cutoff = bucket - KEEP_BUCKETS_BACK;
        self.src.retain(|(_, b), _| *b >= cutoff);
        self.dst.retain(|(_, b), _| *b >= cutoff);
    }

    /// Mirrors VolumetricDDoSDetector.score()'s exact control flow and
    /// ordering: counters increment unconditionally first, then
    /// slowloris (stateless) is checked, then flood (using the
    /// counters just updated), then -- ONLY if flood didn't already
    /// fire -- the spoofed-destination counters update and get
    /// checked. Same early-return order as the Python reference.
    pub fn check(&mut self, src_ip: &str, dst_ip: &str, ts: f64, duration_s: f64, bytes_total: f64, dst_port: u16) -> Option<Eng01Hit> {
        let bucket = bucket_of(ts);
        self.sweep_if_needed(bucket);

        let src_key = (src_ip.to_string(), bucket);
        let sb = self.src.entry(src_key.clone()).or_default();
        sb.flow_count += 1;
        sb.dsts.insert(dst_ip.to_string());
        let count = sb.flow_count;
        let distinct_dests = sb.dsts.len() as u32;
        let already_flood_alerted = sb.flood_alerted;

        if duration_s > SLOWLORIS_DURATION_S && bytes_total < SLOWLORIS_MAX_BYTES && slowloris_port(dst_port) {
            return Some(Eng01Hit::Slowloris { duration_s, bytes_total });
        }

        if count >= FLOOD_THRESHOLD {
            let concentration = count as f64 / distinct_dests.max(1) as f64;
            if concentration >= MIN_FLOOD_CONCENTRATION_RATIO {
                if !already_flood_alerted {
                    self.src.get_mut(&src_key).unwrap().flood_alerted = true;
                    return Some(Eng01Hit::Flood { count, distinct_destinations: distinct_dests, concentration_ratio: concentration });
                }
                // Already alerted this (src, window): matches the
                // Python reference exactly -- it does NOT return here
                // either, it falls through to the spoofed-destination
                // check below (a scattered-vs-concentrated flood and a
                // spoofed-source flood are independent signals, so one
                // being deduplicated doesn't suppress the other).
            }
        }

        // many sources -> one multicast/broadcast group is what mDNS/SSDP/LLMNR look like, not a spoofed flood
        if crate::eng02::is_multicast_or_broadcast(dst_ip) { return None; }
        let dst_key = (dst_ip.to_string(), bucket);
        let db = self.dst.entry(dst_key.clone()).or_default();
        db.pkt_count += 1;
        db.srcs.insert(src_ip.to_string());
        let pkt_count = db.pkt_count;
        if pkt_count < SPOOFED_MIN_PACKETS {
            return None;
        }
        let distinct_sources = db.srcs.len() as u32;
        let uniqueness_ratio = distinct_sources as f64 / pkt_count as f64;
        if uniqueness_ratio >= SPOOFED_UNIQUENESS_RATIO {
            let already = self.dst.get(&dst_key).unwrap().spoofed_alerted;
            if !already {
                self.dst.get_mut(&dst_key).unwrap().spoofed_alerted = true;
                return Some(Eng01Hit::Spoofed { packets_to_destination: pkt_count, distinct_source_ips: distinct_sources, uniqueness_ratio });
            }
        }
        None
    }
}

#[pymethods]
impl NativeEng01 {
    #[new]
    fn new() -> Self {
        NativeEng01 { src: HashMap::new(), dst: HashMap::new(), max_bucket_seen: i64::MIN }
    }

    #[pyo3(name = "check", signature = (src_ip, dst_ip, ts, duration_s, bytes_total, dst_port=0))]
    fn py_check(&mut self, py: Python<'_>, src_ip: &str, dst_ip: &str, ts: f64, duration_s: f64, bytes_total: f64, dst_port: u16) -> PyResult<Option<PyObject>> {
        match self.check(src_ip, dst_ip, ts, duration_s, bytes_total, dst_port) {
            Some(hit) => Ok(Some(hit_to_py(py, &hit)?)),
            None => Ok(None),
        }
    }

    fn active_buckets(&self) -> usize {
        self.src.len() + self.dst.len()
    }
}

impl NativeEng01 {
    pub fn new_core() -> Self {
        NativeEng01 { src: HashMap::new(), dst: HashMap::new(), max_bucket_seen: i64::MIN }
    }
}

/// Same dict shape the Python detector consumes ({threat_class, confidence, evidence}).
pub fn hit_to_py(py: Python<'_>, hit: &Eng01Hit) -> PyResult<PyObject> {
    let evidence = PyDict::new_bound(py);
    let (threat_class, confidence): (&str, f64) = match hit {
        Eng01Hit::Slowloris { duration_s, bytes_total } => {
            evidence.set_item("duration_s", duration_s)?;
            evidence.set_item("bytes_total", bytes_total)?;
            ("SLOWLORIS", 85.0)
        }
        Eng01Hit::Flood { count, distinct_destinations, concentration_ratio } => {
            evidence.set_item("src_ip_flow_count", count)?;
            evidence.set_item("distinct_destinations", distinct_destinations)?;
            evidence.set_item("concentration_ratio", (concentration_ratio * 10.0).round() / 10.0)?;
            evidence.set_item("window_seconds", WINDOW_SECONDS)?;
            evidence.set_item("threshold", FLOOD_THRESHOLD)?;
            ("VOLUMETRIC_DDOS", (60.0 + (*count as f64 - FLOOD_THRESHOLD as f64) * 0.5).min(99.0))
        }
        Eng01Hit::Spoofed { packets_to_destination, distinct_source_ips, uniqueness_ratio } => {
            evidence.set_item("packets_to_destination", packets_to_destination)?;
            evidence.set_item("distinct_source_ips_estimate", distinct_source_ips)?;
            evidence.set_item("uniqueness_ratio", (uniqueness_ratio * 1000.0).round() / 1000.0)?;
            evidence.set_item("window_seconds", WINDOW_SECONDS)?;
            evidence.set_item("spoofed_source_pattern", true)?;
            ("VOLUMETRIC_DDOS", 92.0)
        }
    };
    let out = PyDict::new_bound(py);
    out.set_item("threat_class", threat_class)?;
    out.set_item("confidence", confidence)?;
    out.set_item("evidence", evidence)?;
    Ok(out.into())
}
