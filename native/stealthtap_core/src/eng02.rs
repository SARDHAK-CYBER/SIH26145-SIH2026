//! Native fast-path for ENG-02 (C2 beaconing via inter-arrival CV).
//! Exact port of src/engines/eng02_c2_beaconing.py -- same constants,
//! same statistics, same evidence fields. Python still builds the
//! Alert. No dedup here, matching the reference (this engine relies on
//! LiveAgent._emit's cooldown, not its own dedup key).
//!
//! `core()` is the pure-Rust check (used by flow_engines.rs so whole batches of
//! flows are evaluated without touching Python); `check()` is the same thing
//! behind the original PyO3 API.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::HashMap;

const MAX_TRACKED_TIMESTAMPS: usize = 50;
const TIMESTAMP_TTL_SECONDS: f64 = 3600.0;
const MIN_SAMPLES: usize = 8;
const CV_CEILING: f64 = 0.55;
const MIN_INTERVAL_SECONDS: f64 = 2.0;
const MAX_INTERVAL_SECONDS: f64 = 3600.0;
const PRUNE_EVERY: u32 = 5000;

/// Periodic multicast/broadcast (LLMNR, mDNS, SSDP, NTP-multicast, DHCP, IPv6 neighbour discovery) is protocol
/// housekeeping, never a C2 channel: real Wi-Fi capture flagged a neighbour's LLMNR queries to 224.0.0.252.
pub fn is_multicast_or_broadcast(ip: &str) -> bool {
    if ip == "255.255.255.255" || ip.starts_with("ff") || ip.starts_with("FF") { return ip.contains(':') || ip == "255.255.255.255"; }
    match ip.split('.').next().and_then(|o| o.parse::<u8>().ok()) { Some(o) => (224..=239).contains(&o), None => false }
}

fn mean(v: &[f64]) -> f64 {
    if v.is_empty() { 0.0 } else { v.iter().sum::<f64>() / v.len() as f64 }
}

fn median(v: &[f64]) -> f64 {
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = s.len();
    if n == 0 { return 0.0; }
    if n % 2 == 1 { s[n / 2] } else { (s[n / 2 - 1] + s[n / 2]) / 2.0 }
}

fn stddev(v: &[f64], m: f64) -> f64 {
    if v.len() < 2 { return 0.0; }
    let variance = v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / v.len() as f64;
    variance.sqrt()
}

fn round_to(x: f64, places: i32) -> f64 {
    let mul = 10f64.powi(places);
    (x * mul).round() / mul
}

#[pyclass]
pub struct NativeEng02 {
    // (src_ip, dst_ip) -> (last MAX_TRACKED_TIMESTAMPS timestamps, last_ts seen)
    history: HashMap<(String, String), (Vec<f64>, f64)>,
    since_prune: u32,
}

pub struct Eng02Hit {
    pub confidence: f64,
    pub cv: f64,
    pub mean_interval: f64,
    pub sample_count: usize,
    pub clustering_ratio: f64,
}

impl NativeEng02 {
    pub fn new_core() -> Self {
        NativeEng02 { history: HashMap::new(), since_prune: 0 }
    }

    pub fn core(&mut self, src_ip: &str, dst_ip: &str, ts: f64) -> Option<Eng02Hit> {
        if is_multicast_or_broadcast(dst_ip) || is_multicast_or_broadcast(src_ip) { return None; }
        self.since_prune += 1;
        if self.since_prune >= PRUNE_EVERY {
            self.since_prune = 0;
            self.history.retain(|_, (_, last_ts)| ts - *last_ts < TIMESTAMP_TTL_SECONDS);
        }

        let key = (src_ip.to_string(), dst_ip.to_string());
        let entry = self.history.entry(key).or_insert_with(|| (Vec::new(), ts));
        entry.0.push(ts);
        if entry.0.len() > MAX_TRACKED_TIMESTAMPS {
            let drop = entry.0.len() - MAX_TRACKED_TIMESTAMPS;
            entry.0.drain(0..drop);
        }
        entry.1 = ts;

        // MIN_SAMPLES deltas need at least MIN_SAMPLES+1 timestamps: cheap early-out
        if entry.0.len() <= MIN_SAMPLES {
            return None;
        }
        let mut timestamps = entry.0.clone();
        timestamps.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let mut deltas: Vec<f64> = Vec::with_capacity(timestamps.len());
        for w in timestamps.windows(2) {
            let d = w[1] - w[0];
            if d > 0.0 {
                deltas.push(d);
            }
        }
        if deltas.len() < MIN_SAMPLES {
            return None;
        }

        let mean_interval = mean(&deltas);
        if !(MIN_INTERVAL_SECONDS <= mean_interval && mean_interval <= MAX_INTERVAL_SECONDS) {
            return None;
        }

        let sd = stddev(&deltas, mean_interval);
        let cv = if mean_interval > 0.0 { sd / mean_interval } else { f64::INFINITY };
        if cv > CV_CEILING {
            return None;
        }

        let median_interval = median(&deltas);
        let tolerance = median_interval * CV_CEILING;
        let near_median = deltas.iter().filter(|d| (*d - median_interval).abs() <= tolerance).count();
        let clustering_ratio = near_median as f64 / deltas.len() as f64;
        if clustering_ratio < 0.75 {
            return None;
        }

        let confidence = 95.0 - (cv / CV_CEILING) * 25.0;
        Some(Eng02Hit { confidence, cv, mean_interval, sample_count: deltas.len(), clustering_ratio })
    }
}

pub fn hit_to_py(py: Python<'_>, h: &Eng02Hit) -> PyResult<PyObject> {
    let evidence = PyDict::new_bound(py);
    evidence.set_item("coefficient_of_variation", round_to(h.cv, 3))?;
    evidence.set_item("mean_interval_seconds", round_to(h.mean_interval, 2))?;
    evidence.set_item("sample_count", h.sample_count)?;
    evidence.set_item("estimated_jitter_percent", round_to(h.cv * 3f64.sqrt() * 100.0, 1))?;
    evidence.set_item("clustering_ratio", round_to(h.clustering_ratio, 3))?;

    let out = PyDict::new_bound(py);
    out.set_item("confidence", round_to(h.confidence, 1))?;
    out.set_item("evidence", evidence)?;
    Ok(out.into())
}

#[pymethods]
impl NativeEng02 {
    #[new]
    fn new() -> Self {
        NativeEng02::new_core()
    }

    fn check(&mut self, py: Python<'_>, src_ip: &str, dst_ip: &str, ts: f64) -> PyResult<Option<PyObject>> {
        match self.core(src_ip, dst_ip, ts) {
            Some(h) => Ok(Some(hit_to_py(py, &h)?)),
            None => Ok(None),
        }
    }
}
