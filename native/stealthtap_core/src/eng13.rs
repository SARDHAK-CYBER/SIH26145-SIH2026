//! Native fast-path for ENG-13 (brute-force / credential-attack detection).
//! Exact port of src/engines/eng13_bruteforce.py's thresholds and control
//! flow -- see that file for the full rationale. Counting only; Python
//! still builds the final Alert. See eng01.rs's module doc for why an
//! exact HashMap/HashSet here is not an accuracy downgrade from the
//! default (Redis-less) deployment.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::{HashMap, HashSet};

const WINDOW_SECONDS: f64 = 60.0;
const ATTEMPT_THRESHOLD: u32 = 10;
const KEEP_BUCKETS_BACK: i64 = 4;
const AUTH_PORTS: [u16; 10] = [21, 22, 23, 25, 110, 143, 993, 995, 3389, 5900];

fn bucket_of(ts: f64) -> i64 {
    (ts / WINDOW_SECONDS).floor() as i64
}

type Key = (String, String, u16, i64);

#[pyclass]
pub struct NativeEng13 {
    attempts: HashMap<Key, u32>,
    alerted: HashSet<Key>,
    max_bucket_seen: i64,
}

pub struct Eng13Hit {
    pub confidence: f64,
    pub count: u32,
    pub dst_port: u16,
}

impl NativeEng13 {
    pub fn new_core() -> Self {
        NativeEng13 { attempts: HashMap::new(), alerted: HashSet::new(), max_bucket_seen: i64::MIN }
    }

    pub fn core(&mut self, src_ip: &str, dst_ip: &str, dst_port: u16, ts: f64) -> Option<Eng13Hit> {
        if !AUTH_PORTS.contains(&dst_port) {
            return None;
        }
        let bucket = bucket_of(ts);
        if bucket > self.max_bucket_seen {
            self.max_bucket_seen = bucket;
            let cutoff = bucket - KEEP_BUCKETS_BACK;
            self.attempts.retain(|(_, _, _, b), _| *b >= cutoff);
            self.alerted.retain(|(_, _, _, b)| *b >= cutoff);
        }

        let key: Key = (src_ip.to_string(), dst_ip.to_string(), dst_port, bucket);
        let count = {
            let c = self.attempts.entry(key.clone()).or_insert(0);
            *c += 1;
            *c
        };
        if count < ATTEMPT_THRESHOLD {
            return None;
        }
        if self.alerted.contains(&key) {
            return None;
        }
        self.alerted.insert(key);

        let confidence = (70.0 + (count as f64 - ATTEMPT_THRESHOLD as f64) * 0.5).min(97.0);
        Some(Eng13Hit { confidence: (confidence * 10.0).round() / 10.0, count, dst_port })
    }
}

pub fn hit_to_py(py: Python<'_>, h: &Eng13Hit) -> PyResult<PyObject> {
    let evidence = PyDict::new_bound(py);
    evidence.set_item("connection_attempts", h.count)?;
    evidence.set_item("window_seconds", WINDOW_SECONDS)?;
    evidence.set_item("target_port", h.dst_port)?;
    evidence.set_item("threshold", ATTEMPT_THRESHOLD)?;

    let out = PyDict::new_bound(py);
    out.set_item("confidence", h.confidence)?;
    out.set_item("evidence", evidence)?;
    Ok(out.into())
}

#[pymethods]
impl NativeEng13 {
    #[new]
    fn new() -> Self {
        NativeEng13::new_core()
    }

    /// Returns None, or a dict with confidence/evidence ready for
    /// Python to build the Alert, mirroring BruteForceDetector.score().
    fn check(&mut self, py: Python<'_>, src_ip: &str, dst_ip: &str, dst_port: u16, ts: f64) -> PyResult<Option<PyObject>> {
        match self.core(src_ip, dst_ip, dst_port, ts) {
            Some(h) => Ok(Some(hit_to_py(py, &h)?)),
            None => Ok(None),
        }
    }
}
