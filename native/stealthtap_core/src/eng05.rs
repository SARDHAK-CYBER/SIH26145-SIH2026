//! Native fast-path for ENG-05 (reconnaissance / fan-out detection).
//! Exact port of src/engines/eng05_recon.py -- same WINDOW_SECONDS/
//! FANOUT_THRESHOLD/PROBE_MAX_ORIG_BYTES/excluded-ports, same
//! probe-gated deferral this session already added to the Python
//! reference (a non-probe flow can only shrink the fan-out count, so
//! it's skipped here too, same reasoning). No Redis dependency in the
//! reference either -- this was already pure in-process Python state,
//! now moved to Rust for the same per-flow-cost reason as ENG-01/02/06/13.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::{HashMap, HashSet};

const WINDOW_SECONDS: f64 = 300.0;
const FANOUT_THRESHOLD: usize = 25;
const PROBE_MAX_ORIG_BYTES: f64 = 512.0;
const PRUNE_EVERY: u32 = 5000;
const EXCLUDED_FANOUT_PORTS: [u16; 1] = [7680];

#[pyclass]
pub struct NativeEng05 {
    seen: HashMap<String, Vec<(f64, String, u16)>>,
    since_prune: u32,
}

pub struct Eng05Hit {
    pub distinct_targets: usize,
    pub confidence: f64,
}

impl NativeEng05 {
    pub fn new_core() -> Self {
        NativeEng05 { seen: HashMap::new(), since_prune: 0 }
    }

    pub fn core(&mut self, src_ip: &str, dst_ip: &str, dst_port: u16, ts: f64, orig_bytes: f64, resp_bytes: f64) -> Option<Eng05Hit> {
        if EXCLUDED_FANOUT_PORTS.contains(&dst_port) {
            return None;
        }
        let is_probe = resp_bytes == 0.0 && orig_bytes <= PROBE_MAX_ORIG_BYTES;

        self.since_prune += 1;
        if self.since_prune >= PRUNE_EVERY {
            self.since_prune = 0;
            let cutoff = ts - WINDOW_SECONDS;
            self.seen.retain(|_, entries| {
                entries.last().map(|(t, _, _)| *t >= cutoff).unwrap_or(false)
            });
        }

        if !is_probe {
            return None;
        }

        let entries = self.seen.entry(src_ip.to_string()).or_default();
        entries.push((ts, dst_ip.to_string(), dst_port));
        let cutoff = ts - WINDOW_SECONDS;
        entries.retain(|(t, _, _)| *t >= cutoff);

        let distinct: HashSet<(&str, u16)> = entries.iter().map(|(_, d, p)| (d.as_str(), *p)).collect();
        let count = distinct.len();
        if count >= FANOUT_THRESHOLD {
            let confidence = (50.0 + count as f64).min(95.0);
            self.seen.remove(src_ip);
            return Some(Eng05Hit { distinct_targets: count, confidence });
        }
        None
    }
}

pub fn hit_to_py(py: Python<'_>, h: &Eng05Hit) -> PyResult<PyObject> {
    let out = PyDict::new_bound(py);
    out.set_item("distinct_targets", h.distinct_targets)?;
    out.set_item("confidence", h.confidence)?;
    Ok(out.into())
}

#[pymethods]
impl NativeEng05 {
    #[new]
    fn new() -> Self {
        NativeEng05::new_core()
    }

    fn check(&mut self, py: Python<'_>, src_ip: &str, dst_ip: &str, dst_port: u16, ts: f64, orig_bytes: f64, resp_bytes: f64) -> PyResult<Option<PyObject>> {
        match self.core(src_ip, dst_ip, dst_port, ts, orig_bytes, resp_bytes) {
            Some(h) => Ok(Some(hit_to_py(py, &h)?)),
            None => Ok(None),
        }
    }
}
