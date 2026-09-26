//! Native fast-path for ENG-06's ACCUMULATED (low-and-slow) exfiltration
//! check only -- the per-flow check in eng06_exfiltration.py is already
//! stateless (pure arithmetic on one flow's own bytes) and needs no
//! native acceleration (flow_engines.rs re-implements it, with the same
//! constants, so a whole batch of flows can be evaluated without Python).
//! Exact port of _check_accumulated's thresholds.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::HashMap;

const ACCUMULATION_WINDOW_SECONDS: f64 = 300.0;
const ACCUMULATED_RATIO_THRESHOLD: f64 = 10.0;
const MIN_ACCUMULATED_OUTBOUND_BYTES: i64 = 500_000;
const MIN_ACCUMULATED_FLOWS: u32 = 5;   // low-and-slow = many flows (see eng06_exfiltration.py)
const KEEP_BUCKETS_BACK: i64 = 3;

fn bucket_of(ts: f64) -> i64 {
    (ts / ACCUMULATION_WINDOW_SECONDS).floor() as i64
}

#[derive(Default)]
struct Accum {
    orig_bytes: i64,
    resp_bytes: i64,
    flow_count: u32,
}

#[pyclass]
pub struct NativeEng06 {
    state: HashMap<(String, String, i64), Accum>,
    max_bucket_seen: i64,
}

pub struct Eng06Hit {
    pub cum_orig: i64,
    pub cum_resp: i64,
    pub ratio: f64,
    pub flows: u32,
}

impl NativeEng06 {
    pub fn new_core() -> Self {
        NativeEng06 { state: HashMap::new(), max_bucket_seen: i64::MIN }
    }

    pub fn core(&mut self, src_ip: &str, dst_ip: &str, ts: f64, orig_bytes: i64, resp_bytes: i64) -> Option<Eng06Hit> {
        let bucket = bucket_of(ts);
        if bucket > self.max_bucket_seen {
            self.max_bucket_seen = bucket;
            let cutoff = bucket - KEEP_BUCKETS_BACK;
            self.state.retain(|(_, _, b), _| *b >= cutoff);
        }

        let key = (src_ip.to_string(), dst_ip.to_string(), bucket);
        let a = self.state.entry(key).or_default();
        a.orig_bytes += orig_bytes;
        a.resp_bytes += resp_bytes;
        a.flow_count += 1;
        let (cumulative_orig, cumulative_resp, flow_count) = (a.orig_bytes, a.resp_bytes, a.flow_count);

        if cumulative_orig < MIN_ACCUMULATED_OUTBOUND_BYTES || flow_count < MIN_ACCUMULATED_FLOWS {
            return None;
        }
        if cumulative_resp <= 0 {
            return None;
        }
        let cumulative_ratio = cumulative_orig as f64 / cumulative_resp as f64;
        if cumulative_ratio < ACCUMULATED_RATIO_THRESHOLD {
            return None;
        }
        Some(Eng06Hit { cum_orig: cumulative_orig, cum_resp: cumulative_resp, ratio: cumulative_ratio, flows: flow_count })
    }
}

pub fn hit_to_py(py: Python<'_>, h: &Eng06Hit) -> PyResult<PyObject> {
    let evidence = PyDict::new_bound(py);
    evidence.set_item("detection_type", "accumulated_low_and_slow")?;
    evidence.set_item("cumulative_orig_bytes", h.cum_orig)?;
    evidence.set_item("cumulative_resp_bytes", h.cum_resp)?;
    evidence.set_item("cumulative_ratio", (h.ratio * 10.0).round() / 10.0)?;
    evidence.set_item("contributing_flow_count", h.flows)?;
    evidence.set_item("window_seconds", ACCUMULATION_WINDOW_SECONDS)?;
    Ok(evidence.into())
}

#[pymethods]
impl NativeEng06 {
    #[new]
    fn new() -> Self {
        NativeEng06::new_core()
    }

    fn check_accumulated(&mut self, py: Python<'_>, src_ip: &str, dst_ip: &str, ts: f64, orig_bytes: i64, resp_bytes: i64) -> PyResult<Option<PyObject>> {
        match self.core(src_ip, dst_ip, ts, orig_bytes, resp_bytes) {
            Some(h) => Ok(Some(hit_to_py(py, &h)?)),
            None => Ok(None),
        }
    }
}
