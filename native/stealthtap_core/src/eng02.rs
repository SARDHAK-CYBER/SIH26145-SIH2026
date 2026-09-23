//! Native fast-path for ENG-02 (C2 beaconing via inter-arrival CV).
//! Exact port of src/engines/eng02_c2_beaconing.py -- same constants,
//! same statistics, same evidence fields. Python still builds the
//! Alert. No dedup here, matching the reference (this engine relies on
//! LiveAgent._emit's cooldown, not its own dedup key).

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

#[pymethods]
impl NativeEng02 {
    #[new]
    fn new() -> Self {
        NativeEng02 { history: HashMap::new(), since_prune: 0 }
    }

    fn check(&mut self, py: Python<'_>, src_ip: &str, dst_ip: &str, ts: f64) -> PyResult<Option<PyObject>> {
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
            return Ok(None);
        }

        let mean_interval = mean(&deltas);
        if !(MIN_INTERVAL_SECONDS <= mean_interval && mean_interval <= MAX_INTERVAL_SECONDS) {
            return Ok(None);
        }

        let sd = stddev(&deltas, mean_interval);
        let cv = if mean_interval > 0.0 { sd / mean_interval } else { f64::INFINITY };
        if cv > CV_CEILING {
            return Ok(None);
        }

        let median_interval = median(&deltas);
        let tolerance = median_interval * CV_CEILING;
        let near_median = deltas.iter().filter(|d| (*d - median_interval).abs() <= tolerance).count();
        let clustering_ratio = near_median as f64 / deltas.len() as f64;
        if clustering_ratio < 0.75 {
            return Ok(None);
        }

        let confidence = 95.0 - (cv / CV_CEILING) * 25.0;

        let evidence = PyDict::new_bound(py);
        evidence.set_item("coefficient_of_variation", round_to(cv, 3))?;
        evidence.set_item("mean_interval_seconds", round_to(mean_interval, 2))?;
        evidence.set_item("sample_count", deltas.len())?;
        evidence.set_item("estimated_jitter_percent", round_to(cv * 3f64.sqrt() * 100.0, 1))?;
        evidence.set_item("clustering_ratio", round_to(clustering_ratio, 3))?;

        let out = PyDict::new_bound(py);
        out.set_item("confidence", round_to(confidence, 1))?;
        out.set_item("evidence", evidence)?;
        Ok(Some(out.into()))
    }
}
