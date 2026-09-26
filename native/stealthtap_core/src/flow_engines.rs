//! Whole-batch flow scoring, entirely in Rust.
//!
//! The five stateful flow engines (ENG-01 flood/slowloris/spoofed, ENG-02 beaconing, ENG-05 recon,
//! ENG-06 exfiltration, ENG-13 brute force) were already ported to native counters, but each flow
//! still crossed into Python (dict mapping, a coroutine per engine, an `Alert` object) just to be
//! told "no". Profiled on a real 565k-flow capture that per-flow Python path capped the whole
//! pipeline at ~28k flows/s. This runs the exact same cores over a batch of flow records with the
//! GIL released and returns only the rare HITS -- Python then builds the typed Alert for those
//! alone (`alert_from_native_hit` on each detector).
//!
//! Engine order and per-phase membership mirror src/capture/scoring.py:
//!   snapshot -> ENG-01, ENG-05, ENG-13
//!   expire   -> ENG-01, ENG-02, ENG-05, ENG-06, ENG-13

use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::eng01::{self, Eng01Hit, NativeEng01};
use crate::eng02::{self, Eng02Hit, NativeEng02};
use crate::eng05::{self, Eng05Hit, NativeEng05};
use crate::eng06::{self, Eng06Hit, NativeEng06};
use crate::eng13::{self, Eng13Hit, NativeEng13};
use crate::live::LiveConnRecord;

const PER_FLOW_RATIO_THRESHOLD: f64 = 20.0;

pub enum FlowHit {
    E01(Eng01Hit),
    E02(Eng02Hit),
    E05(Eng05Hit),
    E06Single { orig: f64, resp: f64, ratio: f64 },
    E06Acc(Eng06Hit),
    E13(Eng13Hit),
}

pub struct Hit {
    pub engine: &'static str,
    pub hit: FlowHit,
}

pub struct FlowEngines {
    e01: NativeEng01,
    e02: NativeEng02,
    e05: NativeEng05,
    e06: NativeEng06,
    e13: NativeEng13,
    single_flow_min_bytes: f64,
}

impl FlowEngines {
    pub fn new(single_flow_min_bytes: f64) -> Self {
        FlowEngines {
            e01: NativeEng01::new_core(),
            e02: NativeEng02::new_core(),
            e05: NativeEng05::new_core(),
            e06: NativeEng06::new_core(),
            e13: NativeEng13::new_core(),
            single_flow_min_bytes,
        }
    }

    /// Mid-flight snapshot of an active flow: only the rate/fan-out engines.
    pub fn snapshot(&mut self, r: &LiveConnRecord, out: &mut Vec<Hit>) {
        let total = (r.orig_bytes + r.resp_bytes) as f64;
        if let Some(h) = self.e01.check(&r.orig_h, &r.resp_h, r.ts, r.duration, total, r.resp_p) {
            out.push(Hit { engine: "eng01", hit: FlowHit::E01(h) });
        }
        if let Some(h) = self.e05.core(&r.orig_h, &r.resp_h, r.resp_p, r.ts, r.orig_bytes as f64, r.resp_bytes as f64) {
            out.push(Hit { engine: "eng05", hit: FlowHit::E05(h) });
        }
        if let Some(h) = self.e13.core(&r.orig_h, &r.resp_h, r.resp_p, r.ts) {
            out.push(Hit { engine: "eng13", hit: FlowHit::E13(h) });
        }
    }

    /// A flow that has ended: every conn-level engine.
    pub fn expire(&mut self, r: &LiveConnRecord, out: &mut Vec<Hit>) {
        let total = (r.orig_bytes + r.resp_bytes) as f64;
        if let Some(h) = self.e01.check(&r.orig_h, &r.resp_h, r.ts, r.duration, total, r.resp_p) {
            out.push(Hit { engine: "eng01", hit: FlowHit::E01(h) });
        }
        if let Some(h) = self.e02.core(&r.orig_h, &r.resp_h, r.ts) {
            out.push(Hit { engine: "eng02", hit: FlowHit::E02(h) });
        }
        if let Some(h) = self.e05.core(&r.orig_h, &r.resp_h, r.resp_p, r.ts, r.orig_bytes as f64, r.resp_bytes as f64) {
            out.push(Hit { engine: "eng05", hit: FlowHit::E05(h) });
        }
        // ENG-06: the per-flow check runs first and, when it fires, skips accumulation (as in Python)
        let (orig, resp) = (r.orig_bytes as f64, r.resp_bytes as f64);
        if resp > 0.0 && orig >= self.single_flow_min_bytes && orig / resp >= PER_FLOW_RATIO_THRESHOLD {
            out.push(Hit { engine: "eng06", hit: FlowHit::E06Single { orig, resp, ratio: orig / resp } });
        } else if let Some(h) = self.e06.core(&r.orig_h, &r.resp_h, r.ts, r.orig_bytes as i64, r.resp_bytes as i64) {
            out.push(Hit { engine: "eng06", hit: FlowHit::E06Acc(h) });
        }
        if let Some(h) = self.e13.core(&r.orig_h, &r.resp_h, r.resp_p, r.ts) {
            out.push(Hit { engine: "eng13", hit: FlowHit::E13(h) });
        }
    }
}

/// The dict Python's `alert_from_native_hit` consumes (shape depends on the engine; see each detector).
pub fn hit_to_py(py: Python<'_>, h: &Hit) -> PyResult<PyObject> {
    match &h.hit {
        FlowHit::E01(x) => eng01::hit_to_py(py, x),
        FlowHit::E02(x) => eng02::hit_to_py(py, x),
        FlowHit::E05(x) => eng05::hit_to_py(py, x),
        FlowHit::E13(x) => eng13::hit_to_py(py, x),
        FlowHit::E06Acc(x) => {
            let d = PyDict::new_bound(py);
            d.set_item("evidence", eng06::hit_to_py(py, x)?)?;
            Ok(d.into())
        }
        FlowHit::E06Single { orig, resp, ratio } => {
            let ev = PyDict::new_bound(py);
            ev.set_item("detection_type", "single_flow")?;
            ev.set_item("orig_bytes", orig)?;
            ev.set_item("resp_bytes", resp)?;
            ev.set_item("ratio", (ratio * 10.0).round() / 10.0)?;
            let d = PyDict::new_bound(py);
            d.set_item("single", true)?;
            d.set_item("evidence", ev)?;
            Ok(d.into())
        }
    }
}
