//! PyO3 bindings -- the only thing Python imports from this crate.
//!
//! Scope of this first phase, deliberately: classic-pcap parsing into
//! `conn` (TCP/UDP flow) and `dns` (query) records, matching pcap_parser.py's
//! output shape exactly so it's a drop-in accelerator for the SAME engines,
//! not a new detection path to re-validate from scratch. `ssl`/`modbus`
//! are returned empty here -- the Python fallback still runs for those
//! until a later phase ports JA4 and the OT byte-parsers natively. pcapng
//! files are not yet supported (returns a clear error, not a silent
//! wrong answer) -- see native/README.md.

#[cfg(all(target_os = "linux", feature = "afxdp"))]
mod afxdp;
mod capture;
mod eng01;
mod eng02;
mod eng05;
mod eng06;
mod eng13;
mod flow_engines;
mod inventory;
mod ja4;
mod krb;
mod live;
mod parse;
mod pcap;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use eng01::NativeEng01;
use eng02::NativeEng02;
use eng05::NativeEng05;
use eng06::NativeEng06;
use eng13::NativeEng13;
use live::Immediate;

#[pyfunction]
#[pyo3(signature = (path, max_packets=None))]
fn parse_pcap(py: Python<'_>, path: &str, max_packets: Option<usize>) -> PyResult<PyObject> {
    let reader = pcap::PcapReader::open(path)
        .map_err(|e| pyo3::exceptions::PyOSError::new_err(format!("{e}")))?;
    let linktype = reader.linktype;

    let packets = PacketIter { reader };
    let result = py.allow_threads(|| parse::parse_packets(linktype, packets, max_packets));

    let out = PyDict::new_bound(py);

    let conn_list = PyList::empty_bound(py);
    for r in &result.conn {
        let d = PyDict::new_bound(py);
        d.set_item("uid", &r.uid)?;
        d.set_item("ts", r.ts)?;
        d.set_item("id.orig_h", &r.orig_h)?;
        d.set_item("id.orig_p", r.orig_p)?;
        d.set_item("id.resp_h", &r.resp_h)?;
        d.set_item("id.resp_p", r.resp_p)?;
        d.set_item("proto", r.proto)?;
        d.set_item("duration", r.duration)?;
        d.set_item("orig_bytes", r.orig_bytes)?;
        d.set_item("resp_bytes", r.resp_bytes)?;
        d.set_item("orig_pkts", r.orig_pkts)?;
        d.set_item("resp_pkts", r.resp_pkts)?;
        conn_list.append(d)?;
    }
    out.set_item("conn", conn_list)?;

    let dns_list = PyList::empty_bound(py);
    for r in &result.dns {
        let d = PyDict::new_bound(py);
        d.set_item("uid", &r.uid)?;
        d.set_item("ts", r.ts)?;
        d.set_item("id.orig_h", &r.orig_h)?;
        d.set_item("id.orig_p", r.orig_p)?;
        d.set_item("id.resp_h", &r.resp_h)?;
        d.set_item("id.resp_p", r.resp_p)?;
        d.set_item("proto", r.proto)?;
        d.set_item("query", &r.query)?;
        d.set_item("qtype_name", &r.qtype_name)?;
        dns_list.append(d)?;
    }
    out.set_item("dns", dns_list)?;

    out.set_item("ssl", PyList::empty_bound(py))?;      // not yet native -- Python fallback covers it
    out.set_item("modbus", PyList::empty_bound(py))?;   // not yet native -- Python fallback covers it

    Ok(out.into())
}

struct PacketIter {
    reader: pcap::PcapReader,
}

impl Iterator for PacketIter {
    type Item = (f64, Vec<u8>);
    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.next_packet() {
            Ok(Some(p)) => Some((p.ts, p.data)),
            _ => None,
        }
    }
}

pub(crate) fn live_conn_to_dict(py: Python<'_>, r: &live::LiveConnRecord) -> PyResult<PyObject> {
    let d = PyDict::new_bound(py);
    d.set_item("uid", &r.uid)?;
    d.set_item("ts", r.ts)?;
    d.set_item("id.orig_h", &r.orig_h)?;
    d.set_item("id.orig_p", r.orig_p)?;
    d.set_item("id.resp_h", &r.resp_h)?;
    d.set_item("id.resp_p", r.resp_p)?;
    d.set_item("proto", r.proto)?;
    d.set_item("duration", r.duration)?;
    d.set_item("orig_bytes", r.orig_bytes)?;
    d.set_item("resp_bytes", r.resp_bytes)?;
    d.set_item("orig_pkts", r.orig_pkts)?;
    d.set_item("resp_pkts", r.resp_pkts)?;
    d.set_item("segment_hash", &r.segment_hash)?;
    if let Some(sts) = r.snapshot_ts { d.set_item("_snapshot_ts", sts)?; }
    Ok(d.into())
}


/// One immediately-emitted record (dns/ssl/modbus/dnp3/http) as (log_type, dict) -- the single
/// place this mapping lives, shared by LiveFlowAssembler.process() and NativeCapture.poll().
pub(crate) fn immediate_to_dict<'py>(py: Python<'py>, rec: &Immediate) -> PyResult<(&'static str, Bound<'py, PyDict>)> {
    let d = PyDict::new_bound(py);
    let base = |d: &Bound<'py, PyDict>, uid: &str, ts: f64, oh: &str, op: u16, rh: &str, rp: u16| -> PyResult<()> {
        d.set_item("uid", uid)?; d.set_item("ts", ts)?;
        d.set_item("id.orig_h", oh)?; d.set_item("id.orig_p", op)?;
        d.set_item("id.resp_h", rh)?; d.set_item("id.resp_p", rp)?;
        Ok(())
    };
    let lt = match rec {
        Immediate::Dns(r) => {
            base(&d, &r.uid, r.ts, &r.orig_h, r.orig_p, &r.resp_h, r.resp_p)?;
            d.set_item("proto", r.proto)?; d.set_item("query", &r.query)?;
            d.set_item("qtype_name", &r.qtype_name)?; d.set_item("segment_hash", &r.segment_hash)?;
            "dns"
        }
        Immediate::Ssl(r) => {
            base(&d, &r.uid, r.ts, &r.orig_h, r.orig_p, &r.resp_h, r.resp_p)?;
            d.set_item("proto", r.proto)?; d.set_item("ja4", &r.ja4)?; d.set_item("sni", &r.sni)?;
            d.set_item("segment_hash", &r.segment_hash)?;
            "ssl"
        }
        Immediate::Modbus(r) => {
            base(&d, &r.uid, r.ts, &r.orig_h, r.orig_p, &r.resp_h, r.resp_p)?;
            d.set_item("proto", "tcp")?; d.set_item("func", &r.func)?;
            d.set_item("register", r.register)?; d.set_item("segment_hash", &r.segment_hash)?;
            "modbus"
        }
        Immediate::Dnp3(r) => {
            base(&d, &r.uid, r.ts, &r.orig_h, r.orig_p, &r.resp_h, r.resp_p)?;
            d.set_item("proto", "tcp")?; d.set_item("fc_request", &r.fc_request)?;
            d.set_item("segment_hash", &r.segment_hash)?;
            "dnp3"
        }
        Immediate::Kerberos(r) => {
            base(&d, &r.uid, r.ts, &r.orig_h, r.orig_p, &r.resp_h, r.resp_p)?;
            d.set_item("proto", r.proto)?; d.set_item("request_type", &r.request_type)?;
            d.set_item("client", &r.client)?; d.set_item("service", &r.service)?;
            d.set_item("cipher", &r.cipher)?; d.set_item("segment_hash", &r.segment_hash)?;
            "kerberos"
        }
        Immediate::Ot(r) => {
            base(&d, &r.uid, r.ts, &r.orig_h, r.orig_p, &r.resp_h, r.resp_p)?;
            d.set_item("proto", "tcp")?;
            d.set_item("function", &r.function)?;
            d.set_item("detail", &r.detail)?;
            d.set_item("code", r.code)?;
            d.set_item("service", r.code)?;
            d.set_item("class_id", r.class_id)?; d.set_item("instance_id", r.instance_id)?; d.set_item("response", r.response)?;
            d.set_item("segment_hash", &r.segment_hash)?;
            r.kind
        }
        Immediate::Http(r) => {
            base(&d, &r.uid, r.ts, &r.orig_h, r.orig_p, &r.resp_h, r.resp_p)?;
            d.set_item("proto", "tcp")?; d.set_item("method", &r.method)?;
            d.set_item("uri", &r.uri)?; d.set_item("user_agent", &r.user_agent)?;
            d.set_item("request_body_len", r.request_body_len)?;
            d.set_item("segment_hash", &r.segment_hash)?;
            "http"
        }
    };
    Ok((lt, d))
}

pub(crate) fn conn_batch_to_pylist(py: Python<'_>, records: Vec<live::LiveConnRecord>) -> PyResult<PyObject> {
    let list = PyList::empty_bound(py);
    for r in &records {
        let tup = (("conn").to_string(), live_conn_to_dict(py, r)?);
        list.append(tup)?;
    }
    Ok(list.into())
}

/// Streaming, packet-at-a-time flow assembler for the live-capture path --
/// see live.rs's module doc. `LiveAgent` (src/capture/live_agent.py) feeds
/// this raw Ethernet-framed bytes (`bytes(pkt)` from whatever backend
/// captured it) instead of driving src/capture/flow_assembler.py's
/// pure-Python FlowAssembler; same output shape, same field names, so
/// nothing downstream (map_record, the 13 engines) needs to change.
#[pyclass]
struct LiveFlowAssembler {
    inner: live::LiveFlowAssembler,
}

#[pymethods]
impl LiveFlowAssembler {
    #[new]
    #[pyo3(signature = (idle_timeout_s=live::DEFAULT_IDLE_TIMEOUT_S))]
    fn new(idle_timeout_s: f64) -> Self {
        Self { inner: live::LiveFlowAssembler::new(idle_timeout_s) }
    }

    /// `data` must be the raw Ethernet-framed packet bytes (e.g. Python's
    /// `bytes(scapy_pkt)`). Returns [(log_type, record_dict), ...] for
    /// whatever this ONE packet immediately produced (dns/ssl/modbus/dnp3)
    /// -- `conn` records come from snapshot()/expire()/flush(), matching
    /// FlowAssembler.process()'s contract exactly.
    fn process(&mut self, py: Python<'_>, ts: f64, data: &[u8]) -> PyResult<PyObject> {
        let records = self.inner.process(ts, data);
        let list = PyList::empty_bound(py);
        for rec in &records {
            let (log_type, d) = immediate_to_dict(py, rec)?;
            list.append((log_type, d))?;
        }
        Ok(list.into())
    }

    #[pyo3(signature = (limit=4000))]
    fn snapshot(&mut self, py: Python<'_>, limit: usize) -> PyResult<PyObject> {
        conn_batch_to_pylist(py, self.inner.snapshot(limit))
    }

    #[pyo3(signature = (now=None))]
    fn expire(&mut self, py: Python<'_>, now: Option<f64>) -> PyResult<PyObject> {
        conn_batch_to_pylist(py, self.inner.expire(now.unwrap_or_else(live::now_unix)))
    }

    fn flush(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        conn_batch_to_pylist(py, self.inner.flush())
    }

    fn active_flows(&self) -> usize {
        self.inner.active_flows()
    }

    fn stats(&self, py: Python<'_>) -> PyResult<PyObject> {
        let s = &self.inner.stats;
        let d = PyDict::new_bound(py);
        d.set_item("packets", s.packets)?;
        d.set_item("non_ip", s.non_ip)?;
        d.set_item("flows_seen", s.flows_seen)?;
        d.set_item("dns", s.dns)?;
        d.set_item("ssl", s.ssl)?;
        d.set_item("modbus", s.modbus)?;
        d.set_item("dnp3", s.dnp3)?;
        d.set_item("http", s.http)?;
        d.set_item("kerberos", s.kerberos)?;
        d.set_item("s7comm", s.s7comm)?;
        d.set_item("iec104", s.iec104)?;
        d.set_item("cip", s.cip)?;
        d.set_item("conn", s.conn)?;
        Ok(d.into())
    }
}

#[pymodule]
fn stealthtap_core(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_pcap, m)?)?;
    m.add_class::<LiveFlowAssembler>()?;
    m.add_class::<capture::NativeCapture>()?;
    m.add_class::<capture::PcapIndex>()?;
    m.add_class::<NativeEng01>()?;
    m.add_class::<NativeEng02>()?;
    m.add_class::<NativeEng05>()?;
    m.add_class::<NativeEng06>()?;
    m.add_class::<NativeEng13>()?;
    #[cfg(all(target_os = "linux", feature = "afxdp"))]
    m.add_class::<afxdp::AfXdpCapture>()?;
    Ok(())
}
