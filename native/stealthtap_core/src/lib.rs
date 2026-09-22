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

mod parse;
mod pcap;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

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
        d.set_item("proto", "udp")?;
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

#[pymodule]
fn stealthtap_core(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_pcap, m)?)?;
    Ok(())
}
