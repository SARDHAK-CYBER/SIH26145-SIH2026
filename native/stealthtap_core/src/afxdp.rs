//! AF_XDP capture backend -- Linux only (this whole module is excluded from
//! the build on every other platform via the `#[cfg(target_os = "linux")]`
//! on its `mod afxdp;` declaration in lib.rs, so it cannot affect the
//! Windows build this project is primarily developed and tested on).
//!
//! VALIDATED, not just written -- and corrected against a real, initially
//! wrong assumption (same standard as every other native module in this
//! crate -- see native/README.md's "Validated, not asserted" section):
//!
//! - **Compiles and links on a real Linux host**: WSL2 (Kali, kernel
//!   6.6.87-microsoft-standard-WSL2), with `xsk-rs`'s vendored-libbpf +
//!   vendored-libelf + vendored-zlib + use_precompiled_bpf build (no
//!   system libxdp/pkg-config lookup needed at runtime on the target
//!   machine -- only build-time tooling: pkg-config, autoconf/automake/
//!   libtool, autopoint, flex, bison, gawk, a C compiler).
//! - **Real AF_XDP bind + real packet capture, confirmed on real hardware,
//!   not assumed**: bound to a live `eth0` (driver `hv_netvsc`) and
//!   received real packets off the wire (`ip -d link show eth0` while
//!   bound: `prog/xdp id NNN` -- that's **native/driver XDP mode**, not
//!   generic/SKB mode). This corrects an assumption stated in an earlier
//!   version of this comment (and told to the user before checking): that
//!   WSL2's Hyper-V-virtualized NIC could only reach generic mode. It
//!   doesn't confirm the AF_XDP *zero-copy* bind flag specifically
//!   negotiated (native mode and zero-copy are related but distinct --
//!   `hv_netvsc`'s native XDP support has historically been copy-mode in
//!   many kernel versions), so the throughput claim AF_XDP exists for is
//!   still not independently measured here; what's now confirmed is that
//!   the packet path itself -- bind, fill-ring seeding, RX polling, UMEM
//!   frame data access, fill-ring recycling -- is correct on a real
//!   kernel and a real driver, not just type-correct against docs.
//! - **A real bug found this way, not by inspection**: the constructor
//!   originally seeded the ENTIRE `frame_count` (default 4096) into the
//!   fill queue in one `produce()` call, assuming it would partially
//!   succeed if the ring was smaller. It doesn't -- libxdp's default fill
//!   queue size is 2048, and a `produce()` call that doesn't fully fit
//!   rejects the whole batch (0/4096 accepted, not 2048/4096). Fixed by
//!   sizing the fill/completion queues to `frame_count` explicitly via
//!   `UmemConfigBuilder`, confirmed fixed by re-running the same real bind
//!   + capture test.
//! - Needs `CAP_NET_RAW` + `CAP_BPF` (or root) and a kernel built with
//!   `CONFIG_XDP_SOCKETS=y` (present in effectively every distro kernel
//!   since ~5.4). Falls back cleanly (a normal Python exception, caught by
//!   `AfXdpBackend` the same way every other capture backend's failure is
//!   caught) if either is missing.
//! - Uses the `xsk-rs` crate's default (empty) `LibxdpFlags`, meaning
//!   libxdp auto-loads its own default XDP program (a plain
//!   redirect-everything-to-this-socket program) on bind -- this module
//!   does not ship or load a custom eBPF/C program of its own. On this
//!   test system libxdp additionally logged "No bpffs found at
//!   /sys/fs/bpf" and fell back from its multi-program "dispatcher" to
//!   loading a single plain XDP program -- harmless for this single-
//!   capture-program use case (the dispatcher only matters for chaining
//!   multiple independent XDP programs on one interface), but a
//!   production deployment expecting the dispatcher should mount bpffs
//!   (`mount -t bpf bpffs /sys/fs/bpf`) first.
//!
//! `src/capture/afxdp_backend.py` wraps this the same way every other
//! capture backend wraps its OS-level primitive: raw Ethernet-framed bytes
//! out, fed into the same `LiveFlowAssembler`/engine pipeline everything
//! else uses. Nothing downstream of capture needed to change.

use std::num::NonZeroU32;
use std::time::{SystemTime, UNIX_EPOCH};

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

use xsk_rs::config::{Interface, QueueSize, SocketConfig, UmemConfigBuilder};
use xsk_rs::{CompQueue, FillQueue, FrameDesc, RxQueue, Socket, TxQueue, Umem};

fn now_unix() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

#[pyclass]
pub struct AfXdpCapture {
    umem: Umem,
    rx_q: RxQueue,
    fill_q: FillQueue,
    // Unused for a pure-capture backend, but Socket::new hands back
    // ownership of these -- dropping them early would close the socket's
    // TX/completion side out from under the still-live RX/fill side.
    _tx_q: TxQueue,
    _comp_q: CompQueue,
    rx_descs: Vec<FrameDesc>,
    pub stats_received: u64,
    pub stats_refill_short: u64,
}

#[pymethods]
impl AfXdpCapture {
    /// `iface`: interface name, e.g. "eth0". `queue_id`: which RX queue of
    /// that interface to bind (0 for a single-queue NIC, or when not doing
    /// per-queue fanout across multiple sockets/cores). `frame_count`:
    /// number of UMEM frames -- also the hard cap on in-flight packets
    /// between kernel and this process; 4096 matches libxdp's own default
    /// ring sizes.
    #[new]
    #[pyo3(signature = (iface, queue_id=0, frame_count=4096))]
    fn new(iface: &str, queue_id: u32, frame_count: u32) -> PyResult<Self> {
        let frame_count_nz = NonZeroU32::new(frame_count)
            .ok_or_else(|| PyRuntimeError::new_err("frame_count must be > 0"))?;

        // Size the fill/completion rings to match frame_count explicitly --
        // xsk-rs/libxdp's own UmemConfig::default() fill/comp queue sizes
        // are fixed at libbpf's XSK_RING_*__DEFAULT_NUM_DESCS (2048), which
        // is SMALLER than this constructor's own frame_count default
        // (4096). Found the hard way: seeding the fill queue with all 4096
        // UMEM frames at once against a 2048-slot ring doesn't partially
        // succeed, it rejects the whole batch (produce() returned 0/4096,
        // not e.g. 2048/4096) -- confirmed against a real AF_XDP bind on
        // real hardware, not assumed. Matching the ring size to frame_count
        // makes the startup seed always fully succeed regardless of which
        // frame_count the caller picks, rather than silently capping how
        // many of the allocated UMEM frames are ever actually usable.
        let queue_size = QueueSize::new(frame_count)
            .map_err(|e| PyRuntimeError::new_err(format!("frame_count must be a power of two: {e}")))?;
        let umem_config = UmemConfigBuilder::new()
            .fill_queue_size(queue_size)
            .comp_queue_size(queue_size)
            .build()
            .map_err(|e| PyRuntimeError::new_err(format!("invalid UMEM config: {e}")))?;

        let (umem, descs) = Umem::new(umem_config, frame_count_nz, false)
            .map_err(|e| PyRuntimeError::new_err(format!("AF_XDP UMEM creation failed: {e}")))?;

        let interface: Interface = iface
            .parse()
            .map_err(|e| PyRuntimeError::new_err(format!("bad interface {iface:?}: {e}")))?;

        // SAFETY: xsk-rs's own contract -- the UMEM and its frame
        // descriptors must not be used by another socket concurrently in a
        // way that violates the fill/comp/rx/tx handoff protocol. This
        // capture holds sole ownership of `umem` and every FrameDesc it
        // produced, and never shares them with another Socket, so that
        // contract holds.
        let (tx_q, rx_q, fq_cq) = unsafe { Socket::new(SocketConfig::default(), &umem, &interface, queue_id) }
            .map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "AF_XDP socket bind failed on {iface}:{queue_id} -- needs CAP_NET_RAW+CAP_BPF \
                     or root, and a kernel with XDP socket support (CONFIG_XDP_SOCKETS): {e}"
                ))
            })?;
        let (mut fill_q, comp_q) = fq_cq.ok_or_else(|| {
            PyRuntimeError::new_err(
                "AF_XDP socket did not return an exclusive fill/completion queue -- \
                 shared-UMEM binding (a second socket on an already-bound UMEM) is not \
                 supported by this backend",
            )
        })?;

        // Hand the whole UMEM to the kernel up front so there's somewhere
        // for the first receives to land -- mirrors every AF_XDP example's
        // startup sequence (fill queue must be primed before packets
        // arrive, or the kernel has nowhere to write them and drops).
        let produced = unsafe { fill_q.produce(&descs) };
        if produced != descs.len() {
            return Err(PyRuntimeError::new_err(format!(
                "AF_XDP fill queue only accepted {produced}/{} frames on startup",
                descs.len()
            )));
        }

        Ok(Self {
            umem,
            rx_q,
            fill_q,
            _tx_q: tx_q,
            _comp_q: comp_q,
            rx_descs: vec![FrameDesc::default(); descs.len()],
            stats_received: 0,
            stats_refill_short: 0,
        })
    }

    /// Polls for up to `max_batch` received frames, blocking at most
    /// `timeout_ms`. Returns `[(unix_ts, raw_ethernet_bytes), ...]` -- the
    /// exact same shape `AfXdpBackend` needs to build a scapy `Ether()`
    /// packet, matching every other backend's `on_packet` contract.
    #[pyo3(signature = (max_batch=256, timeout_ms=100))]
    fn recv_batch(&mut self, max_batch: usize, timeout_ms: i32) -> PyResult<Vec<(f64, Vec<u8>)>> {
        let batch = max_batch.min(self.rx_descs.len());
        // SAFETY: `self.rx_descs` is sized to the UMEM's own frame count,
        // so every descriptor the kernel could possibly write back here
        // refers to a frame this capture owns.
        let n = unsafe { self.rx_q.poll_and_consume(&mut self.rx_descs[..batch], timeout_ms) }
            .map_err(|e| PyRuntimeError::new_err(format!("AF_XDP poll failed: {e}")))?;
        if n == 0 {
            return Ok(Vec::new());
        }

        let ts = now_unix();
        let mut out = Vec::with_capacity(n);
        for desc in &self.rx_descs[..n] {
            // SAFETY: `desc` was just filled in by poll_and_consume above,
            // from a frame that belongs to `self.umem` (the only UMEM this
            // capture ever binds to), and is read before being handed back
            // to the fill queue below -- never both at once.
            let data = unsafe { self.umem.data(desc) };
            out.push((ts, data.contents().to_vec()));
        }
        self.stats_received += n as u64;

        // Recycle these frames back to the kernel immediately so the ring
        // doesn't starve -- same descriptors, same addresses, now safe to
        // reuse because their contents were already copied out above.
        let refilled = unsafe { self.fill_q.produce(&self.rx_descs[..n]) };
        if refilled != n {
            // Not fatal -- just means fewer frames are available for the
            // next receive until this batch settles; surfaced via stats()
            // rather than raising, so a transient ring-full moment doesn't
            // take capture down.
            self.stats_refill_short += (n - refilled) as u64;
        }

        Ok(out)
    }

    fn stats(&self) -> (u64, u64) {
        (self.stats_received, self.stats_refill_short)
    }
}
