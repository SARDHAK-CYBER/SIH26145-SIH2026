"""
AF_XDP capture backend -- Linux only, native (native/stealthtap_core/src/
afxdp.rs, built on the `xsk-rs` crate). Kernel-bypass-capable capture: a
UMEM (a shared packet-buffer region) plus fill/rx rings, bound directly to
one NIC queue, bypassing the normal per-packet socket-buffer allocation
AF_PACKET/libpcap still pay for.

VALIDATED against a real bind and real traffic, not just written to the
documented API: bound to a live `eth0` (driver `hv_netvsc`, inside a WSL2
Kali distro) and received real packets, with `ip -d link show eth0`
confirming `prog/xdp` while bound -- i.e. **native/driver XDP mode**, not
generic/SKB mode. That corrects an earlier assumption (stated to the user
before checking) that a Hyper-V-virtualized NIC could only reach generic
mode. What's still NOT independently confirmed here is the AF_XDP
zero-copy bind flag specifically (native mode and zero-copy are related
but distinct; `hv_netvsc`'s native XDP support has historically been
copy-mode in many kernel versions) -- so the full performance claim this
backend exists for is closer to proven than originally caveated, but not
completely nailed down without checking driver-level zero-copy stats.
Same "validated, not asserted" standard as everything else in this
codebase -- see native/README.md's afxdp.rs section for the full account,
including a real ring-sizing bug this same testing found and fixed.

Falls back the same way every native feature in this codebase does: if
the native module wasn't built with the `afxdp` module (Windows, or a
Linux build without the xsk-rs toolchain available), or the bind itself
fails (no CAP_NET_RAW/CAP_BPF, no XDP-capable driver, kernel too old),
`select_backend()` catches CaptureError and moves on to AFPacketBackend.
"""
from __future__ import annotations

import platform
import threading
from typing import Callable, Optional

from src.capture.backends import BaseBackend, CaptureError, PacketCB

try:
    import stealthtap_core
    _AFXDP_AVAILABLE = hasattr(stealthtap_core, "AfXdpCapture")
except ImportError:
    _AFXDP_AVAILABLE = False


class AfXdpBackend(BaseBackend):
    name = "af_xdp(xsk)"
    kernel_level = True

    def __init__(self, iface: str, on_packet: PacketCB, bpf: Optional[str] = None,
                 queue_id: int = 0, frame_count: int = 4096,
                 buffer_mb: int = 64, promisc: bool = True):
        if platform.system() != "Linux":
            raise CaptureError("AF_XDP is Linux-only")
        if not _AFXDP_AVAILABLE:
            raise CaptureError(
                "native AF_XDP support not built into stealthtap_core -- "
                "rebuild on Linux (maturin develop --release) to enable it"
            )
        if bpf:
            # libxdp's auto-attached default program (this backend uses no
            # custom eBPF of its own -- see afxdp.rs's module docstring)
            # redirects everything to this socket unconditionally; there is
            # no in-kernel filtering hook to attach a BPF expression to
            # without writing and loading a custom XDP program, which is
            # out of scope here. Filtering still happens correctly in
            # userspace (FlowAssembler/engines apply their own logic
            # regardless of which backend fed them), just not in-kernel.
            print(f"[af_xdp] note: bpf filter {bpf!r} requested but not supported "
                  f"in-kernel by this backend -- all traffic on {iface} will be "
                  f"captured and filtered in userspace instead")
        self.iface = iface
        self.on_packet = on_packet
        self.queue_id = queue_id
        # UMEM default frame size is 4096 bytes (xsk-rs/libxdp default); size
        # the frame count from the requested buffer budget, same intent as
        # AFPacketBackend's block_count sizing.
        self.frame_count = frame_count if frame_count else max(1024, (buffer_mb * 1024 * 1024) // 4096)
        self.promisc = promisc
        self._cap = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def _set_promisc(self) -> None:
        # Same ioctl AFPacketBackend uses -- belt-and-braces alongside
        # whatever the XDP-bound driver does on its own; not fatal if it
        # fails (e.g. no CAP_NET_ADMIN), capture still works either way.
        if not self.promisc:
            return
        try:
            import socket, struct, fcntl
            SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_PROMISC = 0x8913, 0x8914, 0x100
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ifr = struct.pack("16sh", self.iface.encode()[:15], 0)
            flags = struct.unpack("16sh", fcntl.ioctl(s, SIOCGIFFLAGS, ifr))[1]
            fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sh", self.iface.encode()[:15], flags | IFF_PROMISC))
            s.close()
        except Exception:
            pass

    def _worker(self) -> None:
        from scapy.layers.l2 import Ether
        while not self._stop.is_set():
            try:
                batch = self._cap.recv_batch(256, 100)
            except Exception:
                continue
            for _ts, raw in batch:
                try:
                    pkt = Ether(raw)
                except Exception:
                    continue
                try:
                    self.on_packet(pkt)
                except Exception:
                    pass

    def start(self) -> None:
        self._set_promisc()
        try:
            self._cap = stealthtap_core.AfXdpCapture(self.iface, self.queue_id, self.frame_count)
        except Exception as exc:
            raise CaptureError(
                f"AF_XDP bind failed on {self.iface!r} (queue {self.queue_id}): {exc}. "
                f"Needs CAP_NET_RAW+CAP_BPF or root, and a kernel with CONFIG_XDP_SOCKETS."
            )
        self._stop.clear()
        self._thread = threading.Thread(target=self._worker, daemon=True, name="af_xdp")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        self._cap = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def kernel_stats(self) -> Optional[dict]:
        """(received, refill_short) -- refill_short rising means the fill
        queue briefly couldn't take back every just-consumed frame (ring
        pressure), the AF_XDP-side analogue of AFPacketBackend's `drop`."""
        if self._cap is None:
            return None
        try:
            received, refill_short = self._cap.stats()
            return {"recv": received, "drop": refill_short, "ifdrop": 0}
        except Exception:
            return None
