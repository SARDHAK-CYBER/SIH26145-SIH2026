"""
Capture backends, fastest-available first:

  1. AFPacketBackend  -- Linux only. Raw AF_PACKET socket with a
     kernel-side PACKET_MMAP RX ring + PACKET_FANOUT (so multiple worker
     sockets share the load) + an optional kernel BPF filter attached via
     SO_ATTACH_FILTER. Packets are copied straight out of the kernel ring
     with zero per-packet syscalls in the fast path -- this is the
     "kernel-level, high-speed" path.

  2. ScapyBackend     -- portable (libpcap / Npcap). Uses scapy's
     AsyncSniffer, which itself sits on the OS kernel capture driver.
     This is what runs on Windows and on Linux without CAP_NET_RAW.

Both yield scapy packet objects to a callback so the rest of the
pipeline (FlowAssembler) is backend-agnostic.
"""
from __future__ import annotations

import os
import platform
import threading
from typing import Callable, Optional

PacketCB = Callable[[object], None]


class CaptureError(RuntimeError):
    pass


class BaseBackend:
    name = "base"
    kernel_level = False

    def start(self) -> None: ...
    def stop(self) -> None: ...
    @property
    def running(self) -> bool: ...


# --------------------------------------------------------------------------
# Portable backend: libpcap / Npcap with kernel BPF + enlarged kernel ring
# + the driver's own recv/drop counters (the "keeping up?" ground truth).
# --------------------------------------------------------------------------
class ScapyBackend(BaseBackend):
    name = "libpcap/npcap"
    kernel_level = True   # in-kernel BPF + kernel ring buffer via the pcap driver

    def __init__(self, iface: str, on_packet: PacketCB, bpf: Optional[str] = None,
                 buffer_mb: int = 64, promisc: bool = True):
        self.iface = iface
        self.on_packet = on_packet
        self.bpf = bpf or None
        self.buffer_mb = buffer_mb
        self.promisc = promisc
        self._sniffer = None
        self._sock = None
        self._pcap = None
        self.kernel_buffer_set = False

    _INSTALL_HINT = (
        "On Windows install Npcap (https://npcap.com) with 'WinPcap API-compatible "
        "mode' and 'raw 802.11' unchecked, then restart. On Linux, run as root or "
        "grant the process CAP_NET_RAW (setcap cap_net_raw,cap_net_admin+eip)."
    )

    def _enlarge_kernel_buffer(self) -> None:
        """Push the NPF/libpcap kernel ring buffer up so micro-bursts don't
        overflow between user-space reads on a fast link."""
        if self.buffer_mb <= 0 or self._pcap is None:
            return
        nbytes = self.buffer_mb * 1024 * 1024
        try:
            from scapy.libs.winpcapy import pcap_setbuff, pcap_set_buffer_size
            if pcap_setbuff(self._pcap, nbytes) == 0 or pcap_set_buffer_size(self._pcap, nbytes) == 0:
                self.kernel_buffer_set = True
        except Exception:
            self.kernel_buffer_set = False

    def kernel_stats(self):
        """(recv, drop, ifdrop) from the capture driver. `drop` rising =
        the kernel ring overflowed = user space can't keep up = the
        high-speed-overrun signal. Returns None where unavailable."""
        if self._pcap is None:
            return None
        try:
            import ctypes
            from scapy.libs.winpcapy import pcap_stat, pcap_stats
            st = pcap_stat()
            if pcap_stats(self._pcap, ctypes.byref(st)) != 0:
                return None
            return {"recv": int(st.ps_recv), "drop": int(st.ps_drop), "ifdrop": int(st.ps_ifdrop)}
        except Exception:
            return None

    def start(self) -> None:
        try:
            import os as _os
            _os.environ.setdefault("SCAPY_USE_PCAPDNET", "1")
            from scapy.config import conf
            conf.use_pcap = True     # real kernel capture driver (in-kernel BPF + drop counters)
            conf.manufdb = None      # skip the OUI DB load (slow, unused here)
            from scapy.sendrecv import AsyncSniffer
        except Exception as exc:  # pragma: no cover
            raise CaptureError(f"scapy unavailable: {exc}")

        caps = capabilities()
        if platform.system() == "Windows" and caps.get("npcap_installed") is False:
            raise CaptureError(f"Npcap is not installed -- live capture cannot start. {self._INSTALL_HINT}")
        if platform.system() != "Windows" and caps.get("can_raw_socket") is False:
            raise CaptureError(f"no raw-socket permission -- live capture cannot start. {self._INSTALL_HINT}")

        try:
            # conf.L2listen compiles + installs the BPF program INTO the kernel.
            self._sock = conf.L2listen(iface=self.iface, filter=self.bpf, promisc=self.promisc)
            self._pcap = getattr(getattr(self._sock, "ins", None), "pcap", None) \
                or getattr(self._sock, "pcap", None)
            self._enlarge_kernel_buffer()
            self._sniffer = AsyncSniffer(opened_socket=self._sock, prn=self.on_packet, store=False)
            self._sniffer.start()
        except Exception as exc:
            self.stop()
            raise CaptureError(f"could not start capture on {self.iface!r}: {exc}. {self._INSTALL_HINT}")

        import time as _t
        for _ in range(20):
            if getattr(self._sniffer, "running", False):
                return
            _t.sleep(0.1)
        exc = getattr(self._sniffer, "exception", None)
        self.stop()
        raise CaptureError(f"capture thread failed to start on {self.iface!r}"
                           f"{f': {exc}' if exc else ''}. {self._INSTALL_HINT}")

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        self._pcap = None

    @property
    def running(self) -> bool:
        return self._sniffer is not None and getattr(self._sniffer, "running", False)


# --------------------------------------------------------------------------
# Kernel-level backend: AF_PACKET + PACKET_MMAP ring + FANOUT (Linux)
# --------------------------------------------------------------------------
class AFPacketBackend(BaseBackend):
    name = "af_packet(mmap+fanout)"
    kernel_level = True

    def __init__(self, iface: str, on_packet: PacketCB, bpf: Optional[str] = None,
                 workers: int = 0, block_size: int = 1 << 20, block_count: int = 64,
                 buffer_mb: int = 64, promisc: bool = True):
        if platform.system() != "Linux":
            raise CaptureError("AF_PACKET is Linux-only")
        self.iface = iface
        self.on_packet = on_packet
        self.bpf = bpf or None
        self.workers = workers or max(1, (os.cpu_count() or 2) // 2)
        # size the mmap ring from the requested buffer budget, split across workers
        if buffer_mb > 0:
            self.block_count = max(8, (buffer_mb * 1024 * 1024) // block_size // max(1, self.workers))
        else:
            self.block_count = block_count
        self.block_size = block_size
        self.promisc = promisc
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self._socks: list = []
        self._acc_recv = 0
        self._acc_drop = 0

    def kernel_stats(self):
        """PACKET_STATISTICS (tpacket_stats): {recv, drop}. The Linux
        getsockopt is delta-since-last-read and resets on read, so we
        accumulate here to match the libpcap backend's cumulative
        semantics. drop rising = ring overflow = high-speed overrun."""
        import struct
        SOL_PACKET = 263
        PACKET_STATISTICS = 6
        for s in self._socks:
            try:
                raw = s.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
                recv, drop = struct.unpack("II", raw)
                self._acc_recv += recv
                self._acc_drop += drop
            except Exception:
                return None
        return {"recv": self._acc_recv, "drop": self._acc_drop, "ifdrop": 0}

    # -- kernel BPF program compiled from a tcpdump-style filter --
    def _compile_bpf(self):
        if not self.bpf:
            return None
        try:
            # scapy can compile a filter into a BPF program on Linux
            from scapy.arch.common import compile_filter
            return compile_filter(self.bpf, iface=self.iface)
        except Exception:
            return None

    def _make_socket(self, fanout_id: int):
        import socket
        import struct

        ETH_P_ALL = 0x0003
        SOL_PACKET = 263
        PACKET_FANOUT = 18
        PACKET_FANOUT_HASH = 0
        PACKET_RX_RING = 5
        SO_ATTACH_FILTER = 26

        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))  # type: ignore[attr-defined]

        bpf = self._compile_bpf()
        if bpf is not None:
            try:
                s.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, bpf)
            except Exception:
                pass  # fall back to userspace filtering in FlowAssembler's caller

        # PACKET_MMAP v1 RX ring: struct tpacket_req { uint blk? } -- use TPACKET_V3-lite
        # via the classic tpacket_req (block-less framing) for portability.
        frame_size = 2048
        frame_nr = (self.block_size // frame_size) * self.block_count
        tpacket_req = struct.pack("IIII", self.block_size, self.block_count, frame_size, frame_nr)
        try:
            s.setsockopt(SOL_PACKET, PACKET_RX_RING, tpacket_req)
        except Exception:
            pass  # ring not available -> plain recv loop still works

        s.bind((self.iface, 0))

        try:
            fanout_arg = (fanout_id & 0xFFFF) | (PACKET_FANOUT_HASH << 16)
            s.setsockopt(SOL_PACKET, PACKET_FANOUT, struct.pack("=I", fanout_arg))
        except Exception:
            pass
        s.settimeout(1.0)
        return s

    def _worker(self, sock):
        from scapy.layers.l2 import Ether
        while not self._stop.is_set():
            try:
                raw = sock.recv(65535)
            except OSError:
                continue
            if not raw:
                continue
            try:
                pkt = Ether(raw)
            except Exception:
                continue
            try:
                self.on_packet(pkt)
            except Exception:
                pass

    def _set_promisc(self):
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
            pass  # PACKET_MR_PROMISC below still covers capture; this is belt-and-braces

    def start(self) -> None:
        import socket
        self._set_promisc()
        try:
            fanout_id = os.getpid() & 0xFFFF
            for i in range(self.workers):
                s = self._make_socket(fanout_id)
                self._socks.append(s)
                t = threading.Thread(target=self._worker, args=(s,), daemon=True,
                                     name=f"afpacket-{i}")
                t.start()
                self._threads.append(t)
        except PermissionError:
            self.stop()
            raise CaptureError("AF_PACKET needs root or CAP_NET_RAW")
        except OSError as exc:
            self.stop()
            raise CaptureError(f"AF_PACKET open failed on {self.iface!r}: {exc}")

    def stop(self) -> None:
        self._stop.set()
        for s in self._socks:
            try:
                s.close()
            except Exception:
                pass
        self._socks.clear()
        for t in self._threads:
            t.join(timeout=2.0)
        self._threads.clear()

    @property
    def running(self) -> bool:
        return any(t.is_alive() for t in self._threads)


# --------------------------------------------------------------------------
def select_backend(iface: str, on_packet: PacketCB, bpf: Optional[str] = None,
                   prefer_kernel: bool = True, buffer_mb: int = 64,
                   promisc: bool = True) -> BaseBackend:
    """Pick the fastest backend that can actually run here.

    Linux + prefer_kernel  -> AFPacketBackend (mmap RX ring + FANOUT + kernel BPF)
    everything else         -> ScapyBackend   (libpcap/Npcap: kernel BPF + enlarged
                                               kernel ring + pcap_stats drop counters)
    """
    if prefer_kernel and platform.system() == "Linux":
        try:
            return AFPacketBackend(iface, on_packet, bpf, buffer_mb=buffer_mb, promisc=promisc)
        except CaptureError:
            pass
    return ScapyBackend(iface, on_packet, bpf, buffer_mb=buffer_mb, promisc=promisc)


def _npcap_present() -> bool:
    """Fast, scapy-free Npcap probe -- checks for the driver DLLs. Avoids
    scapy's interface enumeration, which can block for seconds (or hang)
    on a host where the capture driver is half-installed."""
    import glob
    candidates = [
        r"C:\Windows\System32\Npcap\wpcap.dll",
        r"C:\Windows\System32\Npcap\Packet.dll",
        r"C:\Windows\System32\wpcap.dll",  # WinPcap-compat shim
    ]
    if any(os.path.exists(p) for p in candidates):
        return True
    return bool(glob.glob(r"C:\Windows\System32\*\wpcap.dll"))


def capabilities() -> dict:
    system = platform.system()
    caps = {
        "platform": system,
        "kernel_backend": "af_packet" if system == "Linux" else None,
        "portable_backend": "libpcap" if system != "Windows" else "npcap",
        "npcap_installed": None,
        "can_raw_socket": None,
    }
    if system == "Windows":
        caps["npcap_installed"] = _npcap_present()
    else:
        try:
            import socket
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)  # type: ignore[attr-defined]
            s.close()
            caps["can_raw_socket"] = True
        except Exception:
            caps["can_raw_socket"] = False
    return caps
