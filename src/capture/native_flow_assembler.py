"""
Adapter: makes stealthtap_core.LiveFlowAssembler (Rust) present the exact
same interface as src/capture/flow_assembler.py's FlowAssembler (Python),
so LiveAgent can use either with ZERO call-site changes -- the same
graceful-fallback pattern already used for Zeek/Redis/model_server
elsewhere in this codebase.

Validated against the Python reference on real captures via
scripts/validate_native_live_assembler.py before this adapter existed --
see native/README.md for the methodology and results. Only handles
Ethernet-framed input, which is what real NIC capture actually is (both
AFPacketBackend and ScapyBackend construct genuine Ether()-rooted scapy
packets -- confirmed in src/capture/backends.py), so this is safe for the
live path specifically, unlike an arbitrary pcap file that might use a
different link type.
"""
from __future__ import annotations

import time
from typing import Optional

try:
    import stealthtap_core
    NATIVE_LIVE_ASSEMBLER_AVAILABLE = True
except ImportError:
    NATIVE_LIVE_ASSEMBLER_AVAILABLE = False


class NativeFlowAssemblerAdapter:
    """Drop-in replacement for FlowAssembler -- same process()/snapshot()/
    expire()/flush()/active_flows()/.stats surface, backed by the Rust
    LiveFlowAssembler."""

    def __init__(self, idle_timeout_s: float = 60.0):
        self._inner = stealthtap_core.LiveFlowAssembler(idle_timeout_s)

    def process(self, pkt) -> list[tuple[str, dict]]:
        ts = float(getattr(pkt, "time", None) or time.time())
        try:
            raw = bytes(pkt)
        except Exception:
            return []
        return self._inner.process(ts, raw)

    def snapshot(self, now: Optional[float] = None, limit: int = 4000) -> list[tuple[str, dict]]:
        return self._inner.snapshot(limit)

    def expire(self, now: Optional[float] = None) -> list[tuple[str, dict]]:
        return self._inner.expire(now)

    def flush(self) -> list[tuple[str, dict]]:
        return self._inner.flush()

    def active_flows(self) -> int:
        return self._inner.active_flows()

    @property
    def stats(self) -> dict:
        return self._inner.stats()
