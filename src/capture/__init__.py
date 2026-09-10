"""Live network capture -> StealthTap detection pipeline.

A fourth ingest path alongside batch-Zeek, live-streaming (Zeek->Redpanda),
and upload-PCAP. This one taps a real NIC directly via the Npcap/libpcap
kernel driver, assembles flows in-process, and runs the same ENG01-13
engine set the other paths use.
"""
import os as _os

# Force scapy onto the libpcap/Npcap provider when it IS imported (lazily,
# by backends.py). This is what we want for capture anyway (in-kernel BPF
# + drop counters), and it also skips scapy's default arch init, which on
# some Windows hosts shells out to PowerShell for route/adapter discovery
# and can block ~120 s on the first `import scapy.layers.inet`.
# NOTE: only an env var here -- we deliberately DON'T `import scapy` at
# package import time, so `import src.capture.*` stays instant.
_os.environ.setdefault("SCAPY_USE_PCAPDNET", "1")
