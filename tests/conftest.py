"""Force scapy onto the pcap provider before any test imports a scapy
layer. On some Windows dev hosts the default scapy arch init shells out
to PowerShell for route discovery and blocks ~120 s on first import;
this makes `import scapy.layers.inet` return instantly. No effect on
Linux/CI (where it's already fast)."""
import os

import src  # noqa: F401  -- scapy/Npcap import guard (src/scapy_safe.py) must precede any scapy import

os.environ.setdefault("SCAPY_USE_PCAPDNET", "1")
os.environ.setdefault("SCAPY_MANUFDB", "")
try:
    from scapy.config import conf

    conf.use_pcap = True
    conf.manufdb = None      # skip the OUI DB (slow) -- must be set before scapy.layers import
    # Load only inet+dns, not scapy's full layer set (bluetooth, zigbee,
    # etc.) -- keeps import fast while still populating scapy.all's IP/
    # TCP/UDP/DNS/DNSQR names. `[]` (load nothing) previously broke the
    # FIRST test in a session to `from scapy.all import IP, ...` --
    # exactly what src/api/pcap_analysis.py -> pcap_parser.py does --
    # with an ImportError, since scapy.all only re-exports names from
    # layers it actually loaded.
    conf.load_layers = ["inet", "dns"]
    conf.noenum = True
except Exception:
    pass

