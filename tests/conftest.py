"""Force scapy onto the pcap provider before any test imports a scapy
layer. On some Windows dev hosts the default scapy arch init shells out
to PowerShell for route discovery and blocks ~120 s on first import;
this makes `import scapy.layers.inet` return instantly. No effect on
Linux/CI (where it's already fast)."""
import os

os.environ.setdefault("SCAPY_USE_PCAPDNET", "1")
os.environ.setdefault("SCAPY_MANUFDB", "")
try:
    from scapy.config import conf

    conf.use_pcap = True
    conf.manufdb = None      # skip the OUI DB (slow) -- must be set before scapy.layers import
    conf.load_layers = []    # don't autoload every layer at import
    conf.noenum = True
except Exception:
    pass
