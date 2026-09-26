
# Must run before anything imports scapy (see src/scapy_safe.py)
from src import scapy_safe as _scapy_safe
_scapy_safe.install()
