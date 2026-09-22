"""
Who is the originator of a flow?

Both in-process flow builders (pcap_parser.py for uploads, capture/
flow_assembler.py for live) used to call the FIRST packet they saw the
originator. That is only right if the capture began before the TCP
handshake. A capture that starts mid-connection (every live capture, and
many pcaps) sees a server->client data packet first, so the server was
recorded as the originator: a 118 KB *download* looked like a 118 KB
*upload* with a 86:1 ratio and fired DATA_EXFILTRATION on ordinary web
traffic. Anything using orig/resp bytes (ENG-06, the flow model's
byte_ratio) inherited the same inversion.

Decision order:
  1. TCP SYN (no ACK) -> the sender is the client. SYN+ACK -> the sender
     is the server. Definitive whenever the handshake was captured.
  2. Otherwise the less server-like port is the client: well-known
     (<1024) is a server port, registered (1024-32767) is probably a
     server, >=32768 is an ephemeral client port. Equal ranks keep the
     as-seen direction.
"""
from __future__ import annotations

from typing import Optional

_TCP_SYN, _TCP_ACK = 0x02, 0x10


def _port_rank(port: int) -> int:
    """0 = server-like, 2 = ephemeral/client-like."""
    if port < 1024:
        return 0
    if port < 32768:
        return 1
    return 2


def sender_is_originator(proto: str, sport: int, dport: int, tcp_flags: Optional[int] = None) -> bool:
    """True if the packet's SENDER should be recorded as the flow originator."""
    if proto == "tcp" and tcp_flags is not None:
        syn, ack = bool(tcp_flags & _TCP_SYN), bool(tcp_flags & _TCP_ACK)
        if syn and not ack:
            return True
        if syn and ack:
            return False
    rs, rd = _port_rank(int(sport)), _port_rank(int(dport))
    if rs != rd:
        return rs > rd        # sender has the less server-like port -> sender is the client
    return True
