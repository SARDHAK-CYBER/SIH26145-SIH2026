//! Passive network inventory: who is on the wire, how much they talk, and what
//! protocols they speak -- maintained per packet inside the capture thread so
//! the live dashboard's "hosts / top talkers / protocol mix" cost nothing at
//! query time and nothing in Python per packet.
//!
//! What a passive sensor can honestly see depends on where it sits: on a
//! switch mirror / TAP / gateway it sees every host; on a Wi-Fi client it sees
//! its own traffic plus broadcast/multicast (ARP, mDNS, DHCP, SSDP, NetBIOS)
//! from the others. The inventory reports exactly what was observed, no more.

use std::collections::HashMap;

pub struct Host {
    pub first: f64,
    pub last: f64,
    pub tx_pkts: u64,
    pub rx_pkts: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tcp: u64,
    pub udp: u64,
    pub other: u64,
    pub mac: Option<[u8; 6]>,
    pub via_arp: bool,
}

impl Host {
    fn new(ts: f64) -> Self {
        Host { first: ts, last: ts, tx_pkts: 0, rx_pkts: 0, tx_bytes: 0, rx_bytes: 0,
               tcp: 0, udp: 0, other: 0, mac: None, via_arp: false }
    }
}

pub const PROTO_NAMES: [&str; 32] = [
    "HTTPS/TLS", "HTTP", "QUIC", "DNS", "mDNS", "SSDP", "DHCP", "NTP", "SSH", "RDP", "SMB/NetBIOS",
    "Kerberos", "LDAP", "SMTP/IMAP/POP", "FTP/Telnet", "MQTT", "Modbus", "DNP3", "EtherNet/IP", "S7comm",
    "OPC UA", "BACnet", "SNMP/Syslog", "Database", "ICMP", "ARP", "other-TCP", "other-UDP",
    "IPv6-other", "other-IP", "VPN/IPsec", "Remote-mgmt",
];

fn well_known(proto_is_tcp: bool, port: u16) -> Option<usize> {
    Some(match port {
        443 | 8443 => if proto_is_tcp { 0 } else { 2 },
        80 | 8080 | 8000 | 8008 => 1,
        53 => 3,
        5353 | 5355 => 4,
        1900 => 5,
        67 | 68 | 546 | 547 => 6,
        123 => 7,
        22 => 8,
        3389 => 9,
        445 | 139 | 137 | 138 => 10,
        88 | 464 => 11,
        389 | 636 | 3268 | 3269 => 12,
        25 | 465 | 587 | 110 | 143 | 993 | 995 => 13,
        21 | 23 => 14,
        1883 | 8883 => 15,
        502 => 16,
        20000 => 17,
        44818 | 2222 => 18,
        102 => 19,
        4840 => 20,
        47808 => 21,
        161 | 162 | 514 => 22,
        5432 | 3306 | 1433 | 6379 | 27017 | 9200 | 1521 => 23,
        500 | 4500 | 1194 | 51820 => 30,
        5985 | 5986 | 135 | 5900 | 5901 => 31,
        _ => return None,
    })
}

pub fn classify(is_tcp: bool, sport: u16, dport: u16) -> usize {
    // the lower port is normally the service; check dport first (client -> server)
    if let Some(i) = well_known(is_tcp, dport) { return i; }
    if let Some(i) = well_known(is_tcp, sport) { return i; }
    if is_tcp { 26 } else { 27 }
}

pub struct Inventory {
    pub hosts: HashMap<String, Host>,
    pub max_hosts: usize,
    pub hosts_dropped: u64,
    pub proto_pkts: [u64; 32],
    pub proto_bytes: [u64; 32],
}

impl Inventory {
    pub fn new() -> Self {
        Inventory { hosts: HashMap::new(), max_hosts: 200_000, hosts_dropped: 0,
                    proto_pkts: [0; 32], proto_bytes: [0; 32] }
    }

    fn host(&mut self, ip: &str, ts: f64) -> Option<&mut Host> {
        if !self.hosts.contains_key(ip) {
            if self.hosts.len() >= self.max_hosts { self.hosts_dropped += 1; return None; }
            self.hosts.insert(ip.to_string(), Host::new(ts));
        }
        self.hosts.get_mut(ip)
    }

    /// Every IP packet: byte/packet accounting for both endpoints.
    /// `kind`: 0 = tcp, 1 = udp, 2 = other. `src_mac` is the Ethernet source.
    pub fn observe_ip(&mut self, src: &str, dst: &str, wire: u64, ts: f64, kind: u8, src_mac: Option<[u8; 6]>) {
        if let Some(h) = self.host(src, ts) {
            h.last = ts; h.tx_pkts += 1; h.tx_bytes += wire;
            match kind { 0 => h.tcp += 1, 1 => h.udp += 1, _ => h.other += 1 }
            if h.mac.is_none() { h.mac = src_mac; }
        }
        if let Some(h) = self.host(dst, ts) {
            h.last = ts; h.rx_pkts += 1; h.rx_bytes += wire;
        }
    }

    pub fn observe_proto(&mut self, idx: usize, wire: u64) {
        self.proto_pkts[idx] += 1;
        self.proto_bytes[idx] += wire;
    }

    /// ARP: the sender's IP<->MAC binding is authoritative (an L2-local host).
    pub fn observe_arp(&mut self, ip: &str, mac: [u8; 6], ts: f64, wire: u64) {
        self.observe_proto(25, wire);
        if ip == "0.0.0.0" { return; }
        if let Some(h) = self.host(ip, ts) {
            h.last = ts; h.tx_pkts += 1; h.tx_bytes += wire; h.mac = Some(mac); h.via_arp = true;
        }
    }
}

pub fn mac_str(m: &[u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
}
