//! IPv4/TCP/UDP header extraction, flow orientation, flow assembly, and DNS
//! query extraction -- a byte-level Rust port of the validated logic in
//! pcap_parser.py and src/flow_orientation.py. Every design decision here
//! (SYN/SYN-ACK orientation, port-rank fallback, the flow UID formula, the
//! DNS qr==0 filter) mirrors that Python code exactly and on purpose: it is
//! the reference specification, fixed against real captures this session,
//! not something to reinvent.
//!
//! Panics are never allowed to escape a single packet: `parse_one` returns
//! Option and every slice access is bounds-checked, so one malformed or
//! truncated packet degrades to "skip it" (matching the Python parser's
//! `if not pkt.haslayer(IP): continue`), not "crash the whole capture."
//! That matters specifically because this parses untrusted, potentially
//! adversarial input straight off the wire.

use indexmap::IndexMap;
use sha2::{Digest, Sha256};

pub(crate) const LINKTYPE_ETHERNET: u32 = 1;
const LINKTYPE_LINUX_SLL: u32 = 113;

const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;

#[derive(Clone, Debug)]
pub struct ConnRecord {
    pub uid: String,
    pub ts: f64,
    pub orig_h: String,
    pub orig_p: u16,
    pub resp_h: String,
    pub resp_p: u16,
    pub proto: &'static str,
    pub duration: f64,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
}

#[derive(Clone, Debug)]
pub struct DnsRecord {
    pub uid: String,
    pub ts: f64,
    pub orig_h: String,
    pub orig_p: u16,
    pub resp_h: String,
    pub resp_p: u16,
    pub proto: &'static str,
    pub query: String,
    pub qtype_name: String,
}

pub(crate) fn flow_uid(a_ip: &str, a_port: u16, b_ip: &str, b_port: u16, proto: &str) -> String {
    // Byte-for-byte the same input string pcap_parser.py hashes, so both
    // parsers produce IDENTICAL uids for the same flow -- the strongest
    // single-value equivalence check between the two implementations.
    let raw = format!("{a_ip}:{a_port}-{b_ip}:{b_port}-{proto}");
    let digest = Sha256::digest(raw.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    hex[..16].to_string()
}

fn port_rank(port: u16) -> u8 {
    if port < 1024 { 0 } else if port < 32768 { 1 } else { 2 }
}

/// True if the packet's SENDER should be recorded as the flow originator --
/// mirrors src/flow_orientation.py::sender_is_originator exactly.
pub(crate) fn sender_is_originator(proto: &str, sport: u16, dport: u16, tcp_flags: Option<u8>) -> bool {
    if proto == "tcp" {
        if let Some(flags) = tcp_flags {
            let syn = flags & TCP_SYN != 0;
            let ack = flags & TCP_ACK != 0;
            if syn && !ack { return true; }
            if syn && ack { return false; }
        }
    }
    let (rs, rd) = (port_rank(sport), port_rank(dport));
    if rs != rd { return rs > rd; }
    true
}

pub(crate) fn ipv4_to_string(b: &[u8]) -> String {
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

/// RFC 5952 canonical form -- NOT cosmetic: this string is what flow_uid
/// hashes, and the Python fallback (scapy, backed by the OS's
/// inet_ntop/inet_ntop-equivalent) already produces canonical form
/// (e.g. "2606:4700:4700::1111"). Found by direct side-by-side testing
/// (a real scapy-built IPv6/UDP/DNS packet through both paths): an
/// earlier, simpler uncompressed version of this function
/// ("2606:4700:4700:0:0:0:0:1111") produced a DIFFERENT flow_uid than
/// Python for the exact same real address -- the two paths would
/// silently disagree on identity for any IPv6 flow with a compressible
/// zero-run, which is most real IPv6 addresses. Matching Python exactly
/// matters more here than it would for IPv4 (which has no compression
/// ambiguity to begin with).
pub(crate) fn ipv6_to_string(b: &[u8]) -> String {
    let groups: [u16; 8] = std::array::from_fn(|i| u16::from_be_bytes([b[i * 2], b[i * 2 + 1]]));

    // Longest run of >=2 consecutive zero groups; leftmost wins a tie
    // (RFC 5952 §4.2.3).
    let (mut best_start, mut best_len) = (0usize, 0usize);
    let (mut cur_start, mut cur_len) = (0usize, 0usize);
    for (i, &g) in groups.iter().enumerate() {
        if g == 0 {
            if cur_len == 0 { cur_start = i; }
            cur_len += 1;
            if cur_len > best_len { best_start = cur_start; best_len = cur_len; }
        } else {
            cur_len = 0;
        }
    }
    if best_len < 2 { best_start = 8; best_len = 0; }  // no run worth compressing

    let mut out = String::new();
    let mut i = 0;
    while i < 8 {
        if i == best_start {
            out.push_str("::");
            i += best_len;
            continue;
        }
        if i > 0 && !out.ends_with(':') { out.push(':'); }
        out.push_str(&format!("{:x}", groups[i]));
        i += 1;
    }
    out
}

/// (src_ip, dst_ip, l4_proto_num, l4_payload) from an IPv4 or IPv6 header at
/// the start of `l3`. Shared by the upload-path parser (parse_packets,
/// below) and the live-path assembler (live.rs's LiveFlowAssembler::process)
/// so IPv6 extension-header walking exists in exactly ONE place, not two
/// independently-maintained copies -- this codebase already learned that
/// lesson once (src/flow_mapping.py's docstring documents a real bug from
/// exactly this kind of duplication: a field-name fix landing in one copy
/// but not another).
pub(crate) fn parse_ip_header(l3: &[u8]) -> Option<(String, String, u8, &[u8])> {
    if l3.is_empty() { return None; }
    match l3[0] >> 4 {
        4 => {
            if l3.len() < 20 { return None; }
            let ihl = ((l3[0] & 0x0f) as usize) * 4;
            if ihl < 20 || l3.len() < ihl { return None; }
            let proto_num = l3[9];
            let src_ip = ipv4_to_string(&l3[12..16]);
            let dst_ip = ipv4_to_string(&l3[16..20]);
            Some((src_ip, dst_ip, proto_num, &l3[ihl..]))
        }
        6 => {
            if l3.len() < 40 { return None; }
            let mut next_header = l3[6];
            let src_ip = ipv6_to_string(&l3[8..24]);
            let dst_ip = ipv6_to_string(&l3[24..40]);
            let mut off = 40usize;
            // Walk extension headers -- bounded against a hostile/malformed
            // packet (same "never loop forever on untrusted input" policy
            // as parse_dns_query's labels.len() > 64 bound below).
            for _ in 0..8 {
                match next_header {
                    // Hop-by-Hop(0)/Routing(43)/Destination Options(60):
                    // [next_header(1), hdr_ext_len(1), ...], length in
                    // 8-byte units per RFC 8200 §4. Authentication Header
                    // (51) shares the same layout but a DIFFERENT length
                    // unit (4-byte words + 2, RFC 4302 §2.2) -- handled
                    // separately, not folded into the same arm, so a wrong
                    // guess there can't silently misparse the other three.
                    0 | 43 | 60 => {
                        if l3.len() < off + 2 { return None; }
                        let hdr_len = (l3[off + 1] as usize + 1) * 8;
                        if l3.len() < off + hdr_len { return None; }
                        next_header = l3[off];
                        off += hdr_len;
                    }
                    51 => {
                        if l3.len() < off + 2 { return None; }
                        let hdr_len = (l3[off + 1] as usize + 2) * 4;
                        if l3.len() < off + hdr_len { return None; }
                        next_header = l3[off];
                        off += hdr_len;
                    }
                    44 => {
                        // Fragment header: always exactly 8 bytes, byte 1 is
                        // RESERVED (not a length field) -- RFC 8200 §4.5.
                        // The L4 header only exists in the first fragment;
                        // this parser doesn't reassemble fragments (same
                        // scope limit the IPv4/IHL path already has), so a
                        // non-first fragment is skipped cleanly, not guessed.
                        if l3.len() < off + 8 { return None; }
                        let frag_offset = u16::from_be_bytes([l3[off + 2], l3[off + 3]]) >> 3;
                        if frag_offset != 0 { return None; }
                        next_header = l3[off];
                        off += 8;
                    }
                    _ => break,  // TCP(6)/UDP(17)/ICMPv6(58)/anything else -- stop walking, hand off below
                }
            }
            Some((src_ip, dst_ip, next_header, l3.get(off..)?))
        }
        _ => None,
    }
}

pub(crate) struct L4<'a> {
    pub(crate) proto: &'static str,
    pub(crate) sport: u16,
    pub(crate) dport: u16,
    pub(crate) tcp_flags: Option<u8>,
    pub(crate) payload: &'a [u8],
}

/// Strips the link-layer header, returning the l3_payload for IPv4 (0x0800)
/// or IPv6 (0x86dd) over Ethernet or Linux-cooked-capture -- anything else
/// (ARP, and once ubiquitous but now legacy protocols) returns None. IPv6
/// was added after live-testing against this project's own real network
/// traffic found it was the MAJORITY protocol (76.6% of packets on a real
/// dual-stack Wi-Fi network, measured directly, not assumed) -- silently
/// dropping it here silently dropped detection for most real traffic.
pub(crate) fn strip_link_layer(linktype: u32, data: &[u8]) -> Option<&[u8]> {
    match linktype {
        LINKTYPE_ETHERNET => {
            if data.len() < 14 { return None; }
            let mut off = 12usize;
            let mut ethertype = u16::from_be_bytes([data[off], data[off + 1]]);
            off += 2;
            // 802.1Q VLAN tag(s) -- skip each one, matching what real
            // Ethernet-on-a-switch traffic (a VLAN trunk mirror) looks like.
            while ethertype == 0x8100 || ethertype == 0x88a8 {
                if data.len() < off + 4 { return None; }
                ethertype = u16::from_be_bytes([data[off + 2], data[off + 3]]);
                off += 4;
            }
            if ethertype != 0x0800 && ethertype != 0x86dd { return None; }
            data.get(off..)
        }
        LINKTYPE_LINUX_SLL => {
            // "Linux cooked capture v1": 16-byte header, protocol in the
            // last 2 bytes (same values as an Ethertype). Real captures on
            // this project's own test set use this linktype (e.g. any-
            // interface tcpdump captures) -- confirmed against 0day.pcap.
            if data.len() < 16 { return None; }
            let proto = u16::from_be_bytes([data[14], data[15]]);
            if proto != 0x0800 && proto != 0x86dd { return None; }
            data.get(16..)
        }
        _ => None,
    }
}

pub(crate) fn parse_l4(proto_num: u8, payload: &[u8]) -> Option<L4<'_>> {
    match proto_num {
        6 => {  // TCP
            if payload.len() < 20 { return None; }
            let sport = u16::from_be_bytes([payload[0], payload[1]]);
            let dport = u16::from_be_bytes([payload[2], payload[3]]);
            let data_off = ((payload[12] >> 4) as usize) * 4;
            if data_off < 20 || payload.len() < data_off { return None; }
            let flags = payload[13];
            Some(L4 { proto: "tcp", sport, dport, tcp_flags: Some(flags), payload: &payload[data_off..] })
        }
        17 => {  // UDP
            if payload.len() < 8 { return None; }
            let sport = u16::from_be_bytes([payload[0], payload[1]]);
            let dport = u16::from_be_bytes([payload[2], payload[3]]);
            let len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
            let body_start = 8usize;
            let body_end = len.max(body_start).min(payload.len());
            Some(L4 { proto: "udp", sport, dport, tcp_flags: None, payload: &payload[body_start..body_end] })
        }
        _ => None,
    }
}

/// Best-effort DNS QUESTION-section parse for the FIRST question only (qr==0
/// filter matches pcap_parser.py exactly -- responses are never re-scored as
/// queries). No compression-pointer chasing: the first name in a packet has
/// nothing earlier to point to in practice, and a name that doesn't parse
/// cleanly is skipped, never crashes the capture.
pub(crate) fn parse_dns_query(payload: &[u8]) -> Option<(String, u16)> {
    if payload.len() < 12 { return None; }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let qr = (flags >> 15) & 1;
    if qr != 0 { return None; }  // a response, not a query
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 { return None; }

    let mut pos = 12usize;
    let mut labels: Vec<String> = Vec::new();
    loop {
        if pos >= payload.len() { return None; }
        let len = payload[pos] as usize;
        if len == 0 { pos += 1; break; }
        if len & 0xc0 != 0 { return None; }  // compression pointer -- not chased, bail cleanly
        pos += 1;
        if pos + len > payload.len() { return None; }
        let label = std::str::from_utf8(&payload[pos..pos + len]).ok()?.to_string();
        labels.push(label);
        pos += len;
        if labels.len() > 64 { return None; }  // sane bound against a hostile packet
    }
    if pos + 2 > payload.len() { return None; }
    let qtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
    Some((labels.join("."), qtype))
}

/// DNS-over-TCP (RFC 1035 4.2.2): a 2-byte big-endian length prefix before
/// the DNS message. Best-effort, single-message-per-segment (matches this
/// codebase's existing "skip cleanly on anything more complex" policy) --
/// covers the common real case, e.g. CHAOS-class version.bind/id.server
/// fingerprinting queries, which is what real captures in this project's
/// own eval set actually send this way.
pub(crate) fn parse_dns_query_tcp(payload: &[u8]) -> Option<(String, u16)> {
    if payload.len() < 2 { return None; }
    let _len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    parse_dns_query(&payload[2..])
}

pub(crate) fn qtype_name(qtype: u16) -> String {
    match qtype {
        1 => "A", 16 => "TXT", 28 => "AAAA", 10 => "NULL", 5 => "CNAME",
        _ => return qtype.to_string(),
    }.to_string()
}

struct FlowState {
    orig_ip: String,
    orig_port: u16,
    resp_ip: String,
    resp_port: u16,
    proto: &'static str,
    first_ts: f64,
    last_ts: f64,
    orig_bytes: u64,
    resp_bytes: u64,
    orig_pkts: u64,
    resp_pkts: u64,
    uid: String,
}

pub struct ParseResult {
    pub conn: Vec<ConnRecord>,
    pub dns: Vec<DnsRecord>,
}

pub fn parse_packets(linktype: u32, packets: impl Iterator<Item = (f64, Vec<u8>)>, max_packets: Option<usize>) -> ParseResult {
    // IndexMap, not HashMap: iteration order below must be INSERTION order
    // (first-packet-seen order, scanning the file top to bottom), matching
    // pcap_parser.py's plain dict exactly -- see the Cargo.toml comment.
    let mut flows: IndexMap<(String, u16, String, u16, &'static str), FlowState> = IndexMap::new();
    let mut dns: Vec<DnsRecord> = Vec::new();
    let mut n = 0usize;

    for (ts, data) in packets {
        n += 1;
        if let Some(cap) = max_packets { if n > cap { break; } }

        let Some(l3) = strip_link_layer(linktype, &data) else { continue };
        let Some((src_ip, dst_ip, proto_num, l4_payload)) = parse_ip_header(l3) else { continue };

        let Some(l4) = parse_l4(proto_num, l4_payload) else { continue };

        // DNS query -- UDP port 53 (unicast DNS) or 5353 (mDNS -- scapy
        // binds the same DNS layer there, and real capture traffic uses it
        // heavily: e.g. "SirGabriel._dosvc._tcp.local"), or TCP port 53
        // (DNS-over-TCP, RFC 1035 4.2.2 -- e.g. CHAOS-class
        // version.bind/id.server fingerprinting queries, real traffic in
        // this project's own eval set, missed before this fix). Checked
        // before folding into `conn`, and DNS packets never also become a
        // conn record, matching pcap_parser.py's `continue` after
        // appending a dns record.
        let dns_hit = if l4.proto == "udp" && ([53, 5353].contains(&l4.sport) || [53, 5353].contains(&l4.dport)) {
            parse_dns_query(l4.payload)
        } else if l4.proto == "tcp" && (l4.sport == 53 || l4.dport == 53) {
            parse_dns_query_tcp(l4.payload)
        } else {
            None
        };
        if let Some((qname, qtype)) = dns_hit {
            dns.push(DnsRecord {
                uid: flow_uid(&src_ip, l4.sport, &dst_ip, l4.dport, l4.proto),
                ts, orig_h: src_ip.clone(), orig_p: l4.sport,
                resp_h: dst_ip.clone(), resp_p: l4.dport, proto: l4.proto,
                query: qname.trim_end_matches('.').to_string(),
                qtype_name: qtype_name(qtype),
            });
            continue;
        }

        // Canonical, direction-independent key so both halves of one
        // conversation land in the SAME flow record.
        let key = if (src_ip.as_str(), l4.sport) <= (dst_ip.as_str(), l4.dport) {
            (src_ip.clone(), l4.sport, dst_ip.clone(), l4.dport, l4.proto)
        } else {
            (dst_ip.clone(), l4.dport, src_ip.clone(), l4.sport, l4.proto)
        };

        let payload_len = l4.payload.len() as u64;
        let entry = flows.entry(key).or_insert_with(|| {
            let (orig_ip, orig_port, resp_ip, resp_port) =
                if sender_is_originator(l4.proto, l4.sport, l4.dport, l4.tcp_flags) {
                    (src_ip.clone(), l4.sport, dst_ip.clone(), l4.dport)
                } else {
                    (dst_ip.clone(), l4.dport, src_ip.clone(), l4.sport)
                };
            let uid = flow_uid(&orig_ip, orig_port, &resp_ip, resp_port, l4.proto);
            FlowState { orig_ip, orig_port, resp_ip, resp_port, proto: l4.proto,
                       first_ts: ts, last_ts: ts, orig_bytes: 0, resp_bytes: 0, orig_pkts: 0, resp_pkts: 0, uid }
        });
        entry.last_ts = entry.last_ts.max(ts);
        if src_ip == entry.orig_ip && l4.sport == entry.orig_port {
            entry.orig_bytes += payload_len;
            entry.orig_pkts += 1;
        } else {
            entry.resp_bytes += payload_len;
            entry.resp_pkts += 1;
        }
    }

    // `flows.into_values()` on an IndexMap yields values in FIRST-INSERTION
    // order -- i.e. the order each flow's first packet was encountered
    // scanning the file -- the same order pcap_parser.py's plain dict
    // naturally gives it (a Python dict has been insertion-ordered by
    // language guarantee since 3.7). std::HashMap deliberately randomizes
    // iteration order per process; several detection engines are stateful
    // and processing-order-sensitive (e.g. ENG-01's flood counter dedups
    // "first crossing per window," which depends on the order flows are
    // scored in), so relying on HashMap order here would be a real,
    // if usually-silent, source of run-to-run nondeterminism. IndexMap
    // removes that risk outright -- confirmed byte-for-byte identical
    // conn ordering against pcap_parser.py on real captures via
    // scripts/validate_native_parser.py.
    let conn: Vec<ConnRecord> = flows.into_values().map(|f| ConnRecord {
        uid: f.uid, ts: f.first_ts, orig_h: f.orig_ip, orig_p: f.orig_port,
        resp_h: f.resp_ip, resp_p: f.resp_port, proto: f.proto,
        duration: (f.last_ts - f.first_ts).max(0.0),
        orig_bytes: f.orig_bytes, resp_bytes: f.resp_bytes,
        orig_pkts: f.orig_pkts, resp_pkts: f.resp_pkts,
    }).collect();

    ParseResult { conn, dns }
}
