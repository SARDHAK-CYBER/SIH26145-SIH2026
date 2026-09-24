//! Real JA4 TLS client fingerprint (FoxIO spec) -- a byte-for-byte Rust
//! port of src/capture/ja4.py, which is the validated reference (already
//! used in production on the live-capture path). Same algorithm, same
//! GREASE filtering, same field layout. Ported here so the native live
//! flow assembler doesn't have to call back into Python per-ClientHello.

use sha2::{Digest, Sha256};

const EXT_SNI: u16 = 0x0000;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002B;
const EXT_SIG_ALGS: u16 = 0x000D;

fn is_grease(v: u16) -> bool {
    (v & 0x0F0F) == 0x0A0A && (v >> 8) == (v & 0x00FF)
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(|s| u16::from_be_bytes([s[0], s[1]]))
}

fn tls_version_str(v: u16) -> &'static str {
    match v {
        0x0304 => "13", 0x0303 => "12", 0x0302 => "11", 0x0301 => "10",
        0x0300 => "s3", 0x0002 => "s2", _ => "00",
    }
}

/// None whenever the bytes aren't a cleanly parseable ClientHello -- same
/// "just omit ja4" contract as the Python original, never a panic.
pub fn ja4_from_client_hello(payload: &[u8]) -> Option<String> {
    if payload.len() < 6 { return None; }

    let (hs, _off) = if payload[0] == 0x16 {
        let rec_len = u16_at(payload, 3)? as usize;
        let start = 5usize;
        let end = if rec_len > 0 { (start + rec_len).min(payload.len()) } else { payload.len() };
        (payload.get(start..end)?, start)
    } else {
        (payload, 0usize)
    };
    if hs.len() < 4 || hs[0] != 0x01 { return None; }  // ClientHello

    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    let body_end = if hs_len > 0 { (4 + hs_len).min(hs.len()) } else { hs.len() };
    let body = hs.get(4..body_end)?;
    let mut p = 0usize;

    let legacy_version = u16_at(body, p)?; p += 2;
    p += 32;  // random
    let sid_len = *body.get(p)? as usize; p += 1 + sid_len;

    let cs_len = u16_at(body, p)? as usize; p += 2;
    let ciphers_raw = body.get(p..p + cs_len)?; p += cs_len;
    let mut ciphers: Vec<u16> = (0..ciphers_raw.len() / 2)
        .filter_map(|i| u16_at(ciphers_raw, i * 2))
        .filter(|c| !is_grease(*c))
        .collect();

    let comp_len = *body.get(p)? as usize; p += 1 + comp_len;

    let mut exts: Vec<u16> = Vec::new();
    let mut sni_present = false;
    let mut alpn_first = "00".to_string();
    let mut sig_algs_hex: Vec<String> = Vec::new();
    let mut best_version = legacy_version;

    if p + 2 <= body.len() {
        let ext_total = u16_at(body, p)? as usize; p += 2;
        let end = (p + ext_total).min(body.len());
        while p + 4 <= end {
            let etype = u16_at(body, p)?;
            let esize = u16_at(body, p + 2)? as usize;
            p += 4;
            // A ClientHello whose extensions section runs past what this
            // packet actually has (split across TCP segments -- this
            // function only ever sees one packet's payload, no reassembly)
            // must fail closed, not return a fingerprint computed from a
            // partial extension list. Found via live-traffic testing: on
            // the SAME real packets, this silently returned a WRONG JA4 in
            // 2 of 3 real TLS sessions where ja4.py (correct: any
            // out-of-bounds read raises and the wrapper returns None)
            // returned None. ENG-04 does an EXACT match against real
            // threat-intel JA4 hashes -- a wrong-but-plausible-looking
            // fingerprint is worse than no fingerprint, since it fails
            // silently instead of visibly (no `ssl` record at all, which
            // is what the flow's OTHER packets or a later retransmit can
            // still produce correctly).
            if p + esize > body.len() { return None; }
            let edata = &body[p..p + esize];
            p += esize;
            if is_grease(etype) { continue; }
            exts.push(etype);
            if etype == EXT_SNI {
                sni_present = true;
            } else if etype == EXT_ALPN && edata.len() >= 4 {
                let first_len = edata[2] as usize;
                if let Some(first) = edata.get(3..3 + first_len.min(edata.len().saturating_sub(3))) {
                    if !first.is_empty() {
                        alpn_first = if first[0].is_ascii_alphanumeric() {
                            format!("{}{}", first[0] as char, *first.last().unwrap() as char)
                        } else {
                            "99".to_string()
                        };
                    }
                }
            } else if etype == EXT_SUPPORTED_VERSIONS && edata.len() >= 3 {
                let list_len = edata[0] as usize;
                let mut i = 1usize;
                while i + 1 < 1 + list_len && i + 1 < edata.len() {
                    if let Some(v) = u16_at(edata, i) {
                        if !is_grease(v) {
                            let cur_rank: i32 = tls_version_str(best_version).parse().unwrap_or(0);
                            let new_rank: i32 = tls_version_str(v).parse().unwrap_or(-1);
                            if new_rank > cur_rank || tls_version_str(best_version) == "00" {
                                best_version = v;
                            }
                        }
                    }
                    i += 2;
                }
            } else if etype == EXT_SIG_ALGS && edata.len() >= 2 {
                let sa_len = u16_at(edata, 0)? as usize;
                let mut i = 2usize;
                while i + 1 < 2 + sa_len && i + 1 < edata.len() {
                    if let Some(v) = u16_at(edata, i) { sig_algs_hex.push(format!("{v:04x}")); }
                    i += 2;
                }
            }
        }
    }

    let tls_ver = tls_version_str(best_version);
    let sni_flag = if sni_present { "d" } else { "i" };
    let c_count = ciphers.len().min(99);
    let e_count = exts.len().min(99);
    let ja4_a = format!("t{tls_ver}{sni_flag}{c_count:02}{e_count:02}{alpn_first}");

    ciphers.sort_unstable();
    let ja4_b = if !ciphers.is_empty() {
        let list = ciphers.iter().map(|c| format!("{c:04x}")).collect::<Vec<_>>().join(",");
        hex12(&list)
    } else {
        "000000000000".to_string()
    };

    let mut ext_for_hash: Vec<u16> = exts.iter().copied().filter(|e| *e != EXT_SNI && *e != EXT_ALPN).collect();
    ext_for_hash.sort_unstable();
    let ja4_c = if !ext_for_hash.is_empty() {
        let ext_list = ext_for_hash.iter().map(|e| format!("{e:04x}")).collect::<Vec<_>>().join(",");
        let sig_list = sig_algs_hex.join(",");
        hex12(&format!("{ext_list}_{sig_list}"))
    } else {
        "000000000000".to_string()
    };

    Some(format!("{ja4_a}_{ja4_b}_{ja4_c}"))
}

fn hex12(s: &str) -> String {
    let digest = Sha256::digest(s.as_bytes());
    digest.iter().take(6).map(|b| format!("{b:02x}")).collect()
}
