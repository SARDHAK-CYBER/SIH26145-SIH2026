//! Kerberos KDC replies (AS-REP / TGS-REP) parsed from raw TCP/UDP port-88 payloads, so ENG-11
//! (Kerberoasting) works on live capture -- it used to be dormant there because Kerberos is
//! binary ASN.1/DER, not text like HTTP, and Zeek (which decodes it for the Docker path) is not
//! in the live path.
//!
//! What is read (all cleartext in the reply; only the TICKET body is encrypted):
//!   crealm/cname  -> "who": the requesting principal   ("user/REALM", Zeek's `client`)
//!   ticket.sname  -> "what": the service the ticket is for (Zeek's `service`)
//!   ticket.enc-part.etype -> "how strong": the cipher the ticket is sealed with (Zeek's `cipher`)
//! Kerberoasting is exactly "a TGS ticket for a service account sealed with RC4" -- see
//! src/engines/eng11_kerberos.py. Field semantics follow Zeek's base/protocols/krb.
//!
//! Strictly bounds-checked: anything that doesn't parse cleanly yields None, never a panic.

pub struct KrbReply {
    pub request_type: &'static str,   // "AS" | "TGS"
    pub client: String,               // "cname/REALM"
    pub service: String,              // "krbtgt" or "http/host"
    pub cipher: String,               // zeek-style cipher name
}

/// (tag, value, rest) of one DER TLV at the start of `b`.
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if b.len() < 2 { return None; }
    let tag = b[0];
    let (len, hdr) = if b[1] & 0x80 == 0 {
        (b[1] as usize, 2usize)
    } else {
        let n = (b[1] & 0x7f) as usize;
        if n == 0 || n > 4 || b.len() < 2 + n { return None; }
        let mut l = 0usize;
        for i in 0..n { l = (l << 8) | b[2 + i] as usize; }
        (l, 2 + n)
    };
    if b.len() < hdr + len { return None; }
    Some((tag, &b[hdr..hdr + len], &b[hdr + len..]))
}

/// Iterate the [n] context-tagged fields of a SEQUENCE body: (n, inner-value).
fn fields(seq_body: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    let mut rest = seq_body;
    while let Some((tag, val, r)) = tlv(rest) {
        if tag & 0xe0 == 0xa0 { out.push((tag & 0x1f, val)); }
        rest = r;
    }
    out
}

fn field<'a>(fs: &[(u8, &'a [u8])], n: u8) -> Option<&'a [u8]> {
    fs.iter().find(|(k, _)| *k == n).map(|(_, v)| *v)
}

fn ascii(b: &[u8]) -> String {
    b.iter().map(|&c| if (32..127).contains(&c) { c as char } else { '?' }).collect()
}

/// PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQUENCE OF GeneralString }
fn principal(v: &[u8]) -> Option<Vec<String>> {
    let (t, body, _) = tlv(v)?;
    if t != 0x30 { return None; }
    let fs = fields(body);
    let names = field(&fs, 1)?;
    let (t2, seq, _) = tlv(names)?;
    if t2 != 0x30 { return None; }
    let mut out = Vec::new();
    let mut rest = seq;
    while let Some((_, s, r)) = tlv(rest) { out.push(ascii(s)); rest = r; }
    Some(out)
}

fn etype_of(v: &[u8]) -> Option<i64> {
    // EncryptedData ::= SEQUENCE { etype [0] Int32, kvno [1] ..., cipher [2] OCTET STRING }
    let (t, body, _) = tlv(v)?;
    if t != 0x30 { return None; }
    let fs = fields(body);
    let (ti, iv, _) = tlv(field(&fs, 0)?)?;
    if ti != 0x02 || iv.is_empty() || iv.len() > 4 { return None; }
    let mut n: i64 = if iv[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in iv { n = (n << 8) | b as i64; }
    Some(n)
}

fn cipher_name(etype: i64) -> String {
    match etype {
        1 => "des-cbc-crc", 2 => "des-cbc-md4", 3 => "des-cbc-md5", 16 => "des3-cbc-sha1",
        17 => "aes128-cts-hmac-sha1-96", 18 => "aes256-cts-hmac-sha1-96",
        19 => "aes128-cts-hmac-sha256-128", 20 => "aes256-cts-hmac-sha384-192",
        23 => "rc4-hmac", 24 => "rc4-hmac-exp",
        n => return format!("unknown-{n}"),
    }.to_string()
}

/// `payload` is the TCP payload (4-byte length prefix) or the UDP payload of a packet FROM port 88.
pub fn parse_kdc_reply(payload: &[u8], tcp: bool) -> Option<KrbReply> {
    let mut p = payload;
    if tcp {
        if p.len() < 4 { return None; }
        let l = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) as usize;
        p = &p[4..];
        if l == 0 || p.len() < l { return None; }   // KDC reply split across segments: skip, never guess
        p = &p[..l];
    }
    let (tag, body, _) = tlv(p)?;
    let request_type = match tag { 0x6b => "AS", 0x6d => "TGS", _ => return None };   // [APPLICATION 11] / [APPLICATION 13]
    let (t, seq, _) = tlv(body)?;
    if t != 0x30 { return None; }
    let fs = fields(seq);
    let realm = field(&fs, 3).and_then(|v| tlv(v)).map(|(_, s, _)| ascii(s)).unwrap_or_default();
    let cname = principal(field(&fs, 4)?)?.join("/");
    // ticket [5]: [APPLICATION 1] SEQUENCE { tkt-vno [0], realm [1], sname [2], enc-part [3] }
    let (tt, tbody, _) = tlv(field(&fs, 5)?)?;
    if tt != 0x61 { return None; }
    let (ts, tseq, _) = tlv(tbody)?;
    if ts != 0x30 { return None; }
    let tf = fields(tseq);
    let service = principal(field(&tf, 2)?)?;
    let cipher = cipher_name(etype_of(field(&tf, 3)?)?);
    Some(KrbReply {
        request_type,
        client: if realm.is_empty() { cname } else { format!("{cname}/{realm}") },
        service: service.first().cloned().unwrap_or_default().to_lowercase() + &service.iter().skip(1).map(|s| format!("/{s}")).collect::<String>(),
        cipher,
    })
}
