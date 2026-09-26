//! Application-service attack decoders (plain-text services): SMTP user enumeration, HTTP authentication attempts and
//! admin-deployment endpoints, distcc remote execution.
//!
//! `parse_appsvc` inspects one TCP payload and returns `(function, detail, code)`; `code` carries a rule bit the engine
//! reads (see src/engines/eng14_appsvc.py). It never emits a password: HTTP Basic credentials are decoded in memory,
//! compared against a short default-credential list, and only the USER NAME and a "default credential" flag leave here.
//! Python mirror: src/capture/appsvc.py (kept in parity by tests/test_appsvc.py).

const SMTP_PORTS: [u16; 3] = [25, 587, 2525];

/// user:password pairs shipped as vendor defaults on the services this rule set targets (Tomcat manager, generic admin
/// consoles). Presenting one over CLEARTEXT HTTP is itself a finding.
const DEFAULT_CREDS: &[&str] = &[
    "tomcat:tomcat", "tomcat:s3cret", "tomcat:admin", "admin:tomcat", "admin:admin", "admin:password", "admin:", "admin:1234",
    "admin:12345", "root:root", "root:toor", "root:password", "manager:manager", "role1:role1", "both:tomcat", "guest:guest",
    "cisco:cisco", "user:user", "test:test",
];

const COMPILERS: &[&str] = &["gcc", "g++", "cc", "c++", "cpp", "clang", "clang++", "as", "ld", "cc1", "cc1plus"];

fn b64(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in s {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

fn starts_ci(p: &[u8], prefix: &[u8]) -> bool {
    p.len() >= prefix.len() && p[..prefix.len()].eq_ignore_ascii_case(prefix)
}

fn lossy(b: &[u8], max: usize) -> String {
    let s: String = String::from_utf8_lossy(&b[..b.len().min(max)]).chars().filter(|c| !c.is_control()).collect();
    s.trim().to_string()
}

fn header<'a>(block: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    for line in block.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.len() > name.len() && line[name.len()] == b':' && line[..name.len()].eq_ignore_ascii_case(name) {
            return Some(line[name.len() + 1..].trim_ascii());
        }
    }
    None
}

/// Endpoints whose purpose is to run attacker-supplied code on the server (Tomcat manager WAR deployment, Jenkins script console).
fn admin_deploy(method: &[u8], path: &str) -> bool {
    let p = path.split('?').next().unwrap_or("").to_ascii_lowercase();
    let write = method == b"POST" || method == b"PUT";
    write && (p.starts_with("/manager/html/upload") || p.starts_with("/manager/text/deploy") || p.starts_with("/manager/html/deploy")
        || p == "/manager/deploy" || p == "/script" || p == "/scripttext")
}

fn distcc(p: &[u8]) -> Option<(String, String, u32)> {
    // "DIST" + 8 hex (protocol version) + "ARGC" + 8 hex, then ARGC x ("ARGV" + 8 hex length + bytes)
    if p.len() < 24 || &p[..4] != b"DIST" || &p[12..16] != b"ARGC" {
        return None;
    }
    let hex = |b: &[u8]| -> Option<usize> { usize::from_str_radix(std::str::from_utf8(b).ok()?, 16).ok() };
    hex(&p[4..12])?;
    let argc = hex(&p[16..24])?;
    let (mut i, mut args): (usize, Vec<String>) = (24, Vec::new());
    for _ in 0..argc.min(64) {
        if p.len() < i + 12 || &p[i..i + 4] != b"ARGV" {
            break;
        }
        let n = hex(&p[i + 4..i + 12])?;
        let start = i + 12;
        let end = start.checked_add(n)?.min(p.len());
        args.push(lossy(&p[start..end], 160));
        i = start.checked_add(n)?;
        if i >= p.len() {
            break;
        }
    }
    let argv0 = args.first().map(|a| a.rsplit('/').next().unwrap_or("").to_ascii_lowercase()).unwrap_or_default();
    let is_compiler = COMPILERS.contains(&argv0.as_str())
        || argv0.ends_with("-gcc") || argv0.ends_with("-g++") || argv0.starts_with("gcc-") || argv0.starts_with("g++-") || argv0.starts_with("clang-");
    let detail: String = args.iter().skip(1).take(5).cloned().collect::<Vec<_>>().join(" ").chars().take(160).collect();
    Some((format!("distcc:{argv0}"), detail, if is_compiler { 0 } else { 1 }))
}

fn request(p: &[u8]) -> Option<(String, String, u32)> {
    let end = p.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 2).unwrap_or(p.len().min(2048));
    let head = &p[..end.min(p.len())];
    let line_end = head.iter().position(|&b| b == b'\n')?;
    let line = head[..line_end].strip_suffix(b"\r").unwrap_or(&head[..line_end]);
    let mut it = line.splitn(3, |&b| b == b' ');
    let method = it.next()?;
    let path = std::str::from_utf8(it.next()?).ok()?;
    if !it.next()?.starts_with(b"HTTP/1.") || !matches!(method, b"GET" | b"POST" | b"PUT" | b"HEAD" | b"DELETE") {
        return None;
    }
    if admin_deploy(method, path) {
        return Some(("http_admin_deploy".to_string(), lossy(path.as_bytes(), 96), 1));
    }
    let auth = header(&head[line_end..], b"authorization")?;
    if !starts_ci(auth, b"basic ") {
        return None;
    }
    let cs = String::from_utf8_lossy(&b64(&auth[6..])?).to_string();
    let user: String = cs.split(':').next().unwrap_or("").chars().take(64).collect();
    let default = DEFAULT_CREDS.contains(&cs.as_str());
    Some(("http_basic".to_string(), user, default as u32))
}

pub fn parse_appsvc(p: &[u8], sport: u16, dport: u16) -> Option<(String, String, u32)> {
    let _ = dport;
    let first = *p.first()?;
    // client -> server SMTP verbs used to learn which accounts exist
    if matches!(first, b'V' | b'v' | b'E' | b'e' | b'R' | b'r') {
        for (verb, name) in [(&b"VRFY "[..], "smtp_vrfy"), (&b"EXPN "[..], "smtp_expn"), (&b"RCPT TO:"[..], "smtp_rcpt")] {
            if starts_ci(p, verb) && p.len() < 300 && p.ends_with(b"\n") {
                let arg = lossy(&p[verb.len()..], 80);
                let user = arg.trim_matches(|c| c == '<' || c == '>' || c == ' ').split('@').next().unwrap_or("").to_string();
                return Some((name.to_string(), user, 0));
            }
        }
        return None;
    }
    // server -> client SMTP 55x: the negative answers a harvesting run produces
    if first == b'5' && SMTP_PORTS.contains(&sport) && p.len() >= 4 && p[1] == b'5' && p[2].is_ascii_digit() && (p[3] == b' ' || p[3] == b'-') {
        return Some(("smtp_reject".to_string(), String::new(), 500 + 50 + (p[2] - b'0') as u32));
    }
    if first == b'D' && p.starts_with(b"DIST") {
        return distcc(p);
    }
    if first == b'H' {
        if p.len() >= 12 && &p[..7] == b"HTTP/1." && &p[8..12] == b" 401" {
            return Some(("http_401".to_string(), String::new(), 401));
        }
        if starts_ci(p, b"HEAD ") {
            return request(p);
        }
        return None;
    }
    if matches!(first, b'G' | b'P' | b'D') {
        return request(p);
    }
    None
}
