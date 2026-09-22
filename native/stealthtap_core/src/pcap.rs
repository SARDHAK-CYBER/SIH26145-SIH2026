//! Minimal classic-pcap (libpcap) file reader. No external crate -- the
//! format is a 24-byte global header followed by (16-byte record header +
//! packet bytes) repeated. pcapng is a different container and is NOT
//! handled here yet (see README note in lib.rs) -- every file in this
//! project's real-capture eval set except one is classic pcap.

use std::fs::File;
use std::io::{self, BufReader, Read};

pub struct PcapReader {
    reader: BufReader<File>,
    little_endian: bool,
    nanosecond: bool,
    pub linktype: u32,
}

pub struct RawPacket {
    pub ts: f64,
    pub data: Vec<u8>,
}

impl PcapReader {
    pub fn open(path: &str) -> io::Result<Self> {
        let mut reader = BufReader::new(File::open(path)?);
        let mut hdr = [0u8; 24];
        reader.read_exact(&mut hdr)?;
        let magic = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let (little_endian, nanosecond) = match magic {
            0xa1b2c3d4 => (true, false),
            0xd4c3b2a1 => (false, false),
            0xa1b23c4d => (true, true),
            0x4d3cb2a1 => (false, true),
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "not a classic pcap file (magic mismatch -- pcapng or corrupt)")),
        };
        let rd_u32 = |b: &[u8]| -> u32 {
            if little_endian { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) }
            else { u32::from_be_bytes([b[0], b[1], b[2], b[3]]) }
        };
        let linktype = rd_u32(&hdr[20..24]);
        Ok(Self { reader, little_endian, nanosecond, linktype })
    }

    fn read_u32(&mut self) -> io::Result<Option<u32>> {
        let mut b = [0u8; 4];
        match self.reader.read_exact(&mut b) {
            Ok(()) => Ok(Some(if self.little_endian { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) })),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Returns the next packet, or None at EOF. A truncated/corrupt final
    /// record ends iteration rather than erroring the whole parse -- the
    /// same "best effort on a possibly-imperfect capture" behaviour as the
    /// Python scapy path.
    pub fn next_packet(&mut self) -> io::Result<Option<RawPacket>> {
        let sec = match self.read_u32()? { Some(v) => v, None => return Ok(None) };
        let usec = match self.read_u32()? { Some(v) => v, None => return Ok(None) };
        let incl_len = match self.read_u32()? { Some(v) => v, None => return Ok(None) };
        let _orig_len = match self.read_u32()? { Some(v) => v, None => return Ok(None) };
        if incl_len > 200_000_000 {  // sanity bound, matches the API's own upload cap
            return Ok(None);
        }
        let mut data = vec![0u8; incl_len as usize];
        if self.reader.read_exact(&mut data).is_err() {
            return Ok(None);
        }
        let ts = sec as f64 + (usec as f64) / (if self.nanosecond { 1e9 } else { 1e6 });
        Ok(Some(RawPacket { ts, data }))
    }
}
