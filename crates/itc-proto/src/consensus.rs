//! Minimal consensus (de)serialization — the Bitcoin wire encoding subset the
//! ITC node needs: little-endian integers, CompactSize var-ints, 32-byte hashes,
//! and var-strings.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    UnexpectedEof,
    InvalidValue(&'static str),
}

pub type Result<T> = core::result::Result<T, Error>;

/// A cursor reader over a byte slice.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::UnexpectedEof);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_bytes(1)?[0])
    }
    pub fn read_u16_le(&mut self) -> Result<u16> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    pub fn read_u32_le(&mut self) -> Result<u32> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn read_i32_le(&mut self) -> Result<i32> {
        Ok(self.read_u32_le()? as i32)
    }
    pub fn read_u64_le(&mut self) -> Result<u64> {
        let b = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }
    pub fn read_i64_le(&mut self) -> Result<i64> {
        Ok(self.read_u64_le()? as i64)
    }
    pub fn read_hash(&mut self) -> Result<[u8; 32]> {
        let mut h = [0u8; 32];
        h.copy_from_slice(self.read_bytes(32)?);
        Ok(h)
    }
    pub fn read_array16(&mut self) -> Result<[u8; 16]> {
        let mut a = [0u8; 16];
        a.copy_from_slice(self.read_bytes(16)?);
        Ok(a)
    }
    /// Read a Bitcoin CompactSize var-int.
    pub fn read_compact_size(&mut self) -> Result<u64> {
        let n = self.read_u8()?;
        match n {
            0xff => self.read_u64_le(),
            0xfe => Ok(self.read_u32_le()? as u64),
            0xfd => Ok(self.read_u16_le()? as u64),
            _ => Ok(n as u64),
        }
    }
    /// Read a var-string (CompactSize length prefix + raw bytes, lossy UTF-8).
    pub fn read_var_str(&mut self) -> Result<String> {
        let len = self.read_compact_size()? as usize;
        let b = self.read_bytes(len)?;
        Ok(String::from_utf8_lossy(b).into_owned())
    }
    /// Peek at the next byte without advancing.
    pub fn peek_u8(&self) -> Result<u8> {
        if self.pos >= self.buf.len() {
            return Err(Error::UnexpectedEof);
        }
        Ok(self.buf[self.pos])
    }
    /// Return a slice of all remaining bytes (without advancing).
    pub fn peek_remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
    /// Advance by `n` bytes without reading.
    pub fn skip(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.buf.len());
    }
}

// ---- writers (append to a Vec<u8>) ----
pub fn put_u8(v: &mut Vec<u8>, x: u8) {
    v.push(x);
}
pub fn put_u16_le(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}
pub fn put_u32_le(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}
pub fn put_i32_le(v: &mut Vec<u8>, x: i32) {
    v.extend_from_slice(&x.to_le_bytes());
}
pub fn put_u64_le(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}
pub fn put_i64_le(v: &mut Vec<u8>, x: i64) {
    v.extend_from_slice(&x.to_le_bytes());
}
pub fn put_hash(v: &mut Vec<u8>, h: &[u8; 32]) {
    v.extend_from_slice(h);
}
pub fn put_compact_size(v: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        v.push(n as u8);
    } else if n <= 0xffff {
        v.push(0xfd);
        put_u16_le(v, n as u16);
    } else if n <= 0xffff_ffff {
        v.push(0xfe);
        put_u32_le(v, n as u32);
    } else {
        v.push(0xff);
        put_u64_le(v, n);
    }
}
pub fn put_var_str(v: &mut Vec<u8>, s: &str) {
    put_compact_size(v, s.len() as u64);
    v.extend_from_slice(s.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_size_roundtrip() {
        for n in [0u64, 1, 0xfc, 0xfd, 0xffff, 0x1_0000, 0xffff_ffff, 0x1_0000_0000] {
            let mut v = Vec::new();
            put_compact_size(&mut v, n);
            let mut r = Reader::new(&v);
            assert_eq!(r.read_compact_size().unwrap(), n);
            assert!(r.is_empty());
        }
    }

    #[test]
    fn ints_and_strings_roundtrip() {
        let mut v = Vec::new();
        put_u32_le(&mut v, 0x1234_5678);
        put_i64_le(&mut v, -42);
        put_var_str(&mut v, "/itc-node-rs:0.2.0/");
        let mut r = Reader::new(&v);
        assert_eq!(r.read_u32_le().unwrap(), 0x1234_5678);
        assert_eq!(r.read_i64_le().unwrap(), -42);
        assert_eq!(r.read_var_str().unwrap(), "/itc-node-rs:0.2.0/");
        assert!(r.is_empty());
    }

    #[test]
    fn eof_is_error() {
        let mut r = Reader::new(&[0x01u8]);
        assert!(r.read_u32_le().is_err());
    }
}
