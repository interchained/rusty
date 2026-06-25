//! Block header — the 80-byte Bitcoin/ITC header and its hash.

use crate::consensus::{self, Reader, Result};
use crate::hashes;

/// An 80-byte block header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: i32,
    pub prev_blockhash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl BlockHeader {
    /// Consensus-serialize the 80-byte header.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(80);
        consensus::put_i32_le(&mut v, self.version);
        consensus::put_hash(&mut v, &self.prev_blockhash);
        consensus::put_hash(&mut v, &self.merkle_root);
        consensus::put_u32_le(&mut v, self.time);
        consensus::put_u32_le(&mut v, self.bits);
        consensus::put_u32_le(&mut v, self.nonce);
        v
    }

    /// Decode an 80-byte header from a reader.
    pub fn decode(r: &mut Reader) -> Result<BlockHeader> {
        Ok(BlockHeader {
            version: r.read_i32_le()?,
            prev_blockhash: r.read_hash()?,
            merkle_root: r.read_hash()?,
            time: r.read_u32_le()?,
            bits: r.read_u32_le()?,
            nonce: r.read_u32_le()?,
        })
    }

    /// Block hash = double-SHA256 of the 80-byte header (internal byte order).
    pub fn block_hash(&self) -> [u8; 32] {
        hashes::sha256d(&self.encode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip_and_hash_len() {
        let h = BlockHeader {
            version: 0x2000_0000,
            prev_blockhash: [0x11; 32],
            merkle_root: [0x22; 32],
            time: 1_600_000_000,
            bits: 0x1d00_ffff,
            nonce: 42,
        };
        let enc = h.encode();
        assert_eq!(enc.len(), 80);
        let mut r = Reader::new(&enc);
        let dec = BlockHeader::decode(&mut r).unwrap();
        assert_eq!(h, dec);
        assert!(r.is_empty());
        assert_eq!(h.block_hash().len(), 32);
    }
}
