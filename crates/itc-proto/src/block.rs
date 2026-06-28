//! Block types — the 80-byte header and the full block (header + raw wire bytes).

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

/// A full block: decoded header plus the complete raw P2P wire bytes
/// (header || varint_tx_count || serialized txns). Stored raw so we can
/// persist and re-serve without re-encoding; slice 6 (EVM) decodes the txns.
#[derive(Clone, Debug)]
pub struct Block {
    /// Decoded header — for hash/height lookup and PoW verification.
    pub header: BlockHeader,
    /// Exact bytes as received in the `block` P2P message payload.
    pub raw: Vec<u8>,
}

impl Block {
    /// Parse a block from raw wire bytes (must be ≥ 80 bytes).
    pub fn from_raw(raw: Vec<u8>) -> Option<Block> {
        if raw.len() < 80 {
            return None;
        }
        let mut r = Reader::new(&raw[..80]);
        let header = BlockHeader::decode(&mut r).ok()?;
        Some(Block { header, raw })
    }

    pub fn block_hash(&self) -> [u8; 32] {
        self.header.block_hash()
    }

    pub fn size(&self) -> usize {
        self.raw.len()
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

    #[test]
    fn block_from_raw_too_short_is_none() {
        assert!(Block::from_raw(vec![0u8; 79]).is_none());
    }

    #[test]
    fn block_from_raw_minimal() {
        let h = BlockHeader {
            version: 1, prev_blockhash: [0u8; 32], merkle_root: [0u8; 32],
            time: 0, bits: 0x1d00_ffff, nonce: 0,
        };
        let mut raw = h.encode();
        raw.push(0); // varint tx_count = 0
        let b = Block::from_raw(raw.clone()).unwrap();
        assert_eq!(b.block_hash(), h.block_hash());
        assert_eq!(b.raw, raw);
    }
}
