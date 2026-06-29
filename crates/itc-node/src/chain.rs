//! In-memory header chain: links headers by `prev_blockhash`, assigns heights and
//! cumulative chainwork, tracks the active (most-work linear) chain, and wires the
//! Proof-of-Prefix mismatch detection (via `itc_proto::seam::is_mismatch`).

use std::collections::HashMap;

use itc_proto::block::BlockHeader;
use itc_proto::seam;
use itc_proto::work::{work_from_bits, U256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// Extended the active tip to this height.
    Extended(i32),
    /// Already known.
    Duplicate,
    /// Parent not in the chain (cannot link).
    Orphan,
    /// A strictly-heavier competing chain that differs from us at our tip height
    /// → our active tip is provably not the most-work chain (mismatch flagged).
    HeavierFork(i32),
    /// A competing branch that is not heavier than our active tip.
    SideFork(i32),
}

pub struct HeaderChain {
    headers: HashMap<[u8; 32], BlockHeader>,
    height: HashMap<[u8; 32], i32>,
    work: HashMap<[u8; 32], U256>,
    /// active[h] = block hash at height h on the most-work linear chain.
    active: Vec<[u8; 32]>,
    tip_hash: [u8; 32],
    tip_work: U256,
    mismatch: bool,
}

impl HeaderChain {
    /// A fresh chain seeded with genesis at height 0 (chainwork 0 — the genesis
    /// baseline is common to every candidate, so relative comparisons are exact).
    pub fn new() -> HeaderChain {
        let genesis = itc_proto::genesis_hash_internal();
        let mut height = HashMap::new();
        height.insert(genesis, 0i32);
        let mut work = HashMap::new();
        work.insert(genesis, U256::ZERO);
        HeaderChain {
            headers: HashMap::new(),
            height,
            work,
            active: vec![genesis],
            tip_hash: genesis,
            tip_work: U256::ZERO,
            mismatch: false,
        }
    }


    /// Resume from a trusted persisted tip without replaying all 600k+ headers.
    ///
    /// Allocates the `active` chain index with the tip hash at the correct slot.
    /// Ancestor slots are zero (unknown) — the block locator sends the tip hash
    /// first; if the peer recognizes it (which it will on the real chain) it
    /// replies with 0 new headers and sync finishes instantly. Falls back to
    /// genesis slot if the tip moved (reorg), which triggers a full catch-up.
    ///
    /// Memory: ~32 bytes × height ≈ 20 MB for a 648k-height chain. Acceptable.
    pub fn resume_from_tip(height: i32, hash: [u8; 32]) -> HeaderChain {
        let genesis = itc_proto::genesis_hash_internal();
        let mut height_map = HashMap::new();
        height_map.insert(genesis, 0i32);
        height_map.insert(hash, height);
        let mut work_map = HashMap::new();
        work_map.insert(genesis, U256::ZERO);

        // active[h] = block hash at height h. Unknown ancestors filled with zeros.
        let mut active = vec![[0u8; 32]; (height + 1) as usize];
        active[0] = genesis;
        active[height as usize] = hash;

        HeaderChain {
            headers: HashMap::new(),
            height: height_map,
            work: work_map,
            active,
            tip_hash: hash,
            tip_work: U256::ZERO, // unknown — only used for fork detection, safe to zero
            mismatch: false,
        }
    }

    pub fn tip_height(&self) -> i32 {
        self.active.len() as i32 - 1
    }
    pub fn tip_hash(&self) -> [u8; 32] {
        self.tip_hash
    }
    #[allow(dead_code)]
    pub fn tip_work(&self) -> U256 {
        self.tip_work
    }
    pub fn mismatch(&self) -> bool {
        self.mismatch
    }
    #[allow(dead_code)]
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.height.contains_key(hash)
    }

    /// Connect a header to the chain.
    pub fn connect(&mut self, h: BlockHeader) -> ConnectOutcome {
        let hh = h.block_hash();
        if self.height.contains_key(&hh) {
            return ConnectOutcome::Duplicate;
        }
        let prev = h.prev_blockhash;
        let ph = match self.height.get(&prev) {
            Some(&p) => p,
            None => return ConnectOutcome::Orphan,
        };
        let pw = *self.work.get(&prev).unwrap_or(&U256::ZERO);
        let new_h = ph + 1;
        let new_work = pw.add(work_from_bits(h.bits));

        self.height.insert(hh, new_h);
        self.work.insert(hh, new_work);
        self.headers.insert(hh, h);

        // Common case: extends the active tip → grow the active chain.
        if prev == self.tip_hash {
            self.active.push(hh);
            self.tip_hash = hh;
            self.tip_work = new_work;
            return ConnectOutcome::Extended(new_h);
        }

        // A competing branch. Run the real mismatch test against our active tip.
        let our_h = self.tip_height();
        let at = self.ancestor_hash_at(hh, our_h);
        let more = new_work > self.tip_work;
        if seam::is_mismatch(our_h, &self.tip_hash, new_h, more, at.as_ref()) {
            self.mismatch = true;
            return ConnectOutcome::HeavierFork(new_h);
        }
        ConnectOutcome::SideFork(new_h)
    }

    /// Walk back from `hash` (following parents) to the block at `target_h`.
    fn ancestor_hash_at(&self, start: [u8; 32], target_h: i32) -> Option<[u8; 32]> {
        let mut hash = start;
        loop {
            let h = *self.height.get(&hash)?;
            if h == target_h {
                return Some(hash);
            }
            if h < target_h {
                return None;
            }
            hash = self.headers.get(&hash)?.prev_blockhash;
        }
    }

    /// Hash at a given height on the active chain, or None if out of range.
    pub fn active_hash_at(&self, height: i32) -> Option<[u8; 32]> {
        self.active.get(height as usize).copied()
    }

    /// Hashes for [start..=end] on the active chain (inclusive, capped at tip).
    pub fn active_range(&self, start: i32, end: i32) -> Vec<[u8; 32]> {
        let end = end.min(self.tip_height());
        if start < 0 || start > end {
            return Vec::new();
        }
        self.active[(start as usize)..=(end as usize)].to_vec()
    }

    /// Standard Bitcoin block locator from the active tip (last 10 by one, then
    /// doubling steps, always ending at genesis).
    pub fn block_locator(&self) -> Vec<[u8; 32]> {
        let mut loc = Vec::new();
        let mut height = self.tip_height();
        let mut step = 1i32;
        let mut count = 0;
        while height >= 0 {
            loc.push(self.active[height as usize]);
            if height == 0 {
                break;
            }
            count += 1;
            if count >= 10 {
                step *= 2;
            }
            height -= step;
            if height < 0 {
                height = 0;
            }
        }
        loc
    }

    /// Serve headers after the best locator match on our active chain (up to 2000,
    /// stopping at `hash_stop`). Powers the seeding side.
    pub fn headers_after_locator(&self, locator: &[[u8; 32]], hash_stop: &[u8; 32]) -> Vec<BlockHeader> {
        let mut start = 0i32;
        for hash in locator {
            if let Some(&h) = self.height.get(hash) {
                if (h as usize) < self.active.len() && self.active[h as usize] == *hash && h > start {
                    start = h;
                }
            }
        }
        let mut out = Vec::new();
        let mut h = (start + 1) as usize;
        while h < self.active.len() && out.len() < 2000 {
            let hash = self.active[h];
            if let Some(hdr) = self.headers.get(&hash) {
                out.push(hdr.clone());
                if hash == *hash_stop {
                    break;
                }
            }
            h += 1;
        }
        out
    }
}

impl Default for HeaderChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn child(prev: [u8; 32]) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_blockhash: prev,
            merkle_root: [0u8; 32],
            time: 1,
            bits: 0x1d00_ffff,
            nonce: 0,
        }
    }

    #[test]
    fn extends_from_genesis() {
        let mut c = HeaderChain::new();
        let genesis = itc_proto::genesis_hash_internal();
        let h1 = child(genesis);
        assert_eq!(c.connect(h1.clone()), ConnectOutcome::Extended(1));
        let h2 = child(h1.block_hash());
        assert_eq!(c.connect(h2.clone()), ConnectOutcome::Extended(2));
        assert_eq!(c.tip_height(), 2);
        assert_eq!(c.tip_hash(), h2.block_hash());
        assert_eq!(c.connect(h1), ConnectOutcome::Duplicate);
        assert!(!c.mismatch());
    }

    #[test]
    fn orphan_when_parent_missing() {
        let mut c = HeaderChain::new();
        assert_eq!(c.connect(child([0x99; 32])), ConnectOutcome::Orphan);
    }

    #[test]
    fn locator_starts_at_tip_ends_at_genesis() {
        let mut c = HeaderChain::new();
        let genesis = itc_proto::genesis_hash_internal();
        let mut prev = genesis;
        for _ in 0..5 {
            let h = child(prev);
            c.connect(h.clone());
            prev = h.block_hash();
        }
        let loc = c.block_locator();
        assert_eq!(loc[0], c.tip_hash());
        assert_eq!(*loc.last().unwrap(), genesis);
    }
}
