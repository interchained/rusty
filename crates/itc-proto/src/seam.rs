//! NEDB Proof-of-Prefix seam — the trust-anchor logic, ported from itcd's
//! net_processing seam plus the `g_warm_boot_mismatch` detection wired in itcd
//! PR #50.
//!
//! The node trusts an [`AnchorTip`]. Given headers a peer announced, it decides:
//!  - `Verified`: the peer's chain CONTAINS our tip (builds on it or includes it)
//!    → our tip is on the peer's chain; sync forward.
//!  - `Pending`: no positive containment yet (absence of evidence — normal when
//!    far behind). Mismatch is *proven* only with height + work context, via
//!    [`is_mismatch`], which the node's sync loop supplies (mirrors itcd, where
//!    the negative case needs `pindexLast` height/chainwork).

use crate::block::BlockHeader;

/// A chain tip the node ANCHORS to as truth, without re-deriving consensus.
///
/// `hash` is the block hash in internal (little-endian) byte order, as used on
/// the wire and in the NEDB store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorTip {
    pub height: i32,
    pub hash: [u8; 32],
}

impl AnchorTip {
    /// The genesis-only anchor (height 0). Used before the anchor responds.
    pub fn genesis() -> Self {
        AnchorTip {
            height: 0,
            hash: crate::genesis_hash_internal(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeamResult {
    Verified,
    Mismatch,
    Pending,
}

/// Evaluate the seam against a contiguous run of headers a peer announced
/// (chain order: each header builds on the previous).
///
/// Returns `Verified` if the peer's announced chain builds on, or contains, our
/// anchor tip. Otherwise `Pending` — proving a *mismatch* needs height/work
/// context (see [`is_mismatch`]); raw headers alone never assert a mismatch.
pub fn evaluate(tip: &AnchorTip, headers: &[BlockHeader]) -> SeamResult {
    if headers.is_empty() {
        return SeamResult::Pending;
    }
    // The peer extends our tip directly.
    if headers[0].prev_blockhash == tip.hash {
        return SeamResult::Verified;
    }
    // Our tip appears somewhere in the announced run (as a block or a parent).
    for h in headers {
        if h.prev_blockhash == tip.hash || h.block_hash() == tip.hash {
            return SeamResult::Verified;
        }
    }
    SeamResult::Pending
}

/// Proven-mismatch test, mirroring itcd PR #50 (validation.cpp / net_processing):
/// a peer presenting a STRICTLY-more-work valid chain whose block AT our tip
/// height is a different hash means our tip is provably NOT on the most-work
/// chain. `peer_block_at_tip_height == None` (peer chain not linked down to our
/// height) draws no conclusion — absence of evidence stays the watchdog's job.
pub fn is_mismatch(
    tip_height: i32,
    tip_hash: &[u8; 32],
    peer_best_height: i32,
    peer_strictly_more_work: bool,
    peer_block_at_tip_height: Option<&[u8; 32]>,
) -> bool {
    if !peer_strictly_more_work || peer_best_height < tip_height {
        return false;
    }
    match peer_block_at_tip_height {
        Some(h) => h != tip_hash,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(prev: [u8; 32]) -> BlockHeader {
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
    fn verified_when_peer_builds_on_tip() {
        let tip = AnchorTip { height: 10, hash: [0xaa; 32] };
        let headers = vec![hdr([0xaa; 32])]; // builds directly on our tip
        assert_eq!(evaluate(&tip, &headers), SeamResult::Verified);
    }

    #[test]
    fn pending_when_unrelated() {
        let tip = AnchorTip { height: 10, hash: [0xaa; 32] };
        let headers = vec![hdr([0xbb; 32]), hdr([0xcc; 32])];
        assert_eq!(evaluate(&tip, &headers), SeamResult::Pending);
    }

    #[test]
    fn empty_is_pending() {
        let tip = AnchorTip::genesis();
        assert_eq!(evaluate(&tip, &[]), SeamResult::Pending);
    }

    #[test]
    fn mismatch_rule() {
        let tip = [0xaa; 32];
        let other = [0xbb; 32];
        // strictly more work, reaches our height, different block there → mismatch
        assert!(is_mismatch(100, &tip, 120, true, Some(&other)));
        // same block at our height → no mismatch
        assert!(!is_mismatch(100, &tip, 120, true, Some(&tip)));
        // not more work → no mismatch
        assert!(!is_mismatch(100, &tip, 120, false, Some(&other)));
        // not linked down to our height → no conclusion
        assert!(!is_mismatch(100, &tip, 120, true, None));
    }
}
