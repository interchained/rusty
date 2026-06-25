//! Forward header sync — `getheaders` from the anchor, connect each batch to the
//! chain, and persist new headers + the tip into NEDB as we go.

use std::io;

use itc_proto::block::BlockHeader;

use crate::chain::{ConnectOutcome, HeaderChain};
use crate::p2p::Peer;
use crate::store::Store;

/// Sync headers forward from `peer` into `chain`, persisting into `store`.
pub fn sync_headers(peer: &mut Peer, chain: &mut HeaderChain, store: &Store) -> io::Result<()> {
    let target = peer.peer_height;
    let mut rounds = 0u32;
    loop {
        rounds += 1;
        let locator = chain.block_locator();
        let batch = peer.get_headers(locator)?;
        if batch.is_empty() {
            break;
        }
        let before = chain.tip_height();
        let mut to_persist: Vec<(BlockHeader, i32)> = Vec::new();
        for h in batch.iter() {
            match chain.connect(h.clone()) {
                ConnectOutcome::Extended(height) => to_persist.push((h.clone(), height)),
                ConnectOutcome::HeavierFork(ht) => {
                    println!(
                        "itc-node[sync]: heavier competing chain at height {ht} — Proof-of-Prefix MISMATCH flagged"
                    );
                }
                _ => {}
            }
        }
        // One batched engine write per round, then checkpoint the tip.
        store.put_headers_batch(&to_persist)?;
        store.put_tip(chain.tip_height(), &chain.tip_hash())?;

        let after = chain.tip_height();
        println!(
            "itc-node[sync]: +{} headers — tip now {after} / anchor {target}",
            to_persist.len()
        );
        if after == before {
            break; // no progress
        }
        if batch.len() < 2000 {
            break; // short batch → at the tip
        }
        if target > 0 && after >= target {
            break; // reached the anchor's height
        }
        if rounds > 100_000 {
            break; // hard safety cap
        }
    }
    Ok(())
}
