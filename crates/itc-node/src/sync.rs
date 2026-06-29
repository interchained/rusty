//! Sync — header sync and full block body download from the anchor peer.

use std::io;

use itc_proto::block::BlockHeader;
use itc_proto::hashes::to_internal_hex;

use crate::chain::{ConnectOutcome, HeaderChain};
use crate::p2p::Peer;
use crate::store::Store;

/// Batch size for block body downloads. 16 is conservative — peers typically
/// allow up to 128 outstanding block requests, but we start small.
const BLOCK_BATCH: i32 = 16;

// ── Header sync ──────────────────────────────────────────────────────────────

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
        store.put_headers_batch(&to_persist)?;
        store.put_tip(chain.tip_height(), &chain.tip_hash())?;

        let after = chain.tip_height();
        // Single-line overwriting progress bar
        {
            let pct = if target > 0 { (after as f64 / target as f64 * 100.0) as u32 } else { 0 };
            let filled = ((pct as usize) * 20 / 100).min(20);
            let bar = "█".repeat(filled) + &"░".repeat(20 - filled);
            eprint!("\r  [headers] {after:>7}/{target} [{bar}] {pct:>3}%   ");
        }
        if after == before {
            break;
        }
        if batch.len() < 2000 {
            eprintln!(); // end progress bar line
            break;
        }
        if target > 0 && after >= target {
            eprintln!(); // end progress bar line
            break;
        }
        if rounds > 100_000 {
            eprintln!(); // end progress bar line
            break;
        }
    }
    Ok(())
}

// ── Block body download ───────────────────────────────────────────────────────

/// Download full block bodies for every block we have a header for but no body.
/// Walks the active chain from height 1 to tip, batching getdata requests.
/// Already-stored blocks are skipped (idempotent, resume-safe).
/// Returns (downloaded, skipped) counts.
pub fn sync_blocks(peer: &mut Peer, chain: &HeaderChain, store: &Store, start_height: i32) -> io::Result<(u64, u64)> {
    let tip = chain.tip_height();
    if tip < 1 {
        return Ok((0, 0));
    }
    let mut downloaded = 0u64;
    let mut skipped = 0u64;
    let mut height = start_height.max(1);

    while height <= tip {
        let batch_end = (height + BLOCK_BATCH - 1).min(tip);
        let hashes = chain.active_range(height, batch_end);

        // Filter to blocks we don't have yet.
        let needed: Vec<[u8; 32]> = hashes
            .iter()
            .filter(|h| !store.has_block(&to_internal_hex(*h)))
            .cloned()
            .collect();

        skipped += (hashes.len() - needed.len()) as u64;

        if !needed.is_empty() {
            let blocks = peer.request_blocks(&needed)?;
            for block in blocks {
                let hash_hex = to_internal_hex(&block.block_hash());
                store.put_block(&hash_hex, &block.raw)?;
                downloaded += 1;
            }
            if downloaded % 100 == 0 && downloaded > 0 {
                println!(
                    "itc-node[blocks]: downloaded {downloaded} blocks — height ~{} / {tip}",
                    height + BLOCK_BATCH
                );
            }
        }

        height = batch_end + 1;
    }
    Ok((downloaded, skipped))
}
