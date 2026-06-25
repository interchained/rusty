//! Block-body download — fetch full blocks via `getdata(MSG_BLOCK)`, verify each
//! against its header hash, and persist via the NEDB store.

use std::io;

use itc_proto::hashes::{sha256d, to_internal_hex};

use crate::chain::HeaderChain;
use crate::p2p::Peer;
use crate::store::Store;

/// Download block bodies forward across the synced chain, skipping any already in
/// the store. `max == 0` means unlimited. Each block is verified (its first 80
/// bytes must hash to the expected block hash) before it is persisted. Returns
/// the count newly downloaded.
pub fn download_blocks(
    peer: &mut Peer,
    chain: &HeaderChain,
    store: &Store,
    max: usize,
) -> io::Result<usize> {
    let tip = chain.tip_height();
    let mut downloaded = 0usize;
    let mut height = 1i32;
    while height <= tip {
        if max != 0 && downloaded >= max {
            break;
        }
        let hash = match chain.hash_at_height(height) {
            Some(h) => h,
            None => {
                height += 1;
                continue;
            }
        };
        let id = to_internal_hex(&hash);
        if store.get_block(&id).is_some() {
            height += 1;
            continue; // already have this body
        }
        let raw = peer.get_block(hash)?;
        // A block's hash is the double-SHA256 of its 80-byte header (the prefix).
        if raw.len() < 80 || sha256d(&raw[..80]) != hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("block at height {height} ({id}) failed its header-hash check"),
            ));
        }
        store.put_block(&id, &raw)?;
        downloaded += 1;
        if downloaded % 100 == 0 {
            println!("itc-node[blocks]: downloaded {downloaded} blocks (height {height}/{tip})");
        }
        height += 1;
    }
    Ok(downloaded)
}
