//! itc-node — a standalone, instant-boot, trust-the-anchor ITC relay peer.
//!
//! Proof of Sovereignty: this Rust binary is a first-class peer of the C++ itcd
//! node. It does NOT re-derive consensus and does NOT verify-then-boot. It boots
//! instantly, TRUSTS THE ANCHOR CHAIN (mainnet, via the seed anchor), and earns
//! its place by relaying.
//!
//! Slice 2 (this commit) makes the protocol + handshake real: it connects to the
//! seed anchor over the ITC P2P protocol, completes the version/verack handshake,
//! pulls the first header batch, and runs the Proof-of-Prefix seam. Storage,
//! full sync, serving, relay, and the ElectrumX wallet are the next slices.

mod anchor;
mod p2p;

use itc_proto as proto;
use itc_proto::seam::{self, SeamResult};

fn main() {
    // ── 1. Instant boot ──────────────────────────────────────────────────────
    // No verify-once, no replay, no warm-boot window check. We come up at once.
    println!(
        "itc-node {} — network=Main magic={:02x?} port={} genesis={}",
        env!("CARGO_PKG_VERSION"),
        proto::MAGIC_MAIN,
        proto::DEFAULT_P2P_PORT,
        proto::GENESIS_HASH_HEX,
    );

    // ── 2. Trust the anchor chain ────────────────────────────────────────────
    // Connect to the seed anchor and adopt its tip. The anchor's chain IS truth;
    // we never independently finalize.
    let endpoint = proto::SEED_ANCHOR;
    println!("itc-node: connecting to anchor {endpoint} ...");
    let (mut peer, tip) = match anchor::fetch_anchor_tip(endpoint, proto::MAGIC_MAIN) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("itc-node: anchor connect/handshake failed: {e} (is {endpoint} reachable?)");
            std::process::exit(1);
        }
    };
    println!(
        "itc-node: anchor handshake ok — peer ua={:?} version={} height={}",
        peer.peer_user_agent, peer.peer_version, peer.peer_height
    );
    println!("itc-node: trusting anchor tip — height {}", tip.height);

    // ── 3. Pull the first header batch and run the Proof-of-Prefix seam ───────
    // Our local tip starts at genesis; the seam tells us whether we're on the
    // anchor's chain (Verified) or merely far behind (Pending).
    let our_tip = proto::AnchorTip::genesis();
    match peer.get_headers(vec![proto::genesis_hash_internal()]) {
        Ok(headers) => {
            println!("itc-node: received {} headers from the anchor", headers.len());
            match seam::evaluate(&our_tip, &headers) {
                SeamResult::Verified => println!(
                    "itc-node[seam]: Proof-of-Prefix VERIFIED — our tip is on the anchor's chain; sync forward."
                ),
                SeamResult::Mismatch => println!(
                    "itc-node[seam]: MISMATCH — our tip is NOT on the anchor's chain."
                ),
                SeamResult::Pending => println!(
                    "itc-node[seam]: pending — anchor headers don't yet confirm our tip (normal when far behind)."
                ),
            }
            if let Some(first) = headers.first() {
                println!(
                    "itc-node: first header hash {} (prev {})",
                    proto::hashes::to_display_hex(&first.block_hash()),
                    proto::hashes::to_display_hex(&first.prev_blockhash),
                );
            }
            if let Some(last) = headers.last() {
                println!(
                    "itc-node: last header in batch {}",
                    proto::hashes::to_display_hex(&last.block_hash())
                );
            }
        }
        Err(e) => println!("itc-node: getheaders failed: {e}"),
    }

    println!("itc-node: slice-2 run complete (real handshake + headers + seam). Storage/sync/relay/wallet next.");
}
