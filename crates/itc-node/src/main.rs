//! itc-node — a standalone, instant-boot, trust-the-anchor ITC relay peer.
//!
//! Proof of Sovereignty: this Rust binary is a first-class peer of the C++ itcd
//! node. It boots instantly, TRUSTS THE ANCHOR CHAIN, syncs the header chain
//! forward from the anchor, and then SEEDS those headers back to inbound peers —
//! giving to the network, not leeching.
//!
//! Slice 3 (this commit): real forward header sync (heights + 256-bit chainwork +
//! the Proof-of-Prefix mismatch test) and a seeding server. Block bodies, storage
//! (nedb-engine), tx relay, and the ElectrumX wallet are the next slices.
//!
//! Usage: `itc-node [LISTEN_PORT]`  (default LISTEN_PORT = 17333)

mod anchor;
mod chain;
mod p2p;
mod serve;
mod sync;

use std::sync::Arc;

use itc_proto as proto;

use crate::chain::HeaderChain;

fn main() {
    let listen_port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(proto::DEFAULT_P2P_PORT);

    println!(
        "itc-node {} — network=Main magic={:02x?} genesis={}",
        env!("CARGO_PKG_VERSION"),
        proto::MAGIC_MAIN,
        proto::GENESIS_HASH_HEX,
    );

    // ── 1. Instant boot: connect to the anchor, adopt its tip height ──────────
    let endpoint = proto::SEED_ANCHOR;
    println!("itc-node: connecting to anchor {endpoint} ...");
    let (mut peer, anchor_tip) = match anchor::fetch_anchor_tip(endpoint, proto::MAGIC_MAIN) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("itc-node: anchor connect/handshake failed: {e} (is {endpoint} reachable?)");
            std::process::exit(1);
        }
    };
    println!(
        "itc-node: anchor handshake ok — ua={:?} version={} height={}",
        peer.peer_user_agent, peer.peer_version, peer.peer_height
    );

    // ── 2. Forward header sync — build the chain, assign heights + chainwork ──
    let mut chain = HeaderChain::new();
    println!(
        "itc-node: syncing headers from the anchor (target height {}) ...",
        anchor_tip.height
    );
    if let Err(e) = sync::sync_headers(&mut peer, &mut chain) {
        eprintln!("itc-node: header sync error: {e}");
    }
    println!(
        "itc-node: header sync done — tip height {} hash {}{}",
        chain.tip_height(),
        proto::hashes::to_display_hex(&chain.tip_hash()),
        if chain.mismatch() { "   [PROOF-OF-PREFIX MISMATCH]" } else { "" },
    );

    // ── 3. Seed: serve our headers to inbound peers (the valued-peer behavior) ─
    let our_height = chain.tip_height();
    let chain = Arc::new(chain);
    let listen = format!("0.0.0.0:{listen_port}");
    if let Err(e) = serve::serve(&listen, proto::MAGIC_MAIN, chain, our_height) {
        eprintln!("itc-node: serve error on {listen}: {e}");
        std::process::exit(1);
    }
}
