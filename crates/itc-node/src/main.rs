//! itc-node — instant-boot, trust-the-anchor ITC relay peer (Proof of Sovereignty).
//!
//! Slice 4 (this commit): NEDB-backed persistence. On boot the node loads any
//! persisted header chain from nedb-engine (resume), trusts the anchor, syncs
//! forward — persisting new headers + the tip into NEDB as it goes — then seeds
//! the headers to inbound peers.
//!
//! Usage: `itc-node [LISTEN_PORT]`   (env `ITC_NODE_DATADIR` sets the store path,
//! default `./itc-node-data`).

mod anchor;
mod chain;
mod p2p;
mod serve;
mod store;
mod sync;

use std::sync::Arc;

use itc_proto as proto;

use crate::chain::HeaderChain;
use crate::store::Store;

fn main() {
    let listen_port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(proto::DEFAULT_P2P_PORT);
    let datadir = std::env::var("ITC_NODE_DATADIR").unwrap_or_else(|_| "./itc-node-data".to_string());

    println!(
        "itc-node {} — network=Main magic={:02x?} genesis={}",
        env!("CARGO_PKG_VERSION"),
        proto::MAGIC_MAIN,
        proto::GENESIS_HASH_HEX,
    );

    // ── 0. Open the NEDB store and resume any persisted chain (instant boot) ──
    let store = match Store::open(&datadir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("itc-node: store open failed at {datadir}: {e}");
            std::process::exit(1);
        }
    };
    println!("itc-node: store open at {datadir} (engine head {})", store.head());

    let mut chain = HeaderChain::new();
    let persisted = store.load_headers_to_tip();
    if !persisted.is_empty() {
        for h in persisted {
            chain.connect(h);
        }
        println!(
            "itc-node: resumed from store — tip height {} hash {}",
            chain.tip_height(),
            proto::hashes::to_display_hex(&chain.tip_hash()),
        );
    }

    // ── 1. Trust the anchor: connect + adopt its tip height ───────────────────
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

    // ── 2. Forward header sync — persist each batch into NEDB ─────────────────
    println!(
        "itc-node: syncing headers from {} (anchor target {}) ...",
        chain.tip_height(),
        anchor_tip.height
    );
    if let Err(e) = sync::sync_headers(&mut peer, &mut chain, &store) {
        eprintln!("itc-node: header sync error: {e}");
    }
    println!(
        "itc-node: sync done — tip height {} hash {}{} (engine head {})",
        chain.tip_height(),
        proto::hashes::to_display_hex(&chain.tip_hash()),
        if chain.mismatch() { "   [PROOF-OF-PREFIX MISMATCH]" } else { "" },
        store.head(),
    );

    // ── 3. Seed headers to inbound peers (the valued-peer behavior) ───────────
    let our_height = chain.tip_height();
    let chain = Arc::new(chain);
    let listen = format!("0.0.0.0:{listen_port}");
    if let Err(e) = serve::serve(&listen, proto::MAGIC_MAIN, chain, our_height) {
        eprintln!("itc-node: serve error on {listen}: {e}");
        std::process::exit(1);
    }
}
