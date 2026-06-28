//! itc-node — ITC-L2 full peer node (Proof of Sovereignty).
//!
//! Slice 7: L1 anchor OP_RETURN poster. After syncing, a background thread fires
//! every ITC_ANCHOR_INTERVAL epochs and broadcasts an OP_RETURN tx to ITC L1
//! carrying the NEDB Merkle head — the sovereignty proof that the L2 state is
//! anchored on-chain. Dry-run if ITC_ANCHOR_WIF is not set.
//!
//! Slice 5: full block body download + peer citizenship. The node now:
//!   - Resumes persisted headers + block bodies from NEDB on boot (instant start)
//!   - Syncs all headers from the anchor
//!   - Downloads full block bodies (getdata → block) and stores them in NEDB
//!   - Serves headers AND full blocks to inbound peers (getdata, getheaders)
//!   - Handles inv from peers — fetches blocks we don't have (stays current)
//!
//! The node is a first-class citizen of the ITC network.
//!
//! Usage: `itc-node [LISTEN_PORT]`
//! Env:   ITC_NODE_DATADIR (default: ./itc-node-data)

mod anchor;
mod chain;
mod p2p;
mod serve;
mod store;
mod sync;

use std::sync::Arc;

use itc_proto as proto;

use itc_anchor::{AnchorConfig, AnchorPoster};
use itc_evm::ItcEvm;
use itc_oracle::{DepositOracle, OracleConfig};
use itc_rpc::RpcServer;

use crate::chain::HeaderChain;
use crate::store::Store;

fn main() {
    let listen_port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(proto::DEFAULT_P2P_PORT);
    let datadir = std::env::var("ITC_NODE_DATADIR")
        .unwrap_or_else(|_| "./itc-node-data".to_string());

    println!(
        "itc-node {} — network=Main magic={:02x?} genesis={}",
        env!("CARGO_PKG_VERSION"),
        proto::MAGIC_MAIN,
        proto::GENESIS_HASH_HEX,
    );

    // ── 0. Open NEDB store + resume persisted chain (instant boot) ────────────
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

    // ── 1. Trust the anchor ───────────────────────────────────────────────────
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

    // ── 2. Header sync ────────────────────────────────────────────────────────
    println!(
        "itc-node: syncing headers from height {} (anchor target {}) ...",
        chain.tip_height(),
        anchor_tip.height
    );
    if let Err(e) = sync::sync_headers(&mut peer, &mut chain, &store) {
        eprintln!("itc-node: header sync error: {e}");
    }
    println!(
        "itc-node: headers done — tip {} hash {}{} (engine head {})",
        chain.tip_height(),
        proto::hashes::to_display_hex(&chain.tip_hash()),
        if chain.mismatch() { "  [PROOF-OF-PREFIX MISMATCH]" } else { "" },
        store.head(),
    );

    // ── 3. Deposit oracle setup ───────────────────────────────────────────────
    // The oracle processes each block as it's downloaded, detecting bridge deposits
    // and minting native aITC after DEPOSIT_CONFIRMATIONS confirmations.
    // Configure ITC_BRIDGE_HASH160 (20-byte hex) to activate live deposits.
    let oracle_config = OracleConfig::from_env();
    let mut oracle = DepositOracle::new(oracle_config, Arc::clone(&store.db));
    println!(
        "itc-node[oracle]: deposit scanner armed (ITC_BRIDGE_HASH160={})",
        hex::encode(itc_oracle::OracleConfig::from_env().bridge_lock_hash160)
    );

    // ── 4. Block body download ────────────────────────────────────────────────
    // Download full block bodies for every height we have a header for.
    // This is what makes us a full peer: we can serve blocks, not just headers.
    println!(
        "itc-node: downloading block bodies (tip height {}) — this may take a while ...",
        chain.tip_height()
    );
    match sync::sync_blocks(&mut peer, &chain, &store) {
        Ok((downloaded, skipped)) => println!(
            "itc-node: block download done — {downloaded} downloaded, {skipped} already had"
        ),
        Err(e) => eprintln!("itc-node: block download error (partial progress saved): {e}"),
    }
    println!("itc-node: engine head after sync: {}", store.head());

    // ── 4. L1 anchor poster — sovereignty proof on ITC mainnet ───────────────
    // Spawns a background thread that fires every ITC_ANCHOR_INTERVAL epochs and
    // broadcasts an OP_RETURN tx to ITC L1 carrying the NEDB Merkle head.
    // Dry-run if ITC_ANCHOR_WIF is not set (logs what would be posted).
    {
        let anchor_config = AnchorConfig::from_env(endpoint, proto::MAGIC_MAIN);
        let anchor_db = Arc::clone(&store);
        AnchorPoster::new(anchor_config, anchor_db.db.clone()).spawn();
        println!("itc-node[anchor]: poster spawned (set ITC_ANCHOR_WIF to go live)");
    }

    // ── 5. eth_* JSON-RPC server ──────────────────────────────────────────────
    // MetaMask-compatible endpoint. Bind: ITC_RPC_ADDR (default 0.0.0.0:8545).
    {
        let rpc_addr = std::env::var("ITC_RPC_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8545".to_string());
        let evm = ItcEvm::new(Arc::clone(&store.db));
        RpcServer::new(evm).spawn(rpc_addr);
    }

    // ── 6. Serve — headers + block bodies to inbound peers ───────────────────
    let our_height = chain.tip_height();
    let chain = Arc::new(chain);
    let store = Arc::new(store);
    let listen = format!("0.0.0.0:{listen_port}");
    if let Err(e) = serve::serve(&listen, proto::MAGIC_MAIN, chain, store, our_height) {
        eprintln!("itc-node: serve error on {listen}: {e}");
        std::process::exit(1);
    }
}
