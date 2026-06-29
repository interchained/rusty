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
mod sequencer;
mod serve;
mod store;
mod sync;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use itc_proto as proto;

use std::sync::Mutex;

use itc_anchor::{AnchorConfig, AnchorPoster};
use itc_evm::ItcEvm;
use itc_rpc::RpcServer;

use crate::sequencer::{new_mempool, Sequencer};

use crate::chain::HeaderChain;
use crate::store::Store;

fn main() {
    // Use ITC_P2P_PORT to avoid conflict with interchainedd (17333) on same host.
    let listen_port: u16 = std::env::var("ITC_P2P_PORT")
        .ok().and_then(|s| s.parse().ok())
        .or_else(|| std::env::args().nth(1).and_then(|s| s.parse().ok()))
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

    // ── ASCII boot art ────────────────────────────────────────────────────────
    println!();
    println!(r#"  ██████╗ ██╗   ██╗███████╗████████╗██╗   ██╗"#);
    println!(r#"  ██╔══██╗██║   ██║██╔════╝╚══██╔══╝╚██╗ ██╔╝"#);
    println!(r#"  ██████╔╝██║   ██║███████╗   ██║    ╚████╔╝ "#);
    println!(r#"  ██╔══██╗██║   ██║╚════██║   ██║     ╚██╔╝  "#);
    println!(r#"  ██║  ██║╚██████╔╝███████║   ██║      ██║   "#);
    println!(r#"  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝      ╚═╝   "#);
    println!();
    println!("  ITC-L2 Node  ·  by Mark × Vex  ·  © Interchained LLC 2026");
    println!("  \"Not your keys, not your chain.\"");
    println!();
    println!("itc-node: store open at {datadir} (engine head {})", store.head());

    // ── Graceful shutdown: Ctrl-C / SIGTERM → flush tip then exit ────────────
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let flag = Arc::clone(&shutdown);
        ctrlc::set_handler(move || {
            // Set flag; the main loop sees it between batches and exits cleanly.
            if !flag.load(Ordering::Relaxed) {
                eprintln!("\nitc-node: shutdown signal — flushing after current batch...");
                flag.store(true, Ordering::SeqCst);
            }
        }).expect("Failed to set Ctrl-C handler");
    }

    // Resume from persisted tip — O(1) vs O(648k) header replay.
    // The block locator sends the tip hash first; if the peer recognises it the
    // sync finishes in a single round-trip.  Falls back to genesis on reorg.
    let mut chain = if let Some((tip_h, tip_hash)) = store.get_tip() {
        println!(
            "itc-node: resumed from store — tip height {tip_h} hash {}",
            proto::hashes::to_display_hex(&tip_hash),
        );
        HeaderChain::resume_from_tip(tip_h, tip_hash)
    } else {
        println!("itc-node: no persisted tip — syncing from genesis");
        HeaderChain::new()
    };

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
    if let Err(e) = sync::sync_headers(&mut peer, &mut chain, &store, &shutdown) {
        eprintln!("itc-node: header sync error: {e}");
    }
    println!(
        "itc-node: headers done — tip {} hash {}{} (engine head {})",
        chain.tip_height(),
        proto::hashes::to_display_hex(&chain.tip_hash()),
        if chain.mismatch() { "  [PROOF-OF-PREFIX MISMATCH]" } else { "" },
        store.head(),
    );

    // Bridge oracle only — UTXO mirror removed (lock-and-mint is the sole aITC minting path).
    let oracle_start_height: i32 = std::env::var("ITC_ORACLE_START_HEIGHT")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(1).max(1);
    if oracle_start_height > 1 {
        println!("itc-node[oracle]: checkpoint start — scanning from height {oracle_start_height}");
    }

    // ── 4. Block body download ────────────────────────────────────────────────
    // Download full block bodies for every height we have a header for.
    // This is what makes us a full peer: we can serve blocks, not just headers.
    println!(
        "itc-node: downloading block bodies (tip height {}) — this may take a while ...",
        chain.tip_height()
    );
    // Flush tip in case shutdown was requested during header sync
    if shutdown.load(Ordering::Relaxed) {
        let _ = store.put_tip(chain.tip_height(), &chain.tip_hash());
        eprintln!("itc-node: tip flushed at height {} — clean shutdown", chain.tip_height());
        return;
    }

    match sync::sync_blocks(&mut peer, &chain, &store, oracle_start_height, &shutdown) {
        Ok((downloaded, skipped)) => println!(
            "itc-node: block download done — {downloaded} downloaded, {skipped} already had"
        ),
        Err(e) => eprintln!("itc-node: block download error (partial progress saved): {e}"),
    }
    println!("itc-node: engine head after sync: {}", store.head());

    // ── 3b. Bridge deposit oracle scan ───────────────────────────────────────
    // Walk oracle_start_height..tip, calling DepositOracle::process_block on each.
    // Idempotent (oracle_minted guard) and reboot-safe (oracle_pending in NEDB).
    {
        use itc_oracle::{DepositOracle, OracleConfig};
        let oracle_cfg = OracleConfig::from_env();
        let mut oracle = DepositOracle::new(oracle_cfg, Arc::clone(&store.db));
        let tip = chain.tip_height();
        println!("itc-node[oracle]: scanning {oracle_start_height}..{tip} for bridge deposits...");
        let mut total_minted = 0usize;
        for h in oracle_start_height..=tip {
            if shutdown.load(Ordering::Relaxed) { break; }
            if let Some(hash) = chain.active_hash_at(h) {
                let hash_hex = itc_proto::hashes::to_internal_hex(&hash);
                if let Some(raw) = store.get_block(&hash_hex) {
                    let minted = oracle.process_block(&raw, h);
                    total_minted += minted.len();
                    for d in &minted {
                        println!(
                            "[ORACLE] minted deposit from {} at L1 height {} → 0x{}",
                            d.l1_txid_display, h, hex::encode(d.aitc_address),
                        );
                    }
                }
            }
        }
        println!("itc-node[oracle]: scan done — {total_minted} deposit(s) confirmed");
    }

    // Flush tip on block-sync shutdown
    if shutdown.load(Ordering::Relaxed) {
        let _ = store.put_tip(chain.tip_height(), &chain.tip_hash());
        eprintln!("itc-node: tip flushed at height {} — clean shutdown", chain.tip_height());
        return;
    }


    // ── 4. L1 anchor poster — sovereignty proof on ITC mainnet ───────────────
    // Spawns a background thread that fires every ITC_ANCHOR_INTERVAL epochs and
    // broadcasts an OP_RETURN tx to ITC L1 carrying the NEDB Merkle head.
    // Dry-run if ITC_ANCHOR_WIF is not set (logs what would be posted).
    {
        let anchor_config = AnchorConfig::from_env(endpoint, proto::MAGIC_MAIN);
        // The Store's `db` field is already an Arc<Db>; clone the Arc so the
        // poster thread holds its own owned handle while `store` is still owned
        // here (we Arc it later for the serve loop).
        let anchor_db = store.db.clone();
        AnchorPoster::new(anchor_config, anchor_db).spawn();
        println!("itc-node[anchor]: poster spawned (set ITC_ANCHOR_WIF to go live)");
    }

    // ── 5. EVM + sequencer + eth_* JSON-RPC ──────────────────────────────────
    // Shared EVM executor, mempool, and epoch counter wired across RPC + sequencer.
    let evm_shared = Arc::new(Mutex::new(ItcEvm::new(Arc::clone(&store.db))));
    let mempool = new_mempool();
    let epoch = {
        let rpc_server = RpcServer::new_shared(
            Arc::clone(&evm_shared),
            Arc::clone(&mempool),
        ).with_db(Arc::clone(&store.db));
        let epoch = rpc_server.epoch_counter();
        let rpc_addr = std::env::var("ITC_RPC_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8545".to_string());
        rpc_server.spawn_shared(rpc_addr);
        epoch
    };

    // L2 block sequencer — ticks every 5s, drains mempool, executes txs, persists receipts
    Sequencer::new(
        Arc::clone(&evm_shared),
        Arc::clone(&mempool),
        Arc::clone(&epoch),
        Arc::clone(&store.db),
    ).spawn();
    println!("itc-node[seq]: L2 sequencer started (5s blocks)");

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
