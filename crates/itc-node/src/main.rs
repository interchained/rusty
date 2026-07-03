//! itc-node — ITC-L2 full peer node (Proof of Sovereignty).
//!
//! An anchor-trust relay: it trusts the anchor's chain (Proof-of-Prefix, see
//! `itc_proto::seam`) rather than re-deriving consensus — `work_from_bits` is used
//! only for relative fork comparison, feeding the mismatch detector, not PoW
//! validation. On top of the trusted L1 view it runs an L2 PoA sidechain (EVM +
//! sequencer) bridged by a deposit/exit oracle, and anchors its own state back to
//! L1 via an OP_RETURN poster — the sovereignty proof that the L2 state is
//! provably tied to the chain it trusts.
//!
//! What it does, end to end:
//!   - Resumes headers + block bodies + L2 state from NEDB on boot (instant start,
//!     no replay — see "Boot & durability" below)
//!   - Syncs all headers from the anchor, downloads full block bodies, and serves
//!     both to inbound peers (a first-class peer, not just a light client)
//!   - Scans confirmed L1 blocks for bridge deposits and mints on L2
//!   - Runs the L2 sequencer (EVM execution, `eth_*` JSON-RPC, exit scanning)
//!   - Posts the NEDB Merkle head back to L1 periodically (sovereignty anchor)
//!
//! ## Boot & durability
//!
//! Resume is O(1): `store.tip_header()` reads the chain tip directly from the
//! engine's own durable per-collection tip (`nedb_engine::Db::tip_collection`,
//! nedb-engine v2.5.44+) — no synthetic marker document, no full header replay.
//! That primitive is kept current on every header write and survives a warm
//! restart with no scan, so "resume from tip" and "the tip that's actually
//! durable" are the same read, by construction — not two things kept in sync by
//! hand.
//!
//! Flushing is NOT per-put — it is checkpointed on natural batch/block-count
//! boundaries so buffered writes never drift far from disk without adding I/O to
//! the hot path: `sync_headers` every round (`getheaders` returns up to 2000),
//! `sync_blocks` every ~2000 downloaded bodies, the L2 sequencer every 500
//! produced blocks. All three share one `Arc<Db>`, so any one checkpoint flushes
//! L1 header/block progress and L2 receipts together. On `Ctrl-C`/`SIGTERM`, the
//! handler installed below flushes immediately and unconditionally.
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


    // ── Replay mode: wipe L2 derived state, keep L1 headers+blocks ───────────
    let replay = std::env::args().any(|a| a == "--replay")
        || std::env::var("ITC_ORACLE_REPLAY").is_ok();
    if replay {
        println!("itc-node[replay]: wiping L2 state — L1 headers+blocks preserved");
        // L2 collections (NEDB stores each collection as a subdirectory)
        let l2_collections = [
            "evm_accounts", "evm_storage", "evm_code",
            "l2_receipts",
            "oracle_minted", "oracle_pending", "oracle_state",
        ];
        for coll in &l2_collections {
            let path = format!("{datadir}/{coll}");
            if std::path::Path::new(&path).exists() {
                match std::fs::remove_dir_all(&path) {
                    Ok(_)  => println!("itc-node[replay]: ✓ wiped {coll}"),
                    Err(e) => eprintln!("itc-node[replay]: failed to wipe {coll}: {e}"),
                }
            }
        }
        println!("itc-node[replay]: clean slate — oracle will re-derive from L1 blocks");
        println!();
    }

    // ── 0. Open NEDB store + resume persisted chain (instant boot) ────────────
    let store = match Store::open(&datadir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("itc-node: store open failed at {datadir}: {e}");
            std::process::exit(1);
        }
    };
    println!("itc-node: store open at {datadir} (engine head {})", store.head());

    // ── Boot splash + config ──────────────────────────────────────────────────
    println!();
    println!(r#"  ██████╗ ██╗   ██╗███████╗████████╗██╗   ██╗"#);
    println!(r#"  ██╔══██╗██║   ██║██╔════╝╚══██╔══╝╚██╗ ██╔╝"#);
    println!(r#"  ██████╔╝██║   ██║███████╗   ██║    ╚████╔╝ "#);
    println!(r#"  ██╔══██╗██║   ██║╚════██║   ██║     ╚██╔╝  "#);
    println!(r#"  ██║  ██║╚██████╔╝███████║   ██║      ██║   "#);
    println!(r#"  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝      ╚═╝   "#);
    println!();
    println!("  ITC-L2 Node  ·  by Mark × Vex  ·  © Interchained LLC 2026");
    println!(r#"  "Not your keys, not your chain.""#);
    println!();
    {
        let mask = |v: &str| -> String {
            if v.is_empty() || v.starts_with('(') { return v.to_string(); }
            if v.len() <= 8 { return "*".repeat(v.len()); }
            format!("{}...{}", &v[..4], &v[v.len()-4..])
        };
        let get = |k: &str, def: &str| std::env::var(k).unwrap_or_else(|_| def.to_string());
        let wif      = get("ITC_ANCHOR_WIF",        "(not set — dry-run)");
        let rpc_user = get("ITC_L1_RPC_USER",       "(not set)");
        let rpc_pass = get("ITC_L1_RPC_PASS",       "(not set)");
        println!("  ┌─────────────────────────────────────────────────────┐");
        println!("  │  datadir    {}", get("ITC_NODE_DATADIR",  "./itc-node-data"));
        println!("  │  p2p-port   {}", get("ITC_P2P_PORT",      "17333 (default — conflicts with interchainedd!)"));
        println!("  │  rpc-addr   {}", get("ITC_RPC_ADDR",      "0.0.0.0:8545"));
        println!("  ├─────────────────────────────────────────────────────┤");
        println!("  │  bridge     {}", get("ITC_BRIDGE_ADDRESS","(not set)"));
        println!("  │  fee-bps    {}",  get("ITC_BRIDGE_FEE_BPS","500"));
        println!("  │  confirms   {}",  get("ITC_BRIDGE_CONFIRMATIONS","6"));
        println!("  │  start-h    {}",  get("ITC_ORACLE_START_HEIGHT","1 (full scan)"));
        println!("  ├─────────────────────────────────────────────────────┤");
        println!("  │  anchor-wif {}", mask(&wif));
        println!("  │  l1-rpc     {}", get("ITC_L1_RPC_URL","(not set)"));
        println!("  │  l1-user    {}", mask(&rpc_user));
        println!("  │  l1-pass    {}", mask(&rpc_pass));
        println!("  └─────────────────────────────────────────────────────┘");
        println!();
    }

    // ── Graceful shutdown: Ctrl-C / SIGTERM → guaranteed flush then exit ────
    //
    // The `ctrlc` crate already owns SIGINT/SIGTERM for this process, so the fix
    // here is NOT `nedb_engine::Db::install_exit_flush` (a second signal handler
    // for the same signals would race this one — exactly the anti-pattern that
    // would be wrong to introduce). The fix is making THIS handler flush for real.
    //
    // Previously this called `put_tip()` — a hand-rolled marker doc + a
    // MANIFEST-only flush that never touched the id-index WAL, which is why a
    // Ctrl+C mid-sync could "flush" and still resume from genesis on restart.
    // `flush_all()` is the engine's real durability primitive (WAL + segment sync
    // + MANIFEST, including the tip); `tip_header()` (used to resume — below)
    // reads the real last-connected header directly, so no manually-tracked
    // shadow copy of "the current tip" needs to live in this process anymore.
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let flag     = Arc::clone(&shutdown);
        let flush_db = Arc::clone(&store.db);
        ctrlc::set_handler(move || {
            if !flag.swap(true, Ordering::SeqCst) {
                eprintln!("\nitc-node: shutdown signal received — flushing...");
                flush_db.flush_all();
                eprintln!("itc-node: flushed — safe to restart. bye.");
                // Return from the handler — Ctrl+C interrupted the serve loop's accept()
                // syscall (EINTR), which causes serve() to return an error. The serve error
                // handler checks the shutdown flag and exits main() naturally, letting Rust
                // drop all values including NEDB (which flushes its WAL on Drop).
            } else {
                eprintln!("itc-node: force quit.");
                std::process::exit(1); // second Ctrl-C: immediate hard exit
            }
        }).expect("Failed to set Ctrl-C handler");
    }

    // Resume from persisted tip — O(1) vs O(648k) header replay. Backed by
    // nedb_engine::Db::tip_collection("headers"), durable across a warm restart
    // with no scan (nedb-engine v2.5.44+) — not a hand-rolled marker document.
    // The block locator sends the tip hash first; if the peer recognises it the
    // sync finishes in a single round-trip.  Falls back to genesis on reorg.
    let mut chain = if let Some((tip_h, tip_hash)) = store.tip_header() {
        println!(
            "itc-node: resumed from store — tip height {tip_h} hash {}",
            proto::hashes::to_display_hex(&tip_hash),
        );
        let mut c = HeaderChain::resume_from_tip(tip_h, tip_hash);
        // resume_from_tip only knows the tip + genesis; every height in between
        // is a zero placeholder until hydrated. Block-body sync (which can start
        // from well below the tip via ITC_ORACLE_START_HEIGHT) needs the REAL
        // hash at every height it downloads — without this, it asks peers for
        // the block whose hash is "000...000", which none of them can ever have.
        // See HeaderChain::hydrate_from_store for the full story.
        c.hydrate_from_store(&store);
        c
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
    // Checkpoint in case shutdown was requested during header sync.
    if shutdown.load(Ordering::Relaxed) {
        store.flush();
        eprintln!("itc-node: flushed at height {} — clean shutdown", chain.tip_height());
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

    // Checkpoint on block-sync shutdown.
    if shutdown.load(Ordering::Relaxed) {
        store.flush();
        eprintln!("itc-node: flushed at height {} — clean shutdown", chain.tip_height());
        return;
    }


    // ── 4b. Live L1 follow — keeps syncing new blocks after initial sync ────────
    {
        use itc_oracle::{DepositOracle, OracleConfig};
        use std::sync::atomic::AtomicBool;
        let follow_db   = Arc::clone(&store.db);
        let follow_ep   = endpoint.to_string();
        let follow_osh  = oracle_start_height;
        std::thread::spawn(move || {
            println!("itc-node[l1-follow]: live sync thread started (60s interval)");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
                let s = crate::store::Store::from_arc_db(Arc::clone(&follow_db));
                let (cur_h, cur_hash) = s.tip_header().unwrap_or((0, [0u8; 32]));
                let Ok((mut peer, _)) = crate::anchor::fetch_anchor_tip(&follow_ep, proto::MAGIC_MAIN)
                else { continue };
                let mut chain = crate::chain::HeaderChain::resume_from_tip(cur_h, cur_hash);
                let flag = AtomicBool::new(false);
                if sync::sync_headers(&mut peer, &mut chain, &s, &flag).is_err() { continue }
                let new_h = chain.tip_height();
                if new_h <= cur_h { continue }
                let _ = sync::sync_blocks(&mut peer, &chain, &s, (cur_h + 1).max(follow_osh), &flag);
                let mut oracle = DepositOracle::new(OracleConfig::from_env(), Arc::clone(&follow_db));
                for h in (cur_h + 1)..=new_h {
                    if let Some(hash) = chain.active_hash_at(h) {
                        let hx = itc_proto::hashes::to_internal_hex(&hash);
                        if let Some(raw) = s.get_block(&hx) {
                            let minted = oracle.process_block(&raw, h);
                            for d in &minted {
                                eprintln!();
                                println!("[ORACLE] live mint at L1 {} → 0x{}", h, hex::encode(d.aitc_address));
                            }
                        }
                    }
                }
                // sync_headers/sync_blocks already checkpoint on their own cadence
                // (every round / every ~2000 blocks); tip_header() reflects the real
                // last-connected header directly, no shadow copy to update here.
                println!("[L1] live: synced to height {new_h}");
            }
        });
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

    // Restore the L2 chain height BEFORE the sequencer starts, so block numbers
    // are monotonic across restarts (eth_blockNumber never goes backwards; new
    // receipts never collide with old ones). Prefer the durable meta record;
    // fall back to the max receipt block_number for datadirs created before the
    // durable-epoch fix — a one-time, backwards-compatible recovery. Fresh chain
    // → 0 (unchanged genesis behavior).
    {
        let resume = store.db.get("l2_meta", "chain_height")
            .and_then(|n| n.data.get("height").and_then(|v| v.as_u64()))
            .or_else(|| store.db.list("l2_receipts").iter()
                .filter_map(|n| n.data.get("block_number").and_then(|v| v.as_u64()))
                .max())
            .unwrap_or(0);
        if resume > 0 {
            epoch.store(resume, Ordering::SeqCst);
            println!("itc-node[seq]: resumed L2 chain height at {resume} (durable epoch — no restart renumber)");
        }
    }

    // L2 block sequencer — ticks every 5s, drains mempool, executes txs, persists
    // receipts, and flushes L2 durably on every state-changing block + on shutdown.
    Sequencer::new(
        Arc::clone(&evm_shared),
        Arc::clone(&mempool),
        Arc::clone(&epoch),
        Arc::clone(&store.db),
        Arc::clone(&shutdown),
    ).spawn();
    println!("itc-node[seq]: L2 sequencer started (5s blocks)");

    // ── 6. Serve — headers + block bodies to inbound peers ───────────────────
    let our_height = chain.tip_height();
    let chain = Arc::new(chain);
    let store = Arc::new(store);
    let listen = format!("0.0.0.0:{listen_port}");
    if let Err(e) = serve::serve(&listen, proto::MAGIC_MAIN, chain, store, our_height) {
        if shutdown.load(Ordering::Relaxed) {
            // Serve loop exited because Ctrl+C interrupted accept() — clean shutdown.
            // All Rust values drop here: NEDB Db drops → WAL flushed to disk.
            println!("itc-node: clean shutdown complete.");
        } else {
            eprintln!("itc-node: serve error on {listen}: {e}");
        }
    }
    // main() returns naturally → all Arcs drop → NEDB flushes
}
