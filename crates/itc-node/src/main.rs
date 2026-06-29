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

use itc_proto as proto;

use std::sync::Mutex;

use itc_anchor::{AnchorConfig, AnchorPoster};
use itc_evm::ItcEvm;
use itc_oracle::{DepositOracle, OracleConfig, UtxoMirror};
use itc_rpc::RpcServer;

use crate::sequencer::{new_mempool, Sequencer};

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

    // ── 3. UTXO mirror oracle ─────────────────────────────────────────────────
    // Mirrors the entire ITC L1 UTXO set as native aITC on L2. No bridge action
    // needed — once a user signs any ITC tx on mainnet, their full balance appears
    // on L2 automatically. The oracle processes each block as it is downloaded.
    let mut utxo_mirror = UtxoMirror::open(Arc::clone(&store.db));
    println!("itc-node[oracle]: UTXO mirror armed — scanning all P2PKH outputs");
    // (Exit scanner is owned by the sequencer — wired in there)

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

    // ── 3b. UTXO mirror scan — process all downloaded blocks ─────────────────
    // Walk height 1 → tip, run each raw block through the mirror. Happens once
    // on first run (or after new blocks are downloaded). Fast on warm start
    // because UtxoMirror::open() restores the key/pending maps from NEDB.
    {
        let tip = chain.tip_height();
        println!("itc-node[oracle]: scanning blocks 1..{tip} through UTXO mirror...");
        let mut total_minted = 0u64;
        for h in 1..=tip {
            if let Some(hash) = chain.active_hash_at(h) {
                let hash_hex = itc_proto::hashes::to_internal_hex(&hash);
                if let Some(raw) = store.get_block(&hash_hex) {
                    let (credits, _wei) = utxo_mirror.process_block(&raw, h);
                    total_minted += credits;
                }
            }
        }
        println!("itc-node[oracle]: mirror scan done — {total_minted} total credits");
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
