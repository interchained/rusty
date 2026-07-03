//! L2 block sequencer — ticks every BLOCK_TIME_SECS and produces L2 blocks.
//!
//! Each tick:
//!   1. Drain pending transactions from the mempool
//!   2. Execute them via ItcEvm (revm + NEDB state)
//!   3. Persist receipts to NEDB (l2_receipts collection)
//!   4. Advance the epoch counter (used by eth_blockNumber)
//!   5. Log [SEQ] block=N txs=M nedb_head=<hex>
//!
//! The sequencer is authoritative for L2 block ordering. No consensus needed
//! in v1 — this is a single-operator PoA sidechain.
//!
//! Durability: shares one `Arc<Db>` with L1 header/block sync, so a single
//! `flush_all()` checkpoints L1 progress + L2 receipts together. Checkpoints every
//! `BLOCK_FLUSH_EVERY` produced blocks (not per-put) — see `store.rs` / `sync.rs`
//! for the matching L1 cadence, and `main.rs` for the exit-time flush.

use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nedb_engine::Db;
use revm::primitives::{Address, B256, U256};
use serde_json::json;

use itc_evm::ItcEvm;
use itc_oracle::ExitScanner;

/// L2 block time in seconds.
pub const BLOCK_TIME_SECS: u64 = 5;

/// L2 checkpoint cadence — flush every N produced blocks (not per-put).
const BLOCK_FLUSH_EVERY: u64 = 500;

/// A pending L2 transaction in the mempool.
#[derive(Clone, Debug)]
pub struct PendingTx {
    /// Raw RLP-encoded transaction bytes.
    pub raw: Vec<u8>,
    /// Decoded tx hash (keccak256 of raw bytes).
    pub tx_hash: B256,
    /// Recovered sender address.
    pub from: Address,
    /// Gas limit from the tx.
    #[allow(dead_code)]
    pub gas_limit: u64,
}

/// An executed transaction receipt — persisted to NEDB after block finalization.
#[derive(Clone, Debug)]
pub struct TxReceipt {
    pub tx_hash: B256,
    pub from: Address,
    #[allow(dead_code)]
    pub block_number: u64,
    pub gas_used: u64,
    pub success: bool,
}

/// The L2 mempool — thread-safe pending tx queue.
pub type Mempool = Arc<Mutex<VecDeque<PendingTx>>>;

/// Create a new empty mempool.
pub fn new_mempool() -> Mempool {
    Arc::new(Mutex::new(VecDeque::new()))
}

/// Add a transaction to the mempool (called by eth_sendRawTransaction).
#[allow(dead_code)]
pub fn submit_tx(mempool: &Mempool, tx: PendingTx) {
    mempool.lock().unwrap().push_back(tx);
}

/// The L2 block sequencer. Spawns a background thread that ticks every BLOCK_TIME_SECS.
pub struct Sequencer {
    evm: Arc<Mutex<ItcEvm>>,
    mempool: Mempool,
    epoch: Arc<AtomicU64>,
    db: Arc<Db>,
    exit_scanner: ExitScanner,
}

impl Sequencer {
    pub fn new(evm: Arc<Mutex<ItcEvm>>, mempool: Mempool, epoch: Arc<AtomicU64>, db: Arc<Db>) -> Self {
        let exit_scanner = ExitScanner::new(Arc::clone(&db));
        Sequencer { evm, mempool, epoch, db, exit_scanner }
    }

    /// Spawn the sequencer background thread.
    pub fn spawn(self) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || self.run())
    }

    fn run(self) {
        println!("[SEQ] L2 sequencer started — {BLOCK_TIME_SECS}s blocks");
        loop {
            std::thread::sleep(Duration::from_secs(BLOCK_TIME_SECS));
            self.produce_block();
        }
    }

    fn produce_block(&self) {
        let block_num = self.epoch.fetch_add(1, Ordering::SeqCst) + 1;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Drain up to 500 pending txs per block
        let pending: Vec<PendingTx> = {
            let mut mem = self.mempool.lock().unwrap();
            let n = mem.len().min(500);
            mem.drain(..n).collect()
        };

        // Live status line -- overwrites, no log spam. L1 height comes from
        // the engine's durable per-collection tip (nedb_engine::Db::tip_collection),
        // the same primitive store.rs uses for boot resume, not a shadow copy.
        let l1_h = crate::store::Store::from_arc_db(Arc::clone(&self.db))
            .tip_header()
            .map(|(h, _)| h)
            .unwrap_or(0);
        eprint!("\r  [L1] {l1_h}  |  [L2] {block_num}   ");

        // L2 checkpoint cadence: flush every BLOCK_FLUSH_EVERY produced blocks,
        // regardless of whether THIS block had txs, so a long empty stretch
        // doesn't widen the durability gap before the next real write.
        if block_num % BLOCK_FLUSH_EVERY == 0 {
            self.db.flush_all();
        }

        if pending.is_empty() {
            self.epoch.store(block_num, Ordering::SeqCst);
            return;
        }

        let mut evm = self.evm.lock().unwrap();
        evm.set_block(block_num, now, Address::ZERO);

        let mut receipts: Vec<TxReceipt> = Vec::new();
        let mut total_gas = 0u64;

        for tx in &pending {
            // Build TxEnv from the pending tx (already decoded at submission)
            // For simplicity, re-decode here. A real sequencer would keep decoded form.
            let tx_env = match build_tx_env_from_pending(tx) {
                Some(e) => e,
                None => continue,
            };

            // ── Bridge exit detection (aITC → ITC) ────────────────────────────
            // A burn is a value transfer TO the well-known EXIT_ADDRESS
            // (0x…dEaD) whose calldata carries the ITC L1 recipient address in
            // ASCII (the Elara bridge always sets it). Capture the probe BEFORE
            // execute_tx consumes tx_env; queue it only if execution succeeds.
            let exit_probe: Option<(u128, Vec<u8>)> = match &tx_env.transact_to {
                revm::primitives::TransactTo::Call(to)
                    if hex::encode(to.as_slice()) == itc_oracle::EXIT_ADDRESS
                        && tx_env.value > U256::ZERO =>
                {
                    Some((
                        u128::try_from(tx_env.value).unwrap_or(0),
                        tx_env.data.to_vec(),
                    ))
                }
                _ => None,
            };

            let gas_used;
            let success;
            match evm.execute_tx(tx_env, tx.tx_hash) {
                Ok(result) => {
                    success = result.is_success();
                    gas_used = match result {
                        revm::primitives::ExecutionResult::Success { gas_used, .. } => gas_used,
                        revm::primitives::ExecutionResult::Revert { gas_used, .. } => gas_used,
                        revm::primitives::ExecutionResult::Halt { gas_used, .. } => gas_used,
                    };
                }
                Err(_) => {
                    success = false;
                    gas_used = 21_000;
                }
            }
            total_gas += gas_used;

            if success {
                if let Some((amount_wei, calldata)) = exit_probe {
                    let tx_hash_hex = format!("0x{}", hex::encode(tx.tx_hash.as_slice()));
                    let from_hex    = format!("0x{}", hex::encode(tx.from.as_slice()));
                    // Calldata → ITC L1 recipient. ASCII, trimmed; sanity-gated
                    // so garbage calldata can't route a release to a junk string.
                    let recipient = String::from_utf8(calldata)
                        .ok()
                        .map(|s| s.trim().to_string())
                        .filter(|s| looks_like_itc_address(s));
                    match recipient {
                        Some(r) if amount_wei > 0 => {
                            self.exit_scanner.queue_exit(&tx_hash_hex, &from_hex, amount_wei, &r, block_num);
                        }
                        _ => {
                            println!(
                                "[EXIT] burn {tx_hash_hex} has no valid ITC L1 recipient in calldata — skipped (funds burned, no release queued)"
                            );
                        }
                    }
                }
            }

            receipts.push(TxReceipt {
                tx_hash: tx.tx_hash,
                from: tx.from,
                block_number: block_num,
                gas_used,
                success,
            });
        }

        // Persist receipts to NEDB
        self.persist_receipts(&receipts, block_num);

        let head = self.db.head();
        eprintln!(); // advance past the \r status line
        println!(
            "[SEQ] L2 block={block_num} txs={} gas={total_gas} head={}",
            receipts.len(), &head[..16.min(head.len())]
        );

        // Process any exits that have reached their confirmation threshold.
        self.exit_scanner.process_epoch(block_num);
    }

    fn persist_receipts(&self, receipts: &[TxReceipt], block_num: u64) {
        for r in receipts {
            let id = format!("0x{}", hex::encode(r.tx_hash.as_slice()));
            let data = json!({
                "tx_hash": &id,
                "from": format!("0x{}", hex::encode(r.from.as_slice())),
                "block_number": block_num,
                "gas_used": r.gas_used,
                "status": if r.success { "0x1" } else { "0x0" },
                "block_hash": format!("0x{:064x}", block_num),
                "logs": [],
            });
            let _ = self.db.put("l2_receipts", &id, data, vec![], None, None);
        }
    }
}

/// Loose plausibility gate for an ITC L1 address arriving in burn calldata:
/// bech32 mainnet ("itc1…", 14-90 chars of the bech32 charset) or a legacy
/// base58 address (26-35 alphanumerics). This is NOT validation — the release
/// path builds a real script for it — it only stops garbage calldata from
/// being persisted as a recipient.
fn looks_like_itc_address(s: &str) -> bool {
    let n = s.len();
    if !s.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    if s.starts_with("itc1") {
        return (14..=90).contains(&n); // bech32 mainnet
    }
    (26..=35).contains(&n) // legacy base58
}

fn build_tx_env_from_pending(tx: &PendingTx) -> Option<revm::primitives::TxEnv> {
    use rlp::Rlp;
    use revm::primitives::{Bytes, TransactTo, TxEnv};

    let rlp = Rlp::new(&tx.raw);
    if !rlp.is_list() { return None; }

    let nonce: u64 = rlp.val_at(0).ok()?;
    let gas_price_b: Vec<u8> = rlp.val_at(1).ok()?;
    let gas_limit: u64 = rlp.val_at(2).ok()?;
    let to_b: Vec<u8> = rlp.val_at(3).ok()?;
    let value_b: Vec<u8> = rlp.val_at(4).ok()?;
    let data_b: Vec<u8> = rlp.val_at(5).ok()?;

    let gas_price = bytes_to_u256(&gas_price_b);
    let value = bytes_to_u256(&value_b);

    let transact_to = if to_b.is_empty() {
        TransactTo::Create(revm::primitives::CreateScheme::Create)
    } else if to_b.len() == 20 {
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&to_b);
        TransactTo::Call(revm::primitives::Address::from(arr))
    } else {
        return None;
    };

    Some(TxEnv {
        caller: tx.from,
        transact_to,
        value,
        data: Bytes::from(data_b),
        gas_limit,
        gas_price,
        gas_priority_fee: None,
        nonce: Some(nonce),
        chain_id: Some(itc_evm::CHAIN_ID),
        access_list: vec![],
        ..Default::default()
    })
}

fn bytes_to_u256(b: &[u8]) -> U256 {
    if b.is_empty() { return U256::ZERO; }
    let mut arr = [0u8; 32];
    let start = 32 - b.len().min(32);
    arr[start..].copy_from_slice(&b[b.len().saturating_sub(32)..]);
    U256::from_be_bytes(arr)
}
