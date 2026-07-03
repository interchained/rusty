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
    atomic::{AtomicBool, AtomicU64, Ordering},
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

/// Idle checkpoint cadence — flush every N *empty* produced blocks so a long
/// quiet stretch still persists the advancing epoch without an fsync per 5s
/// tick. Blocks that actually change L2 state flush IMMEDIATELY (see
/// produce_block) — durability of a burn/receipt is never deferred to this.
const IDLE_FLUSH_EVERY: u64 = 60; // ~5 min at 5s blocks

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
    /// Process-wide shutdown flag (shared with main + the ctrlc handler). When
    /// set, the sequencer seals a final block and flushes L2 durably before
    /// exiting — its own clean-shutdown checkpoint, the L2 twin of L1's
    /// flush-on-shutdown in main.rs / sync.rs.
    shutdown: Arc<AtomicBool>,
}

impl Sequencer {
    pub fn new(
        evm: Arc<Mutex<ItcEvm>>,
        mempool: Mempool,
        epoch: Arc<AtomicU64>,
        db: Arc<Db>,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        let exit_scanner = ExitScanner::new(Arc::clone(&db));
        Sequencer { evm, mempool, epoch, db, exit_scanner, shutdown }
    }

    /// Spawn the sequencer background thread.
    pub fn spawn(self) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || self.run())
    }

    fn run(self) {
        println!("[SEQ] L2 sequencer started — {BLOCK_TIME_SECS}s blocks");
        loop {
            // Shutdown-aware wait: sleep in 1s slices so a shutdown signal is
            // noticed within ~1s instead of up to BLOCK_TIME_SECS later.
            for _ in 0..BLOCK_TIME_SECS {
                if self.shutdown.load(Ordering::Relaxed) { break; }
                std::thread::sleep(Duration::from_secs(1));
            }
            if self.shutdown.load(Ordering::Relaxed) {
                // Seal one last block (drains any final mempool txs, flushes on
                // activity) then force a durable flush regardless — so the L2
                // state (EVM accounts, receipts, queued exits) can never be lost
                // to a shutdown that lands between checkpoints. Idempotent with
                // the process-level ctrlc flush on the same shared Db.
                self.produce_block();
                self.db.flush_all();
                println!("[SEQ] shutdown — final L2 flush complete");
                return;
            }
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

        if pending.is_empty() {
            self.epoch.store(block_num, Ordering::SeqCst);
            // Idle block: no L2 state change. Checkpoint only periodically so a
            // long quiet stretch still persists the advancing epoch / shared L1
            // progress, without an fsync every 5s on a dead-idle chain.
            if block_num % IDLE_FLUSH_EVERY == 0 {
                self.db.flush_all();
            }
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

        // Durability: this block CHANGED L2 state — EVM accounts (committed
        // per-tx via commit_changes), receipts, and any queued/processed exit
        // records all landed in NEDB's in-memory write buffer. Checkpoint NOW,
        // not up to IDLE_FLUSH_EVERY blocks later. A burn that isn't flushed is
        // invisible after a crash/kill — and surviving a restart is the entire
        // promise of the bridge. flush_all() is the real durability primitive
        // (id-index WAL + segment fsync + MANIFEST), the same one L1 sync and
        // the shutdown handler use.
        self.db.flush_all();
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

#[cfg(test)]
mod tests {
    use super::*;
    use itc_evm::NedbState;
    use rlp::RlpStream;

    /// 1 ITC in wei.
    const ITC: U256 = U256::from_limbs([0x0DE0B6B3A7640000u64, 0, 0, 0]);

    fn addr(byte: u8) -> Address {
        Address::from([byte; 20])
    }

    /// Minimal legacy-tx RLP carrying exactly the fields build_tx_env_from_pending
    /// reads (nonce, gasPrice, gasLimit, to, value, data) + dummy v/r/s so it is
    /// a well-formed 9-item list. gasPrice 0 → the sender only needs `value`.
    fn legacy_transfer_rlp(nonce: u64, to: Address, value: U256) -> Vec<u8> {
        let mut vbytes = value.to_be_bytes::<32>().to_vec();
        while vbytes.first() == Some(&0) { vbytes.remove(0); } // RLP minimal big-endian
        let mut s = RlpStream::new_list(9);
        s.append(&nonce);
        s.append(&0u64);                 // gasPrice = 0
        s.append(&21_000u64);            // gasLimit
        s.append(&to.as_slice().to_vec());
        s.append(&vbytes);               // value
        s.append_empty_data();           // data
        s.append(&27u64);                // v (dummy — not read)
        s.append(&1u64);                 // r (dummy)
        s.append(&1u64);                 // s (dummy)
        s.out().to_vec()
    }

    /// Regression guard for the L2 durability fix: a block carrying a real
    /// state-changing tx must execute, persist its receipt, AND flush — so the
    /// receipt/account survive a reopen with NO 500-block wait. (Crash-timing —
    /// kill -9 before the next checkpoint — is validated on the real node; this
    /// pins the execute→persist→flush path that the fix reorganized.)
    #[test]
    fn produce_block_executes_persists_and_flushes() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().to_path_buf();

        let alice = addr(0x11);
        let bob   = addr(0x22);
        let tx_hash = B256::from([0xABu8; 32]);

        {
            let db = Arc::new(Db::open(&path, None).unwrap());
            let mut evm = ItcEvm::new(Arc::clone(&db));
            evm.seed_genesis_account(alice, ITC * U256::from(100));
            let evm_arc = Arc::new(Mutex::new(evm));

            let mempool = new_mempool();
            submit_tx(&mempool, PendingTx {
                raw: legacy_transfer_rlp(0, bob, ITC),
                tx_hash,
                from: alice,
                gas_limit: 21_000,
            });

            let seq = Sequencer::new(
                evm_arc,
                mempool,
                Arc::new(AtomicU64::new(0)),
                Arc::clone(&db),
                Arc::new(AtomicBool::new(false)),
            );
            seq.produce_block(); // block 1: one transfer → execute + persist + flush

            // In-session: receipt persisted with success, bob credited.
            let rid = format!("0x{}", hex::encode(tx_hash.as_slice()));
            let receipt = db.get("l2_receipts", &rid).expect("receipt persisted");
            assert_eq!(receipt.data["status"].as_str(), Some("0x1"));
            let bob_acct = db.get("evm_accounts", &NedbState::addr_key(&bob))
                .expect("bob account persisted");
            assert_eq!(NedbState::hex_to_u256(bob_acct.data["balance"].as_str().unwrap()), ITC);
        }

        // Reopen from disk: the block's writes were flushed (not stranded in the
        // write buffer awaiting a distant checkpoint) → still there after reopen.
        let db2 = Db::open(&path, None).unwrap();
        db2.startup_ready.store(true, Ordering::SeqCst);
        let rid = format!("0x{}", hex::encode(tx_hash.as_slice()));
        assert!(db2.get("l2_receipts", &rid).is_some(), "receipt must survive reopen");
        assert!(db2.get("evm_accounts", &NedbState::addr_key(&bob)).is_some(),
                "bob account must survive reopen");
    }

    /// The idle path flushes only on the IDLE_FLUSH_EVERY cadence — an empty
    /// block must not error and must advance the epoch.
    #[test]
    fn empty_block_advances_epoch_without_txs() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(Db::open(tmp.path(), None).unwrap());
        let evm = Arc::new(Mutex::new(ItcEvm::new(Arc::clone(&db))));
        let epoch = Arc::new(AtomicU64::new(0));
        let seq = Sequencer::new(
            evm, new_mempool(), Arc::clone(&epoch),
            Arc::clone(&db), Arc::new(AtomicBool::new(false)),
        );
        seq.produce_block();
        assert_eq!(epoch.load(Ordering::SeqCst), 1, "empty block still advances the epoch");
    }
}
