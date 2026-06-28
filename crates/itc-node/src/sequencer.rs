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

/// L2 block time in seconds.
pub const BLOCK_TIME_SECS: u64 = 5;

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
    pub gas_limit: u64,
}

/// An executed transaction receipt — persisted to NEDB after block finalization.
#[derive(Clone, Debug)]
pub struct TxReceipt {
    pub tx_hash: B256,
    pub from: Address,
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
pub fn submit_tx(mempool: &Mempool, tx: PendingTx) {
    mempool.lock().unwrap().push_back(tx);
}

/// The L2 block sequencer. Spawns a background thread that ticks every BLOCK_TIME_SECS.
pub struct Sequencer {
    evm: Arc<Mutex<ItcEvm>>,
    mempool: Mempool,
    epoch: Arc<AtomicU64>,
    db: Arc<Db>,
}

impl Sequencer {
    pub fn new(evm: Arc<Mutex<ItcEvm>>, mempool: Mempool, epoch: Arc<AtomicU64>, db: Arc<Db>) -> Self {
        Sequencer { evm, mempool, epoch, db }
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

        if pending.is_empty() {
            // Empty block — still advance epoch and anchor
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
        println!(
            "[SEQ] block={block_num} txs={} gas={total_gas} head={head}",
            receipts.len()
        );
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

fn build_tx_env_from_pending(tx: &PendingTx) -> Option<revm::primitives::TxEnv> {
    use rlp::Rlp;
    use revm::primitives::{Bytes, TransactTo, TxEnv, U256};

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
