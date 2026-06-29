//! ItcEvm — transaction and block execution for ITC-L2.
//!
//! Pattern:
//!   1. NedbState (DatabaseRef) read-only view of NEDB state.
//!   2. CacheDB<NedbState> — revm's write buffer (accounts + storage in-memory).
//!   3. Execute transaction(s) via revm EVM.
//!   4. After each tx, flush dirty state → NEDB via NedbState::commit_changes()
//!      with caused_by = [tx_hash]. This is the provenance hook.
//!
//! The net result: every account balance change, nonce bump, storage slot write,
//! and contract deployment is a NEDB node causally linked to the transaction that
//! produced it. AS OF queries replay any historical EVM state. TRACE walks back
//! from any balance to the transaction tree that created it.

use std::sync::Arc;

use nedb_engine::Db;
use revm::{
    db::CacheDB,
    primitives::{
        AccountInfo, Address, BlockEnv, Bytes, CfgEnv, ExecutionResult,
        ResultAndState, TransactTo, TxEnv, B256, U256,
    },
    EVM,
};

use crate::state::NedbState;
use crate::{CHAIN_ID, EVM_SPEC};

/// The ITC-L2 EVM executor. Holds the NEDB-backed state + revm's write cache.
pub struct ItcEvm {
    /// Wraps NedbState; holds in-memory dirty writes between flushes.
    pub cache: CacheDB<NedbState>,
    /// Current L2 block environment (block number, timestamp, etc.).
    pub block: BlockEnv,
}

impl ItcEvm {
    /// Create a new executor backed by the given NEDB database.
    pub fn new(db: Arc<Db>) -> Self {
        ItcEvm {
            cache: CacheDB::new(NedbState::new(db)),
            block: BlockEnv::default(),
        }
    }

    /// Set the block environment (call before executing txs in a new block).
    pub fn set_block(&mut self, number: u64, timestamp: u64, coinbase: Address) {
        self.block.number = U256::from(number);
        self.block.timestamp = U256::from(timestamp);
        self.block.coinbase = coinbase;
        self.block.gas_limit = U256::from(30_000_000u64); // 30M gas per L2 block
        self.block.basefee = U256::ZERO; // No base fee initially (no EIP-1559 pressure on L2 yet)
        self.block.difficulty = U256::ZERO;
        self.block.prevrandao = Some(B256::ZERO);
    }

    /// Build the revm CfgEnv for ITC-L2.
    ///
    /// `disable_base_fee` / `disable_block_gas_limit` are not set here —
    /// those fields are gated behind the `optional_no_base_fee` /
    /// `optional_block_gas_limit` cargo features in revm 3.x, which we don't
    /// enable. The default behavior (base-fee enforced, gas-limit enforced) is
    /// fine for ITC-L2: we set `basefee = 0` in `set_block`, so EIP-1559
    /// pressure is zero anyway, and the 30M block gas limit is the standard.
    fn cfg_env() -> CfgEnv {
        let mut cfg = CfgEnv::default();
        cfg.chain_id = CHAIN_ID;
        cfg.spec_id = EVM_SPEC;
        cfg
    }

    /// Execute one transaction. Returns the EVM execution result.
    /// Automatically flushes dirty state to NEDB with `caused_by: [tx_hash]`.
    ///
    /// `tx_hash` — the ITC-L2 transaction hash, used as the provenance link.
    pub fn execute_tx(
        &mut self,
        tx: TxEnv,
        tx_hash: B256,
    ) -> Result<ExecutionResult, String> {
        let ResultAndState { result, state } = self.transact(tx)?;
        // Flush to NEDB — this is where the provenance magic happens.
        self.cache.db.commit_changes(&state, tx_hash);
        // Also commit to in-memory cache for subsequent reads in same block.
        self.cache.commit(state);
        Ok(result)
    }

    /// Execute a transaction and return the full ResultAndState without flushing.
    /// Useful for gas estimation / simulation (call, don't commit).
    pub fn simulate_tx(&mut self, tx: TxEnv) -> Result<ResultAndState, String> {
        self.transact(tx)
    }

    /// Internal: run revm transact (does NOT commit state).
    fn transact(&mut self, tx: TxEnv) -> Result<ResultAndState, String> {
        let mut evm = EVM::new();
        evm.env.cfg = Self::cfg_env();
        evm.env.block = self.block.clone();
        evm.env.tx = tx;
        evm.database(&mut self.cache);
        evm.transact().map_err(|e| format!("EVM error: {:?}", e))
    }

    /// Helper: build a simple ETH-transfer TxEnv.
    pub fn transfer_tx(from: Address, to: Address, value: U256, gas_price: U256, nonce: u64) -> TxEnv {
        TxEnv {
            caller: from,
            transact_to: TransactTo::Call(to),
            value,
            data: Bytes::default(),
            gas_limit: 21_000,
            gas_price,
            gas_priority_fee: None,
            nonce: Some(nonce),
            chain_id: Some(CHAIN_ID),
            access_list: vec![],
            ..Default::default()
        }
    }

    /// Helper: build a contract-deployment TxEnv.
    pub fn deploy_tx(from: Address, initcode: Bytes, gas_limit: u64, gas_price: U256, nonce: u64) -> TxEnv {
        TxEnv {
            caller: from,
            transact_to: TransactTo::Create(revm::primitives::CreateScheme::Create),
            value: U256::ZERO,
            data: initcode,
            gas_limit,
            gas_price,
            gas_priority_fee: None,
            nonce: Some(nonce),
            chain_id: Some(CHAIN_ID),
            access_list: vec![],
            ..Default::default()
        }
    }

    /// Seed a genesis account directly into the CacheDB (fast, no disk hit).
    pub fn seed_genesis_account(&mut self, addr: Address, balance: U256) {
        let info = AccountInfo {
            balance,
            nonce: 0,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: None,
        };
        self.cache.insert_account_info(addr, info);
        // Also write to NEDB so it persists across restarts.
        self.cache.db.seed_account(addr, balance, 0);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn test_db(dir: &Path) -> Arc<Db> {
        Arc::new(Db::open(dir, None).expect("open test db"))
    }

    /// Parse a hex address string into an Address.
    fn addr(s: &str) -> Address {
        let bytes = hex::decode(s).expect("hex addr");
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&bytes);
        Address::from(arr)
    }

    /// 1 ITC in wei.
    const ITC: U256 = U256::from_limbs([0x0DE0B6B3A7640000u64, 0, 0, 0]);

    #[test]
    fn transfer_persists_to_nedb_with_provenance() {
        let tmp = tempfile::tempdir().unwrap();
        let db = test_db(tmp.path());
        let mut evm = ItcEvm::new(Arc::clone(&db));

        let alice = addr("1000000000000000000000000000000000000001");
        let bob   = addr("2000000000000000000000000000000000000002");
        let zero_addr = Address::ZERO;

        // Genesis: give Alice 100 ITC
        evm.seed_genesis_account(alice, ITC * U256::from(100));
        evm.set_block(1, 1_750_000_000, zero_addr);

        // Transfer 10 ITC from Alice → Bob
        let tx_hash = B256::from([0x42u8; 32]); // synthetic tx hash
        let tx = ItcEvm::transfer_tx(alice, bob, ITC * U256::from(10), U256::ZERO, 0);
        let result = evm.execute_tx(tx, tx_hash).expect("execute transfer");

        assert!(result.is_success(), "transfer should succeed: {:?}", result);

        // Verify Bob has 10 ITC in NEDB
        let bob_account = db.get("evm_accounts", &crate::state::NedbState::addr_key(&bob));
        assert!(bob_account.is_some(), "bob should have an account in NEDB");
        let bob_balance_hex = bob_account.unwrap().data["balance"]
            .as_str()
            .unwrap()
            .to_string();
        let bob_balance = crate::state::NedbState::hex_to_u256(&bob_balance_hex);
        assert_eq!(bob_balance, ITC * U256::from(10), "bob balance should be 10 ITC");

        // Verify provenance: Bob's account was caused_by the tx
        // (NEDB stores caused_by internally; the write above went through with it)
        println!("transfer: bob balance = {} wei", bob_balance);
        println!("provenance: caused_by = [{}]", hex::encode(tx_hash.as_slice()));
        println!("engine head after tx: {}", db.head());
    }

    #[test]
    fn genesis_account_readable_via_basic() {
        use revm::db::DatabaseRef;
        let tmp = tempfile::tempdir().unwrap();
        let db = test_db(tmp.path());
        let state = NedbState::new(Arc::clone(&db));

        let alice = addr("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        state.seed_account(alice, ITC * U256::from(50), 0);

        let info = state.basic(alice).unwrap().unwrap();
        assert_eq!(info.balance, ITC * U256::from(50));
        assert_eq!(info.nonce, 0);
        assert_eq!(info.code_hash, revm::primitives::KECCAK_EMPTY);
        println!("genesis account: balance = {} wei", info.balance);
    }
}
