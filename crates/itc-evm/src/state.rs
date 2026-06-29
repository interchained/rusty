//! NedbState — revm::DatabaseRef backed by NEDB.
//!
//! Implements the read side of the EVM state interface:
//!   basic(addr)           → AccountInfo {balance, nonce, code_hash}
//!   code_by_hash(h)       → Bytecode
//!   storage(addr,slot)    → U256
//!   block_hash(n)         → B256  (zero for now; real L2 block hashes in slice 7)
//!
//! Method names follow the revm 3.x `DatabaseRef` trait surface (no `_ref`
//! suffix — that variant was introduced in revm 4+).
//!
//! Write side: after revm executes a transaction, `commit_changes()` receives
//! the dirty account map from revm's CacheDB and persists every touched account
//! and storage slot to NEDB with `caused_by: [tx_hash]`.
//!
//! NEDB collections:
//!   "evm_accounts"  id=addr_hex   {balance, nonce, code_hash}  caused_by=[tx_hash]
//!   "evm_storage"   id=addr:slot  {value}                      caused_by=[tx_hash]
//!   "evm_code"      id=hash_hex   {bytecode}                   caused_by=[] (immutable)

use std::sync::Arc;

use nedb_engine::Db;
use revm::primitives::{
    AccountInfo, Address, Bytecode, Bytes, B256, U256, KECCAK_EMPTY,
};
// `DatabaseRef` lives in `revm::primitives::db` (re-exported via `revm::db::*`).
// It is NOT re-exported at the crate root in revm 3.x, so we import the long
// path here.
use revm::db::DatabaseRef;
use serde_json::json;

pub const COLL_ACCOUNTS: &str = "evm_accounts";
pub const COLL_STORAGE: &str = "evm_storage";
pub const COLL_CODE: &str = "evm_code";

/// Read-only NEDB state — the source of truth for all EVM account reads.
pub struct NedbState {
    pub db: Arc<Db>,
}

impl NedbState {
    pub fn new(db: Arc<Db>) -> Self {
        NedbState { db }
    }

    // ── Key helpers ─────────────────────────────────────────────────────────

    pub fn addr_key(addr: &Address) -> String {
        hex::encode(addr.as_slice())
    }

    pub fn storage_key(addr: &Address, slot: U256) -> String {
        let slot_hex = hex::encode(slot.to_be_bytes::<32>());
        format!("{}:{}", Self::addr_key(addr), slot_hex)
    }

    pub fn hash_key(h: &B256) -> String {
        hex::encode(h.as_slice())
    }

    pub fn u256_to_hex(v: U256) -> String {
        hex::encode(v.to_be_bytes::<32>())
    }

    pub fn hex_to_u256(s: &str) -> U256 {
        let bytes = hex::decode(s).unwrap_or_default();
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            U256::from_be_bytes(arr)
        } else {
            U256::ZERO
        }
    }

    pub fn hex_to_b256(s: &str) -> Option<B256> {
        let bytes = hex::decode(s).ok()?;
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some(B256::from(arr))
        } else {
            None
        }
    }

    // ── Genesis seeding ─────────────────────────────────────────────────────

    /// Seed a genesis account with an initial balance. Call before executing any txs.
    pub fn seed_account(&self, addr: Address, balance: U256, nonce: u64) {
        let id = Self::addr_key(&addr);
        let data = json!({
            "balance": Self::u256_to_hex(balance),
            "nonce": nonce,
            "code_hash": Self::hash_key(&KECCAK_EMPTY),
        });
        let _ = self.db.put(COLL_ACCOUNTS, &id, data, vec![], None, None);
    }

    /// Seed a contract account with initial code + balance.
    pub fn seed_contract(&self, addr: Address, code: Bytes, balance: U256) {
        use revm::primitives::keccak256;
        let code_hash = keccak256(&code);
        let id = Self::addr_key(&addr);
        let data = json!({
            "balance": Self::u256_to_hex(balance),
            "nonce": 1u64,
            "code_hash": Self::hash_key(&code_hash),
        });
        let _ = self.db.put(COLL_ACCOUNTS, &id, data, vec![], None, None);

        // Store the code
        let code_id = Self::hash_key(&code_hash);
        let code_data = json!({ "bytecode": hex::encode(&code) });
        let _ = self.db.put(COLL_CODE, &code_id, code_data, vec![], None, None);
    }

    // ── Post-execution flush ─────────────────────────────────────────────────

    /// Flush all dirty accounts + storage from a completed revm execution into
    /// NEDB. Every write carries `caused_by: [tx_hash]` — the provenance chain
    /// that makes this EVM's state transitions causally traceable.
    ///
    /// `changes` uses `revm::primitives::HashMap` (re-export of `hashbrown::HashMap`),
    /// which is the same type as the `state` field of `ResultAndState`.
    pub fn commit_changes(
        &self,
        changes: &revm::primitives::HashMap<Address, revm::primitives::Account>,
        tx_hash: B256,
    ) {
        let caused_by = vec![Self::hash_key(&tx_hash)];

        for (addr, account) in changes {
            if !account.is_touched() {
                continue;
            }
            let id = Self::addr_key(addr);
            let info = &account.info;
            let data = json!({
                "balance": Self::u256_to_hex(info.balance),
                "nonce": info.nonce,
                "code_hash": Self::hash_key(&info.code_hash),
            });
            let _ = self.db.put(COLL_ACCOUNTS, &id, data, caused_by.clone(), None, None);

            // Flush bytecode (immutable once written — no caused_by)
            if let Some(code) = &info.code {
                if !code.is_empty() {
                    let code_id = Self::hash_key(&info.code_hash);
                    // revm 3.x: Bytecode has `bytes()` returning `&Bytes` (NOT `bytecode()`).
                    let code_data = json!({ "bytecode": hex::encode(code.bytes()) });
                    let _ = self.db.put(COLL_CODE, &code_id, code_data, vec![], None, None);
                }
            }

            // Flush changed storage slots
            for (slot, slot_value) in &account.storage {
                if slot_value.is_changed() {
                    let storage_id = Self::storage_key(addr, *slot);
                    let storage_data = json!({
                        "value": Self::u256_to_hex(slot_value.present_value()),
                    });
                    let _ = self.db.put(
                        COLL_STORAGE,
                        &storage_id,
                        storage_data,
                        caused_by.clone(),
                        None,
                        None,
                    );
                }
            }
        }
    }
}

// ── DatabaseRef (read-only revm interface) ────────────────────────────────────
//
// revm 3.x defines DatabaseRef methods as `basic`, `code_by_hash`, `storage`,
// `block_hash` (no `_ref` suffix). The `_ref` variants were introduced in
// revm 4+ where both immutable and mutable variants live on the same trait.

impl DatabaseRef for NedbState {
    type Error = String;

    fn basic(&self, address: Address) -> Result<Option<AccountInfo>, String> {
        let id = Self::addr_key(&address);
        let node = match self.db.get(COLL_ACCOUNTS, &id) {
            None => return Ok(None),
            Some(n) => n,
        };
        let balance = node
            .data
            .get("balance")
            .and_then(|v| v.as_str())
            .map(Self::hex_to_u256)
            .unwrap_or(U256::ZERO);
        let nonce = node
            .data
            .get("nonce")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let code_hash = node
            .data
            .get("code_hash")
            .and_then(|v| v.as_str())
            .and_then(Self::hex_to_b256)
            .unwrap_or(KECCAK_EMPTY);

        Ok(Some(AccountInfo {
            balance,
            nonce,
            code_hash,
            code: None, // loaded lazily via code_by_hash
        }))
    }

    fn code_by_hash(&self, code_hash: B256) -> Result<Bytecode, String> {
        if code_hash == KECCAK_EMPTY {
            return Ok(Bytecode::new());
        }
        let id = Self::hash_key(&code_hash);
        let node = match self.db.get(COLL_CODE, &id) {
            None => return Ok(Bytecode::new()),
            Some(n) => n,
        };
        let hex_str = node
            .data
            .get("bytecode")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let bytes = hex::decode(hex_str).unwrap_or_default();
        Ok(Bytecode::new_raw(Bytes::from(bytes)))
    }

    fn storage(&self, address: Address, index: U256) -> Result<U256, String> {
        let id = Self::storage_key(&address, index);
        match self.db.get(COLL_STORAGE, &id) {
            None => Ok(U256::ZERO),
            Some(node) => {
                let val = node
                    .data
                    .get("value")
                    .and_then(|v| v.as_str())
                    .map(Self::hex_to_u256)
                    .unwrap_or(U256::ZERO);
                Ok(val)
            }
        }
    }

    fn block_hash(&self, _number: U256) -> Result<B256, String> {
        // L2 block hashes wired in slice 7. Return zero for now — EVM contracts
        // rarely rely on BLOCKHASH beyond recent history; zero is a safe placeholder.
        Ok(B256::ZERO)
    }
}
