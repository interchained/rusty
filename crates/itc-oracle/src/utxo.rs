//! UTXO mirror — tracks ITC L1 P2PKH balances and mirrors them as native aITC.
//!
//! Because Bitcoin P2PKH outputs only reveal hash160(pubkey) — not the pubkey
//! itself — the mirror uses a two-stage approach:
//!
//!   Stage 1 (receive): output to P2PKH → add to pending_utxos[hash160]
//!   Stage 2 (spend):   input spends P2PKH → scriptSig reveals pubkey
//!                       → derive ETH address from pubkey
//!                       → record known_keys[hash160] = eth_address
//!                       → immediately credit any pending sats to the ETH address
//!
//! Once a hash160 is mapped to an ETH address (i.e., the user has spent at least
//! once from that ITC address), all future received UTXOs are credited immediately.
//!
//! Net effect: the moment you sign any ITC transaction on mainnet, your entire
//! accumulated balance (all time) appears on L2 automatically. No manual bridge.

use std::collections::HashMap;
use std::sync::Arc;

use nedb_engine::Db;
use revm::primitives::{Address, KECCAK_EMPTY, U256};
use serde_json::json;

use itc_proto::script::{p2pkh_hash160, p2pkh_scriptsig_pubkey, pubkey_to_eth_address};
use itc_proto::tx::block_transactions;

use itc_evm::NedbState;
use crate::oracle::sats_to_wei;

// NEDB collection names for oracle state persistence
const COLL_UTXO_PENDING:  &str = "oracle_utxo_pending";   // hash160_hex → {sats}
const COLL_KEY_MAP:        &str = "oracle_key_map";        // hash160_hex → {eth_addr}

/// The UTXO mirror oracle.
pub struct UtxoMirror {
    db: Arc<Db>,
    /// hash160 → total pending unresolved sats (pubkey not yet seen).
    pending: HashMap<[u8; 20], u64>,
    /// hash160 → aITC ETH address (learned when the address first spends on L1).
    known: HashMap<[u8; 20], [u8; 20]>,
}

impl UtxoMirror {
    /// Create and restore from NEDB (resumes any persisted mappings after restart).
    pub fn open(db: Arc<Db>) -> Self {
        let mut mirror = UtxoMirror {
            db: Arc::clone(&db),
            pending: HashMap::new(),
            known: HashMap::new(),
        };
        mirror.restore_from_nedb();
        mirror
    }

    /// Process one block — called for every block in order (genesis → tip).
    /// Returns (newly_minted_count, total_aITC_wei_minted_this_block).
    pub fn process_block(&mut self, block_raw: &[u8], height: i32) -> (u64, U256) {
        let txs = block_transactions(block_raw);
        let mut minted_count = 0u64;
        let mut minted_total = U256::ZERO;

        for tx in &txs {
            let txid_hex = tx.txid_display_hex();
            let is_coinbase = tx.inputs.len() == 1
                && tx.inputs[0].prev_txid == [0u8; 32]
                && tx.inputs[0].prev_vout == 0xffffffff;

            // ── Pass 1: process inputs (discover pubkeys, update balances) ──
            if !is_coinbase {
                for inp in &tx.inputs {
                    if let Some(pubkey) = p2pkh_scriptsig_pubkey(&inp.script_sig) {
                        if let Some(eth_addr) = pubkey_to_eth_address(&pubkey) {
                            // Derive hash160 of this pubkey so we can match outputs.
                            let hash160 = itc_proto::signer_util::hash160_from_pubkey(&pubkey);

                            if !self.known.contains_key(&hash160) {
                                // First time we see this key — flush any pending balance.
                                let pending_sats = self.pending.remove(&hash160).unwrap_or(0);
                                self.known.insert(hash160, eth_addr);
                                self.persist_key_map(&hash160, &eth_addr);

                                if pending_sats > 0 {
                                    let wei = sats_to_wei(pending_sats);
                                    self.credit_aitc(&eth_addr, wei, &txid_hex);
                                    minted_count += 1;
                                    minted_total += wei;
                                    println!(
                                        "[MIRROR] key revealed h={height} hash160={} \
                                         eth=0x{} pending={}sat -> {}wei",
                                        hex::encode(hash160),
                                        hex::encode(eth_addr),
                                        pending_sats,
                                        wei,
                                    );
                                }
                            }
                        }
                    }
                }
            }

            // ── Pass 2: process outputs (credit or queue new UTXOs) ──────────
            for out in &tx.outputs {
                if let Some(hash160) = p2pkh_hash160(&out.script_pubkey) {
                    let sats = out.value;
                    if sats == 0 { continue; }

                    if let Some(&eth_addr) = self.known.get(&hash160) {
                        // Known key — credit immediately.
                        let wei = sats_to_wei(sats);
                        self.credit_aitc(&eth_addr, wei, &txid_hex);
                        minted_count += 1;
                        minted_total += wei;
                    } else {
                        // Unknown key — accumulate as pending.
                        *self.pending.entry(hash160).or_insert(0) += sats;
                        self.persist_pending(&hash160, self.pending[&hash160]);
                    }
                }
            }
        }

        if minted_total > U256::ZERO {
            println!(
                "[MIRROR] block h={height} -- minted {minted_count} credits, total {}wei",
                minted_total
            );
        }

        (minted_count, minted_total)
    }

    // ── NEDB helpers ──────────────────────────────────────────────────────────

    fn credit_aitc(&self, eth_addr: &[u8; 20], wei: U256, caused_by_txid: &str) {
        let state = NedbState::new(Arc::clone(&self.db));
        let addr = Address::from(*eth_addr);
        let caused_by = vec![caused_by_txid.to_string()];

        // `DatabaseRef` lives in `revm::db` (re-exported from `revm::primitives::db`),
        // not at the `revm` crate root — that path doesn't exist in revm 3.x.
        use revm::db::DatabaseRef;
        let existing = state
            .basic(addr)
            .ok()
            .flatten()
            .map(|i| i.balance)
            .unwrap_or(U256::ZERO);

        let new_balance = existing + wei;
        let id = NedbState::addr_key(&addr);
        let data = json!({
            "balance": NedbState::u256_to_hex(new_balance),
            "nonce": 0u64,
            "code_hash": NedbState::hash_key(&KECCAK_EMPTY),
            "origin": "utxo_mirror",
        });
        let _ = state.db.put("evm_accounts", &id, data, caused_by, None, None);
    }

    fn persist_key_map(&self, hash160: &[u8; 20], eth_addr: &[u8; 20]) {
        let id = hex::encode(hash160);
        let data = json!({ "eth": hex::encode(eth_addr) });
        let _ = self.db.put(COLL_KEY_MAP, &id, data, vec![], None, None);
    }

    fn persist_pending(&self, hash160: &[u8; 20], sats: u64) {
        let id = hex::encode(hash160);
        let data = json!({ "sats": sats });
        let _ = self.db.put(COLL_UTXO_PENDING, &id, data, vec![], None, None);
    }

    fn restore_from_nedb(&mut self) {
        // Restore known key map. nedb-engine's `list()` returns `Vec<Node>`
        // (not `Result`), so iterate directly.
        for node in self.db.list(COLL_KEY_MAP) {
            if let Some(eth_hex) = node.data.get("eth").and_then(|v| v.as_str()) {
                if let (Ok(h), Ok(e)) = (
                    hex::decode(&node.id),
                    hex::decode(eth_hex),
                ) {
                    if h.len() == 20 && e.len() == 20 {
                        let mut hash160 = [0u8; 20];
                        let mut eth = [0u8; 20];
                        hash160.copy_from_slice(&h);
                        eth.copy_from_slice(&e);
                        self.known.insert(hash160, eth);
                    }
                }
            }
        }
        // Restore pending balances.
        for node in self.db.list(COLL_UTXO_PENDING) {
            if let Some(sats) = node.data.get("sats").and_then(|v| v.as_u64()) {
                if let Ok(h) = hex::decode(&node.id) {
                    if h.len() == 20 {
                        let mut hash160 = [0u8; 20];
                        hash160.copy_from_slice(&h);
                        self.pending.insert(hash160, sats);
                    }
                }
            }
        }
        if !self.known.is_empty() || !self.pending.is_empty() {
            println!(
                "[MIRROR] restored {} known keys + {} pending balances from NEDB",
                self.known.len(),
                self.pending.len()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sats_to_wei_one_itc() {
        let one_itc = 100_000_000u64;
        let wei = sats_to_wei(one_itc);
        let expected = U256::from(10u64).pow(U256::from(18u64));
        assert_eq!(wei, expected);
    }
}
