//! DepositOracle — the main oracle: watches downloaded blocks, confirms deposits,
//! mints native aITC in the EVM state.
//!
//! ## Safety guarantees (NEDB-backed)
//!
//! | Property        | Mechanism |
//! |-----------------|-----------|
//! | **Idempotent**  | `oracle_minted` collection — guard checked before every mint |
//! | **Retry-safe**  | `oracle_pending` collection — queue survives process crash   |
//! | **Reboot-safe** | `oracle_state` collection — tip height persisted after each block |

use std::sync::Arc;

use nedb_engine::Db;
use revm::primitives::{Address, U256};
use serde_json::json;

use itc_evm::state::{NedbState, COLL_ACCOUNTS};

use crate::deposit::{scan_block_for_deposits, BridgeDeposit};
use crate::{DEPOSIT_CONFIRMATIONS, SATS_TO_WEI_FACTOR};

// ── NEDB collection names for oracle metadata ─────────────────────────────────
const COLL_ORACLE_STATE:   &str = "oracle_state";   // tip height
const COLL_ORACLE_PENDING: &str = "oracle_pending";  // confirmation queue
const COLL_ORACLE_MINTED:  &str = "oracle_minted";  // idempotency guard

/// Default bridge governance fee: 500 basis points = 5%.
pub const DEFAULT_FEE_BPS: u64 = 500;
/// Maximum allowed fee: 1000 BPS = 10%.
pub const MAX_FEE_BPS: u64 = 1_000;

const ITC_HRP: &str = "itc";

fn hash160_from_bech32_address(addr: &str) -> Result<[u8; 20], String> {
    use bech32::FromBase32;
    let (hrp, data, _variant) =
        bech32::decode(addr).map_err(|e| format!("bech32 decode: {e}"))?;
    if hrp != ITC_HRP {
        return Err(format!("unexpected bech32 HRP \"{hrp}\", expected \"{ITC_HRP}\""));
    }
    if data.is_empty() {
        return Err("bech32 data is empty".to_string());
    }
    let program = Vec::<u8>::from_base32(&data[1..])
        .map_err(|e| format!("bech32 5-to-8 bit conversion: {e}"))?;
    if program.len() != 20 {
        return Err(format!("expected 20-byte witness program, got {} bytes", program.len()));
    }
    let mut hash160 = [0u8; 20];
    hash160.copy_from_slice(&program);
    Ok(hash160)
}

#[derive(Clone, Debug)]
pub struct OracleConfig {
    pub bridge_lock_hash160: [u8; 20],
    pub confirmations: i32,
    pub fee_bps: u64,
}

impl OracleConfig {
    pub fn from_env() -> OracleConfig {
        let hash160 = Self::resolve_bridge_hash160();
        let fee_bps = std::env::var("ITC_BRIDGE_FEE_BPS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DEFAULT_FEE_BPS)
            .min(MAX_FEE_BPS);
        OracleConfig {
            bridge_lock_hash160: hash160,
            confirmations: std::env::var("ITC_BRIDGE_CONFIRMATIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEPOSIT_CONFIRMATIONS),
            fee_bps,
        }
    }

    fn resolve_bridge_hash160() -> [u8; 20] {
        if let Ok(addr) = std::env::var("ITC_BRIDGE_ADDRESS") {
            let addr = addr.trim();
            if !addr.is_empty() {
                match hash160_from_bech32_address(addr) {
                    Ok(h) => {
                        println!("[ORACLE] bridge hash160 from ITC_BRIDGE_ADDRESS ({addr}): {}", hex::encode(h));
                        return h;
                    }
                    Err(e) => eprintln!("[ORACLE] ERROR: ITC_BRIDGE_ADDRESS decode failed: {e}"),
                }
            }
        }
        if let Ok(hex_str) = std::env::var("ITC_BRIDGE_HASH160") {
            let hex_str = hex_str.trim();
            if !hex_str.is_empty() {
                match hex::decode(hex_str) {
                    Ok(bytes) if bytes.len() == 20 => {
                        let mut h = [0u8; 20];
                        h.copy_from_slice(&bytes);
                        println!("[ORACLE] bridge hash160 from ITC_BRIDGE_HASH160: {}", hex::encode(h));
                        return h;
                    }
                    Ok(bytes) => eprintln!("[ORACLE] WARNING: ITC_BRIDGE_HASH160 = {} bytes, expected 20", bytes.len()),
                    Err(e) => eprintln!("[ORACLE] WARNING: ITC_BRIDGE_HASH160 is not valid hex: {e}"),
                }
            }
        }
        eprintln!("[ORACLE] WARNING: no bridge address configured — set ITC_BRIDGE_ADDRESS");
        [0u8; 20]
    }

    pub fn apply_fee(&self, gross_sats: u64) -> (u64, u64) {
        let fee = (gross_sats * self.fee_bps + 9_999) / 10_000;
        let net = gross_sats.saturating_sub(fee);
        (net, fee)
    }
}

// ── Pending deposit record ────────────────────────────────────────────────────

#[derive(Clone)]
struct PendingDeposit {
    deposit: BridgeDeposit,
    required_height: i32,
}

// ── Key helpers ───────────────────────────────────────────────────────────────

fn pending_key(txid: &[u8; 32]) -> String {
    format!("pending:{}", hex::encode(txid))
}

fn minted_key(txid: &[u8; 32]) -> String {
    format!("minted:{}", hex::encode(txid))
}

// ── The oracle ────────────────────────────────────────────────────────────────

pub struct DepositOracle {
    config: OracleConfig,
    /// Shared NEDB instance — Arc<Db> is internally thread-safe; no Mutex needed.
    db: Arc<Db>,
    pending: Vec<PendingDeposit>,
    tip_height: i32,
}

impl DepositOracle {
    /// Create and restore from NEDB.
    ///
    /// On first run the collections are empty and the oracle starts at height 0.
    /// On restart the oracle reloads its tip and pending queue from NEDB — no
    /// blocks are re-scanned, and no deposit can be double-minted.
    pub fn new(config: OracleConfig, db: Arc<Db>) -> Self {
        // ── Load persisted tip height ─────────────────────────────────────────
        let tip_height: i32 = db
            .get(COLL_ORACLE_STATE, "tip")
            .and_then(|n| n.data.get("height").and_then(|v| v.as_i64()))
            .map(|h| h as i32)
            .unwrap_or(0);

        // ── Reload pending confirmation queue ─────────────────────────────────
        // NEDB doesn't expose a collection scan in the current API surface, so we
        // track pending txids in a separate index document.
        let pending_ids: Vec<String> = db
            .get(COLL_ORACLE_STATE, "pending_index")
            .and_then(|n| {
                n.data.get("ids")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|e| e.as_str().map(str::to_owned)).collect())
            })
            .unwrap_or_default();

        let mut pending = Vec::new();
        for key in &pending_ids {
            if let Some(node) = db.get(COLL_ORACLE_PENDING, key) {
                if let Some(dep) = deserialize_pending(&node.data) {
                    pending.push(dep);
                }
            }
        }

        if tip_height > 0 || !pending.is_empty() {
            println!(
                "[ORACLE] Restored from NEDB: tip_height={tip_height} pending={} deposit(s)",
                pending.len()
            );
        }

        DepositOracle { config, db, pending, tip_height }
    }

    /// Process a newly downloaded L1 block.
    ///
    /// Idempotent: safe to call with the same block twice (already-minted
    /// deposits are skipped via `oracle_minted`).
    /// Crash-safe: the pending queue is persisted to NEDB before returning.
    pub fn process_block(&mut self, block_raw: &[u8], height: i32) -> Vec<BridgeDeposit> {
        self.tip_height = height;

        // Scan for new deposits in this block
        let found = scan_block_for_deposits(block_raw, &self.config.bridge_lock_hash160, height);
        for deposit in found {
            let required = height + self.config.confirmations;

            // Skip if already in pending (duplicate block delivery)
            let key = pending_key(&deposit.l1_txid);
            if self.pending.iter().any(|p| p.deposit.l1_txid == deposit.l1_txid) {
                continue;
            }
            // Skip if already minted (idempotency guard)
            if self.db.get(COLL_ORACLE_MINTED, &minted_key(&deposit.l1_txid)).is_some() {
                println!("[ORACLE] skipping already-minted deposit {}", deposit.l1_txid_display);
                continue;
            }

            println!(
                "[ORACLE] deposit detected: {} sats from {} at height {} — waiting {} confirmations",
                deposit.amount_sats, deposit.l1_txid_display, height, self.config.confirmations,
            );

            // Persist to NEDB before adding to in-memory queue
            let _ = self.db.put(
                COLL_ORACLE_PENDING, &key,
                serialize_pending(&deposit, required),
                vec![deposit.l1_txid_display.clone()], None, None,
            );
            self.pending.push(PendingDeposit { deposit, required_height: required });
        }

        // Mint confirmed deposits
        let mut minted = Vec::new();
        let mut remaining = Vec::new();
        for p in self.pending.drain(..) {
            if height < p.required_height {
                remaining.push(p);
                continue;
            }
            let (net_sats, fee_sats) = self.config.apply_fee(p.deposit.amount_sats);
            println!(
                "[ORACLE] confirmed: {} sats → {} net ({:.2}% fee = {} sats) from {}",
                p.deposit.amount_sats, net_sats,
                self.config.fee_bps as f64 / 100.0, fee_sats,
                p.deposit.l1_txid_display,
            );
            match self.mint_net(&p.deposit, net_sats) {
                Ok(()) => {
                    println!("[ORACLE] minted {} wei for {}", net_sats as u128 * SATS_TO_WEI_FACTOR as u128, p.deposit.l1_txid_display);
                    // Remove from pending NEDB collection
                    let _ = self.db.put(
                        COLL_ORACLE_PENDING, &pending_key(&p.deposit.l1_txid),
                        json!({"_deleted": true}), vec![], None, None,
                    );
                    minted.push(p.deposit);
                }
                Err(e) => {
                    eprintln!("[ORACLE] ERROR minting {}: {e}", p.deposit.l1_txid_display);
                    remaining.push(p); // retry next block
                }
            }
        }
        self.pending = remaining;

        // Persist state to NEDB
        self.persist_state();

        minted
    }

    // ── Private: NEDB persistence ─────────────────────────────────────────────

    fn persist_state(&self) {
        // Tip height
        let _ = self.db.put(
            COLL_ORACLE_STATE, "tip",
            json!({"height": self.tip_height}),
            vec![], None, None,
        );
        // Pending index (list of keys so we can reload on restart)
        let ids: Vec<String> = self.pending.iter()
            .map(|p| pending_key(&p.deposit.l1_txid))
            .collect();
        let _ = self.db.put(
            COLL_ORACLE_STATE, "pending_index",
            json!({"ids": ids}),
            vec![], None, None,
        );
    }

    // ── Private: mint ─────────────────────────────────────────────────────────

    fn mint_net(&self, deposit: &BridgeDeposit, net_sats: u64) -> Result<(), String> {
        let minted_key = minted_key(&deposit.l1_txid);
        let l1_txid_hex = hex::encode(deposit.l1_txid);

        // ── Idempotency guard ─────────────────────────────────────────────────
        if self.db.get(COLL_ORACLE_MINTED, &minted_key).is_some() {
            println!("[ORACLE] mint idempotency: {} already minted, skipping", deposit.l1_txid_display);
            return Ok(());
        }

        // ── Read current balance from EVM state ───────────────────────────────
        let addr = Address::from(deposit.aitc_address);
        let account_id = NedbState::addr_key(&addr);
        let current_balance: U256 = self.db
            .get(COLL_ACCOUNTS, &account_id)
            .and_then(|n| n.data.get("balance").and_then(|v| v.as_str()).map(|s| NedbState::hex_to_u256(s)))
            .unwrap_or(U256::ZERO);

        let amount_wei = sats_to_wei(net_sats);
        let new_balance = current_balance.checked_add(amount_wei).ok_or("balance overflow")?;

        // ── Write guard FIRST (crash-safe ordering) ───────────────────────────
        // Guard before balance: if we crash between guard-write and balance-write
        // the user gets an under-mint (deposit appears minted but balance not
        // updated). Under-mint is recoverable by operator; double-mint is not.
        let _ = self.db.put(
            COLL_ORACLE_MINTED, &minted_key,
            json!({
                "l1_txid":      l1_txid_hex,
                "net_sats":     net_sats,
                "gross_sats":   deposit.amount_sats,
                "aitc_address": hex::encode(deposit.aitc_address),
                "minted_at_l1": deposit.l1_height,
                "caused_by":    [l1_txid_hex],
                "balance_written": false,   // set to true after balance write
            }),
            vec![l1_txid_hex.clone()],
            None, None,
        );

        // ── Write new balance to EVM state ────────────────────────────────────
        let account_data = json!({
            "balance":    NedbState::u256_to_hex(new_balance),
            "nonce":      0u64,
            "code_hash":  NedbState::hash_key(&revm::primitives::KECCAK_EMPTY),
            "origin":     "bridge_deposit",
            "l1_txid":    l1_txid_hex,
            "gross_sats": deposit.amount_sats,
            "net_sats":   net_sats,
            "caused_by":  [l1_txid_hex.clone()],
        });
        let _ = self.db.put(COLL_ACCOUNTS, &account_id, account_data, vec![l1_txid_hex.clone()], None, None);

        // Mark balance as written (allows operator tooling to detect partial mints)
        let _ = self.db.put(
            COLL_ORACLE_MINTED, &minted_key,
            json!({
                "l1_txid":       l1_txid_hex,
                "net_sats":      net_sats,
                "gross_sats":    deposit.amount_sats,
                "aitc_address":  hex::encode(deposit.aitc_address),
                "minted_at_l1":  deposit.l1_height,
                "caused_by":     [l1_txid_hex.clone()],
                "balance_written": true,
            }),
            vec![l1_txid_hex.clone()],
            None, None,
        );

        Ok(())
    }
}

// ── Serde helpers for oracle_pending ─────────────────────────────────────────

fn serialize_pending(deposit: &BridgeDeposit, required_height: i32) -> serde_json::Value {
    json!({
        "txid":            hex::encode(deposit.l1_txid),
        "txid_display":    deposit.l1_txid_display,
        "amount_sats":     deposit.amount_sats,
        "aitc_address":    hex::encode(deposit.aitc_address),
        "l1_height":       deposit.l1_height,
        "required_height": required_height,
    })
}

fn deserialize_pending(data: &serde_json::Value) -> Option<PendingDeposit> {
    let txid_hex    = data.get("txid")?.as_str()?;
    let txid_bytes  = hex::decode(txid_hex).ok()?;
    let addr_hex    = data.get("aitc_address")?.as_str()?;
    let addr_bytes  = hex::decode(addr_hex).ok()?;
    let amount_sats = data.get("amount_sats")?.as_u64()?;
    let l1_height   = data.get("l1_height")?.as_i64()? as i32;
    let required_height = data.get("required_height")?.as_i64()? as i32;

    if txid_bytes.len() != 32 || addr_bytes.len() != 20 { return None; }

    let mut l1_txid = [0u8; 32];
    let mut aitc_address = [0u8; 20];
    l1_txid.copy_from_slice(&txid_bytes);
    aitc_address.copy_from_slice(&addr_bytes);

    let mut display = l1_txid;
    display.reverse();

    Some(PendingDeposit {
        deposit: BridgeDeposit {
            l1_txid,
            l1_txid_display: hex::encode(display),
            amount_sats,
            aitc_address,
            l1_height,
        },
        required_height,
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Convert satoshis to wei.  Public so the UTXO mirror (which lives in
/// `crate::utxo`) can call it without redefining the conversion.
pub fn sats_to_wei(sats: u64) -> U256 {
    U256::from(sats) * U256::from(SATS_TO_WEI_FACTOR)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bech32_decode_roundtrip() {
        let expected: [u8; 20] = [0x01; 20];
        use bech32::{ToBase32, Variant};
        let mut data = vec![bech32::u5::try_from_u8(0).unwrap()];
        data.extend(expected.to_base32());
        let addr = bech32::encode(ITC_HRP, data, Variant::Bech32).unwrap();
        let got = hash160_from_bech32_address(&addr).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn bech32_wrong_hrp_rejected() {
        use bech32::{ToBase32, Variant};
        let payload: [u8; 20] = [0x42; 20];
        let mut data = vec![bech32::u5::try_from_u8(0).unwrap()];
        data.extend(payload.to_base32());
        let addr = bech32::encode("bc", data, Variant::Bech32).unwrap();
        let result = hash160_from_bech32_address(&addr);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected \"itc\""));
    }

    #[test]
    fn apply_fee_ceiling() {
        let cfg = OracleConfig { bridge_lock_hash160: [0u8; 20], confirmations: 2, fee_bps: 500 };
        let (net, fee) = cfg.apply_fee(1000);
        assert_eq!(fee, 50);
        assert_eq!(net, 950);
        let (net, fee) = cfg.apply_fee(1);
        assert_eq!(fee, 1);
        assert_eq!(net, 0);
    }
}
