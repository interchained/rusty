//! DepositOracle — the main oracle: watches downloaded blocks, confirms deposits,
//! mints native aITC in the EVM state.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use nedb_engine::Db;
use revm::primitives::{Address, U256};
use serde_json::json;

use itc_evm::NedbState;

use crate::deposit::{scan_block_for_deposits, BridgeDeposit};
use crate::{DEPOSIT_CONFIRMATIONS, SATS_TO_WEI_FACTOR};

/// Default bridge governance fee: 500 basis points = 5%.
/// Send 1 ITC → 0.95 aITC minted; 0.05 ITC stays locked in the bridge address.
pub const DEFAULT_FEE_BPS: u64 = 500;
/// Maximum allowed fee: 1000 BPS = 10%.
pub const MAX_FEE_BPS: u64 = 1_000;

/// Oracle configuration — all tweakable via environment or config.
#[derive(Clone, Debug)]
pub struct OracleConfig {
    /// hash160 of the bridge lock P2PKH address on ITC L1.
    /// Set via `ITC_BRIDGE_HASH160` (40-char hex).
    pub bridge_lock_hash160: [u8; 20],
    /// Required L1 confirmations before minting aITC.
    pub confirmations: i32,
    /// Governance fee in basis points (1 BPS = 0.01%).
    /// `ITC_BRIDGE_FEE_BPS` env var. Default: 500 (5%).
    /// Fee stays locked in the bridge address — it is NOT released; it accrues
    /// as governance revenue to be swept by the operator via a separate process.
    pub fee_bps: u64,
}

impl OracleConfig {
    /// Load from environment.
    pub fn from_env() -> OracleConfig {
        let hash160_hex = std::env::var("ITC_BRIDGE_HASH160").unwrap_or_else(|_| {
            "0000000000000000000000000000000000000000".to_string()
        });
        let bytes = hex::decode(&hash160_hex).unwrap_or_default();
        let mut hash160 = [0u8; 20];
        if bytes.len() == 20 {
            hash160.copy_from_slice(&bytes);
        }
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

    /// Apply the governance fee to a gross amount in satoshis.
    /// Returns (net_sats, fee_sats).
    pub fn apply_fee(&self, gross_sats: u64) -> (u64, u64) {
        let fee = (gross_sats * self.fee_bps + 9_999) / 10_000; // ceiling division
        let net = gross_sats.saturating_sub(fee);
        (net, fee)
    }
}

/// A pending deposit waiting for L1 confirmations.
struct PendingDeposit {
    deposit: BridgeDeposit,
    mined_at_height: i32,
    required_height: i32,
}

/// The deposit oracle.
pub struct DepositOracle {
    config: OracleConfig,
    db: Arc<Db>,
    /// Deposits waiting for confirmation.
    pending: VecDeque<PendingDeposit>,
    /// Current L1 tip height (updated each time a block is processed).
    tip_height: i32,
}

impl DepositOracle {
    pub fn new(config: OracleConfig, db: Arc<Db>) -> Self {
        DepositOracle {
            config,
            db,
            pending: VecDeque::new(),
            tip_height: 0,
        }
    }

    /// Process a newly downloaded L1 block.
    ///
    /// Call this for every block as it arrives (or when scanning historical blocks).
    /// Returns the list of deposits that were just confirmed and minted.
    pub fn process_block(&mut self, block_raw: &[u8], height: i32) -> Vec<BridgeDeposit> {
        self.tip_height = height;

        // Scan the new block for bridge deposits.
        let found = scan_block_for_deposits(
            block_raw,
            &self.config.bridge_lock_hash160,
            height,
        );
        for deposit in found {
            let required = height + self.config.confirmations;
            println!(
                "[ORACLE] deposit detected: {} sats from {} at L1 height {} — waiting {} confirmations",
                deposit.amount_sats,
                deposit.l1_txid_display,
                height,
                self.config.confirmations,
            );
            self.pending.push_back(PendingDeposit {
                deposit,
                mined_at_height: height,
                required_height: required,
            });
        }

        // Mint any deposits that have reached required confirmations.
        let mut minted = Vec::new();
        while let Some(p) = self.pending.front() {
            if height < p.required_height {
                break; // not yet confirmed
            }
            let p = self.pending.pop_front().unwrap();
            let (net_sats, fee_sats) = self.config.apply_fee(p.deposit.amount_sats);
            let fee_pct = self.config.fee_bps as f64 / 100.0;
            match self.mint_net(&p.deposit, net_sats) {
                Ok(()) => {
                    println!(
                        "[ORACLE] ✅ minted {} aITC wei to 0x{} \
                         (gross={} fee={}@{:.2}% net={} L1 tx {})",
                        sats_to_wei(net_sats),
                        hex::encode(p.deposit.aitc_address),
                        p.deposit.amount_sats,
                        fee_sats,
                        fee_pct,
                        net_sats,
                        p.deposit.l1_txid_display,
                    );
                    minted.push(p.deposit);
                }
                Err(e) => {
                    println!("[ORACLE] ❌ mint failed for {}: {e}", p.deposit.l1_txid_display);
                }
            }
        }
        minted
    }

    /// Mint `net_sats` (post-fee) aITC to the depositor's EVM address.
    ///
    /// The governance fee is already deducted — `net_sats` is what the user receives.
    /// The fee portion stays locked in `BRIDGE_LOCK_ADDRESS` on L1 and accrues there.
    fn mint_net(&self, deposit: &BridgeDeposit, net_sats: u64) -> Result<(), String> {
        let state = NedbState::new(Arc::clone(&self.db));
        let addr = Address::from(deposit.aitc_address);
        let amount_wei = sats_to_wei(net_sats);
        let l1_txid_hex = hex::encode(deposit.l1_txid);
        let caused_by = vec![l1_txid_hex];

        // Read existing balance (if any).
        use revm::DatabaseRef;
        let existing = state
            .basic_ref(addr)
            .ok()
            .flatten()
            .map(|info| info.balance)
            .unwrap_or(U256::ZERO);

        let new_balance = existing + amount_wei;

        // Write directly to NEDB — native mint at the protocol level.
        // caused_by = [L1_txid] links the aITC balance to the ITC mainnet tx.
        let id = NedbState::addr_key(&addr);
        let data = json!({
            "balance": NedbState::u256_to_hex(new_balance),
            "nonce": 0u64,
            "code_hash": NedbState::hash_key(&revm::primitives::KECCAK_EMPTY),
            "origin": "bridge_deposit",
            "l1_txid": hex::encode(deposit.l1_txid),
            "gross_sats": deposit.amount_sats,
            "net_sats": net_sats,
        });
        state
            .db
            .put("evm_accounts", &id, data, caused_by, None, None)
            .map(|_| ())
            .map_err(|e| format!("NEDB put: {e}"))
    }

    /// Current number of unconfirmed pending deposits.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

/// Convert satoshis to aITC wei (1 satoshi = 10^10 wei so 1 ITC = 10^18 wei).
pub fn sats_to_wei(sats: u64) -> U256 {
    U256::from(sats) * U256::from(SATS_TO_WEI_FACTOR)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sats_to_wei_conversion() {
        // 1 ITC = 1e8 sats = 1e18 wei
        let one_itc_sats = 100_000_000u64;
        let wei = sats_to_wei(one_itc_sats);
        let expected = U256::from(10u64).pow(U256::from(18u64));
        assert_eq!(wei, expected, "1 ITC sats should equal 1e18 wei");
    }
}
