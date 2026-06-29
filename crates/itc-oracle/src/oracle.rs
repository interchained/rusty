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

/// ITC bech32 human-readable part.
const ITC_HRP: &str = "itc";

/// Decode an ITC bech32 address (e.g. `itc1q…`) to its 20-byte hash160.
///
/// ITC follows Bitcoin's bech32 encoding:
///   - `bech32::decode` → `(hrp, 5-bit data words, variant)`
///   - The first word is the witness version byte (0x00 for P2WPKH).
///   - The remaining words are the 5-bit-encoded 20-byte program.
///   - `bech32::convert_bits(&data[1..], 5, 8, false)` converts back to 8-bit bytes.
///
/// Returns an error string if the address is malformed, has the wrong HRP,
/// or does not produce exactly 20 bytes.
fn hash160_from_bech32_address(addr: &str) -> Result<[u8; 20], String> {
    use bech32::FromBase32;

    let (hrp, data, _variant) =
        bech32::decode(addr).map_err(|e| format!("bech32 decode: {e}"))?;

    if hrp != ITC_HRP {
        return Err(format!(
            "unexpected bech32 HRP \"{hrp}\", expected \"{ITC_HRP}\""
        ));
    }

    if data.is_empty() {
        return Err("bech32 data is empty".to_string());
    }

    // data[0] is the witness version (0 for P2WPKH/P2WSH).
    // data[1..] are the 5-bit-encoded witness program bytes.
    let program = Vec::<u8>::from_base32(&data[1..])
        .map_err(|e| format!("bech32 5-to-8 bit conversion: {e}"))?;

    if program.len() != 20 {
        return Err(format!(
            "expected 20-byte witness program, got {} bytes",
            program.len()
        ));
    }

    let mut hash160 = [0u8; 20];
    hash160.copy_from_slice(&program);
    Ok(hash160)
}

/// Oracle configuration — all tweakable via environment or config.
#[derive(Clone, Debug)]
pub struct OracleConfig {
    /// hash160 of the bridge lock P2WPKH address on ITC L1.
    ///
    /// Populated from one of two env vars (in priority order):
    ///   1. `ITC_BRIDGE_ADDRESS` — plain bech32 ITC address (e.g. `itc1q…`).
    ///      The hash160 is extracted automatically; the operator never needs to
    ///      manually compute it.
    ///   2. `ITC_BRIDGE_HASH160` — legacy 40-hex-char hash160 (kept for
    ///      backwards compatibility).
    ///
    /// If neither is set the field is zeroed (oracle will not match any outputs).
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
    ///
    /// Resolution order for the bridge hash160:
    ///
    /// 1. `ITC_BRIDGE_ADDRESS` (bech32 ITC address) — decoded automatically.
    /// 2. `ITC_BRIDGE_HASH160` (40-char hex) — legacy fallback.
    /// 3. All-zeros sentinel (oracle logs a warning and matches nothing).
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

    /// Resolve the 20-byte bridge hash160 from environment variables.
    ///
    /// Tries `ITC_BRIDGE_ADDRESS` first (bech32 decode), then falls back to
    /// `ITC_BRIDGE_HASH160` (hex), then returns zeroes with a warning.
    fn resolve_bridge_hash160() -> [u8; 20] {
        // ── Priority 1: bech32 ITC address ───────────────────────────────────
        if let Ok(addr) = std::env::var("ITC_BRIDGE_ADDRESS") {
            let addr = addr.trim();
            if !addr.is_empty() {
                match hash160_from_bech32_address(addr) {
                    Ok(h) => {
                        println!(
                            "[ORACLE] bridge hash160 resolved from ITC_BRIDGE_ADDRESS \
                             ({addr}): {}",
                            hex::encode(h)
                        );
                        return h;
                    }
                    Err(e) => {
                        // Surface the error loudly so the operator knows immediately.
                        eprintln!(
                            "[ORACLE] ERROR: ITC_BRIDGE_ADDRESS is set but could not be \
                             decoded: {e}. Falling back to ITC_BRIDGE_HASH160."
                        );
                    }
                }
            }
        }

        // ── Priority 2: legacy raw hex hash160 ───────────────────────────────
        if let Ok(hex_str) = std::env::var("ITC_BRIDGE_HASH160") {
            let hex_str = hex_str.trim();
            if !hex_str.is_empty() {
                match hex::decode(hex_str) {
                    Ok(bytes) if bytes.len() == 20 => {
                        let mut h = [0u8; 20];
                        h.copy_from_slice(&bytes);
                        println!(
                            "[ORACLE] bridge hash160 loaded from ITC_BRIDGE_HASH160: {}",
                            hex::encode(h)
                        );
                        return h;
                    }
                    Ok(bytes) => {
                        eprintln!(
                            "[ORACLE] WARNING: ITC_BRIDGE_HASH160 decoded to {} bytes, \
                             expected 20. Ignoring.",
                            bytes.len()
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "[ORACLE] WARNING: ITC_BRIDGE_HASH160 is not valid hex: {e}. \
                             Ignoring."
                        );
                    }
                }
            }
        }

        // ── Fallback: all-zeros (oracle will not match any outputs) ──────────
        eprintln!(
            "[ORACLE] WARNING: neither ITC_BRIDGE_ADDRESS nor ITC_BRIDGE_HASH160 is set. \
             The oracle will not match any bridge deposits. Set ITC_BRIDGE_ADDRESS to the \
             bech32 ITC address of the bridge lock wallet."
        );
        [0u8; 20]
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
    db: Arc<Mutex<Db>>,
    /// Deposits waiting for confirmation.
    pending: VecDeque<PendingDeposit>,
    /// Current L1 tip height (updated each time a block is processed).
    tip_height: i32,
}

impl DepositOracle {
    pub fn new(config: OracleConfig, db: Arc<Mutex<Db>>) -> Self {
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
            println!(
                "[ORACLE] confirmed: {} sats gross → {} sats net ({:.2}% fee = {} sats) \
                 from L1 tx {}",
                p.deposit.amount_sats,
                net_sats,
                fee_pct,
                fee_sats,
                p.deposit.l1_txid_display,
            );
            match self.mint_net(&p.deposit, net_sats) {
                Ok(()) => {
                    println!(
                        "[ORACLE] minted {} aITC wei for {}",
                        net_sats as u128 * SATS_TO_WEI_FACTOR,
                        p.deposit.l1_txid_display,
                    );
                    minted.push(p.deposit);
                }
                Err(e) => {
                    eprintln!(
                        "[ORACLE] ERROR minting deposit {}: {e}",
                        p.deposit.l1_txid_display,
                    );
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

        let current_balance = state
            .balance(&addr)
            .map_err(|e| format!("read balance: {e}"))?;
        let new_balance = current_balance
            .checked_add(amount_wei)
            .ok_or("balance overflow")?;

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
            "caused_by": caused_by,
        });
        state
            .upsert(&id, data)
            .map_err(|e| format!("write balance: {e}"))?;

        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn sats_to_wei(sats: u64) -> U256 {
    U256::from(sats) * U256::from(SATS_TO_WEI_FACTOR)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that a well-formed ITC bech32 address round-trips correctly.
    ///
    /// Address constructed from 20 bytes of 0x01.  The bech32 encoding of
    /// witness-version-0 + 20×0x01 with HRP "itc" can be computed offline and
    /// hardcoded here for a deterministic unit test.
    #[test]
    fn bech32_decode_roundtrip() {
        // 20 bytes of 0x01
        let expected: [u8; 20] = [0x01; 20];

        // Encode: witness version 0 + convert_bits(expected, 8, 5, true)
        use bech32::{ToBase32, Variant};
        let mut data = vec![bech32::u5::try_from_u8(0).unwrap()]; // witness version 0
        data.extend(expected.to_base32());
        let addr = bech32::encode(ITC_HRP, data, Variant::Bech32).unwrap();

        let got = hash160_from_bech32_address(&addr).unwrap();
        assert_eq!(got, expected, "decoded hash160 should match original bytes");
    }

    #[test]
    fn bech32_wrong_hrp_rejected() {
        // Encode with "bc" hrp (Bitcoin mainnet) — should be rejected.
        use bech32::{ToBase32, Variant};
        let payload: [u8; 20] = [0x42; 20];
        let mut data = vec![bech32::u5::try_from_u8(0).unwrap()];
        data.extend(payload.to_base32());
        let addr = bech32::encode("bc", data, Variant::Bech32).unwrap();

        let result = hash160_from_bech32_address(&addr);
        assert!(result.is_err(), "wrong HRP should return Err");
        assert!(result.unwrap_err().contains("expected \"itc\""));
    }

    #[test]
    fn apply_fee_ceiling() {
        let cfg = OracleConfig {
            bridge_lock_hash160: [0u8; 20],
            confirmations: 2,
            fee_bps: 500,
        };
        // 1000 sats × 5% = 50 sats fee, 950 sats net
        let (net, fee) = cfg.apply_fee(1000);
        assert_eq!(fee, 50);
        assert_eq!(net, 950);

        // Ceiling: 1 sat → fee = ceil(1 × 500 / 10000) = 1, net = 0
        let (net, fee) = cfg.apply_fee(1);
        assert_eq!(fee, 1);
        assert_eq!(net, 0);
    }
}
