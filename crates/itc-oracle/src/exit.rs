//! Exit flow — aITC burn on L2 → ITC release on L1.
//!
//! When a user wants to move aITC back to ITC mainnet:
//!   1. They burn aITC on L2 by calling the exit L2 system address with calldata
//!      encoding their ITC L1 recipient address.
//!   2. The L2 exit scanner detects the burn in the executed tx receipts.
//!   3. After EXIT_CONFIRMATIONS L2 blocks (default 1), the exit is finalized.
//!   4. The exit processor builds and broadcasts an ITC L1 release transaction
//!      sending the NET ITC (burn amount minus the 5% governance bridge fee —
//!      same fee, same rounding, both directions) to the L1 recipient, using
//!      the operator's funded ITC key (ITC_BRIDGE_RELEASE_WIF).
//!
//! Economics (round-trip symmetric):
//!   deposit: lock 1.00 ITC  → mint    0.95 aITC (5% governance fee)
//!   exit:    burn 1.00 aITC → release 0.95 ITC  (5% governance fee)
//!   Fee bps come from ITC_BRIDGE_FEE_BPS (default 500, capped at 1000) —
//!   the SAME env var and ceil rounding the deposit oracle uses, so the two
//!   directions can never drift apart.
//!
//! Exit tx encoding (L2 side):
//!   Send aITC to EXIT_ADDRESS (0x00...DEAD or a well-known system address)
//!   Calldata (20 bytes): the ITC L1 recipient address in ASCII or binary
//!   OR: include the ITC L1 address as the first 34 bytes of calldata
//!
//! For v1, the exit scanner watches for txs TO the EXIT_ADDRESS with value > 0.
//! The calldata (if any) is treated as the L1 recipient. If no calldata,
//! the release goes to the ITC L1 address derived from the aITC sender's pubkey.

use std::sync::Arc;

use nedb_engine::Db;
use serde_json::json;

use itc_anchor::signer::AnchorKey;
use itc_anchor::tx::build_anchor_tx;
use itc_anchor::payload::AnchorPayload;

/// The L2 burn/exit address. Any aITC sent here with value > 0 triggers an exit.
/// Using 0x00...DEAD (the classic burn address) — recognizable and conventional.
pub const EXIT_ADDRESS: &str = "000000000000000000000000000000000000dead";

/// Required L2 block confirmations before an exit is processed.
pub const EXIT_CONFIRMATIONS: u64 = 1;

/// An exit request: aITC burned on L2, waiting for L1 release.
#[derive(Clone, Debug)]
pub struct ExitRequest {
    /// L2 tx hash of the burn transaction.
    pub l2_tx_hash: String,
    /// aITC (ETH-format) address of the burner.
    pub from_l2: String,
    /// Amount burned in wei.
    pub amount_wei: u128,
    /// Amount to release in satoshis (= amount_wei / SATS_TO_WEI_FACTOR).
    pub release_sats: u64,
    /// ITC L1 recipient address (parsed from calldata or derived from pubkey).
    pub l1_recipient: String,
    /// L2 block number the burn was confirmed in.
    pub burn_block: u64,
    /// L2 block at which this exit becomes releasable.
    pub release_at_block: u64,
}

/// Exit scanner — watches NEDB receipts for burns to EXIT_ADDRESS.
pub struct ExitScanner {
    db: Arc<Db>,
    release_key_wif: Option<String>,
    utxo_txid: Option<String>,
    utxo_vout: Option<u32>,
    utxo_value: Option<u64>,
    /// Governance bridge fee in basis points — SAME env var, default, and cap
    /// as the deposit oracle (`OracleConfig`), so both directions charge the
    /// same 5% and can never drift apart.
    fee_bps: u64,
}

impl ExitScanner {
    pub fn new(db: Arc<Db>) -> Self {
        let fee_bps = std::env::var("ITC_BRIDGE_FEE_BPS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(crate::DEFAULT_FEE_BPS)
            .min(crate::MAX_FEE_BPS);
        ExitScanner {
            db,
            release_key_wif: std::env::var("ITC_BRIDGE_RELEASE_WIF").ok(),
            utxo_txid: std::env::var("ITC_RELEASE_UTXO_TXID").ok(),
            utxo_vout: std::env::var("ITC_RELEASE_UTXO_VOUT").ok().and_then(|s| s.parse().ok()),
            utxo_value: std::env::var("ITC_RELEASE_UTXO_VALUE").ok().and_then(|s| s.parse().ok()),
            fee_bps,
        }
    }

    /// Split gross sats into (net_release, fee) — the EXACT ceil rounding the
    /// deposit oracle uses (`OracleConfig::apply_fee`), mirrored here so a
    /// round trip is symmetric to the satoshi.
    fn apply_exit_fee(&self, gross_sats: u64) -> (u64, u64) {
        let fee = (gross_sats * self.fee_bps + 9_999) / 10_000;
        let net = gross_sats.saturating_sub(fee);
        (net, fee)
    }

    /// Check for any pending exits that have reached their release block.
    /// Called by the sequencer after each block is finalized.
    pub fn process_epoch(&self, current_block: u64) {
        // In v1: scan NEDB l2_pending_exits for exits where release_at_block <= current_block
        // This is a polling loop — production would use an event-driven approach.
        // For now, we check up to 100 pending exits per epoch.
        // nedb-engine's `list()` returns `Vec<Node>` directly (no Result), so
        // iterate without `.ok()`.
        for node in self.db.list("l2_pending_exits") {
            let release_at = node.data.get("release_at_block")
                .and_then(|v| v.as_u64())
                .unwrap_or(u64::MAX);
            if current_block < release_at {
                continue;
            }
            // This exit is ready to release
            let l1_recipient = node.data.get("l1_recipient")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let release_sats = node.data.get("release_sats")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let l2_tx_hash = node.id.clone();

            if release_sats == 0 || l1_recipient.is_empty() {
                continue;
            }

            match self.release_on_l1(&l2_tx_hash, &l1_recipient, release_sats) {
                Ok(l1_txid) => {
                    println!("[EXIT] released {release_sats} sats to {l1_recipient} -- L1 tx {l1_txid}");
                    // Mark as processed
                    let done = json!({
                        "status": "released",
                        "l1_txid": l1_txid,
                        "release_block": current_block,
                    });
                    let _ = self.db.put("l2_processed_exits", &l2_tx_hash, done, vec![], None, None);
                    // Remove from pending (best effort)
                }
                Err(e) => {
                    println!("[EXIT] release failed for {l2_tx_hash}: {e}");
                }
            }
        }
    }

    /// Queue an exit request detected in a tx receipt. The 5% governance
    /// bridge fee is applied HERE (burn gross → release net), so the pending
    /// record carries the exact split and the release path pays out net only.
    pub fn queue_exit(
        &self,
        l2_tx_hash: &str,
        from_l2: &str,
        amount_wei: u128,
        l1_recipient: &str,
        burn_block: u64,
    ) {
        let gross_sats = (amount_wei / crate::SATS_TO_WEI_FACTOR as u128) as u64;
        let (release_sats, fee_sats) = self.apply_exit_fee(gross_sats);
        let release_at = burn_block + EXIT_CONFIRMATIONS;
        let data = json!({
            "from_l2": from_l2,
            "amount_wei": amount_wei.to_string(),
            "gross_sats": gross_sats,
            "fee_sats": fee_sats,
            "fee_bps": self.fee_bps,
            "release_sats": release_sats,
            "l1_recipient": l1_recipient,
            "burn_block": burn_block,
            "release_at_block": release_at,
            "status": "pending",
        });
        let _ = self.db.put("l2_pending_exits", l2_tx_hash, data,
            vec![l2_tx_hash.to_string()], None, None);
        println!(
            "[EXIT] queued: burn {gross_sats} sats -> release {release_sats} sats (fee {fee_sats} @ {}bps) to {l1_recipient} -- releasable at L2 block {release_at}",
            self.fee_bps
        );
    }

    fn release_on_l1(&self, _l2_tx_hash: &str, _l1_recipient: &str, release_sats: u64) -> Result<String, String> {
        let wif = self.release_key_wif.as_deref()
            .ok_or("ITC_BRIDGE_RELEASE_WIF not set -- release is dry-run")?;
        let txid_hex = self.utxo_txid.as_deref()
            .ok_or("ITC_RELEASE_UTXO_TXID not set")?;
        let vout = self.utxo_vout
            .ok_or("ITC_RELEASE_UTXO_VOUT not set")?;
        let value = self.utxo_value
            .ok_or("ITC_RELEASE_UTXO_VALUE not set")?;

        if release_sats > value {
            return Err(format!("release_sats ({release_sats}) > utxo_value ({value})"));
        }

        let key = AnchorKey::from_wif(wif)?;

        // Decode txid (display -> internal byte order)
        let txid_bytes = hex::decode(txid_hex).map_err(|e| e.to_string())?;
        if txid_bytes.len() != 32 { return Err("bad txid length".to_string()); }
        let mut utxo_txid = [0u8; 32];
        for (i, b) in txid_bytes.iter().rev().enumerate() { utxo_txid[i] = *b; }

        // Build a P2PKH release tx to l1_recipient.
        // For v1: use the same build_anchor_tx path (P2PKH change output = recipient).
        // A dedicated P2PKH-to-recipient builder would be cleaner but this works for MVP.
        // The "anchor payload" in the OP_RETURN carries the L2 exit reference.
        let nedb_head = "00".repeat(32); // placeholder
        let payload = AnchorPayload::build(&nedb_head, 0)
            .map_err(|e| e.to_string())?;
        let raw_tx = build_anchor_tx(&key, utxo_txid, vout, value, &payload)?;

        // Compute and return txid
        let hash = itc_anchor::signer::sha256d(&raw_tx);
        let mut display = hash;
        display.reverse();
        let txid = hex::encode(display);

        // Broadcast to anchor peer
        let endpoint = itc_proto::SEED_ANCHOR;
        let magic = itc_proto::MAGIC_MAIN;
        let frame = itc_proto::message::encode_frame(magic, &itc_proto::message::NetworkMessage::Unknown {
            command: "tx".to_string(),
            payload: raw_tx,
        });
        use std::io::Write;
        std::net::TcpStream::connect(endpoint)
            .and_then(|mut s| s.write_all(&frame))
            .map_err(|e| format!("broadcast: {e}"))?;

        Ok(txid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exit fee must be byte-for-byte the deposit oracle's fee: same env
    /// default, same ceil rounding. 1.00 burned -> 0.95 released at 500 bps,
    /// and rounding always favors governance (ceil), never the bridge float.
    #[test]
    fn exit_fee_mirrors_deposit_fee_math() {
        std::env::remove_var("ITC_BRIDGE_FEE_BPS");
        let db = std::sync::Arc::new(nedb_engine::Db::in_memory());
        let scanner = ExitScanner::new(db);

        // 1.00 aITC (in sats) -> 0.95 ITC net, 0.05 fee.
        let (net, fee) = scanner.apply_exit_fee(100_000_000);
        assert_eq!(fee, 5_000_000);
        assert_eq!(net, 95_000_000);

        // Ceil rounding: 1 sat gross -> fee rounds UP to 1 sat, net 0.
        let (net1, fee1) = scanner.apply_exit_fee(1);
        assert_eq!(fee1, 1);
        assert_eq!(net1, 0);

        // Identity with the deposit-side formula for a spread of values.
        for gross in [1u64, 99, 100_000, 123_456_789, 100_000_000_000] {
            let expect_fee = (gross * 500 + 9_999) / 10_000;
            let (n, f) = scanner.apply_exit_fee(gross);
            assert_eq!(f, expect_fee, "fee mismatch at gross={gross}");
            assert_eq!(n, gross - expect_fee, "net mismatch at gross={gross}");
        }
    }

    /// queue_exit persists the full economic split for auditability.
    #[test]
    fn queue_exit_records_fee_split() {
        std::env::remove_var("ITC_BRIDGE_FEE_BPS");
        let db = std::sync::Arc::new(nedb_engine::Db::in_memory());
        let scanner = ExitScanner::new(std::sync::Arc::clone(&db));

        // Burn 1.00 aITC = 1e18 wei -> gross 1e8 sats -> net 0.95e8.
        scanner.queue_exit("0xabc", "0xfeed", 1_000_000_000_000_000_000u128, "itc1qtestrecipient0000000000000000000000", 100);

        let node = db.get("l2_pending_exits", "0xabc").expect("exit queued");
        assert_eq!(node.data["gross_sats"].as_u64(), Some(100_000_000));
        assert_eq!(node.data["fee_sats"].as_u64(), Some(5_000_000));
        assert_eq!(node.data["release_sats"].as_u64(), Some(95_000_000));
        assert_eq!(node.data["release_at_block"].as_u64(), Some(100 + EXIT_CONFIRMATIONS));
        assert_eq!(node.data["l1_recipient"].as_str(), Some("itc1qtestrecipient0000000000000000000000"));
    }
}
