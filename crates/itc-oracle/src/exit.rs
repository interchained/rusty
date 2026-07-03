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
use itc_anchor::tx::{broadcast_tx, build_release_tx, MIN_FEE_SATS};

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
    /// WIF that funds releases. Its LEGACY P2PKH address holds the float we spend
    /// (key-funded); unset → dry-run (the exactly-once guard keeps exits pending).
    release_key_wif: Option<String>,
    /// The bech32 bridge address (`ITC_BRIDGE_ADDRESS`) that change is returned
    /// to. Cached so a missing/invalid value fails release cleanly (retryable),
    /// not silently.
    bridge_change_addr: Option<String>,
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
            bridge_change_addr: std::env::var("ITC_BRIDGE_ADDRESS").ok(),
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
    ///
    /// EXACTLY-ONCE PAYOUT — the money-safety heart of the exit path (mirrors
    /// the mint side's `oracle_minted` guard). Without this, `process_epoch`
    /// runs every 5s block, `release_at_block <= current_block` stays true for
    /// an already-paid exit forever, and the recipient is re-paid every block
    /// until the release wallet is drained. The guard is BEFORE any payment:
    ///
    ///   l2_processed_exits[tx] == "released"  → already paid: drop from
    ///       pending, skip. (idempotency — the drain guard.)
    ///   l2_processed_exits[tx] == "releasing" → a release was (or may have
    ///       been) broadcast before a crash: NEVER auto-retry — that risks a
    ///       double-pay. Leave for manual review, skip every epoch.
    ///
    /// Intent is marked "releasing" and flushed BEFORE `release_on_l1` builds
    /// or broadcasts, so a crash mid-broadcast is recoverable as "releasing"
    /// (manual review) rather than silently re-released. A pre-broadcast
    /// failure (dry-run / unconfigured / validation) clears the intent so a
    /// transient failure retries next epoch — a SUCCESS can never re-fire.
    pub fn process_epoch(&self, current_block: u64) {
        for node in self.db.list("l2_pending_exits") {
            let release_at = node.data.get("release_at_block")
                .and_then(|v| v.as_u64())
                .unwrap_or(u64::MAX);
            if current_block < release_at {
                continue;
            }
            let l2_tx_hash = node.id.clone();

            // ── Exactly-once guard (BEFORE any payment) ──────────────────────
            if let Some(prev) = self.db.get("l2_processed_exits", &l2_tx_hash) {
                match prev.data.get("status").and_then(|v| v.as_str()) {
                    Some("released") => {
                        // Already paid. Ensure it's out of the pending scan and move on.
                        let _ = self.db.delete("l2_pending_exits", &l2_tx_hash);
                        continue;
                    }
                    Some("releasing") => {
                        // In-flight across a crash — a broadcast may have happened.
                        // Do NOT auto-retry (double-pay risk). Manual review only.
                        continue;
                    }
                    _ => {}
                }
            }

            let l1_recipient = node.data.get("l1_recipient")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let release_sats = node.data.get("release_sats")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            if release_sats == 0 || l1_recipient.is_empty() {
                continue;
            }

            // Mark intent BEFORE broadcast and make it durable — so a crash
            // between broadcast and the "released" write is recoverable as
            // "releasing" (manual review), never silently re-paid.
            let intent = json!({
                "status": "releasing",
                "l1_recipient": &l1_recipient,
                "release_sats": release_sats,
                "intent_block": current_block,
            });
            let _ = self.db.put("l2_processed_exits", &l2_tx_hash, intent, vec![], None, None);
            self.db.flush_all();

            match self.release_on_l1(&l2_tx_hash, &l1_recipient, release_sats) {
                Ok(l1_txid) => {
                    let done = json!({
                        "status": "released",
                        "l1_txid": l1_txid,
                        "l1_recipient": &l1_recipient,
                        "release_sats": release_sats,
                        "release_block": current_block,
                    });
                    let _ = self.db.put("l2_processed_exits", &l2_tx_hash, done, vec![], None, None);
                    let _ = self.db.delete("l2_pending_exits", &l2_tx_hash);
                    self.db.flush_all();
                    println!("[EXIT] released {release_sats} sats to {l1_recipient} -- L1 tx {l1_txid}");
                }
                Err(e) => {
                    // All CURRENT release_on_l1 error paths fail BEFORE broadcast
                    // (unset WIF/UTXO, validation), so clearing the intent is safe
                    // and lets a transient failure retry next epoch. NOTE for the
                    // real P2PKH release builder: if an error can occur AFTER the
                    // broadcast leaves the process, that path must LEAVE the
                    // "releasing" marker (manual review), not clear it.
                    let _ = self.db.delete("l2_processed_exits", &l2_tx_hash);
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

    /// Pay `release_sats` to `l1_recipient` on ITC L1, funded from the bridge
    /// WIF's LEGACY P2PKH float (key-funded), with change → the bech32 bridge
    /// address. Legacy-signed input, segwit (P2WPKH) outputs — see
    /// `itc_anchor::tx::build_release_tx`.
    ///
    /// Error semantics matter for the exactly-once guard in `process_epoch`:
    /// every path here fails BEFORE the tx leaves the process (unset WIF/addr,
    /// no UTXO, build error) EXCEPT the final `broadcast_tx`, which only returns
    /// Ok on an accepted txid and Err on a rejected/unreachable send (not in the
    /// mempool → safe to retry). So an Err never corresponds to spent funds.
    fn release_on_l1(&self, _l2_tx_hash: &str, l1_recipient: &str, release_sats: u64) -> Result<String, String> {
        let wif = self.release_key_wif.as_deref()
            .ok_or("ITC_BRIDGE_RELEASE_WIF not set -- release is dry-run")?;
        let bridge_addr = self.bridge_change_addr.as_deref()
            .ok_or("ITC_BRIDGE_ADDRESS not set (needed for the change output)")?;
        let key = AnchorKey::from_wif(wif)?;

        // Funding: the WIF's legacy P2PKH address. Pull the largest confirmed
        // UTXO the node wallet sees for it (single-input v1 — the release wallet
        // is consolidated; multi-input selection is a follow-up).
        let funding_addr = key.p2pkh_address();
        let utxo = itc_anchor::rpc::fetch_best_utxo(&funding_addr)?
            .ok_or_else(|| format!("no spendable UTXO at bridge funding address {funding_addr}"))?;

        // Output scripts: recipient (burner's ITC bech32) + change (bridge bech32).
        let recipient_h160 = crate::oracle::hash160_from_bech32_address(l1_recipient)
            .map_err(|e| format!("recipient address {l1_recipient}: {e}"))?;
        let recipient_spk = p2wpkh_script_pubkey(&recipient_h160);
        let change_h160 = crate::oracle::hash160_from_bech32_address(bridge_addr)
            .map_err(|e| format!("bridge change address {bridge_addr}: {e}"))?;
        let change_spk = p2wpkh_script_pubkey(&change_h160);

        // Decode funding txid: display (reversed) hex → internal LE order.
        let txid_bytes = hex::decode(&utxo.txid_hex).map_err(|e| format!("utxo txid hex: {e}"))?;
        if txid_bytes.len() != 32 { return Err("utxo txid not 32 bytes".to_string()); }
        let mut utxo_txid = [0u8; 32];
        for (i, b) in txid_bytes.iter().rev().enumerate() { utxo_txid[i] = *b; }

        let raw_tx = build_release_tx(
            &key,
            utxo_txid,
            utxo.vout,
            utxo.value_sats,
            &recipient_spk,
            release_sats,
            &change_spk,
            MIN_FEE_SATS,
        )?;

        // Broadcast via L1 sendrawtransaction — returns the node's txid on accept,
        // Err on reject/unreachable (tx not in mempool → guard retries safely).
        broadcast_tx(itc_proto::SEED_ANCHOR, itc_proto::MAGIC_MAIN, &raw_tx)
    }
}

/// P2WPKH scriptPubKey for a 20-byte witness program: `OP_0 <push20> <hash160>`
/// = `0x00 0x14 <20 bytes>` (22 bytes). Paying to segwit needs no signing — only
/// the legacy input is signed — which is what keeps the release path off BIP143.
fn p2wpkh_script_pubkey(h160: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(22);
    s.push(0x00); // witness version 0
    s.push(0x14); // push 20 bytes
    s.extend_from_slice(h160);
    s
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

    fn pending_exit(db: &std::sync::Arc<nedb_engine::Db>, tx: &str) {
        db.put("l2_pending_exits", tx, json!({
            "l1_recipient": "itc1qtestrecipient0000000000000000000000",
            "release_sats": 95_000_000u64,
            "release_at_block": 10u64,
        }), vec![], None, None).unwrap();
    }

    /// THE drain guard: an exit already marked "released" must never be paid
    /// again — process_epoch drops it from pending and does not re-attempt.
    /// Without the guard, every 5s epoch re-released it until the wallet drained.
    #[test]
    fn released_exit_is_never_paid_twice() {
        std::env::remove_var("ITC_BRIDGE_RELEASE_WIF");
        let db = std::sync::Arc::new(nedb_engine::Db::in_memory());
        let scanner = ExitScanner::new(std::sync::Arc::clone(&db));
        let tx = "0xburn_released";
        pending_exit(&db, tx);
        db.put("l2_processed_exits", tx,
            json!({"status":"released","l1_txid":"deadbeef"}), vec![], None, None).unwrap();

        scanner.process_epoch(100); // well past release_at

        assert!(db.get("l2_pending_exits", tx).is_none(),
            "a released exit must be dropped from pending, never re-scanned");
        assert_eq!(db.get("l2_processed_exits", tx).unwrap().data["status"].as_str(),
            Some("released"), "processed record must stay released, not be overwritten");
    }

    /// In-flight ("releasing") exits — a crash mid-broadcast — must NOT auto-retry
    /// (double-pay risk). They stay put for manual review.
    #[test]
    fn releasing_exit_is_not_auto_retried() {
        std::env::remove_var("ITC_BRIDGE_RELEASE_WIF");
        let db = std::sync::Arc::new(nedb_engine::Db::in_memory());
        let scanner = ExitScanner::new(std::sync::Arc::clone(&db));
        let tx = "0xburn_inflight";
        pending_exit(&db, tx);
        db.put("l2_processed_exits", tx,
            json!({"status":"releasing","intent_block":11}), vec![], None, None).unwrap();

        scanner.process_epoch(100);

        assert_eq!(db.get("l2_processed_exits", tx).unwrap().data["status"].as_str(),
            Some("releasing"), "in-flight exit must remain 'releasing' (manual review)");
        assert!(db.get("l2_pending_exits", tx).is_some(),
            "in-flight exit must not be auto-cleared");
    }

    /// A pre-broadcast failure (dry-run / unconfigured release) must clear the
    /// intent so the exit stays retryable — never stranded as "releasing".
    #[test]
    fn dry_run_release_clears_intent_and_stays_retryable() {
        std::env::remove_var("ITC_BRIDGE_RELEASE_WIF");
        let db = std::sync::Arc::new(nedb_engine::Db::in_memory());
        let scanner = ExitScanner::new(std::sync::Arc::clone(&db));
        let tx = "0xburn_dryrun";
        pending_exit(&db, tx);

        scanner.process_epoch(100); // WIF unset → release_on_l1 errors pre-broadcast

        assert!(db.get("l2_processed_exits", tx).is_none(),
            "pre-broadcast failure must roll back the intent (not strand 'releasing')");
        assert!(db.get("l2_pending_exits", tx).is_some(),
            "a failed dry-run stays pending for a later retry");
    }
}
