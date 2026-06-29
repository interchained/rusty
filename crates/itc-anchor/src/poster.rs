//! AnchorPoster — background thread that posts ITC-L2 sovereignty proofs to L1.
//!
//! Runs every `interval` L2 epochs.  On each tick:
//! 1. Reads the current NEDB Merkle head (`db.head()`)
//! 2. Selects the best available UTXO via `listunspent` JSON-RPC (auto-discovery)
//! 3. Builds the 68-byte OP_RETURN payload
//! 4. If a signing key + UTXO are available: builds + signs + broadcasts the tx
//! 5. If no key / no UTXO: logs the payload and prints setup instructions (dry-run)
//!
//! Configuration comes entirely from environment variables — no secrets in code.
//! See the crate-level documentation in `lib.rs` for the full variable list.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use nedb_engine::Db;

use crate::payload::AnchorPayload;
use crate::rpc::{fetch_best_utxo, Utxo};
use crate::signer::AnchorKey;
use crate::tx::{broadcast_tx, build_anchor_tx};

/// How often the anchor poster fires (in L2 epochs).  Default: 100.
pub const DEFAULT_ANCHOR_INTERVAL: u64 = 100;

/// Configuration for the anchor poster, loaded from environment variables.
///
/// The three UTXO fields (`utxo_txid_hex`, `utxo_vout`, `utxo_value_sats`) are
/// now **optional overrides**.  When they are `None` the poster resolves the
/// UTXO automatically at posting time via `ITC_L1_RPC_URL` / `ITC_L1_RPC_USER`
/// / `ITC_L1_RPC_PASS` + `listunspent`.
#[derive(Clone, Debug)]
pub struct AnchorConfig {
    /// ITC L1 anchor peer endpoint (`host:port`) for P2P broadcast.
    pub anchor_endpoint: String,
    /// ITC P2P network magic.
    pub magic: [u8; 4],
    /// Epochs between anchor posts.
    pub interval: u64,
    /// WIF private key of the funded anchor wallet.  `None` = dry-run mode.
    pub wif: Option<String>,

    // ── Optional static UTXO overrides ──────────────────────────────────────
    // When set, these bypass the auto-discovery RPC call.
    // Useful for air-gapped setups or testnet where JSON-RPC is unavailable.

    /// Override: Funding UTXO txid (hex, display / reversed-bytes order).
    pub utxo_txid_hex: Option<String>,
    /// Override: Funding UTXO output index.
    pub utxo_vout: Option<u32>,
    /// Override: Funding UTXO value in satoshis.
    pub utxo_value_sats: Option<u64>,
}

impl AnchorConfig {
    /// Load from environment variables.
    ///
    /// UTXO resolution priority:
    ///   1. `ITC_ANCHOR_UTXO_TXID` + `ITC_ANCHOR_UTXO_VOUT` + `ITC_ANCHOR_UTXO_VALUE`
    ///      (all three must be set; treated as a static override).
    ///   2. Auto-discovery via `listunspent` JSON-RPC at posting time
    ///      (requires `ITC_L1_RPC_URL`, `ITC_L1_RPC_USER`, `ITC_L1_RPC_PASS`).
    pub fn from_env(anchor_endpoint: &str, magic: [u8; 4]) -> AnchorConfig {
        // Read optional static overrides (all three must be present to use them).
        let utxo_txid_hex   = std::env::var("ITC_ANCHOR_UTXO_TXID").ok();
        let utxo_vout       = std::env::var("ITC_ANCHOR_UTXO_VOUT")
            .ok()
            .and_then(|s| s.parse::<u32>().ok());
        let utxo_value_sats = std::env::var("ITC_ANCHOR_UTXO_VALUE")
            .ok()
            .and_then(|s| s.parse::<u64>().ok());

        // Warn if the operator set some but not all three override vars.
        let override_count = [
            utxo_txid_hex.is_some(),
            utxo_vout.is_some(),
            utxo_value_sats.is_some(),
        ]
        .iter()
        .filter(|&&b| b)
        .count();
        if override_count > 0 && override_count < 3 {
            eprintln!(
                "[ANCHOR] WARNING: partial UTXO override detected ({}/3 vars set). \
                 Set all three of ITC_ANCHOR_UTXO_TXID / ITC_ANCHOR_UTXO_VOUT / \
                 ITC_ANCHOR_UTXO_VALUE, or none (auto-discovery will be used).",
                override_count
            );
        }

        AnchorConfig {
            anchor_endpoint: anchor_endpoint.to_string(),
            magic,
            interval: std::env::var("ITC_ANCHOR_INTERVAL")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_ANCHOR_INTERVAL),
            wif: std::env::var("ITC_ANCHOR_WIF").ok(),
            utxo_txid_hex,
            utxo_vout,
            utxo_value_sats,
        }
    }

    /// Returns `true` if the WIF key is set (a prerequisite for live posting).
    pub fn has_key(&self) -> bool {
        self.wif.is_some()
    }

    /// Returns `true` if all three static UTXO override vars are present.
    pub fn has_static_utxo(&self) -> bool {
        self.utxo_txid_hex.is_some()
            && self.utxo_vout.is_some()
            && self.utxo_value_sats.is_some()
    }

    /// Returns `true` if the RPC variables needed for auto-discovery are set.
    pub fn has_rpc_config(&self) -> bool {
        std::env::var("ITC_L1_RPC_URL").is_ok()
            && std::env::var("ITC_L1_RPC_USER").is_ok()
            && std::env::var("ITC_L1_RPC_PASS").is_ok()
    }

    /// Returns `true` if posting is possible (key + either static UTXO or RPC).
    pub fn is_live(&self) -> bool {
        self.has_key() && (self.has_static_utxo() || self.has_rpc_config())
    }
}

/// The anchor poster.
pub struct AnchorPoster {
    config: AnchorConfig,
    db: Arc<Db>,
}

impl AnchorPoster {
    pub fn new(config: AnchorConfig, db: Arc<Db>) -> Self {
        AnchorPoster { config, db }
    }

    /// Spawn the poster as a background thread.  Returns immediately.
    pub fn spawn(self) -> thread::JoinHandle<()> {
        thread::spawn(move || self.run())
    }

    fn run(self) {
        let mode = if self.config.is_live() { "LIVE" } else { "DRY-RUN" };
        println!(
            "[ANCHOR] poster started — mode={mode} interval={} epochs",
            self.config.interval
        );

        if !self.config.has_key() {
            println!("[ANCHOR] dry-run: set ITC_ANCHOR_WIF to enable broadcasting");
        } else if !self.config.is_live() {
            println!(
                "[ANCHOR] dry-run: set ITC_L1_RPC_URL + ITC_L1_RPC_USER + ITC_L1_RPC_PASS \
                 for auto UTXO discovery, or set ITC_ANCHOR_UTXO_TXID / VOUT / VALUE manually"
            );
        }

        // Tick every 30 seconds.  The epoch counter advances externally; for now
        // we fire on the wall-clock timer.  Slice 8 (eth_* RPC + L2 block
        // production) will hook this to real L2 block events.
        let tick = Duration::from_secs(30);
        let mut epoch: u32 = 0;

        loop {
            thread::sleep(tick);
            epoch += 1;

            if (epoch as u64) % self.config.interval != 0 {
                continue;
            }

            let head = self.db.head();
            if head.chars().all(|c| c == '0') {
                // NEDB has no data yet — skip this tick.
                continue;
            }

            match AnchorPayload::build(&head, epoch) {
                Ok(payload) => self.post(payload, epoch),
                Err(e) => println!("[ANCHOR] payload build error at epoch {epoch}: {e}"),
            }
        }
    }

    fn post(&self, payload: AnchorPayload, epoch: u32) {
        println!(
            "[ANCHOR] epoch={epoch} nedb_head={} — building anchor tx",
            payload.nedb_head_hex()
        );

        if !self.config.is_live() {
            // Dry-run: log what we would post.
            println!(
                "[ANCHOR] DRY-RUN payload (68 bytes): {}",
                hex::encode(payload.as_bytes())
            );
            if !self.config.has_key() {
                println!("[ANCHOR] to broadcast: set ITC_ANCHOR_WIF to a funded WIF key");
            } else {
                println!(
                    "[ANCHOR] to broadcast: set ITC_L1_RPC_URL / ITC_L1_RPC_USER / \
                     ITC_L1_RPC_PASS so the poster can auto-select a UTXO"
                );
            }
            return;
        }

        match self.build_and_broadcast(&payload) {
            Ok(txid) => println!("[ANCHOR] epoch={epoch} broadcast txid={txid}"),
            Err(e) => eprintln!("[ANCHOR] ERROR at epoch {epoch}: {e}"),
        }
    }

    /// Resolve the UTXO to use for this posting cycle.
    ///
    /// Priority:
    ///   1. Static override env vars (all three set) — used as-is.
    ///   2. Auto-discovery via `listunspent` JSON-RPC — selects the largest UTXO
    ///      belonging to the anchor key's P2PKH address.
    fn resolve_utxo(&self, key: &AnchorKey) -> Result<Utxo, String> {
        // ── Priority 1: static override ──────────────────────────────────────
        if self.config.has_static_utxo() {
            let utxo = Utxo {
                txid_hex:   self.config.utxo_txid_hex.clone().unwrap(),
                vout:       self.config.utxo_vout.unwrap(),
                value_sats: self.config.utxo_value_sats.unwrap(),
            };
            println!(
                "[ANCHOR] using static UTXO override: {}:{} ({} sats)",
                utxo.txid_hex, utxo.vout, utxo.value_sats
            );
            return Ok(utxo);
        }

        // ── Priority 2: auto-discovery via listunspent ────────────────────────
        //
        // Derive the P2PKH address for the anchor key so we can pass it to
        // `listunspent`.  ITC uses the same P2PKH address format as Bitcoin
        // (version byte 0x00), encoded in Base58Check.  The address is built
        // from: Base58Check(0x00 || hash160(pubkey)).
        let p2pkh_address = derive_p2pkh_address(&key.address_hash160);

        println!(
            "[ANCHOR] auto-selecting UTXO for anchor address {} via listunspent …",
            p2pkh_address
        );

        match fetch_best_utxo(&p2pkh_address)? {
            Some(utxo) => {
                println!(
                    "[ANCHOR] selected UTXO {}:{} ({} sats)",
                    utxo.txid_hex, utxo.vout, utxo.value_sats
                );
                Ok(utxo)
            }
            None => Err(format!(
                "no confirmed UTXOs found for anchor address {p2pkh_address}. \
                 Fund the address or set ITC_ANCHOR_UTXO_TXID / VOUT / VALUE manually."
            )),
        }
    }

    fn build_and_broadcast(&self, payload: &AnchorPayload) -> Result<String, String> {
        let wif = self.config.wif.as_ref().unwrap();
        let key = AnchorKey::from_wif(wif)?;

        // Resolve UTXO (auto-discovery or static override).
        let utxo = self.resolve_utxo(&key)?;

        // Decode UTXO txid: display order is reversed bytes (little-endian internal).
        let txid_bytes = hex::decode(&utxo.txid_hex)
            .map_err(|e| format!("invalid UTXO txid hex: {e}"))?;
        if txid_bytes.len() != 32 {
            return Err(format!(
                "UTXO txid must be 32 bytes, got {}",
                txid_bytes.len()
            ));
        }
        let mut utxo_txid = [0u8; 32];
        // Bitcoin display order is big-endian; internal storage is little-endian.
        for (i, b) in txid_bytes.iter().enumerate() {
            utxo_txid[31 - i] = *b;
        }

        // Build + sign the tx.
        let raw_tx = build_anchor_tx(&key, utxo_txid, utxo.vout, utxo.value_sats, payload)?;

        // Broadcast via P2P tx message to the anchor peer.
        broadcast_tx(&self.config.anchor_endpoint, self.config.magic, &raw_tx)?;

        // Compute and return the txid (SHA256D of the raw tx, reversed for display).
        let hash = crate::signer::sha256d(&raw_tx);
        let mut display = hash;
        display.reverse();
        Ok(hex::encode(display))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Derive a Base58Check P2PKH address from a 20-byte hash160.
///
/// Format: Base58Check( 0x00 || hash160 )
/// This matches Bitcoin mainnet P2PKH, which ITC uses (same version byte).
fn derive_p2pkh_address(hash160: &[u8; 20]) -> String {
    let mut payload = Vec::with_capacity(21);
    payload.push(0x00u8); // version byte: mainnet P2PKH
    payload.extend_from_slice(hash160);
    bs58::encode(payload).with_check().into_string()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_p2pkh_address_length() {
        // A valid P2PKH address is 25–34 chars in Base58Check.
        let hash160 = [0x89u8; 20];
        let addr = derive_p2pkh_address(&hash160);
        assert!(
            addr.len() >= 25 && addr.len() <= 35,
            "unexpected address length: {} ({})",
            addr.len(),
            addr
        );
        // ITC/Bitcoin mainnet P2PKH starts with '1'.
        assert!(
            addr.starts_with('1'),
            "P2PKH address should start with '1', got: {addr}"
        );
    }

    #[test]
    fn anchor_config_has_static_utxo_requires_all_three() {
        // Simulate partial env — this can't easily be tested with real env vars
        // in a parallel test runner, so we test the struct directly.
        let cfg_none = AnchorConfig {
            anchor_endpoint: "127.0.0.1:9333".to_string(),
            magic: [0u8; 4],
            interval: 100,
            wif: None,
            utxo_txid_hex: None,
            utxo_vout: None,
            utxo_value_sats: None,
        };
        assert!(!cfg_none.has_static_utxo());

        let cfg_partial = AnchorConfig {
            utxo_txid_hex: Some("abc".to_string()),
            utxo_vout: Some(0),
            utxo_value_sats: None, // missing
            ..cfg_none.clone()
        };
        assert!(!cfg_partial.has_static_utxo());

        let cfg_full = AnchorConfig {
            utxo_txid_hex: Some("a".repeat(64)),
            utxo_vout: Some(0),
            utxo_value_sats: Some(100_000),
            ..cfg_none
        };
        assert!(cfg_full.has_static_utxo());
    }
}
