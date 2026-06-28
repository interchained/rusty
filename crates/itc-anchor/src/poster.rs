//! AnchorPoster — background thread that posts ITC-L2 sovereignty proofs to L1.
//!
//! Runs every `interval` L2 epochs. On each tick:
//!   1. Reads the current NEDB Merkle head (db.head())
//!   2. Builds the 68-byte OP_RETURN payload
//!   3. If a signing key + UTXO are configured: builds + signs + broadcasts the tx
//!   4. If no key: logs the payload and prints setup instructions (dry-run mode)
//!
//! Configuration comes entirely from environment variables — no secrets in code.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use nedb_engine::Db;

use crate::payload::AnchorPayload;
use crate::signer::AnchorKey;
use crate::tx::build_anchor_tx;

/// How often the anchor poster fires (in L2 epochs). Default: 100.
pub const DEFAULT_ANCHOR_INTERVAL: u64 = 100;

/// Configuration for the anchor poster, loaded from environment variables.
#[derive(Clone, Debug)]
pub struct AnchorConfig {
    /// ITC L1 anchor peer endpoint (host:port).
    pub anchor_endpoint: String,
    /// ITC P2P network magic.
    pub magic: [u8; 4],
    /// Epochs between anchor posts.
    pub interval: u64,
    /// WIF private key of the funded anchor wallet. None = dry-run mode.
    pub wif: Option<String>,
    /// Funding UTXO txid (hex, display order = reversed bytes).
    pub utxo_txid_hex: Option<String>,
    /// Funding UTXO output index.
    pub utxo_vout: Option<u32>,
    /// Funding UTXO value in satoshis.
    pub utxo_value_sats: Option<u64>,
}

impl AnchorConfig {
    /// Load from environment variables.
    pub fn from_env(anchor_endpoint: &str, magic: [u8; 4]) -> AnchorConfig {
        AnchorConfig {
            anchor_endpoint: anchor_endpoint.to_string(),
            magic,
            interval: std::env::var("ITC_ANCHOR_INTERVAL")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_ANCHOR_INTERVAL),
            wif: std::env::var("ITC_ANCHOR_WIF").ok(),
            utxo_txid_hex: std::env::var("ITC_ANCHOR_UTXO_TXID").ok(),
            utxo_vout: std::env::var("ITC_ANCHOR_UTXO_VOUT")
                .ok()
                .and_then(|s| s.parse().ok()),
            utxo_value_sats: std::env::var("ITC_ANCHOR_UTXO_VALUE")
                .ok()
                .and_then(|s| s.parse().ok()),
        }
    }

    /// Returns true if all fields needed for live (non-dry-run) posting are set.
    pub fn is_live(&self) -> bool {
        self.wif.is_some()
            && self.utxo_txid_hex.is_some()
            && self.utxo_vout.is_some()
            && self.utxo_value_sats.is_some()
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

    /// Spawn the poster as a background thread. Returns immediately.
    pub fn spawn(self) -> thread::JoinHandle<()> {
        thread::spawn(move || self.run())
    }

    fn run(self) {
        let mode = if self.config.is_live() { "LIVE" } else { "DRY-RUN" };
        println!(
            "[ANCHOR] poster started — mode={mode} interval={} epochs",
            self.config.interval
        );
        if !self.config.is_live() {
            println!("[ANCHOR] dry-run: set ITC_ANCHOR_WIF + ITC_ANCHOR_UTXO_TXID/VOUT/VALUE to broadcast real txs");
        }

        // Tick every 30 seconds. The epoch counter advances externally; for now
        // we fire on the wall-clock timer. Slice 8 (eth_* RPC + L2 block production)
        // will hook this to real L2 block events.
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
                // NEDB has no data yet — skip this tick
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
            println!("[ANCHOR] to broadcast: set ITC_ANCHOR_WIF + fund address + set UTXO env vars");
            return;
        }

        match self.build_and_broadcast(&payload) {
            Ok(txid) => println!("[ANCHOR] broadcast ok — l1_txid={txid} epoch={epoch}"),
            Err(e) => println!("[ANCHOR] broadcast error epoch={epoch}: {e}"),
        }
    }

    fn build_and_broadcast(&self, payload: &AnchorPayload) -> Result<String, String> {
        let wif = self.config.wif.as_ref().unwrap();
        let txid_hex = self.config.utxo_txid_hex.as_ref().unwrap();
        let vout = self.config.utxo_vout.unwrap();
        let value = self.config.utxo_value_sats.unwrap();

        // Parse key
        let key = AnchorKey::from_wif(wif)?;

        // Decode UTXO txid: display order is reversed, internal is LE
        let txid_bytes = hex::decode(txid_hex)
            .map_err(|e| format!("bad UTXO txid hex: {e}"))?;
        if txid_bytes.len() != 32 {
            return Err(format!("txid must be 32 bytes, got {}", txid_bytes.len()));
        }
        let mut utxo_txid = [0u8; 32];
        // Bitcoin display order is big-endian (reversed from internal storage)
        for (i, b) in txid_bytes.iter().rev().enumerate() {
            utxo_txid[i] = *b;
        }

        // Build + sign the tx
        let raw_tx = build_anchor_tx(&key, utxo_txid, vout, value, payload)?;

        // Broadcast via P2P tx message to the anchor peer
        broadcast_tx(&self.config.anchor_endpoint, self.config.magic, &raw_tx)?;

        // Compute and return the txid (SHA256D of the raw tx, reversed for display)
        let hash = crate::signer::sha256d(&raw_tx);
        let mut display = hash;
        display.reverse();
        Ok(hex::encode(display))
    }
}

/// Broadcast a raw transaction to the anchor peer via the P2P `tx` message.
fn broadcast_tx(endpoint: &str, magic: [u8; 4], raw_tx: &[u8]) -> Result<(), String> {
    use itc_proto::message::{encode_frame, NetworkMessage};
    use std::io::Write;
    use std::net::TcpStream;

    let mut stream = TcpStream::connect(endpoint)
        .map_err(|e| format!("connect to {endpoint}: {e}"))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| format!("set timeout: {e}"))?;

    // Send the tx message (raw bytes as Unknown command "tx")
    let frame = encode_frame(magic, &NetworkMessage::Unknown {
        command: "tx".to_string(),
        payload: raw_tx.to_vec(),
    });
    stream.write_all(&frame).map_err(|e| format!("write tx: {e}"))?;
    Ok(())
}
