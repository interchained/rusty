//! itc-anchor — ITC-L2 sovereignty proof publisher.
//!
//! Every N L2 epochs the anchor poster builds and broadcasts an ITC L1
//! transaction carrying an `OP_RETURN` output with the NEDB Merkle state root.
//! Any third party can read these outputs from ITC mainnet and independently
//! verify the ITC-L2 state has not been tampered with.
//!
//! # OP_RETURN payload layout (68 bytes total)
//!
//! ```text
//! [0..4]   "ITC2" (0x49 0x54 0x43 0x32) — marks this as an ITC-L2 anchor
//! [4..36]  NEDB Merkle head (32 bytes) — content-addressed state root
//! [36..40] L2 epoch (u32 LE) — monotonic epoch counter
//! [40..68] reserved / zero-padded — future: L2 block hash once L2 block production lands
//! ```
//!
//! # Configuration (environment variables)
//!
//! ## Required for live (non-dry-run) posting
//!
//! - `ITC_ANCHOR_WIF` — WIF-encoded secp256k1 private key of the funded anchor
//!   wallet.  If unset the poster runs in dry-run mode.
//! - `ITC_L1_RPC_URL` — JSON-RPC endpoint of the interchained node, e.g.
//!   `http://127.0.0.1:9332`.
//! - `ITC_L1_RPC_USER` — HTTP Basic Auth username for the JSON-RPC endpoint.
//! - `ITC_L1_RPC_PASS` — HTTP Basic Auth password for the JSON-RPC endpoint.
//!
//! ## Auto-selected at startup (no longer requires manual lookup)
//!
//! On startup (or on each posting cycle if the UTXO is spent), the poster calls
//! `listunspent 1 9999999 ["<anchor_address>"]` and selects the UTXO with the
//! largest value.  The three env vars that used to be required are now **optional
//! overrides**:
//!
//! - `ITC_ANCHOR_UTXO_TXID`  — override auto-selected UTXO txid (hex).
//! - `ITC_ANCHOR_UTXO_VOUT`  — override auto-selected UTXO vout index (u32).
//! - `ITC_ANCHOR_UTXO_VALUE` — override auto-selected UTXO value (satoshis).
//!
//! ## Other
//!
//! - `ITC_ANCHOR_INTERVAL` — epochs between anchor posts (default: 100).
//!
//! © Interchained LLC × Claude Sonnet 4.6

pub mod payload;
pub mod poster;
pub mod rpc;
pub mod signer;
pub mod tx;

pub use payload::{AnchorPayload, ANCHOR_PREFIX};
pub use poster::{AnchorConfig, AnchorPoster};
pub use rpc::{Utxo, fetch_best_utxo};
pub use signer::AnchorKey;
