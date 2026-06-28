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
//! [4..36]  NEDB Merkle head (32 bytes)   — content-addressed state root
//! [36..40] L2 epoch (u32 LE)             — monotonic epoch counter
//! [40..68] reserved / zero-padded        — future: L2 block hash once L2 block production lands
//! ```
//!
//! # Configuration (environment variables)
//!
//! - `ITC_ANCHOR_WIF`        — WIF-encoded secp256k1 private key of the funded anchor wallet.
//!                             If unset, the poster runs in dry-run mode (logs but does not broadcast).
//! - `ITC_ANCHOR_UTXO_TXID`  — Hex txid of the UTXO funding the anchor tx fee.
//! - `ITC_ANCHOR_UTXO_VOUT`  — Output index (u32) of the funding UTXO.
//! - `ITC_ANCHOR_UTXO_VALUE` — Value of the funding UTXO in satoshis.
//! - `ITC_ANCHOR_INTERVAL`   — Epochs between anchor posts (default: 100).
//!
//! © Interchained LLC × Claude Sonnet 4.6

pub mod payload;
pub mod poster;
pub mod signer;
pub mod tx;

pub use payload::{AnchorPayload, ANCHOR_PREFIX};
pub use poster::{AnchorConfig, AnchorPoster};
pub use signer::AnchorKey;
