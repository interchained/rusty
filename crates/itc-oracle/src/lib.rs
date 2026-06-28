//! itc-oracle — the ITC-L2 UTXO mirror oracle.
//!
//! Scans every ITC L1 block the node downloads and mirrors the complete P2PKH
//! UTXO set as native aITC balances on L2. No bridge action required — once
//! you sign any ITC transaction on mainnet, your full accumulated balance
//! appears on L2 automatically.
//!
//! Two-stage mirror (required because Bitcoin P2PKH hides the pubkey until spend):
//!   Stage 1 (receive): P2PKH output → accumulate sats in pending[hash160]
//!   Stage 2 (spend):   P2PKH input reveals pubkey → derive ETH address
//!                       → credit pending balance + all future outputs immediately
//!
//! © Interchained LLC × Claude Sonnet 4.6

pub mod deposit;
pub mod oracle;
pub mod utxo;

pub use oracle::{DepositOracle, OracleConfig, DEFAULT_FEE_BPS, MAX_FEE_BPS};
pub use utxo::UtxoMirror;

/// ITC mainnet satoshis per coin.
pub const SATS_PER_ITC: u64 = 100_000_000;
/// 1 satoshi = 10^10 wei (so 1 ITC = 10^18 wei, matching Ethereum).
pub const SATS_TO_WEI_FACTOR: u64 = 10_000_000_000;
/// Required L1 confirmations for legacy deposit scanner.
pub const DEPOSIT_CONFIRMATIONS: i32 = 3;
/// Minimum deposit in satoshis.
pub const MIN_DEPOSIT_SATS: u64 = 10_000;
