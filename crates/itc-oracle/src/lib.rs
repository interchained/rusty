//! itc-oracle — the ITC-L2 deposit oracle.
//!
//! Scans every ITC L1 block the node downloads for transactions that send ITC to
//! the bridge lock address. When one is found it:
//!   1. Extracts the sender's compressed secp256k1 pubkey from the first P2PKH input.
//!   2. Derives the aITC (Ethereum) address: keccak256(uncomp[1..])[12:]
//!   3. Waits for DEPOSIT_CONFIRMATIONS L1 blocks.
//!   4. Mints native aITC to that address in the EVM state (NEDB evm_accounts).
//!      The NEDB record carries caused_by: [L1_txid] — full provenance.
//!
//! This is trustless in the deposit direction: the Bitcoin ECDSA signature already
//! in the downloaded block is the proof. No OP_RETURN, no external oracle, no faking.
//!
//! © Interchained LLC × Claude Sonnet 4.6

pub mod deposit;
pub mod oracle;

pub use oracle::{DepositOracle, OracleConfig};

/// ITC mainnet satoshis per coin (1 ITC = 1e8 satoshis).
pub const SATS_PER_ITC: u64 = 100_000_000;
/// Satoshis → aITC wei conversion (1 satoshi = 1e10 wei so 1 ITC = 1e18 wei).
pub const SATS_TO_WEI_FACTOR: u64 = 10_000_000_000;
/// Required L1 confirmations before minting aITC.
pub const DEPOSIT_CONFIRMATIONS: i32 = 3;
/// Minimum deposit in satoshis (reject dust).
pub const MIN_DEPOSIT_SATS: u64 = 10_000; // 0.0001 ITC
