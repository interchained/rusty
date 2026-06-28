//! itc-evm — ITC-L2 EVM execution engine.
//!
//! Wires `revm` to NEDB as the state backend. Every account balance, nonce,
//! storage slot, and code hash lives in NEDB with `caused_by: [tx_hash]` —
//! making EVM state transitions tamper-evident, time-travel queryable, and
//! causally traceable via NEDB's native AS OF + TRACE primitives.
//!
//! © Interchained LLC × Claude Sonnet 4.6

pub mod executor;
pub mod state;

pub use executor::ItcEvm;
pub use state::NedbState;

// ── Chain constants ───────────────────────────────────────────────────────────

/// ITC-L2 EVM chain ID (pending chainlist.org registration).
pub const CHAIN_ID: u64 = 17101;

/// ITC-L2 EVM spec — London hard fork.
pub const EVM_SPEC: revm::primitives::SpecId = revm::primitives::SpecId::LONDON;
