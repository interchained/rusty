//! itc-rpc — ITC-L2 Ethereum JSON-RPC server (MetaMask-compatible).
//!
//! Implements the subset of the Ethereum JSON-RPC API that wallets and tools
//! need to interact with the ITC-L2 EVM sidechain:
//!
//! | Method                        | What it does                              |
//! |-------------------------------|-------------------------------------------|
//! | eth_chainId                   | Returns 0x42ed (17101)                    |
//! | eth_blockNumber               | Current L2 epoch counter                 |
//! | net_version                   | Chain ID as decimal string                |
//! | eth_getBalance                | Account balance from NEDB                 |
//! | eth_getTransactionCount       | Account nonce from NEDB                   |
//! | eth_getCode                   | Contract bytecode from NEDB               |
//! | eth_call                      | Simulate tx, return output (no state)     |
//! | eth_estimateGas               | Simulate tx, return gas used              |
//! | eth_sendRawTransaction        | RLP-decode EIP-155 tx, execute, persist   |
//! | eth_getTransactionReceipt     | Lookup executed tx by hash from NEDB      |
//! | eth_getBlockByNumber          | Synthetic L2 block (epoch) info           |
//! | eth_gasPrice                  | Always 0 (no base fee in v1)              |
//! | web3_clientVersion            | "itc-node-rs/0.1.0"                       |
//!
//! Transport: HTTP, thread-per-connection (tiny_http). No WebSocket in slice 8.
//! Bind address: `ITC_RPC_ADDR` env var (default: 0.0.0.0:8545).
//!
//! © Interchained LLC × Claude Sonnet 4.6

pub mod handler;
pub mod server;
pub mod types;

pub use server::RpcServer;
