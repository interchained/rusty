//! JSON-RPC 2.0 wire types and Ethereum hex encoding helpers.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── JSON-RPC 2.0 envelope ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: Option<String>,
    pub method: String,
    pub params: Option<Value>,
    pub id: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct RpcResponse {
    pub jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
    pub id: Value,
}

#[derive(Debug, Serialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

impl RpcResponse {
    pub fn ok(id: Value, result: Value) -> Self {
        RpcResponse { jsonrpc: "2.0", result: Some(result), error: None, id }
    }
    pub fn err(id: Value, code: i64, message: impl Into<String>) -> Self {
        RpcResponse {
            jsonrpc: "2.0",
            result: None,
            error: Some(RpcError { code, message: message.into() }),
            id,
        }
    }
    pub fn not_found(id: Value) -> Self {
        Self::err(id, -32601, "Method not found")
    }
    pub fn invalid_params(id: Value, msg: impl Into<String>) -> Self {
        Self::err(id, -32602, msg)
    }
    pub fn internal(id: Value, msg: impl Into<String>) -> Self {
        Self::err(id, -32603, msg)
    }
}

/// A pending transaction submitted via eth_sendRawTransaction, queued for the sequencer.
#[derive(Clone, Debug)]
pub struct PendingTxRpc {
    pub raw: Vec<u8>,
    pub tx_hash: [u8; 32],
    pub from: [u8; 20],
}

// ── Ethereum hex helpers ──────────────────────────────────────────────────────

/// Encode a u64 as an Ethereum hex quantity string (e.g. "0x1a").
pub fn hex_qty(n: u64) -> String {
    format!("0x{:x}", n)
}

/// Encode a U256 as an Ethereum hex quantity string.
pub fn hex_u256(v: &revm::primitives::U256) -> String {
    format!("0x{}", hex::encode(v.to_be_bytes::<32>()).trim_start_matches('0'))
        .replace("0x", "0x")
        .to_string()
        // Handle the all-zero case
        .replace("0x", if v == &revm::primitives::U256::ZERO { "0x0" } else { "0x" })
}

/// Encode bytes as a 0x-prefixed hex data string.
pub fn hex_data(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

/// Parse a 0x-prefixed hex address string → 20 bytes.
pub fn parse_address(s: &str) -> Option<revm::primitives::Address> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    Some(revm::primitives::Address::from(arr))
}

/// Parse a 0x-prefixed hex quantity → u64.
pub fn parse_qty(s: &str) -> Option<u64> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}

/// Parse a 0x-prefixed hex quantity → U256.
pub fn parse_u256(s: &str) -> Option<revm::primitives::U256> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let padded = format!("{:0>64}", s);
    let bytes = hex::decode(&padded).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(revm::primitives::U256::from_be_bytes(arr))
}
