//! rpc.rs — Thin JSON-RPC client for interchained (itc-anchor crate).
//!
//! Provides `fetch_best_utxo`, which calls `listunspent` on the interchained
//! node and returns the largest available UTXO for the given P2PKH address.
//!
//! Uses `ureq` (a synchronous, zero-async-runtime HTTP client) so this module
//! stays compatible with the existing thread-based architecture in `poster.rs`.
//!
//! # Environment variables consumed
//!
//! | Variable           | Purpose                                      |
//! |--------------------|----------------------------------------------|
//! | `ITC_L1_RPC_URL`   | JSON-RPC base URL, e.g. `http://127.0.0.1:9332` |
//! | `ITC_L1_RPC_USER`  | HTTP Basic Auth username                     |
//! | `ITC_L1_RPC_PASS`  | HTTP Basic Auth password                     |

use serde::Deserialize;

/// A single unspent transaction output returned by `listunspent`.
#[derive(Debug, Clone)]
pub struct Utxo {
    /// Transaction ID in display (reversed-bytes) hex order.
    pub txid_hex: String,
    /// Output index.
    pub vout: u32,
    /// Value in satoshis.
    pub value_sats: u64,
}

// ── Internal deserialization types ───────────────────────────────────────────

#[derive(Deserialize)]
struct RpcResponse {
    result: Option<serde_json::Value>,
    error:  Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct ListUnspentEntry {
    txid:   String,
    vout:   u32,
    /// Amount in ITC (floating-point BTC-style).
    amount: f64,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Call `listunspent 1 9999999 ["<address>"]` on the interchained JSON-RPC
/// and return the UTXO with the largest value.
///
/// Returns `Ok(None)` when the wallet has no confirmed UTXOs (dry-run continues).
/// Returns `Err(String)` on network / RPC / parse failure.
///
/// The RPC connection parameters are read from environment variables:
/// `ITC_L1_RPC_URL`, `ITC_L1_RPC_USER`, `ITC_L1_RPC_PASS`.
pub fn fetch_best_utxo(p2pkh_address: &str) -> Result<Option<Utxo>, String> {
    let url  = std::env::var("ITC_L1_RPC_URL")
        .map_err(|_| "ITC_L1_RPC_URL not set".to_string())?;
    let user = std::env::var("ITC_L1_RPC_USER")
        .map_err(|_| "ITC_L1_RPC_USER not set".to_string())?;
    let pass = std::env::var("ITC_L1_RPC_PASS")
        .map_err(|_| "ITC_L1_RPC_PASS not set".to_string())?;

    let body = serde_json::json!({
        "jsonrpc": "1.0",
        "id":      "itc-anchor",
        "method":  "listunspent",
        "params":  [1, 9_999_999, [p2pkh_address]],
    });

    let response_text = ureq::post(&url)
        .set("Content-Type", "application/json")
        .set(
            "Authorization",
            &format!(
                "Basic {}",
                base64_encode(format!("{user}:{pass}").as_bytes())
            ),
        )
        .send_string(&body.to_string())
        .map_err(|e| format!("RPC HTTP error: {e}"))?
        .into_string()
        .map_err(|e| format!("RPC response read error: {e}"))?;

    let rpc_resp: RpcResponse = serde_json::from_str(&response_text)
        .map_err(|e| format!("RPC JSON parse error: {e}\nraw: {response_text}"))?;

    if let Some(err) = rpc_resp.error {
        if !err.is_null() {
            return Err(format!("RPC returned error: {err}"));
        }
    }

    let result = rpc_resp
        .result
        .ok_or_else(|| "RPC response has no 'result' field".to_string())?;

    let entries: Vec<ListUnspentEntry> = serde_json::from_value(result)
        .map_err(|e| format!("listunspent result parse error: {e}"))?;

    if entries.is_empty() {
        return Ok(None);
    }

    // Pick the UTXO with the largest value so we leave room for the fee.
    let best = entries
        .into_iter()
        .max_by(|a, b| a.amount.partial_cmp(&b.amount).unwrap_or(std::cmp::Ordering::Equal))
        .unwrap(); // safe: entries is non-empty

    // Convert BTC-style float to satoshis (round to nearest integer).
    // interchained uses 8 decimal places, same as Bitcoin.
    let value_sats = (best.amount * 1e8).round() as u64;

    Ok(Some(Utxo {
        txid_hex:   best.txid,
        vout:       best.vout,
        value_sats,
    }))
}

/// Pay `sats` to `address` via the node wallet's `sendtoaddress` RPC.
///
/// The NODE wallet — which holds the bridge float at the bech32 bridge address —
/// selects UTXOs, SEGWIT-SIGNS, adds change back to itself, pays the network fee,
/// and broadcasts. So releasing the bridged funds needs no external key, no
/// separate funding pool, and no hand-rolled BIP143 signing. Returns the L1 txid.
///
/// The amount is built as an EXACT 8-decimal number from the satoshi integer
/// (no f64 rounding) so the recipient is paid to the satoshi.
pub fn send_to_address(address: &str, sats: u64) -> Result<String, String> {
    let url  = std::env::var("ITC_L1_RPC_URL")
        .map_err(|_| "ITC_L1_RPC_URL not set".to_string())?;
    let user = std::env::var("ITC_L1_RPC_USER").unwrap_or_default();
    let pass = std::env::var("ITC_L1_RPC_PASS").unwrap_or_default();

    // Exact ITC amount (8 decimals) from sats — parsed to a JSON number so no
    // floating-point artifact can under/over-pay.
    let amount_str = format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000);
    let amount: serde_json::Value = serde_json::from_str(&amount_str)
        .map_err(|e| format!("amount encode ({amount_str}): {e}"))?;

    let body = serde_json::json!({
        "jsonrpc": "1.0",
        "id":      "itc-bridge-release",
        "method":  "sendtoaddress",
        "params":  [address, amount],
    });

    let response_text = ureq::post(&url)
        .set("Content-Type", "application/json")
        .set(
            "Authorization",
            &format!("Basic {}", base64_encode(format!("{user}:{pass}").as_bytes())),
        )
        .send_string(&body.to_string())
        .map_err(|e| format!("sendtoaddress HTTP error: {e}"))?
        .into_string()
        .map_err(|e| format!("sendtoaddress response read error: {e}"))?;

    let rpc_resp: RpcResponse = serde_json::from_str(&response_text)
        .map_err(|e| format!("sendtoaddress JSON parse error: {e}\nraw: {response_text}"))?;

    if let Some(err) = rpc_resp.error {
        if !err.is_null() {
            return Err(format!("sendtoaddress node error: {err}"));
        }
    }
    rpc_resp
        .result
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .ok_or_else(|| "sendtoaddress: missing txid in response".to_string())
}

// ── Minimal base64 encoder (avoids pulling in a full base64 crate) ────────────
//
// Only used for the HTTP Basic Auth header.  Handles arbitrary byte slices.

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 { TABLE[((n >> 6) & 0x3f) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { TABLE[(n & 0x3f)        as usize] as char } else { '=' });
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_encode_known_vectors() {
        // RFC 4648 test vectors
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn sats_conversion_roundtrip() {
        // 1.23456789 ITC → 123456789 sats
        let btc_amount: f64 = 1.23456789;
        let sats = (btc_amount * 1e8).round() as u64;
        assert_eq!(sats, 123_456_789);
    }
}
