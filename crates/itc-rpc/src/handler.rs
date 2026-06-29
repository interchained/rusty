//! RPC method dispatch — one function per eth_* method.

use std::sync::{Arc, Mutex};

use revm::primitives::{Address, Bytes, TransactTo, TxEnv, U256};
use serde_json::{json, Value};

use itc_evm::ItcEvm;
use nedb_engine::Db;

use crate::types::*;

/// Shared NEDB handle for receipt lookups.
pub type SharedDb = Arc<Db>;

/// Shared EVM executor state (Mutex for single-writer consistency).
pub type SharedEvm = Arc<Mutex<ItcEvm>>;

/// Shared mempool handle (used by eth_sendRawTransaction to submit txs to sequencer).
pub type SharedMempool = Arc<std::sync::Mutex<std::collections::VecDeque<crate::types::PendingTxRpc>>>;

/// Dispatch a JSON-RPC request to the appropriate handler.
pub fn dispatch(method: &str, params: &Value, id: Value, evm: &SharedEvm, epoch: u64, db: Option<&SharedDb>) -> RpcResponse {
    match method {
        // ── Identity ────────────────────────────────────────────────────────
        "eth_chainId" => {
            RpcResponse::ok(id, json!(hex_qty(itc_evm::CHAIN_ID)))
        }
        "net_version" => {
            RpcResponse::ok(id, json!(itc_evm::CHAIN_ID.to_string()))
        }
        "web3_clientVersion" => {
            RpcResponse::ok(id, json!("itc-node-rs/0.1.0"))
        }
        "eth_blockNumber" => {
            RpcResponse::ok(id, json!(hex_qty(epoch)))
        }
        "eth_gasPrice" => {
            RpcResponse::ok(id, json!("0x0")) // No base fee in ITC-L2 v1
        }

        // ── Account state ────────────────────────────────────────────────────
        "eth_getBalance" => {
            let addr = extract_addr(params, 0);
            match addr {
                None => RpcResponse::invalid_params(id, "missing/invalid address"),
                Some(a) => {
                    let evm = evm.lock().unwrap();
                    let balance = evm_balance(&evm, a);
                    RpcResponse::ok(id, json!(hex_u256_safe(balance)))
                }
            }
        }
        "eth_getTransactionCount" => {
            let addr = extract_addr(params, 0);
            match addr {
                None => RpcResponse::invalid_params(id, "missing/invalid address"),
                Some(a) => {
                    let evm = evm.lock().unwrap();
                    let nonce = evm_nonce(&evm, a);
                    RpcResponse::ok(id, json!(hex_qty(nonce)))
                }
            }
        }
        "eth_getCode" => {
            let addr = extract_addr(params, 0);
            match addr {
                None => RpcResponse::invalid_params(id, "missing/invalid address"),
                Some(a) => {
                    let evm = evm.lock().unwrap();
                    let code = evm_code(&evm, a);
                    RpcResponse::ok(id, json!(hex_data(&code)))
                }
            }
        }

        // ── Transaction simulation ────────────────────────────────────────────
        "eth_call" => {
            let tx = match extract_call_tx(params) {
                Ok(t) => t,
                Err(e) => return RpcResponse::invalid_params(id, e),
            };
            let mut evm = evm.lock().unwrap();
            match evm.simulate_tx(tx) {
                Ok(res) => {
                    let output = match &res.result {
                        revm::primitives::ExecutionResult::Success { output, .. } => {
                            output.data().to_vec()
                        }
                        revm::primitives::ExecutionResult::Revert { output, .. } => {
                            return RpcResponse::err(id, 3, format!(
                                "execution reverted: 0x{}", hex::encode(output)
                            ));
                        }
                        revm::primitives::ExecutionResult::Halt { reason, .. } => {
                            return RpcResponse::err(id, 3, format!("execution halted: {reason:?}"));
                        }
                    };
                    RpcResponse::ok(id, json!(hex_data(&output)))
                }
                Err(e) => RpcResponse::internal(id, e),
            }
        }
        "eth_estimateGas" => {
            let tx = match extract_call_tx(params) {
                Ok(t) => t,
                Err(e) => return RpcResponse::invalid_params(id, e),
            };
            let mut evm = evm.lock().unwrap();
            match evm.simulate_tx(tx) {
                Ok(res) => {
                    let gas = match res.result {
                        revm::primitives::ExecutionResult::Success { gas_used, .. } => gas_used,
                        _ => 21_000,
                    };
                    RpcResponse::ok(id, json!(hex_qty(gas)))
                }
                Err(e) => RpcResponse::internal(id, e),
            }
        }

        // ── Transaction submission ────────────────────────────────────────────
        "eth_sendRawTransaction" => {
            let raw_hex = match extract_str(params, 0) {
                Some(s) => s,
                None => return RpcResponse::invalid_params(id, "missing raw tx hex"),
            };
            let raw = match hex::decode(raw_hex.strip_prefix("0x").unwrap_or(raw_hex)) {
                Ok(b) => b,
                Err(_) => return RpcResponse::invalid_params(id, "invalid hex"),
            };
            let (tx_env, tx_hash) = match decode_raw_tx(&raw) {
                Ok(pair) => pair,
                Err(e) => return RpcResponse::invalid_params(id, format!("tx decode: {e}")),
            };
            let mut evm = evm.lock().unwrap();
            match evm.execute_tx(tx_env, tx_hash) {
                Ok(result) if result.is_success() => {
                    RpcResponse::ok(id, json!(format!("0x{}", hex::encode(tx_hash.as_slice()))))
                }
                Ok(result) => {
                    RpcResponse::err(id, 3, format!("execution failed: {:?}", result))
                }
                Err(e) => RpcResponse::internal(id, e),
            }
        }

        // ── Block info ───────────────────────────────────────────────────────
        "eth_getBlockByNumber" => {
            // Return a synthetic block object for the requested epoch.
            let block_num = extract_str(params, 0)
                .and_then(|s| if s == "latest" { Some(epoch) } else { parse_qty(s) })
                .unwrap_or(epoch);
            RpcResponse::ok(id, synthetic_block(block_num))
        }
        "eth_getBlockByHash" => {
            // Blocks are by epoch in ITC-L2 v1; return synthetic for any hash.
            RpcResponse::ok(id, synthetic_block(epoch))
        }

        // ── Transaction lookup ─────────────────────────────────────────────────
        "eth_getTransactionReceipt" => {
            let tx_hash_str = match extract_str(params, 0) {
                Some(s) => s.to_string(),
                None => return RpcResponse::invalid_params(id, "missing tx hash"),
            };
            // Normalize: strip 0x prefix for NEDB lookup key
            let key = if tx_hash_str.starts_with("0x") {
                tx_hash_str.clone()
            } else {
                format!("0x{tx_hash_str}")
            };
            if let Some(db) = db {
                if let Some(node) = db.get("l2_receipts", &key) {
                    return RpcResponse::ok(id, node.data.clone());
                }
            }
            RpcResponse::ok(id, Value::Null)
        }
        "eth_getTransactionByHash" => {
            RpcResponse::ok(id, Value::Null)
        }

        // ── Misc ─────────────────────────────────────────────────────────────
        "eth_syncing" => RpcResponse::ok(id, json!(false)),
        "eth_accounts" => RpcResponse::ok(id, json!([])),
        "net_listening" => RpcResponse::ok(id, json!(true)),
        "net_peerCount" => RpcResponse::ok(id, json!("0x1")),

        _ => RpcResponse::not_found(id),
    }
}

// ── EVM state accessors ───────────────────────────────────────────────────────

fn evm_balance(evm: &ItcEvm, addr: Address) -> U256 {
    use revm::db::DatabaseRef;
    evm.cache.db.basic(addr)
        .ok()
        .flatten()
        .map(|info| info.balance)
        .unwrap_or(U256::ZERO)
}

fn evm_nonce(evm: &ItcEvm, addr: Address) -> u64 {
    use revm::db::DatabaseRef;
    evm.cache.db.basic(addr)
        .ok()
        .flatten()
        .map(|info| info.nonce)
        .unwrap_or(0)
}

fn evm_code(evm: &ItcEvm, addr: Address) -> Vec<u8> {
    use revm::db::DatabaseRef;
    let info = evm.cache.db.basic(addr).ok().flatten();
    match info {
        Some(i) if i.code_hash != revm::primitives::KECCAK_EMPTY => {
            evm.cache.db.code_by_hash(i.code_hash)
                .ok()
                .map(|code| code.bytes().to_vec())
                .unwrap_or_default()
        }
        _ => vec![],
    }
}

// ── Parameter extraction helpers ──────────────────────────────────────────────

fn extract_addr(params: &Value, idx: usize) -> Option<Address> {
    let s = params.get(idx)?.as_str()?;
    parse_address(s)
}

fn extract_str(params: &Value, idx: usize) -> Option<&str> {
    params.get(idx)?.as_str()
}

fn extract_call_tx(params: &Value) -> Result<TxEnv, String> {
    let obj = params.get(0).ok_or("missing call object")?;
    let from = obj.get("from")
        .and_then(|v| v.as_str())
        .and_then(parse_address)
        .unwrap_or(Address::ZERO);
    let to = obj.get("to")
        .and_then(|v| v.as_str())
        .and_then(parse_address);
    let value = obj.get("value")
        .and_then(|v| v.as_str())
        .and_then(parse_u256)
        .unwrap_or(U256::ZERO);
    let data = obj.get("data")
        .and_then(|v| v.as_str())
        .map(|s| {
            let s = s.strip_prefix("0x").unwrap_or(s);
            Bytes::from(hex::decode(s).unwrap_or_default())
        })
        .unwrap_or_default();
    let gas_limit = obj.get("gas")
        .and_then(|v| v.as_str())
        .and_then(parse_qty)
        .unwrap_or(30_000_000);

    Ok(TxEnv {
        caller: from,
        transact_to: match to {
            Some(addr) => TransactTo::Call(addr),
            None => TransactTo::Create(revm::primitives::CreateScheme::Create),
        },
        value,
        data,
        gas_limit,
        gas_price: U256::ZERO,
        gas_priority_fee: None,
        nonce: None, // simulation — don't check nonce
        chain_id: Some(itc_evm::CHAIN_ID),
        access_list: vec![],
        ..Default::default()
    })
}

/// Decode an RLP-encoded EIP-155 (legacy) raw transaction.
/// Returns (TxEnv, tx_hash).
fn decode_raw_tx(raw: &[u8]) -> Result<(TxEnv, revm::primitives::B256), String> {
    use rlp::Rlp;
    let rlp = Rlp::new(raw);
    if !rlp.is_list() {
        return Err("not an RLP list".to_string());
    }
    let nonce: u64 = rlp.val_at(0).map_err(|e| format!("nonce: {e}"))?;
    let gas_price_bytes: Vec<u8> = rlp.val_at(1).map_err(|e| format!("gas_price: {e}"))?;
    let gas_limit: u64 = rlp.val_at(2).map_err(|e| format!("gas_limit: {e}"))?;
    let to_bytes: Vec<u8> = rlp.val_at(3).map_err(|e| format!("to: {e}"))?;
    let value_bytes: Vec<u8> = rlp.val_at(4).map_err(|e| format!("value: {e}"))?;
    let data_bytes: Vec<u8> = rlp.val_at(5).map_err(|e| format!("data: {e}"))?;

    let gas_price = bytes_to_u256(&gas_price_bytes);
    let value = bytes_to_u256(&value_bytes);

    let transact_to = if to_bytes.is_empty() {
        TransactTo::Create(revm::primitives::CreateScheme::Create)
    } else if to_bytes.len() == 20 {
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&to_bytes);
        TransactTo::Call(Address::from(arr))
    } else {
        return Err(format!("invalid 'to' length {}", to_bytes.len()));
    };

    // Recover sender via EIP-155 ecrecover.
    // keccak256(RLP(nonce, gas_price, gas_limit, to, value, data, chain_id, 0, 0))
    // → recover pubkey from (v, r, s) → keccak256(pubkey_uncompressed[1..])[12..]
    let caller = crate::ecrecover::recover_sender(raw, itc_evm::CHAIN_ID)
        .map(Address::from)
        .unwrap_or_else(|| {
            // Recovery failed (e.g. wrong chain_id, malformed sig) — reject the tx.
            Address::ZERO
        });

    // tx_hash = keccak256(raw_tx_bytes)
    use revm::primitives::keccak256;
    let tx_hash = keccak256(raw);

    Ok((TxEnv {
        caller,
        transact_to,
        value,
        data: Bytes::from(data_bytes),
        gas_limit,
        gas_price,
        gas_priority_fee: None,
        nonce: Some(nonce),
        chain_id: Some(itc_evm::CHAIN_ID),
        access_list: vec![],
        ..Default::default()
    }, tx_hash))
}

fn bytes_to_u256(b: &[u8]) -> U256 {
    if b.is_empty() { return U256::ZERO; }
    let mut arr = [0u8; 32];
    let start = 32 - b.len().min(32);
    arr[start..].copy_from_slice(&b[b.len().saturating_sub(32)..]);
    U256::from_be_bytes(arr)
}

fn synthetic_block(epoch: u64) -> Value {
    json!({
        "number": hex_qty(epoch),
        "hash": format!("0x{:064x}", epoch),
        "parentHash": format!("0x{:064x}", epoch.saturating_sub(1)),
        "nonce": "0x0000000000000000",
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "logsBloom": "0x0",
        "transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "stateRoot": "0x0",
        "miner": "0x0000000000000000000000000000000000000000",
        "difficulty": "0x0",
        "totalDifficulty": "0x0",
        "extraData": "0x",
        "size": "0x1",
        "gasLimit": hex_qty(30_000_000),
        "gasUsed": "0x0",
        "timestamp": hex_qty(epoch * 5), // 5s per L2 epoch
        "transactions": [],
        "uncles": [],
        "baseFeePerGas": "0x0",
        "chainId": hex_qty(itc_evm::CHAIN_ID),
    })
}

/// Safe U256 hex — handles zero correctly.
fn hex_u256_safe(v: U256) -> String {
    if v == U256::ZERO {
        return "0x0".to_string();
    }
    let hex = hex::encode(v.to_be_bytes::<32>());
    format!("0x{}", hex.trim_start_matches('0'))
}
