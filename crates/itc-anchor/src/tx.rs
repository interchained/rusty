//! Anchor transaction builder — P2PKH-funded OP_RETURN tx for ITC L1.
//!
//! Builds a minimal Bitcoin-compatible transaction:
//!   - 1 input:  the funded UTXO (P2PKH)
//!   - 2 outputs:
//!       [0] OP_RETURN with the 68-byte anchor payload (value = 0)
//!       [1] P2PKH change back to the anchor address
//!
//! The transaction is signed with SIGHASH_ALL. Broadcast via the P2P `tx` message.

use crate::payload::{AnchorPayload, PAYLOAD_LEN};
use crate::signer::{sha256d, AnchorKey};

/// Minimum fee in satoshis for a typical anchor tx (~250 bytes at 1 sat/byte).
pub const MIN_FEE_SATS: u64 = 1_000;

/// Build, sign, and return the raw anchor transaction bytes.
///
/// - `key`:         the anchor wallet key (funds the input, receives change)
/// - `utxo_txid`:   txid of the funding UTXO (internal byte order — little-endian as stored)
/// - `utxo_vout`:   output index of the funding UTXO
/// - `utxo_value`:  value of the funding UTXO in satoshis
/// - `payload`:     the 68-byte OP_RETURN anchor payload
///
/// Returns raw transaction bytes ready to broadcast via `NetworkMessage::Tx`.
pub fn build_anchor_tx(
    key: &AnchorKey,
    utxo_txid: [u8; 32],
    utxo_vout: u32,
    utxo_value: u64,
    payload: &AnchorPayload,
) -> Result<Vec<u8>, String> {
    if utxo_value < MIN_FEE_SATS {
        return Err(format!("UTXO value {utxo_value} sats is less than minimum fee {MIN_FEE_SATS}"));
    }
    let change_value = utxo_value - MIN_FEE_SATS;

    // ── Step 1: Build unsigned tx (for sighash computation) ─────────────────
    let op_return_script = build_op_return_script(payload.as_bytes());
    let change_script = key.p2pkh_script_pubkey();
    let unsigned = serialize_tx(
        &utxo_txid,
        utxo_vout,
        &[], // empty scriptSig for signing
        change_value,
        &op_return_script,
        &change_script,
        true, // append SIGHASH_ALL for sighash preimage
    );

    // ── Step 2: Compute sighash = SHA256D(unsigned_tx || SIGHASH_ALL_u32_le) ─
    let sighash: [u8; 32] = sha256d(&unsigned);

    // ── Step 3: Sign ────────────────────────────────────────────────────────
    let der_sig = key.sign_sighash(&sighash);
    let script_sig = key.script_sig(&der_sig);

    // ── Step 4: Build the final signed tx ───────────────────────────────────
    let signed = serialize_tx(
        &utxo_txid,
        utxo_vout,
        &script_sig,
        change_value,
        &op_return_script,
        &change_script,
        false, // no SIGHASH_ALL appended
    );

    Ok(signed)
}

// ── Serialization helpers ─────────────────────────────────────────────────────

/// Build the OP_RETURN script for a 68-byte payload:
/// `OP_RETURN OP_PUSH68 <68 bytes>`
fn build_op_return_script(payload: &[u8; PAYLOAD_LEN]) -> Vec<u8> {
    let mut s = Vec::with_capacity(2 + PAYLOAD_LEN);
    s.push(0x6a);             // OP_RETURN
    s.push(PAYLOAD_LEN as u8); // OP_PUSH68 (68 = 0x44)
    s.extend_from_slice(payload);
    s
}

/// Serialize the transaction. `append_sighash_type` adds `0x01000000` (SIGHASH_ALL)
/// at the end of the serialization for the sighash preimage calculation.
fn serialize_tx(
    utxo_txid: &[u8; 32],
    utxo_vout: u32,
    script_sig: &[u8],
    change_value: u64,
    op_return_script: &[u8],
    change_script: &[u8],
    append_sighash_type: bool,
) -> Vec<u8> {
    let mut tx = Vec::with_capacity(300);

    // version (4 bytes LE)
    tx.extend_from_slice(&1u32.to_le_bytes());

    // input count (varint)
    tx.push(0x01);

    // input: txid (32 bytes, as stored = internal/LE order)
    tx.extend_from_slice(utxo_txid);
    // input: vout (4 bytes LE)
    tx.extend_from_slice(&utxo_vout.to_le_bytes());
    // input: scriptSig (with compact-size prefix)
    push_var_bytes(&mut tx, script_sig);
    // input: sequence (0xffffffff)
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());

    // output count (varint) — 2 outputs
    tx.push(0x02);

    // output 0: OP_RETURN (value = 0)
    tx.extend_from_slice(&0u64.to_le_bytes());
    push_var_bytes(&mut tx, op_return_script);

    // output 1: change P2PKH
    tx.extend_from_slice(&change_value.to_le_bytes());
    push_var_bytes(&mut tx, change_script);

    // locktime (4 bytes LE)
    tx.extend_from_slice(&0u32.to_le_bytes());

    // sighash type for preimage (SIGHASH_ALL = 1 as u32 LE)
    if append_sighash_type {
        tx.extend_from_slice(&1u32.to_le_bytes());
    }

    tx
}

fn push_var_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    let n = data.len() as u64;
    match n {
        0..=0xfc => buf.push(n as u8),
        0xfd..=0xffff => { buf.push(0xfd); buf.extend_from_slice(&(n as u16).to_le_bytes()); }
        _ => { buf.push(0xfe); buf.extend_from_slice(&(n as u32).to_le_bytes()); }
    }
    buf.extend_from_slice(data);
}

// ── Bridge RELEASE transaction (aITC → ITC payout) ────────────────────────────

/// Dust threshold — a change output below this is folded into the fee instead of
/// creating a relay-rejected, effectively-unspendable output. 546 sats is
/// Bitcoin's standard P2PKH dust floor (conservative for P2WPKH change).
pub const DUST_SATS: u64 = 546;

/// Build + sign a bridge RELEASE transaction, LEGACY-P2PKH funded.
///
/// Design (Mark's spec — sidesteps segwit signing entirely):
///   • INPUT  — one legacy-P2PKH UTXO owned by `key` (the bridge WIF's legacy
///     address, key-funded). Signed with the legacy SIGHASH_ALL preimage this
///     `AnchorKey` already supports; NO BIP143/segwit signing on real money.
///   • OUT[0] — `release_sats` → `recipient_spk` (the burner's ITC address,
///     a P2WPKH scriptPubKey built by the caller from the bech32 address).
///   • OUT[1] — change (`utxo_value − release_sats − fee`) → `change_spk`
///     (the bech32 bridge address, per Mark), ONLY when change > DUST_SATS;
///     otherwise the dust is absorbed into the fee (no unspendable output).
///
/// Paying TO P2WPKH outputs needs no signing — only the input is signed, and it
/// is legacy. Returns raw tx bytes for `broadcast_tx` (a non-segwit tx, so its
/// txid is the node's returned id).
#[allow(clippy::too_many_arguments)]
pub fn build_release_tx(
    key: &AnchorKey,
    utxo_txid: [u8; 32],
    utxo_vout: u32,
    utxo_value: u64,
    recipient_spk: &[u8],
    release_sats: u64,
    change_spk: &[u8],
    fee_sats: u64,
) -> Result<Vec<u8>, String> {
    if release_sats == 0 {
        return Err("release_sats is zero".to_string());
    }
    let need = release_sats
        .checked_add(fee_sats)
        .ok_or("release_sats + fee overflow")?;
    if utxo_value < need {
        return Err(format!(
            "funding UTXO {utxo_value} sats < release {release_sats} + fee {fee_sats}"
        ));
    }
    let change_value = utxo_value - need;

    // Recipient always; change only when above dust (else folded into fee).
    let mut outputs: Vec<(u64, &[u8])> = Vec::with_capacity(2);
    outputs.push((release_sats, recipient_spk));
    if change_value > DUST_SATS {
        outputs.push((change_value, change_spk));
    }

    // Legacy SIGHASH_ALL: the input's signing subscript is the prevout's P2PKH
    // scriptPubKey (NOT empty) — the correct BIP legacy preimage.
    let subscript = key.p2pkh_script_pubkey();
    let unsigned = serialize_release(&utxo_txid, utxo_vout, &subscript, &outputs, true);
    let sighash = sha256d(&unsigned);
    let der_sig = key.sign_sighash(&sighash);
    let script_sig = key.script_sig(&der_sig);
    let signed = serialize_release(&utxo_txid, utxo_vout, &script_sig, &outputs, false);
    Ok(signed)
}

/// Serialize a 1-input, N-output legacy tx. `append_sighash_type` adds the
/// SIGHASH_ALL (0x01000000 LE) trailer for the sighash preimage.
fn serialize_release(
    utxo_txid: &[u8; 32],
    utxo_vout: u32,
    script_sig: &[u8],
    outputs: &[(u64, &[u8])],
    append_sighash_type: bool,
) -> Vec<u8> {
    let mut tx = Vec::with_capacity(256);
    tx.extend_from_slice(&1u32.to_le_bytes()); // version
    tx.push(0x01);                              // 1 input
    tx.extend_from_slice(utxo_txid);            // prevout txid (internal LE order)
    tx.extend_from_slice(&utxo_vout.to_le_bytes());
    push_var_bytes(&mut tx, script_sig);        // scriptSig (compact-size prefixed)
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
    tx.push(outputs.len() as u8);               // output count (always 1 or 2 → 1-byte varint)
    for (value, spk) in outputs {
        tx.extend_from_slice(&value.to_le_bytes());
        push_var_bytes(&mut tx, spk);
    }
    tx.extend_from_slice(&0u32.to_le_bytes());   // locktime
    if append_sighash_type {
        tx.extend_from_slice(&1u32.to_le_bytes()); // SIGHASH_ALL
    }
    tx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_return_script_length() {
        let payload = AnchorPayload::build(&"ab".repeat(32), 1).unwrap();
        let script = build_op_return_script(payload.as_bytes());
        // 1 (OP_RETURN) + 1 (push68) + 68 (payload) = 70 bytes
        assert_eq!(script.len(), 70);
        assert_eq!(script[0], 0x6a);
        assert_eq!(script[1], 68);
    }

    // A deterministic key for release-tx structure tests: WIF for privkey [1;32]
    // (compressed mainnet), so from_wif's 0x80 + trailing-0x01 checks pass.
    fn test_key() -> AnchorKey {
        let mut payload = vec![0x80u8];
        payload.extend_from_slice(&[1u8; 32]);
        payload.push(0x01);
        let wif = bs58::encode(payload).with_check().into_string();
        AnchorKey::from_wif(&wif).expect("valid test WIF")
    }

    fn p2wpkh(h: &[u8; 20]) -> Vec<u8> {
        let mut s = vec![0x00u8, 0x14];
        s.extend_from_slice(h);
        s
    }

    // Number of outputs in a 1-input legacy tx (scriptSig < 0xfd, always true
    // for P2PKH ~107 bytes): skip version+incount+prevout+scriptSig+sequence.
    fn output_count(tx: &[u8]) -> u8 {
        let mut p = 4 + 1 + 32 + 4;      // version, input count, txid, vout
        let ss_len = tx[p] as usize;     // scriptSig compact-size (1 byte here)
        p += 1 + ss_len + 4;             // scriptSig + sequence
        tx[p]
    }

    #[test]
    fn release_tx_change_above_dust_included_below_folded() {
        let key = test_key();
        let txid = [0x11u8; 32];
        let recipient = p2wpkh(&[0xaau8; 20]);
        let change = p2wpkh(&[0xbbu8; 20]);

        // change = 1_000_000 − 900_000 − 1_000 = 99_000 > DUST → 2 outputs.
        let with_change =
            build_release_tx(&key, txid, 0, 1_000_000, &recipient, 900_000, &change, 1_000).unwrap();
        assert_eq!(output_count(&with_change), 2, "change above dust must add a change output");

        // change = 901_500 − 900_000 − 1_000 = 500 ≤ DUST(546) → folded into fee → 1 output.
        let folded =
            build_release_tx(&key, txid, 0, 901_500, &recipient, 900_000, &change, 1_000).unwrap();
        assert_eq!(output_count(&folded), 1, "dust change must fold into the fee, not create an output");
    }

    #[test]
    fn release_tx_rejects_underfunded_utxo() {
        let key = test_key();
        let recipient = p2wpkh(&[0xaau8; 20]);
        let change = p2wpkh(&[0xbbu8; 20]);
        // utxo exactly == release, no room for fee → must error, never underflow.
        let r = build_release_tx(&key, [0u8; 32], 0, 900_000, &recipient, 900_000, &change, 1_000);
        assert!(r.is_err(), "utxo < release + fee must be rejected");
    }
}

// ── Broadcast via L1 JSON-RPC ─────────────────────────────────────────────────

/// Broadcast a signed raw transaction via the L1 `sendrawtransaction` JSON-RPC method.
///
/// `_anchor_endpoint` and `_magic` are kept for API compatibility with the P2P
/// broadcast path — the current implementation uses the simpler JSON-RPC route.
pub fn broadcast_tx(
    _anchor_endpoint: &str,
    _magic: [u8; 4],
    raw_tx: &[u8],
) -> Result<String, String> {
    let rpc_url  = std::env::var("ITC_L1_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:9332".to_string());
    let rpc_user = std::env::var("ITC_L1_RPC_USER").unwrap_or_default();
    let rpc_pass = std::env::var("ITC_L1_RPC_PASS").unwrap_or_default();

    let raw_hex = hex::encode(raw_tx);
    let body = serde_json::json!({
        "jsonrpc": "1.0",
        "id": "anchor",
        "method": "sendrawtransaction",
        "params": [raw_hex],
    })
    .to_string();

    let creds = base64_encode(format!("{rpc_user}:{rpc_pass}").as_bytes());
    let response = ureq::post(&rpc_url)
        .set("Authorization", &format!("Basic {creds}"))
        .set("Content-Type", "application/json")
        .send_string(&body)
        .map_err(|e| format!("broadcast_tx RPC error: {e}"))?;

    let response_text = response
        .into_string()
        .map_err(|e| format!("broadcast_tx response read error: {e}"))?;

    let json: serde_json::Value = serde_json::from_str(&response_text)
        .map_err(|e| format!("broadcast_tx JSON parse error: {e}\nraw: {response_text}"))?;

    if let Some(err) = json.get("error").filter(|v: &&serde_json::Value| !v.is_null()) {
        return Err(format!("broadcast_tx node error: {err}"));
    }

    json.get("result")
        .and_then(|v: &serde_json::Value| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "broadcast_tx: missing txid in response".to_string())
}

fn base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 { chunk[1] as usize } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as usize } else { 0 };
        out.push(CHARS[b0 >> 2] as char);
        out.push(CHARS[((b0 & 3) << 4) | (b1 >> 4)] as char);
        if chunk.len() > 1 { out.push(CHARS[((b1 & 0xf) << 2) | (b2 >> 6)] as char); } else { out.push('='); }
        if chunk.len() > 2 { out.push(CHARS[b2 & 0x3f] as char); } else { out.push('='); }
    }
    out
}
