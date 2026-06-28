//! Bitcoin script analysis — P2PKH scriptSig pubkey extraction + address matching.
//!
//! The oracle only cares about two things:
//!   1. Is this output a P2PKH to the bridge lock address?
//!   2. What is the sender's compressed secp256k1 pubkey (from the spending input)?

use crate::signer_util::hash160;

// ── Script templates ──────────────────────────────────────────────────────────

/// Check if a scriptPubKey is P2PKH paying to `hash160`.
/// P2PKH template: OP_DUP OP_HASH160 OP_PUSH20 <hash160> OP_EQUALVERIFY OP_CHECKSIG
pub fn is_p2pkh_to(script: &[u8], hash160_target: &[u8; 20]) -> bool {
    script.len() == 25
        && script[0] == 0x76 // OP_DUP
        && script[1] == 0xa9 // OP_HASH160
        && script[2] == 0x14 // push 20 bytes
        && &script[3..23] == hash160_target
        && script[23] == 0x88 // OP_EQUALVERIFY
        && script[24] == 0xac // OP_CHECKSIG
}

/// Extract the hash160 from a P2PKH scriptPubKey, if it is one.
pub fn p2pkh_hash160(script: &[u8]) -> Option<[u8; 20]> {
    if script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xac
    {
        let mut h = [0u8; 20];
        h.copy_from_slice(&script[3..23]);
        Some(h)
    } else {
        None
    }
}

/// Extract the compressed secp256k1 pubkey from a P2PKH scriptSig.
///
/// P2PKH scriptSig format: `<push_len> <DER_sig+hashtype> <push_len> <pubkey>`
///
/// We skip the signature and read the pubkey. Compressed pubkeys are 33 bytes
/// (prefix 0x02 or 0x03). Uncompressed (65 bytes, prefix 0x04) are also returned
/// so the caller can handle them (or reject them — v1 only supports compressed).
pub fn p2pkh_scriptsig_pubkey(script_sig: &[u8]) -> Option<Vec<u8>> {
    if script_sig.is_empty() {
        return None; // coinbase or empty
    }
    let mut pos = 0;

    // Skip the signature push: read the push opcode to get sig length.
    let sig_len = read_push_len(script_sig, &mut pos)?;
    pos += sig_len; // skip over the signature bytes

    // Now read the pubkey push.
    let pubkey_len = read_push_len(script_sig, &mut pos)?;
    if pos + pubkey_len > script_sig.len() {
        return None;
    }
    let pubkey = &script_sig[pos..pos + pubkey_len];

    // Accept compressed (33 bytes, 0x02/0x03) or uncompressed (65 bytes, 0x04).
    if (pubkey_len == 33 && (pubkey[0] == 0x02 || pubkey[0] == 0x03))
        || (pubkey_len == 65 && pubkey[0] == 0x04)
    {
        Some(pubkey.to_vec())
    } else {
        None
    }
}

/// Derive the Ethereum address from a secp256k1 public key.
///
/// For compressed (33 bytes): uncompress first.
/// For uncompressed (65 bytes): use directly.
/// ETH address = last 20 bytes of keccak256(pubkey[1..]).
pub fn pubkey_to_eth_address(pubkey: &[u8]) -> Option<[u8; 20]> {
    let uncompressed: Vec<u8> = match pubkey.len() {
        33 => uncompress_pubkey(pubkey)?,
        65 if pubkey[0] == 0x04 => pubkey.to_vec(),
        _ => return None,
    };
    // ETH address = keccak256(uncompressed[1..])[12..]
    let hash = keccak256(&uncompressed[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Some(addr)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Read a push-data length from a Bitcoin script at `pos`, advancing `pos`.
fn read_push_len(script: &[u8], pos: &mut usize) -> Option<usize> {
    if *pos >= script.len() {
        return None;
    }
    let opcode = script[*pos];
    *pos += 1;
    match opcode {
        1..=75 => Some(opcode as usize),
        76 => {
            // OP_PUSHDATA1
            if *pos >= script.len() { return None; }
            let n = script[*pos] as usize;
            *pos += 1;
            Some(n)
        }
        77 => {
            // OP_PUSHDATA2
            if *pos + 2 > script.len() { return None; }
            let n = u16::from_le_bytes([script[*pos], script[*pos + 1]]) as usize;
            *pos += 2;
            Some(n)
        }
        _ => None, // OP_0 or unknown opcode
    }
}

/// Uncompress a secp256k1 pubkey (33 bytes → 65 bytes) using the curve equation.
/// y² = x³ + 7 (mod p)
fn uncompress_pubkey(compressed: &[u8]) -> Option<Vec<u8>> {
    use secp256k1::{PublicKey, Secp256k1};
    let secp = Secp256k1::new();
    let pk = PublicKey::from_slice(compressed).ok()?;
    let uncompressed = pk.serialize_uncompressed();
    Some(uncompressed.to_vec())
}

/// Keccak-256 hash (used for ETH address derivation).
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    Keccak256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p2pkh_detection() {
        let target = [0x42u8; 20];
        let mut script = vec![0x76u8, 0xa9, 0x14];
        script.extend_from_slice(&target);
        script.extend_from_slice(&[0x88u8, 0xac]);
        assert!(is_p2pkh_to(&script, &target));
        assert!(!is_p2pkh_to(&script, &[0x00u8; 20]));
    }

    #[test]
    fn scriptsig_pubkey_extraction() {
        // Build a fake P2PKH scriptSig: <push 72 bytes> <sig> <push 33 bytes> <pubkey>
        let fake_sig = vec![0xdeu8; 71]; // 71-byte DER sig + hashtype
        let fake_pubkey = {
            let mut p = vec![0x02u8]; // compressed
            p.extend_from_slice(&[0xabu8; 32]);
            p
        };
        let mut script_sig = Vec::new();
        script_sig.push(fake_sig.len() as u8 + 1); // push len = 72 (71 + hashtype byte)
        script_sig.extend_from_slice(&fake_sig);
        script_sig.push(0x01u8); // hashtype
        script_sig.push(fake_pubkey.len() as u8); // push 33
        script_sig.extend_from_slice(&fake_pubkey);

        let extracted = p2pkh_scriptsig_pubkey(&script_sig);
        assert!(extracted.is_some());
        assert_eq!(extracted.unwrap(), fake_pubkey);
    }
}
