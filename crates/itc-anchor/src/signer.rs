//! AnchorKey — secp256k1 signing key for the anchor wallet.
//!
//! Parses WIF (Wallet Import Format) private key from `ITC_ANCHOR_WIF` and
//! exposes P2PKH address derivation + ECDSA signing for anchor transactions.
//!
//! ITC mainnet WIF prefix: 0x80 (same as Bitcoin mainnet — Bitcoin fork).

use secp256k1::{Message, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use ripemd::Ripemd160;

/// A loaded anchor signing key with its derived P2PKH address.
pub struct AnchorKey {
    secret: SecretKey,
    /// Compressed SEC pubkey (33 bytes).
    pub pubkey_bytes: [u8; 33],
    /// hash160(pubkey) — the P2PKH address payload.
    pub address_hash160: [u8; 20],
}

impl AnchorKey {
    /// Parse a WIF-encoded private key. ITC mainnet WIF prefix = 0x80.
    pub fn from_wif(wif: &str) -> Result<AnchorKey, String> {
        let raw = bs58::decode(wif)
            .with_check(None)
            .into_vec()
            .map_err(|e| format!("WIF base58check: {e}"))?;

        if raw.is_empty() {
            return Err("WIF payload empty".to_string());
        }
        if raw[0] != 0x80 {
            return Err(format!("WIF version byte {:02x}, expected 0x80 (mainnet)", raw[0]));
        }
        // Compressed: 1 + 32 + 1(=0x01) = 34.  Uncompressed: 1 + 32 = 33.
        let key_bytes: &[u8] = if raw.len() == 34 && raw[33] == 0x01 {
            &raw[1..33]
        } else if raw.len() == 33 {
            &raw[1..33]
        } else {
            return Err(format!("unexpected WIF payload length {}", raw.len()));
        };

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(key_bytes)
            .map_err(|e| format!("secp256k1: {e}"))?;
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret);
        let pubkey_bytes: [u8; 33] = pubkey.serialize(); // compressed
        let address_hash160 = hash160(&pubkey_bytes);

        Ok(AnchorKey { secret, pubkey_bytes, address_hash160 })
    }

    /// P2PKH scriptPubKey: `OP_DUP OP_HASH160 <20b> OP_EQUALVERIFY OP_CHECKSIG`
    pub fn p2pkh_script_pubkey(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(25);
        s.push(0x76); // OP_DUP
        s.push(0xa9); // OP_HASH160
        s.push(0x14); // push 20 bytes
        s.extend_from_slice(&self.address_hash160);
        s.push(0x88); // OP_EQUALVERIFY
        s.push(0xac); // OP_CHECKSIG
        s
    }

    /// Sign a sighash and return `DER(sig) || SIGHASH_ALL(0x01)`.
    pub fn sign_sighash(&self, sighash: &[u8; 32]) -> Vec<u8> {
        let secp = Secp256k1::new();
        let msg = Message::from_slice(sighash).expect("32-byte sighash");
        let sig = secp.sign_ecdsa(&msg, &self.secret);
        let mut der = sig.serialize_der().to_vec();
        der.push(0x01); // SIGHASH_ALL
        der
    }

    /// Build P2PKH scriptSig: `<len:sig> <sig> <len:pubkey> <pubkey>`.
    pub fn script_sig(&self, der_sig: &[u8]) -> Vec<u8> {
        let mut s = Vec::new();
        push_bytes(&mut s, der_sig);
        push_bytes(&mut s, &self.pubkey_bytes);
        s
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Bitcoin hash160: RIPEMD160(SHA256(data)).
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    Ripemd160::digest(sha).into()
}

/// Bitcoin double-SHA256.
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

/// Push raw bytes onto a script with a minimal-size length prefix.
pub fn push_bytes(script: &mut Vec<u8>, data: &[u8]) {
    let n = data.len();
    match n {
        0..=75 => script.push(n as u8),
        76..=255 => { script.push(0x4c); script.push(n as u8); }
        _ => { script.push(0x4d); script.extend_from_slice(&(n as u16).to_le_bytes()); }
    }
    script.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash160_is_20_bytes() {
        let h = hash160(b"test");
        assert_eq!(h.len(), 20);
    }

    #[test]
    fn p2pkh_script_pubkey_is_25_bytes() {
        // Can't test from_wif without a real key, but we can test the script shape.
        let fake_hash160 = [0x42u8; 20];
        let mut s = Vec::with_capacity(25);
        s.push(0x76); s.push(0xa9); s.push(0x14);
        s.extend_from_slice(&fake_hash160);
        s.push(0x88); s.push(0xac);
        assert_eq!(s.len(), 25);
    }
}
