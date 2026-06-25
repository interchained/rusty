//! 32-byte hashes and Bitcoin's double-SHA256.

use sha2::{Digest, Sha256};

/// Single SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(data));
    out
}

/// Bitcoin double-SHA256 — SHA256(SHA256(data)) — in internal byte order.
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(first));
    out
}

/// The Bitcoin P2P message checksum: first 4 bytes of sha256d(payload).
pub fn checksum(data: &[u8]) -> [u8; 4] {
    let d = sha256d(data);
    [d[0], d[1], d[2], d[3]]
}

/// Format a 32-byte hash as display hex (reversed — big-endian, as explorers show).
pub fn to_display_hex(h: &[u8; 32]) -> String {
    h.iter().rev().map(|b| format!("{:02x}", b)).collect()
}

/// Format a 32-byte hash as internal-order hex (not reversed).
pub fn to_internal_hex(h: &[u8; 32]) -> String {
    h.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256d_known_answer() {
        // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        // sha256d("hello") = 9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50
        let h = sha256d(b"hello");
        assert_eq!(
            to_internal_hex(&h),
            "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"
        );
    }

    #[test]
    fn checksum_is_first4_of_sha256d() {
        let d = sha256d(b"verack-payload-unused");
        assert_eq!(checksum(b"verack-payload-unused"), [d[0], d[1], d[2], d[3]]);
    }

    #[test]
    fn empty_payload_checksum() {
        // sha256d("") = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
        assert_eq!(checksum(b""), [0x5d, 0xf6, 0xe0, 0xe2]);
    }
}
