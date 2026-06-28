//! AnchorPayload — the 68-byte OP_RETURN data for ITC-L2 sovereignty proofs.

/// ITC-L2 anchor marker: "ITC2" in ASCII.
pub const ANCHOR_PREFIX: [u8; 4] = [0x49, 0x54, 0x43, 0x32];

/// Total OP_RETURN payload length (fixed).
pub const PAYLOAD_LEN: usize = 68;

/// A 68-byte ITC-L2 anchor payload.
///
/// Layout:
///   [0..4]   ANCHOR_PREFIX ("ITC2")
///   [4..36]  NEDB Merkle head (32 bytes, big-endian)
///   [36..40] L2 epoch counter (u32 little-endian)
///   [40..68] reserved (zeros for now)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorPayload(pub [u8; PAYLOAD_LEN]);

impl AnchorPayload {
    /// Build an anchor payload from the NEDB head hex string and a monotonic epoch counter.
    ///
    /// `nedb_head` is the 64-char hex string returned by `db.head()`.
    /// `l2_epoch`  is the L2 epoch counter (increments every `ANCHOR_INTERVAL` L2 blocks).
    pub fn build(nedb_head: &str, l2_epoch: u32) -> Result<AnchorPayload, String> {
        let head_bytes = hex::decode(nedb_head)
            .map_err(|e| format!("bad nedb_head hex: {e}"))?;
        if head_bytes.len() != 32 {
            return Err(format!("nedb_head must be 32 bytes (64 hex chars), got {}", head_bytes.len()));
        }

        let mut payload = [0u8; PAYLOAD_LEN];
        payload[0..4].copy_from_slice(&ANCHOR_PREFIX);
        payload[4..36].copy_from_slice(&head_bytes);
        payload[36..40].copy_from_slice(&l2_epoch.to_le_bytes());
        // [40..68] = zero (reserved)
        Ok(AnchorPayload(payload))
    }

    /// The raw 68-byte payload slice.
    pub fn as_bytes(&self) -> &[u8; PAYLOAD_LEN] {
        &self.0
    }

    /// Decode the NEDB head from a payload (bytes [4..36] as hex).
    pub fn nedb_head_hex(&self) -> String {
        hex::encode(&self.0[4..36])
    }

    /// Decode the L2 epoch from a payload.
    pub fn l2_epoch(&self) -> u32 {
        u32::from_le_bytes(self.0[36..40].try_into().unwrap_or([0u8; 4]))
    }

    /// Check if a byte slice begins with the ITC2 anchor prefix.
    pub fn has_prefix(data: &[u8]) -> bool {
        data.len() >= 4 && data[0..4] == ANCHOR_PREFIX
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let head = "a1b2c3d4e5f6".repeat(4) + "a1b2c3d4"; // 32 bytes = 64 hex chars
        let p = AnchorPayload::build(&head, 42).unwrap();
        assert_eq!(p.0[0..4], ANCHOR_PREFIX);
        assert_eq!(p.nedb_head_hex(), head);
        assert_eq!(p.l2_epoch(), 42);
        assert!(AnchorPayload::has_prefix(&p.0));
    }

    #[test]
    fn bad_head_rejected() {
        assert!(AnchorPayload::build("not-hex", 0).is_err());
        assert!(AnchorPayload::build("aabb", 0).is_err()); // too short
    }
}
