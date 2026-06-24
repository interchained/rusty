//! itc-proto — the ITC network protocol layer.
//!
//! Carries the ITC-specific wire constants and types that a vanilla rust-bitcoin
//! dependency cannot express. In a later slice this crate becomes a FORK of
//! rust-bitcoin (extending its `Network`, message enums, and consensus params);
//! for now it stands alone with the real ITC mainnet parameters lifted verbatim
//! from itcd's `chainparams.cpp` (`CMainParams`).

#![forbid(unsafe_code)]

/// ITC mainnet network magic — itcd `pchMessageStart = {1C, 7C, D0, 0D}`.
pub const MAGIC_MAIN: [u8; 4] = [0x1C, 0x7C, 0xD0, 0x0D];

/// Default P2P port — itcd `nDefaultPort`.
pub const DEFAULT_P2P_PORT: u16 = 17333;

/// Canonical seed / Proof-of-Prefix anchor endpoint (host:port).
pub const SEED_ANCHOR: &str = "seed.interchained.org:17101";

/// ElectrumX endpoint backing the light wallet (TLS).
pub const ELECTRUMX_ENDPOINT: &str = "seed.interchained.org:50002";

/// DNS seeds — itcd `vSeeds`.
pub const DNS_SEEDS: &[&str] = &["seed.interchained.org", "seed.interchained.com"];

/// Genesis block hash — itcd `consensus.hashGenesisBlock` (display / big-endian hex).
pub const GENESIS_HASH_HEX: &str =
    "00000000ed361749ae598d60cd78395eb526bc90f5e1198f0b045f95cecc80c8";

/// Protocol version advertised on the wire (itcd peers observed at 70016).
pub const PROTOCOL_VERSION: u32 = 70016;

/// Address-encoding parameters — itcd `base58Prefixes` / `bech32_hrp`.
pub mod address {
    pub const PUBKEY_ADDRESS: u8 = 0;
    pub const SCRIPT_ADDRESS: u8 = 5;
    pub const SECRET_KEY: u8 = 128;
    pub const EXT_PUBLIC_KEY: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
    pub const EXT_SECRET_KEY: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];
    pub const BECH32_HRP: &str = "itc";
}

/// The networks itcd defines. v1 targets `Main`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Main,
    Test,
    Regtest,
}

impl Network {
    /// Wire magic for this network (itcd `pchMessageStart`).
    pub const fn magic(self) -> [u8; 4] {
        match self {
            Network::Main => MAGIC_MAIN,
            Network::Test => [0x0b, 0x11, 0x09, 0x07],
            Network::Regtest => [0xfa, 0xbf, 0xb5, 0xda],
        }
    }
}

/// A chain tip the node ANCHORS to as truth, without re-deriving consensus.
///
/// `hash` is the block hash in internal (little-endian) byte order, as used on
/// the wire and in the NEDB store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorTip {
    pub height: u64,
    pub hash: [u8; 32],
}

impl AnchorTip {
    /// The genesis-only anchor (height 0). Used before the anchor responds.
    pub fn genesis() -> Self {
        AnchorTip { height: 0, hash: genesis_hash_internal() }
    }
}

/// Genesis hash in internal byte order (reverse of the display hex above).
pub fn genesis_hash_internal() -> [u8; 32] {
    let mut bytes = decode_hex32(GENESIS_HASH_HEX);
    bytes.reverse();
    bytes
}

/// ITC P2P message kinds the v1 relay peer must speak. The standard kinds come
/// from the (forthcoming) rust-bitcoin fork; `ProofOfPrefix` is the ITC-custom
/// seam that vanilla rust-bitcoin does not have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageKind {
    Version,
    Verack,
    Ping,
    Pong,
    GetHeaders,
    Headers,
    GetData,
    Block,
    Inv,
    Tx,
    MemPool,
    /// ITC-custom: the NEDB Proof-of-Prefix anchor handshake (cf. itcd
    /// net_processing.cpp seam + validation.cpp `TryWarmBoot`).
    ProofOfPrefix,
}

const fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

/// Decode a 64-char hex string into 32 bytes (display order). Helper for consts.
fn decode_hex32(s: &str) -> [u8; 32] {
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (hex_val(bytes[i * 2]) << 4) | hex_val(bytes[i * 2 + 1]);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_matches_itcd() {
        assert_eq!(MAGIC_MAIN, [0x1C, 0x7C, 0xD0, 0x0D]);
        assert_eq!(Network::Main.magic(), MAGIC_MAIN);
    }

    #[test]
    fn genesis_roundtrips_to_display_hex() {
        // internal order is the reverse of the display hex
        let internal = genesis_hash_internal();
        let mut display = internal;
        display.reverse();
        let hex: String = display.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, GENESIS_HASH_HEX);
    }

    #[test]
    fn default_port_is_17333() {
        assert_eq!(DEFAULT_P2P_PORT, 17333);
    }
}
