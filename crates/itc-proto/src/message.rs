//! ITC P2P messages — the wire envelope and the message types the relay peer
//! speaks: standard Bitcoin commands plus the ITC-custom `ProofOfPrefix` ("ppfx")
//! seam that vanilla rust-bitcoin does not have.
//!
//! Frame layout: magic[4] | command[12, null-padded] | length[4 LE] |
//! checksum[4] (first 4 of sha256d(payload)) | payload[length].

use crate::block::{Block, BlockHeader};
use crate::consensus::{self, Error, Reader, Result};
use crate::hashes;

pub const COMMAND_LEN: usize = 12;
pub const HEADER_LEN: usize = 24;
/// Max payload we will accept (32 MiB) — a DoS guard on the length field.
pub const MAX_PAYLOAD: usize = 32 * 1024 * 1024;

pub const INV_TX: u32 = 1;
pub const INV_BLOCK: u32 = 2;

/// Inventory vector (type + hash).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inventory {
    pub inv_type: u32,
    pub hash: [u8; 32],
}

/// `version` message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionMessage {
    pub version: i32,
    pub services: u64,
    pub timestamp: i64,
    pub recv_services: u64,
    pub recv_ip: [u8; 16],
    pub recv_port: u16,
    pub from_services: u64,
    pub from_ip: [u8; 16],
    pub from_port: u16,
    pub nonce: u64,
    pub user_agent: String,
    pub start_height: i32,
    pub relay: bool,
}

/// `getheaders` message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetHeadersMessage {
    pub version: u32,
    pub locator: Vec<[u8; 32]>,
    pub hash_stop: [u8; 32],
}

/// ITC-custom Proof-of-Prefix seam payload: a node's anchored tip + window base.
/// Mirrors itcd's warm-boot seam (validation.cpp `TryWarmBoot`): a peer can
/// announce the tip it anchors to and the base of its verified window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofOfPrefix {
    pub tip_height: i32,
    pub tip_hash: [u8; 32],
    pub base_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkMessage {
    Version(VersionMessage),
    Verack,
    Ping(u64),
    Pong(u64),
    SendHeaders,
    GetHeaders(GetHeadersMessage),
    Headers(Vec<BlockHeader>),
    Inv(Vec<Inventory>),
    GetData(Vec<Inventory>),
    MemPool,
    /// A full block body (header + transactions). Received via `getdata` INV_BLOCK.
    Block(Block),
    /// ITC-custom seam ("ppfx").
    ProofOfPrefix(ProofOfPrefix),
    /// A command whose envelope we parsed but whose payload we don't decode.
    Unknown { command: String, payload: Vec<u8> },
}

impl NetworkMessage {
    pub fn command(&self) -> &str {
        match self {
            NetworkMessage::Version(_) => "version",
            NetworkMessage::Verack => "verack",
            NetworkMessage::Ping(_) => "ping",
            NetworkMessage::Pong(_) => "pong",
            NetworkMessage::SendHeaders => "sendheaders",
            NetworkMessage::GetHeaders(_) => "getheaders",
            NetworkMessage::Headers(_) => "headers",
            NetworkMessage::Inv(_) => "inv",
            NetworkMessage::GetData(_) => "getdata",
            NetworkMessage::MemPool => "mempool",
            NetworkMessage::Block(_) => "block",
            NetworkMessage::ProofOfPrefix(_) => "ppfx",
            NetworkMessage::Unknown { command, .. } => command.as_str(),
        }
    }

    /// Serialize this message's payload (without the frame envelope).
    pub fn encode_payload(&self) -> Vec<u8> {
        let mut v = Vec::new();
        match self {
            NetworkMessage::Version(m) => {
                consensus::put_i32_le(&mut v, m.version);
                consensus::put_u64_le(&mut v, m.services);
                consensus::put_i64_le(&mut v, m.timestamp);
                put_netaddr(&mut v, m.recv_services, &m.recv_ip, m.recv_port);
                put_netaddr(&mut v, m.from_services, &m.from_ip, m.from_port);
                consensus::put_u64_le(&mut v, m.nonce);
                consensus::put_var_str(&mut v, &m.user_agent);
                consensus::put_i32_le(&mut v, m.start_height);
                consensus::put_u8(&mut v, if m.relay { 1 } else { 0 });
            }
            NetworkMessage::Verack | NetworkMessage::SendHeaders | NetworkMessage::MemPool => {}
            NetworkMessage::Ping(n) | NetworkMessage::Pong(n) => consensus::put_u64_le(&mut v, *n),
            NetworkMessage::GetHeaders(m) => {
                consensus::put_u32_le(&mut v, m.version);
                consensus::put_compact_size(&mut v, m.locator.len() as u64);
                for h in &m.locator {
                    consensus::put_hash(&mut v, h);
                }
                consensus::put_hash(&mut v, &m.hash_stop);
            }
            NetworkMessage::Headers(hs) => {
                consensus::put_compact_size(&mut v, hs.len() as u64);
                for h in hs {
                    v.extend_from_slice(&h.encode());
                    consensus::put_compact_size(&mut v, 0); // tx count, always 0 in headers
                }
            }
            NetworkMessage::Inv(items) | NetworkMessage::GetData(items) => {
                consensus::put_compact_size(&mut v, items.len() as u64);
                for it in items {
                    consensus::put_u32_le(&mut v, it.inv_type);
                    consensus::put_hash(&mut v, &it.hash);
                }
            }
            NetworkMessage::Block(b) => v.extend_from_slice(&b.raw),
            NetworkMessage::ProofOfPrefix(p) => {
                consensus::put_i32_le(&mut v, p.tip_height);
                consensus::put_hash(&mut v, &p.tip_hash);
                consensus::put_hash(&mut v, &p.base_hash);
            }
            NetworkMessage::Unknown { payload, .. } => v.extend_from_slice(payload),
        }
        v
    }

    /// Decode a payload given its command name.
    pub fn decode_payload(command: &str, payload: &[u8]) -> Result<NetworkMessage> {
        let mut r = Reader::new(payload);
        Ok(match command {
            "version" => {
                let version = r.read_i32_le()?;
                let services = r.read_u64_le()?;
                let timestamp = r.read_i64_le()?;
                let (recv_services, recv_ip, recv_port) = read_netaddr(&mut r)?;
                let (from_services, from_ip, from_port) = read_netaddr(&mut r)?;
                let nonce = r.read_u64_le()?;
                let user_agent = r.read_var_str()?;
                let start_height = r.read_i32_le()?;
                let relay = if r.remaining() >= 1 { r.read_u8()? != 0 } else { true };
                NetworkMessage::Version(VersionMessage {
                    version,
                    services,
                    timestamp,
                    recv_services,
                    recv_ip,
                    recv_port,
                    from_services,
                    from_ip,
                    from_port,
                    nonce,
                    user_agent,
                    start_height,
                    relay,
                })
            }
            "verack" => NetworkMessage::Verack,
            "sendheaders" => NetworkMessage::SendHeaders,
            "mempool" => NetworkMessage::MemPool,
            "ping" => NetworkMessage::Ping(r.read_u64_le()?),
            "pong" => NetworkMessage::Pong(r.read_u64_le()?),
            "getheaders" => {
                let version = r.read_u32_le()?;
                let n = r.read_compact_size()? as usize;
                let mut locator = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    locator.push(r.read_hash()?);
                }
                let hash_stop = r.read_hash()?;
                NetworkMessage::GetHeaders(GetHeadersMessage { version, locator, hash_stop })
            }
            "headers" => {
                let n = r.read_compact_size()? as usize;
                let mut hs = Vec::with_capacity(n.min(4096));
                for _ in 0..n {
                    let h = BlockHeader::decode(&mut r)?;
                    let _tx_count = r.read_compact_size()?; // always 0 in headers
                    hs.push(h);
                }
                NetworkMessage::Headers(hs)
            }
            "inv" | "getdata" => {
                let n = r.read_compact_size()? as usize;
                let mut items = Vec::with_capacity(n.min(65536));
                for _ in 0..n {
                    items.push(Inventory {
                        inv_type: r.read_u32_le()?,
                        hash: r.read_hash()?,
                    });
                }
                if command == "inv" {
                    NetworkMessage::Inv(items)
                } else {
                    NetworkMessage::GetData(items)
                }
            }
            "block" => {
                let raw = payload.to_vec();
                match Block::from_raw(raw.clone()) {
                    Some(b) => NetworkMessage::Block(b),
                    None => NetworkMessage::Unknown { command: "block".to_string(), payload: raw },
                }
            }
            "ppfx" => NetworkMessage::ProofOfPrefix(ProofOfPrefix {
                tip_height: r.read_i32_le()?,
                tip_hash: r.read_hash()?,
                base_hash: r.read_hash()?,
            }),
            other => NetworkMessage::Unknown {
                command: other.to_string(),
                payload: payload.to_vec(),
            },
        })
    }
}

/// Encode a full message frame for the given network magic.
pub fn encode_frame(magic: [u8; 4], msg: &NetworkMessage) -> Vec<u8> {
    let payload = msg.encode_payload();
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.extend_from_slice(&magic);
    let cmd = msg.command().as_bytes();
    let mut cmd_buf = [0u8; COMMAND_LEN];
    let n = cmd.len().min(COMMAND_LEN);
    cmd_buf[..n].copy_from_slice(&cmd[..n]);
    frame.extend_from_slice(&cmd_buf);
    consensus::put_u32_le(&mut frame, payload.len() as u32);
    frame.extend_from_slice(&hashes::checksum(&payload));
    frame.extend_from_slice(&payload);
    frame
}

/// Parse the 24-byte message header. Returns (command, payload_len, checksum).
pub fn parse_header(magic: [u8; 4], hdr: &[u8; HEADER_LEN]) -> Result<(String, usize, [u8; 4])> {
    if hdr[0..4] != magic {
        return Err(Error::InvalidValue("bad network magic"));
    }
    let cmd_bytes = &hdr[4..16];
    let end = cmd_bytes.iter().position(|&b| b == 0).unwrap_or(COMMAND_LEN);
    let command = String::from_utf8_lossy(&cmd_bytes[..end]).into_owned();
    let len = u32::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(Error::InvalidValue("payload too large"));
    }
    let checksum = [hdr[20], hdr[21], hdr[22], hdr[23]];
    Ok((command, len, checksum))
}

/// Verify the payload checksum, then decode into a `NetworkMessage`.
pub fn decode_message(command: &str, payload: &[u8], checksum: [u8; 4]) -> Result<NetworkMessage> {
    if hashes::checksum(payload) != checksum {
        return Err(Error::InvalidValue("bad payload checksum"));
    }
    NetworkMessage::decode_payload(command, payload)
}

fn put_netaddr(v: &mut Vec<u8>, services: u64, ip: &[u8; 16], port: u16) {
    consensus::put_u64_le(v, services);
    v.extend_from_slice(ip);
    v.extend_from_slice(&port.to_be_bytes()); // port is big-endian on the wire
}

fn read_netaddr(r: &mut Reader) -> Result<(u64, [u8; 16], u16)> {
    let services = r.read_u64_le()?;
    let ip = r.read_array16()?;
    let pb = r.read_bytes(2)?;
    let port = u16::from_be_bytes([pb[0], pb[1]]);
    Ok((services, ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAGIC_MAIN;

    fn roundtrip(msg: NetworkMessage) {
        let frame = encode_frame(MAGIC_MAIN, &msg);
        assert!(frame.len() >= HEADER_LEN);
        let mut hdr = [0u8; HEADER_LEN];
        hdr.copy_from_slice(&frame[..HEADER_LEN]);
        let (cmd, len, sum) = parse_header(MAGIC_MAIN, &hdr).unwrap();
        assert_eq!(len, frame.len() - HEADER_LEN);
        let payload = &frame[HEADER_LEN..];
        let decoded = decode_message(&cmd, payload, sum).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn verack_and_ping_roundtrip() {
        roundtrip(NetworkMessage::Verack);
        roundtrip(NetworkMessage::Ping(0xdead_beef_0000_0001));
        roundtrip(NetworkMessage::SendHeaders);
    }

    #[test]
    fn version_roundtrip() {
        roundtrip(NetworkMessage::Version(VersionMessage {
            version: 70016,
            services: 0,
            timestamp: 1_700_000_000,
            recv_services: 0,
            recv_ip: [0u8; 16],
            recv_port: 17333,
            from_services: 0,
            from_ip: [0u8; 16],
            from_port: 17333,
            nonce: 0x0102_0304_0506_0708,
            user_agent: "/itc-node-rs:0.2.0/".to_string(),
            start_height: 48569,
            relay: true,
        }));
    }

    #[test]
    fn getheaders_and_ppfx_roundtrip() {
        roundtrip(NetworkMessage::GetHeaders(GetHeadersMessage {
            version: 70016,
            locator: vec![[0x01; 32], [0x02; 32]],
            hash_stop: [0u8; 32],
        }));
        roundtrip(NetworkMessage::ProofOfPrefix(ProofOfPrefix {
            tip_height: 48569,
            tip_hash: [0xab; 32],
            base_hash: [0xcd; 32],
        }));
    }

    #[test]
    fn headers_roundtrip() {
        let h = BlockHeader {
            version: 0x2000_0000,
            prev_blockhash: [0x11; 32],
            merkle_root: [0x22; 32],
            time: 1_600_000_000,
            bits: 0x1d00_ffff,
            nonce: 7,
        };
        roundtrip(NetworkMessage::Headers(vec![h.clone(), h]));
    }

    #[test]
    fn bad_magic_rejected() {
        let frame = encode_frame(MAGIC_MAIN, &NetworkMessage::Verack);
        let mut hdr = [0u8; HEADER_LEN];
        hdr.copy_from_slice(&frame[..HEADER_LEN]);
        assert!(parse_header([0, 0, 0, 0], &hdr).is_err());
    }
}
