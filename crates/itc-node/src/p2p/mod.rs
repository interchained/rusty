//! ITC P2P peer — a real TCP connection to a node, the version/verack handshake,
//! and header retrieval. Uses `itc-proto` for the wire protocol.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use itc_proto as proto;
use itc_proto::block::BlockHeader;
use itc_proto::message::{self, GetHeadersMessage, NetworkMessage, VersionMessage, HEADER_LEN};

/// A connected peer on the ITC network.
pub struct Peer {
    stream: TcpStream,
    magic: [u8; 4],
    pub peer_version: i32,
    pub peer_height: i32,
    pub peer_user_agent: String,
}

impl Peer {
    /// Connect to `addr` and complete the version/verack handshake.
    pub fn connect(addr: &str, magic: [u8; 4], our_height: i32) -> io::Result<Peer> {
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        let mut peer = Peer {
            stream,
            magic,
            peer_version: 0,
            peer_height: 0,
            peer_user_agent: String::new(),
        };
        peer.handshake(our_height)?;
        Ok(peer)
    }

    /// Wrap an already-accepted inbound stream (for the seeding server). Call
    /// [`Peer::handshake`] next to complete the responder handshake.
    pub fn from_stream(stream: TcpStream, magic: [u8; 4]) -> Peer {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(120)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(120)));
        Peer {
            stream,
            magic,
            peer_version: 0,
            peer_height: 0,
            peer_user_agent: String::new(),
        }
    }

    /// Complete the version/verack handshake (works for both initiator and
    /// responder — both sides send `version` first, then exchange `verack`).
    pub fn handshake(&mut self, our_height: i32) -> io::Result<()> {
        self.send(&NetworkMessage::Version(our_version(our_height)))?;
        let mut got_version = false;
        let mut got_verack = false;
        for _ in 0..32 {
            match self.recv()? {
                NetworkMessage::Version(v) => {
                    self.peer_version = v.version;
                    self.peer_height = v.start_height;
                    self.peer_user_agent = v.user_agent;
                    self.send(&NetworkMessage::Verack)?;
                    got_version = true;
                }
                NetworkMessage::Verack => got_verack = true,
                NetworkMessage::Ping(n) => self.send(&NetworkMessage::Pong(n))?,
                _ => {}
            }
            if got_version && got_verack {
                return Ok(());
            }
        }
        Err(io::Error::new(io::ErrorKind::Other, "handshake did not complete"))
    }

    /// Send a `getheaders` with the given block locator and return the first
    /// `headers` reply (answering pings while waiting).
    pub fn get_headers(&mut self, locator: Vec<[u8; 32]>) -> io::Result<Vec<BlockHeader>> {
        self.send(&NetworkMessage::GetHeaders(GetHeadersMessage {
            version: proto::PROTOCOL_VERSION,
            locator,
            hash_stop: [0u8; 32],
        }))?;
        for _ in 0..64 {
            match self.recv()? {
                NetworkMessage::Headers(hs) => return Ok(hs),
                NetworkMessage::Ping(n) => self.send(&NetworkMessage::Pong(n))?,
                _ => {}
            }
        }
        Err(io::Error::new(io::ErrorKind::Other, "no headers reply"))
    }

    /// Send a framed message.
    pub fn send(&mut self, msg: &NetworkMessage) -> io::Result<()> {
        let frame = message::encode_frame(self.magic, msg);
        self.stream.write_all(&frame)
    }

    /// Read and decode one framed message.
    pub fn recv(&mut self) -> io::Result<NetworkMessage> {
        let mut hdr = [0u8; HEADER_LEN];
        self.stream.read_exact(&mut hdr)?;
        let (command, len, checksum) = message::parse_header(self.magic, &hdr)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?;
        let mut payload = vec![0u8; len];
        self.stream.read_exact(&mut payload)?;
        message::decode_message(&command, &payload, checksum)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))
    }
}

fn our_version(start_height: i32) -> VersionMessage {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    VersionMessage {
        version: proto::PROTOCOL_VERSION as i32,
        services: 0,
        timestamp: now,
        recv_services: 0,
        recv_ip: [0u8; 16],
        recv_port: proto::DEFAULT_P2P_PORT,
        from_services: 0,
        from_ip: [0u8; 16],
        from_port: proto::DEFAULT_P2P_PORT,
        nonce: (now as u64) ^ 0x1c7c_d00d_1c7c_d00d,
        user_agent: format!("/itc-node-rs:{}/", env!("CARGO_PKG_VERSION")),
        start_height,
        relay: true,
    }
}
