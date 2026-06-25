//! Seeding server — accept inbound peers and answer their `getheaders` from the
//! chain we synced. This is the "valued peer" behavior: the node gives back.
//!
//! Slice 3 holds headers only (no block bodies yet), so we serve headers and
//! ignore `getdata` for block bodies — block serving arrives with the storage /
//! block-download slice. We do not fake having data we don't hold.

use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use itc_proto::message::NetworkMessage;

use crate::chain::HeaderChain;
use crate::p2p::Peer;

/// Bind `listen` and serve inbound peers from the (read-only) synced chain.
/// Blocks, spawning a thread per connection.
pub fn serve(listen: &str, magic: [u8; 4], chain: Arc<HeaderChain>, our_height: i32) -> io::Result<()> {
    let listener = TcpListener::bind(listen)?;
    println!(
        "itc-node[serve]: seeding on {listen} — tip height {}",
        chain.tip_height()
    );
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let chain = Arc::clone(&chain);
                let who = stream
                    .peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "?".to_string());
                thread::spawn(move || {
                    if let Err(e) = serve_peer(stream, magic, chain, our_height) {
                        println!("itc-node[serve]: peer {who} ended: {e}");
                    }
                });
            }
            Err(e) => println!("itc-node[serve]: accept error: {e}"),
        }
    }
    Ok(())
}

fn serve_peer(
    stream: TcpStream,
    magic: [u8; 4],
    chain: Arc<HeaderChain>,
    our_height: i32,
) -> io::Result<()> {
    let mut peer = Peer::from_stream(stream, magic);
    peer.handshake(our_height)?;
    println!(
        "itc-node[serve]: inbound peer ua={:?} height={}",
        peer.peer_user_agent, peer.peer_height
    );
    loop {
        match peer.recv()? {
            NetworkMessage::GetHeaders(gh) => {
                let hs = chain.headers_after_locator(&gh.locator, &gh.hash_stop);
                let n = hs.len();
                peer.send(&NetworkMessage::Headers(hs))?;
                println!("itc-node[serve]: served {n} headers to {:?}", peer.peer_user_agent);
            }
            NetworkMessage::Ping(nonce) => peer.send(&NetworkMessage::Pong(nonce))?,
            NetworkMessage::GetData(_) => {
                // headers-only this slice; block-body serving lands with storage.
            }
            _ => {}
        }
    }
}
