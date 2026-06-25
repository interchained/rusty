//! Seeding server — accept inbound peers and answer their `getheaders` (from the
//! synced chain) and `getdata` for block bodies (from the NEDB store). This is the
//! "valued peer" behavior: the node gives back.

use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use itc_proto::hashes::to_internal_hex;
use itc_proto::message::{self, NetworkMessage};

use crate::chain::HeaderChain;
use crate::p2p::Peer;
use crate::store::Store;

/// Bind `listen` and serve inbound peers from the synced chain + NEDB store.
/// Blocks, spawning a thread per connection.
pub fn serve(
    listen: &str,
    magic: [u8; 4],
    chain: Arc<HeaderChain>,
    store: Arc<Store>,
    our_height: i32,
) -> io::Result<()> {
    let listener = TcpListener::bind(listen)?;
    println!(
        "itc-node[serve]: seeding on {listen} — tip height {}",
        chain.tip_height()
    );
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let chain = Arc::clone(&chain);
                let store = Arc::clone(&store);
                let who = stream
                    .peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "?".to_string());
                thread::spawn(move || {
                    if let Err(e) = serve_peer(stream, magic, chain, store, our_height) {
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
    store: Arc<Store>,
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
                println!("itc-node[serve]: served {n} headers");
            }
            NetworkMessage::GetData(invs) => {
                let mut served = 0usize;
                for inv in &invs {
                    if inv.inv_type == message::INV_BLOCK {
                        if let Some(raw) = store.get_block(&to_internal_hex(&inv.hash)) {
                            peer.send(&NetworkMessage::Block(raw))?;
                            served += 1;
                        }
                    }
                }
                if served > 0 {
                    println!("itc-node[serve]: served {served} block(s)");
                }
            }
            NetworkMessage::Ping(nonce) => peer.send(&NetworkMessage::Pong(nonce))?,
            _ => {}
        }
    }
}
