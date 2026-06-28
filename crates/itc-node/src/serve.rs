//! Seeding server — accept inbound peers and serve them as a full ITC network citizen:
//! answer `getheaders`, serve full block bodies on `getdata`, and handle `inv`
//! announcements (request blocks we don't have yet).
//!
//! Slice 5: block bodies in NEDB → serve them. We are now a real peer on the
//! network — not just a relay, but a node that gives back full blocks.

use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use itc_proto::block::Block;
use itc_proto::hashes::to_internal_hex;
use itc_proto::message::{Inventory, NetworkMessage, INV_BLOCK};

use crate::chain::HeaderChain;
use crate::p2p::Peer;
use crate::store::Store;

/// Bind `listen` and serve inbound peers. Each connection gets its own thread.
/// `store` is shared read-only for block body serving.
pub fn serve(
    listen: &str,
    magic: [u8; 4],
    chain: Arc<HeaderChain>,
    store: Arc<Store>,
    our_height: i32,
) -> io::Result<()> {
    let listener = TcpListener::bind(listen)?;
    println!(
        "itc-node[serve]: listening on {listen} — tip height {} (full block-serving enabled)",
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
            // ── Header serving ────────────────────────────────────────────────
            NetworkMessage::GetHeaders(gh) => {
                let hs = chain.headers_after_locator(&gh.locator, &gh.hash_stop);
                let n = hs.len();
                peer.send(&NetworkMessage::Headers(hs))?;
                if n > 0 {
                    println!("itc-node[serve]: served {n} headers");
                }
            }

            // ── Block body serving ────────────────────────────────────────────
            NetworkMessage::GetData(items) => {
                for item in &items {
                    if item.inv_type != INV_BLOCK {
                        continue;
                    }
                    let hash_hex = to_internal_hex(&item.hash);
                    match store.get_block(&hash_hex) {
                        Some(raw) => {
                            if let Some(block) = Block::from_raw(raw) {
                                peer.send(&NetworkMessage::Block(block))?;
                            }
                        }
                        None => {
                            // We don't have it — send notfound so the peer doesn't stall.
                            peer.send(&NetworkMessage::Unknown {
                                command: "notfound".to_string(),
                                payload: encode_notfound(&[item.clone()]),
                            })?;
                        }
                    }
                }
            }

            // ── Inv (peer announcing new blocks) ──────────────────────────────
            // Stay current: when a peer announces new blocks, grab them if we
            // don't have them yet. This is the "always syncing" citizen behavior.
            NetworkMessage::Inv(items) => {
                let want: Vec<Inventory> = items
                    .into_iter()
                    .filter(|it| {
                        it.inv_type == INV_BLOCK
                            && !store.has_block(&to_internal_hex(&it.hash))
                    })
                    .collect();
                if !want.is_empty() {
                    peer.send(&NetworkMessage::GetData(want))?;
                }
            }

            // ── Keepalive ─────────────────────────────────────────────────────
            NetworkMessage::Ping(nonce) => peer.send(&NetworkMessage::Pong(nonce))?,

            _ => {}
        }
    }
}

/// Minimal `notfound` payload: varint count + [type u32 LE | hash 32].
fn encode_notfound(items: &[Inventory]) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(items.len() as u8); // compact size (safe for ≤ 252 items)
    for it in items {
        v.extend_from_slice(&it.inv_type.to_le_bytes());
        v.extend_from_slice(&it.hash);
    }
    v
}
