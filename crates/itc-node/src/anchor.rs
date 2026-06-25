//! Trust-the-anchor: connect to the seed anchor and adopt the chain tip we
//! trust, without re-deriving consensus.

use std::io;

use itc_proto::AnchorTip;

use crate::p2p::Peer;

/// Connect to the anchor, complete the handshake, and adopt its reported height
/// as our trusted anchor tip. Returns the live [`Peer`] (for header retrieval)
/// and the [`AnchorTip`].
///
/// The height comes from the peer's `version` on the wire — a real read, not a
/// guess. The tip *hash* is filled in as headers are synced forward (next slice);
/// until then the anchor tip carries the trusted height with a zero hash.
pub fn fetch_anchor_tip(endpoint: &str, magic: [u8; 4]) -> io::Result<(Peer, AnchorTip)> {
    let peer = Peer::connect(endpoint, magic, 0)?;
    let tip = AnchorTip {
        height: peer.peer_height,
        hash: [0u8; 32],
    };
    Ok((peer, tip))
}
