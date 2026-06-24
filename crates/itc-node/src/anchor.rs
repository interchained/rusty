//! Trust-the-anchor: obtain the chain tip the node accepts as truth, without
//! re-deriving consensus. v1 sources it from the seed anchor (P2P :17101) or
//! ElectrumX (:50002) — cf. itcd's NEDB Proof-of-Prefix seam.

use itc_proto::AnchorTip;

/// Return the tip the node trusts as the chain head.
///
/// STUB (plan task: "Implement instant boot ... trust the anchor chain tip").
/// The next slice connects to `endpoint` over the ITC P2P handshake (or ElectrumX
/// `blockchain.headers.subscribe`) and reads its best tip. Until then we return
/// the genesis anchor so the node boots deterministically.
pub fn trust_anchor_tip(endpoint: &str) -> AnchorTip {
    let _ = endpoint; // wired in the anchor slice
    AnchorTip::genesis()
}
