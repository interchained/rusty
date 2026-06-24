//! ITC P2P: handshake, header/block sync, and serving peers.
//!
//! STUB (plan tasks: handshake, header/block sync, serving). The wire protocol
//! comes from the rust-bitcoin fork (via `itc-proto`); the ITC-custom
//! Proof-of-Prefix seam is layered on top. v1 must both SYNC FROM and SEED TO
//! itcd peers — that bidirectional interop is the Proof of Sovereignty.

use itc_proto::AnchorTip;

/// Placeholder for the P2P run loop. Logs intent; real networking lands next slice.
pub fn run_stub(tip: &AnchorTip) {
    println!(
        "itc-node[p2p]: would handshake, then sync from / serve to peers above anchor height {} (stub)",
        tip.height
    );
}
