//! itc-node — a standalone, instant-boot, trust-the-anchor ITC relay peer.
//!
//! Proof of Sovereignty: this Rust binary is a first-class peer of the C++ itcd
//! node. It does NOT re-derive consensus and does NOT verify-then-boot. It boots
//! instantly, TRUSTS THE ANCHOR CHAIN (mainnet, via the seed anchor / ElectrumX)
//! as truth, and earns its place by relaying headers, blocks, and transactions.
//!
//! Slice 1 (this commit) is the foundation: real ITC params + the boot
//! architecture. P2P, sync, relay, store, and wallet are stubbed behind clear
//! interfaces for the next slices.

mod anchor;
mod p2p;
mod relay;
mod store;
mod wallet;

use itc_proto as proto;

fn main() {
    // ── 1. Instant boot ──────────────────────────────────────────────────────
    // No verify-once, no replay, no warm-boot window check. We come up at once.
    println!(
        "itc-node {} starting — network=Main magic={:02x?} port={} genesis={}",
        env!("CARGO_PKG_VERSION"),
        proto::MAGIC_MAIN,
        proto::DEFAULT_P2P_PORT,
        proto::GENESIS_HASH_HEX,
    );

    // ── 2. Trust the anchor chain ────────────────────────────────────────────
    // The tip the anchor reports IS our truth. We do not independently finalize.
    let tip = anchor::trust_anchor_tip(proto::SEED_ANCHOR);
    println!(
        "itc-node: trusting anchor tip — height={} hash={}",
        tip.height,
        hex32(&tip.hash),
    );

    // ── 3. Open local storage (nedb-engine) ──────────────────────────────────
    // No integrity gate at boot — content-addressed reads self-verify on access.
    let _store = store::open();

    // ── 4. Join as a valued peer ─────────────────────────────────────────────
    // Handshake -> sync from peers -> SERVE blocks/headers -> RELAY transactions.
    // Stubbed until the rust-bitcoin fork + ITC seam land in the next slices.
    p2p::run_stub(&tip);
    relay::run_stub();

    // ── 5. Light wallet (ElectrumX-backed) ───────────────────────────────────
    wallet::connect_stub(proto::ELECTRUMX_ENDPOINT);

    println!("itc-node: boot complete (foundation skeleton — p2p/sync/relay/wallet pending).");
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
