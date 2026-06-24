//! Light wallet backed by ElectrumX — the node keeps no local wallet history.
//!
//! STUB (plan task: "Integrate the light ElectrumX-backed wallet"). Talks to the
//! ElectrumX server (seed.interchained.org:50002) for balance, UTXO, and send.

/// Placeholder for the ElectrumX wallet connection.
pub fn connect_stub(endpoint: &str) {
    println!("itc-node[wallet]: would attach ElectrumX wallet at {} (stub)", endpoint);
}
