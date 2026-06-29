//! Deposit detection — parse a raw L1 block and find bridge deposits.

use itc_proto::script::{is_p2pkh_to, p2pkh_scriptsig_pubkey, pubkey_to_eth_address};
use itc_proto::tx::{block_transactions, Tx};

use crate::MIN_DEPOSIT_SATS;

/// A confirmed bridge deposit (ITC sent to BRIDGE_LOCK_ADDRESS).
#[derive(Clone, Debug)]
pub struct BridgeDeposit {
    /// L1 txid (internal byte order, 32 bytes).
    pub l1_txid: [u8; 32],
    /// L1 txid in display hex (reversed).
    pub l1_txid_display: String,
    /// Amount deposited in satoshis.
    pub amount_sats: u64,
    /// aITC (ETH-format) address of the depositor, derived from their secp256k1 pubkey.
    pub aitc_address: [u8; 20],
    /// L1 block height this deposit was mined in.
    pub l1_height: i32,
}

/// Scan a raw L1 block body for transactions that send ITC to `bridge_lock_hash160`.
///
/// Returns all detected deposits. Does NOT check confirmations — the caller
/// is responsible for waiting DEPOSIT_CONFIRMATIONS blocks.
pub fn scan_block_for_deposits(
    block_raw: &[u8],
    bridge_lock_hash160: &[u8; 20],
    l1_height: i32,
) -> Vec<BridgeDeposit> {
    let txs = block_transactions(block_raw);
    let mut deposits = Vec::new();

    for tx in &txs {
        if let Some(deposit) = extract_deposit(tx, bridge_lock_hash160, l1_height) {
            deposits.push(deposit);
        }
    }
    deposits
}

/// Check one transaction for a bridge deposit.
fn extract_deposit(tx: &Tx, bridge_lock_hash160: &[u8; 20], l1_height: i32) -> Option<BridgeDeposit> {
    // Find an output paying to the bridge lock address.
    let deposited_sats: u64 = tx
        .outputs
        .iter()
        .filter(|o| is_p2pkh_to(&o.script_pubkey, bridge_lock_hash160))
        .map(|o| o.value)
        .sum();

    if deposited_sats < MIN_DEPOSIT_SATS {
        return None;
    }

    // Check for an OP_RETURN output carrying the EVM destination address.
    // Format: 0x6a (OP_RETURN) 0x14 (PUSH 20) <20-byte EVM address>
    // This allows wallets to specify a MetaMask-compatible destination (m/44'/60'/0'/0/0)
    // independent of the L1 sender's key path.
    let op_return_dest: Option<[u8; 20]> = tx.outputs.iter().find_map(|o| {
        let s = &o.script_pubkey;
        if s.len() == 22 && s[0] == 0x6a && s[1] == 0x14 {
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&s[2..22]);
            Some(addr)
        } else {
            None
        }
    });

    // Resolve the aITC mint destination:
    // 1. OP_RETURN destination (Ethereum BIP44 path, MetaMask compatible) — preferred
    // 2. Derived from sender's L1 pubkey — fallback for legacy / non-Elara senders
    let aitc_address = if let Some(dest) = op_return_dest {
        dest
    } else {
        // Extract the sender's pubkey from the first non-coinbase P2PKH input.
        tx.inputs.iter().find_map(|inp| {
            if inp.prev_txid == [0u8; 32] {
                return None; // coinbase
            }
            let pubkey = p2pkh_scriptsig_pubkey(&inp.script_sig)?;
            pubkey_to_eth_address(&pubkey)
        })?
    };

    let l1_txid_display = {
        let mut d = tx.txid;
        d.reverse();
        hex::encode(d)
    };

    Some(BridgeDeposit {
        l1_txid: tx.txid,
        l1_txid_display,
        amount_sats: deposited_sats,
        aitc_address,
        l1_height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_block_no_deposits() {
        let deposits = scan_block_for_deposits(&[], &[0u8; 20], 0);
        assert!(deposits.is_empty());
    }
}
