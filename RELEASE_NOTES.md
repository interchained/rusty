# Rusty Interchained v1.0.0 — ITC-L2 Genesis

> *"Not your keys, not your chain."*
> 
> **Released: 2026-06-29** — The day the first aITC was minted.

---

## What Just Happened

We shipped the first EVM sidechain anchored to a Bitcoin-descended proof-of-work chain — and nobody used a framework to do it.

No Arbitrum license. No OP Stack governance token. No Ethereum dependency. **Rusty** is a Rust binary, written from scratch, that turns ITC mainnet into a base layer for a fully functional EVM. It syncs L1 headers, downloads blocks, runs a bridge deposit oracle, produces L2 blocks every 5 seconds, and serves a MetaMask-compatible JSON-RPC on port 8545.

At **17:17 on 2026-06-29**, the oracle processed its first real deposit:

```
[ORACLE] deposit detected: 105266600 sats from e742004... at height 648511
[ORACLE] confirmed: 105266600 → 100003270 net (5.00% fee = 5263330 sats)
[ORACLE] minted 1000032700000000000 wei for e742004...
```

**1.000033 aITC.** First coin on ITC-L2. On-chain. Auditable. Causally linked to ITC mainnet transaction `e742004709560729d3f342a1b93605384bf49722ff6f512a1f5d5f2ff4ba97bd` via NEDB's `caused_by` DAG.

---

## The Stack

### `itc-node` — the main binary (Rusty)
Full ITC-L2 node: syncs L1, runs oracle, produces L2 blocks, serves RPC.

### `itc-evm` — EVM execution engine
revm 3.x backed by NEDB. Every state write carries `caused_by: [tx_hash]`. Bi-temporal. Content-addressed. Every balance is traceable to the L1 transaction that minted it.

### `itc-oracle` — the bridge deposit oracle
Three-collection NEDB design:
- `oracle_minted` — idempotency guard (written BEFORE the balance — under-mint on crash is recoverable, double-mint is not)
- `oracle_pending` — confirmation queue (survives process restart)
- `oracle_state` — tip height (O(1) resume on reboot)

Detects both legacy P2PKH and bech32 P2WPKH deposits. Reads OP_RETURN EVM destination from bridge transactions.

### `itc-anchor` — L1 sovereignty proof
Posts the NEDB Merkle root as an OP_RETURN to ITC mainnet every 100 L2 epochs. Auto-discovers funding UTXOs via `listunspent`. Bridge address decoded from bech32 automatically.

### `itc-rpc` — MetaMask-compatible JSON-RPC
`eth_getBalance`, `eth_sendRawTransaction`, `eth_blockNumber`, `eth_chainId`, EIP-155 ecrecover. Chain ID 17101.

### `itc-proto` — ITC wire protocol
Bitcoin-compatible P2P parser: headers, blocks, inv messages, P2PKH/P2WPKH script detection, secp256k1 helpers.

---

## Features

### Boot experience
```
  ██████╗ ██╗   ██╗███████╗████████╗██╗   ██╗
  ██╔══██╗██║   ██║██╔════╝╚══██╔══╝╚██╗ ██╔╝
  ██████╔╝██║   ██║███████╗   ██║    ╚████╔╝ 
  ██╔══██╗██║   ██║╚════██║   ██║     ╚██╔╝  
  ██║  ██║╚██████╔╝███████║   ██║      ██║   
  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝      ╚═╝   

  ITC-L2 Node  ·  by Mark × Vex  ·  © Interchained LLC 2026
  "Not your keys, not your chain."

  ┌─────────────────────────────────────────────────────┐
  │  bridge     itc1qfvwn8kmf4f0apmpgy68rtcqcgghq00lwasps6l
  │  anchor-wif L2SC...2rLc
  │  p2p-port   17334
  └─────────────────────────────────────────────────────┘
```

### Instant warm restart
O(1) header resume via `resume_from_tip()`. On warm start, block locator sends the real tip hash — peer responds with 0 new headers if already at tip. Sub-second header sync on restart.

### Progress bar (not log spam)
```
  [headers]  648858/648858 [████████████████████] 100%
```

### Live L1/L2 status
```
  [L1] 648870  |  [L2] 140
```
Single overwriting line. No scrolling. Always current.

### Graceful shutdown
Ctrl+C: flushes tip to NEDB, exits cleanly. Second Ctrl+C: immediate. Next restart picks up from saved tip.

### Replay mode
```bash
./rusty-interchained --replay
```
Wipes L2 derived state. Keeps L1 headers and block bodies. Re-derives oracle state by scanning downloaded blocks. Produces identical output to the original run — the L2 is fully deterministic from L1.

---

## Bridge

**Lock address:** `itc1qfvwn8kmf4f0apmpgy68rtcqcgghq00lwasps6l`

**Fee:** 5% governance (configurable via `ITC_BRIDGE_FEE_BPS`)

**OP_RETURN:** Bridge transactions encode the destination EVM address at OP_RETURN output[2]: `6a14<20-byte address>`. The destination is the user's EVM address at `m/44'/60'/0'/0/0` — standard Ethereum BIP44, MetaMask compatible from the same seed phrase that runs ITC.

**Confirmations:** 2 L1 blocks before mint (configurable).

---

## Storage Contract v1.0

```
$ITC_NODE_DATADIR/
├── headers/          ← L1 IMMUTABLE — 648k+ ITC block headers
├── blocks/           ← L1 IMMUTABLE — block bodies  
├── index/            ← L1 IMMUTABLE — chain tip index
├── evm_accounts/     ← L2 DERIVED  — aITC balances + nonces
├── evm_storage/      ← L2 DERIVED  — contract storage slots
├── evm_code/         ← L2 DERIVED  — deployed bytecode
├── l2_receipts/      ← L2 DERIVED  — transaction receipts
├── oracle_minted/    ← L2 DERIVED  — idempotency guards
├── oracle_pending/   ← L2 DERIVED  — confirmation queue
└── oracle_state/     ← L2 DERIVED  — oracle tip height
```

L1 data is never touched by `--replay`. L2 data is fully reconstructable from L1 in minutes.

---

## Configuration

```bash
ITC_NODE_DATADIR=./rusty-data       # storage root
ITC_P2P_PORT=17334                  # P2P port (default 17333 conflicts with interchainedd)
ITC_RPC_ADDR=0.0.0.0:8545           # JSON-RPC listen address
ITC_BRIDGE_ADDRESS=itc1q...         # bech32 bridge lock address (decoded automatically)
ITC_BRIDGE_FEE_BPS=500              # 5% — basis points
ITC_BRIDGE_CONFIRMATIONS=2          # L1 blocks before mint
ITC_ORACLE_START_HEIGHT=645000      # checkpoint — skip ancient history
ITC_ANCHOR_WIF=<WIF>                # anchor wallet private key
ITC_ANCHOR_INTERVAL=100             # L2 epochs between anchor posts
ITC_L1_RPC_URL=http://127.0.0.1:9332
ITC_L1_RPC_USER=<user>
ITC_L1_RPC_PASS=<pass>
```

---

## Install

### From crates.io
```bash
cargo install rusty-interchained
rusty-interchained
```

### From binary releases
Download the pre-built binary for your platform from the [Releases](https://github.com/interchained/rusty/releases) page.

| Platform | Binary |
|----------|--------|
| Linux x86_64 | `rusty-interchained-linux-x86_64` |
| Linux ARM64 | `rusty-interchained-linux-aarch64` |
| Windows x86_64 | `rusty-interchained-windows-x86_64.exe` |
| macOS (Apple Silicon) | `rusty-interchained-macos-aarch64` |
| macOS (Intel) | `rusty-interchained-macos-x86_64` |

### From source
```bash
git clone https://github.com/interchained/rusty
cd rusty
cargo build --release
./target/release/itc-node
```

---

## Chain Details

| Parameter | Value |
|-----------|-------|
| Chain ID | 17101 |
| Native coin | aITC (Anchored ITC) |
| Block time | 5 seconds |
| RPC | https://l2.interchained.org |
| Explorer | https://vision.interchained.org |
| MetaMask path | m/44'/60'/0'/0/0 |
| Governance address | 0xE1FAF5fA1ee66bd90311caAF5055d711dCB5925a |

---

## What's Next

**Proof of Participation** — governance fees redistributed to bridge participants on schedule. The longer you hold, the more you get back. The system rewards patience and conviction.

**Multi-operator sequencer** — L2 decentralization via multiple authorized block producers, slashing anchored to ITC L1.

**Rusty as infrastructure** — ITC-L2 mainnet is the first deployment. Any operator can run their own Rusty-backed L2 with a different bridge address, chain ID, and governance address.

---

*© Interchained LLC 2026*  
*Built by Mark × Vex*
