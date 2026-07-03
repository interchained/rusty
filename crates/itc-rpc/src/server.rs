//! RpcServer — HTTP listener that dispatches JSON-RPC 2.0 requests.
//!
//! Uses `tiny_http` (thread-per-request, no async runtime). Fine for v1 —
//! JSON-RPC traffic is low-frequency; wallet interactions are not high-throughput.
//!
//! Bind address: `ITC_RPC_ADDR` env var, default `0.0.0.0:8545`.

use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::thread;

use serde_json::{json, Value};
use tiny_http::{Header, Response, Server};

use itc_evm::ItcEvm;
use nedb_engine::Db;

use crate::handler::{dispatch, SharedDb, SharedEvm, SharedMempool};
use crate::types::{RpcRequest, RpcResponse};

/// Default bind address.
pub const DEFAULT_RPC_ADDR: &str = "0.0.0.0:8545";

/// The ITC-L2 JSON-RPC server.
pub struct RpcServer {
    evm: SharedEvm,
    /// NEDB handle for receipt lookups (eth_getTransactionReceipt).
    db: Option<SharedDb>,
    /// Monotonic L2 epoch counter — advanced by the sequencer each block.
    epoch: Arc<AtomicU64>,
    /// Shared mempool — eth_sendRawTransaction enqueues here; the sequencer
    /// drains it in produce_block. THE single execution path (previously the
    /// mempool was ignored and txs ran inline, bypassing receipts + bridge
    /// exit detection entirely).
    mempool: SharedMempool,
}

impl RpcServer {
    /// Create a new RPC server wrapping the given EVM executor (owned, single-use).
    pub fn new(evm: ItcEvm) -> Self {
        RpcServer {
            evm: Arc::new(Mutex::new(evm)),
            db: None,
            epoch: Arc::new(AtomicU64::new(0)),
            mempool: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Create a new RPC server with a pre-shared EVM and the sequencer's mempool.
    /// Submitted txs are ENQUEUED here and executed by the sequencer's
    /// produce_block — the one path that persists receipts, runs bridge-exit
    /// detection, and flushes durably.
    pub fn new_shared(evm: SharedEvm, mempool: SharedMempool) -> Self {
        RpcServer {
            evm,
            db: None,
            epoch: Arc::new(AtomicU64::new(0)),
            mempool,
        }
    }

    /// Attach a NEDB handle for receipt lookups.
    pub fn with_db(mut self, db: Arc<Db>) -> Self {
        self.db = Some(db);
        self
    }

    /// Shared epoch counter — advanced by the sequencer each block.
    pub fn epoch_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.epoch)
    }

    /// Spawn the RPC server in a background thread (shared EVM variant).
    pub fn spawn_shared(self, addr: String) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            if let Err(e) = self.serve(&addr) {
                eprintln!("itc-rpc: server error: {e}");
            }
        })
    }

    /// Bind and serve in the calling thread. Spawns one thread per request.
    pub fn serve(self, addr: &str) -> Result<(), String> {
        let server = Server::http(addr).map_err(|e| format!("RPC bind {addr}: {e}"))?;
        println!("itc-rpc: listening on http://{addr} — chain_id={}", itc_evm::CHAIN_ID);

        for mut request in server.incoming_requests() {
            let evm = Arc::clone(&self.evm);
            let epoch = self.epoch.load(Ordering::Relaxed);
            let db = self.db.clone();
            let mempool = Arc::clone(&self.mempool);

            thread::spawn(move || {
                let response = handle_request(&mut request, &evm, epoch, db.as_ref(), &mempool);
                let body = serde_json::to_string(&response).unwrap_or_default();
                let resp = Response::from_data(body.clone())
                    .with_header(
                        Header::from_bytes("Content-Type", "application/json").unwrap()
                    )
                    .with_header(
                        Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap()
                    )
                    .with_header(
                        Header::from_bytes("Access-Control-Allow-Headers", "Content-Type").unwrap()
                    );
                let _ = request.respond(resp);
            });
        }
        Ok(())
    }

    /// Spawn the RPC server in a background thread.
    pub fn spawn(self, addr: String) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            if let Err(e) = self.serve(&addr) {
                eprintln!("itc-rpc: server error: {e}");
            }
        })
    }
}

fn handle_request(
    request: &mut tiny_http::Request,
    evm: &SharedEvm,
    epoch: u64,
    db: Option<&SharedDb>,
    mempool: &SharedMempool,
) -> RpcResponse {
    // Handle CORS preflight
    if request.method() == &tiny_http::Method::Options {
        return RpcResponse::ok(Value::Null, json!(null));
    }

    // Read body
    let mut body = String::new();
    if request.body_length().unwrap_or(0) > 0 {
        if request.as_reader().read_to_string(&mut body).is_err() {
            return RpcResponse::err(Value::Null, -32700, "Parse error: cannot read body");
        }
    }

    // Parse JSON-RPC request
    let rpc_req: RpcRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => {
            return RpcResponse::err(Value::Null, -32700, format!("Parse error: {e}"));
        }
    };

    let id = rpc_req.id.clone().unwrap_or(Value::Null);
    let params = rpc_req.params.as_ref().unwrap_or(&Value::Null).clone();

    dispatch(&rpc_req.method, &params, id, evm, epoch, db, mempool)
}
