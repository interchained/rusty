//! RpcServer — HTTP listener that dispatches JSON-RPC 2.0 requests.
//!
//! Uses `tiny_http` (thread-per-request, no async runtime). Fine for v1 —
//! JSON-RPC traffic is low-frequency; wallet interactions are not high-throughput.
//!
//! Bind address: `ITC_RPC_ADDR` env var, default `0.0.0.0:8545`.

use std::io::{Cursor, Read};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::thread;

use serde_json::{json, Value};
use tiny_http::{Header, Response, Server};

use itc_evm::ItcEvm;

use crate::handler::{dispatch, SharedEvm};
use crate::types::{RpcRequest, RpcResponse};

/// Default bind address.
pub const DEFAULT_RPC_ADDR: &str = "0.0.0.0:8545";

/// The ITC-L2 JSON-RPC server.
pub struct RpcServer {
    evm: SharedEvm,
    /// Monotonic L2 epoch counter (incremented externally by block production;
    /// for now it's a simple counter advanced by the RPC server's uptime ticks).
    epoch: Arc<AtomicU64>,
}

impl RpcServer {
    /// Create a new RPC server wrapping the given EVM executor.
    pub fn new(evm: ItcEvm) -> Self {
        RpcServer {
            evm: Arc::new(Mutex::new(evm)),
            epoch: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Shared epoch counter — the L2 block production slice will advance this.
    pub fn epoch_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.epoch)
    }

    /// Bind and serve in the calling thread. Spawns one thread per request.
    pub fn serve(self, addr: &str) -> Result<(), String> {
        let server = Server::http(addr).map_err(|e| format!("RPC bind {addr}: {e}"))?;
        println!("itc-rpc: listening on http://{addr} — chain_id={}", itc_evm::CHAIN_ID);

        for mut request in server.incoming_requests() {
            let evm = Arc::clone(&self.evm);
            let epoch = self.epoch.load(Ordering::Relaxed);

            thread::spawn(move || {
                let response = handle_request(&mut request, &evm, epoch);
                let body = serde_json::to_string(&response).unwrap_or_default();
                let resp = Response::from_reader(Cursor::new(body.clone()))
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

    dispatch(&rpc_req.method, &params, id, evm, epoch)
}
