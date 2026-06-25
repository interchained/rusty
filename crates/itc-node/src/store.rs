//! Real storage backend over nedb-engine — the v2 content-addressed DAG engine,
//! already Rust, used directly (no FFI). Persists headers, blocks, and the chain
//! index into NEDB collections so the node resumes instantly on the next boot.
//!
//! - `headers` collection: id = block-hash hex, data = {hdr: <80-byte hex>, height},
//!   `caused_by = [parent hash]` — the header is a DAG node caused by its parent.
//! - `blocks`  collection: id = block-hash hex, data = {raw: <block hex>} (ready
//!   for the block-download slice; persisted the same way).
//! - `index`   collection: id = "tip", data = {height, hash} — the persisted tip.

use std::io;
use std::path::Path;
use std::sync::Arc;

use nedb_engine::Db;
use serde_json::json;

use itc_proto::block::BlockHeader;
use itc_proto::consensus::Reader;
use itc_proto::hashes::to_internal_hex;

const COLL_HEADERS: &str = "headers";
const COLL_BLOCKS: &str = "blocks";
const COLL_INDEX: &str = "index";

type PutOp = (String, String, serde_json::Value, Vec<String>, Option<String>, Option<String>);

pub struct Store {
    db: Arc<Db>,
}

fn err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

impl Store {
    /// Open (or create) the NEDB-backed store at `path`.
    pub fn open(path: &str) -> io::Result<Store> {
        let db = Db::open(Path::new(path), None).map_err(err)?;
        let db = Arc::new(db);
        // Warm start is already ready; a cold start (no MANIFEST) rebuilds the
        // index in a background thread. Idempotent and safe either way.
        Db::start_cold_scan(Arc::clone(&db));
        Ok(Store { db })
    }

    /// The engine's tamper-evident Merkle head (for logging / proofs).
    pub fn head(&self) -> String {
        self.db.head()
    }

    /// Persist a single header, linked causally to its parent.
    pub fn put_header(&self, header: &BlockHeader, height: i32) -> io::Result<()> {
        let id = to_internal_hex(&header.block_hash());
        let parent = to_internal_hex(&header.prev_blockhash);
        let data = json!({ "hdr": hex_encode(&header.encode()), "height": height });
        self.db
            .put(COLL_HEADERS, &id, data, vec![parent], None, None)
            .map(|_| ())
            .map_err(err)
    }

    /// Persist a batch of headers in one engine call (parallel, monotonic seq).
    pub fn put_headers_batch(&self, items: &[(BlockHeader, i32)]) -> io::Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        let ops: Vec<PutOp> = items
            .iter()
            .map(|(h, height)| {
                let id = to_internal_hex(&h.block_hash());
                let parent = to_internal_hex(&h.prev_blockhash);
                let data = json!({ "hdr": hex_encode(&h.encode()), "height": *height });
                (COLL_HEADERS.to_string(), id, data, vec![parent], None, None)
            })
            .collect();
        self.db.put_batch(ops).map(|_| ()).map_err(err)
    }

    /// Load a header (and its height) by block-hash hex id.
    pub fn get_header(&self, id: &str) -> Option<(BlockHeader, i32)> {
        let node = self.db.get(COLL_HEADERS, id)?;
        let hdr_hex = node.data.get("hdr")?.as_str()?;
        let height = node.data.get("height")?.as_i64()? as i32;
        let bytes = hex_decode(hdr_hex)?;
        let mut r = Reader::new(&bytes);
        let header = BlockHeader::decode(&mut r).ok()?;
        Some((header, height))
    }

    /// Persist a full block body (raw consensus bytes). Used by the block-download
    /// slice; the storage path is real and ready now.
    pub fn put_block(&self, block_hash_hex: &str, raw: &[u8]) -> io::Result<()> {
        let data = json!({ "raw": hex_encode(raw) });
        self.db
            .put(COLL_BLOCKS, block_hash_hex, data, vec![], None, None)
            .map(|_| ())
            .map_err(err)
    }

    /// Load a full block body's raw bytes by block-hash hex id.
    pub fn get_block(&self, id: &str) -> Option<Vec<u8>> {
        let node = self.db.get(COLL_BLOCKS, id)?;
        hex_decode(node.data.get("raw")?.as_str()?)
    }

    /// Persist the chain tip (height + hash).
    pub fn put_tip(&self, height: i32, hash: &[u8; 32]) -> io::Result<()> {
        let data = json!({ "height": height, "hash": to_internal_hex(hash) });
        self.db
            .put(COLL_INDEX, "tip", data, vec![], None, None)
            .map(|_| ())
            .map_err(err)
    }

    /// Load the persisted chain tip, if any.
    pub fn get_tip(&self) -> Option<(i32, [u8; 32])> {
        let node = self.db.get(COLL_INDEX, "tip")?;
        let height = node.data.get("height")?.as_i64()? as i32;
        let bytes = hex_decode(node.data.get("hash")?.as_str()?)?;
        if bytes.len() != 32 {
            return None;
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&bytes);
        Some((height, h))
    }

    /// Walk from the persisted tip back to genesis, returning headers in chain
    /// order (height 1 .. tip). Empty if nothing is persisted yet.
    pub fn load_headers_to_tip(&self) -> Vec<BlockHeader> {
        let genesis = itc_proto::genesis_hash_internal();
        let mut out = Vec::new();
        let (_, tip) = match self.get_tip() {
            Some(t) => t,
            None => return out,
        };
        let mut cur = tip;
        let mut guard = 0u64;
        while cur != genesis {
            guard += 1;
            if guard > 10_000_000 {
                break;
            }
            match self.get_header(&to_internal_hex(&cur)) {
                Some((hdr, _h)) => {
                    let prev = hdr.prev_blockhash;
                    out.push(hdr);
                    cur = prev;
                }
                None => break, // gap in persisted data — stop, use what we have
            }
        }
        out.reverse(); // genesis-first
        out
    }
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        out.push((hexval(bytes[i])? << 4) | hexval(bytes[i + 1])?);
        i += 2;
    }
    Some(out)
}

fn hexval(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
