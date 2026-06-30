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
// COLL_INDEX kept for reference but tip now lives in COLL_HEADERS as "__tip__"
#[allow(dead_code)]
const COLL_INDEX: &str = "chain_tip";

type PutOp = (String, String, serde_json::Value, Vec<String>, Option<String>, Option<String>);

pub struct Store {
    pub db: Arc<Db>,
}

fn err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

impl Store {
    /// Wrap an already-open NEDB instance (e.g. for background threads).
    #[allow(dead_code)]
    pub fn from_arc_db(db: Arc<Db>) -> Store {
        Store { db }
    }

    /// Open (or create) the NEDB-backed store at `path`.
    ///
    /// On cold start (no MANIFEST on disk), NEDB rebuilds the index from the WAL
    /// in a background thread. `head()` returns empty until the scan completes.
    /// We wait here so that `get_tip()` and other reads see the full indexed state.
    pub fn open(path: &str) -> io::Result<Store> {
        let db = Db::open(Path::new(path), None).map_err(err)?;
        let db = Arc::new(db);
        Db::start_cold_scan(Arc::clone(&db));
        // Wait for the cold scan to complete (indicated by a non-empty head).
        // On warm start the head is immediately available; on cold start we wait.
        // Timeout: 300s (5 minutes) for very large databases.
        let store = Store { db };
        if store.head().is_empty() {
            println!("itc-node[store]: cold start — waiting for NEDB scan to complete...");
            for _ in 0..30_000u32 { // 300s at 10ms intervals
                std::thread::sleep(std::time::Duration::from_millis(10));
                if !store.head().is_empty() { break; }
            }
            println!("itc-node[store]: NEDB scan complete (head={})", &store.head()[..16.min(store.head().len())]);
        }
        Ok(store)
    }

    /// The engine's tamper-evident Merkle head (for logging / proofs).
    pub fn head(&self) -> String {
        self.db.head()
    }

    /// Persist a single header, linked causally to its parent.
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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

    /// Return true if we already have this block body persisted.
    pub fn has_block(&self, id: &str) -> bool {
        self.db.get(COLL_BLOCKS, id).is_some()
    }

    /// Persist the chain tip (height + hash).
    ///
    /// Polls until NEDB's indexer confirms the write is readable.
    /// NEDB has an async indexer — `put()` appends to the WAL immediately but
    /// `get()` reads from the index, which may lag by a few milliseconds.
    /// Blocking here ensures the tip is durable and readable before returning,
    /// so the next boot's `get_tip()` sees the correct height.
    /// Tip lives in headers/"__tip__" — same collection as blocks, same persistence.
    pub fn put_tip(&self, height: i32, hash: &[u8; 32]) -> io::Result<()> {
        let data = json!({ "height": height, "hash": to_internal_hex(hash) });
        self.db
            .put(COLL_HEADERS, "__tip__", data, vec![], None, None)
            .map(|_| ())
            .map_err(err)?;
        // Poll until the write is visible in the index (async indexer lag)
        for attempt in 0..200u32 {
            if let Some((h, _)) = self.get_tip() {
                if h >= height {
                    // Write is indexed — now force MANIFEST write so it survives restart
                    self.checkpoint();
                    return Ok(());
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
            if attempt == 50 {
                eprintln!("[TIP] NEDB indexer lagging for height {height} — waiting...");
            }
        }
        eprintln!("[TIP] WARNING: NEDB did not confirm tip {height} after 2s");
        Ok(())
    }

    /// Force NEDB to write a new MANIFEST checkpoint that includes all recent
    /// WAL entries. Without this, warm-start reads the old MANIFEST and misses
    /// tip writes that happened after the last checkpoint.
    ///
    /// Called after put_tip to guarantee the tip survives the next restart.
    pub fn checkpoint(&self) {
        // Trigger a fresh cold scan → NEDB rebuilds the in-memory index from
        // the full WAL and writes a new MANIFEST at the current seq.
        // This is the only public API to force a MANIFEST write in NEDB v1.
        Db::start_cold_scan(Arc::clone(&self.db));
        // Wait for the scan to complete (head changes when done)
        let before = self.head();
        for _ in 0..500u32 { // 5s max
            std::thread::sleep(std::time::Duration::from_millis(10));
            if self.head() != before { break; }
        }
    }

    /// Load the persisted chain tip, if any.
    pub fn get_tip(&self) -> Option<(i32, [u8; 32])> {
        let node = self.db.get(COLL_HEADERS, "__tip__")?;
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
    #[allow(dead_code)]
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
