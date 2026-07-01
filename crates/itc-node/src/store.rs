//! Real storage backend over nedb-engine — the v2 content-addressed DAG engine,
//! already Rust, used directly (no FFI). Persists headers, blocks, and L2 receipts
//! into NEDB collections so the node resumes instantly on the next boot.
//!
//! - `headers` collection: id = block-hash hex, data = {hdr: <80-byte hex>, height},
//!   `caused_by = [parent hash]` — the header is a DAG node caused by its parent.
//! - `blocks`  collection: id = block-hash hex, data = {raw: <block hex>}.
//!
//! Boot resume (v2.5.44+): the chain tip is NOT a synthetic marker document — it is
//! read directly from the engine's own durable per-collection tip,
//! `db.tip_collection("headers")`. That primitive is kept current on every write and
//! survives a warm restart with no scan (persisted in MANIFEST) — see
//! <https://github.com/Eth-Interchained/nedb/blob/master/docs/REPLICATION.md>.
//! Because a header document's id IS `to_internal_hex(header.block_hash())`, the tip
//! hash is the node's id directly; no header bytes need decoding to resume.
//!
//! Durability: `flush()` wraps the engine's `flush_all()` (WAL + segment sync +
//! MANIFEST, including the tip). Callers checkpoint on their own cadence — this
//! module is a persistence primitive, not a policy: it does not decide *when* to
//! flush, only *how*. See `sync::sync_headers`/`sync_blocks` (L1, every ~2000) and
//! `sequencer::produce_block` (L2, every 500), plus the exit handler in `main.rs`.

use std::io;
use std::io::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nedb_engine::Db;
use serde_json::json;

use itc_proto::block::BlockHeader;
use itc_proto::consensus::Reader;
use itc_proto::hashes::to_internal_hex;

pub const COLL_HEADERS: &str = "headers";
const COLL_BLOCKS: &str = "blocks";

type PutOp = (String, String, serde_json::Value, Vec<String>, Option<String>, Option<String>);

pub struct Store {
    pub db: Arc<Db>,
}

fn err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

impl Store {
    /// Wrap an already-open NEDB instance (e.g. for background threads).
    pub fn from_arc_db(db: Arc<Db>) -> Store {
        Store { db }
    }

    /// Open (or create) the NEDB-backed store at `path`.
    ///
    /// On cold start (no MANIFEST on disk, or a pre-2.5.43 MANIFEST self-healing
    /// into a durable one), NEDB rebuilds the index from the WAL in a background
    /// thread. `tip_header()` and other resume reads are only trustworthy once
    /// that scan finishes — we wait here for the real signal, `scan_status()
    /// .scan_complete`, and NEVER claim done before it is: a database sized in
    /// the millions of objects can take longer to index than any fixed timeout
    /// would allow, and giving up early used to silently print "scan complete"
    /// anyway — which meant `tip_header()` came back empty right after, and the
    /// node fell back to a full genesis resync. There is no safe way to proceed
    /// without the real index; waiting is correct, not just cautious.
    pub fn open(path: &str) -> io::Result<Store> {
        let db = Db::open(Path::new(path), None).map_err(err)?;
        let db = Arc::new(db);
        Db::start_cold_scan(Arc::clone(&db));
        let store = Store { db };
        if !store.db.scan_status().scan_complete {
            wait_for_cold_scan(&store.db);
        }
        Ok(store)
    }

    /// The engine's tamper-evident Merkle head (for logging / proofs).
    pub fn head(&self) -> String {
        self.db.head()
    }

    /// Make buffered writes durable now (id-index WAL + segment sync + MANIFEST,
    /// including the tip). Callers decide the cadence — see module docs.
    pub fn flush(&self) {
        self.db.flush_all();
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

    /// Persist a full block body (raw consensus bytes).
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

    /// The chain tip — (height, block hash) of the most recently connected header —
    /// or `None` if nothing has been synced yet. The durable boot-resume primitive:
    /// backed by `db.tip_collection("headers")`, which is kept current on every
    /// header write and survives a warm restart with no scan (see module docs).
    ///
    /// No header bytes need decoding: a header document's id IS
    /// `to_internal_hex(header.block_hash())`, so the tip hash is the node's id
    /// directly. `height` is read straight from the stored `{hdr, height}` payload.
    pub fn tip_header(&self) -> Option<(i32, [u8; 32])> {
        let node = self.db.tip_collection(COLL_HEADERS)?;
        let height = node.data.get("height")?.as_i64()? as i32;
        let bytes = hex_decode(&node.id)?;
        if bytes.len() != 32 {
            return None;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Some((height, hash))
    }
}

/// Block until the cold scan reports `scan_complete`, rendering a live progress
/// display. No fixed timeout: giving up early and reporting "done" anyway is
/// exactly the bug this replaces (see `Store::open` docs) — for a database with
/// millions of objects, waiting minutes is normal and correct, not stuck.
///
/// There is no engine-exposed "total objects" figure to compute a true
/// percentage against (only `indexed_count`, which grows as the scan runs), so
/// this shows what is actually and honestly known: a live count, a measured
/// indexing rate, and elapsed time — dressed as a scanning hologram rather than
/// a progress bar promising a percentage nothing here can back up.
fn wait_for_cold_scan(db: &Db) {
    const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    const SWEEP_WIDTH: usize = 28;
    const FRAME_INTERVAL: Duration = Duration::from_millis(90);
    const RATE_SAMPLE_INTERVAL: Duration = Duration::from_millis(500);
    const MILESTONE_INTERVAL: Duration = Duration::from_secs(30);

    let cyan = "\x1b[36m";
    let bcyan = "\x1b[1;36m";
    let dim = "\x1b[2m";
    let bold = "\x1b[1m";
    let green = "\x1b[1;32m";
    let reset = "\x1b[0m";

    let start = Instant::now();
    let mut last_sample_t = start;
    let mut last_sample_n = db.scan_status().indexed_count as u64;
    let mut rate = 0.0f64;
    let mut frame = 0usize;
    let mut last_milestone = start;

    eprintln!(
        "{cyan}  ◈ cold start — indexing the DAG in the background (one-time, until the next warm boot){reset}"
    );

    loop {
        let status = db.scan_status();
        if status.scan_complete {
            break;
        }
        let count = status.indexed_count as u64;
        let now = Instant::now();
        let elapsed = now.duration_since(start).as_secs_f64();

        if now.duration_since(last_sample_t) >= RATE_SAMPLE_INTERVAL {
            let dt = now.duration_since(last_sample_t).as_secs_f64();
            let dn = count.saturating_sub(last_sample_n) as f64;
            if dt > 0.0 {
                rate = dn / dt;
            }
            last_sample_t = now;
            last_sample_n = count;
        }

        // Holographic sweep: a bright glyph travels back and forth across a dim
        // field — an honest "activity" indicator, not a percentage claim.
        let cycle = SWEEP_WIDTH.saturating_sub(1).max(1) * 2;
        let pos = frame % cycle.max(1);
        let pos = if pos < SWEEP_WIDTH { pos } else { cycle - pos };
        let mut sweep = String::with_capacity(SWEEP_WIDTH);
        for i in 0..SWEEP_WIDTH {
            sweep.push_str(if i == pos { "█" } else { "▁" });
        }

        eprint!(
            "\r  {cyan}{spin}{reset}  {bcyan}[{sweep}]{reset}  {bold}{count:>13}{reset} objects indexed  {dim}({rate:>7.0}/s · {elapsed:>5.0}s elapsed){reset}   ",
            spin = SPINNER[frame % SPINNER.len()],
            sweep = sweep,
            count = format_count(count),
            rate = rate,
            elapsed = elapsed,
        );
        let _ = std::io::stderr().flush();

        // A plain, newline-terminated line every 30s so log collectors that
        // mangle carriage-return-updated lines (journald, docker logs, etc.)
        // still see periodic, honest proof of progress.
        if now.duration_since(last_milestone) >= MILESTONE_INTERVAL {
            println!(
                "itc-node[store]: still indexing — {} objects so far ({:.0}/s, {:.0}s elapsed)",
                format_count(count), rate, elapsed
            );
            last_milestone = now;
        }

        frame += 1;
        std::thread::sleep(FRAME_INTERVAL);
    }

    let final_count = db.scan_status().indexed_count as u64;
    let total_time = start.elapsed().as_secs_f64();
    eprintln!(
        "\r  {green}✓{reset}  cold scan complete — {bold}{}{reset} objects indexed in {:.1}s{pad}",
        format_count(final_count),
        total_time,
        pad = " ".repeat(30),
    );
}

/// Format a count with thousands separators for readability at millions scale.
fn format_count(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out.chars().rev().collect()
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
