//! Storage adapter over nedb-engine (already Rust — no FFI).
//!
//! STUB (plan task: "Wire nedb-engine as the storage backend"). The next slice
//! depends on the `nedb-engine` crate and maps headers/blocks/index onto its
//! content-addressed object model. No integrity gate at boot by design —
//! content-addressed reads self-verify on access.

/// Opaque handle to the node's local store.
pub struct Store;

/// Open (or create) the local store.
pub fn open() -> Store {
    Store
}
