//! Persistence layer: embedded database session storage.
//!
//! Uses `redb` — a pure-Rust embedded database (B-tree tables with ACID
//! transactions, zero C dependencies) — so ANAJAKKH builds without a C
//! toolchain.
//!
//! - `database` — database open/create, schema versioning.
//! - `sessions` — session records (scope, conversation, plan, summary).

pub mod database;
pub mod sessions;

pub use sessions::{SessionRecord, SessionStore};
