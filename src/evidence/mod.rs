//! Evidence system: immutable, hash-verified records of tool observations.
//!
//! - `models` — the [`Evidence`] record and content hashing.
//! - `parser` — converts tool output into structured evidence.
//! - `storage` — in-memory index + disk persistence per session.

pub mod models;
pub mod parser;
pub mod storage;

pub use models::{sha256_hex, Evidence, EvidenceType};
pub use parser::parse_tool_output;
pub use storage::EvidenceStore;
