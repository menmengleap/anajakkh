//! Findings system: normalized, evidence-referenced conclusions.
//!
//! - `severity` — severity classification and ranking.
//! - `models` — the [`Finding`] record and source separation.
//! - `analyzer` — rule-based detection, AI-output validation, storage.

pub mod analyzer;
pub mod models;
pub mod severity;

pub use analyzer::{Analyzer, FindingStore};
pub use models::{Finding, FindingSource};
pub use severity::Severity;
