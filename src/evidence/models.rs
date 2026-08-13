//! Evidence model.
//!
//! Evidence is immutable after collection: once recorded there are no
//! mutable accessors. Every record carries a SHA-256 content hash so
//! tampering is detectable.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// The kind of observation an evidence record represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    /// A discovered host.
    Host,
    /// An open service/port.
    Service,
    /// A DNS resolution.
    DnsRecord,
    /// An HTTP response observation.
    HttpResponse,
    /// A workspace file observation.
    FileInfo,
    /// Unstructured raw output that did not parse further.
    Raw,
}

impl EvidenceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EvidenceType::Host => "host",
            EvidenceType::Service => "service",
            EvidenceType::DnsRecord => "dns_record",
            EvidenceType::HttpResponse => "http_response",
            EvidenceType::FileInfo => "file_info",
            EvidenceType::Raw => "raw",
        }
    }
}

/// A single immutable evidence record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub r#type: EvidenceType,
    /// Tool that produced the observation, e.g. `nmap`.
    pub source: String,
    /// Target the observation relates to.
    pub target: String,
    /// Structured parsed data.
    pub data: Value,
    /// Optional reference to the raw output file on disk.
    pub raw_ref: Option<String>,
    pub timestamp: DateTime<Utc>,
    /// SHA-256 over (type, source, target, data) — content integrity.
    pub sha256: String,
}

impl Evidence {
    pub fn new(
        r#type: EvidenceType,
        source: impl Into<String>,
        target: impl Into<String>,
        data: Value,
    ) -> Self {
        let mut evidence = Self {
            id: Uuid::new_v4().to_string(),
            r#type,
            source: source.into(),
            target: target.into(),
            data,
            raw_ref: None,
            timestamp: Utc::now(),
            sha256: String::new(),
        };
        evidence.sha256 = evidence.compute_hash();
        evidence
    }

    /// Content hash over the immutable fields (type, source, target, data).
    fn compute_hash(&self) -> String {
        let canonical = serde_json::to_string(&self.data).unwrap_or_default();
        let input = format!(
            "{}|{}|{}|{}",
            self.r#type.as_str(),
            self.source,
            self.target,
            canonical
        );
        sha256_hex(input.as_bytes())
    }
}

/// SHA-256 of `bytes` as a lowercase hex string.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_roundtrip() {
        let ev = Evidence::new(
            EvidenceType::Service,
            "nmap",
            "10.0.0.1",
            serde_json::json!({"port": 22, "state": "open"}),
        );
        let json = serde_json::to_string(&ev).unwrap();
        let back: Evidence = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, ev.id);
        assert_eq!(back.r#type, EvidenceType::Service);
        assert_eq!(back.sha256, ev.sha256);
    }

    #[test]
    fn type_names_are_snake_case() {
        assert_eq!(EvidenceType::Host.as_str(), "host");
        assert_eq!(EvidenceType::Service.as_str(), "service");
        assert_eq!(EvidenceType::DnsRecord.as_str(), "dns_record");
        assert_eq!(EvidenceType::HttpResponse.as_str(), "http_response");
        assert_eq!(EvidenceType::FileInfo.as_str(), "file_info");
        assert_eq!(EvidenceType::Raw.as_str(), "raw");
        assert_eq!(
            serde_json::to_string(&EvidenceType::DnsRecord).unwrap(),
            "\"dns_record\""
        );
    }

    #[test]
    fn hash_is_deterministic_and_content_sensitive() {
        let a = Evidence::new(
            EvidenceType::Host,
            "nmap",
            "10.0.0.1",
            serde_json::json!({"status": "up"}),
        );
        let b = Evidence::new(
            EvidenceType::Host,
            "nmap",
            "10.0.0.1",
            serde_json::json!({"status": "up"}),
        );
        let c = Evidence::new(
            EvidenceType::Host,
            "nmap",
            "10.0.0.1",
            serde_json::json!({"status": "down"}),
        );
        assert_eq!(a.sha256, b.sha256, "same content, same hash");
        assert_ne!(a.sha256, c.sha256, "different content, different hash");
        assert_eq!(a.sha256.len(), 64);
    }

    #[test]
    fn sha256_of_known_input() {
        // Well-known SHA-256 of "hello world".
        assert_eq!(
            sha256_hex(b"hello world"),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}
