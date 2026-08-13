//! Findings analyzer.
//!
//! Two layers produce findings:
//! 1. **Rule-based** — deterministic, `Observed` findings derived directly
//!    from evidence (e.g. telnet exposed → high severity).
//! 2. **AI-assisted** — the provider proposes findings from an evidence
//!    summary; every proposal is validated so the AI can never invent
//!    evidence or reference records that do not exist.
//!
//! The store persists findings under `<workspace>/findings/<session>/`.

use std::collections::HashSet;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use serde_json::Value;

use crate::evidence::Evidence;
use crate::evidence::EvidenceType;

use super::models::{Finding, FindingSource};
use super::severity::Severity;

/// Known insecure services detected from open ports (port → detail).
const INSECURE_SERVICES: &[(u16, &str, Severity, &str, &str)] = &[
    (
        23,
        "Telnet service exposed",
        Severity::High,
        "Telnet transmits credentials and traffic in cleartext.",
        "Disable telnet and use SSH with key-based authentication.",
    ),
    (
        21,
        "FTP service exposed",
        Severity::Medium,
        "FTP transmits credentials in cleartext.",
        "Replace plain FTP with SFTP/FTPS.",
    ),
    (
        445,
        "SMB service exposed",
        Severity::Medium,
        "SMB is a frequent target for lateral movement and ransomware.",
        "Restrict SMB access to trusted networks.",
    ),
    (
        3389,
        "RDP service exposed",
        Severity::Medium,
        "RDP is a common attack surface for brute force and credential theft.",
        "Restrict RDP to trusted networks and enforce strong authentication.",
    ),
    (
        6379,
        "Redis service exposed",
        Severity::High,
        "Redis is often deployed unauthenticated and has a history of RCE.",
        "Require authentication and bind Redis to localhost or a firewall.",
    ),
    (
        3306,
        "MySQL service exposed",
        Severity::Medium,
        "The database service is reachable from the assessed network.",
        "Restrict MySQL access to application hosts.",
    ),
];

/// Stateless findings analyzer.
#[derive(Debug, Clone, Default)]
pub struct Analyzer;

impl Analyzer {
    pub fn new() -> Self {
        Self
    }

    /// Deterministic findings from collected evidence. Only `Observed`
    /// findings are produced here — no inference, no speculation.
    pub fn rule_based(&self, evidence: &[Evidence]) -> Vec<Finding> {
        let mut findings: Vec<Finding> = Vec::new();
        for item in evidence {
            match item.r#type {
                EvidenceType::Service => {
                    if let Some(finding) = service_finding(item) {
                        findings.push(finding);
                    }
                }
                EvidenceType::HttpResponse => {
                    findings.push(http_finding(item));
                }
                _ => {}
            }
        }
        findings
    }

    /// Parse findings from an AI response, validating that every referenced
    /// evidence id exists in `valid_evidence_ids`. Proposals that reference
    /// invented evidence are dropped entirely.
    pub fn parse_ai_findings(text: &str, valid_evidence_ids: &HashSet<String>) -> Vec<Finding> {
        let json_text = extract_json(text);
        let Ok(Value::Array(items)) = serde_json::from_str::<Value>(&json_text) else {
            return Vec::new();
        };
        items
            .iter()
            .filter_map(|item| parse_finding_item(item, valid_evidence_ids))
            .collect()
    }
}

fn service_finding(item: &Evidence) -> Option<Finding> {
    let port = item.data.get("port").and_then(Value::as_u64)? as u16;
    let state = item.data.get("state").and_then(Value::as_str).unwrap_or("");
    if !state.eq_ignore_ascii_case("open") {
        return None;
    }
    let (_, title, severity, description, recommendation) = INSECURE_SERVICES
        .iter()
        .find(|(p, _, _, _, _)| *p == port)?;
    Some(Finding::observed(
        *title,
        *severity,
        item.target.clone(),
        *description,
        Some((*recommendation).to_string()),
        vec![item.id.clone()],
    ))
}

fn http_finding(item: &Evidence) -> Finding {
    let status = item.data.get("status").and_then(Value::as_u64).unwrap_or(0);
    Finding::observed(
        "HTTP service exposed",
        Severity::Informational,
        item.target.clone(),
        format!("HTTP service responded with status {status}"),
        Some("Review exposed web services for misconfigurations and known CVEs.".to_string()),
        vec![item.id.clone()],
    )
}

fn parse_finding_item(item: &Value, valid_evidence_ids: &HashSet<String>) -> Option<Finding> {
    let title = item.get("title")?.as_str()?.trim().to_string();
    if title.is_empty() {
        return None;
    }
    let severity = Severity::from_str(item.get("severity")?.as_str()?).ok()?;
    let confidence = item.get("confidence").and_then(Value::as_f64)? as f32;
    if !(0.0..=1.0).contains(&confidence) {
        return None;
    }
    let target = item
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let description = item
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let recommendation = item
        .get("recommendation")
        .and_then(Value::as_str)
        .map(str::to_string);
    let evidence_ids: Vec<String> = item
        .get("evidence_ids")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    // The AI must not invent evidence: at least one reference, all valid.
    if evidence_ids.is_empty()
        || !evidence_ids
            .iter()
            .all(|id| valid_evidence_ids.contains(id))
    {
        return None;
    }

    let source = match item.get("source").and_then(Value::as_str) {
        Some("observed") => FindingSource::Observed,
        Some("hypothesis") => FindingSource::Hypothesis,
        _ => FindingSource::Inferred,
    };

    Some(Finding::new(
        title,
        severity,
        confidence,
        target,
        description,
        recommendation,
        evidence_ids,
        source,
        None,
    ))
}

/// Extract a JSON array from a model response, tolerating prose around it
/// and ```json code fences.
fn extract_json(text: &str) -> String {
    let trimmed = text.trim();
    if let Some(start) = trimmed.find("```") {
        let rest = &trimmed[start + 3..];
        let rest = rest.strip_prefix("json").unwrap_or(rest);
        if let Some(end) = rest.find("```") {
            return rest[..end].trim().to_string();
        }
        return rest.trim().to_string();
    }
    trimmed.to_string()
}

/// Thread-safe store of generated findings, persisted per session.
#[derive(Clone)]
pub struct FindingStore {
    workspace: PathBuf,
    persistent: bool,
    items: Arc<Mutex<Vec<Finding>>>,
}

impl FindingStore {
    /// Persistent store rooted at `workspace/findings`.
    pub fn new(workspace: PathBuf) -> Self {
        Self {
            workspace,
            persistent: true,
            items: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// In-memory store (tests, embedded executor).
    pub fn in_memory() -> Self {
        Self {
            workspace: PathBuf::new(),
            persistent: false,
            items: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Record one finding. Findings are immutable after recording.
    pub fn record(&self, session_id: &str, finding: Finding) -> Result<()> {
        if self.persistent {
            let dir = self.workspace.join("findings").join(session_id);
            std::fs::create_dir_all(&dir)?;
            let path = dir.join(format!("{}.json", finding.id));
            std::fs::write(&path, serde_json::to_string_pretty(&finding)?)?;
        }
        self.items.lock().expect("findings mutex").push(finding);
        Ok(())
    }

    /// The root directory findings are stored under.
    pub fn root_dir(&self) -> PathBuf {
        self.workspace.join("findings")
    }

    /// Load previously persisted findings for a session into memory
    /// (used when resuming). Returns the number of findings loaded.
    pub fn load(&self, session_id: &str) -> Result<usize> {
        let dir = self.workspace.join("findings").join(session_id);
        if !dir.is_dir() {
            return Ok(0);
        }
        let mut count = 0;
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let is_json = entry
                .path()
                .extension()
                .map(|ext| ext == "json")
                .unwrap_or(false);
            if !is_json {
                continue;
            }
            let text = std::fs::read_to_string(entry.path())?;
            if let Ok(finding) = serde_json::from_str::<Finding>(&text) {
                self.items.lock().expect("findings mutex").push(finding);
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn all(&self) -> Vec<Finding> {
        self.items.lock().expect("findings mutex").clone()
    }

    pub fn len(&self) -> usize {
        self.items.lock().expect("findings mutex").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn find(&self, id: &str) -> Option<Finding> {
        self.items
            .lock()
            .expect("findings mutex")
            .iter()
            .find(|f| f.id == id)
            .cloned()
    }

    pub fn by_severity(&self, severity: Severity) -> Vec<Finding> {
        self.items
            .lock()
            .expect("findings mutex")
            .iter()
            .filter(|f| f.severity == severity)
            .cloned()
            .collect()
    }

    pub fn for_target(&self, target: &str) -> Vec<Finding> {
        self.items
            .lock()
            .expect("findings mutex")
            .iter()
            .filter(|f| f.target == target)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn evidence(ty: EvidenceType, target: &str, data: Value) -> Evidence {
        Evidence::new(ty, "nmap", target, data)
    }

    #[test]
    fn telnet_is_a_high_observed_finding() {
        let ev = evidence(
            EvidenceType::Service,
            "10.0.0.1",
            serde_json::json!({"port": 23, "state": "open", "protocol": "tcp", "service": "telnet"}),
        );
        let findings = Analyzer::new().rule_based(std::slice::from_ref(&ev));
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.source, FindingSource::Observed);
        assert_eq!(f.confidence, 1.0);
        assert_eq!(f.evidence_ids, vec![ev.id.clone()]);
        assert!(f.title.contains("Telnet"));
    }

    #[test]
    fn closed_ports_produce_no_finding() {
        let ev = evidence(
            EvidenceType::Service,
            "10.0.0.1",
            serde_json::json!({"port": 23, "state": "closed", "protocol": "tcp"}),
        );
        assert!(Analyzer::new()
            .rule_based(std::slice::from_ref(&ev))
            .is_empty());
    }

    #[test]
    fn unknown_ports_produce_no_finding() {
        let ev = evidence(
            EvidenceType::Service,
            "10.0.0.1",
            serde_json::json!({"port": 8080, "state": "open", "protocol": "tcp", "service": "http-proxy"}),
        );
        assert!(Analyzer::new().rule_based(&[ev]).is_empty());
    }

    #[test]
    fn http_response_is_an_informational_finding() {
        let ev = Evidence::new(
            EvidenceType::HttpResponse,
            "http",
            "example.com",
            serde_json::json!({"url": "http://example.com/", "status": 200}),
        );
        let findings = Analyzer::new().rule_based(std::slice::from_ref(&ev));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Informational);
        assert_eq!(findings[0].evidence_ids, vec![ev.id.clone()]);
    }

    #[test]
    fn dns_and_host_evidence_are_not_findings() {
        let evs = vec![
            evidence(
                EvidenceType::DnsRecord,
                "example.com",
                serde_json::json!({"name": "example.com", "addresses": ["1.2.3.4"]}),
            ),
            evidence(
                EvidenceType::Host,
                "1.2.3.4",
                serde_json::json!({"ip": "1.2.3.4", "status": "up"}),
            ),
        ];
        assert!(Analyzer::new().rule_based(&evs).is_empty());
    }

    #[test]
    fn parses_ai_findings_with_valid_evidence() {
        let mut valid = HashSet::new();
        valid.insert("ev-1".to_string());
        valid.insert("ev-2".to_string());
        let text = r#"[{"title":"Possible weak cipher","severity":"medium","confidence":0.7,"target":"10.0.0.1","description":"Weak TLS ciphers observed","recommendation":"Reconfigure TLS","evidence_ids":["ev-1"],"source":"inferred"}]"#;
        let findings = Analyzer::parse_ai_findings(text, &valid);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.source, FindingSource::Inferred);
        assert!((f.confidence - 0.7).abs() < 1e-6);
    }

    #[test]
    fn ai_cannot_invent_evidence() {
        let mut valid = HashSet::new();
        valid.insert("ev-1".to_string());
        // References ev-9 which does not exist.
        let text = r#"[{"title":"Fake finding","severity":"high","confidence":0.9,"target":"t","description":"d","evidence_ids":["ev-9"]}]"#;
        assert!(Analyzer::parse_ai_findings(text, &valid).is_empty());

        // No evidence at all — also rejected.
        let text = r#"[{"title":"Fake finding","severity":"high","confidence":0.9,"target":"t","description":"d","evidence_ids":[]}]"#;
        assert!(Analyzer::parse_ai_findings(text, &valid).is_empty());
    }

    #[test]
    fn ai_parsing_tolerates_code_fences() {
        let mut valid = HashSet::new();
        valid.insert("ev-1".to_string());
        let text = "Here you go:\n```json\n[{\"title\":\"T\",\"severity\":\"low\",\"confidence\":0.5,\"target\":\"t\",\"description\":\"d\",\"evidence_ids\":[\"ev-1\"]}]\n```";
        let findings = Analyzer::parse_ai_findings(text, &valid);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn invalid_ai_input_yields_nothing() {
        let mut valid = HashSet::new();
        valid.insert("ev-1".to_string());
        assert!(Analyzer::parse_ai_findings("not json at all", &valid).is_empty());
        assert!(Analyzer::parse_ai_findings("{}", &valid).is_empty());
    }

    #[test]
    fn store_records_and_persists() {
        let ws = std::env::temp_dir().join(format!("anajakkh-find-{}", Uuid::new_v4()));
        let store = FindingStore::new(ws.clone());
        let finding = Finding::observed(
            "SSH service exposed",
            Severity::Low,
            "10.0.0.1",
            "port 22 open",
            None,
            vec!["ev-1".to_string()],
        );
        store.record("session-1", finding.clone()).unwrap();

        assert_eq!(store.len(), 1);
        assert_eq!(store.by_severity(Severity::Low).len(), 1);
        assert_eq!(store.for_target("10.0.0.1").len(), 1);
        assert!(store.find(&finding.id).is_some());

        let file = ws
            .join("findings")
            .join("session-1")
            .join(format!("{}.json", finding.id));
        assert!(file.exists());
        let back: Finding = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        assert_eq!(back.title, finding.title);
        assert_eq!(back.severity, finding.severity);

        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn in_memory_store_works() {
        let store = FindingStore::in_memory();
        assert!(store.is_empty());
        store
            .record(
                "s1",
                Finding::observed("x", Severity::High, "t", "d", None, vec!["e".to_string()]),
            )
            .unwrap();
        assert_eq!(store.len(), 1);
    }
}
