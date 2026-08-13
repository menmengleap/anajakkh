//! Report generation: Markdown, JSON, and HTML from findings + evidence.
//!
//! A [`Report`] is a self-contained snapshot of an assessment session —
//! scope, targets, run summary, findings, and evidence — rendered by the
//! format-specific modules and written under `<workspace>/reports/`.

pub mod html;
pub mod json;
pub mod markdown;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

use crate::agent::SessionSummary;
use crate::evidence::{Evidence, EvidenceStore};
use crate::findings::{Finding, FindingStore};
use crate::security::Scope;
use crate::storage::SessionRecord;

/// A complete, serializable assessment report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Report {
    pub title: String,
    pub session_id: String,
    pub generated_at: DateTime<Utc>,
    pub workspace: PathBuf,
    pub scope: Option<Scope>,
    pub targets: Vec<String>,
    pub summary: Option<SessionSummary>,
    pub evidence: Vec<Evidence>,
    pub findings: Vec<Finding>,
}

impl Report {
    /// Build a report directly from in-memory state (agent pipeline).
    pub fn new(
        session_id: impl Into<String>,
        workspace: PathBuf,
        scope: Option<Scope>,
        targets: Vec<String>,
        summary: Option<SessionSummary>,
        evidence: Vec<Evidence>,
        findings: Vec<Finding>,
    ) -> Self {
        let session_id = session_id.into();
        Self {
            title: format!("ANAJAKKH Assessment — {session_id}"),
            session_id: session_id.clone(),
            generated_at: Utc::now(),
            workspace,
            scope,
            targets,
            summary,
            evidence,
            findings,
        }
    }

    /// Build a report for a persisted session, loading its evidence and
    /// findings from disk (CLI `anajakkh report`).
    pub fn from_record(record: &SessionRecord) -> Result<Self> {
        let evidence_store = EvidenceStore::new(record.workspace.clone());
        evidence_store
            .load(&record.id)
            .context("loading evidence")?;
        let findings_store = FindingStore::new(record.workspace.clone());
        findings_store
            .load(&record.id)
            .context("loading findings")?;

        let targets = record
            .scope
            .as_ref()
            .map(|s| s.targets.iter().map(|t| t.display()).collect())
            .or_else(|| record.summary.as_ref().map(|s| s.targets.clone()))
            .unwrap_or_default();

        Ok(Report::new(
            &record.id,
            record.workspace.clone(),
            record.scope.clone(),
            targets,
            record.summary.clone(),
            evidence_store.all(),
            findings_store.all(),
        ))
    }

    /// Severity breakdown for summaries: `{"critical": n, ...}`.
    pub fn severity_counts(&self) -> Vec<(crate::findings::Severity, usize)> {
        use crate::findings::Severity;
        let order = [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Informational,
        ];
        order
            .into_iter()
            .map(|sev| {
                (
                    sev,
                    self.findings.iter().filter(|f| f.severity == sev).count(),
                )
            })
            .collect()
    }
}

/// Write every format for `report`, returning the created file paths.
/// Files are named `<session_id>-<timestamp>.<ext>` under `workspace/reports/`.
pub fn write_all(workspace: &Path, session_id: &str, report: &Report) -> Result<Vec<PathBuf>> {
    let dir = workspace.join("reports");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating reports directory {}", dir.display()))?;

    let stamp = report.generated_at.format("%Y%m%d-%H%M%S");
    let base = dir.join(format!("{session_id}-{stamp}"));

    let mut paths = Vec::new();
    let md_path = base.with_extension("md");
    std::fs::write(&md_path, markdown::render(report))
        .with_context(|| format!("writing {}", md_path.display()))?;
    paths.push(md_path);

    let json_path = base.with_extension("json");
    std::fs::write(&json_path, json::render(report)?)
        .with_context(|| format!("writing {}", json_path.display()))?;
    paths.push(json_path);

    let html_path = base.with_extension("html");
    std::fs::write(&html_path, html::render(report))
        .with_context(|| format!("writing {}", html_path.display()))?;
    paths.push(html_path);

    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Finding, Severity};
    use uuid::Uuid;

    fn sample_report() -> Report {
        let finding = Finding::observed(
            "Telnet service exposed",
            Severity::High,
            "10.0.0.1",
            "Port 23 accepts cleartext telnet",
            Some("Disable telnet; use SSH".to_string()),
            vec!["ev-1".to_string()],
        );
        let evidence = Evidence::new(
            crate::evidence::EvidenceType::Service,
            "nmap",
            "10.0.0.1",
            serde_json::json!({"port": 23, "state": "open", "protocol": "tcp", "service": "telnet"}),
        );
        Report::new(
            "sess-test",
            PathBuf::from("/tmp/ws"),
            Scope::parse("s", "10.0.0.0/8").ok(),
            vec!["10.0.0.1".to_string()],
            None,
            vec![evidence],
            vec![finding],
        )
    }

    #[test]
    fn severity_counts_are_accurate() {
        let report = sample_report();
        let counts = report.severity_counts();
        assert_eq!(
            counts.iter().find(|(s, _)| *s == Severity::High).unwrap().1,
            1
        );
        assert_eq!(
            counts
                .iter()
                .find(|(s, _)| *s == Severity::Critical)
                .unwrap()
                .1,
            0
        );
    }

    #[test]
    fn from_record_loads_evidence_and_findings() {
        let ws = std::env::temp_dir().join(format!("anajakkh-rep-{}", Uuid::new_v4()));
        let evidence = Evidence::new(
            crate::evidence::EvidenceType::HttpResponse,
            "http",
            "example.com",
            serde_json::json!({"status": 200}),
        );
        let finding = Finding::observed(
            "HTTP service exposed",
            Severity::Informational,
            "example.com",
            "observed",
            None,
            vec![evidence.id.clone()],
        );
        let evidence_store = EvidenceStore::new(ws.clone());
        evidence_store.record("s1", evidence.clone()).unwrap();
        let findings_store = FindingStore::new(ws.clone());
        findings_store.record("s1", finding.clone()).unwrap();

        let mut record = SessionRecord::new("s1", ws.clone());
        record.scope = Scope::parse("s", "example.com").ok();
        let report = Report::from_record(&record).unwrap();
        assert_eq!(report.evidence.len(), 1);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].evidence_ids, vec![evidence.id]);
        assert_eq!(report.targets, vec!["example.com".to_string()]);

        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn write_all_creates_three_files() {
        let ws = std::env::temp_dir().join(format!("anajakkh-rep-w-{}", Uuid::new_v4()));
        let report = sample_report();
        let paths = write_all(&ws, "sess-w", &report).unwrap();
        assert_eq!(paths.len(), 3);
        for path in &paths {
            assert!(path.exists(), "{} should exist", path.display());
        }
        let _ = std::fs::remove_dir_all(&ws);
    }
}
