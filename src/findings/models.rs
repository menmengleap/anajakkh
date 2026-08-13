//! Finding model.
//!
//! A finding is a normalized, evidence-referenced conclusion about the
//! assessed targets. The [`FindingSource`] keeps the three epistemic
//! categories separate:
//! - `Observed` — directly grounded in collected evidence;
//! - `Inferred` — AI reasoning over evidence;
//! - `Hypothesis` — a testable guess, never stated as fact.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::severity::Severity;

/// Epistemic category of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSource {
    /// Directly grounded in collected evidence.
    Observed,
    /// AI reasoning over the collected evidence.
    Inferred,
    /// A hypothesis that needs confirmation.
    Hypothesis,
}

impl FindingSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            FindingSource::Observed => "observed",
            FindingSource::Inferred => "inferred",
            FindingSource::Hypothesis => "hypothesis",
        }
    }
}

/// A normalized security finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    /// 0.0 – 1.0. Values outside this range are clamped on construction.
    pub confidence: f32,
    pub target: String,
    pub description: String,
    pub recommendation: Option<String>,
    /// Evidence records this finding is grounded in. Never empty; findings
    /// must reference evidence.
    pub evidence_ids: Vec<String>,
    /// Whether this is observed, inferred, or a hypothesis.
    pub source: FindingSource,
    /// Optional category, e.g. `exposed_service`, `misconfiguration`.
    pub category: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl Finding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        title: impl Into<String>,
        severity: Severity,
        confidence: f32,
        target: impl Into<String>,
        description: impl Into<String>,
        recommendation: Option<String>,
        evidence_ids: Vec<String>,
        source: FindingSource,
        category: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            title: title.into(),
            severity,
            confidence: confidence.clamp(0.0, 1.0),
            target: target.into(),
            description: description.into(),
            recommendation,
            evidence_ids,
            source,
            category,
            created_at: Utc::now(),
        }
    }

    /// Convenience constructor for observed, evidence-grounded findings.
    pub fn observed(
        title: impl Into<String>,
        severity: Severity,
        target: impl Into<String>,
        description: impl Into<String>,
        recommendation: Option<String>,
        evidence_ids: Vec<String>,
    ) -> Self {
        Self::new(
            title,
            severity,
            1.0,
            target,
            description,
            recommendation,
            evidence_ids,
            FindingSource::Observed,
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_roundtrip() {
        let finding = Finding::observed(
            "SSH service exposed",
            Severity::Low,
            "10.0.0.1",
            "Port 22 accepts SSH connections",
            Some("Enforce key-based authentication".to_string()),
            vec!["ev-1".to_string()],
        );
        let json = serde_json::to_string(&finding).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, finding.id);
        assert_eq!(back.severity, Severity::Low);
        assert_eq!(back.source, FindingSource::Observed);
        assert_eq!(back.evidence_ids, vec!["ev-1".to_string()]);
    }

    #[test]
    fn confidence_is_clamped() {
        let finding = Finding::new(
            "x",
            Severity::Medium,
            1.7,
            "t",
            "d",
            None,
            vec!["ev-1".to_string()],
            FindingSource::Inferred,
            None,
        );
        assert_eq!(finding.confidence, 1.0);

        let finding = Finding::new(
            "x",
            Severity::Medium,
            -0.5,
            "t",
            "d",
            None,
            vec!["ev-1".to_string()],
            FindingSource::Inferred,
            None,
        );
        assert_eq!(finding.confidence, 0.0);
    }

    #[test]
    fn source_names_are_lowercase() {
        assert_eq!(FindingSource::Observed.as_str(), "observed");
        assert_eq!(FindingSource::Inferred.as_str(), "inferred");
        assert_eq!(FindingSource::Hypothesis.as_str(), "hypothesis");
        assert_eq!(
            serde_json::to_string(&FindingSource::Hypothesis).unwrap(),
            "\"hypothesis\""
        );
    }
}
