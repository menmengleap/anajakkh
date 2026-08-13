//! Approval system: explicit human sign-off for dangerous operations.
//!
//! When policy marks an operation as requiring approval, the executor
//! consults this system. An operation only runs if a matching request
//! was explicitly approved by an operator. Requests are immutable once
//! decided.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

use crate::tools::RiskLevel;

/// Lifecycle of an approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

/// A single approval request for a dangerous operation.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub id: String,
    /// Machine-readable operation key, e.g. `tool:nmap`.
    pub operation: String,
    /// Human-readable operation name (tool name, action, ...).
    pub label: String,
    pub risk: RiskLevel,
    pub reason: String,
    pub status: ApprovalStatus,
    pub requested_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
    pub decided_by: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApprovalError {
    #[error("approval request `{0}` not found")]
    NotFound(String),
    #[error("approval request `{0}` was already decided")]
    AlreadyDecided(String),
}

/// Thread-safe store of approval requests. Decisions are final.
#[derive(Debug, Default, Clone)]
pub struct ApprovalSystem {
    requests: HashMap<String, ApprovalRequest>,
}

impl ApprovalSystem {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a pending approval request.
    pub fn request(
        &mut self,
        operation: impl Into<String>,
        label: impl Into<String>,
        risk: RiskLevel,
        reason: impl Into<String>,
    ) -> ApprovalRequest {
        let request = ApprovalRequest {
            id: Uuid::new_v4().to_string(),
            operation: operation.into(),
            label: label.into(),
            risk,
            reason: reason.into(),
            status: ApprovalStatus::Pending,
            requested_at: Utc::now(),
            decided_at: None,
            decided_by: None,
        };
        self.requests.insert(request.id.clone(), request.clone());
        request
    }

    /// Approve a pending request, recording who decided.
    pub fn approve(&mut self, id: &str, by: impl Into<String>) -> Result<(), ApprovalError> {
        self.decide(id, by, ApprovalStatus::Approved)
    }

    /// Deny a pending request, recording who decided.
    pub fn deny(&mut self, id: &str, by: impl Into<String>) -> Result<(), ApprovalError> {
        self.decide(id, by, ApprovalStatus::Denied)
    }

    fn decide(
        &mut self,
        id: &str,
        by: impl Into<String>,
        status: ApprovalStatus,
    ) -> Result<(), ApprovalError> {
        let request = self
            .requests
            .get_mut(id)
            .ok_or_else(|| ApprovalError::NotFound(id.to_string()))?;
        if request.status != ApprovalStatus::Pending {
            return Err(ApprovalError::AlreadyDecided(id.to_string()));
        }
        request.status = status;
        request.decided_at = Some(Utc::now());
        request.decided_by = Some(by.into());
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&ApprovalRequest> {
        self.requests.get(id)
    }

    /// Pending requests, newest first.
    pub fn pending(&self) -> Vec<&ApprovalRequest> {
        let mut pending: Vec<&ApprovalRequest> = self
            .requests
            .values()
            .filter(|r| r.status == ApprovalStatus::Pending)
            .collect();
        pending.sort_by_key(|b| std::cmp::Reverse(b.requested_at));
        pending
    }

    /// Is there an *approved* request for this operation?
    pub fn is_approved(&self, operation: &str) -> bool {
        self.requests
            .values()
            .any(|r| r.operation == operation && r.status == ApprovalStatus::Approved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_approve_deny_flow() {
        let mut system = ApprovalSystem::new();
        let req = system.request(
            "tool:nmap",
            "nmap",
            RiskLevel::Medium,
            "authorized assessment",
        );
        assert_eq!(req.status, ApprovalStatus::Pending);
        assert_eq!(system.pending().len(), 1);

        system.approve(&req.id, "operator").unwrap();
        assert!(system.is_approved("tool:nmap"));
        assert_eq!(system.pending().len(), 0);
        assert_eq!(
            system.get(&req.id).unwrap().decided_by.as_deref(),
            Some("operator")
        );
    }

    #[test]
    fn denied_requests_do_not_authorize() {
        let mut system = ApprovalSystem::new();
        let req = system.request("tool:wipe", "wipe", RiskLevel::Critical, "cleanup");
        system.deny(&req.id, "operator").unwrap();
        assert!(!system.is_approved("tool:wipe"));
    }

    #[test]
    fn double_decision_is_rejected() {
        let mut system = ApprovalSystem::new();
        let req = system.request("tool:nmap", "nmap", RiskLevel::Medium, "ok");
        system.approve(&req.id, "a").unwrap();
        assert_eq!(
            system.deny(&req.id, "b"),
            Err(ApprovalError::AlreadyDecided(req.id.clone()))
        );
    }

    #[test]
    fn unknown_request_is_not_found() {
        let mut system = ApprovalSystem::new();
        assert_eq!(
            system.approve("missing", "operator"),
            Err(ApprovalError::NotFound("missing".to_string()))
        );
    }

    #[test]
    fn approval_matches_operation_key() {
        let mut system = ApprovalSystem::new();
        let req = system.request("tool:nmap", "nmap", RiskLevel::Medium, "ok");
        system.approve(&req.id, "operator").unwrap();
        assert!(system.is_approved("tool:nmap"));
        assert!(!system.is_approved("tool:http"));
    }
}
