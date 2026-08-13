//! Policy: risk-based rules that gate tool execution.
//!
//! The policy layer sits on top of the scope/authorization gate. It
//! decides whether a tool may run unattended, requires explicit
//! approval, or must be denied outright.

use crate::tools::RiskLevel;

use super::approval::ApprovalSystem;

/// Outcome of evaluating an operation against policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The operation may run.
    Allow,
    /// The operation is dangerous and needs explicit approval.
    RequireApproval(String),
    /// The operation is denied by policy.
    Deny(String),
}

/// Configurable policy rules.
///
/// Defaults: operations at `High` risk or above require approval.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Operations at or above this risk require explicit approval.
    pub approval_threshold: RiskLevel,
    /// Tools may never run without a scope unless they opt out
    /// (`required_scope = false` in their metadata).
    pub require_scope: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            approval_threshold: RiskLevel::High,
            require_scope: true,
        }
    }
}

impl Policy {
    pub fn new(approval_threshold: RiskLevel) -> Self {
        Self {
            approval_threshold,
            require_scope: true,
        }
    }

    /// Evaluate a single tool operation.
    pub fn evaluate(&self, tool: &str, risk: RiskLevel) -> PolicyDecision {
        if risk >= self.approval_threshold {
            PolicyDecision::RequireApproval(format!(
                "`{tool}` is a {} risk operation and requires explicit approval",
                risk.as_str()
            ))
        } else {
            PolicyDecision::Allow
        }
    }

    /// Evaluate `tool`, consulting an approval system for already-approved
    /// operations. Returns `Allow` for approved operations.
    pub fn evaluate_with_approvals(
        &self,
        tool: &str,
        risk: RiskLevel,
        approvals: &ApprovalSystem,
    ) -> PolicyDecision {
        match self.evaluate(tool, risk) {
            PolicyDecision::RequireApproval(reason) => {
                let operation = format!("tool:{tool}");
                if approvals.is_approved(&operation) {
                    PolicyDecision::Allow
                } else {
                    PolicyDecision::RequireApproval(reason)
                }
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_and_medium_risk_are_allowed() {
        let policy = Policy::default();
        assert_eq!(
            policy.evaluate("dns", RiskLevel::Low),
            PolicyDecision::Allow
        );
        assert_eq!(
            policy.evaluate("nmap", RiskLevel::Medium),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn high_risk_requires_approval_by_default() {
        let policy = Policy::default();
        match policy.evaluate("exploit", RiskLevel::High) {
            PolicyDecision::RequireApproval(reason) => {
                assert!(reason.contains("exploit"));
                assert!(reason.contains("high"));
            }
            other => panic!("expected RequireApproval, got {other:?}"),
        }
    }

    #[test]
    fn critical_risk_requires_approval() {
        let policy = Policy::default();
        assert!(matches!(
            policy.evaluate("wipe", RiskLevel::Critical),
            PolicyDecision::RequireApproval(_)
        ));
    }

    #[test]
    fn threshold_is_configurable() {
        // Everything at Medium or above needs approval.
        let policy = Policy::new(RiskLevel::Medium);
        assert_eq!(
            policy.evaluate("nmap", RiskLevel::Medium),
            PolicyDecision::RequireApproval(
                "`nmap` is a medium risk operation and requires explicit approval".to_string()
            )
        );
        assert_eq!(
            policy.evaluate("dns", RiskLevel::Low),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn approved_operations_pass() {
        let policy = Policy::default();
        let mut approvals = ApprovalSystem::new();
        approvals.request(
            "tool:exploit",
            "exploit",
            RiskLevel::High,
            "authorized pentest",
        );
        let req_id = approvals.pending()[0].id.clone();
        approvals.approve(&req_id, "operator").unwrap();

        assert_eq!(
            policy.evaluate_with_approvals("exploit", RiskLevel::High, &approvals),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn unapproved_dangerous_operation_is_gated() {
        let policy = Policy::default();
        let approvals = ApprovalSystem::new();
        assert!(matches!(
            policy.evaluate_with_approvals("exploit", RiskLevel::High, &approvals),
            PolicyDecision::RequireApproval(_)
        ));
    }
}
