//! Decision layer: policy evaluation for plan steps.
//!
//! In Phase 2 this provides the authorization gate: tool steps require
//! an authorized scope. Later phases add approvals for dangerous actions.

use crate::security::Scope;

use super::planner::PlanStep;

/// Outcome of evaluating a step against policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The step may proceed.
    Proceed,
    /// The step requires scope/authorization that is not present.
    NeedsApproval(String),
    /// The step is blocked (out of scope or policy violation).
    Blocked(String),
}

/// Evaluate whether `step` may run under `scope`.
pub fn evaluate(step: &PlanStep, scope: Option<&Scope>) -> Decision {
    if let Some(tool) = &step.requires_tool {
        match scope {
            None => Decision::NeedsApproval(format!(
                "`{}` requires an authorized scope. Press Ctrl+S to define one.",
                tool
            )),
            Some(scope) if !scope.authorized => {
                Decision::Blocked("scope is not authorized".to_string())
            }
            Some(_) => Decision::Proceed,
        }
    } else {
        Decision::Proceed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::RiskLevel;

    fn step(action: &str, tool: Option<&str>) -> PlanStep {
        PlanStep {
            id: 1,
            action: action.to_string(),
            description: action.to_string(),
            requires_tool: tool.map(|t| t.to_string()),
            risk: RiskLevel::Low,
        }
    }

    #[test]
    fn tool_step_without_scope_needs_approval() {
        let s = step("service_enumeration", Some("nmap"));
        match evaluate(&s, None) {
            Decision::NeedsApproval(msg) => assert!(msg.contains("nmap")),
            other => panic!("expected NeedsApproval, got {other:?}"),
        }
    }

    #[test]
    fn tool_step_with_scope_proceeds() {
        let s = step("service_enumeration", Some("nmap"));
        let scope = crate::security::Scope::parse("s1", "10.0.0.0/8").unwrap();
        assert_eq!(evaluate(&s, Some(&scope)), Decision::Proceed);
    }

    #[test]
    fn non_tool_step_proceeds_without_scope() {
        let s = step("parse_task", None);
        assert_eq!(evaluate(&s, None), Decision::Proceed);
    }

    #[test]
    fn unauthorized_scope_blocks() {
        let s = step("service_enumeration", Some("nmap"));
        let mut scope = crate::security::Scope::parse("s1", "10.0.0.0/8").unwrap();
        scope.authorized = false;
        assert_eq!(
            evaluate(&s, Some(&scope)),
            Decision::Blocked("scope is not authorized".to_string())
        );
    }
}
