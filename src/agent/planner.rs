//! Planner: converts a user request into structured, scope-verified steps.

use serde::{Deserialize, Serialize};

use crate::security::{Scope, Target};
use crate::tools::RiskLevel;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanStep {
    pub id: u32,
    pub action: String,
    pub description: String,
    pub requires_tool: Option<String>,
    pub risk: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub goal: String,
    pub steps: Vec<PlanStep>,
    pub targets: Vec<Target>,
    pub out_of_scope: Vec<Target>,
}

#[derive(Clone)]
pub struct Planner;

impl Planner {
    pub fn new() -> Self {
        Self
    }

    /// Build a plan for `task` given the current authorized scope.
    ///
    /// The planner always verifies scope first: any targets detected in
    /// the task that fall outside the scope are recorded in
    /// `out_of_scope` and the plan is marked accordingly.
    pub fn plan(&self, task: &str, scope: Option<&Scope>) -> Plan {
        let goal = task.trim().to_string();
        let lower = goal.to_lowercase();
        let targets = Target::from_task(&goal);

        let out_of_scope = match &scope {
            Some(scope) => scope.out_of_scope(&targets),
            None => Vec::new(),
        };

        let wants_scan = [
            "scan",
            "assess",
            "enumerate",
            "discover",
            "recon",
            "probe",
            "fingerprint",
            "service",
            "port",
        ]
        .iter()
        .any(|k| lower.contains(k));
        let wants_http = ["http", "web", "website", "api", "headers"]
            .iter()
            .any(|k| lower.contains(k));
        let wants_filesystem = [
            "filesystem",
            "file inspection",
            "list files",
            "inspect files",
        ]
        .iter()
        .any(|k| lower.contains(k));
        let wants_report = ["report", "findings", "vulnerab", "analy", "evidence"]
            .iter()
            .any(|k| lower.contains(k));

        let mut steps: Vec<PlanStep> = Vec::new();
        let mut push = |action: &str, description: &str, tool: Option<&str>, risk: RiskLevel| {
            steps.push(PlanStep {
                id: steps.len() as u32 + 1,
                action: action.to_string(),
                description: description.to_string(),
                requires_tool: tool.map(|t| t.to_string()),
                risk,
            });
        };

        push(
            "parse_task",
            "Parse and interpret the requested task",
            None,
            RiskLevel::Low,
        );
        push(
            "validate_scope",
            "Validate targets against the authorized scope",
            None,
            RiskLevel::Low,
        );

        if wants_scan {
            push(
                "target_discovery",
                "Discover in-scope targets",
                Some("dns"),
                RiskLevel::Low,
            );
            push(
                "service_enumeration",
                "Enumerate services on targets",
                Some("nmap"),
                RiskLevel::Medium,
            );
        }
        if wants_http || wants_scan {
            push(
                "http_inspection",
                "Inspect exposed HTTP services",
                Some("http"),
                RiskLevel::Medium,
            );
        }
        if wants_filesystem {
            push(
                "filesystem_inspection",
                "Inspect files inside the workspace",
                Some("filesystem"),
                RiskLevel::Medium,
            );
        }
        if wants_report || wants_scan {
            push(
                "analyze",
                "Analyze collected evidence",
                None,
                RiskLevel::Low,
            );
        }
        if wants_report || wants_scan {
            push(
                "generate_findings",
                "Generate findings from collected evidence",
                None,
                RiskLevel::Low,
            );
        }
        if wants_report {
            push(
                "generate_report",
                "Generate a report from findings and evidence",
                None,
                RiskLevel::Low,
            );
        }
        push(
            "summarize",
            "Summarize the assessment",
            None,
            RiskLevel::Low,
        );

        Plan {
            goal,
            steps,
            targets,
            out_of_scope,
        }
    }
}

impl Default for Planner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_task_produces_tool_steps() {
        let plan = Planner::new().plan(
            "Scan example.com for open ports",
            Some(&Scope::parse("s1", "example.com").unwrap()),
        );
        assert!(plan.out_of_scope.is_empty());
        assert!(plan.steps.iter().any(|s| s.action == "validate_scope"));
        assert!(plan
            .steps
            .iter()
            .any(|s| s.requires_tool.as_deref() == Some("nmap")));
        assert!(plan.steps.iter().any(|s| s.action == "summarize"));
        assert!(plan.steps.first().unwrap().action == "parse_task");
    }

    #[test]
    fn detects_out_of_scope_target() {
        let plan = Planner::new().plan(
            "scan example.com and 192.168.1.5",
            Some(&Scope::parse("s1", "example.com").unwrap()),
        );
        assert_eq!(plan.out_of_scope.len(), 1);
        assert_eq!(plan.out_of_scope[0].display(), "192.168.1.5");
    }

    #[test]
    fn report_task_includes_findings() {
        let plan = Planner::new().plan(
            "Write a report of the assessment",
            Some(&Scope::parse("s1", "10.0.0.0/8").unwrap()),
        );
        assert!(plan.steps.iter().any(|s| s.action == "generate_findings"));
    }

    #[test]
    fn scan_task_also_generates_findings() {
        let plan = Planner::new().plan(
            "Scan example.com",
            Some(&Scope::parse("s1", "example.com").unwrap()),
        );
        assert!(plan.steps.iter().any(|s| s.action == "generate_findings"));
    }

    #[test]
    fn steps_are_sequentially_ided() {
        let plan = Planner::new().plan("assess", None);
        for (i, step) in plan.steps.iter().enumerate() {
            assert_eq!(step.id as usize, i + 1);
        }
    }
}
