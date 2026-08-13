//! Plugin-style Tool Registry.
//!
//! Tools register themselves with metadata; the executor routes agent
//! steps to tools through this registry, so new tools can be added
//! without modifying the agent core.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Risk level of a tool, used for approval policy decisions.
///
/// Ordering is significant: `High`/`Critical` require explicit approval
/// under the default policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }
}

/// Static metadata describing a tool.
#[derive(Debug, Clone)]
pub struct ToolMetadata {
    pub name: &'static str,
    pub description: &'static str,
    pub risk_level: RiskLevel,
    pub required_scope: bool,
    pub input_schema: Value,
    pub output_schema: Value,
}

/// Context passed to a tool when executed.
#[derive(Debug, Clone)]
pub struct ToolContext {
    pub args: Value,
    pub scope_id: Option<String>,
    /// Primary target as a display string (IP, domain, or CIDR).
    pub target: Option<String>,
    /// Workspace directory the tool may operate within.
    pub workspace: Option<std::path::PathBuf>,
}

/// Structured result of a tool execution.
#[derive(Debug, Clone)]
pub struct ToolResult {
    pub success: bool,
    pub summary: String,
    pub raw_output: String,
    pub exit_code: Option<i32>,
    /// Structured, machine-readable result. Evidence collection prefers
    /// this over re-parsing `raw_output` when present.
    pub data: Value,
}

/// Interface every security tool implements.
#[async_trait]
pub trait SecurityTool: Send + Sync {
    fn metadata(&self) -> &ToolMetadata;

    async fn execute(&self, context: ToolContext) -> anyhow::Result<ToolResult>;
}

/// Registry mapping tool names to implementations.
#[derive(Default)]
pub struct ToolRegistry {
    tools: HashMap<String, Arc<dyn SecurityTool>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, tool: Arc<dyn SecurityTool>) {
        let name = tool.metadata().name.to_string();
        self.tools.insert(name, tool);
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn SecurityTool>> {
        self.tools.get(name).cloned()
    }

    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.tools.keys().cloned().collect();
        names.sort();
        names
    }

    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    pub fn len(&self) -> usize {
        self.tools.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeTool;

    #[async_trait]
    impl SecurityTool for FakeTool {
        fn metadata(&self) -> &ToolMetadata {
            &ToolMetadata {
                name: "fake",
                description: "fake tool",
                risk_level: RiskLevel::Low,
                required_scope: false,
                input_schema: Value::Null,
                output_schema: Value::Null,
            }
        }

        async fn execute(&self, _ctx: ToolContext) -> anyhow::Result<ToolResult> {
            Ok(ToolResult {
                success: true,
                summary: "ok".to_string(),
                raw_output: String::new(),
                exit_code: Some(0),
                data: Value::Null,
            })
        }
    }

    #[tokio::test]
    async fn register_and_lookup() {
        let mut registry = ToolRegistry::new();
        assert!(registry.is_empty());
        registry.register(Arc::new(FakeTool));
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.names(), vec!["fake".to_string()]);
        let tool = registry.get("fake").expect("tool registered");
        let result = tool
            .execute(ToolContext {
                args: Value::Null,
                scope_id: None,
                target: None,
                workspace: None,
            })
            .await
            .unwrap();
        assert!(result.success);
        assert!(registry.get("nmap").is_none());
    }
}
