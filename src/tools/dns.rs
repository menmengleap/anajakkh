//! DNS tool: resolve in-scope hostnames to addresses.
//!
//! Uses `tokio::net::lookup_host` (the OS resolver) — no external binary
//! required, and no shell involved.

use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::security::Target;

use super::registry::{RiskLevel, SecurityTool, ToolContext, ToolMetadata, ToolResult};

const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

pub struct DnsTool {
    meta: ToolMetadata,
}

impl DnsTool {
    pub fn new() -> Self {
        Self {
            meta: ToolMetadata {
                name: "dns",
                description: "Resolve hostnames to IP addresses (A/AAAA)",
                risk_level: RiskLevel::Low,
                required_scope: true,
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "target": { "type": "string", "description": "hostname to resolve" }
                    },
                    "required": ["target"]
                }),
                output_schema: json!({
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "addresses": { "type": "array", "items": { "type": "string" } }
                    }
                }),
            },
        }
    }
}

impl Default for DnsTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecurityTool for DnsTool {
    fn metadata(&self) -> &ToolMetadata {
        &self.meta
    }

    async fn execute(&self, ctx: ToolContext) -> anyhow::Result<ToolResult> {
        let target = ctx
            .target
            .ok_or_else(|| anyhow::anyhow!("dns requires a target"))?;
        let parsed = Target::parse(&target)?;

        match parsed {
            Target::Ip(ip) => Ok(ToolResult {
                success: true,
                summary: format!("{ip} is an IP address — no hostname resolution needed"),
                raw_output: format!("target {ip} is already an IP address\n"),
                exit_code: Some(0),
                data: json!({ "name": target, "addresses": [], "note": "ip target" }),
            }),
            Target::Cidr { network, prefix } => Ok(ToolResult {
                success: true,
                summary: format!(
                    "{network}/{prefix} is a network range — use nmap for host discovery"
                ),
                raw_output: format!(
                    "target {network}/{prefix} is a network range; host discovery is performed by nmap\n"
                ),
                exit_code: Some(0),
                data: json!({ "name": target, "addresses": [], "note": "cidr target" }),
            }),
            Target::Domain(domain) => {
                match tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((domain.as_str(), 0)))
                    .await
                {
                    Ok(Ok(addresses)) => {
                        let mut resolved: Vec<String> = addresses
                            .map(|addr| addr.ip().to_string())
                            .collect();
                        resolved.sort();
                        resolved.dedup();
                        if resolved.is_empty() {
                            Ok(ToolResult {
                                success: true,
                                summary: format!("no DNS records found for {domain}"),
                                raw_output: format!("no DNS records found for {domain}\n"),
                                exit_code: Some(0),
                                data: json!({ "name": domain, "addresses": [] }),
                            })
                        } else {
                            Ok(ToolResult {
                                success: true,
                                summary: format!(
                                    "resolved {} address(es) for {domain}",
                                    resolved.len()
                                ),
                                raw_output: resolved
                                    .iter()
                                    .map(|a| format!("{domain} → {a}"))
                                    .collect::<Vec<_>>()
                                    .join("\n")
                                    + "\n",
                                exit_code: Some(0),
                                data: json!({ "name": domain, "addresses": resolved }),
                            })
                        }
                    }
                    Ok(Err(err)) => Ok(ToolResult {
                        success: false,
                        summary: format!("DNS resolution failed for {domain}: {err}"),
                        raw_output: format!("DNS resolution failed for {domain}: {err}\n"),
                        exit_code: None,
                        data: Value::Null,
                    }),
                    Err(_) => Ok(ToolResult {
                        success: false,
                        summary: format!("DNS resolution timed out for {domain}"),
                        raw_output: format!("DNS resolution timed out after {}s\n", RESOLVE_TIMEOUT.as_secs()),
                        exit_code: None,
                        data: Value::Null,
                    }),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(target: &str) -> ToolContext {
        ToolContext {
            args: Value::Null,
            scope_id: None,
            target: Some(target.to_string()),
            workspace: None,
        }
    }

    #[tokio::test]
    async fn ip_target_needs_no_resolution() {
        let tool = DnsTool::new();
        let result = tool.execute(context("10.0.0.1")).await.unwrap();
        assert!(result.success);
        assert!(result.summary.contains("IP address"));
    }

    #[tokio::test]
    async fn cidr_target_delegates_to_nmap() {
        let tool = DnsTool::new();
        let result = tool.execute(context("10.0.0.0/24")).await.unwrap();
        assert!(result.success);
        assert!(result.summary.contains("network range"));
    }

    #[tokio::test]
    async fn missing_target_is_an_error() {
        let tool = DnsTool::new();
        let result = tool.execute(context("")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn metadata_is_sane() {
        let tool = DnsTool::new();
        assert_eq!(tool.metadata().name, "dns");
        assert_eq!(tool.metadata().risk_level, RiskLevel::Low);
        assert!(tool.metadata().required_scope);
    }
}
