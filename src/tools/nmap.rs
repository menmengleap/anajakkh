//! Nmap tool: enumerate open ports and services on in-scope targets.
//!
//! Wraps the `nmap` binary through the safe process runner (typed args,
//! timeout, output caps). Parsed host/service counts come from the
//! evidence parser; full structured evidence is produced there too.

use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::evidence::parser::nmap_counts;

use super::process::{self, CommandSpec};
use super::registry::{RiskLevel, SecurityTool, ToolContext, ToolMetadata, ToolResult};

const DEFAULT_PORTS: &str = "22,80,443,8080";
const SCAN_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_OUTPUT_BYTES: usize = 1 << 20;

pub struct NmapTool {
    meta: ToolMetadata,
}

impl NmapTool {
    pub fn new() -> Self {
        Self {
            meta: ToolMetadata {
                name: "nmap",
                description: "Enumerate open ports and service versions on in-scope targets",
                risk_level: RiskLevel::Medium,
                required_scope: true,
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "target": { "type": "string" },
                        "ports": { "type": "string", "description": "port list, e.g. 22,80,443" }
                    },
                    "required": ["target"]
                }),
                output_schema: json!({
                    "type": "object",
                    "properties": {
                        "hosts": { "type": "array" },
                        "services": { "type": "array" }
                    }
                }),
            },
        }
    }
}

impl Default for NmapTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecurityTool for NmapTool {
    fn metadata(&self) -> &ToolMetadata {
        &self.meta
    }

    async fn execute(&self, ctx: ToolContext) -> anyhow::Result<ToolResult> {
        let target = ctx
            .target
            .ok_or_else(|| anyhow::anyhow!("nmap requires a target"))?;
        let ports = ctx
            .args
            .get("ports")
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_PORTS);

        // -Pn: skip host discovery (the scope already authorizes the host);
        // -oG -: grepable output on stdout for parsing.
        let spec = CommandSpec {
            program: "nmap",
            args: vec![
                "-Pn".to_string(),
                "-oG".to_string(),
                "-".to_string(),
                "-p".to_string(),
                ports.to_string(),
                target.clone(),
            ],
            timeout: SCAN_TIMEOUT,
            max_output_bytes: MAX_OUTPUT_BYTES,
        };

        let output = match process::run(spec).await {
            Ok(output) => output,
            Err(err) if err.is_not_found() => {
                return Ok(ToolResult {
                    success: false,
                    summary: format!(
                        "{} executable was not found — install nmap and run `anajakkh doctor`",
                        err.program()
                    ),
                    raw_output: err.to_string(),
                    exit_code: None,
                    data: Value::Null,
                });
            }
            Err(err) => {
                return Ok(ToolResult {
                    success: false,
                    summary: format!("failed to run {}: {err}", err.program()),
                    raw_output: err.to_string(),
                    exit_code: None,
                    data: Value::Null,
                });
            }
        };

        if output.timed_out {
            return Ok(ToolResult {
                success: false,
                summary: format!("nmap timed out after {}s", SCAN_TIMEOUT.as_secs()),
                raw_output: output.stderr,
                exit_code: None,
                data: Value::Null,
            });
        }

        let raw = format!("{}{}", output.stdout, output.stderr);
        let (hosts, services) = nmap_counts(&raw);

        let success = output.exit_code == Some(0);
        let summary = if success {
            format!("{hosts} host(s), {services} service(s) on {target}")
        } else {
            format!("nmap exited with code {:?}", output.exit_code)
        };

        Ok(ToolResult {
            success,
            summary,
            raw_output: raw,
            exit_code: output.exit_code,
            data: Value::Null, // structured evidence is parsed from raw output
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_target_is_an_error() {
        let tool = NmapTool::new();
        let result = tool
            .execute(ToolContext {
                args: Value::Null,
                scope_id: None,
                target: None,
                workspace: None,
            })
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn metadata_is_sane() {
        let tool = NmapTool::new();
        assert_eq!(tool.metadata().name, "nmap");
        assert_eq!(tool.metadata().risk_level, RiskLevel::Medium);
        assert!(tool.metadata().required_scope);
    }
}
