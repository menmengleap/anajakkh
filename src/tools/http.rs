//! HTTP tool: inspect an in-scope web service.
//!
//! Captures status, selected response headers, and the page title.
//! Responses are size-capped; no credentials or cookies are ever sent.

use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use serde_json::{json, Value};

use super::registry::{RiskLevel, SecurityTool, ToolContext, ToolMetadata, ToolResult};

const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
/// Maximum response body bytes read for inspection.
const MAX_BODY_BYTES: usize = 64 * 1024;
/// Maximum title length kept in structured output.
const MAX_TITLE_CHARS: usize = 120;

pub struct HttpTool {
    meta: ToolMetadata,
}

impl HttpTool {
    pub fn new() -> Self {
        Self {
            meta: ToolMetadata {
                name: "http",
                description: "Inspect an HTTP(S) service: status, headers, title",
                risk_level: RiskLevel::Medium,
                required_scope: true,
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "target": { "type": "string" },
                        "scheme": { "type": "string", "enum": ["http", "https"], "default": "http" },
                        "path": { "type": "string", "default": "/" }
                    },
                    "required": ["target"]
                }),
                output_schema: json!({
                    "type": "object",
                    "properties": {
                        "url": { "type": "string" },
                        "status": { "type": "integer" },
                        "server": { "type": "string" },
                        "content_type": { "type": "string" },
                        "title": { "type": "string" }
                    }
                }),
            },
        }
    }
}

impl Default for HttpTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecurityTool for HttpTool {
    fn metadata(&self) -> &ToolMetadata {
        &self.meta
    }

    async fn execute(&self, ctx: ToolContext) -> anyhow::Result<ToolResult> {
        let target = ctx
            .target
            .ok_or_else(|| anyhow::anyhow!("http requires a target"))?;
        let scheme = ctx
            .args
            .get("scheme")
            .and_then(Value::as_str)
            .unwrap_or("http");
        let path = ctx.args.get("path").and_then(Value::as_str).unwrap_or("/");
        let url = format!("{scheme}://{target}{path}");

        let client = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()?;

        let response = match client.get(&url).send().await {
            Ok(response) => response,
            Err(err) => {
                return Ok(ToolResult {
                    success: false,
                    summary: format!("connection to {target} failed: {err}"),
                    raw_output: format!("GET {url} failed: {err}\n"),
                    exit_code: None,
                    data: Value::Null,
                });
            }
        };

        let status = response.status().as_u16();
        let server = response
            .headers()
            .get(reqwest::header::SERVER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        // Collect headers before consuming the response body stream.
        let headers: Value = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.as_str().to_string(), v.to_string()))
            })
            .collect();

        // Read a capped body for title extraction.
        let mut body = Vec::new();
        let mut truncated = false;
        let mut body_stream = response.bytes_stream();
        while let Some(chunk) = body_stream.next().await {
            match chunk {
                Ok(bytes) => {
                    body.extend_from_slice(&bytes);
                    if body.len() > MAX_BODY_BYTES {
                        truncated = true;
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let body_text = String::from_utf8_lossy(&body).into_owned();
        let title = extract_title(&body_text).unwrap_or_default();

        let data = json!({
            "url": url,
            "status": status,
            "server": server,
            "content_type": content_type,
            "title": title,
            "headers": headers,
        });

        let raw_output = format!(
            "GET {url}\nstatus: {status}\nserver: {server}\ncontent-type: {content_type}\ntitle: {title}\n{}\n",
            if truncated { "[body truncated]".to_string() } else { String::new() }
        );

        Ok(ToolResult {
            success: true,
            summary: format!(
                "HTTP {status} · server {}{}",
                if server.is_empty() {
                    "—".to_string()
                } else {
                    server
                },
                if title.is_empty() {
                    String::new()
                } else {
                    format!(" · title \"{title}\"")
                }
            ),
            raw_output,
            exit_code: None,
            data,
        })
    }
}

/// Extract the `<title>` text from HTML, capped in length.
fn extract_title(html: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let open = lower.find("<title")?;
    let after_open = lower[open..].find('>')? + open + 1;
    let close = lower[after_open..].find("</title")? + after_open;
    let title = html[after_open..close].trim();
    if title.is_empty() {
        None
    } else {
        Some(title.chars().take(MAX_TITLE_CHARS).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_title_from_html() {
        let html = "<html><head><title>My Site — v2</title></head><body>hi</body></html>";
        assert_eq!(extract_title(html).as_deref(), Some("My Site — v2"));
    }

    #[test]
    fn no_title_means_none() {
        assert_eq!(extract_title("<html><body>hi</body></html>"), None);
    }

    #[test]
    fn title_is_case_insensitive() {
        let html = "<TITLE>UPPER</TITLE>";
        assert_eq!(extract_title(html).as_deref(), Some("UPPER"));
    }

    #[test]
    fn metadata_is_sane() {
        let tool = HttpTool::new();
        assert_eq!(tool.metadata().name, "http");
        assert_eq!(tool.metadata().risk_level, RiskLevel::Medium);
        assert!(tool.metadata().required_scope);
    }
}
