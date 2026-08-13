//! Concrete AI providers.
//!
//! - [`OpenAiClient`]: talks to any OpenAI-compatible `/chat/completions`
//!   API (OpenAI, Ollama, LM Studio, vLLM, ...) with SSE streaming.
//! - [`EchoProvider`]: offline provider that streams back a structured
//!   response so the whole pipeline works without any API key.

use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use serde_json::{json, Value};

use crate::config::AiSettings;

use super::models::{AiRequest, AiResponse, AiRole, AiUsage};
use super::provider::{AiProvider, AiStream};

const DEFAULT_STREAM_CHUNK_DELAY: Duration = Duration::from_millis(15);

pub struct OpenAiClient {
    base_url: String,
    api_key: String,
    model: String,
    client: reqwest::Client,
}

impl OpenAiClient {
    pub fn new(settings: &AiSettings, api_key: &str) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(settings.timeout_secs.max(10)))
            .build()?;
        Ok(Self {
            base_url: settings.base_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
            model: settings.model.clone(),
            client,
        })
    }

    fn build_body(&self, request: &AiRequest) -> Value {
        json!({
            "model": request.model,
            "messages": request
                .messages
                .iter()
                .map(|m| json!({
                    "role": match m.role {
                        AiRole::System => "system",
                        AiRole::User => "user",
                        AiRole::Assistant => "assistant",
                    },
                    "content": m.content,
                }))
                .collect::<Vec<_>>(),
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "stream": request.stream,
        })
    }

    async fn post(&self, request: &AiRequest) -> anyhow::Result<reqwest::Response> {
        let url = format!("{}/chat/completions", self.base_url);
        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(&self.build_body(request))
            .send()
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("AI provider error {status}: {}", truncate(&text, 300));
        }
        Ok(response)
    }
}

#[async_trait]
impl AiProvider for OpenAiClient {
    fn name(&self) -> &str {
        "openai"
    }

    fn model(&self) -> &str {
        &self.model
    }

    async fn chat(&self, request: AiRequest) -> anyhow::Result<AiResponse> {
        let mut request = request;
        request.stream = false;
        // Metadata only — never log message content or keys.
        tracing::info!(
            "ai request model={} messages={} prompt_chars={}",
            self.model,
            request.messages.len(),
            request
                .messages
                .iter()
                .map(|m| m.content.chars().count())
                .sum::<usize>()
        );
        let started = std::time::Instant::now();
        let response = self.post(&request).await?;
        let body: Value = response.json().await?;
        let content = body
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let usage = body
            .get("usage")
            .map(|u| AiUsage {
                prompt_tokens: u.get("prompt_tokens").and_then(Value::as_u64).unwrap_or(0) as u32,
                completion_tokens: u
                    .get("completion_tokens")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as u32,
                total_tokens: u.get("total_tokens").and_then(Value::as_u64).unwrap_or(0) as u32,
            })
            .unwrap_or_default();
        tracing::info!(
            "ai response model={} chars={} prompt_tokens={} completion_tokens={} total_tokens={} elapsed_ms={}",
            self.model,
            content.chars().count(),
            usage.prompt_tokens,
            usage.completion_tokens,
            usage.total_tokens,
            started.elapsed().as_millis()
        );
        Ok(AiResponse {
            content,
            model: self.model.clone(),
            usage,
        })
    }

    async fn stream_chat(&self, request: AiRequest) -> anyhow::Result<AiStream> {
        let mut request = request;
        request.stream = true;
        // Metadata only — never log message content or keys.
        tracing::info!(
            "ai stream request model={} messages={} prompt_chars={}",
            self.model,
            request.messages.len(),
            request
                .messages
                .iter()
                .map(|m| m.content.chars().count())
                .sum::<usize>()
        );
        let response = self.post(&request).await?;
        let byte_stream = response.bytes_stream();

        // State: the byte stream plus a buffer of unconsumed SSE text.
        let state = (byte_stream, String::new());
        Ok(Box::pin(futures_util::stream::unfold(
            state,
            |(mut stream, mut buffer)| async move {
                loop {
                    // Consume any complete content deltas already buffered.
                    if let Some(line) = take_line(&mut buffer) {
                        if line.trim() == "data: [DONE]" {
                            return None;
                        }
                        if let Some(content) = parse_sse_line(&line) {
                            return Some((Ok(content), (stream, buffer)));
                        }
                        continue;
                    }
                    match stream.next().await {
                        Some(Ok(bytes)) => {
                            buffer.push_str(&String::from_utf8_lossy(&bytes));
                        }
                        Some(Err(err)) => {
                            tracing::warn!("ai stream error: {err}");
                            return None;
                        }
                        None => {
                            // Stream closed: flush any remaining buffered content.
                            let leftover = buffer.trim();
                            if !leftover.is_empty() {
                                if let Some(content) = parse_sse_line(leftover) {
                                    return Some((Ok(content), (stream, String::new())));
                                }
                            }
                            return None;
                        }
                    }
                }
            },
        )))
    }
}

/// Extract the next complete line from a SSE buffer, if any.
fn take_line(buffer: &mut String) -> Option<String> {
    if let Some(pos) = buffer.find('\n') {
        let line = buffer[..pos].to_string();
        buffer.drain(..=pos);
        return Some(line);
    }
    None
}

/// Parse one SSE line; returns `None` when there is no content delta.
fn parse_sse_line(line: &str) -> Option<String> {
    let line = line.trim();
    if !line.starts_with("data:") {
        return None;
    }
    let data = line[5..].trim();
    if data.is_empty() || data == "[DONE]" {
        return None;
    }
    let parsed: Value = serde_json::from_str(data).ok()?;
    let delta = parsed
        .pointer("/choices/0/delta/content")
        .and_then(Value::as_str)?;
    if delta.is_empty() {
        None
    } else {
        Some(delta.to_string())
    }
}

/// Offline provider. Streams a deterministic structured response so the
/// entire agent pipeline can be exercised without network access.
pub struct EchoProvider {
    model: String,
}

impl EchoProvider {
    pub fn new(model: String) -> Self {
        Self { model }
    }

    fn response_text(&self, request: &AiRequest) -> String {
        let task = request
            .messages
            .iter()
            .rev()
            .find(|m| m.role == AiRole::User)
            .map(|m| m.content.clone())
            .unwrap_or_default();
        let task = truncate(&task, 200);

        format!(
            "Offline echo mode — no AI provider is configured (set OPENAI_API_KEY or provider=\"echo\").\n\n\
             I parsed your request: \"{task}\"\n\n\
             Planned pipeline:\n\
             - scope validation\n\
             - target discovery (dns)\n\
             - service enumeration (nmap)\n\
             - http inspection (http)\n\
             - evidence collection\n\
             - findings analysis\n\n\
             Tool results are collected as evidence under the workspace `evidence/` directory. Configure an API key to enable real AI analysis."
        )
    }

    fn chunks(text: &str) -> Vec<String> {
        text.split_inclusive([' ', '\n'])
            .map(|c| c.to_string())
            .collect()
    }
}

#[async_trait]
impl AiProvider for EchoProvider {
    fn name(&self) -> &str {
        "echo"
    }

    fn model(&self) -> &str {
        &self.model
    }

    async fn chat(&self, request: AiRequest) -> anyhow::Result<AiResponse> {
        let content = self.response_text(&request);
        Ok(AiResponse {
            content,
            model: self.model.clone(),
            usage: AiUsage::default(),
        })
    }

    async fn stream_chat(&self, request: AiRequest) -> anyhow::Result<AiStream> {
        let chunks = Self::chunks(&self.response_text(&request));
        Ok(Box::pin(futures_util::stream::unfold(
            chunks.into_iter(),
            |mut iter| async move {
                tokio::time::sleep(DEFAULT_STREAM_CHUNK_DELAY).await;
                iter.next().map(|chunk| (Ok(chunk), iter))
            },
        )))
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::models::AiMessage;

    #[tokio::test]
    async fn echo_streams_chunks() {
        let provider = EchoProvider::new("test".to_string());
        let request = AiRequest::new(
            "test",
            vec![
                AiMessage::system("sys"),
                AiMessage::user("assess example.com"),
            ],
        );
        let mut stream = provider.stream_chat(request).await.unwrap();
        let mut text = String::new();
        while let Some(chunk) = stream.next().await {
            text.push_str(&chunk.unwrap());
        }
        assert!(text.contains("Offline echo mode"));
        assert!(text.contains("example.com"));
    }

    #[test]
    fn parses_sse_line() {
        let line = r#"data: {"choices":[{"delta":{"content":"Hello"}}]}"#;
        assert_eq!(parse_sse_line(line).as_deref(), Some("Hello"));
        assert_eq!(parse_sse_line("data: [DONE]"), None);
        assert_eq!(parse_sse_line("data: {\"choices\":[]}"), None);
        assert_eq!(parse_sse_line("event: ping"), None);
    }

    #[test]
    fn parses_openai_response() {
        let body: Value = serde_json::from_str(
            r#"{"choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}"#,
        )
        .unwrap();
        let content = body
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str)
            .unwrap();
        assert_eq!(content, "hi");
    }
}
