//! Data models for the AI layer.

use serde::{Deserialize, Serialize};

/// Role of a chat message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AiRole {
    System,
    User,
    Assistant,
}

/// A single chat message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiMessage {
    pub role: AiRole,
    pub content: String,
}

impl AiMessage {
    pub fn new(role: AiRole, content: impl Into<String>) -> Self {
        Self {
            role,
            content: content.into(),
        }
    }

    pub fn system(content: impl Into<String>) -> Self {
        Self::new(AiRole::System, content)
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self::new(AiRole::User, content)
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self::new(AiRole::Assistant, content)
    }
}

/// A request sent to an AI provider.
#[derive(Debug, Clone)]
pub struct AiRequest {
    pub model: String,
    pub messages: Vec<AiMessage>,
    pub temperature: f32,
    pub max_tokens: u32,
    pub stream: bool,
}

impl AiRequest {
    pub fn new(model: impl Into<String>, messages: Vec<AiMessage>) -> Self {
        Self {
            model: model.into(),
            messages,
            temperature: 0.2,
            max_tokens: 2048,
            stream: false,
        }
    }
}

/// Token usage reported by the provider.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// A non-streamed response.
#[derive(Debug, Clone)]
pub struct AiResponse {
    pub content: String,
    pub model: String,
    pub usage: AiUsage,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_serde_roundtrip() {
        let msg = AiMessage::user("hello");
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(json, r#"{"role":"user","content":"hello"}"#);
        let back: AiMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn request_builder_defaults() {
        let req = AiRequest::new("gpt-4o-mini", vec![AiMessage::system("be good")]);
        assert_eq!(req.model, "gpt-4o-mini");
        assert!(!req.stream);
        assert_eq!(req.max_tokens, 2048);
    }
}
