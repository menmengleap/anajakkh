//! Provider abstraction so ANAJAKKH is not locked to one AI vendor.

use async_trait::async_trait;
use futures_util::stream::BoxStream;

use super::models::{AiRequest, AiResponse};

/// A stream of content chunks from a provider.
pub type AiStream = BoxStream<'static, anyhow::Result<String>>;

#[async_trait]
pub trait AiProvider: Send + Sync {
    /// Provider name, e.g. "openai", "echo".
    fn name(&self) -> &str;

    /// Model identifier the provider is configured with.
    fn model(&self) -> &str;

    /// Complete a chat request without streaming.
    async fn chat(&self, request: AiRequest) -> anyhow::Result<AiResponse>;

    /// Stream a chat response as content chunks arrive.
    async fn stream_chat(&self, request: AiRequest) -> anyhow::Result<AiStream>;
}
