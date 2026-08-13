//! AI layer: provider abstraction, models, prompts, and clients.

pub mod client;
pub mod models;
pub mod prompts;
pub mod provider;

use std::sync::Arc;

use crate::config::AiSettings;

use self::client::{EchoProvider, OpenAiClient};
use self::provider::AiProvider;

/// Build a provider from settings. Falls back to the offline echo
/// provider when no API key is configured or the provider cannot be
/// initialized — never blocks startup on network access.
pub fn build_provider(settings: &AiSettings) -> Arc<dyn AiProvider> {
    if settings.provider.eq_ignore_ascii_case("echo") {
        tracing::info!("using offline echo provider (provider = \"echo\")");
        return Arc::new(EchoProvider::new(settings.model.clone()));
    }

    match std::env::var(&settings.api_key_env) {
        Ok(key) if !key.trim().is_empty() => match OpenAiClient::new(settings, key.trim()) {
            Ok(client) => {
                tracing::info!(
                    "using provider={} model={}",
                    settings.provider,
                    settings.model
                );
                Arc::new(client)
            }
            Err(err) => {
                tracing::warn!(
                    "failed to init {} provider: {err}; falling back to echo",
                    settings.provider
                );
                Arc::new(EchoProvider::new(settings.model.clone()))
            }
        },
        _ => {
            tracing::warn!(
                "environment variable {} not set; using offline echo provider",
                settings.api_key_env
            );
            Arc::new(EchoProvider::new(settings.model.clone()))
        }
    }
}
