use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Global application settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Workspace directory (default: ~/.anajakkh).
    pub workspace: PathBuf,
    /// AI provider configuration.
    pub ai: AiSettings,
}

/// AI provider settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AiSettings {
    /// Provider name: "openai" (or any OpenAI-compatible API) or "echo" (offline).
    pub provider: String,
    /// Model identifier, e.g. "gpt-4o-mini".
    pub model: String,
    /// Base URL of an OpenAI-compatible API.
    pub base_url: String,
    /// Name of the environment variable holding the API key.
    pub api_key_env: String,
    /// Whether the planner should use the AI provider for planning.
    pub planning: bool,
    /// Request timeout in seconds.
    pub timeout_secs: u64,
    /// Maximum number of tokens to generate.
    pub max_tokens: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            workspace: default_workspace(),
            ai: AiSettings::default(),
        }
    }
}

impl Default for AiSettings {
    fn default() -> Self {
        Self {
            provider: "openai".to_string(),
            model: "gpt-4o-mini".to_string(),
            base_url: "https://api.openai.com/v1".to_string(),
            api_key_env: "OPENAI_API_KEY".to_string(),
            planning: false,
            timeout_secs: 120,
            max_tokens: 2048,
        }
    }
}

/// Default workspace location: `<home>/.anajakkh`.
pub fn default_workspace() -> PathBuf {
    if let Ok(home) = std::env::var("USERPROFILE") {
        PathBuf::from(home).join(".anajakkh")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".anajakkh")
    } else {
        PathBuf::from(".anajakkh")
    }
}

/// Default config file content written by `anajakkh init`.
pub const DEFAULT_CONFIG: &str = r#"# ANAJAKKH configuration.
# Path: <workspace>/config.toml

[ai]
# "openai" for any OpenAI-compatible API, or "echo" for offline mode.
provider = "openai"
model = "gpt-4o-mini"
base_url = "https://api.openai.com/v1"
# Name of the environment variable holding the API key.
api_key_env = "OPENAI_API_KEY"
"#;

impl Settings {
    /// Load settings, optionally overriding the workspace directory.
    ///
    /// Creates the workspace structure if needed and merges
    /// `<workspace>/config.toml` over defaults.
    pub fn load(workspace: Option<PathBuf>) -> Result<Self> {
        let mut settings = Self::default();
        if let Some(ws) = workspace {
            settings.workspace = ws;
        }
        settings.ensure_dirs()?;

        let config_path = settings.config_path();
        if config_path.exists() {
            let text = std::fs::read_to_string(&config_path)
                .with_context(|| format!("reading {}", config_path.display()))?;
            let file: Settings = toml::from_str(&text)
                .with_context(|| format!("parsing {}", config_path.display()))?;
            settings.ai = file.ai;
        }
        Ok(settings)
    }

    /// Create the standard workspace directory tree.
    pub fn ensure_dirs(&self) -> Result<()> {
        for dir in ["", "sessions", "evidence", "reports", "logs", "cache"] {
            let path = self.workspace.join(dir);
            std::fs::create_dir_all(&path)
                .with_context(|| format!("creating {}", path.display()))?;
        }
        Ok(())
    }

    pub fn config_path(&self) -> PathBuf {
        self.workspace.join("config.toml")
    }

    pub fn log_path(&self) -> PathBuf {
        self.workspace.join("logs").join("anajakkh.log")
    }

    /// Read the API key from the environment variable named by `api_key_env`.
    pub fn api_key(&self) -> Option<String> {
        std::env::var(&self.ai.api_key_env)
            .ok()
            .filter(|k| !k.trim().is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_defaults_are_sane() {
        let s = Settings::default();
        assert_eq!(s.ai.provider, "openai");
        assert_eq!(s.ai.api_key_env, "OPENAI_API_KEY");
        assert!(s.workspace.ends_with(".anajakkh"));
    }

    #[test]
    fn parses_config_toml() {
        let parsed: Settings = toml::from_str(DEFAULT_CONFIG).unwrap();
        assert_eq!(parsed.ai.model, "gpt-4o-mini");
        assert_eq!(parsed.ai.base_url, "https://api.openai.com/v1");
    }

    #[test]
    fn echo_provider_config_roundtrip() {
        let toml_str = r#"
[ai]
provider = "echo"
model = "local-test"
base_url = ""
api_key_env = "NONE"
"#;
        let parsed: Settings = toml::from_str(toml_str).unwrap();
        assert_eq!(parsed.ai.provider, "echo");
        assert_eq!(parsed.ai.model, "local-test");
        assert_eq!(parsed.ai.timeout_secs, AiSettings::default().timeout_secs);
    }
}
