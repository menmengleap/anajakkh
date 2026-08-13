//! Tool system: plugin-style registry of security tools.
//!
//! Concrete tools ship in this module: DNS resolution, Nmap port scans,
//! HTTP inspection, and workspace-scoped filesystem inspection. New tools
//! implement [`SecurityTool`] and register themselves — the agent core
//! never needs to change.

pub mod dns;
pub mod filesystem;
pub mod http;
pub mod nmap;
pub mod process;
pub mod registry;

pub use registry::{RiskLevel, SecurityTool, ToolContext, ToolMetadata, ToolRegistry, ToolResult};

/// Build the registry with the default set of tools.
pub fn default_registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    registry.register(std::sync::Arc::new(dns::DnsTool::new()));
    registry.register(std::sync::Arc::new(nmap::NmapTool::new()));
    registry.register(std::sync::Arc::new(http::HttpTool::new()));
    registry.register(std::sync::Arc::new(filesystem::FilesystemTool::new()));
    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_registry_has_all_tools() {
        let registry = default_registry();
        let names = registry.names();
        assert_eq!(
            names,
            vec![
                "dns".to_string(),
                "filesystem".to_string(),
                "http".to_string(),
                "nmap".to_string(),
            ]
        );
    }
}
