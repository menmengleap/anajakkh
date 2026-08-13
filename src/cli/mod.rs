//! Command-line interface.

pub mod commands;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "anajakkh",
    version,
    about = "ANAJAKKH — AI-powered Red Team Security Agent",
    long_about = "ANAJAKKH is a terminal-first AI security agent. Run it with no\narguments to launch the interactive TUI."
)]
pub struct Cli {
    /// Workspace directory (default: ~/.anajakkh).
    #[arg(long, global = true)]
    pub workspace: Option<PathBuf>,

    /// Resume an existing session by id (launches the TUI).
    #[arg(long, global = true)]
    pub resume: Option<String>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Initialize the workspace and default configuration.
    Init,

    /// Check the environment (workspace, config, provider, tools).
    Doctor,

    /// Run a headless assessment of a target.
    Scan { target: String },

    /// Manage persisted sessions.
    Session {
        #[command(subcommand)]
        subcommand: Option<SessionSubcommand>,
    },

    /// Generate a report for a session.
    Report {
        /// Session id to report on (defaults to the most recent session).
        #[arg(long)]
        session: Option<String>,

        /// Output format (defaults to all: markdown, json, html).
        #[arg(long, value_enum)]
        format: Option<ReportFormat>,
    },

    /// Show current configuration.
    Config,
}

#[derive(Debug, Subcommand)]
pub enum SessionSubcommand {
    List,
    Resume { id: String },
}

/// Report output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ReportFormat {
    Markdown,
    Json,
    Html,
}

impl ReportFormat {
    pub fn extension(self) -> &'static str {
        match self {
            ReportFormat::Markdown => "md",
            ReportFormat::Json => "json",
            ReportFormat::Html => "html",
        }
    }
}
