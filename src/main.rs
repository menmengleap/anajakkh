//! ANAJAKKH — AI-powered Red Team Security Agent.
//!
//! Run with no arguments to launch the interactive TUI.

use clap::Parser;

use anajakkh::cli::{self, Cli};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(err) = cli::commands::run(cli).await {
        // Never surface raw Rust errors as the primary UX — print a
        // friendly message and log the full chain.
        cli::commands::print_error("command", &err);
        std::process::exit(1);
    }
}
