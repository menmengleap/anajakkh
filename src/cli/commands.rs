//! Implementations of the CLI commands.

use std::io::Write;

use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

use crate::agent::context::AgentContext;
use crate::agent::{Agent, AgentEvent};
use crate::config::{Settings, DEFAULT_CONFIG};
use crate::security::Scope;
use crate::storage::{SessionRecord, SessionStore};

use super::{Cli, Command, ReportFormat, SessionSubcommand};

/// Initialize logging to the workspace log file.
///
/// Every line written to the file passes through [`crate::logging::RedactingWriter`],
/// so API keys, tokens, and passwords can never reach the log on disk.
fn init_logging(settings: &Settings) -> Result<()> {
    let log_path = settings.log_path();
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("opening log file {}", log_path.display()))?;
    let writer = crate::logging::RedactingWriter::new(file);
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_ansi(false)
        .try_init()
        .ok();
    Ok(())
}

/// Print a friendly, non-raw error message and log the full error chain.
///
/// Raw `anyhow` debug output is never shown as the primary UX; it is
/// written to the log file instead (per the error-UX policy in INFO.md).
pub fn print_error(context: &str, err: &anyhow::Error) {
    eprintln!("✗ {context} failed");
    eprintln!();
    eprintln!("  Reason:");
    for line in err.to_string().lines() {
        eprintln!("  {line}");
    }
    eprintln!();
    eprintln!("  The full error has been written to the workspace log for diagnostics.");
    eprintln!("  (logs/anajakkh.log — never share it if it may contain sensitive data)");
    tracing::error!("{context} failed: {err:?}");
}

/// Entry point for the CLI.
pub async fn run(cli: Cli) -> Result<()> {
    let settings = Settings::load(cli.workspace.clone())?;
    init_logging(&settings)?;
    tracing::info!(
        "anajakkh started (workspace {})",
        settings.workspace.display()
    );

    match cli.command {
        None => {
            // Default: launch the TUI, optionally resuming a session.
            if let Some(id) = &cli.resume {
                if !session_exists(&settings, id) {
                    println!("✗ session `{id}` not found");
                    println!("  Run `anajakkh session list` to see available sessions.");
                    return Ok(());
                }
            }
            crate::app::run(settings, cli.resume).await
        }
        Some(Command::Init) => cmd_init(&settings),
        Some(Command::Doctor) => cmd_doctor(&settings),
        Some(Command::Scan { target }) => cmd_scan(&settings, &target).await,
        Some(Command::Session { subcommand }) => match subcommand {
            Some(SessionSubcommand::List) => cmd_session_list(&settings),
            Some(SessionSubcommand::Resume { id }) => {
                if !session_exists(&settings, &id) {
                    println!("✗ session `{id}` not found");
                    println!("  Run `anajakkh session list` to see available sessions.");
                    return Ok(());
                }
                crate::app::run(settings, Some(id)).await
            }
            None => {
                println!("Usage: anajakkh session <list | resume <session-id>>");
                println!("  anajakkh session list          list persisted sessions");
                println!("  anajakkh session resume <id>   resume a session in the TUI");
                println!("  anajakkh --resume <id>         resume a session in the TUI");
                Ok(())
            }
        },
        Some(Command::Report { session, format }) => {
            cmd_report(&settings, session.as_deref(), format)
        }
        Some(Command::Config) => cmd_config(&settings),
    }
}

/// `anajakkh init` — create workspace structure and default config.
fn cmd_init(settings: &Settings) -> Result<()> {
    settings.ensure_dirs()?;
    let config_path = settings.config_path();
    if !config_path.exists() {
        let mut file = std::fs::File::create(&config_path)
            .with_context(|| format!("creating {}", config_path.display()))?;
        file.write_all(DEFAULT_CONFIG.as_bytes())
            .with_context(|| format!("writing {}", config_path.display()))?;
        println!("✓ Created default config at {}", config_path.display());
    } else {
        println!("• Config already exists at {}", config_path.display());
    }
    println!("✓ Workspace ready at {}", settings.workspace.display());
    println!("  Directories: sessions/ evidence/ reports/ logs/ cache/");
    println!(
        "  Tip: set {} to enable the AI provider.",
        settings.ai.api_key_env
    );
    Ok(())
}

/// `anajakkh scan <target>` — run a headless assessment.
///
/// Defines an authorized scope from the target, plans the assessment, and
/// executes the tool pipeline, printing progress as it goes.
async fn cmd_scan(settings: &Settings, target: &str) -> Result<()> {
    let scope = Scope::parse("cli-scan", target)
        .map_err(|err| anyhow::anyhow!("invalid target `{target}`: {err}"))?;
    println!("Scope: {}", scope.summary());
    println!();

    let agent = Agent::new(settings);
    let mut ctx = AgentContext::new(settings.workspace.clone());
    let session_id = ctx.session_id.clone();
    let session_scope = scope.clone();
    ctx.scope = Some(scope);

    let (tx, mut rx) = mpsc::channel::<AgentEvent>(256);
    let run_agent = agent.clone();
    let task = format!("assess {target} and generate a report");
    let task_for_run = task.clone();
    let _handle = tokio::spawn(async move { run_agent.run(&task_for_run, ctx, tx.clone()).await });
    let mut final_summary: Option<crate::agent::SessionSummary> = None;

    while let Some(event) = rx.recv().await {
        match event {
            AgentEvent::PlanCreated(plan) => {
                println!("Plan:");
                for step in &plan.steps {
                    println!("  {}. {} — {}", step.id, step.action, step.description);
                }
                println!();
            }
            AgentEvent::ScopeValidated { ok, message } => {
                println!("{} {message}", if ok { "✓" } else { "✗" });
            }
            AgentEvent::ToolRunning { tool } => println!("▶ {tool} running..."),
            AgentEvent::ToolCompleted { tool, summary } => {
                println!("✓ {tool}: {summary}");
            }
            AgentEvent::ToolUnavailable { tool, reason } => {
                println!("↷ {tool}: {reason}");
            }
            AgentEvent::EvidenceCollected { source, count } => {
                println!("  evidence: {count} record(s) from {source}");
            }
            AgentEvent::FindingsGenerated { count } => {
                println!(
                    "✓ {count} finding(s) generated — see {}",
                    settings.workspace.join("findings").display()
                );
            }
            AgentEvent::StepSkipped { action, reason, .. } => {
                println!("↷ step {action} skipped: {reason}");
            }
            AgentEvent::StepFailed { action, error, .. } => {
                println!("✗ step {action} failed: {error}");
            }
            AgentEvent::Finished(summary) => {
                println!();
                println!("✓ Assessment completed");
                println!(
                    "  steps {} · skipped {} · failed {}",
                    summary.steps_completed, summary.steps_skipped, summary.steps_failed
                );
                println!(
                    "  tools {} · targets {} · findings {} · evidence {}",
                    if summary.tools_used.is_empty() {
                        "—".to_string()
                    } else {
                        summary.tools_used.join(", ")
                    },
                    summary.targets.len(),
                    summary.findings,
                    summary.evidence,
                );
                final_summary = Some(summary);
                println!(
                    "  evidence stored under {}",
                    settings.workspace.join("evidence").display()
                );
            }
            _ => {}
        }
    }

    // Persist the scan as a session so it can be listed and resumed.
    if let Some(summary) = final_summary {
        let mut record = SessionRecord::new(session_id, settings.workspace.clone());
        record.scope = Some(session_scope);
        record.conversation.push_user(&task);
        record.summary = Some(summary);
        if let Err(err) = SessionStore::open(&settings.workspace).and_then(|s| s.save(&record)) {
            tracing::warn!("failed to persist session: {err}");
        } else {
            println!("  session saved — resume with: anajakkh --resume <session-id>");
        }
    }
    Ok(())
}

/// Does a session with `id` exist?
fn session_exists(settings: &Settings, id: &str) -> bool {
    match SessionStore::open(&settings.workspace) {
        Ok(store) => store.get(id).map(|s| s.is_some()).unwrap_or(false),
        Err(err) => {
            tracing::warn!("session store unavailable: {err}");
            false
        }
    }
}

/// `anajakkh session list` — list persisted sessions.
fn cmd_session_list(settings: &Settings) -> Result<()> {
    let store = SessionStore::open(&settings.workspace)?;
    let sessions = store.list()?;
    if sessions.is_empty() {
        println!("No sessions yet.");
        println!("  Launch the TUI and run an assessment — sessions persist automatically.");
        return Ok(());
    }
    println!("{:<40}  {:<20}  SCOPE", "SESSION ID", "CREATED");
    println!("{}", "─".repeat(90));
    for session in &sessions {
        let scope = session
            .scope
            .as_ref()
            .map(|s| s.summary())
            .unwrap_or_else(|| "—".to_string());
        let status = if session.is_completed() {
            "completed"
        } else {
            "active"
        };
        println!(
            "{:<40}  {:<20}  {} ({})",
            session.id,
            session.created_at.format("%Y-%m-%d %H:%M:%S"),
            scope,
            status
        );
    }
    println!();
    println!("Resume with: anajakkh --resume <session-id>");
    Ok(())
}

/// `anajakkh report [--session <id>] [--format <md|json|html>]`.
///
/// Generates a report from a session's findings and evidence. Defaults to
/// the most recent session and all three formats.
fn cmd_report(
    settings: &Settings,
    session_id: Option<&str>,
    format: Option<ReportFormat>,
) -> Result<()> {
    let store = SessionStore::open(&settings.workspace)?;
    let record = match session_id {
        Some(id) => match store.get(id)? {
            Some(record) => record,
            None => {
                println!("✗ session `{id}` not found");
                println!("  Run `anajakkh session list` to see available sessions.");
                return Ok(());
            }
        },
        None => match store.list()?.into_iter().next() {
            Some(record) => {
                println!("Using most recent session {}", record.id);
                record
            }
            None => {
                println!("No sessions yet.");
                println!(
                    "  Run `anajakkh scan <target>` or launch the TUI to create a session first."
                );
                return Ok(());
            }
        },
    };

    let report = crate::reports::Report::from_record(&record)?;
    if report.findings.is_empty() && report.evidence.is_empty() {
        println!(
            "⚠ session {} has no evidence or findings — the report will be empty.",
            record.id
        );
    }

    let formats: Vec<ReportFormat> = match format {
        Some(single) => vec![single],
        None => vec![
            ReportFormat::Markdown,
            ReportFormat::Json,
            ReportFormat::Html,
        ],
    };

    let dir = settings.workspace.join("reports");
    std::fs::create_dir_all(&dir)?;
    let stamp = report.generated_at.format("%Y%m%d-%H%M%S");
    let base = dir.join(format!("{}-{}", record.id, stamp));

    let mut primary_path = None;
    for fmt in &formats {
        let path = base.with_extension(fmt.extension());
        let content = match fmt {
            ReportFormat::Markdown => crate::reports::markdown::render(&report),
            ReportFormat::Json => crate::reports::json::render(&report)?,
            ReportFormat::Html => crate::reports::html::render(&report),
        };
        std::fs::write(&path, content).with_context(|| format!("writing {}", path.display()))?;
        println!("✓ {}", path.display());
        if primary_path.is_none() {
            primary_path = Some(path.display().to_string());
        }
    }

    // Record the report on the session so `session list`/resume can see it.
    let mut updated = record.clone();
    updated.report = primary_path;
    if let Err(err) = store.save(&updated) {
        tracing::warn!("failed to update session with report path: {err}");
    }
    Ok(())
}

/// `anajakkh doctor` — environment health check.
fn cmd_doctor(settings: &Settings) -> Result<()> {
    println!("ANAJAKKH doctor");
    println!("───────────────");

    let workspace_ok = settings.workspace.exists();
    println!(
        "{} workspace {}",
        check(workspace_ok),
        settings.workspace.display()
    );

    let config_ok = settings.config_path().exists();
    println!(
        "{} config {}",
        check(config_ok),
        settings.config_path().display()
    );

    match settings.api_key() {
        Some(_) => {
            println!("{} API key {} set", check(true), settings.ai.api_key_env);
        }
        None => {
            println!(
                "✗ API key {} not set — using offline echo provider",
                settings.ai.api_key_env
            );
            println!("  Set it or change provider = \"echo\" in config.toml.");
        }
    }

    let nmap = which("nmap");
    println!(
        "{} nmap {}",
        if nmap { "✓" } else { "✗" },
        if nmap {
            "found — network scans will use it"
        } else {
            "not found — network scans (nmap steps) will be skipped; install it and re-run this check"
        }
    );

    let tools = crate::tools::default_registry();
    println!("✓ tools: {}", tools.names().join(", "));

    println!("───────────────");
    println!(
        "Model: {} · Provider: {}",
        settings.ai.model, settings.ai.provider
    );
    println!("Logs: {}", settings.log_path().display());
    Ok(())
}

/// `anajakkh config` — show current configuration.
fn cmd_config(settings: &Settings) -> Result<()> {
    println!("Config file: {}", settings.config_path().display());
    if settings.config_path().exists() {
        let text = std::fs::read_to_string(settings.config_path())
            .with_context(|| format!("reading {}", settings.config_path().display()))?;
        print!("{text}");
    } else {
        println!("(not created yet — run `anajakkh init`)");
    }
    println!("Resolved:");
    println!("  provider   = {}", settings.ai.provider);
    println!("  model      = {}", settings.ai.model);
    println!("  base_url   = {}", settings.ai.base_url);
    println!("  api_key_env= {}", settings.ai.api_key_env);
    println!("  workspace  = {}", settings.workspace.display());
    Ok(())
}

fn check(ok: bool) -> &'static str {
    if ok {
        "✓"
    } else {
        "✗"
    }
}

fn which(name: &str) -> bool {
    std::process::Command::new(name)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
