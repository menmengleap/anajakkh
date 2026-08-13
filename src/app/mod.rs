//! Application core: state machine that bridges the TUI and the agent.

pub mod actions;
pub mod events;
pub mod state;

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use ratatui::DefaultTerminal;
use tokio::sync::mpsc;

use crate::agent::context::AgentContext;
use crate::agent::{Agent, AgentEvent, SessionSummary};
use crate::config::Settings;
use crate::security::Scope;
use crate::storage::{SessionRecord, SessionStore};
use crate::tui;

use self::actions::{action_from_key, Action};
use self::events::{spawn_input_reader, Event};
use self::state::{
    AppState, Mode, NoticeKind, Status, StepState, StepStatus, ToolState, ToolStatus,
};

/// How the run loop should proceed after handling an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlFlow {
    Continue,
    Exit,
}

/// The interactive application.
pub struct App {
    state: AppState,
    agent: Agent,
    store: SessionStore,
    event_tx: mpsc::Sender<Event>,
    /// Shared with the running agent task so Esc can cancel it.
    cancel_flag: Arc<AtomicBool>,
}

impl App {
    /// Build the app, optionally resuming a persisted session by id.
    pub fn new(settings: &Settings, resume: Option<String>) -> (Self, mpsc::Receiver<Event>) {
        let store = match SessionStore::open(&settings.workspace) {
            Ok(store) => store,
            Err(err) => {
                tracing::warn!("session store unavailable: {err}; sessions will not persist");
                SessionStore::in_memory()
            }
        };

        let resumed = match &resume {
            Some(id) => match store.get(id) {
                Ok(Some(record)) => Some(record),
                Ok(None) => {
                    tracing::warn!("session {id} not found — starting a new session");
                    None
                }
                Err(err) => {
                    tracing::warn!("failed to load session {id}: {err}");
                    None
                }
            },
            None => None,
        };

        let (event_tx, event_rx) = mpsc::channel::<Event>(256);
        let state = AppState::new_with_session(
            settings.workspace.clone(),
            settings.ai.model.clone(),
            settings.ai.provider.clone(),
            resumed.clone(),
        );
        let app = Self {
            state,
            agent: Agent::new(settings),
            store,
            event_tx,
            cancel_flag: Arc::new(AtomicBool::new(false)),
        };

        // Reload persisted evidence/findings for the resumed session so
        // Ctrl+L / Ctrl+F reflect history.
        if let Some(record) = &resumed {
            match app.agent.executor().evidence.load(&record.id) {
                Ok(n) => tracing::info!("loaded {n} evidence records for session {}", record.id),
                Err(err) => tracing::warn!("failed to load evidence: {err}"),
            }
            match app.agent.executor().findings.load(&record.id) {
                Ok(n) => tracing::info!("loaded {n} findings for session {}", record.id),
                Err(err) => tracing::warn!("failed to load findings: {err}"),
            }
        }
        (app, event_rx)
    }

    pub fn state(&self) -> &AppState {
        &self.state
    }

    pub fn agent(&self) -> &Agent {
        &self.agent
    }

    /// Handle a single event, possibly spawning agent tasks.
    pub async fn handle(&mut self, event: Event) -> Result<ControlFlow> {
        match event {
            Event::Key(key) => self.handle_key(key).await,
            Event::Tick => Ok(ControlFlow::Continue),
            Event::Resize(_, _) => Ok(ControlFlow::Continue),
            Event::Agent(agent_event) => {
                self.apply_agent_event(agent_event);
                Ok(ControlFlow::Continue)
            }
        }
    }

    async fn handle_key(&mut self, key: crossterm::event::KeyEvent) -> Result<ControlFlow> {
        let Some(action) = action_from_key(key) else {
            return Ok(ControlFlow::Continue);
        };
        match action {
            Action::Exit => {
                if self.state.mode == Mode::ScopeInput {
                    self.state.mode = Mode::Chat;
                    self.state.input.clear();
                    Ok(ControlFlow::Continue)
                } else {
                    self.save_session();
                    Ok(ControlFlow::Exit)
                }
            }
            Action::ToggleHelp => {
                self.state.show_help = !self.state.show_help;
                Ok(ControlFlow::Continue)
            }
            Action::Submit => {
                if self.state.mode == Mode::ScopeInput {
                    self.commit_scope();
                } else {
                    self.submit_input();
                }
                Ok(ControlFlow::Continue)
            }
            Action::Cancel => {
                if self.state.mode == Mode::ScopeInput {
                    self.state.mode = Mode::Chat;
                    self.state.input.clear();
                } else if self.state.show_findings {
                    self.state.show_findings = false;
                } else if self.state.show_help {
                    self.state.show_help = false;
                } else if self.state.status == Status::Working {
                    self.cancel_flag.store(true, Ordering::Relaxed);
                    self.state
                        .push_notice("Cancelling current task...", NoticeKind::Warn);
                } else {
                    self.state.input.clear();
                }
                Ok(ControlFlow::Continue)
            }
            Action::DefineScope => {
                self.state.mode = Mode::ScopeInput;
                self.state.input.clear();
                self.state.push_notice(
                    "Enter authorized scope (targets, comma-separated). Prefix with ! to exclude.",
                    NoticeKind::Info,
                );
                Ok(ControlFlow::Continue)
            }
            Action::CommitScope => {
                self.commit_scope();
                Ok(ControlFlow::Continue)
            }
            Action::TypeChar(c) => {
                self.state.input.insert_char(c);
                Ok(ControlFlow::Continue)
            }
            Action::Backspace => {
                self.state.input.backspace();
                Ok(ControlFlow::Continue)
            }
            Action::Delete => {
                self.state.input.delete();
                Ok(ControlFlow::Continue)
            }
            Action::MoveLeft => {
                self.state.input.move_left();
                Ok(ControlFlow::Continue)
            }
            Action::MoveRight => {
                self.state.input.move_right();
                Ok(ControlFlow::Continue)
            }
            Action::Home => {
                self.state.input.home();
                Ok(ControlFlow::Continue)
            }
            Action::End => {
                self.state.input.end();
                Ok(ControlFlow::Continue)
            }
            Action::ScrollUp => {
                self.state.scroll = self.state.scroll.saturating_sub(1);
                self.state.set_auto_scroll(false);
                Ok(ControlFlow::Continue)
            }
            Action::ScrollDown => {
                self.state.scroll = self.state.scroll.saturating_add(1);
                Ok(ControlFlow::Continue)
            }
            Action::ReRun => {
                if let Some(task) = self.state.last_task.clone() {
                    self.run_task(&task);
                } else {
                    self.state
                        .push_notice("No previous task to re-run.", NoticeKind::Warn);
                }
                Ok(ControlFlow::Continue)
            }
            Action::ShowLogs => {
                let count = self.agent.executor().evidence.len();
                let dir = self.agent.executor().evidence.root_dir();
                self.state.push_notice(
                    &format!(
                        "Tool logs: {count} evidence record(s) under {}",
                        dir.display()
                    ),
                    NoticeKind::Info,
                );
                Ok(ControlFlow::Continue)
            }
            Action::ShowFindings => {
                self.state.show_findings = !self.state.show_findings;
                Ok(ControlFlow::Continue)
            }
            Action::ShowTools => {
                let tools = self.agent.executor().registry.names();
                if tools.is_empty() {
                    self.state
                        .push_notice("No tools registered.", NoticeKind::Info);
                } else {
                    self.state.push_notice(
                        &format!("Registered tools: {}", tools.join(", ")),
                        NoticeKind::Info,
                    );
                }
                Ok(ControlFlow::Continue)
            }
            Action::ShowHistory => {
                let count = self.store.list().map(|s| s.len()).unwrap_or(0);
                self.state.push_notice(
                    &format!(
                        "Session history: {count} session(s) — run `anajakkh session list` or `anajakkh --resume <id>`"
                    ),
                    NoticeKind::Info,
                );
                Ok(ControlFlow::Continue)
            }
            Action::ShowModel => {
                self.state.push_notice(
                    &format!(
                        "Model: {} (provider: {})",
                        self.state.model, self.state.provider
                    ),
                    NoticeKind::Info,
                );
                Ok(ControlFlow::Continue)
            }
        }
    }

    /// Parse the input buffer as a scope definition and commit it.
    fn commit_scope(&mut self) {
        let text = self.state.input.take();
        let scope_id = format!("scope-{}", self.state.memory.len());
        match Scope::parse(&scope_id, &text) {
            Ok(scope) => {
                tracing::info!("scope set: {}", scope.summary());
                let summary = scope.summary();
                self.state.scope = Some(scope);
                self.state.push_notice(
                    &format!("✓ Authorized scope set: {summary}"),
                    NoticeKind::Ok,
                );
                self.save_session();
            }
            Err(err) => {
                self.state
                    .push_notice(&format!("✗ Invalid scope: {err}"), NoticeKind::Error);
            }
        }
        self.state.mode = Mode::Chat;
    }

    /// Take the input buffer and dispatch it as a task.
    fn submit_input(&mut self) {
        let raw = self.state.input.take();
        let raw = raw.trim().to_string();
        if raw.is_empty() {
            return;
        }
        // Resolve `@path/to/file` mentions into attached file contents.
        let (text, files) = resolve_mentions(&raw);
        if !files.is_empty() {
            self.state
                .push_notice(&format!("Attached: {}", files.join(", ")), NoticeKind::Info);
        }
        self.run_task(&text);
    }

    /// Start the agent on `task`.
    fn run_task(&mut self, task: &str) {
        if self.state.status == Status::Working {
            self.state
                .push_notice("Agent is busy — press Esc to cancel.", NoticeKind::Warn);
            return;
        }
        let task = task.to_string();
        self.state.last_task = Some(task.clone());
        self.state.push_user(&task);
        self.state.memory.push_user(task.clone());
        self.state.status = Status::Working;
        self.state.activity.reset();
        self.cancel_flag.store(false, Ordering::Relaxed);

        let mut ctx = AgentContext::with_shared_cancel(
            self.state.workspace.clone(),
            Arc::clone(&self.cancel_flag),
        );
        ctx.session_id = self.state.session_id.clone();
        ctx.scope = self.state.scope.clone();
        ctx.memory = self.state.memory.clone();

        let agent = self.agent.clone();
        let event_tx = self.event_tx.clone();
        let task_for_run = task.clone();
        // Bridge: agent events are forwarded to the app event channel.
        let (agent_tx, mut agent_rx) = mpsc::channel::<AgentEvent>(256);
        tokio::spawn(async move {
            while let Some(ev) = agent_rx.recv().await {
                if event_tx.send(Event::Agent(ev)).await.is_err() {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            let result = agent.run(&task_for_run, ctx, agent_tx.clone()).await;
            if let Err(err) = result {
                let _ = agent_tx
                    .send(AgentEvent::Error {
                        message: "Assessment failed".to_string(),
                        detail: err.to_string(),
                        suggestion: "Check the logs for details.".to_string(),
                    })
                    .await;
            }
        });
    }

    /// Apply an agent event to the UI state.
    fn apply_agent_event(&mut self, event: AgentEvent) {
        match event {
            AgentEvent::Started => {
                self.state.status = Status::Working;
            }
            AgentEvent::PlanCreated(plan) => {
                self.state.last_plan = Some(plan.clone());
                let steps: Vec<StepState> = plan
                    .steps
                    .iter()
                    .map(|s| StepState {
                        step_id: s.id,
                        action: s.action.clone(),
                        description: s.description.clone(),
                        requires_tool: s.requires_tool.clone(),
                        status: StepStatus::Pending,
                    })
                    .collect();
                self.state.activity.set_steps(steps);
                if !plan.out_of_scope.is_empty() {
                    let oos: Vec<String> = plan.out_of_scope.iter().map(|t| t.display()).collect();
                    self.state.push_notice(
                        &format!("⚠ Out-of-scope target(s) detected: {}", oos.join(", ")),
                        NoticeKind::Warn,
                    );
                }
            }
            AgentEvent::ScopeValidated { ok, message } => {
                let kind = if ok { NoticeKind::Ok } else { NoticeKind::Warn };
                self.state.push_notice(&message, kind);
            }
            AgentEvent::StepStarted { step_id, .. } => {
                self.state.activity.mark_step(step_id, StepStatus::Running);
            }
            AgentEvent::StepCompleted {
                step_id,
                action,
                summary,
            } => {
                self.state.activity.mark_step(step_id, StepStatus::Done);
                self.state
                    .push_notice(&format!("✓ {action}: {summary}"), NoticeKind::Ok);
            }
            AgentEvent::StepSkipped {
                step_id,
                action,
                reason,
            } => {
                self.state.activity.mark_step(step_id, StepStatus::Skipped);
                // ToolUnavailable already reported the tool-level reason;
                // keep the step notice for policy-related skips only.
                let is_tool_step = self
                    .state
                    .activity
                    .steps
                    .iter()
                    .find(|s| s.step_id == step_id)
                    .map(|s| s.requires_tool.is_some())
                    .unwrap_or(false);
                if !is_tool_step {
                    self.state
                        .push_notice(&format!("↷ {action} skipped: {reason}"), NoticeKind::Warn);
                }
            }
            AgentEvent::StepFailed {
                step_id,
                action,
                error,
            } => {
                self.state.activity.mark_step(step_id, StepStatus::Failed);
                self.state
                    .push_notice(&format!("✗ {action}: {error}"), NoticeKind::Error);
            }
            AgentEvent::ToolRunning { tool } => {
                self.state.activity.tool = Some(ToolState {
                    tool,
                    status: ToolStatus::Running,
                    summary: String::new(),
                });
            }
            AgentEvent::ToolCompleted { tool, summary } => {
                if let Some(tool_state) = self.state.activity.tool.as_mut() {
                    tool_state.status = ToolStatus::Completed;
                    tool_state.summary = summary.clone();
                }
                self.state
                    .push_notice(&format!("✓ {tool}: {summary}"), NoticeKind::Ok);
            }
            AgentEvent::ToolUnavailable { tool, reason } => {
                if let Some(tool_state) = self.state.activity.tool.as_mut() {
                    tool_state.status = ToolStatus::Unavailable;
                }
                self.state
                    .push_notice(&format!("↷ {tool}: {reason}"), NoticeKind::Warn);
            }
            AgentEvent::EvidenceCollected { source, count } => {
                self.state.push_notice(
                    &format!("  evidence: {count} record(s) from {source}"),
                    NoticeKind::Info,
                );
            }
            AgentEvent::ApprovalRequired { operation, reason } => {
                self.state.push_notice(
                    &format!("⚠ approval required for {operation}: {reason}"),
                    NoticeKind::Warn,
                );
            }
            AgentEvent::FindingsGenerated { count } => {
                self.state.push_notice(
                    &format!("✓ {count} finding(s) generated — Ctrl+F to view"),
                    NoticeKind::Ok,
                );
            }
            AgentEvent::ReportGenerated { path } => {
                self.state.last_report = Some(path.clone());
                self.state
                    .push_notice(&format!("✓ Report written to {path}"), NoticeKind::Ok);
                self.save_session();
            }
            AgentEvent::StreamChunk(chunk) => {
                self.state.activity.streaming.push_str(&chunk);
                self.state.set_auto_scroll(true);
            }
            AgentEvent::StreamEnd => {
                let streamed = std::mem::take(&mut self.state.activity.streaming);
                if !streamed.trim().is_empty() {
                    self.state.push_agent(&streamed);
                    self.state.memory.push_assistant(streamed);
                }
            }
            AgentEvent::Finished(summary) => {
                self.on_finished(summary);
            }
            AgentEvent::Error {
                message,
                detail,
                suggestion,
            } => {
                self.state.status = Status::Error;
                self.state.activity.visible = false;
                self.state
                    .push_notice(&format!("✗ {message}"), NoticeKind::Error);
                self.state
                    .push_notice(&format!("  Reason: {detail}"), NoticeKind::Error);
                self.state.push_notice(
                    &format!("  Suggested action: {suggestion}"),
                    NoticeKind::Warn,
                );
                self.save_session();
            }
        }
    }

    /// Persist the current session (scope, conversation, plan, summary).
    /// Best-effort: failures are logged, never fatal.
    fn save_session(&self) {
        let record = SessionRecord {
            id: self.state.session_id.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            workspace: self.state.workspace.clone(),
            scope: self.state.scope.clone(),
            conversation: self.state.memory.clone(),
            plan: self.state.last_plan.clone(),
            summary: self.state.activity.summary.clone(),
            report: self.state.last_report.clone(),
        };
        if let Err(err) = self.store.save(&record) {
            tracing::warn!("failed to persist session {}: {err}", record.id);
        }
    }

    fn on_finished(&mut self, summary: SessionSummary) {
        self.state.status = Status::Ready;
        self.state.activity.visible = false;
        self.state.activity.summary = Some(summary.clone());
        self.state
            .push_notice("✓ Assessment completed", NoticeKind::Ok);
        self.state.push_notice(
            &format!(
                "  Steps {} · skipped {} · failed {}",
                summary.steps_completed, summary.steps_skipped, summary.steps_failed
            ),
            NoticeKind::Info,
        );
        self.state.push_notice(
            &format!(
                "  Tools {} · targets {} · findings {} · evidence {}",
                if summary.tools_used.is_empty() {
                    "—".to_string()
                } else {
                    summary.tools_used.join(", ")
                },
                summary.targets.len(),
                summary.findings,
                summary.evidence,
            ),
            NoticeKind::Info,
        );
        self.state.push_notice(
            "What would you like me to investigate next?",
            NoticeKind::Info,
        );
        self.save_session();
    }
}

/// Run the interactive TUI application, optionally resuming a session.
pub async fn run(settings: Settings, resume: Option<String>) -> Result<()> {
    let mut terminal = ratatui::init();
    let result = run_tui(&mut terminal, settings, resume).await;
    ratatui::restore();
    result
}

async fn run_tui(
    terminal: &mut DefaultTerminal,
    settings: Settings,
    resume: Option<String>,
) -> Result<()> {
    let (mut app, mut event_rx) = App::new(&settings, resume);
    spawn_input_reader(app.event_tx.clone());

    let mut ticker = tokio::time::interval(Duration::from_millis(250));
    loop {
        terminal.draw(|f| tui::render(f, &mut app))?;

        tokio::select! {
            maybe_event = event_rx.recv() => {
                let Some(event) = maybe_event else { break };
                if app.handle(event).await? == ControlFlow::Exit {
                    break;
                }
            }
            _ = ticker.tick() => {
                if app.handle(Event::Tick).await? == ControlFlow::Exit {
                    break;
                }
            }
        }
    }
    Ok(())
}

/// Resolve `@path/to/file` mentions by appending file contents to the task.
/// Returns `(task_text, attached_files)`.
fn resolve_mentions(input: &str) -> (String, Vec<String>) {
    let mut task = String::new();
    let mut files = Vec::new();
    for token in input.split_whitespace() {
        if let Some(path_str) = token.strip_prefix('@') {
            let path = Path::new(path_str);
            match std::fs::read_to_string(path) {
                Ok(contents) => {
                    files.push(path_str.to_string());
                    task.push_str(&contents);
                    task.push('\n');
                }
                Err(err) => {
                    task.push_str(&format!("[could not attach {path_str}: {err}]\n"));
                }
            }
        } else {
            task.push_str(token);
            task.push(' ');
        }
    }
    (task.trim().to_string(), files)
}
