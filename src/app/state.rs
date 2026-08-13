//! Application UI state.

use std::path::PathBuf;

use crate::agent::memory::MemoryEntry;
use crate::agent::planner::Plan;
use crate::agent::{ConversationMemory, SessionSummary};
use crate::security::Scope;
use crate::storage::SessionRecord;
use crate::tui::input::InputLine;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Chat,
    ScopeInput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ready,
    Working,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeKind {
    Info,
    Ok,
    Warn,
    Error,
}

#[derive(Debug, Clone)]
pub enum Message {
    User(String),
    Agent(String),
    Notice(String, NoticeKind),
}

impl Message {
    pub fn user(text: impl Into<String>) -> Self {
        Message::User(text.into())
    }

    pub fn agent(text: impl Into<String>) -> Self {
        Message::Agent(text.into())
    }

    pub fn notice(text: impl Into<String>, kind: NoticeKind) -> Self {
        Message::Notice(text.into(), kind)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepStatus {
    Pending,
    Running,
    Done,
    Skipped,
    Failed,
}

#[derive(Debug, Clone)]
pub struct StepState {
    pub step_id: u32,
    pub action: String,
    pub description: String,
    pub requires_tool: Option<String>,
    pub status: StepStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolStatus {
    Running,
    Completed,
    Unavailable,
}

#[derive(Debug, Clone)]
pub struct ToolState {
    pub tool: String,
    pub status: ToolStatus,
    pub summary: String,
}

#[derive(Debug, Clone, Default)]
pub struct ActivityState {
    pub visible: bool,
    pub header: Option<String>,
    pub steps: Vec<StepState>,
    pub tool: Option<ToolState>,
    pub streaming: String,
    pub summary: Option<SessionSummary>,
}

impl ActivityState {
    pub fn reset(&mut self) {
        self.visible = true;
        self.header = Some("Planning assessment...".to_string());
        self.steps.clear();
        self.tool = None;
        self.streaming.clear();
        self.summary = None;
    }

    pub fn set_steps(&mut self, steps: Vec<StepState>) {
        self.steps = steps;
    }

    pub fn mark_step(&mut self, step_id: u32, status: StepStatus) {
        if let Some(step) = self.steps.iter_mut().find(|s| s.step_id == step_id) {
            step.status = status;
        }
    }
}

/// Root state for the chat screen.
#[derive(Debug, Clone)]
pub struct AppState {
    pub session_id: String,
    pub workspace: PathBuf,
    pub model: String,
    pub provider: String,
    pub mode: Mode,
    pub status: Status,
    pub input: InputLine,
    pub messages: Vec<Message>,
    pub activity: ActivityState,
    pub scope: Option<Scope>,
    pub show_help: bool,
    pub show_findings: bool,
    pub last_task: Option<String>,
    pub last_plan: Option<Plan>,
    pub last_report: Option<String>,
    pub scroll: u16,
    pub auto_scroll: bool,
    pub memory: ConversationMemory,
}

impl AppState {
    pub fn new(workspace: PathBuf, model: String, provider: String) -> Self {
        Self::new_with_session(workspace, model, provider, None)
    }

    /// Create app state, optionally restoring a persisted session.
    pub fn new_with_session(
        workspace: PathBuf,
        model: String,
        provider: String,
        session: Option<SessionRecord>,
    ) -> Self {
        let messages = vec![
            Message::notice("Welcome to ANAJAKKH", NoticeKind::Info),
            Message::notice("› AI-powered Red Team Security Agent", NoticeKind::Info),
            Message::notice("", NoticeKind::Info),
            Message::notice("Getting started:", NoticeKind::Info),
            Message::notice("  1. Type a task for the agent", NoticeKind::Info),
            Message::notice(
                "  2. Define an authorized target / scope (Ctrl+S)",
                NoticeKind::Info,
            ),
            Message::notice(
                "  3. ANAJAKKH plans and executes the assessment",
                NoticeKind::Info,
            ),
        ];

        let mut state = Self {
            session_id: crate::storage::sessions::new_session_id(),
            workspace,
            model,
            provider,
            mode: Mode::Chat,
            status: Status::Ready,
            input: InputLine::new(),
            messages,
            activity: ActivityState::default(),
            scope: None,
            show_help: false,
            show_findings: false,
            last_task: None,
            last_plan: None,
            last_report: None,
            scroll: 0,
            auto_scroll: true,
            memory: ConversationMemory::new(),
        };

        if let Some(record) = session {
            state.session_id = record.id.clone();
            state.scope = record.scope.clone();
            state.memory = record.conversation.clone();
            if let Some(summary) = &record.summary {
                state.activity.summary = Some(summary.clone());
            }
            for entry in record.conversation.entries() {
                match entry {
                    MemoryEntry::User(text) => {
                        state.messages.push(Message::user(text));
                    }
                    MemoryEntry::Assistant(text) => {
                        state.messages.push(Message::agent(text));
                    }
                    MemoryEntry::System(text) => {
                        state.messages.push(Message::notice(text, NoticeKind::Info));
                    }
                }
            }
            state
                .messages
                .push(Message::notice("\n── Resumed session ──", NoticeKind::Info));
        }
        state
    }

    pub fn push_user(&mut self, text: &str) {
        self.messages.push(Message::user(text.to_string()));
        self.auto_scroll = true;
    }

    pub fn push_agent(&mut self, text: &str) {
        self.messages.push(Message::agent(text.to_string()));
        self.auto_scroll = true;
    }

    pub fn push_notice(&mut self, text: &str, kind: NoticeKind) {
        self.messages.push(Message::notice(text.to_string(), kind));
        self.auto_scroll = true;
    }

    /// True when the user has scrolled up away from the bottom.
    pub fn is_auto_scroll(&self) -> bool {
        self.auto_scroll
    }

    pub fn set_auto_scroll(&mut self, value: bool) {
        self.auto_scroll = value;
    }
}
