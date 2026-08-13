//! Agent: planning, execution, memory, and decision pipeline.

pub mod context;
pub mod decision;
pub mod executor;
pub mod memory;
pub mod planner;

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::ai::build_provider;
use crate::config::Settings;
use crate::evidence::EvidenceStore;
use crate::findings::FindingStore;
use crate::security::ApprovalSystem;
use crate::tools::{default_registry, ToolRegistry};

pub use executor::{Executor, SessionSummary};
pub use memory::ConversationMemory;
pub use planner::{Plan, PlanStep, Planner};

use self::context::AgentContext;

/// Events emitted by the agent for the UI to consume.
#[derive(Debug, Clone)]
pub enum AgentEvent {
    /// Agent has accepted a task and is planning.
    Started,
    /// A plan was created for the current task.
    PlanCreated(Plan),
    /// Scope validation outcome.
    ScopeValidated { ok: bool, message: String },
    /// A plan step began.
    StepStarted { step_id: u32, action: String },
    /// A plan step completed successfully.
    StepCompleted {
        step_id: u32,
        action: String,
        summary: String,
    },
    /// A plan step was skipped (policy, unavailable tool, ...).
    StepSkipped {
        step_id: u32,
        action: String,
        reason: String,
    },
    /// A plan step failed.
    StepFailed {
        step_id: u32,
        action: String,
        error: String,
    },
    /// A tool started executing.
    ToolRunning { tool: String },
    /// A tool completed.
    ToolCompleted { tool: String, summary: String },
    /// A tool could not be used.
    ToolUnavailable { tool: String, reason: String },
    /// Structured evidence was collected from a tool result.
    EvidenceCollected { source: String, count: usize },
    /// A dangerous operation requires explicit operator approval.
    ApprovalRequired { operation: String, reason: String },
    /// Findings were generated from the collected evidence.
    FindingsGenerated { count: usize },
    /// A report was written to disk.
    ReportGenerated { path: String },
    /// A chunk of streamed AI response text.
    StreamChunk(String),
    /// The AI stream ended.
    StreamEnd,
    /// The whole task finished.
    Finished(SessionSummary),
    /// A user-facing error.
    Error {
        message: String,
        detail: String,
        suggestion: String,
    },
}

/// Static agent: planner + executor. Clonable so tasks can be spawned.
#[derive(Clone)]
pub struct Agent {
    planner: Planner,
    executor: Arc<Executor>,
    approvals: Arc<ApprovalSystem>,
}

impl Agent {
    /// Build an agent with the default tool set and a persistent evidence
    /// store rooted at the configured workspace.
    pub fn new(settings: &Settings) -> Self {
        Self::with_tools(settings, default_registry())
    }

    /// Build an agent with a caller-provided tool registry (tests, custom
    /// tool sets). The AI provider and evidence store come from settings.
    pub fn with_tools(settings: &Settings, registry: ToolRegistry) -> Self {
        let provider = build_provider(&settings.ai);
        let approvals = Arc::new(ApprovalSystem::new());
        let evidence = EvidenceStore::new(settings.workspace.clone());
        let findings = FindingStore::new(settings.workspace.clone());
        let executor = Executor::new(registry, Some(provider))
            .with_evidence(evidence)
            .with_findings(findings)
            .with_approvals(Arc::clone(&approvals));
        Self {
            planner: Planner::new(),
            executor: Arc::new(executor),
            approvals,
        }
    }

    pub fn planner(&self) -> &Planner {
        &self.planner
    }

    pub fn executor(&self) -> &Executor {
        &self.executor
    }

    /// The approval system shared with the executor. Callers may grant or
    /// deny pending approval requests while a task is running.
    pub fn approvals(&self) -> &ApprovalSystem {
        &self.approvals
    }

    /// Run a task end-to-end inside a spawned context, emitting events.
    pub async fn run(
        &self,
        task: &str,
        mut ctx: AgentContext,
        tx: mpsc::Sender<AgentEvent>,
    ) -> anyhow::Result<SessionSummary> {
        let _ = tx.send(AgentEvent::Started).await;
        ctx.memory.push_user(task.to_string());
        tracing::info!(
            session = %ctx.session_id,
            "agent run started task={}",
            truncate(task, 120)
        );
        let plan = self.planner.plan(task, ctx.scope.as_ref());
        let summary = self.executor.execute(&plan, &ctx, &tx).await?;
        tracing::info!(
            session = %ctx.session_id,
            "agent run finished steps={} skipped={} failed={} evidence={} findings={}",
            summary.steps_completed,
            summary.steps_skipped,
            summary.steps_failed,
            summary.evidence,
            summary.findings
        );
        Ok(summary)
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}
