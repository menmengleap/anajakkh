//! Executor: runs a plan step-by-step, emitting events for the UI.
//!
//! Each tool-backed step passes three gates before it runs:
//! 1. scope validation (out-of-scope targets are never touched);
//! 2. the decision layer (an authorized scope must exist);
//! 3. the policy layer (high-risk operations require explicit approval).
//!
//! Successful tool results are parsed into structured evidence and stored
//! in the shared [`EvidenceStore`].

use std::collections::HashSet;
use std::sync::Arc;

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::ai::models::AiRequest;
use crate::ai::prompts;
use crate::ai::provider::AiProvider;
use crate::evidence::{parse_tool_output, Evidence, EvidenceStore};
use crate::findings::{Analyzer, FindingStore};
use crate::security::{ApprovalSystem, Policy, PolicyDecision};
use crate::tools::{ToolContext, ToolRegistry, ToolResult};

use super::context::AgentContext;
use super::decision;
use super::planner::Plan;
use super::AgentEvent;

/// Summary of a completed assessment run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionSummary {
    pub steps_total: u32,
    pub steps_completed: u32,
    pub steps_skipped: u32,
    pub steps_failed: u32,
    pub tools_used: Vec<String>,
    pub targets: Vec<String>,
    pub findings: u32,
    pub evidence: u32,
}

pub struct Executor {
    pub registry: ToolRegistry,
    pub provider: Option<Arc<dyn AiProvider>>,
    pub evidence: EvidenceStore,
    pub findings: FindingStore,
    pub policy: Policy,
    pub approvals: Arc<ApprovalSystem>,
}

impl Executor {
    pub fn new(registry: ToolRegistry, provider: Option<Arc<dyn AiProvider>>) -> Self {
        Self {
            registry,
            provider,
            evidence: EvidenceStore::in_memory(),
            findings: FindingStore::in_memory(),
            policy: Policy::default(),
            approvals: Arc::new(ApprovalSystem::new()),
        }
    }

    pub fn with_evidence(mut self, evidence: EvidenceStore) -> Self {
        self.evidence = evidence;
        self
    }

    pub fn with_findings(mut self, findings: FindingStore) -> Self {
        self.findings = findings;
        self
    }

    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    pub fn with_approvals(mut self, approvals: Arc<ApprovalSystem>) -> Self {
        self.approvals = approvals;
        self
    }

    /// Execute every step of `plan`, streaming events to `tx`.
    pub async fn execute(
        &self,
        plan: &Plan,
        ctx: &AgentContext,
        tx: &mpsc::Sender<AgentEvent>,
    ) -> anyhow::Result<SessionSummary> {
        let mut summary = SessionSummary {
            steps_total: plan.steps.len() as u32,
            targets: plan.targets.iter().map(|t| t.display()).collect(),
            ..Default::default()
        };

        let _ = tx.send(AgentEvent::PlanCreated(plan.clone())).await;

        for step in &plan.steps {
            if ctx.is_cancelled() {
                break;
            }
            let _ = tx
                .send(AgentEvent::StepStarted {
                    step_id: step.id,
                    action: step.action.clone(),
                })
                .await;

            match self.execute_step(step, plan, ctx, tx).await {
                Ok(outcome) => {
                    summary.steps_completed += 1;
                    summary.evidence += outcome.evidence_count as u32;
                    summary.findings += outcome.findings_count as u32;
                    if let Some(tool) = outcome.tool_used {
                        if !summary.tools_used.contains(&tool) {
                            summary.tools_used.push(tool);
                        }
                    }
                    let _ = tx
                        .send(AgentEvent::StepCompleted {
                            step_id: step.id,
                            action: step.action.clone(),
                            summary: outcome.summary,
                        })
                        .await;
                }
                Err(StepError::Skipped(reason)) => {
                    summary.steps_skipped += 1;
                    let _ = tx
                        .send(AgentEvent::StepSkipped {
                            step_id: step.id,
                            action: step.action.clone(),
                            reason,
                        })
                        .await;
                }
                Err(StepError::Failed(message)) => {
                    summary.steps_failed += 1;
                    tracing::error!("step {} failed: {message}", step.action);
                    let _ = tx
                        .send(AgentEvent::StepFailed {
                            step_id: step.id,
                            action: step.action.clone(),
                            error: message,
                        })
                        .await;
                }
            }
        }

        let _ = tx.send(AgentEvent::Finished(summary.clone())).await;
        Ok(summary)
    }

    async fn execute_step(
        &self,
        step: &super::planner::PlanStep,
        plan: &Plan,
        ctx: &AgentContext,
        tx: &mpsc::Sender<AgentEvent>,
    ) -> Result<StepOutcome, StepError> {
        match step.action.as_str() {
            "parse_task" => Ok(StepOutcome {
                summary: format!("goal: {}", truncate(&plan.goal, 80)),
                tool_used: None,
                evidence_count: 0,
                findings_count: 0,
            }),

            "validate_scope" => {
                let outcome = match (&ctx.scope, plan.out_of_scope.is_empty()) {
                    (Some(scope), true) => {
                        let message = format!(
                            "targets validated against {} target(s)",
                            scope.targets.len()
                        );
                        let _ = tx
                            .send(AgentEvent::ScopeValidated {
                                ok: true,
                                message: message.clone(),
                            })
                            .await;
                        StepOutcome {
                            summary: message,
                            tool_used: None,
                            evidence_count: 0,
                            findings_count: 0,
                        }
                    }
                    (Some(scope), false) => {
                        let oos: Vec<String> =
                            plan.out_of_scope.iter().map(|t| t.display()).collect();
                        let message = format!(
                            "blocked: target(s) outside authorized scope: {}",
                            oos.join(", ")
                        );
                        let _ = tx
                            .send(AgentEvent::ScopeValidated {
                                ok: false,
                                message: message.clone(),
                            })
                            .await;
                        tracing::warn!("{message} (scope {})", scope.scope_id);
                        return Err(StepError::Skipped(message));
                    }
                    (None, _) => {
                        let message =
                            "no authorized scope defined — press Ctrl+S to set one".to_string();
                        let _ = tx
                            .send(AgentEvent::ScopeValidated {
                                ok: false,
                                message: message.clone(),
                            })
                            .await;
                        return Err(StepError::Skipped(message));
                    }
                };
                Ok(outcome)
            }

            "analyze" => {
                let text = self
                    .analyze(plan, ctx, tx)
                    .await
                    .map_err(|e| StepError::Failed(format!("analysis failed: {e}")))?;
                Ok(StepOutcome {
                    summary: format!("analysis produced {} chars", text.chars().count()),
                    tool_used: None,
                    evidence_count: 0,
                    findings_count: 0,
                })
            }

            "summarize" => {
                let text = self.summarize(plan, ctx, tx).await;
                Ok(StepOutcome {
                    summary: truncate(&text, 80),
                    tool_used: None,
                    evidence_count: 0,
                    findings_count: 0,
                })
            }

            "generate_findings" => {
                let count = self.generate_findings(plan, ctx, tx).await;
                Ok(StepOutcome {
                    summary: format!("{count} finding(s) generated"),
                    tool_used: None,
                    evidence_count: 0,
                    findings_count: count,
                })
            }

            "generate_report" => match self.generate_report(ctx, tx).await {
                Some(path) => Ok(StepOutcome {
                    summary: format!("report written to {}", path.display()),
                    tool_used: None,
                    evidence_count: 0,
                    findings_count: 0,
                }),
                None => Err(StepError::Skipped(
                    "nothing to report — no evidence collected".to_string(),
                )),
            },

            // Tool-backed steps.
            _ => {
                let tool_name = step.requires_tool.as_deref().unwrap_or("unknown");
                // Never route tool steps when known targets are out of scope.
                if !plan.out_of_scope.is_empty() {
                    let oos: Vec<String> = plan.out_of_scope.iter().map(|t| t.display()).collect();
                    let reason = format!(
                        "refusing to run `{tool_name}`: target(s) outside authorized scope: {}",
                        oos.join(", ")
                    );
                    let _ = tx
                        .send(AgentEvent::ToolUnavailable {
                            tool: tool_name.to_string(),
                            reason: reason.clone(),
                        })
                        .await;
                    return Err(StepError::Skipped(reason));
                }
                match decision::evaluate(step, ctx.scope.as_ref()) {
                    decision::Decision::Proceed => {
                        // Policy gate: high-risk operations need approval.
                        match self.policy.evaluate_with_approvals(
                            tool_name,
                            step.risk,
                            &self.approvals,
                        ) {
                            PolicyDecision::Allow => self.run_tool(tool_name, plan, ctx, tx).await,
                            PolicyDecision::RequireApproval(reason) => {
                                let operation = format!("tool:{tool_name}");
                                let _ = tx
                                    .send(AgentEvent::ApprovalRequired {
                                        operation: operation.clone(),
                                        reason: reason.clone(),
                                    })
                                    .await;
                                let _ = tx
                                    .send(AgentEvent::ToolUnavailable {
                                        tool: tool_name.to_string(),
                                        reason: reason.clone(),
                                    })
                                    .await;
                                Err(StepError::Skipped(reason))
                            }
                            PolicyDecision::Deny(reason) => {
                                let _ = tx
                                    .send(AgentEvent::ToolUnavailable {
                                        tool: tool_name.to_string(),
                                        reason: reason.clone(),
                                    })
                                    .await;
                                Err(StepError::Skipped(reason))
                            }
                        }
                    }
                    decision::Decision::NeedsApproval(reason) => {
                        let _ = tx
                            .send(AgentEvent::ToolUnavailable {
                                tool: tool_name.to_string(),
                                reason: reason.clone(),
                            })
                            .await;
                        Err(StepError::Skipped(reason))
                    }
                    decision::Decision::Blocked(reason) => Err(StepError::Skipped(reason)),
                }
            }
        }
    }

    async fn run_tool(
        &self,
        tool_name: &str,
        plan: &Plan,
        ctx: &AgentContext,
        tx: &mpsc::Sender<AgentEvent>,
    ) -> Result<StepOutcome, StepError> {
        let Some(tool) = self.registry.get(tool_name) else {
            let reason = format!("tool `{tool_name}` is not registered in this build");
            let _ = tx
                .send(AgentEvent::ToolUnavailable {
                    tool: tool_name.to_string(),
                    reason: reason.clone(),
                })
                .await;
            return Err(StepError::Skipped(reason));
        };

        // Pick the first in-scope target from the task; fall back to the
        // first scope target so "assess the authorized target" works.
        let target = plan
            .targets
            .iter()
            .find(|t| ctx.scope.as_ref().map(|s| s.contains(t)).unwrap_or(false))
            .or_else(|| ctx.scope.as_ref().and_then(|s| s.targets.first()))
            .map(|t| t.display());

        let _ = tx
            .send(AgentEvent::ToolRunning {
                tool: tool_name.to_string(),
            })
            .await;
        let context = ToolContext {
            args: serde_json::json!({}),
            scope_id: ctx.scope.as_ref().map(|s| s.scope_id.clone()),
            target: target.clone(),
            workspace: Some(ctx.workspace.clone()),
        };
        let started = std::time::Instant::now();
        tracing::info!(
            "tool {tool_name} starting target={}",
            target.as_deref().unwrap_or("—")
        );
        match tool.execute(context).await {
            Ok(result) => {
                tracing::info!(
                    "tool {tool_name} finished success={} summary={} elapsed_ms={}",
                    result.success,
                    result.summary,
                    started.elapsed().as_millis()
                );
                if result.success {
                    let evidence_count = self
                        .collect_evidence(tool_name, target, &result, ctx, tx)
                        .await;
                    let _ = tx
                        .send(AgentEvent::ToolCompleted {
                            tool: tool_name.to_string(),
                            summary: result.summary.clone(),
                        })
                        .await;
                    Ok(StepOutcome {
                        summary: result.summary,
                        tool_used: Some(tool_name.to_string()),
                        evidence_count,
                        findings_count: 0,
                    })
                } else {
                    // Failed run: report it, but never record error output as evidence.
                    let _ = tx
                        .send(AgentEvent::ToolUnavailable {
                            tool: tool_name.to_string(),
                            reason: result.summary.clone(),
                        })
                        .await;
                    Err(StepError::Failed(format!(
                        "tool `{tool_name}` failed: {}",
                        result.summary
                    )))
                }
            }
            Err(err) => {
                tracing::warn!(
                    "tool {tool_name} error target={} elapsed_ms={}: {err}",
                    target.as_deref().unwrap_or("—"),
                    started.elapsed().as_millis()
                );
                let _ = tx
                    .send(AgentEvent::ToolUnavailable {
                        tool: tool_name.to_string(),
                        reason: err.to_string(),
                    })
                    .await;
                Err(StepError::Failed(format!(
                    "tool `{tool_name}` error: {err}"
                )))
            }
        }
    }

    /// Parse a tool result into evidence, persist raw output, and emit a
    /// collection event. Never fails the step: evidence problems are logged.
    async fn collect_evidence(
        &self,
        tool_name: &str,
        target: Option<String>,
        result: &ToolResult,
        ctx: &AgentContext,
        tx: &mpsc::Sender<AgentEvent>,
    ) -> usize {
        let target = target.unwrap_or_default();
        let raw_ref = match self.evidence.save_raw(&ctx.session_id, &result.raw_output) {
            Ok(Some(path)) => Some(path.display().to_string()),
            _ => None,
        };

        let mut items = parse_tool_output(tool_name, &target, &result.raw_output, &result.data);
        let count = items.len();
        for item in items.iter_mut() {
            item.raw_ref = raw_ref.clone();
            if let Err(err) = self.evidence.record(&ctx.session_id, item.clone()) {
                tracing::warn!("failed to store evidence: {err}");
            }
        }
        if count > 0 {
            let _ = tx
                .send(AgentEvent::EvidenceCollected {
                    source: tool_name.to_string(),
                    count,
                })
                .await;
        }
        count
    }

    /// Generate findings from the collected evidence: rule-based first,
    /// then AI-assisted proposals validated against the real evidence.
    /// Findings are deduplicated, sorted by severity, and persisted.
    async fn generate_findings(
        &self,
        plan: &Plan,
        ctx: &AgentContext,
        tx: &mpsc::Sender<AgentEvent>,
    ) -> usize {
        let evidence = self.evidence.all();
        let mut findings = Analyzer::new().rule_based(&evidence);

        if let Some(provider) = &self.provider {
            match self.ai_findings(provider, plan, &evidence).await {
                Ok(proposals) => {
                    let valid: HashSet<String> = evidence.iter().map(|e| e.id.clone()).collect();
                    findings.extend(Analyzer::parse_ai_findings(&proposals, &valid));
                }
                Err(err) => tracing::warn!("AI findings analysis failed: {err}"),
            }
        }

        // Deduplicate by (target, title) and sort most severe first.
        let mut seen = HashSet::new();
        findings.retain(|f| seen.insert((f.target.clone(), f.title.clone())));
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.target.cmp(&b.target))
        });

        let count = findings.len();
        for finding in &findings {
            if let Err(err) = self.findings.record(&ctx.session_id, finding.clone()) {
                tracing::warn!("failed to store finding: {err}");
            }
        }
        if count > 0 {
            let _ = tx.send(AgentEvent::FindingsGenerated { count }).await;
        }
        count
    }

    /// Generate a report from the collected evidence and findings, writing
    /// Markdown, JSON, and HTML under `<workspace>/reports/`. Returns the
    /// markdown path (or `None` when there is nothing to report).
    async fn generate_report(
        &self,
        ctx: &AgentContext,
        tx: &mpsc::Sender<AgentEvent>,
    ) -> Option<std::path::PathBuf> {
        let evidence = self.evidence.all();
        let findings = self.findings.all();
        if evidence.is_empty() && findings.is_empty() {
            return None;
        }
        let targets: Vec<String> = ctx
            .scope
            .as_ref()
            .map(|s| s.targets.iter().map(|t| t.display()).collect())
            .unwrap_or_default();
        let report = crate::reports::Report::new(
            &ctx.session_id,
            ctx.workspace.clone(),
            ctx.scope.clone(),
            targets,
            None,
            evidence,
            findings,
        );
        match crate::reports::write_all(&ctx.workspace, &ctx.session_id, &report) {
            Ok(paths) => {
                let first = paths.first().cloned();
                if let Some(path) = &first {
                    let _ = tx
                        .send(AgentEvent::ReportGenerated {
                            path: path.display().to_string(),
                        })
                        .await;
                }
                first
            }
            Err(err) => {
                tracing::warn!("failed to write report: {err}");
                None
            }
        }
    }

    /// Ask the provider for structured findings over a compact evidence
    /// summary. Non-streaming — the response is parsed as JSON.
    async fn ai_findings(
        &self,
        provider: &Arc<dyn AiProvider>,
        plan: &Plan,
        evidence: &[Evidence],
    ) -> anyhow::Result<String> {
        if evidence.is_empty() {
            return Ok(String::new());
        }
        let summary: Vec<String> = evidence
            .iter()
            .take(100)
            .map(|e| {
                format!(
                    "- {} | {} | target={} | {}",
                    e.id,
                    e.r#type.as_str(),
                    e.target,
                    serde_json::to_string(&e.data).unwrap_or_default()
                )
            })
            .collect();
        let prompt = prompts::findings_prompt(&plan.goal, &summary.join("\n"));
        let request = AiRequest::new(
            provider.model().to_string(),
            vec![
                crate::ai::models::AiMessage::system(prompts::system_prompt()),
                crate::ai::models::AiMessage::user(prompt),
            ],
        );
        let response = provider.chat(request).await?;
        Ok(response.content)
    }

    /// Stream an AI analysis of the plan/results into the event channel.
    async fn analyze(
        &self,
        plan: &Plan,
        ctx: &AgentContext,
        tx: &mpsc::Sender<AgentEvent>,
    ) -> anyhow::Result<String> {
        let Some(provider) = &self.provider else {
            return Ok(String::new());
        };
        let completed: Vec<&str> = plan
            .steps
            .iter()
            .filter(|s| s.requires_tool.is_none())
            .map(|s| s.action.as_str())
            .collect();
        let context = format!(
            "targets: {} | evidence collected: {} records",
            plan.targets
                .iter()
                .map(|t| t.display())
                .collect::<Vec<_>>()
                .join(", "),
            self.evidence.len(),
        );
        let prompt = prompts::analysis_prompt(&plan.goal, &completed.join(", "), &context);
        let mut memory = ctx.memory.clone();
        memory.push_user(prompt);
        let request = AiRequest::new(
            provider.model().to_string(),
            memory.to_ai_messages(&prompts::system_prompt()),
        );
        let started = std::time::Instant::now();
        let mut stream = provider.stream_chat(request).await?;

        let mut full = String::new();
        while let Some(chunk) = stream.next().await {
            if ctx.is_cancelled() {
                break;
            }
            match chunk {
                Ok(text) => {
                    full.push_str(&text);
                    let _ = tx.send(AgentEvent::StreamChunk(text)).await;
                }
                Err(err) => {
                    tracing::warn!("ai stream chunk error: {err}");
                    break;
                }
            }
        }
        tracing::info!(
            "ai analysis stream finished chars={} elapsed_ms={}",
            full.chars().count(),
            started.elapsed().as_millis()
        );
        let _ = tx.send(AgentEvent::StreamEnd).await;
        Ok(full)
    }

    /// Produce a plain-text summary of the run.
    async fn summarize(
        &self,
        _plan: &Plan,
        _ctx: &AgentContext,
        tx: &mpsc::Sender<AgentEvent>,
    ) -> String {
        let evidence_count = self.evidence.len();
        let text = format!(
            "Assessment complete. {} evidence record(s) collected. Full tool output and evidence are stored under the workspace `evidence/` directory.",
            evidence_count
        );
        let _ = tx.send(AgentEvent::StreamChunk(text.clone())).await;
        let _ = tx.send(AgentEvent::StreamEnd).await;
        text
    }
}

struct StepOutcome {
    summary: String,
    tool_used: Option<String>,
    evidence_count: usize,
    findings_count: usize,
}

enum StepError {
    Skipped(String),
    Failed(String),
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}…")
    }
}
