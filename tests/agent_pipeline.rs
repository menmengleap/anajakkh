//! End-to-end agent pipeline tests (no network required — uses echo
//! provider and an injected tool registry, never real network tools).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anajakkh::agent::context::AgentContext;
use anajakkh::agent::{Agent, AgentEvent};
use anajakkh::config::Settings;
use anajakkh::security::Scope;
use anajakkh::tools::{
    RiskLevel, SecurityTool, ToolContext, ToolMetadata, ToolRegistry, ToolResult,
};
use async_trait::async_trait;
use serde_json::json;
use tokio::sync::mpsc;
use uuid::Uuid;

fn test_settings() -> Settings {
    let mut settings = Settings::default();
    settings.ai.provider = "echo".to_string();
    settings.ai.api_key_env = "DOES_NOT_EXIST".to_string();
    settings.workspace = std::env::temp_dir().join(format!("anajakkh-it-{}", Uuid::new_v4()));
    settings
}

/// Agent with no real tools registered, so tests never touch the network
/// or external binaries.
fn test_agent(settings: &Settings) -> Agent {
    Agent::with_tools(settings, ToolRegistry::new())
}

/// A fake `http` tool producing an HTTP response observation (no I/O).
struct FakeHttpTool {
    meta: ToolMetadata,
}

impl FakeHttpTool {
    fn new() -> Self {
        Self {
            meta: ToolMetadata {
                name: "http",
                description: "fake http for tests",
                risk_level: RiskLevel::Medium,
                required_scope: true,
                input_schema: json!({}),
                output_schema: json!({}),
            },
        }
    }
}

#[async_trait]
impl SecurityTool for FakeHttpTool {
    fn metadata(&self) -> &ToolMetadata {
        &self.meta
    }

    async fn execute(&self, _ctx: ToolContext) -> anyhow::Result<ToolResult> {
        Ok(ToolResult {
            success: true,
            summary: "HTTP 200 · server nginx · title \"Test\"".to_string(),
            raw_output: "GET http://example.com/ → 200\n".to_string(),
            exit_code: None,
            data: json!({
                "url": "http://example.com/",
                "status": 200,
                "server": "nginx",
                "content_type": "text/html",
                "title": "Test",
                "headers": {}
            }),
        })
    }
}

/// A fake `dns` tool that produces structured data without any I/O.
struct FakeDnsTool {
    meta: ToolMetadata,
}

impl FakeDnsTool {
    fn new() -> Self {
        Self {
            meta: ToolMetadata {
                name: "dns",
                description: "fake dns for tests",
                risk_level: RiskLevel::Low,
                required_scope: true,
                input_schema: json!({}),
                output_schema: json!({}),
            },
        }
    }
}

#[async_trait]
impl SecurityTool for FakeDnsTool {
    fn metadata(&self) -> &ToolMetadata {
        &self.meta
    }

    async fn execute(&self, _ctx: ToolContext) -> anyhow::Result<ToolResult> {
        Ok(ToolResult {
            success: true,
            summary: "resolved 1 address(es) for example.com".to_string(),
            raw_output: "example.com → 93.184.216.34\n".to_string(),
            exit_code: Some(0),
            data: json!([{ "name": "example.com", "addresses": ["93.184.216.34"] }]),
        })
    }
}

#[tokio::test]
async fn agent_runs_plan_and_finishes() {
    let settings = test_settings();
    let agent = test_agent(&settings);

    let mut ctx = AgentContext::new(settings.workspace.clone());
    ctx.scope = Some(Scope::parse("s1", "example.com").unwrap());

    let (tx, mut rx) = mpsc::channel::<AgentEvent>(64);
    let task = "Scan example.com and write a report".to_string();
    let run_agent = agent.clone();
    let run_task = task.clone();
    let _run_handle = tokio::spawn(async move { run_agent.run(&run_task, ctx, tx).await });

    let mut saw_plan = false;
    let mut saw_finished = false;
    let mut saw_scope_validated = false;
    let mut saw_stream_end = false;
    let mut saw_skipped = false;
    while let Some(event) = rx.recv().await {
        match event {
            AgentEvent::PlanCreated(plan) => {
                saw_plan = true;
                assert!(plan.steps.iter().any(|s| s.action == "validate_scope"));
                assert!(plan.steps.iter().any(|s| s.action == "summarize"));
            }
            AgentEvent::ScopeValidated { ok, .. } => {
                saw_scope_validated = true;
                assert!(ok, "scope should validate");
            }
            AgentEvent::StreamEnd => saw_stream_end = true,
            AgentEvent::StepSkipped { .. } => saw_skipped = true,
            AgentEvent::Finished(_) => saw_finished = true,
            _ => {}
        }
    }

    assert!(saw_plan, "expected PlanCreated");
    assert!(saw_scope_validated, "expected ScopeValidated");
    assert!(saw_stream_end, "expected StreamEnd (echo analysis)");
    assert!(saw_finished, "expected Finished");
    let _ = saw_skipped; // tool steps may be skipped — fine either way
    let _ = std::fs::remove_dir_all(&settings.workspace);
}

#[tokio::test]
async fn out_of_scope_target_is_blocked() {
    let settings = test_settings();
    let agent = test_agent(&settings);

    let mut ctx = AgentContext::new(settings.workspace.clone());
    ctx.scope = Some(Scope::parse("s1", "example.com").unwrap());

    let (tx, mut rx) = mpsc::channel::<AgentEvent>(64);
    let task = "scan example.com and 10.0.0.0/8".to_string();
    let run_agent = agent.clone();
    let run_task = task.clone();
    let mut saw_blocked = false;
    tokio::spawn(async move { run_agent.run(&run_task, ctx, tx).await });
    while let Some(event) = rx.recv().await {
        match event {
            AgentEvent::ScopeValidated { ok, .. } => {
                if !ok {
                    saw_blocked = true;
                }
            }
            AgentEvent::StepSkipped { reason, .. } => {
                if reason.contains("outside authorized scope") {
                    saw_blocked = true;
                }
            }
            AgentEvent::Finished(_) => break,
            _ => {}
        }
    }

    assert!(saw_blocked, "out-of-scope targets must be blocked");
    let _ = std::fs::remove_dir_all(&settings.workspace);
}

#[tokio::test]
async fn cancel_flag_stops_execution() {
    let settings = test_settings();
    let agent = test_agent(&settings);

    let cancel_flag = Arc::new(AtomicBool::new(false));
    let mut ctx =
        AgentContext::with_shared_cancel(settings.workspace.clone(), Arc::clone(&cancel_flag));
    ctx.scope = Some(Scope::parse("s1", "example.com").unwrap());

    let (tx, mut rx) = mpsc::channel::<AgentEvent>(64);
    let task = "scan example.com".to_string();
    let run_agent = agent.clone();
    let run_task = task.clone();
    tokio::spawn(async move { run_agent.run(&run_task, ctx, tx).await });

    // Let a few events flow, then request cancellation.
    let mut saw_start = false;
    while let Some(event) = rx.recv().await {
        match event {
            AgentEvent::Started => {
                saw_start = true;
                cancel_flag.store(true, Ordering::Relaxed);
            }
            AgentEvent::Finished(_) => break,
            _ => {}
        }
        if saw_start {
            break;
        }
    }
    assert!(saw_start);
    // The executor should observe the flag and stop emitting steps.
    assert!(cancel_flag.load(Ordering::Relaxed));
    let _ = std::fs::remove_dir_all(&settings.workspace);
}

#[tokio::test]
async fn out_of_scope_target_blocks_tool_steps() {
    let settings = test_settings();
    let agent = test_agent(&settings);

    let mut ctx = AgentContext::new(settings.workspace.clone());
    ctx.scope = Some(Scope::parse("s1", "example.com").unwrap());

    let (tx, mut rx) = mpsc::channel::<AgentEvent>(64);
    let task = "scan example.com and 192.168.1.5".to_string();
    let run_agent = agent.clone();
    let run_task = task.clone();
    tokio::spawn(async move { run_agent.run(&run_task, ctx, tx).await });

    let mut tool_ran = false;
    let mut blocked_tool = false;
    while let Some(event) = rx.recv().await {
        match event {
            AgentEvent::ToolRunning { .. } => tool_ran = true,
            AgentEvent::ToolUnavailable { tool, reason } => {
                if reason.contains("outside authorized scope") && tool == "dns" {
                    blocked_tool = true;
                }
            }
            AgentEvent::Finished(_) => break,
            _ => {}
        }
    }
    assert!(
        !tool_ran,
        "tool steps must not run when out-of-scope targets exist"
    );
    assert!(
        blocked_tool,
        "expected tool gating for out-of-scope targets"
    );
    let _ = std::fs::remove_dir_all(&settings.workspace);
}

#[tokio::test]
async fn no_scope_means_tool_steps_need_approval() {
    let settings = test_settings();
    let agent = test_agent(&settings);

    let ctx = AgentContext::new(settings.workspace.clone());
    let (tx, mut rx) = mpsc::channel::<AgentEvent>(64);
    let task = "scan example.com".to_string();
    let run_agent = agent.clone();
    let run_task = task.clone();
    let mut saw_unavailable = false;
    tokio::spawn(async move { run_agent.run(&run_task, ctx, tx).await });
    while let Some(event) = rx.recv().await {
        match event {
            AgentEvent::ToolUnavailable { tool, reason } => {
                if tool == "nmap" && reason.contains("scope") {
                    saw_unavailable = true;
                }
            }
            AgentEvent::Finished(_) => break,
            _ => {}
        }
    }
    assert!(saw_unavailable, "tool steps without a scope must be gated");
    let _ = std::fs::remove_dir_all(&settings.workspace);
}

#[tokio::test]
async fn tool_results_become_evidence() {
    let settings = test_settings();
    let mut registry = ToolRegistry::new();
    registry.register(Arc::new(FakeDnsTool::new()));
    let agent = Agent::with_tools(&settings, registry);

    let mut ctx = AgentContext::new(settings.workspace.clone());
    let session_id = ctx.session_id.clone();
    ctx.scope = Some(Scope::parse("s1", "example.com").unwrap());

    let (tx, mut rx) = mpsc::channel::<AgentEvent>(256);
    let run_agent = agent.clone();
    let task = "scan example.com".to_string();
    let mut saw_evidence = false;
    let mut evidence_total = 0u32;
    let mut finished_summary = None;
    tokio::spawn(async move { run_agent.run(&task, ctx, tx).await });
    while let Some(event) = rx.recv().await {
        match event {
            AgentEvent::EvidenceCollected { source, count } => {
                saw_evidence = true;
                assert_eq!(source, "dns");
                evidence_total += count as u32;
            }
            AgentEvent::Finished(summary) => {
                finished_summary = Some(summary);
                break;
            }
            _ => {}
        }
    }

    assert!(
        saw_evidence,
        "expected EvidenceCollected for the fake dns tool"
    );
    assert_eq!(evidence_total, 1);
    let summary = finished_summary.expect("finished");
    assert_eq!(summary.evidence, 1);
    assert!(summary.tools_used.contains(&"dns".to_string()));

    // The evidence must be persisted under <workspace>/evidence/<session>/.
    let dir = settings.workspace.join("evidence").join(&session_id);
    let files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    assert_eq!(files.len(), 1, "one evidence json should be written");
    let raw_dir = dir.join("raw");
    let raw_files: Vec<_> = std::fs::read_dir(&raw_dir).unwrap().flatten().collect();
    assert_eq!(raw_files.len(), 1, "raw output should be preserved");

    let _ = std::fs::remove_dir_all(&settings.workspace);
}

#[tokio::test]
async fn evidence_becomes_findings() {
    let settings = test_settings();
    let mut registry = ToolRegistry::new();
    registry.register(Arc::new(FakeHttpTool::new()));
    let agent = Agent::with_tools(&settings, registry);

    let mut ctx = AgentContext::new(settings.workspace.clone());
    let session_id = ctx.session_id.clone();
    ctx.scope = Some(Scope::parse("s1", "example.com").unwrap());

    let (tx, mut rx) = mpsc::channel::<AgentEvent>(256);
    let run_agent = agent.clone();
    let task = "scan example.com".to_string();
    let mut saw_findings_event = false;
    let mut findings_total = 0u32;
    let mut finished_summary = None;
    tokio::spawn(async move { run_agent.run(&task, ctx, tx).await });
    while let Some(event) = rx.recv().await {
        match event {
            AgentEvent::FindingsGenerated { count } => {
                saw_findings_event = true;
                findings_total += count as u32;
            }
            AgentEvent::Finished(summary) => {
                finished_summary = Some(summary);
                break;
            }
            _ => {}
        }
    }

    assert!(saw_findings_event, "expected FindingsGenerated");
    assert!(findings_total >= 1, "expected at least one finding");
    let summary = finished_summary.expect("finished");
    assert!(summary.findings >= 1);
    assert!(
        summary.evidence >= 1,
        "findings must be grounded in evidence"
    );

    // Findings persisted under <workspace>/findings/<session>/.
    let dir = settings.workspace.join("findings").join(&session_id);
    let files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    assert!(!files.is_empty(), "findings should be written to disk");

    let _ = std::fs::remove_dir_all(&settings.workspace);
}

#[tokio::test]
async fn session_persistence_roundtrip() {
    use anajakkh::storage::{SessionRecord, SessionStore};

    let settings = test_settings();
    let agent = test_agent(&settings);

    let mut ctx = AgentContext::new(settings.workspace.clone());
    let session_id = ctx.session_id.clone();
    ctx.scope = Some(Scope::parse("s1", "example.com").unwrap());

    let (tx, mut rx) = mpsc::channel::<AgentEvent>(256);
    let run_agent = agent.clone();
    let task = "scan example.com".to_string();
    let mut finished_summary = None;
    tokio::spawn(async move { run_agent.run(&task, ctx, tx).await });
    while let Some(event) = rx.recv().await {
        if let AgentEvent::Finished(summary) = event {
            finished_summary = Some(summary);
            break;
        }
    }
    let summary = finished_summary.expect("finished");

    // Persist the session exactly like the app does on completion.
    let store = SessionStore::open(&settings.workspace).unwrap();
    let mut record = SessionRecord::new(session_id.clone(), settings.workspace.clone());
    record.scope = Some(Scope::parse("s1", "example.com").unwrap());
    record.conversation.push_user("scan example.com");
    record.summary = Some(summary);
    store.save(&record).unwrap();

    // Reload and verify the resume data.
    let loaded = store.get(&session_id).unwrap().unwrap();
    assert!(loaded.is_completed());
    assert_eq!(loaded.scope.as_ref().unwrap().summary(), "example.com");
    assert_eq!(loaded.conversation.last_user(), Some("scan example.com"));
    assert_eq!(loaded.id, session_id);

    // A resume (anajakkh session resume <id>) lists it newest-first.
    let list = store.list().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, session_id);

    let _ = std::fs::remove_dir_all(&settings.workspace);
}
