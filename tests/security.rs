//! Security-focused test suite (INFO.md §21).
//!
//! Consolidates the attack-surface guarantees: command injection attempts,
//! scope bypass attempts, malformed targets, path traversal, secret
//! leakage, and unauthorized tool execution. Every test runs offline.

use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anajakkh::agent::context::AgentContext;
use anajakkh::agent::executor::Executor;
use anajakkh::agent::{Agent, AgentEvent};
use anajakkh::config::Settings;
use anajakkh::evidence::EvidenceStore;
use anajakkh::findings::FindingStore;
use anajakkh::logging::RedactingWriter;
use anajakkh::security::{ApprovalSystem, Scope, Target};
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
    settings.workspace = std::env::temp_dir().join(format!("anajakkh-sec-{}", Uuid::new_v4()));
    settings
}

/// A tool that records how many times `execute` was actually invoked.
/// Registered under a real tool name so the planner routes to it.
struct SpyTool {
    meta: ToolMetadata,
    calls: Arc<AtomicUsize>,
}

impl SpyTool {
    fn named(name: &'static str, risk: RiskLevel) -> Self {
        Self {
            meta: ToolMetadata {
                name,
                description: "spy tool for security tests",
                risk_level: risk,
                required_scope: true,
                input_schema: json!({}),
                output_schema: json!({}),
            },
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait]
impl SecurityTool for SpyTool {
    fn metadata(&self) -> &ToolMetadata {
        &self.meta
    }

    async fn execute(&self, _ctx: ToolContext) -> anyhow::Result<ToolResult> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ToolResult {
            success: true,
            summary: "spy executed".to_string(),
            raw_output: "spy output\n".to_string(),
            exit_code: Some(0),
            data: json!({}),
        })
    }
}

/// Run an agent to completion, returning every event it emitted.
async fn run_agent(agent: Agent, task: &str, scope: Option<Scope>) -> Vec<AgentEvent> {
    let settings = test_settings();
    let mut ctx = AgentContext::new(settings.workspace.clone());
    ctx.scope = scope;
    let (tx, mut rx) = mpsc::channel::<AgentEvent>(256);
    let run_agent = agent.clone();
    let run_task = task.to_string();
    tokio::spawn(async move { run_agent.run(&run_task, ctx, tx).await });
    let mut events = Vec::new();
    while let Some(event) = rx.recv().await {
        let finished = matches!(event, AgentEvent::Finished(_));
        events.push(event);
        if finished {
            break;
        }
    }
    let _ = std::fs::remove_dir_all(&settings.workspace);
    events
}

// ---------------------------------------------------------------------------
// Malformed targets
// ---------------------------------------------------------------------------

#[test]
fn malformed_targets_are_rejected() {
    for bad in [
        "",
        " ",
        "http://example.com",
        "example.com/path",
        "example.com:443",
        "10.0.0.1; rm -rf /",
        "10.0.0.1 | cat /etc/passwd",
        "example.com & curl evil.sh",
        "$(touch /tmp/pwned)",
        "`id`",
        "999.1.1.1",
        "10.0.0.0/33",
        "10.0.0.0/abc",
        "exa mple.com",
        "-example.com",
        "example..com",
        "..",
        "../../etc/passwd",
    ] {
        assert!(
            Target::parse(bad).is_err(),
            "target `{bad}` must be rejected"
        );
    }
}

#[test]
fn task_text_cannot_smuggle_metacharacters_as_targets() {
    // `from_task` must only extract well-formed targets.
    let targets = Target::from_task("scan example.com; rm -rf / and http://evil.example/x");
    let displayed: Vec<String> = targets.iter().map(Target::display).collect();
    assert_eq!(displayed, vec!["example.com".to_string()]);
}

// ---------------------------------------------------------------------------
// Scope bypass attempts
// ---------------------------------------------------------------------------

#[test]
fn scope_bypass_attempts_fail() {
    let scope = Scope::parse("s1", "10.0.0.0/8, example.com, !10.0.0.5").unwrap();

    // Excluded target is not authorized.
    assert!(!scope.contains(&Target::parse("10.0.0.5").unwrap()));
    // Out-of-scope CIDR is not authorized.
    assert!(!scope.contains(&Target::parse("11.0.0.1").unwrap()));
    // Domain suffix confusion (notexample.com) is not authorized.
    assert!(!scope.contains(&Target::parse("notexample.com").unwrap()));
    // A scope without explicit authorization allows nothing.
    let mut revoked = Scope::parse("s2", "example.com").unwrap();
    revoked.revoke();
    assert!(!revoked.contains(&Target::parse("example.com").unwrap()));

    // out_of_scope reports the offending targets.
    let oos = scope.out_of_scope(&[
        Target::parse("10.0.0.5").unwrap(),
        Target::parse("example.com").unwrap(),
        Target::parse("172.16.0.1").unwrap(),
    ]);
    let displayed: Vec<String> = oos.iter().map(Target::display).collect();
    assert_eq!(
        displayed,
        vec!["10.0.0.5".to_string(), "172.16.0.1".to_string()]
    );
}

#[tokio::test]
async fn out_of_scope_target_never_reaches_a_tool() {
    let spy = SpyTool::named("dns", RiskLevel::Low);
    let calls = Arc::clone(&spy.calls);
    let mut registry = ToolRegistry::new();
    registry.register(Arc::new(spy));
    let agent = Agent::with_tools(&test_settings(), registry);

    let scope = Scope::parse("s1", "example.com").unwrap();
    let events = run_agent(agent, "scan example.com and 10.0.0.5", Some(scope)).await;

    assert_eq!(calls.load(Ordering::SeqCst), 0, "tool must never run");
    let gated = events.iter().any(|e| match e {
        AgentEvent::ToolUnavailable { tool, reason } => {
            tool == "dns" && reason.contains("outside authorized scope")
        }
        _ => false,
    });
    assert!(gated, "tool gating must explain the out-of-scope block");
}

#[tokio::test]
async fn no_scope_means_no_tool_execution() {
    let spy = SpyTool::named("dns", RiskLevel::Low);
    let calls = Arc::clone(&spy.calls);
    let mut registry = ToolRegistry::new();
    registry.register(Arc::new(spy));
    let agent = Agent::with_tools(&test_settings(), registry);

    let events = run_agent(agent, "scan example.com", None).await;

    assert_eq!(calls.load(Ordering::SeqCst), 0, "tool must never run");
    let gated = events.iter().any(|e| match e {
        AgentEvent::ToolUnavailable { tool, reason } => tool == "dns" && reason.contains("scope"),
        _ => false,
    });
    assert!(
        gated,
        "no-scope tool steps must be gated with an explanation"
    );
}

#[tokio::test]
async fn unapproved_high_risk_operation_is_gated() {
    // Hand-built plan with a High-risk tool step; default policy requires
    // explicit approval for High risk. The tool must not run.
    let spy = SpyTool::named("dns", RiskLevel::High);
    let calls = Arc::clone(&spy.calls);
    let mut registry = ToolRegistry::new();
    registry.register(Arc::new(spy));

    let workspace = test_settings().workspace;
    let executor = Executor::new(registry, None)
        .with_evidence(EvidenceStore::new(workspace.clone()))
        .with_findings(FindingStore::new(workspace.clone()))
        .with_approvals(Arc::new(ApprovalSystem::new()));

    let plan = anajakkh::agent::Plan {
        goal: "run a high risk operation".to_string(),
        steps: vec![anajakkh::agent::PlanStep {
            id: 1,
            action: "custom_high_risk".to_string(),
            description: "high risk operation".to_string(),
            requires_tool: Some("dns".to_string()),
            risk: RiskLevel::High,
        }],
        targets: vec![Target::parse("example.com").unwrap()],
        out_of_scope: Vec::new(),
    };
    let mut ctx = AgentContext::new(workspace);
    ctx.scope = Some(Scope::parse("s1", "example.com").unwrap());
    let (tx, mut rx) = mpsc::channel::<AgentEvent>(64);
    let sender = tx.clone();
    let summary = executor.execute(&plan, &ctx, &sender).await.unwrap();

    assert_eq!(calls.load(Ordering::SeqCst), 0, "tool must not run");
    assert_eq!(summary.steps_skipped, 1);
    let mut saw_approval_required = false;
    while let Ok(event) = rx.try_recv() {
        if let AgentEvent::ApprovalRequired { operation, .. } = event {
            assert_eq!(operation, "tool:dns");
            saw_approval_required = true;
        }
    }
    assert!(saw_approval_required, "expected an approval-required event");
    let _ = std::fs::remove_dir_all(&ctx.workspace);
}

#[tokio::test]
async fn approved_high_risk_operation_runs() {
    // Same as above, but the operation is explicitly approved by an
    // operator first — the policy layer must then allow it.
    let spy = SpyTool::named("dns", RiskLevel::High);
    let calls = Arc::clone(&spy.calls);
    let mut registry = ToolRegistry::new();
    registry.register(Arc::new(spy));

    let mut system = ApprovalSystem::new();
    let req = system.request("tool:dns", "dns", RiskLevel::High, "authorized test");
    system.approve(&req.id, "operator").unwrap();

    let workspace = test_settings().workspace;
    let executor = Executor::new(registry, None)
        .with_evidence(EvidenceStore::new(workspace.clone()))
        .with_findings(FindingStore::new(workspace.clone()))
        .with_approvals(Arc::new(system));

    let plan = anajakkh::agent::Plan {
        goal: "run an approved high risk operation".to_string(),
        steps: vec![anajakkh::agent::PlanStep {
            id: 1,
            action: "custom_high_risk".to_string(),
            description: "approved operation".to_string(),
            requires_tool: Some("dns".to_string()),
            risk: RiskLevel::High,
        }],
        targets: vec![Target::parse("example.com").unwrap()],
        out_of_scope: Vec::new(),
    };
    let mut ctx = AgentContext::new(workspace);
    ctx.scope = Some(Scope::parse("s1", "example.com").unwrap());
    let (tx, _rx) = mpsc::channel::<AgentEvent>(64);
    let summary = executor.execute(&plan, &ctx, &tx).await.unwrap();

    assert_eq!(calls.load(Ordering::SeqCst), 1, "approved tool must run");
    assert_eq!(summary.steps_completed, 1);
    assert_eq!(summary.steps_skipped, 0);
    let _ = std::fs::remove_dir_all(&ctx.workspace);
}

// ---------------------------------------------------------------------------
// Command injection
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[tokio::test]
async fn malicious_argument_is_passed_literally_not_executed() {
    use std::time::Duration;

    use anajakkh::tools::process;

    let marker = std::env::temp_dir().join(format!("anajakkh-inject-{}.txt", Uuid::new_v4()));
    let payload = format!("safe; touch {}", marker.display());

    let output = process::run(process::CommandSpec {
        program: "echo",
        args: vec![payload.clone()],
        timeout: Duration::from_secs(5),
        max_output_bytes: 4096,
    })
    .await
    .unwrap();

    // The argv is echoed verbatim — no shell is involved, so the `;` and
    // the command after it must never be executed.
    assert_eq!(output.stdout.trim(), payload);
    assert!(
        !marker.exists(),
        "shell metacharacters in arguments must not be executed"
    );
}

// ---------------------------------------------------------------------------
// Path traversal
// ---------------------------------------------------------------------------

#[tokio::test]
async fn path_traversal_is_blocked() {
    let dir = std::env::temp_dir().join(format!("anajakkh-traversal-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();

    let tool = anajakkh::tools::filesystem::FilesystemTool::new();
    for attempt in [
        "../../etc/passwd",
        "..\\..\\windows\\system32",
        "/etc/passwd",
    ] {
        let result = tool
            .execute(ToolContext {
                args: json!({ "path": attempt }),
                scope_id: None,
                target: None,
                workspace: Some(dir.clone()),
            })
            .await
            .unwrap();
        assert!(!result.success, "traversal `{attempt}` must be refused");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_escape_is_blocked() {
    let dir = std::env::temp_dir().join(format!("anajakkh-symlink-{}", Uuid::new_v4()));
    let outside = std::env::temp_dir().join(format!("anajakkh-outside-{}.txt", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(&outside, "secret outside the workspace").unwrap();
    std::os::unix::fs::symlink(&outside, dir.join("link")).unwrap();

    let tool = anajakkh::tools::filesystem::FilesystemTool::new();
    for action in ["read", "hash"] {
        let result = tool
            .execute(ToolContext {
                args: json!({ "action": action, "path": "link" }),
                scope_id: None,
                target: None,
                workspace: Some(dir.clone()),
            })
            .await
            .unwrap();
        assert!(
            !result.success,
            "symlink escape via `{action}` must be refused: {}",
            result.summary
        );
    }

    std::fs::remove_dir_all(&dir).unwrap();
    let _ = std::fs::remove_file(&outside);
}

// ---------------------------------------------------------------------------
// Secret leakage
// ---------------------------------------------------------------------------

#[test]
fn redaction_scrubs_secrets_from_log_lines() {
    use anajakkh::logging::redact;

    // The Authorization header consumes the rest of the line, so the
    // following api_key and password are scrubbed in the same pass.
    let line = "request Authorization: Bearer abc.def.ghi api_key=sk-live-999 password: hunter2";
    let out = redact(line);
    assert!(!out.contains("abc.def.ghi"));
    assert!(!out.contains("sk-live-999"));
    assert!(!out.contains("hunter2"));
    assert!(out.contains("[REDACTED]"));

    // Without a header, each assignment is scrubbed individually.
    let out = redact("api_key=sk-live-999 password: hunter2");
    assert!(!out.contains("sk-live-999"));
    assert!(!out.contains("hunter2"));
    assert_eq!(out.matches("[REDACTED]").count(), 2);
}

#[test]
fn log_file_never_contains_secrets() {
    let path = std::env::temp_dir().join(format!("anajakkh-redact-{}.log", Uuid::new_v4()));
    {
        let file = std::fs::File::create(&path).unwrap();
        let mut writer = RedactingWriter::new(file);
        // A secret split across writes, plus one on a full line.
        writer
            .write_all(b"token=supersecret123 and api_key=sk-")
            .unwrap();
        writer.write_all(b"abc456def end\n").unwrap();
        writer.flush().unwrap();
    }
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains("supersecret123"));
    assert!(!text.contains("sk-abc456def"));
    assert!(text.contains("[REDACTED]"));
    assert!(text.contains("end"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn config_display_shows_env_name_not_key() {
    // The config surface must only ever reference the environment variable
    // name, never the key value itself.
    let mut settings = test_settings();
    settings.ai.api_key_env = "OPENAI_API_KEY".to_string();
    // Simulate the config command output (which prints api_key_env).
    let printed = format!(
        "provider={} model={} base_url={} api_key_env={}",
        settings.ai.provider, settings.ai.model, settings.ai.base_url, settings.ai.api_key_env
    );
    assert!(printed.contains("OPENAI_API_KEY"));
    // If a caller holds a real key, it must come from the env, not config.
    std::env::remove_var("OPENAI_API_KEY");
    assert!(settings.api_key().is_none());
}
