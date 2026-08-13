# ANAJAKKH — AI Build Master Prompt

## Role

You are a senior Rust systems engineer, TUI/CLI architect, AI-agent engineer, and application security engineer.

You are building **ANAJAKKH**, a professional AI-powered Red Team Security Agent designed as a terminal-first application.

The goal is to build a production-quality CLI/TUI agent, not a traditional vulnerability scanner.

ANAJAKKH should feel like:

* Claude Code
* OpenCode
* Gemini CLI
* Professional security tooling

but with its own identity and architecture.

---

# 1. Primary Objective

Build ANAJAKKH as a **Rust-first AI Security Agent** with:

* Professional TUI
* AI Agent orchestration
* Tool execution engine
* Authorized scope management
* Planning
* Execution
* Evidence collection
* Findings analysis
* Session memory
* Reports
* Tool logs
* Configuration
* Secure execution controls

The application must be modular and production-ready.

Do not create a fake UI/demo.

Implement real working architecture wherever possible.

---

# 2. Technology Requirements

Use Rust as the primary language.

Recommended stack:

* Rust stable
* ratatui
* crossterm
* tokio
* serde
* serde_json
* reqwest
* sqlx or rusqlite
* tracing
* anyhow
* thiserror
* clap
* uuid
* chrono

Use async architecture with Tokio.

Keep dependencies minimal and justified.

Do not introduce Python unless absolutely necessary.

Do not introduce Node.js for the core application.

---

# 3. Project Architecture

Create a modular architecture similar to:

src/

├── main.rs
├── cli/
│   ├── mod.rs
│   └── commands.rs
│
├── app/
│   ├── mod.rs
│   ├── state.rs
│   ├── events.rs
│   └── actions.rs
│
├── tui/
│   ├── mod.rs
│   ├── layout.rs
│   ├── theme.rs
│   ├── widgets.rs
│   ├── input.rs
│   └── screens/
│
├── agent/
│   ├── mod.rs
│   ├── planner.rs
│   ├── executor.rs
│   ├── memory.rs
│   ├── context.rs
│   └── decision.rs
│
├── ai/
│   ├── mod.rs
│   ├── client.rs
│   ├── provider.rs
│   ├── models.rs
│   └── prompts.rs
│
├── tools/
│   ├── mod.rs
│   ├── registry.rs
│   ├── executor.rs
│   ├── nmap.rs
│   ├── dns.rs
│   ├── http.rs
│   └── filesystem.rs
│
├── security/
│   ├── mod.rs
│   ├── scope.rs
│   ├── authorization.rs
│   ├── policy.rs
│   └── approval.rs
│
├── evidence/
│   ├── mod.rs
│   ├── collector.rs
│   ├── parser.rs
│   └── models.rs
│
├── findings/
│   ├── mod.rs
│   ├── analyzer.rs
│   ├── severity.rs
│   └── models.rs
│
├── reports/
│   ├── mod.rs
│   ├── markdown.rs
│   ├── json.rs
│   └── html.rs
│
├── storage/
│   ├── mod.rs
│   ├── database.rs
│   ├── sessions.rs
│   └── migrations/
│
└── config/
├── mod.rs
└── settings.rs

---

# 4. TUI Design

The default screen must be minimal.

Do NOT build a dashboard with many permanent panels.

Startup experience:

```text
Welcome to ANAJAKKH

› AI-powered Red Team Security Agent

Getting started:

1. Type a task for the agent
2. Define an authorized target / scope
3. ANAJAKKH plans and executes the assessment


──────────────────────────────────────────────────────────────

› Type your message or @path/to/file


~/workspace/assessment                    ● ready    anajakkh-agent

──────────────────────────────────────────────────────────────
```

The main UI should have:

1. Header / branding
2. Conversation area
3. Agent activity
4. Input area
5. Bottom status bar

Keep the interface clean.

Avoid unnecessary borders.

Avoid excessive colors.

Avoid graphical dashboard components.

---

# 5. Agent Session UX

When the user submits:

```text
› Assess the authorized target
```

The agent should display:

```text
● Planning assessment...

  ✓ Scope validated
  ✓ Target discovery
  ● Service enumeration
  ○ Analyze findings
  ○ Generate report

  Tool: nmap
  Status: running...
```

After execution:

```text
✓ Assessment completed

  Hosts        12
  Services     31
  Findings      4
  Evidence     18

› What would you like me to investigate next?
```

The UI must update in real time.

Use asynchronous events instead of blocking the UI thread.

---

# 6. Agent Architecture

Implement the following pipeline:

USER
↓
TASK PARSER
↓
SCOPE VALIDATOR
↓
PLANNER
↓
APPROVAL / POLICY
↓
TOOL ROUTER
↓
TOOL EXECUTION
↓
RESULT PARSER
↓
EVIDENCE STORE
↓
AI ANALYSIS
↓
FINDINGS
↓
REPORT
↓
USER

The Agent must maintain state throughout the session.

---

# 7. Scope & Authorization

This is a critical component.

Every active assessment must have an explicit scope.

Example:

```json
{
  "scope_id": "uuid",
  "targets": [
    "example.com",
    "192.168.1.10"
  ],
  "excluded_targets": [],
  "authorized": true
}
```

Implement:

* target validation
* allowlist
* denylist
* CIDR support
* domain support
* IP support
* exclusions
* authorization state
* dangerous-operation approval

The Agent must refuse execution when the target is outside the authorized scope.

Never silently expand scope.

---

# 8. Tool System

Create a plugin-style Tool Registry.

Example:

```rust
trait SecurityTool {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    async fn execute(&self, context: ToolContext) -> ToolResult;
}
```

Tools should expose structured metadata.

Example:

```text
Tool
├── name
├── description
├── risk_level
├── required_scope
├── input_schema
├── output_schema
└── executor
```

Initial tools:

* Nmap
* DNS lookup
* HTTP inspection
* Filesystem inspection

Design the system so additional tools can be added without modifying the Agent core.

---

# 9. Tool Execution

Never directly concatenate untrusted user input into shell commands.

Use:

* typed arguments
* allowlists
* process spawning
* timeout
* cancellation
* output limits
* exit-code handling
* stderr capture
* structured results

Example:

```text
Tool: nmap
Status: running
Elapsed: 04.2s
```

When finished:

```text
✓ nmap completed

12 hosts
31 services
```

Raw output should be stored separately and accessible through Tool Logs.

---

# 10. AI Layer

Create an abstraction so ANAJAKKH is not locked to one provider.

Example:

```rust
trait AiProvider {
    async fn chat(
        &self,
        request: AiRequest
    ) -> Result<AiResponse>;
}
```

Support configuration such as:

```toml
[ai]
provider = "openai"
model = "..."
base_url = "..."
api_key_env = "OPENAI_API_KEY"
```

Architecture must allow future providers.

The AI layer should support:

* streaming
* structured output
* tool planning
* context
* retries
* timeout
* token limits
* error handling

Never hardcode API keys.

---

# 11. Agent Planning

The Planner converts a user request into structured steps.

Example:

```json
{
  "goal": "Assess authorized target",
  "steps": [
    {
      "id": 1,
      "action": "target_discovery"
    },
    {
      "id": 2,
      "action": "service_enumeration"
    },
    {
      "id": 3,
      "action": "analyze_services"
    },
    {
      "id": 4,
      "action": "generate_findings"
    }
  ]
}
```

The Planner must verify scope before generating executable actions.

---

# 12. Evidence System

Every important tool result should become structured evidence.

Example:

```json
{
  "id": "uuid",
  "type": "service",
  "source": "nmap",
  "target": "authorized-target",
  "data": {},
  "timestamp": "..."
}
```

Evidence should be immutable after collection.

Store:

* source
* target
* timestamp
* tool
* raw output reference
* parsed data
* hashes where appropriate

---

# 13. Findings System

Create a normalized Finding model.

Example:

```json
{
  "id": "uuid",
  "title": "Example Finding",
  "severity": "medium",
  "confidence": 0.91,
  "target": "authorized-target",
  "description": "...",
  "evidence_ids": [],
  "recommendation": "..."
}
```

Support:

* Critical
* High
* Medium
* Low
* Informational

Findings must reference evidence.

Do not allow the AI to invent evidence.

Clearly separate:

* observed evidence
* AI inference
* hypothesis

---

# 14. Session Memory

Implement session state.

Each session should contain:

```text
Session
├── session_id
├── created_at
├── workspace
├── scope
├── conversation
├── plan
├── tool executions
├── evidence
├── findings
└── report
```

Allow:

```text
anajakkh
anajakkh --resume <session-id>
```

---

# 15. Workspace

Support workspace directories.

Example:

```text
~/.anajakkh/

├── config.toml
├── sessions/
├── evidence/
├── reports/
├── logs/
└── cache/
```

Allow the user to specify:

```text
--workspace ./assessment
```

---

# 16. Commands

Implement CLI commands such as:

```text
anajakkh
anajakkh init
anajakkh scan
anajakkh session
anajakkh session list
anajakkh session resume <id>
anajakkh report
anajakkh config
anajakkh doctor
```

The default `anajakkh` command should launch the TUI.

---

# 17. Keyboard Interaction

Implement:

```text
Enter       Send
Esc         Cancel
Ctrl+C      Exit
Ctrl+L      Tool Logs
Ctrl+F      Findings
Ctrl+S      Scope
Ctrl+H      History
Ctrl+T      Tools
Ctrl+M      Model
Ctrl+R      Re-run
Ctrl+?      Help
```

Make keyboard shortcuts configurable later.

---

# 18. Error UX

Never show raw Rust errors directly as the primary UX.

Instead:

```text
✗ Assessment failed

  Reason:
  Nmap executable was not found.

  Suggested action:
  Install nmap and run `anajakkh doctor`.
```

Detailed errors should still be available in logs.

---

# 19. Logging

Use structured logging.

Support:

```text
INFO
WARN
ERROR
DEBUG
TRACE
```

Log:

* Agent events
* Tool execution
* AI requests
* AI responses metadata
* errors
* session events

Never log:

* API keys
* passwords
* secrets
* authentication tokens

---

# 20. Security Requirements

Security is a first-class architectural concern.

Implement:

* explicit authorization
* scope enforcement
* command validation
* process timeouts
* resource limits
* cancellation
* secret redaction
* safe subprocess execution
* audit logging
* dangerous action approval

Do not implement autonomous destructive actions.

Do not bypass authentication or authorization controls.

Do not execute outside the declared assessment scope.

---

# 21. Testing

Create tests for:

### Unit Tests

* Scope validation
* CIDR matching
* Target matching
* Tool registry
* Planner
* Finding parser
* Severity calculation
* Config parsing

### Integration Tests

* Tool execution
* Session persistence
* AI provider
* TUI events
* Report generation

### Security Tests

* command injection attempts
* scope bypass attempts
* malformed targets
* path traversal
* secret leakage
* unauthorized tool execution

---

# 22. Developer Experience

Provide:

```text
README.md
CONTRIBUTING.md
SECURITY.md
LICENSE
Cargo.toml
.env.example
config.example.toml
```

Provide clear development commands:

```bash
cargo build
cargo test
cargo clippy
cargo fmt --check
cargo run
```

The project must compile cleanly.

No placeholder modules that are required by the main application.

No dead architecture.

No fake implementations pretending to work.

---

# 23. Implementation Strategy

Build in phases.

## Phase 1 — Foundation

* Rust project
* CLI
* TUI
* Event loop
* App state
* Theme
* Input handling

## Phase 2 — Agent

* Agent state
* Planner
* Executor
* AI abstraction
* Streaming responses

## Phase 3 — Security

* Scope
* Authorization
* Policy
* Approval system

## Phase 4 — Tools

* Tool Registry
* Nmap
* DNS
* HTTP
* Filesystem

## Phase 5 — Evidence

* Evidence models
* Storage
* Parsing
* Hashing
* References

## Phase 6 — Findings

* Finding model
* Severity
* Confidence
* Evidence references
* AI analysis

## Phase 7 — Sessions

* SQLite
* Session persistence
* Resume
* History

## Phase 8 — Reports

* Markdown
* JSON
* HTML

## Phase 9 — Production Hardening

* Error handling
* Logging
* Security testing
* Performance
* Documentation
* Packaging

---

# 24. Important Development Rule

Do not attempt to build the entire system in one giant file.

Use clean modules and interfaces.

Before implementing a feature:

1. Inspect the existing architecture.
2. Identify the correct module.
3. Implement the smallest complete version.
4. Run tests.
5. Run cargo fmt.
6. Run cargo clippy.
7. Fix errors.
8. Continue to the next phase.

Do not rewrite working components unnecessarily.

Do not change the architecture without a strong reason.

---

# 25. Definition of Done

ANAJAKKH is considered complete when:

* `cargo build` succeeds
* `cargo test` succeeds
* TUI starts successfully
* User can create a session
* User can define an authorized scope
* Agent can receive a task
* Planner creates structured steps
* Policy validates actions
* Tools execute through the registry
* Results are stored as evidence
* AI can analyze structured results
* Findings reference evidence
* Session can be resumed
* Reports can be generated
* Logs are available
* Secrets are protected
* Out-of-scope targets are blocked
* UI remains responsive during tool execution

---

# Final Product Philosophy

ANAJAKKH should feel like:

> "I am talking to an intelligent security engineer inside my terminal."

Not:

> "I am running a vulnerability scanner."

The Agent should communicate intent, progress, evidence, findings, and next actions clearly.

Keep the interface minimal.

Keep the architecture powerful.

Keep execution controlled.

Keep security boundaries explicit.

Build the foundation first, then progressively implement each phase.
