# ANAJAKKH

**ANAJAKKH** is a professional AI-powered Red Team Security Agent built as a
terminal-first application. It is designed to feel like talking to an
intelligent security engineer inside your terminal — not like running a
vulnerability scanner.

Built with Rust: `ratatui` + `crossterm` for the TUI, `tokio` for async
execution, and a provider-agnostic AI layer (OpenAI-compatible APIs, plus a
fully offline `echo` provider).

---

## Status: all phases complete

| Phase | Name        | Status                     |
| ----- | ----------- | -------------------------- |
| 1     | Foundation  | ✅ Rust project, CLI, TUI, event loop, app state, theme, input handling |
| 2     | Agent       | ✅ Agent state, Planner, Executor, AI abstraction, streaming responses |
| 3     | Security    | ✅ Scope, authorization, policy, approval system |
| 4     | Tools       | ✅ Tool registry, Nmap, DNS, HTTP, Filesystem |
| 5     | Evidence    | ✅ Evidence models, storage, parsing, hashing |
| 6     | Findings    | ✅ Finding model, severity, confidence, evidence refs, AI analysis |
| 7     | Sessions    | ✅ Persistence, resume, history (redb, pure-Rust embedded DB) |
| 8     | Reports     | ✅ Markdown, JSON, HTML |
| 9     | Hardening   | ✅ Error UX, redacted logging, security tests, packaging |

Tool execution is gated by three layers: the **scope** validator refuses
out-of-scope targets, the **decision** layer requires an authorized scope,
and the **policy** layer requires explicit operator approval for high-risk
operations. Successful tool results are parsed into **evidence** (SHA-256
hashed, persisted under `<workspace>/evidence/<session>/`). The findings
engine then turns evidence into severity-ranked findings (rule-based
`observed` findings plus AI proposals that are validated so they can never
invent evidence), persisted under `<workspace>/findings/<session>/` and
viewable in the TUI with `Ctrl+F`. Sessions — scope, conversation, plan,
and summary — persist automatically to a `redb` embedded database
(`<workspace>/sessions/sessions.db`); resume with
`anajakkh --resume <id>` or `anajakkh session resume <id>`.

> Note: session storage uses `redb` (a pure-Rust embedded database) rather
> than SQLite, because SQLite's Rust bindings require compiling its C
> library, which this project deliberately avoids (no C toolchain
> dependency).

---

## Quick start

```bash
cargo build
cargo run                 # launch the TUI
cargo run -- init         # create ~/.anajakkh workspace + config
cargo run -- doctor       # environment health check
cargo test
cargo clippy --all-targets
cargo fmt --check
```

The default `anajakkh` command launches the TUI.

### Set up the AI provider (optional)

Copy `config.example.toml` to `<workspace>/config.toml` (default
`~/.anajakkh/config.toml`) or run `anajakkh init`. Then set your API key in
the environment:

```bash
export OPENAI_API_KEY=sk-...
```

Without a key, ANAJAKKH automatically falls back to the **echo provider**, so
the whole pipeline (planning, execution, streaming) works offline.

Any OpenAI-compatible endpoint works — change `base_url` in the config:

```toml
[ai]
provider = "openai"
model = "gpt-4o-mini"
base_url = "https://api.openai.com/v1"
api_key_env = "OPENAI_API_KEY"
```

---

## Using the TUI

```
Welcome to ANAJAKKH

› AI-powered Red Team Security Agent

Getting started:
  1. Type a task for the agent
  2. Define an authorized target / scope (Ctrl+S)
  3. ANAJAKKH plans and executes the assessment
```

### Workflow

1. **Define the authorized scope** — press `Ctrl+S`, enter targets, e.g.
   `example.com, 10.0.0.0/24, !10.0.0.5`, press `Enter`.
2. **Type a task** — e.g. `assess example.com` and press `Enter`.
3. **Watch the agent** — the activity panel shows plan steps updating in real
   time (scope validation, tool steps, evidence collection, analysis), with
   streamed AI output appearing in the conversation. Press `Ctrl+L` to see
   where evidence is stored.

Out-of-scope targets are detected at planning time and blocked; tool steps
without an authorized scope are gated with a clear explanation, and
high-risk operations require explicit approval. Successful tool results are
stored as hashed evidence under `<workspace>/evidence/`.

### Keyboard shortcuts

| Key       | Action                          |
| --------- | ------------------------------- |
| `Enter`   | Send / commit scope             |
| `Esc`     | Cancel task / close help        |
| `Ctrl+C`  | Exit                            |
| `Ctrl+S`  | Define authorized scope         |
| `Ctrl+R`  | Re-run last task                |
| `Ctrl+L`  | Tool logs / evidence            |
| `Ctrl+F`  | Findings                        |
| `Ctrl+T`  | Tools                           || `Ctrl+H`  | Session history                |
| `Ctrl+M`  | Show model                      |
| `Ctrl+?`  | Help                            |
| `↑ / ↓`   | Scroll conversation             |

---

## Architecture

```
src/
├── main.rs            binary entry point
├── lib.rs             library root (modules exposed for tests)
├── cli/               clap CLI: init, doctor, config, scan, session, report
├── app/               app state, event loop, key→action mapping
├── tui/               theme, layout, input line, widgets, screens/chat
├── agent/             planner, executor, memory, context, decision
├── ai/                provider trait, models, prompts, OpenAI + echo clients
├── tools/             tool registry, safe process runner, nmap/dns/http/filesystem
├── security/          scope, authorization, policy, approval
├── evidence/          evidence models, parsing, hashing, storage
├── findings/          finding model, severity, confidence, AI analysis
├── storage/           redb embedded DB, session persistence, resume
└── config/            settings + workspace management
```

Agent pipeline:

```
USER
  ↓
TASK PARSER
  ↓
SCOPE VALIDATOR      ← refuses out-of-scope targets
  ↓
PLANNER              ← structured steps
  ↓
DECISION / POLICY    ← tool steps require an authorized scope
  ↓
TOOL ROUTER          ← routes through the registry (dns, nmap, http, filesystem)
  ↓
EVIDENCE STORE       ← parsed, hashed tool results
  ↓
FINDINGS             ← rule-based + AI, evidence-grounded
  ↓
AI ANALYSIS          ← streamed responses
  ↓
SESSION SAVE         ← scope, conversation, plan, summary
  ↓
SUMMARY → USER
```

---

## CLI commands

| Command                | Status                    |
| ---------------------- | ------------------------- |
| `anajakkh`               | ✅ launches the TUI           |
| `anajakkh init`          | ✅ workspace + config         |
| `anajakkh doctor`        | ✅ environment check          |
| `anajakkh config`        | ✅ show configuration         |
| `anajakkh scan`          | ✅ headless assessment        |
| `anajakkh session list`  | ✅ list persisted sessions    |
| `anajakkh session resume <id>` / `anajakkh --resume <id>` | ✅ resume a session in the TUI |
| `anajakkh report`        | ✅ Markdown, JSON, HTML      |

Workspace layout (`~/.anajakkh` by default, override with `--workspace`):

```
~/.anajakkh/
├── config.toml
├── sessions/
├── evidence/
├── reports/
├── logs/
└── cache/
```

---

## Development

```bash
cargo build             # compile
cargo test              # unit + integration tests (incl. security suite)
cargo clippy --all-targets
cargo fmt --check
cargo run               # run the TUI
cargo build --release   # optimized binary (LTO + strip)
```

## Production hardening

- **Error UX**: raw Rust errors are never the primary UX. Failures print a
  friendly `✗ … failed / Reason: …` message; the full error chain goes to
  the log file.
- **Logging**: structured `tracing` logs land in `<workspace>/logs/anajakkh.log`
  (agent events, tool execution with timing, AI request/response metadata,
  session events). Every line is scrubbed by a redacting writer before it
  hits disk — API keys, `Bearer` tokens, `Authorization` headers,
  `key=value` secrets, and URL userinfo are replaced with `[REDACTED]`
  (`src/logging/`).
- **Security tests**: `tests/security.rs` exercises command injection
  attempts, scope bypass, malformed targets, path traversal (incl. symlink
  escapes), secret leakage, and unauthorized tool execution. Run with
  `cargo test --test security`.
- **Packaging**: `cargo build --release` produces a stripped, LTO-optimized
  binary; `cargo install --path .` installs it as `anajakkh`. See
  [CONTRIBUTING.md](CONTRIBUTING.md) for release notes.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
