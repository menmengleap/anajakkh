# Security Policy

ANAJAKKH is an AI-powered Red Team Security Agent. Security is a first-class
architectural concern, and this document describes the guarantees we make and
how to report issues.

## Design guarantees

- **Explicit authorization**: every active assessment requires an explicit,
  user-defined authorized scope. Tool steps are refused when no scope is
  defined, and out-of-scope targets detected at planning time are blocked.
- **Scope enforcement**: targets support IPs, domains, CIDR ranges, and
  exclusions (`!target`). Scope matching is implemented and tested
  (`src/security/scope.rs`).
- **No autonomous destructive actions**: the agent never performs destructive
  actions without approval, and never bypasses authentication or
  authorization controls.
- **Safe execution**: the tool executor uses typed arguments, allowlists,
  process spawning (argv-only, never a shell), hard timeouts with kill,
  cancellation, output limits, exit-code handling, and stderr capture — never
  shell string concatenation of untrusted input (`src/tools/process.rs`).
- **Secret protection**: API keys are read from environment variables and are
  never hardcoded or logged. Every log line written to disk passes through a
  redacting writer that scrubs API keys, bearer tokens, authorization
  headers, key/value secrets, and URL userinfo (`src/logging/`).
- **Honest output**: evidence and findings are never invented; observed
  evidence, AI inference, and hypothesis are kept separate.
- **Attack-surface tests**: `tests/security.rs` covers command injection
  attempts, scope bypass, malformed targets, path traversal (including
  symlink escapes), secret leakage, and unauthorized tool execution.

## Reporting a vulnerability

If you find a security issue, **do not open a public issue**. Email the
maintainers or open a private advisory. Include:

- A description of the vulnerability.
- Steps to reproduce.
- Impact assessment.
- Suggested fix (if any).

## Handling

We will acknowledge within 5 business days and aim to ship a fix within 30
days for confirmed issues.

## Scope

This policy covers the ANAJAKKH codebase. The AI providers and external tools
it may integrate with (Nmap, DNS resolvers, etc.) have their own security
policies.
