# Contributing to ANAJAKKH

Thanks for contributing! ANAJAKKH is a security agent, so code quality and
security correctness matter.

## Getting started

```bash
cargo build
cargo test
cargo clippy --all-targets
cargo fmt --check
```

The project must compile cleanly with no warnings, no dead architecture, and
no fake implementations pretending to work.

## Architecture rules

- Follow the module layout in [README.md](README.md).
- Before implementing a feature:
  1. Inspect the existing architecture.
  2. Identify the correct module.
  3. Implement the smallest complete version.
  4. Run tests, `cargo fmt`, `cargo clippy`.
- Never rewrite working components unnecessarily.
- Never change the architecture without a strong reason.

## Phase roadmap

Features are built in phases (see README). Contribute to the current phase or
open an issue to discuss a later one:

- **Phase 3 — Security**: scope enforcement, authorization, policy, approval.
- **Phase 4 — Tools**: Nmap, DNS, HTTP, Filesystem tools behind the existing
  `SecurityTool` trait.
- **Phase 5 — Evidence**: evidence models, storage, parsing, hashing.
- **Phase 6 — Findings**: finding model, severity, confidence, AI analysis.
- **Phase 7 — Sessions**: persistence, resume, history (redb).
- **Phase 8 — Reports**: Markdown, JSON, HTML.
- **Phase 9 — Hardening**: error UX, redacted logging, security tests,
  packaging — complete. Contribute fixes and improvements instead.

## Packaging & releases

- Build an optimized binary with `cargo build --release` (LTO + strip are
  already set in `Cargo.toml`).
- Install locally with `cargo install --path .` — the binary is `anajakkh`.
- For portable Linux binaries, cross-compile against `musl` (e.g. via
  `cargo-zigbuild`) so the binary has no glibc dependency.
- No C toolchain is required to *compile C code*: the dependency tree is
  pure Rust (this is why session storage uses `redb` instead of SQLite's C
  bindings). However, on the `x86_64-pc-windows-gnu` (MinGW) target, crates
  using Windows `raw-dylib` linking (`windows-sys` ≥ 0.59, `windows-link`)
  invoke GNU `dlltool` + `as` at build time. A rustup GNU toolchain alone
  ships a linker-only `dlltool` that cannot run without an assembler, so a
  full MinGW-w64 binutils install is required for fresh builds:

  - `choco install mingw -y` (admin shell), **or**
  - extract a portable winlibs MinGW-w64 build (e.g. to `~/mingw64`) and
    prepend `~/mingw64/bin` to `PATH` before invoking cargo.

  The MSVC (`x86_64-pc-windows-msvc`) toolchain does not have this
  requirement but needs Visual Studio Build Tools for linking.
- Before tagging a release, run the full gate:

  ```bash
  cargo fmt --check
  cargo clippy --all-targets
  cargo test            # includes the security suite
  cargo build --release
  ```

## Security requirements

- Never hardcode API keys or secrets.
- Never log API keys, passwords, or tokens.
- Never bypass authentication or authorization controls.
- Never execute outside the declared assessment scope.
- Tool execution must use typed arguments, allowlists, process spawning,
  timeouts, cancellation, and output limits.
- Add security tests for: command injection, scope bypass, malformed targets,
  path traversal, secret leakage, unauthorized tool execution.

## Tests

- Unit tests live next to the code (`#[cfg(test)]`).
- Integration tests live in `tests/`.
- Every new module should ship with tests for its core behavior.

## Commits

Small, focused commits. Write clear messages describing the change and why.

## Code of conduct

Be respectful. Security tooling is serious — prefer precision over noise.
