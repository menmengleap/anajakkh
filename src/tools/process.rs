//! Safe subprocess execution for tools.
//!
//! Rules enforced here:
//! - arguments are passed as an argv vector — never through a shell, so
//!   untrusted input cannot inject commands;
//! - arguments containing NUL bytes are rejected;
//! - every process runs under a hard timeout and is killed on expiry;
//! - stdout/stderr are captured separately with a byte cap;
//! - the child is killed if the parent drops it (`kill_on_drop`).

use std::time::Duration;

use std::process::Stdio;
use thiserror::Error;

use tokio::io::AsyncReadExt;
use tokio::process::Command;

/// Description of a command to run.
#[derive(Debug, Clone)]
pub struct CommandSpec {
    /// Executable name or path.
    pub program: &'static str,
    /// Typed argument vector (never shell-expanded).
    pub args: Vec<String>,
    /// Hard timeout; the process is killed when it elapses.
    pub timeout: Duration,
    /// Maximum captured bytes per stream.
    pub max_output_bytes: usize,
}

/// Captured process output.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    /// `None` when the process was killed by the timeout.
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    /// True when a stream exceeded `max_output_bytes` and was cut off.
    pub truncated: bool,
}

#[derive(Debug, Error)]
pub enum ProcessError {
    #[error("failed to spawn `{program}`: {source}")]
    Spawn {
        program: String,
        source: std::io::Error,
    },
    #[error("invalid argument for `{program}`: {message}")]
    InvalidArgument { program: String, message: String },
    #[error("`{program}` failed to finish: {source}")]
    Run {
        program: String,
        source: std::io::Error,
    },
}

impl ProcessError {
    /// The program name involved in the error.
    pub fn program(&self) -> &str {
        match self {
            ProcessError::Spawn { program, .. }
            | ProcessError::InvalidArgument { program, .. }
            | ProcessError::Run { program, .. } => program,
        }
    }

    /// True when the executable itself could not be found.
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            ProcessError::Spawn { source, .. } if source.kind() == std::io::ErrorKind::NotFound
        )
    }
}

/// Run a command with the safety guarantees above.
pub async fn run(spec: CommandSpec) -> Result<CommandOutput, ProcessError> {
    for arg in &spec.args {
        if arg.contains('\0') {
            return Err(ProcessError::InvalidArgument {
                program: spec.program.to_string(),
                message: "argument contains a NUL byte".to_string(),
            });
        }
    }

    let mut child = Command::new(spec.program)
        .args(&spec.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|source| ProcessError::Spawn {
            program: spec.program.to_string(),
            source,
        })?;

    let stdout = child.stdout.take().expect("stdout is piped");
    let stderr = child.stderr.take().expect("stderr is piped");

    let outcome = tokio::time::timeout(spec.timeout, async {
        let (stdout, stderr) = tokio::join!(
            read_capped(stdout, spec.max_output_bytes),
            read_capped(stderr, spec.max_output_bytes),
        );
        let status = child.wait().await.map_err(|source| ProcessError::Run {
            program: spec.program.to_string(),
            source,
        })?;
        Ok::<CommandOutput, ProcessError>(CommandOutput {
            stdout: stdout.0,
            stderr: stderr.0,
            exit_code: status.code(),
            timed_out: false,
            truncated: stdout.1 || stderr.1,
        })
    })
    .await;

    match outcome {
        Ok(result) => result,
        Err(_elapsed) => {
            // Hard timeout: kill the child and report it.
            let _ = child.kill().await;
            let _ = child.wait().await;
            Ok(CommandOutput {
                stdout: String::new(),
                stderr: format!("process killed after {}s timeout", spec.timeout.as_secs()),
                exit_code: None,
                timed_out: true,
                truncated: false,
            })
        }
    }
}

/// Read a stream up to `limit` bytes, then stop (dropping the pipe so the
/// child observes the closed reader).
async fn read_capped<R: AsyncReadExt + Unpin>(mut reader: R, limit: usize) -> (String, bool) {
    let mut buf: Vec<u8> = Vec::new();
    let mut truncated = false;
    let mut chunk = [0u8; 4096];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > limit {
                    truncated = true;
                    break;
                }
            }
            Err(_) => break,
        }
    }
    (String::from_utf8_lossy(&buf).into_owned(), truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn echo_spec() -> CommandSpec {
        #[cfg(unix)]
        let spec = CommandSpec {
            program: "echo",
            args: vec!["hello anajakkh".to_string()],
            timeout: Duration::from_secs(5),
            max_output_bytes: 4096,
        };
        #[cfg(windows)]
        let spec = CommandSpec {
            program: "cmd",
            args: vec![
                "/C".to_string(),
                "echo".to_string(),
                "hello anajakkh".to_string(),
            ],
            timeout: Duration::from_secs(5),
            max_output_bytes: 4096,
        };
        spec
    }

    #[tokio::test]
    async fn runs_a_simple_command() {
        let output = run(echo_spec()).await.unwrap();
        assert_eq!(output.exit_code, Some(0));
        assert!(output.stdout.contains("hello anajakkh"));
        assert!(!output.timed_out);
        assert!(!output.truncated);
    }

    #[tokio::test]
    async fn missing_binary_is_detected() {
        let err = run(CommandSpec {
            program: "anajakkh-no-such-binary-xyz",
            args: vec![],
            timeout: Duration::from_secs(2),
            max_output_bytes: 1024,
        })
        .await
        .unwrap_err();
        assert!(err.is_not_found(), "expected NotFound, got {err:?}");
    }

    #[tokio::test]
    async fn nul_bytes_are_rejected() {
        let err = run(CommandSpec {
            program: "echo",
            args: vec!["bad\0arg".to_string()],
            timeout: Duration::from_secs(2),
            max_output_bytes: 1024,
        })
        .await
        .unwrap_err();
        assert!(matches!(err, ProcessError::InvalidArgument { .. }));
    }

    #[tokio::test]
    async fn nonzero_exit_code_is_captured() {
        // `false` exists on every POSIX system; on Windows use `cmd /C exit 1`.
        #[cfg(unix)]
        let spec = CommandSpec {
            program: "sh",
            args: vec!["-c".to_string(), "exit 3".to_string()],
            timeout: Duration::from_secs(5),
            max_output_bytes: 1024,
        };
        #[cfg(windows)]
        let spec = CommandSpec {
            program: "cmd",
            args: vec!["/C".to_string(), "exit 3".to_string()],
            timeout: Duration::from_secs(5),
            max_output_bytes: 1024,
        };
        let output = run(spec).await.unwrap();
        assert_eq!(output.exit_code, Some(3));
        assert!(!output.timed_out);
    }

    #[tokio::test]
    async fn output_is_capped() {
        // Produce far more output than the cap; the reader must stop early.
        #[cfg(unix)]
        let spec = CommandSpec {
            program: "sh",
            args: vec![
                "-c".to_string(),
                "yes xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx | head -c 200000".to_string(),
            ],
            timeout: Duration::from_secs(10),
            max_output_bytes: 1024,
        };
        #[cfg(windows)]
        let spec = CommandSpec {
            program: "cmd",
            args: vec![
                "/C".to_string(),
                "for /L %i in (1,1,5000) do @echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                    .to_string(),
            ],
            timeout: Duration::from_secs(10),
            max_output_bytes: 1024,
        };
        let output = run(spec).await.unwrap();
        assert!(
            output.truncated,
            "large output must be flagged as truncated"
        );
        assert!(
            output.stdout.len() < 100_000,
            "reader must stop early, captured {} bytes",
            output.stdout.len()
        );
    }
}
