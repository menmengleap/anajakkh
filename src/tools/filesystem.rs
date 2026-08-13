//! Filesystem tool: inspect files inside the workspace only.
//!
//! Safety rules:
//! - every path is canonicalized and must stay inside the workspace;
//! - symlink escapes are blocked by canonicalization;
//! - reads are size-capped; hashing uses SHA-256.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::evidence::sha256_hex;

use super::registry::{RiskLevel, SecurityTool, ToolContext, ToolMetadata, ToolResult};

/// Maximum directory entries reported in one listing.
const MAX_ENTRIES: usize = 200;
/// Maximum directory walk depth.
const MAX_DEPTH: usize = 4;
/// Maximum bytes read for hashing a file.
const MAX_HASH_BYTES: usize = 1 << 20;
/// Maximum bytes kept in a read preview.
const MAX_PREVIEW_BYTES: usize = 4096;

pub struct FilesystemTool {
    meta: ToolMetadata,
}

impl FilesystemTool {
    pub fn new() -> Self {
        Self {
            meta: ToolMetadata {
                name: "filesystem",
                description: "List, read, and hash files inside the authorized workspace",
                risk_level: RiskLevel::Medium,
                required_scope: true,
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "action": { "type": "string", "enum": ["list", "read", "hash"], "default": "list" },
                        "path": { "type": "string", "default": "." }
                    }
                }),
                output_schema: json!({
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "path": { "type": "string" },
                            "is_dir": { "type": "boolean" },
                            "size": { "type": "integer" },
                            "sha256": { "type": "string" }
                        }
                    }
                }),
            },
        }
    }
}

impl Default for FilesystemTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecurityTool for FilesystemTool {
    fn metadata(&self) -> &ToolMetadata {
        &self.meta
    }

    async fn execute(&self, ctx: ToolContext) -> anyhow::Result<ToolResult> {
        let workspace = ctx
            .workspace
            .ok_or_else(|| anyhow::anyhow!("filesystem tool requires a workspace"))?;
        let action = ctx
            .args
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or("list");
        let path_arg = ctx.args.get("path").and_then(Value::as_str).unwrap_or(".");

        let path = match resolve_within(&workspace, path_arg) {
            Ok(path) => path,
            Err(err) => {
                return Ok(ToolResult {
                    success: false,
                    summary: err.to_string(),
                    raw_output: err.to_string(),
                    exit_code: None,
                    data: Value::Null,
                });
            }
        };

        match action {
            "list" => {
                let entries = list_dir(&path)?;
                let count = entries.len();
                let raw: Vec<String> = entries
                    .iter()
                    .map(|e| {
                        let is_dir = e["is_dir"].as_bool().unwrap_or(false);
                        format!(
                            "{}{}  {} bytes",
                            e["path"].as_str().unwrap_or(""),
                            if is_dir { "/" } else { "" },
                            e["size"].as_u64().unwrap_or(0)
                        )
                    })
                    .collect();
                Ok(ToolResult {
                    success: true,
                    summary: format!(
                        "listed {count} entr{} in {}",
                        if count == 1 { "y" } else { "ies" },
                        workspace.display()
                    ),
                    raw_output: raw.join("\n") + "\n",
                    exit_code: None,
                    data: json!(entries),
                })
            }
            "read" => {
                let (preview, size, hash, truncated) = read_file(&path)?;
                Ok(ToolResult {
                    success: true,
                    summary: format!(
                        "read {} ({} bytes, sha256 {}{})",
                        path.display(),
                        size,
                        &hash[..12.min(hash.len())],
                        if truncated { ", truncated" } else { "" }
                    ),
                    raw_output: format!(
                        "path: {}\nsize: {}\nsha256: {}\n{}\n{}",
                        path.display(),
                        size,
                        hash,
                        if truncated { "[content truncated]" } else { "" },
                        preview
                    ),
                    exit_code: None,
                    data: json!([{
                        "path": relative_to(&workspace, &path),
                        "size": size,
                        "sha256": hash,
                        "is_dir": false,
                        "truncated": truncated,
                        "content_preview": preview,
                    }]),
                })
            }
            "hash" => {
                let (hash, size) = hash_file(&path)?;
                Ok(ToolResult {
                    success: true,
                    summary: format!("sha256 {} = {}", path.display(), hash),
                    raw_output: format!("sha256  {}  {}\n", hash, path.display()),
                    exit_code: None,
                    data: json!([{
                        "path": relative_to(&workspace, &path),
                        "size": size,
                        "sha256": hash,
                        "is_dir": false,
                    }]),
                })
            }
            other => Ok(ToolResult {
                success: false,
                summary: format!(
                    "unknown filesystem action `{other}` (expected list, read, or hash)"
                ),
                raw_output: String::new(),
                exit_code: None,
                data: Value::Null,
            }),
        }
    }
}

/// Resolve `rel` inside `workspace`, refusing anything that escapes it.
fn resolve_within(workspace: &Path, rel: &str) -> anyhow::Result<PathBuf> {
    let ws = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.to_path_buf());
    let candidate = if Path::new(rel).is_absolute() {
        PathBuf::from(rel)
    } else {
        ws.join(rel)
    };
    let canon = candidate.canonicalize().map_err(|err| {
        anyhow::anyhow!("path `{rel}` does not exist or is not accessible: {err}")
    })?;
    if !canon.starts_with(&ws) {
        anyhow::bail!(
            "refusing to access path outside workspace: {}",
            canon.display()
        );
    }
    Ok(canon)
}

fn relative_to(workspace: &Path, path: &Path) -> String {
    path.strip_prefix(workspace)
        .unwrap_or(path)
        .display()
        .to_string()
}

/// List entries under `root` up to [`MAX_DEPTH`] deep, [`MAX_ENTRIES`] wide.
fn list_dir(root: &Path) -> anyhow::Result<Vec<Value>> {
    let mut out = Vec::new();
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        if out.len() >= MAX_ENTRIES {
            break;
        }
        let entries = std::fs::read_dir(&dir)
            .map_err(|err| anyhow::anyhow!("cannot list {}: {err}", dir.display()))?;
        for entry in entries.flatten() {
            if out.len() >= MAX_ENTRIES {
                break;
            }
            let path = entry.path();
            let meta = entry.metadata().ok();
            let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            out.push(json!({
                "path": relative_to(root, &path),
                "is_dir": is_dir,
                "size": meta.map(|m| m.len()).unwrap_or(0),
            }));
            if is_dir && depth < MAX_DEPTH {
                stack.push((path, depth + 1));
            }
        }
    }
    Ok(out)
}

/// Read a file, returning (preview, total_size, sha256, truncated).
fn read_file(path: &Path) -> anyhow::Result<(String, u64, String, bool)> {
    let meta = std::fs::metadata(path)
        .map_err(|err| anyhow::anyhow!("cannot stat {}: {err}", path.display()))?;
    let total = meta.len();
    let file = std::fs::File::open(path)
        .map_err(|err| anyhow::anyhow!("cannot open {}: {err}", path.display()))?;
    use std::io::Read;
    let mut data = Vec::new();
    file.take(MAX_HASH_BYTES as u64)
        .read_to_end(&mut data)
        .map_err(|err| anyhow::anyhow!("cannot read {}: {err}", path.display()))?;
    let truncated = data.len() as u64 > MAX_HASH_BYTES as u64 || total > MAX_HASH_BYTES as u64;
    let hash = sha256_hex(&data);
    let preview: String = String::from_utf8_lossy(&data[..data.len().min(MAX_PREVIEW_BYTES)])
        .chars()
        .take(MAX_PREVIEW_BYTES)
        .collect();
    Ok((preview, total, hash, truncated))
}

/// Hash a file, returning (sha256, size).
fn hash_file(path: &Path) -> anyhow::Result<(String, u64)> {
    let meta = std::fs::metadata(path)
        .map_err(|err| anyhow::anyhow!("cannot stat {}: {err}", path.display()))?;
    let file = std::fs::File::open(path)
        .map_err(|err| anyhow::anyhow!("cannot open {}: {err}", path.display()))?;
    use std::io::Read;
    let mut data = Vec::new();
    file.take(MAX_HASH_BYTES as u64)
        .read_to_end(&mut data)
        .map_err(|err| anyhow::anyhow!("cannot read {}: {err}", path.display()))?;
    Ok((sha256_hex(&data), meta.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(workspace: &Path, args: Value) -> ToolContext {
        ToolContext {
            args,
            scope_id: None,
            target: None,
            workspace: Some(workspace.to_path_buf()),
        }
    }

    #[tokio::test]
    async fn lists_workspace_root() {
        let dir = std::env::temp_dir().join(format!("anajakkh-fs-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("notes.txt"), "hello").unwrap();

        let tool = FilesystemTool::new();
        let result = tool.execute(context(&dir, json!({}))).await.unwrap();
        assert!(result.success);
        assert!(result.summary.contains("listed"));
        let data = result.data.as_array().unwrap();
        assert!(data.iter().any(|e| e["path"] == "notes.txt"));
        assert!(data
            .iter()
            .any(|e| e["path"] == "sub" && e["is_dir"] == true));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn hashes_a_file() {
        let dir = std::env::temp_dir().join(format!("anajakkh-fs-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), "hello world").unwrap();

        let tool = FilesystemTool::new();
        let result = tool
            .execute(context(&dir, json!({ "action": "hash", "path": "a.txt" })))
            .await
            .unwrap();
        assert!(result.success);
        assert!(result
            .summary
            .contains("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn blocks_escapes_outside_workspace() {
        let dir = std::env::temp_dir().join(format!("anajakkh-fs-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        let tool = FilesystemTool::new();
        // Path traversal attempt.
        let result = tool
            .execute(context(&dir, json!({ "path": "../../etc/passwd" })))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(
            result.summary.contains("outside workspace")
                || result.summary.contains("does not exist"),
            "unexpected summary: {}",
            result.summary
        );

        // Absolute path outside workspace.
        let outside = std::env::temp_dir().join("anajakkh-fs-outside.txt");
        std::fs::write(&outside, "x").unwrap();
        let result = tool
            .execute(context(&dir, json!({ "path": outside.to_string_lossy() })))
            .await
            .unwrap();
        assert!(!result.success);

        std::fs::remove_dir_all(&dir).unwrap();
        let _ = std::fs::remove_file(&outside);
    }

    #[tokio::test]
    async fn metadata_is_sane() {
        let tool = FilesystemTool::new();
        assert_eq!(tool.metadata().name, "filesystem");
        assert_eq!(tool.metadata().risk_level, RiskLevel::Medium);
    }
}
