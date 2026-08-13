//! Agent execution context: session identity, workspace, scope, memory.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use uuid::Uuid;

use crate::security::Scope;

use super::memory::ConversationMemory;

/// Everything an agent task needs beyond its static configuration.
#[derive(Debug, Clone)]
pub struct AgentContext {
    pub session_id: String,
    pub workspace: PathBuf,
    pub scope: Option<Scope>,
    pub memory: ConversationMemory,
    cancel_flag: Arc<AtomicBool>,
}

impl AgentContext {
    pub fn new(workspace: PathBuf) -> Self {
        Self {
            session_id: Uuid::new_v4().to_string(),
            workspace,
            scope: None,
            memory: ConversationMemory::new(),
            cancel_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create a context that shares a caller-owned cancel flag, so the UI
    /// can request cancellation of the running task.
    pub fn with_shared_cancel(workspace: PathBuf, cancel_flag: Arc<AtomicBool>) -> Self {
        Self {
            session_id: Uuid::new_v4().to_string(),
            workspace,
            scope: None,
            memory: ConversationMemory::new(),
            cancel_flag,
        }
    }

    pub fn cancel(&self) {
        self.cancel_flag.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel_flag.load(Ordering::Relaxed)
    }
}
