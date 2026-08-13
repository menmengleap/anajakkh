//! Session persistence.
//!
//! A [`SessionRecord`] captures everything needed to resume an assessment:
//! scope, conversation memory, the last plan, and the run summary.
//! Evidence and findings live as JSON files keyed by the same session id,
//! so resuming a session continues writing to the same directories.
//!
//! Storage uses `redb` — a pure-Rust embedded database (no C toolchain
//! needed). Rows are keyed by session id; listing sorts newest-first.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use redb::{Database, ReadableTable};

use crate::agent::memory::MemoryEntry;
use crate::agent::planner::Plan;
use crate::agent::{ConversationMemory, SessionSummary};
use crate::security::Scope;
use uuid::Uuid;

use super::database::{open_database, open_in_memory, SESSIONS};

/// A persisted session.
#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub workspace: PathBuf,
    pub scope: Option<Scope>,
    pub conversation: ConversationMemory,
    pub plan: Option<Plan>,
    pub summary: Option<SessionSummary>,
    /// Path to the generated report (markdown), if any.
    pub report: Option<String>,
}

impl SessionRecord {
    pub fn new(id: impl Into<String>, workspace: PathBuf) -> Self {
        let now = Utc::now();
        Self {
            id: id.into(),
            created_at: now,
            updated_at: now,
            workspace,
            scope: None,
            conversation: ConversationMemory::new(),
            plan: None,
            summary: None,
            report: None,
        }
    }

    /// True when a run has completed for this session.
    pub fn is_completed(&self) -> bool {
        self.summary.is_some()
    }
}

/// Database-backed store of sessions.
pub struct SessionStore {
    db: Database,
}

impl SessionStore {
    /// Open the store at `<workspace>/sessions/sessions.db`.
    pub fn open(workspace: &Path) -> Result<Self> {
        let db_path = workspace.join("sessions").join("sessions.db");
        let db = open_database(&db_path)?;
        Ok(Self { db })
    }

    /// In-memory store — used when the on-disk database cannot be opened,
    /// so the app still runs (session persistence degrades gracefully).
    pub fn in_memory() -> Self {
        let db = open_in_memory().expect("in-memory session store");
        Self { db }
    }

    /// Insert or update a session record.
    pub fn save(&self, record: &SessionRecord) -> Result<()> {
        // Preserve the original created_at on update.
        let created_at = match self.get(&record.id)? {
            Some(existing) => existing.created_at,
            None => record.created_at,
        };

        let persisted = PersistedSession {
            created_at,
            updated_at: record.updated_at,
            workspace: record.workspace.clone(),
            scope: record.scope.clone(),
            conversation: record.conversation.entries(),
            plan: record.plan.clone(),
            summary: record.summary.clone(),
            report: record.report.clone(),
        };
        let json = serde_json::to_string(&persisted).context("serializing session")?;

        let write_txn = self.db.begin_write().context("beginning session write")?;
        {
            let mut sessions = write_txn
                .open_table(SESSIONS)
                .context("opening sessions table")?;
            sessions
                .insert(record.id.as_str(), json.as_str())
                .context("writing session")?;
        }
        write_txn.commit().context("committing session write")?;
        Ok(())
    }

    /// Load a session by id.
    pub fn get(&self, id: &str) -> Result<Option<SessionRecord>> {
        let read_txn = self.db.begin_read().context("beginning session read")?;
        let sessions = read_txn
            .open_table(SESSIONS)
            .context("opening sessions table")?;
        let Some(value) = sessions.get(id).context("reading session")? else {
            return Ok(None);
        };
        let persisted: PersistedSession =
            serde_json::from_str(value.value()).context("parsing session")?;
        Ok(Some(persisted.into_record(id.to_string())))
    }

    /// List all sessions, newest first.
    pub fn list(&self) -> Result<Vec<SessionRecord>> {
        let read_txn = self.db.begin_read().context("beginning session listing")?;
        let sessions = read_txn
            .open_table(SESSIONS)
            .context("opening sessions table")?;
        let mut records: Vec<(DateTime<Utc>, SessionRecord)> = Vec::new();
        for entry in sessions.iter().context("iterating sessions")? {
            let (key, value) = entry.context("reading session entry")?;
            let persisted: PersistedSession =
                serde_json::from_str(value.value()).context("parsing session")?;
            records.push((
                persisted.created_at,
                persisted.into_record(key.value().to_string()),
            ));
        }
        records.sort_by_key(|record| std::cmp::Reverse(record.0));
        Ok(records.into_iter().map(|(_, record)| record).collect())
    }

    /// Delete a session row. Evidence/findings JSON files are left in
    /// place for the operator to remove.
    pub fn delete(&self, id: &str) -> Result<()> {
        let write_txn = self.db.begin_write().context("beginning session delete")?;
        {
            let mut sessions = write_txn
                .open_table(SESSIONS)
                .context("opening sessions table")?;
            sessions.remove(id).context("deleting session")?;
        }
        write_txn.commit().context("committing session delete")?;
        Ok(())
    }
}

/// What is actually stored per session (id lives in the table key).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PersistedSession {
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    workspace: PathBuf,
    scope: Option<Scope>,
    conversation: Vec<MemoryEntry>,
    plan: Option<Plan>,
    summary: Option<SessionSummary>,
    #[serde(default)]
    report: Option<String>,
}

impl PersistedSession {
    fn into_record(self, id: String) -> SessionRecord {
        SessionRecord {
            id,
            created_at: self.created_at,
            updated_at: self.updated_at,
            workspace: self.workspace,
            scope: self.scope,
            conversation: ConversationMemory::from_entries(self.conversation),
            plan: self.plan,
            summary: self.summary,
            report: self.report,
        }
    }
}

/// Fresh session id helper for callers that create sessions.
pub fn new_session_id() -> String {
    Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::memory::MemoryEntry;

    fn temp_workspace(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("anajakkh-sess-{tag}-{}", Uuid::new_v4()))
    }

    #[test]
    fn save_get_list_roundtrip() {
        let ws = temp_workspace("roundtrip");
        let store = SessionStore::open(&ws).unwrap();

        let mut record = SessionRecord::new("sess-1", ws.clone());
        record.scope = Scope::parse("sess-1", "example.com").ok();
        record.conversation.push_user("scan example.com");
        record.conversation.push_assistant("done");
        store.save(&record).unwrap();

        let loaded = store.get("sess-1").unwrap().expect("session exists");
        assert_eq!(loaded.id, "sess-1");
        assert_eq!(loaded.scope.as_ref().unwrap().summary(), "example.com");
        assert_eq!(loaded.conversation.len(), 2);
        assert_eq!(loaded.conversation.last_user(), Some("scan example.com"));
        assert!(!loaded.is_completed());

        let list = store.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "sess-1");

        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn save_preserves_created_at_and_updates() {
        let ws = temp_workspace("created");
        let store = SessionStore::open(&ws).unwrap();

        let mut record = SessionRecord::new("sess-2", ws.clone());
        store.save(&record).unwrap();
        let first = store.get("sess-2").unwrap().unwrap();

        // Simulate the session progressing.
        record.conversation.push_user("more work");
        record.summary = Some(SessionSummary::default());
        store.save(&record).unwrap();

        let second = store.get("sess-2").unwrap().unwrap();
        assert_eq!(second.created_at, first.created_at);
        assert!(second.updated_at >= first.updated_at);
        assert!(second.is_completed());
        assert_eq!(second.conversation.len(), 1);

        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn missing_session_returns_none() {
        let ws = temp_workspace("missing");
        let store = SessionStore::open(&ws).unwrap();
        assert!(store.get("nope").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn delete_removes_session() {
        let ws = temp_workspace("delete");
        let store = SessionStore::open(&ws).unwrap();
        store
            .save(&SessionRecord::new("sess-3", ws.clone()))
            .unwrap();
        store.delete("sess-3").unwrap();
        assert!(store.get("sess-3").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn in_memory_store_works() {
        let store = SessionStore::in_memory();
        store
            .save(&SessionRecord::new("sess-4", PathBuf::from("/tmp")))
            .unwrap();
        assert!(store.get("sess-4").unwrap().is_some());
    }

    #[test]
    fn list_orders_newest_first() {
        let ws = temp_workspace("order");
        let store = SessionStore::open(&ws).unwrap();
        let a = SessionRecord::new("older", ws.clone());
        let mut b = SessionRecord::new("newer", ws.clone());
        b.created_at = a.created_at + chrono::Duration::seconds(60);
        store.save(&a).unwrap();
        store.save(&b).unwrap();
        let list = store.list().unwrap();
        assert_eq!(list[0].id, "newer");
        assert_eq!(list[1].id, "older");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn memory_entries_serde() {
        let entries = vec![
            MemoryEntry::User("hi".to_string()),
            MemoryEntry::Assistant("hello".to_string()),
        ];
        let json = serde_json::to_string(&entries).unwrap();
        let back: Vec<MemoryEntry> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, entries);
    }
}
