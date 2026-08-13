//! Evidence storage.
//!
//! Records are kept in memory for the session and, when the store is
//! persistent, written immutably to
//! `<workspace>/evidence/<session-id>/<id>.json`. Raw tool output is
//! stored under `.../raw/` and referenced by each record.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use uuid::Uuid;

use super::models::{Evidence, EvidenceType};

/// Thread-safe evidence store shared by the executor.
#[derive(Clone)]
pub struct EvidenceStore {
    workspace: PathBuf,
    persistent: bool,
    items: Arc<Mutex<Vec<Evidence>>>,
}

impl EvidenceStore {
    /// Persistent store rooted at `workspace/evidence`.
    pub fn new(workspace: PathBuf) -> Self {
        Self {
            workspace,
            persistent: true,
            items: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// In-memory store (used by tests and embedded executor).
    pub fn in_memory() -> Self {
        Self {
            workspace: PathBuf::new(),
            persistent: false,
            items: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Record one evidence item. Evidence is immutable after recording.
    pub fn record(&self, session_id: &str, evidence: Evidence) -> Result<()> {
        if self.persistent {
            let dir = self.workspace.join("evidence").join(session_id);
            std::fs::create_dir_all(&dir)?;
            let path = dir.join(format!("{}.json", evidence.id));
            std::fs::write(&path, serde_json::to_string_pretty(&evidence)?)?;
        }
        self.items.lock().expect("evidence mutex").push(evidence);
        Ok(())
    }

    /// Load previously persisted evidence for a session into memory
    /// (used when resuming). Returns the number of records loaded.
    pub fn load(&self, session_id: &str) -> Result<usize> {
        let dir = self.workspace.join("evidence").join(session_id);
        if !dir.is_dir() {
            return Ok(0);
        }
        let mut count = 0;
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let is_json = entry
                .path()
                .extension()
                .map(|ext| ext == "json")
                .unwrap_or(false);
            if !is_json {
                continue;
            }
            let text = std::fs::read_to_string(entry.path())?;
            if let Ok(evidence) = serde_json::from_str::<Evidence>(&text) {
                self.items.lock().expect("evidence mutex").push(evidence);
                count += 1;
            }
        }
        Ok(count)
    }

    /// Persist raw tool output for a session, returning the file path.
    /// Returns `None` for non-persistent stores or empty content.
    pub fn save_raw(&self, session_id: &str, content: &str) -> Result<Option<PathBuf>> {
        if !self.persistent || content.trim().is_empty() {
            return Ok(None);
        }
        let dir = self.workspace.join("evidence").join(session_id).join("raw");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{}.txt", Uuid::new_v4()));
        std::fs::write(&path, content)?;
        Ok(Some(path))
    }

    /// The root directory evidence is stored under.
    pub fn root_dir(&self) -> PathBuf {
        self.workspace.join("evidence")
    }

    pub fn all(&self) -> Vec<Evidence> {
        self.items.lock().expect("evidence mutex").clone()
    }

    pub fn len(&self) -> usize {
        self.items.lock().expect("evidence mutex").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn find(&self, id: &str) -> Option<Evidence> {
        self.items
            .lock()
            .expect("evidence mutex")
            .iter()
            .find(|e| e.id == id)
            .cloned()
    }

    pub fn by_type(&self, ty: EvidenceType) -> Vec<Evidence> {
        self.items
            .lock()
            .expect("evidence mutex")
            .iter()
            .filter(|e| e.r#type == ty)
            .cloned()
            .collect()
    }

    pub fn for_target(&self, target: &str) -> Vec<Evidence> {
        self.items
            .lock()
            .expect("evidence mutex")
            .iter()
            .filter(|e| e.target == target)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::models::Evidence;

    fn temp_workspace(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("anajakkh-ev-{tag}-{}", Uuid::new_v4()))
    }

    #[test]
    fn in_memory_store_records() {
        let store = EvidenceStore::in_memory();
        store
            .record(
                "s1",
                Evidence::new(
                    EvidenceType::Host,
                    "nmap",
                    "10.0.0.1",
                    serde_json::json!({"status": "up"}),
                ),
            )
            .unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(store.by_type(EvidenceType::Host).len(), 1);
        assert_eq!(store.for_target("10.0.0.1").len(), 1);
        assert!(store.find(&store.all()[0].id).is_some());
    }

    #[test]
    fn persistent_store_writes_files() {
        let ws = temp_workspace("persist");
        let store = EvidenceStore::new(ws.clone());
        let ev = Evidence::new(
            EvidenceType::Service,
            "nmap",
            "10.0.0.1",
            serde_json::json!({"port": 22}),
        );
        store.record("session-abc", ev.clone()).unwrap();
        store.save_raw("session-abc", "raw text").unwrap();

        let file = ws
            .join("evidence")
            .join("session-abc")
            .join(format!("{}.json", ev.id));
        assert!(file.exists(), "evidence json should be written");
        let back: Evidence =
            serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        assert_eq!(back.sha256, ev.sha256);

        let raw_dir = ws.join("evidence").join("session-abc").join("raw");
        let raw_files: Vec<_> = std::fs::read_dir(&raw_dir).unwrap().flatten().collect();
        assert_eq!(raw_files.len(), 1);

        std::fs::remove_dir_all(&ws).unwrap();
    }

    #[test]
    fn persistent_store_roundtrips_in_memory() {
        let ws = temp_workspace("roundtrip");
        let store = EvidenceStore::new(ws.clone());
        let ev = Evidence::new(
            EvidenceType::DnsRecord,
            "dns",
            "example.com",
            serde_json::json!({"name": "example.com"}),
        );
        store.record("s1", ev.clone()).unwrap();
        assert!(store.find(&ev.id).is_some());
        std::fs::remove_dir_all(&ws).unwrap();
    }

    #[test]
    fn empty_raw_output_is_not_saved() {
        let ws = temp_workspace("noraw");
        let store = EvidenceStore::new(ws.clone());
        assert!(store.save_raw("s1", "  ").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&ws); // may not exist — that's the point
    }
}
