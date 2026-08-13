//! Database connection management.
//!
//! Uses `redb` — a pure-Rust embedded database (B-tree tables with
//! transactions) — so no C toolchain is required to build ANAJAKKH.
//!
//! Schema evolution is tracked with a small `meta` table holding
//! `schema_version`; versioned setup steps run in order on open.

use std::path::Path;

use anyhow::{Context, Result};
use redb::{Database, ReadableTable, TableDefinition};

/// Sessions table: session id → serialized [`crate::storage::SessionRecord`].
pub const SESSIONS: TableDefinition<&str, &str> = TableDefinition::new("sessions");

/// Metadata table (currently just `schema_version`).
const META: TableDefinition<&str, &str> = TableDefinition::new("meta");

/// Current schema version. Bump when the sessions schema changes.
pub const SCHEMA_VERSION: u64 = 1;

/// Open (or create) the database at `path`, ensuring the schema is current.
pub fn open_database(path: &Path) -> Result<Database> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating database directory {}", parent.display()))?;
    }
    let db =
        Database::create(path).with_context(|| format!("opening database {}", path.display()))?;
    ensure_schema(&db)?;
    Ok(db)
}

/// Create an in-memory database (used when the on-disk database cannot be
/// opened, so the app still runs).
pub fn open_in_memory() -> Result<Database> {
    let db = Database::builder()
        .create_with_backend(redb::backends::InMemoryBackend::new())
        .context("opening in-memory database")?;
    ensure_schema(&db)?;
    Ok(db)
}

/// Apply any pending schema steps and record the new version.
fn ensure_schema(db: &Database) -> Result<()> {
    let write_txn = db.begin_write().context("beginning schema write")?;
    {
        let mut meta = write_txn.open_table(META).context("opening meta table")?;
        let current: u64 = meta
            .get("schema_version")
            .ok()
            .flatten()
            .map(|g| g.value().parse().unwrap_or(0))
            .unwrap_or(0);
        if current < SCHEMA_VERSION {
            // Version 1: create the sessions table (redb `open_table` in a
            // write transaction creates the table if missing).
            write_txn
                .open_table(SESSIONS)
                .context("creating sessions table")?;
            let version = SCHEMA_VERSION.to_string();
            meta.insert("schema_version", version.as_str())
                .context("recording schema version")?;
        }
    }
    write_txn.commit().context("committing schema")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use redb::ReadableTableMetadata;
    use uuid::Uuid;

    #[test]
    fn opens_and_tracks_schema_version() {
        let dir = std::env::temp_dir().join(format!("anajakkh-db-{}", Uuid::new_v4()));
        let db_path = dir.join("sessions.db");
        let db = open_database(&db_path).unwrap();
        let read_txn = db.begin_read().unwrap();
        let meta = read_txn.open_table(META).unwrap();
        let version = meta
            .get("schema_version")
            .unwrap()
            .unwrap()
            .value()
            .to_string();
        assert_eq!(version, SCHEMA_VERSION.to_string());
        drop(read_txn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn in_memory_database_works() {
        let db = open_in_memory().unwrap();
        let write_txn = db.begin_write().unwrap();
        {
            let mut sessions = write_txn.open_table(SESSIONS).unwrap();
            sessions.insert("s1", "{}").unwrap();
        }
        write_txn.commit().unwrap();
        let read_txn = db.begin_read().unwrap();
        let sessions = read_txn.open_table(SESSIONS).unwrap();
        assert_eq!(sessions.len().unwrap(), 1);
    }
}
