use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use mcpx_core::snapshot::ServerBaseline;
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use tracing::info;

pub struct Store {
    conn: Connection,
}

#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub server_name: String,
    pub event_type: String,
    pub detail: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ShimDecision {
    pub id: i64,
    pub server_name: String,
    pub tool_name: String,
    pub mappings: serde_json::Value,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Store {
    /// Open (or create) the mcpx database at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
        }

        let conn = Connection::open(path)
            .with_context(|| format!("Failed to open database: {}", path.display()))?;

        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    /// Open the default database at ~/.mcpx/mcpx.db
    pub fn open_default() -> Result<Self> {
        let path = default_db_path()?;
        Self::open(&path)
    }

    fn migrate(&self) -> Result<()> {
        self.conn
            .execute_batch(
                "
            CREATE TABLE IF NOT EXISTS baselines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_name TEXT NOT NULL,
                server_version TEXT,
                protocol_version TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                pinned_at TEXT NOT NULL,
                mcpx_version TEXT NOT NULL,
                UNIQUE(server_name)
            );

            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_name TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                observed_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_name TEXT NOT NULL,
                event_type TEXT NOT NULL,
                detail_json TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS shim_decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_name TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                mappings_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_baselines_server ON baselines(server_name);
            CREATE INDEX IF NOT EXISTS idx_snapshots_server ON snapshots(server_name);
            CREATE INDEX IF NOT EXISTS idx_events_server ON events(server_name);
            CREATE INDEX IF NOT EXISTS idx_shim_decisions_server_tool ON shim_decisions(server_name, tool_name);
            ",
            )
            .context("Failed to run database migrations")?;
        Ok(())
    }

    /// Get the pinned baseline for a server, if one exists.
    pub fn get_baseline(&self, server_name: &str) -> Result<Option<ServerBaseline>> {
        let mut stmt = self
            .conn
            .prepare("SELECT snapshot_json FROM baselines WHERE server_name = ?1")?;
        let result = stmt.query_row([server_name], |row| {
            let json: String = row.get(0)?;
            Ok(json)
        });

        match result {
            Ok(json) => {
                let baseline: ServerBaseline = serde_json::from_str(&json)?;
                Ok(Some(baseline))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Pin a baseline for a server (upsert).
    pub fn pin_baseline(&self, baseline: &ServerBaseline) -> Result<()> {
        let json = serde_json::to_string(baseline)?;
        self.conn.execute(
            "INSERT INTO baselines (server_name, server_version, protocol_version, snapshot_json, pinned_at, mcpx_version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(server_name) DO UPDATE SET
                server_version = excluded.server_version,
                protocol_version = excluded.protocol_version,
                snapshot_json = excluded.snapshot_json,
                pinned_at = excluded.pinned_at,
                mcpx_version = excluded.mcpx_version",
            rusqlite::params![
                baseline.server_name,
                baseline.server_version,
                baseline.protocol_version,
                json,
                baseline.pinned_at.to_rfc3339(),
                baseline.mcpx_version,
            ],
        )?;
        info!(server = %baseline.server_name, tools = baseline.tools.len(), "Baseline pinned");
        Ok(())
    }

    /// Record a snapshot observation.
    pub fn record_snapshot(&self, server_name: &str, baseline: &ServerBaseline) -> Result<()> {
        let json = serde_json::to_string(baseline)?;
        self.conn.execute(
            "INSERT INTO snapshots (server_name, snapshot_json, observed_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![server_name, json, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Record an audit event. Returns the event ID.
    pub fn record_event(
        &self,
        server_name: &str,
        event_type: &str,
        detail: Option<&serde_json::Value>,
    ) -> Result<i64> {
        let detail_json = detail.map(|d| serde_json::to_string(d).unwrap_or_default());
        self.conn.execute(
            "INSERT INTO events (server_name, event_type, detail_json, created_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![server_name, event_type, detail_json, Utc::now().to_rfc3339()],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// List recent audit events for a server, newest first.
    pub fn list_events(&self, server_name: &str, limit: usize) -> Result<Vec<AuditEvent>> {
        let limit = i64::try_from(limit).context("limit is too large")?;
        let mut stmt = self.conn.prepare(
            "SELECT server_name, event_type, detail_json, created_at
             FROM events
             WHERE server_name = ?1
             ORDER BY id DESC
             LIMIT ?2",
        )?;

        let rows = stmt.query_map(rusqlite::params![server_name, limit], |row| {
            let server_name: String = row.get(0)?;
            let event_type: String = row.get(1)?;
            let detail_json: Option<String> = row.get(2)?;
            let created_at: String = row.get(3)?;

            let detail = detail_json
                .as_deref()
                .map(serde_json::from_str::<serde_json::Value>)
                .transpose()
                .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;

            let created_at = DateTime::parse_from_rfc3339(&created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        3,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;

            Ok(AuditEvent {
                server_name,
                event_type,
                detail,
                created_at,
            })
        })?;

        let mut events = Vec::new();
        for row in rows {
            events.push(row?);
        }
        Ok(events)
    }

    /// List all server names that have pinned baselines.
    pub fn list_baselines(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT server_name FROM baselines ORDER BY server_name")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        let mut names = Vec::new();
        for row in rows {
            names.push(row?);
        }
        Ok(names)
    }

    /// Delete a baseline.
    pub fn delete_baseline(&self, server_name: &str) -> Result<bool> {
        let count = self.conn.execute(
            "DELETE FROM baselines WHERE server_name = ?1",
            [server_name],
        )?;
        Ok(count > 0)
    }

    /// Record a shim decision (`proposed`, `approved`, `auto_approved`).
    pub fn record_shim_decision(
        &self,
        server_name: &str,
        tool_name: &str,
        mappings: &serde_json::Value,
        status: &str,
    ) -> Result<i64> {
        let now = Utc::now().to_rfc3339();
        let mappings_json = serde_json::to_string(mappings)?;
        self.conn.execute(
            "INSERT INTO shim_decisions (server_name, tool_name, mappings_json, status, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![server_name, tool_name, mappings_json, status, now, now],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Return status for an exact mappings proposal if one exists.
    pub fn get_shim_status(
        &self,
        server_name: &str,
        tool_name: &str,
        mappings: &serde_json::Value,
    ) -> Result<Option<String>> {
        let mappings_json = serde_json::to_string(mappings)?;
        let mut stmt = self.conn.prepare(
            "SELECT status
             FROM shim_decisions
             WHERE server_name = ?1 AND tool_name = ?2 AND mappings_json = ?3
             ORDER BY id DESC
             LIMIT 1",
        )?;
        let result = stmt.query_row(
            rusqlite::params![server_name, tool_name, mappings_json],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(status) => Ok(Some(status)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Approve the latest proposed shim for a tool.
    pub fn approve_latest_shim(&self, server_name: &str, tool_name: &str) -> Result<bool> {
        let now = Utc::now().to_rfc3339();
        let mut stmt = self.conn.prepare(
            "SELECT id
             FROM shim_decisions
             WHERE server_name = ?1 AND tool_name = ?2 AND status = 'proposed'
             ORDER BY id DESC
             LIMIT 1",
        )?;
        let id_result = stmt.query_row(rusqlite::params![server_name, tool_name], |row| {
            row.get::<_, i64>(0)
        });

        let id = match id_result {
            Ok(id) => id,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(false),
            Err(e) => return Err(e.into()),
        };

        self.conn.execute(
            "UPDATE shim_decisions SET status = 'approved', updated_at = ?2 WHERE id = ?1",
            rusqlite::params![id, now],
        )?;
        Ok(true)
    }

    /// List recorded shim decisions for a server.
    pub fn list_shims(&self, server_name: &str) -> Result<Vec<ShimDecision>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, server_name, tool_name, mappings_json, status, created_at, updated_at
             FROM shim_decisions
             WHERE server_name = ?1
             ORDER BY id DESC",
        )?;

        let rows = stmt.query_map([server_name], |row| {
            let id: i64 = row.get(0)?;
            let server_name: String = row.get(1)?;
            let tool_name: String = row.get(2)?;
            let mappings_json: String = row.get(3)?;
            let status: String = row.get(4)?;
            let created_at: String = row.get(5)?;
            let updated_at: String = row.get(6)?;

            let mappings: serde_json::Value =
                serde_json::from_str(&mappings_json).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        3,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;

            let created_at = DateTime::parse_from_rfc3339(&created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        5,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;
            let updated_at = DateTime::parse_from_rfc3339(&updated_at)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        6,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;

            Ok(ShimDecision {
                id,
                server_name,
                tool_name,
                mappings,
                status,
                created_at,
                updated_at,
            })
        })?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }
}

fn default_db_path() -> Result<PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .context("Could not determine home directory")?;
    Ok(PathBuf::from(home).join(".mcpx").join("mcpx.db"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpx_core::snapshot::{ServerBaseline, ToolSnapshot};
    use tempfile::NamedTempFile;

    fn make_baseline() -> ServerBaseline {
        ServerBaseline {
            server_name: "test-server".into(),
            server_version: Some("1.0.0".into()),
            protocol_version: "2025-06-18".into(),
            tools: vec![ToolSnapshot {
                name: "search".into(),
                description: Some("Search".into()),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                annotations: None,
                description_hash: "abc".into(),
                schema_hash: "def".into(),
                output_schema_hash: "ghi".into(),
            }],
            pinned_at: Utc::now(),
            mcpx_version: "0.1.0".into(),
        }
    }

    #[test]
    fn roundtrip_baseline() {
        let tmp = NamedTempFile::new().unwrap();
        let store = Store::open(tmp.path()).unwrap();

        let baseline = make_baseline();
        store.pin_baseline(&baseline).unwrap();

        let loaded = store.get_baseline("test-server").unwrap().unwrap();
        assert_eq!(loaded.server_name, "test-server");
        assert_eq!(loaded.tools.len(), 1);
    }

    #[test]
    fn list_baselines() {
        let tmp = NamedTempFile::new().unwrap();
        let store = Store::open(tmp.path()).unwrap();

        store.pin_baseline(&make_baseline()).unwrap();
        let names = store.list_baselines().unwrap();
        assert_eq!(names, vec!["test-server"]);
    }

    #[test]
    fn missing_baseline_returns_none() {
        let tmp = NamedTempFile::new().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        assert!(store.get_baseline("nonexistent").unwrap().is_none());
    }

    #[test]
    fn record_and_list_events() {
        let tmp = NamedTempFile::new().unwrap();
        let store = Store::open(tmp.path()).unwrap();

        store
            .record_event("test-server", "schema_change", None)
            .unwrap();
        store
            .record_event(
                "test-server",
                "breaking_change",
                Some(&serde_json::json!({"diffs": 3})),
            )
            .unwrap();
        store
            .record_event("other-server", "schema_change", None)
            .unwrap();

        let events = store.list_events("test-server", 10).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, "breaking_change");
        assert_eq!(events[1].event_type, "schema_change");
        assert_eq!(events[0].server_name, "test-server");
        assert!(events[0].detail.is_some());

        let limited = store.list_events("test-server", 1).unwrap();
        assert_eq!(limited.len(), 1);
        assert_eq!(limited[0].event_type, "breaking_change");
    }

    #[test]
    fn record_and_approve_shim_decision() {
        let tmp = NamedTempFile::new().unwrap();
        let store = Store::open(tmp.path()).unwrap();

        let mappings = serde_json::json!([{"from":"q","to":"query"}]);
        store
            .record_shim_decision("test-server", "search", &mappings, "proposed")
            .unwrap();

        let status = store
            .get_shim_status("test-server", "search", &mappings)
            .unwrap()
            .unwrap();
        assert_eq!(status, "proposed");

        let approved = store.approve_latest_shim("test-server", "search").unwrap();
        assert!(approved);

        let status = store
            .get_shim_status("test-server", "search", &mappings)
            .unwrap()
            .unwrap();
        assert_eq!(status, "approved");

        let shims = store.list_shims("test-server").unwrap();
        assert_eq!(shims.len(), 1);
        assert_eq!(shims[0].tool_name, "search");
    }
}
