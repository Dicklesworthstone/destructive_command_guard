//! `SQLite` schema definitions for command telemetry.
//!
//! This module defines the database schema, types, and core operations for
//! the telemetry system. The schema is designed for:
//!
//! - Efficient writes during hook execution (< 1ms target)
//! - Flexible queries for analytics and debugging
//! - Full-text search on command content
//! - Graceful schema migrations

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fmt::Write as FmtWrite;
use std::path::{Path, PathBuf};

/// Current schema version for migrations.
pub const CURRENT_SCHEMA_VERSION: u32 = 2;

/// Default database filename.
pub const DEFAULT_DB_FILENAME: &str = "telemetry.db";

/// Telemetry-specific error type.
#[derive(Debug)]
pub enum TelemetryError {
    /// `SQLite` error.
    Sqlite(rusqlite::Error),
    /// I/O error.
    Io(std::io::Error),
    /// Schema version mismatch (expected, found).
    SchemaMismatch { expected: u32, found: u32 },
    /// Database is disabled.
    Disabled,
}

impl std::fmt::Display for TelemetryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "SQLite error: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::SchemaMismatch { expected, found } => {
                write!(f, "Schema mismatch: expected v{expected}, found v{found}")
            }
            Self::Disabled => write!(f, "Telemetry is disabled"),
        }
    }
}

impl std::error::Error for TelemetryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlite(e) => Some(e),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for TelemetryError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

impl From<std::io::Error> for TelemetryError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Command evaluation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Command was allowed to execute.
    Allow,
    /// Command was blocked from execution.
    Deny,
    /// Command triggered a warning but was allowed.
    Warn,
    /// Command was allowed via bypass (allow-once).
    Bypass,
}

impl Outcome {
    /// Convert to database string representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Warn => "warn",
            Self::Bypass => "bypass",
        }
    }

    fn parse_inner(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            "warn" => Some(Self::Warn),
            "bypass" => Some(Self::Bypass),
            _ => None,
        }
    }

    /// Parse from database string representation.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::parse_inner(s)
    }
}

impl std::str::FromStr for Outcome {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_inner(s).ok_or(())
    }
}

/// A single command entry for the telemetry database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandEntry {
    /// Timestamp when the command was evaluated (ISO 8601).
    pub timestamp: DateTime<Utc>,
    /// Agent type that issued the command (e.g., "`claude_code`", "codex").
    pub agent_type: String,
    /// Working directory where the command was executed.
    pub working_dir: String,
    /// The actual command string.
    pub command: String,
    /// Evaluation outcome.
    pub outcome: Outcome,
    /// Pack ID that matched (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pack_id: Option<String>,
    /// Pattern name that matched (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern_name: Option<String>,
    /// Evaluation duration in microseconds.
    #[serde(default)]
    pub eval_duration_us: u64,
    /// Optional session ID to group commands.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Exit code if the command was executed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Parent command ID for subshell tracking.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_command_id: Option<i64>,
    /// Hostname for multi-machine setups.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Allowlist layer that matched (if command was allowed by allowlist).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowlist_layer: Option<String>,
    /// Bypass code used (if command was bypassed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bypass_code: Option<String>,
}

impl Default for CommandEntry {
    fn default() -> Self {
        Self {
            timestamp: Utc::now(),
            agent_type: String::new(),
            working_dir: String::new(),
            command: String::new(),
            outcome: Outcome::Allow,
            pack_id: None,
            pattern_name: None,
            eval_duration_us: 0,
            session_id: None,
            exit_code: None,
            parent_command_id: None,
            hostname: None,
            allowlist_layer: None,
            bypass_code: None,
        }
    }
}

impl CommandEntry {
    /// Compute a SHA256 hash of the command for deduplication/grouping.
    #[must_use]
    pub fn command_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.command.as_bytes());
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(digest.len() * 2);
        for byte in digest {
            let _ = write!(hex, "{byte:02x}");
        }
        hex
    }
}

/// Telemetry database handle.
pub struct TelemetryDb {
    conn: Connection,
    path: Option<PathBuf>,
}

impl TelemetryDb {
    /// Open or create the telemetry database at the default path.
    ///
    /// The default path is `~/.config/dcg/telemetry.db` unless overridden
    /// by the `DCG_TELEMETRY_DB` environment variable.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or initialized.
    pub fn open(path: Option<PathBuf>) -> Result<Self, TelemetryError> {
        // Check if telemetry is disabled
        if env::var(super::ENV_TELEMETRY_DISABLED)
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false)
        {
            return Err(TelemetryError::Disabled);
        }

        let db_path = path.unwrap_or_else(Self::default_path);

        // Ensure parent directory exists
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(&db_path)?;
        let db = Self {
            conn,
            path: Some(db_path),
        };
        db.initialize_schema()?;
        Ok(db)
    }

    /// Open an in-memory database for testing.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be initialized.
    pub fn open_in_memory() -> Result<Self, TelemetryError> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn, path: None };
        db.initialize_schema()?;
        Ok(db)
    }

    /// Get the default database path.
    #[must_use]
    pub fn default_path() -> PathBuf {
        if let Ok(path) = env::var(super::ENV_TELEMETRY_DB_PATH) {
            return PathBuf::from(path);
        }

        let base = dirs::config_dir()
            .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".config"));
        base.join("dcg").join(DEFAULT_DB_FILENAME)
    }

    /// Get the database file path (None for in-memory).
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Get the current schema version.
    ///
    /// # Errors
    ///
    /// Returns an error if the schema version cannot be read.
    pub fn get_schema_version(&self) -> Result<u32, TelemetryError> {
        let version: u32 = self.conn.query_row(
            "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1",
            [],
            |row| row.get(0),
        )?;
        Ok(version)
    }

    /// Attempt to open the telemetry database, returning None on failure.
    ///
    /// This is intended for fail-open paths (telemetry should never block the hook).
    #[must_use]
    pub fn try_open(path: Option<PathBuf>) -> Option<Self> {
        Self::open(path).ok()
    }

    /// Get the database file size in bytes.
    ///
    /// Returns 0 for in-memory databases.
    ///
    /// # Errors
    ///
    /// Returns an error if the file metadata cannot be read.
    pub fn file_size(&self) -> Result<u64, TelemetryError> {
        match &self.path {
            Some(p) => Ok(std::fs::metadata(p)?.len()),
            None => Ok(0),
        }
    }

    /// Count total commands in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn count_commands(&self) -> Result<u64, TelemetryError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// Log a command entry to the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the insert fails.
    pub fn log_command(&self, entry: &CommandEntry) -> Result<i64, TelemetryError> {
        let command_hash = entry.command_hash();
        let timestamp = entry.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let eval_duration_us = i64::try_from(entry.eval_duration_us).unwrap_or(i64::MAX);

        self.conn.execute(
            r"INSERT INTO commands (
                timestamp, agent_type, working_dir, command, command_hash,
                outcome, pack_id, pattern_name, eval_duration_us,
                session_id, exit_code, parent_command_id, hostname,
                allowlist_layer, bypass_code
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15
            )",
            params![
                timestamp,
                entry.agent_type,
                entry.working_dir,
                entry.command,
                command_hash,
                entry.outcome.as_str(),
                entry.pack_id,
                entry.pattern_name,
                eval_duration_us,
                entry.session_id,
                entry.exit_code,
                entry.parent_command_id,
                entry.hostname,
                entry.allowlist_layer,
                entry.bypass_code,
            ],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Run VACUUM to reclaim space after deletions.
    ///
    /// # Errors
    ///
    /// Returns an error if the VACUUM fails.
    pub fn vacuum(&self) -> Result<(), TelemetryError> {
        self.conn.execute("VACUUM", [])?;
        Ok(())
    }

    /// Initialize the database schema.
    fn initialize_schema(&self) -> Result<(), TelemetryError> {
        // Enable WAL mode for better concurrent performance
        self.conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        // Create schema version table
        self.conn.execute(
            r"CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now')),
                description TEXT NOT NULL DEFAULT 'Initial schema'
            )",
            [],
        )?;

        // Check if we need to initialize
        let needs_init: bool = self
            .conn
            .query_row("SELECT COUNT(*) = 0 FROM schema_version", [], |row| {
                row.get(0)
            })
            .unwrap_or(true);

        if needs_init {
            self.create_v1_schema()?;
        } else {
            // Run migrations if needed
            let version = self.get_schema_version()?;
            if version < CURRENT_SCHEMA_VERSION {
                self.run_migrations(version)?;
            }
        }

        Ok(())
    }

    /// Create the v1 schema (initial version).
    fn create_v1_schema(&self) -> Result<(), TelemetryError> {
        // Main commands table
        self.conn.execute(
            r"CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                agent_type TEXT NOT NULL,
                working_dir TEXT NOT NULL,
                command TEXT NOT NULL,
                command_hash TEXT NOT NULL,
                outcome TEXT NOT NULL CHECK (outcome IN ('allow', 'deny', 'warn', 'bypass')),
                pack_id TEXT,
                pattern_name TEXT,
                eval_duration_us INTEGER DEFAULT 0,
                session_id TEXT,
                exit_code INTEGER,
                parent_command_id INTEGER REFERENCES commands(id),
                hostname TEXT,
                allowlist_layer TEXT,
                bypass_code TEXT
            )",
            [],
        )?;

        // Create indexes for common query patterns
        self.conn.execute_batch(
            r"
            -- Time-based queries (most common)
            CREATE INDEX IF NOT EXISTS idx_commands_timestamp ON commands(timestamp);

            -- Outcome filtering
            CREATE INDEX IF NOT EXISTS idx_commands_outcome ON commands(outcome);

            -- Project-specific queries
            CREATE INDEX IF NOT EXISTS idx_commands_working_dir ON commands(working_dir);

            -- Pack analysis
            CREATE INDEX IF NOT EXISTS idx_commands_pack_id ON commands(pack_id);

            -- Agent breakdown
            CREATE INDEX IF NOT EXISTS idx_commands_agent_type ON commands(agent_type);

            -- Session grouping
            CREATE INDEX IF NOT EXISTS idx_commands_session_id ON commands(session_id);

            -- Command hash for deduplication analysis
            CREATE INDEX IF NOT EXISTS idx_commands_command_hash ON commands(command_hash);

            -- Composite index for common query patterns
            CREATE INDEX IF NOT EXISTS idx_commands_outcome_timestamp
                ON commands(outcome, timestamp);

            CREATE INDEX IF NOT EXISTS idx_commands_pack_outcome
                ON commands(pack_id, outcome);
            ",
        )?;

        // Create FTS5 virtual table for full-text search
        self.conn.execute(
            r"CREATE VIRTUAL TABLE IF NOT EXISTS commands_fts USING fts5(
                command,
                content='commands',
                content_rowid='id'
            )",
            [],
        )?;

        // Create triggers to keep FTS in sync
        self.conn.execute_batch(
            r"
            -- Trigger for INSERT
            CREATE TRIGGER IF NOT EXISTS commands_fts_insert AFTER INSERT ON commands BEGIN
                INSERT INTO commands_fts(rowid, command) VALUES (new.id, new.command);
            END;

            -- Trigger for DELETE
            CREATE TRIGGER IF NOT EXISTS commands_fts_delete AFTER DELETE ON commands BEGIN
                INSERT INTO commands_fts(commands_fts, rowid, command)
                    VALUES('delete', old.id, old.command);
            END;

            -- Trigger for UPDATE
            CREATE TRIGGER IF NOT EXISTS commands_fts_update AFTER UPDATE ON commands BEGIN
                INSERT INTO commands_fts(commands_fts, rowid, command)
                    VALUES('delete', old.id, old.command);
                INSERT INTO commands_fts(rowid, command) VALUES (new.id, new.command);
            END;
            ",
        )?;

        // Record schema version
        self.conn.execute(
            "INSERT INTO schema_version (version, description) VALUES (?1, ?2)",
            params![CURRENT_SCHEMA_VERSION, "Initial schema"],
        )?;

        Ok(())
    }

    /// Run migrations from a given version to current.
    fn run_migrations(&self, from_version: u32) -> Result<(), TelemetryError> {
        // Apply migrations in order.
        if from_version < 2 {
            self.migrate_v1_to_v2()?;
        }

        // Ensure we're at the expected version
        let current = self.get_schema_version()?;
        if current != CURRENT_SCHEMA_VERSION {
            return Err(TelemetryError::SchemaMismatch {
                expected: CURRENT_SCHEMA_VERSION,
                found: current,
            });
        }

        Ok(())
    }

    fn schema_version_has_description(&self) -> Result<bool, TelemetryError> {
        let columns: Vec<String> = self
            .conn
            .prepare("PRAGMA table_info(schema_version)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<_, _>>()?;
        Ok(columns.iter().any(|col| col == "description"))
    }

    fn migrate_v1_to_v2(&self) -> Result<(), TelemetryError> {
        if !self.schema_version_has_description()? {
            self.conn.execute(
                "ALTER TABLE schema_version ADD COLUMN description TEXT NOT NULL DEFAULT 'Initial schema'",
                [],
            )?;
        }

        self.conn.execute(
            "INSERT INTO schema_version (version, description) VALUES (?1, ?2)",
            params![2_u32, "Add schema version descriptions"],
        )?;
        Ok(())
    }

    /// Access the underlying connection for advanced queries.
    ///
    /// This is primarily for testing and advanced use cases.
    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.conn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type OptionalFields = (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );

    fn reset_schema_version_to_v1(db: &TelemetryDb) {
        db.conn.execute("DROP TABLE schema_version", []).unwrap();
        db.conn
            .execute(
                r"CREATE TABLE schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
                )",
                [],
            )
            .unwrap();
        db.conn
            .execute("INSERT INTO schema_version (version) VALUES (1)", [])
            .unwrap();
    }

    fn test_entry() -> CommandEntry {
        CommandEntry {
            timestamp: Utc::now(),
            agent_type: "claude_code".to_string(),
            working_dir: "/test/project".to_string(),
            command: "git status".to_string(),
            outcome: Outcome::Allow,
            ..Default::default()
        }
    }

    #[test]
    fn test_schema_creation() {
        let db = TelemetryDb::open_in_memory().unwrap();

        // Verify all expected tables exist
        let tables: Vec<String> = db
            .conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();

        assert!(tables.contains(&"commands".to_string()));
        assert!(tables.contains(&"schema_version".to_string()));
    }

    #[test]
    fn test_commands_table_columns() {
        let db = TelemetryDb::open_in_memory().unwrap();

        let columns: Vec<String> = db
            .conn
            .prepare("PRAGMA table_info(commands)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();

        // Required columns
        assert!(columns.contains(&"id".to_string()));
        assert!(columns.contains(&"timestamp".to_string()));
        assert!(columns.contains(&"agent_type".to_string()));
        assert!(columns.contains(&"working_dir".to_string()));
        assert!(columns.contains(&"command".to_string()));
        assert!(columns.contains(&"command_hash".to_string()));
        assert!(columns.contains(&"outcome".to_string()));
        assert!(columns.contains(&"eval_duration_us".to_string()));

        // Optional columns from bead spec
        assert!(columns.contains(&"session_id".to_string()));
        assert!(columns.contains(&"exit_code".to_string()));
        assert!(columns.contains(&"parent_command_id".to_string()));
        assert!(columns.contains(&"hostname".to_string()));
    }

    #[test]
    fn test_indexes_created() {
        let db = TelemetryDb::open_in_memory().unwrap();

        let indexes: Vec<String> = db
            .conn
            .prepare("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();

        // Performance-critical indexes
        assert!(indexes.iter().any(|i| i.contains("timestamp")));
        assert!(indexes.iter().any(|i| i.contains("outcome")));
        assert!(indexes.iter().any(|i| i.contains("working_dir")));
        assert!(indexes.iter().any(|i| i.contains("pack_id")));
        assert!(indexes.iter().any(|i| i.contains("agent_type")));
    }

    #[test]
    fn test_fts_table_created() {
        let db = TelemetryDb::open_in_memory().unwrap();

        // FTS5 virtual table for full-text search
        let result = db.conn.query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='commands_fts'",
            [],
            |_| Ok(()),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_insert_and_query() {
        let db = TelemetryDb::open_in_memory().unwrap();

        let entry = test_entry();
        db.log_command(&entry).unwrap();

        let count: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))
            .unwrap();

        assert_eq!(count, 1);
    }

    #[test]
    fn test_timestamp_format() {
        let db = TelemetryDb::open_in_memory().unwrap();

        let entry = test_entry();
        db.log_command(&entry).unwrap();

        let stored: String = db
            .conn
            .query_row("SELECT timestamp FROM commands LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap();

        // ISO 8601 format with T separator
        assert!(stored.contains('T'));
        assert!(stored.ends_with('Z'));
    }

    #[test]
    fn test_schema_version() {
        let db = TelemetryDb::open_in_memory().unwrap();
        let version = db.get_schema_version().unwrap();
        assert_eq!(version, CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn test_database_creation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");

        assert!(!db_path.exists());
        let _db = TelemetryDb::open(Some(db_path.clone())).unwrap();
        assert!(db_path.exists());
    }

    #[test]
    fn test_parent_directory_created() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("nested/deep/test.db");

        let _db = TelemetryDb::open(Some(db_path.clone())).unwrap();
        assert!(db_path.exists());
    }

    #[test]
    fn test_wal_mode_enabled() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("wal.db");
        let db = TelemetryDb::open(Some(db_path)).unwrap();

        let mode: String = db
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();

        assert_eq!(mode.to_lowercase(), "wal");
    }

    #[test]
    fn test_try_open_corruption_returns_none() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("corrupt.db");

        std::fs::write(&db_path, b"not a valid sqlite db").unwrap();
        let result = TelemetryDb::try_open(Some(db_path));
        assert!(result.is_none());
    }

    #[test]
    #[cfg(unix)]
    fn test_try_open_permission_denied_returns_none() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().unwrap();
        let dir_path = temp_dir.path().join("readonly");
        std::fs::create_dir(&dir_path).unwrap();

        std::fs::set_permissions(&dir_path, std::fs::Permissions::from_mode(0o444)).unwrap();

        let db_path = dir_path.join("test.db");
        let result = TelemetryDb::try_open(Some(db_path));
        assert!(result.is_none());

        // Restore permissions so temp_dir cleanup can succeed
        std::fs::set_permissions(&dir_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn test_migration_adds_schema_version_description() {
        let db = TelemetryDb::open_in_memory().unwrap();
        reset_schema_version_to_v1(&db);

        db.run_migrations(1).unwrap();

        let version = db.get_schema_version().unwrap();
        assert_eq!(version, CURRENT_SCHEMA_VERSION);

        let description_count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM schema_version WHERE description IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(description_count > 0);
    }

    #[test]
    fn test_command_hash_deterministic() {
        let entry1 = CommandEntry {
            command: "git status".to_string(),
            ..Default::default()
        };
        let entry2 = CommandEntry {
            command: "git status".to_string(),
            ..Default::default()
        };

        assert_eq!(entry1.command_hash(), entry2.command_hash());
        assert_eq!(entry1.command_hash().len(), 64); // SHA256 = 64 hex chars
    }

    #[test]
    fn test_outcome_roundtrip() {
        for outcome in [
            Outcome::Allow,
            Outcome::Deny,
            Outcome::Warn,
            Outcome::Bypass,
        ] {
            let s = outcome.as_str();
            let parsed = Outcome::parse(s).unwrap();
            assert_eq!(outcome, parsed);
        }
    }

    #[test]
    fn test_fts_search() {
        let db = TelemetryDb::open_in_memory().unwrap();

        // Insert a few commands
        db.log_command(&CommandEntry {
            command: "git push origin main".to_string(),
            ..Default::default()
        })
        .unwrap();
        db.log_command(&CommandEntry {
            command: "npm install lodash".to_string(),
            ..Default::default()
        })
        .unwrap();
        db.log_command(&CommandEntry {
            command: "git pull origin feature".to_string(),
            ..Default::default()
        })
        .unwrap();

        // Search for git commands
        let count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM commands_fts WHERE commands_fts MATCH 'git'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(count, 2);
    }

    #[test]
    fn test_count_commands_empty() {
        let db = TelemetryDb::open_in_memory().unwrap();
        assert_eq!(db.count_commands().unwrap(), 0);
    }

    #[test]
    fn test_count_commands_with_data() {
        let db = TelemetryDb::open_in_memory().unwrap();

        for i in 0..10 {
            db.log_command(&CommandEntry {
                command: format!("command {i}"),
                ..Default::default()
            })
            .unwrap();
        }

        assert_eq!(db.count_commands().unwrap(), 10);
    }

    #[test]
    fn test_file_size_in_memory() {
        let db = TelemetryDb::open_in_memory().unwrap();
        assert_eq!(db.file_size().unwrap(), 0);
    }

    #[test]
    fn test_all_optional_fields() {
        let db = TelemetryDb::open_in_memory().unwrap();

        let entry = CommandEntry {
            timestamp: Utc::now(),
            agent_type: "claude_code".to_string(),
            working_dir: "/project".to_string(),
            command: "test command".to_string(),
            outcome: Outcome::Deny,
            pack_id: Some("core.git".to_string()),
            pattern_name: Some("force-push".to_string()),
            eval_duration_us: 1500,
            session_id: Some("session-123".to_string()),
            exit_code: Some(0),
            parent_command_id: None,
            hostname: Some("dev-machine".to_string()),
            allowlist_layer: None,
            bypass_code: Some("ab12".to_string()),
        };

        let id = db.log_command(&entry).unwrap();
        assert!(id > 0);

        // Verify all fields stored correctly
        let (pack_id, pattern_name, session_id, hostname, bypass_code): OptionalFields = db
            .conn
            .query_row(
                "SELECT pack_id, pattern_name, session_id, hostname, bypass_code
                 FROM commands WHERE id = ?1",
                params![id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();

        assert_eq!(pack_id, Some("core.git".to_string()));
        assert_eq!(pattern_name, Some("force-push".to_string()));
        assert_eq!(session_id, Some("session-123".to_string()));
        assert_eq!(hostname, Some("dev-machine".to_string()));
        assert_eq!(bypass_code, Some("ab12".to_string()));
    }

    #[test]
    fn test_outcome_constraint() {
        let db = TelemetryDb::open_in_memory().unwrap();

        // Valid outcome should work
        db.conn
            .execute(
                "INSERT INTO commands (timestamp, agent_type, working_dir, command, command_hash, outcome)
                 VALUES ('2026-01-01T00:00:00Z', 'test', '/test', 'cmd', 'hash', 'allow')",
                [],
            )
            .unwrap();

        // Invalid outcome should fail
        let result = db.conn.execute(
            "INSERT INTO commands (timestamp, agent_type, working_dir, command, command_hash, outcome)
             VALUES ('2026-01-01T00:00:00Z', 'test', '/test', 'cmd', 'hash', 'invalid')",
            [],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_reopen_existing_db() {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("test.db");

        // Create and populate
        {
            let db = TelemetryDb::open(Some(db_path.clone())).unwrap();
            db.log_command(&test_entry()).unwrap();
            assert_eq!(db.count_commands().unwrap(), 1);
        }

        // Reopen and verify
        {
            let db = TelemetryDb::open(Some(db_path)).unwrap();
            assert_eq!(db.count_commands().unwrap(), 1);
            assert_eq!(db.get_schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
        }
    }
}
