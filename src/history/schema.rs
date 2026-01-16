//! `SQLite` schema definitions for command history.
//!
//! This module defines the database schema, types, and core operations for
//! the history system. The schema is designed for:
//!
//! - Efficient writes during hook execution (< 1ms target)
//! - Flexible queries for analytics and debugging
//! - Full-text search on command content
//! - Graceful schema migrations

use chrono::{DateTime, Duration, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fmt::Write as FmtWrite;
use std::path::{Path, PathBuf};

/// Current schema version for migrations.
pub const CURRENT_SCHEMA_VERSION: u32 = 4;

/// Default database filename.
pub const DEFAULT_DB_FILENAME: &str = "history.db";

/// History-specific error type.
#[derive(Debug)]
pub enum HistoryError {
    /// `SQLite` error.
    Sqlite(rusqlite::Error),
    /// I/O error.
    Io(std::io::Error),
    /// Schema version mismatch (expected, found).
    SchemaMismatch { expected: u32, found: u32 },
    /// Database is disabled.
    Disabled,
    /// Database integrity check failed.
    IntegrityCheckFailed(String),
    /// Backup operation failed.
    BackupFailed(String),
}

impl std::fmt::Display for HistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "SQLite error: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::SchemaMismatch { expected, found } => {
                write!(f, "Schema mismatch: expected v{expected}, found v{found}")
            }
            Self::Disabled => write!(f, "History is disabled"),
            Self::IntegrityCheckFailed(msg) => write!(f, "Integrity check failed: {msg}"),
            Self::BackupFailed(msg) => write!(f, "Backup failed: {msg}"),
        }
    }
}

impl std::error::Error for HistoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlite(e) => Some(e),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for HistoryError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

impl From<std::io::Error> for HistoryError {
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

/// A single command entry for the history database.
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
    /// Stable rule identifier: `pack_id:pattern_name`
    /// Present only for denied commands that matched a pattern.
    /// Format: "core.git:reset-hard", "core.filesystem:rm-rf-root"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
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
            rule_id: None,
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
    /// Compute and return the `rule_id` from `pack_id` and `pattern_name`.
    /// Returns `Some("pack_id:pattern_name")` if both are present, else `None`.
    #[must_use]
    pub fn compute_rule_id(&self) -> Option<String> {
        match (&self.pack_id, &self.pattern_name) {
            (Some(pack), Some(pattern)) => Some(format!("{pack}:{pattern}")),
            _ => None,
        }
    }

    /// Get the `rule_id`, using the stored value or computing it from parts.
    #[must_use]
    pub fn get_rule_id(&self) -> Option<String> {
        self.rule_id.clone().or_else(|| self.compute_rule_id())
    }

    /// Ensure `rule_id` is set from `pack_id` and `pattern_name` if not already set.
    /// Returns true if `rule_id` was set or already present.
    pub fn ensure_rule_id(&mut self) -> bool {
        if self.rule_id.is_some() {
            return true;
        }
        self.rule_id = self.compute_rule_id();
        self.rule_id.is_some()
    }
}

/// Aggregate outcome counts for history stats.
#[derive(Debug, Clone, Default, Serialize)]
pub struct OutcomeStats {
    pub allowed: u64,
    pub denied: u64,
    pub warned: u64,
    pub bypassed: u64,
}

/// Performance percentiles for history stats.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PerformanceStats {
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
}

/// Top pattern count summary.
#[derive(Debug, Clone, Serialize)]
pub struct PatternStat {
    pub name: String,
    pub count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pack_id: Option<String>,
}

/// Top project summary.
#[derive(Debug, Clone, Serialize)]
pub struct ProjectStat {
    pub path: String,
    pub command_count: u64,
}

/// Agent breakdown summary.
#[derive(Debug, Clone, Serialize)]
pub struct AgentStat {
    pub name: String,
    pub count: u64,
}

/// Trend comparison for history stats.
#[derive(Debug, Clone, Serialize)]
pub struct StatsTrends {
    pub commands_change: f64,
    pub block_rate_change: f64,
    pub top_pattern_change: Vec<(String, i32)>,
}

/// Result of a database health check.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    /// `SQLite` integrity check result (should be "ok").
    pub integrity_check: String,
    /// Whether the integrity check passed.
    pub integrity_ok: bool,
    /// Foreign key check result count (0 = no violations).
    pub foreign_key_violations: usize,
    /// Number of commands in main table.
    pub commands_count: u64,
    /// Number of entries in FTS index.
    pub fts_count: u64,
    /// Whether FTS index is in sync with main table.
    pub fts_in_sync: bool,
    /// Current journal mode.
    pub journal_mode: String,
    /// Database file size in bytes.
    pub file_size_bytes: u64,
    /// WAL file size in bytes (0 if not using WAL).
    pub wal_size_bytes: u64,
    /// Current schema version.
    pub schema_version: u32,
    /// Page size in bytes.
    pub page_size: u32,
    /// Total page count.
    pub page_count: u64,
    /// Free list page count.
    pub freelist_count: u64,
}

/// Result of a database backup operation.
#[derive(Debug, Clone, Serialize)]
pub struct BackupResult {
    /// Path to the backup file.
    pub backup_path: String,
    /// Size of the backup file in bytes.
    pub backup_size_bytes: u64,
    /// Whether the backup was compressed.
    pub compressed: bool,
    /// Time taken to create backup in milliseconds.
    pub duration_ms: u64,
    /// Whether backup integrity was verified.
    pub verified: bool,
}

/// Aggregated history stats for a time window.
#[derive(Debug, Clone, Serialize)]
pub struct HistoryStats {
    pub period_days: u64,
    pub total_commands: u64,
    pub outcomes: OutcomeStats,
    pub block_rate: f64,
    pub top_patterns: Vec<PatternStat>,
    pub top_projects: Vec<ProjectStat>,
    pub agents: Vec<AgentStat>,
    pub performance: PerformanceStats,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trends: Option<StatsTrends>,
}

#[derive(Debug, Clone)]
struct StatsSnapshot {
    total_commands: u64,
    outcomes: OutcomeStats,
    block_rate: f64,
    top_patterns: Vec<PatternStat>,
    top_projects: Vec<ProjectStat>,
    agents: Vec<AgentStat>,
    performance: PerformanceStats,
}

fn format_timestamp(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn percentile_from_sorted(values: &[u64], numerator: usize, denominator: usize) -> u64 {
    if values.is_empty() || denominator == 0 {
        return 0;
    }

    let max_index = values.len() - 1;
    let numerator = numerator.min(denominator);
    let idx = (max_index * numerator + (denominator / 2)) / denominator;
    values[idx.min(max_index)]
}

#[allow(clippy::cast_precision_loss)]
fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    numerator as f64 / denominator as f64
}

#[allow(clippy::cast_precision_loss)]
fn percent_change(current: u64, previous: u64) -> f64 {
    if previous == 0 {
        return if current == 0 { 0.0 } else { 100.0 };
    }
    ((current as f64 - previous as f64) / previous as f64) * 100.0
}

fn build_trends(current: &StatsSnapshot, previous: &StatsSnapshot) -> StatsTrends {
    let prev_patterns: HashMap<&str, i32> = previous
        .top_patterns
        .iter()
        .enumerate()
        .map(|(idx, stat)| {
            let rank = i32::try_from(idx + 1).unwrap_or(i32::MAX);
            (stat.name.as_str(), rank)
        })
        .collect();

    let top_pattern_change = current
        .top_patterns
        .iter()
        .enumerate()
        .map(|(idx, stat)| {
            let current_rank = i32::try_from(idx + 1).unwrap_or(i32::MAX);
            let prev_rank = prev_patterns
                .get(stat.name.as_str())
                .copied()
                .unwrap_or(current_rank);
            (stat.name.clone(), prev_rank - current_rank)
        })
        .collect::<Vec<_>>();

    StatsTrends {
        commands_change: percent_change(current.total_commands, previous.total_commands),
        block_rate_change: (current.block_rate - previous.block_rate) * 100.0,
        top_pattern_change,
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

/// History database handle.
pub struct HistoryDb {
    conn: Connection,
    path: Option<PathBuf>,
}

impl HistoryDb {
    /// Open or create the history database at the default path.
    ///
    /// The default path is `~/.config/dcg/history.db` unless overridden
    /// by the `DCG_HISTORY_DB` environment variable.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or initialized.
    pub fn open(path: Option<PathBuf>) -> Result<Self, HistoryError> {
        // Check if history is disabled
        if env::var(super::ENV_HISTORY_DISABLED)
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false)
        {
            return Err(HistoryError::Disabled);
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
    pub fn open_in_memory() -> Result<Self, HistoryError> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn, path: None };
        db.initialize_schema()?;
        Ok(db)
    }

    /// Get the default database path.
    #[must_use]
    pub fn default_path() -> PathBuf {
        if let Ok(path) = env::var(super::ENV_HISTORY_DB_PATH) {
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
    pub fn get_schema_version(&self) -> Result<u32, HistoryError> {
        let version: u32 = self.conn.query_row(
            "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1",
            [],
            |row| row.get(0),
        )?;
        Ok(version)
    }

    /// Attempt to open the history database, returning None on failure.
    ///
    /// This is intended for fail-open paths (history should never block the hook).
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
    pub fn file_size(&self) -> Result<u64, HistoryError> {
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
    pub fn count_commands(&self) -> Result<u64, HistoryError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// Prune history entries older than the specified number of days.
    ///
    /// When `dry_run` is true, no rows are deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if any query fails.
    pub fn prune_older_than_days(
        &self,
        older_than_days: u64,
        dry_run: bool,
    ) -> Result<u64, HistoryError> {
        let days_i64 = i64::try_from(older_than_days).unwrap_or(i64::MAX);
        let cutoff = Utc::now() - Duration::days(days_i64);
        let cutoff_ts = format_timestamp(cutoff);

        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM commands WHERE timestamp < ?1",
            [cutoff_ts.clone()],
            |row| row.get(0),
        )?;

        if !dry_run {
            let _ = self
                .conn
                .execute("DELETE FROM commands WHERE timestamp < ?1", [cutoff_ts])?;
        }

        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// Compute history stats for the last `period_days` days.
    ///
    /// # Errors
    ///
    /// Returns an error if any underlying query fails.
    pub fn compute_stats(&self, period_days: u64) -> Result<HistoryStats, HistoryError> {
        let now = Utc::now();
        let period_days_i64 = i64::try_from(period_days).unwrap_or(i64::MAX);
        let since = now - Duration::days(period_days_i64);
        let snapshot = self.compute_stats_range(since, now)?;
        Ok(HistoryStats {
            period_days,
            total_commands: snapshot.total_commands,
            outcomes: snapshot.outcomes,
            block_rate: snapshot.block_rate,
            top_patterns: snapshot.top_patterns,
            top_projects: snapshot.top_projects,
            agents: snapshot.agents,
            performance: snapshot.performance,
            trends: None,
        })
    }

    /// Compute history stats with trend comparison against the previous period.
    ///
    /// # Errors
    ///
    /// Returns an error if any underlying query fails.
    pub fn compute_stats_with_trends(
        &self,
        period_days: u64,
    ) -> Result<HistoryStats, HistoryError> {
        let now = Utc::now();
        let period_days_i64 = i64::try_from(period_days).unwrap_or(i64::MAX);
        let since = now - Duration::days(period_days_i64);
        let prev_start = since - Duration::days(period_days_i64);

        let current = self.compute_stats_range(since, now)?;
        let previous = self.compute_stats_range(prev_start, since)?;

        let trends = build_trends(&current, &previous);

        Ok(HistoryStats {
            period_days,
            total_commands: current.total_commands,
            outcomes: current.outcomes,
            block_rate: current.block_rate,
            top_patterns: current.top_patterns,
            top_projects: current.top_projects,
            agents: current.agents,
            performance: current.performance,
            trends: Some(trends),
        })
    }

    #[allow(clippy::too_many_lines)]
    fn compute_stats_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<StatsSnapshot, HistoryError> {
        let start_ts = format_timestamp(start);
        let end_ts = format_timestamp(end);

        let total: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM commands WHERE timestamp >= ?1 AND timestamp < ?2",
            params![&start_ts, &end_ts],
            |row| row.get(0),
        )?;
        let total_commands = u64::try_from(total).unwrap_or(0);

        let mut outcomes = OutcomeStats::default();
        let mut stmt = self.conn.prepare(
            "SELECT outcome, COUNT(*) FROM commands
             WHERE timestamp >= ?1 AND timestamp < ?2
             GROUP BY outcome",
        )?;
        let rows = stmt.query_map(params![&start_ts, &end_ts], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (outcome, count) = row?;
            let count = u64::try_from(count).unwrap_or(0);
            match Outcome::parse(&outcome) {
                Some(Outcome::Allow) => outcomes.allowed = count,
                Some(Outcome::Deny) => outcomes.denied = count,
                Some(Outcome::Warn) => outcomes.warned = count,
                Some(Outcome::Bypass) => outcomes.bypassed = count,
                None => {}
            }
        }

        let block_rate = ratio(outcomes.denied, total_commands);

        let mut top_patterns = Vec::new();
        let mut stmt = self.conn.prepare(
            "SELECT pattern_name, pack_id, COUNT(*) FROM commands
             WHERE timestamp >= ?1 AND timestamp < ?2 AND pattern_name IS NOT NULL
             GROUP BY pattern_name, pack_id
             ORDER BY COUNT(*) DESC, pattern_name ASC
             LIMIT 10",
        )?;
        let rows = stmt.query_map(params![&start_ts, &end_ts], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (name, pack_id, count) = row?;
            top_patterns.push(PatternStat {
                name,
                count: u64::try_from(count).unwrap_or(0),
                pack_id,
            });
        }

        let mut top_projects = Vec::new();
        let mut stmt = self.conn.prepare(
            "SELECT working_dir, COUNT(*) FROM commands
             WHERE timestamp >= ?1 AND timestamp < ?2
             GROUP BY working_dir
             ORDER BY COUNT(*) DESC, working_dir ASC
             LIMIT 10",
        )?;
        let rows = stmt.query_map(params![&start_ts, &end_ts], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (path, count) = row?;
            top_projects.push(ProjectStat {
                path,
                command_count: u64::try_from(count).unwrap_or(0),
            });
        }

        let mut agents = Vec::new();
        let mut stmt = self.conn.prepare(
            "SELECT agent_type, COUNT(*) FROM commands
             WHERE timestamp >= ?1 AND timestamp < ?2
             GROUP BY agent_type
             ORDER BY COUNT(*) DESC, agent_type ASC",
        )?;
        let rows = stmt.query_map(params![&start_ts, &end_ts], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (name, count) = row?;
            agents.push(AgentStat {
                name,
                count: u64::try_from(count).unwrap_or(0),
            });
        }

        let mut durations = Vec::new();
        let mut stmt = self.conn.prepare(
            "SELECT eval_duration_us FROM commands
             WHERE timestamp >= ?1 AND timestamp < ?2 AND eval_duration_us > 0
             ORDER BY eval_duration_us ASC",
        )?;
        let rows = stmt.query_map(params![&start_ts, &end_ts], |row| {
            let value: i64 = row.get(0)?;
            Ok(value)
        })?;
        for row in rows {
            let value = row?;
            if let Ok(value) = u64::try_from(value) {
                durations.push(value);
            }
        }

        let performance = if durations.is_empty() {
            PerformanceStats::default()
        } else {
            let max_us = *durations.last().unwrap_or(&0);
            PerformanceStats {
                p50_us: percentile_from_sorted(&durations, 50, 100),
                p95_us: percentile_from_sorted(&durations, 95, 100),
                p99_us: percentile_from_sorted(&durations, 99, 100),
                max_us,
            }
        };

        Ok(StatsSnapshot {
            total_commands,
            outcomes,
            block_rate,
            top_patterns,
            top_projects,
            agents,
            performance,
        })
    }

    /// Log a command entry to the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the insert fails.
    pub fn log_command(&self, entry: &CommandEntry) -> Result<i64, HistoryError> {
        let command_hash = entry.command_hash();
        let timestamp = entry.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let eval_duration_us = i64::try_from(entry.eval_duration_us).unwrap_or(i64::MAX);

        // Compute rule_id if not already set but pack_id and pattern_name are present
        let rule_id = entry.rule_id.clone().or_else(|| entry.compute_rule_id());

        self.conn.execute(
            r"INSERT INTO commands (
                timestamp, agent_type, working_dir, command, command_hash,
                outcome, pack_id, pattern_name, rule_id, eval_duration_us,
                session_id, exit_code, parent_command_id, hostname,
                allowlist_layer, bypass_code
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16
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
                rule_id,
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
    pub fn vacuum(&self) -> Result<(), HistoryError> {
        self.conn.execute("VACUUM", [])?;
        Ok(())
    }

    /// Initialize the database schema.
    fn initialize_schema(&self) -> Result<(), HistoryError> {
        // Enable WAL mode for better concurrent performance
        self.conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        // Set busy timeout for better concurrent access (5 seconds default)
        self.conn.execute_batch("PRAGMA busy_timeout=5000;")?;

        // Configure WAL checkpoint behavior
        self.conn.execute_batch("PRAGMA wal_autocheckpoint=1000;")?;

        // Create schema version table (includes all columns up to v3)
        self.conn.execute(
            r"CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now')),
                description TEXT NOT NULL DEFAULT 'Initial schema',
                last_prune_at TEXT
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
    fn create_v1_schema(&self) -> Result<(), HistoryError> {
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
                rule_id TEXT,
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

            -- Rule ID for per-pattern analytics (only indexed for non-NULL values)
            CREATE INDEX IF NOT EXISTS idx_commands_rule_id ON commands(rule_id)
                WHERE rule_id IS NOT NULL;

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

        // Create stats_cache table for real-time statistics (v3 feature)
        self.conn.execute(
            r"CREATE TABLE IF NOT EXISTS stats_cache (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )",
            [],
        )?;

        // Record schema version
        self.conn.execute(
            "INSERT INTO schema_version (version, description, last_prune_at) VALUES (?1, ?2, NULL)",
            params![CURRENT_SCHEMA_VERSION, "Initial schema"],
        )?;

        Ok(())
    }

    /// Run migrations from a given version to current.
    fn run_migrations(&self, from_version: u32) -> Result<(), HistoryError> {
        // Apply migrations in order.
        if from_version < 2 {
            self.migrate_v1_to_v2()?;
        }
        if from_version < 3 {
            self.migrate_v2_to_v3()?;
        }
        if from_version < 4 {
            self.migrate_v3_to_v4()?;
        }

        // Ensure we're at the expected version
        let current = self.get_schema_version()?;
        if current != CURRENT_SCHEMA_VERSION {
            return Err(HistoryError::SchemaMismatch {
                expected: CURRENT_SCHEMA_VERSION,
                found: current,
            });
        }

        Ok(())
    }

    fn schema_version_has_description(&self) -> Result<bool, HistoryError> {
        let columns: Vec<String> = self
            .conn
            .prepare("PRAGMA table_info(schema_version)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<_, _>>()?;
        Ok(columns.iter().any(|col| col == "description"))
    }

    fn migrate_v1_to_v2(&self) -> Result<(), HistoryError> {
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

    fn migrate_v2_to_v3(&self) -> Result<(), HistoryError> {
        // Add stats_cache table for real-time statistics
        self.conn.execute(
            r"CREATE TABLE IF NOT EXISTS stats_cache (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )",
            [],
        )?;

        // Add last_prune_at column to schema_version for auto-prune tracking
        // Check if column exists first
        let columns: Vec<String> = self
            .conn
            .prepare("PRAGMA table_info(schema_version)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<_, _>>()?;

        if !columns.iter().any(|col| col == "last_prune_at") {
            self.conn.execute(
                "ALTER TABLE schema_version ADD COLUMN last_prune_at TEXT",
                [],
            )?;
        }

        // Record migration
        self.conn.execute(
            "INSERT INTO schema_version (version, description) VALUES (?1, ?2)",
            params![3_u32, "Add stats cache and auto-prune tracking"],
        )?;

        Ok(())
    }

    fn migrate_v3_to_v4(&self) -> Result<(), HistoryError> {
        // Add rule_id column for stable pattern identification
        // Check if column exists first
        let columns: Vec<String> = self
            .conn
            .prepare("PRAGMA table_info(commands)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<_, _>>()?;

        if !columns.iter().any(|col| col == "rule_id") {
            self.conn
                .execute("ALTER TABLE commands ADD COLUMN rule_id TEXT", [])?;
        }

        // Backfill rule_id from existing pack_id and pattern_name
        self.conn.execute(
            r"UPDATE commands
              SET rule_id = pack_id || ':' || pattern_name
              WHERE rule_id IS NULL
                AND pack_id IS NOT NULL
                AND pattern_name IS NOT NULL",
            [],
        )?;

        // Create index for rule_id queries (partial index for non-NULL values)
        self.conn.execute(
            r"CREATE INDEX IF NOT EXISTS idx_commands_rule_id
              ON commands(rule_id) WHERE rule_id IS NOT NULL",
            [],
        )?;

        // Record migration
        self.conn.execute(
            "INSERT INTO schema_version (version, description) VALUES (?1, ?2)",
            params![4_u32, "Add rule_id column and index"],
        )?;

        Ok(())
    }

    // ========================================================================
    // Batch Operations
    // ========================================================================

    /// Log multiple command entries in a single transaction (batched insert).
    ///
    /// This is more efficient than calling `log_command` repeatedly for bulk inserts.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction fails.
    pub fn log_commands_batch(&self, entries: &[CommandEntry]) -> Result<(), HistoryError> {
        if entries.is_empty() {
            return Ok(());
        }

        let tx = self.conn.unchecked_transaction()?;

        for entry in entries {
            let command_hash = entry.command_hash();
            let timestamp = entry.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
            let eval_duration_us = i64::try_from(entry.eval_duration_us).unwrap_or(i64::MAX);

            tx.execute(
                r"INSERT INTO commands (
                    timestamp, agent_type, working_dir, command, command_hash,
                    outcome, pack_id, pattern_name, eval_duration_us,
                    session_id, exit_code, parent_command_id, hostname,
                    allowlist_layer, bypass_code, rule_id
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16
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
                    entry.get_rule_id(),
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    // ========================================================================
    // WAL and Checkpoint Operations
    // ========================================================================

    /// Manually checkpoint the WAL file.
    ///
    /// This moves committed transactions from WAL to the main database file.
    /// Uses PASSIVE mode to avoid blocking readers.
    ///
    /// # Errors
    ///
    /// Returns an error if the checkpoint fails.
    pub fn checkpoint(&self) -> Result<(), HistoryError> {
        self.conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);")?;
        Ok(())
    }

    /// Checkpoint with TRUNCATE mode (resets WAL file).
    ///
    /// This is more aggressive and may block briefly, but reclaims disk space.
    ///
    /// # Errors
    ///
    /// Returns an error if the checkpoint fails.
    pub fn checkpoint_truncate(&self) -> Result<(), HistoryError> {
        self.conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    // ========================================================================
    // Auto-Prune Support
    // ========================================================================

    /// Check if automatic pruning should run based on the last prune timestamp.
    ///
    /// Returns true if no prune has been recorded or if the last prune was
    /// more than 24 hours ago.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn should_auto_prune(&self) -> Result<bool, HistoryError> {
        let result: Option<String> = self
            .conn
            .query_row(
                "SELECT last_prune_at FROM schema_version WHERE last_prune_at IS NOT NULL ORDER BY version DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .ok();

        result.map_or(Ok(true), |timestamp_str| {
            chrono::DateTime::parse_from_rfc3339(&timestamp_str).map_or(
                Ok(true), // Invalid timestamp, assume prune needed
                |last_prune| {
                    let hours_since_prune =
                        (Utc::now() - last_prune.with_timezone(&Utc)).num_hours();
                    Ok(hours_since_prune >= 24)
                },
            )
        })
    }

    /// Record the current timestamp as the last prune time.
    ///
    /// # Errors
    ///
    /// Returns an error if the update fails.
    pub fn record_prune_timestamp(&self) -> Result<(), HistoryError> {
        let now = format_timestamp(Utc::now());
        self.conn.execute(
            "UPDATE schema_version SET last_prune_at = ?1 WHERE version = (SELECT MAX(version) FROM schema_version)",
            [now],
        )?;
        Ok(())
    }

    // ========================================================================
    // Statistics Cache
    // ========================================================================

    /// Get a cached statistic value.
    ///
    /// Returns None if the key doesn't exist or is stale (older than `max_age_secs`).
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn get_cached_stat(
        &self,
        key: &str,
        max_age_secs: i64,
    ) -> Result<Option<i64>, HistoryError> {
        let result: Option<(i64, String)> = self
            .conn
            .query_row(
                "SELECT value, updated_at FROM stats_cache WHERE key = ?1",
                [key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();

        match result {
            None => Ok(None),
            Some((value, updated_at)) => {
                if let Ok(updated) = chrono::DateTime::parse_from_rfc3339(&updated_at) {
                    let age_secs = (Utc::now() - updated.with_timezone(&Utc)).num_seconds();
                    if age_secs <= max_age_secs {
                        return Ok(Some(value));
                    }
                }
                Ok(None) // Stale or invalid timestamp
            }
        }
    }

    /// Update a cached statistic value.
    ///
    /// # Errors
    ///
    /// Returns an error if the upsert fails.
    pub fn update_cached_stat(&self, key: &str, value: i64) -> Result<(), HistoryError> {
        let now = format_timestamp(Utc::now());
        self.conn.execute(
            "INSERT INTO stats_cache (key, value, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = ?3",
            params![key, value, now],
        )?;
        Ok(())
    }

    /// Increment a cached statistic value atomically.
    ///
    /// Creates the key with value 1 if it doesn't exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn increment_cached_stat(&self, key: &str) -> Result<(), HistoryError> {
        let now = format_timestamp(Utc::now());
        self.conn.execute(
            "INSERT INTO stats_cache (key, value, updated_at) VALUES (?1, 1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = value + 1, updated_at = ?2",
            params![key, now],
        )?;
        Ok(())
    }

    // ========================================================================
    // Health Check
    // ========================================================================

    /// Perform a comprehensive database health check.
    ///
    /// Checks integrity, FTS sync, and reports statistics.
    ///
    /// # Errors
    ///
    /// Returns an error if any check query fails.
    pub fn check_health(&self) -> Result<CheckResult, HistoryError> {
        // Integrity check
        let integrity_check: String = self
            .conn
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        let integrity_ok = integrity_check == "ok";

        // Foreign key check
        let fk_violations: Vec<()> = self
            .conn
            .prepare("PRAGMA foreign_key_check")?
            .query_map([], |_| Ok(()))?
            .collect::<Result<_, _>>()?;
        let foreign_key_violations = fk_violations.len();

        // Commands count
        let commands_count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))?;
        let commands_count = u64::try_from(commands_count).unwrap_or(0);

        // FTS count
        let fts_count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM commands_fts", [], |row| row.get(0))?;
        let fts_count = u64::try_from(fts_count).unwrap_or(0);

        // Journal mode
        let journal_mode: String = self
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))?;

        // File sizes
        let file_size_bytes = self.file_size().unwrap_or(0);
        let wal_size_bytes = self.path.as_ref().map_or(0, |p| {
            // SQLite WAL files are named by appending "-wal" to the database path
            let wal_path = PathBuf::from(format!("{}-wal", p.display()));
            std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0)
        });

        // Schema version
        let schema_version = self.get_schema_version().unwrap_or(0);

        // Page info
        let page_size: i64 = self
            .conn
            .query_row("PRAGMA page_size", [], |row| row.get(0))?;
        let page_count: i64 = self
            .conn
            .query_row("PRAGMA page_count", [], |row| row.get(0))?;
        let freelist_count: i64 = self
            .conn
            .query_row("PRAGMA freelist_count", [], |row| row.get(0))?;

        Ok(CheckResult {
            integrity_check,
            integrity_ok,
            foreign_key_violations,
            commands_count,
            fts_count,
            fts_in_sync: commands_count == fts_count,
            journal_mode,
            file_size_bytes,
            wal_size_bytes,
            schema_version,
            page_size: u32::try_from(page_size).unwrap_or(0),
            page_count: u64::try_from(page_count).unwrap_or(0),
            freelist_count: u64::try_from(freelist_count).unwrap_or(0),
        })
    }

    /// Rebuild the FTS (Full-Text Search) index from scratch.
    ///
    /// This is useful for recovering from FTS corruption or when the FTS
    /// index has become out of sync with the main commands table.
    ///
    /// # Returns
    ///
    /// Returns the number of commands re-indexed.
    ///
    /// # Errors
    ///
    /// Returns an error if the rebuild fails.
    pub fn rebuild_fts(&self) -> Result<u64, HistoryError> {
        // Use a transaction to ensure atomicity - if anything fails, we roll back
        // to the previous state rather than leaving the database in an inconsistent state
        let tx = self.conn.unchecked_transaction()?;

        // First, drop triggers to prevent interference during rebuild
        tx.execute_batch(
            r"
            DROP TRIGGER IF EXISTS commands_fts_insert;
            DROP TRIGGER IF EXISTS commands_fts_delete;
            DROP TRIGGER IF EXISTS commands_fts_update;
            ",
        )?;

        // Drop and recreate the FTS table
        tx.execute("DROP TABLE IF EXISTS commands_fts", [])?;

        tx.execute(
            r"CREATE VIRTUAL TABLE commands_fts USING fts5(
                command,
                content='commands',
                content_rowid='id'
            )",
            [],
        )?;

        // Rebuild the index by inserting all existing commands
        // Using the 'rebuild' command is the most efficient way
        tx.execute(
            "INSERT INTO commands_fts(commands_fts) VALUES('rebuild')",
            [],
        )?;

        // Get the count of re-indexed entries
        let fts_count: i64 =
            tx.query_row("SELECT COUNT(*) FROM commands_fts", [], |row| row.get(0))?;

        // Recreate the triggers
        tx.execute_batch(
            r"
            CREATE TRIGGER commands_fts_insert AFTER INSERT ON commands BEGIN
                INSERT INTO commands_fts(rowid, command) VALUES (new.id, new.command);
            END;

            CREATE TRIGGER commands_fts_delete AFTER DELETE ON commands BEGIN
                INSERT INTO commands_fts(commands_fts, rowid, command)
                VALUES ('delete', old.id, old.command);
            END;

            CREATE TRIGGER commands_fts_update AFTER UPDATE ON commands BEGIN
                INSERT INTO commands_fts(commands_fts, rowid, command)
                VALUES ('delete', old.id, old.command);
                INSERT INTO commands_fts(rowid, command) VALUES (new.id, new.command);
            END;
            ",
        )?;

        // Commit the transaction - only now are all changes visible
        tx.commit()?;

        Ok(u64::try_from(fts_count).unwrap_or(0))
    }

    /// Check and optionally repair database health issues.
    ///
    /// Performs `check_health` and attempts to fix recoverable issues:
    /// - FTS out of sync: rebuilds the FTS index
    ///
    /// # Returns
    ///
    /// Returns a tuple of (original health check, repairs made).
    ///
    /// # Errors
    ///
    /// Returns an error if health check or repairs fail.
    pub fn repair(&self) -> Result<(CheckResult, Vec<String>), HistoryError> {
        let health = self.check_health()?;
        let mut repairs = Vec::new();

        // Repair FTS if out of sync
        if !health.fts_in_sync {
            let reindexed = self.rebuild_fts()?;
            repairs.push(format!(
                "Rebuilt FTS index ({reindexed} commands re-indexed)"
            ));
        }

        Ok((health, repairs))
    }

    // ========================================================================
    // Backup
    // ========================================================================

    /// Create a backup of the database to the specified path.
    ///
    /// Uses `VACUUM INTO` for a consistent backup. Optionally compresses
    /// the output with gzip.
    ///
    /// # Errors
    ///
    /// Returns an error if the backup fails.
    pub fn backup(&self, output_path: &Path, compress: bool) -> Result<BackupResult, HistoryError> {
        use std::time::Instant;

        let start = Instant::now();

        // Checkpoint first to minimize WAL size
        self.checkpoint()?;

        if compress {
            // For compression, we need to vacuum to a temp file first
            let temp_path = output_path.with_extension("db.tmp");

            // VACUUM INTO creates a clean copy
            self.conn
                .execute("VACUUM INTO ?1", [temp_path.to_string_lossy().as_ref()])?;

            // Compress the temp file to the final path
            let temp_file = std::fs::File::open(&temp_path)?;
            let final_file = std::fs::File::create(output_path)?;
            let mut encoder =
                flate2::write::GzEncoder::new(final_file, flate2::Compression::default());
            std::io::copy(&mut std::io::BufReader::new(temp_file), &mut encoder)?;
            encoder.finish()?;

            // Clean up temp file
            let _ = std::fs::remove_file(&temp_path);
        } else {
            // Direct VACUUM INTO
            self.conn
                .execute("VACUUM INTO ?1", [output_path.to_string_lossy().as_ref()])?;
        }

        let backup_size_bytes = std::fs::metadata(output_path)?.len();
        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = start.elapsed().as_millis() as u64;

        // Verify backup integrity (quick check)
        let verified = if compress {
            // Skip verification for compressed backups (would need to decompress)
            false
        } else {
            // Verify uncompressed backups
            Connection::open(output_path)
                .and_then(|conn| {
                    conn.query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
                })
                .map(|result| result == "ok")
                .unwrap_or(false)
        };

        Ok(BackupResult {
            backup_path: output_path.to_string_lossy().to_string(),
            backup_size_bytes,
            compressed: compress,
            duration_ms,
            verified,
        })
    }

    /// Access the underlying connection for advanced queries.
    ///
    /// This is primarily for testing and advanced use cases.
    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Query commands for export with optional filtering.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    #[allow(clippy::redundant_closure_for_method_calls)]
    pub fn query_commands_for_export(
        &self,
        options: &ExportOptions,
    ) -> Result<Vec<CommandEntry>, HistoryError> {
        let mut sql = String::from(
            "SELECT timestamp, agent_type, working_dir, command, outcome,
                    pack_id, pattern_name, rule_id, eval_duration_us, session_id,
                    exit_code, parent_command_id, hostname, allowlist_layer, bypass_code
             FROM commands WHERE 1=1",
        );
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(outcome) = &options.outcome_filter {
            sql.push_str(" AND outcome = ?");
            params.push(Box::new(outcome.as_str().to_string()));
        }

        if let Some(since) = &options.since {
            sql.push_str(" AND timestamp >= ?");
            params.push(Box::new(format_timestamp(*since)));
        }

        if let Some(until) = &options.until {
            sql.push_str(" AND timestamp < ?");
            params.push(Box::new(format_timestamp(*until)));
        }

        sql.push_str(" ORDER BY timestamp DESC");

        if let Some(limit) = options.limit {
            sql.push_str(" LIMIT ?");
            params.push(Box::new(i64::try_from(limit).unwrap_or(i64::MAX)));
        }

        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(param_refs.as_slice(), |row| {
            let timestamp_str: String = row.get(0)?;
            let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
                .map_or_else(|_| Utc::now(), |dt| dt.with_timezone(&Utc));

            let outcome_str: String = row.get(4)?;
            let outcome = Outcome::parse(&outcome_str).unwrap_or(Outcome::Allow);

            let eval_duration_us: i64 = row.get(8)?;

            Ok(CommandEntry {
                timestamp,
                agent_type: row.get(1)?,
                working_dir: row.get(2)?,
                command: row.get(3)?,
                outcome,
                pack_id: row.get(5)?,
                pattern_name: row.get(6)?,
                rule_id: row.get(7)?,
                eval_duration_us: u64::try_from(eval_duration_us).unwrap_or(0),
                session_id: row.get(9)?,
                exit_code: row.get(10)?,
                parent_command_id: row.get(11)?,
                hostname: row.get(12)?,
                allowlist_layer: row.get(13)?,
                bypass_code: row.get(14)?,
            })
        })?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    /// Export commands to JSON format.
    ///
    /// Returns a JSON object with metadata and commands array.
    ///
    /// # Errors
    ///
    /// Returns an error if the query or serialization fails.
    pub fn export_json<W: std::io::Write>(
        &self,
        writer: &mut W,
        options: &ExportOptions,
    ) -> Result<usize, HistoryError> {
        let entries = self.query_commands_for_export(options)?;
        let count = entries.len();

        let export = ExportedData {
            exported_at: Utc::now(),
            total_records: count,
            filters: ExportFilters {
                outcome: options.outcome_filter.map(|o| o.as_str().to_string()),
                since: options.since,
                until: options.until,
            },
            commands: entries,
        };

        serde_json::to_writer_pretty(writer, &export)
            .map_err(|e| HistoryError::Io(std::io::Error::other(e)))?;

        Ok(count)
    }

    /// Export commands to JSONL (JSON Lines) format for streaming.
    ///
    /// Each line is a valid JSON object representing one command.
    ///
    /// # Errors
    ///
    /// Returns an error if the query or serialization fails.
    pub fn export_jsonl<W: std::io::Write>(
        &self,
        writer: &mut W,
        options: &ExportOptions,
    ) -> Result<usize, HistoryError> {
        let entries = self.query_commands_for_export(options)?;
        let count = entries.len();

        for entry in &entries {
            serde_json::to_writer(&mut *writer, entry)
                .map_err(|e| HistoryError::Io(std::io::Error::other(e)))?;
            writeln!(writer)?;
        }

        Ok(count)
    }

    /// Export commands to CSV format.
    ///
    /// Includes a header row followed by data rows.
    ///
    /// # Errors
    ///
    /// Returns an error if the query or write fails.
    pub fn export_csv<W: std::io::Write>(
        &self,
        writer: &mut W,
        options: &ExportOptions,
    ) -> Result<usize, HistoryError> {
        let entries = self.query_commands_for_export(options)?;
        let count = entries.len();

        // Write header
        writeln!(
            writer,
            "timestamp,agent_type,working_dir,command,outcome,pack_id,pattern_name,eval_duration_us"
        )?;

        // Write data rows
        for entry in &entries {
            writeln!(
                writer,
                "{},{},{},{},{},{},{},{}",
                csv_escape(&format_timestamp(entry.timestamp)),
                csv_escape(&entry.agent_type),
                csv_escape(&entry.working_dir),
                csv_escape(&entry.command),
                entry.outcome.as_str(),
                entry.pack_id.as_deref().unwrap_or(""),
                entry.pattern_name.as_deref().unwrap_or(""),
                entry.eval_duration_us,
            )?;
        }

        Ok(count)
    }

    // ========================================================================
    // Pack Effectiveness Analysis Methods
    // ========================================================================

    /// Analyze pack effectiveness for the specified period.
    ///
    /// This analyzes patterns to identify:
    /// - High-value patterns (high volume, low bypass rate)
    /// - Potentially overly aggressive patterns (high bypass rate)
    /// - Inactive packs that never triggered
    /// - Potential coverage gaps
    ///
    /// # Arguments
    ///
    /// * `period_days` - Number of days to analyze
    /// * `enabled_packs` - List of currently enabled pack IDs
    ///
    /// # Errors
    ///
    /// Returns an error if any database query fails.
    pub fn analyze_pack_effectiveness(
        &self,
        period_days: u64,
        enabled_packs: &[&str],
    ) -> Result<PackEffectivenessAnalysis, HistoryError> {
        let now = Utc::now();
        let period_days_i64 = i64::try_from(period_days).unwrap_or(i64::MAX);
        let since = now - Duration::days(period_days_i64);
        let since_ts = format_timestamp(since);
        let end_ts = format_timestamp(now);

        // Get total commands for context
        let total_commands: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM commands WHERE timestamp >= ?1 AND timestamp < ?2",
            params![&since_ts, &end_ts],
            |row| row.get(0),
        )?;
        let total_commands = u64::try_from(total_commands).unwrap_or(0);

        // Query pattern effectiveness (denied + bypassed counts)
        let pattern_stats = self.query_pattern_effectiveness(&since_ts, &end_ts)?;

        // Categorize patterns by bypass rate
        let (high_value, aggressive) = Self::categorize_patterns(&pattern_stats);

        // Find inactive packs
        let active_packs = self.query_active_packs(&since_ts, &end_ts)?;
        let inactive_packs: Vec<String> = enabled_packs
            .iter()
            .filter(|pack| !active_packs.contains(&pack.to_string()))
            .map(std::string::ToString::to_string)
            .collect();

        // Find potential coverage gaps
        let potential_gaps = self.find_coverage_gaps(&since_ts, &end_ts)?;

        // Generate recommendations
        let recommendations = Self::generate_recommendations(
            &high_value,
            &aggressive,
            &inactive_packs,
            &potential_gaps,
        );

        Ok(PackEffectivenessAnalysis {
            period_days,
            analyzed_at: now,
            total_commands,
            high_value_patterns: high_value,
            potentially_aggressive: aggressive,
            inactive_packs,
            potential_gaps,
            recommendations,
        })
    }

    /// Query pattern effectiveness statistics.
    fn query_pattern_effectiveness(
        &self,
        since_ts: &str,
        end_ts: &str,
    ) -> Result<Vec<PatternEffectiveness>, HistoryError> {
        let mut patterns = Vec::new();

        // Get deny counts per pattern
        let mut deny_counts: HashMap<(String, Option<String>), u64> = HashMap::new();
        let mut stmt = self.conn.prepare(
            "SELECT pattern_name, pack_id, COUNT(*) FROM commands
             WHERE timestamp >= ?1 AND timestamp < ?2
             AND outcome = 'deny' AND pattern_name IS NOT NULL
             GROUP BY pattern_name, pack_id",
        )?;
        let rows = stmt.query_map(params![since_ts, end_ts], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (pattern, pack_id, count) = row?;
            deny_counts.insert((pattern, pack_id), u64::try_from(count).unwrap_or(0));
        }

        // Get bypass counts per pattern
        let mut bypass_counts: HashMap<(String, Option<String>), u64> = HashMap::new();
        let mut stmt = self.conn.prepare(
            "SELECT pattern_name, pack_id, COUNT(*) FROM commands
             WHERE timestamp >= ?1 AND timestamp < ?2
             AND outcome = 'bypass' AND pattern_name IS NOT NULL
             GROUP BY pattern_name, pack_id",
        )?;
        let rows = stmt.query_map(params![since_ts, end_ts], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (pattern, pack_id, count) = row?;
            bypass_counts.insert((pattern, pack_id), u64::try_from(count).unwrap_or(0));
        }

        // Merge into PatternEffectiveness structs
        let mut all_patterns: HashMap<(String, Option<String>), (u64, u64)> = HashMap::new();
        for (key, count) in deny_counts {
            all_patterns.entry(key).or_insert((0, 0)).0 = count;
        }
        for (key, count) in bypass_counts {
            all_patterns.entry(key).or_insert((0, 0)).1 = count;
        }

        for ((pattern, pack_id), (denied, bypassed)) in all_patterns {
            let total = denied + bypassed;
            #[allow(clippy::cast_precision_loss)]
            let bypass_rate = if total > 0 {
                (bypassed as f64 / total as f64) * 100.0
            } else {
                0.0
            };

            patterns.push(PatternEffectiveness {
                pattern,
                pack_id,
                total_triggers: total,
                denied_count: denied,
                bypassed_count: bypassed,
                bypass_rate,
            });
        }

        // Sort by total triggers descending
        patterns.sort_by(|a, b| b.total_triggers.cmp(&a.total_triggers));

        Ok(patterns)
    }

    /// Categorize patterns into high-value and potentially aggressive.
    fn categorize_patterns(
        patterns: &[PatternEffectiveness],
    ) -> (Vec<PatternEffectiveness>, Vec<PatternEffectiveness>) {
        // Thresholds
        const HIGH_BYPASS_THRESHOLD: f64 = 20.0; // 20% bypass rate = potentially aggressive
        const MIN_TRIGGERS_FOR_AGGRESSIVE: u64 = 5; // Need enough data to judge
        const MIN_TRIGGERS_FOR_HIGH_VALUE: u64 = 10; // High volume threshold
        const LOW_BYPASS_THRESHOLD: f64 = 5.0; // Low bypass rate for high-value

        let mut high_value = Vec::new();
        let mut aggressive = Vec::new();

        for p in patterns {
            // High value: high volume + low bypass rate
            if p.total_triggers >= MIN_TRIGGERS_FOR_HIGH_VALUE
                && p.bypass_rate <= LOW_BYPASS_THRESHOLD
            {
                high_value.push(p.clone());
            }

            // Potentially aggressive: high bypass rate
            if p.total_triggers >= MIN_TRIGGERS_FOR_AGGRESSIVE
                && p.bypass_rate >= HIGH_BYPASS_THRESHOLD
            {
                aggressive.push(p.clone());
            }
        }

        // Sort high-value by volume descending
        high_value.sort_by(|a, b| b.total_triggers.cmp(&a.total_triggers));
        // Sort aggressive by bypass rate descending
        aggressive.sort_by(|a, b| {
            b.bypass_rate
                .partial_cmp(&a.bypass_rate)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        (high_value, aggressive)
    }

    /// Query active packs (packs that triggered at least once).
    fn query_active_packs(
        &self,
        since_ts: &str,
        end_ts: &str,
    ) -> Result<Vec<String>, HistoryError> {
        let mut packs = Vec::new();
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT pack_id FROM commands
             WHERE timestamp >= ?1 AND timestamp < ?2
             AND pack_id IS NOT NULL",
        )?;
        let rows = stmt.query_map(params![since_ts, end_ts], |row| row.get::<_, String>(0))?;
        for row in rows {
            packs.push(row?);
        }
        Ok(packs)
    }

    /// Find potential coverage gaps (dangerous commands that were allowed).
    fn find_coverage_gaps(
        &self,
        since_ts: &str,
        end_ts: &str,
    ) -> Result<Vec<PotentialGap>, HistoryError> {
        let mut gaps = Vec::new();

        // Heuristic patterns for potentially dangerous allowed commands
        let dangerous_patterns = [
            ("--force", "Force flag used"),
            ("--hard", "Hard reset/operation"),
            ("-rf", "Recursive force delete"),
            ("prune", "Prune operation"),
            ("DROP", "SQL DROP statement"),
            ("DELETE FROM", "SQL DELETE statement"),
            ("TRUNCATE", "SQL TRUNCATE statement"),
            ("rm -r", "Recursive remove"),
            ("chmod 777", "World-writable permissions"),
        ];

        let mut stmt = self.conn.prepare(
            "SELECT command, timestamp, working_dir FROM commands
             WHERE timestamp >= ?1 AND timestamp < ?2
             AND outcome = 'allow'
             ORDER BY timestamp DESC
             LIMIT 1000",
        )?;
        let rows = stmt.query_map(params![since_ts, end_ts], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?;

        for row in rows {
            let (command, timestamp_str, working_dir) = row?;
            let command_lower = command.to_lowercase();

            for (pattern, reason) in &dangerous_patterns {
                if command_lower.contains(&pattern.to_lowercase()) {
                    // Parse timestamp
                    let timestamp = chrono::DateTime::parse_from_rfc3339(&timestamp_str)
                        .map_or_else(|_| Utc::now(), |dt| dt.with_timezone(&Utc));

                    gaps.push(PotentialGap {
                        command: command.clone(),
                        reason: reason.to_string(),
                        timestamp,
                        working_dir: working_dir.clone(),
                    });
                    break; // Only report each command once
                }
            }
        }

        // Limit to top 20 gaps
        gaps.truncate(20);
        Ok(gaps)
    }

    /// Generate recommendations based on analysis.
    fn generate_recommendations(
        high_value: &[PatternEffectiveness],
        aggressive: &[PatternEffectiveness],
        inactive_packs: &[String],
        gaps: &[PotentialGap],
    ) -> Vec<PackRecommendation> {
        let mut recommendations = Vec::new();

        // Recommend relaxing aggressive patterns
        for p in aggressive.iter().take(3) {
            recommendations.push(PackRecommendation {
                recommendation_type: RecommendationType::RelaxPattern,
                description: format!(
                    "Pattern '{}' has a {:.1}% bypass rate ({} of {} triggers bypassed). \
                     Consider adding an allowlist entry or refining the pattern.",
                    p.pattern, p.bypass_rate, p.bypassed_count, p.total_triggers
                ),
                suggested_action: Some(format!(
                    "dcg allow {}:{} --reason \"High bypass rate\"",
                    p.pack_id.as_deref().unwrap_or("unknown"),
                    p.pattern
                )),
                config_change: None,
                related_pattern: Some(p.pattern.clone()),
                priority: 8,
            });
        }

        // Recommend disabling inactive packs
        for pack in inactive_packs.iter().take(3) {
            recommendations.push(PackRecommendation {
                recommendation_type: RecommendationType::DisablePack,
                description: format!(
                    "Pack '{pack}' is enabled but has not triggered any rules. \
                     Consider disabling it to reduce overhead."
                ),
                suggested_action: None,
                config_change: Some(format!(
                    "[packs.{}]\nenabled = false",
                    pack.replace('.', "_")
                )),
                related_pattern: Some(pack.clone()),
                priority: 3,
            });
        }

        // Recommend adding coverage for gaps
        if !gaps.is_empty() {
            let gap_count = gaps.len();
            let example = &gaps[0];
            recommendations.push(PackRecommendation {
                recommendation_type: RecommendationType::AddPattern,
                description: format!(
                    "Found {} potentially dangerous commands that were allowed. \
                     Example: '{}' ({})",
                    gap_count,
                    truncate_string(&example.command, 50),
                    example.reason
                ),
                suggested_action: Some("Review allowed commands with `dcg history export --outcome allow` and consider adding patterns".to_string()),
                config_change: None,
                related_pattern: None,
                priority: 7,
            });
        }

        // Praise high-value patterns
        if !high_value.is_empty() {
            let total_blocked: u64 = high_value.iter().map(|p| p.denied_count).sum();
            recommendations.push(PackRecommendation {
                recommendation_type: RecommendationType::Tuning,
                description: format!(
                    "{} high-value patterns blocked {} potentially destructive commands with minimal false positives.",
                    high_value.len(),
                    total_blocked
                ),
                suggested_action: None,
                config_change: None,
                related_pattern: None,
                priority: 1,
            });
        }

        // Sort by priority descending
        recommendations.sort_by(|a, b| b.priority.cmp(&a.priority));
        recommendations
    }
}

/// Truncate a string for display.
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Options for export operations.
#[derive(Debug, Clone, Default)]
pub struct ExportOptions {
    /// Filter by outcome (allow, deny, warn, bypass).
    pub outcome_filter: Option<Outcome>,
    /// Include only commands since this timestamp.
    pub since: Option<DateTime<Utc>>,
    /// Include only commands until this timestamp.
    pub until: Option<DateTime<Utc>>,
    /// Maximum number of records to export.
    pub limit: Option<usize>,
}

/// Exported data container with metadata.
#[derive(Debug, Serialize)]
pub struct ExportedData {
    /// When the export was generated.
    pub exported_at: DateTime<Utc>,
    /// Total number of records exported.
    pub total_records: usize,
    /// Filters applied to the export.
    pub filters: ExportFilters,
    /// The exported commands.
    pub commands: Vec<CommandEntry>,
}

/// Filters applied during export.
#[derive(Debug, Serialize)]
pub struct ExportFilters {
    /// Outcome filter if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// Since timestamp if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<DateTime<Utc>>,
    /// Until timestamp if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<DateTime<Utc>>,
}

// ============================================================================
// Pack Effectiveness Analysis Types
// ============================================================================

/// Pattern effectiveness statistics with bypass analysis.
#[derive(Debug, Clone, Serialize)]
pub struct PatternEffectiveness {
    /// Pattern name.
    pub pattern: String,
    /// Pack ID the pattern belongs to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pack_id: Option<String>,
    /// Total times this pattern triggered (deny + bypass).
    pub total_triggers: u64,
    /// Times the pattern blocked a command (deny).
    pub denied_count: u64,
    /// Times the pattern was bypassed (allow-once).
    pub bypassed_count: u64,
    /// Bypass rate as a percentage (0.0-100.0).
    pub bypass_rate: f64,
}

/// A potential coverage gap where dangerous commands were allowed.
#[derive(Debug, Clone, Serialize)]
pub struct PotentialGap {
    /// The command that was allowed but may be dangerous.
    pub command: String,
    /// Why this command may be a gap (heuristic match).
    pub reason: String,
    /// When this command was executed.
    pub timestamp: DateTime<Utc>,
    /// Working directory where command was executed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
}

/// Type of recommendation for pack configuration.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationType {
    /// Consider relaxing an overly aggressive pattern.
    RelaxPattern,
    /// Consider enabling a currently disabled pack.
    EnablePack,
    /// Consider disabling an unused pack.
    DisablePack,
    /// Add a new pattern to cover a gap.
    AddPattern,
    /// General tuning suggestion.
    Tuning,
}

/// An actionable recommendation for improving pack configuration.
#[derive(Debug, Clone, Serialize)]
pub struct PackRecommendation {
    /// Type of recommendation.
    #[serde(rename = "type")]
    pub recommendation_type: RecommendationType,
    /// Human-readable description.
    pub description: String,
    /// Suggested action to take.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_action: Option<String>,
    /// Suggested config change (TOML snippet).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_change: Option<String>,
    /// Pattern or pack this relates to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_pattern: Option<String>,
    /// Priority score (higher = more important).
    pub priority: u8,
}

/// Complete pack effectiveness analysis result.
#[derive(Debug, Clone, Serialize)]
pub struct PackEffectivenessAnalysis {
    /// Analysis period in days.
    pub period_days: u64,
    /// When this analysis was generated.
    pub analyzed_at: DateTime<Utc>,
    /// Total commands analyzed.
    pub total_commands: u64,
    /// High-value patterns (high volume, low bypass rate).
    pub high_value_patterns: Vec<PatternEffectiveness>,
    /// Potentially overly aggressive patterns (high bypass rate).
    pub potentially_aggressive: Vec<PatternEffectiveness>,
    /// Enabled packs that never triggered.
    pub inactive_packs: Vec<String>,
    /// Potential coverage gaps (dangerous commands that were allowed).
    pub potential_gaps: Vec<PotentialGap>,
    /// Generated recommendations.
    pub recommendations: Vec<PackRecommendation>,
}

/// Escape a string for CSV output.
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    type OptionalFields = (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );

    fn reset_schema_version_to_v1(db: &HistoryDb) {
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

    #[allow(clippy::too_many_arguments)]
    fn insert_entry(
        db: &HistoryDb,
        idx: usize,
        timestamp: DateTime<Utc>,
        outcome: Outcome,
        pattern_name: Option<&str>,
        pack_id: Option<&str>,
        agent_type: &str,
        working_dir: &str,
        eval_duration_us: u64,
    ) {
        let entry = CommandEntry {
            timestamp,
            agent_type: agent_type.to_string(),
            working_dir: working_dir.to_string(),
            command: format!("cmd-{idx}"),
            outcome,
            pack_id: pack_id.map(str::to_string),
            pattern_name: pattern_name.map(str::to_string),
            eval_duration_us,
            ..Default::default()
        };
        db.log_command(&entry).unwrap();
    }

    fn create_test_db_with_outcomes(allow: usize, deny: usize, warn: usize) -> HistoryDb {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now() - Duration::days(1);
        let mut idx = 0;
        for _ in 0..allow {
            insert_entry(
                &db,
                idx,
                now,
                Outcome::Allow,
                None,
                None,
                "claude_code",
                "/project/a",
                100,
            );
            idx += 1;
        }
        for _ in 0..deny {
            insert_entry(
                &db,
                idx,
                now,
                Outcome::Deny,
                Some("reset-hard"),
                Some("core.git"),
                "claude_code",
                "/project/a",
                120,
            );
            idx += 1;
        }
        for _ in 0..warn {
            insert_entry(
                &db,
                idx,
                now,
                Outcome::Warn,
                Some("force-push"),
                Some("core.git"),
                "claude_code",
                "/project/a",
                140,
            );
            idx += 1;
        }
        db
    }

    fn create_test_db_with_patterns(patterns: &[(&str, usize)]) -> HistoryDb {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now() - Duration::days(1);
        let mut idx = 0;
        for (name, count) in patterns {
            for _ in 0..*count {
                insert_entry(
                    &db,
                    idx,
                    now,
                    Outcome::Deny,
                    Some(name),
                    Some("core.git"),
                    "claude_code",
                    "/project/a",
                    100,
                );
                idx += 1;
            }
        }
        db
    }

    fn create_test_db_with_durations(durations: &[u64]) -> HistoryDb {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now() - Duration::days(1);
        for (idx, duration) in durations.iter().enumerate() {
            insert_entry(
                &db,
                idx,
                now,
                Outcome::Allow,
                None,
                None,
                "claude_code",
                "/project/a",
                *duration,
            );
        }
        db
    }

    fn create_test_db_with_projects(projects: &[(&str, usize)]) -> HistoryDb {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now() - Duration::days(1);
        let mut idx = 0;
        for (path, count) in projects {
            for _ in 0..*count {
                insert_entry(
                    &db,
                    idx,
                    now,
                    Outcome::Allow,
                    None,
                    None,
                    "claude_code",
                    path,
                    100,
                );
                idx += 1;
            }
        }
        db
    }

    fn create_test_db_with_agents(agents: &[(&str, usize)]) -> HistoryDb {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now() - Duration::days(1);
        let mut idx = 0;
        for (agent, count) in agents {
            for _ in 0..*count {
                insert_entry(
                    &db,
                    idx,
                    now,
                    Outcome::Allow,
                    None,
                    None,
                    agent,
                    "/project/a",
                    100,
                );
                idx += 1;
            }
        }
        db
    }

    fn create_test_db_with_trend_data() -> HistoryDb {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();
        let mut idx = 0;
        // Current period (last 30 days)
        for _ in 0..50 {
            insert_entry(
                &db,
                idx,
                now - Duration::days(5),
                Outcome::Allow,
                None,
                None,
                "claude_code",
                "/project/a",
                100,
            );
            idx += 1;
        }
        // Previous period (30-60 days ago)
        for _ in 0..25 {
            insert_entry(
                &db,
                idx,
                now - Duration::days(40),
                Outcome::Allow,
                None,
                None,
                "claude_code",
                "/project/a",
                100,
            );
            idx += 1;
        }
        db
    }

    #[test]
    fn test_schema_creation() {
        let db = HistoryDb::open_in_memory().unwrap();

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
        let db = HistoryDb::open_in_memory().unwrap();

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
        let db = HistoryDb::open_in_memory().unwrap();

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
        let db = HistoryDb::open_in_memory().unwrap();

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
        let db = HistoryDb::open_in_memory().unwrap();

        let entry = test_entry();
        db.log_command(&entry).unwrap();

        let count: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))
            .unwrap();

        assert_eq!(count, 1);
    }

    #[test]
    fn test_stats_outcome_distribution() {
        let db = create_test_db_with_outcomes(70, 20, 10);

        let stats = db.compute_stats(30).unwrap();

        assert_eq!(stats.total_commands, 100);
        assert_eq!(stats.outcomes.allowed, 70);
        assert_eq!(stats.outcomes.denied, 20);
        assert_eq!(stats.outcomes.warned, 10);
    }

    #[test]
    fn test_stats_top_patterns() {
        let db =
            create_test_db_with_patterns(&[("reset-hard", 50), ("force-push", 30), ("rm-rf", 20)]);

        let stats = db.compute_stats(30).unwrap();

        assert_eq!(stats.top_patterns[0].name, "reset-hard");
        assert_eq!(stats.top_patterns[0].count, 50);
    }

    #[test]
    fn test_stats_performance_percentiles() {
        let db = create_test_db_with_durations(&[100, 200, 300, 400, 500, 1000, 2000, 5000, 10000]);

        let stats = db.compute_stats(30).unwrap();

        assert!(stats.performance.p50_us <= stats.performance.p95_us);
        assert!(stats.performance.p95_us <= stats.performance.p99_us);
    }

    #[test]
    fn test_stats_project_breakdown() {
        let db = create_test_db_with_projects(&[
            ("/project/a", 50),
            ("/project/b", 30),
            ("/project/c", 20),
        ]);

        let stats = db.compute_stats(30).unwrap();

        assert_eq!(stats.top_projects[0].path, "/project/a");
        assert_eq!(stats.top_projects[0].command_count, 50);
    }

    #[test]
    fn test_stats_agent_distribution() {
        let db = create_test_db_with_agents(&[("claude_code", 60), ("codex", 30), ("gemini", 10)]);

        let stats = db.compute_stats(30).unwrap();

        assert_eq!(stats.agents[0].name, "claude_code");
        assert_eq!(stats.agents[0].count, 60);
    }

    #[test]
    fn test_stats_with_trends() {
        let db = create_test_db_with_trend_data();

        let stats = db.compute_stats_with_trends(30).unwrap();

        assert!(stats.trends.is_some());
        let trends = stats.trends.unwrap();
        assert!(!trends.commands_change.is_nan());
    }

    #[test]
    fn test_stats_empty_db() {
        let db = HistoryDb::open_in_memory().unwrap();

        let stats = db.compute_stats(30).unwrap();

        assert_eq!(stats.total_commands, 0);
        assert_eq!(stats.outcomes.allowed, 0);
    }

    #[test]
    fn test_stats_json_output() {
        let db = create_test_db_with_outcomes(50, 30, 20);

        let stats = db.compute_stats(30).unwrap();
        let json = serde_json::to_string(&stats).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["total_commands"].is_number());
    }

    #[test]
    fn test_timestamp_format() {
        let db = HistoryDb::open_in_memory().unwrap();

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
        let db = HistoryDb::open_in_memory().unwrap();
        let version = db.get_schema_version().unwrap();
        assert_eq!(version, CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn test_database_creation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");

        assert!(!db_path.exists());
        let _db = HistoryDb::open(Some(db_path.clone())).unwrap();
        assert!(db_path.exists());
    }

    #[test]
    fn test_parent_directory_created() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("nested/deep/test.db");

        let _db = HistoryDb::open(Some(db_path.clone())).unwrap();
        assert!(db_path.exists());
    }

    #[test]
    fn test_wal_mode_enabled() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("wal.db");
        let db = HistoryDb::open(Some(db_path)).unwrap();

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
        let result = HistoryDb::try_open(Some(db_path));
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
        let result = HistoryDb::try_open(Some(db_path));
        assert!(result.is_none());

        // Restore permissions so temp_dir cleanup can succeed
        std::fs::set_permissions(&dir_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn test_migration_adds_schema_version_description() {
        let db = HistoryDb::open_in_memory().unwrap();
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
        let db = HistoryDb::open_in_memory().unwrap();

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
        let db = HistoryDb::open_in_memory().unwrap();
        assert_eq!(db.count_commands().unwrap(), 0);
    }

    #[test]
    fn test_count_commands_with_data() {
        let db = HistoryDb::open_in_memory().unwrap();

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
    fn test_prune_older_than_days() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        let mut old_entry = test_entry();
        old_entry.timestamp = now - Duration::days(30);
        db.log_command(&old_entry).unwrap();

        let mut recent_entry = test_entry();
        recent_entry.timestamp = now - Duration::days(1);
        db.log_command(&recent_entry).unwrap();

        let pruned = db.prune_older_than_days(7, false).unwrap();
        assert_eq!(pruned, 1);
        assert_eq!(db.count_commands().unwrap(), 1);
    }

    #[test]
    fn test_prune_older_than_days_dry_run() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        let mut old_entry = test_entry();
        old_entry.timestamp = now - Duration::days(30);
        db.log_command(&old_entry).unwrap();

        let pruned = db.prune_older_than_days(7, true).unwrap();
        assert_eq!(pruned, 1);
        assert_eq!(db.count_commands().unwrap(), 1);
    }

    #[test]
    fn test_file_size_in_memory() {
        let db = HistoryDb::open_in_memory().unwrap();
        assert_eq!(db.file_size().unwrap(), 0);
    }

    #[test]
    fn test_all_optional_fields() {
        let db = HistoryDb::open_in_memory().unwrap();

        let entry = CommandEntry {
            timestamp: Utc::now(),
            agent_type: "claude_code".to_string(),
            working_dir: "/project".to_string(),
            command: "test command".to_string(),
            outcome: Outcome::Deny,
            pack_id: Some("core.git".to_string()),
            pattern_name: Some("force-push".to_string()),
            rule_id: None,
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
        let db = HistoryDb::open_in_memory().unwrap();

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
            let db = HistoryDb::open(Some(db_path.clone())).unwrap();
            db.log_command(&test_entry()).unwrap();
            assert_eq!(db.count_commands().unwrap(), 1);
        }

        // Reopen and verify
        {
            let db = HistoryDb::open(Some(db_path)).unwrap();
            assert_eq!(db.count_commands().unwrap(), 1);
            assert_eq!(db.get_schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
        }
    }

    // Export tests

    fn create_test_db_with_data(count: usize) -> HistoryDb {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now() - Duration::days(1);
        for idx in 0..count {
            insert_entry(
                &db,
                idx,
                now,
                Outcome::Allow,
                None,
                None,
                "claude_code",
                "/project/a",
                100,
            );
        }
        db
    }

    fn create_test_db_with_mixed_outcomes(count: usize) -> HistoryDb {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now() - Duration::days(1);
        for idx in 0..count {
            let outcome = if idx % 2 == 0 {
                Outcome::Allow
            } else {
                Outcome::Deny
            };
            insert_entry(
                &db,
                idx,
                now,
                outcome,
                if outcome == Outcome::Deny {
                    Some("reset-hard")
                } else {
                    None
                },
                if outcome == Outcome::Deny {
                    Some("core.git")
                } else {
                    None
                },
                "claude_code",
                "/project/a",
                100,
            );
        }
        db
    }

    #[test]
    fn test_json_export_format() {
        let db = create_test_db_with_data(10);
        let mut buf = Vec::new();

        db.export_json(&mut buf, &ExportOptions::default()).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert!(json["exported_at"].is_string());
        assert!(json["total_records"].as_i64().unwrap() >= 10);
        assert!(json["commands"].is_array());
    }

    #[test]
    fn test_csv_export_format() {
        let db = create_test_db_with_data(10);
        let mut buf = Vec::new();

        db.export_csv(&mut buf, &ExportOptions::default()).unwrap();

        let content = String::from_utf8(buf).unwrap();
        // Should have header row
        assert!(content.starts_with("timestamp,agent_type,"));
        // Should have data rows (header + 10 data = at least 11 lines)
        assert!(content.lines().count() >= 11);
    }

    #[test]
    fn test_jsonl_export_streaming() {
        let db = create_test_db_with_data(50);
        let mut buf = Vec::new();

        db.export_jsonl(&mut buf, &ExportOptions::default())
            .unwrap();

        let content = String::from_utf8(buf).unwrap();
        // Each line should be valid JSON
        for line in content.lines() {
            serde_json::from_str::<serde_json::Value>(line).unwrap();
        }
        assert_eq!(content.lines().count(), 50);
    }

    #[test]
    fn test_export_with_outcome_filter() {
        let db = create_test_db_with_mixed_outcomes(100);
        let mut buf = Vec::new();

        db.export_json(
            &mut buf,
            &ExportOptions {
                outcome_filter: Some(Outcome::Deny),
                ..Default::default()
            },
        )
        .unwrap();

        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        for cmd in json["commands"].as_array().unwrap() {
            assert_eq!(cmd["outcome"], "deny");
        }
    }

    #[test]
    fn test_export_with_limit() {
        let db = create_test_db_with_data(100);
        let mut buf = Vec::new();

        db.export_json(
            &mut buf,
            &ExportOptions {
                limit: Some(10),
                ..Default::default()
            },
        )
        .unwrap();

        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(json["commands"].as_array().unwrap().len(), 10);
    }

    #[test]
    fn test_export_with_date_range() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Insert commands at different times
        let mut old_entry = test_entry();
        old_entry.timestamp = now - Duration::days(30);
        db.log_command(&old_entry).unwrap();

        let mut recent_entry = test_entry();
        recent_entry.timestamp = now - Duration::days(1);
        db.log_command(&recent_entry).unwrap();

        let mut buf = Vec::new();
        db.export_json(
            &mut buf,
            &ExportOptions {
                since: Some(now - Duration::days(7)),
                ..Default::default()
            },
        )
        .unwrap();

        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        // Should only include the recent entry
        assert_eq!(json["commands"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_empty_export() {
        let db = HistoryDb::open_in_memory().unwrap();
        let mut buf = Vec::new();

        let count = db.export_json(&mut buf, &ExportOptions::default()).unwrap();

        assert_eq!(count, 0);
        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(json["total_records"].as_i64().unwrap(), 0);
        assert!(json["commands"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_csv_escape_special_chars() {
        let db = HistoryDb::open_in_memory().unwrap();

        // Insert a command with special characters
        let entry = CommandEntry {
            command: "echo \"hello, world\"\ntest".to_string(),
            ..Default::default()
        };
        db.log_command(&entry).unwrap();

        let mut buf = Vec::new();
        db.export_csv(&mut buf, &ExportOptions::default()).unwrap();

        let content = String::from_utf8(buf).unwrap();
        // The command with special chars should be quoted
        assert!(content.contains("\"echo \"\"hello, world\"\""));
    }

    #[test]
    fn test_query_commands_for_export() {
        let db = create_test_db_with_data(25);
        let entries = db
            .query_commands_for_export(&ExportOptions::default())
            .unwrap();
        assert_eq!(entries.len(), 25);

        // Test with limit
        let entries = db
            .query_commands_for_export(&ExportOptions {
                limit: Some(5),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(entries.len(), 5);
    }

    // ========================================================================
    // Pack Effectiveness Analysis Tests
    // ========================================================================

    /// Helper to insert entries with specific outcomes and patterns.
    fn insert_analysis_entry(
        db: &HistoryDb,
        pattern: &str,
        pack_id: &str,
        outcome: Outcome,
        timestamp: DateTime<Utc>,
    ) {
        let entry = CommandEntry {
            timestamp,
            agent_type: "claude_code".to_string(),
            working_dir: "/test/project".to_string(),
            command: format!("test command for {pattern}"),
            outcome,
            pack_id: Some(pack_id.to_string()),
            pattern_name: Some(pattern.to_string()),
            eval_duration_us: 100,
            ..Default::default()
        };
        db.log_command(&entry).unwrap();
    }

    #[test]
    fn test_identifies_high_bypass_rate() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Pattern A: 95 denies, 5 bypasses = 5% bypass rate (OK)
        for _ in 0..95 {
            insert_analysis_entry(&db, "pattern-a", "core.git", Outcome::Deny, now);
        }
        for _ in 0..5 {
            insert_analysis_entry(&db, "pattern-a", "core.git", Outcome::Bypass, now);
        }

        // Pattern B: 70 denies, 30 bypasses = 30% bypass rate (FLAGGED)
        for _ in 0..70 {
            insert_analysis_entry(&db, "pattern-b", "core.git", Outcome::Deny, now);
        }
        for _ in 0..30 {
            insert_analysis_entry(&db, "pattern-b", "core.git", Outcome::Bypass, now);
        }

        let analysis = db
            .analyze_pack_effectiveness(30, &["core.git", "core.filesystem"])
            .unwrap();

        // Pattern B should be flagged as aggressive (30% bypass)
        assert!(
            analysis
                .potentially_aggressive
                .iter()
                .any(|p| p.pattern == "pattern-b"),
            "Pattern B should be flagged as aggressive"
        );

        // Pattern A should NOT be flagged (5% bypass)
        assert!(
            !analysis
                .potentially_aggressive
                .iter()
                .any(|p| p.pattern == "pattern-a"),
            "Pattern A should not be flagged"
        );
    }

    #[test]
    fn test_identifies_inactive_packs() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Only core.git triggers
        for _ in 0..50 {
            insert_analysis_entry(&db, "pattern-a", "core.git", Outcome::Deny, now);
        }

        // core.filesystem and cloud.azure never trigger
        let enabled_packs = ["core.git", "core.filesystem", "cloud.azure"];
        let analysis = db.analyze_pack_effectiveness(30, &enabled_packs).unwrap();

        // cloud.azure and core.filesystem should be inactive
        assert!(
            analysis.inactive_packs.contains(&"cloud.azure".to_string()),
            "cloud.azure should be inactive"
        );
        assert!(
            analysis
                .inactive_packs
                .contains(&"core.filesystem".to_string()),
            "core.filesystem should be inactive"
        );
        // core.git should NOT be inactive
        assert!(
            !analysis.inactive_packs.contains(&"core.git".to_string()),
            "core.git should be active"
        );
    }

    #[test]
    fn test_identifies_high_value_patterns() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Pattern A: 500 denies, 10 bypasses = 2% bypass rate (high value)
        for _ in 0..500 {
            insert_analysis_entry(&db, "pattern-a", "core.git", Outcome::Deny, now);
        }
        for _ in 0..10 {
            insert_analysis_entry(&db, "pattern-a", "core.git", Outcome::Bypass, now);
        }

        // Pattern B: 9 denies, 1 bypass = 10% bypass rate (low volume)
        for _ in 0..9 {
            insert_analysis_entry(&db, "pattern-b", "core.git", Outcome::Deny, now);
        }
        insert_analysis_entry(&db, "pattern-b", "core.git", Outcome::Bypass, now);

        let analysis = db.analyze_pack_effectiveness(30, &["core.git"]).unwrap();

        // Pattern A should be high value (high volume, low bypass)
        assert!(
            analysis
                .high_value_patterns
                .iter()
                .any(|p| p.pattern == "pattern-a"),
            "Pattern A should be high value"
        );

        // Pattern B should NOT be high value (too few triggers)
        assert!(
            !analysis
                .high_value_patterns
                .iter()
                .any(|p| p.pattern == "pattern-b"),
            "Pattern B should not be high value (low volume)"
        );
    }

    #[test]
    fn test_generates_actionable_recommendations() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Create an aggressive pattern to trigger recommendation
        for _ in 0..60 {
            insert_analysis_entry(&db, "aggressive-pattern", "core.git", Outcome::Deny, now);
        }
        for _ in 0..40 {
            insert_analysis_entry(&db, "aggressive-pattern", "core.git", Outcome::Bypass, now);
        }

        let analysis = db
            .analyze_pack_effectiveness(30, &["core.git", "unused.pack"])
            .unwrap();

        // Should have recommendations
        assert!(
            !analysis.recommendations.is_empty(),
            "Should have recommendations"
        );

        // Each recommendation should have an action or config suggestion
        for rec in &analysis.recommendations {
            assert!(
                rec.suggested_action.is_some() || rec.config_change.is_some() || rec.priority <= 2,
                "Recommendation should be actionable: {rec:?}"
            );
        }
    }

    #[test]
    fn test_coverage_gap_detection() {
        let db = HistoryDb::open_in_memory().unwrap();
        // Use a timestamp slightly in the past to avoid race condition with
        // analyze_pack_effectiveness which uses Utc::now() as the end bound
        let entry_time = Utc::now() - Duration::seconds(1);

        // Insert allowed commands that look dangerous
        let dangerous_commands = [
            "git push --force origin feature",
            "docker system prune --all",
            "rm -rf /tmp/test",
        ];

        for cmd in &dangerous_commands {
            let entry = CommandEntry {
                timestamp: entry_time,
                agent_type: "claude_code".to_string(),
                working_dir: "/test/project".to_string(),
                command: cmd.to_string(),
                outcome: Outcome::Allow,
                pack_id: None,
                pattern_name: None,
                eval_duration_us: 100,
                ..Default::default()
            };
            db.log_command(&entry).unwrap();
        }

        let analysis = db.analyze_pack_effectiveness(30, &["core.git"]).unwrap();

        // Should detect potential gaps
        assert!(
            !analysis.potential_gaps.is_empty(),
            "Should detect coverage gaps"
        );
        assert!(
            analysis
                .potential_gaps
                .iter()
                .any(|g| g.command.contains("--force") || g.command.contains("prune")),
            "Should flag dangerous commands"
        );
    }

    #[test]
    fn test_analysis_with_no_data() {
        let db = HistoryDb::open_in_memory().unwrap();

        let analysis = db
            .analyze_pack_effectiveness(30, &["core.git", "core.filesystem"])
            .unwrap();

        // Should return empty but not error
        assert!(analysis.high_value_patterns.is_empty());
        assert!(analysis.potentially_aggressive.is_empty());
        assert_eq!(analysis.total_commands, 0);
    }

    #[test]
    fn test_machine_readable_recommendations() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Create some data to generate recommendations
        for _ in 0..50 {
            insert_analysis_entry(&db, "test-pattern", "core.git", Outcome::Deny, now);
        }
        for _ in 0..50 {
            insert_analysis_entry(&db, "test-pattern", "core.git", Outcome::Bypass, now);
        }

        let analysis = db
            .analyze_pack_effectiveness(30, &["core.git", "unused.pack"])
            .unwrap();

        // Should be valid JSON for automation
        let json = serde_json::to_string(&analysis.recommendations).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();

        for rec in &parsed {
            assert!(rec["type"].is_string());
            assert!(rec["description"].is_string());
        }
    }

    #[test]
    fn test_rebuild_fts() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Insert some commands
        let commands = ["git status", "docker ps", "npm install", "cargo build"];
        for cmd in &commands {
            let entry = CommandEntry {
                timestamp: now,
                agent_type: "test".to_string(),
                working_dir: "/test".to_string(),
                command: cmd.to_string(),
                outcome: Outcome::Allow,
                ..Default::default()
            };
            db.log_command(&entry).unwrap();
        }

        // Verify initial FTS state
        let health1 = db.check_health().unwrap();
        assert_eq!(health1.commands_count, 4);
        assert_eq!(health1.fts_count, 4);
        assert!(health1.fts_in_sync);

        // Rebuild FTS
        let reindexed = db.rebuild_fts().unwrap();
        assert_eq!(reindexed, 4);

        // Verify FTS still works after rebuild
        let health2 = db.check_health().unwrap();
        assert_eq!(health2.commands_count, 4);
        assert_eq!(health2.fts_count, 4);
        assert!(health2.fts_in_sync);
    }

    #[test]
    fn test_repair_healthy_db() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Insert some commands
        for i in 0..3 {
            let entry = CommandEntry {
                timestamp: now,
                agent_type: "test".to_string(),
                working_dir: "/test".to_string(),
                command: format!("test command {i}"),
                outcome: Outcome::Allow,
                ..Default::default()
            };
            db.log_command(&entry).unwrap();
        }

        // Repair a healthy database
        let (health, repairs) = db.repair().unwrap();

        // Should be healthy
        assert!(health.fts_in_sync);
        assert_eq!(health.commands_count, 3);

        // No repairs should have been made
        assert!(
            repairs.is_empty(),
            "No repairs should be needed for healthy DB"
        );
    }

    #[test]
    fn test_fts_triggers_work_after_rebuild() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Insert initial command
        let entry1 = CommandEntry {
            timestamp: now,
            agent_type: "test".to_string(),
            working_dir: "/test".to_string(),
            command: "initial command".to_string(),
            outcome: Outcome::Allow,
            ..Default::default()
        };
        db.log_command(&entry1).unwrap();

        // Rebuild FTS
        db.rebuild_fts().unwrap();

        // Insert new command after rebuild
        let entry2 = CommandEntry {
            timestamp: now,
            agent_type: "test".to_string(),
            working_dir: "/test".to_string(),
            command: "new command after rebuild".to_string(),
            outcome: Outcome::Allow,
            ..Default::default()
        };
        db.log_command(&entry2).unwrap();

        // Verify triggers work - FTS should have both commands
        let health = db.check_health().unwrap();
        assert_eq!(health.commands_count, 2);
        assert_eq!(health.fts_count, 2);
        assert!(health.fts_in_sync);
    }
}
