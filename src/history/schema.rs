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
use fsqlite::Connection;
use fsqlite_error::FrankenError;
use fsqlite_types::value::SqliteValue;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fmt::Write as FmtWrite;
use std::path::{Path, PathBuf};

// ============================================================================
// SqliteValue Conversion Helpers
// ============================================================================

/// Extract a `String` from a `SqliteValue`.
fn sv_to_string(v: &SqliteValue) -> String {
    match v {
        SqliteValue::Text(s) => s.clone(),
        SqliteValue::Integer(i) => i.to_string(),
        SqliteValue::Float(f) => f.to_string(),
        SqliteValue::Null => String::new(),
        SqliteValue::Blob(_) => String::new(),
    }
}

/// Extract an `i64` from a `SqliteValue`.
fn sv_to_i64(v: &SqliteValue) -> i64 {
    match v {
        SqliteValue::Integer(i) => *i,
        SqliteValue::Float(f) => *f as i64,
        SqliteValue::Text(s) => s.parse().unwrap_or(0),
        _ => 0,
    }
}

/// Extract an `f64` from a `SqliteValue`.
#[allow(dead_code)]
fn sv_to_f64(v: &SqliteValue) -> f64 {
    match v {
        SqliteValue::Float(f) => *f,
        SqliteValue::Integer(i) => *i as f64,
        SqliteValue::Text(s) => s.parse().unwrap_or(0.0),
        _ => 0.0,
    }
}

/// Extract an `f32` from a `SqliteValue`.
fn sv_to_f32(v: &SqliteValue) -> f32 {
    match v {
        SqliteValue::Float(f) => *f as f32,
        SqliteValue::Integer(i) => *i as f32,
        SqliteValue::Text(s) => s.parse().unwrap_or(0.0),
        _ => 0.0,
    }
}

/// Extract an `i32` from a `SqliteValue`.
fn sv_to_i32(v: &SqliteValue) -> i32 {
    match v {
        SqliteValue::Integer(i) => i32::try_from(*i).unwrap_or(0),
        SqliteValue::Float(f) => *f as i32,
        SqliteValue::Text(s) => s.parse().unwrap_or(0),
        _ => 0,
    }
}

/// Extract an `Option<String>` from a `SqliteValue`.
fn sv_to_opt_string(v: &SqliteValue) -> Option<String> {
    match v {
        SqliteValue::Text(s) => Some(s.clone()),
        SqliteValue::Null => None,
        SqliteValue::Integer(i) => Some(i.to_string()),
        _ => None,
    }
}

/// Convert an `Option<String>` to a `SqliteValue`.
fn opt_string_to_sv(v: Option<&String>) -> SqliteValue {
    match v {
        Some(s) => SqliteValue::Text(s.clone()),
        None => SqliteValue::Null,
    }
}

/// Convert an `Option<i32>` to a `SqliteValue`.
fn opt_i32_to_sv(v: Option<&i32>) -> SqliteValue {
    match v {
        Some(i) => SqliteValue::Integer(i64::from(*i)),
        None => SqliteValue::Null,
    }
}

/// Convert an `Option<i64>` to a `SqliteValue`.
fn opt_i64_to_sv(v: Option<&i64>) -> SqliteValue {
    match v {
        Some(i) => SqliteValue::Integer(*i),
        None => SqliteValue::Null,
    }
}

/// Inline bind parameters into SQL for use with `conn.query()`.
///
/// Workaround: fsqlite's `query_with_params()` only returns the first matching
/// row instead of all rows. This helper substitutes `?1`, `?2`, ... placeholders
/// with the actual values so we can use the non-parameterized `query()` method.
fn inline_params(sql: &str, params: &[SqliteValue]) -> String {
    let mut result = sql.to_string();
    // Replace in reverse order so ?10 is replaced before ?1
    for (i, param) in params.iter().enumerate().rev() {
        let placeholder = format!("?{}", i + 1);
        let value = match param {
            SqliteValue::Text(s) => format!("'{}'", s.replace('\'', "''")),
            SqliteValue::Integer(i) => i.to_string(),
            SqliteValue::Float(f) => f.to_string(),
            SqliteValue::Null => "NULL".to_string(),
            SqliteValue::Blob(_) => "X''".to_string(),
        };
        result = result.replace(&placeholder, &value);
    }
    result
}

/// Current schema version for migrations.
pub const CURRENT_SCHEMA_VERSION: u32 = 5;

/// Default database filename.
pub const DEFAULT_DB_FILENAME: &str = "history.db";

/// History-specific error type.
#[derive(Debug)]
pub enum HistoryError {
    /// FrankenSQLite error.
    Sqlite(FrankenError),
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

impl From<FrankenError> for HistoryError {
    fn from(e: FrankenError) -> Self {
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

// ============================================================================
// Suggestion Analysis Types
// ============================================================================

/// Command that was blocked frequently in a time window.
#[derive(Debug, Clone, Serialize)]
pub struct FrequentBlock {
    /// The blocked command.
    pub command: String,
    /// Number of times the command was blocked.
    pub block_count: u64,
    /// Most recent timestamp when the command was blocked.
    pub last_seen: DateTime<Utc>,
}

/// Command blocks clustered by working directory.
#[derive(Debug, Clone, Serialize)]
pub struct PathCluster {
    /// The blocked command.
    pub command: String,
    /// Working directory where the command was blocked.
    pub working_dir: String,
    /// Number of times the command was blocked in this directory.
    pub block_count: u64,
}

/// Command that was manually bypassed (allow-once) and may be a suggestion candidate.
#[derive(Debug, Clone, Serialize)]
pub struct SuggestionCandidate {
    /// The command that was bypassed.
    pub command: String,
    /// Number of times the command was bypassed.
    pub bypass_count: u64,
    /// Most recent timestamp when the command was bypassed.
    pub last_seen: DateTime<Utc>,
}

/// Helper for history analysis queries used by suggestion heuristics.
pub struct HistoryAnalyzer<'a> {
    conn: &'a Connection,
}

impl<'a> HistoryAnalyzer<'a> {
    /// Create a new analyzer for the provided history database.
    #[must_use]
    pub fn new(db: &'a HistoryDb) -> Self {
        Self { conn: &db.conn }
    }

    /// Return commands blocked at least `min_count` times in the last `days` days.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn get_frequent_blocks(
        &self,
        days: u32,
        min_count: u32,
    ) -> Result<Vec<FrequentBlock>, HistoryError> {
        let days_i64 = i64::from(days);
        let since = Utc::now() - Duration::days(days_i64);
        let since_ts = format_timestamp(since);
        let min_count_i64 = i64::from(min_count);

        let rows = self.conn.query(&inline_params(
            "SELECT command, COUNT(*) as block_count, MAX(timestamp) as last_seen
             FROM commands
             WHERE outcome = 'deny' AND timestamp >= ?1
             GROUP BY command
             HAVING COUNT(*) >= ?2
             ORDER BY block_count DESC, command ASC",
            &[
                SqliteValue::Text(since_ts),
                SqliteValue::Integer(min_count_i64),
            ],
        ))?;

        let mut blocks = Vec::new();
        for row in &rows {
            let vals = row.values();
            let command = sv_to_string(&vals[0]);
            let block_count = sv_to_i64(&vals[1]);
            let last_seen_str = sv_to_string(&vals[2]);
            let last_seen = DateTime::parse_from_rfc3339(&last_seen_str)
                .map_or_else(|_| Utc::now(), |dt| dt.with_timezone(&Utc));
            blocks.push(FrequentBlock {
                command,
                block_count: u64::try_from(block_count).unwrap_or(0),
                last_seen,
            });
        }

        Ok(blocks)
    }

    /// Return command + working directory clusters blocked at least `min_count` times.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn get_path_clusters(&self, min_count: u32) -> Result<Vec<PathCluster>, HistoryError> {
        let min_count_i64 = i64::from(min_count);

        let rows = self.conn.query(&inline_params(
            "SELECT command, working_dir, COUNT(*) as block_count
             FROM commands
             WHERE outcome = 'deny'
             GROUP BY command, working_dir
             HAVING COUNT(*) >= ?1
             ORDER BY block_count DESC, command ASC, working_dir ASC",
            &[SqliteValue::Integer(min_count_i64)],
        ))?;

        let mut clusters = Vec::new();
        for row in &rows {
            let vals = row.values();
            let command = sv_to_string(&vals[0]);
            let working_dir = sv_to_string(&vals[1]);
            let block_count = sv_to_i64(&vals[2]);
            clusters.push(PathCluster {
                command,
                working_dir,
                block_count: u64::try_from(block_count).unwrap_or(0),
            });
        }

        Ok(clusters)
    }

    /// Return commands that were manually bypassed (allow-once).
    ///
    /// This approximates "manual allows" using the `bypass` outcome.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn get_suggestion_candidates(&self) -> Result<Vec<SuggestionCandidate>, HistoryError> {
        let rows = self.conn.query(
            "SELECT command, COUNT(*) as bypass_count, MAX(timestamp) as last_seen
             FROM commands
             WHERE outcome = 'bypass'
             GROUP BY command
             ORDER BY bypass_count DESC, command ASC",
        )?;

        let mut candidates = Vec::new();
        for row in &rows {
            let vals = row.values();
            let command = sv_to_string(&vals[0]);
            let bypass_count = sv_to_i64(&vals[1]);
            let last_seen_str = sv_to_string(&vals[2]);
            let last_seen = DateTime::parse_from_rfc3339(&last_seen_str)
                .map_or_else(|_| Utc::now(), |dt| dt.with_timezone(&Utc));
            candidates.push(SuggestionCandidate {
                command,
                bypass_count: u64::try_from(bypass_count).unwrap_or(0),
                last_seen,
            });
        }

        Ok(candidates)
    }
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

        let path_str = db_path.to_string_lossy().to_string();
        let conn = Connection::open(&path_str)?;
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
        let conn = Connection::open(":memory:")?;
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

        // Check XDG-style path first (~/.config/dcg/), then platform-native
        let xdg_base = dirs::home_dir().map(|h| h.join(".config"));
        let xdg_path = xdg_base
            .as_ref()
            .map(|b| b.join("dcg").join(DEFAULT_DB_FILENAME));
        if let Some(ref path) = xdg_path {
            if path.exists()
                || xdg_base
                    .as_ref()
                    .map(|b| b.join("dcg").exists())
                    .unwrap_or(false)
            {
                return path.clone();
            }
        }

        // Fall back to platform-native
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
        let row = self
            .conn
            .query_row("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1")?;
        let version = sv_to_i64(&row.values()[0]);
        Ok(u32::try_from(version).unwrap_or(0))
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
        let row = self.conn.query_row("SELECT COUNT(*) FROM commands")?;
        let count = sv_to_i64(&row.values()[0]);
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

        let row = self.conn.query_row_with_params(
            "SELECT COUNT(*) FROM commands WHERE timestamp < ?1",
            &[SqliteValue::Text(cutoff_ts.clone())],
        )?;
        let count = sv_to_i64(&row.values()[0]);

        if !dry_run {
            self.conn.execute_with_params(
                "DELETE FROM commands WHERE timestamp < ?1",
                &[SqliteValue::Text(cutoff_ts)],
            )?;
            // Rebuild FTS index after deletion since fsqlite FTS5 doesn't support
            // individual row deletion via 'delete' control command triggers
            self.rebuild_fts()?;
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
        let ts_params = &[
            SqliteValue::Text(start_ts.clone()),
            SqliteValue::Text(end_ts.clone()),
        ];

        let total_row = self.conn.query_row_with_params(
            "SELECT COUNT(*) FROM commands WHERE timestamp >= ?1 AND timestamp < ?2",
            ts_params,
        )?;
        let total_commands = u64::try_from(sv_to_i64(&total_row.values()[0])).unwrap_or(0);

        let mut outcomes = OutcomeStats::default();
        let outcome_rows = self.conn.query(&inline_params(
            "SELECT outcome, COUNT(*) FROM commands
             WHERE timestamp >= ?1 AND timestamp < ?2
             GROUP BY outcome",
            ts_params,
        ))?;
        for row in &outcome_rows {
            let vals = row.values();
            let outcome = sv_to_string(&vals[0]);
            let count = u64::try_from(sv_to_i64(&vals[1])).unwrap_or(0);
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
        let pattern_rows = self.conn.query(&inline_params(
            "SELECT pattern_name, pack_id, COUNT(*) FROM commands
             WHERE timestamp >= ?1 AND timestamp < ?2 AND pattern_name IS NOT NULL
             GROUP BY pattern_name, pack_id
             ORDER BY COUNT(*) DESC, pattern_name ASC
             LIMIT 10",
            ts_params,
        ))?;
        for row in &pattern_rows {
            let vals = row.values();
            let name = sv_to_string(&vals[0]);
            let pack_id = sv_to_opt_string(&vals[1]);
            let count = sv_to_i64(&vals[2]);
            top_patterns.push(PatternStat {
                name,
                count: u64::try_from(count).unwrap_or(0),
                pack_id,
            });
        }

        let mut top_projects = Vec::new();
        let project_rows = self.conn.query(&inline_params(
            "SELECT working_dir, COUNT(*) FROM commands
             WHERE timestamp >= ?1 AND timestamp < ?2
             GROUP BY working_dir
             ORDER BY COUNT(*) DESC, working_dir ASC
             LIMIT 10",
            ts_params,
        ))?;
        for row in &project_rows {
            let vals = row.values();
            let path = sv_to_string(&vals[0]);
            let count = sv_to_i64(&vals[1]);
            top_projects.push(ProjectStat {
                path,
                command_count: u64::try_from(count).unwrap_or(0),
            });
        }

        let mut agents = Vec::new();
        let agent_rows = self.conn.query(&inline_params(
            "SELECT agent_type, COUNT(*) FROM commands
             WHERE timestamp >= ?1 AND timestamp < ?2
             GROUP BY agent_type
             ORDER BY COUNT(*) DESC, agent_type ASC",
            ts_params,
        ))?;
        for row in &agent_rows {
            let vals = row.values();
            let name = sv_to_string(&vals[0]);
            let count = sv_to_i64(&vals[1]);
            agents.push(AgentStat {
                name,
                count: u64::try_from(count).unwrap_or(0),
            });
        }

        let mut durations = Vec::new();
        let dur_rows = self.conn.query(&inline_params(
            "SELECT eval_duration_us FROM commands
             WHERE timestamp >= ?1 AND timestamp < ?2 AND eval_duration_us > 0
             ORDER BY eval_duration_us ASC",
            ts_params,
        ))?;
        for row in &dur_rows {
            let value = sv_to_i64(&row.values()[0]);
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

        self.conn.execute_with_params(
            r"INSERT INTO commands (
                timestamp, agent_type, working_dir, command, command_hash,
                outcome, pack_id, pattern_name, rule_id, eval_duration_us,
                session_id, exit_code, parent_command_id, hostname,
                allowlist_layer, bypass_code
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16
            )",
            &[
                SqliteValue::Text(timestamp),
                SqliteValue::Text(entry.agent_type.clone()),
                SqliteValue::Text(entry.working_dir.clone()),
                SqliteValue::Text(entry.command.clone()),
                SqliteValue::Text(command_hash),
                SqliteValue::Text(entry.outcome.as_str().to_string()),
                opt_string_to_sv(entry.pack_id.as_ref()),
                opt_string_to_sv(entry.pattern_name.as_ref()),
                opt_string_to_sv(rule_id.as_ref()),
                SqliteValue::Integer(eval_duration_us),
                opt_string_to_sv(entry.session_id.as_ref()),
                opt_i32_to_sv(entry.exit_code.as_ref()),
                opt_i64_to_sv(entry.parent_command_id.as_ref()),
                opt_string_to_sv(entry.hostname.as_ref()),
                opt_string_to_sv(entry.allowlist_layer.as_ref()),
                opt_string_to_sv(entry.bypass_code.as_ref()),
            ],
        )?;

        // FrankenSQLite: last_insert_rowid() is a stub, use max(id) instead
        let row = self.conn.query_row("SELECT max(id) FROM commands")?;
        Ok(sv_to_i64(&row.values()[0]))
    }

    /// Run VACUUM to reclaim space after deletions.
    ///
    /// # Errors
    ///
    /// Returns an error if the VACUUM fails.
    pub fn vacuum(&self) -> Result<(), HistoryError> {
        self.conn.execute("VACUUM")?;
        Ok(())
    }

    /// Initialize the database schema.
    fn initialize_schema(&self) -> Result<(), HistoryError> {
        // Enable WAL mode for better concurrent performance
        self.conn.execute("PRAGMA journal_mode=WAL;")?;

        // Set busy timeout for better concurrent access (5 seconds default)
        self.conn.execute("PRAGMA busy_timeout=5000;")?;

        // Configure WAL checkpoint behavior
        self.conn.execute("PRAGMA wal_autocheckpoint=1000;")?;

        // Create schema version table (includes all columns up to v3)
        self.conn.execute(
            r"CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now')),
                description TEXT NOT NULL DEFAULT 'Initial schema',
                last_prune_at TEXT
            )",
        )?;

        // Check if we need to initialize
        let needs_init = self
            .conn
            .query_row("SELECT COUNT(*) = 0 FROM schema_version")
            .map(|row| sv_to_i64(&row.values()[0]) != 0)
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
    #[allow(clippy::too_many_lines)]
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
        )?;

        // Create indexes for common query patterns (split from execute_batch)
        self.conn
            .execute("CREATE INDEX IF NOT EXISTS idx_commands_timestamp ON commands(timestamp)")?;
        self.conn
            .execute("CREATE INDEX IF NOT EXISTS idx_commands_outcome ON commands(outcome)")?;
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_commands_working_dir ON commands(working_dir)",
        )?;
        self.conn
            .execute("CREATE INDEX IF NOT EXISTS idx_commands_pack_id ON commands(pack_id)")?;
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_commands_rule_id ON commands(rule_id) WHERE rule_id IS NOT NULL")?;
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_commands_agent_type ON commands(agent_type)",
        )?;
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_commands_session_id ON commands(session_id)",
        )?;
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_commands_command_hash ON commands(command_hash)",
        )?;
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_commands_outcome_timestamp ON commands(outcome, timestamp)")?;
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_commands_pack_outcome ON commands(pack_id, outcome)",
        )?;

        // Create FTS5 virtual table for full-text search
        self.conn.execute(
            r"CREATE VIRTUAL TABLE IF NOT EXISTS commands_fts USING fts5(
                command,
                content='commands',
                content_rowid='id'
            )",
        )?;

        // Create trigger to keep FTS in sync on INSERT.
        // Note: fsqlite's FTS5 does not support the 'delete' control command via
        // INSERT INTO fts(fts, rowid, col) VALUES('delete', ...), so we omit
        // DELETE/UPDATE triggers. Instead, prune_older_than_days rebuilds FTS after deletion.
        self.conn.execute(
            r"CREATE TRIGGER IF NOT EXISTS commands_fts_insert AFTER INSERT ON commands BEGIN
                INSERT INTO commands_fts(command) VALUES (new.command);
            END",
        )?;

        // Create stats_cache table for real-time statistics (v3 feature)
        self.conn.execute(
            r"CREATE TABLE IF NOT EXISTS stats_cache (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )",
        )?;

        // Create suggestion_audit table for tracking accepted/modified/rejected suggestions (v5 feature)
        self.conn.execute(
            r"CREATE TABLE IF NOT EXISTS suggestion_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL CHECK (action IN ('accepted', 'modified', 'rejected')),
                pattern TEXT NOT NULL,
                final_pattern TEXT,
                risk_level TEXT NOT NULL,
                risk_score REAL NOT NULL,
                confidence_tier TEXT NOT NULL,
                confidence_points INTEGER NOT NULL,
                cluster_frequency INTEGER NOT NULL,
                unique_variants INTEGER NOT NULL,
                sample_commands TEXT NOT NULL,
                rule_id TEXT,
                session_id TEXT,
                working_dir TEXT
            )",
        )?;

        // Create indexes for suggestion_audit
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_suggestion_audit_timestamp ON suggestion_audit(timestamp)")?;
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_suggestion_audit_action ON suggestion_audit(action)",
        )?;
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_suggestion_audit_session_id ON suggestion_audit(session_id)")?;

        // Record schema version
        self.conn.execute_with_params(
            "INSERT INTO schema_version (version, description, last_prune_at) VALUES (?1, ?2, NULL)",
            &[
                SqliteValue::Integer(i64::from(CURRENT_SCHEMA_VERSION)),
                SqliteValue::Text("Initial schema".to_string()),
            ],
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
        if from_version < 5 {
            self.migrate_v4_to_v5()?;
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
        let rows = self.conn.query("PRAGMA table_info(schema_version)")?;
        Ok(rows
            .iter()
            .any(|row| sv_to_string(&row.values()[1]) == "description"))
    }

    fn migrate_v1_to_v2(&self) -> Result<(), HistoryError> {
        if !self.schema_version_has_description()? {
            self.conn.execute(
                "ALTER TABLE schema_version ADD COLUMN description TEXT NOT NULL DEFAULT 'Initial schema'",
            )?;
        }

        self.conn.execute_with_params(
            "INSERT INTO schema_version (version, description) VALUES (?1, ?2)",
            &[
                SqliteValue::Integer(2),
                SqliteValue::Text("Add schema version descriptions".to_string()),
            ],
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
        )?;

        // Add last_prune_at column to schema_version for auto-prune tracking
        // Check if column exists first
        let rows = self.conn.query("PRAGMA table_info(schema_version)")?;
        let has_last_prune = rows
            .iter()
            .any(|row| sv_to_string(&row.values()[1]) == "last_prune_at");

        if !has_last_prune {
            self.conn
                .execute("ALTER TABLE schema_version ADD COLUMN last_prune_at TEXT")?;
        }

        // Record migration
        self.conn.execute_with_params(
            "INSERT INTO schema_version (version, description) VALUES (?1, ?2)",
            &[
                SqliteValue::Integer(3),
                SqliteValue::Text("Add stats cache and auto-prune tracking".to_string()),
            ],
        )?;

        Ok(())
    }

    fn migrate_v3_to_v4(&self) -> Result<(), HistoryError> {
        // Add rule_id column for stable pattern identification
        // Check if column exists first
        let rows = self.conn.query("PRAGMA table_info(commands)")?;
        let has_rule_id = rows
            .iter()
            .any(|row| sv_to_string(&row.values()[1]) == "rule_id");

        if !has_rule_id {
            self.conn
                .execute("ALTER TABLE commands ADD COLUMN rule_id TEXT")?;
        }

        // Backfill rule_id from existing pack_id and pattern_name
        self.conn.execute(
            r"UPDATE commands
              SET rule_id = pack_id || ':' || pattern_name
              WHERE rule_id IS NULL
                AND pack_id IS NOT NULL
                AND pattern_name IS NOT NULL",
        )?;

        // Create index for rule_id queries (partial index for non-NULL values)
        self.conn.execute(
            r"CREATE INDEX IF NOT EXISTS idx_commands_rule_id
              ON commands(rule_id) WHERE rule_id IS NOT NULL",
        )?;

        // Record migration
        self.conn.execute_with_params(
            "INSERT INTO schema_version (version, description) VALUES (?1, ?2)",
            &[
                SqliteValue::Integer(4),
                SqliteValue::Text("Add rule_id column and index".to_string()),
            ],
        )?;

        Ok(())
    }

    fn migrate_v4_to_v5(&self) -> Result<(), HistoryError> {
        // Add suggestion_audit table for tracking accepted/modified/rejected suggestions
        self.conn.execute(
            r"CREATE TABLE IF NOT EXISTS suggestion_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL CHECK (action IN ('accepted', 'modified', 'rejected')),
                pattern TEXT NOT NULL,
                final_pattern TEXT,
                risk_level TEXT NOT NULL,
                risk_score REAL NOT NULL,
                confidence_tier TEXT NOT NULL,
                confidence_points INTEGER NOT NULL,
                cluster_frequency INTEGER NOT NULL,
                unique_variants INTEGER NOT NULL,
                sample_commands TEXT NOT NULL,
                rule_id TEXT,
                session_id TEXT,
                working_dir TEXT
            )",
        )?;

        // Create indexes for common query patterns
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_suggestion_audit_timestamp ON suggestion_audit(timestamp)")?;
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_suggestion_audit_action ON suggestion_audit(action)",
        )?;
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_suggestion_audit_session_id ON suggestion_audit(session_id)")?;

        // Record migration
        self.conn.execute_with_params(
            "INSERT INTO schema_version (version, description) VALUES (?1, ?2)",
            &[
                SqliteValue::Integer(5),
                SqliteValue::Text(
                    "Add suggestion_audit table for tracking suggestion actions".to_string(),
                ),
            ],
        )?;

        Ok(())
    }

    // ========================================================================
    // Batch Operations
    // ========================================================================

    /// Log multiple command entries in a single transaction (batched insert).
    ///
    /// Uses `BEGIN IMMEDIATE` for reliable single-writer batching.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction fails.
    pub fn log_commands_batch(&self, entries: &[CommandEntry]) -> Result<(), HistoryError> {
        if entries.is_empty() {
            return Ok(());
        }

        // Use BEGIN IMMEDIATE for reliable single-writer batching.
        // BEGIN CONCURRENT is available in fsqlite for multi-writer MVCC scenarios,
        // but the HistoryWriter uses a single connection so IMMEDIATE is sufficient.
        self.conn.execute("BEGIN IMMEDIATE;")?;

        let result = (|| -> Result<(), HistoryError> {
            for entry in entries {
                let command_hash = entry.command_hash();
                let timestamp = entry.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
                let eval_duration_us = i64::try_from(entry.eval_duration_us).unwrap_or(i64::MAX);

                // Use inline_params + execute to avoid execute_with_params
                // nesting auto-transaction inside our explicit BEGIN IMMEDIATE.
                let sql = inline_params(
                    r"INSERT INTO commands (
                        timestamp, agent_type, working_dir, command, command_hash,
                        outcome, pack_id, pattern_name, eval_duration_us,
                        session_id, exit_code, parent_command_id, hostname,
                        allowlist_layer, bypass_code, rule_id
                    ) VALUES (
                        ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16
                    )",
                    &[
                        SqliteValue::Text(timestamp),
                        SqliteValue::Text(entry.agent_type.clone()),
                        SqliteValue::Text(entry.working_dir.clone()),
                        SqliteValue::Text(entry.command.clone()),
                        SqliteValue::Text(command_hash),
                        SqliteValue::Text(entry.outcome.as_str().to_string()),
                        opt_string_to_sv(entry.pack_id.as_ref()),
                        opt_string_to_sv(entry.pattern_name.as_ref()),
                        SqliteValue::Integer(eval_duration_us),
                        opt_string_to_sv(entry.session_id.as_ref()),
                        opt_i32_to_sv(entry.exit_code.as_ref()),
                        opt_i64_to_sv(entry.parent_command_id.as_ref()),
                        opt_string_to_sv(entry.hostname.as_ref()),
                        opt_string_to_sv(entry.allowlist_layer.as_ref()),
                        opt_string_to_sv(entry.bypass_code.as_ref()),
                        opt_string_to_sv(entry.get_rule_id().as_ref()),
                    ],
                );
                self.conn.execute(&sql)?;
            }
            Ok(())
        })();

        match result {
            Ok(()) => {
                self.conn.execute("COMMIT;")?;
                Ok(())
            }
            Err(e) => {
                let _ = self.conn.execute("ROLLBACK;");
                Err(e)
            }
        }
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
        self.conn.execute("PRAGMA wal_checkpoint(PASSIVE);")?;
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
        self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")?;
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
        let result = self.conn.query_row(
            "SELECT last_prune_at FROM schema_version WHERE last_prune_at IS NOT NULL ORDER BY version DESC LIMIT 1",
        );

        match result {
            Ok(row) => {
                let timestamp_str = sv_to_string(&row.values()[0]);
                if timestamp_str.is_empty() {
                    return Ok(true);
                }
                chrono::DateTime::parse_from_rfc3339(&timestamp_str).map_or(
                    Ok(true), // Invalid timestamp, assume prune needed
                    |last_prune| {
                        let hours_since_prune =
                            (Utc::now() - last_prune.with_timezone(&Utc)).num_hours();
                        Ok(hours_since_prune >= 24)
                    },
                )
            }
            Err(_) => Ok(true), // No rows found, prune needed
        }
    }

    /// Record the current timestamp as the last prune time.
    ///
    /// # Errors
    ///
    /// Returns an error if the update fails.
    pub fn record_prune_timestamp(&self) -> Result<(), HistoryError> {
        let now = format_timestamp(Utc::now());
        self.conn.execute_with_params(
            "UPDATE schema_version SET last_prune_at = ?1 WHERE version = (SELECT MAX(version) FROM schema_version)",
            &[SqliteValue::Text(now)],
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
        let result = self.conn.query_row_with_params(
            "SELECT value, updated_at FROM stats_cache WHERE key = ?1",
            &[SqliteValue::Text(key.to_string())],
        );

        match result {
            Ok(row) => {
                let vals = row.values();
                let value = sv_to_i64(&vals[0]);
                let updated_at = sv_to_string(&vals[1]);
                if let Ok(updated) = chrono::DateTime::parse_from_rfc3339(&updated_at) {
                    let age_secs = (Utc::now() - updated.with_timezone(&Utc)).num_seconds();
                    if age_secs <= max_age_secs {
                        return Ok(Some(value));
                    }
                }
                Ok(None) // Stale or invalid timestamp
            }
            Err(_) => Ok(None),
        }
    }

    /// Update a cached statistic value.
    ///
    /// # Errors
    ///
    /// Returns an error if the upsert fails.
    pub fn update_cached_stat(&self, key: &str, value: i64) -> Result<(), HistoryError> {
        let now = format_timestamp(Utc::now());
        self.conn.execute_with_params(
            "INSERT INTO stats_cache (key, value, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = ?3",
            &[
                SqliteValue::Text(key.to_string()),
                SqliteValue::Integer(value),
                SqliteValue::Text(now),
            ],
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
        self.conn.execute_with_params(
            "INSERT INTO stats_cache (key, value, updated_at) VALUES (?1, 1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = value + 1, updated_at = ?2",
            &[SqliteValue::Text(key.to_string()), SqliteValue::Text(now)],
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
        let integrity_row = self.conn.query_row("PRAGMA integrity_check")?;
        let integrity_check = sv_to_string(&integrity_row.values()[0]);
        let integrity_ok = integrity_check == "ok";

        // Foreign key check
        let fk_rows = self.conn.query("PRAGMA foreign_key_check")?;
        let foreign_key_violations = fk_rows.len();

        // Commands count
        let cmd_row = self.conn.query_row("SELECT COUNT(*) FROM commands")?;
        let commands_count = u64::try_from(sv_to_i64(&cmd_row.values()[0])).unwrap_or(0);

        // FTS count
        let fts_row = self.conn.query_row("SELECT COUNT(*) FROM commands_fts")?;
        let fts_count = u64::try_from(sv_to_i64(&fts_row.values()[0])).unwrap_or(0);

        // Journal mode
        let jm_row = self.conn.query_row("PRAGMA journal_mode")?;
        let journal_mode = sv_to_string(&jm_row.values()[0]);

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
        let ps_row = self.conn.query_row("PRAGMA page_size")?;
        let page_size = sv_to_i64(&ps_row.values()[0]);
        let pc_row = self.conn.query_row("PRAGMA page_count")?;
        let page_count = sv_to_i64(&pc_row.values()[0]);
        let fl_row = self.conn.query_row("PRAGMA freelist_count")?;
        let freelist_count = sv_to_i64(&fl_row.values()[0]);

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
        self.conn.execute("BEGIN IMMEDIATE;")?;

        let result = (|| -> Result<u64, HistoryError> {
            // First, drop triggers to prevent interference during rebuild
            self.conn
                .execute("DROP TRIGGER IF EXISTS commands_fts_insert")?;
            self.conn
                .execute("DROP TRIGGER IF EXISTS commands_fts_delete")?;
            self.conn
                .execute("DROP TRIGGER IF EXISTS commands_fts_update")?;

            // Drop and recreate the FTS table
            self.conn.execute("DROP TABLE IF EXISTS commands_fts")?;

            self.conn.execute(
                r"CREATE VIRTUAL TABLE commands_fts USING fts5(
                    command,
                    content='commands',
                    content_rowid='id'
                )",
            )?;

            // Manually rebuild FTS by inserting all existing commands.
            // fsqlite FTS5 does not support the control column syntax
            // INSERT INTO fts(fts) VALUES('rebuild'), so we do it explicitly.
            self.conn
                .execute("INSERT INTO commands_fts(command) SELECT command FROM commands")?;

            // Get the count of re-indexed entries
            let fts_row = self.conn.query_row("SELECT COUNT(*) FROM commands_fts")?;
            let fts_count = sv_to_i64(&fts_row.values()[0]);

            // Recreate INSERT trigger only (fsqlite FTS5 does not support 'delete' control command)
            self.conn.execute(
                r"CREATE TRIGGER commands_fts_insert AFTER INSERT ON commands BEGIN
                    INSERT INTO commands_fts(command) VALUES (new.command);
                END",
            )?;

            Ok(u64::try_from(fts_count).unwrap_or(0))
        })();

        match result {
            Ok(count) => {
                self.conn.execute("COMMIT;")?;
                Ok(count)
            }
            Err(e) => {
                let _ = self.conn.execute("ROLLBACK;");
                Err(e)
            }
        }
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
            self.conn.execute_with_params(
                "VACUUM INTO ?1",
                &[SqliteValue::Text(temp_path.to_string_lossy().to_string())],
            )?;

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
            self.conn.execute_with_params(
                "VACUUM INTO ?1",
                &[SqliteValue::Text(output_path.to_string_lossy().to_string())],
            )?;
        }

        let backup_size_bytes = std::fs::metadata(output_path)?.len();
        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = start.elapsed().as_millis() as u64;

        // Verify backup integrity (quick check)
        let verified = if compress {
            // Skip verification for compressed backups (would need to decompress)
            false
        } else {
            // Verify uncompressed backups via FrankenSQLite
            let path_str = output_path.to_string_lossy().to_string();
            Connection::open(&path_str)
                .and_then(|conn| conn.query_row("PRAGMA integrity_check"))
                .map(|row| sv_to_string(&row.values()[0]) == "ok")
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
        let mut params: Vec<SqliteValue> = Vec::new();
        let mut param_idx = 1;

        if let Some(outcome) = &options.outcome_filter {
            write!(sql, " AND outcome = ?{param_idx}").unwrap();
            params.push(SqliteValue::Text(outcome.as_str().to_string()));
            param_idx += 1;
        }

        if let Some(since) = &options.since {
            write!(sql, " AND timestamp >= ?{param_idx}").unwrap();
            params.push(SqliteValue::Text(format_timestamp(*since)));
            param_idx += 1;
        }

        if let Some(until) = &options.until {
            write!(sql, " AND timestamp < ?{param_idx}").unwrap();
            params.push(SqliteValue::Text(format_timestamp(*until)));
            param_idx += 1;
        }

        sql.push_str(" ORDER BY timestamp DESC");

        if let Some(limit) = options.limit {
            write!(sql, " LIMIT ?{param_idx}").unwrap();
            params.push(SqliteValue::Integer(
                i64::try_from(limit).unwrap_or(i64::MAX),
            ));
        }

        let rows = self.conn.query(&inline_params(&sql, &params))?;

        let mut entries = Vec::new();
        for row in &rows {
            let vals = row.values();
            let timestamp_str = sv_to_string(&vals[0]);
            let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
                .map_or_else(|_| Utc::now(), |dt| dt.with_timezone(&Utc));

            let outcome_str = sv_to_string(&vals[4]);
            let outcome = Outcome::parse(&outcome_str).unwrap_or(Outcome::Allow);

            let eval_duration_us = sv_to_i64(&vals[8]);

            entries.push(CommandEntry {
                timestamp,
                agent_type: sv_to_string(&vals[1]),
                working_dir: sv_to_string(&vals[2]),
                command: sv_to_string(&vals[3]),
                outcome,
                pack_id: sv_to_opt_string(&vals[5]),
                pattern_name: sv_to_opt_string(&vals[6]),
                rule_id: sv_to_opt_string(&vals[7]),
                eval_duration_us: u64::try_from(eval_duration_us).unwrap_or(0),
                session_id: sv_to_opt_string(&vals[9]),
                exit_code: match &vals[10] {
                    SqliteValue::Integer(i) => Some(i32::try_from(*i).unwrap_or(0)),
                    SqliteValue::Null => None,
                    _ => None,
                },
                parent_command_id: match &vals[11] {
                    SqliteValue::Integer(i) => Some(*i),
                    SqliteValue::Null => None,
                    _ => None,
                },
                hostname: sv_to_opt_string(&vals[12]),
                allowlist_layer: sv_to_opt_string(&vals[13]),
                bypass_code: sv_to_opt_string(&vals[14]),
            });
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
        let total_row = self.conn.query_row_with_params(
            "SELECT COUNT(*) FROM commands WHERE timestamp >= ?1 AND timestamp < ?2",
            &[
                SqliteValue::Text(since_ts.clone()),
                SqliteValue::Text(end_ts.clone()),
            ],
        )?;
        let total_commands = u64::try_from(sv_to_i64(&total_row.values()[0])).unwrap_or(0);

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
        let ts_params = &[
            SqliteValue::Text(since_ts.to_string()),
            SqliteValue::Text(end_ts.to_string()),
        ];

        // Get deny counts per pattern
        let mut deny_counts: HashMap<(String, Option<String>), u64> = HashMap::new();
        let deny_rows = self.conn.query(&inline_params(
            "SELECT pattern_name, pack_id, COUNT(*) FROM commands
             WHERE timestamp >= ?1 AND timestamp < ?2
             AND outcome = 'deny' AND pattern_name IS NOT NULL
             GROUP BY pattern_name, pack_id",
            ts_params,
        ))?;
        for row in &deny_rows {
            let vals = row.values();
            let pattern = sv_to_string(&vals[0]);
            let pack_id = sv_to_opt_string(&vals[1]);
            let count = sv_to_i64(&vals[2]);
            deny_counts.insert((pattern, pack_id), u64::try_from(count).unwrap_or(0));
        }

        // Get bypass counts per pattern
        let mut bypass_counts: HashMap<(String, Option<String>), u64> = HashMap::new();
        let bypass_rows = self.conn.query(&inline_params(
            "SELECT pattern_name, pack_id, COUNT(*) FROM commands
             WHERE timestamp >= ?1 AND timestamp < ?2
             AND outcome = 'bypass' AND pattern_name IS NOT NULL
             GROUP BY pattern_name, pack_id",
            ts_params,
        ))?;
        for row in &bypass_rows {
            let vals = row.values();
            let pattern = sv_to_string(&vals[0]);
            let pack_id = sv_to_opt_string(&vals[1]);
            let count = sv_to_i64(&vals[2]);
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
        patterns.sort_by_key(|p| std::cmp::Reverse(p.total_triggers));

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
        high_value.sort_by_key(|p| std::cmp::Reverse(p.total_triggers));
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
        let rows = self.conn.query(&inline_params(
            "SELECT DISTINCT pack_id FROM commands
             WHERE timestamp >= ?1 AND timestamp < ?2
             AND pack_id IS NOT NULL",
            &[
                SqliteValue::Text(since_ts.to_string()),
                SqliteValue::Text(end_ts.to_string()),
            ],
        ))?;
        let mut packs = Vec::new();
        for row in &rows {
            packs.push(sv_to_string(&row.values()[0]));
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

        let rows = self.conn.query(&inline_params(
            "SELECT command, timestamp, working_dir FROM commands
             WHERE timestamp >= ?1 AND timestamp < ?2
             AND outcome = 'allow'
             ORDER BY timestamp DESC
             LIMIT 1000",
            &[
                SqliteValue::Text(since_ts.to_string()),
                SqliteValue::Text(end_ts.to_string()),
            ],
        ))?;

        for row in &rows {
            let vals = row.values();
            let command = sv_to_string(&vals[0]);
            let timestamp_str = sv_to_string(&vals[1]);
            let working_dir = sv_to_opt_string(&vals[2]);
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
        recommendations.sort_by_key(|r| std::cmp::Reverse(r.priority));
        recommendations
    }

    // ========================================================================
    // Rule-Level Metrics Queries
    // ========================================================================

    /// Get aggregated metrics for all rules.
    ///
    /// Returns per-rule statistics including hit counts, override rates, and trends.
    ///
    /// # Arguments
    ///
    /// * `since` - Optional start time (defaults to all time)
    /// * `limit` - Maximum number of rules to return (defaults to 100)
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn get_rule_metrics(
        &self,
        since: Option<DateTime<Utc>>,
        limit: usize,
    ) -> Result<Vec<RuleMetrics>, HistoryError> {
        let since_ts = since.map_or_else(
            || "1970-01-01T00:00:00Z".to_string(),
            |dt| dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        );

        // Query for main aggregates
        let limit_i64 = i64::try_from(limit).unwrap_or(100);
        // fsqlite does not support SUM(CASE WHEN ...) with GROUP BY.
        // Use two separate queries and merge bypass counts in Rust.
        let rows = self.conn.query(&inline_params(
            r"SELECT
                rule_id,
                COUNT(*) as total_hits,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                COUNT(DISTINCT command_hash) as unique_commands
             FROM commands
             WHERE rule_id IS NOT NULL
               AND timestamp >= ?1
             GROUP BY rule_id
             ORDER BY total_hits DESC
             LIMIT ?2",
            &[
                SqliteValue::Text(since_ts.clone()),
                SqliteValue::Integer(limit_i64),
            ],
        ))?;
        // Bypass counts per rule
        let bypass_rows = self.conn.query(&inline_params(
            "SELECT rule_id, COUNT(*) FROM commands WHERE rule_id IS NOT NULL AND outcome = 'bypass' AND timestamp >= ?1 GROUP BY rule_id",
            &[SqliteValue::Text(since_ts)],
        ))?;
        let bypass_map: HashMap<String, i64> = bypass_rows
            .iter()
            .map(|r| (sv_to_string(&r.values()[0]), sv_to_i64(&r.values()[1])))
            .collect();

        let mut metrics = Vec::new();
        for row in &rows {
            let vals = row.values();
            let rule_id = sv_to_string(&vals[0]);
            let total_hits = sv_to_i64(&vals[1]);
            let first_seen_str = sv_to_string(&vals[2]);
            let last_seen_str = sv_to_string(&vals[3]);
            let unique_commands = sv_to_i64(&vals[4]);

            let total_hits = u64::try_from(total_hits).unwrap_or(0);
            let overrides_i64 = bypass_map.get(&rule_id).copied().unwrap_or(0);
            let overrides = u64::try_from(overrides_i64).unwrap_or(0);
            let unique_commands = u64::try_from(unique_commands).unwrap_or(0);

            #[allow(clippy::cast_precision_loss)]
            let override_rate = if total_hits > 0 {
                (overrides as f64 / total_hits as f64) * 100.0
            } else {
                0.0
            };

            let first_seen = chrono::DateTime::parse_from_rfc3339(&first_seen_str)
                .map_or_else(|_| Utc::now(), |dt| dt.with_timezone(&Utc));
            let last_seen = chrono::DateTime::parse_from_rfc3339(&last_seen_str)
                .map_or_else(|_| Utc::now(), |dt| dt.with_timezone(&Utc));

            // Calculate trend with week-over-week comparison
            let (trend, previous_period_hits, change_percentage, is_anomaly) =
                self.calculate_rule_trend(&rule_id, total_hits);

            metrics.push(RuleMetrics {
                rule_id,
                total_hits,
                allowlist_overrides: overrides,
                override_rate,
                first_seen,
                last_seen,
                unique_commands,
                trend,
                is_noisy: override_rate >= RuleMetrics::NOISY_THRESHOLD,
                previous_period_hits,
                change_percentage,
                is_anomaly,
            });
        }

        Ok(metrics)
    }

    /// Get metrics for a specific rule.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn get_rule_metrics_for_rule(
        &self,
        rule_id: &str,
    ) -> Result<Option<RuleMetrics>, HistoryError> {
        // fsqlite does not support SUM(CASE WHEN ...) or scalar subqueries
        // mixed with aggregates. Use two separate queries.
        let params = &[SqliteValue::Text(rule_id.to_string())];
        let result = self.conn.query_row(&inline_params(
            r"SELECT
                COUNT(*) as total_hits,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                COUNT(DISTINCT command_hash) as unique_commands
             FROM commands
             WHERE rule_id = ?1",
            params,
        ));

        match result {
            Ok(row) => {
                let vals = row.values();
                let total_hits_i64 = sv_to_i64(&vals[0]);

                if total_hits_i64 == 0 {
                    return Ok(None);
                }

                let total_hits = u64::try_from(total_hits_i64).unwrap_or(0);
                // Separate query for bypass count
                let bypass_count = self
                    .conn
                    .query_row(&inline_params(
                        "SELECT COUNT(*) FROM commands WHERE rule_id = ?1 AND outcome = 'bypass'",
                        params,
                    ))
                    .map(|r| sv_to_i64(&r.values()[0]))
                    .unwrap_or(0);
                let overrides = u64::try_from(bypass_count).unwrap_or(0);
                let unique_commands = u64::try_from(sv_to_i64(&vals[3])).unwrap_or(0);

                let first_seen_opt = sv_to_opt_string(&vals[1]);
                let last_seen_opt = sv_to_opt_string(&vals[2]);

                #[allow(clippy::cast_precision_loss)]
                let override_rate = if total_hits > 0 {
                    (overrides as f64 / total_hits as f64) * 100.0
                } else {
                    0.0
                };

                let first_seen = first_seen_opt
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                    .map_or_else(Utc::now, |dt| dt.with_timezone(&Utc));
                let last_seen = last_seen_opt
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                    .map_or_else(Utc::now, |dt| dt.with_timezone(&Utc));

                let (trend, previous_period_hits, change_percentage, is_anomaly) =
                    self.calculate_rule_trend(rule_id, total_hits);

                Ok(Some(RuleMetrics {
                    rule_id: rule_id.to_string(),
                    total_hits,
                    allowlist_overrides: overrides,
                    override_rate,
                    first_seen,
                    last_seen,
                    unique_commands,
                    trend,
                    is_noisy: override_rate >= RuleMetrics::NOISY_THRESHOLD,
                    previous_period_hits,
                    change_percentage,
                    is_anomaly,
                }))
            }
            Err(FrankenError::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(HistoryError::Sqlite(e)),
        }
    }

    /// Get the noisiest rules (highest override rate).
    ///
    /// # Arguments
    ///
    /// * `limit` - Maximum number of rules to return
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn get_noisiest_rules(&self, limit: usize) -> Result<Vec<RuleMetrics>, HistoryError> {
        let min_hits = i64::try_from(RuleMetrics::MIN_HITS_FOR_TREND).unwrap_or(5);

        // fsqlite does not support SUM(CASE WHEN ...) with GROUP BY.
        // Use two queries and merge bypass counts in Rust, then sort.
        let rows = self.conn.query(&inline_params(
            r"SELECT
                rule_id,
                COUNT(*) as total_hits,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                COUNT(DISTINCT command_hash) as unique_commands
             FROM commands
             WHERE rule_id IS NOT NULL
             GROUP BY rule_id
             HAVING total_hits >= ?1",
            &[SqliteValue::Integer(min_hits)],
        ))?;
        let bypass_rows = self.conn.query(
            "SELECT rule_id, COUNT(*) FROM commands WHERE rule_id IS NOT NULL AND outcome = 'bypass' GROUP BY rule_id",
        )?;
        let bypass_map: HashMap<String, i64> = bypass_rows
            .iter()
            .map(|r| (sv_to_string(&r.values()[0]), sv_to_i64(&r.values()[1])))
            .collect();

        let mut metrics = Vec::new();
        for row in &rows {
            let vals = row.values();
            let rule_id = sv_to_string(&vals[0]);
            let total_hits = sv_to_i64(&vals[1]);
            let first_seen_str = sv_to_string(&vals[2]);
            let last_seen_str = sv_to_string(&vals[3]);
            let unique_commands = sv_to_i64(&vals[4]);

            let total_hits = u64::try_from(total_hits).unwrap_or(0);
            let overrides_i64 = bypass_map.get(&rule_id).copied().unwrap_or(0);
            let overrides = u64::try_from(overrides_i64).unwrap_or(0);
            let unique_commands = u64::try_from(unique_commands).unwrap_or(0);

            #[allow(clippy::cast_precision_loss)]
            let override_rate = if total_hits > 0 {
                (overrides as f64 / total_hits as f64) * 100.0
            } else {
                0.0
            };

            let first_seen = chrono::DateTime::parse_from_rfc3339(&first_seen_str)
                .map_or_else(|_| Utc::now(), |dt| dt.with_timezone(&Utc));
            let last_seen = chrono::DateTime::parse_from_rfc3339(&last_seen_str)
                .map_or_else(|_| Utc::now(), |dt| dt.with_timezone(&Utc));

            let (trend, previous_period_hits, change_percentage, is_anomaly) =
                self.calculate_rule_trend(&rule_id, total_hits);

            metrics.push(RuleMetrics {
                rule_id,
                total_hits,
                allowlist_overrides: overrides,
                override_rate,
                first_seen,
                last_seen,
                unique_commands,
                trend,
                is_noisy: override_rate >= RuleMetrics::NOISY_THRESHOLD,
                previous_period_hits,
                change_percentage,
                is_anomaly,
            });
        }

        // Sort by override rate descending and apply limit (done in Rust since
        // the SQL no longer handles the bypass-rate-based ordering)
        metrics.sort_by(|a, b| {
            b.override_rate
                .partial_cmp(&a.override_rate)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        metrics.truncate(limit);

        Ok(metrics)
    }

    /// Calculate trend by comparing recent vs previous period.
    ///
    /// Returns (trend, `previous_period_hits`, `change_percentage`, `is_anomaly`).
    fn calculate_rule_trend(&self, rule_id: &str, total_hits: u64) -> (RuleTrend, u64, f64, bool) {
        if total_hits < RuleMetrics::MIN_HITS_FOR_TREND {
            return (RuleTrend::Stable, 0, 0.0, false);
        }

        let now = Utc::now();
        let one_week_ago = now - chrono::Duration::days(7);
        let two_weeks_ago = now - chrono::Duration::days(14);

        let recent_ts = one_week_ago.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let previous_ts = two_weeks_ago.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let now_ts = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        // Count recent period
        let recent_count: i64 = self.conn.query_row_with_params(
            "SELECT COUNT(*) FROM commands WHERE rule_id = ?1 AND timestamp >= ?2 AND timestamp < ?3",
            &[
                SqliteValue::Text(rule_id.to_string()),
                SqliteValue::Text(recent_ts.clone()),
                SqliteValue::Text(now_ts),
            ],
        ).map(|row| sv_to_i64(&row.values()[0])).unwrap_or(0);

        // Count previous period
        let previous_count: i64 = self.conn.query_row_with_params(
            "SELECT COUNT(*) FROM commands WHERE rule_id = ?1 AND timestamp >= ?2 AND timestamp < ?3",
            &[
                SqliteValue::Text(rule_id.to_string()),
                SqliteValue::Text(previous_ts),
                SqliteValue::Text(recent_ts),
            ],
        ).map(|row| sv_to_i64(&row.values()[0])).unwrap_or(0);

        let previous_hits = u64::try_from(previous_count).unwrap_or(0);

        if previous_count == 0 {
            // No previous data - can't determine trend percentage, but can be anomaly if new
            let is_anomaly = recent_count > 10; // Treat new rules with many hits as anomalous
            return (RuleTrend::Stable, 0, 0.0, is_anomaly);
        }

        #[allow(clippy::cast_precision_loss)]
        let change_percentage =
            ((recent_count as f64 - previous_count as f64) / previous_count as f64) * 100.0;
        let is_anomaly = change_percentage >= RuleMetrics::ANOMALY_THRESHOLD;

        let trend = if change_percentage > (RuleMetrics::TREND_THRESHOLD * 100.0) {
            RuleTrend::Increasing
        } else if change_percentage < -(RuleMetrics::TREND_THRESHOLD * 100.0) {
            RuleTrend::Decreasing
        } else {
            RuleTrend::Stable
        };

        (trend, previous_hits, change_percentage, is_anomaly)
    }

    // ========================================================================
    // Suggestion Audit Logging
    // ========================================================================

    /// Log a suggestion audit entry to the database.
    ///
    /// Records when a user accepts, modifies, or rejects a suggested allowlist pattern.
    /// This provides traceability for how the allowlist evolved over time.
    ///
    /// # Errors
    ///
    /// Returns an error if the insert fails.
    pub fn log_suggestion_audit(&self, entry: &SuggestionAuditEntry) -> Result<i64, HistoryError> {
        let timestamp = entry.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let cluster_frequency = i64::try_from(entry.cluster_frequency).unwrap_or(i64::MAX);
        let unique_variants = i64::try_from(entry.unique_variants).unwrap_or(i64::MAX);

        self.conn.execute_with_params(
            r"INSERT INTO suggestion_audit (
                timestamp, action, pattern, final_pattern, risk_level, risk_score,
                confidence_tier, confidence_points, cluster_frequency, unique_variants,
                sample_commands, rule_id, session_id, working_dir
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14
            )",
            &[
                SqliteValue::Text(timestamp),
                SqliteValue::Text(entry.action.as_str().to_string()),
                SqliteValue::Text(entry.pattern.clone()),
                opt_string_to_sv(entry.final_pattern.as_ref()),
                SqliteValue::Text(entry.risk_level.clone()),
                SqliteValue::Float(f64::from(entry.risk_score)),
                SqliteValue::Text(entry.confidence_tier.clone()),
                SqliteValue::Integer(i64::from(entry.confidence_points)),
                SqliteValue::Integer(cluster_frequency),
                SqliteValue::Integer(unique_variants),
                SqliteValue::Text(entry.sample_commands.clone()),
                opt_string_to_sv(entry.rule_id.as_ref()),
                opt_string_to_sv(entry.session_id.as_ref()),
                opt_string_to_sv(entry.working_dir.as_ref()),
            ],
        )?;

        let row = self
            .conn
            .query_row("SELECT max(id) FROM suggestion_audit")?;
        Ok(sv_to_i64(&row.values()[0]))
    }

    /// Count suggestion audit entries in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn count_suggestion_audits(&self) -> Result<u64, HistoryError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM suggestion_audit")
            .map(|row| sv_to_i64(&row.values()[0]))
            .map_err(HistoryError::Sqlite)?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// Query recent suggestion audit entries.
    ///
    /// # Arguments
    ///
    /// * `limit` - Maximum number of entries to return
    /// * `action_filter` - Optional filter by action type
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn query_suggestion_audits(
        &self,
        limit: usize,
        action_filter: Option<SuggestionAction>,
    ) -> Result<Vec<SuggestionAuditEntry>, HistoryError> {
        let mut sql = String::from(
            "SELECT timestamp, action, pattern, final_pattern, risk_level, risk_score,
                    confidence_tier, confidence_points, cluster_frequency, unique_variants,
                    sample_commands, rule_id, session_id, working_dir
             FROM suggestion_audit",
        );

        let mut params: Vec<SqliteValue> = Vec::new();
        let mut param_idx = 1;

        if let Some(action) = action_filter {
            write!(sql, " WHERE action = ?{param_idx}").unwrap();
            params.push(SqliteValue::Text(action.as_str().to_string()));
            param_idx += 1;
        }

        write!(sql, " ORDER BY timestamp DESC LIMIT ?{param_idx}").unwrap();
        params.push(SqliteValue::Integer(
            i64::try_from(limit).unwrap_or(i64::MAX),
        ));

        let rows = self.conn.query(&inline_params(&sql, &params))?;

        let mut entries = Vec::new();
        for row in &rows {
            let vals = row.values();
            let timestamp_str = sv_to_string(&vals[0]);
            let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
                .map_or_else(|_| Utc::now(), |dt| dt.with_timezone(&Utc));

            let action_str = sv_to_string(&vals[1]);
            let action = SuggestionAction::parse(&action_str).unwrap_or(SuggestionAction::Accepted);

            let cluster_frequency = sv_to_i64(&vals[8]);
            let unique_variants = sv_to_i64(&vals[9]);

            entries.push(SuggestionAuditEntry {
                timestamp,
                action,
                pattern: sv_to_string(&vals[2]),
                final_pattern: sv_to_opt_string(&vals[3]),
                risk_level: sv_to_string(&vals[4]),
                risk_score: sv_to_f32(&vals[5]),
                confidence_tier: sv_to_string(&vals[6]),
                confidence_points: sv_to_i32(&vals[7]),
                cluster_frequency: usize::try_from(cluster_frequency).unwrap_or(0),
                unique_variants: usize::try_from(unique_variants).unwrap_or(0),
                sample_commands: sv_to_string(&vals[10]),
                rule_id: sv_to_opt_string(&vals[11]),
                session_id: sv_to_opt_string(&vals[12]),
                working_dir: sv_to_opt_string(&vals[13]),
            });
        }
        Ok(entries)
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

// ============================================================================
// Rule-Level Metrics Types
// ============================================================================

/// Trend direction for rule activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleTrend {
    /// Rule triggers are increasing compared to previous period.
    Increasing,
    /// Rule triggers are stable.
    Stable,
    /// Rule triggers are decreasing.
    Decreasing,
}

impl std::fmt::Display for RuleTrend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Increasing => write!(f, "↑ increasing"),
            Self::Stable => write!(f, "→ stable"),
            Self::Decreasing => write!(f, "↓ decreasing"),
        }
    }
}

/// Per-rule aggregated metrics.
#[derive(Debug, Clone, Serialize)]
pub struct RuleMetrics {
    /// Stable rule identifier (`pack_id:pattern_name`).
    pub rule_id: String,
    /// Total times this rule triggered (deny + bypass + warn).
    pub total_hits: u64,
    /// Times the rule resulted in allowlist override (bypass).
    pub allowlist_overrides: u64,
    /// Override rate as a percentage (0.0-100.0).
    pub override_rate: f64,
    /// When this rule was first triggered.
    pub first_seen: DateTime<Utc>,
    /// When this rule was last triggered.
    pub last_seen: DateTime<Utc>,
    /// Number of unique commands that triggered this rule.
    pub unique_commands: u64,
    /// Trend direction based on recent vs previous period.
    pub trend: RuleTrend,
    /// Whether this rule is considered noisy (high override rate).
    pub is_noisy: bool,
    /// Hits in the previous period (for week-over-week comparison).
    pub previous_period_hits: u64,
    /// Percentage change from previous period (-100.0 to +infinity).
    pub change_percentage: f64,
    /// Whether this rule shows an anomalous spike (> 200% increase).
    pub is_anomaly: bool,
}

impl RuleMetrics {
    /// Threshold for considering a rule noisy.
    pub const NOISY_THRESHOLD: f64 = 30.0;
    /// Minimum hits required to calculate trend.
    pub const MIN_HITS_FOR_TREND: u64 = 5;
    /// Threshold change for increasing/decreasing trend (30% change).
    pub const TREND_THRESHOLD: f64 = 0.3;
    /// Threshold for anomaly detection (200% increase).
    pub const ANOMALY_THRESHOLD: f64 = 200.0;
}

// ============================================================================
// Suggestion Audit Logging Types
// ============================================================================

/// User action taken on a suggestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuggestionAction {
    /// User accepted the suggestion as-is.
    Accepted,
    /// User modified the suggestion before accepting.
    Modified,
    /// User rejected the suggestion.
    Rejected,
}

impl SuggestionAction {
    /// Convert to database string representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Modified => "modified",
            Self::Rejected => "rejected",
        }
    }

    /// Parse from database string representation.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "accepted" => Some(Self::Accepted),
            "modified" => Some(Self::Modified),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }
}

impl std::str::FromStr for SuggestionAction {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(())
    }
}

impl std::fmt::Display for SuggestionAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// An audit entry for a suggestion action.
///
/// Records when a user accepts, modifies, or rejects a suggested allowlist pattern.
/// This provides traceability for how the allowlist evolved over time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestionAuditEntry {
    /// Timestamp when the action was taken (ISO 8601).
    pub timestamp: DateTime<Utc>,
    /// The action taken by the user.
    pub action: SuggestionAction,
    /// The suggested regex pattern.
    pub pattern: String,
    /// The final pattern (may differ from suggestion if modified).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_pattern: Option<String>,
    /// Risk level of the suggestion (low, medium, high).
    pub risk_level: String,
    /// Numeric risk score from 0.0 (safest) to 1.0 (most dangerous).
    pub risk_score: f32,
    /// Confidence tier (high, medium, low).
    pub confidence_tier: String,
    /// Confidence score points.
    pub confidence_points: i32,
    /// How many times commands matching this pattern were blocked.
    pub cluster_frequency: usize,
    /// Number of unique command variants in the source cluster.
    pub unique_variants: usize,
    /// Sample commands from the cluster (JSON array, limited to 5).
    pub sample_commands: String,
    /// Rule ID if the pattern corresponds to a specific rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Session ID to correlate with command history.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Working directory where the suggestion was generated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
}

impl Default for SuggestionAuditEntry {
    fn default() -> Self {
        Self {
            timestamp: Utc::now(),
            action: SuggestionAction::Accepted,
            pattern: String::new(),
            final_pattern: None,
            risk_level: "low".to_string(),
            risk_score: 0.0,
            confidence_tier: "medium".to_string(),
            confidence_points: 0,
            cluster_frequency: 0,
            unique_variants: 0,
            sample_commands: "[]".to_string(),
            rule_id: None,
            session_id: None,
            working_dir: None,
        }
    }
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
        db.conn.execute("DROP TABLE schema_version").unwrap();
        db.conn
            .execute(
                r"CREATE TABLE schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
                )",
            )
            .unwrap();
        db.conn
            .execute("INSERT INTO schema_version (version) VALUES (1)")
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

    fn insert_command(
        db: &HistoryDb,
        command: &str,
        outcome: Outcome,
        working_dir: &str,
        timestamp: DateTime<Utc>,
    ) {
        let entry = CommandEntry {
            timestamp,
            agent_type: "claude_code".to_string(),
            working_dir: working_dir.to_string(),
            command: command.to_string(),
            outcome,
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
        let rows = db
            .conn
            .query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap();
        let tables: Vec<String> = rows
            .iter()
            .map(|row| sv_to_string(&row.values()[0]))
            .collect();

        assert!(tables.contains(&"commands".to_string()));
        assert!(tables.contains(&"schema_version".to_string()));
    }

    #[test]
    fn test_commands_table_columns() {
        let db = HistoryDb::open_in_memory().unwrap();

        // Verify columns exist by selecting them (fsqlite PRAGMA table_info
        // may return empty results for in-memory databases).
        let row = db.conn.query_row(
            "SELECT id, timestamp, agent_type, working_dir, command, command_hash,
                        outcome, eval_duration_us, session_id, exit_code,
                        parent_command_id, hostname
                 FROM commands LIMIT 0",
        );
        // The query should parse successfully even with no data (LIMIT 0).
        // If any column didn't exist, this would fail with "no such column".
        assert!(
            row.is_ok() || matches!(row, Err(FrankenError::QueryReturnedNoRows)),
            "all expected columns should exist in commands table"
        );
    }

    #[test]
    fn test_indexes_created() {
        let db = HistoryDb::open_in_memory().unwrap();

        let rows = db
            .conn
            .query("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'")
            .unwrap();
        let indexes: Vec<String> = rows
            .iter()
            .map(|row| sv_to_string(&row.values()[0]))
            .collect();

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
        let result = db
            .conn
            .query_row("SELECT 1 FROM sqlite_master WHERE type='table' AND name='commands_fts'");
        assert!(result.is_ok());
    }

    #[test]
    fn test_insert_and_query() {
        let db = HistoryDb::open_in_memory().unwrap();

        let entry = test_entry();
        db.log_command(&entry).unwrap();

        let count: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM commands")
            .map(|row| sv_to_i64(&row.values()[0]))
            .unwrap();

        assert_eq!(count, 1);
    }

    #[test]
    fn test_log_command_computes_rule_id_from_pack_and_pattern() {
        let db = HistoryDb::open_in_memory().unwrap();

        let entry = CommandEntry {
            timestamp: Utc::now(),
            agent_type: "claude_code".to_string(),
            working_dir: "/test/project".to_string(),
            command: "git reset --hard".to_string(),
            outcome: Outcome::Deny,
            pack_id: Some("core.git".to_string()),
            pattern_name: Some("reset-hard".to_string()),
            rule_id: None,
            ..Default::default()
        };

        db.log_command(&entry).unwrap();

        let stored: Option<String> = db
            .conn
            .query_row("SELECT rule_id FROM commands LIMIT 1")
            .map(|row| sv_to_opt_string(&row.values()[0]))
            .unwrap();
        assert_eq!(stored, Some("core.git:reset-hard".to_string()));
    }

    #[test]
    fn test_log_command_preserves_explicit_rule_id() {
        let db = HistoryDb::open_in_memory().unwrap();

        let entry = CommandEntry {
            timestamp: Utc::now(),
            agent_type: "claude_code".to_string(),
            working_dir: "/test/project".to_string(),
            command: "git reset --hard".to_string(),
            outcome: Outcome::Deny,
            pack_id: Some("core.git".to_string()),
            pattern_name: Some("reset-hard".to_string()),
            rule_id: Some("override.rule-id".to_string()),
            ..Default::default()
        };

        db.log_command(&entry).unwrap();

        let stored: Option<String> = db
            .conn
            .query_row("SELECT rule_id FROM commands LIMIT 1")
            .map(|row| sv_to_opt_string(&row.values()[0]))
            .unwrap();
        assert_eq!(stored, Some("override.rule-id".to_string()));
    }

    #[test]
    fn test_log_command_records_rule_id_for_allowlist_override() {
        let db = HistoryDb::open_in_memory().unwrap();

        let entry = CommandEntry {
            timestamp: Utc::now(),
            agent_type: "claude_code".to_string(),
            working_dir: "/test/project".to_string(),
            command: "git reset --hard".to_string(),
            outcome: Outcome::Allow,
            pack_id: Some("core.git".to_string()),
            pattern_name: Some("reset-hard".to_string()),
            allowlist_layer: Some("user".to_string()),
            ..Default::default()
        };

        db.log_command(&entry).unwrap();

        let stored: Option<String> = db
            .conn
            .query_row("SELECT rule_id FROM commands LIMIT 1")
            .map(|row| sv_to_opt_string(&row.values()[0]))
            .unwrap();
        assert_eq!(stored, Some("core.git:reset-hard".to_string()));
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
            .query_row("SELECT timestamp FROM commands LIMIT 1")
            .map(|row| sv_to_string(&row.values()[0]))
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
            .query_row("PRAGMA journal_mode")
            .map(|row| sv_to_string(&row.values()[0]))
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
            .query_row("SELECT COUNT(*) FROM schema_version WHERE description IS NOT NULL")
            .map(|row| sv_to_i64(&row.values()[0]))
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

        // Search for git commands using LIKE (fsqlite's FTS5 MATCH operator does
        // not correctly handle aggregation in the fallback execution path).
        let count: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM commands_fts WHERE command LIKE '%git%'")
            .map(|row| sv_to_i64(&row.values()[0]))
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
        let row = db
            .conn
            .query_row_with_params(
                "SELECT pack_id, pattern_name, session_id, hostname, bypass_code
                 FROM commands WHERE id = ?1",
                &[SqliteValue::Integer(id)],
            )
            .unwrap();
        let vals = row.values();
        let (pack_id, pattern_name, session_id, hostname, bypass_code): OptionalFields = (
            sv_to_opt_string(&vals[0]),
            sv_to_opt_string(&vals[1]),
            sv_to_opt_string(&vals[2]),
            sv_to_opt_string(&vals[3]),
            sv_to_opt_string(&vals[4]),
        );

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
            )
            .unwrap();

        // Note: fsqlite does not enforce CHECK constraints at this time,
        // so we only verify valid outcomes can be inserted. Application-level
        // validation in CommandEntry::outcome ensures correctness.
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
    // History Analyzer Tests
    // ========================================================================

    #[test]
    fn test_history_analyzer_frequent_blocks() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now() - Duration::days(1);

        for _ in 0..3 {
            insert_command(&db, "rm -rf ./build", Outcome::Deny, "/project/a", now);
        }
        insert_command(&db, "git reset --hard", Outcome::Deny, "/project/a", now);

        let analyzer = HistoryAnalyzer::new(&db);
        let results = analyzer.get_frequent_blocks(30, 2).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].command, "rm -rf ./build");
        assert_eq!(results[0].block_count, 3);
    }

    #[test]
    fn test_history_analyzer_path_clusters() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now() - Duration::days(1);

        insert_command(&db, "rm -rf ./build", Outcome::Deny, "/project/a", now);
        insert_command(&db, "rm -rf ./build", Outcome::Deny, "/project/a", now);
        insert_command(&db, "rm -rf ./build", Outcome::Deny, "/project/b", now);

        let analyzer = HistoryAnalyzer::new(&db);
        let results = analyzer.get_path_clusters(2).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].command, "rm -rf ./build");
        assert_eq!(results[0].working_dir, "/project/a");
        assert_eq!(results[0].block_count, 2);
    }

    #[test]
    fn test_history_analyzer_suggestion_candidates() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now() - Duration::days(1);

        insert_command(&db, "git clean -fd", Outcome::Bypass, "/project/a", now);
        insert_command(&db, "git clean -fd", Outcome::Bypass, "/project/a", now);
        insert_command(&db, "rm -rf ./tmp", Outcome::Bypass, "/project/b", now);

        let analyzer = HistoryAnalyzer::new(&db);
        let results = analyzer.get_suggestion_candidates().unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].command, "git clean -fd");
        assert_eq!(results[0].bypass_count, 2);
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

    // ==========================================================================
    // Suggestion Audit Tests
    // ==========================================================================

    fn test_suggestion_audit_entry(action: SuggestionAction) -> SuggestionAuditEntry {
        SuggestionAuditEntry {
            timestamp: Utc::now(),
            action,
            pattern: "git reset --hard".to_string(),
            final_pattern: None,
            risk_level: "high".to_string(),
            risk_score: 0.85,
            confidence_tier: "strong".to_string(),
            confidence_points: 15,
            cluster_frequency: 42,
            unique_variants: 3,
            sample_commands: "git reset --hard HEAD~1, git reset --hard origin/main".to_string(),
            rule_id: Some("git-reset-hard-001".to_string()),
            session_id: Some("ses-abc123".to_string()),
            working_dir: Some("/test/project".to_string()),
        }
    }

    #[test]
    fn test_log_suggestion_audit_inserts_entry() {
        let db = HistoryDb::open_in_memory().unwrap();
        let entry = test_suggestion_audit_entry(SuggestionAction::Accepted);

        let id = db.log_suggestion_audit(&entry).unwrap();
        assert!(id > 0, "Should return a positive ID");

        // Verify it was inserted
        let count = db.count_suggestion_audits().unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_log_suggestion_audit_with_modified_action() {
        let db = HistoryDb::open_in_memory().unwrap();
        let mut entry = test_suggestion_audit_entry(SuggestionAction::Modified);
        entry.final_pattern = Some("git reset --soft".to_string());

        let id = db.log_suggestion_audit(&entry).unwrap();
        assert!(id > 0);

        // Query and verify the final_pattern was stored
        let results = db
            .query_suggestion_audits(10, Some(SuggestionAction::Modified))
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].final_pattern,
            Some("git reset --soft".to_string())
        );
    }

    #[test]
    fn test_count_suggestion_audits_returns_accurate_count() {
        let db = HistoryDb::open_in_memory().unwrap();

        // Insert multiple entries
        for _ in 0..5 {
            let entry = test_suggestion_audit_entry(SuggestionAction::Accepted);
            db.log_suggestion_audit(&entry).unwrap();
        }
        for _ in 0..3 {
            let entry = test_suggestion_audit_entry(SuggestionAction::Rejected);
            db.log_suggestion_audit(&entry).unwrap();
        }

        let count = db.count_suggestion_audits().unwrap();
        assert_eq!(count, 8);
    }

    #[test]
    fn test_query_suggestion_audits_returns_all_when_no_filter() {
        let db = HistoryDb::open_in_memory().unwrap();

        db.log_suggestion_audit(&test_suggestion_audit_entry(SuggestionAction::Accepted))
            .unwrap();
        db.log_suggestion_audit(&test_suggestion_audit_entry(SuggestionAction::Modified))
            .unwrap();
        db.log_suggestion_audit(&test_suggestion_audit_entry(SuggestionAction::Rejected))
            .unwrap();

        let results = db.query_suggestion_audits(100, None).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_query_suggestion_audits_filters_by_action() {
        let db = HistoryDb::open_in_memory().unwrap();

        // Insert entries with different actions
        for _ in 0..4 {
            db.log_suggestion_audit(&test_suggestion_audit_entry(SuggestionAction::Accepted))
                .unwrap();
        }
        for _ in 0..2 {
            db.log_suggestion_audit(&test_suggestion_audit_entry(SuggestionAction::Modified))
                .unwrap();
        }
        db.log_suggestion_audit(&test_suggestion_audit_entry(SuggestionAction::Rejected))
            .unwrap();

        // Filter by Accepted
        let accepted = db
            .query_suggestion_audits(100, Some(SuggestionAction::Accepted))
            .unwrap();
        assert_eq!(accepted.len(), 4);
        assert!(
            accepted
                .iter()
                .all(|e| e.action == SuggestionAction::Accepted)
        );

        // Filter by Modified
        let modified = db
            .query_suggestion_audits(100, Some(SuggestionAction::Modified))
            .unwrap();
        assert_eq!(modified.len(), 2);
        assert!(
            modified
                .iter()
                .all(|e| e.action == SuggestionAction::Modified)
        );

        // Filter by Rejected
        let rejected = db
            .query_suggestion_audits(100, Some(SuggestionAction::Rejected))
            .unwrap();
        assert_eq!(rejected.len(), 1);
        assert!(
            rejected
                .iter()
                .all(|e| e.action == SuggestionAction::Rejected)
        );
    }

    #[test]
    fn test_query_suggestion_audits_respects_limit() {
        let db = HistoryDb::open_in_memory().unwrap();

        // Insert 10 entries
        for _ in 0..10 {
            db.log_suggestion_audit(&test_suggestion_audit_entry(SuggestionAction::Accepted))
                .unwrap();
        }

        // Query with limit of 5
        let results = db.query_suggestion_audits(5, None).unwrap();
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn test_query_suggestion_audits_orders_by_timestamp_desc() {
        let db = HistoryDb::open_in_memory().unwrap();

        // Insert entries with different timestamps
        for i in 0..3 {
            let mut entry = test_suggestion_audit_entry(SuggestionAction::Accepted);
            entry.timestamp = Utc::now() - Duration::hours(i);
            entry.pattern = format!("pattern-{i}");
            db.log_suggestion_audit(&entry).unwrap();
        }

        let results = db.query_suggestion_audits(100, None).unwrap();
        assert_eq!(results.len(), 3);
        // Most recent first (pattern-0 has the newest timestamp)
        assert_eq!(results[0].pattern, "pattern-0");
        assert_eq!(results[1].pattern, "pattern-1");
        assert_eq!(results[2].pattern, "pattern-2");
    }

    #[test]
    fn test_suggestion_audit_stores_all_fields() {
        let db = HistoryDb::open_in_memory().unwrap();

        let entry = SuggestionAuditEntry {
            timestamp: Utc::now(),
            action: SuggestionAction::Accepted,
            pattern: "rm -rf /".to_string(),
            final_pattern: Some("rm -rf ./temp".to_string()),
            risk_level: "critical".to_string(),
            risk_score: 0.99,
            confidence_tier: "strong".to_string(),
            confidence_points: 20,
            cluster_frequency: 100,
            unique_variants: 5,
            sample_commands: "rm -rf /, rm -rf ~".to_string(),
            rule_id: Some("rm-rf-001".to_string()),
            session_id: Some("ses-xyz789".to_string()),
            working_dir: Some("/dangerous/path".to_string()),
        };

        db.log_suggestion_audit(&entry).unwrap();

        let results = db.query_suggestion_audits(1, None).unwrap();
        assert_eq!(results.len(), 1);

        let stored = &results[0];
        assert_eq!(stored.action, SuggestionAction::Accepted);
        assert_eq!(stored.pattern, "rm -rf /");
        assert_eq!(stored.final_pattern, Some("rm -rf ./temp".to_string()));
        assert_eq!(stored.risk_level, "critical");
        assert!((stored.risk_score - 0.99).abs() < 0.001);
        assert_eq!(stored.confidence_tier, "strong");
        assert_eq!(stored.confidence_points, 20);
        assert_eq!(stored.cluster_frequency, 100);
        assert_eq!(stored.unique_variants, 5);
        assert_eq!(stored.sample_commands, "rm -rf /, rm -rf ~");
        assert_eq!(stored.rule_id, Some("rm-rf-001".to_string()));
        assert_eq!(stored.session_id, Some("ses-xyz789".to_string()));
        assert_eq!(stored.working_dir, Some("/dangerous/path".to_string()));
    }

    #[test]
    fn test_suggestion_audit_with_null_optional_fields() {
        let db = HistoryDb::open_in_memory().unwrap();

        let entry = SuggestionAuditEntry {
            timestamp: Utc::now(),
            action: SuggestionAction::Rejected,
            pattern: "test pattern".to_string(),
            final_pattern: None,
            risk_level: "low".to_string(),
            risk_score: 0.1,
            confidence_tier: "weak".to_string(),
            confidence_points: 2,
            cluster_frequency: 5,
            unique_variants: 1,
            sample_commands: "test".to_string(),
            rule_id: None,
            session_id: None,
            working_dir: None,
        };

        db.log_suggestion_audit(&entry).unwrap();

        let results = db.query_suggestion_audits(1, None).unwrap();
        assert_eq!(results.len(), 1);

        let stored = &results[0];
        assert_eq!(stored.final_pattern, None);
        assert_eq!(stored.rule_id, None);
        assert_eq!(stored.session_id, None);
        assert_eq!(stored.working_dir, None);
    }

    // ============================================================================
    // Rule Metrics Unit Tests (1dri.3)
    // ============================================================================

    /// Helper to insert a command with a specific `rule_id` and outcome.
    fn insert_rule_entry(
        db: &HistoryDb,
        rule_id: &str,
        outcome: Outcome,
        timestamp: DateTime<Utc>,
        command: &str,
    ) {
        let (pack_id, pattern_name) = rule_id.split_once(':').unwrap_or((rule_id, "pattern"));
        let entry = CommandEntry {
            timestamp,
            agent_type: "test_agent".to_string(),
            working_dir: "/test".to_string(),
            command: command.to_string(),
            outcome,
            pack_id: Some(pack_id.to_string()),
            pattern_name: Some(pattern_name.to_string()),
            rule_id: Some(rule_id.to_string()),
            ..Default::default()
        };
        db.log_command(&entry).unwrap();
    }

    #[test]
    fn test_get_rule_metrics_basic() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Insert commands for different rules
        for i in 0..5 {
            insert_rule_entry(
                &db,
                "core.git:reset-hard",
                Outcome::Deny,
                now,
                &format!("cmd-a-{i}"),
            );
        }
        for i in 0..3 {
            insert_rule_entry(
                &db,
                "core.filesystem:rm-rf",
                Outcome::Deny,
                now,
                &format!("cmd-b-{i}"),
            );
        }

        let metrics = db.get_rule_metrics(None, 100).unwrap();

        assert_eq!(metrics.len(), 2);
        // Ordered by total_hits descending
        assert_eq!(metrics[0].rule_id, "core.git:reset-hard");
        assert_eq!(metrics[0].total_hits, 5);
        assert_eq!(metrics[1].rule_id, "core.filesystem:rm-rf");
        assert_eq!(metrics[1].total_hits, 3);
    }

    #[test]
    fn test_get_rule_metrics_with_limit() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Insert commands for 5 different rules
        for (i, rule) in ["rule:a", "rule:b", "rule:c", "rule:d", "rule:e"]
            .iter()
            .enumerate()
        {
            for j in 0..(5 - i) {
                insert_rule_entry(&db, rule, Outcome::Deny, now, &format!("cmd-{i}-{j}"));
            }
        }

        // Limit to top 3
        let metrics = db.get_rule_metrics(None, 3).unwrap();
        assert_eq!(metrics.len(), 3);
        assert_eq!(metrics[0].total_hits, 5);
        assert_eq!(metrics[1].total_hits, 4);
        assert_eq!(metrics[2].total_hits, 3);
    }

    #[test]
    fn test_get_rule_metrics_with_since_filter() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();
        let old = now - Duration::days(10);
        let recent = now - Duration::hours(1);

        // Insert old commands
        insert_rule_entry(&db, "pack:old-rule", Outcome::Deny, old, "old-cmd-1");
        insert_rule_entry(&db, "pack:old-rule", Outcome::Deny, old, "old-cmd-2");

        // Insert recent commands
        insert_rule_entry(&db, "pack:new-rule", Outcome::Deny, recent, "new-cmd-1");
        insert_rule_entry(&db, "pack:new-rule", Outcome::Deny, recent, "new-cmd-2");
        insert_rule_entry(&db, "pack:new-rule", Outcome::Deny, recent, "new-cmd-3");

        // Query with since filter (last 7 days)
        let since = now - Duration::days(7);
        let metrics = db.get_rule_metrics(Some(since), 100).unwrap();

        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].rule_id, "pack:new-rule");
        assert_eq!(metrics[0].total_hits, 3);
    }

    #[test]
    fn test_get_rule_metrics_override_rate() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Insert 10 denials and 5 bypasses for the same rule
        for i in 0..10 {
            insert_rule_entry(
                &db,
                "test:override-rule",
                Outcome::Deny,
                now,
                &format!("deny-{i}"),
            );
        }
        for i in 0..5 {
            insert_rule_entry(
                &db,
                "test:override-rule",
                Outcome::Bypass,
                now,
                &format!("bypass-{i}"),
            );
        }

        let metrics = db.get_rule_metrics(None, 100).unwrap();
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].total_hits, 15);
        assert_eq!(metrics[0].allowlist_overrides, 5);
        // 5/15 = 33.33%
        assert!((metrics[0].override_rate - 33.333).abs() < 0.1);
    }

    #[test]
    fn test_get_rule_metrics_noisy_threshold() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Create a noisy rule (> 30% override rate)
        for i in 0..7 {
            insert_rule_entry(&db, "pack:noisy", Outcome::Deny, now, &format!("deny-{i}"));
        }
        for i in 0..3 {
            insert_rule_entry(
                &db,
                "pack:noisy",
                Outcome::Bypass,
                now,
                &format!("bypass-{i}"),
            );
        }

        // Create a non-noisy rule (< 30% override rate)
        for i in 0..9 {
            insert_rule_entry(
                &db,
                "pack:quiet",
                Outcome::Deny,
                now,
                &format!("deny-q-{i}"),
            );
        }
        insert_rule_entry(&db, "pack:quiet", Outcome::Bypass, now, "bypass-q-1");

        let metrics = db.get_rule_metrics(None, 100).unwrap();
        let noisy = metrics.iter().find(|m| m.rule_id == "pack:noisy").unwrap();
        let quiet = metrics.iter().find(|m| m.rule_id == "pack:quiet").unwrap();

        // 3/10 = 30%, which is >= NOISY_THRESHOLD
        assert!(noisy.is_noisy);
        // 1/10 = 10%, which is < NOISY_THRESHOLD
        assert!(!quiet.is_noisy);
    }

    #[test]
    fn test_get_rule_metrics_unique_commands() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Same command multiple times (should count as 1 unique)
        for _ in 0..5 {
            insert_rule_entry(&db, "pack:repeated", Outcome::Deny, now, "same-command");
        }

        // Different commands
        for i in 0..3 {
            insert_rule_entry(
                &db,
                "pack:varied",
                Outcome::Deny,
                now,
                &format!("unique-cmd-{i}"),
            );
        }

        let metrics = db.get_rule_metrics(None, 100).unwrap();
        let repeated = metrics
            .iter()
            .find(|m| m.rule_id == "pack:repeated")
            .unwrap();
        let varied = metrics.iter().find(|m| m.rule_id == "pack:varied").unwrap();

        assert_eq!(repeated.total_hits, 5);
        assert_eq!(repeated.unique_commands, 1);
        assert_eq!(varied.total_hits, 3);
        assert_eq!(varied.unique_commands, 3);
    }

    #[test]
    fn test_get_rule_metrics_for_rule_exists() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        insert_rule_entry(&db, "core.git:force-push", Outcome::Deny, now, "cmd-1");
        insert_rule_entry(&db, "core.git:force-push", Outcome::Deny, now, "cmd-2");
        insert_rule_entry(&db, "core.git:force-push", Outcome::Bypass, now, "cmd-3");

        let metrics = db.get_rule_metrics_for_rule("core.git:force-push").unwrap();
        assert!(metrics.is_some());
        let m = metrics.unwrap();
        assert_eq!(m.total_hits, 3);
        assert_eq!(m.allowlist_overrides, 1);
        assert_eq!(m.unique_commands, 3);
    }

    #[test]
    fn test_get_rule_metrics_for_rule_not_found() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        insert_rule_entry(&db, "core.git:reset-hard", Outcome::Deny, now, "cmd-1");

        // When querying a non-existent rule, total_hits will be 0 and the function returns None
        let metrics = db.get_rule_metrics_for_rule("nonexistent:rule").unwrap();
        // The implementation returns None for rules with 0 hits
        assert!(metrics.is_none());
    }

    #[test]
    fn test_get_noisiest_rules() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Create rules with varying override rates
        // Rule A: 50% override rate (5 deny, 5 bypass) - very noisy
        for i in 0..5 {
            insert_rule_entry(
                &db,
                "pack:rule-a",
                Outcome::Deny,
                now,
                &format!("a-deny-{i}"),
            );
        }
        for i in 0..5 {
            insert_rule_entry(
                &db,
                "pack:rule-a",
                Outcome::Bypass,
                now,
                &format!("a-bypass-{i}"),
            );
        }

        // Rule B: 40% override rate (6 deny, 4 bypass)
        for i in 0..6 {
            insert_rule_entry(
                &db,
                "pack:rule-b",
                Outcome::Deny,
                now,
                &format!("b-deny-{i}"),
            );
        }
        for i in 0..4 {
            insert_rule_entry(
                &db,
                "pack:rule-b",
                Outcome::Bypass,
                now,
                &format!("b-bypass-{i}"),
            );
        }

        // Rule C: 10% override rate (9 deny, 1 bypass) - less noisy
        for i in 0..9 {
            insert_rule_entry(
                &db,
                "pack:rule-c",
                Outcome::Deny,
                now,
                &format!("c-deny-{i}"),
            );
        }
        insert_rule_entry(&db, "pack:rule-c", Outcome::Bypass, now, "c-bypass-1");

        let noisy = db.get_noisiest_rules(10).unwrap();

        // get_noisiest_rules returns all rules >= MIN_HITS_FOR_TREND, ordered by override rate desc
        // It does NOT filter by NOISY_THRESHOLD - it just orders by noisiness
        assert_eq!(noisy.len(), 3);
        // Ordered by override rate descending
        assert_eq!(noisy[0].rule_id, "pack:rule-a");
        assert!((noisy[0].override_rate - 50.0).abs() < 0.1);
        assert_eq!(noisy[1].rule_id, "pack:rule-b");
        assert!((noisy[1].override_rate - 40.0).abs() < 0.1);
        assert_eq!(noisy[2].rule_id, "pack:rule-c");
        assert!((noisy[2].override_rate - 10.0).abs() < 0.1);
    }

    #[test]
    fn test_get_noisiest_rules_respects_limit() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Create 5 noisy rules
        for rule_num in 0..5 {
            let rule_id = format!("pack:noisy-{rule_num}");
            // Each rule has 50% override rate
            for i in 0..5 {
                insert_rule_entry(
                    &db,
                    &rule_id,
                    Outcome::Deny,
                    now,
                    &format!("deny-{rule_num}-{i}"),
                );
            }
            for i in 0..5 {
                insert_rule_entry(
                    &db,
                    &rule_id,
                    Outcome::Bypass,
                    now,
                    &format!("bypass-{rule_num}-{i}"),
                );
            }
        }

        let noisy = db.get_noisiest_rules(3).unwrap();
        assert_eq!(noisy.len(), 3);
    }

    #[test]
    fn test_get_noisiest_rules_minimum_hits() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Rule with high override rate but too few hits (< MIN_HITS_FOR_TREND = 5)
        insert_rule_entry(&db, "pack:few-hits", Outcome::Deny, now, "deny-1");
        insert_rule_entry(&db, "pack:few-hits", Outcome::Bypass, now, "bypass-1");
        insert_rule_entry(&db, "pack:few-hits", Outcome::Bypass, now, "bypass-2");
        // 2/3 = 66% but only 3 hits

        // Rule with enough hits
        for i in 0..5 {
            insert_rule_entry(
                &db,
                "pack:enough-hits",
                Outcome::Deny,
                now,
                &format!("deny-{i}"),
            );
        }
        for i in 0..5 {
            insert_rule_entry(
                &db,
                "pack:enough-hits",
                Outcome::Bypass,
                now,
                &format!("bypass-{i}"),
            );
        }

        let noisy = db.get_noisiest_rules(10).unwrap();

        // Only the rule with >= 5 hits should appear
        assert_eq!(noisy.len(), 1);
        assert_eq!(noisy[0].rule_id, "pack:enough-hits");
    }

    #[test]
    fn test_rule_metrics_first_and_last_seen() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();
        let earlier = now - Duration::days(5);
        let later = now - Duration::hours(1);

        insert_rule_entry(&db, "pack:time-test", Outcome::Deny, earlier, "first-cmd");
        insert_rule_entry(
            &db,
            "pack:time-test",
            Outcome::Deny,
            now - Duration::days(2),
            "middle-cmd",
        );
        insert_rule_entry(&db, "pack:time-test", Outcome::Deny, later, "last-cmd");

        let metrics = db.get_rule_metrics(None, 100).unwrap();
        assert_eq!(metrics.len(), 1);

        let m = &metrics[0];
        // First seen should be the earliest timestamp
        assert!(m.first_seen <= earlier + Duration::seconds(1));
        // Last seen should be the latest timestamp
        assert!(m.last_seen >= later - Duration::seconds(1));
    }

    #[test]
    fn test_rule_trend_stable_insufficient_data() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Only 3 hits - below MIN_HITS_FOR_TREND threshold
        for i in 0..3 {
            insert_rule_entry(&db, "pack:few", Outcome::Deny, now, &format!("cmd-{i}"));
        }

        let metrics = db.get_rule_metrics(None, 100).unwrap();
        assert_eq!(metrics[0].trend, RuleTrend::Stable);
    }

    #[test]
    fn test_rule_metrics_empty_database() {
        let db = HistoryDb::open_in_memory().unwrap();

        let metrics = db.get_rule_metrics(None, 100).unwrap();
        assert!(metrics.is_empty());

        let noisy = db.get_noisiest_rules(10).unwrap();
        assert!(noisy.is_empty());
    }

    #[test]
    fn test_rule_metrics_only_allow_outcomes_excluded() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Only allow outcomes (no rule_id typically set)
        let entry = CommandEntry {
            timestamp: now,
            agent_type: "test".to_string(),
            working_dir: "/test".to_string(),
            command: "git status".to_string(),
            outcome: Outcome::Allow,
            rule_id: None, // Allow typically has no rule_id
            ..Default::default()
        };
        db.log_command(&entry).unwrap();

        let metrics = db.get_rule_metrics(None, 100).unwrap();
        // Should be empty since we filter on rule_id IS NOT NULL
        assert!(metrics.is_empty());
    }

    #[test]
    fn test_rule_metrics_mixed_packs() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Multiple rules from different packs
        insert_rule_entry(&db, "core.git:reset-hard", Outcome::Deny, now, "git-1");
        insert_rule_entry(&db, "core.git:force-push", Outcome::Deny, now, "git-2");
        insert_rule_entry(&db, "core.filesystem:rm-rf", Outcome::Deny, now, "fs-1");
        insert_rule_entry(
            &db,
            "containers.docker:prune",
            Outcome::Deny,
            now,
            "docker-1",
        );
        insert_rule_entry(
            &db,
            "containers.docker:prune",
            Outcome::Deny,
            now,
            "docker-2",
        );

        let metrics = db.get_rule_metrics(None, 100).unwrap();
        assert_eq!(metrics.len(), 4);

        // Verify all packs represented
        let rule_ids: Vec<&str> = metrics.iter().map(|m| m.rule_id.as_str()).collect();
        assert!(rule_ids.contains(&"core.git:reset-hard"));
        assert!(rule_ids.contains(&"core.git:force-push"));
        assert!(rule_ids.contains(&"core.filesystem:rm-rf"));
        assert!(rule_ids.contains(&"containers.docker:prune"));
    }

    #[test]
    fn test_rule_metrics_contains_trending_fields() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Insert data for a rule with enough hits for trend calculation
        for i in 0..10 {
            let entry = CommandEntry {
                command: format!("git reset --hard HEAD~{i}"),
                outcome: Outcome::Deny,
                agent_type: "test".to_string(),
                working_dir: "/test".to_string(),
                pack_id: Some("core.git".to_string()),
                pattern_name: Some("reset-hard".to_string()),
                rule_id: Some("core.git:reset-hard".to_string()),
                timestamp: now - chrono::Duration::hours(i),
                ..Default::default()
            };
            db.log_command(&entry).unwrap();
        }

        let metrics = db.get_rule_metrics(None, 10).unwrap();
        assert_eq!(metrics.len(), 1);

        let m = &metrics[0];
        // Trending fields should be present and initialized
        // previous_period_hits is 0 since no data from 7-14 days ago
        assert_eq!(m.previous_period_hits, 0);
        // change_percentage and is_anomaly depend on previous data
        // With no previous period data, check they have reasonable defaults
        assert!(m.change_percentage.is_finite());
    }

    #[test]
    fn test_rule_metrics_change_percentage_with_trend_data() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Insert data from 10 days ago (previous period: 7-14 days)
        for i in 0..5 {
            let entry = CommandEntry {
                command: format!("git reset --hard HEAD~{i}"),
                outcome: Outcome::Deny,
                agent_type: "test".to_string(),
                working_dir: "/test".to_string(),
                pack_id: Some("core.git".to_string()),
                pattern_name: Some("reset-hard".to_string()),
                rule_id: Some("core.git:reset-hard".to_string()),
                timestamp: now - chrono::Duration::days(10) + chrono::Duration::hours(i64::from(i)),
                ..Default::default()
            };
            db.log_command(&entry).unwrap();
        }

        // Insert data from 3 days ago (recent period: 0-7 days)
        for i in 0..10 {
            let entry = CommandEntry {
                command: format!("git reset --hard HEAD~{i}"),
                outcome: Outcome::Deny,
                agent_type: "test".to_string(),
                working_dir: "/test".to_string(),
                pack_id: Some("core.git".to_string()),
                pattern_name: Some("reset-hard".to_string()),
                rule_id: Some("core.git:reset-hard".to_string()),
                timestamp: now - chrono::Duration::days(3) + chrono::Duration::hours(i64::from(i)),
                ..Default::default()
            };
            db.log_command(&entry).unwrap();
        }

        let metrics = db.get_rule_metrics(None, 10).unwrap();
        assert_eq!(metrics.len(), 1);

        let m = &metrics[0];
        // 5 hits in previous period, 10 in recent = 100% increase
        assert_eq!(m.previous_period_hits, 5);
        assert!((m.change_percentage - 100.0).abs() < 0.1);
        // 100% is not >= 200%, so not an anomaly
        assert!(!m.is_anomaly);
    }

    #[test]
    fn test_rule_metrics_anomaly_detection() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Insert 2 hits from 10 days ago (previous period)
        for i in 0..2 {
            let entry = CommandEntry {
                command: format!("git reset --hard HEAD~{i}"),
                outcome: Outcome::Deny,
                agent_type: "test".to_string(),
                working_dir: "/test".to_string(),
                pack_id: Some("core.git".to_string()),
                pattern_name: Some("reset-hard".to_string()),
                rule_id: Some("core.git:reset-hard".to_string()),
                timestamp: now - chrono::Duration::days(10) + chrono::Duration::hours(i64::from(i)),
                ..Default::default()
            };
            db.log_command(&entry).unwrap();
        }

        // Insert 10 hits from 3 days ago (recent period) - 400% increase
        for i in 0..10 {
            let entry = CommandEntry {
                command: format!("git reset --hard HEAD~{i}"),
                outcome: Outcome::Deny,
                agent_type: "test".to_string(),
                working_dir: "/test".to_string(),
                pack_id: Some("core.git".to_string()),
                pattern_name: Some("reset-hard".to_string()),
                rule_id: Some("core.git:reset-hard".to_string()),
                timestamp: now - chrono::Duration::days(3) + chrono::Duration::hours(i64::from(i)),
                ..Default::default()
            };
            db.log_command(&entry).unwrap();
        }

        let metrics = db.get_rule_metrics(None, 10).unwrap();
        let m = &metrics[0];

        // 2 hits previous, 10 recent = (10-2)/2 * 100 = 400% change
        assert_eq!(m.previous_period_hits, 2);
        assert!((m.change_percentage - 400.0).abs() < 0.1);
        // 400% >= 200% threshold, so is_anomaly should be true
        assert!(m.is_anomaly);
    }

    #[test]
    fn test_get_rule_metrics_for_rule_includes_trending_fields() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Insert enough data for a rule
        for i in 0..RuleMetrics::MIN_HITS_FOR_TREND {
            let entry = CommandEntry {
                command: format!("git reset --hard HEAD~{i}"),
                outcome: Outcome::Deny,
                agent_type: "test".to_string(),
                working_dir: "/test".to_string(),
                pack_id: Some("core.git".to_string()),
                pattern_name: Some("reset-hard".to_string()),
                rule_id: Some("core.git:reset-hard".to_string()),
                timestamp: now - chrono::Duration::hours(i64::try_from(i).unwrap_or(i64::MAX)),
                ..Default::default()
            };
            db.log_command(&entry).unwrap();
        }

        let m = db
            .get_rule_metrics_for_rule("core.git:reset-hard")
            .unwrap()
            .unwrap();

        // Verify trending fields are populated
        assert!(m.change_percentage.is_finite());
        // previous_period_hits should be 0 (no data 7-14 days ago)
        assert_eq!(m.previous_period_hits, 0);
    }

    #[test]
    fn test_get_noisiest_rules_includes_trending_fields() {
        let db = HistoryDb::open_in_memory().unwrap();
        let now = Utc::now();

        // Create a noisy rule with high bypass rate
        for i in 0..10 {
            let outcome = if i < 8 {
                Outcome::Bypass
            } else {
                Outcome::Deny
            };
            let entry = CommandEntry {
                command: format!("git clean -fdx {i}"),
                outcome,
                agent_type: "test".to_string(),
                working_dir: "/test".to_string(),
                pack_id: Some("core.git".to_string()),
                pattern_name: Some("clean-force".to_string()),
                rule_id: Some("core.git:clean-force".to_string()),
                timestamp: now - chrono::Duration::hours(i64::from(i)),
                ..Default::default()
            };
            db.log_command(&entry).unwrap();
        }

        let metrics = db.get_noisiest_rules(10).unwrap();
        assert_eq!(metrics.len(), 1);

        let m = &metrics[0];
        // Verify trending fields exist
        assert!(m.change_percentage.is_finite());
        assert_eq!(m.previous_period_hits, 0);
    }
}
