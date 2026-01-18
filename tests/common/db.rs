//! Test database factory for history tests.
//!
//! Provides isolated test databases that are automatically cleaned up.
//!
//! # Features
//!
//! - Each `TestDb` gets its own temp directory
//! - Automatic cleanup on drop
//! - Thread-safe unique naming via atomic counter
//! - Seed data support for pre-populating tests

use chrono::{DateTime, Duration, Utc};
use destructive_command_guard::history::{CommandEntry, HistoryDb, Outcome};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use tempfile::TempDir;

/// Atomic counter for unique test database naming.
static TEST_DB_COUNTER: AtomicU32 = AtomicU32::new(0);

/// An isolated test database with automatic cleanup.
///
/// The database is created in a temporary directory that is automatically
/// removed when the `TestDb` is dropped. This ensures test isolation and
/// prevents disk space accumulation from failed tests.
///
/// # Example
///
/// ```ignore
/// let test_db = TestDb::new();
/// test_db.db.log_command(&entry)?;
/// // temp directory cleaned up automatically when test_db goes out of scope
/// ```
pub struct TestDb {
    /// The history database handle.
    pub db: HistoryDb,
    /// Path to the database file.
    pub path: PathBuf,
    /// Temporary directory (dropped = deleted).
    _temp_dir: TempDir,
}

impl TestDb {
    /// Create a new isolated test database.
    ///
    /// Each call creates a unique database in a fresh temp directory.
    ///
    /// # Panics
    ///
    /// Panics if the temp directory or database cannot be created.
    #[must_use]
    pub fn new() -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp directory for TestDb");
        let id = TEST_DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = temp_dir.path().join(format!("test_history_{id}.db"));

        let db =
            HistoryDb::open(Some(path.clone())).expect("Failed to create test history database");

        Self {
            db,
            path,
            _temp_dir: temp_dir,
        }
    }

    /// Create a test database pre-populated with seed data.
    ///
    /// # Arguments
    ///
    /// * `commands` - Slice of `TestCommand` entries to insert
    ///
    /// # Panics
    ///
    /// Panics if database creation or seed insertion fails.
    #[must_use]
    pub fn with_seed_data(commands: &[TestCommand]) -> Self {
        let test_db = Self::new();
        let now = Utc::now();

        for cmd in commands {
            let entry = cmd.to_entry(now);
            test_db
                .db
                .log_command(&entry)
                .expect("Failed to seed test command");
        }

        test_db
    }

    /// Create a test database with a standard mix of commands.
    ///
    /// Includes a variety of outcomes, agent types, and patterns for
    /// comprehensive testing.
    #[must_use]
    pub fn with_standard_mix() -> Self {
        Self::with_seed_data(&super::fixtures::standard_mix())
    }

    /// Create an in-memory test database (no file on disk).
    ///
    /// Faster than file-based but cannot test file operations.
    #[must_use]
    pub fn in_memory() -> HistoryDb {
        HistoryDb::open_in_memory().expect("Failed to create in-memory test database")
    }
}

impl Default for TestDb {
    fn default() -> Self {
        Self::new()
    }
}

/// A test command specification for seeding databases.
///
/// Uses relative timestamps (offsets from "now") for reproducible tests
/// that don't depend on absolute times.
#[derive(Debug, Clone)]
pub struct TestCommand {
    /// The command string.
    pub command: &'static str,
    /// Evaluation outcome.
    pub outcome: Outcome,
    /// Agent type (e.g., "`claude_code`", "codex").
    pub agent_type: &'static str,
    /// Working directory path.
    pub working_dir: &'static str,
    /// Timestamp offset from "now" in seconds (negative = past).
    pub timestamp_offset_secs: i64,
    /// Optional pack ID that matched.
    pub pack_id: Option<&'static str>,
    /// Optional pattern name that matched.
    pub pattern_name: Option<&'static str>,
    /// Optional rule ID (format: `pack_id:pattern_name`).
    pub rule_id: Option<&'static str>,
    /// Evaluation duration in microseconds.
    pub eval_duration_us: u64,
}

impl Default for TestCommand {
    fn default() -> Self {
        Self {
            command: "echo 'test'",
            outcome: Outcome::Allow,
            agent_type: "claude_code",
            working_dir: "/data/projects/test",
            timestamp_offset_secs: 0,
            pack_id: None,
            pattern_name: None,
            rule_id: None,
            eval_duration_us: 100,
        }
    }
}

impl TestCommand {
    /// Convert to a `CommandEntry` with the given base time.
    #[must_use]
    pub fn to_entry(&self, base_time: DateTime<Utc>) -> CommandEntry {
        let timestamp = if self.timestamp_offset_secs >= 0 {
            base_time + Duration::seconds(self.timestamp_offset_secs)
        } else {
            base_time - Duration::seconds(-self.timestamp_offset_secs)
        };

        CommandEntry {
            timestamp,
            agent_type: self.agent_type.to_string(),
            working_dir: self.working_dir.to_string(),
            command: self.command.to_string(),
            outcome: self.outcome,
            pack_id: self.pack_id.map(ToString::to_string),
            pattern_name: self.pattern_name.map(ToString::to_string),
            rule_id: self.rule_id.map(ToString::to_string),
            eval_duration_us: self.eval_duration_us,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_creates_unique_paths() {
        let db1 = TestDb::new();
        let db2 = TestDb::new();
        assert_ne!(db1.path, db2.path);
    }

    #[test]
    fn test_db_can_write_and_read() {
        let test_db = TestDb::new();
        let entry = CommandEntry {
            command: "git status".to_string(),
            outcome: Outcome::Allow,
            agent_type: "test".to_string(),
            working_dir: "/test".to_string(),
            ..Default::default()
        };

        let id = test_db.db.log_command(&entry).unwrap();
        assert!(id > 0);
        assert_eq!(test_db.db.count_commands().unwrap(), 1);
    }

    #[test]
    fn test_db_with_seed_data() {
        let commands = vec![
            TestCommand {
                command: "git status",
                outcome: Outcome::Allow,
                ..Default::default()
            },
            TestCommand {
                command: "git push --force",
                outcome: Outcome::Deny,
                pack_id: Some("core.git"),
                pattern_name: Some("force-push"),
                ..Default::default()
            },
        ];

        let test_db = TestDb::with_seed_data(&commands);
        assert_eq!(test_db.db.count_commands().unwrap(), 2);
    }

    #[test]
    fn test_command_timestamp_offset() {
        let now = Utc::now();

        let past = TestCommand {
            timestamp_offset_secs: -3600,
            ..Default::default()
        };
        let entry = past.to_entry(now);
        assert!(entry.timestamp < now);

        let future = TestCommand {
            timestamp_offset_secs: 3600,
            ..Default::default()
        };
        let entry = future.to_entry(now);
        assert!(entry.timestamp > now);
    }

    #[test]
    fn test_standard_mix_creates_db() {
        let test_db = TestDb::with_standard_mix();
        assert!(test_db.db.count_commands().unwrap() > 0);
    }

    #[test]
    fn test_in_memory_db() {
        let db = TestDb::in_memory();
        assert_eq!(db.count_commands().unwrap(), 0);
    }
}
