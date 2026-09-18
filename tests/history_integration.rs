//! Integration tests for the history system.
//!
//! These tests verify the full history pipeline from command logging
//! to querying, ensuring all components work together correctly.
//!
//! # Running
//!
//! ```bash
//! cargo test --test history_integration
//! ```

mod common;

use chrono::Utc;
use common::db::TestDb;
use common::fixtures;
use common::logging::init_test_logging;
use destructive_command_guard::config::{HistoryConfig, HistoryRedactionMode};
use destructive_command_guard::history::{
    CommandEntry, HistoryDb, HistoryWriter, Outcome, SqliteValue,
};
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// Wait for normal writer shutdown, including closing its SQLite connection.
///
/// This is a persistence-test barrier, not a hook-latency assertion. Waiting
/// only for a short flush acknowledgement conflates host scheduling with data
/// loss, and opening a reader before shutdown can race WAL close handling.
/// The generous watchdog keeps a genuinely stuck worker from hanging the suite.
/// An acknowledgement is NOT proof of persistence: every caller must still
/// assert the exact stored rows/content, since best-effort writes can be dropped.
fn finish_history_writer(writer: HistoryWriter, context: &str) {
    const WATCHDOG: Duration = Duration::from_secs(30);
    let started = Instant::now();
    let (completed_tx, completed_rx) = std::sync::mpsc::sync_channel(1);
    let _waiter = std::thread::Builder::new()
        .name("history-test-shutdown".to_string())
        .spawn(move || {
            drop(writer);
            let _ = completed_tx.send(());
        })
        .expect("spawn history shutdown waiter");

    match completed_rx.recv_timeout(WATCHDOG) {
        Ok(()) => {}
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!(
            "{context}: history flush/shutdown did not complete within {WATCHDOG:?} \
             ({:?} elapsed); the worker may be stalled or the host overloaded; \
             persistence has not yet been checked",
            started.elapsed()
        ),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => panic!(
            "{context}: history shutdown waiter disconnected after {:?}; \
             this is not a successful flush",
            started.elapsed()
        ),
    }
}

fn sv_to_string(v: &SqliteValue) -> String {
    match v {
        SqliteValue::Text(s) => s.clone(),
        SqliteValue::Integer(i) => i.to_string(),
        SqliteValue::Real(f) => f.to_string(),
        SqliteValue::Null => String::new(),
        SqliteValue::Blob(_) => String::new(),
    }
}

fn sv_to_i64(v: &SqliteValue) -> i64 {
    match v {
        SqliteValue::Integer(i) => *i,
        SqliteValue::Real(f) => *f as i64,
        SqliteValue::Text(s) => s.parse().unwrap_or(0),
        _ => 0,
    }
}

fn sv_to_opt_string(v: &SqliteValue) -> Option<String> {
    match v {
        SqliteValue::Text(s) => Some(s.clone()),
        SqliteValue::Null => None,
        SqliteValue::Integer(i) => Some(i.to_string()),
        _ => None,
    }
}

/// Test: Full history pipeline - log -> query cycle
#[test]
fn test_full_history_pipeline() {
    init_test_logging();

    let test_db = TestDb::new();

    // Log a command
    let entry = CommandEntry {
        timestamp: Utc::now(),
        agent_type: "claude_code".to_string(),
        working_dir: "/data/projects/test".to_string(),
        command: "git status".to_string(),
        outcome: Outcome::Allow,
        eval_duration_us: 150,
        ..Default::default()
    };

    let id = test_db.db.log_command(&entry).unwrap();
    assert!(id > 0, "Command ID should be positive");

    // Verify command was logged
    let count = test_db.db.count_commands().unwrap();
    assert_eq!(count, 1, "Should have exactly 1 command");
}

/// Test: Multiple commands maintain correct ordering
#[test]
fn test_command_ordering() {
    init_test_logging();

    let test_db = TestDb::new();
    let now = Utc::now();

    // Log commands with specific timestamps
    for i in 0..10 {
        let offset = chrono::Duration::seconds(i * 60);
        let entry = CommandEntry {
            timestamp: now + offset,
            command: format!("command_{i}"),
            ..Default::default()
        };
        test_db.db.log_command(&entry).unwrap();
    }

    assert_eq!(test_db.db.count_commands().unwrap(), 10);

    // Verify via raw query that timestamps are in order
    let query_rows = test_db
        .db
        .connection()
        .query("SELECT command FROM commands ORDER BY timestamp ASC")
        .unwrap();
    let rows: Vec<String> = query_rows
        .iter()
        .map(|row| sv_to_string(&row.values()[0]))
        .collect();

    for (i, cmd) in rows.iter().enumerate() {
        assert_eq!(cmd, &format!("command_{i}"));
    }
}

/// Test: Standard mix fixture creates valid database
#[test]
fn test_standard_mix_fixture() {
    init_test_logging();

    let test_db = TestDb::with_standard_mix();

    let count = test_db.db.count_commands().unwrap();
    assert!(count > 0, "Standard mix should have commands");

    // Verify we have multiple outcomes
    let query_rows = test_db
        .db
        .connection()
        .query("SELECT DISTINCT outcome FROM commands")
        .unwrap();
    assert!(query_rows.len() >= 2, "Should have multiple outcome types");
}

/// Test: Large dataset performance
#[test]
fn test_large_dataset_insertion() {
    init_test_logging();

    let commands = fixtures::large_dataset(1000);
    let test_db = TestDb::in_memory();
    let now = Utc::now();
    for cmd in &commands {
        let entry = cmd.to_entry(now);
        test_db.log_command(&entry).unwrap();
    }

    assert_eq!(test_db.count_commands().unwrap(), 1000);
}

/// Test: FTS search works on seeded data
#[test]
fn test_fts_on_seeded_data() {
    init_test_logging();

    let test_db = TestDb::with_standard_mix();

    // Search for git commands
    let git_count = test_db
        .db
        .connection()
        .query("SELECT rowid FROM commands_fts WHERE command LIKE '%git%'")
        .map(|rows| rows.len())
        .unwrap();

    assert!(git_count > 0, "Should find git commands via FTS");
}

/// Test: Outcome distribution queries work correctly
#[test]
fn test_outcome_distribution_queries() {
    init_test_logging();

    let commands = fixtures::outcome_distribution();
    let test_db = TestDb::with_seed_data(&commands);

    // Query outcome distribution
    let allow_count: i64 = test_db
        .db
        .connection()
        .query_row("SELECT COUNT(*) FROM commands WHERE outcome = 'allow'")
        .map(|row| sv_to_i64(&row.values()[0]))
        .unwrap();

    let deny_count: i64 = test_db
        .db
        .connection()
        .query_row("SELECT COUNT(*) FROM commands WHERE outcome = 'deny'")
        .map(|row| sv_to_i64(&row.values()[0]))
        .unwrap();

    assert_eq!(allow_count, 70, "Should have 70 allows");
    assert_eq!(deny_count, 20, "Should have 20 denies");
}

/// Test: Pack analysis queries
#[test]
fn test_pack_analysis_queries() {
    init_test_logging();

    let test_db = TestDb::with_standard_mix();

    // Count commands by pack
    let query_rows = test_db
        .db
        .connection()
        .query("SELECT pack_id, COUNT(*) as cnt FROM commands GROUP BY pack_id ORDER BY cnt DESC")
        .unwrap();
    let pack_counts: Vec<(Option<String>, i64)> = query_rows
        .iter()
        .map(|row| {
            let v = row.values();
            (sv_to_opt_string(&v[0]), sv_to_i64(&v[1]))
        })
        .collect();

    assert!(!pack_counts.is_empty(), "Should have pack counts");

    // Verify we have both NULL (safe commands) and non-NULL (blocked) packs
    let null_count = pack_counts.iter().filter(|(p, _)| p.is_none()).count();
    let non_null_count = pack_counts.iter().filter(|(p, _)| p.is_some()).count();

    assert!(null_count > 0, "Should have commands with no pack (safe)");
    assert!(
        non_null_count > 0,
        "Should have commands with pack (blocked)"
    );
}

/// Test: Working directory filtering
#[test]
fn test_working_dir_filtering() {
    init_test_logging();

    let test_db = TestDb::with_standard_mix();

    // Count distinct working directories
    let dir_count: i64 = test_db
        .db
        .connection()
        .query_row("SELECT COUNT(DISTINCT working_dir) FROM commands")
        .map(|row| sv_to_i64(&row.values()[0]))
        .unwrap();

    assert!(dir_count > 0, "Should have working directories");
}

/// Test: Agent type tracking
#[test]
fn test_agent_type_tracking() {
    init_test_logging();

    let test_db = TestDb::with_standard_mix();

    // Count commands by agent type
    let query_rows = test_db
        .db
        .connection()
        .query("SELECT agent_type, COUNT(*) FROM commands GROUP BY agent_type")
        .unwrap();
    let agent_counts: Vec<(String, i64)> = query_rows
        .iter()
        .map(|row| {
            let v = row.values();
            (sv_to_string(&v[0]), sv_to_i64(&v[1]))
        })
        .collect();

    assert!(!agent_counts.is_empty(), "Should track agent types");

    // Standard mix includes multiple agent types
    assert!(
        agent_counts
            .iter()
            .map(|(a, _)| a.as_str())
            .any(|agent| agent == "claude_code"),
        "Should have claude_code agent"
    );
}

/// Test: Database file persistence
#[test]
fn test_database_persistence() {
    init_test_logging();

    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("persistent_test.db");

    // Create and populate
    {
        let db = HistoryDb::open(Some(db_path.clone())).unwrap();
        for i in 0..5 {
            db.log_command(&CommandEntry {
                command: format!("persist_cmd_{i}"),
                ..Default::default()
            })
            .unwrap();
        }
        assert_eq!(db.count_commands().unwrap(), 5);
    }

    // Reopen and verify
    {
        let db = HistoryDb::open(Some(db_path)).unwrap();
        assert_eq!(db.count_commands().unwrap(), 5);
    }
}

/// Test: In-memory database for fast tests
#[test]
fn test_in_memory_operations() {
    init_test_logging();

    let db = TestDb::in_memory();

    for i in 0..100 {
        db.log_command(&CommandEntry {
            command: format!("mem_cmd_{i}"),
            ..Default::default()
        })
        .unwrap();
    }

    assert_eq!(db.count_commands().unwrap(), 100);
}

/// Test: Command hash is deterministic
#[test]
fn test_command_hash_stored() {
    init_test_logging();

    let test_db = TestDb::new();

    let entry = CommandEntry {
        command: "deterministic_command".to_string(),
        ..Default::default()
    };
    let expected_hash = entry.command_hash();

    test_db.db.log_command(&entry).unwrap();

    let stored_hash: String = test_db
        .db
        .connection()
        .query_row("SELECT command_hash FROM commands WHERE command = 'deterministic_command'")
        .map(|row| sv_to_string(&row.values()[0]))
        .unwrap();

    assert_eq!(stored_hash, expected_hash);
}

/// Test: Concurrent writes (basic thread safety)
#[test]
fn test_concurrent_writes() {
    init_test_logging();

    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("concurrent_test.db");

    // Test that a single connection can handle many interleaved writes from
    // different "agent" contexts reliably.
    let db = HistoryDb::open(Some(db_path.clone())).unwrap();

    // Initial seed entry
    db.log_command(&CommandEntry {
        command: "init".to_string(),
        ..Default::default()
    })
    .unwrap();

    // Simulate 4 agent streams writing 25 commands each
    for thread_id in 0..4u32 {
        for i in 0..25u32 {
            let entry = CommandEntry {
                command: format!("thread_{thread_id}_cmd_{i}"),
                agent_type: format!("thread_{thread_id}"),
                ..Default::default()
            };
            db.log_command(&entry)
                .unwrap_or_else(|e| panic!("log_command failed: {e:?}"));
        }
    }

    let count = db.count_commands().unwrap();

    // 1 init + 4 agents * 25 commands = 101
    assert_eq!(count, 101, "All writes should succeed");
}

#[test]
fn concurrent_opens_and_inserts_keep_fts_exactly_synchronized() {
    init_test_logging();

    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("concurrent_fts.db");
    HistoryDb::open(Some(db_path.clone())).expect("initialize history schema");

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let successes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut workers = Vec::new();
    for worker_id in 0..8 {
        let db_path = db_path.clone();
        let barrier = barrier.clone();
        let successes = successes.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            let Ok(db) = HistoryDb::open(Some(db_path)) else {
                return;
            };
            for entry_id in 0..20 {
                if db
                    .log_command(&CommandEntry {
                        command: format!("concurrent-fts-{worker_id}-{entry_id}"),
                        ..Default::default()
                    })
                    .is_ok()
                {
                    successes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }));
    }
    for worker in workers {
        worker.join().expect("history worker panicked");
    }

    let connection = rusqlite::Connection::open(&db_path).expect("open stock SQLite");
    let commands: i64 = connection
        .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))
        .expect("command count");
    let fts: i64 = connection
        .query_row("SELECT COUNT(*) FROM commands_fts", [], |row| row.get(0))
        .expect("FTS count");
    assert!(successes.load(std::sync::atomic::Ordering::Relaxed) > 0);
    assert_eq!(
        commands, fts,
        "every committed command must have an FTS row"
    );
}

#[test]
fn locked_history_database_never_delays_writer_drop_past_hook_budget() {
    init_test_logging();

    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("locked_history.db");
    HistoryDb::open(Some(db_path.clone())).expect("initialize history schema");
    let locker = rusqlite::Connection::open(&db_path).expect("open lock connection");
    locker
        .execute_batch("BEGIN IMMEDIATE")
        .expect("hold SQLite writer lock");

    let config = HistoryConfig {
        enabled: true,
        redaction_mode: HistoryRedactionMode::None,
        batch_size: 1,
        ..Default::default()
    };
    let started = Instant::now();
    let writer = HistoryWriter::new(Some(db_path), &config);
    writer.log(CommandEntry {
        command: "history lock contention probe".to_string(),
        ..Default::default()
    });
    writer.flush_sync();
    drop(writer);
    let elapsed = started.elapsed();

    locker
        .execute_batch("ROLLBACK")
        .expect("release writer lock");
    assert!(
        elapsed < Duration::from_millis(200),
        "best-effort history delayed hook completion by {elapsed:?}"
    );
}

/// A flush acknowledgement means processed, not persisted. Contention must
/// remain best-effort, and a dropped entry must never be replayed by a later
/// flush. Persistence tests therefore still need exact row/content assertions.
#[test]
fn acknowledged_busy_history_entry_is_dropped_not_replayed() {
    init_test_logging();

    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("acknowledged_busy_history.db");
    let config = HistoryConfig {
        enabled: true,
        redaction_mode: HistoryRedactionMode::None,
        batch_size: 1,
        ..Default::default()
    };
    let writer = HistoryWriter::new(Some(db_path.clone()), &config);
    assert!(
        writer.flush_sync_with_timeout(Duration::from_secs(30)),
        "history initialization did not acknowledge within the test watchdog"
    );

    let locker = rusqlite::Connection::open(&db_path).expect("open lock connection");
    locker
        .execute_batch("BEGIN IMMEDIATE")
        .expect("hold writer lock");
    writer.log(CommandEntry {
        command: "dropped while busy".to_string(),
        ..Default::default()
    });
    let acknowledged = writer.flush_sync_with_timeout(Duration::from_secs(30));
    // Release the lock before asserting, including on a failed acknowledgement.
    locker
        .execute_batch("ROLLBACK")
        .expect("release writer lock");
    assert!(
        acknowledged,
        "busy entry was not processed within the test watchdog"
    );

    writer.log(CommandEntry {
        command: "persisted after unlock".to_string(),
        ..Default::default()
    });
    drop(locker);
    finish_history_writer(writer, "busy-entry recovery");

    let reader = HistoryDb::open(Some(db_path)).expect("open reader");
    let rows = reader
        .connection()
        .query("SELECT command FROM commands ORDER BY id")
        .expect("query persisted entries");
    assert_eq!(rows.len(), 1, "only the post-contention entry may persist");
    assert_eq!(sv_to_string(&rows[0].values()[0]), "persisted after unlock");
}

/// Test: VACUUM operation
#[test]
fn test_vacuum_operation() {
    init_test_logging();

    let test_db = TestDb::new();

    // Add some data
    for i in 0..10 {
        test_db
            .db
            .log_command(&CommandEntry {
                command: format!("vacuum_test_{i}"),
                ..Default::default()
            })
            .unwrap();
    }

    // VACUUM should not error
    test_db.db.vacuum().unwrap();

    // Data should still be there
    assert_eq!(test_db.db.count_commands().unwrap(), 10);
}

#[test]
fn test_history_writer_logs_allow() {
    init_test_logging();

    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("history_writer_allow.db");

    let config = HistoryConfig {
        enabled: true,
        redaction_mode: HistoryRedactionMode::None,
        ..Default::default()
    };
    let writer = HistoryWriter::new(Some(db_path.clone()), &config);

    writer.log(CommandEntry {
        timestamp: Utc::now(),
        agent_type: "claude_code".to_string(),
        working_dir: "/tmp".to_string(),
        command: "git status".to_string(),
        outcome: Outcome::Allow,
        ..Default::default()
    });
    finish_history_writer(writer, "allow entry");

    let reader = HistoryDb::open(Some(db_path)).expect("open reader");
    assert_eq!(reader.count_commands().unwrap(), 1);
}

#[test]
fn test_history_writer_respects_disabled() {
    init_test_logging();

    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("history_writer_disabled.db");

    let config = HistoryConfig {
        enabled: false,
        ..Default::default()
    };
    let writer = HistoryWriter::new(Some(db_path.clone()), &config);

    writer.log(CommandEntry {
        timestamp: Utc::now(),
        agent_type: "claude_code".to_string(),
        working_dir: "/tmp".to_string(),
        command: "git status".to_string(),
        outcome: Outcome::Allow,
        ..Default::default()
    });
    finish_history_writer(writer, "disabled history writer");
    assert!(!db_path.exists(), "disabled writer must not create storage");

    let reader = HistoryDb::open(Some(db_path)).expect("open reader");
    assert_eq!(reader.count_commands().unwrap(), 0);
}

#[test]
fn test_history_writer_full_redaction() {
    init_test_logging();

    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("history_writer_redaction.db");

    let config = HistoryConfig {
        enabled: true,
        redaction_mode: HistoryRedactionMode::Full,
        ..Default::default()
    };
    let writer = HistoryWriter::new(Some(db_path.clone()), &config);

    writer.log(CommandEntry {
        timestamp: Utc::now(),
        agent_type: "claude_code".to_string(),
        working_dir: "/tmp".to_string(),
        command: "curl -H 'Bearer secret'".to_string(),
        outcome: Outcome::Allow,
        ..Default::default()
    });
    finish_history_writer(writer, "redacted entry");

    let reader = HistoryDb::open(Some(db_path)).expect("open reader");
    let stored: String = reader
        .connection()
        .query_row("SELECT command FROM commands LIMIT 1")
        .map(|row| sv_to_string(&row.values()[0]))
        .unwrap();
    assert_eq!(stored, "[REDACTED]");
}

#[test]
fn test_history_writer_logs_deny_with_match_info() {
    init_test_logging();

    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("history_writer_deny.db");

    let config = HistoryConfig {
        enabled: true,
        redaction_mode: HistoryRedactionMode::None,
        ..Default::default()
    };
    let writer = HistoryWriter::new(Some(db_path.clone()), &config);

    writer.log(CommandEntry {
        timestamp: Utc::now(),
        agent_type: "claude_code".to_string(),
        working_dir: "/tmp".to_string(),
        command: "git reset --hard".to_string(),
        outcome: Outcome::Deny,
        pack_id: Some("core.git".to_string()),
        pattern_name: Some("reset-hard".to_string()),
        ..Default::default()
    });
    finish_history_writer(writer, "deny entry");

    let reader = HistoryDb::open(Some(db_path)).expect("open reader");
    let row = reader
        .connection()
        .query_row("SELECT outcome, pack_id, pattern_name FROM commands LIMIT 1")
        .unwrap();
    let vals = row.values();
    let stored = (
        sv_to_string(&vals[0]),
        sv_to_string(&vals[1]),
        sv_to_string(&vals[2]),
    );
    assert_eq!(stored.0, "deny");
    assert_eq!(stored.1, "core.git");
    assert_eq!(stored.2, "reset-hard");
}

#[test]
fn test_history_writer_flushes_on_drop() {
    init_test_logging();

    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("history_writer_drop.db");

    let config = HistoryConfig {
        enabled: true,
        redaction_mode: HistoryRedactionMode::None,
        ..Default::default()
    };

    {
        let writer = HistoryWriter::new(Some(db_path.clone()), &config);
        writer.log(CommandEntry {
            timestamp: Utc::now(),
            agent_type: "claude_code".to_string(),
            working_dir: "/tmp".to_string(),
            command: "git status".to_string(),
            outcome: Outcome::Allow,
            ..Default::default()
        });
    }

    let reader = HistoryDb::open(Some(db_path)).expect("open reader");
    assert_eq!(reader.count_commands().unwrap(), 1);
}

#[test]
fn test_history_writer_async_performance() {
    init_test_logging();

    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("history_writer_perf.db");

    let config = HistoryConfig {
        enabled: true,
        redaction_mode: HistoryRedactionMode::None,
        ..Default::default()
    };
    let writer = HistoryWriter::new(Some(db_path.clone()), &config);

    // Exercise asynchronous batching without making the integration test
    // disproportionately expensive on constrained CI workers.
    let entry_count = 200;

    let start = Instant::now();
    for i in 0..entry_count {
        writer.log(CommandEntry {
            timestamp: Utc::now(),
            agent_type: "claude_code".to_string(),
            working_dir: "/tmp".to_string(),
            command: format!("command_{i}"),
            outcome: Outcome::Allow,
            ..Default::default()
        });
    }
    let elapsed = start.elapsed();

    // Keep this generous to avoid CI variance while ensuring async path is fast.
    assert!(
        elapsed < Duration::from_secs(2),
        "Logging too slow: {elapsed:?}"
    );

    finish_history_writer(writer, "async batch");
    let reader = HistoryDb::open(Some(db_path)).expect("open reader");
    assert_eq!(reader.count_commands().unwrap(), entry_count);
}

#[test]
fn fresh_history_survives_repeated_hook_style_reopens_with_stock_integrity() {
    init_test_logging();

    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("repeated_hook_writes.db");
    let config = HistoryConfig {
        enabled: true,
        redaction_mode: HistoryRedactionMode::None,
        batch_size: 1,
        ..Default::default()
    };

    for index in 0..50 {
        let writer = HistoryWriter::new(Some(db_path.clone()), &config);
        writer.log(CommandEntry {
            timestamp: Utc::now(),
            agent_type: "claude_code".to_string(),
            working_dir: "/tmp".to_string(),
            command: format!("echo probe-{index}"),
            outcome: Outcome::Allow,
            ..Default::default()
        });
        finish_history_writer(writer, &format!("reopen probe {index}"));
    }

    let stock = rusqlite::Connection::open(&db_path).expect("open with stock SQLite");
    let integrity: String = stock
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .expect("stock integrity_check");
    let commands: i64 = stock
        .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))
        .expect("command count");
    let fts: i64 = stock
        .query_row("SELECT COUNT(*) FROM commands_fts", [], |row| row.get(0))
        .expect("FTS count");
    let page_count: i64 = stock
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .expect("page count");
    let freelist_count: i64 = stock
        .query_row("PRAGMA freelist_count", [], |row| row.get(0))
        .expect("freelist count");

    assert_eq!(integrity, "ok");
    assert_eq!(commands, 50);
    assert_eq!(fts, commands);
    assert!(
        freelist_count <= page_count / 4,
        "fresh repeated writes leaked disproportionate free pages: {freelist_count}/{page_count}"
    );
    // Migration must not retain the legacy fsqlite namespace sidecars.
    for suffix in ["-fsqlite-ns-gate", "-fsqlite-ns-use"] {
        assert!(
            !std::path::PathBuf::from(format!("{}{suffix}", db_path.display())).exists(),
            "history backend created legacy namespace sidecar {suffix}"
        );
    }
}

#[test]
fn history_max_size_mb_is_a_hard_main_database_cap() {
    init_test_logging();

    const MAX_SIZE_BYTES: u64 = 1024 * 1024;
    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("size_limited.db");
    let config = HistoryConfig {
        enabled: true,
        redaction_mode: HistoryRedactionMode::None,
        max_size_mb: 1,
        batch_size: 1,
        ..Default::default()
    };
    let writer = HistoryWriter::new(Some(db_path.clone()), &config);
    let payload = "x".repeat(64 * 1024);

    for index in 0..100 {
        writer.log(CommandEntry {
            timestamp: Utc::now(),
            agent_type: "claude_code".to_string(),
            working_dir: "/tmp".to_string(),
            command: format!("{index}:{payload}"),
            outcome: Outcome::Allow,
            ..Default::default()
        });
    }
    finish_history_writer(writer, "size-cap batch");

    let main_size = std::fs::metadata(&db_path).expect("history metadata").len();
    assert!(
        main_size <= MAX_SIZE_BYTES,
        "max_size_mb was exceeded: {main_size} > {MAX_SIZE_BYTES}"
    );

    let stock = rusqlite::Connection::open(&db_path).expect("open capped history");
    let integrity: String = stock
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .expect("integrity_check");
    let commands: i64 = stock
        .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))
        .expect("command count");
    assert_eq!(integrity, "ok");
    assert!(
        commands > 0 && commands < 100,
        "the cap should retain committed rows and reject later growth: {commands}"
    );
}

#[test]
fn configured_direct_history_writes_share_the_hard_size_cap() {
    init_test_logging();

    const MAX_SIZE_BYTES: u64 = 1024 * 1024;
    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("direct_size_limited.db");
    let db = HistoryDb::open_with_max_size(Some(db_path.clone()), 1)
        .expect("open configured capped history");
    let payload = "x".repeat(64 * 1024);
    let mut successes = 0;
    let mut failures = 0;

    for index in 0..100 {
        match db.log_command(&CommandEntry {
            timestamp: Utc::now(),
            agent_type: "cli".to_string(),
            working_dir: "/tmp".to_string(),
            command: format!("{index}:{payload}"),
            outcome: Outcome::Allow,
            ..Default::default()
        }) {
            Ok(_) => successes += 1,
            Err(_) => failures += 1,
        }
    }
    db.checkpoint_truncate().expect("checkpoint capped history");

    let main_size = std::fs::metadata(&db_path).expect("history metadata").len();
    assert!(
        main_size <= MAX_SIZE_BYTES,
        "configured direct writes exceeded max_size_mb: {main_size} > {MAX_SIZE_BYTES}"
    );
    assert!(
        successes > 0 && failures > 0,
        "the cap must retain early writes and reject later growth: {successes} successes, {failures} failures"
    );
    assert_eq!(
        db.count_commands().expect("command count"),
        u64::try_from(successes).expect("success count fits u64")
    );
}
