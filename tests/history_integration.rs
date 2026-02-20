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
use destructive_command_guard::history::{CommandEntry, HistoryDb, HistoryWriter, Outcome};
use fsqlite_types::value::SqliteValue;
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn sv_to_string(v: &SqliteValue) -> String {
    match v {
        SqliteValue::Text(s) => s.clone(),
        SqliteValue::Integer(i) => i.to_string(),
        SqliteValue::Float(f) => f.to_string(),
        SqliteValue::Null => String::new(),
        SqliteValue::Blob(_) => String::new(),
    }
}

fn sv_to_i64(v: &SqliteValue) -> i64 {
    match v {
        SqliteValue::Integer(i) => *i,
        SqliteValue::Float(f) => *f as i64,
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
    let test_db = TestDb::with_seed_data(&commands);

    assert_eq!(test_db.db.count_commands().unwrap(), 1000);
}

/// Test: FTS search works on seeded data
#[test]
fn test_fts_on_seeded_data() {
    init_test_logging();

    let test_db = TestDb::with_standard_mix();

    // Search for git commands
    let git_count: i64 = test_db
        .db
        .connection()
        .query_row("SELECT COUNT(*) FROM commands_fts WHERE command LIKE '%git%'")
        .map(|row| sv_to_i64(&row.values()[0]))
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

    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("concurrent_test.db");

    // fsqlite uses MVCC within a single connection; multi-connection file
    // writes are not supported.  Test that a single connection can handle
    // many interleaved writes from different "agent" contexts reliably.
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
    writer.flush_sync();

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
    writer.flush_sync();

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
    writer.flush_sync();

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
    writer.flush_sync();

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

    let start = Instant::now();
    for i in 0..1000 {
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

    writer.flush_sync();
    let reader = HistoryDb::open(Some(db_path)).expect("open reader");
    assert_eq!(reader.count_commands().unwrap(), 1000);
}
