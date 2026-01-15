//! Integration test: full history pipeline (log -> query -> fts).

mod common;

use chrono::Utc;
use common::db::TestDb;
use common::logging::init_test_logging;
use destructive_command_guard::history::{CommandEntry, Outcome};

#[test]
fn test_full_history_pipeline() {
    init_test_logging();

    let test_db = TestDb::new();
    let entry = CommandEntry {
        timestamp: Utc::now(),
        agent_type: "claude_code".to_string(),
        working_dir: "/test".to_string(),
        command: "git status".to_string(),
        outcome: Outcome::Allow,
        eval_duration_us: 150,
        ..Default::default()
    };

    let id = test_db.db.log_command(&entry).expect("log command");
    assert!(id > 0, "expected positive row id");

    let count = test_db.db.count_commands().expect("count commands");
    assert_eq!(count, 1);

    let (stored_command, stored_outcome): (String, String) = test_db
        .db
        .connection()
        .query_row(
            "SELECT command, outcome FROM commands WHERE id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("query stored command");

    assert_eq!(stored_command, "git status");
    assert_eq!(stored_outcome, "allow");

    let fts_count: i64 = test_db
        .db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM commands_fts WHERE commands_fts MATCH 'git'",
            [],
            |row| row.get(0),
        )
        .expect("fts query");
    assert_eq!(fts_count, 1);
}
