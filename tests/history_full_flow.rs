//! Integration test: full history pipeline (log -> query -> fts).

mod common;

use chrono::Utc;
use common::db::TestDb;
use common::logging::init_test_logging;
use destructive_command_guard::history::{CommandEntry, Outcome};
use fsqlite_types::value::SqliteValue;

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

    let row = test_db
        .db
        .connection()
        .query_row_with_params(
            "SELECT command, outcome FROM commands WHERE id = ?1",
            &[SqliteValue::Integer(id)],
        )
        .expect("query stored command");
    let vals = row.values();
    let (stored_command, stored_outcome) = (sv_to_string(&vals[0]), sv_to_string(&vals[1]));

    assert_eq!(stored_command, "git status");
    assert_eq!(stored_outcome, "allow");

    let fts_count: i64 = test_db
        .db
        .connection()
        .query_row("SELECT COUNT(*) FROM commands_fts WHERE command LIKE '%git%'")
        .map(|row| sv_to_i64(&row.values()[0]))
        .expect("fts query");
    assert_eq!(fts_count, 1);
}
