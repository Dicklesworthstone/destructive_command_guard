//! Integration test: full history pipeline (log -> query -> fts).

mod common;

use chrono::Utc;
use common::db::TestDb;
use common::logging::init_test_logging;
use dcg_cli::history::{CommandEntry, Outcome};
use fsqlite_types::value::SqliteValue;

fn sv_to_string(v: &SqliteValue) -> String {
    match v {
        SqliteValue::Text(s) => s.to_string(),
        SqliteValue::Integer(i) => i.to_string(),
        SqliteValue::Float(f) => f.to_string(),
        SqliteValue::Null => String::new(),
        SqliteValue::Blob(_) => String::new(),
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

    let fts_count = test_db
        .db
        .connection()
        .query("SELECT rowid FROM commands_fts WHERE command LIKE '%git%'")
        .map(|rows| rows.len())
        .expect("fts query");
    assert_eq!(fts_count, 1);
}
