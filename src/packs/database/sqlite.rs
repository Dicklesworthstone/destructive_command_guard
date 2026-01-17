//! `SQLite` patterns - protections against destructive sqlite3 commands.
//!
//! This includes patterns for:
//! - DROP TABLE/DATABASE commands
//! - DELETE without WHERE
//! - .quit without .backup

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `SQLite` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "database.sqlite".to_string(),
        name: "SQLite",
        description: "Protects against destructive SQLite operations like DROP TABLE, \
                      DELETE without WHERE, and accidental data loss",
        keywords: &["sqlite", "sqlite3", "DROP", "TRUNCATE", "DELETE"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // SELECT queries are safe
        safe_pattern!("select-query", r"(?i)^\s*SELECT\s+"),
        // .schema, .tables, .dump are read-only
        safe_pattern!("dot-schema", r"\.schema"),
        safe_pattern!("dot-tables", r"\.tables"),
        safe_pattern!("dot-dump", r"\.dump"),
        // .backup is safe (creates backup)
        safe_pattern!("dot-backup", r"\.backup"),
        // EXPLAIN is safe
        safe_pattern!("explain", r"(?i)^\s*EXPLAIN\s+"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // DROP TABLE
        destructive_pattern!(
            "drop-table",
            r"(?i)\bDROP\s+TABLE\b",
            "DROP TABLE permanently deletes the table (even with IF EXISTS). Verify it is intended."
        ),
        // DELETE without WHERE
        destructive_pattern!(
            "delete-without-where",
            r"(?i)DELETE\s+FROM\s+[a-zA-Z_][a-zA-Z0-9_]*\s*(?:;|$)",
            "DELETE without WHERE deletes ALL rows. Add a WHERE clause."
        ),
        // VACUUM INTO with existing file could overwrite
        destructive_pattern!(
            "vacuum-into",
            r"(?i)VACUUM\s+INTO\s+",
            "VACUUM INTO overwrites the target file if it exists."
        ),
        // sqlite3 < file.sql can run arbitrary commands
        destructive_pattern!(
            "sqlite3-stdin",
            r"sqlite3\s+[^\s]+\s+<\s+",
            "Running SQL from file could contain destructive commands. Review the file first."
        ),
    ]
}
