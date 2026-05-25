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
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // The previous `\.schema`, `\.tables`, `\.dump`, `\.backup` patterns matched
    // those substrings anywhere in the command. That let a compound command like
    //   sqlite3 mydb "DROP TABLE foo; .dump"
    // short-circuit as safe (because `.dump` is present) and never reach the
    // destructive `DROP TABLE` check. Dropped in favor of anchored variants.
    vec![
        // SELECT queries are safe
        safe_pattern!("select-query", r"(?i)^\s*SELECT\s+"),
        // sqlite3 invoked with a dot-command as the SQL argument (quoted).
        // Require a quote boundary immediately before the dot-command so embedded
        // `.dump` inside a longer statement cannot whitelist it.
        safe_pattern!(
            "sqlite3-dot-command",
            r#"sqlite3\b[^|;&]*['"]\s*\.(?:schema|tables|dump|backup|help)\b[^'"]*['"]?\s*$"#
        ),
        // Bare dot-command on its own line (sqlite3 REPL input captured as-is).
        safe_pattern!(
            "dot-command-standalone",
            r"^\s*\.(?:schema|tables|dump|backup|help)\b"
        ),
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
            "DROP TABLE permanently deletes the table (even with IF EXISTS). Verify it is intended.",
            Critical,
            "DROP TABLE permanently removes a table and all its data from the SQLite database. \
             Unlike some other databases, SQLite has no recycle bin or undo mechanism. The IF \
             EXISTS clause only prevents errors, it doesn't make the operation less destructive.\n\n\
             Safer alternatives:\n\
             - .schema tablename: View table structure first\n\
             - .dump tablename: Export table data as SQL backup\n\
             - .backup: Create full database backup before dropping\n\
             - ALTER TABLE ... RENAME: Rename instead of drop if reorganizing"
        ),
        // DELETE without WHERE
        destructive_pattern!(
            "delete-without-where",
            r"(?i)DELETE\s+FROM\s+[a-zA-Z_][a-zA-Z0-9_]*\s*(?:;|$)",
            "DELETE without WHERE deletes ALL rows. Add a WHERE clause.",
            Critical,
            "DELETE FROM without a WHERE clause removes every row from the table. This is \
             almost always unintentional - if you truly want to remove all rows, TRUNCATE or \
             DROP TABLE + CREATE is more explicit about the intent. SQLite doesn't support \
             TRUNCATE, making this pattern especially dangerous.\n\n\
             Safer alternatives:\n\
             - SELECT COUNT(*) FROM table: Check row count first\n\
             - DELETE FROM table WHERE condition: Add explicit conditions\n\
             - .backup before DELETE: Create backup first\n\
             - Use transactions: BEGIN; DELETE ...; verify; COMMIT or ROLLBACK"
        ),
        // VACUUM INTO with existing file could overwrite
        destructive_pattern!(
            "vacuum-into",
            r"(?i)VACUUM\s+INTO\s+",
            "VACUUM INTO overwrites the target file if it exists.",
            Medium,
            "VACUUM INTO creates a new compacted copy of the database at the specified path. \
             If a file already exists at that path, it will be overwritten without warning. \
             This can accidentally destroy other databases or important files.\n\n\
             Safer alternatives:\n\
             - Check if target file exists before running\n\
             - Use a unique filename with timestamp\n\
             - .backup filename: Alternative backup method\n\
             - Move existing file before VACUUM INTO"
        ),
        // sqlite3 < file.sql can run arbitrary commands
        destructive_pattern!(
            "sqlite3-stdin",
            r"sqlite3\s+[^\s]+\s+<\s+",
            "Running SQL from file could contain destructive commands. Review the file first.",
            High,
            "Piping SQL from a file into sqlite3 executes all commands without review. The \
             file may contain DROP TABLE, DELETE, or other destructive statements. If the \
             file comes from an untrusted source or was auto-generated, it could cause \
             unintended data loss.\n\n\
             Safer alternatives:\n\
             - Review the SQL file contents first\n\
             - .backup before running: Create database backup\n\
             - .read filename inside sqlite3: Allows Ctrl+C interruption\n\
             - Run in a transaction: Wrap file contents in BEGIN/COMMIT"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();
        assert_eq!(pack.id, "database.sqlite");
        assert_patterns_compile(&pack);
    }

    #[test]
    fn compound_command_dot_command_does_not_bypass_drop() {
        let pack = create_pack();
        let m = pack
            .check("sqlite3 mydb \"DROP TABLE foo; .dump\"")
            .expect("DROP TABLE in a compound with .dump must still block");
        assert_eq!(m.name, Some("drop-table"));

        let m = pack
            .check("sqlite3 mydb \"DELETE FROM users; .schema\"")
            .expect("DELETE FROM in a compound with .schema must still block");
        assert_eq!(m.name, Some("delete-without-where"));
    }

    #[test]
    fn standalone_dot_commands_remain_safe() {
        let pack = create_pack();
        assert!(
            pack.matches_safe(".schema users"),
            "bare .schema is still safe"
        );
        assert!(
            pack.matches_safe("sqlite3 mydb '.dump'"),
            "sqlite3 '.dump' is still safe"
        );
        assert!(
            pack.matches_safe("sqlite3 mydb \".schema users\""),
            "sqlite3 \".schema users\" is still safe"
        );
    }

    #[test]
    fn sqlite_blocks_each_destructive_pattern() {
        let pack = create_pack();
        assert_blocks(&pack, "DROP TABLE users", "DROP TABLE");
        assert_blocks(&pack, "DROP TABLE IF EXISTS users", "DROP TABLE");
        assert_blocks(&pack, "DELETE FROM users;", "DELETE without WHERE");
        assert_blocks(&pack, "DELETE FROM users", "DELETE without WHERE");
        assert_blocks(&pack, "sqlite3 mydb < init.sql", "SQL from file");
    }

    #[test]
    fn sqlite_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "DROP TABLE users", Severity::Critical);
        assert_blocks_with_severity(&pack, "DELETE FROM users;", Severity::Critical);
        assert_blocks_with_severity(&pack, "sqlite3 mydb < init.sql", Severity::High);
    }

    #[test]
    fn sqlite_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "SELECT * FROM users;");
        assert_safe_pattern_matches(&pack, ".schema users");
        assert_safe_pattern_matches(&pack, ".tables");
        assert_safe_pattern_matches(&pack, "EXPLAIN SELECT * FROM users;");
    }

    #[test]
    fn sqlite_delete_with_where_is_allowed() {
        let pack = create_pack();
        assert_allows(&pack, "DELETE FROM users WHERE id = 1;");
        assert_allows(&pack, "DELETE FROM users WHERE active = false");
    }

    #[test]
    fn sqlite_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "git status");
    }
}
