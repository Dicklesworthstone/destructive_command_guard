//! `PostgreSQL` patterns - protections against destructive psql/pg commands.
//!
//! This includes patterns for:
//! - DROP DATABASE/TABLE/SCHEMA commands
//! - TRUNCATE commands
//! - dropdb CLI command
//! - `pg_dump` with --clean flag

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `PostgreSQL` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "database.postgresql".to_string(),
        name: "PostgreSQL",
        description: "Protects against destructive PostgreSQL operations like DROP DATABASE, \
                      TRUNCATE, and dropdb",
        keywords: &[
            "psql", "dropdb", "DROP", "TRUNCATE", "pg_dump", "postgres", "DELETE", "delete",
            "drop", "truncate",
        ],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // pg_dump without --clean is safe (backup only)
        safe_pattern!("pg-dump-no-clean", r"pg_dump\s+(?!.*--clean)(?!.*-c\b)"),
        // psql with --dry-run or explain
        safe_pattern!("psql-dry-run", r"psql\s+.*--dry-run"),
        // SELECT queries are safe
        safe_pattern!("select-query", r"(?i)^\s*SELECT\s+"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // DROP DATABASE
        destructive_pattern!(
            "drop-database",
            r"(?i)\bDROP\s+DATABASE\b",
            "DROP DATABASE permanently deletes the entire database (even with IF EXISTS). Verify and back up first."
        ),
        // DROP TABLE
        destructive_pattern!(
            "drop-table",
            r"(?i)\bDROP\s+TABLE\b",
            "DROP TABLE permanently deletes the table (even with IF EXISTS). Verify and back up first."
        ),
        // DROP SCHEMA
        destructive_pattern!(
            "drop-schema",
            r"(?i)\bDROP\s+SCHEMA\b",
            "DROP SCHEMA permanently deletes the schema and all its objects (even with IF EXISTS)."
        ),
        // TRUNCATE (faster than DELETE, no rollback)
        destructive_pattern!(
            "truncate-table",
            r"(?i)TRUNCATE\s+(?:TABLE\s+)?[a-zA-Z_]",
            "TRUNCATE permanently deletes all rows without logging individual deletions."
        ),
        // DELETE without WHERE (deletes all rows)
        destructive_pattern!(
            "delete-without-where",
            r#"(?i)DELETE\s+FROM\s+(?:(?:[a-zA-Z_][a-zA-Z0-9_]*|"[^"]+")(?:\.(?:[a-zA-Z_][a-zA-Z0-9_]*|"[^"]+"))?)\s*(?:;|$)"#,
            "DELETE without WHERE clause deletes ALL rows. Add a WHERE clause or use TRUNCATE intentionally."
        ),
        // dropdb CLI command
        destructive_pattern!(
            "dropdb-cli",
            r"dropdb\s+",
            "dropdb permanently deletes the entire database. Verify the database name carefully."
        ),
        // pg_dump with --clean (drops before creating)
        destructive_pattern!(
            "pg-dump-clean",
            r"pg_dump\s+.*(?:--clean|-c\b)",
            "pg_dump --clean drops objects before creating them. This can be destructive on restore."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::*;

    #[test]
    fn test_delete_without_where() {
        let pack = create_pack();
        assert_blocks(&pack, "DELETE FROM users;", "DELETE without WHERE");
        assert_blocks(&pack, "DELETE FROM public.users;", "DELETE without WHERE");
        assert_blocks(&pack, "DELETE FROM \"Users\";", "DELETE without WHERE");
        assert_blocks(
            &pack,
            "DELETE FROM \"Public\".\"Users\";",
            "DELETE without WHERE",
        );
        assert_blocks(&pack, "delete from users", "DELETE without WHERE");

        // Should NOT block if WHERE clause is present
        assert_allows(&pack, "DELETE FROM users WHERE id = 1;");
        assert_allows(&pack, "DELETE FROM users WHERE active = false");
    }
}
