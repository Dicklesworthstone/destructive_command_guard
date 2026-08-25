//! `PostgreSQL` patterns - protections against destructive psql/pg commands.
//!
//! This includes patterns for:
//! - DROP DATABASE/TABLE/SCHEMA commands
//! - TRUNCATE commands
//! - dropdb CLI command
//! - `pg_dump` with --clean flag

use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};
use crate::{destructive_pattern, safe_pattern};

// ============================================================================
// Suggestion constants (must be 'static for the pattern struct)
// ============================================================================

/// Suggestions for `DROP DATABASE` pattern.
const DROP_DATABASE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "pg_dump -h {host} -U {user} {dbname} > backup.sql",
        "Create a full backup before dropping",
    ),
    PatternSuggestion::new(
        "psql -c '\\l' | grep {dbname}",
        "Verify database name before dropping",
    ),
    PatternSuggestion::new(
        "SELECT datname FROM pg_database WHERE datname = '{dbname}'",
        "Check if database exists",
    ),
];

/// Suggestions for `DROP TABLE` pattern.
const DROP_TABLE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "pg_dump -t {tablename} {dbname} > table_backup.sql",
        "Backup the table before dropping",
    ),
    PatternSuggestion::new(
        "SELECT COUNT(*) FROM {tablename}",
        "Check row count before dropping",
    ),
    PatternSuggestion::new("\\d {tablename}", "Review table structure (in psql)"),
    PatternSuggestion::new(
        "SELECT * FROM {tablename} LIMIT 10",
        "Preview table contents",
    ),
];

/// Suggestions for `DROP SCHEMA` pattern.
const DROP_SCHEMA_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "pg_dump -n {schema_name} {dbname} > schema_backup.sql",
        "Backup schema before dropping",
    ),
    PatternSuggestion::new(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = '{schema_name}'",
        "List all tables in the schema",
    ),
    PatternSuggestion::gated(
        "DROP SCHEMA {schema_name} RESTRICT",
        "RESTRICT fails if the schema is not empty — still a DROP, so it is gated as well",
    ),
];

/// Suggestions for `TRUNCATE TABLE` pattern.
const TRUNCATE_TABLE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "SELECT COUNT(*) FROM {tablename}",
        "Check how many rows would be deleted",
    ),
    PatternSuggestion::gated(
        "BEGIN; TRUNCATE {tablename}; -- ROLLBACK or COMMIT",
        "Wrap in a transaction for rollback capability — the TRUNCATE inside is gated as well",
    ),
    PatternSuggestion::new(
        "CREATE TABLE {tablename}_backup AS SELECT * FROM {tablename}",
        "Backup data before truncating",
    ),
];

/// Suggestions for `DELETE without WHERE` pattern.
const DELETE_WITHOUT_WHERE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "DELETE FROM {tablename} WHERE {condition}",
        "Add a WHERE clause to limit deletion",
    ),
    PatternSuggestion::new(
        "SELECT COUNT(*) FROM {tablename}",
        "Check how many rows exist",
    ),
    PatternSuggestion::gated(
        "TRUNCATE TABLE {tablename}",
        "Faster if you truly want all rows gone — but TRUNCATE is gated as well",
    ),
    PatternSuggestion::gated(
        "BEGIN; DELETE FROM {tablename}; -- ROLLBACK or COMMIT",
        "Wrap in a transaction for rollback capability — the unfiltered DELETE is gated as well",
    ),
];

/// Suggestions for `dropdb` CLI pattern.
const DROPDB_CLI_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "pg_dump -h {host} -U {user} {dbname} > backup.sql",
        "Create a full backup before dropping",
    ),
    PatternSuggestion::new("psql -c '\\l'", "List databases to verify the correct one"),
    PatternSuggestion::new(
        "psql -c 'SELECT pg_database_size(''{dbname}'') / 1024 / 1024 AS size_mb'",
        "Check database size before dropping",
    ),
];

/// Suggestions for `pg_dump --clean` pattern.
const PG_DUMP_CLEAN_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "pg_dump {dbname} > backup.sql",
        "Create backup without DROP statements",
    ),
    PatternSuggestion::new(
        "createdb {newdb} && pg_restore -d {newdb} backup.dump",
        "Restore to a new database first, then verify",
    ),
];

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
        // SELECT queries are safe
        safe_pattern!("select-query", r"(?i)^\s*SELECT\s+"),
    ]
}

#[allow(clippy::too_many_lines)]
fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "stdin-unverified",
            r"(?!)",
            "psql receives indirect input that dcg cannot statically verify.",
            High,
            "Materialize and review the exact SQL before piping or redirecting it into psql."
        ),
        // DROP DATABASE
        destructive_pattern!(
            "drop-database",
            r"(?i)\bDROP\s+DATABASE\b",
            "DROP DATABASE permanently deletes the entire database (even with IF EXISTS). Verify and back up first.",
            Critical,
            "DROP DATABASE completely removes a database and ALL its contents:\n\n\
             - All tables, views, and indexes\n\
             - All functions, procedures, and triggers\n\
             - All data - gone permanently\n\
             - Users/roles remain but lose access\n\n\
             IF EXISTS only prevents errors if the database doesn't exist - it still deletes!\n\n\
             Before dropping:\n  \
             pg_dump -h host -U user dbname > backup.sql\n\n\
             Verify database name:\n  \
             psql -c '\\l' | grep dbname",
            DROP_DATABASE_SUGGESTIONS
        ),
        // DROP TABLE
        destructive_pattern!(
            "drop-table",
            r"(?i)\bDROP\s+TABLE\b",
            "DROP TABLE permanently deletes the table (even with IF EXISTS). Verify and back up first.",
            High,
            "DROP TABLE removes the table structure and ALL data:\n\n\
             - All rows are deleted\n\
             - Indexes, constraints, triggers are removed\n\
             - Foreign keys referencing this table may fail\n\
             - CASCADE drops dependent objects too\n\n\
             IF EXISTS only prevents errors - it still drops the table!\n\n\
             Backup table first:\n  \
             pg_dump -t tablename dbname > table_backup.sql\n\n\
             Preview table contents:\n  \
             SELECT COUNT(*) FROM tablename;\n  \
             SELECT * FROM tablename LIMIT 10;",
            DROP_TABLE_SUGGESTIONS
        ),
        // DROP SCHEMA
        destructive_pattern!(
            "drop-schema",
            r"(?i)\bDROP\s+SCHEMA\b",
            "DROP SCHEMA permanently deletes the schema and all its objects (even with IF EXISTS).",
            Critical,
            "DROP SCHEMA removes a schema and potentially ALL objects within it:\n\n\
             - With CASCADE: Drops all tables, views, functions in the schema\n\
             - With RESTRICT (default): Fails if schema is not empty\n\
             - public schema deletion is catastrophic\n\n\
             List schema contents first:\n  \
             SELECT table_name FROM information_schema.tables \n  \
             WHERE table_schema = 'schema_name';\n\n\
             Backup schema:\n  \
             pg_dump -n schema_name dbname > schema_backup.sql",
            DROP_SCHEMA_SUGGESTIONS
        ),
        // TRUNCATE (faster than DELETE, no rollback)
        destructive_pattern!(
            "truncate-table",
            r"(?i)\bTRUNCATE\s+(?:TABLE\s+)?[a-zA-Z_]",
            "TRUNCATE permanently deletes all rows without logging individual deletions.",
            High,
            "TRUNCATE is faster than DELETE but more dangerous:\n\n\
             - Removes ALL rows instantly\n\
             - Cannot be rolled back outside a transaction\n\
             - Does not fire DELETE triggers\n\
             - Resets IDENTITY/SERIAL columns\n\
             - CASCADE truncates referencing tables too\n\n\
             TRUNCATE is transactional in PostgreSQL. Wrap in transaction:\n  \
             BEGIN;\n  \
             TRUNCATE tablename;\n  \
             -- verify, then COMMIT or ROLLBACK\n\n\
             Check row count first:\n  \
             SELECT COUNT(*) FROM tablename;",
            TRUNCATE_TABLE_SUGGESTIONS
        ),
        // DELETE without WHERE (deletes all rows)
        destructive_pattern!(
            "delete-without-where",
            r#"(?i)DELETE\s+FROM\s+(?:(?:[a-zA-Z_][a-zA-Z0-9_]*|"[^"]+")(?:\.(?:[a-zA-Z_][a-zA-Z0-9_]*|"[^"]+"))?)\s*(?:;|$)"#,
            "DELETE without WHERE clause deletes ALL rows. Add a WHERE clause or use TRUNCATE intentionally.",
            High,
            "DELETE without WHERE removes ALL rows from the table:\n\n\
             - Each row deletion is logged (slower than TRUNCATE)\n\
             - Can be rolled back within a transaction\n\
             - Fires DELETE triggers for each row\n\
             - Does not reset IDENTITY/SERIAL counters\n\n\
             If you meant to delete all rows, use TRUNCATE for speed.\n\
             Otherwise, add a WHERE clause:\n  \
             DELETE FROM tablename WHERE condition;\n\n\
             Preview what would be deleted:\n  \
             SELECT COUNT(*) FROM tablename;  -- all rows!\n  \
             SELECT * FROM tablename LIMIT 10;",
            DELETE_WITHOUT_WHERE_SUGGESTIONS
        ),
        // dropdb CLI command
        destructive_pattern!(
            "dropdb-cli",
            r"\bdropdb\s+",
            "dropdb permanently deletes the entire database. Verify the database name carefully.",
            Critical,
            "dropdb is the CLI equivalent of DROP DATABASE:\n\n\
             - Completely removes the database\n\
             - All data is lost permanently\n\
             - No confirmation prompt by default\n\
             - Cannot be undone\n\n\
             Triple-check the database name. Common mistake:\n  \
             dropdb myapp_production  # Oops, meant myapp_staging\n\n\
             Backup first:\n  \
             pg_dump -h host -U user dbname > backup.sql\n\n\
             List databases to verify:\n  \
             psql -c '\\l'",
            DROPDB_CLI_SUGGESTIONS
        ),
        // pg_dump with --clean (drops before creating)
        destructive_pattern!(
            "pg-dump-clean",
            r"pg_dump\s+.*(?:--clean|-c\b)",
            "pg_dump --clean drops objects before creating them. This can be destructive on restore.",
            High,
            "pg_dump --clean adds DROP statements to the backup file. On restore:\n\n\
             - DROP TABLE is run before CREATE TABLE\n\
             - Existing data is deleted before restore\n\
             - If restore fails partway, data may be lost\n\n\
             This is safe for backup, but dangerous when restoring to a database \
             with existing data you want to keep.\n\n\
             Safer approach for restoring:\n\
             - Restore to a new database first\n\
             - Verify the restore\n\
             - Then swap databases\n\n\
             Without --clean:\n  \
             pg_dump dbname > backup.sql  # Creates only, no drops",
            PG_DUMP_CLEAN_SUGGESTIONS
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
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

        assert_allows(&pack, "DELETE FROM users WHERE id = 1;");
        assert_allows(&pack, "DELETE FROM users WHERE active = false");
    }

    #[test]
    fn postgresql_blocks_each_destructive_pattern() {
        let pack = create_pack();
        assert_blocks(&pack, "DROP DATABASE mydb", "DROP DATABASE");
        assert_blocks(&pack, "DROP DATABASE IF EXISTS mydb", "DROP DATABASE");
        assert_blocks(&pack, "DROP TABLE users", "DROP TABLE");
        assert_blocks(&pack, "DROP TABLE IF EXISTS users CASCADE", "DROP TABLE");
        assert_blocks(&pack, "DROP SCHEMA public CASCADE", "DROP SCHEMA");
        assert_blocks(&pack, "TRUNCATE TABLE users", "TRUNCATE");
        assert_blocks(&pack, "TRUNCATE users", "TRUNCATE");
        assert_blocks(&pack, "dropdb mydb", "dropdb");
        assert_blocks(&pack, "pg_dump --clean mydb", "pg_dump --clean");
        assert_blocks(&pack, "pg_dump -c mydb", "pg_dump --clean");
    }

    #[test]
    fn postgresql_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "DROP DATABASE mydb", Severity::Critical);
        assert_blocks_with_severity(&pack, "DROP TABLE users", Severity::High);
        assert_blocks_with_severity(&pack, "DROP SCHEMA public", Severity::Critical);
        assert_blocks_with_severity(&pack, "TRUNCATE TABLE users", Severity::High);
        assert_blocks_with_severity(&pack, "DELETE FROM users;", Severity::High);
        assert_blocks_with_severity(&pack, "dropdb mydb", Severity::Critical);
        assert_blocks_with_severity(&pack, "pg_dump --clean mydb", Severity::High);
    }

    #[test]
    fn postgresql_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "pg_dump mydb > backup.sql");
        assert_safe_pattern_matches(&pack, "SELECT * FROM users;");
        assert_safe_pattern_matches(&pack, "SELECT COUNT(*) FROM orders;");
    }

    #[test]
    fn psql_dry_run_text_does_not_bypass_destructive_sql() {
        let pack = create_pack();
        assert_no_safe_match(&pack, "psql -c 'DROP TABLE users; --dry-run'");
        assert_blocks_with_pattern(&pack, "psql -c 'DROP TABLE users; --dry-run'", "drop-table");
        assert_no_safe_match(&pack, "psql --dry-run -c 'DROP TABLE users'");
        assert_blocks_with_pattern(&pack, "psql --dry-run -c 'DROP TABLE users'", "drop-table");
        assert_no_safe_match(&pack, "psql -c 'TRUNCATE users; --dry-run'");
        assert_blocks_with_pattern(
            &pack,
            "psql -c 'TRUNCATE users; --dry-run'",
            "truncate-table",
        );
    }

    #[test]
    fn postgresql_case_insensitive() {
        let pack = create_pack();
        assert_blocks(&pack, "drop database mydb", "DROP DATABASE");
        assert_blocks(&pack, "drop table users", "DROP TABLE");
        assert_blocks(&pack, "truncate table users", "TRUNCATE");
    }

    #[test]
    fn postgresql_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "git status");
    }

    #[test]
    fn truncate_pattern_requires_word_boundary() {
        // Regression: `truncate-table` regex previously had no `\b` anchor,
        // so any word ENDING in `TRUNCATE` (e.g. `MYTRUNCATE TABLE foo`)
        // matched and caused false-positive blocks. With the keywords list
        // including `TRUNCATE`, commands like
        //   echo "MYTRUNCATE TABLE foo described in the docs"
        // would block.
        let pack = create_pack();
        assert_no_match(&pack, "echo \"MYTRUNCATE TABLE foo described in the docs\"");
        assert_no_match(&pack, "echo NEEDSTRUNCATE TABLE later");
        assert_no_match(&pack, "ls myTRUNCATE-table-script.sh");
        // Real TRUNCATE still blocks.
        assert_blocks(&pack, "TRUNCATE TABLE users", "TRUNCATE");
        assert_blocks(&pack, "psql -c 'TRUNCATE users'", "TRUNCATE");
    }

    #[test]
    fn dropdb_pattern_requires_word_boundary() {
        // Regression: `dropdb-cli` regex previously was `dropdb\s+`, so any
        // word ending in `dropdb` (e.g. `superdropdb mydb` or
        // `cat mydropdb-readme`) matched. With the keywords list including
        // `dropdb`, even `cat superdropdb-script.sh` would be processed
        // by this pack and `superdropdb foo` would block.
        let pack = create_pack();
        assert_no_match(&pack, "echo superdropdb mydb");
        assert_no_match(&pack, "ls mydropdb-readme.md");
        assert_no_match(&pack, "echo \"my_dropdb_alias mydb\"");
        // Real dropdb still blocks.
        assert_blocks(&pack, "dropdb mydb", "dropdb");
        assert_blocks(&pack, "/usr/bin/dropdb mydb", "dropdb");
    }
}
