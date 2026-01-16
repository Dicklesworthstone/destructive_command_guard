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
             psql -c '\\l' | grep dbname"
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
             SELECT * FROM tablename LIMIT 10;"
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
             pg_dump -n schema_name dbname > schema_backup.sql"
        ),
        // TRUNCATE (faster than DELETE, no rollback)
        destructive_pattern!(
            "truncate-table",
            r"(?i)TRUNCATE\s+(?:TABLE\s+)?[a-zA-Z_]",
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
             SELECT COUNT(*) FROM tablename;"
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
             SELECT * FROM tablename LIMIT 10;"
        ),
        // dropdb CLI command
        destructive_pattern!(
            "dropdb-cli",
            r"dropdb\s+",
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
             psql -c '\\l'"
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
             pg_dump dbname > backup.sql  # Creates only, no drops"
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
