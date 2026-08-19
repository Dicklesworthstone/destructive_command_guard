//! `MySQL`/`MariaDB` patterns - protections against destructive mysql commands.
//!
//! This includes patterns for:
//! - DROP DATABASE/TABLE commands
//! - TRUNCATE commands
//! - DELETE without WHERE
//! - mysqladmin drop
//! - mysqldump with destructive flags

use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};
use crate::{destructive_pattern, safe_pattern};

// ============================================================================
// Suggestion constants (must be 'static for the pattern struct)
// ============================================================================

/// Suggestions for `DROP DATABASE` pattern.
const DROP_DATABASE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "mysqldump -h {host} -u {user} -p {dbname} > backup.sql",
        "Create a full backup before dropping",
    ),
    PatternSuggestion::new(
        "SHOW DATABASES LIKE '{dbname}'",
        "Verify database name before dropping",
    ),
    PatternSuggestion::new(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = '{dbname}'",
        "List all tables in the database",
    ),
];

/// Suggestions for `DROP TABLE` pattern.
const DROP_TABLE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "mysqldump -h {host} -u {user} -p {dbname} {tablename} > table_backup.sql",
        "Backup the table before dropping",
    ),
    PatternSuggestion::new(
        "SELECT COUNT(*) FROM {tablename}",
        "Check row count before dropping",
    ),
    PatternSuggestion::new(
        "DESCRIBE {tablename}",
        "Review table structure before dropping",
    ),
    PatternSuggestion::new(
        "SELECT * FROM {tablename} LIMIT 10",
        "Preview table contents",
    ),
];

/// Suggestions for `TRUNCATE TABLE` pattern.
const TRUNCATE_TABLE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "SELECT COUNT(*) FROM {tablename}",
        "Check how many rows would be deleted",
    ),
    PatternSuggestion::new(
        "CREATE TABLE {tablename}_backup AS SELECT * FROM {tablename}",
        "Backup data to temporary table before truncating",
    ),
    PatternSuggestion::gated(
        "DELETE FROM {tablename}",
        "Transactional, recoverable deletion — but an unfiltered DELETE is gated as well",
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
        "Check how many rows exist before deletion",
    ),
    PatternSuggestion::gated(
        "TRUNCATE TABLE {tablename}",
        "Faster if you truly want all rows gone — but TRUNCATE is gated as well",
    ),
    PatternSuggestion::new(
        "SELECT * FROM {tablename} LIMIT 10",
        "Preview table contents before deletion",
    ),
];

/// Suggestions for `mysqladmin drop` pattern.
const MYSQLADMIN_DROP_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "mysqldump -h {host} -u {user} -p {dbname} > backup.sql",
        "Create a full backup before dropping",
    ),
    PatternSuggestion::new(
        "mysql -e 'SHOW DATABASES'",
        "List databases to verify the correct one",
    ),
    PatternSuggestion::new(
        "mysql -e 'USE {dbname}; SHOW TABLES'",
        "Review tables in the database",
    ),
];

/// Suggestions for `mysqldump --add-drop-database` pattern.
const MYSQLDUMP_ADD_DROP_DATABASE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "mysqldump {dbname} > backup.sql",
        "Create backup without DROP DATABASE statement",
    ),
    PatternSuggestion::new(
        "mysql -e 'CREATE DATABASE {newdb}' && mysql {newdb} < backup.sql",
        "Restore to a new database first, then verify",
    ),
];

/// Suggestions for `mysqldump --add-drop-table` pattern.
const MYSQLDUMP_ADD_DROP_TABLE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "mysqldump --skip-add-drop-table {dbname} > backup.sql",
        "Create backup without DROP TABLE statements",
    ),
    PatternSuggestion::new(
        "mysqldump {dbname} > backup.sql",
        "Default dump includes DROP TABLE (use --skip-add-drop-table to disable)",
    ),
];

/// Suggestions for `GRANT ALL ON *.*` pattern.
const GRANT_ALL_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "GRANT ALL ON {specific_db}.* TO '{user}'@'{host}'",
        "Limit privileges to a specific database",
    ),
    PatternSuggestion::new(
        "GRANT SELECT, INSERT, UPDATE ON {db}.* TO '{user}'@'{host}'",
        "Grant only needed privileges",
    ),
    PatternSuggestion::new(
        "SHOW GRANTS FOR '{user}'@'{host}'",
        "Review current grants before adding more",
    ),
];

/// Suggestions for `DROP USER` pattern.
const DROP_USER_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "SHOW GRANTS FOR '{user}'@'{host}'",
        "Document privileges before dropping",
    ),
    PatternSuggestion::new(
        "ALTER USER '{user}'@'{host}' ACCOUNT LOCK",
        "Disable account instead of dropping",
    ),
    PatternSuggestion::new(
        "SELECT * FROM mysql.user WHERE user='{username}'",
        "Verify user exists and check details",
    ),
];

/// Suggestions for `RESET MASTER` pattern.
const RESET_MASTER_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "PURGE BINARY LOGS BEFORE '{date}'",
        "Selectively purge old logs instead of all",
    ),
    PatternSuggestion::new("SHOW BINARY LOGS", "List current binary logs before reset"),
    PatternSuggestion::new(
        "SHOW SLAVE STATUS",
        "Check replica status before resetting master",
    ),
];

/// Create the `MySQL`/`MariaDB` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "database.mysql".to_string(),
        name: "MySQL/MariaDB",
        description: "Protects against destructive MySQL/MariaDB operations like DROP DATABASE, \
                      TRUNCATE, and mysqladmin drop",
        keywords: &[
            "mysql",
            "mysqladmin",
            "mysqldump",
            "mariadb",
            "DROP",
            "TRUNCATE",
            "DELETE",
            "delete",
            "drop",
            "truncate",
            "GRANT",
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
        // SELECT queries are safe
        safe_pattern!("select-query", r"(?i)^\s*SELECT\s+"),
        // SHOW commands are safe (read-only)
        safe_pattern!("show-command", r"(?i)^\s*SHOW\s+"),
        // DESCRIBE/DESC/EXPLAIN are safe
        safe_pattern!("describe-query", r"(?i)^\s*(?:DESCRIBE|DESC|EXPLAIN)\s+"),
        // mysqldump without --add-drop is safe (backup only)
        safe_pattern!(
            "mysqldump-no-drop",
            r"mysqldump\s+(?!.*--add-drop-database)(?!.*--add-drop-table)"
        ),
        // mysql with --execute for SELECT only
        safe_pattern!(
            "mysql-select",
            r#"mysql\s+.*(?:-e|--execute)\s*['"]?\s*SELECT"#
        ),
    ]
}

#[allow(clippy::too_many_lines)]
fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "stdin-unverified",
            r"(?!)",
            "mysql/mariadb receives indirect input that dcg cannot statically verify.",
            High,
            "Materialize and review the exact SQL before piping or redirecting it into the client."
        ),
        // DROP DATABASE
        destructive_pattern!(
            "drop-database",
            r"(?i)\bDROP\s+DATABASE\b",
            "DROP DATABASE permanently deletes the entire database. Verify and back up first.",
            Critical,
            "DROP DATABASE completely removes a database and ALL its contents:\n\n\
             - All tables, views, and indexes\n\
             - All stored procedures and functions\n\
             - All triggers and events\n\
             - All data - gone permanently\n\
             - User privileges on the database remain but are orphaned\n\n\
             IF EXISTS only prevents errors if the database doesn't exist - it still deletes!\n\n\
             Before dropping:\n  \
             mysqldump -h host -u user -p dbname > backup.sql\n\n\
             Verify database name:\n  \
             SHOW DATABASES LIKE 'dbname';",
            DROP_DATABASE_SUGGESTIONS
        ),
        // DROP TABLE
        destructive_pattern!(
            "drop-table",
            r"(?i)\bDROP\s+TABLE\b",
            "DROP TABLE permanently deletes the table. Verify and back up first.",
            High,
            "DROP TABLE removes the table structure and ALL data:\n\n\
             - All rows are permanently deleted\n\
             - Indexes and constraints are removed\n\
             - Foreign key relationships may break\n\
             - Triggers on the table are dropped\n\
             - AUTO_INCREMENT values are lost\n\n\
             IF EXISTS only prevents errors - it still drops the table!\n\n\
             Backup table first:\n  \
             mysqldump -h host -u user -p dbname tablename > table_backup.sql\n\n\
             Preview table contents:\n  \
             SELECT COUNT(*) FROM tablename;\n  \
             SELECT * FROM tablename LIMIT 10;",
            DROP_TABLE_SUGGESTIONS
        ),
        // TRUNCATE TABLE
        destructive_pattern!(
            "truncate-table",
            r"(?i)TRUNCATE\s+(?:TABLE\s+)?[a-zA-Z_]",
            "TRUNCATE permanently deletes all rows. Cannot be rolled back in MySQL.",
            High,
            "TRUNCATE is faster than DELETE but more dangerous in MySQL:\n\n\
             - Removes ALL rows instantly\n\
             - CANNOT be rolled back (implicit commit)\n\
             - Does not fire DELETE triggers\n\
             - Resets AUTO_INCREMENT counter to 1\n\
             - Requires DROP privilege\n\
             - Acquires table lock\n\n\
             Unlike PostgreSQL, MySQL's TRUNCATE is NOT transactional!\n\n\
             Check row count first:\n  \
             SELECT COUNT(*) FROM tablename;\n\n\
             If you need rollback capability, use:\n  \
             DELETE FROM tablename;  -- Slower but transactional (dcg gates an \
             unfiltered DELETE too, so this form also needs approval)",
            TRUNCATE_TABLE_SUGGESTIONS
        ),
        // DELETE without WHERE
        destructive_pattern!(
            "delete-without-where",
            r"(?i)DELETE\s+FROM\s+(?:(?:[a-zA-Z_][a-zA-Z0-9_]*|`[^`]+`)(?:\.(?:[a-zA-Z_][a-zA-Z0-9_]*|`[^`]+`))?)\s*(?:;|$)",
            "DELETE without WHERE clause deletes ALL rows. Add a WHERE clause.",
            High,
            "DELETE without WHERE removes ALL rows from the table:\n\n\
             - Each row deletion is logged in binary log\n\
             - CAN be rolled back if within a transaction\n\
             - Fires DELETE triggers for each row\n\
             - Does NOT reset AUTO_INCREMENT counter\n\
             - Much slower than TRUNCATE for large tables\n\n\
             If you meant to delete all rows:\n\
             - TRUNCATE is faster (but non-transactional, and dcg gates it too)\n\
             - DELETE in transaction allows rollback\n\n\
             Otherwise, add a WHERE clause:\n  \
             DELETE FROM tablename WHERE condition;\n\n\
             Preview what would be deleted:\n  \
             SELECT COUNT(*) FROM tablename;  -- all rows!\n  \
             SELECT * FROM tablename LIMIT 10;",
            DELETE_WITHOUT_WHERE_SUGGESTIONS
        ),
        // mysqladmin drop
        destructive_pattern!(
            "mysqladmin-drop",
            r"mysqladmin\s+.*drop\b",
            "mysqladmin drop permanently deletes the database. Verify carefully.",
            Critical,
            "mysqladmin drop is the CLI equivalent of DROP DATABASE:\n\n\
             - Completely removes the database\n\
             - All data is lost permanently\n\
             - Has an 'are you sure?' prompt by default\n\
             - Adding --force skips confirmation!\n\n\
             Triple-check the database name. Common mistake:\n  \
             mysqladmin drop myapp_production  # Oops, meant myapp_staging\n\n\
             Backup first:\n  \
             mysqldump -h host -u user -p dbname > backup.sql\n\n\
             List databases to verify:\n  \
             mysql -e 'SHOW DATABASES;'",
            MYSQLADMIN_DROP_SUGGESTIONS
        ),
        // mysqldump with --add-drop-database
        destructive_pattern!(
            "mysqldump-add-drop-database",
            r"mysqldump\s+.*--add-drop-database",
            "mysqldump --add-drop-database drops the database before restore.",
            High,
            "mysqldump --add-drop-database adds DROP DATABASE to the backup file.\n\n\
             On restore, this will:\n\
             - DROP the database before CREATE DATABASE\n\
             - Destroy ALL existing data in that database\n\
             - If restore fails partway, data may be lost\n\n\
             This is dangerous when restoring to a database with data you want to keep.\n\n\
             Safer approach:\n\
             - Restore to a new/different database first\n\
             - Verify the restore completed successfully\n\
             - Then rename or swap databases\n\n\
             Without --add-drop-database:\n  \
             mysqldump dbname > backup.sql  # Creates only, no drops",
            MYSQLDUMP_ADD_DROP_DATABASE_SUGGESTIONS
        ),
        // mysqldump with --add-drop-table
        destructive_pattern!(
            "mysqldump-add-drop-table",
            r"mysqldump\s+.*--add-drop-table",
            "mysqldump --add-drop-table drops tables before creating them on restore.",
            Medium,
            "mysqldump --add-drop-table adds DROP TABLE before each CREATE TABLE.\n\n\
             This is actually the DEFAULT behavior of mysqldump!\n\
             On restore, each table is dropped before being recreated.\n\n\
             Risks:\n\
             - If restore fails partway, some tables may be dropped without recreation\n\
             - Existing data in those tables is permanently lost\n\n\
             Safer alternatives:\n\
             - Use --skip-add-drop-table to disable drops\n\
             - Restore to a new database first, then verify\n\
             - Keep the original database until restore is confirmed\n\n\
             To preserve existing data:\n  \
             mysqldump --skip-add-drop-table dbname > backup.sql",
            MYSQLDUMP_ADD_DROP_TABLE_SUGGESTIONS
        ),
        // GRANT ALL PRIVILEGES
        destructive_pattern!(
            "grant-all",
            r"(?i)GRANT\s+ALL\s+(?:PRIVILEGES\s+)?ON\s+\*\.\*",
            "GRANT ALL ON *.* gives unrestricted access to all databases.",
            High,
            "GRANT ALL PRIVILEGES ON *.* gives the user complete control:\n\n\
             - Can create, modify, and drop ANY database\n\
             - Can create, modify, and drop ANY user\n\
             - Can grant privileges to others\n\
             - Essentially creates a superuser\n\n\
             This is rarely necessary and violates principle of least privilege.\n\n\
             Better alternatives:\n\
             - GRANT ALL ON specific_db.* - Limit to one database\n\
             - GRANT SELECT, INSERT, UPDATE ON db.* - Limit operations\n\
             - GRANT ... ON db.table - Limit to specific tables\n\n\
             Review current grants:\n  \
             SHOW GRANTS FOR 'user'@'host';",
            GRANT_ALL_SUGGESTIONS
        ),
        // DROP USER
        destructive_pattern!(
            "drop-user",
            r"(?i)\bDROP\s+USER\b",
            "DROP USER permanently removes the user account and all their privileges.",
            Medium,
            "DROP USER removes the MySQL user account:\n\n\
             - All privileges granted to the user are revoked\n\
             - User can no longer authenticate\n\
             - Applications using this user will fail\n\
             - Cannot be undone (user must be recreated)\n\n\
             IF EXISTS only prevents errors if user doesn't exist.\n\n\
             Before dropping:\n  \
             SHOW GRANTS FOR 'user'@'host';  -- Document privileges\n  \
             SELECT * FROM mysql.user WHERE user='username';  -- Verify user\n\n\
             Consider disabling instead:\n  \
             ALTER USER 'user'@'host' ACCOUNT LOCK;",
            DROP_USER_SUGGESTIONS
        ),
        // RESET MASTER
        destructive_pattern!(
            "reset-master",
            r"(?i)\bRESET\s+MASTER\b",
            "RESET MASTER deletes all binary logs and resets the binlog position.",
            Critical,
            "RESET MASTER is destructive to replication and point-in-time recovery:\n\n\
             - Deletes ALL binary log files\n\
             - Resets binary log index\n\
             - Clears GTID executed set\n\
             - Breaks replication to all replicas\n\
             - Loses point-in-time recovery capability\n\n\
             Replicas must be reconfigured after RESET MASTER on the source.\n\n\
             Before running:\n\
             - Ensure no replicas are replicating\n\
             - Backup binary logs if needed for recovery\n\
             - Consider PURGE BINARY LOGS for selective cleanup\n\n\
             Safer alternative:\n  \
             PURGE BINARY LOGS BEFORE 'date';  -- Keeps recent logs",
            RESET_MASTER_SUGGESTIONS
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::*;

    #[test]
    fn test_drop_database() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "DROP DATABASE mydb;",
            "permanently deletes the entire database",
        );
        assert_blocks(
            &pack,
            "drop database mydb",
            "permanently deletes the entire database",
        );
        assert_blocks(
            &pack,
            "DROP DATABASE IF EXISTS mydb;",
            "permanently deletes the entire database",
        );
    }

    #[test]
    fn test_drop_table() {
        let pack = create_pack();
        assert_blocks(&pack, "DROP TABLE users;", "permanently deletes the table");
        assert_blocks(
            &pack,
            "DROP TABLE IF EXISTS users;",
            "permanently deletes the table",
        );
    }

    #[test]
    fn test_truncate() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "TRUNCATE TABLE users;",
            "permanently deletes all rows",
        );
        assert_blocks(&pack, "TRUNCATE users;", "permanently deletes all rows");
        assert_blocks(
            &pack,
            "truncate table orders",
            "permanently deletes all rows",
        );
    }

    #[test]
    fn test_delete_without_where() {
        let pack = create_pack();
        assert_blocks(&pack, "DELETE FROM users;", "DELETE without WHERE");
        assert_blocks(&pack, "DELETE FROM `users`;", "DELETE without WHERE");
        assert_blocks(&pack, "DELETE FROM mydb.users;", "DELETE without WHERE");
        assert_blocks(&pack, "delete from users", "DELETE without WHERE");

        // Should NOT block if WHERE clause is present
        assert_allows(&pack, "DELETE FROM users WHERE id = 1;");
        assert_allows(&pack, "DELETE FROM users WHERE active = false");
    }

    #[test]
    fn test_mysqladmin_drop() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "mysqladmin drop mydb",
            "permanently deletes the database",
        );
        assert_blocks(
            &pack,
            "mysqladmin -u root drop testdb",
            "permanently deletes the database",
        );
        assert_blocks(
            &pack,
            "mysqladmin --force drop mydb",
            "permanently deletes the database",
        );
    }

    #[test]
    fn test_grant_all() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "GRANT ALL ON *.* TO 'user'@'host';",
            "unrestricted access",
        );
        assert_blocks(
            &pack,
            "GRANT ALL PRIVILEGES ON *.* TO 'admin'@'%';",
            "unrestricted access",
        );

        // Should NOT block for specific database grants
        assert_allows(&pack, "GRANT ALL ON mydb.* TO 'user'@'host';");
        assert_allows(&pack, "GRANT SELECT ON *.* TO 'readonly'@'%';");
    }

    #[test]
    fn test_safe_patterns() {
        let pack = create_pack();
        assert_allows(&pack, "SELECT * FROM users;");
        assert_allows(&pack, "SHOW DATABASES;");
        assert_allows(&pack, "SHOW TABLES;");
        assert_allows(&pack, "DESCRIBE users;");
        assert_allows(&pack, "EXPLAIN SELECT * FROM users;");
    }
}
