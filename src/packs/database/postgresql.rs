//! `PostgreSQL` patterns - protections against destructive psql/pg commands.
//!
//! This includes patterns for:
//! - DROP DATABASE/TABLE/SCHEMA commands
//! - TRUNCATE commands
//! - dropdb CLI command
//! - `pg_dump` with --clean flag

use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};
use crate::{destructive_pattern, safe_pattern};
use std::borrow::Cow;

/// Blank out *nested* PostgreSQL block comments so a statement behind one is
/// still visible to the pack's patterns (#432).
///
/// **PostgreSQL block comments nest; MySQL's do not.** The shared
/// `truncate-table` expression skips a comment with
/// `/\*(?:[^*]|\*+[^*/])*\*+/`, which ends at the first `*/` — right for MySQL,
/// wrong here, so `/* /* */ */ TRUNCATE TABLE users;` had its statement hidden
/// behind what dcg read as the comment's tail. Verified against PostgreSQL 18:
/// that command truncates.
///
/// Arbitrary nesting is not a regular language, so this is a scanner rather
/// than a wider regex. Four rules keep it from becoming a false-negative
/// machine of its own, which the first draft was:
///
/// * **Only nested comments are blanked.** A comment that never reaches depth
///   two is left alone, because the pattern's own skip group already handles
///   it. Everything that used to match still matches byte for byte.
/// * **Only closed comments are blanked.** An unterminated `/*` is left alone
///   rather than swallowing the rest of the input. PostgreSQL rejects it as a
///   syntax error, so nothing runs either way — but this text is a *shell*
///   command line, where `/*` is also a glob, and blanking to the end of
///   `rm -rf /*/*; dropdb mydb` would hide the `dropdb` from this pack.
/// * **`--` is not treated as a comment at all.** In the shell text these
///   patterns run against, `--` is the end-of-options separator:
///   `ssh host -- dropdb mydb` is a real denial, and blanking from `--` to the
///   end of the line withdrew it. A leading `-- …` SQL comment needs no help,
///   because the expression already anchors on `\r?\n` before the statement.
/// * **Strings are not comments.** `'…'` (with `''` escapes), `"…"` and
///   `$tag$…$tag$` bodies are copied through untouched, so a literal
///   containing `/*` neither starts a comment nor gets blanked.
///
/// The mask is **length preserving**: every blanked byte becomes a space and
/// every newline is kept, so byte offsets in the masked view are byte offsets
/// in the original, spans still map back, and the `\r?\n`-anchored
/// alternatives still see their line structure.
pub(crate) fn mask_comments(sql: &str) -> Cow<'_, str> {
    if !sql.contains("/*") {
        return Cow::Borrowed(sql);
    }

    let bytes = sql.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0usize;

    while index < bytes.len() {
        let byte = bytes[index];

        match byte {
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                let (end, max_depth, closed) = block_comment_extent(bytes, index);
                if closed && max_depth >= 2 {
                    for &inner in &bytes[index..end] {
                        out.push(if inner == b'\n' || inner == b'\r' {
                            inner
                        } else {
                            b' '
                        });
                    }
                } else {
                    out.extend_from_slice(&bytes[index..end]);
                }
                index = end;
            }
            b'\'' | b'"' => {
                let quote = byte;
                out.push(byte);
                index += 1;
                while index < bytes.len() {
                    out.push(bytes[index]);
                    if bytes[index] == quote {
                        // A doubled quote is an escaped quote, not the end.
                        if bytes.get(index + 1) == Some(&quote) {
                            out.push(quote);
                            index += 2;
                            continue;
                        }
                        index += 1;
                        break;
                    }
                    index += 1;
                }
            }
            b'$' => {
                if let Some(tag_end) = dollar_quote_tag_end(bytes, index) {
                    let tag = &bytes[index..=tag_end];
                    out.extend_from_slice(tag);
                    index = tag_end + 1;
                    // Copy the body through to the closing tag, or to the end
                    // of input when it is never closed.
                    let closing = find_subslice(&bytes[index..], tag).map(|at| index + at);
                    let stop = closing.map_or(bytes.len(), |at| at + tag.len());
                    out.extend_from_slice(&bytes[index..stop]);
                    index = stop;
                } else {
                    out.push(byte);
                    index += 1;
                }
            }
            _ => {
                out.push(byte);
                index += 1;
            }
        }
    }

    debug_assert_eq!(out.len(), bytes.len(), "masking must preserve byte offsets");
    match String::from_utf8(out) {
        Ok(masked) if masked != sql => Cow::Owned(masked),
        // Masking only ever replaces ASCII bytes with ASCII spaces, so a
        // decode failure is impossible; fail open rather than panic if that
        // reasoning ever stops holding.
        _ => Cow::Borrowed(sql),
    }
}

/// Walk a block comment starting at `start` (which must be `/*`).
///
/// Returns the byte index just past the comment, the deepest nesting it
/// reached, and whether it closed. A comment that does not close reports the
/// end of input, so the caller can leave it untouched.
fn block_comment_extent(bytes: &[u8], start: usize) -> (usize, usize, bool) {
    let mut index = start + 2;
    let mut depth = 1usize;
    let mut max_depth = 1usize;
    while index < bytes.len() {
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            depth += 1;
            max_depth = max_depth.max(depth);
            index += 2;
            continue;
        }
        if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
            depth -= 1;
            index += 2;
            if depth == 0 {
                return (index, max_depth, true);
            }
            continue;
        }
        index += 1;
    }
    (bytes.len(), max_depth, false)
}

/// The index of the final `$` of a dollar-quote tag starting at `start`, if the
/// bytes there are one. Tags are `$$` or `$name$` with an identifier body.
fn dollar_quote_tag_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'$' => return Some(index),
            b'_' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' => index += 1,
            _ => return None,
        }
    }
    None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

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
            "drop", "truncate", "UPDATE", "update",
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
            // Keep byte-identical to `crate::packs::database::TRUNCATE_TABLE_PATTERN`
            // (asserted by `truncate_table_pattern_is_shared`); the rationale
            // for every constraint lives on that constant. Issue #403.
            r#"(?i)(?:(?:^|[;"'`])(?:\s|/\*(?:[^*]|\*+[^*/])*\*+/)*|\r?\n(?:\s|/\*(?:[^*]|\*+[^*/])*\*+/)*(?=TRUNCATE\s+TABLE\b)|/\*!\d*\s*)(?<![-\w.$])TRUNCATE\s+(?:TABLE\s+)?(?:ONLY\s+)?[A-Za-z_][A-Za-z0-9_$]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_$]*)*(?![A-Za-z0-9_$]*[-.])\s*(?:[;,)"'`]|\*/|$|\s+(?:CASCADE|RESTRICT|RESTART|CONTINUE|IDENTITY)\b)"#,
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
            r#"(?i)\bDELETE\s+FROM\s+(?:(?:[a-zA-Z_][a-zA-Z0-9_]*|"[^"]+")(?:\.(?:[a-zA-Z_][a-zA-Z0-9_]*|"[^"]+"))?)\s*(?:;|$)"#,
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
        // UPDATE without WHERE rewrites every row — the same unscoped blast
        // radius as the DELETE rule above, which denied while this allowed.
        destructive_pattern!(
            "update-without-where",
            r#"(?i)\bUPDATE\s+(?:ONLY\s+)?(?:[a-zA-Z_][a-zA-Z0-9_]*|"[^"]+")(?:\.(?:[a-zA-Z_][a-zA-Z0-9_]*|"[^"]+"))?\s+(?:AS\s+\w+\s+)?SET\b(?:(?!\bWHERE\b)[^;])*(?:;|$)"#,
            "UPDATE without WHERE clause overwrites the column in ALL rows. Add a WHERE clause.",
            High,
            "UPDATE without WHERE changes every row in the table, replacing whatever values \
             were there. Unless it runs inside a transaction you then roll back, the previous \
             values are gone.\n\n\
             Scope it:\n  \
             UPDATE tablename SET col = value WHERE condition;\n\n\
             Preview what would change:\n  \
             SELECT COUNT(*) FROM tablename WHERE condition;\n\n\
             Or wrap it: BEGIN; UPDATE …; SELECT …; ROLLBACK/COMMIT;"
        ),
        // ALTER TABLE … DROP COLUMN deletes that column's data for every row.
        // `ALTER COLUMN c DROP DEFAULT | NOT NULL | IDENTITY | EXPRESSION` and
        // `DROP CONSTRAINT` change metadata only and stay allowed.
        destructive_pattern!(
            "drop-column",
            r"(?i)\bALTER\s+TABLE\b[^;]*?\bDROP\s+(?:COLUMN\s+)?(?:IF\s+EXISTS\s+)?(?!(?:CONSTRAINT|DEFAULT|NOT\s+NULL|IDENTITY|EXPRESSION)\b)[A-Za-z_\x22]",
            "ALTER TABLE ... DROP COLUMN permanently deletes that column's data in every row.",
            High,
            "Dropping a column removes its values from every row. PostgreSQL does not keep \
             them anywhere you can restore from without a backup.\n\n\
             Back up the column first:\n  \
             CREATE TABLE tablename_col_backup AS SELECT id, col FROM tablename;\n\n\
             Or keep it for now: stop reading it in the application, then drop it later."
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

    /// Issue #403: Tailwind's `truncate` utility class is not SQL DDL.
    ///
    /// The class list is the overwhelmingly common spelling in current
    /// frontend code, and `truncate` followed by another class satisfied the
    /// old "word, whitespace, letter" pattern, so ordinary React/TypeScript
    /// edits could not be made through any shell command.
    #[test]
    fn tailwind_truncate_class_is_not_ddl() {
        let pack = create_pack();
        for command in [
            "truncate line-through",
            "TRUNCATE line-through",
            "truncate text-sm",
            "truncate flex-1",
            "echo class=\"min-w-0 truncate line-through\"",
            "bun run build -- --class truncate line-through",
            // The `\b`-after-punctuation class: a word boundary also exists
            // after `.` and `-`, so these used to match.
            "x.truncate 5",
            "cargo run -- --no-truncate output",
        ] {
            assert_allows(&pack, command);
        }
    }

    /// The same expression must still see every real spelling of the DDL.
    #[test]
    fn truncate_ddl_spellings_still_block() {
        let pack = create_pack();
        for command in [
            "truncate table users",
            "TRUNCATE TABLE users",
            "truncate users",
            "truncate users;",
            "truncate only users",
            "TRUNCATE TABLE public.users",
            "truncate foo CASCADE",
            "truncate table a, b",
            "TRUNCATE users RESTART IDENTITY",
        ] {
            assert_blocks_with_pattern(&pack, command, "truncate-table");
        }
    }

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
    fn truncate_pattern_requires_statement_position() {
        // Regression #394: the rule matched the word `truncate` anywhere in
        // argv, so a plain file read whose operand happened to be named like a
        // SQL identifier was denied as "would delete database rows". An operand
        // of another command is never in statement position.
        let pack = create_pack();
        for command in [
            "cat truncate x",
            "sort truncate b",
            "wc -l truncate x",
            "ls truncate x",
            "head -5 truncate x",
            "diff truncate other",
            "cp truncate backup",
        ] {
            assert_no_match(&pack, command);
        }

        // Every real execution path opens the statement where SQL can start:
        // text start (a heredoc body or a reconstructed pipeline payload), an
        // opening quote, or the previous statement's `;`.
        assert_blocks(&pack, "TRUNCATE TABLE users", "TRUNCATE");
        assert_blocks(&pack, "psql -c \"TRUNCATE TABLE users\"", "TRUNCATE");
        assert_blocks(&pack, "psql --command 'TRUNCATE users'", "TRUNCATE");
        assert_blocks(
            &pack,
            "psql -c \"BEGIN; TRUNCATE users; COMMIT;\"",
            "TRUNCATE",
        );
        assert_blocks(&pack, "TRUNCATE TABLE public.users CASCADE", "TRUNCATE");
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
    /// #432: PostgreSQL block comments nest, so a comment-skipping expression
    /// that ends at the first `*/` hides the statement behind it. Verified on a
    /// live PostgreSQL 18 instance by the reporter: the first command below
    /// truncates a seeded table.
    ///
    /// The masking is applied by the evaluator, which is where the decision is
    /// made, so the verdicts are asserted there
    /// (`evaluator::tests::nested_sql_comments_do_not_hide_the_statement_issue_432`).
    /// What this test pins is that the statement survives masking at all — the
    /// pack's own patterns match a *masked* view, and if the mask ate the
    /// statement no rule could fire.
    #[test]
    fn nested_block_comments_leave_the_following_statement_visible() {
        let pack = create_pack();
        for command in [
            "/* /* */ */ TRUNCATE TABLE users;",
            "/* /* /* */ */ */ TRUNCATE TABLE users;",
            "/* x */ TRUNCATE TABLE users;",
            "/*/* nested without spaces */*/ TRUNCATE TABLE users;",
            "-- a line comment\nTRUNCATE TABLE users;",
            "/* multi\n   line\n   /* nested */ */\nTRUNCATE TABLE users;",
        ] {
            let masked = mask_comments(command);
            assert!(
                masked.contains("TRUNCATE TABLE users;"),
                "masking must not eat the statement: {command:?} -> {masked:?}"
            );
            assert_blocks(&pack, masked.as_ref(), "TRUNCATE");
        }
    }

    /// Everything the mask must leave exactly as it found it. The first draft
    /// of this masker blanked `--` to end of line and swallowed unterminated
    /// comments, and both withdrew real denials from shell text — `--` is the
    /// end-of-options separator (`ssh host -- dropdb mydb`) and `/*` is a glob.
    #[test]
    fn comment_masking_only_touches_nested_closed_comments() {
        for unchanged in [
            "SELECT 1;",
            // Not nested: the pattern's own skip group already handles it, so
            // masking here could only change behaviour that already works.
            "/* plain */ TRUNCATE TABLE users;",
            // `--` is shell syntax here, not a SQL comment.
            "ssh example-host -- dropdb mydb",
            "-- drop it\nTRUNCATE TABLE users;",
            // Unterminated: left alone rather than blanked to the end, because
            // `/*` is also a shell glob.
            "/* unterminated TRUNCATE TABLE users;",
            "rm -rf /*/*; dropdb mydb",
            // Strings and dollar-quoted bodies are data.
            "SELECT '/* /* */ */ not a comment';",
            "SELECT 'it''s /* /* */ */ fine';",
            "SELECT $$ /* /* */ */ body $$; TRUNCATE TABLE users;",
            "SELECT $tag$ /* /* */ */ body $tag$;",
            "SELECT $1 FROM t;",
        ] {
            assert_eq!(
                mask_comments(unchanged),
                unchanged,
                "must be left unchanged: {unchanged:?}"
            );
        }

        // A nested, closed comment is blanked, and only it.
        assert_eq!(
            mask_comments("/* /* */ */ TRUNCATE TABLE users;"),
            "            TRUNCATE TABLE users;"
        );
        let source = "SELECT 1; /*/* c */*/ TRUNCATE TABLE users;";
        let masked = mask_comments(source);
        assert_eq!(masked.len(), source.len());
        assert!(masked.starts_with("SELECT 1; "), "{masked:?}");
        assert!(masked.ends_with(" TRUNCATE TABLE users;"), "{masked:?}");
        assert!(
            !masked.contains('*'),
            "the comment must be gone: {masked:?}"
        );

        // Length and line structure are preserved, so spans and the
        // `\r?\n`-anchored alternatives keep working.
        for source in [
            "/* /* */ */ TRUNCATE TABLE users;",
            "/* multi\n   /* nested */ */\nTRUNCATE TABLE users;",
        ] {
            let masked = mask_comments(source);
            assert_eq!(
                masked.len(),
                source.len(),
                "masking must preserve byte offsets: {source:?} -> {masked:?}"
            );
            assert_eq!(
                masked.lines().count(),
                source.lines().count(),
                "newlines must survive: {source:?} -> {masked:?}"
            );
        }
    }

    /// An unterminated block comment is left alone: PostgreSQL rejects it as a
    /// syntax error so nothing runs, and blanking it would hide later commands
    /// in the same shell line from this pack.
    #[test]
    fn an_unterminated_comment_is_left_alone() {
        let pack = create_pack();
        assert_eq!(
            mask_comments("/* TRUNCATE TABLE users;"),
            "/* TRUNCATE TABLE users;"
        );
        assert_no_match(&pack, "/* TRUNCATE TABLE users;");
        // And a later statement on the same line is still reachable.
        let masked = mask_comments("rm -rf /*/*; dropdb mydb");
        assert!(masked.contains("dropdb mydb"), "{masked:?}");
    }

    /// Unscoped UPDATE and DROP COLUMN destroy data like the already-denied
    /// unscoped DELETE and DROP TABLE, and were allowed.
    #[test]
    fn unscoped_update_and_drop_column_are_denied() {
        let pack = create_pack();
        for (command, rule) in [
            ("UPDATE users SET admin = true;", "update-without-where"),
            (
                "update public.users set email = null",
                "update-without-where",
            ),
            ("UPDATE users AS u SET name = 'x'", "update-without-where"),
            ("ALTER TABLE users DROP COLUMN email;", "drop-column"),
            ("alter table users drop email", "drop-column"),
            (
                "ALTER TABLE users DROP COLUMN IF EXISTS email",
                "drop-column",
            ),
            (
                "ALTER TABLE users ADD COLUMN x int, DROP COLUMN y",
                "drop-column",
            ),
        ] {
            assert_blocks_with_pattern(&pack, command, rule);
        }
        for command in [
            "UPDATE users SET admin = true WHERE id = 1;",
            "update users set x = 1 where x is null",
            "ALTER TABLE users ALTER COLUMN email DROP NOT NULL",
            "ALTER TABLE users ALTER COLUMN email DROP DEFAULT",
            "ALTER TABLE users DROP CONSTRAINT users_email_key",
            "ALTER TABLE users ADD COLUMN email text",
            "apt update",
            "brew update && brew upgrade",
        ] {
            assert_no_match(&pack, command);
        }
    }
}
