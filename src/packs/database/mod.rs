//! Database pack - protections for database management commands.
//!
//! This pack provides protection against destructive database operations:
//! - `PostgreSQL` (`psql`, `dropdb`, `pg_dump`)
//! - `MySQL`/`MariaDB` (`mysql`, `mysqldump`)
//! - `MongoDB` (`mongosh`, `mongodump`)
//! - `Redis` (`redis-cli`)
//! - `SQLite` (`sqlite3`)
//! - Snowflake (modern `snow sql` CLI)
//! - `Supabase` (`supabase db`, `supabase migration`, `supabase projects`)
//! - `BigQuery` (`bq` CLI and `GoogleSQL`)
//! - Databricks (`databricks` CLI: workspace/fs/bundle/secrets/api deletes)

/// Shared `TRUNCATE [TABLE] <name>` DDL pattern for the SQL dialects whose
/// `TRUNCATE` takes an optional `TABLE` keyword (`MySQL`/`MariaDB`,
/// `PostgreSQL`).
///
/// The obvious spelling — `TRUNCATE\s+(?:TABLE\s+)?[a-zA-Z_]` — is "the word
/// `truncate`, whitespace, a letter", which every Tailwind CSS class list
/// satisfies: `class="min-w-0 truncate line-through"` reads as
/// `TRUNCATE <tablename>` and blocked ordinary React/TypeScript edits in any
/// project using the (extremely common) `truncate` utility class (issue #403).
/// Three constraints separate DDL from a class list without weakening the rule:
///
/// 1. `(?<![-\w.$])` — the keyword must start a word, and `\b` alone is not
///    that: a word boundary also exists after `.`, `-`, and `$`, so `\b`
///    matched `s.truncate`, `--truncate` and `text-truncate`. This is the
///    recurring "`\b` after punctuation" defect, audited across the sibling
///    rules in these packs.
/// 2. The table name is a full SQL identifier (optionally schema-qualified),
///    and may not be followed by `-`. An unquoted SQL identifier cannot
///    contain a hyphen, so `truncate line-through`, `truncate text-sm` and
///    `truncate flex-1` can never be DDL.
/// 3. The statement must *end* after the identifier — end of input, `;`, `,`,
///    `)`, a closing quote, or one of `TRUNCATE`'s own trailing clauses.
///    A class list continues with more class tokens instead.
///
/// `TRUNCATE TABLE …` (the explicit-keyword spelling) is covered by the same
/// expression; nothing about it is relaxed.
///
/// Held here (rather than in either pack) so the two copies stay auditable
/// from one place; `truncate_table_pattern_is_shared` asserts they match.
/// `destructive_pattern!` takes a literal, so the packs spell the expression
/// out rather than referencing this constant.
#[cfg(test)]
pub(crate) const TRUNCATE_TABLE_PATTERN: &str = r#"(?i)(?<![-\w.$])TRUNCATE\s+(?:TABLE\s+)?(?:ONLY\s+)?[A-Za-z_][A-Za-z0-9_$]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_$]*)*(?![A-Za-z0-9_$]*[-.])\s*(?:[;,)"'`]|$|\s+(?:CASCADE|RESTRICT|RESTART|CONTINUE|IDENTITY)\b)"#;

pub mod bigquery;
pub mod databricks;
pub mod mongodb;
pub mod mysql;
pub mod postgresql;
pub mod redis;
pub mod snowflake;
pub mod sqlite;
pub mod supabase;

#[cfg(test)]
mod tests {
    use super::TRUNCATE_TABLE_PATTERN;

    fn truncate_pattern_of(pack: &crate::packs::Pack) -> &str {
        pack.destructive_patterns
            .iter()
            .find(|pattern| pattern.name == Some("truncate-table"))
            .expect("pack defines truncate-table")
            .regex
            .as_str()
    }

    /// The `TRUNCATE` false positive in #403 reproduced in three packs because
    /// each carried its own copy of the expression. Keep the copies identical
    /// so a future narrowing cannot fix one dialect and leave the others.
    #[test]
    fn truncate_table_pattern_is_shared() {
        for pack in [
            super::mysql::create_pack(),
            super::postgresql::create_pack(),
        ] {
            assert_eq!(
                truncate_pattern_of(&pack),
                TRUNCATE_TABLE_PATTERN,
                "{} must use the shared TRUNCATE pattern",
                pack.id
            );
        }
    }
}
