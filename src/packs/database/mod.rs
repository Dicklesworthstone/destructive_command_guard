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
/// 4. The statement must also *begin* where a SQL statement can begin — the
///    start of the evaluated text, just after a `;`, or just inside an opening
///    quote (issue #394). Without this, the word `truncate` anywhere in argv
///    read as DDL: `cat truncate x`, `sort truncate b`, and `wc -l truncate x`
///    are file reads whose operands happen to be named like SQL, and all three
///    were denied as "would delete database rows". An operand of another
///    command is never in statement position, so this separates them without
///    touching a single real invocation.
///
///    The three unconditional openers are what every real execution path
///    produces: a heredoc body or a reconstructed `echo … | mysql` payload
///    starts at text start; `mysql -e "TRUNCATE …"`, `--execute="…"`, and
///    `psql -c '…'` open with a quote; and a later statement in a
///    multi-statement payload follows the previous statement's `;`.
///
///    A bare newline is a *conditional* opener: it counts only when the
///    explicit `TRUNCATE TABLE` spelling follows it. A newline alone would
///    re-admit the #403 class-list false positive, where a wrapped
///    `class="… truncate\n flex"` reads as `TRUNCATE flex"`; requiring the
///    `TABLE` keyword is evidence no class list carries. This exists because
///    the first, quote-only form of constraint 4 under-blocked a real shape:
///    `mysql -e "-- comment\nTRUNCATE TABLE users"` puts the statement on a
///    continuation line after a SQL comment, so it has no `;` before it and is
///    not at text start. Multi-line heredoc payloads were never affected —
///    their bodies are evaluated per line — but the `-e` route was.
///
///    A SQL comment between the opener and the keyword is skipped the same way
///    whitespace is, because it is invisible to the server: `mysql -e "/* clean
///    */ TRUNCATE TABLE users"` executes exactly as the bare statement does.
///    Skipping only whitespace silently lost that whole shape — the same class
///    the newline branch was added for, and carrying the same explicit `TABLE`
///    evidence. MySQL's *executable* comment `/*!40000 TRUNCATE TABLE users */`
///    is the inverse: its contents do run, so `/*!` is an opener in its own
///    right rather than something to skip, and the skip group excludes it.
///
///    Residual, deliberately accepted: the same continuation-line shape with
///    the optional `TABLE` keyword omitted (`-- comment\nTRUNCATE users`) is
///    not matched. Closing it needs a newline opener with no keyword evidence,
///    which is exactly what #403 showed is too broad.
///
/// `TRUNCATE TABLE …` (the explicit-keyword spelling) is covered by the same
/// expression; nothing about it is relaxed.
///
/// Held here (rather than in either pack) so the two copies stay auditable
/// from one place; `truncate_table_pattern_is_shared` asserts they match.
/// `destructive_pattern!` takes a literal, so the packs spell the expression
/// out rather than referencing this constant.
#[cfg(test)]
pub(crate) const TRUNCATE_TABLE_PATTERN: &str = r#"(?i)(?:(?:^|[;"'`])(?:\s|/\*(?!!)(?s:.*?)\*/)*|\r?\n(?:\s|/\*(?!!)(?s:.*?)\*/)*(?=TRUNCATE\s+TABLE\b)|/\*!\d*\s*)(?<![-\w.$])TRUNCATE\s+(?:TABLE\s+)?(?:ONLY\s+)?[A-Za-z_][A-Za-z0-9_$]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_$]*)*(?![A-Za-z0-9_$]*[-.])\s*(?:[;,)"'`]|\*/|$|\s+(?:CASCADE|RESTRICT|RESTART|CONTINUE|IDENTITY)\b)"#;

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

    /// The `TRUNCATE` false positive in #403 reproduced in `database.mysql` and
    /// `database.postgresql`, because each carried its own copy of this
    /// expression. Keep the copies identical so a future narrowing cannot fix
    /// one dialect and leave the other.
    ///
    /// The reporter also named `database.bigquery` as carrying the "same
    /// shape". It does not, and never has: its rule is `\bTRUNCATE\s+TABLE\b`,
    /// which requires the literal `TABLE` keyword and so cannot read a Tailwind
    /// class list as SQL. It is deliberately outside this loop — asserting it
    /// against the shared pattern would fail, and widening it to match would
    /// import the very false positive #403 is about. `database.snowflake`
    /// stubs its regex to `(?!)` and decides `truncate-table` semantically, so
    /// it is likewise not a copy of this expression.
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
