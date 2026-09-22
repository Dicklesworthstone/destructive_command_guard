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
///    evidence.
///
///    **The comment body must be unambiguous.** It is spelled
///    `/\*(?:[^*]|\*+[^*/])*\*+/`, the classic non-merging C-comment form, and
///    NOT `/\*(?s:.*?)\*/`. The lazy version can merge across a `*/` boundary,
///    so over M adjacent `/**/` units there are 2^(M-1) ways to tile the
///    prefix. That is not merely slow: `RegexEngine::is_match` returns `false`
///    when fancy-regex reports `BacktrackLimitExceeded`, so at 13 units the
///    rule silently stopped matching and
///    `mysql -e "/**//**/…/**/Q; TRUNCATE TABLE users;"` was ALLOWED. A
///    fail-open on a resource limit is attacker-steerable, so the expression
///    must not be able to reach the limit in the first place.
///
///    MySQL's *executable* comment `/*!40000 …*/` is a wrapper, not a comment:
///    its contents run. It is therefore skippable like any other comment when
///    the statement follows it (`/*!40000 SET … */ TRUNCATE TABLE users`), and
///    `/\*!\d*\s*` is additionally an opener in its own right for when the
///    statement sits INSIDE it (`/*!40000 TRUNCATE TABLE users */`). The `\*/`
///    terminator exists for that second form.
///
///    Two accepted over-blocks come with the `\*/` terminator, both in the
///    safe direction and both inside an opt-in pack: a TRUNCATE named only
///    inside a non-executing comment after a `;` (`mysql -e "SELECT 1 /* a;
///    TRUNCATE b */"`) is denied, and PostgreSQL inherits the MySQL `/*!`
///    opener because all three copies are byte-identical, so
///    `psql -c "/*! TRUNCATE TABLE users */"` is denied although Postgres
///    treats that as an ordinary comment.
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
pub(crate) const TRUNCATE_TABLE_PATTERN: &str = r#"(?i)(?:(?:^|[;"'`])(?:\s|/\*(?:[^*]|\*+[^*/])*\*+/)*|\r?\n(?:\s|/\*(?:[^*]|\*+[^*/])*\*+/)*(?=TRUNCATE\s+TABLE\b)|/\*!\d*\s*)(?<![-\w.$])TRUNCATE\s+(?:TABLE\s+)?(?:ONLY\s+)?[A-Za-z_][A-Za-z0-9_$]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_$]*)*(?![A-Za-z0-9_$]*[-.])\s*(?:[;,)"'`]|\*/|$|\s+(?:CASCADE|RESTRICT|RESTART|CONTINUE|IDENTITY)\b)"#;

/// `UPDATE <table> SET …` with no `WHERE` before the statement ends rewrites
/// every row — the unscoped blast radius every SQL pack already denies for
/// `DELETE`. Shared by the PostgreSQL, MySQL and SQLite packs (each spells it
/// out; `sql_mutation_patterns_are_shared` keeps the copies identical).
/// Covers MySQL `LOW_PRIORITY`/`IGNORE`, SQLite `OR <conflict>`, quoted,
/// backticked and bracketed identifiers, and a table alias.
#[cfg(test)]
pub(crate) const UPDATE_WITHOUT_WHERE_PATTERN: &str = r#"(?i)\bUPDATE\s+(?:(?:LOW_PRIORITY|IGNORE|ONLY|OR\s+(?:ROLLBACK|ABORT|REPLACE|FAIL|IGNORE))\s+)*(?:[A-Za-z_][\w$]*|"[^"]+"|`[^`]+`|\[[^\]]+\])(?:\s*\.\s*(?:[A-Za-z_][\w$]*|"[^"]+"|`[^`]+`|\[[^\]]+\]))?\s+(?:(?:AS\s+)?(?!SET\b)[A-Za-z_]\w*\s+)?SET\b(?:(?!\bWHERE\b)[^;])*(?:;|$)"#;

/// `ALTER TABLE … DROP [COLUMN] <col>` deletes that column's data in every
/// row. Metadata-only drops stay allowed: `DROP CONSTRAINT|DEFAULT|NOT NULL|
/// IDENTITY|EXPRESSION` and MySQL's `DROP INDEX|KEY|PRIMARY KEY|FOREIGN KEY|
/// CHECK`. `DROP PARTITION` is NOT exempt: it deletes that partition's rows.
#[cfg(test)]
pub(crate) const DROP_COLUMN_PATTERN: &str = r#"(?i)\bALTER\s+TABLE\b[^;]*?\bDROP\s+(?:COLUMN\s+)?(?:IF\s+EXISTS\s+)?(?!(?:CONSTRAINT|DEFAULT|NOT\s+NULL|IDENTITY|EXPRESSION|INDEX|KEY|PRIMARY\s+KEY|FOREIGN\s+KEY|CHECK)\b)[A-Za-z_"`\[]"#;

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
    use super::{DROP_COLUMN_PATTERN, TRUNCATE_TABLE_PATTERN, UPDATE_WITHOUT_WHERE_PATTERN};

    /// Same reasoning as `truncate_table_pattern_is_shared`: one copy per
    /// dialect drifts, so the three SQL packs must spell these identically.
    #[test]
    fn sql_mutation_patterns_are_shared() {
        for pack in [
            super::postgresql::create_pack(),
            super::mysql::create_pack(),
            super::sqlite::create_pack(),
        ] {
            for (name, shared) in [
                ("update-without-where", UPDATE_WITHOUT_WHERE_PATTERN),
                ("drop-column", DROP_COLUMN_PATTERN),
            ] {
                let pattern = pack
                    .destructive_patterns
                    .iter()
                    .find(|pattern| pattern.name == Some(name))
                    .unwrap_or_else(|| panic!("{} defines {name}", pack.id));
                assert_eq!(pattern.regex.as_str(), shared, "{} {name}", pack.id);
            }
        }
    }

    /// What the shared expressions decide, per dialect spelling.
    #[test]
    fn sql_mutation_patterns_decide_per_dialect() {
        let matches = |pattern: &str, sql: &str| {
            fancy_regex::Regex::new(pattern)
                .expect("compiles")
                .is_match(sql)
                .expect("matches")
        };
        for sql in [
            "UPDATE users SET admin = 1",
            "UPDATE LOW_PRIORITY IGNORE `users` SET admin = 1;",
            "UPDATE OR REPLACE users SET x = 1",
            "UPDATE [dbo].[users] SET x = 1",
            "update app.users u set x = 1",
        ] {
            assert!(matches(UPDATE_WITHOUT_WHERE_PATTERN, sql), "{sql}");
        }
        for sql in [
            "UPDATE users SET admin = 1 WHERE id = 7",
            "UPDATE users SET a = 1 WHERE id IN (SELECT id FROM t)",
            "apt update",
            "SELECT * FROM users WHERE updated = 1",
        ] {
            assert!(!matches(UPDATE_WITHOUT_WHERE_PATTERN, sql), "{sql}");
        }
        for sql in [
            "ALTER TABLE users DROP COLUMN email",
            "ALTER TABLE `users` DROP `email`",
            "ALTER TABLE logs DROP PARTITION p2023",
        ] {
            assert!(matches(DROP_COLUMN_PATTERN, sql), "{sql}");
        }
        for sql in [
            "ALTER TABLE users DROP INDEX idx_email",
            "ALTER TABLE users DROP PRIMARY KEY",
            "ALTER TABLE users DROP FOREIGN KEY fk_org",
            "ALTER TABLE users ALTER COLUMN email DROP DEFAULT",
            "ALTER TABLE users DROP CONSTRAINT users_email_key",
        ] {
            assert!(!matches(DROP_COLUMN_PATTERN, sql), "{sql}");
        }
    }

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
