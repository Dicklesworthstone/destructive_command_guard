//! `BigQuery` protection: the `bq` CLI and `GoogleSQL`.
//!
//! Three `BigQuery` specifics drive the rules here, and each one makes a
//! naive port of the `PostgreSQL`/Snowflake packs wrong:
//!
//! - A *dataset* is a `SCHEMA` in `GoogleSQL`. `DROP SCHEMA` is therefore the
//!   dataset-level catastrophe, not a namespace tidy-up.
//! - `GoogleSQL` **requires** a `WHERE` clause on `DELETE`/`UPDATE`, so
//!   `WHERE TRUE` is the idiomatic full-table spelling. A `delete-without-where`
//!   rule modelled on `PostgreSQL` would never fire.
//! - Time travel (2–7 days) is the only undo. Settings that shorten it —
//!   `--max_time_travel_hours`, `expiration_timestamp` — destroy the recovery
//!   path itself, so they are destructive in their own right.
//!
//! CLI rules are scoped with `executables = ["bq"]`: `bq` is a two-letter
//! token that shows up in prose, filenames, and other commands, so these must
//! only fire when the resolved argv0 really is `bq`. The `GoogleSQL` rules are
//! unscoped because SQL reaches us through files, pipes, and heredocs as well
//! as `bq query` arguments.
//!
//! **Scope note.** Snowflake additionally carries a dialect-aware argv
//! recovery layer (`collect_dialect_snowflake_flows`: PowerShell call
//! operators, dynamic executable spellings, CLI size budgets). That is not
//! ported here. The consequence is bounded: destructive `GoogleSQL` still
//! blocks, because those rules match the raw command text regardless of how
//! argv was spelled — what is missing is the extra depth of recovering `bq`
//! argv under exotic dialect forms, which would refine attribution rather
//! than change a verdict.

use crate::destructive_pattern;
use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};

/// Parsed code-bearing surfaces of one `bq` argv vector.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BqCliAnalysis<'a> {
    /// SQL supplied as a positional operand to `bq query`.
    ///
    /// There is deliberately no `file_values` sibling: unlike `snow sql -f`,
    /// `bq query` has no flag that names a SQL file. Reading SQL from a file
    /// is spelled `bq query < file.sql`, a shell redirect, which arrives here
    /// as `reads_stdin_as_code`. An always-empty field would read as coverage
    /// while providing none.
    pub query_values: Vec<&'a str>,
    /// Whether stdin carries executable SQL.
    pub reads_stdin_as_code: bool,
    /// Why argv analysis must fail closed, if option arity was ambiguous.
    pub unverified_reason: Option<&'static str>,
}

impl BqCliAnalysis<'_> {
    /// True when the argv vector is a SQL-bearing `bq` invocation.
    ///
    /// Part of the analysis contract, mirroring `SnowSqlCliAnalysis`. Snowflake
    /// additionally consumes its version from a dialect-aware argv recovery
    /// layer (PowerShell call operators, dynamic executables, CLI size
    /// budgets) that is deliberately NOT ported here — see the module note on
    /// scope. Without that layer bq SQL is still scanned, because the
    /// `GoogleSQL` rules match the raw command text; what is missing is only
    /// the extra depth of recovering argv under exotic dialect spellings.
    #[must_use]
    pub fn is_sql_command(&self) -> bool {
        !self.query_values.is_empty()
            || self.reads_stdin_as_code
            || self.unverified_reason.is_some()
    }
}

const AMBIGUOUS_OPTION_REASON: &str = "bq received an unknown option whose operand arity cannot be proven, so a later SQL operand \
     cannot be ruled out";

/// `bq` global and `query` options that consume a following value.
///
/// Deliberately conservative: an option missing from this list is treated as
/// unknown and fails closed rather than silently skipping a token that might
/// be a `DROP`.
const VALUE_OPTIONS: &[&str] = &[
    "project_id",
    "dataset_id",
    "location",
    "job_id",
    "max_rows",
    "maximum_bytes_billed",
    "destination_table",
    "destination_schema",
    "schema",
    "label",
    "parameter",
    "time_partitioning_field",
    "time_partitioning_type",
    "time_partitioning_expiration",
    "clustering_fields",
    "range_partitioning",
    "schema_update_option",
    "source_format",
    "field_delimiter",
    "encoding",
    "format",
    "api",
    "job_property",
    "max_time_travel_hours",
    "default_table_expiration",
    "default_partition_expiration",
    "expiration",
    "description",
    "transfer_config",
    "reservation_id",
    "slots",
    "external_table_definition",
    // `--apilog <file>` takes a path. `--headless` is boolean and lives in
    // FLAG_OPTIONS; swapping the two made phase 1 eat the `query` subcommand
    // as an operand and return an inert analysis.
    "apilog",
    "flagfile",
    // Documented short options that take a value.
    "n",
];

/// `bq` options that take no value.
const FLAG_OPTIONS: &[&str] = &[
    "use_legacy_sql",
    "nouse_legacy_sql",
    "dry_run",
    "batch",
    "append_table",
    "replace",
    "force",
    "recursive",
    "quiet",
    "sync",
    "nosync",
    "rpc",
    "debug_mode",
    "headless",
    "fingerprint_job_id",
    "require_partition_filter",
    "norequire_partition_filter",
    // Documented short options that take no value.
    "q",
];

/// How many operands a `--long` option consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LongOption {
    /// Consumes no operand.
    Flag,
    /// Consumes the following token (unless attached with `=`).
    Value,
    /// Arity unknown — callers must fail closed.
    Unknown,
}

/// Classify one `--long` option name (the part before any `=`).
///
/// Flags are checked BEFORE values, and the `no` prefix is only stripped when
/// the remainder is itself a known flag. Getting this backwards is a
/// fail-open bug: reading `--nolocation` as `--location <value>` would consume
/// the following token, and that token can be the SQL.
fn classify_long_option(name: &str) -> LongOption {
    if FLAG_OPTIONS.contains(&name) {
        return LongOption::Flag;
    }
    // bq spells a boolean's negative as `--noFLAG` (`--nosync`,
    // `--nouse_legacy_sql`). Only a known flag may be un-negated this way.
    if let Some(rest) = name.strip_prefix("no")
        && FLAG_OPTIONS.contains(&rest)
    {
        return LongOption::Flag;
    }
    if VALUE_OPTIONS.contains(&name) {
        return LongOption::Value;
    }
    LongOption::Unknown
}

/// Split an option token into its name and any `=`-attached value.
///
/// bq uses absl flags, which accept `-flag` and `--flag` interchangeably, so
/// one leading dash is stripped the same as two. Returns `None` for a token
/// that is not an option (including a bare `-`, which is a stdin operand).
fn split_option_token(arg: &str) -> Option<(&str, Option<&str>)> {
    let body = arg.strip_prefix("--").or_else(|| arg.strip_prefix('-'))?;
    if body.is_empty() {
        return None;
    }
    Some(
        body.split_once('=')
            .map_or((body, None), |(name, value)| (name, Some(value))),
    )
}

/// Parse arguments after the `bq` executable and identify executable SQL.
///
/// Unknown options fail closed: their arity can hide a later SQL operand, so
/// the remaining tokens become code operands and stdin is marked code-bearing
/// rather than assuming the invocation is inert.
#[must_use]
pub fn analyze_bq_args(args: &[String]) -> BqCliAnalysis<'_> {
    let mut analysis = BqCliAnalysis::default();

    // Both phases share this so they cannot drift apart.
    let fail_closed = |analysis: &mut BqCliAnalysis<'_>| {
        analysis.unverified_reason = Some(AMBIGUOUS_OPTION_REASON);
        analysis.reads_stdin_as_code = true;
    };

    // Phase 1: walk global options until the subcommand word.
    //
    // `-v` is deliberately NOT treated as `--version` here: several CLIs spell
    // verbose that way, and guessing wrong would return an inert analysis for
    // a command that does carry SQL. An unrecognized option fails closed.
    let mut index = 0usize;
    let subcommand_index = loop {
        let Some(arg) = args.get(index) else {
            return BqCliAnalysis::default();
        };
        if matches!(arg.as_str(), "--help" | "-h" | "--version") {
            return BqCliAnalysis::default();
        }
        // A bare `--` before any subcommand is a malformed invocation whose
        // remaining shape cannot be proven. `split_option_token` returns None
        // for it, which would otherwise make it break out as the "subcommand"
        // and yield an inert analysis.
        if arg == "--" {
            fail_closed(&mut analysis);
            return analysis;
        }
        if let Some((name, attached)) = split_option_token(arg) {
            match classify_long_option(name) {
                LongOption::Flag => index += 1,
                LongOption::Value => {
                    if attached.is_some() {
                        index += 1;
                    } else {
                        // A value option with no operand left cannot be
                        // proven inert either.
                        if args.get(index + 1).is_none() {
                            fail_closed(&mut analysis);
                            return analysis;
                        }
                        index += 2;
                    }
                }
                LongOption::Unknown => {
                    fail_closed(&mut analysis);
                    return analysis;
                }
            }
            continue;
        }
        break index;
    };

    // Only `bq query` carries SQL. Everything else is argv-shaped and handled
    // by the executable-scoped CLI rules.
    if args.get(subcommand_index).map(String::as_str) != Some("query") {
        return BqCliAnalysis::default();
    }

    // Phase 2: walk `query` options collecting SQL operands.
    let mut explicit_source = false;
    // After a bare `--`, every remaining token is an operand, never an option.
    let mut options_terminated = false;
    index = subcommand_index + 1;
    while index < args.len() {
        let arg = &args[index];
        if !options_terminated && arg == "--" {
            options_terminated = true;
            index += 1;
            continue;
        }
        if !options_terminated && matches!(arg.as_str(), "--help" | "-h") {
            // Never discard SQL already proven present: `bq query "DROP ..."
            // --help` still put the statement on the command line.
            if analysis.query_values.is_empty() && !analysis.reads_stdin_as_code {
                return BqCliAnalysis::default();
            }
            return analysis;
        }
        // Deliberately NOT gated on `options_terminated`: `--` ends OPTION
        // parsing, but a bare `-` is bq's stdin operand either way, so
        // `bq query -- -` still reads the statement from stdin rather than
        // executing the literal string "-".
        if arg == "-" {
            analysis.reads_stdin_as_code = true;
            explicit_source = true;
            index += 1;
            continue;
        }
        if let Some((name, attached)) = split_option_token(arg).filter(|_| !options_terminated) {
            match classify_long_option(name) {
                LongOption::Flag => index += 1,
                LongOption::Value => {
                    if attached.is_some() {
                        index += 1;
                    } else {
                        if args.get(index + 1).is_none() {
                            fail_closed(&mut analysis);
                            return analysis;
                        }
                        index += 2;
                    }
                }
                LongOption::Unknown => {
                    fail_closed(&mut analysis);
                    return analysis;
                }
            }
            continue;
        }
        // A bare positional operand to `bq query` is the SQL text.
        analysis.query_values.push(arg.as_str());
        explicit_source = true;
        index += 1;
    }

    // `bq query` with no positional SQL reads the statement from stdin.
    if !explicit_source {
        analysis.reads_stdin_as_code = true;
    }
    analysis
}

/// Create the `BigQuery` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "database.bigquery".to_string(),
        name: "BigQuery",
        description: "Protects the `bq` CLI and GoogleSQL against dataset drops, table \
                      overwrites, unfiltered DML, and settings that shorten the time-travel \
                      recovery window",
        // Keyword matching is ASCII-case-insensitive, so one spelling per
        // token. Deliberately NOT bare `REPLACE` or `MERGE`: those match
        // `s.replace(...)` and `git merge`, which would make this pack a
        // candidate for indirect-input analysis on unrelated commands.
        keywords: &[
            "bq",
            "bigquery",
            "DROP",
            "TRUNCATE",
            "DELETE",
            "UPDATE",
            "ALTER",
            "OVERWRITE",
            "OR REPLACE",
            "NOT MATCHED",
        ],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // A safe first statement must never whitelist a destructive later one, so
    // there are no whole-command safe regexes here.
    Vec::new()
}

/// Suggestions shared by the rules whose recovery path is time travel.
const TIME_TRAVEL_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "bq cp <dataset>.<table>@<epoch_ms> <dataset>.<table>_backup",
        "Snapshot the table from time travel before changing it",
    ),
    PatternSuggestion::new(
        "bq show --format=prettyjson <dataset>.<table>",
        "Confirm which table you are about to act on",
    ),
];

#[allow(clippy::too_many_lines)]
fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // ---------------------------------------------------------------
        // bq CLI. Two independent layers keep these off other commands:
        //
        //   1. `executables = ["bq"]` — the evaluator only consults these
        //      once the resolved argv0 really is `bq` (#289-B).
        //   2. A `bq`-anchored regex prefix — because `executables` scoping
        //      lives in the evaluator, NOT in `Pack::check`. Without the
        //      anchor a bare `\brm\b` matches `git rm old_file.txt` at the
        //      pack level, which is what any caller of `pack.check()` sees.
        //
        // Specific rules come first: the pack returns the FIRST matching
        // pattern, so a generic `bq rm` above `bq rm -r` would swallow it.
        // ---------------------------------------------------------------
        destructive_pattern!(
            "bq-rm-recursive",
            r"(?:^|[\s;&|(])(?:[^\s;&|]*[/\\])?bq(?:\.exe)?(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+rm\b(?:\s+[^\s;&|]+)*\s+(?:-r\b|-{1,2}recursive\b)",
            "bq rm -r deletes a dataset and every table, view, and routine inside it.",
            Critical,
            "Recursive removal deletes the dataset together with all of its contents in one \
             call. Individual tables can sometimes be recovered from time travel within \
             2-7 days, but the dataset itself cannot be restored once dropped.\n\n\
             Inspect the contents first:\n  \
             bq ls <project>:<dataset>",
            &const {
                [
                    PatternSuggestion::new(
                        "bq ls <project>:<dataset>",
                        "List what the recursive delete would take with it",
                    ),
                    PatternSuggestion::new(
                        "bq rm <project>:<dataset>.<table>",
                        "Remove one table at a time instead",
                    ),
                ]
            },
            executables = ["bq"]
        ),
        destructive_pattern!(
            "bq-rm-transfer-config",
            r"(?:^|[\s;&|(])(?:[^\s;&|]*[/\\])?bq(?:\.exe)?(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+rm\b(?:\s+[^\s;&|]+)*\s+-{1,2}transfer_config\b",
            "bq rm --transfer_config deletes a scheduled query or data transfer.",
            High,
            "Removing a transfer config stops the scheduled load or query silently — the \
             next run simply never happens, and the schedule, destination, and parameters \
             are gone with it.\n\n\
             Record the config before removing it:\n  \
             bq show --transfer_config <resource-name>",
            &const {
                [PatternSuggestion::new(
                    "bq show --transfer_config <resource-name>",
                    "Capture the schedule and parameters first",
                )]
            },
            executables = ["bq"]
        ),
        destructive_pattern!(
            "bq-rm-reservation",
            r"(?:^|[\s;&|(])(?:[^\s;&|]*[/\\])?bq(?:\.exe)?(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+rm\b(?:\s+[^\s;&|]+)*\s+-{1,2}(?:reservation|capacity_commitment|reservation_assignment)\b",
            "bq rm --reservation removes purchased capacity and can change query cost and performance.",
            High,
            "Reservations and capacity commitments are billing objects. Removing one moves \
             the affected workloads onto on-demand pricing, which changes both cost and \
             concurrency behaviour immediately.\n\n\
             Inspect the reservation first:\n  \
             bq show --reservation --location=<location> <name>",
            &const {
                [PatternSuggestion::new(
                    "bq ls --reservation --location=<location>",
                    "Confirm which reservation the name refers to",
                )]
            },
            executables = ["bq"]
        ),
        destructive_pattern!(
            "bq-rm",
            r"(?:^|[\s;&|(])(?:[^\s;&|]*[/\\])?bq(?:\.exe)?(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+rm\b",
            "bq rm deletes a table, view, model, or dataset.",
            High,
            "Deletion is immediate. A table may be recoverable from time travel within the \
             dataset's window (2-7 days) using the `@<epoch_ms>` decorator, but only if \
             nothing recreates the name in the meantime; datasets and models have no such \
             recovery.\n\n\
             Confirm the target first:\n  \
             bq show <project>:<dataset>.<table>",
            TIME_TRAVEL_SUGGESTIONS,
            executables = ["bq"]
        ),
        destructive_pattern!(
            "bq-load-replace",
            r"(?:^|[\s;&|(])(?:[^\s;&|]*[/\\])?bq(?:\.exe)?(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+load\b(?:\s+[^\s;&|]+)*\s+-{1,2}replace\b",
            "bq load --replace overwrites all existing data in the destination table.",
            High,
            "`--replace` truncates the destination table before loading. If the source file \
             is wrong, short, or malformed, the previous contents are already gone and only \
             time travel can recover them.\n\n\
             Safer alternative:\n\
             - bq load --noreplace: append instead of overwriting\n\
             - load into a staging table first, then swap",
            &const {
                [
                    PatternSuggestion::new(
                        "bq load --noreplace ...",
                        "Append rather than overwrite the destination",
                    ),
                    PatternSuggestion::new(
                        "bq load <dataset>.<table>_staging ...",
                        "Load into a staging table and verify before swapping",
                    ),
                ]
            },
            executables = ["bq"]
        ),
        destructive_pattern!(
            "bq-query-replace",
            r"(?:^|[\s;&|(])(?:[^\s;&|]*[/\\])?bq(?:\.exe)?(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+query\b(?:\s+[^\s;&|]+)*\s+-{1,2}replace\b",
            "bq query --replace overwrites the destination table with the query result.",
            High,
            "`--replace` discards the destination table's current contents before writing \
             the result. A query that returns fewer rows than expected silently destroys \
             the difference.\n\n\
             Safer alternative:\n\
             - bq query --append_table: add rows instead of replacing them\n\
             - bq query --dry_run: check what the query would process first",
            &const {
                [
                    PatternSuggestion::new(
                        "bq query --dry_run ...",
                        "Validate the query without writing anything",
                    ),
                    PatternSuggestion::new(
                        "bq query --append_table ...",
                        "Append to the destination instead of replacing it",
                    ),
                ]
            },
            executables = ["bq"]
        ),
        destructive_pattern!(
            "bq-cp-force",
            r"(?:^|[\s;&|(])(?:[^\s;&|]*[/\\])?bq(?:\.exe)?(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+cp\b(?:\s+[^\s;&|]+)*\s+(?:-f\b|-{1,2}force\b)",
            "bq cp -f overwrites the destination table without prompting.",
            High,
            "`-f` suppresses the overwrite confirmation, so an existing destination table is \
             replaced silently. Copying onto the wrong destination is not detectable after \
             the fact except through time travel.\n\n\
             Check whether the destination already exists:\n  \
             bq show <project>:<dataset>.<table>",
            TIME_TRAVEL_SUGGESTIONS,
            executables = ["bq"]
        ),
        destructive_pattern!(
            "bq-mk-force",
            r"(?:^|[\s;&|(])(?:[^\s;&|]*[/\\])?bq(?:\.exe)?(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+mk\b(?:\s+[^\s;&|]+)*\s+(?:-f\b|-{1,2}force\b)",
            "bq mk -f overwrites an existing table definition.",
            Medium,
            "`bq mk -f` succeeds when the object already exists, replacing its definition \
             rather than failing. Recreating a table this way drops the existing rows.\n\n\
             Check first:\n  \
             bq show <project>:<dataset>.<table>",
            &const {
                [PatternSuggestion::new(
                    "bq show <project>:<dataset>.<table>",
                    "Confirm whether the object already exists",
                )]
            },
            executables = ["bq"]
        ),
        destructive_pattern!(
            "bq-update-time-travel",
            r"(?:^|[\s;&|(])(?:[^\s;&|]*[/\\])?bq(?:\.exe)?(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+update\b(?:\s+[^\s;&|]+)*\s+-{1,2}max_time_travel_hours\b",
            "bq update --max_time_travel_hours shortens the only window in which deleted BigQuery data can be recovered.",
            High,
            "Time travel (48-168 hours) is BigQuery's only undo. Lowering it discards \
             history immediately and irreversibly: data older than the new window cannot be \
             recovered afterwards, including data you have not yet noticed is missing. This \
             destroys the recovery path itself rather than any single table.\n\n\
             Take a snapshot before shortening the window:\n  \
             bq cp <dataset>.<table>@<epoch_ms> <dataset>.<table>_backup",
            TIME_TRAVEL_SUGGESTIONS,
            executables = ["bq"]
        ),
        destructive_pattern!(
            "bq-update-expiration",
            r"(?:^|[\s;&|(])(?:[^\s;&|]*[/\\])?bq(?:\.exe)?(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+update\b(?:\s+[^\s;&|]+)*\s+-{1,2}(?:expiration|default_table_expiration|default_partition_expiration)\b",
            "bq update --expiration schedules automatic deletion of tables or partitions.",
            High,
            "An expiration is a deferred delete. Setting one on a dataset applies to tables \
             created afterwards; setting one on a table schedules that table's removal. The \
             deletion happens later, without a prompt, and is easy to forget was configured.\n\n\
             Inspect the current setting:\n  \
             bq show --format=prettyjson <project>:<dataset>",
            &const {
                [PatternSuggestion::new(
                    "bq show --format=prettyjson <project>:<dataset>",
                    "See the current expiration before changing it",
                )]
            },
            executables = ["bq"]
        ),
        destructive_pattern!(
            "bq-cancel",
            r"(?:^|[\s;&|(])(?:[^\s;&|]*[/\\])?bq(?:\.exe)?(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+cancel\b",
            "bq cancel stops a running job, which may leave a partial load or export.",
            Medium,
            "Cancelling a load or export mid-flight can leave the destination in a partial \
             state: some files written, some rows loaded. Check what the job is doing before \
             stopping it.\n\n\
             Inspect the job first:\n  \
             bq show --job=true <job-id>",
            &const {
                [PatternSuggestion::new(
                    "bq show --job=true <job-id>",
                    "See what the job is doing before cancelling it",
                )]
            },
            executables = ["bq"]
        ),
        // ---------------------------------------------------------------
        // GoogleSQL. Unscoped: SQL arrives via files, pipes, and heredocs
        // as well as `bq query` operands.
        // ---------------------------------------------------------------
        destructive_pattern!(
            "drop-schema",
            r"(?i)\bDROP\s+(?:SCHEMA|DATABASE)\b",
            "DROP SCHEMA removes a BigQuery dataset and everything inside it.",
            Critical,
            "In GoogleSQL a *dataset* is a SCHEMA, so this is the dataset-level catastrophe \
             rather than a namespace tidy-up. With CASCADE it removes every table, view, and \
             routine in the dataset. Individual tables may be recoverable from time travel \
             for 2-7 days; the dataset is not.\n\n\
             List the contents first:\n  \
             bq ls <project>:<dataset>",
            &const {
                [PatternSuggestion::new(
                    "bq ls <project>:<dataset>",
                    "List what the drop would take with it",
                )]
            }
        ),
        destructive_pattern!(
            "drop-snapshot-table",
            r"(?i)\bDROP\s+SNAPSHOT\s+TABLE\b",
            "DROP SNAPSHOT TABLE destroys a point-in-time backup.",
            Critical,
            "A table snapshot is often the backup taken precisely because time travel is too \
             short. Dropping it removes the recovery point itself, and unlike the source \
             table it has no time-travel window of its own.",
            &const {
                [PatternSuggestion::new(
                    "SELECT * FROM `<project>.<dataset>.INFORMATION_SCHEMA.TABLES` WHERE table_type = 'SNAPSHOT'",
                    "Confirm which snapshots exist before dropping one",
                )]
            }
        ),
        destructive_pattern!(
            "drop-materialized-view-or-external-table",
            r"(?i)\bDROP\s+(?:MATERIALIZED\s+VIEW|EXTERNAL\s+TABLE)\b",
            "DROP MATERIALIZED VIEW / EXTERNAL TABLE removes a derived or federated object.",
            Medium,
            "A materialized view holds precomputed data that must be rebuilt, which costs a \
             full refresh; an external table definition carries the schema and source URIs \
             needed to read the underlying files. Neither the data nor the definition is \
             recoverable from time travel.",
            &const {
                [PatternSuggestion::new(
                    "SELECT ddl FROM `<project>.<dataset>.INFORMATION_SCHEMA.TABLES` WHERE table_name = '<name>'",
                    "Capture the DDL before dropping it",
                )]
            }
        ),
        destructive_pattern!(
            "drop-routine",
            r"(?i)\bDROP\s+(?:TABLE\s+FUNCTION|FUNCTION|PROCEDURE)\b",
            "DROP FUNCTION/PROCEDURE/TABLE FUNCTION removes a routine other queries may depend on.",
            High,
            "Routine definitions are not covered by time travel. Anything calling the routine \
             — scheduled queries, views, downstream jobs — starts failing at its next run.\n\n\
             Capture the definition first:\n  \
             SELECT ddl FROM `<project>.<dataset>.INFORMATION_SCHEMA.ROUTINES`",
            &const {
                [PatternSuggestion::new(
                    "SELECT ddl FROM `<project>.<dataset>.INFORMATION_SCHEMA.ROUTINES` WHERE routine_name = '<name>'",
                    "Save the routine definition before dropping it",
                )]
            }
        ),
        destructive_pattern!(
            "drop-model",
            r"(?i)\bDROP\s+MODEL\b",
            "DROP MODEL deletes a trained BigQuery ML model.",
            High,
            "A model is not covered by time travel and cannot be restored — rebuilding it \
             means re-running training over the original data, which costs both money and \
             hours, and reproduces the result only if that training data still exists in \
             the same form.\n\n\
             Copy it first:\n  \
             bq cp <dataset>.<model> <dataset>.<model>_backup",
            &const {
                [PatternSuggestion::new(
                    "bq cp <dataset>.<model> <dataset>.<model>_backup",
                    "Copy the trained model before dropping it",
                )]
            }
        ),
        destructive_pattern!(
            "drop-all-row-access-policies",
            r"(?i)\bDROP\s+(?:ALL\s+ROW\s+ACCESS\s+POLICIES|ROW\s+ACCESS\s+POLICY)\b",
            "DROP ROW ACCESS POLICY removes row-level security from a table.",
            High,
            "This does not delete data — it exposes it. Every row previously filtered by a \
             policy becomes visible to anyone with table access, which is a disclosure event \
             rather than a data-loss one, and it is silent.",
            &const {
                [PatternSuggestion::new(
                    "SELECT * FROM `<project>.<dataset>.INFORMATION_SCHEMA.ROW_ACCESS_POLICIES`",
                    "Record the policies before removing them",
                )]
            }
        ),
        destructive_pattern!(
            "drop-search-index",
            r"(?i)\bDROP\s+(?:SEARCH|VECTOR)\s+INDEX\b",
            "DROP SEARCH INDEX removes an index that must be fully rebuilt.",
            Medium,
            "Rebuilding a search or vector index over a large table is expensive and not \
             instantaneous; queries relying on it degrade to full scans in the meantime.",
            &const {
                [PatternSuggestion::new(
                    "SELECT * FROM `<project>.<dataset>.INFORMATION_SCHEMA.SEARCH_INDEXES`",
                    "Confirm which index the name refers to",
                )]
            }
        ),
        destructive_pattern!(
            "drop-capacity-or-reservation",
            r"(?i)\bDROP\s+(?:CAPACITY|RESERVATION|ASSIGNMENT)\b",
            "DROP CAPACITY/RESERVATION/ASSIGNMENT changes billing and query capacity.",
            High,
            "These are billing objects. Dropping one moves affected workloads to on-demand \
             pricing immediately, changing both cost and concurrency.",
            &const {
                [PatternSuggestion::new(
                    "SELECT * FROM `<project>.region-<region>.INFORMATION_SCHEMA.RESERVATIONS`",
                    "Confirm the reservation before dropping it",
                )]
            }
        ),
        destructive_pattern!(
            "drop-view",
            r"(?i)\bDROP\s+VIEW\b",
            "DROP VIEW removes a view definition.",
            Medium,
            "View definitions are not covered by time travel. Downstream queries and \
             dashboards referencing the view break at their next run.\n\n\
             Capture the definition first:\n  \
             SELECT view_definition FROM `<project>.<dataset>.INFORMATION_SCHEMA.VIEWS`",
            &const {
                [PatternSuggestion::new(
                    "SELECT view_definition FROM `<project>.<dataset>.INFORMATION_SCHEMA.VIEWS` WHERE table_name = '<name>'",
                    "Save the view definition before dropping it",
                )]
            }
        ),
        // Generic DROP TABLE last among the DROP rules: `DROP SNAPSHOT TABLE`
        // and `DROP TABLE FUNCTION` must reach their specific rules first.
        destructive_pattern!(
            "drop-table",
            r"(?i)\bDROP\s+TABLE\b",
            "DROP TABLE removes a table and its data.",
            High,
            "The table may be recoverable from time travel within the dataset's window \
             (2-7 days) via `<table>@<epoch_ms>`, but only if nothing recreates the name in \
             the meantime — recreating it starts a fresh history and forecloses recovery.\n\n\
             Snapshot before dropping:\n  \
             bq cp <dataset>.<table>@<epoch_ms> <dataset>.<table>_backup",
            TIME_TRAVEL_SUGGESTIONS
        ),
        destructive_pattern!(
            "alter-table-drop-column",
            r"(?i)\bALTER\s+TABLE\b[^;]{0,200}?\bDROP\s+COLUMN\b",
            "ALTER TABLE DROP COLUMN removes a column and its data.",
            High,
            "Dropping a column deletes its values. Time travel recovers the whole table to a \
             prior point rather than restoring one column, so recovery means reconstructing \
             the table.",
            TIME_TRAVEL_SUGGESTIONS
        ),
        destructive_pattern!(
            "alter-set-expiration",
            r"(?i)\bALTER\s+(?:TABLE|SCHEMA|MATERIALIZED\s+VIEW)\b[^;]{0,200}?\bSET\s+OPTIONS\b[^;]{0,200}?\bexpiration_timestamp\b",
            "SET OPTIONS(expiration_timestamp) schedules automatic deletion.",
            High,
            "An expiration timestamp is a deferred delete: the object disappears at that time \
             with no further prompt. Setting it in the past deletes immediately.",
            &const {
                [PatternSuggestion::new(
                    "ALTER TABLE `<t>` SET OPTIONS(expiration_timestamp = NULL)",
                    "Clear an expiration instead of setting one",
                )]
            }
        ),
        destructive_pattern!(
            "alter-table-rename",
            r"(?i)\bALTER\s+TABLE\b[^;]{0,200}?\bRENAME\s+TO\b",
            "ALTER TABLE RENAME TO breaks every reference to the old table name.",
            Medium,
            "Renaming is not itself data loss, but views, scheduled queries, and downstream \
             jobs referencing the old name fail at their next run, and a later `CREATE TABLE` \
             reusing the old name makes the break silent.",
            &const {
                [PatternSuggestion::new(
                    "SELECT * FROM `<project>.<dataset>.INFORMATION_SCHEMA.VIEWS` WHERE view_definition LIKE '%<name>%'",
                    "Find references before renaming",
                )]
            }
        ),
        destructive_pattern!(
            "create-or-replace-routine",
            r"(?i)\bCREATE\s+OR\s+REPLACE\s+(?:TABLE\s+FUNCTION|FUNCTION|PROCEDURE|MODEL)\b",
            "CREATE OR REPLACE FUNCTION/PROCEDURE overwrites an existing routine definition.",
            Medium,
            "The previous definition is discarded with no version history. If the new body is \
             wrong, the old one must be reconstructed from source control or memory.",
            &const {
                [PatternSuggestion::new(
                    "SELECT ddl FROM `<project>.<dataset>.INFORMATION_SCHEMA.ROUTINES` WHERE routine_name = '<name>'",
                    "Save the current definition before replacing it",
                )]
            }
        ),
        destructive_pattern!(
            "create-or-replace-table",
            r"(?i)\bCREATE\s+OR\s+REPLACE\s+(?:MATERIALIZED\s+VIEW|EXTERNAL\s+TABLE|SNAPSHOT\s+TABLE|TEMP(?:ORARY)?\s+TABLE|TABLE|VIEW)\b",
            "CREATE OR REPLACE TABLE discards the existing table and its data.",
            High,
            "This is a drop and recreate in one statement: the old rows are gone before the \
             new ones are written. A query that produces fewer rows than expected destroys \
             the difference silently.\n\n\
             Safer alternative:\n\
             - CREATE TABLE IF NOT EXISTS: fails instead of overwriting\n\
             - write to a staging table and swap after verifying",
            TIME_TRAVEL_SUGGESTIONS
        ),
        destructive_pattern!(
            "load-data-overwrite",
            r"(?i)\bLOAD\s+DATA\s+OVERWRITE\b",
            "LOAD DATA OVERWRITE replaces all existing data in the destination table.",
            High,
            "`OVERWRITE` truncates the destination before loading. If the source is wrong or \
             short, the previous contents are already gone.\n\n\
             Safer alternative:\n\
             - LOAD DATA INTO: append instead of replacing",
            &const {
                [PatternSuggestion::new(
                    "LOAD DATA INTO `<project>.<dataset>.<table>` ...",
                    "Append rather than overwrite",
                )]
            }
        ),
        destructive_pattern!(
            "export-data-overwrite",
            r"(?i)\bEXPORT\s+DATA\b[^;]{0,200}?\boverwrite\s*=\s*true",
            "EXPORT DATA with overwrite=true replaces files at the destination URI.",
            Medium,
            "Existing objects under the destination prefix in Cloud Storage are replaced. If \
             the bucket is not versioned, the previous export is unrecoverable.",
            &const {
                [PatternSuggestion::new(
                    "gcloud storage ls <destination-uri>",
                    "See what is already at the destination first",
                )]
            }
        ),
        destructive_pattern!(
            "truncate-table",
            r"(?i)\bTRUNCATE\s+TABLE\b",
            "TRUNCATE TABLE removes every row in the table.",
            High,
            "All rows are deleted while the schema stays in place. Recovery is time travel \
             only, within the dataset's 2-7 day window.",
            TIME_TRAVEL_SUGGESTIONS
        ),
        // GoogleSQL REQUIRES a WHERE clause on DELETE/UPDATE, so `WHERE TRUE`
        // is the idiomatic full-table spelling. A rule modelled on PostgreSQL's
        // missing-WHERE shape would never fire here.
        destructive_pattern!(
            "delete-all-rows",
            r"(?i)\bDELETE\s+(?:FROM\s+)?[^\s;]+(?:\s+(?:AS\s+)?[A-Za-z_][A-Za-z0-9_]*)?\s+WHERE\s+(?:TRUE|1\s*=\s*1)\b",
            "DELETE ... WHERE TRUE removes every row in the table.",
            High,
            "In GoogleSQL a WHERE clause is mandatory on DELETE, so `WHERE TRUE` is the \
             idiomatic way to spell \"delete everything\" — it is a full-table delete, not a \
             filtered one. Recovery is time travel only.\n\n\
             Check the blast radius first:\n  \
             SELECT COUNT(*) FROM `<table>` WHERE <your-predicate>",
            TIME_TRAVEL_SUGGESTIONS
        ),
        destructive_pattern!(
            "update-all-rows",
            r"(?i)\bUPDATE\s+[^\s;]+(?:\s+(?:AS\s+)?[A-Za-z_][A-Za-z0-9_]*)?\s+SET\b[^;]{0,4000}?\bWHERE\s+(?:TRUE|1\s*=\s*1)\b",
            "UPDATE ... WHERE TRUE rewrites every row in the table.",
            High,
            "`WHERE TRUE` is the idiomatic full-table spelling in GoogleSQL, where the WHERE \
             clause is mandatory. Every row is rewritten, and the prior values are recoverable \
             only through time travel.\n\n\
             Check the blast radius first:\n  \
             SELECT COUNT(*) FROM `<table>` WHERE <your-predicate>",
            TIME_TRAVEL_SUGGESTIONS
        ),
        destructive_pattern!(
            "merge-delete-not-matched-by-source",
            r"(?i)\bMERGE\b[^;]{0,4000}?\bWHEN\s+NOT\s+MATCHED\s+BY\s+SOURCE\b[^;]{0,400}?\bTHEN\s+DELETE\b",
            "MERGE ... WHEN NOT MATCHED BY SOURCE THEN DELETE removes every target row absent from the source.",
            High,
            "The delete is driven by what the source query returns. If the source is empty, \
             filtered, or partially loaded, this deletes most or all of the target table — \
             and the statement looks routine in review.\n\n\
             Check what the source actually returns first:\n  \
             SELECT COUNT(*) FROM (<source-query>)",
            TIME_TRAVEL_SUGGESTIONS
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::{
        assert_blocks_with_pattern, assert_blocks_with_severity, assert_no_match, validate_pack,
    };

    #[test]
    fn test_pack_creation() {
        validate_pack(&create_pack());
    }

    #[test]
    fn bq_cli_destructive_variants_block() {
        let pack = create_pack();
        for (command, expected) in [
            ("bq rm -r -f my_project:my_dataset", "bq-rm-recursive"),
            ("bq rm --recursive my_dataset", "bq-rm-recursive"),
            (
                "bq rm --transfer_config projects/p/locations/us/transferConfigs/abc",
                "bq-rm-transfer-config",
            ),
            (
                "bq rm --reservation --location=US my-reservation",
                "bq-rm-reservation",
            ),
            ("bq rm my_dataset.my_table", "bq-rm"),
            (
                "bq load --replace my_dataset.t gs://bucket/f.csv",
                "bq-load-replace",
            ),
            (
                "bq query --replace --destination_table d.t 'SELECT 1'",
                "bq-query-replace",
            ),
            ("bq cp -f d.src d.dst", "bq-cp-force"),
            ("bq mk -f --table d.t", "bq-mk-force"),
            (
                "bq update --max_time_travel_hours 48 my_dataset",
                "bq-update-time-travel",
            ),
            (
                "bq update --default_table_expiration 3600 my_dataset",
                "bq-update-expiration",
            ),
            ("bq cancel job_12345", "bq-cancel"),
        ] {
            assert_blocks_with_pattern(&pack, command, expected);
        }
    }

    /// The pack returns the first matching pattern in vec order, so the
    /// generic catch-alls must sort below their specific siblings.
    #[test]
    fn specific_rm_rules_are_not_shadowed_by_generic_rm() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "bq rm -r my_dataset", "bq-rm-recursive");
        assert_blocks_with_pattern(
            &pack,
            "bq rm --transfer_config abc",
            "bq-rm-transfer-config",
        );
        assert_blocks_with_pattern(&pack, "bq rm --reservation r", "bq-rm-reservation");
    }

    #[test]
    fn googlesql_destructive_variants_block() {
        let pack = create_pack();
        for (command, expected) in [
            ("DROP SCHEMA my_dataset CASCADE", "drop-schema"),
            ("drop database my_dataset", "drop-schema"),
            ("DROP SNAPSHOT TABLE d.snap", "drop-snapshot-table"),
            ("DROP TABLE FUNCTION d.tf", "drop-routine"),
            ("DROP FUNCTION d.fn", "drop-routine"),
            ("DROP PROCEDURE d.proc", "drop-routine"),
            (
                "DROP ALL ROW ACCESS POLICIES ON d.t",
                "drop-all-row-access-policies",
            ),
            ("DROP SEARCH INDEX idx ON d.t", "drop-search-index"),
            ("DROP VECTOR INDEX idx ON d.t", "drop-search-index"),
            ("DROP RESERVATION my-res", "drop-capacity-or-reservation"),
            ("DROP VIEW d.v", "drop-view"),
            (
                "DROP MATERIALIZED VIEW d.mv",
                "drop-materialized-view-or-external-table",
            ),
            ("DROP TABLE d.t", "drop-table"),
            ("ALTER TABLE d.t DROP COLUMN c", "alter-table-drop-column"),
            ("ALTER TABLE d.t RENAME TO t2", "alter-table-rename"),
            (
                "CREATE OR REPLACE TABLE d.t AS SELECT 1",
                "create-or-replace-table",
            ),
            (
                "CREATE OR REPLACE FUNCTION d.f() AS (1)",
                "create-or-replace-routine",
            ),
            (
                "LOAD DATA OVERWRITE d.t FROM FILES (uris=['gs://b/f'])",
                "load-data-overwrite",
            ),
            ("TRUNCATE TABLE d.t", "truncate-table"),
            ("DELETE FROM d.t WHERE TRUE", "delete-all-rows"),
            ("delete from d.t where 1 = 1", "delete-all-rows"),
            ("UPDATE d.t SET x = 1 WHERE TRUE", "update-all-rows"),
        ] {
            assert_blocks_with_pattern(&pack, command, expected);
        }
    }

    /// `ALTER TABLE ... SET OPTIONS(expiration_timestamp = ...)` destroys the
    /// recovery path, which is why it is destructive at all.
    #[test]
    fn expiration_and_time_travel_settings_block() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "ALTER TABLE d.t SET OPTIONS(expiration_timestamp = TIMESTAMP '2026-01-01 00:00:00 UTC')",
            "alter-set-expiration",
        );
        assert_blocks_with_severity(
            &pack,
            "bq update --max_time_travel_hours 48 my_dataset",
            Severity::High,
        );
    }

    /// Two-part SQL rules are bounded by `[^;]`, so the halves must come from
    /// the SAME statement. An unbounded `[\s\S]` span would let a harmless
    /// `ALTER TABLE` in one statement pair with a `DROP COLUMN` in another and
    /// report a rule that describes neither.
    #[test]
    fn two_part_sql_rules_do_not_span_statements() {
        let pack = create_pack();

        // Same statement: matches.
        assert_blocks_with_pattern(
            &pack,
            "ALTER TABLE d.t DROP COLUMN c",
            "alter-table-drop-column",
        );

        // Split across statements: alter-table-drop-column must NOT claim it.
        let split = "ALTER TABLE d.t SET OPTIONS(description='x'); SELECT 1; UPDATE other SET DROP COLUMN_LIKE = 1 WHERE id = 2";
        let matched = pack.check(split).and_then(|m| m.name);
        assert_ne!(
            matched,
            Some("alter-table-drop-column"),
            "a DROP COLUMN in a later statement must not pair with an earlier ALTER TABLE"
        );
    }

    #[test]
    fn merge_delete_by_source_blocks() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "MERGE d.target T USING d.source S ON T.id = S.id WHEN NOT MATCHED BY SOURCE THEN DELETE",
            "merge-delete-not-matched-by-source",
        );
    }

    #[test]
    fn dataset_level_drops_are_critical() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "DROP SCHEMA my_dataset CASCADE", Severity::Critical);
        assert_blocks_with_severity(&pack, "DROP SNAPSHOT TABLE d.snap", Severity::Critical);
        assert_blocks_with_severity(&pack, "bq rm -r my_dataset", Severity::Critical);
    }

    /// Regression: the CLI rules were anchored on a bare `bq`, so any
    /// path-qualified or extension-suffixed spelling missed entirely — and
    /// unlike the GoogleSQL rules these have no raw-SQL fallback, so
    /// `./bq rm -r prod` was a total miss of a Critical rule.
    #[test]
    fn path_qualified_bq_still_matches() {
        let pack = create_pack();
        for command in [
            "bq rm -r prod_dataset",
            "./bq rm -r prod_dataset",
            "/usr/bin/bq rm -r prod_dataset",
            "/opt/google-cloud-sdk/bin/bq rm -r prod_dataset",
            "bq.exe rm -r prod_dataset",
            r"C:\gcloud\bin\bq.exe rm -r prod_dataset",
        ] {
            assert_blocks_with_pattern(&pack, command, "bq-rm-recursive");
        }
    }

    /// Regression: GoogleSQL allows a table alias, and generated SQL uses it.
    /// `[^\s;]+\s+WHERE` assumed the table was followed IMMEDIATELY by WHERE,
    /// so an alias bypassed both full-table DML rules.
    #[test]
    fn aliased_tables_do_not_bypass_full_table_dml() {
        let pack = create_pack();
        for command in [
            "DELETE FROM ds.events WHERE TRUE",
            "DELETE FROM `proj.ds.events` AS e WHERE TRUE",
            "DELETE FROM ds.events e WHERE TRUE",
        ] {
            assert_blocks_with_pattern(&pack, command, "delete-all-rows");
        }
        for command in [
            "UPDATE ds.events SET x = 1 WHERE TRUE",
            "UPDATE `proj.ds.events` AS e SET e.x = 1 WHERE TRUE",
            "UPDATE ds.events e SET e.x = 1 WHERE TRUE",
        ] {
            assert_blocks_with_pattern(&pack, command, "update-all-rows");
        }
    }

    /// BigQuery ML models are not covered by time travel and cost real money
    /// and hours to retrain, so they need their own rule.
    #[test]
    fn bigquery_ml_models_are_covered() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "DROP MODEL `proj.ds.churn`", "drop-model");
        assert_blocks_with_pattern(
            &pack,
            "CREATE OR REPLACE MODEL `proj.ds.churn` OPTIONS(model_type='linear_reg') AS SELECT 1",
            "create-or-replace-routine",
        );
        assert_blocks_with_pattern(
            &pack,
            "DROP ROW ACCESS POLICY apac_filter ON ds.events",
            "drop-all-row-access-policies",
        );
    }

    /// `bq` is a two-letter token that appears in prose and other commands.
    /// The CLI rules are `executables = ["bq"]`-scoped precisely so they can
    /// never fire on a command that merely contains those letters.
    #[test]
    fn unrelated_commands_do_not_match() {
        let pack = create_pack();
        for command in [
            "echo bq",
            "cat bq_notes.txt",
            "git rm old_file.txt",
            "rm -rf build",
            "cargo update",
            "sbq --help",
            "ls",
        ] {
            assert_no_match(&pack, command);
        }
    }

    /// Read-only BigQuery work must stay allowed.
    #[test]
    fn read_only_bq_commands_are_allowed() {
        let pack = create_pack();
        for command in [
            "bq ls my_project:my_dataset",
            "bq show my_dataset.my_table",
            "bq query 'SELECT COUNT(*) FROM d.t'",
            "bq query --dry_run 'SELECT 1'",
            "bq head -n 10 d.t",
        ] {
            assert_no_match(&pack, command);
        }
    }

    // -----------------------------------------------------------------
    // analyze_bq_args
    // -----------------------------------------------------------------

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_string()).collect()
    }

    #[test]
    fn analyze_extracts_positional_sql() {
        let args = argv(&["query", "--nouse_legacy_sql", "DROP TABLE d.t"]);
        let analysis = analyze_bq_args(&args);
        assert_eq!(analysis.query_values, vec!["DROP TABLE d.t"]);
        assert!(!analysis.reads_stdin_as_code);
        assert!(analysis.unverified_reason.is_none());
        assert!(analysis.is_sql_command());
    }

    #[test]
    fn analyze_treats_bare_query_as_stdin_code() {
        let args = argv(&["query"]);
        let analysis = analyze_bq_args(&args);
        assert!(analysis.reads_stdin_as_code);
        assert!(analysis.is_sql_command());
    }

    #[test]
    fn analyze_handles_value_options_before_the_subcommand() {
        let args = argv(&["--project_id", "p", "query", "DROP TABLE d.t"]);
        assert_eq!(analyze_bq_args(&args).query_values, vec!["DROP TABLE d.t"]);

        let attached = argv(&["--project_id=p", "query", "DROP TABLE d.t"]);
        assert_eq!(
            analyze_bq_args(&attached).query_values,
            vec!["DROP TABLE d.t"]
        );
    }

    /// An unknown option's arity can hide a later SQL operand, so analysis
    /// fails closed rather than skipping the token.
    #[test]
    fn analyze_fails_closed_on_unknown_options() {
        let args = argv(&["query", "--future_option", "DROP TABLE d.t"]);
        let analysis = analyze_bq_args(&args);
        assert!(analysis.unverified_reason.is_some());
        assert!(analysis.reads_stdin_as_code);
        assert!(analysis.is_sql_command());
    }

    /// Regression: `--noX` must only be un-negated when `X` is a known FLAG.
    /// Stripping `no` before the VALUE lookup made `--nolocation` read as
    /// `--location <value>`, which consumed the following token — and that
    /// token can be the SQL. Fail closed instead.
    #[test]
    fn analyze_does_not_treat_negated_names_as_value_options() {
        assert_eq!(classify_long_option("nosync"), LongOption::Flag);
        assert_eq!(classify_long_option("nouse_legacy_sql"), LongOption::Flag);
        assert_eq!(classify_long_option("location"), LongOption::Value);
        assert_eq!(
            classify_long_option("nolocation"),
            LongOption::Unknown,
            "must not resolve to the VALUE option `location` and eat the next token"
        );

        let args = argv(&["query", "--nolocation", "DROP TABLE d.t"]);
        let analysis = analyze_bq_args(&args);
        assert!(
            analysis.unverified_reason.is_some(),
            "an unknown negated option must fail closed, not swallow the SQL"
        );
        assert!(analysis.query_values.is_empty());
    }

    /// A value option with no operand left cannot be proven inert in either
    /// phase; both must fail closed rather than stepping past the end.
    #[test]
    fn analyze_fails_closed_on_dangling_value_option() {
        for args in [
            argv(&["--project_id"]),
            argv(&["query", "--destination_table"]),
        ] {
            let analysis = analyze_bq_args(&args);
            assert!(
                analysis.unverified_reason.is_some(),
                "dangling value option must fail closed: {args:?}"
            );
        }
    }

    /// `-v` is verbose in several CLIs. Guessing it means `--version` would
    /// return an inert analysis for a command that does carry SQL.
    #[test]
    fn analyze_fails_closed_on_unknown_short_options() {
        let args = argv(&["-v", "query", "DROP TABLE d.t"]);
        let analysis = analyze_bq_args(&args);
        assert!(analysis.unverified_reason.is_some());
        assert!(analysis.reads_stdin_as_code);
    }

    /// bq uses absl flags: `-flag` and `--flag` are interchangeable, and there
    /// are real short options. Treating every single-dash token as unknown
    /// turned documented read-only invocations into unverified envelopes.
    #[test]
    fn analyze_accepts_absl_single_dash_and_short_options() {
        for args in [
            argv(&["-q", "query", "SELECT 1"]),
            argv(&["-project_id=my-proj", "query", "SELECT 1"]),
            argv(&["--project_id=my-proj", "query", "SELECT 1"]),
        ] {
            let analysis = analyze_bq_args(&args);
            assert!(
                analysis.unverified_reason.is_none(),
                "documented flag spelling must not fail closed: {args:?}"
            );
            assert_eq!(analysis.query_values, vec!["SELECT 1"], "{args:?}");
        }

        // `-n` takes a value, so the SQL is the token AFTER the count.
        let args = argv(&["query", "-n", "100", "SELECT 1"]);
        let analysis = analyze_bq_args(&args);
        assert!(analysis.unverified_reason.is_none());
        assert_eq!(analysis.query_values, vec!["SELECT 1"]);
    }

    /// Regression: `--headless` is boolean and `--apilog` takes a path. With
    /// the two swapped, phase 1 consumed `query` as `--headless`'s operand and
    /// returned the INERT default — a known option with the wrong arity was
    /// failing open, unlike an unknown one.
    #[test]
    fn analyze_has_correct_arity_for_headless_and_apilog() {
        assert_eq!(classify_long_option("headless"), LongOption::Flag);
        assert_eq!(classify_long_option("apilog"), LongOption::Value);

        let args = argv(&["--headless", "query", "DROP TABLE d.t"]);
        let analysis = analyze_bq_args(&args);
        assert_eq!(
            analysis.query_values,
            vec!["DROP TABLE d.t"],
            "--headless must not swallow the query subcommand"
        );

        let args = argv(&["--apilog", "/tmp/bq.log", "query", "DROP TABLE d.t"]);
        assert_eq!(analyze_bq_args(&args).query_values, vec!["DROP TABLE d.t"]);
    }

    /// A trailing `--help` must not discard SQL already proven present.
    #[test]
    fn analyze_keeps_sql_collected_before_a_trailing_help() {
        let args = argv(&["query", "DROP TABLE d.t", "--help"]);
        assert_eq!(analyze_bq_args(&args).query_values, vec!["DROP TABLE d.t"]);
    }

    /// The `--` option terminator. `split_option_token` returns None for it,
    /// so without explicit handling phase 1 broke out treating `--` as the
    /// subcommand and returned the INERT default instead of failing closed.
    #[test]
    fn analyze_handles_the_option_terminator() {
        // Before a subcommand: malformed, unprovable, fail closed.
        let args = argv(&["--", "query", "DROP TABLE d.t"]);
        let analysis = analyze_bq_args(&args);
        assert!(
            analysis.unverified_reason.is_some(),
            "a bare -- before the subcommand must fail closed, not read as inert"
        );

        // After `query`: everything following is an operand, and the `--` is
        // not itself SQL.
        let args = argv(&["query", "--", "DROP TABLE d.t"]);
        let analysis = analyze_bq_args(&args);
        assert_eq!(analysis.query_values, vec!["DROP TABLE d.t"]);
        assert!(analysis.unverified_reason.is_none());

        // A token that merely looks like an option is an operand after `--`.
        let args = argv(&["query", "--", "--not-an-option"]);
        assert_eq!(
            analyze_bq_args(&args).query_values,
            vec!["--not-an-option"],
            "after -- nothing is parsed as an option"
        );

        // `--` ends OPTION parsing, but `-` is still the stdin operand, so
        // `echo 'DROP ...' | bq query -- -` must stay attributable.
        let args = argv(&["query", "--", "-"]);
        let analysis = analyze_bq_args(&args);
        assert!(
            analysis.reads_stdin_as_code,
            "a bare - after -- is still bq's stdin operand, not literal SQL"
        );
        assert!(analysis.query_values.is_empty());

        // Terminator with nothing after it still leaves stdin as the source.
        let args = argv(&["query", "--"]);
        assert!(analyze_bq_args(&args).reads_stdin_as_code);
    }

    #[test]
    fn analyze_ignores_non_query_subcommands() {
        assert_eq!(
            analyze_bq_args(&argv(&["ls", "my_dataset"])),
            BqCliAnalysis::default()
        );
        assert!(!analyze_bq_args(&argv(&["rm", "-r", "d"])).is_sql_command());
    }

    #[test]
    fn analyze_ignores_help_and_version() {
        assert_eq!(
            analyze_bq_args(&argv(&["--help"])),
            BqCliAnalysis::default()
        );
        assert_eq!(
            analyze_bq_args(&argv(&["query", "--help"])),
            BqCliAnalysis::default()
        );
    }

    #[test]
    fn analyze_marks_stdin_operand() {
        let args = argv(&["query", "-"]);
        let analysis = analyze_bq_args(&args);
        assert!(analysis.reads_stdin_as_code);
    }
}
