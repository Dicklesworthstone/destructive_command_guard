//! `BigQuery` patterns - protections against destructive `bq` CLI and
//! `GoogleSQL` operations.
//!
//! Two families of rule live here, and they are deliberately scoped
//! differently:
//!
//! - **CLI rules** (`bq rm`, `bq load --replace`, ...) carry
//!   `executables = ["bq"]`. `bq` is a two-letter token that appears inside
//!   ordinary prose and filenames, so an unscoped `\bbq\s+rm\b` would fire on
//!   `echo "run bq rm -r later"`. Executable scoping makes the rule fire only
//!   when the resolved argv0 of the matching segment really is `bq`.
//! - **`GoogleSQL` rules** (`DROP TABLE`, `DELETE ... WHERE TRUE`, ...) are
//!   unscoped. The SQL a user runs does not always sit on a `bq` command line:
//!   it arrives through `bq query < migration.sql`, a pipe, or a heredoc, and
//!   the evaluator replays that payload against this pack with no argv0 to
//!   attribute it to.
//!
//! `BigQuery` differs from the other SQL packs in ways the patterns encode:
//!
//! - A *dataset* is a `SCHEMA` in `GoogleSQL`, so `DROP SCHEMA` is the
//!   dataset-level catastrophe, not a namespace tidy-up.
//! - `GoogleSQL` **requires** a `WHERE` clause on `DELETE`/`UPDATE`. The
//!   idiom for "all rows" is therefore `WHERE TRUE`, which a
//!   `delete-without-where` rule modelled on `PostgreSQL` would never see.
//! - Deleted tables are recoverable only inside the time-travel window, so
//!   shrinking `--max_time_travel_hours` destroys the undo path itself.

use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};
use crate::{destructive_pattern, safe_pattern};

// ============================================================================
// Suggestion constants (must be 'static for the pattern struct)
// ============================================================================

/// Suggestions for `bq rm -r` (recursive dataset removal).
const BQ_RM_RECURSIVE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "bq ls --max_results=1000 {dataset}",
        "List everything the recursive remove would take with it",
    ),
    PatternSuggestion::new(
        "bq extract --destination_format=AVRO {dataset}.{table} gs://{bucket}/{table}-*.avro",
        "Export each table to Cloud Storage before removing the dataset",
    ),
    PatternSuggestion::new(
        "bq rm {dataset}",
        "Drop the -r and let the command fail if the dataset is non-empty",
    ),
];

/// Suggestions for `DROP SCHEMA` (drops a `BigQuery` dataset).
const DROP_SCHEMA_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "SELECT table_name FROM `{project}.{dataset}`.INFORMATION_SCHEMA.TABLES",
        "List the tables the dataset still holds",
    ),
    PatternSuggestion::new(
        "DROP SCHEMA `{project}.{dataset}`",
        "Omit CASCADE so the drop fails if the dataset is not empty",
    ),
];

/// Suggestions for `DROP TABLE`.
const DROP_TABLE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "SELECT COUNT(*) FROM `{project}.{dataset}.{table}`",
        "Check the row count before dropping",
    ),
    PatternSuggestion::new(
        "CREATE SNAPSHOT TABLE `{dataset}.{table}_snap` CLONE `{dataset}.{table}`",
        "Take a zero-copy snapshot first - it survives the DROP",
    ),
    PatternSuggestion::new(
        "bq cp {dataset}.{table} {dataset}.{table}_backup",
        "Copy the table aside before dropping",
    ),
];

/// Suggestions for `DELETE ... WHERE TRUE`.
const DELETE_ALL_ROWS_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "SELECT COUNT(*) FROM `{table}` WHERE TRUE",
        "Count exactly what the DELETE would remove",
    ),
    PatternSuggestion::new(
        "DELETE FROM `{table}` WHERE {condition}",
        "Replace WHERE TRUE with the condition you actually meant",
    ),
    PatternSuggestion::new(
        "TRUNCATE TABLE `{table}`",
        "If you truly want every row gone, say so explicitly",
    ),
];

/// Suggestions for `--max_time_travel_hours`.
const TIME_TRAVEL_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "bq show --format=prettyjson {dataset}",
        "Read the dataset's current maxTimeTravelHours before changing it",
    ),
    PatternSuggestion::new(
        "SELECT * FROM `{dataset}.{table}` FOR SYSTEM_TIME AS OF \
         TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)",
        "Confirm what time travel can still recover today",
    ),
];

/// Create the `BigQuery` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "database.bigquery".to_string(),
        name: "BigQuery",
        description: "Protects against destructive BigQuery operations like bq rm -r, \
                      --replace loads, DROP SCHEMA/TABLE, DELETE ... WHERE TRUE, and \
                      shrinking the time-travel recovery window",
        // Keyword matching is ASCII-case-insensitive, so one spelling of each
        // token is enough. Keep them specific: a bare `REPLACE` matches
        // `s.replace(...)` and a bare `MERGE` matches `git merge`, and any
        // keyword hit makes this pack a candidate for indirect-input analysis
        // on commands that have nothing to do with BigQuery.
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
    vec![
        // Read-only `bq` subcommands. The subcommand must be the first
        // non-flag token after `bq`, and the rest of the line must be
        // quote-free: `bq query 'SELECT 1' ls` has a quoted payload this
        // pattern has no business vouching for.
        safe_pattern!(
            "bq-read-only-subcommand",
            r#"(?i)\bbq\s+(?:-{1,2}[^\s'"]+\s+)*(?:ls|show|head|version|help)\b[^'"\n]*(?:\n|$)"#
        ),
        // `--dry_run` really does prevent execution in BigQuery. Require it to
        // appear before any quote so it must be a flag, not text inside the
        // SQL literal.
        safe_pattern!("bq-query-dry-run", r#"(?i)\bbq\s+[^'"\n]*--dry_run\b"#),
        // Exports read; they never write to BigQuery.
        safe_pattern!(
            "bq-extract",
            r#"(?i)\bbq\s+(?:-{1,2}[^\s'"]+\s+)*extract\b"#
        ),
        // Plain reads.
        safe_pattern!("select-query", r"(?i)^\s*SELECT\s+"),
    ]
}

#[allow(clippy::too_many_lines)]
fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Sentinel rule. Never matches by regex; the evaluator raises it by
        // name when `bq query` is fed SQL that dcg cannot read statically
        // (a pipe, a redirect, a command substitution).
        destructive_pattern!(
            "stdin-unverified",
            r"(?!)",
            "bq receives indirect input that dcg cannot statically verify.",
            High,
            "Materialize and review the exact GoogleSQL before piping or redirecting it into \
             `bq query`. A query read from stdin is executed unseen, and a single \
             `DROP SCHEMA ... CASCADE` in that stream removes an entire dataset."
        ),
        // ------------------------------------------------------------------
        // `bq` CLI rules - scoped to argv0 == bq.
        // ------------------------------------------------------------------
        destructive_pattern!(
            "bq-rm-recursive",
            r#"(?i)\bbq\s+(?:-{1,2}[^\s'"]+\s+)*rm\b[^|;&\n]*(?:\s--recursive\b|\s-[a-z]*r[a-z]*(?:\s|$))"#,
            "bq rm -r deletes the dataset and every table, view, model, and routine inside it.",
            Critical,
            "`bq rm -r DATASET` is the BigQuery equivalent of DROP SCHEMA CASCADE:\n\n\
             - Every table, view, materialized view, model, and routine in the dataset goes\n\
             - Combined with -f there is no confirmation prompt at all\n\
             - Recovery depends entirely on the dataset's time-travel window\n\
             - Table snapshots stored in the same dataset are removed too\n\n\
             Inventory the dataset first:\n  \
             bq ls --max_results=1000 mydataset\n\n\
             Export what matters:\n  \
             bq extract --destination_format=AVRO mydataset.mytable \\\n    \
             gs://mybucket/mytable-*.avro",
            BQ_RM_RECURSIVE_SUGGESTIONS,
            executables = ["bq"]
        ),
        destructive_pattern!(
            "bq-rm-force",
            r#"(?i)\bbq\s+(?:-{1,2}[^\s'"]+\s+)*rm\b[^|;&\n]*(?:\s--force\b|\s-[a-z]*f[a-z]*(?:\s|$))"#,
            "bq rm -f deletes the resource with no confirmation prompt.",
            High,
            "`-f`/`--force` suppresses the interactive \"Are you sure?\" that is normally the \
             last thing standing between a typo and a deleted table.\n\n\
             Drop the flag and answer the prompt, or verify the target first:\n  \
             bq show mydataset.mytable",
            executables = ["bq"]
        ),
        destructive_pattern!(
            "bq-rm-transfer-config",
            r#"(?i)\bbq\s+(?:-{1,2}[^\s'"]+\s+)*rm\b[^|;&\n]*--transfer_config\b"#,
            "bq rm --transfer_config deletes a scheduled query or data transfer and its run history.",
            High,
            "Removing a transfer configuration stops the scheduled query or ingestion it \
             drives and discards its run history. Downstream tables silently stop being \
             refreshed, which usually surfaces days later as stale data rather than as an \
             error.\n\n\
             Read the config before deleting it:\n  \
             bq show --transfer_config projects/PROJECT/locations/LOCATION/transferConfigs/ID\n\n\
             Pause instead of delete:\n  \
             bq update --transfer_config --disabled=true CONFIG",
            executables = ["bq"]
        ),
        destructive_pattern!(
            "bq-rm-reservation",
            r#"(?i)\bbq\s+(?:-{1,2}[^\s'"]+\s+)*rm\b[^|;&\n]*--(?:reservation|capacity_commitment|reservation_assignment)\b"#,
            "bq rm on a reservation or capacity commitment changes query capacity and billing.",
            High,
            "Reservations and capacity commitments are the slots your queries run on:\n\n\
             - Deleting a reservation pushes its assigned projects back to on-demand pricing\n\
             - Deleting a capacity commitment can incur early-termination charges\n\
             - Running queries can be starved of slots mid-flight\n\n\
             Inspect current capacity first:\n  \
             bq ls --reservation --location=US\n  \
             bq ls --capacity_commitment --location=US",
            executables = ["bq"]
        ),
        // Generic `bq rm` catch-all. Must stay below the specific rm rules above:
        // `matches_destructive` returns the first pattern in this vec that matches, so a
        // catch-all placed earlier would shadow their more precise reasons.
        destructive_pattern!(
            "bq-rm",
            r#"(?i)\bbq\s+(?:-{1,2}[^\s'"]+\s+)*rm\b"#,
            "bq rm deletes a BigQuery dataset, table, view, model, or routine.",
            High,
            "`bq rm` removes the named resource. Deleted tables are recoverable only from \
             within the dataset's time-travel window (7 days by default, and configurable \
             down to 2 days), and only if a table with the same name has not been created \
             since.\n\n\
             Verify the target:\n  \
             bq show mydataset.mytable\n\n\
             Snapshot it first - a snapshot is zero-copy and survives the delete:\n  \
             bq cp --snapshot mydataset.mytable mydataset.mytable_snap",
            executables = ["bq"]
        ),
        destructive_pattern!(
            "bq-load-replace",
            r#"(?i)\bbq\s+(?:-{1,2}[^\s'"]+\s+)*load\b[^|;&\n]*\s-{1,2}replace\b"#,
            "bq load --replace overwrites the destination table, discarding all existing rows.",
            High,
            "`--replace` truncates the destination table before loading. Every existing row \
             is gone whether or not the new data lands correctly, and a load that fails \
             partway can leave the table empty.\n\n\
             Append instead:\n  \
             bq load --noreplace mydataset.mytable gs://mybucket/data.json\n\n\
             Or stage and swap:\n  \
             bq load mydataset.mytable_new gs://mybucket/data.json\n  \
             # verify row counts, then\n  \
             bq cp -f mydataset.mytable_new mydataset.mytable",
            executables = ["bq"]
        ),
        destructive_pattern!(
            "bq-query-replace",
            r#"(?i)\bbq\s+(?:-{1,2}[^\s'"]+\s+)*query\b[^|;&\n]*\s-{1,2}replace\b"#,
            "bq query --replace overwrites the destination table with the query result.",
            High,
            "With `--destination_table`, `--replace` truncates that table before writing the \
             query result. If the query returns fewer rows than expected - or zero - the old \
             contents are still gone.\n\n\
             Preview the result size first:\n  \
             bq query --dry_run --use_legacy_sql=false 'SELECT ...'\n\n\
             Append instead:\n  \
             bq query --append_table --destination_table=mydataset.mytable 'SELECT ...'",
            executables = ["bq"]
        ),
        destructive_pattern!(
            "bq-cp-force",
            r#"(?i)\bbq\s+(?:-{1,2}[^\s'"]+\s+)*cp\b[^|;&\n]*\s-{1,2}(?:f\b|force\b)"#,
            "bq cp -f overwrites the destination table without confirmation.",
            High,
            "`bq cp -f` replaces the destination table's contents with the source table's. \
             The destination's previous data is recoverable only through time travel.\n\n\
             Use --no_clobber to fail instead of overwrite:\n  \
             bq cp -n mydataset.src mydataset.dst",
            executables = ["bq"]
        ),
        destructive_pattern!(
            "bq-mk-force",
            r#"(?i)\bbq\s+(?:-{1,2}[^\s'"]+\s+)*mk\b[^|;&\n]*\s-{1,2}(?:f\b|force\b)"#,
            "bq mk -f recreates an existing table, discarding its data.",
            High,
            "`bq mk` normally refuses to touch a resource that already exists. `-f`/`--force` \
             turns that refusal into a silent recreate, so a `bq mk -f` against a live table \
             replaces it with an empty one carrying the new schema.\n\n\
             Drop the flag and let the collision be an error:\n  \
             bq mk --table mydataset.mytable schema.json",
            executables = ["bq"]
        ),
        destructive_pattern!(
            "bq-update-time-travel",
            r#"(?i)\bbq\s+(?:-{1,2}[^\s'"]+\s+)*update\b[^|;&\n]*--max_time_travel_hours\b"#,
            "Lowering --max_time_travel_hours shortens the window in which deleted BigQuery data can be recovered.",
            High,
            "Time travel is BigQuery's undo. Lowering `--max_time_travel_hours` (the minimum \
             is 48) permanently discards the history outside the new window - including the \
             history you would need to recover from a mistake made ten minutes from now.\n\n\
             Read the current setting before changing it:\n  \
             bq show --format=prettyjson mydataset\n\n\
             If the goal is cost, prefer table expiration or partition expiration on the \
             specific tables that are cheap to lose.",
            TIME_TRAVEL_SUGGESTIONS,
            executables = ["bq"]
        ),
        destructive_pattern!(
            "bq-update-expiration",
            r#"(?i)\bbq\s+(?:-{1,2}[^\s'"]+\s+)*update\b[^|;&\n]*--(?:default_table_expiration|default_partition_expiration|expiration|time_partitioning_expiration)\b"#,
            "Setting an expiration schedules automatic deletion of tables or partitions.",
            Medium,
            "Expiration settings delete data on a timer, with no further prompt. A \
             `--default_table_expiration` applies to tables created afterwards; an \
             `--expiration` on an existing table sets a deletion time for that table's data.\n\n\
             Clear an expiration by setting it to 0:\n  \
             bq update --default_table_expiration 0 mydataset\n\n\
             Check what is currently set:\n  \
             bq show --format=prettyjson mydataset",
            executables = ["bq"]
        ),
        destructive_pattern!(
            "bq-cancel",
            r#"(?i)\bbq\s+(?:-{1,2}[^\s'"]+\s+)*cancel\b"#,
            "bq cancel stops a running job; partially written results may be left behind.",
            Medium,
            "Cancelling a job stops it where it stands. A load or a query writing to a \
             destination table may already have written some data, and BigQuery does not \
             roll that back for every job type.\n\n\
             Inspect the job before cancelling:\n  \
             bq show -j JOB_ID",
            executables = ["bq"]
        ),
        // ------------------------------------------------------------------
        // GoogleSQL rules - unscoped, because the payload reaches this pack
        // through files, pipes, and heredocs as well as `bq query` arguments.
        // ------------------------------------------------------------------
        destructive_pattern!(
            "drop-schema",
            r"(?i)\bDROP\s+(?:EXTERNAL\s+)?SCHEMA\b",
            "DROP SCHEMA deletes a BigQuery dataset (even with IF EXISTS). With CASCADE it takes every table with it.",
            Critical,
            "In GoogleSQL a SCHEMA *is* a dataset, so DROP SCHEMA is dataset-level \
             destruction, not a namespace tidy-up:\n\n\
             - DROP SCHEMA ... CASCADE removes every table, view, model, and routine\n\
             - Without CASCADE the statement fails on a non-empty dataset, which is the \
               safer form\n\
             - IF EXISTS only suppresses the error; it still drops\n\n\
             List the contents first:\n  \
             SELECT table_name\n  \
             FROM `myproject.mydataset`.INFORMATION_SCHEMA.TABLES;",
            DROP_SCHEMA_SUGGESTIONS
        ),
        destructive_pattern!(
            "drop-snapshot-table",
            r"(?i)\bDROP\s+SNAPSHOT\s+TABLE\b",
            "DROP SNAPSHOT TABLE deletes a point-in-time backup of a table.",
            Critical,
            "A table snapshot is a zero-copy backup - frequently the only thing standing \
             between an accidental DROP TABLE and permanent loss once the time-travel window \
             has passed. Dropping the snapshot removes the recovery path, and the loss is not \
             visible until someone needs it.\n\n\
             Confirm what the snapshot covers first:\n  \
             SELECT * FROM `mydataset`.INFORMATION_SCHEMA.TABLE_SNAPSHOTS;",
            DROP_TABLE_SUGGESTIONS
        ),
        // Above `drop-table`: `DROP TABLE FUNCTION` also contains `DROP TABLE`,
        // and the first matching pattern in this vec is the one reported.
        destructive_pattern!(
            "drop-routine",
            r"(?i)\bDROP\s+(?:TABLE\s+FUNCTION|FUNCTION|PROCEDURE|MODEL|ROW\s+ACCESS\s+POLICY)\b",
            "DROP removes a stored routine, model, or row-level access policy.",
            Medium,
            "Dropping a routine or model deletes code and trained state that may not exist \
             anywhere else - a BigQuery ML model in particular can represent hours of \
             training that no repository holds.\n\n\
             Dropping a ROW ACCESS POLICY is different in kind: it does not delete data, it \
             *exposes* it. Rows previously filtered out become visible to everyone with table \
             access.\n\n\
             Review the definition first:\n  \
             SELECT * FROM `mydataset`.INFORMATION_SCHEMA.ROUTINES;"
        ),
        destructive_pattern!(
            "drop-all-row-access-policies",
            r"(?i)\bDROP\s+ALL\s+ROW\s+ACCESS\s+POLICIES\b",
            "DROP ALL ROW ACCESS POLICIES exposes every previously filtered row to anyone with table access.",
            High,
            "This statement deletes no data - it removes the filters that decide who may see \
             which rows. Every reader of the table immediately sees the whole table, and \
             nothing in the query results signals that the boundary is gone.\n\n\
             List what is in place before removing it:\n  \
             SELECT * FROM `mydataset.mytable`.INFORMATION_SCHEMA.ROW_ACCESS_POLICIES;\n\n\
             Drop a single policy if that is what you meant:\n  \
             DROP ROW ACCESS POLICY mypolicy ON `mydataset.mytable`;"
        ),
        destructive_pattern!(
            "drop-search-index",
            r"(?i)\bDROP\s+(?:SEARCH|VECTOR)\s+INDEX\b",
            "DROP SEARCH/VECTOR INDEX discards an index that can take hours and real cost to rebuild.",
            Medium,
            "The index holds no source data, so nothing is lost permanently - but queries that \
             relied on it silently fall back to full scans, which changes both latency and \
             bytes billed. Rebuilding is asynchronous and not instant.\n\n\
             Check size and status before dropping:\n  \
             SELECT index_name, total_storage_bytes, index_status\n  \
             FROM `mydataset`.INFORMATION_SCHEMA.SEARCH_INDEXES;"
        ),
        destructive_pattern!(
            "drop-capacity-or-reservation",
            r"(?i)\bDROP\s+(?:CAPACITY|RESERVATION|ASSIGNMENT)\b",
            "Dropping a capacity commitment, reservation, or assignment changes query capacity and billing.",
            High,
            "These DDL statements are the SQL equivalent of `bq rm --reservation`:\n\n\
             - DROP RESERVATION pushes its assigned projects back to on-demand pricing\n\
             - DROP CAPACITY can incur early-termination charges\n\
             - DROP ASSIGNMENT moves a project's workload off its slots mid-flight\n\n\
             Inspect current capacity first:\n  \
             SELECT * FROM `region-us`.INFORMATION_SCHEMA.RESERVATIONS;\n  \
             SELECT * FROM `region-us`.INFORMATION_SCHEMA.ASSIGNMENTS;"
        ),
        destructive_pattern!(
            "drop-table",
            r"(?i)\bDROP\s+(?:EXTERNAL\s+)?TABLE\b",
            "DROP TABLE permanently deletes the table (even with IF EXISTS). Verify and snapshot first.",
            High,
            "DROP TABLE removes the table and all its data:\n\n\
             - Recovery is possible only inside the time-travel window (2-7 days)\n\
             - Time-travel recovery also fails if a new table takes the same name\n\
             - IF EXISTS only prevents an error; it still drops\n\n\
             Take a snapshot first - it is zero-copy and outlives the DROP:\n  \
             CREATE SNAPSHOT TABLE `mydataset.mytable_snap`\n  \
             CLONE `mydataset.mytable`;\n\n\
             Check what you are about to lose:\n  \
             SELECT COUNT(*) FROM `myproject.mydataset.mytable`;",
            DROP_TABLE_SUGGESTIONS
        ),
        destructive_pattern!(
            "drop-view",
            r"(?i)\bDROP\s+(?:MATERIALIZED\s+)?VIEW\b",
            "DROP VIEW removes the view definition; dependent queries and dashboards break.",
            Medium,
            "A view holds no data, but its definition is often the only place the business \
             logic lives, and anything selecting from it starts failing immediately. A \
             materialized view additionally discards its precomputed results, so the first \
             query after a rebuild pays full cost.\n\n\
             Save the definition before dropping:\n  \
             SELECT view_definition\n  \
             FROM `myproject.mydataset`.INFORMATION_SCHEMA.VIEWS\n  \
             WHERE table_name = 'myview';"
        ),
        destructive_pattern!(
            "truncate-table",
            r"(?i)\bTRUNCATE\s+TABLE\s+[`a-zA-Z_]",
            "TRUNCATE TABLE deletes every row in the table.",
            High,
            "TRUNCATE TABLE empties the table in one statement:\n\n\
             - All rows removed; the schema stays\n\
             - Not rollback-able outside a multi-statement transaction\n\
             - Recoverable only through time travel\n\n\
             Count first:\n  \
             SELECT COUNT(*) FROM `mydataset.mytable`;\n\n\
             Or wrap it so you can back out:\n  \
             BEGIN TRANSACTION;\n  \
             TRUNCATE TABLE `mydataset.mytable`;\n  \
             -- verify, then COMMIT TRANSACTION or ROLLBACK TRANSACTION"
        ),
        destructive_pattern!(
            "delete-all-rows",
            r"(?is)\bDELETE\s+(?:FROM\s+)?\S.{0,400}?\bWHERE\s+(?:TRUE\b|1\s*=\s*1\b)",
            "DELETE ... WHERE TRUE deletes every row in the table.",
            High,
            "GoogleSQL requires a WHERE clause on DELETE, so `WHERE TRUE` is how a full-table \
             delete is written. That makes it easy to type deliberately and easy to leave \
             behind after testing - the clause looks like a guard while doing the opposite.\n\n\
             Count what it would remove:\n  \
             SELECT COUNT(*) FROM `mydataset.mytable` WHERE TRUE;\n\n\
             Say it explicitly if you mean it:\n  \
             TRUNCATE TABLE `mydataset.mytable`;",
            DELETE_ALL_ROWS_SUGGESTIONS
        ),
        destructive_pattern!(
            "delete-without-where",
            r"(?i)\bDELETE\s+FROM\s+(?:`[^`]+`|[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*){0,2})\s*(?:;|$)",
            "DELETE without a WHERE clause targets every row.",
            High,
            "GoogleSQL rejects a DELETE with no WHERE clause, so this statement will either \
             error out or - if it is running under legacy SQL or a non-BigQuery engine that \
             shares this script - delete the whole table.\n\n\
             Either add the condition you meant:\n  \
             DELETE FROM `mydataset.mytable` WHERE event_date < '2024-01-01';\n\n\
             Or be explicit about wanting everything gone:\n  \
             TRUNCATE TABLE `mydataset.mytable`;",
            DELETE_ALL_ROWS_SUGGESTIONS
        ),
        destructive_pattern!(
            "update-all-rows",
            r"(?is)\bUPDATE\s+\S.{0,400}?\bSET\b.{0,400}?\bWHERE\s+(?:TRUE\b|1\s*=\s*1\b)",
            "UPDATE ... WHERE TRUE rewrites every row in the table.",
            High,
            "`WHERE TRUE` satisfies GoogleSQL's mandatory-WHERE rule without restricting \
             anything, so this rewrites the whole table. The previous values survive only in \
             the time-travel window.\n\n\
             Check the blast radius:\n  \
             SELECT COUNT(*) FROM `mydataset.mytable` WHERE TRUE;\n\n\
             Preview the new values before committing to them:\n  \
             SELECT col, <new_expression> FROM `mydataset.mytable` LIMIT 100;"
        ),
        destructive_pattern!(
            "create-or-replace-table",
            r"(?i)\bCREATE\s+OR\s+REPLACE\s+(?:EXTERNAL\s+|SNAPSHOT\s+|MATERIALIZED\s+)?TABLE\b",
            "CREATE OR REPLACE TABLE atomically discards the existing table's data.",
            High,
            "CREATE OR REPLACE TABLE drops the existing table and creates the new one in a \
             single atomic step. It is safe when the SELECT is correct and destructive when \
             it is not: an empty or filtered result replaces the real data with no error.\n\n\
             Write to a staging table and compare before swapping:\n  \
             CREATE TABLE `mydataset.mytable_new` AS SELECT ...;\n  \
             SELECT COUNT(*) FROM `mydataset.mytable_new`;\n\n\
             Or use CREATE TABLE IF NOT EXISTS when you only meant to ensure it exists."
        ),
        destructive_pattern!(
            "create-or-replace-routine",
            r"(?i)\bCREATE\s+OR\s+REPLACE\s+(?:MATERIALIZED\s+)?(?:VIEW|TABLE\s+FUNCTION|FUNCTION|PROCEDURE|MODEL|ROW\s+ACCESS\s+POLICY)\b",
            "CREATE OR REPLACE overwrites an existing view, routine, model, or access policy definition.",
            Medium,
            "The previous definition is gone the moment this runs, and BigQuery keeps no \
             history of it - time travel covers table data, not object definitions. If the \
             replacement is subtly wrong, there is nothing to diff against.\n\n\
             Capture the current definition first:\n  \
             SELECT view_definition FROM `myproject.mydataset`.INFORMATION_SCHEMA.VIEWS\n  \
             WHERE table_name = 'myview';\n\n\
             Replacing a ROW ACCESS POLICY is a permissions change: a broader filter exposes \
             rows that were previously hidden."
        ),
        destructive_pattern!(
            "load-data-overwrite",
            r"(?i)\bLOAD\s+DATA\s+OVERWRITE\b",
            "LOAD DATA OVERWRITE replaces the whole table with the loaded file's contents.",
            High,
            "OVERWRITE truncates the destination before writing. A source file that is short, \
             stale, or mid-upload replaces good data with bad, and the load reports success.\n\n\
             Append instead, and swap only after checking:\n  \
             LOAD DATA INTO `mydataset.mytable` FROM FILES (...);\n\n\
             Or land it in a staging table and compare row counts before promoting it."
        ),
        destructive_pattern!(
            "export-data-overwrite",
            r"(?is)\bEXPORT\s+DATA\b.{0,400}?\boverwrite\s*=\s*true\b",
            "EXPORT DATA with overwrite=true deletes existing files at the destination URI.",
            Medium,
            "`overwrite=true` lets the export clear whatever already sits under the destination \
             prefix. If the URI is wrong or shared with another job's output, that data is \
             gone - Cloud Storage deletes here are not covered by BigQuery time travel.\n\n\
             Look before you write:\n  \
             gcloud storage ls gs://mybucket/myprefix/\n\n\
             Or export to a run-specific prefix and leave overwrite unset."
        ),
        destructive_pattern!(
            "alter-set-expiration",
            r"(?is)\bALTER\s+(?:TABLE|SCHEMA|MATERIALIZED\s+VIEW)\b.{0,300}?\bSET\s+OPTIONS\s*\(.{0,300}?\b(?:expiration_timestamp|partition_expiration_days|default_table_expiration_days|default_partition_expiration_days|max_time_travel_hours)\b",
            "ALTER ... SET OPTIONS with an expiration or time-travel option schedules deletion or shrinks the undo window.",
            High,
            "These options delete data later rather than now, which is what makes them easy to \
             set wrong:\n\n\
             - expiration_timestamp puts a deletion date on the table itself\n\
             - partition_expiration_days / default_table_expiration_days start expiring \
               existing partitions and tables as soon as they are set, including ones already \
               older than the new limit\n\
             - max_time_travel_hours (48-168) shortens the only window in which a mistaken \
               DROP or DELETE can be undone; lowering it discards recovery data immediately\n\n\
             Read the current settings before changing them:\n  \
             SELECT option_name, value\n  \
             FROM `myproject.mydataset`.INFORMATION_SCHEMA.SCHEMATA_OPTIONS;\n\n\
             Clear an expiration rather than shortening it:\n  \
             ALTER TABLE `mydataset.mytable` SET OPTIONS (expiration_timestamp = NULL);",
            TIME_TRAVEL_SUGGESTIONS
        ),
        destructive_pattern!(
            "alter-table-drop-column",
            r"(?i)\bALTER\s+TABLE\b.{0,200}?\bDROP\s+COLUMN\b",
            "ALTER TABLE ... DROP COLUMN removes the column and its data.",
            Medium,
            "Dropping a column deletes its values. BigQuery reclaims the storage \
             asynchronously, so the column is unreadable immediately even though billing \
             takes a while to reflect it.\n\n\
             Rename it out of the way instead, and drop it once nothing breaks:\n  \
             ALTER TABLE `mydataset.mytable` RENAME COLUMN mycol TO mycol_deprecated;"
        ),
        destructive_pattern!(
            "alter-table-rename",
            r"(?is)\bALTER\s+(?:TABLE|VIEW|MATERIALIZED\s+VIEW)\b.{0,200}?\bRENAME\s+TO\b",
            "ALTER ... RENAME TO breaks every query, view, and scheduled job referencing the old name.",
            Medium,
            "No rows are lost, but the object disappears from under everything that referenced \
             it - views, scheduled queries, dashboards, and downstream ETL all start failing \
             on a name that no longer resolves. BigQuery does not rewrite those references, and \
             time travel does not follow the rename.\n\n\
             Find the dependents first:\n  \
             SELECT table_name, view_definition\n  \
             FROM `myproject.mydataset`.INFORMATION_SCHEMA.VIEWS\n  \
             WHERE view_definition LIKE '%mytable%';\n\n\
             A view over the old name keeps callers working while they migrate:\n  \
             CREATE VIEW `mydataset.mytable` AS SELECT * FROM `mydataset.mytable_new`;"
        ),
        destructive_pattern!(
            "merge-delete-not-matched-by-source",
            r"(?is)\bMERGE\b.{0,600}?\bWHEN\s+NOT\s+MATCHED\s+BY\s+SOURCE\b.{0,200}?\bTHEN\s+DELETE\b",
            "MERGE ... WHEN NOT MATCHED BY SOURCE THEN DELETE removes every target row the source does not contain.",
            High,
            "This clause makes the target table a mirror of the source. If the source query \
             is filtered, late, or empty, the MERGE deletes the rows it failed to \
             produce - a partial upstream extract becomes a mass delete.\n\n\
             Count the rows at risk before running it:\n  \
             SELECT COUNT(*) FROM `target` t\n  \
             WHERE NOT EXISTS (SELECT 1 FROM `source` s WHERE s.id = t.id);\n\n\
             Guard the clause so it cannot fire on an empty source, or drop the DELETE and \
             mark rows inactive instead."
        ),
    ]
}

// ============================================================================
// argv analysis for the `bq` CLI
// ============================================================================

/// Global `bq` flags that consume the following token when written bare.
///
/// `bq` uses absl flags, so `--flag=value` is also valid and needs no arity
/// knowledge; only the space-separated form does.
const GLOBAL_VALUE_FLAGS: &[&str] = &[
    "api",
    "api_version",
    "apilog",
    "bigqueryrc",
    "dataset_id",
    "format",
    "httplib2_debuglevel",
    "job_id",
    "job_property",
    "location",
    "max_rows",
    "project_id",
    "request_reason",
    "service_account",
    "service_account_credential_file",
    "service_account_private_key_file",
    "service_account_private_key_password",
    "trace",
    "universe_domain",
];

/// Global `bq` flags that stand alone.
const GLOBAL_BOOL_FLAGS: &[&str] = &[
    "debug_mode",
    "disable_ssl_validation",
    "enable_gdrive",
    "fingerprint_job_id",
    "headless",
    "q",
    "quiet",
    "sync",
    "use_gce_service_account",
    "use_google_auth",
];

/// `bq query` flags that consume the following token when written bare.
const QUERY_VALUE_FLAGS: &[&str] = &[
    "clustering_fields",
    "connection_property",
    "destination_kms_key",
    "destination_schema",
    "destination_table",
    "display_name",
    "external_table_definition",
    "flagfile",
    "job_timeout_ms",
    "label",
    "max_statement_results",
    "maximum_bytes_billed",
    "min_completion_ratio",
    "n",
    "parameter",
    "priority",
    "range_partitioning",
    "reservation_id",
    "schedule",
    "schema_update_option",
    "script_statement_timeout_ms",
    "session_id",
    "start_row",
    "target_dataset",
    "time_partitioning_expiration",
    "time_partitioning_field",
    "time_partitioning_type",
    "udf_resource",
];

/// `bq query` flags that stand alone.
const QUERY_BOOL_FLAGS: &[&str] = &[
    "allow_large_results",
    "append_table",
    "batch",
    "continuous",
    "dry_run",
    "flatten_results",
    "replace",
    "require_cache",
    "require_partition_filter",
    "rpc",
    "use_cache",
    "use_legacy_sql",
];

/// Code-bearing surfaces of one `bq` argv vector.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BqCliAnalysis<'a> {
    /// SQL supplied as a positional operand of `bq query`.
    pub code_values: Vec<&'a str>,
    /// Whether stdin is executable SQL - `bq query` with no SQL operand reads
    /// the statement from stdin, so a pipe or `<` redirect is code.
    pub reads_stdin_as_code: bool,
}

/// Parse the arguments after the `bq` executable and identify executable SQL.
///
/// Only `bq query` carries a SQL payload, so every other subcommand returns an
/// empty analysis - those surfaces are covered by the `executables = ["bq"]`
/// CLI rules instead.
///
/// Unknown or future options are handled conservatively rather than
/// fail-closed-with-a-block: an option whose arity we cannot resolve makes the
/// remaining tokens code operands *and* marks stdin as code-bearing. That can
/// over-collect (a project name inspected as if it were SQL matches nothing),
/// but it cannot let a `DROP` slip past because we mistook it for a flag value.
#[must_use]
pub fn analyze_bq_args(args: &[String]) -> BqCliAnalysis<'_> {
    /// Consume one flag token. `Some(step)` is how far to advance.
    fn flag_step(
        args: &[String],
        index: usize,
        value_flags: &[&str],
        bool_flags: &[&str],
    ) -> Option<usize> {
        let arg = args[index].as_str();
        let long = arg.strip_prefix("--").or_else(|| arg.strip_prefix('-'))?;
        // `--flag=value` is self-delimiting whatever the flag turns out to be.
        if long.contains('=') {
            return Some(1);
        }
        // absl spells every boolean's negation `--noflag`.
        let name = long.strip_prefix("no").unwrap_or(long);
        if bool_flags.contains(&long) || bool_flags.contains(&name) {
            return Some(1);
        }
        if value_flags.contains(&long) {
            // A trailing option with no operand consumes nothing after it.
            return Some(if index + 1 < args.len() { 2 } else { 1 });
        }
        None
    }

    let mut analysis = BqCliAnalysis::default();

    // Phase 1: global flags, up to the subcommand.
    let mut index = 0usize;
    let query_index = loop {
        let Some(arg) = args.get(index) else {
            return analysis;
        };
        if matches!(
            arg.as_str(),
            "--help" | "-h" | "--version" | "help" | "version"
        ) {
            return analysis;
        }
        if !arg.starts_with('-') {
            if arg != "query" {
                // Some other subcommand: no SQL operand to interpret.
                return analysis;
            }
            break index;
        }
        let Some(step) = flag_step(args, index, GLOBAL_VALUE_FLAGS, GLOBAL_BOOL_FLAGS) else {
            // Ambiguous arity before the subcommand: we cannot even tell which
            // subcommand runs, so treat everything left as possible SQL.
            analysis.reads_stdin_as_code = true;
            analysis
                .code_values
                .extend(args[index..].iter().map(String::as_str));
            return analysis;
        };
        index += step;
    };

    // Phase 2: `bq query` flags and the SQL positional.
    index = query_index + 1;
    let mut options_ended = false;
    while index < args.len() {
        let arg = args[index].as_str();
        if !options_ended && arg == "--" {
            options_ended = true;
            index += 1;
            continue;
        }
        if options_ended || !arg.starts_with('-') {
            analysis.code_values.push(arg);
            index += 1;
            continue;
        }
        if matches!(arg, "--help" | "-h") {
            return BqCliAnalysis::default();
        }
        let Some(step) = flag_step(args, index, QUERY_VALUE_FLAGS, QUERY_BOOL_FLAGS)
            .or_else(|| flag_step(args, index, GLOBAL_VALUE_FLAGS, GLOBAL_BOOL_FLAGS))
        else {
            analysis.reads_stdin_as_code = true;
            analysis
                .code_values
                .extend(args[index..].iter().map(String::as_str));
            return analysis;
        };
        index += step;
    }

    // `bq query` with no SQL operand reads the statement from stdin.
    analysis.reads_stdin_as_code = analysis.code_values.is_empty();
    analysis
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_string()).collect()
    }

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();
        assert_eq!(pack.id, "database.bigquery");
        validate_pack(&pack);
    }

    #[test]
    fn analyze_bq_args_finds_the_sql_positional() {
        let args = argv(&["query", "DROP TABLE d.t"]);
        let analysis = analyze_bq_args(&args);
        assert_eq!(analysis.code_values, vec!["DROP TABLE d.t"]);
        assert!(!analysis.reads_stdin_as_code);

        // Global flags in both spellings, then command flags.
        let args = argv(&[
            "--project_id",
            "myproj",
            "--format=prettyjson",
            "query",
            "--nouse_legacy_sql",
            "--destination_table",
            "d.t2",
            "-n",
            "10",
            "DELETE FROM d.t WHERE TRUE",
        ]);
        let analysis = analyze_bq_args(&args);
        assert_eq!(analysis.code_values, vec!["DELETE FROM d.t WHERE TRUE"]);
        assert!(!analysis.reads_stdin_as_code);
    }

    #[test]
    fn analyze_bq_args_treats_a_missing_operand_as_stdin() {
        let args = argv(&["query"]);
        let analysis = analyze_bq_args(&args);
        assert!(analysis.reads_stdin_as_code);
        assert!(analysis.code_values.is_empty());

        let args = argv(&["query", "--use_legacy_sql=false"]);
        assert!(analyze_bq_args(&args).reads_stdin_as_code);
    }

    #[test]
    fn analyze_bq_args_ignores_subcommands_without_a_sql_operand() {
        for args in [
            argv(&["ls", "mydataset"]),
            argv(&["rm", "-f", "d.t"]),
            argv(&["show", "--format=prettyjson", "d.t"]),
            argv(&["version"]),
            argv(&[]),
        ] {
            assert_eq!(analyze_bq_args(&args), BqCliAnalysis::default());
        }
    }

    #[test]
    fn analyze_bq_args_fails_conservatively_on_unknown_option_arity() {
        // A future bare flag could be either arity. Everything after it stays a
        // candidate operand rather than being silently skipped as a value.
        let args = argv(&["query", "--some_future_flag", "DROP TABLE d.t"]);
        let analysis = analyze_bq_args(&args);
        assert!(analysis.reads_stdin_as_code);
        assert!(analysis.code_values.contains(&"DROP TABLE d.t"));

        // Same before the subcommand, where the subcommand itself is unknown.
        let args = argv(&["--future_global", "query", "DROP TABLE d.t"]);
        let analysis = analyze_bq_args(&args);
        assert!(analysis.reads_stdin_as_code);
        assert!(analysis.code_values.contains(&"DROP TABLE d.t"));
    }

    #[test]
    fn bigquery_blocks_bq_cli_removals() {
        let pack = create_pack();
        assert_blocks(&pack, "bq rm -r -f analytics_prod", "bq rm -r");
        assert_blocks(&pack, "bq rm --recursive analytics_prod", "bq rm -r");
        assert_blocks(&pack, "bq rm -f mydataset.mytable", "no confirmation");
        assert_blocks(&pack, "bq rm mydataset.mytable", "bq rm deletes");
        assert_blocks(
            &pack,
            "bq rm --transfer_config projects/p/locations/us/transferConfigs/1",
            "scheduled query",
        );
        assert_blocks(
            &pack,
            "bq rm --reservation --location=US myreservation",
            "query capacity",
        );
    }

    #[test]
    fn bigquery_blocks_overwriting_cli_flags() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "bq load --replace mydataset.mytable gs://bucket/data.json",
            "overwrites the destination table",
        );
        assert_blocks(
            &pack,
            "bq query --replace --destination_table=ds.t 'SELECT 1'",
            "overwrites the destination table",
        );
        assert_blocks(&pack, "bq cp -f ds.src ds.dst", "without confirmation");
        assert_blocks(&pack, "bq mk -f --table ds.t schema.json", "recreates");
    }

    #[test]
    fn bigquery_blocks_recovery_window_changes() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "bq update --max_time_travel_hours 48 mydataset",
            "recovered",
        );
        assert_blocks(
            &pack,
            "bq update --default_table_expiration 3600 mydataset",
            "automatic deletion",
        );
        assert_blocks(&pack, "bq cancel bqjob_r123", "stops a running job");
    }

    #[test]
    fn bigquery_blocks_googlesql_ddl() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "DROP SCHEMA mydataset CASCADE",
            "deletes a BigQuery dataset",
        );
        assert_blocks(
            &pack,
            "DROP SCHEMA IF EXISTS mydataset",
            "deletes a BigQuery dataset",
        );
        assert_blocks(
            &pack,
            "DROP TABLE `p.d.t`",
            "DROP TABLE permanently deletes",
        );
        assert_blocks(
            &pack,
            "DROP EXTERNAL TABLE d.t",
            "DROP TABLE permanently deletes",
        );
        assert_blocks(
            &pack,
            "DROP SNAPSHOT TABLE d.t_snap",
            "point-in-time backup",
        );
        assert_blocks(&pack, "DROP MATERIALIZED VIEW d.mv", "DROP VIEW");
        assert_blocks(&pack, "DROP MODEL d.m", "stored routine");
        assert_blocks(&pack, "DROP ROW ACCESS POLICY p ON d.t", "stored routine");
        assert_blocks(&pack, "TRUNCATE TABLE `d.t`", "deletes every row");
        assert_blocks(
            &pack,
            "CREATE OR REPLACE TABLE d.t AS SELECT 1",
            "discards the existing table",
        );
        assert_blocks(
            &pack,
            "ALTER TABLE d.t DROP COLUMN legacy_id",
            "removes the column",
        );
        // `DROP TABLE FUNCTION` must not be reported as a plain table drop.
        assert_blocks(&pack, "DROP TABLE FUNCTION d.tvf", "stored routine");
    }

    #[test]
    fn bigquery_blocks_ddl_that_changes_access_or_capacity() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "DROP ALL ROW ACCESS POLICIES ON `d.t`",
            "exposes every previously filtered row",
        );
        assert_blocks(
            &pack,
            "DROP SEARCH INDEX my_index ON d.t",
            "hours and real cost",
        );
        assert_blocks(
            &pack,
            "DROP VECTOR INDEX my_index ON d.t",
            "hours and real cost",
        );
        assert_blocks(
            &pack,
            "DROP RESERVATION `admin_project.region-us.res`",
            "billing",
        );
        assert_blocks(
            &pack,
            "DROP CAPACITY `admin_project.region-us.commit`",
            "billing",
        );
        assert_blocks(
            &pack,
            "DROP ASSIGNMENT `admin_project.region-us.res.a`",
            "billing",
        );
    }

    #[test]
    fn bigquery_blocks_alter_statements_that_destroy_recoverability() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "ALTER SCHEMA mydataset SET OPTIONS (max_time_travel_hours = 48)",
            "shrinks the undo window",
        );
        assert_blocks(
            &pack,
            "ALTER TABLE `d.t` SET OPTIONS (expiration_timestamp = TIMESTAMP '2026-01-01 00:00:00 UTC')",
            "schedules deletion",
        );
        assert_blocks(
            &pack,
            "ALTER TABLE `d.t` SET OPTIONS (partition_expiration_days = 7)",
            "schedules deletion",
        );
        assert_blocks(
            &pack,
            "ALTER TABLE `d.t` RENAME TO t_v2",
            "breaks every query",
        );
        // Options that do not affect retention are left alone.
        assert_no_match(
            &pack,
            "ALTER TABLE `d.t` SET OPTIONS (description = 'now documented')",
        );
        // The remedy suggested by alter-table-drop-column must not itself be blocked.
        assert_no_match(
            &pack,
            "ALTER TABLE `d.t` RENAME COLUMN legacy_id TO legacy_id_deprecated",
        );
    }

    #[test]
    fn bigquery_blocks_statements_that_overwrite_in_place() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "CREATE OR REPLACE VIEW d.v AS SELECT 1",
            "overwrites an existing view",
        );
        assert_blocks(
            &pack,
            "CREATE OR REPLACE MATERIALIZED VIEW d.mv AS SELECT 1",
            "overwrites an existing view",
        );
        assert_blocks(
            &pack,
            "CREATE OR REPLACE PROCEDURE d.p() BEGIN SELECT 1; END",
            "overwrites an existing view",
        );
        assert_blocks(
            &pack,
            "LOAD DATA OVERWRITE `d.t` FROM FILES (uris = ['gs://b/f.csv'], format = 'CSV')",
            "replaces the whole table",
        );
        assert_blocks(
            &pack,
            "EXPORT DATA OPTIONS (uri = 'gs://b/out/*.csv', format = 'CSV', overwrite = true) \
             AS SELECT * FROM d.t",
            "deletes existing files",
        );
        // An export that does not clear the destination is fine.
        assert_no_match(
            &pack,
            "EXPORT DATA OPTIONS (uri = 'gs://b/out/*.csv', format = 'CSV') AS SELECT 1",
        );
    }

    #[test]
    fn bigquery_blocks_where_true_dml() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "DELETE FROM `myproject.mydataset.mytable` WHERE TRUE",
            "deletes every row",
        );
        assert_blocks(&pack, "delete from d.t where true", "deletes every row");
        assert_blocks(&pack, "DELETE FROM d.t WHERE 1 = 1", "deletes every row");
        assert_blocks(
            &pack,
            "UPDATE `d.t` SET status = 'x' WHERE TRUE",
            "rewrites every row",
        );
        assert_blocks(&pack, "DELETE FROM d.t;", "targets every row");
    }

    #[test]
    fn bigquery_blocks_merge_source_mirroring_delete() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "MERGE `d.target` T USING `d.source` S ON T.id = S.id \
             WHEN NOT MATCHED BY SOURCE THEN DELETE",
            "every target row the source does not contain",
        );
    }

    #[test]
    fn bigquery_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "bq rm -r -f analytics", Severity::Critical);
        assert_blocks_with_severity(&pack, "DROP SCHEMA mydataset", Severity::Critical);
        assert_blocks_with_severity(&pack, "DROP SNAPSHOT TABLE d.s", Severity::Critical);
        assert_blocks_with_severity(&pack, "DROP TABLE d.t", Severity::High);
        assert_blocks_with_severity(&pack, "DELETE FROM d.t WHERE TRUE", Severity::High);
        assert_blocks_with_severity(
            &pack,
            "bq update --max_time_travel_hours 48 d",
            Severity::High,
        );
        assert_blocks_with_severity(&pack, "DROP VIEW d.v", Severity::Medium);
        assert_blocks_with_severity(&pack, "bq cancel bqjob_r1", Severity::Medium);
    }

    #[test]
    fn bigquery_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "bq ls mydataset");
        assert_safe_pattern_matches(&pack, "bq --project_id=proj show mydataset.mytable");
        assert_safe_pattern_matches(&pack, "bq query --dry_run 'SELECT 1'");
        assert_safe_pattern_matches(&pack, "bq extract mydataset.mytable gs://bucket/out-*.avro");
        assert_safe_pattern_matches(&pack, "SELECT COUNT(*) FROM `d.t`");
    }

    #[test]
    fn bigquery_read_only_workflows_are_allowed() {
        let pack = create_pack();
        assert_allows(&pack, "bq ls --max_results=1000 mydataset");
        assert_allows(&pack, "bq show --format=prettyjson mydataset");
        assert_allows(&pack, "bq head -n 10 mydataset.mytable");
        assert_allows(&pack, "DELETE FROM `d.t` WHERE event_date < '2024-01-01'");
        assert_allows(&pack, "UPDATE `d.t` SET x = 1 WHERE id = 7");
        assert_allows(&pack, "bq load --noreplace ds.t gs://bucket/data.json");
        assert_allows(&pack, "bq cp -n ds.src ds.dst");
    }

    #[test]
    fn bigquery_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "git status");
    }

    #[test]
    fn dry_run_inside_the_sql_literal_does_not_whitelist() {
        // The `bq-query-dry-run` safe pattern refuses to look past a quote, so
        // text *inside* the query cannot claim the command was a dry run.
        let pack = create_pack();
        assert_no_safe_match(&pack, "bq query 'DROP TABLE d.t -- --dry_run'");
        assert_blocks_with_pattern(
            &pack,
            "bq query 'DROP TABLE d.t -- --dry_run'",
            "drop-table",
        );
        assert_no_safe_match(&pack, "bq query \"DROP SCHEMA d CASCADE; -- --dry_run\"");
    }

    #[test]
    fn read_only_subcommand_does_not_whitelist_a_quoted_payload() {
        // `bq-read-only-subcommand` must not match when a quoted argument
        // follows, or `bq query '... ls ...'` shapes would self-whitelist.
        let pack = create_pack();
        assert_no_safe_match(&pack, "bq query 'SELECT * FROM d.t; DROP TABLE d.t' ls");
        assert_blocks_with_pattern(
            &pack,
            "bq query 'SELECT * FROM d.t; DROP TABLE d.t' ls",
            "drop-table",
        );
    }

    #[test]
    fn compound_command_safe_segment_does_not_shield_a_drop() {
        // Pack::check splits on shell separators, so a read-only first segment
        // cannot vouch for a destructive second one.
        let pack = create_pack();
        let matched = pack
            .check("bq ls mydataset && bq rm -r -f mydataset")
            .expect("the recursive remove must still block");
        assert_eq!(matched.name, Some("bq-rm-recursive"));
    }

    #[test]
    fn where_true_rule_requires_a_real_where_clause() {
        // Regression guard: `.{0,400}?` between DELETE and WHERE must not let
        // the rule reach across a statement boundary into an unrelated WHERE.
        let pack = create_pack();
        assert_allows(&pack, "DELETE FROM `d.t` WHERE truthy_flag = 1");
        assert_allows(&pack, "UPDATE `d.t` SET x = 1 WHERE trueish = 2");
    }

    #[test]
    fn bq_prose_does_not_block_without_the_executable() {
        // The CLI rules carry `executables = ["bq"]`, which only the evaluator
        // enforces. Pack::check has no argv0 to resolve, so this test pins the
        // regex-level behavior the scoping is layered on top of: the rules
        // still require a `bq <subcommand>` shape rather than a bare mention.
        let pack = create_pack();
        assert_no_match(&pack, "echo 'the bq tool has an rm subcommand'");
        assert_no_match(&pack, "cat notes-about-bq.md");
    }
}
