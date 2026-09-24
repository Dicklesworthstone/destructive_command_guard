//! Snowflake CLI (`snow sql`) protection.
//!
//! The legacy SnowSQL client (`snowsql`) exposes the same SQL, file and stdin
//! surfaces; [`snowsql_args_as_snow_sql`] maps its argv onto `snow sql` so both
//! share this analysis, and its `!system` shell escape is a guarded directive.
//!
//! Snowflake's modern CLI accepts SQL through inline queries, files, standard
//! input, and transitive `!source` / `!load` directives. Regexes over the raw
//! shell command are not sufficient: they either miss file/stdin payloads or
//! treat comments and string literals as executable SQL. This module therefore
//! exposes two bounded semantic layers for the evaluator:
//!
//! - [`analyze_snow_sql_args`] identifies code/file/stdin inputs to `snow sql`.
//! - [`scan_sql`] lexes complete SQL payloads statement-by-statement and returns
//!   a stable rule name, a safe result, or a fail-closed unverified result.
//! - [`scan_sql_report`] retains every guarded statement in deterministic source
//!   order while preserving [`scan_sql`]'s highest-severity primary match.

use crate::destructive_pattern;
use crate::normalize::{
    NormalizeTokenKind, ShellDialect, ShellTokenDecoder, ShellTokenRole, strip_wrapper_prefixes,
    tokenize_for_shell_dialect,
};
use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern, Severity};
use std::path::PathBuf;

pub(crate) const MAX_SNOWFLAKE_CLI_BYTES: usize = 64 * 1024;
const MAX_SNOWFLAKE_CLI_SEGMENTS: usize = 64;
const MAX_SNOWFLAKE_CLI_TOKENS: usize = 128;

/// Maximum SQL payload accepted by the standalone semantic scanner.
pub const MAX_SNOWFLAKE_SQL_BYTES: usize = 256 * 1024;
/// Maximum number of statements accepted in one payload.
pub const MAX_SNOWFLAKE_STATEMENTS: usize = 512;
/// Maximum number of lexical tokens accepted in one payload.
pub const MAX_SNOWFLAKE_TOKENS: usize = 32 * 1024;
/// Maximum number of guarded findings returned from one payload.
pub const MAX_SNOWFLAKE_FINDINGS: usize = MAX_SNOWFLAKE_STATEMENTS;
/// Maximum number of local include directives returned from one payload.
pub const MAX_SNOWFLAKE_INCLUDES: usize = 32;

/// Stable rule used when SQL, CLI options, or nested sources cannot be proven.
pub const UNVERIFIED_RULE: &str = "stdin-unverified";

/// Parser result used when a dialect interpretation splits one `snow sql`
/// invocation into an otherwise valid source plus positional arguments.
pub(crate) const UNEXPECTED_POSITIONAL_REASON: &str =
    "snow sql contains an unexpected positional operand";

/// Fail-closed reason for a PowerShell call whose target is runtime-dependent
/// while its static argv tail has the shape of a `snow sql` invocation.
pub(crate) const DYNAMIC_EXECUTABLE_REASON: &str = "a PowerShell call operator can resolve a runtime-dependent executable with a snow sql argument shape";

/// Fail-closed reason for a command that exceeds the bounded Snowflake CLI
/// parser's input budget.
pub(crate) const OVERSIZED_CLI_REASON: &str =
    "the shell command exceeds the bounded Snowflake CLI analysis budget";

/// Whether the command is too large for complete Snowflake CLI analysis.
///
/// The hook's outer command limit is configurable and may be larger than this
/// parser's defensive bound. Once the Snowflake pack is enabled, exceeding the
/// inner bound must therefore select the pack and fail closed rather than look
/// indistinguishable from a command with no `snow sql` invocation.
#[must_use]
pub(crate) fn snowflake_cli_exceeds_analysis_budget(command: &str) -> bool {
    command.len() > MAX_SNOWFLAKE_CLI_BYTES
}

fn snow_executable(word: &str) -> bool {
    let basename = word.rsplit(['/', '\\']).next().unwrap_or(word);
    basename.eq_ignore_ascii_case("snow") || basename.eq_ignore_ascii_case("snow.exe")
}

fn snowsql_executable(word: &str) -> bool {
    let basename = word.rsplit(['/', '\\']).next().unwrap_or(word);
    basename.eq_ignore_ascii_case("snowsql") || basename.eq_ignore_ascii_case("snowsql.exe")
}

/// Rewrite a legacy SnowSQL (`snowsql`) argv as the `snow sql` argv with the
/// same executable surface, so both clients share one fail-closed analyzer.
///
/// SnowSQL takes SQL from `-q`/`--query`, files from `-f`/`--filename`, and
/// otherwise reads stdin or opens a REPL -- the same three surfaces `snow sql`
/// has. Connection and session options are consumed with their documented
/// arity and dropped. Anything else -- an unknown option, a positional, `--`,
/// or `-v` followed by a bare word (its value is optional, so its arity is
/// ambiguous) -- is passed through or replaced by an unknown option, which the
/// `snow sql` parser already fails closed on. Returns `None` for `--help`.
#[must_use]
pub(crate) fn snowsql_args_as_snow_sql(args: &[String]) -> Option<Vec<String>> {
    const VALUE_SHORT: &[&str] = &[
        "-a", "-u", "-d", "-s", "-r", "-w", "-h", "-p", "-m", "-o", "-c", "-D",
    ];
    const VALUE_LONG: &[&str] = &[
        "accountname",
        "username",
        "dbname",
        "schemaname",
        "rolename",
        "warehouse",
        "host",
        "port",
        "region",
        "mfa-passcode",
        "authenticator",
        "token",
        "variable",
        "option",
        "query_tag",
        "config",
        "private-key-path",
        "connection",
    ];
    const FLAG_SHORT: &[&str] = &["-P", "-M", "-U", "-K"];
    const FLAG_LONG: &[&str] = &[
        "mfa-passcode-in-password",
        "abort-detached-query",
        "probe-connection",
        "prompt",
        "mfa-prompt",
        "noup",
        "versions",
        "single-transaction",
        "disable-request-pooling",
        "upgrade",
        "client-session-keep-alive",
        "include_connector_version",
    ];
    const AMBIGUOUS: &str = "--dcg-snowsql-ambiguous-option-arity";

    let mut out = vec!["sql".to_string()];
    let mut index = 0usize;
    while index < args.len() {
        let arg = args[index].as_str();
        if matches!(arg, "-?" | "--help") {
            return None;
        }
        if arg == "--" {
            out.extend(args[index..].iter().cloned());
            break;
        }
        // SQL and file sources keep their spelling; `snow sql` accepts the
        // same `-q`/`--query`/`-f`/`--filename` forms, attached or not.
        if matches!(arg, "-q" | "--query" | "-f" | "--filename") {
            out.push(if arg.contains('q') { "-q" } else { "-f" }.to_string());
            if let Some(value) = args.get(index + 1) {
                out.push(value.clone());
            }
            index += 2;
            continue;
        }
        if arg.starts_with("--query=")
            || arg.starts_with("--filename=")
            || (arg.len() > 2 && (arg.starts_with("-q") || arg.starts_with("-f")))
        {
            out.push(arg.to_string());
            index += 1;
            continue;
        }
        if matches!(arg, "-v" | "--version") {
            if args
                .get(index + 1)
                .is_some_and(|next| !next.starts_with('-'))
            {
                out.push(AMBIGUOUS.to_string());
                break;
            }
            index += 1;
            continue;
        }
        if VALUE_SHORT.contains(&arg) {
            if args.get(index + 1).is_none() {
                out.push(AMBIGUOUS.to_string());
                break;
            }
            index += 2;
            continue;
        }
        if FLAG_SHORT.contains(&arg) {
            index += 1;
            continue;
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (name, attached) = long
                .split_once('=')
                .map_or((long, None), |(name, value)| (name, Some(value)));
            if VALUE_LONG.contains(&name) || name == "version" {
                if attached.is_none() {
                    if args.get(index + 1).is_none() {
                        out.push(AMBIGUOUS.to_string());
                        break;
                    }
                    index += 1;
                }
                index += 1;
                continue;
            }
            if FLAG_LONG.contains(&name) && attached.is_none() {
                index += 1;
                continue;
            }
            out.push(arg.to_string());
            index += 1;
            continue;
        }
        // An attached short value (`-aACCOUNT`) for a value option.
        if arg.len() > 2 && VALUE_SHORT.contains(&&arg[..2]) {
            index += 1;
            continue;
        }
        // Unknown short options and positionals: `snow sql` rejects both.
        out.push(arg.to_string());
        index += 1;
    }
    Some(out)
}

/// Present a `snowsql` invocation to executable-keyed consumers as the
/// equivalent `snow sql` one; every other invocation is returned unchanged.
#[must_use]
pub(crate) fn canonical_snow_invocation(
    executable: String,
    args: Vec<String>,
) -> (String, Vec<String>) {
    if snowsql_executable(&executable) {
        if let Some(translated) = snowsql_args_as_snow_sql(&args) {
            return ("snow".to_string(), translated);
        }
    }
    (executable, args)
}

fn decode_static_words(input: &str, dialect: ShellDialect) -> Option<Vec<String>> {
    let tokens = tokenize_for_shell_dialect(input, dialect);
    if tokens.len() > MAX_SNOWFLAKE_CLI_TOKENS
        || tokens
            .iter()
            .any(|token| token.kind == NormalizeTokenKind::Separator)
    {
        return None;
    }
    let mut decoder = ShellTokenDecoder::new(dialect);
    tokens
        .iter()
        .filter(|token| token.kind == NormalizeTokenKind::Word)
        .map(|token| {
            let raw = token.text(input)?;
            decoder
                .decode(raw, ShellTokenRole::Syntax)
                .map(std::borrow::Cow::into_owned)
        })
        .collect()
}

fn snow_args_from_segment(segment: &str, dialect: ShellDialect) -> Option<Vec<String>> {
    let segment = segment.trim();
    if segment.is_empty() {
        return None;
    }

    if dialect == ShellDialect::PowerShell
        && segment
            .strip_prefix('&')
            .is_some_and(|tail| tail.chars().next().is_some_and(char::is_whitespace))
    {
        if let Some((executable, tail)) =
            crate::packs::core::git::powershell_static_call_executable(segment)
        {
            let executable = executable?;
            if snowsql_executable(&executable) {
                return decode_static_words(tail, dialect)
                    .and_then(|args| snowsql_args_as_snow_sql(&args));
            }
            return snow_executable(&executable)
                .then(|| decode_static_words(tail, dialect))
                .flatten();
        }
    }

    let stripped = (dialect == ShellDialect::Posix).then(|| strip_wrapper_prefixes(segment));
    let input = stripped
        .as_ref()
        .map_or(segment, |result| result.normalized.as_ref());
    let tokens = tokenize_for_shell_dialect(input, dialect);
    if tokens.len() > MAX_SNOWFLAKE_CLI_TOKENS
        || tokens
            .iter()
            .any(|token| token.kind == NormalizeTokenKind::Separator)
    {
        return None;
    }

    let mut decoder = ShellTokenDecoder::new(dialect);
    let mut words = Vec::with_capacity(tokens.len());
    for token in tokens
        .iter()
        .filter(|token| token.kind == NormalizeTokenKind::Word)
    {
        let raw = token.text(input)?;
        let Some(decoded) = decoder.decode(raw, ShellTokenRole::Syntax) else {
            continue;
        };
        words.push((raw, decoded.into_owned()));
    }

    let mut index = 0usize;
    if matches!(dialect, ShellDialect::Posix | ShellDialect::Unknown) {
        while words
            .get(index)
            .is_some_and(|(_, word)| crate::normalize::is_env_assignment(word))
        {
            index += 1;
        }
    }
    if dialect == ShellDialect::Cmd {
        while let Some((_, word)) = words.get_mut(index) {
            *word = word.trim_start_matches('@').to_string();
            if word.is_empty() || word.eq_ignore_ascii_case("call") {
                index += 1;
            } else {
                break;
            }
        }
    }
    if dialect == ShellDialect::PowerShell {
        let (raw, word) = words.get(index)?;
        if word == "&" {
            index += 1;
        } else if raw.starts_with(['\'', '"']) {
            // A bare quoted value is data in PowerShell. Only the call
            // operator can promote it to an executable command word.
            return None;
        }
    }

    let (_, executable) = words.get(index)?;
    let is_snowsql = snowsql_executable(executable);
    if !snow_executable(executable) && !is_snowsql {
        return None;
    }
    let args: Vec<String> = words
        .into_iter()
        .skip(index + 1)
        .map(|(_, word)| word)
        .collect();
    if is_snowsql {
        return snowsql_args_as_snow_sql(&args);
    }
    Some(args)
}

fn powershell_dynamic_snow_sql_target(segment: &str) -> bool {
    let Some((executable, tail)) =
        crate::packs::core::git::powershell_static_call_executable(segment)
    else {
        return false;
    };
    if executable.is_some() {
        return false;
    }
    let Some(args) = decode_static_words(tail, ShellDialect::PowerShell) else {
        return false;
    };
    analyze_snow_sql_args(&args).is_sql_command()
}

/// Whether a statement-leading PowerShell call operator has a dynamic target
/// and a bounded, static argv tail that could invoke `snow sql`.
///
/// This is deliberately narrower than "dynamic call operator": proven static
/// non-`snow` targets and inert strings are not candidates. Both caller-proven
/// PowerShell and Unknown mode are supported because Unknown mode performs the
/// same conservative cross-dialect recovery as [`snow_cli_args_in_dialect`].
#[must_use]
pub(crate) fn dynamic_snowflake_executable_unverified(
    command: &str,
    dialect: ShellDialect,
) -> bool {
    if snowflake_cli_exceeds_analysis_budget(command)
        || !matches!(dialect, ShellDialect::PowerShell | ShellDialect::Unknown)
    {
        return false;
    }

    if powershell_dynamic_snow_sql_target(command) {
        return true;
    }
    let segments =
        crate::packs::split_command_segments_in_dialect(command, ShellDialect::PowerShell);
    segments.len() <= MAX_SNOWFLAKE_CLI_SEGMENTS
        && segments.into_iter().any(powershell_dynamic_snow_sql_target)
}

/// Recover argv vectors for statically identifiable `snow` invocations using
/// only caller-proven shell syntax. The bounded, command-position parser does
/// not reinterpret quoted arguments to unrelated executables as commands.
#[must_use]
pub(crate) fn snow_cli_args_in_dialect(command: &str, dialect: ShellDialect) -> Vec<Vec<String>> {
    if snowflake_cli_exceeds_analysis_budget(command) {
        return Vec::new();
    }
    if dialect == ShellDialect::Unknown {
        let mut matches = Vec::new();
        for candidate in [
            ShellDialect::Posix,
            ShellDialect::PowerShell,
            ShellDialect::Cmd,
        ] {
            for args in snow_cli_args_in_dialect(command, candidate) {
                if !matches.contains(&args) {
                    matches.push(args);
                }
            }
        }
        return matches;
    }

    // Resolve only the bounded literal-printf substitution subset already
    // shared by semantic executable recovery. This turns
    // `$(printf snow) sql ...` into a concrete Snowflake invocation while
    // leaving every runtime-dependent substitution opaque.
    let resolved_posix = (dialect == ShellDialect::Posix)
        .then(|| crate::packs::core::git::posix_substitution_view(command))
        .transpose()
        .ok()
        .flatten()
        .filter(|view| !view.has_dynamic && view.command != command);
    let command = resolved_posix
        .as_ref()
        .map_or(command, |view| view.command.as_str());

    let segments = crate::packs::split_command_segments_in_dialect(command, dialect);
    if segments.len() > MAX_SNOWFLAKE_CLI_SEGMENTS {
        return Vec::new();
    }
    let mut matches = Vec::new();
    if dialect == ShellDialect::PowerShell {
        if let Some(args) = snow_args_from_segment(command, dialect) {
            matches.push(args);
        }
    }
    for segment in segments {
        if let Some(args) = snow_args_from_segment(segment, dialect) {
            if !matches.contains(&args) {
                matches.push(args);
            }
        }
    }
    matches
}

/// Candidate-selection override for a shell-obfuscated `snow` executable.
#[must_use]
pub(crate) fn snowflake_semantic_scan_required(command: &str, dialect: ShellDialect) -> bool {
    snowflake_cli_exceeds_analysis_budget(command)
        || !snow_cli_args_in_dialect(command, dialect).is_empty()
        || dynamic_snowflake_executable_unverified(command, dialect)
}

const REVIEW_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "SHOW <object-type> LIKE '<name>'",
        "Confirm the exact target and current object before changing it",
    ),
    PatternSuggestion::new(
        "CREATE <object-type> <backup> CLONE <source>",
        "Create a zero-copy clone before destructive DDL",
    ),
    PatternSuggestion::new(
        "SELECT COUNT(*) FROM <target>",
        "Measure the affected data and preview representative rows first",
    ),
];

const ACCESS_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "SHOW GRANTS ON <object>",
        "Review current grants before changing access or ownership",
    ),
    PatternSuggestion::new(
        "GRANT <required-privilege> ON <specific-object> TO ROLE <role>",
        "Grant only the required privilege on a specific object",
    ),
];

const INGESTION_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "SHOW PIPES; SHOW STREAMS; SHOW TASKS;",
        "Inspect pipeline state and downstream dependencies first",
    ),
    PatternSuggestion::new(
        "ALTER <PIPE|TASK|WAREHOUSE> <name> RESUME",
        "Prefer a reviewed, explicitly reversible lifecycle operation",
    ),
];

/// Create the Snowflake CLI pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "database.snowflake".to_string(),
        name: "Snowflake CLI",
        description: "Protects modern `snow sql` queries, files, stdin, nested sources, data, \
                      ingestion, compute, and account privileges",
        keywords: &[
            "snow",
            "snowsql",
            "Snow",
            "SNOW",
            "DROP",
            "drop",
            "TRUNCATE",
            "truncate",
            "DELETE",
            "delete",
            "UPDATE",
            "update",
            "ALTER",
            "alter",
            "GRANT",
            "grant",
            "REVOKE",
            "revoke",
            "REMOVE",
            "remove",
            "OVERWRITE",
            "overwrite",
            "EXECUTE",
            "execute",
        ],
        // Whole-command safe regexes are intentionally absent. A safe first
        // statement must never whitelist a destructive later statement.
        safe_patterns: create_safe_patterns(),
        // These entries provide stable metadata for semantic matches. Their
        // regexes are deliberately impossible; evaluator integration must call
        // `scan_sql` over the recovered SQL payload.
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: true,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    Vec::new()
}

#[allow(clippy::too_many_lines)]
fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "stdin-unverified",
            r"(?!)",
            "snow sql receives SQL or a source that dcg cannot completely verify.",
            High,
            "Materialize the exact rendered SQL, keep all !source inputs local, and review every statement before execution.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "drop-database",
            r"(?!)",
            "DROP DATABASE removes the database and every contained schema and object.",
            Critical,
            "Snowflake Time Travel and UNDROP are conditional on object support, retention, privileges, and subsequent operations; they are not a substitute for preventing the drop.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "drop-schema",
            r"(?!)",
            "DROP SCHEMA removes the schema and can remove all contained objects.",
            Critical,
            "Review the schema contents, prefer RESTRICT where supported, and clone the schema before broad DDL.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "drop-table",
            r"(?!)",
            "DROP TABLE removes the active table and its data.",
            Critical,
            "Verify the fully qualified target, inspect retention, and create a zero-copy clone before dropping the table.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "replace-database",
            r"(?!)",
            "CREATE OR REPLACE DATABASE replaces a live database.",
            Critical,
            "Create and validate a separate database or clone instead of replacing the active database in place.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "replace-schema",
            r"(?!)",
            "CREATE OR REPLACE SCHEMA replaces a live schema.",
            Critical,
            "Clone the schema and test the migration against the clone before changing production.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "replace-table",
            r"(?!)",
            "CREATE OR REPLACE TABLE replaces the active table.",
            Critical,
            "Build and validate a separate table or clone, then use a reviewed cutover operation.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "truncate-table",
            r"(?!)",
            "TRUNCATE TABLE removes every row from the target table.",
            Critical,
            "Preview the row count and clone the table before truncating it.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "delete-all",
            r"(?!)",
            "DELETE without a top-level WHERE clause removes every row.",
            Critical,
            "Add a reviewed WHERE predicate and run the equivalent SELECT and COUNT first.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "update-all",
            r"(?!)",
            "UPDATE without a top-level WHERE clause modifies every row.",
            Critical,
            "Add a reviewed WHERE predicate and preview the exact target rows first.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "drop-data-product",
            r"(?!)",
            "DROP removes a live view, materialized view, or dynamic table.",
            High,
            "Inspect dependencies and validate a replacement object before removing the live query surface.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "drop-ingestion-object",
            r"(?!)",
            "DROP removes a live stage, pipe, stream, or task.",
            High,
            "Inspect pipeline dependencies and state before removing an ingestion or scheduling object.",
            INGESTION_SUGGESTIONS
        ),
        destructive_pattern!(
            "drop-warehouse",
            r"(?!)",
            "DROP WAREHOUSE removes compute used by applications, tasks, or users.",
            High,
            "Inspect warehouse consumers and prefer a reversible suspend only after reviewing active workloads.",
            INGESTION_SUGGESTIONS
        ),
        destructive_pattern!(
            "drop-principal",
            r"(?!)",
            "DROP USER or DROP ROLE can break services and revoke access hierarchies.",
            High,
            "Review grants and dependencies, then disable access reversibly before deleting a principal.",
            ACCESS_SUGGESTIONS
        ),
        destructive_pattern!(
            "drop-security-object",
            r"(?!)",
            "DROP removes a live integration, network policy, or share.",
            High,
            "Review all consumers, grants, and recovery options before removing the security or sharing object.",
            ACCESS_SUGGESTIONS
        ),
        destructive_pattern!(
            "drop-programmable-object",
            r"(?!)",
            "DROP removes a file format, sequence, function, or procedure used by workloads.",
            Medium,
            "Inspect object dependencies and preserve the current definition before removal.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "remove-stage-files",
            r"(?!)",
            "REMOVE deletes files from an internal Snowflake stage.",
            High,
            "LIST the exact stage path and verify retention or a backup before removing files.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "pause-pipe",
            r"(?!)",
            "ALTER PIPE pauses ingestion and can silently make downstream data stale.",
            High,
            "Inspect pipe status and downstream freshness requirements before pausing ingestion.",
            INGESTION_SUGGESTIONS
        ),
        destructive_pattern!(
            "suspend-task",
            r"(?!)",
            "ALTER TASK SUSPEND stops scheduled execution.",
            High,
            "Inspect task dependencies and active runs before suspending the task.",
            INGESTION_SUGGESTIONS
        ),
        destructive_pattern!(
            "execute-task",
            r"(?!)",
            "EXECUTE TASK immediately starts a task run and may cascade a task graph.",
            High,
            "Inspect the task definition, owner privileges, graph dependencies, and active runs before forcing execution.",
            INGESTION_SUGGESTIONS
        ),
        destructive_pattern!(
            "suspend-warehouse",
            r"(?!)",
            "ALTER WAREHOUSE SUSPEND can interrupt active or queued workloads.",
            High,
            "Inspect active queries and dependent tasks before suspending compute.",
            INGESTION_SUGGESTIONS
        ),
        destructive_pattern!(
            "broad-revoke",
            r"(?!)",
            "REVOKE removes broad privileges or role membership and can break applications immediately.",
            High,
            "Review current grants and identify every affected principal before revoking access.",
            ACCESS_SUGGESTIONS
        ),
        destructive_pattern!(
            "broad-grant",
            r"(?!)",
            "GRANT creates account-wide, all-privilege, or ACCOUNTADMIN access.",
            High,
            "Grant only the required privileges on specific objects to a least-privilege role.",
            ACCESS_SUGGESTIONS
        ),
        destructive_pattern!(
            "transfer-ownership",
            r"(?!)",
            "GRANT OWNERSHIP transfers control and can revoke or copy existing grants.",
            High,
            "Inventory outbound privileges and review COPY/REVOKE CURRENT GRANTS semantics before transferring ownership.",
            ACCESS_SUGGESTIONS
        ),
        destructive_pattern!(
            "alter-table-drop-column",
            r"(?!)",
            "ALTER TABLE DROP COLUMN removes a column and its active data.",
            High,
            "Clone the table and validate all downstream consumers before removing the column.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "alter-table-swap",
            r"(?!)",
            "ALTER TABLE SWAP WITH exchanges table identities atomically.",
            High,
            "Verify both fully qualified tables and compare row counts and schemas before swapping.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "insert-overwrite",
            r"(?!)",
            "INSERT OVERWRITE replaces the target table's current rows.",
            High,
            "Write to and validate a separate table before a reviewed cutover.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "copy-overwrite",
            r"(?!)",
            "COPY INTO a location with OVERWRITE = TRUE can replace exported files.",
            High,
            "Export to a versioned path and LIST the destination before copying.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "put-overwrite",
            r"(?!)",
            "PUT with OVERWRITE = TRUE can replace files in an internal stage.",
            High,
            "Upload to a versioned stage path and LIST existing files first.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "replace-live-object",
            r"(?!)",
            "CREATE OR REPLACE replaces a live Snowflake object and may lose grants, state, or configuration.",
            High,
            "Create and validate a separate object before changing the live definition.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "bounded-delete",
            r"(?!)",
            "DELETE mutates every row selected by its WHERE predicate.",
            Medium,
            "Run the equivalent SELECT and COUNT against a clone before deleting rows.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "bounded-update",
            r"(?!)",
            "UPDATE mutates every row selected by its WHERE predicate.",
            Medium,
            "Preview affected rows and validate the update against a clone first.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "merge-data",
            r"(?!)",
            "MERGE can update, insert, or delete rows based on source matching.",
            Medium,
            "Validate source uniqueness and preview matched and unmatched rows against a clone.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "copy-into-table",
            r"(?!)",
            "COPY INTO a table can load duplicate, corrupt, or unexpected data.",
            Medium,
            "Validate the staged files and load into a clone or scratch table first.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "rename-object",
            r"(?!)",
            "Renaming a database, schema, or table can break fully qualified consumers.",
            Medium,
            "Inventory consumers and stage a coordinated cutover before renaming the object.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "alter-column",
            r"(?!)",
            "ALTER TABLE ALTER COLUMN can break writes and downstream consumers.",
            Medium,
            "Validate type, nullability, default, and policy changes against a clone first.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "warehouse-settings",
            r"(?!)",
            "ALTER WAREHOUSE SET can create availability or cost risk.",
            Medium,
            "Review active consumers, size, scaling, and auto-suspend settings before applying changes.",
            INGESTION_SUGGESTIONS
        ),
        destructive_pattern!(
            "abort-query",
            r"(?!)",
            "!abort cancels an active Snowflake query.",
            Medium,
            "Inspect query history and confirm the exact query ID before aborting it.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "interactive-edit",
            r"(?!)",
            "!edit executes SQL modified in an external editor that dcg cannot inspect in advance.",
            High,
            "Materialize the final SQL in a reviewed local file and execute it with snow sql -f.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "shell-escape",
            r"(?!)",
            "!system runs a shell command from inside the SnowSQL session, outside dcg's shell analysis.",
            High,
            "SnowSQL's !system passes its operand to the operating-system shell. Run that \
             command directly in the shell instead, where dcg evaluates it like any other command.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "execute-immediate",
            r"(?!)",
            "EXECUTE IMMEDIATE runs generated SQL whose rendered semantics require explicit review.",
            Medium,
            "Materialize and review the exact rendered SQL, including templates and variables, before executing it.",
            REVIEW_SUGGESTIONS
        ),
        // ------------------------------------------------------------------
        // CLI-surface drops. Unlike the semantic `snow sql` entries above,
        // these are ordinary regexes over the (sanitized) command line: the
        // Snowflake CLI can drop live objects directly, without any SQL
        // payload, via `snow object drop`, `snow stage drop`/`remove`,
        // `snow app teardown`, `snow spcs ... drop`, and `snow snowpark
        // drop` — and `--force` variants skip the interactive confirmation.
        // The shared prefix accepts global options (with values) between
        // `snow` and the subcommand path while refusing to cross shell
        // separators.
        // ------------------------------------------------------------------
        destructive_pattern!(
            "cli-object-drop-database",
            r"(?:^|[\s;&|(])snow(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+object\s+drop\s+(?:database|schema)\b",
            "snow object drop database/schema removes the object and everything inside it.",
            Critical,
            "Dropping a database or schema removes ALL contained objects (tables, views, \
             stages, pipes, tasks, functions). Time Travel/UNDROP recovery is conditional \
             on retention, edition, and privileges - it is not a substitute for preventing \
             the drop. Verify with `snow object list database` / `snow object describe` \
             and consider `CREATE DATABASE <name>_backup CLONE <name>` first.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "cli-object-drop",
            r"(?:^|[\s;&|(])snow(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+object\s+drop\b",
            "snow object drop permanently removes a Snowflake object.",
            High,
            "snow object drop removes tables, views, stages, streams, tasks, warehouses, \
             users, roles, integrations, and more; --force skips the confirmation prompt. \
             Dropping shared infrastructure can break applications and automation \
             immediately. Inspect first with `snow object describe <type> <name>`.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "cli-stage-drop",
            r"(?:^|[\s;&|(])snow(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+stage\s+drop\b",
            "snow stage drop removes the stage; internal staged files are not recoverable.",
            High,
            "Dropped stages cannot be recovered - internal stage files are gone, and \
             workflows (COPY INTO, Snowpipe) referencing the stage break immediately. \
             List contents first with `snow stage list-files <stage>`.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "cli-stage-remove",
            r"(?:^|[\s;&|(])snow(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+stage\s+remove\b",
            "snow stage remove deletes files from a stage.",
            High,
            "Files removed from an internal stage are not covered by Time Travel. \
             Ingestion pipelines expecting those files will silently see nothing to \
             load. Preview with `snow stage list-files <stage>` and consider copying \
             the files out first.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "cli-app-teardown",
            r"(?:^|[\s;&|(])snow(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+app\s+teardown\b",
            "snow app teardown drops the Native App and (with --cascade) its owned objects.",
            High,
            "snow app teardown drops the application object and the application \
             package's development artifacts; with --cascade it also drops objects the \
             app owns, databases included. Anyone using the app loses access \
             immediately.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "cli-app-version-drop",
            r"(?:^|[\s;&|(])snow(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+app\s+version\s+drop\b",
            "snow app version drop removes a Native App version definition.",
            Medium,
            "Dropping an application package version prevents new installs and upgrades \
             of that version; releases pinned to it break.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "cli-snowpark-drop",
            r"(?:^|[\s;&|(])snow(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+snowpark\s+drop\b",
            "snow snowpark drop removes a deployed procedure or function from Snowflake.",
            Medium,
            "snow snowpark drop function/procedure drops the named object from \
             Snowflake. Downstream callers (tasks, other procedures, applications) \
             fail until it is redeployed.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "cli-spcs-drop",
            r"(?:^|[\s;&|(])snow(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+spcs\s+(?:service|compute-pool|image-repository)\s+drop\b",
            "snow spcs ... drop removes container services infrastructure.",
            High,
            "Dropping an SPCS service stops and removes the running workload; dropping \
             a compute pool removes the compute for every service on it; dropping an \
             image repository deletes the stored images.",
            INGESTION_SUGGESTIONS
        ),
        destructive_pattern!(
            "cli-dbt-drop",
            r"(?:^|[\s;&|(])snow(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+dbt\s+drop\b",
            "snow dbt drop removes a dbt project object from Snowflake.",
            Medium,
            "snow dbt drop removes the named DBT PROJECT object; scheduled `snow dbt \
             execute` runs and tasks referencing it fail until it is redeployed.",
            REVIEW_SUGGESTIONS
        ),
        destructive_pattern!(
            "cli-dcm-drop",
            r"(?:^|[\s;&|(])snow(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+dcm\s+drop\b",
            "snow dcm drop removes a DCM project object from Snowflake.",
            Medium,
            "snow dcm drop removes the named DCM PROJECT object, including its \
             deployment history in Snowflake.",
            REVIEW_SUGGESTIONS
        ),
    ]
}

/// Whether Snowflake CLI templating can render code before submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnowflakeTemplating {
    /// Default/current CLI behavior, or any explicitly enabled templating mode.
    Enabled,
    /// `--enable-templating NONE` was explicitly selected.
    Disabled,
}

impl Default for SnowflakeTemplating {
    fn default() -> Self {
        Self::Enabled
    }
}

/// Parsed code-bearing surfaces of one `snow sql` argv vector.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SnowSqlCliAnalysis<'a> {
    /// SQL values supplied by `-q` / `--query`.
    pub query_values: Vec<&'a str>,
    /// Files supplied by repeatable `-f` / `--filename`.
    pub file_values: Vec<&'a str>,
    /// Whether stdin is executable SQL (`-i`, a stdin pseudo-file, or REPL).
    pub reads_stdin_as_code: bool,
    /// Whether nested remote sources are rejected by the CLI.
    pub local_only: bool,
    /// Effective client-side templating behavior.
    pub templating: SnowflakeTemplating,
    /// Whether SQL comments survive client-side templating.
    pub retain_comments: bool,
    /// Why argv analysis must fail closed, if option arity was ambiguous.
    pub unverified_reason: Option<&'static str>,
}

impl SnowSqlCliAnalysis<'_> {
    /// True when the argv vector is a modern `snow sql` invocation.
    #[must_use]
    pub fn is_sql_command(&self) -> bool {
        !self.query_values.is_empty()
            || !self.file_values.is_empty()
            || self.reads_stdin_as_code
            || self.local_only
            || self.unverified_reason.is_some()
    }
}

/// Parse arguments after the `snow` executable and identify executable SQL.
///
/// Unknown/future options are fail-closed because their arity can hide a later
/// `-q` or `-f` operand. `snow sql` without an explicit source enters the REPL,
/// so stdin remains code-bearing when the shell supplies a pipe or redirect.
#[must_use]
pub fn analyze_snow_sql_args(args: &[String]) -> SnowSqlCliAnalysis<'_> {
    const VALUE_OPTIONS: &[&str] = &[
        "variable",
        "enable-templating",
        "project",
        "env",
        "connection",
        "environment",
        "host",
        "port",
        "account",
        "accountname",
        "user",
        "username",
        "password",
        "authenticator",
        "workload-identity-provider",
        "private-key-file",
        "private-key-path",
        "token",
        "token-file-path",
        "database",
        "dbname",
        "schema",
        "schemaname",
        "role",
        "rolename",
        "warehouse",
        "mfa-passcode",
        "diag-log-path",
        "diag-allowlist-path",
        "oauth-client-id",
        "oauth-client-secret",
        "oauth-authorization-url",
        "oauth-token-request-url",
        "oauth-redirect-uri",
        "oauth-scope",
        "format",
        "decimal-precision",
    ];
    const FLAG_OPTIONS: &[&str] = &[
        "retain-comments",
        "single-transaction",
        "no-single-transaction",
        "local-only",
        "no-prompt-exit-repl",
        "temporary-connection",
        "enable-diag",
        "oauth-disable-pkce",
        "oauth-enable-refresh-tokens",
        "oauth-enable-single-use-refresh-tokens",
        "client-store-temporary-credential",
        "verbose",
        "debug",
        "silent",
        "enhanced-exit-codes",
    ];

    let mut pre_index = 0usize;
    let sql_index = loop {
        let Some(arg) = args.get(pre_index) else {
            return SnowSqlCliAnalysis::default();
        };
        if matches!(arg.as_str(), "--help" | "-h" | "--version" | "-V") {
            return SnowSqlCliAnalysis::default();
        }
        if arg == "sql" {
            break pre_index;
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (name, attached) = long
                .split_once('=')
                .map_or((long, None), |(name, value)| (name, Some(value)));
            if VALUE_OPTIONS.contains(&name) {
                if attached.is_none() {
                    if args.get(pre_index + 1).is_none() {
                        return SnowSqlCliAnalysis::default();
                    }
                    pre_index += 2;
                } else {
                    pre_index += 1;
                }
                continue;
            }
            if FLAG_OPTIONS.contains(&name) && attached.is_none() {
                pre_index += 1;
                continue;
            }
            return ambiguous_pre_sql_option(args, pre_index);
        }
        if matches!(arg.as_str(), "-D" | "-p" | "-c") {
            if args.get(pre_index + 1).is_none() {
                return SnowSqlCliAnalysis::default();
            }
            pre_index += 2;
            continue;
        }
        if arg.starts_with("-D") || arg.starts_with("-p") || arg.starts_with("-c") {
            pre_index += 1;
            continue;
        }
        if matches!(arg.as_str(), "-x" | "-v") {
            pre_index += 1;
            continue;
        }
        if arg.starts_with('-') {
            return ambiguous_pre_sql_option(args, pre_index);
        }
        // The first positional token is the command group. A connection or
        // option value named `sql` must not be mistaken for that group.
        return SnowSqlCliAnalysis::default();
    };

    let mut analysis = SnowSqlCliAnalysis::default();
    let mut explicit_source = false;
    let mut index = sql_index + 1;
    while index < args.len() {
        let arg = &args[index];
        if matches!(arg.as_str(), "--help" | "-h") {
            return SnowSqlCliAnalysis::default();
        }
        if arg == "--" {
            analysis.unverified_reason = Some(
                "snow sql accepts no positional SQL operands, but argv contains an option terminator",
            );
            break;
        }
        if matches!(arg.as_str(), "-q" | "--query") {
            let Some(value) = args.get(index + 1) else {
                analysis.unverified_reason =
                    Some("snow sql query option is missing its SQL operand");
                break;
            };
            analysis.query_values.push(value);
            explicit_source = true;
            index += 2;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--query=") {
            if value.is_empty() {
                analysis.unverified_reason =
                    Some("snow sql query option has an empty attached operand");
                break;
            }
            analysis.query_values.push(value);
            explicit_source = true;
            index += 1;
            continue;
        }
        if let Some(value) = arg
            .strip_prefix("-q")
            .and_then(|value| (!value.is_empty()).then_some(value.trim_start_matches('=')))
        {
            if value.is_empty() {
                analysis.unverified_reason =
                    Some("snow sql query option has an empty attached operand");
                break;
            }
            analysis.query_values.push(value);
            explicit_source = true;
            index += 1;
            continue;
        }
        if matches!(arg.as_str(), "-f" | "--filename") {
            let Some(value) = args.get(index + 1) else {
                analysis.unverified_reason =
                    Some("snow sql filename option is missing its path operand");
                break;
            };
            if path_reads_stdin(value) {
                analysis.reads_stdin_as_code = true;
            } else {
                analysis.file_values.push(value);
            }
            explicit_source = true;
            index += 2;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--filename=") {
            if value.is_empty() {
                analysis.unverified_reason =
                    Some("snow sql filename option has an empty attached operand");
                break;
            }
            if path_reads_stdin(value) {
                analysis.reads_stdin_as_code = true;
            } else {
                analysis.file_values.push(value);
            }
            explicit_source = true;
            index += 1;
            continue;
        }
        if let Some(value) = arg
            .strip_prefix("-f")
            .and_then(|value| (!value.is_empty()).then_some(value.trim_start_matches('=')))
        {
            if value.is_empty() {
                analysis.unverified_reason =
                    Some("snow sql filename option has an empty attached operand");
                break;
            }
            if path_reads_stdin(value) {
                analysis.reads_stdin_as_code = true;
            } else {
                analysis.file_values.push(value);
            }
            explicit_source = true;
            index += 1;
            continue;
        }
        if matches!(arg.as_str(), "-i" | "--stdin") {
            analysis.reads_stdin_as_code = true;
            explicit_source = true;
            index += 1;
            continue;
        }

        if let Some(long) = arg.strip_prefix("--") {
            let (name, attached) = long
                .split_once('=')
                .map_or((long, None), |(name, value)| (name, Some(value)));
            if name == "local-only" && attached.is_none() {
                analysis.local_only = true;
                index += 1;
                continue;
            }
            if name == "retain-comments" && attached.is_none() {
                analysis.retain_comments = true;
                index += 1;
                continue;
            }
            if VALUE_OPTIONS.contains(&name) {
                let value = if let Some(value) = attached {
                    value
                } else if let Some(value) = args.get(index + 1) {
                    index += 1;
                    value
                } else {
                    analysis.unverified_reason =
                        Some("snow sql option is missing its required value");
                    break;
                };
                if name == "enable-templating" {
                    analysis.templating = if value.eq_ignore_ascii_case("none") {
                        SnowflakeTemplating::Disabled
                    } else {
                        SnowflakeTemplating::Enabled
                    };
                }
                index += 1;
                continue;
            }
            if FLAG_OPTIONS.contains(&name) && attached.is_none() {
                index += 1;
                continue;
            }
            analysis.unverified_reason =
                Some("snow sql contains an unknown option whose operand arity cannot be proven");
            break;
        }

        if matches!(arg.as_str(), "-D" | "-p" | "-c") {
            if args.get(index + 1).is_none() {
                analysis.unverified_reason =
                    Some("snow sql short option is missing its required value");
                break;
            }
            index += 2;
            continue;
        }
        if arg.starts_with("-D") || arg.starts_with("-p") || arg.starts_with("-c") {
            if arg.len() == 2 {
                analysis.unverified_reason =
                    Some("snow sql short option is missing its required value");
                break;
            }
            index += 1;
            continue;
        }
        if matches!(arg.as_str(), "-x" | "-v") {
            index += 1;
            continue;
        }
        if arg.starts_with('-') {
            analysis.unverified_reason = Some(
                "snow sql contains an unknown short option whose operand arity cannot be proven",
            );
            break;
        }

        analysis.unverified_reason = Some(UNEXPECTED_POSITIONAL_REASON);
        break;
    }

    if !explicit_source && analysis.unverified_reason.is_none() {
        analysis.reads_stdin_as_code = true;
    }
    analysis
}

fn path_reads_stdin(path: &str) -> bool {
    let normalized = path.trim().trim_matches(['\'', '"']);
    matches!(
        normalized,
        "-" | "/dev/stdin" | "/dev/fd/0" | "/proc/self/fd/0"
    ) || normalized.starts_with("/dev/fd/0/")
        || normalized.starts_with("/proc/self/fd/0/")
}

fn ambiguous_pre_sql_option(args: &[String], option_index: usize) -> SnowSqlCliAnalysis<'_> {
    let mut analysis = SnowSqlCliAnalysis::default();
    if args[option_index + 1..].iter().any(|arg| arg == "sql") {
        analysis.unverified_reason = Some(
            "snow contains an unknown global option whose operand arity obscures a later sql command",
        );
    }
    analysis
}

/// A semantic Snowflake SQL match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnowflakeSqlMatch {
    /// Stable pattern name in [`create_pack`].
    pub pattern_name: &'static str,
    /// Byte range of the destructive statement in the SQL payload.
    pub statement_span: std::ops::Range<usize>,
}

/// Why a SQL payload could not be verified within the bounded scanner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnowflakeSqlError {
    /// Human-readable fail-closed reason.
    pub reason: String,
}

/// Result of semantic Snowflake SQL analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnowflakeSqlScan {
    /// No guarded semantics were found.
    Safe,
    /// A guarded statement was found.
    Match(SnowflakeSqlMatch),
    /// Analysis was ambiguous or exceeded a hard bound.
    Unverified(SnowflakeSqlError),
}

/// Complete bounded findings for a verified Snowflake SQL payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnowflakeSqlReport {
    /// Highest-severity match, identical to the match returned by [`scan_sql`].
    pub primary: SnowflakeSqlMatch,
    /// Every guarded statement or directive, ordered by its byte position.
    ///
    /// The primary match is also present in this list. Equal-position findings
    /// retain scanner discovery order, making summaries stable across runs.
    pub findings: Vec<SnowflakeSqlMatch>,
}

/// Result of complete bounded Snowflake SQL analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnowflakeSqlReportScan {
    /// No guarded semantics were found.
    Safe,
    /// One or more guarded statements were found.
    Match(SnowflakeSqlReport),
    /// Analysis was ambiguous or exceeded a hard bound.
    Unverified(SnowflakeSqlError),
}

/// Scan SQL using current Snowflake CLI defaults (templating enabled).
#[must_use]
pub fn scan_sql(payload: &str) -> SnowflakeSqlScan {
    scan_sql_with_options(payload, SnowflakeTemplating::Enabled, false)
}

/// Scan SQL and retain every guarded statement in deterministic source order.
#[must_use]
pub fn scan_sql_report(payload: &str) -> SnowflakeSqlReportScan {
    scan_sql_report_with_options(payload, SnowflakeTemplating::Enabled, false)
}

/// Scan SQL using the templating mode proven from `snow sql` argv.
#[must_use]
pub fn scan_sql_with_templating(
    payload: &str,
    templating: SnowflakeTemplating,
) -> SnowflakeSqlScan {
    scan_sql_with_options(payload, templating, false)
}

/// Scan SQL with a proven templating mode and retain every guarded statement.
#[must_use]
pub fn scan_sql_report_with_templating(
    payload: &str,
    templating: SnowflakeTemplating,
) -> SnowflakeSqlReportScan {
    scan_sql_report_with_options(payload, templating, false)
}

/// Scan SQL using all rendering behavior proven from `snow sql` argv.
///
/// Retained comments are included in dynamic-template detection because a
/// rendered value containing a newline can terminate a line comment and emit
/// executable SQL. With the default comment removal, comment text is inert.
#[must_use]
pub fn scan_sql_with_options(
    payload: &str,
    templating: SnowflakeTemplating,
    retain_comments: bool,
) -> SnowflakeSqlScan {
    match scan_sql_report_with_options(payload, templating, retain_comments) {
        SnowflakeSqlReportScan::Safe => SnowflakeSqlScan::Safe,
        SnowflakeSqlReportScan::Match(report) => SnowflakeSqlScan::Match(report.primary),
        SnowflakeSqlReportScan::Unverified(error) => SnowflakeSqlScan::Unverified(error),
    }
}

/// Scan SQL using all proven rendering behavior and retain every finding.
///
/// Findings are never silently truncated. A payload that would produce more
/// than [`MAX_SNOWFLAKE_FINDINGS`] entries is unverified so callers cannot show
/// an incomplete destructive-operation summary.
#[must_use]
pub fn scan_sql_report_with_options(
    payload: &str,
    templating: SnowflakeTemplating,
    retain_comments: bool,
) -> SnowflakeSqlReportScan {
    if payload.len() > MAX_SNOWFLAKE_SQL_BYTES {
        return unverified_report(format!(
            "Snowflake SQL payload exceeds {MAX_SNOWFLAKE_SQL_BYTES} bytes"
        ));
    }
    if templating == SnowflakeTemplating::Enabled
        && contains_template_code(payload, retain_comments)
    {
        return unverified_report(
            "Snowflake CLI templating can render executable SQL that dcg cannot resolve statically"
                .to_string(),
        );
    }

    let directives = match scan_directives(payload) {
        Ok(directives) => directives,
        Err(error) => return SnowflakeSqlReportScan::Unverified(error),
    };
    let mut findings: Vec<RankedMatch> = directives
        .iter()
        .filter_map(|directive| match directive.kind {
            DirectiveKind::Abort => Some(RankedMatch::new(
                "abort-query",
                Severity::Medium,
                directive.span.clone(),
            )),
            DirectiveKind::Edit => Some(RankedMatch::new(
                "interactive-edit",
                Severity::High,
                directive.span.clone(),
            )),
            DirectiveKind::System => Some(RankedMatch::new(
                "shell-escape",
                Severity::High,
                directive.span.clone(),
            )),
            DirectiveKind::Source => None,
        })
        .collect();
    if findings.len() > MAX_SNOWFLAKE_FINDINGS {
        return too_many_findings();
    }
    // Keep the existing primary-selection contract: the last equal-severity
    // directive wins, and a later SQL statement replaces it only when the
    // statement has strictly greater severity.
    let mut best = findings.iter().max_by_key(|finding| finding.rank).cloned();

    let statements = match lex_statements(payload) {
        Ok(statements) => statements,
        Err(error) => return SnowflakeSqlReportScan::Unverified(error),
    };
    for statement in &statements {
        if let Some(finding) = classify_statement(statement) {
            if best
                .as_ref()
                .is_none_or(|current| finding.rank > current.rank)
            {
                best = Some(finding.clone());
            }
            findings.push(finding);
            if findings.len() > MAX_SNOWFLAKE_FINDINGS {
                return too_many_findings();
            }
        }
    }

    let Some(primary) = best else {
        return SnowflakeSqlReportScan::Safe;
    };
    findings.sort_by_key(|finding| (finding.span.start, finding.span.end));
    SnowflakeSqlReportScan::Match(SnowflakeSqlReport {
        primary: SnowflakeSqlMatch {
            pattern_name: primary.pattern_name,
            statement_span: primary.span,
        },
        findings: findings
            .into_iter()
            .map(|finding| SnowflakeSqlMatch {
                pattern_name: finding.pattern_name,
                statement_span: finding.span,
            })
            .collect(),
    })
}

fn too_many_findings() -> SnowflakeSqlReportScan {
    unverified_report(format!(
        "Snowflake SQL contains more than {MAX_SNOWFLAKE_FINDINGS} guarded findings"
    ))
}

fn unverified_report(reason: String) -> SnowflakeSqlReportScan {
    SnowflakeSqlReportScan::Unverified(SnowflakeSqlError { reason })
}

fn contains_template_code(payload: &str, include_comments: bool) -> bool {
    let bytes = payload.as_bytes();
    if include_comments && (0..bytes.len()).any(|index| template_marker_at(bytes, index)) {
        return true;
    }
    let mut state = DirectiveLexState::Normal;
    let mut index = 0usize;
    while index < bytes.len() {
        if !matches!(state, DirectiveLexState::BlockComment(_)) && template_marker_at(bytes, index)
        {
            return true;
        }
        match state {
            DirectiveLexState::Normal => match bytes[index] {
                b'-' if bytes.get(index + 1) == Some(&b'-') => {
                    index += 2;
                    while index < bytes.len() && !matches!(bytes[index], b'\n' | b'\r') {
                        index += 1;
                    }
                }
                b'/' if bytes.get(index + 1) == Some(&b'*') => {
                    state = DirectiveLexState::BlockComment(1);
                    index += 2;
                }
                b'\'' => {
                    state = DirectiveLexState::SingleQuoted;
                    index += 1;
                }
                b'"' => {
                    state = DirectiveLexState::DoubleQuoted;
                    index += 1;
                }
                b'$' if bytes.get(index + 1) == Some(&b'$') => {
                    state = DirectiveLexState::DollarQuoted;
                    index += 2;
                }
                _ => index += payload[index..].chars().next().map_or(1, char::len_utf8),
            },
            DirectiveLexState::SingleQuoted => {
                if bytes[index] == b'\\' {
                    index = (index + 2).min(bytes.len());
                } else if bytes[index] == b'\'' {
                    if bytes.get(index + 1) == Some(&b'\'') {
                        index += 2;
                    } else {
                        state = DirectiveLexState::Normal;
                        index += 1;
                    }
                } else {
                    index += payload[index..].chars().next().map_or(1, char::len_utf8);
                }
            }
            DirectiveLexState::DoubleQuoted => {
                if bytes[index] == b'"' {
                    if bytes.get(index + 1) == Some(&b'"') {
                        index += 2;
                    } else {
                        state = DirectiveLexState::Normal;
                        index += 1;
                    }
                } else {
                    index += payload[index..].chars().next().map_or(1, char::len_utf8);
                }
            }
            DirectiveLexState::DollarQuoted => {
                if bytes[index] == b'$' && bytes.get(index + 1) == Some(&b'$') {
                    state = DirectiveLexState::Normal;
                    index += 2;
                } else {
                    index += payload[index..].chars().next().map_or(1, char::len_utf8);
                }
            }
            DirectiveLexState::BlockComment(depth) => {
                if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
                    state = DirectiveLexState::BlockComment(depth + 1);
                    index += 2;
                } else if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                    state = if depth == 1 {
                        DirectiveLexState::Normal
                    } else {
                        DirectiveLexState::BlockComment(depth - 1)
                    };
                    index += 2;
                } else {
                    index += payload[index..].chars().next().map_or(1, char::len_utf8);
                }
            }
        }
    }
    false
}

fn template_marker_at(bytes: &[u8], index: usize) -> bool {
    matches!(
        (bytes.get(index), bytes.get(index + 1)),
        (Some(b'<'), Some(b'%')) | (Some(b'{'), Some(b'{' | b'%'))
    ) || (bytes.get(index) == Some(&b'&')
        && bytes
            .get(index + 1)
            .is_some_and(|next| next.is_ascii_alphabetic() || matches!(next, b'_' | b'{')))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenKind {
    Word(String),
    Symbol(u8),
    StringLiteral,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SqlToken {
    kind: TokenKind,
    depth: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SqlStatement {
    span: std::ops::Range<usize>,
    tokens: Vec<SqlToken>,
}

fn lex_statements(payload: &str) -> Result<Vec<SqlStatement>, SnowflakeSqlError> {
    let bytes = payload.as_bytes();
    let mut statements = Vec::new();
    let mut tokens = Vec::new();
    let mut total_tokens = 0usize;
    let mut depth = 0usize;
    let mut statement_start = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            byte if byte.is_ascii_whitespace() => index += 1,
            b'-' if bytes.get(index + 1) == Some(&b'-') => {
                index += 2;
                while index < bytes.len() && !matches!(bytes[index], b'\n' | b'\r') {
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index = skip_block_comment(payload, index)?;
            }
            b'\'' => {
                let end = skip_quoted(payload, index, b'\'')?;
                push_token(
                    &mut tokens,
                    &mut total_tokens,
                    TokenKind::StringLiteral,
                    depth,
                )?;
                index = end;
            }
            b'"' => index = skip_quoted(payload, index, b'"')?,
            b'$' if bytes.get(index + 1) == Some(&b'$') => {
                let Some(end) = payload[index + 2..].find("$$") else {
                    return Err(sql_error("unterminated Snowflake dollar-quoted string"));
                };
                index += 2 + end + 2;
            }
            b';' => {
                if !tokens.is_empty() {
                    statements.push(SqlStatement {
                        span: statement_start..index + 1,
                        tokens: std::mem::take(&mut tokens),
                    });
                    if statements.len() > MAX_SNOWFLAKE_STATEMENTS {
                        return Err(sql_error(format!(
                            "Snowflake SQL contains more than {MAX_SNOWFLAKE_STATEMENTS} statements"
                        )));
                    }
                }
                index += 1;
                if bytes.get(index) == Some(&b'>') {
                    index += 1;
                }
                statement_start = index;
            }
            b'(' => {
                push_token(
                    &mut tokens,
                    &mut total_tokens,
                    TokenKind::Symbol(b'('),
                    depth,
                )?;
                depth += 1;
                index += 1;
            }
            b')' => {
                if depth == 0 {
                    return Err(sql_error("unbalanced closing parenthesis in Snowflake SQL"));
                }
                depth -= 1;
                push_token(
                    &mut tokens,
                    &mut total_tokens,
                    TokenKind::Symbol(b')'),
                    depth,
                )?;
                index += 1;
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = index;
                index += 1;
                while bytes
                    .get(index)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
                {
                    index += 1;
                }
                push_token(
                    &mut tokens,
                    &mut total_tokens,
                    TokenKind::Word(payload[start..index].to_ascii_uppercase()),
                    depth,
                )?;
            }
            symbol => {
                push_token(
                    &mut tokens,
                    &mut total_tokens,
                    TokenKind::Symbol(symbol),
                    depth,
                )?;
                index += payload[index..].chars().next().map_or(1, char::len_utf8);
            }
        }
    }
    if depth != 0 {
        return Err(sql_error("unbalanced parentheses in Snowflake SQL"));
    }
    if !tokens.is_empty() {
        statements.push(SqlStatement {
            span: statement_start..payload.len(),
            tokens,
        });
    }
    if statements.len() > MAX_SNOWFLAKE_STATEMENTS {
        return Err(sql_error(format!(
            "Snowflake SQL contains more than {MAX_SNOWFLAKE_STATEMENTS} statements"
        )));
    }
    Ok(statements)
}

fn skip_quoted(payload: &str, start: usize, quote: u8) -> Result<usize, SnowflakeSqlError> {
    let bytes = payload.as_bytes();
    let mut index = start + 1;
    while index < bytes.len() {
        if quote == b'\'' && bytes[index] == b'\\' {
            if index + 1 >= bytes.len() {
                return Err(sql_error(
                    "unterminated backslash escape in Snowflake string",
                ));
            }
            index += 2;
            continue;
        }
        if bytes[index] == quote {
            if bytes.get(index + 1) == Some(&quote) {
                index += 2;
                continue;
            }
            return Ok(index + 1);
        }
        index += payload[index..].chars().next().map_or(1, char::len_utf8);
    }
    Err(sql_error(if quote == b'\'' {
        "unterminated Snowflake string literal"
    } else {
        "unterminated Snowflake quoted identifier"
    }))
}

fn skip_block_comment(payload: &str, start: usize) -> Result<usize, SnowflakeSqlError> {
    let bytes = payload.as_bytes();
    let mut depth = 1usize;
    let mut index = start + 2;
    while index < bytes.len() {
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            depth += 1;
            index += 2;
        } else if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
            depth -= 1;
            index += 2;
            if depth == 0 {
                return Ok(index);
            }
        } else {
            index += payload[index..].chars().next().map_or(1, char::len_utf8);
        }
    }
    Err(sql_error("unterminated Snowflake SQL block comment"))
}

fn push_token(
    tokens: &mut Vec<SqlToken>,
    total_tokens: &mut usize,
    kind: TokenKind,
    depth: usize,
) -> Result<(), SnowflakeSqlError> {
    *total_tokens += 1;
    if *total_tokens > MAX_SNOWFLAKE_TOKENS {
        return Err(sql_error(format!(
            "Snowflake SQL contains more than {MAX_SNOWFLAKE_TOKENS} tokens"
        )));
    }
    tokens.push(SqlToken { kind, depth });
    Ok(())
}

fn sql_error(reason: impl Into<String>) -> SnowflakeSqlError {
    SnowflakeSqlError {
        reason: reason.into(),
    }
}

#[derive(Debug, Clone)]
struct RankedMatch {
    pattern_name: &'static str,
    rank: u8,
    span: std::ops::Range<usize>,
}

impl RankedMatch {
    fn new(pattern_name: &'static str, severity: Severity, span: std::ops::Range<usize>) -> Self {
        let rank = match severity {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
        };
        Self {
            pattern_name,
            rank,
            span,
        }
    }
}

fn classify_statement(statement: &SqlStatement) -> Option<RankedMatch> {
    let outer = classify_statement_shallow(statement);
    let task_body = task_body_statement(statement).and_then(|body| {
        let words = top_level_words(&body);
        if words.first() == Some(&"CALL") {
            Some(RankedMatch::new(
                UNVERIFIED_RULE,
                Severity::High,
                statement.span.clone(),
            ))
        } else {
            classify_statement_shallow(&body)
        }
    });

    match (outer, task_body) {
        (Some(outer), Some(body)) if outer.rank >= body.rank => Some(outer),
        (Some(_), Some(body)) => Some(body),
        (Some(outer), None) => Some(outer),
        (None, Some(body)) => Some(body),
        (None, None) => None,
    }
}

fn top_level_words(statement: &SqlStatement) -> Vec<&str> {
    statement
        .tokens
        .iter()
        .filter_map(|token| {
            (token.depth == 0)
                .then_some(&token.kind)
                .and_then(|kind| match kind {
                    TokenKind::Word(word) => Some(word.as_str()),
                    TokenKind::Symbol(_) | TokenKind::StringLiteral => None,
                })
        })
        .collect()
}

fn task_body_statement(statement: &SqlStatement) -> Option<SqlStatement> {
    let word_tokens: Vec<(usize, &str)> = statement
        .tokens
        .iter()
        .enumerate()
        .filter_map(|(index, token)| {
            (token.depth == 0)
                .then_some(&token.kind)
                .and_then(|kind| match kind {
                    TokenKind::Word(word) => Some((index, word.as_str())),
                    TokenKind::Symbol(_) | TokenKind::StringLiteral => None,
                })
        })
        .collect();
    let words: Vec<&str> = word_tokens.iter().map(|(_, word)| *word).collect();
    let task_word = if starts(&words, &["CREATE", "TASK"]) {
        1
    } else if starts(&words, &["CREATE", "OR", "REPLACE", "TASK"])
        || starts(&words, &["CREATE", "OR", "ALTER", "TASK"])
    {
        3
    } else {
        return None;
    };
    let as_word = word_tokens
        .iter()
        .enumerate()
        .skip(task_word + 1)
        .find_map(|(word_index, (_, word))| (*word == "AS").then_some(word_index))?;
    let body_token_start = word_tokens.get(as_word)?.0.checked_add(1)?;
    let tokens = statement.tokens.get(body_token_start..)?.to_vec();
    (!tokens.is_empty()).then(|| SqlStatement {
        span: statement.span.clone(),
        tokens,
    })
}

#[allow(clippy::too_many_lines)]
fn classify_statement_shallow(statement: &SqlStatement) -> Option<RankedMatch> {
    let words = top_level_words(statement);
    let span = statement.span.clone();

    // `WITH <name> AS PROCEDURE ... CALL <name>(...)` both defines and executes
    // an anonymous procedure. The body may be SQL, JavaScript, Python, Java,
    // or Scala, and string/dollar-quoted bodies are intentionally opaque to
    // this bounded SQL lexer. Treat the executable envelope as unverified
    // rather than allowing arbitrary procedure code to bypass statement
    // classification merely because its body lexes as a string literal.
    if words.first() == Some(&"WITH")
        && contains_sequence(&words, &["AS", "PROCEDURE"])
        && words.contains(&"CALL")
    {
        return Some(RankedMatch::new(UNVERIFIED_RULE, Severity::High, span));
    }

    if starts(&words, &["DROP", "DATABASE"]) && words.get(2) != Some(&"ROLE") {
        return Some(RankedMatch::new("drop-database", Severity::Critical, span));
    }
    if starts(&words, &["DROP", "SCHEMA"]) {
        return Some(RankedMatch::new("drop-schema", Severity::Critical, span));
    }
    if starts(&words, &["DROP", "TABLE"])
        || starts_any(
            &words,
            &[
                &["DROP", "EXTERNAL", "TABLE"],
                &["DROP", "EVENT", "TABLE"],
                &["DROP", "HYBRID", "TABLE"],
                &["DROP", "ICEBERG", "TABLE"],
            ],
        )
    {
        return Some(RankedMatch::new("drop-table", Severity::Critical, span));
    }
    let replaced_object = replaced_object_words(&words);
    if replaced_object
        .is_some_and(|object| starts(object, &["DATABASE"]) && object.get(1) != Some(&"ROLE"))
    {
        return Some(RankedMatch::new(
            "replace-database",
            Severity::Critical,
            span,
        ));
    }
    if replaced_object.is_some_and(|object| starts(object, &["SCHEMA"])) {
        return Some(RankedMatch::new("replace-schema", Severity::Critical, span));
    }
    if replaced_object.is_some_and(|object| {
        starts_any(
            object,
            &[
                &["TABLE"],
                &["EXTERNAL", "TABLE"],
                &["EVENT", "TABLE"],
                &["HYBRID", "TABLE"],
                &["ICEBERG", "TABLE"],
            ],
        )
    }) {
        return Some(RankedMatch::new("replace-table", Severity::Critical, span));
    }
    if starts(&words, &["TRUNCATE", "TABLE"]) || starts(&words, &["TRUNCATE"]) {
        return Some(RankedMatch::new("truncate-table", Severity::Critical, span));
    }
    if starts(&words, &["DELETE", "FROM"]) {
        let rule = if words.contains(&"WHERE") {
            ("bounded-delete", Severity::Medium)
        } else {
            ("delete-all", Severity::Critical)
        };
        return Some(RankedMatch::new(rule.0, rule.1, span));
    }
    if words.first() == Some(&"UPDATE") && words.contains(&"SET") {
        let rule = if words.contains(&"WHERE") {
            ("bounded-update", Severity::Medium)
        } else {
            ("update-all", Severity::Critical)
        };
        return Some(RankedMatch::new(rule.0, rule.1, span));
    }

    if starts_any(
        &words,
        &[
            &["DROP", "VIEW"],
            &["DROP", "MATERIALIZED", "VIEW"],
            &["DROP", "DYNAMIC", "TABLE"],
        ],
    ) {
        return Some(RankedMatch::new("drop-data-product", Severity::High, span));
    }
    if starts_any(
        &words,
        &[
            &["DROP", "STAGE"],
            &["DROP", "PIPE"],
            &["DROP", "STREAM"],
            &["DROP", "TASK"],
        ],
    ) {
        return Some(RankedMatch::new(
            "drop-ingestion-object",
            Severity::High,
            span,
        ));
    }
    if starts(&words, &["DROP", "WAREHOUSE"]) {
        return Some(RankedMatch::new("drop-warehouse", Severity::High, span));
    }
    if starts(&words, &["DROP", "USER"])
        || starts(&words, &["DROP", "ROLE"])
        || starts(&words, &["DROP", "DATABASE", "ROLE"])
        || starts(&words, &["DROP", "APPLICATION", "ROLE"])
    {
        return Some(RankedMatch::new("drop-principal", Severity::High, span));
    }
    if starts_any(
        &words,
        &[
            &["DROP", "INTEGRATION"],
            &["DROP", "API", "INTEGRATION"],
            &["DROP", "SECURITY", "INTEGRATION"],
            &["DROP", "STORAGE", "INTEGRATION"],
            &["DROP", "NOTIFICATION", "INTEGRATION"],
            &["DROP", "EXTERNAL", "ACCESS", "INTEGRATION"],
            &["DROP", "NETWORK", "POLICY"],
            &["DROP", "SHARE"],
        ],
    ) {
        return Some(RankedMatch::new(
            "drop-security-object",
            Severity::High,
            span,
        ));
    }
    if starts_any(
        &words,
        &[
            &["DROP", "FILE", "FORMAT"],
            &["DROP", "SEQUENCE"],
            &["DROP", "FUNCTION"],
            &["DROP", "EXTERNAL", "FUNCTION"],
            &["DROP", "PROCEDURE"],
        ],
    ) {
        return Some(RankedMatch::new(
            "drop-programmable-object",
            Severity::Medium,
            span,
        ));
    }
    if words.first() == Some(&"REMOVE") {
        return Some(RankedMatch::new("remove-stage-files", Severity::High, span));
    }
    if starts(&words, &["ALTER", "PIPE"])
        && contains_sequence(&words, &["PIPE_EXECUTION_PAUSED", "TRUE"])
    {
        return Some(RankedMatch::new("pause-pipe", Severity::High, span));
    }
    if starts(&words, &["ALTER", "TASK"]) && words.contains(&"SUSPEND") {
        return Some(RankedMatch::new("suspend-task", Severity::High, span));
    }
    if starts(&words, &["EXECUTE", "TASK"]) {
        return Some(RankedMatch::new("execute-task", Severity::High, span));
    }
    if starts(&words, &["ALTER", "WAREHOUSE"]) && words.contains(&"SUSPEND") {
        return Some(RankedMatch::new("suspend-warehouse", Severity::High, span));
    }
    if words.first() == Some(&"REVOKE")
        && (words.contains(&"ALL")
            || words.contains(&"ACCOUNT")
            || words.contains(&"OWNERSHIP")
            || starts(&words, &["REVOKE", "ROLE"])
            || starts(&words, &["REVOKE", "DATABASE", "ROLE"]))
    {
        return Some(RankedMatch::new("broad-revoke", Severity::High, span));
    }
    if starts(&words, &["GRANT", "OWNERSHIP"]) {
        return Some(RankedMatch::new("transfer-ownership", Severity::High, span));
    }
    if words.first() == Some(&"GRANT")
        && (words.contains(&"ALL")
            || contains_sequence(&words, &["ON", "ACCOUNT"])
            || contains_sequence(&words, &["ROLE", "ACCOUNTADMIN"]))
    {
        return Some(RankedMatch::new("broad-grant", Severity::High, span));
    }
    if starts(&words, &["ALTER", "TABLE"]) && contains_sequence(&words, &["DROP", "COLUMN"]) {
        return Some(RankedMatch::new(
            "alter-table-drop-column",
            Severity::High,
            span,
        ));
    }
    if starts(&words, &["ALTER", "TABLE"]) && contains_sequence(&words, &["SWAP", "WITH"]) {
        return Some(RankedMatch::new("alter-table-swap", Severity::High, span));
    }
    if starts(&words, &["INSERT", "OVERWRITE"]) {
        return Some(RankedMatch::new("insert-overwrite", Severity::High, span));
    }
    if starts(&words, &["COPY", "INTO"])
        && copy_targets_location(statement)
        && contains_sequence(&words, &["OVERWRITE", "TRUE"])
    {
        return Some(RankedMatch::new("copy-overwrite", Severity::High, span));
    }
    if words.first() == Some(&"PUT") && contains_sequence(&words, &["OVERWRITE", "TRUE"]) {
        return Some(RankedMatch::new("put-overwrite", Severity::High, span));
    }
    if replaced_object.is_some_and(|object| {
        starts_any(
            object,
            &[
                &["PIPE"],
                &["STREAM"],
                &["TASK"],
                &["STAGE"],
                &["INTEGRATION"],
                &["API", "INTEGRATION"],
                &["SECURITY", "INTEGRATION"],
                &["STORAGE", "INTEGRATION"],
                &["NOTIFICATION", "INTEGRATION"],
                &["EXTERNAL", "ACCESS", "INTEGRATION"],
                &["CATALOG", "INTEGRATION"],
                &["SHARE"],
                &["PROCEDURE"],
                &["FUNCTION"],
                &["EXTERNAL", "FUNCTION"],
                &["VIEW"],
                &["MATERIALIZED", "VIEW"],
                &["DYNAMIC", "TABLE"],
            ],
        )
    }) {
        return Some(RankedMatch::new(
            "replace-live-object",
            Severity::High,
            span,
        ));
    }
    if words.first() == Some(&"MERGE") {
        return Some(RankedMatch::new("merge-data", Severity::Medium, span));
    }
    if starts(&words, &["COPY", "INTO"]) && !copy_targets_location(statement) {
        return Some(RankedMatch::new("copy-into-table", Severity::Medium, span));
    }
    if (starts(&words, &["ALTER", "DATABASE"])
        || starts(&words, &["ALTER", "SCHEMA"])
        || starts(&words, &["ALTER", "TABLE"]))
        && contains_sequence(&words, &["RENAME", "TO"])
    {
        return Some(RankedMatch::new("rename-object", Severity::Medium, span));
    }
    if starts(&words, &["ALTER", "TABLE"])
        && (contains_sequence(&words, &["ALTER", "COLUMN"])
            || contains_sequence(&words, &["MODIFY", "COLUMN"]))
    {
        return Some(RankedMatch::new("alter-column", Severity::Medium, span));
    }
    if starts(&words, &["ALTER", "WAREHOUSE"]) && words.contains(&"SET") {
        return Some(RankedMatch::new(
            "warehouse-settings",
            Severity::Medium,
            span,
        ));
    }
    if starts(&words, &["EXECUTE", "IMMEDIATE"]) {
        return Some(RankedMatch::new(
            "execute-immediate",
            Severity::Medium,
            span,
        ));
    }
    if words.first() == Some(&"DECLARE") || (words.first() == Some(&"BEGIN") && words.len() > 1) {
        return Some(RankedMatch::new(UNVERIFIED_RULE, Severity::High, span));
    }
    None
}

fn starts(words: &[&str], prefix: &[&str]) -> bool {
    words.starts_with(prefix)
}

fn starts_any(words: &[&str], prefixes: &[&[&str]]) -> bool {
    prefixes.iter().any(|prefix| starts(words, prefix))
}

fn contains_sequence(words: &[&str], needle: &[&str]) -> bool {
    words.windows(needle.len()).any(|window| window == needle)
}

fn replaced_object_words<'a>(words: &'a [&str]) -> Option<&'a [&'a str]> {
    let mut object = words.strip_prefix(&["CREATE", "OR", "REPLACE"])?;
    while object
        .first()
        .is_some_and(|word| matches!(*word, "SECURE" | "TEMP" | "TEMPORARY" | "TRANSIENT"))
    {
        object = &object[1..];
    }
    Some(object)
}

fn copy_targets_location(statement: &SqlStatement) -> bool {
    let Some(into_index) = statement.tokens.iter().position(|token| {
        token.depth == 0 && matches!(&token.kind, TokenKind::Word(word) if word == "INTO")
    }) else {
        return false;
    };
    statement.tokens[into_index + 1..]
        .iter()
        .find(|token| token.depth == 0)
        .is_some_and(|token| {
            matches!(
                token.kind,
                TokenKind::Symbol(b'@') | TokenKind::StringLiteral
            )
        })
}

/// A nested input referenced by `!source` or its `!load` alias.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnowflakeSource {
    /// Local file that the evaluator must inspect recursively.
    Local(PathBuf),
    /// URL source that cannot be inspected as a stable local file.
    Remote(String),
}

/// Extract bounded `!source` / `!load` references outside comments and strings.
pub fn source_references(payload: &str) -> Result<Vec<SnowflakeSource>, SnowflakeSqlError> {
    let directives = scan_directives(payload)?;
    let mut references = Vec::new();
    for directive in directives {
        if directive.kind != DirectiveKind::Source {
            continue;
        }
        let Some(operand) = directive.operand else {
            return Err(sql_error(
                "Snowflake !source/!load directive has no static operand",
            ));
        };
        if contains_template_code(&operand, false) || operand.contains(['$', '`']) {
            return Err(sql_error(
                "Snowflake !source/!load directive uses a dynamic path",
            ));
        }
        let lowercase_operand = operand.to_ascii_lowercase();
        if lowercase_operand.starts_with("http://") || lowercase_operand.starts_with("https://") {
            references.push(SnowflakeSource::Remote(operand));
        } else {
            references.push(SnowflakeSource::Local(PathBuf::from(operand)));
        }
        if references.len() > MAX_SNOWFLAKE_INCLUDES {
            return Err(sql_error(format!(
                "Snowflake SQL contains more than {MAX_SNOWFLAKE_INCLUDES} source directives"
            )));
        }
    }
    Ok(references)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectiveKind {
    Source,
    Abort,
    Edit,
    /// SnowSQL's `!system <command>`: a shell escape, not SQL.
    System,
}

#[derive(Debug, Clone)]
struct Directive {
    kind: DirectiveKind,
    operand: Option<String>,
    span: std::ops::Range<usize>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum DirectiveLexState {
    #[default]
    Normal,
    SingleQuoted,
    DoubleQuoted,
    DollarQuoted,
    BlockComment(usize),
}

fn scan_directives(payload: &str) -> Result<Vec<Directive>, SnowflakeSqlError> {
    let mut directives = Vec::new();
    let mut offset = 0usize;
    let mut state = DirectiveLexState::Normal;
    for line in payload.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        let trimmed = body.trim_start();
        let leading = body.len() - trimmed.len();
        let directive = if state == DirectiveLexState::Normal {
            let lower = trimmed.to_ascii_lowercase();
            if directive_boundary(&lower, "!source") {
                Some((DirectiveKind::Source, "!source".len()))
            } else if directive_boundary(&lower, "!load") {
                Some((DirectiveKind::Source, "!load".len()))
            } else if directive_boundary(&lower, "!abort") {
                Some((DirectiveKind::Abort, "!abort".len()))
            } else if directive_boundary(&lower, "!edit") {
                Some((DirectiveKind::Edit, "!edit".len()))
            } else if directive_boundary(&lower, "!system") {
                Some((DirectiveKind::System, "!system".len()))
            } else {
                None
            }
        } else {
            None
        };
        let Some((kind, command_len)) = directive else {
            advance_directive_state(body, &mut state)?;
            offset += line.len();
            continue;
        };

        let remainder = strip_directive_comment(&trimmed[command_len..]);
        // `!edit` takes no path, and `!system`'s operand is shell text whose
        // quoting is not ours to parse.
        let operand = if matches!(kind, DirectiveKind::Edit | DirectiveKind::System) {
            None
        } else {
            let words = shell_words::split(remainder.trim().trim_end_matches(';'))
                .map_err(|_| sql_error("Snowflake CLI directive contains ambiguous quoting"))?;
            if words.len() > 1 && kind == DirectiveKind::Source {
                return Err(sql_error(
                    "Snowflake !source/!load directive has more than one path operand",
                ));
            }
            words.into_iter().next()
        };
        directives.push(Directive {
            kind,
            operand,
            span: offset + leading..offset + body.len(),
        });
        offset += line.len();
    }
    if state != DirectiveLexState::Normal {
        return Err(sql_error(
            "Snowflake SQL ends inside a comment, quoted identifier, or string literal",
        ));
    }
    Ok(directives)
}

fn advance_directive_state(
    line: &str,
    state: &mut DirectiveLexState,
) -> Result<(), SnowflakeSqlError> {
    let bytes = line.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        match *state {
            DirectiveLexState::Normal => match bytes[index] {
                b'-' if bytes.get(index + 1) == Some(&b'-') => return Ok(()),
                b'/' if bytes.get(index + 1) == Some(&b'*') => {
                    *state = DirectiveLexState::BlockComment(1);
                    index += 2;
                }
                b'\'' => {
                    *state = DirectiveLexState::SingleQuoted;
                    index += 1;
                }
                b'"' => {
                    *state = DirectiveLexState::DoubleQuoted;
                    index += 1;
                }
                b'$' if bytes.get(index + 1) == Some(&b'$') => {
                    *state = DirectiveLexState::DollarQuoted;
                    index += 2;
                }
                _ => index += line[index..].chars().next().map_or(1, char::len_utf8),
            },
            DirectiveLexState::SingleQuoted => {
                if bytes[index] == b'\\' {
                    if index + 1 >= bytes.len() {
                        return Err(sql_error(
                            "Snowflake string ends with an incomplete backslash escape",
                        ));
                    }
                    index += 2;
                } else if bytes[index] == b'\'' {
                    if bytes.get(index + 1) == Some(&b'\'') {
                        index += 2;
                    } else {
                        *state = DirectiveLexState::Normal;
                        index += 1;
                    }
                } else {
                    index += line[index..].chars().next().map_or(1, char::len_utf8);
                }
            }
            DirectiveLexState::DoubleQuoted => {
                if bytes[index] == b'"' {
                    if bytes.get(index + 1) == Some(&b'"') {
                        index += 2;
                    } else {
                        *state = DirectiveLexState::Normal;
                        index += 1;
                    }
                } else {
                    index += line[index..].chars().next().map_or(1, char::len_utf8);
                }
            }
            DirectiveLexState::DollarQuoted => {
                if bytes[index] == b'$' && bytes.get(index + 1) == Some(&b'$') {
                    *state = DirectiveLexState::Normal;
                    index += 2;
                } else {
                    index += line[index..].chars().next().map_or(1, char::len_utf8);
                }
            }
            DirectiveLexState::BlockComment(depth) => {
                if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
                    *state = DirectiveLexState::BlockComment(depth + 1);
                    index += 2;
                } else if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                    *state = if depth == 1 {
                        DirectiveLexState::Normal
                    } else {
                        DirectiveLexState::BlockComment(depth - 1)
                    };
                    index += 2;
                } else {
                    index += line[index..].chars().next().map_or(1, char::len_utf8);
                }
            }
        }
    }
    Ok(())
}

fn directive_boundary(line: &str, command: &str) -> bool {
    line.strip_prefix(command).is_some_and(|tail| {
        tail.is_empty()
            || tail
                .chars()
                .next()
                .is_some_and(|ch| ch.is_whitespace() || ch == ';')
    })
}

fn strip_directive_comment(input: &str) -> &str {
    let bytes = input.as_bytes();
    let mut index = 0usize;
    let mut quote = None;
    while index < bytes.len() {
        if let Some(active) = quote {
            if bytes[index] == b'\\' {
                index = index.saturating_add(2);
                continue;
            }
            if bytes[index] == active {
                quote = None;
            }
            index += 1;
            continue;
        }
        if matches!(bytes[index], b'\'' | b'"') {
            quote = Some(bytes[index]);
            index += 1;
            continue;
        }
        if bytes[index] == b'-' && bytes.get(index + 1) == Some(&b'-') {
            return &input[..index];
        }
        index += 1;
    }
    input
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::{
        assert_blocks_with_pattern, assert_blocks_with_severity, assert_no_match,
    };

    #[test]
    fn cli_surface_drops_are_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "snow object drop database prod_db",
            "cli-object-drop-database",
        );
        assert_blocks_with_pattern(
            &pack,
            "snow object drop schema prod_db.public",
            "cli-object-drop-database",
        );
        assert_blocks_with_pattern(&pack, "snow object drop table t --force", "cli-object-drop");
        assert_blocks_with_pattern(&pack, "snow stage drop my_stage", "cli-stage-drop");
        assert_blocks_with_pattern(
            &pack,
            "snow stage remove my_stage /data/file.csv",
            "cli-stage-remove",
        );
        assert_blocks_with_pattern(&pack, "snow app teardown --cascade", "cli-app-teardown");
        assert_blocks_with_pattern(&pack, "snow app version drop v1_0", "cli-app-version-drop");
        assert_blocks_with_pattern(
            &pack,
            "snow snowpark drop procedure 'hello(int)'",
            "cli-snowpark-drop",
        );
        assert_blocks_with_pattern(&pack, "snow dbt drop analytics_project", "cli-dbt-drop");
        assert_blocks_with_pattern(&pack, "snow dcm drop my_dcm_project", "cli-dcm-drop");
        assert_blocks_with_pattern(&pack, "snow spcs service drop my_service", "cli-spcs-drop");
        assert_blocks_with_pattern(
            &pack,
            "snow spcs compute-pool drop my_pool",
            "cli-spcs-drop",
        );
        // Global flags (with values) between `snow` and the subcommand path.
        assert_blocks_with_pattern(
            &pack,
            "snow --connection prod object drop database prod_db",
            "cli-object-drop-database",
        );
    }

    #[test]
    fn cli_surface_drop_severities() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "snow object drop database prod", Severity::Critical);
        assert_blocks_with_severity(&pack, "snow object drop table t", Severity::High);
        assert_blocks_with_severity(&pack, "snow app version drop v1", Severity::Medium);
    }

    #[test]
    fn cli_surface_read_only_commands_do_not_match() {
        let pack = create_pack();
        assert_no_match(&pack, "snow object list table");
        assert_no_match(&pack, "snow object describe table users");
        assert_no_match(&pack, "snow stage list-files my_stage");
        assert_no_match(&pack, "snow stage copy @src ./local");
        assert_no_match(&pack, "snow app run");
        assert_no_match(&pack, "snow connection test");
        assert_no_match(&pack, "snow dbt list");
        assert_no_match(&pack, "snow dcm list");
        // `snow ... drop` text inside inert data must not match: the prefix
        // requires `snow` in command position and refuses to cross shell
        // separators.
        assert_no_match(&pack, "echo let it snow");
    }

    fn assert_match(sql: &str, expected: &str) {
        match scan_sql(sql) {
            SnowflakeSqlScan::Match(found) => assert_eq!(found.pattern_name, expected, "{sql}"),
            result => panic!("expected {expected} for {sql:?}, got {result:?}"),
        }
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn candidate_override_is_dialect_aware_and_command_position_only() {
        let cases = [
            (
                ShellDialect::PowerShell,
                "& ('s'+'now') sql -q 'MERGE INTO prod.t USING stage.s ON 1=1'",
                "MERGE INTO prod.t USING stage.s ON 1=1",
            ),
            (
                ShellDialect::Cmd,
                r#"s^now sql -q "COPY INTO prod.t FROM @stage""#,
                "COPY INTO prod.t FROM @stage",
            ),
            (
                ShellDialect::Posix,
                r"$'\x73\x6e\x6f\x77' sql -q 'MERGE INTO prod.t USING stage.s ON 1=1'",
                "MERGE INTO prod.t USING stage.s ON 1=1",
            ),
        ];
        for (dialect, command, expected_query) in cases {
            assert!(
                snowflake_semantic_scan_required(command, dialect),
                "{command}"
            );
            let args = snow_cli_args_in_dialect(command, dialect);
            let analysis = analyze_snow_sql_args(&args[0]);
            assert_eq!(analysis.query_values, [expected_query], "{command}");
        }

        for (dialect, command) in [
            (
                ShellDialect::PowerShell,
                "Write-Output \"& ('s'+'now') sql -q 'MERGE INTO prod.t USING stage.s ON 1=1'\"",
            ),
            (
                ShellDialect::PowerShell,
                "'snow' sql -q 'MERGE INTO prod.t USING stage.s ON 1=1'",
            ),
            (
                ShellDialect::Cmd,
                r#"echo s^now sql -q "COPY INTO prod.t FROM @stage""#,
            ),
            (
                ShellDialect::Posix,
                r#"printf '%s\n' "$'\x73\x6e\x6f\x77' sql -q COPY""#,
            ),
        ] {
            assert!(
                !snowflake_semantic_scan_required(command, dialect),
                "inert data must not force the pack: {command}"
            );
        }

        let dynamic_target = "& ([string]::Concat([char]115,[char]110,[char]111,[char]119)) sql -q 'DROP DATABASE analytics_prod'";
        for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
            assert!(
                snowflake_semantic_scan_required(dynamic_target, dialect),
                "a runtime-dependent PowerShell target with snow sql argv must force the pack"
            );
            assert!(dynamic_snowflake_executable_unverified(
                dynamic_target,
                dialect
            ));
        }
        let literal_posix_target = "$(printf snow) sql -q 'DROP DATABASE analytics_prod'";
        assert!(snowflake_semantic_scan_required(
            literal_posix_target,
            ShellDialect::Posix,
        ));
        let args = snow_cli_args_in_dialect(literal_posix_target, ShellDialect::Posix);
        assert_eq!(args.len(), 1);
        assert_eq!(
            analyze_snow_sql_args(&args[0]).query_values,
            ["DROP DATABASE analytics_prod"],
        );
        for command in [
            "& ('python') sql -q 'DROP DATABASE analytics_prod'",
            "Write-Output \"& ([string]::Concat([char]115,[char]110,[char]111,[char]119)) sql -q 'DROP DATABASE analytics_prod'\"",
        ] {
            assert!(
                !snowflake_semantic_scan_required(command, ShellDialect::PowerShell),
                "static non-snow targets and inert data must not force the pack: {command}"
            );
            assert!(!dynamic_snowflake_executable_unverified(
                command,
                ShellDialect::PowerShell,
            ));
        }
    }

    #[test]
    fn oversized_cli_input_requires_fail_closed_semantic_evaluation() {
        let command = "x".repeat(MAX_SNOWFLAKE_CLI_BYTES + 1);
        assert!(snowflake_cli_exceeds_analysis_budget(&command));
        for dialect in [
            ShellDialect::Posix,
            ShellDialect::PowerShell,
            ShellDialect::Cmd,
            ShellDialect::Unknown,
        ] {
            assert!(
                snowflake_semantic_scan_required(&command, dialect),
                "an oversized command must select the Snowflake pack for {dialect:?}"
            );
        }
    }

    fn assert_report(sql: &str) -> SnowflakeSqlReport {
        match scan_sql_report(sql) {
            SnowflakeSqlReportScan::Match(report) => report,
            result => panic!("expected complete findings for {sql:?}, got {result:?}"),
        }
    }

    #[test]
    fn cli_analysis_covers_query_file_stdin_and_current_options() {
        let args = strings(&[
            "--connection",
            "prod",
            "sql",
            "--query=SELECT 1",
            "-f",
            "migrations/2026 07 cleanup.sql",
            "-fmore.sql",
            "--local-only",
            "--retain-comments",
            "--format",
            "JSON_EXT",
        ]);
        let analysis = analyze_snow_sql_args(&args);
        assert_eq!(analysis.query_values, ["SELECT 1"]);
        assert_eq!(
            analysis.file_values,
            ["migrations/2026 07 cleanup.sql", "more.sql"]
        );
        assert!(analysis.local_only);
        assert!(analysis.retain_comments);
        assert!(!analysis.reads_stdin_as_code);
        assert_eq!(analysis.unverified_reason, None);

        let stdin_args = strings(&["sql", "-i"]);
        let stdin = analyze_snow_sql_args(&stdin_args);
        assert!(stdin.reads_stdin_as_code);
        let repl_args = strings(&["sql"]);
        let repl = analyze_snow_sql_args(&repl_args);
        assert!(repl.reads_stdin_as_code);
        let non_sql_args = strings(&["connection", "list"]);
        let non_sql = analyze_snow_sql_args(&non_sql_args);
        assert!(!non_sql.is_sql_command());
        let sql_connection_name = strings(&["--connection", "sql", "connection", "list"]);
        assert!(!analyze_snow_sql_args(&sql_connection_name).is_sql_command());

        let stdin_file = strings(&["sql", "--filename", "/dev/stdin"]);
        let stdin_file = analyze_snow_sql_args(&stdin_file);
        assert!(stdin_file.file_values.is_empty());
        assert!(stdin_file.reads_stdin_as_code);
    }

    #[test]
    fn cli_analysis_fails_closed_on_ambiguous_argv() {
        for args in [
            strings(&["sql", "--future-option", "-q", "DROP TABLE prod.t"]),
            strings(&["--future-global", "value", "sql", "-q", "DROP TABLE prod.t"]),
            strings(&["sql", "--query"]),
            strings(&["sql", "unexpected.sql"]),
        ] {
            assert!(analyze_snow_sql_args(&args).unverified_reason.is_some());
        }
        let disabled_args = strings(&[
            "sql",
            "--enable-templating=NONE",
            "-q",
            "SELECT '<% inert %>'",
        ]);
        let disabled = analyze_snow_sql_args(&disabled_args);
        assert_eq!(disabled.templating, SnowflakeTemplating::Disabled);
    }

    #[test]
    fn critical_ddl_and_unbounded_dml_are_statement_local() {
        for (sql, rule) in [
            ("DROP DATABASE analytics_prod", "drop-database"),
            ("drop schema if exists prod cascade", "drop-schema"),
            ("DROP TABLE prod.customers", "drop-table"),
            ("CREATE OR REPLACE\nDATABASE prod", "replace-database"),
            ("CREATE OR REPLACE SCHEMA prod", "replace-schema"),
            (
                "CREATE OR REPLACE\nTABLE prod.t AS SELECT 1",
                "replace-table",
            ),
            (
                "CREATE OR REPLACE TRANSIENT TABLE prod.t AS SELECT 1",
                "replace-table",
            ),
            ("TRUNCATE TABLE prod.events", "truncate-table"),
            ("DELETE FROM prod.orders", "delete-all"),
            ("UPDATE prod.orders SET status = 'lost'", "update-all"),
        ] {
            assert_match(sql, rule);
        }
        assert_match(
            "SELECT COUNT(*) FROM prod.users; DROP TABLE prod.users",
            "drop-table",
        );
    }

    #[test]
    fn complete_report_retains_all_findings_spans_and_primary_contract() {
        let sql = "SELECT 1;\nUPDATE prod.orders SET status = 'held' WHERE id = 7;\n\
                   -- DROP DATABASE quoted_only\nSELECT 'TRUNCATE TABLE inert';\n\
                   DROP TABLE prod.retired;\nDELETE FROM prod.audit;";
        let report = assert_report(sql);
        assert_eq!(report.primary.pattern_name, "drop-table");
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.pattern_name)
                .collect::<Vec<_>>(),
            ["bounded-update", "drop-table", "delete-all"]
        );
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| sql[finding.statement_span.clone()].trim())
                .collect::<Vec<_>>(),
            [
                "UPDATE prod.orders SET status = 'held' WHERE id = 7;",
                "DROP TABLE prod.retired;",
                "DELETE FROM prod.audit;",
            ]
        );
        assert_eq!(
            scan_sql(sql),
            SnowflakeSqlScan::Match(report.primary.clone())
        );
    }

    #[test]
    fn complete_report_orders_directives_and_statements_by_source_position() {
        let sql = "  !abort 01abc\nSELECT 1;\nDROP SCHEMA prod.old;\n!edit";
        let expected = assert_report(sql);
        assert_eq!(
            expected
                .findings
                .iter()
                .map(|finding| finding.pattern_name)
                .collect::<Vec<_>>(),
            ["abort-query", "drop-schema", "interactive-edit"]
        );
        assert_eq!(
            expected
                .findings
                .iter()
                .map(|finding| finding.statement_span.start)
                .collect::<Vec<_>>(),
            [2, 24, 47]
        );
        for _ in 0..16 {
            assert_eq!(
                scan_sql_report(sql),
                SnowflakeSqlReportScan::Match(expected.clone())
            );
        }
    }

    #[test]
    fn complete_report_ignores_guard_words_in_comments_and_strings() {
        let sql = "-- DROP DATABASE prod\nSELECT 'DELETE FROM prod.t';\n\
                   /* TRUNCATE TABLE prod.t; */\n\
                   UPDATE prod.t SET reviewed = TRUE WHERE id = 1;\n\
                   SELECT 'ALTER TASK hourly SUSPEND';";
        let report = assert_report(sql);
        assert_eq!(report.primary.pattern_name, "bounded-update");
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].pattern_name, "bounded-update");
        assert_eq!(
            sql[report.findings[0].statement_span.clone()].trim(),
            "/* TRUNCATE TABLE prod.t; */\nUPDATE prod.t SET reviewed = TRUE WHERE id = 1;"
        );
    }

    #[test]
    fn complete_report_fails_closed_instead_of_truncating_findings() {
        let at_limit = "!abort query-id\n".repeat(MAX_SNOWFLAKE_FINDINGS);
        let report = assert_report(&at_limit);
        assert_eq!(report.findings.len(), MAX_SNOWFLAKE_FINDINGS);

        let over_limit = "!abort query-id\n".repeat(MAX_SNOWFLAKE_FINDINGS + 1);
        let SnowflakeSqlReportScan::Unverified(error) = scan_sql_report(&over_limit) else {
            panic!("over-limit report must fail closed");
        };
        assert!(
            error.reason.contains("guarded findings"),
            "{}",
            error.reason
        );

        let too_many_statements = "DELETE FROM prod.t;".repeat(MAX_SNOWFLAKE_STATEMENTS + 1);
        assert!(matches!(
            scan_sql_report(&too_many_statements),
            SnowflakeSqlReportScan::Unverified(_)
        ));
    }

    #[test]
    fn comments_strings_identifiers_and_dollar_bodies_are_inert() {
        for sql in [
            "-- DROP DATABASE prod\nSELECT 1",
            "/* TRUNCATE TABLE prod.t; */ SHOW TABLES",
            "/* outer /* nested */ DROP TABLE still_a_comment */ SELECT 1",
            "-- {{ ignored_template }}\nSELECT 1",
            "SELECT 'DROP TABLE prod.t', 'DELETE FROM prod.t'",
            "SELECT \"DROP\" FROM \"TRUNCATE TABLE\"",
            "CREATE PROCEDURE p() RETURNS STRING LANGUAGE SQL AS $$ BEGIN DROP TABLE x; END; $$",
        ] {
            assert_eq!(scan_sql(sql), SnowflakeSqlScan::Safe, "{sql}");
        }
    }

    #[test]
    fn executable_anonymous_procedures_fail_closed() {
        for sql in [
            "WITH cleanup AS PROCEDURE() RETURNS STRING LANGUAGE SQL AS $$ BEGIN DROP TABLE prod.t; RETURN 'done'; END; $$ CALL cleanup()",
            "WITH cleanup AS PROCEDURE() RETURNS STRING LANGUAGE JAVASCRIPT AS 'snowflake.execute({sqlText: `DELETE FROM prod.t`}); return `done`;' CALL cleanup()",
            "WITH cleanup AS PROCEDURE() RETURNS STRING LANGUAGE PYTHON RUNTIME_VERSION = '3.10' HANDLER = 'run' AS $$def run(session):\n    session.sql('TRUNCATE TABLE prod.t').collect()\n    return 'done'$$ CALL cleanup()",
        ] {
            assert_match(sql, UNVERIFIED_RULE);
        }

        assert_eq!(
            scan_sql("WITH values_cte AS (SELECT 1 AS value) SELECT value FROM values_cte"),
            SnowflakeSqlScan::Safe
        );
    }

    #[test]
    fn read_only_and_reversible_lifecycle_sql_remains_safe() {
        for sql in [
            "SELECT * FROM prod.events",
            "SHOW TABLES IN SCHEMA prod.public",
            "DESCRIBE TABLE prod.public.events",
            "EXPLAIN SELECT 1",
            "CREATE TABLE scratch.events CLONE prod.events",
            "UNDROP TABLE prod.events",
            "ALTER TASK hourly RESUME",
            "ALTER WAREHOUSE app_wh RESUME",
            "ALTER PIPE ingest SET PIPE_EXECUTION_PAUSED = FALSE",
        ] {
            assert_eq!(scan_sql(sql), SnowflakeSqlScan::Safe, "{sql}");
        }
    }

    #[test]
    fn ingestion_compute_and_access_hazards_are_detected() {
        for (sql, rule) in [
            ("REMOVE @raw/archive/", "remove-stage-files"),
            (
                "ALTER PIPE ingest SET PIPE_EXECUTION_PAUSED = TRUE",
                "pause-pipe",
            ),
            ("ALTER TASK hourly SUSPEND", "suspend-task"),
            ("EXECUTE TASK hourly", "execute-task"),
            ("ALTER WAREHOUSE app_wh SUSPEND", "suspend-warehouse"),
            ("GRANT ALL PRIVILEGES ON ACCOUNT TO ROLE ops", "broad-grant"),
            ("GRANT ROLE ACCOUNTADMIN TO USER service", "broad-grant"),
            (
                "GRANT OWNERSHIP ON TABLE prod.t TO ROLE app COPY CURRENT GRANTS",
                "transfer-ownership",
            ),
            ("REVOKE ROLE app FROM USER service", "broad-revoke"),
            ("DROP STREAM orders_stream", "drop-ingestion-object"),
            ("DROP USER service", "drop-principal"),
            ("DROP DATABASE ROLE app.reader", "drop-principal"),
        ] {
            assert_match(sql, rule);
        }
    }

    #[test]
    fn task_bodies_are_scanned_before_scheduling_or_execution() {
        for (sql, rule) in [
            (
                "CREATE TASK wipe WAREHOUSE=app_wh AS DELETE FROM prod.orders",
                "delete-all",
            ),
            (
                "CREATE TASK bounded WAREHOUSE=app_wh AS DELETE FROM prod.orders WHERE id = 1",
                "bounded-delete",
            ),
            (
                "CREATE TASK opaque WAREHOUSE=app_wh AS CALL cleanup_orders()",
                UNVERIFIED_RULE,
            ),
            (
                "CREATE TASK wipe WAREHOUSE=app_wh AS DELETE FROM prod.orders; ALTER TASK wipe RESUME",
                "delete-all",
            ),
        ] {
            assert_match(sql, rule);
        }

        assert_eq!(
            scan_sql("CREATE TASK read_only WAREHOUSE=app_wh AS SELECT COUNT(*) FROM prod.orders"),
            SnowflakeSqlScan::Safe
        );
        assert_match(
            "CREATE OR REPLACE TASK read_only WAREHOUSE=app_wh AS SELECT 1",
            "replace-live-object",
        );
    }

    #[test]
    fn overwrite_and_structural_mutations_are_detected() {
        for (sql, rule) in [
            (
                "ALTER TABLE prod.t DROP COLUMN secret",
                "alter-table-drop-column",
            ),
            ("ALTER TABLE prod.t SWAP WITH scratch.t", "alter-table-swap"),
            (
                "INSERT OVERWRITE INTO prod.t SELECT * FROM staging.t",
                "insert-overwrite",
            ),
            (
                "COPY INTO @exports/run FROM prod.t OVERWRITE = TRUE",
                "copy-overwrite",
            ),
            (
                "COPY INTO 's3://exports/run/' FROM prod.t OVERWRITE = TRUE",
                "copy-overwrite",
            ),
            (
                "PUT file:///tmp/data @stage OVERWRITE = TRUE",
                "put-overwrite",
            ),
            (
                "CREATE OR REPLACE TASK hourly AS SELECT 1",
                "replace-live-object",
            ),
        ] {
            assert_match(sql, rule);
        }
    }

    #[test]
    fn bounded_mutations_do_not_become_unbounded_from_nested_where() {
        assert_match(
            "DELETE FROM prod.t WHERE id IN (SELECT id FROM keepers)",
            "bounded-delete",
        );
        assert_match(
            "UPDATE prod.t SET x = (SELECT max(x) FROM source WHERE ready) WHERE id = 1",
            "bounded-update",
        );
        assert_match("MERGE INTO prod.t USING staging.s ON 1=1", "merge-data");
        assert_match("COPY INTO prod.t FROM @stage", "copy-into-table");
    }

    #[test]
    fn templating_and_malformed_or_oversized_payloads_fail_closed() {
        for sql in [
            "SELECT * FROM <% database %>.events",
            "{{ executable_sql }}",
            "SELECT &legacy_variable",
            "SELECT 'unterminated",
            "SELECT 1 /* unterminated",
        ] {
            assert!(
                matches!(scan_sql(sql), SnowflakeSqlScan::Unverified(_)),
                "{sql}"
            );
        }
        assert_eq!(
            scan_sql_with_templating(
                "SELECT '<% inert when disabled %>'",
                SnowflakeTemplating::Disabled,
            ),
            SnowflakeSqlScan::Safe
        );
        assert!(matches!(
            scan_sql_with_options(
                "-- {{ rendered_value }}\nSELECT 1",
                SnowflakeTemplating::Enabled,
                true,
            ),
            SnowflakeSqlScan::Unverified(_)
        ));
        let oversized = " ".repeat(MAX_SNOWFLAKE_SQL_BYTES + 1);
        assert!(matches!(
            scan_sql(&oversized),
            SnowflakeSqlScan::Unverified(_)
        ));
    }

    #[test]
    fn source_directives_are_bounded_and_distinguish_local_remote_dynamic() {
        let refs = source_references(
            "!source migrations/001.sql\n!load 'migrations/2026 07.sql' -- reviewed\n!source https://example.test/prod.sql",
        )
        .expect("static source directives");
        assert_eq!(
            refs,
            [
                SnowflakeSource::Local(PathBuf::from("migrations/001.sql")),
                SnowflakeSource::Local(PathBuf::from("migrations/2026 07.sql")),
                SnowflakeSource::Remote("https://example.test/prod.sql".to_string()),
            ]
        );
        assert!(source_references("!source <% path %>").is_err());
        assert!(
            source_references(
                "SELECT $$\n!source ignored.sql\n$$;\n/*\n!load ignored-too.sql\n*/\n!source real.sql"
            )
            .is_ok_and(|refs| refs == [SnowflakeSource::Local(PathBuf::from("real.sql"))])
        );
        assert_match("!abort 01abc", "abort-query");
        assert_match("!edit", "interactive-edit");
        assert_match("EXECUTE IMMEDIATE $$SELECT 1$$", "execute-immediate");
        assert_match("DECLARE result RESULTSET", UNVERIFIED_RULE);
    }

    #[test]
    fn semantic_rule_names_have_pack_metadata() {
        let pack = create_pack();
        let cases = [
            "DROP DATABASE prod",
            "DELETE FROM prod.t WHERE id = 1",
            "ALTER TASK hourly SUSPEND",
            "GRANT OWNERSHIP ON TABLE t TO ROLE r",
            "!edit",
        ];
        for sql in cases {
            let SnowflakeSqlScan::Match(found) = scan_sql(sql) else {
                panic!("expected semantic match for {sql}");
            };
            assert!(
                pack.destructive_patterns
                    .iter()
                    .any(|pattern| pattern.name == Some(found.pattern_name)),
                "semantic rule {} is missing metadata",
                found.pattern_name
            );
        }
        assert!(
            pack.destructive_patterns
                .iter()
                .any(|pattern| pattern.name == Some(UNVERIFIED_RULE))
        );
        for pattern in &pack.destructive_patterns {
            assert!(
                !pattern.regex.is_match("snow sql -q 'DROP DATABASE prod'"),
                "raw metadata regex {} must not bypass the bounded semantic scanner",
                pattern.name.unwrap_or("unnamed")
            );
            assert!(
                pattern.regex.is_compiled(),
                "metadata regex {} must compile",
                pattern.name.unwrap_or("unnamed")
            );
        }
    }
}
