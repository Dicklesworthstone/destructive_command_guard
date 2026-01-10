//! CLI argument parsing and command handling.
//!
//! This module provides the command-line interface for dcg (`destructive_command_guard`),
//! including subcommands for configuration management and pack information.

use clap::{Args, Parser, Subcommand};

use crate::config::Config;
use crate::evaluator::{EvaluationDecision, MatchSource, evaluate_command_with_pack_order};
use crate::load_default_allowlists;
use crate::packs::REGISTRY;

/// High-performance Claude Code hook for blocking destructive commands.
///
/// dcg (`destructive_command_guard`) protects against accidental execution of
/// destructive commands by AI coding agents. It blocks dangerous git commands,
/// filesystem operations, database queries, and more.
#[derive(Parser, Debug)]
#[command(name = "dcg")]
#[command(version, about, long_about = None)]
#[command(after_help = "Run 'dcg doctor' to verify your installation.")]
pub struct Cli {
    /// Subcommand to run (omit to run in hook mode)
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Available subcommands
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Check installation, configuration, and hook registration
    #[command(name = "doctor")]
    Doctor {
        /// Attempt to fix any issues found
        #[arg(long)]
        fix: bool,

        /// Output format (pretty or json)
        #[arg(long, short, value_enum, default_value_t = DoctorFormat::Pretty)]
        format: DoctorFormat,
    },

    /// Manage allowlist entries (add, list, remove, validate)
    #[command(name = "allowlist")]
    Allowlist {
        #[command(subcommand)]
        action: AllowlistAction,
    },

    /// Add a rule to the allowlist (shortcut for `allowlist add`)
    #[command(name = "allow")]
    Allow {
        /// Rule ID to allowlist (e.g., "core.git:reset-hard")
        rule_id: String,

        /// Reason for allowlisting (required)
        #[arg(long, short = 'r')]
        reason: String,

        /// Add to project allowlist (default if in git repo)
        #[arg(long, conflicts_with = "user")]
        project: bool,

        /// Add to user allowlist
        #[arg(long, conflicts_with = "project")]
        user: bool,

        /// Expiration date (ISO 8601 / RFC 3339)
        #[arg(long)]
        expires: Option<String>,
    },

    /// Remove a rule from the allowlist (shortcut for `allowlist remove`)
    #[command(name = "unallow")]
    Unallow {
        /// Rule ID to remove (e.g., "core.git:reset-hard")
        rule_id: String,

        /// Remove from project allowlist (default if in git repo)
        #[arg(long, conflicts_with = "user")]
        project: bool,

        /// Remove from user allowlist
        #[arg(long, conflicts_with = "project")]
        user: bool,
    },

    /// Install the hook into Claude Code settings
    #[command(name = "install")]
    Install {
        /// Force overwrite existing hook configuration
        #[arg(long)]
        force: bool,
    },

    /// Remove the hook from Claude Code settings
    #[command(name = "uninstall")]
    Uninstall {
        /// Also remove configuration files
        #[arg(long)]
        purge: bool,
    },

    /// Update dcg to the latest release (re-runs the installer)
    #[command(name = "update")]
    Update(UpdateCommand),

    /// List all available packs and their status
    #[command(name = "packs")]
    ListPacks {
        /// Show only enabled packs
        #[arg(long)]
        enabled: bool,

        /// Show detailed information including pattern counts
        #[arg(short, long)]
        verbose: bool,
    },

    /// Show information about a specific pack
    #[command(name = "pack")]
    PackInfo {
        /// Pack ID (e.g., "database.postgresql", "core.git")
        pack_id: String,

        /// Show all patterns in the pack
        #[arg(long)]
        patterns: bool,
    },

    /// Test a command against enabled packs
    #[command(name = "test")]
    TestCommand {
        /// Command to test
        command: String,

        /// Additional packs to enable for this test
        #[arg(long, value_delimiter = ',')]
        with_packs: Option<Vec<String>>,

        /// Show detailed decision trace (same as `dcg explain`)
        #[arg(long)]
        explain: bool,

        /// Output format when using --explain
        #[arg(long, short = 'f', value_enum, default_value = "pretty")]
        format: ExplainFormat,

        /// Enable heredoc/inline-script scanning (overrides config)
        #[arg(long = "heredoc-scan", conflicts_with = "no_heredoc_scan")]
        heredoc_scan: bool,

        /// Disable heredoc/inline-script scanning (overrides config)
        #[arg(long = "no-heredoc-scan", conflicts_with = "heredoc_scan")]
        no_heredoc_scan: bool,

        /// Timeout budget for heredoc extraction (milliseconds)
        #[arg(long = "heredoc-timeout", value_name = "MS")]
        heredoc_timeout_ms: Option<u64>,

        /// Languages to scan (comma-separated). Example: python,bash,javascript
        #[arg(
            long = "heredoc-languages",
            value_delimiter = ',',
            value_name = "LANGS"
        )]
        heredoc_languages: Option<Vec<String>>,
    },

    /// Generate a sample configuration file
    #[command(name = "init")]
    Init {
        /// Output path (defaults to stdout)
        #[arg(short, long)]
        output: Option<String>,

        /// Overwrite existing file
        #[arg(long)]
        force: bool,
    },

    /// Show current configuration
    #[command(name = "config")]
    ShowConfig,

    /// Scan files for destructive commands (CI/pre-commit integration)
    ///
    /// Extracts executable command contexts from files and evaluates them
    /// using the same pipeline as hook mode. Use `--fail-on` to control
    /// exit codes for CI integration.
    #[command(name = "scan")]
    Scan(ScanCommand),

    /// Simulate policy evaluation on command logs (replay/dry-run)
    ///
    /// Parses a file containing commands (one per line) and evaluates each
    /// against the current policy. Useful for:
    /// - Rolling out new packs in warn-only mode
    /// - Analyzing false positive patterns
    /// - Generating allowlist candidates
    ///
    /// Input formats are auto-detected per line:
    /// - Plain command strings
    /// - Hook JSON (`{"tool_name":"Bash","tool_input":{"command":"..."}}`)
    /// - Decision log entries (`DCG_LOG_V1|...`)
    #[command(name = "simulate")]
    Simulate(SimulateCommand),

    /// Explain why a command would be blocked or allowed (decision trace)
    ///
    /// Shows the full decision pipeline: keyword gating, pack evaluation,
    /// pattern matching, and allowlist checks.
    #[command(name = "explain")]
    Explain {
        /// Command to explain
        command: String,

        /// Output format
        #[arg(long, short = 'f', value_enum, default_value = "pretty")]
        format: ExplainFormat,

        /// Additional packs to enable for this evaluation
        #[arg(long, value_delimiter = ',')]
        with_packs: Option<Vec<String>>,
    },

    /// Run regression corpus tests and output detailed JSON logs
    ///
    /// Loads test cases from TOML corpus files and evaluates each command,
    /// producing stable JSON output suitable for diffing against baselines.
    #[command(name = "corpus")]
    Corpus(CorpusCommand),
}

/// `dcg corpus` command arguments.
#[derive(Args, Debug)]
pub struct CorpusCommand {
    /// Path to corpus directory (default: tests/corpus)
    #[arg(long, short = 'd', default_value = "tests/corpus")]
    pub dir: std::path::PathBuf,

    /// Baseline file to diff against (exit non-zero on mismatch)
    #[arg(long, short = 'b')]
    pub baseline: Option<std::path::PathBuf>,

    /// Output format
    #[arg(long, short = 'f', value_enum, default_value = "json")]
    pub format: CorpusFormat,

    /// Write output to file instead of stdout
    #[arg(long, short = 'o')]
    pub output: Option<std::path::PathBuf>,

    /// Filter to specific category (`true_positives`, `false_positives`, `bypass_attempts`, `edge_cases`)
    #[arg(long, short = 'c')]
    pub category: Option<String>,

    /// Show only failed tests
    #[arg(long)]
    pub failures_only: bool,

    /// Suppress per-case output, show summary only
    #[arg(long)]
    pub summary_only: bool,
}

/// Output format for corpus command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum CorpusFormat {
    /// Structured JSON output (stable, diffable)
    #[default]
    Json,
    /// Human-readable colored output
    Pretty,
}

/// Options for self-updating dcg via the installer scripts.
#[derive(Args, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct UpdateCommand {
    /// Install specific version (default: latest)
    #[arg(long)]
    version: Option<String>,

    /// Install to system path (/usr/local/bin on Unix)
    #[arg(long)]
    system: bool,

    /// Auto-update PATH in shell rc files (Unix only)
    #[arg(long)]
    easy_mode: bool,

    /// Install to a custom destination directory
    #[arg(long)]
    dest: Option<std::path::PathBuf>,

    /// Build from source instead of downloading a binary (Unix only)
    #[arg(long)]
    from_source: bool,

    /// Run self-test after install
    #[arg(long)]
    verify: bool,

    /// Suppress non-error output (Unix only)
    #[arg(long)]
    quiet: bool,

    /// Disable gum formatting (Unix only)
    #[arg(long)]
    no_gum: bool,
}

/// `dcg scan` command arguments and actions.
#[derive(Args, Debug)]
#[command(args_conflicts_with_subcommands = true)]
pub struct ScanCommand {
    // === File selection modes (mutually exclusive) ===
    /// Scan files staged for commit (git index)
    #[arg(long, conflicts_with_all = ["paths", "git_diff"])]
    staged: bool,

    /// Scan explicit file paths (directories are expanded recursively)
    #[arg(long, conflicts_with_all = ["staged", "git_diff"], num_args = 1..)]
    paths: Option<Vec<std::path::PathBuf>>,

    /// Scan files changed in a git diff range (e.g., "HEAD~3..HEAD", "main..feature")
    #[arg(
        long = "git-diff",
        value_name = "REV_RANGE",
        conflicts_with_all = ["staged", "paths"]
    )]
    git_diff: Option<String>,

    // === Output / policy flags ===
    /// Output format
    #[arg(long, short = 'f', value_enum)]
    format: Option<crate::scan::ScanFormat>,

    /// Exit non-zero when findings meet this threshold
    #[arg(long, value_enum)]
    fail_on: Option<crate::scan::ScanFailOn>,

    // === Safety / performance knobs ===
    /// Maximum file size to scan (bytes); larger files are skipped
    #[arg(
        long = "max-file-size",
        value_name = "BYTES",
        value_parser = clap::value_parser!(u64)
    )]
    max_file_size: Option<u64>,

    /// Maximum number of findings to report (stop scanning after limit)
    #[arg(long = "max-findings", value_name = "N")]
    max_findings: Option<usize>,

    /// Exclude files matching glob pattern (repeatable)
    #[arg(long, value_name = "GLOB")]
    exclude: Vec<String>,

    /// Include only files matching glob pattern (repeatable)
    #[arg(long, value_name = "GLOB")]
    include: Vec<String>,

    // === Redaction / truncation ===
    /// Redact sensitive content in output
    #[arg(long, value_enum)]
    redact: Option<crate::scan::ScanRedactMode>,

    /// Truncate long commands in output (chars; 0 = no truncation)
    #[arg(long, value_name = "N")]
    truncate: Option<usize>,

    // === UX flags ===
    /// Include verbose output (skipped-file reasons, extractor stats)
    #[arg(long, short = 'v')]
    verbose: bool,

    /// Limit exemplars shown in pretty output
    #[arg(long, value_name = "N", default_value = "10")]
    top: usize,

    /// Optional action subcommand (pre-commit integration helpers)
    #[command(subcommand)]
    action: Option<ScanAction>,
}

/// `dcg scan` subcommands.
#[derive(Subcommand, Debug)]
pub enum ScanAction {
    /// Install a `.git/hooks/pre-commit` hook that runs `dcg scan --staged`.
    #[command(name = "install-pre-commit")]
    InstallPreCommit,

    /// Uninstall the `.git/hooks/pre-commit` hook installed by dcg.
    #[command(name = "uninstall-pre-commit")]
    UninstallPreCommit,
}

/// `dcg simulate` command arguments.
///
/// This task (git_safety_guard-1gt.8.1) implements the streaming parser.
/// The evaluation loop and aggregation will be added in git_safety_guard-1gt.8.2.
#[derive(Args, Debug)]
pub struct SimulateCommand {
    /// Input file (use "-" for stdin)
    #[arg(long, short = 'f', default_value = "-")]
    pub file: String,

    /// Maximum number of lines to process
    #[arg(long)]
    pub max_lines: Option<usize>,

    /// Maximum bytes to read from input
    #[arg(long)]
    pub max_bytes: Option<usize>,

    /// Maximum command length in bytes (longer commands are skipped)
    #[arg(long, default_value = "65536")]
    pub max_command_bytes: usize,

    /// Fail on first malformed line (default: count and continue)
    #[arg(long)]
    pub strict: bool,

    /// Output format (for parse stats, evaluation comes later)
    #[arg(long, short = 'F', value_enum, default_value = "pretty")]
    pub format: SimulateFormat,

    /// Show verbose output (per-line format detection, etc.)
    #[arg(long, short = 'v')]
    pub verbose: bool,

    /// Redact sensitive data in exemplar commands
    #[arg(long, value_enum, default_value = "none")]
    pub redact: crate::scan::ScanRedactMode,

    /// Maximum length for exemplar commands in output (0 = unlimited)
    #[arg(long, default_value = "120")]
    pub truncate: usize,

    /// Limit output to top N rules by count (0 = show all)
    #[arg(long, default_value = "20")]
    pub top: usize,
}

/// Output format for simulate command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum SimulateFormat {
    /// Human-readable output
    #[default]
    Pretty,
    /// Structured JSON output
    Json,
}

/// Output format for explain command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum ExplainFormat {
    /// Human-readable colored output
    #[default]
    Pretty,
    /// Compact single-line output
    Compact,
    /// Structured JSON output
    Json,
}

/// Allowlist subcommand actions
#[derive(Subcommand, Debug)]
pub enum AllowlistAction {
    /// Add a rule to the allowlist
    #[command(name = "add")]
    Add {
        /// Rule ID to allowlist (e.g., "core.git:reset-hard")
        rule_id: String,

        /// Reason for allowlisting (required)
        #[arg(long, short = 'r')]
        reason: String,

        /// Add to project allowlist (default if in git repo)
        #[arg(long, conflicts_with = "user")]
        project: bool,

        /// Add to user allowlist
        #[arg(long, conflicts_with = "project")]
        user: bool,

        /// Expiration date (ISO 8601 / RFC 3339)
        #[arg(long)]
        expires: Option<String>,

        /// Environment condition (e.g., CI=true)
        #[arg(long = "condition", value_name = "KEY=VAL")]
        conditions: Vec<String>,
    },

    /// Add an exact command to the allowlist
    #[command(name = "add-command")]
    AddCommand {
        /// Exact command to allowlist
        command: String,

        /// Reason for allowlisting (required)
        #[arg(long, short = 'r')]
        reason: String,

        /// Add to project allowlist (default if in git repo)
        #[arg(long, conflicts_with = "user")]
        project: bool,

        /// Add to user allowlist
        #[arg(long, conflicts_with = "project")]
        user: bool,

        /// Expiration date (ISO 8601 / RFC 3339)
        #[arg(long)]
        expires: Option<String>,
    },

    /// List allowlist entries
    #[command(name = "list")]
    List {
        /// Show project allowlist only
        #[arg(long, conflicts_with = "user")]
        project: bool,

        /// Show user allowlist only
        #[arg(long, conflicts_with = "project")]
        user: bool,

        /// Output format
        #[arg(long, value_enum, default_value = "pretty")]
        format: AllowlistOutputFormat,
    },

    /// Remove a rule from the allowlist
    #[command(name = "remove")]
    Remove {
        /// Rule ID to remove (e.g., "core.git:reset-hard")
        rule_id: String,

        /// Remove from project allowlist (default if in git repo)
        #[arg(long, conflicts_with = "user")]
        project: bool,

        /// Remove from user allowlist
        #[arg(long, conflicts_with = "project")]
        user: bool,
    },

    /// Validate allowlist entries
    #[command(name = "validate")]
    Validate {
        /// Validate project allowlist only
        #[arg(long, conflicts_with = "user")]
        project: bool,

        /// Validate user allowlist only
        #[arg(long, conflicts_with = "project")]
        user: bool,

        /// Treat warnings as errors
        #[arg(long)]
        strict: bool,
    },
}

/// Output format for allowlist list command
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum AllowlistOutputFormat {
    /// Human-readable output
    Pretty,
    /// JSON output
    Json,
}

/// Output format for doctor command
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum DoctorFormat {
    /// Human-readable colored output
    #[default]
    Pretty,
    /// Structured JSON output for automation
    Json,
}

/// Status of a doctor check
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorCheckStatus {
    /// Check passed
    Ok,
    /// Check passed with warning
    Warning,
    /// Check failed
    Error,
    /// Check was skipped
    Skipped,
}

/// A single doctor check result
#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    pub id: &'static str,
    pub name: &'static str,
    pub status: DoctorCheckStatus,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub fixed: bool,
}

/// Full doctor report (for JSON output)
#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorReport {
    pub schema_version: u32,
    pub checks: Vec<DoctorCheck>,
    pub issues: usize,
    pub fixed: usize,
    pub ok: bool,
}

/// Run the CLI command.
///
/// # Errors
///
/// Returns an error when no subcommand is provided (hook mode), or when a
/// subcommand that performs I/O fails.
#[allow(clippy::too_many_lines)]
pub fn run_command(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load();

    match cli.command {
        Some(Command::Doctor { fix, format }) => {
            doctor(fix, format);
        }
        Some(Command::Install { force }) => {
            install_hook(force)?;
        }
        Some(Command::Uninstall { purge }) => {
            uninstall_hook(purge)?;
        }
        Some(Command::Update(update)) => {
            self_update(update)?;
        }
        Some(Command::ListPacks { enabled, verbose }) => {
            list_packs(&config, enabled, verbose);
        }
        Some(Command::PackInfo { pack_id, patterns }) => {
            pack_info(&pack_id, patterns)?;
        }
        Some(Command::TestCommand {
            command,
            with_packs,
            explain,
            format,
            heredoc_scan,
            no_heredoc_scan,
            heredoc_timeout_ms,
            heredoc_languages,
        }) => {
            if explain {
                // Delegate to explain handler for detailed trace output
                handle_explain(&config, &command, format, with_packs);
            } else {
                test_command(
                    &config,
                    &command,
                    with_packs,
                    heredoc_scan,
                    no_heredoc_scan,
                    heredoc_timeout_ms,
                    heredoc_languages,
                );
            }
        }
        Some(Command::Init { output, force }) => {
            init_config(output, force)?;
        }
        Some(Command::ShowConfig) => {
            show_config(&config);
        }
        Some(Command::Allowlist { action }) => {
            handle_allowlist_command(action)?;
        }
        Some(Command::Allow {
            rule_id,
            reason,
            project,
            user,
            expires,
        }) => {
            // Shortcut for `allowlist add`
            let layer = resolve_layer(project, user);
            allowlist_add_rule(&rule_id, &reason, layer, expires.as_deref(), &[])?;
        }
        Some(Command::Unallow {
            rule_id,
            project,
            user,
        }) => {
            // Shortcut for `allowlist remove`
            let layer = resolve_layer(project, user);
            allowlist_remove(&rule_id, layer)?;
        }
        Some(Command::Scan(scan)) => {
            handle_scan_command(&config, scan)?;
        }
        Some(Command::Simulate(sim)) => {
            handle_simulate_command(sim, &config)?;
        }
        Some(Command::Explain {
            command,
            format,
            with_packs,
        }) => {
            handle_explain(&config, &command, format, with_packs);
        }
        Some(Command::Corpus(corpus)) => {
            handle_corpus_command(&config, corpus)?;
        }
        None => {
            // No subcommand - run in hook mode (default behavior)
            // This is handled by main.rs
            return Err("No subcommand provided. Running in hook mode.".into());
        }
    }

    Ok(())
}

/// List all packs and their status
fn list_packs(config: &Config, enabled_only: bool, verbose: bool) {
    let enabled_packs = config.enabled_pack_ids();
    let infos = REGISTRY.list_packs(&enabled_packs);

    println!("Available packs:");
    println!();

    // Group by category
    let mut by_category: std::collections::BTreeMap<&str, Vec<_>> =
        std::collections::BTreeMap::new();
    for info in &infos {
        let category = info.id.split('.').next().unwrap_or(&info.id);
        by_category.entry(category).or_default().push(info);
    }

    for (category, packs) in by_category {
        println!("  {category}:");
        for info in packs {
            if enabled_only && !info.enabled {
                continue;
            }

            let status = if info.enabled { "✓" } else { "○" };
            if verbose {
                println!(
                    "    {} {} - {} ({} safe, {} destructive)",
                    status,
                    info.id,
                    info.description,
                    info.safe_pattern_count,
                    info.destructive_pattern_count
                );
            } else {
                println!("    {} {} - {}", status, info.id, info.name);
            }
        }
        println!();
    }

    println!("Legend: ✓ = enabled, ○ = disabled");
    println!();
    println!("Enable packs in ~/.config/dcg/config.toml");
}

/// Show detailed information about a pack
fn pack_info(pack_id: &str, show_patterns: bool) -> Result<(), Box<dyn std::error::Error>> {
    let pack = REGISTRY
        .get(pack_id)
        .ok_or_else(|| format!("Pack not found: {pack_id}"))?;

    println!("Pack: {}", pack.name);
    println!("ID: {}", pack.id);
    println!("Description: {}", pack.description);
    println!("Keywords: {}", pack.keywords.join(", "));
    println!();
    println!("Patterns:");
    println!("  Safe patterns: {}", pack.safe_patterns.len());
    println!(
        "  Destructive patterns: {}",
        pack.destructive_patterns.len()
    );

    if show_patterns {
        println!();
        println!("Safe patterns:");
        for pattern in &pack.safe_patterns {
            println!("  - {} : {}", pattern.name, pattern.regex.as_str());
        }

        println!();
        println!("Destructive patterns:");
        for pattern in &pack.destructive_patterns {
            let name = pattern.name.unwrap_or("unnamed");
            println!("  - {} : {}", name, pattern.regex.as_str());
            println!("    Reason: {}", pattern.reason);
        }
    }

    Ok(())
}

/// Test a command against the configured packs using the shared evaluator.
///
/// This ensures parity with hook mode by using the same evaluation logic:
/// 1. Config allow overrides
/// 2. Config block overrides
/// 3. Quick rejection (keyword filtering)
/// 4. Command normalization
/// 5. Pack pattern matching
#[allow(clippy::needless_pass_by_value)] // Value is consumed from CLI args
fn test_command(
    config: &Config,
    command: &str,
    extra_packs: Option<Vec<String>>,
    heredoc_scan: bool,
    no_heredoc_scan: bool,
    heredoc_timeout_ms: Option<u64>,
    heredoc_languages: Option<Vec<String>>,
) {
    // Build effective config with extra packs if specified
    let mut effective_config = extra_packs.map_or_else(
        || config.clone(),
        |packs| {
            let mut modified = config.clone();
            modified.packs.enabled.extend(packs);
            modified
        },
    );

    // CLI overrides for heredoc scanning (higher priority than env/config file).
    if heredoc_scan {
        effective_config.heredoc.enabled = Some(true);
    }
    if no_heredoc_scan {
        effective_config.heredoc.enabled = Some(false);
    }
    if let Some(timeout_ms) = heredoc_timeout_ms {
        effective_config.heredoc.timeout_ms = Some(timeout_ms);
    }
    if let Some(langs) = heredoc_languages {
        effective_config.heredoc.languages = Some(langs);
    }

    // Get enabled packs and collect keywords for quick rejection
    let enabled_packs = effective_config.enabled_pack_ids();
    let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    let heredoc_settings = effective_config.heredoc_settings();

    // Compile overrides once (not per-command)
    let compiled_overrides = effective_config.overrides.compile();

    // Load allowlists (project/user/system) for parity with hook mode.
    // This is a small file read and only affects decisions when a rule matches.
    let allowlists = load_default_allowlists();

    // Use shared evaluator for consistent behavior with hook mode
    let result = evaluate_command_with_pack_order(
        command,
        &enabled_keywords,
        &ordered_packs,
        &compiled_overrides,
        &allowlists,
        &heredoc_settings,
    );

    println!("Command: {command}");
    println!();

    match result.decision {
        EvaluationDecision::Allow => {
            if let Some(override_info) = &result.allowlist_override {
                println!(
                    "Result: ALLOWED (allowlisted by {})",
                    override_info.layer.label()
                );
                println!("Allowlist reason: {}", override_info.reason);
            } else {
                println!("Result: ALLOWED");
            }
        }
        EvaluationDecision::Deny => {
            println!("Result: BLOCKED");
            if let Some(ref info) = result.pattern_info {
                if let Some(ref pack_id) = info.pack_id {
                    println!("Pack: {pack_id}");
                }
                if let Some(ref pattern_name) = info.pattern_name {
                    println!("Pattern: {pattern_name}");
                }
                println!("Reason: {}", info.reason);
                let source = match info.source {
                    MatchSource::ConfigOverride => "config override",
                    MatchSource::LegacyPattern => "legacy pattern",
                    MatchSource::Pack => "pack",
                    MatchSource::HeredocAst => "heredoc/inline script (AST)",
                };
                println!("Source: {source}");
            }
        }
    }
}

/// Generate a sample configuration file
fn init_config(output: Option<String>, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    let sample = Config::generate_sample_config();

    match output {
        Some(path) => {
            let path = std::path::Path::new(&path);
            if path.exists() && !force {
                return Err(
                    format!("File exists: {}. Use --force to overwrite.", path.display()).into(),
                );
            }

            // Create parent directories if needed
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            std::fs::write(path, sample)?;
            println!("Configuration written to: {}", path.display());
        }
        None => {
            println!("{sample}");
        }
    }

    Ok(())
}

/// Show the current configuration
fn show_config(config: &Config) {
    println!("Current configuration:");
    println!();
    println!("Config sources (lowest → highest priority):");
    let user_cfg = config_path();
    let system_cfg = std::path::PathBuf::from("/etc/dcg").join("config.toml");
    if system_cfg.exists() {
        println!("  - system: {}", system_cfg.display());
    }
    if user_cfg.exists() {
        println!("  - user: {}", user_cfg.display());
    }
    if let Some(repo_root) = find_repo_root_from_cwd() {
        let project_cfg = repo_root.join(".dcg.toml");
        if project_cfg.exists() {
            println!("  - project: {}", project_cfg.display());
        }
    }
    if let Ok(value) = std::env::var(crate::config::ENV_CONFIG_PATH) {
        if let Some(path) = crate::config::resolve_config_path_value(
            &value,
            std::env::current_dir().ok().as_deref(),
        ) {
            if path.exists() {
                println!("  - DCG_CONFIG: {}", path.display());
            } else {
                println!("  - DCG_CONFIG: {} (missing)", path.display());
            }
        } else {
            println!("  - DCG_CONFIG: (set but empty)");
        }
    }
    println!();
    println!("General:");
    println!("  Color: {}", config.general.color);
    println!("  Verbose: {}", config.general.verbose);
    println!("  Log file: {:?}", config.general.log_file);
    println!();
    println!("Enabled packs:");
    for pack in config.enabled_pack_ids() {
        println!("  - {pack}");
    }
    println!();
    println!("Disabled packs:");
    for pack in &config.packs.disabled {
        println!("  - {pack}");
    }
    println!();

    let heredoc = config.heredoc_settings();
    println!("Heredoc scanning:");
    println!("  Enabled: {}", heredoc.enabled);
    println!("  Timeout (ms): {}", heredoc.limits.timeout_ms);
    println!("  Max body bytes: {}", heredoc.limits.max_body_bytes);
    println!("  Max body lines: {}", heredoc.limits.max_body_lines);
    println!("  Max heredocs: {}", heredoc.limits.max_heredocs);
    println!(
        "  Fail-open on parse error: {}",
        heredoc.fallback_on_parse_error
    );
    println!("  Fail-open on timeout: {}", heredoc.fallback_on_timeout);

    let lang_label = |lang: crate::heredoc::ScriptLanguage| -> &'static str {
        match lang {
            crate::heredoc::ScriptLanguage::Bash => "bash",
            crate::heredoc::ScriptLanguage::Go => "go",
            crate::heredoc::ScriptLanguage::Php => "php",
            crate::heredoc::ScriptLanguage::Python => "python",
            crate::heredoc::ScriptLanguage::Ruby => "ruby",
            crate::heredoc::ScriptLanguage::Perl => "perl",
            crate::heredoc::ScriptLanguage::JavaScript => "javascript",
            crate::heredoc::ScriptLanguage::TypeScript => "typescript",
            crate::heredoc::ScriptLanguage::Unknown => "unknown",
        }
    };

    if let Some(langs) = &heredoc.allowed_languages {
        let langs = langs.iter().copied().map(lang_label).collect::<Vec<_>>();
        println!("  Languages: {}", langs.join(","));
    } else {
        println!("  Languages: all");
    }
}

const DCG_SCAN_PRE_COMMIT_SENTINEL: &str = "# dcg:scan-pre-commit";

fn build_scan_pre_commit_hook_script() -> String {
    format!(
        r#"#!/usr/bin/env sh
{DCG_SCAN_PRE_COMMIT_SENTINEL}
# Generated by: dcg scan install-pre-commit
#
# This hook runs `dcg scan --staged` to block commits that introduce destructive
# commands in executable contexts (CI workflows, scripts, etc.).
#
# Bypass once (unsafe): git commit --no-verify

set -u

if ! command -v dcg >/dev/null 2>&1; then
  echo "dcg pre-commit hook: 'dcg' not found in PATH; skipping scan." >&2
  echo "Fix: install dcg or remove this hook via: dcg scan uninstall-pre-commit" >&2
  exit 0
fi

dcg scan --staged
status=$?
if [ "$status" -ne 0 ]; then
  echo >&2
  echo "dcg scan blocked this commit." >&2
  echo "Fix findings (preferred), or allowlist false positives:" >&2
  echo "  dcg allow <rule_id> -r \"<reason>\" --project" >&2
  echo "  dcg allowlist add-command \"<command>\" -r \"<reason>\" --project" >&2
  echo "Bypass once (unsafe): git commit --no-verify" >&2
  exit "$status"
fi
"#,
    )
}

fn git_resolve_path(
    cwd: &std::path::Path,
    git_path: &str,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    ensure_git_repo(cwd)?;

    let output = std::process::Command::new("git")
        .current_dir(cwd)
        .args(["rev-parse", "--git-path", git_path])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git rev-parse --git-path {git_path} failed: {stderr}").into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let path_str = stdout.trim();
    if path_str.is_empty() {
        return Err(format!("git rev-parse --git-path {git_path} returned empty output").into());
    }

    let path = std::path::PathBuf::from(path_str);
    Ok(if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    })
}

fn git_show_toplevel(
    cwd: &std::path::Path,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    ensure_git_repo(cwd)?;

    let output = std::process::Command::new("git")
        .current_dir(cwd)
        .args(["rev-parse", "--show-toplevel"])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git rev-parse --show-toplevel failed: {stderr}").into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let root = stdout.trim();
    if root.is_empty() {
        return Err("git rev-parse --show-toplevel returned empty output".into());
    }

    Ok(std::path::PathBuf::from(root))
}

#[derive(Debug, Clone)]
struct LoadedHooksToml {
    path: std::path::PathBuf,
    cfg: crate::scan::HooksToml,
    warnings: Vec<String>,
}

fn maybe_load_repo_hooks_toml(
    cwd: &std::path::Path,
) -> Result<Option<LoadedHooksToml>, Box<dyn std::error::Error>> {
    let Ok(repo_root) = git_show_toplevel(cwd) else {
        return Ok(None);
    };

    let path = repo_root.join(".dcg/hooks.toml");
    if !path.exists() {
        return Ok(None);
    }

    let contents = std::fs::read_to_string(&path)?;
    let (cfg, warnings) = crate::scan::parse_hooks_toml(&contents)
        .map_err(|e| format!("Failed to parse {}: {e}", path.display()))?;

    Ok(Some(LoadedHooksToml {
        path,
        cfg,
        warnings,
    }))
}

fn hook_looks_like_dcg_scan_pre_commit(hook_bytes: &[u8]) -> bool {
    String::from_utf8_lossy(hook_bytes).contains(DCG_SCAN_PRE_COMMIT_SENTINEL)
}

fn install_scan_pre_commit_hook() -> Result<(), Box<dyn std::error::Error>> {
    let cwd = std::env::current_dir()?;
    let hook_path = install_scan_pre_commit_hook_at(&cwd)?;
    eprintln!("Installed pre-commit hook: {}", hook_path.display());
    Ok(())
}

fn install_scan_pre_commit_hook_at(
    cwd: &std::path::Path,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let hook_path = git_resolve_path(cwd, "hooks/pre-commit")?;

    if hook_path.exists() {
        let existing = std::fs::read(&hook_path)?;
        if !hook_looks_like_dcg_scan_pre_commit(&existing) {
            return Err(format!(
                "Refusing to overwrite existing pre-commit hook at {}\n\n\
This hook does not appear to have been installed by dcg.\n\n\
Manual integration options:\n\
  1) Add a line to your existing hook to run: dcg scan --staged\n\
  2) Configure your hook manager to run: dcg scan --staged\n\n\
To replace your hook with a dcg-managed hook, delete it manually and re-run:\n\
  dcg scan install-pre-commit",
                hook_path.display()
            )
            .into());
        }
    } else if let Some(parent) = hook_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&hook_path, build_scan_pre_commit_hook_script())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut perms = std::fs::metadata(&hook_path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&hook_path, perms)?;
    }

    Ok(hook_path)
}

fn uninstall_scan_pre_commit_hook() -> Result<(), Box<dyn std::error::Error>> {
    let cwd = std::env::current_dir()?;
    let removed = uninstall_scan_pre_commit_hook_at(&cwd)?;
    if let Some(path) = removed {
        eprintln!("Removed pre-commit hook: {}", path.display());
    } else {
        eprintln!("No dcg pre-commit hook found (nothing to remove).");
    }
    Ok(())
}

fn uninstall_scan_pre_commit_hook_at(
    cwd: &std::path::Path,
) -> Result<Option<std::path::PathBuf>, Box<dyn std::error::Error>> {
    let hook_path = git_resolve_path(cwd, "hooks/pre-commit")?;

    if !hook_path.exists() {
        return Ok(None);
    }

    let existing = std::fs::read(&hook_path)?;
    if !hook_looks_like_dcg_scan_pre_commit(&existing) {
        return Err(format!(
            "Refusing to remove existing pre-commit hook at {}\n\n\
This hook does not appear to have been installed by dcg.\n\n\
If you want to remove it, delete it manually.\n\
If you want to keep it, you can still add dcg scanning by adding this line:\n\
  dcg scan --staged",
            hook_path.display()
        )
        .into());
    }

    std::fs::remove_file(&hook_path)?;
    Ok(Some(hook_path))
}

/// Handle the `dcg scan` subcommand.
///
/// Validates file selection mode, builds scan options, and delegates to
/// the scan module for execution.
#[derive(Debug, Clone)]
struct ResolvedScanSettings {
    format: crate::scan::ScanFormat,
    fail_on: crate::scan::ScanFailOn,
    max_file_size: u64,
    max_findings: usize,
    redact: crate::scan::ScanRedactMode,
    truncate: usize,
    include: Vec<String>,
    exclude: Vec<String>,
}

#[derive(Debug, Clone)]
struct ScanSettingsOverrides {
    format: Option<crate::scan::ScanFormat>,
    fail_on: Option<crate::scan::ScanFailOn>,
    max_file_size: Option<u64>,
    max_findings: Option<usize>,
    redact: Option<crate::scan::ScanRedactMode>,
    truncate: Option<usize>,
    include: Vec<String>,
    exclude: Vec<String>,
}

impl ScanSettingsOverrides {
    fn resolve(self, hooks: Option<&crate::scan::HooksToml>) -> ResolvedScanSettings {
        let mut resolved = ResolvedScanSettings {
            format: crate::scan::ScanFormat::Pretty,
            fail_on: crate::scan::ScanFailOn::Error,
            max_file_size: 1_048_576,
            max_findings: 100,
            redact: crate::scan::ScanRedactMode::None,
            truncate: 200,
            include: Vec::new(),
            exclude: Vec::new(),
        };

        if let Some(hooks) = hooks {
            if let Some(format) = hooks.scan.format {
                resolved.format = format;
            }
            if let Some(fail_on) = hooks.scan.fail_on {
                resolved.fail_on = fail_on;
            }
            if let Some(max_file_size) = hooks.scan.max_file_size {
                resolved.max_file_size = max_file_size;
            }
            if let Some(max_findings) = hooks.scan.max_findings {
                resolved.max_findings = max_findings;
            }
            if let Some(redact) = hooks.scan.redact {
                resolved.redact = redact;
            }
            if let Some(truncate) = hooks.scan.truncate {
                resolved.truncate = truncate;
            }
            resolved.include.clone_from(&hooks.scan.paths.include);
            resolved.exclude.clone_from(&hooks.scan.paths.exclude);
        }

        if let Some(format) = self.format {
            resolved.format = format;
        }
        if let Some(fail_on) = self.fail_on {
            resolved.fail_on = fail_on;
        }
        if let Some(max_file_size) = self.max_file_size {
            resolved.max_file_size = max_file_size;
        }
        if let Some(max_findings) = self.max_findings {
            resolved.max_findings = max_findings;
        }
        if let Some(redact) = self.redact {
            resolved.redact = redact;
        }
        if let Some(truncate) = self.truncate {
            resolved.truncate = truncate;
        }
        if !self.include.is_empty() {
            resolved.include = self.include;
        }
        if !self.exclude.is_empty() {
            resolved.exclude = self.exclude;
        }

        resolved
    }
}

/// Handle the `dcg simulate` command.
///
/// This implements git_safety_guard-1gt.8.1 (streaming parser) and
/// git_safety_guard-1gt.8.2 (evaluation loop + aggregation).
fn handle_simulate_command(
    sim: SimulateCommand,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::simulate::{
        SimulateLimits, SimulateOutputConfig, SimulationConfig, format_json_output,
        format_pretty_output, run_simulation_from_reader,
    };
    use std::fs::File;
    use std::io::{self, BufReader};

    let SimulateCommand {
        file,
        max_lines,
        max_bytes,
        max_command_bytes,
        strict,
        format,
        verbose,
        redact,
        truncate,
        top,
    } = sim;

    let limits = SimulateLimits {
        max_lines,
        max_bytes,
        max_command_bytes: Some(max_command_bytes),
    };

    // Open input (file or stdin)
    let reader: Box<dyn io::Read> = if file == "-" {
        Box::new(io::stdin())
    } else {
        Box::new(BufReader::new(File::open(&file)?))
    };

    let sim_config = SimulationConfig::default();

    // Run simulation with evaluation loop
    let result = run_simulation_from_reader(reader, limits, config, sim_config, strict)?;

    // Build output configuration
    let output_config = SimulateOutputConfig {
        redact,
        truncate,
        top,
        verbose,
    };

    // Output results using formatting functions
    match format {
        SimulateFormat::Pretty => {
            print!("{}", format_pretty_output(&result, &output_config));
        }
        SimulateFormat::Json => {
            println!("{}", format_json_output(result, &output_config)?);
        }
    }

    Ok(())
}

fn handle_scan_command(
    config: &Config,
    scan: ScanCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    let ScanCommand {
        staged,
        paths,
        git_diff,
        format,
        fail_on,
        max_file_size,
        max_findings,
        exclude,
        include,
        redact,
        truncate,
        verbose,
        top,
        action,
    } = scan;

    match action {
        Some(ScanAction::InstallPreCommit) => {
            install_scan_pre_commit_hook()?;
        }
        Some(ScanAction::UninstallPreCommit) => {
            uninstall_scan_pre_commit_hook()?;
        }
        None => {
            let cwd = std::env::current_dir()?;
            let hooks = maybe_load_repo_hooks_toml(&cwd)?;
            if let Some(hooks) = &hooks {
                for warning in &hooks.warnings {
                    eprintln!("Warning: {}: {warning}", hooks.path.display());
                }
            }

            let settings = ScanSettingsOverrides {
                format,
                fail_on,
                max_file_size,
                max_findings,
                redact,
                truncate,
                include,
                exclude,
            }
            .resolve(hooks.as_ref().map(|h| &h.cfg));

            handle_scan(
                config,
                staged,
                paths,
                git_diff,
                settings.format,
                settings.fail_on,
                settings.max_file_size,
                settings.max_findings,
                &settings.exclude,
                &settings.include,
                settings.redact,
                settings.truncate,
                verbose,
                top,
            )?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::needless_pass_by_value)] // Values consumed from CLI args
fn handle_scan(
    config: &Config,
    staged: bool,
    paths: Option<Vec<std::path::PathBuf>>,
    git_diff: Option<String>,
    format: crate::scan::ScanFormat,
    fail_on: crate::scan::ScanFailOn,
    max_file_size: u64,
    max_findings: usize,
    exclude: &[String],
    include: &[String],
    redact: crate::scan::ScanRedactMode,
    truncate: usize,
    verbose: bool,
    top: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::scan::{ScanEvalContext, ScanOptions, scan_paths, should_fail};

    // Validate file selection mode - at least one must be specified
    let file_sources = [staged, paths.is_some(), git_diff.is_some()]
        .iter()
        .filter(|&&x| x)
        .count();

    if file_sources == 0 {
        eprintln!("Error: No file selection mode specified.");
        eprintln!();
        eprintln!("Use one of:");
        eprintln!("  --staged         Scan files staged for commit");
        eprintln!("  --paths <paths>  Scan explicit file paths");
        eprintln!("  --git-diff <rev> Scan files changed in a git diff range");
        std::process::exit(1);
    }

    // Build scan options
    let options = ScanOptions {
        format,
        fail_on,
        max_file_size_bytes: max_file_size,
        max_findings,
        redact,
        truncate,
    };

    // Build evaluation context from config
    let ctx = ScanEvalContext::from_config(config);

    // Determine paths to scan
    let scan_paths_list: Vec<std::path::PathBuf> = if staged {
        get_staged_files()?
    } else if let Some(ref paths) = paths {
        paths.clone()
    } else if let Some(ref rev_range) = git_diff {
        get_git_diff_files(rev_range)?
    } else {
        unreachable!("File selection mode already validated")
    };

    // Apply include/exclude filters
    let filtered_paths = filter_paths(&scan_paths_list, include, exclude);

    if verbose {
        eprintln!(
            "Scanning {} file(s) (filtered from {})",
            filtered_paths.len(),
            scan_paths_list.len()
        );
    }

    // Run scan
    let report = scan_paths(&filtered_paths, &options, config, &ctx)?;

    // Output results
    match format {
        crate::scan::ScanFormat::Pretty => {
            print_scan_pretty(&report, verbose, top);
        }
        crate::scan::ScanFormat::Json => {
            let json = serde_json::to_string_pretty(&report)?;
            println!("{json}");
        }
        crate::scan::ScanFormat::Markdown => {
            print_scan_markdown(&report, top, truncate);
        }
    }

    // Exit with appropriate code based on fail-on policy
    if should_fail(&report, fail_on) {
        std::process::exit(1);
    }

    Ok(())
}

/// Get list of files staged for commit (git index).
fn get_staged_files() -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
    let cwd = std::env::current_dir()?;
    get_staged_files_at(&cwd)
}

fn get_staged_files_at(
    cwd: &std::path::Path,
) -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
    ensure_git_repo(cwd)?;

    let output = std::process::Command::new("git")
        .current_dir(cwd)
        .args([
            "diff",
            "--cached",
            "-M",
            "--name-status",
            "-z",
            "--diff-filter=ACMR",
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git diff --cached failed: {stderr}").into());
    }

    Ok(parse_git_name_status_z(&output.stdout))
}

/// Get list of files changed in a git diff range.
fn get_git_diff_files(
    rev_range: &str,
) -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
    let cwd = std::env::current_dir()?;
    get_git_diff_files_at(&cwd, rev_range)
}

fn get_git_diff_files_at(
    cwd: &std::path::Path,
    rev_range: &str,
) -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
    ensure_git_repo(cwd)?;

    let output = std::process::Command::new("git")
        .current_dir(cwd)
        .args([
            "diff",
            "-M",
            "--name-status",
            "-z",
            "--diff-filter=ACMR",
            rev_range,
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git diff --name-status failed: {stderr}").into());
    }

    Ok(parse_git_name_status_z(&output.stdout))
}

fn ensure_git_repo(cwd: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let output = std::process::Command::new("git")
        .current_dir(cwd)
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Not a git repository: {stderr}").into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim() != "true" {
        return Err("Not inside a git work tree".into());
    }

    Ok(())
}

fn parse_git_name_status_z(stdout: &[u8]) -> Vec<std::path::PathBuf> {
    use std::collections::BTreeSet;

    let mut set: BTreeSet<String> = BTreeSet::new();
    let mut it = stdout.split(|b| *b == 0).filter(|s| !s.is_empty());

    while let Some(status_bytes) = it.next() {
        let status = String::from_utf8_lossy(status_bytes);
        let Some(kind) = status.chars().next() else {
            continue;
        };

        match kind {
            // Renames/copies: status, old path, new path
            'R' | 'C' => {
                let _old = it.next();
                let new = it.next();
                if let Some(new) = new {
                    set.insert(String::from_utf8_lossy(new).to_string());
                }
            }
            // Added/modified/other: status, path
            _ => {
                if let Some(path) = it.next() {
                    set.insert(String::from_utf8_lossy(path).to_string());
                }
            }
        }
    }

    set.into_iter().map(std::path::PathBuf::from).collect()
}

/// Filter paths by include/exclude glob patterns.
fn filter_paths(
    paths: &[std::path::PathBuf],
    include: &[String],
    exclude: &[String],
) -> Vec<std::path::PathBuf> {
    paths
        .iter()
        .filter(|p| {
            let path_str = p.to_string_lossy();

            // If include patterns are specified, path must match at least one
            if !include.is_empty() {
                let matches_include = include.iter().any(|pattern| glob_match(pattern, &path_str));
                if !matches_include {
                    return false;
                }
            }

            // Path must not match any exclude pattern
            !exclude.iter().any(|pattern| glob_match(pattern, &path_str))
        })
        .cloned()
        .collect()
}

/// Simple glob matching (supports * and **).
fn glob_match(pattern: &str, path: &str) -> bool {
    use std::borrow::Cow;

    fn normalize_separators(s: &str) -> Cow<'_, str> {
        if s.contains('\\') {
            Cow::Owned(s.replace('\\', "/"))
        } else {
            Cow::Borrowed(s)
        }
    }

    fn matches_glob_prefix(prefix_raw: &str, path: &str) -> bool {
        if prefix_raw.is_empty() {
            return true;
        }

        // Allow matching the prefix directory itself (e.g., pattern `src/**` should match `src`)
        // while still requiring a path boundary (avoid matching `src2/...`).
        let prefix_no_slash = prefix_raw.trim_end_matches('/');
        if path == prefix_no_slash {
            return true;
        }

        if prefix_raw.ends_with('/') {
            return path.starts_with(prefix_raw);
        }

        // If the pattern author omitted a trailing '/', enforce a boundary at the next char.
        if !path.starts_with(prefix_raw) {
            return false;
        }

        path.as_bytes()
            .get(prefix_raw.len())
            .is_some_and(|b| *b == b'/')
    }

    let pattern = normalize_separators(pattern);
    let path = normalize_separators(path);
    let pattern = pattern.as_ref();
    let path = path.as_ref();

    // Very basic glob support for now - full glob crate could be added later
    if let Some((prefix_raw, suffix_raw)) = pattern.split_once("**") {
        // ** matches any path segment(s)
        if !matches_glob_prefix(prefix_raw, path) {
            return false;
        }

        let suffix = suffix_raw.trim_start_matches('/');
        if suffix.is_empty() {
            return true;
        }

        // For suffix like "*.rs", check the final path component.
        if suffix.contains('*') && !suffix.contains('/') {
            let last = path.rsplit('/').next().unwrap_or(path);
            let parts: Vec<&str> = suffix.split('*').collect();
            if parts.len() == 2 {
                let (pre, suf) = (parts[0], parts[1]);
                if !last.starts_with(pre) || !last.ends_with(suf) {
                    return false;
                }

                let min_len = pre.len() + suf.len();
                return last.len() >= min_len;
            }
        }

        return path.ends_with(suffix);
    }

    if pattern.contains('*') {
        // Single * matches anything except /
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            let prefix = parts[0];
            let suffix = parts[1];

            if !path.starts_with(prefix) || !path.ends_with(suffix) {
                return false;
            }

            // Check that prefix and suffix don't overlap
            // e.g., pattern "test*st" should NOT match "test" because the middle would be negative
            let min_len = prefix.len() + suffix.len();
            if path.len() < min_len {
                return false;
            }

            // The middle section (between prefix and suffix) must not contain /
            let middle_start = prefix.len();
            let middle_end = path.len() - suffix.len();
            return !path[middle_start..middle_end].contains('/');
        }
    }

    // Exact match
    pattern == path
}

/// Print scan report in pretty format.
fn print_scan_pretty(report: &crate::scan::ScanReport, verbose: bool, top: usize) {
    use colored::Colorize;

    if report.findings.is_empty() {
        println!("{}", "No findings.".green());
    } else {
        let total = report.findings.len();
        let shown = if top == 0 { total } else { total.min(top) };
        println!("{} finding(s):", total.to_string().yellow().bold());
        println!();

        let mut current_file: Option<&str> = None;
        for finding in report.findings.iter().take(shown) {
            if current_file != Some(finding.file.as_str()) {
                current_file = Some(finding.file.as_str());
                println!("{}", finding.file.bold());
            }

            let decision_icon = match finding.decision {
                crate::scan::ScanDecision::Deny => "DENY".red().bold(),
                crate::scan::ScanDecision::Warn => "WARN".yellow().bold(),
                crate::scan::ScanDecision::Allow => "ALLOW".green().bold(),
            };

            let severity_icon = match finding.severity {
                crate::scan::ScanSeverity::Error => "error".red(),
                crate::scan::ScanSeverity::Warning => "warning".yellow(),
                crate::scan::ScanSeverity::Info => "info".blue(),
            };

            let location = finding.col.map_or_else(
                || finding.line.to_string(),
                |col| format!("{}:{col}", finding.line),
            );

            println!(
                "  [{decision_icon}] ({severity_icon}) {location}  extractor={}",
                finding.extractor_id
            );
            println!("    {}", finding.extracted_command.dimmed());

            if let Some(ref rule_id) = finding.rule_id {
                println!("    Rule: {rule_id}");
            }

            if let Some(ref reason) = finding.reason {
                println!("    Reason: {reason}");
            }

            if let Some(ref suggestion) = finding.suggestion {
                println!("    Suggestion: {}", suggestion.green());
            }
        }

        if shown < total {
            println!();
            println!(
                "{}",
                format!(
                    "… {remaining} more finding(s) not shown (use --top 0 to show all)",
                    remaining = total - shown
                )
                .bright_black()
            );
        }
    }

    // Summary
    println!("---");
    let considered = report.summary.files_scanned + report.summary.files_skipped;
    println!(
        "Files: {considered} considered, {} scanned, {} skipped",
        report.summary.files_scanned, report.summary.files_skipped
    );
    println!("Commands extracted: {}", report.summary.commands_extracted);
    println!(
        "Findings: {} (allow={}, warn={}, deny={})",
        report.summary.findings_total,
        report.summary.decisions.allow,
        report.summary.decisions.warn,
        report.summary.decisions.deny
    );
    println!(
        "Severities: error={}, warning={}, info={}",
        report.summary.severities.error,
        report.summary.severities.warning,
        report.summary.severities.info
    );

    if let Some(elapsed_ms) = report.summary.elapsed_ms {
        println!("Elapsed: {elapsed_ms} ms");
    }

    if report.summary.max_findings_reached {
        println!(
            "{}",
            "Note: max findings limit reached, scan stopped early".yellow()
        );
    }

    if verbose {
        // Additional verbose info could go here
    }
}

/// Print scan report as GitHub-flavored Markdown (for PR comments).
///
/// Output structure:
/// - Summary header with findings counts
/// - Findings grouped by file, each in a `<details>` block
/// - Severity badges (error/warning/info)
/// - Truncated command preview for readability
fn print_scan_markdown(report: &crate::scan::ScanReport, top: usize, truncate: usize) {
    use std::collections::BTreeMap;

    // Header
    println!("## DCG Scan Results\n");

    if report.findings.is_empty() {
        println!(":white_check_mark: **No findings** - all commands passed safety checks.\n");
        print_scan_markdown_summary(report);
        return;
    }

    // Summary badges
    let error_count = report.summary.severities.error;
    let warning_count = report.summary.severities.warning;
    let info_count = report.summary.severities.info;

    if error_count > 0 {
        print!(":x: **{error_count} error(s)** ");
    }
    if warning_count > 0 {
        print!(":warning: **{warning_count} warning(s)** ");
    }
    if info_count > 0 {
        print!(":information_source: **{info_count} info** ");
    }
    println!("\n");

    // Group findings by file
    let mut by_file: BTreeMap<&str, Vec<&crate::scan::ScanFinding>> = BTreeMap::new();
    for finding in &report.findings {
        by_file.entry(&finding.file).or_default().push(finding);
    }

    // Limit total findings shown
    let total_findings = report.findings.len();
    let limit = if top == 0 { usize::MAX } else { top };
    let mut shown = 0;

    for (file, findings) in &by_file {
        if shown >= limit {
            break;
        }

        let file_errors = findings
            .iter()
            .filter(|f| matches!(f.severity, crate::scan::ScanSeverity::Error))
            .count();
        let file_warnings = findings
            .iter()
            .filter(|f| matches!(f.severity, crate::scan::ScanSeverity::Warning))
            .count();

        // Build summary line
        let mut summary_parts = Vec::new();
        if file_errors > 0 {
            summary_parts.push(format!("{file_errors} error(s)"));
        }
        if file_warnings > 0 {
            summary_parts.push(format!("{file_warnings} warning(s)"));
        }
        let summary_suffix = if summary_parts.is_empty() {
            String::new()
        } else {
            format!(" - {}", summary_parts.join(", "))
        };

        println!("<details>");
        println!("<summary><code>{file}</code>{summary_suffix}</summary>\n");

        for finding in findings {
            if shown >= limit {
                break;
            }

            let severity_badge = match finding.severity {
                crate::scan::ScanSeverity::Error => ":x:",
                crate::scan::ScanSeverity::Warning => ":warning:",
                crate::scan::ScanSeverity::Info => ":information_source:",
            };

            let decision_str = match finding.decision {
                crate::scan::ScanDecision::Deny => "DENY",
                crate::scan::ScanDecision::Warn => "WARN",
                crate::scan::ScanDecision::Allow => "ALLOW",
            };

            let location = finding.col.map_or_else(
                || finding.line.to_string(),
                |col| format!("{}:{col}", finding.line),
            );

            // Truncate command for readability
            let cmd_preview = truncate_for_markdown(&finding.extracted_command, truncate);

            println!("{severity_badge} **{decision_str}** at line {location}");
            println!("```");
            println!("{cmd_preview}");
            println!("```");

            if let Some(ref rule_id) = finding.rule_id {
                println!("- **Rule:** `{rule_id}`");
            }
            if let Some(ref reason) = finding.reason {
                println!("- **Reason:** {reason}");
            }
            if let Some(ref suggestion) = finding.suggestion {
                println!("- :bulb: **Suggestion:** {suggestion}");
            }
            println!();

            shown += 1;
        }

        println!("</details>\n");
    }

    if shown < total_findings {
        println!("*Showing {shown} of {total_findings} findings. Use `--top 0` to show all.*\n");
    }

    print_scan_markdown_summary(report);
}

/// Print markdown summary section.
fn print_scan_markdown_summary(report: &crate::scan::ScanReport) {
    println!("---\n");
    println!("### Summary\n");
    println!("| Metric | Value |");
    println!("|--------|-------|");
    println!("| Files scanned | {} |", report.summary.files_scanned);
    println!("| Files skipped | {} |", report.summary.files_skipped);
    println!(
        "| Commands extracted | {} |",
        report.summary.commands_extracted
    );
    println!("| Total findings | {} |", report.summary.findings_total);

    if let Some(elapsed_ms) = report.summary.elapsed_ms {
        println!("| Elapsed | {elapsed_ms} ms |");
    }

    if report.summary.max_findings_reached {
        println!("\n:warning: *Max findings limit reached, scan stopped early.*");
    }
}

/// Truncate a string for markdown display, respecting char boundaries.
fn truncate_for_markdown(s: &str, max_len: usize) -> String {
    if max_len == 0 || s.len() <= max_len {
        return s.to_string();
    }

    // Find a safe truncation point (char boundary)
    let mut end = max_len;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }

    if end == 0 {
        return "...".to_string();
    }

    format!("{}...", &s[..end])
}

/// Handle the `dcg explain` subcommand.
///
/// Shows a detailed decision trace for why a command would be allowed or denied.
/// Currently wraps the evaluator result; full tracing integration is future work.
#[allow(clippy::needless_pass_by_value)] // Value consumed from CLI args
fn handle_explain(
    config: &Config,
    command: &str,
    format: ExplainFormat,
    extra_packs: Option<Vec<String>>,
) {
    use crate::trace::{MatchInfo, TraceCollector, TraceDetails};

    // Build effective config with extra packs if specified
    let effective_config = extra_packs.map_or_else(
        || config.clone(),
        |packs| {
            let mut modified = config.clone();
            modified.packs.enabled.extend(packs);
            modified
        },
    );

    // Get enabled packs and collect keywords
    let enabled_packs = effective_config.enabled_pack_ids();
    let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    let heredoc_settings = effective_config.heredoc_settings();
    let compiled_overrides = effective_config.overrides.compile();
    let allowlists = crate::LayeredAllowlist::default();

    // Start tracing
    let mut collector = TraceCollector::new(command);

    // Evaluate with timing
    collector.begin_step();
    let result = evaluate_command_with_pack_order(
        command,
        &enabled_keywords,
        &ordered_packs,
        &compiled_overrides,
        &allowlists,
        &heredoc_settings,
    );
    collector.end_step(
        "full_evaluation",
        TraceDetails::KeywordGating {
            quick_rejected: result.decision == EvaluationDecision::Allow
                && result.pattern_info.is_none(),
            keywords_checked: enabled_keywords.iter().map(|s| (*s).to_string()).collect(),
            first_match: result.pattern_info.as_ref().and_then(|p| p.pack_id.clone()),
        },
    );
    collector.set_budget_skip(result.skipped_due_to_budget);

    // Add match info if present
    if let Some(ref pattern) = result.pattern_info {
        let rule_id = pattern
            .pack_id
            .as_ref()
            .zip(pattern.pattern_name.as_ref())
            .map(|(pack, name)| format!("{pack}:{name}"));
        collector.set_match(MatchInfo {
            rule_id,
            pack_id: pattern.pack_id.clone(),
            pattern_name: pattern.pattern_name.clone(),
            severity: pattern.severity,
            reason: pattern.reason.clone(),
            source: pattern.source,
            match_start: pattern.matched_span.map(|s| s.start),
            match_end: pattern.matched_span.map(|s| s.end),
            matched_text_preview: pattern.matched_text_preview.clone(),
        });
    }

    // Finish and get trace
    let trace = collector.finish(result.decision);

    // Format and print based on selected format
    match format {
        ExplainFormat::Pretty => {
            let output = trace.format_pretty(colored::control::SHOULD_COLORIZE.should_colorize());
            println!("{output}");
        }
        ExplainFormat::Compact => {
            println!("{}", trace.format_compact(None));
        }
        ExplainFormat::Json => {
            let json_output = trace.to_json_output();
            let json = serde_json::to_string_pretty(&json_output)
                .unwrap_or_else(|e| format!("{{\"error\": \"JSON serialization failed: {e}\"}}"));
            println!("{json}");
        }
    }
}

// =============================================================================
// Corpus command implementation
// =============================================================================

/// A single test case loaded from the corpus.
#[derive(Debug, serde::Deserialize)]
struct CorpusTestCase {
    description: String,
    command: String,
    expected: String,
    #[serde(default)]
    rule_id: Option<String>,
}

/// A corpus file containing multiple test cases.
#[derive(Debug, serde::Deserialize)]
struct CorpusFile {
    #[serde(rename = "case")]
    cases: Vec<CorpusTestCase>,
}

/// Category of test cases, determines pass/fail logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum CorpusCategory {
    TruePositives,
    FalsePositives,
    BypassAttempts,
    EdgeCases,
}

impl CorpusCategory {
    fn from_dir_name(name: &str) -> Option<Self> {
        match name {
            "true_positives" => Some(Self::TruePositives),
            "false_positives" => Some(Self::FalsePositives),
            "bypass_attempts" => Some(Self::BypassAttempts),
            "edge_cases" => Some(Self::EdgeCases),
            _ => None,
        }
    }
}

impl std::fmt::Display for CorpusCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruePositives => write!(f, "true_positives"),
            Self::FalsePositives => write!(f, "false_positives"),
            Self::BypassAttempts => write!(f, "bypass_attempts"),
            Self::EdgeCases => write!(f, "edge_cases"),
        }
    }
}

/// Result of running a single corpus test case.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct CorpusTestResult {
    /// Unique test ID (<file:index>)
    id: String,
    /// Category of the test
    category: CorpusCategory,
    /// Source file (relative path)
    file: String,
    /// Test description
    description: String,
    /// Command that was tested
    command: String,
    /// Expected decision
    expected: String,
    /// Actual decision
    actual: String,
    /// Whether the test passed
    passed: bool,
    /// Expected rule ID (if specified)
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_rule_id: Option<String>,
    /// Actual rule ID that matched
    #[serde(skip_serializing_if = "Option::is_none")]
    actual_rule_id: Option<String>,
    /// Pack ID that matched
    #[serde(skip_serializing_if = "Option::is_none")]
    pack_id: Option<String>,
    /// Pattern name that matched
    #[serde(skip_serializing_if = "Option::is_none")]
    pattern_name: Option<String>,
    /// Match source (pack, allowlist, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    match_source: Option<String>,
    /// Whether command was quick-rejected
    quick_rejected: bool,
    /// Evaluation duration in microseconds
    duration_us: u64,
}

/// Category statistics.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct CategoryStats {
    total: usize,
    passed: usize,
    failed: usize,
}

/// Summary statistics for the corpus run.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct CorpusSummary {
    by_decision: std::collections::HashMap<String, usize>,
    by_pack: std::collections::HashMap<String, usize>,
    by_category: std::collections::HashMap<String, CategoryStats>,
}

/// Full corpus output structure.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct CorpusOutput {
    schema_version: u32,
    generated_at: String,
    binary_version: String,
    corpus_dir: String,
    total_cases: usize,
    total_passed: usize,
    total_failed: usize,
    summary: CorpusSummary,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cases: Vec<CorpusTestResult>,
}

/// Load and run corpus tests, returning structured output.
fn run_corpus(
    config: &Config,
    corpus_dir: &std::path::Path,
    category_filter: Option<&str>,
) -> CorpusOutput {
    let mut results = Vec::new();
    let mut summary = CorpusSummary {
        by_decision: std::collections::HashMap::new(),
        by_pack: std::collections::HashMap::new(),
        by_category: std::collections::HashMap::new(),
    };

    let categories = ["true_positives", "false_positives", "bypass_attempts", "edge_cases"];

    for category_name in categories {
        // Apply category filter if specified
        if let Some(filter) = category_filter {
            if category_name != filter {
                continue;
            }
        }

        let category_dir = corpus_dir.join(category_name);
        if !category_dir.exists() {
            continue;
        }

        let category = match CorpusCategory::from_dir_name(category_name) {
            Some(c) => c,
            None => continue,
        };

        // Initialize category stats
        summary
            .by_category
            .entry(category_name.to_string())
            .or_default();

        // Read all TOML files in the category directory (sorted for deterministic order)
        let entries = match std::fs::read_dir(&category_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        // Collect and sort file paths for deterministic ordering
        let mut file_paths: Vec<_> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "toml"))
            .collect();
        file_paths.sort();

        for path in file_paths {
            // Note: extension check already done in filter above
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Warning: Failed to read {}: {e}", path.display());
                    continue;
                }
            };

            let corpus_file: CorpusFile = match toml::from_str(&content) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Warning: Failed to parse {}: {e}", path.display());
                    continue;
                }
            };

            let file_name = path
                .strip_prefix(corpus_dir)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();

            for (idx, case) in corpus_file.cases.into_iter().enumerate() {
                let result = run_single_corpus_test(config, &case, category, &file_name, idx);

                // Update summary stats
                *summary.by_decision.entry(result.actual.clone()).or_default() += 1;
                if let Some(ref pack) = result.pack_id {
                    *summary.by_pack.entry(pack.clone()).or_default() += 1;
                }

                let cat_stats = summary
                    .by_category
                    .entry(category_name.to_string())
                    .or_default();
                cat_stats.total += 1;
                if result.passed {
                    cat_stats.passed += 1;
                } else {
                    cat_stats.failed += 1;
                }

                results.push(result);
            }
        }
    }

    // Sort results by ID for deterministic output
    results.sort_by(|a, b| a.id.cmp(&b.id));

    let total_passed = results.iter().filter(|r| r.passed).count();
    let total_failed = results.len() - total_passed;

    CorpusOutput {
        schema_version: 1,
        generated_at: chrono::Utc::now().to_rfc3339(),
        binary_version: env!("CARGO_PKG_VERSION").to_string(),
        corpus_dir: corpus_dir.to_string_lossy().to_string(),
        total_cases: results.len(),
        total_passed,
        total_failed,
        summary,
        cases: results,
    }
}

/// Run a single corpus test case through the evaluator.
fn run_single_corpus_test(
    config: &Config,
    case: &CorpusTestCase,
    category: CorpusCategory,
    file_name: &str,
    index: usize,
) -> CorpusTestResult {
    use std::time::Instant;

    // Build config with pack from rule_id if needed
    let mut effective_config = config.clone();
    if let Some(ref rule_id) = case.rule_id {
        if let Some((pack_id, _)) = rule_id.split_once(':') {
            if !pack_id.starts_with("core") && !effective_config.packs.enabled.contains(&pack_id.to_string()) {
                effective_config.packs.enabled.push(pack_id.to_string());
            }
        }
    }

    let enabled_packs = effective_config.enabled_pack_ids();
    let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    let compiled_overrides = effective_config.overrides.compile();
    let allowlists = crate::LayeredAllowlist::default();
    let heredoc_settings = effective_config.heredoc_settings();

    // Time the evaluation
    let start = Instant::now();
    let result = evaluate_command_with_pack_order(
        &case.command,
        &enabled_keywords,
        &ordered_packs,
        &compiled_overrides,
        &allowlists,
        &heredoc_settings,
    );
    let duration_us = start.elapsed().as_micros() as u64;

    let actual = match result.decision {
        EvaluationDecision::Allow => "allow",
        EvaluationDecision::Deny => "deny",
    };

    // Extract pattern info
    let (pack_id, pattern_name, actual_rule_id, match_source) = result
        .pattern_info
        .as_ref()
        .map_or((None, None, None, None), |info| {
            let pack = info.pack_id.clone();
            let pattern = info.pattern_name.clone();
            let rule = pack
                .as_ref()
                .zip(pattern.as_ref())
                .map(|(p, n)| format!("{p}:{n}"));
            let source = Some(format!("{:?}", info.source).to_lowercase());
            (pack, pattern, rule, source)
        });

    // Determine if test passed based on category
    let passed = match category {
        CorpusCategory::TruePositives | CorpusCategory::BypassAttempts => actual == "deny",
        CorpusCategory::FalsePositives => actual == "allow",
        CorpusCategory::EdgeCases => true, // Any decision is fine (didn't crash)
    };

    // Check if quick-rejected (allowed without pattern match)
    let quick_rejected = actual == "allow" && result.pattern_info.is_none();

    CorpusTestResult {
        id: format!("{file_name}:{index}"),
        category,
        file: file_name.to_string(),
        description: case.description.clone(),
        command: case.command.clone(),
        expected: case.expected.clone(),
        actual: actual.to_string(),
        passed,
        expected_rule_id: case.rule_id.clone(),
        actual_rule_id,
        pack_id,
        pattern_name,
        match_source,
        quick_rejected,
        duration_us,
    }
}

/// Handle the `dcg corpus` command.
fn handle_corpus_command(
    config: &Config,
    cmd: CorpusCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    // Run corpus tests
    let mut output = run_corpus(config, &cmd.dir, cmd.category.as_deref());

    // Handle baseline diffing BEFORE filtering/clearing (need full results for comparison)
    if let Some(ref baseline_path) = cmd.baseline {
        let baseline_content = std::fs::read_to_string(baseline_path)?;
        let baseline: CorpusOutput = serde_json::from_str(&baseline_content)?;

        // Compare results
        let diffs = diff_corpus_outputs(&baseline, &output);

        if !diffs.is_empty() {
            eprintln!("{}", "Baseline mismatch!".red().bold());
            for diff in &diffs {
                eprintln!("  {diff}");
            }
            return Err(format!("{} differences from baseline", diffs.len()).into());
        } else if cmd.format == CorpusFormat::Pretty {
            println!("{}", "Baseline matches!".green().bold());
        }
    }

    // Filter to failures only if requested
    if cmd.failures_only {
        output.cases.retain(|r| !r.passed);
    }

    // Clear cases if summary only
    if cmd.summary_only {
        output.cases.clear();
    }

    // Format output
    let output_str = match cmd.format {
        CorpusFormat::Json => serde_json::to_string_pretty(&output)?,
        CorpusFormat::Pretty => format_corpus_pretty(&output),
    };

    // Write output
    if let Some(ref output_path) = cmd.output {
        std::fs::write(output_path, &output_str)?;
        if cmd.format == CorpusFormat::Pretty {
            println!("Output written to {}", output_path.display());
        }
    } else {
        println!("{output_str}");
    }

    // Exit with error if any tests failed
    if output.total_failed > 0 && cmd.baseline.is_none() {
        return Err(format!("{} test(s) failed", output.total_failed).into());
    }

    Ok(())
}

/// Compare two corpus outputs and return differences.
fn diff_corpus_outputs(baseline: &CorpusOutput, current: &CorpusOutput) -> Vec<String> {
    let mut diffs = Vec::new();

    // Build lookup maps by ID
    let baseline_map: std::collections::HashMap<_, _> =
        baseline.cases.iter().map(|c| (c.id.as_str(), c)).collect();
    let current_map: std::collections::HashMap<_, _> =
        current.cases.iter().map(|c| (c.id.as_str(), c)).collect();

    // Check for missing cases
    for id in baseline_map.keys() {
        if !current_map.contains_key(id) {
            diffs.push(format!("REMOVED: {id}"));
        }
    }

    // Check for new cases
    for id in current_map.keys() {
        if !baseline_map.contains_key(id) {
            diffs.push(format!("ADDED: {id}"));
        }
    }

    // Check for changed results
    for (id, current_case) in &current_map {
        if let Some(baseline_case) = baseline_map.get(id) {
            if current_case.actual != baseline_case.actual {
                diffs.push(format!(
                    "CHANGED: {id} - decision: {} -> {}",
                    baseline_case.actual, current_case.actual
                ));
            }
            if current_case.actual_rule_id != baseline_case.actual_rule_id {
                diffs.push(format!(
                    "CHANGED: {id} - rule: {:?} -> {:?}",
                    baseline_case.actual_rule_id, current_case.actual_rule_id
                ));
            }
        }
    }

    diffs
}

/// Format corpus output for human-readable display.
fn format_corpus_pretty(output: &CorpusOutput) -> String {
    use colored::Colorize;

    let mut result = String::new();
    let colorize = colored::control::SHOULD_COLORIZE.should_colorize();

    // Header
    result.push_str(&format!(
        "{}\n\n",
        if colorize {
            "dcg corpus".green().bold().to_string()
        } else {
            "dcg corpus".to_string()
        }
    ));

    result.push_str(&format!("Corpus: {}\n", output.corpus_dir));
    result.push_str(&format!("Version: {}\n", output.binary_version));
    result.push_str(&format!("Generated: {}\n\n", output.generated_at));

    // Summary
    result.push_str(&format!(
        "{}\n",
        if colorize {
            "=== Summary ===".blue().bold().to_string()
        } else {
            "=== Summary ===".to_string()
        }
    ));

    result.push_str(&format!(
        "Total: {} ({} passed, {} failed)\n\n",
        output.total_cases, output.total_passed, output.total_failed
    ));

    // By category (sorted for deterministic output)
    result.push_str("By Category:\n");
    let mut categories: Vec<_> = output.summary.by_category.iter().collect();
    categories.sort_by_key(|(k, _)| *k);
    for (cat, stats) in categories {
        let status = if stats.failed == 0 { "OK" } else { "FAIL" };
        let status_str = if colorize {
            if stats.failed == 0 {
                status.green().to_string()
            } else {
                status.red().to_string()
            }
        } else {
            status.to_string()
        };
        result.push_str(&format!(
            "  {}: {}/{} [{}]\n",
            cat, stats.passed, stats.total, status_str
        ));
    }
    result.push('\n');

    // By decision (sorted for deterministic output)
    result.push_str("By Decision:\n");
    let mut decisions: Vec<_> = output.summary.by_decision.iter().collect();
    decisions.sort_by_key(|(k, _)| *k);
    for (decision, count) in decisions {
        result.push_str(&format!("  {decision}: {count}\n"));
    }
    result.push('\n');

    // By pack (top 10)
    result.push_str("By Pack (top 10):\n");
    let mut packs: Vec<_> = output.summary.by_pack.iter().collect();
    packs.sort_by(|a, b| b.1.cmp(a.1));
    for (pack, count) in packs.iter().take(10) {
        result.push_str(&format!("  {pack}: {count}\n"));
    }
    result.push('\n');

    // Failed tests
    let failures: Vec<_> = output.cases.iter().filter(|c| !c.passed).collect();
    if !failures.is_empty() {
        result.push_str(&format!(
            "{}\n",
            if colorize {
                "=== Failures ===".red().bold().to_string()
            } else {
                "=== Failures ===".to_string()
            }
        ));

        for case in failures {
            result.push_str(&format!(
                "  {} - {}\n",
                if colorize {
                    "FAIL".red().to_string()
                } else {
                    "FAIL".to_string()
                },
                case.description
            ));
            result.push_str(&format!("    ID: {}\n", case.id));
            result.push_str(&format!("    Command: {}\n", case.command));
            result.push_str(&format!(
                "    Expected: {}, Actual: {}\n",
                case.expected, case.actual
            ));
            if let Some(ref rule) = case.actual_rule_id {
                result.push_str(&format!("    Rule: {rule}\n"));
            }
            result.push('\n');
        }
    }

    result
}

/// Check installation, configuration, and hook registration
#[allow(clippy::too_many_lines, clippy::unnecessary_unwrap)]
fn doctor(fix: bool, format: DoctorFormat) {
    use colored::Colorize;

    // For now, ignore format parameter - only pretty output supported
    let _ = format;

    println!("{}", "dcg doctor".green().bold());
    println!();

    let mut issues = 0;
    let mut fixed = 0;

    // Check 1: Binary in PATH
    print!("Checking binary in PATH... ");
    if which_dcg().is_some() {
        println!("{}", "OK".green());
    } else {
        println!("{}", "NOT FOUND".red());
        issues += 1;
        println!("  dcg binary not found in PATH");
        println!("  Run the install script or add to PATH manually");
    }

    // Check 2: Claude Code settings file exists
    print!("Checking Claude Code settings... ");
    let settings_path = claude_settings_path();
    if settings_path.exists() {
        println!("{}", "OK".green());
    } else {
        println!("{}", "NOT FOUND".yellow());
        println!("  ~/.claude/settings.json not found");
        println!("  This is normal if Claude Code hasn't been configured yet");
    }

    // Check 3: Hook wiring (expanded diagnostics)
    print!("Checking hook wiring... ");
    let hook_diag = diagnose_hook_wiring();

    if !hook_diag.settings_exists {
        println!("{}", "SKIPPED".yellow());
        println!("  No settings file to check");
    } else if let Some(ref err) = hook_diag.settings_error {
        println!("{}", "ERROR".red());
        issues += 1;
        println!("  {err}");
        println!("  → Fix the settings.json file or reinstall Claude Code");
    } else if hook_diag.dcg_hook_count == 0 {
        println!("{}", "NOT REGISTERED".red());
        issues += 1;
        if fix {
            println!("  Attempting to register hook...");
            if install_hook(false).is_ok() {
                println!("  {}", "Fixed!".green());
                fixed += 1;
            } else {
                println!("  {}", "Failed to fix".red());
            }
        } else {
            println!("  → Run 'dcg install' to register the hook");
        }
    } else if hook_diag.dcg_hook_count > 1 {
        println!("{}", "WARNING".yellow());
        println!(
            "  Found {} dcg hook entries (expected 1)",
            hook_diag.dcg_hook_count
        );
        println!("  → Run 'dcg uninstall && dcg install' to fix duplicates");
    } else if !hook_diag.wrong_matcher_hooks.is_empty() {
        println!("{}", "MISCONFIGURED".red());
        issues += 1;
        println!(
            "  Hook registered with wrong matcher: {:?}",
            hook_diag.wrong_matcher_hooks
        );
        println!("  → dcg must be a Bash hook, not other tool types");
        println!("  → Run 'dcg uninstall && dcg install' to fix");
    } else if !hook_diag.missing_executable_hooks.is_empty() {
        println!("{}", "BROKEN".red());
        issues += 1;
        for path in &hook_diag.missing_executable_hooks {
            println!("  Hook points to missing executable: {path}");
        }
        println!("  → Run 'dcg uninstall && dcg install' to fix");
    } else {
        println!("{}", "OK".green());
    }

    // Check 4: Config validation (expanded diagnostics)
    print!("Checking configuration... ");
    let config_diag = validate_config_diagnostics();

    match &config_diag.config_path {
        None => {
            println!("{}", "USING DEFAULTS".yellow());
            println!("  No config file found, using built-in defaults");
            if fix {
                let config_path = config_path();
                if config_path.exists() {
                    // File exists but wasn't loaded - could be empty, unreadable, or invalid
                    println!(
                        "  {} exists but wasn't loaded (check permissions/format)",
                        config_path.display()
                    );
                    issues += 1;
                } else {
                    println!("  Creating default config...");
                    if let Some(parent) = config_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    match std::fs::write(&config_path, Config::generate_sample_config()) {
                        Ok(()) => {
                            println!("  {} Created: {}", "Fixed!".green(), config_path.display());
                            fixed += 1;
                        }
                        Err(e) => {
                            println!("  {} Failed to create config: {e}", "Error".red());
                        }
                    }
                }
            } else {
                println!("  → Run 'dcg init -o ~/.config/dcg/config.toml' to create one");
            }
        }
        Some(path) if config_diag.parse_error.is_some() => {
            println!("{}", "INVALID".red());
            issues += 1;
            println!("  Config: {}", path.display());
            if let Some(ref err) = config_diag.parse_error {
                println!("  {err}");
            }
            println!("  → Fix the TOML syntax error in your config file");
        }
        Some(path) => {
            if config_diag.has_errors() || config_diag.has_warnings() {
                println!("{}", "WARNING".yellow());
                println!("  Config: {}", path.display());
                if !config_diag.unknown_packs.is_empty() {
                    println!("  Unknown pack IDs: {:?}", config_diag.unknown_packs);
                    println!("  → Run 'dcg packs list' to see available packs");
                }
                if !config_diag.invalid_override_patterns.is_empty() {
                    println!("  Invalid override patterns:");
                    for (pattern, error) in &config_diag.invalid_override_patterns {
                        println!("    - \"{pattern}\": {error}");
                    }
                    println!("  → Fix the regex patterns in [overrides] section");
                }
            } else {
                println!("{} ({})", "OK".green(), path.display());
            }
        }
    }

    // Check 5: Pattern packs
    print!("Checking pattern packs... ");
    let config = Config::load();
    let enabled = config.enabled_pack_ids();
    println!("{} ({} enabled)", "OK".green(), enabled.len());

    // Check 6: Smoke test
    print!("Running smoke test... ");
    if run_smoke_test() {
        println!("{}", "OK".green());
    } else {
        println!("{}", "FAILED".red());
        issues += 1;
        println!("  Evaluator smoke test failed");
        println!("  → This may indicate a bug; please report it");
    }

    // Check 7: Observe mode status
    print!("Checking observe mode... ");
    if let Some(observe_until) = config.policy().observe_until.as_ref() {
        let now = chrono::Utc::now();
        if let Some(until) = observe_until.parsed_utc() {
            if &now < until {
                // Observe window is active
                let remaining = *until - now;
                let days = remaining.num_days();
                println!("{}", "ACTIVE".yellow());
                println!(
                    "  Observe mode enabled until: {}",
                    until.format("%Y-%m-%d %H:%M UTC")
                );
                if days > 0 {
                    println!("  {days} days remaining");
                } else {
                    let hours = remaining.num_hours();
                    println!("  {hours} hours remaining");
                }
                println!("  Non-critical rules are using WARN instead of DENY");
                println!("  → This is expected during rollout");
            } else {
                // Observe window has expired
                println!("{}", "EXPIRED".yellow().bold());
                issues += 1;
                println!(
                    "  Observe mode expired: {}",
                    until.format("%Y-%m-%d %H:%M UTC")
                );
                println!(
                    "  {} DCG is now enforcing normal severity defaults",
                    "→".bold()
                );
                println!("  To acknowledge and remove the expired setting:");
                println!("    1. Edit your config file");
                println!("    2. Remove or update the 'observe_until' line in [policy]");
                println!();
                println!("  Or to extend the observe window:");
                println!(
                    "    observe_until = \"{}\"",
                    (now + chrono::Duration::days(30)).format("%Y-%m-%dT%H:%M:%SZ")
                );
            }
        } else {
            // observe_until set but couldn't parse timestamp
            println!("{}", "INVALID".red());
            issues += 1;
            println!(
                "  observe_until value could not be parsed: {}",
                &**observe_until
            );
            println!("  → Use ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ");
        }
    } else if config.policy().default_mode.is_some() {
        // No observe_until but default_mode is set (permanent warn/log mode)
        let mode = config.policy().default_mode.unwrap();
        if matches!(
            mode,
            crate::config::PolicyMode::Warn | crate::config::PolicyMode::Log
        ) {
            println!("{}", "PERMANENT".yellow());
            println!("  policy.default_mode = {mode:?} (no expiration set)");
            println!("  Non-critical rules will always use {mode:?} mode");
            println!("  → Consider adding observe_until for time-limited rollout");
        } else {
            println!("{}", "OK".green());
            println!("  Enforcing normal policy (default_mode = {mode:?})");
        }
    } else {
        println!("{}", "OK".green());
    }

    // Check 8: Allowlist discovery + validation
    print!("Checking allowlist entries... ");
    let allowlist_diag = diagnose_allowlists();
    if allowlist_diag.total_errors > 0 {
        println!("{}", "INVALID".red());
        issues += allowlist_diag.total_errors;
        for msg in &allowlist_diag.error_messages {
            println!("  {msg}");
        }
        println!("  → Run 'dcg allowlist validate' for details");
    } else if allowlist_diag.total_warnings > 0 {
        println!("{}", "WARNING".yellow());
        for msg in &allowlist_diag.warning_messages {
            println!("  {msg}");
        }
        println!("  → Run 'dcg allowlist validate' for details");
    } else if allowlist_diag.layers_found == 0 {
        println!("{}", "NONE".yellow().dimmed());
        println!("  No allowlist files found (project or user)");
        println!("  → Use 'dcg allow <rule-id> -r \"reason\"' to create one");
    } else {
        println!(
            "{} ({} layer{})",
            "OK".green(),
            allowlist_diag.layers_found,
            if allowlist_diag.layers_found == 1 {
                ""
            } else {
                "s"
            }
        );
    }

    println!();
    if issues == 0 {
        println!("{}", "All checks passed!".green().bold());
    } else if fix && fixed == issues {
        println!("{}", "All issues fixed!".green().bold());
    } else {
        println!(
            "{} issue(s) found{}",
            issues.to_string().red().bold(),
            if fix {
                format!(", {fixed} fixed")
            } else {
                String::new()
            }
        );
    }
}

fn is_dcg_command(cmd: &str) -> bool {
    cmd == "dcg" || cmd.ends_with("/dcg")
}

fn is_dcg_hook_entry(entry: &serde_json::Value) -> bool {
    entry
        .get("matcher")
        .and_then(|m| m.as_str())
        .is_some_and(|m| m == "Bash")
        && entry
            .get("hooks")
            .and_then(|h| h.as_array())
            .is_some_and(|hooks| {
                hooks.iter().any(|hook| {
                    hook.get("command")
                        .and_then(|c| c.as_str())
                        .is_some_and(is_dcg_command)
                })
            })
}

/// Install the dcg hook entry into an in-memory Claude settings JSON value.
///
/// Returns `Ok(true)` when a new hook entry was added, `Ok(false)` when an
/// existing hook was detected and `force == false`.
///
/// # Errors
///
/// Returns an error if the settings JSON is not in the expected format:
/// - root must be an object
/// - `hooks` must be an object (if present)
/// - `hooks.PreToolUse` must be an array (if present)
fn install_dcg_hook_into_settings(
    settings: &mut serde_json::Value,
    force: bool,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Build the hook configuration.
    let hook_config = serde_json::json!({
        "matcher": "Bash",
        "hooks": [{
            "type": "command",
            "command": "dcg"
        }]
    });

    let settings_obj = settings
        .as_object_mut()
        .ok_or("Invalid settings format (expected JSON object)")?;

    let hooks_value = settings_obj
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));

    let hooks_obj = hooks_value
        .as_object_mut()
        .ok_or("Invalid hooks format (expected JSON object)")?;

    let pre_tool_use_value = hooks_obj
        .entry("PreToolUse")
        .or_insert_with(|| serde_json::json!([]));

    let pre_tool_use = pre_tool_use_value
        .as_array_mut()
        .ok_or("Invalid PreToolUse hooks format (expected JSON array)")?;

    let already_installed = pre_tool_use.iter().any(is_dcg_hook_entry);
    if already_installed && !force {
        return Ok(false);
    }

    if force {
        pre_tool_use.retain(|h| !is_dcg_hook_entry(h));
    }

    pre_tool_use.push(hook_config);
    Ok(true)
}

/// Remove the dcg hook entry from an in-memory Claude settings JSON value.
///
/// Returns `Ok(true)` when at least one entry was removed, `Ok(false)` when no
/// dcg hook entry existed.
///
/// # Errors
///
/// Returns an error if `hooks.PreToolUse` exists but is not an array.
fn uninstall_dcg_hook_from_settings(
    settings: &mut serde_json::Value,
) -> Result<bool, Box<dyn std::error::Error>> {
    let Some(hooks) = settings.get_mut("hooks") else {
        return Ok(false);
    };
    let Some(pre_tool_use) = hooks.get_mut("PreToolUse") else {
        return Ok(false);
    };

    let Some(arr) = pre_tool_use.as_array_mut() else {
        return Err("Invalid PreToolUse hooks format (expected JSON array)".into());
    };

    let before = arr.len();
    arr.retain(|h| !is_dcg_hook_entry(h));
    Ok(arr.len() < before)
}

/// Install the dcg hook entry into Claude Code settings.
///
/// This is a wrapper around `install_dcg_hook_into_settings` that handles the
/// file I/O and error reporting.
///
/// # Errors
///
/// Returns an error if the settings file cannot be read, parsed, or written.
fn install_hook(force: bool) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let settings_path = claude_settings_path();

    // Read existing settings or create new
    let mut settings: serde_json::Value = if settings_path.exists() {
        let content = std::fs::read_to_string(&settings_path)?;
        serde_json::from_str(&content)?
    } else {
        // Create parent directory if needed
        if let Some(parent) = settings_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        serde_json::json!({})
    };

    let changed = install_dcg_hook_into_settings(&mut settings, force)?;
    if !changed {
        println!("{}", "Hook already installed!".yellow());
        println!("Use --force to reinstall");
        return Ok(());
    }

    // Write back
    let content = serde_json::to_string_pretty(&settings)?;
    std::fs::write(&settings_path, content)?;

    println!("{}", "Hook installed successfully!".green().bold());
    println!("Settings updated: {}", settings_path.display());
    println!();
    println!(
        "{}",
        "Restart Claude Code for the changes to take effect.".yellow()
    );

    Ok(())
}

/// Remove the dcg hook entry from Claude Code settings.
///
/// This is a wrapper around `uninstall_dcg_hook_from_settings` that handles the
/// file I/O and error reporting.
///
/// # Errors
///
/// Returns an error if the settings file cannot be read, parsed, or written.
fn uninstall_hook(purge: bool) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let settings_path = claude_settings_path();

    if !settings_path.exists() {
        println!("{}", "No Claude Code settings found.".yellow());
        return Ok(());
    }

    // Read existing settings
    let content = std::fs::read_to_string(&settings_path)?;
    let mut settings: serde_json::Value = serde_json::from_str(&content)?;

    // Remove dcg hooks (fail if settings structure is unexpected).
    let removed = uninstall_dcg_hook_from_settings(&mut settings)?;

    if removed {
        // Write back
        let content = serde_json::to_string_pretty(&settings)?;
        std::fs::write(&settings_path, content)?;
        println!("{}", "Hook removed successfully!".green().bold());
    } else {
        println!("{}", "No dcg hook found in settings.".yellow());
    }

    // Purge config files if requested
    if purge {
        let config_dir = config_dir();
        if config_dir.exists() {
            std::fs::remove_dir_all(&config_dir)?;
            println!("Removed configuration directory: {}", config_dir.display());
        }
    }

    println!();
    println!(
        "{}",
        "Restart Claude Code for the changes to take effect.".yellow()
    );

    Ok(())
}

/// Update dcg by re-running the platform installer.
fn self_update(update: UpdateCommand) -> Result<(), Box<dyn std::error::Error>> {
    if cfg!(windows) {
        return self_update_windows(update);
    }

    self_update_unix(update)
}

fn self_update_unix(update: UpdateCommand) -> Result<(), Box<dyn std::error::Error>> {
    let script_url = "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/master/install.sh";
    let mut args: Vec<String> = Vec::new();

    if let Some(version) = update.version {
        args.push("--version".to_string());
        args.push(version);
    }
    if update.system {
        args.push("--system".to_string());
    }
    if update.easy_mode {
        args.push("--easy-mode".to_string());
    }
    if let Some(dest) = update.dest {
        args.push("--dest".to_string());
        args.push(dest.to_string_lossy().into_owned());
    }
    if update.from_source {
        args.push("--from-source".to_string());
    }
    if update.verify {
        args.push("--verify".to_string());
    }
    if update.quiet {
        args.push("--quiet".to_string());
    }
    if update.no_gum {
        args.push("--no-gum".to_string());
    }

    let mut escaped_args = String::new();
    for (idx, arg) in args.iter().enumerate() {
        if idx > 0 {
            escaped_args.push(' ');
        }
        escaped_args.push_str(&shell_escape_posix(arg));
    }

    let command = if escaped_args.is_empty() {
        format!("curl -fsSL {} | bash -s --", shell_escape_posix(script_url))
    } else {
        format!(
            "curl -fsSL {} | bash -s -- {}",
            shell_escape_posix(script_url),
            escaped_args
        )
    };

    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .status()?;

    if !status.success() {
        return Err(format!("Installer failed with status {status}").into());
    }

    Ok(())
}

fn self_update_windows(update: UpdateCommand) -> Result<(), Box<dyn std::error::Error>> {
    if update.system || update.from_source || update.quiet || update.no_gum {
        return Err(
            "Windows updater supports only --version, --dest, --easy-mode, and --verify.".into(),
        );
    }

    let script_url = "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/master/install.ps1";
    let mut args: Vec<String> = Vec::new();

    if let Some(version) = update.version {
        args.push(format!("-Version {}", shell_escape_powershell(&version)));
    }
    if let Some(dest) = update.dest {
        args.push(format!(
            "-Dest {}",
            shell_escape_powershell(&dest.to_string_lossy())
        ));
    }
    if update.easy_mode {
        args.push("-EasyMode".to_string());
    }
    if update.verify {
        args.push("-Verify".to_string());
    }

    let args_str = if args.is_empty() {
        String::new()
    } else {
        format!(" {}", args.join(" "))
    };

    let command = format!(
        "$ErrorActionPreference='Stop'; \
$url={url}; \
$tmp=Join-Path $env:TEMP 'dcg-install.ps1'; \
Invoke-WebRequest -Uri $url -OutFile $tmp; \
& $tmp{args}; \
$code=$LASTEXITCODE; \
Remove-Item $tmp -ErrorAction SilentlyContinue; \
exit $code;",
        url = shell_escape_powershell(script_url),
        args = args_str
    );

    let status = std::process::Command::new("powershell")
        .arg("-NoProfile")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg(command)
        .status()?;

    if !status.success() {
        return Err(format!("Installer failed with status {status}").into());
    }

    Ok(())
}

fn shell_escape_posix(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    let mut escaped = String::from("'");
    for ch in value.chars() {
        if ch == '\'' {
            escaped.push_str("'\\''");
        } else {
            escaped.push(ch);
        }
    }
    escaped.push('\'');
    escaped
}

fn shell_escape_powershell(value: &str) -> String {
    let mut escaped = String::from("'");
    for ch in value.chars() {
        if ch == '\'' {
            escaped.push_str("''");
        } else {
            escaped.push(ch);
        }
    }
    escaped.push('\'');
    escaped
}

/// Get the path to Claude Code settings
fn claude_settings_path() -> std::path::PathBuf {
    dirs::home_dir()
        .unwrap_or_default()
        .join(".claude")
        .join("settings.json")
}

/// Get the path to dcg config directory
fn config_dir() -> std::path::PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".config"))
        .join("dcg")
}

/// Get the path to dcg config file
fn config_path() -> std::path::PathBuf {
    config_dir().join("config.toml")
}

/// Check if dcg is in PATH
fn which_dcg() -> Option<std::path::PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let path = dir.join("dcg");
            if path.is_file() { Some(path) } else { None }
        })
    })
}

/// Check if the hook is registered in Claude Code settings
#[allow(dead_code)]
fn check_hook_registered() -> Result<bool, Box<dyn std::error::Error>> {
    let settings_path = claude_settings_path();
    if !settings_path.exists() {
        return Ok(false);
    }

    let content = std::fs::read_to_string(&settings_path)?;
    let settings: serde_json::Value = serde_json::from_str(&content)?;

    let registered = settings
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(|arr| arr.as_array())
        .is_some_and(|a| a.iter().any(is_dcg_hook_entry));

    Ok(registered)
}

// ============================================================================
// Doctor: expanded diagnostics (git_safety_guard-1gt.7.1)
// NOTE: These diagnostic types are scaffolding for future `dcg doctor` enhancements.
// ============================================================================

/// Detailed hook wiring diagnostics.
#[allow(dead_code)]
#[derive(Debug, Default)]
struct HookDiagnostics {
    /// Settings file exists
    settings_exists: bool,
    /// Settings JSON is valid
    settings_valid: bool,
    /// Error message if settings invalid
    settings_error: Option<String>,
    /// Number of dcg hook entries found
    dcg_hook_count: usize,
    /// Dcg hooks found with wrong matcher (not "Bash")
    wrong_matcher_hooks: Vec<String>,
    /// Dcg hooks pointing to absolute path that doesn't exist
    missing_executable_hooks: Vec<String>,
    /// Other non-dcg hooks in `PreToolUse`
    other_hooks_count: usize,
}

#[allow(dead_code)]
impl HookDiagnostics {
    fn is_healthy(&self) -> bool {
        self.settings_valid
            && self.dcg_hook_count == 1
            && self.wrong_matcher_hooks.is_empty()
            && self.missing_executable_hooks.is_empty()
    }

    fn has_issues(&self) -> bool {
        !self.settings_valid
            || self.dcg_hook_count == 0
            || self.dcg_hook_count > 1
            || !self.wrong_matcher_hooks.is_empty()
            || !self.missing_executable_hooks.is_empty()
    }
}

/// Diagnose hook wiring in detail.
#[allow(dead_code)]
fn diagnose_hook_wiring() -> HookDiagnostics {
    let mut diag = HookDiagnostics::default();
    let settings_path = claude_settings_path();

    if !settings_path.exists() {
        return diag;
    }
    diag.settings_exists = true;

    // Read and parse settings
    let content = match std::fs::read_to_string(&settings_path) {
        Ok(c) => c,
        Err(e) => {
            diag.settings_error = Some(format!("Failed to read settings: {e}"));
            return diag;
        }
    };

    let settings: serde_json::Value = match serde_json::from_str(&content) {
        Ok(s) => s,
        Err(e) => {
            diag.settings_error = Some(format!("Invalid JSON: {e}"));
            return diag;
        }
    };
    diag.settings_valid = true;

    // Check hooks structure
    let Some(hooks) = settings.get("hooks") else {
        return diag;
    };
    let Some(pre_tool_use) = hooks.get("PreToolUse") else {
        return diag;
    };
    let Some(entries) = pre_tool_use.as_array() else {
        diag.settings_error = Some("hooks.PreToolUse is not an array".to_string());
        diag.settings_valid = false;
        return diag;
    };

    // Analyze each entry
    for entry in entries {
        let matcher = entry.get("matcher").and_then(|m| m.as_str());
        let hooks_arr = entry.get("hooks").and_then(|h| h.as_array());

        let Some(hooks_arr) = hooks_arr else {
            continue;
        };

        for hook in hooks_arr {
            let cmd = hook.get("command").and_then(|c| c.as_str());
            if let Some(cmd) = cmd {
                if is_dcg_command(cmd) {
                    diag.dcg_hook_count += 1;

                    // Check matcher
                    if matcher != Some("Bash") {
                        diag.wrong_matcher_hooks
                            .push(matcher.unwrap_or("(none)").to_string());
                    }

                    // Check if absolute path exists
                    if cmd.starts_with('/') && !std::path::Path::new(cmd).exists() {
                        diag.missing_executable_hooks.push(cmd.to_string());
                    }
                } else {
                    diag.other_hooks_count += 1;
                }
            }
        }
    }

    diag
}

/// Config validation diagnostics.
#[allow(dead_code)]
#[derive(Debug, Default)]
struct ConfigDiagnostics {
    /// Config file path (if found)
    config_path: Option<std::path::PathBuf>,
    /// TOML parse error (if any)
    parse_error: Option<String>,
    /// Unknown pack IDs in enabled list
    unknown_packs: Vec<String>,
    /// Override patterns that failed to compile
    invalid_override_patterns: Vec<(String, String)>, // (pattern, error)
}

#[allow(dead_code)]
impl ConfigDiagnostics {
    fn has_errors(&self) -> bool {
        self.parse_error.is_some() || !self.unknown_packs.is_empty()
    }

    fn has_warnings(&self) -> bool {
        !self.invalid_override_patterns.is_empty()
    }
}

/// Validate configuration in detail.
#[allow(dead_code)]
fn validate_config_diagnostics() -> ConfigDiagnostics {
    let mut diag = ConfigDiagnostics::default();

    let cwd = std::env::current_dir().ok();

    // Explicit config path override (highest precedence for doctor diagnostics)
    if let Ok(value) = std::env::var(crate::config::ENV_CONFIG_PATH) {
        let Some(path) = crate::config::resolve_config_path_value(
            &value,
            cwd.as_deref(),
        ) else {
            diag.parse_error = Some("DCG_CONFIG is set but empty".to_string());
            return diag;
        };
        if !path.exists() {
            diag.parse_error = Some(format!(
                "DCG_CONFIG points to a missing file: {}",
                path.display()
            ));
            diag.config_path = Some(path);
            return diag;
        }
        diag.config_path = Some(path);
    }

    // Find default/user/project config path (when DCG_CONFIG isn't set)
    if diag.config_path.is_none() {
        let cfg_path = config_path();
        if cfg_path.exists() {
            diag.config_path = Some(cfg_path);
        } else if let Some(repo_root) = find_repo_root_from_cwd() {
            let project_config = repo_root.join(".dcg.toml");
            if project_config.exists() {
                diag.config_path = Some(project_config);
            }
        }
    }

    // If no config, nothing to validate
    let Some(ref path) = diag.config_path else {
        return diag;
    };

    // Read and parse
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            diag.parse_error = Some(format!("Failed to read: {e}"));
            return diag;
        }
    };

    let config: Config = match toml::from_str(&content) {
        Ok(c) => c,
        Err(e) => {
            diag.parse_error = Some(format!("Invalid TOML: {e}"));
            return diag;
        }
    };

    // Validate pack IDs
    for pack_id in &config.packs.enabled {
        if !is_valid_pack_id(pack_id) {
            diag.unknown_packs.push(pack_id.clone());
        }
    }
    for pack_id in &config.packs.disabled {
        if !is_valid_pack_id(pack_id) {
            diag.unknown_packs.push(pack_id.clone());
        }
    }

    // Validate override patterns
    let compiled = config.overrides.compile();
    for ip in &compiled.invalid_patterns {
        diag.invalid_override_patterns
            .push((ip.pattern.clone(), ip.error.clone()));
    }

    diag
}

/// Check if a pack ID is valid (exists in registry or is a known category).
#[allow(dead_code)]
fn is_valid_pack_id(id: &str) -> bool {
    // Direct pack lookup
    if REGISTRY.get(id).is_some() {
        return true;
    }

    // Check if it's a category prefix (e.g., "containers" enables all containers.*)
    let known_categories = [
        "core",
        "containers",
        "kubernetes",
        "database",
        "cloud",
        "infrastructure",
        "system",
        "strict_git",
        "package_managers",
    ];

    if known_categories.contains(&id) {
        return true;
    }

    // At this point:
    // - id is NOT in REGISTRY (checked above)
    // - id is NOT a bare category name (checked above)
    // Therefore, if id contains a dot (e.g., "containers.fake"), it's invalid
    // because we only accept full pack IDs that exist in REGISTRY.
    false
}

/// Run a quick smoke test to verify the evaluator works.
///
/// Tests both an allow case and a deny case to ensure basic functionality.
#[allow(dead_code)]
fn run_smoke_test() -> bool {
    let config = Config::load();
    let enabled_packs = config.enabled_pack_ids();
    let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    let compiled_overrides = config.overrides.compile();
    let allowlists = crate::LayeredAllowlist::default();
    let heredoc_settings = config.heredoc_settings();

    // Test 1: "git status" should be allowed
    let allow_result = crate::evaluate_command_with_pack_order(
        "git status",
        &enabled_keywords,
        &ordered_packs,
        &compiled_overrides,
        &allowlists,
        &heredoc_settings,
    );
    if !allow_result.is_allowed() {
        return false;
    }

    // Test 2: "git reset --hard" should be denied
    let deny_result = crate::evaluate_command_with_pack_order(
        "git reset --hard",
        &enabled_keywords,
        &ordered_packs,
        &compiled_overrides,
        &allowlists,
        &heredoc_settings,
    );
    if deny_result.is_allowed() {
        return false;
    }

    true
}

// ============================================================================

/// Allowlist validation diagnostics for doctor command.
#[derive(Debug, Default)]
struct AllowlistDiagnostics {
    /// Number of allowlist layers found (project/user)
    layers_found: usize,
    /// Total error count
    total_errors: usize,
    /// Total warning count
    total_warnings: usize,
    /// Error messages to display
    error_messages: Vec<String>,
    /// Warning messages to display
    warning_messages: Vec<String>,
}

/// Diagnose allowlist health across project and user layers.
fn diagnose_allowlists() -> AllowlistDiagnostics {
    use crate::allowlist::{AllowSelector, AllowlistLayer};

    let mut diag = AllowlistDiagnostics::default();

    // Load all allowlists
    let allowlist = crate::allowlist::load_default_allowlists();

    // Check each layer
    for loaded in &allowlist.layers {
        // Skip system layer in doctor (less common)
        if loaded.layer == AllowlistLayer::System {
            continue;
        }

        // Count as found if path exists
        let path = match loaded.layer {
            AllowlistLayer::Project => {
                if let Some(repo_root) = find_repo_root_from_cwd() {
                    repo_root.join(".dcg").join("allowlist.toml")
                } else {
                    continue;
                }
            }
            AllowlistLayer::User => config_dir().join("allowlist.toml"),
            AllowlistLayer::System => continue,
        };

        if !path.exists() {
            continue;
        }

        diag.layers_found += 1;
        let layer_label = loaded.layer.label();

        // Report parse errors
        for err in &loaded.file.errors {
            diag.total_errors += 1;
            diag.error_messages
                .push(format!("{layer_label}: {}", err.message));
        }

        // Check entries
        for (idx, entry) in loaded.file.entries.iter().enumerate() {
            let entry_num = idx + 1;

            // Check for expired entries
            if let Some(expires_at) = &entry.expires_at {
                if is_expired(expires_at) {
                    diag.total_warnings += 1;
                    diag.warning_messages.push(format!(
                        "{layer_label}: entry {entry_num} expired ({expires_at})"
                    ));
                }
            }

            // Check for risky regex patterns without acknowledgement
            if matches!(entry.selector, AllowSelector::RegexPattern(_)) && !entry.risk_acknowledged
            {
                diag.total_warnings += 1;
                diag.warning_messages.push(format!(
                    "{layer_label}: entry {entry_num} uses regex without risk_acknowledged"
                ));
            }

            // Check for overly broad wildcards
            if let AllowSelector::Rule(rule_id) = &entry.selector {
                if rule_id.pack_id == "*" {
                    diag.total_errors += 1;
                    diag.error_messages.push(format!(
                        "{layer_label}: entry {entry_num} uses dangerous global wildcard (*:*)"
                    ));
                } else if rule_id.pattern_name == "*" {
                    diag.total_warnings += 1;
                    diag.warning_messages.push(format!(
                        "{layer_label}: entry {entry_num} uses pack wildcard ({}:*)",
                        rule_id.pack_id
                    ));
                }
            }
        }
    }

    diag
}
// Allowlist CLI implementation
// ============================================================================

use crate::allowlist::{AllowEntry, AllowSelector, AllowlistLayer, RuleId};

/// Resolve which allowlist layer to use based on CLI flags.
///
/// Default: project if in a git repo, otherwise user.
fn resolve_layer(project: bool, user: bool) -> AllowlistLayer {
    if user {
        AllowlistLayer::User
    } else if project {
        AllowlistLayer::Project
    } else {
        // Default: project if we can detect a git repo, otherwise user
        if find_repo_root_from_cwd().is_some() {
            AllowlistLayer::Project
        } else {
            AllowlistLayer::User
        }
    }
}

/// Find the repo root from the current working directory.
fn find_repo_root_from_cwd() -> Option<std::path::PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    crate::config::find_repo_root(&cwd, crate::config::REPO_ROOT_SEARCH_MAX_HOPS)
}

/// Get the path to the allowlist file for a given layer.
fn allowlist_path_for_layer(layer: AllowlistLayer) -> std::path::PathBuf {
    match layer {
        AllowlistLayer::Project => {
            let repo_root = find_repo_root_from_cwd()
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
            repo_root.join(".dcg").join("allowlist.toml")
        }
        AllowlistLayer::User => config_dir().join("allowlist.toml"),
        AllowlistLayer::System => std::path::PathBuf::from("/etc/dcg/allowlist.toml"),
    }
}

/// Handle allowlist subcommand dispatch.
fn handle_allowlist_command(action: AllowlistAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        AllowlistAction::Add {
            rule_id,
            reason,
            project,
            user,
            expires,
            conditions,
        } => {
            let layer = resolve_layer(project, user);
            allowlist_add_rule(&rule_id, &reason, layer, expires.as_deref(), &conditions)?;
        }
        AllowlistAction::AddCommand {
            command,
            reason,
            project,
            user,
            expires,
        } => {
            let layer = resolve_layer(project, user);
            allowlist_add_command(&command, &reason, layer, expires.as_deref())?;
        }
        AllowlistAction::List {
            project,
            user,
            format,
        } => {
            allowlist_list(project, user, format)?;
        }
        AllowlistAction::Remove {
            rule_id,
            project,
            user,
        } => {
            let layer = resolve_layer(project, user);
            allowlist_remove(&rule_id, layer)?;
        }
        AllowlistAction::Validate {
            project,
            user,
            strict,
        } => {
            allowlist_validate(project, user, strict)?;
        }
    }
    Ok(())
}

/// Add a rule to the allowlist.
fn allowlist_add_rule(
    rule_id: &str,
    reason: &str,
    layer: AllowlistLayer,
    expires: Option<&str>,
    conditions: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    // Validate rule ID format
    let parsed_rule = RuleId::parse(rule_id)
        .ok_or_else(|| format!("Invalid rule ID: {rule_id} (expected pack_id:pattern_name)"))?;

    // Validate expiration date format if provided
    if let Some(exp) = expires {
        crate::allowlist::validate_expiration_date(exp)?;
    }

    // Validate condition formats
    for cond in conditions {
        crate::allowlist::validate_condition(cond)?;
    }

    let path = allowlist_path_for_layer(layer);
    let mut doc = load_or_create_allowlist_doc(&path).unwrap();

    // Check for duplicate
    if has_rule_entry(&doc, &parsed_rule) {
        println!(
            "{} Rule {} already exists in {} allowlist",
            "Warning:".yellow(),
            rule_id,
            layer.label()
        );
        return Ok(());
    }

    // Build entry
    let entry = build_rule_entry(&parsed_rule, reason, expires, conditions);
    append_entry(&mut doc, entry);

    // Write back
    write_allowlist(&path, &doc).unwrap();

    println!(
        "{} Added {} to {} allowlist",
        "✓".green(),
        rule_id.cyan(),
        layer.label()
    );
    println!("  File: {}", path.display());

    Ok(())
}

/// Add an exact command to the allowlist.
fn allowlist_add_command(
    command: &str,
    reason: &str,
    layer: AllowlistLayer,
    expires: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    // Validate expiration date format if provided
    if let Some(exp) = expires {
        crate::allowlist::validate_expiration_date(exp)?;
    }

    let path = allowlist_path_for_layer(layer);
    let mut doc = load_or_create_allowlist_doc(&path).unwrap();

    // Check for duplicate
    if has_command_entry(&doc, command) {
        println!(
            "{} Command already exists in {} allowlist",
            "Warning:".yellow(),
            layer.label()
        );
        return Ok(());
    }

    // Build entry
    let entry = build_command_entry(command, reason, expires);
    append_entry(&mut doc, entry);

    // Write back
    write_allowlist(&path, &doc).unwrap();

    println!(
        "{} Added exact command to {} allowlist",
        "✓".green(),
        layer.label()
    );
    println!("  File: {}", path.display());

    Ok(())
}

/// List allowlist entries.
fn allowlist_list(
    project_only: bool,
    user_only: bool,
    format: AllowlistOutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let layers: Vec<AllowlistLayer> = if project_only {
        vec![AllowlistLayer::Project]
    } else if user_only {
        vec![AllowlistLayer::User]
    } else {
        vec![AllowlistLayer::Project, AllowlistLayer::User]
    };

    let mut all_entries: Vec<(AllowlistLayer, std::path::PathBuf, AllowEntry)> = Vec::new();

    // Load all allowlists once (more efficient than loading per-layer)
    let allowlist = crate::allowlist::load_default_allowlists();

    for layer in layers {
        let path = allowlist_path_for_layer(layer);
        if !path.exists() {
            continue;
        }

        for loaded in &allowlist.layers {
            if loaded.layer == layer {
                for entry in &loaded.file.entries {
                    all_entries.push((layer, path.clone(), entry.clone()));
                }
            }
        }
    }

    match format {
        AllowlistOutputFormat::Pretty => {
            if all_entries.is_empty() {
                println!("{}", "No allowlist entries found.".yellow());
                return Ok(());
            }

            println!("{}", "Allowlist entries:".bold());
            println!();

            for (layer, path, entry) in &all_entries {
                let selector_str = match &entry.selector {
                    AllowSelector::Rule(rule_id) => {
                        serde_json::json!({"type": "rule", "value": rule_id.to_string()})
                    }
                    AllowSelector::ExactCommand(cmd) => {
                        serde_json::json!({"type": "exact_command", "value": cmd})
                    }
                    AllowSelector::CommandPrefix(prefix) => {
                        serde_json::json!({"type": "command_prefix", "value": prefix})
                    }
                    AllowSelector::RegexPattern(re) => {
                        serde_json::json!({"type": "pattern", "value": re})
                    }
                };

                println!("  {} [{}]", selector_str, layer.label());
                println!("    Reason: {}", entry.reason);
                if let Some(added_by) = &entry.added_by {
                    println!("    Added by: {added_by}");
                }
                if let Some(added_at) = &entry.added_at {
                    println!("    Added at: {added_at}");
                }
                if let Some(expires_at) = &entry.expires_at {
                    let expired = is_expired(expires_at);
                    let status = if expired {
                        "EXPIRED".red().to_string()
                    } else {
                        expires_at.clone()
                    };
                    println!("    Expires: {status}");
                }
                println!("    File: {}", path.display());
                println!();
            }
        }
        AllowlistOutputFormat::Json => {
            let json_entries: Vec<serde_json::Value> = all_entries
                .iter()
                .map(|(layer, path, entry)| {
                    let selector = match &entry.selector {
                        AllowSelector::Rule(rule_id) => {
                            serde_json::json!({"type": "rule", "value": rule_id.to_string()})
                        }
                        AllowSelector::ExactCommand(cmd) => {
                            serde_json::json!({"type": "exact_command", "value": cmd})
                        }
                        AllowSelector::CommandPrefix(prefix) => {
                            serde_json::json!({"type": "command_prefix", "value": prefix})
                        }
                        AllowSelector::RegexPattern(re) => {
                            serde_json::json!({"type": "pattern", "value": re})
                        }
                    };
                    serde_json::json!({
                        "layer": layer.label(),
                        "path": path.display().to_string(),
                        "selector": selector,
                        "reason": entry.reason,
                        "added_by": entry.added_by,
                        "added_at": entry.added_at,
                        "expires_at": entry.expires_at,
                    })
                })
                .collect();

            println!("{}", serde_json::to_string_pretty(&json_entries)?);
        }
    }

    Ok(())
}

/// Remove a rule from the allowlist.
fn allowlist_remove(
    rule_id: &str,
    layer: AllowlistLayer,
) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let parsed_rule = RuleId::parse(rule_id)
        .ok_or_else(|| format!("Invalid rule ID: {rule_id} (expected pack_id:pattern_name)"))?;

    let path = allowlist_path_for_layer(layer);
    if !path.exists() {
        println!(
            "{} No {} allowlist file found at {}",
            "Warning:".yellow(),
            layer.label(),
            path.display()
        );
        return Ok(());
    }

    let mut doc = load_or_create_allowlist_doc(&path).unwrap();

    let removed = remove_rule_entry(&mut doc, &parsed_rule);
    if !removed {
        println!(
            "{} Rule {} not found in {} allowlist",
            "Warning:".yellow(),
            rule_id,
            layer.label()
        );
        return Ok(());
    }

    write_allowlist(&path, &doc).unwrap();

    println!(
        "{} Removed {} from {} allowlist",
        "✓".green(),
        rule_id.cyan(),
        layer.label()
    );

    Ok(())
}

/// Validate allowlist entries.
fn allowlist_validate(
    project_only: bool,
    user_only: bool,
    strict: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let layers: Vec<AllowlistLayer> = if project_only {
        vec![AllowlistLayer::Project]
    } else if user_only {
        vec![AllowlistLayer::User]
    } else {
        vec![AllowlistLayer::Project, AllowlistLayer::User]
    };

    let mut errors = 0;
    let mut warnings = 0;

    // Load all allowlists once (more efficient than loading per-layer)
    let allowlist = crate::allowlist::load_default_allowlists();

    for layer in layers {
        let path = allowlist_path_for_layer(layer);
        if !path.exists() {
            continue;
        }

        println!("{} allowlist: {}", layer.label().bold(), path.display());

        for loaded in &allowlist.layers {
            if loaded.layer != layer {
                continue;
            }

            // Report parse errors
            for err in &loaded.file.errors {
                println!("  {} {}", "ERROR:".red(), err.message);
                errors += 1;
            }

            // Check entries
            for (idx, entry) in loaded.file.entries.iter().enumerate() {
                // Check for expired entries
                if let Some(expires_at) = &entry.expires_at {
                    if is_expired(expires_at) {
                        println!(
                            "  {} Entry {} is expired ({})",
                            "WARNING:".yellow(),
                            idx + 1,
                            expires_at
                        );
                        warnings += 1;
                    }
                }

                // Check for risky regex patterns without acknowledgement
                if matches!(entry.selector, AllowSelector::RegexPattern(_))
                    && !entry.risk_acknowledged
                {
                    println!(
                        "  {} Entry {} uses regex pattern without risk_acknowledged=true",
                        "WARNING:".yellow(),
                        idx + 1
                    );
                    warnings += 1;
                }

                // Check for overly broad wildcards
                if let AllowSelector::Rule(rule_id) = &entry.selector {
                    if rule_id.pack_id == "*" {
                        println!(
                            "  {} Entry {} uses global wildcard pack (dangerous)",
                            "ERROR:".red(),
                            idx + 1
                        );
                        errors += 1;
                    } else if rule_id.pattern_name == "*" {
                        println!(
                            "  {} Entry {} uses pack wildcard ({}:*)",
                            "WARNING:".yellow(),
                            idx + 1,
                            rule_id.pack_id
                        );
                        warnings += 1;
                    }
                }
            }
        }

        println!();
    }

    let total_issues = if strict { errors + warnings } else { errors };

    if total_issues == 0 {
        println!("{}", "All allowlist entries are valid.".green());
        Ok(())
    } else {
        let msg = format!(
            "{} error(s), {} warning(s)",
            errors.to_string().red(),
            warnings.to_string().yellow()
        );
        println!("{msg}");
        Err(format!("Validation failed: {errors} error(s), {warnings} warning(s)").into())
    }
}

// ============================================================================
// TOML manipulation helpers (using toml_edit for stable formatting)
// ============================================================================

/// Load an existing allowlist file or create an empty document.
fn load_or_create_allowlist_doc(
    path: &std::path::Path,
) -> Result<toml_edit::DocumentMut, Box<dyn std::error::Error>> {
    if path.exists() {
        let content = std::fs::read_to_string(path)?;
        let doc: toml_edit::DocumentMut = content.parse()?;
        Ok(doc)
    } else {
        // Create new document with header comment
        let mut doc = toml_edit::DocumentMut::new();
        doc.as_table_mut().set_implicit(true);
        Ok(doc)
    }
}

/// Write the allowlist document back to disk.
fn write_allowlist(
    path: &std::path::Path,
    doc: &toml_edit::DocumentMut,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, doc.to_string())?;
    Ok(())
}

/// Check if a rule entry already exists in the document.
fn has_rule_entry(doc: &toml_edit::DocumentMut, rule_id: &RuleId) -> bool {
    let Some(allow) = doc.get("allow") else {
        return false;
    };
    let Some(arr) = allow.as_array_of_tables() else {
        return false;
    };

    let rule_str = rule_id.to_string();
    arr.iter().any(|tbl| {
        tbl.get("rule")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s == rule_str)
    })
}

/// Check if an exact command entry already exists.
fn has_command_entry(doc: &toml_edit::DocumentMut, command: &str) -> bool {
    let Some(allow) = doc.get("allow") else {
        return false;
    };
    let Some(arr) = allow.as_array_of_tables() else {
        return false;
    };

    arr.iter().any(|tbl| {
        tbl.get("exact_command")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s == command)
    })
}

/// Build a new rule entry as an inline table.
fn build_rule_entry(
    rule_id: &RuleId,
    reason: &str,
    expires: Option<&str>,
    conditions: &[String],
) -> toml_edit::Table {
    let mut tbl = toml_edit::Table::new();

    tbl.insert("rule", toml_edit::value(rule_id.to_string()));
    tbl.insert("reason", toml_edit::value(reason));

    // Add audit metadata
    if let Some(user) = get_current_user() {
        tbl.insert("added_by", toml_edit::value(user));
    }
    tbl.insert("added_at", toml_edit::value(current_timestamp()));

    if let Some(exp) = expires {
        tbl.insert("expires_at", toml_edit::value(exp));
    }

    if !conditions.is_empty() {
        let mut cond_tbl = toml_edit::InlineTable::new();
        for cond in conditions {
            if let Some((k, v)) = cond.split_once('=') {
                cond_tbl.insert(k.trim(), v.trim().into());
            }
        }
        tbl.insert("conditions", toml_edit::Item::Value(cond_tbl.into()));
    }

    tbl
}

/// Build a new exact command entry.
fn build_command_entry(command: &str, reason: &str, expires: Option<&str>) -> toml_edit::Table {
    let mut tbl = toml_edit::Table::new();

    tbl.insert("exact_command", toml_edit::value(command));
    tbl.insert("reason", toml_edit::value(reason));

    // Add audit metadata
    if let Some(user) = get_current_user() {
        tbl.insert("added_by", toml_edit::value(user));
    }
    tbl.insert("added_at", toml_edit::value(current_timestamp()));

    if let Some(exp) = expires {
        tbl.insert("expires_at", toml_edit::value(exp));
    }

    tbl
}

/// Append an entry to the [[allow]] array.
fn append_entry(doc: &mut toml_edit::DocumentMut, entry: toml_edit::Table) {
    // Get or create the [[allow]] array of tables
    let allow = doc
        .entry("allow")
        .or_insert_with(|| toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new()));

    if let Some(arr) = allow.as_array_of_tables_mut() {
        arr.push(entry);
    }
}

/// Remove a rule entry from the document. Returns true if removed.
fn remove_rule_entry(doc: &mut toml_edit::DocumentMut, rule_id: &RuleId) -> bool {
    let Some(allow) = doc.get_mut("allow") else {
        return false;
    };
    let Some(arr) = allow.as_array_of_tables_mut() else {
        return false;
    };

    let rule_str = rule_id.to_string();
    let initial_len = arr.len();

    // Find the index to remove
    let mut remove_idx = None;
    for (idx, tbl) in arr.iter().enumerate() {
        if tbl
            .get("rule")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s == rule_str)
        {
            remove_idx = Some(idx);
            break;
        }
    }

    if let Some(idx) = remove_idx {
        arr.remove(idx);
    }

    arr.len() < initial_len
}

/// Get the current user (from environment or whoami).
fn get_current_user() -> Option<String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
}

/// Get current timestamp in RFC 3339 format.
fn current_timestamp() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Check if a timestamp string is expired.
fn is_expired(timestamp: &str) -> bool {
    // Try to parse as RFC 3339
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(timestamp) {
        return dt < chrono::Utc::now();
    }
    // Try simpler formats
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%S") {
        let utc = dt.and_utc();
        return utc < chrono::Utc::now();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dcg_entry() -> serde_json::Value {
        serde_json::json!({
            "matcher": "Bash",
            "hooks": [{
                "type": "command",
                "command": "dcg"
            }]
        })
    }

    fn entry_has_hook_command(entry: &serde_json::Value, command: &str) -> bool {
        entry
            .get("hooks")
            .and_then(|h| h.as_array())
            .is_some_and(|hooks| {
                hooks.iter().any(|hook| {
                    hook.get("command")
                        .and_then(|c| c.as_str())
                        .is_some_and(|c| c == command)
                })
            })
    }

    #[test]
    fn install_into_settings_creates_structure() {
        let mut settings = serde_json::json!({});
        let changed = install_dcg_hook_into_settings(&mut settings, false).expect("install ok");
        assert!(changed);

        let pre = settings
            .get("hooks")
            .and_then(|h| h.get("PreToolUse"))
            .and_then(|arr| arr.as_array())
            .expect("PreToolUse array exists");
        assert_eq!(pre.len(), 1);
        assert!(is_dcg_hook_entry(&pre[0]));
    }

    #[test]
    fn install_into_settings_does_not_duplicate_without_force() {
        let mut settings = serde_json::json!({
            "hooks": { "PreToolUse": [ make_dcg_entry() ] }
        });

        let changed = install_dcg_hook_into_settings(&mut settings, false).expect("install ok");
        assert!(!changed, "should detect existing hook");

        let pre = settings.get("hooks").and_then(|h| h.get("PreToolUse")).and_then(|arr| arr.as_array()).unwrap();
        assert_eq!(pre.iter().filter(|e| is_dcg_hook_entry(e)).count(), 1);
    }

    #[test]
    fn install_into_settings_force_reinstalls_single_entry() {
        let other = serde_json::json!({
            "matcher": "Bash",
            "hooks": [{ "type": "command", "command": "other-hook" }]
        });
        let mut settings = serde_json::json!({
            "hooks": { "PreToolUse": [ make_dcg_entry(), other ] }
        });

        let changed = install_dcg_hook_into_settings(&mut settings, true).expect("install ok");
        assert!(changed);

        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.iter().filter(|e| is_dcg_hook_entry(e)).count(), 1);
        assert!(
            pre.iter().any(|e| entry_has_hook_command(e, "other-hook")),
            "should retain other hook entry"
        );
    }

    #[test]
    fn install_into_settings_errors_on_invalid_pre_tool_use_type() {
        let mut settings = serde_json::json!({
            "hooks": { "PreToolUse": { "not": "an array" } }
        });
        let err = install_dcg_hook_into_settings(&mut settings, false).expect_err("should error");
        assert!(err.to_string().contains("PreToolUse"));
    }

    #[test]
    fn uninstall_from_settings_removes_dcg_entries() {
        let other = serde_json::json!({
            "matcher": "Bash",
            "hooks": [{ "type": "command", "command": "other-hook" }]
        });
        let mut settings = serde_json::json!({
            "hooks": { "PreToolUse": [ make_dcg_entry(), other ] }
        });

        let removed = uninstall_dcg_hook_from_settings(&mut settings).expect("uninstall ok");
        assert!(removed);

        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.iter().filter(|e| is_dcg_hook_entry(e)).count(), 0);
        assert_eq!(pre.len(), 1, "should retain non-dcg hook");
        assert!(entry_has_hook_command(&pre[0], "other-hook"));
    }

    #[test]
    fn uninstall_from_settings_errors_on_invalid_pre_tool_use_type() {
        let mut settings = serde_json::json!({
            "hooks": { "PreToolUse": { "not": "an array" } }
        });
        let err = uninstall_dcg_hook_from_settings(&mut settings).expect_err("should error");
        assert!(err.to_string().contains("PreToolUse"));
    }

    #[test]
    fn test_cli_parse_no_args() {
        let cli = Cli::parse_from(["dcg"]);
        assert!(cli.command.is_none());
    }

    #[test]
    fn test_cli_parse_packs() {
        let cli = Cli::parse_from(["dcg", "packs"]);
        assert!(matches!(cli.command, Some(Command::ListPacks { .. })));
    }

    #[test]
    fn test_cli_parse_packs_verbose() {
        let cli = Cli::parse_from(["dcg", "packs", "--verbose"]);
        if let Some(Command::ListPacks { verbose, .. }) = cli.command {
            assert!(verbose);
        } else {
            panic!("Expected ListPacks command");
        }
    }

    #[test]
    fn test_cli_parse_pack_info() {
        let cli = Cli::parse_from(["dcg", "pack", "core.git"]);
        if let Some(Command::PackInfo { pack_id, .. }) = cli.command {
            assert_eq!(pack_id, "core.git");
        } else {
            panic!("Expected PackInfo command");
        }
    }

    #[test]
    fn test_cli_parse_test() {
        let cli = Cli::parse_from(["dcg", "test", "git reset --hard"]);
        if let Some(Command::TestCommand { command, .. }) = cli.command {
            assert_eq!(command, "git reset --hard");
        } else {
            panic!("Expected TestCommand command");
        }
    }

    #[test]
    fn test_cli_parse_init() {
        let cli = Cli::parse_from(["dcg", "init"]);
        assert!(matches!(cli.command, Some(Command::Init { .. })));
    }

    #[test]
    fn test_cli_parse_update() {
        let cli = Cli::parse_from(["dcg", "update", "--version", "v0.2.0"]);
        if let Some(Command::Update(update)) = cli.command {
            assert_eq!(update.version.as_deref(), Some("v0.2.0"));
        } else {
            panic!("Expected Update command");
        }
    }

    // ========================================================================
    // Allowlist CLI tests
    // ========================================================================

    #[test]
    fn test_cli_parse_allowlist_add() {
        let cli = Cli::parse_from([
            "dcg",
            "allowlist",
            "add",
            "core.git:reset-hard",
            "-r",
            "Testing reset workflow",
        ]);
        if let Some(Command::Allowlist {
            action: AllowlistAction::Add {
                rule_id, reason, ..
            },
        }) = cli.command
        {
            assert_eq!(rule_id, "core.git:reset-hard");
            assert_eq!(reason, "Testing reset workflow");
        } else {
            panic!("Expected Allowlist Add command");
        }
    }

    #[test]
    fn test_cli_parse_allow_shortcut() {
        let cli = Cli::parse_from([
            "dcg",
            "allow",
            "core.git:push-force",
            "-r",
            "CI force push",
            "--user",
        ]);
        if let Some(Command::Allow {
            rule_id,
            reason,
            user,
            project,
            ..
        }) = cli.command
        {
            assert_eq!(rule_id, "core.git:push-force");
            assert_eq!(reason, "CI force push");
            assert!(user);
            assert!(!project);
        } else {
            panic!("Expected Allow command");
        }
    }

    #[test]
    fn test_cli_parse_unallow_shortcut() {
        let cli = Cli::parse_from(["dcg", "unallow", "core.git:reset-hard", "--project"]);
        if let Some(Command::Unallow {
            rule_id,
            project,
            user,
        }) = cli.command
        {
            assert_eq!(rule_id, "core.git:reset-hard");
            assert!(project);
            assert!(!user);
        } else {
            panic!("Expected Unallow command");
        }
    }

    #[test]
    fn test_cli_parse_allowlist_list() {
        let cli = Cli::parse_from(["dcg", "allowlist", "list", "--format", "json"]);
        if let Some(Command::Allowlist {
            action: AllowlistAction::List { format, .. },
        }) = cli.command
        {
            assert_eq!(format, AllowlistOutputFormat::Json);
        } else {
            panic!("Expected Allowlist List command");
        }
    }

    #[test]
    fn test_cli_parse_allowlist_validate() {
        let cli = Cli::parse_from(["dcg", "allowlist", "validate", "--strict"]);
        if let Some(Command::Allowlist {
            action: AllowlistAction::Validate { strict, .. },
        }) = cli.command
        {
            assert!(strict);
        } else {
            panic!("Expected Allowlist Validate command");
        }
    }

    #[test]
    fn test_cli_parse_allowlist_add_command() {
        let cli = Cli::parse_from([
            "dcg",
            "allowlist",
            "add-command",
            "git push --force origin main",
            "-r",
            "Release workflow",
        ]);
        if let Some(Command::Allowlist {
            action: AllowlistAction::AddCommand {
                command, reason, ..
            },
        }) = cli.command
        {
            assert_eq!(command, "git push --force origin main");
            assert_eq!(reason, "Release workflow");
        } else {
            panic!("Expected Allowlist AddCommand command");
        }
    }

    #[test]
    fn test_allowlist_toml_helpers() {
        // Test building a rule entry
        let rule_id = RuleId::parse("core.git:reset-hard").unwrap();
        let entry = build_rule_entry(&rule_id, "test", None, &[]);
        assert!(entry.get("rule").is_some());
        assert!(entry.get("reason").is_some());
        assert!(entry.get("added_at").is_some());

        // Test building entry with expiration
        let entry_with_exp = build_rule_entry(&rule_id, "test", Some("2030-01-01T00:00:00Z"), &[]);
        assert!(entry_with_exp.get("expires_at").is_some());

        // Test building entry with conditions
        let entry_with_cond = build_rule_entry(&rule_id, "test", None, &["CI=true".to_string()]);
        assert!(entry_with_cond.get("conditions").is_some());
    }

    #[test]
    fn test_is_expired() {
        // Past date should be expired
        assert!(is_expired("2020-01-01T00:00:00Z"));
        // Future date should not be expired
        assert!(!is_expired("2099-12-31T23:59:59Z"));
        // Invalid date should not be considered expired
        assert!(!is_expired("not-a-date"));
    }

    // ========================================================================
    // Allowlist E2E / Idempotence tests (git_safety_guard-1gt.2.5)
    // ========================================================================

    #[test]
    fn allowlist_add_creates_file_and_entry() {
        use tempfile::TempDir;
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("allowlist.toml");

        // File should not exist yet
        assert!(!path.exists());

        // Load or create, add entry, write
        let mut doc = load_or_create_allowlist_doc(&path).unwrap();
        let rule = RuleId::parse("core.git:reset-hard").unwrap();
        let entry = build_rule_entry(&rule, "test", None, &[]);
        append_entry(&mut doc, entry);
        write_allowlist(&path, &doc).unwrap();

        // File should now exist with content
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("core.git:reset-hard"));
        assert!(content.contains("reason = \"test\""));
    }

    #[test]
    fn allowlist_add_is_idempotent_via_duplicate_check() {
        use tempfile::TempDir;
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("allowlist.toml");

        let rule = RuleId::parse("core.git:push-force").unwrap();

        // Add first entry
        let mut doc = load_or_create_allowlist_doc(&path).unwrap();
        let entry = build_rule_entry(&rule, "first", None, &[]);
        append_entry(&mut doc, entry);
        write_allowlist(&path, &doc).unwrap();

        // has_rule_entry should detect duplicate
        let doc2 = load_or_create_allowlist_doc(&path).unwrap();
        assert!(has_rule_entry(&doc2, &rule), "should detect existing rule");

        // Count entries - should only have 1
        let allow_array = doc2.get("allow").and_then(|v| v.as_array_of_tables());
        assert_eq!(allow_array.map_or(0, toml_edit::ArrayOfTables::len), 1);
    }

    #[test]
    fn allowlist_remove_deletes_matching_entry() {
        use tempfile::TempDir;
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("allowlist.toml");

        let rule = RuleId::parse("core.git:clean-force").unwrap();

        // Add entry
        let mut doc = load_or_create_allowlist_doc(&path).unwrap();
        let entry = build_rule_entry(&rule, "to be removed", None, &[]);
        append_entry(&mut doc, entry);
        write_allowlist(&path, &doc).unwrap();

        // Verify it exists
        let doc_before = load_or_create_allowlist_doc(&path).unwrap();
        assert!(has_rule_entry(&doc_before, &rule), "should have existing rule");

        // Remove it
        let mut doc_to_modify = load_or_create_allowlist_doc(&path).unwrap();
        let removed = remove_rule_entry(&mut doc_to_modify, &rule);
        assert!(removed, "should have removed entry");
        write_allowlist(&path, &doc_to_modify).unwrap();

        // Verify it's gone
        let doc_after = load_or_create_allowlist_doc(&path).unwrap();
        assert!(!has_rule_entry(&doc_after, &rule), "should not have existing rule");
    }

    #[test]
    fn allowlist_remove_nonexistent_returns_false() {
        use tempfile::TempDir;
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("allowlist.toml");

        let rule = RuleId::parse("core.git:nonexistent").unwrap();

        // Create empty allowlist
        let mut doc = load_or_create_allowlist_doc(&path).unwrap();
        write_allowlist(&path, &doc).unwrap();

        // Try to remove non-existent entry
        let removed = remove_rule_entry(&mut doc, &rule);
        assert!(!removed, "should return false for non-existent entry");
    }

    #[test]
    fn allowlist_expired_entries_are_skipped_in_matching() {
        use crate::allowlist::{AllowlistLayer, is_expired, parse_allowlist_toml};
        use std::path::Path;

        let toml = r#"
            [[allow]]
            rule = "core.git:reset-hard"
            reason = "expired entry"
            expires_at = "2020-01-01T00:00:00Z"
        "#;

        // Parsing creates the entry (doesn't filter it out)
        let file = parse_allowlist_toml(AllowlistLayer::Project, Path::new("test"), toml);
        assert_eq!(file.entries.len(), 1, "parser should create the entry");
        assert!(
            file.errors.is_empty(),
            "parser should not report error for expired entry"
        );

        // But the entry should be marked as expired (skipped during matching)
        assert!(
            is_expired(&file.entries[0]),
            "entry should be detected as expired"
        );
    }

    #[test]
    fn allowlist_regex_without_ack_is_invalid_for_matching() {
        use crate::allowlist::{AllowlistLayer, has_required_risk_ack, parse_allowlist_toml};
        use std::path::Path;

        let toml = r#"
            [[allow]]
            pattern = "rm.*-rf"
            reason = "risky pattern"
        "#;

        // Parsing creates the entry (doesn't add error)
        let file = parse_allowlist_toml(AllowlistLayer::Project, Path::new("test"), toml);
        assert_eq!(file.entries.len(), 1, "parser should create the entry");

        // But the entry should fail the risk acknowledgement check (skipped during matching)
        assert!(
            !has_required_risk_ack(&file.entries[0]),
            "regex without ack should fail risk check"
        );
    }

    #[test]
    fn allowlist_command_entry_duplicate_detection() {
        use tempfile::TempDir;
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("allowlist.toml");

        let command = "git push --force origin main";

        // Add first entry
        let mut doc = load_or_create_allowlist_doc(&path).unwrap();
        let entry = build_command_entry(command, "first", None);
        append_entry(&mut doc, entry);
        write_allowlist(&path, &doc).unwrap();

        // has_command_entry should detect duplicate
        let doc2 = load_or_create_allowlist_doc(&path).unwrap();
        assert!(
            has_command_entry(&doc2, command),
            "should detect existing command"
        );
    }

    // ========================================================================
    // Scan CLI tests
    // ========================================================================

    #[test]
    fn test_cli_parse_scan_staged() {
        let cli = Cli::try_parse_from(["dcg", "scan", "--staged"]).expect("parse");
        if let Some(Command::Scan(scan)) = cli.command {
            assert!(scan.staged);
            assert!(scan.paths.is_none());
            assert!(scan.git_diff.is_none());
            assert!(scan.action.is_none());
        } else {
            panic!("Expected Scan command");
        }
    }

    #[test]
    fn test_cli_parse_scan_paths() {
        let cli = Cli::try_parse_from(["dcg", "scan", "--paths", "src/main.rs", "src/lib.rs"])
            .expect("parse");
        if let Some(Command::Scan(scan)) = cli.command {
            assert!(!scan.staged);
            assert_eq!(
                scan.paths,
                Some(vec![
                    std::path::PathBuf::from("src/main.rs"),
                    std::path::PathBuf::from("src/lib.rs"),
                ])
            );
            assert!(scan.git_diff.is_none());
            assert!(scan.action.is_none());
        } else {
            panic!("Expected Scan command");
        }
    }

    #[test]
    fn test_cli_parse_scan_git_diff() {
        let cli = Cli::try_parse_from(["dcg", "scan", "--git-diff", "main..HEAD"]).expect("parse");
        if let Some(Command::Scan(scan)) = cli.command {
            assert!(!scan.staged);
            assert!(scan.paths.is_none());
            assert_eq!(scan.git_diff, Some("main..HEAD".to_string()));
            assert!(scan.action.is_none());
        } else {
            panic!("Expected Scan command");
        }
    }

    #[test]
    fn test_cli_parse_scan_format_json() {
        let cli = Cli::try_parse_from(["dcg", "scan", "--staged", "--format", "json"])
            .expect("parse");
        if let Some(Command::Scan(scan)) = cli.command {
            assert_eq!(scan.format, Some(crate::scan::ScanFormat::Json));
        } else {
            panic!("Expected Scan command");
        }
    }

    #[test]
    fn test_cli_parse_scan_fail_on() {
        let cli = Cli::try_parse_from(["dcg", "scan", "--staged", "--fail-on", "warning"])
            .expect("parse");
        if let Some(Command::Scan(scan)) = cli.command {
            assert_eq!(scan.fail_on, Some(crate::scan::ScanFailOn::Warning));
        } else {
            panic!("Expected Scan command");
        }
    }

    #[test]
    fn test_cli_parse_scan_max_file_size() {
        let cli = Cli::try_parse_from(["dcg", "scan", "--staged", "--max-file-size", "2048"])
            .expect("parse");
        if let Some(Command::Scan(scan)) = cli.command {
            assert_eq!(scan.max_file_size, Some(2048));
        } else {
            panic!("Expected Scan command");
        }
    }

    #[test]
    fn test_cli_parse_scan_exclude_include() {
        let cli = Cli::try_parse_from([
            "dcg",
            "scan",
            "--staged",
            "--exclude",
            "*.log",
            "--exclude",
            "target/**",
            "--include",
            "src/**",
        ])
        .expect("parse");
        if let Some(Command::Scan(scan)) = cli.command {
            assert_eq!(scan.exclude, vec!["*.log", "target/**"]);
            assert_eq!(scan.include, vec!["src/**"]);
        } else {
            panic!("Expected Scan command");
        }
    }

    #[test]
    fn test_cli_parse_scan_conflicts() {
        // --staged and --paths should conflict
        let result = Cli::try_parse_from(["dcg", "scan", "--staged", "--paths", "file.txt"]);
        assert!(result.is_err());

        // --staged and --git-diff should conflict
        let result = Cli::try_parse_from(["dcg", "scan", "--staged", "--git-diff", "main..HEAD"]);
        assert!(result.is_err());

        // --paths and --git-diff should conflict
        let result = Cli::try_parse_from([
            "dcg",
            "scan",
            "--paths",
            "file.txt",
            "--git-diff",
            "main..HEAD",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_parse_scan_install_pre_commit() {
        let cli = Cli::try_parse_from(["dcg", "scan", "install-pre-commit"]).expect("parse");
        if let Some(Command::Scan(scan)) = cli.command {
            assert!(matches!(scan.action, Some(ScanAction::InstallPreCommit)));
        } else {
            panic!("Expected Scan command");
        }
    }

    #[test]
    fn test_cli_parse_scan_uninstall_pre_commit() {
        let cli = Cli::try_parse_from(["dcg", "scan", "uninstall-pre-commit"]).expect("parse");
        if let Some(Command::Scan(scan)) = cli.command {
            assert!(matches!(scan.action, Some(ScanAction::UninstallPreCommit)));
        } else {
            panic!("Expected Scan command");
        }
    }

    #[test]
    fn test_cli_parse_scan_subcommand_conflicts_with_args() {
        let result = Cli::try_parse_from(["dcg", "scan", "--staged", "install-pre-commit"]);
        assert!(
            result.is_err(),
            "args should conflict with scan subcommands"
        );
    }

    // ========================================================================
    // .dcg/hooks.toml merge tests
    // ========================================================================

    #[test]
    fn scan_settings_merge_uses_hooks_defaults_when_cli_unset() {
        let (hooks, _warnings) = crate::scan::parse_hooks_toml(
            r#"
[scan]
format = "json"
fail_on = "warning"
max_file_size = 123
max_findings = 5
redact = "quoted"
truncate = 9

[scan.paths]
include = ["src/**"]
exclude = ["target/**"]
"#,
        )
        .expect("parse");

        let settings = ScanSettingsOverrides {
            format: None,
            fail_on: None,
            max_file_size: None,
            max_findings: None,
            redact: None,
            truncate: None,
            include: Vec::new(),
            exclude: Vec::new(),
        }
        .resolve(Some(&hooks));

        assert_eq!(settings.format, crate::scan::ScanFormat::Json);
        assert_eq!(settings.fail_on, crate::scan::ScanFailOn::Warning);
        assert_eq!(settings.max_file_size, 123);
        assert_eq!(settings.max_findings, 5);
        assert_eq!(settings.redact, crate::scan::ScanRedactMode::Quoted);
        assert_eq!(settings.truncate, 9);
        assert_eq!(settings.include, vec!["src/**"]);
        assert_eq!(settings.exclude, vec!["target/**"]);
    }

    #[test]
    fn scan_settings_merge_cli_overrides_hooks() {
        let (hooks, _warnings) =
            crate::scan::parse_hooks_toml("[scan]\nformat = \"json\"\n").expect("parse");

        let settings = ScanSettingsOverrides {
            format: Some(crate::scan::ScanFormat::Pretty),
            fail_on: Some(crate::scan::ScanFailOn::Error),
            max_file_size: Some(777),
            max_findings: Some(42),
            redact: Some(crate::scan::ScanRedactMode::Aggressive),
            truncate: Some(0),
            include: vec!["cli/**".to_string()],
            exclude: vec!["cli/tmp/**".to_string()],
        }
        .resolve(Some(&hooks));

        assert_eq!(settings.format, crate::scan::ScanFormat::Pretty);
        assert_eq!(settings.fail_on, crate::scan::ScanFailOn::Error);
        assert_eq!(settings.max_file_size, 777);
        assert_eq!(settings.max_findings, 42);
        assert_eq!(settings.redact, crate::scan::ScanRedactMode::Aggressive);
        assert_eq!(settings.truncate, 0);
        assert_eq!(settings.include, vec!["cli/**"]);
        assert_eq!(settings.exclude, vec!["cli/tmp/**"]);
    }

    #[test]
    fn scan_settings_defaults_are_stable_without_hooks_or_cli() {
        let settings = ScanSettingsOverrides {
            format: None,
            fail_on: None,
            max_file_size: None,
            max_findings: None,
            redact: None,
            truncate: None,
            include: Vec::new(),
            exclude: Vec::new(),
        }
        .resolve(None);

        assert_eq!(settings.format, crate::scan::ScanFormat::Pretty);
        assert_eq!(settings.fail_on, crate::scan::ScanFailOn::Error);
        assert_eq!(settings.max_file_size, 1_048_576);
        assert_eq!(settings.max_findings, 100);
        assert_eq!(settings.redact, crate::scan::ScanRedactMode::None);
        assert_eq!(settings.truncate, 200);
        assert!(settings.include.is_empty());
        assert!(settings.exclude.is_empty());
    }

    // ========================================================================
    // Pre-commit install/uninstall tests
    // ========================================================================

    fn init_temp_git_repo(dir: &std::path::Path) {
        let output = std::process::Command::new("git")
            .current_dir(dir)
            .args(["init", "-q"])
            .output()
            .expect("git init");
        assert!(
            output.status.success(),
            "git init failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn scan_pre_commit_install_uninstall_roundtrip() {
        let tmp = tempfile::tempdir().expect("tempdir");
        init_temp_git_repo(tmp.path());

        let hook_path = install_scan_pre_commit_hook_at(tmp.path()).expect("install");
        assert!(hook_path.exists(), "hook should exist after install");

        let contents_1 = std::fs::read_to_string(&hook_path).expect("read hook");
        assert!(
            contents_1.contains(DCG_SCAN_PRE_COMMIT_SENTINEL),
            "hook should contain sentinel"
        );
        assert!(
            contents_1.contains("dcg scan --staged"),
            "hook should run dcg scan --staged"
        );

        let hook_path_2 = install_scan_pre_commit_hook_at(tmp.path()).expect("install again");
        assert_eq!(hook_path, hook_path_2);

        let contents_2 = std::fs::read_to_string(&hook_path).expect("read hook");
        assert_eq!(contents_1, contents_2, "install should be idempotent");

        let removed = uninstall_scan_pre_commit_hook_at(tmp.path()).expect("uninstall");
        assert!(removed.is_some(), "hook should be removed");

        let removed_again = uninstall_scan_pre_commit_hook_at(tmp.path()).expect("uninstall again");
        assert!(removed_again.is_none(), "should be a no-op when missing");
    }

    #[test]
    fn scan_pre_commit_install_refuses_to_overwrite_unknown_hook() {
        let tmp = tempfile::tempdir().expect("tempdir");
        init_temp_git_repo(tmp.path());

        let hook_path = git_resolve_path(tmp.path(), "hooks/pre-commit").expect("hook path");
        let existing = "#!/usr/bin/env bash\necho hi\n";
        std::fs::write(&hook_path, existing).expect("write existing hook");

        let err = install_scan_pre_commit_hook_at(tmp.path()).expect_err("should refuse");
        assert!(err.to_string().contains("Refusing to overwrite"));

        let after = std::fs::read_to_string(&hook_path).expect("read hook after");
        assert_eq!(after, existing, "should not modify unknown hook");
    }

    #[test]
    fn scan_pre_commit_uninstall_refuses_to_remove_unknown_hook() {
        let tmp = tempfile::tempdir().expect("tempdir");
        init_temp_git_repo(tmp.path());

        let hook_path = git_resolve_path(tmp.path(), "hooks/pre-commit").expect("hook path");
        let existing = "#!/usr/bin/env bash\necho hi\n";
        std::fs::write(&hook_path, existing).expect("write existing hook");

        let err = uninstall_scan_pre_commit_hook_at(tmp.path()).expect_err("should refuse");
        assert!(err.to_string().contains("Refusing to remove"));

        let after = std::fs::read_to_string(&hook_path).expect("read hook after");
        assert_eq!(after, existing, "should not modify unknown hook");
    }

    #[test]
    fn test_cli_parse_explain() {
        let cli = Cli::try_parse_from(["dcg", "explain", "git reset --hard"]).expect("parse");
        if let Some(Command::Explain {
            command,
            format,
            with_packs,
        }) = cli.command
        {
            assert_eq!(command, "git reset --hard");
            assert_eq!(format, ExplainFormat::Pretty);
            assert!(with_packs.is_none());
        } else {
            panic!("Expected Explain command");
        }
    }

    #[test]
    fn test_cli_parse_explain_with_format() {
        let cli =
            Cli::try_parse_from(["dcg", "explain", "--format", "json", "docker system prune"])
                .expect("parse");
        if let Some(Command::Explain {
            command, format, ..
        }) = cli.command
        {
            assert_eq!(command, "docker system prune");
            assert_eq!(format, ExplainFormat::Json);
        } else {
            panic!("Expected Explain command");
        }
    }

    #[test]
    fn test_cli_parse_test_with_explain_flag() {
        let cli =
            Cli::try_parse_from(["dcg", "test", "--explain", "git reset --hard"]).expect("parse");
        if let Some(Command::TestCommand {
            command,
            explain,
            format,
            ..
        }) = cli.command
        {
            assert_eq!(command, "git reset --hard");
            assert!(explain);
            assert_eq!(format, ExplainFormat::Pretty); // default format
        } else {
            panic!("Expected TestCommand");
        }
    }

    #[test]
    fn test_cli_parse_test_with_explain_and_format() {
        let cli = Cli::try_parse_from([
            "dcg",
            "test",
            "--explain",
            "--format",
            "compact",
            "rm -rf /tmp",
        ])
        .expect("parse");
        if let Some(Command::TestCommand {
            command,
            explain,
            format,
            ..
        }) = cli.command
        {
            assert_eq!(command, "rm -rf /tmp");
            assert!(explain);
            assert_eq!(format, ExplainFormat::Compact);
        } else {
            panic!("Expected TestCommand");
        }
    }

    #[test]
    fn test_cli_parse_test_without_explain_flag() {
        let cli = Cli::try_parse_from(["dcg", "test", "git status"]).expect("parse");
        if let Some(Command::TestCommand {
            command,
            explain,
            format,
            ..
        }) = cli.command
        {
            assert_eq!(command, "git status");
            assert!(!explain);
            assert_eq!(format, ExplainFormat::Pretty); // default
        } else {
            panic!("Expected TestCommand");
        }
    }

    // ========================================================================
    // Scan git integration tests
    // ========================================================================

    fn run_git(cwd: &std::path::Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .current_dir(cwd)
            .args(args)
            .output()
            .expect("run git");

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!("git {args:?} failed: {stderr}");
        }
    }

    fn init_fixture_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        run_git(dir.path(), &["init"]);
        run_git(dir.path(), &["config", "user.email", "test@example.com"]);
        run_git(dir.path(), &["config", "user.name", "Test User"]);

        std::fs::write(dir.path().join("base.txt"), "base").expect("write base");
        run_git(dir.path(), &["add", "base.txt"]);
        run_git(dir.path(), &["commit", "-m", "init"]);

        dir
    }

    #[test]
    fn get_staged_files_errors_when_not_git_repo() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = get_staged_files_at(dir.path()).expect_err("should error");
        assert!(err.to_string().contains("Not a git repository"));
    }

    #[test]
    fn get_staged_files_handles_spaces_and_newlines() {
        let repo = init_fixture_repo();

        std::fs::write(repo.path().join("hello world.rs"), "x").expect("write");
        std::fs::write(repo.path().join("weird\nname.rs"), "y").expect("write");
        run_git(repo.path(), &["add", "hello world.rs", "weird\nname.rs"]);

        let paths = get_staged_files_at(repo.path()).expect("staged files");
        let rendered: Vec<String> = paths
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();

        assert!(rendered.contains(&"hello world.rs".to_string()));
        assert!(rendered.contains(&"weird\nname.rs".to_string()));
    }

    #[test]
    fn get_staged_files_rename_returns_new_path() {
        let repo = init_fixture_repo();

        std::fs::write(repo.path().join("old.rs"), "x").expect("write");
        run_git(repo.path(), &["add", "old.rs"]);
        run_git(repo.path(), &["commit", "-m", "add old"]);

        run_git(repo.path(), &["mv", "old.rs", "new.rs"]);

        let paths = get_staged_files_at(repo.path()).expect("staged files");
        let rendered: Vec<String> = paths
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();

        assert!(rendered.contains(&"new.rs".to_string()));
        assert!(!rendered.contains(&"old.rs".to_string()));
    }

    #[test]
    fn get_staged_files_delete_is_skipped() {
        let repo = init_fixture_repo();

        std::fs::write(repo.path().join("delete.rs"), "x").expect("write");
        run_git(repo.path(), &["add", "delete.rs"]);
        run_git(repo.path(), &["commit", "-m", "add delete"]);

        run_git(repo.path(), &["rm", "delete.rs"]);

        let paths = get_staged_files_at(repo.path()).expect("staged files");
        let contains_deleted = paths.iter().any(|p| p.to_string_lossy() == "delete.rs");

        assert!(!contains_deleted);
    }

    #[test]
    fn get_git_diff_files_returns_changed_paths() {
        let repo = init_fixture_repo();

        std::fs::write(repo.path().join("diff.rs"), "v1").expect("write");
        run_git(repo.path(), &["add", "diff.rs"]);
        run_git(repo.path(), &["commit", "-m", "add diff"]);

        std::fs::write(repo.path().join("diff.rs"), "v2").expect("write");
        run_git(repo.path(), &["add", "diff.rs"]);
        run_git(repo.path(), &["commit", "-m", "mod diff"]);

        let paths = get_git_diff_files_at(repo.path(), "HEAD~1..HEAD").expect("diff files");
        let contains_diff = paths.iter().any(|p| p.to_string_lossy() == "diff.rs");

        assert!(contains_diff);
    }

    // ========================================================================
    // Git-diff integration tests (git_safety_guard-scan.5.3)
    // ========================================================================

    #[test]
    fn git_diff_empty_returns_empty() {
        let repo = init_fixture_repo();
        std::fs::write(repo.path().join("stable.rs"), "content").expect("write");
        run_git(repo.path(), &["add", "stable.rs"]);
        run_git(repo.path(), &["commit", "-m", "add stable"]);
        let paths = get_git_diff_files_at(repo.path(), "HEAD..HEAD").expect("diff");
        assert!(
            paths.is_empty(),
            "Empty diff should return empty list: {paths:?}"
        );
    }

    #[test]
    fn git_diff_renamed_file() {
        let repo = init_fixture_repo();
        std::fs::write(repo.path().join("old.rs"), "x").expect("write");
        run_git(repo.path(), &["add", "old.rs"]);
        run_git(repo.path(), &["commit", "-m", "add"]);
        run_git(repo.path(), &["mv", "old.rs", "new.rs"]);
        run_git(repo.path(), &["commit", "-m", "rename"]);
        let paths = get_git_diff_files_at(repo.path(), "HEAD~1..HEAD").expect("diff");
        let strs: Vec<String> = paths
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        assert!(
            strs.contains(&"new.rs".to_string()),
            "Should have new: {strs:?}"
        );
        assert!(
            !strs.contains(&"old.rs".to_string()),
            "Should not have old: {strs:?}"
        );
    }

    #[test]
    fn git_diff_deleted_skipped() {
        let repo = init_fixture_repo();
        std::fs::write(repo.path().join("del.rs"), "x").expect("write");
        run_git(repo.path(), &["add", "del.rs"]);
        run_git(repo.path(), &["commit", "-m", "add"]);
        run_git(repo.path(), &["rm", "del.rs"]);
        run_git(repo.path(), &["commit", "-m", "del"]);
        let paths = get_git_diff_files_at(repo.path(), "HEAD~1..HEAD").expect("diff");
        assert!(
            !paths.iter().any(|p| p.to_string_lossy() == "del.rs"),
            "Deleted skipped: {paths:?}"
        );
    }

    #[test]
    fn git_diff_deterministic() {
        let repo = init_fixture_repo();
        std::fs::write(repo.path().join("z.rs"), "z").expect("write");
        std::fs::write(repo.path().join("a.rs"), "a").expect("write");
        run_git(repo.path(), &["add", "."]);
        run_git(repo.path(), &["commit", "-m", "add"]);
        let p1 = get_git_diff_files_at(repo.path(), "HEAD~1..HEAD").expect("diff1");
        let p2 = get_git_diff_files_at(repo.path(), "HEAD~1..HEAD").expect("diff2");
        let s1: Vec<String> = p1.iter().map(|p| p.to_string_lossy().to_string()).collect();
        let s2: Vec<String> = p2.iter().map(|p| p.to_string_lossy().to_string()).collect();
        assert_eq!(s1, s2, "Deterministic order");
    }

    #[test]
    fn git_diff_mixed_ops() {
        let repo = init_fixture_repo();
        std::fs::write(repo.path().join("mod.rs"), "v1").expect("write");
        std::fs::write(repo.path().join("del.rs"), "x").expect("write");
        std::fs::write(repo.path().join("ren.rs"), "x").expect("write");
        run_git(repo.path(), &["add", "."]);
        run_git(repo.path(), &["commit", "-m", "init"]);
        std::fs::write(repo.path().join("new.rs"), "x").expect("write");
        std::fs::write(repo.path().join("mod.rs"), "v2").expect("write");
        run_git(repo.path(), &["rm", "del.rs"]);
        run_git(repo.path(), &["mv", "ren.rs", "renamed.rs"]);
        run_git(repo.path(), &["add", "."]);
        run_git(repo.path(), &["commit", "-m", "mix"]);
        let paths = get_git_diff_files_at(repo.path(), "HEAD~1..HEAD").expect("diff");
        let s: Vec<String> = paths
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        assert!(s.contains(&"new.rs".to_string()), "Has new");
        assert!(s.contains(&"mod.rs".to_string()), "Has mod");
        assert!(s.contains(&"renamed.rs".to_string()), "Has renamed");
        assert!(!s.contains(&"ren.rs".to_string()), "No old rename");
        assert!(!s.contains(&"del.rs".to_string()), "No deleted");
    }

    // ========================================================================
    // Glob matching tests
    // ========================================================================

    #[test]
    fn test_glob_match_exact() {
        assert!(glob_match("src/main.rs", "src/main.rs"));
        assert!(!glob_match("src/main.rs", "src/lib.rs"));
    }

    #[test]
    fn test_glob_match_star() {
        assert!(glob_match("*.rs", "main.rs"));
        assert!(glob_match("src/*.rs", "src/main.rs"));
        assert!(!glob_match("*.rs", "src/main.rs")); // * doesn't match /
    }

    #[test]
    fn test_glob_match_double_star() {
        assert!(glob_match("**/*.rs", "main.rs"));
        assert!(glob_match("**/*.rs", "src/main.rs"));
        assert!(glob_match("**/*.rs", "src/deep/nested/main.rs"));
        assert!(glob_match("src/**", "src/main.rs"));
        assert!(glob_match("src/**", "src/deep/nested/file.rs"));
        assert!(glob_match("src/**", "src"));
        assert!(!glob_match("src/**", "src2/main.rs"));
        assert!(!glob_match("target/**", "targeted/file.txt"));
        assert!(!glob_match(
            ".github/workflows/**",
            ".github/workflows2/ci.yml"
        ));
        assert!(glob_match("src/**", r"src\main.rs"));
        assert!(glob_match("**/*.rs", r"src\main.rs"));
    }

    #[test]
    fn test_glob_match_overlapping_prefix_suffix() {
        // Edge case: pattern where prefix+suffix > path length would cause panic
        // without the min_len check in glob_match
        assert!(!glob_match("test*st", "test")); // "test" ends with "st" but prefix+suffix=6 > 4
        assert!(glob_match("test*st", "testst")); // exactly prefix+suffix=6, path=6, empty middle
        assert!(glob_match("test*st", "test_xst")); // middle is "x", valid match
        assert!(glob_match("a*b", "ab")); // prefix+suffix=2, path=2, empty middle is OK
        assert!(glob_match("a*b", "axb")); // middle is "x"
        assert!(!glob_match("a*b", "b")); // doesn't start with "a"
        // Key edge case: overlapping prefix/suffix where path.len() < prefix.len() + suffix.len()
        // Pattern "ab*ab" has prefix="ab" (2) + suffix="ab" (2) = min_len 4
        // Path "ab" has len 2 which is < 4, so cannot match (would panic without min_len check)
        assert!(!glob_match("ab*ab", "ab")); // path too short
        assert!(glob_match("ab*ab", "abab")); // exactly min_len, empty middle
        assert!(glob_match("ab*ab", "abXab")); // middle is "X"
    }

    // ========================================================================
    // Markdown output tests (scan.5.2)
    // ========================================================================

    #[test]
    fn truncate_for_markdown_short_strings_unchanged() {
        assert_eq!(truncate_for_markdown("hello", 10), "hello");
        assert_eq!(truncate_for_markdown("", 10), "");
        assert_eq!(truncate_for_markdown("abc", 3), "abc");
    }

    #[test]
    fn truncate_for_markdown_long_strings_truncated() {
        assert_eq!(truncate_for_markdown("hello world", 5), "hello...");
        assert_eq!(truncate_for_markdown("abcdefghij", 7), "abcdefg...");
    }

    #[test]
    fn truncate_for_markdown_zero_max_no_truncation() {
        // max_len=0 means unlimited
        assert_eq!(truncate_for_markdown("hello world", 0), "hello world");
    }

    #[test]
    fn truncate_for_markdown_unicode_boundary() {
        // "café" = 5 bytes: c(1) + a(1) + f(1) + é(2)
        // Truncating at byte 4 lands mid-character (é spans bytes 3-4)
        // Should back up to byte 3 (char boundary after 'f')
        assert_eq!(truncate_for_markdown("café", 4), "caf...");

        // Truncating at byte 3 lands at char boundary
        assert_eq!(truncate_for_markdown("café", 3), "caf...");

        // Truncating at byte 5 keeps entire string (no truncation needed)
        assert_eq!(truncate_for_markdown("café", 5), "café");

        // Emoji test: "hi👋" = 6 bytes: h(1) + i(1) + 👋(4)
        // Truncating at byte 3 lands mid-emoji, should back up to byte 2
        assert_eq!(truncate_for_markdown("hi👋", 3), "hi...");

        // Truncating at byte 2 lands at char boundary
        assert_eq!(truncate_for_markdown("hi👋", 2), "hi...");

        // Truncating at byte 5 keeps entire string (no truncation needed)
        // Wait, byte 5 is inside the emoji. It should truncate to "hi..." because it can't fit the emoji.
        assert_eq!(truncate_for_markdown("hi👋", 5), "hi...");
    }

    #[test]
    fn scan_format_markdown_variant_exists() {
        // Verify the Markdown variant is available and can be compared
        assert_eq!(
            crate::scan::ScanFormat::Markdown,
            crate::scan::ScanFormat::Markdown
        );
    }

    #[test]
    fn cli_parse_scan_format_markdown() {
        let cli = Cli::try_parse_from(["dcg", "scan", "--staged", "--format", "markdown"])
            .expect("parse");
        if let Some(Command::Scan(scan)) = cli.command {
            assert_eq!(scan.format, Some(crate::scan::ScanFormat::Markdown));
        } else {
            panic!("Expected Scan command");
        }
    }

    // ==========================================================================
    // Doctor diagnostics tests (git_safety_guard-1gt.7.1)
    // ==========================================================================

    #[test]
    fn hook_diagnostics_default_is_not_healthy() {
        let diag = HookDiagnostics::default();
        // Default has settings_valid=false, dcg_hook_count=0
        assert!(!diag.is_healthy());
        assert!(diag.has_issues());
    }

    #[test]
    fn hook_diagnostics_healthy_single_hook() {
        let diag = HookDiagnostics {
            settings_exists: true,
            settings_valid: true,
            settings_error: None,
            dcg_hook_count: 1,
            wrong_matcher_hooks: vec![],
            missing_executable_hooks: vec![],
            other_hooks_count: 2,
        };
        assert!(diag.is_healthy());
        assert!(!diag.has_issues());
    }

    #[test]
    fn hook_diagnostics_unhealthy_zero_hooks() {
        let diag = HookDiagnostics {
            settings_exists: true,
            settings_valid: true,
            settings_error: None,
            dcg_hook_count: 0,
            wrong_matcher_hooks: vec![],
            missing_executable_hooks: vec![],
            other_hooks_count: 0,
        };
        assert!(!diag.is_healthy());
        assert!(diag.has_issues());
    }

    #[test]
    fn hook_diagnostics_unhealthy_duplicate_hooks() {
        let diag = HookDiagnostics {
            settings_exists: true,
            settings_valid: true,
            settings_error: None,
            dcg_hook_count: 2, // Duplicates
            wrong_matcher_hooks: vec![],
            missing_executable_hooks: vec![],
            other_hooks_count: 0,
        };
        assert!(!diag.is_healthy());
        assert!(diag.has_issues());
    }

    #[test]
    fn hook_diagnostics_unhealthy_wrong_matcher() {
        let diag = HookDiagnostics {
            settings_exists: true,
            settings_valid: true,
            settings_error: None,
            dcg_hook_count: 1,
            wrong_matcher_hooks: vec!["Write".to_string()],
            missing_executable_hooks: vec![],
            other_hooks_count: 0,
        };
        assert!(!diag.is_healthy());
        assert!(diag.has_issues());
    }

    #[test]
    fn hook_diagnostics_unhealthy_missing_executable() {
        let diag = HookDiagnostics {
            settings_exists: true,
            settings_valid: true,
            settings_error: None,
            dcg_hook_count: 1,
            wrong_matcher_hooks: vec![],
            missing_executable_hooks: vec!["/nonexistent/path/dcg".to_string()],
            other_hooks_count: 0,
        };
        assert!(!diag.is_healthy());
        assert!(diag.has_issues());
    }

    #[test]
    fn hook_diagnostics_unhealthy_invalid_settings() {
        let diag = HookDiagnostics {
            settings_exists: true,
            settings_valid: false,
            settings_error: Some("Invalid JSON".to_string()),
            dcg_hook_count: 0,
            wrong_matcher_hooks: vec![],
            missing_executable_hooks: vec![],
            other_hooks_count: 0,
        };
        assert!(!diag.is_healthy());
        assert!(diag.has_issues());
    }

    #[test]
    fn config_diagnostics_default_has_no_errors() {
        let diag = ConfigDiagnostics::default();
        assert!(!diag.has_errors());
        assert!(!diag.has_warnings());
    }

    #[test]
    fn config_diagnostics_parse_error_is_error() {
        let diag = ConfigDiagnostics {
            config_path: Some(std::path::PathBuf::from("/test/config.toml")),
            parse_error: Some("Invalid TOML".to_string()),
            unknown_packs: vec![],
            invalid_override_patterns: vec![],
        };
        assert!(diag.has_errors());
        assert!(!diag.has_warnings());
    }

    #[test]
    fn config_diagnostics_unknown_packs_is_error() {
        let diag = ConfigDiagnostics {
            config_path: Some(std::path::PathBuf::from("/test/config.toml")),
            parse_error: None,
            unknown_packs: vec!["nonexistent.pack".to_string()],
            invalid_override_patterns: vec![],
        };
        assert!(diag.has_errors());
        assert!(!diag.has_warnings());
    }

    #[test]
    fn config_diagnostics_invalid_patterns_is_warning() {
        let diag = ConfigDiagnostics {
            config_path: Some(std::path::PathBuf::from("/test/config.toml")),
            parse_error: None,
            unknown_packs: vec![],
            invalid_override_patterns: vec![("invalid(regex".to_string(), "error".to_string())],
        };
        assert!(!diag.has_errors());
        assert!(diag.has_warnings());
    }

    #[test]
    fn is_valid_pack_id_accepts_core() {
        assert!(is_valid_pack_id("core"));
    }

    #[test]
    fn is_valid_pack_id_accepts_category_prefix() {
        assert!(is_valid_pack_id("containers"));
        assert!(is_valid_pack_id("kubernetes"));
        assert!(is_valid_pack_id("database"));
        assert!(is_valid_pack_id("cloud"));
    }

    #[test]
    fn is_valid_pack_id_accepts_core_git() {
        // core.git should be a valid pack in the registry
        assert!(is_valid_pack_id("core.git"));
    }

    #[test]
    fn is_valid_pack_id_rejects_unknown() {
        assert!(!is_valid_pack_id("nonexistent"));
        assert!(!is_valid_pack_id("fake.pack"));
        assert!(!is_valid_pack_id(""));
    }

    #[test]
    fn is_valid_pack_id_rejects_category_with_unknown_subpack() {
        // containers is a valid category, but containers.fake is not a valid pack
        assert!(!is_valid_pack_id("containers.fake"));
    }

    #[test]
    fn diagnose_hook_wiring_from_json_valid_settings() {
        // Test the JSON parsing logic by calling the internal helpers
        let settings = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            { "type": "command", "command": "dcg" }
                        ]
                    }
                ]
            }
        });

        // Verify the structure is valid and has dcg hook
        let pre_tool_use = settings
            .get("hooks")
            .and_then(|h| h.get("PreToolUse"))
            .and_then(|p| p.as_array())
            .expect("PreToolUse array");

        assert_eq!(pre_tool_use.len(), 1);
        assert!(is_dcg_hook_entry(&pre_tool_use[0]));
    }

    #[test]
    fn diagnose_hook_wiring_from_json_wrong_matcher() {
        // dcg hook with wrong matcher (Write instead of Bash)
        // Note: is_dcg_hook_entry requires BOTH Bash matcher AND dcg command,
        // so this entry won't be recognized as a dcg hook entry.
        // The diagnose_hook_wiring function detects this case separately.
        let settings = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Write",
                        "hooks": [
                            { "type": "command", "command": "dcg" }
                        ]
                    }
                ]
            }
        });

        let pre_tool_use = settings["hooks"]["PreToolUse"].as_array().unwrap();
        let entry = &pre_tool_use[0];

        // Entry has dcg command but is_dcg_hook_entry returns false due to wrong matcher
        assert!(
            !is_dcg_hook_entry(entry),
            "should not be dcg hook due to wrong matcher"
        );

        // Verify the command is dcg
        let cmd = entry["hooks"][0]["command"].as_str().unwrap();
        assert!(is_dcg_command(cmd));

        // Verify matcher is wrong
        let matcher = entry.get("matcher").and_then(|m| m.as_str());
        assert_eq!(matcher, Some("Write"));
    }

    #[test]
    fn diagnose_hook_wiring_from_json_multiple_dcg_hooks() {
        // Multiple dcg hooks (duplicates)
        let settings = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            { "type": "command", "command": "dcg" }
                        ]
                    },
                    {
                        "matcher": "Bash",
                        "hooks": [
                            { "type": "command", "command": "/usr/local/bin/dcg" }
                        ]
                    }
                ]
            }
        });

        let pre_tool_use = settings["hooks"]["PreToolUse"].as_array().unwrap();
        let dcg_count = pre_tool_use.iter().filter(|e| is_dcg_hook_entry(e)).count();

        assert_eq!(dcg_count, 2, "should detect duplicate dcg hooks");
    }

    #[test]
    fn is_dcg_command_recognizes_various_forms() {
        assert!(is_dcg_command("dcg"));
        assert!(is_dcg_command("/usr/local/bin/dcg"));
        assert!(is_dcg_command("/home/user/.cargo/bin/dcg"));
        assert!(is_dcg_command("~/.local/bin/dcg"));

        assert!(!is_dcg_command("other-hook"));
        assert!(!is_dcg_command(""));
        assert!(!is_dcg_command("dcg-wrapper"));
    }

    #[test]
    fn smoke_test_passes_with_default_config() {
        // The smoke test should pass with default configuration
        assert!(run_smoke_test(), "smoke test should pass");
    }
}
