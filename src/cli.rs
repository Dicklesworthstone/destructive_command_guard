//! CLI argument parsing and command handling.
//!
//! This module provides the command-line interface for dcg (`destructive_command_guard`),
//! including subcommands for configuration management and pack information.

use chrono::Utc;
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::generate;
use inquire::{Select, Text};

use crate::agent::{DetectionMethod, detect_agent_with_details};
use crate::config::Config;
use crate::evaluator::{
    DEFAULT_WINDOW_WIDTH, EvaluationDecision, EvaluationResult, MatchSource,
    evaluate_command_with_pack_order, evaluate_command_with_pack_order_deadline_at_path,
};
use crate::exit_codes::EXIT_DENIED;
use crate::highlight::{HighlightSpan, format_highlighted_command, should_use_color};
use crate::history::{
    ExportOptions, HistoryDb, HistoryStats, Outcome, SuggestionAction, SuggestionAuditEntry,
};
use crate::interactive::{
    AllowlistScope, InteractiveConfig, InteractiveResult, check_interactive_available,
    print_not_available_message, run_interactive_prompt,
};
use crate::load_default_allowlists;
use crate::packs::{DecisionMode, REGISTRY, Severity as PackSeverity};
use crate::pending_exceptions::{
    AllowOnceEntry, AllowOnceScopeKind, AllowOnceStore, PendingExceptionRecord,
    PendingExceptionStore,
};
use crate::suggest::{
    AllowlistSuggestion, CommandEntryInfo, ConfidenceTier, RiskLevel, filter_by_confidence,
    filter_by_risk, generate_enhanced_suggestions,
};
use std::io::IsTerminal;

/// Unified output format for all dcg commands.
///
/// This enum provides a consistent interface for output format selection across
/// all commands. It supports the common formats needed by both human users
/// (pretty/text) and AI agents (json/jsonl).
///
/// # Robot Mode
///
/// When `--robot` mode is enabled, the format defaults to `Json` regardless
/// of the command-specific default.
///
/// # Aliases
///
/// Several aliases are provided for compatibility:
/// - `text` and `human` map to `Pretty`
/// - `sarif` and `structured` map to `Json`
///
/// # Example
///
/// ```bash
/// # Human-readable output (default)
/// dcg test "rm -rf /"
///
/// # JSON output for scripting
/// dcg test "rm -rf /" --format json
///
/// # Robot mode (implies JSON, suppresses stderr)
/// dcg --robot test "rm -rf /"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// Human-readable colored output (default for interactive use)
    #[default]
    #[value(alias = "text", alias = "human")]
    Pretty,

    /// Structured JSON output (for agents and scripting)
    #[value(alias = "sarif", alias = "structured")]
    Json,

    /// JSON Lines format (one JSON object per line, for streaming)
    #[value(name = "jsonl")]
    Jsonl,

    /// Compact single-line output (for specific commands)
    Compact,
}

impl OutputFormat {
    /// Returns true if this format produces JSON output.
    #[must_use]
    pub const fn is_json(&self) -> bool {
        matches!(self, Self::Json | Self::Jsonl)
    }

    /// Returns true if this format is human-readable.
    #[must_use]
    pub const fn is_human_readable(&self) -> bool {
        matches!(self, Self::Pretty | Self::Compact)
    }
}

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
    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true, env = "DCG_VERBOSE")]
    pub verbose: u8,

    /// Suppress non-error output
    #[arg(
        short,
        long,
        global = true,
        conflicts_with = "verbose",
        env = "DCG_QUIET"
    )]
    pub quiet: bool,

    /// Use legacy output rendering (fallback if rich output causes issues)
    #[arg(long, global = true, env = "DCG_LEGACY_OUTPUT")]
    pub legacy_output: bool,

    /// Disable colored output globally
    #[arg(long, global = true, env = "DCG_NO_COLOR")]
    pub no_color: bool,

    /// Disable suggestion output in warnings/denials
    #[arg(long, global = true, env = "DCG_NO_SUGGESTIONS")]
    pub no_suggestions: bool,

    /// Enable robot/machine mode for AI agent integration
    ///
    /// When enabled:
    /// - All output is JSON on stdout
    /// - stderr is completely silent (no rich output, no human messages)
    /// - Exit codes follow standardized values (see docs/adr-002-robot-mode-api.md)
    /// - Human-friendly decorations are suppressed
    ///
    /// This flag is designed for AI coding agents (Claude Code, Gemini CLI, etc.)
    /// that need to parse dcg's output programmatically.
    ///
    /// Exit codes in robot mode:
    /// - 0: Success / Allow
    /// - 1: Denied / Blocked
    /// - 2: Warning (with --fail-on warn)
    /// - 3: Configuration error
    /// - 4: Parse/input error
    /// - 5: IO error
    ///
    /// Enable robot mode for machine-friendly output (also enabled by DCG_ROBOT=1 env var).
    /// In robot mode: always outputs JSON, silent stderr, standardized exit codes.
    #[arg(long, global = true)]
    pub robot: bool,

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
        #[arg(long, short, value_enum, default_value_t = DoctorFormat::Pretty, env = "DCG_FORMAT")]
        format: DoctorFormat,
    },

    /// Run in hook mode with batch processing support
    ///
    /// Explicit hook mode for processing commands from stdin. When `--batch` is
    /// specified, reads JSONL (one JSON hook input per line) and outputs JSONL
    /// with decisions.
    ///
    /// Without `--batch`, behaves identically to running `dcg` with no subcommand.
    #[command(name = "hook")]
    Hook(HookCommand),

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

        /// Make entry temporary with given duration (e.g., 1h, 30m, 2d)
        #[arg(short = 't', long, conflicts_with = "expires")]
        temporary: Option<String>,

        /// Expiration date (ISO 8601 / RFC 3339)
        #[arg(long, conflicts_with = "temporary")]
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

    /// Allow a blocked command once using the short code
    #[command(name = "allow-once")]
    AllowOnce(AllowOnceCommand),

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

    /// Generate shell completion scripts
    #[command(name = "completions")]
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: CompletionShell,
    },

    /// List all available packs and their status
    #[command(name = "packs")]
    ListPacks {
        /// Show only enabled packs
        #[arg(long)]
        enabled: bool,

        // NOTE: Removed `verbose: bool` - use global `-v`/`--verbose` instead.
        // The global flag (u8 count) conflicts with local bool flags.
        /// Output format (json for structured output, pretty for human-readable)
        #[arg(
            long,
            short = 'f',
            value_enum,
            default_value = "pretty",
            env = "DCG_FORMAT"
        )]
        format: PacksFormat,
    },

    /// Pack management commands (info, validate)
    #[command(name = "pack")]
    Pack {
        #[command(subcommand)]
        action: PackAction,
    },

    /// Test a command against enabled packs
    #[command(name = "test")]
    TestCommand {
        /// Command to test
        command: String,

        /// Use a specific config file (overrides default config discovery)
        #[arg(long, short = 'c', value_name = "PATH")]
        config: Option<std::path::PathBuf>,

        /// Additional packs to enable for this test
        #[arg(long, value_delimiter = ',')]
        with_packs: Option<Vec<String>>,

        /// Show detailed decision trace (same as `dcg explain`)
        #[arg(long)]
        explain: bool,

        /// Output format (json for structured output, pretty for human-readable)
        #[arg(
            long,
            short = 'f',
            value_enum,
            default_value = "pretty",
            env = "DCG_FORMAT"
        )]
        format: TestFormat,

        /// Disable colored output
        #[arg(long)]
        no_color: bool,

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
        #[arg(
            long,
            short = 'f',
            value_enum,
            default_value = "pretty",
            env = "DCG_FORMAT"
        )]
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

    /// Show local statistics from the log file
    ///
    /// Displays aggregated statistics about blocked commands, allows,
    /// and bypasses from the configured log file.
    #[command(name = "stats")]
    Stats(StatsCommand),

    /// Query command history database
    #[command(name = "history")]
    History {
        #[command(subcommand)]
        action: HistoryAction,
    },

    /// Suggest allowlist patterns based on command history
    ///
    /// Analyzes denied commands from the history database and suggests
    /// patterns that could be added to the allowlist. Includes risk
    /// assessment and confidence scoring for each suggestion.
    #[command(name = "suggest-allowlist")]
    SuggestAllowlist(SuggestAllowlistCommand),

    /// Developer tools for pack development and testing
    #[command(name = "dev")]
    Dev {
        #[command(subcommand)]
        action: DevAction,
    },

    /// Start MCP server for direct agent integration
    ///
    /// Runs dcg as an MCP (Model Context Protocol) server over stdio,
    /// allowing AI agents to integrate directly without shell hooks.
    ///
    /// Tools exposed:
    /// - `check_command`: Evaluate a command using dcg policy
    /// - `scan_file`: Scan a file or directory for destructive commands
    /// - `explain_pattern`: Explain a dcg rule by `rule_id`
    ///
    /// Example agent configuration (Claude Code):
    /// ```json
    /// {
    ///   "mcpServers": {
    ///     "dcg": { "command": "dcg", "args": ["mcp-server"] }
    ///   }
    /// }
    /// ```
    #[command(name = "mcp-server")]
    McpServer,
}

/// `dcg hook` command arguments.
#[derive(Args, Debug)]
pub struct HookCommand {
    /// Enable batch mode: read JSONL from stdin, output JSONL results
    ///
    /// Each line should be a JSON hook input:
    /// ```jsonl
    /// {"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}
    /// {"tool_name":"Bash","tool_input":{"command":"git status"}}
    /// ```
    ///
    /// Output format:
    /// ```jsonl
    /// {"index":0,"decision":"deny","rule_id":"core.filesystem:rm-rf-root"}
    /// {"index":1,"decision":"allow"}
    /// ```
    #[arg(long)]
    pub batch: bool,

    /// Process commands in parallel (implies --batch)
    ///
    /// Uses multiple threads to evaluate commands concurrently.
    /// Output maintains input order via the `index` field.
    #[arg(long)]
    pub parallel: bool,

    /// Number of parallel workers (default: number of CPUs)
    #[arg(long, default_value = "0")]
    pub workers: usize,

    /// Continue processing on parse errors (skip invalid lines)
    #[arg(long)]
    pub continue_on_error: bool,
}

/// Output format for batch hook mode.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BatchHookOutput {
    /// Index of the input line (0-based)
    pub index: usize,
    /// Decision: "allow" or "deny"
    pub decision: &'static str,
    /// Rule ID if denied (e.g., "core.git:reset-hard")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Pack ID if denied
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pack_id: Option<String>,
    /// Error message if parsing failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
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
    #[arg(
        long,
        short = 'f',
        value_enum,
        default_value = "json",
        env = "DCG_FORMAT"
    )]
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
    #[value(alias = "sarif")]
    Json,
    /// Human-readable colored output
    #[value(alias = "text")]
    Pretty,
}

/// `dcg stats` command arguments.
#[derive(Args, Debug)]
pub struct StatsCommand {
    /// Time period in days (default: 30)
    #[arg(long, short = 'd', default_value = "30")]
    pub days: u64,

    /// Path to log file (overrides config)
    #[arg(long, short = 'f')]
    pub file: Option<std::path::PathBuf>,

    /// Output format
    #[arg(
        long,
        short = 'o',
        value_enum,
        default_value = "pretty",
        env = "DCG_FORMAT"
    )]
    pub format: StatsFormat,

    /// Show per-rule metrics from history database
    ///
    /// Displays detailed statistics for individual rules including hit counts,
    /// allowlist override rates, trends, and more.
    #[arg(long, short = 'r')]
    pub rules: bool,

    /// Limit number of rules to display (default: 20)
    #[arg(long, short = 'n', default_value = "20")]
    pub limit: usize,
}

/// Output format for stats command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum StatsFormat {
    /// Human-readable table output
    #[default]
    #[value(alias = "text")]
    Pretty,
    /// Structured JSON output
    #[value(alias = "sarif")]
    Json,
}

/// Output format for test command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum TestFormat {
    /// Human-readable colored output
    #[default]
    #[value(alias = "text")]
    Pretty,
    /// Structured JSON output
    #[value(alias = "sarif")]
    Json,
}

/// Output format for packs list command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum PacksFormat {
    /// Human-readable grouped output
    #[default]
    #[value(alias = "text")]
    Pretty,
    /// Structured JSON output
    #[value(alias = "sarif")]
    Json,
}

/// Schema version for TestOutput JSON format
const TEST_OUTPUT_SCHEMA_VERSION: u32 = 1;

/// JSON output structure for `dcg test` command
#[derive(Debug, Clone, serde::Serialize)]
pub struct TestOutput {
    /// Schema version for forward compatibility (currently 1)
    pub schema_version: u32,
    /// DCG version (e.g., "0.3.0")
    pub dcg_version: String,
    /// Whether robot mode was enabled for this output
    pub robot_mode: bool,
    /// The command that was tested
    pub command: String,
    /// The decision: "allow" or "deny"
    pub decision: String,
    /// Rule ID if blocked (e.g., "core.git:reset-hard")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Pack ID that matched (e.g., "core.git")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pack_id: Option<String>,
    /// Pattern name within the pack
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern_name: Option<String>,
    /// Reason for blocking
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Explanation for the match (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    /// Match source: `config_override`, `pack`, `heredoc_ast`, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Matched span (start, end) in the command
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_span: Option<(usize, usize)>,
    /// Severity level: "critical", "high", "medium", "low"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Allowlist override info if allowed via allowlist
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowlist: Option<AllowlistOverrideInfo>,
    /// Detected agent information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentInfo>,
}

/// Allowlist override information in test output
#[derive(Debug, Clone, serde::Serialize)]
pub struct AllowlistOverrideInfo {
    /// Which layer: "project", "user", "system"
    pub layer: String,
    /// Reason from the allowlist entry
    pub reason: String,
}

/// Agent detection information in test output
#[derive(Debug, Clone, serde::Serialize)]
pub struct AgentInfo {
    /// The detected agent name (e.g., "claude-code", "aider", "unknown")
    pub detected: String,
    /// Trust level for this agent (e.g., "high", "medium", "low")
    pub trust_level: String,
    /// How the agent was detected (e.g., "environment_variable", "explicit", "process", "none")
    pub detection_method: String,
}

/// JSON output structure for `dcg packs` command
#[derive(Debug, Clone, serde::Serialize)]
pub struct PacksOutput {
    /// List of all packs
    pub packs: Vec<PackInfo>,
    /// Count of enabled packs
    pub enabled_count: usize,
    /// Total pack count
    pub total_count: usize,
}

/// Pack information in the packs list
#[derive(Debug, Clone, serde::Serialize)]
pub struct PackInfo {
    /// Pack ID (e.g., "core.git")
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Category (e.g., "core", "database")
    pub category: String,
    /// Description
    pub description: String,
    /// Whether the pack is enabled
    pub enabled: bool,
    /// Number of safe patterns
    pub safe_pattern_count: usize,
    /// Number of destructive patterns
    pub destructive_pattern_count: usize,
}

/// `dcg suggest-allowlist` command arguments.
#[derive(Args, Debug)]
pub struct SuggestAllowlistCommand {
    /// Minimum times a command was blocked to be considered (default: 3)
    #[arg(long, default_value = "3")]
    pub min_frequency: usize,

    /// Look back period (e.g., "30d", "7d", "24h")
    #[arg(long, default_value = "30d")]
    pub since: String,

    /// Filter by confidence tier (high, medium, low, all)
    #[arg(long, default_value = "all")]
    pub confidence: ConfidenceTierFilter,

    /// Filter by risk level (low, medium, high, all)
    #[arg(long, default_value = "all")]
    pub risk: RiskLevelFilter,

    /// Non-interactive mode: print suggestions without prompts
    #[arg(long)]
    pub non_interactive: bool,

    /// Output format (text, json)
    #[arg(
        long,
        short = 'f',
        value_enum,
        default_value = "text",
        env = "DCG_FORMAT"
    )]
    pub format: SuggestFormat,

    /// Maximum number of suggestions to show
    #[arg(long, default_value = "20")]
    pub limit: usize,

    /// Undo recently added auto-suggested patterns (removes patterns added in the last N minutes)
    #[arg(long)]
    pub undo: Option<u32>,
}

/// Output format for suggest-allowlist command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum SuggestFormat {
    /// Human-readable colored output
    #[default]
    #[value(alias = "pretty")]
    Text,
    /// Structured JSON output
    #[value(alias = "sarif")]
    Json,
}

/// Filter for confidence tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum ConfidenceTierFilter {
    /// High confidence suggestions only
    High,
    /// Medium confidence suggestions only
    Medium,
    /// Low confidence suggestions only
    Low,
    /// All confidence levels
    #[default]
    All,
}

/// Filter for risk levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum RiskLevelFilter {
    /// Low risk suggestions only
    Low,
    /// Medium risk suggestions only
    Medium,
    /// High risk suggestions only
    High,
    /// All risk levels
    #[default]
    All,
}

/// Export format options for history export.
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum ExportFormat {
    /// JSON with metadata wrapper
    #[default]
    Json,
    /// JSON Lines (one JSON object per line)
    Jsonl,
    /// Comma-separated values
    Csv,
}

/// History subcommand actions
#[derive(Subcommand, Debug, Clone)]
pub enum HistoryAction {
    /// Show history stats and summaries
    #[command(name = "stats")]
    Stats {
        /// Time period in days (default: 30)
        #[arg(long, short = 'd', default_value = "30")]
        days: u64,

        /// Include trend comparisons against the previous period
        #[arg(long)]
        trends: bool,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Prune history entries older than the specified age
    #[command(name = "prune")]
    Prune {
        /// Prune entries older than this many days
        #[arg(long, value_name = "DAYS")]
        older_than_days: u64,

        /// Show what would be pruned without deleting
        #[arg(long)]
        dry_run: bool,

        /// Confirm pruning (required unless --dry-run)
        #[arg(long)]
        yes: bool,
    },

    /// Export command history to a file
    #[command(name = "export")]
    Export {
        /// Output file path (stdout if not specified)
        #[arg(long, short = 'o', value_name = "PATH")]
        output: Option<String>,

        /// Export format
        #[arg(long, short = 'f', value_enum, default_value = "json")]
        format: ExportFormat,

        /// Filter by outcome (allow, deny, warn, bypass)
        #[arg(long, value_name = "OUTCOME")]
        outcome: Option<String>,

        /// Include only commands since this date/time (ISO 8601)
        #[arg(long, value_name = "DATETIME")]
        since: Option<String>,

        /// Include only commands until this date/time (ISO 8601)
        #[arg(long, value_name = "DATETIME")]
        until: Option<String>,

        /// Maximum number of records to export
        #[arg(long, value_name = "N")]
        limit: Option<usize>,

        /// Compress output with gzip
        #[arg(long)]
        compress: bool,
    },

    /// Analyze pack effectiveness and generate recommendations
    #[command(name = "analyze")]
    Analyze {
        /// Time period in days (default: 30)
        #[arg(long, short = 'd', default_value = "30")]
        days: u64,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Show only recommendations
        #[arg(long)]
        recommendations_only: bool,

        /// Show potential false positives (bypassed commands)
        #[arg(long)]
        false_positives: bool,

        /// Show potential coverage gaps (dangerous allowed commands)
        #[arg(long)]
        gaps: bool,
    },

    /// Check database health and integrity
    #[command(name = "check")]
    Check {
        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Fail with non-zero exit code if integrity check fails
        #[arg(long)]
        strict: bool,
    },

    /// Create a backup of the history database
    #[command(name = "backup")]
    Backup {
        /// Output file path for the backup
        #[arg(value_name = "PATH")]
        output: String,

        /// Compress the backup with gzip
        #[arg(long, short = 'z')]
        compress: bool,
    },
}

/// Developer tool subcommands
#[derive(Subcommand, Debug)]
pub enum DevAction {
    /// Test a regex pattern against sample commands
    ///
    /// Validates regex syntax and tests matching against provided commands.
    /// Useful for developing and debugging pack patterns.
    #[command(name = "test-pattern")]
    TestPattern {
        /// Regex pattern to test
        pattern: String,

        /// Test commands to match against (interactive if not provided)
        #[arg(long, short = 'c', num_args = 1..)]
        commands: Option<Vec<String>>,

        /// Pattern type for context
        #[arg(long, value_enum, default_value = "destructive")]
        pattern_type: PatternType,
    },

    /// Validate pack structure and patterns
    ///
    /// Checks a pack source file for structural issues, pattern validity,
    /// regex complexity, and test coverage.
    #[command(name = "validate-pack")]
    ValidatePack {
        /// Pack ID to validate (e.g., "core.git", "database.postgresql")
        pack_id: String,
        // NOTE: Removed `verbose: bool` - use global `-v`/`--verbose` instead.
        // The global flag (u8 count) conflicts with local bool flags.
    },

    /// Debug pattern matching for a command
    ///
    /// Shows detailed trace of how each pack evaluates the command,
    /// including keyword matching, safe/destructive pattern evaluation.
    #[command(name = "debug")]
    Debug {
        /// Command to debug
        command: String,

        /// Show all packs, not just those with keyword matches
        #[arg(long)]
        all_packs: bool,
    },

    /// Run pattern matching benchmarks
    ///
    /// Measures performance of pack evaluation for given commands.
    #[command(name = "benchmark")]
    Benchmark {
        /// Pack ID to benchmark (or "all" for all enabled packs)
        #[arg(default_value = "all")]
        pack_id: String,

        /// Number of iterations
        #[arg(long, short = 'n', default_value = "1000")]
        iterations: usize,

        /// Commands to benchmark (uses defaults if not provided)
        #[arg(long, short = 'c', num_args = 1..)]
        commands: Option<Vec<String>>,
    },

    /// Generate test fixtures for a pack
    ///
    /// Creates YAML/TOML test case files based on pack patterns.
    #[command(name = "generate-fixtures")]
    GenerateFixtures {
        /// Pack ID to generate fixtures for
        pack_id: String,

        /// Output directory (default: tests/fixtures)
        #[arg(long, short = 'o', default_value = "tests/fixtures")]
        output_dir: std::path::PathBuf,

        /// Overwrite existing fixtures
        #[arg(long)]
        force: bool,
    },
}

/// Pattern type for dev test-pattern command
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum PatternType {
    /// Safe pattern (whitelist)
    Safe,
    /// Destructive pattern (blacklist)
    #[default]
    Destructive,
}

/// Options for self-updating dcg via the installer scripts.
#[derive(Args, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct UpdateCommand {
    /// Check for updates without installing (queries GitHub releases)
    #[arg(long, conflicts_with_all = ["version", "system", "easy_mode", "dest", "from_source", "verify", "quiet", "no_gum"])]
    pub check: bool,

    /// Force refresh version check (ignore 24-hour cache)
    #[arg(long, requires = "check")]
    pub refresh: bool,

    /// Output format for version check
    #[arg(
        long,
        short = 'f',
        value_enum,
        default_value_t = UpdateFormat::Pretty,
        requires = "check",
        env = "DCG_FORMAT"
    )]
    pub format: UpdateFormat,

    /// Force reinstall even if the target version is already installed (Unix only)
    #[arg(long, conflicts_with_all = ["check"])]
    pub force: bool,

    /// Install specific version (default: latest)
    #[arg(long)]
    pub version: Option<String>,

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

    /// Rollback to a previous version. Without a value, rolls back to the most recent backup.
    /// With a value (e.g., --rollback v1.8.0), rolls back to that specific version.
    #[arg(long, num_args = 0..=1, value_name = "VERSION", conflicts_with_all = ["check", "version", "system", "easy_mode", "from_source"])]
    pub rollback: Option<Option<String>>,

    /// List available backup versions that can be restored
    #[arg(long, conflicts_with_all = ["check", "version", "system", "easy_mode", "from_source", "rollback"])]
    pub list_versions: bool,
}

/// Output format for update --check command.
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum UpdateFormat {
    /// Human-readable colored output
    #[default]
    #[value(alias = "text")]
    Pretty,
    /// Structured JSON output
    #[value(alias = "sarif")]
    Json,
}

/// Shells supported for completion script generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Powershell,
    Elvish,
}

impl CompletionShell {
    const fn as_shell(self) -> clap_complete::Shell {
        match self {
            Self::Bash => clap_complete::Shell::Bash,
            Self::Zsh => clap_complete::Shell::Zsh,
            Self::Fish => clap_complete::Shell::Fish,
            Self::Powershell => clap_complete::Shell::PowerShell,
            Self::Elvish => clap_complete::Shell::Elvish,
        }
    }
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
    #[arg(long, short = 'f', value_enum, env = "DCG_FORMAT")]
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
    // NOTE: Removed `verbose: bool` - use global `-v`/`--verbose` instead.
    // The global flag (u8 count) conflicts with local bool flags.
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
    #[arg(
        long,
        short = 'F',
        value_enum,
        default_value = "pretty",
        env = "DCG_FORMAT"
    )]
    pub format: SimulateFormat,

    // NOTE: Removed `verbose: bool` - use global `-v`/`--verbose` instead.
    // The global flag (u8 count) conflicts with local bool flags.
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
    #[value(alias = "text")]
    Pretty,
    /// Structured JSON output
    #[value(alias = "sarif")]
    Json,
}

/// Output format for explain command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum ExplainFormat {
    /// Human-readable colored output
    #[default]
    #[value(alias = "text")]
    Pretty,
    /// Compact single-line output
    Compact,
    /// Structured JSON output
    #[value(alias = "sarif")]
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
        #[arg(long, value_enum, default_value = "pretty", env = "DCG_FORMAT")]
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

/// Subcommands for managing allow-once entries.
#[derive(Subcommand, Debug, Clone)]
pub enum AllowOnceAction {
    /// List pending codes and active allow-once entries (redacted by default)
    #[command(name = "list")]
    List,

    /// Clear expired entries and optionally wipe stores
    #[command(name = "clear")]
    Clear(AllowOnceClearArgs),

    /// Revoke a pending code or active allow-once entry
    #[command(name = "revoke")]
    Revoke(AllowOnceRevokeArgs),
}

#[derive(Args, Debug, Clone)]
pub struct AllowOnceClearArgs {
    /// Wipe both pending codes and active allow-once entries
    #[arg(long)]
    pub all: bool,

    /// Wipe pending codes
    #[arg(long)]
    pub pending: bool,

    /// Wipe active allow-once entries
    #[arg(long = "allow-once")]
    pub allow_once: bool,
}

#[derive(Args, Debug, Clone)]
pub struct AllowOnceRevokeArgs {
    /// Short code or full hash (or prefix) to revoke
    pub target: String,
}

/// Allow-once command arguments.
///
/// - `dcg allow-once <CODE>` (legacy shorthand for applying an allow-once code)
/// - `dcg allow-once list|clear|revoke` (management commands)
#[derive(Args, Debug)]
#[command(subcommand_precedence_over_arg = true)]
#[allow(clippy::struct_excessive_bools)]
pub struct AllowOnceCommand {
    /// Optional management subcommand.
    #[command(subcommand)]
    pub action: Option<AllowOnceAction>,

    /// Short code printed at the top of a denial message (legacy shorthand for apply)
    #[arg(value_name = "CODE")]
    pub code: Option<String>,

    /// Automatically confirm (non-interactive)
    #[arg(long, short = 'y', global = true)]
    pub yes: bool,

    /// Show raw command text in output (default shows redacted)
    #[arg(long, global = true)]
    pub show_raw: bool,

    /// Dry-run (do not write allow-once entry) (apply-only)
    #[arg(long)]
    pub dry_run: bool,

    /// Output JSON for automation
    #[arg(long, global = true)]
    pub json: bool,

    /// Allow a single use only (consumed after first allow) (apply-only)
    #[arg(long)]
    pub single_use: bool,

    /// Override explicit config blocklist (extra confirmation required) (apply-only)
    #[arg(long)]
    pub force: bool,

    /// Select a specific entry when multiple match the code (1-based) (apply-only)
    #[arg(long, value_name = "N", conflicts_with = "hash")]
    pub pick: Option<usize>,

    /// Select by full hash when multiple match the code (apply-only)
    #[arg(long, value_name = "HASH", conflicts_with = "pick")]
    pub hash: Option<String>,
}

/// Output format for allowlist list command
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum AllowlistOutputFormat {
    /// Human-readable output
    #[value(alias = "text")]
    Pretty,
    /// JSON output
    #[value(alias = "sarif")]
    Json,
}

/// Output format for doctor command
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum DoctorFormat {
    /// Human-readable colored output
    #[default]
    #[value(alias = "text")]
    Pretty,
    /// Structured JSON output for automation
    #[value(alias = "sarif")]
    Json,
}

/// Pack subcommand actions
#[derive(Subcommand, Debug)]
pub enum PackAction {
    /// Show information about a specific pack (built-in or external)
    #[command(name = "info")]
    Info {
        /// Pack ID (e.g., "database.postgresql", "core.git")
        pack_id: String,

        /// Show all patterns in the pack
        #[arg(long)]
        patterns: bool,
    },

    /// Validate an external pack YAML file
    ///
    /// Checks for:
    /// - Valid YAML syntax
    /// - Required fields (id, name, version)
    /// - ID format (namespace.name)
    /// - Version format (semver)
    /// - Pattern regex compilation
    /// - Duplicate pattern names
    /// - Collision with built-in packs
    #[command(name = "validate")]
    Validate {
        /// Path to pack YAML file
        file_path: String,

        /// Treat warnings as errors (exit non-zero on warnings)
        #[arg(long)]
        strict: bool,

        /// Output format
        #[arg(long, short = 'f', value_enum, default_value_t = PackValidateFormat::Pretty, env = "DCG_FORMAT")]
        format: PackValidateFormat,
    },
}

/// Output format for pack validate command
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum PackValidateFormat {
    /// Human-readable colored output
    #[default]
    #[value(alias = "text")]
    Pretty,
    /// Structured JSON output for tooling integration
    #[value(alias = "sarif")]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Verbosity {
    level: u8,
    quiet: bool,
}

impl Verbosity {
    fn from_cli(cli: &Cli) -> Self {
        Self {
            level: cli.verbose.min(3),
            quiet: cli.quiet,
        }
    }

    const fn level(self) -> u8 {
        if self.quiet { 0 } else { self.level }
    }

    const fn is_verbose(self) -> bool {
        self.level() >= 1
    }

    const fn is_debug(self) -> bool {
        self.level() >= 2
    }

    const fn is_trace(self) -> bool {
        self.level() >= 3
    }
}

fn maybe_show_update_notice(cli: &Cli, config: &Config, verbosity: Verbosity) {
    if verbosity.quiet || !config.general.check_updates {
        return;
    }

    if let Some(
        Command::Update(_) | Command::Hook(_) | Command::Completions { .. } | Command::McpServer,
    ) = cli.command
    {
        // Skip update notices for update/hook/completion/server flows.
        return;
    }

    let stderr_is_tty = std::io::stderr().is_terminal();
    if stderr_is_tty {
        if let Some(cached) = crate::update::read_cached_check() {
            if cached.update_available {
                eprintln!(
                    "! A new version of dcg is available: {} -> {}\n  Run `dcg update` to upgrade",
                    cached.current_version, cached.latest_version
                );
            }
        }
    }

    if stderr_is_tty {
        crate::update::spawn_update_check_if_needed();
    }
}

/// # Errors
///
/// Returns an error when no subcommand is provided (hook mode) or when a
/// subcommand that performs I/O fails.
#[allow(clippy::too_many_lines)]
pub fn run_command(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load();
    let verbosity = Verbosity::from_cli(&cli);
    maybe_show_update_notice(&cli, &config, verbosity);

    match cli.command {
        Some(Command::Doctor { fix, format }) => {
            doctor(fix, format);
        }
        Some(Command::Hook(cmd)) => {
            run_hook_command(&config, &cmd)?;
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
        Some(Command::Completions { shell }) => {
            write_completions(shell)?;
        }
        Some(Command::ListPacks { enabled, format }) => {
            // Robot mode forces JSON output
            let robot_mode = cli.robot || std::env::var("DCG_ROBOT").is_ok();
            let effective_format = if robot_mode {
                PacksFormat::Json
            } else {
                format
            };

            list_packs(
                &config,
                enabled,
                verbosity.is_verbose(),
                effective_format,
                verbosity.quiet,
            );
        }
        Some(Command::Pack { action }) => {
            handle_pack_command(&config, action)?;
        }
        Some(Command::TestCommand {
            command,
            config: config_path,
            with_packs,
            explain,
            format,
            no_color,
            heredoc_scan,
            no_heredoc_scan,
            heredoc_timeout_ms,
            heredoc_languages,
        }) => {
            // Robot mode forces JSON output
            let robot_mode = cli.robot || std::env::var("DCG_ROBOT").is_ok();
            let effective_format = if robot_mode { TestFormat::Json } else { format };

            // Load specific config file if provided, otherwise use default
            let effective_config = if let Some(ref path) = config_path {
                Config::load_from_file(path).unwrap_or_else(|| {
                    eprintln!("Warning: Failed to load config from {}", path.display());
                    config.clone()
                })
            } else {
                config.clone()
            };

            if explain {
                // Delegate to explain handler for detailed trace output
                // Convert TestFormat to ExplainFormat for explain mode
                let explain_format = match effective_format {
                    TestFormat::Pretty => ExplainFormat::Pretty,
                    TestFormat::Json => ExplainFormat::Json,
                };
                handle_explain(&effective_config, &command, explain_format, with_packs);
            } else {
                let was_blocked = test_command(
                    &effective_config,
                    &command,
                    with_packs,
                    effective_format,
                    verbosity,
                    no_color || robot_mode, // Robot mode also implies no color
                    robot_mode,
                    heredoc_scan,
                    no_heredoc_scan,
                    heredoc_timeout_ms,
                    heredoc_languages,
                );
                // Exit with code 1 if command would be blocked (for CI/robot mode scripting)
                if was_blocked {
                    std::process::exit(EXIT_DENIED);
                }
            }
        }
        Some(Command::Init { output, force }) => {
            init_config(output, force)?;
        }
        Some(Command::ShowConfig) => {
            if !verbosity.quiet {
                show_config(&config);
            }
        }
        Some(Command::Allowlist { action }) => {
            handle_allowlist_command(action)?;
        }
        Some(Command::Allow {
            rule_id,
            reason,
            project,
            user,
            temporary,
            expires,
        }) => {
            // Shortcut for `allowlist add`
            let layer = resolve_layer(project, user);

            // Compute the effective expiration: --temporary converts duration to absolute time
            let effective_expires = match (&temporary, &expires) {
                (Some(duration_str), None) => {
                    // Parse duration and compute absolute expiration time
                    let duration = crate::allowlist::parse_duration(duration_str)
                        .map_err(|e| format!("Invalid duration: {e}"))?;

                    // Warn if duration is longer than 30 days
                    if let Some(days) = duration.num_days().checked_abs() {
                        if days > 30 {
                            eprintln!(
                                "Warning: Temporary allowlist entry expires in {days} days. \
                                 Consider using a permanent entry with `--expires` for long durations."
                            );
                        }
                    }

                    let expires_at = Utc::now()
                        .checked_add_signed(duration)
                        .ok_or("Duration overflow: expiration time too far in the future")?;
                    Some(expires_at.to_rfc3339())
                }
                (None, Some(exp)) => Some(exp.clone()),
                (None, None) => None,
                // This case is prevented by clap's conflicts_with, but handle it for safety
                (Some(_), Some(_)) => {
                    return Err("Cannot specify both --temporary and --expires".into());
                }
            };

            allowlist_add_rule(&rule_id, &reason, layer, effective_expires.as_deref(), &[])?;
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
        Some(Command::AllowOnce(cmd)) => {
            handle_allow_once_command(&config, &cmd)?;
        }
        Some(Command::Scan(scan)) => {
            handle_scan_command(&config, scan, verbosity)?;
        }
        Some(Command::Simulate(sim)) => {
            handle_simulate_command(sim, &config, verbosity)?;
        }
        Some(Command::Explain {
            command,
            format,
            with_packs,
        }) => {
            // Robot mode forces JSON output
            let robot_mode = cli.robot || std::env::var("DCG_ROBOT").is_ok();
            let effective_format = if robot_mode {
                ExplainFormat::Json
            } else {
                format
            };

            if !verbosity.quiet {
                handle_explain(&config, &command, effective_format, with_packs);
            }
        }
        Some(Command::Corpus(corpus)) => {
            handle_corpus_command(&config, &corpus)?;
        }
        Some(Command::Stats(stats)) => {
            handle_stats_command(&config, &stats, verbosity.quiet)?;
        }
        Some(Command::History { action }) => {
            handle_history_command(&config, action)?;
        }
        Some(Command::SuggestAllowlist(cmd)) => {
            handle_suggest_allowlist_command(&config, &cmd)?;
        }
        Some(Command::Dev { action }) => {
            handle_dev_command(&config, action, verbosity)?;
        }
        Some(Command::McpServer) => {
            crate::mcp::run_mcp_server()?;
        }
        None => {
            // No subcommand - run in hook mode (default behavior)
            // This is handled by main.rs
            return Err("No subcommand provided. Running in hook mode.".into());
        }
    }

    Ok(())
}

fn write_completions(shell: CompletionShell) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{self, Write};

    let mut cmd = Cli::command();
    let bin_name = cmd.get_name().to_string();
    let mut stdout = io::stdout();
    generate(shell.as_shell(), &mut cmd, &bin_name, &mut stdout);
    stdout.flush()?;
    Ok(())
}

// ============================================================================
// Hook Command (dcg hook --batch)
// ============================================================================

/// Run the hook command with optional batch processing.
#[allow(clippy::too_many_lines)]
fn run_hook_command(config: &Config, cmd: &HookCommand) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{self, BufRead, Write};

    // If not batch mode and not parallel, fall through to normal hook mode
    if !cmd.batch && !cmd.parallel {
        // Delegate to main.rs hook mode by returning an error
        // that main.rs will catch and handle
        return Err("Hook mode without --batch; delegating to main.rs".into());
    }

    // Parallel implies batch
    let workers = if cmd.workers == 0 {
        std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(4)
    } else {
        cmd.workers
    };

    // Load configuration for evaluation
    let compiled_overrides = config.overrides.compile();
    let allowlists = crate::load_default_allowlists();
    let heredoc_settings = config.heredoc_settings();
    let enabled_packs = config.enabled_pack_ids();
    let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    let keyword_index = REGISTRY.build_enabled_keyword_index(&ordered_packs);

    // TODO: External pack loading is not yet implemented.
    // When ExternalPackLoader is implemented, load custom YAML packs here.

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout_lock = stdout.lock();

    if cmd.parallel && workers > 1 {
        // Parallel processing: collect all lines, process in parallel, output in order
        let lines: Vec<(usize, String)> = stdin
            .lock()
            .lines()
            .enumerate()
            .filter_map(|(idx, line)| line.ok().map(|l| (idx, l)))
            .collect();

        // Process in parallel using rayon
        #[cfg(feature = "rayon")]
        {
            use rayon::prelude::*;

            let results: Vec<BatchHookOutput> = lines
                .into_par_iter()
                .map(|(index, line)| {
                    evaluate_batch_line(
                        index,
                        &line,
                        &enabled_keywords,
                        &ordered_packs,
                        keyword_index.as_ref(),
                        &compiled_overrides,
                        &allowlists,
                        &heredoc_settings,
                        cmd.continue_on_error,
                    )
                })
                .collect();

            // Sort by index and output
            let mut sorted = results;
            sorted.sort_by_key(|r| r.index);

            for result in sorted {
                let json = serde_json::to_string(&result)?;
                writeln!(stdout_lock, "{json}")?;
            }
        }

        // Fallback to sequential if rayon is not available
        #[cfg(not(feature = "rayon"))]
        {
            for (index, line) in lines {
                let result = evaluate_batch_line(
                    index,
                    &line,
                    &enabled_keywords,
                    &ordered_packs,
                    keyword_index.as_ref(),
                    &compiled_overrides,
                    &allowlists,
                    &heredoc_settings,
                    cmd.continue_on_error,
                );
                let json = serde_json::to_string(&result)?;
                writeln!(stdout_lock, "{json}")?;
            }
        }
    } else {
        // Sequential processing: stream input to output
        for (index, line) in stdin.lock().lines().enumerate() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    if cmd.continue_on_error {
                        let result = BatchHookOutput {
                            index,
                            decision: "error",
                            rule_id: None,
                            pack_id: None,
                            error: Some(format!("IO error: {e}")),
                        };
                        let json = serde_json::to_string(&result)?;
                        writeln!(stdout_lock, "{json}")?;
                        continue;
                    }
                    return Err(e.into());
                }
            };

            let result = evaluate_batch_line(
                index,
                &line,
                &enabled_keywords,
                &ordered_packs,
                keyword_index.as_ref(),
                &compiled_overrides,
                &allowlists,
                &heredoc_settings,
                cmd.continue_on_error,
            );
            let json = serde_json::to_string(&result)?;
            writeln!(stdout_lock, "{json}")?;
        }
    }

    Ok(())
}

/// Evaluate a single batch line and return the result.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn evaluate_batch_line(
    index: usize,
    line: &str,
    enabled_keywords: &[&str],
    ordered_packs: &[String],
    keyword_index: Option<&crate::packs::EnabledKeywordIndex>,
    compiled_overrides: &crate::config::CompiledOverrides,
    allowlists: &crate::allowlist::LayeredAllowlist,
    heredoc_settings: &crate::config::HeredocSettings,
    continue_on_error: bool,
) -> BatchHookOutput {
    // Skip empty lines
    if line.trim().is_empty() {
        return BatchHookOutput {
            index,
            decision: "skip",
            rule_id: None,
            pack_id: None,
            error: Some("Empty line".to_string()),
        };
    }

    // Parse JSON input
    let hook_input: crate::hook::HookInput = match serde_json::from_str(line) {
        Ok(input) => input,
        Err(e) => {
            if continue_on_error {
                return BatchHookOutput {
                    index,
                    decision: "error",
                    rule_id: None,
                    pack_id: None,
                    error: Some(format!("JSON parse error: {e}")),
                };
            }
            return BatchHookOutput {
                index,
                decision: "error",
                rule_id: None,
                pack_id: None,
                error: Some(format!("JSON parse error: {e}")),
            };
        }
    };

    // Only process Bash tool invocations
    if hook_input.tool_name.as_deref() != Some("Bash") {
        return BatchHookOutput {
            index,
            decision: "skip",
            rule_id: None,
            pack_id: None,
            error: Some("Not a Bash tool invocation".to_string()),
        };
    }

    let Some(tool_input) = hook_input.tool_input else {
        return BatchHookOutput {
            index,
            decision: "skip",
            rule_id: None,
            pack_id: None,
            error: Some("Missing tool_input".to_string()),
        };
    };

    let Some(command_value) = tool_input.command else {
        return BatchHookOutput {
            index,
            decision: "skip",
            rule_id: None,
            pack_id: None,
            error: Some("Missing command".to_string()),
        };
    };

    let serde_json::Value::String(command) = command_value else {
        return BatchHookOutput {
            index,
            decision: "skip",
            rule_id: None,
            pack_id: None,
            error: Some("Command is not a string".to_string()),
        };
    };

    if command.is_empty() {
        return BatchHookOutput {
            index,
            decision: "skip",
            rule_id: None,
            pack_id: None,
            error: Some("Empty command".to_string()),
        };
    }

    // Evaluate the command
    let eval_result = evaluate_command_with_pack_order_deadline_at_path(
        &command,
        enabled_keywords,
        ordered_packs,
        keyword_index,
        compiled_overrides,
        allowlists,
        heredoc_settings,
        None,
        None,
        None, // No deadline for batch mode
    );

    match eval_result.decision {
        EvaluationDecision::Allow => BatchHookOutput {
            index,
            decision: "allow",
            rule_id: None,
            pack_id: None,
            error: None,
        },
        EvaluationDecision::Deny => {
            // Extract pattern info for deny decisions
            let (rule_id, pack_id) =
                eval_result
                    .pattern_info
                    .as_ref()
                    .map_or((None, None), |info| {
                        let rule_id = match (&info.pack_id, &info.pattern_name) {
                            (Some(p), Some(pat)) => Some(format!("{p}:{pat}")),
                            (Some(p), None) => Some(p.clone()),
                            _ => None,
                        };
                        (rule_id, info.pack_id.clone())
                    });

            BatchHookOutput {
                index,
                decision: "deny",
                rule_id,
                pack_id,
                error: None,
            }
        }
    }
}

/// List all packs and their status
fn list_packs(
    config: &Config,
    enabled_only: bool,
    verbose: bool,
    format: PacksFormat,
    quiet: bool,
) {
    if quiet {
        return;
    }

    let enabled_packs = config.enabled_pack_ids();
    let infos = REGISTRY.list_packs(&enabled_packs);

    // Build pack list (filtered if enabled_only)
    let pack_list: Vec<PackInfo> = infos
        .iter()
        .filter(|info| !enabled_only || info.enabled)
        .map(|info| {
            let category = info.id.split('.').next().unwrap_or(&info.id).to_string();
            PackInfo {
                id: info.id.clone(),
                name: info.name.to_string(),
                category,
                description: info.description.to_string(),
                enabled: info.enabled,
                safe_pattern_count: info.safe_pattern_count,
                destructive_pattern_count: info.destructive_pattern_count,
            }
        })
        .collect();

    // Handle JSON output
    if format == PacksFormat::Json {
        let enabled_count = pack_list.iter().filter(|p| p.enabled).count();
        let output = PacksOutput {
            packs: pack_list,
            enabled_count,
            total_count: infos.len(),
        };
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return;
    }

    // Rich output when feature enabled
    #[cfg(feature = "rich-output")]
    {
        list_packs_rich(config, enabled_only, verbose);
    }

    // Pretty output (default, non-rich fallback)
    #[cfg(not(feature = "rich-output"))]
    {
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
}

/// Rich terminal packs output using DcgConsole and markup.
#[cfg(feature = "rich-output")]
fn list_packs_rich(config: &Config, enabled_only: bool, verbose: bool) {
    use crate::output::console::console;

    let con = console();
    let enabled_packs = config.enabled_pack_ids();
    let infos = REGISTRY.list_packs(&enabled_packs);

    // Header
    con.rule(Some("[bold cyan] Available Packs [/]"));
    con.print("");

    // Group by category
    let mut by_category: std::collections::BTreeMap<&str, Vec<_>> =
        std::collections::BTreeMap::new();
    for info in &infos {
        let category = info.id.split('.').next().unwrap_or(&info.id);
        by_category.entry(category).or_default().push(info);
    }

    for (category, packs) in by_category {
        con.print(&format!("[bold]{category}[/]:"));
        for info in packs {
            if enabled_only && !info.enabled {
                continue;
            }

            let (status, color) = if info.enabled {
                ("●", "green")
            } else {
                ("○", "dim")
            };

            if verbose {
                con.print(&format!(
                    "  [{color}]{status}[/] [bold]{id}[/] - {desc} [dim]({safe} safe, {destr} destructive)[/]",
                    id = info.id,
                    desc = info.description,
                    safe = info.safe_pattern_count,
                    destr = info.destructive_pattern_count
                ));
            } else {
                con.print(&format!(
                    "  [{color}]{status}[/] [bold]{id}[/] - {name}",
                    id = info.id,
                    name = info.name
                ));
            }
        }
        con.print("");
    }

    con.print("[dim]Legend: [green]●[/] = enabled, ○ = disabled[/]");
    con.print("[dim]Enable packs in ~/.config/dcg/config.toml[/]");
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

// ============================================================================
// Pack Commands (dcg pack info/validate)
// ============================================================================

/// Handle all `dcg pack` subcommands
fn handle_pack_command(
    _config: &Config,
    action: PackAction,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        PackAction::Info { pack_id, patterns } => {
            pack_info(&pack_id, patterns)?;
        }
        PackAction::Validate {
            file_path,
            strict,
            format,
        } => {
            pack_validate(&file_path, strict, format)?;
        }
    }
    Ok(())
}

/// Validate an external pack YAML file
#[allow(clippy::too_many_lines)]
fn pack_validate(
    file_path: &str,
    strict: bool,
    format: PackValidateFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::packs::external::{
        CURRENT_SCHEMA_VERSION, ExternalPack, RegexEngineType, analyze_pack_engines,
        check_builtin_collision, summarize_pack_engines,
    };
    use std::path::Path;

    let path = Path::new(file_path);

    let mut result = PackValidationOutput {
        valid: true,
        file: file_path.to_string(),
        pack_id: None,
        pack_name: None,
        pack_version: None,
        errors: Vec::new(),
        warnings: Vec::new(),
        suggestions: Vec::new(),
        patterns: None,
        engine_summary: None,
    };

    // Step 1: Check if file exists
    if !path.exists() {
        result.valid = false;
        result.errors.push(PackValidationIssue {
            code: "E001".to_string(),
            message: format!("File not found: {file_path}"),
            suggestion: None,
        });
        return output_pack_validation(&result, format, strict);
    }

    // Step 2: Read file content
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            result.valid = false;
            result.errors.push(PackValidationIssue {
                code: "E002".to_string(),
                message: format!("Failed to read file: {e}"),
                suggestion: None,
            });
            return output_pack_validation(&result, format, strict);
        }
    };

    // Step 3: Parse YAML
    let pack: ExternalPack = match serde_yaml::from_str(&content) {
        Ok(p) => p,
        Err(e) => {
            result.valid = false;
            result.errors.push(PackValidationIssue {
                code: "E003".to_string(),
                message: format!("YAML parse error: {e}"),
                suggestion: Some("Check YAML syntax (indentation, colons, quotes)".to_string()),
            });
            return output_pack_validation(&result, format, strict);
        }
    };

    // Store basic pack info for output
    result.pack_id = Some(pack.id.clone());
    result.pack_name = Some(pack.name.clone());
    result.pack_version = Some(pack.version.clone());

    // Step 4: Validate schema version
    if pack.schema_version > CURRENT_SCHEMA_VERSION {
        result.valid = false;
        result.errors.push(PackValidationIssue {
            code: "E004".to_string(),
            message: format!(
                "Schema version {} is not supported (max: {})",
                pack.schema_version, CURRENT_SCHEMA_VERSION
            ),
            suggestion: Some(format!(
                "Use schema_version: {CURRENT_SCHEMA_VERSION} or lower"
            )),
        });
    }

    // Step 5: Validate ID format
    let id_regex = regex::Regex::new(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$").unwrap();
    if !id_regex.is_match(&pack.id) {
        result.valid = false;
        result.errors.push(PackValidationIssue {
            code: "E005".to_string(),
            message: format!(
                "Invalid pack ID '{}': must match pattern namespace.name (e.g., 'mycompany.deploy')",
                pack.id
            ),
            suggestion: Some("Use lowercase letters, numbers, underscores. Format: namespace.name".to_string()),
        });
    }

    // Step 6: Validate version format (semver)
    let version_regex = regex::Regex::new(r"^\d+\.\d+\.\d+$").unwrap();
    if !version_regex.is_match(&pack.version) {
        result.valid = false;
        result.errors.push(PackValidationIssue {
            code: "E006".to_string(),
            message: format!(
                "Invalid version '{}': must be semantic version (e.g., '1.0.0')",
                pack.version
            ),
            suggestion: Some("Use MAJOR.MINOR.PATCH format (e.g., 1.0.0, 2.1.3)".to_string()),
        });
    }

    // Step 7: Check for empty pack
    if pack.destructive_patterns.is_empty() && pack.safe_patterns.is_empty() {
        result.valid = false;
        result.errors.push(PackValidationIssue {
            code: "E007".to_string(),
            message: "Pack has no patterns defined".to_string(),
            suggestion: Some("Add at least one destructive_pattern or safe_pattern".to_string()),
        });
    }

    // Step 8: Check for duplicate pattern names
    let mut seen_names = std::collections::HashSet::new();
    for pattern in &pack.destructive_patterns {
        if !seen_names.insert(&pattern.name) {
            result.valid = false;
            result.errors.push(PackValidationIssue {
                code: "E008".to_string(),
                message: format!("Duplicate pattern name: {}", pattern.name),
                suggestion: Some("Pattern names must be unique within a pack".to_string()),
            });
        }
    }
    for pattern in &pack.safe_patterns {
        if !seen_names.insert(&pattern.name) {
            result.valid = false;
            result.errors.push(PackValidationIssue {
                code: "E008".to_string(),
                message: format!("Duplicate pattern name: {}", pattern.name),
                suggestion: Some("Pattern names must be unique within a pack".to_string()),
            });
        }
    }

    // Step 9: Validate regex patterns
    for pattern in &pack.destructive_patterns {
        if let Err(e) = crate::packs::regex_engine::CompiledRegex::new(&pattern.pattern) {
            result.valid = false;
            result.errors.push(PackValidationIssue {
                code: "E009".to_string(),
                message: format!("Invalid regex in pattern '{}': {}", pattern.name, e),
                suggestion: Some("Check regex syntax".to_string()),
            });
        }
    }
    for pattern in &pack.safe_patterns {
        if let Err(e) = crate::packs::regex_engine::CompiledRegex::new(&pattern.pattern) {
            result.valid = false;
            result.errors.push(PackValidationIssue {
                code: "E009".to_string(),
                message: format!("Invalid regex in pattern '{}': {}", pattern.name, e),
                suggestion: Some("Check regex syntax".to_string()),
            });
        }
    }

    // Step 10: Check for collision with built-in packs
    if let Some(builtin_name) = check_builtin_collision(&pack.id) {
        result.valid = false;
        result.errors.push(PackValidationIssue {
            code: "E010".to_string(),
            message: format!(
                "Pack ID '{}' collides with built-in pack '{}'",
                pack.id, builtin_name
            ),
            suggestion: Some(
                "Use a different namespace (e.g., 'mycompany.git' instead of 'core.git')"
                    .to_string(),
            ),
        });
    }

    // === Warnings (non-fatal) ===

    // Check for broad patterns
    for pattern in &pack.destructive_patterns {
        if pattern.pattern.contains(".*") && !pattern.pattern.starts_with('^') {
            result.warnings.push(PackValidationIssue {
                code: "W001".to_string(),
                message: format!(
                    "Pattern '{}' contains '.*' without anchor - may be too broad",
                    pattern.name
                ),
                suggestion: Some("Consider anchoring with ^ at the start".to_string()),
            });
        }
    }

    // Check for missing descriptions
    for pattern in &pack.destructive_patterns {
        if pattern.description.is_none() {
            result.warnings.push(PackValidationIssue {
                code: "W002".to_string(),
                message: format!("Pattern '{}' has no description", pattern.name),
                suggestion: Some(
                    "Add a description to help users understand why this blocks".to_string(),
                ),
            });
        }
    }

    // Check for missing explanations on high/critical patterns
    for pattern in &pack.destructive_patterns {
        use crate::packs::external::ExternalSeverity;
        if matches!(
            pattern.severity,
            ExternalSeverity::High | ExternalSeverity::Critical
        ) && pattern.explanation.is_none()
        {
            result.warnings.push(PackValidationIssue {
                code: "W003".to_string(),
                message: format!(
                    "High/critical pattern '{}' has no explanation",
                    pattern.name
                ),
                suggestion: Some(
                    "Add an explanation for verbose output to help users understand the risk"
                        .to_string(),
                ),
            });
        }
    }

    // Check for keywords not used in patterns
    for keyword in &pack.keywords {
        let keyword_lower = keyword.to_lowercase();
        let found_in_pattern = pack
            .destructive_patterns
            .iter()
            .any(|p| p.pattern.to_lowercase().contains(&keyword_lower))
            || pack
                .safe_patterns
                .iter()
                .any(|p| p.pattern.to_lowercase().contains(&keyword_lower));
        if !found_in_pattern {
            result.warnings.push(PackValidationIssue {
                code: "W004".to_string(),
                message: format!("Keyword '{keyword}' not found in any pattern"),
                suggestion: Some(
                    "Keywords should match substrings in patterns for efficient filtering"
                        .to_string(),
                ),
            });
        }
    }

    // === Suggestions (informational) ===

    // Suggest adding keywords if none defined
    if pack.keywords.is_empty()
        && (!pack.destructive_patterns.is_empty() || !pack.safe_patterns.is_empty())
    {
        result.suggestions.push(PackValidationIssue {
            code: "S001".to_string(),
            message: "No keywords defined".to_string(),
            suggestion: Some(
                "Adding keywords improves performance by enabling quick-reject filtering"
                    .to_string(),
            ),
        });
    }

    // Add pattern and engine summary
    result.patterns = Some(PackPatternSummary {
        destructive: pack.destructive_patterns.len(),
        safe: pack.safe_patterns.len(),
    });

    let engine_summary = summarize_pack_engines(&pack);
    result.engine_summary = Some(PackEngineSummary {
        linear: engine_summary.linear_count,
        backtracking: engine_summary.backtracking_count,
        linear_percentage: engine_summary.linear_percentage(),
    });

    // Suggest optimizing if too many backtracking patterns
    if engine_summary.backtracking_count > 0 && engine_summary.linear_percentage() < 80.0 {
        let engine_infos = analyze_pack_engines(&pack);
        let backtrack_names: Vec<_> = engine_infos
            .iter()
            .filter(|e| e.engine == RegexEngineType::Backtracking)
            .map(|e| e.name.as_str())
            .collect();
        result.suggestions.push(PackValidationIssue {
            code: "S002".to_string(),
            message: format!(
                "{} of {} patterns use backtracking engine",
                engine_summary.backtracking_count,
                engine_summary.total()
            ),
            suggestion: Some(format!(
                "Patterns using backtracking: {}. Consider simplifying to avoid lookahead/lookbehind if possible.",
                backtrack_names.join(", ")
            )),
        });
    }

    output_pack_validation(&result, format, strict)
}

/// Output validation result in the specified format
fn output_pack_validation(
    result: &PackValidationOutput,
    format: PackValidateFormat,
    strict: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let has_warnings = !result.warnings.is_empty();
    let exit_error = !result.valid || (strict && has_warnings);

    match format {
        PackValidateFormat::Json => {
            println!("{}", serde_json::to_string_pretty(result)?);
        }
        PackValidateFormat::Pretty => {
            println!("{}", "Pack Validation Report".bold().cyan());
            println!();
            println!("File: {}", result.file);

            if let (Some(id), Some(name), Some(version)) =
                (&result.pack_id, &result.pack_name, &result.pack_version)
            {
                println!();
                println!("{} Pack ID: {}", "✓".green(), id);
                println!("{} Name: {}", "✓".green(), name);
                println!("{} Version: {}", "✓".green(), version);
            }

            if let Some(patterns) = &result.patterns {
                println!();
                println!("{}", "Patterns:".bold());
                println!(
                    "  {} destructive patterns",
                    patterns.destructive.to_string().cyan()
                );
                println!("  {} safe patterns", patterns.safe.to_string().cyan());
            }

            if let Some(engines) = &result.engine_summary {
                println!();
                println!("{}", "Engine Analysis:".bold());
                println!(
                    "  {} linear (O(n)), {} backtracking ({:.0}% linear)",
                    engines.linear.to_string().green(),
                    engines.backtracking.to_string().yellow(),
                    engines.linear_percentage
                );
            }

            if !result.errors.is_empty() {
                println!();
                println!("{}", "Errors:".bold().red());
                for err in &result.errors {
                    println!("  {} [{}] {}", "✗".red(), err.code, err.message);
                    if let Some(suggestion) = &err.suggestion {
                        println!("    {}", format!("→ {suggestion}").dimmed());
                    }
                }
            }

            if !result.warnings.is_empty() {
                println!();
                println!("{}", "Warnings:".bold().yellow());
                for warn in &result.warnings {
                    println!("  {} [{}] {}", "⚠".yellow(), warn.code, warn.message);
                    if let Some(suggestion) = &warn.suggestion {
                        println!("    {}", format!("→ {suggestion}").dimmed());
                    }
                }
            }

            if !result.suggestions.is_empty() {
                println!();
                println!("{}", "Suggestions:".bold().blue());
                for sug in &result.suggestions {
                    println!("  {} [{}] {}", "ℹ".blue(), sug.code, sug.message);
                    if let Some(suggestion) = &sug.suggestion {
                        println!("    {}", format!("→ {suggestion}").dimmed());
                    }
                }
            }

            println!();
            if result.valid && !has_warnings {
                println!("{}", "✓ Pack is valid and ready to use.".bold().green());
                if let Some(id) = &result.pack_id {
                    println!();
                    println!("Add to your config:");
                    println!(
                        "  {}",
                        format!("[packs]\ncustom_paths = [\"path/to/{id}.yaml\"]").dimmed()
                    );
                }
            } else if result.valid {
                println!("{}", "✓ Pack is valid (with warnings).".bold().yellow());
            } else {
                println!("{}", "✗ Pack validation failed.".bold().red());
            }
        }
    }

    if exit_error {
        std::process::exit(1);
    }
    Ok(())
}

// Type alias for validation output to avoid repeating the struct definition
#[derive(serde::Serialize)]
struct PackValidationOutput {
    valid: bool,
    file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pack_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pack_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pack_version: Option<String>,
    errors: Vec<PackValidationIssue>,
    warnings: Vec<PackValidationIssue>,
    suggestions: Vec<PackValidationIssue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    patterns: Option<PackPatternSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    engine_summary: Option<PackEngineSummary>,
}

#[derive(serde::Serialize)]
struct PackValidationIssue {
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    suggestion: Option<String>,
}

#[derive(serde::Serialize)]
struct PackPatternSummary {
    destructive: usize,
    safe: usize,
}

#[derive(serde::Serialize)]
struct PackEngineSummary {
    linear: usize,
    backtracking: usize,
    linear_percentage: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InteractiveDecision {
    Block,
    AllowOnce,
    AddToAllowlist,
    ShowDetails,
}

fn should_prompt_interactively(
    format: TestFormat,
    verbosity: Verbosity,
    mode: DecisionMode,
    severity: Option<PackSeverity>,
    interactive_config: &InteractiveConfig,
) -> bool {
    if format == TestFormat::Json || verbosity.quiet {
        return false;
    }

    if mode != DecisionMode::Deny {
        return false;
    }

    if !matches!(severity, Some(PackSeverity::Medium | PackSeverity::Low)) {
        return false;
    }

    if std::env::var("DCG_NON_INTERACTIVE").is_ok() || std::env::var("CI").is_ok() {
        return false;
    }

    if check_interactive_available(interactive_config).is_err() {
        return false;
    }

    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

fn prompt_for_block_action() -> InteractiveDecision {
    let options = vec![
        "Block this command (recommended)",
        "Allow once (this time only)",
        "Add to allowlist (remember for future)",
        "Show more details",
    ];

    let selection = Select::new("What would you like to do?", options)
        .with_help_message("Use arrow keys to select, Enter to confirm")
        .prompt();

    match selection {
        Ok("Allow once (this time only)") => InteractiveDecision::AllowOnce,
        Ok("Add to allowlist (remember for future)") => InteractiveDecision::AddToAllowlist,
        Ok("Show more details") => InteractiveDecision::ShowDetails,
        _ => InteractiveDecision::Block,
    }
}

/// Security-aware interactive prompt with verification code.
///
/// This prompt requires the user to type a random verification code before
/// allowing bypass of a blocked command. This prevents automated tools
/// (like AI agents) from bypassing security controls.
///
/// Returns the allowlist scope if verification succeeds, or None if the
/// user cancels, times out, or enters an invalid code.
fn prompt_secure_bypass(
    command: &str,
    reason: &str,
    rule_id: Option<&str>,
    config: &InteractiveConfig,
) -> Option<AllowlistScope> {
    use colored::Colorize;

    // Check if interactive mode is available
    if let Err(reason) = check_interactive_available(config) {
        print_not_available_message(&reason);
        return None;
    }

    // Run the security-aware prompt
    match run_interactive_prompt(command, reason, rule_id, config) {
        InteractiveResult::AllowlistRequested(scope) => Some(scope),
        InteractiveResult::InvalidCode => {
            eprintln!(
                "{}",
                "Invalid verification code. Command remains blocked.".red()
            );
            None
        }
        InteractiveResult::Timeout => {
            eprintln!("{}", "Timeout. Command remains blocked.".yellow());
            None
        }
        InteractiveResult::Cancelled => {
            eprintln!("{}", "Cancelled. Command remains blocked.".bright_black());
            None
        }
        InteractiveResult::NotAvailable(reason) => {
            print_not_available_message(&reason);
            None
        }
    }
}

/// Check if the security-aware prompt should be used instead of the simple prompt.
///
/// The security-aware prompt is used for:
/// - Critical severity blocks (always require verification)
/// - High severity blocks (require verification)
///
/// For medium/low severity blocks, the simpler inquire-based prompt is used
/// for better UX during testing.
fn should_use_secure_prompt(severity: Option<PackSeverity>) -> bool {
    matches!(severity, Some(PackSeverity::Critical | PackSeverity::High))
}

fn prompt_allowlist_reason(default_reason: &str) -> String {
    Text::new("Reason for allowlisting?")
        .with_initial_value(default_reason)
        .prompt()
        .unwrap_or_else(|_| default_reason.to_string())
}

fn resolve_mode_for_cli(
    config: &Config,
    command: &str,
    result: &EvaluationResult,
) -> Option<DecisionMode> {
    let info = result.pattern_info.as_ref()?;
    let pack = info.pack_id.as_deref();
    let pattern = info.pattern_name.as_deref();

    let mut mode = match info.source {
        MatchSource::Pack | MatchSource::HeredocAst => {
            config.policy().resolve_mode(pack, pattern, info.severity)
        }
        MatchSource::ConfigOverride | MatchSource::LegacyPattern => DecisionMode::Deny,
    };

    if matches!(info.source, MatchSource::Pack | MatchSource::HeredocAst) {
        let sanitized = crate::context::sanitize_for_pattern_matching(command);
        let normalized_command = crate::normalize::normalize_command(command);
        let normalized_sanitized = crate::normalize::normalize_command(sanitized.as_ref());

        let mut confidence_command = command;
        let mut confidence_sanitized: Option<&str> = None;

        if normalized_command.len() == normalized_sanitized.len() {
            confidence_command = normalized_command.as_ref();
            if sanitized.as_ref() != command {
                confidence_sanitized = Some(normalized_sanitized.as_ref());
            }
        }

        let confidence_result = crate::apply_confidence_scoring(
            confidence_command,
            confidence_sanitized,
            result,
            mode,
            &config.confidence,
        );
        mode = confidence_result.mode;
    }

    Some(mode)
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
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn test_command(
    config: &Config,
    command: &str,
    extra_packs: Option<Vec<String>>,
    format: TestFormat,
    verbosity: Verbosity,
    no_color: bool,
    robot_mode: bool,
    heredoc_scan: bool,
    no_heredoc_scan: bool,
    heredoc_timeout_ms: Option<u64>,
    heredoc_languages: Option<Vec<String>>,
) -> bool {
    use std::time::Instant;

    if verbosity.quiet {
        return false; // Not blocked in quiet mode
    }

    if verbosity.is_trace() && format == TestFormat::Pretty {
        handle_explain(config, command, ExplainFormat::Pretty, extra_packs);
        return false; // Explain mode doesn't track blocked status
    }

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
    let keyword_index = REGISTRY.build_enabled_keyword_index(&ordered_packs);
    let heredoc_settings = effective_config.heredoc_settings();

    // Compile overrides once (not per-command)
    let compiled_overrides = effective_config.overrides.compile();

    // Load allowlists (project/user/system) for parity with hook mode.
    // This is a small file read and only affects decisions when a rule matches.
    let allowlists = load_default_allowlists();

    // Detect the current AI coding agent for agent-specific profiles
    let detection = detect_agent_with_details();
    let trust_level = effective_config.trust_level_for_agent(&detection.agent);
    let agent_info = AgentInfo {
        detected: detection.agent.config_key().to_string(),
        trust_level: format!("{:?}", trust_level).to_lowercase(),
        detection_method: match detection.method {
            DetectionMethod::Environment => "environment_variable".to_string(),
            DetectionMethod::Explicit => "explicit".to_string(),
            DetectionMethod::Process => "process".to_string(),
            DetectionMethod::None => "none".to_string(),
        },
    };

    // TODO: External pack loading is not yet implemented.
    // When ExternalPackLoader is implemented, load custom YAML packs here.

    // Use shared evaluator for consistent behavior with hook mode
    let start = Instant::now();
    let result = evaluate_command_with_pack_order_deadline_at_path(
        command,
        &enabled_keywords,
        &ordered_packs,
        keyword_index.as_ref(),
        &compiled_overrides,
        &allowlists,
        &heredoc_settings,
        None, // allow_once_audit
        None, // project_path
        None, // deadline
    );
    let elapsed = start.elapsed();

    // Handle JSON output
    if format == TestFormat::Json {
        let output = match result.decision {
            EvaluationDecision::Allow => {
                let allowlist =
                    result
                        .allowlist_override
                        .as_ref()
                        .map(|info| AllowlistOverrideInfo {
                            layer: info.layer.label().to_string(),
                            reason: info.reason.clone(),
                        });
                TestOutput {
                    schema_version: TEST_OUTPUT_SCHEMA_VERSION,
                    dcg_version: env!("CARGO_PKG_VERSION").to_string(),
                    robot_mode,
                    command: command.to_string(),
                    decision: "allow".to_string(),
                    rule_id: None,
                    pack_id: None,
                    pattern_name: None,
                    reason: None,
                    explanation: None,
                    source: None,
                    matched_span: None,
                    severity: None,
                    allowlist,
                    agent: Some(agent_info.clone()),
                }
            }
            EvaluationDecision::Deny => {
                let (
                    pack_id,
                    pattern_name,
                    reason,
                    explanation,
                    source_str,
                    matched_span,
                    rule_id,
                    severity,
                ) = result.pattern_info.as_ref().map_or(
                    (None, None, None, None, None, None, None, None),
                    |info| {
                        let source_str = match info.source {
                            MatchSource::ConfigOverride => "config_override",
                            MatchSource::LegacyPattern => "legacy_pattern",
                            MatchSource::Pack => "pack",
                            MatchSource::HeredocAst => "heredoc_ast",
                        };
                        let rule_id = info
                            .pack_id
                            .as_ref()
                            .and_then(|p| info.pattern_name.as_ref().map(|n| format!("{p}:{n}")));
                        let severity_str = info.severity.map(|s| match s {
                            PackSeverity::Critical => "critical",
                            PackSeverity::High => "high",
                            PackSeverity::Medium => "medium",
                            PackSeverity::Low => "low",
                        });
                        (
                            info.pack_id.clone(),
                            info.pattern_name.clone(),
                            Some(info.reason.clone()),
                            info.explanation.clone(),
                            Some(source_str.to_string()),
                            info.matched_span.as_ref().map(|s| (s.start, s.end)),
                            rule_id,
                            severity_str.map(std::string::ToString::to_string),
                        )
                    },
                );
                TestOutput {
                    schema_version: TEST_OUTPUT_SCHEMA_VERSION,
                    dcg_version: env!("CARGO_PKG_VERSION").to_string(),
                    robot_mode,
                    command: command.to_string(),
                    decision: "deny".to_string(),
                    rule_id,
                    pack_id,
                    pattern_name,
                    reason,
                    explanation,
                    source: source_str,
                    matched_span,
                    severity,
                    allowlist: None,
                    agent: Some(agent_info.clone()),
                }
            }
        };
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return result.decision == EvaluationDecision::Deny;
    }

    // Pretty output (default)
    // Use color based on terminal detection and --no-color flag
    let use_color = !no_color && should_use_color();

    // Use default window width for highlighting
    let term_width = DEFAULT_WINDOW_WIDTH;

    // Build highlight label if we have span info
    let highlight_info = result.pattern_info.as_ref().and_then(|info| {
        info.matched_span.as_ref().map(|span| {
            let label = info
                .pack_id
                .as_ref()
                .and_then(|pack| {
                    info.pattern_name
                        .as_ref()
                        .map(|pattern| format!("Matched: {pack}:{pattern}"))
                })
                .or_else(|| info.pack_id.as_ref().map(|p| format!("Matched: {p}")))
                .unwrap_or_else(|| "Matched destructive pattern".to_string());
            (span, label)
        })
    });

    // Print command with highlighting if available
    if let Some((span, label)) = &highlight_info {
        let highlight_span = HighlightSpan::with_label(span.start, span.end, label.clone());
        let highlighted =
            format_highlighted_command(command, &highlight_span, use_color, term_width);
        println!("Command: {}", highlighted.command_line);
        println!("         {}", highlighted.caret_line);
        if let Some(ref label_line) = highlighted.label_line {
            println!("         {label_line}");
        }
    } else {
        println!("Command: {command}");
    }
    println!();

    let resolved_mode = resolve_mode_for_cli(&effective_config, command, &result);

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
            let mut result_line = "Result: BLOCKED".to_string();

            if let Some(ref info) = result.pattern_info {
                if let Some(ref pack_id) = info.pack_id {
                    println!("Pack: {pack_id}");
                }
                if let Some(ref pattern_name) = info.pattern_name {
                    println!("Pattern: {pattern_name}");
                }
                println!("Reason: {}", info.reason);
                if let Some(ref explanation) = info.explanation {
                    println!("Explanation: {explanation}");
                }
                let source = match info.source {
                    MatchSource::ConfigOverride => "config override",
                    MatchSource::LegacyPattern => "legacy pattern",
                    MatchSource::Pack => "pack",
                    MatchSource::HeredocAst => "heredoc/inline script (AST)",
                };
                println!("Source: {source}");

                let rule_id = info
                    .pack_id
                    .as_ref()
                    .zip(info.pattern_name.as_ref())
                    .map(|(pack, pattern)| format!("{pack}:{pattern}"));
                let mode = resolved_mode.unwrap_or(DecisionMode::Deny);

                match mode {
                    DecisionMode::Warn => {
                        result_line = "Result: WARN (policy allows)".to_string();
                    }
                    DecisionMode::Log => {
                        result_line = "Result: LOG (policy allows)".to_string();
                    }
                    DecisionMode::Deny => {
                        // For critical/high severity, use security-aware prompt
                        // For medium/low severity, use simpler inquire-based prompt
                        if should_use_secure_prompt(info.severity) {
                            // Security-aware prompt with verification code
                            if let Some(scope) = prompt_secure_bypass(
                                command,
                                &info.reason,
                                rule_id.as_deref(),
                                &effective_config.interactive,
                            ) {
                                match scope {
                                    AllowlistScope::Once => {
                                        result_line =
                                            "Result: ALLOWED (once, not persisted)".to_string();
                                    }
                                    AllowlistScope::Session => {
                                        result_line = "Result: ALLOWED (session only)".to_string();
                                    }
                                    AllowlistScope::Temporary(duration) => {
                                        let hours = duration.as_secs() / 3600;
                                        result_line =
                                            format!("Result: ALLOWED (temporary, {hours} hours)");
                                    }
                                    AllowlistScope::Permanent => {
                                        let layer = resolve_layer(false, false);
                                        let reason =
                                            "Verified bypass via dcg test (security prompt)";
                                        let add_result = rule_id.as_ref().map_or_else(
                                            || allowlist_add_command(command, reason, layer, None),
                                            |rule_id| {
                                                allowlist_add_rule(
                                                    rule_id,
                                                    reason,
                                                    layer,
                                                    None,
                                                    &[],
                                                )
                                            },
                                        );

                                        if let Err(err) = add_result {
                                            eprintln!("Allowlist update failed: {err}");
                                            result_line = "Result: BLOCKED".to_string();
                                        } else {
                                            result_line = format!(
                                                "Result: ALLOWED (allowlisted in {})",
                                                layer.label()
                                            );
                                        }
                                    }
                                }
                            }
                            // If prompt_secure_bypass returns None, result_line stays at BLOCKED
                        } else if should_prompt_interactively(
                            format,
                            verbosity,
                            mode,
                            info.severity,
                            &effective_config.interactive,
                        ) {
                            // Simpler inquire-based prompt for medium/low severity
                            let action = loop {
                                let choice = prompt_for_block_action();
                                if choice == InteractiveDecision::ShowDetails {
                                    handle_explain(
                                        &effective_config,
                                        command,
                                        ExplainFormat::Pretty,
                                        None,
                                    );
                                    println!();
                                } else {
                                    break choice;
                                }
                            };

                            match action {
                                InteractiveDecision::AllowOnce => {
                                    result_line =
                                        "Result: ALLOWED (allow once, not persisted)".to_string();
                                }
                                InteractiveDecision::AddToAllowlist => {
                                    let layer = resolve_layer(false, false);
                                    let reason = prompt_allowlist_reason(
                                        "Interactive approval via dcg test",
                                    );
                                    let add_result = rule_id.as_ref().map_or_else(
                                        || allowlist_add_command(command, &reason, layer, None),
                                        |rule_id| {
                                            allowlist_add_rule(rule_id, &reason, layer, None, &[])
                                        },
                                    );

                                    if let Err(err) = add_result {
                                        eprintln!("Allowlist update failed: {err}");
                                        result_line = "Result: BLOCKED".to_string();
                                    } else {
                                        result_line = format!(
                                            "Result: ALLOWED (allowlisted in {})",
                                            layer.label()
                                        );
                                    }
                                }
                                InteractiveDecision::Block | InteractiveDecision::ShowDetails => {}
                            }
                        }
                    }
                }
            }

            println!("{result_line}");
        }
    }

    if verbosity.is_verbose() {
        println!("Elapsed: {:.2}ms", elapsed.as_secs_f64() * 1000.0);
        println!("Agent: {}", detection.agent);
        println!("Trust level: {}", agent_info.trust_level);
        if let Some(ref info) = result.pattern_info {
            if let Some(severity) = info.severity {
                println!("Severity: {}", severity.label());
            }
        }
    }

    if verbosity.is_debug() {
        // Agent detection details
        println!("Agent detection:");
        println!(
            "  Detected: {} ({})",
            detection.agent,
            detection.agent.config_key()
        );
        println!("  Method: {}", agent_info.detection_method);
        if let Some(ref matched) = detection.matched_value {
            println!("  Matched: {matched}");
        }
        println!("  Profile: agents.{}", detection.agent.config_key());
        println!("  Trust level: {}", agent_info.trust_level);

        if let Some(ref info) = result.pattern_info {
            if let Some(ref pack_id) = info.pack_id {
                if let Some(ref pattern_name) = info.pattern_name {
                    println!("Rule: {pack_id}:{pattern_name}");
                }
            }
            if let Some(ref span) = info.matched_span {
                println!("Match span: {}..{}", span.start, span.end);
            }
            if let Some(ref preview) = info.matched_text_preview {
                println!("Match preview: \"{preview}\"");
            }
        }
        let normalized = crate::normalize::normalize_command(command);
        if normalized.as_ref() != command {
            println!("Normalized: {normalized}");
        }
    }

    // Return true if the command was blocked (for exit code handling)
    result.decision == EvaluationDecision::Deny
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
    verbosity: Verbosity,
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

    if !verbosity.quiet {
        if verbosity.is_debug() {
            eprintln!(
                "Simulate settings: format={format:?}, strict={strict}, max_command_bytes={max_command_bytes}"
            );
        }
        if verbosity.is_trace() {
            eprintln!(
                "Simulate input: file={file}, max_lines={max_lines:?}, max_bytes={max_bytes:?}, top={top}, truncate={truncate}, redact={redact:?}"
            );
        }
    }

    // Run simulation with evaluation loop
    let result = run_simulation_from_reader(reader, limits, config, sim_config, strict)?;

    // Build output configuration
    let output_config = SimulateOutputConfig {
        redact,
        truncate,
        top,
        verbose: verbosity.is_verbose(),
    };

    if verbosity.quiet {
        return Ok(());
    }

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
    verbosity: Verbosity,
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
        top,
        action,
    } = scan;
    let effective_verbose = verbosity.is_verbose();
    let quiet = verbosity.quiet;
    let debug = verbosity.is_debug();
    let trace = verbosity.is_trace();

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
                effective_verbose,
                quiet,
                debug,
                trace,
                top,
            )?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::needless_pass_by_value)] // Values consumed from CLI args
#[allow(clippy::fn_params_excessive_bools)]
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
    quiet: bool,
    debug: bool,
    trace: bool,
    top: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::output::progress::MaybeProgress;
    use crate::scan::{ScanEvalContext, ScanOptions, scan_paths_with_progress, should_fail};

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
        return Err("No file selection mode specified".into());
    };

    if !quiet {
        if verbose {
            eprintln!("Scanning {} path(s)", scan_paths_list.len());
        }
        if debug {
            eprintln!(
                "Scan settings: format={format:?}, fail_on={fail_on:?}, max_file_size={max_file_size}, max_findings={max_findings}"
            );
        }
        if trace {
            eprintln!(
                "Scan filters: include={include:?}, exclude={exclude:?}, truncate={truncate}, redact={redact:?}"
            );
        }
    }

    // Run scan with progress reporting
    let repo_root = find_repo_root_from_cwd();

    // Create progress tracker lazily when we know total file count
    // Use RefCell to allow mutation inside the closure
    use std::cell::RefCell;
    let progress: RefCell<Option<MaybeProgress>> = RefCell::new(None);

    let mut progress_callback = |current: usize, total: usize, file: &str| {
        if current == 0 {
            // First call signals total file count - initialize progress
            if !quiet {
                *progress.borrow_mut() = Some(MaybeProgress::new(total as u64));
            }
        } else if let Some(ref p) = *progress.borrow() {
            // Subsequent calls tick the progress bar
            p.tick(file);
        }
    };

    let report = scan_paths_with_progress(
        &scan_paths_list,
        &options,
        config,
        &ctx,
        include,
        exclude,
        repo_root.as_deref(),
        if quiet {
            None
        } else {
            Some(&mut progress_callback)
        },
    )?;

    // Finish progress bar if it was created
    if let Some(ref p) = *progress.borrow() {
        p.finish_and_clear();
    }

    // Output results
    if !quiet {
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
            crate::scan::ScanFormat::Sarif => {
                let sarif = crate::sarif::SarifReport::from_scan_report(&report);
                let json = serde_json::to_string_pretty(&sarif)?;
                println!("{json}");
            }
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

/// Print scan report in pretty format.
#[cfg(not(feature = "rich-output"))]
fn print_scan_pretty(report: &crate::scan::ScanReport, verbose: bool, top: usize) {
    use crate::output::{ScanResultRow, ScanResultsTable, TableStyle, auto_theme};
    use colored::Colorize;

    if report.findings.is_empty() {
        println!("{}", "No findings.".green());
    } else {
        let total = report.findings.len();
        let shown = if top == 0 { total } else { total.min(top) };
        println!("{} finding(s):", total.to_string().yellow().bold());
        println!();

        // Render findings as a table
        let rows: Vec<ScanResultRow> = report
            .findings
            .iter()
            .take(shown)
            .map(ScanResultRow::from_scan_finding)
            .collect();

        let theme = auto_theme();
        let table = ScanResultsTable::new(rows)
            .with_theme(&theme)
            .with_style(TableStyle::Ascii)
            .with_command_preview();

        println!("{}", table.render());

        // Show detailed info for findings with reasons/suggestions
        let findings_with_details: Vec<_> = report
            .findings
            .iter()
            .take(shown)
            .filter(|f| f.reason.is_some() || f.suggestion.is_some())
            .collect();

        if !findings_with_details.is_empty() && verbose {
            println!();
            println!("{}", "Details:".bold());
            for finding in findings_with_details {
                let location = finding.col.map_or_else(
                    || format!("{}:{}", finding.file, finding.line),
                    |col| format!("{}:{}:{col}", finding.file, finding.line),
                );
                println!("  {}", location.dimmed());
                if let Some(ref reason) = finding.reason {
                    println!("    Reason: {reason}");
                }
                if let Some(ref suggestion) = finding.suggestion {
                    println!("    Suggestion: {}", suggestion.green());
                }
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

/// Print scan report in pretty format with rich output.
#[cfg(feature = "rich-output")]
fn print_scan_pretty(report: &crate::scan::ScanReport, verbose: bool, top: usize) {
    use crate::output::console::console;
    use crate::output::{ScanResultRow, ScanResultsTable, auto_theme};

    let con = console();

    if report.findings.is_empty() {
        con.print("[green]No findings.[/]");
    } else {
        let total = report.findings.len();
        let shown = if top == 0 { total } else { total.min(top) };

        con.rule(Some("[bold] Scan Findings [/]"));
        con.print(&format!("[yellow bold]{total}[/] finding(s)"));
        con.print("");

        // Render findings as a table using rich_rust
        let rows: Vec<ScanResultRow> = report
            .findings
            .iter()
            .take(shown)
            .map(ScanResultRow::from_scan_finding)
            .collect();

        let theme = auto_theme();
        let table = ScanResultsTable::new(rows)
            .with_theme(&theme)
            .with_command_preview();

        con.print(&table.render());

        // Show detailed info for findings with reasons/suggestions
        let findings_with_details: Vec<_> = report
            .findings
            .iter()
            .take(shown)
            .filter(|f| f.reason.is_some() || f.suggestion.is_some())
            .collect();

        if !findings_with_details.is_empty() && verbose {
            con.print("");
            con.print("[bold]Details:[/]");
            for finding in findings_with_details {
                let location = finding.col.map_or_else(
                    || format!("{}:{}", finding.file, finding.line),
                    |col| format!("{}:{}:{col}", finding.file, finding.line),
                );
                con.print(&format!("  [dim]{location}[/]"));
                if let Some(ref reason) = finding.reason {
                    con.print(&format!("    [cyan]Reason:[/] {reason}"));
                }
                if let Some(ref suggestion) = finding.suggestion {
                    con.print(&format!("    [green]Suggestion:[/] {suggestion}"));
                }
            }
        }

        if shown < total {
            con.print("");
            con.print(&format!(
                "[dim]… {} more finding(s) not shown (use --top 0 to show all)[/]",
                total - shown
            ));
        }
    }

    // Summary
    con.print("");
    con.print("[dim]───[/]");
    let considered = report.summary.files_scanned + report.summary.files_skipped;
    con.print(&format!(
        "[cyan]Files:[/] {considered} considered, {} scanned, {} skipped",
        report.summary.files_scanned, report.summary.files_skipped
    ));
    con.print(&format!(
        "[cyan]Commands extracted:[/] {}",
        report.summary.commands_extracted
    ));
    con.print(&format!(
        "[cyan]Findings:[/] {} ([green]allow={}[/], [yellow]warn={}[/], [red]deny={}[/])",
        report.summary.findings_total,
        report.summary.decisions.allow,
        report.summary.decisions.warn,
        report.summary.decisions.deny
    ));
    con.print(&format!(
        "[cyan]Severities:[/] [red]error={}[/], [yellow]warning={}[/], [blue]info={}[/]",
        report.summary.severities.error,
        report.summary.severities.warning,
        report.summary.severities.info
    ));

    if let Some(elapsed_ms) = report.summary.elapsed_ms {
        con.print(&format!("[cyan]Elapsed:[/] {elapsed_ms} ms"));
    }

    if report.summary.max_findings_reached {
        con.print("[yellow]Note: max findings limit reached, scan stopped early[/]");
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
    let keyword_index = REGISTRY.build_enabled_keyword_index(&ordered_packs);
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
        keyword_index.as_ref(),
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
            explanation: pattern.explanation.clone(),
        });
    }

    // Finish and get trace
    let trace = collector.finish(result.decision);

    // Format and print based on selected format
    match format {
        ExplainFormat::Pretty => {
            #[cfg(feature = "rich-output")]
            {
                explain_rich(&trace);
            }
            #[cfg(not(feature = "rich-output"))]
            {
                let output =
                    trace.format_pretty(colored::control::SHOULD_COLORIZE.should_colorize());
                println!("{output}");
            }
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

/// Rich output for explain command with tree visualization.
#[cfg(feature = "rich-output")]
fn explain_rich(trace: &crate::trace::ExplainTrace) {
    use crate::evaluator::EvaluationDecision;
    use crate::output::console::console;
    use crate::trace::TraceDetails;

    let con = console();

    // Header
    con.rule(Some("[bold] DCG EXPLAIN [/]"));
    con.print("");

    // Decision with color
    let (decision_icon, decision_color, decision_text) = match trace.decision {
        EvaluationDecision::Allow => ("✓", "green", "ALLOW"),
        EvaluationDecision::Deny => ("✗", "red", "DENY"),
    };
    con.print(&format!(
        "[bold]Decision:[/] [{decision_color} bold]{decision_icon} {decision_text}[/]"
    ));
    con.print(&format!(
        "[bold]Latency:[/]  [dim]{:.2}ms[/]",
        trace.total_duration_us as f64 / 1000.0
    ));
    con.print("");

    // Command tree
    con.print("[bold cyan]Command[/]");
    let has_normalized = trace
        .normalized_command
        .as_ref()
        .is_some_and(|n| n != &trace.command);
    let has_sanitized = trace
        .sanitized_command
        .as_ref()
        .is_some_and(|s| s != &trace.command && Some(s) != trace.normalized_command.as_ref());

    if has_normalized || has_sanitized {
        con.print(&format!("├─ [cyan]Input:[/]      {}", trace.command));
        if has_normalized {
            let branch = if has_sanitized { "├─" } else { "└─" };
            con.print(&format!(
                "{branch} [cyan]Normalized:[/] {}",
                trace.normalized_command.as_ref().unwrap()
            ));
        }
        if has_sanitized {
            con.print(&format!(
                "└─ [cyan]Sanitized:[/]  {}",
                trace.sanitized_command.as_ref().unwrap()
            ));
        }
    } else {
        con.print(&format!("└─ [cyan]Input:[/] {}", trace.command));
    }
    con.print("");

    // Match tree (for denials or when there's match info)
    if let Some(ref info) = trace.match_info {
        con.print("[bold yellow]Match[/]");

        let has_explanation = info.explanation.is_some();
        let mut items: Vec<(&str, String)> = vec![];

        if let Some(ref rule_id) = info.rule_id {
            items.push(("Rule ID", format!("[yellow]{rule_id}[/]")));
        }
        if let Some(ref pack_id) = info.pack_id {
            items.push(("Pack", pack_id.clone()));
        }
        if let Some(ref pattern) = info.pattern_name {
            items.push(("Pattern", pattern.clone()));
        }
        items.push(("Reason", info.reason.clone()));

        if let (Some(start), Some(end)) = (info.match_start, info.match_end) {
            items.push(("Span", format!("bytes {start}..{end}")));
        }
        if let Some(ref preview) = info.matched_text_preview {
            items.push(("Matched", format!("[red]{preview}[/]")));
        }

        for (i, (label, value)) in items.iter().enumerate() {
            let branch = if i == items.len() - 1 && !has_explanation {
                "└─"
            } else {
                "├─"
            };
            con.print(&format!("{branch} [cyan]{label}:[/] {value}"));
        }

        if let Some(ref explanation) = info.explanation {
            con.print("└─ [cyan]Explanation:[/]");
            for line in explanation.lines() {
                con.print(&format!("   [dim]{line}[/]"));
            }
        }
        con.print("");
    }

    // Allowlist override
    if let Some(ref al_info) = trace.allowlist_info {
        con.print("[bold green]Allowlist Override[/]");
        con.print(&format!("├─ [cyan]Layer:[/]  {:?}", al_info.layer));
        con.print(&format!("├─ [cyan]Reason:[/] {}", al_info.entry_reason));
        con.print(&format!(
            "└─ [dim]Overrode: {} - {}[/]",
            al_info
                .original_match
                .rule_id
                .as_deref()
                .unwrap_or("unknown"),
            al_info.original_match.reason
        ));
        con.print("");
    }

    // Pack summary tree
    if let Some(ref summary) = trace.pack_summary {
        con.print("[bold magenta]Packs[/]");
        con.print(&format!(
            "├─ [cyan]Enabled:[/] {} packs",
            summary.enabled_count
        ));

        if !summary.evaluated.is_empty() {
            let branch = if summary.skipped.is_empty() {
                "└─"
            } else {
                "├─"
            };
            con.print(&format!(
                "{branch} [cyan]Evaluated:[/] {}",
                summary.evaluated.join(", ")
            ));
        }

        if !summary.skipped.is_empty() {
            con.print(&format!(
                "└─ [dim]Skipped (keyword gating): {}[/]",
                summary.skipped.join(", ")
            ));
        }
        con.print("");
    }

    // Pipeline trace tree
    if !trace.steps.is_empty() {
        con.print("[bold blue]Pipeline Trace[/]");
        let step_count = trace.steps.len();

        for (i, step) in trace.steps.iter().enumerate() {
            let branch = if i == step_count - 1 {
                "└─"
            } else {
                "├─"
            };
            let duration_ms = step.duration_us as f64 / 1000.0;

            // Format details summary
            let details_summary = match &step.details {
                TraceDetails::KeywordGating {
                    quick_rejected,
                    first_match,
                    ..
                } => {
                    if *quick_rejected {
                        "[green]quick pass[/]".to_string()
                    } else if let Some(kw) = first_match {
                        format!("matched: {kw}")
                    } else {
                        "no match".to_string()
                    }
                }
                TraceDetails::Normalization { was_modified, .. } => if *was_modified {
                    "modified"
                } else {
                    "unchanged"
                }
                .to_string(),
                TraceDetails::Sanitization {
                    was_modified,
                    spans_masked,
                    ..
                } => {
                    if *was_modified {
                        format!("{spans_masked} spans masked")
                    } else {
                        "unchanged".to_string()
                    }
                }
                TraceDetails::HeredocDetection {
                    triggered,
                    scripts_extracted,
                    ..
                } => {
                    if *triggered {
                        format!("{scripts_extracted} scripts")
                    } else {
                        "none".to_string()
                    }
                }
                TraceDetails::AllowlistCheck {
                    matched,
                    matched_layer,
                    ..
                } => {
                    if *matched {
                        format!("matched: {:?}", matched_layer.as_ref().unwrap())
                    } else {
                        "no match".to_string()
                    }
                }
                TraceDetails::PackEvaluation {
                    matched_pack,
                    packs_evaluated,
                    ..
                } => {
                    if let Some(pack) = matched_pack {
                        format!("matched in {pack}")
                    } else {
                        format!("{} packs checked", packs_evaluated.len())
                    }
                }
                TraceDetails::PolicyDecision { decision, .. } => match decision {
                    EvaluationDecision::Allow => "[green]allow[/]".to_string(),
                    EvaluationDecision::Deny => "[red]deny[/]".to_string(),
                },
                _ => String::new(),
            };

            con.print(&format!(
                "{branch} [cyan]{:<18}[/] [dim]({:>6.2}ms)[/] {}",
                step.name, duration_ms, details_summary
            ));
        }
        con.print("");
    }

    // Suggestions
    if let Some(ref info) = trace.match_info {
        if let Some(rule_id) = info.rule_id.as_deref() {
            if let Some(suggestions) = crate::suggestions::get_suggestions(rule_id) {
                if !suggestions.is_empty() && crate::output::suggestions_enabled() {
                    con.print("[bold yellow]Suggestions[/]");
                    let suggestion_count = suggestions.len();

                    for (i, s) in suggestions.iter().enumerate() {
                        let branch = if i == suggestion_count - 1 {
                            "└─"
                        } else {
                            "├─"
                        };
                        con.print(&format!(
                            "{branch} [yellow]{}[/]: {}",
                            s.kind.label(),
                            s.text
                        ));
                        if let Some(ref cmd) = s.command {
                            con.print(&format!("   [dim]$[/] [green]{cmd}[/]"));
                        }
                        if let Some(ref url) = s.url {
                            con.print(&format!("   [dim]→ {url}[/]"));
                        }
                    }
                }
            }
        }
    }
}

// =============================================================================
// =============================================================================
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

    /// Tier 1 heredoc/inline-script trigger indices on the raw command.
    ///
    /// This is intended for debugging false positives in the regression corpus.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    heredoc_triggers: Vec<usize>,

    /// Tier 1 trigger indices after safe-string sanitization (only populated when
    /// sanitization changes the command and triggers are re-evaluated).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    heredoc_triggers_sanitized: Vec<usize>,

    /// If Tier 1 triggered on the raw command but sanitization removed all triggers,
    /// records the suppression reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    heredoc_suppression_reason: Option<String>,
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
    decision: std::collections::HashMap<String, usize>,
    pack: std::collections::HashMap<String, usize>,
    category: std::collections::HashMap<String, CategoryStats>,
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
        decision: std::collections::HashMap::new(),
        pack: std::collections::HashMap::new(),
        category: std::collections::HashMap::new(),
    };

    let categories = [
        "true_positives",
        "false_positives",
        "bypass_attempts",
        "edge_cases",
    ];

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

        let Some(category) = CorpusCategory::from_dir_name(category_name) else {
            continue;
        };

        // Initialize category stats
        summary
            .category
            .entry(category_name.to_string())
            .or_default();

        // Read all TOML files in the category directory (sorted for deterministic order)
        let Ok(entries) = std::fs::read_dir(&category_dir) else {
            continue;
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
                *summary.decision.entry(result.actual.clone()).or_default() += 1;
                if let Some(ref pack) = result.pack_id {
                    *summary.pack.entry(pack.clone()).or_default() += 1;
                }

                let cat_stats = summary
                    .category
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
            if !pack_id.starts_with("core")
                && !effective_config
                    .packs
                    .enabled
                    .contains(&pack_id.to_string())
            {
                effective_config.packs.enabled.push(pack_id.to_string());
            }
        }
    }

    let enabled_packs = effective_config.enabled_pack_ids();
    let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    let keyword_index = REGISTRY.build_enabled_keyword_index(&ordered_packs);
    let compiled_overrides = effective_config.overrides.compile();
    let allowlists = crate::LayeredAllowlist::default();
    let heredoc_settings = effective_config.heredoc_settings();

    // Capture Tier 1 trigger details for debugging false positives.
    let mut heredoc_triggers = Vec::new();
    let mut heredoc_triggers_sanitized = Vec::new();
    let mut heredoc_suppression_reason = None;
    if crate::heredoc::check_triggers(&case.command) == crate::heredoc::TriggerResult::Triggered {
        heredoc_triggers = crate::heredoc::matched_triggers(&case.command);

        let sanitized = crate::context::sanitize_for_pattern_matching(&case.command);
        if matches!(sanitized, std::borrow::Cow::Owned(_)) {
            let sanitized_str = sanitized.as_ref();
            heredoc_triggers_sanitized = crate::heredoc::matched_triggers(sanitized_str);
            if heredoc_triggers_sanitized.is_empty() {
                heredoc_suppression_reason =
                    Some("sanitized_removed_all_tier1_triggers".to_string());
            }
        }
    }

    // Time the evaluation
    let start = Instant::now();
    let result = evaluate_command_with_pack_order(
        &case.command,
        &enabled_keywords,
        &ordered_packs,
        keyword_index.as_ref(),
        &compiled_overrides,
        &allowlists,
        &heredoc_settings,
    );
    let duration_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);

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
        heredoc_triggers,
        heredoc_triggers_sanitized,
        heredoc_suppression_reason,
    }
}

/// Handle the `dcg corpus` command.
fn handle_corpus_command(
    config: &Config,
    cmd: &CorpusCommand,
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

/// Handle the `dcg stats` command.
#[allow(clippy::option_if_let_else)]
fn handle_stats_command(
    config: &Config,
    cmd: &StatsCommand,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::stats;

    if quiet {
        return Ok(());
    }

    // Handle --rules mode (query history database for rule-level metrics)
    if cmd.rules {
        return handle_stats_rules(config, cmd);
    }

    // Determine log file path
    let log_path = if let Some(ref path) = cmd.file {
        path.clone()
    } else if let Some(ref log_file) = config.general.log_file {
        // Expand ~ in path
        if log_file.starts_with("~/") {
            dirs::home_dir().map_or_else(
                || std::path::PathBuf::from(log_file),
                |h| h.join(&log_file[2..]),
            )
        } else {
            std::path::PathBuf::from(log_file)
        }
    } else {
        // Default log file location
        dirs::data_local_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("~/.local/share"))
            .join("dcg")
            .join("blocked.log")
    };

    // Check if log file exists
    if !log_path.exists() {
        if matches!(cmd.format, StatsFormat::Json) {
            // Output empty stats for JSON format
            let empty_stats = stats::AggregatedStats {
                period_start: 0,
                period_end: 0,
                total_entries: 0,
                total_blocks: 0,
                total_allows: 0,
                total_bypasses: 0,
                total_warns: 0,
                by_pack: vec![],
            };
            print!("{}", stats::format_stats_json(&empty_stats));
            return Ok(());
        }
        println!("No log file found at: {}", log_path.display());
        println!();
        println!("To enable logging, add to your config (~/.config/dcg/config.toml):");
        println!();
        println!("  [general]");
        println!("  log_file = \"~/.local/share/dcg/blocked.log\"");
        println!();
        println!("Or run with --file to specify a log file directly.");
        return Ok(());
    }

    // Convert days to seconds
    let period_secs = cmd.days * 24 * 60 * 60;

    // Parse log file
    let aggregated = stats::parse_log_file(&log_path, period_secs)?;

    // Format and print output
    match cmd.format {
        StatsFormat::Pretty => {
            #[cfg(feature = "rich-output")]
            {
                format_stats_pack_rich(&aggregated, cmd.days);
            }
            #[cfg(not(feature = "rich-output"))]
            {
                print!("{}", stats::format_stats_pretty(&aggregated, cmd.days));
            }
        }
        StatsFormat::Json => {
            print!("{}", stats::format_stats_json(&aggregated));
        }
    }

    Ok(())
}

/// Handle the `dcg stats --rules` command.
fn handle_stats_rules(
    config: &Config,
    cmd: &StatsCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::history::HistoryDb;
    use chrono::{Duration, Utc};

    // Open history database
    let db_path = config.history.expanded_database_path();
    let db = match HistoryDb::open(db_path) {
        Ok(db) => db,
        Err(err) => {
            if matches!(cmd.format, StatsFormat::Json) {
                // Output empty metrics for JSON format
                print!("{}", format_rule_metrics_json(&[], cmd.days)?);
                return Ok(());
            }
            if matches!(err, crate::history::HistoryError::Disabled) {
                println!("History is disabled. Enable it in config to use rule metrics.");
                println!();
                println!("To enable history, add to your config (~/.config/dcg/config.toml):");
                println!();
                println!("  [history]");
                println!("  enabled = true");
                return Ok(());
            }
            println!("Error opening history database: {err}");
            return Ok(());
        }
    };

    // Calculate the start time based on --days
    let since = Some(Utc::now() - Duration::days(i64::try_from(cmd.days).unwrap_or(30)));

    // Query rule metrics
    let metrics = db.get_rule_metrics(since, cmd.limit)?;

    if metrics.is_empty() {
        if matches!(cmd.format, StatsFormat::Json) {
            // Output empty metrics for JSON format
            print!("{}", format_rule_metrics_json(&[], cmd.days)?);
            return Ok(());
        }
        println!("No rule metrics found in the last {} days.", cmd.days);
        println!();
        println!("Rule metrics are collected when commands are blocked or bypassed.");
        println!("Run some commands through dcg to generate metrics.");
        return Ok(());
    }

    // Format and print output
    match cmd.format {
        StatsFormat::Pretty => {
            #[cfg(feature = "rich-output")]
            {
                format_rule_metrics_rich(&metrics, cmd.days);
            }
            #[cfg(not(feature = "rich-output"))]
            {
                print!("{}", format_rule_metrics_pretty(&metrics, cmd.days));
            }
        }
        StatsFormat::Json => {
            print!("{}", format_rule_metrics_json(&metrics, cmd.days)?);
        }
    }

    Ok(())
}

/// Format rule metrics as a pretty table.
#[cfg(not(feature = "rich-output"))]
#[allow(clippy::too_many_lines)]
fn format_rule_metrics_pretty(metrics: &[crate::history::RuleMetrics], period_days: u64) -> String {
    use std::fmt::Write;

    let mut output = String::new();
    let _ = writeln!(output, "Rule Metrics (last {period_days} days):");
    let _ = writeln!(output);

    // Calculate column widths
    let max_rule_len = metrics
        .iter()
        .map(|m| m.rule_id.len())
        .max()
        .unwrap_or(10)
        .clamp(10, 40);

    // Header
    let _ = writeln!(
        output,
        "  {:<width$}  {:>6}  {:>9}  {:>7}  {:>8}  {:>8}  {:>9}",
        "Rule ID",
        "Hits",
        "Overrides",
        "Rate",
        "Trend",
        "Change",
        "Noisy",
        width = max_rule_len
    );
    let _ = writeln!(
        output,
        "  {:-<width$}  {:->6}  {:->9}  {:->7}  {:->8}  {:->8}  {:->9}",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        width = max_rule_len
    );

    // Rule rows
    for m in metrics {
        let rule_id_display = if m.rule_id.len() > max_rule_len {
            format!("{}...", &m.rule_id[..max_rule_len - 3])
        } else {
            m.rule_id.clone()
        };
        let noisy_display = if m.is_noisy { "yes" } else { "-" };
        let trend_display = match m.trend {
            crate::history::RuleTrend::Increasing => "↑",
            crate::history::RuleTrend::Stable => "→",
            crate::history::RuleTrend::Decreasing => "↓",
        };
        // Format change percentage with anomaly indicator
        let change_display = if m.change_percentage.abs() < 0.01 {
            "-".to_string()
        } else if m.is_anomaly {
            format!("{:+.0}%!", m.change_percentage)
        } else {
            format!("{:+.0}%", m.change_percentage)
        };
        let _ = writeln!(
            output,
            "  {:<width$}  {:>6}  {:>9}  {:>6.1}%  {:>8}  {:>8}  {:>9}",
            rule_id_display,
            m.total_hits,
            m.allowlist_overrides,
            m.override_rate,
            trend_display,
            change_display,
            noisy_display,
            width = max_rule_len
        );
    }

    // Totals
    let total_hits: u64 = metrics.iter().map(|m| m.total_hits).sum();
    let total_overrides: u64 = metrics.iter().map(|m| m.allowlist_overrides).sum();
    #[allow(clippy::cast_precision_loss)]
    let avg_rate = if total_hits > 0 {
        (total_overrides as f64 / total_hits as f64) * 100.0
    } else {
        0.0
    };
    let _ = writeln!(
        output,
        "  {:-<width$}  {:->6}  {:->9}  {:->7}  {:->8}  {:->8}  {:->9}",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        width = max_rule_len
    );
    let _ = writeln!(
        output,
        "  {:<width$}  {:>6}  {:>9}  {:>6.1}%",
        "Total",
        total_hits,
        total_overrides,
        avg_rate,
        width = max_rule_len
    );
    let _ = writeln!(output);
    let _ = writeln!(
        output,
        "  {} rules shown (use -n to change limit)",
        metrics.len()
    );

    output
}

/// Rich output for pack statistics.
#[cfg(feature = "rich-output")]
fn format_stats_pack_rich(stats: &crate::stats::AggregatedStats, period_days: u64) {
    use crate::output::console::console;

    let con = console();

    con.rule(Some(&format!(
        "[bold] Pack Statistics ({period_days} days) [/]"
    )));
    con.print("");

    if stats.by_pack.is_empty() {
        con.print("[dim]No events recorded in this period.[/]");
        return;
    }

    // Header
    con.print("[bold cyan]Pack                      Blocks   Allows  Bypasses   Warns[/]");
    con.print("[dim]─────────────────────────────────────────────────────────────[/]");

    // Pack rows
    for pack in &stats.by_pack {
        let blocks_color = if pack.blocks > 0 { "red" } else { "dim" };
        let allows_color = if pack.allows > 0 { "green" } else { "dim" };
        let bypasses_color = if pack.bypasses > 0 { "yellow" } else { "dim" };
        let warns_color = if pack.warns > 0 { "yellow" } else { "dim" };

        con.print(&format!(
            "{:<24}  [{blocks_color}]{:>7}[/]  [{allows_color}]{:>7}[/]  [{bypasses_color}]{:>8}[/]  [{warns_color}]{:>6}[/]",
            pack.pack_id, pack.blocks, pack.allows, pack.bypasses, pack.warns
        ));
    }

    // Total row
    con.print("[dim]─────────────────────────────────────────────────────────────[/]");
    con.print(&format!(
        "[bold]{:<24}  {:>7}  {:>7}  {:>8}  {:>6}[/]",
        "Total", stats.total_blocks, stats.total_allows, stats.total_bypasses, stats.total_warns
    ));
}

/// Rich output for rule metrics.
#[cfg(feature = "rich-output")]
fn format_rule_metrics_rich(metrics: &[crate::history::RuleMetrics], period_days: u64) {
    use crate::output::console::console;

    let con = console();

    con.rule(Some(&format!(
        "[bold] Rule Metrics ({period_days} days) [/]"
    )));
    con.print("");

    // Header
    con.print("[bold cyan]Rule ID                            Hits  Overrides    Rate  Trend  Change    Noisy[/]");
    con.print("[dim]─────────────────────────────────────────────────────────────────────────────────────[/]");

    // Rule rows
    for m in metrics {
        let rule_display = if m.rule_id.len() > 32 {
            format!("{}...", &m.rule_id[..29])
        } else {
            m.rule_id.clone()
        };

        let trend_display = match m.trend {
            crate::history::RuleTrend::Increasing => "[red]↑[/]",
            crate::history::RuleTrend::Stable => "[dim]→[/]",
            crate::history::RuleTrend::Decreasing => "[green]↓[/]",
        };

        let change_display = if m.change_percentage.abs() < 0.01 {
            "[dim]-[/]".to_string()
        } else if m.is_anomaly {
            format!("[red bold]{:+.0}%![/]", m.change_percentage)
        } else if m.change_percentage > 0.0 {
            format!("[yellow]{:+.0}%[/]", m.change_percentage)
        } else {
            format!("[green]{:+.0}%[/]", m.change_percentage)
        };

        let noisy_display = if m.is_noisy {
            "[yellow]yes[/]"
        } else {
            "[dim]-[/]"
        };

        let rate_color = if m.override_rate > 50.0 {
            "yellow"
        } else if m.override_rate > 20.0 {
            "white"
        } else {
            "dim"
        };

        con.print(&format!(
            "{:<32}  {:>6}  {:>9}  [{rate_color}]{:>5.1}%[/]  {:>5}  {:>8}  {:>8}",
            rule_display,
            m.total_hits,
            m.allowlist_overrides,
            m.override_rate,
            trend_display,
            change_display,
            noisy_display
        ));
    }

    // Totals
    let total_hits: u64 = metrics.iter().map(|m| m.total_hits).sum();
    let total_overrides: u64 = metrics.iter().map(|m| m.allowlist_overrides).sum();
    #[allow(clippy::cast_precision_loss)]
    let avg_rate = if total_hits > 0 {
        (total_overrides as f64 / total_hits as f64) * 100.0
    } else {
        0.0
    };

    con.print("[dim]─────────────────────────────────────────────────────────────────────────────────────[/]");
    con.print(&format!(
        "[bold]{:<32}  {:>6}  {:>9}  {:>5.1}%[/]",
        "Total", total_hits, total_overrides, avg_rate
    ));
    con.print("");
    con.print(&format!(
        "[dim]{} rules shown (use -n to change limit)[/]",
        metrics.len()
    ));
}

/// JSON output structure for rule metrics.
#[derive(serde::Serialize)]
struct RuleMetricsOutput {
    period_days: u64,
    rules: Vec<RuleMetricEntry>,
    totals: RuleMetricsTotals,
}

/// Single rule entry in JSON output.
#[derive(serde::Serialize)]
struct RuleMetricEntry {
    rule_id: String,
    pack_id: String,
    pattern_name: String,
    total_hits: u64,
    allowlist_overrides: u64,
    override_rate: f64,
    first_seen: String,
    last_seen: String,
    unique_commands: u64,
    trend: String,
    is_noisy: bool,
    /// Hits in the previous period (for comparison).
    previous_period_hits: u64,
    /// Percentage change from previous period.
    change_percentage: f64,
    /// Whether this rule shows anomalous spike behavior.
    is_anomaly: bool,
}

/// Totals for rule metrics JSON output.
#[derive(serde::Serialize)]
struct RuleMetricsTotals {
    total_hits: u64,
    total_overrides: u64,
    avg_override_rate: f64,
    rule_count: usize,
}

/// Format rule metrics as JSON.
fn format_rule_metrics_json(
    metrics: &[crate::history::RuleMetrics],
    period_days: u64,
) -> Result<String, Box<dyn std::error::Error>> {
    let rules: Vec<RuleMetricEntry> = metrics
        .iter()
        .map(|m| {
            // Split rule_id into pack_id and pattern_name
            let (pack_id, pattern_name) = m.rule_id.split_once(':').map_or_else(
                || (m.rule_id.clone(), String::new()),
                |(p, n)| (p.to_string(), n.to_string()),
            );
            RuleMetricEntry {
                rule_id: m.rule_id.clone(),
                pack_id,
                pattern_name,
                total_hits: m.total_hits,
                allowlist_overrides: m.allowlist_overrides,
                override_rate: m.override_rate,
                first_seen: m.first_seen.to_rfc3339(),
                last_seen: m.last_seen.to_rfc3339(),
                unique_commands: m.unique_commands,
                trend: match m.trend {
                    crate::history::RuleTrend::Increasing => "increasing".to_string(),
                    crate::history::RuleTrend::Stable => "stable".to_string(),
                    crate::history::RuleTrend::Decreasing => "decreasing".to_string(),
                },
                is_noisy: m.is_noisy,
                previous_period_hits: m.previous_period_hits,
                change_percentage: m.change_percentage,
                is_anomaly: m.is_anomaly,
            }
        })
        .collect();

    let total_hits: u64 = metrics.iter().map(|m| m.total_hits).sum();
    let total_overrides: u64 = metrics.iter().map(|m| m.allowlist_overrides).sum();
    #[allow(clippy::cast_precision_loss)]
    let avg_rate = if total_hits > 0 {
        (total_overrides as f64 / total_hits as f64) * 100.0
    } else {
        0.0
    };

    let output = RuleMetricsOutput {
        period_days,
        rules,
        totals: RuleMetricsTotals {
            total_hits,
            total_overrides,
            avg_override_rate: avg_rate,
            rule_count: metrics.len(),
        },
    };

    Ok(serde_json::to_string_pretty(&output)?)
}

/// Handle the `dcg suggest-allowlist` command.
/// Parse a duration string like "30d", "7d", "24h", "1w" into a chrono Duration.
fn parse_duration_string(s: &str) -> Result<chrono::Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("Empty duration string".to_string());
    }

    // Find where the number ends and the unit begins
    let num_end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());

    if num_end == 0 {
        return Err(format!("Invalid duration: {s} (no number found)"));
    }

    let value: i64 = s[..num_end]
        .parse()
        .map_err(|_| format!("Invalid number in duration: {s}"))?;

    let unit = &s[num_end..];

    match unit.to_lowercase().as_str() {
        "d" | "day" | "days" => Ok(chrono::Duration::days(value)),
        "h" | "hr" | "hour" | "hours" => Ok(chrono::Duration::hours(value)),
        "w" | "week" | "weeks" => Ok(chrono::Duration::weeks(value)),
        "m" | "min" | "minutes" => Ok(chrono::Duration::minutes(value)),
        "" => Err(format!("Missing unit in duration: {s} (use d, h, w, or m)")),
        _ => Err(format!("Unknown duration unit: {unit} (use d, h, w, or m)")),
    }
}

/// Handle the `dcg suggest-allowlist` command.
///
/// Analyzes denied commands from history and suggests allowlist patterns.
fn handle_suggest_allowlist_command(
    config: &Config,
    cmd: &SuggestAllowlistCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    // Handle --undo mode first
    if let Some(minutes) = cmd.undo {
        return handle_suggest_allowlist_undo(minutes);
    }

    // Parse the "since" duration
    let duration = parse_duration_string(&cmd.since)?;
    let since_time = Utc::now() - duration;

    // Open history database
    let db_path = config.history.expanded_database_path();
    let db = match HistoryDb::open(db_path) {
        Ok(db) => db,
        Err(err) => {
            if matches!(cmd.format, SuggestFormat::Json) {
                // Output empty array for JSON format
                println!("[]");
                return Ok(());
            }
            if matches!(err, crate::history::HistoryError::Disabled) {
                println!("History is disabled. Enable it in config to use suggest-allowlist.");
                return Ok(());
            }
            println!("Error opening history database: {err}");
            println!();
            println!("Run 'dcg history stats' to check database status.");
            return Ok(());
        }
    };

    // Query denied commands from history
    let options = ExportOptions {
        outcome_filter: Some(Outcome::Deny),
        since: Some(since_time),
        until: None,
        limit: None,
    };

    let entries = db.query_commands_for_export(&options)?;

    if entries.is_empty() {
        if matches!(cmd.format, SuggestFormat::Json) {
            // Output empty array for JSON format
            println!("[]");
            return Ok(());
        }
        println!("No denied commands found in the last {}.", cmd.since);
        println!();
        println!("Suggestions:");
        println!("  - Check if history is enabled: dcg history stats");
        println!("  - Try a longer time period: --since 90d");
        return Ok(());
    }

    // Also query bypassed commands to include bypass information
    let bypass_options = ExportOptions {
        outcome_filter: Some(Outcome::Bypass),
        since: Some(since_time),
        until: None,
        limit: None,
    };
    let bypass_entries = db
        .query_commands_for_export(&bypass_options)
        .unwrap_or_default();

    // Build a set of commands that were bypassed
    let bypassed_commands: std::collections::HashSet<String> =
        bypass_entries.iter().map(|e| e.command.clone()).collect();

    // Convert to CommandEntryInfo with path and bypass information
    let entry_infos: Vec<CommandEntryInfo> = entries
        .iter()
        .map(|e| CommandEntryInfo {
            command: e.command.clone(),
            working_dir: e.working_dir.clone(),
            was_bypassed: bypassed_commands.contains(&e.command),
        })
        .collect();

    // Generate enhanced suggestions with confidence and risk analysis
    let mut suggestions = generate_enhanced_suggestions(&entry_infos, cmd.min_frequency);

    if suggestions.is_empty() {
        if matches!(cmd.format, SuggestFormat::Json) {
            // Output empty array for JSON format
            println!("[]");
            return Ok(());
        }
        println!(
            "No commands found that were blocked {} or more times.",
            cmd.min_frequency
        );
        println!();
        println!("Try lowering --min-frequency or increasing --since period.");
        return Ok(());
    }

    // Apply confidence filtering
    suggestions = match cmd.confidence {
        ConfidenceTierFilter::High => filter_by_confidence(suggestions, ConfidenceTier::High),
        ConfidenceTierFilter::Medium => filter_by_confidence(suggestions, ConfidenceTier::Medium),
        ConfidenceTierFilter::Low => filter_by_confidence(suggestions, ConfidenceTier::Low),
        ConfidenceTierFilter::All => suggestions,
    };

    // Apply risk filtering
    suggestions = match cmd.risk {
        RiskLevelFilter::Low => filter_by_risk(suggestions, RiskLevel::Low),
        RiskLevelFilter::Medium => filter_by_risk(suggestions, RiskLevel::Medium),
        RiskLevelFilter::High => filter_by_risk(suggestions, RiskLevel::High),
        RiskLevelFilter::All => suggestions,
    };

    // Take up to the limit
    suggestions.truncate(cmd.limit);

    if suggestions.is_empty() {
        if matches!(cmd.format, SuggestFormat::Json) {
            // Output empty array for JSON format
            println!("[]");
            return Ok(());
        }
        println!("No suggestions available.");
        return Ok(());
    }

    // Output based on format
    match cmd.format {
        SuggestFormat::Json => {
            output_suggestions_json(&suggestions)?;
        }
        SuggestFormat::Text => {
            if cmd.non_interactive {
                // Non-interactive mode: no writes to database
                output_suggestions_text(&suggestions);
            } else {
                // Interactive mode: pass db for audit logging and config for conflict detection
                output_suggestions_interactive(&suggestions, entries.len(), Some(&db), config)?;
            }
        }
    }

    Ok(())
}

/// Output suggestions as JSON.
fn output_suggestions_json(
    suggestions: &[AllowlistSuggestion],
) -> Result<(), Box<dyn std::error::Error>> {
    #[derive(serde::Serialize)]
    struct JsonSuggestion {
        pattern: String,
        frequency: usize,
        unique_variants: usize,
        confidence: String,
        risk: String,
        reason: String,
        score: f32,
        example_commands: Vec<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        path_patterns: Vec<String>,
        suggest_path_specific: bool,
        bypass_count: usize,
    }

    let output: Vec<JsonSuggestion> = suggestions
        .iter()
        .map(|s| JsonSuggestion {
            pattern: s.cluster.proposed_pattern.clone(),
            frequency: s.cluster.frequency,
            unique_variants: s.cluster.unique_count,
            confidence: s.confidence.as_str().to_string(),
            risk: s.risk.as_str().to_string(),
            reason: s.reason.as_str().to_string(),
            score: s.score,
            example_commands: s.cluster.commands.clone(),
            path_patterns: s.path_patterns.iter().map(|p| p.pattern.clone()).collect(),
            suggest_path_specific: s.suggest_path_specific,
            bypass_count: s.bypass_count,
        })
        .collect();

    let json = serde_json::to_string_pretty(&output)?;
    println!("{json}");
    Ok(())
}

/// Output suggestions as formatted text (non-interactive).
fn output_suggestions_text(suggestions: &[AllowlistSuggestion]) {
    println!("Allowlist Suggestions");
    println!("=====================");
    println!();

    for (i, suggestion) in suggestions.iter().enumerate() {
        println!("[{}/{}] Suggestion", i + 1, suggestions.len());
        println!("────────────────────────────────────────");
        println!("Pattern: {}", suggestion.cluster.proposed_pattern);
        println!(
            "Blocked: {} times ({} unique variants)",
            suggestion.cluster.frequency, suggestion.cluster.unique_count
        );
        println!(
            "Confidence: {} | Risk: {} | Score: {:.2}",
            suggestion.confidence, suggestion.risk, suggestion.score
        );
        println!("Reason: {}", suggestion.reason.description());
        if suggestion.bypass_count > 0 {
            println!("Bypassed: {} times", suggestion.bypass_count);
        }
        if !suggestion.path_patterns.is_empty() {
            println!("Common paths:");
            for pp in suggestion.path_patterns.iter().take(3) {
                println!(
                    "  • {} ({} occurrences{})",
                    pp.pattern,
                    pp.occurrence_count,
                    if pp.is_project_dir {
                        ", project dir"
                    } else {
                        ""
                    }
                );
            }
        }
        println!();
        println!("Example commands:");
        for cmd in suggestion.cluster.commands.iter().take(5) {
            println!("  • {cmd}");
        }
        if suggestion.cluster.commands.len() > 5 {
            println!("  ... and {} more", suggestion.cluster.commands.len() - 5);
        }
        println!();
    }
}

/// Output suggestions interactively (prompting user for each).
#[allow(clippy::too_many_lines)]
fn output_suggestions_interactive(
    suggestions: &[AllowlistSuggestion],
    total_denied: usize,
    db: Option<&HistoryDb>,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;
    use std::io::{self, BufRead, Write};

    println!("Analyzing {total_denied} denied commands...");
    println!("Found {} potential allowlist patterns.", suggestions.len());
    println!();
    println!("For each suggestion, you can:");
    println!("  [A]ccept - Record pattern (to add to allowlist)");
    println!("  [S]kip   - Move to next suggestion");
    println!("  [Q]uit   - Exit without more changes");
    println!();

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let working_dir = std::env::current_dir()
        .ok()
        .map(|p| p.to_string_lossy().to_string());

    for (i, suggestion) in suggestions.iter().enumerate() {
        let cluster = &suggestion.cluster;
        // Check for potential conflicts before displaying
        let conflict_check = check_pattern_conflicts(&cluster.proposed_pattern, config);

        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!(" [{}/{}] Suggestion", i + 1, suggestions.len());
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!(" Pattern: {}", cluster.proposed_pattern);
        println!(
            " Blocked: {} times ({} unique variants)",
            cluster.frequency, cluster.unique_count
        );

        // Display confidence, risk, and score
        let confidence_color = match suggestion.confidence {
            ConfidenceTier::High => "high".green(),
            ConfidenceTier::Medium => "medium".yellow(),
            ConfidenceTier::Low => "low".red(),
        };
        let risk_color = match suggestion.risk {
            RiskLevel::Low => "low".green(),
            RiskLevel::Medium => "medium".yellow(),
            RiskLevel::High => "high".red(),
        };
        println!(
            " Confidence: {} | Risk: {} | Score: {:.2}",
            confidence_color, risk_color, suggestion.score
        );
        println!(" Reason: {}", suggestion.reason.description());

        // Show bypass information if available
        if suggestion.bypass_count > 0 {
            println!(
                " {} Bypassed {} time(s) - user manually allowed this command",
                "✓".green(),
                suggestion.bypass_count
            );
        }

        // Show path patterns if suggesting path-specific allowlisting
        if !suggestion.path_patterns.is_empty() {
            println!();
            println!(" Common paths:");
            for pp in suggestion.path_patterns.iter().take(3) {
                let project_indicator = if pp.is_project_dir {
                    " (project dir)".dimmed()
                } else {
                    "".normal()
                };
                println!(
                    "   • {} ({} occurrences){}",
                    pp.pattern, pp.occurrence_count, project_indicator
                );
            }
            if suggestion.suggest_path_specific {
                println!(
                    "   {}",
                    "→ Consider path-specific allowlisting for this pattern".cyan()
                );
            }
        }

        // Display warnings if there are conflicts or the pattern is overly broad
        if conflict_check.conflicts_with_blocks || conflict_check.is_overly_broad {
            println!();
            println!(" {}", "⚠ Warnings:".yellow());
            if let Some(ref warning) = conflict_check.block_conflict_warning {
                println!("   • {}", warning.yellow());
            }
            if conflict_check.is_overly_broad {
                println!(
                    "   • {}",
                    "Pattern is overly broad (uses wildcards without anchors)".yellow()
                );
                if let Some(ref suggestion_text) = conflict_check.refinement_suggestion {
                    println!("     {}", suggestion_text.dimmed());
                }
            }
        }

        println!();
        println!(" Example commands:");
        for cmd in cluster.commands.iter().take(5) {
            println!("   • {cmd}");
        }
        if cluster.commands.len() > 5 {
            println!("   ... and {} more", cluster.commands.len() - 5);
        }
        println!();

        // Prompt for action
        print!(" [A]ccept  [S]kip  [Q]uit: ");
        stdout.flush()?;

        let mut input = String::new();
        stdin.lock().read_line(&mut input)?;

        match input.trim().to_lowercase().as_str() {
            "a" | "accept" => {
                // Log audit entry for accepted suggestion
                if let Some(db) = db {
                    let audit_entry = SuggestionAuditEntry {
                        timestamp: Utc::now(),
                        action: SuggestionAction::Accepted,
                        pattern: cluster.proposed_pattern.clone(),
                        final_pattern: None,
                        risk_level: suggestion.risk.as_str().to_string(),
                        risk_score: suggestion.risk.score(),
                        confidence_tier: suggestion.confidence.as_str().to_string(),
                        confidence_points: match suggestion.confidence {
                            ConfidenceTier::High => 3,
                            ConfidenceTier::Medium => 2,
                            ConfidenceTier::Low => 1,
                        },
                        cluster_frequency: cluster.frequency,
                        unique_variants: cluster.unique_count,
                        sample_commands: serde_json::to_string(&cluster.commands)
                            .unwrap_or_default(),
                        rule_id: None,
                        session_id: None,
                        working_dir: working_dir.clone(),
                    };
                    if let Err(e) = db.log_suggestion_audit(&audit_entry) {
                        eprintln!(" Warning: Could not log audit entry: {e}");
                    }
                }

                // Generate a descriptive reason from the suggestion
                let reason = format!(
                    "Auto-suggested ({} confidence, {} risk): {}",
                    suggestion.confidence.as_str(),
                    suggestion.risk.as_str(),
                    suggestion.reason.description()
                );

                // Write the pattern to the allowlist
                match allowlist_add_pattern(
                    &cluster.proposed_pattern,
                    &reason,
                    suggestion.confidence.as_str(),
                    suggestion.risk.as_str(),
                    cluster.frequency,
                    cluster.unique_count,
                ) {
                    Ok(path) => {
                        use colored::Colorize;
                        println!(" {} Pattern added to allowlist", "✓".green());
                        println!("   File: {}", path.display());
                        println!();
                    }
                    Err(e) => {
                        use colored::Colorize;
                        // Check if it's a duplicate error (not a real failure)
                        if e.to_string().contains("already exists") {
                            println!(" {} Pattern already in allowlist", "ℹ".cyan());
                        } else {
                            eprintln!(" {} Could not write to allowlist: {e}", "✗".red());
                            println!("   You can manually add it with:");
                            println!(
                                "   dcg allowlist add-pattern --pattern '{}' --reason '{}'",
                                cluster.proposed_pattern, reason
                            );
                        }
                        println!();
                    }
                }
            }
            "q" | "quit" => {
                println!();
                println!("Exiting. No changes made to allowlist.");
                break;
            }
            _ => {
                // Skip by default - log as rejected for tracking
                if let Some(db) = db {
                    let audit_entry = SuggestionAuditEntry {
                        timestamp: Utc::now(),
                        action: SuggestionAction::Rejected,
                        pattern: cluster.proposed_pattern.clone(),
                        final_pattern: None,
                        risk_level: suggestion.risk.as_str().to_string(),
                        risk_score: suggestion.risk.score(),
                        confidence_tier: suggestion.confidence.as_str().to_string(),
                        confidence_points: match suggestion.confidence {
                            ConfidenceTier::High => 3,
                            ConfidenceTier::Medium => 2,
                            ConfidenceTier::Low => 1,
                        },
                        cluster_frequency: cluster.frequency,
                        unique_variants: cluster.unique_count,
                        sample_commands: serde_json::to_string(&cluster.commands)
                            .unwrap_or_default(),
                        rule_id: None,
                        session_id: None,
                        working_dir: working_dir.clone(),
                    };
                    // Best effort - don't warn on skip audit failures
                    let _ = db.log_suggestion_audit(&audit_entry);
                }
                println!(" → Skipped");
                println!();
            }
        }
    }

    Ok(())
}

/// Handle the `dcg history` command.
fn handle_history_command(
    config: &Config,
    action: HistoryAction,
) -> Result<(), Box<dyn std::error::Error>> {
    let db_path = config.history.expanded_database_path();
    let db = match HistoryDb::open(db_path) {
        Ok(db) => db,
        Err(err) => {
            println!("Error opening history database: {err}");
            return Ok(());
        }
    };

    match action {
        HistoryAction::Stats { days, trends, json } => {
            history_stats(&db, days, trends, json)?;
        }
        HistoryAction::Prune {
            older_than_days,
            dry_run,
            yes,
        } => {
            history_prune(&db, older_than_days, dry_run, yes)?;
        }
        HistoryAction::Export {
            output,
            format,
            outcome,
            since,
            until,
            limit,
            compress,
        } => {
            history_export(&db, output, format, outcome, since, until, limit, compress)?;
        }
        HistoryAction::Analyze {
            days,
            json,
            recommendations_only,
            false_positives,
            gaps,
        } => {
            history_analyze(&db, days, json, recommendations_only, false_positives, gaps)?;
        }
        HistoryAction::Check { json, strict } => {
            history_check(&db, json, strict)?;
        }
        HistoryAction::Backup { output, compress } => {
            history_backup(&db, &output, compress)?;
        }
    }

    Ok(())
}

fn history_stats(
    db: &HistoryDb,
    days: u64,
    trends: bool,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let stats = if trends {
        db.compute_stats_with_trends(days)?
    } else {
        db.compute_stats(days)?
    };

    if json {
        let output = serde_json::to_string_pretty(&stats)?;
        println!("{output}");
    } else {
        let output = format_history_stats_pretty(&stats);
        print!("{output}");
    }

    Ok(())
}

fn history_prune(
    db: &HistoryDb,
    older_than_days: u64,
    dry_run: bool,
    yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if older_than_days == 0 {
        return Err("older-than-days must be at least 1".into());
    }

    if !dry_run && !yes {
        println!("Refusing to prune without --yes or --dry-run.");
        return Ok(());
    }

    let pruned = db.prune_older_than_days(older_than_days, dry_run)?;
    if dry_run {
        println!("Would prune {pruned} entries older than {older_than_days} days");
    } else {
        println!("Pruned {pruned} entries older than {older_than_days} days");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::needless_pass_by_value)]
fn history_export(
    db: &HistoryDb,
    output_path: Option<String>,
    format: ExportFormat,
    outcome: Option<String>,
    since: Option<String>,
    until: Option<String>,
    limit: Option<usize>,
    compress: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use chrono::DateTime;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::fs::File;
    use std::io::{self, BufWriter, Write};

    // Parse outcome filter
    let outcome_filter = outcome
        .as_deref()
        .map(|o| Outcome::parse(o).ok_or_else(|| format!("Invalid outcome: {o}")))
        .transpose()?;

    // Parse date/time filters
    let since_dt = since
        .as_deref()
        .map(|s| {
            DateTime::parse_from_rfc3339(s)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .map_err(|_| format!("Invalid since datetime: {s} (use ISO 8601 format)"))
        })
        .transpose()?;

    let until_dt = until
        .as_deref()
        .map(|s| {
            DateTime::parse_from_rfc3339(s)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .map_err(|_| format!("Invalid until datetime: {s} (use ISO 8601 format)"))
        })
        .transpose()?;

    let options = ExportOptions {
        outcome_filter,
        since: since_dt,
        until: until_dt,
        limit,
    };

    // Create output writer
    let count: usize;
    if let Some(path) = output_path {
        let file = File::create(&path)?;
        if compress {
            let encoder = GzEncoder::new(file, Compression::default());
            let mut writer = BufWriter::new(encoder);
            count = export_to_writer(db, &mut writer, format, &options)?;
            writer.flush()?;
        } else {
            let mut writer = BufWriter::new(file);
            count = export_to_writer(db, &mut writer, format, &options)?;
            writer.flush()?;
        }
        eprintln!("Exported {count} records to {path}");
    } else {
        let stdout = io::stdout();
        let mut writer = stdout.lock();
        count = export_to_writer(db, &mut writer, format, &options)?;
        writer.flush()?;
        eprintln!("Exported {count} records");
    }

    Ok(())
}

fn export_to_writer<W: std::io::Write>(
    db: &HistoryDb,
    writer: &mut W,
    format: ExportFormat,
    options: &ExportOptions,
) -> Result<usize, Box<dyn std::error::Error>> {
    let count = match format {
        ExportFormat::Json => db.export_json(writer, options)?,
        ExportFormat::Jsonl => db.export_jsonl(writer, options)?,
        ExportFormat::Csv => db.export_csv(writer, options)?,
    };
    Ok(count)
}

#[allow(clippy::fn_params_excessive_bools, clippy::too_many_lines)]
fn history_analyze(
    db: &HistoryDb,
    days: u64,
    json: bool,
    recommendations_only: bool,
    false_positives: bool,
    gaps: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    // Get enabled packs from config
    let config = Config::load();
    let enabled_pack_ids = config.enabled_pack_ids();
    let enabled_packs: Vec<&str> = enabled_pack_ids.iter().map(String::as_str).collect();

    let analysis = db.analyze_pack_effectiveness(days, &enabled_packs)?;

    if json {
        let output = serde_json::to_string_pretty(&analysis)?;
        println!("{output}");
        return Ok(());
    }

    // Pretty print output
    println!(
        "\n{}",
        "═══ Pack Effectiveness Analysis ═══".bright_cyan().bold()
    );
    println!(
        "Period: {} days | Commands analyzed: {}\n",
        analysis.period_days,
        analysis.total_commands.to_string().yellow()
    );

    // Show recommendations (always unless specific view requested)
    if !false_positives && !gaps || recommendations_only {
        if analysis.recommendations.is_empty() {
            println!("{}", "No recommendations at this time.".dimmed());
        } else {
            println!("{}", "📋 Recommendations:".bright_white().bold());
            for rec in &analysis.recommendations {
                let priority_indicator = match rec.priority {
                    8..=10 => "🔴".to_string(),
                    5..=7 => "🟡".to_string(),
                    _ => "🟢".to_string(),
                };
                println!("  {} {}", priority_indicator, rec.description);
                if let Some(action) = &rec.suggested_action {
                    println!("     └─ {}", action.dimmed());
                }
            }
            println!();
        }
    }

    // Show false positives (potentially aggressive patterns)
    if false_positives || (!recommendations_only && !gaps) {
        if analysis.potentially_aggressive.is_empty() {
            println!(
                "{}",
                "✓ No patterns with high bypass rates detected.".green()
            );
        } else {
            println!(
                "{}",
                "⚠️  Potentially Aggressive Patterns (high bypass rate):"
                    .yellow()
                    .bold()
            );
            for p in &analysis.potentially_aggressive {
                println!(
                    "  • {} ({}): {:.1}% bypass rate ({}/{} triggers)",
                    p.pattern.bright_white(),
                    p.pack_id.as_deref().unwrap_or("unknown").dimmed(),
                    p.bypass_rate,
                    p.bypassed_count,
                    p.total_triggers
                );
            }
            println!();
        }
    }

    // Show coverage gaps
    if gaps || (!recommendations_only && !false_positives) {
        if analysis.potential_gaps.is_empty() {
            println!("{}", "✓ No potential coverage gaps detected.".green());
        } else {
            println!(
                "{}",
                "⚠️  Potential Coverage Gaps (dangerous commands that were allowed):"
                    .yellow()
                    .bold()
            );
            for gap in analysis.potential_gaps.iter().take(10) {
                let cmd_display = if gap.command.len() > 60 {
                    format!("{}...", &gap.command[..57])
                } else {
                    gap.command.clone()
                };
                println!(
                    "  • {} ({})",
                    cmd_display.bright_white(),
                    gap.reason.dimmed()
                );
            }
            if analysis.potential_gaps.len() > 10 {
                println!("  ... and {} more", analysis.potential_gaps.len() - 10);
            }
            println!();
        }
    }

    // Show high-value patterns summary
    if !recommendations_only && !false_positives && !gaps {
        if !analysis.high_value_patterns.is_empty() {
            let total_blocked: u64 = analysis
                .high_value_patterns
                .iter()
                .map(|p| p.denied_count)
                .sum();
            println!(
                "{}",
                format!(
                    "✓ {} high-value patterns blocked {} commands with minimal false positives.",
                    analysis.high_value_patterns.len(),
                    total_blocked
                )
                .green()
            );
        }

        // Show inactive packs
        if !analysis.inactive_packs.is_empty() {
            println!(
                "\n{} Inactive packs (enabled but never triggered): {}",
                "ℹ️ ".dimmed(),
                analysis.inactive_packs.join(", ").dimmed()
            );
        }
    }

    Ok(())
}

fn history_check(
    db: &HistoryDb,
    json: bool,
    strict: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let result = db.check_health()?;

    if json {
        let output = serde_json::to_string_pretty(&result)?;
        println!("{output}");
    } else {
        println!(
            "\n{}",
            "═══ History Database Health Check ═══".bright_cyan().bold()
        );

        // Integrity status
        let integrity_status = if result.integrity_ok {
            "✓ PASSED".green()
        } else {
            "✗ FAILED".red()
        };
        println!(
            "Integrity check: {} ({})",
            integrity_status, result.integrity_check
        );

        // Foreign key check
        if result.foreign_key_violations == 0 {
            println!("Foreign keys: {} violations", "0".green());
        } else {
            println!(
                "Foreign keys: {} violations",
                result.foreign_key_violations.to_string().red()
            );
        }

        // FTS sync status
        let fts_status = if result.fts_in_sync {
            "✓ in sync".green()
        } else {
            "✗ out of sync".red()
        };
        println!(
            "FTS index: {} ({} commands, {} FTS entries)",
            fts_status, result.commands_count, result.fts_count
        );

        // Storage info
        println!("\n{}", "Storage:".bright_white());
        println!(
            "  Database: {} ({} pages)",
            format_size(result.file_size_bytes),
            result.page_count
        );
        println!("  WAL file: {}", format_size(result.wal_size_bytes));
        println!(
            "  Free pages: {} ({} bytes)",
            result.freelist_count,
            result.freelist_count * u64::from(result.page_size)
        );

        // Schema info
        println!("\n{}", "Configuration:".bright_white());
        println!("  Schema version: {}", result.schema_version);
        println!("  Journal mode: {}", result.journal_mode);
        println!("  Page size: {} bytes", result.page_size);
    }

    if strict && !result.integrity_ok {
        std::process::exit(1);
    }

    Ok(())
}

fn history_backup(
    db: &HistoryDb,
    output: &str,
    compress: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;
    use std::path::Path;

    let output_path = Path::new(output);

    // Add .gz extension if compressing and not already present
    let has_gz_ext = output_path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("gz"));
    let final_path = if compress && !has_gz_ext {
        output_path.with_extension(format!(
            "{}.gz",
            output_path
                .extension()
                .map(|e| e.to_string_lossy())
                .unwrap_or_default()
        ))
    } else {
        output_path.to_path_buf()
    };

    println!("Creating backup...");
    let result = db.backup(&final_path, compress)?;

    println!("\n{}", "═══ Backup Complete ═══".bright_cyan().bold());
    println!("Output: {}", result.backup_path.bright_white());
    println!(
        "Size: {} {}",
        format_size(result.backup_size_bytes),
        if result.compressed {
            "(compressed)"
        } else {
            ""
        }
    );
    println!("Duration: {} ms", result.duration_ms);
    if result.verified {
        println!("Verification: {}", "✓ PASSED".green());
    } else {
        println!("Verification: {}", "skipped (compressed backup)".dimmed());
    }

    Ok(())
}

/// Format a byte size in human-readable format.
#[allow(clippy::cast_precision_loss)]
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} bytes")
    }
}

fn format_history_stats_pretty(stats: &HistoryStats) -> String {
    use std::fmt::Write;

    let mut output = String::new();
    let _ = writeln!(output, "History stats (last {} days)", stats.period_days);
    let _ = writeln!(output, "Total commands: {}", stats.total_commands);
    let _ = writeln!(
        output,
        "Outcomes: allow {} | deny {} | warn {} | bypass {}",
        stats.outcomes.allowed,
        stats.outcomes.denied,
        stats.outcomes.warned,
        stats.outcomes.bypassed
    );
    let _ = writeln!(output, "Block rate: {:.2}%", stats.block_rate * 100.0);
    let _ = writeln!(
        output,
        "Performance (us): p50 {} | p95 {} | p99 {} | max {}",
        stats.performance.p50_us,
        stats.performance.p95_us,
        stats.performance.p99_us,
        stats.performance.max_us
    );

    if !stats.top_patterns.is_empty() {
        let _ = writeln!(output, "Top patterns:");
        for pattern in &stats.top_patterns {
            let _ = writeln!(
                output,
                "  - {} ({}{})",
                pattern.name,
                pattern.count,
                pattern
                    .pack_id
                    .as_ref()
                    .map_or_else(String::new, |pack| format!(", {pack}"))
            );
        }
    }

    if !stats.top_projects.is_empty() {
        let _ = writeln!(output, "Top projects:");
        for project in &stats.top_projects {
            let _ = writeln!(output, "  - {} ({})", project.path, project.command_count);
        }
    }

    if !stats.agents.is_empty() {
        let _ = writeln!(output, "Top agents:");
        for agent in &stats.agents {
            let _ = writeln!(output, "  - {} ({})", agent.name, agent.count);
        }
    }

    if let Some(trends) = &stats.trends {
        let _ = writeln!(
            output,
            "Trends: commands {:+.1}% | block rate {:+.2}pp",
            trends.commands_change, trends.block_rate_change
        );
        if !trends.top_pattern_change.is_empty() {
            let _ = writeln!(output, "Pattern shifts:");
            for (name, delta) in &trends.top_pattern_change {
                let _ = writeln!(output, "  - {name}: {delta:+}");
            }
        }
    }

    output
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

    // Sort diffs for deterministic output (HashMap iteration is non-deterministic)
    diffs.sort();

    diffs
}

/// Format corpus output for human-readable display.
#[allow(clippy::too_many_lines)]
fn format_corpus_pretty(output: &CorpusOutput) -> String {
    use colored::Colorize;
    use std::fmt::Write;

    let mut result = String::new();
    let colorize = colored::control::SHOULD_COLORIZE.should_colorize();

    // Header
    let _ = writeln!(
        result,
        "{}\n",
        if colorize {
            "dcg corpus".green().bold().to_string()
        } else {
            "dcg corpus".to_string()
        }
    );

    let _ = writeln!(result, "Corpus: {}", output.corpus_dir);
    let _ = writeln!(result, "Version: {}", output.binary_version);
    let _ = writeln!(result, "Generated: {}\n", output.generated_at);

    // Summary
    let _ = writeln!(
        result,
        "{}",
        if colorize {
            "=== Summary ===".blue().bold().to_string()
        } else {
            "=== Summary ===".to_string()
        }
    );

    let _ = writeln!(
        result,
        "Total: {} ({} passed, {} failed)\n",
        output.total_cases, output.total_passed, output.total_failed
    );

    // By category (sorted for deterministic output)
    result.push_str("By Category:\n");
    let mut categories: Vec<_> = output.summary.category.iter().collect();
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
        let _ = writeln!(
            result,
            "  {}: {}/{} [{}]",
            cat, stats.passed, stats.total, status_str
        );
    }
    result.push('\n');

    // By decision (sorted for deterministic output)
    result.push_str("By Decision:\n");
    let mut decisions: Vec<_> = output.summary.decision.iter().collect();
    decisions.sort_by_key(|(k, _)| *k);
    for (decision, count) in decisions {
        let _ = writeln!(result, "  {decision}: {count}");
    }
    result.push('\n');

    // By pack (top 10)
    result.push_str("By Pack (top 10):\n");
    let mut packs: Vec<_> = output.summary.pack.iter().collect();
    packs.sort_by(|a, b| b.1.cmp(a.1));
    for (pack, count) in packs.iter().take(10) {
        let _ = writeln!(result, "  {pack}: {count}");
    }
    result.push('\n');

    // Failed tests
    let failures: Vec<_> = output.cases.iter().filter(|c| !c.passed).collect();
    if !failures.is_empty() {
        let _ = writeln!(
            result,
            "{}",
            if colorize {
                "=== Failures ===".red().bold().to_string()
            } else {
                "=== Failures ===".to_string()
            }
        );

        for case in failures {
            let _ = writeln!(
                result,
                "  {} - {}",
                if colorize {
                    "FAIL".red().to_string()
                } else {
                    "FAIL".to_string()
                },
                case.description
            );
            let _ = writeln!(result, "    ID: {}", case.id);
            let _ = writeln!(result, "    Command: {}", case.command);
            let _ = writeln!(
                result,
                "    Expected: {}, Actual: {}",
                case.expected, case.actual
            );
            if let Some(ref rule) = case.actual_rule_id {
                let _ = writeln!(result, "    Rule: {rule}");
            }
            result.push('\n');
        }
    }

    result
}

/// Check installation, configuration, and hook registration
fn doctor(fix: bool, format: DoctorFormat) {
    match format {
        DoctorFormat::Pretty => {
            #[cfg(feature = "rich-output")]
            {
                doctor_rich(fix);
            }
            #[cfg(not(feature = "rich-output"))]
            {
                doctor_pretty(fix);
            }
        }
        DoctorFormat::Json => doctor_json(fix),
    }
}

/// Human-readable doctor output (colored crate, non-rich fallback).
#[cfg(not(feature = "rich-output"))]
#[allow(clippy::too_many_lines, clippy::unnecessary_unwrap)]
fn doctor_pretty(fix: bool) {
    use colored::Colorize;

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
    } else if let Some(mode) = config.policy().default_mode {
        // No observe_until but default_mode is set (permanent warn/log mode)
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

const DOCTOR_SCHEMA_VERSION: u32 = 1;

fn doctor_json(fix: bool) {
    let report = collect_doctor_report(fix);
    let json = serde_json::to_string_pretty(&report).expect("serialize doctor report");
    println!("{json}");
}

/// Rich terminal doctor output using DcgConsole and markup.
#[cfg(feature = "rich-output")]
fn doctor_rich(fix: bool) {
    use crate::output::console::console;

    let report = collect_doctor_report(fix);
    let con = console();

    // Header
    con.rule(Some("[bold green] dcg doctor [/]"));
    con.print("");

    // Render each check
    for check in &report.checks {
        let (icon, color) = match check.status {
            DoctorCheckStatus::Ok => ("✓", "green"),
            DoctorCheckStatus::Warning => ("⚠", "yellow"),
            DoctorCheckStatus::Error => ("✗", "red"),
            DoctorCheckStatus::Skipped => ("○", "dim"),
        };

        // Status line with icon
        con.print(&format!(
            "[{color}]{icon}[/] [bold]{name}[/]: [{color}]{msg}[/]",
            name = check.name,
            msg = check.message
        ));

        // Remediation hint (indented)
        if let Some(ref rem) = check.remediation {
            con.print(&format!("  [dim]→ {rem}[/]"));
        }

        // Fixed indicator
        if check.fixed {
            con.print("  [green bold]Fixed![/]");
        }
    }

    // Summary
    con.print("");
    if report.ok {
        con.print("[green bold]All checks passed![/]");
    } else if report.fixed > 0 && report.fixed == report.issues {
        con.print("[green bold]All issues fixed![/]");
    } else {
        con.print(&format!(
            "[red bold]{issues}[/] issue(s) found{fixed}",
            issues = report.issues,
            fixed = if report.fixed > 0 {
                format!(", [green]{} fixed[/]", report.fixed)
            } else {
                String::new()
            }
        ));
    }
}

#[allow(clippy::too_many_lines, clippy::option_if_let_else)]
fn collect_doctor_report(fix: bool) -> DoctorReport {
    let mut checks = Vec::new();
    let mut issues = 0usize;
    let mut fixed = 0usize;

    // Check 1: Binary in PATH
    let (status, message, remediation) = if which_dcg().is_some() {
        (DoctorCheckStatus::Ok, "dcg found in PATH".to_string(), None)
    } else {
        issues += 1;
        (
            DoctorCheckStatus::Error,
            "dcg binary not found in PATH".to_string(),
            Some("Run the install script or add dcg to PATH".to_string()),
        )
    };
    checks.push(DoctorCheck {
        id: "binary_path",
        name: "Binary in PATH",
        status,
        message,
        remediation,
        fixed: false,
    });

    // Check 2: Claude settings file exists
    let settings_path = claude_settings_path();
    let (status, message) = if settings_path.exists() {
        (
            DoctorCheckStatus::Ok,
            format!("settings.json found at {}", settings_path.display()),
        )
    } else {
        (
            DoctorCheckStatus::Warning,
            "settings.json not found (Claude Code not configured)".to_string(),
        )
    };
    checks.push(DoctorCheck {
        id: "claude_settings",
        name: "Claude Code settings file",
        status,
        message,
        remediation: None,
        fixed: false,
    });

    // Check 3: Hook wiring
    let hook_diag = diagnose_hook_wiring();
    let mut hook_fixed = false;
    let (status, message, remediation) = if !hook_diag.settings_exists {
        (
            DoctorCheckStatus::Skipped,
            "No settings file to check".to_string(),
            None,
        )
    } else if let Some(ref err) = hook_diag.settings_error {
        issues += 1;
        (
            DoctorCheckStatus::Error,
            format!("Settings error: {err}"),
            Some("Fix settings.json or reinstall Claude Code".to_string()),
        )
    } else if hook_diag.dcg_hook_count == 0 {
        issues += 1;
        if fix {
            match install_hook_silent(false) {
                Ok(true) => {
                    fixed += 1;
                    hook_fixed = true;
                    (
                        DoctorCheckStatus::Ok,
                        "Hook registered successfully".to_string(),
                        None,
                    )
                }
                Ok(false) => (
                    DoctorCheckStatus::Error,
                    "Hook not registered (no changes made)".to_string(),
                    Some("Run 'dcg install' to register the hook".to_string()),
                ),
                Err(e) => (
                    DoctorCheckStatus::Error,
                    format!("Failed to register hook: {e}"),
                    Some("Run 'dcg install' to register the hook".to_string()),
                ),
            }
        } else {
            (
                DoctorCheckStatus::Error,
                "dcg hook not registered".to_string(),
                Some("Run 'dcg install' to register the hook".to_string()),
            )
        }
    } else if hook_diag.dcg_hook_count > 1 {
        (
            DoctorCheckStatus::Warning,
            format!(
                "Found {} dcg hook entries (expected 1)",
                hook_diag.dcg_hook_count
            ),
            Some("Run 'dcg uninstall && dcg install' to fix duplicates".to_string()),
        )
    } else if !hook_diag.wrong_matcher_hooks.is_empty() {
        issues += 1;
        (
            DoctorCheckStatus::Error,
            format!(
                "Hook registered with wrong matcher: {:?}",
                hook_diag.wrong_matcher_hooks
            ),
            Some("dcg must be a Bash hook; reinstall to fix".to_string()),
        )
    } else if !hook_diag.missing_executable_hooks.is_empty() {
        issues += 1;
        (
            DoctorCheckStatus::Error,
            format!(
                "Hook points to missing executable: {:?}",
                hook_diag.missing_executable_hooks
            ),
            Some("Run 'dcg uninstall && dcg install' to fix".to_string()),
        )
    } else {
        (
            DoctorCheckStatus::Ok,
            "dcg hook registered".to_string(),
            None,
        )
    };
    checks.push(DoctorCheck {
        id: "hook_wiring",
        name: "Hook wiring",
        status,
        message,
        remediation,
        fixed: hook_fixed,
    });

    // Check 4: Config validation
    let config_diag = validate_config_diagnostics();
    let mut config_fixed = false;
    let (status, message, remediation) = match &config_diag.config_path {
        None => {
            if fix {
                let cfg_path = config_path();
                if cfg_path.exists() {
                    issues += 1;
                    (
                        DoctorCheckStatus::Error,
                        format!("Config exists at {} but was not loaded", cfg_path.display()),
                        Some("Check permissions and config syntax".to_string()),
                    )
                } else {
                    match write_default_config() {
                        Ok(path) => {
                            fixed += 1;
                            config_fixed = true;
                            (
                                DoctorCheckStatus::Ok,
                                format!("Created default config at {}", path.display()),
                                None,
                            )
                        }
                        Err(e) => {
                            issues += 1;
                            (
                                DoctorCheckStatus::Error,
                                format!("Failed to create config: {e}"),
                                Some("Create config with 'dcg init'".to_string()),
                            )
                        }
                    }
                }
            } else {
                (
                    DoctorCheckStatus::Warning,
                    "No config file found; using defaults".to_string(),
                    Some("Run 'dcg init -o ~/.config/dcg/config.toml'".to_string()),
                )
            }
        }
        Some(path) if config_diag.parse_error.is_some() => {
            issues += 1;
            (
                DoctorCheckStatus::Error,
                format!(
                    "Invalid config at {}: {}",
                    path.display(),
                    config_diag.parse_error.as_deref().unwrap_or("parse error")
                ),
                Some("Fix the TOML syntax error in your config file".to_string()),
            )
        }
        Some(path) => {
            if config_diag.has_errors() || config_diag.has_warnings() {
                let mut details = Vec::new();
                if !config_diag.unknown_packs.is_empty() {
                    details.push(format!("Unknown pack IDs: {:?}", config_diag.unknown_packs));
                }
                if !config_diag.invalid_override_patterns.is_empty() {
                    details.push(format!(
                        "Invalid override patterns: {}",
                        config_diag.invalid_override_patterns.len()
                    ));
                }
                (
                    DoctorCheckStatus::Warning,
                    format!(
                        "Config warnings at {}: {}",
                        path.display(),
                        details.join("; ")
                    ),
                    Some("Run 'dcg packs list' and fix invalid overrides".to_string()),
                )
            } else {
                (
                    DoctorCheckStatus::Ok,
                    format!("Config valid at {}", path.display()),
                    None,
                )
            }
        }
    };
    checks.push(DoctorCheck {
        id: "config",
        name: "Configuration",
        status,
        message,
        remediation,
        fixed: config_fixed,
    });

    // Check 5: Pattern packs
    let config = Config::load();
    let enabled = config.enabled_pack_ids();
    checks.push(DoctorCheck {
        id: "packs",
        name: "Pattern packs",
        status: DoctorCheckStatus::Ok,
        message: format!("{} packs enabled", enabled.len()),
        remediation: None,
        fixed: false,
    });

    // Check 6: Smoke test
    if run_smoke_test() {
        checks.push(DoctorCheck {
            id: "smoke_test",
            name: "Evaluator smoke test",
            status: DoctorCheckStatus::Ok,
            message: "Evaluator smoke test passed".to_string(),
            remediation: None,
            fixed: false,
        });
    } else {
        issues += 1;
        checks.push(DoctorCheck {
            id: "smoke_test",
            name: "Evaluator smoke test",
            status: DoctorCheckStatus::Error,
            message: "Evaluator smoke test failed".to_string(),
            remediation: Some("Report a bug with the failing command".to_string()),
            fixed: false,
        });
    }

    // Check 7: Observe mode status
    let (status, message, remediation) =
        if let Some(observe_until) = config.policy().observe_until.as_ref() {
            let now = chrono::Utc::now();
            if let Some(until) = observe_until.parsed_utc() {
                if now < *until {
                    (
                        DoctorCheckStatus::Warning,
                        format!(
                            "Observe mode active until {}",
                            until.format("%Y-%m-%d %H:%M UTC")
                        ),
                        None,
                    )
                } else {
                    issues += 1;
                    (
                        DoctorCheckStatus::Error,
                        format!(
                            "Observe mode expired at {}",
                            until.format("%Y-%m-%d %H:%M UTC")
                        ),
                        Some("Remove or update observe_until in [policy]".to_string()),
                    )
                }
            } else {
                issues += 1;
                let raw: &str = observe_until;
                (
                    DoctorCheckStatus::Error,
                    format!("observe_until value could not be parsed: {raw}"),
                    Some("Use ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ".to_string()),
                )
            }
        } else if let Some(mode) = config.policy().default_mode {
            if matches!(
                mode,
                crate::config::PolicyMode::Warn | crate::config::PolicyMode::Log
            ) {
                (
                    DoctorCheckStatus::Warning,
                    format!("policy.default_mode = {mode:?} (no expiration)"),
                    Some("Consider adding observe_until for time-limited rollout".to_string()),
                )
            } else {
                (
                    DoctorCheckStatus::Ok,
                    format!("Enforcing normal policy (default_mode = {mode:?})"),
                    None,
                )
            }
        } else {
            (
                DoctorCheckStatus::Ok,
                "Observe mode disabled".to_string(),
                None,
            )
        };
    checks.push(DoctorCheck {
        id: "observe_mode",
        name: "Observe mode",
        status,
        message,
        remediation,
        fixed: false,
    });

    // Check 8: Allowlist discovery + validation
    let allowlist_diag = diagnose_allowlists();
    let (status, message, remediation) = if allowlist_diag.total_errors > 0 {
        issues += allowlist_diag.total_errors;
        (
            DoctorCheckStatus::Error,
            format!(
                "Allowlist errors: {}",
                allowlist_diag.error_messages.join("; ")
            ),
            Some("Run 'dcg allowlist validate' for details".to_string()),
        )
    } else if allowlist_diag.total_warnings > 0 {
        (
            DoctorCheckStatus::Warning,
            format!(
                "Allowlist warnings: {}",
                allowlist_diag.warning_messages.join("; ")
            ),
            Some("Run 'dcg allowlist validate' for details".to_string()),
        )
    } else if allowlist_diag.layers_found == 0 {
        (
            DoctorCheckStatus::Warning,
            "No allowlist files found (project or user)".to_string(),
            Some("Use 'dcg allow <rule-id> -r \"reason\"' to create one".to_string()),
        )
    } else {
        (
            DoctorCheckStatus::Ok,
            format!("Allowlist layers found: {}", allowlist_diag.layers_found),
            None,
        )
    };
    checks.push(DoctorCheck {
        id: "allowlists",
        name: "Allowlists",
        status,
        message,
        remediation,
        fixed: false,
    });

    DoctorReport {
        schema_version: DOCTOR_SCHEMA_VERSION,
        checks,
        issues,
        fixed,
        ok: issues == 0 || (fix && fixed == issues),
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

/// Install the dcg hook entry into Claude Code settings without printing.
fn install_hook_silent(force: bool) -> Result<bool, Box<dyn std::error::Error>> {
    let settings_path = claude_settings_path();

    let mut settings: serde_json::Value = if settings_path.exists() {
        let content = std::fs::read_to_string(&settings_path)?;
        serde_json::from_str(&content)?
    } else {
        if let Some(parent) = settings_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        serde_json::json!({})
    };

    let changed = install_dcg_hook_into_settings(&mut settings, force)?;
    if changed {
        let content = serde_json::to_string_pretty(&settings)?;
        std::fs::write(&settings_path, content)?;
    }
    Ok(changed)
}

/// Create the default config file at the standard path.
fn write_default_config() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let config_path = config_path();
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&config_path, Config::generate_sample_config())?;
    Ok(config_path)
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
    // Handle --list-versions flag: show available backup versions
    if update.list_versions {
        return handle_list_versions();
    }

    // Handle --rollback flag: restore a previous version
    if let Some(ref version) = update.rollback {
        return handle_rollback(version.as_deref());
    }

    // Handle --check flag: just check for updates without installing
    if update.check {
        return handle_version_check(update.refresh, update.format);
    }

    if cfg!(windows) {
        return self_update_windows(update);
    }

    self_update_unix(update)
}

/// Handle --list-versions flag: display available backup versions.
fn handle_list_versions() -> Result<(), Box<dyn std::error::Error>> {
    use crate::update::{format_backup_list, list_backups};

    let backups = list_backups().map_err(|e| format!("Failed to list backups: {e}"))?;

    let use_color = std::io::IsTerminal::is_terminal(&std::io::stdout());
    print!("{}", format_backup_list(&backups, use_color));

    Ok(())
}

/// Handle --rollback flag: restore a previous version.
fn handle_rollback(target_version: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    use crate::update::rollback;

    eprintln!("Rolling back dcg...");

    match rollback(target_version) {
        Ok(message) => {
            println!("{message}");
            println!("\nRestart dcg to use the restored version.");
            Ok(())
        }
        Err(e) => Err(format!("Rollback failed: {e}").into()),
    }
}

/// Perform update using native Rust `self_update` crate.
///
/// Note: Native update is not yet implemented. Use installer flags instead:
/// `dcg update --system` or `dcg update --from-source`
/// Check for updates and display the result.
fn handle_version_check(
    force_refresh: bool,
    format: UpdateFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::update::{check_for_update, format_check_result, format_check_result_json};

    if !matches!(format, UpdateFormat::Json) {
        eprintln!("Checking for updates...");
    }

    match check_for_update(force_refresh) {
        Ok(result) => match format {
            UpdateFormat::Pretty => {
                // Detect if stdout is a TTY for color output
                let use_color = std::io::IsTerminal::is_terminal(&std::io::stdout());
                print!("{}", format_check_result(&result, use_color));
            }
            UpdateFormat::Json => {
                let json = format_check_result_json(&result)
                    .map_err(|e| format!("Failed to format JSON: {e}"))?;
                println!("{json}");
            }
        },
        Err(e) => return Err(format!("Failed to check for updates: {e}").into()),
    }
    Ok(())
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
    if update.force {
        args.push("--force".to_string());
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
    if update.system || update.from_source || update.quiet || update.no_gum || update.force {
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

/// Get the path to dcg config directory.
///
/// Prefers XDG-style `~/.config/dcg/` if it exists, otherwise falls back to
/// platform-native location. This ensures users can use `~/.config/dcg/` on
/// all platforms, including macOS where `dirs::config_dir()` returns
/// `~/Library/Application Support`.
fn config_dir() -> std::path::PathBuf {
    // Check XDG-style path first (~/.config/dcg/)
    if let Some(home) = dirs::home_dir() {
        let xdg_dir = home.join(".config").join("dcg");
        if xdg_dir.exists() {
            return xdg_dir;
        }
    }

    // Fall back to platform-native or default to ~/.config/dcg
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
        let Some(path) = crate::config::resolve_config_path_value(&value, cwd.as_deref()) else {
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
    let keyword_index = REGISTRY.build_enabled_keyword_index(&ordered_packs);
    let compiled_overrides = config.overrides.compile();
    let allowlists = crate::LayeredAllowlist::default();
    let heredoc_settings = config.heredoc_settings();

    // Test 1: "git status" should be allowed
    let allow_result = crate::evaluate_command_with_pack_order(
        "git status",
        &enabled_keywords,
        &ordered_packs,
        keyword_index.as_ref(),
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
        keyword_index.as_ref(),
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

#[allow(clippy::too_many_lines)]
fn handle_allow_once_command(
    config: &Config,
    cmd: &AllowOnceCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{self, Write};

    if let Some(action) = &cmd.action {
        match action {
            AllowOnceAction::List => return handle_allow_once_list(config, cmd),
            AllowOnceAction::Clear(args) => return handle_allow_once_clear(config, cmd, args),
            AllowOnceAction::Revoke(args) => return handle_allow_once_revoke(config, cmd, args),
        }
    }

    let Some(code) = cmd.code.as_deref() else {
        return Err("Missing allow-once code. Usage: dcg allow-once <CODE>".into());
    };

    let now = Utc::now();
    let cwd = std::env::current_dir().unwrap_or_default();
    let pending_path = PendingExceptionStore::default_path(Some(&cwd));
    let pending_store = PendingExceptionStore::new(pending_path);

    let (matches, _maintenance) = pending_store.lookup_by_code(code, now)?;
    if matches.is_empty() {
        return Err(
            format!("No pending exception found for code '{code}'. It may be expired.").into(),
        );
    }

    let selected = select_pending_entry(&matches, cmd)?;

    let is_config_block = selected.source.as_deref() == Some("ConfigOverride");
    if is_config_block && !cmd.force {
        return Err(
            "This denial came from your config blocklist; re-run with --force to override.".into(),
        );
    }
    if cmd.json && !cmd.yes && !cmd.dry_run {
        return Err("JSON output requires --yes or --dry-run to avoid prompts.".into());
    }

    let selected_cwd = if selected.cwd == "<unknown>" || selected.cwd.is_empty() {
        cwd
    } else {
        std::path::PathBuf::from(&selected.cwd)
    };
    let repo_root =
        crate::config::find_repo_root(&selected_cwd, crate::config::REPO_ROOT_SEARCH_MAX_HOPS);
    let (scope_kind, scope_path) = repo_root.map_or_else(
        || (AllowOnceScopeKind::Cwd, selected_cwd.clone()),
        |root| (AllowOnceScopeKind::Project, root),
    );
    let scope_path_str = scope_path.to_string_lossy().to_string();

    let entry = AllowOnceEntry::from_pending(
        selected,
        now,
        scope_kind,
        &scope_path_str,
        cmd.single_use,
        cmd.force && is_config_block,
        &config.logging.redaction,
    );

    if cmd.json {
        let output = serde_json::json!({
            "status": "ok",
            "code": code,
            "dry_run": cmd.dry_run,
            "single_use": cmd.single_use,
            "force": entry.force_allow_config,
            "scope_kind": format!("{scope_kind:?}").to_lowercase(),
            "scope_path": scope_path_str,
            "command": if cmd.show_raw { selected.command_raw.clone() } else { selected.command_redacted.clone() },
            "cwd": selected.cwd.clone(),
            "expires_at": entry.expires_at,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
        if cmd.dry_run {
            return Ok(());
        }
    } else {
        let display_command = if cmd.show_raw {
            selected.command_raw.as_str()
        } else {
            selected.command_redacted.as_str()
        };
        println!("Allow-once confirmation:");
        println!("  Command: {display_command}");
        println!("  CWD: {}", selected.cwd);
        println!("  Expires: {}", entry.expires_at);
        println!("  Scope: {scope_kind:?} ({scope_path_str})");
        if cmd.single_use {
            println!("  Mode: single-use");
        } else {
            println!("  Mode: reusable until expiry");
        }

        let needs_prompt = !(cmd.yes || cmd.dry_run);
        if needs_prompt {
            if cmd.force && is_config_block {
                print!("Type 'FORCE' to confirm override: ");
                io::stdout().flush()?;
                let mut response = String::new();
                io::stdin().read_line(&mut response)?;
                if response.trim() != "FORCE" {
                    return Err("Aborted.".into());
                }
            } else {
                print!("Proceed? [y/N]: ");
                io::stdout().flush()?;
                let mut response = String::new();
                io::stdin().read_line(&mut response)?;
                let response = response.trim().to_lowercase();
                if response != "y" && response != "yes" {
                    return Err("Aborted.".into());
                }
            }
        }

        if cmd.dry_run {
            println!("Dry-run: no allow-once entry written.");
            return Ok(());
        }
    }

    let allow_once_path = AllowOnceStore::default_path(Some(&selected_cwd));
    let allow_once_store = AllowOnceStore::new(allow_once_path.clone());
    let _maintenance = allow_once_store.add_entry(&entry, now)?;

    // Remove the pending exception so it doesn't show up in lists anymore.
    // This is best-effort (if it fails, the allowed command still works).
    if let Err(e) = pending_store.remove_by_full_hash(&selected.full_hash, now) {
        eprintln!("Warning: Failed to remove pending exception: {e}");
    }

    if !cmd.json {
        println!("✓ Allow-once entry created");
        println!("  File: {}", allow_once_path.display());
    }

    Ok(())
}

fn handle_allow_once_list(
    _config: &Config,
    cmd: &AllowOnceCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = Utc::now();
    let cwd = std::env::current_dir().unwrap_or_default();

    let pending_store = PendingExceptionStore::new(PendingExceptionStore::default_path(Some(&cwd)));
    let allow_once_store = AllowOnceStore::new(AllowOnceStore::default_path(Some(&cwd)));

    let (pending, pending_maintenance) = pending_store.load_active(now)?;
    let (allow_once, allow_once_maintenance) = allow_once_store.load_active(now)?;

    if cmd.json {
        let output = build_allow_once_list_json(
            &pending,
            pending_maintenance,
            &allow_once,
            allow_once_maintenance,
            cmd.show_raw,
        );
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    println!("Allow-once pending codes: {}", pending.len());
    if pending.is_empty() {
        println!("  (none)");
    } else {
        for record in &pending {
            let cmd_display = if cmd.show_raw {
                record.command_raw.as_str()
            } else {
                record.command_redacted.as_str()
            };
            println!(
                "  - {} [{}] {}",
                record.short_code,
                &record.full_hash[..8.min(record.full_hash.len())],
                cmd_display
            );
        }
    }

    println!();
    println!("Allow-once active entries: {}", allow_once.len());
    if allow_once.is_empty() {
        println!("  (none)");
    } else {
        for entry in &allow_once {
            let cmd_display = if cmd.show_raw {
                entry.command_raw.as_str()
            } else {
                entry.command_redacted.as_str()
            };
            println!(
                "  - {} [{}] {}",
                entry.source_short_code,
                &entry.source_full_hash[..8.min(entry.source_full_hash.len())],
                cmd_display
            );
        }
    }

    if !pending_maintenance.is_empty() || !allow_once_maintenance.is_empty() {
        println!();
        println!(
            "Maintenance: pending(pruned_expired={}, pruned_consumed={}, parse_errors={}), allow_once(pruned_expired={}, pruned_consumed={}, parse_errors={})",
            pending_maintenance.pruned_expired,
            pending_maintenance.pruned_consumed,
            pending_maintenance.parse_errors,
            allow_once_maintenance.pruned_expired,
            allow_once_maintenance.pruned_consumed,
            allow_once_maintenance.parse_errors
        );
    }

    Ok(())
}

fn build_allow_once_list_json(
    pending: &[PendingExceptionRecord],
    pending_maintenance: crate::pending_exceptions::PendingMaintenance,
    allow_once: &[AllowOnceEntry],
    allow_once_maintenance: crate::pending_exceptions::PendingMaintenance,
    show_raw: bool,
) -> serde_json::Value {
    let pending_json: Vec<serde_json::Value> = pending
        .iter()
        .map(|record| {
            serde_json::json!({
                "short_code": &record.short_code,
                "full_hash": &record.full_hash,
                "created_at": &record.created_at,
                "expires_at": &record.expires_at,
                "cwd": &record.cwd,
                "reason": &record.reason,
                "single_use": record.single_use,
                "source": record.source.as_deref(),
                "command": if show_raw { &record.command_raw } else { &record.command_redacted },
            })
        })
        .collect();

    let allow_once_json: Vec<serde_json::Value> = allow_once
        .iter()
        .map(|entry| {
            serde_json::json!({
                "source_short_code": &entry.source_short_code,
                "source_full_hash": &entry.source_full_hash,
                "created_at": &entry.created_at,
                "expires_at": &entry.expires_at,
                "scope_kind": format!("{:?}", entry.scope_kind).to_lowercase(),
                "scope_path": &entry.scope_path,
                "reason": &entry.reason,
                "single_use": entry.single_use,
                "force_allow_config": entry.force_allow_config,
                "command": if show_raw { &entry.command_raw } else { &entry.command_redacted },
            })
        })
        .collect();

    serde_json::json!({
        "status": "ok",
        "pending": {
            "count": pending_json.len(),
            "maintenance": pending_maintenance,
            "entries": pending_json,
        },
        "allow_once": {
            "count": allow_once_json.len(),
            "maintenance": allow_once_maintenance,
            "entries": allow_once_json,
        },
    })
}

fn handle_allow_once_clear(
    config: &Config,
    cmd: &AllowOnceCommand,
    args: &AllowOnceClearArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{self, Write};

    if cmd.json && !cmd.yes {
        return Err("JSON output requires --yes to avoid interactive prompts.".into());
    }

    let now = Utc::now();
    let cwd = std::env::current_dir().unwrap_or_default();

    let pending_store = PendingExceptionStore::new(PendingExceptionStore::default_path(Some(&cwd)));
    let allow_once_store = AllowOnceStore::new(AllowOnceStore::default_path(Some(&cwd)));

    let wipe_pending = args.all || args.pending;
    let wipe_allow_once = args.all || args.allow_once;

    let (pending_preview, pending_preview_maintenance) = pending_store.preview_active(now)?;
    let (allow_once_preview, allow_once_preview_maintenance) =
        allow_once_store.preview_active(now)?;

    let pending_wipe_count = if wipe_pending {
        pending_preview.len()
    } else {
        0
    };
    let allow_once_wipe_count = if wipe_allow_once {
        allow_once_preview.len()
    } else {
        0
    };

    if !cmd.json && !cmd.yes && (wipe_pending || wipe_allow_once) {
        println!("Allow-once clear confirmation:");
        println!("  pending_wipe_active={pending_wipe_count}");
        println!("  allow_once_wipe_active={allow_once_wipe_count}");
        print!("Proceed? [y/N]: ");
        io::stdout().flush()?;
        let mut response = String::new();
        io::stdin().read_line(&mut response)?;
        let response = response.trim().to_lowercase();
        if response != "y" && response != "yes" {
            return Err("Aborted.".into());
        }
    }

    let (pending_wiped, pending_maintenance) = if wipe_pending {
        pending_store.clear_all(now)?
    } else {
        let (_active, maintenance) = pending_store.load_active(now)?;
        (0, maintenance)
    };
    let (allow_once_wiped, allow_once_maintenance) = if wipe_allow_once {
        allow_once_store.clear_all(now)?
    } else {
        let (_active, maintenance) = allow_once_store.load_active(now)?;
        (0, maintenance)
    };

    if let Some(log_file) = config.general.log_file.as_deref() {
        let _ = crate::pending_exceptions::log_allow_once_action(
            log_file,
            "clear",
            &format!(
                "pending_wiped={pending_wiped}, allow_once_wiped={allow_once_wiped}, flags=all:{} pending:{} allow_once:{}",
                args.all, args.pending, args.allow_once
            ),
        );
    }

    if cmd.json {
        let output = serde_json::json!({
            "status": "ok",
            "pending": {
                "wiped": pending_wiped,
                "preview_maintenance": pending_preview_maintenance,
                "maintenance": pending_maintenance,
            },
            "allow_once": {
                "wiped": allow_once_wiped,
                "preview_maintenance": allow_once_preview_maintenance,
                "maintenance": allow_once_maintenance,
            },
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    println!("✓ Cleared allow-once stores");
    println!("  Pending wiped: {pending_wiped}");
    println!("  Allow-once wiped: {allow_once_wiped}");
    Ok(())
}

fn handle_allow_once_revoke(
    config: &Config,
    cmd: &AllowOnceCommand,
    args: &AllowOnceRevokeArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{self, Write};

    if cmd.json && !cmd.yes {
        return Err("JSON output requires --yes to avoid interactive prompts.".into());
    }

    let now = Utc::now();
    let cwd = std::env::current_dir().unwrap_or_default();

    let pending_store = PendingExceptionStore::new(PendingExceptionStore::default_path(Some(&cwd)));
    let allow_once_store = AllowOnceStore::new(AllowOnceStore::default_path(Some(&cwd)));

    let (pending_preview, _) = pending_store.preview_active(now)?;
    let (allow_once_preview, _) = allow_once_store.preview_active(now)?;
    let full_hash =
        resolve_allow_once_revoke_target(&args.target, &pending_preview, &allow_once_preview)?;

    if !cmd.json && !cmd.yes {
        println!("Allow-once revoke confirmation:");
        println!("  target: {}", args.target);
        println!("  resolved_full_hash: {full_hash}");
        print!("Proceed? [y/N]: ");
        io::stdout().flush()?;
        let mut response = String::new();
        io::stdin().read_line(&mut response)?;
        let response = response.trim().to_lowercase();
        if response != "y" && response != "yes" {
            return Err("Aborted.".into());
        }
    }

    let (pending_removed, pending_maintenance) =
        pending_store.remove_by_full_hash(&full_hash, now)?;
    let (allow_once_removed, allow_once_maintenance) =
        allow_once_store.remove_by_source_full_hash(&full_hash, now)?;

    if let Some(log_file) = config.general.log_file.as_deref() {
        let _ = crate::pending_exceptions::log_allow_once_action(
            log_file,
            "revoke",
            &format!(
                "target={}, full_hash={}, pending_removed={}, allow_once_removed={}",
                args.target, full_hash, pending_removed, allow_once_removed
            ),
        );
    }

    if cmd.json {
        let output = serde_json::json!({
            "status": "ok",
            "target": &args.target,
            "full_hash": full_hash,
            "pending": { "removed": pending_removed, "maintenance": pending_maintenance },
            "allow_once": { "removed": allow_once_removed, "maintenance": allow_once_maintenance },
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    println!("✓ Revoked allow-once exception");
    println!("  Pending removed: {pending_removed}");
    println!("  Allow-once removed: {allow_once_removed}");
    Ok(())
}

fn resolve_allow_once_revoke_target(
    target: &str,
    pending: &[PendingExceptionRecord],
    allow_once: &[AllowOnceEntry],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut matches: Vec<String> = Vec::new();

    // Short codes are 5-digit numeric strings; anything else is a hash prefix
    let is_short_code = target.len() <= 5 && target.chars().all(|c| c.is_ascii_digit());

    if is_short_code {
        matches.extend(
            pending
                .iter()
                .filter(|record| record.short_code == target)
                .map(|record| record.full_hash.clone()),
        );
        matches.extend(
            allow_once
                .iter()
                .filter(|entry| entry.source_short_code == target)
                .map(|entry| entry.source_full_hash.clone()),
        );
    } else {
        matches.extend(
            pending
                .iter()
                .filter(|record| record.full_hash.starts_with(target))
                .map(|record| record.full_hash.clone()),
        );
        matches.extend(
            allow_once
                .iter()
                .filter(|entry| entry.source_full_hash.starts_with(target))
                .map(|entry| entry.source_full_hash.clone()),
        );
    }

    matches.sort();
    matches.dedup();

    match matches.as_slice() {
        [] => Err(format!("No allow-once exception found matching '{target}'.").into()),
        [one] => Ok(one.clone()),
        many => Err(format!(
            "Ambiguous allow-once revoke target '{target}'. Matches: {}",
            many.join(", ")
        )
        .into()),
    }
}

fn select_pending_entry<'a>(
    matches: &'a [PendingExceptionRecord],
    cmd: &AllowOnceCommand,
) -> Result<&'a PendingExceptionRecord, Box<dyn std::error::Error>> {
    if matches.len() == 1 {
        return Ok(&matches[0]);
    }

    if let Some(hash) = cmd.hash.as_deref() {
        let record = matches
            .iter()
            .find(|record| record.full_hash == hash)
            .ok_or_else(|| format!("No pending entry with hash '{hash}'"))?;
        return Ok(record);
    }

    if let Some(pick) = cmd.pick {
        if pick == 0 || pick > matches.len() {
            return Err(format!("Pick must be between 1 and {}", matches.len()).into());
        }
        return Ok(&matches[pick - 1]);
    }

    print_pending_choices(matches, cmd.show_raw);
    Err("Multiple pending entries share this code; use --pick or --hash.".into())
}

fn print_pending_choices(matches: &[PendingExceptionRecord], show_raw: bool) {
    println!("Multiple pending entries match this code:");
    for (idx, record) in matches.iter().enumerate() {
        let display_command = if show_raw {
            record.command_raw.as_str()
        } else {
            record.command_redacted.as_str()
        };
        println!(
            "  {}. [{}] {} (cwd: {}, created: {})",
            idx + 1,
            &record.full_hash[..8.min(record.full_hash.len())],
            display_command,
            record.cwd,
            record.created_at
        );
    }
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
    let mut doc = load_or_create_allowlist_doc(&path)?;

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
    write_allowlist(&path, &doc)?;

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
    let mut doc = load_or_create_allowlist_doc(&path)?;

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
    write_allowlist(&path, &doc)?;

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

    let mut doc = load_or_create_allowlist_doc(&path)?;

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

    write_allowlist(&path, &doc)?;

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

/// Write the allowlist document back to disk atomically.
///
/// Uses a temp file + rename strategy to prevent corruption:
/// 1. Write content to a temp file in the same directory
/// 2. Validate the temp file parses correctly as TOML
/// 3. Atomically rename temp file to target path
///
/// This ensures that power loss or crash during write won't leave a
/// corrupted allowlist file.
fn write_allowlist(
    path: &std::path::Path,
    doc: &toml_edit::DocumentMut,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let content = doc.to_string();

    // Create temp file in same directory (required for atomic rename on same filesystem)
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let temp_name = format!(".dcg-allowlist-{}.tmp", std::process::id());
    let temp_path = parent.join(&temp_name);

    // Write to temp file
    {
        let mut temp_file = std::fs::File::create(&temp_path)?;
        temp_file.write_all(content.as_bytes())?;
        temp_file.sync_all()?; // Ensure data is flushed to disk
    }

    // Validate the temp file parses correctly before committing
    let verification = std::fs::read_to_string(&temp_path)?;
    if let Err(parse_err) = verification.parse::<toml_edit::DocumentMut>() {
        // Remove temp file on parse failure
        let _ = std::fs::remove_file(&temp_path);
        return Err(
            format!("Generated TOML failed validation (this is a bug): {parse_err}").into(),
        );
    }

    // Atomic rename (on Unix, this is atomic; on Windows, it replaces atomically)
    std::fs::rename(&temp_path, path)?;

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

/// Build a new pattern entry for a regex-based allowlist (from suggest-allowlist).
///
/// Pattern entries require `risk_acknowledged = true` because they use regex matching.
fn build_pattern_entry(
    pattern: &str,
    reason: &str,
    risk_level: &str,
    confidence_tier: &str,
    frequency: usize,
    unique_variants: usize,
) -> toml_edit::Table {
    let mut tbl = toml_edit::Table::new();

    tbl.insert("pattern", toml_edit::value(pattern));

    // Build a descriptive reason with metadata
    let full_reason = format!(
        "{reason} (auto-suggested: {confidence_tier} confidence, {risk_level} risk, {frequency} occurrences, {unique_variants} variants)"
    );
    tbl.insert("reason", toml_edit::value(full_reason));

    // Add audit metadata
    if let Some(user) = get_current_user() {
        tbl.insert("added_by", toml_edit::value(user));
    }
    tbl.insert("added_at", toml_edit::value(current_timestamp()));

    // Pattern-based allowlist entries MUST acknowledge risk
    tbl.insert("risk_acknowledged", toml_edit::value(true));

    tbl
}

/// Check if a pattern entry already exists in the document.
fn has_pattern_entry(doc: &toml_edit::DocumentMut, pattern: &str) -> bool {
    let Some(allow) = doc.get("allow") else {
        return false;
    };
    let Some(arr) = allow.as_array_of_tables() else {
        return false;
    };

    arr.iter().any(|tbl| {
        tbl.get("pattern")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s == pattern)
    })
}

/// Add a regex pattern to the allowlist (from suggest-allowlist).
///
/// Returns Ok(path) on success, or Err on failure.
fn allowlist_add_pattern(
    pattern: &str,
    reason: &str,
    risk_level: &str,
    confidence_tier: &str,
    frequency: usize,
    unique_variants: usize,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    // Determine layer: prefer project if in a git repo, else user
    let layer = if find_repo_root_from_cwd().is_some() {
        AllowlistLayer::Project
    } else {
        AllowlistLayer::User
    };

    let path = allowlist_path_for_layer(layer);
    let mut doc = load_or_create_allowlist_doc(&path)?;

    // Check for duplicate
    if has_pattern_entry(&doc, pattern) {
        return Err(format!(
            "Pattern '{}' already exists in {} allowlist",
            pattern,
            layer.label()
        )
        .into());
    }

    // Build and append entry
    let entry = build_pattern_entry(
        pattern,
        reason,
        risk_level,
        confidence_tier,
        frequency,
        unique_variants,
    );
    append_entry(&mut doc, entry);

    // Write atomically (temp file + rename to prevent corruption)
    write_allowlist(&path, &doc)?;

    Ok(path)
}

/// Result of pattern conflict detection.
#[derive(Debug, Default)]
pub struct PatternConflictCheck {
    /// True if the pattern may conflict with existing block overrides.
    pub conflicts_with_blocks: bool,
    /// Human-readable warning message if conflicts exist.
    pub block_conflict_warning: Option<String>,
    /// True if the pattern is overly broad (contains unconstrained wildcards).
    pub is_overly_broad: bool,
    /// Human-readable suggestion for refinement if too broad.
    pub refinement_suggestion: Option<String>,
}

/// Check if a suggested pattern has potential conflicts or issues.
///
/// This function performs two checks:
/// 1. Does this pattern potentially overlap with any configured block overrides?
/// 2. Is this pattern overly broad (contains .* or .+ without anchoring)?
///
/// These are informational warnings - they don't prevent adding the pattern.
fn check_pattern_conflicts(pattern: &str, config: &Config) -> PatternConflictCheck {
    let mut result = PatternConflictCheck::default();

    // Check for overly broad patterns
    // A pattern is "overly broad" if it uses .* or .+ without anchors
    let has_unanchored_wildcard = (pattern.contains(".*") || pattern.contains(".+"))
        && !pattern.starts_with('^')
        && !pattern.ends_with('$');

    if has_unanchored_wildcard {
        result.is_overly_broad = true;
        result.refinement_suggestion = Some(
            "Consider adding anchors (^ and $) or more specific token patterns \
             to avoid matching unintended commands."
                .to_string(),
        );
    }

    // Check for conflicts with block overrides
    // We compile the pattern and see if any of the block patterns would match
    // the same space. This is a heuristic check.
    let compiled_overrides = config.overrides.compile();
    if compiled_overrides.block.is_empty() {
        return result;
    }

    // For each block pattern, check if there's textual overlap
    // This is a simple heuristic: we look for common substrings
    let pattern_lower = pattern.to_lowercase();
    for block in &compiled_overrides.block {
        let block_pattern_lower = block.pattern.to_lowercase();

        // Check for substring overlap in the pattern text
        // This is imperfect but catches obvious cases
        let overlap = find_pattern_overlap(&pattern_lower, &block_pattern_lower);
        if overlap {
            result.conflicts_with_blocks = true;
            result.block_conflict_warning = Some(format!(
                "This pattern may conflict with block override: '{}' ({})",
                block.pattern, block.reason
            ));
            break;
        }
    }

    result
}

/// Check for textual overlap between two regex patterns.
///
/// This is a heuristic check that looks for common literal substrings
/// that might indicate the patterns could match overlapping commands.
fn find_pattern_overlap(pattern1: &str, pattern2: &str) -> bool {
    // Extract literal tokens from patterns (words, commands)
    let tokens1: Vec<&str> = pattern1
        .split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_')
        .filter(|s| s.len() >= 3) // Only consider meaningful tokens
        .collect();

    let tokens2: Vec<&str> = pattern2
        .split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_')
        .filter(|s| s.len() >= 3)
        .collect();

    // Check for any common tokens
    for t1 in &tokens1 {
        for t2 in &tokens2 {
            if t1 == t2 {
                return true;
            }
        }
    }

    false
}

/// Handle the --undo flag for suggest-allowlist.
///
/// Removes auto-suggested pattern entries that were added within the last N minutes.
/// This allows users to undo patterns they accepted by mistake.
fn handle_suggest_allowlist_undo(minutes: u32) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let cutoff = Utc::now() - chrono::Duration::minutes(i64::from(minutes));

    // Check both project and user allowlists
    let layers_to_check = [
        (
            AllowlistLayer::Project,
            find_repo_root_from_cwd().map(|r| r.join(".dcg").join("allowlist.toml")),
        ),
        (
            AllowlistLayer::User,
            dirs::config_dir().map(|d| d.join("dcg").join("allowlist.toml")),
        ),
    ];

    let mut total_removed = 0;

    for (layer, path_opt) in layers_to_check {
        let Some(path) = path_opt else {
            continue;
        };

        if !path.exists() {
            continue;
        }

        let Ok(mut doc) = load_or_create_allowlist_doc(&path) else {
            continue;
        };

        let removed = remove_auto_suggested_entries(&mut doc, cutoff);
        if removed > 0 {
            write_allowlist(&path, &doc)?;
            println!(
                "{} Removed {} auto-suggested pattern(s) from {} allowlist ({})",
                "✓".green(),
                removed,
                layer.label(),
                path.display()
            );
            total_removed += removed;
        }
    }

    if total_removed == 0 {
        println!("No auto-suggested patterns found added in the last {minutes} minutes.");
        println!();
        println!("Patterns are identified by:");
        println!("  - Having 'auto-suggested' in the reason field");
        println!("  - Having an added_at timestamp within the time window");
    } else {
        println!();
        println!("Total: {total_removed} pattern(s) removed.");
    }

    Ok(())
}

/// Remove auto-suggested entries added after the cutoff time.
///
/// Returns the number of entries removed.
fn remove_auto_suggested_entries(
    doc: &mut toml_edit::DocumentMut,
    cutoff: chrono::DateTime<Utc>,
) -> usize {
    let Some(allow) = doc.get_mut("allow") else {
        return 0;
    };
    let Some(arr) = allow.as_array_of_tables_mut() else {
        return 0;
    };

    let initial_len = arr.len();

    // Find indices to remove (reverse order to avoid index shifting)
    let mut remove_indices: Vec<usize> = Vec::new();
    for (idx, tbl) in arr.iter().enumerate() {
        // Check if it's an auto-suggested pattern entry
        let is_pattern = tbl.get("pattern").is_some();
        let is_auto_suggested = tbl
            .get("reason")
            .and_then(|v| v.as_str())
            .is_some_and(|r| r.contains("auto-suggested"));

        if !is_pattern || !is_auto_suggested {
            continue;
        }

        // Check the added_at timestamp
        let added_at = tbl.get("added_at").and_then(|v| v.as_str());
        if let Some(timestamp) = added_at {
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(timestamp) {
                if dt >= cutoff {
                    remove_indices.push(idx);
                }
            }
        }
    }

    // Remove in reverse order to maintain correct indices
    for idx in remove_indices.into_iter().rev() {
        arr.remove(idx);
    }

    initial_len - arr.len()
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
    // Fail-closed: treat unparseable timestamps as expired for security.
    // This prevents entries with corrupted/invalid timestamps from persisting indefinitely.
    true
}

// ============================================================================
// Developer Tools (dcg dev)
// ============================================================================

/// Handle all `dcg dev` subcommands
fn handle_dev_command(
    config: &Config,
    action: DevAction,
    verbosity: Verbosity,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        DevAction::TestPattern {
            pattern,
            commands,
            pattern_type,
        } => {
            dev_test_pattern(&pattern, commands, pattern_type)?;
        }
        DevAction::ValidatePack { pack_id } => {
            dev_validate_pack(config, &pack_id, verbosity.is_verbose())?;
        }
        DevAction::Debug { command, all_packs } => {
            dev_debug(config, &command, all_packs);
        }
        DevAction::Benchmark {
            pack_id,
            iterations,
            commands,
        } => {
            dev_benchmark(config, &pack_id, iterations, commands);
        }
        DevAction::GenerateFixtures {
            pack_id,
            output_dir,
            force,
        } => {
            dev_generate_fixtures(&pack_id, &output_dir, force)?;
        }
    }
    Ok(())
}

/// Test a regex pattern against sample commands
fn dev_test_pattern(
    pattern: &str,
    commands: Option<Vec<String>>,
    pattern_type: PatternType,
) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;
    use fancy_regex::Regex;

    println!("{}", "Pattern Tester".bold().cyan());
    println!();
    println!("Pattern: {}", pattern.yellow());
    println!(
        "Type: {}",
        match pattern_type {
            PatternType::Safe => "safe (whitelist)".green(),
            PatternType::Destructive => "destructive (blacklist)".red(),
        }
    );
    println!();

    // Validate regex
    let regex = match Regex::new(pattern) {
        Ok(r) => {
            println!("{} Regex syntax valid", "✓".green());
            r
        }
        Err(e) => {
            println!("{} Regex syntax error: {}", "✗".red(), e);
            return Err(format!("Invalid regex: {e}").into());
        }
    };

    // Analyze regex complexity (basic heuristics)
    let has_lookahead = pattern.contains("(?=") || pattern.contains("(?!");
    let has_lookbehind = pattern.contains("(?<=") || pattern.contains("(?<!");
    let has_backref =
        pattern.contains(r"\1") || pattern.contains(r"\2") || pattern.contains(r"\k<");
    let nested_quantifiers = pattern.contains("+*")
        || pattern.contains("*+")
        || pattern.contains("++")
        || pattern.contains("**");

    let complexity_score = if nested_quantifiers {
        (
            "high".red(),
            "WARNING: nested quantifiers can cause catastrophic backtracking",
        )
    } else if has_backref {
        ("medium".yellow(), "backreferences can be slow")
    } else if has_lookahead || has_lookbehind {
        ("low".green(), "lookarounds are efficient in fancy_regex")
    } else {
        ("minimal".green(), "simple pattern")
    };

    println!(
        "Complexity: {} ({})",
        complexity_score.0, complexity_score.1
    );
    println!();

    // Test against commands
    let test_commands = commands.unwrap_or_else(|| {
        println!(
            "{}",
            "No commands provided. Using default test cases:".dimmed()
        );
        vec![
            "ls -la".to_string(),
            "git status".to_string(),
            "git reset --hard".to_string(),
            "rm -rf /".to_string(),
        ]
    });

    println!("{}", "Test Results:".bold());
    for cmd in &test_commands {
        let matched = regex.is_match(cmd).unwrap_or(false);
        let status = if matched {
            match pattern_type {
                PatternType::Destructive => format!("{} BLOCKED", "✓".green()),
                PatternType::Safe => format!("{} ALLOWED", "✓".green()),
            }
        } else {
            format!("{} no match", "○".dimmed())
        };
        println!(
            "  {} '{}' -> {}",
            if matched { "→" } else { " " },
            cmd,
            status
        );
    }

    Ok(())
}

/// Validate pack structure and patterns
fn dev_validate_pack(
    config: &Config,
    pack_id: &str,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    println!("{}", format!("Validating pack: {pack_id}").bold().cyan());
    println!();

    // Find the pack in the registry
    let enabled_packs = config.enabled_pack_ids();
    let infos = REGISTRY.list_packs(&enabled_packs);

    let pack_info = infos.iter().find(|p| p.id == pack_id);

    if let Some(info) = pack_info {
        println!("{}", "Structure:".bold());
        println!("  {} Pack ID: {}", "✓".green(), info.id);
        println!("  {} Name: {}", "✓".green(), info.name);
        println!("  {} Description: {}", "✓".green(), info.description);
        println!(
            "  {} Status: {}",
            "✓".green(),
            if info.enabled {
                "enabled".green()
            } else {
                "disabled".yellow()
            }
        );
        println!();

        println!("{}", "Patterns:".bold());
        println!(
            "  {} {} safe patterns",
            "✓".green(),
            info.safe_pattern_count
        );
        println!(
            "  {} {} destructive patterns",
            "✓".green(),
            info.destructive_pattern_count
        );

        // Validate all patterns compile
        let pack = REGISTRY.get(pack_id);
        if let Some(p) = pack {
            let mut pattern_errors = Vec::new();

            for safe in &p.safe_patterns {
                match fancy_regex::Regex::new(safe.regex.as_str()) {
                    Ok(re) => {
                        if let Err(e) = re.is_match("test") {
                            pattern_errors.push(format!(
                                "Safe pattern '{}': runtime error: {}",
                                safe.name, e
                            ));
                        }
                    }
                    Err(e) => {
                        pattern_errors.push(format!(
                            "Safe pattern '{}': compile error: {}",
                            safe.name, e
                        ));
                    }
                }
            }

            for destructive in &p.destructive_patterns {
                match fancy_regex::Regex::new(destructive.regex.as_str()) {
                    Ok(re) => {
                        if let Err(e) = re.is_match("test") {
                            pattern_errors.push(format!(
                                "Destructive pattern '{}': runtime error: {}",
                                destructive.name.unwrap_or("unnamed"),
                                e
                            ));
                        }
                    }
                    Err(e) => {
                        pattern_errors.push(format!(
                            "Destructive pattern '{}': compile error: {}",
                            destructive.name.unwrap_or("unnamed"),
                            e
                        ));
                    }
                }
            }

            if pattern_errors.is_empty() {
                println!("  {} All patterns compile successfully", "✓".green());
            } else {
                for err in &pattern_errors {
                    println!("  {} {}", "✗".red(), err);
                }
            }

            if verbose {
                println!();
                println!("{}", "Keywords:".bold());
                println!("  {:?}", p.keywords);
            }
        }

        println!();
        println!("Overall: {}", "PASS".green().bold());
    } else {
        println!("{} Pack '{}' not found", "✗".red(), pack_id);
        println!();
        println!("Available packs:");
        for info in &infos {
            println!("  - {}", info.id);
        }
        return Err(format!("Pack not found: {pack_id}").into());
    }

    Ok(())
}

/// Debug pattern matching for a command
fn dev_debug(config: &Config, command: &str, all_packs: bool) {
    use colored::Colorize;

    println!("{}", "Pattern Matching Debug".bold().cyan());
    println!();
    println!("Command: {}", command.yellow());
    println!();

    let enabled_packs = config.enabled_pack_ids();
    let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);

    // Check keyword matching
    println!("{}", "Keyword Matching:".bold());
    let command_lower = command.to_lowercase();
    let mut matched_keywords: Vec<&str> = Vec::new();
    for &kw in &enabled_keywords {
        if command_lower.contains(kw) {
            matched_keywords.push(kw);
        }
    }

    if matched_keywords.is_empty() {
        println!(
            "  {} No keywords matched (command would be quick-rejected)",
            "○".dimmed()
        );
    } else {
        for kw in &matched_keywords {
            println!("  {} Keyword matched: '{}'", "→".green(), kw);
        }
    }
    println!();

    // Check each pack
    println!("{}", "Pack Evaluation:".bold());
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);

    for pack_id in &ordered_packs {
        if let Some(pack) = REGISTRY.get(pack_id) {
            // Check if pack keywords match
            let pack_matches = pack.keywords.iter().any(|k| command_lower.contains(k));

            if !pack_matches && !all_packs {
                continue;
            }

            let pack_status = if pack_matches {
                format!("[{pack_id}]").green()
            } else {
                format!("[{pack_id}]").dimmed()
            };

            println!("  {pack_status}");

            if !pack_matches {
                println!("    {} No keyword match", "○".dimmed());
                continue;
            }

            // Check safe patterns
            for safe in &pack.safe_patterns {
                let matched = safe.regex.is_match(command);
                if matched {
                    println!(
                        "    {} Safe pattern '{}' -> {}",
                        "✓".green(),
                        safe.name,
                        "MATCH".green().bold()
                    );
                } else if all_packs {
                    println!(
                        "    {} Safe pattern '{}' -> no match",
                        "○".dimmed(),
                        safe.name
                    );
                }
            }

            // Check destructive patterns
            for destructive in &pack.destructive_patterns {
                let matched = destructive.regex.is_match(command);
                if matched {
                    println!(
                        "    {} Destructive pattern '{}' -> {}",
                        "✗".red(),
                        destructive.name.unwrap_or("unnamed"),
                        "MATCH".red().bold()
                    );
                    println!("      Reason: {}", destructive.reason);
                } else if all_packs {
                    println!(
                        "    {} Destructive pattern '{}' -> no match",
                        "○".dimmed(),
                        destructive.name.unwrap_or("unnamed")
                    );
                }
            }
        }
    }
}

/// Run pattern matching benchmarks
#[allow(clippy::cast_precision_loss)]
fn dev_benchmark(config: &Config, pack_id: &str, iterations: usize, commands: Option<Vec<String>>) {
    use colored::Colorize;
    use std::time::Instant;

    println!("{}", "Pattern Matching Benchmark".bold().cyan());
    println!();
    println!(
        "Pack: {}",
        if pack_id == "all" {
            "all enabled packs"
        } else {
            pack_id
        }
    );
    println!("Iterations: {iterations}");
    println!();

    let enabled_packs = config.enabled_pack_ids();

    let test_commands = commands.unwrap_or_else(|| {
        vec![
            "ls -la".to_string(),
            "git status".to_string(),
            "git reset --hard".to_string(),
            "rm -rf /tmp/test".to_string(),
            "docker ps".to_string(),
            "kubectl get pods".to_string(),
        ]
    });

    let packs_to_test: Vec<&str> = if pack_id == "all" {
        enabled_packs.iter().map(String::as_str).collect()
    } else {
        vec![pack_id]
    };

    println!("{}", "Results:".bold());
    println!("{:<40} {:>12} {:>12}", "Command", "Mean (µs)", "Std (µs)");
    println!("{}", "-".repeat(66));

    for cmd in &test_commands {
        let mut times = Vec::with_capacity(iterations);

        for _ in 0..iterations {
            let start = Instant::now();

            for pid in &packs_to_test {
                if let Some(pack) = REGISTRY.get(pid) {
                    for safe in &pack.safe_patterns {
                        let _ = safe.regex.is_match(cmd);
                    }
                    for destructive in &pack.destructive_patterns {
                        let _ = destructive.regex.is_match(cmd);
                    }
                }
            }

            times.push(start.elapsed().as_micros() as f64);
        }

        // Calculate statistics
        let mean = times.iter().sum::<f64>() / times.len() as f64;
        let variance = times.iter().map(|t| (t - mean).powi(2)).sum::<f64>() / times.len() as f64;
        let std_dev = variance.sqrt();

        // Truncate command for display
        let cmd_display = if cmd.len() > 38 {
            format!("{}...", &cmd[..35])
        } else {
            cmd.clone()
        };

        println!(
            "{:<40} {:>12} {:>12}",
            cmd_display,
            format!("{:.1}", mean),
            format!("±{:.1}", std_dev)
        );
    }

    println!();
    println!("Budget: {} per command (hook mode)", "< 500µs".green());
}

/// Generate test fixtures for a pack
fn dev_generate_fixtures(
    pack_id: &str,
    output_dir: &std::path::Path,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;
    use std::fmt::Write;

    // Helper to escape strings for TOML basic strings
    fn escape_toml(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t")
    }

    println!(
        "{}",
        format!("Generating fixtures for: {pack_id}").bold().cyan()
    );
    println!();

    // Find the pack
    let pack = REGISTRY.get(pack_id);

    if let Some(p) = pack {
        // Ensure output directory exists
        std::fs::create_dir_all(output_dir)?;

        let safe_file = output_dir.join(format!("{}_safe.toml", pack_id.replace('.', "_")));
        let destructive_file =
            output_dir.join(format!("{}_destructive.toml", pack_id.replace('.', "_")));

        // Check if files exist
        if !force && (safe_file.exists() || destructive_file.exists()) {
            println!(
                "{} Fixture files already exist. Use --force to overwrite.",
                "✗".red()
            );
            return Err("Files exist".into());
        }

        // Generate safe fixtures
        let mut safe_content = String::from("# Safe pattern test fixtures\n");
        let _ = write!(safe_content, "# Generated for pack: {pack_id}\n\n");

        for safe in &p.safe_patterns {
            let _ = write!(
                safe_content,
                "[[case]]\npattern = \"{}\"\ndescription = \"{}\"\nexpected = \"allow\"\n\n",
                escape_toml(safe.name),
                escape_toml(safe.name)
            );
        }

        // Generate destructive fixtures
        let mut destructive_content = String::from("# Destructive pattern test fixtures\n");
        let _ = write!(destructive_content, "# Generated for pack: {pack_id}\n\n");

        for destructive in &p.destructive_patterns {
            let _ = write!(
                destructive_content,
                "[[case]]\npattern = \"{}\"\ndescription = \"{}\"\nreason = \"{}\"\nexpected = \"deny\"\nrule_id = \"{}:{}\"\n\n",
                escape_toml(destructive.name.unwrap_or("unnamed")),
                escape_toml(destructive.name.unwrap_or("unnamed")),
                escape_toml(destructive.reason),
                pack_id,
                escape_toml(destructive.name.unwrap_or("unnamed"))
            );
        }

        // Write files
        std::fs::write(&safe_file, &safe_content)?;
        std::fs::write(&destructive_file, &destructive_content)?;

        println!("{} Created:", "✓".green());
        println!("  - {}", safe_file.display());
        println!("  - {}", destructive_file.display());
        println!();
        println!(
            "{}",
            "Note: These are skeleton fixtures. Add actual test commands.".dimmed()
        );
    } else {
        println!("{} Pack '{}' not found", "✗".red(), pack_id);
        return Err(format!("Pack not found: {pack_id}").into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct BatchEvalContext {
        enabled_keywords: Vec<&'static str>,
        ordered_packs: Vec<String>,
        keyword_index: Option<crate::packs::EnabledKeywordIndex>,
        compiled_overrides: crate::config::CompiledOverrides,
        allowlists: crate::allowlist::LayeredAllowlist,
        heredoc_settings: crate::config::HeredocSettings,
    }

    fn build_batch_eval_context() -> BatchEvalContext {
        let config = Config::default();
        let compiled_overrides = config.overrides.compile();
        let allowlists = crate::allowlist::LayeredAllowlist::default();
        let heredoc_settings = config.heredoc_settings();
        let enabled_packs = config.enabled_pack_ids();
        let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
        let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
        let keyword_index = REGISTRY.build_enabled_keyword_index(&ordered_packs);

        BatchEvalContext {
            enabled_keywords,
            ordered_packs,
            keyword_index,
            compiled_overrides,
            allowlists,
            heredoc_settings,
        }
    }

    fn process_batch_lines(lines: &[&str]) -> Vec<BatchHookOutput> {
        let ctx = build_batch_eval_context();
        lines
            .iter()
            .enumerate()
            .map(|(index, line)| {
                evaluate_batch_line(
                    index,
                    line,
                    &ctx.enabled_keywords,
                    &ctx.ordered_packs,
                    ctx.keyword_index.as_ref(),
                    &ctx.compiled_overrides,
                    &ctx.allowlists,
                    &ctx.heredoc_settings,
                    true,
                )
            })
            .collect()
    }

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

        let pre = settings
            .get("hooks")
            .and_then(|h| h.get("PreToolUse"))
            .and_then(|arr| arr.as_array())
            .unwrap();
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
        // Tests that `--verbose` with packs command uses the global verbose flag
        let cli = Cli::parse_from(["dcg", "packs", "--verbose"]);
        assert!(matches!(cli.command, Some(Command::ListPacks { .. })));
        assert_eq!(cli.verbose, 1); // Global verbose flag should be set
    }

    #[test]
    fn test_cli_parse_pack_info() {
        let cli = Cli::parse_from(["dcg", "pack", "info", "core.git"]);
        if let Some(Command::Pack {
            action: PackAction::Info { pack_id, .. },
        }) = cli.command
        {
            assert_eq!(pack_id, "core.git");
        } else {
            unreachable!("Expected Pack Info command");
        }
    }

    #[test]
    fn test_cli_parse_test() {
        let cli = Cli::parse_from(["dcg", "test", "git reset --hard"]);
        if let Some(Command::TestCommand { command, .. }) = cli.command {
            assert_eq!(command, "git reset --hard");
        } else {
            unreachable!("Expected TestCommand command");
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
            unreachable!("Expected Update command");
        }
    }

    // ========================================================================
    // Batch hook mode tests
    // ========================================================================

    #[test]
    fn test_batch_processes_multiple_commands() {
        let lines = [
            r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#,
            r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#,
        ];
        let results = process_batch_lines(&lines);

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].index, 0);
        assert_eq!(results[1].index, 1);
        assert_eq!(results[0].decision, "deny");
        assert_eq!(results[1].decision, "allow");
    }

    #[test]
    fn test_batch_maintains_order() {
        let lines = [
            r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#,
            r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#,
            r#"{"tool_name":"Bash","tool_input":{"command":"git log"}}"#,
        ];
        let results = process_batch_lines(&lines);

        let indices: Vec<usize> = results.iter().map(|r| r.index).collect();
        assert_eq!(indices, vec![0, 1, 2]);
        assert_eq!(results[0].decision, "allow");
        assert_eq!(results[1].decision, "deny");
        assert_eq!(results[2].decision, "allow");
    }

    #[test]
    fn test_batch_handles_malformed_line() {
        let lines = [
            "not json",
            r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#,
        ];
        let results = process_batch_lines(&lines);

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].decision, "error");
        assert!(
            results[0]
                .error
                .as_deref()
                .unwrap_or("")
                .contains("JSON parse error")
        );
        assert_eq!(results[1].decision, "allow");
    }

    #[test]
    fn test_batch_skips_non_bash() {
        let lines = [r#"{"tool_name":"Read","tool_input":{"command":"git status"}}"#];
        let results = process_batch_lines(&lines);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, "skip");
        assert!(
            results[0]
                .error
                .as_deref()
                .unwrap_or("")
                .contains("Not a Bash")
        );
    }

    #[test]
    fn test_batch_handles_large_input() {
        let line = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
        let lines: Vec<&str> = std::iter::repeat_n(line, 1000).collect();
        let results = process_batch_lines(&lines);

        assert_eq!(results.len(), 1000);
        assert!(results.iter().all(|r| r.decision == "allow"));
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
            unreachable!("Expected Allowlist Add command");
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
            unreachable!("Expected Allow command");
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
            unreachable!("Expected Unallow command");
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
            unreachable!("Expected Allowlist List command");
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
            unreachable!("Expected Allowlist Validate command");
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
            unreachable!("Expected Allowlist AddCommand command");
        }
    }

    #[test]
    fn test_cli_parse_allow_once() {
        let cli = Cli::parse_from([
            "dcg",
            "allow-once",
            "ab12",
            "--single-use",
            "--dry-run",
            "--yes",
            "--pick",
            "2",
        ]);
        if let Some(Command::AllowOnce(cmd)) = cli.command {
            assert_eq!(cmd.code.as_deref(), Some("ab12"));
            assert!(cmd.action.is_none());
            assert!(cmd.single_use);
            assert!(cmd.dry_run);
            assert!(cmd.yes);
            assert_eq!(cmd.pick, Some(2));
        } else {
            unreachable!("Expected AllowOnce command");
        }
    }

    #[test]
    fn test_cli_parse_allow_once_list() {
        let cli = Cli::parse_from(["dcg", "allow-once", "list"]);
        if let Some(Command::AllowOnce(cmd)) = cli.command {
            assert!(matches!(cmd.action, Some(AllowOnceAction::List)));
        } else {
            unreachable!("Expected AllowOnce list command");
        }
    }

    #[test]
    fn test_cli_parse_allow_once_revoke_with_global_flags_after_subcommand() {
        let cli = Cli::parse_from(["dcg", "allow-once", "revoke", "deadbeef", "--yes", "--json"]);
        if let Some(Command::AllowOnce(cmd)) = cli.command {
            assert!(cmd.yes);
            assert!(cmd.json);
            assert!(matches!(cmd.action, Some(AllowOnceAction::Revoke(_))));
        } else {
            unreachable!("Expected AllowOnce revoke command");
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
        // Invalid date IS considered expired (fail-closed for security)
        // This prevents entries with corrupted timestamps from persisting indefinitely
        assert!(is_expired("not-a-date"));
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
        assert!(
            has_rule_entry(&doc_before, &rule),
            "should have existing rule"
        );

        // Remove it
        let mut doc_to_modify = load_or_create_allowlist_doc(&path).unwrap();
        let removed = remove_rule_entry(&mut doc_to_modify, &rule);
        assert!(removed, "should have removed entry");
        write_allowlist(&path, &doc_to_modify).unwrap();

        // Verify it's gone
        let doc_after = load_or_create_allowlist_doc(&path).unwrap();
        assert!(
            !has_rule_entry(&doc_after, &rule),
            "should not have existing rule"
        );
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
    fn allowlist_pattern_entry_creates_valid_toml() {
        use tempfile::TempDir;
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("allowlist.toml");

        // File should not exist yet
        assert!(!path.exists());

        // Create a pattern entry (as would be done by suggest-allowlist)
        let mut doc = load_or_create_allowlist_doc(&path).unwrap();
        let entry = build_pattern_entry(
            "npm run (build|test|lint)",
            "NPM scripts",
            "low",
            "high",
            42,
            3,
        );
        append_entry(&mut doc, entry);
        write_allowlist(&path, &doc).unwrap();

        // File should now exist with correct content
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("pattern = \"npm run (build|test|lint)\""),
            "pattern should be in TOML"
        );
        assert!(
            content.contains("risk_acknowledged = true"),
            "risk_acknowledged should be true for patterns"
        );
        assert!(
            content.contains("auto-suggested"),
            "reason should mention auto-suggested"
        );
        assert!(
            content.contains("42 occurrences"),
            "reason should include frequency"
        );
    }

    #[test]
    fn allowlist_pattern_duplicate_detection() {
        use tempfile::TempDir;
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("allowlist.toml");

        let pattern = "npm run (build|test)";

        // Add first pattern entry
        let mut doc = load_or_create_allowlist_doc(&path).unwrap();
        let entry = build_pattern_entry(pattern, "test", "low", "high", 10, 2);
        append_entry(&mut doc, entry);
        write_allowlist(&path, &doc).unwrap();

        // has_pattern_entry should detect duplicate
        let doc2 = load_or_create_allowlist_doc(&path).unwrap();
        assert!(
            has_pattern_entry(&doc2, pattern),
            "should detect existing pattern"
        );
        assert!(
            !has_pattern_entry(&doc2, "different pattern"),
            "should not detect different pattern"
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
    // Allowlist write safety tests (5apz.5)
    // ========================================================================

    #[test]
    fn allowlist_pattern_write_includes_risk_acknowledged() {
        // Pattern entries must always include risk_acknowledged = true
        let entry = build_pattern_entry(
            "rm -rf /tmp/cache.*",
            "Temporary cache cleanup",
            "medium",
            "high",
            15,
            3,
        );

        // Verify risk_acknowledged is present and true
        let risk_ack = entry.get("risk_acknowledged");
        assert!(
            risk_ack.is_some(),
            "risk_acknowledged field must be present"
        );
        assert_eq!(
            risk_ack.unwrap().as_bool(),
            Some(true),
            "risk_acknowledged must be true for pattern entries"
        );
    }

    #[test]
    fn allowlist_pattern_write_prevents_duplicates() {
        use tempfile::TempDir;
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("allowlist.toml");

        let pattern = "npm run (dev|start|test)";

        // Write pattern once
        let mut doc = load_or_create_allowlist_doc(&path).unwrap();
        let entry = build_pattern_entry(pattern, "NPM scripts", "low", "high", 50, 3);
        append_entry(&mut doc, entry);
        write_allowlist(&path, &doc).unwrap();

        // Verify the pattern exists
        let doc2 = load_or_create_allowlist_doc(&path).unwrap();
        assert!(
            has_pattern_entry(&doc2, pattern),
            "pattern should exist after write"
        );

        // Attempting to add again should be detected as duplicate
        assert!(
            has_pattern_entry(&doc2, pattern),
            "duplicate detection should work before write attempt"
        );
    }

    #[test]
    fn allowlist_pattern_entry_format_matches_spec() {
        // Verify all required fields are present in pattern entries
        let entry = build_pattern_entry(
            "git (fetch|pull|push) origin",
            "Git remote operations",
            "low",
            "high",
            100,
            3,
        );

        // Required fields for pattern entries
        assert!(entry.get("pattern").is_some(), "pattern field is required");
        assert!(entry.get("reason").is_some(), "reason field is required");
        assert!(
            entry.get("risk_acknowledged").is_some(),
            "risk_acknowledged is required"
        );
        assert!(
            entry.get("added_at").is_some(),
            "added_at timestamp is required"
        );

        // Verify pattern value
        assert_eq!(
            entry.get("pattern").unwrap().as_str(),
            Some("git (fetch|pull|push) origin")
        );

        // Verify reason includes auto-suggested metadata
        let reason = entry.get("reason").unwrap().as_str().unwrap();
        assert!(
            reason.contains("auto-suggested"),
            "reason should mention auto-suggested"
        );
        assert!(
            reason.contains("high confidence"),
            "reason should include confidence tier"
        );
        assert!(
            reason.contains("low risk"),
            "reason should include risk level"
        );
        assert!(
            reason.contains("100 occurrences"),
            "reason should include frequency"
        );
        assert!(
            reason.contains("3 variants"),
            "reason should include variant count"
        );
    }

    #[test]
    fn suggestion_audit_entry_includes_required_metadata() {
        // Verify that SuggestionAuditEntry can be constructed with all required fields
        use crate::history::{SuggestionAction, SuggestionAuditEntry};

        let entry = SuggestionAuditEntry {
            timestamp: Utc::now(),
            action: SuggestionAction::Accepted,
            pattern: "npm run (build|test)".to_string(),
            final_pattern: None,
            risk_level: "low".to_string(),
            risk_score: 0.15,
            confidence_tier: "high".to_string(),
            confidence_points: 85,
            cluster_frequency: 42,
            unique_variants: 3,
            sample_commands: r#"["npm run build","npm run test"]"#.to_string(),
            rule_id: None,
            session_id: Some("test-session-123".to_string()),
            working_dir: Some("/home/user/project".to_string()),
        };

        // Verify all fields are accessible and correct
        assert_eq!(entry.pattern, "npm run (build|test)");
        assert_eq!(entry.action, SuggestionAction::Accepted);
        assert_eq!(entry.risk_level, "low");
        assert!(entry.risk_score > 0.0);
        assert_eq!(entry.confidence_tier, "high");
        assert_eq!(entry.confidence_points, 85);
        assert_eq!(entry.cluster_frequency, 42);
        assert_eq!(entry.unique_variants, 3);
        assert!(entry.sample_commands.contains("npm run build"));
    }

    #[test]
    fn suggestion_audit_entry_can_be_stored_and_retrieved() {
        use crate::history::{HistoryDb, SuggestionAction, SuggestionAuditEntry};

        let db = HistoryDb::open_in_memory().unwrap();

        let entry = SuggestionAuditEntry {
            timestamp: Utc::now(),
            action: SuggestionAction::Accepted,
            pattern: "cargo (build|test|run)".to_string(),
            final_pattern: None,
            risk_level: "low".to_string(),
            risk_score: 0.1,
            confidence_tier: "high".to_string(),
            confidence_points: 90,
            cluster_frequency: 100,
            unique_variants: 3,
            sample_commands: r#"["cargo build","cargo test"]"#.to_string(),
            rule_id: None,
            session_id: Some("cli-test-session".to_string()),
            working_dir: Some("/test/project".to_string()),
        };

        // Store the entry
        let id = db.log_suggestion_audit(&entry).unwrap();
        assert!(id > 0, "should return positive row ID");

        // Retrieve and verify
        let results = db.query_suggestion_audits(1, None).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pattern, "cargo (build|test|run)");
        assert_eq!(results[0].action, SuggestionAction::Accepted);
        assert_eq!(results[0].session_id, Some("cli-test-session".to_string()));
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
            unreachable!("Expected Scan command");
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
            unreachable!("Expected Scan command");
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
            unreachable!("Expected Scan command");
        }
    }

    #[test]
    fn test_cli_parse_scan_format_json() {
        let cli =
            Cli::try_parse_from(["dcg", "scan", "--staged", "--format", "json"]).expect("parse");
        if let Some(Command::Scan(scan)) = cli.command {
            assert_eq!(scan.format, Some(crate::scan::ScanFormat::Json));
        } else {
            unreachable!("Expected Scan command");
        }
    }

    #[test]
    fn test_cli_parse_scan_fail_on() {
        let cli = Cli::try_parse_from(["dcg", "scan", "--staged", "--fail-on", "warning"])
            .expect("parse");
        if let Some(Command::Scan(scan)) = cli.command {
            assert_eq!(scan.fail_on, Some(crate::scan::ScanFailOn::Warning));
        } else {
            unreachable!("Expected Scan command");
        }
    }

    #[test]
    fn test_cli_parse_scan_max_file_size() {
        let cli = Cli::try_parse_from(["dcg", "scan", "--staged", "--max-file-size", "2048"])
            .expect("parse");
        if let Some(Command::Scan(scan)) = cli.command {
            assert_eq!(scan.max_file_size, Some(2048));
        } else {
            unreachable!("Expected Scan command");
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
            unreachable!("Expected Scan command");
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
            unreachable!("Expected Scan command");
        }
    }

    #[test]
    fn test_cli_parse_scan_uninstall_pre_commit() {
        let cli = Cli::try_parse_from(["dcg", "scan", "uninstall-pre-commit"]).expect("parse");
        if let Some(Command::Scan(scan)) = cli.command {
            assert!(matches!(scan.action, Some(ScanAction::UninstallPreCommit)));
        } else {
            unreachable!("Expected Scan command");
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
    fn test_cli_parse_history_stats() {
        let cli = Cli::try_parse_from([
            "dcg", "history", "stats", "--days", "7", "--json", "--trends",
        ])
        .expect("parse");
        if let Some(Command::History { action }) = cli.command {
            if let HistoryAction::Stats { days, trends, json } = action {
                assert_eq!(days, 7);
                assert!(trends);
                assert!(json);
            } else {
                unreachable!("Expected History stats action");
            }
        } else {
            unreachable!("Expected History command");
        }
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
            unreachable!("Expected Explain command");
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
            unreachable!("Expected Explain command");
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
            assert_eq!(format, TestFormat::Pretty); // default format
        } else {
            unreachable!("Expected TestCommand");
        }
    }

    #[test]
    fn test_cli_parse_test_with_format_json() {
        let cli =
            Cli::try_parse_from(["dcg", "test", "--format", "json", "rm -rf /tmp"]).expect("parse");
        if let Some(Command::TestCommand {
            command, format, ..
        }) = cli.command
        {
            assert_eq!(command, "rm -rf /tmp");
            assert_eq!(format, TestFormat::Json);
        } else {
            unreachable!("Expected TestCommand");
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
            assert_eq!(format, TestFormat::Pretty); // default
        } else {
            unreachable!("Expected TestCommand");
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

        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
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
            unreachable!("Expected Scan command");
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
    fn allow_once_disambiguation_selects_by_pick_or_hash() {
        use crate::logging::{RedactionConfig, RedactionMode};

        let ts = chrono::DateTime::parse_from_rfc3339("2099-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let redaction = RedactionConfig {
            enabled: true,
            mode: RedactionMode::Arguments,
            max_argument_len: 8,
        };

        let a =
            PendingExceptionRecord::new(ts, "/repo", "git status", "ok", &redaction, false, None);
        let mut b = PendingExceptionRecord::new(
            ts,
            "/repo",
            "git reset --hard",
            "blocked",
            &redaction,
            false,
            None,
        );
        // Force a short-code collision to exercise disambiguation.
        b.short_code = a.short_code.clone();

        let cmd_pick = AllowOnceCommand {
            action: None,
            code: Some(a.short_code.clone()),
            yes: true,
            show_raw: false,
            dry_run: true,
            json: true,
            single_use: false,
            force: false,
            pick: Some(2),
            hash: None,
        };
        let records = [a.clone(), b.clone()];
        let selected = select_pending_entry(&records, &cmd_pick).unwrap();
        assert_eq!(selected.command_raw, b.command_raw);

        let cmd_hash = AllowOnceCommand {
            action: None,
            code: Some(a.short_code.clone()),
            yes: true,
            show_raw: false,
            dry_run: true,
            json: true,
            single_use: false,
            force: false,
            pick: None,
            hash: Some(b.full_hash.clone()),
        };
        let records = [a, b.clone()];
        let selected = select_pending_entry(&records, &cmd_hash).unwrap();
        assert_eq!(selected.full_hash, b.full_hash);
    }

    #[test]
    fn allow_once_disambiguation_rejects_invalid_pick() {
        use crate::logging::{RedactionConfig, RedactionMode};

        let ts = chrono::DateTime::parse_from_rfc3339("2099-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let redaction = RedactionConfig {
            enabled: true,
            mode: RedactionMode::Arguments,
            max_argument_len: 8,
        };

        let a =
            PendingExceptionRecord::new(ts, "/repo", "git status", "ok", &redaction, false, None);
        let mut b = PendingExceptionRecord::new(
            ts,
            "/repo",
            "git reset --hard",
            "blocked",
            &redaction,
            false,
            None,
        );
        b.short_code = a.short_code.clone();

        let cmd_pick = AllowOnceCommand {
            action: None,
            code: Some(a.short_code.clone()),
            yes: true,
            show_raw: false,
            dry_run: true,
            json: true,
            single_use: false,
            force: false,
            pick: Some(3),
            hash: None,
        };

        let records = [a, b];
        let err = select_pending_entry(&records, &cmd_pick).expect_err("invalid pick should error");
        assert!(err.to_string().contains("Pick must be between 1 and 2"));
    }

    #[test]
    fn smoke_test_passes_with_default_config() {
        // The smoke test should pass with default configuration
        assert!(run_smoke_test(), "smoke test should pass");
    }

    #[test]
    fn prompt_disabled_for_json_format() {
        let verbosity = Verbosity {
            level: 1,
            quiet: false,
        };
        assert!(!should_prompt_interactively(
            TestFormat::Json,
            verbosity,
            DecisionMode::Deny,
            Some(PackSeverity::Medium),
            &InteractiveConfig::default(),
        ));
    }

    #[test]
    fn prompt_disabled_for_non_blocking_mode() {
        let verbosity = Verbosity {
            level: 1,
            quiet: false,
        };
        assert!(!should_prompt_interactively(
            TestFormat::Pretty,
            verbosity,
            DecisionMode::Warn,
            Some(PackSeverity::Medium),
            &InteractiveConfig::default(),
        ));
    }
}
