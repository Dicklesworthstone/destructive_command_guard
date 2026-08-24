//! CLI argument parsing and command handling.
//!
//! This module provides the command-line interface for dcg (`destructive_command_guard`),
//! including subcommands for configuration management and pack information.

use chrono::Utc;
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::generate;
use inquire::{Select, Text};

use crate::agent::{DetectionMethod, detect_agent_with_details};
use crate::config::{Config, ConfigFileLayer, ConfigFileStatus, ConfigSourceOutcome};
use crate::evaluator::{
    DEFAULT_WINDOW_WIDTH, EvaluationDecision, EvaluationResult, MatchSource,
    evaluate_command_with_pack_order, evaluate_command_with_pack_order_deadline_at_path,
    evaluate_command_with_pack_order_deadline_at_path_in_dialect,
};
use crate::exit_codes::{EXIT_DENIED, EXIT_WARNING};
use crate::highlight::{HighlightSpan, format_highlighted_command, should_use_color};
use crate::history::{
    ExportOptions, HistoryDb, HistoryStats, InteractiveAllowlistAuditEntry,
    InteractiveAllowlistOptionType, Outcome, SuggestionAction, SuggestionAuditEntry,
};
use crate::interactive::{
    AllowlistScope, InteractiveConfig, InteractiveResult, check_interactive_available,
    print_not_available_message, run_interactive_prompt,
};
use crate::load_default_allowlists;
use crate::output::robot_mode_enabled;
use crate::packs::{
    DecisionMode, ExternalPackStore, REGISTRY, Severity as PackSeverity, get_external_packs,
    load_external_packs,
};
use crate::pending_exceptions::{
    AllowOnceEntry, AllowOnceScopeKind, AllowOnceStore, PendingExceptionRecord,
    PendingExceptionStore,
};
use crate::perf::Deadline;
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
        action = clap::ArgAction::SetTrue,
        value_parser = clap::builder::FalseyValueParser::new(),
        global = true,
        conflicts_with = "verbose",
        env = "DCG_QUIET"
    )]
    pub quiet: bool,

    /// Use legacy output rendering (fallback if rich output causes issues)
    #[arg(
        long,
        action = clap::ArgAction::SetTrue,
        value_parser = clap::builder::FalseyValueParser::new(),
        global = true,
        env = "DCG_LEGACY_OUTPUT"
    )]
    pub legacy_output: bool,

    /// Disable colored output globally
    #[arg(
        long,
        action = clap::ArgAction::SetTrue,
        value_parser = clap::builder::FalseyValueParser::new(),
        global = true,
        env = "DCG_NO_COLOR"
    )]
    pub no_color: bool,

    /// Disable suggestion output in warnings/denials
    #[arg(
        long,
        action = clap::ArgAction::SetTrue,
        value_parser = clap::builder::FalseyValueParser::new(),
        global = true,
        env = "DCG_NO_SUGGESTIONS"
    )]
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
    /// - 1: Denied / Blocked / Indeterminate
    /// - 2: Warning (with --fail-on warn)
    /// - 3: Configuration error
    /// - 4: Parse/input error
    /// - 5: IO error
    ///
    /// Enable robot mode for machine-friendly output (also enabled by DCG_ROBOT=1 env var).
    /// In robot mode: always outputs JSON, silent stderr, standardized exit codes.
    #[arg(long, global = true)]
    pub robot: bool,

    /// Override automatic agent detection for agent-specific profiles
    #[arg(long, global = true, value_name = "AGENT")]
    pub agent: Option<String>,

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

        /// Exit non-zero when checks fail (for `dcg doctor || handle_failure`)
        #[arg(long)]
        strict: bool,

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

        /// Add to explicitly trusted project allowlist (default: user)
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

        /// Remove from explicitly trusted project allowlist (default: user)
        #[arg(long, conflicts_with = "user")]
        project: bool,

        /// Remove from user allowlist
        #[arg(long, conflicts_with = "project")]
        user: bool,
    },

    /// Allow a blocked command once using the short code
    #[command(name = "allow-once")]
    AllowOnce(AllowOnceCommand),

    /// Issue a short-lived permit that unblocks `git checkout --` and
    /// `git restore` for the next recovery step.
    ///
    /// Use this when `git pull --rebase` has failed partway (e.g., after a
    /// stash pop left the worktree messy) and the next step really is to
    /// discard the mess. The permit is scoped to the current repository's
    /// `.dcg/` state dir, expires after a short TTL (default 120s), and is
    /// consumed on the first matching allow. During an active rebase
    /// (`.git/rebase-merge/` or `.git/rebase-apply/` present) the permit is
    /// not needed — dcg unblocks automatically in that state.
    #[command(name = "rebase-recover")]
    RebaseRecover {
        /// Permit time-to-live in seconds (default 120, max 600).
        #[arg(long, value_name = "SECONDS")]
        ttl: Option<u64>,
    },

    /// Install the hook into Claude Code settings (or another agent with
    /// `--grok`, `--agy`, `--opencode`, or `--omp`)
    #[command(name = "install")]
    Install {
        /// Force overwrite existing hook configuration
        #[arg(long)]
        force: bool,

        /// Install to project-level `.claude/settings.json` (in the current repo)
        /// instead of user-level `~/.claude/settings.json`
        #[arg(long)]
        project: bool,

        /// Install the dcg PreToolUse hook for Grok (xAI) at
        /// `~/.grok/hooks/dcg.json` (user-level) or `./.grok/hooks/dcg.json`
        /// (when combined with `--project`). Grok also picks up dcg from
        /// `~/.claude/settings.json` via its Claude-Code compatibility layer,
        /// but the native path gives the cleanest doctor output.
        #[arg(long, conflicts_with_all = ["agy", "opencode", "omp"])]
        grok: bool,

        /// Install the dcg PreToolUse hook for the Antigravity CLI (`agy`) at
        /// `~/.gemini/config/hooks.json` (user-level) or
        /// `<repo>/.gemini/config/hooks.json` (with `--project`). `agy` reads
        /// Claude-Code-compatible `PreToolUse` hooks from this file and aborts
        /// its `run_command` shell tool when dcg returns a block decision.
        #[arg(long, conflicts_with_all = ["grok", "opencode", "omp"])]
        agy: bool,

        /// Install a native OpenCode plugin at
        /// `~/.config/opencode/plugins/dcg-guard.js` (user-level, covering
        /// every project) or `<repo>/.opencode/plugins/dcg-guard.js` (with
        /// `--project`). The plugin implements OpenCode's
        /// `tool.execute.before` hook: every bash tool call is routed through
        /// dcg's Claude-compatible hook protocol, and a deny aborts the tool
        /// call with dcg's reason. Restart OpenCode after installing (#318).
        #[arg(long, conflicts_with_all = ["grok", "agy", "omp"])]
        opencode: bool,

        /// Install a native Oh My Pi (`omp`) `tool_call` extension at the
        /// active user profile's `extensions/dcg-guard.ts` path (normally
        /// `~/.omp/agent/extensions/dcg-guard.ts`) or
        /// `<cwd>/.omp/extensions/dcg-guard.ts` (with `--project`). OMP's
        /// extension discovery is cwd-only and does not walk Git ancestors.
        /// Every OMP bash tool call is routed through dcg before execution.
        #[arg(long, conflicts_with_all = ["grok", "agy", "opencode"])]
        omp: bool,
    },

    /// Full setup: install hook + add shell startup check
    ///
    /// Installs the dcg hook into Claude Code settings (like `dcg install`)
    /// and optionally adds a shell startup check to ~/.bashrc and/or ~/.zshrc
    /// that warns if the hook is ever silently removed.
    #[command(name = "setup")]
    Setup {
        /// Force overwrite existing hook configuration
        #[arg(long)]
        force: bool,

        /// Skip the interactive prompt and automatically add the shell check
        #[arg(long)]
        shell_check: bool,

        /// Skip the shell startup check prompt
        #[arg(long)]
        no_shell_check: bool,
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

        /// Show all patterns in verbose pack trees
        #[arg(long)]
        expand: bool,

        /// Maximum patterns to show per verbose section before truncating
        #[arg(long, value_name = "N", default_value_t = crate::output::DEFAULT_PACK_TREE_MAX_PATTERNS)]
        max_patterns: usize,

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
        #[arg(
            value_name = "COMMAND",
            required_unless_present = "stdin",
            conflicts_with = "stdin"
        )]
        command: Option<String>,

        /// Read the command to test from stdin
        ///
        /// This keeps destructive test text off the parent shell command line,
        /// which is useful when dcg is itself installed as that shell's hook.
        #[arg(long)]
        stdin: bool,

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

        /// Apply the live hook's wall-clock evaluation deadline
        #[arg(long, conflicts_with = "explain")]
        enforce_budget: bool,

        /// Bypass a soft block from the graduated response system
        #[arg(long)]
        force: bool,

        /// Evaluate a single shell dialect instead of all of them (#269)
        ///
        /// `--dialect posix` reproduces the evaluation path the Bash
        /// PreToolUse hook takes; the default (`unknown`) fans out to every
        /// dialect because the CLI cannot know the source shell.
        #[arg(long, value_enum, default_value = "unknown", env = "DCG_DIALECT")]
        dialect: DialectArg,
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

        /// Auto-detect packs from project files in the current directory
        #[arg(long)]
        auto: bool,

        /// Preview what --auto would enable without writing anything
        #[arg(long)]
        dry_run: bool,

        /// Directory to scan for project files (defaults to current directory)
        #[arg(long)]
        project_dir: Option<String>,
    },

    /// Show current configuration (or manage config tooling)
    ///
    /// With no subcommand, prints the effective merged configuration. The
    /// `schema` subcommand emits the JSON Schema for `config.toml` (for editor
    /// autocomplete/validation via Even Better TOML / taplo).
    #[command(name = "config")]
    ShowConfig {
        /// Output format (`pretty` for humans, `json` for agents/scripts)
        #[arg(long, value_enum, default_value_t = ConfigFormat::Pretty, env = "DCG_FORMAT")]
        format: ConfigFormat,

        /// Config tooling subcommand (omit to show the effective configuration)
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },

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

        /// Evaluate a single shell dialect instead of all of them (#269)
        ///
        /// `--dialect posix` reproduces the evaluation path the Bash
        /// PreToolUse hook takes; the default (`unknown`) fans out to every
        /// dialect because the CLI cannot know the source shell.
        #[arg(long, value_enum, default_value = "unknown", env = "DCG_DIALECT")]
        dialect: DialectArg,
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

    /// Classify a command's risk level without blocking
    ///
    /// Returns structured risk classification (JSON or text) instead of a
    /// block/pass decision. Designed for Claude Code hooks to use dcg
    /// bidirectionally: block dangerous commands AND auto-allow safe ones.
    ///
    /// Exit codes (consistent with dcg exit code contract):
    /// - 0: allow (safe or low risk)
    /// - 2: warn (medium risk)
    /// - 1: block (high or critical risk)
    ///
    /// # Examples
    ///
    /// ```bash
    /// # JSON output (default)
    /// dcg classify "git status"
    ///
    /// # Text output
    /// dcg classify --format text "rm -rf /"
    ///
    /// # Use in Claude Code hook to auto-allow safe commands
    /// dcg classify --format json "ls -la"
    /// ```
    #[command(name = "classify")]
    Classify {
        /// Command to classify
        command: String,

        /// Output format (json or text)
        #[arg(
            long,
            short = 'f',
            value_enum,
            default_value = "json",
            env = "DCG_FORMAT"
        )]
        format: ClassifyFormat,

        /// Disable colored output
        #[arg(long)]
        no_color: bool,
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

    /// Additional packs to enable for this hook run (comma-separated)
    ///
    /// Mirrors `dcg test --with-packs`: enables extra packs (e.g.
    /// `containers.docker`, `kubernetes.kubectl`) for the batch evaluation
    /// without editing a config file (issue #151).
    #[arg(long, value_delimiter = ',')]
    pub with_packs: Option<Vec<String>>,
}

/// Output format for batch hook mode.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BatchHookOutput {
    /// Index of the input line (0-based)
    pub index: usize,
    /// Decision: "allow", "deny", or "indeterminate"
    pub decision: &'static str,
    /// Policy mode resolved for the matched rule: "deny", "ask", "warn", or
    /// "log". Present only when a rule matched. `warn` and `log` matches are
    /// reported with `decision: "allow"` because the active `[policy]`
    /// allows them — the same resolution bare `dcg` and `dcg test` apply
    /// (#330). `ask` is reported as `deny`: this protocol has no review
    /// channel, so it blocks exactly like a non-review-capable hook.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<&'static str>,
    /// Rule ID if a rule matched (e.g., "core.git:reset-hard")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Pack ID if a rule matched
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
    /// TOON output for token-efficient structured data
    Toon,
}

impl TestFormat {
    #[must_use]
    pub const fn is_structured(self) -> bool {
        matches!(self, Self::Json | Self::Toon)
    }
}

/// Output format for classify command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum ClassifyFormat {
    /// Structured JSON output (default for agent consumption)
    #[default]
    #[value(alias = "sarif")]
    Json,
    /// Human-readable text output
    #[value(alias = "human")]
    Text,
}

/// Output format for the `config` command (issue #159).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum ConfigFormat {
    /// Human-readable text output
    #[default]
    #[value(alias = "text")]
    Pretty,
    /// Structured JSON output for programmatic consumption
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

/// Schema version for ClassifyOutput JSON format
const CLASSIFY_OUTPUT_SCHEMA_VERSION: u32 = 1;

/// Stable machine- and human-readable explanation for an incomplete safety
/// evaluation. Keep this wording distinct from a rule denial: no destructive
/// pattern has been proven, but execution is still blocked conservatively.
const INDETERMINATE_REASON: &str = "Safety evaluation did not complete within the analysis budget";

const fn policy_blocks_cli_execution(
    decision: EvaluationDecision,
    mode: Option<DecisionMode>,
) -> bool {
    match decision {
        EvaluationDecision::Allow => false,
        EvaluationDecision::Indeterminate => true,
        EvaluationDecision::Deny => !matches!(mode, Some(DecisionMode::Warn | DecisionMode::Log)),
    }
}

/// JSON output structure for `dcg classify` command.
///
/// Provides risk classification for a command, enabling Claude Code hooks
/// to make bidirectional decisions: block dangerous commands AND auto-allow safe ones.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClassifyOutput {
    /// Schema version for forward compatibility (currently 1)
    pub schema_version: u32,
    /// DCG version (e.g., "0.3.0")
    pub dcg_version: String,
    /// The command that was classified
    pub command: String,
    /// The decision: "allow", "warn", "block", or "indeterminate"
    pub decision: String,
    /// Risk level: "safe", "low", "medium", "high", "critical", or "unknown"
    pub risk_level: String,
    /// Risk score from 0.0 (safe) to 1.0 (critical)
    pub risk_score: f64,
    /// Reasons for the classification (empty if safe)
    pub reasons: Vec<ClassifyReason>,
    /// Suggested safer alternatives (empty if safe)
    pub suggestions: Vec<String>,
}

/// A single reason contributing to a classify decision.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClassifyReason {
    /// Rule identifier (e.g., "core.git:reset-hard")
    pub rule_id: String,
    /// Severity: "critical", "high", "medium", "low"
    pub severity: String,
    /// Human-readable explanation of why this pattern matched
    pub explanation: String,
}

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
    /// The policy decision: "allow", "deny", "ask", "warn", "log", or "indeterminate"
    pub decision: String,
    /// Resolved policy mode for a matched rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
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
    /// Dialect-divergence metadata (#289): present only when the command was
    /// evaluated under the default all-dialect (`unknown`) analysis and that
    /// analysis denied it. Additive field — absent means "not checked".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dialect_divergence: Option<DialectDivergence>,
}

/// Whether the posix dialect alone — the dialect the live Bash hook uses —
/// would allow a command the all-dialect analysis denied (#289).
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct DialectDivergence {
    /// `true` when posix alone allows: the denial is a diagnostics-only
    /// verdict that the Bash hook would never produce.
    pub posix_would_allow: bool,
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

    /// Apply suggestions by index (comma-separated, 1-based). Skips interactive prompts.
    /// Example: --apply 1,3,5
    #[arg(long, value_delimiter = ',')]
    pub apply: Option<Vec<usize>>,

    /// Permit `--apply` to write suggestions whose safety decision is
    /// `RequireConfirmation` (e.g. patterns that touch system paths). Without
    /// this flag those suggestions are skipped to preserve the safety
    /// gate normally enforced in interactive mode.
    #[arg(long)]
    pub accept_risk: bool,
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

    /// Show interactive allowlist audit entries
    #[command(name = "interactive")]
    Interactive {
        /// Maximum number of entries to show
        #[arg(long, value_name = "N", default_value = "50")]
        limit: usize,

        /// Filter by option type (exact, temporary, path_specific)
        #[arg(long, value_name = "TYPE")]
        option: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
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

    /// Only update the binary; skip hook configuration and shell RC modifications.
    ///
    /// Equivalent to passing `--no-configure` to the installer. Useful when the
    /// hook is managed at the project level (`.claude/settings.json`) and you
    /// don't want `dcg update` to re-add the hook to user-level settings or
    /// re-inject the shell startup check.
    #[arg(long, visible_alias = "binary-only", conflicts_with_all = ["check", "rollback", "list_versions"])]
    pub no_configure: bool,

    /// Replace the installed binary even when it is a pinned or local build.
    ///
    /// `dcg update` refuses to overwrite a binary that is pinned
    /// (`general.update_pin = true` / `DCG_UPDATE_PIN=1`) or that was built
    /// locally ahead of its release tag, because replacing it can silently
    /// downgrade guard coverage (#320). This flag is the explicit escape
    /// hatch: it acknowledges that the published release should replace the
    /// local build.
    #[arg(long, conflicts_with_all = ["check", "rollback", "list_versions"])]
    pub replace_local_build: bool,
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

    /// Additional packs to enable for this scan (comma-separated)
    #[arg(long, value_delimiter = ',')]
    with_packs: Option<Vec<String>>,

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

    /// Files or directories to scan, given positionally.
    ///
    /// `dcg scan a.sh b.sh` is equivalent to `dcg scan --paths a.sh b.sh`
    /// (issue #158). Mutually exclusive with `--staged`, `--git-diff`, and
    /// `--paths`.
    #[arg(value_name = "PATH", conflicts_with_all = ["staged", "git_diff", "paths"])]
    positional_paths: Vec<std::path::PathBuf>,

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

/// Shell dialect selector for `dcg explain` / `dcg test` (#269).
///
/// The CLI evaluates at [`ShellDialect::Unknown`] by default because it does
/// not know which shell would run the command, so it fans out to every dialect.
/// The live PreToolUse hook resolves a concrete dialect (Posix for `Bash`,
/// PowerShell for `PowerShell`) and evaluates that one path, so diagnostics can
/// report costs and paths the hook does not have. This opt-in flag lets a user
/// pin the same dialect the hook resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum DialectArg {
    /// Evaluate every dialect (CLI default; matches no single hook path)
    #[default]
    Unknown,
    /// POSIX shell — the dialect the `Bash` PreToolUse hook resolves
    #[value(alias = "bash", alias = "sh")]
    Posix,
    /// PowerShell — the dialect the `PowerShell` PreToolUse hook resolves
    #[value(alias = "pwsh", alias = "powershell")]
    Ps,
    /// Windows `cmd.exe`
    Cmd,
}

impl From<DialectArg> for crate::normalize::ShellDialect {
    fn from(value: DialectArg) -> Self {
        match value {
            DialectArg::Unknown => Self::Unknown,
            DialectArg::Posix => Self::Posix,
            DialectArg::Ps => Self::PowerShell,
            DialectArg::Cmd => Self::Cmd,
        }
    }
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

        /// Add to explicitly trusted project allowlist (default: user)
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

        /// Path glob pattern where this entry applies (repeatable)
        #[arg(long = "path", value_name = "GLOB")]
        paths: Vec<String>,
    },

    /// Add an exact command to the allowlist
    #[command(name = "add-command")]
    AddCommand {
        /// Exact command to allowlist
        command: String,

        /// Reason for allowlisting (required)
        #[arg(long, short = 'r')]
        reason: String,

        /// Add to explicitly trusted project allowlist (default: user)
        #[arg(long, conflicts_with = "user")]
        project: bool,

        /// Add to user allowlist
        #[arg(long, conflicts_with = "project")]
        user: bool,

        /// Expiration date (ISO 8601 / RFC 3339)
        #[arg(long)]
        expires: Option<String>,

        /// Path glob pattern where this entry applies (repeatable)
        #[arg(long = "path", value_name = "GLOB")]
        paths: Vec<String>,
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

        /// Remove from explicitly trusted project allowlist (default: user)
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

    /// Remove expired allowlist entries
    #[command(name = "prune")]
    Prune {
        /// Prune project allowlist only
        #[arg(long, conflicts_with = "user")]
        project: bool,

        /// Prune user allowlist only
        #[arg(long, conflicts_with = "project")]
        user: bool,

        /// Show what would be removed without writing changes
        #[arg(long)]
        dry_run: bool,

        /// Output format
        #[arg(long, value_enum, default_value = "pretty", env = "DCG_FORMAT")]
        format: AllowlistOutputFormat,
    },
}

/// Subcommands for the `config` command.
#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Print the JSON Schema for dcg's `config.toml`
    ///
    /// The schema powers editor autocomplete and validation (e.g. the "Even
    /// Better TOML" / taplo extensions). Point your `config.toml` at the
    /// published schema, or write a local copy with `--output`.
    #[command(name = "schema")]
    Schema {
        /// Write the schema to a file instead of stdout
        #[arg(long, short = 'o')]
        output: Option<std::path::PathBuf>,
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

        /// Hide pattern details (patterns are shown by default)
        #[arg(long)]
        no_patterns: bool,

        /// Output as JSON instead of human-readable text
        #[arg(long)]
        json: bool,
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
    // A pinned install (#320) refuses `dcg update`, so advertising the update
    // would only nag about an action dcg will then decline to perform.
    if verbosity.quiet || !config.general.check_updates || config.general.update_pin {
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
    // Source tracing performs path/status bookkeeping for diagnostics. Keep it
    // completely off the hook/test/scan hot paths; only commands that render
    // those outcomes request a report from the shared loader.
    let needs_config_trace = matches!(
        &cli.command,
        Some(Command::Doctor { .. }) | Some(Command::ShowConfig { action: None, .. })
    );
    let (config, config_sources) = if needs_config_trace {
        let loaded_config = Config::load_with_report();
        (loaded_config.config, Some(loaded_config.sources))
    } else {
        (Config::load(), None)
    };
    let verbosity = Verbosity::from_cli(&cli);
    maybe_show_update_notice(&cli, &config, verbosity);

    match cli.command {
        Some(Command::Doctor {
            fix,
            strict,
            format,
        }) => {
            let ok = doctor(
                fix,
                format,
                &config,
                config_sources
                    .as_deref()
                    .expect("doctor requested config source tracing"),
            );
            // Opt-in, matching `pack validate --strict`. Exiting non-zero by
            // default would be a behaviour change for everyone already calling
            // doctor in a pipeline.
            if strict && !ok {
                std::process::exit(EXIT_DENIED);
            }
        }
        Some(Command::Hook(cmd)) => {
            // `dcg hook` returns the process exit code (deny -> 1, parse halt
            // -> 4, otherwise 0) so batch/JSONL consumers can gate on it
            // (issues #148, #165).
            let code = run_hook_command(&config, &cmd)?;
            if code != crate::exit_codes::EXIT_SUCCESS {
                std::process::exit(code);
            }
        }
        Some(Command::Install {
            force,
            project,
            grok,
            agy,
            opencode,
            omp,
        }) => {
            if grok {
                install_grok_hook(force, project)?;
            } else if agy {
                install_antigravity_hook(force, project)?;
            } else if opencode {
                install_opencode_plugin(force, project)?;
            } else if omp {
                install_omp_extension(force, project)?;
            } else {
                install_hook(force, project)?;
            }
        }
        Some(Command::Setup {
            force,
            shell_check,
            no_shell_check,
        }) => {
            run_setup(force, shell_check, no_shell_check)?;
        }
        Some(Command::Uninstall { purge }) => {
            uninstall_hook(purge)?;
        }
        Some(Command::Update(update)) => {
            self_update(update, config.general.update_pin)?;
        }
        Some(Command::Completions { shell }) => {
            write_completions(shell)?;
        }
        Some(Command::ListPacks {
            enabled,
            expand,
            max_patterns,
            format,
        }) => {
            // Robot mode forces JSON output
            let robot_mode = robot_mode_enabled(cli.robot);
            let effective_format = if robot_mode {
                PacksFormat::Json
            } else {
                format
            };

            // Load external packs from custom_paths so they appear in the listing
            let external_paths = config.packs.expand_custom_paths();
            let _ = load_external_packs(&external_paths);

            list_packs(
                &config,
                enabled,
                verbosity.is_verbose(),
                effective_format,
                verbosity.quiet,
                expand,
                max_patterns,
            );
        }
        Some(Command::Pack { action }) => {
            handle_pack_command(&config, action)?;
        }
        Some(Command::TestCommand {
            command,
            stdin,
            config: config_path,
            with_packs,
            explain,
            format,
            no_color,
            heredoc_scan,
            no_heredoc_scan,
            heredoc_timeout_ms,
            heredoc_languages,
            enforce_budget,
            force,
            dialect,
        }) => {
            // Robot mode forces JSON output
            let robot_mode = robot_mode_enabled(cli.robot);
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

            let command = if stdin {
                read_test_command_from_stdin(effective_config.general.max_command_bytes())?
            } else {
                command.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "COMMAND is required unless --stdin is used",
                    )
                })?
            };

            if explain {
                // Delegate to explain handler for detailed trace output
                // Convert TestFormat to ExplainFormat for explain mode
                let explain_format = match effective_format {
                    TestFormat::Pretty => ExplainFormat::Pretty,
                    TestFormat::Json | TestFormat::Toon => ExplainFormat::Json,
                };
                handle_explain(
                    &effective_config,
                    &command,
                    explain_format,
                    with_packs,
                    dialect,
                );
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
                    // Robot mode is an agent-integration boundary: callers
                    // rely on the configured hook timeout so dcg answers with
                    // a bounded `indeterminate` JSON verdict before the
                    // parent's own timeout kills it. Only interactive human
                    // `dcg test` keeps budget enforcement opt-in via
                    // `--enforce-budget` (issue #309).
                    enforce_budget || robot_mode,
                    force,
                    dialect,
                );
                // Exit with code 1 if command would be blocked (for CI/robot mode scripting)
                if was_blocked {
                    std::process::exit(EXIT_DENIED);
                }
            }
        }
        Some(Command::Init {
            output,
            force,
            auto,
            dry_run,
            project_dir,
        }) => {
            if dry_run || auto {
                let scan_dir = project_dir
                    .as_deref()
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
                let detections = detect_project_packs(&scan_dir);

                if dry_run {
                    print_auto_detect_results(&detections, &scan_dir, true);
                } else {
                    print_auto_detect_results(&detections, &scan_dir, false);
                    let packs: Vec<String> = detections.iter().map(|d| d.pack_id.clone()).collect();
                    init_config_with_packs(output, force, &packs)?;
                }
            } else {
                init_config(output, force)?;
            }
        }
        Some(Command::ShowConfig { format, action }) => match action {
            Some(ConfigAction::Schema { output }) => {
                let schema = crate::config::config_json_schema_string();
                if let Some(path) = output {
                    std::fs::write(&path, &schema)?;
                    if !verbosity.quiet {
                        println!("Wrote config JSON Schema to {}", path.display());
                    }
                } else {
                    print!("{schema}");
                }
            }
            None => {
                if !verbosity.quiet {
                    match format {
                        ConfigFormat::Json => show_config_json(
                            &config,
                            config_sources
                                .as_deref()
                                .expect("config output requested source tracing"),
                        ),
                        ConfigFormat::Pretty => show_config(
                            &config,
                            config_sources
                                .as_deref()
                                .expect("config output requested source tracing"),
                        ),
                    }
                }
            }
        },
        Some(Command::Allowlist { action }) => {
            handle_allowlist_command(action, config.allowlist.auto_prune_expired)?;
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
        Some(Command::RebaseRecover { ttl }) => {
            handle_rebase_recover(ttl, robot_mode_enabled(cli.robot))?;
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
            dialect,
        }) => {
            // Robot mode forces JSON output
            let robot_mode = robot_mode_enabled(cli.robot);
            let effective_format = if robot_mode {
                ExplainFormat::Json
            } else {
                format
            };

            if !verbosity.quiet {
                handle_explain(&config, &command, effective_format, with_packs, dialect);
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
            let robot_mode = robot_mode_enabled(cli.robot);
            handle_suggest_allowlist_command(&config, &cmd, robot_mode)?;
        }
        Some(Command::Dev { action }) => {
            handle_dev_command(&config, action, verbosity)?;
        }
        Some(Command::Classify {
            command,
            format,
            no_color,
        }) => {
            let robot_mode = robot_mode_enabled(cli.robot);
            let exit_code = classify_command(&config, &command, format, no_color || robot_mode);
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
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
fn run_hook_command(config: &Config, cmd: &HookCommand) -> Result<i32, Box<dyn std::error::Error>> {
    use std::io::{self, BufRead, Write};

    // `dcg hook` reads JSONL hook payloads from stdin and writes one result
    // line per (non-empty) input line. `--batch` is accepted for explicitness
    // but is no longer required — a single JSON object on stdin is processed as
    // a one-line batch instead of erroring with an internal message (issue
    // #157). `--parallel` selects parallel evaluation.

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

    // Fail-closed: when enabled, an unparseable line is treated as a deny
    // rather than a passive error (issue #160).
    let fail_closed = config.is_fail_closed();

    let mut enabled_packs = config.enabled_pack_ids();
    // `--with-packs` enables extra packs for this run, mirroring `dcg test`
    // (issue #151). Done before keyword collection so the extra packs' keywords
    // participate in the quick-reject filter.
    if let Some(extra) = cmd.with_packs.as_ref() {
        for pack in extra {
            enabled_packs.insert(pack.clone());
        }
    }
    let mut enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);

    // Load external packs from custom_paths (glob + tilde expansion).
    let external_paths = config.packs.expand_custom_paths();
    let external_store = load_external_packs(&external_paths);

    // Auto-enable external packs and merge their keywords.
    for id in external_store.pack_ids() {
        enabled_packs.insert(id.clone());
    }
    enabled_keywords.extend(external_store.keywords().iter().copied());

    // Build ordered pack list AFTER external packs are loaded so they're included.
    let mut ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    for id in external_store.pack_ids() {
        if !ordered_packs.contains(id) {
            ordered_packs.push(id.clone());
        }
    }
    // Disable keyword index when external packs are present (not covered by index).
    let keyword_index = if external_store.pack_ids().next().is_some() {
        None
    } else {
        REGISTRY.build_enabled_keyword_index(&ordered_packs)
    };

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout_lock = stdout.lock();

    // Running tallies across all emitted results:
    // - `emit_index`: indices are assigned ONLY to emitted results, so blank
    //   input lines (which are skipped entirely) do not create phantom indexed
    //   entries (issue #154).
    // - `any_blocked`: if any command is denied or cannot be evaluated to a
    //   definitive decision, the process exits non-zero so a caller can gate
    //   on the exit code, like `dcg test` does (issues #148, #213).
    // - `parse_halt`: without `--continue-on-error`, the first malformed line
    //   emits an `error` result and then halts processing (issue #165).
    let mut emit_index = 0usize;
    let mut any_blocked = false;
    let mut parse_halt = false;

    if cmd.parallel && workers > 1 {
        // Parallel processing: collect all non-blank lines, evaluate in
        // parallel, then emit in input order. Blank lines are dropped here so
        // they neither create indexed entries nor consume an index (#154).
        let lines: Vec<(usize, String)> = stdin
            .lock()
            .lines()
            .map_while(std::result::Result::ok)
            .filter(|l| !l.trim().is_empty())
            .enumerate()
            .collect();

        #[cfg(feature = "rayon")]
        let mut results: Vec<(usize, BatchHookOutput)> = {
            use rayon::prelude::*;

            lines
                .into_par_iter()
                .map(|(order, line)| {
                    (
                        order,
                        evaluate_batch_line(
                            config,
                            &line,
                            &enabled_keywords,
                            &ordered_packs,
                            keyword_index.as_ref(),
                            &compiled_overrides,
                            &allowlists,
                            &heredoc_settings,
                        ),
                    )
                })
                .collect()
        };

        #[cfg(not(feature = "rayon"))]
        let mut results: Vec<(usize, BatchHookOutput)> = lines
            .into_iter()
            .map(|(order, line)| {
                (
                    order,
                    evaluate_batch_line(
                        config,
                        &line,
                        &enabled_keywords,
                        &ordered_packs,
                        keyword_index.as_ref(),
                        &compiled_overrides,
                        &allowlists,
                        &heredoc_settings,
                    ),
                )
            })
            .collect();

        results.sort_by_key(|(order, _)| *order);

        for (_, mut result) in results {
            // Fail-closed: an unparseable line is a DENY, not a passive error
            // (issue #160).
            if fail_closed && result.decision == "error" {
                result.decision = "deny";
            }
            result.index = emit_index;
            emit_index += 1;
            if matches!(result.decision, "deny" | "indeterminate") {
                any_blocked = true;
            }
            let halt = result.decision == "error" && !cmd.continue_on_error;
            writeln!(stdout_lock, "{}", serde_json::to_string(&result)?)?;
            if halt {
                parse_halt = true;
                break;
            }
        }
    } else {
        // Sequential processing: stream input to output.
        for line in stdin.lock().lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    if cmd.continue_on_error {
                        let result = BatchHookOutput {
                            index: emit_index,
                            decision: "error",
                            mode: None,
                            rule_id: None,
                            pack_id: None,
                            error: Some(format!("IO error: {e}")),
                        };
                        emit_index += 1;
                        writeln!(stdout_lock, "{}", serde_json::to_string(&result)?)?;
                        continue;
                    }
                    return Err(e.into());
                }
            };

            // Blank lines are skipped entirely: no output, no index (#154).
            if line.trim().is_empty() {
                continue;
            }

            let mut result = evaluate_batch_line(
                config,
                &line,
                &enabled_keywords,
                &ordered_packs,
                keyword_index.as_ref(),
                &compiled_overrides,
                &allowlists,
                &heredoc_settings,
            );
            // Fail-closed: an unparseable line is a DENY, not a passive error
            // (issue #160).
            if fail_closed && result.decision == "error" {
                result.decision = "deny";
            }
            result.index = emit_index;
            emit_index += 1;
            if matches!(result.decision, "deny" | "indeterminate") {
                any_blocked = true;
            }
            let halt = result.decision == "error" && !cmd.continue_on_error;
            writeln!(stdout_lock, "{}", serde_json::to_string(&result)?)?;
            if halt {
                parse_halt = true;
                break;
            }
        }
    }

    // Exit code contract for `dcg hook` (issues #148, #165):
    // - any deny/indeterminate -> EXIT_DENIED (1): callers can gate on the
    //   exit code, and incomplete safety analysis never becomes success.
    // - parse halt -> EXIT_PARSE_ERROR (4): a malformed line stopped processing.
    // - otherwise  -> EXIT_SUCCESS (0).
    let exit_code = if any_blocked {
        crate::exit_codes::EXIT_DENIED
    } else if parse_halt {
        crate::exit_codes::EXIT_PARSE_ERROR
    } else {
        crate::exit_codes::EXIT_SUCCESS
    };
    Ok(exit_code)
}

/// Evaluate a single batch line and return the result.
///
/// The returned `index` is a placeholder (`0`); the caller assigns the real
/// emit index so that skipped blank lines do not consume an index (issue #154).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn evaluate_batch_line(
    config: &Config,
    line: &str,
    enabled_keywords: &[&str],
    ordered_packs: &[String],
    keyword_index: Option<&crate::packs::EnabledKeywordIndex>,
    compiled_overrides: &crate::config::CompiledOverrides,
    allowlists: &crate::allowlist::LayeredAllowlist,
    heredoc_settings: &crate::config::HeredocSettings,
) -> BatchHookOutput {
    // Strip a leading UTF-8 BOM (U+FEFF). It can only appear on the first
    // physical line of stdin, but stripping per-line is harmless and ensures a
    // BOM-prefixed but otherwise-valid hook line is parsed and evaluated rather
    // than fail-open-allowed (issue #160). serde_json does not skip a BOM.
    let line = line.strip_prefix('\u{feff}').unwrap_or(line);

    // Skip empty lines
    if line.trim().is_empty() {
        return BatchHookOutput {
            index: 0,
            decision: "skip",
            mode: None,
            rule_id: None,
            pack_id: None,
            error: Some("Empty line".to_string()),
        };
    }

    // Parse JSON input. A malformed line yields an `error` result; whether
    // processing continues or halts after it is decided by the caller based on
    // `--continue-on-error` (see `run_hook_command`, issue #165).
    let hook_input: crate::hook::HookInput = match serde_json::from_str(line) {
        Ok(input) => input,
        Err(e) => {
            return BatchHookOutput {
                index: 0,
                decision: "error",
                mode: None,
                rule_id: None,
                pack_id: None,
                error: Some(format!("JSON parse error: {e}")),
            };
        }
    };

    let Some(extracted_command) = crate::hook::extract_command_with_context(&hook_input) else {
        return BatchHookOutput {
            index: 0,
            decision: "skip",
            mode: None,
            rule_id: None,
            pack_id: None,
            error: Some("Not a supported shell tool invocation or missing command".to_string()),
        };
    };
    // Batched envelopes (VS Code Agent Host `toolCalls`) carry additional
    // shell commands that must each be evaluated independently (issue #252).
    // Every entry is resolved — evaluation AND policy mode — before one is
    // chosen to speak for the line, by rank: deny > indeterminate > ask >
    // warn > log > allow. Stopping at the first evaluator-level non-allow was
    // a fail-open once `[policy]` could turn that entry into a warn/log
    // `allow` (#330): the entries after it were never evaluated.
    let project_path = std::env::current_dir().ok();
    let mut decisive: Option<BatchEntryOutcome> = None;
    for (command, dialect) in
        std::iter::once((extracted_command.command, extracted_command.dialect))
            .chain(extracted_command.additional_commands)
    {
        let result = evaluate_command_with_pack_order_deadline_at_path_in_dialect(
            &command,
            enabled_keywords,
            ordered_packs,
            keyword_index,
            compiled_overrides,
            allowlists,
            heredoc_settings,
            None,
            project_path.as_deref(), // scope path-aware allowlist entries (#186)
            None,                    // No deadline for batch mode
            dialect,
        );
        let outcome = resolve_batch_entry(config, &command, result);
        if decisive
            .as_ref()
            .is_none_or(|current| outcome.rank() > current.rank())
        {
            decisive = Some(outcome);
        }
        if decisive
            .as_ref()
            .is_some_and(|current| current.rank() == BatchEntryOutcome::MAX_RANK)
        {
            break;
        }
    }
    let decisive = decisive.expect("the primary command is always evaluated");
    BatchHookOutput {
        index: 0,
        decision: decisive.decision,
        mode: decisive.mode,
        rule_id: decisive.rule_id,
        pack_id: decisive.pack_id,
        error: decisive.error,
    }
}

/// One resolved entry of a `dcg hook` line: the evaluator's verdict with the
/// active `[policy]` applied, plus the precedence used to pick the entry that
/// speaks for a batched line.
struct BatchEntryOutcome {
    decision: &'static str,
    mode: Option<&'static str>,
    rule_id: Option<String>,
    pack_id: Option<String>,
    error: Option<String>,
    rank: u8,
}

impl BatchEntryOutcome {
    /// Rank of a hard deny — nothing outranks it, so scanning can stop.
    const MAX_RANK: u8 = 5;

    const fn rank(&self) -> u8 {
        self.rank
    }
}

/// Apply the active `[policy]` to one evaluated batch entry.
///
/// The evaluator reports the rule's default decision; the active `[policy]`
/// (and confidence scoring) decide what that match means. Bare `dcg` and
/// `dcg test` already resolve this; `dcg hook` skipped it and enforced `deny`
/// for rules the user had downgraded to warn/log, disagreeing with `dcg test`
/// on the same config (#330). Explicit `[overrides].block` and legacy
/// fail-closed findings stay deny inside the resolver.
fn resolve_batch_entry(
    config: &Config,
    command: &str,
    eval_result: crate::evaluator::EvaluationResult,
) -> BatchEntryOutcome {
    match eval_result.decision {
        EvaluationDecision::Allow => BatchEntryOutcome {
            decision: "allow",
            mode: None,
            rule_id: None,
            pack_id: None,
            error: None,
            rank: 0,
        },
        EvaluationDecision::Indeterminate => BatchEntryOutcome {
            decision: "indeterminate",
            mode: None,
            rule_id: None,
            pack_id: None,
            error: Some(INDETERMINATE_REASON.to_string()),
            rank: 4,
        },
        EvaluationDecision::Deny => {
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

            let mode = crate::evaluator::resolve_effective_mode(config, command, &eval_result)
                .unwrap_or(DecisionMode::Deny);
            let (decision, mode_label, rank) = match mode {
                DecisionMode::Deny => ("deny", "deny", BatchEntryOutcome::MAX_RANK),
                // No review channel on this protocol: block, like every
                // non-review-capable hook and `dcg test`.
                DecisionMode::Ask => ("deny", "ask", 3),
                DecisionMode::Warn => ("allow", "warn", 2),
                DecisionMode::Log => ("allow", "log", 1),
            };
            if mode == DecisionMode::Warn {
                let reason = eval_result
                    .pattern_info
                    .as_ref()
                    .map_or("", |info| info.reason.as_str());
                eprintln!(
                    "[dcg] Warning: {} matched but policy mode is warn; allowing. {reason}",
                    rule_id.as_deref().unwrap_or("a destructive pattern")
                );
            }

            BatchEntryOutcome {
                decision,
                mode: Some(mode_label),
                rule_id,
                pack_id,
                error: None,
                rank,
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
    expand: bool,
    max_patterns: usize,
) {
    if quiet {
        return;
    }

    let enabled_packs = config.enabled_pack_ids();
    let infos = REGISTRY.list_packs(&enabled_packs);

    // Build pack list (filtered if enabled_only)
    let mut pack_list: Vec<PackInfo> = infos
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

    // Include external packs from custom_paths
    // External packs are auto-enabled when loaded (same behavior as test_command_inner)
    if let Some(external_store) = get_external_packs() {
        for (id, pack) in external_store.iter_packs() {
            // External packs loaded via custom_paths are always enabled by convention
            // (if you add a pack to custom_paths, you want it active)
            let is_enabled = true;
            if enabled_only && !is_enabled {
                continue;
            }
            let category = id.split('.').next().unwrap_or(id).to_string();
            pack_list.push(PackInfo {
                id: id.clone(),
                name: pack.name.to_string(),
                category,
                description: pack.description.to_string(),
                enabled: is_enabled,
                safe_pattern_count: pack.safe_patterns.len(),
                destructive_pattern_count: pack.destructive_patterns.len(),
            });
        }
    }

    // Handle JSON output
    let total_count = infos.len() + get_external_packs().map_or(0, ExternalPackStore::len);
    if format == PacksFormat::Json {
        let enabled_count = pack_list.iter().filter(|p| p.enabled).count();
        let output = PacksOutput {
            packs: pack_list,
            enabled_count,
            total_count,
        };
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return;
    }

    // Rich output when feature enabled and the process is attached to a
    // terminal that can render it. Non-TTY output keeps the plain stdout
    // contract used by scripts and tests.
    #[cfg(feature = "rich-output")]
    {
        if crate::output::should_use_rich_output() {
            list_packs_rich(&pack_list, verbose, expand, max_patterns);
            return;
        }
    }

    // Pretty output (default, non-rich fallback)
    println!("Available packs:");
    println!();

    // Group by category (use pack_list which includes both built-in and external packs)
    let mut by_category: std::collections::BTreeMap<&str, Vec<&PackInfo>> =
        std::collections::BTreeMap::new();
    for info in &pack_list {
        let category = info.category.as_str();
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
                let description = markdown_single_line_for_cli(&info.description);
                println!(
                    "    {} {} - {} ({} safe, {} destructive)",
                    status,
                    info.id,
                    description,
                    info.safe_pattern_count,
                    info.destructive_pattern_count
                );
                print_pack_patterns_plain(info, expand, max_patterns);
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

fn print_pack_patterns_plain(info: &PackInfo, expand: bool, max_patterns: usize) {
    let Some(pack) = REGISTRY.get(&info.id) else {
        return;
    };
    let use_color = crate::output::auto_theme().colors_enabled;

    let safe_patterns = pack
        .safe_patterns
        .iter()
        .map(|pattern| {
            let regex = crate::highlight::format_regex_pattern(pattern.regex.as_str(), use_color);
            format!("{}: {}", pattern.name, regex)
        })
        .collect();
    print_pack_pattern_lines("Safe patterns", safe_patterns, expand, max_patterns);

    let destructive_patterns = pack
        .destructive_patterns
        .iter()
        .map(|pattern| {
            let name = pattern.name.unwrap_or("unnamed");
            let severity_label = pattern.severity.label();
            let regex = crate::highlight::format_regex_pattern(pattern.regex.as_str(), use_color);
            format!("{name} [{severity_label}]: {regex}")
        })
        .collect();
    print_pack_pattern_lines(
        "Destructive patterns",
        destructive_patterns,
        expand,
        max_patterns,
    );
}

fn print_pack_pattern_lines(title: &str, lines: Vec<String>, expand: bool, max_patterns: usize) {
    if lines.is_empty() {
        return;
    }

    println!("      {title}:");
    let total = lines.len();
    let max_patterns = max_patterns.max(1);

    if expand || total <= max_patterns {
        for line in lines {
            println!("        - {line}");
        }
        return;
    }

    let head_count = max_patterns.div_ceil(2);
    let tail_count = max_patterns.saturating_sub(head_count);
    let hidden_count = total.saturating_sub(head_count + tail_count);

    for line in lines.iter().take(head_count) {
        println!("        - {line}");
    }
    println!("        - ... {hidden_count} more patterns (--expand to show all)");
    if tail_count > 0 {
        for line in lines.iter().skip(total - tail_count) {
            println!("        - {line}");
        }
    }
}

/// Rich terminal packs output using DcgConsole and markup.
#[cfg(feature = "rich-output")]
fn list_packs_rich(pack_list: &[PackInfo], verbose: bool, expand: bool, max_patterns: usize) {
    let tree_items: Vec<_> = pack_list
        .iter()
        .map(|info| {
            let item = crate::output::PackTreeItem::new(
                &info.id,
                &info.name,
                &info.category,
                &info.description,
                info.enabled,
                info.safe_pattern_count,
                info.destructive_pattern_count,
            );

            if !verbose {
                return item;
            }

            let Some(pack) = REGISTRY.get(&info.id) else {
                return item;
            };

            let safe_patterns = pack
                .safe_patterns
                .iter()
                .map(|pattern| {
                    crate::output::PackTreePattern::safe(pattern.name, pattern.regex.as_str())
                })
                .collect();
            let destructive_patterns = pack
                .destructive_patterns
                .iter()
                .map(|pattern| {
                    crate::output::PackTreePattern::destructive(
                        pattern.name.unwrap_or("unnamed"),
                        pattern.regex.as_str(),
                        pattern.severity.label(),
                    )
                })
                .collect();

            item.with_patterns(safe_patterns, destructive_patterns)
        })
        .collect();

    let options = crate::output::PackTreeOptions::new(verbose)
        .expand(expand)
        .max_patterns(max_patterns);

    crate::output::pack_list_tree_with_options(&tree_items, options)
        .with_theme(&crate::output::auto_theme())
        .render();

    // Render the legend/config hint as a separate footer beneath the tree so it
    // does not appear as a fake pack category inside the hierarchy (#187).
    println!();
    for line in crate::output::pack_legend_lines() {
        println!("{line}");
    }
}

fn markdown_single_line_for_cli(text: &str) -> String {
    crate::highlight::format_markdown_explanation(
        text,
        false,
        usize::from(crate::output::terminal_width()).max(40),
    )
    .split_whitespace()
    .collect::<Vec<_>>()
    .join(" ")
}

fn print_markdown_field(label: &str, text: &str, indent: &str, use_color: bool) {
    let prefix_width = indent.chars().count() + label.chars().count() + 2;
    let width = usize::from(crate::output::terminal_width())
        .saturating_sub(prefix_width)
        .max(20);
    let rendered = crate::highlight::format_markdown_explanation(text, use_color, width);
    let mut lines = rendered.lines();

    if let Some(first) = lines.next() {
        println!("{indent}{label}: {first}");
        for line in lines {
            println!("{indent}  {line}");
        }
    } else {
        println!("{indent}{label}:");
    }
}

/// Show detailed information about a pack
fn pack_info(
    pack_id: &str,
    show_patterns: bool,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let pack = REGISTRY
        .get(pack_id)
        .ok_or_else(|| format!("Pack not found: {pack_id}"))?;

    if json_output {
        #[derive(serde::Serialize)]
        struct PackInfoJson {
            id: String,
            name: String,
            description: String,
            keywords: Vec<String>,
            safe_pattern_count: usize,
            destructive_pattern_count: usize,
            #[serde(skip_serializing_if = "Option::is_none")]
            safe_patterns: Option<Vec<SafePatternJson>>,
            #[serde(skip_serializing_if = "Option::is_none")]
            destructive_patterns: Option<Vec<DestructivePatternJson>>,
        }
        #[derive(serde::Serialize)]
        struct SafePatternJson {
            name: String,
            regex: String,
        }
        #[derive(serde::Serialize)]
        struct DestructivePatternJson {
            name: String,
            regex: String,
            severity: String,
            reason: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            explanation: Option<String>,
            #[serde(skip_serializing_if = "Vec::is_empty")]
            suggestions: Vec<SuggestionJson>,
        }
        #[derive(serde::Serialize)]
        struct SuggestionJson {
            command: String,
            description: String,
            /// dcg also gates this suggestion; it needs explicit approval (#316).
            gated: bool,
        }

        let safe_patterns = if show_patterns {
            Some(
                pack.safe_patterns
                    .iter()
                    .map(|p| SafePatternJson {
                        name: p.name.to_string(),
                        regex: p.regex.as_str().to_string(),
                    })
                    .collect(),
            )
        } else {
            None
        };

        let destructive_patterns = if show_patterns {
            Some(
                pack.destructive_patterns
                    .iter()
                    .map(|p| DestructivePatternJson {
                        name: p.name.unwrap_or("unnamed").to_string(),
                        regex: p.regex.as_str().to_string(),
                        severity: p.severity.label().to_string(),
                        reason: p.reason.to_string(),
                        explanation: p.explanation.map(String::from),
                        suggestions: p
                            .suggestions
                            .iter()
                            .map(|s| SuggestionJson {
                                command: s.command.to_string(),
                                description: s.description.to_string(),
                                gated: s.gated,
                            })
                            .collect(),
                    })
                    .collect(),
            )
        } else {
            None
        };

        let info = PackInfoJson {
            id: pack.id.clone(),
            name: pack.name.to_string(),
            description: pack.description.to_string(),
            keywords: pack.keywords.iter().map(|k| (*k).to_string()).collect(),
            safe_pattern_count: pack.safe_patterns.len(),
            destructive_pattern_count: pack.destructive_patterns.len(),
            safe_patterns,
            destructive_patterns,
        };

        println!("{}", serde_json::to_string_pretty(&info)?);
        return Ok(());
    }

    println!("Pack: {}", pack.name);
    println!("ID: {}", pack.id);
    let use_color = crate::output::auto_theme().colors_enabled;
    print_markdown_field("Description", pack.description, "", use_color);
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
            let regex = crate::highlight::format_regex_pattern(pattern.regex.as_str(), use_color);
            println!("  - {} : {}", pattern.name, regex);
        }

        println!();
        println!("Destructive patterns:");
        for pattern in &pack.destructive_patterns {
            let name = pattern.name.unwrap_or("unnamed");
            let severity_label = pattern.severity.label().to_uppercase();
            let regex = crate::highlight::format_regex_pattern(pattern.regex.as_str(), use_color);
            println!("  - {name} [{severity_label}] : {regex}");
            println!("    Reason: {}", pattern.reason);
            if let Some(explanation) = pattern.explanation {
                print_markdown_field("Explanation", explanation, "    ", use_color);
            }
            for suggestion in pattern.suggestions {
                let gated_marker = if suggestion.gated {
                    " [gated: dcg also requires approval for this]"
                } else {
                    ""
                };
                println!(
                    "    Suggestion: {} - {}{gated_marker}",
                    suggestion.command, suggestion.description
                );
            }
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
        PackAction::Info {
            pack_id,
            no_patterns,
            json,
        } => {
            pack_info(&pack_id, !no_patterns, json)?;
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
    let non_interactive_env =
        std::env::var("DCG_NON_INTERACTIVE").is_ok() || std::env::var("CI").is_ok();
    let interactive_available = check_interactive_available(interactive_config).is_ok();
    let stdin_is_tty = std::io::stdin().is_terminal();
    let stdout_is_tty = std::io::stdout().is_terminal();

    should_prompt_interactively_with_context(
        format,
        verbosity,
        mode,
        severity,
        non_interactive_env,
        interactive_available,
        stdin_is_tty,
        stdout_is_tty,
    )
}

fn should_prompt_interactively_with_context(
    format: TestFormat,
    verbosity: Verbosity,
    mode: DecisionMode,
    severity: Option<PackSeverity>,
    non_interactive_env: bool,
    interactive_available: bool,
    stdin_is_tty: bool,
    stdout_is_tty: bool,
) -> bool {
    if format.is_structured() || verbosity.quiet {
        return false;
    }

    if mode != DecisionMode::Deny {
        return false;
    }

    if !matches!(severity, Some(PackSeverity::Medium | PackSeverity::Low)) {
        return false;
    }

    if non_interactive_env {
        return false;
    }

    if !interactive_available {
        return false;
    }

    stdin_is_tty && stdout_is_tty
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InteractiveAllowlistTarget {
    ExactCommand,
    MatchedRule,
}

#[derive(Debug, Clone)]
struct InteractiveAllowlistApplication {
    summary: String,
    pattern_added: String,
    option_type: InteractiveAllowlistOptionType,
    option_detail: Option<String>,
    config_file: std::path::PathBuf,
}

fn prompt_allowlist_target(rule_id: Option<&str>) -> InteractiveAllowlistTarget {
    let Some(rule_id) = rule_id else {
        return InteractiveAllowlistTarget::ExactCommand;
    };

    let exact = "Exact command only (recommended)".to_string();
    let rule = format!("Matched rule `{rule_id}` (broader)");
    let options = vec![exact.clone(), rule.clone()];

    match Select::new("Allowlist target:", options)
        .with_help_message(
            "Exact command is safer; rule-based allows all future matches of this rule",
        )
        .prompt()
    {
        Ok(choice) if choice == rule => InteractiveAllowlistTarget::MatchedRule,
        _ => InteractiveAllowlistTarget::ExactCommand,
    }
}

fn prompt_allowlist_path_scope() -> Vec<String> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let scope_path = cwd.canonicalize().unwrap_or(cwd);
    let scope_path_str = scope_path.to_string_lossy().into_owned();

    let scoped = format!("Current directory only ({scope_path_str})");
    let global = "All directories (global)".to_string();
    let options = vec![scoped.clone(), global];

    match Select::new("Path scope:", options)
        .with_help_message("Directory-scoped entries are safer")
        .prompt()
    {
        Ok(choice) if choice == scoped => vec![scope_path_str],
        _ => Vec::new(),
    }
}

fn prompt_allowlist_lifetime_choice() -> Option<std::time::Duration> {
    let permanent = "Permanent allowlist entry".to_string();
    let temporary = "Temporary allowlist entry (24 hours)".to_string();
    let options = vec![permanent.clone(), temporary.clone()];

    match Select::new("Lifetime:", options)
        .with_help_message("Temporary entries auto-expire and are safer")
        .prompt()
    {
        Ok(choice) if choice == temporary => Some(std::time::Duration::from_secs(24 * 3600)),
        _ => None,
    }
}

fn duration_to_expires_at(
    duration: std::time::Duration,
) -> Result<String, Box<dyn std::error::Error>> {
    let duration = chrono::Duration::from_std(duration)
        .map_err(|e| format!("Failed to convert duration: {e}"))?;
    let expires_at = Utc::now()
        .checked_add_signed(duration)
        .ok_or("Duration overflow while computing expiration timestamp")?;
    Ok(expires_at.to_rfc3339())
}

fn interactive_option_type(
    expires: Option<&str>,
    paths: &[String],
) -> InteractiveAllowlistOptionType {
    if expires.is_some() {
        InteractiveAllowlistOptionType::Temporary
    } else if paths.is_empty() {
        InteractiveAllowlistOptionType::Exact
    } else {
        InteractiveAllowlistOptionType::PathSpecific
    }
}

fn current_username() -> Option<String> {
    ["USER", "LOGNAME", "USERNAME"]
        .iter()
        .find_map(|key| std::env::var(key).ok())
        .and_then(|value| (!value.trim().is_empty()).then_some(value))
}

fn apply_interactive_allowlist_entry(
    command: &str,
    rule_id: Option<&str>,
    reason: &str,
    layer: crate::allowlist::AllowlistLayer,
    expires: Option<&str>,
) -> Result<InteractiveAllowlistApplication, Box<dyn std::error::Error>> {
    let target = prompt_allowlist_target(rule_id);
    let paths = prompt_allowlist_path_scope();
    let option_type = interactive_option_type(expires, &paths);
    let option_detail = Some(format!(
        "target={};scope={};layer={};expires={};paths={}",
        match target {
            InteractiveAllowlistTarget::ExactCommand => "exact_command",
            InteractiveAllowlistTarget::MatchedRule => "matched_rule",
        },
        if paths.is_empty() {
            "all_directories"
        } else {
            "current_directory_only"
        },
        layer.label(),
        expires.unwrap_or("none"),
        if paths.is_empty() {
            "*".to_string()
        } else {
            paths.join("|")
        }
    ));
    let config_file = allowlist_path_for_layer(layer);

    let scope_label = if paths.is_empty() {
        "all directories"
    } else {
        "current directory only"
    };

    match (target, rule_id) {
        (InteractiveAllowlistTarget::MatchedRule, Some(rule_id)) => {
            allowlist_add_rule_with_paths(rule_id, reason, layer, expires, &[], &paths)?;
            Ok(InteractiveAllowlistApplication {
                summary: format!("rule target, {scope_label}"),
                pattern_added: rule_id.to_string(),
                option_type,
                option_detail,
                config_file,
            })
        }
        _ => {
            allowlist_add_command_with_paths(command, reason, layer, expires, &paths)?;
            Ok(InteractiveAllowlistApplication {
                summary: format!("exact command target, {scope_label}"),
                pattern_added: command.to_string(),
                option_type,
                option_detail,
                config_file,
            })
        }
    }
}

fn log_interactive_allowlist_audit_event(
    config: &Config,
    command: &str,
    applied: &InteractiveAllowlistApplication,
) -> Result<(), Box<dyn std::error::Error>> {
    if !config.history.enabled {
        return Ok(());
    }

    let db_path = config.history.expanded_database_path();
    let db = HistoryDb::open_with_max_size(db_path, config.history.max_size_mb)?;

    let cwd = std::env::current_dir()
        .ok()
        .and_then(|path| path.canonicalize().ok().or(Some(path)))
        .map(|path| path.to_string_lossy().into_owned());

    let entry = InteractiveAllowlistAuditEntry {
        timestamp: Utc::now(),
        command: command.to_string(),
        pattern_added: applied.pattern_added.clone(),
        option_type: applied.option_type,
        option_detail: applied.option_detail.clone(),
        config_file: applied.config_file.to_string_lossy().into_owned(),
        cwd,
        user: current_username(),
    };

    let _ = db.log_interactive_allowlist_audit(&entry)?;
    Ok(())
}

fn resolve_mode_for_cli(
    config: &Config,
    command: &str,
    result: &EvaluationResult,
) -> Option<DecisionMode> {
    crate::evaluator::resolve_effective_mode(config, command, result)
}

fn read_test_command_from_stdin(max_command_bytes: usize) -> std::io::Result<String> {
    use std::io::Read as _;

    let mut bytes = Vec::new();
    let limit = u64::try_from(max_command_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    std::io::stdin()
        .lock()
        .take(limit)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_command_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("stdin command exceeds general.max_command_bytes ({max_command_bytes} bytes)"),
        ));
    }

    let mut command = String::from_utf8(bytes).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("stdin command is not valid UTF-8: {error}"),
        )
    })?;
    if command.ends_with('\n') {
        command.pop();
        if command.ends_with('\r') {
            command.pop();
        }
    }
    if command.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "stdin did not contain a command",
        ));
    }

    Ok(command)
}

/// Re-evaluate a blocked command under the posix dialect to detect a
/// diagnostics-only denial (#289 C1).
///
/// `dcg test` / `dcg explain` default to [`ShellDialect::Unknown`], which is a
/// fail-closed union over every dialect. The live Bash hook resolves a single
/// dialect — posix — from the tool name, so a denial that only the union
/// produces is a decision no Bash hook would ever make. Users filed false
/// positives against that gap (#273) and could not reproduce real hook blocks.
///
/// Returns `Some` only when there is something to report — the defaulted
/// dialect denied and posix alone allows. `None` covers "check did not apply"
/// (allowed command, caller-chosen dialect) and "checked, no divergence"
/// alike, which keeps the JSON payload free of a field that says nothing.
/// Cost: exactly one extra evaluation, and only on the deny path of a
/// defaulted dialect.
#[allow(clippy::too_many_arguments)]
fn cli_dialect_divergence(
    dialect: DialectArg,
    decision: EvaluationDecision,
    command: &str,
    enabled_keywords: &[&str],
    ordered_packs: &[String],
    keyword_index: Option<&crate::packs::EnabledKeywordIndex>,
    compiled_overrides: &crate::config::CompiledOverrides,
    allowlists: &crate::allowlist::LayeredAllowlist,
    heredoc_settings: &crate::config::HeredocSettings,
    project_path: Option<&std::path::Path>,
) -> Option<DialectDivergence> {
    // `--dialect unknown` is the same analysis as the default, so the note is
    // equally true there; any other explicit dialect is the user's own choice
    // and must be reported as-is.
    if dialect != DialectArg::Unknown {
        return None;
    }
    // Only a blocking decision can diverge in the direction that matters (a
    // denial the hook would not produce). Indeterminate results are budget
    // artifacts, not dialect disagreements.
    if decision != EvaluationDecision::Deny {
        return None;
    }

    let posix = evaluate_command_with_pack_order_deadline_at_path_in_dialect(
        command,
        enabled_keywords,
        ordered_packs,
        keyword_index,
        compiled_overrides,
        allowlists,
        heredoc_settings,
        None, // allow_once_audit
        project_path,
        None, // deadline
        crate::normalize::ShellDialect::Posix,
    );

    (posix.decision == EvaluationDecision::Allow).then_some(DialectDivergence {
        posix_would_allow: true,
    })
}

/// Build the human-readable dialect-divergence note (#289 C1).
///
/// Returns `None` unless the all-dialect analysis denied a command that posix
/// alone would allow.
fn dialect_divergence_note(divergence: Option<DialectDivergence>, command: &str) -> Option<String> {
    if !divergence.is_some_and(|d| d.posix_would_allow) {
        return None;
    }
    Some(format!(
        "Note: this denial comes from the all-dialect analysis (the CLI default, --dialect unknown).\n\
         \x20     The Bash hook (posix dialect) would ALLOW this command.\n\
         \x20     Reproduce the hook's decision with: dcg test --dialect posix {}",
        single_quote_for_shell(command)
    ))
}

/// Print the dialect-divergence note when one applies (#289 C1).
fn print_dialect_divergence_note(divergence: Option<DialectDivergence>, command: &str) {
    if let Some(note) = dialect_divergence_note(divergence, command) {
        println!();
        println!("{note}");
    }
}

/// Wrap `command` in single quotes for a copy-pasteable POSIX shell example.
fn single_quote_for_shell(command: &str) -> String {
    format!("'{}'", command.replace('\'', r"'\''"))
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
    enforce_budget: bool,
    force: bool,
    dialect: DialectArg,
) -> bool {
    use std::time::{Duration, Instant};

    // NOTE: quiet mode is handled AFTER evaluation (see below) so the returned
    // decision — and therefore the process exit code — still reflects whether
    // the command is blocked. Returning early here would make
    // `DCG_QUIET=1 dcg test <blocked>` exit 0 and silently bypass the block
    // (issue #149).

    if verbosity.is_trace() && format == TestFormat::Pretty {
        handle_explain(config, command, ExplainFormat::Pretty, extra_packs, dialect);
        return false; // Explain mode doesn't track blocked status
    }

    // Keep the explicit CLI contribution separate as well as reflecting it in
    // the effective config. Agent profiles apply to configured and external
    // packs, while an invocation-local `--with-packs` remains the final
    // authority for the packs the caller explicitly requested.
    let cli_extra_packs = extra_packs.as_deref().unwrap_or(&[]);
    let mut effective_config = extra_packs.as_ref().map_or_else(
        || config.clone(),
        |packs| {
            let mut modified = config.clone();
            modified.packs.enabled.extend(packs.iter().cloned());
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

    let heredoc_settings = effective_config.heredoc_settings();

    // Compile overrides once (not per-command)
    let compiled_overrides = effective_config.overrides.compile();

    // Load external packs from custom_paths (glob + tilde expansion).
    let external_paths = effective_config.packs.expand_custom_paths();
    let external_store = load_external_packs(&external_paths);

    // Detect the current AI coding agent for agent-specific profiles.
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

    // Hook mode starts its deadline right after the stdin read, so its budget
    // covers self-heal, external-pack loading, and evaluation (issue #293).
    // The CLI deliberately diverges: it starts the deadline HERE, after
    // config-derived setup, agent detection, and external-pack loading, so
    // only pack expansion, allowlist loading, and evaluation consume the
    // budget. `--enforce-budget` exists to reproduce hook-mode *evaluation*
    // latency from the command line, and the CLI's own startup is not part of
    // any agent's hook window — charging it here would make the flag report a
    // budget the hook never spends. Timing the loading stages is what
    // `dcg doctor`/`--timing` are for.
    let evaluation_deadline = enforce_budget.then(|| {
        Deadline::new(Duration::from_millis(
            effective_config.effective_hook_timeout_ms(),
        ))
    });

    // Resolve the same agent-specific pack and allowlist policy as hook mode.
    let mut enabled_packs = effective_config.enabled_pack_ids_for_agent(&detection.agent);
    let allowlists =
        effective_config.apply_agent_allowlist_profile(&detection.agent, load_default_allowlists());

    // Auto-enable external packs, then apply agent exclusions to those later
    // contributions as hook mode does. Explicit `--with-packs` is re-applied
    // last so the invocation-local override retains its established priority.
    for id in external_store.pack_ids() {
        enabled_packs.insert(id.clone());
    }
    effective_config.remove_disabled_packs_for_agent(&mut enabled_packs, &detection.agent);
    enabled_packs.extend(cli_extra_packs.iter().cloned());

    // Collect keywords only after the final pack policy is known.
    let mut enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    enabled_keywords.extend(external_store.keywords().iter().copied());

    // Build ordered pack list AFTER external packs are loaded so they're included.
    let mut ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    for id in external_store.pack_ids() {
        if !ordered_packs.contains(id) {
            ordered_packs.push(id.clone());
        }
    }
    // Disable keyword index when external packs are present (not covered by index).
    let keyword_index = if external_store.pack_ids().next().is_some() {
        None
    } else {
        REGISTRY.build_enabled_keyword_index(&ordered_packs)
    };

    // Use shared evaluator for consistent behavior with hook mode
    let project_path = std::env::current_dir().ok();
    let start = Instant::now();
    let mut result = evaluate_command_with_pack_order_deadline_at_path_in_dialect(
        command,
        &enabled_keywords,
        &ordered_packs,
        keyword_index.as_ref(),
        &compiled_overrides,
        &allowlists,
        &heredoc_settings,
        None,                    // allow_once_audit
        project_path.as_deref(), // project_path scopes path-aware allowlist entries (#186)
        evaluation_deadline.as_ref(),
        dialect.into(),
    );

    // NOTE: External packs from custom_paths are now checked in evaluate_command()
    // alongside built-in packs, so no separate fallback check is needed here.

    // Apply graduated response system
    result.record_and_graduate(command, &effective_config.response);

    // If --force and we have a SoftBlock, bypass it
    if force {
        if let Some(crate::evaluator::GraduatedResponse::SoftBlock { .. }) =
            &result.graduated_response
        {
            result.decision = EvaluationDecision::Allow;
            result.bypass_method = Some(crate::evaluator::BypassMethod::Force);
        }
    }

    let elapsed = start.elapsed();
    let resolved_mode = resolve_mode_for_cli(&effective_config, command, &result);

    // Quiet mode: the command was fully evaluated above, so suppress all
    // human/structured output but still return the real decision so the exit
    // code is correct (blocked/indeterminate -> exit 1, allowed -> exit 0).
    // See issues #149 and #213.
    if verbosity.quiet {
        return policy_blocks_cli_execution(result.decision, resolved_mode);
    }

    // #289 C1: a denial under the defaulted all-dialect analysis may be one the
    // Bash hook (posix only) would never produce. Computed after the quiet
    // early-return so the extra evaluation is only paid for when it is reported.
    let dialect_divergence = cli_dialect_divergence(
        dialect,
        result.decision,
        command,
        &enabled_keywords,
        &ordered_packs,
        keyword_index.as_ref(),
        &compiled_overrides,
        &allowlists,
        &heredoc_settings,
        project_path.as_deref(),
    );

    // Handle structured output (JSON/TOON)
    if format.is_structured() {
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
                    mode: None,
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
                    dialect_divergence,
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
                    decision: resolved_mode
                        .unwrap_or(DecisionMode::Deny)
                        .label()
                        .to_string(),
                    mode: Some(
                        resolved_mode
                            .unwrap_or(DecisionMode::Deny)
                            .label()
                            .to_string(),
                    ),
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
                    dialect_divergence,
                }
            }
            EvaluationDecision::Indeterminate => TestOutput {
                schema_version: TEST_OUTPUT_SCHEMA_VERSION,
                dcg_version: env!("CARGO_PKG_VERSION").to_string(),
                robot_mode,
                command: command.to_string(),
                decision: "indeterminate".to_string(),
                mode: None,
                rule_id: None,
                pack_id: None,
                pattern_name: None,
                reason: Some(INDETERMINATE_REASON.to_string()),
                explanation: Some(
                    "Execution is blocked because DCG could not complete safety analysis."
                        .to_string(),
                ),
                source: Some("analysis_budget".to_string()),
                matched_span: None,
                severity: None,
                allowlist: None,
                agent: Some(agent_info.clone()),
                dialect_divergence,
            },
        };
        match format {
            TestFormat::Json => {
                println!("{}", serde_json::to_string_pretty(&output).unwrap());
            }
            TestFormat::Toon => {
                let json = serde_json::to_value(&output).expect("TestOutput should serialize");
                let encoded = toon::encode(json, None);
                println!("{encoded}");
            }
            TestFormat::Pretty => unreachable!("handled above"),
        }
        return policy_blocks_cli_execution(result.decision, resolved_mode);
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

    let mut interactive_allowed = false;
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
                    print_markdown_field("Explanation", explanation, "", use_color);
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
                    DecisionMode::Ask => {
                        result_line =
                            "Result: REVIEW REQUIRED (blocked outside a review-capable hook)"
                                .to_string();
                    }
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
                                        let layer = resolve_layer(false, false);
                                        let hours = duration.as_secs() / 3600;
                                        match duration_to_expires_at(duration) {
                                            Ok(expires) => {
                                                let reason = "Verified bypass via dcg test (security prompt temporary)";
                                                match apply_interactive_allowlist_entry(
                                                    command,
                                                    rule_id.as_deref(),
                                                    reason,
                                                    layer,
                                                    Some(expires.as_str()),
                                                ) {
                                                    Ok(applied) => {
                                                        if let Err(err) =
                                                            log_interactive_allowlist_audit_event(
                                                                &effective_config,
                                                                command,
                                                                &applied,
                                                            )
                                                        {
                                                            eprintln!(
                                                                "Warning: failed to write interactive allowlist audit: {err}"
                                                            );
                                                        }
                                                        result_line = format!(
                                                            "Result: ALLOWED (temporary allowlisted in {} for {} hours; {})",
                                                            layer.label(),
                                                            hours,
                                                            applied.summary
                                                        );
                                                    }
                                                    Err(err) => {
                                                        eprintln!("Allowlist update failed: {err}");
                                                        result_line = "Result: BLOCKED".to_string();
                                                    }
                                                }
                                            }
                                            Err(err) => {
                                                eprintln!(
                                                    "Failed to compute temporary expiration: {err}"
                                                );
                                                result_line = "Result: BLOCKED".to_string();
                                            }
                                        }
                                    }
                                    AllowlistScope::Permanent => {
                                        let layer = resolve_layer(false, false);
                                        let reason =
                                            "Verified bypass via dcg test (security prompt)";
                                        match apply_interactive_allowlist_entry(
                                            command,
                                            rule_id.as_deref(),
                                            reason,
                                            layer,
                                            None,
                                        ) {
                                            Ok(applied) => {
                                                if let Err(err) =
                                                    log_interactive_allowlist_audit_event(
                                                        &effective_config,
                                                        command,
                                                        &applied,
                                                    )
                                                {
                                                    eprintln!(
                                                        "Warning: failed to write interactive allowlist audit: {err}"
                                                    );
                                                }
                                                result_line = format!(
                                                    "Result: ALLOWED (allowlisted in {}; {})",
                                                    layer.label(),
                                                    applied.summary
                                                );
                                            }
                                            Err(err) => {
                                                eprintln!("Allowlist update failed: {err}");
                                                result_line = "Result: BLOCKED".to_string();
                                            }
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
                                        DialectArg::Unknown,
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
                                    let lifetime = prompt_allowlist_lifetime_choice();
                                    let expires = match lifetime {
                                        Some(duration) => match duration_to_expires_at(duration) {
                                            Ok(expires) => Some(expires),
                                            Err(err) => {
                                                eprintln!(
                                                    "Failed to compute temporary expiration: {err}"
                                                );
                                                result_line = "Result: BLOCKED".to_string();
                                                None
                                            }
                                        },
                                        None => None,
                                    };

                                    if result_line != "Result: BLOCKED" {
                                        match apply_interactive_allowlist_entry(
                                            command,
                                            rule_id.as_deref(),
                                            &reason,
                                            layer,
                                            expires.as_deref(),
                                        ) {
                                            Ok(applied) => {
                                                if let Err(err) =
                                                    log_interactive_allowlist_audit_event(
                                                        &effective_config,
                                                        command,
                                                        &applied,
                                                    )
                                                {
                                                    eprintln!(
                                                        "Warning: failed to write interactive allowlist audit: {err}"
                                                    );
                                                }
                                                if let Some(duration) = lifetime {
                                                    let hours = duration.as_secs() / 3600;
                                                    result_line = format!(
                                                        "Result: ALLOWED (temporary allowlisted in {} for {} hours; {})",
                                                        layer.label(),
                                                        hours,
                                                        applied.summary
                                                    );
                                                } else {
                                                    result_line = format!(
                                                        "Result: ALLOWED (allowlisted in {}; {})",
                                                        layer.label(),
                                                        applied.summary
                                                    );
                                                }
                                            }
                                            Err(err) => {
                                                eprintln!("Allowlist update failed: {err}");
                                                result_line = "Result: BLOCKED".to_string();
                                            }
                                        }
                                    }
                                }
                                InteractiveDecision::Block | InteractiveDecision::ShowDetails => {}
                            }
                        }
                    }
                }
            }

            interactive_allowed = result_line.starts_with("Result: ALLOWED");
            println!("{result_line}");
        }
        EvaluationDecision::Indeterminate => {
            println!("Result: INDETERMINATE (BLOCKED)");
            println!("Reason: {INDETERMINATE_REASON}");
        }
    }

    // #289 C1: point the user at the dialect the live Bash hook actually uses
    // when the all-dialect union is the only thing producing this denial.
    if !interactive_allowed {
        print_dialect_divergence_note(dialect_divergence, command);
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

    // Return true unless execution was affirmatively allowed. An incomplete
    // evaluation is a blocked outcome for CLI exit-code purposes (#213).
    !interactive_allowed && policy_blocks_cli_execution(result.decision, resolved_mode)
}

/// Classify a command's risk level and return an exit code.
///
/// Returns:
/// - 0 for allow (safe or low risk)
/// - `EXIT_DENIED` (1) for block (high or critical) or indeterminate
/// - `EXIT_WARNING` (2) for warn (medium risk)
fn classify_command(config: &Config, command: &str, format: ClassifyFormat, no_color: bool) -> i32 {
    // Build effective config (no extra packs for classify — uses current config as-is)
    let effective_config = config.clone();

    // Get enabled packs and collect keywords for quick rejection
    let mut enabled_packs = effective_config.enabled_pack_ids();
    let mut enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let heredoc_settings = effective_config.heredoc_settings();

    // Compile overrides once
    let compiled_overrides = effective_config.overrides.compile();

    // Load allowlists (project/user/system)
    let allowlists = load_default_allowlists();

    // Load external packs from custom_paths
    let external_paths = effective_config.packs.expand_custom_paths();
    let external_store = load_external_packs(&external_paths);

    // Auto-enable external packs and merge their keywords
    for id in external_store.pack_ids() {
        enabled_packs.insert(id.clone());
    }
    enabled_keywords.extend(external_store.keywords().iter().copied());

    // Build ordered pack list
    let mut ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    for id in external_store.pack_ids() {
        if !ordered_packs.contains(id) {
            ordered_packs.push(id.clone());
        }
    }
    let keyword_index = if external_store.pack_ids().next().is_some() {
        None
    } else {
        REGISTRY.build_enabled_keyword_index(&ordered_packs)
    };

    // Evaluate the command
    let project_path = std::env::current_dir().ok();
    let result = evaluate_command_with_pack_order_deadline_at_path(
        command,
        &enabled_keywords,
        &ordered_packs,
        keyword_index.as_ref(),
        &compiled_overrides,
        &allowlists,
        &heredoc_settings,
        None,                    // allow_once_audit
        project_path.as_deref(), // project_path scopes path-aware allowlist entries (#186)
        None,                    // deadline
    );

    // Map EvaluationResult to classification
    let (decision, risk_level, risk_score, reasons, suggestions) = match result.decision {
        EvaluationDecision::Allow => {
            // Check if this was an allowlist override (still matched a pattern)
            if result.allowlist_override.is_some() {
                // Matched a dangerous pattern but allowlisted — still "allow" but note it
                ("allow".to_string(), "low".to_string(), 0.2, vec![], vec![])
            } else {
                ("allow".to_string(), "safe".to_string(), 0.0, vec![], vec![])
            }
        }
        EvaluationDecision::Deny => {
            let severity = result.pattern_info.as_ref().and_then(|info| info.severity);
            let effective_mode = resolve_mode_for_cli(&effective_config, command, &result)
                .unwrap_or(DecisionMode::Deny);

            // Build reasons from pattern info
            let reasons = result
                .pattern_info
                .as_ref()
                .map(|info| {
                    let rule_id = info
                        .pack_id
                        .as_ref()
                        .and_then(|p| info.pattern_name.as_ref().map(|n| format!("{p}:{n}")))
                        .unwrap_or_else(|| "unknown".to_string());
                    let severity_str = info.severity.map_or("high", |s| s.label()).to_string();
                    let explanation = info
                        .explanation
                        .clone()
                        .unwrap_or_else(|| info.reason.clone());
                    vec![ClassifyReason {
                        rule_id,
                        severity: severity_str,
                        explanation,
                    }]
                })
                .unwrap_or_default();

            // Collect suggestions from pattern info
            let suggestions = result
                .pattern_info
                .as_ref()
                .map(|info| {
                    info.suggestions
                        .iter()
                        .filter(|s| s.platform.matches_current())
                        .map(|s| {
                            let gated_marker = if s.gated {
                                " [gated: dcg also requires approval for this]"
                            } else {
                                ""
                            };
                            if s.description.is_empty() {
                                format!("{}{gated_marker}", s.command)
                            } else {
                                format!("{} ({}){gated_marker}", s.command, s.description)
                            }
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            // Determine decision and risk based on severity and effective mode
            match effective_mode {
                DecisionMode::Log => {
                    // Log-only: treat as allow with low risk
                    let risk_score = match severity {
                        Some(PackSeverity::Low) => 0.2,
                        Some(PackSeverity::Medium) => 0.3,
                        _ => 0.2,
                    };
                    (
                        "allow".to_string(),
                        severity.map_or("low", |s| s.label()).to_string(),
                        risk_score,
                        reasons,
                        suggestions,
                    )
                }
                DecisionMode::Warn => {
                    let risk_score = match severity {
                        Some(PackSeverity::Medium) => 0.5,
                        Some(PackSeverity::Low) => 0.3,
                        _ => 0.5,
                    };
                    (
                        "warn".to_string(),
                        severity.map_or("medium", |s| s.label()).to_string(),
                        risk_score,
                        reasons,
                        suggestions,
                    )
                }
                DecisionMode::Ask => {
                    let (risk_level, risk_score) = match severity {
                        Some(PackSeverity::Critical) => ("critical", 1.0),
                        Some(PackSeverity::High) => ("high", 0.8),
                        Some(PackSeverity::Medium) => ("medium", 0.5),
                        Some(PackSeverity::Low) => ("low", 0.3),
                        None => ("high", 0.8),
                    };
                    (
                        "ask".to_string(),
                        risk_level.to_string(),
                        risk_score,
                        reasons,
                        suggestions,
                    )
                }
                DecisionMode::Deny => {
                    let (risk_level, risk_score) = match severity {
                        Some(PackSeverity::Critical) => ("critical", 1.0),
                        Some(PackSeverity::High) => ("high", 0.8),
                        Some(PackSeverity::Medium) => ("medium", 0.5),
                        Some(PackSeverity::Low) => ("low", 0.3),
                        None => ("high", 0.8), // Default to high if severity unknown
                    };
                    (
                        "block".to_string(),
                        risk_level.to_string(),
                        risk_score,
                        reasons,
                        suggestions,
                    )
                }
            }
        }
        EvaluationDecision::Indeterminate => (
            "indeterminate".to_string(),
            "unknown".to_string(),
            1.0,
            vec![ClassifyReason {
                rule_id: "dcg:analysis-budget".to_string(),
                severity: "unknown".to_string(),
                explanation: INDETERMINATE_REASON.to_string(),
            }],
            vec![],
        ),
    };

    let output = ClassifyOutput {
        schema_version: CLASSIFY_OUTPUT_SCHEMA_VERSION,
        dcg_version: env!("CARGO_PKG_VERSION").to_string(),
        command: command.to_string(),
        decision: decision.clone(),
        risk_level: risk_level.clone(),
        risk_score,
        reasons,
        suggestions,
    };

    match format {
        ClassifyFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
        ClassifyFormat::Text => {
            let use_color = !no_color && should_use_color();
            let decision_display = if use_color {
                match decision.as_str() {
                    "allow" => "\x1b[32mALLOW\x1b[0m",
                    "warn" => "\x1b[33mWARN\x1b[0m",
                    "ask" => "\x1b[33mASK (BLOCKED PENDING REVIEW)\x1b[0m",
                    "block" => "\x1b[31mBLOCK\x1b[0m",
                    "indeterminate" => "\x1b[31mINDETERMINATE (BLOCKED)\x1b[0m",
                    _ => &decision,
                }
            } else {
                match decision.as_str() {
                    "allow" => "ALLOW",
                    "warn" => "WARN",
                    "ask" => "ASK (BLOCKED PENDING REVIEW)",
                    "block" => "BLOCK",
                    "indeterminate" => "INDETERMINATE (BLOCKED)",
                    _ => &decision,
                }
            };
            println!("{decision_display} [{risk_level}] {command}");
            for reason in &output.reasons {
                println!("  rule: {} ({})", reason.rule_id, reason.severity);
                println!("  why:  {}", reason.explanation);
            }
            for suggestion in &output.suggestions {
                println!("  try:  {suggestion}");
            }
        }
    }

    // Exit code based on decision
    match output.decision.as_str() {
        "allow" => 0,
        "warn" => EXIT_WARNING,
        "ask" => EXIT_DENIED,
        "block" => EXIT_DENIED,
        "indeterminate" => EXIT_DENIED,
        _ => EXIT_DENIED,
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

/// A single project file detection that maps to a pack.
struct PackDetection {
    /// The pack ID to enable (e.g., "containers.docker").
    pack_id: String,
    /// What project file triggered this detection.
    evidence: String,
}

/// Scan a directory for project files and return the packs that should be enabled.
fn detect_project_packs(dir: &std::path::Path) -> Vec<PackDetection> {
    let mut detections: Vec<PackDetection> = Vec::new();
    let mut seen_packs = std::collections::HashSet::new();

    /// Add a detection if not already seen.
    fn add_detection(
        pack_id: &str,
        evidence: &str,
        seen: &mut std::collections::HashSet<String>,
        out: &mut Vec<PackDetection>,
    ) {
        if seen.insert(pack_id.to_string()) {
            out.push(PackDetection {
                pack_id: pack_id.to_string(),
                evidence: evidence.to_string(),
            });
        }
    }

    // --- Container detection ---
    if dir.join("Dockerfile").exists() || dir.join("dockerfile").exists() {
        add_detection(
            "containers.docker",
            "Dockerfile",
            &mut seen_packs,
            &mut detections,
        );
    }
    // Check for Dockerfile.* variants
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("Dockerfile.") || name.starts_with("dockerfile.") {
                add_detection(
                    "containers.docker",
                    &format!("{name}"),
                    &mut seen_packs,
                    &mut detections,
                );
            }
        }
    }
    if dir.join("docker-compose.yml").exists() || dir.join("docker-compose.yaml").exists() {
        add_detection(
            "containers.compose",
            "docker-compose.yml",
            &mut seen_packs,
            &mut detections,
        );
        add_detection(
            "containers.docker",
            "docker-compose.yml (implies Docker)",
            &mut seen_packs,
            &mut detections,
        );
    }
    if dir.join("compose.yml").exists() || dir.join("compose.yaml").exists() {
        add_detection(
            "containers.compose",
            "compose.yml",
            &mut seen_packs,
            &mut detections,
        );
        add_detection(
            "containers.docker",
            "compose.yml (implies Docker)",
            &mut seen_packs,
            &mut detections,
        );
    }
    if dir.join("Containerfile").exists() {
        add_detection(
            "containers.podman",
            "Containerfile",
            &mut seen_packs,
            &mut detections,
        );
    }

    // --- Infrastructure as Code ---
    if dir.join("terraform").is_dir()
        || dir.join(".terraform").is_dir()
        || dir.join("main.tf").exists()
        || dir.join("terraform.tfvars").exists()
    {
        add_detection(
            "infrastructure.terraform",
            "Terraform files (*.tf)",
            &mut seen_packs,
            &mut detections,
        );
    }
    // Check for any .tf files in the root
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".tf") {
                add_detection(
                    "infrastructure.terraform",
                    &format!("{name}"),
                    &mut seen_packs,
                    &mut detections,
                );
                break;
            }
        }
    }
    if dir.join("Pulumi.yaml").exists() || dir.join("Pulumi.yml").exists() {
        add_detection(
            "infrastructure.pulumi",
            "Pulumi.yaml",
            &mut seen_packs,
            &mut detections,
        );
    }
    if dir.join("ansible.cfg").exists()
        || dir.join("playbook.yml").exists()
        || dir.join("playbooks").is_dir()
        || dir.join("roles").is_dir()
    {
        add_detection(
            "infrastructure.ansible",
            "Ansible config/playbooks",
            &mut seen_packs,
            &mut detections,
        );
    }
    // Atmos (atmos.tools) keeps its root config in atmos.yaml/atmos.yml; the
    // wrapper verbs (terraform deploy/clean, helmfile destroy) are guarded by
    // the infrastructure.atmos pack.
    if dir.join("atmos.yaml").exists() || dir.join("atmos.yml").exists() {
        add_detection(
            "infrastructure.atmos",
            "atmos.yaml",
            &mut seen_packs,
            &mut detections,
        );
    }

    // --- CI/CD ---
    if dir.join(".github").join("workflows").is_dir() {
        add_detection(
            "cicd.github_actions",
            ".github/workflows/",
            &mut seen_packs,
            &mut detections,
        );
    }
    if dir.join(".gitlab-ci.yml").exists() {
        add_detection(
            "cicd.gitlab_ci",
            ".gitlab-ci.yml",
            &mut seen_packs,
            &mut detections,
        );
    }
    if dir.join("Jenkinsfile").exists() {
        add_detection(
            "cicd.jenkins",
            "Jenkinsfile",
            &mut seen_packs,
            &mut detections,
        );
    }
    if dir.join(".circleci").is_dir() {
        add_detection(
            "cicd.circleci",
            ".circleci/",
            &mut seen_packs,
            &mut detections,
        );
    }

    // --- Kubernetes ---
    if dir.join("k8s").is_dir() || dir.join("kubernetes").is_dir() {
        add_detection(
            "kubernetes.kubectl",
            "k8s/ or kubernetes/ directory",
            &mut seen_packs,
            &mut detections,
        );
    }
    if dir.join("Chart.yaml").exists() || dir.join("charts").is_dir() {
        add_detection(
            "kubernetes.helm",
            "Chart.yaml or charts/",
            &mut seen_packs,
            &mut detections,
        );
        add_detection(
            "kubernetes.kubectl",
            "Helm chart (implies kubectl)",
            &mut seen_packs,
            &mut detections,
        );
    }
    if dir.join("kustomization.yaml").exists() || dir.join("kustomization.yml").exists() {
        add_detection(
            "kubernetes.kustomize",
            "kustomization.yaml",
            &mut seen_packs,
            &mut detections,
        );
        add_detection(
            "kubernetes.kubectl",
            "Kustomize (implies kubectl)",
            &mut seen_packs,
            &mut detections,
        );
    }

    // --- Cloud providers ---
    if dir.join(".aws").is_dir()
        || dir.join("serverless.yml").exists()
        || dir.join("serverless.yaml").exists()
        || dir.join("sam-template.yaml").exists()
        || (dir.join("template.yaml").exists() && dir.join("samconfig.toml").exists())
    {
        add_detection(
            "cloud.aws",
            ".aws/ or serverless config",
            &mut seen_packs,
            &mut detections,
        );
    }
    if dir.join("cloudbuild.yaml").exists()
        || dir.join("cloudbuild.yml").exists()
        || (dir.join("app.yaml").exists() && dir.join(".gcloudignore").exists())
    {
        add_detection(
            "cloud.gcp",
            "Google Cloud config",
            &mut seen_packs,
            &mut detections,
        );
    }
    if dir.join("azure-pipelines.yml").exists() || dir.join(".azure").is_dir() {
        add_detection(
            "cloud.azure",
            "Azure config",
            &mut seen_packs,
            &mut detections,
        );
    }

    // --- Database detection from dependency files ---
    detect_database_packs_from_deps(dir, &mut seen_packs, &mut detections);

    // --- Package managers ---
    if dir.join("package.json").exists()
        || dir.join("Cargo.toml").exists()
        || dir.join("Gemfile").exists()
        || dir.join("requirements.txt").exists()
        || dir.join("pyproject.toml").exists()
        || dir.join("go.mod").exists()
        || dir.join("composer.json").exists()
    {
        add_detection(
            "package_managers",
            "Package manifest detected",
            &mut seen_packs,
            &mut detections,
        );
    }

    // --- Secrets managers ---
    if dir.join(".vault").is_dir() || dir.join("vault.hcl").exists() {
        add_detection(
            "secrets.vault",
            "Vault configuration",
            &mut seen_packs,
            &mut detections,
        );
    }
    if dir.join(".op").is_dir() {
        add_detection(
            "secrets.onepassword",
            ".op/ directory",
            &mut seen_packs,
            &mut detections,
        );
    }

    detections
}

/// Check if `keyword` appears as a complete word in `content`.
///
/// A "word" is bounded by non-alphanumeric characters (or start/end of string).
/// This prevents false positives like "pg" matching "upgrading" or "package".
fn contains_word(content: &str, keyword: &str) -> bool {
    let kw_bytes = keyword.as_bytes();
    let kw_len = kw_bytes.len();
    let content_bytes = content.as_bytes();
    let content_len = content_bytes.len();

    if kw_len == 0 || kw_len > content_len {
        return false;
    }

    let mut start = 0;
    while let Some(pos) = content[start..].find(keyword) {
        let abs_pos = start + pos;
        let before_ok = abs_pos == 0 || !content_bytes[abs_pos - 1].is_ascii_alphanumeric();
        let after_pos = abs_pos + kw_len;
        let after_ok =
            after_pos >= content_len || !content_bytes[after_pos].is_ascii_alphanumeric();

        if before_ok && after_ok {
            return true;
        }

        // Advance past this match to avoid infinite loop
        start = abs_pos + 1;
    }

    false
}

/// Scan dependency files for database driver references and add appropriate pack detections.
fn detect_database_packs_from_deps(
    dir: &std::path::Path,
    seen_packs: &mut std::collections::HashSet<String>,
    detections: &mut Vec<PackDetection>,
) {
    // Database driver keywords mapped to pack IDs
    let db_patterns: &[(&str, &[&str])] = &[
        (
            "database.postgresql",
            &[
                "pg",
                "postgres",
                "postgresql",
                "psycopg",
                "asyncpg",
                "diesel",
                "sqlx",
                "tokio-postgres",
                "libpq",
            ],
        ),
        (
            "database.mysql",
            &["mysql", "mysql2", "mysqlclient", "pymysql", "mariadb"],
        ),
        (
            "database.mongodb",
            &["mongoose", "mongodb", "mongoid", "pymongo", "motor"],
        ),
        (
            "database.redis",
            &["redis", "ioredis", "redis-py", "predis", "hiredis"],
        ),
        (
            "database.sqlite",
            &[
                "sqlite",
                "sqlite3",
                "better-sqlite3",
                "rusqlite",
                "frankensqlite",
            ],
        ),
        (
            "database.snowflake",
            &[
                "snowflake-connector-python",
                "snowflake-snowpark-python",
                "snowflake-sdk",
                "snowflake-sqlalchemy",
            ],
        ),
        ("database.supabase", &["supabase", "@supabase/supabase-js"]),
        (
            "database.bigquery",
            &[
                "google-cloud-bigquery",
                "@google-cloud/bigquery",
                "pandas-gbq",
                "sqlalchemy-bigquery",
            ],
        ),
    ];

    // Scan multiple dependency files
    let dep_files: &[&str] = &[
        "package.json",
        "requirements.txt",
        "Pipfile",
        "pyproject.toml",
        "Gemfile",
        "Cargo.toml",
        "go.mod",
        "composer.json",
        "go.sum",
    ];

    for dep_file in dep_files {
        let path = dir.join(dep_file);
        if !path.exists() {
            continue;
        }
        // Read the file content (limit to 256KB to avoid huge lockfiles)
        let content = match std::fs::read_to_string(&path) {
            Ok(c) if c.len() <= 256 * 1024 => c,
            _ => continue,
        };
        let content_lower = content.to_lowercase();

        for &(pack_id, keywords) in db_patterns {
            for &kw in keywords {
                if contains_word(&content_lower, kw) {
                    if seen_packs.insert(pack_id.to_string()) {
                        detections.push(PackDetection {
                            pack_id: pack_id.to_string(),
                            evidence: format!("{dep_file} contains \"{kw}\""),
                        });
                    }
                    break;
                }
            }
        }
    }
}

/// Print the results of auto-detection.
fn print_auto_detect_results(
    detections: &[PackDetection],
    scan_dir: &std::path::Path,
    dry_run: bool,
) {
    use colored::Colorize;

    if dry_run {
        println!(
            "{} Scanning {} for project files...",
            "[dry-run]".yellow().bold(),
            scan_dir.display()
        );
    } else {
        println!("Scanning {} for project files...", scan_dir.display());
    }
    println!();

    if detections.is_empty() {
        println!("No project-specific files detected.");
        println!("Using default packs: core.filesystem, core.git");
        return;
    }

    println!("{}", "Detected packs:".bold());
    for d in detections {
        println!(
            "  {} {} {}",
            "+".green().bold(),
            d.pack_id.green(),
            format!("({})", d.evidence).dimmed()
        );
    }
    println!();

    // Always-on packs
    println!("{}", "Always enabled: core.filesystem, core.git".dimmed());
    println!();

    if dry_run {
        println!(
            "{}",
            "Run 'dcg init --auto' to write this configuration.".yellow()
        );
    }
}

/// Generate a configuration file with specific packs enabled.
fn init_config_with_packs(
    output: Option<String>,
    force: bool,
    packs: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let config = generate_config_with_packs(packs);

    let path_str = output.unwrap_or_else(|| config_path().to_string_lossy().into_owned());
    let path = std::path::Path::new(&path_str);

    if path.exists() && !force {
        return Err(format!("File exists: {}. Use --force to overwrite.", path.display()).into());
    }

    // Create parent directories if needed
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, config)?;
    println!("Configuration written to: {}", path.display());

    Ok(())
}

/// Generate a TOML configuration string with the given packs enabled.
fn generate_config_with_packs(packs: &[String]) -> String {
    // Start with the sample config but replace the packs section
    let mut lines = vec![
        "# dcg configuration".to_string(),
        "# https://github.com/Dicklesworthstone/destructive_command_guard".to_string(),
        "# Generated by: dcg init --auto".to_string(),
        String::new(),
        "[general]".to_string(),
        "color = \"auto\"".to_string(),
        "verbose = false".to_string(),
        String::new(),
        "[packs]".to_string(),
        "# Auto-detected packs from project files.".to_string(),
        "# Core packs (core.filesystem, core.git) are always enabled implicitly.".to_string(),
    ];

    if packs.is_empty() {
        lines.push("enabled = []".to_string());
    } else {
        lines.push("enabled = [".to_string());
        for (i, pack) in packs.iter().enumerate() {
            if i < packs.len() - 1 {
                lines.push(format!("    \"{pack}\","));
            } else {
                lines.push(format!("    \"{pack}\""));
            }
        }
        lines.push("]".to_string());
    }

    lines.push(String::new());
    lines.push("disabled = []".to_string());
    lines.push(String::new());

    lines.join("\n")
}

fn config_source_path_label(source: &ConfigSourceOutcome) -> String {
    source.path.as_ref().map_or_else(
        || "(no path)".to_string(),
        |path| path.display().to_string(),
    )
}

fn config_source_summary(source: &ConfigSourceOutcome) -> String {
    let mut summary = format!(
        "{} [{}; {}]",
        config_source_path_label(source),
        source.status.label(),
        source.authority.label()
    );
    if let Some(detail) = &source.detail {
        summary.push_str(" — ");
        summary.push_str(detail);
    }
    summary
}

fn config_sources_json(sources: &[ConfigSourceOutcome]) -> Vec<serde_json::Value> {
    sources
        .iter()
        .map(|source| {
            let level = match source.layer {
                ConfigFileLayer::System => "system",
                ConfigFileLayer::User => "user",
                ConfigFileLayer::AutomaticProject => "automatic_project",
                ConfigFileLayer::Explicit => "explicit",
            };
            serde_json::json!({
                "level": level,
                "label": source.layer.label(),
                "path": source.path.as_ref().map(|path| path.display().to_string()),
                "status": source.status,
                "authority": source.authority,
                "detail": source.detail.as_deref(),
            })
        })
        .collect()
}

/// Show the current configuration and the exact source outcomes that produced it.
fn show_config(config: &Config, sources: &[ConfigSourceOutcome]) {
    println!("Current configuration:");
    println!();
    println!("Config file outcomes (lowest → highest priority):");
    for source in sources {
        println!(
            "  - {}: {}",
            source.layer.label(),
            config_source_summary(source)
        );
    }
    println!();
    println!("General:");
    println!("  Color: {}", config.general.color);
    println!("  Verbose: {}", config.general.verbose);
    println!("  Log file: {:?}", config.general.log_file);
    println!(
        "  Hook timeout (ms): {} ({})",
        config.effective_hook_timeout_ms(),
        config.hook_timeout_source()
    );
    println!("  Hook self-heal: {}", config.general.self_heal_hook);
    println!("  Fail closed: {}", config.general.fail_closed);
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
        "  Bounded fallback on parse error: {}",
        heredoc.fallback_on_parse_error
    );
    println!(
        "  Bounded fallback on timeout: {}",
        heredoc.fallback_on_timeout
    );

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

    // Removed config keys (#327): a key that parses but is never enforced is
    // indistinguishable from one that simply didn't match, so say it here —
    // the command a user actually runs to check their configuration.
    let removed_key_warnings = config.overrides.removed_key_warnings();
    if !removed_key_warnings.is_empty() {
        println!();
        println!("Warnings:");
        for warning in &removed_key_warnings {
            println!("  - {warning}");
        }
    }
}

/// Emit the current configuration as JSON for agents/scripts (issue #159).
///
/// Mirrors the fields shown by [`show_config`] in a stable, machine-readable
/// shape so consumers can parse the active configuration without scraping the
/// human-readable output.
fn show_config_json(config: &Config, sources: &[ConfigSourceOutcome]) {
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

    let heredoc = config.heredoc_settings();
    let languages = heredoc.allowed_languages.as_ref().map_or_else(
        || serde_json::Value::String("all".to_string()),
        |langs| {
            serde_json::Value::Array(
                langs
                    .iter()
                    .copied()
                    .map(|l| serde_json::Value::String(lang_label(l).to_string()))
                    .collect(),
            )
        },
    );

    // Sort enabled packs for deterministic JSON output (the set is unordered).
    let mut enabled_packs: Vec<String> = config.enabled_pack_ids().into_iter().collect();
    enabled_packs.sort();

    // Echo the enforcement-relevant sections so an automated check can assert
    // what is actually loaded (#327): before this, `jq '.overrides'` returned
    // null whether a section was enforcing or absent, and `dcg test` was the
    // only observable. HashMap-backed sections go through BTreeMap views for
    // deterministic output.
    let rules_view: std::collections::BTreeMap<&String, &crate::config::RuleConfig> =
        config.rules.iter().collect();
    let policy_rules_view: std::collections::BTreeMap<&String, _> =
        config.policy.rules.iter().collect();
    let policy_packs_view: std::collections::BTreeMap<&String, _> =
        config.policy.packs.iter().collect();
    let mut removed_keys_present: Vec<&str> = Vec::new();
    if config.overrides.allowlist.is_some() {
        removed_keys_present.push("overrides.allowlist");
    }
    if config.overrides.allowlist_rules.is_some() {
        removed_keys_present.push("overrides.allowlist_rules");
    }

    let output = serde_json::json!({
        "dcg_version": env!("CARGO_PKG_VERSION"),
        "config_sources": config_sources_json(sources),
        "general": {
            "color": config.general.color,
            "verbose": config.general.verbose,
            "log_file": config.general.log_file,
            "hook_timeout_ms": config.effective_hook_timeout_ms(),
            "hook_timeout_source": config.hook_timeout_source(),
            "self_heal_hook": config.general.self_heal_hook,
            "fail_closed": config.general.fail_closed,
        },
        "packs": {
            "enabled": enabled_packs,
            "disabled": config.packs.disabled,
        },
        "heredoc": {
            "enabled": heredoc.enabled,
            "timeout_ms": heredoc.limits.timeout_ms,
            "max_body_bytes": heredoc.limits.max_body_bytes,
            "max_body_lines": heredoc.limits.max_body_lines,
            "max_heredocs": heredoc.limits.max_heredocs,
            "fail_open_on_parse_error": heredoc.fallback_on_parse_error,
            "fail_open_on_timeout": heredoc.fallback_on_timeout,
            "languages": languages,
        },
        "overrides": {
            "allow": config.overrides.allow,
            "block": config.overrides.block,
            "removed_keys_present": removed_keys_present,
        },
        "rules": rules_view,
        "policy": {
            "default_mode": config.policy.default_mode,
            "packs": policy_packs_view,
            "rules": policy_rules_view,
        },
        "warnings": config.overrides.removed_key_warnings(),
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&output)
            .unwrap_or_else(|_| "{\"error\":\"failed to serialize config\"}".to_string())
    );
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
  repo_root=$(git rev-parse --show-toplevel 2>/dev/null || pwd -P)
  echo >&2
  echo "dcg scan blocked this commit." >&2
  echo "Fix findings (preferred), or allowlist false positives:" >&2
  echo "  dcg allow <rule_id> -r \"<reason>\" --user --path \"$repo_root\" --path \"$repo_root/**\"" >&2
  echo "  dcg allowlist add-command \"<command>\" -r \"<reason>\" --user --path \"$repo_root\" --path \"$repo_root/**\"" >&2
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
        with_packs,
        max_file_size,
        max_findings,
        exclude,
        include,
        redact,
        truncate,
        top,
        positional_paths,
        action,
    } = scan;

    // Merge positionally-supplied paths into the `--paths` selection so
    // `dcg scan a.sh b.sh` behaves like `dcg scan --paths a.sh b.sh` (issue
    // #158). The two forms are mutually exclusive at the clap layer, so at most
    // one is non-empty; prefer the explicit `--paths` if somehow both are set.
    let paths = match (paths, positional_paths) {
        (Some(p), _) => Some(p),
        (None, pos) if !pos.is_empty() => Some(pos),
        (None, _) => None,
    };

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
            let effective_config = with_packs.as_ref().map_or_else(
                || config.clone(),
                |packs| {
                    let mut modified = config.clone();
                    modified.packs.enabled.extend(packs.iter().cloned());
                    modified
                },
            );
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
                &effective_config,
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

    // SECURITY: `rev_range` is user-supplied (`--git-diff <rev>`). Without
    // validation it is forwarded as a positional arg to `git diff`, which
    // happily interprets values starting with `-` as flags. A value like
    // `--output=/etc/dcg/allowlist.toml` redirects the diff into that
    // file (clobbering it); `--ext-diff` activates external diff drivers
    // from `.git/config` (arbitrary command execution if an attacker
    // controls the repo's gitconfig). Reject anything that looks like a
    // flag or contains shell metacharacters.
    validate_git_rev_range(rev_range)?;

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

/// Reject `rev_range` values that could be misinterpreted by `git diff` as
/// flags (anything starting with `-`) or that contain shell metacharacters
/// (`\0`, `\n`, `\r`, whitespace, `;`, `&`, `|`, etc.). Legitimate git
/// rev-ranges look like `HEAD~3..HEAD`, `main..feature`,
/// `release/1.0..HEAD`, `v1.2.3...v2.0`, or a single ref like `HEAD@{1}`.
///
/// We do *not* reject every character forbidden by `git check-ref-format`;
/// the goal is to block the unambiguous flag/injection cases, not to
/// reproduce git's full refname grammar in here. If git itself rejects a
/// legitimate-looking value the underlying error is surfaced normally.
fn validate_git_rev_range(rev_range: &str) -> Result<(), Box<dyn std::error::Error>> {
    if rev_range.is_empty() {
        return Err("--git-diff value is empty".into());
    }
    if rev_range.starts_with('-') {
        return Err(format!(
            "--git-diff value {rev_range:?} starts with '-' (would be parsed by git as a flag)"
        )
        .into());
    }
    for ch in rev_range.chars() {
        let bad = matches!(
            ch,
            '\0' | '\n' | '\r' | ' ' | '\t' | ';' | '&' | '|' | '`' | '$' | '<' | '>' | '(' | ')'
        );
        if bad {
            return Err(format!(
                "--git-diff value {rev_range:?} contains a disallowed character ({ch:?})"
            )
            .into());
        }
    }
    Ok(())
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
fn print_scan_pretty(report: &crate::scan::ScanReport, verbose: bool, top: usize) {
    #[cfg(feature = "rich-output")]
    {
        if crate::output::should_use_rich_output() {
            print_scan_pretty_rich(report, verbose, top);
            return;
        }
    }

    print_scan_pretty_plain(report, verbose, top);
}

fn print_scan_pretty_plain(report: &crate::scan::ScanReport, verbose: bool, top: usize) {
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
    if !report.summary.paths_skipped.is_empty() {
        println!("{}", "Skipped input path(s):".yellow());
        for entry in &report.summary.paths_skipped {
            println!("  {} ({:?})", entry.path, entry.reason);
        }
    }
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
fn print_scan_pretty_rich(report: &crate::scan::ScanReport, verbose: bool, top: usize) {
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
    if !report.summary.paths_skipped.is_empty() {
        con.print("[yellow]Skipped input path(s):[/]");
        for entry in &report.summary.paths_skipped {
            con.print(&format!("  {} ({:?})", entry.path, entry.reason));
        }
    }
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
        "| Input paths skipped | {} |",
        report.summary.paths_skipped.len()
    );
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

    if !report.summary.paths_skipped.is_empty() {
        println!("\n### Skipped Input Paths\n");
        for entry in &report.summary.paths_skipped {
            println!("- `{}` ({:?})", entry.path, entry.reason);
        }
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
    dialect: DialectArg,
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
    let mut enabled_packs = effective_config.enabled_pack_ids();
    let mut enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let heredoc_settings = effective_config.heredoc_settings();
    let compiled_overrides = effective_config.overrides.compile();
    let allowlists = load_default_allowlists();

    // Load external packs from custom_paths (glob + tilde expansion).
    let external_paths = effective_config.packs.expand_custom_paths();
    let external_store = load_external_packs(&external_paths);

    // Auto-enable external packs and merge their keywords.
    for id in external_store.pack_ids() {
        enabled_packs.insert(id.clone());
    }
    enabled_keywords.extend(external_store.keywords().iter().copied());

    // Build ordered pack list AFTER external packs are loaded so they're included.
    let mut ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    for id in external_store.pack_ids() {
        if !ordered_packs.contains(id) {
            ordered_packs.push(id.clone());
        }
    }
    // Disable keyword index when external packs are present (not covered by index).
    let keyword_index = if external_store.pack_ids().next().is_some() {
        None
    } else {
        REGISTRY.build_enabled_keyword_index(&ordered_packs)
    };

    // Start tracing
    let mut collector = TraceCollector::new(command);

    // Evaluate with timing
    collector.begin_step();
    let result = evaluate_command_with_pack_order_deadline_at_path_in_dialect(
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
        dialect.into(),
    );
    collector.end_step(
        "full_evaluation",
        TraceDetails::KeywordGating {
            quick_rejected: result.quick_rejected,
            keywords_checked: enabled_keywords.iter().map(|s| (*s).to_string()).collect(),
            first_match: result.pattern_info.as_ref().and_then(|p| p.pack_id.clone()),
        },
    );
    collector.set_budget_skip(result.skipped_due_to_budget);

    // #289 C1: same divergence check as `dcg test` — an explain trace that
    // blames the all-dialect union must say so, or the reader will chase a
    // denial the Bash hook never makes.
    let dialect_divergence = cli_dialect_divergence(
        dialect,
        result.decision,
        command,
        &enabled_keywords,
        &ordered_packs,
        keyword_index.as_ref(),
        &compiled_overrides,
        &allowlists,
        &heredoc_settings,
        None, // project_path: matches the evaluation above
    );

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

    // A rule that matched but was stood down by a configured target exemption
    // is an allow that came from configuration, so explain must say so (#284).
    let target_suppressions = crate::config::take_rule_target_suppressions();

    // Format and print based on selected format
    match format {
        ExplainFormat::Pretty => {
            #[cfg(feature = "rich-output")]
            {
                if crate::output::should_use_rich_output() {
                    explain_rich(&trace);
                } else {
                    print_explain_pretty_plain(&trace);
                }
            }
            #[cfg(not(feature = "rich-output"))]
            {
                print_explain_pretty_plain(&trace);
            }
            print_dialect_divergence_note(dialect_divergence, command);
            print_rule_target_suppression_notes(&target_suppressions);
        }
        ExplainFormat::Compact => {
            println!("{}", trace.format_compact(None));
            print_dialect_divergence_note(dialect_divergence, command);
            print_rule_target_suppression_notes(&target_suppressions);
        }
        ExplainFormat::Json => {
            let mut json_output = trace.to_json_output();
            json_output.dialect_divergence = dialect_divergence;
            let json = serde_json::to_string_pretty(&json_output)
                .unwrap_or_else(|e| format!("{{\"error\": \"JSON serialization failed: {e}\"}}"));
            println!("{json}");
        }
    }
}

/// Report rules that matched but were stood down by a configured target
/// exemption (#284).
///
/// The decision trace records what *decided* the command; this note records
/// what *stopped deciding* it, so an allow is never silent about the config
/// that produced it.
fn print_rule_target_suppression_notes(suppressions: &[crate::config::RuleTargetSuppression]) {
    for suppression in suppressions {
        println!(
            "Note: rule {} matched but target \"{}\" was exempted by [rules.\"{}\"] exempt_target_globs entry \"{}\"",
            suppression.rule_id, suppression.target, suppression.rule_id, suppression.glob
        );
    }
}

fn print_explain_pretty_plain(trace: &crate::trace::ExplainTrace) {
    let output = trace.format_pretty(colored::control::SHOULD_COLORIZE.should_colorize());
    println!("{output}");
    print_explain_regex_line(trace);
}

fn print_explain_regex_line(trace: &crate::trace::ExplainTrace) {
    let Some(match_info) = trace.match_info.as_ref() else {
        return;
    };
    let Some((pack_id, pattern_name)) = match_info
        .pack_id
        .as_deref()
        .zip(match_info.pattern_name.as_deref())
    else {
        return;
    };
    let Some(regex) = crate::highlight::find_pattern_regex(pack_id, pattern_name) else {
        return;
    };

    let regex =
        crate::highlight::format_regex_pattern(&regex, crate::output::auto_theme().colors_enabled);
    println!("Regex: {regex}");
}

/// Rich output for explain command with tree visualization.
#[cfg(feature = "rich-output")]
fn explain_rich(trace: &crate::trace::ExplainTrace) {
    crate::output::explain_trace_tree(trace)
        .with_theme(&crate::output::auto_theme())
        .render();
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

    let mut enabled_packs = effective_config.enabled_pack_ids();
    let mut enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let compiled_overrides = effective_config.overrides.compile();
    let allowlists = crate::LayeredAllowlist::default();
    let heredoc_settings = effective_config.heredoc_settings();

    // Load external packs from custom_paths (glob + tilde expansion).
    let external_paths = effective_config.packs.expand_custom_paths();
    let external_store = load_external_packs(&external_paths);

    // Auto-enable external packs and merge their keywords.
    for id in external_store.pack_ids() {
        enabled_packs.insert(id.clone());
    }
    enabled_keywords.extend(external_store.keywords().iter().copied());

    // Build ordered pack list AFTER external packs are loaded.
    let mut ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    for id in external_store.pack_ids() {
        if !ordered_packs.contains(id) {
            ordered_packs.push(id.clone());
        }
    }
    // Disable keyword index when external packs are present.
    let keyword_index = if external_store.pack_ids().next().is_some() {
        None
    } else {
        REGISTRY.build_enabled_keyword_index(&ordered_packs)
    };

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
        EvaluationDecision::Indeterminate => "indeterminate",
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

    let quick_rejected = result.quick_rejected;

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
                if crate::output::should_use_rich_output() {
                    format_stats_pack_rich(&aggregated, cmd.days);
                } else {
                    print!("{}", stats::format_stats_pretty(&aggregated, cmd.days));
                }
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
    let db = match HistoryDb::open_with_max_size(db_path, config.history.max_size_mb) {
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
                if crate::output::should_use_rich_output() {
                    format_rule_metrics_rich(&metrics, cmd.days);
                } else {
                    print!("{}", format_rule_metrics_pretty(&metrics, cmd.days));
                }
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
    robot_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Handle --undo mode first
    if let Some(minutes) = cmd.undo {
        return handle_suggest_allowlist_undo(minutes);
    }

    // Parse the "since" duration
    let duration = parse_duration_string(&cmd.since)?;
    let since_time = Utc::now() - duration;

    let effective_format = if robot_mode {
        SuggestFormat::Json
    } else {
        cmd.format
    };

    // Open history database
    let db_path = config.history.expanded_database_path();
    let db = match HistoryDb::open_with_max_size(db_path, config.history.max_size_mb) {
        Ok(db) => db,
        Err(err) => {
            if matches!(effective_format, SuggestFormat::Json) {
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
        if matches!(effective_format, SuggestFormat::Json) {
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
        if matches!(effective_format, SuggestFormat::Json) {
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
        if matches!(effective_format, SuggestFormat::Json) {
            // Output empty array for JSON format
            println!("[]");
            return Ok(());
        }
        println!("No suggestions available.");
        return Ok(());
    }

    // --apply mode: apply specific suggestions by 1-based index, non-interactively
    if let Some(ref indices) = cmd.apply {
        apply_suggestions_by_index(&suggestions, indices, &db, cmd.accept_risk);
        return Ok(());
    }

    // Output based on format
    match effective_format {
        SuggestFormat::Json => {
            output_suggestions_json(&suggestions)?;
        }
        SuggestFormat::Text => {
            let force_non_interactive = robot_mode
                || cmd.non_interactive
                || std::env::var("DCG_NON_INTERACTIVE").is_ok()
                || std::env::var("CI").is_ok();
            if force_non_interactive {
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

/// Apply suggestions by 1-based index without interactive prompts.
///
/// `accept_risk` opts into writing suggestions whose `safety` decision is
/// `RequireConfirmation`. Without it, those entries are skipped — interactive
/// mode would have prompted for explicit confirmation, and `--apply` must not
/// silently bypass that gate. `NeverSuggest` entries are already removed by
/// `filter_suggestions_for_safety`, so they never reach this function.
fn apply_suggestions_by_index(
    suggestions: &[AllowlistSuggestion],
    indices: &[usize],
    db: &HistoryDb,
    accept_risk: bool,
) {
    let working_dir = std::env::current_dir()
        .ok()
        .map(|p| p.to_string_lossy().to_string());

    let mut applied = 0usize;
    let mut skipped = 0usize;

    for &idx in indices {
        if idx == 0 || idx > suggestions.len() {
            eprintln!(
                "Index {idx} out of range (1-{}), skipping",
                suggestions.len()
            );
            skipped += 1;
            continue;
        }

        let suggestion = &suggestions[idx - 1];
        let cluster = &suggestion.cluster;

        if suggestion.safety.requires_confirmation() && !accept_risk {
            let safety_reason = suggestion
                .safety
                .reason()
                .unwrap_or("requires explicit confirmation");
            eprintln!(
                "[{idx}] Skipped (safety): {} — {safety_reason}. Re-run with --accept-risk to apply.",
                cluster.proposed_pattern
            );
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
                sample_commands: serde_json::to_string(&cluster.commands).unwrap_or_default(),
                rule_id: None,
                session_id: None,
                working_dir: working_dir.clone(),
            };
            let _ = db.log_suggestion_audit(&audit_entry);
            skipped += 1;
            continue;
        }

        let reason = format!(
            "Auto-suggested ({} confidence, {} risk): {}",
            suggestion.confidence.as_str(),
            suggestion.risk.as_str(),
            suggestion.reason.description()
        );

        match allowlist_add_pattern(
            &cluster.proposed_pattern,
            &reason,
            suggestion.risk.as_str(),
            suggestion.confidence.as_str(),
            cluster.frequency,
            cluster.unique_count,
        ) {
            Ok(path) => {
                println!(
                    "[{idx}] Applied: {} → {}",
                    cluster.proposed_pattern,
                    path.display()
                );
                applied += 1;

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
                    sample_commands: serde_json::to_string(&cluster.commands).unwrap_or_default(),
                    rule_id: None,
                    session_id: None,
                    working_dir: working_dir.clone(),
                };
                let _ = db.log_suggestion_audit(&audit_entry);
            }
            Err(e) => {
                if e.to_string().contains("already exists") {
                    println!("[{idx}] Already in allowlist: {}", cluster.proposed_pattern);
                } else {
                    eprintln!("[{idx}] Failed: {e}");
                }
                skipped += 1;
            }
        }
    }

    println!();
    println!("{applied} applied, {skipped} skipped");
}

/// Handle the `dcg history` command.
fn handle_history_command(
    config: &Config,
    action: HistoryAction,
) -> Result<(), Box<dyn std::error::Error>> {
    let db_path = config.history.expanded_database_path();
    let db = match HistoryDb::open_with_max_size(db_path, config.history.max_size_mb) {
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
        HistoryAction::Interactive {
            limit,
            option,
            json,
        } => {
            history_interactive(&db, limit, option, json)?;
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

fn history_interactive(
    db: &HistoryDb,
    limit: usize,
    option: Option<String>,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if limit == 0 {
        return Err("limit must be at least 1".into());
    }

    let option_filter = option
        .as_deref()
        .map(|raw| {
            InteractiveAllowlistOptionType::parse(raw).ok_or_else(|| {
                format!("Invalid option type: {raw} (expected exact, temporary, or path_specific)")
            })
        })
        .transpose()?;

    let entries = db.query_interactive_allowlist_audits(limit, option_filter)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }

    if entries.is_empty() {
        println!("No interactive allowlist audit entries found.");
        return Ok(());
    }

    println!("Interactive allowlist audit entries (most recent first):");
    for entry in entries {
        println!(
            "- {} [{}] {} -> {}",
            entry.timestamp.to_rfc3339(),
            entry.option_type,
            entry.command,
            entry.pattern_added
        );
        if let Some(detail) = entry.option_detail.as_deref() {
            println!("    detail: {detail}");
        }
        println!("    config: {}", entry.config_file);
        if let Some(cwd) = entry.cwd.as_deref() {
            println!("    cwd: {cwd}");
        }
        if let Some(user) = entry.user.as_deref() {
            println!("    user: {user}");
        }
    }

    Ok(())
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

/// Check installation, configuration, and hook registration.
///
/// Returns the same verdict the report carries in its `ok` field, so the
/// caller can make the exit status agree with the diagnosis. Without this a
/// `dcg doctor || handle_failure` guard is dead code: the tool would report
/// that the guard is not guarding and still exit 0.
fn doctor(
    fix: bool,
    format: DoctorFormat,
    config: &Config,
    config_sources: &[ConfigSourceOutcome],
) -> bool {
    match format {
        DoctorFormat::Pretty => {
            #[cfg(feature = "rich-output")]
            {
                if crate::output::should_use_rich_output() {
                    doctor_rich(fix, config, config_sources)
                } else {
                    doctor_pretty(fix, config, config_sources)
                }
            }
            #[cfg(not(feature = "rich-output"))]
            {
                doctor_pretty(fix, config, config_sources)
            }
        }
        DoctorFormat::Json => doctor_json(fix, config, config_sources),
    }
}

/// Human-readable doctor output (colored crate, non-rich fallback).
#[allow(clippy::too_many_lines, clippy::unnecessary_unwrap)]
fn doctor_pretty(fix: bool, config: &Config, config_sources: &[ConfigSourceOutcome]) -> bool {
    use colored::Colorize;

    println!("{}", "dcg doctor".green().bold());
    println!();

    let mut issues = 0;
    let mut fixed = 0;
    let mut wired_to_an_agent = true;

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
        wired_to_an_agent = false;
    }

    // Check 3: Hook wiring (expanded diagnostics)
    print!("Checking hook wiring... ");
    let hook_diag = diagnose_hook_wiring();
    issues += hook_diagnostics_issue_count(&hook_diag);

    if !hook_diag.settings_exists {
        println!("{}", "SKIPPED".yellow());
        println!("  No settings file to check");
    } else if let Some(ref err) = hook_diag.settings_error {
        println!("{}", "ERROR".red());
        println!("  {err}");
        println!("  → Fix the settings.json file or reinstall Claude Code");
    } else if hook_diag.dcg_hook_count == 0 {
        println!("{}", "NOT REGISTERED".red());
        if fix {
            println!("  Attempting to register hook...");
            if install_hook(false, false).is_ok() {
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
        if fix {
            println!("  Attempting to reconcile hooks...");
            if install_hook(true, false).is_ok() {
                println!("  {}", "Fixed!".green());
                fixed += 1;
            } else {
                println!("  {}", "Failed to fix".red());
            }
        } else {
            println!("  → Run 'dcg install --force' to reconcile duplicates safely");
        }
    } else if !hook_diag.wrong_matcher_hooks.is_empty() {
        println!("{}", "MISCONFIGURED".red());
        println!(
            "  Hook registered with wrong matcher: {:?}",
            hook_diag.wrong_matcher_hooks
        );
        println!("  → dcg must match both Claude shell tools ({CLAUDE_SHELL_MATCHER})");
        if fix {
            println!("  Attempting to migrate the hook...");
            if install_hook(true, false).is_ok() {
                println!("  {}", "Fixed!".green());
                fixed += 1;
            } else {
                println!("  {}", "Failed to fix".red());
            }
        } else {
            println!("  → Run 'dcg install --force' to migrate safely");
        }
    } else if !hook_diag.misconfigured_hooks.is_empty() {
        println!("{}", "MISCONFIGURED".red());
        for hook in &hook_diag.misconfigured_hooks {
            println!("  Hook cannot synchronously enforce a block: {hook}");
        }
        if fix {
            println!("  Attempting to replace the hook...");
            if install_hook(true, false).is_ok() {
                println!("  {}", "Fixed!".green());
                fixed += 1;
            } else {
                println!("  {}", "Failed to fix".red());
            }
        } else {
            println!("  → Run 'dcg install --force' to replace the hook safely");
        }
    } else if !hook_diag.missing_executable_hooks.is_empty() {
        println!("{}", "BROKEN".red());
        for path in &hook_diag.missing_executable_hooks {
            println!("  Hook points to missing executable: {path}");
        }
        if fix {
            println!("  Attempting to replace the broken entry...");
            if install_hook(true, false).is_ok() {
                println!("  {}", "Fixed!".green());
                fixed += 1;
            } else {
                println!("  {}", "Failed to fix".red());
            }
        } else {
            println!("  → Run 'dcg install --force' to replace the broken entry");
        }
    } else {
        println!("{}", "OK".green());
        println!(
            "  Exactly one dcg hook registered; {} unrelated hook{} preserved",
            hook_diag.other_hooks_count,
            if hook_diag.other_hooks_count == 1 {
                ""
            } else {
                "s"
            }
        );
    }

    // Check 3b: Grok (xAI) native hook registration.
    //
    // We only surface this check when Grok is plausibly in use, to avoid
    // adding noise for users who don't have Grok installed. Plausible signals:
    //   - GROK_* env vars present in the current process (Grok is the parent)
    //   - ~/.grok directory exists (Grok was installed at some point)
    //
    // Grok also works via the Claude compatibility layer (~/.claude/settings.json
    // — covered by Check 3 above). The native dcg.json gives a cleaner doctor
    // output and avoids coupling Grok's behavior to Claude's settings file.
    let grok_session_present = std::env::var_os("GROK_SESSION_ID").is_some()
        || std::env::var_os("GROK_HOOK_EVENT").is_some()
        || std::env::var_os("GROK_WORKSPACE_ROOT").is_some();
    let grok_home = dirs::home_dir().map(|h| h.join(".grok"));
    let grok_home_exists = grok_home.as_ref().is_some_and(|p| p.exists() && p.is_dir());
    if grok_session_present || grok_home_exists {
        print!("Checking Grok hook registration... ");

        let user_hook = grok_user_hook_path();
        let user_hook_exists = user_hook.exists();
        let claude_compat_path = claude_settings_path();
        let claude_compat_exists = claude_compat_path.exists();

        if user_hook_exists {
            println!("{}", "OK".green());
            println!("  Found: {}", user_hook.display());
            if claude_compat_exists {
                println!(
                    "  Grok also picks up dcg from {} (Claude compatibility layer).",
                    claude_compat_path.display()
                );
            }
        } else if claude_compat_exists && hook_diag.dcg_hook_count >= 1 {
            // Grok will use the Claude-compat path; this still works but the
            // native path is preferred. Surface as a friendly note, not an
            // error, so users who deliberately rely on Claude-compat aren't
            // pestered. Any non-zero hook count is fine here because the
            // "duplicate Claude hooks" case is already reported as a WARNING
            // by Check 3 above — from Grok's point of view the compat layer
            // is wired up either way, so we shouldn't escalate to
            // "NOT REGISTERED" just because the Claude side has duplicates.
            println!("{}", "OK (via Claude compat)".green());
            println!(
                "  No native ~/.grok/hooks/dcg.json — Grok will pick up dcg from {}.",
                claude_compat_path.display()
            );
            println!(
                "  For a native install, run 'dcg install --grok' (creates {}).",
                user_hook.display()
            );
        } else {
            println!("{}", "NOT REGISTERED".yellow());
            // Reached only when Grok is in use AND neither the native hook nor
            // the Claude-compat path is wired — the guard is not guarding.
            // This branch already incremented `fixed` on a successful repair;
            // without the matching `issues` increment the summary verdict
            // (`issues == 0 || (fix && fixed == issues)`) was corrupted in
            // both directions: an unrelated unfixed issue could be masked, and
            // a fully repaired machine could still report failure.
            //
            // `collect_doctor_report` carries the same check (id `grok_hook`)
            // so `--strict` cannot give one answer for `--format json` and a
            // different one here.
            issues += 1;
            if fix {
                println!("  Attempting native install...");
                if install_grok_hook(false, false).is_ok() {
                    println!("  {}", "Fixed!".green());
                    fixed += 1;
                } else {
                    println!("  {}", "Failed to fix".red());
                }
            } else {
                println!("  → Run 'dcg install --grok' to register the native hook");
                println!(
                    "    (or 'dcg install' for the Claude-compat path at {})",
                    claude_compat_path.display()
                );
            }
        }
    }

    // Check 3c: OpenCode plugin registration (#318). Only surfaced when
    // OpenCode is plausibly in use. Unlike Grok, OpenCode has NO Claude
    // compatibility layer: without the native plugin its shell calls never
    // reach dcg, so a missing plugin is an error, not a nudge.
    //
    // `collect_doctor_report` carries the same check (id `opencode_plugin`)
    // so `--strict` and `--format json` agree.
    if opencode_appears_in_use() {
        print!("Checking OpenCode plugin registration... ");
        let plugin_path = opencode_user_plugin_path();
        if opencode_plugin_is_dcg_owned(&plugin_path) {
            println!("{}", "OK".green());
            println!("  Found: {}", plugin_path.display());
        } else {
            println!("{}", "NOT REGISTERED".yellow());
            issues += 1;
            if fix {
                println!("  Attempting plugin install...");
                if install_opencode_plugin(false, false).is_ok() {
                    println!("  {}", "Fixed!".green());
                    fixed += 1;
                } else {
                    println!("  {}", "Failed to fix".red());
                }
            } else {
                println!("  → Run 'dcg install --opencode' to install the native plugin");
                println!("    (OpenCode shell commands are NOT guarded until it is installed)");
            }
        }
    }

    // Check 3d: Oh My Pi extension registration. OMP has no Claude-compatible
    // fallback: without its native ExtensionAPI module, bash calls do not reach
    // dcg at all.
    if omp_appears_in_use() {
        print!("Checking Oh My Pi extension registration... ");
        match registered_omp_extension_path() {
            Ok(Some(extension_path)) => {
                println!("{}", "OK".green());
                println!("  Found: {}", extension_path.display());
            }
            Err(error) => {
                println!("{}", "MISCONFIGURED".red());
                println!("  {error}");
                issues += 1;
                println!(
                    "  → Fix or unset OMP_PROFILE, PI_PROFILE, or PI_CONFIG_DIR, then run \
                     'dcg install --omp'"
                );
            }
            Ok(None) => {
                println!("{}", "NOT REGISTERED".yellow());
                issues += 1;
                if fix {
                    println!("  Attempting extension install...");
                    if install_omp_extension(false, false).is_ok() {
                        println!("  {}", "Fixed!".green());
                        fixed += 1;
                    } else {
                        println!("  {}", "Failed to fix".red());
                    }
                } else {
                    println!("  → Run 'dcg install --omp' to install the native extension");
                    println!("    (OMP bash commands are NOT guarded until it is installed)");
                }
            }
        }
    }

    // Check 3e: Build provenance / update pin (#320). Warning-only: it never
    // increments `issues`, so it cannot fail `--strict` — it flags the state
    // that is one routine `dcg update` away from silently replacing a local
    // build. `collect_doctor_report` carries the same check.
    {
        print!("Checking build provenance... ");
        let (status, message, remediation) = build_provenance_doctor_parts(config);
        match status {
            DoctorCheckStatus::Warning => {
                println!("{}", "WARNING".yellow());
                println!("  {message}");
                if let Some(remediation) = remediation {
                    println!("  → {remediation}");
                }
            }
            _ => {
                println!("{}", "OK".green());
                println!("  {message}");
            }
        }
    }

    // Check 4: Config validation (expanded diagnostics)
    print!("Checking configuration... ");
    let config_diag = validate_config_diagnostics(config, config_sources);

    if config_diag.has_errors() {
        println!("{}", "INVALID".red());
        issues += 1;
        for error in &config_diag.source_errors {
            println!("  {error}");
        }
        println!("  → Repair or unset the rejected/invalid trusted config source");
    } else if config_diag.loaded_sources == 0 {
        println!("{}", "USING DEFAULTS".yellow());
        println!("  No config file was loaded; using built-in defaults plus environment overrides");
        for warning in &config_diag.source_warnings {
            println!("  Warning: {warning}");
        }
        if fix {
            let config_path = config_path();
            if config_path.exists() {
                println!(
                    "  {} exists but wasn't loaded (check permissions/format)",
                    config_path.display()
                );
                issues += 1;
            } else {
                println!("  Creating default user config...");
                if let Some(parent) = config_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                match std::fs::write(&config_path, Config::generate_sample_config()) {
                    Ok(()) => {
                        println!("  {} Created: {}", "Fixed!".green(), config_path.display());
                        // Count the issue this repair resolves — see the
                        // matching comment in `collect_doctor_report`. An
                        // uncounted `fixed` cancels a real unfixed issue in
                        // the `fixed == issues` verdict.
                        issues += 1;
                        fixed += 1;
                    }
                    Err(e) => {
                        // Must count: `collect_doctor_report` counts the same
                        // failure, and --strict now derives the exit status
                        // from this counter. Leaving it uncounted made
                        // `doctor --fix --strict` exit 0 on an unwritable
                        // config dir while `--format json` exited non-zero.
                        issues += 1;
                        println!("  {} Failed to create config: {e}", "Error".red());
                    }
                }
            }
        } else {
            println!("  → Run 'dcg init -o ~/.config/dcg/config.toml' to create one");
        }
    } else if config_diag.has_warnings() {
        println!("{}", "WARNING".yellow());
        for warning in &config_diag.source_warnings {
            println!("  {warning}");
        }
        if !config_diag.unknown_packs.is_empty() {
            println!(
                "  Unknown effective pack IDs: {:?}",
                config_diag.unknown_packs
            );
            println!("  → Run 'dcg packs list' to see available packs");
        }
        if !config_diag.invalid_override_patterns.is_empty() {
            println!("  Invalid effective override patterns:");
            for (pattern, error) in &config_diag.invalid_override_patterns {
                println!("    - \"{pattern}\": {error}");
            }
            println!("  → Fix the regex patterns in the trusted config source");
        }
        if !config_diag.rule_target_exemption_warnings.is_empty() {
            println!("  Inert rule target exemptions:");
            for warning in &config_diag.rule_target_exemption_warnings {
                println!("    - {warning}");
            }
            println!(
                "  → See the \"Per-rule target-path exemptions\" section of the README \
                 for the supported rules"
            );
        }
        if !config_diag.removed_key_warnings.is_empty() {
            println!("  Removed config keys present (not enforced):");
            for warning in &config_diag.removed_key_warnings {
                println!("    - {warning}");
            }
        }
    } else {
        println!(
            "{} ({} file source{})",
            "OK".green(),
            config_diag.loaded_sources,
            if config_diag.loaded_sources == 1 {
                ""
            } else {
                "s"
            }
        );
    }
    for source in config_sources {
        println!(
            "  {}: {}",
            source.layer.label(),
            config_source_summary(source)
        );
    }

    // Check 5: Pattern packs
    print!("Checking pattern packs... ");
    let enabled = config.enabled_pack_ids();
    println!("{} ({} enabled)", "OK".green(), enabled.len());
    println!(
        "  Hook evaluation budget: {} ms ({})",
        config.effective_hook_timeout_ms(),
        config.hook_timeout_source()
    );

    // Check 6: Smoke test
    print!("Running smoke test... ");
    if run_smoke_test(config) {
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
        let summary = if wired_to_an_agent {
            "All checks passed!"
        } else {
            "All checks passed (guard not wired to any agent)"
        };
        println!("{}", summary.green().bold());
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
    issues == 0 || (fix && fixed == issues)
}

const DOCTOR_SCHEMA_VERSION: u32 = 1;

fn doctor_json(fix: bool, config: &Config, config_sources: &[ConfigSourceOutcome]) -> bool {
    let report = collect_doctor_report(fix, config, config_sources);
    let json = serde_json::to_string_pretty(&report).expect("serialize doctor report");
    println!("{json}");
    report.ok
}

/// Rich terminal doctor output using DcgConsole and markup.
#[cfg(feature = "rich-output")]
fn doctor_rich(fix: bool, config: &Config, config_sources: &[ConfigSourceOutcome]) -> bool {
    use crate::output::console::console;

    let report = collect_doctor_report(fix, config, config_sources);
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
        con.print(&format!("[green bold]{}[/]", doctor_pass_summary(&report)));
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
    report.ok
}

/// The pass-line for a clean report.
///
/// `warning`-status checks do not count toward `issues`, so a machine with dcg
/// installed but wired into no agent at all reports `ok: true`. That is
/// defensible — dcg is usable standalone — but a bare "All checks passed!"
/// claims coverage that was never established. Say which of the two it is.
///
/// Only `doctor_rich` consumes this; `doctor_pretty` computes the same
/// distinction from its own inline check state. Gated to match its single
/// caller so a `--no-default-features` build does not see dead code.
#[cfg(feature = "rich-output")]
fn doctor_pass_summary(report: &DoctorReport) -> &'static str {
    let wired = report.checks.iter().all(|check| {
        !(check.id == "claude_settings" && check.status == DoctorCheckStatus::Warning)
    });
    if wired {
        "All checks passed!"
    } else {
        "All checks passed (guard not wired to any agent)"
    }
}

#[allow(clippy::too_many_lines, clippy::option_if_let_else)]
fn collect_doctor_report(
    fix: bool,
    config: &Config,
    config_sources: &[ConfigSourceOutcome],
) -> DoctorReport {
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
    issues += hook_diagnostics_issue_count(&hook_diag);
    let mut hook_fixed = false;
    let hook_repair = if fix
        && hook_diag.settings_exists
        && hook_diag.settings_error.is_none()
        && hook_diag.has_issues()
    {
        Some(install_hook_silent(true))
    } else {
        None
    };
    let (status, message, remediation) = if !hook_diag.settings_exists {
        (
            DoctorCheckStatus::Skipped,
            "No settings file to check".to_string(),
            None,
        )
    } else if let Some(ref err) = hook_diag.settings_error {
        (
            DoctorCheckStatus::Error,
            format!("Settings error: {err}"),
            Some("Fix settings.json or reinstall Claude Code".to_string()),
        )
    } else if let Some(repair) = hook_repair {
        match repair {
            Ok(true) => {
                fixed += 1;
                hook_fixed = true;
                (
                    DoctorCheckStatus::Ok,
                    "Hook repaired with the current absolute dcg executable path".to_string(),
                    None,
                )
            }
            Ok(false) => (
                DoctorCheckStatus::Error,
                "Hook repair made no changes".to_string(),
                Some("Run 'dcg install --force' to replace the hook safely".to_string()),
            ),
            Err(error) => (
                DoctorCheckStatus::Error,
                format!("Failed to repair hook: {error}"),
                Some("Run 'dcg install --force' to replace the hook safely".to_string()),
            ),
        }
    } else if hook_diag.dcg_hook_count == 0 {
        (
            DoctorCheckStatus::Error,
            "dcg hook not registered".to_string(),
            Some("Run 'dcg install' to register the hook".to_string()),
        )
    } else if hook_diag.dcg_hook_count > 1 {
        (
            DoctorCheckStatus::Warning,
            format!(
                "Found {} dcg hook entries (expected 1)",
                hook_diag.dcg_hook_count
            ),
            Some("Run 'dcg install --force' to reconcile duplicates safely".to_string()),
        )
    } else if !hook_diag.wrong_matcher_hooks.is_empty() {
        (
            DoctorCheckStatus::Error,
            format!(
                "Hook registered with wrong matcher: {:?}",
                hook_diag.wrong_matcher_hooks
            ),
            Some(format!(
                "dcg must use matcher {CLAUDE_SHELL_MATCHER}; run 'dcg install --force'"
            )),
        )
    } else if !hook_diag.misconfigured_hooks.is_empty() {
        (
            DoctorCheckStatus::Error,
            format!(
                "Hook cannot synchronously enforce a block: {:?}",
                hook_diag.misconfigured_hooks
            ),
            Some("Run 'dcg install --force' to replace the hook safely".to_string()),
        )
    } else if !hook_diag.missing_executable_hooks.is_empty() {
        (
            DoctorCheckStatus::Error,
            format!(
                "Hook points to missing executable: {:?}",
                hook_diag.missing_executable_hooks
            ),
            Some("Run 'dcg install --force' to replace the broken entry".to_string()),
        )
    } else {
        (
            DoctorCheckStatus::Ok,
            format!(
                "Exactly one dcg hook registered; {} unrelated hook{} preserved",
                hook_diag.other_hooks_count,
                if hook_diag.other_hooks_count == 1 {
                    ""
                } else {
                    "s"
                }
            ),
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
    let config_diag = validate_config_diagnostics(config, config_sources);
    let mut config_fixed = false;
    let source_summary = config_sources
        .iter()
        .map(config_source_diagnostic_message)
        .collect::<Vec<_>>()
        .join("; ");
    let (status, message, remediation) = if config_diag.has_errors() {
        issues += 1;
        (
            DoctorCheckStatus::Error,
            format!(
                "Trusted config source errors: {}. Sources: {source_summary}",
                config_diag.source_errors.join("; ")
            ),
            Some("Repair or unset the rejected/invalid trusted config source".to_string()),
        )
    } else if config_diag.loaded_sources == 0 {
        if fix {
            let cfg_path = config_path();
            if cfg_path.exists() {
                issues += 1;
                (
                    DoctorCheckStatus::Error,
                    format!(
                        "No config file loaded, but {} exists. Sources: {source_summary}",
                        cfg_path.display()
                    ),
                    Some("Check permissions and config syntax".to_string()),
                )
            } else {
                match write_default_config() {
                    Ok(path) => {
                        // Count the issue this repair resolves. The verdict is
                        // `issues == 0 || (fix && fixed == issues)`, so a
                        // `fixed` with no matching `issues` inflates the
                        // counter and lets THIS success cancel a genuinely
                        // unfixed issue elsewhere — `--fix --strict` would exit
                        // 0 on a machine whose hook is still misconfigured.
                        // Only counted under `--fix`; without it, a missing
                        // config stays a Warning, so no new false alarm.
                        issues += 1;
                        fixed += 1;
                        config_fixed = true;
                        (
                            DoctorCheckStatus::Ok,
                            format!(
                                "Created default user config at {}. Previous sources: {source_summary}",
                                path.display()
                            ),
                            None,
                        )
                    }
                    Err(e) => {
                        issues += 1;
                        (
                            DoctorCheckStatus::Error,
                            format!("Failed to create config: {e}. Sources: {source_summary}"),
                            Some("Create config with 'dcg init'".to_string()),
                        )
                    }
                }
            }
        } else {
            (
                DoctorCheckStatus::Warning,
                format!(
                    "No config file loaded; using defaults plus environment overrides. Sources: {source_summary}"
                ),
                Some("Run 'dcg init -o ~/.config/dcg/config.toml'".to_string()),
            )
        }
    } else if config_diag.has_warnings() {
        let mut details = config_diag.source_warnings.clone();
        if !config_diag.unknown_packs.is_empty() {
            details.push(format!(
                "Unknown effective pack IDs: {:?}",
                config_diag.unknown_packs
            ));
        }
        if !config_diag.invalid_override_patterns.is_empty() {
            details.push(format!(
                "Invalid effective override patterns: {}",
                config_diag.invalid_override_patterns.len()
            ));
        }
        details.extend(config_diag.rule_target_exemption_warnings.iter().cloned());
        details.extend(config_diag.removed_key_warnings.iter().cloned());
        (
            DoctorCheckStatus::Warning,
            format!(
                "Configuration warnings: {}. Sources: {source_summary}",
                details.join("; ")
            ),
            Some("Inspect `dcg config` and repair the reported effective source".to_string()),
        )
    } else {
        (
            DoctorCheckStatus::Ok,
            format!(
                "{} config file source{} loaded. Sources: {source_summary}",
                config_diag.loaded_sources,
                if config_diag.loaded_sources == 1 {
                    ""
                } else {
                    "s"
                }
            ),
            None,
        )
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
    let enabled = config.enabled_pack_ids();
    checks.push(DoctorCheck {
        id: "packs",
        name: "Pattern packs",
        status: DoctorCheckStatus::Ok,
        message: format!(
            "{} packs enabled; hook evaluation budget {} ms ({})",
            enabled.len(),
            config.effective_hook_timeout_ms(),
            config.hook_timeout_source()
        ),
        remediation: None,
        fixed: false,
    });

    // Check 6: Smoke test
    if run_smoke_test(config) {
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

    // Check 9: Detected-but-not-enabled packs
    if let Ok(cwd) = std::env::current_dir() {
        let detections = detect_project_packs(&cwd);
        if !detections.is_empty() {
            let not_enabled: Vec<&PackDetection> = detections
                .iter()
                .filter(|d| !enabled.contains(&d.pack_id))
                .collect();

            let (status, message, remediation) = if not_enabled.is_empty() {
                (
                    DoctorCheckStatus::Ok,
                    "All detected project packs are enabled".to_string(),
                    None,
                )
            } else {
                let pack_list: Vec<&str> = not_enabled.iter().map(|d| d.pack_id.as_str()).collect();
                (
                    DoctorCheckStatus::Warning,
                    format!(
                        "Project files suggest packs not currently enabled: {}",
                        pack_list.join(", ")
                    ),
                    Some("Run 'dcg init --auto' to enable detected packs".to_string()),
                )
            };
            checks.push(DoctorCheck {
                id: "auto_detect",
                name: "Project pack detection",
                status,
                message,
                remediation,
                fixed: false,
            });
        }
    }

    // Grok hook registration.
    //
    // This check used to exist only in `doctor_pretty`. That was tolerable
    // while doctor's exit status was always 0, but `--strict` derives the exit
    // status from whichever renderer ran — and the pretty one is what runs in
    // CI, since rich output is disabled without a TTY. Without this, the same
    // machine answered the same question two ways: `dcg doctor --strict`
    // exited 1 while `dcg doctor --strict --format json` exited 0.
    let grok_session_present = std::env::var_os("GROK_SESSION_ID").is_some()
        || std::env::var_os("GROK_HOOK_EVENT").is_some()
        || std::env::var_os("GROK_WORKSPACE_ROOT").is_some();
    let grok_home = dirs::home_dir().map(|h| h.join(".grok"));
    let grok_home_exists = grok_home.as_ref().is_some_and(|p| p.exists() && p.is_dir());
    if grok_session_present || grok_home_exists {
        let user_hook = grok_user_hook_path();
        let claude_compat_exists = claude_settings_path().exists();
        let mut grok_fixed = false;
        let (status, message, remediation) = if user_hook.exists() {
            (
                DoctorCheckStatus::Ok,
                format!("Native Grok hook found at {}", user_hook.display()),
                None,
            )
        } else if claude_compat_exists && hook_diag.dcg_hook_count >= 1 {
            // Wired via the Claude compatibility layer. Deliberately not an
            // error: users who rely on compat should not be pestered.
            (
                DoctorCheckStatus::Ok,
                "No native ~/.grok/hooks/dcg.json; Grok picks up dcg from the Claude \
                 compatibility layer"
                    .to_string(),
                Some("Run 'dcg install --grok' for a native hook".to_string()),
            )
        } else {
            // Grok is in use and the guard is wired NOWHERE for it.
            issues += 1;
            if fix && install_grok_hook(false, false).is_ok() {
                fixed += 1;
                grok_fixed = true;
                (
                    DoctorCheckStatus::Ok,
                    format!("Installed native Grok hook at {}", user_hook.display()),
                    None,
                )
            } else {
                (
                    DoctorCheckStatus::Error,
                    "Grok is in use but dcg is registered neither natively nor via the \
                     Claude compatibility layer"
                        .to_string(),
                    Some("Run 'dcg install --grok'".to_string()),
                )
            }
        };
        checks.push(DoctorCheck {
            id: "grok_hook",
            name: "Grok hook registration",
            status,
            message,
            remediation,
            fixed: grok_fixed,
        });
    }

    // OpenCode plugin registration (#318). Mirrored in `doctor_pretty` — see
    // the renderer-parity note above the Grok block.
    if opencode_appears_in_use() {
        let plugin_path = opencode_user_plugin_path();
        let mut opencode_fixed = false;
        let (status, message, remediation) = if opencode_plugin_is_dcg_owned(&plugin_path) {
            (
                DoctorCheckStatus::Ok,
                format!("Native OpenCode plugin found at {}", plugin_path.display()),
                None,
            )
        } else {
            // OpenCode has no Claude-compatibility fallback: without the
            // plugin, its shell calls never reach dcg at all.
            issues += 1;
            if fix && install_opencode_plugin(false, false).is_ok() {
                fixed += 1;
                opencode_fixed = true;
                (
                    DoctorCheckStatus::Ok,
                    format!(
                        "Installed native OpenCode plugin at {}",
                        plugin_path.display()
                    ),
                    None,
                )
            } else {
                (
                    DoctorCheckStatus::Error,
                    "OpenCode is in use but has no dcg plugin — its shell commands are not \
                     guarded"
                        .to_string(),
                    Some("Run 'dcg install --opencode'".to_string()),
                )
            }
        };
        checks.push(DoctorCheck {
            id: "opencode_plugin",
            name: "OpenCode plugin registration",
            status,
            message,
            remediation,
            fixed: opencode_fixed,
        });
    }

    // Oh My Pi extension registration. Mirrored in `doctor_pretty` so strict,
    // pretty, and JSON doctor output agree.
    if omp_appears_in_use() {
        let mut omp_fixed = false;
        let (status, message, remediation) = match registered_omp_extension_path() {
            Ok(Some(registered_path)) => (
                DoctorCheckStatus::Ok,
                format!(
                    "Native Oh My Pi extension found at {}",
                    registered_path.display()
                ),
                None,
            ),
            Err(error) => {
                issues += 1;
                (
                    DoctorCheckStatus::Error,
                    format!("Cannot resolve the Oh My Pi extension path: {error}"),
                    Some(
                        "Fix or unset OMP_PROFILE, PI_PROFILE, or PI_CONFIG_DIR, then run \
                         'dcg install --omp'"
                            .to_string(),
                    ),
                )
            }
            Ok(None) => {
                issues += 1;
                if fix && install_omp_extension(false, false).is_ok() {
                    fixed += 1;
                    omp_fixed = true;
                    let installed_path = omp_user_extension_path()
                        .expect("OMP extension path validated during installation");
                    (
                        DoctorCheckStatus::Ok,
                        format!(
                            "Installed native Oh My Pi extension at {}",
                            installed_path.display()
                        ),
                        None,
                    )
                } else {
                    (
                        DoctorCheckStatus::Error,
                        "Oh My Pi is in use but has no dcg extension — its bash commands are not \
                     guarded"
                            .to_string(),
                        Some("Run 'dcg install --omp'".to_string()),
                    )
                }
            }
        };
        checks.push(DoctorCheck {
            id: "omp_extension",
            name: "Oh My Pi extension registration",
            status,
            message,
            remediation,
            fixed: omp_fixed,
        });
    }

    // Build provenance vs. `dcg update` (#320). Warning-only: it never fails
    // `--strict`, it flags the state that is one routine `dcg update` away
    // from silently replacing a local build. Mirrored in `doctor_pretty`.
    {
        let (status, message, remediation) = build_provenance_doctor_parts(config);
        checks.push(DoctorCheck {
            id: "build_provenance",
            name: "Build provenance / update pin",
            status,
            message,
            remediation,
            fixed: false,
        });
    }

    DoctorReport {
        schema_version: DOCTOR_SCHEMA_VERSION,
        checks,
        issues,
        fixed,
        ok: issues == 0 || (fix && fixed == issues),
    }
}

const CLAUDE_SHELL_MATCHER: &str = "Bash|PowerShell";
const LEGACY_CLAUDE_SHELL_MATCHER: &str = "Bash";
const ANTIGRAVITY_SHELL_MATCHER: &str = "Bash";

fn current_dcg_executable() -> std::io::Result<std::path::PathBuf> {
    let executable = std::env::current_exe().map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("could not resolve the running dcg executable: {error}"),
        )
    })?;
    if !executable.is_absolute() {
        return Err(std::io::Error::other(format!(
            "running dcg executable path is not absolute: {}",
            executable.display()
        )));
    }
    if !executable.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "running dcg executable path is not a regular file: {}",
                executable.display()
            ),
        ));
    }
    Ok(executable)
}

#[cfg(unix)]
fn posix_quote_hook_program(program: &str) -> String {
    if program.chars().all(|character| {
        character.is_ascii_alphanumeric()
            || matches!(
                character,
                '/' | '_' | '-' | '.' | ':' | '+' | ',' | '@' | '%'
            )
    }) {
        return program.to_string();
    }

    let mut quoted = String::with_capacity(program.len() + 2);
    quoted.push('"');
    for character in program.chars() {
        if matches!(character, '\\' | '"' | '$' | '`') {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    quoted.push('"');
    quoted
}

fn claude_dcg_hook_for_executable(
    executable: &std::path::Path,
) -> std::io::Result<serde_json::Value> {
    let command = hook_command_for_executable(executable)?;

    #[cfg(windows)]
    {
        Ok(serde_json::json!({
            "type": "command",
            "command": command,
            "shell": "powershell"
        }))
    }

    #[cfg(not(windows))]
    {
        Ok(serde_json::json!({
            "type": "command",
            "command": command
        }))
    }
}

fn hook_command_for_executable(executable: &std::path::Path) -> std::io::Result<String> {
    if !executable.is_absolute() {
        return Err(std::io::Error::other(format!(
            "dcg hook executable path is not absolute: {}",
            executable.display()
        )));
    }
    let executable = executable.to_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "dcg hook executable path is not valid UTF-8: {}",
                executable.display()
            ),
        )
    })?;

    #[cfg(windows)]
    {
        let escaped = executable.replace('\'', "''");
        Ok(format!("& '{escaped}'"))
    }

    #[cfg(not(windows))]
    {
        Ok(posix_quote_hook_program(executable))
    }
}

fn claude_dcg_hook() -> std::io::Result<serde_json::Value> {
    claude_dcg_hook_for_executable(&current_dcg_executable()?)
}

fn antigravity_dcg_hook() -> std::io::Result<serde_json::Value> {
    claude_dcg_hook_for_executable(&current_dcg_executable()?)
}

fn quoted_hook_program(command: &str) -> Option<String> {
    let quote = command.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"') {
        return None;
    }
    let mut program = String::new();
    let mut index = 1usize;
    while index < command.len() {
        let character = command[index..].chars().next()?;
        if character as u32 == u32::from(quote) {
            if quote == b'\'' && command.as_bytes().get(index + 1) == Some(&b'\'') {
                program.push('\'');
                index += 2;
                continue;
            }
            return Some(program);
        }
        if quote == b'"' && character == '`' {
            index += 1;
            let escaped = command[index..].chars().next()?;
            program.push(escaped);
            index += escaped.len_utf8();
            continue;
        }
        if quote == b'"' && character == '\\' {
            let next_index = index + character.len_utf8();
            let Some(escaped) = command[next_index..].chars().next() else {
                program.push(character);
                break;
            };
            if matches!(escaped, '\\' | '"' | '$' | '`') {
                program.push(escaped);
                index = next_index + escaped.len_utf8();
                continue;
            }
        }
        program.push(character);
        index += character.len_utf8();
    }
    None
}

fn command_token_looks_like_path(token: &str) -> bool {
    token.starts_with(['/', '\\'])
        || token.as_bytes().get(1).is_some_and(|byte| *byte == b':')
        || token.contains(['/', '\\'])
}

fn is_dcg_program_basename(program: &str) -> bool {
    let basename = program.rsplit(['/', '\\']).next().unwrap_or(program);
    let stem = basename
        .get(..basename.len().saturating_sub(4))
        .filter(|_| {
            basename
                .get(basename.len().saturating_sub(4)..)
                .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".exe"))
        })
        .unwrap_or(basename);
    stem.eq_ignore_ascii_case("dcg")
        || (std::path::Path::new(program).is_absolute()
            && std::env::current_exe()
                .ok()
                .is_some_and(|current| current == std::path::Path::new(program)))
}

fn dcg_command_program(cmd: &str) -> Option<String> {
    // Recognize whether a hook entry's `command` belongs to dcg. This must be
    // path-separator- and extension-agnostic so it works on Windows, where the
    // Grok/agy installers write the full `current_exe()` path — e.g.
    // `C:\Users\me\.local\bin\dcg.exe` (backslashes + `.exe`), optionally quoted
    // and followed by arguments. Mirrors install.ps1's `Get-DcgCommandName`
    // (quote-stripping + last path segment + case-insensitive compare) so the
    // install-side and runtime-side agree.
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Native-Windows Claude hooks invoke an absolute dcg path through
    // PowerShell's call operator so paths containing spaces remain executable:
    // `& 'C:\Users\Jane Doe\.local\bin\dcg.exe'`. Strip only that leading
    // operator before applying the ordinary program-token parser.
    let trimmed = trimmed
        .strip_prefix('&')
        .map_or(trimmed, |rest| rest.trim_start());

    // Extract the program token: a leading quoted path (`"…dcg.exe" --flag`) or
    // the first whitespace-delimited token of an unquoted command.
    if matches!(trimmed.as_bytes().first(), Some(b'\'' | b'"')) {
        let program = quoted_hook_program(trimmed)?;
        return is_dcg_program_basename(&program).then_some(program);
    }

    let first = trimmed.split_whitespace().next().unwrap_or(trimmed);
    if command_token_looks_like_path(first) {
        let leaf_start = trimmed
            .rfind(['/', '\\'])
            .map_or(0, |separator| separator + 1);
        let leaf = &trimmed[leaf_start..];
        let leaf_program = leaf.split_whitespace().next().unwrap_or(leaf);
        if is_dcg_program_basename(leaf_program) {
            let prefix = &trimmed[..leaf_start];
            let has_prior_executable = prefix.split_whitespace().any(|token| {
                let normalized = token.trim_matches(['\'', '"']).to_ascii_lowercase();
                [".exe", ".cmd", ".bat", ".ps1"]
                    .iter()
                    .any(|extension| normalized.ends_with(extension))
            });
            if !has_prior_executable {
                let end = leaf_start + leaf_program.len();
                return Some(trimmed[..end].to_string());
            }
        }
    }

    is_dcg_program_basename(first).then(|| first.to_string())
}

fn is_dcg_command(cmd: &str) -> bool {
    dcg_command_program(cmd).is_some()
}

/// Detect a hook executable path that is well-formed for the *other*
/// platform (#264): a `C:\…\dcg.exe`-style path on a Unix host, or a
/// `/home/…/dcg`-style path on native Windows. This happens when an
/// agent-settings manager (cc-switch and similar) re-materializes a
/// `settings.json` cached on a different OS; naming the likely cause keeps
/// users from debugging the wrong layer, and warns that fixing only
/// `settings.json` gets overwritten on the manager's next sync.
fn foreign_platform_hook_path(program: &str) -> Option<&'static str> {
    let bytes = program.as_bytes();
    let has_drive_prefix = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/');
    let looks_windows = has_drive_prefix
        || program.contains('\\')
        || std::path::Path::new(program)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"));
    if cfg!(windows) {
        (program.starts_with('/') && !looks_windows).then_some(
            "the hook points at a Unix-style dcg path on a Windows host — an \
             agent-settings manager (e.g. cc-switch) likely restored a settings.json \
             cached on another OS; fix the manager's stored value first (or it will \
             reinstate the stale path on its next sync), then run 'dcg install --force'",
        )
    } else {
        looks_windows.then_some(
            "the hook points at a Windows-style dcg.exe path on a Unix host — an \
             agent-settings manager (e.g. cc-switch) likely restored a settings.json \
             cached on another OS; fix the manager's stored value first (or it will \
             reinstate the stale path on its next sync), then run 'dcg install --force'",
        )
    }
}

#[cfg(test)]
fn is_dcg_hook_entry(entry: &serde_json::Value) -> bool {
    is_dcg_hook_entry_for_matcher(entry, CLAUDE_SHELL_MATCHER)
}

#[cfg(test)]
fn is_dcg_hook_entry_for_matcher(entry: &serde_json::Value, matcher: &str) -> bool {
    entry
        .get("matcher")
        .and_then(|m| m.as_str())
        .is_some_and(|m| m == matcher)
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

fn is_exact_hook_entry_for_matcher(
    entry: &serde_json::Value,
    matcher: &str,
    desired_hook: &serde_json::Value,
) -> bool {
    entry
        .get("matcher")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|entry_matcher| entry_matcher == matcher)
        && entry
            .get("hooks")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|hooks| hooks.iter().any(|hook| hook == desired_hook))
}

fn remove_dcg_hooks_from_pre_tool_use(pre_tool_use: &mut Vec<serde_json::Value>) -> bool {
    let mut removed = false;
    let mut retained_entries = Vec::with_capacity(pre_tool_use.len());

    for mut entry in std::mem::take(pre_tool_use) {
        let drop_entry = if let Some(hooks) = entry.get_mut("hooks").and_then(|h| h.as_array_mut())
        {
            let before = hooks.len();
            hooks.retain(|hook| {
                !hook
                    .get("command")
                    .and_then(|c| c.as_str())
                    .is_some_and(is_dcg_command)
            });
            let entry_removed = hooks.len() < before;
            removed |= entry_removed;
            entry_removed && hooks.is_empty()
        } else {
            false
        };

        if !drop_entry {
            retained_entries.push(entry);
        }
    }

    *pre_tool_use = retained_entries;
    removed
}

fn install_dcg_hook_for_matcher(
    settings: &mut serde_json::Value,
    force: bool,
    matcher: &str,
    legacy_matchers: &[&str],
    desired_hook: serde_json::Value,
) -> Result<bool, Box<dyn std::error::Error>> {
    let hook_config = serde_json::json!({
        "matcher": matcher,
        "hooks": []
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

    let original = pre_tool_use.clone();
    let mut canonical_entry = None;
    let mut retained_entries = Vec::with_capacity(original.len());

    for mut entry in original {
        let entry_matcher = entry
            .get("matcher")
            .and_then(|value| value.as_str())
            .map(str::to_owned);
        let is_canonical_entry = entry_matcher.as_deref() == Some(matcher);

        if is_canonical_entry {
            let Some(entry_hooks) = entry
                .get_mut("hooks")
                .and_then(|value| value.as_array_mut())
            else {
                return Err(format!(
                    "Invalid {matcher} matcher hooks format (expected JSON array)"
                )
                .into());
            };
            let original_len = entry_hooks.len();
            entry_hooks.retain(|hook| {
                !hook
                    .get("command")
                    .and_then(|command| command.as_str())
                    .is_some_and(is_dcg_command)
            });
            let keep_duplicate = entry_hooks.len() == original_len || !entry_hooks.is_empty();

            if canonical_entry.is_none() {
                canonical_entry = Some(entry);
            } else if keep_duplicate {
                retained_entries.push(entry);
            }
            continue;
        }

        let is_legacy_entry =
            legacy_matchers.contains(&entry_matcher.as_deref().unwrap_or_default());
        let drop_entry = match entry.get_mut("hooks") {
            None | Some(serde_json::Value::Null) => false,
            Some(value) => match value.as_array_mut() {
                None if is_legacy_entry => {
                    return Err(format!(
                        "Invalid legacy {} matcher hooks format (expected JSON array)",
                        entry_matcher.as_deref().unwrap_or_default()
                    )
                    .into());
                }
                None => false,
                Some(entry_hooks) => {
                    let original_len = entry_hooks.len();
                    entry_hooks.retain(|hook| {
                        !hook
                            .get("command")
                            .and_then(|command| command.as_str())
                            .is_some_and(is_dcg_command)
                    });
                    entry_hooks.len() < original_len && entry_hooks.is_empty()
                }
            },
        };

        if !drop_entry {
            retained_entries.push(entry);
        }
    }

    let mut canonical_entry = canonical_entry.unwrap_or(hook_config);
    canonical_entry["hooks"]
        .as_array_mut()
        .expect("validated canonical entry always contains a hooks array")
        .insert(0, desired_hook);
    retained_entries.insert(0, canonical_entry);

    let changed = force || *pre_tool_use != retained_entries;
    if changed {
        *pre_tool_use = retained_entries;
    }
    Ok(changed)
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
    let desired_hook = claude_dcg_hook()?;
    install_dcg_hook_for_matcher(
        settings,
        force,
        CLAUDE_SHELL_MATCHER,
        &[LEGACY_CLAUDE_SHELL_MATCHER],
        desired_hook,
    )
}

fn install_antigravity_hook_into_settings(
    settings: &mut serde_json::Value,
    force: bool,
) -> Result<bool, Box<dyn std::error::Error>> {
    let desired_hook = antigravity_dcg_hook()?;
    install_dcg_hook_for_matcher(
        settings,
        force,
        ANTIGRAVITY_SHELL_MATCHER,
        &[],
        desired_hook,
    )
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

    Ok(remove_dcg_hooks_from_pre_tool_use(arr))
}

/// Install the dcg hook entry into Claude Code settings.
///
/// When `project` is `true`, writes to `.claude/settings.json` inside the
/// current git repository root instead of the user-level
/// `~/.claude/settings.json`.
///
/// This is a wrapper around `install_dcg_hook_into_settings` that handles the
/// file I/O and error reporting.
///
/// # Errors
///
/// Returns an error if the settings file cannot be read, parsed, or written.
fn install_hook(force: bool, project: bool) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let settings_path = if project {
        project_claude_settings_path()?
    } else {
        claude_settings_path()
    };

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

    let level = if project { "project" } else { "user" };
    println!("{}", "Hook installed successfully!".green().bold());
    println!("Settings updated ({level}): {}", settings_path.display());
    println!();
    println!(
        "{}",
        "Restart Claude Code for the changes to take effect.".yellow()
    );

    Ok(())
}

/// Build the JSON body for a Grok `~/.grok/hooks/dcg.json` hook file.
///
/// Resolves the dcg binary path via `current_exe()` so the installed hook
/// always points at the same executable that was used to install it
/// (matching Claude's installer behavior). Resolution errors are fatal rather
/// than falling back to PATH, because agent hook environments do not reliably
/// inherit interactive-shell PATH entries.
///
/// The `matcher: "Bash"` field uses Grok's documented Claude-compat alias
/// which Grok internally rewrites to `run_terminal_cmd` before dispatching.
/// Timeout matches dcg's hook fast-path budget (well under 5s in practice).
fn build_grok_hook_config() -> std::io::Result<serde_json::Value> {
    let executable = current_dcg_executable()?;
    let dcg_cmd = hook_command_for_executable(&executable)?;

    Ok(serde_json::json!({
        "description": "dcg (Destructive Command Guard) — blocks rm -rf, git reset --hard, force pushes, DROP DATABASE, kubectl delete, and similar destructive commands before Grok's run_terminal_cmd tool can execute them.",
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": dcg_cmd,
                            "timeout": 5
                        }
                    ]
                }
            ]
        }
    }))
}

/// Install the dcg hook into Grok's hook directory.
///
/// Writes a self-contained `dcg.json` to `~/.grok/hooks/` (user-level) or
/// `<repo>/.grok/hooks/` (with `--project`). Grok auto-discovers every
/// `*.json` in those directories and merges them at session start, so we
/// don't touch `user-settings.json` or `settings.json`.
///
/// Returns `Err` if the file cannot be written or, for project installs, if
/// the current directory is not inside a git repository.
fn install_grok_hook(force: bool, project: bool) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let hook_path = if project {
        project_grok_hook_path()?
    } else {
        grok_user_hook_path()
    };

    if hook_path.exists() && !force {
        println!(
            "{} Grok hook already exists at {}",
            "Hook already installed!".yellow(),
            hook_path.display()
        );
        println!("Use --force to reinstall");
        return Ok(());
    }

    if let Some(parent) = hook_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let body = build_grok_hook_config()?;
    let content = serde_json::to_string_pretty(&body)?;
    std::fs::write(&hook_path, content)?;

    let level = if project { "project" } else { "user" };
    println!("{}", "Grok hook installed successfully!".green().bold());
    println!("Hook file written ({level}): {}", hook_path.display());
    println!();
    if project {
        println!(
            "{}",
            "Project hooks require explicit trust the first time Grok opens this repo —".yellow()
        );
        println!(
            "{}",
            "open the hooks modal in Grok (Ctrl+L) and accept, or run /hooks-trust.".yellow()
        );
    } else {
        println!(
            "{}",
            "Restart Grok (or press 'l' in the hooks modal) for the change to take effect."
                .yellow()
        );
    }

    Ok(())
}

/// Install the dcg hook into the Antigravity CLI (`agy`) hooks config.
///
/// `agy` reads Claude-Code-compatible `PreToolUse` hooks from
/// `~/.gemini/config/hooks.json` (canonical post-migration path; the legacy
/// `~/.gemini/antigravity-cli/hooks.json` is symlinked to it). The file uses
/// the same `{"hooks":{"PreToolUse":[{"matcher":...,"hooks":[{"type":
/// "command","command":"/absolute/path/to/dcg"}]}]}}` shape as Claude's
/// `settings.json`, while retaining agy's Bash-only matcher. When dcg returns a block decision
/// (stdout `{"decision":"block",...}`), `agy` aborts its `run_command` tool.
///
/// With `--project`, writes to `<repo>/.gemini/config/hooks.json` instead.
///
/// Returns `Err` if the file cannot be read/written or, for project installs,
/// if the current directory is not inside a git repository.
fn install_antigravity_hook(force: bool, project: bool) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let hooks_path = if project {
        project_antigravity_hooks_path()?
    } else {
        antigravity_hooks_path()
    };

    // `agy` migrates ~/.gemini/antigravity-cli/hooks.json to
    // ~/.gemini/config/hooks.json and leaves a symlink at the old path. If the
    // canonical file is itself a symlink (or the old path exists as a real
    // file), prefer editing the real target so we don't clobber the symlink.
    let mut settings: serde_json::Value = if hooks_path.exists() {
        let content = std::fs::read_to_string(&hooks_path)?;
        if content.trim().is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_str(&content)?
        }
    } else {
        if let Some(parent) = hooks_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        serde_json::json!({})
    };

    let changed = install_antigravity_hook_into_settings(&mut settings, force)?;
    if !changed {
        println!("{}", "Hook already installed!".yellow());
        println!("Use --force to reinstall");
        return Ok(());
    }

    let content = serde_json::to_string_pretty(&settings)?;
    std::fs::write(&hooks_path, content)?;

    let level = if project { "project" } else { "user" };
    println!(
        "{}",
        "Antigravity (agy) hook installed successfully!"
            .green()
            .bold()
    );
    println!("Hooks file updated ({level}): {}", hooks_path.display());
    println!();
    println!(
        "{}",
        "Restart agy (start a new session) for the change to take effect.".yellow()
    );

    Ok(())
}

/// Path to the user-level Antigravity (`agy`) hooks file
/// (`~/.gemini/config/hooks.json`).
///
/// This is the canonical post-migration path: `agy` migrates
/// `~/.gemini/antigravity-cli/hooks.json` here on first run and symlinks the
/// old path to it. Both paths resolve to this file, so editing it is correct
/// regardless of which one `agy` was last run with.
fn antigravity_hooks_path() -> std::path::PathBuf {
    dirs::home_dir()
        .unwrap_or_default()
        .join(".gemini")
        .join("config")
        .join("hooks.json")
}

/// Path to a project-level Antigravity (`agy`) hooks file
/// (`<repo>/.gemini/config/hooks.json`).
///
/// Returns `Err` if the current directory is not inside a git repository.
fn project_antigravity_hooks_path() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let repo_root = find_repo_root_from_cwd()
        .ok_or("Not inside a git repository — cannot determine project root")?;
    Ok(repo_root.join(".gemini").join("config").join("hooks.json"))
}

/// Ownership marker embedded in the generated OpenCode plugin (#318).
///
/// The installer refuses to overwrite a plugin file that lacks this marker
/// (it belongs to the user, not dcg), and the uninstallers delete only files
/// that carry it.
pub(crate) const OPENCODE_PLUGIN_MARKER: &str = "dcg-opencode-plugin";

/// User-level OpenCode plugin path: `~/.config/opencode/plugins/dcg-guard.js`
/// (OpenCode reads its global config from `$XDG_CONFIG_HOME/opencode`,
/// falling back to `~/.config/opencode`, on every platform).
fn opencode_user_plugin_path() -> std::path::PathBuf {
    let config_root = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map_or_else(
            || dirs::home_dir().unwrap_or_default().join(".config"),
            std::path::PathBuf::from,
        );
    config_root
        .join("opencode")
        .join("plugins")
        .join("dcg-guard.js")
}

/// Project-level OpenCode plugin path: `<repo>/.opencode/plugins/dcg-guard.js`.
fn project_opencode_plugin_path() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let repo_root = find_repo_root_from_cwd()
        .ok_or("Not inside a git repository — cannot determine project root")?;
    Ok(repo_root
        .join(".opencode")
        .join("plugins")
        .join("dcg-guard.js"))
}

/// Generate the OpenCode `tool.execute.before` plugin source (#318).
///
/// The plugin routes every OpenCode `bash` tool call through dcg's
/// Claude-compatible hook protocol: an empty stdout means allow; a
/// `hookSpecificOutput.permissionDecision` of `deny` (or `ask`, since
/// OpenCode has no operator-review state) aborts the tool call by throwing,
/// which is OpenCode's documented veto mechanism. Infrastructure failures
/// (dcg missing/unrunnable) fail open with a stderr notice, matching the
/// hook-envelope failure policy; the *evaluation* itself stays fail-closed
/// inside dcg.
///
/// The dcg binary path is embedded as a JSON string literal (valid JSON
/// strings are valid JS string literals), NOT shell-quoted — the plugin
/// spawns dcg directly without a shell.
fn executable_javascript_literal(executable: &std::path::Path) -> std::io::Result<String> {
    let path = executable.to_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "dcg executable path is not valid UTF-8 and cannot be embedded in JavaScript",
        )
    })?;
    serde_json::to_string(path)
        .map_err(|e| std::io::Error::other(format!("cannot encode dcg path as a JS literal: {e}")))
}

fn build_opencode_plugin_source(executable: &std::path::Path) -> std::io::Result<String> {
    let path_literal = executable_javascript_literal(executable)?;
    Ok(format!(
        r#"// {OPENCODE_PLUGIN_MARKER}: generated by `dcg install --opencode` — do not edit.
// Routes every OpenCode bash tool call through dcg (Destructive Command
// Guard) before execution. Remove with `uninstall.sh` or by deleting this
// file. Docs: https://github.com/Dicklesworthstone/destructive_command_guard
const DCG_BIN = {path_literal};

export const DcgGuard = async () => {{
  return {{
    "tool.execute.before": async (input, output) => {{
      if (!input || input.tool !== "bash") return;
      const command = output?.args?.command;
      if (typeof command !== "string" || command.length === 0) return;

      let stdoutText;
      try {{
        const proc = Bun.spawn([process.env.DCG_BIN || DCG_BIN], {{
          stdin: new TextEncoder().encode(
            JSON.stringify({{ tool_name: "Bash", tool_input: {{ command }} }})
          ),
          stdout: "pipe",
          stderr: "ignore",
          env: {{ ...process.env, OPENCODE: "1" }},
        }});
        stdoutText = await new Response(proc.stdout).text();
        await proc.exited;
      }} catch (err) {{
        // dcg missing or unrunnable is an infrastructure failure, not a
        // safety verdict: fail open, but say so.
        console.error(`[dcg] OpenCode guard could not run dcg: ${{err}}`);
        return;
      }}

      const text = (stdoutText || "").trim();
      if (!text) return; // empty stdout = allow

      let decision;
      try {{
        decision = JSON.parse(text);
      }} catch {{
        return; // non-JSON stdout: treat as allow (matches other harnesses)
      }}
      const hso = decision.hookSpecificOutput;
      const verdict = hso && hso.permissionDecision;
      if (verdict === "deny" || verdict === "ask") {{
        // OpenCode has no operator-review state, so `ask` fails closed.
        throw new Error(hso.permissionDecisionReason || "Blocked by dcg");
      }}
    }},
  }};
}};
"#
    ))
}

/// Whether this machine appears to run OpenCode: its config directory
/// exists, an `OPENCODE*` env var is present, or the current session was
/// spawned by it. Used to gate the doctor check so machines without OpenCode
/// are not pestered.
fn opencode_appears_in_use() -> bool {
    if std::env::vars_os().any(|(k, _)| k.to_string_lossy().starts_with("OPENCODE")) {
        return true;
    }
    opencode_user_plugin_path()
        .parent()
        .and_then(std::path::Path::parent)
        .is_some_and(std::path::Path::is_dir)
}

/// Whether `path` holds a dcg-generated OpenCode plugin.
fn opencode_plugin_is_dcg_owned(path: &std::path::Path) -> bool {
    std::fs::read_to_string(path)
        .map(|content| content.contains(OPENCODE_PLUGIN_MARKER))
        .unwrap_or(false)
}

/// Ownership marker embedded in the generated Oh My Pi extension.
///
/// Installation refuses to overwrite a file without this marker, and the
/// uninstallers use it to distinguish dcg-owned output from user code.
pub(crate) const OMP_EXTENSION_MARKER: &str = "dcg-omp-extension";

/// Normalize a profile name using the upstream OMP profile-name contract.
/// Empty, whitespace-only, and `default` select the default profile. Invalid
/// explicit values are errors: OMP's module-load fallback is only a bootstrap
/// detail, and its CLI re-validates the environment and refuses startup before
/// writing profile state.
fn normalize_omp_profile_name(profile: &str) -> std::io::Result<Option<String>> {
    let name = profile.trim();
    if name.is_empty() || name == "default" {
        return Ok(None);
    }
    if name == "." || name == ".." || name.ends_with('.') || name.len() > 64 {
        return Err(invalid_omp_profile_error(profile));
    }

    let mut chars = name.chars();
    if !chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c))
    {
        return Err(invalid_omp_profile_error(profile));
    }

    let base = name.split('.').next().unwrap_or(name);
    let upper = base.to_ascii_uppercase();
    let reserved = matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (upper.len() == 4
            && (upper.starts_with("COM") || upper.starts_with("LPT"))
            && upper.as_bytes()[3].is_ascii_digit());
    if reserved {
        return Err(invalid_omp_profile_error(profile));
    }
    Ok(Some(name.to_string()))
}

fn invalid_omp_profile_error(profile: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "Invalid OMP profile {profile:?}. Profile names must match \
             ^[a-z0-9][a-z0-9._-]{{0,63}}$, cannot be '.' or '..', cannot end with '.', \
             and cannot be a Windows reserved device name (CON, PRN, AUX, NUL, COM0-9, \
             LPT0-9, or any of those with an extension)"
        ),
    )
}

/// Observable state of one OMP profile environment variable. Keeping absence
/// distinct from an explicit default selection is what preserves the
/// `OMP_PROFILE`-over-`PI_PROFILE` precedence rule.
enum OmpProfileEnvValue {
    Absent,
    Default,
    Named(String),
}

fn omp_profile_env_value(variable: &'static str) -> std::io::Result<OmpProfileEnvValue> {
    match std::env::var(variable) {
        Ok(profile) => normalize_omp_profile_name(&profile)
            .map(|profile| profile.map_or(OmpProfileEnvValue::Default, OmpProfileEnvValue::Named))
            .map_err(|error| std::io::Error::new(error.kind(), format!("{variable}: {error}"))),
        Err(std::env::VarError::NotPresent) => Ok(OmpProfileEnvValue::Absent),
        Err(std::env::VarError::NotUnicode(_)) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{variable} must contain valid Unicode; OMP rejects non-Unicode profile values"
            ),
        )),
    }
}

/// Resolve OMP's active named profile. `OMP_PROFILE` takes precedence whenever
/// it is set, including when it is explicitly empty; `PI_PROFILE` is the
/// legacy fallback used only when `OMP_PROFILE` is absent.
fn omp_active_profile() -> std::io::Result<Option<String>> {
    match omp_profile_env_value("OMP_PROFILE")? {
        OmpProfileEnvValue::Named(profile) => Ok(Some(profile)),
        OmpProfileEnvValue::Default => Ok(None),
        OmpProfileEnvValue::Absent => match omp_profile_env_value("PI_PROFILE")? {
            OmpProfileEnvValue::Named(profile) => Ok(Some(profile)),
            OmpProfileEnvValue::Absent | OmpProfileEnvValue::Default => Ok(None),
        },
    }
}

/// Resolve OMP's config root without allowing Rust's Windows path semantics to
/// turn a drive-qualified config *name* into a path outside `home`.
///
/// Upstream passes `PI_CONFIG_DIR` to Node's `path.join(home, name)`. On
/// Windows, a value such as `C:\\omp` becomes an invalid child beneath `home`;
/// Rust's `Path::join` would instead replace `home` and target `C:\\omp`.
/// Reject that malformed Windows-only value so dcg never writes somewhere OMP
/// itself would not load from.
fn omp_config_root_from(
    home: &std::path::Path,
    config_name: &str,
    windows_semantics: bool,
) -> std::io::Result<std::path::PathBuf> {
    let relative = config_name.trim_start_matches(['/', '\\']);
    let bytes = relative.as_bytes();
    let drive_qualified = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if windows_semantics && drive_qualified {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "PI_CONFIG_DIR must be a directory name relative to HOME on Windows, not \
                 drive-qualified path {config_name:?}"
            ),
        ));
    }
    Ok(home.join(relative))
}

/// OMP's active user agent directory. The default is `~/.omp/agent`; named
/// profiles live under `~/.omp/profiles/<name>/agent`. OMP ignores the legacy
/// `PI_CODING_AGENT_DIR` override when a named profile is active, so dcg does
/// the same.
fn omp_user_agent_dir() -> std::io::Result<std::path::PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "could not determine the home directory for Oh My Pi",
        )
    })?;
    let config_name = match std::env::var("PI_CONFIG_DIR") {
        Ok(value) if !value.is_empty() => value,
        Ok(_) | Err(std::env::VarError::NotPresent) => ".omp".to_string(),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "PI_CONFIG_DIR must contain valid Unicode",
            ));
        }
    };
    let config_root = omp_config_root_from(&home, &config_name, cfg!(windows))?;

    if let Some(profile) = omp_active_profile()? {
        return Ok(config_root.join("profiles").join(profile).join("agent"));
    }

    Ok(std::env::var_os("PI_CODING_AGENT_DIR")
        .filter(|value| !value.is_empty())
        .map_or_else(|| config_root.join("agent"), std::path::PathBuf::from))
}

/// User-level OMP extension path for the active profile.
fn omp_user_extension_path() -> std::io::Result<std::path::PathBuf> {
    Ok(omp_user_agent_dir()?
        .join("extensions")
        .join("dcg-guard.ts"))
}

/// Project-level OMP extension path: `<cwd>/.omp/extensions/dcg-guard.ts`.
///
/// Unlike some of OMP's context-file providers, native extension discovery is
/// anchored to the process working directory and never walks Git ancestors.
/// Keep this resolver equally literal so an installed guard is one OMP will
/// actually load, including when the cwd is not inside a Git repository.
fn project_omp_extension_path() -> std::io::Result<std::path::PathBuf> {
    Ok(std::env::current_dir()?
        .join(".omp")
        .join("extensions")
        .join("dcg-guard.ts"))
}

/// Generate an OMP ExtensionAPI module that gates every `bash` tool call on
/// dcg's robot-mode evaluator. The command is sent on stdin and dcg is spawned
/// directly (never through a shell). A deny-like JSON verdict or exit 1 is a
/// safety block; status-only infrastructure failures fail open with a visible
/// diagnostic, consistent with dcg's other generated integration bridges.
fn build_omp_extension_source(executable: &std::path::Path) -> std::io::Result<String> {
    let path_literal = executable_javascript_literal(executable)?;
    Ok(format!(
        r#"// {OMP_EXTENSION_MARKER}: generated by `dcg install --omp` — do not edit.
// Routes every Oh My Pi bash tool call through dcg (Destructive Command Guard)
// before execution. Docs: https://github.com/Dicklesworthstone/destructive_command_guard
import type {{ ExtensionAPI }} from "@oh-my-pi/pi-coding-agent";
import {{ settings }} from "@oh-my-pi/pi-coding-agent/config/settings";
import {{ procmgr }} from "@oh-my-pi/pi-utils";
import {{ resolveToCwd }} from "@oh-my-pi/pi-coding-agent/tools/path-utils";
import {{ extractLeadingCdTarget }} from "@oh-my-pi/pi-coding-agent/tools/shell-tokenize";

const DCG_BIN = {path_literal};
type DcgChildOutcome = "spawn-throw" | "exit-0" | "exit-1" | "exit-2" | "exit-other";
type DcgParsedVerdict = "empty" | "malformed" | "allow" | "deny" | "ask" | "indeterminate" | "unknown";
type DcgBridgeAction = "allow" | "block" | "infrastructure";
type DcgParsedOutput = {{ verdict: DcgParsedVerdict; reason?: string; ruleId?: string }};
type OmpBashToolInput = {{ command?: unknown; cwd?: unknown; async?: unknown; pty?: unknown }};
type OmpToolCallClassification =
  | {{ kind: "other-tool" }}
  | {{ kind: "invalid-bash" }}
  | {{ kind: "bash"; input: OmpBashToolInput; command: string }};

const BLOCKING_DECISIONS: ReadonlySet<DcgParsedVerdict> = new Set<DcgParsedVerdict>(["deny", "ask", "indeterminate"]);
// Bun exposes no stdout when spawn itself throws. That runtime catch remains a
// visible infrastructure fail-open; this total row makes the pure classifier
// exhaustive for replay/model tests and preserves deny-like monotonicity.
const DCG_CHILD_TRANSITIONS: Record<DcgChildOutcome, Record<DcgParsedVerdict, DcgBridgeAction>> = {{
  "spawn-throw": {{ empty: "infrastructure", malformed: "infrastructure", allow: "infrastructure", deny: "block", ask: "block", indeterminate: "block", unknown: "infrastructure" }},
  "exit-0": {{ empty: "allow", malformed: "allow", allow: "allow", deny: "block", ask: "block", indeterminate: "block", unknown: "allow" }},
  "exit-1": {{ empty: "block", malformed: "block", allow: "block", deny: "block", ask: "block", indeterminate: "block", unknown: "block" }},
  "exit-2": {{ empty: "allow", malformed: "allow", allow: "allow", deny: "block", ask: "block", indeterminate: "block", unknown: "allow" }},
  "exit-other": {{ empty: "infrastructure", malformed: "infrastructure", allow: "infrastructure", deny: "block", ask: "block", indeterminate: "block", unknown: "infrastructure" }},
}};

// OMP's agent loop schema-validates built-in bash arguments before emitting
// tool_call, but direct/non-loop wrapper dispatch is also public. Preserve the
// exact tool-name boundary and fail closed only when an identifiable bash call
// violates the required object-with-string-command shape.
export function classifyOmpToolCall(event: unknown): OmpToolCallClassification {{
  if (typeof event !== "object" || event === null || Array.isArray(event)) return {{ kind: "other-tool" }};
  const record = event as Record<string, unknown>;
  if (record.toolName !== "bash") return {{ kind: "other-tool" }};
  const input = record.input;
  if (typeof input !== "object" || input === null || Array.isArray(input)) return {{ kind: "invalid-bash" }};
  const toolInput = input as OmpBashToolInput;
  if (typeof toolInput.command !== "string") return {{ kind: "invalid-bash" }};
  return {{ kind: "bash", input: toolInput, command: toolInput.command }};
}}

function parseDcgOutput(stdoutText: string): DcgParsedOutput {{
  const text = stdoutText.trim();
  if (!text) return {{ verdict: "empty" }};

  let raw: unknown;
  try {{
    raw = JSON.parse(text);
  }} catch {{
    return {{ verdict: "malformed" }};
  }}
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {{
    return {{ verdict: "unknown" }};
  }}

  const record = raw as Record<string, unknown>;
  const decision = record.decision;
  const verdict: DcgParsedVerdict =
    decision === "allow" ||
    decision === "deny" ||
    decision === "ask" ||
    decision === "indeterminate"
      ? decision
      : "unknown";
  return {{
    verdict,
    reason: typeof record.reason === "string" ? record.reason : undefined,
    ruleId: typeof record.rule_id === "string" ? record.rule_id : undefined,
  }};
}}

export function classifyDcgChild(
  outcome: DcgChildOutcome,
  stdoutText: string,
): {{ action: DcgBridgeAction; output: DcgParsedOutput }} {{
  const output = parseDcgOutput(stdoutText);
  return {{ action: DCG_CHILD_TRANSITIONS[outcome][output.verdict], output }};
}}

function childOutcomeFromExitCode(exitCode: unknown): DcgChildOutcome {{
  if (exitCode === 0) return "exit-0";
  if (exitCode === 1) return "exit-1";
  if (exitCode === 2) return "exit-2";
  return "exit-other";
}}

export default function dcgGuard(pi: ExtensionAPI): void {{
  pi.on("tool_call", async (event, ctx) => {{
    const toolCall = classifyOmpToolCall(event);
    if (toolCall.kind === "other-tool") return;
    if (toolCall.kind === "invalid-bash") {{
      return {{
        block: true,
        reason: "[dcg] OMP guard received malformed bash input (expected an object with a string command)",
      }};
    }}
    const {{ input: toolInput, command }} = toolCall;
    // OMP's schema permits the empty string and its BashTool treats it as a
    // no-op. Preserve that exact case; every non-empty string, including
    // whitespace, still crosses the dcg decision boundary.
    if (command.length === 0) return;

    // Match OMP's BashTool filesystem-cwd derivation. Structured cwd wins;
    // when it is absent OMP extracts only its conservative
    // `cd <path> && ...` prefix. Reusing OMP's exported helpers keeps tilde,
    // absolute, relative, Windows-drive-alias, and bare-root semantics
    // synchronized upstream.
    // An internal protocol URL is expanded only later by BashTool, with state
    // this callback does not expose. resolveToCwd rejects it here, and the
    // catch fails closed rather than evaluating under an unrelated policy.
    let commandCwd: string;
    try {{
      const structuredCwd = typeof toolInput?.cwd === "string" && toolInput.cwd
        ? toolInput.cwd
        : undefined;
      const requestedCwd = structuredCwd || extractLeadingCdTarget(command)?.path;
      commandCwd = requestedCwd ? resolveToCwd(requestedCwd, ctx.cwd) : ctx.cwd;
    }} catch (err) {{
      return {{
        block: true,
        reason: `[dcg] OMP guard could not resolve the bash working directory safely: ${{err}}`,
      }};
    }}

    // OMP executes ordinary and managed-async BashTool calls in its embedded
    // Brush shell, including on native Windows. Only an eligible local PTY
    // bypasses Brush for the configured external shell. Mirror OMP's route
    // predicate exactly: async wins before PTY, and PI_NO_PTY=1 disables PTY.
    // OMP does not expose its ClientBridge terminal capability to extensions;
    // ACP and JSON-RPC both report ctx.mode="rpc", so never guess from mode.
    let shellDialect: "posix" | "ps" | "cmd" = "posix";
    const usesLocalPty =
      toolInput?.pty === true && toolInput?.async !== true && ctx.hasUI && process.env.PI_NO_PTY !== "1";
    if (usesLocalPty) {{
      try {{
        const shell = settings.getShellConfig().shell;
        shellDialect = procmgr.isCmdShell(shell) ? "cmd" : procmgr.isPowerShell(shell) ? "ps" : "posix";
      }} catch (err) {{
        return {{
          block: true,
          reason: `[dcg] OMP guard could not resolve the local PTY shell dialect safely: ${{err}}`,
        }};
      }}
    }}

    let stdoutText;
    let stderrText;
    let exitCode;
    try {{
      const proc = Bun.spawn([
        process.env.DCG_BIN || DCG_BIN,
        "--robot", "test", "--stdin", "--agent", "omp", "--dialect", shellDialect,
      ], {{
        cwd: commandCwd,
        stdin: new TextEncoder().encode(command),
        stdout: "pipe",
        stderr: "pipe",
      }});
      [stdoutText, stderrText, exitCode] = await Promise.all([
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
        proc.exited,
      ]);
    }} catch (err) {{
      console.error(`[dcg] OMP guard could not run dcg: ${{err}}`);
      return;
    }}

    // Treat the two child streams as separate capabilities: stdout alone may
    // carry the robot decision; stderr is diagnostic-only but never discarded.
    const classification = classifyDcgChild(
      childOutcomeFromExitCode(exitCode),
      typeof stdoutText === "string" ? stdoutText : "",
    );
    const stderrDetail = typeof stderrText === "string" ? stderrText.trim() : "";
    if (classification.action === "infrastructure") {{
      console.error(`[dcg] OMP guard infrastructure failure (exit ${{exitCode}})${{stderrDetail ? `: ${{stderrDetail}}` : ""}}`);
      return;
    }}
    if (stderrDetail) console.error(`[dcg] OMP guard dcg stderr: ${{stderrDetail}}`);
    if (classification.action === "allow") return;

    const output = classification.output;
    const reason = BLOCKING_DECISIONS.has(output.verdict)
      ? output.reason || "Blocked by dcg"
      : "Blocked by dcg (exit 1 without a blocking decision)";
    const rule = output.ruleId ? `\n\nRule: ${{output.ruleId}}` : "";
    return {{ block: true, reason: `${{reason}}${{rule}}` }};
  }});
}}
"#
    ))
}

/// Whether this machine plausibly uses OMP. This gates doctor output so users
/// without OMP are not prompted to install an irrelevant extension.
fn omp_appears_in_use() -> bool {
    if std::env::var_os("OMP_PROFILE").is_some()
        || std::env::var_os("PI_PROFILE").is_some()
        || which_executable("omp").is_some()
    {
        return true;
    }
    let default_root_exists = dirs::home_dir().is_some_and(|home| home.join(".omp").is_dir());
    default_root_exists
        || omp_user_agent_dir().is_ok_and(|path| path.is_dir())
        || project_omp_extension_path()
            .ok()
            .is_some_and(|path| path.exists())
}

/// Whether `path` holds a dcg-generated OMP extension.
fn omp_extension_is_dcg_owned(path: &std::path::Path) -> bool {
    std::fs::read_to_string(path)
        .map(|content| content.contains(OMP_EXTENSION_MARKER))
        .unwrap_or(false)
}

/// A dcg-owned OMP extension loaded by the current project/profile. Doctor must
/// accept either installation mode instead of always inspecting the user path.
fn registered_omp_extension_path() -> std::io::Result<Option<std::path::PathBuf>> {
    // Validate the live profile environment before doctor claims that OMP can
    // start and load either extension. Keep the project-registration fast path
    // independent of user-path settings that OMP does not need to discover it.
    let _validated_profile = omp_active_profile()?;
    if let Some(project_path) = project_omp_extension_path()
        .ok()
        .filter(|path| omp_extension_is_dcg_owned(path))
    {
        return Ok(Some(project_path));
    }

    let user_path = omp_user_extension_path()?;
    Ok(omp_extension_is_dcg_owned(&user_path).then_some(user_path))
}

/// Shared doctor verdict for the build-provenance / update-pin check (#320),
/// used by both renderers so `--strict` and `--format json` agree.
fn build_provenance_doctor_parts(config: &Config) -> (DoctorCheckStatus, String, Option<String>) {
    let pinned = config.general.update_pin;
    match crate::update::build_provenance() {
        crate::update::BuildProvenance::Release => (
            DoctorCheckStatus::Ok,
            "Binary matches its release tag; `dcg update` is safe".to_string(),
            None,
        ),
        crate::update::BuildProvenance::LocalAheadOfRelease { describe } => {
            if pinned {
                (
                    DoctorCheckStatus::Ok,
                    format!(
                        "Local build ahead of its release tag ({describe}); pinned against \
                         `dcg update` via general.update_pin"
                    ),
                    None,
                )
            } else {
                (
                    DoctorCheckStatus::Warning,
                    format!(
                        "Local build ahead of its release tag ({describe}); a routine `dcg \
                         update` would silently replace it with the published release"
                    ),
                    Some(
                        "Set `general.update_pin = true` in ~/.config/dcg/config.toml to pin \
                         this build (escape hatch: `dcg update --replace-local-build`)"
                            .to_string(),
                    ),
                )
            }
        }
        crate::update::BuildProvenance::Unknown => (
            DoctorCheckStatus::Ok,
            "No build provenance embedded (non-git build); update-pin checks rely on \
             general.update_pin only"
                .to_string(),
            None,
        ),
    }
}

/// Install the native OpenCode plugin (#318).
fn install_opencode_plugin(force: bool, project: bool) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let plugin_path = if project {
        project_opencode_plugin_path()?
    } else {
        opencode_user_plugin_path()
    };

    if plugin_path.exists() {
        let existing = std::fs::read_to_string(&plugin_path).unwrap_or_default();
        if !existing.contains(OPENCODE_PLUGIN_MARKER) {
            return Err(format!(
                "{} exists but was not generated by dcg (missing the '{OPENCODE_PLUGIN_MARKER}' \
                 marker). Refusing to overwrite a user-owned plugin — move it aside or merge \
                 the dcg guard into it manually.",
                plugin_path.display()
            )
            .into());
        }
        if !force {
            println!("{}", "Plugin already installed!".yellow());
            println!("Use --force to reinstall");
            return Ok(());
        }
    }

    let executable = current_dcg_executable()?;
    let source = build_opencode_plugin_source(&executable)?;

    if let Some(parent) = plugin_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_settings_atomic(&plugin_path, &source)?;

    let level = if project { "project" } else { "user" };
    println!(
        "{}",
        "OpenCode plugin installed successfully!".green().bold()
    );
    println!("Plugin written ({level}): {}", plugin_path.display());
    println!();
    println!(
        "{}",
        "Restart OpenCode (start a new session) for the plugin to load.".yellow()
    );
    Ok(())
}

/// Install the native Oh My Pi ExtensionAPI guard.
fn install_omp_extension(force: bool, project: bool) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let extension_path = if project {
        // Project extension discovery is cwd-only, but OMP still resolves and
        // validates its active profile before loading any project extension.
        let _validated_profile = omp_active_profile()?;
        project_omp_extension_path()?
    } else {
        omp_user_extension_path()?
    };

    if extension_path.exists() {
        let existing = std::fs::read_to_string(&extension_path).unwrap_or_default();
        if !existing.contains(OMP_EXTENSION_MARKER) {
            return Err(format!(
                "{} exists but was not generated by dcg (missing the '{OMP_EXTENSION_MARKER}' \
                 marker). Refusing to overwrite a user-owned extension — move it aside or merge \
                 the dcg guard into it manually.",
                extension_path.display()
            )
            .into());
        }
        if !force {
            println!("{}", "OMP extension already installed!".yellow());
            println!("Use --force to reinstall");
            return Ok(());
        }
    }

    let executable = current_dcg_executable()?;
    let source = build_omp_extension_source(&executable)?;
    if let Some(parent) = extension_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_settings_atomic(&extension_path, &source)?;

    let level = if project { "project" } else { "user/profile" };
    println!("{}", "OMP extension installed successfully!".green().bold());
    println!("Extension written ({level}): {}", extension_path.display());
    println!();
    println!(
        "{}",
        "Restart Oh My Pi (start a new session) for the extension to load.".yellow()
    );
    Ok(())
}

/// The shell snippet that checks whether the DCG hook is still present in
/// Claude Code settings on every new shell session. Runs in milliseconds,
/// silent when the hook is present, yellow warning when missing.
///
/// Unix-only: this is a POSIX-shell (bash/zsh) snippet sourced from RC files,
/// which native Windows shells do not use.
#[cfg(unix)]
const DCG_SHELL_CHECK_SNIPPET: &str = r#"
# dcg: warn if hook was silently removed from Claude Code settings
if command -v dcg &>/dev/null && command -v jq &>/dev/null; then
  if [ -f "$HOME/.claude/settings.json" ] && \
     ! jq -e '.hooks.PreToolUse[]? | select(.hooks[]?.command | test("dcg\"?$"))' \
       "$HOME/.claude/settings.json" &>/dev/null; then
    printf '\033[1;33m[dcg] Hook missing from ~/.claude/settings.json — run: dcg install\033[0m\n'
  fi
fi
"#;

/// Marker used to identify the DCG shell check block for idempotent injection.
#[cfg(unix)]
const DCG_SHELL_CHECK_MARKER: &str = "# dcg: warn if hook was silently removed";

/// Check whether a shell RC file already contains the DCG startup check.
#[cfg(unix)]
fn rc_has_dcg_check(path: &std::path::Path) -> bool {
    if let Ok(content) = std::fs::read_to_string(path) {
        content.contains(DCG_SHELL_CHECK_MARKER)
    } else {
        false
    }
}

/// Outcome of [`inject_shell_check`].
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellCheckOutcome {
    /// The snippet was appended to an RC file that had none.
    Added,
    /// The RC file already carries the current snippet text.
    AlreadyCurrent,
    /// A stale marker-guarded block was replaced (or, if its boundary was
    /// unrecognizable, a current block was appended alongside it).
    Updated,
}

/// Replace the managed dcg shell-check region (the marker line through the
/// first column-0 `fi`) with the current snippet. Returns `None` when the
/// region boundary cannot be located (hand-mangled block).
///
/// The column-0 requirement is deliberate: the snippet's only unindented `fi`
/// is its final line, so an indent-tolerant match would truncate the block at
/// its interior `  fi` and corrupt the RC file.
#[cfg(unix)]
fn repair_shell_check_region(content: &str) -> Option<String> {
    let mut region_start: Option<usize> = None;
    let mut offset = 0usize;
    for line in content.split_inclusive('\n') {
        if region_start.is_none() {
            if line.trim_start().starts_with(DCG_SHELL_CHECK_MARKER) {
                region_start = Some(offset);
            }
        } else if line.trim_end() == "fi" && line.starts_with('f') {
            let region_end = offset + line.len();
            let mut repaired = String::with_capacity(content.len() + DCG_SHELL_CHECK_SNIPPET.len());
            repaired.push_str(&content[..region_start?]);
            repaired.push_str(DCG_SHELL_CHECK_SNIPPET.trim_start_matches('\n'));
            repaired.push_str(&content[region_end..]);
            return Some(repaired);
        }
        offset += line.len();
    }
    None
}

/// Add the DCG shell startup check to a shell RC file, or repair a stale one.
///
/// A marker whose block text differs from the current snippet is rewritten in
/// place (issue #282's second act on the PowerShell side: marker-only
/// idempotence pinned users to the first snippet version they ever received).
#[cfg(unix)]
fn inject_shell_check(
    path: &std::path::Path,
) -> Result<ShellCheckOutcome, Box<dyn std::error::Error>> {
    if let Ok(content) = std::fs::read_to_string(path) {
        if content.contains(DCG_SHELL_CHECK_MARKER) {
            if content.contains(DCG_SHELL_CHECK_SNIPPET.trim_start_matches('\n')) {
                return Ok(ShellCheckOutcome::AlreadyCurrent);
            }
            if let Some(repaired) = repair_shell_check_region(&content) {
                std::fs::write(path, repaired)?;
            } else {
                // Boundary unrecognizable — append a current block so at
                // least the up-to-date check runs.
                append_shell_check(path)?;
            }
            return Ok(ShellCheckOutcome::Updated);
        }
    }

    append_shell_check(path)?;
    Ok(ShellCheckOutcome::Added)
}

#[cfg(unix)]
fn append_shell_check(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

    use std::io::Write;
    write!(file, "{DCG_SHELL_CHECK_SNIPPET}")?;
    Ok(())
}

/// Full setup: install the hook and optionally add the shell startup check.
///
/// # Errors
///
/// Returns an error if hook installation or file I/O fails.
fn run_setup(
    force: bool,
    auto_shell_check: bool,
    no_shell_check: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // --- Step 1: Install the hook (same as `dcg install`) ---
    install_hook(force, false)?;

    // --- Step 2: Offer the shell startup check ---
    // The check appends a snippet to ~/.bashrc / ~/.zshrc, which native Windows
    // (PowerShell / cmd) does not source. It is therefore a Unix-shell-only
    // feature; on Windows this is a clean, informative no-op (the PowerShell
    // `$PROFILE` equivalent is offered by install.ps1 — win-installer-profile-check).
    #[cfg(unix)]
    {
        run_shell_check_setup(auto_shell_check, no_shell_check)?;
    }

    #[cfg(not(unix))]
    {
        use colored::Colorize;
        let _ = (auto_shell_check, no_shell_check);
        println!();
        println!(
            "{}",
            "Shell startup check is a Unix-shell feature; skipped on this platform.".cyan()
        );
        println!(
            "{}",
            "PowerShell users: install.ps1 can add an equivalent $PROFILE check.".dimmed()
        );
    }

    Ok(())
}

/// Unix-only shell-startup-check setup: appends the dcg hook-removal warning
/// snippet to the user's shell RC file(s) (`~/.bashrc` / `~/.zshrc`). Gated to
/// Unix because native Windows shells do not source these files (see `run_setup`);
/// the PowerShell `$PROFILE` equivalent is handled by the installer instead.
#[cfg(unix)]
fn run_shell_check_setup(
    auto_shell_check: bool,
    no_shell_check: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    if no_shell_check {
        return Ok(());
    }

    let home = dirs::home_dir().ok_or("Could not determine home directory")?;

    // Collect candidate RC files that actually exist (or that the user's
    // current shell would source).
    let mut rc_files: Vec<std::path::PathBuf> = Vec::new();
    let zshrc = home.join(".zshrc");
    let bashrc = home.join(".bashrc");

    if zshrc.exists() {
        rc_files.push(zshrc);
    }
    if bashrc.exists() {
        rc_files.push(bashrc);
    }

    if rc_files.is_empty() {
        // No RC files found — try to create one for the current shell.
        if let Ok(shell) = std::env::var("SHELL") {
            if shell.contains("zsh") {
                rc_files.push(home.join(".zshrc"));
            } else {
                rc_files.push(home.join(".bashrc"));
            }
        } else {
            rc_files.push(home.join(".bashrc"));
        }
    }

    // Check if all candidates already have the snippet.
    let all_present = rc_files.iter().all(|p| rc_has_dcg_check(p));
    if all_present {
        println!();
        println!(
            "{}",
            "Shell startup check already present in all RC files.".green()
        );
        return Ok(());
    }

    // Decide whether to inject.
    let should_inject = if auto_shell_check {
        true
    } else if std::io::stdin().is_terminal() {
        println!();
        println!("{}", "Shell startup check".cyan().bold());
        println!("Claude Code can silently remove the dcg hook when it rewrites settings.json.");
        println!("A small shell check in your RC file will warn you on every new terminal");
        println!("if the hook goes missing. It runs in milliseconds and is silent normally.");
        println!();

        let targets: Vec<String> = rc_files
            .iter()
            .filter(|p| !rc_has_dcg_check(p))
            .map(|p| format!("  {}", p.display()))
            .collect();

        println!("Would add to:");
        for t in &targets {
            println!("{}", t.dimmed());
        }
        println!();

        let answer = inquire::Confirm::new("Add shell startup check?")
            .with_default(true)
            .prompt();

        matches!(answer, Ok(true))
    } else {
        // Non-interactive: skip unless --shell-check was passed.
        false
    };

    if should_inject {
        for rc_path in &rc_files {
            match inject_shell_check(rc_path) {
                Ok(ShellCheckOutcome::Added) => {
                    println!("{} {}", "Added shell check to".green(), rc_path.display());
                }
                Ok(ShellCheckOutcome::Updated) => {
                    println!(
                        "{} {}",
                        "Updated stale shell check in".green(),
                        rc_path.display()
                    );
                }
                Ok(ShellCheckOutcome::AlreadyCurrent) => {
                    println!("{} {}", "Already present in".yellow(), rc_path.display());
                }
                Err(e) => {
                    eprintln!("{} {}: {}", "Failed to update".red(), rc_path.display(), e);
                }
            }
        }
        println!();
        println!(
            "{}",
            "Restart your shell (or source your RC file) to activate the check.".yellow()
        );
    } else {
        println!();
        println!(
            "{}",
            "Skipped shell startup check. You can add it later with: dcg setup --shell-check"
                .dimmed()
        );
    }

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
fn self_update(
    update: UpdateCommand,
    update_pinned: bool,
) -> Result<(), Box<dyn std::error::Error>> {
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

    // #320: refuse to replace a pinned install or a local build that is
    // ahead of its release tag BEFORE any network or installer work — a
    // half-completed update on a guard is worse than a clean refusal.
    if !update.replace_local_build {
        if update_pinned {
            return Err(format!(
                "dcg update is pinned: this install set `general.update_pin = true` (or \
                 `DCG_UPDATE_PIN=1`), so `dcg update` refuses to replace the binary.\n\
                 Installed: dcg v{}{}\n\
                 To update anyway, rerun with `dcg update --replace-local-build`, or remove \
                 the pin first.",
                crate::update::current_version(),
                crate::update::GIT_SHA.map_or_else(String::new, |sha| format!(" ({sha})")),
            )
            .into());
        }
        if let crate::update::BuildProvenance::LocalAheadOfRelease { describe } =
            crate::update::build_provenance()
        {
            return Err(format!(
                "this dcg binary is a local build ahead of its release tag (git describe: \
                 {describe}).\n\
                 Replacing it with the published release would silently discard that local \
                 delta — for a guard, that can mean downgrading coverage you depend on. \
                 Refusing before any download or install work.\n\
                 - To keep the local build and stop update nudges: set \
                 `general.update_pin = true` in ~/.config/dcg/config.toml\n\
                 - To replace it with the published release anyway: \
                 `dcg update --replace-local-build`",
            )
            .into());
        }
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

fn normalize_release_tag(version: &str) -> Result<String, Box<dyn std::error::Error>> {
    let trimmed = version.trim();
    let semver_text = trimmed.strip_prefix('v').unwrap_or(trimmed);
    let parsed = match semver::Version::parse(semver_text) {
        Ok(parsed) => parsed,
        Err(err) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid release version '{version}': {err}"),
            )
            .into());
        }
    };
    Ok(format!("v{parsed}"))
}

fn update_installer_tag_from_versions(
    requested_version: Option<&str>,
    latest_version: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    normalize_release_tag(requested_version.unwrap_or(latest_version))
}

fn update_installer_tag(
    requested_version: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    match requested_version {
        Some(version) => {
            update_installer_tag_from_versions(Some(version), env!("CARGO_PKG_VERSION"))
        }
        None => match crate::update::check_for_update(true) {
            Ok(result) => update_installer_tag_from_versions(None, &result.latest_version),
            Err(err) => Err(format!(
                "Failed to resolve latest release for dcg update: {err}. Re-run with --version vX.Y.Z to install a known release."
            )
            .into()),
        },
    }
}

#[cfg(test)]
fn update_installer_tag_from_check_result(
    requested_version: Option<&str>,
    latest_result: Result<&str, &str>,
) -> Result<String, Box<dyn std::error::Error>> {
    match requested_version {
        Some(version) => update_installer_tag_from_versions(Some(version), env!("CARGO_PKG_VERSION")),
        None => match latest_result {
            Ok(latest_version) => update_installer_tag_from_versions(None, latest_version),
            Err(err) => Err(format!(
                "Failed to resolve latest release for dcg update: {err}. Re-run with --version vX.Y.Z to install a known release."
            )
            .into()),
        },
    }
}

struct InstallerTempDir {
    path: Option<std::path::PathBuf>,
}

impl InstallerTempDir {
    fn create() -> Result<Self, Box<dyn std::error::Error>> {
        let base = std::env::temp_dir();
        let process_id = std::process::id();
        for attempt in 0..100_u32 {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos();
            let path = base.join(format!("dcg-install-{process_id}-{nanos}-{attempt}"));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path: Some(path) }),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err.into()),
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "Failed to create a unique installer temp directory",
        )
        .into())
    }

    fn path(&self) -> &std::path::Path {
        self.path
            .as_deref()
            .expect("installer temp directory has already been persisted")
    }

    fn persist(mut self) -> std::path::PathBuf {
        self.path
            .take()
            .expect("installer temp directory has already been persisted")
    }
}

impl Drop for InstallerTempDir {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

fn try_download_file(
    url: &str,
    destination: &std::path::Path,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut command = if cfg!(windows) {
        std::process::Command::new("curl.exe")
    } else {
        std::process::Command::new("curl")
    };
    let status = command
        .arg("-fsSL")
        .arg(url)
        .arg("-o")
        .arg(destination)
        .status()?;

    Ok(status.success())
}

fn download_file(
    url: &str,
    destination: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if try_download_file(url, destination)? {
        Ok(())
    } else {
        Err(format!("Failed to download {url}").into())
    }
}

fn verify_installer_checksum(
    artifact_path: &std::path::Path,
    checksum_path: &std::path::Path,
    artifact_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fmt::Write as _;

    use sha2::{Digest, Sha256};

    let checksum_content = std::fs::read_to_string(checksum_path)?;
    let expected = checksum_content
        .split_whitespace()
        .next()
        .ok_or_else(|| format!("{artifact_name}.sha256 is empty"))?;
    if expected.len() != 64 || !expected.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!("{artifact_name}.sha256 is malformed (need 64 hex chars)").into());
    }

    let artifact = std::fs::read(artifact_path)?;
    let digest = Sha256::digest(&artifact);
    let mut actual = String::with_capacity(64);
    for byte in digest {
        let _ = write!(actual, "{byte:02x}");
    }
    if expected.eq_ignore_ascii_case(&actual) {
        Ok(())
    } else {
        Err(format!("{artifact_name} sha256 verification failed").into())
    }
}

fn download_verified_installer(
    script_url: &str,
    sha_url: &str,
    artifact_name: &str,
) -> Result<(InstallerTempDir, std::path::PathBuf), Box<dyn std::error::Error>> {
    let temp_dir = InstallerTempDir::create()?;
    let script_path = temp_dir.path().join(artifact_name);
    let checksum_path = temp_dir.path().join(format!("{artifact_name}.sha256"));

    download_file(script_url, &script_path)?;
    if try_download_file(sha_url, &checksum_path)? {
        verify_installer_checksum(&script_path, &checksum_path, artifact_name)?;
        eprintln!("dcg update: {artifact_name} sha256 verified.");
    } else {
        eprintln!(
            "dcg update: {artifact_name}.sha256 not published for this tag; proceeding without verification."
        );
    }

    Ok((temp_dir, script_path))
}

fn self_update_unix(update: UpdateCommand) -> Result<(), Box<dyn std::error::Error>> {
    // Tag-pin the installer URL so the install.sh that runs is from the
    // requested version, or from the latest release for the default update path
    // (not whatever is on `main`).
    //
    // Per `git_safety_guard-ythp`, we additionally download install.sh to a
    // temp file and verify install.sh.sha256 when the matching release
    // publishes it. Older tags will not have the checksum; we warn and proceed
    // to preserve the update path for stale binaries.
    let requested_version = update.version.clone();
    let normalized_tag = update_installer_tag(requested_version.as_deref())?;
    let script_url = format!(
        "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/{normalized_tag}/install.sh"
    );
    // Releases-download URL where install.sh.sha256 is published from
    // dist.yml. Pre-ythp tags will 404 here; the verification step
    // detects that and warns rather than aborting.
    let sha_url = format!(
        "https://github.com/Dicklesworthstone/destructive_command_guard/releases/download/{normalized_tag}/install.sh.sha256"
    );

    eprintln!("dcg update: downloading and verifying install.sh from {normalized_tag}.");

    let mut args: Vec<String> = Vec::new();

    // Always pass the resolved tag. Otherwise the verified tag-pinned script
    // would perform a second "latest" lookup and could install a different
    // release than the one whose installer we verified.
    args.push("--version".to_string());
    args.push(normalized_tag.clone());
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
    if update.no_configure {
        args.push("--no-configure".to_string());
    }

    let (_temp_dir, script_path) =
        download_verified_installer(&script_url, &sha_url, "install.sh")?;

    let status = std::process::Command::new("bash")
        .arg(&script_path)
        .args(&args)
        .status()?;

    if !status.success() {
        return Err(format!("Installer failed with status {status}").into());
    }

    Ok(())
}

const WINDOWS_UPDATE_RUNNER: &str = r#"[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$exitCode = 1
$configurationPath = Join-Path $PSScriptRoot 'runner-config.json'
$configuration = Get-Content -LiteralPath $configurationPath -Raw | ConvertFrom-Json
$parentProcessId = [UInt32]$configuration.parent_process_id
$installerPath = [string]$configuration.installer_path
$cleanupDirectory = [string]$configuration.cleanup_directory
$logPath = [string]$configuration.log_path

# Windows PowerShell 5.1 returns a JSON array as one Object[] pipeline object.
# Casting that object directly to [string[]] produces one flattened string such
# as "-Version v0.7.3 -Verify". Explicit pipeline enumeration preserves argv.
[string[]]$installerArguments = @(
  $configuration.installer_arguments | ForEach-Object { [string]$_ }
)

function Add-DcgUpdateLog {
  param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string]$Message
  )
  $line = $Message + [Environment]::NewLine
  [IO.File]::AppendAllText($logPath, $line, [Text.UTF8Encoding]::new($false))
}

try {
  Add-DcgUpdateLog "dcg update worker started at $([DateTime]::UtcNow.ToString('o'))."
  $parentProcess = if ($parentProcessId -le [UInt32][Int32]::MaxValue) {
    Get-Process -Id ([Int32]$parentProcessId) -ErrorAction SilentlyContinue
  } else {
    $null
  }
  if ($null -ne $parentProcess) {
    $parentProcess | Wait-Process -ErrorAction SilentlyContinue
  }

  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installerPath @installerArguments 2>&1 |
    ForEach-Object { Add-DcgUpdateLog ([string]$_) }
  $exitCode = $LASTEXITCODE
  if ($exitCode -eq 0) {
    Add-DcgUpdateLog 'dcg update completed successfully.'
  } else {
    Add-DcgUpdateLog "dcg update installer exited with code $exitCode."
  }
} catch {
  Add-DcgUpdateLog "dcg update failed: $($_.Exception.Message)"
  $exitCode = 1
} finally {
  Remove-Item -LiteralPath $cleanupDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
exit $exitCode
"#;

const WINDOWS_UPDATE_CIM_LAUNCHER: &str = r#"$ErrorActionPreference = 'Stop'
$commandLine = $env:DCG_UPDATE_WORKER_COMMAND
if ([string]::IsNullOrWhiteSpace($commandLine)) {
  throw 'DCG_UPDATE_WORKER_COMMAND is empty'
}
$created = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
  CommandLine = $commandLine
}
if ([UInt32]$created.ReturnValue -ne 0) {
  throw "Win32_Process.Create failed with code $($created.ReturnValue)"
}
Write-Output ([string]$created.ProcessId)
"#;

fn windows_update_log_path() -> std::path::PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("dcg")
        .join("update.log")
}

fn windows_update_installer_arguments(update: &UpdateCommand, normalized_tag: &str) -> Vec<String> {
    let mut args = vec!["-Version".to_string(), normalized_tag.to_string()];
    if let Some(dest) = &update.dest {
        args.push("-Dest".to_string());
        args.push(dest.to_string_lossy().into_owned());
    }
    if update.easy_mode {
        args.push("-EasyMode".to_string());
    }
    if update.verify {
        args.push("-Verify".to_string());
    }
    if update.no_configure {
        args.push("-NoConfigure".to_string());
    }
    args
}

fn windows_update_worker_command_line(
    runner_path: &std::path::Path,
) -> Result<String, Box<dyn std::error::Error>> {
    let runner = runner_path
        .to_str()
        .ok_or("Windows update runner path is not valid Unicode")?;
    if runner.contains('"') {
        return Err("Windows update runner path contains an invalid quote".into());
    }
    Ok(format!(
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{runner}\""
    ))
}

fn launch_windows_update_worker_via_cim(
    worker_command_line: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let output = std::process::Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg(WINDOWS_UPDATE_CIM_LAUNCHER)
        .env("DCG_UPDATE_WORKER_COMMAND", worker_command_line)
        .output()?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(format!(
        "Win32_Process.Create could not launch the update worker (status {}): {}{}",
        output.status,
        stdout.trim(),
        stderr.trim()
    )
    .into())
}

fn launch_windows_update_worker_direct(
    runner_path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    fn runner_command(runner_path: &std::path::Path) -> std::process::Command {
        let mut runner = std::process::Command::new("powershell.exe");
        runner
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-ExecutionPolicy")
            .arg("Bypass")
            .arg("-File")
            .arg(runner_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        runner
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
        // CREATE_BREAKAWAY_FROM_JOB is ignored when combined with
        // DETACHED_PROCESS. Try a real job breakaway first, then fall back to
        // the original detached launch when the host job disallows breakaway.
        let mut breakaway = runner_command(runner_path);
        breakaway.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB);
        match breakaway.spawn() {
            Ok(_) => Ok(()),
            Err(breakaway_error) => {
                let mut detached = runner_command(runner_path);
                detached.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
                detached.spawn().map_err(|detached_error| {
                    format!(
                        "job-breakaway worker failed ({breakaway_error}); \
                         detached worker failed ({detached_error})"
                    )
                })?;
                Ok(())
            }
        }
    }
    #[cfg(not(windows))]
    {
        runner_command(runner_path).spawn()?;
        Ok(())
    }
}

fn launch_windows_update_worker(
    runner_path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let worker_command_line = windows_update_worker_command_line(runner_path)?;
    match launch_windows_update_worker_via_cim(&worker_command_line) {
        Ok(()) => Ok(()),
        Err(cim_error) => {
            eprintln!(
                "dcg update: resilient Win32_Process launch failed ({cim_error}); \
                 falling back to a detached worker."
            );
            launch_windows_update_worker_direct(runner_path).map_err(|direct_error| {
                format!(
                    "Failed to launch Windows update worker via Win32_Process ({cim_error}) \
                     or direct process creation ({direct_error})"
                )
                .into()
            })
        }
    }
}

fn self_update_windows(update: UpdateCommand) -> Result<(), Box<dyn std::error::Error>> {
    if update.system || update.from_source || update.quiet || update.no_gum || update.force {
        return Err(
            "Windows updater supports only --version, --dest, --easy-mode, --verify, and \
             --no-configure."
                .into(),
        );
    }

    // Same tag-pinning + sha256 verification as `self_update_unix`. See
    // that function's comment for the full rationale (`git_safety_guard-ythp`).
    let requested_version = update.version.clone();
    let normalized_tag = update_installer_tag(requested_version.as_deref())?;
    let script_url = format!(
        "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/{normalized_tag}/install.ps1"
    );
    let sha_url = format!(
        "https://github.com/Dicklesworthstone/destructive_command_guard/releases/download/{normalized_tag}/install.ps1.sha256"
    );

    eprintln!("dcg update: downloading and verifying install.ps1 from {normalized_tag}.");

    let args = windows_update_installer_arguments(&update, &normalized_tag);

    let (temp_dir, script_path) =
        download_verified_installer(&script_url, &sha_url, "install.ps1")?;
    let runner_path = temp_dir.path().join("run-update-after-exit.ps1");
    let configuration_path = temp_dir.path().join("runner-config.json");
    std::fs::write(&runner_path, WINDOWS_UPDATE_RUNNER)?;

    let log_path = windows_update_log_path();
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let configuration = serde_json::json!({
        "parent_process_id": std::process::id(),
        "installer_path": script_path,
        "installer_arguments": args,
        "cleanup_directory": temp_dir.path(),
        "log_path": log_path,
    });
    std::fs::write(&configuration_path, serde_json::to_vec(&configuration)?)?;

    launch_windows_update_worker(&runner_path)?;
    let _persisted_temp_dir = temp_dir.persist();

    eprintln!(
        "dcg update: verified {normalized_tag} and staged replacement after this process exits."
    );
    eprintln!(
        "dcg update: progress will be written to {}.",
        log_path.display()
    );

    Ok(())
}

/// Get the path to user-level Claude Code settings (`~/.claude/settings.json`).
fn claude_settings_path() -> std::path::PathBuf {
    dirs::home_dir()
        .unwrap_or_default()
        .join(".claude")
        .join("settings.json")
}

/// Get the path to project-level Claude Code settings (`.claude/settings.json`
/// relative to the current repository root).
///
/// Returns `Err` if the current directory is not inside a git repository.
fn project_claude_settings_path() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let repo_root = find_repo_root_from_cwd()
        .ok_or("Not inside a git repository — cannot determine project root")?;
    Ok(repo_root.join(".claude").join("settings.json"))
}

/// Path to the user-level Grok dcg hook file (`~/.grok/hooks/dcg.json`).
///
/// Per `~/.grok/docs/user-guide/10-hooks.md`, Grok auto-discovers every
/// `*.json` under `~/.grok/hooks/`. A separate file per integration (rather
/// than editing `~/.grok/user-settings.json`) keeps installs/uninstalls
/// independent of unrelated user settings.
fn grok_user_hook_path() -> std::path::PathBuf {
    dirs::home_dir()
        .unwrap_or_default()
        .join(".grok")
        .join("hooks")
        .join("dcg.json")
}

/// Path to a project-level Grok dcg hook file (`<repo>/.grok/hooks/dcg.json`).
///
/// Returns `Err` if the current directory is not inside a git repository.
fn project_grok_hook_path() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let repo_root = find_repo_root_from_cwd()
        .ok_or("Not inside a git repository — cannot determine project root")?;
    Ok(repo_root.join(".grok").join("hooks").join("dcg.json"))
}

/// Get the path to dcg config directory.
///
/// Prefers `$XDG_CONFIG_HOME/dcg/`, then XDG-style `~/.config/dcg/` if it exists,
/// otherwise falls back to the platform-native location. This ensures users can
/// use `~/.config/dcg/` on all platforms, including macOS where
/// `dirs::config_dir()` returns `~/Library/Application Support`.
fn config_dir() -> std::path::PathBuf {
    // Check XDG_CONFIG_HOME first (if set)
    if let Ok(xdg_home) = std::env::var("XDG_CONFIG_HOME") {
        if let Some(xdg_home) = crate::config::resolve_config_path_value(&xdg_home, None) {
            return xdg_home.join("dcg");
        }
    }

    // Check XDG-style path next (~/.config/dcg/)
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
    // Prefer an existing config file in the same order as config loading.
    if let Ok(xdg_home) = std::env::var("XDG_CONFIG_HOME") {
        if let Some(xdg_home) = crate::config::resolve_config_path_value(&xdg_home, None) {
            let path = xdg_home.join("dcg").join("config.toml");
            if path.exists() {
                return path;
            }
        }
    }

    if let Some(home) = dirs::home_dir() {
        let path = home.join(".config").join("dcg").join("config.toml");
        if path.exists() {
            return path;
        }
    }

    if let Some(config_dir) = dirs::config_dir() {
        let path = config_dir.join("dcg").join("config.toml");
        if path.exists() {
            return path;
        }
    }

    config_dir().join("config.toml")
}

/// Check if dcg is in PATH
fn which_dcg() -> Option<std::path::PathBuf> {
    which_executable("dcg")
}

/// Find a native executable in PATH using the platform's executable suffix.
/// OMP and dcg both ship native `.exe` files on Windows rather than command
/// shims, so the same exact lookup is appropriate for doctor discovery.
fn which_executable(name: &str) -> Option<std::path::PathBuf> {
    // Probe for the platform-correct filename (`EXE_SUFFIX` is ".exe" on
    // Windows and empty on Unix), otherwise native executables appear missing.
    let exe_name = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let path = dir.join(&exe_name);
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
    let desired_hook = claude_dcg_hook()?;

    let registered = settings
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(|arr| arr.as_array())
        .is_some_and(|entries| {
            entries.iter().any(|entry| {
                is_exact_hook_entry_for_matcher(entry, CLAUDE_SHELL_MATCHER, &desired_hook)
            })
        });

    Ok(registered)
}

/// Ensure the DCG hook is registered in `~/.claude/settings.json` with the
/// current absolute executable path.
///
/// This is the self-healing mechanism that protects against Claude Code
/// silently overwriting `settings.json` mid-session (removing the DCG hook),
/// and against older PATH-dependent hook entries.
///
/// Called on every hook invocation when `general.self_heal_hook` is enabled. If
/// the hook entry is missing or stale, it is silently repaired and a warning
/// is emitted to stderr.
///
/// Design constraints:
/// - **Fail-open**: any error (IO, JSON parse, etc.) is swallowed — never
///   block command evaluation because of a self-heal failure.
/// - **Fast path**: if the hook is present, this is just a file read + JSON
///   parse + array scan (typically < 1ms).
/// - **Idempotent**: safe to call on every invocation.
pub fn ensure_hook_registered() {
    if let Err(e) = ensure_hook_registered_inner() {
        // Fail-open: log warning but never block the hook pipeline.
        eprintln!("[dcg] Warning: self-heal check failed: {e}");
    }
}

/// Inner implementation for `ensure_hook_registered` that returns errors
/// so the outer function can swallow them for fail-open behavior.
fn ensure_hook_registered_inner() -> Result<(), Box<dyn std::error::Error>> {
    let settings_path = claude_settings_path();
    let lock_path = self_heal_lock_path(&settings_path);
    ensure_hook_registered_at(&settings_path, &lock_path)
}

/// Path to the advisory lock file that serializes concurrent self-heal
/// writers of `settings_path`.
///
/// Lives in dcg's own config directory rather than `~/.claude` so dcg does
/// not litter Claude Code's directory with extra files — but the *name* is
/// derived from the protected file, not from the config directory. The config
/// directory moves with `XDG_CONFIG_HOME`/`DCG_CONFIG_DIR`, so a fixed
/// `selfheal.lock` let two processes with different environments heal the
/// same `settings.json` under two different locks and interleave their
/// read-modify-write. Keying the name to a stable hash of the canonicalized
/// settings path makes the lock follow the file it protects.
fn self_heal_lock_path(settings_path: &std::path::Path) -> std::path::PathBuf {
    use sha2::{Digest, Sha256};

    // Canonicalize so `~/.claude/settings.json` and a symlink/`..`-laden
    // spelling of the same file hash identically. A not-yet-existing path
    // falls back to its literal form (self-heal no-ops on it anyway).
    let canonical = std::fs::canonicalize(settings_path)
        .unwrap_or_else(|_| settings_path.to_path_buf())
        .to_string_lossy()
        .into_owned();
    let digest = Sha256::digest(canonical.as_bytes());
    let mut hex8 = String::with_capacity(8);
    for byte in digest.iter().take(4) {
        use std::fmt::Write as _;
        let _ = write!(hex8, "{byte:02x}");
    }
    config_dir().join(format!("selfheal-{hex8}.lock"))
}

/// True if `settings` already contains the exact desired dcg hook entry for
/// the Claude shell matcher.
fn settings_has_exact_dcg_hook(
    settings: &serde_json::Value,
    desired_hook: &serde_json::Value,
) -> bool {
    settings
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(|arr| arr.as_array())
        .is_some_and(|entries| {
            entries.iter().any(|entry| {
                is_exact_hook_entry_for_matcher(entry, CLAUDE_SHELL_MATCHER, desired_hook)
            })
        })
}

/// Try to take an exclusive advisory lock on `lock_path` with a small bounded
/// wait (same `fs2::FileExt` mechanism as the pending-exceptions store).
///
/// Returns `Ok(Some(file))` while holding the lock (released when the file is
/// dropped), or `Ok(None)` if the lock stayed contended past the bounded wait
/// — the caller should skip self-heal for this invocation rather than block
/// the hook pipeline; it reruns on the next invocation.
fn try_acquire_self_heal_lock(
    lock_path: &std::path::Path,
) -> Result<Option<std::fs::File>, Box<dyn std::error::Error>> {
    use fs2::FileExt;

    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(lock_path)?;

    const ATTEMPTS: u32 = 5;
    for attempt in 0..ATTEMPTS {
        // Treat any lock failure (WouldBlock or otherwise) as contention:
        // self-heal is best-effort and must never block command evaluation.
        if file.try_lock_exclusive().is_ok() {
            return Ok(Some(file));
        }
        if attempt + 1 < ATTEMPTS {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    Ok(None)
}

/// Atomically replace `path` with `content` using the same temp-file, fsync,
/// then rename idiom as `write_allowlist`: the temp file lives in the
/// target's own directory so the rename never crosses filesystems, and a
/// crash mid-write leaves the original file intact instead of
/// truncated/invalid JSON (which would make Claude Code silently drop ALL
/// hooks).
///
/// Two properties the naive temp+rename does NOT have, and that self-heal
/// must not silently take away from a user:
/// - **Symlinks are followed, not replaced.** `~/.claude/settings.json` is
///   very often a symlink into a dotfile manager (chezmoi, GNU stow, Nix home
///   manager). Renaming over the link would orphan the managed target and
///   silently detach the file from the user's source of truth, so the write
///   resolves the link first and replaces the real file.
/// - **Permissions are preserved.** settings.json can hold API keys in `env`
///   blocks; a `chmod 600` file must not come back world-readable 0644 just
///   because dcg repaired a hook entry.
fn write_settings_atomic(
    path: &std::path::Path,
    content: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    // Resolve symlinks so the rename lands on the real file, and so the temp
    // file shares its filesystem. A path that cannot be canonicalized (does
    // not exist yet) keeps its literal form.
    let target = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());

    let parent = target.parent().unwrap_or_else(|| std::path::Path::new("."));
    let temp_name = format!(".dcg-settings-{}.tmp", std::process::id());
    let temp_path = parent.join(&temp_name);

    // Every failure after this point must remove the temp file: a failed
    // write/sync used to leave `.dcg-settings-<pid>.tmp` behind forever.
    let write_result = (|| -> Result<(), Box<dyn std::error::Error>> {
        {
            let mut temp_file = std::fs::File::create(&temp_path)?;
            temp_file.write_all(content.as_bytes())?;
            temp_file.sync_all()?; // Ensure data is flushed to disk
        }

        copy_file_permissions(&target, &temp_path)?;

        // Atomic rename (on Unix this is atomic; on Windows `std::fs::rename`
        // replaces the existing file via MOVEFILE_REPLACE_EXISTING).
        std::fs::rename(&temp_path, &target)?;
        Ok(())
    })();

    if write_result.is_err() {
        // Clean up our own temp file so failed attempts don't accumulate.
        let _ = std::fs::remove_file(&temp_path);
    }

    write_result
}

/// Copy `from`'s permission bits onto `to` so an atomic temp+rename replace
/// does not silently widen a restrictive mode (e.g. a `chmod 600`
/// settings.json or allowlist).
///
/// A missing/unreadable source is not an error: there is nothing to preserve,
/// and the temp file's default mode is the correct outcome. On non-Unix this
/// is a no-op — Windows permissions live in ACLs that `std::fs` cannot carry
/// across, and `rename` does not reset them the way a fresh file would.
#[allow(clippy::unnecessary_wraps)] // the non-unix arm still needs the Result shape
fn copy_file_permissions(
    from: &std::path::Path,
    to: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        if let Ok(metadata) = std::fs::metadata(from) {
            std::fs::set_permissions(to, metadata.permissions())?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (from, to);
    }
    Ok(())
}

/// Path-parameterized core of `ensure_hook_registered_inner` (separated for
/// testability against an isolated settings/lock location).
fn ensure_hook_registered_at(
    settings_path: &std::path::Path,
    lock_path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if !settings_path.exists() {
        // No settings.json at all — nothing to heal. The user hasn't run
        // `dcg install` yet, or Claude Code hasn't been configured.
        return Ok(());
    }

    let desired_hook = claude_dcg_hook()?;

    // Fast path (lock-free): if the hook is present, nothing to do. This is
    // the common case on every hook invocation, so it stays a read + parse.
    let content = std::fs::read_to_string(settings_path)?;
    let settings: serde_json::Value = serde_json::from_str(&content)?;
    if settings_has_exact_dcg_hook(&settings, &desired_hook) {
        return Ok(());
    }

    // Repair needed — serialize concurrent self-healers so two dcg hook
    // processes cannot interleave read-modify-write and lose each other's
    // changes. If the lock stays contended, skip: another process is healing
    // right now, and this check reruns on the next hook invocation.
    let Some(_lock) = try_acquire_self_heal_lock(lock_path)? else {
        return Ok(());
    };

    // Re-read under the lock so the modification applies to the freshest
    // snapshot (a concurrent healer may have already repaired the file).
    let content = std::fs::read_to_string(settings_path)?;
    let mut settings: serde_json::Value = serde_json::from_str(&content)?;
    if settings_has_exact_dcg_hook(&settings, &desired_hook) {
        return Ok(());
    }

    // Hook was removed or still uses a stale/PATH-dependent command — repair it.
    let changed = install_dcg_hook_into_settings(&mut settings, false)?;
    if changed {
        let new_content = serde_json::to_string_pretty(&settings)?;
        write_settings_atomic(settings_path, &new_content)?;
        eprintln!(
            "[dcg] \x1b[1;33mWarning: DCG hook was missing or stale in {} — repaired automatically.\x1b[0m",
            settings_path.display()
        );
        eprintln!(
            "[dcg] \x1b[1;33mThis can mean Claude Code rewrote settings.json or an older hook relied on PATH.\x1b[0m"
        );
    }

    Ok(())
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
    /// Dcg hooks found with a matcher other than the Claude shell matcher.
    wrong_matcher_hooks: Vec<String>,
    /// Dcg hooks whose shape cannot synchronously enforce a block.
    misconfigured_hooks: Vec<String>,
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
            && self.misconfigured_hooks.is_empty()
            && self.missing_executable_hooks.is_empty()
    }

    fn has_issues(&self) -> bool {
        !self.settings_valid
            || self.dcg_hook_count == 0
            || self.dcg_hook_count > 1
            || !self.wrong_matcher_hooks.is_empty()
            || !self.misconfigured_hooks.is_empty()
            || !self.missing_executable_hooks.is_empty()
    }
}

fn hook_diagnostics_issue_count(diagnostics: &HookDiagnostics) -> usize {
    usize::from(diagnostics.settings_exists && diagnostics.has_issues())
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
    let desired_hook = claude_dcg_hook();

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
                    if matcher != Some(CLAUDE_SHELL_MATCHER) {
                        diag.wrong_matcher_hooks
                            .push(matcher.unwrap_or("(none)").to_string());
                    }

                    let hook_object = hook.as_object();
                    let expected_property_count = if cfg!(windows) { 3 } else { 2 };
                    let type_is_command =
                        hook.get("type").and_then(serde_json::Value::as_str) == Some("command");
                    let is_synchronous =
                        hook.get("async").and_then(serde_json::Value::as_bool) != Some(true);
                    let shell_is_safe = if cfg!(windows) {
                        hook.get("shell").and_then(serde_json::Value::as_str) == Some("powershell")
                    } else {
                        hook.get("shell").is_none()
                    };
                    let exact_owned_shape =
                        hook_object.is_some_and(|object| object.len() == expected_property_count);
                    if !type_is_command || !is_synchronous || !shell_is_safe || !exact_owned_shape {
                        diag.misconfigured_hooks.push(format!(
                            "{cmd} (expected a synchronous command hook with the platform-safe shell)"
                        ));
                    }
                    match &desired_hook {
                        Ok(expected) if hook != expected => {
                            diag.misconfigured_hooks.push(format!(
                                "{cmd} (hook does not invoke this dcg executable with \
                                 platform-safe quoting)"
                            ));
                        }
                        Err(error) => {
                            diag.misconfigured_hooks.push(format!(
                                "{cmd} (could not resolve the running dcg executable: {error})"
                            ));
                        }
                        Ok(_) => {}
                    }

                    // Resolve the executable token rather than testing the
                    // entire wrapper string (`& 'C:\...\dcg.exe'`). This also
                    // handles escaped apostrophes and legacy unquoted paths
                    // containing spaces.
                    if let Some(program) = dcg_command_program(cmd) {
                        let path = std::path::Path::new(&program);
                        if let Some(hint) = foreign_platform_hook_path(&program) {
                            // #264: a well-formed path for the *other*
                            // platform deserves its own diagnosis — the
                            // generic messages send users hunting the wrong
                            // cause.
                            diag.misconfigured_hooks.push(format!("{cmd} ({hint})"));
                        } else if !path.is_absolute() {
                            diag.misconfigured_hooks.push(format!(
                                "{cmd} (the hook executable must be an absolute path; \
                                 agent hook shells do not inherit the interactive PATH)"
                            ));
                        } else if !path.is_file() {
                            diag.missing_executable_hooks.push(program);
                        }
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
#[derive(Debug, Default)]
struct ConfigDiagnostics {
    loaded_sources: usize,
    source_errors: Vec<String>,
    source_warnings: Vec<String>,
    /// Unknown pack IDs in enabled list
    unknown_packs: Vec<String>,
    /// Override patterns that failed to compile
    invalid_override_patterns: Vec<(String, String)>, // (pattern, error)
    /// `[rules]` target exemptions that will not take effect (#284)
    rule_target_exemption_warnings: Vec<String>,
    /// Config keys that parse but were removed from the schema and are never
    /// enforced (#327: `overrides.allowlist`, `overrides.allowlist_rules`)
    removed_key_warnings: Vec<String>,
}

impl ConfigDiagnostics {
    fn has_errors(&self) -> bool {
        !self.source_errors.is_empty()
    }

    fn has_warnings(&self) -> bool {
        !self.source_warnings.is_empty()
            || !self.unknown_packs.is_empty()
            || !self.invalid_override_patterns.is_empty()
            || !self.rule_target_exemption_warnings.is_empty()
            || !self.removed_key_warnings.is_empty()
    }
}

fn config_source_diagnostic_message(source: &ConfigSourceOutcome) -> String {
    format!(
        "{}: {}",
        source.layer.label(),
        config_source_summary(source)
    )
}

/// Validate the effective configuration and the exact source outcomes returned
/// by the loader. No paths are reopened here, so doctor cannot disagree with
/// the decision that produced `config`.
fn validate_config_diagnostics(
    config: &Config,
    sources: &[ConfigSourceOutcome],
) -> ConfigDiagnostics {
    let mut diag = ConfigDiagnostics::default();

    for source in sources {
        match source.status {
            ConfigFileStatus::Loaded => diag.loaded_sources += 1,
            ConfigFileStatus::Missing if source.layer == ConfigFileLayer::Explicit => {
                diag.source_errors
                    .push(config_source_diagnostic_message(source));
            }
            ConfigFileStatus::Rejected | ConfigFileStatus::Invalid
                if source.layer == ConfigFileLayer::AutomaticProject =>
            {
                // Untrusted automatic policy is safely ignored; surface it so
                // users can repair the checkout without claiming it affected
                // effective policy.
                diag.source_warnings
                    .push(config_source_diagnostic_message(source));
            }
            ConfigFileStatus::Rejected | ConfigFileStatus::Invalid => {
                diag.source_errors
                    .push(config_source_diagnostic_message(source));
            }
            ConfigFileStatus::IgnoredUnsupported => {
                diag.source_warnings
                    .push(config_source_diagnostic_message(source));
            }
            ConfigFileStatus::Missing | ConfigFileStatus::Skipped => {}
        }
    }

    // Validate the merged, effective pack IDs. Automatic-project entries that
    // were filtered out never appear here and therefore cannot manufacture a
    // misleading doctor error.
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

    // Validate only effective override patterns for the same reason.
    let compiled = config.overrides.compile();
    for ip in &compiled.invalid_patterns {
        diag.invalid_override_patterns
            .push((ip.pattern.clone(), ip.error.clone()));
    }

    // A `[rules]` target exemption on an unsupported rule, or with an unusable
    // glob, is silently inert: the user keeps getting the denial they tried to
    // carve out. Surface it rather than leaving them unserved (#284).
    diag.rule_target_exemption_warnings = config.rule_target_exemption_warnings();

    // Removed config keys that still parse are indistinguishable from working
    // ones without a warning; surface them the same way inert exemptions are
    // (#327).
    diag.removed_key_warnings = config.overrides.removed_key_warnings();

    diag
}

/// Check if a pack ID is valid (exists in registry or is a registry category).
#[allow(dead_code)]
fn is_valid_pack_id(id: &str) -> bool {
    // Direct pack lookup
    if REGISTRY.get(id).is_some() {
        return true;
    }

    // Categories are registry metadata inferred from pack IDs. Deriving this
    // list keeps doctor in sync when a new category or curated preset lands.
    REGISTRY
        .all_categories()
        .into_iter()
        .any(|category| category == id)
}

/// Run a quick smoke test to verify the evaluator works.
///
/// Tests both an allow case and a deny case to ensure basic functionality.
#[allow(dead_code)]
fn run_smoke_test(config: &Config) -> bool {
    let mut enabled_packs = config.enabled_pack_ids();
    let mut enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let compiled_overrides = config.overrides.compile();
    let allowlists = crate::LayeredAllowlist::default();
    let heredoc_settings = config.heredoc_settings();

    // Load external packs from custom_paths (glob + tilde expansion).
    let external_paths = config.packs.expand_custom_paths();
    let external_store = load_external_packs(&external_paths);

    // Auto-enable external packs and merge their keywords.
    for id in external_store.pack_ids() {
        enabled_packs.insert(id.clone());
    }
    enabled_keywords.extend(external_store.keywords().iter().copied());

    // Build ordered pack list AFTER external packs are loaded.
    let mut ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    for id in external_store.pack_ids() {
        if !ordered_packs.contains(id) {
            ordered_packs.push(id.clone());
        }
    }
    // Disable keyword index when external packs are present.
    let keyword_index = if external_store.pack_ids().next().is_some() {
        None
    } else {
        REGISTRY.build_enabled_keyword_index(&ordered_packs)
    };

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

    // An inactive repository allowlist is intentionally absent from the
    // effective runtime stack, but doctor should still make that state visible
    // so users do not mistake a checked-in exception for active policy.
    let project_path = allowlist_path_for_layer(AllowlistLayer::Project);
    if project_path.exists() && !project_allowlist_is_trusted() {
        diag.layers_found += 1;
        diag.total_warnings += 1;
        diag.warning_messages.push(format!(
            "project: {} is inactive because repository policy is untrusted; review and select the repository .dcg.toml through DCG_CONFIG to activate it",
            project_path.display()
        ));
    }

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
            AllowlistLayer::Agent => continue,
            AllowlistLayer::Project => allowlist_path_for_layer(AllowlistLayer::Project),
            AllowlistLayer::User => crate::allowlist::user_allowlist_path(),
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
/// The default is always the user-owned layer. A repository-owned allowlist is
/// inactive unless the user explicitly trusts the repository policy, so
/// silently writing there would create an exception that runtime ignores.
fn resolve_layer(project: bool, user: bool) -> AllowlistLayer {
    if user {
        AllowlistLayer::User
    } else if project {
        AllowlistLayer::Project
    } else {
        AllowlistLayer::User
    }
}

fn project_allowlist_is_trusted() -> bool {
    std::env::current_dir()
        .ok()
        .is_some_and(|cwd| crate::config::explicitly_trusts_project_policy(&cwd))
}

fn ensure_allowlist_layer_is_writable(
    layer: AllowlistLayer,
) -> Result<(), Box<dyn std::error::Error>> {
    if layer != AllowlistLayer::Project || project_allowlist_is_trusted() {
        return Ok(());
    }

    let repo_root = find_repo_root_from_cwd()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let trust_path = repo_root.join(".dcg.toml");
    let descendant_glob = repo_root.join("**");
    Err(format!(
        "Project allowlists are inactive for untrusted repository contents. \
         Store the exception in the user layer, scoped to this repository root \
         and its descendants (for example `dcg allowlist add <rule> --user \
         --path \"{}\" --path \"{}\"`), or review the repository policy and \
         explicitly select it with `DCG_CONFIG={} ...` before using `--project`.",
        repo_root.display(),
        descendant_glob.display(),
        trust_path.display(),
    )
    .into())
}

#[derive(Debug)]
struct InspectedAllowlistLayer {
    loaded: crate::allowlist::LoadedAllowlistLayer,
    effective: bool,
}

/// Load the layers selected for an allowlist read operation.
///
/// Default reads expose only effective policy. An explicit `--project` is a
/// diagnostic request and therefore reads the raw repository file even when
/// that file is inactive; callers must surface `effective` in their output.
fn inspect_allowlist_layers(project_only: bool, user_only: bool) -> Vec<InspectedAllowlistLayer> {
    let project_trusted = project_allowlist_is_trusted();
    let selected = if project_only {
        vec![AllowlistLayer::Project]
    } else if user_only {
        vec![AllowlistLayer::User]
    } else if project_trusted {
        vec![AllowlistLayer::Project, AllowlistLayer::User]
    } else {
        vec![AllowlistLayer::User]
    };

    selected
        .into_iter()
        .map(|layer| {
            let path = allowlist_path_for_layer(layer);
            InspectedAllowlistLayer {
                loaded: crate::allowlist::LoadedAllowlistLayer {
                    layer,
                    path: path.clone(),
                    file: crate::allowlist::load_allowlist_file(layer, &path),
                },
                effective: layer != AllowlistLayer::Project || project_trusted,
            }
        })
        .collect()
}

/// Find the repo root from the current working directory.
fn find_repo_root_from_cwd() -> Option<std::path::PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    crate::config::find_repo_root(&cwd, crate::config::REPO_ROOT_SEARCH_MAX_HOPS)
}

/// Get the path to the allowlist file for a given layer.
fn allowlist_path_for_layer(layer: AllowlistLayer) -> std::path::PathBuf {
    match layer {
        AllowlistLayer::Agent => std::path::PathBuf::from("<agent-profile>"),
        AllowlistLayer::Project => std::env::current_dir().map_or_else(
            |_| std::path::PathBuf::from(".dcg").join("allowlist.toml"),
            |cwd| crate::allowlist::project_allowlist_path(&cwd),
        ),
        AllowlistLayer::User => crate::allowlist::user_allowlist_path(),
        AllowlistLayer::System => crate::config::system_config_dir().join("allowlist.toml"),
    }
}

/// Handle allowlist subcommand dispatch.
fn handle_allowlist_command(
    action: AllowlistAction,
    auto_prune_expired: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if auto_prune_expired && !matches!(action, AllowlistAction::Prune { .. }) {
        prune_allowlist_layers(false, false, false)?;
    }

    match action {
        AllowlistAction::Add {
            rule_id,
            reason,
            project,
            user,
            expires,
            conditions,
            paths,
        } => {
            let layer = resolve_layer(project, user);
            allowlist_add_rule_with_paths(
                &rule_id,
                &reason,
                layer,
                expires.as_deref(),
                &conditions,
                &paths,
            )?;
        }
        AllowlistAction::AddCommand {
            command,
            reason,
            project,
            user,
            expires,
            paths,
        } => {
            let layer = resolve_layer(project, user);
            if paths.is_empty() {
                allowlist_add_command(&command, &reason, layer, expires.as_deref())?;
            } else {
                allowlist_add_command_with_paths(
                    &command,
                    &reason,
                    layer,
                    expires.as_deref(),
                    &paths,
                )?;
            }
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
        AllowlistAction::Prune {
            project,
            user,
            dry_run,
            format,
        } => {
            allowlist_prune(project, user, dry_run, format)?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
/// Handle `dcg rebase-recover` — issue a short-lived permit that unblocks
/// `git checkout --` and `git restore` for the next recovery step.
///
/// The permit file lives in `.dcg/rebase-recovery-permit` at the repo
/// root (anchored to the nearest `.git/`), expires after `ttl` seconds
/// (default 120, hard-capped at 600 via the rebase_recovery module), and
/// is consumed after one successful allow.
fn handle_rebase_recover(
    ttl: Option<u64>,
    robot_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::rebase_recovery::{
        DEFAULT_PERMIT_TTL_SECS, MAX_PERMIT_TTL_SECS, is_rebase_in_progress, set_permit,
    };

    let cwd = std::env::current_dir().map_err(|e| format!("Cannot read current directory: {e}"))?;
    let ttl_secs = ttl.unwrap_or(DEFAULT_PERMIT_TTL_SECS);
    if ttl_secs == 0 {
        return Err("ttl must be at least 1 second".into());
    }
    let effective_ttl = ttl_secs.min(MAX_PERMIT_TTL_SECS);
    let path = set_permit(&cwd, effective_ttl)?;

    let rebase_active = is_rebase_in_progress(&cwd);

    if robot_mode {
        let status = if rebase_active {
            "rebase_in_progress"
        } else {
            "permit_issued"
        };
        println!(
            r#"{{"status":"{status}","permit_path":"{}","ttl_secs":{effective_ttl},"rebase_in_progress":{rebase_active}}}"#,
            path.display()
                .to_string()
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
        );
        return Ok(());
    }

    println!(
        "dcg rebase-recovery permit issued\n  \
         path:   {}\n  \
         ttl:    {effective_ttl}s\n  \
         scope:  core.git:checkout-discard, checkout-ref-discard, restore-worktree, restore-worktree-explicit\n\n\
         Next: retry `git checkout -- .` or `git restore <paths>` in this repo.\n\
         The permit is single-shot — the first matching allow consumes it.",
        path.display()
    );
    if rebase_active {
        println!(
            "\nNote: a rebase is already in progress (`.git/rebase-merge/` or `.git/rebase-apply/`).\n\
             The recovery patterns are already auto-allowed in this state, so the permit is redundant\n\
             here but harmless."
        );
    }
    if effective_ttl < ttl_secs {
        eprintln!(
            "Warning: requested ttl={ttl_secs}s exceeds max ({MAX_PERMIT_TTL_SECS}s); clamped to {effective_ttl}s."
        );
    }
    Ok(())
}

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

    // Confirmation needs a human, so establish that one can answer *before*
    // printing anything that could be mistaken for a granted allowance. An
    // agent-invoked `dcg allow-once <CODE>` inherits a closed stdin, so the
    // prompt read hit EOF and aborted only after the confirmation block had
    // already been printed — which read as a successful grant while the store
    // was never written (#262).
    let needs_prompt = !(cmd.yes || cmd.dry_run);
    if needs_prompt && !std::io::stdin().is_terminal() {
        return Err(format!(
            "Allow-once needs an interactive confirmation, but stdin is not a terminal, so the \
             answer can never arrive. NOTHING was written and '{code}' is still pending. Re-run \
             from a terminal, or confirm non-interactively with: dcg allow-once {code} --yes"
        )
        .into());
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

        if needs_prompt {
            if cmd.force && is_config_block {
                print!("Type 'FORCE' to confirm override: ");
                io::stdout().flush()?;
                let mut response = String::new();
                io::stdin().read_line(&mut response)?;
                if response.trim() != "FORCE" {
                    return Err("Aborted: no allow-once entry was written.".into());
                }
            } else {
                print!("Proceed? [y/N]: ");
                io::stdout().flush()?;
                let mut response = String::new();
                io::stdin().read_line(&mut response)?;
                let response = response.trim().to_lowercase();
                if response != "y" && response != "yes" {
                    return Err("Aborted: no allow-once entry was written.".into());
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

    // Short codes are 6-digit numeric strings (formerly 5; legacy codes still
    // accepted). Anything else is a hash prefix.
    let is_short_code = target.len() <= 6 && target.chars().all(|c| c.is_ascii_digit());

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
    allowlist_add_rule_with_paths(rule_id, reason, layer, expires, conditions, &[])
}

/// Return true if `pack_id` refers to a pack dcg knows about — a built-in pack
/// in the registry (matched exactly or as a group prefix, e.g. `kubernetes`
/// for `kubernetes.kubectl`) or an external pack declared via the config's
/// `custom_paths`. Used to reject allowlist rules that reference nonexistent
/// packs (issue #162).
fn pack_id_is_known(pack_id: &str) -> bool {
    // Allowlist-rule matching compares the rule's pack_id to a matched rule's
    // FULL concrete pack id exactly (see `allowlist.rs`: `rule_id.pack_id !=
    // pack_id`). A bare group prefix like `core` (for `core.git`) therefore
    // never matches anything, so it must NOT validate. `REGISTRY.get` is an
    // exact full-id lookup, which is precisely what we need (issue #162).
    if REGISTRY.get(pack_id).is_some() {
        return true;
    }

    // Synthetic `heredoc.<family>` namespaces are not registered packs, but
    // they are the concrete pack ids the evaluator attaches to embedded-code
    // AST denials and to the #261 unverifiable-sink rules
    // (`heredoc.python:shutil_rmtree`, `heredoc.posix:eval-dynamic`, …). The
    // allowlist engine matches them exactly, and the denials print
    // `dcg allowlist add '<that rule>'` as the remediation, so they must
    // validate here. A single `heredoc.<family>` component is required — a
    // bare `heredoc` group prefix would never match a concrete rule (issue
    // #162's rationale).
    if let Some(family) = pack_id.strip_prefix("heredoc.") {
        if !family.is_empty() && !family.contains('.') {
            return true;
        }
    }

    // Fall back to external packs declared in config `custom_paths`.
    let config = Config::load();
    let external = load_external_packs(&config.packs.expand_custom_paths());
    external.pack_ids().any(|id| id == pack_id)
}

/// Add a rule to the allowlist with optional path scoping.
fn allowlist_add_rule_with_paths(
    rule_id: &str,
    reason: &str,
    layer: AllowlistLayer,
    expires: Option<&str>,
    conditions: &[String],
    paths: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    ensure_allowlist_layer_is_writable(layer)?;

    // Validate rule ID format
    let parsed_rule = RuleId::parse(rule_id)
        .ok_or_else(|| format!("Invalid rule ID: {rule_id} (expected pack_id:pattern_name)"))?;

    // Reject rules that reference a pack dcg doesn't know about. Such entries
    // can never match anything and silently do nothing, which misleads users
    // into thinking they have allowlisted a command (issue #162).
    if !pack_id_is_known(&parsed_rule.pack_id) {
        return Err(format!(
            "Unknown pack ID '{}' in rule '{rule_id}'. The entry would never match anything. \
             Run `dcg packs --verbose` to see available pack IDs.",
            parsed_rule.pack_id
        )
        .into());
    }

    // Validate expiration date format if provided
    if let Some(exp) = expires {
        crate::allowlist::validate_expiration_date(exp)?;
    }

    // Validate condition formats
    for cond in conditions {
        crate::allowlist::validate_condition(cond)?;
    }

    // Validate path glob patterns
    for path in paths {
        crate::allowlist::validate_glob_pattern(path)?;
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
    let entry = if paths.is_empty() {
        build_rule_entry(&parsed_rule, reason, expires, conditions)
    } else {
        build_rule_entry_with_paths(&parsed_rule, reason, expires, conditions, paths)
    };
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
    allowlist_add_command_with_paths(command, reason, layer, expires, &[])
}

/// Add an exact command to the allowlist with optional path scoping.
fn allowlist_add_command_with_paths(
    command: &str,
    reason: &str,
    layer: AllowlistLayer,
    expires: Option<&str>,
    paths: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    ensure_allowlist_layer_is_writable(layer)?;

    // Validate expiration date format if provided
    if let Some(exp) = expires {
        crate::allowlist::validate_expiration_date(exp)?;
    }

    // Validate path glob patterns
    for path in paths {
        crate::allowlist::validate_glob_pattern(path)?;
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
    let entry = if paths.is_empty() {
        build_command_entry(command, reason, expires)
    } else {
        build_command_entry_with_paths(command, reason, expires, paths)
    };
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

    let inspected = inspect_allowlist_layers(project_only, user_only);
    let mut all_entries: Vec<(AllowlistLayer, std::path::PathBuf, AllowEntry, bool)> = Vec::new();

    for inspection in &inspected {
        if !inspection.loaded.path.exists() {
            continue;
        }

        for entry in &inspection.loaded.file.entries {
            all_entries.push((
                inspection.loaded.layer,
                inspection.loaded.path.clone(),
                entry.clone(),
                inspection.effective,
            ));
        }
    }

    let inspecting_inactive_project = inspected.iter().any(|inspection| {
        inspection.loaded.layer == AllowlistLayer::Project
            && inspection.loaded.path.exists()
            && !inspection.effective
    });

    match format {
        AllowlistOutputFormat::Pretty => {
            if inspecting_inactive_project {
                println!(
                    "{}",
                    "Status: INACTIVE — this repository allowlist is untrusted and does not affect decisions."
                        .yellow()
                );
                println!();
            }

            if all_entries.is_empty() {
                println!("{}", "No allowlist entries found.".yellow());
                return Ok(());
            }

            println!("{}", "Allowlist entries:".bold());
            println!();

            for (layer, path, entry, effective) in &all_entries {
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

                let layer_status = if *effective {
                    layer.label().to_string()
                } else {
                    format!("{}, INACTIVE (untrusted repository policy)", layer.label())
                };
                println!("  {selector_str} [{layer_status}]");
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
                .map(|(layer, path, entry, effective)| {
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
                        "effective": effective,
                        "status": if *effective { "effective" } else { "inactive_untrusted_project" },
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

    ensure_allowlist_layer_is_writable(layer)?;

    let path = allowlist_path_for_layer(layer);
    if !path.exists() {
        // Nothing to remove: report a failed removal (exit non-zero) so scripts
        // and CI can detect it, instead of silently succeeding (issue #163).
        return Err(format!(
            "No {} allowlist file found at {}",
            layer.label(),
            path.display()
        )
        .into());
    }

    let mut doc = load_or_create_allowlist_doc(&path)?;

    // Accept either a `pack_id:pattern_name` rule id OR an exact command string
    // (as written by `dcg allowlist add-command`). Try the rule form first when
    // the argument parses as one, then fall back to an exact-command match so
    // `add-command` entries are removable via the CLI (issue #161).
    let removed_rule =
        RuleId::parse(rule_id).is_some_and(|parsed| remove_rule_entry(&mut doc, &parsed));
    let removed = removed_rule || remove_command_entry(&mut doc, rule_id);

    if !removed {
        // The rule/command was not present: exit non-zero so a failed removal
        // is observable (issue #163).
        return Err(format!("{rule_id} not found in {} allowlist", layer.label()).into());
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

    let mut errors = 0;
    let mut warnings = 0;

    for inspection in inspect_allowlist_layers(project_only, user_only) {
        let loaded = inspection.loaded;
        if !loaded.path.exists() {
            continue;
        }

        println!(
            "{} allowlist: {}",
            loaded.layer.label().bold(),
            loaded.path.display()
        );
        if !inspection.effective {
            println!(
                "  {} Repository policy is untrusted; this file is inactive and is being validated for inspection only.",
                "INACTIVE:".yellow()
            );
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
            if matches!(entry.selector, AllowSelector::RegexPattern(_)) && !entry.risk_acknowledged
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

/// Remove expired entries from selected allowlist files.
fn allowlist_prune(
    project_only: bool,
    user_only: bool,
    dry_run: bool,
    format: AllowlistOutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let inactive_project_inspection = project_only && dry_run && !project_allowlist_is_trusted();
    let pruned = prune_allowlist_layers(project_only, user_only, dry_run)?;

    match format {
        AllowlistOutputFormat::Pretty => {
            if inactive_project_inspection {
                println!(
                    "{}",
                    "Status: INACTIVE — dry-run is inspecting an untrusted repository allowlist; no runtime policy is affected."
                        .yellow()
                );
                println!();
            }
            if pruned.is_empty() {
                println!("{}", "No expired allowlist entries found.".green());
                return Ok(());
            }

            let action = if dry_run { "Would prune" } else { "Pruned" };
            println!(
                "{} {} expired allowlist entr{}",
                "✓".green(),
                action,
                if pruned.len() == 1 { "y" } else { "ies" }
            );
            println!();

            for entry in &pruned {
                println!(
                    "  {} {} [{}]",
                    entry.selector_kind,
                    entry.selector_value,
                    entry.layer.label()
                );
                if let Some(reason) = &entry.reason {
                    println!("    Reason: {reason}");
                }
                if let Some(expires_at) = &entry.expires_at {
                    println!("    Expires: {expires_at}");
                }
                if let Some(ttl) = &entry.ttl {
                    println!("    TTL: {ttl}");
                }
                println!("    File: {}", entry.path.display());
            }
        }
        AllowlistOutputFormat::Json => {
            let entries: Vec<serde_json::Value> = pruned
                .iter()
                .map(|entry| {
                    serde_json::json!({
                        "layer": entry.layer.label(),
                        "path": entry.path.display().to_string(),
                        "index": entry.index,
                        "selector": {
                            "type": &entry.selector_kind,
                            "value": &entry.selector_value,
                        },
                        "reason": &entry.reason,
                        "expires_at": &entry.expires_at,
                        "ttl": &entry.ttl,
                        "added_at": &entry.added_at,
                    })
                })
                .collect();

            let output = serde_json::json!({
                "dry_run": dry_run,
                "project_policy_status": if project_only {
                    if project_allowlist_is_trusted() {
                        "effective"
                    } else {
                        "inactive_untrusted_project"
                    }
                } else {
                    "not_selected"
                },
                "pruned": entries.len(),
                "entries": entries,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrunedAllowlistEntry {
    index: usize,
    layer: AllowlistLayer,
    path: std::path::PathBuf,
    selector_kind: String,
    selector_value: String,
    reason: Option<String>,
    expires_at: Option<String>,
    ttl: Option<String>,
    added_at: Option<String>,
}

fn prune_allowlist_layers(
    project_only: bool,
    user_only: bool,
    dry_run: bool,
) -> Result<Vec<PrunedAllowlistEntry>, Box<dyn std::error::Error>> {
    let project_trusted = project_allowlist_is_trusted();
    if project_only && !dry_run {
        ensure_allowlist_layer_is_writable(AllowlistLayer::Project)?;
    }

    let layers: Vec<AllowlistLayer> = if project_only {
        vec![AllowlistLayer::Project]
    } else if user_only {
        vec![AllowlistLayer::User]
    } else if project_trusted {
        vec![AllowlistLayer::Project, AllowlistLayer::User]
    } else {
        vec![AllowlistLayer::User]
    };

    let mut pruned = Vec::new();

    for layer in layers {
        let path = allowlist_path_for_layer(layer);
        if !path.exists() {
            continue;
        }

        let mut doc = load_or_create_allowlist_doc(&path)?;
        let layer_pruned = prune_expired_allowlist_doc(&mut doc, layer, &path, dry_run);
        if !dry_run && !layer_pruned.is_empty() {
            write_allowlist(&path, &doc)?;
        }
        pruned.extend(layer_pruned);
    }

    Ok(pruned)
}

fn prune_expired_allowlist_doc(
    doc: &mut toml_edit::DocumentMut,
    layer: AllowlistLayer,
    path: &std::path::Path,
    dry_run: bool,
) -> Vec<PrunedAllowlistEntry> {
    let pruned = collect_expired_allowlist_entries(doc, layer, path);
    if dry_run || pruned.is_empty() {
        return pruned;
    }

    if let Some(arr) = doc
        .get_mut("allow")
        .and_then(toml_edit::Item::as_array_of_tables_mut)
    {
        for idx in pruned.iter().map(|entry| entry.index).rev() {
            arr.remove(idx);
        }
    }

    pruned
}

fn collect_expired_allowlist_entries(
    doc: &toml_edit::DocumentMut,
    layer: AllowlistLayer,
    path: &std::path::Path,
) -> Vec<PrunedAllowlistEntry> {
    let Some(arr) = doc
        .get("allow")
        .and_then(toml_edit::Item::as_array_of_tables)
    else {
        return Vec::new();
    };

    arr.iter()
        .enumerate()
        .filter_map(|(index, tbl)| {
            let expires_at = toml_item_string(tbl.get("expires_at"));
            let ttl = toml_item_string(tbl.get("ttl"));
            let added_at = toml_item_string(tbl.get("added_at"));

            if !crate::allowlist::is_expiration_expired(
                expires_at.as_deref(),
                ttl.as_deref(),
                added_at.as_deref(),
            ) {
                return None;
            }

            let (selector_kind, selector_value) = allowlist_table_selector(tbl);
            Some(PrunedAllowlistEntry {
                index,
                layer,
                path: path.to_path_buf(),
                selector_kind,
                selector_value,
                reason: toml_item_string(tbl.get("reason")),
                expires_at,
                ttl,
                added_at,
            })
        })
        .collect()
}

fn toml_item_string(item: Option<&toml_edit::Item>) -> Option<String> {
    let item = item?;
    if let Some(s) = item.as_str() {
        return Some(s.to_string());
    }
    item.as_datetime().map(ToString::to_string)
}

fn allowlist_table_selector(tbl: &toml_edit::Table) -> (String, String) {
    for (key, label) in [
        ("rule", "rule"),
        ("exact_command", "exact_command"),
        ("command_prefix", "command_prefix"),
        ("pattern", "pattern"),
    ] {
        if let Some(value) = toml_item_string(tbl.get(key)) {
            return (label.to_string(), value);
        }
    }

    ("unknown".to_string(), "<unknown>".to_string())
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

    // Preserve the existing file's permissions: a temp+rename replace
    // otherwise resets a deliberately restrictive mode (e.g. `chmod 600`) to
    // the process umask default.
    copy_file_permissions(path, &temp_path)?;

    // Create a backup before replacing the file so we can recover from write failures.
    let backup_path = backup_allowlist_file(path)?;

    // Atomic rename (on Unix, this is atomic; on Windows, it replaces atomically)
    std::fs::rename(&temp_path, path)?;

    // Validate final file and roll back if needed.
    let final_content = std::fs::read_to_string(path)?;
    if let Err(parse_err) = final_content.parse::<toml_edit::DocumentMut>() {
        if let Some(ref backup_path) = backup_path {
            std::fs::copy(backup_path, path)?;
        }
        return Err(format!(
            "Final allowlist verification failed after write (rolled back): {parse_err}"
        )
        .into());
    }

    Ok(())
}

fn backup_allowlist_file(
    path: &std::path::Path,
) -> Result<Option<std::path::PathBuf>, Box<dyn std::error::Error>> {
    if !path.exists() {
        return Ok(None);
    }

    let filename = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("allowlist.toml");
    let backup_name = format!(
        "{}.bak.{}",
        filename,
        Utc::now().format("%Y%m%dT%H%M%S%.6fZ")
    );
    let backup_path = path.with_file_name(backup_name);
    std::fs::copy(path, &backup_path)?;
    Ok(Some(backup_path))
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
    build_rule_entry_with_paths(rule_id, reason, expires, conditions, &[])
}

/// Build a new rule entry with optional path scoping.
fn build_rule_entry_with_paths(
    rule_id: &RuleId,
    reason: &str,
    expires: Option<&str>,
    conditions: &[String],
    paths: &[String],
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

    if !paths.is_empty() {
        let mut path_array = toml_edit::Array::new();
        for path in paths {
            path_array.push(path.as_str());
        }
        tbl.insert("paths", toml_edit::Item::Value(path_array.into()));
    }

    tbl
}

/// Build a new exact command entry.
fn build_command_entry(command: &str, reason: &str, expires: Option<&str>) -> toml_edit::Table {
    build_command_entry_with_paths(command, reason, expires, &[])
}

/// Build a new exact command entry with optional path scoping.
fn build_command_entry_with_paths(
    command: &str,
    reason: &str,
    expires: Option<&str>,
    paths: &[String],
) -> toml_edit::Table {
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

    if !paths.is_empty() {
        let mut path_array = toml_edit::Array::new();
        for path in paths {
            path_array.push(path.as_str());
        }
        tbl.insert("paths", toml_edit::Item::Value(path_array.into()));
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
    // Suggested trust grants default to the user-owned layer. Writing an
    // auto-discovered repository allowlist would produce an inactive entry and
    // invite a future checkout to smuggle policy into dcg.
    let layer = AllowlistLayer::User;

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

    // Suggested entries now live in the user layer. Retain cleanup support for
    // a project layer only when that repository policy is explicitly trusted;
    // an untrusted checkout must never induce an in-place policy rewrite.
    let mut layers_to_check = Vec::new();
    if project_allowlist_is_trusted() {
        layers_to_check.push((
            AllowlistLayer::Project,
            Some(allowlist_path_for_layer(AllowlistLayer::Project)),
        ));
    }
    layers_to_check.push((
        AllowlistLayer::User,
        Some(allowlist_path_for_layer(AllowlistLayer::User)),
    ));

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

/// Remove an exact-command entry from the document. Returns true if removed.
///
/// Mirrors [`remove_rule_entry`] but matches the `exact_command` field, so
/// entries created by `dcg allowlist add-command` can be removed via the CLI
/// (issue #161).
fn remove_command_entry(doc: &mut toml_edit::DocumentMut, command: &str) -> bool {
    let Some(allow) = doc.get_mut("allow") else {
        return false;
    };
    let Some(arr) = allow.as_array_of_tables_mut() else {
        return false;
    };

    let initial_len = arr.len();

    let mut remove_idx = None;
    for (idx, tbl) in arr.iter().enumerate() {
        if tbl
            .get("exact_command")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s == command)
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

    /// The shell startup check self-repairs a stale marker-guarded block
    /// instead of skipping it (the Unix analog of install.ps1's #282 fix).
    #[cfg(unix)]
    mod shell_check_repair {
        use super::super::{
            DCG_SHELL_CHECK_MARKER, DCG_SHELL_CHECK_SNIPPET, ShellCheckOutcome, inject_shell_check,
            repair_shell_check_region,
        };

        const STALE_BLOCK: &str = "\n# dcg: warn if hook was silently removed from Claude Code settings\nif command -v dcg >/dev/null && command -v jq >/dev/null; then\n  if jq -e 'OLD_STALE_EXPRESSION' \"$HOME/.claude/settings.json\" >/dev/null; then\n    echo OLD-WARNING\n  fi\nfi\n";

        #[test]
        fn fresh_rc_gets_snippet_appended() {
            let dir = tempfile::tempdir().expect("tempdir");
            let rc = dir.path().join(".zshrc");
            std::fs::write(&rc, "# fresh rc\n").unwrap();
            let outcome = inject_shell_check(&rc).expect("inject");
            assert_eq!(outcome, ShellCheckOutcome::Added);
            let content = std::fs::read_to_string(&rc).unwrap();
            assert!(content.contains(DCG_SHELL_CHECK_MARKER));
            assert!(content.contains("# fresh rc"));
        }

        #[test]
        fn current_snippet_is_left_untouched() {
            let dir = tempfile::tempdir().expect("tempdir");
            let rc = dir.path().join(".zshrc");
            std::fs::write(&rc, format!("# before\n{DCG_SHELL_CHECK_SNIPPET}")).unwrap();
            let before = std::fs::read_to_string(&rc).unwrap();
            let outcome = inject_shell_check(&rc).expect("inject");
            assert_eq!(outcome, ShellCheckOutcome::AlreadyCurrent);
            assert_eq!(
                std::fs::read_to_string(&rc).unwrap(),
                before,
                "an up-to-date RC file must be byte-identical after a re-run"
            );
        }

        #[test]
        fn stale_block_is_replaced_in_place() {
            let dir = tempfile::tempdir().expect("tempdir");
            let rc = dir.path().join(".zshrc");
            std::fs::write(
                &rc,
                format!("alias ll='ls -la'\n{STALE_BLOCK}\nafter_marker() {{ echo hi; }}\n"),
            )
            .unwrap();
            let outcome = inject_shell_check(&rc).expect("inject");
            assert_eq!(outcome, ShellCheckOutcome::Updated);
            let content = std::fs::read_to_string(&rc).unwrap();
            assert!(
                !content.contains("OLD_STALE_EXPRESSION"),
                "stale block text removed"
            );
            assert!(
                content.contains(DCG_SHELL_CHECK_SNIPPET.trim_start_matches('\n')),
                "current snippet present"
            );
            assert!(content.contains("alias ll"), "content before preserved");
            assert!(content.contains("after_marker"), "content after preserved");
            assert_eq!(
                content.matches(DCG_SHELL_CHECK_MARKER).count(),
                1,
                "marker appears exactly once after repair"
            );

            // And the repaired file is stable on the next run.
            let outcome = inject_shell_check(&rc).expect("inject");
            assert_eq!(outcome, ShellCheckOutcome::AlreadyCurrent);
        }

        #[test]
        fn mangled_block_falls_back_to_append() {
            let dir = tempfile::tempdir().expect("tempdir");
            let rc = dir.path().join(".zshrc");
            // Marker present but no column-0 `fi` — boundary unrecognizable.
            std::fs::write(
                &rc,
                "# dcg: warn if hook was silently removed from Claude Code settings\nif true; then\n  echo mangled\n",
            )
            .unwrap();
            let outcome = inject_shell_check(&rc).expect("inject");
            assert_eq!(outcome, ShellCheckOutcome::Updated);
            let content = std::fs::read_to_string(&rc).unwrap();
            assert!(
                content.contains(DCG_SHELL_CHECK_SNIPPET.trim_start_matches('\n')),
                "current snippet appended"
            );
            assert!(
                content.contains("echo mangled"),
                "remnant left, not corrupted"
            );
        }

        #[test]
        fn repair_region_rejects_interior_indented_fi() {
            // The interior `  fi` must NOT terminate the region — only the
            // column-0 `fi` does. A repair that stopped early would leave
            // trailing junk that breaks the RC file.
            let content = format!("{STALE_BLOCK}# after\n");
            let repaired = repair_shell_check_region(&content).expect("region found");
            assert!(!repaired.contains("OLD_STALE_EXPRESSION"));
            assert!(repaired.contains("# after"));
            assert!(!repaired.contains("echo OLD-WARNING"));
        }

        #[test]
        fn repair_region_returns_none_without_terminator() {
            let content = "# dcg: warn if hook was silently removed\nif true; then\n  echo x\n";
            assert!(repair_shell_check_region(content).is_none());
        }
    }

    struct BatchEvalContext {
        config: Config,
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
            config,
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
                let mut result = evaluate_batch_line(
                    &ctx.config,
                    line,
                    &ctx.enabled_keywords,
                    &ctx.ordered_packs,
                    ctx.keyword_index.as_ref(),
                    &ctx.compiled_overrides,
                    &ctx.allowlists,
                    &ctx.heredoc_settings,
                );
                result.index = index;
                result
            })
            .collect()
    }

    fn make_dcg_entry() -> serde_json::Value {
        let hook = claude_dcg_hook().expect("current executable resolves");
        serde_json::json!({
            "matcher": CLAUDE_SHELL_MATCHER,
            "hooks": [hook]
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
    fn claude_hook_command_is_platform_safe() {
        let executable = current_dcg_executable().expect("current executable");
        let hook = claude_dcg_hook().expect("hook generation");
        let command = hook["command"].as_str().expect("hook command");
        let parsed_program = dcg_command_program(command).expect("dcg program");
        assert_eq!(std::path::Path::new(&parsed_program), executable);

        #[cfg(windows)]
        {
            assert!(command.starts_with("& '"));
            assert_eq!(hook["shell"], "powershell");
        }

        #[cfg(not(windows))]
        {
            assert_ne!(command, "dcg");
            assert!(hook.get("shell").is_none());
        }
    }

    #[test]
    fn grok_hook_command_is_platform_safe() {
        let executable = current_dcg_executable().expect("current executable");
        let config = build_grok_hook_config().expect("Grok hook generation");
        let command = config["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .expect("Grok hook command");
        let parsed_program = dcg_command_program(command).expect("dcg program");
        assert_eq!(std::path::Path::new(&parsed_program), executable);
        assert_ne!(command, "dcg");
    }

    #[cfg(unix)]
    #[test]
    fn posix_hook_quoting_round_trips_shell_metacharacters() {
        let executable =
            std::path::Path::new("/tmp/space dollar$ backtick` quote\" slash\\ apostrophe'/dcg");
        let hook = claude_dcg_hook_for_executable(executable).expect("hook generation");
        let command = hook["command"].as_str().expect("hook command");
        assert_eq!(dcg_command_program(command).as_deref(), executable.to_str());
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", &format!("set -- {command}; printf %s \"$1\"")])
            .output()
            .expect("run /bin/sh");
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).expect("UTF-8 shell output"),
            executable.to_str().expect("UTF-8 fixture")
        );
    }

    #[test]
    fn dcg_hook_command_parser_handles_windows_quoting_and_legacy_spaces() {
        assert_eq!(
            dcg_command_program(r"& 'C:\Users\O''Brien\.local\bin\dcg.exe'"),
            Some(r"C:\Users\O'Brien\.local\bin\dcg.exe".to_string())
        );
        assert_eq!(
            dcg_command_program(r"C:\Users\Jane Doe\.local\bin\dcg.exe"),
            Some(r"C:\Users\Jane Doe\.local\bin\dcg.exe".to_string())
        );
        assert!(is_dcg_command(
            r"C:\Users\Jane Doe\.local\bin\dcg.EXE --flag"
        ));
        assert!(
            !is_dcg_command(r"C:\tools\runner.exe C:\Users\Jane Doe\.local\bin\dcg.exe"),
            "dcg used as another executable's argument is not a dcg-owned hook"
        );
        assert!(!is_dcg_command(r"& 'C:\unterminated\dcg.exe"));
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
    fn install_into_settings_replaces_bare_dcg_without_force() {
        let mut settings = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": CLAUDE_SHELL_MATCHER,
                    "hooks": [
                        { "type": "command", "command": "dcg" },
                        { "type": "command", "command": "coexisting-hook" }
                    ]
                }]
            }
        });

        let changed = install_dcg_hook_into_settings(&mut settings, false)
            .expect("bare hook migration succeeds");
        assert!(changed, "a PATH-dependent hook must be migrated");

        let entry = &settings["hooks"]["PreToolUse"][0];
        assert_eq!(entry["hooks"][0], claude_dcg_hook().expect("desired hook"));
        assert_eq!(entry["hooks"][1]["command"], "coexisting-hook");

        let command = entry["hooks"][0]["command"].as_str().expect("hook command");
        let program = dcg_command_program(command).expect("dcg executable");
        assert!(std::path::Path::new(&program).is_absolute());

        let changed_again =
            install_dcg_hook_into_settings(&mut settings, false).expect("second install succeeds");
        assert!(!changed_again, "absolute hook migration must be idempotent");
    }

    #[test]
    fn install_into_settings_migrates_legacy_bash_hook_without_widening_siblings() {
        let mut settings = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": LEGACY_CLAUDE_SHELL_MATCHER,
                    "hooks": [
                        { "type": "command", "command": "dcg" },
                        { "type": "command", "command": "bash-only-hook" }
                    ],
                    "customField": "preserve"
                }]
            }
        });

        let changed = install_dcg_hook_into_settings(&mut settings, false).expect("migration ok");
        assert!(changed, "legacy matcher should be migrated without --force");

        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(
            pre.iter().filter(|entry| is_dcg_hook_entry(entry)).count(),
            1
        );
        assert_eq!(pre[0]["matcher"], CLAUDE_SHELL_MATCHER);
        assert_eq!(pre[0]["hooks"][0], claude_dcg_hook().expect("desired hook"));

        let legacy = pre
            .iter()
            .find(|entry| entry["matcher"] == LEGACY_CLAUDE_SHELL_MATCHER)
            .expect("Bash-only sibling entry must remain");
        assert!(entry_has_hook_command(legacy, "bash-only-hook"));
        assert_eq!(legacy["customField"], "preserve");
        assert!(!entry_has_hook_command(legacy, "dcg"));
    }

    #[test]
    fn install_into_settings_repairs_dcg_hook_under_wrong_matcher() {
        let mut settings = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Write",
                    "hooks": [
                        { "type": "command", "command": "dcg" },
                        { "type": "command", "command": "write-only-hook" }
                    ],
                    "customField": "preserve"
                }]
            }
        });

        let changed = install_dcg_hook_into_settings(&mut settings, true).expect("repair ok");
        assert!(changed);
        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(
            pre.iter()
                .flat_map(|entry| entry["hooks"].as_array().into_iter().flatten())
                .filter(|hook| hook
                    .get("command")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(is_dcg_command))
                .count(),
            1
        );
        assert_eq!(pre[0]["matcher"], CLAUDE_SHELL_MATCHER);
        let write_entry = pre
            .iter()
            .find(|entry| entry["matcher"] == "Write")
            .expect("non-dcg sibling entry remains");
        assert!(entry_has_hook_command(write_entry, "write-only-hook"));
        assert_eq!(write_entry["customField"], "preserve");
    }

    #[test]
    fn install_into_settings_preserves_canonical_entry_metadata_and_siblings() {
        let mut settings = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": CLAUDE_SHELL_MATCHER,
                    "hooks": [{ "type": "command", "command": "other-hook" }],
                    "customField": "preserve"
                }]
            }
        });

        let changed = install_dcg_hook_into_settings(&mut settings, false).expect("install ok");
        assert!(changed);

        let entry = &settings["hooks"]["PreToolUse"][0];
        assert_eq!(entry["customField"], "preserve");
        assert_eq!(entry["hooks"][0], claude_dcg_hook().expect("desired hook"));
        assert_eq!(entry["hooks"][1]["command"], "other-hook");
    }

    #[test]
    fn install_into_settings_inserts_dcg_before_existing_hooks() {
        let other = serde_json::json!({
            "matcher": "Bash",
            "hooks": [{ "type": "command", "command": "other-hook" }]
        });
        let mut settings = serde_json::json!({
            "hooks": { "PreToolUse": [ other ] }
        });

        let changed = install_dcg_hook_into_settings(&mut settings, false).expect("install ok");
        assert!(changed);

        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert!(is_dcg_hook_entry(&pre[0]), "dcg hook should run first");
        assert!(entry_has_hook_command(&pre[1], "other-hook"));
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
        assert!(is_dcg_hook_entry(&pre[0]), "dcg hook should run first");
        assert!(
            pre.iter().any(|e| entry_has_hook_command(e, "other-hook")),
            "should retain other hook entry"
        );
    }

    #[test]
    fn install_into_settings_force_preserves_coexisting_hook_in_same_entry() {
        let mut settings = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [
                        { "type": "command", "command": "dcg" },
                        { "type": "command", "command": "other-hook" }
                    ]
                }]
            }
        });

        let changed = install_dcg_hook_into_settings(&mut settings, true).expect("install ok");
        assert!(changed);

        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.iter().filter(|e| is_dcg_hook_entry(e)).count(), 1);
        assert!(is_dcg_hook_entry(&pre[0]), "dcg hook should run first");
        assert!(
            pre.iter().any(|e| entry_has_hook_command(e, "other-hook")),
            "force reinstall should retain non-dcg hooks from mixed hook entries"
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
    fn install_into_settings_refuses_malformed_legacy_matcher_hooks() {
        let mut settings = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": LEGACY_CLAUDE_SHELL_MATCHER,
                    "hooks": { "not": "an array" }
                }]
            }
        });
        let original = settings.clone();

        let err = install_dcg_hook_into_settings(&mut settings, false)
            .expect_err("malformed legacy entry must fail closed");
        assert!(err.to_string().contains("legacy Bash matcher hooks"));
        assert_eq!(
            settings, original,
            "in-memory settings must remain unchanged on validation failure"
        );
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
    fn uninstall_from_settings_preserves_coexisting_hook_in_same_entry() {
        let mut settings = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [
                        { "type": "command", "command": "dcg" },
                        { "type": "command", "command": "other-hook" }
                    ]
                }]
            }
        });

        let removed = uninstall_dcg_hook_from_settings(&mut settings).expect("uninstall ok");
        assert!(removed);

        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1, "should keep the mixed entry for other hooks");
        assert!(!is_dcg_hook_entry(&pre[0]));
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
    fn test_cli_parse_packs_pattern_tree_controls() {
        let cli = Cli::parse_from(["dcg", "packs", "--expand", "--max-patterns", "6"]);
        if let Some(Command::ListPacks {
            expand,
            max_patterns,
            ..
        }) = cli.command
        {
            assert!(expand);
            assert_eq!(max_patterns, 6);
        } else {
            unreachable!("Expected ListPacks");
        }
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
            assert_eq!(command.as_deref(), Some("git reset --hard"));
        } else {
            unreachable!("Expected TestCommand command");
        }
    }

    #[test]
    fn test_cli_parse_test_from_stdin() {
        let cli = Cli::try_parse_from(["dcg", "test", "--stdin"]).expect("parse --stdin");
        if let Some(Command::TestCommand { command, stdin, .. }) = cli.command {
            assert!(command.is_none());
            assert!(stdin);
        } else {
            unreachable!("Expected TestCommand command");
        }
        assert!(Cli::try_parse_from(["dcg", "test"]).is_err());
        assert!(Cli::try_parse_from(["dcg", "test", "--stdin", "git status"]).is_err());
    }

    #[test]
    fn test_cli_parse_init() {
        let cli = Cli::parse_from(["dcg", "init"]);
        assert!(matches!(cli.command, Some(Command::Init { .. })));
    }

    #[test]
    fn test_cli_parse_init_auto() {
        let cli = Cli::parse_from(["dcg", "init", "--auto"]);
        if let Some(Command::Init { auto, dry_run, .. }) = cli.command {
            assert!(auto);
            assert!(!dry_run);
        } else {
            unreachable!("Expected Init command");
        }
    }

    #[test]
    fn test_cli_parse_init_dry_run() {
        let cli = Cli::parse_from(["dcg", "init", "--dry-run"]);
        if let Some(Command::Init { dry_run, auto, .. }) = cli.command {
            assert!(dry_run);
            assert!(!auto);
        } else {
            unreachable!("Expected Init command");
        }
    }

    #[test]
    fn test_cli_parse_init_auto_with_project_dir() {
        let cli = Cli::parse_from(["dcg", "init", "--auto", "--project-dir", "/tmp/myproject"]);
        if let Some(Command::Init {
            auto, project_dir, ..
        }) = cli.command
        {
            assert!(auto);
            assert_eq!(project_dir.as_deref(), Some("/tmp/myproject"));
        } else {
            unreachable!("Expected Init command");
        }
    }

    #[test]
    fn test_detect_project_packs_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let detections = detect_project_packs(tmp.path());
        assert!(
            detections.is_empty(),
            "Empty dir should produce no detections"
        );
    }

    #[test]
    fn test_detect_project_packs_dockerfile() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("Dockerfile"), "FROM alpine").unwrap();
        let detections = detect_project_packs(tmp.path());
        assert!(
            detections
                .iter()
                .map(|d| d.pack_id.as_str())
                .any(|x| x == "containers.docker"),
            "Should detect Docker from Dockerfile"
        );
    }

    #[test]
    fn test_detect_project_packs_compose() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("docker-compose.yml"), "version: '3'").unwrap();
        let detections = detect_project_packs(tmp.path());
        assert!(
            detections
                .iter()
                .map(|d| d.pack_id.as_str())
                .any(|x| x == "containers.compose"),
            "Should detect compose"
        );
        assert!(
            detections
                .iter()
                .map(|d| d.pack_id.as_str())
                .any(|x| x == "containers.docker"),
            "Should also detect docker from compose"
        );
    }

    #[test]
    fn test_detect_project_packs_terraform() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("main.tf"), "resource {}").unwrap();
        let detections = detect_project_packs(tmp.path());
        assert!(
            detections
                .iter()
                .map(|d| d.pack_id.as_str())
                .any(|x| x == "infrastructure.terraform"),
            "Should detect terraform from main.tf"
        );
    }

    #[test]
    fn test_detect_project_packs_atmos() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("atmos.yaml"), "base_path: .").unwrap();
        let detections = detect_project_packs(tmp.path());
        assert!(
            detections
                .iter()
                .map(|d| d.pack_id.as_str())
                .any(|x| x == "infrastructure.atmos"),
            "Should detect atmos from atmos.yaml"
        );
    }

    #[test]
    fn test_detect_project_packs_github_actions() {
        let tmp = tempfile::tempdir().unwrap();
        let workflows = tmp.path().join(".github").join("workflows");
        std::fs::create_dir_all(&workflows).unwrap();
        std::fs::write(workflows.join("ci.yml"), "on: push").unwrap();
        let detections = detect_project_packs(tmp.path());
        assert!(
            detections
                .iter()
                .map(|d| d.pack_id.as_str())
                .any(|x| x == "cicd.github_actions"),
            "Should detect GitHub Actions"
        );
    }

    #[test]
    fn test_detect_project_packs_kubernetes() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("k8s")).unwrap();
        std::fs::write(tmp.path().join("Chart.yaml"), "apiVersion: v2").unwrap();
        let detections = detect_project_packs(tmp.path());
        assert!(
            detections
                .iter()
                .map(|d| d.pack_id.as_str())
                .any(|x| x == "kubernetes.kubectl"),
            "Should detect kubectl from k8s/"
        );
        assert!(
            detections
                .iter()
                .map(|d| d.pack_id.as_str())
                .any(|x| x == "kubernetes.helm"),
            "Should detect helm from Chart.yaml"
        );
    }

    #[test]
    fn test_detect_project_packs_db_from_package_json() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"pg":"^8.0.0","mongoose":"^7.0.0"}}"#,
        )
        .unwrap();
        let detections = detect_project_packs(tmp.path());
        assert!(
            detections
                .iter()
                .map(|d| d.pack_id.as_str())
                .any(|x| x == "database.postgresql"),
            "Should detect postgres from pg dep"
        );
        assert!(
            detections
                .iter()
                .map(|d| d.pack_id.as_str())
                .any(|x| x == "database.mongodb"),
            "Should detect mongo from mongoose dep"
        );
        assert!(
            detections
                .iter()
                .map(|d| d.pack_id.as_str())
                .any(|x| x == "package_managers"),
            "Should detect package_managers from package.json"
        );
    }

    #[test]
    fn test_detect_project_packs_cloud_aws() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("serverless.yml"), "service: myapp").unwrap();
        let detections = detect_project_packs(tmp.path());
        assert!(
            detections
                .iter()
                .map(|d| d.pack_id.as_str())
                .any(|x| x == "cloud.aws"),
            "Should detect AWS from serverless.yml"
        );
    }

    #[test]
    fn test_detect_project_packs_cloud_gcp() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("cloudbuild.yaml"), "steps:").unwrap();
        let detections = detect_project_packs(tmp.path());
        assert!(
            detections
                .iter()
                .map(|d| d.pack_id.as_str())
                .any(|x| x == "cloud.gcp"),
            "Should detect GCP from cloudbuild.yaml"
        );
    }

    #[test]
    fn test_detect_project_packs_no_duplicates() {
        let tmp = tempfile::tempdir().unwrap();
        // Multiple docker-related files should only yield one containers.docker entry
        std::fs::write(tmp.path().join("Dockerfile"), "FROM alpine").unwrap();
        std::fs::write(tmp.path().join("docker-compose.yml"), "version: '3'").unwrap();
        let detections = detect_project_packs(tmp.path());
        let docker_count = detections
            .iter()
            .filter(|d| d.pack_id == "containers.docker")
            .count();
        assert_eq!(docker_count, 1, "Should deduplicate containers.docker");
    }

    #[test]
    fn test_generate_config_with_packs() {
        let packs = vec![
            "containers.docker".to_string(),
            "database.postgresql".to_string(),
        ];
        let config = generate_config_with_packs(&packs);
        assert!(config.contains("containers.docker"));
        assert!(config.contains("database.postgresql"));
        assert!(config.contains("[packs]"));
        assert!(config.contains("dcg init --auto"));
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

    #[test]
    fn test_cli_parse_update_no_configure() {
        let cli = Cli::parse_from(["dcg", "update", "--no-configure"]);
        if let Some(Command::Update(update)) = cli.command {
            assert!(update.no_configure);
        } else {
            unreachable!("Expected Update command");
        }
    }

    #[test]
    fn test_cli_parse_update_binary_only_alias() {
        let cli = Cli::parse_from(["dcg", "update", "--binary-only"]);
        if let Some(Command::Update(update)) = cli.command {
            assert!(update.no_configure, "--binary-only should set no_configure");
        } else {
            unreachable!("Expected Update command");
        }
    }

    #[test]
    fn test_normalize_release_tag_adds_v_prefix() {
        assert_eq!(normalize_release_tag("0.2.0").unwrap(), "v0.2.0");
        assert_eq!(normalize_release_tag("v0.2.0").unwrap(), "v0.2.0");
    }

    #[test]
    fn test_update_installer_tag_prefers_requested_version() {
        assert_eq!(update_installer_tag(Some("0.2.0")).unwrap(), "v0.2.0");
        assert_eq!(update_installer_tag(Some("v0.2.0")).unwrap(), "v0.2.0");
    }

    #[test]
    fn test_update_installer_tag_defaults_to_latest_version() {
        assert_eq!(
            update_installer_tag_from_versions(None, "0.9.0").unwrap(),
            "v0.9.0"
        );
        assert_eq!(
            update_installer_tag_from_versions(None, "v0.9.0").unwrap(),
            "v0.9.0"
        );
    }

    #[test]
    fn test_update_installer_tag_errors_when_latest_unknown() {
        let err = update_installer_tag_from_check_result(None, Err("network unavailable"))
            .expect_err("default update must not silently reinstall current version");
        assert!(
            err.to_string().contains("Failed to resolve latest release"),
            "{err}"
        );
    }

    #[test]
    fn test_update_installer_tag_allows_requested_version_when_latest_unknown() {
        assert_eq!(
            update_installer_tag_from_check_result(Some("0.2.0"), Err("network unavailable"))
                .unwrap(),
            "v0.2.0"
        );
    }

    #[test]
    fn test_update_installer_tag_rejects_non_semver_tags() {
        assert!(update_installer_tag(Some("../../main")).is_err());
        assert!(update_installer_tag(Some("main")).is_err());
    }

    #[test]
    fn windows_update_runner_waits_before_replacing_the_binary() {
        let wait = WINDOWS_UPDATE_RUNNER
            .find("Wait-Process")
            .expect("runner must wait for the locked parent binary");
        let install = WINDOWS_UPDATE_RUNNER
            .find("& powershell.exe")
            .expect("runner must invoke the verified installer");
        assert!(wait < install);
        assert!(WINDOWS_UPDATE_RUNNER.contains("if ($null -ne $parentProcess)"));
        assert!(WINDOWS_UPDATE_RUNNER.contains("ConvertFrom-Json"));
        assert!(
            WINDOWS_UPDATE_RUNNER
                .contains("$configuration.installer_arguments | ForEach-Object { [string]$_ }"),
            "PowerShell 5.1 JSON arrays must be explicitly enumerated into argv"
        );
        assert!(
            WINDOWS_UPDATE_RUNNER.contains("[AllowEmptyString()]"),
            "installer output may contain blank lines"
        );
        assert!(WINDOWS_UPDATE_RUNNER.contains("Remove-Item -LiteralPath $cleanupDirectory"));
        assert!(WINDOWS_UPDATE_RUNNER.contains("dcg update completed successfully."));
    }

    #[test]
    fn windows_update_uses_cim_worker_that_survives_parent_jobs() {
        assert!(WINDOWS_UPDATE_CIM_LAUNCHER.contains("Invoke-CimMethod"));
        assert!(WINDOWS_UPDATE_CIM_LAUNCHER.contains("Win32_Process"));
        assert!(WINDOWS_UPDATE_CIM_LAUNCHER.contains("MethodName Create"));
        assert!(WINDOWS_UPDATE_CIM_LAUNCHER.contains("ReturnValue"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_update_runner_parses_in_windows_powershell() {
        let temp = tempfile::tempdir().unwrap();
        let runner = temp.path().join("run-update-after-exit.ps1");
        std::fs::write(&runner, WINDOWS_UPDATE_RUNNER).unwrap();
        let parser_probe = r"$tokens = $null
$errors = $null
[Management.Automation.Language.Parser]::ParseFile(
  $env:DCG_UPDATE_RUNNER_PARSE_PATH,
  [ref]$tokens,
  [ref]$errors
) | Out-Null
if ($errors.Count -ne 0) {
  $errors | ForEach-Object { Write-Error ([string]$_) }
  exit 1
}";
        let output = std::process::Command::new("powershell.exe")
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-Command")
            .arg(parser_probe)
            .env("DCG_UPDATE_RUNNER_PARSE_PATH", &runner)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "runner parse failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn windows_update_worker_command_quotes_paths_with_spaces() {
        let runner = std::path::Path::new(r"C:\Users\Jane Doe\AppData\Local\Temp\dcg\runner.ps1");
        assert_eq!(
            windows_update_worker_command_line(runner).unwrap(),
            r#"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\Users\Jane Doe\AppData\Local\Temp\dcg\runner.ps1""#
        );
        assert!(
            windows_update_worker_command_line(std::path::Path::new(
                "C:\\invalid\"path\\runner.ps1"
            ))
            .is_err()
        );
    }

    #[test]
    fn windows_update_preserves_installer_argv_and_no_configure() {
        let cli = Cli::parse_from([
            "dcg",
            "update",
            "--version",
            "v0.7.3",
            "--dest",
            r"C:\Program Files\dcg",
            "--verify",
            "--no-configure",
        ]);
        let Some(Command::Update(update)) = cli.command else {
            unreachable!("Expected Update command");
        };
        assert_eq!(
            windows_update_installer_arguments(&update, "v0.7.3"),
            vec![
                "-Version",
                "v0.7.3",
                "-Dest",
                r"C:\Program Files\dcg",
                "-Verify",
                "-NoConfigure",
            ]
        );
    }

    #[test]
    fn test_cli_parse_install_project() {
        let cli = Cli::parse_from(["dcg", "install", "--project"]);
        if let Some(Command::Install {
            force,
            project,
            grok,
            agy,
            opencode,
            omp,
        }) = cli.command
        {
            assert!(!force);
            assert!(project);
            assert!(!grok);
            assert!(!agy);
            assert!(!opencode);
            assert!(!omp);
        } else {
            unreachable!("Expected Install command");
        }
    }

    #[test]
    fn test_cli_parse_install_force_and_project() {
        let cli = Cli::parse_from(["dcg", "install", "--force", "--project"]);
        if let Some(Command::Install {
            force,
            project,
            grok,
            agy,
            opencode,
            omp,
        }) = cli.command
        {
            assert!(force);
            assert!(project);
            assert!(!grok);
            assert!(!agy);
            assert!(!opencode);
            assert!(!omp);
        } else {
            unreachable!("Expected Install command");
        }
    }

    #[test]
    fn test_cli_parse_install_grok() {
        let cli = Cli::parse_from(["dcg", "install", "--grok"]);
        if let Some(Command::Install {
            force,
            project,
            grok,
            agy,
            opencode,
            omp,
        }) = cli.command
        {
            assert!(!force);
            assert!(!project);
            assert!(grok);
            assert!(!agy);
            assert!(!opencode);
            assert!(!omp);
        } else {
            unreachable!("Expected Install command");
        }
    }

    #[test]
    fn test_cli_parse_install_grok_with_project() {
        let cli = Cli::parse_from(["dcg", "install", "--grok", "--project"]);
        if let Some(Command::Install {
            force,
            project,
            grok,
            agy,
            opencode,
            omp,
        }) = cli.command
        {
            assert!(!force);
            assert!(project);
            assert!(grok);
            assert!(!agy);
            assert!(!opencode);
            assert!(!omp);
        } else {
            unreachable!("Expected Install command");
        }
    }

    #[test]
    fn test_cli_parse_install_agy() {
        let cli = Cli::parse_from(["dcg", "install", "--agy"]);
        if let Some(Command::Install {
            force,
            project,
            grok,
            agy,
            opencode,
            omp,
        }) = cli.command
        {
            assert!(!force);
            assert!(!project);
            assert!(!grok);
            assert!(agy);
            assert!(!opencode);
            assert!(!omp);
        } else {
            unreachable!("Expected Install command");
        }
    }

    #[test]
    fn test_cli_parse_install_agy_with_project() {
        let cli = Cli::parse_from(["dcg", "install", "--agy", "--project"]);
        if let Some(Command::Install {
            force,
            project,
            grok,
            agy,
            opencode,
            omp,
        }) = cli.command
        {
            assert!(!force);
            assert!(project);
            assert!(!grok);
            assert!(agy);
            assert!(!opencode);
            assert!(!omp);
        } else {
            unreachable!("Expected Install command");
        }
    }

    #[test]
    fn test_cli_parse_install_opencode() {
        let cli = Cli::parse_from(["dcg", "install", "--opencode"]);
        if let Some(Command::Install {
            force,
            project,
            grok,
            agy,
            opencode,
            omp,
        }) = cli.command
        {
            assert!(!force);
            assert!(!project);
            assert!(!grok);
            assert!(!agy);
            assert!(opencode);
            assert!(!omp);
        } else {
            unreachable!("Expected Install command");
        }
    }

    #[test]
    fn test_cli_parse_install_opencode_with_force() {
        let cli = Cli::parse_from(["dcg", "install", "--opencode", "--force"]);
        if let Some(Command::Install {
            force,
            project,
            grok,
            agy,
            opencode,
            omp,
        }) = cli.command
        {
            assert!(force);
            assert!(!project);
            assert!(!grok);
            assert!(!agy);
            assert!(opencode);
            assert!(!omp);
        } else {
            unreachable!("Expected Install command");
        }
    }

    #[test]
    fn test_cli_parse_install_omp_with_project_and_force() {
        let cli = Cli::parse_from(["dcg", "install", "--omp", "--project", "--force"]);
        if let Some(Command::Install {
            force,
            project,
            grok,
            agy,
            opencode,
            omp,
        }) = cli.command
        {
            assert!(force);
            assert!(project);
            assert!(!grok);
            assert!(!agy);
            assert!(!opencode);
            assert!(omp);
        } else {
            unreachable!("Expected Install command");
        }
    }

    #[test]
    fn install_agent_targets_are_mutually_exclusive() {
        for (left, right) in [
            ("--grok", "--agy"),
            ("--grok", "--opencode"),
            ("--grok", "--omp"),
            ("--agy", "--opencode"),
            ("--agy", "--omp"),
            ("--opencode", "--omp"),
        ] {
            assert!(
                Cli::try_parse_from(["dcg", "install", left, right]).is_err(),
                "install must reject conflicting targets {left} and {right}"
            );
        }
    }

    /// #318: the generated OpenCode plugin embeds the absolute dcg path as a
    /// JSON string literal (never a bare PATH lookup, never shell-quoted) and
    /// carries the ownership marker the installer/uninstaller key on.
    #[test]
    fn opencode_plugin_source_embeds_absolute_path_and_marker() {
        let executable = current_dcg_executable().expect("current executable");
        let source = build_opencode_plugin_source(&executable).expect("plugin generation");

        assert!(
            source.contains(OPENCODE_PLUGIN_MARKER),
            "generated plugin must carry the ownership marker"
        );
        assert!(
            source.contains("\"tool.execute.before\""),
            "plugin must register OpenCode's tool.execute.before hook"
        );

        // Extract the embedded literal and prove it round-trips to the exact
        // executable path through a JSON parser (JS string semantics).
        let line = source
            .lines()
            .find(|l| l.starts_with("const DCG_BIN = "))
            .expect("plugin embeds DCG_BIN");
        let literal = line
            .trim_start_matches("const DCG_BIN = ")
            .trim_end_matches(';');
        let parsed: String = serde_json::from_str(literal).expect("valid JSON string literal");
        assert_eq!(std::path::Path::new(&parsed), executable);
        assert_ne!(parsed, "dcg", "never a bare PATH lookup");
        // An `ask` verdict must fail closed (OpenCode has no review UI).
        assert!(source.contains("verdict === \"deny\" || verdict === \"ask\""));
    }

    #[test]
    fn omp_extension_source_has_native_blocking_contract() {
        let executable = current_dcg_executable().expect("current executable");
        let source = build_omp_extension_source(&executable).expect("extension generation");

        assert!(source.contains(OMP_EXTENSION_MARKER));
        assert!(source.contains("pi.on(\"tool_call\""));
        assert!(source.contains("event.toolName !== \"bash\""));
        assert!(source.contains("\"--robot\", \"test\", \"--stdin\""));
        assert!(source.contains("\"--agent\", \"omp\""));
        assert!(source.contains("\"deny\", \"ask\", \"indeterminate\""));
        assert!(source.contains("return { block: true, reason:"));
        assert!(source.contains("classifyDcgChild("));
        assert!(
            source.contains(
                "import { resolveToCwd } from \"@oh-my-pi/pi-coding-agent/tools/path-utils\";"
            ),
            "the bridge must use OMP's own cwd resolver so tilde, absolute, relative, and workspace-root aliases match bash execution"
        );
        assert!(
            source.contains(
                "import { extractLeadingCdTarget } from \"@oh-my-pi/pi-coding-agent/tools/shell-tokenize\";"
            ),
            "OMP also derives cwd from a leading cd prefix when the structured cwd is absent"
        );
        assert!(
            source.contains("pi.on(\"tool_call\", async (event, ctx) =>"),
            "the callback context carries OMP's session cwd"
        );
        assert!(
            source.contains(
                "const requestedCwd = structuredCwd || extractLeadingCdTarget(command)?.path;"
            ),
            "the structured cwd must win, with OMP's exact leading-cd derivation as fallback"
        );
        assert!(
            source.contains(
                "commandCwd = requestedCwd ? resolveToCwd(requestedCwd, ctx.cwd) : ctx.cwd;"
            ),
            "each effective bash cwd must be resolved against the callback's session cwd"
        );
        assert!(
            source.contains("cwd: commandCwd,"),
            "dcg must run in the same effective cwd as the guarded bash call"
        );

        let line = source
            .lines()
            .find(|line| line.starts_with("const DCG_BIN = "))
            .expect("extension embeds DCG_BIN");
        let literal = line
            .trim_start_matches("const DCG_BIN = ")
            .trim_end_matches(';');
        let parsed: String = serde_json::from_str(literal).expect("valid JSON string literal");
        assert_eq!(std::path::Path::new(&parsed), executable);
        assert_ne!(parsed, "dcg", "never a bare PATH lookup");
    }

    /// OMP's ordinary agent-loop path validates BashToolInput before emitting
    /// `tool_call`, but the extension wrapper also supports direct/non-loop
    /// dispatch. Keep the generated boundary total over adversarial runtime
    /// shapes: ignore other tools, block an identifiable malformed bash call,
    /// preserve OMP's valid empty-string no-op, and evaluate every non-empty
    /// string (including whitespace) without trimming it into an exemption.
    #[test]
    fn omp_extension_source_structurally_classifies_tool_calls() {
        let executable = current_dcg_executable().expect("current executable");
        let source = build_omp_extension_source(&executable).expect("extension generation");

        assert!(source.contains("type OmpToolCallClassification ="));
        assert!(source.contains(
            "export function classifyOmpToolCall(event: unknown): OmpToolCallClassification"
        ));
        assert!(source.contains(
            r#"if (typeof event !== "object" || event === null || Array.isArray(event)) return { kind: "other-tool" };"#
        ));
        assert!(
            source.contains(r#"if (record.toolName !== "bash") return { kind: "other-tool" };"#)
        );
        assert!(source.contains(
            r#"if (typeof input !== "object" || input === null || Array.isArray(input)) return { kind: "invalid-bash" };"#
        ));
        assert!(source.contains(
            r#"if (typeof toolInput.command !== "string") return { kind: "invalid-bash" };"#
        ));
        assert!(
            source.contains(
                r#"return { kind: "bash", input: toolInput, command: toolInput.command };"#
            )
        );
        assert!(source.contains("const toolCall = classifyOmpToolCall(event);"));
        assert!(source.contains("if (toolCall.kind === \"other-tool\") return;"));
        assert!(source.contains("if (toolCall.kind === \"invalid-bash\") {"));
        assert!(source.contains("const { input: toolInput, command } = toolCall;"));
        assert!(source.contains("if (command.length === 0) return;"));
        assert!(
            !source.contains("command.trim()"),
            "whitespace is a non-empty OMP command and must still reach dcg"
        );
        assert!(
            !source.contains("typeof command !== \"string\" || !command"),
            "malformed bash input must block instead of sharing the empty-command no-op"
        );

        let classify = source
            .find("const toolCall = classifyOmpToolCall(event);")
            .expect("structural classification call");
        let spawn = source.find("const proc = Bun.spawn").expect("dcg spawn");
        assert!(
            classify < spawn,
            "the structural boundary must classify the event before dcg is spawned"
        );
    }

    /// A machine-readable safety verdict must be monotone across the child
    /// process's data and status channels: no exit status may erase a parsed
    /// deny-like verdict, and dcg's blocking exit status must win even when
    /// stdout is absent, damaged, or contradictory. Keep the complete finite
    /// state machine in generated TypeScript so pass-level executable tests can
    /// drive the same pure classifier without reconstructing its policy.
    #[test]
    fn omp_extension_source_encodes_monotonic_child_transition_table() {
        let executable = current_dcg_executable().expect("current executable");
        let source = build_omp_extension_source(&executable).expect("extension generation");

        assert!(source.contains("type DcgChildOutcome ="));
        assert!(source.contains("type DcgParsedVerdict ="));
        assert!(source.contains("const DCG_CHILD_TRANSITIONS:"));
        for row in [
            r#""spawn-throw": { empty: "infrastructure", malformed: "infrastructure", allow: "infrastructure", deny: "block", ask: "block", indeterminate: "block", unknown: "infrastructure" }"#,
            r#""exit-0": { empty: "allow", malformed: "allow", allow: "allow", deny: "block", ask: "block", indeterminate: "block", unknown: "allow" }"#,
            r#""exit-1": { empty: "block", malformed: "block", allow: "block", deny: "block", ask: "block", indeterminate: "block", unknown: "block" }"#,
            r#""exit-2": { empty: "allow", malformed: "allow", allow: "allow", deny: "block", ask: "block", indeterminate: "block", unknown: "allow" }"#,
            r#""exit-other": { empty: "infrastructure", malformed: "infrastructure", allow: "infrastructure", deny: "block", ask: "block", indeterminate: "block", unknown: "infrastructure" }"#,
        ] {
            assert!(
                source.contains(row),
                "generated bridge is missing transition row: {row}"
            );
        }
        assert!(source.contains("function parseDcgOutput("));
        assert!(source.contains("export function classifyDcgChild("));
        assert!(source.contains("const classification = classifyDcgChild("));
        assert!(
            source.contains(
                "reason: typeof record.reason === \"string\" ? record.reason : undefined"
            )
        );
        assert!(
            source.contains(
                "ruleId: typeof record.rule_id === \"string\" ? record.rule_id : undefined"
            )
        );
        assert!(
            !source.contains("DCG_MAX_JSON_CHARS"),
            "a post-buffer parse cap is not a resource bound and could erase a valid deny verdict"
        );
        assert!(
            !source.contains("if (exitCode === 0 || exitCode === 2) return;"),
            "an early status-only allow would erase a parsed blocking verdict"
        );
    }

    /// The robot protocol is a two-channel contract: stdout alone carries the
    /// machine decision, while stderr carries diagnostics that must remain
    /// visible. Keep both properties explicit so swapping the pipes cannot
    /// either fabricate a block from diagnostic JSON or erase a blocking exit.
    #[test]
    fn omp_extension_source_keeps_stdout_authoritative_and_stderr_visible() {
        let executable = current_dcg_executable().expect("current executable");
        let source = build_omp_extension_source(&executable).expect("extension generation");

        assert!(source.contains(
            r#"const classification = classifyDcgChild(
      childOutcomeFromExitCode(exitCode),
      typeof stdoutText === "string" ? stdoutText : "",
    );"#
        ));
        assert_eq!(
            source.matches("classifyDcgChild(").count(),
            2,
            "the generated module must contain only the pure classifier and its stdout-fed call"
        );
        let classifier = &source[source
            .find("export function classifyDcgChild(")
            .expect("classifier declaration")
            ..source
                .find("function childOutcomeFromExitCode(")
                .expect("classifier boundary")];
        assert!(
            !classifier.contains("stderr"),
            "stderr JSON is diagnostic text, never a decision input"
        );
        assert!(source.contains(
            r#"const stderrDetail = typeof stderrText === "string" ? stderrText.trim() : "";"#
        ));
        assert_eq!(
            source
                .matches(
                    "if (stderrDetail) console.error(`[dcg] OMP guard dcg stderr: ${stderrDetail}`);"
                )
                .count(),
            1,
            "allow and block must share one non-infrastructure stderr forwarding point"
        );
        assert_eq!(
            source.matches(
                "console.error(`[dcg] OMP guard infrastructure failure (exit ${exitCode})${stderrDetail ? `: ${stderrDetail}` : \"\"}`);"
            ).count(),
            1,
            "the infrastructure diagnostic must include child stderr exactly once"
        );

        let infrastructure = source
            .find("if (classification.action === \"infrastructure\")")
            .expect("infrastructure outcome branch");
        let forward = source
            .find("if (stderrDetail) console.error(`[dcg] OMP guard dcg stderr: ${stderrDetail}`);")
            .expect("non-infrastructure stderr forwarding");
        let allow = source
            .find("if (classification.action === \"allow\") return;")
            .expect("allow outcome branch");
        let block = source
            .find("return { block: true, reason: `${reason}${rule}` };")
            .expect("block outcome return");
        assert!(
            infrastructure < forward && forward < allow && allow < block,
            "stderr must be emitted once before either non-infrastructure outcome returns"
        );
        assert!(source.contains(
            r#""exit-1": { empty: "block", malformed: "block", allow: "block", deny: "block", ask: "block", indeterminate: "block", unknown: "block" }"#
        ));
    }

    /// OMP 18's ordinary and managed-async BashTool routes execute in the
    /// embedded Brush shell even on Windows. Only an eligible local PTY uses
    /// OMP's configured external shell, which may be cmd.exe or PowerShell.
    /// Keep this source contract mutation-sensitive: replacing the dynamic
    /// argument with a blanket posix/unknown dialect must fail this test.
    #[test]
    fn omp_extension_source_selects_dialect_only_for_eligible_local_pty() {
        let executable = current_dcg_executable().expect("current executable");
        let source = build_omp_extension_source(&executable).expect("extension generation");

        assert!(
            source.contains("import type { ExtensionAPI } from \"@oh-my-pi/pi-coding-agent\";")
        );
        assert!(
            source.contains(
                "import { settings } from \"@oh-my-pi/pi-coding-agent/config/settings\";"
            )
        );
        assert!(source.contains("import { procmgr } from \"@oh-my-pi/pi-utils\";"));
        assert!(
            source.contains("command?: unknown; cwd?: unknown; async?: unknown; pty?: unknown")
        );
        assert!(source.contains(
            "toolInput?.pty === true && toolInput?.async !== true && ctx.hasUI && process.env.PI_NO_PTY !== \"1\""
        ));
        assert!(source.contains(
            "procmgr.isCmdShell(shell) ? \"cmd\" : procmgr.isPowerShell(shell) ? \"ps\" : \"posix\""
        ));
        assert!(source.contains("settings.getShellConfig().shell"));
        assert!(source.contains("\"--dialect\", shellDialect"));
        assert!(
            !source.contains("\"--dialect\", \"posix\""),
            "a hard-coded POSIX argument leaves eligible native-Windows PTY calls open to cmd/PowerShell evasions"
        );
        assert!(
            !source.contains("ctx.mode ===") && !source.contains("ctx.mode !=="),
            "ACP and JSON-RPC both expose mode=rpc; guessing the hidden ACP terminal capability would overmatch POSIX-only RPC execution"
        );
    }

    #[test]
    #[cfg(unix)]
    fn generated_javascript_rejects_a_lossy_executable_path() {
        use std::os::unix::ffi::OsStringExt;

        let invalid = std::ffi::OsString::from_vec(b"/tmp/dcg-\xff".to_vec());
        let error = executable_javascript_literal(std::path::Path::new(&invalid))
            .expect_err("non-UTF-8 paths cannot be represented faithfully in JavaScript");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn omp_profile_names_follow_upstream_safety_contract() {
        assert_eq!(
            normalize_omp_profile_name("work").expect("valid profile"),
            Some("work".to_string())
        );
        assert_eq!(
            normalize_omp_profile_name(" team-1.dev ").expect("trimmed valid profile"),
            Some("team-1.dev".to_string())
        );
        for default in ["", "  ", "default", " default "] {
            assert_eq!(
                normalize_omp_profile_name(default).expect("default profile sentinel"),
                None,
                "{default:?}"
            );
        }
        for invalid in [".", "..", "Upper", "../escape", "NUL", "con.txt", "lpt9"] {
            let error = normalize_omp_profile_name(invalid)
                .expect_err("invalid explicit profile must not become the default");
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{invalid}");
        }
    }

    #[test]
    fn omp_config_root_rejects_windows_drive_qualified_overrides() {
        let home = std::path::Path::new("/test-home");
        for invalid in [r"C:\omp", "c:omp", r"\D:\profiles"] {
            let error = omp_config_root_from(home, invalid, true)
                .expect_err("Windows drive-qualified config names must be rejected");
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        }

        assert_eq!(
            omp_config_root_from(home, "/etc/omp-cfg", true).expect("separator-rooted name"),
            home.join("etc/omp-cfg")
        );
        assert_eq!(
            omp_config_root_from(home, r"C:\omp", false).expect("valid POSIX child name"),
            home.join(r"C:\omp")
        );
    }

    #[test]
    fn test_install_antigravity_hook_writes_valid_hook() {
        // Writes the dcg PreToolUse hook into a hooks.json at the resolved
        // Antigravity path and asserts the wire shape + command match what
        // `agy` reads. Uses a temp HOME so the real ~/.gemini is never touched.
        let tmp = tempfile::tempdir().expect("tempdir");
        let hooks_path = tmp.path().join(".gemini").join("config").join("hooks.json");
        std::fs::create_dir_all(hooks_path.parent().unwrap()).unwrap();

        // Mirror install_dcg_hook_into_settings against an empty config, which
        // is exactly what install_antigravity_hook does for a fresh file.
        let mut settings = serde_json::json!({});
        let changed =
            install_antigravity_hook_into_settings(&mut settings, false).expect("install");
        assert!(changed, "first install should change settings");
        std::fs::write(
            &hooks_path,
            serde_json::to_string_pretty(&settings).unwrap(),
        )
        .unwrap();

        // Re-read and validate the structure the way agy parses it.
        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&hooks_path).unwrap()).unwrap();
        let pre_tool_use = written["hooks"]["PreToolUse"]
            .as_array()
            .expect("hooks.PreToolUse must be an array");
        assert_eq!(pre_tool_use.len(), 1, "exactly one dcg hook entry");
        let entry = &pre_tool_use[0];
        assert_eq!(entry["matcher"], "Bash");
        let cmd = &entry["hooks"][0];
        assert_eq!(
            cmd,
            &antigravity_dcg_hook().expect("desired Antigravity hook")
        );

        // The written entry must be recognized as a dcg hook (idempotency).
        assert!(is_dcg_hook_entry_for_matcher(
            entry,
            ANTIGRAVITY_SHELL_MATCHER
        ));

        // A second install without --force is a no-op (already installed).
        let changed_again =
            install_antigravity_hook_into_settings(&mut settings, false).expect("second install");
        assert!(!changed_again, "second install should be idempotent");
    }

    // ========================================================================
    // Batch hook mode tests
    // ========================================================================

    #[test]
    fn quick_reject_trace_uses_exact_evaluator_provenance() {
        let indeterminate = EvaluationResult::indeterminate_due_to_budget();
        assert!(policy_blocks_cli_execution(indeterminate.decision, None));
        assert!(!indeterminate.quick_rejected);

        let clean_allow = EvaluationResult::allowed();
        assert!(!policy_blocks_cli_execution(clean_allow.decision, None));
        assert!(!clean_allow.quick_rejected);

        let quick_allow = EvaluationResult::allowed_by_quick_reject();
        assert!(!policy_blocks_cli_execution(quick_allow.decision, None));
        assert!(quick_allow.quick_rejected);

        // Defend the reporting boundary even if a partially-built result ever
        // carries the legacy Allow discriminant alongside a budget skip.
        let mut inconsistent_budget_skip = EvaluationResult::allowed();
        inconsistent_budget_skip.skipped_due_to_budget = true;
        assert!(
            !inconsistent_budget_skip.quick_rejected,
            "budget exhaustion must never be reported as a quick-rejected allow"
        );
    }

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
    fn test_batch_preserves_explicit_shell_dialect_context() {
        let lines = [
            r#"{"tool_name":"PowerShell","tool_input":{"command":"g`it branch -`d feature"}}"#,
            r#"{"tool_name":"pwsh","tool_input":{"command":"g`it branch --format -`d"}}"#,
            r#"{"tool_name":"cmd.exe","tool_input":{"command":"g^it branch ^-d feature"}}"#,
            r#"{"tool_name":"cmd","tool_input":{"command":"g^it branch --format ^-d"}}"#,
            r#"{"tool_name":"Bash","tool_input":{"command":"g`it branch -`d feature"}}"#,
            r#"{"tool_name":"runTerminalCommand","tool_input":{"command":"g^it branch ^-d feature"}}"#,
        ];
        let results = process_batch_lines(&lines);

        let decisions: Vec<&str> = results.iter().map(|result| result.decision).collect();
        // The last line has no proven dialect (`runTerminalCommand`), so it is
        // evaluated under `Unknown` and the #294 fan-out replays the cmd view
        // that de-escapes `g^it branch ^-d` into a real `git branch -d`. The
        // Bash line before it stays allowed: POSIX has no backtick escape, so
        // that command really is not git.
        assert_eq!(
            decisions,
            ["deny", "allow", "deny", "allow", "allow", "deny"]
        );
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
                .contains("supported shell tool")
        );
    }

    #[test]
    fn test_batch_accepts_copilot_hook_input() {
        let lines = [
            r#"{"event":"pre-tool-use","toolName":"run_shell_command","toolInput":{"command":"rm -rf /"}}"#,
        ];
        let results = process_batch_lines(&lines);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, "deny");
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
    fn test_cli_parse_allowlist_add_with_paths() {
        let cli = Cli::parse_from([
            "dcg",
            "allowlist",
            "add",
            "core.git:reset-hard",
            "-r",
            "Scoped override",
            "--path",
            "/workspace/project",
            "--path",
            "/workspace/project/subdir/**",
        ]);
        if let Some(Command::Allowlist {
            action: AllowlistAction::Add { paths, .. },
        }) = cli.command
        {
            assert_eq!(
                paths,
                vec![
                    "/workspace/project".to_string(),
                    "/workspace/project/subdir/**".to_string()
                ]
            );
        } else {
            unreachable!("Expected Allowlist Add command with paths");
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
    fn test_cli_parse_allowlist_prune() {
        let cli = Cli::parse_from([
            "dcg",
            "allowlist",
            "prune",
            "--dry-run",
            "--user",
            "--format",
            "json",
        ]);
        if let Some(Command::Allowlist {
            action:
                AllowlistAction::Prune {
                    dry_run,
                    user,
                    format,
                    ..
                },
        }) = cli.command
        {
            assert!(dry_run);
            assert!(user);
            assert_eq!(format, AllowlistOutputFormat::Json);
        } else {
            unreachable!("Expected Allowlist Prune command");
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
    fn test_cli_parse_allowlist_add_command_with_paths() {
        let cli = Cli::parse_from([
            "dcg",
            "allowlist",
            "add-command",
            "git push --force origin main",
            "-r",
            "Release workflow",
            "--path",
            "/workspace/project",
        ]);
        if let Some(Command::Allowlist {
            action: AllowlistAction::AddCommand { paths, .. },
        }) = cli.command
        {
            assert_eq!(paths, vec!["/workspace/project".to_string()]);
        } else {
            unreachable!("Expected Allowlist AddCommand command with paths");
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
    fn test_allowlist_toml_helpers_with_paths() {
        let rule_id = RuleId::parse("core.git:reset-hard").unwrap();
        let path_scoped_rule = build_rule_entry_with_paths(
            &rule_id,
            "path scoped",
            None,
            &[],
            &["/workspace/project".to_string()],
        );
        assert!(path_scoped_rule.get("paths").is_some());

        let path_scoped_command = build_command_entry_with_paths(
            "git reset --hard HEAD~1",
            "path scoped command",
            None,
            &["/workspace/project/subdir/**".to_string()],
        );
        assert!(path_scoped_command.get("paths").is_some());
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
    fn write_allowlist_creates_backup_when_overwriting() {
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let path = temp.path().join("allowlist.toml");
        std::fs::write(
            &path,
            "[[allow]]\nrule = \"core.git:reset-hard\"\nreason = \"old\"\n",
        )
        .unwrap();

        let mut doc = load_or_create_allowlist_doc(&path).unwrap();
        let rule = RuleId::parse("core.git:clean-force").unwrap();
        let entry = build_rule_entry(&rule, "new", None, &[]);
        append_entry(&mut doc, entry);
        write_allowlist(&path, &doc).unwrap();

        let backup_count = std::fs::read_dir(temp.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("allowlist.toml.bak."))
            .count();
        assert_eq!(backup_count, 1, "exactly one backup should be created");
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
    fn allowlist_prune_removes_only_expired_entries() {
        use tempfile::TempDir;
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("allowlist.toml");

        let expired_rule = RuleId::parse("core.git:reset-hard").unwrap();
        let active_rule = RuleId::parse("core.git:clean-force").unwrap();
        let mut doc = load_or_create_allowlist_doc(&path).unwrap();
        append_entry(
            &mut doc,
            build_rule_entry(&expired_rule, "expired", Some("2020-01-01T00:00:00Z"), &[]),
        );
        append_entry(
            &mut doc,
            build_rule_entry(&active_rule, "active", Some("2099-01-01T00:00:00Z"), &[]),
        );

        let pruned = prune_expired_allowlist_doc(&mut doc, AllowlistLayer::Project, &path, false);
        assert_eq!(pruned.len(), 1);
        assert_eq!(pruned[0].selector_value, "core.git:reset-hard");
        assert!(!has_rule_entry(&doc, &expired_rule));
        assert!(has_rule_entry(&doc, &active_rule));
    }

    #[test]
    fn allowlist_prune_dry_run_preserves_document() {
        use tempfile::TempDir;
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("allowlist.toml");

        let expired_rule = RuleId::parse("core.git:reset-hard").unwrap();
        let mut doc = load_or_create_allowlist_doc(&path).unwrap();
        append_entry(
            &mut doc,
            build_rule_entry(&expired_rule, "expired", Some("2020-01-01T00:00:00Z"), &[]),
        );

        let pruned = prune_expired_allowlist_doc(&mut doc, AllowlistLayer::Project, &path, true);
        assert_eq!(pruned.len(), 1);
        assert!(has_rule_entry(&doc, &expired_rule));
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

    #[test]
    fn test_interactive_option_type_resolution() {
        let no_paths: Vec<String> = Vec::new();
        assert_eq!(
            interactive_option_type(None, &no_paths),
            InteractiveAllowlistOptionType::Exact
        );

        let paths = vec!["/tmp/workspace".to_string()];
        assert_eq!(
            interactive_option_type(None, &paths),
            InteractiveAllowlistOptionType::PathSpecific
        );

        assert_eq!(
            interactive_option_type(Some("2030-01-01T00:00:00Z"), &no_paths),
            InteractiveAllowlistOptionType::Temporary
        );
    }

    #[test]
    fn test_log_interactive_allowlist_audit_event_skips_when_history_disabled() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("history.sqlite3");

        let mut config = Config::default();
        config.history.enabled = false;
        config.history.database_path = Some(db_path.to_string_lossy().into_owned());

        let applied = InteractiveAllowlistApplication {
            summary: "exact command target, all directories".to_string(),
            pattern_added: "git reset --hard".to_string(),
            option_type: InteractiveAllowlistOptionType::Exact,
            option_detail: Some("target=exact_command".to_string()),
            config_file: temp_dir.path().join(".dcg/allowlist.toml"),
        };

        log_interactive_allowlist_audit_event(&config, "git reset --hard", &applied)
            .expect("history disabled should be a no-op");

        assert!(
            !db_path.exists(),
            "history db should not be created when history is disabled"
        );
    }

    #[test]
    fn test_log_interactive_allowlist_audit_event_persists_entry() {
        use crate::history::HistoryDb;

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("history.sqlite3");

        let mut config = Config::default();
        config.history.enabled = true;
        config.history.database_path = Some(db_path.to_string_lossy().into_owned());

        let applied = InteractiveAllowlistApplication {
            summary: "rule target, current directory only".to_string(),
            pattern_added: "core.git:reset-hard".to_string(),
            option_type: InteractiveAllowlistOptionType::PathSpecific,
            option_detail: Some("target=matched_rule;scope=current_directory_only".to_string()),
            config_file: temp_dir.path().join(".dcg/allowlist.toml"),
        };

        log_interactive_allowlist_audit_event(&config, "git reset --hard", &applied)
            .expect("audit entry should be logged");

        let db = HistoryDb::open(Some(db_path)).expect("history db opens");
        assert_eq!(
            db.count_interactive_allowlist_audits()
                .expect("count audit entries"),
            1
        );

        let rows = db
            .query_interactive_allowlist_audits(10, None)
            .expect("query audit entries");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].command, "git reset --hard");
        assert_eq!(rows[0].pattern_added, "core.git:reset-hard");
        assert_eq!(
            rows[0].option_type,
            InteractiveAllowlistOptionType::PathSpecific
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
    fn test_cli_parse_scan_with_packs() {
        let cli = Cli::try_parse_from([
            "dcg",
            "scan",
            "--paths",
            "scripts",
            "--with-packs",
            "careful_company_running_windows.email,database.snowflake",
        ])
        .expect("parse");
        if let Some(Command::Scan(scan)) = cli.command {
            assert_eq!(
                scan.with_packs,
                Some(vec![
                    "careful_company_running_windows.email".to_string(),
                    "database.snowflake".to_string(),
                ])
            );
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
    fn test_cli_parse_history_interactive() {
        let cli = Cli::try_parse_from([
            "dcg",
            "history",
            "interactive",
            "--limit",
            "25",
            "--option",
            "temporary",
            "--json",
        ])
        .expect("parse");

        if let Some(Command::History { action }) = cli.command {
            if let HistoryAction::Interactive {
                limit,
                option,
                json,
            } = action
            {
                assert_eq!(limit, 25);
                assert_eq!(option.as_deref(), Some("temporary"));
                assert!(json);
            } else {
                unreachable!("Expected History interactive action");
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
            ..
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

    /// #269: an opt-in dialect selector on both diagnostic commands, so a user
    /// can reproduce the single dialect the live hook resolves. The default
    /// must stay all-dialect.
    #[test]
    fn test_cli_parse_dialect_flag() {
        use crate::normalize::ShellDialect;

        let cli = Cli::try_parse_from(["dcg", "test", "--dialect", "posix", "git status"])
            .expect("parse test --dialect");
        let Some(Command::TestCommand { dialect, .. }) = cli.command else {
            unreachable!("Expected TestCommand");
        };
        assert_eq!(dialect, DialectArg::Posix);
        assert_eq!(ShellDialect::from(dialect), ShellDialect::Posix);

        let cli = Cli::try_parse_from(["dcg", "explain", "--dialect", "bash", "git status"])
            .expect("parse explain --dialect with alias");
        let Some(Command::Explain { dialect, .. }) = cli.command else {
            unreachable!("Expected Explain");
        };
        assert_eq!(dialect, DialectArg::Posix);

        // Default stays all-dialect on both commands.
        let cli = Cli::try_parse_from(["dcg", "test", "git status"]).expect("parse");
        let Some(Command::TestCommand { dialect, .. }) = cli.command else {
            unreachable!("Expected TestCommand");
        };
        assert_eq!(dialect, DialectArg::Unknown);
        assert_eq!(ShellDialect::from(dialect), ShellDialect::Unknown);

        let cli = Cli::try_parse_from(["dcg", "explain", "git status"]).expect("parse");
        let Some(Command::Explain { dialect, .. }) = cli.command else {
            unreachable!("Expected Explain");
        };
        assert_eq!(dialect, DialectArg::Unknown);

        for (argument, expected) in [
            ("ps", ShellDialect::PowerShell),
            ("pwsh", ShellDialect::PowerShell),
            ("cmd", ShellDialect::Cmd),
            ("sh", ShellDialect::Posix),
        ] {
            let cli = Cli::try_parse_from(["dcg", "test", "--dialect", argument, "git status"])
                .unwrap_or_else(|e| panic!("parse --dialect {argument}: {e}"));
            let Some(Command::TestCommand { dialect, .. }) = cli.command else {
                unreachable!("Expected TestCommand");
            };
            assert_eq!(
                ShellDialect::from(dialect),
                expected,
                "--dialect {argument}"
            );
        }

        assert!(
            Cli::try_parse_from(["dcg", "test", "--dialect", "klingon", "git status"]).is_err(),
            "an unknown dialect must be rejected rather than silently ignored"
        );
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
            assert_eq!(command.as_deref(), Some("git reset --hard"));
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
            assert_eq!(command.as_deref(), Some("rm -rf /tmp"));
            assert_eq!(format, TestFormat::Json);
        } else {
            unreachable!("Expected TestCommand");
        }
    }

    #[test]
    fn test_cli_parse_test_with_format_toon() {
        let cli =
            Cli::try_parse_from(["dcg", "test", "--format", "toon", "rm -rf /tmp"]).expect("parse");
        if let Some(Command::TestCommand {
            command, format, ..
        }) = cli.command
        {
            assert_eq!(command.as_deref(), Some("rm -rf /tmp"));
            assert_eq!(format, TestFormat::Toon);
        } else {
            unreachable!("Expected TestCommand");
        }
    }

    #[test]
    fn test_cli_parse_test_with_force_flag() {
        let cli =
            Cli::try_parse_from(["dcg", "test", "--force", "git reset --hard"]).expect("parse");
        if let Some(Command::TestCommand { command, force, .. }) = cli.command {
            assert_eq!(command.as_deref(), Some("git reset --hard"));
            assert!(force);
        } else {
            unreachable!("Expected TestCommand");
        }
    }

    #[test]
    fn test_cli_parse_test_with_enforced_hook_budget() {
        let cli = Cli::try_parse_from([
            "dcg",
            "test",
            "--enforce-budget",
            "--format",
            "json",
            "git status",
        ])
        .expect("parse");
        if let Some(Command::TestCommand {
            command,
            enforce_budget,
            ..
        }) = cli.command
        {
            assert_eq!(command.as_deref(), Some("git status"));
            assert!(enforce_budget);
        } else {
            unreachable!("Expected TestCommand");
        }
        assert!(
            Cli::try_parse_from(["dcg", "test", "--enforce-budget", "--explain", "git status"])
                .is_err()
        );
    }

    #[test]
    fn test_cli_parse_test_without_force_flag() {
        let cli = Cli::try_parse_from(["dcg", "test", "git status"]).expect("parse");
        if let Some(Command::TestCommand {
            enforce_budget,
            force,
            ..
        }) = cli.command
        {
            assert!(!enforce_budget);
            assert!(!force);
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
            assert_eq!(command.as_deref(), Some("git status"));
            assert!(!explain);
            assert_eq!(format, TestFormat::Pretty); // default
        } else {
            unreachable!("Expected TestCommand");
        }
    }

    #[test]
    fn test_toon_roundtrip_for_test_output_payload() {
        let payload = TestOutput {
            schema_version: TEST_OUTPUT_SCHEMA_VERSION,
            dcg_version: "v0.0.0-test".to_string(),
            robot_mode: false,
            command: "rm -rf /".to_string(),
            decision: "deny".to_string(),
            mode: Some("deny".to_string()),
            rule_id: Some("core.filesystem:rm-rf-root".to_string()),
            pack_id: Some("core.filesystem".to_string()),
            pattern_name: Some("rm-rf-root".to_string()),
            reason: Some("Refusing to remove root directory".to_string()),
            explanation: Some("Root path deletion is always destructive".to_string()),
            source: Some("pack".to_string()),
            matched_span: Some((0, 8)),
            severity: Some("critical".to_string()),
            allowlist: None,
            agent: Some(AgentInfo {
                detected: "unknown".to_string(),
                trust_level: "medium".to_string(),
                detection_method: "none".to_string(),
            }),
            dialect_divergence: None,
        };

        let json = serde_json::to_value(&payload).expect("serialize payload to json");
        let toon_encoded = toon::encode(json.clone(), None);
        let decoded: serde_json::Value = toon::try_decode(&toon_encoded, None)
            .expect("decode TOON payload")
            .into();
        // tru normalizes integers to f64 in roundtrip; compare canonically.
        fn canon(v: &serde_json::Value) -> serde_json::Value {
            match v {
                serde_json::Value::Number(n) => n
                    .as_f64()
                    .and_then(serde_json::Number::from_f64)
                    .map_or(serde_json::Value::Null, serde_json::Value::Number),
                serde_json::Value::Array(a) => {
                    serde_json::Value::Array(a.iter().map(canon).collect())
                }
                serde_json::Value::Object(o) => serde_json::Value::Object(
                    o.iter().map(|(k, v)| (k.clone(), canon(v))).collect(),
                ),
                other => other.clone(),
            }
        }
        assert_eq!(canon(&decoded), canon(&json));
    }

    // ========================================================================
    // Classify command tests
    // ========================================================================

    #[test]
    fn test_cli_parse_classify_basic() {
        let cli = Cli::try_parse_from(["dcg", "classify", "git status"]).expect("parse");
        if let Some(Command::Classify {
            command,
            format,
            no_color,
        }) = cli.command
        {
            assert_eq!(command, "git status");
            assert_eq!(format, ClassifyFormat::Json); // default is json
            assert!(!no_color);
        } else {
            unreachable!("Expected Classify");
        }
    }

    #[test]
    fn test_cli_parse_classify_with_format_text() {
        let cli = Cli::try_parse_from(["dcg", "classify", "--format", "text", "rm -rf /"])
            .expect("parse");
        if let Some(Command::Classify {
            command, format, ..
        }) = cli.command
        {
            assert_eq!(command, "rm -rf /");
            assert_eq!(format, ClassifyFormat::Text);
        } else {
            unreachable!("Expected Classify");
        }
    }

    #[test]
    fn test_cli_parse_classify_with_no_color() {
        let cli = Cli::try_parse_from(["dcg", "classify", "--no-color", "git push --force"])
            .expect("parse");
        if let Some(Command::Classify { no_color, .. }) = cli.command {
            assert!(no_color);
        } else {
            unreachable!("Expected Classify");
        }
    }

    #[test]
    fn test_classify_output_serialization() {
        let output = ClassifyOutput {
            schema_version: CLASSIFY_OUTPUT_SCHEMA_VERSION,
            dcg_version: "v0.0.0-test".to_string(),
            command: "rm -rf /".to_string(),
            decision: "block".to_string(),
            risk_level: "critical".to_string(),
            risk_score: 1.0,
            reasons: vec![ClassifyReason {
                rule_id: "core.filesystem:rm-rf-root".to_string(),
                severity: "critical".to_string(),
                explanation: "Removes the root filesystem".to_string(),
            }],
            suggestions: vec!["rm -ri / (interactive mode)".to_string()],
        };

        let json = serde_json::to_string_pretty(&output).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["decision"], "block");
        assert_eq!(parsed["risk_level"], "critical");
        assert_eq!(parsed["risk_score"], 1.0);
        assert_eq!(parsed["reasons"].as_array().unwrap().len(), 1);
        assert_eq!(
            parsed["reasons"][0]["rule_id"],
            "core.filesystem:rm-rf-root"
        );
        assert_eq!(parsed["suggestions"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_classify_output_safe_command_serialization() {
        let output = ClassifyOutput {
            schema_version: CLASSIFY_OUTPUT_SCHEMA_VERSION,
            dcg_version: "v0.0.0-test".to_string(),
            command: "git status".to_string(),
            decision: "allow".to_string(),
            risk_level: "safe".to_string(),
            risk_score: 0.0,
            reasons: vec![],
            suggestions: vec![],
        };

        let json = serde_json::to_string_pretty(&output).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed["decision"], "allow");
        assert_eq!(parsed["risk_level"], "safe");
        assert_eq!(parsed["risk_score"], 0.0);
        assert!(parsed["reasons"].as_array().unwrap().is_empty());
        assert!(parsed["suggestions"].as_array().unwrap().is_empty());
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

    #[test]
    fn git_diff_rejects_flag_like_rev_range() {
        // Regression: --git-diff used to forward its argument to `git diff`
        // with no validation. Values starting with `-` were interpreted
        // as flags, including dangerous ones like `--output=/etc/...`
        // (overwrites the file with diff content) and `--ext-diff`
        // (activates external diff drivers from .git/config).
        let bad_inputs = [
            "--output=/etc/passwd",
            "--ext-diff",
            "--upload-pack=evil",
            "-",
            "--no-renames",
        ];
        for bad in bad_inputs {
            let err = validate_git_rev_range(bad).expect_err(&format!(
                "validate_git_rev_range({bad:?}) should reject flag-like input"
            ));
            let msg = err.to_string();
            assert!(
                msg.contains("'-'") || msg.contains("disallowed"),
                "expected flag rejection message, got: {msg}"
            );
        }
    }

    #[test]
    fn git_diff_rejects_shell_metacharacters() {
        // Defense in depth: even if downstream callers ever interpolate
        // rev_range into a shell string, we reject the chars that would
        // matter.
        let bad_inputs = [
            "main; rm -rf /",
            "HEAD && echo pwned",
            "HEAD | curl evil",
            "HEAD\nrm -rf /",
            "$(echo evil)",
            "`evil`",
            "main\0HEAD",
        ];
        for bad in bad_inputs {
            assert!(
                validate_git_rev_range(bad).is_err(),
                "validate_git_rev_range({bad:?}) should reject shell metacharacter"
            );
        }
    }

    #[test]
    fn git_diff_accepts_legitimate_rev_ranges() {
        // Real git rev-ranges that should pass through unchanged.
        let good_inputs = [
            "HEAD",
            "HEAD~3..HEAD",
            "main..feature",
            "release/1.0..HEAD",
            "v1.2.3...v2.0",
            "HEAD@{1}",
            "abc1234",
            "abc1234..def5678",
        ];
        for good in good_inputs {
            assert!(
                validate_git_rev_range(good).is_ok(),
                "validate_git_rev_range({good:?}) should accept legitimate input"
            );
        }
    }

    #[test]
    fn git_diff_rejects_empty() {
        assert!(validate_git_rev_range("").is_err());
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
            misconfigured_hooks: vec![],
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
            misconfigured_hooks: vec![],
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
            misconfigured_hooks: vec![],
            missing_executable_hooks: vec![],
            other_hooks_count: 0,
        };
        assert!(!diag.is_healthy());
        assert!(diag.has_issues());
        assert_eq!(hook_diagnostics_issue_count(&diag), 1);
    }

    #[test]
    fn hook_diagnostics_missing_settings_is_skipped_not_an_issue() {
        let diag = HookDiagnostics::default();
        assert!(!diag.settings_exists);
        assert_eq!(hook_diagnostics_issue_count(&diag), 0);
    }

    #[test]
    fn hook_diagnostics_unhealthy_wrong_matcher() {
        let diag = HookDiagnostics {
            settings_exists: true,
            settings_valid: true,
            settings_error: None,
            dcg_hook_count: 1,
            wrong_matcher_hooks: vec!["Write".to_string()],
            misconfigured_hooks: vec![],
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
            misconfigured_hooks: vec![],
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
            misconfigured_hooks: vec![],
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
    fn config_diagnostics_trusted_source_failure_is_error() {
        let diag = ConfigDiagnostics {
            source_errors: vec!["Invalid TOML".to_string()],
            ..ConfigDiagnostics::default()
        };
        assert!(diag.has_errors());
        assert!(!diag.has_warnings());
    }

    #[test]
    fn config_diagnostics_unknown_effective_packs_is_warning() {
        let diag = ConfigDiagnostics {
            unknown_packs: vec!["nonexistent.pack".to_string()],
            ..ConfigDiagnostics::default()
        };
        assert!(!diag.has_errors());
        assert!(diag.has_warnings());
    }

    #[test]
    fn config_diagnostics_invalid_patterns_is_warning() {
        let diag = ConfigDiagnostics {
            invalid_override_patterns: vec![("invalid(regex".to_string(), "error".to_string())],
            ..ConfigDiagnostics::default()
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
                "PreToolUse": [make_dcg_entry()]
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
        // dcg hook with a non-shell matcher (Write).
        // Note: is_dcg_hook_entry requires BOTH the canonical Claude shell
        // matcher and a dcg command,
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
                        "matcher": CLAUDE_SHELL_MATCHER,
                        "hooks": [
                            { "type": "command", "command": "dcg" }
                        ]
                    },
                    {
                        "matcher": CLAUDE_SHELL_MATCHER,
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
    fn heredoc_synthetic_rule_namespaces_are_allowlistable() {
        // Fresh-eyes review of #261: the unverifiable-sink denials print
        // `dcg allowlist add '<heredoc.* rule>'` as remediation, and the
        // evaluator matches those rule ids exactly, so the CLI must accept
        // them (it rejected them before, contradicting the printed advice).
        for pack_id in [
            "heredoc.posix",
            "heredoc.powershell",
            "heredoc.shell",
            "heredoc.python",
            "heredoc.bash",
        ] {
            assert!(
                pack_id_is_known(pack_id),
                "synthetic heredoc namespace must validate for allowlisting: {pack_id}"
            );
        }
        // A bare group prefix still must not validate (issue #162's rule).
        assert!(!pack_id_is_known("heredoc"));
        assert!(!pack_id_is_known("heredoc.posix.extra"));
        assert!(!pack_id_is_known("core"));
    }

    #[test]
    fn foreign_platform_hook_paths_are_named_explicitly() {
        // #264: a stale cross-platform hook path (cc-switch migrating a
        // cached settings.json between Windows and WSL/Linux) gets a
        // diagnosis naming the likely cause instead of the generic message.
        #[cfg(not(windows))]
        {
            assert!(foreign_platform_hook_path(r"C:\Users\me\.local\bin\dcg.exe").is_some());
            assert!(foreign_platform_hook_path(r"D:/tools/dcg.exe").is_some());
            assert!(foreign_platform_hook_path("dcg.exe").is_some());
            assert!(foreign_platform_hook_path("/home/user/.local/bin/dcg").is_none());
            assert!(foreign_platform_hook_path("/usr/local/bin/dcg").is_none());
        }
        #[cfg(windows)]
        {
            assert!(foreign_platform_hook_path("/home/user/.local/bin/dcg").is_some());
            assert!(foreign_platform_hook_path(r"C:\Users\me\.local\bin\dcg.exe").is_none());
        }
    }

    #[test]
    fn is_dcg_command_recognizes_various_forms() {
        // Unix forms
        assert!(is_dcg_command("dcg"));
        assert!(is_dcg_command("/usr/local/bin/dcg"));
        assert!(is_dcg_command("/home/user/.cargo/bin/dcg"));
        assert!(is_dcg_command("~/.local/bin/dcg"));

        // Windows forms: backslash paths, `.exe`, drive letters, and quoting —
        // exactly what `dcg install --grok|--agy` write via current_exe().
        assert!(is_dcg_command(r"C:\Users\me\.local\bin\dcg.exe"));
        assert!(is_dcg_command(r"C:\Users\me\.local\bin\dcg.EXE"));
        assert!(is_dcg_command("dcg.exe"));
        assert!(is_dcg_command(r#""C:\Program Files\dcg\dcg.exe" --flag"#));
        assert!(is_dcg_command("'C:\\tools\\dcg.exe'"));
        assert!(is_dcg_command(r"& 'C:\Users\Jane Doe\.local\bin\dcg.exe'"));
        // Unix path with trailing args / surrounding whitespace
        assert!(is_dcg_command("  /usr/local/bin/dcg  "));

        // Negatives — stem-exact, so look-alikes must not match
        assert!(!is_dcg_command("other-hook"));
        assert!(!is_dcg_command(""));
        assert!(!is_dcg_command("dcg-wrapper"));
        assert!(!is_dcg_command(r"C:\tools\mydcg.exe"));
        assert!(!is_dcg_command(r"C:\tools\dcgwrapper.exe"));
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
        assert!(run_smoke_test(&Config::default()), "smoke test should pass");
    }

    #[test]
    fn config_source_json_distinguishes_automatic_project_authority() {
        let source = ConfigSourceOutcome {
            layer: ConfigFileLayer::AutomaticProject,
            authority: crate::config::ConfigFileAuthority::EnforcementOnly,
            status: ConfigFileStatus::Loaded,
            path: Some(std::path::PathBuf::from("/repo/.dcg.toml")),
            detail: None,
        };

        let json = config_sources_json(&[source]);
        assert_eq!(json[0]["level"], "automatic_project");
        assert_eq!(json[0]["label"], "automatic project");
        assert_eq!(json[0]["authority"], "enforcement_only");
        assert_eq!(json[0]["status"], "loaded");
    }

    #[test]
    fn config_diagnostics_classify_trusted_and_automatic_failures_separately() {
        let sources = vec![
            ConfigSourceOutcome {
                layer: ConfigFileLayer::AutomaticProject,
                authority: crate::config::ConfigFileAuthority::EnforcementOnly,
                status: ConfigFileStatus::Invalid,
                path: Some(std::path::PathBuf::from("/repo/.dcg.toml")),
                detail: Some("safe bounded parse location".to_string()),
            },
            ConfigSourceOutcome {
                layer: ConfigFileLayer::Explicit,
                authority: crate::config::ConfigFileAuthority::Full,
                status: ConfigFileStatus::Missing,
                path: Some(std::path::PathBuf::from("/missing.toml")),
                detail: None,
            },
        ];

        let diagnostics = validate_config_diagnostics(&Config::default(), &sources);
        assert_eq!(diagnostics.source_errors.len(), 1);
        assert!(diagnostics.source_errors[0].contains("DCG_CONFIG"));
        assert_eq!(diagnostics.source_warnings.len(), 1);
        assert!(diagnostics.source_warnings[0].contains("automatic project"));
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
    fn prompt_disabled_for_toon_format() {
        let verbosity = Verbosity {
            level: 1,
            quiet: false,
        };
        assert!(!should_prompt_interactively(
            TestFormat::Toon,
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

    #[test]
    fn prompt_disabled_for_non_interactive_env_context() {
        let verbosity = Verbosity {
            level: 1,
            quiet: false,
        };
        assert!(!should_prompt_interactively_with_context(
            TestFormat::Pretty,
            verbosity,
            DecisionMode::Deny,
            Some(PackSeverity::Medium),
            true,
            true,
            true,
            true,
        ));
    }

    #[test]
    fn prompt_disabled_when_interactive_not_available_context() {
        let verbosity = Verbosity {
            level: 1,
            quiet: false,
        };
        assert!(!should_prompt_interactively_with_context(
            TestFormat::Pretty,
            verbosity,
            DecisionMode::Deny,
            Some(PackSeverity::Medium),
            false,
            false,
            true,
            true,
        ));
    }

    #[test]
    fn prompt_disabled_for_non_tty_context() {
        let verbosity = Verbosity {
            level: 1,
            quiet: false,
        };
        assert!(!should_prompt_interactively_with_context(
            TestFormat::Pretty,
            verbosity,
            DecisionMode::Deny,
            Some(PackSeverity::Medium),
            false,
            true,
            false,
            true,
        ));
    }

    #[test]
    fn prompt_enabled_when_all_requirements_met_context() {
        let verbosity = Verbosity {
            level: 1,
            quiet: false,
        };
        assert!(should_prompt_interactively_with_context(
            TestFormat::Pretty,
            verbosity,
            DecisionMode::Deny,
            Some(PackSeverity::Medium),
            false,
            true,
            true,
            true,
        ));
    }

    // ========================================================================
    // Self-heal hook registration tests
    // ========================================================================

    #[test]
    fn self_heal_reregisters_missing_hook() {
        // Create a temporary settings.json WITHOUT the dcg hook
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join("settings.json");
        let settings = serde_json::json!({
            "hooks": {
                "PreToolUse": []
            }
        });
        std::fs::write(
            &settings_path,
            serde_json::to_string_pretty(&settings).unwrap(),
        )
        .unwrap();

        // Read it back, install the hook, and write
        let content = std::fs::read_to_string(&settings_path).unwrap();
        let mut settings: serde_json::Value = serde_json::from_str(&content).unwrap();

        let is_registered = settings
            .get("hooks")
            .and_then(|h| h.get("PreToolUse"))
            .and_then(|arr| arr.as_array())
            .is_some_and(|a| a.iter().any(is_dcg_hook_entry));
        assert!(!is_registered, "hook should not be registered yet");

        let changed = install_dcg_hook_into_settings(&mut settings, false).unwrap();
        assert!(changed, "should have installed the hook");

        let is_registered = settings
            .get("hooks")
            .and_then(|h| h.get("PreToolUse"))
            .and_then(|arr| arr.as_array())
            .is_some_and(|a| a.iter().any(is_dcg_hook_entry));
        assert!(is_registered, "hook should be registered after install");
    }

    #[test]
    fn self_heal_noop_when_hook_present() {
        let mut settings = serde_json::json!({
            "hooks": {
                "PreToolUse": [make_dcg_entry()]
            }
        });

        let changed = install_dcg_hook_into_settings(&mut settings, false).unwrap();
        assert!(!changed, "should not modify when hook is already present");
    }

    #[test]
    fn self_heal_handles_overwritten_settings() {
        // Simulate Claude Code overwriting settings.json with no hooks at all
        let mut settings = serde_json::json!({
            "permissions": {
                "allow": ["Bash(*)"]
            }
        });

        let changed = install_dcg_hook_into_settings(&mut settings, false).unwrap();
        assert!(
            changed,
            "should install hook into settings with no hooks key"
        );

        // Verify the structure was created correctly
        let is_registered = settings
            .get("hooks")
            .and_then(|h| h.get("PreToolUse"))
            .and_then(|arr| arr.as_array())
            .is_some_and(|a| a.iter().any(is_dcg_hook_entry));
        assert!(is_registered, "hook should be registered after self-heal");

        // Verify existing keys were preserved
        assert!(
            settings.get("permissions").is_some(),
            "existing keys should be preserved"
        );
    }

    #[test]
    fn self_heal_at_repairs_isolated_settings_end_to_end() {
        // End-to-end through the real repair path (lock + atomic replace)
        // against an isolated settings/lock location.
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join("settings.json");
        let lock_path = dir.path().join("selfheal.lock");
        let settings = serde_json::json!({
            "permissions": { "allow": ["Bash(*)"] },
            "hooks": { "PreToolUse": [] }
        });
        std::fs::write(
            &settings_path,
            serde_json::to_string_pretty(&settings).unwrap(),
        )
        .unwrap();

        ensure_hook_registered_at(&settings_path, &lock_path).unwrap();

        // The repaired file must be valid JSON with the hook registered and
        // unrelated keys preserved.
        let content = std::fs::read_to_string(&settings_path).unwrap();
        let healed: serde_json::Value =
            serde_json::from_str(&content).expect("settings must remain valid JSON after repair");
        let is_registered = healed
            .get("hooks")
            .and_then(|h| h.get("PreToolUse"))
            .and_then(|arr| arr.as_array())
            .is_some_and(|a| a.iter().any(is_dcg_hook_entry));
        assert!(is_registered, "hook should be registered after self-heal");
        assert!(
            healed.get("permissions").is_some(),
            "existing keys should be preserved"
        );

        // The atomic replace must not leave its temp file behind.
        let leftover_tmp = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| e.file_name().to_string_lossy().ends_with(".tmp"));
        assert!(!leftover_tmp, "no temp file should be left behind");

        // Second run hits the lock-free fast path and changes nothing.
        ensure_hook_registered_at(&settings_path, &lock_path).unwrap();
        let content_after = std::fs::read_to_string(&settings_path).unwrap();
        assert_eq!(content, content_after, "second run should be a no-op");
    }

    #[test]
    fn self_heal_at_skips_when_lock_held() {
        use fs2::FileExt;

        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join("settings.json");
        let lock_path = dir.path().join("selfheal.lock");
        let original = serde_json::to_string_pretty(&serde_json::json!({
            "hooks": { "PreToolUse": [] }
        }))
        .unwrap();
        std::fs::write(&settings_path, &original).unwrap();

        // Hold the exclusive lock on an independent handle, exactly as a
        // concurrent self-healing dcg process would (flock/LockFileEx
        // conflict across separate handles even within one process).
        let holder = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .unwrap();
        holder.lock_exclusive().unwrap();

        // Contended lock must mean skip-not-block: Ok, quickly, no changes.
        let start = std::time::Instant::now();
        ensure_hook_registered_at(&settings_path, &lock_path).unwrap();
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "contended self-heal must return promptly, not block"
        );
        let content = std::fs::read_to_string(&settings_path).unwrap();
        assert_eq!(
            content, original,
            "settings must be untouched when the lock is contended"
        );

        holder.unlock().unwrap();

        // Once the lock is free, the same call repairs the hook.
        ensure_hook_registered_at(&settings_path, &lock_path).unwrap();
        let healed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&settings_path).unwrap()).unwrap();
        let is_registered = healed
            .get("hooks")
            .and_then(|h| h.get("PreToolUse"))
            .and_then(|arr| arr.as_array())
            .is_some_and(|a| a.iter().any(is_dcg_hook_entry));
        assert!(is_registered, "hook should be repaired once lock is free");
    }

    #[test]
    fn self_heal_at_leaves_corrupt_settings_untouched() {
        // Planted negative: invalid JSON must error out (the caller warns and
        // fails open) and the corrupt file must be left byte-for-byte intact.
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join("settings.json");
        let lock_path = dir.path().join("selfheal.lock");
        let corrupt = "{ \"hooks\": { \"PreToolUse\": [ TRUNCATED";
        std::fs::write(&settings_path, corrupt).unwrap();

        let result = ensure_hook_registered_at(&settings_path, &lock_path);
        assert!(result.is_err(), "corrupt settings should surface an error");

        let content = std::fs::read_to_string(&settings_path).unwrap();
        assert_eq!(
            content, corrupt,
            "corrupt settings must not be modified or truncated"
        );
    }

    #[test]
    fn self_heal_at_noop_when_settings_missing() {
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join("settings.json");
        let lock_path = dir.path().join("selfheal.lock");

        ensure_hook_registered_at(&settings_path, &lock_path).unwrap();
        assert!(
            !settings_path.exists(),
            "self-heal must not create settings.json from nothing"
        );
    }

    #[test]
    #[cfg(unix)]
    fn write_settings_atomic_preserves_a_symlinked_settings_file() {
        // ~/.claude/settings.json is very often a symlink into a dotfile
        // manager (chezmoi / stow / home-manager). A temp+rename replace that
        // does not resolve the link would silently orphan the managed target.
        let dir = tempfile::tempdir().unwrap();
        let real_dir = dir.path().join("dotfiles");
        std::fs::create_dir_all(&real_dir).unwrap();
        let real_path = real_dir.join("claude-settings.json");
        std::fs::write(&real_path, "{\"old\": true}").unwrap();

        let link_path = dir.path().join("settings.json");
        std::os::unix::fs::symlink(&real_path, &link_path).unwrap();

        write_settings_atomic(&link_path, "{\"new\": true}").unwrap();

        assert!(
            std::fs::symlink_metadata(&link_path)
                .unwrap()
                .file_type()
                .is_symlink(),
            "settings.json must still be a symlink after self-heal"
        );
        assert_eq!(
            std::fs::read_to_string(&real_path).unwrap(),
            "{\"new\": true}",
            "the write must land on the symlink's target"
        );
        // No temp file left in either directory.
        for probe in [dir.path(), real_dir.as_path()] {
            let leftover_tmp = std::fs::read_dir(probe)
                .unwrap()
                .filter_map(Result::ok)
                .any(|e| e.file_name().to_string_lossy().ends_with(".tmp"));
            assert!(!leftover_tmp, "no temp file should be left in {probe:?}");
        }
    }

    #[test]
    #[cfg(unix)]
    fn write_settings_atomic_preserves_restrictive_mode() {
        // settings.json can hold API keys in `env` blocks: a `chmod 600` file
        // must not come back 0644 because dcg repaired a hook entry.
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, "{\"old\": true}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        write_settings_atomic(&path, "{\"new\": true}").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "restrictive mode must survive the atomic write"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"new\": true}");
    }

    #[test]
    #[cfg(unix)]
    fn write_allowlist_preserves_restrictive_mode() {
        // Same defect, same fix, in the pre-existing allowlist atomic write.
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowlist.toml");
        std::fs::write(&path, "[commands]\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let doc: toml_edit::DocumentMut = "[commands]\nfoo = \"bar\"\n".parse().unwrap();
        write_allowlist(&path, &doc).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "restrictive mode must survive the atomic write"
        );
        assert!(std::fs::read_to_string(&path).unwrap().contains("foo"));
    }

    #[test]
    #[cfg(unix)]
    fn self_heal_at_repairs_through_a_symlink() {
        // End-to-end: the whole repair path must keep the symlink intact.
        let dir = tempfile::tempdir().unwrap();
        let real_dir = dir.path().join("dotfiles");
        std::fs::create_dir_all(&real_dir).unwrap();
        let real_path = real_dir.join("claude-settings.json");
        std::fs::write(
            &real_path,
            serde_json::to_string_pretty(&serde_json::json!({
                "hooks": { "PreToolUse": [] }
            }))
            .unwrap(),
        )
        .unwrap();
        let link_path = dir.path().join("settings.json");
        std::os::unix::fs::symlink(&real_path, &link_path).unwrap();
        let lock_path = dir.path().join("selfheal.lock");

        ensure_hook_registered_at(&link_path, &lock_path).unwrap();

        assert!(
            std::fs::symlink_metadata(&link_path)
                .unwrap()
                .file_type()
                .is_symlink(),
            "self-heal must not replace the symlink with a regular file"
        );
        let healed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&real_path).unwrap()).unwrap();
        let is_registered = healed
            .get("hooks")
            .and_then(|h| h.get("PreToolUse"))
            .and_then(|arr| arr.as_array())
            .is_some_and(|a| a.iter().any(is_dcg_hook_entry));
        assert!(is_registered, "hook must be repaired in the link target");
    }

    #[test]
    fn self_heal_lock_path_is_keyed_to_the_protected_file() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("settings.json");
        let b = dir.path().join("other-settings.json");
        std::fs::write(&a, "{}").unwrap();
        std::fs::write(&b, "{}").unwrap();

        // Stable for the same file...
        assert_eq!(self_heal_lock_path(&a), self_heal_lock_path(&a));
        // ...and distinct for a different one.
        assert_ne!(self_heal_lock_path(&a), self_heal_lock_path(&b));

        // Shape: <config dir>/selfheal-<8 hex>.lock
        let name = self_heal_lock_path(&a)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let hex = name
            .strip_prefix("selfheal-")
            .and_then(|rest| rest.strip_suffix(".lock"))
            .expect("lock file name must be selfheal-<hex>.lock");
        assert_eq!(hex.len(), 8, "expected an 8-char hex key, got {name:?}");
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    #[cfg(unix)]
    fn self_heal_lock_path_is_identical_for_aliases_of_one_file() {
        // Two processes reaching the same settings.json by different
        // spellings (symlink, `..` hop) must contend on ONE lock.
        let dir = tempfile::tempdir().unwrap();
        let real_dir = dir.path().join("dotfiles");
        std::fs::create_dir_all(&real_dir).unwrap();
        let real_path = real_dir.join("claude-settings.json");
        std::fs::write(&real_path, "{}").unwrap();
        let link_path = dir.path().join("settings.json");
        std::os::unix::fs::symlink(&real_path, &link_path).unwrap();
        let dotted = real_dir
            .join("..")
            .join("dotfiles")
            .join(real_path.file_name().map(std::path::PathBuf::from).unwrap());

        assert_eq!(
            self_heal_lock_path(&real_path),
            self_heal_lock_path(&link_path)
        );
        assert_eq!(
            self_heal_lock_path(&real_path),
            self_heal_lock_path(&dotted)
        );
    }

    #[test]
    fn write_settings_atomic_replaces_existing_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, "{\"old\": true}").unwrap();

        write_settings_atomic(&path, "{\"new\": true}").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"new\": true}");
        let leftover_tmp = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| e.file_name().to_string_lossy().ends_with(".tmp"));
        assert!(!leftover_tmp, "no temp file should be left behind");
    }

    // ========================================================================
    // #289 C1: dialect-divergence hint for `dcg test` / `dcg explain`
    // ========================================================================

    /// Evaluate `command` the way the CLI does, then run the #289 C1
    /// divergence check against that decision.
    fn divergence_for(
        command: &str,
        dialect: DialectArg,
        extra_packs: &[&str],
    ) -> Option<DialectDivergence> {
        let mut config = Config::default();
        config
            .packs
            .enabled
            .extend(extra_packs.iter().map(|id| (*id).to_string()));
        let compiled_overrides = config.overrides.compile();
        let allowlists = crate::allowlist::LayeredAllowlist::default();
        let heredoc_settings = config.heredoc_settings();
        let enabled_packs = config.enabled_pack_ids();
        let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
        let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
        let keyword_index = REGISTRY.build_enabled_keyword_index(&ordered_packs);

        let result = evaluate_command_with_pack_order_deadline_at_path_in_dialect(
            command,
            &enabled_keywords,
            &ordered_packs,
            keyword_index.as_ref(),
            &compiled_overrides,
            &allowlists,
            &heredoc_settings,
            None,
            None,
            None,
            dialect.into(),
        );

        cli_dialect_divergence(
            dialect,
            result.decision,
            command,
            &enabled_keywords,
            &ordered_packs,
            keyword_index.as_ref(),
            &compiled_overrides,
            &allowlists,
            &heredoc_settings,
            None,
        )
    }

    #[test]
    fn issue_289_c1_unknown_dialect_denial_that_posix_allows_reports_divergence() {
        // `rd /s /q` is Cmd syntax: only the all-dialect union denies it.
        let command = r"rd /s /q C:\x";
        let divergence = divergence_for(command, DialectArg::Unknown, &["windows.filesystem"])
            .expect("deny under the default dialect must run the posix check");
        assert!(divergence.posix_would_allow);

        let note = dialect_divergence_note(Some(divergence), command).expect("note");
        assert!(note.contains("all-dialect analysis"), "note: {note}");
        assert!(note.contains("would ALLOW this command"), "note: {note}");
        assert!(
            note.contains(r"dcg test --dialect posix 'rd /s /q C:\x'"),
            "note must be copy-pasteable: {note}"
        );
    }

    #[test]
    fn issue_289_c1_posix_denied_command_shows_no_note() {
        // The Bash hook denies this too, so there is no divergence to report
        // and nothing is added to the human or JSON output.
        let command = "git reset --hard HEAD~1";
        let divergence = divergence_for(command, DialectArg::Unknown, &[]);
        assert!(divergence.is_none());
        assert!(dialect_divergence_note(divergence, command).is_none());
    }

    #[test]
    fn issue_289_c1_explicit_dialect_never_reports_divergence() {
        let command = r"rd /s /q C:\x";
        for dialect in [DialectArg::Posix, DialectArg::Cmd, DialectArg::Ps] {
            assert!(
                divergence_for(command, dialect, &["windows.filesystem"]).is_none(),
                "explicit --dialect {dialect:?} must report its own verdict as-is"
            );
        }
    }

    #[test]
    fn issue_289_c1_allowed_command_skips_the_second_evaluation() {
        assert!(divergence_for("ls -la", DialectArg::Unknown, &[]).is_none());
    }

    #[test]
    fn issue_289_c1_note_single_quotes_are_escaped() {
        let note = dialect_divergence_note(
            Some(DialectDivergence {
                posix_would_allow: true,
            }),
            "echo 'hi'",
        )
        .expect("note");
        assert!(note.contains(r"'echo '\''hi'\'''"), "note: {note}");
    }
}
