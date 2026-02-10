#![forbid(unsafe_code)]
//! Destructive Command Guard (dcg) for Claude Code.
//!
//! Blocks destructive commands that can lose uncommitted work or delete files.
//! This hook runs before Bash commands execute and can deny dangerous operations.
//!
//! Exit behavior:
//!   - Exit 0 with JSON {"hookSpecificOutput": {"permissionDecision": "deny", ...}} = block
//!   - Exit 0 with no output = allow
//!
//! # Performance
//!
//! This hook is invoked for every Bash command, so latency is critical:
//! - Quick rejection filter skips regex for 99%+ of commands
//! - Lazy-initialized static patterns compiled once
//! - `Cow<str>` avoids allocation when no path normalization needed
//! - `memchr` SIMD-accelerated substring search for quick rejection
//! - Inlined hot paths for better codegen

use clap::Parser;
use colored::Colorize;
use destructive_command_guard::cli::{self, Cli};
// Exit codes are used by cli.rs for robot mode; main.rs uses them for hook mode errors
use destructive_command_guard::config::Config;
use destructive_command_guard::evaluator::{
    EvaluationDecision, MatchSource, evaluate_command_with_pack_order_deadline_at_path,
};
#[allow(unused_imports)]
use destructive_command_guard::exit_codes::{EXIT_DENIED, EXIT_PARSE_ERROR, EXIT_SUCCESS};
use destructive_command_guard::history::{
    CommandEntry, ENV_HISTORY_DB_PATH, HistoryDb, HistoryWriter, Outcome as HistoryOutcome,
};
use destructive_command_guard::hook;
use destructive_command_guard::load_default_allowlists;
use destructive_command_guard::normalize::normalize_command;
use destructive_command_guard::packs::load_external_packs;
#[cfg(test)]
use destructive_command_guard::packs::pack_aware_quick_reject;
use destructive_command_guard::packs::{DecisionMode, REGISTRY};
use destructive_command_guard::pending_exceptions::{PendingExceptionStore, log_maintenance};
use destructive_command_guard::perf::{Deadline, HOOK_EVALUATION_BUDGET};
use destructive_command_guard::sanitize_for_pattern_matching;
// Import HookInput for parsing stdin JSON in hook mode
#[cfg(test)]
use destructive_command_guard::hook::HookInput;
#[cfg(test)]
use std::borrow::Cow;
use std::collections::HashSet;
use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::time::{Duration, Instant};

// Build metadata from vergen (set by build.rs)
const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_TIMESTAMP: Option<&str> = option_env!("VERGEN_BUILD_TIMESTAMP");
const RUSTC_SEMVER: Option<&str> = option_env!("VERGEN_RUSTC_SEMVER");
const CARGO_TARGET: Option<&str> = option_env!("VERGEN_CARGO_TARGET_TRIPLE");

// NOTE: HookInput, ToolInput, HookOutput, HookSpecificOutput types are now defined
// in the hook module. Use hook::HookInput, hook::read_hook_input(), etc.

/// Configure colored output based on TTY detection.
///
/// Disables colors if stderr is not a terminal (e.g., piped to a file).
fn configure_colors() {
    if std::env::var_os("NO_COLOR").is_some() || std::env::var_os("DCG_NO_COLOR").is_some() {
        colored::control::set_override(false);
        return;
    }

    if !io::stderr().is_terminal() {
        colored::control::set_override(false);
    }
}

const HISTORY_AGENT_TYPE: &str = "claude_code";

fn history_db_path(config: &destructive_command_guard::config::HistoryConfig) -> Option<PathBuf> {
    if let Ok(path) = std::env::var(ENV_HISTORY_DB_PATH) {
        return Some(PathBuf::from(path));
    }
    config.expanded_database_path()
}

fn build_history_entry(
    command: &str,
    working_dir: &str,
    outcome: HistoryOutcome,
    eval_duration: Duration,
    pack_id: Option<&str>,
    pattern_name: Option<&str>,
    allowlist_layer: Option<&str>,
) -> CommandEntry {
    let eval_duration_us = u64::try_from(eval_duration.as_micros()).unwrap_or(u64::MAX);

    CommandEntry {
        agent_type: HISTORY_AGENT_TYPE.to_string(),
        working_dir: working_dir.to_string(),
        command: command.to_string(),
        outcome,
        pack_id: pack_id.map(str::to_string),
        pattern_name: pattern_name.map(str::to_string),
        eval_duration_us,
        allowlist_layer: allowlist_layer.map(str::to_string),
        ..Default::default()
    }
}

fn install_history_shutdown_handler(
    handle: destructive_command_guard::history::HistoryFlushHandle,
) {
    let _ = ctrlc::set_handler(move || {
        eprintln!("[dcg] Flushing history...");
        handle.flush_sync();
        std::process::exit(130);
    });
}

// NOTE: Denial output functions (format_denial_message, print_colorful_warning, deny)
// are now in the hook module. Use hook::output_denial() for all denial responses.

/// Print version information and exit.
fn print_version() {
    // ASCII art logo - compact shield design
    eprintln!();
    eprintln!(
        "  {}",
        "╭─────────────────────────────────────────╮".bright_black()
    );
    eprintln!(
        "  {}  🛡  {}               {}",
        "│".bright_black(),
        "Destructive Command Guard".white().bold(),
        "│".bright_black()
    );
    eprintln!(
        "  {}     {}                           {}",
        "│".bright_black(),
        format!("dcg v{PKG_VERSION}").cyan().bold(),
        "│".bright_black()
    );
    eprintln!(
        "  {}                                         {}",
        "│".bright_black(),
        "│".bright_black()
    );

    // Build info
    if let Some(ts) = BUILD_TIMESTAMP {
        // Extract just the date part for cleaner display
        let date = ts.split('T').next().unwrap_or(ts);
        eprintln!(
            "  {}  {} {}                   {}",
            "│".bright_black(),
            "Built:".bright_black(),
            date.white(),
            "│".bright_black()
        );
    }
    if let Some(rustc) = RUSTC_SEMVER {
        eprintln!(
            "  {}  {} {}                      {}",
            "│".bright_black(),
            "Rustc:".bright_black(),
            rustc.white(),
            "│".bright_black()
        );
    }
    if let Some(target) = CARGO_TARGET {
        eprintln!(
            "  {}  {} {}         {}",
            "│".bright_black(),
            "Target:".bright_black(),
            target.white(),
            "│".bright_black()
        );
    }

    eprintln!(
        "  {}                                         {}",
        "│".bright_black(),
        "│".bright_black()
    );
    eprintln!(
        "  {}  {}  {}",
        "│".bright_black(),
        "Protecting your code from destructive ops".green(),
        "│".bright_black()
    );
    eprintln!(
        "  {}",
        "╰─────────────────────────────────────────╯".bright_black()
    );
    eprintln!();
}

#[allow(clippy::too_many_lines)]
fn main() {
    // Configure colors based on TTY detection
    configure_colors();

    // Check for --version flag (useful when run directly, not as hook)
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        print_version();
        return;
    }

    // Check for --help flag
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return;
    }

    // Parse CLI arguments (subcommands). If parsing fails (e.g., unknown flags),
    // print the clap error and exit instead of falling into hook mode and
    // blocking on stdin.
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    // Initialize output system based on CLI flags.
    // --legacy-output, --no-color, or --robot forces plain output mode.
    // Robot mode also suppresses all stderr output.
    let robot_mode = cli.robot || std::env::var("DCG_ROBOT").is_ok();
    let force_plain_output = cli.legacy_output || cli.no_color || robot_mode;
    destructive_command_guard::output::init(force_plain_output);
    destructive_command_guard::output::init_console(force_plain_output);
    destructive_command_guard::output::init_suggestions(!cli.no_suggestions && !robot_mode);

    // In robot mode, also disable colors completely
    if robot_mode {
        colored::control::set_override(false);
    }

    // If there's a subcommand, handle it and exit.
    if cli.command.is_some() {
        if let Err(e) = cli::run_command(cli) {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
        return;
    }

    // Load configuration
    let config = Config::load();

    // Check if bypass is requested (escape hatch)
    if Config::is_bypassed() {
        return;
    }

    // Compile overrides once (precompiled regexes, no per-command compilation)
    let compiled_overrides = config.overrides.compile();

    // Load layered allowlists (project/user/system). Missing/invalid files are treated
    // as empty for hook safety; allowlist decisions are only consulted on matches.
    let allowlists = load_default_allowlists();

    // Compute effective heredoc settings once (avoid per-command parsing/allocations).
    let heredoc_settings = config.heredoc_settings();

    // Get enabled pack IDs early for pack-aware quick reject.
    // This is done before stdin read to minimize latency on the critical path.
    let mut enabled_packs: HashSet<String> = config.enabled_pack_ids();
    let mut enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);

    // Load external packs from custom_paths (glob + tilde expansion).
    // External packs are loaded once and cached for the process lifetime.
    let external_paths = config.packs.expand_custom_paths();
    let external_store = load_external_packs(&external_paths);

    // Log warnings from external pack loading (fail-open: don't block on warnings).
    if config.general.verbose {
        for warning in external_store.warnings() {
            eprintln!("[dcg] Warning: {warning}");
        }
    }

    // Auto-enable external packs: packs loaded via custom_paths are implicitly enabled.
    // This avoids requiring users to both add a path AND explicitly enable the pack ID.
    for id in external_store.pack_ids() {
        enabled_packs.insert(id.clone());
    }

    // Merge external pack keywords into enabled keywords for quick rejection.
    // This ensures commands with external pack keywords are not prematurely rejected.
    enabled_keywords.extend(external_store.keywords().iter().copied());

    // Build ordered pack list and keyword index AFTER external packs are loaded,
    // so external pack IDs are included in the evaluation iteration list.
    let mut ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    // Append external pack IDs (not in the registry, so expand_enabled_ordered won't include them).
    for id in external_store.pack_ids() {
        if !ordered_packs.contains(id) {
            ordered_packs.push(id.clone());
        }
    }
    // Keyword index only covers built-in packs; disable when external packs are present
    // to ensure the non-indexed path (which handles both built-in and external) is used.
    let keyword_index = if external_store.pack_ids().next().is_some() {
        None
    } else {
        REGISTRY.build_enabled_keyword_index(&ordered_packs)
    };

    // Read and parse input
    let max_input_bytes = config.general.max_hook_input_bytes();
    let hook_input = match hook::read_hook_input(max_input_bytes) {
        Ok(input) => input,
        Err(hook::HookReadError::InputTooLarge(len)) => {
            eprintln!(
                "[dcg] Warning: stdin input ({len} bytes) exceeds limit ({max_input_bytes} bytes); allowing command (fail-open)"
            );
            return;
        }
        Err(_) => return, // Fail open on IO or JSON errors
    };

    // Start evaluation deadline after input size checks (includes evaluation).
    let deadline = Deadline::new(
        config
            .general
            .hook_timeout_ms
            .map_or(HOOK_EVALUATION_BUDGET, Duration::from_millis),
    );

    let Some((command, hook_protocol)) = hook::extract_command_with_protocol(&hook_input) else {
        return;
    };

    // Check command size limit (fail-open: allow and warn)
    let max_command_bytes = config.general.max_command_bytes();
    if command.len() > max_command_bytes {
        eprintln!(
            "[dcg] Warning: command ({} bytes) exceeds limit ({} bytes); allowing command (fail-open)",
            command.len(),
            max_command_bytes
        );
        return;
    }

    let cwd_path = std::env::current_dir().ok();
    let working_dir = cwd_path.as_ref().map_or_else(
        || "<unknown>".to_string(),
        |path| path.to_string_lossy().to_string(),
    );

    let history_writer = if config.history.enabled {
        HistoryDb::try_open(history_db_path(&config.history))
            .map(|db| HistoryWriter::new(db, &config.history))
    } else {
        None
    };

    if let Some(writer) = history_writer.as_ref() {
        if let Some(handle) = writer.flush_handle() {
            install_history_shutdown_handler(handle);
        }
    }

    if deadline.is_exceeded() {
        if let Some(log_file) = config.general.log_file.as_deref() {
            let _ = hook::log_budget_skip(
                log_file,
                &command,
                "pre_evaluation",
                deadline.elapsed(),
                HOOK_EVALUATION_BUDGET,
            );
        }
        return;
    }

    // Use the shared evaluator for hook mode parity with `dcg test`.
    let eval_start = Instant::now();
    let result = evaluate_command_with_pack_order_deadline_at_path(
        &command,
        &enabled_keywords,
        &ordered_packs,
        keyword_index.as_ref(),
        &compiled_overrides,
        &allowlists,
        &heredoc_settings,
        None, // allow_once_audit
        None, // project_path
        Some(&deadline),
    );

    // NOTE: External packs from custom_paths are now checked in evaluate_command()
    // alongside built-in packs, so no separate fallback check is needed here.

    let eval_duration = eval_start.elapsed();

    if result.skipped_due_to_budget {
        if let Some(writer) = history_writer.as_ref() {
            let entry = build_history_entry(
                &command,
                &working_dir,
                HistoryOutcome::Allow,
                eval_duration,
                None,
                None,
                None,
            );
            writer.log(entry);
        }
        if let Some(log_file) = config.general.log_file.as_deref() {
            let _ = hook::log_budget_skip(
                log_file,
                &command,
                "evaluation",
                deadline.elapsed(),
                HOOK_EVALUATION_BUDGET,
            );
        }
        return;
    }

    if result.decision != EvaluationDecision::Deny {
        if let Some(writer) = history_writer.as_ref() {
            let mut pack_id = None;
            let mut pattern_name = None;
            let mut allowlist_layer = None;

            if let Some(override_) = result.allowlist_override.as_ref() {
                allowlist_layer = Some(override_.layer.label());
                pack_id = override_.matched.pack_id.as_deref();
                pattern_name = override_.matched.pattern_name.as_deref();
            }

            let entry = build_history_entry(
                &command,
                &working_dir,
                HistoryOutcome::Allow,
                eval_duration,
                pack_id,
                pattern_name,
                allowlist_layer,
            );
            writer.log(entry);
        }
        return;
    }

    let Some(ref info) = result.pattern_info else {
        // Fail open: structurally unexpected, but hook safety wins.
        if let Some(writer) = history_writer.as_ref() {
            let entry = build_history_entry(
                &command,
                &working_dir,
                HistoryOutcome::Allow,
                eval_duration,
                None,
                None,
                None,
            );
            writer.log(entry);
        }
        return;
    };

    let pack = info.pack_id.as_deref();
    let mut mode = match info.source {
        MatchSource::Pack | MatchSource::HeredocAst => {
            config
                .policy()
                .resolve_mode(pack, info.pattern_name.as_deref(), info.severity)
        }
        // Never downgrade explicit blocks.
        MatchSource::ConfigOverride | MatchSource::LegacyPattern => DecisionMode::Deny,
    };

    // Apply confidence scoring (if enabled) to potentially downgrade Deny to Warn.
    // Only applies to pack/heredoc matches, not config overrides.
    if matches!(info.source, MatchSource::Pack | MatchSource::HeredocAst) {
        let sanitized = sanitize_for_pattern_matching(&command);
        let normalized_command = normalize_command(&command);
        let normalized_sanitized = normalize_command(sanitized.as_ref());

        let mut confidence_command = command.as_str();
        let mut confidence_sanitized: Option<&str> = None;

        if normalized_command.len() == normalized_sanitized.len() {
            confidence_command = normalized_command.as_ref();
            if sanitized.as_ref() != command {
                confidence_sanitized = Some(normalized_sanitized.as_ref());
            }
        }

        let confidence_result = destructive_command_guard::apply_confidence_scoring(
            confidence_command,
            confidence_sanitized,
            &result,
            mode,
            &config.confidence,
        );
        mode = confidence_result.mode;
    }

    let pattern = info.pattern_name.as_deref();
    let explanation = info.explanation.as_deref();

    if let Some(writer) = history_writer.as_ref() {
        let outcome = match mode {
            DecisionMode::Deny => HistoryOutcome::Deny,
            DecisionMode::Warn => HistoryOutcome::Warn,
            DecisionMode::Log => HistoryOutcome::Allow,
        };
        let entry = build_history_entry(
            &command,
            &working_dir,
            outcome,
            eval_duration,
            pack,
            pattern,
            None,
        );
        writer.log(entry);
    }

    match mode {
        DecisionMode::Deny => {
            let store_path = PendingExceptionStore::default_path(cwd_path.as_deref());
            let store = PendingExceptionStore::new(store_path);
            let reason = match (pack, pattern) {
                (Some(pack_id), Some(pattern_name)) => {
                    format!("{pack_id}:{pattern_name} - {}", info.reason)
                }
                _ => info.reason.clone(),
            };

            let mut allow_once_info: Option<hook::AllowOnceInfo> = None;
            if let Ok((record, maintenance)) = store.record_block(
                &command,
                &working_dir,
                &reason,
                &config.logging.redaction,
                false,
                Some(format!("{:?}", info.source)),
                None,
            ) {
                allow_once_info = Some(hook::AllowOnceInfo {
                    code: record.short_code,
                    full_hash: record.full_hash,
                });
                if let Some(log_file) = config.general.log_file.as_deref() {
                    let _ = log_maintenance(log_file, maintenance, "record_block");
                }
            }

            hook::output_denial_for_protocol(
                hook_protocol,
                &command,
                &info.reason,
                pack,
                pattern,
                explanation,
                allow_once_info.as_ref(),
                info.matched_span.as_ref(),
                info.severity,
                None, // confidence not yet available in PatternMatch
                info.suggestions,
            );

            // Log if configured
            if let Some(log_file) = &config.general.log_file {
                let _ = hook::log_blocked_command(log_file, &command, &info.reason, pack);
            }
        }
        DecisionMode::Warn => {
            hook::output_warning(&command, &info.reason, pack, pattern, explanation);
        }
        DecisionMode::Log => {
            // Silent allow; optionally log to file for history.
            if let Some(log_file) = &config.general.log_file {
                let _ = hook::log_blocked_command(log_file, &command, &info.reason, pack);
            }
        }
    }
}

/// Print help information.
#[allow(clippy::too_many_lines)]
fn print_help() {
    eprintln!();
    eprintln!("  🛡  {} {}", "dcg".green().bold(), PKG_VERSION.cyan());
    eprintln!(
        "     {}",
        "Destructive Command Guard - A Claude Code safety hook".bright_black()
    );
    eprintln!();

    // Usage section
    eprintln!("  {}", "USAGE".yellow().bold());
    eprintln!("  {}", "─".repeat(50).bright_black());
    eprintln!(
        "    This tool runs as a Claude Code {} hook.",
        "PreToolUse".cyan()
    );
    eprintln!("    It reads JSON from stdin and outputs JSON to stdout.");
    eprintln!();

    // Configuration section
    eprintln!("  {}", "CONFIGURATION".yellow().bold());
    eprintln!("  {}", "─".repeat(50).bright_black());
    eprintln!("    Add to {}:", "~/.claude/settings.json".cyan());
    eprintln!();
    eprintln!(
        "    {}",
        "╭──────────────────────────────────────────────────────────────╮".bright_black()
    );
    eprintln!(
        "    {} {} {}",
        "│".bright_black(),
        r#"{"hooks": {"PreToolUse": [{"matcher": "Bash","#.white(),
        "│".bright_black()
    );
    eprintln!(
        "    {}   {} {}",
        "│".bright_black(),
        r#""hooks": [{"type": "command", "command": "dcg"}]}]}}"#.white(),
        "│".bright_black()
    );
    eprintln!(
        "    {}",
        "╰──────────────────────────────────────────────────────────────╯".bright_black()
    );
    eprintln!();

    // Options section
    eprintln!("  {}", "OPTIONS".yellow().bold());
    eprintln!("  {}", "─".repeat(50).bright_black());
    eprintln!(
        "    {}     Print version information",
        "--version, -V".green()
    );
    eprintln!(
        "    {}        Print this help message",
        "--help, -h".green()
    );
    eprintln!();

    // Commands section
    eprintln!("  {}", "COMMANDS".yellow().bold());
    eprintln!("  {}", "─".repeat(50).bright_black());
    eprintln!(
        "    {}         Test a command against enabled packs",
        "test".green()
    );
    eprintln!(
        "    {}      Explain why a command would be blocked/allowed",
        "explain".green()
    );
    eprintln!(
        "    {}       Check installation and hook registration",
        "doctor".green()
    );
    eprintln!(
        "    {}        List all available packs and their status",
        "packs".green()
    );
    eprintln!(
        "    {}         Pack management commands (info, validate)",
        "pack".green()
    );
    eprintln!(
        "    {}    Manage allowlist entries (add, list, remove)",
        "allowlist".green()
    );
    eprintln!("    {}        Add a rule to the allowlist", "allow".green());
    eprintln!(
        "    {}      Remove a rule from the allowlist",
        "unallow".green()
    );
    eprintln!(
        "    {}   Allow a blocked command once via short code",
        "allow-once".green()
    );
    eprintln!(
        "    {}         Scan files for destructive commands",
        "scan".green()
    );
    eprintln!(
        "    {}     Simulate policy evaluation on command logs",
        "simulate".green()
    );
    eprintln!("    {}       Show current configuration", "config".green());
    eprintln!(
        "    {}         Generate a sample configuration file",
        "init".green()
    );
    eprintln!(
        "    {}      Install the hook into Claude Code settings",
        "install".green()
    );
    eprintln!(
        "    {}    Remove the hook from Claude Code settings",
        "uninstall".green()
    );
    eprintln!(
        "    {}       Update dcg to the latest release",
        "update".green()
    );
    eprintln!(
        "    {}        Show local statistics from the log file",
        "stats".green()
    );
    eprintln!(
        "    {}      Query command history database",
        "history".green()
    );
    eprintln!(
        "    {}  Suggest allowlist patterns from history",
        "suggest-allowlist".green()
    );
    eprintln!("    {}       Run regression corpus tests", "corpus".green());
    eprintln!(
        "    {}         Run in explicit hook mode (batch support)",
        "hook".green()
    );
    eprintln!(
        "    {}  Generate shell completion scripts",
        "completions".green()
    );
    eprintln!(
        "    {}          Developer tools for pack development",
        "dev".green()
    );
    eprintln!(
        "    {}   Start MCP server for agent integration",
        "mcp-server".green()
    );
    eprintln!();
    eprintln!(
        "    Run {} for detailed help on a command.",
        "dcg <command> --help".cyan()
    );
    eprintln!();

    // Environment section
    eprintln!("  {}", "ENVIRONMENT".yellow().bold());
    eprintln!("  {}", "─".repeat(50).bright_black());
    eprintln!(
        "    {}=0-3     Verbosity level (0 = quiet, 3 = trace)",
        "DCG_VERBOSE".green()
    );
    eprintln!(
        "    {}=1       Suppress non-error output",
        "DCG_QUIET".green()
    );
    eprintln!(
        "    {}=1    Disable colored output (same as NO_COLOR)",
        "DCG_NO_COLOR".green()
    );
    eprintln!(
        "    {}=text|json|sarif  Default output format (command-specific)",
        "DCG_FORMAT".green()
    );
    eprintln!(
        "    {}=/path  Use explicit config file",
        "DCG_CONFIG".green()
    );
    eprintln!(
        "    {}=ms  Hook evaluation timeout budget",
        "DCG_HOOK_TIMEOUT_MS".green()
    );
    eprintln!(
        "    {}=1      Robot mode for AI agents (JSON output, no stderr)",
        "DCG_ROBOT".green()
    );
    eprintln!();

    // Blocked commands section
    eprintln!("  {}", "BLOCKED COMMANDS".yellow().bold());
    eprintln!("  {}", "─".repeat(50).bright_black());
    eprintln!();
    eprintln!(
        "    {} {}",
        "Git".red().bold(),
        "(core.git pack)".bright_black()
    );
    eprintln!("      {} git reset --hard", "•".red());
    eprintln!("      {} git checkout -- <path>", "•".red());
    eprintln!("      {} git restore (without --staged)", "•".red());
    eprintln!("      {} git clean -f", "•".red());
    eprintln!("      {} git push --force", "•".red());
    eprintln!("      {} git branch -D", "•".red());
    eprintln!("      {} git stash drop/clear", "•".red());
    eprintln!();
    eprintln!(
        "    {} {}",
        "Filesystem".red().bold(),
        "(core.filesystem pack)".bright_black()
    );
    eprintln!(
        "      {} rm -rf outside of /tmp, /var/tmp, $TMPDIR",
        "•".red()
    );
    eprintln!();

    // Additional packs note
    eprintln!("    📦 Additional packs: containers.docker, kubernetes.kubectl,");
    eprintln!("       databases.sql, cloud.terraform, and more.");
    eprintln!();

    // Links section
    eprintln!("  {}", "─".repeat(50).bright_black());
    eprintln!(
        "    📖 {}",
        "https://github.com/Dicklesworthstone/destructive_command_guard"
            .blue()
            .underline()
    );
    eprintln!();
}

#[cfg(test)]
mod tests {
    use super::*;

    mod input_parsing_tests {
        use super::*;

        fn parse_and_get_command(json: &str) -> Option<String> {
            let hook_input: HookInput = serde_json::from_str(json).ok()?;
            hook::extract_command(&hook_input)
        }

        #[test]
        fn parses_valid_bash_input() {
            let json = r#"{"tool_name": "Bash", "tool_input": {"command": "git status"}}"#;
            assert_eq!(parse_and_get_command(json), Some("git status".to_string()));
        }

        #[test]
        fn rejects_non_bash_tool() {
            let json = r#"{"tool_name": "Read", "tool_input": {"command": "git status"}}"#;
            assert_eq!(parse_and_get_command(json), None);
        }

        #[test]
        fn parses_valid_copilot_input() {
            let json = r#"{"event":"pre-tool-use","toolName":"run_shell_command","toolInput":{"command":"git status"}}"#;
            assert_eq!(parse_and_get_command(json), Some("git status".to_string()));
        }

        #[test]
        fn rejects_missing_tool_name() {
            let json = r#"{"tool_input": {"command": "git status"}}"#;
            assert_eq!(parse_and_get_command(json), None);
        }

        #[test]
        fn rejects_missing_tool_input() {
            let json = r#"{"tool_name": "Bash"}"#;
            assert_eq!(parse_and_get_command(json), None);
        }

        #[test]
        fn rejects_missing_command() {
            let json = r#"{"tool_name": "Bash", "tool_input": {}}"#;
            assert_eq!(parse_and_get_command(json), None);
        }

        #[test]
        fn rejects_empty_command() {
            let json = r#"{"tool_name": "Bash", "tool_input": {"command": ""}}"#;
            assert_eq!(parse_and_get_command(json), None);
        }

        #[test]
        fn rejects_non_string_command() {
            let json = r#"{"tool_name": "Bash", "tool_input": {"command": 123}}"#;
            assert_eq!(parse_and_get_command(json), None);
        }

        #[test]
        fn rejects_invalid_json() {
            assert_eq!(parse_and_get_command("not json"), None);
            assert_eq!(parse_and_get_command("{invalid}"), None);
        }
    }

    mod deny_output_tests {
        use super::*;
        use destructive_command_guard::hook::{HookOutput, HookSpecificOutput};

        fn capture_deny_output(command: &str, reason: &str) -> HookOutput<'static> {
            HookOutput {
                hook_specific_output: HookSpecificOutput {
                    hook_event_name: "PreToolUse",
                    permission_decision: "deny",
                    permission_decision_reason: Cow::Owned(format!(
                        "BLOCKED by dcg\n\n\
                         Reason: {reason}\n\n\
                         Command: {command}\n\n\
                         If this operation is truly needed, ask the user for explicit \
                         permission and have them run the command manually."
                    )),
                    allow_once_code: None,
                    allow_once_full_hash: None,
                    rule_id: None,
                    pack_id: None,
                    severity: None,
                    confidence: None,
                    remediation: None,
                },
            }
        }

        #[test]
        fn deny_output_has_correct_structure() {
            let output = capture_deny_output("git reset --hard", "test reason");
            let json = serde_json::to_string(&output).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

            assert_eq!(parsed["hookSpecificOutput"]["hookEventName"], "PreToolUse");
            assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "deny");
            assert!(
                parsed["hookSpecificOutput"]["permissionDecisionReason"]
                    .as_str()
                    .unwrap()
                    .contains("git reset --hard")
            );
            assert!(
                parsed["hookSpecificOutput"]["permissionDecisionReason"]
                    .as_str()
                    .unwrap()
                    .contains("test reason")
            );
        }

        #[test]
        fn deny_output_is_valid_json() {
            let output = capture_deny_output("rm -rf /", "dangerous");
            let json = serde_json::to_string(&output).unwrap();
            assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());
        }
    }

    /// Regression tests for git_safety_guard-99e.1 (BUG: Non-core packs unreachable)
    ///
    /// These tests verify that when non-core packs (docker, kubectl, etc.) are enabled,
    /// their commands actually reach the pack checking logic and get blocked appropriately.
    ///
    /// The bug was that `global_quick_reject` only checked for "git" and "rm" keywords,
    /// causing all non-git/rm commands to be allowed before reaching pack checks.
    mod pack_reachability_tests {
        use super::*;
        use std::collections::HashSet;

        /// Test that `pack_aware_quick_reject` does NOT reject docker commands
        /// when docker keywords are in the enabled keywords list.
        #[test]
        fn pack_aware_quick_reject_allows_docker_when_enabled() {
            // Docker pack keywords
            let docker_keywords: Vec<&str> = vec!["docker", "prune", "rmi", "volume"];

            // Commands that should NOT be rejected (contain docker keywords)
            assert!(
                !pack_aware_quick_reject("docker system prune", &docker_keywords),
                "docker system prune should NOT be quick-rejected when docker pack enabled"
            );
            assert!(
                !pack_aware_quick_reject("docker volume prune", &docker_keywords),
                "docker volume prune should NOT be quick-rejected when docker pack enabled"
            );
            assert!(
                !pack_aware_quick_reject("docker ps", &docker_keywords),
                "docker ps should NOT be quick-rejected when docker pack enabled"
            );
            assert!(
                !pack_aware_quick_reject("docker rmi -f myimage", &docker_keywords),
                "docker rmi should NOT be quick-rejected when docker pack enabled"
            );

            // Commands that SHOULD be rejected (no docker keywords)
            assert!(
                pack_aware_quick_reject("ls -la", &docker_keywords),
                "ls should be quick-rejected (no docker keywords)"
            );
            assert!(
                pack_aware_quick_reject("cargo build", &docker_keywords),
                "cargo should be quick-rejected (no docker keywords)"
            );
        }

        /// Test that `pack_aware_quick_reject` does NOT reject kubectl commands
        /// when kubectl keywords are in the enabled keywords list.
        #[test]
        fn pack_aware_quick_reject_allows_kubectl_when_enabled() {
            // kubectl pack keywords (from kubernetes/kubectl.rs)
            let kubectl_keywords: Vec<&str> = vec!["kubectl", "delete", "drain", "cordon", "taint"];

            // Commands that should NOT be rejected
            assert!(
                !pack_aware_quick_reject("kubectl delete namespace foo", &kubectl_keywords),
                "kubectl delete should NOT be quick-rejected when kubectl pack enabled"
            );
            assert!(
                !pack_aware_quick_reject("kubectl get pods", &kubectl_keywords),
                "kubectl get should NOT be quick-rejected when kubectl pack enabled"
            );

            // Commands that SHOULD be rejected
            assert!(
                pack_aware_quick_reject("ls -la", &kubectl_keywords),
                "ls should be quick-rejected (no kubectl keywords)"
            );
        }

        /// Test that the pack registry correctly blocks docker system prune
        /// when the containers.docker pack is enabled.
        #[test]
        fn registry_blocks_docker_prune_when_pack_enabled() {
            let mut enabled = HashSet::new();
            enabled.insert("containers.docker".to_string());

            let result = REGISTRY.check_command("docker system prune", &enabled);
            assert!(
                result.blocked,
                "docker system prune should be blocked when containers.docker pack is enabled"
            );
            assert_eq!(
                result.pack_id.as_deref(),
                Some("containers.docker"),
                "Block should be attributed to containers.docker pack"
            );
        }

        /// Test that docker ps is allowed (safe pattern) even when docker pack enabled.
        #[test]
        fn registry_allows_docker_ps_when_pack_enabled() {
            let mut enabled = HashSet::new();
            enabled.insert("containers.docker".to_string());

            let result = REGISTRY.check_command("docker ps", &enabled);
            assert!(
                !result.blocked,
                "docker ps should be allowed (safe pattern) even when containers.docker pack enabled"
            );
        }

        /// Test that docker system prune is NOT blocked when docker pack is disabled.
        #[test]
        fn registry_allows_docker_prune_when_pack_disabled() {
            // Only core pack enabled (default)
            let mut enabled = HashSet::new();
            enabled.insert("core".to_string());

            let result = REGISTRY.check_command("docker system prune", &enabled);
            assert!(
                !result.blocked,
                "docker system prune should be allowed when containers.docker pack is NOT enabled"
            );
        }

        /// Test that kubectl delete namespace is blocked when kubectl pack enabled.
        #[test]
        fn registry_blocks_kubectl_delete_namespace_when_pack_enabled() {
            let mut enabled = HashSet::new();
            enabled.insert("kubernetes.kubectl".to_string());

            let result = REGISTRY.check_command("kubectl delete namespace production", &enabled);
            assert!(
                result.blocked,
                "kubectl delete namespace should be blocked when kubernetes.kubectl pack is enabled"
            );
            assert_eq!(
                result.pack_id.as_deref(),
                Some("kubernetes.kubectl"),
                "Block should be attributed to kubernetes.kubectl pack"
            );
        }

        /// Test that enabling a category enables all sub-packs.
        #[test]
        fn registry_expands_category_to_subpacks() {
            let mut enabled = HashSet::new();
            enabled.insert("containers".to_string()); // Category, not specific pack

            let result = REGISTRY.check_command("docker system prune", &enabled);
            assert!(
                result.blocked,
                "docker system prune should be blocked when 'containers' category is enabled"
            );
        }

        /// Test that `collect_enabled_keywords` includes docker keywords when docker pack enabled.
        #[test]
        fn collect_enabled_keywords_includes_docker() {
            let mut enabled = HashSet::new();
            enabled.insert("containers.docker".to_string());

            let keywords = REGISTRY.collect_enabled_keywords(&enabled);

            assert!(
                keywords.contains(&"docker"),
                "Enabled keywords should include 'docker' when containers.docker pack is enabled"
            );
            // "prune" is NOT a keyword for containers.docker (it would trigger on git prune)
            // assert!(
            //    keywords.contains(&"prune"),
            //    "Enabled keywords should include 'prune' when containers.docker pack is enabled"
            // );
        }

        /// Integration test: full pipeline blocks docker prune with pack enabled.
        /// This simulates what happens in hook mode when docker pack is enabled.
        #[test]
        fn full_pipeline_blocks_docker_prune_with_pack_enabled() {
            let command = "docker system prune";

            // Simulate config with docker pack enabled
            let mut enabled_packs = HashSet::new();
            enabled_packs.insert("core".to_string());
            enabled_packs.insert("containers.docker".to_string());

            // Collect keywords from enabled packs
            let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);

            // Step 1: pack_aware_quick_reject should NOT reject this command
            assert!(
                !pack_aware_quick_reject(command, &enabled_keywords),
                "docker system prune should NOT be quick-rejected with docker pack enabled"
            );

            // Step 2: Normalize command
            let normalized = normalize_command(command);

            // Step 3: Check against pack registry (should block)
            let result = REGISTRY.check_command(&normalized, &enabled_packs);
            assert!(
                result.blocked,
                "docker system prune should be blocked by pack registry"
            );
            assert_eq!(
                result.pack_id.as_deref(),
                Some("containers.docker"),
                "Block should be from containers.docker pack"
            );
        }

        /// Integration test: full pipeline allows docker ps with pack enabled.
        #[test]
        fn full_pipeline_allows_docker_ps_with_pack_enabled() {
            let command = "docker ps";

            let mut enabled_packs = HashSet::new();
            enabled_packs.insert("core".to_string());
            enabled_packs.insert("containers.docker".to_string());

            let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);

            // Should NOT be quick-rejected
            assert!(
                !pack_aware_quick_reject(command, &enabled_keywords),
                "docker ps should NOT be quick-rejected"
            );

            let normalized = normalize_command(command);
            let result = REGISTRY.check_command(&normalized, &enabled_packs);

            assert!(
                !result.blocked,
                "docker ps should be allowed (matches safe pattern)"
            );
        }
    }

    // ========================================================================
    // Input size limit tests (git_safety_guard-99e.10)
    // ========================================================================

    mod input_limit_tests {
        use super::*;

        #[test]
        fn config_default_limits() {
            let config = Config::default();
            // Verify defaults are set correctly
            assert_eq!(config.general.max_hook_input_bytes(), 256 * 1024);
            assert_eq!(config.general.max_command_bytes(), 64 * 1024);
            assert_eq!(config.general.max_findings_per_command(), 100);
        }

        #[test]
        fn config_custom_limits() {
            let mut config = Config::default();
            config.general.max_hook_input_bytes = Some(128 * 1024);
            config.general.max_command_bytes = Some(32 * 1024);
            config.general.max_findings_per_command = Some(50);

            assert_eq!(config.general.max_hook_input_bytes(), 128 * 1024);
            assert_eq!(config.general.max_command_bytes(), 32 * 1024);
            assert_eq!(config.general.max_findings_per_command(), 50);
        }

        #[test]
        #[allow(clippy::assertions_on_constants)]
        fn default_constants_are_reasonable() {
            use destructive_command_guard::config::{
                DEFAULT_MAX_COMMAND_BYTES, DEFAULT_MAX_FINDINGS_PER_COMMAND,
                DEFAULT_MAX_HOOK_INPUT_BYTES,
            };
            // Verify constants are reasonable sizes (compile-time validations)
            assert!(DEFAULT_MAX_HOOK_INPUT_BYTES >= 64 * 1024); // At least 64KB
            assert!(DEFAULT_MAX_HOOK_INPUT_BYTES <= 1024 * 1024); // At most 1MB
            assert!(DEFAULT_MAX_COMMAND_BYTES >= 16 * 1024); // At least 16KB
            assert!(DEFAULT_MAX_COMMAND_BYTES <= 256 * 1024); // At most 256KB
            assert!(DEFAULT_MAX_FINDINGS_PER_COMMAND >= 10); // At least 10
            assert!(DEFAULT_MAX_FINDINGS_PER_COMMAND <= 1000); // At most 1000
        }
    }
}
