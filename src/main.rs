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
use destructive_command_guard::config::Config;
use destructive_command_guard::evaluator::{
    EvaluationDecision, MatchSource, evaluate_command_with_pack_order_deadline,
};
use destructive_command_guard::hook;
use destructive_command_guard::perf::{Deadline, HOOK_EVALUATION_BUDGET};
use destructive_command_guard::load_default_allowlists;
use destructive_command_guard::packs::{DecisionMode, REGISTRY};
#[cfg(test)]
use destructive_command_guard::packs::{normalize_command, pack_aware_quick_reject};
#[cfg(test)]
use fancy_regex::Regex;
#[cfg(test)]
use memchr::memmem;
// Import HookInput for parsing stdin JSON in hook mode
use destructive_command_guard::hook::HookInput;
#[cfg(test)]
use std::borrow::Cow;
use std::collections::HashSet;
use std::io::{self, IsTerminal, Read};
#[cfg(test)]
use std::sync::LazyLock;

// Build metadata from vergen (set by build.rs)
const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_TIMESTAMP: Option<&str> = option_env!("VERGEN_BUILD_TIMESTAMP");
const RUSTC_SEMVER: Option<&str> = option_env!("VERGEN_RUSTC_SEMVER");
const CARGO_TARGET: Option<&str> = option_env!("VERGEN_CARGO_TARGET_TRIPLE");

// NOTE: HookInput, ToolInput, HookOutput, HookSpecificOutput types are now defined
// in the hook module. Use hook::HookInput, hook::read_hook_input(), etc.

/// A safe pattern that, when matched, allows the command immediately.
#[cfg(test)]
struct Pattern {
    regex: Regex,
    /// Debug name for the pattern (used in error messages and tests).
    #[allow(dead_code)]
    name: &'static str,
}

/// A destructive pattern that, when matched, blocks the command.
#[cfg(test)]
struct DestructivePattern {
    regex: Regex,
    /// Human-readable explanation of why this command is blocked.
    reason: &'static str,
}

#[cfg(test)]
macro_rules! pattern {
    ($name:literal, $re:literal) => {
        Pattern {
            regex: Regex::new($re).expect(concat!("pattern '", $name, "' should compile")),
            name: $name,
        }
    };
}

#[cfg(test)]
macro_rules! destructive {
    ($re:literal, $reason:literal) => {
        DestructivePattern {
            regex: Regex::new($re).expect(concat!("destructive pattern should compile: ", $re)),
            reason: $reason,
        }
    };
}

#[cfg(test)]
static SAFE_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![
        pattern!("checkout-new-branch", r"git\s+checkout\s+-b\s+"),
        pattern!("checkout-orphan", r"git\s+checkout\s+--orphan\s+"),
        pattern!(
            "restore-staged-long",
            r"git\s+restore\s+--staged\s+(?!.*--worktree)(?!.*-W\b)"
        ),
        pattern!(
            "restore-staged-short",
            r"git\s+restore\s+-S\s+(?!.*--worktree)(?!.*-W\b)"
        ),
        pattern!("clean-dry-run-short", r"git\s+clean\s+-[a-z]*n[a-z]*"),
        pattern!("clean-dry-run-long", r"git\s+clean\s+--dry-run"),
        pattern!(
            "rm-rf-tmp-1",
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        pattern!(
            "rm-fr-tmp-1",
            r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        pattern!(
            "rm-rf-var-tmp-1",
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        pattern!(
            "rm-fr-var-tmp-1",
            r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        pattern!(
            "rm-rf-tmpdir-1",
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        pattern!(
            "rm-fr-tmpdir-1",
            r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        pattern!(
            "rm-rf-tmpdir-brace-1",
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+\$\{TMPDIR(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        pattern!(
            "rm-fr-tmpdir-brace-1",
            r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+\$\{TMPDIR(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        pattern!(
            "rm-rf-tmpdir-quoted-1",
            r#"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+"\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"#
        ),
        pattern!(
            "rm-fr-tmpdir-quoted-1",
            r#"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+"\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"#
        ),
        pattern!(
            "rm-rf-tmpdir-brace-quoted-1",
            r#"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+"\$\{TMPDIR(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"#
        ),
        pattern!(
            "rm-fr-tmpdir-brace-quoted-1",
            r#"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+"\$\{TMPDIR(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"#
        ),
        pattern!(
            "rm-r-f-tmp",
            r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        pattern!(
            "rm-f-r-tmp",
            r"rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        pattern!(
            "rm-r-f-var-tmp",
            r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        pattern!(
            "rm-f-r-var-tmp",
            r"rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        pattern!(
            "rm-r-f-tmpdir",
            r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        pattern!(
            "rm-f-r-tmpdir",
            r"rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        pattern!(
            "rm-r-f-tmpdir-brace",
            r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+\$\{TMPDIR(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        pattern!(
            "rm-f-r-tmpdir-brace",
            r"rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+\$\{TMPDIR(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        pattern!(
            "rm-recursive-force-tmp",
            r"rm\s+.*--recursive.*--force\s+/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        pattern!(
            "rm-force-recursive-tmp",
            r"rm\s+.*--force.*--recursive\s+/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        pattern!(
            "rm-recursive-force-var-tmp",
            r"rm\s+.*--recursive.*--force\s+/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        pattern!(
            "rm-force-recursive-var-tmp",
            r"rm\s+.*--force.*--recursive\s+/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        pattern!(
            "rm-recursive-force-tmpdir",
            r"rm\s+.*--recursive.*--force\s+\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        pattern!(
            "rm-force-recursive-tmpdir",
            r"rm\s+.*--force.*--recursive\s+\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        pattern!(
            "rm-recursive-force-tmpdir-brace",
            r"rm\s+.*--recursive.*--force\s+\$\{TMPDIR(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        pattern!(
            "rm-force-recursive-tmpdir-brace",
            r"rm\s+.*--force.*--recursive\s+\$\{TMPDIR(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
    ]
});

#[cfg(test)]
static DESTRUCTIVE_PATTERNS: LazyLock<Vec<DestructivePattern>> = LazyLock::new(|| {
    vec![
        destructive!(
            r"git\s+checkout\s+--\s+",
            "git checkout -- discards uncommitted changes permanently. Use 'git stash' first."
        ),
        destructive!(
            r"git\s+checkout\s+(?!-b\b)(?!--orphan\b)[^\s]+\s+--\s+",
            "git checkout <ref> -- <path> overwrites working tree. Use 'git stash' first."
        ),
        destructive!(
            r"git\s+restore\s+(?!--staged\b)(?!-S\b)",
            "git restore discards uncommitted changes. Use 'git stash' or 'git diff' first."
        ),
        destructive!(
            r"git\s+restore\s+.*(?:--worktree|-W\b)",
            "git restore --worktree/-W discards uncommitted changes permanently."
        ),
        destructive!(
            r"git\s+reset\s+--hard",
            "git reset --hard destroys uncommitted changes. Use 'git stash' first."
        ),
        destructive!(
            r"git\s+reset\s+--merge",
            "git reset --merge can lose uncommitted changes."
        ),
        destructive!(
            r"git\s+clean\s+-[a-z]*f",
            "git clean -f removes untracked files permanently. Review with 'git clean -n' first."
        ),
        destructive!(
            r"git\s+push\s+.*--force(?![-a-z])",
            "Force push can destroy remote history. Use --force-with-lease if necessary."
        ),
        destructive!(
            r"git\s+push\s+.*-f\b",
            "Force push (-f) can destroy remote history. Use --force-with-lease if necessary."
        ),
        destructive!(
            r"git\s+branch\s+-D\b",
            "git branch -D force-deletes without merge check. Use -d for safety."
        ),
        destructive!(
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+[/~]|rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+[/~]",
            "rm -rf on root or home paths is EXTREMELY DANGEROUS. This command will NOT be executed. Ask the user to run it manually if truly needed."
        ),
        destructive!(
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f|rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR]",
            "rm -rf is destructive and requires human approval. Explain what you want to delete and why, then ask the user to run the command manually."
        ),
        destructive!(
            r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f|rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]",
            "rm with separate -r -f flags is destructive and requires human approval."
        ),
        destructive!(
            r"rm\s+.*--recursive.*--force|rm\s+.*--force.*--recursive",
            "rm --recursive --force is destructive and requires human approval."
        ),
        destructive!(
            r"git\s+stash\s+drop",
            "git stash drop permanently deletes stashed changes. List stashes first."
        ),
        destructive!(
            r"git\s+stash\s+clear",
            "git stash clear permanently deletes ALL stashed changes."
        ),
    ]
});

/// Pre-compiled finders for quick rejection (SIMD-accelerated).
/// Only used in tests - production code uses `pack_aware_quick_reject` from packs module.
#[cfg(test)]
static GIT_FINDER: LazyLock<memmem::Finder<'static>> = LazyLock::new(|| memmem::Finder::new("git"));
#[cfg(test)]
static RM_FINDER: LazyLock<memmem::Finder<'static>> = LazyLock::new(|| memmem::Finder::new("rm"));

/// Quick rejection filter using SIMD-accelerated substring search.
///
/// Returns `true` if the command can be immediately allowed (no "git" or "rm").
/// This skips expensive regex matching for 99%+ of commands.
///
/// NOTE: This is only used in tests. Production code uses `pack_aware_quick_reject`
/// from the packs module which checks all enabled pack keywords.
#[cfg(test)]
#[inline]
fn quick_reject(cmd: &str) -> bool {
    let bytes = cmd.as_bytes();
    GIT_FINDER.find(bytes).is_none() && RM_FINDER.find(bytes).is_none()
}

/// Configure colored output based on TTY detection.
///
/// Disables colors if stderr is not a terminal (e.g., piped to a file).
fn configure_colors() {
    if !io::stderr().is_terminal() {
        colored::control::set_override(false);
    }
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
    let enabled_packs: HashSet<String> = config.enabled_pack_ids();
    let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);

    // Read stdin with size limit to prevent DoS from pathological inputs.
    // Hook input is typically ~100-200 bytes of JSON.
    // Use take() to enforce size limit (reads up to limit+1 to detect overflow).
    let max_input_bytes = config.general.max_hook_input_bytes();
    let mut input = String::with_capacity(256);
    {
        let mut limited = io::stdin().lock().take(max_input_bytes as u64 + 1);
        if limited.read_to_string(&mut input).is_err() {
            return;
        }
    }

    // Check if input exceeded the limit (fail-open: allow and warn)
    if input.len() > max_input_bytes {
        eprintln!(
            "[dcg] Warning: stdin input ({} bytes) exceeds limit ({} bytes); allowing command (fail-open)",
            input.len(),
            max_input_bytes
        );
        return;
    }

    // Start evaluation deadline after input size checks (includes JSON parse + evaluation).
    let deadline = Deadline::new(HOOK_EVALUATION_BUDGET);

    // Fast path: parse JSON directly from the input buffer
    let Ok(hook_input) = serde_json::from_str::<HookInput>(&input) else {
        return;
    };

    if deadline.is_exceeded() {
        if let (Some(log_file), Some(command)) =
            (config.general.log_file.as_deref(), hook::extract_command(&hook_input))
        {
            let _ = hook::log_budget_skip(
                log_file,
                &command,
                "input_parsing",
                deadline.elapsed(),
                HOOK_EVALUATION_BUDGET,
            );
        }
        return;
    }

    // Only process Bash tool invocations
    if hook_input.tool_name.as_deref() != Some("Bash") {
        return;
    }

    let Some(tool_input) = hook_input.tool_input else {
        return;
    };

    let Some(command_value) = tool_input.command else {
        return;
    };

    let serde_json::Value::String(command) = command_value else {
        return;
    };

    if command.is_empty() {
        return;
    }

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
    let result = evaluate_command_with_pack_order_deadline(
        &command,
        &enabled_keywords,
        &ordered_packs,
        &compiled_overrides,
        &allowlists,
        &heredoc_settings,
        Some(&deadline),
    );

    if result.skipped_due_to_budget {
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
        return;
    }

    let Some(info) = result.pattern_info else {
        // Fail open: structurally unexpected, but hook safety wins.
        return;
    };

    let pack = info.pack_id.as_deref();
    let mode = match info.source {
        MatchSource::Pack | MatchSource::HeredocAst => {
            config
                .policy()
                .resolve_mode(pack, info.pattern_name.as_deref(), info.severity)
        }
        // Never downgrade explicit blocks.
        MatchSource::ConfigOverride | MatchSource::LegacyPattern => DecisionMode::Deny,
    };

    let pattern = info.pattern_name.as_deref();

    match mode {
        DecisionMode::Deny => {
            hook::output_denial(&command, &info.reason, pack, pattern);

            // Log if configured
            if let Some(log_file) = &config.general.log_file {
                let _ = hook::log_blocked_command(log_file, &command, &info.reason, pack);
            }
        }
        DecisionMode::Warn => {
            hook::output_warning(&command, &info.reason, pack, pattern);
        }
        DecisionMode::Log => {
            // Silent allow; optionally log to file for telemetry.
            if let Some(log_file) = &config.general.log_file {
                let _ = hook::log_blocked_command(log_file, &command, &info.reason, pack);
            }
        }
    }
}

/// Print help information.
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

    mod normalize_command_tests {
        use super::*;

        #[test]
        fn preserves_plain_git_command() {
            assert_eq!(normalize_command("git status"), "git status");
        }

        #[test]
        fn preserves_plain_rm_command() {
            assert_eq!(normalize_command("rm -rf /tmp/foo"), "rm -rf /tmp/foo");
        }

        #[test]
        fn strips_usr_bin_git() {
            assert_eq!(normalize_command("/usr/bin/git status"), "git status");
        }

        #[test]
        fn strips_usr_local_bin_git() {
            assert_eq!(
                normalize_command("/usr/local/bin/git checkout -b feature"),
                "git checkout -b feature"
            );
        }

        #[test]
        fn strips_bin_rm() {
            assert_eq!(
                normalize_command("/bin/rm -rf /tmp/test"),
                "rm -rf /tmp/test"
            );
        }

        #[test]
        fn strips_usr_bin_rm() {
            assert_eq!(normalize_command("/usr/bin/rm file.txt"), "rm file.txt");
        }

        #[test]
        fn strips_sbin_path() {
            assert_eq!(normalize_command("/sbin/rm foo"), "rm foo");
        }

        #[test]
        fn strips_usr_sbin_path() {
            assert_eq!(normalize_command("/usr/sbin/rm bar"), "rm bar");
        }

        #[test]
        fn preserves_command_with_path_arguments() {
            assert_eq!(
                normalize_command("git add /usr/bin/something"),
                "git add /usr/bin/something"
            );
        }

        #[test]
        fn handles_empty_string() {
            assert_eq!(normalize_command(""), "");
        }

        #[test]
        fn strips_quotes_from_executed_git_command_word() {
            assert_eq!(
                normalize_command("\"git\" reset --hard"),
                "git reset --hard"
            );
        }

        #[test]
        fn strips_quotes_from_executed_rm_command_word() {
            assert_eq!(normalize_command("\"rm\" -rf /etc"), "rm -rf /etc");
        }

        #[test]
        fn strips_quotes_from_executed_absolute_path_command_word() {
            assert_eq!(
                normalize_command("\"/usr/bin/git\" reset --hard"),
                "git reset --hard"
            );
        }

        #[test]
        fn strips_quotes_after_separators() {
            assert_eq!(
                normalize_command("echo hi; \"rm\" -rf /etc"),
                "echo hi; rm -rf /etc"
            );
        }

        #[test]
        fn strips_quotes_after_wrappers_and_options() {
            assert_eq!(
                normalize_command("sudo -u root \"rm\" -rf /etc"),
                "sudo -u root rm -rf /etc"
            );
        }

        #[test]
        fn does_not_strip_quotes_from_arguments() {
            assert_eq!(
                normalize_command("echo \"rm\" -rf /etc"),
                "echo \"rm\" -rf /etc"
            );
        }

        #[test]
        fn does_not_strip_quotes_for_command_query_mode() {
            assert_eq!(
                normalize_command("command -v \"git\""),
                "command -v \"git\""
            );
        }

        #[test]
        fn strips_quotes_inside_subshell_segments() {
            assert_eq!(normalize_command("( \"rm\" -rf /etc )"), "( rm -rf /etc )");
        }
    }

    mod quick_reject_tests {
        use super::*;

        #[test]
        fn rejects_commands_without_git_or_rm() {
            assert!(quick_reject("ls -la"));
            assert!(quick_reject("cat file.txt"));
            assert!(quick_reject("echo hello"));
            assert!(quick_reject("cargo build"));
            assert!(quick_reject("npm install"));
        }

        #[test]
        fn does_not_reject_git_commands() {
            assert!(!quick_reject("git status"));
            assert!(!quick_reject("git checkout main"));
            assert!(!quick_reject("/usr/bin/git log"));
        }

        #[test]
        fn does_not_reject_rm_commands() {
            assert!(!quick_reject("rm file.txt"));
            assert!(!quick_reject("rm -rf /tmp/test"));
            assert!(!quick_reject("/bin/rm foo"));
        }

        #[test]
        fn does_not_reject_when_git_in_argument() {
            assert!(!quick_reject("cat .git/config"));
            assert!(!quick_reject("ls .gitignore"));
        }

        #[test]
        fn handles_empty_string() {
            assert!(quick_reject(""));
        }
    }

    mod safe_pattern_tests {
        use super::*;

        fn is_safe(cmd: &str) -> bool {
            let normalized = normalize_command(cmd);
            SAFE_PATTERNS
                .iter()
                .any(|p| p.regex.is_match(&normalized).unwrap_or(false))
        }

        #[test]
        fn allows_checkout_new_branch() {
            assert!(is_safe("git checkout -b feature-branch"));
            assert!(is_safe("git checkout -b fix/bug-123"));
        }

        #[test]
        fn allows_checkout_orphan() {
            assert!(is_safe("git checkout --orphan gh-pages"));
            assert!(is_safe("git checkout --orphan new-root"));
        }

        #[test]
        fn allows_restore_staged_only() {
            assert!(is_safe("git restore --staged file.txt"));
            assert!(is_safe("git restore -S file.txt"));
            assert!(is_safe("git restore --staged ."));
        }

        #[test]
        fn rejects_restore_staged_with_worktree() {
            assert!(!is_safe("git restore --staged --worktree file.txt"));
            assert!(!is_safe("git restore --staged -W file.txt"));
            assert!(!is_safe("git restore -S --worktree file.txt"));
            assert!(!is_safe("git restore -S -W file.txt"));
        }

        #[test]
        fn allows_clean_dry_run() {
            assert!(is_safe("git clean -n"));
            assert!(is_safe("git clean -dn"));
            assert!(is_safe("git clean -nd"));
            assert!(is_safe("git clean --dry-run"));
        }

        #[test]
        fn allows_rm_rf_in_tmp() {
            assert!(is_safe("rm -rf /tmp/test"));
            assert!(is_safe("rm -rf /tmp/build-artifacts"));
            assert!(is_safe("rm -Rf /tmp/cache"));
            assert!(is_safe("rm -fr /tmp/stuff"));
            assert!(is_safe("rm -fR /tmp/more"));
        }

        #[test]
        fn rejects_rm_rf_tmp_path_traversal() {
            // Path traversal can escape temp directories (e.g. /tmp/../etc == /etc).
            assert!(!is_safe("rm -rf /tmp/../etc"));
            assert!(!is_safe("rm -rf /tmp/.."));
            assert!(!is_safe("rm -rf /tmp/foo/../../etc"));
            assert!(!is_safe("rm -rf /var/tmp/../etc"));
            assert!(!is_safe("rm -rf $TMPDIR/../etc"));
            assert!(!is_safe("rm -rf ${TMPDIR}/../etc"));
            assert!(!is_safe("rm -r -f /tmp/../etc"));
            assert!(!is_safe("rm --recursive --force /tmp/../etc"));
        }

        #[test]
        fn allows_rm_rf_in_tmp_with_dotdot_in_filename() {
            assert!(is_safe("rm -rf /tmp/foo..bar"));
        }

        #[test]
        fn allows_rm_rf_in_var_tmp() {
            assert!(is_safe("rm -rf /var/tmp/test"));
            assert!(is_safe("rm -fr /var/tmp/cache"));
        }

        #[test]
        fn allows_rm_rf_with_tmpdir_variable() {
            assert!(is_safe("rm -rf $TMPDIR/test"));
            assert!(is_safe("rm -rf ${TMPDIR}/test"));
            assert!(is_safe("rm -rf \"$TMPDIR/test\""));
            assert!(is_safe("rm -rf \"${TMPDIR}/test\""));
        }

        #[test]
        fn allows_rm_with_separate_flags_in_tmp() {
            assert!(is_safe("rm -r -f /tmp/test"));
            assert!(is_safe("rm -f -r /tmp/test"));
            assert!(is_safe("rm -r -f /var/tmp/test"));
            assert!(is_safe("rm -f -r /var/tmp/test"));
        }

        #[test]
        fn allows_rm_with_long_flags_in_tmp() {
            assert!(is_safe("rm --recursive --force /tmp/test"));
            assert!(is_safe("rm --force --recursive /tmp/test"));
            assert!(is_safe("rm --recursive --force /var/tmp/test"));
            assert!(is_safe("rm --force --recursive /var/tmp/test"));
        }

        #[test]
        fn allows_rm_with_separate_flags_in_tmpdir() {
            assert!(is_safe("rm -r -f $TMPDIR/test"));
            assert!(is_safe("rm -f -r $TMPDIR/test"));
            assert!(is_safe("rm -r -f ${TMPDIR}/test"));
            assert!(is_safe("rm -f -r ${TMPDIR}/test"));
        }

        #[test]
        fn allows_rm_with_long_flags_in_tmpdir() {
            assert!(is_safe("rm --recursive --force $TMPDIR/test"));
            assert!(is_safe("rm --force --recursive $TMPDIR/test"));
            assert!(is_safe("rm --recursive --force ${TMPDIR}/test"));
            assert!(is_safe("rm --force --recursive ${TMPDIR}/test"));
        }
    }

    mod destructive_pattern_tests {
        use super::*;

        fn is_destructive(cmd: &str) -> Option<&'static str> {
            let normalized = normalize_command(cmd);
            for pattern in SAFE_PATTERNS.iter() {
                if pattern.regex.is_match(&normalized).unwrap_or(false) {
                    return None;
                }
            }
            for pattern in DESTRUCTIVE_PATTERNS.iter() {
                if pattern.regex.is_match(&normalized).unwrap_or(false) {
                    return Some(pattern.reason);
                }
            }
            None
        }

        #[test]
        fn blocks_git_checkout_dash_dash() {
            let result = is_destructive("git checkout -- file.txt");
            assert!(result.is_some());
            assert!(result.unwrap().contains("discard"));
        }

        #[test]
        fn blocks_git_checkout_ref_dash_dash_path() {
            let result = is_destructive("git checkout HEAD -- file.txt");
            assert!(result.is_some());
        }

        #[test]
        fn blocks_git_restore_without_staged() {
            let result = is_destructive("git restore file.txt");
            assert!(result.is_some());
            assert!(result.unwrap().contains("discard"));
        }

        #[test]
        fn blocks_git_restore_with_worktree() {
            assert!(is_destructive("git restore --worktree file.txt").is_some());
            assert!(is_destructive("git restore -W file.txt").is_some());
        }

        #[test]
        fn blocks_git_reset_hard() {
            let result = is_destructive("git reset --hard");
            assert!(result.is_some());
            assert!(result.unwrap().contains("destroys"));
        }

        #[test]
        fn blocks_git_reset_hard_with_ref() {
            assert!(is_destructive("git reset --hard HEAD~1").is_some());
            assert!(is_destructive("git reset --hard origin/main").is_some());
        }

        #[test]
        fn blocks_git_reset_merge() {
            let result = is_destructive("git reset --merge");
            assert!(result.is_some());
        }

        #[test]
        fn blocks_git_clean_force() {
            let result = is_destructive("git clean -f");
            assert!(result.is_some());
            assert!(result.unwrap().contains("untracked"));
        }

        #[test]
        fn blocks_git_clean_df() {
            assert!(is_destructive("git clean -df").is_some());
            assert!(is_destructive("git clean -fd").is_some());
        }

        #[test]
        fn blocks_git_push_force() {
            let result = is_destructive("git push --force");
            assert!(result.is_some());
            assert!(result.unwrap().contains("remote history"));

            assert!(is_destructive("git push origin main --force").is_some());
            assert!(is_destructive("git push --force origin main").is_some());
        }

        #[test]
        fn blocks_git_push_f() {
            assert!(is_destructive("git push -f").is_some());
            assert!(is_destructive("git push origin main -f").is_some());
        }

        #[test]
        fn blocks_git_branch_force_delete() {
            let result = is_destructive("git branch -D feature-branch");
            assert!(result.is_some());
            assert!(result.unwrap().contains("force-delete"));
        }

        #[test]
        fn blocks_rm_rf_on_root_paths() {
            assert!(is_destructive("rm -rf /").is_some());
            assert!(is_destructive("rm -rf /etc").is_some());
            assert!(is_destructive("rm -rf /home").is_some());
            assert!(is_destructive("rm -rf ~/").is_some());
            assert!(is_destructive("rm -rf ~/Documents").is_some());
        }

        #[test]
        fn blocks_rm_rf_outside_safe_dirs() {
            assert!(is_destructive("rm -rf ./build").is_some());
            assert!(is_destructive("rm -rf node_modules").is_some());
        }

        #[test]
        fn blocks_rm_with_separate_rf_flags() {
            assert!(is_destructive("rm -r -f ./build").is_some());
            assert!(is_destructive("rm -f -r ./build").is_some());
        }

        #[test]
        fn blocks_rm_with_long_flags() {
            assert!(is_destructive("rm --recursive --force ./build").is_some());
            assert!(is_destructive("rm --force --recursive ./build").is_some());
        }

        #[test]
        fn blocks_git_stash_drop() {
            let result = is_destructive("git stash drop");
            assert!(result.is_some());
            assert!(result.unwrap().contains("stash"));
        }

        #[test]
        fn blocks_git_stash_drop_with_ref() {
            assert!(is_destructive("git stash drop stash@{0}").is_some());
            assert!(is_destructive("git stash drop 1").is_some());
        }

        #[test]
        fn blocks_git_stash_clear() {
            let result = is_destructive("git stash clear");
            assert!(result.is_some());
            assert!(result.unwrap().contains("ALL stashed"));
        }

        #[test]
        fn allows_safe_git_commands() {
            assert!(is_destructive("git status").is_none());
            assert!(is_destructive("git log").is_none());
            assert!(is_destructive("git diff").is_none());
            assert!(is_destructive("git add .").is_none());
            assert!(is_destructive("git commit -m 'test'").is_none());
            assert!(is_destructive("git push").is_none());
            assert!(is_destructive("git pull").is_none());
            assert!(is_destructive("git fetch").is_none());
            assert!(is_destructive("git branch -d feature").is_none());
            assert!(is_destructive("git stash").is_none());
            assert!(is_destructive("git stash pop").is_none());
            assert!(is_destructive("git stash list").is_none());
        }

        #[test]
        fn allows_push_with_force_with_lease() {
            assert!(is_destructive("git push --force-with-lease").is_none());
            assert!(is_destructive("git push origin main --force-with-lease").is_none());
        }
    }

    mod input_parsing_tests {
        use super::*;

        fn parse_and_get_command(json: &str) -> Option<String> {
            let hook_input: HookInput = serde_json::from_str(json).ok()?;
            if hook_input.tool_name.as_deref() != Some("Bash") {
                return None;
            }
            let tool_input = hook_input.tool_input?;
            let command_value = tool_input.command?;
            match command_value {
                serde_json::Value::String(s) if !s.is_empty() => Some(s),
                _ => None,
            }
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

    mod integration_tests {
        use super::*;

        fn would_block(cmd: &str) -> bool {
            if quick_reject(cmd) {
                return false;
            }
            let normalized = normalize_command(cmd);
            for pattern in SAFE_PATTERNS.iter() {
                if pattern.regex.is_match(&normalized).unwrap_or(false) {
                    return false;
                }
            }
            for pattern in DESTRUCTIVE_PATTERNS.iter() {
                if pattern.regex.is_match(&normalized).unwrap_or(false) {
                    return true;
                }
            }
            false
        }

        #[test]
        fn full_pipeline_blocks_dangerous_commands() {
            assert!(would_block("git reset --hard"));
            assert!(would_block("git checkout -- ."));
            assert!(would_block("rm -rf ~/"));
            assert!(would_block("/usr/bin/git reset --hard HEAD"));
            assert!(would_block("/bin/rm -rf /etc"));
        }

        #[test]
        fn full_pipeline_allows_safe_commands() {
            assert!(!would_block("git status"));
            assert!(!would_block("git checkout -b feature"));
            assert!(!would_block("rm -rf /tmp/build"));
            assert!(!would_block("ls -la"));
            assert!(!would_block("cargo build"));
            assert!(!would_block("git clean -n"));
        }

        #[test]
        fn full_pipeline_with_absolute_paths() {
            assert!(would_block("/usr/bin/git reset --hard"));
            assert!(!would_block("/usr/bin/git checkout -b feature"));
            assert!(would_block("/bin/rm -rf /home/user"));
            assert!(!would_block("/bin/rm -rf /tmp/cache"));
        }
    }

    mod optimization_tests {
        use super::*;

        #[test]
        fn normalize_command_returns_borrowed_for_plain_commands() {
            let cmd = "git status";
            let result = normalize_command(cmd);
            // Should be Cow::Borrowed (no allocation)
            assert!(matches!(result, Cow::Borrowed(_)));
            assert_eq!(result, "git status");
        }

        #[test]
        fn normalize_command_returns_owned_for_path_commands() {
            let result = normalize_command("/usr/bin/git status");
            // Should be Cow::Owned (allocation required)
            assert!(matches!(result, Cow::Owned(_)));
            assert_eq!(result, "git status");
        }

        #[test]
        fn normalize_command_fast_path_for_non_slash_commands() {
            // Commands not starting with '/' should take the fast path
            let result = normalize_command("git push origin main");
            assert!(matches!(result, Cow::Borrowed(_)));
        }

        #[test]
        fn quick_reject_uses_memchr_correctly() {
            // These should be rejected (no git or rm)
            assert!(quick_reject("ls -la /home/user"));
            assert!(quick_reject("cat /etc/passwd"));
            assert!(quick_reject("echo 'hello world'"));
            assert!(quick_reject("curl https://example.com"));
            assert!(quick_reject("python script.py"));
            assert!(quick_reject("node app.js"));
            assert!(quick_reject("docker ps"));
            assert!(quick_reject("kubectl get pods"));

            // These should NOT be rejected (contain git or rm)
            assert!(!quick_reject("git --version"));
            assert!(!quick_reject("rm --help"));
            assert!(!quick_reject("cat .gitignore")); // contains "git"
            assert!(!quick_reject("rm"));
            assert!(!quick_reject("git"));
        }

        #[test]
        fn quick_reject_handles_edge_cases() {
            // Edge cases
            assert!(quick_reject(""));
            assert!(quick_reject(" "));
            assert!(quick_reject("\t\n"));
            assert!(!quick_reject("gitk")); // Contains "git"
            assert!(!quick_reject("xrm")); // Contains "rm"
        }

        #[test]
        fn pattern_lazy_initialization_works() {
            // Access patterns to trigger lazy initialization
            let safe_count = SAFE_PATTERNS.len();
            let destructive_count = DESTRUCTIVE_PATTERNS.len();

            // Verify patterns were compiled
            assert!(safe_count > 0);
            assert!(destructive_count > 0);

            // Access again to verify caching works
            assert_eq!(SAFE_PATTERNS.len(), safe_count);
            assert_eq!(DESTRUCTIVE_PATTERNS.len(), destructive_count);
        }

        #[test]
        fn memchr_finder_initialization_works() {
            // Trigger lazy initialization
            let bytes = b"git status";
            let git_match = GIT_FINDER.find(bytes);
            let rm_match = RM_FINDER.find(bytes);

            assert!(git_match.is_some());
            assert!(rm_match.is_none());
        }
    }

    mod edge_case_tests {
        use super::*;

        fn would_block(cmd: &str) -> bool {
            if quick_reject(cmd) {
                return false;
            }
            let normalized = normalize_command(cmd);
            for pattern in SAFE_PATTERNS.iter() {
                if pattern.regex.is_match(&normalized).unwrap_or(false) {
                    return false;
                }
            }
            for pattern in DESTRUCTIVE_PATTERNS.iter() {
                if pattern.regex.is_match(&normalized).unwrap_or(false) {
                    return true;
                }
            }
            false
        }

        #[test]
        fn handles_multiline_commands() {
            // Commands with newlines (shouldn't happen in practice, but test anyway)
            assert!(!would_block("git status\necho done"));
        }

        #[test]
        fn handles_unicode_in_commands() {
            // Unicode characters in paths
            assert!(!would_block("git add 日本語ファイル.txt"));
            assert!(!would_block("git commit -m '添加中文'"));
        }

        #[test]
        fn handles_very_long_commands() {
            // Very long command (stress test)
            let long_path = "/tmp/".to_string() + &"a".repeat(1000);
            let cmd = format!("rm -rf {long_path}");
            assert!(!would_block(&cmd)); // Should be allowed (in /tmp)
        }

        #[test]
        fn handles_commands_with_special_characters() {
            // Special shell characters
            assert!(!would_block("git log --oneline | head -10"));
            assert!(!would_block("git status && git diff"));
            assert!(!would_block("git log $(date)"));
            assert!(!would_block("git log `whoami`"));
        }

        #[test]
        fn handles_quoted_arguments() {
            // Various quoting styles
            assert!(!would_block(r#"git commit -m "message with spaces""#));
            assert!(!would_block("git commit -m 'single quotes'"));
            assert!(!would_block("git commit -m $'escape sequences'"));
        }

        #[test]
        fn handles_subshell_paths() {
            // Subshell/command substitution in paths
            assert!(would_block("rm -rf $(pwd)")); // Blocked (not in safe dir)
            assert!(would_block("rm -rf `pwd`")); // Blocked (not in safe dir)
        }

        #[test]
        fn git_reset_soft_is_allowed() {
            // git reset --soft is safe (doesn't touch working tree)
            assert!(!would_block("git reset --soft HEAD~1"));
            assert!(!would_block("git reset --soft"));
        }

        #[test]
        fn git_reset_mixed_is_allowed() {
            // git reset (no flags) or --mixed is safe (only resets index)
            assert!(!would_block("git reset HEAD"));
            assert!(!would_block("git reset --mixed HEAD"));
        }

        #[test]
        fn handles_git_with_env_vars() {
            // Git with environment variables
            assert!(!would_block("GIT_DIR=/custom git status"));
            assert!(!would_block("GIT_WORK_TREE=/work git diff"));
        }

        #[test]
        fn handles_sudo_prefix() {
            // Sudo before git/rm
            assert!(would_block("sudo rm -rf /"));
            assert!(would_block("sudo git reset --hard"));
        }

        #[test]
        fn rm_interactive_is_allowed() {
            // rm -i (interactive) is safe
            assert!(!would_block("rm -i file.txt"));
            assert!(!would_block("rm -ri directory"));
        }

        #[test]
        fn rm_without_recursive_force_is_allowed() {
            // Plain rm without -rf is allowed
            assert!(!would_block("rm file.txt"));
            assert!(!would_block("rm -f file.txt")); // Force but not recursive
            assert!(!would_block("rm -r directory")); // Recursive but not force
        }
    }

    mod benchmark_simulation_tests {
        use super::*;

        #[test]
        fn quick_reject_performance_common_commands() {
            // Simulate common commands that should be quickly rejected
            let common_commands = vec![
                "ls -la",
                "cd /home/user",
                "cat file.txt",
                "echo 'hello'",
                "cargo build --release",
                "npm install",
                "python script.py",
                "node app.js",
                "docker ps",
                "kubectl get pods",
                "make all",
                "gcc -o output main.c",
                "curl https://example.com",
                "wget https://example.com/file",
                "tar -xzf archive.tar.gz",
                "unzip file.zip",
                "ssh user@host",
                "scp file user@host:/path",
                "rsync -av src/ dest/",
                "find . -name '*.rs'",
            ];

            for cmd in common_commands {
                // All these should be quickly rejected
                assert!(
                    quick_reject(cmd),
                    "Command should be quickly rejected: {cmd}"
                );
            }
        }

        #[test]
        fn full_pipeline_performance_git_commands() {
            // Common safe git commands should pass through efficiently
            let safe_git_commands = vec![
                "git status",
                "git log --oneline -10",
                "git diff HEAD",
                "git add .",
                "git add -A",
                "git commit -m 'message'",
                "git push origin main",
                "git pull origin main",
                "git fetch --all",
                "git branch -a",
                "git branch -d merged-branch",
                "git checkout main",
                "git checkout -b new-feature",
                "git merge feature-branch",
                "git rebase main",
                "git stash",
                "git stash pop",
                "git stash list",
                "git tag v1.0.0",
                "git remote -v",
            ];

            for cmd in safe_git_commands {
                let normalized = normalize_command(cmd);
                // None of these should match destructive patterns
                let is_destructive = DESTRUCTIVE_PATTERNS
                    .iter()
                    .any(|p| p.regex.is_match(&normalized).unwrap_or(false));
                assert!(
                    !is_destructive,
                    "Safe command incorrectly marked destructive: {cmd}"
                );
            }
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
            assert!(
                keywords.contains(&"prune"),
                "Enabled keywords should include 'prune' when containers.docker pack is enabled"
            );
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

            // Step 3: Check against legacy patterns (should not match)
            let legacy_safe = SAFE_PATTERNS
                .iter()
                .any(|p| p.regex.is_match(&normalized).unwrap_or(false));
            let legacy_destructive = DESTRUCTIVE_PATTERNS
                .iter()
                .any(|p| p.regex.is_match(&normalized).unwrap_or(false));

            // Docker commands should not match legacy git/rm patterns
            assert!(
                !legacy_safe,
                "docker command should not match legacy safe patterns"
            );
            assert!(
                !legacy_destructive,
                "docker command should not match legacy destructive patterns"
            );

            // Step 4: Check against pack registry (should block)
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
