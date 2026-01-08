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
use destructive_command_guard::hook;
use destructive_command_guard::packs::{REGISTRY, pack_aware_quick_reject};
use fancy_regex::Regex;
#[cfg(test)]
use memchr::memmem;
// Import hook types for tests
use destructive_command_guard::hook::HookInput;
use std::borrow::Cow;
use std::collections::HashSet;
use std::io::{self, BufRead, IsTerminal};
use std::sync::LazyLock;

// Build metadata from vergen (set by build.rs)
const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_TIMESTAMP: Option<&str> = option_env!("VERGEN_BUILD_TIMESTAMP");
const RUSTC_SEMVER: Option<&str> = option_env!("VERGEN_RUSTC_SEMVER");
const CARGO_TARGET: Option<&str> = option_env!("VERGEN_CARGO_TARGET_TRIPLE");

// NOTE: HookInput, ToolInput, HookOutput, HookSpecificOutput types are now defined
// in the hook module. Use hook::HookInput, hook::read_hook_input(), etc.

/// A safe pattern that, when matched, allows the command immediately.
struct Pattern {
    regex: Regex,
    /// Debug name for the pattern (used in error messages and tests).
    #[allow(dead_code)]
    name: &'static str,
}

/// A destructive pattern that, when matched, blocks the command.
struct DestructivePattern {
    regex: Regex,
    /// Human-readable explanation of why this command is blocked.
    reason: &'static str,
}

macro_rules! pattern {
    ($name:literal, $re:literal) => {
        Pattern {
            regex: Regex::new($re).expect(concat!("pattern '", $name, "' should compile")),
            name: $name,
        }
    };
}

macro_rules! destructive {
    ($re:literal, $reason:literal) => {
        DestructivePattern {
            regex: Regex::new($re).expect(concat!("destructive pattern should compile: ", $re)),
            reason: $reason,
        }
    };
}

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
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+/tmp/"
        ),
        pattern!(
            "rm-fr-tmp-1",
            r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+/tmp/"
        ),
        pattern!(
            "rm-rf-var-tmp-1",
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+/var/tmp/"
        ),
        pattern!(
            "rm-fr-var-tmp-1",
            r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+/var/tmp/"
        ),
        pattern!(
            "rm-rf-tmpdir-1",
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+\$TMPDIR/"
        ),
        pattern!(
            "rm-fr-tmpdir-1",
            r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+\$TMPDIR/"
        ),
        pattern!(
            "rm-rf-tmpdir-brace-1",
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+\$\{TMPDIR"
        ),
        pattern!(
            "rm-fr-tmpdir-brace-1",
            r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+\$\{TMPDIR"
        ),
        pattern!(
            "rm-rf-tmpdir-quoted-1",
            r#"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+"\$TMPDIR/"#
        ),
        pattern!(
            "rm-fr-tmpdir-quoted-1",
            r#"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+"\$TMPDIR/"#
        ),
        pattern!(
            "rm-rf-tmpdir-brace-quoted-1",
            r#"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+"\$\{TMPDIR"#
        ),
        pattern!(
            "rm-fr-tmpdir-brace-quoted-1",
            r#"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+"\$\{TMPDIR"#
        ),
        pattern!(
            "rm-r-f-tmp",
            r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+/tmp/"
        ),
        pattern!(
            "rm-f-r-tmp",
            r"rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+/tmp/"
        ),
        pattern!(
            "rm-r-f-var-tmp",
            r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+/var/tmp/"
        ),
        pattern!(
            "rm-f-r-var-tmp",
            r"rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+/var/tmp/"
        ),
        pattern!(
            "rm-r-f-tmpdir",
            r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+\$TMPDIR/"
        ),
        pattern!(
            "rm-f-r-tmpdir",
            r"rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+\$TMPDIR/"
        ),
        pattern!(
            "rm-r-f-tmpdir-brace",
            r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+\$\{TMPDIR"
        ),
        pattern!(
            "rm-f-r-tmpdir-brace",
            r"rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+\$\{TMPDIR"
        ),
        pattern!(
            "rm-recursive-force-tmp",
            r"rm\s+.*--recursive.*--force\s+/tmp/"
        ),
        pattern!(
            "rm-force-recursive-tmp",
            r"rm\s+.*--force.*--recursive\s+/tmp/"
        ),
        pattern!(
            "rm-recursive-force-var-tmp",
            r"rm\s+.*--recursive.*--force\s+/var/tmp/"
        ),
        pattern!(
            "rm-force-recursive-var-tmp",
            r"rm\s+.*--force.*--recursive\s+/var/tmp/"
        ),
        pattern!(
            "rm-recursive-force-tmpdir",
            r"rm\s+.*--recursive.*--force\s+\$TMPDIR/"
        ),
        pattern!(
            "rm-force-recursive-tmpdir",
            r"rm\s+.*--force.*--recursive\s+\$TMPDIR/"
        ),
        pattern!(
            "rm-recursive-force-tmpdir-brace",
            r"rm\s+.*--recursive.*--force\s+\$\{TMPDIR"
        ),
        pattern!(
            "rm-force-recursive-tmpdir-brace",
            r"rm\s+.*--force.*--recursive\s+\$\{TMPDIR"
        ),
    ]
});

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

/// Regex to strip absolute paths from git/rm binaries.
/// Matches patterns like `/usr/bin/git`, `/bin/rm`, `/usr/local/bin/git`.
static PATH_NORMALIZER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/(?:\S*/)*s?bin/(rm|git)(?=\s|$)").unwrap());

/// Pre-compiled finders for quick rejection (SIMD-accelerated).
/// Only used in tests - production code uses `pack_aware_quick_reject` from packs module.
#[cfg(test)]
static GIT_FINDER: LazyLock<memmem::Finder<'static>> = LazyLock::new(|| memmem::Finder::new("git"));
#[cfg(test)]
static RM_FINDER: LazyLock<memmem::Finder<'static>> = LazyLock::new(|| memmem::Finder::new("rm"));

/// Normalize a command by stripping absolute paths from git/rm binaries.
///
/// Returns a `Cow::Borrowed` if no transformation is needed (zero allocation),
/// or `Cow::Owned` if the command was modified.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(normalize_command("/usr/bin/git status"), Cow::Owned("git status".into()));
/// assert_eq!(normalize_command("git status"), Cow::Borrowed("git status"));
/// ```
#[inline]
fn normalize_command(cmd: &str) -> Cow<'_, str> {
    // Fast path: if command doesn't start with '/', no normalization possible
    if !cmd.starts_with('/') {
        return Cow::Borrowed(cmd);
    }
    PATH_NORMALIZER.replace(cmd, "$1")
}

/// Quick rejection filter using SIMD-accelerated substring search.
///
/// Returns `true` if the command can be immediately allowed (no "git" or "rm").
/// This skips expensive regex matching for 99%+ of commands.
///
/// NOTE: This is only used in tests. Production code uses `pack_aware_quick_reject`
/// from the packs module which checks all enabled pack keywords.
///
/// Production uses `pack_aware_quick_reject` which checks all enabled pack keywords.
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

// NOTE: format_denial_message is now in hook module.
// Use hook::format_denial_message() if needed.

// NOTE: print_colorful_warning, format_denial_message, and deny() are now in hook module.
// Use hook::output_denial() for all denial responses.

/// Print version information and exit.
fn print_version() {
    let version_line = format!("{} {}", "dcg".green().bold(), PKG_VERSION.cyan());
    eprintln!("{version_line}");

    if let Some(ts) = BUILD_TIMESTAMP {
        eprintln!("  {} {}", "Built:".bright_black(), ts.white());
    }
    if let Some(rustc) = RUSTC_SEMVER {
        eprintln!("  {} {}", "Rustc:".bright_black(), rustc.white());
    }
    if let Some(target) = CARGO_TARGET {
        eprintln!("  {} {}", "Target:".bright_black(), target.white());
    }
}

fn main() {
    // Configure colors based on TTY detection
    configure_colors();

    // Try to parse CLI arguments
    let cli = Cli::try_parse();

    // If CLI parsing succeeds and there's a subcommand, handle it
    if let Ok(cli) = cli {
        if cli.command.is_some() {
            if let Err(e) = cli::run_command(cli) {
                // If the error is "no subcommand provided", fall through to hook mode
                if e.to_string() != "No subcommand provided. Running in hook mode." {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            } else {
                return;
            }
        }
    }

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

    // Load configuration
    let config = Config::load();

    // Check if bypass is requested (escape hatch)
    if Config::is_bypassed() {
        return;
    }

    // Compile overrides once (precompiled regexes, no per-command compilation)
    let compiled_overrides = config.overrides.compile();

    // Get enabled pack IDs early for pack-aware quick reject.
    // This is done before stdin read to minimize latency on the critical path.
    let enabled_packs: HashSet<String> = config.enabled_pack_ids();
    let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);

    // Read stdin with a reasonable capacity hint for typical hook input.
    // Hook input is typically ~100-200 bytes of JSON.
    let mut input = String::with_capacity(256);
    {
        let stdin = io::stdin();
        let mut handle = stdin.lock();
        if handle.read_line(&mut input).is_err() {
            return;
        }
    } // handle dropped here, releasing the lock early

    // Fast path: parse JSON directly from the input buffer
    let Ok(hook_input) = serde_json::from_str::<HookInput>(&input) else {
        return;
    };

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

    // Check explicit allow overrides first (using precompiled regexes)
    if compiled_overrides.check_allow(&command) {
        return;
    }

    // Check explicit block overrides (using precompiled regexes)
    if let Some(reason) = compiled_overrides.check_block(&command) {
        hook::output_denial(&command, reason, None);
        return;
    }

    // Quick rejection: if command doesn't contain any keywords from enabled packs,
    // allow immediately. This is the hot path for 99%+ of commands.
    //
    // This uses pack_aware_quick_reject which checks keywords from ALL enabled packs
    // (not just core git/rm), ensuring non-core packs like docker/kubectl are reachable.
    if pack_aware_quick_reject(&command, &enabled_keywords) {
        return;
    }

    // Normalize the command (strips /usr/bin/git -> git, etc.)
    let normalized = normalize_command(&command);

    // LEGACY: Check safe patterns first (whitelist approach).
    // If any safe pattern matches, allow immediately.
    for pattern in SAFE_PATTERNS.iter() {
        if pattern.regex.is_match(&normalized).unwrap_or(false) {
            return;
        }
    }

    // LEGACY: Check destructive patterns (blacklist approach).
    // If any destructive pattern matches, deny with reason.
    for pattern in DESTRUCTIVE_PATTERNS.iter() {
        if pattern.regex.is_match(&normalized).unwrap_or(false) {
            hook::output_denial(&command, pattern.reason, None);
            return;
        }
    }

    // NEW: Check against enabled packs from configuration
    // (enabled_packs was computed earlier for pack-aware quick reject)
    let result = REGISTRY.check_command(&normalized, &enabled_packs);

    if result.blocked {
        let reason = result.reason.as_deref().unwrap_or("Blocked by pack");
        let pack_id = result.pack_id.as_deref();
        hook::output_denial(&command, reason, pack_id);

        // Log if configured
        if let Some(log_file) = &config.general.log_file {
            let _ = hook::log_blocked_command(log_file, &command, reason, pack_id);
        }
    }

    // No pattern matched: default allow
}

/// Print help information.
fn print_help() {
    eprintln!(
        "{} {} - {}",
        "dcg".green().bold(),
        PKG_VERSION.cyan(),
        "A Claude Code hook that blocks destructive commands".white()
    );
    eprintln!();
    eprintln!("{}", "USAGE:".yellow().bold());
    eprintln!(
        "    This tool is designed to run as a Claude Code {} hook.",
        "PreToolUse".cyan()
    );
    eprintln!("    It reads JSON from stdin and outputs JSON to stdout.");
    eprintln!();
    eprintln!("{}", "CONFIGURATION:".yellow().bold());
    eprintln!("    Add to {}:", "~/.claude/settings.json".cyan());
    eprintln!();
    eprintln!(
        "    {}",
        r#"{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "dcg"}]}]}}"#
            .bright_black()
    );
    eprintln!();
    eprintln!("{}", "OPTIONS:".yellow().bold());
    eprintln!(
        "    {}    Print version information",
        "--version, -V".green()
    );
    eprintln!("    {}       Print this help message", "--help, -h".green());
    eprintln!();
    eprintln!("{}", "BLOCKED COMMANDS:".yellow().bold());
    eprintln!(
        "    {} git reset --hard, git checkout --, git restore (without --staged)",
        "Git:".red()
    );
    eprintln!("         git clean -f, git push --force, git branch -D, git stash drop/clear");
    eprintln!(
        "    {} rm -rf outside of /tmp, /var/tmp, or $TMPDIR",
        "Filesystem:".red()
    );
    eprintln!();
    eprintln!(
        "For more information: {}",
        "https://github.com/Dicklesworthstone/destructive_command_guard"
            .blue()
            .underline()
    );
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
}
