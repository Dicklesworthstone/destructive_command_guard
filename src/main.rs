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
use destructive_command_guard::agent::{Agent, detect_agent};
use destructive_command_guard::allowlist::LayeredAllowlist;
use destructive_command_guard::cli::{self, Cli};
// Exit codes are used by cli.rs for robot mode; main.rs uses them for hook mode errors
use destructive_command_guard::config::Config;
use destructive_command_guard::evaluator::{
    EvaluationDecision, MatchSource, evaluate_command_with_pack_order_deadline_at_path,
};
#[allow(unused_imports)]
use destructive_command_guard::exit_codes::{EXIT_DENIED, EXIT_PARSE_ERROR, EXIT_SUCCESS};
use destructive_command_guard::history::{
    CommandEntry, ENV_HISTORY_DB_PATH, HistoryWriter, Outcome as HistoryOutcome,
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
    let color_disabled = std::env::var_os("NO_COLOR").is_some()
        || destructive_command_guard::output::env_flag_enabled("DCG_NO_COLOR")
        || !io::stderr().is_terminal();

    if color_disabled {
        colored::control::set_override(false);
        return;
    }

    // Color is enabled on a real terminal — enable Windows VT processing.
    enable_windows_ansi();
}

/// Enable Windows virtual-terminal processing so the hand-rolled ANSI escapes
/// used across the codebase (output/denial.rs, update.rs, trace.rs, …) render as
/// colors instead of a literal `<-[33m` on legacy conhost. `colored`'s helper
/// targets the STDOUT handle (covers `dcg explain`, `dcg packs`, `dcg update
/// --list-backups`, …). Idempotent; a no-op off-Windows.
///
/// The blocked-command panel is written to STDERR. Modern Windows consoles
/// (Windows Terminal, PowerShell 7, Win10 1607+) enable VT for stderr
/// automatically; enabling it on the stderr handle on *legacy* conhost would
/// require an unsafe `SetConsoleMode`, which this crate forbids
/// (`#![forbid(unsafe_code)]`). That legacy-conhost stderr path is validated on
/// a real Windows box in win-validate-color (.7.4).
#[inline]
fn enable_windows_ansi() {
    #[cfg(windows)]
    {
        let _ = colored::control::set_virtual_terminal(true);
    }
}

fn history_db_path(config: &destructive_command_guard::config::HistoryConfig) -> Option<PathBuf> {
    if let Ok(path) = std::env::var(ENV_HISTORY_DB_PATH) {
        return Some(PathBuf::from(path));
    }
    config.expanded_database_path()
}

fn build_history_entry(
    agent_type: &str,
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
        agent_type: agent_type.to_string(),
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

fn history_agent_type_for_protocol(protocol: hook::HookProtocol, detected_agent: &Agent) -> &str {
    match protocol {
        hook::HookProtocol::Codex => Agent::CodexCli.config_key(),
        hook::HookProtocol::Gemini => Agent::GeminiCli.config_key(),
        hook::HookProtocol::Copilot => Agent::CopilotCli.config_key(),
        hook::HookProtocol::Hermes => Agent::Hermes.config_key(),
        hook::HookProtocol::Grok => Agent::Grok.config_key(),
        hook::HookProtocol::Antigravity => Agent::Antigravity.config_key(),
        hook::HookProtocol::ClaudeCompatible => detected_agent.config_key(),
    }
}

fn effective_agent_for_hook_protocol(
    protocol: hook::HookProtocol,
    detected_agent: &Agent,
) -> Agent {
    match protocol {
        hook::HookProtocol::Codex => Agent::CodexCli,
        hook::HookProtocol::Gemini => Agent::GeminiCli,
        hook::HookProtocol::Copilot => Agent::CopilotCli,
        hook::HookProtocol::Hermes => Agent::Hermes,
        hook::HookProtocol::Grok => Agent::Grok,
        hook::HookProtocol::Antigravity => Agent::Antigravity,
        hook::HookProtocol::ClaudeCompatible => detected_agent.clone(),
    }
}

/// Handle hook input that could not be parsed (issue #160).
///
/// Records an audit-trail entry to history — so operators can see malformed
/// inputs even though dcg fails open by default — and, when fail-closed mode is
/// enabled (`DCG_FAIL_CLOSED` / `general.fail_closed`) AND the failure is a JSON
/// parse error, emits a Claude-compatible deny so the agent blocks the command
/// instead of silently allowing it. Transient IO errors keep the historic
/// fail-open behavior even under fail-closed, since they are not attacker-
/// controlled malformed payloads.
/// Map an env/process-detected [`Agent`] to its hook wire protocol.
///
/// Used when dcg must emit a denial WITHOUT a parsed payload (a fail-closed
/// parse failure, issue #160): protocol detection normally reads the payload,
/// which is exactly what failed here, so fall back to the detected agent so the
/// deny matches what that agent actually understands (for example, Codex gets
/// its minimal `hookSpecificOutput` JSON rather than Claude's extended fields).
fn hook_protocol_for_agent(agent: &Agent) -> hook::HookProtocol {
    match agent {
        Agent::CodexCli => hook::HookProtocol::Codex,
        Agent::GeminiCli => hook::HookProtocol::Gemini,
        Agent::CopilotCli => hook::HookProtocol::Copilot,
        Agent::Hermes => hook::HookProtocol::Hermes,
        Agent::Grok => hook::HookProtocol::Grok,
        Agent::Antigravity => hook::HookProtocol::Antigravity,
        _ => hook::HookProtocol::ClaudeCompatible,
    }
}

fn handle_unparseable_hook_input(
    config: &Config,
    detected_agent: &Agent,
    read_err: &hook::HookReadError,
    max_input_bytes: usize,
) {
    // Block when fail-closed AND the failure is an attacker-influenceable
    // payload problem: a JSON parse error OR an oversized input (padding a
    // command past the size limit must not skip evaluation under fail-closed —
    // issue #160). Transient IO read errors always fail open; they are not
    // malformed payloads.
    let blockable = matches!(
        read_err,
        hook::HookReadError::Json(_) | hook::HookReadError::InputTooLarge(_)
    );
    let block = blockable && config.is_fail_closed();

    // Audit trail: record the event to history (best-effort, never fatal).
    if config.history.enabled {
        let working_dir = std::env::current_dir().ok().map_or_else(
            || "<unknown>".to_string(),
            |p| p.to_string_lossy().to_string(),
        );
        let outcome = if block {
            HistoryOutcome::Deny
        } else {
            HistoryOutcome::Allow
        };
        let writer = HistoryWriter::new(history_db_path(&config.history), &config.history);
        let entry = build_history_entry(
            detected_agent.config_key(),
            "<unparseable hook input>",
            &working_dir,
            outcome,
            Duration::ZERO,
            None,
            None,
            Some("parse-error"),
        );
        writer.log(entry);
        // Flush synchronously because this parse-error path returns
        // immediately after publishing its fail-open/fail-closed decision.
        writer.flush_sync();
    }

    if !block {
        // Fail-open (default). Keep the historic oversized-input warning so an
        // operator can see why a large command was allowed; other errors warn
        // only under verbose.
        match read_err {
            hook::HookReadError::InputTooLarge(len) => {
                eprintln!(
                    "[dcg] Warning: stdin input ({len} bytes) exceeds limit ({max_input_bytes} bytes); allowing command (fail-open)"
                );
            }
            _ if config.general.verbose => {
                eprintln!(
                    "[dcg] Warning: could not parse hook input; allowing command (fail-open)"
                );
            }
            _ => {}
        }
        return;
    }

    // Fail-closed: emit an agent-appropriate denial. Without a parsed payload we
    // cannot run protocol detection, so derive the protocol from the
    // env/process-detected agent.
    let protocol = hook_protocol_for_agent(detected_agent);
    let reason = if matches!(read_err, hook::HookReadError::InputTooLarge(_)) {
        "BLOCKED by dcg: the hook input exceeds the size limit and cannot be evaluated; \
         DCG_FAIL_CLOSED is set (fail-closed mode)."
    } else {
        "BLOCKED by dcg: the hook input could not be parsed; DCG_FAIL_CLOSED is set \
         (fail-closed mode). Fix the malformed hook payload or unset DCG_FAIL_CLOSED."
    };
    hook::output_denial_for_protocol(
        protocol,
        "<unparseable hook input>",
        reason,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        &[],
        None,
    );
}

/// Process-wide registry of shutdown actions.
///
/// `std::process::exit` skips Drop, so any subsystem with cross-call buffered
/// state (history writer, future stores) needs an explicit pre-exit flush.
/// Each subsystem registers a closure here at startup; the SIGINT handler
/// invokes them in order before exiting. New stores should add a registration
/// call — do not add ad-hoc flush logic to the SIGINT handler itself.
type ShutdownAction = Box<dyn Fn() + Send + Sync>;

static SHUTDOWN_ACTIONS: std::sync::OnceLock<std::sync::Mutex<Vec<ShutdownAction>>> =
    std::sync::OnceLock::new();

fn shutdown_registry() -> &'static std::sync::Mutex<Vec<ShutdownAction>> {
    SHUTDOWN_ACTIONS.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

fn register_shutdown_action<F>(action: F)
where
    F: Fn() + Send + Sync + 'static,
{
    let actions = shutdown_registry();
    if let Ok(mut guard) = actions.lock() {
        guard.push(Box::new(action));
    }
}

fn run_shutdown_actions() {
    let actions = shutdown_registry();
    // Recover from a poisoned lock: a previous panic mid-action shouldn't
    // prevent subsequent shutdown calls from flushing remaining stores.
    let guard = match actions.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    for action in guard.iter() {
        // Catch panics so one buggy flush doesn't skip the rest. We can't
        // do anything useful with the panic payload at shutdown — at best,
        // log it; failing that, swallow it. The other registered stores
        // still need their chance to flush.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action));
    }
}

fn install_signal_shutdown_handler() {
    // Idempotent: ctrlc::set_handler returns Err on duplicate install. The
    // handler itself runs every action in the registry deterministically
    // (in registration order), then exits 130. Code 130 is the canonical
    // "interrupted by SIGINT" status (128 + SIGINT(2)).
    let _ = ctrlc::set_handler(|| {
        eprintln!("[dcg] Flushing on signal...");
        run_shutdown_actions();
        std::process::exit(130);
    });
}

fn install_history_shutdown_handler(
    handle: destructive_command_guard::history::HistoryFlushHandle,
) {
    register_shutdown_action(move || {
        handle.flush_sync();
    });
    install_signal_shutdown_handler();
}

fn is_top_level_global_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--verbose"
            | "--quiet"
            | "-q"
            | "--legacy-output"
            | "--no-color"
            | "--no-suggestions"
            | "--robot"
    ) || (arg.starts_with('-') && !arg.starts_with("--") && arg[1..].chars().all(|c| c == 'v'))
}

fn top_level_flag_requested(args: &[String], long: &str, short: &str) -> bool {
    let mut index = 1;
    while index < args.len() {
        let arg = &args[index];
        if arg == long || arg == short {
            return true;
        }
        if is_top_level_global_flag(arg) {
            index += 1;
            continue;
        }
        if arg == "--agent" {
            index += 2;
            continue;
        }
        if arg.starts_with("--agent=") {
            index += 1;
            continue;
        }
        return false;
    }

    false
}

fn remove_disabled_packs_for_agent(
    enabled_packs: &mut HashSet<String>,
    config: &Config,
    agent: &Agent,
) {
    let profile = config.agents.profile_for_agent(agent);
    for disabled in &profile.disabled_packs {
        enabled_packs.remove(disabled);
        enabled_packs.retain(|pack| !pack.starts_with(&format!("{disabled}.")));
    }
}

fn apply_agent_allowlist_profile(
    config: &Config,
    agent: &Agent,
    mut allowlists: LayeredAllowlist,
) -> LayeredAllowlist {
    if config.allowlist_disabled_for_agent(agent) {
        return LayeredAllowlist::default();
    }

    allowlists.prepend_agent_exact_commands(
        agent.config_key(),
        config.additional_allowlist_for_agent(agent),
    );
    allowlists
}

fn load_effective_allowlists_for_agent(config: &Config, agent: &Agent) -> LayeredAllowlist {
    apply_agent_allowlist_profile(config, agent, load_default_allowlists())
}

// NOTE: Denial output functions (format_denial_message, print_colorful_warning, deny)
// are now in the hook module. Use hook::output_denial() for all denial responses.

/// Print version information and exit.
fn print_version() {
    // Machine-readable version on stdout (for scripts, installers, etc.)
    println!("{PKG_VERSION}");

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
    if top_level_flag_requested(&args, "--version", "-V") {
        print_version();
        return;
    }

    // Check for --help flag
    if top_level_flag_requested(&args, "--help", "-h") {
        print_help();
        return;
    }

    // Parse CLI arguments (subcommands). If parsing fails (e.g., unknown flags),
    // print the clap error and exit instead of falling into hook mode and
    // blocking on stdin.
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let exit_code = e.exit_code();
            eprintln!("{e}");
            std::process::exit(exit_code);
        }
    };

    // Initialize output system based on CLI flags.
    // --legacy-output, --no-color, or --robot forces plain output mode.
    // Robot mode also suppresses all stderr output.
    let robot_mode = destructive_command_guard::output::robot_mode_enabled(cli.robot);
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
    let detected_agent = detect_agent();

    // Check if bypass is requested (escape hatch)
    if Config::is_bypassed() {
        return;
    }

    // Self-heal: verify the DCG hook is still registered in settings.json.
    // Claude Code can silently overwrite settings.json mid-session, removing the hook.
    // This re-registers it automatically (fail-open: errors are logged, never fatal).
    if config.general.self_heal_hook {
        cli::ensure_hook_registered();
    }

    // Compile overrides once (precompiled regexes, no per-command compilation)
    let compiled_overrides = config.overrides.compile();

    // Compute effective heredoc settings once (avoid per-command parsing/allocations).
    let heredoc_settings = config.heredoc_settings();

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

    // Read and parse input
    let max_input_bytes = config.general.max_hook_input_bytes();
    let hook_input = match hook::read_hook_input(max_input_bytes) {
        Ok(input) => input,
        Err(read_err) => {
            // Malformed, oversized, or unreadable hook input. The default is
            // fail-open (allow), but we (a) record an audit-trail entry to
            // history so operators can see it, and (b) BLOCK instead of allow
            // when fail-closed mode is enabled — including oversized input,
            // which is attacker-controllable (issue #160). Routing oversized
            // input through the same handler is what closes the size-bypass.
            handle_unparseable_hook_input(&config, &detected_agent, &read_err, max_input_bytes);
            return;
        }
    };

    // Start evaluation deadline after input size checks (includes evaluation).
    // Enforce a minimum timeout to prevent bypass via `hook_timeout_ms = 0`
    // which would cause deadline_exceeded() to immediately allow all commands.
    let deadline = Deadline::new(
        config
            .general
            .hook_timeout_ms
            .map_or(HOOK_EVALUATION_BUDGET, |ms| {
                Duration::from_millis(ms.max(destructive_command_guard::perf::MIN_HOOK_TIMEOUT_MS))
            }),
    );

    let Some((command, hook_protocol)) = hook::extract_command_with_protocol(&hook_input) else {
        return;
    };
    let history_agent_type = history_agent_type_for_protocol(hook_protocol, &detected_agent);
    let effective_agent = effective_agent_for_hook_protocol(hook_protocol, &detected_agent);

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

    // Load layered allowlists (project/user/system). Missing/invalid files are treated
    // as empty for hook safety; allowlist decisions are only consulted on matches.
    // Use the hook protocol when it identifies the agent more reliably than env/process
    // detection, because Codex/Gemini hooks are often launched without agent-specific
    // environment variables.
    let allowlists = load_effective_allowlists_for_agent(&config, &effective_agent);

    let mut enabled_packs: HashSet<String> = config.enabled_pack_ids_for_agent(&effective_agent);

    // Auto-enable external packs: packs loaded via custom_paths are implicitly enabled.
    // This avoids requiring users to both add a path AND explicitly enable the pack ID.
    for id in external_store.pack_ids() {
        enabled_packs.insert(id.clone());
    }
    remove_disabled_packs_for_agent(&mut enabled_packs, &config, &effective_agent);

    let mut enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
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

    let cwd_path = std::env::current_dir().ok();
    let working_dir = cwd_path.as_ref().map_or_else(
        || "<unknown>".to_string(),
        |path| path.to_string_lossy().to_string(),
    );

    let history_writer = if config.history.enabled {
        Some(HistoryWriter::new(
            history_db_path(&config.history),
            &config.history,
        ))
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
        None,                // allow_once_audit
        cwd_path.as_deref(), // project_path: scopes path-aware allowlist entries (#186)
        Some(&deadline),
    );

    // NOTE: External packs from custom_paths are now checked in evaluate_command()
    // alongside built-in packs, so no separate fallback check is needed here.

    let eval_duration = eval_start.elapsed();

    if result.skipped_due_to_budget {
        if let Some(writer) = history_writer.as_ref() {
            let entry = build_history_entry(
                history_agent_type,
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
                history_agent_type,
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
                history_agent_type,
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

    // Rebase-recovery unblock (issue #104).
    //
    // Before emitting a hard deny, check whether this is one of the narrow
    // "recovery" patterns (`checkout-discard`, `restore-worktree`, etc.)
    // AND a recovery signal is active: either a rebase is in progress
    // (`.git/rebase-merge/` or `.git/rebase-apply/`) or a short-lived
    // `dcg rebase-recover` permit was issued. If yes, convert the deny
    // into an allow with a stderr note and (for the permit case) consume
    // the cookie so subsequent unrelated commands stay blocked.
    //
    // Safety: only fires when BOTH (a) the matched pattern is on the
    // small recovery allowlist, AND (b) a recovery signal is active.
    // Outside this narrow window the original deny path is unchanged.
    if matches!(mode, DecisionMode::Deny) {
        if let Some(cwd_ref) = cwd_path.as_deref() {
            if let Some(reason) = destructive_command_guard::rebase_recovery::should_allow_recovery(
                cwd_ref, pack, pattern,
            ) {
                // Consume the permit if that's why we allowed (single-shot).
                if matches!(
                    reason,
                    destructive_command_guard::rebase_recovery::RecoveryReason::ActivePermit(_)
                ) {
                    destructive_command_guard::rebase_recovery::consume_permit(cwd_ref);
                }
                // Inform on stderr (visible to the agent and to humans).
                // Stays silent when stderr isn't a TTY and robot mode is on,
                // but the message itself is always safe to emit.
                eprintln!(
                    "[dcg] Allowing `{}` → rebase-recovery mode ({})",
                    pattern.unwrap_or("<unknown>"),
                    reason.label()
                );
                if let Some(writer) = history_writer.as_ref() {
                    let entry = build_history_entry(
                        history_agent_type,
                        &command,
                        &working_dir,
                        HistoryOutcome::Allow,
                        eval_duration,
                        pack,
                        pattern,
                        Some("rebase-recovery"),
                    );
                    writer.log(entry);
                }
                return;
            }
        }
    }

    if let Some(writer) = history_writer.as_ref() {
        let outcome = match mode {
            DecisionMode::Deny => HistoryOutcome::Deny,
            DecisionMode::Warn => HistoryOutcome::Warn,
            DecisionMode::Log => HistoryOutcome::Allow,
        };
        let entry = build_history_entry(
            history_agent_type,
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

            let branch_ctx = if config.git_awareness.should_show_branch_in_output() {
                result.branch_context.as_ref()
            } else {
                None
            };
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
                branch_ctx,
            );

            // Log if configured
            if let Some(log_file) = &config.general.log_file {
                let _ = hook::log_blocked_command(log_file, &command, &info.reason, pack);
            }

            // All deny protocols, including current Codex, return normally so
            // buffered history is flushed by `HistoryWriter::Drop`. Codex gets
            // a minimal stdout JSON denial from `output_denial_for_protocol`.
        }
        DecisionMode::Warn => {
            hook::output_warning_for_protocol(
                hook_protocol,
                &command,
                &info.reason,
                pack,
                pattern,
                explanation,
            );
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
        "Destructive Command Guard - multi-agent safety hook".bright_black()
    );
    eprintln!();

    // Usage section
    eprintln!("  {}", "USAGE".yellow().bold());
    eprintln!("  {}", "─".repeat(50).bright_black());
    eprintln!("    Runs as a pre-execution shell hook for Claude Code, Codex CLI,");
    eprintln!("    Gemini CLI, GitHub Copilot CLI, Cursor IDE, and Hermes Agent.");
    eprintln!("    Compatible agents, including Codex, receive protocol-specific stdout JSON.");
    eprintln!();

    // Configuration section
    eprintln!("  {}", "CONFIGURATION".yellow().bold());
    eprintln!("  {}", "─".repeat(50).bright_black());
    eprintln!("    Installers configure supported agent hooks automatically.");
    eprintln!(
        "    Common Claude Code config in {}:",
        "~/.claude/settings.json".cyan()
    );
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
        "    {}=text|json|sarif  Default output format (command-specific).",
        "DCG_FORMAT".green()
    );
    eprintln!("                          `sarif` is real SARIF only for `dcg scan`; on every");
    eprintln!("                          other command `sarif`/`structured` is an alias for");
    eprintln!("                          JSON, and `text` an alias for pretty. Per-command");
    eprintln!("                          accepted values: see `dcg <command> --help`.");
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
    eprintln!(
        "    {}=1  Block (deny) on unparseable hook input (default: fail-open)",
        "DCG_FAIL_CLOSED".green()
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

    // Additional packs note. These IDs must be real pack IDs that resolve via
    // `dcg pack info <id>` — listing non-existent IDs here misleads users into
    // trying to enable packs that don't exist (see issue #152).
    eprintln!("    📦 Additional packs: containers.docker, kubernetes.kubectl,");
    eprintln!("       database.postgresql, infrastructure.terraform, and more.");
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

    mod top_level_dispatch_tests {
        use super::*;

        fn args(items: &[&str]) -> Vec<String> {
            items.iter().map(|item| (*item).to_string()).collect()
        }

        #[test]
        fn top_level_help_is_detected_before_subcommands() {
            assert!(top_level_flag_requested(
                &args(&["dcg", "--help"]),
                "--help",
                "-h"
            ));
            assert!(top_level_flag_requested(
                &args(&["dcg", "--no-color", "-h"]),
                "--help",
                "-h"
            ));
        }

        #[test]
        fn subcommand_help_is_left_for_clap() {
            assert!(!top_level_flag_requested(
                &args(&["dcg", "simulate", "--help"]),
                "--help",
                "-h"
            ));
            assert!(!top_level_flag_requested(
                &args(&["dcg", "--robot", "test", "-h"]),
                "--help",
                "-h"
            ));
        }

        #[test]
        fn update_version_flag_is_not_top_level_version() {
            assert!(!top_level_flag_requested(
                &args(&["dcg", "update", "--version", "v0.2.0"]),
                "--version",
                "-V"
            ));
            assert!(top_level_flag_requested(
                &args(&["dcg", "-vv", "--version"]),
                "--version",
                "-V"
            ));
        }

        #[test]
        fn top_level_agent_override_does_not_hide_global_flags() {
            assert!(top_level_flag_requested(
                &args(&["dcg", "--agent", "custom-agent", "--version"]),
                "--version",
                "-V"
            ));
            assert!(top_level_flag_requested(
                &args(&["dcg", "--agent=custom-agent", "--help"]),
                "--help",
                "-h"
            ));
        }

        #[test]
        fn subcommand_agent_override_is_left_for_clap() {
            assert!(!top_level_flag_requested(
                &args(&["dcg", "test", "--agent", "custom-agent", "--help"]),
                "--help",
                "-h"
            ));
        }
    }

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

    mod history_entry_tests {
        use super::*;

        #[test]
        fn build_history_entry_uses_detected_agent_key() {
            let entry = build_history_entry(
                Agent::CodexCli.config_key(),
                "git status",
                "/tmp/project",
                HistoryOutcome::Allow,
                Duration::from_micros(42),
                None,
                None,
                None,
            );

            assert_eq!(entry.agent_type, "codex-cli");
            assert_eq!(entry.command, "git status");
            assert_eq!(entry.eval_duration_us, 42);
        }

        #[test]
        fn history_agent_type_prefers_definitive_hook_protocols() {
            assert_eq!(
                history_agent_type_for_protocol(hook::HookProtocol::Codex, &Agent::Unknown),
                "codex-cli"
            );
            assert_eq!(
                history_agent_type_for_protocol(hook::HookProtocol::Gemini, &Agent::Unknown),
                "gemini-cli"
            );
            assert_eq!(
                history_agent_type_for_protocol(hook::HookProtocol::Copilot, &Agent::Unknown),
                "copilot-cli"
            );
        }

        #[test]
        fn history_agent_type_preserves_detected_claude_compatible_agent() {
            let custom = Agent::Custom("internal-agent".to_string());

            assert_eq!(
                history_agent_type_for_protocol(hook::HookProtocol::ClaudeCompatible, &custom),
                "internal-agent"
            );
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

    mod agent_profile_hook_tests {
        use super::*;
        use destructive_command_guard::allowlist::{
            AllowEntry, AllowSelector, AllowlistFile, AllowlistLayer, LoadedAllowlistLayer, RuleId,
        };
        use destructive_command_guard::config::AgentProfile;
        use destructive_command_guard::evaluator::EvaluationResult;
        use std::collections::HashMap;
        use std::path::PathBuf;

        fn project_allowlist_for_rule(rule: &str) -> LayeredAllowlist {
            LayeredAllowlist {
                layers: vec![LoadedAllowlistLayer {
                    layer: AllowlistLayer::Project,
                    path: PathBuf::from("project-allowlist.toml"),
                    file: AllowlistFile {
                        entries: vec![AllowEntry {
                            selector: AllowSelector::Rule(
                                RuleId::parse(rule).expect("rule id should parse"),
                            ),
                            reason: "project override".to_string(),
                            added_by: None,
                            added_at: None,
                            expires_at: None,
                            ttl: None,
                            session: None,
                            session_id: None,
                            context: None,
                            conditions: HashMap::new(),
                            environments: Vec::new(),
                            paths: None,
                            risk_acknowledged: false,
                        }],
                        errors: Vec::new(),
                    },
                }],
            }
        }

        fn evaluate_with_agent(config: &Config, agent: &Agent, command: &str) -> EvaluationResult {
            let mut enabled_packs = config.enabled_pack_ids_for_agent(agent);
            remove_disabled_packs_for_agent(&mut enabled_packs, config, agent);
            let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
            let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
            let keyword_index = REGISTRY.build_enabled_keyword_index(&ordered_packs);
            let compiled_overrides = config.overrides.compile();
            let allowlists =
                apply_agent_allowlist_profile(config, agent, LayeredAllowlist::default());

            evaluate_command_with_pack_order_deadline_at_path(
                command,
                &enabled_keywords,
                &ordered_packs,
                keyword_index.as_ref(),
                &compiled_overrides,
                &allowlists,
                &config.heredoc_settings(),
                None,
                None,
                None,
            )
        }

        #[test]
        fn hook_agent_disabled_allowlist_ignores_base_and_agent_entries() {
            let mut config = Config::default();
            config.agents.profiles.insert(
                "unknown".to_string(),
                AgentProfile {
                    disabled_allowlist: true,
                    additional_allowlist: vec!["git reset --hard".to_string()],
                    ..Default::default()
                },
            );

            let allowlists = apply_agent_allowlist_profile(
                &config,
                &Agent::Unknown,
                project_allowlist_for_rule("core.git:reset-hard"),
            );

            assert!(
                allowlists.layers.is_empty(),
                "disabled_allowlist should suppress project/user/system and agent entries"
            );

            let compiled_overrides = config.overrides.compile();
            let result = destructive_command_guard::evaluate_command(
                "git reset --hard",
                &config,
                &["git"],
                &compiled_overrides,
                &allowlists,
            );

            assert_eq!(result.decision, EvaluationDecision::Deny);
            assert!(result.allowlist_override.is_none());
        }

        #[test]
        fn hook_agent_additional_allowlist_allows_exact_command() {
            let mut config = Config::default();
            config.agents.profiles.insert(
                "claude-code".to_string(),
                AgentProfile {
                    additional_allowlist: vec!["git reset --hard".to_string()],
                    ..Default::default()
                },
            );

            let allowlists = apply_agent_allowlist_profile(
                &config,
                &Agent::ClaudeCode,
                LayeredAllowlist::default(),
            );
            let compiled_overrides = config.overrides.compile();
            let result = destructive_command_guard::evaluate_command(
                "git reset --hard",
                &config,
                &["git"],
                &compiled_overrides,
                &allowlists,
            );

            assert_eq!(result.decision, EvaluationDecision::Allow);
            assert_eq!(allowlists.layers[0].layer, AllowlistLayer::Agent);
        }

        #[test]
        fn hook_agent_extra_packs_participate_in_evaluation() {
            let mut config = Config::default();
            config.agents.profiles.insert(
                "unknown".to_string(),
                AgentProfile {
                    extra_packs: vec!["containers.docker".to_string()],
                    ..Default::default()
                },
            );

            let result = evaluate_with_agent(&config, &Agent::Unknown, "docker system prune");

            assert_eq!(result.decision, EvaluationDecision::Deny);
            assert_eq!(
                result
                    .pattern_info
                    .as_ref()
                    .and_then(|info| info.pack_id.as_deref()),
                Some("containers.docker")
            );
        }

        #[test]
        fn hook_agent_disabled_packs_are_removed_from_evaluation() {
            let mut config = Config::default();
            config.packs.enabled = vec!["containers.docker".to_string()];
            config.agents.profiles.insert(
                "unknown".to_string(),
                AgentProfile {
                    disabled_packs: vec!["containers".to_string()],
                    ..Default::default()
                },
            );

            let result = evaluate_with_agent(&config, &Agent::Unknown, "docker system prune");

            assert_eq!(result.decision, EvaluationDecision::Allow);
            assert!(result.pattern_info.is_none());
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

    mod shutdown_registry_tests {
        use super::*;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[test]
        fn registered_actions_all_run_on_shutdown_invocation() {
            // Each registered closure increments a shared counter. We verify
            // BOTH ran (after - before >= 2) without depending on ordering
            // between this test and other tests that may have registered
            // actions in the same process — the registry is process-wide.
            let counter = Arc::new(AtomicUsize::new(0));

            let c1 = Arc::clone(&counter);
            register_shutdown_action(move || {
                c1.fetch_add(1, Ordering::SeqCst);
            });
            let c2 = Arc::clone(&counter);
            register_shutdown_action(move || {
                c2.fetch_add(1, Ordering::SeqCst);
            });

            let before = counter.load(Ordering::SeqCst);
            run_shutdown_actions();
            let after = counter.load(Ordering::SeqCst);

            assert!(
                after - before >= 2,
                "both registered actions must run; before={before} after={after}"
            );
        }

        #[test]
        fn run_shutdown_actions_continues_after_panicking_action() {
            // git_safety_guard-i5gd defense: a buggy or panicking flush
            // closure must not skip subsequent registered actions. We
            // register a panicker and a counter-incrementer; after the
            // panic-catching shutdown invocation the counter must have
            // advanced, proving the second action ran.
            let counter = Arc::new(AtomicUsize::new(0));

            register_shutdown_action(|| {
                panic!("simulated flush failure");
            });
            let c = Arc::clone(&counter);
            register_shutdown_action(move || {
                c.fetch_add(1, Ordering::SeqCst);
            });

            let before = counter.load(Ordering::SeqCst);
            run_shutdown_actions();
            let after = counter.load(Ordering::SeqCst);

            assert!(
                after > before,
                "panicking action must not block subsequent ones; before={before} after={after}"
            );
        }
    }
}
