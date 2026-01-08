//! CLI argument parsing and command handling.
//!
//! This module provides the command-line interface for dcg (`destructive_command_guard`),
//! including subcommands for configuration management and pack information.

use clap::{Parser, Subcommand};

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

/// Run the CLI command.
///
/// # Errors
///
/// Returns an error when no subcommand is provided (hook mode), or when a
/// subcommand that performs I/O fails.
pub fn run_command(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load();

    match cli.command {
        Some(Command::Doctor { fix }) => {
            doctor(fix);
        }
        Some(Command::Install { force }) => {
            install_hook(force)?;
        }
        Some(Command::Uninstall { purge }) => {
            uninstall_hook(purge)?;
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
            heredoc_scan,
            no_heredoc_scan,
            heredoc_timeout_ms,
            heredoc_languages,
        }) => {
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

/// Check installation, configuration, and hook registration
fn doctor(fix: bool) {
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

    // Check 3: Hook is registered
    print!("Checking hook registration... ");
    match check_hook_registered() {
        Ok(true) => println!("{}", "OK".green()),
        Ok(false) => {
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
                println!("  Run 'dcg install' to register the hook");
            }
        }
        Err(e) => {
            println!("{}", "ERROR".red());
            println!("  {e}");
        }
    }

    // Check 4: Config file
    print!("Checking configuration... ");
    let config_path = config_path();
    if config_path.exists() {
        println!("{} ({})", "OK".green(), config_path.display());
    } else {
        println!("{}", "USING DEFAULTS".yellow());
        println!("  No config file found, using defaults");
        println!("  Run 'dcg init -o ~/.config/dcg/config.toml' to create one");
    }

    // Check 5: Pattern packs
    print!("Checking pattern packs... ");
    let config = Config::load();
    let enabled = config.enabled_pack_ids();
    println!("{} ({} enabled)", "OK".green(), enabled.len());

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

/// Install the hook into Claude Code settings
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

/// Remove the hook from Claude Code settings
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
    let mut current = cwd.as_path();
    loop {
        if current.join(".git").exists() {
            return Some(current.to_path_buf());
        }
        current = current.parent()?;
    }
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
        validate_expiration_date(exp)?;
    }

    // Validate condition formats
    for cond in conditions {
        validate_condition(cond)?;
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
        validate_expiration_date(exp)?;
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
                    AllowSelector::Rule(rule_id) => format!("rule: {rule_id}"),
                    AllowSelector::ExactCommand(cmd) => format!("exact_command: {cmd}"),
                    AllowSelector::CommandPrefix(prefix) => format!("command_prefix: {prefix}"),
                    AllowSelector::RegexPattern(re) => format!("pattern: {re}"),
                };

                println!("  {} [{}]", selector_str.cyan(), layer.label());
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

/// Validate and optionally warn about expiration date format.
/// Returns Ok(()) if valid or parseable, Err with message if completely invalid.
fn validate_expiration_date(timestamp: &str) -> Result<(), String> {
    // Try RFC 3339 first (e.g., "2030-01-01T00:00:00Z" or "2030-01-01T00:00:00+00:00")
    if chrono::DateTime::parse_from_rfc3339(timestamp).is_ok() {
        return Ok(());
    }
    // Try ISO 8601 without timezone
    if chrono::NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%S").is_ok() {
        return Ok(());
    }
    // Try date only (YYYY-MM-DD) - treat as midnight UTC
    if chrono::NaiveDate::parse_from_str(timestamp, "%Y-%m-%d").is_ok() {
        return Ok(());
    }
    Err(format!(
        "Invalid expiration date format: '{timestamp}'. \
         Expected ISO 8601 format (e.g., '2030-01-01', '2030-01-01T00:00:00Z')"
    ))
}

/// Validate condition format (KEY=VALUE).
fn validate_condition(condition: &str) -> Result<(), String> {
    if condition.contains('=') {
        let parts: Vec<&str> = condition.splitn(2, '=').collect();
        if parts.len() == 2 && !parts[0].trim().is_empty() {
            return Ok(());
        }
    }
    Err(format!(
        "Invalid condition format: '{condition}'. Expected KEY=VALUE format (e.g., 'CI=true')"
    ))
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

        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
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
        let entry = build_rule_entry(&rule_id, "test reason", None, &[]);
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

    #[test]
    fn test_validate_expiration_date_valid_formats() {
        // RFC 3339 with Z
        assert!(validate_expiration_date("2030-01-01T00:00:00Z").is_ok());
        // RFC 3339 with offset
        assert!(validate_expiration_date("2030-01-01T00:00:00+00:00").is_ok());
        // ISO 8601 without timezone
        assert!(validate_expiration_date("2030-01-01T00:00:00").is_ok());
        // Date only
        assert!(validate_expiration_date("2030-01-01").is_ok());
    }

    #[test]
    fn test_validate_expiration_date_invalid_formats() {
        // Not a date
        assert!(validate_expiration_date("not-a-date").is_err());
        // Wrong format
        assert!(validate_expiration_date("01/01/2030").is_err());
        // Empty
        assert!(validate_expiration_date("").is_err());
    }

    #[test]
    fn test_validate_condition_valid() {
        assert!(validate_condition("CI=true").is_ok());
        assert!(validate_condition("ENV=production").is_ok());
        assert!(validate_condition("KEY=value with spaces").is_ok());
        assert!(validate_condition("EMPTY=").is_ok()); // empty value is OK
    }

    #[test]
    fn test_validate_condition_invalid() {
        // No equals sign
        assert!(validate_condition("invalid").is_err());
        // Empty key
        assert!(validate_condition("=value").is_err());
        // Just equals
        assert!(validate_condition("=").is_err());
    }
}
