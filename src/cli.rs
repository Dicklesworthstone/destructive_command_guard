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
    Scan {
        // === File selection modes (mutually exclusive) ===
        /// Scan files staged for commit (git index)
        #[arg(long, conflicts_with_all = ["paths", "git_diff"])]
        staged: bool,

        /// Scan explicit file paths (directories are expanded recursively)
        #[arg(long, conflicts_with_all = ["staged", "git_diff"], num_args = 1..)]
        paths: Option<Vec<std::path::PathBuf>>,

        /// Scan files changed in a git diff range (e.g., "HEAD~3..HEAD", "main..feature")
        #[arg(long = "git-diff", value_name = "REV_RANGE", conflicts_with_all = ["staged", "paths"])]
        git_diff: Option<String>,

        // === Output / policy flags ===
        /// Output format
        #[arg(long, short = 'f', value_enum, default_value = "pretty")]
        format: crate::scan::ScanFormat,

        /// Exit non-zero when findings meet this threshold
        #[arg(long, value_enum, default_value = "error")]
        fail_on: crate::scan::ScanFailOn,

        // === Safety / performance knobs ===
        /// Maximum file size to scan (bytes); larger files are skipped
        #[arg(
            long = "max-file-size",
            value_name = "BYTES",
            default_value = "1048576"
        )]
        max_file_size: u64,

        /// Maximum number of findings to report (stop scanning after limit)
        #[arg(long = "max-findings", value_name = "N", default_value = "100")]
        max_findings: usize,

        /// Exclude files matching glob pattern (repeatable)
        #[arg(long, value_name = "GLOB")]
        exclude: Vec<String>,

        /// Include only files matching glob pattern (repeatable)
        #[arg(long, value_name = "GLOB")]
        include: Vec<String>,

        // === Redaction / truncation ===
        /// Redact sensitive content in output
        #[arg(long, value_enum, default_value = "none")]
        redact: ScanRedactMode,

        /// Truncate long commands in output (chars; 0 = no truncation)
        #[arg(long, value_name = "N", default_value = "200")]
        truncate: usize,

        // === UX flags ===
        /// Include verbose output (skipped-file reasons, extractor stats)
        #[arg(long, short = 'v')]
        verbose: bool,

        /// Limit exemplars shown in pretty output
        #[arg(long, value_name = "N", default_value = "10")]
        top: usize,
    },

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
}

/// Redaction mode for scan output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum ScanRedactMode {
    /// No redaction
    #[default]
    None,
    /// Redact quoted strings
    Quoted,
    /// Aggressive redaction (paths, args, etc.)
    Aggressive,
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
        Some(Command::Scan {
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
        }) => {
            handle_scan(
                &config,
                staged,
                paths,
                git_diff,
                format,
                fail_on,
                max_file_size,
                max_findings,
                &exclude,
                &include,
                redact,
                truncate,
                verbose,
                top,
            )?;
        }
        Some(Command::Explain {
            command,
            format,
            with_packs,
        }) => {
            handle_explain(&config, &command, format, with_packs);
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

/// Handle the `dcg scan` subcommand.
///
/// Validates file selection mode, builds scan options, and delegates to
/// the scan module for execution.
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
    _redact: ScanRedactMode,
    _truncate: usize,
    verbose: bool,
    _top: usize,
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
            print_scan_pretty(&report, verbose);
        }
        crate::scan::ScanFormat::Json => {
            let json = serde_json::to_string_pretty(&report)?;
            println!("{json}");
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
    // Very basic glob support for now - full glob crate could be added later
    if pattern.contains("**") {
        // ** matches any path segment(s)
        let parts: Vec<&str> = pattern.split("**").collect();
        if parts.len() == 2 {
            let prefix = parts[0].trim_end_matches('/');
            let suffix = parts[1].trim_start_matches('/');

            // Check prefix matches
            if !prefix.is_empty() && !path.starts_with(prefix) {
                return false;
            }

            // Check suffix - may contain wildcards
            if suffix.is_empty() {
                return true;
            }

            // For suffix like "*.rs", we need to check if any segment matches
            if suffix.contains('*') {
                // Apply single-star matching to the remainder after prefix
                let remainder = if prefix.is_empty() {
                    path
                } else {
                    path.strip_prefix(prefix)
                        .and_then(|s| s.strip_prefix('/'))
                        .unwrap_or(path)
                };

                // For **/*.ext pattern, check if any path component matches *.ext
                let ext_parts: Vec<&str> = suffix.split('*').collect();
                if ext_parts.len() == 2 {
                    let suffix_prefix = ext_parts[0];
                    let suffix_suffix = ext_parts[1];
                    // Check if any segment or the whole remainder matches
                    return remainder.ends_with(suffix_suffix)
                        && (suffix_prefix.is_empty()
                            || remainder
                                .rsplit('/')
                                .next()
                                .is_some_and(|s| s.starts_with(suffix_prefix)));
                }
            }

            return path.ends_with(suffix);
        }
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
fn print_scan_pretty(report: &crate::scan::ScanReport, verbose: bool) {
    use colored::Colorize;

    if report.findings.is_empty() {
        println!("{}", "No findings.".green());
    } else {
        println!(
            "{} finding(s):",
            report.findings.len().to_string().yellow().bold()
        );
        println!();

        for finding in &report.findings {
            let severity_icon = match finding.severity {
                crate::scan::ScanSeverity::Error => "ERROR".red().bold(),
                crate::scan::ScanSeverity::Warning => "WARN".yellow().bold(),
                crate::scan::ScanSeverity::Info => "INFO".blue(),
            };

            let location = finding.col.map_or_else(
                || format!("{}:{}", finding.file, finding.line),
                |col| format!("{}:{}:{}", finding.file, finding.line, col),
            );

            println!("[{severity_icon}] {location}");
            println!("  Command: {}", finding.extracted_command.dimmed());

            if let Some(ref rule_id) = finding.rule_id {
                println!("  Rule: {rule_id}");
            }

            if let Some(ref reason) = finding.reason {
                println!("  Reason: {reason}");
            }

            if let Some(ref suggestion) = finding.suggestion {
                println!("  Suggestion: {}", suggestion.green());
            }

            println!();
        }
    }

    // Summary
    println!("---");
    println!(
        "Files: {} considered, {} scanned",
        report.summary.files_considered, report.summary.files_scanned
    );
    println!("Commands extracted: {}", report.summary.commands_extracted);
    println!(
        "Findings: {} ({} blocked, {} warned)",
        report.summary.findings, report.summary.blocked, report.summary.warned
    );

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
    let allowlists = load_default_allowlists();

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

    // ========================================================================
    // Scan CLI tests
    // ========================================================================

    #[test]
    fn test_cli_parse_scan_staged() {
        let cli = Cli::try_parse_from(["dcg", "scan", "--staged"]).expect("parse");
        if let Some(Command::Scan {
            staged,
            paths,
            git_diff,
            ..
        }) = cli.command
        {
            assert!(staged);
            assert!(paths.is_none());
            assert!(git_diff.is_none());
        } else {
            panic!("Expected Scan command");
        }
    }

    #[test]
    fn test_cli_parse_scan_paths() {
        let cli = Cli::try_parse_from(["dcg", "scan", "--paths", "src/main.rs", "src/lib.rs"])
            .expect("parse");
        if let Some(Command::Scan {
            staged,
            paths,
            git_diff,
            ..
        }) = cli.command
        {
            assert!(!staged);
            assert_eq!(
                paths,
                Some(vec![
                    std::path::PathBuf::from("src/main.rs"),
                    std::path::PathBuf::from("src/lib.rs"),
                ])
            );
            assert!(git_diff.is_none());
        } else {
            panic!("Expected Scan command");
        }
    }

    #[test]
    fn test_cli_parse_scan_git_diff() {
        let cli = Cli::try_parse_from(["dcg", "scan", "--git-diff", "main..HEAD"]).expect("parse");
        if let Some(Command::Scan {
            staged,
            paths,
            git_diff,
            ..
        }) = cli.command
        {
            assert!(!staged);
            assert!(paths.is_none());
            assert_eq!(git_diff, Some("main..HEAD".to_string()));
        } else {
            panic!("Expected Scan command");
        }
    }

    #[test]
    fn test_cli_parse_scan_format_json() {
        let cli =
            Cli::try_parse_from(["dcg", "scan", "--staged", "--format", "json"]).expect("parse");
        if let Some(Command::Scan { format, .. }) = cli.command {
            assert_eq!(format, crate::scan::ScanFormat::Json);
        } else {
            panic!("Expected Scan command");
        }
    }

    #[test]
    fn test_cli_parse_scan_fail_on() {
        let cli = Cli::try_parse_from(["dcg", "scan", "--staged", "--fail-on", "warning"])
            .expect("parse");
        if let Some(Command::Scan { fail_on, .. }) = cli.command {
            assert_eq!(fail_on, crate::scan::ScanFailOn::Warning);
        } else {
            panic!("Expected Scan command");
        }
    }

    #[test]
    fn test_cli_parse_scan_max_file_size() {
        let cli = Cli::try_parse_from(["dcg", "scan", "--staged", "--max-file-size", "2048"])
            .expect("parse");
        if let Some(Command::Scan { max_file_size, .. }) = cli.command {
            assert_eq!(max_file_size, 2048);
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
        if let Some(Command::Scan {
            exclude, include, ..
        }) = cli.command
        {
            assert_eq!(exclude, vec!["*.log", "target/**"]);
            assert_eq!(include, vec!["src/**"]);
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
    }

    #[test]
    fn test_glob_match_overlapping_prefix_suffix() {
        // Edge case: pattern where prefix+suffix > path length would cause panic
        // without the min_len check in glob_match
        assert!(!glob_match("test*st", "test")); // "test" ends with "st" but prefix+suffix=6 > 4
        assert!(glob_match("test*st", "testst")); // exactly prefix+suffix=6, path=6, empty middle
        assert!(glob_match("test*st", "test_xst")); // middle is "_x", valid match
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
}
