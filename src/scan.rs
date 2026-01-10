//! Repository scanning (`dcg scan`) for destructive commands.
//!
//! This module is intentionally **extractor-based** (not naive substring grep).
//! The core idea is to extract only *executable contexts* from files, then
//! evaluate extracted commands using the shared evaluator pipeline.
//!
//! # Extraction contract
//!
//! Each extractor returns `ExtractedCommand` entries:
//!
//! - `file`, `line`, optional `col`
//! - `extractor_id` identifying the execution context (e.g. `shell.script`)
//! - `command` (the extracted executable command text)
//! - optional `metadata` (structured context for debugging / future UX)
//!
//! Extractors MUST be conservative: if unsure whether something is executed,
//! prefer returning no extraction rather than producing false positives.
//!
//! # Output schema (v1)
//!
//! `dcg scan --format json` emits a `ScanReport` containing:
//! - stable ordering of findings (deterministic output for CI / PR comments)
//! - `decision` in {allow,warn,deny}
//! - `severity` in {info,warning,error}
//! - stable `rule_id` (`pack_id:pattern_name`) when available
//!
//! Note: the shared evaluator currently only blocks deny-by-default pack rules.
//! Scan output uses this evaluator behavior for parity.

use crate::config::{Config, HeredocSettings};
use crate::evaluator::{
    EvaluationDecision, MatchSource, PatternMatch, evaluate_command_with_pack_order_at_path,
};
use crate::packs::{DecisionMode, REGISTRY, Severity};
use crate::suggestions::{SuggestionKind, get_suggestion_by_kind};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

pub const SCAN_SCHEMA_VERSION: u32 = 1;

/// Project-level scan config for repo integrations (pre-commit/CI).
///
/// Loaded from `.dcg/hooks.toml` (if present).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HooksToml {
    #[serde(default)]
    pub scan: HooksTomlScan,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct HooksTomlScan {
    pub fail_on: Option<ScanFailOn>,
    pub format: Option<ScanFormat>,
    pub max_file_size: Option<u64>,
    pub max_findings: Option<usize>,
    pub redact: Option<ScanRedactMode>,
    pub truncate: Option<usize>,
    #[serde(default)]
    pub paths: HooksTomlScanPaths,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct HooksTomlScanPaths {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// Parse `.dcg/hooks.toml` and return (typed config, warnings).
///
/// - Unknown keys are ignored, but surfaced as warnings (string messages).
/// - Invalid values return a descriptive error.
///
/// # Errors
///
/// Returns an error string if the TOML is syntactically invalid or cannot be
/// deserialized into the supported schema (e.g. invalid enum values).
pub fn parse_hooks_toml(contents: &str) -> Result<(HooksToml, Vec<String>), String> {
    let value: toml::Value = toml::from_str(contents).map_err(|e| e.to_string())?;
    let mut warnings = Vec::new();
    warn_unknown_hooks_toml_keys(&value, "", &mut warnings);

    let cfg: HooksToml = toml::from_str(contents).map_err(|e| e.to_string())?;
    Ok((cfg, warnings))
}

fn warn_unknown_hooks_toml_keys(value: &toml::Value, path: &str, warnings: &mut Vec<String>) {
    let Some(table) = value.as_table() else {
        return;
    };

    let allowed: &[&str] = match path {
        "" => &["scan"],
        "scan" => &[
            "fail_on",
            "format",
            "max_file_size",
            "max_findings",
            "redact",
            "truncate",
            "paths",
        ],
        "scan.paths" => &["include", "exclude"],
        _ => &[],
    };

    for (key, val) in table {
        let child_path = if path.is_empty() {
            key.clone()
        } else {
            format!("{path}.{key}")
        };

        if !allowed.contains(&key.as_str()) {
            warnings.push(format!("Unknown key `{child_path}` will be ignored"));
            continue;
        }

        if val.is_table() {
            warn_unknown_hooks_toml_keys(val, &child_path, warnings);
        }
    }
}

/// Scan output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ScanFormat {
    Pretty,
    Json,
    /// GitHub-flavored Markdown for PR comments (uses `<details>` blocks)
    Markdown,
}

/// Controls scan failure behavior (CI integration).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ScanFailOn {
    None,
    Warning,
    Error,
}

impl ScanFailOn {
    #[must_use]
    pub const fn blocks(&self, severity: ScanSeverity) -> bool {
        match self {
            Self::None => false,
            Self::Warning => matches!(severity, ScanSeverity::Warning | ScanSeverity::Error),
            Self::Error => matches!(severity, ScanSeverity::Error),
        }
    }
}

/// Redaction mode for scan output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ScanRedactMode {
    /// No redaction.
    #[default]
    None,
    /// Redact quoted strings.
    Quoted,
    /// Aggressive redaction (quoted strings + likely sensitive spans).
    Aggressive,
}

/// Scan decision for an extracted command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanDecision {
    Allow,
    Warn,
    Deny,
}

/// Scan severity (used for `--fail-on` policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanSeverity {
    Info,
    Warning,
    Error,
}

impl ScanSeverity {
    #[must_use]
    pub const fn rank(&self) -> u8 {
        match self {
            Self::Error => 3,
            Self::Warning => 2,
            Self::Info => 1,
        }
    }
}

/// Extracted executable command from a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedCommand {
    pub file: String,
    pub line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub col: Option<usize>,
    pub extractor_id: String,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// A scan finding produced by evaluating an extracted command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub file: String,
    pub line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub col: Option<usize>,
    pub extractor_id: String,
    pub extracted_command: String,
    pub decision: ScanDecision,
    pub severity: ScanSeverity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
}

/// Counts of findings by decision.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanDecisionCounts {
    pub allow: usize,
    pub warn: usize,
    pub deny: usize,
}

/// Counts of findings by severity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanSeverityCounts {
    pub info: usize,
    pub warning: usize,
    pub error: usize,
}

/// Summary statistics for a scan run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub commands_extracted: usize,
    pub findings_total: usize,
    pub decisions: ScanDecisionCounts,
    pub severities: ScanSeverityCounts,
    pub max_findings_reached: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
}

/// Complete scan output (stable JSON schema).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: u32,
    pub summary: ScanSummary,
    pub findings: Vec<ScanFinding>,
}

/// In-memory scan configuration (CLI + defaults).
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub format: ScanFormat,
    pub fail_on: ScanFailOn,
    pub max_file_size_bytes: u64,
    pub max_findings: usize,
    pub redact: ScanRedactMode,
    /// Truncate extracted commands in output (chars). 0 disables truncation.
    pub truncate: usize,
}

/// Precomputed evaluator context for scanning.
#[derive(Debug)]
pub struct ScanEvalContext {
    pub enabled_keywords: Vec<&'static str>,
    pub ordered_packs: Vec<String>,
    pub compiled_overrides: crate::config::CompiledOverrides,
    pub allowlists: crate::allowlist::LayeredAllowlist,
    pub heredoc_settings: HeredocSettings,
}

impl ScanEvalContext {
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        let enabled_packs: HashSet<String> = config.enabled_pack_ids();
        let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
        let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
        let compiled_overrides = config.overrides.compile();
        let allowlists = crate::load_default_allowlists();
        let heredoc_settings = config.heredoc_settings();

        Self {
            enabled_keywords,
            ordered_packs,
            compiled_overrides,
            allowlists,
            heredoc_settings,
        }
    }
}

#[must_use]
pub fn should_fail(report: &ScanReport, fail_on: ScanFailOn) -> bool {
    report.findings.iter().any(|f| fail_on.blocks(f.severity))
}

pub fn sort_findings(findings: &mut [ScanFinding]) {
    findings.sort_by(|a, b| {
        let key_a = (
            a.file.as_str(),
            a.line,
            a.col.unwrap_or(0),
            a.rule_id.as_deref().unwrap_or(a.extractor_id.as_str()),
            a.extractor_id.as_str(),
            a.severity.rank(),
            a.extracted_command.as_str(),
        );
        let key_b = (
            b.file.as_str(),
            b.line,
            b.col.unwrap_or(0),
            b.rule_id.as_deref().unwrap_or(b.extractor_id.as_str()),
            b.extractor_id.as_str(),
            b.severity.rank(),
            b.extracted_command.as_str(),
        );
        key_a.cmp(&key_b)
    });
}

#[must_use]
pub fn evaluate_extracted_command(
    extracted: &ExtractedCommand,
    options: &ScanOptions,
    config: &Config,
    ctx: &ScanEvalContext,
) -> Option<ScanFinding> {
    let project_path = {
        let candidate = std::path::Path::new(&extracted.file);
        if candidate.is_absolute() {
            Some(candidate.to_path_buf())
        } else {
            std::env::current_dir().ok().map(|cwd| cwd.join(candidate))
        }
    };
    let result = evaluate_command_with_pack_order_at_path(
        &extracted.command,
        &ctx.enabled_keywords,
        &ctx.ordered_packs,
        &ctx.compiled_overrides,
        &ctx.allowlists,
        &ctx.heredoc_settings,
        project_path.as_deref(),
    );

    if result.decision == EvaluationDecision::Allow {
        return None;
    }

    let Some(pattern) = result.pattern_info else {
        return Some(ScanFinding {
            file: extracted.file.clone(),
            line: extracted.line,
            col: extracted.col,
            extractor_id: extracted.extractor_id.clone(),
            extracted_command: extracted.command.clone(),
            decision: ScanDecision::Deny,
            severity: ScanSeverity::Error,
            rule_id: None,
            reason: Some("Blocked (missing match metadata)".to_string()),
            suggestion: None,
        });
    };

    let (rule_id, severity, decision_mode) = resolve_severity_and_rule_id(config, &pattern);

    let scan_decision = match decision_mode {
        Some(DecisionMode::Deny) | None => ScanDecision::Deny,
        Some(DecisionMode::Warn) => ScanDecision::Warn,
        Some(DecisionMode::Log) => ScanDecision::Allow,
    };

    let scan_severity = match severity {
        Some(Severity::Medium) => ScanSeverity::Warning,
        Some(Severity::Low) => ScanSeverity::Info,
        Some(Severity::Critical | Severity::High) | None => ScanSeverity::Error,
    };

    let suggestion = rule_id
        .as_deref()
        .and_then(|id| get_suggestion_by_kind(id, SuggestionKind::SaferAlternative))
        .map(|s| s.text.clone());

    let extracted_command = redact_and_truncate(&extracted.command, options);

    Some(ScanFinding {
        file: extracted.file.clone(),
        line: extracted.line,
        col: extracted.col,
        extractor_id: extracted.extractor_id.clone(),
        extracted_command,
        decision: scan_decision,
        severity: scan_severity,
        rule_id,
        reason: Some(pattern.reason),
        suggestion,
    })
}

fn resolve_severity_and_rule_id(
    config: &Config,
    pattern: &PatternMatch,
) -> (Option<String>, Option<Severity>, Option<DecisionMode>) {
    let Some(pack_id) = pattern.pack_id.as_deref() else {
        return (None, None, None);
    };

    let Some(pattern_name) = pattern.pattern_name.as_deref() else {
        return (None, None, None);
    };

    let rule_id = Some(format!("{pack_id}:{pattern_name}"));

    let severity = pattern.severity;

    // Never downgrade explicit blocks; packs/AST matches are policy-controlled.
    let mode = match pattern.source {
        MatchSource::Pack | MatchSource::HeredocAst => {
            config
                .policy()
                .resolve_mode(Some(pack_id), Some(pattern_name), severity)
        }
        MatchSource::ConfigOverride | MatchSource::LegacyPattern => DecisionMode::Deny,
    };

    (rule_id, severity, Some(mode))
}

fn redact_and_truncate(command: &str, options: &ScanOptions) -> String {
    let redacted = match options.redact {
        ScanRedactMode::None => command.to_string(),
        ScanRedactMode::Quoted => redact_quoted_strings(command),
        ScanRedactMode::Aggressive => redact_aggressively(command),
    };

    truncate_utf8(&redacted, options.truncate)
}

fn truncate_utf8(s: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return s.to_string();
    }

    let char_count = s.chars().count();
    if char_count <= max_chars {
        return s.to_string();
    }

    if max_chars == 1 {
        return "…".to_string();
    }

    let keep = max_chars - 1;
    let truncated: String = s.chars().take(keep).collect();
    format!("{truncated}…")
}

#[must_use]
pub fn redact_quoted_strings(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();

    while let Some(c) = it.next() {
        match c {
            '\'' => {
                out.push('\'');
                out.push('…');
                for next in it.by_ref() {
                    if next == '\'' {
                        out.push('\'');
                        break;
                    }
                }
            }
            '"' => {
                out.push('"');
                out.push('…');
                let mut escaped = false;
                for next in it.by_ref() {
                    if escaped {
                        escaped = false;
                        continue;
                    }
                    if next == '\\' {
                        escaped = true;
                        continue;
                    }
                    if next == '"' {
                        out.push('"');
                        break;
                    }
                }
            }
            _ => out.push(c),
        }
    }

    out
}

#[must_use]
pub fn redact_aggressively(s: &str) -> String {
    // First pass: redact quoted strings (most likely secret-bearing spans).
    let s = redact_quoted_strings(s);

    // Second pass: redact KEY=VALUE tokens when key looks secret-y.
    // This keeps output debuggable while avoiding accidental leakage.
    let mut out = String::with_capacity(s.len());
    let mut token = String::new();

    for c in s.chars() {
        if c.is_whitespace() {
            if !token.is_empty() {
                out.push_str(&redact_token(&token));
                token.clear();
            }
            out.push(c);
        } else {
            token.push(c);
        }
    }

    if !token.is_empty() {
        out.push_str(&redact_token(&token));
    }

    out
}

fn redact_token(token: &str) -> String {
    // Redact long hex-ish blobs (common for hashes/keys).
    if token.len() >= 32 && token.chars().all(|c| c.is_ascii_hexdigit()) {
        return "…".to_string();
    }

    if let Some(eq) = token.find('=') {
        let lower = token[..eq].to_ascii_lowercase();
        let (k, _v) = token.split_at(eq + 1);
        if lower.contains("token")
            || lower.contains("secret")
            || lower.contains("password")
            || lower.contains("passwd")
            || lower.contains("api_key")
            || lower.contains("apikey")
            || lower.contains("bearer")
        {
            return format!("{k}…");
        }
    }

    token.to_string()
}

/// Scan file paths (directories are expanded recursively).
///
/// This is a small, conservative implementation intended to support the `scan`
/// epic without pulling in heavy parsing dependencies. Extraction is delegated
/// to extractor modules.
///
/// Currently implements:
/// - Shell-script extractor (`*.sh`)
/// - Dockerfile extractor (`Dockerfile`, `*.dockerfile`, `Dockerfile.*`)
/// - GitHub Actions workflow extractor (`.github/workflows/*.yml|*.yaml`)
/// - GitLab CI extractor (`.gitlab-ci.yml`, `*.gitlab-ci.yml`)
/// - Makefile extractor (`Makefile`)
/// - package.json extractor (`package.json` - scripts only)
/// - Terraform extractor (`*.tf` - provisioner blocks)
/// - docker-compose extractor (`docker-compose.yml`, `compose.yml` - command/entrypoint)
#[allow(clippy::missing_errors_doc)]
#[allow(clippy::too_many_lines)]
pub fn scan_paths(
    paths: &[PathBuf],
    options: &ScanOptions,
    config: &Config,
    ctx: &ScanEvalContext,
) -> Result<ScanReport, String> {
    let started = std::time::Instant::now();

    let mut files: Vec<PathBuf> = Vec::new();
    for path in paths {
        collect_files_recursively(path, &mut files);
    }

    files.sort();
    files.dedup();

    let mut files_scanned = 0usize;
    let mut files_skipped = 0usize;
    let mut commands_extracted = 0usize;
    let mut findings: Vec<ScanFinding> = Vec::new();
    let mut max_findings_reached = false;

    for file in &files {
        if findings.len() >= options.max_findings {
            max_findings_reached = true;
            break;
        }

        let Ok(meta) = std::fs::metadata(file) else {
            files_skipped += 1;
            continue;
        };

        if !meta.is_file() {
            files_skipped += 1;
            continue;
        }

        if meta.len() > options.max_file_size_bytes {
            files_skipped += 1;
            continue;
        }

        // Determine which extractor(s) to use
        let is_shell = is_shell_script_path(file);
        let is_docker = is_dockerfile_path(file);
        let is_actions = is_github_actions_workflow_path(file);
        let is_gitlab = is_gitlab_ci_path(file);
        let is_makefile = is_makefile_path(file);
        let is_package_json = is_package_json_path(file);
        let is_terraform = is_terraform_path(file);
        let is_compose = is_docker_compose_path(file);

        if !is_shell
            && !is_docker
            && !is_actions
            && !is_gitlab
            && !is_makefile
            && !is_package_json
            && !is_terraform
            && !is_compose
        {
            files_skipped += 1;
            continue;
        }

        let Ok(bytes) = std::fs::read(file) else {
            files_skipped += 1;
            continue;
        };

        let content = String::from_utf8_lossy(&bytes);
        let file_label = file.to_string_lossy();
        files_scanned += 1;

        // Extract commands using appropriate extractor(s)
        let mut extracted: Vec<ExtractedCommand> = Vec::new();

        if is_shell {
            extracted.extend(extract_shell_script_from_str(
                &file_label,
                &content,
                &ctx.enabled_keywords,
            ));
        }

        if is_docker {
            extracted.extend(extract_dockerfile_from_str(
                &file_label,
                &content,
                &ctx.enabled_keywords,
            ));
        }

        if is_actions {
            extracted.extend(extract_github_actions_workflow_from_str(
                &file_label,
                &content,
                &ctx.enabled_keywords,
            ));
        }

        if is_gitlab {
            extracted.extend(extract_gitlab_ci_from_str(
                &file_label,
                &content,
                &ctx.enabled_keywords,
            ));
        }

        if is_makefile {
            extracted.extend(extract_makefile_from_str(
                &file_label,
                &content,
                &ctx.enabled_keywords,
            ));
        }

        if is_package_json {
            extracted.extend(extract_package_json_from_str(
                &file_label,
                &content,
                &ctx.enabled_keywords,
            ));
        }

        if is_terraform {
            extracted.extend(extract_terraform_from_str(
                &file_label,
                &content,
                &ctx.enabled_keywords,
            ));
        }

        if is_compose {
            extracted.extend(extract_docker_compose_from_str(
                &file_label,
                &content,
                &ctx.enabled_keywords,
            ));
        }

        commands_extracted += extracted.len();

        for cmd in extracted {
            if findings.len() >= options.max_findings {
                max_findings_reached = true;
                break;
            }

            if let Some(finding) = evaluate_extracted_command(&cmd, options, config, ctx) {
                findings.push(finding);
            }
        }

        if max_findings_reached {
            break;
        }
    }

    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).ok();
    Ok(build_report(
        findings,
        files_scanned,
        files_skipped,
        commands_extracted,
        max_findings_reached,
        elapsed_ms,
    ))
}
fn collect_files_recursively(path: &PathBuf, out: &mut Vec<PathBuf>) {
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };

    if meta.is_file() {
        out.push(path.clone());
        return;
    }

    if !meta.is_dir() {
        return;
    }

    let Ok(read_dir) = std::fs::read_dir(path) else {
        return;
    };

    // Deterministic traversal: sort entries by path.
    let mut entries: Vec<PathBuf> = read_dir.filter_map(|e| e.ok().map(|e| e.path())).collect();
    entries.sort();

    for entry in entries {
        collect_files_recursively(&entry, out);
    }
}

// ============================================================================
// Shell script extractor (*.sh)
// ============================================================================

fn is_shell_script_path(path: &Path) -> bool {
    path.extension()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|ext: &str| {
            let ext = ext.to_ascii_lowercase();
            matches!(ext.as_str(), "sh" | "bash" | "zsh" | "dash" | "ksh")
        })
}

fn extract_shell_script_from_str(
    file: &str,
    content: &str,
    enabled_keywords: &[&'static str],
) -> Vec<ExtractedCommand> {
    const MAX_CONTINUATION_LINES: usize = 20;
    const MAX_JOINED_CHARS: usize = 8 * 1024;

    let mut out = Vec::new();
    let mut buffer: Option<(usize, String, usize)> = None;

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;

        let (segment, continues) = split_shell_line_continuation(raw_line);
        let segment = segment.trim();

        if let Some((start_line, mut joined, cont_lines)) = buffer.take() {
            if !joined.is_empty() && !segment.is_empty() {
                joined.push(' ');
            }
            joined.push_str(segment);

            if continues && cont_lines < MAX_CONTINUATION_LINES && joined.len() < MAX_JOINED_CHARS {
                buffer = Some((start_line, joined, cont_lines + 1));
                continue;
            }

            if let Some(cmd) =
                extract_shell_command_line(file, start_line, &joined, enabled_keywords)
            {
                out.push(cmd);
            }
            continue;
        }

        if continues {
            buffer = Some((line_no, segment.to_string(), 1));
            continue;
        }

        if let Some(cmd) = extract_shell_command_line(file, line_no, segment, enabled_keywords) {
            out.push(cmd);
        }
    }

    if let Some((start_line, joined, _)) = buffer.take() {
        if let Some(cmd) = extract_shell_command_line(file, start_line, &joined, enabled_keywords) {
            out.push(cmd);
        }
    }

    out
}

/// Split a shell line into (segment, continues) where `continues` is true when
/// the line ends with an unescaped backslash outside of single quotes.
fn split_shell_line_continuation(line: &str) -> (&str, bool) {
    let trimmed = line.trim_end();
    if !trimmed.ends_with('\\') {
        return (trimmed, false);
    }

    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for c in trimmed.chars() {
        if escaped {
            escaped = false;
            continue;
        }

        if c == '\\' && !in_single {
            escaped = true;
            continue;
        }

        match c {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            _ => {}
        }
    }

    if escaped && !in_single {
        let without = trimmed.strip_suffix('\\').unwrap_or(trimmed).trim_end();
        (without, true)
    } else {
        (trimmed, false)
    }
}

fn extract_shell_script_with_offset_and_id(
    file: &str,
    start_line: usize,
    content: &str,
    enabled_keywords: &[&'static str],
    extractor_id: &'static str,
) -> Vec<ExtractedCommand> {
    let mut extracted = extract_shell_script_from_str(file, content, enabled_keywords);
    let offset = start_line.saturating_sub(1);

    for cmd in &mut extracted {
        cmd.line = cmd.line.saturating_add(offset);
        cmd.extractor_id = extractor_id.to_string();
    }

    extracted
}

fn extract_shell_command_line(
    file: &str,
    line: usize,
    candidate: &str,
    enabled_keywords: &[&'static str],
) -> Option<ExtractedCommand> {
    let candidate = candidate.trim();

    if candidate.is_empty() || candidate.starts_with('#') {
        return None;
    }

    let candidate = strip_shell_inline_comment(candidate).trim();
    if candidate.is_empty() {
        return None;
    }

    if !enabled_keywords.is_empty() && !contains_any_keyword(candidate, enabled_keywords) {
        return None;
    }

    let words = split_shell_words(candidate);
    let first = words.first()?.as_str();

    if is_shell_control_line(first) {
        return None;
    }

    if is_shell_function_declaration(&words) {
        return None;
    }

    if is_shell_assignment_only(&words) {
        return None;
    }

    Some(ExtractedCommand {
        file: file.to_string(),
        line,
        col: None,
        extractor_id: "shell.script".to_string(),
        command: candidate.to_string(),
        metadata: None,
    })
}

fn is_shell_control_line(first_word: &str) -> bool {
    matches!(
        first_word,
        "if" | "then"
            | "else"
            | "elif"
            | "fi"
            | "for"
            | "while"
            | "until"
            | "do"
            | "done"
            | "case"
            | "esac"
            | "{"
            | "}"
            | "function"
    )
}

fn is_shell_function_declaration(words: &[String]) -> bool {
    let Some(first) = words.first() else {
        return false;
    };

    if first == "function" {
        return true;
    }

    if first.ends_with("()") {
        return true;
    }

    if words.get(1).is_some_and(|w| w == "()") {
        return true;
    }

    if first.contains("()") && words.get(1).is_some_and(|w| w == "{") {
        return true;
    }

    false
}

fn is_shell_assignment_only(words: &[String]) -> bool {
    let mut idx = 0usize;
    if words.first().is_some_and(|w| {
        matches!(
            w.as_str(),
            "export" | "local" | "readonly" | "declare" | "typeset"
        )
    }) {
        idx += 1;
    }
    while idx < words.len() && is_shell_assignment_word(&words[idx]) {
        idx += 1;
    }

    idx == words.len()
}

fn is_shell_assignment_word(word: &str) -> bool {
    let Some(eq) = word.find('=') else {
        return false;
    };

    if eq == 0 {
        return false;
    }

    let var = &word[..eq];
    is_shell_var_name(var)
}

fn is_shell_var_name(s: &str) -> bool {
    let mut it = s.chars();
    let Some(first) = it.next() else {
        return false;
    };

    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }

    it.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn contains_any_keyword(haystack: &str, keywords: &[&'static str]) -> bool {
    keywords.iter().any(|k| haystack.contains(k))
}

fn strip_shell_inline_comment(s: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut prev: Option<char> = None;

    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
            prev = Some(c);
            continue;
        }

        if c == '\\' && !in_single {
            escaped = true;
            prev = Some(c);
            continue;
        }

        match c {
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            '#' if !in_single && !in_double => {
                let token_start = i == 0
                    || prev.is_some_and(|p| p.is_whitespace() || matches!(p, ';' | '|' | '&'));
                if token_start {
                    return &s[..i];
                }
            }
            _ => {}
        }

        prev = Some(c);
    }

    s
}

fn split_shell_words(s: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();

    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for c in s.chars() {
        if escaped {
            cur.push(c);
            escaped = false;
            continue;
        }

        if c == '\\' && !in_single {
            escaped = true;
            continue;
        }

        match c {
            '\'' if !in_double => {
                in_single = !in_single;
                cur.push(c);
            }
            '"' if !in_single => {
                in_double = !in_double;
                cur.push(c);
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if !cur.is_empty() {
                    words.push(cur);
                    cur = String::new();
                }
            }
            _ => cur.push(c),
        }
    }

    if !cur.is_empty() {
        words.push(cur);
    }

    words
}

// ============================================================================
// Dockerfile extractor (Dockerfile, *.dockerfile, Dockerfile.*)
// ============================================================================

fn is_dockerfile_path(path: &Path) -> bool {
    let file_name = path.file_name().and_then(std::ffi::OsStr::to_str);
    let Some(name) = file_name else {
        return false;
    };

    let lower = name.to_ascii_lowercase();

    if lower == "dockerfile" {
        return true;
    }

    if lower.ends_with(".dockerfile") {
        return true;
    }

    if lower.starts_with("dockerfile.") {
        return true;
    }

    false
}

fn extract_dockerfile_from_str(
    file: &str,
    content: &str,
    enabled_keywords: &[&'static str],
) -> Vec<ExtractedCommand> {
    const MAX_CONTINUATION_LINES: usize = 50;
    const MAX_JOINED_CHARS: usize = 32 * 1024;

    let mut out = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut idx = 0;

    while idx < lines.len() {
        let line_no = idx + 1;
        let raw_line = lines[idx];
        let trimmed = raw_line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            idx += 1;
            continue;
        }

        let upper = trimmed.to_ascii_uppercase();
        // Handle "RUN " (space), "RUN\t" (tab), or bare "RUN" followed by continuation
        let is_run = upper == "RUN" || upper.starts_with("RUN ") || upper.starts_with("RUN\t");
        if !is_run {
            idx += 1;
            continue;
        }

        let cmd_start = if trimmed.len() > 4 { &trimmed[4..] } else { "" };
        let cmd_trimmed = cmd_start.trim_start();

        if cmd_trimmed.starts_with('[') {
            // Exec-form: RUN ["cmd", "arg1", "arg2"]
            // Join args with spaces to approximate a shell command for scanning.
            if let Ok(args) = serde_json::from_str::<Vec<String>>(cmd_trimmed) {
                let joined = args.join(" ");
                if !joined.is_empty()
                    && (enabled_keywords.is_empty()
                        || contains_any_keyword(&joined, enabled_keywords))
                {
                    out.push(ExtractedCommand {
                        file: file.to_string(),
                        line: line_no,
                        col: None,
                        extractor_id: "dockerfile.run.exec".to_string(),
                        command: joined,
                        metadata: None,
                    });
                }
            }
            idx += 1;
            continue;
        }

        let (command, lines_consumed) =
            join_dockerfile_continuation(&lines, idx, MAX_CONTINUATION_LINES, MAX_JOINED_CHARS);

        idx += lines_consumed;

        let full_trimmed = command.trim();
        let cmd_part = if full_trimmed.len() > 4 {
            full_trimmed[4..].trim_start()
        } else {
            continue;
        };

        if cmd_part.starts_with('[') {
            continue;
        }

        let cmd_part = strip_shell_inline_comment(cmd_part).trim();

        if cmd_part.is_empty() {
            continue;
        }

        if !enabled_keywords.is_empty() && !contains_any_keyword(cmd_part, enabled_keywords) {
            continue;
        }

        out.push(ExtractedCommand {
            file: file.to_string(),
            line: line_no,
            col: None,
            extractor_id: "dockerfile.run".to_string(),
            command: cmd_part.to_string(),
            metadata: None,
        });
    }

    out
}

fn join_dockerfile_continuation(
    lines: &[&str],
    start_idx: usize,
    max_lines: usize,
    max_chars: usize,
) -> (String, usize) {
    let mut joined = String::new();
    let mut idx = start_idx;
    let mut lines_consumed = 0usize;

    while idx < lines.len() && lines_consumed < max_lines && joined.len() < max_chars {
        let raw_line = lines[idx];
        lines_consumed += 1;
        idx += 1;

        let trimmed = raw_line.trim_end();
        let (segment, continues) = trimmed
            .strip_suffix('\\')
            .map_or((trimmed, false), |before| (before.trim_end(), true));

        if !joined.is_empty() && !segment.trim().is_empty() {
            joined.push(' ');
        }
        joined.push_str(segment.trim_start());

        if !continues {
            break;
        }
    }

    (joined, lines_consumed)
}

// ============================================================================
// GitHub Actions workflow extractor (.github/workflows/*.yml|*.yaml)
// ============================================================================

fn is_github_actions_workflow_path(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(std::ffi::OsStr::to_str) else {
        return false;
    };
    let ext = ext.to_ascii_lowercase();
    if ext != "yml" && ext != "yaml" {
        return false;
    }

    let components: Vec<String> = path
        .components()
        .filter_map(|c| c.as_os_str().to_str().map(str::to_ascii_lowercase))
        .collect();

    components
        .windows(2)
        .any(|w| w[0] == ".github" && w[1] == "workflows")
}

fn extract_github_actions_workflow_from_str(
    file: &str,
    content: &str,
    enabled_keywords: &[&'static str],
) -> Vec<ExtractedCommand> {
    const EXTRACTOR_ID: &str = "github_actions.steps.run";

    let lines: Vec<&str> = content.lines().collect();
    let mut out = Vec::new();
    let mut steps_indent: Option<usize> = None;

    let mut idx = 0usize;
    while idx < lines.len() {
        let line_no = idx + 1;
        let raw_line = lines[idx];
        let trimmed_start = raw_line.trim_start();

        if trimmed_start.is_empty() || trimmed_start.starts_with('#') {
            idx += 1;
            continue;
        }

        let indent = raw_line.len() - trimmed_start.len();

        if let Some(steps) = steps_indent {
            // Exit steps block when indentation returns to the steps key level (or less).
            if !trimmed_start.starts_with('-') && indent <= steps {
                steps_indent = None;
            }
        }

        if steps_indent.is_none() {
            if let Some(rest) = yaml_key_value(trimmed_start, "steps") {
                if rest.is_empty() || rest.starts_with('#') {
                    steps_indent = Some(indent);
                }
            }
            idx += 1;
            continue;
        }

        let Some(steps) = steps_indent else {
            unreachable!("steps_indent is checked above");
        };

        let in_steps_line = indent > steps || (indent == steps && trimmed_start.starts_with('-'));
        if !in_steps_line {
            idx += 1;
            continue;
        }

        let mut candidate = trimmed_start;
        if let Some(after_dash) = candidate.strip_prefix('-') {
            candidate = after_dash.trim_start();
        }

        let Some(run_value) = yaml_key_value(candidate, "run") else {
            idx += 1;
            continue;
        };

        if run_value.starts_with('|') || run_value.starts_with('>') {
            let block_start_line = line_no + 1;
            let mut block = String::new();
            let mut j = idx + 1;

            while j < lines.len() {
                let raw = lines[j];
                let trimmed = raw.trim_start();

                if !trimmed.is_empty() {
                    let block_indent = raw.len() - trimmed.len();
                    if block_indent <= indent {
                        break;
                    }
                }

                if !block.is_empty() {
                    block.push('\n');
                }
                block.push_str(raw);
                j += 1;
            }

            out.extend(extract_shell_script_with_offset_and_id(
                file,
                block_start_line,
                &block,
                enabled_keywords,
                EXTRACTOR_ID,
            ));

            idx = j;
            continue;
        }

        let unquoted = unquote_yaml_scalar(run_value);
        out.extend(extract_shell_script_with_offset_and_id(
            file,
            line_no,
            &unquoted,
            enabled_keywords,
            EXTRACTOR_ID,
        ));

        idx += 1;
    }

    out
}

fn unquote_yaml_scalar(s: &str) -> String {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') {
        // Double-quoted: handle escapes
        if s.len() < 2 {
            return String::new();
        }
        let content = &s[1..s.len() - 1];
        let mut out = String::with_capacity(content.len());
        let mut chars = content.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some('"') => out.push('"'),
                    Some('\\') | None => out.push('\\'),
                    Some(other) => {
                        out.push('\\');
                        out.push(other);
                    }
                }
            } else {
                out.push(c);
            }
        }
        return out;
    }
    if s.starts_with('\'') && s.ends_with('\'') {
        // Single-quoted: only '' is escape for '
        if s.len() < 2 {
            return String::new();
        }
        let content = &s[1..s.len() - 1];
        return content.replace("''", "'");
    }
    s.to_string()
}

// ============================================================================
// GitLab CI extractor (.gitlab-ci.yml, *.gitlab-ci.yml)
// ============================================================================

fn is_gitlab_ci_path(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(std::ffi::OsStr::to_str) else {
        return false;
    };
    let lower = file_name.to_ascii_lowercase();
    lower == ".gitlab-ci.yml" || lower.ends_with(".gitlab-ci.yml")
}

#[allow(clippy::too_many_lines)]
#[must_use]
pub fn extract_gitlab_ci_from_str(
    file: &str,
    content: &str,
    enabled_keywords: &[&'static str],
) -> Vec<ExtractedCommand> {
    const EXTRACTOR_ID: &str = "gitlab_ci.script";

    let lines: Vec<&str> = content.lines().collect();
    let mut out = Vec::new();
    let mut anchors: HashMap<String, Vec<ExtractedCommand>> = HashMap::new();
    let mut skip_indent: Option<usize> = None;

    let mut idx = 0usize;
    while idx < lines.len() {
        let line_no = idx + 1;
        let raw_line = lines[idx];
        let trimmed_start = raw_line.trim_start();

        if trimmed_start.is_empty() || trimmed_start.starts_with('#') {
            idx += 1;
            continue;
        }

        let indent = raw_line.len() - trimmed_start.len();

        if let Some(skip) = skip_indent {
            if indent <= skip {
                skip_indent = None;
            } else {
                idx += 1;
                continue;
            }
        }

        if yaml_key_value(trimmed_start, "variables").is_some()
            || yaml_key_value(trimmed_start, "rules").is_some()
            || yaml_key_value(trimmed_start, "only").is_some()
            || yaml_key_value(trimmed_start, "except").is_some()
        {
            skip_indent = Some(indent);
            idx += 1;
            continue;
        }

        if let Some(value) = yaml_key_value(trimmed_start, "before_script")
            .or_else(|| yaml_key_value(trimmed_start, "script"))
            .or_else(|| yaml_key_value(trimmed_start, "after_script"))
        {
            if let Some((anchor_name, _remainder)) = parse_yaml_anchor(value, '&') {
                let (commands, next_idx) = extract_gitlab_sequence_items(
                    file,
                    &lines,
                    idx + 1,
                    indent,
                    enabled_keywords,
                    EXTRACTOR_ID,
                    &mut anchors,
                );
                anchors.insert(anchor_name, commands.clone());
                out.extend(commands);
                idx = next_idx;
                continue;
            }

            if let Some((alias_name, _)) = parse_yaml_anchor(value, '*') {
                if let Some(anchored) = anchors.get(&alias_name) {
                    out.extend(anchored.iter().cloned());
                }
                idx += 1;
                continue;
            }

            if value.starts_with('|') || value.starts_with('>') {
                let (block, block_start_line, next_idx) = parse_yaml_block(&lines, idx + 1, indent);
                out.extend(extract_shell_script_with_offset_and_id(
                    file,
                    block_start_line,
                    &block,
                    enabled_keywords,
                    EXTRACTOR_ID,
                ));
                idx = next_idx;
                continue;
            }

            if let Some(items) = parse_inline_yaml_sequence(value) {
                for item in items {
                    out.extend(extract_shell_script_with_offset_and_id(
                        file,
                        line_no,
                        &item,
                        enabled_keywords,
                        EXTRACTOR_ID,
                    ));
                }
                idx += 1;
                continue;
            }

            if value.is_empty() || value.starts_with('#') {
                let (commands, next_idx) = extract_gitlab_sequence_items(
                    file,
                    &lines,
                    idx + 1,
                    indent,
                    enabled_keywords,
                    EXTRACTOR_ID,
                    &mut anchors,
                );
                out.extend(commands);
                idx = next_idx;
                continue;
            }

            out.extend(extract_shell_script_with_offset_and_id(
                file,
                line_no,
                &unquote_yaml_scalar(value),
                enabled_keywords,
                EXTRACTOR_ID,
            ));

            idx += 1;
            continue;
        }

        if let Some(anchor_name) = gitlab_anchor_definition(trimmed_start) {
            let (commands, next_idx) = extract_gitlab_sequence_items(
                file,
                &lines,
                idx + 1,
                indent,
                enabled_keywords,
                EXTRACTOR_ID,
                &mut anchors,
            );

            if !commands.is_empty() {
                anchors.insert(anchor_name, commands);
                idx = next_idx;
                continue;
            }
        }

        idx += 1;
    }

    out
}

fn gitlab_anchor_definition(line: &str) -> Option<String> {
    let (_, rest) = line.split_once(':')?;
    let rest = rest.trim_start();
    let (anchor_name, remainder) = parse_yaml_anchor(rest, '&')?;
    if remainder.is_empty() || remainder.starts_with('#') {
        return Some(anchor_name);
    }
    None
}

fn extract_gitlab_sequence_items(
    file: &str,
    lines: &[&str],
    start_idx: usize,
    parent_indent: usize,
    enabled_keywords: &[&'static str],
    extractor_id: &'static str,
    anchors: &mut HashMap<String, Vec<ExtractedCommand>>,
) -> (Vec<ExtractedCommand>, usize) {
    let mut out = Vec::new();
    let mut idx = start_idx;

    while idx < lines.len() {
        let line_no = idx + 1;
        let raw_line = lines[idx];
        let trimmed_start = raw_line.trim_start();

        if trimmed_start.is_empty() || trimmed_start.starts_with('#') {
            idx += 1;
            continue;
        }

        let indent = raw_line.len() - trimmed_start.len();
        if indent <= parent_indent {
            break;
        }

        if !trimmed_start.starts_with('-') {
            idx += 1;
            continue;
        }

        let item_indent = indent;
        let mut item_value = trimmed_start.trim_start_matches('-').trim_start();
        let mut anchor_name: Option<String> = None;

        if let Some((anchor, remainder)) = parse_yaml_anchor(item_value, '&') {
            anchor_name = Some(anchor);
            item_value = remainder;
        }

        if let Some((alias_name, _)) = parse_yaml_anchor(item_value, '*') {
            if let Some(anchored) = anchors.get(&alias_name) {
                out.extend(anchored.iter().cloned());
            }
            idx += 1;
            continue;
        }

        if item_value.starts_with('|') || item_value.starts_with('>') {
            let (block, block_start_line, next_idx) = parse_yaml_block(lines, idx + 1, item_indent);
            let extracted = extract_shell_script_with_offset_and_id(
                file,
                block_start_line,
                &block,
                enabled_keywords,
                extractor_id,
            );
            if let Some(anchor) = anchor_name {
                anchors.insert(anchor, extracted.clone());
            }
            out.extend(extracted);
            idx = next_idx;
            continue;
        }

        if !item_value.is_empty() && !item_value.starts_with('#') {
            let extracted = extract_shell_script_with_offset_and_id(
                file,
                line_no,
                &unquote_yaml_scalar(item_value),
                enabled_keywords,
                extractor_id,
            );
            if let Some(anchor) = anchor_name {
                anchors.insert(anchor, extracted.clone());
            }
            out.extend(extracted);
        }

        idx += 1;
    }

    (out, idx)
}

fn parse_yaml_block(
    lines: &[&str],
    start_idx: usize,
    parent_indent: usize,
) -> (String, usize, usize) {
    let block_start_line = start_idx + 1;
    let mut block = String::new();
    let mut idx = start_idx;

    while idx < lines.len() {
        let raw = lines[idx];
        let trimmed = raw.trim_start();

        if !trimmed.is_empty() {
            let indent = raw.len() - trimmed.len();
            if indent <= parent_indent {
                break;
            }
        }

        if !block.is_empty() {
            block.push('\n');
        }
        block.push_str(raw);
        idx += 1;
    }

    (block, block_start_line, idx)
}

fn parse_inline_yaml_sequence(value: &str) -> Option<Vec<String>> {
    let trimmed = value.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return None;
    }
    let inner = trimmed.trim_start_matches('[').trim_end_matches(']');
    let mut out = Vec::new();

    for part in inner.split(',') {
        let item = part.trim();
        if item.is_empty() {
            continue;
        }
        let unquoted = item.trim_matches(&['"', '\''][..]);
        if !unquoted.is_empty() {
            out.push(unquoted.to_string());
        }
    }

    Some(out)
}

fn parse_yaml_anchor(value: &str, prefix: char) -> Option<(String, &str)> {
    let trimmed = value.trim_start();
    let rest = trimmed.strip_prefix(prefix)?;
    let mut name = String::new();

    for ch in rest.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            name.push(ch);
        } else {
            break;
        }
    }

    if name.is_empty() {
        return None;
    }

    let remainder = &rest[name.len()..];
    Some((name, remainder.trim_start()))
}

fn yaml_key_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let trimmed = line.trim_start();
    let after_key = trimmed.strip_prefix(key)?;

    // Require `key:` or `key :` (avoid matching prefixes like `runner:` for `run`).
    let after_key = after_key
        .strip_prefix(':')
        .or_else(|| after_key.trim_start().strip_prefix(':'))?;

    Some(after_key.trim_start())
}

// ============================================================================
// Makefile extractor (Makefile)
// ============================================================================

fn is_makefile_path(path: &Path) -> bool {
    let file_name = path.file_name().and_then(std::ffi::OsStr::to_str);
    file_name.is_some_and(|name| name.eq_ignore_ascii_case("makefile"))
}

fn extract_makefile_from_str(
    file: &str,
    content: &str,
    enabled_keywords: &[&'static str],
) -> Vec<ExtractedCommand> {
    const EXTRACTOR_ID: &str = "makefile.recipe";

    let lines: Vec<&str> = content.lines().collect();
    let mut out = Vec::new();
    let mut idx = 0usize;

    while idx < lines.len() {
        let raw_line = lines[idx];
        if !raw_line.starts_with('\t') {
            idx += 1;
            continue;
        }

        let start_line = idx + 1;
        let mut block = String::new();
        let mut prev_continues = false;

        while idx < lines.len() {
            let line = lines[idx];
            let is_recipe_line = line.starts_with('\t');

            if !is_recipe_line && !prev_continues {
                break;
            }

            if !block.is_empty() {
                block.push('\n');
            }
            block.push_str(line);

            prev_continues = line.trim_end().ends_with('\\');
            idx += 1;
        }

        out.extend(extract_shell_script_with_offset_and_id(
            file,
            start_line,
            &block,
            enabled_keywords,
            EXTRACTOR_ID,
        ));
    }

    out
}

// ============================================================================
// package.json extractor
// ============================================================================

fn is_package_json_path(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(std::ffi::OsStr::to_str) else {
        return false;
    };
    file_name == "package.json"
}

/// Extract executable scripts from package.json.
///
/// Extracts:
/// - All values in `scripts` object (these are npm script commands)
/// - Lifecycle scripts: preinstall, postinstall, prepublish, etc.
///
/// Does NOT extract:
/// - `description`, `keywords`, `repository` fields
/// - Values in `config` or other non-executable fields
#[must_use]
pub fn extract_package_json_from_str(
    file: &str,
    content: &str,
    enabled_keywords: &[&'static str],
) -> Vec<ExtractedCommand> {
    const EXTRACTOR_ID: &str = "package_json.script";

    let mut out = Vec::new();

    // Parse JSON
    let Ok(json) = serde_json::from_str::<serde_json::Value>(content) else {
        return out;
    };

    // Extract scripts object
    let Some(scripts) = json.get("scripts").and_then(|s| s.as_object()) else {
        return out;
    };

    // Build a line number map for accurate line reporting
    let line_map = build_json_line_map(content);

    for (script_name, script_value) in scripts {
        let Some(script_cmd) = script_value.as_str() else {
            continue;
        };

        // Find the line number for this script
        let line_no = find_json_key_line(&line_map, script_name, "scripts");

        // Check if the command contains any enabled keywords
        let has_keyword = enabled_keywords.iter().any(|kw| script_cmd.contains(kw));

        if has_keyword {
            out.push(ExtractedCommand {
                file: file.to_string(),
                line: line_no,
                col: None,
                extractor_id: EXTRACTOR_ID.to_string(),
                command: script_cmd.to_string(),
                metadata: Some(serde_json::json!({ "script_name": script_name })),
            });
        }
    }

    out
}

/// Build a map of line content for JSON line number lookups.
fn build_json_line_map(content: &str) -> Vec<&str> {
    content.lines().collect()
}

/// Find the line number of a JSON key within a parent object.
fn find_json_key_line(lines: &[&str], key: &str, parent: &str) -> usize {
    let parent_pattern = format!("\"{parent}\"");
    let key_pattern = format!("\"{key}\"");

    let mut start_idx = 0;

    // Try to find parent key first
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with(&parent_pattern) && trimmed.contains(':') {
            start_idx = idx + 1;
            break;
        }
    }

    // Search for key after parent (or from start if parent not found)
    for (idx, line) in lines.iter().enumerate().skip(start_idx) {
        let trimmed = line.trim();
        if trimmed.starts_with(&key_pattern) && trimmed.contains(':') {
            return idx + 1;
        }
    }

    // Fallback: search from beginning if we started later and didn't find it
    if start_idx > 0 {
        for (idx, line) in lines.iter().enumerate().take(start_idx) {
            let trimmed = line.trim();
            if trimmed.starts_with(&key_pattern) && trimmed.contains(':') {
                return idx + 1;
            }
        }
    }

    1 // Default to line 1 if not found
}

// ============================================================================
// Terraform extractor (*.tf) - provisioner blocks
// ============================================================================

fn is_terraform_path(path: &Path) -> bool {
    path.extension()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|ext| ext.eq_ignore_ascii_case("tf"))
}

/// Extract commands from Terraform provisioner blocks.
///
/// Extracts:
/// - `local-exec` provisioner `command` values
/// - `remote-exec` provisioner `inline` array entries
///
/// Does NOT extract:
/// - Variable definitions
/// - Output values
/// - Resource attributes (non-provisioner)
/// - Comments
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn extract_terraform_from_str(
    file: &str,
    content: &str,
    enabled_keywords: &[&'static str],
) -> Vec<ExtractedCommand> {
    const EXTRACTOR_ID_LOCAL: &str = "terraform.provisioner.local_exec";
    const EXTRACTOR_ID_REMOTE: &str = "terraform.provisioner.remote_exec";

    let lines: Vec<&str> = content.lines().collect();
    let mut out = Vec::new();
    let mut idx = 0usize;

    while idx < lines.len() {
        let raw_line = lines[idx];
        let trimmed = raw_line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            idx += 1;
            continue;
        }

        // Look for provisioner blocks
        if let Some(prov_type) = detect_provisioner_block(trimmed) {
            // Calculate leading indent only (not affected by trailing whitespace)
            let block_indent = raw_line.len() - raw_line.trim_start().len();
            idx += 1;

            // Parse the provisioner block
            match prov_type {
                ProvisionerType::LocalExec => {
                    while idx < lines.len() {
                        let inner_line = lines[idx];
                        let inner_trimmed = inner_line.trim();

                        if inner_trimmed == "}" {
                            let inner_indent = inner_line.len() - inner_line.trim_start().len();
                            if inner_indent <= block_indent {
                                break;
                            }
                        }

                        if let Some(cmd) = extract_hcl_string_value(inner_trimmed, "command") {
                            let has_keyword = enabled_keywords.iter().any(|kw| cmd.contains(kw));
                            if has_keyword {
                                out.push(ExtractedCommand {
                                    file: file.to_string(),
                                    line: idx + 1,
                                    col: None,
                                    extractor_id: EXTRACTOR_ID_LOCAL.to_string(),
                                    command: cmd,
                                    metadata: Some(serde_json::Value::String(
                                        "provisioner: local-exec".to_string(),
                                    )),
                                });
                            }
                        }

                        if let Some((heredoc_marker, is_stripping)) =
                            detect_heredoc_start(inner_trimmed, "command")
                        {
                            let heredoc_start = idx + 1;
                            idx += 1;
                            let mut heredoc_content = String::new();

                            while idx < lines.len() {
                                // For <<- (stripping), trim before comparing; for << match exactly
                                let heredoc_line = if is_stripping {
                                    lines[idx].trim()
                                } else {
                                    lines[idx]
                                };
                                if heredoc_line == heredoc_marker {
                                    break;
                                }
                                if !heredoc_content.is_empty() {
                                    heredoc_content.push('\n');
                                }
                                heredoc_content.push_str(lines[idx]);
                                idx += 1;
                            }

                            out.extend(extract_shell_script_with_offset_and_id(
                                file,
                                heredoc_start + 1,
                                &heredoc_content,
                                enabled_keywords,
                                EXTRACTOR_ID_LOCAL,
                            ));
                        }

                        idx += 1;
                    }
                }
                ProvisionerType::RemoteExec => {
                    while idx < lines.len() {
                        let inner_line = lines[idx];
                        let inner_trimmed = inner_line.trim();

                        if inner_trimmed == "}" {
                            let inner_indent = inner_line.len() - inner_line.trim_start().len();
                            if inner_indent <= block_indent {
                                break;
                            }
                        }

                        if inner_trimmed.starts_with("inline") && inner_trimmed.contains('=') {
                            let array_start = idx + 1;
                            if inner_trimmed.contains('[') && inner_trimmed.contains(']') {
                                for cmd in extract_hcl_array_items(inner_trimmed) {
                                    let has_keyword =
                                        enabled_keywords.iter().any(|kw| cmd.contains(kw));
                                    if has_keyword {
                                        out.push(ExtractedCommand {
                                            file: file.to_string(),
                                            line: array_start,
                                            col: None,
                                            extractor_id: EXTRACTOR_ID_REMOTE.to_string(),
                                            command: cmd,
                                            metadata: Some(serde_json::Value::String(
                                                "provisioner: remote-exec".to_string(),
                                            )),
                                        });
                                    }
                                }
                            } else if inner_trimmed.contains('[') {
                                idx += 1;
                                while idx < lines.len() {
                                    let arr_line = lines[idx].trim();
                                    if arr_line.starts_with(']') {
                                        break;
                                    }
                                    if let Some(cmd) = extract_quoted_string(arr_line) {
                                        let has_keyword =
                                            enabled_keywords.iter().any(|kw| cmd.contains(kw));
                                        if has_keyword {
                                            out.push(ExtractedCommand {
                                                file: file.to_string(),
                                                line: idx + 1,
                                                col: None,
                                                extractor_id: EXTRACTOR_ID_REMOTE.to_string(),
                                                command: cmd,
                                                metadata: Some(serde_json::Value::String(
                                                    "provisioner: remote-exec".to_string(),
                                                )),
                                            });
                                        }
                                    }
                                    idx += 1;
                                }
                            }
                        }

                        idx += 1;
                    }
                }
            }
        }

        idx += 1;
    }

    out
}

#[derive(Debug, Clone, Copy)]
enum ProvisionerType {
    LocalExec,
    RemoteExec,
}

fn detect_provisioner_block(line: &str) -> Option<ProvisionerType> {
    if !line.starts_with("provisioner") {
        return None;
    }

    if line.contains("\"local-exec\"") || line.contains("'local-exec'") {
        Some(ProvisionerType::LocalExec)
    } else if line.contains("\"remote-exec\"") || line.contains("'remote-exec'") {
        Some(ProvisionerType::RemoteExec)
    } else {
        None
    }
}

fn extract_hcl_string_value(line: &str, key: &str) -> Option<String> {
    if !line.starts_with(key) {
        return None;
    }

    let after_key = line[key.len()..].trim_start();
    if !after_key.starts_with('=') {
        return None;
    }

    let after_eq = after_key[1..].trim_start();
    extract_quoted_string(after_eq)
}

fn extract_quoted_string(s: &str) -> Option<String> {
    let s = s.trim();
    let s = s.trim_end_matches(',');

    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        return Some(s[1..s.len() - 1].to_string());
    }
    None
}

/// Returns (marker, `is_stripping`) where `is_stripping` is true for `<<-` heredocs
fn detect_heredoc_start(line: &str, key: &str) -> Option<(String, bool)> {
    if !line.starts_with(key) {
        return None;
    }

    let after_key = line[key.len()..].trim_start();
    if !after_key.starts_with('=') {
        return None;
    }

    let after_eq = after_key[1..].trim_start();
    if let Some(marker) = after_eq.strip_prefix("<<-") {
        let marker = marker.trim();
        if !marker.is_empty() {
            return Some((marker.to_string(), true)); // stripping heredoc
        }
    } else if let Some(marker) = after_eq.strip_prefix("<<") {
        let marker = marker.trim();
        if !marker.is_empty() {
            return Some((marker.to_string(), false)); // non-stripping heredoc
        }
    }
    None
}

fn extract_hcl_array_items(line: &str) -> Vec<String> {
    let mut items = Vec::new();

    let Some(start) = line.find('[') else {
        return items;
    };
    let Some(end) = line.rfind(']') else {
        return items;
    };

    if start >= end {
        return items;
    }

    let array_content = &line[start + 1..end];

    for part in split_hcl_array(array_content) {
        if let Some(s) = extract_quoted_string(&part) {
            items.push(s);
        }
    }

    items
}

fn split_hcl_array(content: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut quote_char = '\0';
    let mut escaped = false;

    for c in content.chars() {
        if escaped {
            current.push(c);
            escaped = false;
            continue;
        }

        if c == '\\' && in_quote {
            escaped = true;
            current.push(c);
            continue;
        }

        if in_quote {
            current.push(c);
            if c == quote_char {
                in_quote = false;
            }
        } else if c == '"' || c == '\'' {
            in_quote = true;
            quote_char = c;
            current.push(c);
        } else if c == ',' {
            parts.push(current.trim().to_string());
            current.clear();
        } else {
            current.push(c);
        }
    }

    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }

    parts
}

// ============================================================================
// docker-compose extractor
// ============================================================================

fn is_docker_compose_path(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(std::ffi::OsStr::to_str) else {
        return false;
    };
    let lower = file_name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "docker-compose.yml" | "docker-compose.yaml" | "compose.yml" | "compose.yaml"
    )
}

/// Extract executable commands from docker-compose files.
///
/// Extracts:
/// - `command:` values (service command)
/// - `entrypoint:` values (service entrypoint)
/// - `healthcheck.test:` commands
///
/// Does NOT extract:
/// - `environment:` values (data only)
/// - `labels:` values (metadata only)
/// - Comments
#[must_use]
pub fn extract_docker_compose_from_str(
    file: &str,
    content: &str,
    enabled_keywords: &[&'static str],
) -> Vec<ExtractedCommand> {
    const EXTRACTOR_ID: &str = "docker_compose.command";

    let lines: Vec<&str> = content.lines().collect();
    let mut out = Vec::new();
    let mut skip_indent: Option<usize> = None;

    let mut idx = 0usize;
    while idx < lines.len() {
        let raw_line = lines[idx];
        let trimmed_start = raw_line.trim_start();

        // Skip empty lines and comments
        if trimmed_start.is_empty() || trimmed_start.starts_with('#') {
            idx += 1;
            continue;
        }

        let indent = raw_line.len() - trimmed_start.len();

        // Handle skip regions (environment, labels, etc.)
        if let Some(skip) = skip_indent {
            if indent <= skip {
                skip_indent = None;
            } else {
                idx += 1;
                continue;
            }
        }

        // Skip environment and labels blocks (these are data, not commands)
        if yaml_key_value(trimmed_start, "environment").is_some()
            || yaml_key_value(trimmed_start, "labels").is_some()
            || yaml_key_value(trimmed_start, "volumes").is_some()
            || yaml_key_value(trimmed_start, "ports").is_some()
            || yaml_key_value(trimmed_start, "networks").is_some()
            || yaml_key_value(trimmed_start, "depends_on").is_some()
        {
            skip_indent = Some(indent);
            idx += 1;
            continue;
        }

        // Extract command: values
        if let Some(value) = yaml_key_value(trimmed_start, "command") {
            out.extend(extract_docker_compose_command(
                file,
                &lines,
                idx,
                indent,
                value,
                enabled_keywords,
                EXTRACTOR_ID,
            ));
            idx += 1;
            continue;
        }

        // Extract entrypoint: values
        if let Some(value) = yaml_key_value(trimmed_start, "entrypoint") {
            out.extend(extract_docker_compose_command(
                file,
                &lines,
                idx,
                indent,
                value,
                enabled_keywords,
                EXTRACTOR_ID,
            ));
            idx += 1;
            continue;
        }

        // Extract healthcheck.test: values
        if let Some(value) = yaml_key_value(trimmed_start, "test") {
            // Only extract if we're likely in a healthcheck context
            // (simple heuristic: check if "healthcheck" appeared recently)
            let in_healthcheck = (idx.saturating_sub(5)..idx)
                .any(|i| lines.get(i).is_some_and(|l| l.contains("healthcheck")));
            if in_healthcheck {
                out.extend(extract_docker_compose_command(
                    file,
                    &lines,
                    idx,
                    indent,
                    value,
                    enabled_keywords,
                    EXTRACTOR_ID,
                ));
            }
            idx += 1;
            continue;
        }

        idx += 1;
    }

    out
}

/// Extract a command value from docker-compose (handles string, array, and block formats).
fn extract_docker_compose_command(
    file: &str,
    lines: &[&str],
    idx: usize,
    indent: usize,
    value: &str,
    enabled_keywords: &[&'static str],
    extractor_id: &'static str,
) -> Vec<ExtractedCommand> {
    let line_no = idx + 1;
    let mut out = Vec::new();

    // Handle inline sequence: command: ["sh", "-c", "rm -rf /"]
    if let Some(items) = parse_inline_yaml_sequence(value) {
        // Join array elements to form the command
        let cmd = items.join(" ");
        if enabled_keywords.iter().any(|kw| cmd.contains(kw)) {
            out.push(ExtractedCommand {
                file: file.to_string(),
                line: line_no,
                col: None,
                extractor_id: extractor_id.to_string(),
                command: cmd,
                metadata: None,
            });
        }
        return out;
    }

    // Handle block scalar: command: |
    if value.starts_with('|') || value.starts_with('>') {
        let (block, block_start_line, _next_idx) = parse_yaml_block(lines, idx + 1, indent);
        out.extend(extract_shell_script_with_offset_and_id(
            file,
            block_start_line,
            &block,
            enabled_keywords,
            extractor_id,
        ));
        return out;
    }

    // Handle empty value followed by sequence
    if value.is_empty() || value.starts_with('#') {
        // Look for sequence items on following lines
        let mut seq_idx = idx + 1;
        let mut cmd_parts = Vec::new();
        while seq_idx < lines.len() {
            let seq_line = lines[seq_idx];
            let seq_trimmed = seq_line.trim_start();
            let seq_indent = seq_line.len() - seq_trimmed.len();

            if seq_indent <= indent && !seq_trimmed.is_empty() {
                break;
            }

            if seq_trimmed.starts_with("- ") {
                let item = seq_trimmed.strip_prefix("- ").unwrap_or("").trim();
                // Strip quotes if present
                let item = item.trim_matches('"').trim_matches('\'');
                cmd_parts.push(item.to_string());
            } else if !seq_trimmed.is_empty() && !seq_trimmed.starts_with('#') {
                break;
            }

            seq_idx += 1;
        }

        if !cmd_parts.is_empty() {
            let cmd = cmd_parts.join(" ");
            if enabled_keywords.iter().any(|kw| cmd.contains(kw)) {
                out.push(ExtractedCommand {
                    file: file.to_string(),
                    line: line_no,
                    col: None,
                    extractor_id: extractor_id.to_string(),
                    command: cmd,
                    metadata: None,
                });
            }
        }
        return out;
    }

    // Handle inline string: command: /bin/sh -c "rm -rf /"
    // Strip quotes if present
    let cmd = value.trim_matches('"').trim_matches('\'').to_string();
    if enabled_keywords.iter().any(|kw| cmd.contains(kw)) {
        out.push(ExtractedCommand {
            file: file.to_string(),
            line: line_no,
            col: None,
            extractor_id: extractor_id.to_string(),
            command: cmd,
            metadata: None,
        });
    }

    out
}

#[must_use]
pub fn build_report(
    mut findings: Vec<ScanFinding>,
    files_scanned: usize,
    files_skipped: usize,
    commands_extracted: usize,
    max_findings_reached: bool,
    elapsed_ms: Option<u64>,
) -> ScanReport {
    sort_findings(&mut findings);

    let mut decisions = ScanDecisionCounts::default();
    let mut severities = ScanSeverityCounts::default();

    for f in &findings {
        match f.decision {
            ScanDecision::Allow => decisions.allow += 1,
            ScanDecision::Warn => decisions.warn += 1,
            ScanDecision::Deny => decisions.deny += 1,
        }

        match f.severity {
            ScanSeverity::Info => severities.info += 1,
            ScanSeverity::Warning => severities.warning += 1,
            ScanSeverity::Error => severities.error += 1,
        }
    }

    ScanReport {
        schema_version: SCAN_SCHEMA_VERSION,
        summary: ScanSummary {
            files_scanned,
            files_skipped,
            commands_extracted,
            findings_total: findings.len(),
            decisions,
            severities,
            max_findings_reached,
            elapsed_ms,
        },
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> Config {
        Config::default()
    }

    #[test]
    fn hooks_toml_parses_valid_config() {
        let input = r#"
[scan]
fail_on = "warning"
format = "json"
max_file_size = 1234
max_findings = 50
redact = "quoted"
truncate = 10

[scan.paths]
include = ["scripts/**", ".github/workflows/**"]
exclude = ["target/**"]
"#;

        let (cfg, warnings) = parse_hooks_toml(input).expect("parse");
        assert!(warnings.is_empty(), "should not warn on valid config");
        assert_eq!(cfg.scan.fail_on, Some(ScanFailOn::Warning));
        assert_eq!(cfg.scan.format, Some(ScanFormat::Json));
        assert_eq!(cfg.scan.max_file_size, Some(1234));
        assert_eq!(cfg.scan.max_findings, Some(50));
        assert_eq!(cfg.scan.redact, Some(ScanRedactMode::Quoted));
        assert_eq!(cfg.scan.truncate, Some(10));
        assert_eq!(
            cfg.scan.paths.include,
            vec!["scripts/**", ".github/workflows/**"]
        );
        assert_eq!(cfg.scan.paths.exclude, vec!["target/**"]);
    }

    #[test]
    fn hooks_toml_warns_on_unknown_keys() {
        let input = r#"
top_level = "x"

[scan]
format = "json"
unknown = 123

[scan.paths]
include = ["src/**"]
extra = ["x"]
"#;

        let (_cfg, warnings) = parse_hooks_toml(input).expect("parse");
        assert!(
            warnings.iter().any(|w| w.contains("top_level")),
            "should warn on unknown top-level keys"
        );
        assert!(
            warnings.iter().any(|w| w.contains("scan.unknown")),
            "should warn on unknown scan keys"
        );
        assert!(
            warnings.iter().any(|w| w.contains("scan.paths.extra")),
            "should warn on unknown scan.paths keys"
        );
    }

    #[test]
    fn hooks_toml_invalid_enum_value_errors() {
        let input = r#"
[scan]
fail_on = "nope"
"#;

        let err = parse_hooks_toml(input).expect_err("should fail");
        assert!(
            err.to_lowercase().contains("fail_on") || err.to_lowercase().contains("unknown"),
            "error should mention the invalid value: {err}"
        );
    }

    #[test]
    fn fail_on_policy_blocks_as_expected() {
        let report = build_report(
            vec![
                ScanFinding {
                    file: "a".to_string(),
                    line: 1,
                    col: None,
                    extractor_id: "x".to_string(),
                    extracted_command: "rm -rf /".to_string(),
                    decision: ScanDecision::Deny,
                    severity: ScanSeverity::Error,
                    rule_id: Some("core.filesystem:rm-rf-general".to_string()),
                    reason: Some("blocked".to_string()),
                    suggestion: None,
                },
                ScanFinding {
                    file: "b".to_string(),
                    line: 1,
                    col: None,
                    extractor_id: "x".to_string(),
                    extracted_command: "echo hi".to_string(),
                    decision: ScanDecision::Warn,
                    severity: ScanSeverity::Warning,
                    rule_id: None,
                    reason: Some("warn".to_string()),
                    suggestion: None,
                },
            ],
            2,
            0,
            2,
            false,
            None,
        );

        assert!(should_fail(&report, ScanFailOn::Error));
        assert!(should_fail(&report, ScanFailOn::Warning));
        assert!(!should_fail(&report, ScanFailOn::None));
    }

    #[test]
    fn finding_order_is_deterministic() {
        let mut findings = vec![
            ScanFinding {
                file: "b".to_string(),
                line: 2,
                col: None,
                extractor_id: "x".to_string(),
                extracted_command: "cmd".to_string(),
                decision: ScanDecision::Warn,
                severity: ScanSeverity::Warning,
                rule_id: Some("pack:rule".to_string()),
                reason: None,
                suggestion: None,
            },
            ScanFinding {
                file: "a".to_string(),
                line: 1,
                col: None,
                extractor_id: "x".to_string(),
                extracted_command: "cmd".to_string(),
                decision: ScanDecision::Deny,
                severity: ScanSeverity::Error,
                rule_id: Some("pack:rule".to_string()),
                reason: None,
                suggestion: None,
            },
        ];

        sort_findings(&mut findings);
        assert_eq!(findings[0].file, "a");
        assert_eq!(findings[0].line, 1);
    }

    #[test]
    fn evaluator_integration_maps_pack_rule_to_rule_id() {
        let config = default_config();
        let ctx = ScanEvalContext::from_config(&config);
        let options = ScanOptions {
            format: ScanFormat::Pretty,
            fail_on: ScanFailOn::Error,
            max_file_size_bytes: 1024 * 1024,
            max_findings: 100,
            redact: ScanRedactMode::None,
            truncate: 0,
        };
        let extracted = ExtractedCommand {
            file: "test".to_string(),
            line: 1,
            col: None,
            extractor_id: "shell.script".to_string(),
            command: "git reset --hard".to_string(),
            metadata: None,
        };

        let finding = evaluate_extracted_command(&extracted, &options, &config, &ctx)
            .expect("git reset --hard should be blocked");
        assert_eq!(finding.decision, ScanDecision::Deny);
        assert_eq!(finding.severity, ScanSeverity::Error);
        assert_eq!(finding.rule_id.as_deref(), Some("core.git:reset-hard"));
        assert!(finding.reason.is_some());
    }

    // ========================================================================
    // Extractor tests (false-positive controls)
    // ========================================================================

    #[test]
    fn shell_extractor_skips_assignment_with_trailing_comment() {
        let content = r#"
DOC="rm -rf /" # this is data, not an executed command
export NOTE="git reset --hard" # also data
"#;

        let extracted = extract_shell_script_from_str("test.sh", content, &["rm", "git"]);
        assert!(
            extracted.is_empty(),
            "Expected no extracted commands, got: {extracted:?}"
        );
    }

    #[test]
    fn shell_extractor_extracts_commands_after_export_assignment() {
        let content = r"export FOO=bar && rm -rf ./tmp";
        let extracted = extract_shell_script_from_str("test.sh", content, &["rm"]);

        assert_eq!(extracted.len(), 1);
        assert!(extracted[0].command.contains("rm -rf"));
    }

    #[test]
    fn shell_extractor_skips_function_declaration_with_spaced_parens() {
        let content = "git_reset () {\n}\n";
        let extracted = extract_shell_script_from_str("test.sh", content, &["git"]);

        assert!(
            extracted.is_empty(),
            "Expected no extracted commands, got: {extracted:?}"
        );
    }

    #[test]
    fn dockerfile_extractor_ignores_shell_comments_in_run() {
        let content = r"
FROM ubuntu:22.04
RUN echo hello # rm -rf /
";

        let extracted = extract_dockerfile_from_str("Dockerfile", content, &["rm"]);
        assert!(
            extracted.is_empty(),
            "Expected no extracted commands, got: {extracted:?}"
        );
    }

    #[test]
    fn dockerfile_extractor_strips_shell_comments_in_run_and_keeps_real_command() {
        let content = r"
FROM ubuntu:22.04
RUN rm -rf ./tmp # cleanup temp dir
";

        let extracted = extract_dockerfile_from_str("Dockerfile", content, &["rm"]);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].command, "rm -rf ./tmp");
    }

    #[test]
    fn dockerfile_extractor_does_not_extract_env_values() {
        let content = r#"
FROM ubuntu:22.04
ENV X="rm -rf /" # should not be treated as executable context
ENV NOTE="git reset --hard"
"#;

        let extracted = extract_dockerfile_from_str("Dockerfile", content, &["rm", "git"]);
        assert!(
            extracted.is_empty(),
            "Expected no extracted commands, got: {extracted:?}"
        );
    }

    #[test]
    fn github_actions_extractor_does_not_extract_env_or_with_fields() {
        let content = r#"jobs:
  test:
    steps:
      - name: "rm -rf /"
        env:
          X: "rm -rf /"
        with:
          args: "rm -rf /"
        run: echo hello
"#;

        // Only `steps[].run` is executable context. This fixture includes `rm` only in
        // data fields; the extractor must return nothing.
        let extracted =
            extract_github_actions_workflow_from_str(".github/workflows/ci.yml", content, &["rm"]);
        assert!(
            extracted.is_empty(),
            "Expected no extracted commands, got: {extracted:?}"
        );
    }

    // ========================================================================
    // JSON schema tests (git_safety_guard-scan.2.4)
    // ========================================================================

    #[test]
    fn json_schema_version_is_present() {
        let report = build_report(vec![], 0, 0, 0, false, None);
        assert_eq!(report.schema_version, SCAN_SCHEMA_VERSION);
        assert_eq!(report.schema_version, 1);
    }

    #[test]
    fn json_schema_has_all_required_fields() {
        let report = build_report(vec![], 5, 2, 10, false, Some(42));

        // Summary fields
        assert_eq!(report.summary.files_scanned, 5);
        assert_eq!(report.summary.files_skipped, 2);
        assert_eq!(report.summary.commands_extracted, 10);
        assert_eq!(report.summary.findings_total, 0);
        assert!(!report.summary.max_findings_reached);
        assert_eq!(report.summary.elapsed_ms, Some(42));

        // Decision counts
        assert_eq!(report.summary.decisions.allow, 0);
        assert_eq!(report.summary.decisions.warn, 0);
        assert_eq!(report.summary.decisions.deny, 0);

        // Severity counts
        assert_eq!(report.summary.severities.info, 0);
        assert_eq!(report.summary.severities.warning, 0);
        assert_eq!(report.summary.severities.error, 0);
    }

    #[test]
    fn report_serializes_to_valid_json() {
        let report = build_report(
            vec![ScanFinding {
                file: "test.sh".to_string(),
                line: 42,
                col: Some(5),
                extractor_id: "shell.script".to_string(),
                extracted_command: "rm -rf /".to_string(),
                decision: ScanDecision::Deny,
                severity: ScanSeverity::Error,
                rule_id: Some("core.filesystem:rm-rf-root-home".to_string()),
                reason: Some("dangerous".to_string()),
                suggestion: Some("use safer rm".to_string()),
            }],
            1,
            0,
            1,
            false,
            Some(100),
        );

        let json = serde_json::to_string(&report).expect("should serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse");

        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["summary"]["files_scanned"], 1);
        assert_eq!(parsed["findings"][0]["file"], "test.sh");
        assert_eq!(parsed["findings"][0]["line"], 42);
        assert_eq!(parsed["findings"][0]["col"], 5);
        assert_eq!(parsed["findings"][0]["decision"], "deny");
        assert_eq!(parsed["findings"][0]["severity"], "error");
    }

    // ========================================================================
    // Summary calculation tests
    // ========================================================================

    #[test]
    fn summary_counts_decisions_correctly() {
        let findings = vec![
            make_finding("a", ScanDecision::Allow, ScanSeverity::Info),
            make_finding("b", ScanDecision::Allow, ScanSeverity::Info),
            make_finding("c", ScanDecision::Warn, ScanSeverity::Warning),
            make_finding("d", ScanDecision::Deny, ScanSeverity::Error),
            make_finding("e", ScanDecision::Deny, ScanSeverity::Error),
            make_finding("f", ScanDecision::Deny, ScanSeverity::Error),
        ];

        let report = build_report(findings, 6, 0, 6, false, None);

        assert_eq!(report.summary.decisions.allow, 2);
        assert_eq!(report.summary.decisions.warn, 1);
        assert_eq!(report.summary.decisions.deny, 3);
    }

    #[test]
    fn summary_counts_severities_correctly() {
        let findings = vec![
            make_finding("a", ScanDecision::Allow, ScanSeverity::Info),
            make_finding("b", ScanDecision::Warn, ScanSeverity::Warning),
            make_finding("c", ScanDecision::Warn, ScanSeverity::Warning),
            make_finding("d", ScanDecision::Deny, ScanSeverity::Error),
        ];

        let report = build_report(findings, 4, 0, 4, false, None);

        assert_eq!(report.summary.severities.info, 1);
        assert_eq!(report.summary.severities.warning, 2);
        assert_eq!(report.summary.severities.error, 1);
    }

    fn make_finding(file: &str, decision: ScanDecision, severity: ScanSeverity) -> ScanFinding {
        ScanFinding {
            file: file.to_string(),
            line: 1,
            col: None,
            extractor_id: "test".to_string(),
            extracted_command: "cmd".to_string(),
            decision,
            severity,
            rule_id: None,
            reason: None,
            suggestion: None,
        }
    }

    // ========================================================================
    // Redaction tests
    // ========================================================================

    #[test]
    fn redact_quoted_strings_handles_single_quotes() {
        let input = "echo 'secret password here'";
        let output = redact_quoted_strings(input);
        assert_eq!(output, "echo '…'");
    }

    #[test]
    fn redact_quoted_strings_handles_double_quotes() {
        let input = r#"echo "secret password here""#;
        let output = redact_quoted_strings(input);
        assert_eq!(output, r#"echo "…""#);
    }

    #[test]
    fn redact_quoted_strings_handles_escaped_quotes() {
        let input = r#"echo "hello \"world\" test""#;
        let output = redact_quoted_strings(input);
        assert_eq!(output, r#"echo "…""#);
    }

    #[test]
    fn redact_quoted_strings_handles_mixed_quotes() {
        let input = r#"cmd 'arg1' "arg2" 'arg3'"#;
        let output = redact_quoted_strings(input);
        assert_eq!(output, r#"cmd '…' "…" '…'"#);
    }

    #[test]
    fn redact_quoted_strings_preserves_unquoted() {
        let input = "git reset --hard HEAD";
        let output = redact_quoted_strings(input);
        assert_eq!(output, input);
    }

    #[test]
    fn redact_aggressively_redacts_sensitive_env_vars() {
        let input = "curl -H TOKEN=abc123secret";
        let output = redact_aggressively(input);
        assert!(output.contains("TOKEN=…"));
        assert!(!output.contains("abc123secret"));
    }

    #[test]
    fn redact_aggressively_redacts_long_hex_strings() {
        // Long hex strings are redacted when they appear as standalone tokens
        let input = "curl -H 0123456789abcdef0123456789abcdef";
        let output = redact_aggressively(input);
        // The 32+ char hex string should be redacted to "…"
        assert!(output.contains("…"));
        assert!(!output.contains("0123456789abcdef0123456789abcdef"));
    }

    #[test]
    fn redact_aggressively_preserves_normal_commands() {
        let input = "git status --short";
        let output = redact_aggressively(input);
        assert_eq!(output, input);
    }

    // ========================================================================
    // Truncation tests
    // ========================================================================

    #[test]
    fn truncate_utf8_handles_short_strings() {
        assert_eq!(truncate_utf8("hello", 10), "hello");
        assert_eq!(truncate_utf8("hello", 5), "hello");
        // With limit 6, we keep the full string (no truncation needed)
        assert_eq!(truncate_utf8("hello", 6), "hello");
    }

    #[test]
    fn truncate_utf8_truncates_long_strings() {
        assert_eq!(truncate_utf8("hello world", 6), "hello…");
        assert_eq!(truncate_utf8("abcdefghij", 5), "abcd…");
    }

    #[test]
    fn truncate_utf8_handles_edge_cases() {
        assert_eq!(truncate_utf8("hello", 1), "…");
        assert_eq!(truncate_utf8("hello", 0), "hello"); // 0 means no truncation
    }

    #[test]
    fn truncate_utf8_handles_unicode() {
        // Emoji are multi-byte but single chars
        let input = "🎉🎊🎈🎁";
        assert_eq!(truncate_utf8(input, 3), "🎉🎊…");
        assert_eq!(truncate_utf8(input, 5), input);
    }

    // ========================================================================
    // Fail-on policy tests
    // ========================================================================

    #[test]
    fn fail_on_none_never_fails() {
        assert!(!ScanFailOn::None.blocks(ScanSeverity::Info));
        assert!(!ScanFailOn::None.blocks(ScanSeverity::Warning));
        assert!(!ScanFailOn::None.blocks(ScanSeverity::Error));
    }

    #[test]
    fn fail_on_warning_blocks_warning_and_error() {
        assert!(!ScanFailOn::Warning.blocks(ScanSeverity::Info));
        assert!(ScanFailOn::Warning.blocks(ScanSeverity::Warning));
        assert!(ScanFailOn::Warning.blocks(ScanSeverity::Error));
    }

    #[test]
    fn fail_on_error_blocks_only_error() {
        assert!(!ScanFailOn::Error.blocks(ScanSeverity::Info));
        assert!(!ScanFailOn::Error.blocks(ScanSeverity::Warning));
        assert!(ScanFailOn::Error.blocks(ScanSeverity::Error));
    }

    #[test]
    fn should_fail_with_warning_only_findings() {
        let report = build_report(
            vec![make_finding("a", ScanDecision::Warn, ScanSeverity::Warning)],
            1,
            0,
            1,
            false,
            None,
        );

        assert!(!should_fail(&report, ScanFailOn::Error));
        assert!(should_fail(&report, ScanFailOn::Warning));
        assert!(!should_fail(&report, ScanFailOn::None));
    }

    #[test]
    fn should_fail_with_empty_report() {
        let report = build_report(vec![], 0, 0, 0, false, None);

        assert!(!should_fail(&report, ScanFailOn::Error));
        assert!(!should_fail(&report, ScanFailOn::Warning));
        assert!(!should_fail(&report, ScanFailOn::None));
    }

    // ========================================================================
    // Severity ranking tests
    // ========================================================================

    #[test]
    fn severity_rank_ordering() {
        assert!(ScanSeverity::Error.rank() > ScanSeverity::Warning.rank());
        assert!(ScanSeverity::Warning.rank() > ScanSeverity::Info.rank());
    }

    // ========================================================================
    // Safe command tests (must NOT block)
    // ========================================================================

    #[test]
    fn safe_commands_are_not_blocked() {
        let config = default_config();
        let ctx = ScanEvalContext::from_config(&config);
        let options = ScanOptions {
            format: ScanFormat::Pretty,
            fail_on: ScanFailOn::Error,
            max_file_size_bytes: 1024 * 1024,
            max_findings: 100,
            redact: ScanRedactMode::None,
            truncate: 0,
        };

        let safe_commands = [
            "git status",
            "git log --oneline",
            "ls -la",
            "echo hello",
            "cat file.txt",
            "grep pattern file",
            "rm file.txt", // single file rm without -rf is not blocked
        ];

        for cmd in safe_commands {
            let extracted = ExtractedCommand {
                file: "test.sh".to_string(),
                line: 1,
                col: None,
                extractor_id: "shell.script".to_string(),
                command: cmd.to_string(),
                metadata: None,
            };

            let finding = evaluate_extracted_command(&extracted, &options, &config, &ctx);
            assert!(
                finding.is_none(),
                "Command '{cmd}' should not be blocked but got: {finding:?}"
            );
        }
    }

    // ========================================================================
    // Dangerous command tests (MUST block)
    // ========================================================================

    #[test]
    fn dangerous_commands_are_blocked() {
        let config = default_config();
        let ctx = ScanEvalContext::from_config(&config);
        let options = ScanOptions {
            format: ScanFormat::Pretty,
            fail_on: ScanFailOn::Error,
            max_file_size_bytes: 1024 * 1024,
            max_findings: 100,
            redact: ScanRedactMode::None,
            truncate: 0,
        };

        let dangerous_commands = [
            ("git reset --hard", "core.git:reset-hard"),
            ("git push --force origin main", "core.git:push-force-long"),
            ("git clean -fd", "core.git:clean-force"),
            // Note: rm -rf /path matches rm-rf-root-home (starts with /)
            // Use a relative path to match rm-rf-general
            ("rm -rf ./some/path", "core.filesystem:rm-rf-general"),
        ];

        for (cmd, expected_rule) in dangerous_commands {
            let extracted = ExtractedCommand {
                file: "test.sh".to_string(),
                line: 1,
                col: None,
                extractor_id: "shell.script".to_string(),
                command: cmd.to_string(),
                metadata: None,
            };

            let finding = evaluate_extracted_command(&extracted, &options, &config, &ctx)
                .unwrap_or_else(|| panic!("Command '{cmd}' should be blocked"));
            assert_eq!(
                finding.decision,
                ScanDecision::Deny,
                "Command '{cmd}' should be denied"
            );
            assert_eq!(
                finding.rule_id.as_deref(),
                Some(expected_rule),
                "Command '{cmd}' should match rule {expected_rule}"
            );
        }
    }

    // ========================================================================
    // Suggestion integration tests
    // ========================================================================

    #[test]
    fn blocked_commands_include_suggestions_when_available() {
        let config = default_config();
        let ctx = ScanEvalContext::from_config(&config);
        let options = ScanOptions {
            format: ScanFormat::Pretty,
            fail_on: ScanFailOn::Error,
            max_file_size_bytes: 1024 * 1024,
            max_findings: 100,
            redact: ScanRedactMode::None,
            truncate: 0,
        };

        let extracted = ExtractedCommand {
            file: "test.sh".to_string(),
            line: 1,
            col: None,
            extractor_id: "shell.script".to_string(),
            command: "git reset --hard HEAD".to_string(),
            metadata: None,
        };

        let finding = evaluate_extracted_command(&extracted, &options, &config, &ctx)
            .expect("should be blocked");

        // core.git:reset-hard has SaferAlternative suggestion
        assert!(
            finding.suggestion.is_some(),
            "Finding should include suggestion"
        );
        assert!(
            finding.suggestion.as_ref().unwrap().contains("soft")
                || finding.suggestion.as_ref().unwrap().contains("mixed"),
            "Suggestion should mention safer alternatives"
        );
    }

    // ========================================================================
    // Shell extractor tests (git_safety_guard-scan.3.1)
    // ========================================================================

    #[test]
    fn shell_extractor_skips_comments() {
        let content = "# comment with git keyword\ngit status";
        let extracted = extract_shell_script_from_str("test.sh", content, &["git"]);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].command, "git status");
    }

    #[test]
    fn shell_extractor_skips_control_structures() {
        let content = "if [ -n \"$X\" ]; then\n  git status\nfi";
        let extracted = extract_shell_script_from_str("test.sh", content, &["git"]);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].command, "git status");
        assert_eq!(extracted[0].line, 2);
    }

    #[test]
    fn shell_extractor_skips_else_keyword() {
        let content = "if [ -n \"$X\" ]; then\n  git status\nelse\n  git diff\nfi";
        let extracted = extract_shell_script_from_str("test.sh", content, &["git"]);
        assert_eq!(extracted.len(), 2);
        assert_eq!(extracted[0].command, "git status");
        assert_eq!(extracted[0].line, 2);
        assert_eq!(extracted[1].command, "git diff");
        assert_eq!(extracted[1].line, 4);
    }

    #[test]
    fn shell_extractor_joins_line_continuations() {
        let content = "git log \\\n  --oneline";
        let extracted = extract_shell_script_from_str("test.sh", content, &["git"]);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].line, 1);
        assert_eq!(extracted[0].command, "git log --oneline");
    }

    #[test]
    fn shell_extractor_keyword_prefilter() {
        let content = "echo hello\ngit status";
        let extracted = extract_shell_script_from_str("test.sh", content, &["git"]);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].command, "git status");
    }

    // ========================================================================
    // Dockerfile extractor tests (git_safety_guard-scan.3.2)
    // ========================================================================

    #[test]
    fn dockerfile_extractor_extracts_run_shell_form() {
        let content = "FROM alpine\nRUN apt-get update";
        let extracted = extract_dockerfile_from_str("Dockerfile", content, &["apt"]);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].line, 2);
        assert_eq!(extracted[0].extractor_id, "dockerfile.run");
        assert_eq!(extracted[0].command, "apt-get update");
    }

    #[test]
    fn dockerfile_extractor_extracts_json_exec_form() {
        let content = "FROM alpine\nRUN [\"apt-get\", \"update\"]\nRUN apt-get install";
        let extracted = extract_dockerfile_from_str("Dockerfile", content, &["apt"]);
        assert_eq!(extracted.len(), 2);
        assert_eq!(extracted[0].command, "apt-get update");
        assert_eq!(extracted[1].command, "apt-get install");
    }

    #[test]
    fn dockerfile_extractor_handles_continuations() {
        let content = "FROM alpine\nRUN apt-get update \\\n    && apt-get install curl";
        let extracted = extract_dockerfile_from_str("Dockerfile", content, &["apt"]);
        assert_eq!(extracted.len(), 1);
        assert!(extracted[0].command.contains("apt-get update"));
        assert!(extracted[0].command.contains("apt-get install"));
    }

    #[test]
    fn dockerfile_extractor_ignores_non_run() {
        let content = "# apt comment\nFROM alpine\nLABEL apt=test\nRUN apt-get update";
        let extracted = extract_dockerfile_from_str("Dockerfile", content, &["apt"]);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].command, "apt-get update");
    }

    #[test]
    fn dockerfile_path_detection() {
        use std::path::Path;
        assert!(is_dockerfile_path(Path::new("Dockerfile")));
        assert!(is_dockerfile_path(Path::new("dockerfile")));
        assert!(is_dockerfile_path(Path::new("Dockerfile.dev")));
        assert!(is_dockerfile_path(Path::new("app.dockerfile")));
        assert!(!is_dockerfile_path(Path::new("Dockerfile-backup")));
        assert!(!is_dockerfile_path(Path::new("build.sh")));
    }

    #[test]
    fn shell_path_detection() {
        use std::path::Path;
        assert!(is_shell_script_path(Path::new("build.sh")));
        assert!(is_shell_script_path(Path::new("deploy.SH")));
        assert!(is_shell_script_path(Path::new("script.bash")));
        assert!(!is_shell_script_path(Path::new("Dockerfile")));
    }

    #[test]
    fn dockerfile_extractor_handles_tab_after_run() {
        // Tabs are valid whitespace between RUN and command
        let content = "FROM alpine\nRUN\tapt-get update";
        let extracted = extract_dockerfile_from_str("Dockerfile", content, &["apt"]);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].command, "apt-get update");
    }

    // ========================================================================
    // GitHub Actions extractor tests (git_safety_guard-scan.3.3)
    // ========================================================================

    #[test]
    fn github_actions_path_detection() {
        use std::path::Path;
        assert!(is_github_actions_workflow_path(Path::new(
            ".github/workflows/ci.yml"
        )));
        assert!(is_github_actions_workflow_path(Path::new(
            ".github/workflows/ci.yaml"
        )));
        assert!(is_github_actions_workflow_path(Path::new(
            ".github/workflows/sub/ci.yml"
        )));
        assert!(is_github_actions_workflow_path(Path::new(
            ".GITHUB/WORKFLOWS/CI.YML"
        )));
        assert!(!is_github_actions_workflow_path(Path::new(
            ".github/workflows/ci.json"
        )));
        assert!(!is_github_actions_workflow_path(Path::new(
            "workflows/ci.yml"
        )));
        assert!(!is_github_actions_workflow_path(Path::new(
            ".github/workflow/ci.yml"
        )));
    }

    #[test]
    fn github_actions_extractor_extracts_run_steps_only() {
        let content = r#"name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: "rm -rf /"
      - run: git status
      - run: rm -rf ./build
"#;

        let extracted = extract_github_actions_workflow_from_str(
            ".github/workflows/ci.yml",
            content,
            &["git", "rm"],
        );
        assert_eq!(extracted.len(), 2);
        assert_eq!(extracted[0].line, 8);
        assert_eq!(extracted[0].extractor_id, "github_actions.steps.run");
        assert_eq!(extracted[0].command, "git status");
        assert_eq!(extracted[1].line, 9);
        assert_eq!(extracted[1].extractor_id, "github_actions.steps.run");
        assert_eq!(extracted[1].command, "rm -rf ./build");
    }

    #[test]
    fn github_actions_extractor_handles_block_scalar_and_skips_comments() {
        // Note: list items can appear at the same indentation level as the `steps:` key.
        let content = r"jobs:
  test:
    steps:
    - run: |
        echo hello
        # rm -rf /
        rm -rf ./build
";

        let extracted =
            extract_github_actions_workflow_from_str(".github/workflows/ci.yml", content, &["rm"]);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].line, 7);
        assert_eq!(extracted[0].extractor_id, "github_actions.steps.run");
        assert_eq!(extracted[0].command, "rm -rf ./build");
    }

    #[test]
    fn github_actions_extractor_ignores_run_outside_steps() {
        let content = r"run: rm -rf /
jobs:
  test:
    steps:
      - run: echo hello
";

        let extracted =
            extract_github_actions_workflow_from_str(".github/workflows/ci.yml", content, &["rm"]);
        assert!(extracted.is_empty());
    }

    // ========================================================================
    // GitLab CI extractor tests (git_safety_guard-ehc)
    // ========================================================================

    #[test]
    fn gitlab_ci_path_detection() {
        use std::path::Path;
        assert!(is_gitlab_ci_path(Path::new(".gitlab-ci.yml")));
        assert!(is_gitlab_ci_path(Path::new("foo.gitlab-ci.yml")));
        assert!(is_gitlab_ci_path(Path::new("FOO.GITLAB-CI.YML")));
        assert!(!is_gitlab_ci_path(Path::new("gitlab-ci.yml")));
        assert!(!is_gitlab_ci_path(Path::new(".gitlab-ci.yaml")));
    }

    #[test]
    fn gitlab_ci_extractor_extracts_script_sections_only() {
        let content = r#"before_script:
  - echo "before"
build:
  script:
    - echo "build"
  after_script:
    - rm -rf ./build
variables:
  DANGEROUS: "rm -rf /"
"#;

        let extracted = extract_gitlab_ci_from_str(".gitlab-ci.yml", content, &["rm", "echo"]);
        assert_eq!(extracted.len(), 3);
        assert_eq!(extracted[0].line, 2);
        assert_eq!(extracted[0].extractor_id, "gitlab_ci.script");
        assert_eq!(extracted[0].command, "echo \"before\"");
        assert_eq!(extracted[1].line, 5);
        assert_eq!(extracted[1].command, "echo \"build\"");
        assert_eq!(extracted[2].line, 7);
        assert_eq!(extracted[2].command, "rm -rf ./build");
    }

    #[test]
    fn gitlab_ci_extractor_handles_anchor_alias() {
        let content = r#".common_script: &common_script
  - echo "one"
  - rm -rf ./build
deploy:
  script: *common_script
"#;

        let extracted = extract_gitlab_ci_from_str(".gitlab-ci.yml", content, &["rm", "echo"]);
        assert_eq!(extracted.len(), 2);
        assert_eq!(extracted[0].line, 2);
        assert_eq!(extracted[0].command, "echo \"one\"");
        assert_eq!(extracted[1].line, 3);
        assert_eq!(extracted[1].command, "rm -rf ./build");
    }

    // ========================================================================
    // Makefile extractor tests (git_safety_guard-scan.3.4)
    // ========================================================================

    #[test]
    fn makefile_path_detection() {
        use std::path::Path;
        assert!(is_makefile_path(Path::new("Makefile")));
        assert!(is_makefile_path(Path::new("makefile")));
        assert!(!is_makefile_path(Path::new("Makefile.backup")));
        assert!(!is_makefile_path(Path::new("build.mk")));
        assert!(!is_makefile_path(Path::new("build.sh")));
    }

    #[test]
    fn makefile_extractor_extracts_recipe_lines_only() {
        let content = "VAR = rm -rf /\n\
\n\
all:\n\
\tgit status\n\
\t# rm -rf /\n\
\trm -rf ./build\n";

        let extracted = extract_makefile_from_str("Makefile", content, &["git", "rm"]);
        assert_eq!(extracted.len(), 2);
        assert_eq!(extracted[0].line, 4);
        assert_eq!(extracted[0].extractor_id, "makefile.recipe");
        assert_eq!(extracted[0].command, "git status");
        assert_eq!(extracted[1].line, 6);
        assert_eq!(extracted[1].extractor_id, "makefile.recipe");
        assert_eq!(extracted[1].command, "rm -rf ./build");
    }

    #[test]
    fn makefile_extractor_handles_backslash_continuations() {
        // Makefile line continuations can be written without a leading tab on the continuation line.
        let content = "all:\n\
\tgit log \\\n\
  --oneline\n";

        let extracted = extract_makefile_from_str("Makefile", content, &["git"]);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].line, 2);
        assert_eq!(extracted[0].extractor_id, "makefile.recipe");
        assert_eq!(extracted[0].command, "git log --oneline");
    }

    // =========================================================================
    // package.json extractor tests
    // =========================================================================

    #[test]
    fn is_package_json_path_detects_correctly() {
        assert!(is_package_json_path(Path::new("package.json")));
        assert!(is_package_json_path(Path::new("/foo/bar/package.json")));
        assert!(is_package_json_path(Path::new("./package.json")));

        // Should NOT match
        assert!(!is_package_json_path(Path::new("package.json.bak")));
        assert!(!is_package_json_path(Path::new("package-lock.json")));
        assert!(!is_package_json_path(Path::new("my-package.json")));
        assert!(!is_package_json_path(Path::new("Package.json"))); // case-sensitive
    }

    #[test]
    fn package_json_extracts_scripts() {
        let content = r#"{
  "name": "test-package",
  "scripts": {
    "clean": "rm -rf dist",
    "build": "npm run compile"
  }
}"#;

        let extracted = extract_package_json_from_str("package.json", content, &["rm"]);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].command, "rm -rf dist");
        assert_eq!(extracted[0].extractor_id, "package_json.script");
        assert!(extracted[0].metadata.is_some());
    }

    #[test]
    fn package_json_extracts_multiple_matching_scripts() {
        let content = r#"{
  "scripts": {
    "clean": "rm -rf dist",
    "nuke": "rm -rf node_modules",
    "build": "tsc"
  }
}"#;

        let extracted = extract_package_json_from_str("package.json", content, &["rm"]);
        assert_eq!(extracted.len(), 2);
        assert!(extracted.iter().any(|e| e.command == "rm -rf dist"));
        assert!(extracted.iter().any(|e| e.command == "rm -rf node_modules"));
    }

    #[test]
    fn package_json_ignores_non_script_fields() {
        let content = r#"{
  "name": "test-package",
  "description": "Uses rm -rf for cleanup",
  "keywords": ["rm", "cleanup"],
  "scripts": {
    "build": "npm run compile"
  },
  "config": {
    "danger": "rm -rf /"
  }
}"#;

        let extracted = extract_package_json_from_str("package.json", content, &["rm"]);
        // Should NOT extract from description, keywords, or config
        assert!(extracted.is_empty());
    }

    #[test]
    fn package_json_handles_empty_scripts() {
        let content = r#"{
  "name": "test-package",
  "scripts": {}
}"#;

        let extracted = extract_package_json_from_str("package.json", content, &["rm"]);
        assert!(extracted.is_empty());
    }

    #[test]
    fn package_json_handles_missing_scripts() {
        let content = r#"{
  "name": "test-package"
}"#;

        let extracted = extract_package_json_from_str("package.json", content, &["rm"]);
        assert!(extracted.is_empty());
    }

    #[test]
    fn package_json_handles_invalid_json() {
        let content = "{ this is not valid json }";

        let extracted = extract_package_json_from_str("package.json", content, &["rm"]);
        assert!(extracted.is_empty());
    }

    #[test]
    fn package_json_extracts_lifecycle_scripts() {
        let content = r#"{
  "scripts": {
    "preinstall": "rm -rf old-cache",
    "postinstall": "echo done",
    "build": "tsc"
  }
}"#;

        let extracted = extract_package_json_from_str("package.json", content, &["rm"]);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].command, "rm -rf old-cache");
    }

    #[test]
    fn package_json_line_numbers_are_accurate() {
        let content = r#"{
  "name": "test",
  "scripts": {
    "clean": "rm -rf dist"
  }
}"#;

        let extracted = extract_package_json_from_str("package.json", content, &["rm"]);
        assert_eq!(extracted.len(), 1);
        // "clean" appears on line 4
        assert_eq!(extracted[0].line, 4);
    }

    #[test]
    fn package_json_line_numbers_disambiguation() {
        let content = r#"{
  "dependencies": {
    "clean": "1.0.0"
  },
  "scripts": {
    "clean": "rm -rf dist"
  }
}"#;

        let extracted = extract_package_json_from_str("package.json", content, &["rm"]);
        assert_eq!(extracted.len(), 1);
        // "clean" script is on line 6. "clean" dependency is on line 3.
        assert_eq!(extracted[0].line, 6);
    }

    // =========================================================================
    // Terraform extractor tests (git_safety_guard-p9e)
    // =========================================================================

    #[test]
    fn terraform_path_detection() {
        use std::path::Path;
        assert!(is_terraform_path(Path::new("main.tf")));
        assert!(is_terraform_path(Path::new("outputs.tf")));
        assert!(is_terraform_path(Path::new("path/to/resource.TF")));
        assert!(!is_terraform_path(Path::new("main.tf.bak")));
        assert!(!is_terraform_path(Path::new("terraform.tfstate")));
        assert!(!is_terraform_path(Path::new("README.md")));
    }

    #[test]
    fn terraform_local_exec_simple_command() {
        let content = r#"
resource "null_resource" "cleanup" {
  provisioner "local-exec" {
    command = "rm -rf /tmp/*"
  }
}
"#;
        let extracted = extract_terraform_from_str("main.tf", content, &["rm"]);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].command, "rm -rf /tmp/*");
        assert_eq!(
            extracted[0].extractor_id,
            "terraform.provisioner.local_exec"
        );
    }

    #[test]
    fn terraform_remote_exec_inline_array() {
        let content = r#"
resource "aws_instance" "web" {
  provisioner "remote-exec" {
    inline = [
      "echo hello",
      "rm -rf /tmp/*",
      "echo done"
    ]
  }
}
"#;
        let extracted = extract_terraform_from_str("main.tf", content, &["rm", "echo"]);
        assert_eq!(extracted.len(), 3);
        assert!(extracted.iter().any(|c| c.command == "rm -rf /tmp/*"));
        assert!(extracted.iter().any(|c| c.command == "echo hello"));
        assert!(extracted.iter().any(|c| c.command == "echo done"));
        assert!(
            extracted
                .iter()
                .all(|c| c.extractor_id == "terraform.provisioner.remote_exec")
        );
    }

    #[test]
    fn terraform_ignores_non_provisioner_blocks() {
        // Dangerous strings in variable defaults should NOT be extracted
        let content = r#"
variable "dangerous" {
  default = "rm -rf /"
}

output "msg" {
  value = "rm -rf everything"
}
"#;
        let extracted = extract_terraform_from_str("variables.tf", content, &["rm"]);
        assert!(
            extracted.is_empty(),
            "Should not extract from variable/output blocks"
        );
    }

    #[test]
    fn terraform_inline_single_line_array() {
        let content = r#"
resource "null_resource" "test" {
  provisioner "remote-exec" {
    inline = ["rm -rf /tmp", "echo done"]
  }
}
"#;
        let extracted = extract_terraform_from_str("main.tf", content, &["rm", "echo"]);
        assert_eq!(extracted.len(), 2);
    }

    #[test]
    fn terraform_ignores_comments() {
        let content = r#"
# This is a comment with rm -rf /
// This is also a comment with rm -rf
resource "null_resource" "test" {
  # provisioner "local-exec" { command = "rm -rf" }
  provisioner "local-exec" {
    command = "rm -rf /actual"
  }
}
"#;
        let extracted = extract_terraform_from_str("main.tf", content, &["rm"]);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].command, "rm -rf /actual");
    }

    // =========================================================================
    // docker-compose extractor tests
    // =========================================================================

    #[test]
    fn is_docker_compose_path_detects_correctly() {
        // Should match
        assert!(is_docker_compose_path(Path::new("docker-compose.yml")));
        assert!(is_docker_compose_path(Path::new("docker-compose.yaml")));
        assert!(is_docker_compose_path(Path::new("compose.yml")));
        assert!(is_docker_compose_path(Path::new("compose.yaml")));
        assert!(is_docker_compose_path(Path::new(
            "/foo/bar/docker-compose.yml"
        )));
        // Case insensitive
        assert!(is_docker_compose_path(Path::new("Docker-Compose.YML")));
        assert!(is_docker_compose_path(Path::new("COMPOSE.YAML")));

        // Should NOT match
        assert!(!is_docker_compose_path(Path::new("docker-compose.json")));
        assert!(!is_docker_compose_path(Path::new("my-docker-compose.yml")));
        assert!(!is_docker_compose_path(Path::new("compose.yml.bak")));
    }

    #[test]
    fn docker_compose_extracts_inline_command() {
        let content = r"
services:
  app:
    image: alpine
    command: rm -rf /data
";
        let extracted = extract_docker_compose_from_str("docker-compose.yml", content, &["rm"]);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].command, "rm -rf /data");
        assert_eq!(extracted[0].extractor_id, "docker_compose.command");
    }

    #[test]
    fn docker_compose_extracts_entrypoint() {
        let content = r#"
services:
  app:
    entrypoint: /bin/sh -c "rm -rf /tmp/*"
"#;
        let extracted = extract_docker_compose_from_str("docker-compose.yml", content, &["rm"]);
        assert_eq!(extracted.len(), 1);
        assert!(extracted[0].command.contains("rm -rf"));
    }

    #[test]
    fn docker_compose_extracts_array_command() {
        let content = r#"
services:
  app:
    command: ["sh", "-c", "rm -rf /cache"]
"#;
        let extracted = extract_docker_compose_from_str("docker-compose.yml", content, &["rm"]);
        assert_eq!(extracted.len(), 1);
        assert!(extracted[0].command.contains("rm"));
    }

    #[test]
    fn docker_compose_ignores_environment() {
        let content = r#"
services:
  app:
    environment:
      CLEANUP: "rm -rf /"
      DANGER: "kubectl delete"
    command: echo safe
"#;
        let extracted =
            extract_docker_compose_from_str("docker-compose.yml", content, &["rm", "kubectl"]);
        // Should NOT extract from environment
        assert!(extracted.is_empty());
    }

    #[test]
    fn docker_compose_ignores_labels() {
        let content = r#"
services:
  app:
    labels:
      description: "Uses rm -rf for cleanup"
    command: echo hello
"#;
        let extracted = extract_docker_compose_from_str("docker-compose.yml", content, &["rm"]);
        assert!(extracted.is_empty());
    }

    #[test]
    fn docker_compose_extracts_healthcheck_test() {
        let content = r"
services:
  db:
    healthcheck:
      test: rm -rf /health/check
      interval: 30s
";
        let extracted = extract_docker_compose_from_str("docker-compose.yml", content, &["rm"]);
        assert_eq!(extracted.len(), 1);
        assert!(extracted[0].command.contains("rm -rf"));
    }

    #[test]
    fn docker_compose_handles_empty_file() {
        let content = "";
        let extracted = extract_docker_compose_from_str("docker-compose.yml", content, &["rm"]);
        assert!(extracted.is_empty());
    }

    #[test]
    fn docker_compose_handles_no_services() {
        let content = r#"
version: "3"
networks:
  default:
"#;
        let extracted = extract_docker_compose_from_str("docker-compose.yml", content, &["rm"]);
        assert!(extracted.is_empty());
    }
}
