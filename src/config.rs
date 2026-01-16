//! Configuration system for dcg.
//!
//! Supports layered configuration from multiple sources:
//! 1. Environment variables (highest priority)
//! 2. Project config (.dcg.toml in repo root)
//! 3. User config (~/.config/dcg/config.toml)
//! 4. System config (/etc/dcg/config.toml)
//! 5. Compiled defaults (lowest priority)

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Environment variable prefix for all config options.
const ENV_PREFIX: &str = "DCG";

/// Default config file name.
const CONFIG_FILE_NAME: &str = "config.toml";

/// Project-level config file name.
const PROJECT_CONFIG_NAME: &str = ".dcg.toml";

/// Env var for selecting an explicit config file path.
///
/// This is intentionally separate from per-setting env overrides (packs, verbose,
/// heredoc settings, etc.). It changes *which file* is loaded as a config layer.
pub(crate) const ENV_CONFIG_PATH: &str = "DCG_CONFIG";

/// Maximum parent directories to traverse when searching for a repo root.
///
/// This bounds filesystem work in deeply nested directories.
pub(crate) const REPO_ROOT_SEARCH_MAX_HOPS: usize = 50;

/// Main configuration structure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// General settings.
    pub general: GeneralConfig,

    /// Output display settings.
    pub output: OutputConfig,

    /// Pack configuration.
    pub packs: PacksConfig,

    /// Decision mode policy configuration.
    pub policy: PolicyConfig,

    /// Custom overrides.
    pub overrides: OverridesConfig,

    /// Heredoc/inline-script scanning configuration.
    pub heredoc: HeredocConfig,

    /// Confidence scoring configuration for ambiguous matches.
    pub confidence: ConfidenceConfig,

    /// Structured logging configuration.
    pub logging: crate::logging::LoggingConfig,

    /// Command history configuration.
    pub history: HistoryConfig,

    /// Project-specific configurations (keyed by absolute path).
    #[serde(default)]
    pub projects: std::collections::HashMap<String, ProjectConfig>,
}

// -----------------------------------------------------------------------------
// Config file layering (presence-aware)
// -----------------------------------------------------------------------------
//
// The public `Config` structs use `#[serde(default)]` to provide ergonomic
// defaults when loading a *single* config file.
//
// For layered config precedence (system → user → project → env), we must also
// preserve whether a field was present in TOML. Otherwise we lose information
// about "explicitly set to default" vs "not set at all", which breaks the
// "higher precedence wins" mental model (e.g. you could not set
// `general.verbose=false` if a lower layer set it to true).
//
// To fix this, file configs are parsed into a partial/layer representation where
// scalar fields are `Option<T>` and we only apply fields that are `Some(...)`.

#[derive(Debug, Clone, Default, Deserialize)]
struct ConfigLayer {
    general: Option<GeneralConfigLayer>,
    output: Option<OutputConfigLayer>,
    packs: Option<PacksConfig>,
    policy: Option<PolicyConfig>,
    overrides: Option<OverridesConfig>,
    heredoc: Option<HeredocConfig>,
    confidence: Option<ConfidenceConfigLayer>,
    logging: Option<LoggingConfigLayer>,
    history: Option<HistoryConfigLayer>,
    projects: Option<std::collections::HashMap<String, ProjectConfig>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct GeneralConfigLayer {
    color: Option<String>,
    log_file: Option<String>,
    verbose: Option<bool>,
    max_hook_input_bytes: Option<usize>,
    max_command_bytes: Option<usize>,
    max_findings_per_command: Option<usize>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
struct OutputConfigLayer {
    highlight_enabled: Option<bool>,
    explanations_enabled: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct LoggingConfigLayer {
    enabled: Option<bool>,
    file: Option<String>,
    format: Option<crate::logging::LogFormat>,
    redaction: Option<RedactionConfigLayer>,
    events: Option<LogEventFilterLayer>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct HistoryConfigLayer {
    enabled: Option<bool>,
    redaction_mode: Option<HistoryRedactionMode>,
    retention_days: Option<u32>,
    max_size_mb: Option<u32>,
    database_path: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct RedactionConfigLayer {
    enabled: Option<bool>,
    mode: Option<crate::logging::RedactionMode>,
    max_argument_len: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct LogEventFilterLayer {
    deny: Option<bool>,
    warn: Option<bool>,
    allow: Option<bool>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
struct ConfidenceConfigLayer {
    enabled: Option<bool>,
    warn_threshold: Option<f32>,
    protect_critical: Option<bool>,
}

fn expand_tilde_path(value: &str) -> (PathBuf, bool) {
    if value == "~" {
        if let Some(home) = dirs::home_dir() {
            return (home, true);
        }
        return (PathBuf::from(value), false);
    }

    let Some(rest) = value
        .strip_prefix("~/")
        .or_else(|| value.strip_prefix("~\\"))
    else {
        return (PathBuf::from(value), false);
    };
    let Some(home) = dirs::home_dir() else {
        return (PathBuf::from(value), false);
    };
    (home.join(rest), true)
}

/// Resolve a config path value, expanding `~` and resolving relative paths.
///
/// Returns None when the value is empty/whitespace.
pub(crate) fn resolve_config_path_value(value: &str, cwd: Option<&Path>) -> Option<PathBuf> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let had_tilde_prefix = trimmed.starts_with('~');
    let (mut path, _tilde_expanded) = expand_tilde_path(trimmed);
    if !had_tilde_prefix && path.is_relative() {
        if let Some(cwd) = cwd {
            path = cwd.join(path);
        }
    }
    Some(path)
}

/// Find the git repo root by searching for a `.git` directory upwards from `start_dir`.
///
/// This search is bounded by `max_hops` to avoid unbounded filesystem traversal in
/// very deep directory trees.
pub(crate) fn find_repo_root(start_dir: &Path, max_hops: usize) -> Option<PathBuf> {
    let mut current = start_dir.to_path_buf();
    for _ in 0..=max_hops {
        if current.join(".git").exists() {
            return Some(current);
        }
        if !current.pop() {
            break;
        }
    }
    None
}

/// Heredoc and inline-script scanning configuration.
///
/// This configuration controls Tier 1/2/3 heredoc scanning behavior. Because the
/// hook is performance- and UX-sensitive, defaults are conservative and fail-open
/// on extraction/parse errors.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HeredocConfig {
    /// Enable heredoc/inline-script scanning.
    pub enabled: Option<bool>,

    /// Timeout budget for Tier 2 extraction (milliseconds).
    pub timeout_ms: Option<u64>,

    /// Maximum bytes extracted from heredoc bodies.
    pub max_body_bytes: Option<usize>,

    /// Maximum number of lines extracted from heredoc bodies.
    pub max_body_lines: Option<usize>,

    /// Maximum number of heredocs to process per command.
    pub max_heredocs: Option<usize>,

    /// Optional allowlist of languages to scan.
    ///
    /// Values are case-insensitive and may include aliases:
    /// - bash: bash, sh, shell
    /// - python: python, py
    /// - ruby: ruby, rb
    /// - perl: perl, pl
    /// - javascript: javascript, js, node
    /// - typescript: typescript, ts
    /// - php: php
    /// - go: go, golang
    /// - unknown: unknown
    ///
    /// Special value "all" scans all languages (the default if omitted).
    pub languages: Option<Vec<String>>,

    /// Fail-open when AST parsing fails for embedded code.
    pub fallback_on_parse_error: Option<bool>,

    /// Fail-open when extraction/parsing exceeds the timeout budget.
    pub fallback_on_timeout: Option<bool>,

    /// Content-based allowlist for heredocs (patterns, hashes, commands).
    pub allowlist: Option<HeredocAllowlistConfig>,
}

/// Effective heredoc scanning settings used by the evaluator.
#[derive(Debug, Clone)]
pub struct HeredocSettings {
    pub enabled: bool,
    pub limits: crate::heredoc::ExtractionLimits,
    pub allowed_languages: Option<Vec<crate::heredoc::ScriptLanguage>>,
    pub fallback_on_parse_error: bool,
    pub fallback_on_timeout: bool,
    /// Content-based allowlist for heredocs (patterns, hashes, commands).
    pub content_allowlist: Option<HeredocAllowlistConfig>,
}

impl Default for HeredocSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            limits: crate::heredoc::ExtractionLimits::default(),
            allowed_languages: None,
            fallback_on_parse_error: true,
            fallback_on_timeout: true,
            content_allowlist: None,
        }
    }
}

/// Heredoc content allowlist for known-safe patterns and content hashes.
///
/// Supports multiple allowlisting mechanisms:
/// - Command prefixes: allow all heredocs in commands starting with specific paths
/// - Pattern matching: allow heredocs containing specific patterns (optionally filtered by language)
/// - Content hashes: allow heredocs with specific content hashes (for known-good scripts)
/// - Project scopes: additional allowances for specific project directories
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HeredocAllowlistConfig {
    /// Command prefixes to allowlist entirely (e.g., "./scripts/approved.sh").
    #[serde(default)]
    pub commands: Vec<String>,

    /// Content patterns to allowlist.
    #[serde(default)]
    pub patterns: Vec<AllowedHeredocPattern>,

    /// Content hashes to allowlist (hash of exact heredoc content).
    #[serde(default)]
    pub content_hashes: Vec<ContentHashEntry>,

    /// Project-specific allowlist overrides.
    #[serde(default)]
    pub projects: Vec<ProjectHeredocAllowlist>,
}

/// A pattern-based heredoc allowlist entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AllowedHeredocPattern {
    /// Optional language filter (e.g., "python", "bash"). If None, matches any language.
    pub language: Option<String>,
    /// Substring pattern to match in heredoc content.
    pub pattern: String,
    /// Human-readable reason for allowlisting.
    pub reason: String,
}

/// A content-hash based heredoc allowlist entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentHashEntry {
    /// Hash of the exact heredoc content.
    ///
    /// This is a stable, deterministic SHA-256 hash (lowercase hex).
    pub hash: String,
    /// Human-readable reason for allowlisting.
    pub reason: String,
}

/// Project-specific heredoc allowlist overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectHeredocAllowlist {
    /// Absolute path prefix for the project.
    pub path: String,
    /// Additional patterns for this project.
    #[serde(default)]
    pub patterns: Vec<AllowedHeredocPattern>,
    /// Additional content hashes for this project.
    #[serde(default)]
    pub content_hashes: Vec<ContentHashEntry>,
}

/// Result of a heredoc allowlist match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeredocAllowlistHit<'a> {
    /// The type of allowlist entry that matched.
    pub kind: HeredocAllowlistHitKind,
    /// The reason provided in the allowlist entry.
    pub reason: &'a str,
    /// The matched pattern, hash, or command.
    pub matched: &'a str,
}

/// The type of heredoc allowlist match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeredocAllowlistHitKind {
    /// Matched a content hash.
    ContentHash,
    /// Matched a pattern.
    Pattern,
    /// Matched a project-specific content hash.
    ProjectContentHash,
    /// Matched a project-specific pattern.
    ProjectPattern,
}

/// Confidence scoring configuration for ambiguous pattern matches.
///
/// When enabled, confidence scoring analyzes the context of pattern matches
/// to determine if they're likely true positives or false positives. Matches
/// in data contexts (quoted strings, commit messages, search patterns) have
/// lower confidence and may be downgraded from Deny to Warn.
///
/// # Example Configuration (TOML)
///
/// ```toml
/// [confidence]
/// enabled = true
/// warn_threshold = 0.5
/// protect_critical = true
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ConfidenceConfig {
    /// Enable confidence scoring for pattern matches.
    ///
    /// When enabled, the evaluator computes a confidence score for each match
    /// based on execution context (is the match in executed code or data?).
    /// Low-confidence matches may be downgraded from Deny to Warn.
    ///
    /// Default: false (disabled for backwards compatibility)
    pub enabled: bool,

    /// Confidence threshold below which Deny is downgraded to Warn.
    ///
    /// Values range from 0.0 (always warn) to 1.0 (never warn).
    /// Recommended range: 0.3 - 0.7
    ///
    /// Default: 0.5
    pub warn_threshold: f32,

    /// Protect Critical severity patterns from confidence downgrading.
    ///
    /// When true, Critical severity matches always Deny regardless of
    /// confidence score. This prevents catastrophic commands like `rm -rf /`
    /// from being downgraded even if they appear in data context.
    ///
    /// Default: true
    pub protect_critical: bool,
}

impl Default for ConfidenceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            warn_threshold: crate::confidence::DEFAULT_WARN_THRESHOLD,
            protect_critical: true,
        }
    }
}

impl HeredocConfig {
    #[must_use]
    pub fn settings(&self) -> HeredocSettings {
        let mut limits = crate::heredoc::ExtractionLimits::default();
        if let Some(timeout_ms) = self.timeout_ms {
            limits.timeout_ms = timeout_ms;
        }
        if let Some(max_body_bytes) = self.max_body_bytes {
            limits.max_body_bytes = max_body_bytes;
        }
        if let Some(max_body_lines) = self.max_body_lines {
            limits.max_body_lines = max_body_lines;
        }
        if let Some(max_heredocs) = self.max_heredocs {
            limits.max_heredocs = max_heredocs;
        }

        let allowed_languages = self.languages.as_ref().and_then(|langs| {
            let mut parsed: Vec<crate::heredoc::ScriptLanguage> = Vec::new();
            for raw in langs {
                let raw = raw.trim();
                if raw.is_empty() {
                    continue;
                }

                if raw.eq_ignore_ascii_case("all") {
                    return None;
                }

                let lang = match raw.to_ascii_lowercase().as_str() {
                    "bash" | "sh" | "shell" => Some(crate::heredoc::ScriptLanguage::Bash),
                    "python" | "py" => Some(crate::heredoc::ScriptLanguage::Python),
                    "ruby" | "rb" => Some(crate::heredoc::ScriptLanguage::Ruby),
                    "perl" | "pl" => Some(crate::heredoc::ScriptLanguage::Perl),
                    "javascript" | "js" | "node" => {
                        Some(crate::heredoc::ScriptLanguage::JavaScript)
                    }
                    "typescript" | "ts" => Some(crate::heredoc::ScriptLanguage::TypeScript),
                    "php" => Some(crate::heredoc::ScriptLanguage::Php),
                    "go" | "golang" => Some(crate::heredoc::ScriptLanguage::Go),
                    "unknown" => Some(crate::heredoc::ScriptLanguage::Unknown),
                    _ => None,
                };

                if let Some(lang) = lang {
                    if !parsed.contains(&lang) {
                        parsed.push(lang);
                    }
                }
            }

            if parsed.is_empty() {
                // Avoid accidental full-disable due to typos: treat as "all".
                None
            } else {
                Some(parsed)
            }
        });

        HeredocSettings {
            enabled: self.enabled.unwrap_or(true),
            limits,
            allowed_languages,
            fallback_on_parse_error: self.fallback_on_parse_error.unwrap_or(true),
            fallback_on_timeout: self.fallback_on_timeout.unwrap_or(true),
            content_allowlist: self.allowlist.clone(),
        }
    }
}

impl HeredocAllowlistConfig {
    /// Check if a command is allowlisted by its prefix.
    #[must_use]
    pub fn is_command_allowlisted(&self, command: &str) -> Option<&str> {
        for cmd in &self.commands {
            // Skip empty prefixes to prevent accidental allow-all
            if cmd.is_empty() {
                continue;
            }
            if command.starts_with(cmd.as_str()) {
                return Some(cmd.as_str());
            }
        }
        None
    }

    /// Check if heredoc content is allowlisted.
    ///
    /// Checks in order: content hashes, patterns, then project-specific entries.
    #[must_use]
    pub fn is_content_allowlisted(
        &self,
        content: &str,
        language: crate::heredoc::ScriptLanguage,
        project_path: Option<&std::path::Path>,
    ) -> Option<HeredocAllowlistHit<'_>> {
        // Check global content hashes first
        let mut hash: Option<String> = None;
        for entry in &self.content_hashes {
            let computed = hash.get_or_insert_with(|| content_hash(content));
            if entry.hash == *computed {
                return Some(HeredocAllowlistHit {
                    kind: HeredocAllowlistHitKind::ContentHash,
                    reason: &entry.reason,
                    matched: &entry.hash,
                });
            }
        }

        // Check global patterns
        for pattern in &self.patterns {
            if pattern_matches(pattern, content, language) {
                return Some(HeredocAllowlistHit {
                    kind: HeredocAllowlistHitKind::Pattern,
                    reason: &pattern.reason,
                    matched: &pattern.pattern,
                });
            }
        }

        // Check project-specific entries
        if let Some(path) = project_path {
            for project in &self.projects {
                // Skip empty project paths to prevent accidental allow-all
                if project.path.is_empty() {
                    continue;
                }
                // Match by path components to avoid false positives
                // e.g., "/home/user/project" should NOT match "/home/user/project-other".
                if path.starts_with(std::path::Path::new(&project.path)) {
                    // Check project content hashes
                    for entry in &project.content_hashes {
                        let computed = hash.get_or_insert_with(|| content_hash(content));
                        if entry.hash == *computed {
                            return Some(HeredocAllowlistHit {
                                kind: HeredocAllowlistHitKind::ProjectContentHash,
                                reason: &entry.reason,
                                matched: &entry.hash,
                            });
                        }
                    }

                    // Check project patterns
                    for pattern in &project.patterns {
                        if pattern_matches(pattern, content, language) {
                            return Some(HeredocAllowlistHit {
                                kind: HeredocAllowlistHitKind::ProjectPattern,
                                reason: &pattern.reason,
                                matched: &pattern.pattern,
                            });
                        }
                    }
                }
            }
        }

        None
    }

    /// Merge another allowlist config into this one (other takes precedence for additions).
    pub fn merge(&mut self, other: &Self) {
        // Merge commands (deduplicate)
        for cmd in &other.commands {
            if !self.commands.contains(cmd) {
                self.commands.push(cmd.clone());
            }
        }

        // Merge patterns (deduplicate by pattern string)
        for pattern in &other.patterns {
            if !self.patterns.iter().any(|p| p.pattern == pattern.pattern) {
                self.patterns.push(pattern.clone());
            }
        }

        // Merge content hashes (deduplicate by hash)
        for entry in &other.content_hashes {
            if !self.content_hashes.iter().any(|e| e.hash == entry.hash) {
                self.content_hashes.push(entry.clone());
            }
        }

        // Merge project overrides (merge by path)
        for project in &other.projects {
            if let Some(existing) = self.projects.iter_mut().find(|p| p.path == project.path) {
                // Merge patterns into existing project
                for pattern in &project.patterns {
                    if !existing
                        .patterns
                        .iter()
                        .any(|p| p.pattern == pattern.pattern)
                    {
                        existing.patterns.push(pattern.clone());
                    }
                }
                // Merge hashes into existing project
                for entry in &project.content_hashes {
                    if !existing.content_hashes.iter().any(|e| e.hash == entry.hash) {
                        existing.content_hashes.push(entry.clone());
                    }
                }
            } else {
                self.projects.push(project.clone());
            }
        }
    }
}

impl HeredocAllowlistHitKind {
    /// Human-readable label for the hit kind.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::ContentHash => "content_hash",
            Self::Pattern => "pattern",
            Self::ProjectContentHash => "project_content_hash",
            Self::ProjectPattern => "project_pattern",
        }
    }
}

/// Check if a pattern matches the content for the given language.
fn pattern_matches(
    pattern: &AllowedHeredocPattern,
    content: &str,
    language: crate::heredoc::ScriptLanguage,
) -> bool {
    // Empty patterns are invalid and should never match (prevents accidental allow-all)
    if pattern.pattern.is_empty() {
        return false;
    }
    // Check language filter
    if let Some(lang_filter) = &pattern.language {
        if !language_filter_matches(lang_filter, language) {
            return false;
        }
    }
    // Check content contains pattern
    content.contains(&pattern.pattern)
}

/// Check if a language filter string matches the given language.
/// Supports both full names (e.g., "javascript") and common aliases (e.g., "js").
/// An empty or whitespace-only filter matches all languages (same as `language: None`).
fn language_filter_matches(filter: &str, language: crate::heredoc::ScriptLanguage) -> bool {
    use crate::heredoc::ScriptLanguage::{
        Bash, Go, JavaScript, Perl, Php, Python, Ruby, TypeScript, Unknown,
    };
    let filter_lower = filter.trim().to_ascii_lowercase();

    // Empty filter matches all languages (consistent with `language: None`)
    if filter_lower.is_empty() {
        return true;
    }

    match language {
        Bash => matches!(filter_lower.as_str(), "bash" | "sh" | "shell"),
        Python => matches!(filter_lower.as_str(), "python" | "py"),
        Ruby => matches!(filter_lower.as_str(), "ruby" | "rb"),
        Perl => matches!(filter_lower.as_str(), "perl" | "pl"),
        JavaScript => matches!(filter_lower.as_str(), "javascript" | "js" | "node"),
        TypeScript => matches!(filter_lower.as_str(), "typescript" | "ts"),
        Php => matches!(filter_lower.as_str(), "php"),
        Go => matches!(filter_lower.as_str(), "go" | "golang"),
        Unknown => filter_lower == "unknown",
    }
}

/// Compute a stable content hash for heredoc allowlisting.
///
/// This uses SHA-256 and returns lowercase hex. Allowlisting still requires
/// explicit user configuration; the hash is for stable identification, not as a
/// security boundary.
///
/// # Returns
///
/// A 64-character hex string representing the 256-bit hash.
fn content_hash(content: &str) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(content.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

/// General configuration options.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    /// Color output mode: "auto", "always", "never".
    pub color: String,

    /// Path to log file for blocked commands (optional).
    pub log_file: Option<String>,

    /// Whether to show verbose output.
    pub verbose: bool,

    /// Maximum bytes to read from stdin in hook mode.
    /// Commands exceeding this limit are allowed (fail-open) with a warning.
    /// Default: 262144 (256 KiB).
    pub max_hook_input_bytes: Option<usize>,

    /// Maximum bytes for command string after extraction from JSON.
    /// Commands exceeding this limit are allowed (fail-open) with a warning.
    /// Default: 65536 (64 KiB).
    pub max_command_bytes: Option<usize>,

    /// Maximum findings to report per command.
    /// Limits output size and processing time for pathological inputs.
    /// Default: 100.
    pub max_findings_per_command: Option<usize>,
}

/// Default limits for input size (used when not configured).
pub const DEFAULT_MAX_HOOK_INPUT_BYTES: usize = 256 * 1024; // 256 KiB
pub const DEFAULT_MAX_COMMAND_BYTES: usize = 64 * 1024; // 64 KiB
pub const DEFAULT_MAX_FINDINGS_PER_COMMAND: usize = 100;

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            color: "auto".to_string(),
            log_file: None,
            verbose: false,
            max_hook_input_bytes: None,
            max_command_bytes: None,
            max_findings_per_command: None,
        }
    }
}

impl GeneralConfig {
    /// Get max hook input bytes (with default fallback).
    #[must_use]
    pub fn max_hook_input_bytes(&self) -> usize {
        self.max_hook_input_bytes
            .unwrap_or(DEFAULT_MAX_HOOK_INPUT_BYTES)
    }

    /// Get max command bytes (with default fallback).
    #[must_use]
    pub fn max_command_bytes(&self) -> usize {
        self.max_command_bytes.unwrap_or(DEFAULT_MAX_COMMAND_BYTES)
    }

    /// Get max findings per command (with default fallback).
    #[must_use]
    pub fn max_findings_per_command(&self) -> usize {
        self.max_findings_per_command
            .unwrap_or(DEFAULT_MAX_FINDINGS_PER_COMMAND)
    }
}

/// Output display configuration.
///
/// Controls optional output enhancements like span highlighting and explanations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OutputConfig {
    /// Enable span highlighting in denial output.
    /// When enabled, shows caret-style markers under the matched portion.
    /// Default: true
    pub highlight_enabled: Option<bool>,

    /// Enable explanations in denial output.
    /// When enabled, shows detailed explanations for why patterns are dangerous.
    /// Default: true
    pub explanations_enabled: Option<bool>,
}

impl OutputConfig {
    /// Check if span highlighting is enabled (default: true).
    #[must_use]
    pub fn highlight_enabled(&self) -> bool {
        self.highlight_enabled.unwrap_or(true)
    }

    /// Check if explanations are enabled (default: true).
    #[must_use]
    pub fn explanations_enabled(&self) -> bool {
        self.explanations_enabled.unwrap_or(true)
    }
}

/// Pack enablement configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PacksConfig {
    /// List of enabled packs (e.g., `["database.postgresql", "kubernetes"]`).
    pub enabled: Vec<String>,

    /// List of explicitly disabled packs (for disabling sub-packs of enabled categories).
    pub disabled: Vec<String>,
}

impl PacksConfig {
    /// Get enabled pack IDs as a deduplicated set.
    #[must_use]
    pub fn enabled_pack_ids(&self) -> HashSet<String> {
        let mut enabled: HashSet<String> = self.enabled.iter().cloned().collect();

        // Remove explicitly disabled packs.
        for disabled in &self.disabled {
            enabled.remove(disabled);
            // Also remove sub-packs if a category is disabled.
            enabled.retain(|p| !p.starts_with(&format!("{disabled}.")));
        }

        // Core is always enabled.
        enabled.insert("core".to_string());

        enabled
    }
}

/// Decision mode policy configuration.
///
/// Controls how matched patterns are handled: deny (block), warn (allow with warning),
/// or log (silent allow with optional logging).
///
/// Defaults respect severity: Critical/High → deny, Medium → warn, Low → log.
/// This config allows overriding the default behavior per pack or per specific rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    /// Global default mode (overrides severity-based defaults).
    /// If not set, severity-based defaults apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_mode: Option<PolicyMode>,

    /// Optional observe-mode window end timestamp.
    ///
    /// When set and the current time is **before** this timestamp:
    /// - `default_mode` applies, but defaults to `"warn"` when unset.
    ///
    /// When set and the current time is **at/after** this timestamp:
    /// - `default_mode` is ignored and dcg reverts to severity-based defaults.
    ///
    /// Accepted formats:
    /// - RFC 3339: `2026-02-01T00:00:00Z`
    /// - ISO 8601 without timezone (treated as UTC): `2026-02-01T00:00:00`
    /// - Date only (treated as end of day UTC): `2026-02-01`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observe_until: Option<ObserveUntil>,

    /// Per-pack mode overrides.
    /// Key is `pack_id` (e.g., "core.git", "database.postgresql").
    /// Value is the mode to use for all patterns in that pack.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub packs: std::collections::HashMap<String, PolicyMode>,

    /// Per-rule mode overrides.
    /// Key is `rule_id` (e.g., "core.git:reset-hard", "core.filesystem:rm-rf-root").
    /// Value is the mode to use for that specific rule.
    /// Takes precedence over pack-level and global overrides.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub rules: std::collections::HashMap<String, PolicyMode>,
}

/// Policy mode for overriding default decision behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    /// Block the command (output JSON deny, print warning).
    Deny,
    /// Warn but allow (print warning to stderr, no JSON deny).
    Warn,
    /// Log only (silent allow, record for history).
    Log,
}

impl PolicyMode {
    /// Convert to the internal `DecisionMode`.
    #[must_use]
    pub const fn to_decision_mode(self) -> crate::packs::DecisionMode {
        match self {
            Self::Deny => crate::packs::DecisionMode::Deny,
            Self::Warn => crate::packs::DecisionMode::Warn,
            Self::Log => crate::packs::DecisionMode::Log,
        }
    }
}

impl PolicyConfig {
    /// Resolve the effective decision mode for a given rule.
    ///
    /// Priority (highest to lowest):
    /// 1. Rule-specific override (via `rules["pack_id:pattern_name"]`)
    /// 2. Pack-specific override (via `packs["pack_id"]`)
    /// 3. Global default (`default_mode`)
    /// 4. Severity-based default (from pattern's severity)
    #[must_use]
    pub fn resolve_mode(
        &self,
        pack_id: Option<&str>,
        pattern_name: Option<&str>,
        severity: Option<crate::packs::Severity>,
    ) -> crate::packs::DecisionMode {
        self.resolve_mode_at(Utc::now(), pack_id, pattern_name, severity)
    }

    #[must_use]
    pub fn resolve_mode_at(
        &self,
        now: DateTime<Utc>,
        pack_id: Option<&str>,
        pattern_name: Option<&str>,
        severity: Option<crate::packs::Severity>,
    ) -> crate::packs::DecisionMode {
        // 1. Rule-specific override
        if let (Some(pack), Some(pattern)) = (pack_id, pattern_name) {
            let rule_id = format!("{pack}:{pattern}");
            if let Some(mode) = self.rules.get(&rule_id) {
                return mode.to_decision_mode();
            }
        }

        // Safety constraint: Critical rules may only be loosened via an explicit per-rule override.
        // Pack-level/global defaults must never downgrade Critical to warn/log.
        if matches!(severity, Some(crate::packs::Severity::Critical)) {
            return crate::packs::DecisionMode::Deny;
        }

        // 2. Pack-specific override
        if let Some(pack) = pack_id {
            if let Some(mode) = self.packs.get(pack) {
                return mode.to_decision_mode();
            }
        }

        // 3. Global default (optionally gated by observe_until)
        let effective_default_mode = self
            .observe_until
            .as_ref()
            .and_then(ObserveUntil::parsed_utc)
            .map_or(self.default_mode, |until| {
                if &now < until {
                    Some(self.default_mode.unwrap_or(PolicyMode::Warn))
                } else {
                    None
                }
            });

        if let Some(mode) = effective_default_mode {
            return mode.to_decision_mode();
        }

        // 4. Severity-based default
        severity.map_or(crate::packs::DecisionMode::Deny, |s| s.default_mode())
    }
}

/// Custom pattern overrides.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OverridesConfig {
    /// Patterns to allow that would otherwise be blocked.
    #[serde(default)]
    pub allow: Vec<AllowOverride>,

    /// Additional patterns to block.
    #[serde(default)]
    pub block: Vec<BlockOverride>,
}

/// An allow override - patterns that should be permitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AllowOverride {
    /// Simple pattern string.
    Simple(String),
    /// Conditional override with optional `when` clause.
    Conditional {
        pattern: String,
        /// Optional condition (e.g., "CI=true").
        when: Option<String>,
    },
}

impl AllowOverride {
    /// Get the pattern string.
    #[must_use]
    pub fn pattern(&self) -> &str {
        match self {
            Self::Simple(p) => p,
            Self::Conditional { pattern, .. } => pattern,
        }
    }

    /// Check if the condition is met (if any).
    #[must_use]
    pub fn condition_met(&self) -> bool {
        match self {
            Self::Simple(_) | Self::Conditional { when: None, .. } => true,
            Self::Conditional {
                when: Some(condition),
                ..
            } => {
                // Parse condition like "CI=true"
                if let Some((var, expected)) = condition.split_once('=') {
                    env::var(var).map(|v| v == expected).unwrap_or(false)
                } else {
                    // Just check if the env var is set
                    env::var(condition).is_ok()
                }
            }
        }
    }
}

/// A block override - additional patterns to block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockOverride {
    /// The regex pattern to match.
    pub pattern: String,
    /// Human-readable reason for blocking.
    pub reason: String,
}

/// Redaction mode for command history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HistoryRedactionMode {
    /// Store commands without redaction.
    None,
    /// Redact sensitive values using pattern-based filters.
    #[default]
    Pattern,
    /// Fully redact command contents.
    Full,
}

impl std::str::FromStr for HistoryRedactionMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "pattern" => Ok(Self::Pattern),
            "full" => Ok(Self::Full),
            _ => Err(format!("invalid history redaction mode: {value}")),
        }
    }
}

/// History configuration options.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HistoryConfig {
    /// Enable command history collection.
    pub enabled: bool,
    /// Redaction mode for stored commands.
    pub redaction_mode: HistoryRedactionMode,
    /// Retention window in days.
    pub retention_days: u32,
    /// Maximum database size in megabytes.
    pub max_size_mb: u32,
    /// Optional database file path override.
    pub database_path: Option<String>,
    /// Enable automatic pruning of old entries.
    pub auto_prune: bool,
    /// Interval in hours between automatic prune checks.
    pub prune_check_interval_hours: u32,
    /// Batch size for write operations (improves performance).
    pub batch_size: u32,
    /// Flush interval in milliseconds for batched writes.
    pub batch_flush_interval_ms: u32,
}

impl HistoryConfig {
    /// Default retention window (days).
    pub const DEFAULT_RETENTION_DAYS: u32 = 90;
    /// Default maximum database size (MB).
    pub const DEFAULT_MAX_SIZE_MB: u32 = 500;
    /// Maximum allowed retention window (days).
    pub const MAX_RETENTION_DAYS: u32 = 3650;
    /// Default interval between automatic prune checks (hours).
    pub const DEFAULT_PRUNE_CHECK_INTERVAL_HOURS: u32 = 24;
    /// Default batch size for write operations.
    pub const DEFAULT_BATCH_SIZE: u32 = 50;
    /// Default flush interval for batched writes (ms).
    pub const DEFAULT_BATCH_FLUSH_INTERVAL_MS: u32 = 100;

    /// Expand the configured database path, if set.
    #[must_use]
    pub fn expanded_database_path(&self) -> Option<PathBuf> {
        let raw = self.database_path.as_ref()?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }

        let had_tilde_prefix = trimmed.starts_with('~');
        let (mut path, _tilde_expanded) = expand_tilde_path(trimmed);
        if !had_tilde_prefix && path.is_relative() {
            if let Ok(cwd) = env::current_dir() {
                path = cwd.join(path);
            }
        }
        Some(path)
    }

    /// Validate history settings.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid retention values.
    pub fn validate(&self) -> Result<(), String> {
        if self.retention_days == 0 {
            return Err("history retention_days must be at least 1".to_string());
        }
        if self.retention_days > Self::MAX_RETENTION_DAYS {
            return Err(format!(
                "history retention_days must be <= {}",
                Self::MAX_RETENTION_DAYS
            ));
        }
        Ok(())
    }
}

impl Default for HistoryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            redaction_mode: HistoryRedactionMode::Pattern,
            retention_days: Self::DEFAULT_RETENTION_DAYS,
            max_size_mb: Self::DEFAULT_MAX_SIZE_MB,
            database_path: None,
            auto_prune: false,
            prune_check_interval_hours: Self::DEFAULT_PRUNE_CHECK_INTERVAL_HOURS,
            batch_size: Self::DEFAULT_BATCH_SIZE,
            batch_flush_interval_ms: Self::DEFAULT_BATCH_FLUSH_INTERVAL_MS,
        }
    }
}

// ============================================================================
// Compiled Overrides (Runtime-Only, Pre-compiled Regexes)
// ============================================================================

use crate::packs::regex_engine::CompiledRegex;

/// A compiled allow override with precompiled regex.
///
/// This is the runtime representation used for evaluation.
/// Created once at config load time, not per-command.
#[derive(Debug)]
pub struct CompiledAllowOverride {
    /// The precompiled regex pattern.
    pub regex: CompiledRegex,
    /// The original pattern string (for diagnostics).
    pub pattern: String,
    /// The condition evaluator (returns true if condition is met).
    /// For simple overrides, this always returns true.
    /// For conditional overrides, this checks the environment.
    condition: ConditionCheck,
}

/// Condition check type - either always true or checks an env var.
#[derive(Debug)]
enum ConditionCheck {
    /// Always allow (no condition).
    Always,
    /// Check if env var equals expected value.
    EnvEquals { var: String, expected: String },
    /// Check if env var is set (any value).
    EnvSet { var: String },
}

impl ConditionCheck {
    /// Check if the condition is met.
    fn is_met(&self) -> bool {
        match self {
            Self::Always => true,
            Self::EnvEquals { var, expected } => {
                std::env::var(var).map(|v| v == *expected).unwrap_or(false)
            }
            Self::EnvSet { var } => std::env::var(var).is_ok(),
        }
    }
}

impl CompiledAllowOverride {
    /// Check if this override matches and its condition is met.
    ///
    /// Returns true if the command matches and should be allowed.
    #[inline]
    #[must_use]
    pub fn matches(&self, command: &str) -> bool {
        self.condition.is_met() && self.regex.is_match(command)
    }
}

/// A compiled block override with precompiled regex.
#[derive(Debug)]
pub struct CompiledBlockOverride {
    /// The precompiled regex pattern.
    pub regex: CompiledRegex,
    /// The original pattern string (for diagnostics).
    pub pattern: String,
    /// Human-readable reason for blocking.
    pub reason: String,
}

impl CompiledBlockOverride {
    /// Check if this override matches.
    ///
    /// Returns the reason if blocked.
    #[inline]
    #[must_use]
    pub fn matches(&self, command: &str) -> Option<&str> {
        if self.regex.is_match(command) {
            Some(&self.reason)
        } else {
            None
        }
    }
}

/// Compiled overrides - runtime representation with precompiled regexes.
///
/// This struct is created once per config load and reused for all command
/// evaluations. It eliminates per-command regex compilation overhead.
#[derive(Debug, Default)]
pub struct CompiledOverrides {
    /// Compiled allow overrides.
    pub allow: Vec<CompiledAllowOverride>,
    /// Compiled block overrides.
    pub block: Vec<CompiledBlockOverride>,
    /// Patterns that failed to compile (for diagnostics).
    pub invalid_patterns: Vec<InvalidPattern>,
}

/// Record of a pattern that failed to compile.
#[derive(Debug, Clone)]
pub struct InvalidPattern {
    /// The original pattern string.
    pub pattern: String,
    /// The compilation error message.
    pub error: String,
    /// Whether this was an allow or block pattern.
    pub kind: PatternKind,
}

/// Kind of override pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternKind {
    Allow,
    Block,
}

impl CompiledOverrides {
    /// Check allow overrides. Returns true if command should be allowed.
    #[inline]
    #[must_use]
    pub fn check_allow(&self, command: &str) -> bool {
        self.allow.iter().any(|o| o.matches(command))
    }

    /// Check block overrides. Returns the reason if command should be blocked.
    #[inline]
    #[must_use]
    pub fn check_block(&self, command: &str) -> Option<&str> {
        self.block.iter().find_map(|o| o.matches(command))
    }

    /// Check if there are any invalid patterns.
    #[must_use]
    pub fn has_invalid_patterns(&self) -> bool {
        !self.invalid_patterns.is_empty()
    }
}

impl OverridesConfig {
    /// Compile all override patterns into precompiled regexes.
    ///
    /// Invalid patterns are collected but do not cause errors (fail-open).
    /// Use `CompiledOverrides::invalid_patterns` to check for issues.
    #[must_use]
    pub fn compile(&self) -> CompiledOverrides {
        let mut compiled = CompiledOverrides::default();

        // Compile allow overrides
        for allow in &self.allow {
            match CompiledRegex::new(allow.pattern()) {
                Ok(regex) => {
                    let condition = match allow {
                        AllowOverride::Simple(_)
                        | AllowOverride::Conditional { when: None, .. } => ConditionCheck::Always,
                        AllowOverride::Conditional {
                            when: Some(condition),
                            ..
                        } => {
                            if let Some((var, expected)) = condition.split_once('=') {
                                ConditionCheck::EnvEquals {
                                    var: var.to_string(),
                                    expected: expected.to_string(),
                                }
                            } else {
                                ConditionCheck::EnvSet {
                                    var: condition.clone(),
                                }
                            }
                        }
                    };
                    compiled.allow.push(CompiledAllowOverride {
                        regex,
                        pattern: allow.pattern().to_string(),
                        condition,
                    });
                }
                Err(e) => {
                    compiled.invalid_patterns.push(InvalidPattern {
                        pattern: allow.pattern().to_string(),
                        error: e.clone(),
                        kind: PatternKind::Allow,
                    });
                }
            }
        }

        // Compile block overrides
        for block in &self.block {
            match CompiledRegex::new(&block.pattern) {
                Ok(regex) => {
                    compiled.block.push(CompiledBlockOverride {
                        regex,
                        pattern: block.pattern.clone(),
                        reason: block.reason.clone(),
                    });
                }
                Err(e) => {
                    compiled.invalid_patterns.push(InvalidPattern {
                        pattern: block.pattern.clone(),
                        error: e.clone(),
                        kind: PatternKind::Block,
                    });
                }
            }
        }

        compiled
    }
}

/// Project-specific configuration overrides.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProjectConfig {
    /// Pack configuration for this project.
    pub packs: Option<PacksConfig>,

    /// Overrides for this project.
    pub overrides: Option<OverridesConfig>,
}

impl Config {
    /// Load configuration from all sources, merging them in priority order.
    ///
    /// Priority (highest to lowest):
    /// 1. Environment variables (settings overrides)
    /// 2. Explicit config file (`DCG_CONFIG=/path/to/config.toml`)
    /// 3. Project config (`.dcg.toml` in repo root)
    /// 4. User config (`~/.config/dcg/config.toml`)
    /// 5. System config (`/etc/dcg/config.toml`)
    /// 6. Compiled defaults
    #[must_use]
    pub fn load() -> Self {
        // Start with truly empty defaults - packs must be explicitly enabled.
        // generate_default() is for sample configs shown to users, not runtime defaults.
        let mut config = Self::default();
        let cwd = env::current_dir().ok();

        // Optional explicit config path override (highest-priority file config).
        let explicit_layer = env::var(ENV_CONFIG_PATH)
            .ok()
            .and_then(|value| resolve_config_path_value(&value, cwd.as_deref()))
            .and_then(|path| Self::load_layer_from_file(&path));

        // Load system config (lowest priority of file configs)
        if let Some(system_config) = Self::load_system_config_layer() {
            config.merge_layer(system_config);
        }

        // Load user config
        //
        // If an explicit config file is present and valid, we treat it as the
        // user-level config and skip loading the default user config path to
        // reduce layering confusion.
        if explicit_layer.is_none() {
            if let Some(user_config) = Self::load_user_config_layer() {
                config.merge_layer(user_config);
            }
        }

        // Load project config (if in a git repo)
        if let Some(project_config) = Self::load_project_config_layer_from(cwd.as_deref()) {
            config.merge_layer(project_config);
        }

        // Apply explicit config last among file configs (if present and valid).
        if let Some(explicit_layer) = explicit_layer {
            config.merge_layer(explicit_layer);
        }

        // Apply environment variable overrides (highest priority)
        config.apply_env_overrides();

        config
    }

    /// Load a configuration *layer* from a specific file.
    ///
    /// Layers preserve field presence (via `Option<T>`) so higher-precedence
    /// configs can explicitly set values back to defaults.
    #[must_use]
    fn load_layer_from_file(path: &Path) -> Option<ConfigLayer> {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => {
                eprintln!(
                    "Warning: Failed to read config file '{}': {}",
                    path.display(),
                    e
                );
                return None;
            }
        };

        match toml::from_str(&content) {
            Ok(layer) => Some(layer),
            Err(e) => {
                eprintln!(
                    "Warning: Failed to parse config file '{}': {}",
                    path.display(),
                    e
                );
                None
            }
        }
    }

    /// Load configuration from a specific file.
    #[must_use]
    pub fn load_from_file(path: &Path) -> Option<Self> {
        let content = fs::read_to_string(path).ok()?;
        toml::from_str(&content).ok()
    }

    /// Load system-wide configuration.
    fn load_system_config_layer() -> Option<ConfigLayer> {
        let path = PathBuf::from("/etc/dcg").join(CONFIG_FILE_NAME);
        Self::load_layer_from_file(&path)
    }

    /// Load user configuration.
    fn load_user_config_layer() -> Option<ConfigLayer> {
        let config_dir = dirs::config_dir()?;
        let path = config_dir.join("dcg").join(CONFIG_FILE_NAME);
        Self::load_layer_from_file(&path)
    }

    /// Load project-level configuration (`.dcg.toml` in repo root).
    fn load_project_config_layer_from(start_dir: Option<&Path>) -> Option<ConfigLayer> {
        let start_dir = start_dir?;
        let repo_root = find_repo_root(start_dir, REPO_ROOT_SEARCH_MAX_HOPS)?;
        let config_path = repo_root.join(PROJECT_CONFIG_NAME);
        if !config_path.exists() {
            return None;
        }
        Self::load_layer_from_file(&config_path)
    }

    /// Merge another config layer into this one (other takes priority when set).
    fn merge_layer(&mut self, other: ConfigLayer) {
        if let Some(general) = other.general {
            self.merge_general_layer(general);
        }

        if let Some(output) = other.output {
            self.merge_output_layer(output);
        }

        if let Some(packs) = other.packs {
            self.merge_packs_layer(packs);
        }

        if let Some(policy) = other.policy {
            self.merge_policy_layer(policy);
        }

        if let Some(overrides) = other.overrides {
            self.merge_overrides_layer(overrides);
        }

        if let Some(heredoc) = other.heredoc {
            self.merge_heredoc_layer(heredoc);
        }

        if let Some(confidence) = other.confidence {
            self.merge_confidence_layer(confidence);
        }

        if let Some(logging) = other.logging {
            self.merge_logging_layer(logging);
        }

        if let Some(history) = other.history {
            self.merge_history_layer(history);
        }

        // Merge project configs
        if let Some(projects) = other.projects {
            self.projects.extend(projects);
        }
    }

    fn merge_general_layer(&mut self, general: GeneralConfigLayer) {
        if let Some(color) = general.color {
            self.general.color = color;
        }
        if let Some(log_file) = general.log_file {
            self.general.log_file = Some(log_file);
        }
        if let Some(verbose) = general.verbose {
            self.general.verbose = verbose;
        }
        if let Some(max_hook_input_bytes) = general.max_hook_input_bytes {
            self.general.max_hook_input_bytes = Some(max_hook_input_bytes);
        }
        if let Some(max_command_bytes) = general.max_command_bytes {
            self.general.max_command_bytes = Some(max_command_bytes);
        }
        if let Some(max_findings_per_command) = general.max_findings_per_command {
            self.general.max_findings_per_command = Some(max_findings_per_command);
        }
    }

    const fn merge_output_layer(&mut self, output: OutputConfigLayer) {
        if let Some(highlight_enabled) = output.highlight_enabled {
            self.output.highlight_enabled = Some(highlight_enabled);
        }
        if let Some(explanations_enabled) = output.explanations_enabled {
            self.output.explanations_enabled = Some(explanations_enabled);
        }
    }

    fn merge_packs_layer(&mut self, packs: PacksConfig) {
        self.packs.enabled.extend(packs.enabled);
        self.packs.disabled.extend(packs.disabled);
    }

    fn merge_policy_layer(&mut self, policy: PolicyConfig) {
        if policy.default_mode.is_some() {
            self.policy.default_mode = policy.default_mode;
        }
        if policy.observe_until.is_some() {
            self.policy.observe_until = policy.observe_until;
        }
        self.policy.packs.extend(policy.packs);
        self.policy.rules.extend(policy.rules);
    }

    fn merge_overrides_layer(&mut self, overrides: OverridesConfig) {
        self.overrides.allow.extend(overrides.allow);
        self.overrides.block.extend(overrides.block);
    }

    fn merge_heredoc_layer(&mut self, heredoc: HeredocConfig) {
        if heredoc.enabled.is_some() {
            self.heredoc.enabled = heredoc.enabled;
        }
        if heredoc.timeout_ms.is_some() {
            self.heredoc.timeout_ms = heredoc.timeout_ms;
        }
        if heredoc.max_body_bytes.is_some() {
            self.heredoc.max_body_bytes = heredoc.max_body_bytes;
        }
        if heredoc.max_body_lines.is_some() {
            self.heredoc.max_body_lines = heredoc.max_body_lines;
        }
        if heredoc.max_heredocs.is_some() {
            self.heredoc.max_heredocs = heredoc.max_heredocs;
        }
        if heredoc.languages.is_some() {
            self.heredoc.languages = heredoc.languages;
        }
        if heredoc.fallback_on_parse_error.is_some() {
            self.heredoc.fallback_on_parse_error = heredoc.fallback_on_parse_error;
        }
        if heredoc.fallback_on_timeout.is_some() {
            self.heredoc.fallback_on_timeout = heredoc.fallback_on_timeout;
        }

        // Merge heredoc allowlist (additive).
        if let Some(other_allowlist) = heredoc.allowlist {
            if let Some(existing) = self.heredoc.allowlist.as_mut() {
                existing.merge(&other_allowlist);
            } else {
                self.heredoc.allowlist = Some(other_allowlist);
            }
        }
    }

    #[allow(clippy::missing_const_for_fn)] // Uses `if let` which isn't const-compatible
    fn merge_confidence_layer(&mut self, confidence: ConfidenceConfigLayer) {
        if let Some(enabled) = confidence.enabled {
            self.confidence.enabled = enabled;
        }
        if let Some(warn_threshold) = confidence.warn_threshold {
            self.confidence.warn_threshold = warn_threshold;
        }
        if let Some(protect_critical) = confidence.protect_critical {
            self.confidence.protect_critical = protect_critical;
        }
    }

    fn merge_logging_layer(&mut self, logging: LoggingConfigLayer) {
        if let Some(enabled) = logging.enabled {
            self.logging.enabled = enabled;
        }
        if let Some(file) = logging.file {
            self.logging.file = Some(file);
        }
        if let Some(format) = logging.format {
            self.logging.format = format;
        }
        if let Some(redaction) = logging.redaction {
            if let Some(enabled) = redaction.enabled {
                self.logging.redaction.enabled = enabled;
            }
            if let Some(mode) = redaction.mode {
                self.logging.redaction.mode = mode;
            }
            if let Some(max_argument_len) = redaction.max_argument_len {
                self.logging.redaction.max_argument_len = max_argument_len;
            }
        }
        if let Some(events) = logging.events {
            if let Some(deny) = events.deny {
                self.logging.events.deny = deny;
            }
            if let Some(warn) = events.warn {
                self.logging.events.warn = warn;
            }
            if let Some(allow) = events.allow {
                self.logging.events.allow = allow;
            }
        }
    }

    fn merge_history_layer(&mut self, history: HistoryConfigLayer) {
        if let Some(enabled) = history.enabled {
            self.history.enabled = enabled;
        }
        if let Some(redaction_mode) = history.redaction_mode {
            self.history.redaction_mode = redaction_mode;
        }
        if let Some(retention_days) = history.retention_days {
            self.history.retention_days = retention_days;
        }
        if let Some(max_size_mb) = history.max_size_mb {
            self.history.max_size_mb = max_size_mb;
        }
        if let Some(database_path) = history.database_path {
            self.history.database_path = Some(database_path);
        }
    }

    /// Apply environment variable overrides.
    fn apply_env_overrides(&mut self) {
        self.apply_env_overrides_from(|key| env::var(key).ok());
    }

    fn apply_env_overrides_from<F>(&mut self, mut get_env: F)
    where
        F: FnMut(&str) -> Option<String>,
    {
        // DCG_PACKS="core,database.postgresql,kubernetes"
        if let Some(packs) = get_env(&format!("{ENV_PREFIX}_PACKS")) {
            self.packs.enabled = packs.split(',').map(|s| s.trim().to_string()).collect();
        }

        // DCG_DISABLE="kubernetes.helm"
        if let Some(disable) = get_env(&format!("{ENV_PREFIX}_DISABLE")) {
            self.packs.disabled = disable.split(',').map(|s| s.trim().to_string()).collect();
        }

        // DCG_VERBOSE=1
        if get_env(&format!("{ENV_PREFIX}_VERBOSE")).is_some() {
            self.general.verbose = true;
        }

        // DCG_COLOR=never
        if let Some(color) = get_env(&format!("{ENV_PREFIX}_COLOR")) {
            self.general.color = color;
        }

        // -----------------------------------------------------------------
        // Heredoc scanning (env overrides)
        // -----------------------------------------------------------------

        // DCG_HEREDOC_ENABLED=true|false|1|0
        if let Some(enabled) = get_env(&format!("{ENV_PREFIX}_HEREDOC_ENABLED")) {
            if let Some(parsed) = parse_env_bool(&enabled) {
                self.heredoc.enabled = Some(parsed);
            }
        }

        // DCG_HEREDOC_TIMEOUT=50 (ms)
        let timeout_var = format!("{ENV_PREFIX}_HEREDOC_TIMEOUT");
        let timeout_ms_var = format!("{ENV_PREFIX}_HEREDOC_TIMEOUT_MS");
        if let Some(timeout_ms) = get_env(&timeout_ms_var).or_else(|| get_env(&timeout_var)) {
            if let Ok(parsed) = timeout_ms.trim().parse::<u64>() {
                self.heredoc.timeout_ms = Some(parsed);
            }
        }

        // DCG_HEREDOC_LANGUAGES=python,bash,javascript
        if let Some(langs) = get_env(&format!("{ENV_PREFIX}_HEREDOC_LANGUAGES")) {
            let parsed: Vec<String> = langs
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !parsed.is_empty() {
                self.heredoc.languages = Some(parsed);
            }
        }

        // -----------------------------------------------------------------
        // Policy config (env overrides)
        // -----------------------------------------------------------------

        // DCG_POLICY_DEFAULT_MODE=deny|warn|log
        if let Some(mode) = get_env(&format!("{ENV_PREFIX}_POLICY_DEFAULT_MODE")) {
            if let Some(parsed) = parse_policy_mode(&mode) {
                self.policy.default_mode = Some(parsed);
            }
        }

        // DCG_POLICY_OBSERVE_UNTIL=2030-01-01T00:00:00Z
        if let Some(observe_until) = get_env(&format!("{ENV_PREFIX}_POLICY_OBSERVE_UNTIL")) {
            self.policy.observe_until = ObserveUntil::parse(&observe_until);
        }

        // -----------------------------------------------------------------
        // History config (env overrides)
        // -----------------------------------------------------------------

        // DCG_HISTORY_ENABLED=true|false|1|0
        if let Some(enabled) = get_env(&format!("{ENV_PREFIX}_HISTORY_ENABLED")) {
            if let Some(parsed) = parse_env_bool(&enabled) {
                self.history.enabled = parsed;
            }
        }

        // DCG_HISTORY_REDACTION_MODE=none|pattern|full
        if let Some(mode) = get_env(&format!("{ENV_PREFIX}_HISTORY_REDACTION_MODE")) {
            if let Ok(parsed) = HistoryRedactionMode::from_str(&mode) {
                self.history.redaction_mode = parsed;
            }
        }
    }

    /// Get a reference to the policy config.
    #[must_use]
    pub const fn policy(&self) -> &PolicyConfig {
        &self.policy
    }

    /// Check if the bypass flag is set (escape hatch).
    #[must_use]
    pub fn is_bypassed() -> bool {
        env::var(format!("{ENV_PREFIX}_BYPASS")).is_ok()
    }

    /// Get the effective pack configuration for a specific project path.
    #[must_use]
    pub fn effective_packs_for_project(&self, project_path: &Path) -> PacksConfig {
        // Check if there's a project-specific config
        let path_str = project_path.to_string_lossy();

        for (project_pattern, project_config) in &self.projects {
            if path_str.starts_with(project_pattern) {
                if let Some(packs) = &project_config.packs {
                    return packs.clone();
                }
            }
        }

        // Fall back to global config
        self.packs.clone()
    }

    /// Get enabled pack IDs as a deduplicated set.
    #[must_use]
    pub fn enabled_pack_ids(&self) -> HashSet<String> {
        if self.projects.is_empty() {
            return self.packs.enabled_pack_ids();
        }

        if let Ok(cwd) = std::env::current_dir() {
            return self.effective_packs_for_project(&cwd).enabled_pack_ids();
        }

        self.packs.enabled_pack_ids()
    }

    /// Get effective heredoc scanning settings for evaluation.
    #[must_use]
    pub fn heredoc_settings(&self) -> HeredocSettings {
        self.heredoc.settings()
    }

    /// Get the path to the user config file (creates dir if needed).
    #[must_use]
    pub fn user_config_path() -> Option<PathBuf> {
        let config_dir = dirs::config_dir()?;
        let guard_dir = config_dir.join("dcg");

        // Create directory if it doesn't exist
        if !guard_dir.exists() {
            fs::create_dir_all(&guard_dir).ok()?;
        }

        Some(guard_dir.join(CONFIG_FILE_NAME))
    }

    /// Save configuration to the user config file.
    ///
    /// # Errors
    ///
    /// Returns an error if the config directory cannot be determined/created,
    /// serialization fails, or the config file cannot be written.
    pub fn save_to_user_config(&self) -> Result<PathBuf, String> {
        let path = Self::user_config_path().ok_or("Could not determine config directory")?;

        let content =
            toml::to_string_pretty(self).map_err(|e| format!("Failed to serialize config: {e}"))?;

        fs::write(&path, content).map_err(|e| format!("Failed to write config: {e}"))?;

        Ok(path)
    }

    /// Generate a default configuration with common packs enabled.
    #[must_use]
    pub fn generate_default() -> Self {
        Self {
            general: GeneralConfig::default(),
            output: OutputConfig::default(),
            packs: PacksConfig {
                enabled: vec![
                    // Core is implicit, but list common ones
                    "database.postgresql".to_string(),
                    "containers.docker".to_string(),
                ],
                disabled: vec![],
            },
            policy: PolicyConfig::default(),
            overrides: OverridesConfig::default(),
            heredoc: HeredocConfig::default(),
            confidence: ConfidenceConfig::default(),
            logging: crate::logging::LoggingConfig::default(),
            history: HistoryConfig::default(),
            projects: std::collections::HashMap::new(),
        }
    }

    /// Generate a sample configuration string with comments.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn generate_sample_config() -> String {
        r#"# dcg configuration
# https://github.com/Dicklesworthstone/destructive_command_guard

[general]
# Color output: "auto" | "always" | "never"
color = "auto"

# Log blocked commands to file (optional)
# log_file = "~/.local/share/dcg/blocked.log"

# Verbose output
verbose = false

#─────────────────────────────────────────────────────────────
# OUTPUT CONFIGURATION
#─────────────────────────────────────────────────────────────

[output]
# Enable span highlighting in denial output.
# Shows caret-style markers under the matched portion.
# highlight_enabled = true

# Enable explanations in denial output.
# Shows detailed explanations for why patterns are dangerous.
# explanations_enabled = true

#─────────────────────────────────────────────────────────────
# PACK CONFIGURATION
#─────────────────────────────────────────────────────────────

[packs]
# Enable entire categories or specific sub-packs.
# Core pack is always enabled implicitly.
#
# Available packs:
#   core                  - Git and filesystem protections (always on)
#   database.postgresql   - PostgreSQL destructive commands
#   database.mysql        - MySQL destructive commands
#   database.mongodb      - MongoDB destructive commands
#   database.redis        - Redis FLUSH commands
#   database.sqlite       - SQLite destructive commands
#   containers.docker     - Docker destructive commands
#   containers.compose    - Docker Compose destructive commands
#   containers.podman     - Podman destructive commands
#   kubernetes.kubectl    - kubectl delete commands
#   kubernetes.helm       - Helm uninstall commands
#   kubernetes.kustomize  - Kustomize delete commands
#   cloud.aws             - AWS CLI destructive commands
#   cloud.gcp             - GCP CLI destructive commands
#   cloud.azure           - Azure CLI destructive commands
#   infrastructure.terraform - Terraform destroy commands
#   infrastructure.ansible   - Ansible state=absent patterns
#   infrastructure.pulumi    - Pulumi destroy commands
#   system.disk           - Disk operations (dd, mkfs, fdisk)
#   system.permissions    - Dangerous permission changes
#   system.services       - Service management commands
#   strict_git            - Extra paranoid git protections
#   package_managers      - npm unpublish, cargo yank, etc.

enabled = [
    "database.postgresql",
    "containers.docker",
    # "kubernetes",         # Uncomment to enable all kubernetes sub-packs
    # "cloud.aws",
]

# Explicitly disable specific sub-packs
disabled = [
    # "kubernetes.kustomize",  # Example: disable kustomize if you don't use it
]

#─────────────────────────────────────────────────────────────
# DECISION MODE POLICY
#─────────────────────────────────────────────────────────────

[policy]
# Optional global override for how matched rules are handled:
# - "deny": block (default)
# - "warn": allow but print a warning to stderr (no hook JSON deny)
# - "log": allow silently (no stderr/stdout; optional log_file history)
#
# If unset, dcg uses severity defaults:
# - critical/high => deny
# - medium => warn
# - low => log
#
# default_mode = "deny"
#
# Optional observe-mode window end timestamp.
# When set and before the timestamp, `default_mode` applies (defaulting to "warn" when unset).
# When set and after the timestamp, `default_mode` is ignored and severity defaults apply.
# observe_until = "2026-02-01T00:00:00Z"

[policy.packs]
# Override mode for an entire pack (pack_id => mode).
# Examples:
# "core.git" = "warn"                # warn-first rollout for git pack
# "containers.docker" = "deny"       # keep docker destructive ops as hard blocks

[policy.rules]
# Override mode for a specific rule (rule_id => mode).
# Examples:
# "core.git:push-force-long" = "warn"
# "core.git:reset-hard" = "deny"     # keep critical rules as hard blocks
#
# Safety: Critical rules are only loosened via explicit per-rule overrides.

#─────────────────────────────────────────────────────────────
# CUSTOM OVERRIDES
#─────────────────────────────────────────────────────────────

[overrides]
# Allow specific patterns that would otherwise be blocked.
# Supports simple strings or conditional objects.
allow = [
    # Example: Allow deleting test namespaces
    # "kubectl delete namespace test-.*",

    # Example: Allow dropping test databases
    # "dropdb test_.*",

    # Example: Conditional - only in CI
    # { pattern = "docker system prune", when = "CI=true" },
]

# Block additional patterns not covered by any pack.
block = [
    # Example: Block a custom dangerous script
    # { pattern = "deploy-to-prod\\.sh.*--force", reason = "Never force-deploy to production" },

    # Example: Block piping curl to shell
    # { pattern = "curl.*\\| ?sh", reason = "Piping curl to shell is dangerous" },
]

#─────────────────────────────────────────────────────────────
# HEREDOC / INLINE SCRIPT SCANNING
#─────────────────────────────────────────────────────────────

[heredoc]
# Enable scanning for heredocs and inline scripts (python -c, bash -c, etc.).
enabled = true

# Extraction timeout budget (milliseconds). Parsing/matching has its own budget.
timeout_ms = 50

# Resource limits for extracted bodies (Tier 2).
max_body_bytes = 1048576
max_body_lines = 10000
max_heredocs = 10

# Optional language filter (scan only these languages). Omit for "all".
# languages = ["python", "bash", "javascript", "typescript", "ruby", "perl"]

# Graceful degradation (hook defaults are fail-open).
fallback_on_parse_error = true
fallback_on_timeout = true

#─────────────────────────────────────────────────────────────
# HISTORY
#─────────────────────────────────────────────────────────────

[history]
# Enable command history (opt-in).
enabled = false

# Redaction mode for stored commands: "pattern" | "full" | "none"
redaction_mode = "pattern"

# Retention window and database size limits.
retention_days = 90
max_size_mb = 500

# Optional database path override.
# database_path = "~/.config/dcg/history.db"

#─────────────────────────────────────────────────────────────
# PROJECT-SPECIFIC OVERRIDES
#─────────────────────────────────────────────────────────────

# Override settings for specific project directories.
# The key is the absolute path to the project.

# [projects."/path/to/database-project"]
# packs.enabled = ["database"]
# packs.disabled = []
# overrides.allow = ["dropdb test_.*"]

# [projects."/path/to/k8s-infra"]
# packs.enabled = ["kubernetes", "cloud.aws", "infrastructure.terraform"]
"#
        .to_string()
    }
}

fn parse_env_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "y" | "on" => Some(true),
        "0" | "false" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}

fn parse_policy_mode(value: &str) -> Option<PolicyMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "deny" | "block" => Some(PolicyMode::Deny),
        "warn" | "warning" => Some(PolicyMode::Warn),
        "log" | "log-only" | "logonly" => Some(PolicyMode::Log),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObserveUntil {
    raw: String,
    parsed_utc: Option<DateTime<Utc>>,
}

impl ObserveUntil {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }
        Some(Self {
            raw: trimmed.to_string(),
            parsed_utc: parse_timestamp_as_utc(trimmed),
        })
    }

    #[must_use]
    pub const fn parsed_utc(&self) -> Option<&DateTime<Utc>> {
        self.parsed_utc.as_ref()
    }
}

impl std::ops::Deref for ObserveUntil {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

impl Serialize for ObserveUntil {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for ObserveUntil {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        let trimmed = raw.trim();
        Ok(Self {
            raw: trimmed.to_string(),
            parsed_utc: parse_timestamp_as_utc(trimmed),
        })
    }
}

fn parse_timestamp_as_utc(value: &str) -> Option<DateTime<Utc>> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    // RFC 3339 (e.g., "2030-01-01T00:00:00Z" or "2030-01-01T00:00:00+00:00")
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(value) {
        return Some(dt.with_timezone(&Utc));
    }

    // ISO 8601 without timezone (treat as UTC)
    if let Ok(dt) = NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S") {
        return Some(dt.and_utc());
    }

    // Date only (YYYY-MM-DD) - treat as end of day UTC (23:59:59)
    if let Ok(date) = NaiveDate::parse_from_str(value, "%Y-%m-%d") {
        if let Some(end_of_day) = date.and_hms_opt(23, 59, 59) {
            return Some(end_of_day.and_utc());
        }
        return None;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.general.color, "auto");
        assert!(config.packs.enabled.is_empty());
    }

    #[test]
    fn test_enabled_pack_ids_includes_core() {
        let config = Config::default();
        let enabled = config.enabled_pack_ids();
        assert!(enabled.contains("core"));
    }

    #[test]
    fn test_enabled_pack_ids_respects_disabled() {
        let config = Config {
            packs: PacksConfig {
                enabled: vec!["kubernetes".to_string(), "kubernetes.helm".to_string()],
                disabled: vec!["kubernetes.helm".to_string()],
            },
            ..Default::default()
        };
        let enabled = config.enabled_pack_ids();
        assert!(enabled.contains("kubernetes"));
        assert!(!enabled.contains("kubernetes.helm"));
    }

    #[test]
    fn test_enabled_pack_ids_uses_project_override() {
        let cwd = std::env::current_dir().expect("current_dir");

        let mut config = Config::default();
        config.packs.enabled = vec!["kubernetes".to_string()];

        let mut projects = std::collections::HashMap::new();
        projects.insert(
            cwd.to_string_lossy().to_string(),
            ProjectConfig {
                packs: Some(PacksConfig {
                    enabled: vec!["database.postgresql".to_string()],
                    disabled: Vec::new(),
                }),
                overrides: None,
            },
        );
        config.projects = projects;

        let enabled = config.enabled_pack_ids();
        assert!(enabled.contains("database.postgresql"));
        assert!(!enabled.contains("kubernetes"));
    }

    #[test]
    fn test_allow_override_simple() {
        let override_ = AllowOverride::Simple("test pattern".to_string());
        assert_eq!(override_.pattern(), "test pattern");
        assert!(override_.condition_met());
    }

    #[test]
    fn test_allow_override_conditional_no_condition() {
        let override_ = AllowOverride::Conditional {
            pattern: "test pattern".to_string(),
            when: None,
        };
        assert!(override_.condition_met());
    }

    #[test]
    fn test_sample_config_parses() {
        let sample = Config::generate_sample_config();
        // Remove comment lines for parsing test
        let _config: Result<Config, _> = toml::from_str(&sample);
        // Note: The sample has comments which toml handles fine
    }

    #[test]
    fn test_history_config_defaults() {
        let config = HistoryConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.redaction_mode, HistoryRedactionMode::Pattern);
        assert_eq!(config.retention_days, HistoryConfig::DEFAULT_RETENTION_DAYS);
        assert_eq!(config.max_size_mb, HistoryConfig::DEFAULT_MAX_SIZE_MB);
    }

    #[test]
    fn test_history_config_from_toml() {
        let input = r#"
[history]
enabled = true
redaction_mode = "full"
retention_days = 30
max_size_mb = 250
database_path = "/tmp/dcg-history.db"
"#;
        let config: Config = toml::from_str(input).expect("config parses");
        assert!(config.history.enabled);
        assert_eq!(config.history.redaction_mode, HistoryRedactionMode::Full);
        assert_eq!(config.history.retention_days, 30);
        assert_eq!(config.history.max_size_mb, 250);
        assert_eq!(
            config.history.database_path.as_deref(),
            Some("/tmp/dcg-history.db")
        );
    }

    #[test]
    fn test_history_redaction_mode_parsing() {
        assert_eq!(
            HistoryRedactionMode::from_str("none").expect("none"),
            HistoryRedactionMode::None
        );
        assert_eq!(
            HistoryRedactionMode::from_str("pattern").expect("pattern"),
            HistoryRedactionMode::Pattern
        );
        assert_eq!(
            HistoryRedactionMode::from_str("full").expect("full"),
            HistoryRedactionMode::Full
        );
        assert!(HistoryRedactionMode::from_str("invalid").is_err());
    }

    #[test]
    fn test_history_env_overrides() {
        let env_map: std::collections::HashMap<&str, &str> = std::collections::HashMap::from([
            ("DCG_HISTORY_ENABLED", "true"),
            ("DCG_HISTORY_REDACTION_MODE", "full"),
        ]);
        let mut config = Config::default();
        config.apply_env_overrides_from(|key| env_map.get(key).map(|v| (*v).to_string()));

        assert!(config.history.enabled);
        assert_eq!(config.history.redaction_mode, HistoryRedactionMode::Full);
    }

    #[test]
    fn test_history_database_path_expansion() {
        if dirs::home_dir().is_none() {
            return;
        }

        let config = HistoryConfig {
            database_path: Some("~/.config/dcg/history.db".to_string()),
            ..Default::default()
        };
        let expanded = config
            .expanded_database_path()
            .expect("expanded database path");
        assert!(!expanded.to_string_lossy().contains('~'));
        assert!(expanded.to_string_lossy().contains("dcg"));
    }

    #[test]
    fn test_history_retention_validation() {
        let config = HistoryConfig {
            retention_days: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config = HistoryConfig {
            retention_days: HistoryConfig::MAX_RETENTION_DAYS + 1,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config = HistoryConfig {
            retention_days: HistoryConfig::DEFAULT_RETENTION_DAYS,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_merge() {
        let mut base = Config::default();
        let layer: ConfigLayer = toml::from_str(
            r#"
[packs]
enabled = ["database.postgresql"]
"#,
        )
        .expect("layer parses");
        base.merge_layer(layer);
        assert!(
            base.packs
                .enabled
                .contains(&"database.postgresql".to_string())
        );
    }

    #[test]
    fn test_config_merge_merges_heredoc_allowlist() {
        let mut base = Config::default();
        base.heredoc.allowlist = Some(HeredocAllowlistConfig {
            commands: vec!["cmd1".to_string()],
            ..Default::default()
        });

        let other = ConfigLayer {
            heredoc: Some(HeredocConfig {
                allowlist: Some(HeredocAllowlistConfig {
                    commands: vec!["cmd2".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        base.merge_layer(other);

        let allowlist = base.heredoc.allowlist.as_ref().expect("allowlist merged");
        assert!(allowlist.commands.contains(&"cmd1".to_string()));
        assert!(allowlist.commands.contains(&"cmd2".to_string()));
    }

    #[test]
    fn test_config_merge_layer_general_verbose_can_be_disabled() {
        let mut config = Config::default();
        config.general.verbose = true;

        let layer: ConfigLayer = toml::from_str(
            r"
[general]
verbose = false
",
        )
        .expect("layer parses");
        config.merge_layer(layer);

        assert!(!config.general.verbose);
    }

    #[test]
    fn test_config_merge_layer_general_missing_fields_do_not_override() {
        let mut config = Config::default();
        config.general.verbose = true;

        let layer: ConfigLayer = toml::from_str(
            r#"
[general]
color = "never"
"#,
        )
        .expect("layer parses");
        config.merge_layer(layer);

        assert!(config.general.verbose);
        assert_eq!(config.general.color, "never");
    }

    #[test]
    fn test_config_merge_layer_logging_is_reversible() {
        let mut config = Config::default();
        config.logging.enabled = true;
        config.logging.format = crate::logging::LogFormat::Json;
        config.logging.events.deny = false;
        config.logging.events.warn = false;
        config.logging.events.allow = true;

        let layer: ConfigLayer = toml::from_str(
            r#"
[logging]
enabled = false
format = "text"

[logging.events]
deny = true
warn = true
allow = false
"#,
        )
        .expect("layer parses");
        config.merge_layer(layer);

        assert!(!config.logging.enabled);
        assert_eq!(config.logging.format, crate::logging::LogFormat::Text);
        assert!(config.logging.events.deny);
        assert!(config.logging.events.warn);
        assert!(!config.logging.events.allow);
    }

    #[test]
    fn test_heredoc_settings_defaults() {
        let config = Config::default();
        let settings = config.heredoc_settings();
        assert!(settings.enabled);
        assert_eq!(settings.limits.timeout_ms, 50);
        assert!(settings.allowed_languages.is_none());
        assert!(settings.fallback_on_parse_error);
        assert!(settings.fallback_on_timeout);
    }

    #[test]
    fn test_heredoc_env_overrides_enabled_timeout_languages() {
        let env_map: std::collections::HashMap<&str, &str> = std::collections::HashMap::from([
            ("DCG_HEREDOC_ENABLED", "0"),
            ("DCG_HEREDOC_TIMEOUT_MS", "123"),
            ("DCG_HEREDOC_LANGUAGES", "python, bash, js, unknown_value"),
        ]);
        let mut config = Config::default();
        config.apply_env_overrides_from(|key| env_map.get(key).map(|v| (*v).to_string()));

        let settings = config.heredoc_settings();
        assert!(!settings.enabled);
        assert_eq!(settings.limits.timeout_ms, 123);
        assert_eq!(
            settings.allowed_languages,
            Some(vec![
                crate::heredoc::ScriptLanguage::Python,
                crate::heredoc::ScriptLanguage::Bash,
                crate::heredoc::ScriptLanguage::JavaScript
            ])
        );
    }

    #[test]
    fn test_heredoc_language_filter_all_is_treated_as_unfiltered() {
        let mut config = Config::default();
        config.heredoc.languages = Some(vec!["all".to_string(), "python".to_string()]);
        let settings = config.heredoc_settings();
        assert!(settings.allowed_languages.is_none());
    }

    #[test]
    fn test_heredoc_language_filter_invalid_only_falls_back_to_all() {
        let mut config = Config::default();
        config.heredoc.languages = Some(vec!["definitely_not_a_language".to_string()]);
        let settings = config.heredoc_settings();
        assert!(settings.allowed_languages.is_none());
    }

    #[test]
    fn test_find_repo_root_finds_git_within_limit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_root = temp.path().join("repo");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");
        let deep = repo_root.join("a/b/c");
        std::fs::create_dir_all(&deep).expect("create deep dir");

        let found = find_repo_root(&deep, 10).expect("repo root found");
        assert_eq!(found, repo_root);
    }

    #[test]
    fn test_find_repo_root_respects_hop_limit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_root = temp.path().join("repo");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");
        let deep = repo_root.join("a/b/c");
        std::fs::create_dir_all(&deep).expect("create deep dir");

        // With a hop limit of 1, we shouldn't reach the repo root from a/b/c.
        assert!(find_repo_root(&deep, 1).is_none());
    }

    // ========================================================================
    // CompiledOverrides Tests (git_safety_guard-99e.4.1)
    // ========================================================================

    #[test]
    fn test_compile_simple_allow_override() {
        let overrides = OverridesConfig {
            allow: vec![AllowOverride::Simple("git reset --hard".to_string())],
            block: vec![],
        };
        let compiled = overrides.compile();

        assert_eq!(compiled.allow.len(), 1);
        assert!(compiled.invalid_patterns.is_empty());
        assert!(compiled.check_allow("git reset --hard"));
        assert!(!compiled.check_allow("git status"));
    }

    #[test]
    fn test_compile_block_override() {
        let overrides = OverridesConfig {
            allow: vec![],
            block: vec![BlockOverride {
                pattern: "dangerous-command".to_string(),
                reason: "This is dangerous!".to_string(),
            }],
        };
        let compiled = overrides.compile();

        assert_eq!(compiled.block.len(), 1);
        assert!(compiled.invalid_patterns.is_empty());
        assert_eq!(
            compiled.check_block("dangerous-command --force"),
            Some("This is dangerous!")
        );
        assert_eq!(compiled.check_block("safe-command"), None);
    }

    #[test]
    fn test_compile_invalid_regex_fails_open() {
        let overrides = OverridesConfig {
            allow: vec![AllowOverride::Simple("[invalid regex".to_string())],
            block: vec![BlockOverride {
                pattern: "[also invalid".to_string(),
                reason: "Won't compile".to_string(),
            }],
        };
        let compiled = overrides.compile();

        // Invalid patterns should NOT be in the compiled lists
        assert!(compiled.allow.is_empty());
        assert!(compiled.block.is_empty());

        // But they should be recorded in invalid_patterns
        assert_eq!(compiled.invalid_patterns.len(), 2);
        assert!(compiled.has_invalid_patterns());

        // Check that we recorded the right kinds
        assert!(
            compiled
                .invalid_patterns
                .iter()
                .any(|p| p.kind == PatternKind::Allow)
        );
        assert!(
            compiled
                .invalid_patterns
                .iter()
                .any(|p| p.kind == PatternKind::Block)
        );
    }

    #[test]
    fn test_compile_conditional_override_always() {
        let overrides = OverridesConfig {
            allow: vec![AllowOverride::Conditional {
                pattern: "test-pattern".to_string(),
                when: None,
            }],
            block: vec![],
        };
        let compiled = overrides.compile();

        assert_eq!(compiled.allow.len(), 1);
        // With no condition, it should always match
        assert!(compiled.check_allow("test-pattern"));
    }

    #[test]
    fn test_compile_regex_pattern() {
        let overrides = OverridesConfig {
            allow: vec![AllowOverride::Simple(
                r"kubectl delete namespace test-\d+".to_string(),
            )],
            block: vec![],
        };
        let compiled = overrides.compile();

        assert!(compiled.check_allow("kubectl delete namespace test-123"));
        assert!(compiled.check_allow("kubectl delete namespace test-999"));
        assert!(!compiled.check_allow("kubectl delete namespace production"));
    }

    #[test]
    fn test_compiled_overrides_engine_selection_lookahead_vs_linear() {
        let overrides = OverridesConfig {
            allow: vec![
                // Lookahead -> must use backtracking engine.
                AllowOverride::Simple(r"git\s+push\s+.*--force(?![-a-z])".to_string()),
                // No lookaround/backrefs -> should use linear engine.
                AllowOverride::Simple(r"test-\d+".to_string()),
            ],
            block: vec![],
        };
        let compiled = overrides.compile();

        assert_eq!(compiled.allow.len(), 2);
        assert!(compiled.invalid_patterns.is_empty());

        assert!(
            compiled.allow[0].regex.uses_backtracking(),
            "lookahead patterns must route to fancy_regex"
        );
        assert!(
            !compiled.allow[1].regex.uses_backtracking(),
            "patterns without lookaround/backrefs should route to regex::Regex"
        );

        assert!(compiled.check_allow("git push --force"));
        assert!(compiled.check_allow("git push origin main --force"));
        assert!(!compiled.check_allow("git push --force-with-lease"));

        assert!(compiled.check_allow("test-123"));
        assert!(!compiled.check_allow("test-abc"));
    }

    #[test]
    fn test_compiled_block_override_engine_selection_backreference() {
        let overrides = OverridesConfig {
            allow: vec![],
            block: vec![BlockOverride {
                pattern: r"(\w+)\s+\1".to_string(),
                reason: "duplicate word".to_string(),
            }],
        };
        let compiled = overrides.compile();

        assert_eq!(compiled.block.len(), 1);
        assert!(compiled.invalid_patterns.is_empty());
        assert!(
            compiled.block[0].regex.uses_backtracking(),
            "backreference patterns must route to fancy_regex"
        );

        assert_eq!(compiled.check_block("hello hello"), Some("duplicate word"));
        assert_eq!(compiled.check_block("hello world"), None);
    }

    #[test]
    fn test_compiled_overrides_check_order() {
        // Allow takes precedence (checked first in evaluator)
        let overrides = OverridesConfig {
            allow: vec![AllowOverride::Simple("test-command".to_string())],
            block: vec![BlockOverride {
                pattern: "test-command".to_string(),
                reason: "Blocked!".to_string(),
            }],
        };
        let compiled = overrides.compile();

        // Both patterns match
        assert!(compiled.check_allow("test-command"));
        assert!(compiled.check_block("test-command").is_some());

        // In the evaluator, allow is checked first, so command would be allowed
    }

    #[test]
    fn test_compiled_overrides_empty() {
        let overrides = OverridesConfig::default();
        let compiled = overrides.compile();

        assert!(compiled.allow.is_empty());
        assert!(compiled.block.is_empty());
        assert!(!compiled.has_invalid_patterns());
        assert!(!compiled.check_allow("anything"));
        assert!(compiled.check_block("anything").is_none());
    }

    #[test]
    fn test_compiled_overrides_multiple_patterns() {
        let overrides = OverridesConfig {
            allow: vec![
                AllowOverride::Simple("pattern-a".to_string()),
                AllowOverride::Simple("pattern-b".to_string()),
            ],
            block: vec![
                BlockOverride {
                    pattern: "block-1".to_string(),
                    reason: "Reason 1".to_string(),
                },
                BlockOverride {
                    pattern: "block-2".to_string(),
                    reason: "Reason 2".to_string(),
                },
            ],
        };
        let compiled = overrides.compile();

        assert!(compiled.check_allow("pattern-a"));
        assert!(compiled.check_allow("pattern-b"));
        assert!(!compiled.check_allow("pattern-c"));

        assert_eq!(compiled.check_block("block-1"), Some("Reason 1"));
        assert_eq!(compiled.check_block("block-2"), Some("Reason 2"));
        assert_eq!(compiled.check_block("block-3"), None);
    }

    // ========================================================================
    // PolicyConfig Tests (git_safety_guard-1gt.3)
    // ========================================================================

    #[test]
    fn test_policy_mode_to_decision_mode() {
        assert_eq!(
            PolicyMode::Deny.to_decision_mode(),
            crate::packs::DecisionMode::Deny
        );
        assert_eq!(
            PolicyMode::Warn.to_decision_mode(),
            crate::packs::DecisionMode::Warn
        );
        assert_eq!(
            PolicyMode::Log.to_decision_mode(),
            crate::packs::DecisionMode::Log
        );
    }

    #[test]
    fn test_policy_resolve_mode_rule_override_takes_precedence() {
        let policy = PolicyConfig {
            default_mode: Some(PolicyMode::Deny),
            observe_until: None,
            packs: std::collections::HashMap::from([("core.git".to_string(), PolicyMode::Warn)]),
            rules: std::collections::HashMap::from([(
                "core.git:reset-hard".to_string(),
                PolicyMode::Log,
            )]),
        };

        // Rule-specific override should win
        let mode = policy.resolve_mode(
            Some("core.git"),
            Some("reset-hard"),
            Some(crate::packs::Severity::High),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Log);
    }

    #[test]
    fn test_policy_resolve_mode_pack_override_when_no_rule() {
        let policy = PolicyConfig {
            default_mode: Some(PolicyMode::Deny),
            packs: std::collections::HashMap::from([("core.git".to_string(), PolicyMode::Warn)]),
            ..Default::default()
        };

        // No rule override, so pack override wins
        let mode = policy.resolve_mode(
            Some("core.git"),
            Some("push-force"),
            Some(crate::packs::Severity::High),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Warn);
    }

    #[test]
    fn test_policy_resolve_mode_global_default_when_no_pack() {
        let policy = PolicyConfig {
            default_mode: Some(PolicyMode::Log),
            ..Default::default()
        };

        // No pack override, so global default wins
        let mode = policy.resolve_mode(
            Some("containers.docker"),
            Some("prune"),
            Some(crate::packs::Severity::Medium),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Log);
    }

    #[test]
    fn test_policy_resolve_mode_severity_default_when_nothing_set() {
        let policy = PolicyConfig::default();

        // High severity defaults to Deny
        let mode_high = policy.resolve_mode(
            Some("core.git"),
            Some("reset-hard"),
            Some(crate::packs::Severity::High),
        );
        assert_eq!(mode_high, crate::packs::DecisionMode::Deny);

        // Medium severity defaults to Warn
        let mode_medium = policy.resolve_mode(
            Some("core.git"),
            Some("something"),
            Some(crate::packs::Severity::Medium),
        );
        assert_eq!(mode_medium, crate::packs::DecisionMode::Warn);

        // Low severity defaults to Log
        let mode_low = policy.resolve_mode(
            Some("core.git"),
            Some("something"),
            Some(crate::packs::Severity::Low),
        );
        assert_eq!(mode_low, crate::packs::DecisionMode::Log);
    }

    #[test]
    fn test_policy_resolve_mode_critical_cannot_be_loosened_by_pack() {
        let mut policy = PolicyConfig::default();
        policy
            .packs
            .insert("core.git".to_string(), PolicyMode::Warn);

        // Critical severity should ALWAYS be Deny, even with pack override
        let mode = policy.resolve_mode(
            Some("core.git"),
            Some("reset-hard"),
            Some(crate::packs::Severity::Critical),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Deny);
    }

    #[test]
    fn test_policy_resolve_mode_critical_cannot_be_loosened_by_global() {
        let policy = PolicyConfig {
            default_mode: Some(PolicyMode::Log),
            ..Default::default()
        };

        // Critical severity should ALWAYS be Deny, even with global override
        let mode = policy.resolve_mode(
            Some("core.git"),
            Some("reset-hard"),
            Some(crate::packs::Severity::Critical),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Deny);
    }

    #[test]
    fn test_policy_resolve_mode_critical_can_be_loosened_by_rule() {
        let mut policy = PolicyConfig::default();
        policy
            .rules
            .insert("core.git:reset-hard".to_string(), PolicyMode::Warn);

        // Critical CAN be loosened via explicit per-rule override
        let mode = policy.resolve_mode(
            Some("core.git"),
            Some("reset-hard"),
            Some(crate::packs::Severity::Critical),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Warn);
    }

    #[test]
    fn test_policy_resolve_mode_no_severity_defaults_to_deny() {
        let policy = PolicyConfig::default();

        // No severity provided should default to Deny
        let mode = policy.resolve_mode(Some("core.git"), Some("pattern"), None);
        assert_eq!(mode, crate::packs::DecisionMode::Deny);
    }

    #[test]
    fn test_policy_env_override_default_mode() {
        let env_map: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::from([("DCG_POLICY_DEFAULT_MODE", "warn")]);

        let mut config = Config::default();
        config.apply_env_overrides_from(|key| env_map.get(key).map(|v| (*v).to_string()));

        assert_eq!(config.policy.default_mode, Some(PolicyMode::Warn));
    }

    #[test]
    fn test_policy_env_override_observe_until() {
        let env_map: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::from([("DCG_POLICY_OBSERVE_UNTIL", "2030-01-01T00:00:00Z")]);

        let mut config = Config::default();
        config.apply_env_overrides_from(|key| env_map.get(key).map(|v| (*v).to_string()));

        assert_eq!(
            config.policy.observe_until.as_deref(),
            Some("2030-01-01T00:00:00Z")
        );
    }

    #[test]
    fn test_policy_env_override_parses_all_modes() {
        for (input, expected) in [
            ("deny", Some(PolicyMode::Deny)),
            ("block", Some(PolicyMode::Deny)),
            ("warn", Some(PolicyMode::Warn)),
            ("warning", Some(PolicyMode::Warn)),
            ("log", Some(PolicyMode::Log)),
            ("log-only", Some(PolicyMode::Log)),
            ("logonly", Some(PolicyMode::Log)),
            ("DENY", Some(PolicyMode::Deny)), // case-insensitive
            ("invalid", None),
        ] {
            let result = parse_policy_mode(input);
            assert_eq!(result, expected, "parse_policy_mode({input:?}) mismatch");
        }
    }

    #[test]
    fn test_policy_config_merge() {
        let mut base = Config::default();
        base.policy.default_mode = Some(PolicyMode::Deny);
        base.policy.observe_until = ObserveUntil::parse("2000-01-01T00:00:00Z");
        base.policy
            .packs
            .insert("core.git".to_string(), PolicyMode::Deny);

        let other = ConfigLayer {
            policy: Some(PolicyConfig {
                default_mode: Some(PolicyMode::Warn),
                observe_until: ObserveUntil::parse("2030-01-01T00:00:00Z"),
                packs: std::collections::HashMap::from([(
                    "containers.docker".to_string(),
                    PolicyMode::Log,
                )]),
                rules: std::collections::HashMap::from([(
                    "core.git:reset-hard".to_string(),
                    PolicyMode::Log,
                )]),
            }),
            ..Default::default()
        };

        base.merge_layer(other);

        // Other's default_mode should win
        assert_eq!(base.policy.default_mode, Some(PolicyMode::Warn));
        // Other's observe_until should win
        assert_eq!(
            base.policy.observe_until.as_deref(),
            Some("2030-01-01T00:00:00Z")
        );
        // Both packs should be present
        assert_eq!(base.policy.packs.get("core.git"), Some(&PolicyMode::Deny));
        assert_eq!(
            base.policy.packs.get("containers.docker"),
            Some(&PolicyMode::Log)
        );
        // Rules should be merged
        assert_eq!(
            base.policy.rules.get("core.git:reset-hard"),
            Some(&PolicyMode::Log)
        );
    }

    #[test]
    fn test_sample_config_includes_policy_section() {
        let sample = Config::generate_sample_config();
        assert!(
            sample.contains("[policy]"),
            "Sample config should have [policy] section"
        );
        assert!(
            sample.contains("default_mode"),
            "Sample config should mention default_mode"
        );
        assert!(
            sample.contains("observe_until"),
            "Sample config should mention observe_until"
        );
        assert!(
            sample.contains("[policy.packs]"),
            "Sample config should have [policy.packs]"
        );
        assert!(
            sample.contains("[policy.rules]"),
            "Sample config should have [policy.rules]"
        );
    }

    // ========================================================================
    // Observe mode tests (git_safety_guard-1gt.3.3)
    // ========================================================================

    #[test]
    fn test_policy_observe_window_active_defaults_to_warn_when_unset() {
        let policy = PolicyConfig {
            observe_until: ObserveUntil::parse("2030-01-01T00:00:00Z"),
            ..Default::default()
        };

        let now = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);

        let mode = policy.resolve_mode_at(
            now,
            Some("core.git"),
            Some("push-force-long"),
            Some(crate::packs::Severity::High),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Warn);
    }

    #[test]
    fn test_policy_observe_window_expired_ignores_default_mode() {
        let policy = PolicyConfig {
            default_mode: Some(PolicyMode::Warn),
            observe_until: ObserveUntil::parse("2026-01-01T00:00:00Z"),
            ..Default::default()
        };

        let now = chrono::DateTime::parse_from_rfc3339("2026-01-02T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);

        let mode = policy.resolve_mode_at(
            now,
            Some("core.git"),
            Some("push-force-long"),
            Some(crate::packs::Severity::High),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Deny);
    }

    #[test]
    fn test_policy_observe_window_active_does_not_loosen_critical_without_rule_override() {
        let policy = PolicyConfig {
            default_mode: Some(PolicyMode::Warn),
            observe_until: ObserveUntil::parse("2030-01-01T00:00:00Z"),
            ..Default::default()
        };

        let now = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);

        let mode = policy.resolve_mode_at(
            now,
            Some("core.git"),
            Some("reset-hard"),
            Some(crate::packs::Severity::Critical),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Deny);
    }

    // ========================================================================
    // Heredoc allowlist tests (git_safety_guard-cpal)
    // ========================================================================

    #[test]
    fn test_heredoc_allowlist_command_match() {
        let allowlist = HeredocAllowlistConfig {
            commands: vec![
                "./scripts/approved.sh".to_string(),
                "/opt/company/tool".to_string(),
            ],
            ..Default::default()
        };

        assert_eq!(
            allowlist.is_command_allowlisted("./scripts/approved.sh arg1"),
            Some("./scripts/approved.sh")
        );
        assert_eq!(
            allowlist.is_command_allowlisted("/opt/company/tool --flag"),
            Some("/opt/company/tool")
        );
        assert_eq!(allowlist.is_command_allowlisted("./scripts/other.sh"), None);
    }

    #[test]
    fn test_heredoc_allowlist_pattern_match() {
        let allowlist = HeredocAllowlistConfig {
            patterns: vec![
                AllowedHeredocPattern {
                    language: Some("python".to_string()),
                    pattern: "company_tool.cleanup()".to_string(),
                    reason: "Internal tool".to_string(),
                },
                AllowedHeredocPattern {
                    language: None, // any language
                    pattern: "safe_command".to_string(),
                    reason: "Known safe".to_string(),
                },
            ],
            ..Default::default()
        };

        // Python pattern matches python content
        let hit = allowlist.is_content_allowlisted(
            "import company_tool\ncompany_tool.cleanup()",
            crate::heredoc::ScriptLanguage::Python,
            None,
        );
        assert!(hit.is_some());
        let hit = hit.unwrap();
        assert_eq!(hit.kind, HeredocAllowlistHitKind::Pattern);
        assert_eq!(hit.matched, "company_tool.cleanup()");

        // Python pattern does NOT match bash content
        let hit = allowlist.is_content_allowlisted(
            "company_tool.cleanup()",
            crate::heredoc::ScriptLanguage::Bash,
            None,
        );
        assert!(hit.is_none());

        // Language-agnostic pattern matches any language
        let hit = allowlist.is_content_allowlisted(
            "run safe_command here",
            crate::heredoc::ScriptLanguage::Bash,
            None,
        );
        assert!(hit.is_some());
    }

    #[test]
    fn test_heredoc_allowlist_hash_match() {
        let content = "specific content to hash";
        let hash = super::content_hash(content);
        assert_eq!(
            hash,
            "71bc8277a3e8d59ec84d4fb69364fcb43805a24d451705e1d5a6d826d1dc644b"
        );

        let allowlist = HeredocAllowlistConfig {
            content_hashes: vec![ContentHashEntry {
                hash: hash.clone(),
                reason: "Approved script".to_string(),
            }],
            ..Default::default()
        };

        let hit =
            allowlist.is_content_allowlisted(content, crate::heredoc::ScriptLanguage::Bash, None);
        assert!(hit.is_some());
        let hit = hit.unwrap();
        assert_eq!(hit.kind, HeredocAllowlistHitKind::ContentHash);
        assert_eq!(hit.matched, &hash);

        // Different content should not match
        let hit = allowlist.is_content_allowlisted(
            "different content",
            crate::heredoc::ScriptLanguage::Bash,
            None,
        );
        assert!(hit.is_none());
    }

    #[test]
    fn test_heredoc_allowlist_project_scope() {
        let allowlist = HeredocAllowlistConfig {
            projects: vec![ProjectHeredocAllowlist {
                path: "/home/user/trusted-project".to_string(),
                patterns: vec![AllowedHeredocPattern {
                    language: Some("bash".to_string()),
                    pattern: "rm -rf ./build".to_string(),
                    reason: "Build cleanup".to_string(),
                }],
                content_hashes: vec![],
            }],
            ..Default::default()
        };

        // Match within project scope
        let hit = allowlist.is_content_allowlisted(
            "rm -rf ./build",
            crate::heredoc::ScriptLanguage::Bash,
            Some(std::path::Path::new("/home/user/trusted-project/src")),
        );
        assert!(hit.is_some());
        let hit = hit.unwrap();
        assert_eq!(hit.kind, HeredocAllowlistHitKind::ProjectPattern);

        // No match outside project scope
        let hit = allowlist.is_content_allowlisted(
            "rm -rf ./build",
            crate::heredoc::ScriptLanguage::Bash,
            Some(std::path::Path::new("/home/user/other-project")),
        );
        assert!(hit.is_none());

        // No match without project path
        let hit = allowlist.is_content_allowlisted(
            "rm -rf ./build",
            crate::heredoc::ScriptLanguage::Bash,
            None,
        );
        assert!(hit.is_none());
    }

    #[test]
    fn test_heredoc_allowlist_merge() {
        let mut base = HeredocAllowlistConfig {
            commands: vec!["cmd1".to_string()],
            patterns: vec![AllowedHeredocPattern {
                language: None,
                pattern: "pattern1".to_string(),
                reason: "reason1".to_string(),
            }],
            ..Default::default()
        };

        let other = HeredocAllowlistConfig {
            commands: vec!["cmd1".to_string(), "cmd2".to_string()], // cmd1 duplicate
            patterns: vec![AllowedHeredocPattern {
                language: None,
                pattern: "pattern2".to_string(),
                reason: "reason2".to_string(),
            }],
            ..Default::default()
        };

        base.merge(&other);

        // Duplicates should not be added
        assert_eq!(base.commands.len(), 2);
        assert!(base.commands.contains(&"cmd1".to_string()));
        assert!(base.commands.contains(&"cmd2".to_string()));

        // Both patterns should be present
        assert_eq!(base.patterns.len(), 2);
    }

    #[test]
    fn test_heredoc_allowlist_hit_kind_labels() {
        assert_eq!(HeredocAllowlistHitKind::ContentHash.label(), "content_hash");
        assert_eq!(HeredocAllowlistHitKind::Pattern.label(), "pattern");
        assert_eq!(
            HeredocAllowlistHitKind::ProjectContentHash.label(),
            "project_content_hash"
        );
        assert_eq!(
            HeredocAllowlistHitKind::ProjectPattern.label(),
            "project_pattern"
        );
    }

    #[test]
    fn test_heredoc_settings_includes_allowlist() {
        let config = HeredocConfig {
            allowlist: Some(HeredocAllowlistConfig {
                commands: vec!["test-cmd".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };

        let settings = config.settings();
        assert!(settings.content_allowlist.is_some());
        let allowlist = settings.content_allowlist.unwrap();
        assert_eq!(allowlist.commands.len(), 1);
    }

    #[test]
    fn test_heredoc_allowlist_project_path_no_false_positive() {
        // Regression test: "/home/user/project" should NOT match "/home/user/project-other"
        let allowlist = HeredocAllowlistConfig {
            projects: vec![ProjectHeredocAllowlist {
                path: "/home/user/project".to_string(),
                patterns: vec![AllowedHeredocPattern {
                    language: Some("bash".to_string()),
                    pattern: "dangerous command".to_string(),
                    reason: "Test".to_string(),
                }],
                content_hashes: vec![],
            }],
            ..Default::default()
        };

        // Should NOT match: project-other is a different project
        let hit = allowlist.is_content_allowlisted(
            "dangerous command",
            crate::heredoc::ScriptLanguage::Bash,
            Some(std::path::Path::new("/home/user/project-other/src")),
        );
        assert!(hit.is_none(), "Should not match project-other");

        // Should NOT match: projects is a different project
        let hit = allowlist.is_content_allowlisted(
            "dangerous command",
            crate::heredoc::ScriptLanguage::Bash,
            Some(std::path::Path::new("/home/user/projects/src")),
        );
        assert!(hit.is_none(), "Should not match 'projects'");

        // SHOULD match: exact path
        let hit = allowlist.is_content_allowlisted(
            "dangerous command",
            crate::heredoc::ScriptLanguage::Bash,
            Some(std::path::Path::new("/home/user/project")),
        );
        assert!(hit.is_some(), "Should match exact path");

        // SHOULD match: subdirectory of project
        let hit = allowlist.is_content_allowlisted(
            "dangerous command",
            crate::heredoc::ScriptLanguage::Bash,
            Some(std::path::Path::new("/home/user/project/src/lib")),
        );
        assert!(hit.is_some(), "Should match subdirectory");
    }

    #[test]
    fn test_heredoc_allowlist_language_aliases() {
        // Test that language aliases like "js", "sh", "py" work
        let allowlist = HeredocAllowlistConfig {
            patterns: vec![
                AllowedHeredocPattern {
                    language: Some("js".to_string()), // alias for javascript
                    pattern: "console.log".to_string(),
                    reason: "JS logging".to_string(),
                },
                AllowedHeredocPattern {
                    language: Some("sh".to_string()), // alias for bash
                    pattern: "echo hello".to_string(),
                    reason: "Shell echo".to_string(),
                },
                AllowedHeredocPattern {
                    language: Some("py".to_string()), // alias for python
                    pattern: "print".to_string(),
                    reason: "Python print".to_string(),
                },
                AllowedHeredocPattern {
                    language: Some("ts".to_string()), // alias for typescript
                    pattern: "interface".to_string(),
                    reason: "TS interface".to_string(),
                },
                AllowedHeredocPattern {
                    language: Some("node".to_string()), // alias for javascript
                    pattern: "require(".to_string(),
                    reason: "Node require".to_string(),
                },
            ],
            ..Default::default()
        };

        // "js" should match JavaScript
        let hit = allowlist.is_content_allowlisted(
            "console.log('hello')",
            crate::heredoc::ScriptLanguage::JavaScript,
            None,
        );
        assert!(hit.is_some(), "js alias should match JavaScript");

        // "sh" should match Bash
        let hit = allowlist.is_content_allowlisted(
            "echo hello",
            crate::heredoc::ScriptLanguage::Bash,
            None,
        );
        assert!(hit.is_some(), "sh alias should match Bash");

        // "py" should match Python
        let hit = allowlist.is_content_allowlisted(
            "print('hello')",
            crate::heredoc::ScriptLanguage::Python,
            None,
        );
        assert!(hit.is_some(), "py alias should match Python");

        // "ts" should match TypeScript
        let hit = allowlist.is_content_allowlisted(
            "interface Foo {}",
            crate::heredoc::ScriptLanguage::TypeScript,
            None,
        );
        assert!(hit.is_some(), "ts alias should match TypeScript");

        // "node" should match JavaScript
        let hit = allowlist.is_content_allowlisted(
            "const fs = require('fs')",
            crate::heredoc::ScriptLanguage::JavaScript,
            None,
        );
        assert!(hit.is_some(), "node alias should match JavaScript");

        // "js" should NOT match Python
        let hit = allowlist.is_content_allowlisted(
            "console.log('hello')",
            crate::heredoc::ScriptLanguage::Python,
            None,
        );
        assert!(hit.is_none(), "js alias should not match Python");
    }

    #[test]
    fn test_heredoc_allowlist_empty_pattern_does_not_match() {
        // Empty patterns should never match (security: prevents accidental allow-all)
        let allowlist = HeredocAllowlistConfig {
            patterns: vec![AllowedHeredocPattern {
                language: None,
                pattern: String::new(), // Empty pattern
                reason: "Empty pattern should not match".to_string(),
            }],
            ..Default::default()
        };

        // Empty pattern should NOT match any content
        let hit = allowlist.is_content_allowlisted(
            "rm -rf /",
            crate::heredoc::ScriptLanguage::Bash,
            None,
        );
        assert!(hit.is_none(), "Empty pattern should not match any content");

        // Even empty content should not match empty pattern
        let hit = allowlist.is_content_allowlisted("", crate::heredoc::ScriptLanguage::Bash, None);
        assert!(
            hit.is_none(),
            "Empty pattern should not match empty content"
        );
    }

    #[test]
    fn test_heredoc_allowlist_empty_command_prefix_does_not_match() {
        // Empty command prefixes should never match (security: prevents accidental allow-all)
        let allowlist = HeredocAllowlistConfig {
            commands: vec![String::new()], // Empty command prefix
            ..Default::default()
        };

        // Empty prefix should NOT match any command
        assert!(
            allowlist.is_command_allowlisted("rm -rf /").is_none(),
            "Empty command prefix should not match any command"
        );

        // Even empty command should not match empty prefix
        assert!(
            allowlist.is_command_allowlisted("").is_none(),
            "Empty command prefix should not match empty command"
        );
    }

    #[test]
    fn test_heredoc_allowlist_empty_project_path_does_not_match() {
        // Empty project paths should never match (security: prevents accidental allow-all)
        let allowlist = HeredocAllowlistConfig {
            projects: vec![ProjectHeredocAllowlist {
                path: String::new(), // Empty project path
                patterns: vec![AllowedHeredocPattern {
                    language: None,
                    pattern: "rm".to_string(),
                    reason: "Test pattern".to_string(),
                }],
                content_hashes: vec![],
            }],
            ..Default::default()
        };

        // Empty project path should NOT match any project
        let hit = allowlist.is_content_allowlisted(
            "rm -rf /",
            crate::heredoc::ScriptLanguage::Bash,
            Some(std::path::Path::new("/home/user/project")),
        );
        assert!(
            hit.is_none(),
            "Empty project path should not match any project"
        );
    }

    #[test]
    fn test_heredoc_allowlist_empty_language_filter_matches_all() {
        // Empty language filter should match all languages (same as `language: None`)
        let allowlist = HeredocAllowlistConfig {
            patterns: vec![AllowedHeredocPattern {
                language: Some(String::new()), // Empty language filter
                pattern: "test_pattern".to_string(),
                reason: "Empty language should match all".to_string(),
            }],
            ..Default::default()
        };

        // Empty language filter should match Bash
        let hit = allowlist.is_content_allowlisted(
            "test_pattern here",
            crate::heredoc::ScriptLanguage::Bash,
            None,
        );
        assert!(hit.is_some(), "Empty language filter should match Bash");

        // Empty language filter should match Python
        let hit = allowlist.is_content_allowlisted(
            "test_pattern here",
            crate::heredoc::ScriptLanguage::Python,
            None,
        );
        assert!(hit.is_some(), "Empty language filter should match Python");

        // Empty language filter should match JavaScript
        let hit = allowlist.is_content_allowlisted(
            "test_pattern here",
            crate::heredoc::ScriptLanguage::JavaScript,
            None,
        );
        assert!(
            hit.is_some(),
            "Empty language filter should match JavaScript"
        );
    }
}
