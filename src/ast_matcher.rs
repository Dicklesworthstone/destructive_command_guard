//! AST-based pattern matching for heredoc and inline script content.
//!
//! This module implements Tier 3 of the heredoc detection architecture,
//! using ast-grep-core for structural pattern matching.
//!
//! # Architecture
//!
//! ```text
//! Content + Language
//!      │
//!      ▼
//! ┌─────────────────┐
//! │   AstMatcher    │ ─── Parse error ──► ALLOW + diagnostic
//! │   (ast-grep)    │ ─── Timeout ──► ALLOW + diagnostic
//! │   <5ms typical  │ ─── No match ──► ALLOW
//! │   20ms max      │ ─── Match ──► BLOCK
//! └─────────────────┘
//! ```
//!
//! # Error Handling
//!
//! All errors result in fail-open behavior (ALLOW) with diagnostics:
//! - Parse errors: Language syntax not recognized
//! - Timeouts: Pattern matching exceeded time budget
//! - Unknown language: No grammar available
//!
//! # Performance
//!
//! - Pattern compilation: One-time at startup
//! - Parse: <2ms for typical heredoc sizes
//! - Match: <1ms typical
//! - Hard timeout: 20ms

use crate::heredoc::ScriptLanguage;
use ast_grep_core::{AstGrep, Pattern};
use ast_grep_language::SupportLang;
use memchr::memchr_iter;
use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

/// Hard timeout for AST operations (20ms as per ADR).
const AST_TIMEOUT_MS: u64 = 20;

/// Severity level for pattern matches.
///
/// Determines the default action taken when a pattern matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    /// Always block - no allowlist override without explicit config.
    Critical,
    /// Block by default, can be allowlisted.
    High,
    /// Warn by default (log but don't block).
    Medium,
    /// Log only - informational.
    Low,
}

impl Severity {
    /// Human-readable label for this severity.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    /// Whether this severity should block by default.
    #[must_use]
    pub const fn blocks_by_default(&self) -> bool {
        matches!(self, Self::Critical | Self::High)
    }
}

/// Result of a pattern match.
#[derive(Debug, Clone)]
pub struct PatternMatch {
    /// Stable rule ID for allowlisting (e.g., `heredoc.python.subprocess_rm`).
    pub rule_id: String,
    /// Human-readable reason for the match.
    pub reason: String,
    /// Preview of the matched text (truncated if too long).
    pub matched_text_preview: String,
    /// Byte offset of match start in the content.
    pub start: usize,
    /// Byte offset of match end in the content.
    pub end: usize,
    /// 1-based line number where match starts.
    pub line_number: usize,
    /// Severity level of this match.
    pub severity: Severity,
    /// Optional suggestion for safe alternative.
    pub suggestion: Option<String>,
}

/// Error during AST matching (all errors are non-fatal, fail-open).
#[derive(Debug, Clone)]
pub enum MatchError {
    /// Language not supported by ast-grep.
    UnsupportedLanguage(ScriptLanguage),
    /// Failed to parse content as the specified language.
    ParseError {
        language: ScriptLanguage,
        detail: String,
    },
    /// Pattern matching exceeded timeout.
    Timeout { elapsed_ms: u64, budget_ms: u64 },
    /// Pattern compilation failed (should not happen with static patterns).
    PatternError { pattern: String, detail: String },
}

impl std::fmt::Display for MatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedLanguage(lang) => {
                write!(f, "unsupported language for AST matching: {lang:?}")
            }
            Self::ParseError { language, detail } => {
                write!(f, "AST parse error for {language:?}: {detail}")
            }
            Self::Timeout {
                elapsed_ms,
                budget_ms,
            } => {
                write!(
                    f,
                    "AST matching timeout: {elapsed_ms}ms > {budget_ms}ms budget"
                )
            }
            Self::PatternError { pattern, detail } => {
                write!(f, "pattern compilation error for '{pattern}': {detail}")
            }
        }
    }
}

/// A compiled AST pattern with metadata.
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    /// The pattern string (for debugging/logging).
    pub pattern_str: String,
    /// Stable rule ID.
    pub rule_id: String,
    /// Human-readable reason.
    pub reason: String,
    /// Match severity.
    pub severity: Severity,
    /// Optional safe alternative suggestion.
    pub suggestion: Option<String>,
}

impl CompiledPattern {
    /// Create a new compiled pattern.
    #[must_use]
    pub const fn new(
        pattern_str: String,
        rule_id: String,
        reason: String,
        severity: Severity,
        suggestion: Option<String>,
    ) -> Self {
        Self {
            pattern_str,
            rule_id,
            reason,
            severity,
            suggestion,
        }
    }
}

#[derive(Debug)]
struct PrecompiledPattern {
    pattern: Pattern,
    meta: CompiledPattern,
}

/// AST pattern matcher using ast-grep-core.
///
/// Holds pre-compiled patterns for each supported language.
pub struct AstMatcher {
    /// Patterns organized by language.
    patterns: HashMap<ScriptLanguage, Vec<PrecompiledPattern>>,
    /// Timeout for matching operations.
    timeout: Duration,
}

impl Default for AstMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl AstMatcher {
    /// Create a new matcher with default destructive patterns.
    #[must_use]
    pub fn new() -> Self {
        Self {
            patterns: precompile_patterns(default_patterns()),
            timeout: Duration::from_millis(AST_TIMEOUT_MS),
        }
    }

    /// Create a matcher with custom patterns.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // HashMap is not const-constructible
    pub fn with_patterns(patterns: HashMap<ScriptLanguage, Vec<CompiledPattern>>) -> Self {
        Self {
            patterns: precompile_patterns(patterns),
            timeout: Duration::from_millis(AST_TIMEOUT_MS),
        }
    }

    /// Create a matcher with custom timeout.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Builder pattern, not suitable for const
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Find pattern matches in the given code.
    ///
    /// # Errors
    ///
    /// Returns `MatchError` on:
    /// - Unsupported language
    /// - Parse failure
    /// - Timeout
    ///
    /// All errors are non-fatal; callers should fail-open (allow the command).
    #[allow(clippy::cast_possible_truncation)] // Timeout values are always small
    pub fn find_matches(
        &self,
        code: &str,
        language: ScriptLanguage,
    ) -> Result<Vec<PatternMatch>, MatchError> {
        let start_time = Instant::now();
        let budget_ms = self.timeout.as_millis() as u64;

        // Helper to create timeout error
        let timeout_err = |start: Instant| MatchError::Timeout {
            elapsed_ms: start.elapsed().as_millis() as u64,
            budget_ms,
        };

        // Perl is not supported by ast-grep-language; use a conservative regex fallback.
        if language == ScriptLanguage::Perl {
            return find_matches_perl(code, start_time, self.timeout, budget_ms);
        }

        // Check language support FIRST (before patterns, so we report unsupported properly)
        let Some(ast_lang) = script_language_to_ast_lang(language) else {
            return Err(MatchError::UnsupportedLanguage(language));
        };

        // Get patterns for this language (after language support check)
        let patterns = match self.patterns.get(&language) {
            Some(p) if !p.is_empty() => p,
            _ => return Ok(Vec::new()), // No patterns = no matches
        };

        let newline_positions: Vec<usize> = memchr_iter(b'\n', code.as_bytes()).collect();

        // Parse the code
        let ast = AstGrep::new(code, ast_lang);
        let root = ast.root();

        // Check timeout after parsing
        if start_time.elapsed() > self.timeout {
            return Err(timeout_err(start_time));
        }

        let mut matches = Vec::new();

        // Match each pattern
        for compiled in patterns {
            // Check timeout before each pattern
            if start_time.elapsed() > self.timeout {
                return Err(timeout_err(start_time));
            }

            // Find all matches for this pattern
            for node in root.find_all(&compiled.pattern) {
                // Check timeout during matching (a single pattern can match many nodes)
                if start_time.elapsed() > self.timeout {
                    return Err(timeout_err(start_time));
                }

                let matched_text = node.text();
                let range = node.range();

                // Calculate line number (1-based)
                let line_number = newline_positions.partition_point(|&idx| idx < range.start) + 1;

                // Create preview (truncate if too long, UTF-8 safe)
                let preview = truncate_preview(&matched_text, 60);

                let Some(refined) = refine_match_meta(language, &compiled.meta, &matched_text)
                else {
                    continue;
                };

                matches.push(PatternMatch {
                    rule_id: refined.rule_id,
                    reason: refined.reason,
                    matched_text_preview: preview,
                    start: range.start,
                    end: range.end,
                    line_number,
                    severity: refined.severity,
                    suggestion: refined.suggestion,
                });
            }
        }

        Ok(matches)
    }

    /// Check if any blocking patterns match (convenience method).
    ///
    /// Returns the first blocking match, or None if no blocking patterns match.
    #[must_use]
    pub fn has_blocking_match(&self, code: &str, language: ScriptLanguage) -> Option<PatternMatch> {
        self.find_matches(code, language)
            .ok()
            .and_then(|matches| matches.into_iter().find(|m| m.severity.blocks_by_default()))
    }
}

/// Truncate a string to at most `max_chars` characters, UTF-8 safe.
///
/// If truncation occurs, appends "..." to indicate more content exists.
fn truncate_preview(text: &str, max_chars: usize) -> String {
    let char_count = text.chars().count();
    if char_count <= max_chars {
        text.to_string()
    } else {
        // Leave room for "..."
        let truncate_at = max_chars.saturating_sub(3);
        let truncated: String = text.chars().take(truncate_at).collect();
        format!("{truncated}...")
    }
}

/// Convert `ScriptLanguage` to ast-grep's `SupportLang`.
const fn script_language_to_ast_lang(lang: ScriptLanguage) -> Option<SupportLang> {
    match lang {
        ScriptLanguage::Python => Some(SupportLang::Python),
        ScriptLanguage::JavaScript => Some(SupportLang::JavaScript),
        ScriptLanguage::TypeScript => Some(SupportLang::TypeScript),
        ScriptLanguage::Ruby => Some(SupportLang::Ruby),
        ScriptLanguage::Bash => Some(SupportLang::Bash),
        ScriptLanguage::Go => Some(SupportLang::Go),
        ScriptLanguage::Perl | ScriptLanguage::Unknown => None,
    }
}

// ============================================================================
// Match refinement (payload / path analysis)
// ============================================================================

#[derive(Debug)]
struct RefinedMatchMeta {
    rule_id: String,
    reason: String,
    severity: Severity,
    suggestion: Option<String>,
}

static JS_RECURSIVE_TRUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)\brecursive\s*:\s*true\b").expect("js recursive:true regex compiles")
});

static JS_EXEC_SYNC_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    // Matches: execSync("...") / execSync('...')
    Regex::new(r#"(?m)\bexecSync\b\s*\(\s*(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#)
        .expect("js execSync literal regex compiles")
});

static JS_SPAWN_SYNC_CMD_ARGS: LazyLock<Regex> = LazyLock::new(|| {
    // Matches: spawnSync("cmd", [ ... ]) / spawnSync('cmd', [ ... ])
    Regex::new(
        r#"(?m)\bspawnSync\b\s*\(\s*(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')\s*,\s*\[(?P<args>[^\]]*)\]"#,
    )
    .expect("js spawnSync(cmd, [args]) regex compiles")
});

static JS_ARRAY_STRING_LITERALS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#)
        .expect("js array string literal regex compiles")
});

static JS_FIRST_STRING_ARG: LazyLock<Regex> = LazyLock::new(|| {
    // Captures the first string literal argument in a call expression.
    Regex::new(r#"(?m)\(\s*(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#)
        .expect("js first string arg regex compiles")
});

static RUBY_SYSTEM_EXEC_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    // Matches:
    // - system("...") / system '...'
    // - exec("...")   / exec '...'
    // - Kernel.system("...") / Kernel.exec("...")
    Regex::new(
        r#"(?m)\b(?:(?:Kernel|Process)\.)?(?P<call>system|exec)\b(?:\s*\(\s*|\s+)(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#,
    )
    .expect("ruby system/exec literal regex compiles")
});

static RUBY_BACKTICKS_LITERAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)`(?P<cmd>[^`\n]*)`").expect("ruby backticks regex compiles"));

static RUBY_FIRST_STRING_ARG: LazyLock<Regex> = LazyLock::new(|| {
    // Captures first string literal argument in Ruby call forms:
    // - foo("...") / foo('...')
    // - foo "..."  / foo '...'
    Regex::new(r#"(?m)(?:\(\s*|\s+)(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#)
        .expect("ruby first string arg regex compiles")
});

fn refine_match_meta(
    language: ScriptLanguage,
    meta: &CompiledPattern,
    matched_text: &str,
) -> Option<RefinedMatchMeta> {
    match language {
        ScriptLanguage::JavaScript => refine_javascript_match(meta, matched_text),
        ScriptLanguage::TypeScript => refine_typescript_match(meta, matched_text),
        ScriptLanguage::Ruby => refine_ruby_match(meta, matched_text),
        _ => Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: meta.severity,
            suggestion: meta.suggestion.clone(),
        }),
    }
}

fn refine_javascript_match(meta: &CompiledPattern, matched_text: &str) -> Option<RefinedMatchMeta> {
    let rule_id = meta.rule_id.as_str();

    if matches!(
        rule_id,
        "heredoc.javascript.execsync" | "heredoc.javascript.require_execsync"
    ) {
        let payload = JS_EXEC_SYNC_LITERAL
            .captures(matched_text)
            .and_then(|caps| string_literal_from_caps(&caps));

        if let Some(payload) = payload {
            return detect_shell_payload(payload).map(|hit| RefinedMatchMeta {
                rule_id: format!("{rule_id}.{}", hit.rule_suffix),
                reason: hit.reason.to_string(),
                severity: hit.severity,
                suggestion: hit.suggestion.map(str::to_string),
            });
        }

        // Dynamic payloads: warn only (fail-open).
        return Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: meta.severity,
            suggestion: meta.suggestion.clone(),
        });
    }

    if rule_id == "heredoc.javascript.spawnsync" {
        if let Some(caps) = JS_SPAWN_SYNC_CMD_ARGS.captures(matched_text) {
            let cmd = string_literal_from_caps(&caps).unwrap_or("");
            let args = caps.name("args").map_or("", |m| m.as_str());
            let args: Vec<&str> = JS_ARRAY_STRING_LITERALS
                .captures_iter(args)
                .filter_map(|caps| string_literal_from_caps(&caps))
                .collect();

            if let Some(reconstructed) = reconstruct_spawn_command(cmd, &args) {
                return detect_shell_payload(&reconstructed).map(|hit| RefinedMatchMeta {
                    rule_id: format!("{rule_id}.{}", hit.rule_suffix),
                    reason: hit.reason.to_string(),
                    severity: hit.severity,
                    suggestion: hit.suggestion.map(str::to_string),
                });
            }

            return None;
        }

        // Dynamic spawnSync: warn only.
        return Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: Severity::Medium,
            suggestion: meta.suggestion.clone(),
        });
    }

    if rule_id.starts_with("heredoc.javascript.fs_")
        || rule_id.starts_with("heredoc.javascript.fspromises_")
    {
        let path = JS_FIRST_STRING_ARG
            .captures(matched_text)
            .and_then(|caps| string_literal_from_caps(&caps));

        let recursive_relevant = JS_RECURSIVE_TRUE.is_match(matched_text);
        let catastrophic = path.is_some_and(is_catastrophic_path);

        // For fs.rm* / fs.rmdir* we only care about recursive deletion (or catastrophic literal paths).
        let needs_recursive = matches!(
            rule_id,
            "heredoc.javascript.fs_rmsync"
                | "heredoc.javascript.fs_rmdirsync"
                | "heredoc.javascript.fs_rm"
                | "heredoc.javascript.fs_rmdir"
                | "heredoc.javascript.fspromises_rm"
                | "heredoc.javascript.fspromises_rmdir"
        );

        if needs_recursive && !recursive_relevant && !catastrophic {
            return None;
        }

        if catastrophic {
            return Some(RefinedMatchMeta {
                rule_id: format!("{rule_id}.catastrophic"),
                reason: format!("{} (catastrophic target path)", meta.reason),
                severity: Severity::Critical,
                suggestion: meta.suggestion.clone(),
            });
        }

        return Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: Severity::Medium,
            suggestion: meta.suggestion.clone(),
        });
    }

    Some(RefinedMatchMeta {
        rule_id: meta.rule_id.clone(),
        reason: meta.reason.clone(),
        severity: meta.severity,
        suggestion: meta.suggestion.clone(),
    })
}

fn refine_typescript_match(meta: &CompiledPattern, matched_text: &str) -> Option<RefinedMatchMeta> {
    let rule_id = meta.rule_id.as_str();

    if matches!(
        rule_id,
        "heredoc.typescript.execsync" | "heredoc.typescript.require_execsync"
    ) {
        let payload = JS_EXEC_SYNC_LITERAL
            .captures(matched_text)
            .and_then(|caps| string_literal_from_caps(&caps));

        if let Some(payload) = payload {
            return detect_shell_payload(payload).map(|hit| RefinedMatchMeta {
                rule_id: format!("{rule_id}.{}", hit.rule_suffix),
                reason: hit.reason.to_string(),
                severity: hit.severity,
                suggestion: hit.suggestion.map(str::to_string),
            });
        }

        return Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: Severity::Medium,
            suggestion: meta.suggestion.clone(),
        });
    }

    if rule_id == "heredoc.typescript.spawnsync" {
        if let Some(caps) = JS_SPAWN_SYNC_CMD_ARGS.captures(matched_text) {
            let cmd = string_literal_from_caps(&caps).unwrap_or("");
            let args = caps.name("args").map_or("", |m| m.as_str());
            let args: Vec<&str> = JS_ARRAY_STRING_LITERALS
                .captures_iter(args)
                .filter_map(|caps| string_literal_from_caps(&caps))
                .collect();

            if let Some(reconstructed) = reconstruct_spawn_command(cmd, &args) {
                return detect_shell_payload(&reconstructed).map(|hit| RefinedMatchMeta {
                    rule_id: format!("{rule_id}.{}", hit.rule_suffix),
                    reason: hit.reason.to_string(),
                    severity: hit.severity,
                    suggestion: hit.suggestion.map(str::to_string),
                });
            }

            return None;
        }

        return Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: Severity::Medium,
            suggestion: meta.suggestion.clone(),
        });
    }

    if rule_id.starts_with("heredoc.typescript.fs_")
        || rule_id.starts_with("heredoc.typescript.fspromises_")
        || rule_id == "heredoc.typescript.deno_remove"
    {
        let path = JS_FIRST_STRING_ARG
            .captures(matched_text)
            .and_then(|caps| string_literal_from_caps(&caps));

        let recursive_relevant = JS_RECURSIVE_TRUE.is_match(matched_text);
        let catastrophic = path.is_some_and(is_catastrophic_path);

        let needs_recursive = matches!(
            rule_id,
            "heredoc.typescript.fs_rmsync"
                | "heredoc.typescript.fs_rmdirsync"
                | "heredoc.typescript.fs_rm"
                | "heredoc.typescript.fs_rmdir"
                | "heredoc.typescript.fspromises_rm"
                | "heredoc.typescript.fspromises_rmdir"
                | "heredoc.typescript.deno_remove"
        );

        if needs_recursive && !recursive_relevant && !catastrophic {
            return None;
        }

        if catastrophic {
            return Some(RefinedMatchMeta {
                rule_id: format!("{rule_id}.catastrophic"),
                reason: format!("{} (catastrophic target path)", meta.reason),
                severity: Severity::Critical,
                suggestion: meta.suggestion.clone(),
            });
        }

        return Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: meta.severity,
            suggestion: meta.suggestion.clone(),
        });
    }

    Some(RefinedMatchMeta {
        rule_id: meta.rule_id.clone(),
        reason: meta.reason.clone(),
        severity: meta.severity,
        suggestion: meta.suggestion.clone(),
    })
}

fn refine_ruby_match(meta: &CompiledPattern, matched_text: &str) -> Option<RefinedMatchMeta> {
    let rule_id = meta.rule_id.as_str();

    if matches!(
        rule_id,
        "heredoc.ruby.system"
            | "heredoc.ruby.exec"
            | "heredoc.ruby.kernel_system"
            | "heredoc.ruby.kernel_exec"
            | "heredoc.ruby.backticks"
            | "heredoc.ruby.open3_capture3"
            | "heredoc.ruby.open3_popen3"
    ) {
        let payload = if rule_id == "heredoc.ruby.backticks" {
            RUBY_BACKTICKS_LITERAL
                .captures(matched_text)
                .and_then(|caps| caps.name("cmd").map(|m| m.as_str()))
        } else if rule_id.starts_with("heredoc.ruby.open3_") {
            // Open3 methods take the command as first argument
            RUBY_FIRST_STRING_ARG
                .captures(matched_text)
                .and_then(|caps| string_literal_from_caps(&caps))
        } else {
            RUBY_SYSTEM_EXEC_LITERAL
                .captures(matched_text)
                .and_then(|caps| string_literal_from_caps(&caps))
        };

        if let Some(payload) = payload {
            return detect_shell_payload(payload).map(|hit| RefinedMatchMeta {
                rule_id: format!("{rule_id}.{}", hit.rule_suffix),
                reason: hit.reason.to_string(),
                severity: hit.severity,
                suggestion: hit.suggestion.map(str::to_string),
            });
        }

        // Dynamic system/exec/backticks/Open3: warn only (couldn't extract literal command).
        return Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: Severity::Medium,
            suggestion: meta.suggestion.clone(),
        });
    }

    if rule_id.starts_with("heredoc.ruby.fileutils_")
        || rule_id.starts_with("heredoc.ruby.file_")
        || rule_id.starts_with("heredoc.ruby.dir_")
    {
        let path = RUBY_FIRST_STRING_ARG
            .captures(matched_text)
            .and_then(|caps| string_literal_from_caps(&caps));

        let catastrophic = path.is_some_and(is_catastrophic_path);
        if catastrophic {
            return Some(RefinedMatchMeta {
                rule_id: format!("{rule_id}.catastrophic"),
                reason: format!("{} (catastrophic target path)", meta.reason),
                severity: Severity::Critical,
                suggestion: meta.suggestion.clone(),
            });
        }

        return Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: Severity::Medium,
            suggestion: meta.suggestion.clone(),
        });
    }

    Some(RefinedMatchMeta {
        rule_id: meta.rule_id.clone(),
        reason: meta.reason.clone(),
        severity: meta.severity,
        suggestion: meta.suggestion.clone(),
    })
}

fn reconstruct_spawn_command(cmd: &str, args: &[&str]) -> Option<String> {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return None;
    }

    let mut out = String::new();
    out.push_str(cmd);
    for arg in args {
        out.push(' ');
        out.push_str(arg);
    }

    Some(out)
}

// ============================================================================
// Perl regex fallback matcher (git_safety_guard-2d4)
// ============================================================================

static PERL_SYSTEM_EXEC_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    // Matches:
    // - system("...") / system '...'
    // - exec("...")   / exec '...'
    //
    // We intentionally only match *simple single-line* string literals to keep signal high.
    Regex::new(
        r#"(?m)\b(?P<call>system|exec)\b(?:\s*\(\s*|\s+)(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#,
    )
    .expect("perl system/exec literal regex compiles")
});

static PERL_BACKTICKS_LITERAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)`(?P<cmd>[^`\n]*)`").expect("perl backticks regex compiles"));

static PERL_QX_SLASH_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    // Matches qx/.../ (slash delimiter only, v1).
    Regex::new(r"(?m)\bqx\s*/(?P<cmd>(?:\\.|[^/\n])*)/").expect("perl qx// regex compiles")
});

static PERL_FILE_PATH_RMTREE_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?m)\bFile::Path::(?P<fn>rmtree|remove_tree)\b(?:\s*\(\s*|\s+)(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#,
    )
    .expect("perl File::Path rmtree/remove_tree regex compiles")
});

static PERL_UNLINK_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)\bunlink\b(?:\s*\(\s*|\s+)(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#)
        .expect("perl unlink regex compiles")
});

static PERL_RMDIR_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)\brmdir\b(?:\s*\(\s*|\s+)(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#)
        .expect("perl rmdir regex compiles")
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PerlShellCall {
    System,
    Exec,
    Backticks,
    Qx,
}

impl PerlShellCall {
    #[must_use]
    const fn id_prefix(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Exec => "exec",
            Self::Backticks => "backticks",
            Self::Qx => "qx",
        }
    }
}

#[derive(Clone, Copy)]
enum PerlCommentState {
    Normal,
    Single,
    Double,
    Backtick,
}

fn find_matches_perl(
    code: &str,
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
) -> Result<Vec<PatternMatch>, MatchError> {
    let newline_positions: Vec<usize> = memchr_iter(b'\n', code.as_bytes()).collect();
    let masked = mask_perl_comments(code);
    let haystack = masked.as_ref();

    let mut matches = Vec::new();

    scan_perl_system_exec(
        &mut matches,
        code,
        haystack,
        &newline_positions,
        start_time,
        timeout,
        budget_ms,
    )?;
    scan_perl_backticks(
        &mut matches,
        code,
        haystack,
        &newline_positions,
        start_time,
        timeout,
        budget_ms,
    )?;
    scan_perl_qx(
        &mut matches,
        code,
        haystack,
        &newline_positions,
        start_time,
        timeout,
        budget_ms,
    )?;
    scan_perl_file_path(
        &mut matches,
        code,
        haystack,
        &newline_positions,
        start_time,
        timeout,
        budget_ms,
    )?;
    scan_perl_unlink_rmdir(
        &mut matches,
        code,
        haystack,
        &newline_positions,
        start_time,
        timeout,
        budget_ms,
    )?;

    Ok(matches)
}

#[inline]
fn perl_check_timeout(
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
) -> Result<(), MatchError> {
    if start_time.elapsed() > timeout {
        let elapsed_ms = u64::try_from(start_time.elapsed().as_millis()).unwrap_or(u64::MAX);
        return Err(MatchError::Timeout {
            elapsed_ms,
            budget_ms,
        });
    }
    Ok(())
}

fn scan_perl_system_exec(
    out: &mut Vec<PatternMatch>,
    code: &str,
    haystack: &str,
    newline_positions: &[usize],
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
) -> Result<(), MatchError> {
    for caps in PERL_SYSTEM_EXEC_LITERAL.captures_iter(haystack) {
        perl_check_timeout(start_time, timeout, budget_ms)?;
        let Some(m) = caps.get(0) else {
            continue;
        };

        let call = caps.name("call").map_or("", |m| m.as_str());
        let call = match call {
            "system" => PerlShellCall::System,
            "exec" => PerlShellCall::Exec,
            _ => continue,
        };

        let Some(payload) = string_literal_from_caps(&caps) else {
            continue;
        };

        push_perl_shell_payload_match(
            out,
            code,
            newline_positions,
            call,
            payload,
            m.start(),
            m.end(),
        );
    }

    Ok(())
}

fn scan_perl_backticks(
    out: &mut Vec<PatternMatch>,
    code: &str,
    haystack: &str,
    newline_positions: &[usize],
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
) -> Result<(), MatchError> {
    for caps in PERL_BACKTICKS_LITERAL.captures_iter(haystack) {
        perl_check_timeout(start_time, timeout, budget_ms)?;
        let Some(m) = caps.get(0) else {
            continue;
        };
        let Some(payload) = caps.name("cmd").map(|m| m.as_str()) else {
            continue;
        };

        push_perl_shell_payload_match(
            out,
            code,
            newline_positions,
            PerlShellCall::Backticks,
            payload,
            m.start(),
            m.end(),
        );
    }

    Ok(())
}

fn scan_perl_qx(
    out: &mut Vec<PatternMatch>,
    code: &str,
    haystack: &str,
    newline_positions: &[usize],
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
) -> Result<(), MatchError> {
    for caps in PERL_QX_SLASH_LITERAL.captures_iter(haystack) {
        perl_check_timeout(start_time, timeout, budget_ms)?;
        let Some(m) = caps.get(0) else {
            continue;
        };
        let Some(payload) = caps.name("cmd").map(|m| m.as_str()) else {
            continue;
        };

        push_perl_shell_payload_match(
            out,
            code,
            newline_positions,
            PerlShellCall::Qx,
            unescape_perl_qx_payload(payload).as_ref(),
            m.start(),
            m.end(),
        );
    }

    Ok(())
}

fn unescape_perl_qx_payload(payload: &str) -> std::borrow::Cow<'_, str> {
    if payload.contains("\\/") {
        return std::borrow::Cow::Owned(payload.replace("\\/", "/"));
    }
    std::borrow::Cow::Borrowed(payload)
}

fn scan_perl_file_path(
    out: &mut Vec<PatternMatch>,
    code: &str,
    haystack: &str,
    newline_positions: &[usize],
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
) -> Result<(), MatchError> {
    for caps in PERL_FILE_PATH_RMTREE_LITERAL.captures_iter(haystack) {
        perl_check_timeout(start_time, timeout, budget_ms)?;
        let Some(m) = caps.get(0) else {
            continue;
        };
        let Some(path) = string_literal_from_caps(&caps) else {
            continue;
        };
        let fn_name = caps.name("fn").map_or("rmtree", |m| m.as_str());

        let severity = if is_catastrophic_path(path) {
            Severity::Critical
        } else {
            Severity::Medium
        };

        let rule_id = format!("heredoc.perl.file_path.{fn_name}");
        let reason = format!("File::Path::{fn_name}() recursively deletes directories");

        push_regex_match(
            out,
            code,
            newline_positions,
            &rule_id,
            &reason,
            severity,
            Some("Verify target path carefully before running".to_string()),
            m.start(),
            m.end(),
        );
    }

    Ok(())
}

fn scan_perl_unlink_rmdir(
    out: &mut Vec<PatternMatch>,
    code: &str,
    haystack: &str,
    newline_positions: &[usize],
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
) -> Result<(), MatchError> {
    for caps in PERL_UNLINK_LITERAL.captures_iter(haystack) {
        perl_check_timeout(start_time, timeout, budget_ms)?;
        let Some(m) = caps.get(0) else {
            continue;
        };
        // Only match string-literal unlink; severity is warn-only by default.
        push_regex_match(
            out,
            code,
            newline_positions,
            "heredoc.perl.unlink",
            "unlink() deletes files",
            Severity::Low,
            None,
            m.start(),
            m.end(),
        );
    }

    for caps in PERL_RMDIR_LITERAL.captures_iter(haystack) {
        perl_check_timeout(start_time, timeout, budget_ms)?;
        let Some(m) = caps.get(0) else {
            continue;
        };
        push_regex_match(
            out,
            code,
            newline_positions,
            "heredoc.perl.rmdir",
            "rmdir() deletes directories",
            Severity::Low,
            None,
            m.start(),
            m.end(),
        );
    }

    Ok(())
}

fn mask_perl_comments(code: &str) -> std::borrow::Cow<'_, str> {
    if !code.as_bytes().contains(&b'#') {
        return std::borrow::Cow::Borrowed(code);
    }

    let mut out = code.as_bytes().to_vec();
    let mut state = PerlCommentState::Normal;
    let mut i = 0usize;

    while i < out.len() {
        match state {
            PerlCommentState::Normal => match out[i] {
                b'#' => {
                    // Mask until newline (keep newline itself).
                    let start = i;
                    while i < out.len() && out[i] != b'\n' {
                        i += 1;
                    }
                    for b in &mut out[start..i] {
                        *b = b' ';
                    }
                }
                b'\'' => {
                    state = PerlCommentState::Single;
                    i += 1;
                }
                b'"' => {
                    state = PerlCommentState::Double;
                    i += 1;
                }
                b'`' => {
                    state = PerlCommentState::Backtick;
                    i += 1;
                }
                _ => i += 1,
            },
            PerlCommentState::Single => {
                if out[i] == b'\\' {
                    i = (i + 2).min(out.len());
                    continue;
                }
                if out[i] == b'\'' {
                    state = PerlCommentState::Normal;
                }
                i += 1;
            }
            PerlCommentState::Double => {
                if out[i] == b'\\' {
                    i = (i + 2).min(out.len());
                    continue;
                }
                if out[i] == b'"' {
                    state = PerlCommentState::Normal;
                }
                i += 1;
            }
            PerlCommentState::Backtick => {
                if out[i] == b'\\' {
                    i = (i + 2).min(out.len());
                    continue;
                }
                if out[i] == b'`' {
                    state = PerlCommentState::Normal;
                }
                i += 1;
            }
        }
    }

    String::from_utf8(out).map_or(std::borrow::Cow::Borrowed(code), std::borrow::Cow::Owned)
}

fn string_literal_from_caps<'t>(caps: &regex::Captures<'t>) -> Option<&'t str> {
    caps.name("dq")
        .or_else(|| caps.name("sq"))
        .map(|m| m.as_str())
}

fn push_perl_shell_payload_match(
    out: &mut Vec<PatternMatch>,
    code: &str,
    newline_positions: &[usize],
    call: PerlShellCall,
    payload: &str,
    start: usize,
    end: usize,
) {
    let Some(hit) = detect_shell_payload(payload) else {
        return;
    };

    let rule_id = format!("heredoc.perl.{}.{}", call.id_prefix(), hit.rule_suffix);
    push_regex_match(
        out,
        code,
        newline_positions,
        &rule_id,
        hit.reason,
        hit.severity,
        hit.suggestion.map(str::to_string),
        start,
        end,
    );
}

struct ShellPayloadHit {
    rule_suffix: &'static str,
    reason: &'static str,
    severity: Severity,
    suggestion: Option<&'static str>,
}

fn detect_shell_payload(payload: &str) -> Option<ShellPayloadHit> {
    for segment in payload.split(&[';', '\n', '|', '&'][..]) {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }

        let mut tokens = segment.split_whitespace().peekable();
        let Some(cmd) = next_shell_command(&mut tokens) else {
            continue;
        };

        match cmd {
            "git" => {
                if let Some(hit) = detect_git_destructive(tokens) {
                    return Some(hit);
                }
            }
            "rm" => {
                if let Some(hit) = detect_rm_rf_destructive(tokens) {
                    return Some(hit);
                }
            }
            _ => {}
        }
    }

    None
}

fn detect_git_destructive<'a, I>(mut tokens: I) -> Option<ShellPayloadHit>
where
    I: Iterator<Item = &'a str>,
{
    let sub = tokens.next()?;

    if sub == "reset" {
        if tokens.any(|t| t == "--hard") {
            return Some(ShellPayloadHit {
                rule_suffix: "git_reset_hard",
                reason: "git reset --hard destroys uncommitted changes",
                severity: Severity::High,
                suggestion: Some("Use 'git stash' first, or prefer safer alternatives"),
            });
        }
        return None;
    }

    if sub == "clean" {
        let mut has_f = false;
        let mut has_d = false;

        for t in tokens {
            if t == "--force" {
                has_f = true;
                continue;
            }
            if t == "--dry-run" || t == "-n" {
                continue;
            }
            if t.starts_with('-') {
                let flags = t.trim_start_matches('-');
                has_f |= flags.contains('f');
                has_d |= flags.contains('d');
            }
        }

        if has_f && has_d {
            return Some(ShellPayloadHit {
                rule_suffix: "git_clean_fd",
                reason: "git clean -fd permanently deletes untracked files",
                severity: Severity::High,
                suggestion: Some("Use 'git clean -n' first to preview deletions"),
            });
        }
    }

    None
}

fn detect_rm_rf_destructive<'a, I>(tokens: I) -> Option<ShellPayloadHit>
where
    I: Iterator<Item = &'a str>,
{
    let mut has_r = false;
    let mut has_f = false;
    let mut target: Option<&str> = None;
    let mut options_ended = false;

    for token in tokens {
        if !options_ended && token == "--" {
            options_ended = true;
            continue;
        }
        if !options_ended && token.starts_with('-') {
            if token == "--recursive" {
                has_r = true;
                continue;
            }
            if token == "--force" {
                has_f = true;
                continue;
            }

            let flags = token.trim_start_matches('-');
            has_r |= flags.chars().any(|c| matches!(c, 'r' | 'R'));
            has_f |= flags.contains('f');
            continue;
        }

        target = Some(token);
        break;
    }

    if !has_r || !has_f {
        return None;
    }

    let target = clean_path_token(target?);
    let catastrophic = is_catastrophic_path(target);

    Some(ShellPayloadHit {
        rule_suffix: if catastrophic {
            "rm_rf_catastrophic"
        } else {
            "rm_rf"
        },
        reason: if catastrophic {
            "rm -rf recursively deletes files/directories (catastrophic target path)"
        } else {
            "rm -rf recursively deletes files/directories"
        },
        severity: if catastrophic {
            Severity::Critical
        } else {
            Severity::Medium
        },
        suggestion: Some("Verify the target path and use safer alternatives when possible"),
    })
}

fn next_shell_command<'a, I>(tokens: &mut std::iter::Peekable<I>) -> Option<&'a str>
where
    I: Iterator<Item = &'a str>,
{
    loop {
        let token = tokens.next()?;
        match token {
            "sudo" => {
                while let Some(&next) = tokens.peek() {
                    if !next.starts_with('-') {
                        break;
                    }
                    let flag = tokens.next().unwrap_or_default();
                    if matches!(flag, "-u" | "-g" | "-h") {
                        let _ = tokens.next();
                    }
                }
            }
            "command" => {
                while let Some(&next) = tokens.peek() {
                    if next.starts_with('-') {
                        let _ = tokens.next();
                        continue;
                    }
                    break;
                }
            }
            "env" => {
                while let Some(&next) = tokens.peek() {
                    if next.starts_with('-') || next.contains('=') {
                        let _ = tokens.next();
                        continue;
                    }
                    break;
                }
            }
            _ => return Some(token),
        }
    }
}

fn clean_path_token(token: &str) -> &str {
    let token = token.trim_matches(|c: char| c == '"' || c == '\'');
    token.trim_end_matches(&[';', ',', ')', ']', '}'][..])
}

/// Check if a path contains `..` as an actual path component (not in a filename).
///
/// Examples:
/// - `/tmp/../etc` → true (path traversal)
/// - `/tmp/foo..bar` → false (dots in filename, not traversal)
/// - `../etc` → true (relative path traversal)
fn contains_path_traversal(path: &str) -> bool {
    // Check for `..` as a path segment: `/../`, `/..` at end, `../` at start, or exactly `..`
    path.contains("/../") || path.ends_with("/..") || path.starts_with("../") || path == ".."
}

fn is_catastrophic_path(path: &str) -> bool {
    // Root or home always catastrophic
    if matches!(path, "/" | "~") || path.starts_with("~/") {
        return true;
    }

    // Temp directories are safe UNLESS they contain path traversal.
    // Path traversal can escape temp directories (e.g., /tmp/../etc -> /etc).
    if path.starts_with("/tmp") || path.starts_with("/var/tmp") {
        return contains_path_traversal(path);
    }

    // Standard catastrophic system paths
    path.starts_with("/etc")
        || path.starts_with("/home")
        || path.starts_with("/usr")
        || path.starts_with("/bin")
        || path.starts_with("/sbin")
        || path.starts_with("/lib")
        || path.starts_with("/lib64")
}

#[allow(clippy::too_many_arguments)]
fn push_regex_match(
    out: &mut Vec<PatternMatch>,
    code: &str,
    newline_positions: &[usize],
    rule_id: &str,
    reason: &str,
    severity: Severity,
    suggestion: Option<String>,
    start: usize,
    end: usize,
) {
    let line_number = newline_positions.partition_point(|&idx| idx < start) + 1;
    let matched_text = code.get(start..end).unwrap_or("");
    let preview = truncate_preview(matched_text, 60);

    out.push(PatternMatch {
        rule_id: rule_id.to_string(),
        reason: reason.to_string(),
        matched_text_preview: preview,
        start,
        end,
        line_number,
        severity,
        suggestion,
    });
}

/// Default patterns for heredoc scanning.
///
/// These patterns detect destructive operations in embedded scripts.
/// Each pattern has a stable rule ID for allowlisting.
#[allow(clippy::too_many_lines)]
fn default_patterns() -> HashMap<ScriptLanguage, Vec<CompiledPattern>> {
    let mut patterns = HashMap::new();

    // Python patterns
    patterns.insert(
        ScriptLanguage::Python,
        vec![
            CompiledPattern::new(
                "shutil.rmtree($$$)".to_string(),
                "heredoc.python.shutil_rmtree".to_string(),
                "shutil.rmtree() recursively deletes directories".to_string(),
                Severity::Critical,
                Some("Use shutil.rmtree with explicit path validation".to_string()),
            ),
            CompiledPattern::new(
                "os.remove($$$)".to_string(),
                "heredoc.python.os_remove".to_string(),
                "os.remove() deletes files".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "os.rmdir($$$)".to_string(),
                "heredoc.python.os_rmdir".to_string(),
                "os.rmdir() deletes directories".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "os.unlink($$$)".to_string(),
                "heredoc.python.os_unlink".to_string(),
                "os.unlink() deletes files".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "pathlib.Path($$$).unlink($$$)".to_string(),
                "heredoc.python.pathlib_unlink".to_string(),
                "Path.unlink() deletes files".to_string(),
                Severity::High,
                None,
            ),
            // Also match when Path is imported directly: from pathlib import Path
            CompiledPattern::new(
                "Path($$$).unlink($$$)".to_string(),
                "heredoc.python.pathlib_unlink".to_string(),
                "Path.unlink() deletes files".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "pathlib.Path($$$).rmdir($$$)".to_string(),
                "heredoc.python.pathlib_rmdir".to_string(),
                "Path.rmdir() deletes directories".to_string(),
                Severity::High,
                None,
            ),
            // Also match when Path is imported directly
            CompiledPattern::new(
                "Path($$$).rmdir($$$)".to_string(),
                "heredoc.python.pathlib_rmdir".to_string(),
                "Path.rmdir() deletes directories".to_string(),
                Severity::High,
                None,
            ),
            // Shell execution patterns - Medium severity to avoid false positives
            // per bead guidance: "Do not block on shell=True alone"
            CompiledPattern::new(
                "subprocess.run($$$)".to_string(),
                "heredoc.python.subprocess_run".to_string(),
                "subprocess.run() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "subprocess.call($$$)".to_string(),
                "heredoc.python.subprocess_call".to_string(),
                "subprocess.call() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "subprocess.Popen($$$)".to_string(),
                "heredoc.python.subprocess_popen".to_string(),
                "subprocess.Popen() spawns shell processes".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "os.system($$$)".to_string(),
                "heredoc.python.os_system".to_string(),
                "os.system() executes shell commands".to_string(),
                Severity::Medium, // Lowered per bead: avoid "code execution exists" as default deny
                Some("Use subprocess with explicit arguments instead".to_string()),
            ),
            CompiledPattern::new(
                "os.popen($$$)".to_string(),
                "heredoc.python.os_popen".to_string(),
                "os.popen() executes shell commands".to_string(),
                Severity::Medium,
                Some("Use subprocess instead".to_string()),
            ),
        ],
    );

    // JavaScript/Node patterns
    patterns.insert(
        ScriptLanguage::JavaScript,
        vec![
            CompiledPattern::new(
                "fs.rmSync($$$)".to_string(),
                "heredoc.javascript.fs_rmsync".to_string(),
                "fs.rmSync() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "fs.rmdirSync($$$)".to_string(),
                "heredoc.javascript.fs_rmdirsync".to_string(),
                "fs.rmdirSync() deletes directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "fs.unlinkSync($$$)".to_string(),
                "heredoc.javascript.fs_unlinksync".to_string(),
                "fs.unlinkSync() deletes files".to_string(),
                Severity::Low,
                None,
            ),
            CompiledPattern::new(
                "child_process.execSync($$$)".to_string(),
                "heredoc.javascript.execsync".to_string(),
                "execSync() executes shell commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "require('child_process').execSync($$$)".to_string(),
                "heredoc.javascript.require_execsync".to_string(),
                "execSync() executes shell commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command arguments carefully".to_string()),
            ),
            // Spawn variants
            CompiledPattern::new(
                "child_process.spawnSync($$$)".to_string(),
                "heredoc.javascript.spawnsync".to_string(),
                "spawnSync() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command and arguments carefully".to_string()),
            ),
            // Async versions (still dangerous)
            CompiledPattern::new(
                "fs.rm($$$)".to_string(),
                "heredoc.javascript.fs_rm".to_string(),
                "fs.rm() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "fs.rmdir($$$)".to_string(),
                "heredoc.javascript.fs_rmdir".to_string(),
                "fs.rmdir() deletes directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "fs.unlink($$$)".to_string(),
                "heredoc.javascript.fs_unlink".to_string(),
                "fs.unlink() deletes files".to_string(),
                Severity::Low,
                None,
            ),
            // Promise-based fs variants
            CompiledPattern::new(
                "fsPromises.rm($$$)".to_string(),
                "heredoc.javascript.fspromises_rm".to_string(),
                "fsPromises.rm() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "fsPromises.rmdir($$$)".to_string(),
                "heredoc.javascript.fspromises_rmdir".to_string(),
                "fsPromises.rmdir() deletes directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            ),
        ],
    );

    // TypeScript patterns (git_safety_guard-26f)
    patterns.insert(
        ScriptLanguage::TypeScript,
        vec![
            CompiledPattern::new(
                "fs.rmSync($$$)".to_string(),
                "heredoc.typescript.fs_rmsync".to_string(),
                "fs.rmSync() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "fs.rmdirSync($$$)".to_string(),
                "heredoc.typescript.fs_rmdirsync".to_string(),
                "fs.rmdirSync() deletes directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "fs.unlinkSync($$$)".to_string(),
                "heredoc.typescript.fs_unlinksync".to_string(),
                "fs.unlinkSync() deletes files".to_string(),
                Severity::Low,
                None,
            ),
            CompiledPattern::new(
                "Deno.remove($$$)".to_string(),
                "heredoc.typescript.deno_remove".to_string(),
                "Deno.remove() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "child_process.execSync($$$)".to_string(),
                "heredoc.typescript.execsync".to_string(),
                "execSync() executes shell commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "require('child_process').execSync($$$)".to_string(),
                "heredoc.typescript.require_execsync".to_string(),
                "execSync() executes shell commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "child_process.spawnSync($$$)".to_string(),
                "heredoc.typescript.spawnsync".to_string(),
                "spawnSync() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command and arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "fs.rm($$$)".to_string(),
                "heredoc.typescript.fs_rm".to_string(),
                "fs.rm() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "fs.rmdir($$$)".to_string(),
                "heredoc.typescript.fs_rmdir".to_string(),
                "fs.rmdir() deletes directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "fs.unlink($$$)".to_string(),
                "heredoc.typescript.fs_unlink".to_string(),
                "fs.unlink() deletes files".to_string(),
                Severity::Low,
                None,
            ),
            CompiledPattern::new(
                "fsPromises.rm($$$)".to_string(),
                "heredoc.typescript.fspromises_rm".to_string(),
                "fsPromises.rm() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "fsPromises.rmdir($$$)".to_string(),
                "heredoc.typescript.fspromises_rmdir".to_string(),
                "fsPromises.rmdir() deletes directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            ),
        ],
    );

    // Ruby patterns (git_safety_guard-mvh)
    patterns.insert(
        ScriptLanguage::Ruby,
        vec![
            // =========================================================================
            // Filesystem Deletion (High Signal)
            // =========================================================================
            CompiledPattern::new(
                "FileUtils.rm_rf($$$)".to_string(),
                "heredoc.ruby.fileutils_rm_rf".to_string(),
                "FileUtils.rm_rf() recursively deletes directories".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                Some("Verify target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "FileUtils.remove_dir($$$)".to_string(),
                "heredoc.ruby.fileutils_remove_dir".to_string(),
                "FileUtils.remove_dir() deletes directories".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                None,
            ),
            CompiledPattern::new(
                "FileUtils.rm($$$)".to_string(),
                "heredoc.ruby.fileutils_rm".to_string(),
                "FileUtils.rm() deletes files".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                None,
            ),
            CompiledPattern::new(
                "FileUtils.remove($$$)".to_string(),
                "heredoc.ruby.fileutils_remove".to_string(),
                "FileUtils.remove() deletes files".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                None,
            ),
            CompiledPattern::new(
                "File.delete($$$)".to_string(),
                "heredoc.ruby.file_delete".to_string(),
                "File.delete() removes files".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                None,
            ),
            CompiledPattern::new(
                "File.unlink($$$)".to_string(),
                "heredoc.ruby.file_unlink".to_string(),
                "File.unlink() removes files".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                None,
            ),
            CompiledPattern::new(
                "Dir.rmdir($$$)".to_string(),
                "heredoc.ruby.dir_rmdir".to_string(),
                "Dir.rmdir() removes directories".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                None,
            ),
            CompiledPattern::new(
                "Dir.delete($$$)".to_string(),
                "heredoc.ruby.dir_delete".to_string(),
                "Dir.delete() removes directories".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                None,
            ),
            // =========================================================================
            // Process Execution (Medium severity by default - avoid false positives)
            // =========================================================================
            CompiledPattern::new(
                "system($$$)".to_string(),
                "heredoc.ruby.system".to_string(),
                "system() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "exec($$$)".to_string(),
                "heredoc.ruby.exec".to_string(),
                "exec() replaces process with shell command".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "`$$$`".to_string(),
                "heredoc.ruby.backticks".to_string(),
                "Backticks execute shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            // Kernel.system and Kernel.exec variants
            CompiledPattern::new(
                "Kernel.system($$$)".to_string(),
                "heredoc.ruby.kernel_system".to_string(),
                "Kernel.system() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "Kernel.exec($$$)".to_string(),
                "heredoc.ruby.kernel_exec".to_string(),
                "Kernel.exec() replaces process with shell command".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            // Open3 for shell execution
            CompiledPattern::new(
                "Open3.capture3($$$)".to_string(),
                "heredoc.ruby.open3_capture3".to_string(),
                "Open3.capture3() executes shell commands".to_string(),
                Severity::Medium,
                None,
            ),
            CompiledPattern::new(
                "Open3.popen3($$$)".to_string(),
                "heredoc.ruby.open3_popen3".to_string(),
                "Open3.popen3() executes shell commands".to_string(),
                Severity::Medium,
                None,
            ),
        ],
    );

    // Bash patterns
    patterns.insert(
        ScriptLanguage::Bash,
        vec![
            CompiledPattern::new(
                "rm -rf $$$".to_string(),
                "heredoc.bash.rm_rf".to_string(),
                "rm -rf recursively deletes files/directories".to_string(),
                Severity::Critical,
                Some("Verify the target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "rm -r $$$".to_string(),
                "heredoc.bash.rm_r".to_string(),
                "rm -r recursively deletes".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "git reset --hard".to_string(),
                "heredoc.bash.git_reset_hard".to_string(),
                "git reset --hard discards uncommitted changes".to_string(),
                Severity::Critical,
                Some("Use 'git stash' to save changes first".to_string()),
            ),
            CompiledPattern::new(
                "git clean -fd".to_string(),
                "heredoc.bash.git_clean_fd".to_string(),
                "git clean -fd deletes untracked files".to_string(),
                Severity::High,
                Some("Use 'git clean -n' to preview first".to_string()),
            ),
        ],
    );

    patterns
}

/// Global default matcher instance (lazy-initialized).
pub static DEFAULT_MATCHER: LazyLock<AstMatcher> = LazyLock::new(AstMatcher::new);

fn precompile_patterns(
    patterns: HashMap<ScriptLanguage, Vec<CompiledPattern>>,
) -> HashMap<ScriptLanguage, Vec<PrecompiledPattern>> {
    let mut out: HashMap<ScriptLanguage, Vec<PrecompiledPattern>> = HashMap::new();

    for (language, patterns) in patterns {
        let Some(ast_lang) = script_language_to_ast_lang(language) else {
            continue;
        };

        let mut compiled = Vec::with_capacity(patterns.len());
        for meta in patterns {
            let Ok(pattern) = Pattern::try_new(&meta.pattern_str, ast_lang) else {
                // Fail-open: skip invalid patterns silently (default patterns should be validated by tests).
                continue;
            };

            compiled.push(PrecompiledPattern { pattern, meta });
        }

        if !compiled.is_empty() {
            out.insert(language, compiled);
        }
    }

    out
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::similar_names)] // `matcher` vs `matches` is readable in test code
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn severity_labels() {
        assert_eq!(Severity::Critical.label(), "critical");
        assert_eq!(Severity::High.label(), "high");
        assert_eq!(Severity::Medium.label(), "medium");
        assert_eq!(Severity::Low.label(), "low");
    }

    #[test]
    fn severity_blocking() {
        assert!(Severity::Critical.blocks_by_default());
        assert!(Severity::High.blocks_by_default());
        assert!(!Severity::Medium.blocks_by_default());
        assert!(!Severity::Low.blocks_by_default());
    }

    #[test]
    fn match_error_display() {
        let errors = vec![
            MatchError::UnsupportedLanguage(ScriptLanguage::Perl),
            MatchError::ParseError {
                language: ScriptLanguage::Python,
                detail: "syntax error".to_string(),
            },
            MatchError::Timeout {
                elapsed_ms: 25,
                budget_ms: 20,
            },
            MatchError::PatternError {
                pattern: "bad pattern".to_string(),
                detail: "invalid syntax".to_string(),
            },
        ];

        for err in errors {
            let display = format!("{err}");
            assert!(!display.is_empty());
        }
    }

    #[test]
    fn matcher_default_has_patterns() {
        let matcher = AstMatcher::new();
        assert!(!matcher.patterns.is_empty());
        assert!(matcher.patterns.contains_key(&ScriptLanguage::Python));
        assert!(matcher.patterns.contains_key(&ScriptLanguage::JavaScript));
        assert!(matcher.patterns.contains_key(&ScriptLanguage::Ruby));
        assert!(matcher.patterns.contains_key(&ScriptLanguage::Bash));
    }

    #[test]
    fn python_positive_match() {
        let matcher = AstMatcher::new();
        let code = "import shutil\nshutil.rmtree('/tmp/test')";

        let matches = matcher.find_matches(code, ScriptLanguage::Python);
        match matches {
            Ok(m) => {
                assert!(!m.is_empty(), "should match shutil.rmtree");
                assert_eq!(m[0].rule_id, "heredoc.python.shutil_rmtree");
                assert!(m[0].severity.blocks_by_default());
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn python_negative_match() {
        let matcher = AstMatcher::new();
        let code = "import os\nprint('hello world')";

        let matches = matcher.find_matches(code, ScriptLanguage::Python);
        match matches {
            Ok(m) => assert!(m.is_empty(), "should not match safe code"),
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    mod javascript_positive_fixtures {
        use super::*;

        #[test]
        fn fs_rmsync_catastrophic_blocks() {
            let matcher = AstMatcher::new();
            let code = "const fs = require('fs');\nfs.rmSync('/etc', { recursive: true });";

            let matches = matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.javascript.fs_rmsync.catastrophic"),
                "catastrophic fs.rmSync should be detected"
            );
            let hit = matches
                .into_iter()
                .find(|m| m.rule_id == "heredoc.javascript.fs_rmsync.catastrophic")
                .unwrap();
            assert!(hit.severity.blocks_by_default());
        }

        #[test]
        fn fs_rmsync_non_catastrophic_warns_only() {
            let matcher = AstMatcher::new();
            let code = "const fs = require('fs');\nfs.rmSync('./dist', { recursive: true });";

            let matches = matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.javascript.fs_rmsync"),
                "non-catastrophic recursive rmSync should be detected"
            );
            let hit = matches
                .into_iter()
                .find(|m| m.rule_id == "heredoc.javascript.fs_rmsync")
                .unwrap();
            assert!(!hit.severity.blocks_by_default());
        }

        #[test]
        fn execsync_git_reset_hard_blocks() {
            let matcher = AstMatcher::new();
            let code = "const child_process = require('child_process');\nchild_process.execSync('git reset --hard');";

            let matches = matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".git_reset_hard")
                        && m.severity.blocks_by_default()),
                "execSync('git reset --hard') should block"
            );
        }

        #[test]
        fn execsync_rm_rf_non_catastrophic_warns_only() {
            let matcher = AstMatcher::new();
            let code = "const child_process = require('child_process');\nchild_process.execSync('rm -rf ./build');";

            let matches = matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(
                matches.iter().any(|m| m.rule_id.ends_with(".rm_rf")),
                "execSync('rm -rf ./build') should be detected"
            );
            let hit = matches
                .into_iter()
                .find(|m| m.rule_id.ends_with(".rm_rf"))
                .unwrap();
            assert!(!hit.severity.blocks_by_default());
        }

        #[test]
        fn spawnsync_rm_rf_catastrophic_blocks() {
            let matcher = AstMatcher::new();
            let code = "const child_process = require('child_process');\nchild_process.spawnSync('rm', ['-rf', '/']);";

            let matches = matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".rm_rf_catastrophic")
                        && m.severity.blocks_by_default()),
                "spawnSync('rm', ['-rf','/']) should block"
            );
        }

        #[test]
        fn fs_rmsync_path_traversal_escapes_tmp_blocks() {
            // Path traversal from /tmp to /etc should be detected as catastrophic
            let matcher = AstMatcher::new();
            let code = "const fs = require('fs');\nfs.rmSync('/tmp/../etc', { recursive: true });";

            let matches = matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.javascript.fs_rmsync.catastrophic"),
                "path traversal /tmp/../etc should be detected as catastrophic"
            );
            let hit = matches
                .into_iter()
                .find(|m| m.rule_id == "heredoc.javascript.fs_rmsync.catastrophic")
                .unwrap();
            assert!(hit.severity.blocks_by_default());
        }
    }

    mod javascript_negative_fixtures {
        use super::*;

        #[test]
        fn printed_dangerous_string_does_not_match() {
            let matcher = AstMatcher::new();
            let code = "console.log('rm -rf /');";

            let matches = matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn require_child_process_alone_does_not_match() {
            let matcher = AstMatcher::new();
            let code = "require('child_process');";

            let matches = matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn execsync_safe_payload_does_not_match() {
            let matcher = AstMatcher::new();
            let code = "const child_process = require('child_process');\nchild_process.execSync('git status');";

            let matches = matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn fs_rmsync_without_recursive_does_not_match() {
            let matcher = AstMatcher::new();
            let code = "const fs = require('fs');\nfs.rmSync('./file.txt');";

            let matches = matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn spawnsync_echo_does_not_match() {
            let matcher = AstMatcher::new();
            let code = "const child_process = require('child_process');\nchild_process.spawnSync('echo', ['rm -rf /']);";

            let matches = matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn fs_rmsync_tmp_dotdot_in_filename_does_not_block() {
            // Filenames with consecutive dots are NOT path traversal
            let matcher = AstMatcher::new();
            let code =
                "const fs = require('fs');\nfs.rmSync('/tmp/foo..bar', { recursive: true });";

            let matches = matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            // Should match as medium severity (warn), NOT as catastrophic
            assert!(
                !matches.iter().any(|m| m.rule_id.contains("catastrophic")),
                "foo..bar is a filename, not path traversal"
            );
        }
    }

    #[test]
    fn unsupported_language_returns_error() {
        let matcher = AstMatcher::new();
        let code = "print 'hello perl';";

        let result = matcher.find_matches(code, ScriptLanguage::Unknown);
        assert!(matches!(result, Err(MatchError::UnsupportedLanguage(_))));
    }

    #[test]
    fn has_blocking_match_returns_first_blocker() {
        let matcher = AstMatcher::new();
        let code = "import shutil\nshutil.rmtree('/danger')";

        let result = matcher.has_blocking_match(code, ScriptLanguage::Python);
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_id, "heredoc.python.shutil_rmtree");
    }

    #[test]
    fn has_blocking_match_returns_none_for_safe_code() {
        let matcher = AstMatcher::new();
        let code = "x = 1 + 2";

        let result = matcher.has_blocking_match(code, ScriptLanguage::Python);
        assert!(result.is_none());
    }

    #[test]
    fn has_blocking_match_fails_open_on_error() {
        let matcher = AstMatcher::new();
        let code = "some perl code";

        // Unknown is unsupported - should fail open (return None, not panic)
        let result = matcher.has_blocking_match(code, ScriptLanguage::Unknown);
        assert!(result.is_none());
    }

    mod perl_positive_fixtures {
        use super::*;

        #[test]
        fn perl_system_rm_rf_catastrophic_blocks() {
            let matcher = AstMatcher::new();
            let code = "system(\"rm -rf /\");\n";

            let matches = matcher
                .find_matches(code, ScriptLanguage::Perl)
                .expect("perl matcher should run");
            assert!(!matches.is_empty());
            assert!(matches[0].rule_id.contains("rm_rf"));
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn perl_system_rm_rf_non_catastrophic_warns_only() {
            let matcher = AstMatcher::new();
            let code = "system('rm -rf ./build');\n";

            let matches = matcher
                .find_matches(code, ScriptLanguage::Perl)
                .expect("perl matcher should run");
            assert!(!matches.is_empty());
            assert!(matches[0].rule_id.contains("rm_rf"));
            assert!(!matches[0].severity.blocks_by_default());
        }

        #[test]
        fn perl_backticks_git_reset_hard_blocks() {
            let matcher = AstMatcher::new();
            let code = "`git reset --hard`;\n";

            let matches = matcher
                .find_matches(code, ScriptLanguage::Perl)
                .expect("perl matcher should run");
            assert!(!matches.is_empty());
            assert!(matches[0].rule_id.contains("git_reset_hard"));
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn perl_qx_rm_rf_catastrophic_blocks() {
            let matcher = AstMatcher::new();
            let code = "qx/rm -rf \\/etc/;\n";

            let matches = matcher
                .find_matches(code, ScriptLanguage::Perl)
                .expect("perl matcher should run");
            assert!(!matches.is_empty());
            assert!(matches[0].rule_id.contains("rm_rf"));
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn perl_file_path_rmtree_warns_by_default() {
            // Use longer timeout for test reliability (default 20ms can be flaky under load)
            let matcher = AstMatcher::new().with_timeout(std::time::Duration::from_millis(100));
            let code = "use File::Path;\nFile::Path::rmtree(\"/tmp/test\");\n";

            let matches = matcher
                .find_matches(code, ScriptLanguage::Perl)
                .expect("perl matcher should run within 100ms");
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.perl.file_path.rmtree"),
                "should match File::Path::rmtree"
            );
            let rmtree = matches
                .into_iter()
                .find(|m| m.rule_id == "heredoc.perl.file_path.rmtree")
                .expect("rmtree match present");
            assert!(!rmtree.severity.blocks_by_default());
        }
    }

    mod perl_negative_fixtures {
        use super::*;

        #[test]
        fn perl_comments_do_not_match() {
            let matcher = AstMatcher::new();
            let code = "# system(\"rm -rf /\")\nprint \"ok\";\n";

            let matches = matcher
                .find_matches(code, ScriptLanguage::Perl)
                .expect("perl matcher should run");
            assert!(
                matches.is_empty(),
                "commented-out dangerous code is not executed"
            );
        }

        #[test]
        fn perl_printing_dangerous_string_does_not_match() {
            let matcher = AstMatcher::new();
            let code = "print \"rm -rf /\";\n";

            let matches = matcher
                .find_matches(code, ScriptLanguage::Perl)
                .expect("perl matcher should run");
            assert!(
                matches.is_empty(),
                "printed strings are data, not execution"
            );
        }
    }

    #[test]
    fn match_includes_line_number() {
        let matcher = AstMatcher::new();
        let code = "x = 1\ny = 2\nshutil.rmtree('/test')";

        let matches = matcher
            .find_matches(code, ScriptLanguage::Python)
            .expect("should parse");
        assert!(!matches.is_empty());
        assert_eq!(matches[0].line_number, 3); // shutil.rmtree is on line 3
    }

    #[test]
    fn match_preview_truncates_long_text() {
        let ast_matcher = AstMatcher::new();
        // Create code with a very long argument
        let long_path = "/very/long/path/".repeat(10);
        let code = format!("import shutil\nshutil.rmtree('{long_path}')");

        let results = ast_matcher
            .find_matches(&code, ScriptLanguage::Python)
            .expect("should parse");
        assert!(!results.is_empty());
        // Preview should be truncated
        assert!(results[0].matched_text_preview.len() <= 63);
        assert!(results[0].matched_text_preview.ends_with("..."));
    }

    #[test]
    fn empty_code_returns_no_matches() {
        let ast_matcher = AstMatcher::new();

        let results = ast_matcher
            .find_matches("", ScriptLanguage::Python)
            .expect("should parse empty code");
        assert!(results.is_empty());
    }

    #[test]
    fn default_matcher_is_lazy_initialized() {
        // Just verify it can be accessed without panic
        let _ = &*DEFAULT_MATCHER;
        assert!(!DEFAULT_MATCHER.patterns.is_empty());
    }

    #[test]
    fn default_patterns_all_precompile() {
        let raw = default_patterns();
        let expected: HashMap<ScriptLanguage, usize> =
            raw.iter().map(|(lang, pats)| (*lang, pats.len())).collect();

        let compiled = precompile_patterns(raw);

        for (lang, expected_len) in expected {
            let got = compiled.get(&lang).map_or(0, std::vec::Vec::len);
            assert_eq!(
                got, expected_len,
                "all default patterns should compile for {lang:?}"
            );
        }
    }

    #[test]
    fn truncate_preview_handles_utf8_safely() {
        // Test with ASCII
        assert_eq!(truncate_preview("hello", 10), "hello");
        assert_eq!(truncate_preview("hello world!", 8), "hello...");

        // Test with multi-byte UTF-8 (emojis are 4 bytes each)
        let emojis = "🎉🎊🎁🎄🎅";
        assert_eq!(truncate_preview(emojis, 10), emojis); // 5 chars, fits
        assert_eq!(truncate_preview(emojis, 4), "🎉..."); // truncates to 1 emoji + ...

        // Test with CJK characters (3 bytes each)
        let cjk = "你好世界";
        assert_eq!(truncate_preview(cjk, 10), cjk); // 4 chars, fits
        assert_eq!(truncate_preview(cjk, 4), cjk); // exactly 4 chars, fits
        assert_eq!(truncate_preview(cjk, 3), "..."); // 4 > 3, truncates (no room for even 1 char + "...")

        // Edge cases
        assert_eq!(truncate_preview("", 10), "");
        assert_eq!(truncate_preview("ab", 3), "ab");
        assert_eq!(truncate_preview("abc", 3), "abc");
        assert_eq!(truncate_preview("abcd", 3), "...");
    }

    mod ruby_positive_fixtures {
        use super::*;

        #[test]
        fn fileutils_rm_rf_catastrophic_blocks() {
            let matcher = AstMatcher::new();
            let code = "require 'fileutils'\nFileUtils.rm_rf('/')";

            let matches = matcher.find_matches(code, ScriptLanguage::Ruby).unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.ruby.fileutils_rm_rf.catastrophic"
                        && m.severity.blocks_by_default()),
                "catastrophic FileUtils.rm_rf should block"
            );
        }

        #[test]
        fn fileutils_rm_rf_non_catastrophic_warns_only() {
            let matcher = AstMatcher::new();
            let code = "require 'fileutils'\nFileUtils.rm_rf('./tmp')";

            let matches = matcher.find_matches(code, ScriptLanguage::Ruby).unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.ruby.fileutils_rm_rf"
                        && !m.severity.blocks_by_default()),
                "non-catastrophic FileUtils.rm_rf should warn only"
            );
        }

        #[test]
        fn system_rm_rf_catastrophic_blocks() {
            let matcher = AstMatcher::new();
            let code = "system('rm -rf /')";

            let matches = matcher.find_matches(code, ScriptLanguage::Ruby).unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".rm_rf_catastrophic")
                        && m.severity.blocks_by_default()),
                "system('rm -rf /') should block"
            );
        }

        #[test]
        fn backticks_rm_rf_catastrophic_blocks() {
            let matcher = AstMatcher::new();
            let code = "`rm -rf /`";

            let matches = matcher.find_matches(code, ScriptLanguage::Ruby).unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".rm_rf_catastrophic")
                        && m.severity.blocks_by_default()),
                "backticks `rm -rf /` should block"
            );
        }

        #[test]
        fn exec_git_reset_hard_blocks() {
            let matcher = AstMatcher::new();
            let code = "exec('git reset --hard HEAD~1')";

            let matches = matcher.find_matches(code, ScriptLanguage::Ruby).unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".git_reset_hard")
                        && m.severity.blocks_by_default()),
                "exec('git reset --hard ...') should block"
            );
        }

        #[test]
        fn open3_capture3_rm_rf_catastrophic_blocks() {
            let matcher = AstMatcher::new();
            let code = "require 'open3'\nOpen3.capture3('rm -rf /')";

            let matches = matcher.find_matches(code, ScriptLanguage::Ruby).unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".rm_rf_catastrophic")
                        && m.severity.blocks_by_default()),
                "Open3.capture3('rm -rf /') should block"
            );
        }

        #[test]
        fn open3_popen3_git_reset_hard_blocks() {
            let matcher = AstMatcher::new();
            let code = "Open3.popen3('git reset --hard') { |i,o,e,t| }";

            let matches = matcher.find_matches(code, ScriptLanguage::Ruby).unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".git_reset_hard")
                        && m.severity.blocks_by_default()),
                "Open3.popen3('git reset --hard') should block"
            );
        }
    }

    mod ruby_negative_fixtures {
        use super::*;

        #[test]
        fn puts_dangerous_string_does_not_match() {
            let matcher = AstMatcher::new();
            let code = "puts 'rm -rf /'";

            let matches = matcher.find_matches(code, ScriptLanguage::Ruby).unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn system_safe_payload_does_not_match() {
            let matcher = AstMatcher::new();
            let code = "system('git status')";

            let matches = matcher.find_matches(code, ScriptLanguage::Ruby).unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn open3_capture3_safe_payload_does_not_match() {
            let matcher = AstMatcher::new();
            let code = "Open3.capture3('git status')";

            let matches = matcher.find_matches(code, ScriptLanguage::Ruby).unwrap();
            assert!(
                matches.is_empty(),
                "Open3.capture3 with safe payload should not match"
            );
        }

        #[test]
        fn backticks_safe_payload_does_not_match() {
            let matcher = AstMatcher::new();
            let code = "`echo hello`";

            let matches = matcher.find_matches(code, ScriptLanguage::Ruby).unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn require_only_does_not_match() {
            let matcher = AstMatcher::new();
            let code = "require 'fileutils'";

            let matches = matcher.find_matches(code, ScriptLanguage::Ruby).unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn file_delete_under_tmp_warns_only() {
            let matcher = AstMatcher::new();
            let code = "File.delete('/tmp/test.txt')";

            let matches = matcher.find_matches(code, ScriptLanguage::Ruby).unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.ruby.file_delete"
                        && !m.severity.blocks_by_default()),
                "File.delete under /tmp should warn only"
            );
        }
    }

    mod typescript_positive_fixtures {
        use super::*;

        #[test]
        fn fs_rmsync_catastrophic_blocks_with_type_assertion() {
            let matcher = AstMatcher::new();
            let code =
                "import * as fs from 'fs';\nfs.rmSync('/etc' as string, { recursive: true });";

            let matches = matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.typescript.fs_rmsync.catastrophic"
                        && m.severity.blocks_by_default()),
                "catastrophic fs.rmSync should block"
            );
        }

        #[test]
        fn fs_rmsync_non_catastrophic_warns_only() {
            let matcher = AstMatcher::new();
            let code = "import * as fs from 'fs';\nfs.rmSync('./dist', { recursive: true });";

            let matches = matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.typescript.fs_rmsync"
                        && !m.severity.blocks_by_default()),
                "non-catastrophic recursive rmSync should warn only"
            );
        }

        #[test]
        fn execsync_git_reset_hard_blocks_inside_decorated_class() {
            let matcher = AstMatcher::new();
            let code = "@sealed\nclass Danger {\n  run(): void {\n    require('child_process').execSync('git reset --hard');\n  }\n}\n";

            let matches = matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".git_reset_hard")
                        && m.severity.blocks_by_default()),
                "execSync('git reset --hard') should block"
            );
        }

        #[test]
        fn spawnsync_rm_rf_catastrophic_blocks_in_generic_function() {
            let matcher = AstMatcher::new();
            let code = "import * as child_process from 'child_process';\nfunction go<T extends string>(x: T): void {\n  child_process.spawnSync('rm', ['-rf', '/']);\n}\n";

            let matches = matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".rm_rf_catastrophic")
                        && m.severity.blocks_by_default()),
                "spawnSync('rm', ['-rf','/']) should block"
            );
        }

        #[test]
        fn deno_remove_catastrophic_blocks() {
            let matcher = AstMatcher::new();
            let code = "type Path = string;\nconst p: Path = '/etc';\nDeno.remove('/etc', { recursive: true });";

            let matches = matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(
                matches.iter().any(
                    |m| m.rule_id == "heredoc.typescript.deno_remove.catastrophic"
                        && m.severity.blocks_by_default()
                ),
                "catastrophic Deno.remove should block"
            );
        }
    }

    mod typescript_negative_fixtures {
        use super::*;

        #[test]
        fn execsync_safe_payload_does_not_match() {
            let matcher = AstMatcher::new();
            let code = "require('child_process').execSync('git status');";

            let matches = matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn fs_rmsync_without_recursive_does_not_match() {
            let matcher = AstMatcher::new();
            let code = "import * as fs from 'fs';\nfs.rmSync('./file.txt' as string);";

            let matches = matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn printed_dangerous_string_does_not_match() {
            let matcher = AstMatcher::new();
            let code = "console.log('rm -rf /');";

            let matches = matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn require_child_process_alone_does_not_match() {
            let matcher = AstMatcher::new();
            let code = "require('child_process');";

            let matches = matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn spawnsync_echo_does_not_match() {
            let matcher = AstMatcher::new();
            let code = "import * as child_process from 'child_process';\nchild_process.spawnSync('echo', ['rm -rf /']);";

            let matches = matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(matches.is_empty());
        }
    }

    #[test]
    fn bash_positive_match() {
        let matcher = AstMatcher::new();
        let code = "rm -rf /tmp/dangerous";

        let matches = matcher.find_matches(code, ScriptLanguage::Bash);
        match matches {
            Ok(m) => {
                assert!(!m.is_empty(), "should match rm -rf");
                assert!(m[0].rule_id.contains("bash"));
                assert!(m[0].severity.blocks_by_default());
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn bash_negative_match() {
        let matcher = AstMatcher::new();
        let code = "echo 'hello world'";

        let matches = matcher.find_matches(code, ScriptLanguage::Bash);
        match matches {
            Ok(m) => assert!(m.is_empty(), "should not match safe code"),
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    // =========================================================================
    // Python Fixture Tests (git_safety_guard-beq)
    // =========================================================================

    /// Positive fixtures: patterns that MUST match (Critical/High severity = blocks)
    mod python_positive_fixtures {
        use super::*;

        #[test]
        fn shutil_rmtree_blocks() {
            let matcher = AstMatcher::new();
            let code = "import shutil\nshutil.rmtree('/dangerous/path')";
            let matches = matcher.find_matches(code, ScriptLanguage::Python).unwrap();
            assert!(!matches.is_empty(), "shutil.rmtree must match");
            assert_eq!(matches[0].rule_id, "heredoc.python.shutil_rmtree");
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn os_remove_blocks() {
            let matcher = AstMatcher::new();
            let code = "import os\nos.remove('/etc/passwd')";
            let matches = matcher.find_matches(code, ScriptLanguage::Python).unwrap();
            assert!(!matches.is_empty(), "os.remove must match");
            assert_eq!(matches[0].rule_id, "heredoc.python.os_remove");
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn os_rmdir_blocks() {
            let matcher = AstMatcher::new();
            let code = "import os\nos.rmdir('/important/dir')";
            let matches = matcher.find_matches(code, ScriptLanguage::Python).unwrap();
            assert!(!matches.is_empty(), "os.rmdir must match");
            assert_eq!(matches[0].rule_id, "heredoc.python.os_rmdir");
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn os_unlink_blocks() {
            let matcher = AstMatcher::new();
            let code = "import os\nos.unlink('/critical/file')";
            let matches = matcher.find_matches(code, ScriptLanguage::Python).unwrap();
            assert!(!matches.is_empty(), "os.unlink must match");
            assert_eq!(matches[0].rule_id, "heredoc.python.os_unlink");
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn pathlib_unlink_blocks() {
            let matcher = AstMatcher::new();
            let code = "from pathlib import Path\nPath('/secret').unlink()";
            let matches = matcher.find_matches(code, ScriptLanguage::Python).unwrap();
            assert!(!matches.is_empty(), "pathlib.Path().unlink() must match");
            assert_eq!(matches[0].rule_id, "heredoc.python.pathlib_unlink");
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn pathlib_rmdir_blocks() {
            let matcher = AstMatcher::new();
            let code = "from pathlib import Path\nPath('/danger/dir').rmdir()";
            let matches = matcher.find_matches(code, ScriptLanguage::Python).unwrap();
            assert!(!matches.is_empty(), "pathlib.Path().rmdir() must match");
            assert_eq!(matches[0].rule_id, "heredoc.python.pathlib_rmdir");
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn subprocess_run_warns() {
            // subprocess.run is Medium severity - warns but doesn't block by default
            // per bead: "Do not block on shell=True alone"
            let matcher = AstMatcher::new();
            let code = "import subprocess\nsubprocess.run(['ls', '-la'])";
            let matches = matcher.find_matches(code, ScriptLanguage::Python).unwrap();
            assert!(!matches.is_empty(), "subprocess.run must match");
            assert_eq!(matches[0].rule_id, "heredoc.python.subprocess_run");
            assert!(
                !matches[0].severity.blocks_by_default(),
                "Medium should not block"
            );
        }

        #[test]
        fn os_system_warns() {
            // os.system is Medium severity - warns but doesn't block by default
            let matcher = AstMatcher::new();
            let code = "import os\nos.system('echo hello')";
            let matches = matcher.find_matches(code, ScriptLanguage::Python).unwrap();
            assert!(!matches.is_empty(), "os.system must match");
            assert_eq!(matches[0].rule_id, "heredoc.python.os_system");
            assert!(
                !matches[0].severity.blocks_by_default(),
                "Medium should not block"
            );
        }
    }

    /// Negative fixtures: patterns that must NOT match (safe code)
    mod python_negative_fixtures {
        use super::*;

        #[test]
        fn print_statement_does_not_match() {
            let matcher = AstMatcher::new();
            // String containing destructive command text is NOT executed
            let code = "print('rm -rf /')";
            let matches = matcher.find_matches(code, ScriptLanguage::Python).unwrap();
            assert!(matches.is_empty(), "print statement must not match");
        }

        #[test]
        fn import_alone_does_not_match() {
            let matcher = AstMatcher::new();
            // Just importing doesn't execute anything dangerous
            let code = "import shutil\nimport os\nimport subprocess";
            let matches = matcher.find_matches(code, ScriptLanguage::Python).unwrap();
            assert!(matches.is_empty(), "imports alone must not match");
        }

        #[test]
        fn comment_does_not_match() {
            let matcher = AstMatcher::new();
            // Comments mentioning dangerous operations are not executed
            let code = "# shutil.rmtree('/') would be dangerous\nx = 1";
            let matches = matcher.find_matches(code, ScriptLanguage::Python).unwrap();
            assert!(matches.is_empty(), "comments must not match");
        }

        #[test]
        fn safe_file_operations_do_not_match() {
            let matcher = AstMatcher::new();
            // Safe file operations should not trigger
            let code = r"
import os
os.path.exists('/tmp/test')
os.path.isfile('/tmp/test')
os.listdir('/tmp')
with open('/tmp/log.txt', 'w') as f:
    f.write('hello')
";
            let matches = matcher.find_matches(code, ScriptLanguage::Python).unwrap();
            assert!(matches.is_empty(), "safe file operations must not match");
        }

        #[test]
        fn string_variable_does_not_match() {
            let matcher = AstMatcher::new();
            // String that looks like dangerous code but is just data
            let code = r#"
dangerous_cmd = "shutil.rmtree('/')"
docs = "Example: os.remove(path)"
"#;
            let matches = matcher.find_matches(code, ScriptLanguage::Python).unwrap();
            assert!(matches.is_empty(), "string literals must not match");
        }

        #[test]
        fn docstring_does_not_match() {
            let matcher = AstMatcher::new();
            let code = r#"
def cleanup():
    """
    Warning: Do not call shutil.rmtree('/') as it will delete everything.
    Use os.remove() for single files only.
    """
    pass
"#;
            let matches = matcher.find_matches(code, ScriptLanguage::Python).unwrap();
            assert!(matches.is_empty(), "docstrings must not match");
        }

        #[test]
        fn safe_tmp_cleanup_in_context() {
            let matcher = AstMatcher::new();
            // This tests structural matching - the pattern matches but this is
            // about whether we match at all (we do), not about path safety
            // NOTE: This test verifies the pattern DOES match (as expected)
            // Path-based filtering would be a separate concern
            let code = "import shutil\nshutil.rmtree('/tmp/build_artifacts')";
            let matches = matcher.find_matches(code, ScriptLanguage::Python).unwrap();
            // Pattern matching finds this - path filtering is separate policy
            assert!(!matches.is_empty(), "shutil.rmtree matches structurally");
        }
    }
}
