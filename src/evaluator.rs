//! Shared command evaluator for hook mode and CLI.
//!
//! This module provides a unified evaluation entry point that can be used by both
//! the hook mode (stdin JSON) and CLI (`dcg test`) to ensure consistent behavior.
//!
//! # Architecture
//!
//! The evaluator performs the following steps in order:
//!
//! 1. **Config allow overrides** - Check if command matches an explicit allow pattern
//! 2. **Config block overrides** - Check if command matches an explicit block pattern
//! 3. **Heredoc/inline scripts** - Extract + AST-scan embedded code (fail-open)
//! 4. **Quick rejection** - Skip pack evaluation if no relevant keywords present
//! 5. **Context sanitization** - Mask known-safe string arguments (reduce false positives)
//! 6. **Command normalization** - Strip absolute paths from git/rm binaries
//! 7. **Pack registry** - Check enabled packs (safe patterns first, then destructive)
//!
//! # Example
//!
//! ```ignore
//! use destructive_command_guard::config::Config;
//! use destructive_command_guard::evaluator::{evaluate_command, EvaluationDecision};
//!
//! let config = Config::load();
//! let compiled_overrides = config.overrides.compile();
//! let enabled_keywords = vec!["git", "rm", "docker"];
//! let allowlists = destructive_command_guard::load_default_allowlists();
//! let result = evaluate_command(
//!     "git reset --hard",
//!     &config,
//!     &enabled_keywords,
//!     &compiled_overrides,
//!     &allowlists,
//! );
//!
//! match result.decision {
//!     EvaluationDecision::Allow => println!("Command allowed"),
//!     EvaluationDecision::Deny => {
//!         if let Some(info) = &result.pattern_info {
//!             println!("Blocked by {}: {}", info.pack_id.as_deref().unwrap_or("legacy"), info.reason);
//!         }
//!     }
//! }
//! ```

use crate::allowlist::{AllowlistLayer, LayeredAllowlist};
use crate::ast_matcher::DEFAULT_MATCHER;
use crate::config::Config;
use crate::context::sanitize_for_pattern_matching;
use crate::heredoc::{
    ExtractionResult, SkipReason, TriggerResult, check_triggers, extract_content,
};
use crate::normalize::{PATH_NORMALIZER, QUOTED_PATH_NORMALIZER, strip_wrapper_prefixes};
use crate::packs::{REGISTRY, pack_aware_quick_reject, pack_aware_quick_reject_with_normalized};
use crate::pending_exceptions::AllowOnceStore;
use crate::perf::Deadline;
use chrono::Utc;
use regex::RegexSet;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// Convert `ast_matcher::Severity` to `packs::Severity`.
///
/// Both enums have identical variants; this bridges the two type systems.
const fn ast_severity_to_pack_severity(s: crate::ast_matcher::Severity) -> crate::packs::Severity {
    match s {
        crate::ast_matcher::Severity::Critical => crate::packs::Severity::Critical,
        crate::ast_matcher::Severity::High => crate::packs::Severity::High,
        crate::ast_matcher::Severity::Medium => crate::packs::Severity::Medium,
        crate::ast_matcher::Severity::Low => crate::packs::Severity::Low,
    }
}

/// Maximum length for match text preview (in characters, not bytes).
const MAX_PREVIEW_CHARS: usize = 80;

/// Extract a UTF-8 safe preview of the matched text from a command.
///
/// The preview is truncated to `MAX_PREVIEW_CHARS` characters if too long,
/// with "..." appended to indicate truncation.
///
/// If the byte offsets fall in the middle of a multi-byte UTF-8 character,
/// we snap to the nearest valid character boundary to avoid panics.
fn extract_match_preview(command: &str, span: &MatchSpan) -> String {
    // Ensure byte offsets are within bounds
    let start = span.start.min(command.len());
    let end = span.end.min(command.len());

    if start >= end {
        return String::new();
    }

    // Snap to valid UTF-8 character boundaries to avoid panics.
    // If start is not at a boundary, move forward to the next boundary.
    // If end is not at a boundary, move backward to the previous boundary.
    let safe_start = if command.is_char_boundary(start) {
        start
    } else {
        // Find the next character boundary
        (start + 1..=command.len())
            .find(|&i| command.is_char_boundary(i))
            .unwrap_or(command.len())
    };

    let safe_end = if command.is_char_boundary(end) {
        end
    } else {
        // Find the previous character boundary
        (0..end)
            .rfind(|&i| command.is_char_boundary(i))
            .unwrap_or(0)
    };

    if safe_start >= safe_end {
        return String::new();
    }

    // Now safe to slice (boundaries are guaranteed valid)
    let matched = &command[safe_start..safe_end];

    // Truncate to MAX_PREVIEW_CHARS characters (UTF-8 safe)
    truncate_preview(matched, MAX_PREVIEW_CHARS)
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

// ============================================================================
// UTF-8 Safe Windowing for Long Commands
// ============================================================================

/// Default maximum width for command display (characters, not bytes).
pub const DEFAULT_WINDOW_WIDTH: usize = 120;

/// Result of windowing a command for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowedCommand {
    /// The windowed command string (with "..." if truncated).
    pub display: String,
    /// The span adjusted for the windowed string (for caret alignment).
    /// None if the original span couldn't be mapped to the window.
    pub adjusted_span: Option<WindowedSpan>,
}

/// Span within the windowed command for caret alignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowedSpan {
    /// Start character offset in the windowed display string.
    pub start: usize,
    /// End character offset in the windowed display string.
    pub end: usize,
}

/// Snap a byte offset to the nearest valid UTF-8 character boundary.
///
/// If `prefer_forward` is true, snaps forward; otherwise snaps backward.
fn snap_to_char_boundary(s: &str, offset: usize, prefer_forward: bool) -> usize {
    if offset >= s.len() {
        return s.len();
    }
    if s.is_char_boundary(offset) {
        return offset;
    }
    if prefer_forward {
        (offset + 1..=s.len())
            .find(|&i| s.is_char_boundary(i))
            .unwrap_or(s.len())
    } else {
        (0..offset).rfind(|&i| s.is_char_boundary(i)).unwrap_or(0)
    }
}

/// Create a windowed view of a command centered around a match span.
///
/// This function:
/// - Returns the full command if it fits within `max_width` characters
/// - Otherwise, centers the window around the match span
/// - Adds "..." prefix when left-truncating
/// - Adds "..." suffix when right-truncating
/// - Ensures all slicing respects UTF-8 character boundaries
///
/// # Arguments
///
/// * `command` - The full command string
/// * `span` - The match span (byte offsets) to center around
/// * `max_width` - Maximum display width in characters (not bytes)
///
/// # Returns
///
/// A `WindowedCommand` with the display string and adjusted span for caret alignment.
///
/// # Example
///
/// ```
/// use destructive_command_guard::evaluator::{window_command, MatchSpan};
///
/// let cmd = "very long prefix ... git reset --hard ... more suffix text";
/// let span = MatchSpan { start: 24, end: 40 }; // "git reset --hard"
/// let result = window_command(cmd, &span, 40);
///
/// // Result shows match in context with ellipsis
/// assert!(result.display.contains("git reset --hard"));
/// assert!(result.adjusted_span.is_some());
/// ```
#[must_use]
pub fn window_command(command: &str, span: &MatchSpan, max_width: usize) -> WindowedCommand {
    let char_count = command.chars().count();

    // If command fits, return as-is with byte-to-char span conversion
    if char_count <= max_width {
        let adjusted_span = byte_span_to_char_span(command, span);
        return WindowedCommand {
            display: command.to_string(),
            adjusted_span,
        };
    }

    // Snap span to character boundaries
    let safe_start = snap_to_char_boundary(command, span.start, true);
    let safe_end = snap_to_char_boundary(command, span.end, false);

    if safe_start >= safe_end || safe_start >= command.len() {
        // Invalid span - return truncated command without span
        let truncated: String = command.chars().take(max_width.saturating_sub(3)).collect();
        return WindowedCommand {
            display: format!("{truncated}..."),
            adjusted_span: None,
        };
    }

    // Convert byte offsets to character positions for windowing logic
    let match_char_start = command[..safe_start].chars().count();
    let match_char_end = command[..safe_end].chars().count();
    let match_char_len = match_char_end.saturating_sub(match_char_start);

    // Calculate window bounds in character positions
    // Reserve space for "..." on each side (3 chars each)
    let ellipsis_len = 3;
    let available_width = max_width.saturating_sub(ellipsis_len * 2);

    // If match itself is larger than window, show what we can
    if match_char_len >= available_width {
        let visible_match: String = command[safe_start..safe_end]
            .chars()
            .take(available_width)
            .collect();
        return WindowedCommand {
            display: format!("...{visible_match}..."),
            adjusted_span: Some(WindowedSpan {
                start: ellipsis_len,
                end: ellipsis_len + visible_match.chars().count(),
            }),
        };
    }

    // Calculate context to show around the match
    let context_budget = available_width.saturating_sub(match_char_len);
    let left_context = context_budget / 2;
    let right_context = context_budget - left_context;

    // Determine window start/end in character positions
    let window_char_start = match_char_start.saturating_sub(left_context);
    let window_char_end = (match_char_end + right_context).min(char_count);

    // Check if we need ellipsis on each side
    let needs_left_ellipsis = window_char_start > 0;
    let needs_right_ellipsis = window_char_end < char_count;

    // Build the windowed string
    let mut result = String::new();
    let adjusted_start = if needs_left_ellipsis {
        result.push_str("...");
        ellipsis_len
    } else {
        0
    };

    // Extract the windowed portion
    let windowed: String = command
        .chars()
        .skip(window_char_start)
        .take(window_char_end - window_char_start)
        .collect();

    // Calculate adjusted span within the windowed result
    let span_start_in_window = match_char_start - window_char_start + adjusted_start;
    let span_end_in_window = span_start_in_window + match_char_len;

    result.push_str(&windowed);

    if needs_right_ellipsis {
        result.push_str("...");
    }

    WindowedCommand {
        display: result,
        adjusted_span: Some(WindowedSpan {
            start: span_start_in_window,
            end: span_end_in_window,
        }),
    }
}

/// Convert a byte span to a character span for caret alignment.
fn byte_span_to_char_span(command: &str, span: &MatchSpan) -> Option<WindowedSpan> {
    let safe_start = snap_to_char_boundary(command, span.start, true);
    let safe_end = snap_to_char_boundary(command, span.end, false);

    if safe_start >= safe_end || safe_start >= command.len() {
        return None;
    }

    let char_start = command[..safe_start].chars().count();
    let char_end = command[..safe_end].chars().count();

    Some(WindowedSpan {
        start: char_start,
        end: char_end,
    })
}

fn compute_normalized_offset(command_for_match: &str, normalized: &str) -> Option<usize> {
    if normalized == command_for_match {
        return Some(0);
    }

    if let Some(pos) = command_for_match.find(normalized) {
        return Some(pos);
    }

    let stripped = strip_wrapper_prefixes(command_for_match);
    let stripped_cmd = stripped.normalized.as_ref();
    let base_offset = command_for_match.find(stripped_cmd)?;

    if stripped_cmd == normalized {
        return Some(base_offset);
    }

    if let Some(pos) = stripped_cmd.find(normalized) {
        return Some(base_offset + pos);
    }

    if let Ok(Some(caps)) = QUOTED_PATH_NORMALIZER.captures(stripped_cmd) {
        if let Some(m) = caps.get(1) {
            return Some(base_offset + m.start());
        }
    }

    if let Ok(Some(caps)) = PATH_NORMALIZER.captures(stripped_cmd) {
        if let Some(m) = caps.get(1) {
            return Some(base_offset + m.start());
        }
    }

    None
}

fn map_span_with_offset(
    span: MatchSpan,
    offset: Option<usize>,
    original_len: usize,
) -> Option<MatchSpan> {
    let offset = offset?;
    let start = span.start.saturating_add(offset);
    let end = span.end.saturating_add(offset);
    if start <= end && end <= original_len {
        Some(MatchSpan { start, end })
    } else {
        None
    }
}

/// The decision made by the evaluator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationDecision {
    /// Command is allowed to execute.
    Allow,
    /// Command is blocked from executing.
    Deny,
}

/// Byte span of a match within the evaluated command string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchSpan {
    /// Start byte offset (inclusive).
    pub start: usize,
    /// End byte offset (exclusive).
    pub end: usize,
}

/// Information about the pattern that matched (for denials).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternMatch {
    /// The pack that blocked the command (None for legacy patterns or config overrides).
    pub pack_id: Option<String>,
    /// The name of the pattern that matched (if available).
    pub pattern_name: Option<String>,
    /// Severity level of the matched pattern.
    pub severity: Option<crate::packs::Severity>,
    /// Human-readable reason for blocking.
    pub reason: String,
    /// Source of the match (for debugging/explain mode).
    pub source: MatchSource,
    /// Byte span of the first match within the command (for explain highlighting).
    pub matched_span: Option<MatchSpan>,
    /// Preview of the matched text (UTF-8 safe, truncated if too long).
    pub matched_text_preview: Option<String>,
    /// Detailed explanation of why this pattern is dangerous.
    /// More verbose than `reason`, intended for explain/verbose output modes.
    /// Falls back to `reason` when not provided.
    pub explanation: Option<String>,
}

/// Information about an allowlist override (DENY -> ALLOW).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowlistOverride {
    /// Which allowlist layer matched (project/user/system).
    pub layer: AllowlistLayer,
    /// The allowlist entry reason (why this override exists).
    pub reason: String,
    /// The match that would have denied the command.
    pub matched: PatternMatch,
}

/// Source of a pattern match (for debugging and explain mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchSource {
    /// Matched a config override (allow or block).
    ConfigOverride,
    /// Matched a legacy pattern in main.rs.
    LegacyPattern,
    /// Matched a pattern from a pack.
    Pack,
    /// Matched an AST/heuristic pattern in an embedded script (heredoc / inline code).
    HeredocAst,
}

/// Result of evaluating a command.
#[derive(Debug, Clone)]
pub struct EvaluationResult {
    /// The decision (Allow or Deny).
    pub decision: EvaluationDecision,
    /// Pattern match information (present when decision is Deny or Warn).
    pub pattern_info: Option<PatternMatch>,
    /// Allowlist override information (present when decision is Allow due to allowlist).
    pub allowlist_override: Option<AllowlistOverride>,
    /// Effective decision mode (how to handle the decision).
    /// Present when a pattern matched. None means the command is clean (no pattern matched).
    /// - Deny: block command, output warning + JSON deny
    /// - Warn: allow command, output warning only
    /// - Log: allow command, log only (no visible output)
    pub effective_mode: Option<crate::packs::DecisionMode>,
    /// Whether evaluation skipped deeper analysis due to a deadline overrun.
    pub skipped_due_to_budget: bool,
}

impl EvaluationResult {
    /// Create an "allowed" result.
    #[inline]
    #[must_use]
    pub const fn allowed() -> Self {
        Self {
            decision: EvaluationDecision::Allow,
            pattern_info: None,
            allowlist_override: None,
            effective_mode: None,
            skipped_due_to_budget: false,
        }
    }

    /// Create an "allowed" result due to budget exhaustion (fail-open).
    #[inline]
    #[must_use]
    pub const fn allowed_due_to_budget() -> Self {
        Self {
            decision: EvaluationDecision::Allow,
            pattern_info: None,
            allowlist_override: None,
            effective_mode: None,
            skipped_due_to_budget: true,
        }
    }

    /// Create a "denied" result from config override.
    #[inline]
    #[must_use]
    pub const fn denied_by_config(reason: String) -> Self {
        Self {
            decision: EvaluationDecision::Deny,
            pattern_info: Some(PatternMatch {
                pack_id: None,
                pattern_name: None,
                severity: None,
                reason,
                source: MatchSource::ConfigOverride,
                matched_span: None,
                matched_text_preview: None,
                explanation: None,
            }),
            allowlist_override: None,
            effective_mode: Some(crate::packs::DecisionMode::Deny),
            skipped_due_to_budget: false,
        }
    }

    /// Create a "denied" result from legacy pattern.
    #[inline]
    #[must_use]
    pub fn denied_by_legacy(reason: &str) -> Self {
        Self {
            decision: EvaluationDecision::Deny,
            pattern_info: Some(PatternMatch {
                pack_id: None,
                pattern_name: None,
                severity: None,
                reason: reason.to_string(),
                source: MatchSource::LegacyPattern,
                matched_span: None,
                matched_text_preview: None,
                explanation: None,
            }),
            allowlist_override: None,
            effective_mode: Some(crate::packs::DecisionMode::Deny),
            skipped_due_to_budget: false,
        }
    }

    /// Create a "denied" result from legacy pattern with match span.
    #[inline]
    #[must_use]
    pub fn denied_by_legacy_with_span(reason: &str, command: &str, span: MatchSpan) -> Self {
        let preview = extract_match_preview(command, &span);
        Self {
            decision: EvaluationDecision::Deny,
            pattern_info: Some(PatternMatch {
                pack_id: None,
                pattern_name: None,
                severity: None,
                reason: reason.to_string(),
                source: MatchSource::LegacyPattern,
                matched_span: Some(span),
                matched_text_preview: Some(preview),
                explanation: None,
            }),
            allowlist_override: None,
            effective_mode: Some(crate::packs::DecisionMode::Deny),
            skipped_due_to_budget: false,
        }
    }

    /// Create a "denied" result from a pack.
    #[inline]
    #[must_use]
    pub fn denied_by_pack(pack_id: &str, reason: &str, explanation: Option<&str>) -> Self {
        Self {
            decision: EvaluationDecision::Deny,
            pattern_info: Some(PatternMatch {
                pack_id: Some(pack_id.to_string()),
                pattern_name: None,
                severity: None,
                reason: reason.to_string(),
                source: MatchSource::Pack,
                matched_span: None,
                matched_text_preview: None,
                explanation: explanation.map(str::to_string),
            }),
            allowlist_override: None,
            effective_mode: Some(crate::packs::DecisionMode::Deny),
            skipped_due_to_budget: false,
        }
    }

    /// Create a "denied" result from a pack with match span info.
    #[inline]
    #[must_use]
    pub fn denied_by_pack_with_span(
        pack_id: &str,
        reason: &str,
        explanation: Option<&str>,
        command: &str,
        span: MatchSpan,
    ) -> Self {
        let preview = extract_match_preview(command, &span);
        Self {
            decision: EvaluationDecision::Deny,
            pattern_info: Some(PatternMatch {
                pack_id: Some(pack_id.to_string()),
                pattern_name: None,
                severity: None,
                reason: reason.to_string(),
                source: MatchSource::Pack,
                matched_span: Some(span),
                matched_text_preview: Some(preview),
                explanation: explanation.map(str::to_string),
            }),
            allowlist_override: None,
            effective_mode: Some(crate::packs::DecisionMode::Deny),
            skipped_due_to_budget: false,
        }
    }

    /// Create a "denied" result from a pack with pattern name.
    #[inline]
    #[must_use]
    pub fn denied_by_pack_pattern(
        pack_id: &str,
        pattern_name: &str,
        reason: &str,
        explanation: Option<&str>,
        severity: crate::packs::Severity,
    ) -> Self {
        Self {
            decision: EvaluationDecision::Deny,
            pattern_info: Some(PatternMatch {
                pack_id: Some(pack_id.to_string()),
                pattern_name: Some(pattern_name.to_string()),
                severity: Some(severity),
                reason: reason.to_string(),
                source: MatchSource::Pack,
                matched_span: None,
                matched_text_preview: None,
                explanation: explanation.map(str::to_string),
            }),
            allowlist_override: None,
            effective_mode: Some(severity.default_mode()),
            skipped_due_to_budget: false,
        }
    }

    /// Create a "denied" result from a pack with pattern name and match span.
    #[inline]
    #[must_use]
    pub fn denied_by_pack_pattern_with_span(
        pack_id: &str,
        pattern_name: &str,
        reason: &str,
        explanation: Option<&str>,
        severity: crate::packs::Severity,
        command: &str,
        span: MatchSpan,
    ) -> Self {
        let preview = extract_match_preview(command, &span);
        Self {
            decision: EvaluationDecision::Deny,
            pattern_info: Some(PatternMatch {
                pack_id: Some(pack_id.to_string()),
                pattern_name: Some(pattern_name.to_string()),
                severity: Some(severity),
                reason: reason.to_string(),
                source: MatchSource::Pack,
                matched_span: Some(span),
                matched_text_preview: Some(preview),
                explanation: explanation.map(str::to_string),
            }),
            allowlist_override: None,
            effective_mode: Some(severity.default_mode()),
            skipped_due_to_budget: false,
        }
    }

    /// Create an "allowed" result due to allowlist override.
    #[must_use]
    pub const fn allowed_by_allowlist(
        matched: PatternMatch,
        layer: AllowlistLayer,
        reason: String,
    ) -> Self {
        Self {
            decision: EvaluationDecision::Allow,
            pattern_info: None,
            allowlist_override: Some(AllowlistOverride {
                layer,
                reason,
                matched,
            }),
            // Allowlist overrides apply to a matched rule (typically deny-by-default).
            effective_mode: Some(crate::packs::DecisionMode::Deny),
            skipped_due_to_budget: false,
        }
    }

    /// Check if the command was allowed.
    #[inline]
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        self.decision == EvaluationDecision::Allow
    }

    /// Check if the command was denied.
    #[inline]
    #[must_use]
    pub fn is_denied(&self) -> bool {
        self.decision == EvaluationDecision::Deny
    }

    /// Get the reason for denial (if denied).
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.pattern_info.as_ref().map(|p| p.reason.as_str())
    }

    /// Get the pack ID that blocked (if denied by a pack).
    #[must_use]
    pub fn pack_id(&self) -> Option<&str> {
        self.pattern_info
            .as_ref()
            .and_then(|p| p.pack_id.as_deref())
    }
}

/// Evaluate a command against all patterns and packs using precompiled overrides.
///
/// This is the main entry point for command evaluation. It performs all checks
/// in the correct order and returns a structured result.
///
/// # Arguments
///
/// * `command` - The raw command string to evaluate
/// * `config` - Loaded configuration with pack settings
/// * `enabled_keywords` - Keywords from enabled packs for quick rejection
/// * `compiled_overrides` - Precompiled config overrides (avoids per-command regex compilation)
///
/// # Returns
///
/// An `EvaluationResult` indicating whether the command is allowed or denied,
/// with detailed pattern match information for denials.
///
/// # Performance
///
/// This function is optimized for the common case (allow):
/// - Quick rejection skips regex for 99%+ of commands
/// - Config overrides use precompiled regexes (no per-command compilation)
/// - Short-circuits on first match
#[must_use]
pub fn evaluate_command(
    command: &str,
    config: &Config,
    enabled_keywords: &[&str],
    compiled_overrides: &crate::config::CompiledOverrides,
    allowlists: &LayeredAllowlist,
) -> EvaluationResult {
    evaluate_command_with_deadline(
        command,
        config,
        enabled_keywords,
        compiled_overrides,
        allowlists,
        None,
    )
}

#[inline]
fn deadline_exceeded(deadline: Option<&Deadline>) -> bool {
    deadline.is_some_and(|d| d.max_duration().is_zero() || d.is_exceeded())
}

#[inline]
fn remaining_below(deadline: Option<&Deadline>, budget: &crate::perf::Budget) -> bool {
    deadline.is_some_and(|d| !d.has_budget_for(budget))
}

fn resolve_project_path(
    heredoc_settings: &crate::config::HeredocSettings,
    project_path: Option<&Path>,
) -> Option<PathBuf> {
    if heredoc_settings
        .content_allowlist
        .as_ref()
        .is_none_or(|a| a.projects.is_empty())
    {
        return None;
    }

    if let Some(path) = project_path {
        return Some(path.to_path_buf());
    }

    std::env::current_dir().ok()
}

fn allow_once_match(
    command: &str,
    allow_once_audit: Option<&crate::pending_exceptions::AllowOnceAuditConfig<'_>>,
) -> Option<crate::pending_exceptions::AllowOnceEntry> {
    let cwd = std::env::current_dir().ok()?;
    let store = AllowOnceStore::new(AllowOnceStore::default_path(Some(&cwd)));
    match store.match_command(command, &cwd, Utc::now(), allow_once_audit) {
        Ok(Some(entry)) => Some(entry),
        _ => None,
    }
}

#[allow(dead_code)]
fn allow_once_match_force_config(
    command: &str,
    allow_once_audit: Option<&crate::pending_exceptions::AllowOnceAuditConfig<'_>>,
) -> Option<crate::pending_exceptions::AllowOnceEntry> {
    let cwd = std::env::current_dir().ok()?;
    let store = AllowOnceStore::new(AllowOnceStore::default_path(Some(&cwd)));
    match store.match_command_force_config(command, &cwd, Utc::now(), allow_once_audit) {
        Ok(Some(entry)) => Some(entry),
        _ => None,
    }
}

/// Evaluate a command against all patterns and packs using a deadline.
///
/// When `deadline` is provided and exceeded, evaluation fails open and returns
/// `skipped_due_to_budget=true` so hook mode can allow the command safely.
#[must_use]
pub fn evaluate_command_with_deadline(
    command: &str,
    config: &Config,
    enabled_keywords: &[&str],
    compiled_overrides: &crate::config::CompiledOverrides,
    allowlists: &LayeredAllowlist,
    deadline: Option<&Deadline>,
) -> EvaluationResult {
    let enabled_packs: HashSet<String> = config.enabled_pack_ids();
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    let keyword_index = REGISTRY.build_enabled_keyword_index(&ordered_packs);
    let heredoc_settings = config.heredoc_settings();
    evaluate_command_with_pack_order_deadline(
        command,
        enabled_keywords,
        &ordered_packs,
        keyword_index.as_ref(),
        compiled_overrides,
        allowlists,
        &heredoc_settings,
        None,
        deadline,
    )
}

/// Evaluate a command using a precomputed pack order.
///
/// This is the hot-path optimized variant for hook mode: callers can compute the
/// enabled pack set and expanded ordered pack list once at startup and reuse it
/// for every command invocation.
///
/// # Arguments
///
/// * `command` - The raw command string to evaluate
/// * `enabled_keywords` - Keywords from enabled packs for quick rejection
/// * `ordered_packs` - Expanded pack IDs in deterministic evaluation order
/// * `compiled_overrides` - Precompiled config overrides
/// * `allowlists` - Layered allowlists (project/user/system)
#[must_use]
pub fn evaluate_command_with_pack_order(
    command: &str,
    enabled_keywords: &[&str],
    ordered_packs: &[String],
    keyword_index: Option<&crate::packs::EnabledKeywordIndex>,
    compiled_overrides: &crate::config::CompiledOverrides,
    allowlists: &LayeredAllowlist,
    heredoc_settings: &crate::config::HeredocSettings,
) -> EvaluationResult {
    evaluate_command_with_pack_order_at_path(
        command,
        enabled_keywords,
        ordered_packs,
        keyword_index,
        compiled_overrides,
        allowlists,
        heredoc_settings,
        None,
    )
}

/// Evaluate a command using a precomputed pack order and an optional project path.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn evaluate_command_with_pack_order_at_path(
    command: &str,
    enabled_keywords: &[&str],
    ordered_packs: &[String],
    keyword_index: Option<&crate::packs::EnabledKeywordIndex>,
    compiled_overrides: &crate::config::CompiledOverrides,
    allowlists: &LayeredAllowlist,
    heredoc_settings: &crate::config::HeredocSettings,
    project_path: Option<&Path>,
) -> EvaluationResult {
    evaluate_command_with_pack_order_deadline_at_path(
        command,
        enabled_keywords,
        ordered_packs,
        keyword_index,
        compiled_overrides,
        allowlists,
        heredoc_settings,
        None,
        project_path,
        None,
    )
}

/// Evaluate a command with deadline support for fail-open behavior.
///
/// This is the hook-mode entry point that supports budget enforcement.
/// If the deadline is exceeded at check points, returns `allowed_due_to_budget()`.
///
/// # Arguments
///
/// * `command` - The raw command string to evaluate
/// * `enabled_keywords` - Keywords from enabled packs for quick rejection
/// * `ordered_packs` - Ordered list of enabled pack IDs
/// * `compiled_overrides` - Precompiled config overrides
/// * `allowlists` - Layered allowlist for overrides
/// * `heredoc_settings` - Settings for heredoc analysis
/// * `deadline` - Optional deadline for fail-open behavior
///
/// # Returns
///
/// An `EvaluationResult` with `skipped_due_to_budget: true` if deadline exceeded.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn evaluate_command_with_pack_order_deadline(
    command: &str,
    enabled_keywords: &[&str],
    ordered_packs: &[String],
    keyword_index: Option<&crate::packs::EnabledKeywordIndex>,
    compiled_overrides: &crate::config::CompiledOverrides,
    allowlists: &LayeredAllowlist,
    heredoc_settings: &crate::config::HeredocSettings,
    allow_once_audit: Option<&crate::pending_exceptions::AllowOnceAuditConfig<'_>>,
    deadline: Option<&Deadline>,
) -> EvaluationResult {
    evaluate_command_with_pack_order_deadline_at_path(
        command,
        enabled_keywords,
        ordered_packs,
        keyword_index,
        compiled_overrides,
        allowlists,
        heredoc_settings,
        allow_once_audit,
        None,
        deadline,
    )
}

/// Evaluate a command with deadline support and an optional project path.
#[must_use]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub fn evaluate_command_with_pack_order_deadline_at_path(
    command: &str,
    enabled_keywords: &[&str],
    ordered_packs: &[String],
    keyword_index: Option<&crate::packs::EnabledKeywordIndex>,
    compiled_overrides: &crate::config::CompiledOverrides,
    allowlists: &LayeredAllowlist,
    heredoc_settings: &crate::config::HeredocSettings,
    allow_once_audit: Option<&crate::pending_exceptions::AllowOnceAuditConfig<'_>>,
    project_path: Option<&Path>,
    deadline: Option<&Deadline>,
) -> EvaluationResult {
    // Check deadline at entry - if already exceeded, fail-open immediately.
    if deadline_exceeded(deadline) {
        return EvaluationResult::allowed_due_to_budget();
    }

    // Empty commands are allowed (no-op)
    if command.is_empty() {
        return EvaluationResult::allowed();
    }

    // Step 1: Check precompiled allow overrides first
    if compiled_overrides.check_allow(command) {
        return EvaluationResult::allowed();
    }

    // Step 1.5: Check precompiled block overrides (allow-once may optionally override).
    if let Some(reason) = compiled_overrides.check_block(command) {
        if allow_once_match_force_config(command, allow_once_audit).is_some() {
            return EvaluationResult::allowed();
        }
        return EvaluationResult::denied_by_config(reason.to_string());
    }

    // Step 1.6: Check allow-once overrides.
    if allow_once_match(command, allow_once_audit).is_some() {
        return EvaluationResult::allowed();
    }

    if deadline_exceeded(deadline) {
        return EvaluationResult::allowed_due_to_budget();
    }

    // Step 3: Heredoc / inline-script detection (Tier 1/2/3, fail-open).
    let mut precomputed_sanitized = None;
    let mut heredoc_allowlist_hit: Option<(PatternMatch, AllowlistLayer, String)> = None;

    let project_path = resolve_project_path(heredoc_settings, project_path);
    let project_path = project_path.as_deref();

    if heredoc_settings.enabled {
        if remaining_below(deadline, &crate::perf::HEREDOC_TRIGGER) {
            return EvaluationResult::allowed_due_to_budget();
        }

        if check_triggers(command) == TriggerResult::Triggered {
            let sanitized = sanitize_for_pattern_matching(command);
            let sanitized_str = sanitized.as_ref();
            let should_scan = if matches!(sanitized, std::borrow::Cow::Owned(_)) {
                check_triggers(sanitized_str) == TriggerResult::Triggered
            } else {
                true
            };
            precomputed_sanitized = Some(sanitized);

            if should_scan {
                let context = HeredocEvaluationContext {
                    allowlists,
                    heredoc_settings,
                    project_path,
                    deadline,
                    enabled_keywords,
                    ordered_packs,
                    keyword_index,
                    compiled_overrides,
                    allow_once_audit,
                };
                if let Some(blocked) =
                    evaluate_heredoc(command, context, &mut heredoc_allowlist_hit)
                {
                    return blocked;
                }
            }
        }
    }

    if deadline_exceeded(deadline) {
        return EvaluationResult::allowed_due_to_budget();
    }

    // Step 4: Quick rejection - if no relevant keywords, allow immediately
    if pack_aware_quick_reject(command, enabled_keywords) {
        if let Some((matched, layer, reason)) = heredoc_allowlist_hit {
            return EvaluationResult::allowed_by_allowlist(matched, layer, reason);
        }
        return EvaluationResult::allowed();
    }

    if deadline_exceeded(deadline) {
        return EvaluationResult::allowed_due_to_budget();
    }

    // Step 5: False-positive immunity - strip known-safe string arguments (commit messages, search
    // patterns, issue descriptions, etc.) so dangerous substrings inside data do not trigger
    // blocking.
    //
    // Also normalize the command here (Step 6) and reuse for pack evaluation.
    // pack_aware_quick_reject_with_normalized returns both the quick-reject decision
    // and the normalized command, avoiding duplicate normalization.
    let sanitized = precomputed_sanitized.unwrap_or_else(|| sanitize_for_pattern_matching(command));
    let command_for_match = sanitized.as_ref();

    // Use the optimized version that returns both decision and normalized form.
    let (quick_reject, normalized) =
        pack_aware_quick_reject_with_normalized(command_for_match, enabled_keywords);
    if matches!(sanitized, std::borrow::Cow::Owned(_)) && quick_reject {
        if let Some((matched, layer, reason)) = heredoc_allowlist_hit {
            return EvaluationResult::allowed_by_allowlist(matched, layer, reason);
        }
        return EvaluationResult::allowed();
    }

    if deadline_exceeded(deadline) {
        return EvaluationResult::allowed_due_to_budget();
    }

    // Check exact command and prefix allowlists (reusing normalized from quick-reject)
    if allowlists.match_exact_command(&normalized).is_some()
        || allowlists.match_command_prefix(&normalized).is_some()
    {
        return EvaluationResult::allowed();
    }

    // Step 7: Mask heredoc content for non-executing targets (cat, tee, etc.)
    // This prevents false positives where documentation text containing dangerous
    // patterns like "rm -rf /" in heredocs to cat/tee triggers blocking.
    let masked = crate::heredoc::mask_non_executing_heredocs(&normalized);
    let command_for_packs = masked.as_ref();

    let result = evaluate_packs_with_allowlists(
        command_for_packs,
        &normalized,
        command_for_match,
        command,
        ordered_packs,
        allowlists,
        keyword_index,
        None,
    );
    if result.allowlist_override.is_none() {
        if let Some((matched, layer, reason)) = heredoc_allowlist_hit {
            return EvaluationResult::allowed_by_allowlist(matched, layer, reason);
        }
    }

    result
}

#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
fn evaluate_packs_with_allowlists(
    command_for_packs: &str,
    normalized: &str,
    command_for_match: &str,
    original_command: &str,
    ordered_packs: &[String],
    allowlists: &LayeredAllowlist,
    keyword_index: Option<&crate::packs::EnabledKeywordIndex>,
    deadline: Option<&Deadline>,
) -> EvaluationResult {
    if deadline_exceeded(deadline) || remaining_below(deadline, &crate::perf::PATTERN_MATCH) {
        return EvaluationResult::allowed_due_to_budget();
    }

    // Pre-compute which packs might match.
    //
    // When a keyword index is available, use a single global substring scan to
    // conservatively select candidate packs (superset of legacy PackEntry::might_match).
    // Otherwise, fall back to the per-pack metadata scan.
    let candidate_packs: Vec<(&String, &crate::packs::Pack)> = keyword_index.map_or_else(
        || {
            ordered_packs
                .iter()
                .filter_map(|pack_id| {
                    let entry = REGISTRY.get_entry(pack_id)?;
                    if !entry.might_match(command_for_packs) {
                        return None;
                    }
                    Some((pack_id, entry.get_pack()))
                })
                .collect()
        },
        |index| {
            let mask = index.candidate_pack_mask(command_for_packs);
            ordered_packs
                .iter()
                .enumerate()
                .filter_map(|(i, pack_id)| {
                    if (mask >> i) & 1 == 0 {
                        return None;
                    }
                    let entry = REGISTRY.get_entry(pack_id)?;
                    Some((pack_id, entry.get_pack()))
                })
                .collect()
        },
    );

    let has_filesystem_pack = candidate_packs
        .iter()
        .any(|(pack_id, _)| pack_id.as_str() == "core.filesystem");
    let rm_parse = has_filesystem_pack
        .then(|| crate::packs::core::filesystem::parse_rm_command(command_for_packs));

    let normalized_offset = compute_normalized_offset(command_for_match, normalized);
    let original_len = original_command.len();

    // Single-pass per-pack evaluation: safe patterns only protect their own pack's
    // destructive patterns, not other packs. This prevents compound command bypass
    // where e.g., "git checkout -b foo" safe pattern would whitelist "rm -rf / ; git checkout -b foo".
    //
    // For each pack:
    // 1. Check safe patterns - if match, skip this pack's destructive patterns (continue)
    // 2. Check destructive patterns - if match, block (unless allowlisted)
    //
    // The rm_parse optimization for core.filesystem is handled inline.
    let mut first_allowlist_hit: Option<(PatternMatch, AllowlistLayer, String)> = None;

    for &(pack_id, pack) in &candidate_packs {
        if deadline_exceeded(deadline) || remaining_below(deadline, &crate::perf::PATTERN_MATCH) {
            return EvaluationResult::allowed_due_to_budget();
        }

        // Check safe patterns for this pack first.
        // If a safe pattern matches, skip this pack's destructive patterns only.
        // This prevents compound command bypass where one pack's safe pattern
        // would whitelist destructive commands from other packs.
        if pack_id == "core.filesystem" {
            // core.filesystem uses rm_parse for more accurate safe pattern detection
            match rm_parse.as_ref() {
                Some(crate::packs::core::filesystem::RmParseDecision::Allow) => {
                    continue; // Safe pattern match - skip this pack
                }
                Some(crate::packs::core::filesystem::RmParseDecision::NoMatch) | None => {
                    // rm_parse didn't find rm command or wasn't computed, check safe patterns as fallback
                    if pack.matches_safe(command_for_packs) {
                        continue;
                    }
                }
                Some(crate::packs::core::filesystem::RmParseDecision::Deny(hit)) => {
                    if let Some(allow_hit) = allowlists.match_rule(pack_id, hit.pattern_name) {
                        if first_allowlist_hit.is_none() {
                            let span = hit.span.as_ref().map(|span| MatchSpan {
                                start: span.start,
                                end: span.end,
                            });
                            let mapped_span = span.and_then(|span| {
                                map_span_with_offset(span, normalized_offset, original_len)
                            });
                            let preview = mapped_span
                                .as_ref()
                                .map(|span| extract_match_preview(original_command, span))
                                .or_else(|| {
                                    span.as_ref()
                                        .map(|span| extract_match_preview(command_for_packs, span))
                                });
                            first_allowlist_hit = Some((
                                PatternMatch {
                                    pack_id: Some(pack_id.clone()),
                                    pattern_name: Some(hit.pattern_name.to_string()),
                                    severity: Some(hit.severity),
                                    reason: hit.reason.to_string(),
                                    source: MatchSource::Pack,
                                    matched_span: mapped_span,
                                    matched_text_preview: preview,
                                    explanation: None,
                                },
                                allow_hit.layer,
                                allow_hit.entry.reason.clone(),
                            ));
                        }
                        continue;
                    }

                    if let Some(span) = hit.span.as_ref().map(|span| MatchSpan {
                        start: span.start,
                        end: span.end,
                    }) {
                        if let Some(mapped_span) =
                            map_span_with_offset(span, normalized_offset, original_len)
                        {
                            return EvaluationResult::denied_by_pack_pattern_with_span(
                                pack_id,
                                hit.pattern_name,
                                hit.reason,
                                None,
                                hit.severity,
                                original_command,
                                mapped_span,
                            );
                        }
                    }

                    return EvaluationResult::denied_by_pack_pattern(
                        pack_id,
                        hit.pattern_name,
                        hit.reason,
                        None,
                        hit.severity,
                    );
                }
            }
        } else {
            // Non-core.filesystem packs: check safe patterns before destructive
            if pack.matches_safe(command_for_packs) {
                continue; // Safe pattern match - skip this pack's destructive patterns
            }
        }

        for pattern in &pack.destructive_patterns {
            if deadline_exceeded(deadline) || remaining_below(deadline, &crate::perf::PATTERN_MATCH)
            {
                return EvaluationResult::allowed_due_to_budget();
            }

            // All severity levels are now evaluated. The policy layer in main.rs
            // determines whether to deny, warn, or log based on severity and config.

            let matched_span = pattern
                .regex
                .find(command_for_packs)
                .map(|(start, end)| MatchSpan { start, end });
            let Some(span) = matched_span else {
                continue;
            };

            let reason = pattern.reason;
            let mapped_span = map_span_with_offset(span, normalized_offset, original_len);
            let preview = mapped_span
                .as_ref()
                .map(|span| extract_match_preview(original_command, span))
                .or_else(|| Some(extract_match_preview(command_for_packs, &span)));

            // Allowlist check: only applies when we have a stable match identity (named pattern).
            if let Some(pattern_name) = pattern.name {
                if let Some(hit) = allowlists.match_rule(pack_id, pattern_name) {
                    if first_allowlist_hit.is_none() {
                        first_allowlist_hit = Some((
                            PatternMatch {
                                pack_id: Some(pack_id.clone()),
                                pattern_name: Some(pattern_name.to_string()),
                                severity: Some(pattern.severity),
                                reason: reason.to_string(),
                                source: MatchSource::Pack,
                                matched_span: mapped_span,
                                matched_text_preview: preview,
                                explanation: pattern.explanation.map(str::to_string),
                            },
                            hit.layer,
                            hit.entry.reason.clone(),
                        ));
                    }

                    // Bypass only this rule and keep evaluating other rules/packs.
                    continue;
                }

                if let Some(mapped_span) = mapped_span {
                    return EvaluationResult::denied_by_pack_pattern_with_span(
                        pack_id,
                        pattern_name,
                        reason,
                        pattern.explanation,
                        pattern.severity,
                        original_command,
                        mapped_span,
                    );
                }

                return EvaluationResult::denied_by_pack_pattern(
                    pack_id,
                    pattern_name,
                    reason,
                    pattern.explanation,
                    pattern.severity,
                );
            }

            if let Some(mapped_span) = mapped_span {
                return EvaluationResult::denied_by_pack_with_span(
                    pack_id,
                    reason,
                    pattern.explanation,
                    original_command,
                    mapped_span,
                );
            }

            return EvaluationResult::denied_by_pack(pack_id, reason, pattern.explanation);
        }
    }

    if let Some((matched, layer, reason)) = first_allowlist_hit {
        return EvaluationResult::allowed_by_allowlist(matched, layer, reason);
    }

    EvaluationResult::allowed()
}

/// Evaluate a command with legacy pattern support using precompiled overrides.
///
/// This version includes legacy `SAFE_PATTERNS` and `DESTRUCTIVE_PATTERNS` checking.
/// It's intended to be used by the main hook entrypoint until the legacy patterns
/// are migrated to the pack system (git_safety_guard-99e.3.4).
///
/// # Arguments
///
/// * `command` - The raw command string to evaluate
/// * `config` - Loaded configuration with pack settings
/// * `enabled_keywords` - Keywords from enabled packs for quick rejection
/// * `compiled_overrides` - Precompiled config overrides (avoids per-command regex compilation)
/// * `safe_patterns` - Legacy safe patterns (whitelist)
/// * `destructive_patterns` - Legacy destructive patterns (blacklist)
///
/// # Type Parameters
///
/// This function accepts any types that implement pattern matching:
/// * `S` - Safe pattern type with `is_match` method returning `bool`
/// * `D` - Destructive pattern type with `is_match` method returning `bool` and `reason` method
#[allow(clippy::too_many_lines)]
pub fn evaluate_command_with_legacy<S, D>(
    command: &str,
    config: &Config,
    enabled_keywords: &[&str],
    compiled_overrides: &crate::config::CompiledOverrides,
    allowlists: &LayeredAllowlist,
    safe_patterns: &[S],
    destructive_patterns: &[D],
) -> EvaluationResult
where
    S: LegacySafePattern,
    D: LegacyDestructivePattern,
{
    // Empty commands are allowed (no-op)
    if command.is_empty() {
        return EvaluationResult::allowed();
    }

    // Step 1: Check precompiled allow overrides first
    if compiled_overrides.check_allow(command) {
        return EvaluationResult::allowed();
    }

    // Step 1.5: Check allow-once overrides (may be superseded by config blocklist).
    let allow_once = allow_once_match(command, None);

    // Step 2: Check precompiled block overrides
    if let Some(reason) = compiled_overrides.check_block(command) {
        if allow_once
            .as_ref()
            .is_some_and(|entry| entry.force_allow_config)
        {
            return EvaluationResult::allowed();
        }
        return EvaluationResult::denied_by_config(reason.to_string());
    }

    if allow_once.is_some() {
        return EvaluationResult::allowed();
    }

    // Step 2.5: Pre-calculate ordered packs for heredoc recursion (and later use)
    let enabled_packs: HashSet<String> = config.enabled_pack_ids();
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    let keyword_index = REGISTRY.build_enabled_keyword_index(&ordered_packs);

    // Step 3: Heredoc / inline-script detection (Tier 1/2/3, fail-open).
    // See `evaluate_command` for detailed rationale.
    let heredoc_settings = config.heredoc_settings();
    let mut precomputed_sanitized = None;
    let mut heredoc_allowlist_hit: Option<(PatternMatch, AllowlistLayer, String)> = None;
    let project_path = resolve_project_path(&heredoc_settings, None);
    let project_path = project_path.as_deref();
    if heredoc_settings.enabled && check_triggers(command) == TriggerResult::Triggered {
        let sanitized = sanitize_for_pattern_matching(command);
        let sanitized_str = sanitized.as_ref();
        let should_scan = if matches!(sanitized, std::borrow::Cow::Owned(_)) {
            check_triggers(sanitized_str) == TriggerResult::Triggered
        } else {
            true
        };
        precomputed_sanitized = Some(sanitized);

        if should_scan {
            let context = HeredocEvaluationContext {
                allowlists,
                heredoc_settings: &heredoc_settings,
                project_path,
                deadline: None,
                enabled_keywords,
                ordered_packs: &ordered_packs,
                keyword_index: keyword_index.as_ref(),
                compiled_overrides,
                allow_once_audit: None,
            };
            if let Some(blocked) = evaluate_heredoc(command, context, &mut heredoc_allowlist_hit) {
                return blocked;
            }
        }
    }

    // Step 4: Quick rejection - if no relevant keywords, allow immediately
    if pack_aware_quick_reject(command, enabled_keywords) {
        if let Some((matched, layer, reason)) = heredoc_allowlist_hit {
            return EvaluationResult::allowed_by_allowlist(matched, layer, reason);
        }
        return EvaluationResult::allowed();
    }

    // Step 5: False-positive immunity - strip known-safe string arguments (commit messages, search
    // patterns, issue descriptions, etc.) so dangerous substrings inside data do not trigger
    // blocking.
    //
    // Also normalize the command here (Step 6) and reuse for pattern matching.
    // pack_aware_quick_reject_with_normalized returns both the quick-reject decision
    // and the normalized command, avoiding duplicate normalization.
    let sanitized = precomputed_sanitized.unwrap_or_else(|| sanitize_for_pattern_matching(command));
    let command_for_match = sanitized.as_ref();

    // Use the optimized version that returns both decision and normalized form.
    let (quick_reject, normalized) =
        pack_aware_quick_reject_with_normalized(command_for_match, enabled_keywords);
    if matches!(sanitized, std::borrow::Cow::Owned(_)) && quick_reject {
        if let Some((matched, layer, reason)) = heredoc_allowlist_hit {
            return EvaluationResult::allowed_by_allowlist(matched, layer, reason);
        }
        return EvaluationResult::allowed();
    }

    // Step 7: Check legacy safe patterns (whitelist, reusing normalized from quick-reject)
    for pattern in safe_patterns {
        if pattern.is_match(&normalized) {
            return EvaluationResult::allowed();
        }
    }

    let normalized_offset = compute_normalized_offset(command_for_match, &normalized);
    let original_len = command.len();

    // Step 8: Check legacy destructive patterns (blacklist)
    for pattern in destructive_patterns {
        if let Some(span) = pattern.find_span(&normalized) {
            if let Some(mapped_span) = map_span_with_offset(span, normalized_offset, original_len) {
                return EvaluationResult::denied_by_legacy_with_span(
                    pattern.reason(),
                    command,
                    mapped_span,
                );
            }
            return EvaluationResult::denied_by_legacy(pattern.reason());
        }
    }

    // Step 9: Check enabled packs with allowlist override semantics.
    let result = evaluate_packs_with_allowlists(
        &normalized,
        &normalized,
        command_for_match,
        command,
        &ordered_packs,
        allowlists,
        keyword_index.as_ref(),
        None,
    );
    if result.allowlist_override.is_none() {
        if let Some((matched, layer, reason)) = heredoc_allowlist_hit {
            return EvaluationResult::allowed_by_allowlist(matched, layer, reason);
        }
    }

    result
}
/// Context for heredoc evaluation to avoid too many arguments.
#[derive(Clone, Copy)]
struct HeredocEvaluationContext<'a> {
    allowlists: &'a LayeredAllowlist,
    heredoc_settings: &'a crate::config::HeredocSettings,
    project_path: Option<&'a Path>,
    deadline: Option<&'a Deadline>,
    enabled_keywords: &'a [&'a str],
    ordered_packs: &'a [String],
    keyword_index: Option<&'a crate::packs::EnabledKeywordIndex>,
    compiled_overrides: &'a crate::config::CompiledOverrides,
    allow_once_audit: Option<&'a crate::pending_exceptions::AllowOnceAuditConfig<'a>>,
}

#[allow(clippy::too_many_lines)]
fn evaluate_heredoc(
    command: &str,
    context: HeredocEvaluationContext<'_>,
    first_allowlist_hit: &mut Option<(PatternMatch, AllowlistLayer, String)>,
) -> Option<EvaluationResult> {
    if deadline_exceeded(context.deadline)
        || remaining_below(context.deadline, &crate::perf::FULL_HEREDOC_PIPELINE)
    {
        return Some(EvaluationResult::allowed_due_to_budget());
    }

    // Check command-level allowlist before any extraction.
    // This allows users to whitelist entire commands (e.g., "./scripts/approved.sh").
    if let Some(ref content_allowlist) = context.heredoc_settings.content_allowlist {
        if let Some(matched_cmd) = content_allowlist.is_command_allowlisted(command) {
            tracing::debug!(matched_command = matched_cmd, "heredoc command allowlisted");
            // Command is allowlisted - skip all heredoc analysis
            return None;
        }
    }

    let (contents, fallback_needed) =
        match extract_content(command, &context.heredoc_settings.limits) {
            ExtractionResult::Extracted(contents) => (contents, false),
            ExtractionResult::NoContent => return None,
            ExtractionResult::Skipped(reasons) => {
                let is_timeout = reasons
                    .iter()
                    .any(|r| matches!(r, SkipReason::Timeout { .. }));

                let strict_timeout = is_timeout && !context.heredoc_settings.fallback_on_timeout;
                let strict_other = !is_timeout && !context.heredoc_settings.fallback_on_parse_error;
                if strict_timeout || strict_other {
                    let summary = reasons
                        .iter()
                        .map(std::string::ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("; ");
                    let reason = if strict_timeout {
                        format!(
                            "Embedded code blocked: extraction exceeded timeout and \
                         fallback_on_timeout=false ({summary})"
                        )
                    } else {
                        format!(
                            "Embedded code blocked: extraction skipped and \
                         fallback_on_parse_error=false ({summary})"
                        )
                    };
                    return Some(EvaluationResult::denied_by_legacy(&reason));
                }

                // Fallback check: if skipped due to size limits, perform a rudimentary
                // substring check for critical patterns that would otherwise be missed.
                if reasons
                    .iter()
                    .any(|r| matches!(r, SkipReason::ExceededSizeLimit { .. }))
                {
                    if let Some(blocked) = check_fallback_patterns(command) {
                        return Some(blocked);
                    }
                }

                return None;
            }
            ExtractionResult::Partial { extracted, skipped } => {
                // Check strict mode settings for skipped items
                let is_timeout = skipped
                    .iter()
                    .any(|r| matches!(r, SkipReason::Timeout { .. }));

                let strict_timeout = is_timeout && !context.heredoc_settings.fallback_on_timeout;
                let strict_other = !is_timeout && !context.heredoc_settings.fallback_on_parse_error;
                if strict_timeout || strict_other {
                    let summary = skipped
                        .iter()
                        .map(std::string::ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("; ");
                    let reason = if strict_timeout {
                        format!(
                            "Embedded code blocked: extraction exceeded timeout (partial) and \
                         fallback_on_timeout=false ({summary})"
                        )
                    } else {
                        format!(
                            "Embedded code blocked: extraction partial and \
                         fallback_on_parse_error=false ({summary})"
                        )
                    };
                    return Some(EvaluationResult::denied_by_legacy(&reason));
                }

                // We have partial content. Analyze what we extracted first (high fidelity).
                // Then if no block, run fallback checks on the whole command if size limit was exceeded.
                let fallback_needed = skipped
                    .iter()
                    .any(|r| matches!(r, SkipReason::ExceededSizeLimit { .. }));

                (extracted, fallback_needed)
            }
            ExtractionResult::Failed(err) => {
                if !context.heredoc_settings.fallback_on_parse_error {
                    let reason = format!(
                        "Embedded code blocked: extraction failed and \
                     fallback_on_parse_error=false ({err})"
                    );
                    return Some(EvaluationResult::denied_by_legacy(&reason));
                }

                return None;
            }
        };

    for content in contents {
        if deadline_exceeded(context.deadline)
            || remaining_below(context.deadline, &crate::perf::FULL_HEREDOC_PIPELINE)
        {
            return Some(EvaluationResult::allowed_due_to_budget());
        }

        if let Some(allowed) = &context.heredoc_settings.allowed_languages {
            if !allowed.contains(&content.language) {
                continue;
            }
        }

        // Check content-level allowlist before AST matching.
        // This allows users to whitelist specific patterns or content hashes.
        if let Some(ref content_allowlist) = context.heredoc_settings.content_allowlist {
            if let Some(hit) = content_allowlist.is_content_allowlisted(
                &content.content,
                content.language,
                context.project_path,
            ) {
                tracing::debug!(
                    hit_kind = hit.kind.label(),
                    matched = hit.matched,
                    reason = hit.reason,
                    "heredoc content allowlisted"
                );
                // Content is allowlisted - skip AST matching for this heredoc
                continue;
            }
        }

        // Skip ALL heredoc content analysis if the target command is non-executing.
        // Commands like `cat`, `tee`, `grep`, etc. just output the heredoc content
        // as data - they don't execute it as code. This prevents false positives
        // where documentation text containing dangerous command examples is blocked.
        if content
            .target_command
            .as_ref()
            .is_some_and(|cmd| crate::heredoc::is_non_executing_heredoc_command(cmd))
        {
            tracing::trace!(
                target_command = ?content.target_command,
                "Skipping heredoc content analysis for non-executing target"
            );
            continue; // Skip to next extracted content - this heredoc is just data
        }

        // Tier 2.5: Recursive Shell Analysis
        // If content is Bash, extract inner commands and feed them back to the full evaluator.
        // This ensures that `kubectl`, `docker`, etc. inside heredocs are checked against their packs.
        if content.language == crate::heredoc::ScriptLanguage::Bash {
            let inner_commands = crate::heredoc::extract_shell_commands(&content.content);
            for inner in inner_commands {
                if deadline_exceeded(context.deadline) {
                    return Some(EvaluationResult::allowed_due_to_budget());
                }

                let result = evaluate_command_with_pack_order_deadline_at_path(
                    &inner.text,
                    context.enabled_keywords,
                    context.ordered_packs,
                    context.keyword_index,
                    context.compiled_overrides,
                    context.allowlists,
                    context.heredoc_settings,
                    context.allow_once_audit,
                    context.project_path,
                    context.deadline,
                );

                if result.is_denied() {
                    // Propagate denial, wrapping the reason context
                    if let Some(mut info) = result.pattern_info {
                        info.reason = format!(
                            "Embedded shell command blocked: {} (line {} of heredoc)",
                            info.reason, inner.line_number
                        );
                        info.source = MatchSource::HeredocAst; // Mark as heredoc source
                        if let Some(span) = info.matched_span {
                            if let Some(mapped_inner) =
                                map_heredoc_span(command, &content, inner.start, inner.end)
                            {
                                let mapped = MatchSpan {
                                    start: mapped_inner.start.saturating_add(span.start),
                                    end: mapped_inner.start.saturating_add(span.end),
                                };
                                if mapped.end <= command.len() {
                                    info.matched_span = Some(mapped);
                                    info.matched_text_preview =
                                        Some(extract_match_preview(command, &mapped));
                                } else {
                                    info.matched_span = None;
                                }
                            } else {
                                info.matched_span = None;
                            }
                        }

                        return Some(EvaluationResult {
                            decision: EvaluationDecision::Deny,
                            pattern_info: Some(info),
                            allowlist_override: None,
                            effective_mode: Some(crate::packs::DecisionMode::Deny),
                            skipped_due_to_budget: false,
                        });
                    }
                    return Some(result);
                }
            }
        }

        let matches = match DEFAULT_MATCHER.find_matches(&content.content, content.language) {
            Ok(matches) => matches,
            Err(err) => {
                let is_timeout = matches!(err, crate::ast_matcher::MatchError::Timeout { .. });
                let strict_timeout = is_timeout && !context.heredoc_settings.fallback_on_timeout;
                let strict_other = !is_timeout && !context.heredoc_settings.fallback_on_parse_error;
                if strict_timeout || strict_other {
                    let reason = format!(
                        "Embedded code blocked: AST matching error with strict fallback \
                         configuration ({err})"
                    );
                    return Some(EvaluationResult::denied_by_legacy(&reason));
                }

                continue;
            }
        };

        for m in matches {
            if deadline_exceeded(context.deadline)
                || remaining_below(context.deadline, &crate::perf::FULL_HEREDOC_PIPELINE)
            {
                return Some(EvaluationResult::allowed_due_to_budget());
            }

            if !m.severity.blocks_by_default() {
                continue;
            }

            let (pack_id, pattern_name) = split_ast_rule_id(&m.rule_id);

            if let Some(hit) = context.allowlists.match_rule(&pack_id, &pattern_name) {
                if first_allowlist_hit.is_none() {
                    let reason =
                        format_heredoc_denial_reason(&content, &m, &pack_id, &pattern_name);
                    let mapped_span = map_heredoc_span(command, &content, m.start, m.end);
                    *first_allowlist_hit = Some((
                        PatternMatch {
                            pack_id: Some(pack_id),
                            pattern_name: Some(pattern_name),
                            severity: Some(ast_severity_to_pack_severity(m.severity)),
                            reason,
                            source: MatchSource::HeredocAst,
                            matched_span: mapped_span,
                            matched_text_preview: Some(m.matched_text_preview),
                            explanation: None,
                        },
                        hit.layer,
                        hit.entry.reason.clone(),
                    ));
                }
                continue;
            }

            let reason = format_heredoc_denial_reason(&content, &m, &pack_id, &pattern_name);
            let mapped_span = map_heredoc_span(command, &content, m.start, m.end);
            return Some(EvaluationResult {
                decision: EvaluationDecision::Deny,
                pattern_info: Some(PatternMatch {
                    pack_id: Some(pack_id),
                    pattern_name: Some(pattern_name),
                    severity: Some(ast_severity_to_pack_severity(m.severity)),
                    reason,
                    source: MatchSource::HeredocAst,
                    matched_span: mapped_span,
                    matched_text_preview: Some(m.matched_text_preview),
                    explanation: None,
                }),
                allowlist_override: None,
                effective_mode: Some(crate::packs::DecisionMode::Deny),
                skipped_due_to_budget: false,
            });
        }
    }

    if fallback_needed {
        if let Some(blocked) = check_fallback_patterns(command) {
            return Some(blocked);
        }
    }

    None
}

#[allow(dead_code)]
fn check_fallback_patterns(command: &str) -> Option<EvaluationResult> {
    // List of critical destructive patterns to check when AST analysis is skipped (e.g. oversized input).
    // These patterns must be robust to whitespace variations where applicable.
    static FALLBACK_PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
        RegexSet::new([
            r"shutil\.rmtree",
            r"os\.remove",
            r"os\.rmdir",
            r"os\.unlink",
            r"fs\.rmSync",
            r"fs\.rmdirSync",
            r"child_process\.execSync",
            r"child_process\.spawnSync",
            r"os\.RemoveAll",
            r"\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\b", // rm -rf, rm -fr, rm -r -f
            r"\bgit\s+reset\s+--hard\b",
        ])
        .expect("fallback patterns must compile")
    });

    // Sanitize the command first to mask comments and safe arguments (e.g. commit messages).
    // This prevents false positives where a destructive command is mentioned in a comment
    // inside a large heredoc.
    let sanitized = sanitize_for_pattern_matching(command);
    let check_target = sanitized.as_ref();

    if FALLBACK_PATTERNS.is_match(check_target) {
        return Some(EvaluationResult::denied_by_legacy(
            "Oversized command contains destructive pattern (fallback check)",
        ));
    }

    None
}

fn split_ast_rule_id(rule_id: &str) -> (String, String) {
    // Expected format: heredoc.<language>.<pattern>[.<suffix>...]
    if let Some(rest) = rule_id.strip_prefix("heredoc.") {
        if let Some((lang, tail)) = rest.split_once('.') {
            let pack_id = format!("heredoc.{lang}");
            return (pack_id, tail.to_string());
        }
        return ("heredoc".to_string(), rule_id.to_string());
    }

    // Fallback: best-effort split on last dot.
    if let Some((pack_id, pattern_name)) = rule_id.rsplit_once('.') {
        return (pack_id.to_string(), pattern_name.to_string());
    }

    ("unknown".to_string(), rule_id.to_string())
}

fn format_heredoc_denial_reason(
    extracted: &crate::heredoc::ExtractedContent,
    m: &crate::ast_matcher::PatternMatch,
    pack_id: &str,
    pattern_name: &str,
) -> String {
    let lang = match extracted.language {
        crate::heredoc::ScriptLanguage::Bash => "bash",
        crate::heredoc::ScriptLanguage::Go => "go",
        crate::heredoc::ScriptLanguage::Python => "python",
        crate::heredoc::ScriptLanguage::Ruby => "ruby",
        crate::heredoc::ScriptLanguage::Perl => "perl",
        crate::heredoc::ScriptLanguage::JavaScript => "javascript",
        crate::heredoc::ScriptLanguage::TypeScript => "typescript",
        crate::heredoc::ScriptLanguage::Php => "php",
        crate::heredoc::ScriptLanguage::Unknown => "unknown",
    };

    format!(
        "Embedded {lang} code blocked: {} (rule {pack_id}:{pattern_name}, line {}, matched: {})",
        m.reason, m.line_number, m.matched_text_preview
    )
}

fn map_heredoc_span(
    command: &str,
    content: &crate::heredoc::ExtractedContent,
    start: usize,
    end: usize,
) -> Option<MatchSpan> {
    let range = content.content_range.as_ref()?;
    let raw = command.get(range.clone())?;
    if raw.len() != content.content.len() {
        return None;
    }
    if raw != content.content {
        return None;
    }

    let mapped_start = range.start.saturating_add(start);
    let mapped_end = range.start.saturating_add(end);
    if mapped_start <= mapped_end && mapped_end <= command.len() {
        Some(MatchSpan {
            start: mapped_start,
            end: mapped_end,
        })
    } else {
        None
    }
}

/// Trait for legacy safe patterns.
pub trait LegacySafePattern {
    /// Check if the pattern matches the command.
    fn is_match(&self, cmd: &str) -> bool;
}

/// Trait for legacy destructive patterns.
pub trait LegacyDestructivePattern {
    /// Check if the pattern matches the command.
    fn is_match(&self, cmd: &str) -> bool;
    /// Find the first match span, if available.
    fn find_span(&self, cmd: &str) -> Option<MatchSpan> {
        let _ = cmd;
        None
    }
    /// Get the reason for blocking.
    fn reason(&self) -> &str;
}

impl LegacySafePattern for crate::packs::SafePattern {
    fn is_match(&self, cmd: &str) -> bool {
        self.regex.is_match(cmd)
    }
}

impl LegacyDestructivePattern for crate::packs::DestructivePattern {
    fn is_match(&self, cmd: &str) -> bool {
        self.regex.is_match(cmd)
    }

    fn find_span(&self, cmd: &str) -> Option<MatchSpan> {
        self.regex
            .find(cmd)
            .map(|(start, end)| MatchSpan { start, end })
    }

    fn reason(&self) -> &str {
        self.reason
    }
}

// =============================================================================
// Confidence Scoring Integration (git_safety_guard-t8x.5)
// =============================================================================

/// Result of applying confidence scoring to a decision.
#[derive(Debug, Clone)]
pub struct ConfidenceResult {
    /// The (potentially adjusted) decision mode.
    pub mode: crate::packs::DecisionMode,
    /// The confidence score (if computed).
    pub score: Option<crate::confidence::ConfidenceScore>,
    /// Whether the mode was downgraded due to low confidence.
    pub downgraded: bool,
}

/// Apply confidence scoring to potentially downgrade a Deny to Warn.
///
/// This function computes a confidence score for the pattern match and
/// optionally downgrades the decision mode if confidence is low.
///
/// # Arguments
///
/// * `command` - The original command being evaluated
/// * `sanitized_command` - The sanitized version (with safe data masked), if available
/// * `result` - The evaluation result (must have `pattern_info` for confidence to apply)
/// * `current_mode` - The decision mode from policy resolution
/// * `config` - Confidence scoring configuration
///
/// # Returns
///
/// A `ConfidenceResult` with the (potentially adjusted) mode and confidence details.
#[must_use]
pub fn apply_confidence_scoring(
    command: &str,
    sanitized_command: Option<&str>,
    result: &EvaluationResult,
    current_mode: crate::packs::DecisionMode,
    config: &crate::config::ConfidenceConfig,
) -> ConfidenceResult {
    // If confidence scoring is disabled, return unchanged mode
    if !config.enabled {
        return ConfidenceResult {
            mode: current_mode,
            score: None,
            downgraded: false,
        };
    }

    // Only apply confidence scoring to Deny decisions that might be downgraded
    if current_mode != crate::packs::DecisionMode::Deny {
        return ConfidenceResult {
            mode: current_mode,
            score: None,
            downgraded: false,
        };
    }

    // Need pattern info to compute confidence
    let Some(info) = &result.pattern_info else {
        return ConfidenceResult {
            mode: current_mode,
            score: None,
            downgraded: false,
        };
    };

    // Protect Critical severity from downgrading (if configured)
    if config.protect_critical
        && info
            .severity
            .is_some_and(|s| s == crate::packs::Severity::Critical)
    {
        return ConfidenceResult {
            mode: current_mode,
            score: None,
            downgraded: false,
        };
    }

    // Get match span for confidence computation
    let Some(span) = &info.matched_span else {
        // No span = can't compute confidence = conservative (keep Deny)
        return ConfidenceResult {
            mode: current_mode,
            score: None,
            downgraded: false,
        };
    };

    // Compute confidence
    let ctx = crate::confidence::ConfidenceContext {
        command,
        sanitized_command,
        match_start: span.start,
        match_end: span.end,
    };
    let score = crate::confidence::compute_match_confidence(&ctx);

    // Check if we should downgrade
    let should_downgrade = score.is_low(config.warn_threshold);
    let new_mode = if should_downgrade {
        crate::packs::DecisionMode::Warn
    } else {
        current_mode
    };

    ConfidenceResult {
        mode: new_mode,
        score: Some(score),
        downgraded: should_downgrade,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowlist::{
        AllowEntry, AllowSelector, AllowlistFile, LoadedAllowlistLayer, RuleId,
    };
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn default_config() -> Config {
        Config::default()
    }

    fn default_compiled_overrides() -> crate::config::CompiledOverrides {
        crate::config::CompiledOverrides::default()
    }

    fn default_allowlists() -> LayeredAllowlist {
        LayeredAllowlist::default()
    }

    fn project_allowlists_for_rule(rule: &str, reason: &str) -> LayeredAllowlist {
        let rule = RuleId::parse(rule).expect("rule id must parse");
        LayeredAllowlist {
            layers: vec![LoadedAllowlistLayer {
                layer: AllowlistLayer::Project,
                path: PathBuf::from("project-allowlist.toml"),
                file: AllowlistFile {
                    entries: vec![AllowEntry {
                        selector: AllowSelector::Rule(rule),
                        reason: reason.to_string(),
                        added_by: None,
                        added_at: None,
                        expires_at: None,
                        context: None,
                        conditions: HashMap::new(),
                        environments: Vec::new(),
                        risk_acknowledged: false,
                    }],
                    errors: Vec::new(),
                },
            }],
        }
    }

    #[allow(dead_code)]
    fn project_allowlists_for_pack_wildcard(pack_id: &str, reason: &str) -> LayeredAllowlist {
        LayeredAllowlist {
            layers: vec![LoadedAllowlistLayer {
                layer: AllowlistLayer::Project,
                path: PathBuf::from("project-allowlist.toml"),
                file: AllowlistFile {
                    entries: vec![AllowEntry {
                        selector: AllowSelector::Rule(RuleId {
                            pack_id: pack_id.to_string(),
                            pattern_name: "*".to_string(),
                        }),
                        reason: reason.to_string(),
                        added_by: None,
                        added_at: None,
                        expires_at: None,
                        context: None,
                        conditions: HashMap::new(),
                        environments: Vec::new(),
                        risk_acknowledged: false,
                    }],
                    errors: Vec::new(),
                },
            }],
        }
    }

    #[test]
    fn test_empty_command_allowed() {
        let config = default_config();
        let compiled = default_compiled_overrides();
        let allowlists = default_allowlists();
        let result = evaluate_command("", &config, &[], &compiled, &allowlists);
        assert!(result.is_allowed());
        assert!(result.pattern_info.is_none());
    }

    #[test]
    fn test_safe_command_allowed() {
        let config = default_config();
        let compiled = default_compiled_overrides();
        let allowlists = default_allowlists();
        let result = evaluate_command("ls -la", &config, &["git", "rm"], &compiled, &allowlists);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_result_helper_methods() {
        let allowed = EvaluationResult::allowed();
        assert!(allowed.is_allowed());
        assert!(!allowed.is_denied());
        assert!(allowed.reason().is_none());
        assert!(allowed.pack_id().is_none());

        let denied = EvaluationResult::denied_by_pack("test.pack", "test reason", None);
        assert!(!denied.is_allowed());
        assert!(denied.is_denied());
        assert_eq!(denied.reason(), Some("test reason"));
        assert_eq!(denied.pack_id(), Some("test.pack"));
    }

    #[test]
    fn test_denied_by_config() {
        let denied = EvaluationResult::denied_by_config("config block".to_string());
        assert!(denied.is_denied());
        assert_eq!(denied.reason(), Some("config block"));
        assert!(denied.pack_id().is_none());
        assert_eq!(
            denied.pattern_info.as_ref().unwrap().source,
            MatchSource::ConfigOverride
        );
    }

    #[test]
    fn test_denied_by_legacy() {
        let denied = EvaluationResult::denied_by_legacy("legacy reason");
        assert!(denied.is_denied());
        assert_eq!(denied.reason(), Some("legacy reason"));
        assert!(denied.pack_id().is_none());
        assert_eq!(
            denied.pattern_info.as_ref().unwrap().source,
            MatchSource::LegacyPattern
        );
    }

    #[test]
    fn test_denied_by_pack_pattern() {
        let denied = EvaluationResult::denied_by_pack_pattern(
            "core.git",
            "reset-hard",
            "test",
            None,
            crate::packs::Severity::Critical,
        );
        assert!(denied.is_denied());
        assert_eq!(denied.pack_id(), Some("core.git"));
        assert_eq!(
            denied.pattern_info.as_ref().unwrap().pattern_name,
            Some("reset-hard".to_string())
        );
    }

    #[test]
    fn test_quick_reject_skips_patterns() {
        let config = default_config();
        let compiled = default_compiled_overrides();
        let allowlists = default_allowlists();
        let result = evaluate_command(
            "cargo build --release",
            &config,
            &["git", "rm"],
            &compiled,
            &allowlists,
        );
        assert!(result.is_allowed());

        // Even with more keywords
        let result = evaluate_command(
            "npm install",
            &config,
            &["git", "rm", "docker", "kubectl"],
            &compiled,
            &allowlists,
        );
        assert!(result.is_allowed());
    }

    // =========================================================================
    // Heredoc / Inline Script Integration Tests (git_safety_guard-e7m)
    // =========================================================================

    #[test]
    fn heredoc_scan_runs_before_keyword_quick_reject() {
        let config = default_config();
        let compiled = default_compiled_overrides();
        let allowlists = default_allowlists();

        // This command would be ALLOWED by keyword quick-reject if we only looked for
        // unrelated pack keywords. The embedded JavaScript is still destructive and must
        // be analyzed and denied.
        let cmd = r#"node -e "require('child_process').execSync('rm -rf /')"""#;
        let result = evaluate_command(cmd, &config, &["kubectl"], &compiled, &allowlists);
        assert!(result.is_denied());

        let info = result.pattern_info.expect("deny must include pattern info");
        assert_eq!(info.source, MatchSource::HeredocAst);
        assert!(
            info.pack_id
                .as_deref()
                .is_some_and(|p| p.starts_with("heredoc."))
        );
    }

    #[test]
    fn heredoc_triggers_inside_safe_string_arguments_do_not_scan_or_block() {
        let config = default_config();
        let compiled = default_compiled_overrides();
        let allowlists = default_allowlists();

        // The commit message contains heredoc/inline-script trigger strings and a destructive
        // payload, but it's data-only (safe-string context). We must not treat it as executed.
        let cmd =
            r#"git commit -m "example: node -e \"require('child_process').execSync('rm -rf /')\"""#;
        let result = evaluate_command(cmd, &config, &["git"], &compiled, &allowlists);
        assert!(result.is_allowed());
    }

    #[test]
    fn bd_notes_with_dangerous_text_is_allowed() {
        let config = default_config();
        let compiled = default_compiled_overrides();
        let allowlists = default_allowlists();

        // Notes are documentation; dangerous text should not trigger blocking.
        let cmd = "bd create --notes This mentions rm -rf / but is just docs";
        let result = evaluate_command(cmd, &config, &["rm"], &compiled, &allowlists);
        assert!(result.is_allowed());
    }

    #[test]
    fn bd_description_inline_code_is_blocked() {
        let config = default_config();
        let compiled = default_compiled_overrides();
        let allowlists = default_allowlists();

        // Inline code in a data flag must still be evaluated and blocked.
        let cmd = r#"bd create --description "$(rm -rf /)""#;
        let result = evaluate_command(cmd, &config, &["rm"], &compiled, &allowlists);
        assert!(result.is_denied());
    }

    #[test]
    fn echo_with_dangerous_text_is_allowed() {
        let config = default_config();
        let compiled = default_compiled_overrides();
        let allowlists = default_allowlists();

        // echo arguments are data; should not be blocked by keyword matching.
        let cmd = r#"echo "rm -rf /""#;
        let result = evaluate_command(cmd, &config, &["rm"], &compiled, &allowlists);
        assert!(result.is_allowed());
    }

    #[test]
    fn heredoc_commands_are_evaluated_and_block_when_severity_blocks_by_default() {
        let config = default_config();
        let compiled = default_compiled_overrides();
        let allowlists = default_allowlists();

        // This command would be ALLOWED by keyword quick-reject if we only looked for unrelated
        // pack keywords. The embedded JavaScript still must be analyzed and denied.
        let cmd =
            "node <<EOF\nconst fs = require('fs');\nfs.rmSync('/etc', { recursive: true });\nEOF";
        let result = evaluate_command(cmd, &config, &["kubectl"], &compiled, &allowlists);
        assert!(result.is_denied());

        let info = result.pattern_info.expect("deny must include pattern info");
        assert_eq!(info.source, MatchSource::HeredocAst);
        assert_eq!(info.pack_id.as_deref(), Some("heredoc.javascript"));
        assert!(
            info.pattern_name
                .as_deref()
                .is_some_and(|p| p.starts_with("fs_rmsync")),
            "expected a fs_rmsync* heredoc rule, got {:?}",
            info.pattern_name
        );
    }

    #[test]
    fn heredoc_commands_with_non_blocking_matches_are_allowed() {
        let config = default_config();
        let compiled = default_compiled_overrides();
        let allowlists = default_allowlists();

        // Non-catastrophic recursive deletes are currently warn-only; evaluator should not block.
        let cmd =
            "node <<EOF\nconst fs = require('fs');\nfs.rmSync('./dist', { recursive: true });\nEOF";
        let result = evaluate_command(cmd, &config, &["kubectl"], &compiled, &allowlists);
        assert!(result.is_allowed());
        assert!(result.pattern_info.is_none());
    }

    #[test]
    fn heredoc_scanning_can_be_disabled_via_config() {
        let mut config = default_config();
        config.heredoc.enabled = Some(false);
        let compiled = default_compiled_overrides();
        let allowlists = default_allowlists();

        let cmd =
            "node <<EOF\nconst fs = require('fs');\nfs.rmSync('/etc', { recursive: true });\nEOF";
        let result = evaluate_command(cmd, &config, &["kubectl"], &compiled, &allowlists);
        assert!(result.is_allowed());
        assert!(result.pattern_info.is_none());
    }

    #[test]
    fn heredoc_language_filter_can_skip_unwanted_languages() {
        let mut config = default_config();
        config.heredoc.languages = Some(vec!["python".to_string()]);
        let compiled = default_compiled_overrides();
        let allowlists = default_allowlists();

        let cmd =
            "node <<EOF\nconst fs = require('fs');\nfs.rmSync('/etc', { recursive: true });\nEOF";
        let result = evaluate_command(cmd, &config, &["kubectl"], &compiled, &allowlists);
        assert!(result.is_allowed());
        assert!(result.pattern_info.is_none());
    }

    #[test]
    fn heredoc_allowlist_can_override_ast_denial() {
        let config = default_config();
        let compiled = default_compiled_overrides();
        let allowlists =
            project_allowlists_for_rule("heredoc.javascript:fs_rmsync.catastrophic", "local dev");

        let cmd =
            "node <<EOF\nconst fs = require('fs');\nfs.rmSync('/etc', { recursive: true });\nEOF";
        let result = evaluate_command(cmd, &config, &["kubectl"], &compiled, &allowlists);
        assert!(result.is_allowed());

        let override_info = result
            .allowlist_override
            .as_ref()
            .expect("allowlist override metadata must be present");
        assert_eq!(override_info.layer, AllowlistLayer::Project);
        assert_eq!(override_info.reason, "local dev");
        assert_eq!(
            override_info.matched.pack_id.as_deref(),
            Some("heredoc.javascript")
        );
        assert_eq!(
            override_info.matched.pattern_name.as_deref(),
            Some("fs_rmsync.catastrophic")
        );
        assert_eq!(override_info.matched.source, MatchSource::HeredocAst);
    }

    #[test]
    fn heredoc_content_allowlist_project_scope_skips_ast_scan() {
        let mut config = default_config();
        let cwd = std::env::current_dir().expect("current_dir must be available");
        let cwd_str = cwd.to_string_lossy().into_owned();

        config.heredoc.allowlist = Some(crate::config::HeredocAllowlistConfig {
            projects: vec![crate::config::ProjectHeredocAllowlist {
                path: cwd_str,
                patterns: vec![crate::config::AllowedHeredocPattern {
                    language: Some("javascript".to_string()),
                    pattern: "fs.rmSync('/etc'".to_string(),
                    reason: "project allowlist".to_string(),
                }],
                content_hashes: vec![],
            }],
            ..Default::default()
        });

        let compiled = config.overrides.compile();
        let allowlists = default_allowlists();

        // This would normally be denied by heredoc AST rules (catastrophic path).
        let cmd =
            "node <<EOF\nconst fs = require('fs');\nfs.rmSync('/etc', { recursive: true });\nEOF";
        let result = evaluate_command(cmd, &config, &["kubectl"], &compiled, &allowlists);
        assert!(
            result.is_allowed(),
            "project-scoped heredoc content allowlist should skip AST denial"
        );
    }

    #[test]
    fn heredoc_content_allowlist_project_scope_does_not_match_other_projects() {
        let mut config = default_config();

        config.heredoc.allowlist = Some(crate::config::HeredocAllowlistConfig {
            projects: vec![crate::config::ProjectHeredocAllowlist {
                path: "/definitely-not-a-prefix".to_string(),
                patterns: vec![crate::config::AllowedHeredocPattern {
                    language: Some("javascript".to_string()),
                    pattern: "fs.rmSync('/etc'".to_string(),
                    reason: "wrong project".to_string(),
                }],
                content_hashes: vec![],
            }],
            ..Default::default()
        });

        let compiled = config.overrides.compile();
        let allowlists = default_allowlists();

        let cmd =
            "node <<EOF\nconst fs = require('fs');\nfs.rmSync('/etc', { recursive: true });\nEOF";
        let result = evaluate_command(cmd, &config, &["kubectl"], &compiled, &allowlists);
        assert!(
            result.is_denied(),
            "content allowlist should not apply when cwd is outside configured project scope"
        );
    }

    #[test]
    fn heredoc_trigger_strings_inside_safe_string_arguments_do_not_scan_or_block() {
        let config = default_config();
        let compiled = default_compiled_overrides();
        let allowlists = default_allowlists();

        // Commit messages can contain heredoc syntax as documentation; these are data-only.
        let cmd = r#"git commit -m "docs: example heredoc: cat <<EOF rm -rf / EOF""#;
        let result = evaluate_command(cmd, &config, &["git"], &compiled, &allowlists);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_evaluation_decision_equality() {
        assert_eq!(EvaluationDecision::Allow, EvaluationDecision::Allow);
        assert_eq!(EvaluationDecision::Deny, EvaluationDecision::Deny);
        assert_ne!(EvaluationDecision::Allow, EvaluationDecision::Deny);
    }

    #[test]
    fn test_match_source_equality() {
        assert_eq!(MatchSource::ConfigOverride, MatchSource::ConfigOverride);
        assert_eq!(MatchSource::LegacyPattern, MatchSource::LegacyPattern);
        assert_eq!(MatchSource::Pack, MatchSource::Pack);
        assert_eq!(MatchSource::HeredocAst, MatchSource::HeredocAst);
        assert_ne!(MatchSource::ConfigOverride, MatchSource::Pack);
    }

    // =========================================================================
    // Allowlist Override Tests (git_safety_guard-1gt.2.2)
    // =========================================================================

    #[test]
    fn allowlist_hit_overrides_deny() {
        let config = default_config();
        let compiled = default_compiled_overrides();
        let allowlists = project_allowlists_for_rule("core.git:reset-hard", "local dev flow");

        let result = evaluate_command(
            "git reset --hard",
            &config,
            &["git"],
            &compiled,
            &allowlists,
        );
        assert!(result.is_allowed());
        assert!(result.allowlist_override.is_some());
    }

    #[test]
    fn allowlist_miss_does_not_change_decision() {
        let config = default_config();
        let compiled = default_compiled_overrides();
        let allowlists = project_allowlists_for_rule("core.git:reset-merge", "not this one");

        let result = evaluate_command(
            "git reset --hard",
            &config,
            &["git"],
            &compiled,
            &allowlists,
        );
        assert!(result.is_denied());
        assert!(result.allowlist_override.is_none());
        assert_eq!(result.pack_id(), Some("core.git"));
    }

    #[test]
    fn wildcard_allowlist_matches_only_within_pack() {
        let mut config = default_config();
        config.packs.enabled.push("strict_git".to_string());

        let compiled = config.overrides.compile();
        let allowlists = project_allowlists_for_pack_wildcard("core.git", "allow all core.git");

        // Matches core.git, should allow.
        let git_result = evaluate_command(
            "git reset --hard",
            &config,
            &["git", "rm"],
            &compiled,
            &allowlists,
        );
        assert!(git_result.is_allowed());
        assert!(git_result.allowlist_override.is_some());

        // Matches core.filesystem, should still deny (wildcard is pack-scoped).
        let rm_result = evaluate_command(
            "rm -rf /etc",
            &config,
            &["git", "rm"],
            &compiled,
            &allowlists,
        );
        assert!(rm_result.is_denied());
        assert_eq!(rm_result.pack_id(), Some("core.filesystem"));
    }

    #[test]
    fn allowlisting_one_rule_does_not_disable_other_packs() {
        let mut config = default_config();
        config.packs.enabled.push("strict_git".to_string());

        let compiled = config.overrides.compile();
        let allowlists =
            project_allowlists_for_rule("core.git:push-force-long", "allow core force");

        // This command matches BOTH core.git and strict_git.
        // We allowlisted core.git:push-force-long.
        // So core.git should ALLOW it.
        // But strict_git should still DENY it (as it checks later and isn't allowlisted).
        let result = evaluate_command(
            "git push origin main --force",
            &config,
            &["git"],
            &compiled,
            &allowlists,
        );

        assert!(result.is_denied());
        // strict_git checks AFTER core.git.
        // core.git allows it (due to override).
        // strict_git blocks it.
        // So we expect strict_git.
        assert_eq!(result.pack_id(), Some("strict_git"));
        assert_eq!(
            result
                .pattern_info
                .as_ref()
                .unwrap()
                .pattern_name
                .as_deref(),
            Some("push-force-any") // strict_git rule name
        );
    }

    // =========================================================================
    // Evaluator Behavior Tests (git_safety_guard-99e.3.5, git_safety_guard-1g6)
    // =========================================================================
    //
    // These tests verify evaluator behavior using real pack patterns.
    // Mock types removed per git_safety_guard-1g6.

    /// Table-driven test: commands that should be ALLOWED.
    #[test]
    fn evaluator_allows_safe_commands() {
        let config = default_config();
        let compiled = default_compiled_overrides();
        let allowlists = default_allowlists();
        let keywords = &["git", "rm", "docker", "kubectl"];

        let test_cases = [
            // Non-relevant commands (quick-rejected)
            "ls -la",
            "cargo build --release",
            "npm install",
            "echo hello",
            "cat /etc/passwd",
            // Empty command
            "",
        ];

        for cmd in test_cases {
            let result = evaluate_command(cmd, &config, keywords, &compiled, &allowlists);
            assert!(
                result.is_allowed(),
                "Expected ALLOWED for {cmd:?}, got DENIED"
            );
        }
    }

    /// Test: config allow overrides work correctly.
    #[test]
    fn evaluator_respects_config_allow_override() {
        let config = default_config();
        let compiled = default_compiled_overrides();

        let tmp = std::env::temp_dir();
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = tmp.join(format!(
            "dcg_allowlist_test_{}_{}.toml",
            std::process::id(),
            unique
        ));

        let toml = r#"
            [[allow]]
            rule = "core.git:reset-hard"
            reason = "integration test"
        "#;
        std::fs::write(&path, toml).expect("write allowlist file");

        let allowlists = LayeredAllowlist::load_from_paths(Some(path), None, None);

        let result = evaluate_command(
            "git reset --hard",
            &config,
            &["git"],
            &compiled,
            &allowlists,
        );
        assert!(result.is_allowed());
        assert!(result.allowlist_override.is_some());
    }

    // =========================================================================
    // Match Span Tests (git_safety_guard-99e.2.4)
    // =========================================================================

    #[test]
    fn truncate_preview_handles_utf8_safely() {
        // ASCII string
        let short = "hello";
        assert_eq!(super::truncate_preview(short, 10), "hello");

        // Exactly at limit
        let exact = "hello";
        assert_eq!(super::truncate_preview(exact, 5), "hello");

        // Over limit, needs truncation
        let long = "hello world";
        assert_eq!(super::truncate_preview(long, 8), "hello...");

        // UTF-8 multibyte characters (should not break in middle of char)
        let japanese = "こんにちは世界"; // 7 chars, 21 bytes
        let truncated = super::truncate_preview(japanese, 5);
        assert!(truncated.ends_with("..."));
        // Should have 2 chars + "..."
        assert_eq!(truncated, "こん...");

        // Emoji
        let emoji = "🔥🔥🔥🔥🔥"; // 5 emoji, 20 bytes
        let truncated_emoji = super::truncate_preview(emoji, 3);
        assert_eq!(truncated_emoji, "..."); // 0 chars + "..." since 3-3=0
    }

    #[test]
    fn extract_match_preview_bounds_check() {
        let cmd = "rm -rf /important";

        // Normal span
        let span = super::MatchSpan { start: 0, end: 2 };
        assert_eq!(super::extract_match_preview(cmd, &span), "rm");

        // Span at end
        let span_end = super::MatchSpan { start: 7, end: 17 };
        assert_eq!(super::extract_match_preview(cmd, &span_end), "/important");

        // Span beyond bounds (should clamp)
        let span_overflow = super::MatchSpan {
            start: 0,
            end: 1000,
        };
        assert_eq!(
            super::extract_match_preview(cmd, &span_overflow),
            "rm -rf /important"
        );

        // Start beyond end (should return empty)
        let span_invalid = super::MatchSpan {
            start: 100,
            end: 50,
        };
        assert_eq!(super::extract_match_preview(cmd, &span_invalid), "");
    }

    #[test]
    fn extract_match_preview_handles_invalid_utf8_boundaries() {
        // Multi-byte UTF-8: "日本" is 6 bytes (3 bytes per character)
        let cmd = "日本語"; // 9 bytes, 3 characters

        // Valid boundaries (0, 3, 6, 9 are all valid)
        let valid_span = super::MatchSpan { start: 0, end: 3 };
        assert_eq!(super::extract_match_preview(cmd, &valid_span), "日");

        // Invalid start boundary (byte 1 is middle of first char)
        // Should snap forward to byte 3 (start of second char)
        let invalid_start = super::MatchSpan { start: 1, end: 6 };
        assert_eq!(super::extract_match_preview(cmd, &invalid_start), "本");

        // Invalid end boundary (byte 4 is middle of second char)
        // Should snap backward to byte 3 (end of first char)
        let invalid_end = super::MatchSpan { start: 0, end: 4 };
        assert_eq!(super::extract_match_preview(cmd, &invalid_end), "日");

        // Both boundaries invalid - should still not panic
        let both_invalid = super::MatchSpan { start: 1, end: 4 };
        // start snaps to 3, end snaps to 3, so start >= end -> empty
        assert_eq!(super::extract_match_preview(cmd, &both_invalid), "");

        // Span entirely within a character (start=1, end=2)
        // Both snap to boundaries, resulting in empty
        let within_char = super::MatchSpan { start: 1, end: 2 };
        assert_eq!(super::extract_match_preview(cmd, &within_char), "");
    }

    #[test]
    fn heredoc_matches_include_span_info() {
        let mut config = default_config();
        config.packs.enabled.push("system.core".to_string());
        let compiled = config.overrides.compile();
        let allowlists = default_allowlists();
        let enabled_packs = config.enabled_pack_ids();
        let keywords_vec = crate::packs::REGISTRY.collect_enabled_keywords(&enabled_packs);
        let keywords: Vec<&str> = keywords_vec.clone();

        // Heredoc containing dangerous command
        let cmd = "cat <<'EOF'\nrm -rf /\nEOF";

        let result = evaluate_command(cmd, &config, &keywords, &compiled, &allowlists);

        if result.is_denied() {
            if let Some(ref pattern_info) = result.pattern_info {
                // If there's a span, verify it's valid
                if let Some(span) = pattern_info.matched_span {
                    assert!(span.start <= span.end, "Span start should not exceed end");
                    assert!(
                        span.end <= cmd.len(),
                        "Span end should not exceed command length"
                    );
                    let matched = cmd.get(span.start..span.end).unwrap_or("");
                    assert!(
                        matched.contains("rm -rf /"),
                        "Matched span should point into heredoc content"
                    );
                }
            }
        }
    }

    #[test]
    fn match_span_maps_to_original_with_wrappers() {
        let mut config = default_config();
        config.packs.enabled.push("core.git".to_string());
        let compiled = config.overrides.compile();
        let allowlists = default_allowlists();
        let enabled_packs = config.enabled_pack_ids();
        let keywords_vec = crate::packs::REGISTRY.collect_enabled_keywords(&enabled_packs);
        let keywords: Vec<&str> = keywords_vec.clone();

        let cmd = "sudo git reset --hard";
        let result = evaluate_command(cmd, &config, &keywords, &compiled, &allowlists);

        assert!(result.is_denied(), "Command should be denied");
        let pattern_info = result.pattern_info.expect("Expected pattern info");
        let span = pattern_info.matched_span.expect("Expected matched span");
        let matched = cmd.get(span.start..span.end).unwrap_or("");
        assert_eq!(matched, "git reset --hard");
    }

    #[test]
    fn match_span_determinism() {
        let mut config = default_config();
        config.packs.enabled.push("system.core".to_string());
        let compiled = config.overrides.compile();
        let allowlists = default_allowlists();
        let enabled_packs = config.enabled_pack_ids();
        let keywords_vec = crate::packs::REGISTRY.collect_enabled_keywords(&enabled_packs);
        let keywords: Vec<&str> = keywords_vec.clone();

        let cmd = "rm -rf /";

        // Run multiple times and verify same result
        let result1 = evaluate_command(cmd, &config, &keywords, &compiled, &allowlists);
        let result2 = evaluate_command(cmd, &config, &keywords, &compiled, &allowlists);

        assert_eq!(result1.decision, result2.decision);
        assert_eq!(
            result1.pattern_info.as_ref().map(|p| p.matched_span),
            result2.pattern_info.as_ref().map(|p| p.matched_span),
            "Match span should be deterministic"
        );
        assert_eq!(
            result1
                .pattern_info
                .as_ref()
                .map(|p| p.matched_text_preview.as_ref()),
            result2
                .pattern_info
                .as_ref()
                .map(|p| p.matched_text_preview.as_ref()),
            "Match text preview should be deterministic"
        );
    }

    // =========================================================================
    // Deadline / Fail-Open Tests (git_safety_guard-99e.14)
    // =========================================================================

    mod deadline_tests {
        use super::*;
        use crate::perf::Deadline;
        use std::time::Duration;

        fn test_heredoc_settings() -> crate::config::HeredocSettings {
            crate::config::Config::default().heredoc_settings()
        }

        /// When deadline is already exceeded (zero duration), evaluation should fail-open immediately.
        #[test]
        fn exceeded_deadline_fails_open() {
            let compiled_overrides = default_compiled_overrides();
            let allowlists = default_allowlists();
            let heredoc_settings = test_heredoc_settings();
            let enabled_keywords: Vec<&str> = vec!["git", "rm"];
            let ordered_packs: Vec<String> = vec!["core.git".to_string()];
            let keyword_index = crate::packs::REGISTRY.build_enabled_keyword_index(&ordered_packs);

            // Create a deadline with zero duration - should be immediately exceeded
            let deadline = Deadline::new(Duration::ZERO);

            let result = evaluate_command_with_pack_order_deadline(
                "git reset --hard",
                &enabled_keywords,
                &ordered_packs,
                keyword_index.as_ref(),
                &compiled_overrides,
                &allowlists,
                &heredoc_settings,
                None,
                Some(&deadline),
            );

            // Should allow due to budget exhaustion, not deny
            assert!(
                result.is_allowed(),
                "Zero-duration deadline should fail open and allow command"
            );
            assert!(
                result.skipped_due_to_budget,
                "Result should indicate it was skipped due to budget"
            );
        }

        /// Normal deadline should allow evaluation to proceed.
        #[test]
        fn normal_deadline_allows_evaluation() {
            let compiled_overrides = default_compiled_overrides();
            let allowlists = default_allowlists();
            let heredoc_settings = test_heredoc_settings();
            let enabled_keywords: Vec<&str> = vec!["git", "rm"];
            let ordered_packs: Vec<String> = vec!["core.git".to_string()];
            let keyword_index = crate::packs::REGISTRY.build_enabled_keyword_index(&ordered_packs);

            // Create a generous deadline
            let deadline = Deadline::new(Duration::from_secs(10));

            let result = evaluate_command_with_pack_order_deadline(
                "git reset --hard",
                &enabled_keywords,
                &ordered_packs,
                keyword_index.as_ref(),
                &compiled_overrides,
                &allowlists,
                &heredoc_settings,
                None,
                Some(&deadline),
            );

            // Should deny the destructive command normally
            assert!(
                result.is_denied(),
                "Normal deadline should allow evaluation to proceed and deny destructive command"
            );
            assert!(
                !result.skipped_due_to_budget,
                "Result should not indicate budget skip"
            );
        }

        /// No deadline (None) should allow evaluation to proceed.
        #[test]
        fn no_deadline_allows_evaluation() {
            let compiled_overrides = default_compiled_overrides();
            let allowlists = default_allowlists();
            let heredoc_settings = test_heredoc_settings();
            let enabled_keywords: Vec<&str> = vec!["git", "rm"];
            let ordered_packs: Vec<String> = vec!["core.git".to_string()];
            let keyword_index = crate::packs::REGISTRY.build_enabled_keyword_index(&ordered_packs);

            let result = evaluate_command_with_pack_order_deadline(
                "git reset --hard",
                &enabled_keywords,
                &ordered_packs,
                keyword_index.as_ref(),
                &compiled_overrides,
                &allowlists,
                &heredoc_settings,
                None,
                None, // No deadline
            );

            // Should deny the destructive command normally
            assert!(
                result.is_denied(),
                "No deadline should allow evaluation to proceed and deny destructive command"
            );
            assert!(
                !result.skipped_due_to_budget,
                "Result should not indicate budget skip"
            );
        }

        /// Safe commands should be allowed even with tight deadline.
        #[test]
        fn safe_command_with_deadline() {
            let compiled_overrides = default_compiled_overrides();
            let allowlists = default_allowlists();
            let heredoc_settings = test_heredoc_settings();
            let enabled_keywords: Vec<&str> = vec!["git", "rm"];
            let ordered_packs: Vec<String> = vec!["core.git".to_string()];
            let keyword_index = crate::packs::REGISTRY.build_enabled_keyword_index(&ordered_packs);

            // Generous deadline for safe command
            let deadline = Deadline::new(Duration::from_secs(10));

            let result = evaluate_command_with_pack_order_deadline(
                "git status",
                &enabled_keywords,
                &ordered_packs,
                keyword_index.as_ref(),
                &compiled_overrides,
                &allowlists,
                &heredoc_settings,
                None,
                Some(&deadline),
            );

            // Should allow safe command
            assert!(result.is_allowed(), "Safe command should be allowed");
            assert!(
                !result.skipped_due_to_budget,
                "Safe command should not trigger budget skip"
            );
        }

        /// Test the `allowed_due_to_budget()` result structure.
        #[test]
        fn allowed_due_to_budget_structure() {
            let result = EvaluationResult::allowed_due_to_budget();

            assert!(result.is_allowed());
            assert!(!result.is_denied());
            assert!(result.skipped_due_to_budget);
            assert!(result.pattern_info.is_none());
            assert!(result.allowlist_override.is_none());
            assert!(result.effective_mode.is_none());
        }
    }

    #[test]
    fn integration_allowlist_file_overrides_deny() {
        let config = default_config();
        let compiled = default_compiled_overrides();

        let tmp = std::env::temp_dir();
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = tmp.join(format!(
            "dcg_allowlist_test_{}_{}.toml",
            std::process::id(),
            unique
        ));

        let toml = r#"
            [[allow]]
            rule = "core.git:reset-hard"
            reason = "integration test"
        "#;
        std::fs::write(&path, toml).expect("write allowlist file");

        let allowlists = LayeredAllowlist::load_from_paths(Some(path), None, None);

        let result = evaluate_command(
            "git reset --hard",
            &config,
            &["git"],
            &compiled,
            &allowlists,
        );
        assert!(result.is_allowed());
        assert!(result.allowlist_override.is_some());
    }

    // =========================================================================
    // Confidence Tiering Tests (git_safety_guard-oien.2.2)
    // =========================================================================
    //
    // These tests verify that Medium/Low severity patterns are evaluated (not skipped)
    // and the evaluator returns Deny results that the policy layer can convert to Warn/Log.

    #[test]
    fn medium_severity_patterns_are_evaluated() {
        // Test that Medium severity patterns are matched and return Deny results.
        // The policy layer in main.rs will convert these to Warn mode.
        let mut config = default_config();
        config.packs.enabled.push("containers.docker".to_string());
        let compiled = config.overrides.compile();
        let allowlists = default_allowlists();

        // docker image prune is a Medium severity pattern
        let result = evaluate_command(
            "docker image prune",
            &config,
            &["docker"],
            &compiled,
            &allowlists,
        );

        // Evaluator should return Deny (policy layer converts to Warn)
        assert!(
            result.is_denied(),
            "Medium severity pattern should be evaluated and return Deny"
        );

        // Verify severity is Medium
        let info = result
            .pattern_info
            .as_ref()
            .expect("should have pattern info");
        assert_eq!(
            info.severity,
            Some(crate::packs::Severity::Medium),
            "Pattern should have Medium severity"
        );
        assert_eq!(info.pack_id.as_deref(), Some("containers.docker"));
        assert_eq!(info.pattern_name.as_deref(), Some("image-prune"));
    }

    #[test]
    fn medium_severity_git_patterns_are_evaluated() {
        // Test git branch -D and stash drop (both Medium severity)
        let config = default_config();
        let compiled = config.overrides.compile();
        let allowlists = default_allowlists();

        // git branch -D is Medium severity
        let branch_result = evaluate_command(
            "git branch -D feature-branch",
            &config,
            &["git"],
            &compiled,
            &allowlists,
        );
        assert!(
            branch_result.is_denied(),
            "git branch -D should be evaluated"
        );
        let branch_info = branch_result.pattern_info.as_ref().unwrap();
        assert_eq!(branch_info.severity, Some(crate::packs::Severity::Medium));
        assert_eq!(
            branch_info.pattern_name.as_deref(),
            Some("branch-force-delete")
        );

        // git stash drop is Medium severity
        let stash_result = evaluate_command(
            "git stash drop stash@{0}",
            &config,
            &["git"],
            &compiled,
            &allowlists,
        );
        assert!(
            stash_result.is_denied(),
            "git stash drop should be evaluated"
        );
        let stash_info = stash_result.pattern_info.as_ref().unwrap();
        assert_eq!(stash_info.severity, Some(crate::packs::Severity::Medium));
        assert_eq!(stash_info.pattern_name.as_deref(), Some("stash-drop"));
    }

    #[test]
    fn critical_patterns_still_return_critical_severity() {
        // Ensure Critical patterns are unchanged
        let config = default_config();
        let compiled = config.overrides.compile();
        let allowlists = default_allowlists();

        // git reset --hard is Critical
        let result = evaluate_command(
            "git reset --hard",
            &config,
            &["git"],
            &compiled,
            &allowlists,
        );
        assert!(result.is_denied());
        let info = result.pattern_info.as_ref().unwrap();
        assert_eq!(
            info.severity,
            Some(crate::packs::Severity::Critical),
            "git reset --hard should remain Critical severity"
        );

        // git stash clear is Critical (vs stash drop which is Medium)
        let clear_result =
            evaluate_command("git stash clear", &config, &["git"], &compiled, &allowlists);
        assert!(clear_result.is_denied());
        let clear_info = clear_result.pattern_info.as_ref().unwrap();
        assert_eq!(
            clear_info.severity,
            Some(crate::packs::Severity::Critical),
            "git stash clear should remain Critical severity"
        );
    }

    #[test]
    fn policy_converts_medium_to_warn_mode() {
        // Test the policy layer correctly converts Medium severity to Warn mode.
        // This simulates what main.rs does after receiving the evaluation result.
        let policy = crate::config::PolicyConfig::default();

        // Medium severity should resolve to Warn mode
        let mode = policy.resolve_mode(
            Some("containers.docker"),
            Some("image-prune"),
            Some(crate::packs::Severity::Medium),
        );
        assert_eq!(
            mode,
            crate::packs::DecisionMode::Warn,
            "Medium severity should default to Warn mode"
        );

        // Critical severity should resolve to Deny mode
        let critical_mode = policy.resolve_mode(
            Some("core.git"),
            Some("reset-hard"),
            Some(crate::packs::Severity::Critical),
        );
        assert_eq!(
            critical_mode,
            crate::packs::DecisionMode::Deny,
            "Critical severity should always be Deny mode"
        );
    }

    // =========================================================================
    // UTF-8 Safe Windowing Tests (git_safety_guard-jpfm.2)
    // =========================================================================

    #[test]
    fn window_command_short_command_unchanged() {
        let cmd = "git reset --hard";
        let span = MatchSpan { start: 0, end: 16 };
        let result = window_command(cmd, &span, 80);

        assert_eq!(result.display, cmd);
        assert!(result.adjusted_span.is_some());
        let adj = result.adjusted_span.unwrap();
        assert_eq!(adj.start, 0);
        assert_eq!(adj.end, 16);
    }

    #[test]
    fn window_command_long_command_with_ellipsis() {
        // Create a long command with match in the middle
        let prefix = "a".repeat(50);
        let suffix = "b".repeat(50);
        let match_text = "git reset --hard";
        let cmd = format!("{prefix}{match_text}{suffix}");
        let span = MatchSpan {
            start: 50,
            end: 50 + 16,
        };

        let result = window_command(&cmd, &span, 40);

        // Should have ellipsis on both sides
        assert!(result.display.starts_with("..."));
        assert!(result.display.ends_with("..."));
        assert!(result.display.contains("git reset --hard"));

        // Adjusted span should point to the match within the windowed string
        let adj = result.adjusted_span.expect("Should have adjusted span");
        let windowed_match: String = result
            .display
            .chars()
            .skip(adj.start)
            .take(adj.end - adj.start)
            .collect();
        assert_eq!(windowed_match, "git reset --hard");
    }

    #[test]
    fn window_command_match_at_start() {
        let match_text = "rm -rf /";
        let suffix = "x".repeat(100);
        let cmd = format!("{match_text}{suffix}");
        let span = MatchSpan { start: 0, end: 8 };

        let result = window_command(&cmd, &span, 40);

        // Should NOT have left ellipsis, but should have right
        assert!(!result.display.starts_with("..."));
        assert!(result.display.ends_with("..."));
        assert!(result.display.contains("rm -rf /"));

        let adj = result.adjusted_span.expect("Should have adjusted span");
        assert_eq!(adj.start, 0);
    }

    #[test]
    fn window_command_match_at_end() {
        let prefix = "y".repeat(100);
        let match_text = "rm -rf /";
        let cmd = format!("{prefix}{match_text}");
        let span = MatchSpan {
            start: 100,
            end: 108,
        };

        let result = window_command(&cmd, &span, 40);

        // Should have left ellipsis, but NOT right
        assert!(result.display.starts_with("..."));
        assert!(!result.display.ends_with("..."));
        assert!(result.display.contains("rm -rf /"));
    }

    #[test]
    fn window_command_utf8_multibyte_chars() {
        // Test with UTF-8 multibyte characters (emoji)
        let cmd = "echo 🎉🎊🎈 && rm -rf / && echo done";
        // "rm -rf /" starts at byte position after "echo 🎉🎊🎈 && "
        // Each emoji is 4 bytes, so: "echo " (5) + 3*4 (12) + " && " (4) = 21 bytes
        let span = MatchSpan { start: 21, end: 29 }; // "rm -rf /"

        let result = window_command(cmd, &span, 50);

        assert!(result.display.contains("rm -rf /"));
        assert!(result.adjusted_span.is_some());
    }

    #[test]
    fn window_command_invalid_span_handles_gracefully() {
        let cmd = "short";
        let span = MatchSpan {
            start: 100,
            end: 200,
        }; // Way past end

        let result = window_command(cmd, &span, 80);

        // Should return full command but no span
        assert_eq!(result.display, "short");
        assert!(result.adjusted_span.is_none());
    }
}
