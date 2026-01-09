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
use crate::packs::{REGISTRY, normalize_command, pack_aware_quick_reject};
use std::collections::HashSet;

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
            }),
            allowlist_override: None,
            effective_mode: Some(crate::packs::DecisionMode::Deny),
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
            }),
            allowlist_override: None,
            effective_mode: Some(crate::packs::DecisionMode::Deny),
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
            }),
            allowlist_override: None,
            effective_mode: Some(crate::packs::DecisionMode::Deny),
        }
    }

    /// Create a "denied" result from a pack.
    #[inline]
    #[must_use]
    pub fn denied_by_pack(pack_id: &str, reason: &str) -> Self {
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
            }),
            allowlist_override: None,
            effective_mode: Some(crate::packs::DecisionMode::Deny),
        }
    }

    /// Create a "denied" result from a pack with pattern name.
    #[inline]
    #[must_use]
    pub fn denied_by_pack_pattern(
        pack_id: &str,
        pattern_name: &str,
        reason: &str,
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
            }),
            allowlist_override: None,
            effective_mode: Some(crate::packs::DecisionMode::Deny),
        }
    }

    /// Create a "denied" result from a pack with pattern name and match span.
    #[inline]
    #[must_use]
    pub fn denied_by_pack_pattern_with_span(
        pack_id: &str,
        pattern_name: &str,
        reason: &str,
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
            }),
            allowlist_override: None,
            effective_mode: Some(crate::packs::DecisionMode::Deny),
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
    let enabled_packs: HashSet<String> = config.enabled_pack_ids();
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    let heredoc_settings = config.heredoc_settings();
    evaluate_command_with_pack_order(
        command,
        enabled_keywords,
        &ordered_packs,
        compiled_overrides,
        allowlists,
        &heredoc_settings,
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
    compiled_overrides: &crate::config::CompiledOverrides,
    allowlists: &LayeredAllowlist,
    heredoc_settings: &crate::config::HeredocSettings,
) -> EvaluationResult {
    // Empty commands are allowed (no-op)
    if command.is_empty() {
        return EvaluationResult::allowed();
    }

    // Step 1: Check precompiled allow overrides first
    if compiled_overrides.check_allow(command) {
        return EvaluationResult::allowed();
    }

    // Step 2: Check precompiled block overrides
    if let Some(reason) = compiled_overrides.check_block(command) {
        return EvaluationResult::denied_by_config(reason.to_string());
    }

    // Step 3: Heredoc / inline-script detection (Tier 1/2/3, fail-open).
    //
    // IMPORTANT: this must run BEFORE keyword quick-reject, because the top-level command
    // might not contain any pack keywords even when the embedded script does.
    //
    // To avoid expensive work on obvious false triggers (e.g., `git commit -m "fix <<EOF"`),
    // we re-check triggers on a sanitized view that masks known-safe string arguments.
    let mut precomputed_sanitized = None;
    let mut heredoc_allowlist_hit: Option<(PatternMatch, AllowlistLayer, String)> = None;

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
            if let Some(blocked) = evaluate_heredoc(
                command,
                allowlists,
                heredoc_settings,
                &mut heredoc_allowlist_hit,
            ) {
                return blocked;
            }
        }
    }

    // Step 4: Quick rejection - if no relevant keywords, allow immediately
    // This handles the 99%+ case where commands don't need pattern checking.
    if pack_aware_quick_reject(command, enabled_keywords) {
        if let Some((matched, layer, reason)) = heredoc_allowlist_hit {
            return EvaluationResult::allowed_by_allowlist(matched, layer, reason);
        }
        return EvaluationResult::allowed();
    }

    // Step 5: False-positive immunity - strip known-safe string arguments (commit messages, search
    // patterns, issue descriptions, etc.) so dangerous substrings inside data do not trigger
    // blocking. If the sanitizer actually removes anything, re-run the keyword gate on the
    // sanitized view.
    let sanitized = precomputed_sanitized.unwrap_or_else(|| sanitize_for_pattern_matching(command));
    let command_for_match = sanitized.as_ref();
    if matches!(sanitized, std::borrow::Cow::Owned(_))
        && pack_aware_quick_reject(command_for_match, enabled_keywords)
    {
        if let Some((matched, layer, reason)) = heredoc_allowlist_hit {
            return EvaluationResult::allowed_by_allowlist(matched, layer, reason);
        }
        return EvaluationResult::allowed();
    }

    // Step 6: Normalize command (strip /usr/bin/git -> git, etc.)
    let normalized = normalize_command(command_for_match);

    // Step 7: Check enabled packs with allowlist override semantics.
    //
    // IMPORTANT: allowlisting must bypass only the specific matched rule, and must not
    // "disable other packs" by stopping evaluation early. If a command matches multiple
    // packs/patterns, allowlisting the first match should still allow later matches to
    // deny the command.
    let result = evaluate_packs_with_allowlists(&normalized, ordered_packs, allowlists);
    if result.allowlist_override.is_none() {
        if let Some((matched, layer, reason)) = heredoc_allowlist_hit {
            return EvaluationResult::allowed_by_allowlist(matched, layer, reason);
        }
    }

    result
}

fn evaluate_packs_with_allowlists(
    normalized: &str,
    ordered_packs: &[String],
    allowlists: &LayeredAllowlist,
) -> EvaluationResult {
    // If we allowlist a deny, we keep scanning for other denies. If none appear,
    // we return ALLOW + the first allowlist override metadata for explain/logging.
    let mut first_allowlist_hit: Option<(PatternMatch, AllowlistLayer, String)> = None;

    for pack_id in ordered_packs {
        let Some(pack) = REGISTRY.get(pack_id) else {
            continue;
        };

        // Per-pack keyword quick reject.
        if !pack.might_match(normalized) {
            continue;
        }

        // Pack safe patterns (whitelist) win within that pack.
        if pack.matches_safe(normalized) {
            continue;
        }

        for pattern in &pack.destructive_patterns {
            // Until warn/log are fully surfaced, match only deny-by-default patterns.
            if !pattern.severity.blocks_by_default() {
                continue;
            }

            if !pattern.regex.is_match(normalized).unwrap_or(false) {
                continue;
            }

            let reason = pattern.reason;

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
                                matched_span: None,
                                matched_text_preview: None,
                            },
                            hit.layer,
                            hit.entry.reason.clone(),
                        ));
                    }

                    // Bypass only this rule and keep evaluating other rules/packs.
                    continue;
                }

                return EvaluationResult::denied_by_pack_pattern(
                    pack_id,
                    pattern_name,
                    reason,
                    pattern.severity,
                );
            }

            return EvaluationResult::denied_by_pack(pack_id, reason);
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

    // Step 2: Check precompiled block overrides
    if let Some(reason) = compiled_overrides.check_block(command) {
        return EvaluationResult::denied_by_config(reason.to_string());
    }

    // Step 3: Heredoc / inline-script detection (Tier 1/2/3, fail-open).
    // See `evaluate_command` for detailed rationale.
    let heredoc_settings = config.heredoc_settings();
    let mut precomputed_sanitized = None;
    let mut heredoc_allowlist_hit: Option<(PatternMatch, AllowlistLayer, String)> = None;
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
            if let Some(blocked) = evaluate_heredoc(
                command,
                allowlists,
                &heredoc_settings,
                &mut heredoc_allowlist_hit,
            ) {
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
    let sanitized = precomputed_sanitized.unwrap_or_else(|| sanitize_for_pattern_matching(command));
    let command_for_match = sanitized.as_ref();
    if matches!(sanitized, std::borrow::Cow::Owned(_))
        && pack_aware_quick_reject(command_for_match, enabled_keywords)
    {
        if let Some((matched, layer, reason)) = heredoc_allowlist_hit {
            return EvaluationResult::allowed_by_allowlist(matched, layer, reason);
        }
        return EvaluationResult::allowed();
    }

    // Step 6: Normalize command (strip /usr/bin/git -> git, etc.)
    let normalized = normalize_command(command_for_match);

    // Step 7: Check legacy safe patterns (whitelist)
    for pattern in safe_patterns {
        if pattern.is_match(&normalized) {
            return EvaluationResult::allowed();
        }
    }

    // Step 8: Check legacy destructive patterns (blacklist)
    for pattern in destructive_patterns {
        if pattern.is_match(&normalized) {
            return EvaluationResult::denied_by_legacy(pattern.reason());
        }
    }

    // Step 9: Check enabled packs with allowlist override semantics.
    let enabled_packs: HashSet<String> = config.enabled_pack_ids();
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    let result = evaluate_packs_with_allowlists(&normalized, &ordered_packs, allowlists);
    if result.allowlist_override.is_none() {
        if let Some((matched, layer, reason)) = heredoc_allowlist_hit {
            return EvaluationResult::allowed_by_allowlist(matched, layer, reason);
        }
    }

    result
}

// ============================================================================
// Heredoc / Inline Script Evaluation (Tier 2/3)
// ============================================================================

#[allow(clippy::too_many_lines)]
fn evaluate_heredoc(
    command: &str,
    allowlists: &LayeredAllowlist,
    heredoc_settings: &crate::config::HeredocSettings,
    first_allowlist_hit: &mut Option<(PatternMatch, AllowlistLayer, String)>,
) -> Option<EvaluationResult> {
    let extracted = match extract_content(command, &heredoc_settings.limits) {
        ExtractionResult::Extracted(contents) => contents,
        ExtractionResult::NoContent => return None,
        ExtractionResult::Skipped(reasons) => {
            let is_timeout = reasons
                .iter()
                .any(|r| matches!(r, SkipReason::Timeout { .. }));

            let strict_timeout = is_timeout && !heredoc_settings.fallback_on_timeout;
            let strict_other = !is_timeout && !heredoc_settings.fallback_on_parse_error;
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

            return None;
        }
        ExtractionResult::Failed(err) => {
            if !heredoc_settings.fallback_on_parse_error {
                let reason = format!(
                    "Embedded code blocked: extraction failed and \
                     fallback_on_parse_error=false ({err})"
                );
                return Some(EvaluationResult::denied_by_legacy(&reason));
            }

            return None;
        }
    };

    for content in extracted {
        if let Some(allowed) = &heredoc_settings.allowed_languages {
            if !allowed.contains(&content.language) {
                continue;
            }
        }

        let matches = match DEFAULT_MATCHER.find_matches(&content.content, content.language) {
            Ok(matches) => matches,
            Err(err) => {
                let is_timeout = matches!(err, crate::ast_matcher::MatchError::Timeout { .. });
                let strict_timeout = is_timeout && !heredoc_settings.fallback_on_timeout;
                let strict_other = !is_timeout && !heredoc_settings.fallback_on_parse_error;
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
            if !m.severity.blocks_by_default() {
                continue;
            }

            let (pack_id, pattern_name) = split_ast_rule_id(&m.rule_id);

            if let Some(hit) = allowlists.match_rule(&pack_id, &pattern_name) {
                if first_allowlist_hit.is_none() {
                    let reason =
                        format_heredoc_denial_reason(&content, &m, &pack_id, &pattern_name);
                    *first_allowlist_hit = Some((
                        PatternMatch {
                            pack_id: Some(pack_id),
                            pattern_name: Some(pattern_name),
                            severity: Some(ast_severity_to_pack_severity(m.severity)),
                            reason,
                            source: MatchSource::HeredocAst,
                            // AST matches already have span info from the matcher
                            matched_span: Some(MatchSpan {
                                start: m.start,
                                end: m.end,
                            }),
                            matched_text_preview: Some(m.matched_text_preview),
                        },
                        hit.layer,
                        hit.entry.reason.clone(),
                    ));
                }
                continue;
            }

            let reason = format_heredoc_denial_reason(&content, &m, &pack_id, &pattern_name);
            return Some(EvaluationResult {
                decision: EvaluationDecision::Deny,
                pattern_info: Some(PatternMatch {
                    pack_id: Some(pack_id),
                    pattern_name: Some(pattern_name),
                    severity: Some(ast_severity_to_pack_severity(m.severity)),
                    reason,
                    source: MatchSource::HeredocAst,
                    // AST matches already have span info from the matcher
                    matched_span: Some(MatchSpan {
                        start: m.start,
                        end: m.end,
                    }),
                    matched_text_preview: Some(m.matched_text_preview),
                }),
                allowlist_override: None,
                effective_mode: Some(crate::packs::DecisionMode::Deny),
            });
        }
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
        return ("heredoc".to_string(), rest.to_string());
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
        crate::heredoc::ScriptLanguage::Unknown => "unknown",
    };

    format!(
        "Embedded {lang} code blocked: {} (rule {pack_id}:{pattern_name}, line {}, matched: {})",
        m.reason, m.line_number, m.matched_text_preview
    )
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
    /// Get the reason for blocking.
    fn reason(&self) -> &str;
}

impl LegacySafePattern for crate::packs::SafePattern {
    fn is_match(&self, cmd: &str) -> bool {
        self.regex.is_match(cmd).unwrap_or(false)
    }
}

impl LegacyDestructivePattern for crate::packs::DestructivePattern {
    fn is_match(&self, cmd: &str) -> bool {
        self.regex.is_match(cmd).unwrap_or(false)
    }

    fn reason(&self) -> &str {
        self.reason
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowlist::{
        AllowEntry, AllowSelector, AllowlistFile, LoadedAllowlistLayer, RuleId,
    };
    use fancy_regex::Regex;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

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

        let denied = EvaluationResult::denied_by_pack("test.pack", "test reason");
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
        // Command with no relevant keywords should be quickly allowed
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
        let cmd = r#"node -e "require('child_process').execSync('rm -rf /')""#;
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
        assert!(
            result.is_allowed(),
            "allowlisting the matched rule should override deny"
        );

        let override_info = result
            .allowlist_override
            .as_ref()
            .expect("allowlist override metadata must be present");
        assert_eq!(override_info.layer, AllowlistLayer::Project);
        assert_eq!(override_info.reason, "local dev flow");
        assert_eq!(override_info.matched.pack_id.as_deref(), Some("core.git"));
        assert_eq!(
            override_info.matched.pattern_name.as_deref(),
            Some("reset-hard")
        );
        assert_eq!(override_info.matched.source, MatchSource::Pack);
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
        assert!(
            result.is_denied(),
            "non-matching allowlist entries must not affect decision"
        );
        assert!(result.allowlist_override.is_none());
        assert_eq!(result.pack_id(), Some("core.git"));
    }

    #[test]
    fn wildcard_allowlist_matches_only_within_pack() {
        let config = default_config();
        let compiled = default_compiled_overrides();
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
        // Allowlisting the core.git rule must not bypass strict_git.
        let result = evaluate_command(
            "git push origin main --force",
            &config,
            &["git"],
            &compiled,
            &allowlists,
        );

        assert!(result.is_denied());
        assert_eq!(result.pack_id(), Some("strict_git"));
        assert_eq!(
            result
                .pattern_info
                .as_ref()
                .unwrap()
                .pattern_name
                .as_deref(),
            Some("push-force-any")
        );
    }

    #[test]
    fn integration_allowlist_file_overrides_deny() {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);

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
    // Hook/CLI Evaluator Parity Tests (git_safety_guard-99e.3.5)
    // =========================================================================
    //
    // These tests verify that evaluate_command and evaluate_command_with_legacy
    // produce identical decisions for pack-based patterns, ensuring hook mode
    // and CLI mode agree once legacy patterns are retired.

    /// Helper struct for legacy safe pattern testing.
    struct MockSafePattern {
        regex: Regex,
    }

    impl LegacySafePattern for MockSafePattern {
        fn is_match(&self, cmd: &str) -> bool {
            self.regex.is_match(cmd).unwrap_or(false)
        }
    }

    /// Helper struct for legacy destructive pattern testing.
    struct MockDestructivePattern {
        regex: Regex,
        reason: String,
    }

    impl LegacyDestructivePattern for MockDestructivePattern {
        fn is_match(&self, cmd: &str) -> bool {
            self.regex.is_match(cmd).unwrap_or(false)
        }
        fn reason(&self) -> &str {
            &self.reason
        }
    }

    /// Table-driven parity test: commands that should be ALLOWED by both paths.
    #[test]
    fn parity_allowed_commands() {
        let config = default_config();
        let compiled = default_compiled_overrides();
        let allowlists = default_allowlists();
        let keywords = &["git", "rm", "docker", "kubectl"];
        let safe_patterns: Vec<MockSafePattern> = vec![];
        let destructive_patterns: Vec<MockDestructivePattern> = vec![];

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
            let result1 = evaluate_command(cmd, &config, keywords, &compiled, &allowlists);
            let result2 = evaluate_command_with_legacy(
                cmd,
                &config,
                keywords,
                &compiled,
                &allowlists,
                &safe_patterns,
                &destructive_patterns,
            );

            assert_eq!(
                result1.decision, result2.decision,
                "Parity mismatch for allowed command: {cmd:?}"
            );
            assert!(
                result1.is_allowed(),
                "Expected ALLOWED for {cmd:?}, got DENIED"
            );
        }
    }

    /// Table-driven parity test: commands blocked by pack patterns.
    #[test]
    fn parity_pack_blocked_commands() {
        // Create a config that enables the docker pack
        let mut config = default_config();
        config.packs.enabled.push("containers.docker".to_string());

        let compiled = config.overrides.compile();
        let allowlists = default_allowlists();
        let enabled_packs = config.enabled_pack_ids();
        let keywords_vec = crate::packs::REGISTRY.collect_enabled_keywords(&enabled_packs);
        let keywords: Vec<&str> = keywords_vec.clone();

        let safe_patterns: Vec<MockSafePattern> = vec![];
        let destructive_patterns: Vec<MockDestructivePattern> = vec![];

        // Commands that should be blocked by docker pack
        let blocked_commands = ["docker system prune", "docker system prune -a"];

        for cmd in blocked_commands {
            let result1 = evaluate_command(cmd, &config, &keywords, &compiled, &allowlists);
            let result2 = evaluate_command_with_legacy(
                cmd,
                &config,
                &keywords,
                &compiled,
                &allowlists,
                &safe_patterns,
                &destructive_patterns,
            );

            assert_eq!(
                result1.decision, result2.decision,
                "Parity mismatch for pack-blocked command: {cmd:?}"
            );
            assert!(
                result1.is_denied(),
                "Expected DENIED for {cmd:?}, got ALLOWED"
            );
            assert_eq!(
                result1.pack_id(),
                result2.pack_id(),
                "Pack ID mismatch for {cmd:?}"
            );
        }
    }

    /// Parity test: config allow overrides work in both paths.
    #[test]
    fn parity_config_allow_override() {
        use crate::config::AllowOverride;

        let mut config = default_config();
        config.packs.enabled.push("containers.docker".to_string());
        // Add an allow override that permits docker prune
        config
            .overrides
            .allow
            .push(AllowOverride::Simple("docker system prune".to_string()));

        let compiled = config.overrides.compile();
        let allowlists = default_allowlists();
        let enabled_packs = config.enabled_pack_ids();
        let keywords_vec = crate::packs::REGISTRY.collect_enabled_keywords(&enabled_packs);
        let keywords: Vec<&str> = keywords_vec.clone();

        let safe_patterns: Vec<MockSafePattern> = vec![];
        let destructive_patterns: Vec<MockDestructivePattern> = vec![];

        let cmd = "docker system prune";

        let result1 = evaluate_command(cmd, &config, &keywords, &compiled, &allowlists);
        let result2 = evaluate_command_with_legacy(
            cmd,
            &config,
            &keywords,
            &compiled,
            &allowlists,
            &safe_patterns,
            &destructive_patterns,
        );

        assert_eq!(
            result1.decision, result2.decision,
            "Parity mismatch for config allow override"
        );
        assert!(
            result1.is_allowed(),
            "Config allow override should permit docker prune"
        );
    }

    /// Parity test: config block overrides work in both paths.
    #[test]
    fn parity_config_block_override() {
        use crate::config::BlockOverride;

        let mut config = default_config();
        // Add a block override that blocks a normally-safe command
        config.overrides.block.push(BlockOverride {
            pattern: "ls.*secret".to_string(),
            reason: "Blocked by config".to_string(),
        });

        let compiled = config.overrides.compile();
        let allowlists = default_allowlists();
        let keywords = &["ls"]; // Need ls keyword to not quick-reject

        let safe_patterns: Vec<MockSafePattern> = vec![];
        let destructive_patterns: Vec<MockDestructivePattern> = vec![];

        let cmd = "ls /secret/files";

        let result1 = evaluate_command(cmd, &config, keywords, &compiled, &allowlists);
        let result2 = evaluate_command_with_legacy(
            cmd,
            &config,
            keywords,
            &compiled,
            &allowlists,
            &safe_patterns,
            &destructive_patterns,
        );

        assert_eq!(
            result1.decision, result2.decision,
            "Parity mismatch for config block override"
        );
        assert!(
            result1.is_denied(),
            "Config block override should deny ls /secret/files"
        );
        assert_eq!(
            result1.pattern_info.as_ref().unwrap().source,
            MatchSource::ConfigOverride
        );
    }

    /// Verify legacy patterns cause divergence (expected until legacy is retired).
    /// This test documents the current behavior and will help catch when we retire legacy.
    #[test]
    fn legacy_patterns_cause_expected_divergence() {
        let config = default_config();
        let compiled = default_compiled_overrides();
        let allowlists = default_allowlists();
        let keywords = &["test"];

        // Create a legacy destructive pattern that blocks "test dangerous"
        let safe_patterns: Vec<MockSafePattern> = vec![];
        let destructive_patterns = vec![MockDestructivePattern {
            regex: Regex::new("test dangerous").unwrap(),
            reason: "Legacy block".to_string(),
        }];

        let cmd = "test dangerous command";

        let result1 = evaluate_command(cmd, &config, keywords, &compiled, &allowlists);
        let result2 = evaluate_command_with_legacy(
            cmd,
            &config,
            keywords,
            &compiled,
            &allowlists,
            &safe_patterns,
            &destructive_patterns,
        );

        // evaluate_command (CLI path) allows it (no pack match)
        assert!(
            result1.is_allowed(),
            "evaluate_command should allow (no pack match)"
        );

        // evaluate_command_with_legacy (hook path) blocks it (legacy match)
        assert!(
            result2.is_denied(),
            "evaluate_command_with_legacy should deny (legacy match)"
        );
        assert_eq!(
            result2.pattern_info.as_ref().unwrap().source,
            MatchSource::LegacyPattern
        );

        // This divergence is expected and will go away when legacy patterns are retired
    }

    /// Verify normalization is applied consistently in both paths.
    #[test]
    fn parity_command_normalization() {
        let mut config = default_config();
        config.packs.enabled.push("containers.docker".to_string());

        let compiled = config.overrides.compile();
        let allowlists = default_allowlists();
        let enabled_packs = config.enabled_pack_ids();
        let keywords_vec = crate::packs::REGISTRY.collect_enabled_keywords(&enabled_packs);
        let keywords: Vec<&str> = keywords_vec.clone();

        let safe_patterns: Vec<MockSafePattern> = vec![];
        let destructive_patterns: Vec<MockDestructivePattern> = vec![];

        // Command with absolute path (should be normalized)
        let cmd = "/usr/bin/docker system prune";

        let result1 = evaluate_command(cmd, &config, &keywords, &compiled, &allowlists);
        let result2 = evaluate_command_with_legacy(
            cmd,
            &config,
            &keywords,
            &compiled,
            &allowlists,
            &safe_patterns,
            &destructive_patterns,
        );

        assert_eq!(
            result1.decision, result2.decision,
            "Parity mismatch for normalized command"
        );
        // Should be blocked after normalization strips /usr/bin/
        assert!(
            result1.is_denied(),
            "Normalized docker prune should be blocked"
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
                }
            }
        }
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
}

// =============================================================================
// Property-Based Tests (git_safety_guard-7tg.1)
// =============================================================================
//
// These tests use proptest to verify evaluator invariants with random inputs.
// They encode properties we never want to regress.

#[cfg(test)]
mod proptest_invariants {
    use super::*;
    use crate::config::Config;
    use crate::packs::normalize_command;
    use proptest::prelude::*;
    use std::sync::LazyLock;

    static EMPTY_ALLOWLISTS: LazyLock<LayeredAllowlist> = LazyLock::new(LayeredAllowlist::default);

    fn default_allowlists() -> &'static LayeredAllowlist {
        &EMPTY_ALLOWLISTS
    }

    /// Strategy for generating arbitrary UTF-8 strings for command testing.
    /// Includes normal commands, edge cases, and adversarial inputs.
    fn command_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            // Normal-looking commands
            "[a-zA-Z][a-zA-Z0-9_\\-]{0,50}( [a-zA-Z0-9_\\-./]+){0,10}",
            // Commands with special characters
            "[!-~]{0,100}",
            // Commands with unicode
            "\\PC{0,100}",
            // Very short commands
            ".{0,5}",
            // Empty string
            Just(String::new()),
            // Path-like commands
            "(/[a-z]+){1,5} [a-z\\-]+( [a-z]+)*",
        ]
    }

    proptest! {
        /// Property: Normalization is idempotent.
        /// normalize(normalize(cmd)) == normalize(cmd)
        #[test]
        fn normalization_is_idempotent(cmd in command_strategy()) {
            let once = normalize_command(&cmd).into_owned();
            let twice = normalize_command(&once).into_owned();
            prop_assert_eq!(
                once, twice,
                "Normalization should be idempotent for: {:?}", cmd
            );
        }

        /// Property: Evaluation is deterministic.
        /// Evaluating the same input twice yields identical results.
        #[test]
        fn evaluation_is_deterministic(cmd in command_strategy()) {
            let config = Config::default();
            let compiled = config.overrides.compile();
            let allowlists = default_allowlists();
            let keywords = &["git", "rm", "docker", "kubectl", "psql", "mysql"];

            let result1 = evaluate_command(&cmd, &config, keywords, &compiled, allowlists);
            let result2 = evaluate_command(&cmd, &config, keywords, &compiled, allowlists);

            prop_assert_eq!(
                result1.decision, result2.decision,
                "Decision should be deterministic for: {:?}", cmd
            );

            // If denied, the reason and pack_id should also match
            if result1.is_denied() {
                prop_assert_eq!(
                    result1.reason(), result2.reason(),
                    "Reason should be deterministic for: {:?}", cmd
                );
                prop_assert_eq!(
                    result1.pack_id(), result2.pack_id(),
                    "Pack ID should be deterministic for: {:?}", cmd
                );
            }
        }

        /// Property: Evaluation never panics for arbitrary UTF-8 input.
        /// This test uses proptest to generate adversarial inputs.
        #[test]
        fn evaluation_never_panics(cmd in "\\PC{0,1000}") {
            let config = Config::default();
            let compiled = config.overrides.compile();
            let allowlists = default_allowlists();
            let keywords = &["git", "rm", "docker", "kubectl"];

            // This should not panic - if it does, proptest will catch it
            let _result = evaluate_command(&cmd, &config, keywords, &compiled, allowlists);
        }

        /// Property: Bounded behavior for large inputs.
        /// Very long commands complete in bounded time and don't cause OOM.
        #[test]
        fn handles_large_inputs(
            prefix in "[a-z]{1,10}",
            repeat_count in 1usize..1000,
        ) {
            // Create a large but bounded command
            let cmd = format!("{} {}", prefix, "arg ".repeat(repeat_count));

            let config = Config::default();
            let compiled = config.overrides.compile();
            let allowlists = default_allowlists();
            let keywords = &["git", "rm"];

            // Should complete without issue
            let result = evaluate_command(&cmd, &config, keywords, &compiled, allowlists);

            // Large commands without relevant keywords should be quick-rejected
            if !cmd.contains("git") && !cmd.contains("rm") {
                prop_assert!(result.is_allowed());
            }
        }

        /// Property: Empty and whitespace-only commands are always allowed.
        #[test]
        fn empty_and_whitespace_allowed(spaces in "[ \\t\\n]*") {
            let config = Config::default();
            let compiled = config.overrides.compile();
            let allowlists = default_allowlists();
            let keywords = &["git", "rm"];

            // Empty commands should be allowed
            let result = evaluate_command(&spaces, &config, keywords, &compiled, allowlists);

            // Commands that are only whitespace should also be allowed
            // (they don't contain any relevant keywords)
            prop_assert!(result.is_allowed());
        }
    }
}
