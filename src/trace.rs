//! Explain trace data model for `dcg explain` mode.
//!
//! This module provides opt-in instrumentation for tracing command evaluation,
//! enabling detailed decision explanations without impacting hook mode performance.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      TraceCollector                             │
//! │  (opt-in, passed as Option<&mut TraceCollector> to evaluator)   │
//! └─────────────────────────────────────────────────────────────────┘
//!                                  │
//!                                  ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                       ExplainTrace                              │
//! │  (complete decision trace with steps, match info, timing)       │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Performance
//!
//! When tracing is disabled (`None`), the evaluator avoids allocations and
//! expensive string formatting. The trace collection is truly opt-in.
//!
//! # Example
//!
//! ```ignore
//! use destructive_command_guard::trace::TraceCollector;
//! use destructive_command_guard::evaluator::EvaluationDecision;
//!
//! let mut collector = TraceCollector::new("git reset --hard");
//! // ... pass &mut collector to evaluator ...
//! let trace = collector.finish(EvaluationDecision::Deny);
//!
//! println!("Decision: {:?}", trace.decision);
//! println!("Total time: {}us", trace.total_duration_us);
//! for step in &trace.steps {
//!     println!("  {} ({}us)", step.name, step.duration_us);
//! }
//! ```

use crate::allowlist::AllowlistLayer;
use crate::evaluator::{EvaluationDecision, MatchSource};
use std::time::Instant;

/// A complete trace of a command evaluation.
///
/// Contains all information needed for `dcg explain` output formatting.
#[derive(Debug, Clone)]
pub struct ExplainTrace {
    /// The original command that was evaluated.
    pub command: String,
    /// The normalized command (after path stripping, etc.).
    pub normalized_command: Option<String>,
    /// The sanitized command (after masking safe string arguments).
    pub sanitized_command: Option<String>,
    /// The final decision (Allow or Deny).
    pub decision: EvaluationDecision,
    /// Total evaluation duration in microseconds.
    pub total_duration_us: u64,
    /// Individual trace steps in chronological order.
    pub steps: Vec<TraceStep>,
    /// Match information (when command was denied or allowlisted).
    pub match_info: Option<MatchInfo>,
    /// Allowlist override information (when a deny was overridden).
    pub allowlist_info: Option<AllowlistInfo>,
    /// Summary of packs that were evaluated.
    pub pack_summary: Option<PackSummary>,
}

/// A single step in the evaluation trace.
#[derive(Debug, Clone)]
pub struct TraceStep {
    /// Human-readable step name.
    pub name: &'static str,
    /// Step duration in microseconds.
    pub duration_us: u64,
    /// Step-specific details.
    pub details: TraceDetails,
}

/// Step-specific details for different evaluation stages.
#[derive(Debug, Clone)]
pub enum TraceDetails {
    /// Input parsing (hook JSON vs CLI input).
    InputParsing {
        /// Whether input was from hook (JSON) or CLI.
        is_hook_input: bool,
        /// Command length in bytes.
        command_len: usize,
    },

    /// Keyword gating (quick reject).
    KeywordGating {
        /// Whether the command was quick-rejected (no keywords found).
        quick_rejected: bool,
        /// Keywords that were checked.
        keywords_checked: Vec<String>,
        /// First keyword that matched (if any).
        first_match: Option<String>,
    },

    /// Command normalization.
    Normalization {
        /// Whether the command was modified.
        was_modified: bool,
        /// Original prefix that was stripped (if any).
        stripped_prefix: Option<String>,
    },

    /// Context sanitization (false positive immunity).
    Sanitization {
        /// Whether the command was modified.
        was_modified: bool,
        /// Number of spans that were masked.
        spans_masked: usize,
    },

    /// Heredoc/inline script detection.
    HeredocDetection {
        /// Whether heredoc triggers were found.
        triggered: bool,
        /// Number of scripts extracted.
        scripts_extracted: usize,
        /// Languages detected.
        languages: Vec<String>,
    },

    /// Allowlist check.
    AllowlistCheck {
        /// Number of layers checked.
        layers_checked: usize,
        /// Whether a match was found.
        matched: bool,
        /// The layer that matched (if any).
        matched_layer: Option<AllowlistLayer>,
    },

    /// Pack evaluation.
    PackEvaluation {
        /// Packs that were evaluated (not skipped).
        packs_evaluated: Vec<String>,
        /// Packs that were skipped (keyword gating).
        packs_skipped: Vec<String>,
        /// The pack that matched (if any).
        matched_pack: Option<String>,
        /// The pattern name that matched (if any).
        matched_pattern: Option<String>,
    },

    /// Config override check.
    ConfigOverride {
        /// Whether an allow override matched.
        allow_matched: bool,
        /// Whether a block override matched.
        block_matched: bool,
        /// The override reason (if blocked).
        reason: Option<String>,
    },

    /// Final policy decision.
    PolicyDecision {
        /// The decision made.
        decision: EvaluationDecision,
        /// Whether the decision was due to allowlist override.
        allowlisted: bool,
    },
}

/// Information about a pattern match (for denials or allowlist overrides).
#[derive(Debug, Clone)]
pub struct MatchInfo {
    /// Stable rule ID (e.g., `core.git:reset-hard`).
    pub rule_id: Option<String>,
    /// Pack ID that matched.
    pub pack_id: Option<String>,
    /// Pattern name that matched.
    pub pattern_name: Option<String>,
    /// Human-readable reason.
    pub reason: String,
    /// Source of the match.
    pub source: MatchSource,
    /// Byte offset where match starts in the command.
    pub match_start: Option<usize>,
    /// Byte offset where match ends in the command.
    pub match_end: Option<usize>,
    /// Preview of matched text (truncated if too long).
    pub matched_text_preview: Option<String>,
}

/// Information about an allowlist override.
#[derive(Debug, Clone)]
pub struct AllowlistInfo {
    /// The layer that matched.
    pub layer: AllowlistLayer,
    /// The allowlist entry reason.
    pub entry_reason: String,
    /// The original match that was overridden.
    pub original_match: MatchInfo,
}

/// Summary of pack evaluation.
#[derive(Debug, Clone)]
pub struct PackSummary {
    /// Total number of enabled packs.
    pub enabled_count: usize,
    /// Packs that were evaluated (not skipped by keyword gating).
    pub evaluated: Vec<String>,
    /// Packs that were skipped (keyword gating).
    pub skipped: Vec<String>,
}

/// Collector for building a trace during evaluation.
///
/// This is the opt-in instrumentation hook. Pass `Some(&mut collector)` to
/// the evaluator to enable tracing, or `None` to disable.
#[derive(Debug)]
pub struct TraceCollector {
    /// Start time of the evaluation.
    start_time: Instant,
    /// Current step start time.
    step_start: Instant,
    /// Steps collected so far.
    steps: Vec<TraceStep>,
    /// The original command.
    command: String,
    /// Normalized command (set during evaluation).
    normalized_command: Option<String>,
    /// Sanitized command (set during evaluation).
    sanitized_command: Option<String>,
    /// Match information (set during evaluation).
    match_info: Option<MatchInfo>,
    /// Allowlist information (set during evaluation).
    allowlist_info: Option<AllowlistInfo>,
    /// Pack summary (set during evaluation).
    pack_summary: Option<PackSummary>,
}

impl TraceCollector {
    /// Create a new trace collector.
    #[must_use]
    pub fn new(command: &str) -> Self {
        let now = Instant::now();
        Self {
            start_time: now,
            step_start: now,
            steps: Vec::with_capacity(8), // Typical number of steps
            command: command.to_string(),
            normalized_command: None,
            sanitized_command: None,
            match_info: None,
            allowlist_info: None,
            pack_summary: None,
        }
    }

    /// Start timing a new step.
    pub fn begin_step(&mut self) {
        self.step_start = Instant::now();
    }

    /// End the current step and record it.
    #[allow(clippy::cast_possible_truncation)] // Microseconds fit in u64
    pub fn end_step(&mut self, name: &'static str, details: TraceDetails) {
        let duration_us = self.step_start.elapsed().as_micros() as u64;
        self.steps.push(TraceStep {
            name,
            duration_us,
            details,
        });
    }

    /// Record a step with explicit duration (for when step wasn't timed with begin/end).
    pub fn record_step(&mut self, name: &'static str, duration_us: u64, details: TraceDetails) {
        self.steps.push(TraceStep {
            name,
            duration_us,
            details,
        });
    }

    /// Set the normalized command.
    pub fn set_normalized(&mut self, normalized: &str) {
        self.normalized_command = Some(normalized.to_string());
    }

    /// Set the sanitized command.
    pub fn set_sanitized(&mut self, sanitized: &str) {
        self.sanitized_command = Some(sanitized.to_string());
    }

    /// Set match information.
    pub fn set_match(&mut self, info: MatchInfo) {
        self.match_info = Some(info);
    }

    /// Set allowlist override information.
    pub fn set_allowlist(&mut self, info: AllowlistInfo) {
        self.allowlist_info = Some(info);
    }

    /// Set pack summary.
    pub fn set_pack_summary(&mut self, summary: PackSummary) {
        self.pack_summary = Some(summary);
    }

    /// Finish collection and produce the final trace.
    #[allow(clippy::cast_possible_truncation)] // Microseconds fit in u64
    #[must_use]
    pub fn finish(self, decision: EvaluationDecision) -> ExplainTrace {
        let total_duration_us = self.start_time.elapsed().as_micros() as u64;
        ExplainTrace {
            command: self.command,
            normalized_command: self.normalized_command,
            sanitized_command: self.sanitized_command,
            decision,
            total_duration_us,
            steps: self.steps,
            match_info: self.match_info,
            allowlist_info: self.allowlist_info,
            pack_summary: self.pack_summary,
        }
    }
}

impl ExplainTrace {
    /// Get the stable rule ID (if a match occurred).
    #[must_use]
    pub fn rule_id(&self) -> Option<&str> {
        self.match_info.as_ref().and_then(|m| m.rule_id.as_deref())
    }

    /// Check if the command was allowed due to an allowlist override.
    #[must_use]
    pub const fn was_allowlisted(&self) -> bool {
        self.allowlist_info.is_some()
    }

    /// Get the first match (either from denial or allowlist).
    #[must_use]
    pub fn first_match(&self) -> Option<&MatchInfo> {
        self.match_info
            .as_ref()
            .or_else(|| self.allowlist_info.as_ref().map(|a| &a.original_match))
    }

    /// Find a step by name.
    #[must_use]
    pub fn find_step(&self, name: &str) -> Option<&TraceStep> {
        self.steps.iter().find(|s| s.name == name)
    }

    /// Format the trace as a compact single-line string.
    ///
    /// Format examples:
    /// - `ALLOW (94us) git status`
    /// - `DENY core.git:reset-hard (847us) git reset --hard — destroys uncommitted changes`
    /// - `WARN containers.docker:system-prune (1.2ms) docker system prune -af — removes all unused data`
    ///
    /// The command is truncated to `max_command_len` characters (default 60) with UTF-8 safety.
    #[must_use]
    pub fn format_compact(&self, max_command_len: Option<usize>) -> String {
        let max_len = max_command_len.unwrap_or(60);
        let decision_str = match self.decision {
            EvaluationDecision::Allow => "ALLOW",
            EvaluationDecision::Deny => "DENY",
        };

        let duration_str = format_duration(self.total_duration_us);
        let command_preview = truncate_utf8(&self.command, max_len);

        self.match_info.as_ref().map_or_else(
            || format!("{decision_str} ({duration_str}) {command_preview}"),
            |info| {
                let rule_id = info.rule_id.as_deref().unwrap_or("unknown");
                let reason = &info.reason;
                format!("{decision_str} {rule_id} ({duration_str}) {command_preview} — {reason}")
            },
        )
    }

    /// Get the reason for the decision (from match info).
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.match_info.as_ref().map(|m| m.reason.as_str())
    }

    /// Format the trace as human-readable pretty output.
    ///
    /// This format is optimized for answering:
    /// - What was the decision?
    /// - What matched (rule id) and where?
    /// - Which stages were run and how long did they take?
    /// - What can I do next (safe alternatives, allowlist command)?
    ///
    /// Set `use_color` to enable ANSI color codes for terminal output.
    #[must_use]
    pub fn format_pretty(&self, use_color: bool) -> String {
        let mut out = String::with_capacity(1024);

        // Color helpers
        let (bold, reset, green, red, yellow, cyan, dim) = if use_color {
            ("\x1b[1m", "\x1b[0m", "\x1b[32m", "\x1b[31m", "\x1b[33m", "\x1b[36m", "\x1b[2m")
        } else {
            ("", "", "", "", "", "", "")
        };

        // ═══════════════════════════════════════════════════════════════════
        // HEADER
        // ═══════════════════════════════════════════════════════════════════
        out.push_str(&format!("{bold}══════════════════════════════════════════════════════════════════{reset}\n"));
        out.push_str(&format!("{bold}DCG EXPLAIN{reset}\n"));
        out.push_str(&format!("{bold}══════════════════════════════════════════════════════════════════{reset}\n\n"));

        // Decision with color
        let decision_str = match self.decision {
            EvaluationDecision::Allow => format!("{green}{bold}ALLOW{reset}"),
            EvaluationDecision::Deny => format!("{red}{bold}DENY{reset}"),
        };
        out.push_str(&format!("{bold}Decision:{reset} {decision_str}\n"));
        out.push_str(&format!("{bold}Latency:{reset}  {}\n", format_duration(self.total_duration_us)));
        out.push('\n');

        // ═══════════════════════════════════════════════════════════════════
        // COMMAND
        // ═══════════════════════════════════════════════════════════════════
        out.push_str(&format!("{bold}─── Command ───────────────────────────────────────────────────────{reset}\n"));
        out.push_str(&format!("{cyan}Input:{reset}      {}\n", &self.command));

        if let Some(ref normalized) = self.normalized_command {
            if normalized != &self.command {
                out.push_str(&format!("{cyan}Normalized:{reset} {normalized}\n"));
            }
        }

        if let Some(ref sanitized) = self.sanitized_command {
            if sanitized != &self.command && Some(sanitized) != self.normalized_command.as_ref() {
                out.push_str(&format!("{cyan}Sanitized:{reset}  {sanitized}\n"));
            }
        }
        out.push('\n');

        // ═══════════════════════════════════════════════════════════════════
        // MATCH INFO (for denials or allowlisted commands)
        // ═══════════════════════════════════════════════════════════════════
        if let Some(ref info) = self.match_info {
            out.push_str(&format!("{bold}─── Match ─────────────────────────────────────────────────────────{reset}\n"));

            if let Some(ref rule_id) = info.rule_id {
                out.push_str(&format!("{cyan}Rule ID:{reset}    {yellow}{rule_id}{reset}\n"));
            }

            if let Some(ref pack_id) = info.pack_id {
                out.push_str(&format!("{cyan}Pack:{reset}       {pack_id}\n"));
            }

            if let Some(ref pattern) = info.pattern_name {
                out.push_str(&format!("{cyan}Pattern:{reset}    {pattern}\n"));
            }

            out.push_str(&format!("{cyan}Reason:{reset}     {}\n", info.reason));

            // Show matched span if available
            if let (Some(start), Some(end)) = (info.match_start, info.match_end) {
                out.push_str(&format!("{cyan}Span:{reset}       bytes {start}..{end}\n"));

                // Show matched text with highlighting
                if let Some(ref preview) = info.matched_text_preview {
                    out.push_str(&format!("{cyan}Matched:{reset}    {red}{preview}{reset}\n"));
                }
            }
            out.push('\n');
        }

        // ═══════════════════════════════════════════════════════════════════
        // ALLOWLIST OVERRIDE
        // ═══════════════════════════════════════════════════════════════════
        if let Some(ref al_info) = self.allowlist_info {
            out.push_str(&format!("{bold}─── Allowlist Override ────────────────────────────────────────────{reset}\n"));
            out.push_str(&format!("{cyan}Layer:{reset}      {:?}\n", al_info.layer));
            out.push_str(&format!("{cyan}Reason:{reset}     {}\n", al_info.entry_reason));

            // Show what was overridden
            out.push_str(&format!("{dim}(Overrode {}: {}){reset}\n",
                al_info.original_match.rule_id.as_deref().unwrap_or("unknown"),
                al_info.original_match.reason
            ));
            out.push('\n');
        }

        // ═══════════════════════════════════════════════════════════════════
        // PACK SUMMARY
        // ═══════════════════════════════════════════════════════════════════
        if let Some(ref summary) = self.pack_summary {
            out.push_str(&format!("{bold}─── Pack Evaluation ───────────────────────────────────────────────{reset}\n"));
            out.push_str(&format!("{cyan}Enabled:{reset}    {} packs\n", summary.enabled_count));

            if !summary.evaluated.is_empty() {
                out.push_str(&format!("{cyan}Evaluated:{reset}  {}\n", summary.evaluated.join(", ")));
            }

            if !summary.skipped.is_empty() {
                out.push_str(&format!("{dim}Skipped (keyword gating): {}{reset}\n", summary.skipped.join(", ")));
            }
            out.push('\n');
        }

        // ═══════════════════════════════════════════════════════════════════
        // PIPELINE TRACE (steps)
        // ═══════════════════════════════════════════════════════════════════
        if !self.steps.is_empty() {
            out.push_str(&format!("{bold}─── Pipeline Trace ────────────────────────────────────────────────{reset}\n"));

            for step in &self.steps {
                let duration_str = format_duration(step.duration_us);
                let details_summary = format_step_details_summary(&step.details);

                out.push_str(&format!(
                    "{cyan}{:<18}{reset} {dim}({:>8}){reset} {}\n",
                    step.name, duration_str, details_summary
                ));
            }
            out.push('\n');
        }

        // ═══════════════════════════════════════════════════════════════════
        // SUGGESTIONS
        // ═══════════════════════════════════════════════════════════════════
        if let Some(ref info) = self.match_info {
            if let Some(rule_id) = info.rule_id.as_deref() {
                if let Some(suggestions) = crate::suggestions::get_suggestions(rule_id) {
                    if !suggestions.is_empty() {
                        out.push_str(&format!("{bold}─── Suggestions ───────────────────────────────────────────────────{reset}\n"));

                        for s in suggestions {
                            out.push_str(&format!("{yellow}• {}{reset}: {}\n", s.kind.label(), s.text));
                            if let Some(ref cmd) = s.command {
                                out.push_str(&format!("  {dim}${reset} {green}{cmd}{reset}\n"));
                            }
                            if let Some(ref url) = s.url {
                                out.push_str(&format!("  {dim}→ {url}{reset}\n"));
                            }
                        }
                        out.push('\n');
                    }
                }
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        // FOOTER
        // ═══════════════════════════════════════════════════════════════════
        out.push_str(&format!("{bold}══════════════════════════════════════════════════════════════════{reset}\n"));

        out
    }
}

/// Format a one-line summary of step details.
fn format_step_details_summary(details: &TraceDetails) -> String {
    match details {
        TraceDetails::InputParsing { is_hook_input, command_len } => {
            let source = if *is_hook_input { "hook" } else { "CLI" };
            format!("source={source}, len={command_len}")
        }
        TraceDetails::KeywordGating { quick_rejected, first_match, .. } => {
            if *quick_rejected {
                "quick-rejected (no keywords)".to_string()
            } else if let Some(kw) = first_match {
                format!("matched keyword \"{kw}\"")
            } else {
                "no match".to_string()
            }
        }
        TraceDetails::Normalization { was_modified, stripped_prefix } => {
            if *was_modified {
                if let Some(prefix) = stripped_prefix {
                    format!("stripped \"{prefix}\"")
                } else {
                    "modified".to_string()
                }
            } else {
                "no change".to_string()
            }
        }
        TraceDetails::Sanitization { was_modified, spans_masked } => {
            if *was_modified {
                format!("masked {spans_masked} span(s)")
            } else {
                "no change".to_string()
            }
        }
        TraceDetails::HeredocDetection { triggered, scripts_extracted, languages } => {
            if *triggered {
                let langs = if languages.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", languages.join(", "))
                };
                format!("extracted {scripts_extracted} script(s){langs}")
            } else {
                "no heredocs".to_string()
            }
        }
        TraceDetails::AllowlistCheck { layers_checked, matched, matched_layer } => {
            if *matched {
                format!("hit at {:?}", matched_layer.as_ref().unwrap_or(&AllowlistLayer::System))
            } else {
                format!("checked {layers_checked} layer(s), no match")
            }
        }
        TraceDetails::PackEvaluation { packs_evaluated, matched_pack, matched_pattern, .. } => {
            if let (Some(pack), Some(pattern)) = (matched_pack, matched_pattern) {
                format!("matched {pack}:{pattern}")
            } else {
                format!("checked {} pack(s), no match", packs_evaluated.len())
            }
        }
        TraceDetails::ConfigOverride { allow_matched, block_matched, reason } => {
            if *block_matched {
                format!("BLOCK: {}", reason.as_deref().unwrap_or("config override"))
            } else if *allow_matched {
                "ALLOW: config override".to_string()
            } else {
                "no override".to_string()
            }
        }
        TraceDetails::PolicyDecision { decision, allowlisted } => {
            let dec = match decision {
                EvaluationDecision::Allow => "ALLOW",
                EvaluationDecision::Deny => "DENY",
            };
            if *allowlisted {
                format!("{dec} (allowlisted)")
            } else {
                dec.to_string()
            }
        }
    }
}

/// Format a duration in microseconds as a human-readable string.
///
/// - Under 1000us: "847us"
/// - 1000us to 9999us: "1.2ms" (one decimal place)
/// - 10000us to 999999us: "10ms" (no decimal)
/// - 1000000us+: "1.5s" (one decimal place)
#[must_use]
pub fn format_duration(us: u64) -> String {
    if us < 1000 {
        format!("{us}us")
    } else if us < 1_000_000 {
        if us < 10_000 {
            // 0.1ms == 100us (rounded to nearest tenth)
            let tenths_ms = us.saturating_add(50) / 100;
            let whole = tenths_ms / 10;
            let frac = tenths_ms % 10;
            format!("{whole}.{frac}ms")
        } else {
            let ms = us / 1000;
            format!("{ms}ms")
        }
    } else {
        // 0.1s == 100_000us (rounded to nearest tenth)
        let tenths_s = us.saturating_add(50_000) / 100_000;
        let whole = tenths_s / 10;
        let frac = tenths_s % 10;
        format!("{whole}.{frac}s")
    }
}

/// Truncate a string to at most `max_len` characters, ensuring UTF-8 safety.
///
/// If truncation is needed, appends "..." and ensures the result is at most `max_len` chars.
/// Never breaks in the middle of a multi-byte UTF-8 character.
#[must_use]
pub fn truncate_utf8(s: &str, max_len: usize) -> String {
    if max_len < 4 {
        // Too short for meaningful truncation with "..."
        return s.chars().take(max_len).collect();
    }

    let char_count = s.chars().count();
    if char_count <= max_len {
        return s.to_string();
    }

    // Leave room for "..."
    let truncate_at = max_len.saturating_sub(3);
    let mut result: String = s.chars().take(truncate_at).collect();
    result.push_str("...");
    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_collector_basic_flow() {
        let mut collector = TraceCollector::new("git reset --hard");

        collector.begin_step();
        std::thread::sleep(std::time::Duration::from_micros(10));
        collector.end_step(
            "keyword_gating",
            TraceDetails::KeywordGating {
                quick_rejected: false,
                keywords_checked: vec!["git".to_string()],
                first_match: Some("git".to_string()),
            },
        );

        collector.set_normalized("git reset --hard");
        collector.set_match(MatchInfo {
            rule_id: Some("core.git:reset-hard".to_string()),
            pack_id: Some("core.git".to_string()),
            pattern_name: Some("reset-hard".to_string()),
            reason: "destroys uncommitted changes".to_string(),
            source: MatchSource::Pack,
            match_start: Some(0),
            match_end: Some(15),
            matched_text_preview: Some("git reset --hard".to_string()),
        });

        let trace = collector.finish(EvaluationDecision::Deny);

        assert_eq!(trace.decision, EvaluationDecision::Deny);
        assert_eq!(trace.command, "git reset --hard");
        assert!(trace.total_duration_us > 0);
        assert_eq!(trace.steps.len(), 1);
        assert_eq!(trace.steps[0].name, "keyword_gating");
        assert!(trace.match_info.is_some());
        assert_eq!(trace.rule_id(), Some("core.git:reset-hard"));
    }

    #[test]
    fn trace_collector_allowed_flow() {
        let mut collector = TraceCollector::new("git status");

        collector.begin_step();
        collector.end_step(
            "keyword_gating",
            TraceDetails::KeywordGating {
                quick_rejected: false,
                keywords_checked: vec!["git".to_string()],
                first_match: Some("git".to_string()),
            },
        );

        let trace = collector.finish(EvaluationDecision::Allow);

        assert_eq!(trace.decision, EvaluationDecision::Allow);
        assert!(trace.match_info.is_none());
        assert!(!trace.was_allowlisted());
    }

    #[test]
    fn trace_collector_allowlist_override() {
        let mut collector = TraceCollector::new("git reset --hard");

        let original_match = MatchInfo {
            rule_id: Some("core.git:reset-hard".to_string()),
            pack_id: Some("core.git".to_string()),
            pattern_name: Some("reset-hard".to_string()),
            reason: "destroys uncommitted changes".to_string(),
            source: MatchSource::Pack,
            match_start: Some(0),
            match_end: Some(15),
            matched_text_preview: Some("git reset --hard".to_string()),
        };

        collector.set_allowlist(AllowlistInfo {
            layer: AllowlistLayer::Project,
            entry_reason: "Allowed for release automation".to_string(),
            original_match,
        });

        let trace = collector.finish(EvaluationDecision::Allow);

        assert_eq!(trace.decision, EvaluationDecision::Allow);
        assert!(trace.was_allowlisted());
        assert!(trace.allowlist_info.is_some());
        assert_eq!(
            trace.allowlist_info.as_ref().unwrap().layer,
            AllowlistLayer::Project
        );
    }

    #[test]
    fn trace_step_ordering_preserved() {
        let mut collector = TraceCollector::new("test");

        collector.record_step(
            "step1",
            10,
            TraceDetails::InputParsing {
                is_hook_input: false,
                command_len: 4,
            },
        );
        collector.record_step(
            "step2",
            20,
            TraceDetails::KeywordGating {
                quick_rejected: true,
                keywords_checked: vec![],
                first_match: None,
            },
        );
        collector.record_step(
            "step3",
            30,
            TraceDetails::PolicyDecision {
                decision: EvaluationDecision::Allow,
                allowlisted: false,
            },
        );

        let trace = collector.finish(EvaluationDecision::Allow);

        assert_eq!(trace.steps.len(), 3);
        assert_eq!(trace.steps[0].name, "step1");
        assert_eq!(trace.steps[1].name, "step2");
        assert_eq!(trace.steps[2].name, "step3");
        assert_eq!(trace.steps[0].duration_us, 10);
        assert_eq!(trace.steps[1].duration_us, 20);
        assert_eq!(trace.steps[2].duration_us, 30);
    }

    #[test]
    fn trace_find_step() {
        let mut collector = TraceCollector::new("test");

        collector.record_step(
            "keyword_gating",
            10,
            TraceDetails::KeywordGating {
                quick_rejected: false,
                keywords_checked: vec!["git".to_string()],
                first_match: Some("git".to_string()),
            },
        );

        let trace = collector.finish(EvaluationDecision::Allow);

        assert!(trace.find_step("keyword_gating").is_some());
        assert!(trace.find_step("nonexistent").is_none());
    }

    #[test]
    fn match_info_captures_span() {
        let info = MatchInfo {
            rule_id: Some("test:pattern".to_string()),
            pack_id: Some("test".to_string()),
            pattern_name: Some("pattern".to_string()),
            reason: "test reason".to_string(),
            source: MatchSource::Pack,
            match_start: Some(10),
            match_end: Some(25),
            matched_text_preview: Some("matched text".to_string()),
        };

        assert_eq!(info.match_start, Some(10));
        assert_eq!(info.match_end, Some(25));
        assert_eq!(info.matched_text_preview, Some("matched text".to_string()));
    }

    #[test]
    fn pack_summary_tracks_evaluation() {
        let summary = PackSummary {
            enabled_count: 5,
            evaluated: vec!["core.git".to_string(), "core.filesystem".to_string()],
            skipped: vec!["containers.docker".to_string()],
        };

        assert_eq!(summary.enabled_count, 5);
        assert_eq!(summary.evaluated.len(), 2);
        assert_eq!(summary.skipped.len(), 1);
    }

    // ========================================================================
    // Compact formatter tests
    // ========================================================================

    #[test]
    fn format_duration_microseconds() {
        assert_eq!(format_duration(0), "0us");
        assert_eq!(format_duration(1), "1us");
        assert_eq!(format_duration(94), "94us");
        assert_eq!(format_duration(847), "847us");
        assert_eq!(format_duration(999), "999us");
    }

    #[test]
    fn format_duration_milliseconds() {
        assert_eq!(format_duration(1000), "1.0ms");
        assert_eq!(format_duration(1200), "1.2ms");
        assert_eq!(format_duration(1500), "1.5ms");
        assert_eq!(format_duration(9999), "10.0ms"); // 9.999ms rounds to 10.0ms (still in decimal range)
        assert_eq!(format_duration(10000), "10ms");
        assert_eq!(format_duration(100_000), "100ms");
        assert_eq!(format_duration(999_999), "999ms"); // 999.999ms truncates to 999ms
    }

    #[test]
    fn format_duration_seconds() {
        assert_eq!(format_duration(1_000_000), "1.0s");
        assert_eq!(format_duration(1_500_000), "1.5s");
        assert_eq!(format_duration(10_000_000), "10.0s");
    }

    #[test]
    fn truncate_utf8_no_truncation_needed() {
        assert_eq!(truncate_utf8("hello", 10), "hello");
        assert_eq!(truncate_utf8("hello", 5), "hello");
        assert_eq!(truncate_utf8("", 10), "");
    }

    #[test]
    fn truncate_utf8_basic_truncation() {
        assert_eq!(truncate_utf8("hello world", 8), "hello...");
        assert_eq!(
            truncate_utf8("git reset --hard HEAD~5", 15),
            "git reset --..."
        );
    }

    #[test]
    fn truncate_utf8_unicode_safe() {
        // Japanese "hello" - each character is one char in Rust
        let japanese = "こんにちは世界";
        assert_eq!(truncate_utf8(japanese, 7), "こんにちは世界");
        assert_eq!(truncate_utf8(japanese, 6), "こんに...");

        // Emoji test - when max_len < 4, we can't fit "..." so we just truncate
        let emoji = "🎉🎊🎁🎂";
        assert_eq!(truncate_utf8(emoji, 4), "🎉🎊🎁🎂"); // Exact fit, no truncation
        assert_eq!(truncate_utf8(emoji, 3), "🎉🎊🎁"); // max_len < 4, no room for "..."
        assert_eq!(truncate_utf8(emoji, 5), "🎉🎊🎁🎂"); // Fits without truncation (4 chars < 5)

        // More emojis to test actual truncation
        let more_emoji = "🎉🎊🎁🎂🎈🎀";
        assert_eq!(truncate_utf8(more_emoji, 5), "🎉🎊...");
    }

    #[test]
    fn truncate_utf8_very_short_max() {
        assert_eq!(truncate_utf8("hello", 3), "hel");
        assert_eq!(truncate_utf8("hello", 2), "he");
        assert_eq!(truncate_utf8("hello", 1), "h");
        assert_eq!(truncate_utf8("hello", 0), "");
    }

    #[test]
    fn format_compact_allow() {
        let mut collector = TraceCollector::new("git status");
        collector.record_step(
            "test",
            94,
            TraceDetails::PolicyDecision {
                decision: EvaluationDecision::Allow,
                allowlisted: false,
            },
        );

        let trace = ExplainTrace {
            command: "git status".to_string(),
            normalized_command: None,
            sanitized_command: None,
            decision: EvaluationDecision::Allow,
            total_duration_us: 94,
            steps: vec![],
            match_info: None,
            allowlist_info: None,
            pack_summary: None,
        };

        let compact = trace.format_compact(None);
        assert_eq!(compact, "ALLOW (94us) git status");
    }

    #[test]
    fn format_compact_deny() {
        let trace = ExplainTrace {
            command: "git reset --hard".to_string(),
            normalized_command: None,
            sanitized_command: None,
            decision: EvaluationDecision::Deny,
            total_duration_us: 847,
            steps: vec![],
            match_info: Some(MatchInfo {
                rule_id: Some("core.git:reset-hard".to_string()),
                pack_id: Some("core.git".to_string()),
                pattern_name: Some("reset-hard".to_string()),
                reason: "destroys uncommitted changes".to_string(),
                source: MatchSource::Pack,
                match_start: None,
                match_end: None,
                matched_text_preview: None,
            }),
            allowlist_info: None,
            pack_summary: None,
        };

        let compact = trace.format_compact(None);
        assert_eq!(
            compact,
            "DENY core.git:reset-hard (847us) git reset --hard — destroys uncommitted changes"
        );
    }

    #[test]
    fn format_compact_long_command_truncated() {
        let long_cmd =
            "git commit -m 'This is a very long commit message that should be truncated'";
        let trace = ExplainTrace {
            command: long_cmd.to_string(),
            normalized_command: None,
            sanitized_command: None,
            decision: EvaluationDecision::Allow,
            total_duration_us: 1200,
            steps: vec![],
            match_info: None,
            allowlist_info: None,
            pack_summary: None,
        };

        let compact = trace.format_compact(Some(40));
        assert!(compact.contains("..."));
        assert!(compact.starts_with("ALLOW (1.2ms)"));
    }

    #[test]
    fn format_compact_deny_milliseconds() {
        let trace = ExplainTrace {
            command: "docker system prune -af".to_string(),
            normalized_command: None,
            sanitized_command: None,
            decision: EvaluationDecision::Deny,
            total_duration_us: 1_500,
            steps: vec![],
            match_info: Some(MatchInfo {
                rule_id: Some("containers.docker:system-prune".to_string()),
                pack_id: Some("containers.docker".to_string()),
                pattern_name: Some("system-prune".to_string()),
                reason: "removes all unused data".to_string(),
                source: MatchSource::Pack,
                match_start: None,
                match_end: None,
                matched_text_preview: None,
            }),
            allowlist_info: None,
            pack_summary: None,
        };

        let compact = trace.format_compact(None);
        assert_eq!(
            compact,
            "DENY containers.docker:system-prune (1.5ms) docker system prune -af — removes all unused data"
        );
    }
}
