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
use crate::packs::Severity;
use serde::Serialize;
use std::time::Instant;

/// Current JSON schema version for explain output.
/// JSON schema version for `dcg explain --format json`.
/// v2 adds `matched_span`, `matched_text_preview`, and `explanation` in `match`.
pub const EXPLAIN_JSON_SCHEMA_VERSION: u32 = 2;

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
    /// Whether evaluation was skipped due to time budget exhaustion.
    pub skipped_due_to_budget: bool,
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
    /// Severity level of the matched pattern.
    pub severity: Option<Severity>,
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
    /// Detailed explanation of why the match is dangerous (optional).
    pub explanation: Option<String>,
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
    /// Whether evaluation skipped deeper analysis due to a budget overrun.
    skipped_due_to_budget: bool,
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
            skipped_due_to_budget: false,
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

    /// Mark whether evaluation skipped deeper analysis due to budget.
    pub const fn set_budget_skip(&mut self, skipped: bool) {
        self.skipped_due_to_budget = skipped;
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
            skipped_due_to_budget: self.skipped_due_to_budget,
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
    /// - `DENY containers.docker:system-prune (1.2ms) docker system prune -af — removes all unused data`
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
    #[allow(clippy::too_many_lines, clippy::format_push_string)]
    pub fn format_pretty(&self, use_color: bool) -> String {
        let mut out = String::with_capacity(1024);

        // Color helpers
        let (bold, reset, green, red, yellow, cyan, dim) = if use_color {
            (
                "\x1b[1m", "\x1b[0m", "\x1b[32m", "\x1b[31m", "\x1b[33m", "\x1b[36m", "\x1b[2m",
            )
        } else {
            ("", "", "", "", "", "", "")
        };

        // ═══════════════════════════════════════════════════════════════════
        // HEADER
        // ═══════════════════════════════════════════════════════════════════
        out.push_str(&format!(
            "{bold}══════════════════════════════════════════════════════════════════{reset}\n"
        ));
        out.push_str(&format!("{bold}DCG EXPLAIN{reset}\n"));
        out.push_str(&format!(
            "{bold}══════════════════════════════════════════════════════════════════{reset}\n\n"
        ));

        // Decision with color
        let decision_str = match self.decision {
            EvaluationDecision::Allow => format!("{green}{bold}ALLOW{reset}"),
            EvaluationDecision::Deny => format!("{red}{bold}DENY{reset}"),
        };
        out.push_str(&format!("{bold}Decision:{reset} {decision_str}\n"));
        out.push_str(&format!(
            "{bold}Latency:{reset}  {}\n",
            format_duration(self.total_duration_us)
        ));
        out.push('\n');

        // ═══════════════════════════════════════════════════════════════════
        // COMMAND
        // ═══════════════════════════════════════════════════════════════════
        out.push_str(&format!(
            "{bold}─── Command ───────────────────────────────────────────────────────{reset}\n"
        ));
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
            out.push_str(&format!(
                "{bold}─── Match ─────────────────────────────────────────────────────────{reset}\n"
            ));

            if let Some(ref rule_id) = info.rule_id {
                out.push_str(&format!(
                    "{cyan}Rule ID:{reset}    {yellow}{rule_id}{reset}\n"
                ));
            }

            if let Some(ref pack_id) = info.pack_id {
                out.push_str(&format!("{cyan}Pack:{reset}       {pack_id}\n"));
            }

            if let Some(ref pattern) = info.pattern_name {
                out.push_str(&format!("{cyan}Pattern:{reset}    {pattern}\n"));
            }

            out.push_str(&format!("{cyan}Reason:{reset}     {}\n", info.reason));

            let explanation = info.explanation_or_fallback();
            let mut lines = explanation.lines();
            if let Some(first) = lines.next() {
                out.push_str(&format!("{cyan}Explanation:{reset} {first}\n"));
                let indent = " ".repeat("Explanation: ".len());
                for line in lines {
                    out.push_str(&format!("{dim}{indent}{reset}{line}\n"));
                }
            }

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
            out.push_str(&format!(
                "{bold}─── Allowlist Override ────────────────────────────────────────────{reset}\n"
            ));
            out.push_str(&format!("{cyan}Layer:{reset}      {:?}\n", al_info.layer));
            out.push_str(&format!(
                "{cyan}Reason:{reset}     {}\n",
                al_info.entry_reason
            ));

            // Show what was overridden
            out.push_str(&format!(
                "{dim}(Overrode {}: {}){reset}\n",
                al_info
                    .original_match
                    .rule_id
                    .as_deref()
                    .unwrap_or("unknown"),
                al_info.original_match.reason
            ));
            out.push('\n');
        }

        // ═══════════════════════════════════════════════════════════════════
        // PACK SUMMARY
        // ═══════════════════════════════════════════════════════════════════
        if let Some(ref summary) = self.pack_summary {
            out.push_str(&format!(
                "{bold}─── Pack Evaluation ───────────────────────────────────────────────{reset}\n"
            ));
            out.push_str(&format!(
                "{cyan}Enabled:{reset}    {} packs\n",
                summary.enabled_count
            ));

            if !summary.evaluated.is_empty() {
                out.push_str(&format!(
                    "{cyan}Evaluated:{reset}  {}\n",
                    summary.evaluated.join(", ")
                ));
            }

            if !summary.skipped.is_empty() {
                out.push_str(&format!(
                    "{dim}Skipped (keyword gating): {}{reset}\n",
                    summary.skipped.join(", ")
                ));
            }
            out.push('\n');
        }

        // ═══════════════════════════════════════════════════════════════════
        // PIPELINE TRACE (steps)
        // ═══════════════════════════════════════════════════════════════════
        if !self.steps.is_empty() {
            out.push_str(&format!(
                "{bold}─── Pipeline Trace ────────────────────────────────────────────────{reset}\n"
            ));

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
                            out.push_str(&format!(
                                "{yellow}• {}{reset}: {}\n",
                                s.kind.label(),
                                s.text
                            ));
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
        out.push_str(&format!(
            "{bold}══════════════════════════════════════════════════════════════════{reset}\n"
        ));

        out
    }

    /// Format the trace as JSON output.
    ///
    /// Returns a stable, versioned JSON representation suitable for:
    /// - CI/CD tooling
    /// - Bug reports
    /// - Snapshot testing
    ///
    /// The JSON includes `schema_version` for forward compatibility.
    /// Field ordering is stable (follows struct definition order).
    #[must_use]
    pub fn format_json(&self) -> String {
        let json_output = self.to_json_output();
        // Use pretty printing for human readability
        serde_json::to_string_pretty(&json_output)
            .unwrap_or_else(|e| format!("{{\"error\": \"JSON serialization failed: {e}\"}}"))
    }

    /// Convert to JSON-serializable output structure.
    #[must_use]
    pub fn to_json_output(&self) -> ExplainJsonOutput {
        // Collect suggestions from registry if we have a rule_id
        let suggestions: Vec<JsonSuggestion> = self
            .match_info
            .as_ref()
            .and_then(|m| m.rule_id.as_deref())
            .and_then(crate::suggestions::get_suggestions)
            .map(|slist| {
                slist
                    .iter()
                    .map(|s| JsonSuggestion {
                        kind: s.kind.label().to_string(),
                        text: s.text.clone(),
                        command: s.command.clone(),
                        url: s.url.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        ExplainJsonOutput {
            schema_version: EXPLAIN_JSON_SCHEMA_VERSION,
            command: self.command.clone(),
            normalized_command: self.normalized_command.clone(),
            sanitized_command: self.sanitized_command.clone(),
            decision: match self.decision {
                EvaluationDecision::Allow => "allow".to_string(),
                EvaluationDecision::Deny => "deny".to_string(),
            },
            skipped_due_to_budget: self.skipped_due_to_budget.then_some(true),
            total_duration_us: self.total_duration_us,
            steps: self.steps.iter().map(TraceStep::to_json).collect(),
            match_info: self.match_info.as_ref().map(MatchInfo::to_json),
            allowlist: self.allowlist_info.as_ref().map(AllowlistInfo::to_json),
            pack_summary: self.pack_summary.as_ref().map(PackSummary::to_json),
            suggestions: if suggestions.is_empty() {
                None
            } else {
                Some(suggestions)
            },
        }
    }
}

// ============================================================================
// JSON Output Structures (versioned, stable schema)
// ============================================================================

/// Top-level JSON output structure for `dcg explain --format json`.
#[derive(Debug, Clone, Serialize)]
pub struct ExplainJsonOutput {
    /// Schema version for forward compatibility.
    pub schema_version: u32,
    /// Original command.
    pub command: String,
    /// Normalized command (if different from original).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalized_command: Option<String>,
    /// Sanitized command (if different from original).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sanitized_command: Option<String>,
    /// Decision: "allow" or "deny".
    pub decision: String,
    /// Whether evaluation was skipped due to time budget exhaustion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped_due_to_budget: Option<bool>,
    /// Total evaluation time in microseconds.
    pub total_duration_us: u64,
    /// Pipeline steps in chronological order.
    pub steps: Vec<JsonTraceStep>,
    /// Match information (if command matched a pattern).
    #[serde(rename = "match", skip_serializing_if = "Option::is_none")]
    pub match_info: Option<JsonMatchInfo>,
    /// Allowlist override information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowlist: Option<JsonAllowlistInfo>,
    /// Pack evaluation summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pack_summary: Option<JsonPackSummary>,
    /// Actionable suggestions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestions: Option<Vec<JsonSuggestion>>,
}

/// JSON representation of a trace step.
#[derive(Debug, Clone, Serialize)]
pub struct JsonTraceStep {
    /// Step name.
    pub name: String,
    /// Step duration in microseconds.
    pub duration_us: u64,
    /// Step-specific details.
    pub details: JsonTraceDetails,
}

/// JSON representation of step details (tagged union).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum JsonTraceDetails {
    InputParsing {
        is_hook_input: bool,
        command_len: usize,
    },
    KeywordGating {
        quick_rejected: bool,
        keywords_checked: Vec<String>,
        first_match: Option<String>,
    },
    Normalization {
        was_modified: bool,
        stripped_prefix: Option<String>,
    },
    Sanitization {
        was_modified: bool,
        spans_masked: usize,
    },
    HeredocDetection {
        triggered: bool,
        scripts_extracted: usize,
        languages: Vec<String>,
    },
    AllowlistCheck {
        layers_checked: usize,
        matched: bool,
        matched_layer: Option<String>,
    },
    PackEvaluation {
        packs_evaluated: Vec<String>,
        packs_skipped: Vec<String>,
        matched_pack: Option<String>,
        matched_pattern: Option<String>,
    },
    ConfigOverride {
        allow_matched: bool,
        block_matched: bool,
        reason: Option<String>,
    },
    PolicyDecision {
        decision: String,
        allowlisted: bool,
    },
}

/// JSON representation of match information.
/// Schema v2 adds `matched_span`, `matched_text_preview`, and `explanation`.
#[derive(Debug, Clone, Serialize)]
pub struct JsonMatchInfo {
    /// Stable rule ID (e.g., "core.git:reset-hard").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Pack ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pack_id: Option<String>,
    /// Pattern name within the pack.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern_name: Option<String>,
    /// Severity level (critical, high, medium, low).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Human-readable reason for the match.
    pub reason: String,
    /// Source of the match.
    pub source: String,
    /// Matched span (byte offsets).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_span: Option<JsonSpan>,
    /// Preview of matched text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_text_preview: Option<String>,
    /// Detailed explanation or fallback text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
}

/// JSON representation of a byte span.
#[derive(Debug, Clone, Serialize)]
pub struct JsonSpan {
    /// Start byte offset.
    pub start: usize,
    /// End byte offset.
    pub end: usize,
}

/// JSON representation of allowlist override.
#[derive(Debug, Clone, Serialize)]
pub struct JsonAllowlistInfo {
    /// Layer that matched.
    pub layer: String,
    /// Reason from the allowlist entry.
    pub entry_reason: String,
    /// Original match that was overridden.
    pub original_match: JsonMatchInfo,
}

/// JSON representation of pack evaluation summary.
#[derive(Debug, Clone, Serialize)]
pub struct JsonPackSummary {
    /// Total enabled packs.
    pub enabled_count: usize,
    /// Packs that were evaluated.
    pub evaluated: Vec<String>,
    /// Packs skipped by keyword gating.
    pub skipped: Vec<String>,
}

/// JSON representation of a suggestion.
#[derive(Debug, Clone, Serialize)]
pub struct JsonSuggestion {
    /// Suggestion kind label.
    pub kind: String,
    /// Suggestion text.
    pub text: String,
    /// Optional command to copy/paste.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Optional documentation URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

// Conversion implementations
impl TraceStep {
    fn to_json(&self) -> JsonTraceStep {
        JsonTraceStep {
            name: self.name.to_string(),
            duration_us: self.duration_us,
            details: self.details.to_json(),
        }
    }
}

impl TraceDetails {
    fn to_json(&self) -> JsonTraceDetails {
        match self {
            Self::InputParsing {
                is_hook_input,
                command_len,
            } => JsonTraceDetails::InputParsing {
                is_hook_input: *is_hook_input,
                command_len: *command_len,
            },
            Self::KeywordGating {
                quick_rejected,
                keywords_checked,
                first_match,
            } => JsonTraceDetails::KeywordGating {
                quick_rejected: *quick_rejected,
                keywords_checked: keywords_checked.clone(),
                first_match: first_match.clone(),
            },
            Self::Normalization {
                was_modified,
                stripped_prefix,
            } => JsonTraceDetails::Normalization {
                was_modified: *was_modified,
                stripped_prefix: stripped_prefix.clone(),
            },
            Self::Sanitization {
                was_modified,
                spans_masked,
            } => JsonTraceDetails::Sanitization {
                was_modified: *was_modified,
                spans_masked: *spans_masked,
            },
            Self::HeredocDetection {
                triggered,
                scripts_extracted,
                languages,
            } => JsonTraceDetails::HeredocDetection {
                triggered: *triggered,
                scripts_extracted: *scripts_extracted,
                languages: languages.clone(),
            },
            Self::AllowlistCheck {
                layers_checked,
                matched,
                matched_layer,
            } => JsonTraceDetails::AllowlistCheck {
                layers_checked: *layers_checked,
                matched: *matched,
                matched_layer: matched_layer.as_ref().map(|l| l.label().to_string()),
            },
            Self::PackEvaluation {
                packs_evaluated,
                packs_skipped,
                matched_pack,
                matched_pattern,
            } => JsonTraceDetails::PackEvaluation {
                packs_evaluated: packs_evaluated.clone(),
                packs_skipped: packs_skipped.clone(),
                matched_pack: matched_pack.clone(),
                matched_pattern: matched_pattern.clone(),
            },
            Self::ConfigOverride {
                allow_matched,
                block_matched,
                reason,
            } => JsonTraceDetails::ConfigOverride {
                allow_matched: *allow_matched,
                block_matched: *block_matched,
                reason: reason.clone(),
            },
            Self::PolicyDecision {
                decision,
                allowlisted,
            } => JsonTraceDetails::PolicyDecision {
                decision: match decision {
                    EvaluationDecision::Allow => "allow".to_string(),
                    EvaluationDecision::Deny => "deny".to_string(),
                },
                allowlisted: *allowlisted,
            },
        }
    }
}

impl MatchInfo {
    fn rule_label(&self) -> Option<String> {
        if let Some(rule_id) = self.rule_id.as_ref() {
            return Some(rule_id.clone());
        }

        if let (Some(pack_id), Some(pattern_name)) =
            (self.pack_id.as_deref(), self.pattern_name.as_deref())
        {
            return Some(format!("{pack_id}:{pattern_name}"));
        }

        self.pack_id.clone()
    }

    fn fallback_explanation(&self) -> String {
        self.rule_label().map_or_else(
            || {
                "Matched a destructive pattern. No additional explanation is available yet. \
                 See pack documentation for details."
                    .to_string()
            },
            |label| {
                format!(
                    "Matched destructive pattern {label}. No additional explanation is available \
                     yet. See pack documentation for details."
                )
            },
        )
    }

    fn explanation_or_fallback(&self) -> String {
        self.explanation
            .as_ref()
            .map(|text| text.trim())
            .filter(|text| !text.is_empty())
            .map_or_else(|| self.fallback_explanation(), ToString::to_string)
    }

    fn to_json(&self) -> JsonMatchInfo {
        JsonMatchInfo {
            rule_id: self.rule_id.clone(),
            pack_id: self.pack_id.clone(),
            pattern_name: self.pattern_name.clone(),
            severity: self.severity.map(|s| s.label().to_string()),
            reason: self.reason.clone(),
            source: match self.source {
                MatchSource::Pack => "pack".to_string(),
                MatchSource::ConfigOverride => "config_override".to_string(),
                MatchSource::LegacyPattern => "legacy_pattern".to_string(),
                MatchSource::HeredocAst => "heredoc_ast".to_string(),
            },
            matched_span: match (self.match_start, self.match_end) {
                (Some(start), Some(end)) => Some(JsonSpan { start, end }),
                _ => None,
            },
            matched_text_preview: self.matched_text_preview.clone(),
            explanation: Some(self.explanation_or_fallback()),
        }
    }
}

impl AllowlistInfo {
    fn to_json(&self) -> JsonAllowlistInfo {
        JsonAllowlistInfo {
            layer: self.layer.label().to_string(),
            entry_reason: self.entry_reason.clone(),
            original_match: self.original_match.to_json(),
        }
    }
}

impl PackSummary {
    fn to_json(&self) -> JsonPackSummary {
        JsonPackSummary {
            enabled_count: self.enabled_count,
            evaluated: self.evaluated.clone(),
            skipped: self.skipped.clone(),
        }
    }
}

/// Format a one-line summary of step details.
#[allow(clippy::option_if_let_else)]
#[allow(clippy::too_many_lines)]
fn format_step_details_summary(details: &TraceDetails) -> String {
    match details {
        TraceDetails::InputParsing {
            is_hook_input,
            command_len,
        } => {
            let source = if *is_hook_input { "hook" } else { "CLI" };
            format!("source={source}, len={command_len}")
        }
        TraceDetails::KeywordGating {
            quick_rejected,
            first_match,
            ..
        } => {
            if *quick_rejected {
                "quick-rejected (no keywords)".to_string()
            } else if let Some(kw) = first_match {
                format!("matched keyword \"{kw}\"")
            } else {
                "no match".to_string()
            }
        }
        TraceDetails::Normalization {
            was_modified,
            stripped_prefix,
        } => {
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
        TraceDetails::Sanitization {
            was_modified,
            spans_masked,
        } => {
            if *was_modified {
                format!("masked {spans_masked} span(s)")
            } else {
                "no change".to_string()
            }
        }
        TraceDetails::HeredocDetection {
            triggered,
            scripts_extracted,
            languages,
        } => {
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
        TraceDetails::AllowlistCheck {
            layers_checked,
            matched,
            matched_layer,
        } => {
            if *matched {
                format!(
                    "hit at {:?}",
                    matched_layer.as_ref().unwrap_or(&AllowlistLayer::System)
                )
            } else {
                format!("checked {layers_checked} layer(s), no match")
            }
        }
        TraceDetails::PackEvaluation {
            packs_evaluated,
            matched_pack,
            matched_pattern,
            ..
        } => {
            if let (Some(pack), Some(pattern)) = (matched_pack, matched_pattern) {
                format!("matched {pack}:{pattern}")
            } else {
                format!("checked {} pack(s), no match", packs_evaluated.len())
            }
        }
        TraceDetails::ConfigOverride {
            allow_matched,
            block_matched,
            reason,
        } => {
            if *block_matched {
                format!("BLOCK: {}", reason.as_deref().unwrap_or("config override"))
            } else if *allow_matched {
                "ALLOW: config override".to_string()
            } else {
                "no override".to_string()
            }
        }
        TraceDetails::PolicyDecision {
            decision,
            allowlisted,
        } => {
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
            severity: Some(Severity::Critical),
            reason: "destroys uncommitted changes".to_string(),
            source: MatchSource::Pack,
            match_start: Some(0),
            match_end: Some(15),
            matched_text_preview: Some("git reset --hard".to_string()),
            explanation: None,
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
            severity: Some(Severity::Critical),
            reason: "destroys uncommitted changes".to_string(),
            source: MatchSource::Pack,
            match_start: Some(0),
            match_end: Some(15),
            matched_text_preview: Some("git reset --hard".to_string()),
            explanation: None,
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
            severity: None,
            reason: "test reason".to_string(),
            source: MatchSource::Pack,
            match_start: Some(10),
            match_end: Some(25),
            matched_text_preview: Some("matched text".to_string()),
            explanation: None,
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
            skipped_due_to_budget: false,
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
            skipped_due_to_budget: false,
            total_duration_us: 847,
            steps: vec![],
            match_info: Some(MatchInfo {
                rule_id: Some("core.git:reset-hard".to_string()),
                pack_id: Some("core.git".to_string()),
                pattern_name: Some("reset-hard".to_string()),
                severity: Some(Severity::Critical),
                reason: "destroys uncommitted changes".to_string(),
                source: MatchSource::Pack,
                match_start: None,
                match_end: None,
                matched_text_preview: None,
                explanation: None,
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
            skipped_due_to_budget: false,
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
            skipped_due_to_budget: false,
            total_duration_us: 1_500,
            steps: vec![],
            match_info: Some(MatchInfo {
                rule_id: Some("containers.docker:system-prune".to_string()),
                pack_id: Some("containers.docker".to_string()),
                pattern_name: Some("system-prune".to_string()),
                severity: Some(Severity::High),
                reason: "removes all unused data".to_string(),
                source: MatchSource::Pack,
                match_start: None,
                match_end: None,
                matched_text_preview: None,
                explanation: None,
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

    // ========================================================================
    // Pretty formatter tests
    // ========================================================================

    #[test]
    fn format_pretty_allow_simple() {
        let trace = ExplainTrace {
            command: "git status".to_string(),
            normalized_command: None,
            sanitized_command: None,
            decision: EvaluationDecision::Allow,
            skipped_due_to_budget: false,
            total_duration_us: 94,
            steps: vec![],
            match_info: None,
            allowlist_info: None,
            pack_summary: None,
        };

        let pretty = trace.format_pretty(false);

        // Check key sections are present
        assert!(pretty.contains("DCG EXPLAIN"));
        assert!(pretty.contains("Decision:"));
        assert!(pretty.contains("ALLOW"));
        assert!(pretty.contains("Latency:"));
        assert!(pretty.contains("94us"));
        assert!(pretty.contains("Input:"));
        assert!(pretty.contains("git status"));

        // Should not have match section for allowed commands
        assert!(!pretty.contains("─── Match"));
    }

    #[test]
    fn format_pretty_deny_with_match() {
        let trace = ExplainTrace {
            command: "git reset --hard".to_string(),
            normalized_command: None,
            sanitized_command: None,
            decision: EvaluationDecision::Deny,
            skipped_due_to_budget: false,
            total_duration_us: 847,
            steps: vec![],
            match_info: Some(MatchInfo {
                rule_id: Some("core.git:reset-hard".to_string()),
                pack_id: Some("core.git".to_string()),
                pattern_name: Some("reset-hard".to_string()),
                severity: Some(Severity::Critical),
                reason: "destroys uncommitted changes".to_string(),
                source: MatchSource::Pack,
                match_start: Some(0),
                match_end: Some(16),
                matched_text_preview: Some("git reset --hard".to_string()),
                explanation: None,
            }),
            allowlist_info: None,
            pack_summary: None,
        };

        let pretty = trace.format_pretty(false);

        // Check decision
        assert!(pretty.contains("DENY"));

        // Check match section
        assert!(pretty.contains("─── Match"));
        assert!(pretty.contains("Rule ID:"));
        assert!(pretty.contains("core.git:reset-hard"));
        assert!(pretty.contains("Pack:"));
        assert!(pretty.contains("core.git"));
        assert!(pretty.contains("Pattern:"));
        assert!(pretty.contains("reset-hard"));
        assert!(pretty.contains("Reason:"));
        assert!(pretty.contains("destroys uncommitted changes"));
        assert!(pretty.contains("Explanation:"));
        assert!(pretty.contains("Matched destructive pattern core.git:reset-hard"));
        assert!(pretty.contains("Span:"));
        assert!(pretty.contains("bytes 0..16"));
        assert!(pretty.contains("Matched:"));
        assert!(pretty.contains("git reset --hard"));

        // Check suggestions section (core.git:reset-hard has suggestions)
        assert!(pretty.contains("─── Suggestions"));
    }

    #[test]
    fn format_pretty_with_normalized_command() {
        let trace = ExplainTrace {
            command: "sudo git reset --hard".to_string(),
            normalized_command: Some("git reset --hard".to_string()),
            sanitized_command: None,
            decision: EvaluationDecision::Deny,
            skipped_due_to_budget: false,
            total_duration_us: 1200,
            steps: vec![],
            match_info: Some(MatchInfo {
                rule_id: Some("core.git:reset-hard".to_string()),
                pack_id: Some("core.git".to_string()),
                pattern_name: Some("reset-hard".to_string()),
                severity: Some(Severity::Critical),
                reason: "destroys uncommitted changes".to_string(),
                source: MatchSource::Pack,
                match_start: None,
                match_end: None,
                matched_text_preview: None,
                explanation: None,
            }),
            allowlist_info: None,
            pack_summary: None,
        };

        let pretty = trace.format_pretty(false);

        // Check both input and normalized commands are shown
        assert!(pretty.contains("Input:"));
        assert!(pretty.contains("sudo git reset --hard"));
        assert!(pretty.contains("Normalized:"));
        assert!(pretty.contains("git reset --hard"));
    }

    #[test]
    fn format_pretty_allowlist_override() {
        let original_match = MatchInfo {
            rule_id: Some("core.git:reset-hard".to_string()),
            pack_id: Some("core.git".to_string()),
            pattern_name: Some("reset-hard".to_string()),
            severity: Some(Severity::Critical),
            reason: "destroys uncommitted changes".to_string(),
            source: MatchSource::Pack,
            match_start: None,
            match_end: None,
            matched_text_preview: None,
            explanation: None,
        };

        let trace = ExplainTrace {
            command: "git reset --hard".to_string(),
            normalized_command: None,
            sanitized_command: None,
            decision: EvaluationDecision::Allow,
            skipped_due_to_budget: false,
            total_duration_us: 500,
            steps: vec![],
            match_info: None,
            allowlist_info: Some(AllowlistInfo {
                layer: AllowlistLayer::Project,
                entry_reason: "Allowed for release automation".to_string(),
                original_match,
            }),
            pack_summary: None,
        };

        let pretty = trace.format_pretty(false);

        // Should show allowlist override section
        assert!(pretty.contains("─── Allowlist Override"));
        assert!(pretty.contains("Layer:"));
        assert!(pretty.contains("Project"));
        assert!(pretty.contains("Reason:"));
        assert!(pretty.contains("Allowed for release automation"));
        assert!(pretty.contains("Overrode core.git:reset-hard"));
    }

    #[test]
    fn format_pretty_with_pack_summary() {
        let trace = ExplainTrace {
            command: "git status".to_string(),
            normalized_command: None,
            sanitized_command: None,
            decision: EvaluationDecision::Allow,
            skipped_due_to_budget: false,
            total_duration_us: 100,
            steps: vec![],
            match_info: None,
            allowlist_info: None,
            pack_summary: Some(PackSummary {
                enabled_count: 5,
                evaluated: vec!["core.git".to_string()],
                skipped: vec![
                    "containers.docker".to_string(),
                    "database.postgresql".to_string(),
                ],
            }),
        };

        let pretty = trace.format_pretty(false);

        assert!(pretty.contains("─── Pack Evaluation"));
        assert!(pretty.contains("Enabled:"));
        assert!(pretty.contains("5 packs"));
        assert!(pretty.contains("Evaluated:"));
        assert!(pretty.contains("core.git"));
        assert!(pretty.contains("Skipped (keyword gating)"));
        assert!(pretty.contains("containers.docker"));
    }

    #[test]
    fn format_pretty_with_pipeline_steps() {
        let trace = ExplainTrace {
            command: "git status".to_string(),
            normalized_command: None,
            sanitized_command: None,
            decision: EvaluationDecision::Allow,
            skipped_due_to_budget: false,
            total_duration_us: 200,
            steps: vec![
                TraceStep {
                    name: "keyword_gating",
                    duration_us: 50,
                    details: TraceDetails::KeywordGating {
                        quick_rejected: false,
                        keywords_checked: vec!["git".to_string()],
                        first_match: Some("git".to_string()),
                    },
                },
                TraceStep {
                    name: "pack_evaluation",
                    duration_us: 100,
                    details: TraceDetails::PackEvaluation {
                        packs_evaluated: vec!["core.git".to_string()],
                        packs_skipped: vec![],
                        matched_pack: None,
                        matched_pattern: None,
                    },
                },
                TraceStep {
                    name: "policy_decision",
                    duration_us: 10,
                    details: TraceDetails::PolicyDecision {
                        decision: EvaluationDecision::Allow,
                        allowlisted: false,
                    },
                },
            ],
            match_info: None,
            allowlist_info: None,
            pack_summary: None,
        };

        let pretty = trace.format_pretty(false);

        assert!(pretty.contains("─── Pipeline Trace"));
        assert!(pretty.contains("keyword_gating"));
        assert!(pretty.contains("50us"));
        assert!(pretty.contains("matched keyword \"git\""));
        assert!(pretty.contains("pack_evaluation"));
        assert!(pretty.contains("100us"));
        assert!(pretty.contains("policy_decision"));
        assert!(pretty.contains("ALLOW"));
    }

    #[test]
    fn format_pretty_colors_when_enabled() {
        let trace = ExplainTrace {
            command: "git reset --hard".to_string(),
            normalized_command: None,
            sanitized_command: None,
            decision: EvaluationDecision::Deny,
            skipped_due_to_budget: false,
            total_duration_us: 847,
            steps: vec![],
            match_info: Some(MatchInfo {
                rule_id: Some("core.git:reset-hard".to_string()),
                pack_id: None,
                pattern_name: None,
                severity: Some(Severity::Critical),
                reason: "destroys uncommitted changes".to_string(),
                source: MatchSource::Pack,
                match_start: None,
                match_end: None,
                matched_text_preview: None,
                explanation: None,
            }),
            allowlist_info: None,
            pack_summary: None,
        };

        let with_color = trace.format_pretty(true);
        let without_color = trace.format_pretty(false);

        // Color version should have ANSI codes
        assert!(with_color.contains("\x1b["));
        // Non-color version should not
        assert!(!without_color.contains("\x1b["));

        // Both should have same content
        assert!(with_color.contains("DENY"));
        assert!(without_color.contains("DENY"));
    }

    #[test]
    fn format_step_details_summary_all_variants() {
        // Test each TraceDetails variant produces reasonable summary
        let input_parsing = TraceDetails::InputParsing {
            is_hook_input: true,
            command_len: 42,
        };
        assert_eq!(
            format_step_details_summary(&input_parsing),
            "source=hook, len=42"
        );

        let quick_reject = TraceDetails::KeywordGating {
            quick_rejected: true,
            keywords_checked: vec![],
            first_match: None,
        };
        assert_eq!(
            format_step_details_summary(&quick_reject),
            "quick-rejected (no keywords)"
        );

        let normalization = TraceDetails::Normalization {
            was_modified: true,
            stripped_prefix: Some("sudo ".to_string()),
        };
        assert_eq!(
            format_step_details_summary(&normalization),
            "stripped \"sudo \""
        );

        let sanitization = TraceDetails::Sanitization {
            was_modified: true,
            spans_masked: 3,
        };
        assert_eq!(
            format_step_details_summary(&sanitization),
            "masked 3 span(s)"
        );

        let heredoc = TraceDetails::HeredocDetection {
            triggered: true,
            scripts_extracted: 2,
            languages: vec!["bash".to_string(), "python".to_string()],
        };
        assert_eq!(
            format_step_details_summary(&heredoc),
            "extracted 2 script(s) [bash, python]"
        );

        let allowlist_hit = TraceDetails::AllowlistCheck {
            layers_checked: 2,
            matched: true,
            matched_layer: Some(AllowlistLayer::Project),
        };
        assert_eq!(
            format_step_details_summary(&allowlist_hit),
            "hit at Project"
        );

        let pack_match = TraceDetails::PackEvaluation {
            packs_evaluated: vec!["core.git".to_string()],
            packs_skipped: vec![],
            matched_pack: Some("core.git".to_string()),
            matched_pattern: Some("reset-hard".to_string()),
        };
        assert_eq!(
            format_step_details_summary(&pack_match),
            "matched core.git:reset-hard"
        );

        let config_block = TraceDetails::ConfigOverride {
            allow_matched: false,
            block_matched: true,
            reason: Some("custom block".to_string()),
        };
        assert_eq!(
            format_step_details_summary(&config_block),
            "BLOCK: custom block"
        );

        let policy_allow = TraceDetails::PolicyDecision {
            decision: EvaluationDecision::Allow,
            allowlisted: true,
        };
        assert_eq!(
            format_step_details_summary(&policy_allow),
            "ALLOW (allowlisted)"
        );
    }

    // ========================================================================
    // JSON formatter tests
    // ========================================================================

    #[test]
    fn format_json_has_schema_version() {
        let trace = ExplainTrace {
            command: "git status".to_string(),
            normalized_command: None,
            sanitized_command: None,
            decision: EvaluationDecision::Allow,
            skipped_due_to_budget: false,
            total_duration_us: 94,
            steps: vec![],
            match_info: None,
            allowlist_info: None,
            pack_summary: None,
        };

        let json = trace.format_json();
        assert!(json.contains("\"schema_version\": 2"));
        assert!(json.contains("\"decision\": \"allow\""));
        assert!(json.contains("\"command\": \"git status\""));
        assert!(json.contains("\"total_duration_us\": 94"));
    }

    #[test]
    fn format_json_includes_budget_skip_marker() {
        let trace = ExplainTrace {
            command: "git status".to_string(),
            normalized_command: None,
            sanitized_command: None,
            decision: EvaluationDecision::Allow,
            skipped_due_to_budget: true,
            total_duration_us: 10,
            steps: vec![],
            match_info: None,
            allowlist_info: None,
            pack_summary: None,
        };

        let json = trace.format_json();
        assert!(json.contains("\"skipped_due_to_budget\": true"));
    }

    #[test]
    fn format_json_deny_includes_match_info() {
        let trace = ExplainTrace {
            command: "git reset --hard".to_string(),
            normalized_command: None,
            sanitized_command: None,
            decision: EvaluationDecision::Deny,
            skipped_due_to_budget: false,
            total_duration_us: 847,
            steps: vec![],
            match_info: Some(MatchInfo {
                rule_id: Some("core.git:reset-hard".to_string()),
                pack_id: Some("core.git".to_string()),
                pattern_name: Some("reset-hard".to_string()),
                severity: Some(Severity::Critical),
                reason: "destroys uncommitted changes".to_string(),
                source: MatchSource::Pack,
                match_start: Some(0),
                match_end: Some(16),
                matched_text_preview: Some("git reset --hard".to_string()),
                explanation: None,
            }),
            allowlist_info: None,
            pack_summary: None,
        };

        let json = trace.format_json();

        // Check decision
        assert!(json.contains("\"decision\": \"deny\""));

        // Check match
        assert!(json.contains("\"match\":"));
        assert!(json.contains("\"rule_id\": \"core.git:reset-hard\""));
        assert!(json.contains("\"pack_id\": \"core.git\""));
        assert!(json.contains("\"pattern_name\": \"reset-hard\""));
        assert!(json.contains("\"reason\": \"destroys uncommitted changes\""));
        assert!(json.contains("\"source\": \"pack\""));
        assert!(json.contains("\"explanation\":"));
        assert!(json.contains("Matched destructive pattern core.git:reset-hard"));

        // Check matched span
        assert!(json.contains("\"matched_span\":"));
        assert!(json.contains("\"start\": 0"));
        assert!(json.contains("\"end\": 16"));

        // Check suggestions (core.git:reset-hard has suggestions)
        assert!(json.contains("\"suggestions\":"));
    }

    #[test]
    fn format_json_with_steps() {
        let trace = ExplainTrace {
            command: "git status".to_string(),
            normalized_command: None,
            sanitized_command: None,
            decision: EvaluationDecision::Allow,
            skipped_due_to_budget: false,
            total_duration_us: 200,
            steps: vec![
                TraceStep {
                    name: "keyword_gating",
                    duration_us: 50,
                    details: TraceDetails::KeywordGating {
                        quick_rejected: false,
                        keywords_checked: vec!["git".to_string()],
                        first_match: Some("git".to_string()),
                    },
                },
                TraceStep {
                    name: "policy_decision",
                    duration_us: 10,
                    details: TraceDetails::PolicyDecision {
                        decision: EvaluationDecision::Allow,
                        allowlisted: false,
                    },
                },
            ],
            match_info: None,
            allowlist_info: None,
            pack_summary: None,
        };

        let json = trace.format_json();

        // Check steps array
        assert!(json.contains("\"steps\":"));
        assert!(json.contains("\"name\": \"keyword_gating\""));
        assert!(json.contains("\"duration_us\": 50"));
        assert!(json.contains("\"type\": \"keyword_gating\""));
        assert!(json.contains("\"quick_rejected\": false"));
        assert!(json.contains("\"first_match\": \"git\""));
        assert!(json.contains("\"name\": \"policy_decision\""));
    }

    #[test]
    fn format_json_with_allowlist_override() {
        let original_match = MatchInfo {
            rule_id: Some("core.git:reset-hard".to_string()),
            pack_id: Some("core.git".to_string()),
            pattern_name: Some("reset-hard".to_string()),
            severity: Some(Severity::Critical),
            reason: "destroys uncommitted changes".to_string(),
            source: MatchSource::Pack,
            match_start: None,
            match_end: None,
            matched_text_preview: None,
            explanation: None,
        };

        let trace = ExplainTrace {
            command: "git reset --hard".to_string(),
            normalized_command: None,
            sanitized_command: None,
            decision: EvaluationDecision::Allow,
            skipped_due_to_budget: false,
            total_duration_us: 500,
            steps: vec![],
            match_info: None,
            allowlist_info: Some(AllowlistInfo {
                layer: AllowlistLayer::Project,
                entry_reason: "Allowed for release automation".to_string(),
                original_match,
            }),
            pack_summary: None,
        };

        let json = trace.format_json();

        // Check allowlist section
        assert!(json.contains("\"allowlist\":"));
        assert!(json.contains("\"layer\": \"project\""));
        assert!(json.contains("\"entry_reason\": \"Allowed for release automation\""));
        assert!(json.contains("\"original_match\":"));
    }

    #[test]
    fn format_json_with_pack_summary() {
        let trace = ExplainTrace {
            command: "git status".to_string(),
            normalized_command: None,
            sanitized_command: None,
            decision: EvaluationDecision::Allow,
            skipped_due_to_budget: false,
            total_duration_us: 100,
            steps: vec![],
            match_info: None,
            allowlist_info: None,
            pack_summary: Some(PackSummary {
                enabled_count: 5,
                evaluated: vec!["core.git".to_string()],
                skipped: vec!["containers.docker".to_string()],
            }),
        };

        let json = trace.format_json();

        assert!(json.contains("\"pack_summary\":"));
        assert!(json.contains("\"enabled_count\": 5"));
        assert!(json.contains("\"evaluated\":"));
        assert!(json.contains("\"core.git\""));
        assert!(json.contains("\"skipped\":"));
        assert!(json.contains("\"containers.docker\""));
    }

    #[test]
    fn json_output_is_valid_json() {
        let trace = ExplainTrace {
            command: "git reset --hard".to_string(),
            normalized_command: Some("git reset --hard".to_string()),
            sanitized_command: None,
            decision: EvaluationDecision::Deny,
            skipped_due_to_budget: false,
            total_duration_us: 847,
            steps: vec![TraceStep {
                name: "keyword_gating",
                duration_us: 50,
                details: TraceDetails::KeywordGating {
                    quick_rejected: false,
                    keywords_checked: vec!["git".to_string()],
                    first_match: Some("git".to_string()),
                },
            }],
            match_info: Some(MatchInfo {
                rule_id: Some("core.git:reset-hard".to_string()),
                pack_id: Some("core.git".to_string()),
                pattern_name: Some("reset-hard".to_string()),
                severity: Some(Severity::Critical),
                reason: "destroys uncommitted changes".to_string(),
                source: MatchSource::Pack,
                match_start: Some(0),
                match_end: Some(16),
                matched_text_preview: Some("git reset --hard".to_string()),
                explanation: None,
            }),
            allowlist_info: None,
            pack_summary: Some(PackSummary {
                enabled_count: 3,
                evaluated: vec!["core.git".to_string()],
                skipped: vec!["containers.docker".to_string()],
            }),
        };

        let json = trace.format_json();

        // Parse the JSON to verify it's valid
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&json);
        assert!(parsed.is_ok(), "JSON should be valid: {json}");

        // Verify required fields exist
        let value = parsed.unwrap();
        assert!(value.get("schema_version").is_some());
        assert!(value.get("command").is_some());
        assert!(value.get("decision").is_some());
        assert!(value.get("total_duration_us").is_some());
        assert!(value.get("steps").is_some());
    }

    #[test]
    fn json_schema_version_is_stable() {
        assert_eq!(EXPLAIN_JSON_SCHEMA_VERSION, 2);
    }

    #[test]
    fn to_json_output_returns_correct_struct() {
        let trace = ExplainTrace {
            command: "git status".to_string(),
            normalized_command: None,
            sanitized_command: None,
            decision: EvaluationDecision::Allow,
            skipped_due_to_budget: false,
            total_duration_us: 100,
            steps: vec![],
            match_info: None,
            allowlist_info: None,
            pack_summary: None,
        };

        let output = trace.to_json_output();

        assert_eq!(output.schema_version, 2);
        assert_eq!(output.command, "git status");
        assert_eq!(output.decision, "allow");
        assert_eq!(output.total_duration_us, 100);
        assert!(output.steps.is_empty());
        assert!(output.match_info.is_none());
        assert!(output.allowlist.is_none());
        assert!(output.pack_summary.is_none());
        assert!(output.suggestions.is_none());
    }
}
