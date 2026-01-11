//! Simulation input parsing for `dcg simulate`.
//!
//! This module provides streaming, line-by-line parsing of command logs
//! for replay/simulation against dcg policy. It supports multiple input
//! formats with conservative auto-detection.
//!
//! # Supported input formats
//!
//! 1. **Plain command** - The entire line is a shell command
//! 2. **Hook JSON** - `{"tool_name":"Bash","tool_input":{"command":"..."}}`
//! 3. **Structured decision log** - Schema-versioned log entries (future)
//!
//! # Design principles
//!
//! - **Streaming**: Process line-by-line, never load entire file into memory
//! - **Conservative**: Ambiguous lines are treated as malformed, not guessed
//! - **Deterministic**: Same line always produces same format classification
//! - **Panic-free**: Parser never panics on arbitrary input

use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read};

/// Schema version for simulate output (for future compatibility).
pub const SIMULATE_SCHEMA_VERSION: u32 = 1;

/// Input format detected for a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulateInputFormat {
    /// Plain command string (the entire line is the command)
    PlainCommand,
    /// Hook JSON: `{"tool_name":"Bash","tool_input":{"command":"..."}}`
    HookJson,
    /// Structured decision log entry (schema-versioned)
    DecisionLog,
}

/// Result of parsing a single line.
#[derive(Debug, Clone)]
pub enum ParsedLine {
    /// Successfully parsed command with its detected format
    Command {
        command: String,
        format: SimulateInputFormat,
    },
    /// Line should be ignored (e.g., non-Bash tool in hook JSON)
    Ignore { reason: &'static str },
    /// Line could not be parsed
    Malformed { error: String },
    /// Empty or whitespace-only line
    Empty,
}

/// Limits for the streaming parser.
#[derive(Debug, Clone)]
pub struct SimulateLimits {
    /// Maximum number of lines to process (None = unlimited)
    pub max_lines: Option<usize>,
    /// Maximum total bytes to read (None = unlimited)
    pub max_bytes: Option<usize>,
    /// Maximum command length in bytes (longer commands are truncated/skipped)
    pub max_command_bytes: Option<usize>,
}

impl Default for SimulateLimits {
    fn default() -> Self {
        Self {
            max_lines: None,
            max_bytes: None,
            max_command_bytes: Some(64 * 1024), // 64KB default max command
        }
    }
}

/// Statistics from parsing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParseStats {
    /// Total lines read
    pub lines_read: usize,
    /// Total bytes read
    pub bytes_read: usize,
    /// Number of commands extracted
    pub commands_extracted: usize,
    /// Number of malformed lines
    pub malformed_count: usize,
    /// Number of ignored lines (e.g., non-Bash tools)
    pub ignored_count: usize,
    /// Number of empty lines
    pub empty_count: usize,
    /// Whether parsing stopped due to limits
    pub stopped_at_limit: bool,
    /// Which limit was hit (if any)
    pub limit_hit: Option<LimitHit>,
}

/// Which limit caused parsing to stop.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitHit {
    MaxLines,
    MaxBytes,
}

/// Streaming parser for simulate input.
///
/// Processes input line-by-line with configurable limits.
pub struct SimulateParser<R: Read> {
    reader: BufReader<R>,
    limits: SimulateLimits,
    stats: ParseStats,
    strict: bool,
}

impl<R: Read> SimulateParser<R> {
    /// Create a new parser with the given reader and limits.
    pub fn new(reader: R, limits: SimulateLimits) -> Self {
        Self {
            reader: BufReader::new(reader),
            limits,
            stats: ParseStats::default(),
            strict: false,
        }
    }

    /// Enable strict mode (return error on first malformed line).
    #[must_use]
    pub const fn strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Get current parsing statistics.
    pub const fn stats(&self) -> &ParseStats {
        &self.stats
    }

    /// Consume the parser and return final statistics.
    pub fn into_stats(self) -> ParseStats {
        self.stats
    }

    /// Parse the next line from input.
    ///
    /// Returns `None` when input is exhausted or a limit is reached.
    /// Returns `Some(Err(...))` in strict mode when a malformed line is encountered.
    pub fn next_line(&mut self) -> Option<Result<ParsedLine, ParseError>> {
        // Check limits before reading
        if let Some(max_lines) = self.limits.max_lines {
            if self.stats.lines_read >= max_lines {
                self.stats.stopped_at_limit = true;
                self.stats.limit_hit = Some(LimitHit::MaxLines);
                return None;
            }
        }

        if let Some(max_bytes) = self.limits.max_bytes {
            if self.stats.bytes_read >= max_bytes {
                self.stats.stopped_at_limit = true;
                self.stats.limit_hit = Some(LimitHit::MaxBytes);
                return None;
            }
        }

        // Read next line
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => return None, // EOF
            Ok(n) => {
                self.stats.lines_read += 1;
                self.stats.bytes_read += n;
            }
            Err(e) => {
                return Some(Err(ParseError::Io(e.to_string())));
            }
        }

        // Parse the line
        let parsed = parse_line(&line, self.limits.max_command_bytes);

        // Update stats
        match &parsed {
            ParsedLine::Command { .. } => self.stats.commands_extracted += 1,
            ParsedLine::Malformed { error } => {
                self.stats.malformed_count += 1;
                if self.strict {
                    return Some(Err(ParseError::Malformed {
                        line: self.stats.lines_read,
                        error: error.clone(),
                    }));
                }
            }
            ParsedLine::Ignore { .. } => self.stats.ignored_count += 1,
            ParsedLine::Empty => self.stats.empty_count += 1,
        }

        Some(Ok(parsed))
    }

    /// Collect all parsed commands (for small inputs).
    ///
    /// Returns commands and final stats. In strict mode, stops on first error.
    ///
    /// # Errors
    ///
    /// Returns `ParseError::Io` on I/O failures, or `ParseError::Malformed` in strict
    /// mode when encountering an unparseable line.
    pub fn collect_commands(mut self) -> Result<(Vec<ParsedCommand>, ParseStats), ParseError> {
        let mut commands = Vec::new();

        while let Some(result) = self.next_line() {
            match result? {
                ParsedLine::Command { command, format } => {
                    commands.push(ParsedCommand {
                        command,
                        format,
                        line_number: self.stats.lines_read,
                    });
                }
                ParsedLine::Ignore { .. } | ParsedLine::Malformed { .. } | ParsedLine::Empty => {
                    // Continue (stats already updated)
                }
            }
        }

        Ok((commands, self.stats))
    }
}

/// Iterator adapter for `SimulateParser`.
impl<R: Read> Iterator for SimulateParser<R> {
    type Item = Result<ParsedLine, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_line()
    }
}

/// A successfully parsed command with metadata.
#[derive(Debug, Clone, Serialize)]
pub struct ParsedCommand {
    /// The extracted command string
    pub command: String,
    /// Detected input format
    pub format: SimulateInputFormat,
    /// Line number in the input (1-indexed)
    pub line_number: usize,
}

/// Errors that can occur during parsing.
#[derive(Debug, Clone)]
pub enum ParseError {
    /// I/O error reading input
    Io(String),
    /// Malformed line in strict mode
    Malformed { line: usize, error: String },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Malformed { line, error } => write!(f, "Line {line}: {error}"),
        }
    }
}

impl std::error::Error for ParseError {}

// =============================================================================
// Line parsing implementation
// =============================================================================

/// Parse a single line and detect its format.
fn parse_line(line: &str, max_command_bytes: Option<usize>) -> ParsedLine {
    let trimmed = line.trim();

    // Empty line
    if trimmed.is_empty() {
        return ParsedLine::Empty;
    }

    // Try Decision Log format first (unambiguous prefix)
    if trimmed.starts_with("DCG_LOG_V") {
        return parse_decision_log(trimmed, max_command_bytes);
    }

    // Try Hook JSON format (starts with '{' and parses as valid hook JSON)
    // Note: Shell brace blocks like `{ echo hello; }` also start with '{',
    // so we must fall back to plain command if JSON parsing fails.
    if trimmed.starts_with('{') {
        if let Some(result) = try_parse_hook_json(trimmed, max_command_bytes) {
            return result;
        }
        // Not valid hook JSON, treat as plain command (e.g., shell brace block)
        return parse_plain_command(trimmed, max_command_bytes);
    }

    // Default: treat as plain command
    parse_plain_command(trimmed, max_command_bytes)
}

/// Try to parse a line as hook JSON format.
///
/// Returns `Some(ParsedLine)` if this is valid hook JSON (including Malformed for missing fields),
/// or `None` if the line is not valid JSON (should fall back to plain command).
fn try_parse_hook_json(line: &str, max_command_bytes: Option<usize>) -> Option<ParsedLine> {
    // Minimal JSON structure we expect:
    // {"tool_name":"Bash","tool_input":{"command":"..."}}

    #[derive(Deserialize)]
    struct HookInput {
        tool_name: String,
        tool_input: Option<ToolInput>,
    }

    #[derive(Deserialize)]
    struct ToolInput {
        command: Option<String>,
    }

    // Try to parse as JSON - if it fails, return None to fall back to plain command
    let input: HookInput = serde_json::from_str(line).ok()?;

    // At this point we have valid JSON with tool_name, so treat it as hook format
    // (even if it's malformed, it's still hook JSON, not a plain command)

    // Check if it's a Bash tool
    if input.tool_name != "Bash" {
        return Some(ParsedLine::Ignore {
            reason: "non-Bash tool",
        });
    }

    // Extract command - if missing, it's malformed hook JSON (not a plain command)
    let Some(tool_input) = input.tool_input else {
        return Some(ParsedLine::Malformed {
            error: "missing tool_input".to_string(),
        });
    };

    let Some(command) = tool_input.command else {
        return Some(ParsedLine::Malformed {
            error: "missing command in tool_input".to_string(),
        });
    };

    // Check command length limit
    if let Some(max_bytes) = max_command_bytes {
        if command.len() > max_bytes {
            return Some(ParsedLine::Malformed {
                error: format!(
                    "command exceeds max length ({} > {max_bytes} bytes)",
                    command.len()
                ),
            });
        }
    }

    Some(ParsedLine::Command {
        command,
        format: SimulateInputFormat::HookJson,
    })
}

/// Parse a line as decision log format (future schema).
fn parse_decision_log(line: &str, max_command_bytes: Option<usize>) -> ParsedLine {
    use base64::Engine;

    // Decision log format (v1):
    // DCG_LOG_V1|timestamp|decision|command_base64|...
    //
    // For now, we'll implement a simple version.

    let parts: Vec<&str> = line.splitn(5, '|').collect();

    if parts.len() < 4 {
        return ParsedLine::Malformed {
            error: "invalid decision log format (expected at least 4 pipe-separated fields)"
                .to_string(),
        };
    }

    let version = parts[0];
    if version != "DCG_LOG_V1" {
        return ParsedLine::Malformed {
            error: format!("unsupported log version: {version}"),
        };
    }

    // parts[1] = timestamp (ignored for now)
    // parts[2] = decision (allow/deny/warn - ignored for replay)
    // parts[3] = command (base64 encoded)

    let command_b64 = parts[3];

    // Decode base64
    let command = match base64::engine::general_purpose::STANDARD.decode(command_b64) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => {
                return ParsedLine::Malformed {
                    error: "command is not valid UTF-8".to_string(),
                };
            }
        },
        Err(e) => {
            return ParsedLine::Malformed {
                error: format!("invalid base64 in command field: {e}"),
            };
        }
    };

    // Check command length limit
    if let Some(max_bytes) = max_command_bytes {
        if command.len() > max_bytes {
            return ParsedLine::Malformed {
                error: format!(
                    "command exceeds max length ({} > {max_bytes} bytes)",
                    command.len()
                ),
            };
        }
    }

    ParsedLine::Command {
        command,
        format: SimulateInputFormat::DecisionLog,
    }
}

/// Parse a line as a plain command string.
fn parse_plain_command(line: &str, max_command_bytes: Option<usize>) -> ParsedLine {
    // Check command length limit
    if let Some(max_bytes) = max_command_bytes {
        if line.len() > max_bytes {
            return ParsedLine::Malformed {
                error: format!(
                    "command exceeds max length ({} > {max_bytes} bytes)",
                    line.len()
                ),
            };
        }
    }

    ParsedLine::Command {
        command: line.to_string(),
        format: SimulateInputFormat::PlainCommand,
    }
}

// =============================================================================
// Evaluation Loop + Aggregation (git_safety_guard-1gt.8.2)
// =============================================================================
//
// This section implements the core simulation loop that evaluates parsed commands
// and aggregates results into actionable summaries.

use crate::config::Config;
use crate::evaluator::{EvaluationDecision, EvaluationResult, evaluate_command_with_pack_order};
use crate::packs::REGISTRY;
use std::collections::{HashMap, HashSet};

/// Default number of exemplars to keep per rule.
pub const DEFAULT_EXEMPLAR_LIMIT: usize = 3;

/// Decision category for aggregation (maps to policy mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulateDecision {
    /// Command was allowed (no pattern match or allowlisted).
    Allow,
    /// Command matched a warn-level pattern (warn mode).
    Warn,
    /// Command matched a deny-level pattern (blocked).
    Deny,
}

impl SimulateDecision {
    /// Convert from evaluation result to simulation decision.
    #[inline]
    #[must_use]
    pub const fn from_evaluation(result: &EvaluationResult) -> Self {
        match result.decision {
            EvaluationDecision::Allow => Self::Allow,
            EvaluationDecision::Deny => {
                // Check effective_mode for warn vs deny distinction
                match result.effective_mode {
                    Some(crate::packs::DecisionMode::Warn) => Self::Warn,
                    Some(crate::packs::DecisionMode::Log) => Self::Allow,
                    _ => Self::Deny,
                }
            }
        }
    }
}

/// An exemplar command for a rule (sampled occurrence).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exemplar {
    /// The command string (may be truncated).
    pub command: String,
    /// Line number in the input (1-indexed).
    pub line_number: usize,
    /// Original command length in bytes.
    pub original_length: usize,
}

/// Statistics for a single rule (`pack_id:pattern_name`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleStats {
    /// The rule ID (e.g., "core.git:reset-hard").
    pub rule_id: String,
    /// Pack ID (e.g., "core.git").
    pub pack_id: String,
    /// Pattern name (e.g., "reset-hard").
    pub pattern_name: String,
    /// Number of matches for this rule.
    pub count: usize,
    /// Decision for this rule (deny/warn/allow via allowlist).
    pub decision: SimulateDecision,
    /// Sample exemplars (first K occurrences by input order).
    pub exemplars: Vec<Exemplar>,
}

/// Statistics for a single pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackStats {
    /// The pack ID (e.g., "core.git").
    pub pack_id: String,
    /// Total matches across all patterns in this pack.
    pub count: usize,
    /// Breakdown by decision type.
    pub by_decision: HashMap<String, usize>,
}

/// Summary of simulation results.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SimulationSummary {
    /// Total commands evaluated.
    pub total_commands: usize,
    /// Commands that would be allowed.
    pub allow_count: usize,
    /// Commands that would trigger warnings.
    pub warn_count: usize,
    /// Commands that would be denied/blocked.
    pub deny_count: usize,
}

/// Complete simulation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    /// Schema version for output compatibility.
    pub schema_version: u32,
    /// Summary statistics.
    pub summary: SimulationSummary,
    /// Per-rule statistics (sorted by count desc, then `rule_id` asc).
    pub rules: Vec<RuleStats>,
    /// Per-pack statistics (sorted by count desc, then `pack_id` asc).
    pub packs: Vec<PackStats>,
    /// Parse statistics from the input.
    pub parse_stats: ParseStats,
}

/// Configuration for the simulation evaluator.
#[derive(Debug, Clone)]
pub struct SimulationConfig {
    /// Maximum exemplars to keep per rule.
    pub exemplar_limit: usize,
    /// Maximum command length for exemplars (truncate longer commands).
    pub max_exemplar_command_len: usize,
    /// Include allowlisted commands in results.
    pub include_allowlisted: bool,
}

impl Default for SimulationConfig {
    fn default() -> Self {
        Self {
            exemplar_limit: DEFAULT_EXEMPLAR_LIMIT,
            max_exemplar_command_len: 200,
            include_allowlisted: true,
        }
    }
}

/// Aggregator for simulation results.
///
/// Collects and aggregates evaluation results with deterministic output.
#[derive(Debug)]
pub struct SimulationAggregator {
    config: SimulationConfig,
    summary: SimulationSummary,
    rule_builders: HashMap<String, RuleStatsBuilder>,
    pack_counts: HashMap<String, HashMap<SimulateDecision, usize>>,
}

/// Builder for `RuleStats` (accumulates exemplars).
#[derive(Debug)]
struct RuleStatsBuilder {
    pack_id: String,
    pattern_name: String,
    count: usize,
    decision: SimulateDecision,
    exemplars: Vec<Exemplar>,
    exemplar_limit: usize,
}

impl RuleStatsBuilder {
    fn new(
        pack_id: String,
        pattern_name: String,
        decision: SimulateDecision,
        exemplar_limit: usize,
    ) -> Self {
        Self {
            pack_id,
            pattern_name,
            count: 0,
            decision,
            exemplars: Vec::with_capacity(exemplar_limit),
            exemplar_limit,
        }
    }

    fn add_match(&mut self, command: &str, line_number: usize, max_len: usize) {
        self.count += 1;
        if self.exemplars.len() < self.exemplar_limit {
            let truncated = if command.len() > max_len {
                // Account for "..." suffix (3 chars) so total doesn't exceed max_len
                let target = max_len.saturating_sub(3);
                let mut end = target;
                while end > 0 && !command.is_char_boundary(end) {
                    end -= 1;
                }
                format!("{}...", &command[..end])
            } else {
                command.to_string()
            };
            self.exemplars.push(Exemplar {
                command: truncated,
                line_number,
                original_length: command.len(),
            });
        }
    }

    fn build(self, rule_id: String) -> RuleStats {
        RuleStats {
            rule_id,
            pack_id: self.pack_id,
            pattern_name: self.pattern_name,
            count: self.count,
            decision: self.decision,
            exemplars: self.exemplars,
        }
    }
}

impl SimulationAggregator {
    /// Create a new aggregator with the given configuration.
    #[must_use]
    pub fn new(config: SimulationConfig) -> Self {
        Self {
            config,
            summary: SimulationSummary::default(),
            rule_builders: HashMap::new(),
            pack_counts: HashMap::new(),
        }
    }

    /// Record an evaluation result.
    pub fn record(&mut self, command: &str, line_number: usize, result: &EvaluationResult) {
        self.summary.total_commands += 1;
        let decision = SimulateDecision::from_evaluation(result);

        match decision {
            SimulateDecision::Allow => self.summary.allow_count += 1,
            SimulateDecision::Warn => self.summary.warn_count += 1,
            SimulateDecision::Deny => self.summary.deny_count += 1,
        }

        if let Some(ref pattern_info) = result.pattern_info {
            let pack_id = pattern_info
                .pack_id
                .as_deref()
                .unwrap_or("unknown")
                .to_string();
            let pattern_name = pattern_info
                .pattern_name
                .as_deref()
                .unwrap_or("unknown")
                .to_string();
            let rule_id = format!("{pack_id}:{pattern_name}");

            let builder = self.rule_builders.entry(rule_id).or_insert_with(|| {
                RuleStatsBuilder::new(
                    pack_id.clone(),
                    pattern_name,
                    decision,
                    self.config.exemplar_limit,
                )
            });
            builder.add_match(command, line_number, self.config.max_exemplar_command_len);

            let pack_decisions = self.pack_counts.entry(pack_id).or_default();
            *pack_decisions.entry(decision).or_insert(0) += 1;
        } else if let Some(ref allowlist_override) = result.allowlist_override {
            if self.config.include_allowlisted {
                let pack_id = allowlist_override
                    .matched
                    .pack_id
                    .as_deref()
                    .unwrap_or("unknown")
                    .to_string();
                let pattern_name = allowlist_override
                    .matched
                    .pattern_name
                    .as_deref()
                    .unwrap_or("unknown")
                    .to_string();
                let rule_id = format!("{pack_id}:{pattern_name}");

                let builder = self.rule_builders.entry(rule_id).or_insert_with(|| {
                    RuleStatsBuilder::new(
                        pack_id.clone(),
                        pattern_name,
                        SimulateDecision::Allow,
                        self.config.exemplar_limit,
                    )
                });
                builder.add_match(command, line_number, self.config.max_exemplar_command_len);

                let pack_decisions = self.pack_counts.entry(pack_id).or_default();
                *pack_decisions.entry(SimulateDecision::Allow).or_insert(0) += 1;
            }
        }
    }

    /// Finalize aggregation and produce sorted results.
    #[must_use]
    pub fn finalize(self, parse_stats: ParseStats) -> SimulationResult {
        let mut rules: Vec<RuleStats> = self
            .rule_builders
            .into_iter()
            .map(|(rule_id, builder)| builder.build(rule_id))
            .collect();

        rules.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| a.rule_id.cmp(&b.rule_id))
        });

        let mut packs: Vec<PackStats> = self
            .pack_counts
            .into_iter()
            .map(|(pack_id, decisions)| {
                let count = decisions.values().sum();
                let by_decision: HashMap<String, usize> = decisions
                    .into_iter()
                    .map(|(d, c)| {
                        let key = match d {
                            SimulateDecision::Allow => "allow",
                            SimulateDecision::Warn => "warn",
                            SimulateDecision::Deny => "deny",
                        };
                        (key.to_string(), c)
                    })
                    .collect();
                PackStats {
                    pack_id,
                    count,
                    by_decision,
                }
            })
            .collect();

        packs.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| a.pack_id.cmp(&b.pack_id))
        });

        SimulationResult {
            schema_version: SIMULATE_SCHEMA_VERSION,
            summary: self.summary,
            rules,
            packs,
            parse_stats,
        }
    }
}

/// Run simulation on parsed commands.
pub fn run_simulation<I>(
    commands: I,
    parse_stats: ParseStats,
    config: &Config,
    sim_config: SimulationConfig,
) -> SimulationResult
where
    I: IntoIterator<Item = ParsedCommand>,
{
    let enabled_packs: HashSet<String> = config.enabled_pack_ids();
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    let keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let keyword_index = REGISTRY.build_enabled_keyword_index(&ordered_packs);
    let compiled_overrides = config.overrides.compile();
    let allowlists = crate::allowlist::load_default_allowlists();
    let heredoc_settings = config.heredoc_settings();

    let mut aggregator = SimulationAggregator::new(sim_config);

    for cmd in commands {
        let result = evaluate_command_with_pack_order(
            &cmd.command,
            &keywords,
            &ordered_packs,
            keyword_index.as_ref(),
            &compiled_overrides,
            &allowlists,
            &heredoc_settings,
        );
        aggregator.record(&cmd.command, cmd.line_number, &result);
    }

    aggregator.finalize(parse_stats)
}

/// Run simulation from a reader (convenience wrapper).
///
/// # Errors
///
/// Returns `ParseError` if the input cannot be parsed.
pub fn run_simulation_from_reader<R: std::io::Read>(
    reader: R,
    limits: SimulateLimits,
    config: &Config,
    sim_config: SimulationConfig,
    strict: bool,
) -> Result<SimulationResult, ParseError> {
    let parser = SimulateParser::new(reader, limits).strict(strict);
    let (commands, parse_stats) = parser.collect_commands()?;
    Ok(run_simulation(commands, parse_stats, config, sim_config))
}

// =============================================================================
// Output Formatting (git_safety_guard-1gt.8.3)
// =============================================================================

use crate::scan::ScanRedactMode;

/// Configuration for output formatting.
#[derive(Debug, Clone)]
pub struct SimulateOutputConfig {
    /// Redaction mode for sensitive data.
    pub redact: ScanRedactMode,
    /// Maximum command length in output (0 = unlimited).
    pub truncate: usize,
    /// Limit to top N rules (0 = show all).
    pub top: usize,
    /// Show verbose output with exemplars.
    pub verbose: bool,
}

impl Default for SimulateOutputConfig {
    fn default() -> Self {
        Self {
            redact: ScanRedactMode::None,
            truncate: 120,
            top: 20,
            verbose: false,
        }
    }
}

/// JSON output structure for simulate command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateJsonOutput {
    pub schema_version: u32,
    pub totals: SimulateJsonTotals,
    pub rules: Vec<SimulateJsonRule>,
    pub errors: SimulateJsonErrors,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateJsonTotals {
    pub commands: usize,
    pub allowed: usize,
    pub warned: usize,
    pub denied: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateJsonRule {
    pub rule_id: String,
    pub count: usize,
    pub decision: String,
    pub exemplars: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateJsonErrors {
    pub malformed_count: usize,
    pub ignored_count: usize,
    pub stopped_at_limit: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_hit: Option<String>,
}

/// Apply redaction and truncation to a command string.
#[must_use]
pub fn redact_and_truncate_command(cmd: &str, config: &SimulateOutputConfig) -> String {
    let redacted = match config.redact {
        ScanRedactMode::None => cmd.to_string(),
        ScanRedactMode::Quoted => crate::scan::redact_quoted_strings(cmd),
        ScanRedactMode::Aggressive => crate::scan::redact_aggressively(cmd),
    };

    if config.truncate > 0 && redacted.len() > config.truncate {
        let target = config.truncate.saturating_sub(3);
        let mut end = target;
        while end > 0 && !redacted.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &redacted[..end])
    } else {
        redacted
    }
}

/// Format simulation result as pretty-printed text.
#[must_use]
#[allow(clippy::format_push_string)]
pub fn format_pretty_output(result: &SimulationResult, config: &SimulateOutputConfig) -> String {
    let mut output = String::new();
    output.push_str("Simulation Results\n==================\n\n");
    output.push_str("Summary:\n");
    output.push_str(&format!(
        "  Total commands:  {}\n",
        result.summary.total_commands
    ));
    output.push_str(&format!(
        "  Allowed:         {}\n",
        result.summary.allow_count
    ));
    output.push_str(&format!(
        "  Warned:          {}\n",
        result.summary.warn_count
    ));
    output.push_str(&format!(
        "  Denied:          {}\n",
        result.summary.deny_count
    ));
    output.push('\n');

    if !result.rules.is_empty() {
        output.push_str("Rules Triggered (sorted by count):\n");
        let rules_to_show: Vec<_> = if config.top > 0 {
            result.rules.iter().take(config.top).collect()
        } else {
            result.rules.iter().collect()
        };
        for rule in rules_to_show {
            let decision_str = match rule.decision {
                SimulateDecision::Allow => "allow",
                SimulateDecision::Warn => "warn",
                SimulateDecision::Deny => "DENY",
            };
            output.push_str(&format!(
                "  {:>5} x {} [{}]\n",
                rule.count, rule.rule_id, decision_str
            ));
            if config.verbose {
                for ex in &rule.exemplars {
                    let display_cmd = redact_and_truncate_command(&ex.command, config);
                    output.push_str(&format!("         L{}: {}\n", ex.line_number, display_cmd));
                }
            }
        }
        if config.top > 0 && result.rules.len() > config.top {
            output.push_str(&format!(
                "  ... and {} more rules\n",
                result.rules.len() - config.top
            ));
        }
        output.push('\n');
    }

    if !result.packs.is_empty() {
        output.push_str("Packs Summary:\n");
        for pack in &result.packs {
            output.push_str(&format!("  {:>5} x {}\n", pack.count, pack.pack_id));
        }
        output.push('\n');
    }

    output.push_str("Parse Statistics:\n");
    output.push_str(&format!(
        "  Lines read:         {}\n",
        result.parse_stats.lines_read
    ));
    output.push_str(&format!(
        "  Commands extracted: {}\n",
        result.parse_stats.commands_extracted
    ));
    output.push_str(&format!(
        "  Malformed lines:    {}\n",
        result.parse_stats.malformed_count
    ));
    output.push_str(&format!(
        "  Ignored lines:      {}\n",
        result.parse_stats.ignored_count
    ));
    if result.parse_stats.stopped_at_limit {
        if let Some(ref limit) = result.parse_stats.limit_hit {
            output.push_str(&format!("  Stopped at limit:   {limit:?}\n"));
        }
    }
    output
}

/// Format simulation result as JSON.
///
/// # Errors
///
/// Returns an error if JSON serialization fails.
pub fn format_json_output(
    result: SimulationResult,
    config: &SimulateOutputConfig,
) -> Result<String, serde_json::Error> {
    let rules_to_show: Vec<_> = if config.top > 0 {
        result.rules.into_iter().take(config.top).collect()
    } else {
        result.rules
    };

    let json_rules: Vec<SimulateJsonRule> = rules_to_show
        .into_iter()
        .map(|r| {
            let exemplars: Vec<String> = r
                .exemplars
                .iter()
                .map(|ex| redact_and_truncate_command(&ex.command, config))
                .collect();
            SimulateJsonRule {
                rule_id: r.rule_id,
                count: r.count,
                decision: match r.decision {
                    SimulateDecision::Allow => "allow".to_string(),
                    SimulateDecision::Warn => "warn".to_string(),
                    SimulateDecision::Deny => "deny".to_string(),
                },
                exemplars,
            }
        })
        .collect();

    let output = SimulateJsonOutput {
        schema_version: result.schema_version,
        totals: SimulateJsonTotals {
            commands: result.summary.total_commands,
            allowed: result.summary.allow_count,
            warned: result.summary.warn_count,
            denied: result.summary.deny_count,
        },
        rules: json_rules,
        errors: SimulateJsonErrors {
            malformed_count: result.parse_stats.malformed_count,
            ignored_count: result.parse_stats.ignored_count,
            stopped_at_limit: result.parse_stats.stopped_at_limit,
            limit_hit: result.parse_stats.limit_hit.map(|l| format!("{l:?}")),
        },
    };

    serde_json::to_string_pretty(&output)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Format detection tests
    // -------------------------------------------------------------------------

    #[test]
    fn detect_plain_command() {
        let result = parse_line("git status --short", None);
        match result {
            ParsedLine::Command { command, format } => {
                assert_eq!(command, "git status --short");
                assert_eq!(format, SimulateInputFormat::PlainCommand);
            }
            _ => panic!("expected Command, got {result:?}"),
        }
    }

    #[test]
    fn detect_hook_json_bash() {
        let line = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
        let result = parse_line(line, None);
        match result {
            ParsedLine::Command { command, format } => {
                assert_eq!(command, "git status");
                assert_eq!(format, SimulateInputFormat::HookJson);
            }
            _ => panic!("expected Command, got {result:?}"),
        }
    }

    #[test]
    fn detect_hook_json_non_bash_ignored() {
        let line = r#"{"tool_name":"Read","tool_input":{"path":"/etc/passwd"}}"#;
        let result = parse_line(line, None);
        match result {
            ParsedLine::Ignore { reason } => {
                assert_eq!(reason, "non-Bash tool");
            }
            _ => panic!("expected Ignore, got {result:?}"),
        }
    }

    #[test]
    fn detect_decision_log() {
        // "git status" in base64 = "Z2l0IHN0YXR1cw=="
        let line = "DCG_LOG_V1|2026-01-09T00:00:00Z|allow|Z2l0IHN0YXR1cw==|";
        let result = parse_line(line, None);
        match result {
            ParsedLine::Command { command, format } => {
                assert_eq!(command, "git status");
                assert_eq!(format, SimulateInputFormat::DecisionLog);
            }
            _ => panic!("expected Command, got {result:?}"),
        }
    }

    #[test]
    fn empty_line() {
        assert!(matches!(parse_line("", None), ParsedLine::Empty));
        assert!(matches!(parse_line("   ", None), ParsedLine::Empty));
        assert!(matches!(parse_line("\t\n", None), ParsedLine::Empty));
    }

    #[test]
    fn invalid_json_falls_back_to_plain_command() {
        // Invalid JSON starting with '{' should be treated as a plain command,
        // not malformed. This handles shell brace blocks like `{ echo hello; }`.
        let result = parse_line("{invalid json}", None);
        match result {
            ParsedLine::Command { command, format } => {
                assert_eq!(command, "{invalid json}");
                assert_eq!(format, SimulateInputFormat::PlainCommand);
            }
            _ => panic!("expected Command (PlainCommand), got {result:?}"),
        }
    }

    #[test]
    fn shell_brace_block_as_plain_command() {
        // Shell brace blocks should be treated as plain commands
        let result = parse_line("{ echo hello; } | cat", None);
        match result {
            ParsedLine::Command { command, format } => {
                assert_eq!(command, "{ echo hello; } | cat");
                assert_eq!(format, SimulateInputFormat::PlainCommand);
            }
            _ => panic!("expected Command (PlainCommand), got {result:?}"),
        }
    }

    #[test]
    fn valid_json_missing_command_is_malformed() {
        // Valid JSON with missing fields is still hook JSON format, just malformed
        // (not a plain command)
        let line = r#"{"tool_name":"Bash","tool_input":{}}"#;
        let result = parse_line(line, None);
        match result {
            ParsedLine::Malformed { error } => {
                assert!(error.contains("missing command"));
            }
            _ => panic!("expected Malformed, got {result:?}"),
        }
    }

    #[test]
    fn malformed_decision_log_wrong_version() {
        let line = "DCG_LOG_V99|timestamp|allow|cmd|";
        let result = parse_line(line, None);
        match result {
            ParsedLine::Malformed { error } => {
                assert!(error.contains("unsupported log version"));
            }
            _ => panic!("expected Malformed, got {result:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // Limit tests
    // -------------------------------------------------------------------------

    #[test]
    fn command_length_limit() {
        let long_cmd = "x".repeat(1000);
        let result = parse_line(&long_cmd, Some(500));
        match result {
            ParsedLine::Malformed { error } => {
                assert!(error.contains("exceeds max length"));
            }
            _ => panic!("expected Malformed, got {result:?}"),
        }
    }

    #[test]
    fn command_within_limit() {
        let cmd = "git status";
        let result = parse_line(cmd, Some(500));
        assert!(matches!(result, ParsedLine::Command { .. }));
    }

    // -------------------------------------------------------------------------
    // Streaming parser tests
    // -------------------------------------------------------------------------

    #[test]
    fn parser_collects_commands() {
        let input = r#"git status
{"tool_name":"Bash","tool_input":{"command":"git log"}}
{"tool_name":"Read","tool_input":{"path":"file.txt"}}

echo hello
"#;

        let parser = SimulateParser::new(input.as_bytes(), SimulateLimits::default());
        let (commands, stats) = parser.collect_commands().unwrap();

        assert_eq!(commands.len(), 3);
        assert_eq!(commands[0].command, "git status");
        assert_eq!(commands[0].format, SimulateInputFormat::PlainCommand);
        assert_eq!(commands[1].command, "git log");
        assert_eq!(commands[1].format, SimulateInputFormat::HookJson);
        assert_eq!(commands[2].command, "echo hello");

        assert_eq!(stats.lines_read, 5);
        assert_eq!(stats.commands_extracted, 3);
        assert_eq!(stats.ignored_count, 1); // Read tool
        assert_eq!(stats.empty_count, 1);
        assert_eq!(stats.malformed_count, 0);
    }

    #[test]
    fn parser_respects_line_limit() {
        let input = "line1\nline2\nline3\nline4\nline5\n";

        let limits = SimulateLimits {
            max_lines: Some(3),
            ..Default::default()
        };
        let parser = SimulateParser::new(input.as_bytes(), limits);
        let (commands, stats) = parser.collect_commands().unwrap();

        assert_eq!(commands.len(), 3);
        assert_eq!(stats.lines_read, 3);
        assert!(stats.stopped_at_limit);
        assert!(matches!(stats.limit_hit, Some(LimitHit::MaxLines)));
    }

    #[test]
    fn parser_strict_mode_fails_on_malformed() {
        // Use valid JSON with missing command field to trigger malformed error
        let input = r#"git status
{"tool_name":"Bash","tool_input":{}}
echo hello
"#;

        let parser = SimulateParser::new(input.as_bytes(), SimulateLimits::default()).strict(true);
        let result = parser.collect_commands();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ParseError::Malformed { line: 2, .. }));
    }

    #[test]
    fn parser_non_strict_continues_on_malformed() {
        // Use valid JSON with missing command field to trigger malformed error
        let input = r#"git status
{"tool_name":"Bash","tool_input":{}}
echo hello
"#;

        let parser = SimulateParser::new(input.as_bytes(), SimulateLimits::default()).strict(false);
        let (commands, stats) = parser.collect_commands().unwrap();

        assert_eq!(commands.len(), 2); // git status and echo hello
        assert_eq!(stats.malformed_count, 1);
    }

    #[test]
    fn parser_treats_invalid_json_as_plain_command() {
        // Invalid JSON (like shell brace blocks) should be treated as plain commands
        let input = r"git status
{ echo hello; }
echo world
";

        let parser = SimulateParser::new(input.as_bytes(), SimulateLimits::default());
        let (commands, stats) = parser.collect_commands().unwrap();

        assert_eq!(commands.len(), 3); // All three are plain commands
        assert_eq!(commands[1].command, "{ echo hello; }");
        assert_eq!(commands[1].format, SimulateInputFormat::PlainCommand);
        assert_eq!(stats.malformed_count, 0);
    }

    // -------------------------------------------------------------------------
    // Determinism tests
    // -------------------------------------------------------------------------

    #[test]
    fn parsing_is_deterministic() {
        let lines = [
            "git status",
            r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#,
            "{broken",
            "",
            "DCG_LOG_V1|ts|allow|Z2l0IHN0YXR1cw==|",
        ];

        // Parse each line 100 times and ensure same result
        for line in lines {
            let first = parse_line(line, None);
            for _ in 0..100 {
                let result = parse_line(line, None);
                assert_eq!(
                    format!("{first:?}"),
                    format!("{result:?}"),
                    "Non-deterministic parsing for: {line}"
                );
            }
        }
    }

    // -------------------------------------------------------------------------
    // Aggregation tests (git_safety_guard-1gt.8.2)
    // -------------------------------------------------------------------------

    #[test]
    fn aggregator_counts_decisions_correctly() {
        let config = SimulationConfig::default();
        let mut agg = SimulationAggregator::new(config);

        // Record some results
        agg.record("ls", 1, &EvaluationResult::allowed());
        agg.record("git status", 2, &EvaluationResult::allowed());
        agg.record(
            "rm -rf /",
            3,
            &EvaluationResult::denied_by_pack("core.filesystem", "destructive"),
        );

        let parse_stats = ParseStats {
            lines_read: 3,
            commands_extracted: 3,
            ..Default::default()
        };
        let result = agg.finalize(parse_stats);

        assert_eq!(result.summary.total_commands, 3);
        assert_eq!(result.summary.allow_count, 2);
        assert_eq!(result.summary.deny_count, 1);
        assert_eq!(result.summary.warn_count, 0);
    }

    #[test]
    fn aggregator_sorts_rules_deterministically() {
        let config = SimulationConfig::default();
        let mut agg = SimulationAggregator::new(config);

        // Add rules with same count in different order
        agg.record(
            "cmd1",
            1,
            &EvaluationResult::denied_by_pack_pattern(
                "pack.b",
                "rule1",
                "test",
                crate::packs::Severity::Critical,
            ),
        );
        agg.record(
            "cmd2",
            2,
            &EvaluationResult::denied_by_pack_pattern(
                "pack.a",
                "rule1",
                "test",
                crate::packs::Severity::Critical,
            ),
        );
        agg.record(
            "cmd3",
            3,
            &EvaluationResult::denied_by_pack_pattern(
                "pack.b",
                "rule1",
                "test",
                crate::packs::Severity::Critical,
            ),
        );

        let parse_stats = ParseStats::default();
        let result = agg.finalize(parse_stats);

        // Rules should be sorted by count desc, then rule_id asc
        assert_eq!(result.rules.len(), 2);
        assert_eq!(result.rules[0].rule_id, "pack.b:rule1"); // count=2
        assert_eq!(result.rules[0].count, 2);
        assert_eq!(result.rules[1].rule_id, "pack.a:rule1"); // count=1
        assert_eq!(result.rules[1].count, 1);
    }

    #[test]
    fn aggregator_samples_first_k_exemplars() {
        let config = SimulationConfig {
            exemplar_limit: 2,
            ..Default::default()
        };
        let mut agg = SimulationAggregator::new(config);

        // Add 5 occurrences of the same rule
        for i in 1..=5 {
            agg.record(
                &format!("cmd{i}"),
                i,
                &EvaluationResult::denied_by_pack_pattern(
                    "pack.a",
                    "rule1",
                    "test",
                    crate::packs::Severity::Critical,
                ),
            );
        }

        let parse_stats = ParseStats::default();
        let result = agg.finalize(parse_stats);

        // Should only have first 2 exemplars
        assert_eq!(result.rules[0].exemplars.len(), 2);
        assert_eq!(result.rules[0].exemplars[0].command, "cmd1");
        assert_eq!(result.rules[0].exemplars[0].line_number, 1);
        assert_eq!(result.rules[0].exemplars[1].command, "cmd2");
        assert_eq!(result.rules[0].exemplars[1].line_number, 2);
    }

    #[test]
    fn exemplar_truncation_respects_max_len() {
        let config = SimulationConfig {
            exemplar_limit: 1,
            max_exemplar_command_len: 10, // Total should be <= 10 chars
            include_allowlisted: true,
        };
        let mut agg = SimulationAggregator::new(config);

        // Command is 20 chars, should be truncated to fit within 10 chars including "..."
        agg.record(
            "12345678901234567890",
            1,
            &EvaluationResult::denied_by_pack_pattern(
                "pack.a",
                "rule1",
                "test",
                crate::packs::Severity::Critical,
            ),
        );

        let parse_stats = ParseStats::default();
        let result = agg.finalize(parse_stats);

        // Truncated command should be at most max_exemplar_command_len (10) chars
        let exemplar = &result.rules[0].exemplars[0];
        assert!(
            exemplar.command.len() <= 10,
            "Expected at most 10 chars, got {}: '{}'",
            exemplar.command.len(),
            exemplar.command
        );
        assert!(
            exemplar.command.ends_with("..."),
            "Expected ellipsis, got: '{}'",
            exemplar.command
        );
        assert_eq!(exemplar.original_length, 20);
    }

    #[test]
    fn aggregation_is_deterministic() {
        let commands = vec![
            ParsedCommand {
                command: "rm -rf /".to_string(),
                format: SimulateInputFormat::PlainCommand,
                line_number: 1,
            },
            ParsedCommand {
                command: "git reset --hard".to_string(),
                format: SimulateInputFormat::PlainCommand,
                line_number: 2,
            },
            ParsedCommand {
                command: "rm -rf /tmp".to_string(),
                format: SimulateInputFormat::PlainCommand,
                line_number: 3,
            },
        ];

        let config = Config::default();
        let sim_config = SimulationConfig::default();

        // Run simulation multiple times
        let first = run_simulation(
            commands.clone(),
            ParseStats::default(),
            &config,
            sim_config.clone(),
        );

        for _ in 0..10 {
            let result = run_simulation(
                commands.clone(),
                ParseStats::default(),
                &config,
                sim_config.clone(),
            );

            // Compare summaries
            assert_eq!(first.summary.total_commands, result.summary.total_commands);
            assert_eq!(first.summary.allow_count, result.summary.allow_count);
            assert_eq!(first.summary.deny_count, result.summary.deny_count);

            // Compare rule order
            assert_eq!(first.rules.len(), result.rules.len());
            for (a, b) in first.rules.iter().zip(result.rules.iter()) {
                assert_eq!(a.rule_id, b.rule_id);
                assert_eq!(a.count, b.count);
            }
        }
    }
}
