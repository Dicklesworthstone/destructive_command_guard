//! Output formatters for allowlist suggestion results.
//!
//! The CLI can use these helpers to keep suggestion rendering stable across
//! text and JSON modes without coupling formatting logic to history analysis.

use crate::suggest::{AllowlistSuggestion, PathPattern};
use serde::Serialize;
use std::fmt::Write as _;

/// Schema version for machine-readable suggestion output.
pub const SUGGESTION_OUTPUT_SCHEMA_VERSION: u32 = 1;

/// Controls how many examples are shown in human-readable suggestion output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuggestionRenderOptions {
    /// Maximum example commands shown per suggestion.
    pub max_example_commands: usize,
    /// Maximum path patterns shown per suggestion.
    pub max_path_patterns: usize,
    /// Whether to include the review reminder footer.
    pub include_review_note: bool,
}

impl Default for SuggestionRenderOptions {
    fn default() -> Self {
        Self {
            max_example_commands: 5,
            max_path_patterns: 3,
            include_review_note: true,
        }
    }
}

/// Stable JSON representation for a list of allowlist suggestions.
#[derive(Debug, Clone, Serialize)]
pub struct SuggestionJsonOutput {
    /// Schema version for forward-compatible consumers.
    pub schema_version: u32,
    /// Rendered suggestion entries.
    pub suggestions: Vec<SuggestionJsonEntry>,
}

/// Stable JSON representation for one allowlist suggestion.
#[derive(Debug, Clone, Serialize)]
pub struct SuggestionJsonEntry {
    /// Proposed allowlist regex pattern.
    pub pattern: String,
    /// Total blocked occurrences in the cluster.
    pub frequency: usize,
    /// Number of unique command variants in the cluster.
    pub unique_variants: usize,
    /// Confidence tier (`high`, `medium`, or `low`).
    pub confidence: String,
    /// Risk level (`low`, `medium`, or `high`).
    pub risk: String,
    /// Primary reason code.
    pub reason: String,
    /// Primary reason as display text.
    pub reason_description: String,
    /// Overall score from 0.0 to 1.0.
    pub score: f32,
    /// Example commands represented by this suggestion.
    pub example_commands: Vec<String>,
    /// Common path patterns for path-specific allowlisting.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub path_patterns: Vec<SuggestionPathJson>,
    /// Whether path-specific allowlisting is recommended.
    pub suggest_path_specific: bool,
    /// Number of manual bypasses that contributed to this suggestion.
    pub bypass_count: usize,
    /// Ready-to-review TOML snippet for project/user allowlist files.
    pub suggested_config: String,
}

/// Stable JSON representation for one path pattern.
#[derive(Debug, Clone, Serialize)]
pub struct SuggestionPathJson {
    /// Common path prefix or glob pattern.
    pub pattern: String,
    /// Number of occurrences in this path pattern.
    pub occurrence_count: usize,
    /// Whether this appears to be a project directory.
    pub is_project_dir: bool,
}

/// Render allowlist suggestions as human-readable text.
#[must_use]
pub fn render_suggestions_text(
    suggestions: &[AllowlistSuggestion],
    options: SuggestionRenderOptions,
) -> String {
    if suggestions.is_empty() {
        return "No allowlist suggestions available.\n".to_string();
    }

    let mut output = String::new();
    let _ = writeln!(output, "Allowlist Suggestions");
    let _ = writeln!(output, "=====================");
    let _ = writeln!(output);

    for (index, suggestion) in suggestions.iter().enumerate() {
        let ordinal = index + 1;
        let total = suggestions.len();

        let _ = writeln!(
            output,
            "[{ordinal}/{total}] {}",
            suggestion.cluster.proposed_pattern
        );
        let _ = writeln!(output, "----------------------------------------");
        let _ = writeln!(
            output,
            "Blocked: {} times ({} unique variants)",
            suggestion.cluster.frequency, suggestion.cluster.unique_count
        );
        let _ = writeln!(
            output,
            "Confidence: {} | Risk: {} | Score: {:.2}",
            suggestion.confidence, suggestion.risk, suggestion.score
        );
        let _ = writeln!(output, "Reason: {}", suggestion.reason.description());

        if suggestion.bypass_count > 0 {
            let _ = writeln!(output, "Bypassed: {} times", suggestion.bypass_count);
        }

        if !suggestion.path_patterns.is_empty() {
            let _ = writeln!(output, "Common paths:");
            for path in suggestion
                .path_patterns
                .iter()
                .take(options.max_path_patterns)
            {
                let marker = if path.is_project_dir {
                    ", project dir"
                } else {
                    ""
                };
                let _ = writeln!(
                    output,
                    "  - {} ({} occurrences{marker})",
                    path.pattern, path.occurrence_count
                );
            }
            if suggestion.path_patterns.len() > options.max_path_patterns {
                let remaining = suggestion.path_patterns.len() - options.max_path_patterns;
                let _ = writeln!(output, "  ... and {remaining} more path pattern(s)");
            }
        }

        let _ = writeln!(output, "Example commands:");
        for command in suggestion
            .cluster
            .commands
            .iter()
            .take(options.max_example_commands)
        {
            let _ = writeln!(output, "  - {command}");
        }
        if suggestion.cluster.commands.len() > options.max_example_commands {
            let remaining = suggestion.cluster.commands.len() - options.max_example_commands;
            let _ = writeln!(output, "  ... and {remaining} more command(s)");
        }

        let _ = writeln!(output, "Suggested config:");
        output.push_str(&suggested_config_snippet(suggestion));
        let _ = writeln!(output);
    }

    if options.include_review_note {
        let _ = writeln!(
            output,
            "Review suggestions before applying them; regex allowlist entries require risk acknowledgement."
        );
    }

    output
}

/// Convert suggestions to the stable JSON output structure.
#[must_use]
pub fn suggestions_to_json_output(suggestions: &[AllowlistSuggestion]) -> SuggestionJsonOutput {
    SuggestionJsonOutput {
        schema_version: SUGGESTION_OUTPUT_SCHEMA_VERSION,
        suggestions: suggestions
            .iter()
            .map(|suggestion| SuggestionJsonEntry {
                pattern: suggestion.cluster.proposed_pattern.clone(),
                frequency: suggestion.cluster.frequency,
                unique_variants: suggestion.cluster.unique_count,
                confidence: suggestion.confidence.as_str().to_string(),
                risk: suggestion.risk.as_str().to_string(),
                reason: suggestion.reason.as_str().to_string(),
                reason_description: suggestion.reason.description().to_string(),
                score: suggestion.score,
                example_commands: suggestion.cluster.commands.clone(),
                path_patterns: suggestion
                    .path_patterns
                    .iter()
                    .map(path_pattern_to_json)
                    .collect(),
                suggest_path_specific: suggestion.suggest_path_specific,
                bypass_count: suggestion.bypass_count,
                suggested_config: suggested_config_snippet(suggestion),
            })
            .collect(),
    }
}

/// Render suggestions as pretty JSON.
///
/// # Errors
///
/// Returns an error if JSON serialization fails.
pub fn render_suggestions_json(
    suggestions: &[AllowlistSuggestion],
) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&suggestions_to_json_output(suggestions))
}

/// Render the allowlist TOML entry a user should review before applying.
#[must_use]
pub fn suggested_config_snippet(suggestion: &AllowlistSuggestion) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "[[allow]]");
    let _ = writeln!(
        output,
        "pattern = \"{}\"",
        toml_basic_string(&suggestion.cluster.proposed_pattern)
    );
    let _ = writeln!(
        output,
        "reason = \"Auto-suggested ({} confidence, {} risk): {}\"",
        suggestion.confidence.as_str(),
        suggestion.risk.as_str(),
        toml_basic_string(suggestion.reason.description())
    );
    let _ = writeln!(output, "risk_acknowledged = true");

    if suggestion.suggest_path_specific && !suggestion.path_patterns.is_empty() {
        let paths = suggestion
            .path_patterns
            .iter()
            .map(|path| format!("\"{}\"", toml_basic_string(&path.pattern)))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(output, "paths = [{paths}]");
    }

    output
}

fn path_pattern_to_json(path: &PathPattern) -> SuggestionPathJson {
    SuggestionPathJson {
        pattern: path.pattern.clone(),
        occurrence_count: path.occurrence_count,
        is_project_dir: path.is_project_dir,
    }
}

fn toml_basic_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suggest::{
        AllowlistSuggestion, CommandCluster, ConfidenceTier, PathPattern, RiskLevel,
        SuggestionReason,
    };

    fn make_suggestion() -> AllowlistSuggestion {
        AllowlistSuggestion {
            cluster: CommandCluster {
                commands: vec![
                    "npm run build:dev".to_string(),
                    "npm run build:prod".to_string(),
                    "npm run build:stage".to_string(),
                ],
                normalized: vec![
                    "npm run build:dev".to_string(),
                    "npm run build:prod".to_string(),
                    "npm run build:stage".to_string(),
                ],
                proposed_pattern: "^npm\\s+run\\s+build:(dev|prod|stage)$".to_string(),
                frequency: 12,
                unique_count: 3,
            },
            confidence: ConfidenceTier::High,
            risk: RiskLevel::Low,
            reason: SuggestionReason::PathClustered,
            contributing_factors: vec![SuggestionReason::HighFrequency],
            path_patterns: vec![
                PathPattern {
                    pattern: "/home/user/projects/*".to_string(),
                    occurrence_count: 10,
                    is_project_dir: true,
                },
                PathPattern {
                    pattern: "/home/user/tmp".to_string(),
                    occurrence_count: 2,
                    is_project_dir: false,
                },
            ],
            suggest_path_specific: true,
            bypass_count: 2,
            safety: Default::default(),
            score: 0.92,
        }
    }

    #[test]
    fn text_renderer_has_empty_state() {
        let output = render_suggestions_text(&[], SuggestionRenderOptions::default());
        assert_eq!(output, "No allowlist suggestions available.\n");
    }

    #[test]
    fn text_renderer_includes_core_suggestion_details() {
        let output = render_suggestions_text(
            &[make_suggestion()],
            SuggestionRenderOptions {
                max_example_commands: 2,
                max_path_patterns: 1,
                include_review_note: true,
            },
        );

        assert!(output.contains("Allowlist Suggestions"));
        assert!(output.contains("^npm\\s+run\\s+build:(dev|prod|stage)$"));
        assert!(output.contains("Blocked: 12 times (3 unique variants)"));
        assert!(output.contains("Confidence: high | Risk: low | Score: 0.92"));
        assert!(output.contains("Reason: Consistently blocked in specific directories"));
        assert!(output.contains("Bypassed: 2 times"));
        assert!(output.contains("/home/user/projects/* (10 occurrences, project dir)"));
        assert!(output.contains("... and 1 more path pattern(s)"));
        assert!(output.contains("... and 1 more command(s)"));
        assert!(output.contains("risk_acknowledged = true"));
        assert!(output.contains("Review suggestions before applying"));
    }

    #[test]
    fn suggested_config_escapes_toml_strings() {
        let mut suggestion = make_suggestion();
        suggestion.cluster.proposed_pattern = "^echo \"quoted\" \\\\ path$".to_string();

        let snippet = suggested_config_snippet(&suggestion);

        assert!(snippet.contains(r#"pattern = "^echo \"quoted\" \\\\ path$""#));
        assert!(snippet.contains(r#"paths = ["/home/user/projects/*", "/home/user/tmp"]"#));
    }

    #[test]
    fn json_renderer_uses_stable_shape() {
        let output = render_suggestions_json(&[make_suggestion()]).unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(value["schema_version"], SUGGESTION_OUTPUT_SCHEMA_VERSION);
        assert_eq!(value["suggestions"][0]["frequency"], 12);
        assert_eq!(value["suggestions"][0]["unique_variants"], 3);
        assert_eq!(value["suggestions"][0]["confidence"], "high");
        assert_eq!(value["suggestions"][0]["risk"], "low");
        assert_eq!(value["suggestions"][0]["reason"], "path_clustered");
        assert_eq!(value["suggestions"][0]["bypass_count"], 2);
        assert_eq!(
            value["suggestions"][0]["path_patterns"][0]["pattern"],
            "/home/user/projects/*"
        );
        assert!(
            value["suggestions"][0]["suggested_config"]
                .as_str()
                .unwrap()
                .contains("[[allow]]")
        );
    }
}
