//! SARIF 2.1.0 output format for scan results.
//!
//! SARIF (Static Analysis Results Interchange Format) is the industry standard
//! for security scanning output. It integrates natively with:
//! - GitHub Code Scanning
//! - GitLab Code Quality
//! - Azure DevOps
//! - VS Code SARIF Viewer extension
//! - `SonarQube`
//!
//! Reference: <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>

use crate::scan::{ScanDecision, ScanFinding, ScanReport, ScanSeverity};
use serde::Serialize;
use std::collections::HashMap;

/// SARIF 2.1.0 schema URI.
pub const SARIF_SCHEMA: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";

/// SARIF version string.
pub const SARIF_VERSION: &str = "2.1.0";

/// DCG tool information URI.
pub const DCG_INFO_URI: &str = "https://github.com/Dicklesworthstone/destructive_command_guard";

/// Top-level SARIF report structure.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifReport {
    /// JSON schema for SARIF 2.1.0.
    #[serde(rename = "$schema")]
    pub schema: String,

    /// SARIF version (always "2.1.0").
    pub version: String,

    /// Analysis runs (typically one per tool invocation).
    pub runs: Vec<SarifRun>,
}

/// A single analysis run.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRun {
    /// Tool that produced this run.
    pub tool: SarifTool,

    /// Results (findings) from this run.
    pub results: Vec<SarifResult>,

    /// Invocation details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocations: Option<Vec<SarifInvocation>>,
}

/// Tool information.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifTool {
    /// Driver (primary tool component).
    pub driver: SarifToolComponent,
}

/// Tool component (driver or extension).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifToolComponent {
    /// Tool name.
    pub name: String,

    /// Tool version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Semantic version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic_version: Option<String>,

    /// URI for tool information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub information_uri: Option<String>,

    /// Rules defined by this tool.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<SarifReportingDescriptor>,
}

/// Reporting descriptor (rule definition).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifReportingDescriptor {
    /// Unique rule identifier.
    pub id: String,

    /// Rule name (human-readable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Short description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_description: Option<SarifMessage>,

    /// Full description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_description: Option<SarifMessage>,

    /// Help URI for this rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,

    /// Default configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_configuration: Option<SarifReportingConfiguration>,

    /// Properties bag for additional metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifPropertyBag>,
}

/// Reporting configuration.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifReportingConfiguration {
    /// Default severity level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<SarifLevel>,

    /// Whether the rule is enabled by default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

/// SARIF severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SarifLevel {
    /// Not applicable.
    None,
    /// Informational.
    Note,
    /// Warning.
    Warning,
    /// Error.
    Error,
}

impl From<ScanSeverity> for SarifLevel {
    fn from(severity: ScanSeverity) -> Self {
        match severity {
            ScanSeverity::Error => Self::Error,
            ScanSeverity::Warning => Self::Warning,
            ScanSeverity::Info => Self::Note,
        }
    }
}

/// A message with text content.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifMessage {
    /// Plain text message.
    pub text: String,

    /// Markdown-formatted message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub markdown: Option<String>,
}

impl SarifMessage {
    /// Create a new message with just text.
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            markdown: None,
        }
    }
}

/// Individual analysis result (finding).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifResult {
    /// Rule ID that triggered this result.
    pub rule_id: String,

    /// Severity level.
    pub level: SarifLevel,

    /// Result message.
    pub message: SarifMessage,

    /// Locations where the result was found.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<SarifLocation>,

    /// Code flows (execution paths).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub code_flows: Vec<SarifCodeFlow>,

    /// Suggested fixes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fixes: Vec<SarifFix>,

    /// Properties bag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifPropertyBag>,
}

/// Location in a source file.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLocation {
    /// Physical location in a file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physical_location: Option<SarifPhysicalLocation>,

    /// Message describing this location.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<SarifMessage>,
}

/// Physical location (file + region).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifPhysicalLocation {
    /// Artifact (file) location.
    pub artifact_location: SarifArtifactLocation,

    /// Region within the artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<SarifRegion>,
}

/// Artifact (file) location.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifactLocation {
    /// URI to the artifact (relative or absolute).
    pub uri: String,

    /// URI base ID for resolving relative URIs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri_base_id: Option<String>,
}

/// Region within a file.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRegion {
    /// Start line (1-based).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_line: Option<usize>,

    /// Start column (1-based).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_column: Option<usize>,

    /// End line (1-based).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<usize>,

    /// End column (1-based).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_column: Option<usize>,

    /// Snippet of source code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<SarifArtifactContent>,
}

/// Artifact content (snippet).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifactContent {
    /// Text content.
    pub text: String,
}

/// Code flow (execution path).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifCodeFlow {
    /// Thread flows within this code flow.
    pub thread_flows: Vec<SarifThreadFlow>,
}

/// Thread flow (sequence of locations).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifThreadFlow {
    /// Locations in execution order.
    pub locations: Vec<SarifThreadFlowLocation>,
}

/// Location in a thread flow.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifThreadFlowLocation {
    /// Location details.
    pub location: SarifLocation,
}

/// Suggested fix.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifFix {
    /// Description of the fix.
    pub description: SarifMessage,

    /// Artifact changes for this fix.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub artifact_changes: Vec<SarifArtifactChange>,
}

/// Artifact change (file modification).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifactChange {
    /// Location of the artifact to change.
    pub artifact_location: SarifArtifactLocation,

    /// Replacements to make.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub replacements: Vec<SarifReplacement>,
}

/// Replacement (delete + insert).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifReplacement {
    /// Region to delete.
    pub deleted_region: SarifRegion,

    /// Content to insert.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inserted_content: Option<SarifArtifactContent>,
}

/// Invocation details.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifInvocation {
    /// Whether the invocation completed successfully.
    pub execution_successful: bool,

    /// Working directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<SarifArtifactLocation>,

    /// Start time (ISO 8601).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time_utc: Option<String>,

    /// End time (ISO 8601).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time_utc: Option<String>,
}

/// Property bag for additional metadata.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifPropertyBag {
    /// Additional properties.
    #[serde(flatten)]
    pub properties: HashMap<String, serde_json::Value>,
}

impl SarifPropertyBag {
    /// Create a new empty property bag.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a property.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Serialize) {
        if let Ok(v) = serde_json::to_value(value) {
            self.properties.insert(key.into(), v);
        }
    }
}

impl SarifReport {
    /// Create a SARIF report from a scan report.
    #[must_use]
    pub fn from_scan_report(report: &ScanReport) -> Self {
        let version = env!("CARGO_PKG_VERSION");

        // Collect unique rules from findings
        let mut rules_map: HashMap<String, SarifReportingDescriptor> = HashMap::new();

        for finding in &report.findings {
            let rule_id = finding
                .rule_id
                .clone()
                .unwrap_or_else(|| finding.extractor_id.clone());

            let rule_key = rule_id.clone();
            rules_map.entry(rule_key).or_insert_with(|| SarifReportingDescriptor {
                id: rule_id.clone(),
                name: Some(humanize_rule_id(&rule_id)),
                short_description: finding.reason.as_ref().map(SarifMessage::text),
                full_description: None,
                help_uri: Some(format!(
                    "https://github.com/Dicklesworthstone/destructive_command_guard/blob/master/docs/rules/{}.md",
                    rule_id.replace([':', '.'], "/")
                )),
                default_configuration: Some(SarifReportingConfiguration {
                    level: Some(finding.severity.into()),
                    enabled: Some(true),
                }),
                properties: None,
            });
        }

        let rules: Vec<_> = rules_map.into_values().collect();

        // Convert findings to results
        let results: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.decision != ScanDecision::Allow) // Only include warns/denies
            .map(finding_to_result)
            .collect();

        Self {
            schema: SARIF_SCHEMA.to_string(),
            version: SARIF_VERSION.to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifToolComponent {
                        name: "dcg".to_string(),
                        version: Some(version.to_string()),
                        semantic_version: Some(version.to_string()),
                        information_uri: Some(DCG_INFO_URI.to_string()),
                        rules,
                    },
                },
                results,
                invocations: Some(vec![SarifInvocation {
                    execution_successful: true,
                    working_directory: std::env::current_dir().ok().map(|p| {
                        SarifArtifactLocation {
                            uri: p.display().to_string(),
                            uri_base_id: None,
                        }
                    }),
                    start_time_utc: None,
                    end_time_utc: None,
                }]),
            }],
        }
    }
}

/// Convert a scan finding to a SARIF result.
fn finding_to_result(finding: &ScanFinding) -> SarifResult {
    let rule_id = finding
        .rule_id
        .clone()
        .unwrap_or_else(|| finding.extractor_id.clone());

    let level = match finding.decision {
        ScanDecision::Deny => SarifLevel::Error,
        ScanDecision::Warn => SarifLevel::Warning,
        ScanDecision::Allow => SarifLevel::Note,
    };

    let message = finding.reason.clone().unwrap_or_else(|| {
        format!(
            "Destructive command detected: {}",
            finding.extracted_command
        )
    });

    let mut properties = SarifPropertyBag::new();
    properties.insert("extractor_id", &finding.extractor_id);
    properties.insert("extracted_command", &finding.extracted_command);
    properties.insert("decision", format!("{:?}", finding.decision));

    // Build location
    let location = SarifLocation {
        physical_location: Some(SarifPhysicalLocation {
            artifact_location: SarifArtifactLocation {
                uri: finding.file.clone(),
                uri_base_id: Some("%SRCROOT%".to_string()),
            },
            region: Some(SarifRegion {
                start_line: Some(finding.line),
                start_column: finding.col,
                end_line: Some(finding.line),
                end_column: None,
                snippet: Some(SarifArtifactContent {
                    text: finding.extracted_command.clone(),
                }),
            }),
        }),
        message: None,
    };

    // Build fix suggestion if available
    let fixes = finding.suggestion.as_ref().map_or_else(Vec::new, |s| {
        vec![SarifFix {
            description: SarifMessage::text(s),
            artifact_changes: vec![],
        }]
    });

    SarifResult {
        rule_id,
        level,
        message: SarifMessage::text(message),
        locations: vec![location],
        code_flows: vec![],
        fixes,
        properties: Some(properties),
    }
}

/// Convert a rule ID like "git.force-push" to "Git Force Push".
fn humanize_rule_id(rule_id: &str) -> String {
    rule_id
        .split(['.', ':', '-', '_'])
        .map(|word| {
            let mut chars: Vec<char> = word.chars().collect();
            if let Some(first) = chars.first_mut() {
                *first = first.to_ascii_uppercase();
            }
            chars.into_iter().collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{ScanDecision, ScanFinding, ScanReport, ScanSeverity, ScanSummary};

    fn mock_finding(decision: ScanDecision, severity: ScanSeverity) -> ScanFinding {
        ScanFinding {
            file: "Dockerfile".to_string(),
            line: 23,
            col: Some(5),
            extractor_id: "dockerfile.run".to_string(),
            extracted_command: "rm -rf /".to_string(),
            decision,
            severity,
            rule_id: Some("core.filesystem:recursive-delete-root".to_string()),
            reason: Some("Recursively deletes the entire filesystem".to_string()),
            suggestion: Some("Use a specific path instead of root".to_string()),
        }
    }

    fn mock_report() -> ScanReport {
        ScanReport {
            schema_version: 1,
            summary: ScanSummary {
                files_scanned: 5,
                files_skipped: 0,
                commands_extracted: 2,
                findings_total: 2,
                decisions: crate::scan::ScanDecisionCounts::default(),
                severities: crate::scan::ScanSeverityCounts::default(),
                max_findings_reached: false,
                elapsed_ms: None,
            },
            findings: vec![
                mock_finding(ScanDecision::Deny, ScanSeverity::Error),
                mock_finding(ScanDecision::Warn, ScanSeverity::Warning),
            ],
        }
    }

    #[test]
    fn test_sarif_schema_compliance() {
        let report = mock_report();
        let sarif = SarifReport::from_scan_report(&report);

        assert_eq!(sarif.version, "2.1.0");
        assert!(sarif.schema.contains("sarif-schema-2.1.0"));
        assert_eq!(sarif.runs.len(), 1);
    }

    #[test]
    fn test_sarif_tool_info() {
        let report = mock_report();
        let sarif = SarifReport::from_scan_report(&report);

        let driver = &sarif.runs[0].tool.driver;
        assert_eq!(driver.name, "dcg");
        assert!(driver.version.is_some());
        assert!(driver.information_uri.is_some());
    }

    #[test]
    fn test_sarif_results_exclude_allow() {
        let mut report = mock_report();
        report
            .findings
            .push(mock_finding(ScanDecision::Allow, ScanSeverity::Info));

        let sarif = SarifReport::from_scan_report(&report);

        // Should only include Deny and Warn, not Allow
        assert_eq!(sarif.runs[0].results.len(), 2);
    }

    #[test]
    fn test_sarif_severity_mapping() {
        assert_eq!(SarifLevel::from(ScanSeverity::Error), SarifLevel::Error);
        assert_eq!(SarifLevel::from(ScanSeverity::Warning), SarifLevel::Warning);
        assert_eq!(SarifLevel::from(ScanSeverity::Info), SarifLevel::Note);
    }

    #[test]
    fn test_sarif_location_info() {
        let report = mock_report();
        let sarif = SarifReport::from_scan_report(&report);

        let result = &sarif.runs[0].results[0];
        assert!(!result.locations.is_empty());

        let loc = &result.locations[0];
        let phys = loc.physical_location.as_ref().unwrap();
        assert_eq!(phys.artifact_location.uri, "Dockerfile");

        let region = phys.region.as_ref().unwrap();
        assert_eq!(region.start_line, Some(23));
        assert_eq!(region.start_column, Some(5));
    }

    #[test]
    fn test_sarif_rules_populated() {
        let report = mock_report();
        let sarif = SarifReport::from_scan_report(&report);

        let rules = &sarif.runs[0].tool.driver.rules;
        assert!(!rules.is_empty());
        assert!(
            rules
                .iter()
                .any(|r| r.id == "core.filesystem:recursive-delete-root")
        );
    }

    #[test]
    fn test_sarif_fix_suggestions() {
        let report = mock_report();
        let sarif = SarifReport::from_scan_report(&report);

        let result = &sarif.runs[0].results[0];
        assert!(!result.fixes.is_empty());
        assert!(result.fixes[0].description.text.contains("specific path"));
    }

    #[test]
    fn test_sarif_json_valid() {
        let report = mock_report();
        let sarif = SarifReport::from_scan_report(&report);

        let json = serde_json::to_string_pretty(&sarif).unwrap();
        assert!(json.contains("\"version\": \"2.1.0\""));
        assert!(json.contains("\"$schema\""));
        assert!(json.contains("\"runs\""));
    }

    #[test]
    fn test_humanize_rule_id() {
        assert_eq!(humanize_rule_id("git.force-push"), "Git Force Push");
        assert_eq!(
            humanize_rule_id("core.filesystem:recursive-delete"),
            "Core Filesystem Recursive Delete"
        );
        assert_eq!(
            humanize_rule_id("docker_system_prune"),
            "Docker System Prune"
        );
    }
}
