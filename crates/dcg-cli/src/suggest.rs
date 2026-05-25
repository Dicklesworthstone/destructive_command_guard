#![allow(clippy::missing_const_for_fn)]
//! Suggest-allowlist clustering and pattern generation utilities.
//!
//! This module clusters similar denied commands and generates conservative regex
//! patterns for allowlist suggestions. It prioritizes specificity over generality
//! to avoid allowing destructive command variants.
//!
//! # Pattern Generation Strategy
//!
//! Given a cluster of similar commands, generate a regex pattern that:
//! - Matches all commands in the cluster
//! - Stays as specific as possible
//! - Uses token anchoring and explicit alternation over wildcards
//! - Avoids broad `.*` patterns that could allow destructive variants
//!
//! # Confidence and Risk Assessment
//!
//! Each suggestion includes:
//! - **Confidence tier**: Based on frequency, consistency, and path clustering
//! - **Risk level**: Based on command type and potential for misuse
//! - **Path patterns**: Common directories where the command was blocked

use crate::normalize::strip_wrapper_prefixes;
use regex::{Regex, escape as regex_escape};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Default similarity threshold for clustering (Jaccard over token sets).
const DEFAULT_SIMILARITY_THRESHOLD: f32 = 0.30;

/// Maximum number of alternations before using character class patterns.
const MAX_ALTERNATION_COUNT: usize = 10;

/// Minimum frequency for high confidence suggestions.
const HIGH_CONFIDENCE_MIN_FREQUENCY: usize = 10;

/// Minimum frequency for medium confidence suggestions.
const MEDIUM_CONFIDENCE_MIN_FREQUENCY: usize = 5;

/// Minimum path consistency ratio for path-specific suggestions.
const PATH_CLUSTER_THRESHOLD: f32 = 0.7;

/// Minimum literal prefix length before a single token can be generalized.
const MIN_SHARED_TOKEN_PREFIX_LEN: usize = 4;

// ============================================================================
// Confidence and Risk Assessment Types
// ============================================================================

/// Confidence tier for allowlist suggestions.
///
/// Higher confidence means the suggestion is more likely to be a legitimate
/// pattern that should be allowlisted rather than a false positive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceTier {
    /// High confidence: command is frequently blocked, consistent pattern,
    /// and/or has been manually allowed before.
    High,
    /// Medium confidence: moderate frequency or partial pattern consistency.
    Medium,
    /// Low confidence: infrequent or inconsistent pattern.
    Low,
}

impl ConfidenceTier {
    /// Returns the tier as a string for display.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    /// Returns a numeric score (0.0-1.0) for sorting.
    #[must_use]
    pub const fn score(&self) -> f32 {
        match self {
            Self::High => 1.0,
            Self::Medium => 0.6,
            Self::Low => 0.3,
        }
    }
}

impl std::fmt::Display for ConfidenceTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Risk level for allowlist suggestions.
///
/// Indicates how dangerous it would be to allow this pattern.
/// Higher risk means the pattern could potentially match destructive commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Low risk: safe command types like read-only operations.
    Low,
    /// Medium risk: commands with limited destructive potential.
    Medium,
    /// High risk: commands that could cause significant damage if misused.
    High,
}

impl RiskLevel {
    /// Returns the level as a string for display.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    /// Returns a numeric score (0.0-1.0) for sorting (higher = riskier).
    #[must_use]
    pub const fn score(&self) -> f32 {
        match self {
            Self::Low => 0.2,
            Self::Medium => 0.5,
            Self::High => 0.9,
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Safety decision for an allowlist suggestion.
///
/// `NeverSuggest` patterns are filtered out before suggestions are returned.
/// `RequireConfirmation` patterns may still be shown, but callers should ensure
/// a human explicitly accepts the system-path implication before persisting them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "decision", content = "reason")]
pub enum SuggestionSafetyDecision {
    /// Safe enough for normal suggestion flow.
    Allow,
    /// Can be suggested only with explicit confirmation.
    RequireConfirmation {
        /// Human-readable reason for the confirmation requirement.
        reason: String,
    },
    /// Must not be suggested for allowlisting.
    NeverSuggest {
        /// Human-readable reason for filtering the suggestion.
        reason: String,
    },
}

impl Default for SuggestionSafetyDecision {
    fn default() -> Self {
        Self::Allow
    }
}

impl SuggestionSafetyDecision {
    /// Returns true when this suggestion must be filtered out entirely.
    #[must_use]
    pub const fn is_never_suggest(&self) -> bool {
        matches!(self, Self::NeverSuggest { .. })
    }

    /// Returns true when this suggestion requires explicit confirmation.
    #[must_use]
    pub const fn requires_confirmation(&self) -> bool {
        matches!(self, Self::RequireConfirmation { .. })
    }

    /// Returns the safety reason, if this decision carries one.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Allow => None,
            Self::RequireConfirmation { reason } | Self::NeverSuggest { reason } => {
                Some(reason.as_str())
            }
        }
    }
}

/// Reason why a command is being suggested for allowlisting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuggestionReason {
    /// Command was blocked many times.
    HighFrequency,
    /// Command was blocked in the same directories consistently.
    PathClustered,
    /// Command was blocked but then allowed via bypass.
    ManuallyBypassed,
    /// Command matches a common safe pattern.
    SafePatternMatch,
}

impl SuggestionReason {
    /// Returns the reason as a string for display.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::HighFrequency => "high_frequency",
            Self::PathClustered => "path_clustered",
            Self::ManuallyBypassed => "manually_bypassed",
            Self::SafePatternMatch => "safe_pattern_match",
        }
    }

    /// Returns a human-readable description.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::HighFrequency => "Blocked many times across sessions",
            Self::PathClustered => "Consistently blocked in specific directories",
            Self::ManuallyBypassed => "Blocked but then allowed manually",
            Self::SafePatternMatch => "Matches a known safe command pattern",
        }
    }
}

impl std::fmt::Display for SuggestionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Path pattern information for path-specific allowlisting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathPattern {
    /// Common path prefix or glob pattern.
    pub pattern: String,
    /// Number of occurrences in this path.
    pub occurrence_count: usize,
    /// Whether this is a project directory (contains .git, package.json, etc.).
    pub is_project_dir: bool,
}

/// Enhanced allowlist suggestion with confidence, risk, and path information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistSuggestion {
    /// The cluster of similar commands this suggestion is based on.
    pub cluster: CommandCluster,
    /// Confidence tier for this suggestion.
    pub confidence: ConfidenceTier,
    /// Risk level for this suggestion.
    pub risk: RiskLevel,
    /// Primary reason for the suggestion.
    pub reason: SuggestionReason,
    /// Additional contributing reasons.
    pub contributing_factors: Vec<SuggestionReason>,
    /// Path patterns where the command was blocked (for path-specific allowlisting).
    pub path_patterns: Vec<PathPattern>,
    /// Whether this suggestion is suitable for path-specific allowlisting.
    pub suggest_path_specific: bool,
    /// Number of times the command was manually bypassed after being blocked.
    pub bypass_count: usize,
    /// Safety decision for the proposed allowlist pattern.
    #[serde(default)]
    pub safety: SuggestionSafetyDecision,
    /// Overall score (0.0-1.0) combining confidence and inverse risk.
    pub score: f32,
}

impl AllowlistSuggestion {
    /// Create a new suggestion from a cluster with basic analysis.
    #[must_use]
    pub fn from_cluster(cluster: CommandCluster) -> Self {
        let confidence = calculate_confidence_tier(cluster.frequency, cluster.unique_count);
        let risk = assess_risk_level(&cluster.commands);
        let reason = determine_primary_reason(cluster.frequency, false, &[]);
        let safety = check_suggestion_safety(&cluster.proposed_pattern, risk);
        let score =
            apply_safety_score_adjustment(calculate_suggestion_score(confidence, risk), &safety);

        Self {
            cluster,
            confidence,
            risk,
            reason,
            contributing_factors: Vec::new(),
            path_patterns: Vec::new(),
            suggest_path_specific: false,
            bypass_count: 0,
            safety,
            score,
        }
    }

    /// Enhance the suggestion with path information.
    pub fn with_path_analysis(mut self, working_dirs: &[String]) -> Self {
        let (patterns, suggest_path_specific) = analyze_path_patterns(working_dirs);
        self.path_patterns = patterns;
        self.suggest_path_specific = suggest_path_specific;

        if suggest_path_specific
            && !self
                .contributing_factors
                .contains(&SuggestionReason::PathClustered)
        {
            self.contributing_factors
                .push(SuggestionReason::PathClustered);
            // Path clustering increases confidence
            if self.confidence == ConfidenceTier::Low {
                self.confidence = ConfidenceTier::Medium;
            }
        }

        self.reason = determine_primary_reason(
            self.cluster.frequency,
            self.bypass_count > 0,
            &self.path_patterns,
        );
        self.score = apply_safety_score_adjustment(
            calculate_suggestion_score(self.confidence, self.risk),
            &self.safety,
        );
        self
    }

    /// Set bypass count and update analysis.
    pub fn with_bypass_count(mut self, count: usize) -> Self {
        self.bypass_count = count;
        if count > 0 {
            self.contributing_factors
                .push(SuggestionReason::ManuallyBypassed);
            // Manual bypass significantly increases confidence
            self.confidence = ConfidenceTier::High;
            self.reason = SuggestionReason::ManuallyBypassed;
        }
        self.score = apply_safety_score_adjustment(
            calculate_suggestion_score(self.confidence, self.risk),
            &self.safety,
        );
        self
    }
}

// ============================================================================
// Confidence and Risk Calculation Functions
// ============================================================================

/// Calculate confidence tier based on frequency and pattern consistency.
#[must_use]
pub fn calculate_confidence_tier(frequency: usize, unique_variants: usize) -> ConfidenceTier {
    // High frequency with consistent pattern = high confidence
    if frequency >= HIGH_CONFIDENCE_MIN_FREQUENCY {
        // Check for pattern consistency (ratio of frequency to unique variants)
        let consistency_ratio = if unique_variants > 0 {
            #[allow(clippy::cast_precision_loss)]
            {
                frequency as f32 / unique_variants as f32
            }
        } else {
            0.0
        };

        if consistency_ratio >= 2.0 {
            return ConfidenceTier::High;
        }
        return ConfidenceTier::Medium;
    }

    if frequency >= MEDIUM_CONFIDENCE_MIN_FREQUENCY {
        return ConfidenceTier::Medium;
    }

    ConfidenceTier::Low
}

/// Assess risk level based on command content.
#[must_use]
pub fn assess_risk_level(commands: &[String]) -> RiskLevel {
    // Check for high-risk indicators in any command
    for cmd in commands {
        let lower = cmd.to_lowercase();

        // Critical risk patterns - these should rarely be auto-allowlisted
        if lower.contains("rm -rf")
            || lower.contains("rmdir")
            || lower.contains("drop ")
            || lower.contains("truncate ")
            || lower.contains("delete ")
            || lower.contains("--force")
            || lower.contains("-f ")
            || lower.contains("reset --hard")
            || lower.contains("clean -f")
        {
            return RiskLevel::High;
        }

        // Medium risk patterns
        if lower.contains("rm ")
            || lower.contains("git reset")
            || lower.contains("git checkout")
            || lower.contains("git restore")
            || lower.contains("docker rm")
            || lower.contains("docker rmi")
            || lower.contains("kubectl delete")
            || lower.starts_with("sudo ")
        {
            return RiskLevel::Medium;
        }
    }

    // Low risk - read-only or safe operations
    RiskLevel::Low
}

/// Determine the primary reason for suggesting allowlisting.
#[must_use]
pub fn determine_primary_reason(
    frequency: usize,
    has_bypasses: bool,
    path_patterns: &[PathPattern],
) -> SuggestionReason {
    // Manual bypass is strongest signal
    if has_bypasses {
        return SuggestionReason::ManuallyBypassed;
    }

    // Strong path clustering
    if !path_patterns.is_empty() {
        let total_occurrences: usize = path_patterns.iter().map(|p| p.occurrence_count).sum();
        if let Some(top_pattern) = path_patterns.first() {
            #[allow(clippy::cast_precision_loss)]
            let concentration =
                top_pattern.occurrence_count as f32 / total_occurrences.max(1) as f32;
            if concentration >= PATH_CLUSTER_THRESHOLD {
                return SuggestionReason::PathClustered;
            }
        }
    }

    // Default to frequency-based
    if frequency >= MEDIUM_CONFIDENCE_MIN_FREQUENCY {
        return SuggestionReason::HighFrequency;
    }

    SuggestionReason::HighFrequency
}

/// Calculate overall suggestion score combining confidence and inverse risk.
#[must_use]
pub fn calculate_suggestion_score(confidence: ConfidenceTier, risk: RiskLevel) -> f32 {
    // Higher confidence and lower risk = better score
    let confidence_score = confidence.score();
    let risk_penalty = risk.score();

    // Score = confidence * (1 - risk_weight * risk_score)
    // This gives high-confidence, low-risk suggestions the best scores
    (confidence_score * (1.0 - 0.4 * risk_penalty)).clamp(0.0, 1.0)
}

fn apply_safety_score_adjustment(score: f32, safety: &SuggestionSafetyDecision) -> f32 {
    match safety {
        SuggestionSafetyDecision::Allow => score,
        SuggestionSafetyDecision::RequireConfirmation { .. } => (score * 0.85).clamp(0.0, 1.0),
        SuggestionSafetyDecision::NeverSuggest { .. } => 0.0,
    }
}

/// A suggestion that was removed by the safety filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilteredSuggestion {
    /// Pattern that was rejected.
    pub pattern: String,
    /// Example commands behind the rejected pattern.
    pub example_commands: Vec<String>,
    /// Safety decision with the filter reason.
    pub safety: SuggestionSafetyDecision,
}

/// Result of safety filtering allowlist suggestions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SuggestionSafetyFilterResult {
    /// Suggestions allowed to continue through the suggestion flow.
    pub suggestions: Vec<AllowlistSuggestion>,
    /// Suggestions removed with reasons.
    pub filtered: Vec<FilteredSuggestion>,
}

/// Check whether a generated allowlist pattern is safe to suggest.
#[must_use]
pub fn check_suggestion_safety(pattern: &str, risk: RiskLevel) -> SuggestionSafetyDecision {
    let normalized = normalize_safety_scan_target(pattern);

    if normalized.is_empty() {
        return SuggestionSafetyDecision::NeverSuggest {
            reason: "empty allowlist pattern cannot be suggested safely".to_string(),
        };
    }

    if contains_fork_bomb(pattern) {
        return SuggestionSafetyDecision::NeverSuggest {
            reason: "fork bomb patterns must never be allowlisted automatically".to_string(),
        };
    }

    if targets_root_with_recursive_rm(&normalized) {
        return SuggestionSafetyDecision::NeverSuggest {
            reason: "recursive removal of the filesystem root must never be suggested".to_string(),
        };
    }

    if overwrites_raw_disk(&normalized) {
        return SuggestionSafetyDecision::NeverSuggest {
            reason: "raw disk overwrite patterns must never be suggested".to_string(),
        };
    }

    if formats_block_device(&normalized) {
        return SuggestionSafetyDecision::NeverSuggest {
            reason: "filesystem formatting patterns must never be suggested".to_string(),
        };
    }

    if destroys_database(&normalized) {
        return SuggestionSafetyDecision::NeverSuggest {
            reason: "database-destroying patterns must never be suggested".to_string(),
        };
    }

    if deletes_every_database_row(&normalized) {
        return SuggestionSafetyDecision::NeverSuggest {
            reason: "unbounded DELETE patterns must never be suggested".to_string(),
        };
    }

    if let Some(system_path) = referenced_sensitive_system_path(&normalized) {
        if normalized.contains("rm -rf") || contains_path_wildcard(pattern) {
            return SuggestionSafetyDecision::NeverSuggest {
                reason: format!(
                    "pattern targets sensitive system path `{system_path}` with destructive or broad matching"
                ),
            };
        }

        return SuggestionSafetyDecision::RequireConfirmation {
            reason: format!(
                "pattern references sensitive system path `{system_path}` and requires explicit confirmation"
            ),
        };
    }

    if risk == RiskLevel::High && is_high_risk_destructive_pattern(&normalized) {
        return SuggestionSafetyDecision::NeverSuggest {
            reason: "high-risk destructive patterns must not be suggested for allowlisting"
                .to_string(),
        };
    }

    SuggestionSafetyDecision::Allow
}

/// Remove unsafe allowlist suggestions while returning clear filter reasons.
#[must_use]
pub fn filter_suggestions_for_safety(
    suggestions: Vec<AllowlistSuggestion>,
) -> SuggestionSafetyFilterResult {
    let mut allowed = Vec::with_capacity(suggestions.len());
    let mut filtered = Vec::new();

    for mut suggestion in suggestions {
        let safety = check_suggestion_safety(&suggestion.cluster.proposed_pattern, suggestion.risk);
        suggestion.safety = safety.clone();
        suggestion.score = apply_safety_score_adjustment(suggestion.score, &safety);

        if safety.is_never_suggest() {
            filtered.push(FilteredSuggestion {
                pattern: suggestion.cluster.proposed_pattern,
                example_commands: suggestion.cluster.commands,
                safety,
            });
        } else {
            allowed.push(suggestion);
        }
    }

    SuggestionSafetyFilterResult {
        suggestions: allowed,
        filtered,
    }
}

fn normalize_safety_scan_target(pattern: &str) -> String {
    let mut normalized = pattern.to_ascii_lowercase();
    for (needle, replacement) in [
        (r"\s+", " "),
        (r"\s*", " "),
        (r"\ ", " "),
        (r"\/", "/"),
        (r"\.", "."),
        (r"\-", "-"),
        (r"\*", "*"),
        (r"\|", "|"),
    ] {
        normalized = normalized.replace(needle, replacement);
    }

    let mut out = String::with_capacity(normalized.len());
    for ch in normalized.chars() {
        match ch {
            '^' | '$' | '(' | ')' | '?' | ':' | '\\' => {}
            _ => out.push(ch),
        }
    }

    collapse_whitespace(&out)
}

fn contains_fork_bomb(pattern: &str) -> bool {
    let squashed: String = pattern
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();

    squashed.contains(":(){:|:&};:") || squashed.contains(":|:&")
}

fn targets_root_with_recursive_rm(normalized: &str) -> bool {
    recursive_rm_target(normalized)
        .is_some_and(|target| matches!(target, "/" | "/*" | "/**" | "/." | "/.." | "/.*" | "/.+"))
}

fn recursive_rm_target(normalized: &str) -> Option<&str> {
    let start = normalized.find("rm -rf")? + "rm -rf".len();
    normalized[start..].split_whitespace().next()
}

fn overwrites_raw_disk(normalized: &str) -> bool {
    normalized.contains("dd if=/dev/zero")
        && ["/dev/sd", "/dev/nvme", "/dev/hd", "/dev/vd"]
            .iter()
            .any(|device| normalized.contains(&format!("of={device}")))
}

fn formats_block_device(normalized: &str) -> bool {
    normalized
        .split_whitespace()
        .any(|token| token == "mkfs" || token.starts_with("mkfs."))
}

fn destroys_database(normalized: &str) -> bool {
    normalized.contains("drop database")
        || normalized.contains("drop table")
        || normalized.contains("truncate database")
        || normalized.contains("truncate table")
}

fn deletes_every_database_row(normalized: &str) -> bool {
    normalized.contains("delete from")
        && (normalized.contains("where 1=1") || normalized.contains("where true"))
}

fn referenced_sensitive_system_path(normalized: &str) -> Option<&'static str> {
    [
        "/etc", "/usr", "/bin", "/sbin", "/root", "/dev", "/proc", "/sys", "/boot", "/lib",
        "/lib64", "/var/lib",
    ]
    .into_iter()
    .find(|path| {
        normalized.split_whitespace().any(|token| {
            let token = token.trim_matches(|ch: char| {
                matches!(ch, '"' | '\'' | ';' | ',' | '[' | ']' | '{' | '}')
            });
            token == *path
                || token.starts_with(&format!("{path}/"))
                || token.starts_with(&format!("{path}/*"))
                || token.starts_with(&format!("{path}.*"))
        })
    })
}

fn contains_path_wildcard(pattern: &str) -> bool {
    pattern.contains(".*")
        || pattern.contains(".+")
        || pattern.contains(r"\d+")
        || pattern.contains("[^")
        || pattern.contains("]+")
}

fn is_high_risk_destructive_pattern(normalized: &str) -> bool {
    // Git destructive verbs.
    if normalized.contains("reset --hard")
        || normalized.contains("clean -f")
        || normalized.contains("clean -fd")
        || normalized.contains("branch -d")
        || normalized.contains("push --force")
        || normalized.contains("push -f")
    {
        return true;
    }
    // SQL destructive verbs (already lowercased by the caller).
    if normalized.contains("drop ")
        || normalized.contains("truncate ")
        || normalized.contains("delete ")
    {
        return true;
    }
    // Infrastructure / cloud / orchestration destructive verbs. Without
    // these, a high-frequency `kubectl delete namespace prod` or `terraform
    // destroy` cluster passes the safety filter and is auto-suggested for
    // allowlisting — defeating the entire point of the safety gate. The
    // list is intentionally short and substring-based; the suggestion path
    // already lower-cases input via `normalize_safety_scan_target`.
    let infra_destructive = [
        "kubectl delete",
        "kubectl drain",
        "helm uninstall",
        "helm delete",
        "terraform destroy",
        "terraform apply -auto-approve",
        "pulumi destroy",
        "aws ec2 terminate-instances",
        "aws rds delete-db-instance",
        "aws s3 rm",
        "aws s3api delete-bucket",
        "gcloud compute instances delete",
        "gcloud sql instances delete",
        "gsutil rm -r",
        "az vm delete",
        "az group delete",
        "docker system prune",
        "docker volume prune",
        "podman system prune",
        "kubectl exec",
    ];
    infra_destructive
        .iter()
        .any(|verb| normalized.contains(verb))
}

/// Analyze working directories to find path patterns.
#[must_use]
pub fn analyze_path_patterns(working_dirs: &[String]) -> (Vec<PathPattern>, bool) {
    if working_dirs.is_empty() {
        return (Vec::new(), false);
    }

    // Count occurrences per directory
    let mut dir_counts: HashMap<&str, usize> = HashMap::new();
    for dir in working_dirs {
        *dir_counts.entry(dir.as_str()).or_insert(0) += 1;
    }

    // Find common path prefixes
    let mut prefix_counts: HashMap<String, usize> = HashMap::new();
    for dir in working_dirs {
        // Extract meaningful path components
        let components: Vec<&str> = dir.split('/').filter(|s| !s.is_empty()).collect();

        // Try different prefix lengths
        for len in 1..=components.len().min(5) {
            let prefix = format!("/{}", components[..len].join("/"));
            *prefix_counts.entry(prefix).or_insert(0) += 1;
        }
    }

    // Find the most specific prefix that covers most occurrences
    let total_count = working_dirs.len();
    let mut candidates: Vec<(String, PathPattern)> = prefix_counts
        .into_iter()
        .filter(|(_, count)| {
            #[allow(clippy::cast_precision_loss)]
            let coverage = *count as f32 / total_count as f32;
            coverage >= 0.5 // At least 50% coverage
        })
        .map(|(prefix, count)| {
            let is_project_dir = is_likely_project_dir(&prefix);
            let pattern = path_allowlist_pattern(&prefix, working_dirs);
            (
                prefix,
                PathPattern {
                    pattern,
                    occurrence_count: count,
                    is_project_dir,
                },
            )
        })
        .collect();

    // Sort by occurrence count (descending) then by specificity (longer = more specific)
    candidates.sort_by(|(a_prefix, a), (b_prefix, b)| {
        b.occurrence_count
            .cmp(&a.occurrence_count)
            .then_with(|| b_prefix.len().cmp(&a_prefix.len()))
    });

    // Deduplicate: keep only the most specific pattern for each coverage level
    let mut seen_prefixes: HashSet<String> = HashSet::new();
    candidates.retain(|(prefix, _)| {
        // Skip if a more specific pattern with similar coverage exists
        for seen in &seen_prefixes {
            if prefix.starts_with(seen.as_str()) || seen.starts_with(prefix) {
                return false;
            }
        }
        seen_prefixes.insert(prefix.clone());
        true
    });

    let mut patterns: Vec<PathPattern> =
        candidates.into_iter().map(|(_, pattern)| pattern).collect();

    // Take top 3 patterns
    patterns.truncate(3);

    // Determine if path-specific allowlisting is recommended
    #[allow(clippy::cast_precision_loss)]
    let suggest_path_specific = patterns.first().is_some_and(|p| {
        let coverage = p.occurrence_count as f32 / total_count as f32;
        coverage >= PATH_CLUSTER_THRESHOLD && p.is_project_dir
    });

    (patterns, suggest_path_specific)
}

/// Convert a common directory prefix into an allowlist path pattern.
fn path_allowlist_pattern(prefix: &str, working_dirs: &[String]) -> String {
    let prefix_with_sep = format!("{prefix}/");
    let has_descendants = working_dirs
        .iter()
        .any(|dir| dir != prefix && dir.starts_with(&prefix_with_sep));

    if has_descendants {
        format!("{prefix}/*")
    } else {
        prefix.to_string()
    }
}

/// Check if a path is likely a project directory.
#[must_use]
fn is_likely_project_dir(path: &str) -> bool {
    // Common project directory indicators
    let project_indicators = [
        "/home/",
        "/Users/",
        "/data/projects/",
        "/workspace/",
        "/repo/",
        "/repos/",
        "/src/",
        "/code/",
        "/projects/",
    ];

    // Paths that are NOT project directories
    let non_project_paths = [
        "/tmp", "/var/tmp", "/etc", "/usr", "/bin", "/sbin", "/root", "/",
    ];

    for non_project in non_project_paths {
        if path == non_project || path.starts_with(&format!("{non_project}/")) {
            return false;
        }
    }

    for indicator in project_indicators {
        if path.starts_with(indicator) || path.contains(indicator) {
            return true;
        }
    }

    // Check for common project-related path components
    let path_lower = path.to_lowercase();
    path_lower.contains("project")
        || path_lower.contains("workspace")
        || path_lower.contains("repo")
        || path_lower.contains("/src/")
        || path_lower.contains("/code/")
}

// ============================================================================
// Enhanced Clustering with Path and Bypass Analysis
// ============================================================================

/// Entry with path and bypass information for enhanced analysis.
#[derive(Debug, Clone)]
pub struct CommandEntryInfo {
    /// The command string.
    pub command: String,
    /// Working directory where the command was blocked.
    pub working_dir: String,
    /// Whether this command was later bypassed.
    pub was_bypassed: bool,
}

/// Generate enhanced suggestions from command entries with full analysis.
#[must_use]
pub fn generate_enhanced_suggestions(
    entries: &[CommandEntryInfo],
    min_frequency: usize,
) -> Vec<AllowlistSuggestion> {
    if entries.is_empty() {
        return Vec::new();
    }

    // Group by command with frequency and working dirs
    let mut command_data: HashMap<String, (usize, Vec<String>, bool)> = HashMap::new();
    for entry in entries {
        let data = command_data
            .entry(entry.command.clone())
            .or_insert((0, Vec::new(), false));
        data.0 += 1; // frequency
        data.1.push(entry.working_dir.clone()); // working dirs
        if entry.was_bypassed {
            data.2 = true; // bypass signal for this command
        }
    }

    // Convert to format for clustering
    let commands: Vec<(String, usize)> = command_data
        .iter()
        .filter(|(_, (freq, _, _))| *freq >= min_frequency)
        .map(|(cmd, (freq, _, _))| (cmd.clone(), *freq))
        .collect();

    if commands.is_empty() {
        return Vec::new();
    }

    // Generate clusters
    let clusters = cluster_denied_commands(&commands, 1);

    // Enhance clusters with path and bypass information
    let mut suggestions: Vec<AllowlistSuggestion> = clusters
        .into_iter()
        .map(|cluster| {
            // Collect working dirs for all commands in this cluster
            let working_dirs: Vec<String> = cluster
                .commands
                .iter()
                .filter_map(|cmd| command_data.get(cmd))
                .flat_map(|(_, dirs, _)| dirs.clone())
                .collect();

            // Calculate total bypass count for cluster
            let bypass_count: usize = cluster
                .commands
                .iter()
                .filter_map(|cmd| command_data.get(cmd))
                .filter(|(_, _, was_bypassed)| *was_bypassed)
                .count();

            AllowlistSuggestion::from_cluster(cluster)
                .with_path_analysis(&working_dirs)
                .with_bypass_count(bypass_count)
        })
        .collect();

    suggestions = filter_suggestions_for_safety(suggestions).suggestions;

    // Sort by score (descending)
    suggestions.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    suggestions
}

/// Filter suggestions by confidence tier.
#[must_use]
pub fn filter_by_confidence(
    suggestions: Vec<AllowlistSuggestion>,
    tier: ConfidenceTier,
) -> Vec<AllowlistSuggestion> {
    suggestions
        .into_iter()
        .filter(|s| s.confidence == tier)
        .collect()
}

/// Filter suggestions by risk level.
#[must_use]
pub fn filter_by_risk(
    suggestions: Vec<AllowlistSuggestion>,
    level: RiskLevel,
) -> Vec<AllowlistSuggestion> {
    suggestions
        .into_iter()
        .filter(|s| s.risk == level)
        .collect()
}

// ============================================================================
// Original Types and Functions
// ============================================================================

/// Output cluster of similar commands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandCluster {
    /// Original commands in the cluster (deduplicated, stable order).
    pub commands: Vec<String>,
    /// Normalized commands in the cluster (deduplicated, stable order).
    pub normalized: Vec<String>,
    /// Proposed regex pattern covering the cluster.
    pub proposed_pattern: String,
    /// Total frequency across all commands in the cluster.
    pub frequency: usize,
    /// Unique command variants in the cluster.
    pub unique_count: usize,
}

// ============================================================================
// GeneratedPattern: Conservative pattern generation from command clusters
// ============================================================================

/// A generated pattern with metadata about its specificity and coverage.
///
/// This struct is produced by [`generate_pattern_from_cluster`] and includes
/// information about how well the pattern matches the input commands.
///
/// # Example
///
/// ```
/// use dcg_cli::suggest::generate_pattern_from_cluster;
///
/// let commands = vec![
///     "npm run build".to_string(),
///     "npm run test".to_string(),
///     "npm run lint".to_string(),
/// ];
/// let pattern = generate_pattern_from_cluster(&commands);
/// assert!(pattern.matches_all);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct GeneratedPattern {
    /// The generated regex pattern string.
    pub regex: String,
    /// Specificity score from 0.0 (very broad) to 1.0 (very specific).
    /// Higher scores indicate patterns that are less likely to match
    /// unintended commands.
    pub specificity_score: f32,
    /// Whether the pattern successfully matches all input commands.
    pub matches_all: bool,
    /// Example commands that this pattern matches (from the input).
    pub example_matches: Vec<String>,
}

/// Public allowlist-generalization result for similar command families.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeneralizedPattern {
    /// Conservative regex pattern that covers the matched commands.
    pub pattern: String,
    /// Deduplicated command examples matched by the pattern.
    pub matched_commands: Vec<String>,
    /// Confidence score from 0.0 to 1.0 based on pattern specificity.
    pub confidence: f64,
}

/// Generalize a group of related commands into one conservative regex pattern.
///
/// Returns `None` when there is fewer than two unique commands, when the
/// commands cannot be represented by a valid regex, or when the generated
/// pattern does not cover every command in the input.
#[must_use]
pub fn generalize_commands(commands: &[String]) -> Option<GeneralizedPattern> {
    let unique_commands = deduplicate_commands(commands);
    if unique_commands.len() < 2 {
        return None;
    }

    let generated = generate_pattern_from_cluster(&unique_commands);
    if generated.regex.is_empty() || !generated.matches_all {
        return None;
    }

    Some(GeneralizedPattern {
        pattern: generated.regex,
        matched_commands: unique_commands,
        confidence: f64::from(generated.specificity_score),
    })
}

/// Generate a conservative regex pattern from a cluster of similar commands.
///
/// This function implements the pattern generation strategy:
///
/// 1. Find common prefix and suffix tokens
/// 2. Segment the token stream
/// 3. Classify variable segments (enumeration vs constrained pattern)
/// 4. Build regex with anchors
/// 5. Validate the generated regex against all cluster members
///
/// # Pattern Generation Rules
///
/// - Prefer token anchoring and explicit alternation over wildcards
/// - Avoid `.*` unless the segment is clearly non-destructive
/// - Use `\s+` for whitespace to prevent partial matches
/// - Enumerate known values when count is small (< 10)
/// - Never generalize paths or flags unless identical across cluster
///
/// # Example
///
/// ```
/// use dcg_cli::suggest::generate_pattern_from_cluster;
///
/// // Commands with common structure but variable last token
/// let commands = vec![
///     "npm run build".to_string(),
///     "npm run test".to_string(),
///     "npm run lint".to_string(),
/// ];
/// let pattern = generate_pattern_from_cluster(&commands);
///
/// // Pattern should be specific with explicit alternation
/// assert!(pattern.matches_all);
/// assert!(pattern.specificity_score > 0.5);
/// ```
#[must_use]
pub fn generate_pattern_from_cluster(commands: &[String]) -> GeneratedPattern {
    if commands.is_empty() {
        return GeneratedPattern {
            regex: String::new(),
            specificity_score: 0.0,
            matches_all: true,
            example_matches: Vec::new(),
        };
    }

    // Deduplicate commands while preserving order
    let unique_commands = deduplicate_commands(commands);

    // Single command: return exact match pattern
    if unique_commands.len() == 1 {
        let regex = format!("^{}$", regex_escape(&unique_commands[0]));
        return GeneratedPattern {
            regex,
            specificity_score: 1.0,
            matches_all: true,
            example_matches: unique_commands,
        };
    }

    // Tokenize all commands
    let tokenized: Vec<Vec<&str>> = unique_commands
        .iter()
        .map(|cmd| cmd.split_whitespace().collect())
        .collect();

    // Find common prefix tokens
    let prefix_len = find_common_prefix_length(&tokenized);

    // Find common suffix tokens
    let suffix_len = find_common_suffix_length(&tokenized, prefix_len);

    // Build the pattern from segments
    let regex = build_segmented_pattern(&tokenized, prefix_len, suffix_len);

    // Validate and calculate specificity
    let (matches_all, example_matches) =
        validate_pattern_against_commands(&regex, &unique_commands);
    let specificity_score = calculate_pattern_specificity(&regex, unique_commands.len());

    GeneratedPattern {
        regex,
        specificity_score,
        matches_all,
        example_matches,
    }
}

/// Deduplicate commands while preserving order.
fn deduplicate_commands(commands: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::with_capacity(commands.len());
    for cmd in commands {
        if seen.insert(cmd.clone()) {
            result.push(cmd.clone());
        }
    }
    result
}

/// Find the number of common prefix tokens across all tokenized commands.
fn find_common_prefix_length(tokenized: &[Vec<&str>]) -> usize {
    if tokenized.is_empty() {
        return 0;
    }

    let min_len = tokenized.iter().map(Vec::len).min().unwrap_or(0);
    let first = &tokenized[0];

    for (i, token) in first.iter().enumerate().take(min_len) {
        if !tokenized.iter().all(|t| t.get(i) == Some(token)) {
            return i;
        }
    }
    min_len
}

/// Find the number of common suffix tokens across all tokenized commands.
fn find_common_suffix_length(tokenized: &[Vec<&str>], prefix_len: usize) -> usize {
    if tokenized.is_empty() {
        return 0;
    }

    let min_len = tokenized.iter().map(Vec::len).min().unwrap_or(0);
    if min_len <= prefix_len {
        return 0;
    }

    let first = &tokenized[0];
    let first_len = first.len();

    for i in 0..(min_len - prefix_len) {
        let token = first[first_len - 1 - i];
        let all_match = tokenized.iter().all(|t| {
            let idx = t.len() - 1 - i;
            t.get(idx) == Some(&token)
        });
        if !all_match {
            return i;
        }
    }
    min_len - prefix_len
}

/// Build a segmented pattern from tokenized commands.
fn build_segmented_pattern(
    tokenized: &[Vec<&str>],
    prefix_len: usize,
    suffix_len: usize,
) -> String {
    if tokenized.is_empty() {
        return String::new();
    }

    let mut parts = Vec::new();

    // Add common prefix
    if prefix_len > 0 {
        let prefix_tokens: Vec<&str> = tokenized[0][..prefix_len].to_vec();
        for token in prefix_tokens {
            parts.push(regex_escape(token));
        }
    }

    // Handle variable middle section
    let first = &tokenized[0];
    let first_len = first.len();
    let middle_start = prefix_len;
    let middle_end = first_len.saturating_sub(suffix_len);

    if middle_start < middle_end {
        // Collect all unique middle sections
        let mut middle_variants: Vec<String> = Vec::new();
        let mut seen_middles = HashSet::new();

        for tokens in tokenized {
            let tokens_len = tokens.len();
            let var_end = tokens_len.saturating_sub(suffix_len);
            if middle_start < var_end {
                let middle: Vec<&str> = tokens[middle_start..var_end].to_vec();
                let middle_str = middle.join(" ");
                if seen_middles.insert(middle_str.clone()) {
                    middle_variants.push(middle_str);
                }
            }
        }

        if !middle_variants.is_empty() {
            if middle_variants.len() == 1 {
                // Single variant - use exact match
                let escaped: Vec<String> = middle_variants[0]
                    .split_whitespace()
                    .map(regex_escape)
                    .collect();
                parts.extend(escaped);
            } else if let Some(pattern) = build_shared_single_token_pattern(&middle_variants) {
                parts.push(pattern);
            } else if middle_variants.len() <= MAX_ALTERNATION_COUNT {
                parts.push(build_alternation_pattern(&middle_variants));
            } else {
                // Too many variants - use conservative wildcard
                let pattern = build_conservative_variable_pattern(&middle_variants);
                parts.push(pattern);
            }
        }
    }

    // Add common suffix
    if suffix_len > 0 {
        let suffix_start = first_len - suffix_len;
        let suffix_tokens: Vec<&str> = first[suffix_start..].to_vec();
        for token in suffix_tokens {
            parts.push(regex_escape(token));
        }
    }

    // Join with whitespace pattern and anchor
    format!("^{}$", parts.join(r"\s+"))
}

fn build_alternation_pattern(variants: &[String]) -> String {
    let alternatives: Vec<String> = variants
        .iter()
        .map(|v| {
            v.split_whitespace()
                .map(regex_escape)
                .collect::<Vec<_>>()
                .join(r"\s+")
        })
        .collect();

    let mut sorted_alternatives = alternatives;
    sorted_alternatives.sort();
    format!("(?:{})", sorted_alternatives.join("|"))
}

/// Build a conservative variable pattern for too many variants.
///
/// Instead of using `.*`, we try to be more specific by analyzing the structure
/// of the variants and using character classes where possible.
fn build_conservative_variable_pattern(variants: &[String]) -> String {
    // Analyze the variants to find common structure
    let all_single_token = variants.iter().all(|v| !v.contains(' '));

    if all_single_token {
        if let Some(pattern) = build_shared_single_token_pattern(variants) {
            return pattern;
        }

        // All variants are single tokens - check if they share characteristics
        let all_numeric = variants
            .iter()
            .all(|v| v.chars().all(|c| c.is_ascii_digit()));
        let all_hex = variants.iter().all(|v| {
            v.chars()
                .all(|c| c.is_ascii_hexdigit() || c == '-' || c == '_')
        });
        let all_uuid_like = variants
            .iter()
            .all(|v| v.len() >= 32 && v.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));

        if all_numeric {
            return r"\d+".to_string();
        }
        if all_uuid_like {
            return r"[0-9a-fA-F-]{32,}".to_string();
        }
        if all_hex {
            return r"[0-9a-fA-F_-]+".to_string();
        }

        return build_alternation_pattern(variants);
    }

    build_alternation_pattern(variants)
}

fn build_shared_single_token_pattern(variants: &[String]) -> Option<String> {
    if variants.len() < 2 || !variants.iter().all(|v| !v.is_empty() && !v.contains(' ')) {
        return None;
    }

    let prefix = common_char_prefix(variants);
    if prefix.chars().count() < MIN_SHARED_TOKEN_PREFIX_LEN {
        return None;
    }

    let suffixes: Vec<&str> = variants
        .iter()
        .map(|variant| variant.strip_prefix(&prefix).unwrap_or_default())
        .collect();
    if suffixes.iter().any(|suffix| suffix.is_empty()) {
        return None;
    }

    if prefix.starts_with('/') && !path_prefix_allows_generalization(&prefix) {
        return None;
    }

    if !prefix_allows_generalization(&prefix, &suffixes) {
        return None;
    }

    variable_suffix_pattern(&suffixes).map(|suffix_pattern| {
        let escaped_prefix = regex_escape(&prefix);
        format!("{escaped_prefix}{suffix_pattern}")
    })
}

fn common_char_prefix(values: &[String]) -> String {
    let Some(first) = values.first() else {
        return String::new();
    };

    let mut prefix = String::new();
    for (idx, ch) in first.chars().enumerate() {
        if values
            .iter()
            .skip(1)
            .all(|value| value.chars().nth(idx) == Some(ch))
        {
            prefix.push(ch);
        } else {
            break;
        }
    }
    prefix
}

fn prefix_allows_generalization(prefix: &str, suffixes: &[&str]) -> bool {
    if matches!(prefix.chars().last(), Some(':' | '-' | '_' | '.' | '/')) {
        return true;
    }

    suffixes
        .iter()
        .all(|suffix| suffix.chars().all(|ch| ch.is_ascii_digit()))
}

fn path_prefix_allows_generalization(prefix: &str) -> bool {
    [
        "/tmp/",
        "/var/tmp/",
        "/data/projects/",
        "/workspace/",
        "/repo/",
        "/repos/",
    ]
    .iter()
    .any(|safe_prefix| prefix.starts_with(safe_prefix))
}

fn variable_suffix_pattern(suffixes: &[&str]) -> Option<&'static str> {
    if suffixes
        .iter()
        .all(|suffix| suffix.chars().all(|ch| ch.is_ascii_digit()))
    {
        return Some(r"\d+");
    }

    if suffixes.iter().all(|suffix| {
        !suffix.contains('/')
            && suffix
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':'))
    }) {
        return Some(r"[\w.:-]+");
    }

    None
}

/// Validate that a pattern matches all given commands.
fn validate_pattern_against_commands(pattern: &str, commands: &[String]) -> (bool, Vec<String>) {
    let Ok(regex) = Regex::new(pattern) else {
        return (false, Vec::new());
    };

    let mut matches_all = true;
    let mut example_matches = Vec::new();

    for cmd in commands {
        if regex.is_match(cmd) {
            if example_matches.len() < 3 {
                example_matches.push(cmd.clone());
            }
        } else {
            matches_all = false;
        }
    }

    (matches_all, example_matches)
}

/// Calculate the specificity score of a pattern.
///
/// Higher scores indicate more specific patterns that are less likely to
/// match unintended commands.
fn calculate_pattern_specificity(pattern: &str, command_count: usize) -> f32 {
    let mut score = 1.0_f32;

    // Penalize broad wildcards
    if pattern.contains(".*") {
        score -= 0.4;
    }
    if pattern.contains(".+") {
        score -= 0.3;
    }
    if pattern.contains(r"[\w\s") {
        score -= 0.2;
    }
    if pattern.contains(r"[\w.-]+") {
        score -= 0.15;
    }
    if pattern.contains(r"\d+") {
        score -= 0.15;
    }
    if pattern.contains(r"[\w.:-]+") {
        score -= 0.15;
    }

    // Reward anchoring
    if pattern.starts_with('^') && pattern.ends_with('$') {
        score += 0.1;
    }

    // Reward explicit alternations (but not too many)
    let alternation_count = pattern.matches('|').count();
    if alternation_count > 0 && alternation_count <= MAX_ALTERNATION_COUNT {
        // Small alternations are specific
        score += 0.1;
    } else if alternation_count > MAX_ALTERNATION_COUNT {
        // Too many alternations reduce specificity
        score -= 0.2;
    }

    // Penalize very short patterns (likely too broad)
    if pattern.len() < 10 {
        score -= 0.2;
    }

    // Reward patterns that match exactly the command count (no extras)
    if command_count <= 5 {
        score += 0.1;
    }

    // Clamp to [0.0, 1.0]
    score.clamp(0.0, 1.0)
}

// ============================================================================
// Clustering Implementation
// ============================================================================

#[derive(Debug, Clone)]
struct CommandRecord {
    original: String,
    normalized: String,
    tokens: Vec<String>,
    program: String,
    count: usize,
}

#[derive(Debug, Clone)]
struct TempCluster {
    records: Vec<CommandRecord>,
    rep_tokens: Vec<String>,
}

impl TempCluster {
    fn new(record: CommandRecord) -> Self {
        Self {
            rep_tokens: record.tokens.clone(),
            records: vec![record],
        }
    }

    fn add(&mut self, record: CommandRecord) {
        self.records.push(record);
    }

    fn into_command_cluster(self) -> CommandCluster {
        let mut commands = Vec::new();
        let mut normalized = Vec::new();
        let mut seen_commands = HashSet::new();
        let mut seen_normalized = HashSet::new();
        let mut frequency = 0_usize;

        for record in &self.records {
            frequency = frequency.saturating_add(record.count);
            if seen_commands.insert(record.original.clone()) {
                commands.push(record.original.clone());
            }
            if seen_normalized.insert(record.normalized.clone()) {
                normalized.push(record.normalized.clone());
            }
        }

        let proposed_pattern = build_proposed_pattern(&normalized);
        let unique_count = normalized.len();

        CommandCluster {
            commands,
            normalized,
            proposed_pattern,
            frequency,
            unique_count,
        }
    }
}

/// Cluster denied commands into similarity groups.
///
/// `commands` is a list of (command, count) pairs.
#[must_use]
pub fn cluster_denied_commands(
    commands: &[(String, usize)],
    min_cluster_size: usize,
) -> Vec<CommandCluster> {
    cluster_denied_commands_with_threshold(commands, min_cluster_size, DEFAULT_SIMILARITY_THRESHOLD)
}

fn cluster_denied_commands_with_threshold(
    commands: &[(String, usize)],
    min_cluster_size: usize,
    similarity_threshold: f32,
) -> Vec<CommandCluster> {
    if commands.is_empty() {
        return Vec::new();
    }

    let mut records = Vec::with_capacity(commands.len());
    for (command, count) in commands {
        let normalized = normalize_for_clustering(command);
        let tokens = tokenize_for_similarity(&normalized);
        let program = tokens.first().cloned().unwrap_or_default();
        records.push(CommandRecord {
            original: command.clone(),
            normalized,
            tokens,
            program,
            count: *count,
        });
    }

    let mut groups: HashMap<String, Vec<CommandRecord>> = HashMap::new();
    for record in records {
        groups
            .entry(record.program.clone())
            .or_default()
            .push(record);
    }

    let mut clusters = Vec::new();
    for (_program, group) in groups {
        let mut temp_clusters: Vec<TempCluster> = Vec::new();
        for record in group {
            let mut record_opt = Some(record);
            let mut placed = false;
            for cluster in &mut temp_clusters {
                let record_ref = record_opt.as_ref().expect("record should be present");
                let similarity = jaccard_similarity(&cluster.rep_tokens, &record_ref.tokens);
                if similarity >= similarity_threshold {
                    let record = record_opt.take().expect("record should be present");
                    cluster.add(record);
                    placed = true;
                    break;
                }
            }
            if !placed {
                let record = record_opt.take().expect("record should be present");
                temp_clusters.push(TempCluster::new(record));
            }
        }

        for cluster in temp_clusters {
            if cluster.records.len() >= min_cluster_size {
                clusters.push(cluster.into_command_cluster());
            }
        }
    }

    clusters.sort_by(|a, b| {
        b.frequency
            .cmp(&a.frequency)
            .then_with(|| a.proposed_pattern.cmp(&b.proposed_pattern))
    });

    clusters
}

fn normalize_for_clustering(command: &str) -> String {
    let stripped = strip_wrapper_prefixes(command);
    collapse_whitespace(stripped.normalized.as_ref())
}

fn collapse_whitespace(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut last_was_space = false;
    for ch in input.chars() {
        if ch.is_whitespace() {
            if !last_was_space {
                out.push(' ');
                last_was_space = true;
            }
        } else {
            out.push(ch);
            last_was_space = false;
        }
    }
    out.trim().to_string()
}

fn tokenize_for_similarity(command: &str) -> Vec<String> {
    command
        .split_whitespace()
        .map(str::to_ascii_lowercase)
        .collect()
}

fn jaccard_similarity(a: &[String], b: &[String]) -> f32 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }

    let set_a: HashSet<&str> = a.iter().map(String::as_str).collect();
    let set_b: HashSet<&str> = b.iter().map(String::as_str).collect();

    if set_a.is_empty() && set_b.is_empty() {
        return 1.0;
    }

    let intersection = u32::try_from(set_a.intersection(&set_b).count()).unwrap_or(u32::MAX);
    let union = u32::try_from(set_a.union(&set_b).count()).unwrap_or(u32::MAX);

    if union == 0 {
        0.0
    } else {
        #[allow(clippy::cast_precision_loss)]
        {
            intersection as f32 / union as f32
        }
    }
}

fn build_proposed_pattern(commands: &[String]) -> String {
    if commands.is_empty() {
        return String::new();
    }

    let mut unique = Vec::new();
    let mut seen = HashSet::new();
    for cmd in commands {
        if seen.insert(cmd.clone()) {
            unique.push(cmd.clone());
        }
    }

    if unique.len() == 1 {
        return format!("^{}$", regex_escape(&unique[0]));
    }

    if let Some(generalized) = generalize_commands(&unique) {
        return generalized.pattern;
    }

    format!("^{}$", build_alternation_pattern(&unique))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn denied_entry(command: &str) -> CommandEntryInfo {
        CommandEntryInfo {
            command: command.to_string(),
            working_dir: "/data/projects/dcg".to_string(),
            was_bypassed: false,
        }
    }

    // ========================================================================
    // Safety Filter Tests
    // ========================================================================

    #[test]
    fn safety_filter_removes_recursive_root_delete_suggestions() {
        let entries = vec![
            denied_entry("rm -rf /"),
            denied_entry("rm -rf /"),
            denied_entry("rm -rf /"),
        ];

        let suggestions = generate_enhanced_suggestions(&entries, 3);
        assert!(suggestions.is_empty());

        let result = check_suggestion_safety(r"^rm\s+-rf\s+/$", RiskLevel::High);
        match result {
            SuggestionSafetyDecision::NeverSuggest { reason } => {
                assert!(reason.contains("filesystem root"));
            }
            other => panic!("expected never-suggest decision, got {other:?}"),
        }
    }

    #[test]
    fn safety_filter_removes_database_destroying_suggestions() {
        let decision = check_suggestion_safety(r"^DROP\s+TABLE\s+users$", RiskLevel::High);

        match decision {
            SuggestionSafetyDecision::NeverSuggest { reason } => {
                assert!(reason.contains("database-destroying"));
            }
            other => panic!("expected never-suggest decision, got {other:?}"),
        }
    }

    #[test]
    fn safety_filter_removes_sensitive_path_wildcards() {
        let decision = check_suggestion_safety(r"^rm\s+-rf\s+/etc/cache\d+$", RiskLevel::High);

        match decision {
            SuggestionSafetyDecision::NeverSuggest { reason } => {
                assert!(reason.contains("/etc"));
                assert!(reason.contains("broad"));
            }
            other => panic!("expected never-suggest decision, got {other:?}"),
        }
    }

    #[test]
    fn safety_filter_blocks_high_risk_infra_verbs() {
        // Regression: is_high_risk_destructive_pattern used to only cover
        // git/SQL verbs. A high-frequency `kubectl delete namespace prod`
        // cluster could pass the safety filter and be auto-suggested for
        // allowlisting — exactly the failure mode dcg exists to prevent.
        let infra_destructive_patterns = [
            r"^kubectl\s+delete\s+namespace\s+\w+$",
            r"^kubectl\s+drain\s+\w+$",
            r"^helm\s+uninstall\s+\w+$",
            r"^terraform\s+destroy$",
            r"^terraform\s+apply\s+-auto-approve$",
            r"^pulumi\s+destroy$",
            r"^aws\s+ec2\s+terminate-instances\s+--instance-ids\s+\w+$",
            r"^aws\s+rds\s+delete-db-instance\s+--db-instance-identifier\s+\w+$",
            r"^aws\s+s3\s+rm\s+s3://\w+\s+--recursive$",
            r"^gcloud\s+compute\s+instances\s+delete\s+\w+$",
            r"^az\s+vm\s+delete\s+--name\s+\w+$",
            r"^docker\s+system\s+prune\s+-a$",
        ];
        for pattern in infra_destructive_patterns {
            let decision = check_suggestion_safety(pattern, RiskLevel::High);
            assert!(
                matches!(decision, SuggestionSafetyDecision::NeverSuggest { .. }),
                "infra destructive pattern was NOT classified as NeverSuggest (would be auto-allowlisted!): {pattern} → {decision:?}"
            );
        }
    }

    #[test]
    fn safety_filter_requires_confirmation_for_system_paths() {
        let decision = check_suggestion_safety(r"^cat\s+/etc/hosts$", RiskLevel::Low);

        match decision {
            SuggestionSafetyDecision::RequireConfirmation { reason } => {
                assert!(reason.contains("/etc"));
                assert!(reason.contains("explicit confirmation"));
            }
            other => panic!("expected confirmation decision, got {other:?}"),
        }
    }

    #[test]
    fn safety_filter_allows_namespaced_build_patterns() {
        let decision = check_suggestion_safety(r"^npm\s+run\s+build:[\w.:-]+$", RiskLevel::Low);
        assert_eq!(decision, SuggestionSafetyDecision::Allow);

        let entries = vec![
            denied_entry("npm run build:dev"),
            denied_entry("npm run build:prod"),
            denied_entry("npm run build:staging"),
        ];
        let suggestions = generate_enhanced_suggestions(&entries, 1);

        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].safety, SuggestionSafetyDecision::Allow);
        assert!(suggestions[0].cluster.proposed_pattern.contains("build:"));
    }

    #[test]
    fn safety_filter_result_returns_reasons_for_filtered_patterns() {
        let suggestion = AllowlistSuggestion::from_cluster(CommandCluster {
            commands: vec!["dd if=/dev/zero of=/dev/sda".to_string()],
            normalized: vec!["dd if=/dev/zero of=/dev/sda".to_string()],
            proposed_pattern: r"^dd\s+if=/dev/zero\s+of=/dev/sda$".to_string(),
            frequency: 3,
            unique_count: 1,
        });

        let result = filter_suggestions_for_safety(vec![suggestion]);

        assert!(result.suggestions.is_empty());
        assert_eq!(result.filtered.len(), 1);
        let reason = result.filtered[0]
            .safety
            .reason()
            .expect("filtered suggestion should include a reason");
        assert!(reason.contains("raw disk overwrite"));
    }

    // ========================================================================
    // Clustering Tests
    // ========================================================================

    #[test]
    fn clusters_similar_commands_by_program() {
        let input = vec![
            ("npm run build --production".to_string(), 10),
            ("npm run test --coverage".to_string(), 5),
            ("git status".to_string(), 2),
        ];

        let clusters = cluster_denied_commands(&input, 2);
        assert_eq!(clusters.len(), 1);
        let cluster = &clusters[0];
        assert_eq!(cluster.unique_count, 2);
        assert!(cluster.proposed_pattern.contains("npm"));
        assert!(cluster.proposed_pattern.contains("run"));
    }

    #[test]
    fn respects_min_cluster_size() {
        let input = vec![("git status".to_string(), 1), ("docker ps".to_string(), 1)];

        let clusters = cluster_denied_commands(&input, 2);
        assert!(clusters.is_empty());
    }

    #[test]
    fn proposed_pattern_is_anchored_and_escaped() {
        let input = vec![("echo foo|bar".to_string(), 3)];
        let clusters = cluster_denied_commands(&input, 1);
        assert_eq!(clusters.len(), 1);
        let pattern = &clusters[0].proposed_pattern;
        assert!(pattern.starts_with('^'));
        assert!(pattern.ends_with('$'));
        assert!(pattern.contains("\\|"));
    }

    #[test]
    fn handles_empty_input() {
        let input: Vec<(String, usize)> = vec![];
        let clusters = cluster_denied_commands(&input, 1);
        assert!(clusters.is_empty());
    }

    #[test]
    fn handles_single_command() {
        let input = vec![("git reset --hard".to_string(), 5)];
        let clusters = cluster_denied_commands(&input, 1);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].unique_count, 1);
        assert_eq!(clusters[0].frequency, 5);
        // Single command pattern should be exact match
        assert!(clusters[0].proposed_pattern.starts_with('^'));
        assert!(clusters[0].proposed_pattern.ends_with('$'));
    }

    #[test]
    fn handles_all_different_programs() {
        // Commands with completely different programs don't cluster
        let input = vec![
            ("git status".to_string(), 1),
            ("npm install".to_string(), 1),
            ("docker ps".to_string(), 1),
        ];
        let clusters = cluster_denied_commands(&input, 2);
        assert!(
            clusters.is_empty(),
            "No clusters should form when all programs differ"
        );
    }

    #[test]
    fn strips_wrapper_prefixes_before_clustering() {
        let input = vec![
            ("sudo git reset --hard".to_string(), 3),
            ("git reset --soft".to_string(), 2),
        ];
        let clusters = cluster_denied_commands(&input, 2);
        assert_eq!(clusters.len(), 1);
        // Both commands should cluster together after stripping sudo
        assert!(
            clusters[0]
                .normalized
                .iter()
                .all(|n| !n.starts_with("sudo"))
        );
    }

    #[test]
    fn accumulates_frequency_across_cluster() {
        let input = vec![
            ("git reset --hard".to_string(), 10),
            ("git reset --soft".to_string(), 5),
            ("git reset --mixed".to_string(), 3),
        ];
        let clusters = cluster_denied_commands(&input, 1);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].frequency, 18);
    }

    #[test]
    fn deduplicates_identical_commands() {
        let input = vec![("git status".to_string(), 5), ("git status".to_string(), 3)];
        let clusters = cluster_denied_commands(&input, 1);
        assert_eq!(clusters.len(), 1);
        // unique_count should be 1 since same command
        assert_eq!(clusters[0].unique_count, 1);
        // frequency should be sum
        assert_eq!(clusters[0].frequency, 8);
    }

    #[test]
    fn sorts_clusters_by_frequency_descending() {
        let input = vec![
            ("npm run build".to_string(), 1),
            ("npm run test".to_string(), 1),
            ("git status".to_string(), 50),
            ("git log".to_string(), 50),
        ];
        let clusters = cluster_denied_commands(&input, 2);
        assert_eq!(clusters.len(), 2);
        // git cluster has higher frequency (100) so comes first
        assert!(clusters[0].commands[0].starts_with("git"));
        assert!(clusters[1].commands[0].starts_with("npm"));
    }

    #[test]
    fn jaccard_similarity_identical_tokens() {
        let a = vec!["git".to_string(), "reset".to_string(), "--hard".to_string()];
        let b = vec!["git".to_string(), "reset".to_string(), "--hard".to_string()];
        let similarity = jaccard_similarity(&a, &b);
        assert!(
            (similarity - 1.0).abs() < 0.001,
            "Identical tokens should have similarity 1.0"
        );
    }

    #[test]
    fn jaccard_similarity_no_overlap() {
        let a = vec!["git".to_string(), "status".to_string()];
        let b = vec!["npm".to_string(), "install".to_string()];
        let similarity = jaccard_similarity(&a, &b);
        assert!(
            (similarity - 0.0).abs() < 0.001,
            "No overlap should have similarity 0.0"
        );
    }

    #[test]
    fn jaccard_similarity_empty_sets() {
        let a: Vec<String> = vec![];
        let b: Vec<String> = vec![];
        let similarity = jaccard_similarity(&a, &b);
        assert!(
            (similarity - 1.0).abs() < 0.001,
            "Empty sets should have similarity 1.0"
        );
    }

    #[test]
    fn proposed_pattern_alternation_for_multiple_commands() {
        let input = vec![("echo hello".to_string(), 1), ("echo world".to_string(), 1)];
        let clusters = cluster_denied_commands(&input, 2);
        assert_eq!(clusters.len(), 1);
        // Pattern should use alternation for multiple variants
        let pattern = &clusters[0].proposed_pattern;
        assert!(pattern.contains("(?:"));
        assert!(pattern.contains('|'));
    }

    #[test]
    fn handles_commands_with_special_regex_chars() {
        let input = vec![("echo $HOME".to_string(), 1), ("echo $PATH".to_string(), 1)];
        let clusters = cluster_denied_commands(&input, 2);
        assert_eq!(clusters.len(), 1);
        // Pattern should escape the $
        let pattern = &clusters[0].proposed_pattern;
        assert!(pattern.contains("\\$"));
    }

    #[test]
    fn normalize_collapses_whitespace() {
        let input = vec![
            ("git   reset   --hard".to_string(), 1),
            ("git reset --hard".to_string(), 1),
        ];
        let clusters = cluster_denied_commands(&input, 1);
        assert_eq!(clusters.len(), 1);
        // Both should normalize to same and dedupe
        assert_eq!(clusters[0].unique_count, 1);
    }

    // ========================================================================
    // Pattern Generation Tests (git_safety_guard-wb2m)
    // ========================================================================

    #[test]
    fn generate_pattern_empty_input() {
        let commands: Vec<String> = vec![];
        let pattern = generate_pattern_from_cluster(&commands);
        assert!(pattern.regex.is_empty());
        assert!(pattern.matches_all);
        assert!((pattern.specificity_score - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn generate_pattern_single_command() {
        let commands = vec!["git status".to_string()];
        let pattern = generate_pattern_from_cluster(&commands);
        assert_eq!(pattern.regex, "^git status$");
        assert!(pattern.matches_all);
        assert!((pattern.specificity_score - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn generate_pattern_common_prefix() {
        let commands = vec![
            "npm run build".to_string(),
            "npm run test".to_string(),
            "npm run lint".to_string(),
        ];
        let pattern = generate_pattern_from_cluster(&commands);

        // Should start with common prefix
        assert!(pattern.regex.starts_with("^npm"));
        assert!(pattern.regex.contains("run"));

        // Should match all commands
        assert!(pattern.matches_all);

        // Should use alternation for variable part
        assert!(pattern.regex.contains('|'));

        // Verify it actually matches
        let re = Regex::new(&pattern.regex).unwrap();
        for cmd in &commands {
            assert!(re.is_match(cmd), "Pattern should match: {cmd}");
        }
    }

    #[test]
    fn generate_pattern_common_prefix_and_suffix() {
        let commands = vec![
            "docker run --rm alpine".to_string(),
            "docker run --rm ubuntu".to_string(),
            "docker run --rm debian".to_string(),
        ];
        let pattern = generate_pattern_from_cluster(&commands);

        // Should match all commands
        assert!(pattern.matches_all);

        // Verify it actually matches
        let re = Regex::new(&pattern.regex).unwrap();
        for cmd in &commands {
            assert!(re.is_match(cmd), "Pattern should match: {cmd}");
        }
    }

    #[test]
    fn generate_pattern_does_not_match_destructive_variants() {
        let commands = vec![
            "npm run build".to_string(),
            "npm run test".to_string(),
            "npm run lint".to_string(),
        ];
        let pattern = generate_pattern_from_cluster(&commands);
        let re = Regex::new(&pattern.regex).unwrap();

        // Should NOT match destructive variants
        assert!(
            !re.is_match("rm -rf /"),
            "Pattern should NOT match destructive commands"
        );
        assert!(
            !re.is_match("npm run delete-everything"),
            "Pattern should NOT match non-cluster commands"
        );
    }

    #[test]
    fn generate_pattern_handles_special_chars() {
        let commands = vec![
            "echo $HOME".to_string(),
            "echo $PATH".to_string(),
            "echo $USER".to_string(),
        ];
        let pattern = generate_pattern_from_cluster(&commands);

        // Pattern should be valid regex (escaped special chars)
        let re = Regex::new(&pattern.regex);
        assert!(re.is_ok(), "Pattern should be valid regex");

        // Should match all commands
        assert!(pattern.matches_all);
    }

    #[test]
    fn generate_pattern_specificity_score() {
        // Exact match should have high specificity
        let exact = generate_pattern_from_cluster(&["git status".to_string()]);
        assert!(
            exact.specificity_score >= 0.9,
            "Exact match should have high specificity"
        );

        // Small alternation should have reasonable specificity
        let small = generate_pattern_from_cluster(&[
            "npm run build".to_string(),
            "npm run test".to_string(),
        ]);
        assert!(
            small.specificity_score >= 0.7,
            "Small alternation should have good specificity"
        );
    }

    #[test]
    fn generate_pattern_deduplicates_commands() {
        let commands = vec![
            "git status".to_string(),
            "git status".to_string(),
            "git status".to_string(),
        ];
        let pattern = generate_pattern_from_cluster(&commands);

        // Should be exact match, not alternation
        assert_eq!(pattern.regex, "^git status$");
        assert!(pattern.matches_all);
    }

    #[test]
    fn generate_pattern_variable_segment_analysis() {
        // Commands with numeric variants
        let numeric_commands = vec![
            "fetch page 1".to_string(),
            "fetch page 2".to_string(),
            "fetch page 3".to_string(),
            "fetch page 4".to_string(),
            "fetch page 5".to_string(),
        ];
        let pattern = generate_pattern_from_cluster(&numeric_commands);
        assert!(pattern.matches_all);

        let re = Regex::new(&pattern.regex).unwrap();
        for cmd in &numeric_commands {
            assert!(re.is_match(cmd), "Pattern should match: {cmd}");
        }
    }

    #[test]
    fn generate_pattern_anchored() {
        let commands = vec!["npm run build".to_string(), "npm run test".to_string()];
        let pattern = generate_pattern_from_cluster(&commands);

        // Pattern should be anchored
        assert!(pattern.regex.starts_with('^'));
        assert!(pattern.regex.ends_with('$'));
    }

    #[test]
    fn generate_pattern_respects_max_alternation_count() {
        // Create more variants than MAX_ALTERNATION_COUNT
        let commands: Vec<String> = (0..15).map(|i| format!("cmd arg{i}")).collect();
        let pattern = generate_pattern_from_cluster(&commands);

        // Should still match all commands
        assert!(pattern.matches_all);

        // Specificity should be lower due to broader pattern
        assert!(pattern.specificity_score < 1.0);
    }

    #[test]
    fn generalizes_namespaced_build_variants() {
        let commands = vec![
            "npm run build:dev".to_string(),
            "npm run build:prod".to_string(),
            "npm run build:staging".to_string(),
        ];

        let generalized = generalize_commands(&commands).expect("commands should generalize");

        assert_eq!(generalized.matched_commands, commands);
        assert!(generalized.pattern.contains("build:"));
        assert!(
            generalized.pattern.contains(r"[\w.:-]+"),
            "pattern should use a constrained token suffix, got {}",
            generalized.pattern
        );
        assert!(generalized.confidence > 0.0);

        let re = Regex::new(&generalized.pattern).unwrap();
        assert!(re.is_match("npm run build:qa"));
        assert!(!re.is_match("npm run delete-everything"));
    }

    #[test]
    fn proposed_cluster_pattern_uses_generalized_regex() {
        let input = vec![
            ("npm run build:dev".to_string(), 4),
            ("npm run build:prod".to_string(), 3),
        ];

        let clusters = cluster_denied_commands(&input, 2);

        assert_eq!(clusters.len(), 1);
        assert!(clusters[0].proposed_pattern.contains("build:"));
        assert!(clusters[0].proposed_pattern.contains(r"[\w.:-]+"));
    }

    #[test]
    fn generalizes_temp_path_numeric_suffixes() {
        let commands = vec![
            "rm -rf /tmp/cache1".to_string(),
            "rm -rf /tmp/cache2".to_string(),
            "rm -rf /tmp/cache42".to_string(),
        ];

        let pattern = generate_pattern_from_cluster(&commands);

        assert!(pattern.matches_all);
        assert!(
            pattern.regex.contains(r"/tmp/cache\d+"),
            "temp path suffix should be constrained, got {}",
            pattern.regex
        );

        let re = Regex::new(&pattern.regex).unwrap();
        assert!(re.is_match("rm -rf /tmp/cache99"));
        assert!(!re.is_match("rm -rf /etc/cache99"));
    }

    #[test]
    fn sensitive_paths_are_not_wildcarded() {
        let commands = vec![
            "rm -rf /etc/cache1".to_string(),
            "rm -rf /etc/cache2".to_string(),
        ];

        let pattern = generate_pattern_from_cluster(&commands);

        assert!(pattern.matches_all);
        assert!(
            !pattern.regex.contains(r"/etc/cache\d+"),
            "sensitive paths should remain enumerated, got {}",
            pattern.regex
        );
        assert!(pattern.regex.contains('|'));
    }

    #[test]
    fn single_command_has_no_generalized_pattern() {
        let commands = vec!["git reset --hard".to_string()];

        assert!(generalize_commands(&commands).is_none());
    }

    #[test]
    fn enhanced_suggestions_count_bypass_signal_once_per_command() {
        let entries = vec![
            CommandEntryInfo {
                command: "npm run build".to_string(),
                working_dir: "/repo".to_string(),
                was_bypassed: true,
            },
            CommandEntryInfo {
                command: "npm run build".to_string(),
                working_dir: "/repo".to_string(),
                was_bypassed: true,
            },
            CommandEntryInfo {
                command: "npm run build".to_string(),
                working_dir: "/repo".to_string(),
                was_bypassed: true,
            },
        ];

        let suggestions = generate_enhanced_suggestions(&entries, 3);

        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].cluster.frequency, 3);
        assert_eq!(suggestions[0].bypass_count, 1);
        assert_eq!(suggestions[0].reason, SuggestionReason::ManuallyBypassed);
    }

    #[test]
    fn common_prefix_length_calculation() {
        let tokenized = vec![
            vec!["npm", "run", "build"],
            vec!["npm", "run", "test"],
            vec!["npm", "run", "lint"],
        ];
        let prefix_len = find_common_prefix_length(&tokenized);
        assert_eq!(prefix_len, 2); // "npm run" is common
    }

    #[test]
    fn common_suffix_length_calculation() {
        let tokenized = vec![
            vec!["docker", "run", "--rm", "alpine"],
            vec!["docker", "exec", "--rm", "alpine"],
        ];
        let prefix_len = find_common_prefix_length(&tokenized);
        let suffix_len = find_common_suffix_length(&tokenized, prefix_len);
        assert_eq!(prefix_len, 1); // "docker" is common prefix
        assert_eq!(suffix_len, 2); // "--rm alpine" is common suffix
    }
}
