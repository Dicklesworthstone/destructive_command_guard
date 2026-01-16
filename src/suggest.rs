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

use crate::normalize::strip_wrapper_prefixes;
use regex::{Regex, escape as regex_escape};
use std::collections::{HashMap, HashSet};

/// Default similarity threshold for clustering (Jaccard over token sets).
const DEFAULT_SIMILARITY_THRESHOLD: f32 = 0.30;

/// Maximum number of alternations before using character class patterns.
const MAX_ALTERNATION_COUNT: usize = 10;

/// Output cluster of similar commands.
#[derive(Debug, Clone, PartialEq, Eq)]
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
/// use destructive_command_guard::suggest::generate_pattern_from_cluster;
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
/// use destructive_command_guard::suggest::generate_pattern_from_cluster;
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
            } else if middle_variants.len() <= MAX_ALTERNATION_COUNT {
                // Multiple variants - use alternation
                let alternatives: Vec<String> = middle_variants
                    .iter()
                    .map(|v| {
                        v.split_whitespace()
                            .map(regex_escape)
                            .collect::<Vec<_>>()
                            .join(r"\s+")
                    })
                    .collect();

                // Sort for deterministic output
                let mut sorted_alternatives = alternatives;
                sorted_alternatives.sort();

                let alternation = format!("(?:{})", sorted_alternatives.join("|"));
                parts.push(alternation);
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

/// Build a conservative variable pattern for too many variants.
///
/// Instead of using `.*`, we try to be more specific by analyzing the structure
/// of the variants and using character classes where possible.
fn build_conservative_variable_pattern(variants: &[String]) -> String {
    // Analyze the variants to find common structure
    let all_single_token = variants.iter().all(|v| !v.contains(' '));

    if all_single_token {
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

        // Default: word characters only (no spaces)
        return r"[\w.-]+".to_string();
    }

    // Multiple tokens - use word characters with spaces
    r"[\w\s.-]+".to_string()
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
        score -= 0.1;
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
        score -= 0.1;
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

    let mut parts = Vec::with_capacity(unique.len());
    for cmd in unique {
        parts.push(regex_escape(&cmd));
    }

    format!("^(?:{})$", parts.join("|"))
}

#[cfg(test)]
mod tests {
    use super::*;

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
