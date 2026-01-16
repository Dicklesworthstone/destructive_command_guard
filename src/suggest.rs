#![allow(clippy::missing_const_for_fn)]
//! Suggest-allowlist clustering utilities.
//!
//! This module clusters similar denied commands to support allowlist suggestions.
//! It focuses on deterministic grouping with conservative pattern generation.

use crate::normalize::strip_wrapper_prefixes;
use regex::escape as regex_escape;
use std::collections::{HashMap, HashSet};

/// Default similarity threshold for clustering (Jaccard over token sets).
const DEFAULT_SIMILARITY_THRESHOLD: f32 = 0.30;

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

    fn to_command_cluster(self) -> CommandCluster {
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
        let program = tokens.get(0).cloned().unwrap_or_default();
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
        groups.entry(record.program.clone()).or_default().push(record);
    }

    let mut clusters = Vec::new();
    for (_program, group) in groups {
        let mut temp_clusters: Vec<TempCluster> = Vec::new();
        for record in group {
            let mut placed = false;
            for cluster in &mut temp_clusters {
                let similarity = jaccard_similarity(&cluster.rep_tokens, &record.tokens);
                if similarity >= similarity_threshold {
                    cluster.add(record);
                    placed = true;
                    break;
                }
            }
            if !placed {
                temp_clusters.push(TempCluster::new(record));
            }
        }

        for cluster in temp_clusters {
            if cluster.records.len() >= min_cluster_size {
                clusters.push(cluster.to_command_cluster());
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
        .map(|token| token.to_ascii_lowercase())
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

    let intersection = set_a.intersection(&set_b).count() as f32;
    let union = set_a.union(&set_b).count() as f32;

    if union == 0.0 {
        0.0
    } else {
        intersection / union
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
        let input = vec![
            ("git status".to_string(), 1),
            ("docker ps".to_string(), 1),
        ];

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
}
