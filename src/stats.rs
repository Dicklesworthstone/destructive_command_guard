//! Statistics collection and display for dcg.
//!
//! This module provides functionality to:
//! - Parse log files (both text and JSON formats)
//! - Aggregate statistics by pack
//! - Display statistics for a configurable time period

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default time period for statistics (30 days in seconds).
pub const DEFAULT_PERIOD_SECS: u64 = 30 * 24 * 60 * 60;

/// A single log entry parsed from the log file.
#[derive(Debug, Clone)]
pub struct ParsedLogEntry {
    pub timestamp: u64,
    pub decision: Decision,
    pub pack_id: Option<String>,
    pub pattern_name: Option<String>,
    pub command: Option<String>,
    pub allowlist_override: bool,
}

/// Decision type from log entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    Warn,
    Bypass,
}

/// Statistics for a single pack.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PackStats {
    pub pack_id: String,
    pub blocks: u64,
    pub allows: u64,
    pub bypasses: u64,
    pub warns: u64,
}

impl PackStats {
    #[allow(clippy::missing_const_for_fn)] // String is not const-compatible
    fn new(pack_id: String) -> Self {
        Self {
            pack_id,
            blocks: 0,
            allows: 0,
            bypasses: 0,
            warns: 0,
        }
    }

    #[allow(clippy::missing_const_for_fn)]
    fn record(&mut self, decision: Decision, allowlist_override: bool) {
        match decision {
            Decision::Deny if allowlist_override => self.bypasses += 1,
            Decision::Deny => self.blocks += 1,
            Decision::Allow => self.allows += 1,
            Decision::Warn => self.warns += 1,
            Decision::Bypass => self.bypasses += 1,
        }
    }
}

/// Aggregated statistics across all packs.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AggregatedStats {
    pub period_start: u64,
    pub period_end: u64,
    pub total_entries: u64,
    pub total_blocks: u64,
    pub total_allows: u64,
    pub total_bypasses: u64,
    pub total_warns: u64,
    pub by_pack: Vec<PackStats>,
}

impl AggregatedStats {
    /// Calculate totals from pack stats.
    pub fn calculate_totals(&mut self) {
        self.total_blocks = self.by_pack.iter().map(|p| p.blocks).sum();
        self.total_allows = self.by_pack.iter().map(|p| p.allows).sum();
        self.total_bypasses = self.by_pack.iter().map(|p| p.bypasses).sum();
        self.total_warns = self.by_pack.iter().map(|p| p.warns).sum();
    }
}

/// JSON log entry format (for structured logging).
#[derive(Debug, Deserialize)]
struct JsonLogEntry {
    timestamp: String,
    decision: String,
    #[serde(default)]
    pack_id: Option<String>,
    #[serde(default)]
    pattern_name: Option<String>,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    allowlist_layer: Option<String>,
}

/// Parse a log file and return aggregated statistics.
///
/// # Arguments
/// * `path` - Path to the log file
/// * `period_secs` - Time period in seconds (from now backwards)
///
/// # Errors
/// Returns an error if the file cannot be read.
pub fn parse_log_file(path: &Path, period_secs: u64) -> std::io::Result<AggregatedStats> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let cutoff = now.saturating_sub(period_secs);

    let mut pack_stats: HashMap<String, PackStats> = HashMap::new();
    let mut total_entries = 0u64;

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();

        if trimmed.is_empty() {
            continue;
        }

        // Try to parse as JSON first
        if trimmed.starts_with('{') {
            if let Some(entry) = parse_json_entry(trimmed, cutoff) {
                total_entries += 1;
                let pack_id = entry
                    .pack_id
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string());
                let stats = pack_stats
                    .entry(pack_id.clone())
                    .or_insert_with(|| PackStats::new(pack_id));
                stats.record(entry.decision, entry.allowlist_override);
            }
            continue;
        }

        // Try to parse as text format from structured logging
        // Format: [timestamp] DECISION rule_id "command" -- reason
        if let Some(entry) = parse_text_entry(trimmed, cutoff) {
            total_entries += 1;
            let pack_id = entry
                .pack_id
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            let stats = pack_stats
                .entry(pack_id.clone())
                .or_insert_with(|| PackStats::new(pack_id));
            stats.record(entry.decision, entry.allowlist_override);
            continue;
        }

        // Try to parse as simple log format from hook.rs
        // Format: [timestamp] [pack] reason
        if let Some((ts, pack)) = parse_simple_header(trimmed) {
            if ts >= cutoff {
                total_entries += 1;
                let stats = pack_stats
                    .entry(pack.clone())
                    .or_insert_with(|| PackStats::new(pack));
                stats.record(Decision::Deny, false);
            }
        }
    }

    // Sort packs by block count descending
    let mut by_pack: Vec<PackStats> = pack_stats.into_values().collect();
    by_pack.sort_by(|a, b| b.blocks.cmp(&a.blocks));

    let mut stats = AggregatedStats {
        period_start: cutoff,
        period_end: now,
        total_entries,
        by_pack,
        ..Default::default()
    };
    stats.calculate_totals();

    Ok(stats)
}

/// Parse a JSON log entry.
fn parse_json_entry(line: &str, cutoff: u64) -> Option<ParsedLogEntry> {
    let entry: JsonLogEntry = serde_json::from_str(line).ok()?;

    // Parse timestamp (ISO 8601 or Unix epoch)
    let timestamp = parse_timestamp(&entry.timestamp)?;
    if timestamp < cutoff {
        return None;
    }

    let decision = match entry.decision.to_lowercase().as_str() {
        "allow" => Decision::Allow,
        "deny" => Decision::Deny,
        "warn" => Decision::Warn,
        _ => return None,
    };

    Some(ParsedLogEntry {
        timestamp,
        decision,
        pack_id: entry.pack_id,
        pattern_name: entry.pattern_name,
        command: entry.command,
        allowlist_override: entry.allowlist_layer.is_some(),
    })
}

/// Parse a text log entry from structured logging.
fn parse_text_entry(line: &str, cutoff: u64) -> Option<ParsedLogEntry> {
    // Format: [timestamp] DECISION rule_id "command" -- reason
    if !line.starts_with('[') {
        return None;
    }

    let close_bracket = line.find(']')?;
    let timestamp_str = &line[1..close_bracket];
    let timestamp = parse_timestamp(timestamp_str)?;
    if timestamp < cutoff {
        return None;
    }

    let rest = line[close_bracket + 1..].trim();
    let mut parts = rest.split_whitespace();

    let decision_str = parts.next()?;
    let decision = match decision_str.to_uppercase().as_str() {
        "ALLOW" => Decision::Allow,
        "DENY" => Decision::Deny,
        "WARN" => Decision::Warn,
        _ => return None,
    };

    // Extract rule_id (pack_id:pattern_name)
    let rule_id = parts.next();
    let (pack_id, pattern_name) = rule_id
        .filter(|r| r.contains(':'))
        .map_or((None, None), |r| {
            let mut split = r.splitn(2, ':');
            (
                split.next().map(String::from),
                split.next().map(String::from),
            )
        });

    // Check for allowlist marker
    let allowlist_override = line.contains("[allowlist:");

    Some(ParsedLogEntry {
        timestamp,
        decision,
        pack_id,
        pattern_name,
        command: None,
        allowlist_override,
    })
}

/// Parse simple log header from hook.rs format.
/// Format: [timestamp] [pack] reason
fn parse_simple_header(line: &str) -> Option<(u64, String)> {
    if !line.starts_with('[') {
        return None;
    }

    // Find first timestamp bracket
    let first_close = line.find(']')?;
    let timestamp_str = &line[1..first_close];
    let timestamp = parse_timestamp(timestamp_str)?;

    // Find second bracket (pack)
    let rest = &line[first_close + 1..].trim_start();
    if !rest.starts_with('[') {
        return None;
    }
    let pack_close = rest.find(']')?;
    let pack = rest[1..pack_close].to_string();

    // Skip "budget" entries
    if pack == "budget" {
        return None;
    }

    Some((timestamp, pack))
}

/// Parse a timestamp string into Unix epoch seconds.
fn parse_timestamp(s: &str) -> Option<u64> {
    // Try parsing as Unix epoch (just digits)
    if let Ok(ts) = s.parse::<u64>() {
        return Some(ts);
    }

    // Try parsing as ISO 8601 / RFC 3339
    // Format: 2024-01-15T10:30:00Z or 2024-01-15T10:30:00+00:00
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return u64::try_from(dt.timestamp()).ok();
    }

    // Try without timezone (assume UTC)
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return u64::try_from(dt.and_utc().timestamp()).ok();
    }

    None
}

/// Format statistics for display.
#[must_use]
pub fn format_stats_pretty(stats: &AggregatedStats, period_days: u64) -> String {
    use std::fmt::Write;

    let mut output = String::new();

    let _ = writeln!(output, "Pack Statistics (last {period_days} days):");
    let _ = writeln!(output);

    if stats.by_pack.is_empty() {
        let _ = writeln!(output, "  No events recorded in this period.");
        return output;
    }

    // Calculate column widths
    let max_pack_len = stats
        .by_pack
        .iter()
        .map(|p| p.pack_id.len())
        .max()
        .unwrap_or(10)
        .max(10);

    // Header
    let _ = writeln!(
        output,
        "  {:<width$}  {:>7}  {:>7}  {:>8}  {:>6}",
        "Pack",
        "Blocks",
        "Allows",
        "Bypasses",
        "Warns",
        width = max_pack_len
    );
    let _ = writeln!(
        output,
        "  {:-<width$}  {:->7}  {:->7}  {:->8}  {:->6}",
        "",
        "",
        "",
        "",
        "",
        width = max_pack_len
    );

    // Pack rows
    for pack in &stats.by_pack {
        let _ = writeln!(
            output,
            "  {:<width$}  {:>7}  {:>7}  {:>8}  {:>6}",
            pack.pack_id,
            pack.blocks,
            pack.allows,
            pack.bypasses,
            pack.warns,
            width = max_pack_len
        );
    }

    // Total row
    let _ = writeln!(
        output,
        "  {:-<width$}  {:->7}  {:->7}  {:->8}  {:->6}",
        "",
        "",
        "",
        "",
        "",
        width = max_pack_len
    );
    let _ = writeln!(
        output,
        "  {:<width$}  {:>7}  {:>7}  {:>8}  {:>6}",
        "Total",
        stats.total_blocks,
        stats.total_allows,
        stats.total_bypasses,
        stats.total_warns,
        width = max_pack_len
    );

    output
}

/// Format statistics as JSON.
#[must_use]
pub fn format_stats_json(stats: &AggregatedStats) -> String {
    serde_json::to_string_pretty(stats).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_timestamp_unix() {
        assert_eq!(parse_timestamp("1704672000"), Some(1_704_672_000));
    }

    #[test]
    fn test_parse_timestamp_iso8601() {
        assert!(parse_timestamp("2024-01-15T10:30:00Z").is_some());
    }

    #[test]
    fn test_parse_simple_header() {
        let line = "[1704672000] [core.git] git reset --hard is dangerous";
        let result = parse_simple_header(line);
        assert!(result.is_some());
        let (ts, pack) = result.unwrap();
        assert_eq!(ts, 1_704_672_000);
        assert_eq!(pack, "core.git");
    }

    #[test]
    fn test_parse_json_entry() {
        let json = r#"{"timestamp":"1704672000","decision":"deny","pack_id":"core.git","pattern_name":"reset-hard"}"#;
        let entry = parse_json_entry(json, 0);
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.decision, Decision::Deny);
        assert_eq!(entry.pack_id, Some("core.git".to_string()));
    }

    #[test]
    fn test_parse_text_entry() {
        let line =
            "[2024-01-15T10:30:00Z] DENY core.git:reset-hard \"git reset --hard\" -- dangerous";
        let entry = parse_text_entry(line, 0);
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.decision, Decision::Deny);
        assert_eq!(entry.pack_id, Some("core.git".to_string()));
    }

    #[test]
    fn test_aggregate_stats() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "[1704672000] [core.git] blocked git reset --hard").unwrap();
        writeln!(file, "  Command: git reset --hard HEAD").unwrap();
        writeln!(file).unwrap();
        writeln!(file, "[1704672100] [core.rm] blocked rm -rf").unwrap();
        writeln!(file, "  Command: rm -rf /").unwrap();
        writeln!(file).unwrap();
        writeln!(file, "[1704672000] [core.git] blocked git push --force").unwrap();
        writeln!(file, "  Command: git push --force").unwrap();

        // Use very long period to include all entries
        let stats = parse_log_file(file.path(), u64::MAX).unwrap();
        assert_eq!(stats.total_entries, 3);
        assert_eq!(stats.total_blocks, 3);
    }

    #[test]
    fn test_format_stats_pretty() {
        let stats = AggregatedStats {
            period_start: 0,
            period_end: 1_704_672_000,
            total_entries: 5,
            total_blocks: 3,
            total_allows: 1,
            total_bypasses: 1,
            total_warns: 0,
            by_pack: vec![
                PackStats {
                    pack_id: "core.git".to_string(),
                    blocks: 2,
                    allows: 1,
                    bypasses: 0,
                    warns: 0,
                },
                PackStats {
                    pack_id: "core.rm".to_string(),
                    blocks: 1,
                    allows: 0,
                    bypasses: 1,
                    warns: 0,
                },
            ],
        };

        let output = format_stats_pretty(&stats, 30);
        assert!(output.contains("core.git"));
        assert!(output.contains("core.rm"));
        assert!(output.contains("Total"));
    }
}
