//! Allowlist file parsing and layered loading.
//!
//! This module implements loading of allowlist entries from three layers:
//! - Project: `.dcg/allowlist.toml` at repo root
//! - User: `~/.config/dcg/allowlist.toml`
//! - System: `/etc/dcg/allowlist.toml` (optional)
//!
//! Test override:
//! - `DCG_ALLOWLIST_SYSTEM_PATH` can override the system allowlist path
//!   (useful for hermetic E2E tests).
//!
//! Design goals:
//! - Strongly-typed model (`AllowEntry`, `AllowSelector`)
//! - Robust parsing: invalid TOML or invalid entries must not crash the hook
//! - Explicit, testable layering precedence (project > user > system)

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Allowlist layer identity (used for precedence and diagnostics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AllowlistLayer {
    Project,
    User,
    System,
}

impl AllowlistLayer {
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::User => "user",
            Self::System => "system",
        }
    }
}

/// A stable rule identifier (`pack_id:pattern_name`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuleId {
    pub pack_id: String,
    pub pattern_name: String,
}

impl RuleId {
    /// Parse a `pack_id:pattern_name` rule id.
    ///
    /// Notes:
    /// - This does not validate that the referenced pack/pattern exists.
    /// - Wildcards (e.g., `core.git:*`) are parsed but higher-level validation
    ///   policies are handled by later tasks.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let (pack_id, pattern_name) = s.split_once(':')?;
        let pack_id = pack_id.trim();
        let pattern_name = pattern_name.trim();

        if pack_id.is_empty() || pattern_name.is_empty() {
            return None;
        }

        // Reject whitespace inside identifiers to avoid ambiguous parsing.
        if pack_id.contains(char::is_whitespace) || pattern_name.contains(char::is_whitespace) {
            return None;
        }

        Some(Self {
            pack_id: pack_id.to_string(),
            pattern_name: pattern_name.to_string(),
        })
    }
}

impl std::fmt::Display for RuleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.pack_id, self.pattern_name)
    }
}

/// What an allowlist entry targets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AllowSelector {
    /// Allowlist a specific rule identity (`pack_id:pattern_name`).
    Rule(RuleId),
    /// Allowlist an exact command string (rare, but useful for one-off automation).
    ExactCommand(String),
    /// Allowlist a command prefix (used with a context classifier like "string-argument").
    CommandPrefix(String),
    /// Allowlist by raw regex pattern (requires explicit risk acknowledgement).
    RegexPattern(String),
}

impl AllowSelector {
    #[must_use]
    pub const fn kind_label(&self) -> &'static str {
        match self {
            Self::Rule(_) => "rule",
            Self::ExactCommand(_) => "exact_command",
            Self::CommandPrefix(_) => "command_prefix",
            Self::RegexPattern(_) => "pattern",
        }
    }
}

/// A single allowlist entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowEntry {
    pub selector: AllowSelector,
    pub reason: String,

    // Audit metadata (optional)
    pub added_by: Option<String>,
    pub added_at: Option<String>,
    pub expires_at: Option<String>,

    // Optional match context hint (used for data-only allowlisting)
    pub context: Option<String>,

    // Optional gating
    pub conditions: HashMap<String, String>,
    pub environments: Vec<String>,

    // Safety valve for regex-based allowlisting
    pub risk_acknowledged: bool,
}

/// Structured allowlist parse/load error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowlistError {
    pub layer: AllowlistLayer,
    pub path: PathBuf,
    pub entry_index: Option<usize>,
    pub message: String,
}

/// Parsed allowlist file contents (entries + non-fatal errors).
#[derive(Debug, Clone, Default)]
pub struct AllowlistFile {
    pub entries: Vec<AllowEntry>,
    pub errors: Vec<AllowlistError>,
}

/// A single loaded allowlist layer (with source path).
#[derive(Debug, Clone)]
pub struct LoadedAllowlistLayer {
    pub layer: AllowlistLayer,
    pub path: PathBuf,
    pub file: AllowlistFile,
}

/// All allowlist layers, ordered by precedence (project > user > system).
#[derive(Debug, Clone, Default)]
pub struct LayeredAllowlist {
    pub layers: Vec<LoadedAllowlistLayer>,
}

impl LayeredAllowlist {
    /// Construct a layered allowlist from explicit file paths.
    ///
    /// Any missing path is treated as an empty allowlist for that layer.
    #[must_use]
    pub fn load_from_paths(
        project: Option<PathBuf>,
        user: Option<PathBuf>,
        system: Option<PathBuf>,
    ) -> Self {
        let mut layers: Vec<LoadedAllowlistLayer> = Vec::new();

        if let Some(path) = project {
            layers.push(LoadedAllowlistLayer {
                layer: AllowlistLayer::Project,
                path: path.clone(),
                file: load_allowlist_file(AllowlistLayer::Project, &path),
            });
        }

        if let Some(path) = user {
            layers.push(LoadedAllowlistLayer {
                layer: AllowlistLayer::User,
                path: path.clone(),
                file: load_allowlist_file(AllowlistLayer::User, &path),
            });
        }

        if let Some(path) = system {
            layers.push(LoadedAllowlistLayer {
                layer: AllowlistLayer::System,
                path: path.clone(),
                file: load_allowlist_file(AllowlistLayer::System, &path),
            });
        }

        Self { layers }
    }

    /// Find the first matching rule entry across layers (project > user > system).
    ///
    /// Note: This performs exact rule ID matching without wildcard expansion.
    /// Use `match_rule` for wildcard-aware matching.
    ///
    /// Skips entries that are expired, have unmet conditions, or lack risk ack.
    #[must_use]
    pub fn lookup_rule(&self, rule: &RuleId) -> Option<(&AllowEntry, AllowlistLayer)> {
        for layer in &self.layers {
            for entry in &layer.file.entries {
                // Skip invalid entries
                if !is_entry_valid(entry) {
                    continue;
                }

                if let AllowSelector::Rule(rule_id) = &entry.selector {
                    if rule_id == rule {
                        return Some((entry, layer.layer));
                    }
                }
            }
        }
        None
    }

    /// Find the first allowlist entry that matches a `(pack_id, pattern_name)` match identity.
    ///
    /// Matching supports:
    /// - Exact rule IDs: `core.git:reset-hard`
    /// - Pack-scoped wildcard: `core.git:*` (matches any pattern in that pack)
    ///
    /// An entry is skipped if:
    /// - It has expired (`expires_at` is in the past)
    /// - Its conditions are not met (env vars don't match)
    /// - It's a regex pattern without `risk_acknowledged = true`
    #[must_use]
    pub fn match_rule(&self, pack_id: &str, pattern_name: &str) -> Option<AllowlistHit<'_>> {
        if pack_id == "*" {
            // Never allow global bypass via wildcard pack id.
            return None;
        }

        for layer in &self.layers {
            for entry in &layer.file.entries {
                // Skip entries that are expired, have unmet conditions, or lack risk ack
                if !is_entry_valid(entry) {
                    continue;
                }

                let AllowSelector::Rule(rule_id) = &entry.selector else {
                    continue;
                };

                if rule_id.pack_id != pack_id {
                    continue;
                }

                if rule_id.pattern_name == pattern_name || rule_id.pattern_name == "*" {
                    return Some(AllowlistHit {
                        layer: layer.layer,
                        entry,
                    });
                }
            }
        }

        None
    }
}

/// A successful allowlist match (borrowed view).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowlistHit<'a> {
    pub layer: AllowlistLayer,
    pub entry: &'a AllowEntry,
}

// ============================================================================
// Entry validity checks (expiration, conditions, risk acknowledgement)
// ============================================================================

/// Check if an allowlist entry has expired.
///
/// Returns `true` if the entry has an `expires_at` timestamp that is in the past.
/// Returns `false` if there's no expiration or the timestamp can't be parsed.
///
/// For date-only formats like "2026-01-08", the entry is valid through the entire day
/// (expires at 23:59:59 UTC on that date).
///
/// # Panics
///
/// This function will not panic in practice. The `.expect()` on `and_hms_opt(23, 59, 59)`
/// is safe because 23:59:59 is always a valid time.
#[must_use]
pub fn is_expired(entry: &AllowEntry) -> bool {
    let Some(ref expires_at) = entry.expires_at else {
        return false;
    };

    // Try RFC 3339 first (e.g., "2030-01-01T00:00:00Z" or "2030-01-01T00:00:00+00:00")
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(expires_at) {
        return dt < chrono::Utc::now();
    }

    // Try ISO 8601 without timezone (treat as UTC)
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(expires_at, "%Y-%m-%dT%H:%M:%S") {
        let utc = dt.and_utc();
        return utc < chrono::Utc::now();
    }

    // Try date only (YYYY-MM-DD) - treat as end of day UTC (23:59:59)
    // This matches intuitive semantics: "expires 2026-01-08" means valid through that day
    if let Ok(date) = chrono::NaiveDate::parse_from_str(expires_at, "%Y-%m-%d") {
        let end_of_day = date.and_hms_opt(23, 59, 59).expect("valid time").and_utc();
        return end_of_day < chrono::Utc::now();
    }

    // Invalid timestamp format - treat as expired (fail closed) for safety.
    // This prevents typos like "2025/01/01" from accidentally creating permanent allowlists.
    true
}

/// Check if all conditions on an allowlist entry are satisfied.
///
/// Conditions are a map of `KEY=VALUE` pairs that must match environment variables.
/// All conditions must be satisfied (AND logic).
/// Missing env var means condition is not met.
#[must_use]
pub fn conditions_met(entry: &AllowEntry) -> bool {
    if entry.conditions.is_empty() {
        return true;
    }

    for (key, expected_value) in &entry.conditions {
        match std::env::var(key) {
            Ok(actual_value) if actual_value == *expected_value => {}
            _ => return false,
        }
    }

    true
}

/// Check if a regex pattern entry has required risk acknowledgement.
///
/// Regex patterns are dangerous because they can accidentally allow too much.
/// Entries using `pattern` selector must have `risk_acknowledged = true`.
#[must_use]
pub const fn has_required_risk_ack(entry: &AllowEntry) -> bool {
    match &entry.selector {
        AllowSelector::RegexPattern(_) => entry.risk_acknowledged,
        _ => true, // Non-regex entries don't need acknowledgement
    }
}

/// Check if an allowlist entry is valid for matching.
///
/// An entry is valid if:
/// - It hasn't expired
/// - All conditions are met
/// - Required risk acknowledgement is present (for regex patterns)
#[must_use]
pub fn is_entry_valid(entry: &AllowEntry) -> bool {
    !is_expired(entry) && conditions_met(entry) && has_required_risk_ack(entry)
}

/// Validate and optionally warn about expiration date format.
/// Returns Ok(()) if valid or parseable, Err with message if completely invalid.
///
/// # Errors
///
/// Returns an error if the timestamp is not in a valid ISO 8601 format.
pub fn validate_expiration_date(timestamp: &str) -> Result<(), String> {
    // Try RFC 3339 first (e.g., "2030-01-01T00:00:00Z" or "2030-01-01T00:00:00+00:00")
    if chrono::DateTime::parse_from_rfc3339(timestamp).is_ok() {
        return Ok(());
    }
    // Try ISO 8601 without timezone
    if chrono::NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%S").is_ok() {
        return Ok(());
    }
    // Try date only (YYYY-MM-DD) - treat as midnight UTC
    if chrono::NaiveDate::parse_from_str(timestamp, "%Y-%m-%d").is_ok() {
        return Ok(());
    }
    Err(format!(
        "Invalid expiration date format: '{timestamp}'. \
         Expected ISO 8601 format (e.g., '2030-01-01', '2030-01-01T00:00:00Z')"
    ))
}

/// Validate condition format (KEY=VALUE).
///
/// # Errors
///
/// Returns an error if the condition is not in KEY=VALUE format.
pub fn validate_condition(condition: &str) -> Result<(), String> {
    if condition.contains('=') {
        let parts: Vec<&str> = condition.splitn(2, '=').collect();
        if parts.len() == 2 && !parts[0].trim().is_empty() {
            return Ok(());
        }
    }
    Err(format!(
        "Invalid condition format: '{condition}'. Expected KEY=VALUE format (e.g., 'CI=true')"
    ))
}

/// Load allowlist files using the default locations.
///
/// Missing files are treated as empty allowlists.
/// Invalid TOML is treated as empty for that layer and reported in `errors`.
#[must_use]
pub fn load_default_allowlists() -> LayeredAllowlist {
    let project = std::env::current_dir()
        .ok()
        .and_then(|cwd| find_repo_root(&cwd))
        .map(|root| root.join(".dcg").join("allowlist.toml"));

    let user = dirs::config_dir().map(|d| d.join("dcg").join("allowlist.toml"));

    // System allowlist is optional; keep the fixed path but treat missing as empty.
    // Allow tests to override via env for hermetic E2E (no reliance on real /etc).
    let system = std::env::var("DCG_ALLOWLIST_SYSTEM_PATH").map_or_else(
        |_| Some(PathBuf::from("/etc/dcg/allowlist.toml")),
        |path| {
            let trimmed = path.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(PathBuf::from(trimmed))
            }
        },
    );

    LayeredAllowlist::load_from_paths(project, user, system)
}

fn find_repo_root(start: &Path) -> Option<PathBuf> {
    let mut current = start.to_path_buf();

    loop {
        if current.join(".git").exists() {
            return Some(current);
        }

        if !current.pop() {
            return None;
        }
    }
}

fn load_allowlist_file(layer: AllowlistLayer, path: &Path) -> AllowlistFile {
    if !path.exists() {
        return AllowlistFile::default();
    }

    let content = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            return AllowlistFile {
                entries: Vec::new(),
                errors: vec![AllowlistError {
                    layer,
                    path: path.to_path_buf(),
                    entry_index: None,
                    message: format!("failed to read allowlist file: {e}"),
                }],
            };
        }
    };

    parse_allowlist_toml(layer, path, &content)
}

pub(crate) fn parse_allowlist_toml(
    layer: AllowlistLayer,
    path: &Path,
    content: &str,
) -> AllowlistFile {
    let mut file = AllowlistFile::default();

    let value: toml::Value = match toml::from_str(content) {
        Ok(v) => v,
        Err(e) => {
            file.errors.push(AllowlistError {
                layer,
                path: path.to_path_buf(),
                entry_index: None,
                message: format!("invalid TOML: {e}"),
            });
            return file;
        }
    };

    let Some(root) = value.as_table() else {
        file.errors.push(AllowlistError {
            layer,
            path: path.to_path_buf(),
            entry_index: None,
            message: "allowlist TOML root must be a table".to_string(),
        });
        return file;
    };

    let allow_items = root.get("allow");
    let Some(allow_items) = allow_items else {
        // No entries is fine.
        return file;
    };

    let Some(allow_array) = allow_items.as_array() else {
        file.errors.push(AllowlistError {
            layer,
            path: path.to_path_buf(),
            entry_index: None,
            message: "`allow` must be an array of tables (use [[allow]])".to_string(),
        });
        return file;
    };

    for (idx, item) in allow_array.iter().enumerate() {
        let Some(tbl) = item.as_table() else {
            file.errors.push(AllowlistError {
                layer,
                path: path.to_path_buf(),
                entry_index: Some(idx),
                message: "each [[allow]] entry must be a table".to_string(),
            });
            continue;
        };

        match parse_allow_entry(tbl) {
            Ok(entry) => file.entries.push(entry),
            Err(msg) => file.errors.push(AllowlistError {
                layer,
                path: path.to_path_buf(),
                entry_index: Some(idx),
                message: msg,
            }),
        }
    }

    file
}

fn parse_allow_entry(tbl: &toml::value::Table) -> Result<AllowEntry, String> {
    let reason = match get_string(tbl, "reason") {
        Some(s) if !s.trim().is_empty() => s,
        _ => return Err("missing required field: reason".to_string()),
    };

    let rule = get_string(tbl, "rule");
    let exact_command = get_string(tbl, "exact_command");
    let command_prefix = get_string(tbl, "command_prefix");
    let pattern = get_string(tbl, "pattern");

    let mut selector: Option<AllowSelector> = None;
    let mut selector_count = 0usize;

    if let Some(rule) = rule {
        selector_count += 1;
        let rule_id = RuleId::parse(&rule)
            .ok_or_else(|| "invalid rule id (expected pack_id:pattern_name)".to_string())?;
        selector = Some(AllowSelector::Rule(rule_id));
    }
    if let Some(cmd) = exact_command {
        selector_count += 1;
        selector = Some(AllowSelector::ExactCommand(cmd));
    }
    if let Some(prefix) = command_prefix {
        selector_count += 1;
        selector = Some(AllowSelector::CommandPrefix(prefix));
    }
    if let Some(re) = pattern {
        selector_count += 1;
        selector = Some(AllowSelector::RegexPattern(re));
    }

    if selector_count == 0 {
        return Err(
            "missing selector: one of rule, exact_command, command_prefix, pattern".to_string(),
        );
    }
    if selector_count > 1 {
        return Err("invalid entry: specify exactly one selector field".to_string());
    }

    let added_by = get_string(tbl, "added_by");
    let added_at = get_timestamp_string(tbl, "added_at");
    let expires_at = get_timestamp_string(tbl, "expires_at");

    if let Some(ref exp) = expires_at {
        validate_expiration_date(exp)?;
    }

    let context = get_string(tbl, "context");

    let risk_acknowledged = tbl
        .get("risk_acknowledged")
        .and_then(toml::Value::as_bool)
        .unwrap_or(false);

    let environments = match tbl.get("environments") {
        None => Vec::new(),
        Some(v) => {
            let Some(arr) = v.as_array() else {
                return Err("environments must be an array of strings".to_string());
            };
            let mut envs = Vec::new();
            for item in arr {
                let Some(s) = item.as_str() else {
                    return Err("environments must be an array of strings".to_string());
                };
                envs.push(s.to_string());
            }
            envs
        }
    };

    let conditions = match tbl.get("conditions") {
        None => HashMap::new(),
        Some(v) => {
            let Some(t) = v.as_table() else {
                return Err("conditions must be a table of strings".to_string());
            };
            let mut out: HashMap<String, String> = HashMap::new();
            for (k, v) in t {
                let Some(s) = v.as_str() else {
                    return Err("conditions must be a table of strings".to_string());
                };
                out.insert(k.clone(), s.to_string());
            }
            out
        }
    };

    Ok(AllowEntry {
        selector: selector.expect("selector_count ensured selector exists"),
        reason,
        added_by,
        added_at,
        expires_at,
        context,
        conditions,
        environments,
        risk_acknowledged,
    })
}

fn get_string(tbl: &toml::value::Table, key: &str) -> Option<String> {
    tbl.get(key)
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
}

fn get_timestamp_string(tbl: &toml::value::Table, key: &str) -> Option<String> {
    let v = tbl.get(key)?;
    if let Some(s) = v.as_str() {
        return Some(s.to_string());
    }
    if let Some(dt) = v.as_datetime() {
        return Some(dt.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_allowlist_entries() {
        let toml = r#"
            [[allow]]
            rule = "core.git:reset-hard"
            reason = "intentional for migrations"
            added_by = "alice@example.com"
            added_at = "2026-01-08T01:23:45Z"
            expires_at = 2026-02-01T00:00:00Z

            [[allow]]
            exact_command = "rm -rf /tmp/dcg-test-artifacts"
            reason = "test cleanup"

            [[allow]]
            command_prefix = "bd create"
            context = "string-argument"
            reason = "docs-only args"

            [[allow]]
            pattern = "echo\\s+\\\"Example:.*rm -rf.*\\\""
            reason = "documentation examples"
            risk_acknowledged = true
        "#;

        let file = parse_allowlist_toml(AllowlistLayer::Project, Path::new("dummy"), toml);
        assert!(
            file.errors.is_empty(),
            "expected no errors, got: {:#?}",
            file.errors
        );
        assert_eq!(file.entries.len(), 4);
    }

    #[test]
    fn invalid_toml_is_non_fatal() {
        let file = parse_allowlist_toml(
            AllowlistLayer::User,
            Path::new("dummy"),
            "this is not = valid toml [",
        );
        assert!(file.entries.is_empty());
        assert_eq!(file.errors.len(), 1);
        assert!(file.errors[0].message.contains("invalid TOML"));
    }

    #[test]
    fn missing_reason_is_flagged() {
        let toml = r#"
            [[allow]]
            rule = "core.git:reset-hard"
        "#;
        let file = parse_allowlist_toml(AllowlistLayer::Project, Path::new("dummy"), toml);
        assert!(file.entries.is_empty());
        assert_eq!(file.errors.len(), 1);
        assert!(
            file.errors[0]
                .message
                .contains("missing required field: reason")
        );
    }

    #[test]
    fn missing_selector_is_flagged() {
        let toml = r#"
            [[allow]]
            reason = "no selector here"
        "#;
        let file = parse_allowlist_toml(AllowlistLayer::Project, Path::new("dummy"), toml);
        assert!(file.entries.is_empty());
        assert_eq!(file.errors.len(), 1);
        assert!(file.errors[0].message.contains("missing selector"));
    }

    #[test]
    fn multiple_selectors_are_flagged() {
        let toml = r#"
            [[allow]]
            rule = "core.git:reset-hard"
            exact_command = "git reset --hard"
            reason = "too broad"
        "#;
        let file = parse_allowlist_toml(AllowlistLayer::Project, Path::new("dummy"), toml);
        assert!(file.entries.is_empty());
        assert_eq!(file.errors.len(), 1);
        assert!(file.errors[0].message.contains("exactly one selector"));
    }

    #[test]
    fn invalid_expiration_date_is_flagged() {
        let toml = r#"
            [[allow]]
            rule = "core.git:reset-hard"
            reason = "test"
            expires_at = "not-a-date"
        "#;
        let file = parse_allowlist_toml(AllowlistLayer::Project, Path::new("dummy"), toml);
        assert!(file.entries.is_empty());
        assert_eq!(file.errors.len(), 1);
        assert!(
            file.errors[0]
                .message
                .contains("Invalid expiration date format")
        );
    }

    #[test]
    fn precedence_project_over_user_for_rule_lookup() {
        let rule = RuleId::parse("core.git:reset-hard").unwrap();

        let project_toml = r#"
            [[allow]]
            rule = "core.git:reset-hard"
            reason = "project reason"
        "#;
        let user_toml = r#"
            [[allow]]
            rule = "core.git:reset-hard"
            reason = "user reason"
        "#;

        let project_file =
            parse_allowlist_toml(AllowlistLayer::Project, Path::new("project"), project_toml);
        let user_file = parse_allowlist_toml(AllowlistLayer::User, Path::new("user"), user_toml);

        let allowlists = LayeredAllowlist {
            layers: vec![
                LoadedAllowlistLayer {
                    layer: AllowlistLayer::Project,
                    path: PathBuf::from("project"),
                    file: project_file,
                },
                LoadedAllowlistLayer {
                    layer: AllowlistLayer::User,
                    path: PathBuf::from("user"),
                    file: user_file,
                },
            ],
        };

        let (entry, layer) = allowlists.lookup_rule(&rule).expect("must find rule");
        assert_eq!(layer, AllowlistLayer::Project);
        assert_eq!(entry.reason, "project reason");
    }

    #[test]
    fn wildcard_pack_rule_matches_any_pattern_in_pack() {
        let allowlists = LayeredAllowlist {
            layers: vec![LoadedAllowlistLayer {
                layer: AllowlistLayer::Project,
                path: PathBuf::from("project"),
                file: AllowlistFile {
                    entries: vec![AllowEntry {
                        selector: AllowSelector::Rule(RuleId {
                            pack_id: "core.git".to_string(),
                            pattern_name: "*".to_string(),
                        }),
                        reason: "allow all git rules in this pack".to_string(),
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
        };

        let hit = allowlists
            .match_rule("core.git", "reset-hard")
            .expect("wildcard should match");
        assert_eq!(hit.layer, AllowlistLayer::Project);
        assert_eq!(hit.entry.reason, "allow all git rules in this pack");
    }

    // ==========================================================================
    // Entry validity tests (expiration, conditions, risk acknowledgement)
    // ==========================================================================

    fn make_test_entry() -> AllowEntry {
        AllowEntry {
            selector: AllowSelector::Rule(RuleId {
                pack_id: "core.git".to_string(),
                pattern_name: "reset-hard".to_string(),
            }),
            reason: "test".to_string(),
            added_by: None,
            added_at: None,
            expires_at: None,
            context: None,
            conditions: HashMap::new(),
            environments: Vec::new(),
            risk_acknowledged: false,
        }
    }

    #[test]
    fn entry_without_expiration_is_not_expired() {
        let entry = make_test_entry();
        assert!(!is_expired(&entry));
    }

    #[test]
    fn entry_with_future_rfc3339_is_not_expired() {
        let mut entry = make_test_entry();
        entry.expires_at = Some("2099-12-31T23:59:59Z".to_string());
        assert!(!is_expired(&entry));
    }

    #[test]
    fn entry_with_past_rfc3339_is_expired() {
        let mut entry = make_test_entry();
        entry.expires_at = Some("2020-01-01T00:00:00Z".to_string());
        assert!(is_expired(&entry));
    }

    #[test]
    fn entry_with_future_iso8601_no_tz_is_not_expired() {
        let mut entry = make_test_entry();
        // ISO 8601 without timezone - treated as UTC
        entry.expires_at = Some("2099-12-31T23:59:59".to_string());
        assert!(!is_expired(&entry));
    }

    #[test]
    fn entry_with_past_iso8601_no_tz_is_expired() {
        let mut entry = make_test_entry();
        // ISO 8601 without timezone - treated as UTC
        entry.expires_at = Some("2020-01-01T00:00:00".to_string());
        assert!(is_expired(&entry));
    }

    #[test]
    fn entry_with_future_date_only_is_not_expired() {
        let mut entry = make_test_entry();
        entry.expires_at = Some("2099-12-31".to_string());
        assert!(!is_expired(&entry));
    }

    #[test]
    fn entry_with_past_date_only_is_expired() {
        let mut entry = make_test_entry();
        entry.expires_at = Some("2020-01-01".to_string());
        assert!(is_expired(&entry));
    }

    #[test]
    fn entry_with_invalid_timestamp_is_expired() {
        // Invalid formats should fail closed (treat as expired)
        let mut entry = make_test_entry();
        entry.expires_at = Some("not-a-date".to_string());
        assert!(is_expired(&entry));
    }

    #[test]
    fn expired_entry_is_skipped_in_match_rule() {
        let allowlists = LayeredAllowlist {
            layers: vec![LoadedAllowlistLayer {
                layer: AllowlistLayer::Project,
                path: PathBuf::from("project"),
                file: AllowlistFile {
                    entries: vec![AllowEntry {
                        selector: AllowSelector::Rule(RuleId {
                            pack_id: "core.git".to_string(),
                            pattern_name: "reset-hard".to_string(),
                        }),
                        reason: "expired allowlist".to_string(),
                        added_by: None,
                        added_at: None,
                        expires_at: Some("2020-01-01T00:00:00Z".to_string()),
                        context: None,
                        conditions: HashMap::new(),
                        environments: Vec::new(),
                        risk_acknowledged: false,
                    }],
                    errors: Vec::new(),
                },
            }],
        };

        // Should not match because the entry is expired
        assert!(allowlists.match_rule("core.git", "reset-hard").is_none());
    }

    #[test]
    fn entry_with_no_conditions_is_valid() {
        let entry = make_test_entry();
        assert!(conditions_met(&entry));
    }

    #[test]
    fn entry_with_missing_env_var_is_invalid() {
        // Use a unique env var name that definitely doesn't exist
        let mut entry = make_test_entry();
        entry.conditions.insert(
            "DCG_TEST_NONEXISTENT_VAR_12345_ABCDE".to_string(),
            "anything".to_string(),
        );
        assert!(!conditions_met(&entry));
    }

    #[test]
    fn entry_with_multiple_missing_conditions_is_invalid() {
        let mut entry = make_test_entry();
        entry.conditions.insert(
            "DCG_TEST_MISSING_A_99999".to_string(),
            "value_a".to_string(),
        );
        entry.conditions.insert(
            "DCG_TEST_MISSING_B_99999".to_string(),
            "value_b".to_string(),
        );
        // Both conditions missing, so should fail
        assert!(!conditions_met(&entry));
    }

    #[test]
    fn rule_entry_without_risk_ack_is_valid() {
        // Rule entries don't require risk_acknowledged
        let entry = make_test_entry();
        assert!(has_required_risk_ack(&entry));
    }

    #[test]
    fn regex_entry_without_risk_ack_is_invalid() {
        let entry = AllowEntry {
            selector: AllowSelector::RegexPattern("rm.*-rf".to_string()),
            reason: "test".to_string(),
            added_by: None,
            added_at: None,
            expires_at: None,
            context: None,
            conditions: HashMap::new(),
            environments: Vec::new(),
            risk_acknowledged: false,
        };
        assert!(!has_required_risk_ack(&entry));
    }

    #[test]
    fn regex_entry_with_risk_ack_is_valid() {
        let entry = AllowEntry {
            selector: AllowSelector::RegexPattern("rm.*-rf".to_string()),
            reason: "test".to_string(),
            added_by: None,
            added_at: None,
            expires_at: None,
            context: None,
            conditions: HashMap::new(),
            environments: Vec::new(),
            risk_acknowledged: true,
        };
        assert!(has_required_risk_ack(&entry));
    }

    #[test]
    fn is_entry_valid_combines_all_checks() {
        // Valid entry: not expired, no conditions, not regex
        let entry = make_test_entry();
        assert!(is_entry_valid(&entry));

        // Invalid: expired
        let mut expired = make_test_entry();
        expired.expires_at = Some("2020-01-01".to_string());
        assert!(!is_entry_valid(&expired));

        // Invalid: condition not met (unique nonexistent env var)
        let mut unmet_condition = make_test_entry();
        unmet_condition.conditions.insert(
            "DCG_TEST_COMBINED_NONEXISTENT_77777".to_string(),
            "x".to_string(),
        );
        assert!(!is_entry_valid(&unmet_condition));

        // Invalid: regex without ack
        let regex_no_ack = AllowEntry {
            selector: AllowSelector::RegexPattern(".*".to_string()),
            reason: "test".to_string(),
            added_by: None,
            added_at: None,
            expires_at: None,
            context: None,
            conditions: HashMap::new(),
            environments: Vec::new(),
            risk_acknowledged: false,
        };
        assert!(!is_entry_valid(&regex_no_ack));
    }

    #[test]
    fn unmet_condition_entry_is_skipped_in_match_rule() {
        // Use a unique nonexistent env var name
        let allowlists = LayeredAllowlist {
            layers: vec![LoadedAllowlistLayer {
                layer: AllowlistLayer::Project,
                path: PathBuf::from("project"),
                file: AllowlistFile {
                    entries: vec![AllowEntry {
                        selector: AllowSelector::Rule(RuleId {
                            pack_id: "core.git".to_string(),
                            pattern_name: "reset-hard".to_string(),
                        }),
                        reason: "conditional allowlist".to_string(),
                        added_by: None,
                        added_at: None,
                        expires_at: None,
                        context: None,
                        conditions: {
                            let mut m = HashMap::new();
                            m.insert(
                                "DCG_TEST_SKIP_NONEXISTENT_88888".to_string(),
                                "enabled".to_string(),
                            );
                            m
                        },
                        environments: Vec::new(),
                        risk_acknowledged: false,
                    }],
                    errors: Vec::new(),
                },
            }],
        };

        // Should not match because the condition is not met
        assert!(allowlists.match_rule("core.git", "reset-hard").is_none());
    }

    #[test]
    fn test_validate_expiration_date_valid_formats() {
        // RFC 3339 with Z
        assert!(validate_expiration_date("2030-01-01T00:00:00Z").is_ok());
        // RFC 3339 with offset
        assert!(validate_expiration_date("2030-01-01T00:00:00+00:00").is_ok());
        // ISO 8601 without timezone
        assert!(validate_expiration_date("2030-01-01T00:00:00").is_ok());
        // Date only
        assert!(validate_expiration_date("2030-01-01").is_ok());
    }

    #[test]
    fn test_validate_expiration_date_invalid_formats() {
        // Not a date
        assert!(validate_expiration_date("not-a-date").is_err());
        // Wrong format
        assert!(validate_expiration_date("01/01/2030").is_err());
        // Empty
        assert!(validate_expiration_date("").is_err());
    }

    #[test]
    fn test_validate_condition_valid() {
        assert!(validate_condition("CI=true").is_ok());
        assert!(validate_condition("ENV=production").is_ok());
        assert!(validate_condition("KEY=value with spaces").is_ok());
        assert!(validate_condition("EMPTY=").is_ok()); // empty value is OK
    }

    #[test]
    fn test_validate_condition_invalid() {
        // No equals sign
        assert!(validate_condition("invalid").is_err());
        // Empty key
        assert!(validate_condition("=value").is_err());
        // Just equals
        assert!(validate_condition("=").is_err());
    }
}
