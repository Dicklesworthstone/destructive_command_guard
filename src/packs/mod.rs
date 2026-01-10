//! Pack system for modular command blocking.
//!
//! This module provides the infrastructure for organizing patterns into "packs"
//! that can be enabled or disabled based on user configuration.
//!
//! # Pack Hierarchy
//!
//! Packs are organized in a two-level hierarchy:
//! - Category (e.g., "database", "kubernetes")
//! - Sub-pack (e.g., "database.postgresql", "kubernetes.kubectl")
//!
//! Enabling a category enables all its sub-packs. Sub-packs can be individually
//! disabled even if their parent category is enabled.

pub mod cicd;
pub mod cloud;
pub mod containers;
pub mod core;
pub mod database;
pub mod infrastructure;
pub mod kubernetes;
pub mod package_managers;
pub mod regex_engine;
pub mod safe;
pub mod strict_git;
pub mod system;

// Testing infrastructure
pub mod test_helpers;
#[cfg(test)]
mod test_template;

use fancy_regex::Regex;
use memchr::memmem;
use regex_engine::LazyFancyRegex;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::LazyLock;

/// Unique identifier for a pack (e.g., "core", "database.postgresql").
pub type PackId = String;

/// Severity level for destructive patterns.
///
/// Severity determines the default decision mode and allowlisting behavior:
/// - **Critical**: Always block. These are irreversible, high-confidence detections.
/// - **High**: Block by default, but allowlistable by rule ID.
/// - **Medium**: Warn by default (log + continue), blockable via config.
/// - **Low**: Log only (for telemetry/learning), warneable/blockable via config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Severity {
    /// Always block. Irreversible operations with high confidence.
    /// Examples: `rm -rf /`, `git reset --hard`, `DROP DATABASE`.
    Critical,

    /// Block by default, allowlistable by rule ID.
    /// Examples: `git push --force`, `docker system prune`.
    #[default]
    High,

    /// Warn by default (stderr warning, but allow execution).
    /// Examples: context-dependent patterns, lower-confidence detections.
    Medium,

    /// Log only (silent, for telemetry and learning).
    /// Examples: advisory patterns, patterns under evaluation.
    Low,
}

impl Severity {
    /// Get the default decision mode for this severity level.
    #[must_use]
    pub const fn default_mode(&self) -> DecisionMode {
        match self {
            Self::Critical | Self::High => DecisionMode::Deny,
            Self::Medium => DecisionMode::Warn,
            Self::Low => DecisionMode::Log,
        }
    }

    /// Returns true if this severity level blocks by default.
    #[must_use]
    pub const fn blocks_by_default(&self) -> bool {
        matches!(self, Self::Critical | Self::High)
    }

    /// Get a human-readable label for this severity.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

/// Decision mode for how to handle a matched pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum DecisionMode {
    /// Block the command (output JSON deny, print warning).
    #[default]
    Deny,

    /// Warn but allow (print warning to stderr, no JSON deny).
    Warn,

    /// Log only (silent allow, record for telemetry).
    Log,
}

impl DecisionMode {
    /// Returns true if this mode blocks command execution.
    #[must_use]
    pub const fn blocks(&self) -> bool {
        matches!(self, Self::Deny)
    }

    /// Get a human-readable label for this mode.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Warn => "warn",
            Self::Log => "log",
        }
    }
}

/// A safe pattern that, when matched, allows the command immediately.
pub struct SafePattern {
    /// Lazily-compiled regex pattern.
    pub regex: LazyFancyRegex,
    /// Debug name for the pattern.
    pub name: &'static str,
}

impl std::fmt::Debug for SafePattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SafePattern")
            .field("pattern", &self.regex.as_str())
            .field("name", &self.name)
            .finish()
    }
}

/// A destructive pattern that, when matched, blocks the command.
pub struct DestructivePattern {
    /// Lazily-compiled regex pattern.
    pub regex: LazyFancyRegex,
    /// Human-readable explanation of why this command is blocked.
    pub reason: &'static str,
    /// Optional pattern name for debugging and allowlisting.
    pub name: Option<&'static str>,
    /// Severity level (determines default decision mode).
    pub severity: Severity,
}

impl std::fmt::Debug for DestructivePattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DestructivePattern")
            .field("pattern", &self.regex.as_str())
            .field("reason", &self.reason)
            .field("name", &self.name)
            .field("severity", &self.severity)
            .finish()
    }
}

/// Macro to create a safe pattern with compile-time name checking.
///
/// The pattern is lazily compiled on first use, not at construction time.
#[macro_export]
macro_rules! safe_pattern {
    ($name:literal, $re:literal) => {
        $crate::packs::SafePattern {
            regex: $crate::packs::regex_engine::LazyFancyRegex::new($re),
            name: $name,
        }
    };
}

/// Macro to create a destructive pattern with reason.
///
/// The pattern is lazily compiled on first use, not at construction time.
///
/// # Variants
///
/// - `destructive_pattern!("regex", "reason")` - unnamed, default High severity
/// - `destructive_pattern!("name", "regex", "reason")` - named, default High severity
/// - `destructive_pattern!("name", "regex", "reason", Critical)` - named with explicit severity
#[macro_export]
macro_rules! destructive_pattern {
    // Unnamed pattern, default severity (High)
    ($re:literal, $reason:literal) => {
        $crate::packs::DestructivePattern {
            regex: $crate::packs::regex_engine::LazyFancyRegex::new($re),
            reason: $reason,
            name: None,
            severity: $crate::packs::Severity::High,
        }
    };
    // Named pattern, default severity (High)
    ($name:literal, $re:literal, $reason:literal) => {
        $crate::packs::DestructivePattern {
            regex: $crate::packs::regex_engine::LazyFancyRegex::new($re),
            reason: $reason,
            name: Some($name),
            severity: $crate::packs::Severity::High,
        }
    };
    // Named pattern with explicit severity
    ($name:literal, $re:literal, $reason:literal, $severity:ident) => {
        $crate::packs::DestructivePattern {
            regex: $crate::packs::regex_engine::LazyFancyRegex::new($re),
            reason: $reason,
            name: Some($name),
            severity: $crate::packs::Severity::$severity,
        }
    };
}

/// A pack of patterns for a specific category of commands.
#[derive(Debug)]
pub struct Pack {
    /// Unique identifier (e.g., "database.postgresql").
    pub id: PackId,

    /// Human-readable name (e.g., `PostgreSQL`).
    pub name: &'static str,

    /// Description of what this pack protects against.
    pub description: &'static str,

    /// Keywords for quick-reject filtering (e.g., `["psql", "dropdb", "DROP"]`).
    /// Commands without any of these keywords skip pattern matching for this pack.
    pub keywords: &'static [&'static str],

    /// Safe patterns (whitelist) - checked first.
    pub safe_patterns: Vec<SafePattern>,

    /// Destructive patterns (blacklist) - checked if no safe pattern matches.
    pub destructive_patterns: Vec<DestructivePattern>,

    /// Pre-built Aho-Corasick automaton for O(n) keyword matching.
    /// Built by `PackRegistry::register_pack()` from keywords. Set to `None` in pack
    /// constructors; the registry initializes this during registration.
    pub keyword_matcher: Option<aho_corasick::AhoCorasick>,
}

impl Pack {
    /// Check if a command contains any of this pack's keywords.
    /// Returns false if the command doesn't contain any keywords (quick reject).
    ///
    /// Uses an Aho-Corasick automaton for O(n) matching when available (built
    /// by the registry during pack registration). Falls back to sequential
    /// memchr-based search if the automaton isn't built.
    #[must_use]
    pub fn might_match(&self, cmd: &str) -> bool {
        if self.keywords.is_empty() {
            return true; // No keywords = always check patterns
        }

        // Use Aho-Corasick automaton if available (O(n) regardless of keyword count).
        if let Some(ref ac) = self.keyword_matcher {
            return ac.is_match(cmd);
        }

        // Fallback: sequential memchr-based search (O(k * n) where k = keyword count).
        let bytes = cmd.as_bytes();
        self.keywords
            .iter()
            .any(|kw| memmem::find(bytes, kw.as_bytes()).is_some())
    }

    /// Check if a command matches any safe pattern.
    #[must_use]
    pub fn matches_safe(&self, cmd: &str) -> bool {
        self.safe_patterns.iter().any(|p| p.regex.is_match(cmd))
    }

    /// Check if a command matches any destructive pattern.
    /// Returns the matched pattern's reason, name, and severity if found.
    #[must_use]
    pub fn matches_destructive(&self, cmd: &str) -> Option<DestructiveMatch> {
        self.destructive_patterns
            .iter()
            .find(|p| p.regex.is_match(cmd))
            .map(|p| DestructiveMatch {
                reason: p.reason,
                name: p.name,
                severity: p.severity,
            })
    }

    /// Check a command against this pack.
    /// Returns Some(DestructiveMatch) if blocked, None if allowed.
    #[must_use]
    pub fn check(&self, cmd: &str) -> Option<DestructiveMatch> {
        // Quick reject if no keywords match
        if !self.might_match(cmd) {
            return None;
        }

        // Check safe patterns first (whitelist)
        if self.matches_safe(cmd) {
            return None;
        }

        // Check destructive patterns (blacklist)
        self.matches_destructive(cmd)
    }
}

/// Information about a matched destructive pattern.
#[derive(Debug, Clone)]
pub struct DestructiveMatch {
    /// Human-readable explanation of why this command is blocked.
    pub reason: &'static str,
    /// Optional pattern name for debugging and allowlisting.
    pub name: Option<&'static str>,
    /// Severity level of the matched pattern.
    pub severity: Severity,
}

/// Result of checking a command against all packs.
#[derive(Debug)]
pub struct CheckResult {
    /// Whether the command should be blocked (based on severity and mode).
    pub blocked: bool,
    /// The reason for blocking/warning (if matched).
    pub reason: Option<String>,
    /// Which pack matched (if matched).
    pub pack_id: Option<PackId>,
    /// The name of the pattern that matched (if available).
    pub pattern_name: Option<String>,
    /// Severity of the matched pattern (if matched).
    pub severity: Option<Severity>,
    /// Decision mode applied (if matched).
    pub decision_mode: Option<DecisionMode>,
}

impl CheckResult {
    /// Create an "allowed" result (no pattern matched).
    #[must_use]
    pub const fn allowed() -> Self {
        Self {
            blocked: false,
            reason: None,
            pack_id: None,
            pattern_name: None,
            severity: None,
            decision_mode: None,
        }
    }

    /// Create a "blocked" result with pattern identity and severity.
    #[must_use]
    pub fn blocked(
        reason: &str,
        pack_id: &str,
        pattern_name: Option<&str>,
        severity: Severity,
    ) -> Self {
        let decision_mode = severity.default_mode();
        Self {
            blocked: decision_mode.blocks(),
            reason: Some(reason.to_string()),
            pack_id: Some(pack_id.to_string()),
            pattern_name: pattern_name.map(ToString::to_string),
            severity: Some(severity),
            decision_mode: Some(decision_mode),
        }
    }

    /// Create a result for a matched pattern (may be blocked, warned, or logged
    /// depending on severity).
    #[must_use]
    pub fn matched(
        reason: &str,
        pack_id: &str,
        pattern_name: Option<&str>,
        severity: Severity,
    ) -> Self {
        Self::blocked(reason, pack_id, pattern_name, severity)
    }
}

/// Registry of all available packs.
pub struct PackRegistry {
    /// All registered packs, keyed by ID.
    packs: HashMap<PackId, Pack>,

    /// Pack IDs organized by category for hierarchical enablement.
    categories: HashMap<String, Vec<PackId>>,
}

impl PackRegistry {
    /// Collect all keywords from enabled packs.
    ///
    /// This returns a deduplicated list of keywords that can be used for
    /// pack-aware quick rejection. If a command contains none of these keywords,
    /// it can safely skip pack checking.
    #[must_use]
    pub fn collect_enabled_keywords(&self, enabled_packs: &HashSet<String>) -> Vec<&'static str> {
        let expanded = self.expand_enabled(enabled_packs);
        let mut keywords = Vec::new();

        for pack_id in &expanded {
            if let Some(pack) = self.packs.get(pack_id) {
                keywords.extend(pack.keywords.iter().copied());
            }
        }

        // Deduplicate while preserving order (first occurrence wins)
        let mut seen = HashSet::new();
        keywords.retain(|kw| seen.insert(*kw));

        keywords
    }

    /// Create a new registry with all built-in packs.
    #[must_use]
    pub fn new() -> Self {
        let mut registry = Self {
            packs: HashMap::new(),
            categories: HashMap::new(),
        };

        // Register all built-in packs
        registry.register_pack(core::git::create_pack());
        registry.register_pack(core::filesystem::create_pack());
        registry.register_pack(cicd::github_actions::create_pack());
        registry.register_pack(database::postgresql::create_pack());
        registry.register_pack(database::mysql::create_pack());
        registry.register_pack(database::mongodb::create_pack());
        registry.register_pack(database::redis::create_pack());
        registry.register_pack(database::sqlite::create_pack());
        registry.register_pack(containers::docker::create_pack());
        registry.register_pack(containers::compose::create_pack());
        registry.register_pack(containers::podman::create_pack());
        registry.register_pack(kubernetes::kubectl::create_pack());
        registry.register_pack(kubernetes::helm::create_pack());
        registry.register_pack(kubernetes::kustomize::create_pack());
        registry.register_pack(cloud::aws::create_pack());
        registry.register_pack(cloud::gcp::create_pack());
        registry.register_pack(cloud::azure::create_pack());
        registry.register_pack(infrastructure::terraform::create_pack());
        registry.register_pack(infrastructure::ansible::create_pack());
        registry.register_pack(infrastructure::pulumi::create_pack());
        registry.register_pack(system::disk::create_pack());
        registry.register_pack(system::permissions::create_pack());
        registry.register_pack(system::services::create_pack());
        registry.register_pack(strict_git::create_pack());
        registry.register_pack(package_managers::create_pack());
        registry.register_pack(safe::cleanup::create_pack());

        registry
    }

    /// Register a pack in the registry.
    ///
    /// Builds the Aho-Corasick automaton for keyword matching during registration.
    fn register_pack(&mut self, mut pack: Pack) {
        let id = pack.id.clone();

        // Build Aho-Corasick automaton for O(n) keyword matching.
        // This is done once at registration time, not per-command.
        if !pack.keywords.is_empty() && pack.keyword_matcher.is_none() {
            pack.keyword_matcher = Some(
                aho_corasick::AhoCorasick::new(pack.keywords)
                    .expect("pack keywords should be valid patterns"),
            );
        }

        // Extract category from ID (e.g., "database" from "database.postgresql")
        let category = id.split('.').next().unwrap_or(&id).to_string();

        // Add to categories map
        self.categories
            .entry(category)
            .or_default()
            .push(id.clone());

        // Add to packs map
        self.packs.insert(id, pack);
    }

    /// Get a pack by ID.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Pack> {
        self.packs.get(id)
    }

    /// Get all pack IDs.
    #[must_use]
    pub fn all_pack_ids(&self) -> Vec<&PackId> {
        self.packs.keys().collect()
    }

    /// Get all categories.
    #[must_use]
    pub fn all_categories(&self) -> Vec<&String> {
        self.categories.keys().collect()
    }

    /// Get pack IDs in a category.
    #[must_use]
    pub fn packs_in_category(&self, category: &str) -> Vec<&PackId> {
        self.categories
            .get(category)
            .map(|ids| ids.iter().collect())
            .unwrap_or_default()
    }

    /// Expand enabled pack IDs to include sub-packs when a category is enabled.
    #[must_use]
    pub fn expand_enabled(&self, enabled: &HashSet<String>) -> HashSet<String> {
        let mut expanded = HashSet::new();

        for id in enabled {
            // Check if this is a category
            if let Some(sub_packs) = self.categories.get(id) {
                // Add all sub-packs in the category
                for sub_pack in sub_packs {
                    expanded.insert(sub_pack.clone());
                }
            }
            // Also add the ID itself (in case it's a specific pack)
            expanded.insert(id.clone());
        }

        expanded
    }

    /// Expand enabled pack IDs and return them in a deterministic order.
    ///
    /// This is used by `check_command` to ensure consistent attribution when
    /// multiple packs could match the same command. The ordering is:
    ///
    /// 0. **Tier 0 (safe)**: `safe.*` packs - safe patterns checked first to whitelist
    /// 1. **Tier 1 (core)**: `core.*` packs - most fundamental protections
    /// 2. **Tier 2 (system)**: `system.*` - disk, permissions, services
    /// 3. **Tier 3 (infrastructure)**: `infrastructure.*` - terraform, ansible, pulumi
    /// 4. **Tier 4 (cloud)**: `cloud.*` - aws, gcp, azure
    /// 5. **Tier 5 (kubernetes)**: `kubernetes.*` - kubectl, helm, kustomize
    /// 6. **Tier 6 (containers)**: `containers.*` - docker, compose, podman
    /// 7. **Tier 7 (database)**: `database.*` - postgresql, mysql, etc.
    /// 8. **Tier 8 (`package_managers`)**: package manager protections
    /// 9. **Tier 9 (`strict_git`)**: extra git paranoia
    ///
    /// Within each tier, packs are sorted lexicographically by ID.
    #[must_use]
    pub fn expand_enabled_ordered(&self, enabled: &HashSet<String>) -> Vec<String> {
        let expanded = self.expand_enabled(enabled);

        // Filter to only include pack IDs that actually exist in registry
        let mut pack_ids: Vec<String> = expanded
            .into_iter()
            .filter(|id| self.packs.contains_key(id))
            .collect();

        // Sort by tier then lexicographically within tier
        pack_ids.sort_by(|a, b| {
            let tier_a = Self::pack_tier(a);
            let tier_b = Self::pack_tier(b);
            tier_a.cmp(&tier_b).then_with(|| a.cmp(b))
        });

        pack_ids
    }

    /// Get the priority tier for a pack ID (lower = higher priority).
    ///
    /// Safe packs (tier 0) are evaluated first so their safe patterns can
    /// whitelist commands before other packs' destructive patterns match.
    fn pack_tier(pack_id: &str) -> u8 {
        let category = pack_id.split('.').next().unwrap_or(pack_id);
        match category {
            "safe" => 0,
            "core" => 1,
            "system" => 2,
            "infrastructure" => 3,
            "cloud" => 4,
            "kubernetes" => 5,
            "containers" => 6,
            "database" => 7,
            "package_managers" => 8,
            "strict_git" => 9,
            "cicd" => 10, // CI/CD tools (GitHub Actions, etc.)
            _ => 11,      // Unknown categories go last
        }
    }

    /// Check a command against all enabled packs.
    ///
    /// Packs are evaluated in a deterministic order (see `expand_enabled_ordered`),
    /// ensuring consistent attribution when multiple packs could match.
    ///
    /// # Evaluation order
    ///
    /// The evaluation uses a two-pass approach:
    /// 1. **Safe patterns pass**: Check safe patterns across ALL enabled packs.
    ///    If any pack's safe pattern matches, the command is allowed immediately.
    ///    This allows "safe" packs (like `safe.cleanup`) to whitelist commands
    ///    that would otherwise be blocked by other packs.
    /// 2. **Destructive patterns pass**: Check destructive patterns across all packs.
    ///    The first matching destructive pattern blocks (based on severity).
    ///
    /// Returns a `CheckResult` containing:
    /// - `blocked`: whether the command should be blocked (based on severity)
    /// - `reason`: the human-readable explanation (if matched)
    /// - `pack_id`: which pack matched (if matched)
    /// - `pattern_name`: the specific pattern that matched (if available)
    /// - `severity`: the severity level of the matched pattern
    /// - `decision_mode`: the decision mode applied (deny/warn/log)
    #[must_use]
    pub fn check_command(&self, cmd: &str, enabled_packs: &HashSet<String>) -> CheckResult {
        // Expand category IDs to include all sub-packs in deterministic order
        let ordered_packs = self.expand_enabled_ordered(enabled_packs);

        // Pass 1: Check safe patterns across ALL enabled packs first.
        // If any pack's safe pattern matches, allow the command immediately.
        // This enables "safe" packs to whitelist commands across pack boundaries.
        for pack_id in &ordered_packs {
            if let Some(pack) = self.packs.get(pack_id) {
                // Quick reject: skip packs that don't have keyword matches
                if !pack.might_match(cmd) {
                    continue;
                }
                // Check safe patterns only
                if pack.matches_safe(cmd) {
                    return CheckResult::allowed();
                }
            }
        }

        // Pass 2: Check destructive patterns across all enabled packs.
        // The first matching destructive pattern determines the result.
        for pack_id in &ordered_packs {
            if let Some(pack) = self.packs.get(pack_id) {
                // Quick reject: skip packs that don't have keyword matches
                if !pack.might_match(cmd) {
                    continue;
                }
                // Check destructive patterns only
                if let Some(matched) = pack.matches_destructive(cmd) {
                    return CheckResult::matched(
                        matched.reason,
                        pack_id,
                        matched.name,
                        matched.severity,
                    );
                }
            }
        }

        CheckResult::allowed()
    }

    /// List all packs with their status.
    #[must_use]
    pub fn list_packs(&self, enabled: &HashSet<String>) -> Vec<PackInfo> {
        let expanded = self.expand_enabled(enabled);

        let mut infos: Vec<_> = self
            .packs
            .values()
            .map(|pack| PackInfo {
                id: pack.id.clone(),
                name: pack.name,
                description: pack.description,
                enabled: expanded.contains(&pack.id),
                safe_pattern_count: pack.safe_patterns.len(),
                destructive_pattern_count: pack.destructive_patterns.len(),
            })
            .collect();

        // Sort by ID for consistent output
        infos.sort_by(|a, b| a.id.cmp(&b.id));
        infos
    }
}

impl Default for PackRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about a pack for display.
#[derive(Debug)]
pub struct PackInfo {
    /// Pack ID.
    pub id: PackId,
    /// Human-readable name.
    pub name: &'static str,
    /// Description.
    pub description: &'static str,
    /// Whether the pack is enabled.
    pub enabled: bool,
    /// Number of safe patterns.
    pub safe_pattern_count: usize,
    /// Number of destructive patterns.
    pub destructive_pattern_count: usize,
}

/// Global pack registry (lazily initialized).
pub static REGISTRY: LazyLock<PackRegistry> = LazyLock::new(PackRegistry::new);

/// Regex to strip absolute paths from git/rm binaries.
static PATH_NORMALIZER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/(?:\S*/)*s?bin/(rm|git)(?=\s|$)").unwrap());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NormalizeTokenKind {
    Word,
    Separator,
}

#[derive(Debug, Clone)]
struct NormalizeToken {
    kind: NormalizeTokenKind,
    byte_range: Range<usize>,
}

impl NormalizeToken {
    #[inline]
    #[must_use]
    fn text<'a>(&self, command: &'a str) -> Option<&'a str> {
        command.get(self.byte_range.clone())
    }
}

#[must_use]
fn tokenize_for_normalization(command: &str) -> Vec<NormalizeToken> {
    let bytes = command.as_bytes();
    let len = bytes.len();

    let mut tokens = Vec::new();
    let mut i = 0;

    while i < len {
        i = skip_ascii_whitespace(bytes, i, len);
        if i >= len {
            break;
        }

        if let Some(end) = consume_separator_token(bytes, i, len, &mut tokens) {
            i = end;
            continue;
        }

        let start = i;
        let end = consume_word_token(bytes, i, len);
        i = end;

        if start < i {
            tokens.push(NormalizeToken {
                kind: NormalizeTokenKind::Word,
                byte_range: start..i,
            });
        }
    }

    tokens
}

#[inline]
#[must_use]
fn skip_ascii_whitespace(bytes: &[u8], mut i: usize, len: usize) -> usize {
    while i < len && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

#[inline]
fn consume_separator_token(
    bytes: &[u8],
    i: usize,
    len: usize,
    tokens: &mut Vec<NormalizeToken>,
) -> Option<usize> {
    match bytes[i] {
        b'|' => {
            let end = if i + 1 < len && bytes[i + 1] == b'|' {
                i + 2
            } else {
                i + 1
            };
            tokens.push(NormalizeToken {
                kind: NormalizeTokenKind::Separator,
                byte_range: i..end,
            });
            Some(end)
        }
        b';' | b'(' | b')' => {
            tokens.push(NormalizeToken {
                kind: NormalizeTokenKind::Separator,
                byte_range: i..i + 1,
            });
            Some(i + 1)
        }
        b'&' => {
            let end = if i + 1 < len && bytes[i + 1] == b'&' {
                i + 2
            } else {
                i + 1
            };
            tokens.push(NormalizeToken {
                kind: NormalizeTokenKind::Separator,
                byte_range: i..end,
            });
            Some(end)
        }
        _ => None,
    }
}

#[must_use]
fn consume_word_token(bytes: &[u8], mut i: usize, len: usize) -> usize {
    while i < len {
        let b = bytes[i];

        if b.is_ascii_whitespace() {
            break;
        }

        if matches!(b, b'|' | b';' | b'&' | b'(' | b')') {
            break;
        }

        match b {
            b'\\' => {
                // Skip escaped byte. This is conservative for UTF-8.
                i = (i + 2).min(len);
            }
            b'\'' => {
                // Single-quoted segment (no escapes)
                i += 1;
                while i < len && bytes[i] != b'\'' {
                    i += 1;
                }
                if i < len {
                    i += 1; // consume closing quote
                }
            }
            b'"' => {
                // Double-quoted segment (escapes)
                i += 1;
                while i < len {
                    match bytes[i] {
                        b'"' => {
                            i += 1;
                            break;
                        }
                        b'\\' => {
                            i = (i + 2).min(len);
                        }
                        _ => {
                            i += 1;
                        }
                    }
                }
            }
            _ => {
                i += 1;
            }
        }
    }

    i
}

#[inline]
#[must_use]
fn is_env_assignment(token: &str) -> bool {
    // Rough heuristic for KEY=VALUE tokens used as env assignments.
    let Some((key, _value)) = token.split_once('=') else {
        return false;
    };
    !key.is_empty()
        && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !token.starts_with('-')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NormalizeWrapper {
    None,
    Sudo { options_ended: bool, skip_next: u8 },
    Env { options_ended: bool, skip_next: u8 },
    Command { options_ended: bool, skip_next: u8 },
    CommandQuery,
}

impl NormalizeWrapper {
    #[inline]
    #[must_use]
    fn from_command_word(word: &str) -> Option<Self> {
        match word {
            "sudo" => Some(Self::Sudo {
                options_ended: false,
                skip_next: 0,
            }),
            "env" => Some(Self::Env {
                options_ended: false,
                skip_next: 0,
            }),
            "command" => Some(Self::Command {
                options_ended: false,
                skip_next: 0,
            }),
            _ => None,
        }
    }

    #[inline]
    #[must_use]
    fn should_skip_token(self, token: &str) -> bool {
        match self {
            Self::None | Self::CommandQuery => false,
            Self::Sudo {
                options_ended,
                skip_next,
            }
            | Self::Env {
                options_ended,
                skip_next,
            }
            | Self::Command {
                options_ended,
                skip_next,
            } => {
                if skip_next > 0 {
                    return true;
                }
                if !options_ended && token == "--" {
                    return true;
                }
                !options_ended && token.starts_with('-')
            }
        }
    }

    #[inline]
    #[must_use]
    fn advance_sudo(mut options_ended: bool, mut skip_next: u8, token: &str) -> Self {
        if skip_next > 0 {
            skip_next = skip_next.saturating_sub(1);
            return Self::Sudo {
                options_ended,
                skip_next,
            };
        }
        if !options_ended && token == "--" {
            options_ended = true;
            return Self::Sudo {
                options_ended,
                skip_next,
            };
        }
        if !options_ended && token.starts_with('-') {
            // Options that take an argument: -u USER, -g GROUP, -h HOST, -p PROMPT
            // Also support attached args: -uUSER, -gGROUP, etc (no extra token to skip).
            let takes_value = matches!(token, "-u" | "-g" | "-h" | "-p")
                || token.starts_with("-u")
                || token.starts_with("-g")
                || token.starts_with("-h")
                || token.starts_with("-p");
            if takes_value && token.len() == 2 {
                skip_next = 1;
            }
            return Self::Sudo {
                options_ended,
                skip_next,
            };
        }
        Self::Sudo {
            options_ended,
            skip_next,
        }
    }

    #[inline]
    #[must_use]
    fn advance_env(mut options_ended: bool, mut skip_next: u8, token: &str) -> Self {
        if skip_next > 0 {
            skip_next = skip_next.saturating_sub(1);
            return Self::Env {
                options_ended,
                skip_next,
            };
        }
        if !options_ended && token == "--" {
            options_ended = true;
            return Self::Env {
                options_ended,
                skip_next,
            };
        }
        if !options_ended && token.starts_with('-') {
            // `env -u NAME ...` unsets a variable (takes an argument).
            let takes_value = token == "-u" || token == "--unset" || token.starts_with("-u");
            if takes_value && (token == "-u" || token == "--unset") {
                skip_next = 1;
            }
            return Self::Env {
                options_ended,
                skip_next,
            };
        }
        Self::Env {
            options_ended,
            skip_next,
        }
    }

    #[inline]
    #[must_use]
    fn advance_command(mut options_ended: bool, skip_next: u8, token: &str) -> Self {
        let mut skip_next = skip_next;
        if skip_next > 0 {
            skip_next = skip_next.saturating_sub(1);
            return Self::Command {
                options_ended,
                skip_next,
            };
        }
        if !options_ended && token == "--" {
            options_ended = true;
            return Self::Command {
                options_ended,
                skip_next,
            };
        }
        if !options_ended && token.starts_with('-') {
            // `command -v/-V` queries command resolution (not a wrapper execution).
            if matches!(token, "-v" | "-V") {
                return Self::CommandQuery;
            }
            // `command -p` is wrapper-like (no value).
            return Self::Command {
                options_ended,
                skip_next,
            };
        }
        Self::Command {
            options_ended,
            skip_next,
        }
    }

    #[inline]
    #[must_use]
    fn advance(self, token: &str) -> Self {
        match self {
            Self::Sudo {
                options_ended,
                skip_next,
            } => Self::advance_sudo(options_ended, skip_next, token),
            Self::Env {
                options_ended,
                skip_next,
            } => Self::advance_env(options_ended, skip_next, token),
            Self::Command {
                options_ended,
                skip_next,
            } => Self::advance_command(options_ended, skip_next, token),
            Self::None | Self::CommandQuery => self,
        }
    }
}

#[must_use]
fn normalize_command_word_token(token: &str) -> Option<String> {
    let mut out = token;
    let mut changed = false;

    let stripped = out.trim_start_matches('\\');
    if !stripped.is_empty() && stripped.len() != out.len() {
        // Only strip leading backslashes when it looks like an escaped command word.
        // This avoids turning escaped quotes (e.g., `\"`) into real quotes, which can
        // change tokenization on subsequent normalization passes.
        let first = stripped.as_bytes()[0];
        let looks_like_command =
            first.is_ascii_alphanumeric() || matches!(first, b'/' | b'.' | b'_' | b'~');
        if looks_like_command {
            out = stripped;
            changed = true;
        }
    }

    if let Some((quote, inner)) = out.strip_prefix(['\'', '"']).and_then(|rest| {
        rest.strip_suffix(['\'', '"'])
            .map(|inner| (out.as_bytes()[0], inner))
    }) {
        // Only unquote when it's clearly a single-token command word (no whitespace/separators).
        let inner_bytes = inner.as_bytes();
        let is_safe = !inner_bytes.is_empty()
            && !inner_bytes.iter().any(u8::is_ascii_whitespace)
            && !inner_bytes
                .iter()
                .any(|b| matches!(b, b'|' | b';' | b'&' | b'(' | b')'))
            && inner_bytes.first().is_some_and(|b| *b != quote);

        if is_safe {
            out = inner;
            changed = true;
        }
    }

    if changed { Some(out.to_string()) } else { None }
}

/// Normalize wrapper/segment command words for matching.
///
/// This removes harmless quoting around *executed* command tokens:
/// - `"git" reset --hard` → `git reset --hard`
/// - `sudo "/bin/rm" -rf /etc` → `sudo /bin/rm -rf /etc`
///
/// Quoted **arguments** are intentionally left alone to avoid creating new
/// "dangerous substring" matches in data contexts.
#[must_use]
fn dequote_segment_command_words(command: &str) -> Cow<'_, str> {
    // Fast path: most commands contain no quotes.
    if !command.as_bytes().iter().any(|b| matches!(b, b'\'' | b'"')) {
        return Cow::Borrowed(command);
    }

    let tokens = tokenize_for_normalization(command);
    if tokens.is_empty() {
        return Cow::Borrowed(command);
    }

    let mut replacements: Vec<(Range<usize>, String)> = Vec::new();
    let mut segment_has_cmd = false;
    let mut wrapper: NormalizeWrapper = NormalizeWrapper::None;

    for token in &tokens {
        if token.kind == NormalizeTokenKind::Separator {
            segment_has_cmd = false;
            wrapper = NormalizeWrapper::None;
            continue;
        }

        let Some(token_text) = token.text(command) else {
            // If we can't safely slice, fail open.
            return Cow::Borrowed(command);
        };

        if segment_has_cmd {
            continue;
        }

        let current = token_text;

        // `command -v/-V ...` is a query, not execution.
        if matches!(wrapper, NormalizeWrapper::CommandQuery) {
            segment_has_cmd = true;
            wrapper = NormalizeWrapper::None;
            continue;
        }

        // Wrapper option (or wrapper option argument) - consume and continue.
        if wrapper.should_skip_token(current) {
            wrapper = wrapper.advance(current);
            continue;
        }

        // If a wrapper is active and this token isn't an option/assignment, the wrapper is done.
        if !matches!(wrapper, NormalizeWrapper::None) {
            wrapper = NormalizeWrapper::None;
        }

        // If we haven't found the command word yet, check wrappers/assignments.
        if let Some(next_wrapper) = NormalizeWrapper::from_command_word(current) {
            wrapper = next_wrapper;
            continue;
        }

        if is_env_assignment(current) {
            continue;
        }

        // Found the segment's command word.
        segment_has_cmd = true;

        if let Some(replacement) = normalize_command_word_token(current) {
            replacements.push((token.byte_range.clone(), replacement));
        }
    }

    if replacements.is_empty() {
        return Cow::Borrowed(command);
    }

    // Apply replacements in-order.
    replacements.sort_by_key(|(r, _)| r.start);
    let mut out = String::with_capacity(command.len());
    let mut last = 0usize;
    for (range, replacement) in replacements {
        if range.start > last {
            out.push_str(&command[last..range.start]);
        }
        out.push_str(&replacement);
        last = range.end;
    }
    if last < command.len() {
        out.push_str(&command[last..]);
    }

    Cow::Owned(out)
}

/// Normalize a command by stripping absolute paths from common binaries.
///
/// Returns the original command unchanged if normalization fails (fail-open).
#[inline]
pub fn normalize_command(cmd: &str) -> Cow<'_, str> {
    let cmd = dequote_segment_command_words(cmd);

    match cmd {
        Cow::Borrowed(cmd) => {
            if !cmd.starts_with('/') {
                return Cow::Borrowed(cmd);
            }
            // Use try_replacen to handle regex errors gracefully (e.g., backtrack limit exceeded)
            // On error, return the original command unchanged (fail-open for safety)
            // Limit 1: only replace the first match (path prefix)
            PATH_NORMALIZER
                .try_replacen(cmd, 1, "$1")
                .unwrap_or(Cow::Borrowed(cmd))
        }
        Cow::Owned(cmd) => {
            if !cmd.starts_with('/') {
                return Cow::Owned(cmd);
            }
            match PATH_NORMALIZER.try_replacen(&cmd, 1, "$1") {
                Ok(Cow::Owned(replaced)) => Cow::Owned(replaced),
                Ok(Cow::Borrowed(_)) | Err(_) => Cow::Owned(cmd),
            }
        }
    }
}

/// Pre-compiled finders for core quick rejection (git/rm).
static GIT_FINDER: LazyLock<memmem::Finder<'static>> = LazyLock::new(|| memmem::Finder::new("git"));
static RM_FINDER: LazyLock<memmem::Finder<'static>> = LazyLock::new(|| memmem::Finder::new("rm"));

/// Core quick-reject filter (legacy - only checks git/rm).
/// Returns true if command definitely doesn't need core checking (no "git" or "rm").
///
/// NOTE: This only checks core keywords. Use `pack_aware_quick_reject` for
/// commands that need to be checked against enabled packs.
#[inline]
pub fn global_quick_reject(cmd: &str) -> bool {
    let bytes = cmd.as_bytes();
    GIT_FINDER.find(bytes).is_none() && RM_FINDER.find(bytes).is_none()
}

#[inline]
const fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[inline]
fn keyword_matches_span(span_text: &str, keyword: &str) -> bool {
    if keyword.is_empty() {
        return false;
    }

    let haystack = span_text.as_bytes();
    let needle = keyword.as_bytes();
    if needle.len() > haystack.len() {
        return false;
    }

    let first_is_word = needle.first().is_some_and(|b| is_word_byte(*b));
    let last_is_word = needle.last().is_some_and(|b| is_word_byte(*b));
    let mut offset = 0;

    while let Some(pos) = memmem::find(&haystack[offset..], needle) {
        let start = offset + pos;
        let end = start + needle.len();
        let start_ok =
            !first_is_word || start == 0 || !is_word_byte(haystack[start.saturating_sub(1)]);
        let end_ok = !last_is_word || end == haystack.len() || !is_word_byte(haystack[end]);

        if start_ok && end_ok {
            return true;
        }

        offset = start + 1;
    }

    false
}

#[inline]
fn span_matches_any_keyword(span_text: &str, enabled_keywords: &[&str]) -> bool {
    enabled_keywords
        .iter()
        .any(|keyword| keyword_matches_span(span_text, keyword))
}

/// Pack-aware quick-reject filter.
///
/// Returns true if the command can be safely skipped (contains none of the
/// provided keywords from enabled packs).
///
/// This is the correct function to use when non-core packs are enabled.
/// It checks all keywords from enabled packs, not just "git" and "rm".
///
/// # Performance
///
/// Uses SIMD-accelerated substring search via memchr as a fast prefilter,
/// then applies token-aware checks inside executable spans (via context
/// classification) to avoid substring false triggers.
///
/// # Arguments
///
/// * `cmd` - The command string to check
/// * `enabled_keywords` - Keywords from all enabled packs (from `PackRegistry::collect_enabled_keywords`)
///
/// # Returns
///
/// `true` if the command contains NO keywords (safe to skip pack checking)
/// `false` if the command contains at least one keyword (must check packs)
#[inline]
#[must_use]
pub fn pack_aware_quick_reject(cmd: &str, enabled_keywords: &[&str]) -> bool {
    // Conservative: if the caller provides no keywords, we cannot safely conclude
    // that pack evaluation can be skipped (a pack may have empty/incorrect keywords).
    // Returning false forces evaluation rather than silently allowing everything.
    if enabled_keywords.is_empty() {
        return false;
    }

    let bytes = cmd.as_bytes();
    let any_substring = enabled_keywords
        .iter()
        .any(|keyword| memmem::find(bytes, keyword.as_bytes()).is_some());
    if !any_substring {
        return true;
    }

    // Important: run keyword gating on a normalized view so harmless quoting or
    // path prefixes on *executed command words* don't cause false skips.
    //
    // Example: `" /usr/bin/git" reset --hard` should NOT quick-reject.
    let normalized = normalize_command(cmd);
    let cmd_for_spans = normalized.as_ref();

    let spans = crate::context::classify_command(cmd_for_spans);
    let mut saw_executable = false;

    for span in spans.executable_spans() {
        saw_executable = true;
        let span_text = span.text(cmd_for_spans);
        if span_text.is_empty() {
            continue;
        }
        if span_matches_any_keyword(span_text, enabled_keywords) {
            return false;
        }
    }

    if !saw_executable {
        return true;
    }

    true // No keywords found in executable spans, safe to skip pack checking
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_aware_quick_reject_empty_keywords_is_conservative() {
        assert!(
            !pack_aware_quick_reject("ls -la", &[]),
            "empty keyword list must not allow skipping pack evaluation"
        );
        assert!(
            !pack_aware_quick_reject("git reset --hard", &[]),
            "empty keyword list must not allow skipping pack evaluation"
        );
    }

    #[test]
    fn pack_aware_quick_reject_ignores_substring_matches() {
        let keywords: Vec<&str> = vec!["git", "rm", "docker"];

        assert!(
            pack_aware_quick_reject("cat .gitignore", &keywords),
            "substring in filename should not trigger keyword gating"
        );
        assert!(
            pack_aware_quick_reject("echo digit", &keywords),
            "substring in a larger token should not trigger keyword gating"
        );
    }

    #[test]
    fn pack_aware_quick_reject_keeps_word_boundary_matches() {
        let keywords: Vec<&str> = vec!["git"];

        assert!(
            !pack_aware_quick_reject("git status", &keywords),
            "word boundary keyword should prevent quick-reject"
        );
        assert!(
            !pack_aware_quick_reject("/usr/bin/git status", &keywords),
            "absolute path to git should still prevent quick-reject"
        );
    }

    /// Regression test: rm commands should NOT be quick-rejected regardless of target directory.
    /// Bug git_safety_guard-nwu: "rm -rf build" was incorrectly allowed while "rm -rf src" was blocked.
    #[test]
    fn pack_aware_quick_reject_rm_commands_not_rejected() {
        let keywords: Vec<&str> = vec!["rm"];

        // All rm commands should NOT be quick-rejected (should return false)
        assert!(
            !pack_aware_quick_reject("rm -rf build", &keywords),
            "rm -rf build should NOT be quick-rejected"
        );
        assert!(
            !pack_aware_quick_reject("rm -rf src", &keywords),
            "rm -rf src should NOT be quick-rejected"
        );
        assert!(
            !pack_aware_quick_reject("rm -rf target", &keywords),
            "rm -rf target should NOT be quick-rejected"
        );
        assert!(
            !pack_aware_quick_reject("rm -rf dist", &keywords),
            "rm -rf dist should NOT be quick-rejected"
        );
        assert!(
            !pack_aware_quick_reject("rm -rf node_modules", &keywords),
            "rm -rf node_modules should NOT be quick-rejected"
        );
        assert!(
            !pack_aware_quick_reject("rm -rf foo", &keywords),
            "rm -rf foo should NOT be quick-rejected"
        );
    }

    /// Regression test: full flow from "core" category to keyword collection to quick-reject.
    /// Bug git_safety_guard-nwu: The full evaluation flow was incorrectly allowing build dir removals.
    #[test]
    fn full_flow_core_category_rm_commands_blocked() {
        // Simulate the default config: enabled_pack_ids returns {"core"}
        let mut enabled = HashSet::new();
        enabled.insert("core".to_string());

        // This is what enabled_pack_ids() returns by default
        let keywords = REGISTRY.collect_enabled_keywords(&enabled);

        // Verify "rm" is in the keywords (from core.filesystem)
        assert!(
            keywords.contains(&"rm"),
            "Keywords should include 'rm' from core.filesystem. Got: {keywords:?}"
        );

        // All rm commands should NOT be quick-rejected
        assert!(
            !pack_aware_quick_reject("rm -rf build", &keywords),
            "rm -rf build should NOT be quick-rejected with core keywords"
        );
        assert!(
            !pack_aware_quick_reject("rm -rf src", &keywords),
            "rm -rf src should NOT be quick-rejected with core keywords"
        );
        assert!(
            !pack_aware_quick_reject("rm -rf target", &keywords),
            "rm -rf target should NOT be quick-rejected with core keywords"
        );

        // And check_command should block them
        let result = REGISTRY.check_command("rm -rf build", &enabled);
        assert!(
            result.blocked,
            "rm -rf build should be BLOCKED by core.filesystem"
        );
        let result = REGISTRY.check_command("rm -rf src", &enabled);
        assert!(
            result.blocked,
            "rm -rf src should be BLOCKED by core.filesystem"
        );
    }

    /// Test that `pack_tier` returns correct tiers for all known categories.
    #[test]
    fn pack_tier_ordering() {
        // Core should be highest priority (tier 1)
        assert_eq!(PackRegistry::pack_tier("core.git"), 1);
        assert_eq!(PackRegistry::pack_tier("core.filesystem"), 1);

        // System should be tier 2
        assert_eq!(PackRegistry::pack_tier("system.disk"), 2);
        assert_eq!(PackRegistry::pack_tier("system.permissions"), 2);

        // Infrastructure should be tier 3
        assert_eq!(PackRegistry::pack_tier("infrastructure.terraform"), 3);

        // Cloud should be tier 4
        assert_eq!(PackRegistry::pack_tier("cloud.aws"), 4);

        // Kubernetes should be tier 5
        assert_eq!(PackRegistry::pack_tier("kubernetes.kubectl"), 5);

        // Containers should be tier 6
        assert_eq!(PackRegistry::pack_tier("containers.docker"), 6);

        // Database should be tier 7
        assert_eq!(PackRegistry::pack_tier("database.postgresql"), 7);

        // Package managers should be tier 8
        assert_eq!(PackRegistry::pack_tier("package_managers"), 8);

        // Strict git should be tier 9
        assert_eq!(PackRegistry::pack_tier("strict_git"), 9);

        // CI/CD should be tier 10
        assert_eq!(PackRegistry::pack_tier("cicd.github_actions"), 10);

        // Unknown should be tier 11
        assert_eq!(PackRegistry::pack_tier("unknown.pack"), 11);
    }

    /// Test that `expand_enabled_ordered` returns packs in deterministic order.
    #[test]
    fn expand_enabled_ordered_is_deterministic() {
        let mut enabled = HashSet::new();
        enabled.insert("containers.docker".to_string());
        enabled.insert("kubernetes.kubectl".to_string());
        enabled.insert("core.git".to_string());
        enabled.insert("database.postgresql".to_string());

        // Run multiple times to verify determinism
        let first_run = REGISTRY.expand_enabled_ordered(&enabled);

        for _ in 0..10 {
            let run = REGISTRY.expand_enabled_ordered(&enabled);
            assert_eq!(
                run, first_run,
                "expand_enabled_ordered should produce identical results across runs"
            );
        }
    }

    /// Test that `expand_enabled_ordered` sorts by tier then lexicographically.
    #[test]
    fn expand_enabled_ordered_respects_tier_ordering() {
        let mut enabled = HashSet::new();
        enabled.insert("containers.docker".to_string()); // tier 6
        enabled.insert("core.git".to_string()); // tier 1
        enabled.insert("database.postgresql".to_string()); // tier 7

        let ordered = REGISTRY.expand_enabled_ordered(&enabled);

        // Find positions
        let core_pos = ordered.iter().position(|id| id == "core.git");
        let docker_pos = ordered.iter().position(|id| id == "containers.docker");
        let pg_pos = ordered.iter().position(|id| id == "database.postgresql");

        assert!(
            core_pos.is_some() && docker_pos.is_some() && pg_pos.is_some(),
            "All packs should be present"
        );

        // Core (tier 1) should come before containers (tier 6)
        assert!(
            core_pos.unwrap() < docker_pos.unwrap(),
            "core.git should come before containers.docker"
        );

        // Containers (tier 6) should come before database (tier 7)
        assert!(
            docker_pos.unwrap() < pg_pos.unwrap(),
            "containers.docker should come before database.postgresql"
        );
    }

    /// Test that `expand_enabled_ordered` sorts lexicographically within tier.
    #[test]
    fn expand_enabled_ordered_sorts_within_tier() {
        let mut enabled = HashSet::new();
        enabled.insert("core.git".to_string());
        enabled.insert("core.filesystem".to_string());

        let ordered = REGISTRY.expand_enabled_ordered(&enabled);

        let fs_pos = ordered.iter().position(|id| id == "core.filesystem");
        let git_pos = ordered.iter().position(|id| id == "core.git");

        assert!(
            fs_pos.is_some() && git_pos.is_some(),
            "Both core packs should be present"
        );

        // filesystem < git lexicographically
        assert!(
            fs_pos.unwrap() < git_pos.unwrap(),
            "core.filesystem should come before core.git (lexicographic)"
        );
    }

    /// Test that `check_command` returns consistent attribution across runs.
    /// This is the key regression test for deterministic pack evaluation.
    #[test]
    fn check_command_attribution_is_deterministic() {
        // Enable both core.git and strict_git packs
        // If a git command matches both, core.git should always win (lower tier)
        let mut enabled = HashSet::new();
        enabled.insert("core.git".to_string());
        enabled.insert("strict_git".to_string());

        let cmd = "git reset --hard";

        // Run multiple times
        let first_result = REGISTRY.check_command(cmd, &enabled);

        for _ in 0..10 {
            let result = REGISTRY.check_command(cmd, &enabled);
            assert_eq!(
                result.blocked, first_result.blocked,
                "Blocked status should be consistent"
            );
            assert_eq!(
                result.pack_id, first_result.pack_id,
                "Pack attribution should be consistent across runs"
            );
            assert_eq!(
                result.pattern_name, first_result.pattern_name,
                "Pattern name should be consistent across runs"
            );
        }
    }

    /// Test that when multiple packs match, the higher-priority pack is attributed.
    #[test]
    fn check_command_prefers_higher_priority_pack() {
        let mut enabled = HashSet::new();
        enabled.insert("core.git".to_string()); // tier 1
        enabled.insert("strict_git".to_string()); // tier 9

        let cmd = "git reset --hard";
        let result = REGISTRY.check_command(cmd, &enabled);

        assert!(result.blocked, "Command should be blocked");
        assert_eq!(
            result.pack_id.as_deref(),
            Some("core.git"),
            "core.git (tier 1) should be attributed over strict_git (tier 9)"
        );
    }

    #[test]
    fn database_packs_block_drop_with_if_exists() {
        let pg = database::postgresql::create_pack();
        assert!(
            pg.check("DROP TABLE IF EXISTS foo;").is_some(),
            "DROP TABLE IF EXISTS should be treated as destructive"
        );
        assert!(
            pg.check("DROP DATABASE IF EXISTS foo;").is_some(),
            "DROP DATABASE IF EXISTS should be treated as destructive"
        );

        let sqlite = database::sqlite::create_pack();
        assert!(
            sqlite.check("DROP TABLE IF EXISTS foo;").is_some(),
            "SQLite DROP TABLE IF EXISTS should be treated as destructive"
        );
    }

    #[test]
    fn database_postgresql_blocks_truncate_restart_identity() {
        let pg = database::postgresql::create_pack();
        assert!(
            pg.check("TRUNCATE TABLE foo RESTART IDENTITY;").is_some(),
            "TRUNCATE ... RESTART IDENTITY permanently deletes rows and should be blocked"
        );
    }

    /// Test category expansion produces ordered results.
    #[test]
    fn category_expansion_is_ordered() {
        let mut enabled = HashSet::new();
        enabled.insert("containers".to_string()); // Category - expands to docker, compose, podman

        let ordered = REGISTRY.expand_enabled_ordered(&enabled);

        // All containers packs should be present
        let has_docker = ordered.iter().any(|id| id == "containers.docker");
        let has_compose = ordered.iter().any(|id| id == "containers.compose");
        let has_podman = ordered.iter().any(|id| id == "containers.podman");

        assert!(
            has_docker && has_compose && has_podman,
            "Category expansion should include all sub-packs"
        );

        // Should be in lexicographic order (compose < docker < podman)
        let compose_pos = ordered.iter().position(|id| id == "containers.compose");
        let docker_pos = ordered.iter().position(|id| id == "containers.docker");
        let podman_pos = ordered.iter().position(|id| id == "containers.podman");

        assert!(
            compose_pos.unwrap() < docker_pos.unwrap(),
            "compose should come before docker"
        );
        assert!(
            docker_pos.unwrap() < podman_pos.unwrap(),
            "docker should come before podman"
        );
    }

    /// Test that `check_command` returns `pattern_name` when available.
    #[test]
    fn check_command_returns_pattern_name() {
        let mut enabled = HashSet::new();
        enabled.insert("containers.docker".to_string());

        // docker system prune should match a named destructive pattern
        let cmd = "docker system prune";
        let result = REGISTRY.check_command(cmd, &enabled);

        assert!(result.blocked, "docker system prune should be blocked");
        assert_eq!(
            result.pack_id.as_deref(),
            Some("containers.docker"),
            "Should be attributed to containers.docker"
        );
        // Verify pattern_name is propagated (may be None if pattern is unnamed)
        // The important thing is the field exists and is correctly populated
        assert!(
            result.pattern_name.is_some() || result.reason.is_some(),
            "Blocked result should have pattern metadata"
        );
    }

    /// Test that `DestructiveMatch` contains both reason and name.
    #[test]
    fn destructive_match_contains_metadata() {
        let docker_pack = REGISTRY
            .packs
            .get("containers.docker")
            .expect("docker pack exists");

        // Check docker system prune matches
        let matched = docker_pack.matches_destructive("docker system prune");
        assert!(matched.is_some(), "docker system prune should match");

        let m = matched.unwrap();
        assert!(!m.reason.is_empty(), "reason should not be empty");
        // name may or may not be set depending on pack definition
    }

    /// Regression test for git_safety_guard-hcj: regex backtracking panic.
    ///
    /// Pathological inputs with many consecutive `/` characters can cause
    /// fancy-regex to exceed its backtrack limit. This should fail-open
    /// (return the original command) rather than panic.
    #[test]
    fn normalize_command_handles_pathological_input() {
        // This input was discovered by fuzzing and caused a panic
        let pathological = "//////////////////_(rm";
        let result = normalize_command(pathological);

        // Should not panic, and should return the original command unchanged
        // (since it doesn't match the expected /path/to/bin/rm pattern)
        assert_eq!(result.as_ref(), pathological);

        // Additional pathological inputs
        let long_slashes = "/".repeat(1000) + "rm";
        let result2 = normalize_command(&long_slashes);
        // Should not panic - exact output doesn't matter, just that it doesn't crash
        assert!(!result2.is_empty());

        // Input with null bytes (also discovered by fuzzing)
        let with_nulls = "///\0\0/\0\0/\0\0//\0\0/\0[";
        let result3 = normalize_command(with_nulls);
        assert_eq!(result3.as_ref(), with_nulls);
    }

    // =========================================================================
    // Severity taxonomy tests (git_safety_guard-1gt.3.1)
    // =========================================================================

    /// Test that Severity enum has correct default mode mappings.
    #[test]
    fn severity_default_modes() {
        // Critical and High should block by default
        assert_eq!(Severity::Critical.default_mode(), DecisionMode::Deny);
        assert_eq!(Severity::High.default_mode(), DecisionMode::Deny);

        // Medium should warn by default
        assert_eq!(Severity::Medium.default_mode(), DecisionMode::Warn);

        // Low should log only by default
        assert_eq!(Severity::Low.default_mode(), DecisionMode::Log);
    }

    /// Test that `Severity::blocks_by_default` is consistent with `default_mode`.
    #[test]
    fn severity_blocks_by_default_consistency() {
        assert!(Severity::Critical.blocks_by_default());
        assert!(Severity::High.blocks_by_default());
        assert!(!Severity::Medium.blocks_by_default());
        assert!(!Severity::Low.blocks_by_default());

        // Verify consistency with DecisionMode::blocks()
        for severity in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
        ] {
            assert_eq!(
                severity.blocks_by_default(),
                severity.default_mode().blocks(),
                "blocks_by_default should match default_mode().blocks() for {severity:?}"
            );
        }
    }

    /// Test `DecisionMode` behavior.
    #[test]
    fn decision_mode_blocks() {
        assert!(DecisionMode::Deny.blocks(), "Deny should block");
        assert!(!DecisionMode::Warn.blocks(), "Warn should not block");
        assert!(!DecisionMode::Log.blocks(), "Log should not block");
    }

    /// Test severity labels.
    #[test]
    fn severity_labels() {
        assert_eq!(Severity::Critical.label(), "critical");
        assert_eq!(Severity::High.label(), "high");
        assert_eq!(Severity::Medium.label(), "medium");
        assert_eq!(Severity::Low.label(), "low");
    }

    /// Test decision mode labels.
    #[test]
    fn decision_mode_labels() {
        assert_eq!(DecisionMode::Deny.label(), "deny");
        assert_eq!(DecisionMode::Warn.label(), "warn");
        assert_eq!(DecisionMode::Log.label(), "log");
    }

    /// Test that `CheckResult` includes severity and `decision_mode`.
    #[test]
    fn check_result_includes_severity() {
        let mut enabled = HashSet::new();
        enabled.insert("core.git".to_string());

        let cmd = "git reset --hard";
        let result = REGISTRY.check_command(cmd, &enabled);

        assert!(result.blocked, "git reset --hard should be blocked");
        assert!(
            result.severity.is_some(),
            "Blocked result should include severity"
        );
        assert!(
            result.decision_mode.is_some(),
            "Blocked result should include decision_mode"
        );

        // By default, patterns are High severity which blocks
        let severity = result.severity.unwrap();
        let mode = result.decision_mode.unwrap();
        assert!(severity.blocks_by_default());
        assert!(mode.blocks());
    }

    /// Test that allowed results have None for severity and `decision_mode`.
    #[test]
    fn allowed_result_no_severity() {
        let result = CheckResult::allowed();
        assert!(!result.blocked);
        assert!(result.severity.is_none());
        assert!(result.decision_mode.is_none());
    }

    /// Test `DestructiveMatch` includes severity.
    #[test]
    fn destructive_match_includes_severity() {
        let docker_pack = REGISTRY
            .packs
            .get("containers.docker")
            .expect("docker pack exists");

        let matched = docker_pack.matches_destructive("docker system prune");
        assert!(matched.is_some(), "docker system prune should match");

        let m = matched.unwrap();
        // Default severity is High
        assert_eq!(m.severity, Severity::High);
    }

    /// Test Severity Default trait implementation.
    #[test]
    fn severity_default() {
        let default: Severity = Severity::default();
        assert_eq!(default, Severity::High);
    }

    /// Test `DecisionMode` Default trait implementation.
    #[test]
    fn decision_mode_default() {
        let default: DecisionMode = DecisionMode::default();
        assert_eq!(default, DecisionMode::Deny);
    }

    // =========================================================================
    // Severity regression tests (git_safety_guard-1gt.3.2)
    // =========================================================================
    // These tests prevent accidental severity drift for high-impact rules.
    // Changing severity of a rule changes its blocking behavior (critical/high block,
    // medium warns, low logs). Unintentional changes could let dangerous commands through.

    /// Verify critical git rules remain at Critical severity.
    #[test]
    fn severity_regression_git_critical_rules() {
        let git_pack = REGISTRY
            .get("core.git")
            .expect("core.git pack should exist");

        // These rules should ALWAYS be Critical - they're the most dangerous
        let critical_rules = [
            "reset-hard",
            "clean-force",
            "push-force-long",
            "push-force-short",
            "stash-clear",
        ];

        for rule_name in critical_rules {
            let pattern = git_pack
                .destructive_patterns
                .iter()
                .find(|p| p.name == Some(rule_name))
                .unwrap_or_else(|| panic!("Rule {rule_name} should exist in core.git"));

            assert_eq!(
                pattern.severity,
                Severity::Critical,
                "Rule {rule_name} in core.git should be Critical severity"
            );
        }
    }

    /// Verify filesystem critical rule remains at Critical severity.
    #[test]
    fn severity_regression_filesystem_critical_rules() {
        let fs_pack = REGISTRY
            .get("core.filesystem")
            .expect("core.filesystem pack should exist");

        // rm -rf on root/home is the most dangerous possible command
        let pattern = fs_pack
            .destructive_patterns
            .iter()
            .find(|p| p.name == Some("rm-rf-root-home"))
            .expect("rm-rf-root-home rule should exist");

        assert_eq!(
            pattern.severity,
            Severity::Critical,
            "rm-rf-root-home should be Critical severity (most dangerous)"
        );
    }

    /// Verify high-severity rules aren't accidentally downgraded.
    #[test]
    fn severity_regression_git_high_rules() {
        let git_pack = REGISTRY
            .get("core.git")
            .expect("core.git pack should exist");

        // These should be at least High (blocking by default)
        let high_or_above_rules = [
            "checkout-discard",
            "checkout-ref-discard",
            "restore-worktree",
            "restore-worktree-explicit",
            "reset-merge",
        ];

        for rule_name in high_or_above_rules {
            let pattern = git_pack
                .destructive_patterns
                .iter()
                .find(|p| p.name == Some(rule_name))
                .unwrap_or_else(|| panic!("Rule {rule_name} should exist in core.git"));

            assert!(
                pattern.severity.blocks_by_default(),
                "Rule {rule_name} in core.git should block by default (High or Critical)"
            );
        }
    }

    /// Verify all core pack rules have explicit blocking behavior.
    #[test]
    fn all_core_rules_block_by_default() {
        // Core packs should be conservative - all rules should block by default
        for pack_id in ["core.git", "core.filesystem"] {
            let pack = REGISTRY.get(pack_id).expect("Pack should exist");

            for pattern in &pack.destructive_patterns {
                let name = pattern.name.unwrap_or("<unnamed>");
                assert!(
                    pattern.severity.blocks_by_default(),
                    "Core pack rule {pack_id}:{name} should block by default"
                );
            }
        }
    }

    // =========================================================================
    // Safe cleanup pack cross-pack tests (git_safety_guard-t8x.4)
    // =========================================================================

    /// Test that safe.cleanup pack is at tier 0 (highest priority).
    #[test]
    fn safe_cleanup_tier_is_zero() {
        assert_eq!(
            PackRegistry::pack_tier("safe.cleanup"),
            0,
            "safe.cleanup should be tier 0 (highest priority)"
        );
    }

    /// Test that safe.cleanup pack is registered in the registry.
    #[test]
    fn safe_cleanup_pack_exists() {
        assert!(
            REGISTRY.get("safe.cleanup").is_some(),
            "safe.cleanup pack should be registered"
        );
    }

    /// Test that safe.cleanup overrides core.filesystem blocking for build directories.
    ///
    /// This is the critical integration test for cross-pack safe pattern behavior.
    /// When both safe.cleanup and core.filesystem are enabled, safe.cleanup's safe
    /// patterns should be checked first (due to tier ordering), allowing commands
    /// that would otherwise be blocked by core.filesystem.
    #[test]
    fn safe_cleanup_overrides_core_filesystem_for_build_dirs() {
        // Without safe.cleanup, these commands would be blocked by core.filesystem
        let mut enabled_without_cleanup = HashSet::new();
        enabled_without_cleanup.insert("core.filesystem".to_string());

        let cmd = "rm -rf target/";
        let result = REGISTRY.check_command(cmd, &enabled_without_cleanup);
        assert!(
            result.blocked,
            "rm -rf target/ should be blocked without safe.cleanup"
        );

        // With safe.cleanup enabled, the same command should be allowed
        let mut enabled_with_cleanup = HashSet::new();
        enabled_with_cleanup.insert("core.filesystem".to_string());
        enabled_with_cleanup.insert("safe.cleanup".to_string());

        let result = REGISTRY.check_command(cmd, &enabled_with_cleanup);
        assert!(
            !result.blocked,
            "rm -rf target/ should be allowed when safe.cleanup is enabled"
        );

        // Test other common build directories
        let build_dirs = ["rm -rf dist/", "rm -rf node_modules/", "rm -rf build/"];
        for dir_cmd in build_dirs {
            let result = REGISTRY.check_command(dir_cmd, &enabled_with_cleanup);
            assert!(
                !result.blocked,
                "{dir_cmd} should be allowed when safe.cleanup is enabled"
            );
        }
    }

    /// Test that safe.cleanup does NOT allow path traversal even when enabled.
    #[test]
    fn safe_cleanup_still_blocks_path_traversal() {
        let mut enabled = HashSet::new();
        enabled.insert("core.filesystem".to_string());
        enabled.insert("safe.cleanup".to_string());

        // Path traversal should still be blocked
        let traversal_cmd = "rm -rf ../target/";
        let result = REGISTRY.check_command(traversal_cmd, &enabled);
        assert!(
            result.blocked,
            "rm -rf ../target/ should still be blocked (path traversal)"
        );

        let embedded_traversal = "rm -rf foo/../target/";
        let result = REGISTRY.check_command(embedded_traversal, &enabled);
        assert!(
            result.blocked,
            "rm -rf foo/../target/ should still be blocked (embedded traversal)"
        );
    }

    /// Test that safe.cleanup does NOT allow absolute paths even when enabled.
    #[test]
    fn safe_cleanup_still_blocks_absolute_paths() {
        let mut enabled = HashSet::new();
        enabled.insert("core.filesystem".to_string());
        enabled.insert("safe.cleanup".to_string());

        let absolute_cmd = "rm -rf /target/";
        let result = REGISTRY.check_command(absolute_cmd, &enabled);
        assert!(
            result.blocked,
            "rm -rf /target/ should still be blocked (absolute path)"
        );
    }

    /// Test that safe.cleanup does NOT allow arbitrary directories.
    #[test]
    fn safe_cleanup_still_blocks_non_allowlisted_dirs() {
        let mut enabled = HashSet::new();
        enabled.insert("core.filesystem".to_string());
        enabled.insert("safe.cleanup".to_string());

        // src/ is NOT in the allowlist
        let src_cmd = "rm -rf src/";
        let result = REGISTRY.check_command(src_cmd, &enabled);
        assert!(
            result.blocked,
            "rm -rf src/ should still be blocked (not in cleanup allowlist)"
        );
    }

    mod normalization_tests {
        use super::*;

        #[test]
        fn preserves_plain_git_command() {
            assert_eq!(normalize_command("git status"), "git status");
        }

        #[test]
        fn preserves_plain_rm_command() {
            assert_eq!(normalize_command("rm -rf /tmp/foo"), "rm -rf /tmp/foo");
        }

        #[test]
        fn strips_usr_bin_git() {
            assert_eq!(normalize_command("/usr/bin/git status"), "git status");
        }

        #[test]
        fn strips_usr_local_bin_git() {
            assert_eq!(
                normalize_command("/usr/local/bin/git checkout -b feature"),
                "git checkout -b feature"
            );
        }

        #[test]
        fn strips_bin_rm() {
            assert_eq!(
                normalize_command("/bin/rm -rf /tmp/test"),
                "rm -rf /tmp/test"
            );
        }

        #[test]
        fn strips_usr_bin_rm() {
            assert_eq!(normalize_command("/usr/bin/rm file.txt"), "rm file.txt");
        }

        #[test]
        fn strips_sbin_path() {
            assert_eq!(normalize_command("/sbin/rm foo"), "rm foo");
        }

        #[test]
        fn strips_usr_sbin_path() {
            assert_eq!(normalize_command("/usr/sbin/rm bar"), "rm bar");
        }

        #[test]
        fn preserves_command_with_path_arguments() {
            assert_eq!(
                normalize_command("git add /usr/bin/something"),
                "git add /usr/bin/something"
            );
        }

        #[test]
        fn handles_empty_string() {
            assert_eq!(normalize_command(""), "");
        }

        #[test]
        fn strips_quotes_from_executed_git_command_word() {
            assert_eq!(
                normalize_command("\"git\" reset --hard"),
                "git reset --hard"
            );
        }

        #[test]
        fn strips_quotes_from_executed_rm_command_word() {
            assert_eq!(normalize_command("\"rm\" -rf /etc"), "rm -rf /etc");
        }

        #[test]
        fn strips_quotes_from_executed_absolute_path_command_word() {
            assert_eq!(
                normalize_command("\"/usr/bin/git\" reset --hard"),
                "git reset --hard"
            );
        }

        #[test]
        fn strips_quotes_after_separators() {
            assert_eq!(
                normalize_command("echo hi; \"rm\" -rf /etc"),
                "echo hi; rm -rf /etc"
            );
        }

        #[test]
        fn strips_quotes_after_wrappers_and_options() {
            assert_eq!(
                normalize_command("sudo -u root \"rm\" -rf /etc"),
                "sudo -u root rm -rf /etc"
            );
        }

        #[test]
        fn does_not_strip_quotes_from_arguments() {
            assert_eq!(
                normalize_command("echo \"rm\" -rf /etc"),
                "echo \"rm\" -rf /etc"
            );
        }

        #[test]
        fn does_not_strip_quotes_for_command_query_mode() {
            assert_eq!(
                normalize_command("command -v \"git\""),
                "command -v \"git\""
            );
        }

        #[test]
        fn strips_quotes_inside_subshell_segments() {
            assert_eq!(normalize_command("( \"rm\" -rf /etc )"), "( rm -rf /etc )");
        }
    }

    /// Test that all pack patterns compile correctly.
    ///
    /// This validates that no pack has invalid regex patterns that would only
    /// be discovered at runtime when the lazy regex is first used.
    ///
    /// Related to git_safety_guard-64dc.3 (pattern validity validation).
    #[test]
    fn all_pack_patterns_compile() {
        let mut errors: Vec<String> = Vec::new();

        for pack_id in REGISTRY.all_pack_ids() {
            let pack = REGISTRY.get(pack_id).expect("pack must exist");

            // Validate safe patterns
            for (idx, pattern) in pack.safe_patterns.iter().enumerate() {
                if let Err(e) = fancy_regex::Regex::new(pattern.regex.as_str()) {
                    errors.push(format!(
                        "Pack '{}' safe pattern '{}' (index {}) failed to compile: {}\n  Pattern: {}",
                        pack_id,
                        pattern.name,
                        idx,
                        e,
                        pattern.regex.as_str()
                    ));
                }
            }

            // Validate destructive patterns
            for (idx, pattern) in pack.destructive_patterns.iter().enumerate() {
                let pattern_name = pattern.name.unwrap_or("<unnamed>");
                if let Err(e) = fancy_regex::Regex::new(pattern.regex.as_str()) {
                    errors.push(format!(
                        "Pack '{}' destructive pattern '{}' (index {}) failed to compile: {}\n  Pattern: {}",
                        pack_id,
                        pattern_name,
                        idx,
                        e,
                        pattern.regex.as_str()
                    ));
                }
            }
        }

        if !errors.is_empty() {
            panic!(
                "Found {} invalid regex pattern(s):\n\n{}",
                errors.len(),
                errors.join("\n\n")
            );
        }
    }
}
