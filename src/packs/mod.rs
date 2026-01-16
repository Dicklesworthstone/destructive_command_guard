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

pub mod apigateway;
pub mod backup;
pub mod cdn;
pub mod cicd;
pub mod cloud;
pub mod containers;
pub mod core;
pub mod database;
pub mod dns;
pub mod email;
pub mod featureflags;
pub mod infrastructure;
pub mod kubernetes;
pub mod loadbalancer;
pub mod messaging;
pub mod monitoring;
pub mod package_managers;
pub mod payment;
pub mod platform;
pub mod regex_engine;
pub mod remote;
pub mod safe;
pub mod search;
pub mod secrets;
pub mod storage;
pub mod strict_git;
pub mod system;

// Testing infrastructure
pub mod test_helpers;
#[cfg(test)]
mod test_template;

pub use crate::normalize::normalize_command;
use memchr::memmem;
use regex_engine::LazyCompiledRegex;
use smallvec::SmallVec;
use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, OnceLock};

/// Unique identifier for a pack (e.g., "core", "database.postgresql").
pub type PackId = String;

/// Severity level for destructive patterns.
///
/// Severity determines the default decision mode and allowlisting behavior:
/// - **Critical**: Always block. These are irreversible, high-confidence detections.
/// - **High**: Block by default, but allowlistable by rule ID.
/// - **Medium**: Warn by default (log + continue), blockable via config.
/// - **Low**: Log only (for history/learning), warneable/blockable via config.
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

    /// Log only (silent, for history and learning).
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

    /// Log only (silent allow, record for history).
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
    pub regex: LazyCompiledRegex,
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
    pub regex: LazyCompiledRegex,
    /// Human-readable explanation of why this command is blocked.
    pub reason: &'static str,
    /// Optional pattern name for debugging and allowlisting.
    pub name: Option<&'static str>,
    /// Severity level (determines default decision mode).
    pub severity: Severity,
    /// Detailed explanation of why this pattern is dangerous.
    /// Should explain consequences and suggest alternatives.
    /// This is more verbose than `reason` and intended for verbose output modes.
    pub explanation: Option<&'static str>,
}

impl std::fmt::Debug for DestructivePattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DestructivePattern")
            .field("pattern", &self.regex.as_str())
            .field("reason", &self.reason)
            .field("name", &self.name)
            .field("severity", &self.severity)
            .field("explanation", &self.explanation)
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
            regex: $crate::packs::regex_engine::LazyCompiledRegex::new($re),
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
/// - `destructive_pattern!("name", "regex", "reason", Critical, "explanation")` - with explanation
#[macro_export]
macro_rules! destructive_pattern {
    // Unnamed pattern, default severity (High)
    ($re:literal, $reason:literal) => {
        $crate::packs::DestructivePattern {
            regex: $crate::packs::regex_engine::LazyCompiledRegex::new($re),
            reason: $reason,
            name: None,
            severity: $crate::packs::Severity::High,
            explanation: None,
        }
    };
    // Named pattern, default severity (High)
    ($name:literal, $re:literal, $reason:literal) => {
        $crate::packs::DestructivePattern {
            regex: $crate::packs::regex_engine::LazyCompiledRegex::new($re),
            reason: $reason,
            name: Some($name),
            severity: $crate::packs::Severity::High,
            explanation: None,
        }
    };
    // Named pattern with explicit severity
    ($name:literal, $re:literal, $reason:literal, $severity:ident) => {
        $crate::packs::DestructivePattern {
            regex: $crate::packs::regex_engine::LazyCompiledRegex::new($re),
            reason: $reason,
            name: Some($name),
            severity: $crate::packs::Severity::$severity,
            explanation: None,
        }
    };
    // Named pattern with explicit severity and explanation
    ($name:literal, $re:literal, $reason:literal, $severity:ident, $explanation:literal) => {
        $crate::packs::DestructivePattern {
            regex: $crate::packs::regex_engine::LazyCompiledRegex::new($re),
            reason: $reason,
            name: Some($name),
            severity: $crate::packs::Severity::$severity,
            explanation: Some($explanation),
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

    /// Pre-built `RegexSet` for O(n) safe pattern matching.
    /// Allows checking all safe patterns in a single pass. Built lazily when
    /// the pack is instantiated. Only includes patterns that can use the
    /// linear-time regex engine (no lookahead/lookbehind).
    pub safe_regex_set: Option<regex::RegexSet>,

    /// True if `safe_regex_set` covers ALL safe patterns (no backtracking patterns exist).
    /// When true and the `RegexSet` misses, we can skip individual pattern checks.
    pub safe_regex_set_is_complete: bool,
}

impl Pack {
    /// Create a new pack with the given patterns.
    ///
    /// This constructor initializes the lazy fields (`keyword_matcher`, `safe_regex_set`,
    /// `safe_regex_set_is_complete`) to their default values. These are populated
    /// during pack registration by `PackEntry::get_pack()`.
    #[must_use]
    pub const fn new(
        id: PackId,
        name: &'static str,
        description: &'static str,
        keywords: &'static [&'static str],
        safe_patterns: Vec<SafePattern>,
        destructive_patterns: Vec<DestructivePattern>,
    ) -> Self {
        Self {
            id,
            name,
            description,
            keywords,
            safe_patterns,
            destructive_patterns,
            keyword_matcher: None,
            safe_regex_set: None,
            safe_regex_set_is_complete: false,
        }
    }

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
            if ac.is_match(cmd) {
                return true;
            }

            if !self
                .keywords
                .iter()
                .any(|kw| keyword_contains_whitespace(kw))
            {
                return false;
            }

            return self
                .keywords
                .iter()
                .any(|kw| keyword_contains_whitespace(kw) && keyword_matches_substring(cmd, kw));
        }

        // Fallback: sequential memchr-based search (O(k * n) where k = keyword count).
        self.keywords
            .iter()
            .any(|kw| keyword_matches_substring(cmd, kw))
    }

    /// Check if a command matches any safe pattern.
    ///
    /// Uses `RegexSet` for O(n) matching when available (fast path).
    /// Falls back to individual pattern checks for backtracking patterns.
    #[must_use]
    pub fn matches_safe(&self, cmd: &str) -> bool {
        // Fast path: use RegexSet if available
        if let Some(ref set) = self.safe_regex_set {
            if set.is_match(cmd) {
                return true;
            }
            // If RegexSet covers all patterns and missed, no match
            if self.safe_regex_set_is_complete {
                return false;
            }
        }

        // Fallback: check patterns individually
        // This handles: no RegexSet, RegexSet compilation failed, or backtracking patterns
        self.safe_patterns.iter().any(|p| p.regex.is_match(cmd))
    }

    /// Check if a command matches any destructive pattern.
    /// Returns the matched pattern's reason, name, severity, and explanation if found.
    #[must_use]
    pub fn matches_destructive(&self, cmd: &str) -> Option<DestructiveMatch> {
        self.destructive_patterns
            .iter()
            .find(|p| p.regex.is_match(cmd))
            .map(|p| DestructiveMatch {
                reason: p.reason,
                name: p.name,
                severity: p.severity,
                explanation: p.explanation,
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
    /// Detailed explanation of why this pattern is dangerous.
    /// More verbose than `reason`, intended for explain/verbose output modes.
    /// Falls back to `reason` when not provided.
    pub explanation: Option<&'static str>,
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

/// Static pack metadata for lazy initialization.
///
/// This allows the registry to access pack IDs and keywords without
/// instantiating the full pack (avoiding pattern vector allocations).
pub struct PackEntry {
    /// Pack ID (e.g., "core.git", "database.postgresql").
    pub id: &'static str,
    /// Keywords for quick-reject filtering.
    pub keywords: &'static [&'static str],
    /// Function to build the full pack (called lazily).
    builder: fn() -> Pack,
    /// Cached pack instance (built on first access).
    instance: OnceLock<Pack>,
}

impl PackEntry {
    /// Create a new pack entry with metadata and lazy builder.
    pub const fn new(
        id: &'static str,
        keywords: &'static [&'static str],
        builder: fn() -> Pack,
    ) -> Self {
        Self {
            id,
            keywords,
            builder,
            instance: OnceLock::new(),
        }
    }

    /// Get or build the pack instance.
    ///
    /// # Panics
    ///
    /// Panics if the pack's keywords are not valid patterns for the Aho-Corasick automaton.
    /// This should be guaranteed by the static pack definitions and tests.
    pub fn get_pack(&self) -> &Pack {
        self.instance.get_or_init(|| {
            let mut pack = (self.builder)();
            // Build Aho-Corasick automaton for keyword matching
            if !pack.keywords.is_empty() && pack.keyword_matcher.is_none() {
                pack.keyword_matcher = Some(
                    aho_corasick::AhoCorasick::new(pack.keywords)
                        .expect("pack keywords should be valid patterns"),
                );
            }
            // Build RegexSet for safe pattern matching (fast path)
            if !pack.safe_patterns.is_empty() && pack.safe_regex_set.is_none() {
                // Collect pattern strings that can use linear-time engine
                let patterns: Vec<&str> = pack
                    .safe_patterns
                    .iter()
                    .filter(|p| !regex_engine::needs_backtracking_engine(p.regex.as_str()))
                    .map(|p| p.regex.as_str())
                    .collect();

                // Track if RegexSet covers all patterns (no backtracking patterns)
                pack.safe_regex_set_is_complete = patterns.len() == pack.safe_patterns.len();

                // Only build RegexSet if we have linear patterns
                if !patterns.is_empty() {
                    pack.safe_regex_set = regex::RegexSet::new(patterns).ok();
                }
            }
            pack
        })
    }

    /// Check if the command might match this pack based on keywords (metadata only).
    ///
    /// This allows quick rejection without instantiating the pack (avoiding regex compilation).
    /// Uses sequential memchr-based search since the Aho-Corasick automaton is only available
    /// on the instantiated pack.
    pub fn might_match(&self, cmd: &str) -> bool {
        if self.keywords.is_empty() {
            return true; // No keywords = always check patterns
        }

        let bytes = cmd.as_bytes();
        if self
            .keywords
            .iter()
            .any(|kw| memmem::find(bytes, kw.as_bytes()).is_some())
        {
            return true;
        }

        self.keywords
            .iter()
            .filter(|kw| keyword_contains_whitespace(kw))
            .any(|kw| keyword_matches_substring(cmd, kw))
    }

    /// Check if the pack has been built yet.
    #[cfg(test)]
    pub fn is_built(&self) -> bool {
        self.instance.get().is_some()
    }
}

/// Registry of all available packs.
pub struct PackRegistry {
    /// All registered pack entries (metadata + lazy instances).
    entries: Vec<&'static PackEntry>,

    /// Pack IDs organized by category for hierarchical enablement.
    categories: HashMap<String, Vec<&'static str>>,

    /// Index for fast pack lookup by ID.
    index: HashMap<&'static str, usize>,
}

/// Precomputed keyword index for a specific enabled pack set.
///
/// Built once per config load and reused for each command evaluation, this
/// allows the evaluator to:
/// - Compute a conservative candidate pack set via a single global substring scan.
/// - Avoid repeated per-pack `might_match()` scans when iterating packs.
///
/// Isomorphism constraint: candidate selection must be a **superset** of the
/// legacy per-pack `PackEntry::might_match()` semantics (raw substring matches).
#[derive(Debug)]
pub struct EnabledKeywordIndex {
    pack_count: usize,
    full_mask: u128,
    always_check_mask: u128,
    keyword_matcher: Option<aho_corasick::AhoCorasick>,
    keyword_pack_masks: Vec<u128>,
    whitespace_keywords: Vec<&'static str>,
    whitespace_pack_masks: Vec<u128>,
}

impl EnabledKeywordIndex {
    #[must_use]
    pub const fn pack_count(&self) -> usize {
        self.pack_count
    }

    #[inline]
    #[must_use]
    pub fn candidate_pack_mask(&self, cmd: &str) -> u128 {
        let mut mask = self.always_check_mask;

        let Some(ac) = &self.keyword_matcher else {
            return mask;
        };

        // Overlapping iteration is required to preserve the legacy substring
        // semantics: if "git" is a keyword and the command contains "gitlab",
        // we must include packs keyed on "git" even if a longer keyword also matches.
        for m in ac.find_overlapping_iter(cmd) {
            mask |= self.keyword_pack_masks[m.pattern().as_usize()];
            if mask == self.full_mask {
                break;
            }
        }

        if !self.whitespace_keywords.is_empty() && mask != self.full_mask {
            for (keyword, pack_mask) in self
                .whitespace_keywords
                .iter()
                .zip(self.whitespace_pack_masks.iter())
            {
                if keyword_matches_substring(cmd, keyword) {
                    mask |= *pack_mask;
                    if mask == self.full_mask {
                        break;
                    }
                }
            }
        }

        mask
    }
}

/// Static pack entries - metadata is available without instantiating packs.
/// Packs are built lazily on first access.
static PACK_ENTRIES: [PackEntry; 82] = [
    PackEntry::new("core.git", &["git"], core::git::create_pack),
    PackEntry::new(
        "core.filesystem",
        &["rm", "/rm"],
        core::filesystem::create_pack,
    ),
    PackEntry::new("storage.s3", &["s3", "s3api"], storage::s3::create_pack),
    PackEntry::new(
        "storage.gcs",
        &["gsutil", "gcloud storage"],
        storage::gcs::create_pack,
    ),
    PackEntry::new("storage.minio", &["mc"], storage::minio::create_pack),
    PackEntry::new(
        "storage.azure_blob",
        &["az storage", "azcopy"],
        storage::azure_blob::create_pack,
    ),
    PackEntry::new("remote.rsync", &["rsync"], remote::rsync::create_pack),
    PackEntry::new(
        "remote.ssh",
        &["ssh", "ssh-keygen", "ssh-add", "ssh-agent", "ssh-keyscan"],
        remote::ssh::create_pack,
    ),
    PackEntry::new("remote.scp", &["scp"], remote::scp::create_pack),
    PackEntry::new(
        "cicd.github_actions",
        &["gh"],
        cicd::github_actions::create_pack,
    ),
    PackEntry::new(
        "cicd.gitlab_ci",
        &["glab", "gitlab-runner"],
        cicd::gitlab_ci::create_pack,
    ),
    PackEntry::new(
        "cicd.jenkins",
        &["jenkins-cli", "jenkins", "doDelete"],
        cicd::jenkins::create_pack,
    ),
    PackEntry::new("cicd.circleci", &["circleci"], cicd::circleci::create_pack),
    PackEntry::new("secrets.vault", &["vault"], secrets::vault::create_pack),
    PackEntry::new(
        "secrets.aws_secrets",
        &["aws", "secretsmanager", "ssm"],
        secrets::aws_secrets::create_pack,
    ),
    PackEntry::new(
        "secrets.onepassword",
        &["op"],
        secrets::onepassword::create_pack,
    ),
    PackEntry::new(
        "secrets.doppler",
        &["doppler"],
        secrets::doppler::create_pack,
    ),
    PackEntry::new("platform.github", &["gh"], platform::github::create_pack),
    PackEntry::new(
        "platform.gitlab",
        &["glab", "gitlab-rails", "gitlab-rake"],
        platform::gitlab::create_pack,
    ),
    PackEntry::new(
        "dns.cloudflare",
        &[
            "wrangler",
            "cloudflare",
            "api.cloudflare.com",
            "dns-records",
        ],
        dns::cloudflare::create_pack,
    ),
    PackEntry::new(
        "dns.route53",
        &["aws", "route53"],
        dns::route53::create_pack,
    ),
    PackEntry::new(
        "dns.generic",
        &["nsupdate", "dig", "host", "nslookup"],
        dns::generic::create_pack,
    ),
    PackEntry::new("email.ses", &["ses", "sesv2"], email::ses::create_pack),
    PackEntry::new(
        "email.sendgrid",
        &["sendgrid", "api.sendgrid.com"],
        email::sendgrid::create_pack,
    ),
    PackEntry::new(
        "email.mailgun",
        &["mailgun", "api.mailgun.net"],
        email::mailgun::create_pack,
    ),
    PackEntry::new(
        "email.postmark",
        &["postmark", "api.postmarkapp.com"],
        email::postmark::create_pack,
    ),
    PackEntry::new(
        "featureflags.flipt",
        &["flipt"],
        featureflags::flipt::create_pack,
    ),
    PackEntry::new(
        "featureflags.launchdarkly",
        &["ldcli", "launchdarkly"],
        featureflags::launchdarkly::create_pack,
    ),
    PackEntry::new(
        "featureflags.split",
        &["split", "api.split.io"],
        featureflags::split::create_pack,
    ),
    PackEntry::new(
        "featureflags.unleash",
        &["unleash"],
        featureflags::unleash::create_pack,
    ),
    PackEntry::new(
        "loadbalancer.haproxy",
        &["haproxy", "socat"],
        loadbalancer::haproxy::create_pack,
    ),
    PackEntry::new(
        "loadbalancer.nginx",
        &["nginx", "/etc/nginx"],
        loadbalancer::nginx::create_pack,
    ),
    PackEntry::new(
        "loadbalancer.traefik",
        &["traefik", "ingressroute"],
        loadbalancer::traefik::create_pack,
    ),
    PackEntry::new(
        "loadbalancer.elb",
        &[
            "elbv2",
            "delete-load-balancer",
            "delete-target-group",
            "deregister-targets",
            "delete-listener",
            "delete-rule",
            "deregister-instances-from-load-balancer",
        ],
        loadbalancer::elb::create_pack,
    ),
    PackEntry::new(
        "monitoring.splunk",
        &["splunk"],
        monitoring::splunk::create_pack,
    ),
    PackEntry::new(
        "monitoring.datadog",
        &["datadog-ci", "datadoghq", "datadog"],
        monitoring::datadog::create_pack,
    ),
    PackEntry::new(
        "monitoring.pagerduty",
        &["pd", "pagerduty", "api.pagerduty.com"],
        monitoring::pagerduty::create_pack,
    ),
    PackEntry::new(
        "monitoring.newrelic",
        &["newrelic", "api.newrelic.com", "graphql"],
        monitoring::newrelic::create_pack,
    ),
    PackEntry::new(
        "monitoring.prometheus",
        &[
            "promtool",
            "grafana-cli",
            "/api/v1/admin/tsdb/delete_series",
            "delete_series",
            "/api/dashboards",
            "/api/datasources",
            "/api/alert-notifications",
            "/etc/prometheus",
            "rules.d",
            "prometheusrule",
            "servicemonitor",
            "podmonitor",
        ],
        monitoring::prometheus::create_pack,
    ),
    PackEntry::new(
        "payment.stripe",
        &["stripe", "api.stripe.com"],
        payment::stripe::create_pack,
    ),
    PackEntry::new(
        "payment.braintree",
        &[
            "braintree",
            "braintreegateway.com",
            "braintree.",
            "gateway.customer.",
            "gateway.merchant_account.",
            "gateway.payment_method.",
            "gateway.subscription.",
        ],
        payment::braintree::create_pack,
    ),
    PackEntry::new(
        "payment.square",
        &["square", "api.squareup.com"],
        payment::square::create_pack,
    ),
    PackEntry::new(
        "messaging.kafka",
        &[
            "kafka-topics",
            "kafka-consumer-groups",
            "kafka-configs",
            "kafka-acls",
            "kafka-delete-records",
            "rpk",
        ],
        messaging::kafka::create_pack,
    ),
    PackEntry::new(
        "messaging.rabbitmq",
        &["rabbitmqadmin", "rabbitmqctl"],
        messaging::rabbitmq::create_pack,
    ),
    PackEntry::new("messaging.nats", &["nats"], messaging::nats::create_pack),
    PackEntry::new(
        "messaging.sqs_sns",
        &["aws", "sqs", "sns"],
        messaging::sqs_sns::create_pack,
    ),
    PackEntry::new(
        "search.elasticsearch",
        &[
            "elasticsearch",
            "9200",
            "_search",
            "_cluster",
            "_cat",
            "_doc",
            "_all",
            "_delete_by_query",
        ],
        search::elasticsearch::create_pack,
    ),
    PackEntry::new(
        "search.opensearch",
        &[
            "opensearch",
            "9200",
            "_search",
            "_cluster",
            "_cat",
            "_doc",
            "_all",
            "_delete_by_query",
        ],
        search::opensearch::create_pack,
    ),
    PackEntry::new(
        "search.algolia",
        &["algolia", "algoliasearch"],
        search::algolia::create_pack,
    ),
    PackEntry::new(
        "search.meilisearch",
        &["meili", "meilisearch", "7700", "/indexes", "/keys"],
        search::meilisearch::create_pack,
    ),
    PackEntry::new("backup.borg", &["borg"], backup::borg::create_pack),
    PackEntry::new("backup.rclone", &["rclone"], backup::rclone::create_pack),
    PackEntry::new("backup.restic", &["restic"], backup::restic::create_pack),
    PackEntry::new("backup.velero", &["velero"], backup::velero::create_pack),
    PackEntry::new(
        "database.postgresql",
        &[
            "psql",
            "dropdb",
            "createdb",
            "pg_dump",
            "pg_restore",
            "DROP",
            "TRUNCATE",
            "DELETE",
        ],
        database::postgresql::create_pack,
    ),
    PackEntry::new(
        "database.mysql",
        &["mysql", "mysqldump", "DROP", "TRUNCATE", "DELETE"],
        database::mysql::create_pack,
    ),
    PackEntry::new(
        "database.mongodb",
        &[
            "mongo",
            "mongosh",
            "mongodump",
            "mongorestore",
            "dropDatabase",
            "dropCollection",
        ],
        database::mongodb::create_pack,
    ),
    PackEntry::new(
        "database.redis",
        &["redis-cli", "FLUSHALL", "FLUSHDB", "DEBUG"],
        database::redis::create_pack,
    ),
    PackEntry::new(
        "database.sqlite",
        &["sqlite3", "DROP", "DELETE", "TRUNCATE"],
        database::sqlite::create_pack,
    ),
    PackEntry::new(
        "containers.docker",
        &["docker"],
        containers::docker::create_pack,
    ),
    PackEntry::new(
        "containers.compose",
        &["docker-compose", "docker compose"],
        containers::compose::create_pack,
    ),
    PackEntry::new(
        "containers.podman",
        &["podman"],
        containers::podman::create_pack,
    ),
    PackEntry::new(
        "kubernetes.kubectl",
        &["kubectl"],
        kubernetes::kubectl::create_pack,
    ),
    PackEntry::new("kubernetes.helm", &["helm"], kubernetes::helm::create_pack),
    PackEntry::new(
        "kubernetes.kustomize",
        &["kustomize"],
        kubernetes::kustomize::create_pack,
    ),
    PackEntry::new("cloud.aws", &["aws"], cloud::aws::create_pack),
    PackEntry::new(
        "cloud.gcp",
        &["gcloud", "gsutil", "bq"],
        cloud::gcp::create_pack,
    ),
    PackEntry::new("cloud.azure", &["az"], cloud::azure::create_pack),
    PackEntry::new(
        "cdn.cloudflare_workers",
        &["wrangler"],
        cdn::cloudflare_workers::create_pack,
    ),
    PackEntry::new("cdn.fastly", &["fastly"], cdn::fastly::create_pack),
    PackEntry::new(
        "cdn.cloudfront",
        &["cloudfront"],
        cdn::cloudfront::create_pack,
    ),
    PackEntry::new(
        "apigateway.aws",
        &["aws", "apigateway", "apigatewayv2"],
        apigateway::aws::create_pack,
    ),
    PackEntry::new(
        "apigateway.kong",
        &["kong", "deck", "8001"],
        apigateway::kong::create_pack,
    ),
    PackEntry::new(
        "apigateway.apigee",
        &["apigee", "apigeecli"],
        apigateway::apigee::create_pack,
    ),
    PackEntry::new(
        "infrastructure.terraform",
        &["terraform", "tofu"],
        infrastructure::terraform::create_pack,
    ),
    PackEntry::new(
        "infrastructure.ansible",
        &["ansible", "ansible-playbook"],
        infrastructure::ansible::create_pack,
    ),
    PackEntry::new(
        "infrastructure.pulumi",
        &["pulumi"],
        infrastructure::pulumi::create_pack,
    ),
    PackEntry::new(
        "system.disk",
        &["dd", "mkfs", "fdisk", "parted", "wipefs"],
        system::disk::create_pack,
    ),
    PackEntry::new(
        "system.permissions",
        &["chmod", "chown", "setfacl"],
        system::permissions::create_pack,
    ),
    PackEntry::new(
        "system.services",
        &["systemctl", "service"],
        system::services::create_pack,
    ),
    PackEntry::new("strict_git", &["git"], strict_git::create_pack),
    PackEntry::new(
        "package_managers",
        &[
            "npm", "yarn", "pnpm", "pip", "cargo", "gem", "composer", "go",
        ],
        package_managers::create_pack,
    ),
];

impl PackRegistry {
    /// Collect all keywords from enabled packs.
    ///
    /// This is a **metadata-only** operation - does not instantiate packs.
    /// Keywords are accessed from static `PackEntry` metadata.
    #[must_use]
    pub fn collect_enabled_keywords(&self, enabled_packs: &HashSet<String>) -> Vec<&'static str> {
        let expanded = self.expand_enabled(enabled_packs);
        let mut keywords = Vec::new();

        for pack_id in &expanded {
            if let Some(&idx) = self.index.get(pack_id.as_str()) {
                keywords.extend(self.entries[idx].keywords.iter().copied());
            }
        }

        // Deduplicate while preserving order (first occurrence wins)
        let mut seen = HashSet::new();
        keywords.retain(|kw| seen.insert(*kw));

        keywords
    }

    /// Create a new registry with all built-in packs.
    ///
    /// This is a **metadata-only** operation. Packs are not instantiated
    /// until they are accessed via `get()`.
    #[must_use]
    pub fn new() -> Self {
        let mut categories: HashMap<String, Vec<&'static str>> = HashMap::new();
        let mut index: HashMap<&'static str, usize> = HashMap::new();

        // Build categories and index from static entries
        for (i, entry) in PACK_ENTRIES.iter().enumerate() {
            // Extract category from ID (e.g., "database" from "database.postgresql")
            let category = entry.id.split('.').next().unwrap_or(entry.id);
            categories
                .entry(category.to_string())
                .or_default()
                .push(entry.id);
            index.insert(entry.id, i);
        }

        Self {
            entries: PACK_ENTRIES.iter().collect(),
            categories,
            index,
        }
    }

    /// Get the number of registered packs.
    #[must_use]
    pub fn pack_count(&self) -> usize {
        self.entries.len()
    }

    /// Get a pack by ID.
    ///
    /// This instantiates the pack lazily on first access.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Pack> {
        self.index.get(id).map(|&idx| self.entries[idx].get_pack())
    }

    /// Get all pack IDs.
    ///
    /// This is a **metadata-only** operation - does not instantiate packs.
    #[must_use]
    pub fn all_pack_ids(&self) -> Vec<&'static str> {
        self.entries.iter().map(|e| e.id).collect()
    }

    /// Get all categories.
    #[must_use]
    pub fn all_categories(&self) -> Vec<&String> {
        self.categories.keys().collect()
    }

    /// Get pack IDs in a category.
    ///
    /// This is a **metadata-only** operation - does not instantiate packs.
    #[must_use]
    pub fn packs_in_category(&self, category: &str) -> Vec<&'static str> {
        self.categories.get(category).cloned().unwrap_or_default()
    }

    /// Expand enabled pack IDs to include sub-packs when a category is enabled.
    ///
    /// This is a **metadata-only** operation - does not instantiate packs.
    #[must_use]
    pub fn expand_enabled(&self, enabled: &HashSet<String>) -> HashSet<String> {
        let mut expanded = HashSet::new();

        for id in enabled {
            // Check if this is a category
            if let Some(sub_packs) = self.categories.get(id) {
                // Add all sub-packs in the category
                for &sub_pack in sub_packs {
                    expanded.insert(sub_pack.to_string());
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
    /// 1. **Tier 1 (core/storage/remote)**: `core.*`, `storage.*`, `remote.*` packs - most fundamental protections
    /// 2. **Tier 2 (system)**: `system.*` - disk, permissions, services
    /// 3. **Tier 3 (infrastructure)**: `infrastructure.*` - terraform, ansible, pulumi
    /// 4. **Tier 4 (apigateway/cloud/dns/platform/cdn/loadbalancer)**: `apigateway.*`, `cloud.*`, `dns.*`, `platform.*`, `cdn.*`, `loadbalancer.*`
    /// 5. **Tier 5 (kubernetes)**: `kubernetes.*` - kubectl, helm, kustomize
    /// 6. **Tier 6 (containers)**: `containers.*` - docker, compose, podman
    /// 7. **Tier 7 (database/search/messaging/backup)**: `database.*`, `search.*`, `messaging.*`, `backup.*`
    /// 8. **Tier 8 (`package_managers`)**: package manager protections
    /// 9. **Tier 9 (`strict_git`)**: extra git paranoia
    /// 10. **Tier 10 (services)**: `cicd.*`, `email.*`, `featureflags.*`, `secrets.*`, `monitoring.*`, `payment.*`
    ///
    /// Within each tier, packs are sorted lexicographically by ID.
    #[must_use]
    pub fn expand_enabled_ordered(&self, enabled: &HashSet<String>) -> Vec<String> {
        let expanded = self.expand_enabled(enabled);

        // Filter to only include pack IDs that actually exist in registry
        let mut pack_ids: Vec<String> = expanded
            .into_iter()
            .filter(|id| self.index.contains_key(id.as_str()))
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
            "core" | "storage" | "remote" => 1,
            "system" => 2,
            "infrastructure" => 3,
            "apigateway" | "cdn" | "cloud" | "dns" | "loadbalancer" | "platform" => 4,
            "kubernetes" => 5,
            "containers" => 6,
            "backup" | "database" | "messaging" | "search" => 7,
            "package_managers" => 8,
            "strict_git" => 9,
            "cicd" | "email" | "featureflags" | "secrets" | "monitoring" | "payment" => 10, // CI/CD + email + feature flags + secrets + monitoring + payment tooling
            _ => 11, // Unknown categories go last
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
    ///    This enables "safe" packs (like `safe.cleanup`) to whitelist commands
    ///    that would otherwise be blocked by other packs.
    /// 2. **Destructive patterns pass**: Check destructive patterns across all packs.
    ///    The first matching destructive pattern determines the result.
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

        // Pre-compute candidate packs (might_match cache).
        // This avoids calling might_match twice per pack (once per pass).
        let candidate_packs: Vec<(&String, &Pack)> = ordered_packs
            .iter()
            .filter_map(|pack_id| {
                let pack = self.get(pack_id)?;
                if pack.might_match(cmd) {
                    Some((pack_id, pack))
                } else {
                    None
                }
            })
            .collect();

        // Pass 1: Check safe patterns across ALL candidate packs first.
        // If any pack's safe pattern matches, allow the command immediately.
        // This enables "safe" packs (like `safe.cleanup`) to whitelist commands across pack boundaries.
        for (_pack_id, pack) in &candidate_packs {
            if pack.matches_safe(cmd) {
                return CheckResult::allowed();
            }
        }

        // Pass 2: Check destructive patterns across all candidate packs.
        // The first matching destructive pattern determines the result.
        for (pack_id, pack) in &candidate_packs {
            if let Some(matched) = pack.matches_destructive(cmd) {
                return CheckResult::matched(
                    matched.reason,
                    pack_id,
                    matched.name,
                    matched.severity,
                );
            }
        }

        CheckResult::allowed()
    }

    /// List all packs with their status.
    ///
    /// Note: This instantiates packs to get pattern counts. For metadata-only
    /// listing (e.g., just IDs and enabled status), use `all_pack_ids()` instead.
    #[must_use]
    pub fn list_packs(&self, enabled: &HashSet<String>) -> Vec<PackInfo> {
        let expanded = self.expand_enabled(enabled);

        let mut infos: Vec<_> = self
            .entries
            .iter()
            .map(|entry| {
                let pack = entry.get_pack();
                PackInfo {
                    id: pack.id.clone(),
                    name: pack.name,
                    description: pack.description,
                    enabled: expanded.contains(&pack.id),
                    safe_pattern_count: pack.safe_patterns.len(),
                    destructive_pattern_count: pack.destructive_patterns.len(),
                }
            })
            .collect();

        // Sort by ID for consistent output
        infos.sort_by(|a, b| a.id.cmp(&b.id));
        infos
    }

    /// Get a pack entry by ID (metadata only, no pack instantiation).
    #[must_use]
    pub fn get_entry(&self, id: &str) -> Option<&PackEntry> {
        self.index.get(id).map(|&idx| self.entries[idx])
    }

    /// Build an [`EnabledKeywordIndex`] for a precomputed ordered pack list.
    ///
    /// This is intended to run once per config load; callers reuse the returned
    /// index for each command evaluation.
    ///
    /// Returns `None` if the ordered pack list exceeds the fixed bitset budget
    /// (currently 128 packs), in which case callers should fall back to the
    /// legacy per-pack `might_match()` filtering.
    #[must_use]
    pub fn build_enabled_keyword_index(
        &self,
        ordered_packs: &[String],
    ) -> Option<EnabledKeywordIndex> {
        if ordered_packs.len() > 128 {
            return None;
        }

        let pack_count = ordered_packs.len();
        let full_mask = if pack_count == 128 {
            u128::MAX
        } else {
            (1u128 << pack_count) - 1
        };

        let mut always_check_mask: u128 = 0;
        let mut keyword_to_index: HashMap<&'static str, usize> = HashMap::new();
        let mut patterns: Vec<&'static str> = Vec::new();
        let mut keyword_pack_masks: Vec<u128> = Vec::new();
        let mut whitespace_keywords: Vec<&'static str> = Vec::new();
        let mut whitespace_pack_masks: Vec<u128> = Vec::new();
        let mut whitespace_keyword_to_index: HashMap<&'static str, usize> = HashMap::new();

        for (pack_idx, pack_id) in ordered_packs.iter().enumerate() {
            let Some(entry) = self.get_entry(pack_id.as_str()) else {
                continue;
            };

            let bit = 1u128 << pack_idx;

            if entry.keywords.is_empty() {
                always_check_mask |= bit;
                continue;
            }

            for &kw in entry.keywords {
                if kw.is_empty() {
                    continue;
                }

                if keyword_contains_whitespace(kw) {
                    if let Some(&idx) = whitespace_keyword_to_index.get(kw) {
                        whitespace_pack_masks[idx] |= bit;
                    } else {
                        let idx = whitespace_keywords.len();
                        whitespace_keywords.push(kw);
                        whitespace_pack_masks.push(bit);
                        whitespace_keyword_to_index.insert(kw, idx);
                    }
                }

                if let Some(&idx) = keyword_to_index.get(kw) {
                    keyword_pack_masks[idx] |= bit;
                    continue;
                }

                let idx = patterns.len();
                patterns.push(kw);
                keyword_to_index.insert(kw, idx);
                keyword_pack_masks.push(bit);
            }
        }

        let keyword_matcher = if patterns.is_empty() {
            None
        } else {
            match aho_corasick::AhoCorasick::new(patterns) {
                Ok(ac) => Some(ac),
                Err(_) => return None,
            }
        };

        Some(EnabledKeywordIndex {
            pack_count,
            full_mask,
            always_check_mask,
            keyword_matcher,
            keyword_pack_masks,
            whitespace_keywords,
            whitespace_pack_masks,
        })
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

/// Pre-compiled finders for core quick rejection (git/rm).
#[allow(dead_code)]
static GIT_FINDER: LazyLock<memmem::Finder<'static>> = LazyLock::new(|| memmem::Finder::new("git"));
#[allow(dead_code)]
static RM_FINDER: LazyLock<memmem::Finder<'static>> = LazyLock::new(|| memmem::Finder::new("rm"));

#[inline]
const fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[inline]
fn keyword_contains_whitespace(keyword: &str) -> bool {
    keyword.bytes().any(|byte| byte.is_ascii_whitespace())
}

#[inline]
fn keyword_matches_substring(haystack: &str, keyword: &str) -> bool {
    if keyword.is_empty() {
        return false;
    }

    if !keyword_contains_whitespace(keyword) {
        return memmem::find(haystack.as_bytes(), keyword.as_bytes()).is_some();
    }

    keyword_matches_with_whitespace(haystack, keyword, false)
}

fn split_keyword_parts(keyword: &str) -> SmallVec<[&str; 4]> {
    let mut parts: SmallVec<[&str; 4]> = SmallVec::new();
    let mut start: Option<usize> = None;

    for (idx, byte) in keyword.bytes().enumerate() {
        if byte.is_ascii_whitespace() {
            if let Some(part_start) = start.take() {
                parts.push(&keyword[part_start..idx]);
            }
        } else if start.is_none() {
            start = Some(idx);
        }
    }

    if let Some(part_start) = start {
        parts.push(&keyword[part_start..]);
    }

    parts
}

fn keyword_matches_with_whitespace(
    haystack: &str,
    keyword: &str,
    enforce_boundaries: bool,
) -> bool {
    let parts = split_keyword_parts(keyword);
    if parts.is_empty() {
        return false;
    }

    let hay = haystack.as_bytes();
    let first = parts[0].as_bytes();
    if first.len() > hay.len() {
        return false;
    }

    let first_is_word = first.first().is_some_and(|b| is_word_byte(*b));
    let last = parts[parts.len() - 1].as_bytes();
    let last_is_word = last.last().is_some_and(|b| is_word_byte(*b));
    let mut offset = 0;

    while let Some(pos) = memmem::find(&hay[offset..], first) {
        let start = offset + pos;
        if enforce_boundaries && first_is_word {
            let start_ok = start == 0 || !is_word_byte(hay[start.saturating_sub(1)]);
            if !start_ok {
                offset = start + 1;
                continue;
            }
        }

        let mut idx = start + first.len();
        let mut matched = true;
        for part in parts.iter().skip(1) {
            let mut ws = idx;
            while ws < hay.len() && hay[ws].is_ascii_whitespace() {
                ws += 1;
            }
            if ws == idx {
                matched = false;
                break;
            }
            idx = ws;

            let part_bytes = part.as_bytes();
            if idx + part_bytes.len() > hay.len() || &hay[idx..idx + part_bytes.len()] != part_bytes
            {
                matched = false;
                break;
            }
            idx += part_bytes.len();
        }

        if matched && enforce_boundaries && last_is_word {
            let end_ok = idx == hay.len() || !is_word_byte(hay[idx]);
            if !end_ok {
                matched = false;
            }
        }

        if matched {
            return true;
        }

        offset = start + 1;
    }

    false
}

#[inline]
fn keyword_matches_span(span_text: &str, keyword: &str) -> bool {
    if keyword.is_empty() {
        return false;
    }

    if keyword_contains_whitespace(keyword) {
        return keyword_matches_with_whitespace(span_text, keyword, true);
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
    pack_aware_quick_reject_with_normalized(cmd, enabled_keywords).0
}

/// Result of quick-reject check with the normalized command for reuse.
///
/// Returns `(should_reject, normalized_command)` where:
/// - `should_reject = true` means no keywords found, safe to skip pack evaluation
/// - `should_reject = false` means keywords found, must check packs
/// - `normalized_command` is the normalized form (can be reused for pack evaluation)
///
/// When `should_reject = true` and the fast substring check failed (no keywords at all),
/// returns `Cow::Borrowed(cmd)` since normalization was never computed.
#[inline]
#[must_use]
pub fn pack_aware_quick_reject_with_normalized<'a>(
    cmd: &'a str,
    enabled_keywords: &[&str],
) -> (bool, std::borrow::Cow<'a, str>) {
    // Conservative: if the caller provides no keywords, we cannot safely conclude
    // that pack evaluation can be skipped (a pack may have empty/incorrect keywords).
    // Returning false forces evaluation rather than silently allowing everything.
    if enabled_keywords.is_empty() {
        return (false, normalize_command(cmd));
    }

    let bytes = cmd.as_bytes();
    let mut any_substring = enabled_keywords
        .iter()
        .any(|keyword| memmem::find(bytes, keyword.as_bytes()).is_some());
    if !any_substring {
        any_substring = enabled_keywords
            .iter()
            .filter(|keyword| keyword_contains_whitespace(keyword))
            .any(|keyword| keyword_matches_substring(cmd, keyword));
    }
    if !any_substring {
        // Before returning early, check if the command contains potential obfuscation
        // characters that could hide keywords (backslash escapes, quotes).
        // Examples: g\it -> git, g'i't -> git
        // If so, we must normalize before deciding to skip.
        let has_obfuscation = bytes.iter().any(|b| matches!(b, b'\\' | b'\'' | b'"'));
        if !has_obfuscation {
            // No substring match and no obfuscation - safe to return early.
            // The caller won't need the normalized form since we're rejecting.
            return (true, std::borrow::Cow::Borrowed(cmd));
        }
        // Has potential obfuscation - fall through to normalize and re-check
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
            return (false, normalized);
        }
    }

    if !saw_executable {
        return (true, normalized);
    }

    (true, normalized) // No keywords found in executable spans, safe to skip pack checking
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

        // All rm commands should NOT be quick-rejected
        assert!(
            !pack_aware_quick_reject("rm -rf build", &keywords),
            "rm -rf build should NOT be quick-rejected"
        );
        assert!(
            !pack_aware_quick_reject("rm -rf /tmp/foo", &keywords),
            "rm -rf /tmp/foo should NOT be quick-rejected"
        );
        assert!(
            !pack_aware_quick_reject(r#"rm -rf "$TMPDIR/foo""#, &keywords),
            "rm -rf \"$TMPDIR/foo\" should NOT be quick-rejected"
        );
        assert!(
            !pack_aware_quick_reject(r#"rm -r -f "$TMPDIR/foo""#, &keywords),
            "rm -r -f \"$TMPDIR/foo\" should NOT be quick-rejected"
        );
        assert!(
            !pack_aware_quick_reject(r#"rm --recursive --force "$TMPDIR/foo""#, &keywords),
            "rm --recursive --force \"$TMPDIR/foo\" should NOT be quick-rejected"
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
        assert!(
            !pack_aware_quick_reject("rm -rf dist", &keywords),
            "rm -rf dist should NOT be quick-rejected with core keywords"
        );
        assert!(
            !pack_aware_quick_reject("rm -rf node_modules", &keywords),
            "rm -rf node_modules should NOT be quick-rejected with core keywords"
        );
        assert!(
            !pack_aware_quick_reject("rm -rf foo", &keywords),
            "rm -rf foo should NOT be quick-rejected with core keywords"
        );
    }

    #[test]
    fn pack_aware_quick_reject_handles_multiword_keywords_with_extra_space() {
        let keywords: Vec<&str> = vec!["gcloud storage"];

        assert!(
            !pack_aware_quick_reject("gcloud   storage rm gs://bucket", &keywords),
            "multi-word keywords should match even with extra whitespace"
        );
    }

    #[test]
    fn enabled_keyword_index_matches_multiword_keyword_with_extra_space() {
        let mut enabled = HashSet::new();
        enabled.insert("storage.gcs".to_string());

        let ordered = REGISTRY.expand_enabled_ordered(&enabled);
        let index = REGISTRY
            .build_enabled_keyword_index(&ordered)
            .expect("keyword index should build for small pack set");

        let mask = index.candidate_pack_mask("gcloud   storage rm gs://bucket");
        let pack_idx = ordered
            .iter()
            .position(|id| id == "storage.gcs")
            .expect("storage.gcs should be present in ordered list");

        assert_eq!(
            (mask >> pack_idx) & 1,
            1,
            "candidate mask should include storage.gcs when whitespace varies"
        );
    }

    /// Test that `pack_tier` returns correct tiers for all known categories.
    #[test]
    fn pack_tier_ordering() {
        // Core should be highest priority (tier 1)
        assert_eq!(PackRegistry::pack_tier("core.git"), 1);
        assert_eq!(PackRegistry::pack_tier("core.filesystem"), 1);
        assert_eq!(PackRegistry::pack_tier("storage.s3"), 1);
        assert_eq!(PackRegistry::pack_tier("remote.rsync"), 1);

        // System should be tier 2
        assert_eq!(PackRegistry::pack_tier("system.disk"), 2);
        assert_eq!(PackRegistry::pack_tier("system.permissions"), 2);

        // Infrastructure should be tier 3
        assert_eq!(PackRegistry::pack_tier("infrastructure.terraform"), 3);

        // Tier 4 packs should be tier 4
        assert_eq!(PackRegistry::pack_tier("cloud.aws"), 4);
        assert_eq!(PackRegistry::pack_tier("apigateway.aws"), 4);
        assert_eq!(PackRegistry::pack_tier("dns.cloudflare"), 4);
        assert_eq!(PackRegistry::pack_tier("dns.route53"), 4);
        assert_eq!(PackRegistry::pack_tier("dns.generic"), 4);
        assert_eq!(PackRegistry::pack_tier("platform.github"), 4);
        assert_eq!(PackRegistry::pack_tier("cdn.cloudflare_workers"), 4);
        assert_eq!(PackRegistry::pack_tier("loadbalancer.nginx"), 4);

        // Kubernetes should be tier 5
        assert_eq!(PackRegistry::pack_tier("kubernetes.kubectl"), 5);

        // Containers should be tier 6
        assert_eq!(PackRegistry::pack_tier("containers.docker"), 6);

        // Database should be tier 7
        assert_eq!(PackRegistry::pack_tier("database.postgresql"), 7);
        assert_eq!(PackRegistry::pack_tier("backup.borg"), 7);
        assert_eq!(PackRegistry::pack_tier("backup.rclone"), 7);
        assert_eq!(PackRegistry::pack_tier("backup.restic"), 7);
        assert_eq!(PackRegistry::pack_tier("backup.velero"), 7);
        assert_eq!(PackRegistry::pack_tier("messaging.kafka"), 7);
        assert_eq!(PackRegistry::pack_tier("search.elasticsearch"), 7);

        // Package managers should be tier 8
        assert_eq!(PackRegistry::pack_tier("package_managers"), 8);

        // Strict git should be tier 9
        assert_eq!(PackRegistry::pack_tier("strict_git"), 9);

        // Tier 10 service packs should be tier 10
        assert_eq!(PackRegistry::pack_tier("cicd.github_actions"), 10);
        assert_eq!(PackRegistry::pack_tier("cicd.gitlab_ci"), 10);
        assert_eq!(PackRegistry::pack_tier("cicd.jenkins"), 10);
        assert_eq!(PackRegistry::pack_tier("cicd.circleci"), 10);
        assert_eq!(PackRegistry::pack_tier("email.ses"), 10);
        assert_eq!(PackRegistry::pack_tier("featureflags.launchdarkly"), 10);
        assert_eq!(PackRegistry::pack_tier("secrets.vault"), 10);
        assert_eq!(PackRegistry::pack_tier("monitoring.splunk"), 10);
        assert_eq!(PackRegistry::pack_tier("payment.stripe"), 10);

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
        enabled.insert("kubernetes.kubectl".to_string()); // tier 5
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

    /// Test that `DestructiveMatch` includes severity.
    #[test]
    fn destructive_match_includes_severity() {
        let docker_pack = REGISTRY
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
                .find(|p| p.name == Some(rule_name));
            assert!(
                pattern.is_some(),
                "Rule {rule_name} should exist in core.git"
            );
            let pattern = pattern.unwrap();

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
                .find(|p| p.name == Some(rule_name));
            assert!(
                pattern.is_some(),
                "Rule {rule_name} should exist in core.git"
            );
            let pattern = pattern.unwrap();

            assert!(
                pattern.severity.blocks_by_default(),
                "Rule {rule_name} in core.git should block by default (High or Critical)"
            );
        }
    }

    /// Verify core pack severity assignments are correct.
    ///
    /// Most core rules should block by default (Critical/High), but some recoverable
    /// operations are Medium severity (warn by default). This test documents the
    /// expected severity distribution.
    #[test]
    fn core_rules_have_appropriate_severity() {
        // Patterns that should be Medium (recoverable operations)
        let medium_patterns = [
            ("core.git", "branch-force-delete"), // Recoverable via reflog
            ("core.git", "stash-drop"),          // Recoverable via fsck
        ];

        for pack_id in ["core.git", "core.filesystem"] {
            let pack = REGISTRY.get(pack_id).expect("Pack should exist");

            for pattern in &pack.destructive_patterns {
                let name = pattern.name.unwrap_or("<unnamed>");
                let is_expected_medium = medium_patterns
                    .iter()
                    .any(|(pid, pname)| *pid == pack_id && *pname == name);

                if is_expected_medium {
                    assert!(
                        matches!(pattern.severity, Severity::Medium),
                        "Core pack rule {pack_id}:{name} should be Medium severity (recoverable)"
                    );
                } else {
                    assert!(
                        pattern.severity.blocks_by_default(),
                        "Core pack rule {pack_id}:{name} should block by default"
                    );
                }
            }
        }
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
                "rm -rf /etc"
            );
        }

        #[test]
        fn preserves_quotes_for_safe_commands() {
            // Safe commands like echo should preserve argument quotes to avoid false positives
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

        #[test]
        fn handles_line_continuation_split() {
            // "re\\\nset" -> "reset"
            assert_eq!(
                normalize_command("git re\\\nset --hard"),
                "git reset --hard"
            );
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
                if let Err(e) =
                    crate::packs::regex_engine::CompiledRegex::new(pattern.regex.as_str())
                {
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
                if let Err(e) =
                    crate::packs::regex_engine::CompiledRegex::new(pattern.regex.as_str())
                {
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

        assert!(
            errors.is_empty(),
            "Found {} invalid regex pattern(s):\n\n{}",
            errors.len(),
            errors.join("\n\n")
        );
    }
}
