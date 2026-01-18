//! External pack loading from YAML files.
//!
//! This module provides functionality to load custom pack definitions from YAML files,
//! enabling users to create their own pattern packs without modifying the dcg binary.
//!
//! # Schema
//!
//! External packs follow the schema defined in `docs/pack.schema.yaml`. See that file
//! for the full specification.
//!
//! # Example Pack File
//!
//! ```yaml
//! schema_version: 1
//! id: mycompany.deploy
//! name: MyCompany Deployment Policies
//! version: 1.0.0
//! description: Prevents accidental production deployments
//!
//! keywords:
//!   - deploy
//!   - release
//!
//! destructive_patterns:
//!   - name: prod-direct
//!     pattern: deploy\s+--env\s*=?\s*prod
//!     severity: critical
//!     description: Direct production deployment
//!     explanation: |
//!       Production deployments must go through the release pipeline.
//!
//! safe_patterns:
//!   - name: staging-deploy
//!     pattern: deploy\s+--env\s*=?\s*(staging|dev)
//!     description: Non-production deployments are allowed
//! ```

use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use super::regex_engine::LazyCompiledRegex;
use super::{DestructivePattern, Pack, REGISTRY, SafePattern, Severity};

/// Current schema version for external pack files.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// ID format regex pattern.
const ID_PATTERN: &str = r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$";

/// Version format regex pattern (semantic versioning).
const VERSION_PATTERN: &str = r"^\d+\.\d+\.\d+$";

/// An external pack definition loaded from YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct ExternalPack {
    /// Schema version for forward compatibility.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,

    /// Unique pack identifier (e.g., "mycompany.policies").
    /// Must match pattern: `^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`
    pub id: String,

    /// Human-readable pack name.
    pub name: String,

    /// Semantic version of the pack definition (e.g., "1.0.0").
    pub version: String,

    /// Description of what this pack protects against.
    #[serde(default)]
    pub description: Option<String>,

    /// Keywords that trigger evaluation for this pack.
    /// Commands without any of these keywords skip pattern matching.
    #[serde(default)]
    pub keywords: Vec<String>,

    /// Destructive patterns that block or warn based on severity.
    #[serde(default)]
    pub destructive_patterns: Vec<ExternalDestructivePattern>,

    /// Safe patterns that explicitly allow commands.
    #[serde(default)]
    pub safe_patterns: Vec<ExternalSafePattern>,
}

/// Default schema version for packs that don't specify one.
const fn default_schema_version() -> u32 {
    1
}

/// A destructive pattern from an external pack file.
#[derive(Debug, Clone, Deserialize)]
pub struct ExternalDestructivePattern {
    /// Stable pattern identifier within the pack.
    pub name: String,

    /// The regex pattern to match (fancy-regex syntax).
    pub pattern: String,

    /// Severity level (determines default decision mode).
    #[serde(default)]
    pub severity: ExternalSeverity,

    /// Short human-readable reason shown on denial.
    #[serde(default)]
    pub description: Option<String>,

    /// Longer explanation shown in verbose output.
    #[serde(default)]
    pub explanation: Option<String>,
}

/// A safe pattern from an external pack file.
#[derive(Debug, Clone, Deserialize)]
pub struct ExternalSafePattern {
    /// Stable pattern identifier within the pack.
    pub name: String,

    /// The regex pattern to match (fancy-regex syntax).
    pub pattern: String,

    /// Short reason for allowlisting (for documentation).
    #[serde(default)]
    pub description: Option<String>,
}

/// Severity level as specified in external pack files.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExternalSeverity {
    Low,
    Medium,
    #[default]
    High,
    Critical,
}

impl From<ExternalSeverity> for Severity {
    fn from(severity: ExternalSeverity) -> Self {
        match severity {
            ExternalSeverity::Low => Self::Low,
            ExternalSeverity::Medium => Self::Medium,
            ExternalSeverity::High => Self::High,
            ExternalSeverity::Critical => Self::Critical,
        }
    }
}

/// Errors that can occur when parsing a pack file.
#[derive(Debug)]
pub enum PackParseError {
    /// IO error reading the file.
    Io(io::Error),

    /// YAML parsing error.
    Yaml(serde_yaml::Error),

    /// Invalid pack ID format.
    InvalidId { id: String, reason: String },

    /// Invalid version format.
    InvalidVersion { version: String, reason: String },

    /// Schema version not supported.
    UnsupportedSchemaVersion { found: u32, max_supported: u32 },

    /// Invalid regex pattern.
    InvalidPattern {
        name: String,
        pattern: String,
        error: String,
    },

    /// Duplicate pattern name within a pack.
    DuplicatePattern { name: String },

    /// Empty pack (no patterns defined).
    EmptyPack,

    /// Pack ID collides with a built-in pack.
    ///
    /// External packs cannot override built-in security packs to prevent
    /// accidental or malicious security bypasses.
    IdCollision { id: String, builtin_name: String },
}

impl fmt::Display for PackParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {e}"),
            Self::Yaml(e) => write!(f, "YAML parse error: {e}"),
            Self::InvalidId { id, reason } => {
                write!(f, "Invalid pack ID '{id}': {reason}")
            }
            Self::InvalidVersion { version, reason } => {
                write!(f, "Invalid version '{version}': {reason}")
            }
            Self::UnsupportedSchemaVersion {
                found,
                max_supported,
            } => {
                write!(
                    f,
                    "Schema version {found} is not supported (max: {max_supported})"
                )
            }
            Self::InvalidPattern {
                name,
                pattern,
                error,
            } => {
                write!(f, "Invalid pattern '{name}' ({pattern}): {error}")
            }
            Self::DuplicatePattern { name } => {
                write!(f, "Duplicate pattern name: {name}")
            }
            Self::EmptyPack => write!(f, "Pack has no patterns defined"),
            Self::IdCollision { id, builtin_name } => {
                write!(
                    f,
                    "Pack ID '{id}' collides with built-in pack '{builtin_name}'. \
                     External packs cannot override built-in security packs."
                )
            }
        }
    }
}

impl std::error::Error for PackParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Yaml(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for PackParseError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_yaml::Error> for PackParseError {
    fn from(e: serde_yaml::Error) -> Self {
        Self::Yaml(e)
    }
}

/// Parse an external pack from a YAML file.
///
/// This function reads the file, parses the YAML, and validates the pack structure.
///
/// # Errors
///
/// Returns `PackParseError` if:
/// - The file cannot be read
/// - The YAML is malformed
/// - The pack fails validation (invalid ID, version, patterns, etc.)
pub fn parse_pack_file(path: &Path) -> Result<ExternalPack, PackParseError> {
    let content = std::fs::read_to_string(path)?;
    parse_pack_string(&content)
}

/// Parse an external pack from a YAML string.
///
/// This function parses the YAML and validates the pack structure.
///
/// # Errors
///
/// Returns `PackParseError` if the YAML is malformed or the pack fails validation.
pub fn parse_pack_string(content: &str) -> Result<ExternalPack, PackParseError> {
    let pack: ExternalPack = serde_yaml::from_str(content)?;
    validate_pack(&pack)?;
    Ok(pack)
}

/// Validate an external pack structure.
///
/// Checks:
/// - Schema version is supported
/// - ID matches the required format
/// - Version matches semantic versioning format
/// - All pattern regex compiles successfully
/// - No duplicate pattern names
/// - At least one pattern is defined
fn validate_pack(pack: &ExternalPack) -> Result<(), PackParseError> {
    // Check schema version
    if pack.schema_version > CURRENT_SCHEMA_VERSION {
        return Err(PackParseError::UnsupportedSchemaVersion {
            found: pack.schema_version,
            max_supported: CURRENT_SCHEMA_VERSION,
        });
    }

    // Validate ID format
    let id_regex = regex::Regex::new(ID_PATTERN).expect("ID regex should compile");
    if !id_regex.is_match(&pack.id) {
        return Err(PackParseError::InvalidId {
            id: pack.id.clone(),
            reason: format!("Must match pattern: {ID_PATTERN}"),
        });
    }

    // Validate version format
    let version_regex = regex::Regex::new(VERSION_PATTERN).expect("Version regex should compile");
    if !version_regex.is_match(&pack.version) {
        return Err(PackParseError::InvalidVersion {
            version: pack.version.clone(),
            reason: format!("Must match pattern: {VERSION_PATTERN}"),
        });
    }

    // Check for empty pack
    if pack.destructive_patterns.is_empty() && pack.safe_patterns.is_empty() {
        return Err(PackParseError::EmptyPack);
    }

    // Collect all pattern names for duplicate checking
    let mut seen_names = std::collections::HashSet::new();

    // Validate destructive patterns
    for pattern in &pack.destructive_patterns {
        // Check for duplicate names
        if !seen_names.insert(&pattern.name) {
            return Err(PackParseError::DuplicatePattern {
                name: pattern.name.clone(),
            });
        }

        // Validate regex compiles
        if let Err(e) = fancy_regex::Regex::new(&pattern.pattern) {
            return Err(PackParseError::InvalidPattern {
                name: pattern.name.clone(),
                pattern: pattern.pattern.clone(),
                error: e.to_string(),
            });
        }
    }

    // Validate safe patterns
    for pattern in &pack.safe_patterns {
        // Check for duplicate names
        if !seen_names.insert(&pattern.name) {
            return Err(PackParseError::DuplicatePattern {
                name: pattern.name.clone(),
            });
        }

        // Validate regex compiles
        if let Err(e) = fancy_regex::Regex::new(&pattern.pattern) {
            return Err(PackParseError::InvalidPattern {
                name: pattern.name.clone(),
                pattern: pattern.pattern.clone(),
                error: e.to_string(),
            });
        }
    }

    Ok(())
}

/// Check if a pack ID collides with a built-in pack.
///
/// Returns `Some(builtin_name)` if the ID collides with a built-in pack,
/// `None` otherwise.
///
/// # Collision Rules
///
/// External pack IDs are checked against all built-in pack IDs. A collision
/// occurs when the external pack ID exactly matches a built-in pack ID.
///
/// Note: Category-level IDs (e.g., just "database") are already rejected by
/// the ID format validation, which requires the `namespace.name` format.
///
/// This prevents accidental or malicious security bypasses by ensuring
/// custom packs cannot override built-in protection patterns.
#[must_use]
pub fn check_builtin_collision(pack_id: &str) -> Option<&'static str> {
    // Check exact ID collision with a built-in pack
    REGISTRY.get(pack_id).map(|pack| pack.name)
}

/// Validate an external pack with collision checking against built-in packs.
///
/// This performs all standard validation plus checks that the pack ID
/// does not collide with any built-in pack.
///
/// # Errors
///
/// Returns `PackParseError::IdCollision` if the pack ID matches a built-in pack.
/// Also returns other `PackParseError` variants for other validation failures.
pub fn validate_pack_with_collision_check(pack: &ExternalPack) -> Result<(), PackParseError> {
    // First do standard validation
    validate_pack(pack)?;

    // Then check for collision with built-in packs
    if let Some(builtin_name) = check_builtin_collision(&pack.id) {
        return Err(PackParseError::IdCollision {
            id: pack.id.clone(),
            builtin_name: builtin_name.to_string(),
        });
    }

    Ok(())
}

/// Parse an external pack with collision checking.
///
/// This is the recommended function for loading external packs in production,
/// as it ensures the pack does not override built-in security packs.
///
/// # Errors
///
/// Returns `PackParseError` if:
/// - The file cannot be read
/// - The YAML is malformed
/// - The pack fails validation
/// - The pack ID collides with a built-in pack
pub fn parse_pack_file_checked(path: &Path) -> Result<ExternalPack, PackParseError> {
    let content = std::fs::read_to_string(path)?;
    parse_pack_string_checked(&content)
}

/// Parse an external pack from a YAML string with collision checking.
///
/// # Errors
///
/// Returns `PackParseError` if the YAML is malformed, validation fails,
/// or the pack ID collides with a built-in pack.
pub fn parse_pack_string_checked(content: &str) -> Result<ExternalPack, PackParseError> {
    let pack: ExternalPack = serde_yaml::from_str(content)?;
    validate_pack_with_collision_check(&pack)?;
    Ok(pack)
}

impl ExternalPack {
    /// Convert this external pack definition into a runtime `Pack`.
    ///
    /// This creates a `Pack` that can be used with the evaluator, converting
    /// all external pattern definitions into their runtime equivalents.
    ///
    /// Note: The returned `Pack` uses `'static` strings for the struct fields that
    /// require it. Since external packs are loaded at runtime, we use `Box::leak`
    /// to create static references. This is acceptable because:
    /// 1. External packs are loaded once at startup
    /// 2. The pack data lives for the entire program lifetime
    /// 3. The leaked memory is a small, bounded amount per pack
    #[must_use]
    pub fn into_pack(self) -> Pack {
        // Leak the dynamic strings to get 'static lifetimes
        let name: &'static str = Box::leak(self.name.into_boxed_str());
        let description: &'static str = self
            .description
            .map_or("", |s| Box::leak(s.into_boxed_str()) as &'static str);

        // Convert keywords to static slice
        let keywords: &'static [&'static str] = if self.keywords.is_empty() {
            &[]
        } else {
            let kw_vec: Vec<&'static str> = self
                .keywords
                .into_iter()
                .map(|s| Box::leak(s.into_boxed_str()) as &'static str)
                .collect();
            Box::leak(kw_vec.into_boxed_slice())
        };

        // Convert safe patterns
        let safe_patterns: Vec<SafePattern> = self
            .safe_patterns
            .into_iter()
            .map(|p| {
                let name: &'static str = Box::leak(p.name.into_boxed_str());
                SafePattern {
                    regex: LazyCompiledRegex::new(Box::leak(p.pattern.into_boxed_str())),
                    name,
                }
            })
            .collect();

        // Convert destructive patterns
        let destructive_patterns: Vec<DestructivePattern> = self
            .destructive_patterns
            .into_iter()
            .map(|p| {
                let name: &'static str = Box::leak(p.name.into_boxed_str());
                let reason: &'static str = p
                    .description
                    .map_or("Blocked by external pack pattern", |s| {
                        Box::leak(s.into_boxed_str()) as &'static str
                    });
                let explanation: Option<&'static str> = p
                    .explanation
                    .map(|s| Box::leak(s.into_boxed_str()) as &'static str);

                DestructivePattern {
                    regex: LazyCompiledRegex::new(Box::leak(p.pattern.into_boxed_str())),
                    reason,
                    name: Some(name),
                    severity: p.severity.into(),
                    explanation,
                }
            })
            .collect();

        Pack::new(
            self.id,
            name,
            description,
            keywords,
            safe_patterns,
            destructive_patterns,
        )
    }
}

/// Type of regex engine used for a pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegexEngineType {
    /// Linear-time automaton-based engine
    Linear,
    /// Backtracking engine (required for lookahead/lookbehind)
    Backtracking,
}

impl fmt::Display for RegexEngineType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Linear => write!(f, "linear"),
            Self::Backtracking => write!(f, "backtracking"),
        }
    }
}

/// Summary of regex engines used in a pack.
#[derive(Debug)]
pub struct EngineSummary {
    /// Number of patterns using linear-time engine
    pub linear_count: usize,
    /// Number of patterns using backtracking engine
    pub backtracking_count: usize,
}

impl EngineSummary {
    /// Total number of patterns
    #[must_use]
    pub const fn total(&self) -> usize {
        self.linear_count + self.backtracking_count
    }

    /// Percentage of patterns using linear-time engine
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn linear_percentage(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            100.0
        } else {
            (self.linear_count as f64 / total as f64) * 100.0
        }
    }
}

/// Information about a single pattern's engine.
#[derive(Debug)]
pub struct PatternEngineInfo {
    /// Name of the pattern
    pub name: String,
    /// Regex pattern string
    pub pattern: String,
    /// Whether this is a destructive pattern
    pub is_destructive: bool,
    /// Type of engine used
    pub engine: RegexEngineType,
}

/// Analyze which regex engine each pattern in a pack uses.
#[must_use]
pub fn analyze_pack_engines(pack: &ExternalPack) -> Vec<PatternEngineInfo> {
    use crate::packs::regex_engine::needs_backtracking_engine;

    let mut results = Vec::new();

    for pattern in &pack.destructive_patterns {
        let engine = if needs_backtracking_engine(&pattern.pattern) {
            RegexEngineType::Backtracking
        } else {
            RegexEngineType::Linear
        };
        results.push(PatternEngineInfo {
            name: pattern.name.clone(),
            pattern: pattern.pattern.clone(),
            is_destructive: true,
            engine,
        });
    }

    for pattern in &pack.safe_patterns {
        let engine = if needs_backtracking_engine(&pattern.pattern) {
            RegexEngineType::Backtracking
        } else {
            RegexEngineType::Linear
        };
        results.push(PatternEngineInfo {
            name: pattern.name.clone(),
            pattern: pattern.pattern.clone(),
            is_destructive: false,
            engine,
        });
    }

    results
}

/// Summarize the regex engines used in a pack.
#[must_use]
pub fn summarize_pack_engines(pack: &ExternalPack) -> EngineSummary {
    let infos = analyze_pack_engines(pack);
    let backtracking_count = infos
        .iter()
        .filter(|i| i.engine == RegexEngineType::Backtracking)
        .count();
    let linear_count = infos.len() - backtracking_count;

    EngineSummary {
        linear_count,
        backtracking_count,
    }
}

/// A loaded external pack plus its source path.
#[derive(Debug)]
pub struct LoadedExternalPack {
    /// Pack identifier (e.g., "company.rules").
    pub id: String,
    /// Parsed external pack definition.
    pub pack: ExternalPack,
    /// Source file path.
    pub path: PathBuf,
}

/// A warning emitted while loading external packs.
#[derive(Debug)]
pub struct PackLoadWarning {
    /// Path to the pack file.
    pub path: PathBuf,
    /// Error encountered while parsing/validating.
    pub error: PackParseError,
}

/// Result of loading external packs.
#[derive(Debug)]
pub struct ExternalPackLoadResult {
    /// Successfully loaded packs.
    pub packs: Vec<LoadedExternalPack>,
    /// Non-fatal warnings for packs that failed to load.
    pub warnings: Vec<PackLoadWarning>,
}

/// Loader for external packs (YAML files).
#[derive(Debug, Default)]
pub struct ExternalPackLoader {
    paths: Vec<PathBuf>,
}

impl ExternalPackLoader {
    /// Create a loader from an explicit list of file paths.
    #[must_use]
    pub fn from_paths(paths: &[String]) -> Self {
        let paths = paths.iter().map(PathBuf::from).collect();
        Self { paths }
    }

    /// Return the configured pack paths.
    #[must_use]
    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }

    /// Load all packs, collecting non-fatal warnings.
    ///
    /// Collisions with built-in packs are rejected and surfaced as warnings.
    #[must_use]
    pub fn load_all(&self) -> ExternalPackLoadResult {
        let mut packs = Vec::new();
        let mut warnings = Vec::new();

        for path in &self.paths {
            match parse_pack_file_checked(path) {
                Ok(pack) => {
                    let id = pack.id.clone();
                    packs.push(LoadedExternalPack {
                        id,
                        pack,
                        path: path.clone(),
                    });
                }
                Err(error) => {
                    warnings.push(PackLoadWarning {
                        path: path.clone(),
                        error,
                    });
                }
            }
        }

        ExternalPackLoadResult { packs, warnings }
    }

    /// Load all packs and deduplicate by pack ID (later entries win).
    #[must_use]
    pub fn load_all_deduped(&self) -> ExternalPackLoadResult {
        let mut warnings = Vec::new();
        let mut order: Vec<String> = Vec::new();
        let mut by_id: HashMap<String, LoadedExternalPack> = HashMap::new();

        for path in &self.paths {
            match parse_pack_file_checked(path) {
                Ok(pack) => {
                    let id = pack.id.clone();
                    order.push(id.clone());
                    by_id.insert(
                        id.clone(),
                        LoadedExternalPack {
                            id,
                            pack,
                            path: path.clone(),
                        },
                    );
                }
                Err(error) => {
                    warnings.push(PackLoadWarning {
                        path: path.clone(),
                        error,
                    });
                }
            }
        }

        let mut seen = HashSet::new();
        let mut packs_rev = Vec::new();
        for id in order.iter().rev() {
            if seen.insert(id.clone()) {
                if let Some(pack) = by_id.remove(id) {
                    packs_rev.push(pack);
                }
            }
        }
        packs_rev.reverse();

        ExternalPackLoadResult {
            packs: packs_rev,
            warnings,
        }
    }
}

#[cfg(test)]
#[allow(clippy::needless_raw_string_hashes)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_pack() {
        let yaml = r#"
schema_version: 1
id: test.example
name: Test Pack
version: 1.0.0
description: A test pack for unit testing
keywords:
  - test
  - example
destructive_patterns:
  - name: test-pattern
    pattern: test.*dangerous
    severity: high
    description: Blocks test dangerous commands
safe_patterns:
  - name: test-safe
    pattern: test.*safe
    description: Allows test safe commands
"#;
        let pack = parse_pack_string(yaml).unwrap();
        assert_eq!(pack.id, "test.example");
        assert_eq!(pack.name, "Test Pack");
        assert_eq!(pack.version, "1.0.0");
        assert_eq!(pack.keywords.len(), 2);
        assert_eq!(pack.destructive_patterns.len(), 1);
        assert_eq!(pack.safe_patterns.len(), 1);
    }

    #[test]
    fn test_parse_minimal_pack() {
        let yaml = r#"
id: minimal.pack
name: Minimal
version: 0.1.0
destructive_patterns:
  - name: block-all
    pattern: danger
"#;
        let pack = parse_pack_string(yaml).unwrap();
        assert_eq!(pack.id, "minimal.pack");
        assert_eq!(pack.schema_version, 1); // Default
        assert!(pack.keywords.is_empty());
        assert_eq!(pack.destructive_patterns.len(), 1);
        assert!(pack.safe_patterns.is_empty());
    }

    #[test]
    fn test_invalid_id_format() {
        let yaml = r#"
id: InvalidID
name: Test
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
"#;
        let result = parse_pack_string(yaml);
        assert!(matches!(result, Err(PackParseError::InvalidId { .. })));
    }

    #[test]
    fn test_invalid_id_missing_dot() {
        let yaml = r#"
id: nodotinid
name: Test
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
"#;
        let result = parse_pack_string(yaml);
        assert!(matches!(result, Err(PackParseError::InvalidId { .. })));
    }

    #[test]
    fn test_invalid_version_format() {
        let yaml = r#"
id: test.pack
name: Test
version: 1.0
destructive_patterns:
  - name: test
    pattern: test
"#;
        let result = parse_pack_string(yaml);
        assert!(matches!(result, Err(PackParseError::InvalidVersion { .. })));
    }

    #[test]
    fn test_unsupported_schema_version() {
        let yaml = r#"
schema_version: 999
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
"#;
        let result = parse_pack_string(yaml);
        assert!(matches!(
            result,
            Err(PackParseError::UnsupportedSchemaVersion { .. })
        ));
    }

    #[test]
    fn test_invalid_regex_pattern() {
        let yaml = r#"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: bad-regex
    pattern: "[invalid(regex"
"#;
        let result = parse_pack_string(yaml);
        assert!(matches!(result, Err(PackParseError::InvalidPattern { .. })));
    }

    #[test]
    fn test_duplicate_pattern_name() {
        let yaml = r#"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: duplicate
    pattern: pattern1
  - name: duplicate
    pattern: pattern2
"#;
        let result = parse_pack_string(yaml);
        assert!(matches!(
            result,
            Err(PackParseError::DuplicatePattern { .. })
        ));
    }

    #[test]
    fn test_duplicate_across_safe_and_destructive() {
        let yaml = r#"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: duplicate
    pattern: pattern1
safe_patterns:
  - name: duplicate
    pattern: pattern2
"#;
        let result = parse_pack_string(yaml);
        assert!(matches!(
            result,
            Err(PackParseError::DuplicatePattern { .. })
        ));
    }

    #[test]
    fn test_empty_pack() {
        let yaml = r#"
id: test.pack
name: Test
version: 1.0.0
"#;
        let result = parse_pack_string(yaml);
        assert!(matches!(result, Err(PackParseError::EmptyPack)));
    }

    #[test]
    fn test_severity_levels() {
        let yaml = r#"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: low
    pattern: low
    severity: low
  - name: medium
    pattern: medium
    severity: medium
  - name: high
    pattern: high
    severity: high
  - name: critical
    pattern: critical
    severity: critical
"#;
        let pack = parse_pack_string(yaml).unwrap();
        assert_eq!(pack.destructive_patterns[0].severity, ExternalSeverity::Low);
        assert_eq!(
            pack.destructive_patterns[1].severity,
            ExternalSeverity::Medium
        );
        assert_eq!(
            pack.destructive_patterns[2].severity,
            ExternalSeverity::High
        );
        assert_eq!(
            pack.destructive_patterns[3].severity,
            ExternalSeverity::Critical
        );
    }

    #[test]
    fn test_default_severity() {
        let yaml = r#"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: no-severity
    pattern: test
"#;
        let pack = parse_pack_string(yaml).unwrap();
        assert_eq!(
            pack.destructive_patterns[0].severity,
            ExternalSeverity::High
        ); // Default
    }

    #[test]
    fn test_convert_to_pack() {
        let yaml = r#"
id: test.example
name: Test Example Pack
version: 1.0.0
description: Testing conversion
keywords:
  - test
destructive_patterns:
  - name: block-test
    pattern: dangerous
    severity: critical
    description: Blocks dangerous commands
    explanation: This is a detailed explanation
safe_patterns:
  - name: allow-safe
    pattern: safe
    description: Allows safe commands
"#;
        let external = parse_pack_string(yaml).unwrap();
        let pack = external.into_pack();

        assert_eq!(pack.id, "test.example");
        assert_eq!(pack.name, "Test Example Pack");
        assert_eq!(pack.description, "Testing conversion");
        assert_eq!(pack.keywords.len(), 1);
        assert_eq!(pack.keywords[0], "test");
        assert_eq!(pack.safe_patterns.len(), 1);
        assert_eq!(pack.destructive_patterns.len(), 1);
        assert_eq!(pack.destructive_patterns[0].severity, Severity::Critical);
    }

    #[test]
    fn test_yaml_parse_error() {
        let yaml = "invalid: yaml: content: [";
        let result = parse_pack_string(yaml);
        assert!(matches!(result, Err(PackParseError::Yaml(_))));
    }

    #[test]
    fn test_error_display() {
        let err = PackParseError::InvalidId {
            id: "bad".to_string(),
            reason: "test".to_string(),
        };
        assert!(err.to_string().contains("bad"));

        let err = PackParseError::DuplicatePattern {
            name: "dup".to_string(),
        };
        assert!(err.to_string().contains("dup"));

        let err = PackParseError::IdCollision {
            id: "core.git".to_string(),
            builtin_name: "Git".to_string(),
        };
        assert!(err.to_string().contains("core.git"));
        assert!(err.to_string().contains("Git"));
        assert!(err.to_string().contains("collides"));
    }

    #[test]
    fn test_collision_with_builtin_pack() {
        // Test collision with a known built-in pack (core.git)
        let yaml = r#"
id: core.git
name: Malicious Override
version: 1.0.0
destructive_patterns:
  - name: allow-everything
    pattern: never-match-anything-12345
"#;
        let result = parse_pack_string_checked(yaml);
        assert!(matches!(result, Err(PackParseError::IdCollision { .. })));

        if let Err(PackParseError::IdCollision { id, builtin_name }) = result {
            assert_eq!(id, "core.git");
            assert!(!builtin_name.is_empty());
        }
    }

    #[test]
    fn test_no_collision_with_custom_namespace() {
        // Custom namespace should not collide
        let yaml = r#"
id: mycompany.deploy
name: MyCompany Deploy
version: 1.0.0
destructive_patterns:
  - name: block-prod
    pattern: deploy.*prod
"#;
        let result = parse_pack_string_checked(yaml);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_builtin_collision_function() {
        // Should detect collision with core.git
        let result = check_builtin_collision("core.git");
        assert!(result.is_some());

        // Should detect collision with database.postgresql
        let result = check_builtin_collision("database.postgresql");
        assert!(result.is_some());

        // Should NOT detect collision with custom namespace
        let result = check_builtin_collision("mycompany.custom");
        assert!(result.is_none());

        // Should NOT detect collision with non-existent pack in existing category
        // (e.g., "database.oracle" doesn't exist as built-in)
        let result = check_builtin_collision("database.oracle");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_without_collision_check_allows_override() {
        // parse_pack_string (without collision check) allows any valid ID
        let yaml = r#"
id: core.git
name: Override Git
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
"#;
        // Without collision check, this should succeed
        let result = parse_pack_string(yaml);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_pack_with_collision_check() {
        let yaml = r#"
id: core.filesystem
name: Override Filesystem
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
"#;
        let pack: ExternalPack = serde_yaml::from_str(yaml).unwrap();

        // Standard validation should pass
        assert!(validate_pack(&pack).is_ok());

        // Validation with collision check should fail
        let result = validate_pack_with_collision_check(&pack);
        assert!(matches!(result, Err(PackParseError::IdCollision { .. })));
    }
}
