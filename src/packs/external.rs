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
use std::fmt;
use std::io;
use std::path::Path;

use super::regex_engine::LazyCompiledRegex;
use super::{DestructivePattern, Pack, SafePattern, Severity};

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

#[cfg(test)]
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
    }
}
