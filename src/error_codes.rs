//! Standardized error codes for DCG.
//!
//! This module provides a consistent error code system for all DCG operations.
//! Error codes follow the format `DCG-XXXX` where:
//!
//! - DCG-1xxx: Pattern matching errors
//! - DCG-2xxx: Configuration errors
//! - DCG-3xxx: Runtime errors
//! - DCG-4xxx: External integration errors
//!
//! # Example
//!
//! ```ignore
//! use destructive_command_guard::error_codes::{DcgError, ErrorCode};
//!
//! let error = DcgError::pattern_compile_failed("core.git", "invalid regex: [");
//! println!("{}", serde_json::to_string_pretty(&error).unwrap());
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Error categories for DCG operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    /// Pattern matching and evaluation errors (DCG-1xxx)
    PatternMatch,
    /// Configuration loading and parsing errors (DCG-2xxx)
    Configuration,
    /// Runtime and execution errors (DCG-3xxx)
    Runtime,
    /// External integration errors (DCG-4xxx)
    External,
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PatternMatch => write!(f, "pattern_match"),
            Self::Configuration => write!(f, "configuration"),
            Self::Runtime => write!(f, "runtime"),
            Self::External => write!(f, "external"),
        }
    }
}

/// Standardized error codes for DCG.
///
/// Each error code has a numeric value and a human-readable description.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    // ===========================================
    // DCG-1xxx: Pattern Matching Errors
    // ===========================================
    /// DCG-1001: Pattern compilation failed
    #[serde(rename = "DCG-1001")]
    PatternCompileFailed,

    /// DCG-1002: Pattern match timeout
    #[serde(rename = "DCG-1002")]
    PatternMatchTimeout,

    /// DCG-1003: Invalid pattern syntax
    #[serde(rename = "DCG-1003")]
    InvalidPatternSyntax,

    /// DCG-1004: Pattern evaluation error
    #[serde(rename = "DCG-1004")]
    PatternEvaluationError,

    /// DCG-1005: Quick reject filter error
    #[serde(rename = "DCG-1005")]
    QuickRejectError,

    /// DCG-1006: Safe pattern mismatch
    #[serde(rename = "DCG-1006")]
    SafePatternMismatch,

    /// DCG-1007: Destructive pattern match
    #[serde(rename = "DCG-1007")]
    DestructivePatternMatch,

    /// DCG-1008: Pack pattern not found
    #[serde(rename = "DCG-1008")]
    PackPatternNotFound,

    /// DCG-1009: Heredoc extraction failed
    #[serde(rename = "DCG-1009")]
    HeredocExtractionFailed,

    /// DCG-1010: AST matching error
    #[serde(rename = "DCG-1010")]
    AstMatchingError,

    // ===========================================
    // DCG-2xxx: Configuration Errors
    // ===========================================
    /// DCG-2001: Configuration file not found
    #[serde(rename = "DCG-2001")]
    ConfigFileNotFound,

    /// DCG-2002: Configuration parse error
    #[serde(rename = "DCG-2002")]
    ConfigParseError,

    /// DCG-2003: Invalid configuration value
    #[serde(rename = "DCG-2003")]
    InvalidConfigValue,

    /// DCG-2004: Allowlist load error
    #[serde(rename = "DCG-2004")]
    AllowlistLoadError,

    /// DCG-2005: Invalid allowlist entry
    #[serde(rename = "DCG-2005")]
    InvalidAllowlistEntry,

    /// DCG-2006: Pack configuration error
    #[serde(rename = "DCG-2006")]
    PackConfigError,

    /// DCG-2007: Pack not found
    #[serde(rename = "DCG-2007")]
    PackNotFound,

    /// DCG-2008: Invalid rule ID format
    #[serde(rename = "DCG-2008")]
    InvalidRuleIdFormat,

    /// DCG-2009: Duplicate rule ID
    #[serde(rename = "DCG-2009")]
    DuplicateRuleId,

    /// DCG-2010: Settings file error
    #[serde(rename = "DCG-2010")]
    SettingsFileError,

    // ===========================================
    // DCG-3xxx: Runtime Errors
    // ===========================================
    /// DCG-3001: JSON parse error
    #[serde(rename = "DCG-3001")]
    JsonParseError,

    /// DCG-3002: IO error
    #[serde(rename = "DCG-3002")]
    IoError,

    /// DCG-3003: Timeout exceeded
    #[serde(rename = "DCG-3003")]
    TimeoutExceeded,

    /// DCG-3004: Memory limit exceeded
    #[serde(rename = "DCG-3004")]
    MemoryLimitExceeded,

    /// DCG-3005: Invalid input
    #[serde(rename = "DCG-3005")]
    InvalidInput,

    /// DCG-3006: Hook protocol error
    #[serde(rename = "DCG-3006")]
    HookProtocolError,

    /// DCG-3007: Stdin read error
    #[serde(rename = "DCG-3007")]
    StdinReadError,

    /// DCG-3008: Stdout write error
    #[serde(rename = "DCG-3008")]
    StdoutWriteError,

    /// DCG-3009: File scan error
    #[serde(rename = "DCG-3009")]
    FileScanError,

    /// DCG-3010: Database error
    #[serde(rename = "DCG-3010")]
    DatabaseError,

    // ===========================================
    // DCG-4xxx: External Integration Errors
    // ===========================================
    /// DCG-4001: External pack load failed
    #[serde(rename = "DCG-4001")]
    ExternalPackLoadFailed,

    /// DCG-4002: External pack parse error
    #[serde(rename = "DCG-4002")]
    ExternalPackParseError,

    /// DCG-4003: Network request failed
    #[serde(rename = "DCG-4003")]
    NetworkRequestFailed,

    /// DCG-4004: Version check failed
    #[serde(rename = "DCG-4004")]
    VersionCheckFailed,

    /// DCG-4005: MCP protocol error
    #[serde(rename = "DCG-4005")]
    McpProtocolError,

    /// DCG-4006: Hook integration error
    #[serde(rename = "DCG-4006")]
    HookIntegrationError,

    /// DCG-4007: Git operation failed
    #[serde(rename = "DCG-4007")]
    GitOperationFailed,

    /// DCG-4008: Claude Code hook error
    #[serde(rename = "DCG-4008")]
    ClaudeCodeHookError,

    /// DCG-4009: External command execution failed
    #[serde(rename = "DCG-4009")]
    ExternalCommandFailed,

    /// DCG-4010: API rate limit exceeded
    #[serde(rename = "DCG-4010")]
    ApiRateLimitExceeded,
}

impl ErrorCode {
    /// Get the numeric code as a string (e.g., "DCG-1001").
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            // Pattern matching errors
            Self::PatternCompileFailed => "DCG-1001",
            Self::PatternMatchTimeout => "DCG-1002",
            Self::InvalidPatternSyntax => "DCG-1003",
            Self::PatternEvaluationError => "DCG-1004",
            Self::QuickRejectError => "DCG-1005",
            Self::SafePatternMismatch => "DCG-1006",
            Self::DestructivePatternMatch => "DCG-1007",
            Self::PackPatternNotFound => "DCG-1008",
            Self::HeredocExtractionFailed => "DCG-1009",
            Self::AstMatchingError => "DCG-1010",
            // Configuration errors
            Self::ConfigFileNotFound => "DCG-2001",
            Self::ConfigParseError => "DCG-2002",
            Self::InvalidConfigValue => "DCG-2003",
            Self::AllowlistLoadError => "DCG-2004",
            Self::InvalidAllowlistEntry => "DCG-2005",
            Self::PackConfigError => "DCG-2006",
            Self::PackNotFound => "DCG-2007",
            Self::InvalidRuleIdFormat => "DCG-2008",
            Self::DuplicateRuleId => "DCG-2009",
            Self::SettingsFileError => "DCG-2010",
            // Runtime errors
            Self::JsonParseError => "DCG-3001",
            Self::IoError => "DCG-3002",
            Self::TimeoutExceeded => "DCG-3003",
            Self::MemoryLimitExceeded => "DCG-3004",
            Self::InvalidInput => "DCG-3005",
            Self::HookProtocolError => "DCG-3006",
            Self::StdinReadError => "DCG-3007",
            Self::StdoutWriteError => "DCG-3008",
            Self::FileScanError => "DCG-3009",
            Self::DatabaseError => "DCG-3010",
            // External integration errors
            Self::ExternalPackLoadFailed => "DCG-4001",
            Self::ExternalPackParseError => "DCG-4002",
            Self::NetworkRequestFailed => "DCG-4003",
            Self::VersionCheckFailed => "DCG-4004",
            Self::McpProtocolError => "DCG-4005",
            Self::HookIntegrationError => "DCG-4006",
            Self::GitOperationFailed => "DCG-4007",
            Self::ClaudeCodeHookError => "DCG-4008",
            Self::ExternalCommandFailed => "DCG-4009",
            Self::ApiRateLimitExceeded => "DCG-4010",
        }
    }

    /// Get the error category for this code.
    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        match self {
            Self::PatternCompileFailed
            | Self::PatternMatchTimeout
            | Self::InvalidPatternSyntax
            | Self::PatternEvaluationError
            | Self::QuickRejectError
            | Self::SafePatternMismatch
            | Self::DestructivePatternMatch
            | Self::PackPatternNotFound
            | Self::HeredocExtractionFailed
            | Self::AstMatchingError => ErrorCategory::PatternMatch,

            Self::ConfigFileNotFound
            | Self::ConfigParseError
            | Self::InvalidConfigValue
            | Self::AllowlistLoadError
            | Self::InvalidAllowlistEntry
            | Self::PackConfigError
            | Self::PackNotFound
            | Self::InvalidRuleIdFormat
            | Self::DuplicateRuleId
            | Self::SettingsFileError => ErrorCategory::Configuration,

            Self::JsonParseError
            | Self::IoError
            | Self::TimeoutExceeded
            | Self::MemoryLimitExceeded
            | Self::InvalidInput
            | Self::HookProtocolError
            | Self::StdinReadError
            | Self::StdoutWriteError
            | Self::FileScanError
            | Self::DatabaseError => ErrorCategory::Runtime,

            Self::ExternalPackLoadFailed
            | Self::ExternalPackParseError
            | Self::NetworkRequestFailed
            | Self::VersionCheckFailed
            | Self::McpProtocolError
            | Self::HookIntegrationError
            | Self::GitOperationFailed
            | Self::ClaudeCodeHookError
            | Self::ExternalCommandFailed
            | Self::ApiRateLimitExceeded => ErrorCategory::External,
        }
    }

    /// Get a human-readable description of the error code.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            // Pattern matching errors
            Self::PatternCompileFailed => "Pattern compilation failed",
            Self::PatternMatchTimeout => "Pattern match timed out",
            Self::InvalidPatternSyntax => "Invalid pattern syntax",
            Self::PatternEvaluationError => "Pattern evaluation error",
            Self::QuickRejectError => "Quick reject filter error",
            Self::SafePatternMismatch => "Safe pattern did not match as expected",
            Self::DestructivePatternMatch => "Destructive pattern matched",
            Self::PackPatternNotFound => "Pattern not found in pack",
            Self::HeredocExtractionFailed => "Heredoc extraction failed",
            Self::AstMatchingError => "AST matching error",
            // Configuration errors
            Self::ConfigFileNotFound => "Configuration file not found",
            Self::ConfigParseError => "Failed to parse configuration file",
            Self::InvalidConfigValue => "Invalid configuration value",
            Self::AllowlistLoadError => "Failed to load allowlist",
            Self::InvalidAllowlistEntry => "Invalid allowlist entry",
            Self::PackConfigError => "Pack configuration error",
            Self::PackNotFound => "Pack not found",
            Self::InvalidRuleIdFormat => "Invalid rule ID format",
            Self::DuplicateRuleId => "Duplicate rule ID",
            Self::SettingsFileError => "Settings file error",
            // Runtime errors
            Self::JsonParseError => "JSON parse error",
            Self::IoError => "IO error",
            Self::TimeoutExceeded => "Operation timed out",
            Self::MemoryLimitExceeded => "Memory limit exceeded",
            Self::InvalidInput => "Invalid input",
            Self::HookProtocolError => "Hook protocol error",
            Self::StdinReadError => "Failed to read from stdin",
            Self::StdoutWriteError => "Failed to write to stdout",
            Self::FileScanError => "File scan error",
            Self::DatabaseError => "Database error",
            // External integration errors
            Self::ExternalPackLoadFailed => "Failed to load external pack",
            Self::ExternalPackParseError => "Failed to parse external pack",
            Self::NetworkRequestFailed => "Network request failed",
            Self::VersionCheckFailed => "Version check failed",
            Self::McpProtocolError => "MCP protocol error",
            Self::HookIntegrationError => "Hook integration error",
            Self::GitOperationFailed => "Git operation failed",
            Self::ClaudeCodeHookError => "Claude Code hook error",
            Self::ExternalCommandFailed => "External command execution failed",
            Self::ApiRateLimitExceeded => "API rate limit exceeded",
        }
    }

    /// Get the numeric code value (e.g., 1001 for DCG-1001).
    #[must_use]
    pub const fn numeric_code(&self) -> u16 {
        match self {
            Self::PatternCompileFailed => 1001,
            Self::PatternMatchTimeout => 1002,
            Self::InvalidPatternSyntax => 1003,
            Self::PatternEvaluationError => 1004,
            Self::QuickRejectError => 1005,
            Self::SafePatternMismatch => 1006,
            Self::DestructivePatternMatch => 1007,
            Self::PackPatternNotFound => 1008,
            Self::HeredocExtractionFailed => 1009,
            Self::AstMatchingError => 1010,
            Self::ConfigFileNotFound => 2001,
            Self::ConfigParseError => 2002,
            Self::InvalidConfigValue => 2003,
            Self::AllowlistLoadError => 2004,
            Self::InvalidAllowlistEntry => 2005,
            Self::PackConfigError => 2006,
            Self::PackNotFound => 2007,
            Self::InvalidRuleIdFormat => 2008,
            Self::DuplicateRuleId => 2009,
            Self::SettingsFileError => 2010,
            Self::JsonParseError => 3001,
            Self::IoError => 3002,
            Self::TimeoutExceeded => 3003,
            Self::MemoryLimitExceeded => 3004,
            Self::InvalidInput => 3005,
            Self::HookProtocolError => 3006,
            Self::StdinReadError => 3007,
            Self::StdoutWriteError => 3008,
            Self::FileScanError => 3009,
            Self::DatabaseError => 3010,
            Self::ExternalPackLoadFailed => 4001,
            Self::ExternalPackParseError => 4002,
            Self::NetworkRequestFailed => 4003,
            Self::VersionCheckFailed => 4004,
            Self::McpProtocolError => 4005,
            Self::HookIntegrationError => 4006,
            Self::GitOperationFailed => 4007,
            Self::ClaudeCodeHookError => 4008,
            Self::ExternalCommandFailed => 4009,
            Self::ApiRateLimitExceeded => 4010,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A structured DCG error with code, category, message, and context.
///
/// This is the standard error format for JSON output from DCG commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcgError {
    /// The error code (e.g., "DCG-1001")
    pub code: String,

    /// The error category
    pub category: ErrorCategory,

    /// Human-readable error message
    pub message: String,

    /// Additional context about the error
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub context: HashMap<String, serde_json::Value>,
}

impl DcgError {
    /// Create a new error with the given code and message.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code: code.as_str().to_string(),
            category: code.category(),
            message: message.into(),
            context: HashMap::new(),
        }
    }

    /// Create a new error with context.
    #[must_use]
    pub fn with_context(
        code: ErrorCode,
        message: impl Into<String>,
        context: HashMap<String, serde_json::Value>,
    ) -> Self {
        Self {
            code: code.as_str().to_string(),
            category: code.category(),
            message: message.into(),
            context,
        }
    }

    /// Add a context field to the error.
    #[must_use]
    pub fn add_context(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }

    // =========================================
    // Convenience constructors for common errors
    // =========================================

    /// Create a pattern compilation failure error.
    #[must_use]
    pub fn pattern_compile_failed(pattern_name: &str, details: &str) -> Self {
        Self::new(
            ErrorCode::PatternCompileFailed,
            format!("Failed to compile pattern '{pattern_name}': {details}"),
        )
        .add_context("pattern_name", pattern_name)
    }

    /// Create a pattern match timeout error.
    #[must_use]
    pub fn pattern_match_timeout(pattern_name: &str, timeout_ms: u64) -> Self {
        Self::new(
            ErrorCode::PatternMatchTimeout,
            format!("Pattern '{pattern_name}' match timed out after {timeout_ms}ms"),
        )
        .add_context("pattern_name", pattern_name)
        .add_context("timeout_ms", timeout_ms)
    }

    /// Create a JSON parse error.
    #[must_use]
    pub fn json_parse_error(details: &str) -> Self {
        Self::new(
            ErrorCode::JsonParseError,
            format!("JSON parse error: {details}"),
        )
    }

    /// Create an IO error.
    #[must_use]
    pub fn io_error(operation: &str, details: &str) -> Self {
        Self::new(
            ErrorCode::IoError,
            format!("IO error during {operation}: {details}"),
        )
        .add_context("operation", operation)
    }

    /// Create a config file not found error.
    #[must_use]
    pub fn config_not_found(path: &str) -> Self {
        Self::new(
            ErrorCode::ConfigFileNotFound,
            format!("Configuration file not found: {path}"),
        )
        .add_context("path", path)
    }

    /// Create a config parse error.
    #[must_use]
    pub fn config_parse_error(path: &str, details: &str) -> Self {
        Self::new(
            ErrorCode::ConfigParseError,
            format!("Failed to parse configuration file '{path}': {details}"),
        )
        .add_context("path", path)
    }

    /// Create an allowlist load error.
    #[must_use]
    pub fn allowlist_load_error(layer: &str, path: &str, details: &str) -> Self {
        Self::new(
            ErrorCode::AllowlistLoadError,
            format!("Failed to load {layer} allowlist from '{path}': {details}"),
        )
        .add_context("layer", layer)
        .add_context("path", path)
    }

    /// Create an invalid rule ID format error.
    #[must_use]
    pub fn invalid_rule_id_format(rule_id: &str, details: &str) -> Self {
        Self::new(
            ErrorCode::InvalidRuleIdFormat,
            format!("Invalid rule ID format '{rule_id}': {details}"),
        )
        .add_context("rule_id", rule_id)
    }

    /// Create an external pack load error.
    #[must_use]
    pub fn external_pack_load_failed(path: &str, details: &str) -> Self {
        Self::new(
            ErrorCode::ExternalPackLoadFailed,
            format!("Failed to load external pack from '{path}': {details}"),
        )
        .add_context("path", path)
    }

    /// Create a hook protocol error.
    #[must_use]
    pub fn hook_protocol_error(details: &str) -> Self {
        Self::new(
            ErrorCode::HookProtocolError,
            format!("Hook protocol error: {details}"),
        )
    }

    /// Create a stdin read error.
    #[must_use]
    pub fn stdin_read_error(details: &str) -> Self {
        Self::new(
            ErrorCode::StdinReadError,
            format!("Failed to read from stdin: {details}"),
        )
    }

    /// Create a file scan error.
    #[must_use]
    pub fn file_scan_error(file: &str, details: &str) -> Self {
        Self::new(
            ErrorCode::FileScanError,
            format!("Error scanning file '{file}': {details}"),
        )
        .add_context("file", file)
    }

    /// Convert to JSON string.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            format!(
                r#"{{"code":"{}","category":"{}","message":"{}"}}"#,
                self.code, self.category, self.message
            )
        })
    }

    /// Convert to pretty-printed JSON string.
    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| self.to_json())
    }
}

impl fmt::Display for DcgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for DcgError {}

/// Wrapper for error responses in JSON format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// The error details
    pub error: DcgError,
}

impl ErrorResponse {
    /// Create a new error response.
    #[must_use]
    pub const fn new(error: DcgError) -> Self {
        Self { error }
    }

    /// Convert to JSON string.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| self.error.to_json())
    }

    /// Convert to pretty-printed JSON string.
    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| self.to_json())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_as_str() {
        assert_eq!(ErrorCode::PatternCompileFailed.as_str(), "DCG-1001");
        assert_eq!(ErrorCode::ConfigFileNotFound.as_str(), "DCG-2001");
        assert_eq!(ErrorCode::JsonParseError.as_str(), "DCG-3001");
        assert_eq!(ErrorCode::ExternalPackLoadFailed.as_str(), "DCG-4001");
    }

    #[test]
    fn test_error_code_category() {
        assert_eq!(
            ErrorCode::PatternCompileFailed.category(),
            ErrorCategory::PatternMatch
        );
        assert_eq!(
            ErrorCode::ConfigFileNotFound.category(),
            ErrorCategory::Configuration
        );
        assert_eq!(ErrorCode::JsonParseError.category(), ErrorCategory::Runtime);
        assert_eq!(
            ErrorCode::ExternalPackLoadFailed.category(),
            ErrorCategory::External
        );
    }

    #[test]
    fn test_dcg_error_creation() {
        let error = DcgError::new(ErrorCode::JsonParseError, "unexpected end of input");
        assert_eq!(error.code, "DCG-3001");
        assert_eq!(error.category, ErrorCategory::Runtime);
        assert_eq!(error.message, "unexpected end of input");
        assert!(error.context.is_empty());
    }

    #[test]
    fn test_dcg_error_with_context() {
        let error = DcgError::pattern_compile_failed("core.git:reset-hard", "invalid regex");
        assert_eq!(error.code, "DCG-1001");
        assert_eq!(error.category, ErrorCategory::PatternMatch);
        assert!(error.context.contains_key("pattern_name"));
    }

    #[test]
    fn test_dcg_error_json_serialization() {
        let error = DcgError::json_parse_error("unexpected token");
        let json = error.to_json();
        assert!(json.contains("DCG-3001"));
        assert!(json.contains("runtime"));
        assert!(json.contains("unexpected token"));
    }

    #[test]
    fn test_error_response_json() {
        let error = DcgError::config_not_found("/path/to/config.toml");
        let response = ErrorResponse::new(error);
        let json = response.to_json();
        assert!(json.contains("error"));
        assert!(json.contains("DCG-2001"));
    }

    #[test]
    fn test_error_display() {
        let error = DcgError::io_error("file read", "permission denied");
        let display = error.to_string();
        assert!(display.contains("[DCG-3002]"));
        assert!(display.contains("permission denied"));
    }

    #[test]
    fn test_numeric_code() {
        assert_eq!(ErrorCode::PatternCompileFailed.numeric_code(), 1001);
        assert_eq!(ErrorCode::ConfigFileNotFound.numeric_code(), 2001);
        assert_eq!(ErrorCode::JsonParseError.numeric_code(), 3001);
        assert_eq!(ErrorCode::ExternalPackLoadFailed.numeric_code(), 4001);
    }

    #[test]
    fn test_all_codes_have_descriptions() {
        // Ensure all error codes have non-empty descriptions
        let codes = [
            ErrorCode::PatternCompileFailed,
            ErrorCode::PatternMatchTimeout,
            ErrorCode::InvalidPatternSyntax,
            ErrorCode::ConfigFileNotFound,
            ErrorCode::ConfigParseError,
            ErrorCode::JsonParseError,
            ErrorCode::IoError,
            ErrorCode::ExternalPackLoadFailed,
        ];

        for code in codes {
            assert!(
                !code.description().is_empty(),
                "Code {code:?} has empty description"
            );
        }
    }
}
