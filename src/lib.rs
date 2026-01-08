//! Destructive Command Guard (dcg) library.
//!
//! This library provides the core functionality for blocking destructive commands
//! in AI coding agent workflows. It supports modular "packs" of patterns for
//! different use cases (databases, containers, Kubernetes, cloud providers, etc.).
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        Configuration                             │
//! │  (env vars → project config → user config → system → defaults)  │
//! └─────────────────────────────────────────────────────────────────┘
//!                                  │
//!                                  ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         Evaluator                                │
//! │  (unified entry point for hook mode and CLI)                    │
//! └─────────────────────────────────────────────────────────────────┘
//!                                  │
//!                                  ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         Pack Registry                            │
//! │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
//! │  │   Core   │ │ Database │ │  K8s     │ │  Cloud   │  ...      │
//! │  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
//! └─────────────────────────────────────────────────────────────────┘
//!                                  │
//!                                  ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      Pattern Matching                            │
//! │  Quick Reject (memchr) → Safe Patterns → Destructive Patterns   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! The main entry point for command evaluation is the [`evaluator`] module:
//!
//! ```ignore
//! use destructive_command_guard::config::Config;
//! use destructive_command_guard::evaluator::{evaluate_command, EvaluationDecision};
//!
//! let config = Config::load();
//! let compiled_overrides = config.overrides.compile();
//! let enabled_keywords = vec!["git", "rm"];
//! let allowlists = destructive_command_guard::load_default_allowlists();
//! let result = evaluate_command(
//!     "git status",
//!     &config,
//!     &enabled_keywords,
//!     &compiled_overrides,
//!     &allowlists,
//! );
//!
//! if result.is_denied() {
//!     println!("Blocked: {}", result.reason().unwrap_or("unknown"));
//! }
//! ```

pub mod allowlist;
pub mod ast_matcher;
pub mod cli;
pub mod config;
pub mod context;
pub mod evaluator;
pub mod heredoc;
pub mod hook;
pub mod packs;
pub mod scan;
pub mod suggestions;
pub mod trace;

// Re-export commonly used types
pub use allowlist::{
    AllowEntry, AllowSelector, AllowlistError, AllowlistFile, AllowlistLayer, LayeredAllowlist,
    LoadedAllowlistLayer, RuleId, load_default_allowlists,
};
pub use config::Config;
pub use evaluator::{
    EvaluationDecision, EvaluationResult, LegacyDestructivePattern, LegacySafePattern, MatchSource,
    MatchSpan, PatternMatch, evaluate_command, evaluate_command_with_legacy,
    evaluate_command_with_pack_order,
};
pub use hook::{HookInput, HookOutput, HookResult, HookSpecificOutput};
pub use packs::{Pack, PackId, PackRegistry};

// Re-export context types
pub use context::{
    CommandSpans, ContextClassifier, SAFE_STRING_REGISTRY, SafeFlagEntry, SafeStringRegistry, Span,
    SpanKind, classify_command, is_argument_data, sanitize_for_pattern_matching,
};

// Re-export heredoc detection types
pub use heredoc::{
    ExtractedContent, ExtractedShellCommand, ExtractionLimits, ExtractionResult, HeredocType,
    ScriptLanguage, TriggerResult, check_triggers, extract_content, extract_shell_commands,
    matched_triggers,
};

// Re-export AST matcher types
pub use ast_matcher::{
    AstMatcher, CompiledPattern, DEFAULT_MATCHER, MatchError, PatternMatch as AstPatternMatch,
    Severity,
};

// Re-export trace types for explain mode
pub use trace::{
    AllowlistInfo, EXPLAIN_JSON_SCHEMA_VERSION, ExplainJsonOutput, ExplainTrace, JsonAllowlistInfo,
    JsonMatchInfo, JsonPackSummary, JsonSpan, JsonSuggestion, JsonTraceDetails, JsonTraceStep,
    MatchInfo, PackSummary, TraceCollector, TraceDetails, TraceStep, format_duration,
    truncate_utf8,
};

// Re-export suggestion types
pub use suggestions::{Suggestion, SuggestionKind, get_suggestion_by_kind, get_suggestions};

// Re-export scan types for `dcg scan`
pub use scan::{
    ExtractedCommand, ScanDecision, ScanEvalContext, ScanFailOn, ScanFinding, ScanFormat,
    ScanOptions, ScanReport, ScanSeverity, ScanSummary, scan_paths, should_fail, sort_findings,
};
