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
pub mod logging;
pub mod normalize;
pub mod packs;
pub mod pending_exceptions;
pub mod perf;
pub mod scan;
pub mod simulate;
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
    MatchSpan, PatternMatch, evaluate_command, evaluate_command_with_deadline,
    evaluate_command_with_legacy, evaluate_command_with_pack_order,
    evaluate_command_with_pack_order_at_path, evaluate_command_with_pack_order_deadline,
    evaluate_command_with_pack_order_deadline_at_path,
};
pub use hook::{HookInput, HookOutput, HookResult, HookSpecificOutput};
pub use packs::{Pack, PackId, PackRegistry};
pub use pending_exceptions::{PendingExceptionRecord, PendingExceptionStore};

// Re-export dual regex engine abstraction (from regex safety audit)
pub use packs::regex_engine::{CompiledRegex, needs_backtracking_engine};

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

// Re-export simulate types for `dcg simulate`
pub use simulate::{
    LimitHit, ParseError, ParseStats, ParsedCommand, ParsedLine, SIMULATE_SCHEMA_VERSION,
    SimulateInputFormat, SimulateLimits, SimulateParser,
};

// Re-export performance budget types
pub use perf::{
    ABSOLUTE_MAX, Budget, BudgetStatus, Deadline, FAIL_OPEN_THRESHOLD_MS, FAST_PATH,
    FAST_PATH_BUDGET_US, FULL_HEREDOC_PIPELINE, HEREDOC_EXTRACT, HEREDOC_TRIGGER,
    HOOK_EVALUATION_BUDGET, HOOK_EVALUATION_BUDGET_MS, LANGUAGE_DETECT, PATTERN_MATCH,
    QUICK_REJECT, SLOW_PATH_BUDGET_MS, should_fail_open,
};

// Re-export normalize types for wrapper stripping
pub use normalize::{NormalizedCommand, StrippedWrapper, strip_wrapper_prefixes};
