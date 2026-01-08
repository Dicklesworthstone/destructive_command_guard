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
//! let result = evaluate_command("git status", &config, &enabled_keywords, &compiled_overrides);
//!
//! if result.is_denied() {
//!     println!("Blocked: {}", result.reason().unwrap_or("unknown"));
//! }
//! ```

pub mod cli;
pub mod config;
pub mod context;
pub mod evaluator;
pub mod hook;
pub mod packs;

// Re-export commonly used types
pub use config::Config;
pub use evaluator::{
    EvaluationDecision, EvaluationResult, LegacyDestructivePattern, LegacySafePattern, MatchSource,
    PatternMatch, evaluate_command, evaluate_command_with_legacy,
};
pub use hook::{HookInput, HookOutput, HookResult, HookSpecificOutput};
pub use packs::{Pack, PackId, PackRegistry};

// Re-export context types
pub use context::{
    CommandSpans, ContextClassifier, SAFE_STRING_REGISTRY, SafeFlagEntry, SafeStringRegistry, Span,
    SpanKind, classify_command, is_argument_data,
};
