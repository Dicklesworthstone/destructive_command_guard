//! Performance budgets for dcg.
//!
//! This module defines explicit latency budgets for all dcg operations.
//! These constants serve as the source of truth for:
//! - CI benchmark enforcement (fail on regression)
//! - Runtime fail-open thresholds (heredoc analysis)
//! - Documentation and expectations
//!
//! # Budget Philosophy
//!
//! dcg runs on every Bash command, so performance is critical. We define:
//! - **Target**: Expected p99 latency under normal conditions
//! - **Warning**: Latency that triggers a CI warning
//! - **Panic**: Latency that fails CI or triggers fail-open behavior
//!
//! # Performance Tiers
//!
//! | Tier | Path | Target | Warning | Panic |
//! |------|------|--------|---------|-------|
//! | 0 | Quick reject | < 1μs | < 5μs | > 50μs |
//! | 1 | Fast path | < 75μs | < 150μs | > 500μs |
//! | 2 | Pattern match | < 100μs | < 250μs | > 1ms |
//! | 3 | Heredoc trigger | < 5μs | < 10μs | > 100μs |
//! | 4 | Heredoc extract | < 200μs | < 500μs | > 2ms |
//! | 5 | Language detect | < 20μs | < 50μs | > 200μs |
//! | 6 | Full pipeline | < 5ms | < 15ms | > 50ms |
//!
//! # Absolute Maximum
//!
//! Any operation exceeding 50ms triggers fail-open behavior in hook mode.
//! This ensures dcg never blocks a user's workflow indefinitely.

use std::time::{Duration, Instant};

/// Performance budget for a single operation tier.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    /// Target p99 latency (expected performance).
    pub target: Duration,
    /// Warning threshold (triggers CI warning).
    pub warning: Duration,
    /// Panic threshold (fails CI, triggers fail-open).
    pub panic: Duration,
}

impl Budget {
    /// Create a new budget with the given thresholds.
    #[must_use]
    pub const fn new(target_us: u64, warning_us: u64, panic_us: u64) -> Self {
        Self {
            target: Duration::from_micros(target_us),
            warning: Duration::from_micros(warning_us),
            panic: Duration::from_micros(panic_us),
        }
    }

    /// Create a budget from milliseconds (for longer operations).
    #[must_use]
    pub const fn from_ms(target_ms: u64, warning_ms: u64, panic_ms: u64) -> Self {
        Self {
            target: Duration::from_millis(target_ms),
            warning: Duration::from_millis(warning_ms),
            panic: Duration::from_millis(panic_ms),
        }
    }

    /// Check if a duration exceeds the warning threshold.
    #[must_use]
    pub fn exceeds_warning(&self, duration: Duration) -> bool {
        duration > self.warning
    }

    /// Check if a duration exceeds the panic threshold.
    #[must_use]
    pub fn exceeds_panic(&self, duration: Duration) -> bool {
        duration > self.panic
    }

    /// Return the appropriate status for a duration.
    #[must_use]
    pub fn status(&self, duration: Duration) -> BudgetStatus {
        if duration > self.panic {
            BudgetStatus::Panic
        } else if duration > self.warning {
            BudgetStatus::Warning
        } else if duration > self.target {
            BudgetStatus::Elevated
        } else {
            BudgetStatus::Ok
        }
    }
}

/// Status result from budget check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetStatus {
    /// Duration is within target.
    Ok,
    /// Duration exceeds target but within warning.
    Elevated,
    /// Duration exceeds warning but within panic.
    Warning,
    /// Duration exceeds panic threshold.
    Panic,
}

// =============================================================================
// Deadline Type (for fail-open budget enforcement)
// =============================================================================

/// A deadline for operation completion, used for fail-open behavior.
///
/// The Deadline tracks when an operation started and how long it's allowed
/// to run. When the deadline is exceeded, expensive operations should be
/// skipped and the command allowed to proceed (fail-open).
///
/// # Example
///
/// ```
/// use destructive_command_guard::perf::Deadline;
/// use std::time::Duration;
///
/// let deadline = Deadline::new(Duration::from_millis(10));
/// // ... perform operations ...
/// if deadline.is_exceeded() {
///     // Skip remaining analysis, fail-open
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Deadline {
    /// When the deadline started.
    start: Instant,
    /// Maximum duration allowed.
    max_duration: Duration,
}

impl Deadline {
    /// Create a new deadline with the given maximum duration.
    #[must_use]
    pub fn new(max_duration: Duration) -> Self {
        Self {
            start: Instant::now(),
            max_duration,
        }
    }

    /// Create a deadline from the absolute maximum (fail-open threshold).
    #[must_use]
    pub fn fail_open_default() -> Self {
        Self::new(ABSOLUTE_MAX)
    }

    /// Check if the deadline has been exceeded.
    #[must_use]
    pub fn is_exceeded(&self) -> bool {
        self.start.elapsed() > self.max_duration
    }

    /// Get the remaining time before the deadline, or None if exceeded.
    #[must_use]
    pub fn remaining(&self) -> Option<Duration> {
        self.max_duration.checked_sub(self.start.elapsed())
    }

    /// Get the elapsed time since the deadline started.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Get the maximum duration for this deadline.
    #[must_use]
    pub const fn max_duration(&self) -> Duration {
        self.max_duration
    }

    /// Check if there's enough time remaining for an operation with the given budget.
    ///
    /// Returns true if the remaining time exceeds the budget's panic threshold.
    #[must_use]
    pub fn has_budget_for(&self, budget: &Budget) -> bool {
        self.remaining().is_some_and(|r| r > budget.panic)
    }
}

// =============================================================================
// Tier 0: Quick Reject (no relevant keywords)
// =============================================================================

/// Budget for commands rejected by keyword gating (e.g., `ls -la`).
/// These should be nearly instant as no pattern matching occurs.
pub const QUICK_REJECT: Budget = Budget::new(
    1,  // target: 1μs
    5,  // warning: 5μs
    50, // panic: 50μs
);

// =============================================================================
// Tier 1: Fast Path (safe commands with relevant keywords)
// =============================================================================

/// Budget for safe commands that match keywords but pass safe patterns.
/// Example: `git status`, `docker ps`.
pub const FAST_PATH: Budget = Budget::new(
    75,  // target: 75μs
    150, // warning: 150μs
    500, // panic: 500μs
);

// =============================================================================
// Tier 2: Pattern Matching (full pack evaluation)
// =============================================================================

/// Budget for commands requiring full pattern evaluation.
/// Example: `git reset --hard`, `docker system prune`.
pub const PATTERN_MATCH: Budget = Budget::new(
    100,  // target: 100μs
    250,  // warning: 250μs
    1000, // panic: 1ms
);

// =============================================================================
// Tier 3: Heredoc Trigger Check
// =============================================================================

/// Budget for checking if a command might contain heredoc/inline scripts.
/// This is a quick regex check, not full extraction.
pub const HEREDOC_TRIGGER: Budget = Budget::new(
    5,   // target: 5μs
    10,  // warning: 10μs
    100, // panic: 100μs
);

// =============================================================================
// Tier 4: Heredoc Extraction
// =============================================================================

/// Budget for extracting heredoc content from a command.
/// Includes parsing heredoc markers and extracting body.
pub const HEREDOC_EXTRACT: Budget = Budget::new(
    200,  // target: 200μs
    500,  // warning: 500μs
    2000, // panic: 2ms
);

// =============================================================================
// Tier 5: Language Detection
// =============================================================================

/// Budget for detecting the language of embedded script content.
/// Uses shebang analysis and heuristics.
pub const LANGUAGE_DETECT: Budget = Budget::new(
    20,  // target: 20μs
    50,  // warning: 50μs
    200, // panic: 200μs
);

// =============================================================================
// Tier 6: Full Heredoc Pipeline
// =============================================================================

/// Budget for complete heredoc analysis (trigger + extract + analyze).
/// This is the slow path, used only when heredoc content is detected.
pub const FULL_HEREDOC_PIPELINE: Budget = Budget::from_ms(
    5,  // target: 5ms
    15, // warning: 15ms
    20, // panic: 20ms
);

// =============================================================================
// Absolute Maximum (Fail-Open Threshold)
// =============================================================================

/// Absolute maximum time before hook mode triggers fail-open.
/// Any operation exceeding this duration allows the command to proceed.
/// This ensures dcg never blocks a user's workflow indefinitely.
pub const ABSOLUTE_MAX: Duration = Duration::from_millis(50);

/// Hook evaluation time budget in milliseconds.
///
/// This is the **fail-open** threshold for hook mode. Typical commands should
/// complete in <10ms, but heredoc/inline-script analysis may take longer on
/// pathological inputs; in those cases we fail open rather than break workflows.
pub const HOOK_EVALUATION_BUDGET_MS: u64 = 50;

/// Hook evaluation time budget as a Duration.
pub const HOOK_EVALUATION_BUDGET: Duration = Duration::from_millis(HOOK_EVALUATION_BUDGET_MS);

/// Check if a duration should trigger fail-open behavior.
#[must_use]
pub fn should_fail_open(duration: Duration) -> bool {
    duration > ABSOLUTE_MAX
}

// =============================================================================
// Summary Constants for External Use
// =============================================================================

/// Fast path maximum budget in microseconds (panic threshold).
/// Commands exceeding this trigger CI failures.
pub const FAST_PATH_BUDGET_US: u64 = 500;

/// Slow path (heredoc) maximum budget in milliseconds (panic threshold).
/// Operations exceeding this trigger fail-open behavior.
pub const SLOW_PATH_BUDGET_MS: u64 = 50;

/// Absolute maximum before fail-open (for documentation and config).
pub const FAIL_OPEN_THRESHOLD_MS: u64 = 50;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_status_classification() {
        let budget = Budget::new(10, 50, 100);

        assert_eq!(budget.status(Duration::from_micros(5)), BudgetStatus::Ok);
        assert_eq!(budget.status(Duration::from_micros(10)), BudgetStatus::Ok);
        assert_eq!(
            budget.status(Duration::from_micros(11)),
            BudgetStatus::Elevated
        );
        assert_eq!(
            budget.status(Duration::from_micros(50)),
            BudgetStatus::Elevated
        );
        assert_eq!(
            budget.status(Duration::from_micros(51)),
            BudgetStatus::Warning
        );
        assert_eq!(
            budget.status(Duration::from_micros(100)),
            BudgetStatus::Warning
        );
        assert_eq!(
            budget.status(Duration::from_micros(101)),
            BudgetStatus::Panic
        );
    }

    #[test]
    fn fail_open_threshold() {
        assert!(!should_fail_open(Duration::from_millis(49)));
        assert!(!should_fail_open(Duration::from_millis(50)));
        assert!(should_fail_open(Duration::from_millis(51)));
    }

    #[test]
    fn budget_hierarchy_makes_sense() {
        // Quick reject should be faster than fast path
        assert!(QUICK_REJECT.panic < FAST_PATH.target);

        // Fast path should be faster than pattern match
        assert!(FAST_PATH.panic <= PATTERN_MATCH.panic);

        // Heredoc trigger should be fast
        assert!(HEREDOC_TRIGGER.panic < HEREDOC_EXTRACT.target);

        // Full pipeline should accommodate all components
        assert!(FULL_HEREDOC_PIPELINE.panic >= HEREDOC_EXTRACT.panic);
    }

    #[test]
    fn deadline_creation() {
        let deadline = Deadline::new(Duration::from_millis(100));
        assert!(!deadline.is_exceeded());
        assert!(deadline.remaining().is_some());
        assert_eq!(deadline.max_duration(), Duration::from_millis(100));
    }

    #[test]
    fn deadline_fail_open_default() {
        let deadline = Deadline::fail_open_default();
        assert_eq!(deadline.max_duration(), ABSOLUTE_MAX);
        assert!(!deadline.is_exceeded());
    }

    #[test]
    fn deadline_exceeded_with_zero_duration() {
        let deadline = Deadline::new(Duration::ZERO);
        // A zero-duration deadline should be immediately exceeded
        assert!(deadline.is_exceeded());
        assert!(deadline.remaining().is_none());
    }

    #[test]
    fn deadline_has_budget_for() {
        let deadline = Deadline::new(Duration::from_millis(100));
        let small_budget = Budget::new(1000, 5000, 10_000); // 10ms panic
        let large_budget = Budget::new(10_000, 50_000, 200_000); // 200ms panic

        // Should have budget for small operations
        assert!(deadline.has_budget_for(&small_budget));
        // Should not have budget for operations that take longer than the deadline
        assert!(!deadline.has_budget_for(&large_budget));
    }
}
