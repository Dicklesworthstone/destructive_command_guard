//! Performance budgets for dcg.
//!
//! This module defines explicit latency budgets for all dcg operations.
//! These constants serve as the source of truth for:
//! - CI benchmark enforcement (fail on regression)
//! - Runtime bounded-evaluation thresholds (heredoc analysis)
//! - Documentation and expectations
//!
//! # Budget Philosophy
//!
//! dcg runs on every Bash command, so performance is critical. We define:
//! - **Target**: Expected p99 latency under normal conditions
//! - **Warning**: Latency that triggers a CI warning
//! - **Panic**: Latency that fails CI or triggers the bounded fallback policy
//!
//! # Performance Tiers
//!
//! | Tier | Path | Target | Warning Above | Panic Above |
//! |------|------|--------|---------------|-------------|
//! | 0 | Quick reject | < 1μs | > 5μs | > 50μs |
//! | 1 | Fast path | < 75μs | > 150μs | > 500μs |
//! | 2 | Pattern match | < 100μs | > 250μs | > 1ms |
//! | 3 | Heredoc trigger | < 5μs | > 10μs | > 100μs |
//! | 4 | Heredoc extract | < 200μs | > 500μs | > 2ms |
//! | 5 | Language detect | < 20μs | > 50μs | > 200μs |
//! | 6 | Full heredoc pipeline | < 5ms | > 15ms | > 20ms |
//!
//! # Absolute Maximum
//!
//! Hook evaluation exceeding 1000ms returns an explicit indeterminate decision;
//! it never turns incomplete analysis into a silent allow.
//! This ensures dcg never blocks a user's workflow indefinitely.

use std::time::{Duration, Instant};

/// Performance budget for a single operation tier.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    /// Target p99 latency (expected performance).
    pub target: Duration,
    /// Warning threshold (triggers CI warning).
    pub warning: Duration,
    /// Panic threshold for benchmark/CI budget assertions.
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
// Deadline Type (for bounded, conservative safety evaluation)
// =============================================================================

/// A deadline for bounded operation completion.
///
/// The Deadline tracks when an operation started and how long it's allowed
/// to run. Callers choose the policy for exhaustion. Hook evaluation must
/// return an explicit indeterminate result so elapsed time is never mistaken
/// for proof that a command is safe.
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
///     // Stop remaining analysis and return the caller's bounded outcome.
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

    /// Create a deadline using the default absolute hook budget.
    #[must_use]
    pub fn hook_default() -> Self {
        Self::new(ABSOLUTE_MAX)
    }

    /// Check if the deadline has been exceeded.
    #[must_use]
    pub fn is_exceeded(&self) -> bool {
        // `>=` so a zero-duration deadline is exceeded immediately even when
        // the monotonic clock has not advanced between construction and check.
        self.start.elapsed() >= self.max_duration
    }

    /// Get the remaining time before the deadline, or None if exceeded.
    #[must_use]
    pub fn remaining(&self) -> Option<Duration> {
        let elapsed = self.start.elapsed();
        // Mirror `is_exceeded`'s `>=` comparison so a zero-duration deadline
        // reports None even when the monotonic clock has not advanced between
        // construction and this call (the checked_sub form returned Some(0)
        // in that window, contradicting both the doc contract and
        // `is_exceeded`, and made the zero-duration test flaky).
        (elapsed < self.max_duration).then(|| self.max_duration.saturating_sub(elapsed))
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
// Absolute Hook Evaluation Budget
// =============================================================================

/// Absolute maximum time available to hook safety evaluation.
/// Exhaustion produces an explicit indeterminate result rather than an allow.
pub const ABSOLUTE_MAX: Duration = Duration::from_millis(1_000);

/// Hook evaluation time budget in milliseconds.
///
/// Typical commands complete in well under 50ms, but a one-shot hook process
/// pays lazy pattern compilation for every keyword-matched pack, and loaded
/// hosts can multiply that cost. The previous 200ms default was exceeded
/// *deterministically* by ordinary single-construct commands on fast hardware
/// (#245, #248), turning routine agent commands into fail-closed review
/// prompts. The deadline exists to catch pathological hangs (#189), which sit
/// orders of magnitude above normal evaluation, so 1000ms preserves that
/// backstop with real headroom. Exhaustion is still surfaced as indeterminate
/// so clients can request review or block conservatively — never allow.
pub const HOOK_EVALUATION_BUDGET_MS: u64 = 1_000;

/// Hook evaluation time budget as a Duration.
pub const HOOK_EVALUATION_BUDGET: Duration = Duration::from_millis(HOOK_EVALUATION_BUDGET_MS);

/// Default hook budget when the broad Windows company preset is enabled.
///
/// That preset activates enough packs that cold process startup and lazy
/// pattern compilation can exceed the ordinary 1000ms budget on older Windows
/// workstations. The larger budget lets the same fail-closed evaluation
/// finish; it does not change any allow/deny rule.
pub const CAREFUL_COMPANY_HOOK_EVALUATION_BUDGET_MS: u64 = 3_000;

/// Check whether a duration exceeds the absolute hook evaluation budget.
#[must_use]
pub fn exceeds_absolute_budget(duration: Duration) -> bool {
    duration > ABSOLUTE_MAX
}

// =============================================================================
// Summary Constants for External Use
// =============================================================================

/// Fast path maximum budget in microseconds (panic threshold).
/// Commands exceeding this trigger CI failures.
pub const FAST_PATH_BUDGET_US: u64 = 500;

/// Hook-mode slow-path deadline in milliseconds.
///
/// This mirrors the absolute hook deadline, not the Tier 6 benchmark panic
/// threshold. Tier-specific heredoc budgets are defined above.
pub const SLOW_PATH_BUDGET_MS: u64 = 1_000;

/// Minimum hook evaluation timeout in milliseconds.
///
/// Prevents `hook_timeout_ms = 0` (or an absurdly small value) from forcing
/// every request immediately into the indeterminate review/block path.
///
/// 10ms is enough for the fast path (quick-reject + safe pattern matching)
/// while being well below the default 1000ms budget.
pub const MIN_HOOK_TIMEOUT_MS: u64 = 10;

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

    /// The absolute latency gate must stay wired to the shipped budget.
    ///
    /// #245 shipped because nothing tied the *product's* deadline to a test
    /// that could fail on absolute cost: the perf job only ratcheted against a
    /// recorded baseline. This test asserts the CI gate still reads
    /// `HOOK_EVALUATION_BUDGET_MS` out of this file and still runs the two
    /// suites that catch the failure at the protocol layer. If someone renames
    /// the constant, drops the gate, or removes the harness matrix, this test
    /// fails rather than silently re-opening the hole.
    #[test]
    fn ci_enforces_absolute_latency_gate_against_shipped_budget() {
        const {
            assert!(
                HOOK_EVALUATION_BUDGET_MS > 0,
                "the shipped hook budget must remain positive so gate mode cannot \
                 collapse into a disabled sentinel"
            );
        }
        let ci = include_str!("../.github/workflows/ci.yml");

        let gate_step = ci
            .split("      - name: Absolute evaluator-cost gate vs shipped default budget")
            .nth(1)
            .and_then(|rest| rest.split("\n      - name: ").next())
            .expect("CI must retain the named absolute evaluator-cost gate step");
        assert!(
            gate_step.contains(
                r"BUDGET_MS=$(grep -oP 'pub const HOOK_EVALUATION_BUDGET_MS: u64 = \K[0-9_]+' src/perf.rs | tr -d '_')"
            ),
            "the absolute gate step must derive BUDGET_MS directly from \
             HOOK_EVALUATION_BUDGET_MS in src/perf.rs"
        );
        assert!(
            gate_step.contains("python3 -B scripts/perf_baseline.py --self-test"),
            "the absolute gate must exercise source-binding and large-sample tail mutants"
        );
        assert!(
            gate_step.contains("--assert-budget-ms \"$BUDGET_MS\""),
            "the same absolute gate step must pass its derived BUDGET_MS to \
             scripts/perf_baseline.py"
        );
        assert!(
            gate_step.contains("\"$BUDGET_MS\" -le 0")
                && gate_step.contains("HOOK_EVALUATION_BUDGET_MS must be one positive integer"),
            "zero must be rejected as an invalid shipped budget, not interpreted \
             by the Python harness as a disabled gate"
        );
        assert!(
            gate_step.contains("LATENCY_ARTIFACT_DIR=\"$RUNNER_TEMP/dcg-perf-latency\"")
                && gate_step.contains("--output \"$LATENCY_ARTIFACT_DIR/perf-latency-gate.json\""),
            "the absolute gate must write its self-contained certificate outside \
             the checkout so its own artifact cannot invalidate the source fence"
        );

        // The margin must leave real headroom: a gate set at ~100% of the
        // budget passes right up until the moment users start failing closed.
        let margin = gate_step
            .split("--assert-margin-pct")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|value| value.parse::<u32>().ok())
            .expect("CI must pass an explicit --assert-margin-pct value");
        assert!(
            margin <= 60,
            "latency gate margin is {margin}% of the budget; keep it <=60% so \
             the gate trips before real users hit indeterminate verdicts"
        );
        assert!(
            gate_step.contains("--skip-trace --warmup 5 --runs 100"),
            "the latency gate must retain 100 samples so its 95/95 binomial \
             tolerance rule can reject more than one over-limit sample"
        );

        let artifact_step = ci
            .split("      - name: Upload absolute latency gate certificate")
            .nth(1)
            .and_then(|rest| rest.split("\n      - name: ").next())
            .expect("CI must retain the absolute latency certificate upload step");
        assert!(
            artifact_step.contains("if: always()")
                && artifact_step
                    .contains("path: ${{ runner.temp }}/dcg-perf-latency/perf-latency-gate.json")
                && artifact_step.contains("if-no-files-found: error"),
            "CI must require and retain perf-latency-gate.json on both pass and failure"
        );

        let relative_step = ci
            .split("      - name: Run perf baseline + compare to repo baseline")
            .nth(1)
            .and_then(|rest| rest.split("\n      - name: ").next())
            .expect("CI must retain the relative perf regression step");
        assert!(
            relative_step.contains("PERF_ARTIFACT_DIR=\"$RUNNER_TEMP/dcg-perf-relative\"")
                && relative_step.contains("CURRENT_JSON=\"$PERF_ARTIFACT_DIR/perf-current.json\"")
                && relative_step
                    .contains("REPORT_MD=\"$PERF_ARTIFACT_DIR/perf-regression-report.md\"")
                && relative_step.contains("parse_constant=reject_non_finite_json_constant")
                && relative_step.contains("math.isfinite(numeric)")
                && relative_step.contains("required_baseline_case_ids"),
            "relative perf artifacts must stay outside the checkout so they do not \
             make the following binary/source binding check fail, and malformed \
             or vacuous baseline metrics must fail closed"
        );

        let matrix_step = ci
            .split("      - name: Harness protocol matrix (real binary, every agent wire format)")
            .nth(1)
            .and_then(|rest| rest.split("\n      - name: ").next())
            .expect("CI must retain the harness protocol matrix step");
        assert!(
            matrix_step.contains("scripts/e2e_harness_matrix.sh --binary target/release/dcg"),
            "CI must run the harness protocol matrix against the real release binary"
        );
    }

    /// A release tag is descriptive metadata, not a commit identity: the same
    /// tag text can point at different commits over time. Keep the certificate
    /// bound to the full object id even when `git describe` is identical.
    #[test]
    fn latency_certificate_source_binding_requires_full_git_sha() {
        let build_script = include_str!("../build.rs");
        let main_source = include_str!("main.rs");
        let harness = include_str!("../scripts/perf_baseline.py");

        assert!(
            build_script.contains(".sha(false)"),
            "build.rs must embed the full Git object id, not vergen's short SHA"
        );
        assert!(
            main_source.contains("Git SHA: {sha}"),
            "dcg --version must expose the embedded full Git SHA for the certificate"
        );

        let classifier = harness
            .split("def classify_source_binding(")
            .nth(1)
            .and_then(|rest| rest.split("\ndef capture_git_state(").next())
            .expect("perf harness must retain its source-binding classifier");
        assert!(
            classifier.contains("elif embedded_git_sha != repository_git_sha:")
                && classifier.contains("status = \"verified_exact_git_sha\"")
                && classifier.contains("\"verified\": status == \"verified_exact_git_sha\""),
            "source binding must reject differing full SHAs even when descriptions match"
        );
    }

    /// A certificate must identify the compiler that produced the binary, not
    /// whichever rustup proxy is visible under its isolated measurement HOME.
    #[test]
    fn latency_certificate_binds_native_build_toolchain_and_retains_failures() {
        let build_script = include_str!("../build.rs");
        let main_source = include_str!("main.rs");
        let harness = include_str!("../scripts/perf_baseline.py");

        for required_builder_call in [
            ".semver(true)",
            ".commit_hash(true)",
            ".commit_date(true)",
            ".host_triple(true)",
        ] {
            assert!(
                build_script.contains(required_builder_call),
                "build.rs lost required rustc identity field {required_builder_call}"
            );
        }
        for stable_label in ["Rustc release", "Rustc commit", "Rustc date", "Rustc host"] {
            assert!(
                main_source.contains(stable_label),
                "dcg --version lost stable compiler label {stable_label}"
            );
        }

        let classifier = harness
            .split("def classify_toolchain_binding(")
            .nth(1)
            .and_then(|rest| rest.split("\ndef classify_source_binding(").next())
            .expect("perf harness must retain its compiler-binding classifier");
        assert!(
            classifier.contains("invalid_rustc_identity_fields")
                && classifier.contains("status = \"verified_exact_rustc_vv\"")
                && classifier.contains("embedded[field] != observed[field]"),
            "compiler binding must reject malformed or unequal identities before \
             certifying exact rustc -vV equality"
        );
        assert!(
            harness.contains("PERF_ARTIFACT_SCHEMA_VERSION = 4")
                && harness.contains("gate_enabled = args.assert_budget_ms is not None")
                && harness.contains("def run_guarded_entrypoint(")
                && harness.contains("abort_emitter("),
            "certificate schema, explicit gate sentinel, or emergency ERROR \
             artifact retention regressed"
        );
        assert!(
            harness.contains("REQUIRED_ABSOLUTE_GATE_CASE_IDS")
                && harness.contains("absolute gate case contract is missing required ids")
                && harness.contains("PERF_HOOK_AGENT = \"claude-code\"")
                && harness.contains("[bin_path, \"--agent\", PERF_HOOK_AGENT]"),
            "the absolute gate must not pass an empty or bypass-only case set, \
             or infer a variable agent profile from process ancestry"
        );
    }

    /// OMP's installed extension consumes a compact private robot envelope.
    /// Testing the ordinary robot schema does not certify that callback seam.
    #[test]
    fn harness_matrix_uses_exact_omp_bridge_protocol() {
        let harness = include_str!("../scripts/e2e_harness_matrix.sh");
        let omp_case = harness
            .split("assert_omp_bridge_case()")
            .nth(1)
            .and_then(|rest| rest.split("assert_omp_agent_attribution() {").next())
            .expect("harness matrix must retain its private OMP bridge assertion");
        assert!(
            omp_case.contains("--robot test --stdin")
                && omp_case
                    .contains("--agent omp --dialect posix --format json --omp-bridge-output")
                && omp_case.contains("expected_stdout")
                && omp_case.contains("stdout_bytes")
                && omp_case.contains("\"$@\" | run_dcg_cli"),
            "OMP matrix must assert exact argv, compact bytes, exit status, and streams"
        );
        assert!(
            harness.contains(
                "assert_omp_bridge_case omp newline-only 0 '{\"decision\":\"allow\"}' printf '\\n'"
            ) && harness.contains(
                "assert_omp_bridge_case omp crlf-only 0 '{\"decision\":\"allow\"}' printf '\\r\\n'"
            ) && harness.contains("assert_omp_bridge_case omp control-bytes-destructive-tail 1")
                && harness.contains("printf 'echo safe\\000\\t\\033\\ngit reset --hard'"),
            "OMP matrix must preserve terminal line endings and feed control bytes without lossy shell variables"
        );
    }

    #[test]
    fn fail_open_threshold() {
        assert!(!exceeds_absolute_budget(Duration::from_millis(999)));
        assert!(!exceeds_absolute_budget(Duration::from_millis(1_000)));
        assert!(exceeds_absolute_budget(Duration::from_millis(1_001)));
    }

    #[test]
    fn budget_hierarchy_makes_sense() {
        // Quick reject should be faster than fast path
        assert!(QUICK_REJECT.panic < FAST_PATH.target);

        // Fast path should be faster than pattern match
        assert!(FAST_PATH.panic <= PATTERN_MATCH.panic);

        // Heredoc trigger should be fast
        assert!(HEREDOC_TRIGGER.panic < HEREDOC_EXTRACT.target);

        // Full heredoc pipeline should accommodate all components
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
    fn deadline_hook_default() {
        let deadline = Deadline::hook_default();
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

    fn doc_duration(duration: Duration) -> String {
        let micros = duration.as_micros();
        if micros >= 1000 && micros.is_multiple_of(1000) {
            format!("{}ms", micros / 1000)
        } else {
            format!("{micros}μs")
        }
    }

    fn budget_row(tier: u8, path: &str, budget: Budget) -> String {
        format!(
            "| {tier} | {path} | < {} | > {} | > {} |",
            doc_duration(budget.target),
            doc_duration(budget.warning),
            doc_duration(budget.panic)
        )
    }

    #[test]
    fn budget_documentation_matches_source_of_truth() {
        let readme = include_str!("../README.md");
        let agents = include_str!("../AGENTS.md");
        let ci = include_str!("../.github/workflows/ci.yml");
        let bench = include_str!("../.github/workflows/bench.yml");

        for row in [
            budget_row(0, "Quick reject", QUICK_REJECT),
            budget_row(1, "Fast path", FAST_PATH),
            budget_row(2, "Pattern match", PATTERN_MATCH),
            budget_row(3, "Heredoc trigger", HEREDOC_TRIGGER),
            budget_row(4, "Heredoc extract", HEREDOC_EXTRACT),
            budget_row(5, "Language detect", LANGUAGE_DETECT),
            budget_row(6, "Full heredoc pipeline", FULL_HEREDOC_PIPELINE),
        ] {
            assert!(
                readme.contains(&row),
                "README performance budget table drifted; missing row: {row}"
            );
        }

        // Derive the deadline prose from the constant rather than hard-coding
        // it. A literal here only proves the docs say some fixed number — it
        // cannot detect the constant moving underneath them, which is the
        // exact drift this test exists to prevent (a build with the budget
        // reverted to 200ms passed this test while the docs still claimed
        // 1000ms).
        let deadline_prose = format!(
            "- Hook evaluation deadline: {HOOK_EVALUATION_BUDGET_MS}ms \
             (exhaustion is indeterminate, never a silent allow)"
        );
        for expected in [
            "- Quick reject: < 50us panic",
            "- Fast path: < 500us panic",
            "- Pattern match: < 1ms panic",
            "- Heredoc extract: < 2ms panic",
            "- Full heredoc pipeline: < 20ms panic",
            deadline_prose.as_str(),
        ] {
            assert!(
                agents.contains(expected),
                "AGENTS.md benchmark budget prose drifted from src/perf.rs; missing: {expected}"
            );
        }

        let ci_deadline_prose = format!("# {deadline_prose}");
        for expected in [
            "# - Full heredoc pipeline: 20ms panic",
            ci_deadline_prose.as_str(),
            "Full heredoc pipeline benchmark exceeds 20ms budget",
        ] {
            assert!(
                ci.contains(expected),
                ".github/workflows/ci.yml budget prose drifted from src/perf.rs; missing: {expected}"
            );
        }

        // The README states the same deadline in prose; keep it in lockstep so
        // users are never told a budget the binary does not use.
        assert!(
            readme.contains(&format!("default is **{HOOK_EVALUATION_BUDGET_MS}ms**")),
            "README hook-deadline prose drifted from HOOK_EVALUATION_BUDGET_MS \
             ({HOOK_EVALUATION_BUDGET_MS}ms)"
        );

        assert!(
            bench.contains("- Full heredoc pipeline: < 20ms (panic threshold)"),
            ".github/workflows/bench.yml budget prose drifted"
        );
    }
}
