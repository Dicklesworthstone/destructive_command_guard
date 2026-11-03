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

use std::cell::{Cell, RefCell};
use std::io::Write;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

// =============================================================================
// Opt-in hook phase profiling
// =============================================================================

/// A measured hook operation. Timings are diagnostic wall time, never budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum ProfilePhase {
    /// Waiting for and reading the hook envelope from stdin.
    InputRead,
    /// Decoding and parsing the hook envelope, including fallback parsing.
    RequestParse,
    /// Loading configuration and detecting the invoking agent.
    ConfigLoad,
    /// Per-request setup, including allowlists and enabled-pack indexes.
    RequestSetup,
    /// Verifying or repairing hook registration.
    SelfHeal,
    /// Complete safety evaluation, including recursive command evaluation.
    Evaluation,
    /// Shell normalization and data masking before pattern evaluation.
    Normalization,
    /// Detecting constructs that require embedded-code analysis.
    HeredocDetect,
    /// Extracting embedded executable or data content.
    HeredocExtract,
    /// Evaluating enabled pack patterns and their semantic checks.
    PatternEvaluation,
    /// Selecting candidate packs with the existing keyword and semantic gates.
    PatternSelection,
    /// Preparing source views and segment ranges for selected packs.
    PatternPreparation,
    /// Compiling and evaluating a selected pack's rules.
    PatternRules,
    /// Tokenizing raw shell syntax for normalization and semantic checks.
    ShellTokenization,
    /// Splitting shell execution domains and nested substitutions.
    ShellSegmentation,
    /// Proving and masking non-executable heredoc data.
    HeredocMasking,
    /// Compiling a shell pack regex on first use.
    RegexCompile,
    /// Matching a compiled shell pack regex.
    RegexMatch,
    /// Parsing source into a tree-sitter AST.
    AstParse,
    /// Compiling ast-grep structural patterns.
    AstPatternCompile,
    /// Matching AST patterns, or awaiting that work on the hook thread.
    AstMatch,
    /// Resolving and opening the history store and starting its worker.
    HistoryInit,
    /// Constructing and queueing history entries.
    HistoryRecord,
    /// Explicit history flushes and the bounded wait during writer drop.
    HistoryFlush,
}

const PROFILE_PHASES: [(ProfilePhase, &str); 24] = [
    (ProfilePhase::InputRead, "input_read"),
    (ProfilePhase::RequestParse, "request_parse"),
    (ProfilePhase::ConfigLoad, "config_load"),
    (ProfilePhase::RequestSetup, "request_setup"),
    (ProfilePhase::SelfHeal, "self_heal"),
    (ProfilePhase::Evaluation, "evaluation"),
    (ProfilePhase::Normalization, "normalization"),
    (ProfilePhase::HeredocDetect, "heredoc_detect"),
    (ProfilePhase::HeredocExtract, "heredoc_extract"),
    (ProfilePhase::PatternEvaluation, "pattern_evaluation"),
    (ProfilePhase::PatternSelection, "pattern_selection"),
    (ProfilePhase::PatternPreparation, "pattern_preparation"),
    (ProfilePhase::PatternRules, "pattern_rules"),
    (ProfilePhase::ShellTokenization, "shell_tokenization"),
    (ProfilePhase::ShellSegmentation, "shell_segmentation"),
    (ProfilePhase::HeredocMasking, "heredoc_masking"),
    (ProfilePhase::RegexCompile, "regex_compile"),
    (ProfilePhase::RegexMatch, "regex_match"),
    (ProfilePhase::AstParse, "ast_parse"),
    (ProfilePhase::AstPatternCompile, "ast_pattern_compile"),
    (ProfilePhase::AstMatch, "ast_match"),
    (ProfilePhase::HistoryInit, "history_init"),
    (ProfilePhase::HistoryRecord, "history_record"),
    (ProfilePhase::HistoryFlush, "history_flush"),
];

#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
struct PhaseMeasurement {
    calls: u64,
    completed_calls: u64,
    elapsed_ns: u64,
    exclusive_ns: u64,
}

#[derive(Default)]
struct ProfileMeasurements {
    main: [PhaseMeasurement; PROFILE_PHASES.len()],
    workers: [PhaseMeasurement; PROFILE_PHASES.len()],
}

struct PhaseFrame {
    phase: ProfilePhase,
    started: Instant,
    children: Duration,
}

struct ThreadProfile {
    shared: Arc<Mutex<ProfileMeasurements>>,
    started: Instant,
    worker: bool,
    stack: Vec<PhaseFrame>,
}

impl ThreadProfile {
    fn begin(&mut self, phase: ProfilePhase, now: Instant) -> usize {
        let mut measurements = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        let rows = if self.worker {
            &mut measurements.workers
        } else {
            &mut measurements.main
        };
        rows[phase as usize].calls += 1;
        let depth = self.stack.len();
        self.stack.push(PhaseFrame {
            phase,
            started: now,
            children: Duration::ZERO,
        });
        depth
    }

    fn end(&mut self, now: Instant) {
        let Some(frame) = self.stack.pop() else {
            return;
        };
        let elapsed = now.saturating_duration_since(frame.started);
        if let Some(parent) = self.stack.last_mut() {
            parent.children = parent.children.saturating_add(elapsed);
        }
        let mut measurements = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        let rows = if self.worker {
            &mut measurements.workers
        } else {
            &mut measurements.main
        };
        let row = &mut rows[frame.phase as usize];
        row.completed_calls += 1;
        row.elapsed_ns = row.elapsed_ns.saturating_add(duration_ns(elapsed));
        row.exclusive_ns = row
            .exclusive_ns
            .saturating_add(duration_ns(elapsed.saturating_sub(frame.children)));
    }

    fn end_open_phases(&mut self, now: Instant) {
        while !self.stack.is_empty() {
            self.end(now);
        }
    }
}

thread_local! {
    // An absent collector is the whole disabled path: no clock, environment
    // lookup, lock, or allocation is performed at an instrumented call site.
    static THREAD_PROFILE: RefCell<Option<ThreadProfile>> = const { RefCell::new(None) };
    // The innermost phase open on this thread, kept with or without a
    // collector (one thread-local write per phase boundary, no clock), so an
    // exhausted budget can name the phase it ran out in (#571).
    static CURRENT_PHASE: Cell<Option<ProfilePhase>> = const { Cell::new(None) };
    static EXHAUSTION: Cell<BudgetExhaustion> = const { Cell::new(BudgetExhaustion::NONE) };
}

/// Where this thread's evaluation ran out of budget, for the indeterminate
/// reason (#571). Each field keeps its first observation since the last
/// [`take_budget_exhaustion`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BudgetExhaustion {
    /// The phase open when an expired deadline (or a remaining budget too
    /// small for the next step) was first observed. `Some(None)` means it was
    /// observed outside every instrumented phase.
    pub deadline: Option<Option<ProfilePhase>>,
    /// The first bounded analysis that could not complete (a regex search
    /// limit or an optional proof's own budget), and the phase it ran in.
    pub incomplete: Option<(&'static str, Option<ProfilePhase>)>,
}

impl BudgetExhaustion {
    const NONE: Self = Self {
        deadline: None,
        incomplete: None,
    };
}

/// Record that evaluation on this thread stopped for lack of time.
pub fn note_deadline_exhausted() {
    EXHAUSTION.with(|cell| {
        let mut note = cell.get();
        if note.deadline.is_none() {
            note.deadline = Some(CURRENT_PHASE.with(Cell::get));
            cell.set(note);
        }
    });
}

/// Record that a bounded analysis step (`stage`) could not complete.
pub fn note_incomplete_analysis(stage: &'static str) {
    EXHAUSTION.with(|cell| {
        let mut note = cell.get();
        if note.incomplete.is_none() {
            note.incomplete = Some((stage, CURRENT_PHASE.with(Cell::get)));
            cell.set(note);
        }
    });
}

/// Return and clear this thread's budget-exhaustion notes.
pub fn take_budget_exhaustion() -> BudgetExhaustion {
    EXHAUSTION.with(|cell| cell.replace(BudgetExhaustion::NONE))
}

/// The diagnostic name of a phase, as `DCG_PROFILE` reports it.
#[must_use]
pub fn phase_name(phase: ProfilePhase) -> &'static str {
    PROFILE_PHASES[phase as usize].1
}

/// User plus system CPU time this process has used, where the platform
/// reports it. Wall time alone cannot tell a slow input from a process the
/// host barely scheduled (#571).
#[must_use]
pub fn process_cpu_time() -> Option<Duration> {
    #[cfg(unix)]
    {
        let usage =
            nix::sys::resource::getrusage(nix::sys::resource::UsageWho::RUSAGE_SELF).ok()?;
        let micros = |time: nix::sys::time::TimeVal| {
            u64::try_from(time.tv_sec())
                .ok()?
                .checked_mul(1_000_000)?
                .checked_add(u64::try_from(time.tv_usec()).ok()?)
        };
        let total = micros(usage.user_time())?.checked_add(micros(usage.system_time())?)?;
        Some(Duration::from_micros(total))
    }
    #[cfg(not(unix))]
    {
        None
    }
}

fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// RAII phase measurement. Keep guards lexically nested on their origin thread.
#[must_use = "dropping the guard ends the measurement"]
pub struct PhaseGuard {
    active: Option<(Arc<Mutex<ProfileMeasurements>>, usize)>,
    // The phase this guard's phase nested in, restored on drop.
    outer: Option<ProfilePhase>,
    // A span must end on the thread whose stack it entered.
    _thread_bound: PhantomData<Rc<()>>,
}

/// Enter a phase: always as this thread's current phase, and as a measured
/// span only when hook profiling is active on this thread.
#[inline]
pub fn phase(phase: ProfilePhase) -> PhaseGuard {
    let outer = CURRENT_PHASE.with(|current| current.replace(Some(phase)));
    let active = THREAD_PROFILE.with(|slot| {
        let mut slot = slot.borrow_mut();
        let profile = slot.as_mut()?;
        let depth = profile.begin(phase, Instant::now());
        Some((Arc::clone(&profile.shared), depth))
    });
    PhaseGuard {
        active,
        outer,
        _thread_bound: PhantomData,
    }
}

impl Drop for PhaseGuard {
    fn drop(&mut self) {
        CURRENT_PHASE.with(|current| current.set(self.outer));
        let Some((shared, depth)) = self.active.as_ref() else {
            return;
        };
        THREAD_PROFILE.with(|slot| {
            let mut slot = slot.borrow_mut();
            if let Some(profile) = slot.as_mut() {
                if Arc::ptr_eq(shared, &profile.shared) && profile.stack.len() == depth + 1 {
                    profile.end(Instant::now());
                }
            }
        });
    }
}

/// Captured profiling context for a bounded AST worker.
///
/// Worker wall times are reported separately because they overlap the hook
/// thread's wait. They are not CPU measurements or additions to hook wall time.
pub struct ProfileContext {
    shared: Option<Arc<Mutex<ProfileMeasurements>>>,
}

/// Capture the current optional collector before spawning a worker thread.
#[must_use]
pub fn capture_profile() -> ProfileContext {
    ProfileContext {
        shared: THREAD_PROFILE.with(|slot| {
            slot.borrow()
                .as_ref()
                .map(|profile| Arc::clone(&profile.shared))
        }),
    }
}

impl ProfileContext {
    /// Attach this collector for the worker's lifetime.
    pub fn enter(self) -> WorkerProfileGuard {
        let previous =
            self.shared.map_or(PreviousProfile::Inactive, |shared| {
                match THREAD_PROFILE.with(|slot| {
                    slot.replace(Some(ThreadProfile {
                        shared,
                        started: Instant::now(),
                        worker: true,
                        stack: Vec::new(),
                    }))
                }) {
                    Some(profile) => PreviousProfile::Context(profile),
                    None => PreviousProfile::NoContext,
                }
            });
        WorkerProfileGuard {
            previous,
            _thread_bound: PhantomData,
        }
    }
}

enum PreviousProfile {
    /// No collector was attached, so dropping the guard changes nothing.
    Inactive,
    /// A collector was attached to a previously unprofiled thread.
    NoContext,
    /// A collector temporarily replaced this thread's previous context.
    Context(ThreadProfile),
}

/// Restores the worker thread's previous optional profiling context on drop.
#[must_use = "keep the guard alive while the worker is running"]
pub struct WorkerProfileGuard {
    previous: PreviousProfile,
    _thread_bound: PhantomData<Rc<()>>,
}

impl Drop for WorkerProfileGuard {
    fn drop(&mut self) {
        let previous = match std::mem::replace(&mut self.previous, PreviousProfile::Inactive) {
            PreviousProfile::Inactive => return,
            PreviousProfile::NoContext => None,
            PreviousProfile::Context(profile) => Some(profile),
        };
        if let Some(mut profile) = THREAD_PROFILE.with(|slot| slot.replace(previous)) {
            profile.end_open_phases(Instant::now());
        }
    }
}

/// Opt-in, one-invocation hook diagnostics (`DCG_PROFILE=1`).
///
/// Start after CLI dispatch. On return, emit one `DCG_PROFILE `-prefixed JSON
/// line to stderr. The interval excludes process startup and CLI setup, but
/// includes stdin waiting (`input_read`) and the history writer's bounded
/// shutdown wait. It never includes command text or paths. Robot mode keeps
/// its stderr-silent contract by passing `false` to [`Self::from_env`].
#[must_use = "keep the profiler alive until hook shutdown"]
pub struct HookProfile {
    active: bool,
    _thread_bound: PhantomData<Rc<()>>,
}

impl HookProfile {
    /// Start profiling when stderr is allowed and `DCG_PROFILE` is exactly `1`.
    pub fn from_env(stderr_allowed: bool) -> Self {
        Self::start(stderr_allowed && std::env::var_os("DCG_PROFILE").is_some_and(|v| v == "1"))
    }

    fn start(enabled: bool) -> Self {
        let active = enabled
            && THREAD_PROFILE.with(|slot| {
                let mut slot = slot.borrow_mut();
                if slot.is_some() {
                    return false;
                }
                *slot = Some(ThreadProfile {
                    shared: Arc::new(Mutex::new(ProfileMeasurements::default())),
                    started: Instant::now(),
                    worker: false,
                    stack: Vec::new(),
                });
                true
            });
        Self {
            active,
            _thread_bound: PhantomData,
        }
    }
}

impl Drop for HookProfile {
    fn drop(&mut self) {
        if self.active {
            finish_hook_profile();
        }
    }
}

fn profile_json(profile: &ThreadProfile, now: Instant) -> serde_json::Value {
    let measurements = profile
        .shared
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let rows_json = |rows: &[PhaseMeasurement; PROFILE_PHASES.len()]| {
        PROFILE_PHASES
            .iter()
            .map(|(phase, name)| {
                (
                    (*name).to_string(),
                    serde_json::json!(rows[*phase as usize]),
                )
            })
            .collect::<serde_json::Map<_, _>>()
    };
    let total_ns = duration_ns(now.saturating_duration_since(profile.started));
    let measured_ns = measurements
        .main
        .iter()
        .fold(0_u64, |sum, row| sum.saturating_add(row.exclusive_ns));
    serde_json::json!({
        "schema_version": 1,
        "clock": "monotonic_wall",
        "scope": "hook",
        "total_ns": total_ns,
        "uninstrumented_ns": total_ns.saturating_sub(measured_ns),
        "phases": rows_json(&measurements.main),
        "worker_phases": rows_json(&measurements.workers),
    })
}

/// Flush hook diagnostics before `process::exit`, which skips RAII drops.
///
/// Calling this twice is harmless. Open main-thread phases end at this point;
/// a detached worker may still have `calls > completed_calls`. Worker elapsed
/// times include only completed calls, so an unfinished analysis is visible
/// instead of being represented as a completed zero-cost phase.
pub fn finish_hook_profile() {
    let Some(mut profile) = THREAD_PROFILE.with(|slot| slot.borrow_mut().take()) else {
        return;
    };
    let now = Instant::now();
    profile.end_open_phases(now);
    let report = profile_json(&profile, now);
    // A broken diagnostics pipe must never panic or change the wire decision.
    let _ = writeln!(std::io::stderr().lock(), "DCG_PROFILE {report}");
}

/// Opt-in, command-free phase measurements for `DCG_LOG=dcg_perf=debug`.
///
/// Durations are inclusive wall time, so nested phases must not be summed.
/// Disabled measurements do not read the clock. Storage runs on a separate
/// thread; its timings can overlap evaluation and the shutdown wait. These
/// tracing events are independent of the optional [`HookProfile`] report.
pub struct PhaseTimer {
    phase: &'static str,
    started: Option<Instant>,
}

impl PhaseTimer {
    /// Start a measurement only when the dedicated tracing target is enabled.
    #[must_use]
    pub fn start(phase: &'static str) -> Self {
        Self {
            phase,
            started: tracing::enabled!(target: "dcg_perf", tracing::Level::DEBUG)
                .then(Instant::now),
        }
    }
}

impl Drop for PhaseTimer {
    fn drop(&mut self) {
        if let Some(started) = self.started {
            tracing::debug!(target: "dcg_perf", phase = self.phase,
                elapsed_us = started.elapsed().as_micros(), "hook phase");
        }
    }
}

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
        let exceeded = self.start.elapsed() >= self.max_duration;
        if exceeded {
            note_deadline_exhausted();
        }
        exceeded
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
        let remaining =
            (elapsed < self.max_duration).then(|| self.max_duration.saturating_sub(elapsed));
        if remaining.is_none() {
            note_deadline_exhausted();
        }
        remaining
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

    fn test_thread_profile(shared: Arc<Mutex<ProfileMeasurements>>, worker: bool) -> ThreadProfile {
        ThreadProfile {
            shared,
            started: Instant::now(),
            worker,
            stack: Vec::new(),
        }
    }

    #[test]
    fn budget_exhaustion_names_the_innermost_open_phase_issue_571() {
        // Each test runs on its own thread, so these thread-locals start clean.
        assert_eq!(take_budget_exhaustion(), BudgetExhaustion::default());
        {
            let _evaluation = phase(ProfilePhase::Evaluation);
            {
                let _rules = phase(ProfilePhase::PatternRules);
                let _compile = phase(ProfilePhase::RegexCompile);
                assert!(Deadline::new(Duration::ZERO).is_exceeded());
            }
            // Later observations do not replace the first one.
            assert!(Deadline::new(Duration::ZERO).remaining().is_none());
            note_incomplete_analysis("interpreter_literal_recovery");
            note_incomplete_analysis("match");
            assert_eq!(
                CURRENT_PHASE.with(Cell::get),
                Some(ProfilePhase::Evaluation)
            );
        }
        assert_eq!(CURRENT_PHASE.with(Cell::get), None);
        assert_eq!(
            take_budget_exhaustion(),
            BudgetExhaustion {
                deadline: Some(Some(ProfilePhase::RegexCompile)),
                incomplete: Some((
                    "interpreter_literal_recovery",
                    Some(ProfilePhase::Evaluation)
                )),
            }
        );
        // Taking clears; an expiry outside every phase is still recorded.
        assert_eq!(take_budget_exhaustion(), BudgetExhaustion::default());
        assert!(Deadline::new(Duration::ZERO).is_exceeded());
        assert_eq!(
            take_budget_exhaustion(),
            BudgetExhaustion {
                deadline: Some(None),
                incomplete: None,
            }
        );
        // A deadline that has not passed records nothing.
        assert!(!Deadline::new(Duration::from_secs(3600)).is_exceeded());
        assert!(
            Deadline::new(Duration::from_secs(3600))
                .remaining()
                .is_some()
        );
        assert_eq!(take_budget_exhaustion(), BudgetExhaustion::default());
        assert_eq!(phase_name(ProfilePhase::RegexCompile), "regex_compile");
        assert_eq!(phase_name(ProfilePhase::HistoryFlush), "history_flush");
    }

    #[test]
    fn process_cpu_time_is_reported_on_unix_issue_571() {
        let cpu = process_cpu_time();
        #[cfg(unix)]
        {
            // Burn a little CPU so a coarse clock cannot read zero.
            let started = Instant::now();
            let mut x = 0_u64;
            while started.elapsed() < Duration::from_millis(20) {
                x = std::hint::black_box(x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1));
            }
            let later = process_cpu_time().expect("getrusage succeeds");
            assert!(later > cpu.expect("getrusage succeeds"));
        }
        #[cfg(not(unix))]
        assert!(cpu.is_none());
    }

    #[test]
    fn disabled_profile_has_no_collector_or_worker_context() {
        let _profile = HookProfile::start(false);
        let guard = phase(ProfilePhase::Evaluation);
        assert!(guard.active.is_none());
        let context = capture_profile();
        assert!(context.shared.is_none());
        let worker = context.enter();
        assert!(matches!(worker.previous, PreviousProfile::Inactive));
        assert!(THREAD_PROFILE.with(|slot| slot.borrow().is_none()));
    }

    #[test]
    fn profile_exclusive_time_counts_nested_and_recursive_work_once() {
        let shared = Arc::new(Mutex::new(ProfileMeasurements::default()));
        let mut profile = test_thread_profile(shared, false);
        let start = profile.started;
        profile.begin(ProfilePhase::Evaluation, start);
        profile.begin(
            ProfilePhase::HeredocExtract,
            start + Duration::from_micros(2),
        );
        profile.end(start + Duration::from_micros(7));
        profile.begin(ProfilePhase::Evaluation, start + Duration::from_micros(8));
        profile.end(start + Duration::from_micros(10));
        profile.end(start + Duration::from_micros(20));

        let report = profile_json(&profile, start + Duration::from_micros(25));
        assert_eq!(report["total_ns"], 25_000);
        assert_eq!(report["uninstrumented_ns"], 5_000);
        let evaluation = &report["phases"]["evaluation"];
        assert_eq!(evaluation["calls"], 2);
        assert_eq!(evaluation["completed_calls"], 2);
        assert_eq!(evaluation["elapsed_ns"], 22_000);
        assert_eq!(evaluation["exclusive_ns"], 15_000);
        assert_eq!(report["phases"]["heredoc_extract"]["exclusive_ns"], 5_000);
        assert_eq!(report["phases"]["history_flush"]["calls"], 0);
    }

    #[test]
    fn profile_explicit_exit_finishes_open_main_phases() {
        let mut profile =
            test_thread_profile(Arc::new(Mutex::new(ProfileMeasurements::default())), false);
        let start = profile.started;
        profile.begin(ProfilePhase::RequestSetup, start);
        profile.begin(ProfilePhase::RequestParse, start + Duration::from_micros(3));
        profile.end_open_phases(start + Duration::from_micros(10));
        let report = profile_json(&profile, start + Duration::from_micros(10));
        assert!(profile.stack.is_empty());
        assert_eq!(report["phases"]["request_setup"]["exclusive_ns"], 3_000);
        assert_eq!(report["phases"]["request_parse"]["exclusive_ns"], 7_000);
        assert_eq!(report["phases"]["request_parse"]["completed_calls"], 1);
        assert_eq!(report["uninstrumented_ns"], 0);
    }

    #[test]
    fn profile_worker_time_is_separate_and_incomplete_work_is_visible() {
        let shared = Arc::new(Mutex::new(ProfileMeasurements::default()));
        let mut profile = test_thread_profile(Arc::clone(&shared), false);
        let mut worker = test_thread_profile(shared, true);
        let start = profile.started;
        profile.begin(ProfilePhase::AstMatch, start);
        worker.begin(ProfilePhase::AstParse, start + Duration::from_micros(2));
        profile.end(start + Duration::from_micros(10));

        let incomplete = profile_json(&profile, start + Duration::from_micros(10));
        assert_eq!(incomplete["worker_phases"]["ast_parse"]["calls"], 1);
        assert_eq!(
            incomplete["worker_phases"]["ast_parse"]["completed_calls"],
            0
        );
        assert_eq!(incomplete["worker_phases"]["ast_parse"]["elapsed_ns"], 0);
        worker.end(start + Duration::from_micros(12));

        let complete = profile_json(&profile, start + Duration::from_micros(15));
        assert_eq!(complete["phases"]["ast_match"]["exclusive_ns"], 10_000);
        assert_eq!(complete["worker_phases"]["ast_parse"]["elapsed_ns"], 10_000);
        assert_eq!(complete["uninstrumented_ns"], 5_000);
    }

    #[test]
    fn captured_profile_collects_on_worker_without_contaminating_main() {
        let _profile = HookProfile::start(true);
        let main_phase = phase(ProfilePhase::Evaluation);
        let context = capture_profile();
        std::thread::spawn(move || {
            let worker = context.enter();
            assert!(matches!(worker.previous, PreviousProfile::NoContext));
            let _phase = phase(ProfilePhase::AstParse);
        })
        .join()
        .expect("profiled worker completes");
        drop(main_phase);
        let profile = THREAD_PROFILE.with(|slot| slot.borrow_mut().take().unwrap());
        let report = profile_json(&profile, Instant::now());
        assert_eq!(report["phases"]["evaluation"]["completed_calls"], 1);
        assert_eq!(report["phases"]["ast_parse"]["calls"], 0);
        assert_eq!(report["worker_phases"]["ast_parse"]["completed_calls"], 1);
        assert!(THREAD_PROFILE.with(|slot| slot.borrow().is_none()));
    }

    #[test]
    fn nested_worker_context_restores_main_and_inactive_context_does_not_replace_it() {
        let inactive = capture_profile();
        let _profile = HookProfile::start(true);
        let main_phase = phase(ProfilePhase::Evaluation);
        {
            let worker = inactive.enter();
            assert!(matches!(worker.previous, PreviousProfile::Inactive));
            assert!(THREAD_PROFILE.with(|slot| !slot.borrow().as_ref().unwrap().worker));
        }
        {
            let worker = capture_profile().enter();
            assert!(matches!(worker.previous, PreviousProfile::Context(_)));
            let _phase = phase(ProfilePhase::AstParse);
        }
        assert!(THREAD_PROFILE.with(|slot| !slot.borrow().as_ref().unwrap().worker));
        drop(main_phase);
        let profile = THREAD_PROFILE.with(|slot| slot.borrow_mut().take().unwrap());
        let report = profile_json(&profile, Instant::now());
        assert_eq!(report["phases"]["evaluation"]["completed_calls"], 1);
        assert_eq!(report["phases"]["ast_parse"]["calls"], 0);
        assert_eq!(report["worker_phases"]["ast_parse"]["completed_calls"], 1);
    }

    #[test]
    fn profile_accounts_for_failed_request_parsing() {
        let _profile = HookProfile::start(true);
        assert!(crate::hook::parse_hook_input("{").is_err());
        let profile = THREAD_PROFILE.with(|slot| slot.borrow_mut().take().unwrap());
        let report = profile_json(&profile, Instant::now());
        assert_eq!(report["phases"]["request_parse"]["completed_calls"], 1);
        assert_eq!(report["phases"]["evaluation"]["calls"], 0);
        assert_eq!(report["schema_version"], 1);
        assert_eq!(report["clock"], "monotonic_wall");
    }

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
        for required_dsr_binding in [
            "DSR_RELEASE_GIT_SHA",
            "DSR_RELEASE_GIT_REF",
            "DCG_DSR_GIT_SHA",
            "DCG_DSR_GIT_DESCRIBE",
        ] {
            assert!(
                build_script.contains(required_dsr_binding),
                "build.rs must bridge strict DSR source identity through {required_dsr_binding}"
            );
        }
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

    /// #351/#353: the release fleet gate must fail if the tag-pinned installer
    /// or archive is unverified, or if any probe silently skips verification.
    #[test]
    fn fleet_install_gate_requires_installer_checksums_and_minisign_on_every_platform() {
        let fleet = include_str!("../scripts/e2e_fleet_install.sh");
        let unix_probe = fleet
            .split("unix_probe() {")
            .nth(1)
            .and_then(|rest| rest.split("windows_probe() {").next())
            .expect("fleet gate must retain its Unix probe");
        let windows_probe = fleet
            .split("windows_probe() {")
            .nth(1)
            .and_then(|rest| rest.split("EXPECTED_CASES=(").next())
            .expect("fleet gate must retain its Windows probe");
        let expected_cases = fleet
            .split("EXPECTED_CASES=(")
            .nth(1)
            .and_then(|rest| rest.split(')').next())
            .expect("fleet gate must retain its probe completeness contract");

        assert!(
            unix_probe.contains("--require-minisign --verify --no-configure"),
            "Unix fleet installs must require a valid minisign signature"
        );
        assert!(
            windows_probe.contains("-RequireMinisign -Verify -NoConfigure"),
            "Windows fleet installs must require a valid minisign signature"
        );
        // #638: the installer is the selected release's own asset, checked
        // against that release's checksum and Minisign signature before it runs.
        assert!(
            unix_probe.contains("\"$REPO_RELEASE/$VERSION/install.sh\"")
                && unix_probe.contains("\"$REPO_RELEASE/$VERSION/install.sh.sha256\"")
                && unix_probe.contains("\"$REPO_RELEASE/$VERSION/install.sh.minisig\"")
                && windows_probe.contains("\"$RepoRelease/$Version/install.ps1\"")
                && windows_probe.contains("\"$RepoRelease/$Version/install.ps1.sha256\"")
                && windows_probe.contains("\"$RepoRelease/$Version/install.ps1.minisig\""),
            "fleet installs must verify the exact tag-pinned installer before execution"
        );
        assert!(
            !unix_probe.contains("REPO_RAW") && !windows_probe.contains("RepoRaw"),
            "fleet installs must not fetch the installer outside the signed release assets"
        );
        assert!(
            expected_cases.contains("installer_checksum_verified")
                && expected_cases.contains("installer_signature_verified"),
            "a truncated probe must not pass without reporting installer verification"
        );
        assert!(
            expected_cases.contains("minisign_verified"),
            "a truncated probe must not pass without reporting signature verification"
        );
        assert!(
            expected_cases.contains("provenance_match")
                && unix_probe.contains("EMBEDDED_DESCRIBE")
                && windows_probe.contains("$embeddedDescribe -ceq $Version"),
            "fleet probes must require exact clean-tag provenance, not semver alone"
        );
        assert!(
            unix_probe.contains("Signature verified (minisign key ")
                && windows_probe.contains("Signature verified \\(minisign key "),
            "fleet probes must certify minisign verification specifically, not a different signature mechanism"
        );
        assert!(
            !unix_probe.contains("RESULT:minisign_verified:SKIP")
                && !windows_probe.contains("Emit 'minisign_verified' 'SKIP'"),
            "release probes must fail rather than skip missing signature evidence"
        );
    }

    /// #344: reject bad embedded provenance before an archive reaches the
    /// release job. The public fleet probe is intentionally a second,
    /// post-publication boundary; it must not be the first place a dirty,
    /// ahead, or placeholder describe is discovered.
    #[test]
    fn dist_gate_checks_exact_embedded_tag_before_packaging() {
        let dist = include_str!("../.github/workflows/dist.yml");

        let build_job = dist
            .split("  build:")
            .nth(1)
            .and_then(|rest| rest.split("\n  release:").next())
            .expect("distribution workflow must retain its build job");
        assert!(
            build_job.contains("fetch-depth: 0"),
            "release builders need full tag history for trustworthy git describe metadata"
        );
        assert!(
            build_job.contains("Verify embedded release tag (Unix)")
                && build_job.contains("embedded_describe")
                && build_job.contains("$GITHUB_REF_NAME"),
            "every runnable Unix artifact must report the exact release tag before packaging"
        );
        assert!(
            build_job.contains("$embeddedDescribe -cne $env:GITHUB_REF_NAME"),
            "the native Windows artifact must report the exact release tag before packaging"
        );
        assert!(
            build_job.contains("Verify embedded release tag (Windows ARM64 cross-build)")
                && build_job.contains("Find-ByteSequence")
                && build_job.contains("$tagWithSuffix"),
            "the non-runnable Windows ARM64 artifact must contain the tag and reject dirty/ahead suffixes"
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
