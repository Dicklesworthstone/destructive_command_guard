//! Dual regex engine abstraction for safe and fast pattern matching.
//!
//! The regex safety audit (git_safety_guard-99e.11) found:
//! - ~85% of pack patterns can use the linear-time `regex` crate
//! - ~15% require lookahead/lookbehind (needs `fancy_regex`)
//!
//! This module provides:
//! - [`CompiledRegex`]: Eagerly compiled abstraction that auto-selects engine
//! - [`LazyCompiledRegex`]: Lazily compiled regex using `CompiledRegex` (for pack patterns)
//!
//! The lazy variant avoids regex compilation during pack registry initialization,
//! improving startup latency for the common allow-path case.

use std::borrow::Cow;
use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::OnceLock;

use crate::perf::{DiagnosticId, RegexFailure, RegexFailureCause, RegexOperation};

#[derive(Default)]
struct EvaluationFailureState {
    failed: bool,
    // None after a non-regex proof fails first. A later regex failure must
    // not be attributed as the cause of that earlier incomplete analysis.
    first_regex_failure: Option<RegexFailure>,
}

/// Metadata attached to a rule, never to an ambient evaluation context.
/// Built-in and externally loaded packs use static IDs; direct Pack callers
/// can own their pack ID without leaking memory or borrowing command text.
#[derive(Debug)]
struct RegexRuleIdentity {
    pack_id: Cow<'static, str>,
    pattern_id: Option<&'static str>,
}

thread_local! {
    // Only active evaluator calls retain failures. A completed request cannot
    // poison the next request, and unrelated worker/diagnostic threads cannot
    // change a command's result.
    static EVALUATION_FAILURES: RefCell<Vec<EvaluationFailureState>> = const { RefCell::new(Vec::new()) };
}

/// Tracks incomplete regex work across nested evaluation and dialect views.
///
/// Successful matches retain their allocation-free path. Only an actual
/// engine failure touches this thread-local stack. The guard is thread-bound
/// because its lifetime and state belong to the evaluator that installed it.
pub(crate) struct RegexEvaluationScope {
    _thread_bound: PhantomData<Rc<()>>,
}

impl RegexEvaluationScope {
    pub(crate) fn enter() -> Self {
        EVALUATION_FAILURES
            .with(|stack| stack.borrow_mut().push(EvaluationFailureState::default()));
        Self {
            _thread_bound: PhantomData,
        }
    }

    pub(crate) fn has_failed(&self) -> bool {
        EVALUATION_FAILURES.with(|stack| stack.borrow().last().is_some_and(|state| state.failed))
    }

    /// The first failure, only if it was a regex operation. The returned
    /// record belongs to this request and survives after the scope ends.
    pub(crate) fn failure(&self) -> Option<RegexFailure> {
        EVALUATION_FAILURES.with(|stack| {
            stack
                .borrow()
                .last()
                .and_then(|state| state.first_regex_failure)
        })
    }
}

impl Drop for RegexEvaluationScope {
    fn drop(&mut self) {
        EVALUATION_FAILURES.with(|stack| {
            let mut stack = stack.borrow_mut();
            let child = stack.pop().unwrap_or_default();
            if let Some(parent) = stack.last_mut()
                && !parent.failed
            {
                *parent = child;
            }
        });
    }
}

/// Record that an optional embedded-source proof (the interpreter literal
/// recovery) could not complete for the active evaluation, under the same
/// contract as a failed regex: positive evidence may still deny, but no
/// would-be allow or downgrade can authorize the incomplete request.
///
/// Returns `false` when no evaluation scope is active on this thread; the
/// caller then has nobody to carry the record and must fail closed itself.
pub(crate) fn record_incomplete_analysis(
    stage: &'static str,
    error: &impl std::fmt::Display,
) -> bool {
    let recorded = EVALUATION_FAILURES.with(|stack| {
        stack.borrow_mut().last_mut().is_some_and(|state| {
            state.failed = true;
            true
        })
    });
    if recorded {
        crate::perf::note_incomplete_analysis(stage);
    }
    // Diagnostics contain no submitted command text.
    tracing::debug!(target: "dcg_perf", stage, error = %error, recorded, "analysis incomplete");
    recorded
}

fn record_evaluation_failure(
    operation: RegexOperation,
    cause: RegexFailureCause,
    identity: Option<&RegexRuleIdentity>,
) {
    // Copy only bounded identifier metadata, and only on the failure path.
    // Raw patterns and error strings can contain secrets even without input.
    let failure = RegexFailure {
        pack_id: identity.map(|id| DiagnosticId::new(&id.pack_id)),
        pattern_id: identity.and_then(|id| id.pattern_id.map(DiagnosticId::new)),
        operation,
        cause,
    };
    EVALUATION_FAILURES.with(|stack| {
        if let Some(state) = stack.borrow_mut().last_mut() {
            if !state.failed {
                state.first_regex_failure = Some(failure);
            }
            state.failed = true;
            crate::perf::note_regex_failure(failure);
        }
    });
    tracing::debug!(
        target: "dcg_perf",
        operation = operation.as_str(),
        pack_id = failure.pack_id.as_ref().map(DiagnosticId::as_str),
        pattern_id = failure.pattern_id.as_ref().map(DiagnosticId::as_str),
        cause = ?cause,
        failure = %failure,
        "regex analysis incomplete"
    );
}

fn record_runtime_failure(
    operation: RegexOperation,
    error: &fancy_regex::Error,
    backtrack_limit: usize,
    identity: Option<&RegexRuleIdentity>,
) {
    let cause = if matches!(
        error,
        fancy_regex::Error::RuntimeError(fancy_regex::RuntimeError::BacktrackLimitExceeded)
    ) {
        RegexFailureCause::BacktrackLimit {
            steps: backtrack_limit,
        }
    } else {
        RegexFailureCause::RuntimeError
    };
    record_evaluation_failure(operation, cause, identity);
}

/// Maximum backtracking steps allowed per fancy_regex match.
///
/// The default `fancy_regex` limit is 1,000,000. We lower it to 100,000 to
/// bound worst-case evaluation time for pathological patterns (especially from
/// external packs). This is a work limit, not a wall-clock timeout: the cost
/// of a step depends on the expression, input, and host. When exceeded,
/// `fancy_regex` returns `BacktrackLimitExceeded` and our match methods
/// return `false`/`None`. Inside command evaluation an error also marks the
/// analysis incomplete, so those fallback values can never prove an allow.
pub const BACKTRACK_LIMIT: usize = 100_000;

/// Linear-time expression that cannot match at any byte position.
///
/// Older semantic-only pack metadata used the fancy-regex sentinel `(?!)`.
/// Canonicalizing that exact sentinel to `\b\B` preserves its impossible
/// matching semantics without selecting or initializing the backtracking
/// engine.
pub const NEVER_MATCH_PATTERN: &str = r"\b\B";
const LEGACY_NEVER_MATCH_PATTERN: &str = r"(?!)";

fn canonical_pattern(pattern: &str) -> &str {
    if pattern == LEGACY_NEVER_MATCH_PATTERN {
        NEVER_MATCH_PATTERN
    } else {
        pattern
    }
}

const fn canonical_static_pattern(pattern: &'static str) -> &'static str {
    let bytes = pattern.as_bytes();
    if bytes.len() == 4
        && bytes[0] == b'('
        && bytes[1] == b'?'
        && bytes[2] == b'!'
        && bytes[3] == b')'
    {
        NEVER_MATCH_PATTERN
    } else {
        pattern
    }
}

/// A compiled regex that auto-selects between linear-time and backtracking engines.
///
/// Use this instead of `fancy_regex::Regex` directly when the pattern may not
/// require backtracking features. The `regex` crate provides O(n) guarantees
/// but doesn't support lookahead/lookbehind.
///
/// # Example
///
/// ```ignore
/// use destructive_command_guard::packs::regex_engine::CompiledRegex;
///
/// // Auto-selects linear-time engine (no lookahead)
/// let simple = CompiledRegex::new(r"rm\s+-rf").unwrap();
/// assert!(!simple.uses_backtracking());
///
/// // Lookahead patterns should use backtracking engine
/// let lookahead = CompiledRegex::new(r"git\s+push(?=.*--force)").unwrap();
/// assert!(lookahead.uses_backtracking());
/// ```
#[derive(Debug)]
pub enum CompiledRegex {
    /// Linear-time regex (O(n) guaranteed, no backtracking).
    Linear(regex::Regex),
    /// Backtracking regex (supports lookahead/lookbehind), retaining its
    /// configured work limit so failures report the actual exhausted budget.
    Backtracking {
        /// Compiled backtracking expression.
        regex: fancy_regex::Regex,
        /// Per-pattern maximum backtracking steps supplied to the builder.
        backtrack_limit: usize,
    },
}

impl CompiledRegex {
    /// Compile a pattern, auto-selecting the appropriate engine.
    ///
    /// Uses linear-time `regex` crate unless the pattern contains features
    /// that require backtracking:
    /// - Lookahead: `(?=...)`, `(?!...)`
    /// - Lookbehind: `(?<=...)`, `(?<!...)`
    /// - Backreferences: `\1`, `\2`, etc.
    ///
    /// # Errors
    /// Returns an error if the pattern fails to compile.
    pub fn new(pattern: &str) -> Result<Self, String> {
        Self::new_with_backtrack_limit(pattern, BACKTRACK_LIMIT)
    }

    /// Compile a pattern with a specific backtrack limit for the fancy_regex engine.
    ///
    /// # Errors
    /// Returns an error if the pattern fails to compile.
    pub fn new_with_backtrack_limit(pattern: &str, limit: usize) -> Result<Self, String> {
        let _phase = crate::perf::phase(crate::perf::ProfilePhase::RegexCompile);
        let pattern = canonical_pattern(pattern);
        if needs_backtracking_engine(pattern) {
            fancy_regex::RegexBuilder::new(pattern)
                .backtrack_limit(limit)
                .build()
                .map(|regex| Self::Backtracking {
                    regex,
                    backtrack_limit: limit,
                })
                .map_err(|e| format!("fancy_regex compile error: {e}"))
        } else {
            match regex::Regex::new(pattern) {
                Ok(re) => Ok(Self::Linear(re)),
                Err(e) => {
                    // Fall back to backtracking engine if linear engine fails
                    // This handles any advanced features that needs_backtracking_engine() missed
                    fancy_regex::RegexBuilder::new(pattern)
                        .backtrack_limit(limit)
                        .build()
                        .map(|regex| Self::Backtracking {
                            regex,
                            backtrack_limit: limit,
                        })
                        .map_err(|fancy_err| {
                            format!(
                                "regex compile error: {e}, fancy_regex compile error: {fancy_err}"
                            )
                        })
                }
            }
        }
    }

    /// Compile a pattern using the linear-time engine only.
    ///
    /// # Errors
    /// Returns an error if the pattern uses features not supported by the
    /// linear-time engine (lookahead, lookbehind, backreferences).
    pub fn new_linear(pattern: &str) -> Result<Self, String> {
        let _phase = crate::perf::phase(crate::perf::ProfilePhase::RegexCompile);
        regex::Regex::new(pattern)
            .map(Self::Linear)
            .map_err(|e| format!("regex compile error: {e}"))
    }

    /// Compile a pattern using the backtracking engine.
    ///
    /// # Errors
    /// Returns an error if the pattern fails to compile.
    pub fn new_backtracking(pattern: &str) -> Result<Self, String> {
        let _phase = crate::perf::phase(crate::perf::ProfilePhase::RegexCompile);
        fancy_regex::RegexBuilder::new(pattern)
            .backtrack_limit(BACKTRACK_LIMIT)
            .build()
            .map(|regex| Self::Backtracking {
                regex,
                backtrack_limit: BACKTRACK_LIMIT,
            })
            .map_err(|e| format!("fancy_regex compile error: {e}"))
    }

    /// Check if the pattern matches the text.
    ///
    /// For backtracking engine, returns `false` on regex execution errors.
    #[must_use]
    pub fn is_match(&self, text: &str) -> bool {
        self.is_match_with_identity(text, None)
    }

    fn is_match_with_identity(&self, text: &str, identity: Option<&RegexRuleIdentity>) -> bool {
        let _phase = crate::perf::phase(crate::perf::ProfilePhase::RegexMatch);
        match self {
            Self::Linear(re) => re.is_match(text),
            Self::Backtracking {
                regex,
                backtrack_limit,
            } => regex.is_match(text).unwrap_or_else(|error| {
                record_runtime_failure(RegexOperation::Match, &error, *backtrack_limit, identity);
                false
            }),
        }
    }

    /// Find the first match in the text.
    ///
    /// Returns the start and end byte offsets of the match.
    #[must_use]
    pub fn find(&self, text: &str) -> Option<(usize, usize)> {
        self.find_with_identity(text, None)
    }

    fn find_with_identity(
        &self,
        text: &str,
        identity: Option<&RegexRuleIdentity>,
    ) -> Option<(usize, usize)> {
        let _phase = crate::perf::phase(crate::perf::ProfilePhase::RegexMatch);
        match self {
            Self::Linear(re) => re.find(text).map(|m| (m.start(), m.end())),
            Self::Backtracking {
                regex,
                backtrack_limit,
            } => regex
                .find(text)
                .unwrap_or_else(|error| {
                    record_runtime_failure(
                        RegexOperation::Find,
                        &error,
                        *backtrack_limit,
                        identity,
                    );
                    None
                })
                .map(|m| (m.start(), m.end())),
        }
    }

    /// Find the first match whose search begins at `start`.
    ///
    /// Unlike slicing `text`, this preserves anchors and look-behind context.
    /// Returns `None` when `start` is not a UTF-8 boundary, lies past the end
    /// of `text`, or regex execution fails.
    #[must_use]
    pub fn find_from(&self, text: &str, start: usize) -> Option<(usize, usize)> {
        self.find_from_with_identity(text, start, None)
    }

    fn find_from_with_identity(
        &self,
        text: &str,
        start: usize,
        identity: Option<&RegexRuleIdentity>,
    ) -> Option<(usize, usize)> {
        if start > text.len() || !text.is_char_boundary(start) {
            return None;
        }
        let _phase = crate::perf::phase(crate::perf::ProfilePhase::RegexMatch);
        match self {
            Self::Linear(re) => re.find_at(text, start).map(|m| (m.start(), m.end())),
            Self::Backtracking {
                regex,
                backtrack_limit,
            } => regex
                .find_from_pos(text, start)
                .unwrap_or_else(|error| {
                    record_runtime_failure(
                        RegexOperation::FindFrom,
                        &error,
                        *backtrack_limit,
                        identity,
                    );
                    None
                })
                .map(|m| (m.start(), m.end())),
        }
    }

    /// Get the pattern string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Linear(re) => re.as_str(),
            Self::Backtracking { regex, .. } => regex.as_str(),
        }
    }

    /// Check if this regex uses the backtracking engine.
    #[must_use]
    pub const fn uses_backtracking(&self) -> bool {
        matches!(self, Self::Backtracking { .. })
    }

    /// Replace up to `limit` matches with the replacement string.
    ///
    /// Returns a `Cow::Borrowed` if no replacements were made.
    /// For backtracking engine, falls back to original text on execution errors.
    #[must_use]
    pub fn replacen<'t>(&self, text: &'t str, limit: usize, rep: &str) -> Cow<'t, str> {
        let _phase = crate::perf::phase(crate::perf::ProfilePhase::RegexMatch);
        match self {
            Self::Linear(re) => re.replacen(text, limit, rep),
            // Use try_replacen to handle errors gracefully (returns Result)
            Self::Backtracking {
                regex,
                backtrack_limit,
            } => regex
                .try_replacen(text, limit, rep)
                .unwrap_or_else(|error| {
                    record_runtime_failure(RegexOperation::Replace, &error, *backtrack_limit, None);
                    Cow::Borrowed(text)
                }),
        }
    }
}

/// Check if a pattern requires the backtracking engine.
///
/// Returns `true` if the pattern contains features not supported by the
/// linear-time `regex` crate:
/// - Lookahead: `(?=...)`, `(?!...)`
/// - Lookbehind: `(?<=...)`, `(?<!...)`
/// - Backreferences: `\1`, `\2`, etc.
///
/// Note: This is a heuristic based on syntax. Some edge cases (like `\1` in a
/// character class or escaped in a string literal) may produce false positives,
/// but false positives are safe (just use the slower engine unnecessarily).
#[must_use]
pub fn needs_backtracking_engine(pattern: &str) -> bool {
    if pattern == LEGACY_NEVER_MATCH_PATTERN {
        return false;
    }
    // Lookahead: (?= positive, (?! negative
    // Lookbehind: (?<= positive, (?<! negative
    // Atomic groups: (?>
    if pattern.contains("(?=")
        || pattern.contains("(?!")
        || pattern.contains("(?<=")
        || pattern.contains("(?<!")
        || pattern.contains("(?>")
    {
        return true;
    }

    // Possessive quantifiers: *+, ++, ?+, {n,m}+
    // Note: This is a heuristic. + can also be a literal or part of character class.
    // However, *+, ++, ?+ are almost always possessive quantifiers in this context.
    if pattern.contains("*+")
        || pattern.contains("++")
        || pattern.contains("?+")
        || pattern.contains("}+")
    {
        return true;
    }

    // Backreferences: \1 through \9 (and \10+ for 10+ capture groups)
    // Check for \1-\9 which covers the vast majority of backreference usage
    let bytes = pattern.as_bytes();
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i] == b'\\' {
            let next = bytes[i + 1];
            // \1 through \9 are backreferences
            if next.is_ascii_digit() && next != b'0' {
                return true;
            }
        }
    }

    false
}

// ============================================================================
// Lazy Regex Primitive
// ============================================================================

/// A lazily-compiled regex pattern using `CompiledRegex`.
///
/// This primitive stores the pattern text and defers regex compilation until
/// first use. This is critical for pack registry performance: we can initialize
/// pack metadata (keywords, pattern names) without paying the compilation cost
/// for patterns that may never be evaluated (e.g., on the quick-reject allow path).
///
/// # Performance Characteristics
///
/// - **Construction**: O(1) - just stores the pattern string
/// - **First match**: O(pattern) - compiles the regex once
/// - **Subsequent matches**: Varies (backtracking engine may be super-linear)
///
/// # Thread Safety
///
/// Uses `OnceLock` for thread-safe lazy initialization. Multiple threads may
/// race to compile the pattern, but only one compilation occurs.
///
/// # Example
///
/// ```ignore
/// use destructive_command_guard::packs::regex_engine::LazyCompiledRegex;
///
/// // No compilation happens here
/// static PATTERN: LazyCompiledRegex = LazyCompiledRegex::new(r"git\s+reset\s+--hard");
///
/// // Compilation happens on first use
/// assert!(PATTERN.is_match("git reset --hard HEAD"));
/// ```
#[derive(Debug)]
pub struct LazyCompiledRegex {
    pattern: PatternText,
    compiled: OnceLock<Result<CompiledRegex, String>>,
    // Bind identity to this expression, not the surrounding evaluation. A
    // nested or auxiliary regex must never inherit another rule's metadata.
    rule_identity: OnceLock<RegexRuleIdentity>,
    // Opted-in static safe patterns can prove a miss before paying for their
    // backtracking VM. An unknown proof always retains the ordinary engine.
    anchored_prefix: Option<OnceLock<Option<Box<str>>>>,
    // Only rules needing a whole-command preview proof allocate this state.
    // Ordinary pack patterns retain their allocation-free constructors.
    exclusion: Option<Box<LinearFullMatchExclusion>>,
    // A backtracking pattern can name a linear regex that matches wherever
    // it does; input the superset misses never reaches the backtracking VM.
    superset: Option<Box<LinearSuperset>>,
}

/// Derive only a mandatory literal at the absolute beginning of the input.
/// This is regex syntax analysis, independent of shell quoting or command
/// names. The complete original regex still decides every possible match.
fn required_anchored_prefix(pattern: &str) -> Option<Box<str>> {
    const MAX_PATTERN_BYTES: usize = 8 * 1024;
    const MAX_NODES: usize = 4096;
    if pattern.len() > MAX_PATTERN_BYTES {
        return None;
    }

    let _phase = crate::perf::phase(crate::perf::ProfilePhase::RegexCompile);
    let tree = fancy_regex::Expr::parse_tree(pattern).ok()?;
    let mut remaining = MAX_NODES;
    if !supports_anchored_prefix_proof(&tree.expr, &mut remaining, 0) {
        return None;
    }
    let fancy_regex::Expr::Concat(parts) = &tree.expr else {
        return None;
    };
    let (fancy_regex::Expr::Assertion(fancy_regex::Assertion::StartText), tail) =
        parts.split_first()?
    else {
        return None;
    };

    let mut prefix = String::new();
    for part in tail {
        match part {
            fancy_regex::Expr::Literal { val, casei: false } => prefix.push_str(val),
            // Supported lookaheads restore the input position. Their nested
            // syntax was checked above, including every alternative, so a
            // control verb or other unusual construct cannot bypass a later
            // literal. Assertions and empty expressions consume no input.
            fancy_regex::Expr::LookAround(_, _)
            | fancy_regex::Expr::Assertion(_)
            | fancy_regex::Expr::Empty => {}
            _ => break,
        }
    }
    (!prefix.is_empty()).then(|| prefix.into_boxed_str())
}

/// Stay within ordinary regex syntax whose successful concatenation must
/// execute every term in order. This deliberately excludes control verbs,
/// keep-out, lookbehind, backreferences, subroutines, conditional expressions,
/// and unfamiliar nodes instead of attempting a proof of their semantics.
fn supports_anchored_prefix_proof(
    expression: &fancy_regex::Expr,
    remaining: &mut usize,
    depth: usize,
) -> bool {
    use fancy_regex::{Assertion, Expr, LookAround};

    if depth > 64 || *remaining == 0 {
        return false;
    }
    *remaining -= 1;
    match expression {
        Expr::Empty
        | Expr::Any { .. }
        | Expr::Literal { casei: false, .. }
        | Expr::Delegate { casei: false, .. }
        | Expr::Assertion(
            Assertion::StartText
            | Assertion::EndText
            | Assertion::WordBoundary
            | Assertion::NotWordBoundary,
        ) => true,
        Expr::Concat(children) | Expr::Alt(children) => children
            .iter()
            .all(|child| supports_anchored_prefix_proof(child, remaining, depth + 1)),
        Expr::Group(child) => supports_anchored_prefix_proof(child, remaining, depth + 1),
        Expr::Repeat { child, .. }
        | Expr::LookAround(child, LookAround::LookAhead | LookAround::LookAheadNeg) => {
            supports_anchored_prefix_proof(child, remaining, depth + 1)
        }
        _ => false,
    }
}

/// A positive, full-input proof that a destructive candidate is exempt.
/// Never fall back to fancy-regex here: failure to prove safety must retain
/// the candidate, not lose it to a negative lookahead's backtracking limit.
#[derive(Debug)]
struct LinearFullMatchExclusion {
    pattern: &'static str,
    compiled: OnceLock<Result<regex::Regex, regex::Error>>,
}

impl LinearFullMatchExclusion {
    fn is_match(&self, haystack: &str) -> bool {
        let compiled = self.compiled.get_or_init(|| {
            let _phase = crate::perf::phase(crate::perf::ProfilePhase::RegexCompile);
            regex::Regex::new(&format!(r"\A(?:{})\z", self.pattern))
        });
        let _phase = crate::perf::phase(crate::perf::ProfilePhase::RegexMatch);
        compiled
            .as_ref()
            .is_ok_and(|regex| regex.is_match(haystack))
    }
}

#[derive(Debug)]
struct LinearSuperset {
    pattern: &'static str,
    compiled: OnceLock<Result<regex::Regex, regex::Error>>,
}

impl LinearSuperset {
    /// Whether the candidate pattern can match anywhere in `haystack`. A
    /// superset that does not compile proves nothing, so it answers yes.
    fn may_match(&self, haystack: &str) -> bool {
        let compiled = self.compiled.get_or_init(|| {
            let _phase = crate::perf::phase(crate::perf::ProfilePhase::RegexCompile);
            regex::Regex::new(self.pattern)
        });
        let _phase = crate::perf::phase(crate::perf::ProfilePhase::RegexMatch);
        compiled
            .as_ref()
            .map_or(true, |regex| regex.is_match(haystack))
    }
}

#[derive(Debug)]
enum PatternText {
    Static(&'static str),
    Owned(String),
}

impl PatternText {
    fn as_str(&self) -> &str {
        match self {
            Self::Static(pattern) => pattern,
            Self::Owned(pattern) => pattern.as_str(),
        }
    }
}

impl LazyCompiledRegex {
    /// Create a new lazy regex pattern from a static string.
    ///
    /// This is a `const fn` and performs no regex compilation.
    /// The pattern will be compiled on first use.
    #[must_use]
    pub const fn new(pattern: &'static str) -> Self {
        Self {
            pattern: PatternText::Static(canonical_static_pattern(pattern)),
            compiled: OnceLock::new(),
            rule_identity: OnceLock::new(),
            anchored_prefix: None,
            exclusion: None,
            superset: None,
        }
    }

    /// Create a new lazy regex pattern from an owned string.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new_owned(pattern: String) -> Self {
        let pattern = if pattern == LEGACY_NEVER_MATCH_PATTERN {
            PatternText::Static(NEVER_MATCH_PATTERN)
        } else {
            PatternText::Owned(pattern)
        };
        Self {
            pattern,
            compiled: OnceLock::new(),
            rule_identity: OnceLock::new(),
            anchored_prefix: None,
            exclusion: None,
            superset: None,
        }
    }

    /// Attach static rule metadata when constructing a built-in or external pack.
    /// This does not compile the regex or allocate on its matching path.
    #[must_use]
    pub(crate) fn with_rule_identity(
        self,
        pack_id: &'static str,
        pattern_id: Option<&'static str>,
    ) -> Self {
        self.set_static_rule_identity(pack_id, pattern_id);
        self
    }

    /// Bind an unbound rule while initializing a lazily built registry pack.
    pub(crate) fn set_static_rule_identity(
        &self,
        pack_id: &'static str,
        pattern_id: Option<&'static str>,
    ) {
        self.rule_identity.get_or_init(|| RegexRuleIdentity {
            pack_id: Cow::Borrowed(pack_id),
            pattern_id,
        });
    }

    /// Bind direct `Pack` callers without leaking their dynamically owned IDs.
    /// Registry and external rules are already bound, so they do not clone.
    pub(crate) fn set_rule_identity(&self, pack_id: &str, pattern_id: Option<&'static str>) {
        self.rule_identity.get_or_init(|| RegexRuleIdentity {
            pack_id: Cow::Owned(DiagnosticId::new(pack_id).to_string()),
            pattern_id,
        });
    }

    /// Opt a statically authored safe pattern into a necessary-prefix proof.
    /// Dynamic patterns and the public constructors keep their existing lazy
    /// compile/error behavior. Only a successful, narrowly supported AST
    /// proof may avoid compilation; uncertainty uses the original regex.
    pub(crate) fn enable_anchored_prefix_filter(&mut self) {
        if matches!(&self.pattern, PatternText::Static(_))
            && self.as_str().starts_with('^')
            && needs_backtracking_engine(self.as_str())
        {
            self.anchored_prefix = Some(OnceLock::new());
        }
    }

    fn prefix_may_match(&self, haystack: &str) -> bool {
        self.anchored_prefix.as_ref().is_none_or(|prefix| {
            prefix
                .get_or_init(|| required_anchored_prefix(self.as_str()))
                .as_deref()
                .is_none_or(|required| haystack.starts_with(required))
        })
    }

    /// Attach a positive exemption proof to a destructive pattern (#435).
    ///
    /// The proof must match the ENTIRE input, even when [`Self::find_from`]
    /// begins searching at a later offset. It is compiled only by the linear
    /// engine. Invalid or unsupported proofs do not suppress any match.
    ///
    /// Use only on destructive patterns, not safe-pattern RegexSet entries.
    /// Keep argument boundaries in the supplied input: this cannot recover
    /// information already erased by a caller's normalization.
    #[must_use]
    pub(crate) fn excluding_full_match(mut self, proof: &'static str) -> Self {
        self.exclusion = Some(Box::new(LinearFullMatchExclusion {
            pattern: proof,
            compiled: OnceLock::new(),
        }));
        self
    }

    /// Attach a linear superset to a backtracking pattern (bd-nxn1).
    ///
    /// `superset` is compiled by the linear engine and must match somewhere
    /// in every input in which this pattern matches. The pattern itself with
    /// its lookarounds and atomic groups removed and each back-reference
    /// replaced by its group's pattern is one. Input the superset misses
    /// cannot match, so the backtracking search, and the work limit that
    /// leaves a long input unverified, never runs on it. A superset that
    /// does not compile proves nothing, and the pattern runs as authored.
    #[must_use]
    pub(crate) fn requiring_linear_superset(mut self, superset: &'static str) -> Self {
        self.superset = Some(Box::new(LinearSuperset {
            pattern: superset,
            compiled: OnceLock::new(),
        }));
        self
    }

    /// Whether the cheap proofs leave room for a match: the anchored prefix
    /// and the linear superset, each where one was opted into.
    fn may_match(&self, haystack: &str) -> bool {
        self.prefix_may_match(haystack)
            && self
                .superset
                .as_ref()
                .is_none_or(|superset| superset.may_match(haystack))
    }

    /// The additional full-input exemption proof, if one was authored.
    ///
    /// [`Self::as_str`] describes the candidate regex only. Recompiling that
    /// string alone does not reproduce the exemption semantics; matching
    /// callers should use this object's `is_match`, `find`, or `find_from`.
    #[must_use]
    pub fn full_match_exclusion(&self) -> Option<&'static str> {
        self.exclusion.as_ref().map(|proof| proof.pattern)
    }

    fn is_excluded(&self, haystack: &str) -> bool {
        self.exclusion
            .as_ref()
            .is_some_and(|proof| proof.is_match(haystack))
    }

    /// Get or compile the regex.
    ///
    /// Returns `None` if compilation fails and marks active evaluation incomplete.
    fn get_compiled(&self) -> Option<&CompiledRegex> {
        match self
            .compiled
            .get_or_init(|| CompiledRegex::new(self.pattern.as_str()))
            .as_ref()
        {
            Ok(compiled) => Some(compiled),
            Err(_) => {
                let _phase = crate::perf::phase(crate::perf::ProfilePhase::RegexCompile);
                record_evaluation_failure(
                    RegexOperation::Compile,
                    RegexFailureCause::CompileError,
                    self.rule_identity.get(),
                );
                None
            }
        }
    }

    /// Check if the pattern matches the text and is not fully exempted.
    ///
    /// On first call, this compiles the regex. Subsequent calls reuse the
    /// compiled pattern. Exemption compilation is deferred until a candidate
    /// matches, and a failed exemption proof never suppresses that candidate.
    ///
    /// Returns `false` on candidate regex execution or compile errors.
    #[must_use]
    pub fn is_match(&self, haystack: &str) -> bool {
        self.may_match(haystack)
            && self.get_compiled().is_some_and(|compiled| {
                compiled.is_match_with_identity(haystack, self.rule_identity.get())
            })
            && !self.is_excluded(haystack)
    }

    /// Find the span (start, end) of the first non-exempted match.
    ///
    /// Returns `None` if no match or on candidate execution/compile error.
    #[must_use]
    pub fn find(&self, haystack: &str) -> Option<(usize, usize)> {
        if !self.may_match(haystack) {
            return None;
        }
        let span = self
            .get_compiled()?
            .find_with_identity(haystack, self.rule_identity.get())?;
        (!self.is_excluded(haystack)).then_some(span)
    }

    /// Find the first non-exempted match whose search begins at `start`.
    ///
    /// Both anchors and the exemption proof retain whole-input scope.
    /// Returns `None` if no match exists or on candidate execution/compile error.
    #[must_use]
    pub fn find_from(&self, haystack: &str, start: usize) -> Option<(usize, usize)> {
        if !self.may_match(haystack) {
            return None;
        }
        let span = self.get_compiled()?.find_from_with_identity(
            haystack,
            start,
            self.rule_identity.get(),
        )?;
        (!self.is_excluded(haystack)).then_some(span)
    }

    /// Get the candidate pattern string, without any full-input exclusion.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.pattern.as_str()
    }

    /// Check if the candidate regex has been compiled.
    ///
    /// Useful for testing to verify lazy compilation behavior.
    #[must_use]
    pub fn is_compiled(&self) -> bool {
        matches!(self.compiled.get(), Some(Ok(_)))
    }
}

impl std::fmt::Display for LazyCompiledRegex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regex_errors_are_distinct_from_proven_misses_during_evaluation() {
        let pattern = r"^(a|aa)+\1$";
        let input = format!("{}!", "a".repeat(80));
        let compiled = CompiledRegex::new_with_backtrack_limit(pattern, 100).unwrap();
        let CompiledRegex::Backtracking { regex: raw, .. } = &compiled else {
            panic!("regression must exercise the bounded VM");
        };
        assert!(
            raw.is_match(&input).is_err(),
            "fixture must exhaust real engine work"
        );
        for (case, operation) in [
            RegexOperation::Match,
            RegexOperation::Find,
            RegexOperation::FindFrom,
            RegexOperation::Replace,
        ]
        .into_iter()
        .enumerate()
        {
            let scope = RegexEvaluationScope::enter();
            match case {
                0 => {
                    assert!(!compiled.is_match(&input));
                }
                1 => {
                    assert!(compiled.find(&input).is_none());
                }
                2 => {
                    assert!(compiled.find_from(&input, 0).is_none());
                }
                _ => {
                    assert_eq!(compiled.replacen(&input, 1, "x"), input);
                }
            }
            assert!(
                scope.has_failed(),
                "operation {operation:?} must retain the failure"
            );
            assert_eq!(
                scope.failure(),
                Some(RegexFailure {
                    pack_id: None,
                    pattern_id: None,
                    operation,
                    cause: RegexFailureCause::BacktrackLimit { steps: 100 },
                }),
                "anonymous regexes report their actual limit without an invented rule ID"
            );
        }
        let scope = RegexEvaluationScope::enter();
        assert!(!compiled.is_match("b"));
        assert!(
            !scope.has_failed(),
            "a real miss must not become indeterminate"
        );
        assert!(scope.failure().is_none());
    }

    #[test]
    fn regex_failure_scope_propagates_only_within_its_request_and_thread() {
        let re = CompiledRegex::new_with_backtrack_limit(r"^(a|aa)+\1$", 100).unwrap();
        let input = format!("{}!", "a".repeat(80));
        {
            let parent = RegexEvaluationScope::enter();
            {
                let child = RegexEvaluationScope::enter();
                assert!(re.find_from(&input, 0).is_none());
                assert!(child.has_failed());
                assert_eq!(child.failure().unwrap().operation, RegexOperation::FindFrom);
            }
            assert!(
                parent.has_failed(),
                "nested incomplete analysis reaches its parent"
            );
            assert_eq!(
                parent.failure().unwrap().operation,
                RegexOperation::FindFrom
            );
        }
        let next = RegexEvaluationScope::enter();
        assert!(
            !next.has_failed(),
            "completed request must not poison the next one"
        );
        assert!(next.failure().is_none());
        std::thread::spawn(move || {
            let worker = RegexEvaluationScope::enter();
            assert!(!re.is_match(&input));
            assert!(worker.has_failed());
            assert_eq!(worker.failure().unwrap().operation, RegexOperation::Match);
        })
        .join()
        .unwrap();
        assert!(
            !next.has_failed(),
            "independent threads must not share failure state"
        );
        assert!(next.failure().is_none());
    }

    #[test]
    fn lazy_compile_errors_also_leave_evaluation_incomplete() {
        let invalid = LazyCompiledRegex::new("[");
        let scope = RegexEvaluationScope::enter();
        assert!(invalid.find("ordinary").is_none());
        assert!(scope.has_failed());
        assert_eq!(
            scope.failure(),
            Some(RegexFailure {
                pack_id: None,
                pattern_id: None,
                operation: RegexOperation::Compile,
                cause: RegexFailureCause::CompileError,
            })
        );
        assert!(!invalid.is_compiled());
    }

    #[test]
    fn first_rule_failure_survives_nesting_without_poisoning_other_rules_issue_643() {
        let first = LazyCompiledRegex::new(r"^(a|aa)+\1$")
            .with_rule_identity("test.first", Some("first-rule"));
        let second = LazyCompiledRegex::new(r"^(a|aa)+\1$")
            .with_rule_identity("test.second", Some("second-rule"));
        let input = format!("{}!", "a".repeat(80));
        {
            let outer = RegexEvaluationScope::enter();
            assert!(!first.is_match(&input));
            let original = outer.failure().unwrap();
            assert_eq!(original.pack_id.unwrap().as_str(), "test.first");
            assert_eq!(original.pattern_id.unwrap().as_str(), "first-rule");
            {
                let inner = RegexEvaluationScope::enter();
                assert!(second.find_from(&input, 0).is_none());
                let failure = inner.failure().unwrap();
                assert_eq!(failure.pack_id.unwrap().as_str(), "test.second");
                assert_eq!(failure.pattern_id.unwrap().as_str(), "second-rule");
                assert_eq!(failure.operation, RegexOperation::FindFrom);
            }
            assert_eq!(outer.failure(), Some(original));
            {
                let inner = RegexEvaluationScope::enter();
                assert!(second.is_match("aaaa"));
                assert!(!second.is_match("b"));
                assert!(!inner.has_failed());
                assert!(inner.failure().is_none());
            }
            assert_eq!(outer.failure(), Some(original));
        }
        let independent = RegexEvaluationScope::enter();
        assert!(independent.failure().is_none());
        assert!(second.find(&input).is_none());
        let failure = independent.failure().unwrap();
        assert_eq!(failure.pack_id.unwrap().as_str(), "test.second");
        assert_eq!(failure.operation, RegexOperation::Find);
    }

    #[test]
    fn contributor_lookahead_reports_its_controlled_work_limit_issue_643() {
        // This is the exact expression supplied in #643, with a synthetic
        // command of the documented shape. fancy-regex 0.20 delegates the
        // lookahead bodies, including the word boundary, to regex-automata.
        // This controlled 100-step limit exercises repeated start-position
        // searches; it does not claim to reproduce the reporter's missing
        // exact command at the production 100,000-step limit.
        const PATTERN: &str = r"(?=[\s\S]*(?:^|[\n;&|]\s*)[A-Z]=/data/tmp/x/)(?=[\s\S]*(?:^|[\s;|&])\s*\bIFS\+?=)[\s\S]*";
        let unanchored = CompiledRegex::new_with_backtrack_limit(PATTERN, 100).unwrap();
        let anchored =
            CompiledRegex::new_with_backtrack_limit(&format!(r"\A{PATTERN}"), 100).unwrap();
        let identity = RegexRuleIdentity {
            pack_id: Cow::Borrowed("test.slow_lookahead"),
            pattern_id: Some("slow"),
        };
        let command = format!("scratch {};A=/data/tmp/x/repro", "q".repeat(4_096));
        {
            let scope = RegexEvaluationScope::enter();
            assert!(
                unanchored
                    .find_from_with_identity(&command, 0, Some(&identity))
                    .is_none()
            );
            assert!(
                scope.has_failed(),
                "retries must exhaust the explicit work limit"
            );
            assert_eq!(
                scope.failure(),
                Some(RegexFailure {
                    pack_id: Some(DiagnosticId::new("test.slow_lookahead")),
                    pattern_id: Some(DiagnosticId::new("slow")),
                    operation: RegexOperation::FindFrom,
                    cause: RegexFailureCause::BacktrackLimit { steps: 100 },
                })
            );
        }

        // A fresh scope does not inherit the exhausted rule. Anchoring
        // avoids retrying every position, so the same miss is now complete.
        let scope = RegexEvaluationScope::enter();
        assert!(!scope.has_failed());
        assert!(scope.failure().is_none());
        assert!(
            anchored
                .find_from_with_identity(&command, 0, Some(&identity))
                .is_none()
        );
        assert!(!scope.has_failed());
        assert!(scope.failure().is_none());

        // The same budget still permits ordinary matches for either rule.
        let matching = "A=/data/tmp/x/repro;IFS=,;scratch";
        for compiled in [&unanchored, &anchored] {
            assert_eq!(
                compiled.find_from_with_identity(matching, 0, Some(&identity)),
                Some((0, matching.len()))
            );
            assert!(!scope.has_failed());
            assert!(scope.failure().is_none());
        }
    }

    #[test]
    fn non_regex_first_failure_is_not_attributed_to_a_later_rule_issue_643() {
        let _ = crate::perf::take_budget_exhaustion();
        let pattern = LazyCompiledRegex::new(r"^(a|aa)+\1$")
            .with_rule_identity("test.later", Some("later-rule"));
        let input = format!("{}!", "a".repeat(80));
        let outer = RegexEvaluationScope::enter();
        assert!(record_incomplete_analysis(
            "interpreter_literal_recovery",
            &"bounded proof stopped"
        ));
        {
            let inner = RegexEvaluationScope::enter();
            assert!(!pattern.is_match(&input));
            assert!(inner.failure().is_some());
        }
        assert!(outer.has_failed());
        assert!(outer.failure().is_none());
        let note = crate::perf::take_budget_exhaustion();
        assert_eq!(note.incomplete.unwrap().0, "interpreter_literal_recovery");
        assert!(note.regex_failure.is_none());
    }

    #[test]
    fn unscoped_or_unattributed_regex_does_not_inherit_a_previous_rule_issue_643() {
        let _ = crate::perf::take_budget_exhaustion();
        let bound = LazyCompiledRegex::new(r"^(a|aa)+\1$")
            .with_rule_identity("test.bound", Some("bound-rule"));
        let input = format!("{}!", "a".repeat(80));
        // No evaluator owns this call, so it cannot contaminate a later request.
        assert!(!bound.is_match(&input));
        assert_eq!(
            crate::perf::take_budget_exhaustion(),
            crate::perf::BudgetExhaustion::default()
        );
        let scope = RegexEvaluationScope::enter();
        assert!(scope.failure().is_none());
        let anonymous = CompiledRegex::new_with_backtrack_limit(r"^(a|aa)+\1$", 17).unwrap();
        assert!(!anonymous.is_match(&input));
        let failure = scope.failure().unwrap();
        assert!(failure.pack_id.is_none());
        assert!(failure.pattern_id.is_none());
        assert_eq!(
            failure.cause,
            RegexFailureCause::BacktrackLimit { steps: 17 }
        );
    }

    #[test]
    fn regex_failure_logging_does_not_expose_pattern_or_command_text_issue_643() {
        #[derive(Clone)]
        struct Writer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(move || Writer(sink.clone()))
            .finish();
        let _tracing = tracing::subscriber::set_default(subscriber);
        let invalid = LazyCompiledRegex::new("SECRET_PATTERN[")
            .with_rule_identity("test.private", Some("broken-rule"));
        let scope = RegexEvaluationScope::enter();
        assert!(invalid.find("SECRET_SUBMITTED_COMMAND").is_none());
        let failure = scope.failure().unwrap();
        assert_eq!(failure.operation, RegexOperation::Compile);
        assert_eq!(failure.cause, RegexFailureCause::CompileError);
        let text = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
        assert!(text.contains("test.private:broken-rule"), "{text}");
        assert!(text.contains("operation: compile"), "{text}");
        assert!(!text.contains("SECRET_PATTERN"), "{text}");
        assert!(!text.contains("SECRET_SUBMITTED_COMMAND"), "{text}");
    }

    fn assert_same_regex_results(
        candidate: &LazyCompiledRegex,
        reference: &CompiledRegex,
        text: &str,
    ) {
        assert_eq!(
            candidate.is_match(text),
            reference.is_match(text),
            "{text:?}"
        );
        assert_eq!(candidate.find(text), reference.find(text), "{text:?}");
        for start in (0..=text.len() + 1).chain(std::iter::once(usize::MAX)) {
            assert_eq!(
                candidate.find_from(text, start),
                reference.find_from(text, start),
                "pattern={:?}, text={text:?}, start={start}",
                candidate.as_str(),
            );
        }
    }

    #[test]
    fn anchored_prefix_proof_accepts_only_supported_absolute_prefixes_issue_555() {
        for (pattern, prefix) in [
            (r"^rm(?=\s)\s+.+$", "rm"),
            (r"^(?!bad)(?=(?:rm|mv))rm\s+.+$", "rm"),
            (r"^r(?:m|f)(?!bad)", "r"),
            (r"^rm\.(?!x)\[tmp\]", "rm.[tmp]"),
            (r"^\x72m(?=\s)", "rm"),
            (r"^雪λ(?=\s)\s+.+$", "雪λ"),
            (r"^rm(?:(?!x).)*$", "rm"),
        ] {
            assert_eq!(required_anchored_prefix(pattern).as_deref(), Some(prefix));
        }

        for pattern in [
            r"^rm|find(?!bad)",
            r"^(?:rm|find)(?!bad)",
            r"^(rm)?find(?!bad)",
            r"^r{0,2}m(?!bad)",
            r"(?i)^rm(?!bad)",
            r"^(?i)rm(?!bad)",
            r"(?m)^rm(?!bad)",
            r"^(?m:rm$)(?!bad)",
            r"^(?=a\Kb)rm",
            r"^rm\K(?=x)x",
            r"^(?=(*ACCEPT))rm",
            r"^(?!(*SKIP))rm",
            r"^rm(*FAIL)",
            r"^(?<=x)rm(?!bad)",
            r"^(?<!(?:x|yy))rm(?!bad)",
            r"^rm\G(?!bad)",
            r"^(?(?=rm)rm|find)(?!bad)",
            r"^(rm)\1(?!bad)",
            r"^(?<head>rm)(?&head)(?!bad)",
            r"^rm(?~bad)(?!x)",
            r"^rm(?>x)(?!bad)",
            r"^rm(?=unclosed",
            r"^rm(?=x)\2",
            r"rm(?!bad)",
            r"^(?!bad)",
        ] {
            assert_eq!(required_anchored_prefix(pattern), None, "{pattern}");
        }
    }

    #[test]
    fn anchored_prefix_filter_preserves_regex_language_and_spans_issue_555() {
        let texts = [
            "",
            "ordinary Python data",
            "rm",
            "rm /etc",
            "rm bad",
            "rm x",
            "rm.[tmp]",
            "rmaaa",
            "rmrm",
            "rmx",
            "RM /etc",
            "find /etc",
            " rm /etc",
            "echo rm /etc",
            "echo\nrm /etc",
            "rm\n/etc",
            "rm\r\n/etc",
            "rm\u{a0}/tmp/雪",
            "雪λ /etc",
            "雪λ\n/tmp",
            "rλ雪m",
        ];
        for pattern in [
            r"^rm(?=\s)\s+.+$",
            r"^(?!bad)(?=(?:rm|find))rm\s+.+$",
            r"^r(?:m|f)(?!bad)",
            r"^rm\.(?!x)\[tmp\]",
            r"^\x72m(?=\s)",
            r"^雪λ(?=\s)\s+.+$",
            r"^rm(?:(?!x).)*$",
            r"^(?x) r m (?=\s) \s+ .+ $",
            r"^rm|find(?!bad)",
            r"^(?:rm|find)(?!bad)",
            r"^(rm)?find(?!bad)",
            r"^r{0,2}m(?!bad)",
            r"(?i)^rm(?!bad)",
            r"^(?i)rm(?!bad)",
            r"(?m)^rm(?!bad)",
            r"^(?m:rm$)(?!bad)",
            r"^rm\K(?=x)x",
            r"^(?=rm\K)rm",
            r"^rm\G(?!bad)",
            r"^rm(*FAIL)",
            r"^(?(?=rm)rm|find)(?!bad)",
            r"^(rm)\1(?!bad)",
            r"^(?<head>rm)(?&head)(?!bad)",
            r"^(?<!(?:x|yy))rm(?!bad)",
            r"^rm(?>x)(?!bad)",
            r"^(?!bad)",
        ] {
            let reference = CompiledRegex::new(pattern);
            let mut candidate = LazyCompiledRegex::new(pattern);
            candidate.enable_anchored_prefix_filter();
            match reference {
                Ok(reference) => {
                    for text in texts {
                        assert_same_regex_results(&candidate, &reference, text);
                    }
                }
                Err(error) => {
                    // Some advanced constructs are rejected by the pinned
                    // engine. Preserve its exact compiler error as well as
                    // the public matching result, rather than assuming every
                    // possible fallback fixture is a supported regex.
                    assert_eq!(required_anchored_prefix(pattern), None, "{pattern}");
                    for text in texts {
                        assert!(!candidate.is_match(text), "{pattern}: {text:?}");
                        assert_eq!(candidate.find(text), None);
                        assert_eq!(candidate.find_from(text, 1), None);
                    }
                    assert_eq!(
                        candidate
                            .compiled
                            .get()
                            .and_then(|value| value.as_ref().err()),
                        Some(&error),
                        "{pattern}",
                    );
                }
            }
        }
    }

    #[test]
    fn anchored_prefix_filter_keeps_generic_and_unknown_compilation_issue_555() {
        const PATTERN: &str = r"^rm(?!bad)\s+.+$";
        let generic = LazyCompiledRegex::new(PATTERN);
        assert!(!generic.is_match("ordinary data"));
        assert!(
            generic.is_compiled(),
            "the default constructor is unchanged"
        );

        let mut dynamic = LazyCompiledRegex::new_owned(PATTERN.to_string());
        dynamic.enable_anchored_prefix_filter();
        assert!(dynamic.anchored_prefix.is_none());
        assert!(!dynamic.is_match("ordinary data"));
        assert!(
            dynamic.is_compiled(),
            "owned patterns keep the original engine"
        );

        for pattern in [r"^rm(?=unclosed", r"^(?=(*ACCEPT))rm", r"^rm(?=x)\2"] {
            let error = CompiledRegex::new(pattern).expect_err("invalid or unsupported fixture");
            let mut candidate = LazyCompiledRegex::new(pattern);
            candidate.enable_anchored_prefix_filter();
            assert!(!candidate.is_match("ordinary data"));
            assert_eq!(candidate.find("ordinary data"), None);
            assert_eq!(candidate.find_from("ordinary data", 1), None);
            assert_eq!(
                candidate
                    .compiled
                    .get()
                    .and_then(|result| result.as_ref().err()),
                Some(&error),
                "unknown analysis must retain the original compiler error: {pattern}",
            );
        }
    }

    #[test]
    fn filesystem_safe_prefixes_preserve_all_rules_and_remain_lazy_issue_555() {
        let pack = crate::packs::core::filesystem::create_pack();
        let backtracking: Vec<_> = pack
            .safe_patterns
            .iter()
            .filter(|pattern| needs_backtracking_engine(pattern.regex.as_str()))
            .collect();
        assert_eq!(
            backtracking.len(),
            32,
            "audited anchored safe-pattern corpus"
        );
        for pattern in &backtracking {
            assert!(!pattern.regex.is_match("value_0 = 'ordinary data'"));
            assert!(
                !pattern.regex.is_compiled(),
                "impossible prefix must avoid VM compilation: {}",
                pattern.name,
            );
        }

        let mut commands = vec![
            "ordinary Python data".to_string(),
            "rm -rf /etc".to_string(),
            "rm -rf /tmp/build/..".to_string(),
            "rm -rf /tmp/build; rm -rf /etc".to_string(),
            "echo 'rm -rf /tmp/build'".to_string(),
            "RM -rf /tmp/build".to_string(),
            "mv ~/Documents/a ~/Desktop/b".to_string(),
            "mv 'a file' '/home/u/project/file'".to_string(),
            "mv ~/Documents/a ~/.Trash/".to_string(),
        ];
        for root in ["/tmp", "/var/tmp"] {
            for flags in [
                "-rf",
                "-fr",
                "-r -f",
                "-f -r",
                "--recursive --force",
                "--force --recursive",
            ] {
                commands.push(format!("rm {flags} {root}/build"));
            }
            for command in [
                format!("find {root}/build -delete"),
                format!("find {root}/build -exec rm -rf {{}} \\;"),
                format!("unlink {root}/file"),
                format!("truncate -s 0 {root}/file"),
                format!("shred {root}/file"),
                format!("tar --remove-files -cf backup.tar {root}/file"),
                format!("dd if=/dev/zero of={root}/file"),
                format!("mv {root}/a {root}/b"),
            ] {
                commands.push(command);
            }
        }
        for pattern in backtracking {
            let reference = CompiledRegex::new(pattern.regex.as_str()).unwrap();
            for command in &commands {
                assert_same_regex_results(&pattern.regex, &reference, command);
            }
        }
    }

    #[test]
    #[ignore = "paired safe-regex timing; run in release mode with --nocapture"]
    fn paired_safe_regex_prefix_benchmark_issue_555() {
        use std::hint::black_box;
        use std::time::Instant;

        for lines in [40, 300] {
            let source: Vec<_> = (0..lines)
                .map(|line| format!("value_{line} = 'ordinary Python data'"))
                .collect();
            for cold in [true, false] {
                let run = |reference: bool| {
                    let cold_start = Instant::now();
                    let pack = crate::packs::core::filesystem::create_pack();
                    let patterns: Vec<_> = pack
                        .safe_patterns
                        .iter()
                        .filter(|pattern| needs_backtracking_engine(pattern.regex.as_str()))
                        .collect();
                    let raw: Vec<_> = if reference {
                        patterns
                            .iter()
                            .map(|pattern| CompiledRegex::new(pattern.regex.as_str()).unwrap())
                            .collect()
                    } else {
                        Vec::new()
                    };
                    if !cold && !reference {
                        for pattern in &patterns {
                            assert!(!pattern.regex.is_match(&source[0]));
                        }
                    }
                    let mut results = Vec::with_capacity(source.len());
                    let start = if cold { cold_start } else { Instant::now() };
                    for line in &source {
                        results.push(if reference {
                            raw.iter().any(|pattern| pattern.is_match(black_box(line)))
                        } else {
                            patterns
                                .iter()
                                .any(|pattern| pattern.regex.is_match(black_box(line)))
                        });
                    }
                    let elapsed = start.elapsed();
                    let compiled = if reference {
                        raw.len()
                    } else {
                        patterns
                            .iter()
                            .filter(|pattern| pattern.regex.is_compiled())
                            .count()
                    };
                    (elapsed, results, compiled)
                };
                let mut reference_times = Vec::new();
                let mut candidate_times = Vec::new();
                for sample in 0..7 {
                    for reference in [sample % 2 == 0, sample % 2 != 0] {
                        let (elapsed, results, compiled) = run(reference);
                        assert_eq!(results, vec![false; lines]);
                        assert_eq!(compiled, if reference { 32 } else { 0 });
                        if reference {
                            reference_times.push(elapsed);
                        } else {
                            candidate_times.push(elapsed);
                        }
                    }
                }
                reference_times.sort_unstable();
                candidate_times.sort_unstable();
                eprintln!(
                    "safe_regex_prefix/{}/{lines}: raw_p50_ms={:.3} candidate_p50_ms={:.3} speedup={:.2}x raw_compiled=32 candidate_compiled=0",
                    if cold { "cold" } else { "warm" },
                    reference_times[3].as_secs_f64() * 1_000.0,
                    candidate_times[3].as_secs_f64() * 1_000.0,
                    reference_times[3].as_secs_f64() / candidate_times[3].as_secs_f64(),
                );
            }
        }
    }

    #[test]
    fn test_linear_engine_selection() {
        // Simple patterns should use linear engine
        let re = CompiledRegex::new(r"rm\s+-rf").unwrap();
        assert!(!re.uses_backtracking());
        assert!(re.is_match("rm -rf /"));
    }

    #[test]
    fn test_backtracking_engine_selection() {
        // Lookahead patterns should use backtracking engine
        let re = CompiledRegex::new(r"git\s+push(?=.*--force)").unwrap();
        assert!(re.uses_backtracking());
        assert!(re.is_match("git push --force"));
        assert!(!re.is_match("git push"));
    }

    #[test]
    fn test_lookbehind() {
        let re = CompiledRegex::new(r"(?<=drop\s)database").unwrap();
        assert!(re.uses_backtracking());
        assert!(re.is_match("drop database"));
    }

    #[test]
    fn test_negative_lookahead() {
        let re = CompiledRegex::new(r"rm(?!\s+--dry-run)").unwrap();
        assert!(re.uses_backtracking());
        assert!(re.is_match("rm -rf"));
        assert!(!re.is_match("rm --dry-run"));
    }

    #[test]
    fn test_needs_backtracking_detection() {
        // Simple patterns - linear engine
        assert!(!needs_backtracking_engine(r"simple"));
        assert!(!needs_backtracking_engine(r"git\s+status"));
        assert!(!needs_backtracking_engine(r"\d+\.\d+")); // \d is NOT a backreference
        assert!(!needs_backtracking_engine(r"foo\0bar")); // \0 is NOT a backreference

        // Lookahead/lookbehind - backtracking needed
        assert!(needs_backtracking_engine(r"(?=lookahead)"));
        assert!(needs_backtracking_engine(r"(?!negative)"));
        assert!(needs_backtracking_engine(r"(?<=lookbehind)"));
        assert!(needs_backtracking_engine(r"(?<!negative-behind)"));
        assert!(
            !needs_backtracking_engine(LEGACY_NEVER_MATCH_PATTERN),
            "the legacy impossible sentinel is canonicalized to a linear expression"
        );

        // Backreferences - backtracking needed
        assert!(needs_backtracking_engine(r"(foo)\1"));
        assert!(needs_backtracking_engine(r"(\w+)\s+\1"));
        assert!(needs_backtracking_engine(r"(a)(b)\2\1"));

        // Two-digit backreferences (detected by first digit)
        // \10 starts with \1 which triggers detection
        assert!(needs_backtracking_engine(
            r"(.)(.)(.)(.)(.)(.)(.)(.)(.)(.).\10"
        ));
    }

    #[test]
    fn impossible_semantic_sentinel_is_linear_and_never_matches() {
        let eager = CompiledRegex::new(LEGACY_NEVER_MATCH_PATTERN).unwrap();
        assert!(!eager.uses_backtracking());
        assert!(!eager.is_match(""));
        assert!(!eager.is_match("arbitrary command text"));

        let lazy = LazyCompiledRegex::new(LEGACY_NEVER_MATCH_PATTERN);
        assert_eq!(lazy.as_str(), NEVER_MATCH_PATTERN);
        assert!(!lazy.is_match("git reset --hard"));
        assert!(lazy.is_compiled());
    }

    #[test]
    fn test_backreference_pattern() {
        // Backreferences should use backtracking engine
        let re = CompiledRegex::new(r"(\w+)\s+\1").unwrap();
        assert!(re.uses_backtracking());

        // Should match repeated words
        assert!(re.is_match("hello hello"));
        assert!(re.is_match("the the"));
        assert!(!re.is_match("hello world"));
    }

    #[test]
    fn test_find_linear() {
        let re = CompiledRegex::new(r"rm").unwrap();
        assert!(!re.uses_backtracking());
        assert_eq!(re.find("test rm command"), Some((5, 7)));
        assert_eq!(re.find("no match"), None);
    }

    #[test]
    fn test_find_backtracking() {
        // Use lookahead pattern to force backtracking engine
        let re = CompiledRegex::new(r"git(?=\s+push)").unwrap();
        assert!(re.uses_backtracking());
        assert_eq!(re.find("run git push"), Some((4, 7)));
        assert_eq!(re.find("git status"), None); // lookahead fails
    }

    #[test]
    fn find_from_preserves_context_for_both_engines() {
        let linear = CompiledRegex::new(r"\brm\b").unwrap();
        assert_eq!(linear.find_from("rm then rm", 2), Some((8, 10)));

        let backtracking = CompiledRegex::new(r"(?<=run\s)git").unwrap();
        assert!(backtracking.uses_backtracking());
        assert_eq!(
            backtracking.find_from("run git then run git", 8),
            Some((17, 20))
        );

        for invalid_start in [1, usize::MAX] {
            assert_eq!(
                linear.find_from("é rm", invalid_start),
                None,
                "invalid UTF-8 or out-of-range starts are rejected"
            );
        }
    }

    #[test]
    fn test_replacen_linear() {
        let re = CompiledRegex::new(r"foo").unwrap();
        assert!(!re.uses_backtracking());
        assert_eq!(re.replacen("foo bar foo", 1, "baz"), "baz bar foo");
        assert_eq!(re.replacen("foo bar foo", 0, "baz"), "baz bar baz"); // 0 = all
    }

    #[test]
    fn test_replacen_backtracking() {
        // Use backreference pattern to force backtracking engine
        let re = CompiledRegex::new(r"(\w+)\s+\1").unwrap();
        assert!(re.uses_backtracking());
        // Replace duplicate words with "DUPE"
        assert_eq!(re.replacen("the the cat", 1, "DUPE"), "DUPE cat");
    }

    // ==========================================================================
    // Worst-case regex input tests
    // ==========================================================================
    // These tests verify the linear-time engine handles inputs that would cause
    // exponential blowup in backtracking engines (classic ReDoS patterns).

    #[test]
    fn test_worst_case_alternation() {
        // Pattern: (a|a)+ on input "aaaa..." is O(2^n) for backtracking
        // Linear engine handles this in O(n)
        let re = CompiledRegex::new(r"(a|a)+").unwrap();
        assert!(!re.uses_backtracking()); // Should use linear engine

        // This would hang a backtracking engine but linear handles it fine
        let input = "a".repeat(100);
        assert!(re.is_match(&input));
    }

    #[test]
    fn test_worst_case_nested_quantifiers() {
        // Pattern: (a+)+ on input "aaa...!" is classic ReDoS
        // Linear engine guarantees O(n)
        let re = CompiledRegex::new(r"(a+)+$").unwrap();
        assert!(!re.uses_backtracking());

        // Input that would cause catastrophic backtracking
        let mut input = "a".repeat(50);
        input.push('!'); // Force non-match after lots of 'a's
        assert!(!re.is_match(&input)); // Should complete quickly
    }

    #[test]
    fn test_worst_case_star_quantifier() {
        // Pattern: a*a*a*...a*b on input "aaaa...a" (no b)
        let re = CompiledRegex::new(r"a*a*a*a*a*b").unwrap();
        assert!(!re.uses_backtracking());

        let input = "a".repeat(100);
        assert!(!re.is_match(&input)); // No 'b', should be quick
    }

    #[test]
    fn test_worst_case_dot_star() {
        // Pattern: .*.*.*= with non-matching long input
        let re = CompiledRegex::new(r".*.*.*=").unwrap();
        assert!(!re.uses_backtracking());

        let input = "x".repeat(100);
        assert!(!re.is_match(&input)); // No '=', should complete quickly
    }

    #[test]
    fn test_linear_engine_long_input() {
        // Verify linear engine handles long inputs efficiently
        let re = CompiledRegex::new(r"rm\s+-rf\s+/").unwrap();
        assert!(!re.uses_backtracking());

        // Embed the pattern in a very long command
        let mut cmd = "echo ".to_string();
        cmd.push_str(&"x".repeat(10_000));
        cmd.push_str(" && rm -rf / && ");
        cmd.push_str(&"y".repeat(10_000));

        assert!(re.is_match(&cmd));
    }

    #[test]
    fn test_backtracking_safety() {
        // Patterns with lookahead still need backtracking, but should be bounded
        // This test ensures we don't hang on reasonable inputs
        let re = CompiledRegex::new(r"git\s+push(?=.*--force)").unwrap();
        assert!(re.uses_backtracking());

        // Reasonable size input - should complete quickly
        let cmd = format!("git push {} --force", "branch".repeat(100));
        assert!(re.is_match(&cmd));
    }

    #[test]
    fn test_as_str_preserves_pattern() {
        let pattern = r"test\s+pattern";
        let re = CompiledRegex::new(pattern).unwrap();
        assert_eq!(re.as_str(), pattern);
    }

    #[test]
    fn test_as_str_backtracking() {
        // Verify as_str works with backtracking engine too
        let pattern = r"foo(?=bar)";
        let re = CompiledRegex::new(pattern).unwrap();
        assert!(re.uses_backtracking());
        assert_eq!(re.as_str(), pattern);
    }

    #[test]
    fn test_empty_pattern() {
        // Empty pattern should work (matches empty string at every position)
        let re = CompiledRegex::new("").unwrap();
        assert!(!re.uses_backtracking()); // No backtracking features
        assert!(re.is_match("")); // Matches empty string
        assert!(re.is_match("anything")); // Matches at start of any string
        assert_eq!(re.find("test"), Some((0, 0))); // Zero-width match at position 0
    }

    #[test]
    fn test_compile_error_linear() {
        // Invalid regex should return error
        let result = CompiledRegex::new_linear(r"(unclosed");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("regex compile error"));
    }

    #[test]
    fn test_compile_error_backtracking() {
        // Invalid regex should return error
        let result = CompiledRegex::new_backtracking(r"(unclosed");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("fancy_regex compile error"));
    }

    // =========================================================================
    // LazyCompiledRegex Tests
    // =========================================================================

    #[test]
    fn test_lazy_regex_not_compiled_initially() {
        let lazy = LazyCompiledRegex::new(r"test\s+pattern");
        assert!(!lazy.is_compiled());
    }

    #[test]
    fn test_lazy_regex_compiles_on_first_use() {
        let lazy = LazyCompiledRegex::new(r"test\s+pattern");
        assert!(!lazy.is_compiled());

        // First use triggers compilation
        let _ = lazy.is_match("test pattern");
        assert!(lazy.is_compiled());
    }

    #[test]
    fn test_lazy_regex_is_match_same_as_eager() {
        let pattern = r"git\s+reset\s+--hard";
        let lazy = LazyCompiledRegex::new(pattern);
        let eager = CompiledRegex::new(pattern).unwrap();

        // Test matching inputs
        let inputs = [
            "git reset --hard",
            "git reset --hard HEAD",
            "  git reset --hard  ",
            "git status",   // No match
            "reset --hard", // No match
            "",
        ];

        for input in inputs {
            assert_eq!(
                lazy.is_match(input),
                eager.is_match(input),
                "Mismatch for input: {input:?}"
            );
        }
    }

    #[test]
    fn test_lazy_regex_find_span_same_as_eager() {
        let pattern = r"rm\s+-rf";
        let lazy = LazyCompiledRegex::new(pattern);
        let eager = CompiledRegex::new(pattern).unwrap();

        let inputs = [
            "rm -rf /",
            "sudo rm -rf /tmp",
            "echo rm -rf",
            "rm command",
            "",
        ];

        for input in inputs {
            let lazy_span = lazy.find(input);
            let eager_span = eager.find(input);
            assert_eq!(lazy_span, eager_span, "Span mismatch for input: {input:?}");
        }
    }

    #[test]
    fn test_lazy_regex_as_str() {
        let pattern = r"test\s+pattern";
        let lazy = LazyCompiledRegex::new(pattern);
        assert_eq!(lazy.as_str(), pattern);
    }

    #[test]
    fn test_lazy_regex_lookahead() {
        // Test with lookahead pattern (requires fancy_regex)
        let lazy = LazyCompiledRegex::new(r"git\s+push(?=.*--force)");

        assert!(lazy.is_match("git push --force"));
        assert!(lazy.is_match("git push origin main --force"));
        assert!(!lazy.is_match("git push"));
        assert!(!lazy.is_match("git push origin main"));
    }

    #[test]
    fn test_lazy_regex_lookbehind() {
        // Test with lookbehind pattern
        let lazy = LazyCompiledRegex::new(r"(?<=drop\s)database");

        assert!(lazy.is_match("drop database"));
        assert!(!lazy.is_match("database"));
    }

    #[test]
    fn test_lazy_regex_span_with_lookahead() {
        let lazy = LazyCompiledRegex::new(r"git(?=\s+push)");

        // Lookahead is zero-width, so span should be just "git"
        assert_eq!(lazy.find("git push"), Some((0, 3)));
        assert_eq!(lazy.find("run git push now"), Some((4, 7)));
        assert_eq!(lazy.find("git status"), None);
    }

    #[test]
    fn test_lazy_regex_static_usage() {
        // Verify it works as a static (the primary use case)
        static PATTERN: LazyCompiledRegex = LazyCompiledRegex::new(r"hello\s+world");

        assert!(PATTERN.is_match("hello world"));
        assert!(!PATTERN.is_match("hello"));
    }

    #[test]
    fn test_lazy_regex_empty_pattern() {
        let lazy = LazyCompiledRegex::new("");

        // Empty pattern matches at position 0
        assert!(lazy.is_match(""));
        assert!(lazy.is_match("anything"));
        assert_eq!(lazy.find("test"), Some((0, 0)));
    }

    #[test]
    fn test_lazy_regex_reuses_compiled() {
        let lazy = LazyCompiledRegex::new(r"test");

        // Multiple calls should reuse the same compiled regex
        assert!(lazy.is_match("test"));
        assert!(lazy.is_match("test again"));
        assert!(lazy.is_match("another test"));

        // All calls after first should still show as compiled
        assert!(lazy.is_compiled());
    }

    #[test]
    fn full_input_exclusion_is_honored_by_every_matching_api() {
        let lazy = LazyCompiledRegex::new("delete")
            .excluding_full_match(r"delete item --dry-run(?:=client)?");
        assert_eq!(
            lazy.full_match_exclusion(),
            Some(r"delete item --dry-run(?:=client)?")
        );
        for command in ["delete item --dry-run", "delete item --dry-run=client"] {
            assert!(!lazy.is_match(command));
            assert_eq!(lazy.find(command), None);
            assert_eq!(lazy.find_from(command, 0), None);
        }
        for command in [
            "delete item",
            "delete item --description --dry-run",
            "delete item --dry-run=client --dry-run=none",
            "delete item --dry-run; delete other",
            "delete item --dry-run\ndelete other",
            "prefix delete item --dry-run",
        ] {
            assert!(lazy.is_match(command), "must not exempt: {command}");
            assert!(lazy.find(command).is_some());
            assert!(lazy.find_from(command, 0).is_some());
        }
    }

    #[test]
    fn exclusion_keeps_whole_input_scope_at_later_offsets() {
        let lazy = LazyCompiledRegex::new("delete").excluding_full_match("delete item --dry-run");
        let command = "delete real; delete item --dry-run";
        assert_eq!(lazy.find_from(command, 12), Some((13, 19)));
        assert_eq!(lazy.find_from("é delete", 1), None);
        assert_eq!(lazy.find_from(command, usize::MAX), None);
    }

    #[test]
    fn malformed_or_non_linear_exclusions_retain_denials() {
        for proof in ["(", r"delete (?=item)item", r"(delete) \1"] {
            let lazy = LazyCompiledRegex::new("delete").excluding_full_match(proof);
            assert!(lazy.is_match("delete item"));
            assert_eq!(lazy.find("delete item"), Some((0, 6)));
            assert_eq!(lazy.find_from("delete item", 0), Some((0, 6)));
        }
    }

    #[test]
    fn exclusion_cannot_exempt_a_prefix_or_empty_substring() {
        let lazy = LazyCompiledRegex::new("delete").excluding_full_match("delete|preview");
        assert!(!lazy.is_match("delete"));
        assert!(lazy.is_match("delete live data"));
        let empty = LazyCompiledRegex::new("delete").excluding_full_match("");
        assert!(empty.is_match("delete"));
        let multiline =
            LazyCompiledRegex::new("delete").excluding_full_match(r"(?m)^delete --dry-run$");
        assert!(multiline.is_match("delete --dry-run\ndelete live"));
    }

    #[test]
    fn exclusion_is_lazy_and_linear_for_adversarial_input() {
        let lazy = LazyCompiledRegex::new("delete").excluding_full_match(r"delete (a+)+ --dry-run");
        let proof = lazy.exclusion.as_ref().unwrap();
        assert!(proof.compiled.get().is_none());
        assert!(!lazy.is_match("unrelated"));
        assert!(proof.compiled.get().is_none());
        let command = format!("delete {}! --dry-run", "a".repeat(20_000));
        assert!(lazy.is_match(&command));
        assert!(proof.compiled.get().unwrap().is_ok());
        assert!(lazy.find(&command).is_some());
    }

    // =========================================================================
    // Backtrack Limit Tests (git_safety_guard-wopb)
    // =========================================================================

    #[test]
    fn test_default_backtrack_limit_applied() {
        assert_eq!(BACKTRACK_LIMIT, 100_000);
    }

    #[test]
    fn test_pathological_backtracking_fails_open() {
        // Pattern with catastrophic backtracking: (a+)+$ on "aaa...!" input.
        // With fancy_regex this requires the backtracking engine due to the
        // backreference-style nested quantifiers. We force it via lookahead.
        let re = CompiledRegex::new(r"(?=(a+)+$)").unwrap();
        assert!(re.uses_backtracking());

        // Input designed to trigger exponential backtracking: many 'a's followed
        // by a non-matching character. With limit=100K this should fail-open
        // (return false) instead of running for seconds.
        let mut input = "a".repeat(200);
        input.push('!');

        let start = std::time::Instant::now();
        let result = re.is_match(&input);
        let elapsed = start.elapsed();

        assert!(
            !result,
            "pathological pattern should fail-open (return false)"
        );
        // The backtrack limit makes this sub-millisecond; a broken/removed limit
        // would run for seconds (or hang). The bound is deliberately generous so it
        // can't flake from scheduler preemption under heavy parallel load, while
        // still catching a regression that lets the pathological pattern run long.
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "backtrack limit should cap execution well under 2s, took {elapsed:?}"
        );
    }

    #[test]
    fn test_pathological_find_fails_open() {
        let re = CompiledRegex::new(r"(?=(a+)+$)").unwrap();
        assert!(re.uses_backtracking());

        let mut input = "a".repeat(200);
        input.push('!');

        let start = std::time::Instant::now();
        let result = re.find(&input);
        let elapsed = start.elapsed();

        assert!(result.is_none(), "pathological find should return None");
        // Generous bound (see test_default_backtrack_limit_applied): a working
        // limit caps this to sub-millisecond, a broken one runs for seconds — so a
        // 2s ceiling catches the regression without flaking under load.
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "backtrack limit should cap find well under 2s, took {elapsed:?}"
        );
    }

    #[test]
    fn test_custom_backtrack_limit() {
        // Very tight limit: even simple backtracking patterns may exceed it
        let re = CompiledRegex::new_with_backtrack_limit(r"(?=(a+)+$)", 100).unwrap();
        assert!(re.uses_backtracking());

        let input = "a".repeat(50);
        // With limit=100, even matching input may fail due to limit.
        // The key assertion: it doesn't hang. The bound is generous (a working
        // limit returns in microseconds; the regression is a hang) so scheduler
        // preemption under heavy parallel load can't trip it.
        let start = std::time::Instant::now();
        let _ = re.is_match(&input);
        let elapsed = start.elapsed();
        assert!(elapsed < std::time::Duration::from_secs(2));
    }

    #[test]
    fn test_normal_backtracking_still_works() {
        // Normal lookahead patterns should still work within the 100K limit
        let re = CompiledRegex::new(r"git\s+push(?=.*--force)").unwrap();
        assert!(re.uses_backtracking());

        assert!(re.is_match("git push --force"));
        assert!(re.is_match("git push origin main --force"));
        assert!(!re.is_match("git push origin main"));

        // Reasonable size input — should not hit the limit
        let cmd = format!("git push {} --force", "branch ".repeat(100));
        assert!(re.is_match(&cmd));
    }

    #[test]
    fn test_replacen_respects_backtrack_limit() {
        let re = CompiledRegex::new(r"(?=(a+)+$)").unwrap();
        assert!(re.uses_backtracking());

        let mut input = "a".repeat(200);
        input.push('!');

        let start = std::time::Instant::now();
        let result = re.replacen(&input, 1, "X");
        let elapsed = start.elapsed();

        // Should fail-open: return original text unchanged
        assert_eq!(result.as_ref(), input.as_str());
        // Generous bound: working limit caps to sub-millisecond, broken one runs
        // for seconds — immune to load jitter, still catches the regression.
        assert!(elapsed < std::time::Duration::from_secs(2));
    }
}
