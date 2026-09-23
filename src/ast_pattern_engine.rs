//! AST-based pattern matching for heredoc and inline script content.
//!
//! This module implements Tier 3 of the heredoc detection architecture,
//! using ast-grep-core for structural pattern matching.
//!
//! # Architecture
//!
//! ```text
//! Content + Language
//!      │
//!      ▼
//! ┌─────────────────┐
//! │   AstMatcher    │ ─── Parse error ──► ERROR to bounded fallback
//! │   (ast-grep)    │ ─── Timeout ──► ERROR to bounded fallback
//! │   <5ms typical  │ ─── No match ──► EMPTY result to evaluator
//! │   20ms max      │ ─── Match ──► MATCH result to evaluator
//! └─────────────────┘
//! ```
//!
//! # Error Handling
//!
//! All errors are returned to the evaluator, which applies the configured
//! bounded-fallback or strict-block policy:
//! - Parse errors: Language syntax not recognized
//! - Timeouts: Pattern matching exceeded time budget
//! - Unknown language: No grammar available
//!
//! # Performance
//!
//! - Pattern compilation: One-time at startup
//! - Parse: <2ms for typical heredoc sizes
//! - Match: <1ms typical
//! - Hard timeout: 20ms

use crate::heredoc::ScriptLanguage;
use ast_grep_core::{AstGrep, Pattern};
use ast_grep_language::SupportLang;
use memchr::memchr_iter;
use regex::Regex;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

/// Hard timeout for AST operations (20ms as per ADR).
///
/// Tests use a much more generous budget because the full suite runs thousands
/// of AST-heavy cases in parallel.  On a loaded CI host a worker can be
/// descheduled for hundreds of milliseconds before it parses even this tiny
/// fixture; production builds retain the strict 20ms tier-local ceiling below.
#[cfg(not(test))]
const AST_TIMEOUT_MS: u64 = 20;
#[cfg(test)]
const AST_TIMEOUT_MS: u64 = 5_000;

/// Upper bound on `DCG_AST_TIMEOUT_MS`.
///
/// Comfortably above the hook deadline, past which raising this budget buys
/// nothing, while still refusing a value that would park a worker indefinitely.
const AST_TIMEOUT_CEILING_MS: u64 = 60_000;

/// The AST-matching budget, resolved once per process.
///
/// `DCG_AST_TIMEOUT_MS` may only **raise** the compiled-in budget, never lower
/// it. The `cfg(test)` value above covers in-crate tests, but the protocol
/// suites spawn the real release binary, so they got the strict 20ms and had no
/// way to reach past it: under parallel load a worker is descheduled, the
/// embedded-code analysis reports itself incomplete, and the bounded fallback
/// answers correctly but **without a rule id** — so an assertion about *which*
/// rule fired fails while the product behaves properly (#438). A semantic test
/// should not double as a deadline test.
///
/// Only-raise is the safe direction and is deliberate: a budget an operator
/// could shrink from the environment would push the matcher into its bounded
/// fallback more often, which is precisely the `DCG_*`-in-`settings.json`
/// footgun that #245 was about. Lowering remains possible through the
/// enclosing hook and heredoc budgets, which are measured, not assumed.
fn ast_timeout() -> Duration {
    static RESOLVED_MS: LazyLock<u64> = LazyLock::new(|| {
        resolve_ast_timeout_ms(std::env::var("DCG_AST_TIMEOUT_MS").ok().as_deref())
    });
    Duration::from_millis(*RESOLVED_MS)
}

/// The budget an environment request resolves to, given the compiled-in floor.
///
/// Split out from [`ast_timeout`] because that caches its answer for the process,
/// which is right for a hot path and useless for testing the clamp.
fn resolve_ast_timeout_ms(requested: Option<&str>) -> u64 {
    requested
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map_or(AST_TIMEOUT_MS, |ms| {
            ms.clamp(AST_TIMEOUT_MS, AST_TIMEOUT_CEILING_MS)
        })
}

/// Maximum body size the AST matcher will parse directly.
///
/// Heredoc extraction already defaults to a 1 MiB body cap; keeping the direct
/// matcher aligned prevents library callers and fuzz targets from bypassing the
/// same bounded parsing budget by invoking AST parsing on much larger inputs.
const MAX_AST_INPUT_BYTES: usize = 1024 * 1024;

/// Severity level for pattern matches.
///
/// Determines the default action taken when a pattern matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    /// Always block - no allowlist override without explicit config.
    Critical,
    /// Block by default, can be allowlisted.
    High,
    /// Warn by default (log but don't block).
    Medium,
    /// Log only - informational.
    Low,
}

impl Severity {
    /// Human-readable label for this severity.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    /// Whether this severity should block by default.
    #[must_use]
    pub const fn blocks_by_default(&self) -> bool {
        matches!(self, Self::Critical | Self::High)
    }
}

/// Result of a pattern match.
#[derive(Debug, Clone)]
pub struct PatternMatch {
    /// Stable rule ID for allowlisting (e.g., `heredoc.python.subprocess_rm`).
    pub rule_id: String,
    /// Human-readable reason for the match.
    pub reason: String,
    /// Preview of the matched text (truncated if too long).
    pub matched_text_preview: String,
    /// Byte offset of match start in the content.
    pub start: usize,
    /// Byte offset of match end in the content.
    pub end: usize,
    /// 1-based line number where match starts.
    pub line_number: usize,
    /// Severity level of this match.
    pub severity: Severity,
    /// Optional suggestion for safe alternative.
    pub suggestion: Option<String>,
}

/// Error during AST matching (all errors are non-fatal and returned to the evaluator).
#[derive(Debug, Clone)]
pub enum MatchError {
    /// Language not supported by ast-grep.
    UnsupportedLanguage(ScriptLanguage),
    /// Failed to parse content as the specified language.
    ParseError {
        language: ScriptLanguage,
        detail: String,
    },
    /// Pattern matching exceeded timeout.
    Timeout { elapsed_ms: u64, budget_ms: u64 },
    /// Pattern compilation failed (should not happen with static patterns).
    PatternError { pattern: String, detail: String },
}

impl std::fmt::Display for MatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedLanguage(lang) => {
                write!(f, "unsupported language for AST matching: {lang:?}")
            }
            Self::ParseError { language, detail } => {
                write!(f, "AST parse error for {language:?}: {detail}")
            }
            Self::Timeout {
                elapsed_ms,
                budget_ms,
            } => {
                write!(
                    f,
                    "AST matching timeout: {elapsed_ms}ms > {budget_ms}ms budget"
                )
            }
            Self::PatternError { pattern, detail } => {
                write!(f, "pattern compilation error for '{pattern}': {detail}")
            }
        }
    }
}

/// A compiled AST pattern with metadata.
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    /// The pattern string (for debugging/logging).
    pub pattern_str: String,
    /// Node kind that carves the real pattern out of `pattern_str`.
    ///
    /// `None` means `pattern_str` is itself a parseable fragment of the target
    /// language, which is the common case: Python, JavaScript, Ruby and PHP all
    /// accept a bare expression at the top level of a file, so
    /// `shutil.rmtree($$$)` parses straight to a call node.
    ///
    /// Go does not. Its grammar has no top-level expression statement, so
    /// `os.RemoveAll($$$)` parses to an ERROR node wrapping a `qualified_type`
    /// and some loose tokens — a tree that cannot equal a real
    /// `call_expression`, so the pattern matches nothing, anywhere, ever.
    /// `Pattern::try_new` still returns `Ok` for it and
    /// [`Pattern::has_error`](ast_grep_core::Pattern::has_error) still returns
    /// `false`, so neither the compile step nor a compile-only test can see the
    /// problem (#465).
    ///
    /// Such a language states its pattern inside the smallest enclosing
    /// construct that parses (`func f() { … }`) and names the node to extract.
    pub selector: Option<String>,
    /// Stable rule ID.
    pub rule_id: String,
    /// Human-readable reason.
    pub reason: String,
    /// Match severity.
    pub severity: Severity,
    /// Optional safe alternative suggestion.
    pub suggestion: Option<String>,
}

impl CompiledPattern {
    /// Create a new compiled pattern from a self-contained pattern fragment.
    #[must_use]
    pub const fn new(
        pattern_str: String,
        rule_id: String,
        reason: String,
        severity: Severity,
        suggestion: Option<String>,
    ) -> Self {
        Self {
            pattern_str,
            selector: None,
            rule_id,
            reason,
            severity,
            suggestion,
        }
    }

    /// Create a pattern stated inside enclosing context, matching `selector`.
    ///
    /// For languages whose grammar rejects a bare expression — see
    /// [`CompiledPattern::selector`] — the pattern is written as valid code and
    /// the node kind to match is named separately.
    #[must_use]
    pub const fn contextual(
        context: String,
        selector: String,
        rule_id: String,
        reason: String,
        severity: Severity,
        suggestion: Option<String>,
    ) -> Self {
        Self {
            pattern_str: context,
            selector: Some(selector),
            rule_id,
            reason,
            severity,
            suggestion,
        }
    }
}

#[derive(Debug, Clone)]
struct PrecompiledPattern {
    pattern: Pattern,
    meta: CompiledPattern,
}

/// AST pattern matcher using ast-grep-core.
///
/// Holds pre-compiled patterns for each supported language.
pub struct AstMatcher {
    /// Patterns organized by language.
    patterns: HashMap<ScriptLanguage, Vec<PrecompiledPattern>>,
    /// Timeout for matching operations.
    timeout: Duration,
}

impl Default for AstMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl AstMatcher {
    /// Create a new matcher with default destructive patterns.
    #[must_use]
    pub fn new() -> Self {
        precompile_perl_patterns();
        Self {
            patterns: precompile_patterns(default_patterns()),
            timeout: ast_timeout(),
        }
    }

    /// Create a matcher with custom patterns.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // HashMap is not const-constructible
    pub fn with_patterns(patterns: HashMap<ScriptLanguage, Vec<CompiledPattern>>) -> Self {
        precompile_perl_patterns();
        Self {
            patterns: precompile_patterns(patterns),
            timeout: ast_timeout(),
        }
    }

    /// Create a matcher with custom timeout.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Builder pattern, not suitable for const
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Find pattern matches in the given code.
    ///
    /// # Errors
    ///
    /// Returns `MatchError` on:
    /// - Unsupported language
    /// - Parse failure
    /// - Timeout
    ///
    /// All errors are non-fatal; callers must apply their configured bounded
    /// fallback or strict-block policy.
    pub fn find_matches(
        &self,
        code: &str,
        language: ScriptLanguage,
    ) -> Result<Vec<PatternMatch>, MatchError> {
        let start_time = Instant::now();
        let budget_ms = self.timeout.as_millis() as u64;

        // Perl is not supported by ast-grep-language; use a conservative regex fallback.
        if language == ScriptLanguage::Perl {
            return find_matches_perl(code, start_time, self.timeout, budget_ms);
        }

        // Check language support FIRST (before patterns, so we report unsupported properly)
        let Some(ast_lang) = script_language_to_ast_lang(language) else {
            return Err(MatchError::UnsupportedLanguage(language));
        };

        // Get patterns for this language (after language support check)
        let patterns = match self.patterns.get(&language) {
            Some(p) if !p.is_empty() => p,
            _ => return Ok(Vec::new()), // No patterns = no matches
        };

        if self.timeout.is_zero() || code.len() > MAX_AST_INPUT_BYTES {
            return Err(timeout_error(start_time, budget_ms));
        }

        run_ast_match_with_timeout(
            code.to_string(),
            language,
            ast_lang,
            patterns.clone(),
            self.timeout,
            budget_ms,
        )
    }

    /// Check if any blocking patterns match (convenience method).
    ///
    /// Returns the first blocking match, or None if no blocking patterns match.
    #[must_use]
    pub fn has_blocking_match(&self, code: &str, language: ScriptLanguage) -> Option<PatternMatch> {
        self.find_matches(code, language)
            .ok()
            .and_then(|matches| matches.into_iter().find(|m| m.severity.blocks_by_default()))
    }
}

/// Conservative exec-sink backstop for interpreter-source heredocs (#136).
///
/// Bodies of `python -`/`node -`/`ruby` (etc.) heredocs are masked out of the
/// evaluator's raw-shell rescan because the language AST is authoritative. But
/// ast-grep structural patterns only match *specific call shapes*
/// (`child_process.execSync(...)`, `os.system(...)`, …). Aliased or
/// indirectly-imported sinks — e.g. `const cp = require("child_process");
/// cp.execSync("rm -rf /etc")` — slip past those patterns. Without a backstop,
/// masking would turn such a genuinely-executing deletion into a false negative,
/// violating the zero-false-negative invariant.
///
/// This scan is **name-anchored and literal-only**: it fires only when a known
/// shell-exec sink *name* (`execSync`, `exec`, `spawnSync`, `spawn`,
/// `os.system`, `os.popen`, `subprocess.{run,call,Popen}`, `system`, `popen`)
/// is called with a string-literal argument whose content
/// [`detect_shell_payload`] flags as destructive (`rm -rf …`,
/// `git reset --hard`, …). A destructive token sitting in an inert literal with
/// no sink call (`print("rm -rf x")`, `console.log("rm -rf x")`) does NOT match,
/// so the reporter's false positive stays fixed.
///
/// Returns the first blocking match, or `None`. Language-scoped to the
/// non-shell interpreter languages that get masked. A caller that honours
/// allowlists wants [`scan_executing_sink_matches`] instead.
#[must_use]
pub fn scan_executing_sink_fallback(code: &str, language: ScriptLanguage) -> Option<PatternMatch> {
    scan_executing_sink_matches(code, language)
        .into_iter()
        .next()
}

/// Every BLOCKING exec-sink match in `code` (see
/// [`scan_executing_sink_fallback`] for what counts as one).
///
/// All of them, because a caller that honours allowlists must weigh each: an
/// allowlisted `./build` delete must not hide a `/` delete beside it. And only
/// blocking ones, so a harmless hit never stands in for the body — Ruby's pass
/// used to return its first hit whatever its severity, and `system('rm',
/// '-rf', '/tmp/x')` ahead of `system('rm', '-rf', '/')` ALLOWED the pair.
///
/// Perl is covered too. Its `system`/`exec`, backtick, `qx//` and
/// `File::Path` scans are regex work like this one, but they run inside
/// `find_matches` and are lost with it when that call times out, so they are
/// re-run here without the matcher's deadline.
///
/// Go and PHP are covered for that same reason. Their primary path is the AST
/// layer, and truncated extraction removes it, leaving an argv-split spawn with
/// nothing to catch it: no single literal of `exec.Command("rm", "-rf",
/// "/home/user")` is destructive, so the raw-shell rescan cannot see it either.
/// Measured with the extraction budget pinned, that call was allowed 10/10
/// while the Python, Ruby, JavaScript and Perl twins all denied.
#[must_use]
pub fn scan_executing_sink_matches(code: &str, language: ScriptLanguage) -> Vec<PatternMatch> {
    if language == ScriptLanguage::Perl {
        return find_matches_perl(code, Instant::now(), Duration::MAX, u64::MAX)
            .map(|matches| {
                matches
                    .into_iter()
                    .filter(|m| m.severity.blocks_by_default())
                    .collect()
            })
            .unwrap_or_default();
    }

    let newline_positions: Vec<usize> = memchr_iter(b'\n', code.as_bytes()).collect();
    let mut out = Vec::new();

    // Ruby has command-execution forms whose payload is NOT a quoted string
    // literal (`%x(rm -rf /etc)`, backticks `` `rm -rf /etc` ``). Handle those
    // (plus `IO.popen`/`Open3.*` whose payloads ARE quoted) in a dedicated pass so
    // the heredoc masking never converts a real executing deletion into a false
    // negative (#136).
    if language == ScriptLanguage::Ruby {
        out.extend(scan_ruby_exec_sink_matches(code, &newline_positions));
    }

    let sink_regex: &Regex = match language {
        ScriptLanguage::JavaScript | ScriptLanguage::TypeScript => &JS_EXEC_SINK_LITERAL,
        ScriptLanguage::Python => &PY_EXEC_SINK_LITERAL,
        ScriptLanguage::Ruby => &RUBY_EXEC_SINK_LITERAL,
        // Go and PHP were scoped out here on the grounds that they "use their
        // own primary paths". That is true only while the primary path RUNS.
        // It is the AST layer, and when heredoc extraction is truncated the
        // layer does not run at all -- the same exposure the comment above
        // already grants Perl, whose scans are re-run here because a timed-out
        // `find_matches` takes them down with it.
        //
        // The raw-shell rescan does not cover the difference, because it needs
        // contiguous destructive text and an argv-split spawn has none: in
        // `exec.Command("rm", "-rf", "/home/user")` every literal is separately
        // harmless. Measured with the extraction budget pinned to 1ms, that
        // exact call was ALLOWED 10/10 while Python, Ruby, JavaScript and Perl
        // all denied the same payload, and under natural load on a busy host it
        // allowed 8/20 at the shipped budget.
        //
        // PHP additionally reaches shapes no AST pattern covers at all:
        // `pcntl_exec` is not in `is_php_exec_sink_rule`, so it was allowed with
        // no timing pressure whatsoever.
        ScriptLanguage::Go => &GO_EXEC_SINK_LITERAL,
        ScriptLanguage::Php => &PHP_EXEC_SINK_LITERAL,
        // Bash is never masked, so it has no extraction layer to lose.
        _ => return out,
    };

    for caps in sink_regex.captures_iter(code) {
        let Some(m) = caps.get(0) else { continue };

        // Scan the sink call's full argument region — not just its first string
        // literal — so a destructive payload nested inside a list/tuple literal
        // (`subprocess.run(["sh", "-c", "rm -rf /etc"])`) is caught even when the
        // first literal (`"sh"`) is inert (#136). The region spans from the
        // opening paren of this match to the balanced close paren (bounded to the
        // remainder of the source), descending into bracketed list elements.
        let arg_region = exec_sink_arg_region(code, m.start());
        let Some(hit) = detect_destructive_in_args(arg_region) else {
            continue;
        };

        // Carry the payload's own severity rather than escalating it.
        //
        // This used to read `_ => Severity::High`, which blocked every hit
        // regardless of target. That was right while it compensated for #136's
        // interpreter-body masking: a masked body was invisible to every other
        // layer, so the backstop had to be the maximally conservative one. The
        // masking was reverted, the body keeps flowing through the raw-shell
        // rescan, and this scanner ran nowhere at all until #459 wired it up.
        //
        // Its unique contribution now is the argv join — a shape with no
        // contiguous destructive text for any other layer to see. That is a
        // question of *visibility*, not of severity, so the payload is judged
        // by the one yardstick every consumer shares: the severity
        // `detect_rm_rf_destructive` assigns, which encodes #455's resolved
        // policy. A literal target outside a temp directory is `High` and
        // blocks (`./build`, `node_modules`); `/tmp` and `/var/tmp` are
        // `Medium` and do not, exactly as `rm -rf /tmp/x` is in the shell.
        //
        // Escalating HERE instead would still be wrong: a blanket `High` would
        // defeat that temp carve-out for this one path. Keeping the policy in
        // `detect_rm_rf_destructive` means it is decided once, not per consumer.
        if !hit.severity.blocks_by_default() {
            continue;
        }
        let severity = hit.severity;

        let sink = caps.name("sink").map_or("exec", |s| s.as_str());
        let lang_id = match language {
            ScriptLanguage::JavaScript => "javascript",
            ScriptLanguage::TypeScript => "typescript",
            ScriptLanguage::Python => "python",
            ScriptLanguage::Ruby => "ruby",
            ScriptLanguage::Go => "go",
            ScriptLanguage::Php => "php",
            _ => "unknown",
        };
        let line_number = newline_positions.partition_point(|&idx| idx < m.start()) + 1;

        out.push(PatternMatch {
            rule_id: format!("heredoc.{lang_id}.exec_sink.{}", hit.rule_suffix),
            reason: format!("{} via {sink}() exec sink", hit.reason),
            matched_text_preview: truncate_preview(code.get(m.start()..m.end()).unwrap_or(""), 60),
            start: m.start(),
            end: m.end(),
            line_number,
            severity,
            suggestion: hit.suggestion.map(str::to_string),
        });
    }

    out
}

/// One exec-sink call reconstructed as the shell command line it runs.
pub struct ReconstructedCommand {
    /// The command word and its arguments, space-joined — e.g.
    /// `dd if=/dev/zero of=/dev/sda`.
    pub command: String,
    /// Byte span of the sink call in the scanned `code`, for span mapping.
    pub start: usize,
    /// End of that span.
    pub end: usize,
}

/// Each exec-sink argv-split call in `code`, reconstructed as the shell command
/// line it runs, for evaluation through the full pack pipeline.
///
/// [`scan_executing_sink_matches`] covers the `rm` and `git` argv forms under
/// dedicated `exec_sink.*` rule ids, so a call it already flags is skipped here
/// (routing it to the packs too would deny an allowlisted `rm`/`git` under a
/// second rule id). EVERY other destructive verb — `dd`, `mkfs`, `wipefs`,
/// `truncate`, `shred`, `chmod -R`, … — is known only to the packs, and an
/// argv-split spawn (`spawnSync('dd', ['if=…', 'of=/dev/sda'])`) leaves no
/// contiguous command text for the raw-shell rescan, so re-joining its argv and
/// evaluating THAT is the only way it reaches its pack rule. This is the #459
/// gap generalized past `rm`.
///
/// Only a multi-literal argv is reconstructed: a single-string sink argument
/// (`execSync('dd if=… of=…')`) is contiguous command text the raw-shell rescan
/// already sees, so re-evaluating it would add nothing.
#[must_use]
pub fn exec_sink_reconstructed_commands(
    code: &str,
    language: ScriptLanguage,
) -> Vec<ReconstructedCommand> {
    let sink_regex: &Regex = match language {
        ScriptLanguage::JavaScript | ScriptLanguage::TypeScript => &JS_EXEC_SINK_LITERAL,
        ScriptLanguage::Python => &PY_EXEC_SINK_LITERAL,
        ScriptLanguage::Ruby => &RUBY_EXEC_SINK_LITERAL,
        ScriptLanguage::Perl => &PERL_SYSTEM_EXEC_LITERAL,
        // Go and PHP reach the packs for the same reason every other language
        // does, and their absence here was not a scope decision about them --
        // it is that `rm` and `git` are the only verbs the sink backstop knows,
        // and Go's `exec.Command` reached that backstop through its own AST
        // path. Every OTHER destructive verb lives only in the packs, so
        // `exec.Command("dd", "if=/dev/zero", "of=/dev/sda")` and
        // `exec.Command("wipefs", "-a", "/dev/sda")` were ALLOWED 3/3 with no
        // timing pressure, while the identical argv through Python's
        // `subprocess.run` and Node's `spawnSync` denied under
        // `system.disk:dd-device`. PHP's `pcntl_exec` was allowed for both
        // reasons at once.
        //
        // Reconstruction reads argv[0] as the program, so a call whose real
        // program is something else is unaffected: `exec.Command("/bin/echo",
        // "dd", "if=…", "of=…")` stays allowed, because `echo` is what runs.
        ScriptLanguage::Go => &GO_EXEC_SINK_LITERAL,
        ScriptLanguage::Php => &PHP_EXEC_SINK_LITERAL,
        _ => return Vec::new(),
    };
    // Perl comments can hold a `system(...)` that never runs; mask them so a
    // commented call is not reconstructed and over-blocked. Masking preserves
    // length, so the sink spans still line up with `code`.
    let masked = if language == ScriptLanguage::Perl {
        mask_perl_comments(code)
    } else {
        std::borrow::Cow::Borrowed(code)
    };
    let haystack = masked.as_ref();

    let mut out = Vec::new();
    for caps in sink_regex.captures_iter(haystack) {
        let Some(m) = caps.get(0) else { continue };
        let region = exec_sink_arg_region(haystack, m.start());
        // A call the rm/git backstop owns (any `detect_destructive_in_args`
        // hit) is left to it, so an allowlisted `rm`/`git` is not re-denied
        // here under a pack rule id.
        if detect_destructive_in_args(region).is_some() {
            continue;
        }
        // Operands, for the same reason `detect_destructive_in_args` uses them:
        // reconstructing `dd` from `"d"+"d"` as two argv words would not be the
        // command the call actually runs (#474).
        let operands = concatenated_operands(exec_argv_region(region));
        if operands.len() < 2 {
            continue;
        }
        out.push(ReconstructedCommand {
            command: operands.join(" "),
            start: m.start(),
            end: m.end(),
        });
    }
    out
}

/// High-signal filesystem sink fallback for cases where the full AST pass is
/// unavailable or too close to the hook deadline.
///
/// This intentionally stays narrower than the AST pattern set: it only matches
/// Ruby `FileUtils.*` and JavaScript/TypeScript `fs.rmSync()` calls that start a
/// source line and use a catastrophic literal target. That avoids firing on
/// common inert cases such as comments or strings while still catching the
/// highest-risk deletes before an AST timeout can reduce analysis coverage.
#[must_use]
pub fn scan_filesystem_sink_fallback(code: &str, language: ScriptLanguage) -> Option<PatternMatch> {
    let newline_positions: Vec<usize> = memchr_iter(b'\n', code.as_bytes()).collect();

    if language == ScriptLanguage::Ruby {
        for caps in RUBY_FILEUTILS_LITERAL.captures_iter(code) {
            let Some(m) = caps.get(0) else { continue };
            let Some(path) = string_literal_from_caps(&caps) else {
                continue;
            };
            let fn_name = caps.name("fn").map_or("rm_rf", |s| s.as_str());
            let catastrophic = is_catastrophic_path(path);
            // #455: the fallback has to reach the same verdict the AST pass
            // would, or an AST timeout quietly relaxes the policy.
            let non_temp_recursive = !catastrophic
                && is_recursive_delete_rule(&format!("heredoc.ruby.fileutils_{fn_name}"))
                && !is_temp_scratch_path(path);
            let severity = if catastrophic || non_temp_recursive {
                Severity::Critical
            } else {
                Severity::Medium
            };
            let suffix = if catastrophic {
                ".catastrophic"
            } else if non_temp_recursive {
                ".non_temp"
            } else {
                ""
            };
            let line_number = newline_positions.partition_point(|&idx| idx < m.start()) + 1;

            return Some(PatternMatch {
                rule_id: format!("heredoc.ruby.fileutils_{fn_name}{suffix}"),
                reason: if catastrophic {
                    format!(
                        "FileUtils.{fn_name}() deletes files/directories (catastrophic target path)"
                    )
                } else if non_temp_recursive {
                    format!(
                        "FileUtils.{fn_name}() recursively deletes files/directories outside a temp directory"
                    )
                } else {
                    format!("FileUtils.{fn_name}() deletes files/directories")
                },
                matched_text_preview: truncate_preview(
                    code.get(m.start()..m.end()).unwrap_or(""),
                    60,
                ),
                start: m.start(),
                end: m.end(),
                line_number,
                severity,
                suggestion: Some("Verify target path carefully before running".to_string()),
            });
        }
        return None;
    }

    if matches!(
        language,
        ScriptLanguage::JavaScript | ScriptLanguage::TypeScript
    ) {
        for caps in JS_FS_SINK_LITERAL.captures_iter(code) {
            let Some(m) = caps.get(0) else { continue };
            if !is_javascript_executable_offset(code, m.start()) {
                continue;
            }
            let Some(path) = string_literal_from_caps(&caps) else {
                continue;
            };
            // The captured sink names the rule, so the id matches the AST rule
            // for the same API rather than reporting everything as `fs_rmsync`.
            let sink = caps.name("sink").map_or("rmSync", |s| s.as_str());
            let rule_suffix = match sink {
                "rmdirSync" => "fs_rmdirsync",
                "unlinkSync" => "fs_unlinksync",
                "rm" => "fs_rm",
                _ => "fs_rmsync",
            };
            let catastrophic = is_catastrophic_path(path);
            // #455: the fallback must reach the same verdict as the AST pass.
            // A `recursive: true` delete of a literal outside /tmp blocks; a
            // single-file `fs.rmSync('./a.txt')` is still not this rule's
            // business, so the recursive option has to be present.
            let non_temp_recursive = !catastrophic
                && JS_RECURSIVE_TRUE.is_match(code.get(m.start()..).unwrap_or(""))
                && !is_temp_scratch_path(path);
            if !catastrophic && !non_temp_recursive {
                continue;
            }

            let lang_id = if language == ScriptLanguage::TypeScript {
                "typescript"
            } else {
                "javascript"
            };
            let suffix = if catastrophic {
                "catastrophic"
            } else {
                "non_temp"
            };
            let line_number = newline_positions.partition_point(|&idx| idx < m.start()) + 1;
            return Some(PatternMatch {
                rule_id: format!("heredoc.{lang_id}.{rule_suffix}.{suffix}"),
                reason: if catastrophic {
                    format!("fs.{sink}() deletes files/directories (catastrophic target path)")
                } else {
                    format!(
                        "fs.{sink}() recursively deletes files/directories outside a temp directory"
                    )
                },
                matched_text_preview: truncate_preview(
                    code.get(m.start()..m.end()).unwrap_or(""),
                    60,
                ),
                start: m.start(),
                end: m.end(),
                line_number,
                severity: Severity::Critical,
                suggestion: Some("Verify target path carefully before running".to_string()),
            });
        }
    }

    None
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JavaScriptLexState {
    Code,
    SingleQuoted,
    DoubleQuoted,
    Template,
    LineComment,
    BlockComment,
}

/// Return true only when `offset` is in ordinary JavaScript code. The fallback
/// deliberately treats template interpolation as inert: missing an unusual
/// `${fs.rmSync(...)}` backstop is safer than blocking documentation text, and
/// the primary AST matcher still handles the executable interpolation.
fn is_javascript_executable_offset(code: &str, offset: usize) -> bool {
    let bytes = code.as_bytes();
    let mut state = JavaScriptLexState::Code;
    let mut escaped = false;
    let mut index = 0;

    while index < offset.min(bytes.len()) {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();

        match state {
            JavaScriptLexState::Code => match (byte, next) {
                (b'/', Some(b'/')) => {
                    state = JavaScriptLexState::LineComment;
                    index += 1;
                }
                (b'/', Some(b'*')) => {
                    state = JavaScriptLexState::BlockComment;
                    index += 1;
                }
                (b'\'', _) => state = JavaScriptLexState::SingleQuoted,
                (b'"', _) => state = JavaScriptLexState::DoubleQuoted,
                (b'`', _) => state = JavaScriptLexState::Template,
                _ => {}
            },
            JavaScriptLexState::SingleQuoted => {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'\'' {
                    state = JavaScriptLexState::Code;
                }
            }
            JavaScriptLexState::DoubleQuoted => {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    state = JavaScriptLexState::Code;
                }
            }
            JavaScriptLexState::Template => {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'`' {
                    state = JavaScriptLexState::Code;
                }
            }
            JavaScriptLexState::LineComment => {
                if byte == b'\n' {
                    state = JavaScriptLexState::Code;
                }
            }
            JavaScriptLexState::BlockComment => {
                if byte == b'*' && next == Some(b'/') {
                    state = JavaScriptLexState::Code;
                    index += 1;
                }
            }
        }
        index += 1;
    }

    state == JavaScriptLexState::Code
}

/// Ruby-specific exec-sink backstop covering forms whose destructive payload is
/// not a quoted string literal (`%x(...)`/`%x{...}`/`%x[...]`, backticks) as well
/// as quoted-arg sinks (`system`/`exec`/`spawn`, `IO.popen`, `Open3.*`). Each
/// payload carries the severity `detect_rm_rf_destructive` gives it (see
/// `ruby_exec_sink_match`), and only the blocking ones are returned.
fn scan_ruby_exec_sink_matches(code: &str, newline_positions: &[usize]) -> Vec<PatternMatch> {
    let mut out = Vec::new();
    let mut keep = |m: PatternMatch| {
        if m.severity.blocks_by_default() {
            out.push(m);
        }
    };

    // 1) `%x(...)` / `%x{...}` / `%x[...]` command-substitution literals and
    //    backticks: the payload IS the delimited text, not a nested string.
    for caps in RUBY_PERCENT_X_LITERAL.captures_iter(code) {
        let Some(m) = caps.get(0) else { continue };
        let cmd = ["cmd", "cmd2", "cmd3", "cmd4"]
            .iter()
            .find_map(|name| caps.name(name).map(|c| c.as_str()))
            .unwrap_or("");
        if let Some(hit) = detect_shell_payload(cmd) {
            keep(ruby_exec_sink_match(code, newline_positions, m, "%x", &hit));
        }
    }
    for caps in RUBY_BACKTICKS_LITERAL.captures_iter(code) {
        let Some(m) = caps.get(0) else { continue };
        let cmd = caps.name("cmd").map_or("", |c| c.as_str());
        if let Some(hit) = detect_shell_payload(cmd) {
            keep(ruby_exec_sink_match(
                code,
                newline_positions,
                m,
                "backticks",
                &hit,
            ));
        }
    }

    // 2) Quoted-arg sinks: `system`/`exec`/`spawn`, `IO.popen`, `Open3.*`. Scan
    //    the full balanced argument region so a payload nested in a list arg
    //    (`system("sh", "-c", "rm -rf /etc")`) is caught too.
    for caps in RUBY_QUOTED_EXEC_SINK_LITERAL.captures_iter(code) {
        let Some(m) = caps.get(0) else { continue };
        let arg_region = exec_sink_arg_region(code, m.start());
        if let Some(hit) = detect_destructive_in_args(arg_region) {
            let sink = caps.name("sink").map_or("exec", |s| s.as_str());
            keep(ruby_exec_sink_match(code, newline_positions, m, sink, &hit));
        }
    }

    out
}

fn ruby_exec_sink_match(
    code: &str,
    newline_positions: &[usize],
    m: regex::Match<'_>,
    sink: &str,
    hit: &ShellPayloadHit,
) -> PatternMatch {
    // Carry the payload's own severity, matching the generic sink pass above.
    //
    // This also read `_ => Severity::High`, on the stated grounds that the sink
    // unambiguously executes. It does — but a blanket escalation here overrode
    // the policy every other layer applies, and it made Ruby disagree with
    // JavaScript about the same argv-split shape. #455 has since settled that
    // policy once, in `detect_rm_rf_destructive`: a non-temp literal target is
    // `High` and blocks, a `/tmp` or `/var/tmp` target is `Medium` and does
    // not. Carrying that severity is how this pass follows it.
    let severity = hit.severity;
    let line_number = newline_positions.partition_point(|&idx| idx < m.start()) + 1;
    PatternMatch {
        rule_id: format!("heredoc.ruby.exec_sink.{}", hit.rule_suffix),
        reason: format!("{} via {sink} exec sink", hit.reason),
        matched_text_preview: truncate_preview(code.get(m.start()..m.end()).unwrap_or(""), 60),
        start: m.start(),
        end: m.end(),
        line_number,
        severity,
        suggestion: hit.suggestion.map(str::to_string),
    }
}

static RUBY_PERCENT_X_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    // Ruby command-substitution literal: %x(...), %x{...}, %x[...], %x<...>.
    // Capture the inner command text (single-line, no nesting of the same
    // delimiter — sufficient for the heredoc-body destructive-token scan).
    Regex::new(
        r"(?m)%x(?:\((?P<cmd>[^)\n]*)\)|\{(?P<cmd2>[^}\n]*)\}|\[(?P<cmd3>[^\]\n]*)\]|<(?P<cmd4>[^>\n]*)>)",
    )
    .expect("ruby %x literal regex compiles")
});

static RUBY_QUOTED_EXEC_SINK_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    // Quoted-arg Ruby exec sinks anchored on the sink NAME, with the destructive
    // payload search running over the call's full balanced argument region:
    //   system("rm -rf /etc") / Kernel.exec('…') / IO.popen("rm -rf /etc")
    //   Open3.capture2("rm -rf /etc") / Open3.popen3("…") / spawn("…")
    Regex::new(
        r#"(?m)\b(?:(?:Kernel|Process|IO|Open3)\.)?(?P<sink>system|exec|spawn|popen|capture2e|capture2|capture3|popen2e|popen2|popen3|pipeline_r|pipeline_rw|pipeline)\b(?:\s*\(\s*|\s+)(?:"[^"\n]*"|'[^'\n]*')"#,
    )
    .expect("ruby quoted exec sink regex compiles")
});

/// Where a statement can begin: line start, or just after a separator that
/// ends the previous one.
///
/// These two literals used to anchor at `^[ \t]*`, which fits a heredoc body
/// — where the call is the first thing on its line — and fits a `-e`/`-c`
/// one-liner not at all, because there the call follows `; `. They are the
/// backstop when AST matching times out, so for those two payload families a
/// timeout was an unconditional allow rather than a fallback (#452).
///
/// Line position was never the property worth requiring; *statement* position
/// is. It keeps what the anchor was actually protecting — prose and comments
/// that mention a call in passing ("never run `FileUtils.rm_rf('/')`") are
/// preceded by a word, not by a separator, so they still do not match — while
/// covering the one-liner. Both patterns additionally require a quoted string
/// argument, which already excludes a bare mention of the function name.
///
/// The residual false positive is a comment whose text puts the call right
/// after a separator, e.g. `# cleanup; FileUtils.rm_rf('/tmp/x')`. That is
/// narrower than the unanchored `\b` alternative, which would fire on every
/// passing mention.
const STATEMENT_START: &str = r"(?:^|[;&|{(]|=>|\bdo\b|\bthen\b)[ \t]*";

/// Two constraints on the `fn` alternation, both load-bearing (#454):
///
/// 1. **Every recursive deletion method must be listed explicitly.** The
///    trailing `\b` means a shorter name can never stand in for a longer one:
///    against `FileUtils.rm_r(`, the `rm` alternative matches but `\b` then has
///    to hold between `m` and `_`, and `_` is a word character. So `rm_r` was
///    unmatchable by construction while `rm_rf` blocked — dcg denied
///    `FileUtils.rm('/')`, which raises `Errno::EISDIR` on a directory, and
///    allowed `FileUtils.rm_r('/')`, which wipes it. Per Ruby's docs `rm_rf` is
///    just `rm_r` with `force: true`; the only difference is that `rm_rf`
///    swallows errors, so `rm_r` is what a script that checks for failure uses.
/// 2. **Longest-first ordering within each shared prefix.** `regex` prefers the
///    earliest alternative that yields an overall match, and `fn` is
///    interpolated straight into the rule id (`heredoc.ruby.fileutils_{fn}`).
///    A short-first list would therefore be a silent allowlist-breaking rule-id
///    change rather than a visible failure. The alternation is ordered by
///    descending length within each family so the requirement is checkable by
///    eye.
///
/// `rmdir` is included even though it removes only empty directories, because
/// `Dir.rmdir` — the call `FileUtils.rmdir` delegates to — already blocks on a
/// catastrophic target (`heredoc.ruby.dir_rmdir`). That is the same judgement
/// already applied to `FileUtils.rm('/')`, which raises rather than deleting:
/// a catastrophic literal target is treated as the signal, not the syscall's
/// likely outcome.
static RUBY_FILEUTILS_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?m){STATEMENT_START}FileUtils\.(?P<fn>rm_rf|rmdir|rm_r|rm_f|rm|remove_entry_secure|remove_entry|remove_file|remove_dir|remove)\b(?:\s*\(\s*|\s+)(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#
    ))
    .expect("ruby FileUtils literal regex compiles")
});

/// Name-anchored filesystem-delete sinks, the way [`JS_EXEC_SINK_LITERAL`] is
/// name-anchored for exec sinks.
///
/// The receiver is optional and may be a chain, so all three binding styles are
/// covered by one pattern: `fs.rmSync(p)`, an alias like `f.rmSync(p)`, the
/// `fs.promises.rm(p)` member spelling, and — the reason this changed — a
/// destructured import with NO receiver at all.
///
/// A metavariable in receiver position (`$FS.rmSync($$$)`) closed the aliased
/// spellings in the AST pass, but it structurally cannot match a call that has
/// no receiver, so `const { rmSync } = require('fs'); rmSync('/home/user',
/// {recursive: true})` and `import { rm } from 'node:fs/promises'` stayed
/// allowed at a catastrophic target (#459). Those are current idiomatic Node —
/// the `node:` prefix is the recommended form and destructuring is the default
/// style — so the guarded spellings were the older ones.
///
/// Over-matching is bounded exactly as before: the caller still requires a
/// catastrophic literal target, or `recursive: true` on a non-temp literal,
/// before this blocks. A user-defined `rm('./build')` therefore does not.
///
/// The receiver chain admits one leading **call**, because an identifier chain
/// alone could not express the chained `require('fs')` spelling: `fs.rmSync(p)`
/// matched while `require('fs').rmSync(p)` did not, so whenever the AST pass was
/// unavailable the chained form — the shorter one, and the one a `node -e`
/// one-liner actually writes — was allowed at a catastrophic target (#468). The
/// AST side already took a metavariable receiver for this reason; this is the
/// literal fallback catching up, the same omission in the same pair of lists.
///
/// The call's argument is restricted to a single quoted string rather than
/// anything at all. That keeps the group unambiguous with the identifier chain
/// after it — one requires parentheses, the other forbids them — so there is no
/// alternation for a crafted body to backtrack through. An ambiguous regex here
/// would fail OPEN at the backtrack limit, which is a bypass rather than a
/// slowdown.
static JS_FS_SINK_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?m){STATEMENT_START}(?:await[ \t]+)?(?:[A-Za-z_$][A-Za-z0-9_$]*\s*\(\s*(?:"[^"\n]*"|'[^'\n]*')\s*\)\s*\.\s*)?(?:[A-Za-z_$][A-Za-z0-9_$]*\s*\.\s*)*(?P<sink>rmdirSync|unlinkSync|rmSync|rm)\b\s*\(\s*(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#
    ))
    .expect("JavaScript filesystem sink literal regex compiles")
});

static JS_EXEC_SINK_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    // Any aliased/inline shell-exec sink called with a string literal:
    //   cp.execSync("rm -rf /etc") / exec('git reset --hard') / spawnSync("rm", ...
    //   execFile("sh", ["-c", "rm -rf /etc"]) / fork("rm -rf /etc")
    // Anchored on the sink method name, NOT the receiver, so aliasing is moot.
    // The destructive-payload search runs over the call's full balanced argument
    // region (`exec_sink_arg_region` + `detect_destructive_in_args`), so a payload
    // nested in the LIST arg of execFile/execFileSync/fork is caught even when the
    // first literal (`"sh"`) is inert (#136). Longer names precede their prefixes
    // (`execFileSync` before `execFile` before `exec`; `spawnSync` before `spawn`)
    // so the alternation picks the full sink.
    Regex::new(
        r#"(?m)\b(?P<sink>execFileSync|execFile|execSync|exec|spawnSync|spawn|fork)\s*\(\s*(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#,
    )
    .expect("js exec sink literal regex compiles")
});

/// The first string literal handed to a Python call, used to read the target
/// of `shutil.rmtree('…')` (#455).
static PY_FIRST_STRING_ARG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\(\s*(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#)
        .expect("python first string arg regex compiles")
});

/// A `tempfile` call whose result is a directory `tempfile` itself created.
///
/// `shutil.rmtree(tempfile.mkdtemp())` is the documented way to clean up after
/// `mkdtemp`, and blocking it is a false positive on the single most common
/// correct use of `rmtree` — the target is a fresh scratch directory by
/// construction, so it is exactly what `is_temp_scratch_path` means, reached
/// through a call rather than a literal (#455).
static PY_TEMPFILE_PRODUCED_DIR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:tempfile\s*\.\s*)?(?:mkdtemp|TemporaryDirectory)\s*\(")
        .expect("python tempfile-produced dir regex compiles")
});

/// The first string literal handed to a Go call, used to read the target of
/// `os.RemoveAll("…")` for #455's temp carve-out (#465).
///
/// Go spells a string two ways and both are idiomatic for paths: interpreted
/// (`"…"`) and raw (`` `…` ``). A raw literal is the natural choice on Windows
/// paths, so reading only the interpreted form would carve out
/// `os.RemoveAll("/tmp/build")` while still blocking
/// ``os.RemoveAll(`/tmp/build`)`` — the same target, one spelling apart.
static GO_FIRST_STRING_ARG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\(\s*(?:"(?P<dq>[^"\n]*)"|`(?P<raw>[^`]*)`)"#)
        .expect("go first string arg regex compiles")
});

static PY_EXEC_SINK_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    // Aliased/qualified Python shell sinks invoked as a call. Only the sink NAME
    // + opening paren is anchored here; the destructive-payload search runs over
    // the call's full balanced argument region (see `exec_sink_arg_region` +
    // `detect_destructive_in_args`), so it descends into list/tuple elements and
    // is not fooled by an inert first literal (#136). Longer names precede their
    // prefixes (`check_call` before `call`) so alternation picks the full sink.
    Regex::new(
        r"(?m)\b(?P<sink>system|popen|check_call|check_output|call|run|Popen|getoutput|getstatusoutput)\s*\(",
    )
    .expect("python exec sink literal regex compiles")
});

static RUBY_EXEC_SINK_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    // Aliased/qualified Ruby shell sinks with a string-literal first arg.
    Regex::new(
        r#"(?m)\b(?P<sink>system|exec|spawn)\b(?:\s*\(\s*|\s+)(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#,
    )
    .expect("ruby exec sink literal regex compiles")
});

static GO_EXEC_SINK_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    // Go's argv-split spawn, the shape `exec.Command("rm", "-rf", target)` has
    // and `os/exec` has no other. The package qualifier is optional because an
    // import alias (`import e "os/exec"`) is the aliasing case this scanner
    // exists for, and a bare `Command(` is what a dot-import produces. That
    // breadth costs nothing: a match only becomes a finding when
    // `detect_destructive_in_args` reads a destructive command out of the
    // call's own argument region, so `Command("hello")` is not a hit.
    // `CommandContext` precedes `Command` so alternation takes the full name.
    Regex::new(r"(?m)\b(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?(?P<sink>CommandContext|Command)\s*\(")
        .expect("go exec sink literal regex compiles")
});

static PHP_EXEC_SINK_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    // PHP's exec sinks. `pcntl_exec` is here and is NOT among the AST patterns
    // `is_php_exec_sink_rule` lists, which is the point: its payload reached no
    // layer at all. Longer names precede the prefixes they contain so
    // alternation cannot stop at `exec` inside `shell_exec`/`pcntl_exec`.
    Regex::new(r"(?m)\b(?P<sink>shell_exec|proc_open|pcntl_exec|passthru|popen|system|exec)\s*\(")
        .expect("php exec sink literal regex compiles")
});

#[allow(clippy::cast_possible_truncation)] // Timeout values are always small
fn timeout_error(start_time: Instant, budget_ms: u64) -> MatchError {
    MatchError::Timeout {
        elapsed_ms: start_time.elapsed().as_millis() as u64,
        budget_ms,
    }
}

fn check_ast_timeout(
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
    cancel: &AtomicBool,
) -> Result<(), MatchError> {
    if cancel.load(Ordering::Relaxed) || start_time.elapsed() > timeout {
        return Err(timeout_error(start_time, budget_ms));
    }
    Ok(())
}

fn run_ast_match_with_timeout(
    code: String,
    language: ScriptLanguage,
    ast_lang: SupportLang,
    patterns: Vec<PrecompiledPattern>,
    timeout: Duration,
    budget_ms: u64,
) -> Result<Vec<PatternMatch>, MatchError> {
    let start_time = Instant::now();
    let (tx, rx) = mpsc::sync_channel(1);
    // Shared cancellation flag: when the parent times out it flips this and
    // returns immediately. The worker checks it inside `check_ast_timeout`
    // (which fires between each pattern and between `find_all` iterations) so
    // it stops promptly instead of running for another full `timeout` window
    // after the parent has already returned. Without this, every parent
    // timeout leaks a live worker thread for the duration of the worker's
    // own deadline — under burst hook traffic that piles up.
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = Arc::clone(&cancel);

    // We don't `join` the handle on timeout — the worker may still hold a
    // tree-sitter parser mid-iteration and joining would block the hook past
    // its wall-clock deadline. The cancellation flag bounds the worker's own
    // wall clock so a leaked handle still terminates promptly on its next
    // `check_ast_timeout` call.
    let _worker = thread::Builder::new()
        .name("dcg-ast-match".to_string())
        .spawn(move || {
            // Share the parent's `start_time` semantics by also starting the
            // worker's deadline now; cancellation is the primary stop signal.
            let result = find_matches_ast(
                &code,
                language,
                ast_lang,
                &patterns,
                Instant::now(),
                timeout,
                budget_ms,
                &worker_cancel,
            );
            let _ = tx.send(result);
        })
        .map_err(|err| MatchError::ParseError {
            language,
            detail: format!("failed to start AST parser worker: {err}"),
        })?;

    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            cancel.store(true, Ordering::Relaxed);
            Err(timeout_error(start_time, budget_ms))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            cancel.store(true, Ordering::Relaxed);
            Err(MatchError::ParseError {
                language,
                detail: "AST parser worker exited without a result".to_string(),
            })
        }
    }
}

fn find_matches_ast(
    code: &str,
    language: ScriptLanguage,
    ast_lang: SupportLang,
    patterns: &[PrecompiledPattern],
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
    cancel: &AtomicBool,
) -> Result<Vec<PatternMatch>, MatchError> {
    let newline_positions: Vec<usize> = memchr_iter(b'\n', code.as_bytes()).collect();

    // Parse the code
    let ast = AstGrep::new(code, ast_lang);
    let root = ast.root();

    // Check timeout after parsing
    check_ast_timeout(start_time, timeout, budget_ms, cancel)?;

    let mut matches = Vec::new();

    // Match each pattern
    for compiled in patterns {
        // Check timeout before each pattern
        check_ast_timeout(start_time, timeout, budget_ms, cancel)?;

        // Find all matches for this pattern
        for node in root.find_all(&compiled.pattern) {
            // Check timeout during matching (a single pattern can match many nodes)
            check_ast_timeout(start_time, timeout, budget_ms, cancel)?;

            let matched_text = node.text();
            let range = node.range();

            // Calculate line number (1-based)
            let line_number = newline_positions.partition_point(|&idx| idx < range.start) + 1;

            // Create preview (truncate if too long, UTF-8 safe)
            let preview = truncate_preview(&matched_text, 60);

            let Some(refined) = refine_match_meta(language, &compiled.meta, &matched_text) else {
                continue;
            };

            matches.push(PatternMatch {
                rule_id: refined.rule_id,
                reason: refined.reason,
                matched_text_preview: preview,
                start: range.start,
                end: range.end,
                line_number,
                severity: refined.severity,
                suggestion: refined.suggestion,
            });
        }
    }

    Ok(matches)
}

/// Truncate a string to at most `max_chars` characters, UTF-8 safe.
///
/// If truncation occurs, appends "..." to indicate more content exists.
fn truncate_preview(text: &str, max_chars: usize) -> String {
    let char_count = text.chars().count();
    if char_count <= max_chars {
        text.to_string()
    } else {
        // Leave room for "..."
        let truncate_at = max_chars.saturating_sub(3);
        let truncated: String = text.chars().take(truncate_at).collect();
        format!("{truncated}...")
    }
}

/// Convert `ScriptLanguage` to ast-grep's `SupportLang`.
const fn script_language_to_ast_lang(lang: ScriptLanguage) -> Option<SupportLang> {
    match lang {
        ScriptLanguage::Python => Some(SupportLang::Python),
        ScriptLanguage::JavaScript => Some(SupportLang::JavaScript),
        ScriptLanguage::TypeScript => Some(SupportLang::TypeScript),
        ScriptLanguage::Ruby => Some(SupportLang::Ruby),
        ScriptLanguage::Bash => Some(SupportLang::Bash),
        ScriptLanguage::Go => Some(SupportLang::Go),
        ScriptLanguage::Php => Some(SupportLang::Php),
        ScriptLanguage::Perl | ScriptLanguage::Unknown => None,
    }
}

// ============================================================================
// Match refinement (payload / path analysis)
// ============================================================================

#[derive(Debug)]
struct RefinedMatchMeta {
    rule_id: String,
    reason: String,
    severity: Severity,
    suggestion: Option<String>,
}

static JS_RECURSIVE_TRUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)\brecursive\s*:\s*true\b").expect("js recursive:true regex compiles")
});

static JS_EXEC_SYNC_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    // Matches: execSync("...") / execSync('...')
    Regex::new(r#"(?m)\bexecSync\b\s*\(\s*(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#)
        .expect("js execSync literal regex compiles")
});

static JS_SPAWN_SYNC_CMD_ARGS: LazyLock<Regex> = LazyLock::new(|| {
    // Matches: spawnSync("cmd", [ ... ]) / spawnSync('cmd', [ ... ])
    Regex::new(
        r#"(?m)\bspawnSync\b\s*\(\s*(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')\s*,\s*\[(?P<args>[^\]]*)\]"#,
    )
    .expect("js spawnSync(cmd, [args]) regex compiles")
});

static JS_ARRAY_STRING_LITERALS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#)
        .expect("js array string literal regex compiles")
});

static JS_FIRST_STRING_ARG: LazyLock<Regex> = LazyLock::new(|| {
    // Captures the first string literal argument in a call expression.
    Regex::new(r#"(?m)\(\s*(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#)
        .expect("js first string arg regex compiles")
});

/// The path argument of an `fs` deletion call, anchored on the method name.
///
/// [`JS_FIRST_STRING_ARG`] takes the first string in the matched text, which
/// is the target only when the call is the whole match. For a chained
/// receiver — `require('fs').rmSync('/home/user', …)` — the first string is
/// the *module name*, so the path read as `"fs"`, `is_catastrophic_path` said
/// no, and the severity refinement left the hit warn-only. The rule matched
/// and the command was still allowed (#453).
static JS_FS_DELETE_PATH_ARG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?m)\.(?:rmSync|rmdirSync|unlinkSync|rm|rmdir|unlink)\s*\(\s*(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#,
    )
    .expect("js fs delete path arg regex compiles")
});

static RUBY_SYSTEM_EXEC_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    // Matches:
    // - system("...") / system '...'
    // - exec("...")   / exec '...'
    // - Kernel.system("...") / Kernel.exec("...")
    Regex::new(
        r#"(?m)\b(?:(?:Kernel|Process)\.)?(?P<call>system|exec)\b(?:\s*\(\s*|\s+)(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#,
    )
    .expect("ruby system/exec literal regex compiles")
});

static RUBY_BACKTICKS_LITERAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)`(?P<cmd>[^`\n]*)`").expect("ruby backticks regex compiles"));

static RUBY_FIRST_STRING_ARG: LazyLock<Regex> = LazyLock::new(|| {
    // Captures first string literal argument in Ruby call forms:
    // - foo("...") / foo('...')
    // - foo "..."  / foo '...'
    Regex::new(r#"(?m)(?:\(\s*|\s+)(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#)
        .expect("ruby first string arg regex compiles")
});

fn refine_match_meta(
    language: ScriptLanguage,
    meta: &CompiledPattern,
    matched_text: &str,
) -> Option<RefinedMatchMeta> {
    match language {
        ScriptLanguage::JavaScript => refine_javascript_match(meta, matched_text),
        ScriptLanguage::TypeScript => refine_typescript_match(meta, matched_text),
        ScriptLanguage::Ruby => refine_ruby_match(meta, matched_text),
        ScriptLanguage::Python => Some(refine_python_match(meta, matched_text)),
        ScriptLanguage::Go => Some(refine_go_match(meta, matched_text)),
        ScriptLanguage::Php => Some(refine_php_match(meta, matched_text)),
        _ => Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: meta.severity,
            suggestion: meta.suggestion.clone(),
        }),
    }
}

/// Refine a Python exec-sink match (#136).
///
/// Python shell sinks (`os.system`, `os.popen`, `subprocess.run/call/Popen`) are
/// registered at `Medium` severity so a bare, benign call (e.g.
/// `subprocess.run(["ls"])`) only warns. This refinement escalates the match to a
/// BLOCKING severity when the first string-literal argument is a genuinely
/// destructive shell command (`rm -rf …`, `git reset --hard`, …). This is what
/// lets the language-aware heredoc path stay authoritative for executing sinks:
/// an interpreter-stdin heredoc body whose only destructive token lives inside an
/// inert literal (e.g. `print("rm -rf x")`) is masked from the raw-shell rescan,
/// but a real `os.system("rm -rf /etc")` is caught right here.
///
/// Fail-safe: if the payload cannot be extracted as a literal (dynamic argument),
/// we keep the original `Medium` warn-only meta rather than dropping the match, so
/// the raw-shell rescan (when not masked) still has a chance to act.
fn refine_python_match(meta: &CompiledPattern, matched_text: &str) -> RefinedMatchMeta {
    let rule_id = meta.rule_id.as_str();

    // Exact ids, not a prefix test. A new exec-sink pattern that is not added
    // here registers at Medium and never escalates, so it warns on a real
    // `rm -rf` instead of blocking it — the pattern exists, the finding is
    // reported, and the command runs. #458 needed all three of the pattern
    // list, `PY_EXEC_SINK_LITERAL` and this set to agree, and
    // `every_python_exec_sink_escalates_a_destructive_payload_issue_458`
    // is what keeps them agreeing.
    let is_exec_sink = matches!(
        rule_id,
        "heredoc.python.os_system"
            | "heredoc.python.os_popen"
            | "heredoc.python.subprocess_run"
            | "heredoc.python.subprocess_call"
            | "heredoc.python.subprocess_popen"
            | "heredoc.python.subprocess_check_call"
            | "heredoc.python.subprocess_check_output"
    );

    let unchanged = || RefinedMatchMeta {
        rule_id: meta.rule_id.clone(),
        reason: meta.reason.clone(),
        severity: meta.severity,
        suggestion: meta.suggestion.clone(),
    };

    if is_exec_sink {
        // Scan *every* string literal in the call's argument list, descending
        // into list/tuple literal elements. This catches the list-arg form
        // `subprocess.run(["sh", "-c", "rm -rf /etc"])` whose first literal
        // (`"sh"`) is inert but which genuinely executes `rm -rf` (#136).
        if let Some(hit) = detect_destructive_in_args(matched_text) {
            // A destructive shell command is being executed. Escalate to at
            // least High so the AST path blocks even for non-catastrophic
            // targets (the sink unambiguously runs `rm -rf`/`git reset`).
            let severity = match hit.severity {
                Severity::Critical => Severity::Critical,
                _ => Severity::High,
            };
            return RefinedMatchMeta {
                rule_id: format!("{rule_id}.{}", hit.rule_suffix),
                reason: hit.reason.to_string(),
                severity,
                suggestion: hit.suggestion.map(str::to_string),
            };
        }

        // Dynamic / non-destructive payload: keep warn-only meta (fail-open).
        return unchanged();
    }

    // #455: `shutil.rmtree` is the one recursive delete that blocked a target
    // under /tmp, which `rm -rf /tmp/build` has always allowed. It is also the
    // rule that blocked `shutil.rmtree(tempfile.mkdtemp())` — the documented
    // way to clean up after `mkdtemp`, and a false positive on the most common
    // correct use of the function. Both are the temp carve-out the other
    // languages get; nothing else about the rule changes, so a literal outside
    // /tmp and a target this cannot read both stay Critical.
    if is_recursive_delete_rule(rule_id) {
        let path = PY_FIRST_STRING_ARG
            .captures(matched_text)
            .and_then(|caps| string_literal_from_caps(&caps));
        let targets_scratch = path.is_some_and(is_temp_scratch_path)
            || (path.is_none() && PY_TEMPFILE_PRODUCED_DIR.is_match(matched_text));
        if targets_scratch {
            return RefinedMatchMeta {
                rule_id: format!("{rule_id}.temp"),
                reason: format!("{} (target is a temp directory)", meta.reason),
                severity: Severity::Medium,
                suggestion: meta.suggestion.clone(),
            };
        }
    }

    unchanged()
}

/// Give Go's recursive delete the same temp carve-out every other language has.
///
/// Repairing the Go patterns (#465) turned six rules that matched nothing into
/// rules that match unconditionally, which newly exposed the benign half of
/// `os.RemoveAll`. Measuring each shape against its Python twin — Python being
/// the established #455 policy, not a guess — found exactly one disagreement:
///
/// | shape                                   | Python | Go before |
/// |-----------------------------------------|--------|-----------|
/// | literal `/tmp/build`                    | allow  | **deny**  |
/// | producer nested in the call              | allow  | n/a       |
/// | producer on a previous line              | deny   | deny      |
/// | temp *root* (`gettempdir`/`os.TempDir`)  | deny   | deny      |
/// | `/tmp/../home/u` traversal               | deny   | deny      |
///
/// So only the literal target needs the carve-out. The rest already agree and
/// are left alone:
///
/// - The two-statement idiom (`dir, _ := os.MkdirTemp(…)` then
///   `defer os.RemoveAll(dir)`) keeps blocking. `matched_text` is the call node
///   alone, so the producer on the previous line is not visible here, and
///   proving `dir` still holds that value needs taint analysis this scanner
///   deliberately does not do. Python blocks its own two-statement spelling for
///   the same reason, so Go blocking it is the established posture rather than a
///   Go-specific wart. It is also the fail-safe direction.
/// - `os.RemoveAll(os.TempDir())` keeps blocking: that is the temp *root*, not a
///   directory this program created, and Python denies `tempfile.gettempdir()`
///   for the same reason. Go cannot nest its producer the way Python can —
///   `os.MkdirTemp` returns `(string, error)` — so the nested shape #455 carved
///   out has no valid Go spelling to carve.
///
/// Fail-safe: an unreadable (dynamic) target keeps the original Critical meta.
fn refine_go_match(meta: &CompiledPattern, matched_text: &str) -> RefinedMatchMeta {
    let unchanged = || RefinedMatchMeta {
        rule_id: meta.rule_id.clone(),
        reason: meta.reason.clone(),
        severity: meta.severity,
        suggestion: meta.suggestion.clone(),
    };

    // Exact ids, not a prefix test, for the reason `refine_python_match` gives:
    // an exec-sink pattern missing from this set registers at Medium and never
    // escalates, so it warns on a real `rm -rf` and the command still runs.
    // That is what all four of these did until #472 — Go registered the
    // patterns, reported the finding, and allowed the command, while every
    // other language denied the same payload.
    //
    // `detect_destructive_in_args` already reads a call's literals back as the
    // argv they are, and its own docstring names `exec.Command("rm","-rf","/x")`
    // as a shape it handles; nothing had ever called it for Go.
    if is_go_exec_sink_rule(&meta.rule_id) {
        if let Some(hit) = detect_destructive_in_args(matched_text) {
            // Escalate to at least High so the AST path blocks even for a
            // non-catastrophic target: the sink unambiguously runs the command.
            let severity = match hit.severity {
                Severity::Critical => Severity::Critical,
                _ => Severity::High,
            };
            return RefinedMatchMeta {
                rule_id: format!("{}.{}", meta.rule_id, hit.rule_suffix),
                reason: hit.reason.to_string(),
                severity,
                suggestion: hit.suggestion.map(str::to_string),
            };
        }

        // Dynamic / non-destructive payload: keep warn-only meta (fail-open).
        return unchanged();
    }

    if !is_recursive_delete_rule(&meta.rule_id) {
        return unchanged();
    }

    let path = GO_FIRST_STRING_ARG.captures(matched_text).and_then(|caps| {
        caps.name("dq")
            .or_else(|| caps.name("raw"))
            .map(|found| found.as_str())
    });
    if path.is_some_and(is_temp_scratch_path) {
        return RefinedMatchMeta {
            rule_id: format!("{}.temp", meta.rule_id),
            reason: format!("{} (target is a temp directory)", meta.reason),
            severity: Severity::Medium,
            suggestion: meta.suggestion.clone(),
        };
    }

    unchanged()
}

/// Refine a PHP exec-sink match (#473).
///
/// PHP had no refinement of any kind: `refine_match_meta` fell through to the
/// catch-all that returns the meta unchanged, and all seven exec sinks register
/// at `Medium`. PHP is also scoped out of the exec-sink backstop, on the same
/// "uses its own primary path" ground #472 corrected for Go. So nothing in
/// PHP's own path could ever block, and every PHP exec denial came from the
/// raw-shell rescan finding contiguous destructive text — under
/// `core.filesystem:rm-rf-root-home`, never under the `heredoc.php.*` rule
/// `docs/patterns.md` tabulates.
///
/// Two shapes carry no contiguous text and were allowed outright: the PHP 7.4+
/// argv array `proc_open(["rm","-rf","/etc"], …)`, and a concatenated payload
/// `system("rm" . " -rf" . " /etc")`. `detect_destructive_in_args` reads a
/// call's literals both individually and as the argv they are, which is exactly
/// the pair of views those two shapes need.
///
/// Backticks are deliberately not in the sink set. `` `rm -rf /etc` `` carries
/// no quoted literal for `ANY_STRING_LITERAL` to read, and PHP's backtick
/// operator takes one interpolated string rather than an argument list, so it
/// has neither an argv nor a concatenation form to escape through. Adding it
/// would be a no-op dressed as coverage.
///
/// Fail-safe: a dynamic payload (`system($cmd)`) keeps the warn-only meta.
fn refine_php_match(meta: &CompiledPattern, matched_text: &str) -> RefinedMatchMeta {
    let unchanged = || RefinedMatchMeta {
        rule_id: meta.rule_id.clone(),
        reason: meta.reason.clone(),
        severity: meta.severity,
        suggestion: meta.suggestion.clone(),
    };

    if !is_php_exec_sink_rule(&meta.rule_id) {
        return unchanged();
    }

    let Some(hit) = detect_destructive_in_args(matched_text) else {
        return unchanged();
    };

    // Escalate to at least High so the AST path blocks even for a
    // non-catastrophic target: the sink unambiguously runs the command.
    let severity = match hit.severity {
        Severity::Critical => Severity::Critical,
        _ => Severity::High,
    };
    RefinedMatchMeta {
        rule_id: format!("{}.{}", meta.rule_id, hit.rule_suffix),
        reason: hit.reason.to_string(),
        severity,
        suggestion: hit.suggestion.map(str::to_string),
    }
}

fn refine_javascript_match(meta: &CompiledPattern, matched_text: &str) -> Option<RefinedMatchMeta> {
    let rule_id = meta.rule_id.as_str();

    if matches!(
        rule_id,
        "heredoc.javascript.execsync" | "heredoc.javascript.require_execsync"
    ) {
        let payload = JS_EXEC_SYNC_LITERAL
            .captures(matched_text)
            .and_then(|caps| string_literal_from_caps(&caps));

        if let Some(payload) = payload {
            return detect_shell_payload(payload).map(|hit| RefinedMatchMeta {
                rule_id: format!("{rule_id}.{}", hit.rule_suffix),
                reason: hit.reason.to_string(),
                severity: hit.severity,
                suggestion: hit.suggestion.map(str::to_string),
            });
        }

        // Dynamic payloads: warn only (fail-open).
        return Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: meta.severity,
            suggestion: meta.suggestion.clone(),
        });
    }

    if rule_id == "heredoc.javascript.spawnsync" {
        if let Some(caps) = JS_SPAWN_SYNC_CMD_ARGS.captures(matched_text) {
            let cmd = string_literal_from_caps(&caps).unwrap_or("");
            let args = caps.name("args").map_or("", |m| m.as_str());
            let args: Vec<&str> = JS_ARRAY_STRING_LITERALS
                .captures_iter(args)
                .filter_map(|caps| string_literal_from_caps(&caps))
                .collect();

            if let Some(argv) = spawn_argv(cmd, &args) {
                return detect_argv_payload(&argv).map(|hit| RefinedMatchMeta {
                    rule_id: format!("{rule_id}.{}", hit.rule_suffix),
                    reason: hit.reason.to_string(),
                    severity: hit.severity,
                    suggestion: hit.suggestion.map(str::to_string),
                });
            }

            return None;
        }

        // Dynamic spawnSync: warn only.
        return Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: Severity::Medium,
            suggestion: meta.suggestion.clone(),
        });
    }

    if rule_id.starts_with("heredoc.javascript.fs_") {
        // Prefer the argument of the deletion call itself; fall back to the
        // first string only when the method-anchored form finds nothing.
        let path = JS_FS_DELETE_PATH_ARG
            .captures(matched_text)
            .or_else(|| JS_FIRST_STRING_ARG.captures(matched_text))
            .and_then(|caps| string_literal_from_caps(&caps));

        let recursive_relevant = JS_RECURSIVE_TRUE.is_match(matched_text);
        let catastrophic = path.is_some_and(is_catastrophic_path);

        // For fs.rm* / fs.rmdir* we only care about recursive deletion (or catastrophic literal paths).
        let needs_recursive = matches!(
            rule_id,
            "heredoc.javascript.fs_rmsync"
                | "heredoc.javascript.fs_rmdirsync"
                | "heredoc.javascript.fs_rm"
                | "heredoc.javascript.fs_rmdir"
        );

        if needs_recursive && !recursive_relevant && !catastrophic {
            return None;
        }

        if catastrophic {
            return Some(RefinedMatchMeta {
                rule_id: format!("{rule_id}.catastrophic"),
                reason: format!("{} (catastrophic target path)", meta.reason),
                severity: Severity::Critical,
                suggestion: meta.suggestion.clone(),
            });
        }

        // #455: only when the call actually recurses. `fs.rmSync('./a.txt')`
        // with no `recursive: true` deletes one file and is left alone; the
        // `{recursive: true}` form destroys a tree the way `rm -rf` does.
        if recursive_relevant && is_recursive_delete_rule(rule_id) {
            if let Some(refined) = recursive_delete_refinement(meta, path) {
                return Some(refined);
            }
        }

        return Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: Severity::Medium,
            suggestion: meta.suggestion.clone(),
        });
    }

    Some(RefinedMatchMeta {
        rule_id: meta.rule_id.clone(),
        reason: meta.reason.clone(),
        severity: meta.severity,
        suggestion: meta.suggestion.clone(),
    })
}

fn refine_typescript_match(meta: &CompiledPattern, matched_text: &str) -> Option<RefinedMatchMeta> {
    let rule_id = meta.rule_id.as_str();

    if matches!(
        rule_id,
        "heredoc.typescript.execsync" | "heredoc.typescript.require_execsync"
    ) {
        let payload = JS_EXEC_SYNC_LITERAL
            .captures(matched_text)
            .and_then(|caps| string_literal_from_caps(&caps));

        if let Some(payload) = payload {
            return detect_shell_payload(payload).map(|hit| RefinedMatchMeta {
                rule_id: format!("{rule_id}.{}", hit.rule_suffix),
                reason: hit.reason.to_string(),
                severity: hit.severity,
                suggestion: hit.suggestion.map(str::to_string),
            });
        }

        return Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: Severity::Medium,
            suggestion: meta.suggestion.clone(),
        });
    }

    if rule_id == "heredoc.typescript.spawnsync" {
        if let Some(caps) = JS_SPAWN_SYNC_CMD_ARGS.captures(matched_text) {
            let cmd = string_literal_from_caps(&caps).unwrap_or("");
            let args = caps.name("args").map_or("", |m| m.as_str());
            let args: Vec<&str> = JS_ARRAY_STRING_LITERALS
                .captures_iter(args)
                .filter_map(|caps| string_literal_from_caps(&caps))
                .collect();

            if let Some(argv) = spawn_argv(cmd, &args) {
                return detect_argv_payload(&argv).map(|hit| RefinedMatchMeta {
                    rule_id: format!("{rule_id}.{}", hit.rule_suffix),
                    reason: hit.reason.to_string(),
                    severity: hit.severity,
                    suggestion: hit.suggestion.map(str::to_string),
                });
            }

            return None;
        }

        return Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: Severity::Medium,
            suggestion: meta.suggestion.clone(),
        });
    }

    if rule_id.starts_with("heredoc.typescript.fs_") || rule_id == "heredoc.typescript.deno_remove"
    {
        // Prefer the argument of the deletion call itself; fall back to the
        // first string only when the method-anchored form finds nothing.
        let path = JS_FS_DELETE_PATH_ARG
            .captures(matched_text)
            .or_else(|| JS_FIRST_STRING_ARG.captures(matched_text))
            .and_then(|caps| string_literal_from_caps(&caps));

        let recursive_relevant = JS_RECURSIVE_TRUE.is_match(matched_text);
        let catastrophic = path.is_some_and(is_catastrophic_path);

        let needs_recursive = matches!(
            rule_id,
            "heredoc.typescript.fs_rmsync"
                | "heredoc.typescript.fs_rmdirsync"
                | "heredoc.typescript.fs_rm"
                | "heredoc.typescript.fs_rmdir"
                | "heredoc.typescript.deno_remove"
        );

        if needs_recursive && !recursive_relevant && !catastrophic {
            return None;
        }

        if catastrophic {
            return Some(RefinedMatchMeta {
                rule_id: format!("{rule_id}.catastrophic"),
                reason: format!("{} (catastrophic target path)", meta.reason),
                severity: Severity::Critical,
                suggestion: meta.suggestion.clone(),
            });
        }

        // #455, same rule as the JavaScript arm above.
        if recursive_relevant && is_recursive_delete_rule(rule_id) {
            if let Some(refined) = recursive_delete_refinement(meta, path) {
                return Some(refined);
            }
        }

        return Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: meta.severity,
            suggestion: meta.suggestion.clone(),
        });
    }

    Some(RefinedMatchMeta {
        rule_id: meta.rule_id.clone(),
        reason: meta.reason.clone(),
        severity: meta.severity,
        suggestion: meta.suggestion.clone(),
    })
}

fn refine_ruby_match(meta: &CompiledPattern, matched_text: &str) -> Option<RefinedMatchMeta> {
    let rule_id = meta.rule_id.as_str();

    if matches!(
        rule_id,
        "heredoc.ruby.system"
            | "heredoc.ruby.exec"
            | "heredoc.ruby.kernel_system"
            | "heredoc.ruby.kernel_exec"
            | "heredoc.ruby.backticks"
            | "heredoc.ruby.open3_capture3"
            | "heredoc.ruby.open3_popen3"
    ) {
        let payload = if rule_id == "heredoc.ruby.backticks" {
            RUBY_BACKTICKS_LITERAL
                .captures(matched_text)
                .and_then(|caps| caps.name("cmd").map(|m| m.as_str()))
        } else if rule_id.starts_with("heredoc.ruby.open3_") {
            // Open3 methods take the command as first argument
            RUBY_FIRST_STRING_ARG
                .captures(matched_text)
                .and_then(|caps| string_literal_from_caps(&caps))
        } else {
            RUBY_SYSTEM_EXEC_LITERAL
                .captures(matched_text)
                .and_then(|caps| string_literal_from_caps(&caps))
        };

        if let Some(payload) = payload {
            return detect_shell_payload(payload).map(|hit| RefinedMatchMeta {
                rule_id: format!("{rule_id}.{}", hit.rule_suffix),
                reason: hit.reason.to_string(),
                severity: hit.severity,
                suggestion: hit.suggestion.map(str::to_string),
            });
        }

        // Dynamic system/exec/backticks/Open3: warn only (couldn't extract literal command).
        return Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: Severity::Medium,
            suggestion: meta.suggestion.clone(),
        });
    }

    if rule_id.starts_with("heredoc.ruby.fileutils_")
        || rule_id.starts_with("heredoc.ruby.file_")
        || rule_id.starts_with("heredoc.ruby.dir_")
    {
        let path = RUBY_FIRST_STRING_ARG
            .captures(matched_text)
            .and_then(|caps| string_literal_from_caps(&caps));

        let catastrophic = path.is_some_and(is_catastrophic_path);
        if catastrophic {
            return Some(RefinedMatchMeta {
                rule_id: format!("{rule_id}.catastrophic"),
                reason: format!("{} (catastrophic target path)", meta.reason),
                severity: Severity::Critical,
                suggestion: meta.suggestion.clone(),
            });
        }

        // #455: a recursive delete of a literal path outside /tmp is the same
        // operation `rm -rf ./build` is, and that blocks. Non-recursive
        // FileUtils calls and dynamic targets fall through to warn-only.
        if is_recursive_delete_rule(rule_id) {
            if let Some(refined) = recursive_delete_refinement(meta, path) {
                return Some(refined);
            }
        }

        return Some(RefinedMatchMeta {
            rule_id: meta.rule_id.clone(),
            reason: meta.reason.clone(),
            severity: Severity::Medium,
            suggestion: meta.suggestion.clone(),
        });
    }

    Some(RefinedMatchMeta {
        rule_id: meta.rule_id.clone(),
        reason: meta.reason.clone(),
        severity: meta.severity,
        suggestion: meta.suggestion.clone(),
    })
}

/// `spawnSync(cmd, args)` as the argv the child receives, for
/// `detect_argv_payload`. `None` for an empty command.
fn spawn_argv<'a>(cmd: &'a str, args: &[&'a str]) -> Option<Vec<&'a str>> {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return None;
    }
    Some(std::iter::once(cmd).chain(args.iter().copied()).collect())
}

// ============================================================================
// Perl regex fallback ast_matcher (git_safety_guard-2d4)
// ============================================================================

static PERL_SYSTEM_EXEC_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    // Matches:
    // - system("...") / system '...'
    // - exec("...")   / exec '...'
    //
    // We intentionally only match *simple single-line* string literals to keep signal high.
    Regex::new(
        r#"(?m)\b(?P<call>system|exec)\b(?:\s*\(\s*|\s+)(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#,
    )
    .expect("perl system/exec literal regex compiles")
});

static PERL_BACKTICKS_LITERAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)`(?P<cmd>[^`\n]*)`").expect("perl backticks regex compiles"));

static PERL_QX_SLASH_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    // Matches qx/.../ (slash delimiter only, v1).
    Regex::new(r"(?m)\bqx\s*/(?P<cmd>(?:\\.|[^/\n])*)/").expect("perl qx// regex compiles")
});

/// The `File::Path::` qualifier is optional because the documented way to use
/// this module imports the function and calls it bare (#453):
///
/// ```perl
/// use File::Path qw(rmtree);
/// rmtree('/home/user');
/// ```
///
/// Requiring the qualifier caught only the rarer spelling: `File::Path::rmtree`
/// blocked while the idiomatic `rmtree` was allowed, at every target including
/// catastrophic ones. `unlink` and `rmdir` below are already matched bare, so
/// the qualifier was also the odd convention out within this file.
///
/// A bare `rmtree`/`remove_tree` is still specific enough to key on: these names
/// are not Perl builtins, the scan only ever runs on an extracted Perl body with
/// comments masked, and the call must open with a quoted string or with the
/// legacy interface's array reference (`rmtree(['/a', '/b'])`), whose paths the
/// scan then requires to include a literal.
static PERL_FILE_PATH_RMTREE_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)\b(?:File::Path::)?(?P<fn>rmtree|remove_tree)\b(?:\s*\(\s*|\s+)["'\[]"#)
        .expect("perl File::Path rmtree/remove_tree regex compiles")
});

static PERL_UNLINK_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)\bunlink\b(?:\s*\(\s*|\s+)(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#)
        .expect("perl unlink regex compiles")
});

static PERL_RMDIR_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)\brmdir\b(?:\s*\(\s*|\s+)(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')"#)
        .expect("perl rmdir regex compiles")
});

fn precompile_perl_patterns() {
    // Perl uses the bounded regex fallback rather than ast-grep. Compile its
    // fixed patterns while constructing the matcher so first-use compilation
    // cannot consume the per-match timeout and turn a valid first Perl scan
    // into a tier-local timeout. Construction remains covered by the caller's
    // absolute hook deadline.
    LazyLock::force(&PERL_SYSTEM_EXEC_LITERAL);
    LazyLock::force(&PERL_BACKTICKS_LITERAL);
    LazyLock::force(&PERL_QX_SLASH_LITERAL);
    LazyLock::force(&PERL_FILE_PATH_RMTREE_LITERAL);
    LazyLock::force(&PERL_UNLINK_LITERAL);
    LazyLock::force(&PERL_RMDIR_LITERAL);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PerlShellCall {
    System,
    Exec,
    Backticks,
    Qx,
}

impl PerlShellCall {
    #[must_use]
    const fn id_prefix(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Exec => "exec",
            Self::Backticks => "backticks",
            Self::Qx => "qx",
        }
    }
}

#[derive(Clone, Copy)]
enum PerlCommentState {
    Normal,
    Single,
    Double,
    Backtick,
}

fn find_matches_perl(
    code: &str,
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
) -> Result<Vec<PatternMatch>, MatchError> {
    let newline_positions: Vec<usize> = memchr_iter(b'\n', code.as_bytes()).collect();
    let masked = mask_perl_comments(code);
    let haystack = masked.as_ref();

    let mut matches = Vec::new();

    scan_perl_system_exec(
        &mut matches,
        code,
        haystack,
        &newline_positions,
        start_time,
        timeout,
        budget_ms,
    )?;
    scan_perl_backticks(
        &mut matches,
        code,
        haystack,
        &newline_positions,
        start_time,
        timeout,
        budget_ms,
    )?;
    scan_perl_qx(
        &mut matches,
        code,
        haystack,
        &newline_positions,
        start_time,
        timeout,
        budget_ms,
    )?;
    scan_perl_file_path(
        &mut matches,
        code,
        haystack,
        &newline_positions,
        start_time,
        timeout,
        budget_ms,
    )?;
    scan_perl_unlink_rmdir(
        &mut matches,
        code,
        haystack,
        &newline_positions,
        start_time,
        timeout,
        budget_ms,
    )?;

    Ok(matches)
}

#[inline]
fn perl_check_timeout(
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
) -> Result<(), MatchError> {
    if start_time.elapsed() > timeout {
        let elapsed_ms = u64::try_from(start_time.elapsed().as_millis()).unwrap_or(u64::MAX);
        return Err(MatchError::Timeout {
            elapsed_ms,
            budget_ms,
        });
    }
    Ok(())
}

fn scan_perl_system_exec(
    out: &mut Vec<PatternMatch>,
    code: &str,
    haystack: &str,
    newline_positions: &[usize],
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
) -> Result<(), MatchError> {
    for caps in PERL_SYSTEM_EXEC_LITERAL.captures_iter(haystack) {
        perl_check_timeout(start_time, timeout, budget_ms)?;
        let Some(m) = caps.get(0) else {
            continue;
        };

        let call = caps.name("call").map_or("", |m| m.as_str());
        let call = match call {
            "system" => PerlShellCall::System,
            "exec" => PerlShellCall::Exec,
            _ => continue,
        };

        // The whole argument list, not just the first literal. `system('rm',
        // '-rf', '/')` is Perl's argv form, whose first literal `rm` flags
        // nothing on its own, so reading only that literal left every
        // argv-form `system`/`exec` unguarded — a `/` target included — while
        // the one-string form blocked. JavaScript, Python and Ruby already
        // read the list this way.
        let region = exec_sink_arg_region(haystack, m.start());
        let Some(hit) = detect_destructive_in_args(region) else {
            continue;
        };

        push_perl_shell_hit(
            out,
            code,
            newline_positions,
            call,
            &hit,
            m.start(),
            m.start() + region.len(),
        );
    }

    Ok(())
}

fn scan_perl_backticks(
    out: &mut Vec<PatternMatch>,
    code: &str,
    haystack: &str,
    newline_positions: &[usize],
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
) -> Result<(), MatchError> {
    for caps in PERL_BACKTICKS_LITERAL.captures_iter(haystack) {
        perl_check_timeout(start_time, timeout, budget_ms)?;
        let Some(m) = caps.get(0) else {
            continue;
        };
        let Some(payload) = caps.name("cmd").map(|m| m.as_str()) else {
            continue;
        };

        push_perl_shell_payload_match(
            out,
            code,
            newline_positions,
            PerlShellCall::Backticks,
            payload,
            m.start(),
            m.end(),
        );
    }

    Ok(())
}

fn scan_perl_qx(
    out: &mut Vec<PatternMatch>,
    code: &str,
    haystack: &str,
    newline_positions: &[usize],
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
) -> Result<(), MatchError> {
    for caps in PERL_QX_SLASH_LITERAL.captures_iter(haystack) {
        perl_check_timeout(start_time, timeout, budget_ms)?;
        let Some(m) = caps.get(0) else {
            continue;
        };
        let Some(payload) = caps.name("cmd").map(|m| m.as_str()) else {
            continue;
        };

        push_perl_shell_payload_match(
            out,
            code,
            newline_positions,
            PerlShellCall::Qx,
            unescape_perl_qx_payload(payload).as_ref(),
            m.start(),
            m.end(),
        );
    }

    Ok(())
}

fn unescape_perl_qx_payload(payload: &str) -> std::borrow::Cow<'_, str> {
    if payload.contains("\\/") {
        return std::borrow::Cow::Owned(payload.replace("\\/", "/"));
    }
    std::borrow::Cow::Borrowed(payload)
}

fn scan_perl_file_path(
    out: &mut Vec<PatternMatch>,
    code: &str,
    haystack: &str,
    newline_positions: &[usize],
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
) -> Result<(), MatchError> {
    for caps in PERL_FILE_PATH_RMTREE_LITERAL.captures_iter(haystack) {
        perl_check_timeout(start_time, timeout, budget_ms)?;
        let Some(m) = caps.get(0) else {
            continue;
        };
        // Every path the call deletes, not just the first. Both interfaces take
        // several — `rmtree('/a', '/b')` and the legacy `rmtree(['/a', '/b'],
        // $verbose, $safe)` — and weighing only the first let a temp decoy
        // launder the rest: `rmtree('/tmp/x', '/')` was allowed, and so was
        // `rmtree(['/'])`, since the array form matched nothing at all. The
        // region stops at an options hash (`{ keep_root => 1 }`), whose
        // strings are not paths.
        let region = exec_argv_region(exec_sink_arg_region(haystack, m.start()));
        let paths: Vec<&str> = ANY_STRING_LITERAL
            .captures_iter(region)
            .filter_map(|caps| string_literal_from_caps(&caps))
            .collect();
        if paths.is_empty() {
            continue;
        }
        let fn_name = caps.name("fn").map_or("rmtree", |m| m.as_str());

        // #455: `rmtree`/`remove_tree` are Perl's recursive delete, so they get
        // the same single policy as `rm -rf`, `shutil.rmtree`, `FileUtils.rm_rf`
        // and `fs.rmSync({recursive})` — a literal target outside /tmp blocks.
        // The issue left Perl out of its table only because #453 was open on
        // coverage; the policy question is the same one.
        let catastrophic = paths.iter().any(|path| is_catastrophic_path(path));
        let non_temp = !catastrophic && !paths.iter().all(|path| is_temp_scratch_path(path));
        let severity = if catastrophic || non_temp {
            Severity::Critical
        } else {
            Severity::Medium
        };

        let rule_id = if non_temp {
            format!("heredoc.perl.file_path.{fn_name}.non_temp")
        } else {
            format!("heredoc.perl.file_path.{fn_name}")
        };
        let reason = if non_temp {
            format!(
                "File::Path::{fn_name}() recursively deletes directories outside a temp directory"
            )
        } else {
            format!("File::Path::{fn_name}() recursively deletes directories")
        };

        push_regex_match(
            out,
            code,
            newline_positions,
            &rule_id,
            &reason,
            severity,
            Some("Verify target path carefully before running".to_string()),
            m.start(),
            m.end(),
        );
    }

    Ok(())
}

fn scan_perl_unlink_rmdir(
    out: &mut Vec<PatternMatch>,
    code: &str,
    haystack: &str,
    newline_positions: &[usize],
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
) -> Result<(), MatchError> {
    for caps in PERL_UNLINK_LITERAL.captures_iter(haystack) {
        perl_check_timeout(start_time, timeout, budget_ms)?;
        let Some(m) = caps.get(0) else {
            continue;
        };
        // Only match string-literal unlink; warn-only by default.
        //
        // #455's smaller half: a catastrophic literal target blocks, the way
        // Ruby's `File.delete('/etc/passwd')` already does. Neither call
        // recurses, so this is the catastrophic-target rule and not the
        // recursive-delete one — `unlink('./a.txt')` stays warn-only.
        let catastrophic = string_literal_from_caps(&caps).is_some_and(is_catastrophic_path);
        push_regex_match(
            out,
            code,
            newline_positions,
            if catastrophic {
                "heredoc.perl.unlink.catastrophic"
            } else {
                "heredoc.perl.unlink"
            },
            if catastrophic {
                "unlink() deletes files (catastrophic target path)"
            } else {
                "unlink() deletes files"
            },
            if catastrophic {
                Severity::Critical
            } else {
                Severity::Low
            },
            None,
            m.start(),
            m.end(),
        );
    }

    for caps in PERL_RMDIR_LITERAL.captures_iter(haystack) {
        perl_check_timeout(start_time, timeout, budget_ms)?;
        let Some(m) = caps.get(0) else {
            continue;
        };
        // Same as `unlink` above: `Dir.rmdir('/')` and `os.rmdir('/')` both
        // block, and Perl's spelling did not (#455).
        let catastrophic = string_literal_from_caps(&caps).is_some_and(is_catastrophic_path);
        push_regex_match(
            out,
            code,
            newline_positions,
            if catastrophic {
                "heredoc.perl.rmdir.catastrophic"
            } else {
                "heredoc.perl.rmdir"
            },
            if catastrophic {
                "rmdir() deletes directories (catastrophic target path)"
            } else {
                "rmdir() deletes directories"
            },
            if catastrophic {
                Severity::Critical
            } else {
                Severity::Low
            },
            None,
            m.start(),
            m.end(),
        );
    }

    Ok(())
}

fn mask_perl_comments(code: &str) -> std::borrow::Cow<'_, str> {
    if !code.as_bytes().contains(&b'#') {
        return std::borrow::Cow::Borrowed(code);
    }

    let mut out = code.as_bytes().to_vec();
    let mut state = PerlCommentState::Normal;
    let mut i = 0usize;

    while i < out.len() {
        match state {
            PerlCommentState::Normal => match out[i] {
                b'#' => {
                    // Mask until newline (keep newline itself).
                    let start = i;
                    while i < out.len() && out[i] != b'\n' {
                        i += 1;
                    }
                    for b in &mut out[start..i] {
                        *b = b' ';
                    }
                }
                b'\'' => {
                    state = PerlCommentState::Single;
                    i += 1;
                }
                b'"' => {
                    state = PerlCommentState::Double;
                    i += 1;
                }
                b'`' => {
                    state = PerlCommentState::Backtick;
                    i += 1;
                }
                _ => i += 1,
            },
            PerlCommentState::Single => {
                if out[i] == b'\\' {
                    i = (i + 2).min(out.len());
                    continue;
                }
                if out[i] == b'\'' {
                    state = PerlCommentState::Normal;
                }
                i += 1;
            }
            PerlCommentState::Double => {
                if out[i] == b'\\' {
                    i = (i + 2).min(out.len());
                    continue;
                }
                if out[i] == b'"' {
                    state = PerlCommentState::Normal;
                }
                i += 1;
            }
            PerlCommentState::Backtick => {
                if out[i] == b'\\' {
                    i = (i + 2).min(out.len());
                    continue;
                }
                if out[i] == b'`' {
                    state = PerlCommentState::Normal;
                }
                i += 1;
            }
        }
    }

    String::from_utf8(out).map_or(std::borrow::Cow::Borrowed(code), std::borrow::Cow::Owned)
}

fn string_literal_from_caps<'t>(caps: &regex::Captures<'t>) -> Option<&'t str> {
    caps.name("dq")
        .or_else(|| caps.name("sq"))
        .map(|m| m.as_str())
}

/// Matches every single- or double-quoted string literal in a fragment of
/// source text, exposing the inner content via the `dq`/`sq` capture groups.
///
/// Used to scan an exec-sink call's *entire* argument list — including string
/// elements nested inside a list/tuple literal — for a destructive payload, so
/// `subprocess.run(["sh", "-c", "rm -rf /etc"])` is caught even though its first
/// literal (`"sh"`) is inert. Literals are matched independently of position, so
/// this is intentionally permissive: it is only ever invoked once a known
/// exec-sink call has already been identified.
static ANY_STRING_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)'"#).expect("any string literal regex compiles")
});

/// Return the slice of `code` covering an exec-sink call's argument region,
/// starting at `match_start` (the sink name) and ending at the balanced closing
/// `)` of the call's argument list.
///
/// String literals are skipped so parens/brackets inside them don't perturb the
/// depth count. If the closing paren can't be found (malformed/truncated source),
/// the region is bounded to the end of the current line so we still scan the
/// visible arguments. This lets [`detect_destructive_in_args`] see every literal
/// in `subprocess.run(["sh", "-c", "rm -rf /etc"])`, not just the first.
///
/// A call written without parentheses (Perl and Ruby: `system 'rm', '-rf',
/// $x;`) runs to the end of its line instead, because the first bracket on
/// that line is not the call's own. Matching it used to end the region inside
/// an argument — `lc('/tmp/x')` in `system 'rm', '-rf', lc('/tmp/x'),
/// './build'` — and drop every operand after it. [`exec_argv_region`] then
/// finds where such a list really ends (`;`, `or die …`, `if …`).
fn exec_sink_arg_region(code: &str, match_start: usize) -> &str {
    let after_name = code[match_start..]
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '.' | ':')))
        .map_or(code.len(), |offset| match_start + offset);
    if !code[after_name..].trim_start().starts_with('(') {
        return code[match_start..].split('\n').next().unwrap_or_default();
    }

    let bytes = code.as_bytes();
    let mut depth: i32 = 0;
    let mut seen_open = false;
    let mut quote: Option<u8> = None;
    let mut i = match_start;

    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            // Inside a string literal: only its terminator (un-escaped) matters.
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' | b'\'' => quote = Some(b),
            b'(' | b'[' | b'{' => {
                depth += 1;
                seen_open = true;
            }
            b')' | b']' | b'}' => {
                depth -= 1;
                if seen_open && depth <= 0 {
                    return code
                        .get(match_start..=i)
                        .unwrap_or_else(|| &code[match_start..]);
                }
            }
            b'\n' if !seen_open => {
                // Sink name with no opening paren on this line: bail to line end.
                return code
                    .get(match_start..i)
                    .unwrap_or_else(|| &code[match_start..]);
            }
            _ => {}
        }
        i += 1;
    }

    &code[match_start..]
}

/// Scan **every** string literal in an exec-sink call's argv for a destructive
/// shell payload and return the most severe hit.
///
/// This descends into list/tuple literal elements (e.g. the `"rm -rf /etc"`
/// inside `subprocess.run(["sh", "-c", "rm -rf /etc"])`), closing the list-arg
/// exec-sink false negative where only the first literal was inspected (#136).
/// Callers MUST only invoke this once the surrounding call is confirmed to be a
/// real exec sink, so inert literals (`print("rm -rf x")`) never reach here.
///
/// Most severe, not first: a harmless first finding used to end the search,
/// so `spawnSync('rm', ['-rf', 'rm -rf /tmp/y', '/'])` reported the `Medium`
/// payload in its third literal and never weighed the argv that deletes `/`.
fn detect_destructive_in_args(call_text: &str) -> Option<ShellPayloadHit> {
    // Operands, not literals. A token split across a concatenation operator is
    // one operand the call really builds, and reading its halves separately hid
    // it from both views below in every language at once (#474).
    let operands = concatenated_operands(exec_argv_region(call_text));
    let literals: Vec<&str> = operands.iter().map(Cow::as_ref).collect();

    // 1) Each literal on its own (catches `subprocess.run(["sh","-c","rm -rf /etc"])`
    //    where the destructive command lives in a single literal).
    let mut found = None;
    for literal in &literals {
        found = more_severe(found, detect_shell_payload(literal));
    }

    // 2) Argv: a destructive command split across separate literals
    //    (`spawnSync("rm", ["-rf", "/etc/x"])`, `exec.Command("rm","-rf","/x")`)
    //    has no single literal that flags, so read the literals as the argv
    //    they are (#136). Safe because this runs ONLY after the call is
    //    confirmed to be a real exec sink, so inert literals never reach here.
    if literals.len() > 1 {
        found = more_severe(found, detect_argv_payload(&literals));
    }

    found
}

/// The string operands of a call's argument region, with concatenated literals
/// folded into the single operand they build (#474).
///
/// `detect_destructive_in_args` read each *literal*, never each *operand*, so
/// splitting a token across a `+` hid it from both of its views: no single
/// literal is destructive, and the argv view saw `r`, `m`, `-rf` instead of
/// `rm`, `-rf`. Measured before this, `subprocess.run(["r"+"m","-rf",T])` was
/// allowed in Python, Ruby, JavaScript, Go and PHP alike.
///
/// The fold is driven by the operator, never by adjacency. Comma-separated
/// literals stay separate operands, or the argv view would start manufacturing
/// commands the source never builds — `["echo", "rm", "-rf"]` must remain three
/// operands. So the gap between two literals folds only when it is whitespace
/// plus exactly one `+` or `.`, which is also what keeps a dynamic operand
/// (`"rm -rf " + dir`) fail-open: the identifier in the gap stops the fold.
///
/// `.` is PHP's concatenation operator and `+` is the other four languages'.
/// Accepting both everywhere is safe because neither is valid *between two
/// string literals* in a language that does not use it that way, and a method
/// call like `"a".freeze` leaves letters in the gap, which blocks the fold.
///
/// Borrowed until something is actually joined, so the common no-concatenation
/// case allocates nothing beyond the operand vector.
fn concatenated_operands(region: &str) -> Vec<Cow<'_, str>> {
    let mut operands: Vec<Cow<'_, str>> = Vec::new();
    let mut previous_end: Option<usize> = None;

    for caps in ANY_STRING_LITERAL.captures_iter(region) {
        let Some(whole) = caps.get(0) else { continue };
        let Some(literal) = string_literal_from_caps(&caps) else {
            continue;
        };

        let folds = previous_end.is_some_and(|end| {
            region
                .get(end..whole.start())
                .is_some_and(is_concatenation_gap)
        });
        if folds {
            if let Some(last) = operands.last_mut() {
                last.to_mut().push_str(literal);
            }
        } else {
            operands.push(Cow::Borrowed(literal));
        }
        previous_end = Some(whole.end());
    }

    operands
}

/// Whether the text between two string literals is exactly one concatenation.
///
/// Exactly one operator, because `"a" + + "b"` is not concatenation in any of
/// these languages, and because requiring a count rather than "contains an
/// operator" is what makes a stray token in the gap block the fold.
fn is_concatenation_gap(gap: &str) -> bool {
    let mut operators = 0_usize;
    for ch in gap.chars() {
        match ch {
            '+' | '.' => operators += 1,
            c if c.is_whitespace() => {}
            _ => return false,
        }
    }
    operators == 1
}

/// The part of an exec-sink call that holds the command it runs: its argument
/// list, up to where options begin.
///
/// Options carry strings that are not operands. `spawnSync('rm', ['-rf',
/// '/tmp/x'], { stdio: 'inherit' })` deletes only `/tmp/x`, and with every
/// operand weighed, reading `inherit` as one would block it — just as Ruby's
/// `out: '/dev/null'` would read as a catastrophic target. So the region ends
/// at:
///
/// - a `{…}` argument (a JavaScript options object, a Ruby options hash);
/// - a keyword argument (`cwd='/'`, `out: File::NULL`, `:out => …`), or any
///   argument followed by `=>`, which also ends a JavaScript callback;
/// - the end of a list argument — in JavaScript and Python the list IS the
///   argv (`spawnSync(cmd, args, options)`, `subprocess.run(args, **kw)`);
/// - without parentheses (Perl, Ruby), a `;`, `||`/`&&`, or a low-precedence
///   operator or statement modifier (`or die "…"`, `if $x`).
///
/// A dynamic positional argument does not end it: `system('rm', '-rf', $dir,
/// '/')` still deletes `/`.
fn exec_argv_region(call_text: &str) -> &str {
    let bytes = call_text.as_bytes();
    let mut i = call_text
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '.' | ':')))
        .unwrap_or(call_text.len());
    while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
        i += 1;
    }
    let parenthesized = bytes.get(i) == Some(&b'(');
    if parenthesized {
        i += 1;
    }
    let begin = i;
    let mut depth = 0_usize;
    let mut quote: Option<u8> = None;
    let mut arg_start = begin;
    let mut at_arg_start = true;
    let mut list_arg = false;

    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        if at_arg_start && !b.is_ascii_whitespace() {
            at_arg_start = false;
            arg_start = i;
            if b == b'{' || is_keyword_argument(&call_text[i..]) {
                return &call_text[begin..i];
            }
            list_arg = b == b'[';
        }
        if depth == 0
            && !parenthesized
            && !at_arg_start
            && b.is_ascii_whitespace()
            && starts_low_precedence_operator(&call_text[i..])
        {
            return &call_text[begin..i];
        }
        match b {
            b'"' | b'\'' => quote = Some(b),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                // Below the argument list: the call's own closing paren.
                let Some(inner) = depth.checked_sub(1) else {
                    return &call_text[begin..i];
                };
                depth = inner;
                if depth == 0 && list_arg && b == b']' {
                    return &call_text[begin..=i];
                }
            }
            b',' if depth == 0 => at_arg_start = true,
            b'=' if depth == 0 && bytes.get(i + 1) == Some(&b'>') => {
                return &call_text[begin..arg_start];
            }
            b';' if depth == 0 && !parenthesized => return &call_text[begin..i],
            b'|' | b'&' if depth == 0 && !parenthesized && bytes.get(i + 1) == Some(&b) => {
                return &call_text[begin..i];
            }
            _ => {}
        }
        i += 1;
    }

    &call_text[begin..]
}

/// A keyword argument: `cwd='/'` (Python), `out: File::NULL` or `:out => …`
/// (Ruby). Python's `args=[…]` is the argv itself, so it is not one.
fn is_keyword_argument(arg: &str) -> bool {
    if let Some(symbol) = arg.strip_prefix(':') {
        return symbol.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_');
    }
    if arg.starts_with(|c: char| c.is_ascii_digit()) {
        return false;
    }
    let name_len = arg
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(arg.len());
    let (name, rest) = arg.split_at(name_len);
    if name.is_empty() || name == "args" {
        return false;
    }
    if let Some(after_colon) = rest.strip_prefix(':') {
        return !after_colon.starts_with(':');
    }
    let rest = rest.trim_start();
    rest.starts_with('=') && !rest.starts_with("==") && !rest.starts_with("=>")
}

/// ` or die "…"`, ` if $x`, ` unless …`: where Perl and Ruby end an argument
/// list written without parentheses.
fn starts_low_precedence_operator(rest: &str) -> bool {
    let word = rest.trim_start();
    [
        "or", "and", "xor", "if", "unless", "while", "until", "for", "foreach", "rescue",
    ]
    .iter()
    .any(|keyword| {
        word.strip_prefix(keyword).is_some_and(|after| {
            !after.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
        })
    })
}

fn push_perl_shell_payload_match(
    out: &mut Vec<PatternMatch>,
    code: &str,
    newline_positions: &[usize],
    call: PerlShellCall,
    payload: &str,
    start: usize,
    end: usize,
) {
    let Some(hit) = detect_shell_payload(payload) else {
        return;
    };
    push_perl_shell_hit(out, code, newline_positions, call, &hit, start, end);
}

fn push_perl_shell_hit(
    out: &mut Vec<PatternMatch>,
    code: &str,
    newline_positions: &[usize],
    call: PerlShellCall,
    hit: &ShellPayloadHit,
    start: usize,
    end: usize,
) {
    let rule_id = format!("heredoc.perl.{}.{}", call.id_prefix(), hit.rule_suffix);
    push_regex_match(
        out,
        code,
        newline_positions,
        &rule_id,
        hit.reason,
        hit.severity,
        hit.suggestion.map(str::to_string),
        start,
        end,
    );
}

struct ShellPayloadHit {
    rule_suffix: &'static str,
    reason: &'static str,
    severity: Severity,
    suggestion: Option<&'static str>,
}

fn detect_shell_payload(payload: &str) -> Option<ShellPayloadHit> {
    for segment in payload.split(&[';', '\n', '|', '&'][..]) {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }

        let mut tokens = segment.split_whitespace().peekable();
        let Some(cmd) = next_shell_command(&mut tokens) else {
            continue;
        };
        if let Some(hit) = detect_destructive_command(cmd, tokens, PayloadSyntax::Shell) {
            return Some(hit);
        }
    }

    None
}

/// How the words of a payload reach the program.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PayloadSyntax {
    /// A shell parses them first, so an unquoted `>` or `2>/dev/null` is a
    /// redirection and names no operand.
    Shell,
    /// An argv vector the program receives as-is: every word is an operand or
    /// an option, whatever characters it holds.
    Argv,
}

/// A command handed over as an argv vector — `spawnSync('rm', ['-rf', x])`,
/// `system('rm', '-rf', x)`, `subprocess.run(['rm', '-rf', x])` — rather than
/// as one shell string.
///
/// No shell parses it, so each element is exactly one word. Joining the
/// elements and scanning the result as shell text, as this used to, let one
/// element hide every operand after it: `'/tmp/x;'` ended the "command" at the
/// `;`, and `'>'` would read as a redirection. `spawnSync('rm', ['-rf',
/// '/tmp/x;', '/'])` deletes `/`.
///
/// The shell reading is still consulted when the argv one does not block,
/// because `{ shell: true }` does hand the joined words to a shell, where
/// `['x;', 'git', 'reset', '--hard']` is two commands.
fn detect_argv_payload(argv: &[&str]) -> Option<ShellPayloadHit> {
    let mut words = argv.iter().copied().peekable();
    let as_argv = next_shell_command(&mut words)
        .and_then(|cmd| detect_destructive_command(cmd, words, PayloadSyntax::Argv));
    if as_argv
        .as_ref()
        .is_some_and(|hit| hit.severity.blocks_by_default())
    {
        return as_argv;
    }
    more_severe(as_argv, detect_shell_payload(&argv.join(" ")))
}

fn detect_destructive_command<'a, I>(
    cmd: &str,
    tokens: I,
    syntax: PayloadSyntax,
) -> Option<ShellPayloadHit>
where
    I: Iterator<Item = &'a str>,
{
    // Compare on the basename. `next_shell_command` unwraps `sudo`/`command`/
    // `env` frontends but returns the command word verbatim, so a path
    // spelling never equalled the literals below: `['/bin/rm','-rf',
    // '/home/user']` reached here as `/bin/rm` and this match missed it, while
    // the bare `['rm',…]` spelling was caught (#459). Same stripping the shell
    // path already applies to a command word, same idiom as `normalize.rs`, so
    // `/usr/bin/rm`, `./rm` and `rm.exe` line up with plain `rm` here too.
    let cmd = cmd
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(cmd)
        .trim_end_matches(".exe");

    match cmd {
        "git" => detect_git_destructive(tokens),
        "rm" => detect_rm_rf_destructive(tokens, syntax),
        _ => None,
    }
}

/// The more severe of two findings, preferring `a` on a tie.
fn more_severe(a: Option<ShellPayloadHit>, b: Option<ShellPayloadHit>) -> Option<ShellPayloadHit> {
    const fn rank(severity: Severity) -> u8 {
        match severity {
            Severity::Critical => 3,
            Severity::High => 2,
            Severity::Medium => 1,
            Severity::Low => 0,
        }
    }
    match (a, b) {
        (Some(a), Some(b)) if rank(b.severity) > rank(a.severity) => Some(b),
        (Some(a), _) => Some(a),
        (None, b) => b,
    }
}

/// `Some(file_is_next_word)` when `token` is an unquoted shell redirection —
/// `>`, `2>>` (the file is the next word) or `2>/dev/null`, `<in` (attached) —
/// and `None` when it is an ordinary word. A quoted `'>'` is a file name.
fn shell_redirection(token: &str) -> Option<bool> {
    let operator = token.trim_start_matches(|c: char| c.is_ascii_digit());
    if !operator.starts_with(['<', '>']) {
        return None;
    }
    Some(operator.trim_start_matches(['<', '>']).is_empty())
}

fn detect_git_destructive<'a, I>(mut tokens: I) -> Option<ShellPayloadHit>
where
    I: Iterator<Item = &'a str>,
{
    let sub = tokens.next()?;

    if sub == "reset" {
        if tokens.any(|t| t == "--hard") {
            return Some(ShellPayloadHit {
                rule_suffix: "git_reset_hard",
                reason: "git reset --hard destroys uncommitted changes",
                severity: Severity::High,
                suggestion: Some("Use 'git stash' first, or prefer safer alternatives"),
            });
        }
        return None;
    }

    if sub == "clean" {
        let mut has_f = false;
        let mut has_d = false;

        for t in tokens {
            if t == "--force" {
                has_f = true;
                continue;
            }
            if t == "--dry-run" || t == "-n" {
                continue;
            }
            if t.starts_with('-') {
                let flags = t.trim_start_matches('-');
                has_f |= flags.contains('f');
                has_d |= flags.contains('d');
            }
        }

        if has_f && has_d {
            return Some(ShellPayloadHit {
                rule_suffix: "git_clean_fd",
                reason: "git clean -fd permanently deletes untracked files",
                severity: Severity::High,
                suggestion: Some("Use 'git clean -n' first to preview deletions"),
            });
        }
    }

    None
}

fn detect_rm_rf_destructive<'a, I>(tokens: I, syntax: PayloadSyntax) -> Option<ShellPayloadHit>
where
    I: Iterator<Item = &'a str>,
{
    let mut has_r = false;
    let mut has_f = false;
    let mut options_ended = false;
    let mut skip_redirection_file = false;
    // Every operand is deleted, so every operand is weighed. This used to read
    // only the first and stop, so a temp decoy in front laundered whatever
    // followed it: `spawnSync('rm', ['-rf', '/tmp/x', '/'])` was ALLOWED in
    // JavaScript, Ruby and Perl while `rm -rf /tmp/x /` blocked in the shell.
    let mut operands = 0_usize;
    let mut catastrophic = false;
    let mut temp_scratch = true;

    for token in tokens {
        if skip_redirection_file {
            skip_redirection_file = false;
            continue;
        }
        if syntax == PayloadSyntax::Shell {
            if let Some(file_is_next_word) = shell_redirection(token) {
                skip_redirection_file = file_is_next_word;
                continue;
            }
        }
        if !options_ended && token == "--" {
            options_ended = true;
            continue;
        }
        if !options_ended && token.starts_with('-') {
            if token == "--recursive" {
                has_r = true;
                continue;
            }
            if token == "--force" {
                has_f = true;
                continue;
            }

            let flags = token.trim_start_matches('-');
            has_r |= flags.chars().any(|c| matches!(c, 'r' | 'R'));
            has_f |= flags.contains('f');
            continue;
        }
        // Past the first operand an option still counts: GNU `rm` permutes
        // its arguments, so `rm ./build -rf` is a recursive delete.

        let target = clean_path_token(token);
        if target.is_empty() {
            continue;
        }
        operands += 1;
        catastrophic |= is_catastrophic_path(target);
        temp_scratch &= is_temp_scratch_path(target);
    }

    if !has_r || !has_f || operands == 0 {
        return None;
    }

    // #455's single policy, expressed where every exec-sink consumer reads it:
    // a recursive delete of a literal target outside a temp directory blocks
    // in every language, and `/tmp` / `/var/tmp` are carved out exactly as
    // `rm -rf /tmp/x` is in the shell — only when EVERY operand is one.
    //
    // This used to return `Medium` for every non-catastrophic target. The
    // JavaScript, TypeScript and Ruby refiners, both exec-sink backstops and the
    // Perl `system`/`exec` path all carry this severity through unchanged, so
    // an argv-split `spawnSync('rm', ['-rf', './build'])` was ALLOWED — the one
    // spelling with no contiguous `rm -rf` text for the shell rescan to catch —
    // while `rm -rf ./build` and `shutil.rmtree('./build')` denied. `High` for
    // a non-temp target closes that without relaxing anything: the Python
    // refiner already escalated every hit to `High`, so its verdicts do not
    // move.
    let temp_scratch = !catastrophic && temp_scratch;

    Some(ShellPayloadHit {
        rule_suffix: if catastrophic {
            "rm_rf_catastrophic"
        } else {
            "rm_rf"
        },
        reason: if catastrophic {
            "rm -rf recursively deletes files/directories (catastrophic target path)"
        } else {
            "rm -rf recursively deletes files/directories"
        },
        severity: if catastrophic {
            Severity::Critical
        } else if temp_scratch {
            Severity::Medium
        } else {
            Severity::High
        },
        suggestion: Some("Verify the target path and use safer alternatives when possible"),
    })
}

fn next_shell_command<'a, I>(tokens: &mut std::iter::Peekable<I>) -> Option<&'a str>
where
    I: Iterator<Item = &'a str>,
{
    loop {
        let token = tokens.next()?;
        match token {
            "sudo" => {
                while let Some(&next) = tokens.peek() {
                    if !next.starts_with('-') {
                        break;
                    }
                    let flag = tokens.next().unwrap_or_default();
                    if matches!(flag, "-u" | "-g" | "-h") {
                        let _ = tokens.next();
                    }
                }
            }
            "command" => {
                while let Some(&next) = tokens.peek() {
                    if next.starts_with('-') {
                        let _ = tokens.next();
                        continue;
                    }
                    break;
                }
            }
            "env" => {
                while let Some(&next) = tokens.peek() {
                    if next.starts_with('-') || next.contains('=') {
                        let _ = tokens.next();
                        continue;
                    }
                    break;
                }
            }
            _ => return Some(token),
        }
    }
}

fn clean_path_token(token: &str) -> &str {
    let token = token.trim_matches(|c: char| c == '"' || c == '\'');
    token.trim_end_matches(&[';', ',', ')', ']', '}'][..])
}

/// Check if a path contains `..` as an actual path component (not in a filename).
///
/// Examples:
/// - `/tmp/../etc` → true (path traversal)
/// - `/tmp/foo..bar` → false (dots in filename, not traversal)
/// - `../etc` → true (relative path traversal)
fn contains_path_traversal(path: &str) -> bool {
    // Check for `..` as a path segment: `/../`, `/..` at end, `../` at start, or exactly `..`
    path.contains("/../") || path.ends_with("/..") || path.starts_with("../") || path == ".."
}

fn has_path_prefix(path: &str, prefix: &str) -> bool {
    if !path.starts_with(prefix) {
        return false;
    }
    // It starts with prefix. It's a match if exact match OR next char is separator.
    path.len() == prefix.len() || path.as_bytes()[prefix.len()] == b'/'
}

fn is_catastrophic_path(path: &str) -> bool {
    // Root or home always catastrophic
    if matches!(path, "/" | "~") || path.starts_with("~/") {
        return true;
    }

    // Temp directories are safe UNLESS they contain path traversal.
    // Path traversal can escape temp directories (e.g., /tmp/../etc -> /etc).
    if has_path_prefix(path, "/tmp") || has_path_prefix(path, "/var/tmp") {
        return contains_path_traversal(path);
    }

    // Standard catastrophic system paths
    let sys_dirs = [
        "/etc", "/home", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/var", "/boot", "/root",
        "/opt", "/sys", "/proc", "/dev", "/mnt", "/media", "/srv", "/run",
    ];

    sys_dirs.iter().any(|&dir| has_path_prefix(path, dir))
}

/// A scratch directory a recursive delete may target without review.
///
/// One definition, shared by every language, and deliberately the same one the
/// shell side already uses: `core.filesystem`'s `rm-rf-tmp` / `rm-rf-var-tmp`
/// safe patterns exempt `(?:/private)?/tmp/…` and `(?:/private)?/var/tmp/…`
/// and refuse any `..` component. `rm -rf /tmp/build` is allowed, so
/// `shutil.rmtree('/tmp/build')` and `FileUtils.rm_rf('/tmp/build')` have to be
/// allowed too, or the policy depends on which language the agent picked
/// (#455).
///
/// Traversal disqualifies a path here for the same reason it does there:
/// `/tmp/../etc` names `/etc`, not a scratch directory.
fn is_temp_scratch_path(path: &str) -> bool {
    let candidate = path.strip_prefix("/private").unwrap_or(path);
    (has_path_prefix(candidate, "/tmp") || has_path_prefix(candidate, "/var/tmp"))
        && !contains_path_traversal(candidate)
}

/// Go's exec-sink rule ids, the set `refine_go_match` escalates (#472).
///
/// Only `exec.Command` itself is here. The three chained spellings
/// (`.Run()`, `.Output()`, `.CombinedOutput()`) wrap the *same* call, and the
/// bare pattern matches that inner call in every one of them, so escalating a
/// chained id as well would report two blocking ids for one command — the
/// allowlist trap #467 describes, where granting the id dcg showed you leaves
/// the command denied under the id it did not. The chained patterns keep
/// matching and keep reporting; they simply are not the ones that block.
/// `every_go_exec_sink_escalates_a_destructive_payload_issue_472` asserts both
/// halves: every shape blocks, and each blocks exactly once.
fn is_go_exec_sink_rule(rule_id: &str) -> bool {
    rule_id == "heredoc.go.exec_command"
}

/// PHP's exec-sink rule ids, the set `refine_php_match` escalates (#473).
///
/// Exact ids for the reason `refine_python_match` gives: a sink missing from
/// this list registers at Medium and never escalates, so it reports a finding
/// on a real `rm -rf` and the command still runs. `heredoc.php.backticks` is
/// absent on purpose — see `refine_php_match` for why it has nothing to read.
fn is_php_exec_sink_rule(rule_id: &str) -> bool {
    matches!(
        rule_id,
        "heredoc.php.system"
            | "heredoc.php.exec"
            | "heredoc.php.shell_exec"
            | "heredoc.php.passthru"
            | "heredoc.php.popen"
            | "heredoc.php.proc_open"
    )
}

/// Recursive-delete rule ids, by language, under #455's single policy.
///
/// Membership is what makes a literal non-temp target block, so it is an exact
/// list rather than a prefix test. It holds only the calls that actually
/// recurse: `FileUtils.rm_f` / `rm` / `remove_file` delete one file and
/// `rmdir` needs the directory to be empty already, so none of them can
/// destroy a tree and none of them are here. That empty-directory family is
/// the smaller split the issue offers to bundle, and it is left alone.
fn is_recursive_delete_rule(rule_id: &str) -> bool {
    matches!(
        rule_id,
        "heredoc.python.shutil_rmtree"
            // Go joined this list late only because none of its patterns could
            // match until #465 repaired them; `os.RemoveAll` is the same
            // recursive delete under the same policy.
            | "heredoc.go.os_removeall"
            | "heredoc.ruby.fileutils_rm_rf"
            | "heredoc.ruby.fileutils_rm_r"
            | "heredoc.ruby.fileutils_remove_entry"
            | "heredoc.ruby.fileutils_remove_entry_secure"
            | "heredoc.ruby.fileutils_remove_dir"
            | "heredoc.javascript.fs_rmsync"
            | "heredoc.javascript.fs_rmdirsync"
            | "heredoc.javascript.fs_rm"
            | "heredoc.javascript.fs_rmdir"
            | "heredoc.typescript.fs_rmsync"
            | "heredoc.typescript.fs_rmdirsync"
            | "heredoc.typescript.fs_rm"
            | "heredoc.typescript.fs_rmdir"
    )
}

/// The refinement a recursive delete with a *literal* target gets.
///
/// `None` when nothing is proven — the target is not a literal, or it is a
/// scratch path — and the caller keeps whatever severity it had. A literal
/// outside `/tmp` is the case #455 is about: `FileUtils.rm_rf('./build')` and
/// `fs.rmSync('./dist', {recursive: true})` destroy a working tree exactly the
/// way `rm -rf ./build` does, and that already blocks.
fn recursive_delete_refinement(
    meta: &CompiledPattern,
    path: Option<&str>,
) -> Option<RefinedMatchMeta> {
    let path = path?;
    if is_temp_scratch_path(path) {
        return None;
    }
    Some(RefinedMatchMeta {
        rule_id: format!("{}.non_temp", meta.rule_id),
        reason: format!("{} outside a temp directory", meta.reason),
        severity: Severity::Critical,
        suggestion: Some("Delete under /tmp, or narrow the target and run it manually".to_string()),
    })
}

#[allow(clippy::too_many_arguments)]
fn push_regex_match(
    out: &mut Vec<PatternMatch>,
    code: &str,
    newline_positions: &[usize],
    rule_id: &str,
    reason: &str,
    severity: Severity,
    suggestion: Option<String>,
    start: usize,
    end: usize,
) {
    let line_number = newline_positions.partition_point(|&idx| idx < start) + 1;
    let matched_text = code.get(start..end).unwrap_or("");
    let preview = truncate_preview(matched_text, 60);

    out.push(PatternMatch {
        rule_id: rule_id.to_string(),
        reason: reason.to_string(),
        matched_text_preview: preview,
        start,
        end,
        line_number,
        severity,
        suggestion,
    });
}

/// Default patterns for heredoc scanning.
///
/// These patterns detect destructive operations in embedded scripts.
/// Each pattern has a stable rule ID for allowlisting.
#[allow(clippy::too_many_lines)]
/// The built-in AST corpus.
///
/// `pub(crate)` so the evaluator can assert that every pattern registered at a
/// blocking severity also has an entry in its incomplete-analysis backstop. That
/// pair has silently disagreed three times — Ruby absent entirely (#452),
/// JavaScript's `unlinkSync` and promise `rm` absent, and Go's `os.Remove`
/// present only as `os.RemoveAll` (#468) — and each disagreement was a false
/// negative rather than cosmetic drift, because the backstop is the only thing
/// between an incomplete analysis and an allow.
pub(crate) fn default_patterns() -> HashMap<ScriptLanguage, Vec<CompiledPattern>> {
    let mut patterns = HashMap::new();

    // Python patterns
    patterns.insert(
        ScriptLanguage::Python,
        vec![
            // Receiver metavariable, so a module alias matches too:
            // `import shutil as sh; sh.rmtree(...)` was allowed while the
            // canonical spelling denied. Same shape as the node chained
            // receiver in #453.
            CompiledPattern::new(
                "$M.rmtree($$$)".to_string(),
                "heredoc.python.shutil_rmtree".to_string(),
                "shutil.rmtree() recursively deletes directories".to_string(),
                Severity::Critical,
                Some("Use shutil.rmtree with explicit path validation".to_string()),
            ),
            CompiledPattern::new(
                "os.remove($$$)".to_string(),
                "heredoc.python.os_remove".to_string(),
                "os.remove() deletes files".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "os.rmdir($$$)".to_string(),
                "heredoc.python.os_rmdir".to_string(),
                "os.rmdir() deletes directories".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "os.unlink($$$)".to_string(),
                "heredoc.python.os_unlink".to_string(),
                "os.unlink() deletes files".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "pathlib.Path($$$).unlink($$$)".to_string(),
                "heredoc.python.pathlib_unlink".to_string(),
                "Path.unlink() deletes files".to_string(),
                Severity::High,
                None,
            ),
            // Also match when Path is imported directly: from pathlib import Path
            CompiledPattern::new(
                "Path($$$).unlink($$$)".to_string(),
                "heredoc.python.pathlib_unlink".to_string(),
                "Path.unlink() deletes files".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "pathlib.Path($$$).rmdir($$$)".to_string(),
                "heredoc.python.pathlib_rmdir".to_string(),
                "Path.rmdir() deletes directories".to_string(),
                Severity::High,
                None,
            ),
            // Also match when Path is imported directly
            CompiledPattern::new(
                "Path($$$).rmdir($$$)".to_string(),
                "heredoc.python.pathlib_rmdir".to_string(),
                "Path.rmdir() deletes directories".to_string(),
                Severity::High,
                None,
            ),
            // Shell execution patterns - Medium severity to avoid false positives
            // per bead guidance: "Do not block on shell=True alone"
            CompiledPattern::new(
                "subprocess.run($$$)".to_string(),
                "heredoc.python.subprocess_run".to_string(),
                "subprocess.run() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "subprocess.call($$$)".to_string(),
                "heredoc.python.subprocess_call".to_string(),
                "subprocess.call() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "subprocess.Popen($$$)".to_string(),
                "heredoc.python.subprocess_popen".to_string(),
                "subprocess.Popen() spawns shell processes".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            // `check_call` and `check_output` are the two the Python docs
            // point you at when you want the command to raise on failure, and
            // the argv-list form is the one every style guide prefers over
            // `shell=True`. That combination — recommended function,
            // recommended argument shape — was the one left unguarded (#458).
            //
            // An argv list is also the shape no other layer can cover:
            // `['rm','-rf','/home/user']` puts no literal `rm -rf` in the
            // text, so the raw-shell rescan has nothing to see and an AST
            // pattern is the only thing that reaches it. A string payload
            // denied either way, which is why the gap read as "check_call is
            // partly guarded" rather than as a missing pattern.
            CompiledPattern::new(
                "subprocess.check_call($$$)".to_string(),
                "heredoc.python.subprocess_check_call".to_string(),
                "subprocess.check_call() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "subprocess.check_output($$$)".to_string(),
                "heredoc.python.subprocess_check_output".to_string(),
                "subprocess.check_output() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "os.system($$$)".to_string(),
                "heredoc.python.os_system".to_string(),
                "os.system() executes shell commands".to_string(),
                Severity::Medium, // Lowered per bead: avoid "code execution exists" as default deny
                Some("Use subprocess with explicit arguments instead".to_string()),
            ),
            CompiledPattern::new(
                "os.popen($$$)".to_string(),
                "heredoc.python.os_popen".to_string(),
                "os.popen() executes shell commands".to_string(),
                Severity::Medium,
                Some("Use subprocess instead".to_string()),
            ),
        ],
    );

    // JavaScript/Node patterns
    patterns.insert(
        ScriptLanguage::JavaScript,
        vec![
            // The receiver is a metavariable, not the literal `fs`, so the
            // chained form `require('fs').rmSync(...)` matches as well as a
            // bound `const fs = require('fs')` (#453). That spelling is the
            // shorter one to type and the one a `-e` one-liner actually uses.
            // Over-matching on the receiver is bounded by the severity
            // refinement below, which still requires `recursive: true` or a
            // catastrophic literal path before this denies.
            CompiledPattern::new(
                "$FS.rmSync($$$)".to_string(),
                "heredoc.javascript.fs_rmsync".to_string(),
                "fs.rmSync() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            ),
            // Same metavariable receiver as `rmSync` above, and for the same
            // reason: `require('fs').rmdirSync('/')` was allowed while the
            // bound `fs.rmdirSync('/')` denied, so the shorter spelling a
            // `-e` one-liner actually uses was the one that got through
            // (#453's fix reached only `rmSync`; found while measuring #455).
            CompiledPattern::new(
                "$FS.rmdirSync($$$)".to_string(),
                "heredoc.javascript.fs_rmdirsync".to_string(),
                "fs.rmdirSync() deletes directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "$FS.unlinkSync($$$)".to_string(),
                "heredoc.javascript.fs_unlinksync".to_string(),
                "fs.unlinkSync() deletes files".to_string(),
                Severity::Low,
                None,
            ),
            CompiledPattern::new(
                "child_process.execSync($$$)".to_string(),
                "heredoc.javascript.execsync".to_string(),
                "execSync() executes shell commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "require('child_process').execSync($$$)".to_string(),
                "heredoc.javascript.require_execsync".to_string(),
                "execSync() executes shell commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command arguments carefully".to_string()),
            ),
            // Spawn variants
            CompiledPattern::new(
                "child_process.spawnSync($$$)".to_string(),
                "heredoc.javascript.spawnsync".to_string(),
                "spawnSync() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command and arguments carefully".to_string()),
            ),
            // Async versions (still dangerous). Metavariable receivers for the
            // same reason the `*Sync` siblings above have them: a literal `fs.`
            // matched only one binding spelling, so an aliased promises object
            // was unguarded. `const fsp = require('fs').promises; fsp.rm(p,
            // {recursive:true})` and `const fsp = require('fs/promises')` were
            // both allowed at a catastrophic target while `fs.rm` and the
            // chained `require('fs').promises.rm` denied (#459). Over-matching
            // stays bounded by the same severity refinement: `recursive: true`
            // or a catastrophic/non-temp literal target is still required.
            CompiledPattern::new(
                "$FS.rm($$$)".to_string(),
                "heredoc.javascript.fs_rm".to_string(),
                "fs.rm() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "$FS.rmdir($$$)".to_string(),
                "heredoc.javascript.fs_rmdir".to_string(),
                "fs.rmdir() deletes directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "$FS.unlink($$$)".to_string(),
                "heredoc.javascript.fs_unlink".to_string(),
                "fs.unlink() deletes files".to_string(),
                Severity::Low,
                None,
            ),
            // No separate promise-based entries: `$FS.rm`/`$FS.rmdir` above
            // already cover every promise spelling, and a second pattern on the
            // same call was actively harmful.
            //
            // #453 added `$FS.promises.rm($$$)` for the member spelling and kept
            // `fsPromises.rm($$$)` for the `require('fs/promises')` binding,
            // "where there is no `.promises` member to match". Generalising the
            // receiver to a metavariable (#459) made both redundant, because a
            // metavariable matches the whole receiver node whatever its shape.
            // Measured, not assumed:
            //
            //   $FS.rm($$$)           fs.rm, fs.promises.rm, fsPromises.rm,
            //                         require('fs').promises.rm   (all four)
            //   $FS.promises.rm($$$)  fs.promises.rm, require('fs').promises.rm
            //   fsPromises.rm($$$)    fsPromises.rm
            //
            // So each removed pattern matched a strict subset. What the overlap
            // cost was an allowlist: both patterns fired on one call, `explain`
            // reported only the winner (`fs_rm`), and allowlisting that id left
            // the command denied under `fspromises_rm` — an id the user was
            // never shown. `fs.rm` allowlisted correctly because only one
            // pattern matched it.
        ],
    );

    // TypeScript patterns (git_safety_guard-26f)
    patterns.insert(
        ScriptLanguage::TypeScript,
        vec![
            // Receiver metavariable, as on the JavaScript side above, so the
            // chained `require('fs').rmSync(...)` spelling matches too (#453).
            CompiledPattern::new(
                "$FS.rmSync($$$)".to_string(),
                "heredoc.typescript.fs_rmsync".to_string(),
                "fs.rmSync() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            ),
            // Same metavariable receiver as `rmSync` above, and for the same
            // reason: `require('fs').rmdirSync('/')` was allowed while the
            // bound `fs.rmdirSync('/')` denied, so the shorter spelling a
            // `-e` one-liner actually uses was the one that got through
            // (#453's fix reached only `rmSync`; found while measuring #455).
            CompiledPattern::new(
                "$FS.rmdirSync($$$)".to_string(),
                "heredoc.typescript.fs_rmdirsync".to_string(),
                "fs.rmdirSync() deletes directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "$FS.unlinkSync($$$)".to_string(),
                "heredoc.typescript.fs_unlinksync".to_string(),
                "fs.unlinkSync() deletes files".to_string(),
                Severity::Low,
                None,
            ),
            CompiledPattern::new(
                "Deno.remove($$$)".to_string(),
                "heredoc.typescript.deno_remove".to_string(),
                "Deno.remove() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            ),
            // The synchronous twin: same deletion, same refinement, same rule id
            // (so one grant covers both spellings). Only the async form was
            // modeled, so `Deno.removeSync('/etc', {recursive: true})` was allowed.
            CompiledPattern::new(
                "Deno.removeSync($$$)".to_string(),
                "heredoc.typescript.deno_remove".to_string(),
                "Deno.removeSync() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "child_process.execSync($$$)".to_string(),
                "heredoc.typescript.execsync".to_string(),
                "execSync() executes shell commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "require('child_process').execSync($$$)".to_string(),
                "heredoc.typescript.require_execsync".to_string(),
                "execSync() executes shell commands".to_string(),
                Severity::Medium, // refined to block only on destructive literal payloads
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "child_process.spawnSync($$$)".to_string(),
                "heredoc.typescript.spawnsync".to_string(),
                "spawnSync() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command and arguments carefully".to_string()),
            ),
            // Metavariable receivers, matching the JavaScript block: a literal
            // `fs.` left an aliased promises object unguarded (#459).
            CompiledPattern::new(
                "$FS.rm($$$)".to_string(),
                "heredoc.typescript.fs_rm".to_string(),
                "fs.rm() deletes files/directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "$FS.rmdir($$$)".to_string(),
                "heredoc.typescript.fs_rmdir".to_string(),
                "fs.rmdir() deletes directories".to_string(),
                Severity::Medium, // warn-only unless catastrophic literal target (refined at match time)
                Some("Verify target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "$FS.unlink($$$)".to_string(),
                "heredoc.typescript.fs_unlink".to_string(),
                "fs.unlink() deletes files".to_string(),
                Severity::Low,
                None,
            ),
            // No separate promise-based entries, for the reason spelled out on
            // the JavaScript side above: `$FS.rm`/`$FS.rmdir` match every
            // promise spelling, and a second pattern on the same call defeated
            // an allowlist entry for the rule id `explain` reported.
        ],
    );

    // Ruby patterns (git_safety_guard-mvh)
    patterns.insert(
        ScriptLanguage::Ruby,
        vec![
            // =========================================================================
            // Filesystem Deletion (High Signal)
            // =========================================================================
            CompiledPattern::new(
                "FileUtils.rm_rf($$$)".to_string(),
                "heredoc.ruby.fileutils_rm_rf".to_string(),
                "FileUtils.rm_rf() recursively deletes directories".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                Some("Verify target path carefully before running".to_string()),
            ),
            // `::` is Ruby's other call syntax for the same method, and it was
            // allowed while the `.` spelling denied.
            CompiledPattern::new(
                "FileUtils::rm_rf($$$)".to_string(),
                "heredoc.ruby.fileutils_rm_rf".to_string(),
                "FileUtils::rm_rf() recursively deletes directories".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                Some("Verify target path carefully before running".to_string()),
            ),
            // `rm_r` is the same recursive delete as `rm_rf` (which Ruby defines
            // as `rm_r` with `force: true`); it only differs by propagating
            // errors instead of swallowing them. It must be listed separately
            // here for the same reason it needs its own alternative in
            // `RUBY_FILEUTILS_LITERAL`: these are exact method names, so a
            // covered `rm_rf` grants `rm_r` nothing (#454).
            CompiledPattern::new(
                "FileUtils.rm_r($$$)".to_string(),
                "heredoc.ruby.fileutils_rm_r".to_string(),
                "FileUtils.rm_r() recursively deletes directories".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                Some("Verify target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "FileUtils.remove_entry($$$)".to_string(),
                "heredoc.ruby.fileutils_remove_entry".to_string(),
                "FileUtils.remove_entry() recursively deletes a path and its children".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                Some("Verify target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "FileUtils.remove_entry_secure($$$)".to_string(),
                "heredoc.ruby.fileutils_remove_entry_secure".to_string(),
                "FileUtils.remove_entry_secure() recursively deletes a path and its children"
                    .to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                Some("Verify target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "FileUtils.remove_dir($$$)".to_string(),
                "heredoc.ruby.fileutils_remove_dir".to_string(),
                "FileUtils.remove_dir() deletes directories".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                None,
            ),
            CompiledPattern::new(
                "FileUtils.rm($$$)".to_string(),
                "heredoc.ruby.fileutils_rm".to_string(),
                "FileUtils.rm() deletes files".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                None,
            ),
            // The force variants of the two calls above. Listing `rm`/`remove`
            // without them left the identical inversion this file already hit
            // with `rm_r`, one step smaller: the plain call blocked and its
            // `force: true` sibling did not (#454).
            CompiledPattern::new(
                "FileUtils.rm_f($$$)".to_string(),
                "heredoc.ruby.fileutils_rm_f".to_string(),
                "FileUtils.rm_f() force-deletes files".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                None,
            ),
            CompiledPattern::new(
                "FileUtils.remove($$$)".to_string(),
                "heredoc.ruby.fileutils_remove".to_string(),
                "FileUtils.remove() deletes files".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                None,
            ),
            CompiledPattern::new(
                "FileUtils.remove_file($$$)".to_string(),
                "heredoc.ruby.fileutils_remove_file".to_string(),
                "FileUtils.remove_file() deletes a file".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                None,
            ),
            // Empty directories only, and it delegates to `Dir.rmdir`, which
            // already blocks on a catastrophic target via
            // `heredoc.ruby.dir_rmdir`. Covering only one of the two spellings
            // was the inconsistency (#454).
            CompiledPattern::new(
                "FileUtils.rmdir($$$)".to_string(),
                "heredoc.ruby.fileutils_rmdir".to_string(),
                "FileUtils.rmdir() deletes empty directories".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                None,
            ),
            CompiledPattern::new(
                "File.delete($$$)".to_string(),
                "heredoc.ruby.file_delete".to_string(),
                "File.delete() removes files".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                None,
            ),
            CompiledPattern::new(
                "File.unlink($$$)".to_string(),
                "heredoc.ruby.file_unlink".to_string(),
                "File.unlink() removes files".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                None,
            ),
            CompiledPattern::new(
                "Dir.rmdir($$$)".to_string(),
                "heredoc.ruby.dir_rmdir".to_string(),
                "Dir.rmdir() removes directories".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                None,
            ),
            CompiledPattern::new(
                "Dir.delete($$$)".to_string(),
                "heredoc.ruby.dir_delete".to_string(),
                "Dir.delete() removes directories".to_string(),
                Severity::Medium, // refined to block only on catastrophic literal target
                None,
            ),
            // =========================================================================
            // Process Execution (Medium severity by default - avoid false positives)
            // =========================================================================
            CompiledPattern::new(
                "system($$$)".to_string(),
                "heredoc.ruby.system".to_string(),
                "system() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "exec($$$)".to_string(),
                "heredoc.ruby.exec".to_string(),
                "exec() replaces process with shell command".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "`$$$`".to_string(),
                "heredoc.ruby.backticks".to_string(),
                "Backticks execute shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            // Kernel.system and Kernel.exec variants
            CompiledPattern::new(
                "Kernel.system($$$)".to_string(),
                "heredoc.ruby.kernel_system".to_string(),
                "Kernel.system() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "Kernel.exec($$$)".to_string(),
                "heredoc.ruby.kernel_exec".to_string(),
                "Kernel.exec() replaces process with shell command".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            // Open3 for shell execution
            CompiledPattern::new(
                "Open3.capture3($$$)".to_string(),
                "heredoc.ruby.open3_capture3".to_string(),
                "Open3.capture3() executes shell commands".to_string(),
                Severity::Medium,
                None,
            ),
            CompiledPattern::new(
                "Open3.popen3($$$)".to_string(),
                "heredoc.ruby.open3_popen3".to_string(),
                "Open3.popen3() executes shell commands".to_string(),
                Severity::Medium,
                None,
            ),
        ],
    );

    // Bash patterns
    patterns.insert(
        ScriptLanguage::Bash,
        vec![
            CompiledPattern::new(
                "rm -rf $$$".to_string(),
                "heredoc.bash.rm_rf".to_string(),
                "rm -rf recursively deletes files/directories".to_string(),
                Severity::Critical,
                Some("Verify the target path carefully before running".to_string()),
            ),
            CompiledPattern::new(
                "rm -r $$$".to_string(),
                "heredoc.bash.rm_r".to_string(),
                "rm -r recursively deletes".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "git reset --hard".to_string(),
                "heredoc.bash.git_reset_hard".to_string(),
                "git reset --hard discards uncommitted changes".to_string(),
                Severity::Critical,
                Some("Use 'git stash' to save changes first".to_string()),
            ),
            CompiledPattern::new(
                "git clean -fd".to_string(),
                "heredoc.bash.git_clean_fd".to_string(),
                "git clean -fd deletes untracked files".to_string(),
                Severity::High,
                Some("Use 'git clean -n' to preview first".to_string()),
            ),
        ],
    );

    // Go patterns.
    //
    // Every Go pattern is contextual. Go's grammar has no top-level expression
    // statement, so a bare `os.RemoveAll($$$)` parses to an ERROR node and can
    // never match — see [`CompiledPattern::selector`] for why nothing caught
    // that for six patterns (#465). `func f() { … }` is the smallest enclosing
    // construct that parses, and `call_expression` binds to the OUTERMOST call
    // in it, so the chained `.Run()`/`.Output()` shapes keep their full span
    // rather than degrading to the bare `exec.Command` pattern.
    patterns.insert(
        ScriptLanguage::Go,
        vec![
            // Recursive deletion - always dangerous
            CompiledPattern::contextual(
                "func f() { os.RemoveAll($$$) }".to_string(),
                "call_expression".to_string(),
                "heredoc.go.os_removeall".to_string(),
                "os.RemoveAll() recursively deletes directories".to_string(),
                Severity::Critical,
                Some("Verify the target path carefully before running".to_string()),
            ),
            // File deletion
            CompiledPattern::contextual(
                "func f() { os.Remove($$$) }".to_string(),
                "call_expression".to_string(),
                "heredoc.go.os_remove".to_string(),
                "os.Remove() deletes files".to_string(),
                Severity::High,
                None,
            ),
            // Shell command execution - medium severity, refined at match time
            CompiledPattern::contextual(
                "func f() { exec.Command($$$) }".to_string(),
                "call_expression".to_string(),
                "heredoc.go.exec_command".to_string(),
                "exec.Command() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            // Combined patterns for common usage
            CompiledPattern::contextual(
                "func f() { exec.Command($$$).Run() }".to_string(),
                "call_expression".to_string(),
                "heredoc.go.exec_command_run".to_string(),
                "exec.Command().Run() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::contextual(
                "func f() { exec.Command($$$).Output() }".to_string(),
                "call_expression".to_string(),
                "heredoc.go.exec_command_output".to_string(),
                "exec.Command().Output() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::contextual(
                "func f() { exec.Command($$$).CombinedOutput() }".to_string(),
                "call_expression".to_string(),
                "heredoc.go.exec_command_combined_output".to_string(),
                "exec.Command().CombinedOutput() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
        ],
    );

    // PHP patterns
    patterns.insert(
        ScriptLanguage::Php,
        vec![
            // File/directory deletion
            CompiledPattern::new(
                "unlink($$$)".to_string(),
                "heredoc.php.unlink".to_string(),
                "unlink() deletes files".to_string(),
                Severity::High,
                None,
            ),
            // The fully-qualified spelling. A leading `\` resolves to the
            // global namespace and is the idiomatic way to call a builtin
            // from inside a namespace, so it is ordinary PHP rather than
            // obfuscation — and it was allowed while the bare call denied.
            CompiledPattern::new(
                "\\unlink($$$)".to_string(),
                "heredoc.php.unlink".to_string(),
                "unlink() deletes files".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "\\rmdir($$$)".to_string(),
                "heredoc.php.rmdir".to_string(),
                "rmdir() deletes directories".to_string(),
                Severity::High,
                None,
            ),
            CompiledPattern::new(
                "rmdir($$$)".to_string(),
                "heredoc.php.rmdir".to_string(),
                "rmdir() deletes directories".to_string(),
                Severity::High,
                None,
            ),
            // Shell execution patterns
            CompiledPattern::new(
                "exec($$$)".to_string(),
                "heredoc.php.exec".to_string(),
                "exec() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "system($$$)".to_string(),
                "heredoc.php.system".to_string(),
                "system() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "shell_exec($$$)".to_string(),
                "heredoc.php.shell_exec".to_string(),
                "shell_exec() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "passthru($$$)".to_string(),
                "heredoc.php.passthru".to_string(),
                "passthru() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "proc_open($$$)".to_string(),
                "heredoc.php.proc_open".to_string(),
                "proc_open() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "popen($$$)".to_string(),
                "heredoc.php.popen".to_string(),
                "popen() executes shell commands".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
            CompiledPattern::new(
                "`$$$`".to_string(),
                "heredoc.php.backticks".to_string(),
                "Backticks execute shell commands in PHP".to_string(),
                Severity::Medium,
                Some("Validate command arguments carefully".to_string()),
            ),
        ],
    );

    patterns
}

/// Global default matcher instance (lazy-initialized).
pub static DEFAULT_MATCHER: LazyLock<AstMatcher> = LazyLock::new(AstMatcher::new);

fn precompile_patterns(
    patterns: HashMap<ScriptLanguage, Vec<CompiledPattern>>,
) -> HashMap<ScriptLanguage, Vec<PrecompiledPattern>> {
    let mut out: HashMap<ScriptLanguage, Vec<PrecompiledPattern>> = HashMap::new();

    for (language, patterns) in patterns {
        let Some(ast_lang) = script_language_to_ast_lang(language) else {
            continue;
        };

        let mut compiled = Vec::with_capacity(patterns.len());
        for meta in patterns {
            let built = match meta.selector.as_deref() {
                Some(selector) => Pattern::contextual(&meta.pattern_str, selector, ast_lang),
                None => Pattern::try_new(&meta.pattern_str, ast_lang),
            };
            let Ok(pattern) = built else {
                // Fail-open: skip invalid patterns silently (default patterns should be validated by tests).
                continue;
            };

            compiled.push(PrecompiledPattern { pattern, meta });
        }

        if !compiled.is_empty() {
            out.insert(language, compiled);
        }
    }

    out
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::similar_names)] // `ast_matcher` vs `matches` is readable in test code
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// #438: `DCG_AST_TIMEOUT_MS` may raise the budget and never lower it.
    #[test]
    fn ast_timeout_env_override_only_raises() {
        // Absent, empty, and unparseable all keep the compiled-in budget rather
        // than failing or silently disabling the matcher.
        for requested in [
            None,
            Some(""),
            Some("   "),
            Some("abc"),
            Some("-5"),
            Some("1e3"),
        ] {
            assert_eq!(
                resolve_ast_timeout_ms(requested),
                AST_TIMEOUT_MS,
                "unusable value {requested:?} must keep the compiled-in budget"
            );
        }

        // A smaller budget is refused: it would push the matcher into its
        // bounded fallback, which denies without naming a rule.
        assert_eq!(resolve_ast_timeout_ms(Some("1")), AST_TIMEOUT_MS);
        assert_eq!(resolve_ast_timeout_ms(Some("0")), AST_TIMEOUT_MS);

        // A larger one is honoured, whitespace and all, up to the ceiling.
        let raised = AST_TIMEOUT_MS + 1_000;
        assert_eq!(resolve_ast_timeout_ms(Some(&raised.to_string())), raised);
        assert_eq!(
            resolve_ast_timeout_ms(Some(&format!("  {raised}  "))),
            raised
        );
        assert_eq!(
            resolve_ast_timeout_ms(Some("999999999")),
            AST_TIMEOUT_CEILING_MS,
            "a value past the ceiling is capped, not accepted"
        );

        // And the resolved process budget is never below the floor.
        assert!(ast_timeout() >= Duration::from_millis(AST_TIMEOUT_MS));
    }

    #[test]
    fn severity_labels() {
        assert_eq!(Severity::Critical.label(), "critical");
        assert_eq!(Severity::High.label(), "high");
        assert_eq!(Severity::Medium.label(), "medium");
        assert_eq!(Severity::Low.label(), "low");
    }

    #[test]
    fn severity_blocking() {
        assert!(Severity::Critical.blocks_by_default());
        assert!(Severity::High.blocks_by_default());
        assert!(!Severity::Medium.blocks_by_default());
        assert!(!Severity::Low.blocks_by_default());
    }

    #[test]
    fn match_error_display() {
        let errors = vec![
            MatchError::UnsupportedLanguage(ScriptLanguage::Perl),
            MatchError::ParseError {
                language: ScriptLanguage::Python,
                detail: "syntax error".to_string(),
            },
            MatchError::Timeout {
                elapsed_ms: 25,
                budget_ms: 20,
            },
            MatchError::PatternError {
                pattern: "bad pattern".to_string(),
                detail: "invalid syntax".to_string(),
            },
        ];

        for err in errors {
            let display = format!("{err}");
            assert!(!display.is_empty());
        }
    }

    #[test]
    fn matcher_default_has_patterns() {
        let ast_matcher = AstMatcher::new();
        assert!(!ast_matcher.patterns.is_empty());
        assert!(ast_matcher.patterns.contains_key(&ScriptLanguage::Python));
        assert!(
            ast_matcher
                .patterns
                .contains_key(&ScriptLanguage::JavaScript)
        );
        assert!(ast_matcher.patterns.contains_key(&ScriptLanguage::Ruby));
        assert!(ast_matcher.patterns.contains_key(&ScriptLanguage::Bash));
    }

    #[test]
    fn python_positive_match() {
        // The target moved out of /tmp for #455: `shutil.rmtree('/tmp/test')`
        // is the one case this rule is now expected NOT to block, because
        // `rm -rf /tmp/test` has always been allowed. The structural match is
        // what this test is about, so it uses a target the policy still blocks.
        let ast_matcher = AstMatcher::new();
        let code = "import shutil\nshutil.rmtree('/srv/data')";

        let matches = ast_matcher.find_matches(code, ScriptLanguage::Python);
        match matches {
            Ok(m) => {
                assert!(!m.is_empty(), "should match shutil.rmtree");
                assert_eq!(m[0].rule_id, "heredoc.python.shutil_rmtree");
                assert!(m[0].severity.blocks_by_default());
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    /// #455: the temp carve-out `rm -rf` has always had, given to `rmtree`.
    ///
    /// The false positive this closes is not hypothetical. `shutil.rmtree`
    /// paired with `tempfile.mkdtemp()` is what the standard library's own
    /// documentation recommends for cleaning up a scratch directory, and it
    /// was blocked.
    #[test]
    fn shutil_rmtree_gets_the_same_temp_carve_out_as_rm_rf_issue_455() {
        let ast_matcher = AstMatcher::new();

        for code in [
            "import shutil\nshutil.rmtree('/tmp/test')",
            "import shutil\nshutil.rmtree('/var/tmp/build')",
            "import shutil, tempfile\nshutil.rmtree(tempfile.mkdtemp())",
            "import shutil\nfrom tempfile import mkdtemp\nshutil.rmtree(mkdtemp())",
        ] {
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(
                !matches.iter().any(|m| m.severity.blocks_by_default()),
                "a temp target must not block: {code:?}"
            );
        }

        // The carve-out is the temp directory, not the word. Traversal out of
        // it, a relative `./tmp`, and a target this cannot read all still
        // block — the last one because an unreadable target is not a proven
        // safe one.
        for code in [
            "import shutil\nshutil.rmtree('/tmp/../etc')",
            "import shutil\nshutil.rmtree('./tmp')",
            "import shutil\nshutil.rmtree(target)",
        ] {
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(
                matches.iter().any(|m| m.severity.blocks_by_default()),
                "must still block: {code:?}"
            );
        }
    }

    #[test]
    fn python_negative_match() {
        let ast_matcher = AstMatcher::new();
        let code = "import os\nprint('hello world')";

        let matches = ast_matcher.find_matches(code, ScriptLanguage::Python);
        match matches {
            Ok(m) => assert!(m.is_empty(), "should not match safe code"),
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    mod javascript_positive_fixtures {
        use super::*;

        #[test]
        fn chained_and_promise_spellings_block_like_their_siblings() {
            // #453. The root cause was not the patterns: a chained receiver
            // made `JS_FIRST_STRING_ARG` read the *module name* as the target
            // path, so `require('fs')` scored as non-catastrophic and the hit
            // stayed warn-only. Each of these deletes a home directory.
            let ast_matcher = AstMatcher::new();
            for code in [
                "require('fs').rmSync('/home/user', { recursive: true, force: true })",
                "require('node:fs').rmSync('/home/user', { recursive: true })",
                "require('fs').promises.rm('/home/user', { recursive: true })",
                "const fs = require('fs'); fs.promises.rm('/home/user', { recursive: true })",
            ] {
                let matches = ast_matcher
                    .find_matches(code, ScriptLanguage::JavaScript)
                    .unwrap();
                assert!(
                    matches.iter().any(|m| m.severity.blocks_by_default()),
                    "must block: {code}"
                );
            }
        }

        #[test]
        fn alias_and_alternate_call_spellings_block_like_the_canonical_one() {
            // The #453 sweep carried into python/ruby/php: the same call,
            // spelled the way the language also allows, was being allowed.
            let ast_matcher = AstMatcher::new().with_timeout(std::time::Duration::from_millis(100));
            for (code, language) in [
                // Module alias — `import shutil as sh`.
                (
                    "import shutil as sh\nsh.rmtree('/home/user')",
                    ScriptLanguage::Python,
                ),
                (
                    "import shutil\nshutil.rmtree('/home/user')",
                    ScriptLanguage::Python,
                ),
                // `::` is Ruby's other call syntax for the same method.
                (
                    "require 'fileutils'\nFileUtils::rm_rf('/home/user')",
                    ScriptLanguage::Ruby,
                ),
                // A leading `\` resolves to PHP's global namespace, which is
                // the idiomatic way to call a builtin from inside one.
                ("<?php \\unlink('/home/user/id_rsa');", ScriptLanguage::Php),
                ("<?php \\rmdir('/home/user/.ssh');", ScriptLanguage::Php),
            ] {
                let matches = ast_matcher
                    .find_matches(code, language)
                    .expect("ast_matcher should run within 100ms");
                assert!(
                    matches.iter().any(|m| m.severity.blocks_by_default()),
                    "must block: {code:?}"
                );
            }
        }

        #[test]
        fn the_python_receiver_metavariable_widens_an_already_unconditional_rule() {
            // Stated plainly rather than discovered later: Python's
            // `shutil.rmtree` is `Severity::Critical` with no
            // catastrophic-path refinement, unlike the JavaScript and Ruby
            // rules. It already blocked `shutil.rmtree('./build')`, and
            // accepting any receiver means `mylib.rmtree('./cache')` blocks
            // too. That is a real widening, kept because `rmtree` is a
            // recursive-delete name whatever the module, and because the
            // alternative was missing `import shutil as sh`.
            let ast_matcher = AstMatcher::new().with_timeout(std::time::Duration::from_millis(100));
            for code in [
                "import shutil\nshutil.rmtree('./build')",
                "import mylib\nmylib.rmtree('./cache')",
            ] {
                let matches = ast_matcher
                    .find_matches(code, ScriptLanguage::Python)
                    .expect("ast_matcher should run within 100ms");
                assert!(
                    matches.iter().any(|m| m.severity.blocks_by_default()),
                    "python rmtree blocks at any target: {code:?}"
                );
            }
            // Only a mention with no call stays clear.
            {
                let code = "print('rmtree is dangerous')";
                let matches = ast_matcher
                    .find_matches(code, ScriptLanguage::Python)
                    .expect("ast_matcher should run within 100ms");
                assert!(
                    !matches.iter().any(|m| m.severity.blocks_by_default()),
                    "must not block: {code:?}"
                );
            }
        }

        #[test]
        fn a_chained_receiver_does_not_make_a_safe_target_look_dangerous() {
            // The mirror of the bug: reading the module name as the path could
            // just as easily have gone the other way.
            //
            // The recursive-delete row moved to `/tmp` for #455 — `./dist` now
            // blocks on its own merits, which would make this test pass for
            // the wrong reason. `/tmp/dist` keeps it measuring what it says.
            let ast_matcher = AstMatcher::new();
            for code in [
                "require('fs').rmSync('/tmp/dist', { recursive: true })",
                "require('fs').readFileSync('/home/user/notes.txt')",
            ] {
                let matches = ast_matcher
                    .find_matches(code, ScriptLanguage::JavaScript)
                    .unwrap();
                assert!(
                    !matches.iter().any(|m| m.severity.blocks_by_default()),
                    "must not block: {code}"
                );
            }
        }

        #[test]
        fn fs_rmsync_catastrophic_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "const fs = require('fs');\nfs.rmSync('/etc', { recursive: true });";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.javascript.fs_rmsync.catastrophic"),
                "catastrophic fs.rmSync should be detected"
            );
            let hit = matches
                .into_iter()
                .find(|m| m.rule_id == "heredoc.javascript.fs_rmsync.catastrophic")
                .unwrap();
            assert!(hit.severity.blocks_by_default());
        }

        /// #455: one policy for a recursive delete, whatever language spells it.
        ///
        /// This used to assert the opposite — that `fs.rmSync('./dist', {
        /// recursive: true })` only warns. That was deliberate and documented,
        /// and it was also the whole problem: `rm -rf ./dist` blocks, so an
        /// agent refused the shell spelling got the same effect from a Node
        /// one-liner. Nothing about that is adversarial; it is what a model
        /// does when a step is refused.
        ///
        /// The friction this costs is real and belongs in a test rather than
        /// in someone's build script, so `./dist` and `./node_modules` are
        /// named here on purpose.
        #[test]
        fn recursive_rmsync_outside_tmp_blocks_like_rm_rf_issue_455() {
            let ast_matcher = AstMatcher::new();

            for target in ["./dist", "./node_modules", "build", "/data/cache"] {
                let code = format!(
                    "const fs = require('fs');\nfs.rmSync('{target}', {{ recursive: true }});"
                );
                let matches = ast_matcher
                    .find_matches(&code, ScriptLanguage::JavaScript)
                    .unwrap();
                assert!(
                    matches
                        .iter()
                        .any(|m| m.rule_id == "heredoc.javascript.fs_rmsync.non_temp"
                            && m.severity.blocks_by_default()),
                    "recursive delete outside /tmp must block: {code}"
                );
            }

            // Still warn-only: a scratch directory, and a delete that does not
            // recurse. `fs.rmSync('./a.txt')` removes one file and is not this
            // rule's business.
            for code in [
                "const fs = require('fs');\nfs.rmSync('/tmp/dist', { recursive: true });",
                "const fs = require('fs');\nfs.rmSync('./a.txt');",
            ] {
                let matches = ast_matcher
                    .find_matches(code, ScriptLanguage::JavaScript)
                    .unwrap();
                assert!(
                    !matches.iter().any(|m| m.severity.blocks_by_default()),
                    "must not block: {code}"
                );
            }
        }

        #[test]
        fn execsync_git_reset_hard_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "const child_process = require('child_process');\nchild_process.execSync('git reset --hard');";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".git_reset_hard")
                        && m.severity.blocks_by_default()),
                "execSync('git reset --hard') should block"
            );
        }

        /// #455's single policy reaches an exec-sink `rm -rf` payload too.
        ///
        /// This test used to be `execsync_rm_rf_non_catastrophic_warns_only`,
        /// written long before #455. When #455 made a non-temp recursive delete
        /// deny in every language it deleted the matching warns-only tests for
        /// the calls it covered (`fs_rmsync_…`, `fileutils_rm_rf_…`); this one
        /// was never revisited. `rm -rf` is the canonical recursive delete, so
        /// it follows the same rule: a non-temp target blocks and the temp
        /// carve-out does not. Both halves are pinned.
        #[test]
        fn execsync_rm_rf_follows_the_single_policy_issue_455() {
            let ast_matcher = AstMatcher::new();
            let severity_for = |target: &str| {
                let code = format!(
                    "const child_process = require('child_process');\n\
                     child_process.execSync('rm -rf {target}');"
                );
                ast_matcher
                    .find_matches(&code, ScriptLanguage::JavaScript)
                    .unwrap()
                    .into_iter()
                    .find(|m| m.rule_id.ends_with(".rm_rf"))
                    .unwrap_or_else(|| panic!("execSync('rm -rf {target}') should be detected"))
                    .severity
            };
            assert!(
                severity_for("./build").blocks_by_default(),
                "a recursive delete outside a temp directory blocks (#455)"
            );
            assert!(
                !severity_for("/tmp/build").blocks_by_default(),
                "the temp carve-out is the same one `rm -rf /tmp/x` has in the shell"
            );
        }

        #[test]
        fn spawnsync_rm_rf_catastrophic_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "const child_process = require('child_process');\nchild_process.spawnSync('rm', ['-rf', '/']);";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".rm_rf_catastrophic")
                        && m.severity.blocks_by_default()),
                "spawnSync('rm', ['-rf','/']) should block"
            );
        }

        #[test]
        fn fs_rmsync_path_traversal_escapes_tmp_blocks() {
            // Path traversal from /tmp to /etc should be detected as catastrophic
            let ast_matcher = AstMatcher::new();
            let code = "const fs = require('fs');\nfs.rmSync('/tmp/../etc', { recursive: true });";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.javascript.fs_rmsync.catastrophic"),
                "path traversal /tmp/../etc should be detected as catastrophic"
            );
            let hit = matches
                .into_iter()
                .find(|m| m.rule_id == "heredoc.javascript.fs_rmsync.catastrophic")
                .unwrap();
            assert!(hit.severity.blocks_by_default());
        }
    }

    mod javascript_negative_fixtures {
        use super::*;

        #[test]
        fn printed_dangerous_string_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "console.log('rm -rf /');";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn require_child_process_alone_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "require('child_process');";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn execsync_safe_payload_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "const child_process = require('child_process');\nchild_process.execSync('git status');";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn fs_rmsync_without_recursive_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "const fs = require('fs');\nfs.rmSync('./file.txt');";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn spawnsync_echo_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "const child_process = require('child_process');\nchild_process.spawnSync('echo', ['rm -rf /']);";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn fs_rmsync_tmp_dotdot_in_filename_does_not_block() {
            // Filenames with consecutive dots are NOT path traversal
            let ast_matcher = AstMatcher::new();
            let code =
                "const fs = require('fs');\nfs.rmSync('/tmp/foo..bar', { recursive: true });";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::JavaScript)
                .unwrap();
            // Should match as medium severity (warn), NOT as catastrophic
            assert!(
                !matches.iter().any(|m| m.rule_id.contains("catastrophic")),
                "foo..bar is a filename, not path traversal"
            );
        }
    }

    #[test]
    fn unsupported_language_returns_error() {
        let ast_matcher = AstMatcher::new();
        let code = "print 'hello perl';";

        let result = ast_matcher.find_matches(code, ScriptLanguage::Unknown);
        assert!(matches!(result, Err(MatchError::UnsupportedLanguage(_))));
    }

    #[test]
    fn zero_timeout_fails_open_before_parsing_malformed_input() {
        let ast_matcher = AstMatcher::new().with_timeout(Duration::ZERO);
        let mut code = "function f() {".to_string();
        code.push_str(&"(".repeat(256 * 1024));

        let start = Instant::now();
        let result = ast_matcher.find_matches(&code, ScriptLanguage::JavaScript);

        assert!(
            matches!(result, Err(MatchError::Timeout { .. })),
            "zero timeout should fail open before AST parsing starts"
        );
        // The matches!(Err(Timeout)) check above is the real regression guard. This
        // timing bound only documents "returned promptly without parsing"; it is
        // deliberately generous so scheduler preemption under heavy parallel load
        // can't flake it (parsing the 256K-token malformed input would take far
        // longer than this ceiling).
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "zero-timeout malformed input should return immediately"
        );
    }

    #[test]
    fn oversized_input_fails_open_without_ast_parse() {
        let ast_matcher = AstMatcher::new().with_timeout(Duration::from_secs(10));
        let code = "x = 1\n".repeat((MAX_AST_INPUT_BYTES / 6) + 2);
        assert!(code.len() > MAX_AST_INPUT_BYTES);

        let start = Instant::now();
        let result = ast_matcher.find_matches(&code, ScriptLanguage::Python);

        assert!(
            matches!(result, Err(MatchError::Timeout { .. })),
            "oversized direct matcher input should fail open on the budget guard"
        );
        // As above, the matches!(Err(Timeout)) check is the real guard; this
        // generous timing bound only documents the early return and avoids
        // load-induced flakes.
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "oversized input should not enter ast-grep parsing"
        );
    }

    #[test]
    fn happy_path_still_matches_with_bounded_worker() {
        let ast_matcher = AstMatcher::new().with_timeout(Duration::from_millis(250));
        // A non-temp target, so the rule id is the unrefined one this asserts
        // on; `/tmp/test` now refines to `.temp` (#455).
        let code = "import shutil\nshutil.rmtree('/srv/data')";

        let matches = ast_matcher
            .find_matches(code, ScriptLanguage::Python)
            .expect("small valid input should parse within the worker budget");

        assert!(
            matches
                .iter()
                .any(|m| m.rule_id == "heredoc.python.shutil_rmtree"),
            "bounded worker should preserve normal AST matches"
        );
    }

    #[test]
    fn has_blocking_match_returns_first_blocker() {
        let ast_matcher = AstMatcher::new();
        let code = "import shutil\nshutil.rmtree('/danger')";

        let result = ast_matcher.has_blocking_match(code, ScriptLanguage::Python);
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_id, "heredoc.python.shutil_rmtree");
    }

    #[test]
    fn has_blocking_match_returns_none_for_safe_code() {
        let ast_matcher = AstMatcher::new();
        let code = "x = 1 + 2";

        let result = ast_matcher.has_blocking_match(code, ScriptLanguage::Python);
        assert!(result.is_none());
    }

    #[test]
    fn has_blocking_match_fails_open_on_error() {
        let ast_matcher = AstMatcher::new();
        let code = "some perl code";

        // Unknown is unsupported - should fail open (return None, not panic)
        let result = ast_matcher.has_blocking_match(code, ScriptLanguage::Unknown);
        assert!(result.is_none());
    }

    mod perl_positive_fixtures {
        use super::*;

        #[test]
        fn perl_system_rm_rf_catastrophic_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "system(\"rm -rf /\");\n";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Perl)
                .expect("perl ast_matcher should run");
            assert!(!matches.is_empty());
            assert!(matches[0].rule_id.contains("rm_rf"));
            assert!(matches[0].severity.blocks_by_default());
        }

        /// Perl's `system('rm -rf …')` follows #455's single policy too.
        ///
        /// Formerly `perl_system_rm_rf_non_catastrophic_warns_only`, a pre-#455
        /// pin that #455 never revisited; see
        /// `execsync_rm_rf_follows_the_single_policy_issue_455` for why.
        #[test]
        fn perl_system_rm_rf_follows_the_single_policy_issue_455() {
            let ast_matcher = AstMatcher::new();
            let severity_for = |target: &str| {
                let matches = ast_matcher
                    .find_matches(
                        &format!("system('rm -rf {target}');\n"),
                        ScriptLanguage::Perl,
                    )
                    .expect("perl ast_matcher should run");
                let hit = matches
                    .into_iter()
                    .find(|m| m.rule_id.contains("rm_rf"))
                    .unwrap_or_else(|| panic!("system('rm -rf {target}') should be detected"));
                hit.severity
            };
            assert!(
                severity_for("./build").blocks_by_default(),
                "a recursive delete outside a temp directory blocks (#455)"
            );
            assert!(
                !severity_for("/tmp/build").blocks_by_default(),
                "the temp carve-out is the same one `rm -rf /tmp/x` has in the shell"
            );
        }

        /// Every operand of an exec-sink `rm -rf` is weighed. Only the first
        /// used to count, so a temp decoy in front laundered the rest.
        #[test]
        fn exec_sink_rm_rf_weighs_every_operand() {
            let severity = |call: &str| detect_destructive_in_args(call).map(|hit| hit.severity);
            for (call, expected) in [
                (
                    "spawnSync('rm', ['-rf', '/tmp/x', '/'])",
                    Severity::Critical,
                ),
                ("system('rm', '-rf', '/tmp/x', './build')", Severity::High),
                (
                    "system('rm', '-rf', '/tmp/x', '/var/tmp/y')",
                    Severity::Medium,
                ),
                // An argv element is one word: no shell parses it, so `;` and
                // `>` hide nothing after them.
                (
                    "spawnSync('rm', ['-rf', '/tmp/x;', '/'])",
                    Severity::Critical,
                ),
                (
                    "spawnSync('rm', ['-rf', '/tmp/x', '>', '/'])",
                    Severity::Critical,
                ),
                // In a shell string a QUOTED `>` is a file name too.
                ("execSync(\"rm -rf /tmp/x '>' /\")", Severity::Critical),
                // GNU `rm` permutes: an option after an operand still applies.
                ("spawnSync('rm', ['./build', '-rf'])", Severity::High),
                // A dynamic operand does not end the argv.
                ("system('rm', '-rf', $dir, '/')", Severity::Critical),
                // A harmless payload in one literal does not end the search.
                (
                    "spawnSync('rm', ['-rf', 'rm -rf /tmp/y', '/'])",
                    Severity::Critical,
                ),
                // Python's argv passed by keyword is still the argv.
                (
                    "subprocess.run(args=['rm', '-rf', '/'], check=True)",
                    Severity::Critical,
                ),
            ] {
                assert_eq!(severity(call), Some(expected), "{call}");
            }
        }

        /// What an exec sink is told besides its argv — options, callbacks,
        /// redirections, a paren-less statement's tail — names no operand.
        /// Each of these deletes only `/tmp/x`.
        #[test]
        fn exec_sink_options_are_not_rm_operands() {
            for call in [
                "spawnSync('rm', ['-rf', '/tmp/x'], { stdio: 'inherit' })",
                "execFile('rm', ['-rf', '/tmp/x'], (err) => console.log('rm -rf / failed'))",
                "system('rm', '-rf', '/tmp/x', out: '/dev/null')",
                "system('rm', '-rf', '/tmp/x', :out => '/dev/null')",
                "system('rm', '-rf', '/tmp/x', 'out' => '/dev/null')",
                "subprocess.run(['rm', '-rf', '/tmp/x'], cwd='/')",
                "system 'rm', '-rf', '/tmp/x' or die \"rm -rf / failed\";",
                "system 'rm', '-rf', '/tmp/x' if -d '/etc';",
                "system 'rm', '-rf', '/tmp/x'; unlink '/etc';",
                "execSync('rm -rf /tmp/x 2>/dev/null')",
                "execSync('rm -rf /tmp/x > /dev/null')",
            ] {
                assert_eq!(
                    detect_destructive_in_args(call).map(|hit| hit.severity),
                    Some(Severity::Medium),
                    "{call}"
                );
            }
        }

        /// Perl's argv form of `system`/`exec` is read in full. Only its first
        /// literal used to be, and `rm` alone flags nothing.
        #[test]
        fn perl_argv_form_system_exec_is_read_in_full() {
            let ast_matcher = AstMatcher::new();
            // (blocks, is critical)
            let verdict = |code: &str| {
                let matches = ast_matcher
                    .find_matches(code, ScriptLanguage::Perl)
                    .expect("perl ast_matcher should run");
                (
                    matches.iter().any(|m| m.severity.blocks_by_default()),
                    matches.iter().any(|m| m.severity == Severity::Critical),
                )
            };
            assert_eq!(verdict("system('rm', '-rf', '/');\n"), (true, true));
            assert_eq!(verdict("system 'rm', '-rf', '/';\n"), (true, true));
            assert_eq!(verdict("exec('rm', '-rf', './build');\n"), (true, false));
            assert_eq!(
                verdict("system('git', 'reset', '--hard');\n"),
                (true, false)
            );
            assert_eq!(
                verdict("system('rm', '-rf', '/tmp/x') == 0 or die 'rm -rf / failed';\n"),
                (false, false),
                "the `die` message is outside the call"
            );
            assert_eq!(verdict("system('ls', '-la');\n"), (false, false));
            // Without parentheses, a bracket inside an argument is not the
            // call's own: `./build` after `lc(…)` is still an operand.
            assert_eq!(
                verdict("system 'rm', '-rf', lc('/tmp/x'), './build';\n"),
                (true, false)
            );
            assert_eq!(
                verdict("system 'rm', '-rf', '/tmp/x' if -d lc('/');\n"),
                (false, false),
                "the statement modifier is not part of the argv"
            );
        }

        /// `rmtree`/`remove_tree` weigh every path they are given, in both
        /// interfaces. Only the first used to count, and the legacy array
        /// reference was not matched at all — `rmtree(['/'])` was allowed.
        #[test]
        fn perl_file_path_weighs_every_path() {
            let ast_matcher = AstMatcher::new();
            // (rule id, severity) of the File::Path match, if any.
            let file_path_hit = |code: &str| {
                ast_matcher
                    .find_matches(code, ScriptLanguage::Perl)
                    .expect("perl ast_matcher should run")
                    .into_iter()
                    .find(|m| m.rule_id.starts_with("heredoc.perl.file_path."))
                    .map(|m| (m.rule_id, m.severity))
            };
            let blocks = |code: &str| {
                file_path_hit(code).is_some_and(|(_, severity)| severity.blocks_by_default())
            };
            for code in [
                "rmtree('/tmp/x', '/');\n",
                "remove_tree('/tmp/x', './build');\n",
                "File::Path::rmtree('/tmp/x', '/home/user');\n",
                "rmtree(['/']);\n",
                "rmtree(['/tmp/x', './build'], 1, 1);\n",
                "rmtree '/tmp/x', '/';\n",
            ] {
                assert!(blocks(code), "{code}: {:?}", file_path_hit(code));
            }
            assert_eq!(
                file_path_hit("rmtree('/tmp/x', './build');\n").map(|(rule, _)| rule),
                Some("heredoc.perl.file_path.rmtree.non_temp".to_string())
            );
            // Temp-only targets, however many, stay warn-only; an options
            // hash's strings are not paths; a dynamic list is not judged here.
            for code in [
                "rmtree('/tmp/x', '/var/tmp/y');\n",
                "rmtree(['/tmp/x'], 0, 1);\n",
                "remove_tree('/tmp/x', { error => \\my $err, result => '/' });\n",
            ] {
                assert!(!blocks(code), "{code}: {:?}", file_path_hit(code));
            }
            assert_eq!(file_path_hit("rmtree([$dir]);\n"), None);
        }

        /// #453: `File::Path` is normally imported and called bare, so requiring
        /// the `File::Path::` qualifier guarded only the rarer spelling.
        #[test]
        fn perl_file_path_blocks_imported_and_qualified_spellings_issue_453() {
            let ast_matcher = AstMatcher::new();

            for code in [
                "use File::Path;\nFile::Path::rmtree('/home/user');\n",
                "use File::Path qw(rmtree);\nrmtree('/home/user');\n",
                "use File::Path qw(rmtree);\nrmtree '/home/user';\n",
                "use File::Path;\nFile::Path::remove_tree('/home/user');\n",
                "use File::Path qw(remove_tree);\nremove_tree('/home/user');\n",
            ] {
                let matches = ast_matcher
                    .find_matches(code, ScriptLanguage::Perl)
                    .expect("perl ast_matcher should run");
                assert!(
                    matches
                        .iter()
                        .any(|m| m.rule_id.starts_with("heredoc.perl.file_path.")
                            && m.severity.blocks_by_default()),
                    "catastrophic File::Path delete must block regardless of spelling; \
                     code was {code:?}, got {:?}",
                    matches.iter().map(|m| &m.rule_id).collect::<Vec<_>>()
                );
            }
        }

        /// Negative control for the test above: dropping the required qualifier
        /// must not turn the bare names into a blanket match.
        #[test]
        fn perl_file_path_unqualified_still_respects_target_and_context_issue_453() {
            let ast_matcher = AstMatcher::new();

            // A scratch target warns rather than blocks, as the qualified
            // spelling already did. This row was `./build` until #455 gave
            // Perl the same recursive-delete policy as the other four
            // languages; the unqualified spelling has to follow the qualified
            // one wherever that policy lands, which is what this asserts.
            let scratch = ast_matcher
                .find_matches(
                    "use File::Path qw(rmtree);\nrmtree('/tmp/build');\n",
                    ScriptLanguage::Perl,
                )
                .expect("perl ast_matcher should run");
            assert!(
                !scratch.iter().any(|m| m.severity.blocks_by_default()),
                "rmtree('/tmp/build') targets a scratch directory and must warn only; got {:?}",
                scratch.iter().map(|m| &m.rule_id).collect::<Vec<_>>()
            );

            // …and the non-temp spelling blocks, so the row above is measuring
            // the carve-out rather than a rule that never fires.
            let relative = ast_matcher
                .find_matches(
                    "use File::Path qw(rmtree);\nrmtree('./build');\n",
                    ScriptLanguage::Perl,
                )
                .expect("perl ast_matcher should run");
            assert!(
                relative
                    .iter()
                    .any(|m| m.rule_id == "heredoc.perl.file_path.rmtree.non_temp"
                        && m.severity.blocks_by_default()),
                "rmtree('./build') is a recursive delete outside /tmp and must block; got {:?}",
                relative.iter().map(|m| &m.rule_id).collect::<Vec<_>>()
            );

            // A comment mentioning the call is masked before the scan.
            let comment = ast_matcher
                .find_matches("# never call rmtree('/home/user')\n", ScriptLanguage::Perl)
                .expect("perl ast_matcher should run");
            assert!(
                !comment.iter().any(|m| m.severity.blocks_by_default()),
                "a commented-out rmtree must not block; got {:?}",
                comment.iter().map(|m| &m.rule_id).collect::<Vec<_>>()
            );

            // No string argument means no literal target to judge.
            let dynamic = ast_matcher
                .find_matches("rmtree($dir);\n", ScriptLanguage::Perl)
                .expect("perl ast_matcher should run");
            assert!(
                !dynamic.iter().any(|m| m.severity.blocks_by_default()),
                "rmtree($dir) has no literal target and must not block here; got {:?}",
                dynamic.iter().map(|m| &m.rule_id).collect::<Vec<_>>()
            );
        }

        #[test]
        fn perl_backticks_git_reset_hard_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "`git reset --hard`;\n";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Perl)
                .expect("perl ast_matcher should run");
            assert!(!matches.is_empty());
            assert!(matches[0].rule_id.contains("git_reset_hard"));
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn perl_qx_rm_rf_catastrophic_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "qx/rm -rf \\/etc/;\n";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Perl)
                .expect("perl ast_matcher should run");
            assert!(!matches.is_empty());
            assert!(matches[0].rule_id.contains("rm_rf"));
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn perl_unqualified_rmtree_matches_when_the_module_is_imported() {
            // #453. `File::Path` exports both by default, so the unqualified
            // call is the documented usage and the fully-qualified spelling
            // the rule required is the rarer one.
            let ast_matcher = AstMatcher::new().with_timeout(std::time::Duration::from_millis(100));
            for code in [
                "use File::Path; rmtree('/home/user');",
                "use File::Path qw(remove_tree); remove_tree('/home/user');",
                "use File::Path;\nremove_tree('/home/user');\n",
            ] {
                let matches = ast_matcher
                    .find_matches(code, ScriptLanguage::Perl)
                    .expect("perl ast_matcher should run within 100ms");
                assert!(
                    matches.iter().any(|m| m.severity.blocks_by_default()),
                    "must block: {code}"
                );
            }
        }

        #[test]
        fn perl_unqualified_rmtree_does_not_require_the_import() {
            // Deliberate: the qualifier is optional and there is no
            // import gate, matching `PERL_UNLINK_LITERAL` and
            // `PERL_RMDIR_LITERAL` beside it, which have never required one.
            //
            // The cost is that a local `sub rmtree` deleting a catastrophic
            // path also matches. That is the direction this guard errs in, and
            // it also means a `-MFile::Path` one-liner — where the import is on
            // the command line and never appears in the extracted script — is
            // still covered. An import gate would have been tidier and would
            // have missed that.
            let ast_matcher = AstMatcher::new().with_timeout(std::time::Duration::from_millis(100));
            let matches = ast_matcher
                .find_matches(
                    "sub rmtree { print 'hi' } rmtree('/home/user');",
                    ScriptLanguage::Perl,
                )
                .expect("perl ast_matcher should run within 100ms");
            assert!(
                matches.iter().any(|m| m.severity.blocks_by_default()),
                "a bare rmtree on a catastrophic path blocks whether or not the import is visible"
            );

            // What still must not fire: a mention with no call, and a call on
            // a scratch target. `rmtree('./build')` used to be the second case
            // here; #455 gave Perl the same single recursive-delete policy as
            // the other four languages, so a non-temp target blocks and only
            // the temp carve-out is left.
            for code in [
                "print 'rmtree is dangerous';",
                "use File::Path; rmtree('/tmp/build');",
            ] {
                let matches = ast_matcher
                    .find_matches(code, ScriptLanguage::Perl)
                    .expect("perl ast_matcher should run within 100ms");
                assert!(
                    !matches.iter().any(|m| m.severity.blocks_by_default()),
                    "must not block: {code}"
                );
            }
        }

        #[test]
        fn perl_file_path_rmtree_warns_by_default() {
            // Use longer timeout for test reliability (default 20ms can be flaky under load)
            let ast_matcher = AstMatcher::new().with_timeout(std::time::Duration::from_millis(100));
            let code = "use File::Path;\nFile::Path::rmtree(\"/tmp/test\");\n";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Perl)
                .expect("perl ast_matcher should run within 100ms");
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.perl.file_path.rmtree"),
                "should match File::Path::rmtree"
            );
            let rmtree = matches
                .into_iter()
                .find(|m| m.rule_id == "heredoc.perl.file_path.rmtree")
                .expect("rmtree match present");
            assert!(!rmtree.severity.blocks_by_default());
        }
    }

    mod perl_negative_fixtures {
        use super::*;

        #[test]
        fn perl_comments_do_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "# system(\"rm -rf /\")\nprint \"ok\";\n";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Perl)
                .expect("perl ast_matcher should run");
            assert!(
                matches.is_empty(),
                "commented-out dangerous code is not executed"
            );
        }

        #[test]
        fn perl_printing_dangerous_string_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "print \"rm -rf /\";\n";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Perl)
                .expect("perl ast_matcher should run");
            assert!(
                matches.is_empty(),
                "printed strings are data, not execution"
            );
        }
    }

    #[test]
    fn match_includes_line_number() {
        let ast_matcher = AstMatcher::new();
        let code = "x = 1\ny = 2\nshutil.rmtree('/test')";

        let matches = ast_matcher
            .find_matches(code, ScriptLanguage::Python)
            .expect("should parse");
        assert!(!matches.is_empty());
        assert_eq!(matches[0].line_number, 3); // shutil.rmtree is on line 3
    }

    #[test]
    fn match_preview_truncates_long_text() {
        let ast_matcher = AstMatcher::new();
        // Create code with a very long argument
        let long_path = "/very/long/path/".repeat(10);
        let code = format!("import shutil\nshutil.rmtree('{long_path}')");

        let results = ast_matcher
            .find_matches(&code, ScriptLanguage::Python)
            .expect("should parse");
        assert!(!results.is_empty());
        // Preview should be truncated
        assert!(results[0].matched_text_preview.len() <= 63);
        assert!(results[0].matched_text_preview.ends_with("..."));
    }

    #[test]
    fn empty_code_returns_no_matches() {
        let ast_matcher = AstMatcher::new();

        let results = ast_matcher
            .find_matches("", ScriptLanguage::Python)
            .expect("should parse empty code");
        assert!(results.is_empty());
    }

    #[test]
    fn default_matcher_is_lazy_initialized() {
        // Just verify it can be accessed without panic
        let _ = &*DEFAULT_MATCHER;
        assert!(!DEFAULT_MATCHER.patterns.is_empty());
    }

    #[test]
    fn default_patterns_all_precompile() {
        let raw = default_patterns();
        let expected: HashMap<ScriptLanguage, usize> =
            raw.iter().map(|(lang, pats)| (*lang, pats.len())).collect();

        let compiled = precompile_patterns(raw);

        for (lang, expected_len) in expected {
            let got = compiled.get(&lang).map_or(0, std::vec::Vec::len);
            assert_eq!(
                got, expected_len,
                "all default patterns should compile for {lang:?}"
            );
        }
    }

    /// `docs/patterns.md` must list every rule id, and no others.
    ///
    /// Those tables are what a user copies into an allowlist: `dcg allowlist add`
    /// keys on the exact string, so a stale id documented there is an exception
    /// that silently never matches, and a missing id is a rule nobody can
    /// discover or grant. The file is hand-maintained and had drifted five ways
    /// at once — all nine PHP rules undocumented, four `fspromises_*` rows left
    /// behind by #467, three rows still advertising a pre-#459 spelling, six Go
    /// rows added by #465, and `shutil_rmtree` understating its own receiver.
    ///
    /// Only rule ids are asserted, not the Pattern column. Go's patterns are
    /// registered inside a `func f() { … }` wrapper the selector discards, and
    /// some rows legitimately document two spellings in one cell, so comparing
    /// the text would be noise. The id is the part that has to be exact.
    ///
    /// `src/perf.rs` does the same thing for the CI workflow's coverage
    /// thresholds; this is that pattern applied to the pattern inventory.
    #[test]
    fn documented_rule_ids_match_the_corpus() {
        const DOCS: &str = include_str!("../docs/patterns.md");

        // A table row's first cell, backtick-quoted. Derived ids (`.catastrophic`,
        // `.temp`, `.non_temp`, a payload suffix) are documented in prose under
        // "Derived Rule IDs" rather than as rows, and carry a fourth segment, so
        // requiring exactly three tells them apart from a registered id. Perl is
        // absent by construction: its rules come from `precompile_perl_patterns`
        // rather than this corpus, and its docs are a bullet list, not a table.
        let documented: std::collections::BTreeSet<&str> = DOCS
            .lines()
            .filter(|line| line.starts_with('|'))
            .filter_map(|line| line.split('|').nth(1))
            .map(|cell| cell.trim().trim_matches('`'))
            .filter(|id| id.starts_with("heredoc.") && id.split('.').count() == 3)
            .collect();

        let registered: std::collections::BTreeSet<String> = default_patterns()
            .into_values()
            .flatten()
            .map(|meta| meta.rule_id)
            .collect();

        // The two set differences below imply equality, and a parser that found
        // nothing would make the first one fail — but BOTH sets being empty would
        // pass vacuously, so pin a floor. The corpus was 72 ids across six
        // languages when this was written; the bound is deliberately loose because
        // the point is "not empty", not a count to maintain.
        assert!(
            registered.len() > 50 && documented.len() > 50,
            "expected a populated corpus and doc set, got {} registered and {} \
             documented — this test would otherwise pass vacuously",
            registered.len(),
            documented.len()
        );

        let undocumented: Vec<&String> = registered
            .iter()
            .filter(|id| !documented.contains(id.as_str()))
            .collect();
        let stale: Vec<&&str> = documented
            .iter()
            .filter(|id| !registered.contains(**id))
            .collect();

        assert!(
            undocumented.is_empty(),
            "{} rule id(s) exist but are not in docs/patterns.md, so no user can \
             discover or allowlist them: {undocumented:?}",
            undocumented.len()
        );
        assert!(
            stale.is_empty(),
            "{} rule id(s) are documented but no longer exist, so an allowlist \
             entry copied from the docs would never match: {stale:?}",
            stale.len()
        );
    }

    /// Compiling is not matching: every language's corpus must actually fire.
    ///
    /// `default_patterns_all_precompile` above passed for the entire life of
    /// the Go corpus while all six Go patterns were incapable of matching
    /// anything (#465). A bare `os.RemoveAll($$$)` is not a parseable Go
    /// fragment — Go has no top-level expression statement — so it compiled to
    /// an ERROR-rooted tree. `Pattern::try_new` returned `Ok`, the count check
    /// was satisfied, and `os.RemoveAll` at `Severity::Critical` silently
    /// matched nothing in any Go heredoc.
    ///
    /// Two structural predicates were tried first and both failed to see it:
    /// `Pattern::has_error()` reports `false` for those patterns, and
    /// ast-grep's own `are_kinds_matching` treats an ERROR *goal* kind as a
    /// wildcard, so kind inspection cannot distinguish a broken pattern from a
    /// deliberately permissive one. Only behaviour can, hence a fixture.
    ///
    /// This is a floor, not a per-pattern guarantee: it asserts each language
    /// is non-vacuous. `go_corpus_matches_every_registered_rule_issue_465`
    /// carries the per-rule table for Go, the language this bug class hit.
    #[test]
    fn every_language_corpus_matches_its_fixture_issue_465() {
        // One fixture per language, each exercising at least one registered
        // pattern. A language whose corpus matches nothing here is dead code
        // pretending to be coverage.
        let fixtures: &[(ScriptLanguage, &str)] = &[
            (ScriptLanguage::Bash, "git reset --hard HEAD~1\n"),
            (
                ScriptLanguage::Go,
                "package main\n\nimport \"os\"\n\nfunc main() {\n\tos.RemoveAll(\"/home/user\")\n}\n",
            ),
            (
                ScriptLanguage::JavaScript,
                "require('fs').rmSync('/home/user', { recursive: true })\n",
            ),
            (
                ScriptLanguage::TypeScript,
                "require('fs').rmSync('/home/user', { recursive: true })\n",
            ),
            (ScriptLanguage::Php, "<?php\nunlink('/home/user/id_rsa');\n"),
            (
                ScriptLanguage::Python,
                "import shutil\nshutil.rmtree('/home/user')\n",
            ),
            (
                ScriptLanguage::Ruby,
                "require 'fileutils'\nFileUtils.rm_rf('/home/user')\n",
            ),
        ];

        let registered: Vec<ScriptLanguage> = DEFAULT_MATCHER.patterns.keys().copied().collect();
        for language in &registered {
            assert!(
                fixtures.iter().any(|(lang, _)| lang == language),
                "{language:?} has registered patterns but no fixture; a new language \
                 must prove its corpus matches something"
            );
        }

        for (language, source) in fixtures {
            let hits = DEFAULT_MATCHER
                .find_matches(source, *language)
                .unwrap_or_else(|error| panic!("{language:?} fixture failed to scan: {error:?}"));
            assert!(
                !hits.is_empty(),
                "{language:?} registered {} patterns but matched nothing in its own \
                 fixture — the corpus cannot block anything",
                DEFAULT_MATCHER
                    .patterns
                    .get(language)
                    .map_or(0, std::vec::Vec::len)
            );
        }
    }

    /// Every registered Go rule id must fire on a real Go program (#465).
    ///
    /// Go is the language that carried six unmatchable patterns, so it gets the
    /// per-rule table rather than the per-language floor above. The chained
    /// assertions also pin the selector binding: `call_expression` must resolve
    /// to the OUTERMOST call, or `.Run()`/`.Output()`/`.CombinedOutput()`
    /// silently collapse into the bare `exec.Command` pattern.
    #[test]
    fn go_corpus_matches_every_registered_rule_issue_465() {
        let source = concat!(
            "package main\n\n",
            "import (\n\t\"os\"\n\t\"os/exec\"\n)\n\n",
            "func main() {\n",
            "\tos.RemoveAll(\"/home/user\")\n",
            "\tos.Remove(\"/home/user/.ssh/id_rsa\")\n",
            "\t_ = exec.Command(\"ls\", \"-l\")\n",
            "\t_ = exec.Command(\"rm\", \"-r\", \"-f\", \"/home/user\").Run()\n",
            "\t_, _ = exec.Command(\"rm\", \"-r\", \"-f\", \"/home/user\").Output()\n",
            "\t_, _ = exec.Command(\"rm\", \"-r\", \"-f\", \"/home/user\").CombinedOutput()\n",
            "}\n",
        );

        let hits = DEFAULT_MATCHER
            .find_matches(source, ScriptLanguage::Go)
            .expect("go fixture should scan");

        for expected in [
            "heredoc.go.os_removeall",
            "heredoc.go.os_remove",
            "heredoc.go.exec_command",
            "heredoc.go.exec_command_run",
            "heredoc.go.exec_command_output",
            "heredoc.go.exec_command_combined_output",
        ] {
            assert!(
                hits.iter().any(|hit| hit.rule_id == expected),
                "{expected} matched nothing; got {:?}",
                hits.iter().map(|hit| &hit.rule_id).collect::<Vec<_>>()
            );
        }

        // The recursive delete must block, not merely be reported.
        let removeall = hits
            .iter()
            .find(|hit| hit.rule_id == "heredoc.go.os_removeall")
            .expect("os.RemoveAll should match");
        assert_eq!(removeall.severity, Severity::Critical);
        assert!(removeall.severity.blocks_by_default());
        assert_eq!(
            source.get(removeall.start..removeall.end),
            Some("os.RemoveAll(\"/home/user\")"),
            "the reported span must be the call, not its enclosing function"
        );

        // The chained form keeps its own span; if `call_expression` bound to the
        // inner call instead, `.Run()` would fall outside the match.
        let run = hits
            .iter()
            .find(|hit| hit.rule_id == "heredoc.go.exec_command_run")
            .expect("exec.Command().Run() should match");
        assert!(
            source
                .get(run.start..run.end)
                .is_some_and(|text| text.ends_with(".Run()")),
            "chained match span should cover .Run(): {:?}",
            source.get(run.start..run.end)
        );
    }

    /// One deletion call must produce exactly one deletion rule id (#467).
    ///
    /// Two patterns matching the same call is not merely redundant, it breaks
    /// allowlisting: `explain` reports one winner, and allowlisting that id
    /// leaves the command denied under the shadowed rule, which the user was
    /// never shown. That is what `fsPromises.rm` and `$FS.promises.rm` did
    /// alongside `$FS.rm` — `fs.rm` allowlisted correctly because only one
    /// pattern matched it, and `fsPromises.rm` did not.
    ///
    /// Asserting one id per call is what keeps a future receiver-specific
    /// pattern from silently reintroducing the trap.
    #[test]
    fn one_deletion_call_yields_one_deletion_rule_issue_467() {
        for language in [ScriptLanguage::JavaScript, ScriptLanguage::TypeScript] {
            let lang_id = if language == ScriptLanguage::JavaScript {
                "javascript"
            } else {
                "typescript"
            };
            for receiver in ["fs", "fs.promises", "fsPromises", "require('fs').promises"] {
                for (method, expected) in [("rm", "fs_rm"), ("rmdir", "fs_rmdir")] {
                    let source =
                        format!("{receiver}.{method}('/home/user', {{ recursive: true }});\n");
                    let hits = DEFAULT_MATCHER
                        .find_matches(&source, language)
                        .unwrap_or_else(|error| panic!("{source} should scan: {error:?}"));
                    let deletions: Vec<&str> = hits
                        .iter()
                        .filter(|hit| hit.rule_id.starts_with(&format!("heredoc.{lang_id}.")))
                        .map(|hit| hit.rule_id.as_str())
                        .collect();
                    assert_eq!(
                        deletions.len(),
                        1,
                        "{language:?} {source:?} produced {deletions:?}; a second \
                         matching pattern would shadow the reported rule and defeat \
                         an allowlist entry for it"
                    );
                    assert_eq!(
                        deletions[0],
                        format!("heredoc.{lang_id}.{expected}.catastrophic"),
                        "{language:?} {source:?}"
                    );
                }
            }
        }
    }

    /// Go's recursive delete follows #455's temp policy, and only that far.
    ///
    /// Each row was measured against its Python twin through the real hook
    /// before being written down, so this is the established cross-language
    /// policy rather than a Go-specific invention. See `refine_go_match` for the
    /// comparison table and why the two-statement and temp-root shapes keep
    /// blocking.
    #[test]
    fn go_recursive_delete_gets_the_shared_temp_carve_out_issue_465() {
        fn scan(statement: &str) -> Vec<PatternMatch> {
            let source =
                format!("package main\n\nimport \"os\"\n\nfunc main() {{\n\t{statement}\n}}\n");
            DEFAULT_MATCHER
                .find_matches(&source, ScriptLanguage::Go)
                .unwrap_or_else(|error| panic!("{statement} should scan: {error:?}"))
        }

        fn removeall(statement: &str) -> PatternMatch {
            scan(statement)
                .into_iter()
                .find(|hit| hit.rule_id.starts_with("heredoc.go.os_removeall"))
                .unwrap_or_else(|| panic!("{statement} should match os.RemoveAll"))
        }

        // Carved out: a literal target under a temp root, in either Go string
        // spelling. `rm -rf /tmp/build` has always been allowed.
        for statement in [
            r#"os.RemoveAll("/tmp/build")"#,
            "os.RemoveAll(`/tmp/build`)",
            r#"os.RemoveAll("/var/tmp/build")"#,
            r#"os.RemoveAll("/private/tmp/build")"#,
        ] {
            let hit = removeall(statement);
            assert_eq!(
                hit.rule_id, "heredoc.go.os_removeall.temp",
                "{statement} should carry the temp rule id"
            );
            assert_eq!(hit.severity, Severity::Medium, "{statement}");
            assert!(
                !hit.severity.blocks_by_default(),
                "{statement} must not block"
            );
        }

        // Still Critical. Each for a distinct reason, all of them matching what
        // Python already does for the same shape.
        for (statement, why) in [
            (r#"os.RemoveAll("/home/user")"#, "a real target"),
            (r#"os.RemoveAll("/")"#, "root"),
            (
                r#"os.RemoveAll("/tmp/../home/user")"#,
                "traversal escapes /tmp",
            ),
            (
                "os.RemoveAll(os.TempDir())",
                "the temp root itself, not a created directory",
            ),
            ("os.RemoveAll(dir)", "a dynamic target cannot be read"),
        ] {
            let hit = removeall(statement);
            assert_eq!(hit.rule_id, "heredoc.go.os_removeall", "{statement}: {why}");
            assert_eq!(hit.severity, Severity::Critical, "{statement}: {why}");
            assert!(hit.severity.blocks_by_default(), "{statement}: {why}");
        }

        // `os.Remove` deletes one file, so it is not in the recursive family and
        // gets no carve-out — exactly as Python's `os.remove('/tmp/x')` blocks.
        let single = scan(r#"os.Remove("/tmp/scratch.txt")"#)
            .into_iter()
            .find(|hit| hit.rule_id.starts_with("heredoc.go.os_remove"))
            .expect("os.Remove should match");
        assert_eq!(single.rule_id, "heredoc.go.os_remove");
        assert_eq!(single.severity, Severity::High);
    }

    /// Go's exec sinks must escalate a destructive payload, and exactly once.
    ///
    /// This is #458's policy applied to the one language that never got it.
    /// Go's four `exec.Command` patterns register at `Medium` under a comment
    /// saying they are "refined at match time", but `refine_go_match` only ever
    /// handled #455's temp carve-out, so nothing escalated them. The failure is
    /// the quiet one `refine_python_match` warns about: the pattern matches, a
    /// finding is reported, and the command runs.
    ///
    /// Nothing else caught it either. The exec-sink backstop is scoped out of
    /// Go on the stated ground that Go "uses its own primary path", and the
    /// raw-shell rescan needs contiguous destructive text a Go argv does not
    /// have. Measured through the real hook, every spelling below was `allow`
    /// while the Python twin denied under `heredoc.python:subprocess_run.*`.
    ///
    /// The single-blocking-id assertion is #467's invariant: `exec.Command($$$)`
    /// and `exec.Command($$$).Run()` describe the same command, so escalating
    /// both would report two blocking ids for one call and leave an allowlist
    /// entry for the reported one denied under the other.
    #[test]
    fn every_go_exec_sink_escalates_a_destructive_payload_issue_472() {
        let ast_matcher = AstMatcher::new();

        fn program(statement: &str) -> String {
            format!("package main\n\nimport \"os/exec\"\n\nfunc main() {{\n\t{statement}\n}}\n")
        }
        // Assembled rather than written out, so this file does not carry the
        // literal text of a guarded command — same reason as the Python twin.
        let rmrf = format!("{}{}{}", "rm", "\", \"-", "rf");

        // Every call shape, in both payload spellings: the argv-split form,
        // which only the AST path can read back as a command, and the single
        // literal form.
        for call in [
            String::new(),
            ".Run()".to_string(),
            ".Output()".to_string(),
            ".CombinedOutput()".to_string(),
        ] {
            let bind = if call.is_empty() || call == ".Run()" {
                "_ ="
            } else {
                "_, _ ="
            };
            for payload in [
                format!("\"{rmrf}\", \"/home/user\""),
                format!(
                    "\"sh\", \"-c\", \"{} /home/user\"",
                    rmrf.replace("\", \"", " ")
                ),
            ] {
                let code = program(&format!("{bind} exec.Command({payload}){call}"));
                let matches = ast_matcher.find_matches(&code, ScriptLanguage::Go).unwrap();
                let blocking: Vec<&str> = matches
                    .iter()
                    .filter(|hit| hit.severity.blocks_by_default())
                    .map(|hit| hit.rule_id.as_str())
                    .collect();
                assert!(
                    !blocking.is_empty(),
                    "exec.Command({payload}){call} must block; got {:?}",
                    matches
                        .iter()
                        .map(|hit| (&hit.rule_id, hit.severity))
                        .collect::<Vec<_>>()
                );
                assert_eq!(
                    blocking.len(),
                    1,
                    "exec.Command({payload}){call} produced {blocking:?}; a second \
                     blocking id for the same call shadows the reported rule and \
                     defeats an allowlist entry for it (#467)"
                );
            }
        }

        // The other half of the refinement's job: the same sinks with a benign
        // payload stay warn-only, so the assertions above measure escalation
        // rather than a blanket deny on `exec.Command`.
        for call in ["", ".Run()"] {
            let code = program(&format!("_ = exec.Command(\"ls\", \"-l\"){call}"));
            let matches = ast_matcher.find_matches(&code, ScriptLanguage::Go).unwrap();
            assert!(
                !matches.iter().any(|hit| hit.severity.blocks_by_default()),
                "exec.Command(\"ls\", \"-l\"){call} must stay warn-only; got {:?}",
                matches
                    .iter()
                    .map(|hit| (&hit.rule_id, hit.severity))
                    .collect::<Vec<_>>()
            );
            assert!(
                matches
                    .iter()
                    .any(|hit| hit.rule_id.starts_with("heredoc.go.exec_command")),
                "the benign call must still be REPORTED, or the negative above \
                 would pass on a pattern that stopped matching entirely"
            );
        }
    }

    /// Go and PHP need the backstop, not just their AST path.
    ///
    /// #472 and #473 proved each language's primary path BLOCKS a destructive
    /// payload. Scoping a language out of the exec-sink backstop asserts
    /// something stronger: that the primary path RUNS. For Go and PHP it is the
    /// AST layer, and truncated heredoc extraction removes that layer whole —
    /// which is Perl's exposure exactly, and Perl is re-scanned here for exactly
    /// that reason.
    ///
    /// Nothing else covers the difference. The raw-shell rescan needs contiguous
    /// destructive text, and an argv-split spawn has none: every literal of
    /// `exec.Command("rm", "-rf", "/home/user")` is separately harmless, which
    /// is why the bounded fallback — a text test — cannot see it either. Through
    /// the real hook with the extraction budget pinned to 1ms, that call was
    /// ALLOWED 10/10 while the Python, Ruby, JavaScript and Perl twins denied,
    /// and under natural load on a busy host it allowed 8/20 at the shipped
    /// budget. `pcntl_exec` needed no timing pressure at all: it is in no
    /// `heredoc.php.*` pattern, so its payload reached no layer whatsoever.
    ///
    /// This asserts the backstop directly, because that is the layer that has to
    /// answer when the AST one is gone.
    #[test]
    fn go_and_php_exec_sinks_are_caught_without_their_ast_layer() {
        // Assembled so this file does not carry the literal guarded text.
        let rmrf = format!("{}{}{}", "rm\", \"", "-", "rf");
        let home = "/home/user";

        for (language, source, what) in [
            (
                ScriptLanguage::Go,
                format!(
                    "package main\nimport (\n\t\"os/exec\"\n)\nfunc main() {{\n\t\
                     exec.Command(\"{rmrf}\", \"{home}\").Run()\n}}\n"
                ),
                "exec.Command argv",
            ),
            (
                // The aliasing case the backstop exists for: `import e
                // "os/exec"` makes the AST pattern's `exec.Command` shape miss.
                ScriptLanguage::Go,
                format!(
                    "package main\nimport (\n\te \"os/exec\"\n)\nfunc main() {{\n\t\
                     e.Command(\"{rmrf}\", \"{home}\").Run()\n}}\n"
                ),
                "aliased import",
            ),
            (
                ScriptLanguage::Php,
                format!("<?php\npcntl_exec(\"/bin/{rmrf}\", \"{home}\");\n"),
                "pcntl_exec, in no AST pattern",
            ),
        ] {
            let blocked = scan_executing_sink_matches(&source, language)
                .into_iter()
                .any(|hit| hit.severity.blocks_by_default());
            assert!(
                blocked,
                "{language:?} {what} must block from the backstop alone, with no \
                 AST layer to fall back on; got nothing"
            );
        }

        // The negative that makes the above measure a destructive PAYLOAD rather
        // than a blanket deny on the sink name. `Command(` is a common Go
        // spelling and `exec(` a common PHP one, so a match must still turn on
        // what the call's own arguments say.
        for (language, source, what) in [
            (
                ScriptLanguage::Go,
                "package main\nimport (\n\t\"os/exec\"\n)\nfunc main() {\n\t\
                 exec.Command(\"go\", \"build\", \"./...\").Run()\n}\n"
                    .to_string(),
                "go build",
            ),
            (
                ScriptLanguage::Go,
                "package main\nfunc main() {\n\tc := lib.Command(\"serve\", \"--port\")\n\t_ = c\n}\n"
                    .to_string(),
                "an unrelated Command()",
            ),
            (
                ScriptLanguage::Php,
                "<?php\npcntl_exec(\"/bin/echo\", \"hello\");\n".to_string(),
                "pcntl_exec of echo",
            ),
        ] {
            let blocking: Vec<String> = scan_executing_sink_matches(&source, language)
                .into_iter()
                .filter(|hit| hit.severity.blocks_by_default())
                .map(|hit| hit.rule_id)
                .collect();
            assert!(
                blocking.is_empty(),
                "{language:?} {what} must stay allowed; got {blocking:?}"
            );
        }
    }

    /// Go and PHP reach the PACKS for every other destructive verb.
    ///
    /// The exec-sink backstop knows `rm` and `git`. Every other destructive verb
    /// — `dd`, `mkfs`, `wipefs`, `shred` — lives only in the packs, and an
    /// argv-split spawn leaves no contiguous text for the raw rescan, so
    /// reconstructing its argv is the only way it reaches its rule. Go and PHP
    /// were absent from that reconstruction, so measured through the real hook
    /// with no timing pressure at all, `exec.Command("dd", "if=/dev/zero",
    /// "of=/dev/sda")` and the `wipefs` spelling were ALLOWED 3/3 while the
    /// identical argv through Python's `subprocess.run` and Node's `spawnSync`
    /// denied under `system.disk:dd-device`.
    #[test]
    fn go_and_php_argv_spawns_reconstruct_for_the_packs() {
        // Assembled so this file does not carry the literal guarded text.
        let dd = format!("{}{}", "d", "d");
        let sink = format!("{}{}", "if=/dev/zero\", \"of=", "/dev/sda");

        for (language, source, what) in [
            (
                ScriptLanguage::Go,
                format!(
                    "package main\nimport (\n\t\"os/exec\"\n)\nfunc main() {{\n\t\
                     exec.Command(\"{dd}\", \"{sink}\").Run()\n}}\n"
                ),
                "exec.Command",
            ),
            (
                ScriptLanguage::Php,
                format!("<?php\npcntl_exec(\"/bin/{dd}\", \"{sink}\");\n"),
                "pcntl_exec",
            ),
        ] {
            let commands = exec_sink_reconstructed_commands(&source, language);
            assert!(
                commands.iter().any(|c| c.command.contains(&dd)),
                "{language:?} {what} must reconstruct a command line for the packs; \
                 got {:?}",
                commands.iter().map(|c| &c.command).collect::<Vec<_>>()
            );
        }

        // argv[0] is the program, so a call whose real program is something else
        // must not be reconstructed as the verb sitting in its arguments.
        let source = format!(
            "package main\nimport (\n\t\"os/exec\"\n)\nfunc main() {{\n\t\
             exec.Command(\"/bin/echo\", \"{dd}\", \"{sink}\").Run()\n}}\n"
        );
        for command in exec_sink_reconstructed_commands(&source, ScriptLanguage::Go) {
            assert!(
                command.command.starts_with("/bin/echo"),
                "the reconstructed program must be argv[0]; got {:?}",
                command.command
            );
        }
    }

    /// PHP's exec sinks must escalate a destructive payload (#473).
    ///
    /// PHP had no refinement at all, so nothing in its own path could block.
    /// Every PHP exec denial came from the raw-shell rescan finding contiguous
    /// destructive text, under `core.filesystem:rm-rf-root-home` rather than the
    /// `heredoc.php.*` rule `docs/patterns.md` names — right verdict, wrong
    /// attribution, and an ID nobody could grant.
    ///
    /// The two shapes with no contiguous text were allowed outright, and they
    /// are the two views `detect_destructive_in_args` exists to provide: the
    /// argv array, and the concatenated literal.
    #[test]
    fn every_php_exec_sink_escalates_a_destructive_payload_issue_473() {
        let ast_matcher = AstMatcher::new();
        // Assembled rather than written out, so this file does not carry the
        // literal text of a guarded command.
        let rmrf = format!("{}{}{}", "rm", " -", "rf");

        fn program(statement: &str) -> String {
            format!("<?php\n{statement}\n?>\n")
        }
        fn blocking(matches: &[PatternMatch]) -> Vec<&str> {
            matches
                .iter()
                .filter(|hit| hit.severity.blocks_by_default())
                .map(|hit| hit.rule_id.as_str())
                .collect()
        }

        // The single-literal shape, through every refined sink. These already
        // denied via the pack rule; what is asserted here is that PHP's own
        // rule is now the one that blocks, so the ID in the denial is the ID
        // the docs tabulate.
        for sink in [
            "system",
            "exec",
            "shell_exec",
            "passthru",
            "proc_open",
            "popen",
        ] {
            let call = match sink {
                "popen" => format!("popen(\"{rmrf} /home/user\", \"r\");"),
                "proc_open" => format!("proc_open(\"{rmrf} /home/user\", [], $pipes);"),
                other => format!("{other}(\"{rmrf} /home/user\");"),
            };
            let code = program(&call);
            let matches = ast_matcher
                .find_matches(&code, ScriptLanguage::Php)
                .unwrap();
            let hits = blocking(&matches);
            assert_eq!(
                hits.len(),
                1,
                "{call} must block under exactly one PHP rule; got {:?}",
                matches
                    .iter()
                    .map(|hit| (&hit.rule_id, hit.severity))
                    .collect::<Vec<_>>()
            );
            assert!(
                hits[0].starts_with(&format!("heredoc.php.{sink}.")),
                "{call} blocked under {:?}, not a refined heredoc.php.{sink} id",
                hits[0]
            );
        }

        // The argv-array shape (PHP 7.4+), which only the AST path can reach:
        // the text carries no contiguous payload for a raw rescan to find.
        let code = program(r#"$p = proc_open(["rm","-rf","/home/user"], [], $pipes);"#);
        let matches = ast_matcher
            .find_matches(&code, ScriptLanguage::Php)
            .unwrap();
        assert!(
            !blocking(&matches).is_empty(),
            "proc_open with an argv array must block; got {:?}",
            matches
                .iter()
                .map(|hit| (&hit.rule_id, hit.severity))
                .collect::<Vec<_>>()
        );

        // The concatenated-literal shape, likewise invisible to a raw rescan.
        let code = program(&format!(
            "system(\"{}\" . \" -{}\" . \" /home/user\");",
            "rm", "rf"
        ));
        let matches = ast_matcher
            .find_matches(&code, ScriptLanguage::Php)
            .unwrap();
        assert!(
            !blocking(&matches).is_empty(),
            "a concatenated payload must block; got {:?}",
            matches
                .iter()
                .map(|hit| (&hit.rule_id, hit.severity))
                .collect::<Vec<_>>()
        );

        // The other half of the refinement's job: benign payloads through the
        // same sinks stay warn-only, so the assertions above measure escalation
        // rather than a blanket deny on `system`/`proc_open`.
        for call in [
            "system(\"ls -l\");",
            "$p = proc_open([\"ls\",\"-l\"], [], $pipes);",
            "system($cmd);",
        ] {
            let code = program(call);
            let matches = ast_matcher
                .find_matches(&code, ScriptLanguage::Php)
                .unwrap();
            assert!(
                blocking(&matches).is_empty(),
                "{call} must stay warn-only; got {:?}",
                matches
                    .iter()
                    .map(|hit| (&hit.rule_id, hit.severity))
                    .collect::<Vec<_>>()
            );
            assert!(
                !matches.is_empty(),
                "{call} must still be REPORTED, or the negative above would pass \
                 on a pattern that stopped matching entirely"
            );
        }
    }

    /// A concatenated token is one operand, in every language (#474).
    ///
    /// `detect_destructive_in_args` read each literal and never each operand,
    /// so a token split across a `+` was invisible to both of its views: no
    /// single literal is destructive, and the argv view saw `r`, `m`, `-rf`
    /// rather than `rm`, `-rf`. Measured before the fix, every language allowed
    /// it -- this was never a Go or PHP artifact.
    ///
    /// The negatives carry equal weight here. Folding by adjacency instead of
    /// by operator would make the argv view manufacture commands the source
    /// never builds, so a comma-separated list holding `rm` as an inert element
    /// must keep allowing.
    #[test]
    fn a_concatenated_token_is_one_operand_issue_474() {
        // Assembled so this file does not carry the literal text of a guarded
        // command, and so the halves are genuinely separate literals.
        let split = "\"r\" + \"m\"";
        let php_split = "\"r\" . \"m\"";

        // Each language is exercised at the layer that actually consults
        // `detect_destructive_in_args`, because they do not share one. Python,
        // Go and PHP reach it from their `find_matches` refiners; JavaScript and
        // Ruby reach it from the exec-sink scanner the evaluator runs, and their
        // refiners never see an argv at all (Ruby's reads only the first string
        // literal and drops the match when it is inert). Asserting all five
        // through `find_matches` would have measured that difference instead of
        // the fold.
        enum Layer {
            Refiner,
            SinkScanner,
        }
        for (language, layer, code) in [
            (
                ScriptLanguage::Python,
                Layer::Refiner,
                format!("import subprocess\nsubprocess.run([{split}, \"-rf\", \"/home/user\"])"),
            ),
            (
                ScriptLanguage::Go,
                Layer::Refiner,
                format!(
                    "package main\n\nimport \"os/exec\"\n\nfunc main() {{\n\t_ = exec.Command({split}, \"-rf\", \"/home/user\").Run()\n}}\n"
                ),
            ),
            (
                ScriptLanguage::Php,
                Layer::Refiner,
                format!(
                    "<?php\n$p = proc_open([{php_split},\"-rf\",\"/home/user\"], [], $pipes);\n?>\n"
                ),
            ),
            (
                ScriptLanguage::JavaScript,
                Layer::SinkScanner,
                format!(
                    "const cp = require('child_process');\ncp.spawnSync({split}, [\"-rf\", \"/home/user\"]);"
                ),
            ),
            (
                ScriptLanguage::Ruby,
                Layer::SinkScanner,
                format!("system({split}, \"-rf\", \"/home/user\")"),
            ),
        ] {
            let matches = match layer {
                Layer::Refiner => DEFAULT_MATCHER
                    .find_matches(&code, language)
                    .unwrap_or_else(|error| panic!("{language:?} fixture should scan: {error:?}")),
                Layer::SinkScanner => scan_executing_sink_matches(&code, language),
            };
            assert!(
                matches.iter().any(|hit| hit.severity.blocks_by_default()),
                "{language:?}: a token split across a concatenation operator must \
                 still block; got {:?}",
                matches
                    .iter()
                    .map(|hit| (&hit.rule_id, hit.severity))
                    .collect::<Vec<_>>()
            );
        }

        // Countermetric: the fold is driven by the operator, never by
        // adjacency. A comma-separated list holding `rm` as an inert element
        // stays three operands and must keep allowing, or the argv view has
        // begun inventing commands.
        // Measured at the same layer each language's positive row used, so a
        // pass here cannot come from the match being dropped somewhere else.
        for (language, layer, code) in [
            (
                ScriptLanguage::Python,
                Layer::Refiner,
                "import subprocess\nsubprocess.run([\"echo\", \"rm\", \"-rf\"])".to_string(),
            ),
            (
                ScriptLanguage::Ruby,
                Layer::SinkScanner,
                "system(\"echo\", \"rm\", \"-rf\")".to_string(),
            ),
            (
                ScriptLanguage::JavaScript,
                Layer::SinkScanner,
                "const cp = require('child_process');\ncp.spawnSync(\"echo\", [\"rm\", \"-rf\"]);"
                    .to_string(),
            ),
        ] {
            let matches = match layer {
                Layer::Refiner => DEFAULT_MATCHER
                    .find_matches(&code, language)
                    .unwrap_or_else(|error| panic!("{language:?} fixture should scan: {error:?}")),
                Layer::SinkScanner => scan_executing_sink_matches(&code, language),
            };
            assert!(
                !matches.iter().any(|hit| hit.severity.blocks_by_default()),
                "{language:?}: `echo rm -rf` prints two words and deletes nothing; \
                 folding by adjacency would have turned it into a delete. Got {:?}",
                matches
                    .iter()
                    .map(|hit| (&hit.rule_id, hit.severity))
                    .collect::<Vec<_>>()
            );
        }

        // A dynamic operand keeps the gap non-foldable, so it stays fail-open
        // rather than being joined into something the source never builds.
        let matches = DEFAULT_MATCHER
            .find_matches(
                "import subprocess\nsubprocess.run([\"rm\", \"-rf\", \"/tmp/\" + name])",
                ScriptLanguage::Python,
            )
            .expect("dynamic fixture should scan");
        assert!(
            matches.iter().any(|hit| hit.severity.blocks_by_default()),
            "the `rm`/`-rf` operands are still literal, so this blocks on them; \
             the point is only that `/tmp/` was not silently joined to an \
             identifier. Got {:?}",
            matches
                .iter()
                .map(|hit| (&hit.rule_id, hit.severity))
                .collect::<Vec<_>>()
        );
    }

    /// The gap rule that drives the fold, in isolation (#474).
    #[test]
    fn only_a_single_operator_gap_folds_issue_474() {
        for gap in [" + ", "+", " . ", ".", "\n  + ", " +\n"] {
            assert!(is_concatenation_gap(gap), "{gap:?} should fold");
        }
        for gap in [
            ", ",        // an argv separator, not a concatenation
            " + x + ",   // a dynamic operand between the halves
            ".freeze, ", // a method call, not PHP concatenation
            " + + ",     // two operators is not concatenation in any of these
            "",          // literals cannot abut without an operator
            " ",         // whitespace alone is adjacency, not concatenation
            ") ,(",
        ] {
            assert!(!is_concatenation_gap(gap), "{gap:?} must not fold");
        }
    }

    #[test]
    fn truncate_preview_handles_utf8_safely() {
        // Test with ASCII
        assert_eq!(truncate_preview("hello", 10), "hello");
        assert_eq!(truncate_preview("hello world!", 8), "hello...");

        // Test with multi-byte UTF-8 (emojis are 4 bytes each)
        let emojis = "🎉🎊🎁🎄🎅";
        assert_eq!(truncate_preview(emojis, 10), emojis); // 5 chars, fits
        assert_eq!(truncate_preview(emojis, 4), "🎉..."); // truncates to 1 emoji + ...

        // Test with CJK characters (3 bytes each)
        let cjk = "你好世界";
        assert_eq!(truncate_preview(cjk, 10), cjk); // 4 chars, fits
        assert_eq!(truncate_preview(cjk, 4), cjk); // exactly 4 chars, fits
        assert_eq!(truncate_preview(cjk, 3), "..."); // 4 > 3, truncates (no room for even 1 char + "...")

        // Edge cases
        assert_eq!(truncate_preview("", 10), "");
        assert_eq!(truncate_preview("ab", 3), "ab");
        assert_eq!(truncate_preview("abc", 3), "abc");
        assert_eq!(truncate_preview("abcd", 3), "...");
    }

    mod ruby_positive_fixtures {
        use super::*;

        #[test]
        fn fileutils_rm_rf_catastrophic_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "require 'fileutils'\nFileUtils.rm_rf('/')";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.ruby.fileutils_rm_rf.catastrophic"
                        && m.severity.blocks_by_default()),
                "catastrophic FileUtils.rm_rf should block"
            );
        }

        /// #455, the Ruby half. See the JavaScript twin for the reasoning.
        ///
        /// `./tmp` is the case worth keeping: it is a *relative* directory that
        /// merely happens to be spelled like the system scratch directory, so
        /// it blocks. `rm -rf ./tmp` blocks for the same reason — the safe
        /// pattern is anchored on `/tmp/`, not on the four letters.
        #[test]
        fn recursive_fileutils_delete_outside_tmp_blocks_like_rm_rf_issue_455() {
            let ast_matcher = AstMatcher::new();

            for (method, target) in [
                ("rm_rf", "./build"),
                ("rm_rf", "./tmp"),
                ("rm_r", "./node_modules"),
                ("remove_entry", "/data/cache"),
            ] {
                let code = format!("require 'fileutils'\nFileUtils.{method}('{target}')");
                let matches = ast_matcher
                    .find_matches(&code, ScriptLanguage::Ruby)
                    .unwrap();
                assert!(
                    matches.iter().any(|m| m.rule_id
                        == format!("heredoc.ruby.fileutils_{method}.non_temp")
                        && m.severity.blocks_by_default()),
                    "recursive delete outside /tmp must block: {code}"
                );
            }

            // The scratch directory itself, and the non-recursive family that
            // cannot destroy a tree, both stay warn-only.
            for code in [
                "require 'fileutils'\nFileUtils.rm_rf('/tmp/build')",
                "require 'fileutils'\nFileUtils.rm_f('./build/app.o')",
                "require 'fileutils'\nFileUtils.rmdir('./build')",
            ] {
                let matches = ast_matcher
                    .find_matches(code, ScriptLanguage::Ruby)
                    .unwrap();
                assert!(
                    !matches.iter().any(|m| m.severity.blocks_by_default()),
                    "must not block: {code}"
                );
            }
        }

        /// #454: every recursive `FileUtils` deletion blocks on a catastrophic
        /// target, not just `rm_rf`.
        ///
        /// `rm_r` is the case that was allowed while `FileUtils.rm('/')` — which
        /// raises `Errno::EISDIR` rather than deleting anything — was blocked.
        #[test]
        fn every_recursive_fileutils_delete_blocks_on_catastrophic_target_issue_454() {
            let ast_matcher = AstMatcher::new();

            for method in [
                "rm_rf",
                "rm_r",
                "remove_entry",
                "remove_entry_secure",
                "remove_dir",
            ] {
                let code = format!("require 'fileutils'\nFileUtils.{method}('/')");
                let matches = ast_matcher
                    .find_matches(&code, ScriptLanguage::Ruby)
                    .unwrap();
                let expected = format!("heredoc.ruby.fileutils_{method}.catastrophic");
                assert!(
                    matches
                        .iter()
                        .any(|m| m.rule_id == expected && m.severity.blocks_by_default()),
                    "FileUtils.{method}('/') must block as {expected}; got {:?}",
                    matches.iter().map(|m| &m.rule_id).collect::<Vec<_>>()
                );
            }
        }

        /// The non-recursive deletions block on a catastrophic target too, and no
        /// spelling of one is weaker than its siblings (#454).
        ///
        /// `rm` blocking while `rm_f` did not was the `rm_r` inversion in
        /// miniature. `rmdir` is here because `Dir.rmdir` — what it delegates to
        /// — already blocks; covering one spelling and not the other was the
        /// inconsistency, not a deliberate carve-out.
        #[test]
        fn fileutils_non_recursive_deletes_are_uniformly_covered_issue_454() {
            let ast_matcher = AstMatcher::new();

            for method in ["rm", "rm_f", "remove", "remove_file", "rmdir"] {
                let code = format!("require 'fileutils'\nFileUtils.{method}('/etc')");
                let matches = ast_matcher
                    .find_matches(&code, ScriptLanguage::Ruby)
                    .unwrap();
                let expected = format!("heredoc.ruby.fileutils_{method}.catastrophic");
                assert!(
                    matches
                        .iter()
                        .any(|m| m.rule_id == expected && m.severity.blocks_by_default()),
                    "FileUtils.{method}('/etc') must block as {expected}; got {:?}",
                    matches.iter().map(|m| &m.rule_id).collect::<Vec<_>>()
                );
            }
        }

        /// Negative control for the tests above: widening the method list must
        /// not have made it match everything.
        ///
        /// Two independent directions. Non-deleting `FileUtils` calls must stay
        /// unblocked even on a catastrophic path. And a non-catastrophic target
        /// must still warn rather than block, which is what keeps the additions
        /// from turning ordinary build-directory cleanup into a denial.
        #[test]
        fn fileutils_additions_do_not_block_indiscriminately_issue_454() {
            let ast_matcher = AstMatcher::new();

            // Non-deleting FileUtils calls are what an over-broad alternation
            // would swallow, so they are the real negative control.
            for method in [
                "mkdir_p", "mkdir", "cp_r", "cp", "mv", "chmod_R", "touch", "ln_s",
            ] {
                let code = format!("require 'fileutils'\nFileUtils.{method}('/')");
                let matches = ast_matcher
                    .find_matches(&code, ScriptLanguage::Ruby)
                    .unwrap();
                assert!(
                    !matches
                        .iter()
                        .any(|m| m.rule_id.starts_with("heredoc.ruby.fileutils_")
                            && m.severity.blocks_by_default()),
                    "FileUtils.{method} does not delete and must not block as a \
                     fileutils deletion; got {:?}",
                    matches.iter().map(|m| &m.rule_id).collect::<Vec<_>>()
                );
                assert!(
                    scan_filesystem_sink_fallback(&code, ScriptLanguage::Ruby).is_none(),
                    "FileUtils.{method} must not match the literal fallback either"
                );
            }

            // #455 split this row. `rm_r` and `remove_entry` recurse, so a
            // non-temp target now blocks them the way `rm -rf ./build` is
            // blocked; `rm_f` and `remove_file` delete one file and `rmdir`
            // needs an already-empty directory, so none of the three can
            // destroy a tree and all three stay warn-only. That is the line,
            // and it is drawn on what the call can do rather than on its name.
            for method in ["rm_f", "remove_file", "rmdir"] {
                let code = format!("require 'fileutils'\nFileUtils.{method}('./build')");
                let matches = ast_matcher
                    .find_matches(&code, ScriptLanguage::Ruby)
                    .unwrap();
                assert!(
                    !matches.iter().any(|m| m.severity.blocks_by_default()),
                    "FileUtils.{method}('./build') cannot delete a tree and must warn only; got {:?}",
                    matches.iter().map(|m| &m.rule_id).collect::<Vec<_>>()
                );
            }
        }

        /// The literal pre-AST scan is the backstop when the AST budget is gone,
        /// so it has to know the same method names the AST rules do (#454).
        /// It also has to report the right one: `fn` is interpolated into the
        /// rule id, and allowlists key on rule ids, so a mis-captured name is a
        /// silent breakage rather than a visible failure.
        #[test]
        fn literal_fallback_covers_and_correctly_names_each_fileutils_method_issue_454() {
            for method in [
                "rm_rf",
                "rmdir",
                "rm_r",
                "rm_f",
                "rm",
                "remove_entry_secure",
                "remove_entry",
                "remove_file",
                "remove_dir",
                "remove",
            ] {
                let code = format!("FileUtils.{method}('/')");
                let hit = scan_filesystem_sink_fallback(&code, ScriptLanguage::Ruby)
                    .unwrap_or_else(|| panic!("literal fallback must match FileUtils.{method}"));
                assert_eq!(
                    hit.rule_id,
                    format!("heredoc.ruby.fileutils_{method}.catastrophic"),
                    "literal fallback captured the wrong method name for FileUtils.{method}"
                );
                assert!(
                    hit.severity.blocks_by_default(),
                    "catastrophic FileUtils.{method} must block via the literal fallback"
                );
            }

            // The list above is ordered longest-first within each family, which
            // the rule-id assertions enforce: were `rm` to precede `rm_rf`, the
            // captured name — and so the rule id an allowlist keys on — would
            // silently change rather than fail to match.
            assert!(
                scan_filesystem_sink_fallback("FileUtils.mkdir_p('/')", ScriptLanguage::Ruby)
                    .is_none(),
                "the literal fallback must not match a non-deleting FileUtils call"
            );
        }

        #[test]
        fn system_rm_rf_catastrophic_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "system('rm -rf /')";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".rm_rf_catastrophic")
                        && m.severity.blocks_by_default()),
                "system('rm -rf /') should block"
            );
        }

        #[test]
        fn backticks_rm_rf_catastrophic_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "`rm -rf /`";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".rm_rf_catastrophic")
                        && m.severity.blocks_by_default()),
                "backticks `rm -rf /` should block"
            );
        }

        #[test]
        fn exec_git_reset_hard_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "exec('git reset --hard HEAD~1')";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".git_reset_hard")
                        && m.severity.blocks_by_default()),
                "exec('git reset --hard ...') should block"
            );
        }

        #[test]
        fn open3_capture3_rm_rf_catastrophic_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "require 'open3'\nOpen3.capture3('rm -rf /')";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".rm_rf_catastrophic")
                        && m.severity.blocks_by_default()),
                "Open3.capture3('rm -rf /') should block"
            );
        }

        #[test]
        fn open3_popen3_git_reset_hard_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "Open3.popen3('git reset --hard') { |i,o,e,t| }";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".git_reset_hard")
                        && m.severity.blocks_by_default()),
                "Open3.popen3('git reset --hard') should block"
            );
        }
    }

    mod ruby_negative_fixtures {
        use super::*;

        #[test]
        fn puts_dangerous_string_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "puts 'rm -rf /'";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn system_safe_payload_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "system('git status')";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn open3_capture3_safe_payload_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "Open3.capture3('git status')";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(
                matches.is_empty(),
                "Open3.capture3 with safe payload should not match"
            );
        }

        #[test]
        fn backticks_safe_payload_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "`echo hello`";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn require_only_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "require 'fileutils'";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn file_delete_under_tmp_warns_only() {
            let ast_matcher = AstMatcher::new();
            let code = "File.delete('/tmp/test.txt')";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Ruby)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.ruby.file_delete"
                        && !m.severity.blocks_by_default()),
                "File.delete under /tmp should warn only"
            );
        }
    }

    mod typescript_positive_fixtures {
        use super::*;

        #[test]
        fn fs_rmsync_catastrophic_blocks_with_type_assertion() {
            let ast_matcher = AstMatcher::new();
            let code =
                "import * as fs from 'fs';\nfs.rmSync('/etc' as string, { recursive: true });";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.typescript.fs_rmsync.catastrophic"
                        && m.severity.blocks_by_default()),
                "catastrophic fs.rmSync should block"
            );
        }

        /// Every `fs` deleter takes a metavariable receiver, not just `rmSync`.
        ///
        /// #453 gave `rmSync` a `$FS` receiver so `require('fs').rmSync('/')`
        /// would match the way the bound `fs.rmSync('/')` does. `rmdirSync` and
        /// `unlinkSync` kept a literal `fs.` receiver, so the chained spelling
        /// — the shorter one, and the one a `node -e` one-liner actually writes
        /// — was allowed on a catastrophic target. Found while measuring #455.
        #[test]
        fn a_chained_require_receiver_reaches_every_fs_deleter() {
            let ast_matcher = AstMatcher::new();
            for (code, expected) in [
                (
                    "require('fs').rmdirSync('/')",
                    "heredoc.typescript.fs_rmdirsync.catastrophic",
                ),
                (
                    "require('fs').unlinkSync('/etc/passwd')",
                    "heredoc.typescript.fs_unlinksync.catastrophic",
                ),
                (
                    "require('fs').rmSync('/')",
                    "heredoc.typescript.fs_rmsync.catastrophic",
                ),
            ] {
                let matches = ast_matcher
                    .find_matches(code, ScriptLanguage::TypeScript)
                    .unwrap();
                assert!(
                    matches
                        .iter()
                        .any(|m| m.rule_id == expected && m.severity.blocks_by_default()),
                    "chained receiver must reach {expected}: {code}; got {:?}",
                    matches.iter().map(|m| &m.rule_id).collect::<Vec<_>>()
                );
            }
        }

        /// #455, the TypeScript half. See the JavaScript twin for the reasoning.
        #[test]
        fn recursive_rmsync_outside_tmp_blocks_like_rm_rf_issue_455() {
            let ast_matcher = AstMatcher::new();
            let code = "import * as fs from 'fs';\nfs.rmSync('./dist', { recursive: true });";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id == "heredoc.typescript.fs_rmsync.non_temp"
                        && m.severity.blocks_by_default()),
                "recursive delete outside /tmp must block"
            );

            let safe = "import * as fs from 'fs';\nfs.rmSync('/tmp/dist', { recursive: true });";
            let matches = ast_matcher
                .find_matches(safe, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(
                !matches.iter().any(|m| m.severity.blocks_by_default()),
                "a scratch target must not block"
            );
        }

        #[test]
        fn execsync_git_reset_hard_blocks_inside_decorated_class() {
            let ast_matcher = AstMatcher::new();
            let code = "import * as child_process from 'child_process';\n@sealed\nclass Danger {\n  run(): void {\n    require('child_process').execSync('git reset --hard');\n  }\n}\n";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".git_reset_hard")
                        && m.severity.blocks_by_default()),
                "execSync('git reset --hard') should block"
            );
        }

        #[test]
        fn spawnsync_rm_rf_catastrophic_blocks_in_generic_function() {
            let ast_matcher = AstMatcher::new();
            let code = "import * as child_process from 'child_process';\nfunction go<T extends string>(x: T): void {\n  child_process.spawnSync('rm', ['-rf', '/']);\n}\n";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.ends_with(".rm_rf_catastrophic")
                        && m.severity.blocks_by_default()),
                "spawnSync('rm', ['-rf','/']) should block"
            );
        }

        #[test]
        fn deno_remove_sync_catastrophic_blocks() {
            let ast_matcher = AstMatcher::new();
            let matches = ast_matcher
                .find_matches(
                    "Deno.removeSync('/etc', { recursive: true });",
                    ScriptLanguage::TypeScript,
                )
                .unwrap();
            assert!(
                matches.iter().any(
                    |m| m.rule_id == "heredoc.typescript.deno_remove.catastrophic"
                        && m.severity.blocks_by_default()
                ),
                "catastrophic Deno.removeSync should block: {matches:?}"
            );
        }

        #[test]
        fn deno_remove_catastrophic_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "type Path = string;\nconst p: Path = '/etc';\nDeno.remove('/etc', { recursive: true });";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(
                matches.iter().any(
                    |m| m.rule_id == "heredoc.typescript.deno_remove.catastrophic"
                        && m.severity.blocks_by_default()
                ),
                "catastrophic Deno.remove should block"
            );
        }
    }

    mod typescript_negative_fixtures {
        use super::*;

        #[test]
        fn execsync_safe_payload_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "require('child_process').execSync('git status');";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn fs_rmsync_without_recursive_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "import * as fs from 'fs';\nfs.rmSync('./file.txt' as string);";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn printed_dangerous_string_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "console.log('rm -rf /');";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn require_child_process_alone_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "require('child_process');";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(matches.is_empty());
        }

        #[test]
        fn spawnsync_echo_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = "import * as child_process from 'child_process';\nchild_process.spawnSync('echo', ['rm -rf /']);";

            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::TypeScript)
                .unwrap();
            assert!(matches.is_empty());
        }
    }

    #[test]
    fn bash_positive_match() {
        let ast_matcher = AstMatcher::new();
        let code = "rm -rf /tmp/dangerous";

        let matches = ast_matcher.find_matches(code, ScriptLanguage::Bash);
        match matches {
            Ok(m) => {
                assert!(!m.is_empty(), "should match rm -rf");
                assert!(m[0].rule_id.contains("bash"));
                assert!(m[0].severity.blocks_by_default());
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn bash_negative_match() {
        let ast_matcher = AstMatcher::new();
        let code = "echo 'hello world'";

        let matches = ast_matcher.find_matches(code, ScriptLanguage::Bash);
        match matches {
            Ok(m) => assert!(m.is_empty(), "should not match safe code"),
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    // =========================================================================
    // Python Fixture Tests (git_safety_guard-beq)
    // =========================================================================

    /// Positive fixtures: patterns that MUST match (Critical/High severity = blocks)
    mod python_positive_fixtures {
        use super::*;

        #[test]
        fn shutil_rmtree_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "import shutil\nshutil.rmtree('/dangerous/path')";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(!matches.is_empty(), "shutil.rmtree must match");
            assert_eq!(matches[0].rule_id, "heredoc.python.shutil_rmtree");
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn os_remove_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "import os\nos.remove('/etc/passwd')";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(!matches.is_empty(), "os.remove must match");
            assert_eq!(matches[0].rule_id, "heredoc.python.os_remove");
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn os_rmdir_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "import os\nos.rmdir('/important/dir')";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(!matches.is_empty(), "os.rmdir must match");
            assert_eq!(matches[0].rule_id, "heredoc.python.os_rmdir");
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn os_unlink_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "import os\nos.unlink('/critical/file')";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(!matches.is_empty(), "os.unlink must match");
            assert_eq!(matches[0].rule_id, "heredoc.python.os_unlink");
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn pathlib_unlink_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "from pathlib import Path\nPath('/secret').unlink()";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(!matches.is_empty(), "pathlib.Path().unlink() must match");
            assert_eq!(matches[0].rule_id, "heredoc.python.pathlib_unlink");
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn pathlib_rmdir_blocks() {
            let ast_matcher = AstMatcher::new();
            let code = "from pathlib import Path\nPath('/danger/dir').rmdir()";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(!matches.is_empty(), "pathlib.Path().rmdir() must match");
            assert_eq!(matches[0].rule_id, "heredoc.python.pathlib_rmdir");
            assert!(matches[0].severity.blocks_by_default());
        }

        #[test]
        fn subprocess_run_warns() {
            // subprocess.run is Medium severity - warns but doesn't block by default
            // per bead: "Do not block on shell=True alone"
            let ast_matcher = AstMatcher::new();
            let code = "import subprocess\nsubprocess.run(['ls', '-la'])";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(!matches.is_empty(), "subprocess.run must match");
            assert_eq!(matches[0].rule_id, "heredoc.python.subprocess_run");
            assert!(
                !matches[0].severity.blocks_by_default(),
                "Medium should not block"
            );
        }

        #[test]
        fn subprocess_run_list_arg_destructive_blocks() {
            // Regression (#136): a destructive payload nested inside a LIST arg
            // must escalate to blocking even though the first element ("sh") is
            // inert. `subprocess.run(["sh","-c","rm -rf /etc"])` really executes
            // `sh -c "rm -rf /etc"`, so it must BLOCK, not warn.
            let ast_matcher = AstMatcher::new();
            let code = "import subprocess\nsubprocess.run([\"sh\",\"-c\",\"rm -rf /etc\"])";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(!matches.is_empty(), "subprocess.run(list) must match");
            assert!(
                matches[0].severity.blocks_by_default(),
                "destructive list-arg payload must escalate to blocking, got {:?} ({})",
                matches[0].severity,
                matches[0].rule_id
            );
            assert!(
                matches[0]
                    .rule_id
                    .starts_with("heredoc.python.subprocess_run"),
                "unexpected rule id: {}",
                matches[0].rule_id
            );
        }

        /// #459: the argv reconstruction must recognise a path-spelled binary.
        ///
        /// `detect_shell_payload` compared the command word against the bare
        /// literal `"rm"`, so joining `['/bin/rm','-rf','/home/user']` back into
        /// `/bin/rm -rf /home/user` produced a command word that never matched —
        /// the bare `['rm',…]` spelling blocked while every path spelling was
        /// allowed, even though the shell path strips exactly these prefixes.
        #[test]
        fn subprocess_list_arg_blocks_for_every_binary_spelling_issue_459() {
            let ast_matcher = AstMatcher::new();

            for func in ["run", "call", "Popen"] {
                for binary in [
                    "rm",
                    "/bin/rm",
                    "/usr/bin/rm",
                    "./rm",
                    "../bin/rm",
                    "rm.exe",
                ] {
                    let code = format!(
                        "import subprocess\nsubprocess.{func}(['{binary}','-rf','/home/user'])"
                    );
                    let matches = ast_matcher
                        .find_matches(&code, ScriptLanguage::Python)
                        .unwrap();
                    assert!(
                        matches.iter().any(|m| m.severity.blocks_by_default()),
                        "subprocess.{func}(['{binary}','-rf','/home/user']) must block; got {:?}",
                        matches
                            .iter()
                            .map(|m| (&m.rule_id, m.severity))
                            .collect::<Vec<_>>()
                    );
                }
            }
        }

        /// #458: every Python exec sink escalates a destructive payload.
        ///
        /// Three lists have to agree for one of these to be covered — the
        /// ast-grep pattern list, `PY_EXEC_SINK_LITERAL`, and
        /// `refine_python_match`'s exec-sink id set — and each disagrees in a
        /// different, quiet way. A missing pattern loses the argv-list shape
        /// entirely (that was `check_call`/`check_output`). A missing id in the
        /// refinement set is worse to read: the pattern matches, a finding is
        /// reported at Medium, and the command runs anyway.
        ///
        /// Asserting the end state rather than the list contents is what makes
        /// this hold all three at once. `blocks_by_default()` is false for
        /// Medium, so a sink that regressed on either axis fails here.
        #[test]
        fn every_python_exec_sink_escalates_a_destructive_payload_issue_458() {
            let ast_matcher = AstMatcher::new();
            // Assembled rather than written out, so this file does not carry
            // the literal text of a guarded command — the same reason the
            // `rmrf()` helper exists in the fixtures module below.
            let rmrf = format!("{}{}{}", "rm", " -", "rf");

            // The argv-split shape, which only an AST pattern can reach: the
            // text carries no literal `rm -rf` for a raw rescan to find.
            for func in ["run", "call", "Popen", "check_call", "check_output"] {
                let code =
                    format!("import subprocess\nsubprocess.{func}(['rm','-rf','/home/user'])");
                let matches = ast_matcher
                    .find_matches(&code, ScriptLanguage::Python)
                    .unwrap();
                assert!(
                    matches.iter().any(|m| m.severity.blocks_by_default()),
                    "subprocess.{func}(['rm','-rf','/home/user']) must block; got {:?}",
                    matches
                        .iter()
                        .map(|m| (&m.rule_id, m.severity))
                        .collect::<Vec<_>>()
                );
            }

            // The nested-list shape #136 closed, kept here so the two cannot
            // drift apart for the two sinks added by #458.
            for func in ["run", "call", "Popen", "check_call", "check_output"] {
                let code = format!(
                    "import subprocess\nsubprocess.{func}(['sh','-c','{} /home/user'])",
                    rmrf
                );
                let matches = ast_matcher
                    .find_matches(&code, ScriptLanguage::Python)
                    .unwrap();
                assert!(
                    matches.iter().any(|m| m.severity.blocks_by_default()),
                    "subprocess.{func}(['sh','-c',...]) must block; got {:?}",
                    matches
                        .iter()
                        .map(|m| (&m.rule_id, m.severity))
                        .collect::<Vec<_>>()
                );
            }

            // The os.* sinks take a string rather than an argv list, so they
            // are exercised in the shape they actually have.
            for sink in ["os.system", "os.popen"] {
                let code = format!("import os\n{sink}(\"{} /home/user\")", rmrf);
                let matches = ast_matcher
                    .find_matches(&code, ScriptLanguage::Python)
                    .unwrap();
                assert!(
                    matches.iter().any(|m| m.severity.blocks_by_default()),
                    "{sink} with a destructive payload must block; got {:?}",
                    matches
                        .iter()
                        .map(|m| (&m.rule_id, m.severity))
                        .collect::<Vec<_>>()
                );
            }

            // The other half of the refinement's job: a benign payload through
            // the same sinks stays warn-only, so the assertions above are
            // measuring escalation rather than a blanket deny on the sink.
            for func in ["run", "call", "check_call", "check_output"] {
                let code = format!("import subprocess\nsubprocess.{func}(['ls','-la'])");
                let matches = ast_matcher
                    .find_matches(&code, ScriptLanguage::Python)
                    .unwrap();
                assert!(
                    !matches.iter().any(|m| m.severity.blocks_by_default()),
                    "subprocess.{func}(['ls','-la']) must not block; got {:?}",
                    matches
                        .iter()
                        .map(|m| (&m.rule_id, m.severity))
                        .collect::<Vec<_>>()
                );
            }
        }

        /// Negative control for the test above: stripping the path must not make
        /// the payload scan match an unrelated command whose basename merely ends
        /// in the same letters, and a non-destructive argv list must stay inert.
        #[test]
        fn subprocess_list_arg_basename_stripping_is_not_overbroad_issue_459() {
            let ast_matcher = AstMatcher::new();

            for code in [
                // Not `rm`: basename is `rm-helper` / `norm`, which must not match.
                "import subprocess\nsubprocess.run(['/opt/bin/rm-helper','-rf','/home/user'])",
                "import subprocess\nsubprocess.run(['/opt/bin/norm','-rf','/home/user'])",
                // Real `rm` basename but an ordinary, non-recursive invocation.
                "import subprocess\nsubprocess.run(['/bin/rm','./build/stamp'])",
                // Ordinary tooling with a path spelling.
                "import subprocess\nsubprocess.run(['/usr/bin/git','status'])",
                "import subprocess\nsubprocess.run(['/usr/bin/make','build'])",
            ] {
                let matches = ast_matcher
                    .find_matches(code, ScriptLanguage::Python)
                    .unwrap();
                assert!(
                    !matches.iter().any(|m| m.severity.blocks_by_default()),
                    "must not block: {code:?}; got {:?}",
                    matches
                        .iter()
                        .map(|m| (&m.rule_id, m.severity))
                        .collect::<Vec<_>>()
                );
            }
        }

        #[test]
        fn subprocess_popen_list_arg_destructive_blocks() {
            // Regression (#136): same hole via subprocess.Popen([...]).
            let ast_matcher = AstMatcher::new();
            let code = "import subprocess\nsubprocess.Popen([\"sh\",\"-c\",\"rm -rf /etc\"])";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(!matches.is_empty(), "subprocess.Popen(list) must match");
            assert!(
                matches[0].severity.blocks_by_default(),
                "destructive list-arg payload via Popen must block, got {:?} ({})",
                matches[0].severity,
                matches[0].rule_id
            );
        }

        #[test]
        fn subprocess_run_list_arg_inert_warns() {
            // Guard against over-block: a benign list arg must stay warn-only.
            let ast_matcher = AstMatcher::new();
            let code = "import subprocess\nsubprocess.run([\"sh\",\"-c\",\"rm -rf ./build\"])";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            // rm -rf in an exec sink still escalates (the sink unambiguously runs
            // it), but a non-rm benign command must remain warn-only.
            let benign = "import subprocess\nsubprocess.run([\"ls\",\"-la\"])";
            let benign_matches = ast_matcher
                .find_matches(benign, ScriptLanguage::Python)
                .unwrap();
            assert!(
                !benign_matches.is_empty(),
                "benign subprocess.run(list) still matches at warn level"
            );
            assert!(
                !benign_matches[0].severity.blocks_by_default(),
                "benign list arg must not block"
            );
            // The destructive build-dir case still blocks (rm -rf via exec sink).
            assert!(
                matches[0].severity.blocks_by_default(),
                "rm -rf via exec sink blocks regardless of target"
            );
        }

        #[test]
        fn os_system_warns() {
            // os.system is Medium severity - warns but doesn't block by default
            let ast_matcher = AstMatcher::new();
            let code = "import os\nos.system('echo hello')";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(!matches.is_empty(), "os.system must match");
            assert_eq!(matches[0].rule_id, "heredoc.python.os_system");
            assert!(
                !matches[0].severity.blocks_by_default(),
                "Medium should not block"
            );
        }
    }

    /// Negative fixtures: patterns that must NOT match (safe code)
    mod python_negative_fixtures {
        use super::*;

        #[test]
        fn print_statement_does_not_match() {
            let ast_matcher = AstMatcher::new();
            // String containing destructive command text is NOT executed
            let code = "print('rm -rf /')";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(matches.is_empty(), "print statement must not match");
        }

        #[test]
        fn import_alone_does_not_match() {
            let ast_matcher = AstMatcher::new();
            // Just importing doesn't execute anything dangerous
            let code = "import shutil\nimport os\nimport subprocess";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(matches.is_empty(), "imports alone must not match");
        }

        #[test]
        fn inert_list_literal_assigned_then_printed_does_not_match() {
            // Regression guard (#136): a destructive token inside a list that is
            // merely assigned and printed (no exec sink) must stay ALLOWED. Only
            // actual exec-sink CALLS escalate, never inert list literals.
            let ast_matcher = AstMatcher::new();
            let code = "x = [\"sh\",\"-c\",\"rm -rf /etc\"]\nprint(x)";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(
                matches.is_empty(),
                "inert list literal must not match, got {matches:?}"
            );
            // The conservative exec-sink backstop must also stay silent here.
            assert!(
                scan_executing_sink_fallback(code, ScriptLanguage::Python).is_none(),
                "exec-sink fallback must not fire on an inert list literal"
            );
        }

        #[test]
        fn comment_does_not_match() {
            let ast_matcher = AstMatcher::new();
            // Comments mentioning dangerous operations are not executed
            let code = "# shutil.rmtree('/') would be dangerous\nx = 1";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(matches.is_empty(), "comments must not match");
        }

        #[test]
        fn safe_file_operations_do_not_match() {
            let ast_matcher = AstMatcher::new();
            // Safe file operations should not trigger
            let code = r"
import os
os.path.exists('/tmp/test')
os.path.isfile('/tmp/test')
os.listdir('/tmp')
with open('/tmp/log.txt', 'w') as f:
    f.write('hello')
";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(matches.is_empty(), "safe file operations must not match");
        }

        #[test]
        fn string_variable_does_not_match() {
            let ast_matcher = AstMatcher::new();
            // String that looks like dangerous code but is just data
            let code = r#"
dangerous_cmd = "shutil.rmtree('/')"
docs = "Example: os.remove(path)"
"#;
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(matches.is_empty(), "string literals must not match");
        }

        #[test]
        fn docstring_does_not_match() {
            let ast_matcher = AstMatcher::new();
            let code = r#"
def cleanup():
    """
    Warning: Do not call shutil.rmtree('/') as it will delete everything.
    Use os.remove() for single files only.
    """
    pass
"#;
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            assert!(matches.is_empty(), "docstrings must not match");
        }

        #[test]
        fn safe_tmp_cleanup_in_context() {
            let ast_matcher = AstMatcher::new();
            // This tests structural matching - the pattern matches but this is
            // about whether we match at all (we do), not about path safety
            // NOTE: This test verifies the pattern DOES match (as expected)
            // Path-based filtering would be a separate concern
            let code = "import shutil\nshutil.rmtree('/tmp/build_artifacts')";
            let matches = ast_matcher
                .find_matches(code, ScriptLanguage::Python)
                .unwrap();
            // Pattern matching finds this - path filtering is separate policy
            assert!(!matches.is_empty(), "shutil.rmtree matches structurally");
        }
    }

    mod catastrophic_paths {
        use super::*;

        #[test]
        fn test_is_catastrophic_path_loose_prefix() {
            // These should NOT be catastrophic
            assert!(!is_catastrophic_path("/bin_logs"));
            assert!(!is_catastrophic_path("/usr_local"));
            assert!(!is_catastrophic_path("/etc_backup"));
            assert!(!is_catastrophic_path("/home_page.html"));
        }

        #[test]
        fn test_is_catastrophic_path_strict_prefix() {
            // These SHOULD be catastrophic
            assert!(is_catastrophic_path("/bin"));
            assert!(is_catastrophic_path("/bin/"));
            assert!(is_catastrophic_path("/bin/sh"));
            assert!(is_catastrophic_path("/usr"));
            assert!(is_catastrophic_path("/usr/local"));
            assert!(is_catastrophic_path("/etc/passwd"));
        }

        #[test]
        fn test_is_catastrophic_path_var() {
            // /var should be catastrophic
            assert!(is_catastrophic_path("/var"));
            assert!(is_catastrophic_path("/var/www"));
            assert!(is_catastrophic_path("/var/log"));
        }

        #[test]
        fn test_is_catastrophic_path_tmp_backup_not_catastrophic() {
            // /tmp_backup should NOT be matched as /tmp (and thus fall through to sys_dirs check)
            // Since it's not in sys_dirs, it should return false.
            assert!(!is_catastrophic_path("/tmp_backup"));
        }

        // ---- #136: Python exec-sink refinement & exec-sink backstop ---------

        fn rmrf() -> String {
            format!("{}{}{}", "rm", " -", "rf")
        }

        #[test]
        fn python_os_system_destructive_literal_escalates_to_blocking() {
            let matcher = AstMatcher::new();
            let code = format!("import os\nos.system(\"{} /etc/important\")", rmrf());
            let matches = matcher.find_matches(&code, ScriptLanguage::Python).unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.rule_id.starts_with("heredoc.python.os_system")
                        && m.severity.blocks_by_default()),
                "os.system(rm -rf /etc) must escalate to a blocking severity: {matches:?}"
            );
        }

        #[test]
        fn python_os_system_benign_literal_warns_only() {
            let matcher = AstMatcher::new();
            let code = "import os\nos.system(\"echo hello\")";
            let matches = matcher.find_matches(code, ScriptLanguage::Python).unwrap();
            // The os.system match is still reported but must remain warn-only.
            assert!(
                matches
                    .iter()
                    .filter(|m| m.rule_id.starts_with("heredoc.python.os_system"))
                    .all(|m| !m.severity.blocks_by_default()),
                "benign os.system must stay warn-only: {matches:?}"
            );
        }

        #[test]
        fn python_print_literal_has_no_match() {
            let matcher = AstMatcher::new();
            // print() is not a registered sink: a destructive token in its inert
            // literal yields no AST match at all.
            let code = format!("print(\"{} /etc/important\")", rmrf());
            let matches = matcher.find_matches(&code, ScriptLanguage::Python).unwrap();
            assert!(
                matches.is_empty(),
                "inert print() literal must not match any python pattern: {matches:?}"
            );
        }

        #[test]
        fn fallback_catches_aliased_execsync_literal() {
            let code = format!(
                "const cp = require(\"child_process\")\ncp.execSync(\"{} /etc/important\")",
                rmrf()
            );
            let hit = scan_executing_sink_fallback(&code, ScriptLanguage::JavaScript);
            assert!(
                hit.is_some_and(|m| m.severity.blocks_by_default()),
                "aliased execSync(rm -rf /etc) must be caught by the backstop"
            );
        }

        #[test]
        fn fallback_ignores_inert_literal_without_sink() {
            let code = format!("const x = \"{} /etc\"\nconsole.log(x)", rmrf());
            assert!(
                scan_executing_sink_fallback(&code, ScriptLanguage::JavaScript).is_none(),
                "no exec sink => backstop must not fire"
            );
        }

        #[test]
        fn fallback_ignores_console_log_literal() {
            let code = format!("console.log(\"{} build\")", rmrf());
            assert!(
                scan_executing_sink_fallback(&code, ScriptLanguage::JavaScript).is_none(),
                "console.log is not an exec sink => backstop must not fire"
            );
        }

        #[test]
        fn fallback_does_not_run_for_bash() {
            let code = format!("{} /etc/important", rmrf());
            assert!(
                scan_executing_sink_fallback(&code, ScriptLanguage::Bash).is_none(),
                "bash bodies are never masked, so the backstop is a no-op for them"
            );
        }

        /// A harmless first hit must not stand in for the body. Ruby's pass
        /// returned its first hit whatever its severity, so the temp delete
        /// ahead of the `/` delete made the backstop report `Medium`.
        #[test]
        fn fallback_reports_blocking_hits_behind_a_harmless_one() {
            for code in [
                "system('rm', '-rf', '/tmp/x')\nsystem('rm', '-rf', '/')\n",
                "%x(rm -rf /tmp/x)\nsystem('rm', '-rf', '/')\n",
            ] {
                let hit = scan_executing_sink_fallback(code, ScriptLanguage::Ruby);
                assert!(
                    hit.as_ref()
                        .is_some_and(|m| m.severity == Severity::Critical),
                    "{code:?}: {hit:?}"
                );
            }
            // Every blocking match is returned, from both passes, and no
            // harmless one. (A quoted `system` call is seen by both passes, so
            // count lines rather than matches.)
            let code =
                "system('rm', '-rf', './build')\n`rm -rf ./dist`\nsystem('rm', '-rf', '/tmp/x')\n";
            let matches = scan_executing_sink_matches(code, ScriptLanguage::Ruby);
            let lines: std::collections::BTreeSet<usize> =
                matches.iter().map(|m| m.line_number).collect();
            assert_eq!(
                lines,
                std::collections::BTreeSet::from([1, 2]),
                "{matches:?}"
            );
            assert!(matches.iter().all(|m| m.severity.blocks_by_default()));
        }

        /// Perl's scans run inside `find_matches` and die with it on a timeout,
        /// so the backstop re-runs them.
        #[test]
        fn fallback_covers_perl() {
            for code in [
                "system('rm', '-rf', '/');\n",
                "exec 'rm', '-rf', './build';\n",
                "use File::Path;\nrmtree(['/tmp/x', '/']);\n",
            ] {
                assert!(
                    scan_executing_sink_fallback(code, ScriptLanguage::Perl).is_some(),
                    "{code:?}"
                );
            }
            for code in [
                "system('rm', '-rf', '/tmp/x');\n",
                "unlink('/tmp/x');\n",
                "print 'rm -rf /';\n",
            ] {
                assert!(
                    scan_executing_sink_fallback(code, ScriptLanguage::Perl).is_none(),
                    "{code:?}"
                );
            }
        }

        /// The reconstruction rejoins an argv-split spawn's literals into the
        /// command line, for verbs the rm/git backstop does not own, and skips
        /// the calls it does own.
        #[test]
        fn reconstructs_non_rm_argv_commands() {
            let lines = |code, lang| {
                exec_sink_reconstructed_commands(code, lang)
                    .into_iter()
                    .map(|c| c.command)
                    .collect::<Vec<_>>()
            };
            assert_eq!(
                lines(
                    "cp.spawnSync('dd', ['if=/dev/zero', 'of=/dev/sda'])",
                    ScriptLanguage::JavaScript
                ),
                vec!["dd if=/dev/zero of=/dev/sda".to_string()]
            );
            assert_eq!(
                lines(
                    "subprocess.run(['wipefs', '-a', '/dev/sda'])",
                    ScriptLanguage::Python
                ),
                vec!["wipefs -a /dev/sda".to_string()]
            );
            assert_eq!(
                lines(
                    "system('dd', 'if=/dev/zero', 'of=/dev/sda')",
                    ScriptLanguage::Perl
                ),
                vec!["dd if=/dev/zero of=/dev/sda".to_string()]
            );
            // rm and git are the backstop's; they are not reconstructed here.
            assert!(
                lines(
                    "cp.spawnSync('rm', ['-rf', '/'])",
                    ScriptLanguage::JavaScript
                )
                .is_empty()
            );
            assert!(lines("system('git', 'reset', '--hard')", ScriptLanguage::Ruby).is_empty());
            // A single-string sink argument is contiguous command text the raw
            // rescan already sees, so it is not reconstructed.
            assert!(
                lines(
                    "cp.execSync('dd if=/dev/zero of=/dev/sda')",
                    ScriptLanguage::JavaScript
                )
                .is_empty()
            );
            // A commented-out Perl call runs nothing.
            assert!(
                lines(
                    "# system('dd', 'if=/x', 'of=/dev/sda')\n",
                    ScriptLanguage::Perl
                )
                .is_empty()
            );
        }

        #[test]
        fn filesystem_fallback_catches_ruby_fileutils_catastrophic() {
            let code = "require \"fileutils\"\nFileUtils.rm_rf(\"/\")";
            let hit = scan_filesystem_sink_fallback(code, ScriptLanguage::Ruby);
            assert!(
                hit.is_some_and(|m| m.rule_id == "heredoc.ruby.fileutils_rm_rf.catastrophic"
                    && m.severity.blocks_by_default()),
                "catastrophic FileUtils.rm_rf must be caught by fallback"
            );
        }

        #[test]
        fn filesystem_fallback_catches_javascript_rmsync_catastrophic() {
            let code = "const fs = require('fs');\nfs.rmSync('/etc', { recursive: true });";
            let hit = scan_filesystem_sink_fallback(code, ScriptLanguage::JavaScript);
            assert!(
                hit.is_some_and(|m| m.rule_id == "heredoc.javascript.fs_rmsync.catastrophic"
                    && m.severity.blocks_by_default()),
                "catastrophic fs.rmSync must be caught before the bounded AST pass"
            );
        }

        #[test]
        fn filesystem_fallback_ignores_javascript_comment_and_template_text() {
            let comment = "/*\nfs.rmSync('/')\n*/";
            let template = "const docs = `\nfs.rmSync('/')\n`;";
            assert!(
                scan_filesystem_sink_fallback(comment, ScriptLanguage::JavaScript).is_none(),
                "commented fs.rmSync call must not fire fallback"
            );
            assert!(
                scan_filesystem_sink_fallback(template, ScriptLanguage::JavaScript).is_none(),
                "template text containing fs.rmSync must not fire fallback"
            );
        }

        /// The fallback must reach the same verdict the AST pass would (#455).
        ///
        /// It runs when the AST pass is unavailable or out of time. If it kept
        /// the old policy, an AST timeout would quietly relax the new one, and
        /// the way to get a recursive delete past the guard would be to make
        /// the parse slow.
        #[test]
        fn filesystem_fallback_agrees_with_the_ast_pass_on_recursive_deletes() {
            let blocked = "fs.rmSync('./dist', { recursive: true });";
            let hit = scan_filesystem_sink_fallback(blocked, ScriptLanguage::JavaScript)
                .expect("recursive delete outside /tmp must be caught by the fallback too");
            assert_eq!(hit.rule_id, "heredoc.javascript.fs_rmsync.non_temp");
            assert!(hit.severity.blocks_by_default());

            for code in [
                // A scratch target, and a delete that does not recurse.
                "fs.rmSync('/tmp/dist', { recursive: true });",
                "fs.rmSync('./a.txt');",
            ] {
                assert!(
                    scan_filesystem_sink_fallback(code, ScriptLanguage::JavaScript).is_none(),
                    "fallback must stay quiet: {code}"
                );
            }
        }

        /// #459: the fallback is name-anchored, so a call with NO receiver is
        /// caught.
        ///
        /// `$FS.rmSync($$$)` closed every aliased receiver in the AST pass, but a
        /// metavariable in receiver position cannot match a destructured import
        /// that calls the sink bare — and `const { rmSync } = require('fs')` and
        /// `import { rm } from 'node:fs/promises'` are how current Node is
        /// written, so the guarded spellings were the older ones.
        #[test]
        fn filesystem_fallback_catches_every_receiver_shape_issue_459() {
            for (code, expected) in [
                // No receiver at all: a destructured import.
                (
                    "rmSync('/home/user', { recursive: true });",
                    "heredoc.javascript.fs_rmsync.catastrophic",
                ),
                (
                    "rmdirSync('/home/user', { recursive: true });",
                    "heredoc.javascript.fs_rmdirsync.catastrophic",
                ),
                (
                    "unlinkSync('/home/user/.ssh/id_rsa');",
                    "heredoc.javascript.fs_unlinksync.catastrophic",
                ),
                (
                    "rm('/home/user', { recursive: true });",
                    "heredoc.javascript.fs_rm.catastrophic",
                ),
                // A receiver, under any name.
                (
                    "fs.rmSync('/home/user', { recursive: true });",
                    "heredoc.javascript.fs_rmsync.catastrophic",
                ),
                (
                    "nodefs.rmSync('/home/user', { recursive: true });",
                    "heredoc.javascript.fs_rmsync.catastrophic",
                ),
                // A receiver chain: the `fs.promises` member spelling.
                (
                    "fs.promises.rm('/home/user', { recursive: true });",
                    "heredoc.javascript.fs_rm.catastrophic",
                ),
                // `await` in front, which the pattern allows for.
                (
                    "await rm('/home/user', { recursive: true });",
                    "heredoc.javascript.fs_rm.catastrophic",
                ),
            ] {
                let hit = scan_filesystem_sink_fallback(code, ScriptLanguage::JavaScript)
                    .unwrap_or_else(|| panic!("fallback must catch {code}"));
                assert_eq!(hit.rule_id, expected, "wrong rule id for {code}");
                assert!(hit.severity.blocks_by_default(), "must block: {code}");
            }
        }

        /// The chained `require('fs')` receiver reaches the fallback too (#468).
        ///
        /// The test above covers a receiver that is an identifier or an identifier
        /// chain, which is what the pattern could express. It could not express a
        /// receiver that is itself a *call*, so `require('fs').rmSync('/home/user',
        /// {recursive: true})` was allowed whenever the AST pass was unavailable
        /// while the bound `fs.rmSync(...)` denied — measured end to end through
        /// the hook with `heredoc.max_body_lines = 1`, 12/12 allowed against 12/12
        /// denied for the bound spelling.
        ///
        /// This is the chained spelling the AST patterns already took a
        /// metavariable receiver for, so the two lists simply disagreed.
        #[test]
        fn filesystem_fallback_reaches_a_call_receiver_issue_468() {
            for (code, expected) in [
                (
                    "require('fs').rmSync('/home/user', { recursive: true });",
                    "heredoc.javascript.fs_rmsync.catastrophic",
                ),
                (
                    r#"require("fs").rmSync("/home/user", { recursive: true });"#,
                    "heredoc.javascript.fs_rmsync.catastrophic",
                ),
                (
                    "require('fs').rmdirSync('/home/user');",
                    "heredoc.javascript.fs_rmdirsync.catastrophic",
                ),
                (
                    "require('fs').unlinkSync('/home/user/.ssh/id_rsa');",
                    "heredoc.javascript.fs_unlinksync.catastrophic",
                ),
                // A call receiver followed by a member chain.
                (
                    "require('fs').promises.rm('/home/user', { recursive: true });",
                    "heredoc.javascript.fs_rm.catastrophic",
                ),
                (
                    "require('node:fs/promises').rm('/home/user', { recursive: true });",
                    "heredoc.javascript.fs_rm.catastrophic",
                ),
                // `await` in front of a call receiver.
                (
                    "await require('fs').promises.rm('/home/user');",
                    "heredoc.javascript.fs_rm.catastrophic",
                ),
                // Whitespace around the call and the member access.
                (
                    "require ( 'fs' ) . rmSync ('/home/user', { recursive: true });",
                    "heredoc.javascript.fs_rmsync.catastrophic",
                ),
            ] {
                let hit = scan_filesystem_sink_fallback(code, ScriptLanguage::JavaScript)
                    .unwrap_or_else(|| panic!("fallback must catch {code}"));
                assert_eq!(hit.rule_id, expected, "wrong rule id for {code}");
                assert!(hit.severity.blocks_by_default(), "must block: {code}");
            }

            // TypeScript shares the pattern, so it must gain the same coverage.
            let hit = scan_filesystem_sink_fallback(
                "require('fs').rmSync('/home/user', { recursive: true });",
                ScriptLanguage::TypeScript,
            )
            .expect("typescript fallback must catch a call receiver");
            assert_eq!(hit.rule_id, "heredoc.typescript.fs_rmsync.catastrophic");
        }

        /// Negative control for the call-receiver widening (#468).
        ///
        /// Admitting a call in receiver position must not admit anything else: a
        /// non-deleting method behind the same `require`, a non-qualifying target,
        /// and a receiver call whose argument is not a plain string literal.
        #[test]
        fn filesystem_fallback_call_receiver_is_not_overbroad_issue_468() {
            for code in [
                // Same receiver shape, not a deletion.
                "require('fs').mkdirSync('/home/user/newdir');",
                "require('fs').readFileSync('/home/user/.bashrc');",
                "require('fs').writeFileSync('/home/user/notes.txt', 'x');",
                // Deletion behind the receiver, but the target does not qualify.
                "require('fs').rmSync('/tmp/scratch/x', { recursive: true });",
                "require('fs').rmSync('./build/stamp');",
                // An identifier that merely ends in a sink name.
                "require('fs').confirmSync('/home/user');",
                // Prose mentioning the call.
                "// require('fs').rmSync is what we avoid",
            ] {
                assert!(
                    scan_filesystem_sink_fallback(code, ScriptLanguage::JavaScript).is_none(),
                    "fallback must stay quiet: {code}"
                );
            }
        }

        /// Negative control for the test above: name-anchoring must not turn any
        /// bare call with a path argument into a block.
        #[test]
        fn filesystem_fallback_name_anchor_is_not_overbroad_issue_459() {
            for code in [
                // Not deletions, even at a catastrophic target.
                "mkdirSync('/home/user/newdir');",
                "readFileSync('/home/user/.bashrc');",
                "writeFileSync('/home/user/notes.txt', 'x');",
                "copyFileSync('/home/user/a', '/home/user/b');",
                // Real deletion names, but the target and options do not qualify:
                // a scratch path, and a non-recursive delete of a relative file.
                "rm('/tmp/scratch/x', { recursive: true });",
                "rmSync('./build/stamp');",
                "rm('./build');",
                // A longer identifier that merely ends in a sink name.
                "confirmSync('/home/user');",
            ] {
                assert!(
                    scan_filesystem_sink_fallback(code, ScriptLanguage::JavaScript).is_none(),
                    "fallback must stay quiet: {code}"
                );
            }
        }

        #[test]
        fn filesystem_fallback_ignores_ruby_fileutils_in_comment() {
            let code = "# FileUtils.rm_rf(\"/\")";
            assert!(
                scan_filesystem_sink_fallback(code, ScriptLanguage::Ruby).is_none(),
                "commented FileUtils call must not fire fallback"
            );
        }

        #[test]
        fn filesystem_fallback_ignores_ruby_fileutils_in_string() {
            let code = "puts 'FileUtils.rm_rf(\"/\")'";
            assert!(
                scan_filesystem_sink_fallback(code, ScriptLanguage::Ruby).is_none(),
                "inert string containing FileUtils call must not fire fallback"
            );
        }

        /// #452: these two literals are the backstop when AST matching times
        /// out, and a line-start anchor could not reach a `-e`/`-c` one-liner
        /// — so for those payloads a timeout was an allow, not a fallback.
        #[test]
        fn filesystem_fallback_reaches_one_liner_statement_positions() {
            for code in [
                // The reported payload: the call follows `; `, never a line start.
                "require 'fileutils'; FileUtils.rm_rf('/home/user')",
                "require \"fileutils\"; FileUtils.rm_rf(\"/\")",
                "x = 1 && FileUtils.rm_rf('/')",
                "loop do FileUtils.rm_rf('/') end",
            ] {
                assert!(
                    scan_filesystem_sink_fallback(code, ScriptLanguage::Ruby).is_some(),
                    "one-liner must reach the Ruby fallback: {code}"
                );
            }
            for code in [
                "const fs = require('fs'); fs.rmSync('/', { recursive: true })",
                "const wipe = () => fs.rmSync('/etc', { recursive: true })",
                "if (x) { fs.rmSync('/', { recursive: true }) }",
            ] {
                assert!(
                    scan_filesystem_sink_fallback(code, ScriptLanguage::JavaScript).is_some(),
                    "one-liner must reach the JavaScript fallback: {code}"
                );
            }
        }

        /// The property the old `^[ \t]*` anchor was actually protecting: a
        /// call *mentioned* in passing follows a word, not a separator, so
        /// statement anchoring still refuses it.
        #[test]
        fn filesystem_fallback_still_ignores_a_call_mentioned_in_prose() {
            for code in [
                "# never run FileUtils.rm_rf('/') on a live host",
                "raise 'do not call FileUtils.rm_rf(\"/\") here'",
                "# the FileUtils.rm_rf('/') below is illustrative",
            ] {
                assert!(
                    scan_filesystem_sink_fallback(code, ScriptLanguage::Ruby).is_none(),
                    "a mention preceded by a word must not fire the fallback: {code}"
                );
            }
            assert!(
                scan_filesystem_sink_fallback(
                    "// never call fs.rmSync('/') here",
                    ScriptLanguage::JavaScript
                )
                .is_none(),
                "a mention preceded by a word must not fire the JavaScript fallback"
            );
        }

        #[test]
        fn fallback_catches_python_list_arg_destructive() {
            // Regression (#136): the backstop must descend into list elements, so
            // a destructive payload after an inert "sh" first element is caught.
            let code = format!(
                "import subprocess\nsubprocess.run([\"sh\",\"-c\",\"{} /etc\"])",
                rmrf()
            );
            let hit = scan_executing_sink_fallback(&code, ScriptLanguage::Python);
            assert!(
                hit.is_some_and(|m| m.severity.blocks_by_default()),
                "destructive list-arg payload must be caught by the backstop"
            );
        }

        #[test]
        fn fallback_catches_python_aliased_check_call_list_arg() {
            // check_call has no dedicated AST rule; the backstop must still catch
            // its destructive list-arg form (#136).
            let code = format!(
                "import subprocess as s\ns.check_call([\"sh\",\"-c\",\"{} /etc\"])",
                rmrf()
            );
            let hit = scan_executing_sink_fallback(&code, ScriptLanguage::Python);
            assert!(
                hit.is_some_and(|m| m.severity.blocks_by_default()),
                "check_call(list) destructive payload must be caught by the backstop"
            );
        }

        #[test]
        fn fallback_ignores_python_inert_list_literal() {
            // An inert list literal that is never passed to an exec sink must not
            // trip the backstop, even though it contains a destructive token.
            let code = format!("x = [\"sh\",\"-c\",\"{} build\"]\nprint(x)", rmrf());
            assert!(
                scan_executing_sink_fallback(&code, ScriptLanguage::Python).is_none(),
                "inert list literal must not fire the python backstop"
            );
        }
    }
}
