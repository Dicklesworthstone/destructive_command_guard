//! Two-tier heredoc and inline script detection.
//!
//! This module implements a tiered detection architecture for heredoc and inline
//! script analysis, balancing performance with detection accuracy.
//!
//! # Architecture
//!
//! ```text
//! Command Input
//!      │
//!      ▼
//! ┌─────────────────┐
//! │ Tier 1: Trigger │ ─── No match ──► ALLOW (fast path)
//! │   (<100μs)      │
//! └────────┬────────┘
//!          │ Match
//!          ▼
//! ┌─────────────────┐
//! │ Tier 2: Extract │ ─── Error/Timeout ──► ALLOW + warn
//! │   (<1ms)        │
//! └────────┬────────┘
//!          │ Success
//!          ▼
//! ┌─────────────────┐
//! │ Tier 3: AST     │ ─── No match ──► ALLOW
//! │   (<5ms)        │ ─── Match ──► BLOCK
//! └─────────────────┘
//! ```
//!
//! # Tier 1: Trigger Detection
//!
//! Ultra-fast detection using [`RegexSet`] for parallel matching.
//! Zero allocations on non-match path. MUST have zero false negatives.
//!
//! # Tier 2: Content Extraction
//!
//! Extracts heredoc/inline script content with bounded memory and time.
//! Graceful degradation on malformed input.
//!
//! # Tier 3: AST Pattern Matching (future)
//!
//! Uses ast-grep-core for structural pattern matching.
//! Language-specific patterns for destructive operations.

use memchr::memchr;
use regex::RegexSet;
use std::ops::Range;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tracing::{debug, instrument, trace, warn};

/// Tier 1 trigger patterns for heredoc and inline script detection.
///
/// These patterns are designed for maximum recall (zero false negatives).
/// False positives are acceptable - they just trigger Tier 2 analysis.
///
/// # Performance
///
/// Uses [`RegexSet`] for parallel matching in a single pass over the input.
/// Target latency: <10μs for non-matching, <100μs for matching.
///
/// Note: heredoc operators (e.g. `<<EOF`, `<<< "..."`) are detected via a small,
/// quote-aware scanner so we can suppress obvious false positives inside quoted
/// literals (commit messages, search patterns, etc.) without introducing false
/// negatives for real shell syntax (including `$()`/backtick substitutions).
const HEREDOC_TRIGGER_PATTERNS: [&str; 19] = [
    // Inline interpreter execution. These patterns intentionally allow:
    // - interleaved flags (python -I -c, bash --norc -c)
    // - combined short-flag clusters (bash -lc, node -pe, perl -pi -e)
    // - Windows .exe extensions (python.exe, python3.11.exe, etc.)
    // - Attached quotes (python -c"...", bash -c'...')
    //
    // Tier 1 MUST have zero false negatives for Tier 2 extraction.
    //
    // Here-string operator (<<<).
    // Tier 2 extracts here-strings via context-free regex, so Tier 1 must
    // trigger on any occurrence of <<< (even inside quotes) to maintain the
    // superset invariant.  False positives are acceptable for Tier 1.
    r"<<<",
    // Python inline execution (matches python, python3, python3.11, python.exe, python3.11.exe, etc.)
    r#"\bpython[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+(?:[:.=]\S*)?)(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*))?)*\s+-[A-Za-z]*[ce][A-Za-z]*(?:\s|['"]|$)"#,
    // Ruby inline execution (matches ruby, ruby3, ruby3.0, ruby.exe, etc.)
    r#"\bruby[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+(?:[:.=]\S*)?)(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*))?)*\s+-[A-Za-z]*e[A-Za-z]*(?:\s|['"]|$)"#,
    r#"\birb[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+(?:[:.=]\S*)?)(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*))?)*\s+-[A-Za-z]*e[A-Za-z]*(?:\s|['"]|$)"#,
    // Perl inline execution (matches perl, perl5, perl5.36, perl.exe, etc.)
    r#"\bperl[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+(?:[:.=]\S*)?)(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*))?)*\s+-[A-Za-z]*[eE][A-Za-z]*(?:\s|['"]|$)"#,
    // Node.js inline execution (matches node, node18, nodejs, node.exe, etc.)
    r#"\bnode(?:js)?[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+(?:[:.=]\S*)?)(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*))?)*\s+-[A-Za-z]*[ep][A-Za-z]*(?:\s|['"]|$)"#,
    // PHP inline execution
    r#"\bphp[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+(?:[:.=]\S*)?)(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*))?)*\s+-[A-Za-z]*r[A-Za-z]*(?:\s|['"]|$)"#,
    // Lua inline execution
    r#"\blua[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+(?:[:.=]\S*)?)(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*))?)*\s+-[A-Za-z]*e[A-Za-z]*(?:\s|['"]|$)"#,
    // Shell inline execution (sh -c, bash -c, zsh -c, fish -c, bash -lc, etc.)
    r#"\b(?:sh|bash|zsh|fish)(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+(?:[:.=]\S*)?)(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*))?)*\s+-[A-Za-z]*c[A-Za-z]*(?:\s|['"]|$)"#,
    // PowerShell inline execution (powershell -Command '...', pwsh -c "...",
    // and Windows full-path forms like
    //   "C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -Command '...'
    // which Codex emits as its Windows command_execution shape (#125)). The
    // `-Command` parameter (PowerShell abbreviates it to any prefix, e.g. `-c`,
    // `-com`, case-insensitively) runs an arbitrary inner shell command, so we
    // must descend into its body. `(?i)` makes the interpreter + flag
    // case-insensitive (Windows paths are case-insensitive). A possible closing
    // `"` of a quoted interpreter path is allowed before the flag. Tier 1 may
    // over-trigger; Tier 2 validates the actual flag.
    r#"(?i)\b(?:powershell|pwsh)(?:\.exe)?["']?(?:\s+-\S+(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*))?)*\s+-c[a-z]*\s*['"]"#,
    // PowerShell -EncodedCommand <base64> (abbreviates to -e/-en/-enc/-encodedcommand,
    // case-insensitively). The inner script is base64'd UTF-16LE; Tier 2 decodes and
    // re-evaluates it, so a destructive payload hidden in base64 is still caught. Tier 1
    // over-triggers (any base64-looking token after the flag); Tier 2 validates + decodes.
    r#"(?i)\b(?:powershell|pwsh)(?:\.exe)?["']?(?:\s+-\S+(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*))?)*\s+-e(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?\s+[A-Za-z0-9+/=]"#,
    // cmd.exe inline execution (`cmd /c "..."`, `cmd /k ...`, `cmd /s /c ...`,
    // `cmd.exe /c ...`). The /c (run-then-exit) and /k (run-then-stay) switches run an
    // arbitrary inner command line that Tier 2 extracts and re-evaluates.
    r"(?i)\bcmd(?:\.exe)?\b(?:\s+/[A-Za-z]+)*\s+/[ck]\b",
    // PowerShell Invoke-Expression / its `iex` alias: executes a string as code. Tier 2
    // extracts the quoted argument and re-evaluates it.
    r"(?i)(?:^|[\s;|&({])(?:iex|invoke-expression)\b",
    // Piped execution to interpreters (versioned, with optional .exe)
    r"\|\s*(?:python[0-9.]*|ruby[0-9.]*|perl[0-9.]*|node(?:js)?[0-9.]*|php[0-9.]*|lua[0-9.]*|sh|bash)(?:\.exe)?\b",
    // Piped to xargs (can execute arbitrary commands)
    r"\|\s*xargs\s",
    // exec/eval in various contexts
    r#"\beval\s+['"]"#,
    r#"\bexec\s+['"]"#,
    // `mise exec|x … -c|--command <payload>` runs an inline shell string (#259).
    // Tier 1 must be a superset of the Tier 2 grammar walk in
    // `mise_exec_inline_payloads`, so this deliberately over-matches: any run of
    // non-separator bytes may sit between `mise`, the subcommand, and the flag.
    // `mise`/`exec`/`-c` must share one pipeline segment (no `;`, `|`, `&`, or
    // newline between them). `(?:^|[^\w-])` before the flag keeps `-c` inside
    // longer words (`--cd`, `npm-c`) from firing. `$` is in the trailing class
    // for the attached Bash-quoted form `-c$'…'`. Tier 2 validates the grammar.
    r#"\bmise\b[^\n;|&]*\b(?:exec|x)\b[^\n;|&]*(?:^|[^\w-])(?:-c|--command)(?:[\s='"$]|$)"#,
    // `ssh [options] destination <command…>` hands everything after the
    // destination to the remote login shell as one command line (#326), so it
    // is an inline-script wrapper exactly like `sh -c` and must be recursively
    // evaluated — otherwise `ssh host '<destructive>'` rides through as quoted
    // argv data while the unquoted spelling is denied. Tier 1 must be a
    // superset of the Tier 2 grammar walk in `ssh_remote_payload`, so this
    // deliberately over-matches: `ssh`/`ssh.exe` at a word start followed by
    // more of the same pipeline segment containing a quote or `$` (an
    // all-unquoted remote command is already visible to raw pattern matching,
    // so Tier 2 only needs to run when quoting or expansion is present).
    // `[\s;|&(/]` before `ssh` keeps `ssh-keygen`/`ssh-add`/`autossh` from
    // triggering while still matching path-qualified `/usr/bin/ssh`.
    r#"(?i)(?:^|[\s;|&(/])ssh(?:\.exe)?\s[^\n;|&]*['"$]"#,
];

const MANUAL_HEREDOC_TRIGGER_INDEX: usize = HEREDOC_TRIGGER_PATTERNS.len();

static HEREDOC_TRIGGERS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new(HEREDOC_TRIGGER_PATTERNS).expect("heredoc trigger patterns should compile")
});

#[inline]
#[must_use]
fn contains_active_heredoc_operator(command: &str) -> bool {
    if memchr(b'<', command.as_bytes()).is_none() {
        return false;
    }
    contains_active_heredoc_operator_recursive(command, 0, 0)
}

#[must_use]
fn contains_active_heredoc_operator_recursive(
    command: &str,
    start: usize,
    recursion_depth: usize,
) -> bool {
    // Prevent stack overflow on pathological input.
    //
    // Tier 1 must have zero false negatives; on recursion exhaustion we conservatively
    // trigger (false positives are acceptable here).
    if recursion_depth > 500 {
        return true;
    }

    let bytes = command.as_bytes();
    let len = bytes.len();
    let mut i = start.min(len);

    while i < len {
        match bytes[i] {
            b'<' if i + 1 < len && bytes[i + 1] == b'<' => {
                // Active shell heredoc/here-string operator.
                return true;
            }
            b'\\' => {
                // Handle CRLF escape (consumes 3 bytes: \, \r, \n)
                if i + 2 < len && bytes[i + 1] == b'\r' && bytes[i + 2] == b'\n' {
                    i += 3;
                } else {
                    // Skip escaped byte. Conservative for UTF-8 (see context.rs notes).
                    i = (i + 2).min(len);
                }
            }
            b'\'' => {
                // Single-quoted segment (no escapes, no substitutions).
                i += 1;
                while i < len && bytes[i] != b'\'' {
                    i += 1;
                }
                if i < len {
                    i += 1;
                }
            }
            b'"' => {
                // Double-quoted segment: ignore literal `<<` inside, but scan nested `$()`/backticks.
                let (found, next) = scan_double_quotes_for_heredoc(command, i + 1, recursion_depth);
                if found {
                    return true;
                }
                i = next;
            }
            b'$' if i + 1 < len && bytes[i + 1] == b'(' => {
                let (found, next) =
                    scan_dollar_paren_for_heredoc_recursive(command, i, recursion_depth + 1);
                if found {
                    return true;
                }
                i = next;
            }
            b'`' => {
                let (found, next) =
                    scan_backticks_for_heredoc_recursive(command, i, recursion_depth + 1);
                if found {
                    return true;
                }
                i = next;
            }
            _ => {
                i += 1;
            }
        }
    }

    false
}

#[must_use]
fn scan_double_quotes_for_heredoc(
    command: &str,
    start: usize,
    recursion_depth: usize,
) -> (bool, usize) {
    if recursion_depth > 500 {
        return (true, command.len());
    }

    let bytes = command.as_bytes();
    let len = bytes.len();
    let mut i = start.min(len);

    while i < len {
        match bytes[i] {
            b'"' => return (false, i + 1),
            b'\\' => {
                i = (i + 2).min(len);
            }
            b'$' if i + 1 < len && bytes[i + 1] == b'(' => {
                let (found, next) =
                    scan_dollar_paren_for_heredoc_recursive(command, i, recursion_depth + 1);
                if found {
                    return (true, next);
                }
                i = next;
            }
            b'`' => {
                let (found, next) =
                    scan_backticks_for_heredoc_recursive(command, i, recursion_depth + 1);
                if found {
                    return (true, next);
                }
                i = next;
            }
            _ => {
                i += 1;
            }
        }
    }

    (false, len)
}

#[must_use]
fn scan_dollar_paren_for_heredoc_recursive(
    command: &str,
    start: usize,
    recursion_depth: usize,
) -> (bool, usize) {
    // Prevent stack overflow on pathological input.
    if recursion_depth > 500 {
        return (true, command.len());
    }

    let bytes = command.as_bytes();
    let len = bytes.len();

    debug_assert_eq!(bytes.get(start), Some(&b'$'));
    debug_assert_eq!(bytes.get(start + 1), Some(&b'('));

    let mut i = start + 2;
    let mut depth: u32 = 1;

    while i < len {
        match bytes[i] {
            b'<' if i + 1 < len && bytes[i + 1] == b'<' => {
                return (true, i + 2);
            }
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                if depth == 1 {
                    // End of command substitution.
                    return (false, i + 1);
                }
                depth = depth.saturating_sub(1);
                i += 1;
            }
            b'\\' => {
                i = (i + 2).min(len);
            }
            b'\'' => {
                // Single quotes inside: consume until closing.
                i += 1;
                while i < len && bytes[i] != b'\'' {
                    i += 1;
                }
                if i < len {
                    i += 1;
                }
            }
            b'"' => {
                let (found, next) = scan_double_quotes_for_heredoc(command, i + 1, recursion_depth);
                if found {
                    return (true, next);
                }
                i = next;
            }
            b'$' if i + 1 < len && bytes[i + 1] == b'(' => {
                let (found, next) =
                    scan_dollar_paren_for_heredoc_recursive(command, i, recursion_depth + 1);
                if found {
                    return (true, next);
                }
                i = next;
            }
            b'`' => {
                let (found, next) =
                    scan_backticks_for_heredoc_recursive(command, i, recursion_depth + 1);
                if found {
                    return (true, next);
                }
                i = next;
            }
            _ => {
                i += 1;
            }
        }
    }

    (false, len)
}

#[must_use]
fn scan_backticks_for_heredoc_recursive(
    command: &str,
    start: usize,
    recursion_depth: usize,
) -> (bool, usize) {
    if recursion_depth > 500 {
        return (true, command.len());
    }

    let bytes = command.as_bytes();
    let len = bytes.len();

    debug_assert_eq!(bytes.get(start), Some(&b'`'));

    let mut i = start + 1;
    while i < len {
        match bytes[i] {
            b'<' if i + 1 < len && bytes[i + 1] == b'<' => {
                return (true, i + 2);
            }
            b'\\' => {
                i = (i + 2).min(len);
            }
            b'\'' => {
                i += 1;
                while i < len && bytes[i] != b'\'' {
                    i += 1;
                }
                if i < len {
                    i += 1;
                }
            }
            b'"' => {
                let (found, next) = scan_double_quotes_for_heredoc(command, i + 1, recursion_depth);
                if found {
                    return (true, next);
                }
                i = next;
            }
            b'$' if i + 1 < len && bytes[i + 1] == b'(' => {
                let (found, next) =
                    scan_dollar_paren_for_heredoc_recursive(command, i, recursion_depth + 1);
                if found {
                    return (true, next);
                }
                i = next;
            }
            b'`' => {
                return (false, i + 1);
            }
            _ => {
                i += 1;
            }
        }
    }

    (false, len)
}

/// Result of Tier 1 trigger detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerResult {
    /// No heredoc/inline script indicators found - fast path to ALLOW.
    NoTrigger,
    /// Trigger detected - proceed to Tier 2 extraction.
    Triggered,
}

/// Check if a command contains heredoc or inline script indicators.
///
/// This is Tier 1 of the detection pipeline - ultra-fast screening.
///
/// # Guarantees
///
/// - Zero false negatives: if Tier 2 would find a heredoc, this MUST trigger
/// - Zero allocations on non-match path
/// - Target latency: <10μs for non-matching commands
///
/// # Examples
///
/// ```ignore
/// use destructive_command_guard::heredoc::{check_triggers, TriggerResult};
///
/// // No trigger - fast path
/// assert_eq!(check_triggers("git status"), TriggerResult::NoTrigger);
///
/// // Heredoc trigger
/// assert_eq!(check_triggers("cat << EOF"), TriggerResult::Triggered);
///
/// // Python inline execution
/// assert_eq!(check_triggers("python -c 'import os'"), TriggerResult::Triggered);
/// ```
#[inline]
#[must_use]
#[instrument(skip(command), fields(cmd_len = command.len()))]
pub fn check_triggers(command: &str) -> TriggerResult {
    if contains_active_heredoc_operator(command) || HEREDOC_TRIGGERS.is_match(command) {
        debug!("tier1_trigger: heredoc/inline script indicator detected");
        TriggerResult::Triggered
    } else {
        trace!("tier1_no_trigger: fast path allow");
        TriggerResult::NoTrigger
    }
}

/// Returns the list of trigger pattern indices that matched.
///
/// Useful for debugging and logging which patterns triggered.
#[must_use]
pub fn matched_triggers(command: &str) -> Vec<usize> {
    let mut matches: Vec<usize> = HEREDOC_TRIGGERS.matches(command).into_iter().collect();
    if contains_active_heredoc_operator(command) {
        matches.push(MANUAL_HEREDOC_TRIGGER_INDEX);
    }
    matches
}

// ============================================================================
// Tier 2: Content Extraction
// ============================================================================

use regex::Regex;

/// Limits for content extraction to prevent resource exhaustion.
#[derive(Debug, Clone, Copy)]
pub struct ExtractionLimits {
    /// Maximum bytes to extract from heredoc body (default: 1MB)
    pub max_body_bytes: usize,
    /// Maximum lines to extract from heredoc body (default: 10,000)
    pub max_body_lines: usize,
    /// Maximum number of heredocs to process per command (default: 10)
    pub max_heredocs: usize,
    /// Timeout for extraction in milliseconds (default: 50ms)
    pub timeout_ms: u64,
}

impl Default for ExtractionLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: 1024 * 1024, // 1MB
            max_body_lines: 10_000,
            max_heredocs: 10,
            timeout_ms: 50,
        }
    }
}

/// Detected language for embedded script content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptLanguage {
    Bash,
    Go,
    Php,
    Python,
    Ruby,
    Perl,
    JavaScript,
    TypeScript,
    Unknown,
}

impl ScriptLanguage {
    /// Infer language from a command prefix (e.g., "python", "python3", "python3.11").
    ///
    /// Matches exact command names or names with version suffixes (e.g., "python3.11").
    /// Also handles Windows .exe extensions (e.g., "python.exe", "python3.11.exe").
    /// Does NOT match arbitrary words that start with a command name (e.g., "shebang" ≠ "sh").
    #[must_use]
    pub fn from_command(cmd: &str) -> Self {
        let cmd_lower = cmd.to_lowercase();
        // Strip Windows .exe extension if present
        let cmd_base = cmd_lower.strip_suffix(".exe").unwrap_or(&cmd_lower);

        // Helper: check if cmd matches base name, optionally followed by version digits/dots
        // e.g., "python" matches "python", "python3", "python3.11"
        // but "python" does NOT match "pythonic" or "python_helper"
        let matches_interpreter = |base: &str| -> bool {
            if cmd_base == base {
                return true;
            }
            // Allow version suffixes: digits and dots (e.g., "3", "3.11", "3.11.4")
            cmd_base.strip_prefix(base).is_some_and(|suffix| {
                !suffix.is_empty()
                    && suffix.chars().all(|c| c.is_ascii_digit() || c == '.')
                    && suffix.chars().next().is_some_and(|c| c.is_ascii_digit())
            })
        };

        if matches_interpreter("python") {
            Self::Python
        } else if matches_interpreter("ruby") || matches_interpreter("irb") {
            Self::Ruby
        } else if matches_interpreter("perl") {
            Self::Perl
        } else if matches_interpreter("node") || matches_interpreter("nodejs") {
            Self::JavaScript
        } else if matches_interpreter("deno") || matches_interpreter("bun") {
            Self::TypeScript
        } else if matches_interpreter("php") {
            Self::Php
        } else if matches_interpreter("go") {
            // Note: Go doesn't typically use version suffixes in command names
            Self::Go
        } else if matches_interpreter("sh")
            || matches_interpreter("bash")
            || matches_interpreter("zsh")
            || matches_interpreter("fish")
            // PowerShell (`powershell`, `powershell.exe`, `pwsh`) running an
            // inner command via `-Command`/`-c`. We re-check the body as a
            // shell command: destructive command names (git, rm, etc.) are
            // identical across PowerShell and POSIX shells, so Bash-style
            // re-evaluation surfaces the same rules. This is what lets dcg
            // descend into Codex's Windows `powershell.exe -Command '...'`
            // command shape (#125).
            || matches_interpreter("powershell")
            || matches_interpreter("pwsh")
        {
            Self::Bash
        } else {
            Self::Unknown
        }
    }

    /// Infer language from a shebang line (e.g., `#!/usr/bin/env python3`).
    ///
    /// Parses both direct interpreter paths (`#!/bin/bash`) and env-based shebangs
    /// (`#!/usr/bin/env python3`).
    ///
    /// Returns `None` if no valid shebang is found.
    #[must_use]
    pub fn from_shebang(content: &str) -> Option<Self> {
        let first_line = content.lines().next()?;

        // Shebang must start with #!
        let shebang = first_line.strip_prefix("#!")?;
        let shebang = shebang.trim();

        if shebang.is_empty() {
            return None;
        }

        // Extract interpreter: handle both direct paths and env-style shebangs
        // Examples:
        //   #!/bin/bash              -> bash
        //   #!/bin/bash -e           -> bash (ignores flags)
        //   #!/usr/bin/env python3   -> python3
        //   #!/usr/bin/env python3 -u -> python3 (ignores flags)
        //   #!/usr/bin/env -S python3 -u -> python3 (skips env flags)
        //   #!/usr/bin/python        -> python
        let mut parts = shebang.split_whitespace();
        let first = parts.next()?;
        let basename = first.rsplit('/').next().unwrap_or(first);

        // If it's "env", skip any flags (starting with -) to find the interpreter
        let interpreter = if basename == "env" {
            // Skip env flags like -S, -i, -u, etc.
            loop {
                let next = parts.next()?;
                if !next.starts_with('-') {
                    break next.rsplit('/').next().unwrap_or(next);
                }
            }
        } else {
            basename
        };

        // Use existing from_command logic to map interpreter to language
        let lang = Self::from_command(interpreter);
        if lang == Self::Unknown {
            None
        } else {
            Some(lang)
        }
    }

    /// Infer language from content heuristics (fallback detection).
    ///
    /// Examines the first few lines for language-specific patterns like
    /// import statements, requires, or function definitions.
    ///
    /// This is a low-confidence detection method used only when command
    /// prefix and shebang detection fail.
    ///
    /// Returns `None` if no recognizable patterns are found.
    #[must_use]
    pub fn from_content(content: &str) -> Option<Self> {
        // Only examine first 20 lines to bound heuristic cost
        let lines: Vec<&str> = content.lines().take(20).collect();

        // Python indicators (high confidence)
        let has_python_import = lines.iter().any(|l| {
            let trimmed = l.trim();
            trimmed.starts_with("import ") || trimmed.starts_with("from ")
        });
        if has_python_import {
            return Some(Self::Python);
        }

        // TypeScript indicators (check BEFORE JavaScript since TS is a superset)
        // TypeScript-specific patterns that distinguish it from plain JS
        let has_typescript_patterns = lines.iter().any(|l| {
            let trimmed = l.trim();
            trimmed.contains(": string")
                || trimmed.contains(": number")
                || trimmed.contains(": boolean")
                || trimmed.contains("interface ")
                || trimmed.starts_with("type ")
        });
        if has_typescript_patterns {
            return Some(Self::TypeScript);
        }

        // JavaScript/Node indicators
        let has_js_patterns = lines.iter().any(|l| {
            let trimmed = l.trim();
            trimmed.contains("require(")
                || trimmed.starts_with("const ")
                || trimmed.starts_with("let ")
                || trimmed.starts_with("var ")
                || trimmed.contains("module.exports")
        });
        if has_js_patterns {
            return Some(Self::JavaScript);
        }

        // Ruby indicators
        let has_ruby_patterns = lines.iter().any(|l| {
            let trimmed = l.trim();
            trimmed.starts_with("def ")
                || trimmed.starts_with("class ")
                || trimmed.starts_with("require ")
                || trimmed.starts_with("require_relative ")
                || trimmed.contains(".each do")
                || trimmed.contains(" do |")
        });
        // Ruby also needs "end" somewhere to reduce false positives
        let has_end = content.contains("\nend") || content.ends_with("end");
        if has_ruby_patterns && has_end {
            return Some(Self::Ruby);
        }

        // Go indicators (high confidence)
        // Go has distinctive patterns: package declaration, func, :=, import with quotes
        let has_go_patterns = lines.iter().any(|l| {
            let trimmed = l.trim();
            trimmed.starts_with("package ")
                || trimmed.starts_with("func ")
                || trimmed.contains(":=")
                || (trimmed.starts_with("import ") && trimmed.contains('"'))
                || trimmed == "import ("
        });
        if has_go_patterns {
            return Some(Self::Go);
        }

        // Perl indicators
        let has_perl_patterns = lines.iter().any(|l| {
            let trimmed = l.trim();
            trimmed.starts_with("use strict")
                || trimmed.starts_with("use warnings")
                || trimmed.starts_with("my $")
                || trimmed.starts_with("my @")
                || trimmed.starts_with("my %")
                || trimmed.contains("=~ /")
                || trimmed.contains("=~ s/")
        });
        if has_perl_patterns {
            return Some(Self::Perl);
        }

        // Bash indicators (low priority - many scripts look like bash)
        let has_bash_patterns = lines.iter().any(|l| {
            let trimmed = l.trim();
            trimmed.starts_with("if [")
                || trimmed.starts_with("for ")
                || trimmed.starts_with("while ")
                || trimmed.starts_with("case ")
                || trimmed.contains("$((")
                || trimmed.contains("${")
                || trimmed.starts_with("function ")
                || (trimmed.contains("()") && trimmed.contains('{'))
        });
        if has_bash_patterns {
            return Some(Self::Bash);
        }

        None
    }

    /// Detect language using all available signals with priority order.
    ///
    /// Priority:
    /// 1. Command prefix (highest confidence - e.g., `python -c`)
    /// 2. Shebang line (high confidence - e.g., `#!/usr/bin/env python3`)
    /// 3. Content heuristics (lower confidence - imports, patterns)
    /// 4. Unknown (fallback)
    ///
    /// Returns a tuple of (language, confidence) for explainability.
    #[must_use]
    pub fn detect(cmd: &str, content: &str) -> (Self, DetectionConfidence) {
        // Priority 1: Extract interpreter from command prefix
        if let Some(interpreter) = Self::extract_head_interpreter(cmd) {
            let lang = Self::from_command(&interpreter);
            if lang != Self::Unknown {
                return (lang, DetectionConfidence::CommandPrefix);
            }
        }

        // Priority 1b: Check pipe destinations (e.g. "cat <<EOF | python")
        // This handles cases where the heredoc consumer is later in the pipeline
        if cmd.contains('|') {
            for segment in cmd.split('|') {
                let segment = segment.trim();
                if segment.is_empty() {
                    continue;
                }
                if let Some(interpreter) = Self::extract_head_interpreter(segment) {
                    let lang = Self::from_command(&interpreter);
                    if lang != Self::Unknown {
                        return (lang, DetectionConfidence::CommandPrefix);
                    }
                }
            }
        }

        // Priority 2: Shebang detection
        if let Some(lang) = Self::from_shebang(content) {
            return (lang, DetectionConfidence::Shebang);
        }

        // Priority 3: Content heuristics
        if let Some(lang) = Self::from_content(content) {
            return (lang, DetectionConfidence::ContentHeuristics);
        }

        // Priority 4: Unknown
        (Self::Unknown, DetectionConfidence::Unknown)
    }

    /// Extract the interpreter name from the head of a command string.
    ///
    /// Handles various formats:
    /// - `python3 -c "code"` → "python3"
    /// - `/usr/bin/python -c "code"` → "python"
    /// - `env python3 -c "code"` → "python3"
    /// - `env -S python3 -c "code"` → "python3" (skips env flags)
    /// - `env VAR=val python3 -c "code"` → "python3" (skips env vars)
    /// - `bash -c "code"` → "bash"
    fn extract_head_interpreter(cmd: &str) -> Option<String> {
        // Use robust wrapper stripping to handle env flags (e.g. -u, -C) correctly.
        let normalized = crate::normalize::strip_wrapper_prefixes(cmd);
        let cmd_to_check = normalized.normalized;

        let mut parts = cmd_to_check.split_whitespace();
        let first = parts.next()?;

        // Get basename (strip path)
        let basename = first.rsplit('/').next().unwrap_or(first);
        Some(basename.to_string())
    }
}

/// Confidence level of language detection.
///
/// Used by `dcg explain` to show why a particular language was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetectionConfidence {
    /// Detected from command prefix (e.g., `python -c`).
    /// Highest confidence - the command explicitly names the interpreter.
    CommandPrefix,

    /// Detected from shebang line (e.g., `#!/usr/bin/env python3`).
    /// High confidence - explicit interpreter declaration in the script.
    Shebang,

    /// Detected from content patterns (imports, syntax patterns).
    /// Lower confidence - heuristic-based detection.
    ContentHeuristics,

    /// Could not determine language.
    /// Lowest "confidence" - effectively no detection.
    Unknown,
}

impl DetectionConfidence {
    /// Human-readable label for this confidence level.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::CommandPrefix => "command-prefix",
            Self::Shebang => "shebang",
            Self::ContentHeuristics => "content-heuristics",
            Self::Unknown => "unknown",
        }
    }

    /// Descriptive reason for this confidence level.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::CommandPrefix => "detected from command interpreter (highest confidence)",
            Self::Shebang => "detected from shebang line (high confidence)",
            Self::ContentHeuristics => "inferred from content patterns (lower confidence)",
            Self::Unknown => "could not determine language",
        }
    }
}

/// Type of heredoc extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeredocType {
    /// Standard heredoc (<<)
    Standard,
    /// Tab-stripping heredoc (<<-)
    TabStripped,
    /// Here-string (<<<)
    HereString,
    /// Indentation-stripping heredoc (<<~, Ruby-style)
    IndentStripped,
}

/// Extracted content from a heredoc or inline script.
#[derive(Debug, Clone)]
pub struct ExtractedContent {
    /// The script content (body of heredoc or inline argument).
    pub content: String,
    /// Detected or inferred language.
    pub language: ScriptLanguage,
    /// Heredoc delimiter (e.g., "EOF"), if applicable.
    pub delimiter: Option<String>,
    /// Byte range in the original command.
    pub byte_range: std::ops::Range<usize>,
    /// Byte range of the extracted content inside the original command, if known.
    ///
    /// For inline scripts and here-strings this is the exact content span.
    /// For heredoc bodies, this represents the raw body range (may not map
    /// cleanly if indentation or CRLF normalization occurred).
    pub content_range: Option<std::ops::Range<usize>>,
    /// Whether the delimiter was quoted (suppresses expansion).
    pub quoted: bool,
    /// Type of heredoc (if applicable).
    pub heredoc_type: Option<HeredocType>,
    /// The command that receives this heredoc (e.g., "cat", "bash").
    /// Used to determine if content should be evaluated as executable.
    pub target_command: Option<String>,
}

/// Reason why extraction was skipped (for observability/logging).
#[derive(Debug, Clone, PartialEq)]
pub enum SkipReason {
    /// Input exceeded maximum size limit.
    ExceededSizeLimit { actual: usize, limit: usize },
    /// Input exceeded maximum line count.
    ExceededLineLimit { actual: usize, limit: usize },
    /// Maximum heredoc count reached.
    ExceededHeredocLimit { limit: usize },
    /// Binary-like content detected (contains null bytes or high non-printable ratio).
    BinaryContent {
        null_bytes: usize,
        non_printable_ratio: f32,
    },
    /// Tier 2 extraction exceeded the time budget; the evaluator chooses
    /// bounded fallback or a strict block from configuration.
    Timeout { elapsed_ms: u64, budget_ms: u64 },
    /// Heredoc delimiter not found (unterminated).
    UnterminatedHeredoc { delimiter: String },
    /// Malformed input that couldn't be parsed.
    MalformedInput { reason: String },
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExceededSizeLimit { actual, limit } => {
                write!(f, "exceeded size limit: {actual} bytes > {limit} bytes")
            }
            Self::ExceededLineLimit { actual, limit } => {
                write!(f, "exceeded line limit: {actual} lines > {limit} lines")
            }
            Self::ExceededHeredocLimit { limit } => {
                write!(f, "exceeded heredoc limit: max {limit} heredocs")
            }
            Self::BinaryContent {
                null_bytes,
                non_printable_ratio,
            } => {
                write!(
                    f,
                    "binary content detected: {null_bytes} null bytes, {:.1}% non-printable",
                    non_printable_ratio * 100.0
                )
            }
            Self::Timeout {
                elapsed_ms,
                budget_ms,
            } => write!(
                f,
                "extraction timeout: {elapsed_ms}ms > {budget_ms}ms budget"
            ),
            Self::UnterminatedHeredoc { delimiter } => {
                write!(f, "unterminated heredoc: delimiter '{delimiter}' not found")
            }
            Self::MalformedInput { reason } => {
                write!(f, "malformed input: {reason}")
            }
        }
    }
}

/// Result of Tier 2 content extraction.
#[derive(Debug)]
pub enum ExtractionResult {
    /// No extractable content found after trigger.
    NoContent,
    /// Successfully extracted content.
    Extracted(Vec<ExtractedContent>),
    /// Extraction was skipped; the evaluator retains reasons for its configured
    /// bounded-fallback or strict-block decision.
    Skipped(Vec<SkipReason>),
    Partial {
        extracted: Vec<ExtractedContent>,
        skipped: Vec<SkipReason>,
    },
    /// Extraction failed (timeout, malformed, etc.); the evaluator applies its
    /// configured bounded-fallback or strict-block policy.
    Failed(String),
}

/// Regex patterns for heredoc extraction (compiled once).
static HEREDOC_EXTRACTOR: LazyLock<Regex> = LazyLock::new(|| {
    // Matches: <<[-~]? followed by:
    // 1. Single-quoted delimiter: 'delim' (Group 2)
    // 2. Double-quoted delimiter: "delim" (Group 3)
    // 3. Unquoted delimiter: delim (Group 4)
    // Group 1 is the operator variant (-/~/empty).
    // Note: * instead of + allows empty delimiters (valid in bash).
    Regex::new(r#"<<([-~])?\s*(?:'([^']*)'|"([^"]*)"|([\w.-]+))"#).expect("heredoc regex compiles")
});

/// Regex for here-string extraction with single quotes (<<<).
static HERESTRING_SINGLE_QUOTE: LazyLock<Regex> = LazyLock::new(|| {
    // Matches: <<< 'content' - content can contain double quotes
    // Group 1: content
    Regex::new(r"<<<\s*'([^']*)'").expect("herestring single-quote regex compiles")
});

/// Regex for here-string extraction with double quotes (<<<).
static HERESTRING_DOUBLE_QUOTE: LazyLock<Regex> = LazyLock::new(|| {
    // Matches: <<< "content" - content can contain single quotes
    // Group 1: content
    Regex::new(r#"<<<\s*"([^"]*)""#).expect("herestring double-quote regex compiles")
});

/// Regex for here-string extraction without quotes (<<<).
static HERESTRING_UNQUOTED: LazyLock<Regex> = LazyLock::new(|| {
    // Matches: <<< word - unquoted single word (NOT starting with quote)
    // Group 1: content
    // [^'\x22\s] ensures we don't match quoted forms
    Regex::new(r"<<<\s*([^'\x22\s]\S*)").expect("herestring unquoted regex compiles")
});

/// Regex for inline script flag extraction with single quotes.
static INLINE_SCRIPT_SINGLE_QUOTE: LazyLock<Regex> = LazyLock::new(|| {
    // Matches: command -c/-e/-p/-E/-r followed by single-quoted content
    // Groups: (1) interpreter, (2) optional "js" suffix for node, (3) flag, (4) content
    // Supports versioned interpreters: python3.11, ruby3.0, perl5.36, node18, nodejs20, etc.
    // Supports Windows .exe extensions: python.exe, python3.11.exe, etc.
    // `(?i:powershell|pwsh)` matches the Windows PowerShell host case-insensitively;
    // `["']?` after the interpreter swallows the closing quote of a quoted full
    // path (e.g. `"...\powershell.exe" -Command '...'`) before flags (#125).
    Regex::new(r#"\b(python[0-9.]*(?:\.exe)?|ruby[0-9.]*(?:\.exe)?|irb[0-9.]*(?:\.exe)?|perl[0-9.]*(?:\.exe)?|node(js)?[0-9.]*(?:\.exe)?|php[0-9.]*(?:\.exe)?|lua[0-9.]*(?:\.exe)?|sh(?:\.exe)?|bash(?:\.exe)?|zsh(?:\.exe)?|fish(?:\.exe)?|(?i:powershell|pwsh)(?:\.exe)?)\b["']?(?:\s+(?:--\S+|-[A-Za-z]+(?:[:.=]\S*)?)(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*))?)*\s+(-[A-Za-z]*[ceECpr][A-Za-z]*)\s*'([^']*)'"#)
        .expect("inline script single-quote regex compiles")
});

/// Regex for inline script flag extraction with double quotes.
static INLINE_SCRIPT_DOUBLE_QUOTE: LazyLock<Regex> = LazyLock::new(|| {
    // Matches: command -c/-e/-p/-E/-r followed by double-quoted content
    // Groups: (1) interpreter, (2) optional "js" suffix for node, (3) flag, (4) content
    // Supports versioned interpreters: python3.11, ruby3.0, perl5.36, node18, nodejs20, etc.
    // Supports Windows .exe extensions: python.exe, python3.11.exe, etc.
    // PowerShell host + quoted-path closing quote handled as in the single-quote
    // variant above (#125).
    Regex::new(r#"\b(python[0-9.]*(?:\.exe)?|ruby[0-9.]*(?:\.exe)?|irb[0-9.]*(?:\.exe)?|perl[0-9.]*(?:\.exe)?|node(js)?[0-9.]*(?:\.exe)?|php[0-9.]*(?:\.exe)?|lua[0-9.]*(?:\.exe)?|sh(?:\.exe)?|bash(?:\.exe)?|zsh(?:\.exe)?|fish(?:\.exe)?|(?i:powershell|pwsh)(?:\.exe)?)\b['"]?(?:\s+(?:--\S+|-[A-Za-z]+(?:[:.=]\S*)?)(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*))?)*\s+(-[A-Za-z]*[ceECpr][A-Za-z]*)\s*"([^"]*)""#)
        .expect("inline script double-quote regex compiles")
});

/// Regex for `cmd /c "..."` / `cmd /k ...` inline execution (the Windows analog of
/// `bash -c`). Group 1 = double-quoted inner, group 2 = single-quoted inner,
/// group 3 = unquoted rest-of-line. The inner command line is re-evaluated by the
/// full pipeline, so `cmd /c "del /s /q C:\src"` is blocked like the bare `del`.
static CMD_INLINE_SCRIPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\bcmd(?:\.exe)?\b(?:\s+/[A-Za-z]+)*\s+/[ck]\s+(?:"([^"]*)"|'([^']*)'|([^\n]+))"#,
    )
    .expect("cmd inline script regex compiles")
});

/// Regex for PowerShell `Invoke-Expression`/`iex` of a quoted string. Group 1 =
/// double-quoted, group 2 = single-quoted. The argument is executed as code, so we
/// re-evaluate it.
static IEX_INLINE_SCRIPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:^|[\s;|&({])(?:iex|invoke-expression)\b\s*(?:"([^"]*)"|'([^']*)')"#)
        .expect("iex inline script regex compiles")
});

/// Regex for `powershell -EncodedCommand <base64>` (flag abbreviates to any prefix
/// of `-encodedcommand`, min `-e`). Group 1 = the base64 token, which Tier 2 decodes
/// (base64 -> UTF-16LE -> text) and re-evaluates.
static POWERSHELL_ENCODED_COMMAND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(?:powershell|pwsh)(?:\.exe)?["']?(?:\s+-\S+(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*))?)*\s+-e(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?\s+([A-Za-z0-9+/=]+)"#,
    )
    .expect("powershell encoded-command regex compiles")
});

/// Decode a PowerShell `-EncodedCommand` payload: standard base64 of a UTF-16LE
/// string. Returns `None` (fail-open) on invalid base64 or empty output.
#[must_use]
fn decode_powershell_encoded_command(b64: &str) -> Option<String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    if bytes.len() < 2 {
        return None;
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let decoded = String::from_utf16_lossy(&units);
    if decoded.trim().is_empty() {
        None
    } else {
        Some(decoded)
    }
}

// ============================================================================
// Robustness: Binary Content Detection
// ============================================================================

/// Threshold for non-printable character ratio to consider content binary.
const BINARY_THRESHOLD: f32 = 0.30; // 30% non-printable characters

/// Check if content appears to be binary (contains null bytes or high non-printable ratio).
///
/// # Returns
///
/// `Some(SkipReason::BinaryContent)` if the content appears binary, `None` otherwise.
#[must_use]
#[allow(clippy::cast_precision_loss)] // Precision loss acceptable
#[allow(clippy::naive_bytecount)] // Acceptable for bounded content
pub fn check_binary_content(content: &str) -> Option<SkipReason> {
    let bytes = content.as_bytes();
    if bytes.is_empty() {
        return None;
    }

    // Count null bytes (definite binary indicator)
    let null_bytes = bytes.iter().filter(|&&b| b == 0).count();
    if null_bytes > 0 {
        return Some(SkipReason::BinaryContent {
            null_bytes,
            non_printable_ratio: null_bytes as f32 / bytes.len() as f32,
        });
    }

    // A valid UTF-8 string shouldn't be considered binary just because it has non-ASCII.
    // We count actual control characters (excluding whitespace) and U+FFFD (replacement chars).
    let mut suspect_chars = 0;
    let mut total_chars = 0;

    for c in content.chars() {
        total_chars += 1;
        if (c.is_control() && c != '\n' && c != '\r' && c != '\t')
            || c == std::char::REPLACEMENT_CHARACTER
        {
            suspect_chars += 1;
        }
    }

    let ratio = suspect_chars as f32 / total_chars.max(1) as f32;
    if ratio > BINARY_THRESHOLD {
        return Some(SkipReason::BinaryContent {
            null_bytes: 0,
            non_printable_ratio: ratio,
        });
    }

    None
}

#[inline]
fn record_timeout_if_needed(
    start_time: Instant,
    timeout: Duration,
    budget_ms: u64,
    skip_reasons: &mut Vec<SkipReason>,
) -> bool {
    let elapsed = start_time.elapsed();
    if elapsed < timeout {
        return false;
    }

    if !skip_reasons
        .iter()
        .any(|r| matches!(r, SkipReason::Timeout { .. }))
    {
        let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        skip_reasons.push(SkipReason::Timeout {
            elapsed_ms,
            budget_ms,
        });
    }

    true
}

/// Extract heredoc and inline script content from a command.
///
/// This is Tier 2 of the detection pipeline - content extraction with safety bounds.
///
/// # Guarantees
///
/// - Bounded memory usage (never allocate >`max_body_bytes` per heredoc)
/// - Graceful degradation on malformed input (fail-open with warning)
///
/// # Examples
///
/// ```ignore
/// use destructive_command_guard::heredoc::{extract_content, ExtractionLimits, ExtractionResult};
///
/// let result = extract_content(
///     "python3 -c 'import os; os.system(\"rm -rf /\")'",
///     &ExtractionLimits::default()
/// );
///
/// if let ExtractionResult::Extracted(contents) = result {
///     assert_eq!(contents.len(), 1);
///     assert!(contents[0].content.contains("os.system"));
/// }
/// ```
#[must_use]
#[instrument(skip(command, limits), fields(cmd_len = command.len(), timeout_ms = limits.timeout_ms))]
pub fn extract_content(command: &str, limits: &ExtractionLimits) -> ExtractionResult {
    let start_time = Instant::now();
    let timeout = Duration::from_millis(limits.timeout_ms);
    let mut skip_reasons: Vec<SkipReason> = Vec::new();

    // Enforce input size limit
    if command.len() > limits.max_body_bytes {
        warn!(
            actual = command.len(),
            limit = limits.max_body_bytes,
            "tier2_skip: input exceeds size limit"
        );
        skip_reasons.push(SkipReason::ExceededSizeLimit {
            actual: command.len(),
            limit: limits.max_body_bytes,
        });
        return ExtractionResult::Skipped(skip_reasons);
    }

    // Check for binary content (null bytes or high non-printable ratio)
    if let Some(reason) = check_binary_content(command) {
        warn!(?reason, "tier2_skip: binary content detected");
        skip_reasons.push(reason);
        return ExtractionResult::Skipped(skip_reasons);
    }

    let mut extracted: Vec<ExtractedContent> = Vec::new();

    // Enforce time budget (fail open) before doing any further work.
    if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, &mut skip_reasons) {
        return ExtractionResult::Skipped(skip_reasons);
    }

    // Extract inline scripts (-c/-e flags)
    extract_inline_scripts(
        command,
        limits,
        start_time,
        timeout,
        &mut extracted,
        &mut skip_reasons,
    );
    if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, &mut skip_reasons) {
        return if extracted.is_empty() {
            ExtractionResult::Skipped(skip_reasons)
        } else {
            ExtractionResult::Extracted(extracted)
        };
    }

    // Extract Windows inline wrappers (cmd /c|/k, iex/Invoke-Expression, -EncodedCommand)
    extract_windows_inline_scripts(
        command,
        limits,
        start_time,
        timeout,
        &mut extracted,
        &mut skip_reasons,
    );
    if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, &mut skip_reasons) {
        return if extracted.is_empty() {
            ExtractionResult::Skipped(skip_reasons)
        } else {
            ExtractionResult::Extracted(extracted)
        };
    }

    // Extract `mise exec -c/--command` inline shell payloads (#259)
    extract_mise_inline_scripts(
        command,
        limits,
        start_time,
        timeout,
        &mut extracted,
        &mut skip_reasons,
    );
    if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, &mut skip_reasons) {
        return if extracted.is_empty() {
            ExtractionResult::Skipped(skip_reasons)
        } else {
            ExtractionResult::Extracted(extracted)
        };
    }

    // Extract `ssh … destination <command…>` remote payloads (#326)
    extract_ssh_inline_scripts(
        command,
        limits,
        start_time,
        timeout,
        &mut extracted,
        &mut skip_reasons,
    );
    if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, &mut skip_reasons) {
        return if extracted.is_empty() {
            ExtractionResult::Skipped(skip_reasons)
        } else {
            ExtractionResult::Extracted(extracted)
        };
    }

    // Extract here-strings (<<<)
    extract_herestrings(
        command,
        limits,
        start_time,
        timeout,
        &mut extracted,
        &mut skip_reasons,
    );
    if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, &mut skip_reasons) {
        return if extracted.is_empty() {
            ExtractionResult::Skipped(skip_reasons)
        } else {
            ExtractionResult::Extracted(extracted)
        };
    }

    // Extract heredocs (<<, <<-, <<~)
    extract_heredocs(
        command,
        limits,
        start_time,
        timeout,
        &mut extracted,
        &mut skip_reasons,
    );

    // Return based on what we found
    let elapsed_us = start_time.elapsed().as_micros();
    match (extracted.is_empty(), skip_reasons.is_empty()) {
        (true, true) => {
            trace!(elapsed_us, "tier2_complete: no content found");
            ExtractionResult::NoContent
        }
        (true, false) => {
            warn!(
                elapsed_us,
                skip_count = skip_reasons.len(),
                "tier2_complete: skipped"
            );
            ExtractionResult::Skipped(skip_reasons)
        }
        (false, true) => {
            debug!(
                elapsed_us,
                count = extracted.len(),
                "tier2_complete: content extracted"
            );
            ExtractionResult::Extracted(extracted)
        }
        (false, false) => {
            // Partial extraction with some skips - return what we got
            debug!(
                elapsed_us,
                count = extracted.len(),
                skip_count = skip_reasons.len(),
                "tier2_complete: partial extraction with skips"
            );
            ExtractionResult::Extracted(extracted)
        }
    }
}

/// Extract inline scripts from -c/-e flags.
fn extract_inline_scripts(
    command: &str,
    limits: &ExtractionLimits,
    start_time: Instant,
    timeout: Duration,
    extracted: &mut Vec<ExtractedContent>,
    skip_reasons: &mut Vec<SkipReason>,
) {
    if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
        return;
    }
    if extracted.len() >= limits.max_heredocs {
        skip_reasons.push(SkipReason::ExceededHeredocLimit {
            limit: limits.max_heredocs,
        });
        return;
    }

    // Helper to extract from a given regex pattern
    let mut hit_limit = false;
    let mut extract_from_pattern = |pattern: &Regex| {
        for cap in pattern.captures_iter(command) {
            if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
                return;
            }
            if extracted.len() >= limits.max_heredocs {
                hit_limit = true;
                break;
            }

            let cmd_name = cap.get(1).map_or("", |m| m.as_str());
            let flag = cap.get(3).map_or("", |m| m.as_str());
            // Content is in group 4: (1) interpreter, (2) optional "js", (3) flag, (4) content
            let content_match = cap.get(4);
            let content = content_match.map_or("", |m| m.as_str());

            // The regex covers multiple interpreters; validate that the matched flag actually
            // implies inline code for this interpreter (e.g. bash needs -c, perl needs -e/-E).
            // PowerShell host names are case-insensitive on Windows
            // (`powershell`, `PowerShell.exe`, `pwsh`). Computed up front so the
            // branch condition below isn't a block (clippy::blocks_in_conditions). (#125)
            let cmd_lower = cmd_name.to_ascii_lowercase();
            let is_powershell =
                cmd_lower.starts_with("powershell") || cmd_lower.starts_with("pwsh");
            let is_inline_flag = if cmd_name.starts_with("python") {
                flag.contains('c') || flag.contains('e')
            } else if cmd_name.starts_with("ruby") || cmd_name.starts_with("irb") {
                flag.contains('e')
            } else if cmd_name.starts_with("perl") {
                flag.contains('e') || flag.contains('E')
            } else if cmd_name.starts_with("node") {
                flag.contains('e') || flag.contains('p')
            } else if cmd_name.starts_with("php") {
                flag.contains('r')
            } else if cmd_name.starts_with("lua") {
                flag.contains('e')
            } else if is_powershell {
                // The inline-execution flag is `-Command`, which PowerShell accepts as
                // any unambiguous prefix (`-c`, `-co`, `-com`, …), case-insensitively. (#125)
                let f = flag.to_ascii_lowercase();
                f.starts_with("-c")
            } else {
                // sh/bash/zsh/fish
                flag.contains('c')
            };

            if !is_inline_flag {
                continue;
            }

            // Enforce content size limit
            if content.len() > limits.max_body_bytes {
                // Skip but don't add to skip_reasons (would be too noisy)
                continue;
            }

            let full_match = cap.get(0).unwrap();
            extracted.push(ExtractedContent {
                content: content.to_string(),
                language: ScriptLanguage::from_command(cmd_name),
                delimiter: None,
                byte_range: full_match.start()..full_match.end(),
                content_range: content_match.map(|m| m.start()..m.end()),
                quoted: true, // -c/-e content is always in quotes
                heredoc_type: None,
                target_command: Some(cmd_name.to_string()), // -c/-e content is executed by the interpreter
            });
        }
    };

    // Extract from both single-quoted and double-quoted patterns
    extract_from_pattern(&INLINE_SCRIPT_SINGLE_QUOTE);
    extract_from_pattern(&INLINE_SCRIPT_DOUBLE_QUOTE);

    if hit_limit {
        skip_reasons.push(SkipReason::ExceededHeredocLimit {
            limit: limits.max_heredocs,
        });
    }
}

/// Push one extracted Windows inner command (re-evaluated as a shell command).
///
/// Returns `false` if the per-command heredoc/inline limit was hit (caller should
/// stop), `true` to continue. Oversized bodies are skipped quietly (return `true`).
/// Kept as a free function (not a closure) so the per-loop `record_timeout_if_needed`
/// borrows of `skip_reasons` don't conflict with the `extracted`/`skip_reasons`
/// mutable borrows this needs.
fn push_windows_inner(
    extracted: &mut Vec<ExtractedContent>,
    skip_reasons: &mut Vec<SkipReason>,
    limits: &ExtractionLimits,
    content: &str,
    full: std::ops::Range<usize>,
    content_range: Option<std::ops::Range<usize>>,
    target: &str,
) -> bool {
    if extracted.len() >= limits.max_heredocs {
        skip_reasons.push(SkipReason::ExceededHeredocLimit {
            limit: limits.max_heredocs,
        });
        return false;
    }
    if content.len() > limits.max_body_bytes {
        return true; // skip oversize body quietly, keep scanning
    }
    extracted.push(ExtractedContent {
        content: content.to_string(),
        // Re-evaluate the inner command line as a shell command, exactly like the
        // PowerShell `-Command` body is, so windows.* (and core) packs apply to it.
        language: ScriptLanguage::Bash,
        delimiter: None,
        byte_range: full,
        content_range,
        quoted: true,
        heredoc_type: None,
        target_command: Some(target.to_string()),
    });
    true
}

/// Extract Windows-specific inline scripts that wrap an inner command line:
/// `cmd /c "..."` / `cmd /k ...`, `iex` / `Invoke-Expression "..."`, and
/// `powershell -EncodedCommand <base64>` (decoded from base64 UTF-16LE). The inner
/// content is re-evaluated by the full pipeline so a destructive command hidden by
/// any of these wrappers is blocked exactly as the bare form is. Fail-open: a bad
/// base64 payload or a timeout simply yields no extraction.
fn extract_windows_inline_scripts(
    command: &str,
    limits: &ExtractionLimits,
    start_time: Instant,
    timeout: Duration,
    extracted: &mut Vec<ExtractedContent>,
    skip_reasons: &mut Vec<SkipReason>,
) {
    if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
        return;
    }

    // cmd /c | /k  (double-quoted, single-quoted, or unquoted rest-of-line)
    for cap in CMD_INLINE_SCRIPT.captures_iter(command) {
        if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
            return;
        }
        if let Some(m) = cap.get(1).or_else(|| cap.get(2)).or_else(|| cap.get(3)) {
            let full = cap.get(0).expect("group 0 always present");
            if !push_windows_inner(
                extracted,
                skip_reasons,
                limits,
                m.as_str(),
                full.start()..full.end(),
                Some(m.start()..m.end()),
                "cmd",
            ) {
                return;
            }
        }
    }

    // iex / Invoke-Expression "<code>"
    for cap in IEX_INLINE_SCRIPT.captures_iter(command) {
        if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
            return;
        }
        if let Some(m) = cap.get(1).or_else(|| cap.get(2)) {
            let full = cap.get(0).expect("group 0 always present");
            if !push_windows_inner(
                extracted,
                skip_reasons,
                limits,
                m.as_str(),
                full.start()..full.end(),
                Some(m.start()..m.end()),
                "iex",
            ) {
                return;
            }
        }
    }

    // powershell -EncodedCommand <base64>  (decode base64 UTF-16LE, then re-evaluate)
    for cap in POWERSHELL_ENCODED_COMMAND.captures_iter(command) {
        if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
            return;
        }
        let Some(b64) = cap.get(1) else { continue };
        let Some(decoded) = decode_powershell_encoded_command(b64.as_str()) else {
            continue; // fail-open on invalid base64
        };
        let full = cap.get(0).expect("group 0 always present");
        // The decoded text isn't a substring of the original command, so there is
        // no content_range to report.
        if !push_windows_inner(
            extracted,
            skip_reasons,
            limits,
            &decoded,
            full.start()..full.end(),
            None,
            "powershell",
        ) {
            return;
        }
    }
}

/// Byte spans of one `mise exec -c/--command` inline shell payload.
struct MiseInlinePayload {
    /// Raw payload text, one layer of matching surrounding quotes removed.
    content: Range<usize>,
    /// Full `mise … -c <payload>` span, for span attribution.
    full: Range<usize>,
}

/// Extract `mise exec -c/--command` inline shell payloads (#259).
///
/// `mise [GLOBAL FLAGS] exec|x [FLAGS] [TOOL@VERSION]… -c|--command <payload>`
/// hands `<payload>` to a shell, so it is an inline-script wrapper exactly like
/// `sh -c` and must be recursively evaluated. Without this, a quoted payload was
/// span-classified as argv data of an unrecognised consumer and rode through
/// (`mise exec -c "<destructive>"` allowed, while `mise exec -- sh -c "…"` denied).
///
/// `normalize::mise_exec_wrapper_command_index` walks the same grammar for the
/// *wrapper-stripping* path and deliberately bails at `-c`; this walk starts
/// from the same shape but stops **at** the payload and captures it.
///
/// Deviation from the stripper, deliberately in the deny direction: once an
/// unmodeled option is seen the grammar is no longer trustworthy, so the walk
/// keeps scanning for a `-c` payload instead of bailing. Bailing there is the
/// #260 blind-spot mechanism — an attacker only needs one unrecognised flag
/// (`mise exec --no-such-flag -c "<destructive>"`) to disarm the extractor.
/// Fail-open otherwise: no `mise`, no `exec`/`x`, an explicit `--`, or a missing
/// payload simply yields no extraction.
fn extract_mise_inline_scripts(
    command: &str,
    limits: &ExtractionLimits,
    start_time: Instant,
    timeout: Duration,
    extracted: &mut Vec<ExtractedContent>,
    skip_reasons: &mut Vec<SkipReason>,
) {
    if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
        return;
    }
    if !command.contains("mise") {
        return;
    }

    let tokens = crate::normalize::tokenize_for_normalization(command);
    for index in 0..tokens.len() {
        if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
            return;
        }
        let token = &tokens[index];
        if token.kind != crate::normalize::NormalizeTokenKind::Word {
            continue;
        }
        let Some(word) = token.text(command) else {
            continue;
        };
        // Path-qualified spellings (`/usr/bin/mise`, `~/.local/bin/mise.exe`)
        // are the same program.
        let basename = word.rsplit(['/', '\\']).next().unwrap_or(word);
        let basename = basename
            .strip_suffix(".exe")
            .or_else(|| basename.strip_suffix(".EXE"))
            .unwrap_or(basename);
        if basename != "mise" {
            continue;
        }
        for payload in mise_exec_inline_payloads(command, &tokens, index) {
            let Some(content) = command.get(payload.content.clone()) else {
                continue;
            };
            if !push_windows_inner(
                extracted,
                skip_reasons,
                limits,
                content,
                payload.full,
                Some(payload.content),
                "mise",
            ) {
                return;
            }
        }
    }
}

/// Locate every `-c`/`--command` payload of the `mise` invocation whose
/// executable token is at `start`. See [`extract_mise_inline_scripts`] for the
/// grammar and the deliberate deny-direction deviation on unmodeled options.
///
/// All payloads are collected, not just the first: `-c` is a last-wins option,
/// so `mise exec -c 'echo hi' -c '<destructive>'` runs the *second* string, and
/// stopping at the first match would let a benign decoy disarm the extractor.
fn mise_exec_inline_payloads(
    command: &str,
    tokens: &[crate::normalize::NormalizeToken],
    start: usize,
) -> Vec<MiseInlinePayload> {
    let mut payloads = Vec::new();
    mise_collect_inline_payloads(command, tokens, start, &mut payloads);
    payloads
}

fn mise_collect_inline_payloads(
    command: &str,
    tokens: &[crate::normalize::NormalizeToken],
    start: usize,
    payloads: &mut Vec<MiseInlinePayload>,
) -> Option<()> {
    use crate::normalize::{
        NormalizeTokenKind, mise_flag_consumes_nothing, mise_option_takes_separate_value,
    };

    let full_start = tokens.get(start)?.byte_range.start;
    // Grammar certainty: cleared by the first option whose arity dcg does not
    // model. While uncertain, bare words no longer prove the wrapped command
    // has started, so the walk keeps looking for an inline payload.
    let mut grammar_is_modeled = true;
    let mut index = start + 1;

    // Phase 1: global flags, then the subcommand.
    let subcommand = loop {
        let token = tokens.get(index)?;
        if token.kind != NormalizeTokenKind::Word {
            return None;
        }
        // Quoting a flag does not change the argv the program receives, so
        // `mise "exec" "-c" '<payload>'` is the same invocation as the bare
        // spelling and must walk the same grammar.
        let (word, _, _) = dequoted_flag_word(
            token.text(command)?,
            token.byte_range.start,
            token.byte_range.end,
        );
        if matches!(word, "-h" | "--help" | "-V" | "--version") {
            return None;
        }
        if mise_option_takes_separate_value(word) {
            index += 2;
            continue;
        }
        if mise_flag_consumes_nothing(word) {
            index += 1;
            continue;
        }
        if word.starts_with('-') {
            grammar_is_modeled = false;
            index += 1;
            continue;
        }
        break word;
    };
    if subcommand != "exec" && subcommand != "x" {
        return None;
    }
    index += 1;

    // Phase 2: exec flags and TOOL@VERSION specs, up to the payload.
    loop {
        let token = tokens.get(index)?;
        if token.kind != NormalizeTokenKind::Word {
            return None;
        }
        let (word, word_start, word_end) = dequoted_flag_word(
            token.text(command)?,
            token.byte_range.start,
            token.byte_range.end,
        );

        if word == "--" {
            // Everything after `--` is the wrapped command's own argv; a `-c`
            // there belongs to that program, not to mise.
            return None;
        }
        if word == "-c" || word == "--command" {
            let value = tokens.get(index + 1)?;
            if value.kind != NormalizeTokenKind::Word {
                return None;
            }
            let text = command.get(value.byte_range.clone())?;
            payloads.push(MiseInlinePayload {
                content: unquoted_payload_range(text, value.byte_range.start),
                full: full_start..value.byte_range.end,
            });
            index += 2;
            continue;
        }
        // Glued long form `--command=<payload>`. Checked before
        // `mise_flag_consumes_nothing`, which accepts every `--opt=value`.
        if let Some(value) = word.strip_prefix("--command=") {
            let value_start = word_end - value.len();
            payloads.push(MiseInlinePayload {
                content: unquoted_payload_range(value, value_start),
                full: full_start..word_end,
            });
            index += 1;
            continue;
        }
        // Attached short form `-c"<payload>"` / `-c'<payload>'`, mirroring the
        // interpreter inline patterns' attached-quote support.
        if let Some(value) = word.strip_prefix("-c")
            && !value.is_empty()
            && (value.starts_with(['"', '\''])
                || value.starts_with("$'")
                || value.starts_with("$\""))
        {
            payloads.push(MiseInlinePayload {
                content: unquoted_payload_range(value, word_start + 2),
                full: full_start..word_end,
            });
            index += 1;
            continue;
        }
        if matches!(word, "-h" | "--help" | "-V" | "--version") {
            return None;
        }
        if mise_option_takes_separate_value(word) {
            index += 2;
            continue;
        }
        if mise_flag_consumes_nothing(word) {
            index += 1;
            continue;
        }
        if word.starts_with('-') {
            grammar_is_modeled = false;
            index += 1;
            continue;
        }
        if word.contains('@') {
            // TOOL@VERSION spec.
            index += 1;
            continue;
        }
        if grammar_is_modeled {
            // First bare word under a fully modeled grammar: the wrapped
            // command starts here, so there is no mise inline payload.
            return None;
        }
        index += 1;
    }
}

/// Byte range of a payload value at `offset`, with one layer of matching
/// surrounding quotes removed so the range slices the raw inner text (which
/// span mapping requires).
///
/// The Bash quoting introducers `$'…'` (ANSI-C) and `$"…"` (locale-translated)
/// are stripped too: the shell hands `mise exec -c $'<payload>'` exactly the
/// same argv as the plain spelling, and leaving the `$'` on the extracted text
/// makes the recursive evaluation classify the whole payload as a quoted
/// literal — i.e. inert data — which is a false negative.
fn unquoted_payload_range(text: &str, offset: usize) -> Range<usize> {
    let bytes = text.as_bytes();
    let dollar_quoted = text.len() >= 3
        && bytes.first() == Some(&b'$')
        && matches!(
            (bytes.get(1), bytes.last()),
            (Some(b'\''), Some(b'\'')) | (Some(b'"'), Some(b'"'))
        );
    if dollar_quoted {
        return offset + 2..offset + text.len() - 1;
    }
    let quoted = text.len() >= 2
        && matches!(
            (bytes.first(), bytes.last()),
            (Some(b'\''), Some(b'\'')) | (Some(b'"'), Some(b'"'))
        );
    if quoted {
        offset + 1..offset + text.len() - 1
    } else {
        offset..offset + text.len()
    }
}

/// A flag token with one layer of matching surrounding quotes removed, plus the
/// byte range of the returned text.
///
/// Quoting a flag is invisible to the program being launched — `mise exec "-c"
/// '<payload>'` and `mise exec -c '<payload>'` produce identical argv — so the
/// grammar walk must treat them identically. Only whole-token quoting is
/// stripped; partially quoted tokens (`-c"<payload>"`) keep their raw text so
/// the glued-payload handlers still see the quote they key on.
fn dequoted_flag_word(text: &str, start: usize, end: usize) -> (&str, usize, usize) {
    let bytes = text.as_bytes();
    let quoted = text.len() >= 2
        && matches!(
            (bytes.first(), bytes.last()),
            (Some(b'\''), Some(b'\'')) | (Some(b'"'), Some(b'"'))
        );
    if quoted && let Some(inner) = text.get(1..text.len() - 1) {
        return (inner, start + 1, end - 1);
    }
    (text, start, end)
}

/// Byte spans of one `ssh … destination <command…>` remote payload.
struct SshRemotePayload {
    /// Payload text: for a single payload word, one layer of matching
    /// surrounding quotes removed; for multiple words, the raw span from the
    /// first payload byte to the last (per-word quoting left intact, exactly
    /// as the remote shell will see it after the local shell's one decode).
    content: Range<usize>,
    /// Full `ssh … <payload>` span, for span attribution.
    full: Range<usize>,
}

/// ssh short options that consume a value (OpenSSH `getopt` string; the value
/// may be attached, `-p22`, or the following argv word, `-p 22`).
const SSH_VALUE_OPTIONS: &[u8] = b"BbcDEeFIiJLlmOoPpQRSWw";
/// ssh short options that take no value and may be bundled (`-fnT`).
const SSH_FLAG_OPTIONS: &[u8] = b"1246AaCfGgKkMNnqsTtVvXxYy";

enum SshOptionShape {
    /// Every letter is a no-value flag; the token is complete.
    FlagsOnly,
    /// The token ends in a value-taking letter; the NEXT token is its value.
    TakesSeparateValue,
    /// A value-taking letter with the value attached in the same token.
    ValueAttached,
    /// An option dcg does not model (long options, new letters).
    Unknown,
}

/// Classify one leading-dash ssh option token against the modeled OpenSSH
/// grammar. Bundled flags are walked letter by letter: the first value-taking
/// letter either consumes the token's remainder (attached value) or the next
/// argv word (separate value), matching `getopt` semantics.
fn classify_ssh_option(word: &str) -> SshOptionShape {
    let Some(letters) = word.strip_prefix('-') else {
        return SshOptionShape::Unknown;
    };
    if letters.is_empty() || letters.starts_with('-') {
        // Bare `-` or a long option: not part of the modeled grammar (`--` is
        // handled by the caller before classification).
        return SshOptionShape::Unknown;
    }
    let bytes = letters.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if SSH_FLAG_OPTIONS.contains(byte) {
            continue;
        }
        if SSH_VALUE_OPTIONS.contains(byte) {
            return if index + 1 == bytes.len() {
                SshOptionShape::TakesSeparateValue
            } else {
                SshOptionShape::ValueAttached
            };
        }
        return SshOptionShape::Unknown;
    }
    SshOptionShape::FlagsOnly
}

/// Extract the remote command payload of `ssh` invocations (#326).
///
/// `ssh [options] destination [command [argument …]]` concatenates every argv
/// word after the destination with spaces and hands the result to the remote
/// login shell — it is an inline-shell wrapper exactly like `sh -c`, minus the
/// flag. Without this, `ssh host '<destructive>'` was span-classified as argv
/// data of an unrecognised consumer and rode through, while the unquoted
/// spelling was denied by raw pattern matching (#326).
///
/// Fail-open to the status quo, never past it: an unmodeled option (long
/// options, letters newer than the modeled OpenSSH `getopt` string) makes the
/// destination unidentifiable, so the walk extracts nothing and the command
/// keeps exactly today's raw-token visibility. Unlike mise's `-c`, the payload
/// here is positional — misparsing the destination under an unmodeled grammar
/// would extract the wrong text, so bailing is the accuracy-preserving choice
/// (a real ssh also refuses unknown options outright, so nothing executes in
/// that shape anyway).
fn extract_ssh_inline_scripts(
    command: &str,
    limits: &ExtractionLimits,
    start_time: Instant,
    timeout: Duration,
    extracted: &mut Vec<ExtractedContent>,
    skip_reasons: &mut Vec<SkipReason>,
) {
    if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
        return;
    }
    if !command.contains("ssh") && !command.contains("SSH") {
        return;
    }

    let tokens = crate::normalize::tokenize_for_normalization(command);
    for index in 0..tokens.len() {
        if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
            return;
        }
        let token = &tokens[index];
        if token.kind != crate::normalize::NormalizeTokenKind::Word {
            continue;
        }
        let Some(word) = token.text(command) else {
            continue;
        };
        // Path-qualified spellings (`/usr/bin/ssh`, `C:\…\ssh.exe`) are the
        // same program; `ssh-keygen`/`ssh-add`/`autossh` are not.
        let basename = word.rsplit(['/', '\\']).next().unwrap_or(word);
        let basename = basename
            .strip_suffix(".exe")
            .or_else(|| basename.strip_suffix(".EXE"))
            .unwrap_or(basename);
        if !basename.eq_ignore_ascii_case("ssh") {
            continue;
        }
        let Some(payload) = ssh_remote_payload(command, &tokens, index) else {
            continue;
        };
        let Some(content) = command.get(payload.content.clone()) else {
            continue;
        };
        if !push_windows_inner(
            extracted,
            skip_reasons,
            limits,
            content,
            payload.full,
            Some(payload.content),
            "ssh",
        ) {
            return;
        }
    }
}

/// Locate the remote-command payload of the `ssh` invocation whose executable
/// token is at `start`. See [`extract_ssh_inline_scripts`] for the grammar and
/// the deliberate bail on unmodeled options.
fn ssh_remote_payload(
    command: &str,
    tokens: &[crate::normalize::NormalizeToken],
    start: usize,
) -> Option<SshRemotePayload> {
    use crate::normalize::NormalizeTokenKind;

    let full_start = tokens.get(start)?.byte_range.start;
    let mut index = start + 1;
    let mut options_ended = false;

    // Phase 1: options, then the destination.
    loop {
        let token = tokens.get(index)?;
        if token.kind != NormalizeTokenKind::Word {
            // Separator before any destination: an interactive `ssh host` in
            // an earlier segment shape, or plain `ssh` — no payload.
            return None;
        }
        let (word, _, _) = dequoted_flag_word(
            token.text(command)?,
            token.byte_range.start,
            token.byte_range.end,
        );
        if !options_ended && word == "--" {
            options_ended = true;
            index += 1;
            continue;
        }
        if !options_ended && word.len() > 1 && word.starts_with('-') {
            match classify_ssh_option(word) {
                SshOptionShape::FlagsOnly | SshOptionShape::ValueAttached => {
                    index += 1;
                }
                SshOptionShape::TakesSeparateValue => {
                    index += 2;
                }
                SshOptionShape::Unknown => return None,
            }
            continue;
        }
        // First non-option word: the destination.
        index += 1;
        break;
    }

    // Phase 2: the payload is the run of Word tokens after the destination,
    // up to the next shell separator (which belongs to the LOCAL shell).
    let payload_start = index;
    let mut payload_end = index;
    while let Some(token) = tokens.get(payload_end) {
        if token.kind != NormalizeTokenKind::Word {
            break;
        }
        payload_end += 1;
    }
    if payload_end == payload_start {
        // Interactive session: no remote command.
        return None;
    }

    let first = tokens.get(payload_start)?;
    let last = tokens.get(payload_end - 1)?;
    if payload_end - payload_start == 1 {
        // Single payload word: strip one layer of quotes so the recursive
        // evaluation sees the remote command line itself, exactly as the
        // remote shell will.
        let text = command.get(first.byte_range.clone())?;
        return Some(SshRemotePayload {
            content: unquoted_payload_range(text, first.byte_range.start),
            full: full_start..first.byte_range.end,
        });
    }
    Some(SshRemotePayload {
        content: first.byte_range.start..last.byte_range.end,
        full: full_start..last.byte_range.end,
    })
}

/// Extract here-strings (<<<).
fn extract_herestrings(
    command: &str,
    limits: &ExtractionLimits,
    start_time: Instant,
    timeout: Duration,
    extracted: &mut Vec<ExtractedContent>,
    skip_reasons: &mut Vec<SkipReason>,
) {
    if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
        return;
    }
    if extracted.len() >= limits.max_heredocs {
        return; // Already hit limit, don't add another skip reason
    }

    let mut hit_limit = false;

    // Helper to extract from a given pattern (quoted patterns have content in group 1)
    let mut extract_quoted = |pattern: &Regex, is_quoted: bool| {
        for cap in pattern.captures_iter(command) {
            if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
                return;
            }
            if extracted.len() >= limits.max_heredocs {
                hit_limit = true;
                break;
            }

            // Content is in group 1 for all our here-string patterns
            let content_match = cap.get(1);
            let content = content_match.map_or("", |m| m.as_str());

            if content.len() > limits.max_body_bytes {
                continue;
            }

            let full_match = cap.get(0).unwrap();

            // Extract the command that receives the here-string
            let target_cmd = extract_heredoc_target_command(command, full_match.start());

            extracted.push(ExtractedContent {
                content: content.to_string(),
                language: ScriptLanguage::Bash, // Here-strings are bash-specific
                delimiter: None,
                byte_range: full_match.start()..full_match.end(),
                content_range: content_match.map(|m| m.start()..m.end()),
                quoted: is_quoted,
                heredoc_type: Some(HeredocType::HereString),
                target_command: target_cmd,
            });
        }
    };

    // Extract from single-quoted, double-quoted, then unquoted patterns
    // Quoted patterns first to avoid unquoted matching the outer quotes
    extract_quoted(&HERESTRING_SINGLE_QUOTE, true);
    extract_quoted(&HERESTRING_DOUBLE_QUOTE, true);
    extract_quoted(&HERESTRING_UNQUOTED, false);

    if hit_limit {
        skip_reasons.push(SkipReason::ExceededHeredocLimit {
            limit: limits.max_heredocs,
        });
    }
}

/// Extract heredocs (<<, <<-, <<~).
fn extract_heredocs(
    command: &str,
    limits: &ExtractionLimits,
    start_time: Instant,
    timeout: Duration,
    extracted: &mut Vec<ExtractedContent>,
    skip_reasons: &mut Vec<SkipReason>,
) {
    if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
        return;
    }
    if extracted.len() >= limits.max_heredocs {
        return; // Already hit limit
    }

    let mut hit_limit = false;
    for cap in HEREDOC_EXTRACTOR.captures_iter(command) {
        if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
            return;
        }
        if extracted.len() >= limits.max_heredocs {
            hit_limit = true;
            break;
        }

        let operator_variant = cap.get(1).map(|m| m.as_str());

        let (delimiter, quoted) = if let Some(m) = cap.get(2) {
            (m.as_str(), true)
        } else if let Some(m) = cap.get(3) {
            (m.as_str(), true)
        } else if let Some(m) = cap.get(4) {
            (m.as_str(), false)
        } else {
            // Should be unreachable if regex matched
            continue;
        };

        // Determine heredoc type
        let heredoc_type = match operator_variant {
            Some("-") => HeredocType::TabStripped,
            Some("~") => HeredocType::IndentStripped,
            _ => HeredocType::Standard,
        };

        let full_match = cap.get(0).unwrap();
        let mut start_pos = full_match.end();

        // Heredoc bodies start on the next line. If there are trailing tokens after the delimiter
        // on the same line (pipelines, redirects, etc.), skip them so we don't corrupt the
        // extracted body (which can otherwise cause AST parse failures and false negatives).
        start_pos = command[start_pos..]
            .find('\n')
            .map_or(command.len(), |rel| start_pos.saturating_add(rel));

        // Find the terminating delimiter
        match extract_heredoc_body(
            command,
            start_pos,
            delimiter,
            heredoc_type,
            limits,
            start_time,
            timeout,
        ) {
            Ok((content, end_pos, body_start_abs, body_end_abs)) => {
                let (language, _confidence) = ScriptLanguage::detect(command, &content);
                // Extract the command that receives the heredoc
                let target_cmd = extract_heredoc_target_command(command, full_match.start());
                extracted.push(ExtractedContent {
                    content,
                    language,
                    delimiter: Some(delimiter.to_string()),
                    byte_range: full_match.start()..end_pos.min(command.len()),
                    content_range: Some(body_start_abs..body_end_abs),
                    quoted,
                    heredoc_type: Some(heredoc_type),
                    target_command: target_cmd,
                });
            }
            Err(reason) => {
                skip_reasons.push(reason);
                if matches!(skip_reasons.last(), Some(SkipReason::Timeout { .. })) {
                    return;
                }
            }
        }
    }

    if hit_limit {
        skip_reasons.push(SkipReason::ExceededHeredocLimit {
            limit: limits.max_heredocs,
        });
    }
}

/// Extract the command that receives a heredoc or here-string.
///
/// Looks backwards from the heredoc operator position to find the command word.
/// Returns `Some(command_name)` if found, `None` otherwise.
///
/// Examples:
/// - `cat <<EOF` -> Some("cat")
/// - `bash <<EOF` -> Some("bash")
/// - `cat file.txt | tee <<EOF` -> Some("tee")
/// - `$(cat <<EOF)` -> Some("cat")
fn extract_heredoc_target_command(command: &str, heredoc_start: usize) -> Option<String> {
    extract_heredoc_target_token(command, heredoc_start).map(|target| {
        target
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(target.as_str())
            .to_string()
    })
}

/// Extract the lexical command token that owns a heredoc, preserving an
/// explicit path. Most callers need only the basename, but shell-name override
/// analysis must distinguish a bare `cat` (subject to function/alias lookup)
/// from `/bin/cat` (not subject to shell name lookup).
fn extract_heredoc_target_token(command: &str, heredoc_start: usize) -> Option<String> {
    extract_heredoc_target_resolution(command, heredoc_start).map(|(target, _wrapped)| target)
}

/// Resolve the lexical heredoc target while retaining whether the owning
/// simple command used a shell/external wrapper before that target. Wrapper
/// resolution is mutable shell state, so the masking proof must not erase it.
fn extract_heredoc_target_resolution(
    command: &str,
    heredoc_start: usize,
) -> Option<(String, bool)> {
    if heredoc_start == 0 {
        return None;
    }

    // The heredoc operator binds to the simple command on its OWN physical line,
    // so only that line can own this heredoc. Bounding here is a soundness fix:
    // `tokenize_backwards` stops at `| ; & $ ( )` but NOT at newlines, so an
    // unbounded scan resolves the target from an EARLIER line — e.g.
    // `cat f\nbash <<EOF\nrm -rf /\nEOF` would resolve the target as `cat` (a data
    // sink) and mask the executing `bash` body: a false negative. Limiting the
    // scan to the current line risks only a false positive, never a false
    // negative (the conservative direction for a security guard).
    let line_start = command[..heredoc_start]
        .rfind(['\n', '\r'])
        .map_or(0, |i| i + 1);
    let before = &command[line_start..heredoc_start];

    // Trim trailing whitespace before the heredoc operator
    let trimmed = before.trim_end();
    if trimmed.is_empty() {
        return None;
    }

    // Parse tokens backwards, then walk them in original order so we identify
    // the command that owns the heredoc rather than the last argument before
    // the operator.
    let tokens = tokenize_backwards(trimmed);
    let mut wrapper_seen = false;

    for token in tokens.iter().rev() {
        if is_shell_env_assignment(token) {
            continue;
        }

        // Skip flags
        if token.starts_with('-') {
            continue;
        }

        // Skip common shell wrappers until we reach the actual target command.
        if SHELL_WRAPPER_COMMANDS.contains(&token.as_str()) {
            wrapper_seen = true;
            continue;
        }

        // Skip quoted strings (arguments like '{print $1}' or "hello world")
        if (token.starts_with('\'') && token.ends_with('\''))
            || (token.starts_with('"') && token.ends_with('"'))
        {
            continue;
        }

        // Skip if this looks like a file path argument
        if token.contains('/') {
            let basename = token.rsplit('/').next().unwrap_or(token);

            // Check if this looks like a command path (/bin/cat, /usr/bin/bash)
            // vs a file argument (/tmp/file, /path/to/data)
            let is_known_command = NON_EXECUTING_HEREDOC_COMMANDS.contains(&basename)
                || [
                    "bash", "sh", "zsh", "fish", "ksh", "dash", "python", "perl", "ruby", "node",
                ]
                .contains(&basename);

            // Command paths are typically in standard locations
            let looks_like_command_path = token.starts_with("/bin/")
                || token.starts_with("/usr/bin/")
                || token.starts_with("/usr/local/bin/")
                || token.starts_with("/sbin/")
                || token.starts_with("/usr/sbin/")
                || is_known_command;

            if !looks_like_command_path {
                // Doesn't look like a command path, skip it
                continue;
            }

            return Some((token.clone(), wrapper_seen));
        }

        // Skip if this looks like a file with extension
        let has_extension = token.contains('.') && !token.starts_with('.');
        let is_known_command = NON_EXECUTING_HEREDOC_COMMANDS.contains(&token.as_str())
            || [
                "bash", "sh", "zsh", "fish", "ksh", "dash", "python", "perl", "ruby", "node",
            ]
            .contains(&token.as_str());
        if has_extension && !is_known_command {
            continue;
        }

        return Some((token.clone(), wrapper_seen));
    }

    None
}

fn is_shell_env_assignment(token: &str) -> bool {
    shell_assignment_name(token).is_some()
}

fn shell_assignment_name(token: &str) -> Option<&str> {
    let (raw_name, _value) = token.split_once('=')?;
    let name = raw_name.strip_suffix('+').unwrap_or(raw_name);
    (!name.is_empty()
        && name.bytes().enumerate().all(|(idx, byte)| match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => true,
            b'0'..=b'9' => idx > 0,
            _ => false,
        }))
    .then_some(name)
}

/// Tokenize a command string backwards, respecting quotes.
/// Returns tokens in reverse order (last token first).
///
/// Note: This function does not handle escaped quotes inside double-quoted strings
/// (e.g., `"foo\"bar"`). In such cases, tokenization may be incorrect. This is acceptable
/// because the failure mode is safe - we won't find the target command and thus won't
/// mask the heredoc content, which is the conservative choice for security.
fn tokenize_backwards(s: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let bytes = s.as_bytes();
    let mut i = s.len();

    while i > 0 {
        // Skip trailing whitespace
        while i > 0 && bytes[i - 1].is_ascii_whitespace() {
            i -= 1;
        }
        if i == 0 {
            break;
        }

        let end = i;

        // Check for quoted string
        if bytes[i - 1] == b'\'' || bytes[i - 1] == b'"' {
            let quote = bytes[i - 1];
            i -= 1;
            // Find matching opening quote
            while i > 0 && bytes[i - 1] != quote {
                i -= 1;
            }
            i = i.saturating_sub(1); // Skip opening quote if present
            tokens.push(s[i..end].to_string());
            continue;
        }

        // Check for command separator (|, ;, &, $, ()
        if matches!(bytes[i - 1], b'|' | b';' | b'&' | b'$' | b'(' | b')') {
            // Stop parsing - we've reached a command boundary
            break;
        }

        // Regular word - scan backwards to whitespace or separator
        while i > 0 {
            let c = bytes[i - 1];
            if c.is_ascii_whitespace() || matches!(c, b'|' | b';' | b'&' | b'$' | b'(' | b')') {
                break;
            }
            i -= 1;
        }

        if i < end {
            tokens.push(s[i..end].to_string());
        }
    }

    tokens
}

/// Commands that do NOT execute their stdin/heredoc content as code.
/// Heredocs passed to these commands are DATA, not executable scripts.
const NON_EXECUTING_HEREDOC_COMMANDS: &[&str] = &[
    // Text output commands
    "cat",
    "tee",
    "echo",
    "printf",
    // File writing/appending
    "dd",
    // Text processing (read stdin, output transformed text)
    "head",
    "tail",
    "grep",
    "egrep",
    "fgrep",
    "sed",
    "awk",
    "cut",
    "sort",
    "uniq",
    "tr",
    "wc",
    "rev",
    "nl",
    "fold",
    "fmt",
    "expand",
    "unexpand",
    "column",
    "paste",
    "join",
    // Encoding/compression (transform data, don't execute)
    "base64",
    "xxd",
    "od",
    "hexdump",
    "gzip",
    "gunzip",
    "bzip2",
    "bunzip2",
    "xz",
    "lzma",
    "zcat",
    "bzcat",
    "xzcat",
    // Network (send data, don't execute)
    "nc",
    "netcat",
    "curl",
    "wget",
    // Checksum/hash
    "md5sum",
    "sha1sum",
    "sha256sum",
    "sha512sum",
    "cksum",
    // Diff/comparison
    "diff",
    "cmp",
    "comm",
    // Mail (compose message body)
    "mail",
    "sendmail",
    // Variable assignment (read into variable, don't execute)
    "read",
];

/// No-op builtins that discard their stdin and never execute it: `:`, `true`,
/// `false`. `: <<'EOF' … EOF` and `true <<'EOF' … EOF` are the canonical shell
/// "block comment" idiom, so destructive-looking prose in the body is a false
/// positive (#181).
///
/// Unlike the unconditional [`NON_EXECUTING_HEREDOC_COMMANDS`] sinks, these are
/// masked *only when the AST proves the heredoc delimiter is quoted. A quoted delimiter suppresses all shell
/// expansion, guaranteeing the body is inert literal data. With an *unquoted*
/// delimiter the body still undergoes command substitution — `true <<EOF` /
/// `$(rm -rf …)` / `EOF` really runs the deletion — so those must keep flowing
/// through pack matching (never a false negative).
const NOOP_STDIN_DISCARDING_COMMANDS: &[&str] = &[":", "true", "false"];

#[must_use]
fn is_noop_stdin_discarding_command(cmd: &str) -> bool {
    let cmd_name = cmd.rsplit('/').next().unwrap_or(cmd);
    NOOP_STDIN_DISCARDING_COMMANDS.contains(&cmd_name)
}

/// Return whether a nominal stdin-data sink can be shadowed by shell state
/// visible before this redirection. A function or alias named `cat`, `tee`,
/// etc. may execute its stdin, and `eval`/`source` can install such a binding
/// without exposing it to static inspection. Masking is therefore sound only
/// when the command name still resolves to the documented sink. The exact
/// normalized `/bin/<name>` and `/usr/bin/<name>` OS utility paths bypass shell
/// name lookup; arbitrary absolute or relative paths carry no such guarantee.
pub(crate) fn stdin_data_sink_may_be_overridden(
    command: &str,
    redirection_start: usize,
    target_command: &str,
) -> bool {
    let target = target_command
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(target_command)
        .trim_end_matches(".exe");
    let Some((lexical_target, wrapper_seen)) =
        extract_heredoc_target_resolution(command, redirection_start)
    else {
        return true;
    };
    // `sudo`, `env`, `nohup`, `command`, and `builtin` have materially
    // different lookup and execution rules, and every one can itself be a
    // function/alias or PATH-selected executable. Skipping such a token and
    // proving only its final argument is unsound. Preserve the heredoc body for
    // the evaluator instead of attempting a partial wrapper proof.
    if wrapper_seen {
        return true;
    }
    if lexical_target.contains(['/', '\\']) {
        // Basename classification alone is not a proof about an arbitrary
        // executable: `./cat` and `/tmp/cat` may run their stdin as shell. Only
        // the two normalized OS utility paths retain the documented data-sink
        // contract; every other path-qualified token fails closed.
        return !is_trusted_os_data_sink_path(&lexical_target, target);
    }
    if std::env::var_os(format!("BASH_FUNC_{target}%%")).is_some() {
        return true;
    }

    let Some(prefix) = command.get(..redirection_start) else {
        return true;
    };
    let ast = AstGrep::new(prefix, SupportLang::Bash);
    let mut overridden = false;
    let mut parse_error = false;
    find_visible_shell_name_override(ast.root(), target, &mut overridden, &mut parse_error);
    if overridden && !parse_error {
        return true;
    }
    if !parse_error {
        return false;
    }
    // The prefix cut can land mid-construct: a heredoc inside an unclosed
    // command substitution (`gh api -f body="$(cat <<'EOF'` …, #357) leaves
    // the prefix unparsable even though the complete command is perfectly
    // well-formed shell. Re-run the override scan over the WHOLE command,
    // which sees strictly more source than the prefix did. This stays sound:
    // an override nested inside a sibling command substitution runs in a
    // subshell and cannot rebind the receiver's name in the shell that feeds
    // this heredoc, while top-level assignments, function definitions, and
    // mutator commands are all top-level nodes the walker still visits —
    // including ones after the operator, which only adds conservatism. A
    // whole-command parse error keeps the fail-closed answer.
    let ast = AstGrep::new(command, SupportLang::Bash);
    let mut overridden = false;
    let mut parse_error = false;
    find_shell_name_override_deep(ast.root(), target, &mut overridden, &mut parse_error);
    overridden || parse_error
}

/// The whole-command retry walker for [`stdin_data_sink_may_be_overridden`].
///
/// Identical to [`find_visible_shell_name_override`] except that it keeps
/// descending *into* command nodes instead of stopping at each resolved simple
/// command. The prefix walker may stop there because everything nested deeper
/// in the prefix runs before the heredoc's own command; the whole-command walk
/// cannot, because an override *inside the same command substitution* as the
/// receiver (`foo "$(cat(){ bash -s; }; cat <<'EOF' …)"`) runs in the very
/// subshell that feeds the heredoc. Descending everywhere also re-flags the
/// temporary-env shapes (`PATH=/tmp printf …`) the prefix walker deliberately
/// tolerates — acceptable, since this path only ever runs where the old
/// behavior was "never mask", so every extra flag is mere conservatism.
#[allow(clippy::needless_pass_by_value)]
fn find_shell_name_override_deep<D: ast_grep_core::Doc>(
    node: ast_grep_core::Node<'_, D>,
    target: &str,
    overridden: &mut bool,
    parse_error: &mut bool,
) {
    if *overridden || *parse_error {
        return;
    }
    match node.kind().as_ref() {
        "ERROR" => {
            *parse_error = true;
            return;
        }
        "function_definition" => {
            let Some(name) = node.field("name") else {
                *overridden = true;
                return;
            };
            let name = name.text();
            if name.as_ref() == target || !is_static_shell_name(name.as_ref()) {
                *overridden = true;
                return;
            }
        }
        "variable_assignment" => {
            let text = node.text();
            if shell_assignment_name(text.as_ref()) == Some("PATH") {
                *overridden = true;
                return;
            }
        }
        "command" => {
            let text = node.text();
            match shell_words::split(text.as_ref()) {
                Ok(tokens) => {
                    if shell_command_may_override_name(&tokens, target) {
                        *overridden = true;
                        return;
                    }
                    // Unlike the prefix walker, fall through and keep
                    // descending: nested substitutions share fate with the
                    // heredoc receiver when they enclose it.
                }
                Err(_) => {
                    *parse_error = true;
                    *overridden = true;
                    return;
                }
            }
        }
        _ => {}
    }
    for child in node.children() {
        find_shell_name_override_deep(child, target, overridden, parse_error);
    }
}

#[must_use]
fn is_trusted_os_data_sink_path(lexical_target: &str, basename: &str) -> bool {
    lexical_target
        .strip_prefix("/bin/")
        .is_some_and(|name| name == basename)
        || lexical_target
            .strip_prefix("/usr/bin/")
            .is_some_and(|name| name == basename)
}

#[allow(clippy::needless_pass_by_value)]
fn find_visible_shell_name_override<D: ast_grep_core::Doc>(
    node: ast_grep_core::Node<'_, D>,
    target: &str,
    overridden: &mut bool,
    parse_error: &mut bool,
) {
    if *overridden || *parse_error {
        return;
    }
    match node.kind().as_ref() {
        "ERROR" => {
            *parse_error = true;
            return;
        }
        "function_definition" => {
            let Some(name) = node.field("name") else {
                // A function definition whose binding cannot be resolved is
                // exactly the case where proving a later bare sink is unsafe.
                *overridden = true;
                return;
            };
            let name = name.text();
            if name.as_ref() == target || !is_static_shell_name(name.as_ref()) {
                *overridden = true;
                return;
            }
            // Keep descending into a differently named function body. A later
            // invocation can make an `eval`/`source` inside it mutate the
            // parent shell, and proving the complete shell call graph here
            // would be less reliable than conservatively retaining the body.
        }
        "variable_assignment" => {
            let text = node.text();
            if shell_assignment_name(text.as_ref()) == Some("PATH") {
                *overridden = true;
                return;
            }
        }
        "command" => {
            let text = node.text();
            match shell_words::split(text.as_ref()) {
                Ok(tokens) => {
                    if shell_command_may_override_name(&tokens, target) {
                        *overridden = true;
                        return;
                    }
                    // The complete simple command was resolved above. Its
                    // assignment children are temporary environment state
                    // unless the command itself is a modeled mutator; do not
                    // reclassify `PATH=/tmp printf ...` as persistent state.
                    return;
                }
                Err(_) => {
                    // AST-valid shell that the secondary word splitter cannot
                    // resolve must never establish a data-only proof.
                    *parse_error = true;
                    *overridden = true;
                    return;
                }
            }
        }
        _ => {}
    }
    for child in node.children() {
        find_visible_shell_name_override(child, target, overridden, parse_error);
    }
}

#[must_use]
fn is_static_shell_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => true,
            b'0'..=b'9' => index > 0,
            _ => false,
        })
}

#[must_use]
fn shell_word_has_runtime_expansion(word: &str) -> bool {
    word.bytes()
        .any(|byte| matches!(byte, b'$' | b'`' | b'*' | b'?' | b'['))
}

#[must_use]
fn shell_word_assigns_path(word: &str) -> bool {
    shell_assignment_name(word) == Some("PATH")
}

/// Resolve the command word after assignment prefixes and the two shell
/// builtins that can explicitly dispatch another builtin. Query-only
/// `command -v/-V` and `builtin -p` forms do not execute the following word.
fn effective_shell_command(tokens: &[String]) -> Option<(usize, &str)> {
    let mut index = tokens
        .iter()
        .position(|word| !is_shell_env_assignment(word))?;

    match tokens[index].as_str() {
        "command" => {
            index += 1;
            while let Some(option) = tokens.get(index).map(String::as_str) {
                match option {
                    "-v" | "-V" => return None,
                    "-p" | "--" => index += 1,
                    _ => break,
                }
            }
        }
        "builtin" => {
            index += 1;
            if tokens.get(index).is_some_and(|option| option == "-p") {
                return None;
            }
            if tokens.get(index).is_some_and(|option| option == "--") {
                index += 1;
            }
        }
        _ => {}
    }

    tokens.get(index).map(|word| (index, word.as_str()))
}

#[must_use]
fn alias_command_may_override_name(arguments: &[String], target: &str) -> bool {
    arguments.iter().any(|argument| {
        if matches!(argument.as_str(), "--" | "-p") {
            return false;
        }
        if let Some((name, _value)) = argument.split_once('=') {
            return name == target || !is_static_shell_name(name);
        }

        // A static operand merely asks `alias` to print that binding. A word
        // containing expansion or globbing can become `target=value` only at
        // runtime, so its mutation target is unresolved and must fail closed.
        shell_word_has_runtime_expansion(argument)
    })
}

#[must_use]
fn assignment_builtin_may_override_path(arguments: &[String]) -> bool {
    arguments.iter().any(|argument| {
        if argument == "--" || argument.starts_with('-') {
            return false;
        }
        shell_word_assigns_path(argument) || shell_word_has_runtime_expansion(argument)
    })
}

#[must_use]
fn env_command_may_override_name(
    arguments: &[String],
    target: &str,
    mut path_resolution_changed: bool,
) -> bool {
    if !arguments.iter().any(|argument| argument == target) {
        // The target extractor found a different simple command; this `env`
        // invocation belongs to earlier shell state and cannot persistently
        // alter PATH in the parent shell.
        return false;
    }
    let mut index = 0usize;
    while let Some(argument) = arguments.get(index).map(String::as_str) {
        if shell_word_assigns_path(argument) {
            path_resolution_changed = true;
            index += 1;
            continue;
        }
        if is_shell_env_assignment(argument) {
            index += 1;
            continue;
        }
        match argument {
            "--" => {
                index += 1;
                break;
            }
            "-i" | "--ignore-environment" => {
                path_resolution_changed = true;
                index += 1;
            }
            "-u" | "--unset" => {
                let Some(name) = arguments.get(index + 1) else {
                    return false;
                };
                if name == "PATH" || shell_word_has_runtime_expansion(name) {
                    path_resolution_changed = true;
                }
                index += 2;
            }
            "-C" | "--chdir" => {
                if arguments.get(index + 1).is_none() {
                    return false;
                }
                index += 2;
            }
            _ if argument.starts_with("--unset=") => {
                let name = argument.trim_start_matches("--unset=");
                if name == "PATH" || shell_word_has_runtime_expansion(name) {
                    path_resolution_changed = true;
                }
                index += 1;
            }
            _ if argument.starts_with('-') => {
                // Unknown env option arity makes the command position
                // unresolved. The target extractor nevertheless classified a
                // bare data sink, so retaining the body is the safe outcome.
                return arguments[index + 1..]
                    .iter()
                    .any(|word| word == target || shell_word_has_runtime_expansion(word));
            }
            _ if shell_word_has_runtime_expansion(argument) => return true,
            _ => break,
        }
    }

    path_resolution_changed && index < arguments.len()
}

#[must_use]
fn hash_command_may_override_name(arguments: &[String], target: &str) -> bool {
    let Some(option_index) = arguments
        .iter()
        .position(|argument| argument == "-p" || argument.starts_with("-p"))
    else {
        return false;
    };
    let path_is_attached = arguments[option_index].len() > 2;
    let name_index = option_index + usize::from(!path_is_attached) + 1;
    arguments
        .get(name_index)
        .is_none_or(|name| name == target || shell_word_has_runtime_expansion(name))
}

#[must_use]
fn enable_command_may_override_name(arguments: &[String], target: &str) -> bool {
    let Some(option_index) = arguments
        .iter()
        .position(|argument| argument == "-f" || argument.starts_with("-f"))
    else {
        return false;
    };
    let library_is_attached = arguments[option_index].len() > 2;
    let name_index = option_index + usize::from(!library_is_attached) + 1;
    arguments
        .get(name_index)
        .is_none_or(|name| name == target || shell_word_has_runtime_expansion(name))
}

#[must_use]
fn shell_command_may_override_name(tokens: &[String], target: &str) -> bool {
    if tokens.iter().all(|word| is_shell_env_assignment(word))
        && tokens.iter().any(|word| shell_word_assigns_path(word))
    {
        return true;
    }
    let Some((command_index, command)) = effective_shell_command(tokens) else {
        return false;
    };
    let leading_path_mutation = tokens[..command_index]
        .iter()
        .any(|word| shell_word_assigns_path(word));
    if leading_path_mutation && command == target {
        return true;
    }
    match command {
        // These execute shell text from an opaque runtime source. Even a source
        // file whose current contents appear harmless may be replaced between
        // inspection and execution, so bare-name masking cannot remain sound.
        "eval" | "source" | "." => true,
        "alias" => alias_command_may_override_name(&tokens[command_index + 1..], target),
        "export" | "declare" | "typeset" | "local" | "readonly" => {
            assignment_builtin_may_override_path(&tokens[command_index + 1..])
        }
        "unset" => tokens[command_index + 1..]
            .iter()
            .any(|name| name == "PATH" || shell_word_has_runtime_expansion(name)),
        "env" => env_command_may_override_name(
            &tokens[command_index + 1..],
            target,
            leading_path_mutation,
        ),
        "hash" => hash_command_may_override_name(&tokens[command_index + 1..], target),
        "enable" => enable_command_may_override_name(&tokens[command_index + 1..], target),
        _ => false,
    }
}

const SHELL_WRAPPER_COMMANDS: &[&str] = &["sudo", "env", "command", "builtin", "nohup"];

/// Check if a command executes its heredoc/stdin content as code.
///
/// Returns `true` if the command is known to NOT execute its input,
/// meaning heredoc content passed to it is DATA, not CODE.
#[must_use]
pub fn is_non_executing_heredoc_command(cmd: &str) -> bool {
    // Normalize: strip path prefix if present
    let cmd_name = cmd.rsplit('/').next().unwrap_or(cmd);
    NON_EXECUTING_HEREDOC_COMMANDS.contains(&cmd_name)
}

/// Check if a heredoc target is a non-shell interpreter that reads its *program*
/// from the heredoc body (e.g. `python3 - <<PY`, `node - <<JS`, `ruby <<RB`).
///
/// For these targets the body is source code in a concrete, AST-supported
/// language (Python/JS/TS/Ruby/Perl/PHP/Go) — NOT shell. The language-aware
/// heredoc pipeline (`evaluate_heredoc` + `AstMatcher`) is the *authoritative*
/// check for that body: it blocks executing sinks (`os.system`,
/// `subprocess.*`, `child_process.exec*`, Ruby/Perl `system`/backticks, …) while
/// treating destructive tokens inside inert string/comment literals as harmless.
///
/// Re-scanning that same source as *raw shell* (Step 7 of the evaluator) is
/// meaningless and only produces false positives such as
/// `print("rm -rf build")` tripping `core.filesystem` (#136). So callers mask
/// these bodies out of the raw-shell rescan, exactly like `cat`/`tee` data.
///
/// **Shell interpreters are deliberately excluded.** `bash`/`sh`/`zsh`/`fish`
/// (and PowerShell, which maps to [`ScriptLanguage::Bash`]) read *shell* from
/// stdin; their bodies must keep flowing through the raw-shell pack scan and the
/// recursive shell analysis, so a real `bash <<SH … rm -rf /etc … SH` still
/// blocks. Returning `false` here is the fail-safe (never mask shell).
#[must_use]
pub fn is_interpreter_source_heredoc_command(cmd: &str) -> bool {
    let cmd_name = cmd.rsplit('/').next().unwrap_or(cmd);
    match ScriptLanguage::from_command(cmd_name) {
        // #136 REVERTED: NO interpreter-stdin language is masked any more.
        //
        // Masking a body so an inert string literal like `print("rm -rf x")` is
        // allowed inherently removes that body from the raw-shell rescan — the
        // only layer that guarantees ZERO false negatives. No regex/AST heuristic
        // can soundly tell an inert literal from a destructive one that reaches an
        // exec sink via variable indirection (`c = "rm -rf /etc"; os.system(c)`),
        // aliasing (`f = exec; f("rm -rf /etc")`), backtick/template literals
        // (``execSync(`rm -rf /etc`)``), or an opaque imported sink — all of which
        // execute REAL deletions and were ALLOWED while masking was active. That
        // violates dcg's prime invariant (false positives are acceptable, false
        // negatives are NOT). Distinguishing those cases needs true taint
        // analysis, which is out of scope for this scanner, so every interpreter
        // body (`python3 -`, `node -`, `ruby -`, …) now keeps flowing through the
        // conservative raw-shell scan. The independent `cat`/`tee` data-sink
        // masking (`is_non_executing_heredoc_command`) is unaffected — those
        // targets genuinely do not execute their stdin.
        ScriptLanguage::Python
        | ScriptLanguage::JavaScript
        | ScriptLanguage::TypeScript
        | ScriptLanguage::Ruby
        | ScriptLanguage::Bash
        | ScriptLanguage::Perl
        | ScriptLanguage::Php
        | ScriptLanguage::Go
        | ScriptLanguage::Unknown => false,
    }
}

/// Whether a heredoc target name provably does NOT execute its stdin as shell.
///
/// True only for a concrete non-shell interpreter reading its program from the
/// body (`python`/`python3`, `node`/`nodejs`, `deno`/`bun`, `ruby`/`irb`,
/// `perl`, `php`, `go`), path basenames included.
///
/// [`ScriptLanguage::Bash`] — which covers `sh`/`bash`/`zsh`/`fish` and
/// PowerShell — is deliberately excluded because those receivers execute their
/// stdin as shell, and so is [`ScriptLanguage::Unknown`], because an
/// unrecognized name (`dash`, `ksh`, `busybox`, a wrapper script) may well be
/// a shell. `false` is the fail-safe answer in every uncertain case: the body
/// simply keeps its conservative treatment.
///
/// This function makes no claim that the body is *safe* — only that the outer
/// shell hands it to a non-shell program. Its sole consumer is
/// [`range_is_inert_interpreter_stdin`].
#[must_use]
pub fn is_non_shell_interpreter_stdin_command(cmd: &str) -> bool {
    let cmd_name = cmd.rsplit(['/', '\\']).next().unwrap_or(cmd);
    matches!(
        ScriptLanguage::from_command(cmd_name),
        ScriptLanguage::Python
            | ScriptLanguage::JavaScript
            | ScriptLanguage::TypeScript
            | ScriptLanguage::Ruby
            | ScriptLanguage::Perl
            | ScriptLanguage::Php
            | ScriptLanguage::Go
    )
}

/// True when `range` (byte offsets into `command`) lies entirely inside a
/// heredoc body that no shell will ever expand or execute:
///
/// 1. the delimiter is **quoted** (`<<'EOF'`, `<<"EOF"`, `<<E\OF`), so POSIX
///    guarantees the *outer* shell performs no parameter expansion, command
///    substitution, or arithmetic expansion on the body, and
/// 2. the receiver is a proven non-shell interpreter
///    ([`is_non_shell_interpreter_stdin_command`]) whose name the visible
///    shell state cannot have rebound
///    ([`stdin_data_sink_may_be_overridden`]), so the *inner* program does
///    not run the body as shell either.
///
/// Under those two conditions the bytes in `range` are handed to the
/// interpreter verbatim; no shell anywhere sees them as shell syntax. That is
/// the whole claim — the body is still interpreter source and deliberately
/// keeps flowing through the conservative raw-shell rescan (#136/#278);
/// nothing here masks it. The predicate exists to withdraw findings whose
/// entire evidence IS outer-shell syntax (an unquoted `$`/backtick reaching
/// git's argv for `core.git:branch-dynamic-token`, a `>` read as an
/// outer-shell redirect for the `core.filesystem` truncate rules — #357,
/// #363).
///
/// Fail-safe in every ambiguous direction: an empty/inverted range, an
/// unparsable command, a here-string, an unquoted delimiter, an unknown or
/// wrapper-obscured receiver, and a range that leaks past either body
/// boundary all return `false`.
#[must_use]
pub(crate) fn range_is_inert_interpreter_stdin(command: &str, range: &Range<usize>) -> bool {
    if range.start >= range.end || !command.contains("<<") {
        return false;
    }
    // Only AST-proven heredoc operators qualify: raw `<<` bytes inside quotes
    // or comments must never be able to declare part of the command inert.
    let Some(heredocs) = active_heredocs(command) else {
        return false;
    };
    heredocs.iter().any(|heredoc| {
        let ActiveHeredocBody::Heredoc {
            body_start,
            body_end,
            delimiter_quoted,
        } = heredoc.body
        else {
            return false;
        };
        if !delimiter_quoted || range.start < body_start || range.end > body_end {
            return false;
        }
        let Some(target) = extract_heredoc_target_command(command, heredoc.operator_start) else {
            return false;
        };
        if !is_non_shell_interpreter_stdin_command(&target) {
            return false;
        }
        !stdin_data_sink_may_be_overridden(command, heredoc.operator_start, &target)
    })
}

/// Check whether the command owning the heredoc at `heredoc_start` is a `git`
/// built-in invocation that reads the heredoc body as DATA from stdin — a
/// commit/tag/note *message* (`-F -`, `-F-`, `--file=-`, `--file -`) or the
/// documented `hash-object`/`update-index` `--stdin` input.
///
/// For these targets git consumes stdin as data (a commit message, blob content,
/// an index path list, …) and NEVER executes it as shell, so the body is masked
/// out of the raw-shell rescan exactly like `cat`/`tee` (#109). Without this, a
/// commit message that merely contains the words "restore" or "reset --hard"
/// trips the `core.git:*` rules (#136) even though nothing in that message is
/// ever executed.
///
/// Soundness (zero false negatives): this is an *additional* allow-to-mask gate,
/// so the fail-safe direction is correct — when the parse is ambiguous it returns
/// `false` and the body keeps flowing through the scan (a false positive at
/// worst). It requires program `git` plus an EXPLICIT stdin sentinel; it does not
/// fire on a bare `git commit <<EOF` (no `-F -`), an unknown/aliased subcommand,
/// or configuration-bearing `-c`/`--config-env`/`GIT_CONFIG*` input. Only the
/// heredoc body is masked by the caller: the `git …` line itself and everything
/// after the terminator are still scanned, so a real destructive command chained
/// after the heredoc still blocks. `--stdin-paths` is deliberately NOT matched.
/// The scan is bounded to the heredoc's own physical line (see below) and
/// `tokenize_backwards` additionally stops at shell separators (`| ; & $ ( )`),
/// so it never reads tokens across a command boundary; quoted args (e.g. a
/// `-m "…-F -…"` message) are single tokens and cannot be mistaken for real flags.
fn is_git_stdin_data_sink(command: &str, heredoc_start: usize) -> bool {
    if heredoc_start == 0 {
        return false;
    }
    // A heredoc operator binds to the simple command on its OWN physical line, so
    // only that line can own this heredoc. Bounding the scan to the current line
    // is essential for soundness: `tokenize_backwards` stops at `| ; & $ ( )` but
    // NOT at newlines, so without this a `git … -F -` on an EARLIER line would
    // leak its stdin sentinel onto a later, genuinely-executing heredoc and mask
    // its body — e.g. `git commit -F - f\nbash <<EOF\nrm -rf /\nEOF` would wrongly
    // be allowed (a false negative). Trimming to the last line risks only a false
    // positive (an exotic backslash-continued invocation no longer matched),
    // never a false negative.
    let prefix = &command[..heredoc_start];
    let line_start = prefix.rfind(['\n', '\r']).map_or(0, |i| i + 1);
    let before = prefix[line_start..].trim_end();
    if before.is_empty() {
        return false;
    }

    // Tokens of the current command in original (left-to-right) order.
    let mut tokens = tokenize_backwards(before);
    tokens.reverse();

    // Resolve the program word, skipping env-assignments and shell wrappers
    // (sudo/env/command/builtin/nohup) the same way target extraction does.
    let mut idx = 0;
    while let Some(t) = tokens.get(idx) {
        if is_shell_env_assignment(t) {
            // Environment-provided Git configuration can define shell aliases.
            // If any such state is visible, do not prove the heredoc a data
            // sink; leaving the body scannable is the safe direction.
            if t.split_once('=')
                .is_some_and(|(name, _)| name.starts_with("GIT_CONFIG"))
            {
                return false;
            }
            idx += 1;
        } else if SHELL_WRAPPER_COMMANDS.contains(&t.as_str()) {
            idx += 1;
        } else {
            break;
        }
    }
    let Some(program) = tokens.get(idx) else {
        return false;
    };
    if program.rsplit('/').next().unwrap_or(program) != "git" {
        return false;
    }

    let args = &tokens[idx + 1..];
    let Some((subcommand, subcommand_args)) = git_builtin_subcommand_and_args(args) else {
        return false;
    };

    // Only built-in subcommands with a documented data-only stdin contract are
    // eligible. Unknown commands may be persistent or visible shell aliases,
    // and Git passes the heredoc through to those aliases unchanged.
    let accepts_file_stdin = matches!(subcommand, "commit" | "tag" | "notes");
    let accepts_plain_stdin = matches!(subcommand, "hash-object" | "update-index");
    // `git apply` reads the patch itself from stdin when no file operand (or
    // `-`) is given, and a unified-diff body is data in every mode (--cached,
    // --check, --index, worktree): git parses it as a patch, never executes
    // it (#374). One exception keeps the fail-closed path: `--unsafe-paths`
    // lets the patch govern paths outside the working tree, so that body
    // stays visible for scanning.
    if subcommand == "apply" {
        return !subcommand_args.iter().any(|arg| arg == "--unsafe-paths");
    }
    for (i, arg) in subcommand_args.iter().enumerate() {
        match arg.as_str() {
            // `-F -` / `--file -`: message read from stdin (commit/tag/notes).
            "-F" | "--file" if accepts_file_stdin => {
                if subcommand_args.get(i + 1).map(String::as_str) == Some("-") {
                    return true;
                }
            }
            // Glued / `=-` forms of the same.
            "-F-" | "--file=-" if accepts_file_stdin => return true,
            // Blob/index/object content from stdin (NOT --stdin-paths).
            "--stdin" if accepts_plain_stdin => return true,
            _ => {}
        }
    }
    false
}

/// Resolve a statically visible built-in Git subcommand after bounded global
/// option parsing. Configuration-bearing options are rejected because they can
/// define aliases; unknown option arity likewise fails closed.
fn git_builtin_subcommand_and_args(args: &[String]) -> Option<(&str, &[String])> {
    let mut index = 0usize;
    while let Some(arg) = args.get(index).map(String::as_str) {
        if arg == "--" {
            index += 1;
            break;
        }
        if matches!(arg, "-c" | "--config-env")
            || arg.starts_with("-c")
            || arg.starts_with("--config-env=")
        {
            return None;
        }
        if matches!(
            arg,
            "-C" | "--git-dir" | "--work-tree" | "--namespace" | "--super-prefix"
        ) {
            index = index.checked_add(2)?;
            if index > args.len() {
                return None;
            }
            continue;
        }
        if arg.starts_with("-C") && arg.len() > 2
            || [
                "--git-dir=",
                "--work-tree=",
                "--namespace=",
                "--super-prefix=",
                "--exec-path=",
            ]
            .iter()
            .any(|prefix| arg.starts_with(prefix))
        {
            index += 1;
            continue;
        }
        if matches!(
            arg,
            "-p" | "-P"
                | "--paginate"
                | "--no-pager"
                | "--no-replace-objects"
                | "--bare"
                | "--literal-pathspecs"
                | "--glob-pathspecs"
                | "--noglob-pathspecs"
                | "--icase-pathspecs"
                | "--no-optional-locks"
        ) {
            index += 1;
            continue;
        }
        if arg.starts_with('-') {
            return None;
        }
        break;
    }

    let subcommand = args.get(index)?.as_str();
    matches!(
        subcommand,
        "commit" | "tag" | "notes" | "hash-object" | "update-index" | "apply"
    )
    .then(|| (subcommand, &args[index + 1..]))
}

/// Check whether the command owning the heredoc is `spx session handoff`.
///
/// `spx session handoff` consumes its stdin as a structured handoff document;
/// it does not execute that document as shell.  Treating the prose body as
/// command-line tokens causes false positives such as a sentence containing
/// "git ... restore" matching `core.git:restore-worktree` (#181).
///
/// This is deliberately narrower than adding `spx` to
/// [`NON_EXECUTING_HEREDOC_COMMANDS`]: other `spx` subcommands are not covered
/// by the stdin-data contract.  As with the git sink above, parsing is bounded
/// to the heredoc's physical line and fails closed (leaves the body visible) on
/// any ambiguous shape.
fn is_spx_session_handoff_stdin_data_sink(command: &str, heredoc_start: usize) -> bool {
    if heredoc_start == 0 {
        return false;
    }

    let prefix = &command[..heredoc_start];
    let line_start = prefix.rfind(['\n', '\r']).map_or(0, |i| i + 1);
    let before = prefix[line_start..].trim_end();
    if before.is_empty() {
        return false;
    }

    let mut tokens = tokenize_backwards(before);
    tokens.reverse();

    let mut idx = 0;
    while let Some(token) = tokens.get(idx) {
        if is_shell_env_assignment(token) || SHELL_WRAPPER_COMMANDS.contains(&token.as_str()) {
            idx += 1;
        } else {
            break;
        }
    }

    let Some(program) = tokens.get(idx) else {
        return false;
    };
    if program.rsplit('/').next().unwrap_or(program) != "spx" {
        return false;
    }

    matches!(
        tokens.get(idx + 1..idx + 3),
        Some([session, handoff]) if session == "session" && handoff == "handoff"
    )
}

/// Check whether the heredoc/here-string at `heredoc_start` feeds a command
/// with a documented structured-stdin DATA contract (`git commit -F -` and
/// friends, `spx session handoff`). Such bodies are consumed as data (a commit
/// message, a handoff document), never executed as shell (#277).
pub(crate) fn is_structured_stdin_data_sink(command: &str, heredoc_start: usize) -> bool {
    is_git_stdin_data_sink(command, heredoc_start)
        || is_spx_session_handoff_stdin_data_sink(command, heredoc_start)
}

/// Mask heredoc content when the target command doesn't execute it.
///
/// This prevents false positives where dangerous patterns in DATA (not CODE)
/// trigger security blocks. For example, `cat <<EOF\nrm -rf /\nEOF` should
/// not be blocked because `cat` just outputs the text - it doesn't execute it.
///
/// Returns a `Cow::Borrowed` if no masking was needed, or `Cow::Owned` if
/// heredoc content was replaced with placeholder text.
#[must_use]
pub fn mask_non_executing_heredocs(command: &str) -> std::borrow::Cow<'_, str> {
    mask_non_executing_heredocs_with_policy(command, false)
}

/// Mask quoted heredoc bodies only when their target consumes stdin as data.
///
/// A quoted POSIX heredoc delimiter suppresses expansion in the outer shell,
/// so command-substitution analysis must not treat literal `$()` text passed
/// to `cat`, `tee`, or another data sink as executable. Unquoted heredocs are
/// deliberately left intact because the outer shell expands them before the
/// data sink runs. Shell/interpreter targets are likewise left intact because
/// they may execute the body after receiving it.
#[must_use]
pub fn mask_non_expanding_data_heredocs(command: &str) -> std::borrow::Cow<'_, str> {
    mask_non_executing_heredocs_with_policy(command, true)
}

fn mask_non_executing_heredocs_with_policy(
    command: &str,
    require_quoted_delimiter: bool,
) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;

    // Quick check: no heredoc operator means nothing to mask
    if !command.contains("<<") {
        return Cow::Borrowed(command);
    }
    // Only AST-proven redirect operators may introduce heredocs. Treating raw
    // `<<` text inside quotes/comments as syntax can make an inert fake
    // delimiter erase later executable lines from the security view. When
    // parsing is ambiguous, preserve every byte and accept a conservative
    // false positive instead of masking uncertain source.
    let Some(active_heredocs) = active_heredocs(command) else {
        return Cow::Borrowed(command);
    };

    let mut result = String::new();
    let mut pos = 0;
    let mut active_heredocs = active_heredocs.into_iter();

    while pos < command.len() {
        let Some(active_heredoc) = active_heredocs.next() else {
            if result.is_empty() {
                return Cow::Borrowed(command);
            }
            result.push_str(&command[pos..]);
            break;
        };
        let heredoc_start = active_heredoc.operator_start;
        if heredoc_start < pos {
            continue;
        }

        // Check for <<< (here-string)
        if matches!(active_heredoc.body, ActiveHeredocBody::HereString) {
            // Extract target command for here-string
            let target_cmd = extract_heredoc_target_command(command, heredoc_start);
            let target_may_be_overridden = target_cmd.as_deref().is_some_and(|target| {
                stdin_data_sink_may_be_overridden(command, heredoc_start, target)
            });
            let should_mask_herestring = !require_quoted_delimiter
                && !target_may_be_overridden
                && (target_cmd.as_ref().is_some_and(|cmd| {
                    is_non_executing_heredoc_command(cmd)
                        || is_interpreter_source_heredoc_command(cmd)
                }) || is_structured_stdin_data_sink(command, heredoc_start));

            if should_mask_herestring {
                // Mask here-string content for non-executing targets
                if let Some((content_start, content_end)) =
                    find_herestring_content_bounds(command, heredoc_start + 3)
                {
                    // Copy up to the content start (includes <<<)
                    if result.is_empty() {
                        result = command[..content_start].to_string();
                    } else {
                        result.push_str(&command[pos..content_start]);
                    }
                    // Replace content with placeholder
                    result.push_str("'MASKED'");
                    pos = content_end;
                    continue;
                }
            }

            // Not masking - just advance past <<< and continue
            if !result.is_empty() {
                result.push_str(&command[pos..heredoc_start + 3]);
            }
            pos = heredoc_start + 3;
            continue;
        }

        // Extract target command (what receives the heredoc)
        let target_cmd = extract_heredoc_target_command(command, heredoc_start);
        let ActiveHeredocBody::Heredoc {
            body_start,
            body_end,
            delimiter_quoted,
        } = active_heredoc.body
        else {
            // Unknown future body kinds must remain unmasked rather than
            // turning an advisory false-positive filter into a hook panic.
            continue;
        };
        let target_may_be_overridden = target_cmd.as_deref().is_some_and(|target| {
            stdin_data_sink_may_be_overridden(command, heredoc_start, target)
        });

        // Mask the body out of the raw-shell rescan when the target either
        // (a) does not execute its stdin at all (cat/tee/…), or
        // (b) is a non-shell interpreter reading its program from the body
        //     (python -/node -/ruby/…), which the language-aware AST path has
        //     already analyzed authoritatively (#136). Shell interpreters are
        //     excluded so real `bash <<SH … rm -rf … SH` still blocks.
        let target_is_data_sink = !target_may_be_overridden
            && (target_cmd.as_ref().is_some_and(|cmd| {
                is_non_executing_heredoc_command(cmd) || is_interpreter_source_heredoc_command(cmd)
            }) || is_structured_stdin_data_sink(command, heredoc_start)
                || (delimiter_quoted
                    && target_cmd
                        .as_deref()
                        .is_some_and(is_noop_stdin_discarding_command)));
        let should_mask = target_is_data_sink && (!require_quoted_delimiter || delimiter_quoted);

        if should_mask {
            // Tree-sitter's body span is authoritative for delimiter quote
            // removal and concatenation (`<<'E'OF`, `<<E\OF`, ...). Re-parsing
            // the raw delimiter token here can overrun the real terminator and
            // erase later executable commands.
            if result.is_empty() {
                result = command[..body_start].to_string();
            } else {
                result.push_str(&command[pos..body_start]);
            }
            result.push_str(&mask_preserve_newlines(&command[body_start..body_end]));
            pos = body_end;
            continue;
        }

        // Not masking - copy everything up to and including <<
        if result.is_empty() {
            // First heredoc we're not masking - check if we need to start building result
        } else {
            result.push_str(&command[pos..heredoc_start + 2]);
        }
        pos = heredoc_start + 2;
    }

    if result.is_empty() {
        Cow::Borrowed(command)
    } else {
        Cow::Owned(result)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveHeredocBody {
    HereString,
    Heredoc {
        body_start: usize,
        body_end: usize,
        delimiter_quoted: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ActiveHeredoc {
    operator_start: usize,
    body: ActiveHeredocBody,
}

fn active_heredocs(command: &str) -> Option<Vec<ActiveHeredoc>> {
    const MAX_HEREDOC_MASK_SOURCE_BYTES: usize = 256 * 1024;
    if command.len() > MAX_HEREDOC_MASK_SOURCE_BYTES {
        return None;
    }

    let ast = AstGrep::new(command, SupportLang::Bash);
    let mut heredocs = Vec::new();
    let mut parse_error = false;
    collect_active_heredocs(ast.root(), &mut heredocs, &mut parse_error);
    if parse_error {
        return active_indent_stripped_heredoc_fallback(command);
    }
    heredocs.sort_by_key(|heredoc| heredoc.operator_start);
    heredocs.dedup_by_key(|heredoc| heredoc.operator_start);
    Some(heredocs)
}

/// tree-sitter-bash deliberately rejects Ruby's `<<~` heredoc operator even
/// though dcg's tier-2 extractor supports it for embedded Ruby/documentation
/// workflows. Preserve that established masking behavior only when the input
/// has exactly one heredoc-like operator and the quote-aware trigger scanner
/// proves it is active shell syntax. Ambiguous multi-operator parse failures
/// remain unmasked so malformed input cannot erase later executable text.
fn active_indent_stripped_heredoc_fallback(command: &str) -> Option<Vec<ActiveHeredoc>> {
    if command.match_indices("<<").count() != 1 || !contains_active_heredoc_operator(command) {
        return None;
    }

    let extracted = match extract_content(command, &ExtractionLimits::default()) {
        ExtractionResult::Extracted(extracted) | ExtractionResult::Partial { extracted, .. } => {
            extracted
        }
        ExtractionResult::NoContent
        | ExtractionResult::Skipped(_)
        | ExtractionResult::Failed(_) => return None,
    };
    let mut candidates = extracted.into_iter().filter(|content| {
        content.heredoc_type == Some(HeredocType::IndentStripped) && content.content_range.is_some()
    });
    let candidate = candidates.next()?;
    if candidates.next().is_some() {
        return None;
    }
    let body_range = candidate.content_range?;
    Some(vec![ActiveHeredoc {
        operator_start: candidate.byte_range.start,
        body: ActiveHeredocBody::Heredoc {
            body_start: body_range.start,
            body_end: body_range.end,
            delimiter_quoted: candidate.quoted,
        },
    }])
}

#[allow(clippy::needless_pass_by_value)]
fn collect_active_heredocs<D: ast_grep_core::Doc>(
    node: ast_grep_core::Node<'_, D>,
    heredocs: &mut Vec<ActiveHeredoc>,
    parse_error: &mut bool,
) {
    let kind = node.kind();
    if kind == "ERROR" {
        *parse_error = true;
        return;
    }
    if kind == "herestring_redirect" {
        let text = node.text();
        if let Some(offset) = text.find("<<") {
            heredocs.push(ActiveHeredoc {
                operator_start: node.range().start + offset,
                body: ActiveHeredocBody::HereString,
            });
        } else {
            *parse_error = true;
        }
        return;
    }
    if kind == "heredoc_redirect" {
        let text = node.text();
        let Some(offset) = text.find("<<") else {
            *parse_error = true;
            return;
        };
        let mut body_range = None;
        let mut end_start = None;
        // tree-sitter-bash exposes the normalized delimiter as
        // `heredoc_start`; its node text does not retain the quote or
        // backslash bytes that suppress expansion. Inspect the redirect
        // header itself so `<<'EOF'`, `<<\"EOF\"`, and `<<E\\OF` remain
        // distinguishable from an expanding `<<EOF` body.
        let header = text
            .split_once(['\r', '\n'])
            .map_or_else(|| text.as_ref(), |(line, _)| line);
        let mut delimiter_quoted = header.contains(['\'', '"', '\\']);
        for child in node.children() {
            match child.kind().as_ref() {
                "heredoc_body" => body_range = Some(child.range()),
                "heredoc_end" => end_start = Some(child.range().start),
                "heredoc_start" => {
                    delimiter_quoted |= child.text().contains(['\'', '"', '\\']);
                }
                _ => {}
            }
        }
        let body_range =
            body_range.or_else(|| end_start.map(|start| std::ops::Range { start, end: start }));
        let Some(body_range) = body_range else {
            *parse_error = true;
            return;
        };
        if body_range.start > body_range.end || body_range.end > node.range().end {
            *parse_error = true;
            return;
        }
        heredocs.push(ActiveHeredoc {
            operator_start: node.range().start + offset,
            body: ActiveHeredocBody::Heredoc {
                body_start: body_range.start,
                body_end: body_range.end,
                delimiter_quoted,
            },
        });
        return;
    }
    for child in node.children() {
        collect_active_heredocs(child, heredocs, parse_error);
    }
}

fn mask_preserve_newlines(input: &str) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    for b in input.as_bytes() {
        match b {
            b'\n' | b'\r' => out.push(*b),
            _ => out.push(b' '),
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

/// Find the bounds of a here-string's content (start and end byte positions).
/// Returns `(content_start, content_end)` where `content_start` is after any opening quote
/// and `content_end` is before any closing quote or at whitespace/end for unquoted.
fn find_herestring_content_bounds(command: &str, after_operator: usize) -> Option<(usize, usize)> {
    if after_operator >= command.len() {
        return None;
    }

    let remaining = &command[after_operator..];
    let bytes = remaining.as_bytes();

    // Skip whitespace after <<<
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() && bytes[i] != b'\n' {
        i += 1;
    }

    if i >= bytes.len() || bytes[i] == b'\n' {
        return None;
    }

    // Check for quoted content
    if bytes[i] == b'\'' || bytes[i] == b'"' {
        let quote = bytes[i];
        let quote_start = i;
        i += 1;
        // Find closing quote
        while i < bytes.len() && bytes[i] != quote {
            // Handle escaped characters in double quotes
            if quote == b'"' && bytes[i] == b'\\' && i + 1 < bytes.len() {
                i += 2;
            } else {
                i += 1;
            }
        }
        if i < bytes.len() && bytes[i] == quote {
            // Include the quotes in the masked region
            return Some((
                after_operator + quote_start,
                after_operator + i + 1, // after closing quote
            ));
        }
        // No closing quote found - treat as unquoted
    }

    // Unquoted - find end at whitespace or command separator
    let word_start = i;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_whitespace() || matches!(c, b';' | b'&' | b'|' | b')' | b'\n') {
            break;
        }
        i += 1;
    }

    if i > word_start {
        Some((after_operator + word_start, after_operator + i))
    } else {
        None
    }
}

/// Extract the body of a heredoc, finding the terminating delimiter.
fn extract_heredoc_body(
    command: &str,
    start: usize,
    delimiter: &str,
    heredoc_type: HeredocType,
    limits: &ExtractionLimits,
    start_time: Instant,
    timeout: Duration,
) -> Result<(String, usize, usize, usize), SkipReason> {
    if start > command.len() {
        return Err(SkipReason::MalformedInput {
            reason: "heredoc start offset out of bounds".to_string(),
        });
    }

    let remaining = &command[start..];

    // Skip leading newline if present (heredoc body starts on next line)
    let body_start_offset = usize::from(remaining.starts_with('\n'));
    let body_start = &remaining[body_start_offset..];
    let body_start_abs = start + body_start_offset;

    let mut body_lines: Vec<&str> = Vec::new();
    let mut total_bytes: usize = 0;
    let mut cursor: usize = 0; // offset within body_start

    for part in body_start.split_inclusive('\n') {
        // Enforce timeout inside the loop (a single heredoc can be large).
        if start_time.elapsed() >= timeout {
            let elapsed_ms = u64::try_from(start_time.elapsed().as_millis()).unwrap_or(u64::MAX);
            return Err(SkipReason::Timeout {
                elapsed_ms,
                budget_ms: limits.timeout_ms,
            });
        }

        let line = part.strip_suffix('\n').unwrap_or(part);
        // Normalize CRLF line endings so terminator detection works cross-platform and so extracted
        // code doesn't include stray '\r' characters (which can break AST parsing).
        let line = line.strip_suffix('\r').unwrap_or(line);

        // Check if this line is the terminator
        let trimmed = match heredoc_type {
            HeredocType::TabStripped => line.trim_start_matches('\t'),
            HeredocType::IndentStripped => line.trim_start(),
            HeredocType::Standard | HeredocType::HereString => line,
        };

        if trimmed == delimiter {
            // End position should be accurate in the ORIGINAL command (including any indentation
            // before the delimiter). We intentionally exclude the newline after the terminator.
            let terminator_start = body_start_abs + cursor;
            let terminator_end = terminator_start + line.len();
            let mut body_end_abs = terminator_start;
            if body_end_abs > body_start_abs {
                let bytes = command.as_bytes();
                if bytes.get(body_end_abs.saturating_sub(1)) == Some(&b'\n') {
                    body_end_abs = body_end_abs.saturating_sub(1);
                    if bytes.get(body_end_abs.saturating_sub(1)) == Some(&b'\r') {
                        body_end_abs = body_end_abs.saturating_sub(1);
                    }
                }
            }

            let content = match heredoc_type {
                HeredocType::TabStripped => body_lines
                    .iter()
                    .map(|l| l.trim_start_matches('\t'))
                    .collect::<Vec<_>>()
                    .join("\n"),
                HeredocType::IndentStripped => {
                    // Compute the common leading-whitespace prefix in BYTES
                    // and then walk each line back to a char boundary
                    // before slicing. The naive `&l[min_indent..]` slice
                    // panics when a line's `min_indent`-th byte falls in
                    // the middle of a multi-byte UTF-8 codepoint — which
                    // happens when one line uses ASCII spaces while
                    // another uses a multi-byte whitespace such as NBSP
                    // (`\u{00A0}`, 2 bytes) or the ideographic space
                    // (`\u{3000}`, 3 bytes). Under `panic = "abort"` (the
                    // release profile) such a panic crashes the hook
                    // process, which AGENTS.md forbids — the hook must
                    // fail open. If the boundary doesn't line up we fall
                    // back to `trim_start()` for that line, which is the
                    // conservative interpretation (strip ALL of its
                    // leading whitespace).
                    let min_indent = body_lines
                        .iter()
                        .filter(|l| !l.trim().is_empty())
                        .map(|l| l.len() - l.trim_start().len())
                        .min()
                        .unwrap_or(0);

                    body_lines
                        .iter()
                        .map(|l| {
                            if l.len() >= min_indent && l.is_char_boundary(min_indent) {
                                &l[min_indent..]
                            } else {
                                l.trim_start()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                }
                HeredocType::Standard | HeredocType::HereString => body_lines.join("\n"),
            };

            return Ok((content, terminator_end, body_start_abs, body_end_abs));
        }

        // Enforce limits (fail-open by returning a specific skip reason).
        total_bytes = total_bytes.saturating_add(part.len());
        if total_bytes > limits.max_body_bytes {
            return Err(SkipReason::ExceededSizeLimit {
                actual: total_bytes,
                limit: limits.max_body_bytes,
            });
        }

        if body_lines.len() >= limits.max_body_lines {
            return Err(SkipReason::ExceededLineLimit {
                actual: body_lines.len() + 1,
                limit: limits.max_body_lines,
            });
        }

        body_lines.push(line);
        cursor = cursor.saturating_add(part.len());
    }

    Err(SkipReason::UnterminatedHeredoc {
        delimiter: delimiter.to_string(),
    })
}

// ============================================================================
// Shell Command Extraction for Evaluator Integration (git_safety_guard-uau)
// ============================================================================

use ast_grep_core::AstGrep;
use ast_grep_language::SupportLang;

/// Extracted shell command with position info for evaluator integration.
///
/// Each command represents a simple command invocation that can be
/// fed to the evaluator for destructive pattern matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedShellCommand {
    /// The full command text (reconstructed from AST).
    pub text: String,
    /// Byte offset in the original content.
    pub start: usize,
    /// End byte offset.
    pub end: usize,
    /// 1-based line number.
    pub line_number: usize,
}

/// Extract executable POSIX command-substitution bodies with the Bash parser.
///
/// A hand-written parenthesis scanner cannot soundly distinguish the closing
/// delimiter from `)` in comments, nested groups, `case` patterns, functions,
/// or nested substitutions inside double quotes. Tree-sitter-bash already
/// models those grammar rules, so the evaluator uses this bounded AST view for
/// security decisions. A recovery/error region fails closed only when it could
/// conceal substitution syntax that was not captured as a parsed node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixCommandSubstitution {
    /// Command body after removing the outer `$()` or backtick delimiters.
    pub body: String,
    /// Start byte of the complete substitution in the parsed source.
    pub start: usize,
    /// Exclusive end byte of the complete substitution in the parsed source.
    pub end: usize,
}

/// The Bash AST could not provide complete, non-overlapping source ranges for
/// every POSIX command substitution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PosixCommandSubstitutionParseError;

pub fn extract_posix_command_substitutions(
    content: &str,
) -> Result<Vec<PosixCommandSubstitution>, PosixCommandSubstitutionParseError> {
    // Keep the common evaluator path independent of tree-sitter. Backticks
    // and `$(` are the only POSIX command-substitution introducers; arithmetic
    // expansion may pass this prefilter, but the AST will not classify it as a
    // command substitution.
    if content.trim().is_empty() || (!content.contains("$(") && !content.contains('`')) {
        return Ok(Vec::new());
    }
    const MAX_SUBSTITUTION_SOURCE_BYTES: usize = 256 * 1024;
    if content.len() > MAX_SUBSTITUTION_SOURCE_BYTES {
        return Err(PosixCommandSubstitutionParseError);
    }

    let ast = AstGrep::new(content, SupportLang::Bash);
    let root = ast.root();
    let mut substitutions = Vec::new();
    let mut parse_error = false;
    let mut error_ranges = Vec::new();
    collect_command_substitutions_recursive(
        root,
        &mut substitutions,
        &mut parse_error,
        &mut error_ranges,
    );
    if !parse_error {
        parse_error =
            error_ranges_conceal_substitution_syntax(content, &error_ranges, &substitutions);
    }
    if parse_error {
        Err(PosixCommandSubstitutionParseError)
    } else {
        substitutions.sort_by(|left, right| {
            left.start
                .cmp(&right.start)
                .then_with(|| right.end.cmp(&left.end))
        });
        Ok(substitutions)
    }
}

/// Whether a tree-sitter recovery region contains command-substitution syntax
/// that was not captured as a parsed `command_substitution` node.
///
/// Tree-sitter recovers from ungrammatical input by wrapping it in `ERROR`
/// nodes. Failing closed on *every* recovery node meant a single unparseable
/// fragment anywhere in a submission poisoned the whole command — but only
/// when a `$(` or backtick happened to appear somewhere, turning benign but
/// grammar-exotic submissions into unactionable hard denies. The enumeration
/// is only incomplete if substitution syntax hides *inside* a recovery region
/// without a corresponding parsed node, so that is the only case that still
/// fails closed.
fn error_ranges_conceal_substitution_syntax(
    content: &str,
    error_ranges: &[(usize, usize)],
    substitutions: &[PosixCommandSubstitution],
) -> bool {
    if error_ranges.is_empty() {
        return false;
    }
    let covered = |offset: usize| {
        substitutions
            .iter()
            .any(|substitution| offset >= substitution.start && offset < substitution.end)
    };
    for &(start, end) in error_ranges {
        let Some(region) = content.get(start..end) else {
            return true;
        };
        for (relative, _) in region.match_indices("$(") {
            if !covered(start + relative) {
                return true;
            }
        }
        for (relative, _) in region.match_indices('`') {
            if !covered(start + relative) {
                return true;
            }
        }
    }
    false
}

pub fn extract_posix_command_substitution_bodies(
    content: &str,
) -> Result<Vec<String>, PosixCommandSubstitutionParseError> {
    extract_posix_command_substitutions(content).map(|substitutions| {
        substitutions
            .into_iter()
            .map(|substitution| substitution.body)
            .collect()
    })
}

#[allow(clippy::needless_pass_by_value)]
fn collect_command_substitutions_recursive<D: ast_grep_core::Doc>(
    node: ast_grep_core::Node<'_, D>,
    substitutions: &mut Vec<PosixCommandSubstitution>,
    parse_error: &mut bool,
    error_ranges: &mut Vec<(usize, usize)>,
) {
    let kind = node.kind();
    if kind == "ERROR" {
        let range = node.range();
        error_ranges.push((range.start, range.end));
    } else if kind == "command_substitution" {
        let text = node.text();
        let text = text.as_ref();
        // Inside a double-quoted string, tree-sitter-bash 0.25 folds the
        // whitespace separating a preceding expansion from `$(` into the
        // substitution node itself: `"$s $(true)"` yields a
        // `command_substitution` whose text is ` $(true)` (issue #279). The
        // construct is well formed, so trim that leading whitespace and shift
        // the reported start past it; any other unexpected prefix still fails
        // closed below.
        let leading_whitespace = text.len() - text.trim_start().len();
        let text = &text[leading_whitespace..];
        let body = text
            .strip_prefix("$(")
            .and_then(|inner| inner.strip_suffix(')'))
            .or_else(|| {
                text.strip_prefix('`')
                    .and_then(|inner| inner.strip_suffix('`'))
            });
        if let Some(body) = body {
            // Backquoted substitutions escape nested backticks as `\``. The
            // nested shell parse sees those as executable delimiters after the
            // outer backquote layer is removed, so expose them to recursion.
            let range = node.range();
            substitutions.push(PosixCommandSubstitution {
                body: body.replace("\\`", "`"),
                start: range.start + leading_whitespace,
                end: range.end,
            });
        } else {
            *parse_error = true;
        }
        // The evaluator recursively parses each captured body. Descending here
        // would emit nested substitutions twice and make deeply nested input
        // grow exponentially across recursion levels.
        return;
    }

    for child in node.children() {
        collect_command_substitutions_recursive(child, substitutions, parse_error, error_ranges);
    }
}

/// Extract executable shell commands from heredoc/script content.
///
/// This function parses shell content using tree-sitter-bash (via ast-grep)
/// and extracts individual commands that should be evaluated against the
/// main evaluator pipeline. This keeps all destructive knowledge in packs
/// rather than duplicating rules for heredoc content.
///
/// # What gets extracted
///
/// - Simple commands: `rm -rf /path`, `git reset --hard`
/// - Pipe sources and targets: commands on either side of `|`
/// - Commands inside command substitutions: contents of `$(...)`
/// - Commands inside subshells: contents of `(...)`
///
/// # What does NOT get extracted (false positive avoidance)
///
/// - Comments: `# rm -rf / dangerous` is NOT executed
/// - String literals in echo/printf: content inside quotes is data, not execution
/// - Heredoc delimiters themselves
///
/// # Performance
///
/// Uses ast-grep for parsing which is very fast (<2ms for typical heredocs).
/// No timeout is enforced here as the AST matcher already has its own timeout.
///
/// # Examples
///
/// ```ignore
/// use destructive_command_guard::heredoc::extract_shell_commands;
///
/// // Simple command
/// let commands = extract_shell_commands("rm -rf /tmp/test");
/// assert_eq!(commands.len(), 1);
/// assert_eq!(commands[0].text, "rm -rf /tmp/test");
///
/// // Pipeline - both sides extracted
/// let commands = extract_shell_commands("find . | xargs rm");
/// assert_eq!(commands.len(), 2);
///
/// // Comment - not extracted
/// let commands = extract_shell_commands("# rm -rf / dangerous");
/// assert_eq!(commands.len(), 0);
/// ```
#[must_use]
#[instrument(skip(content), fields(content_len = content.len()))]
pub fn extract_shell_commands(content: &str) -> Vec<ExtractedShellCommand> {
    if content.trim().is_empty() {
        trace!("extract_shell_commands: empty content");
        return Vec::new();
    }

    let start = Instant::now();
    let ast = AstGrep::new(content, SupportLang::Bash);
    let root = ast.root();

    let mut commands = Vec::new();

    // Walk the AST to find command nodes
    // tree-sitter-bash uses "command" nodes for simple commands
    collect_commands_recursive(root, content, &mut commands);

    debug!(
        elapsed_us = start.elapsed().as_micros(),
        count = commands.len(),
        "extract_shell_commands: AST analysis complete"
    );
    commands
}

/// Recursively collect command nodes from the AST.
///
/// Walks the tree looking for "command" nodes (simple commands in bash).
/// Recurses into all child nodes to find nested commands, including:
/// - Command substitutions: `$(cmd)`
/// - Subshells: `(cmd)`
/// - Pipelines, command lists, loops, conditionals, etc.
#[allow(clippy::needless_pass_by_value)]
fn collect_commands_recursive<D: ast_grep_core::Doc>(
    node: ast_grep_core::Node<'_, D>,
    content: &str,
    commands: &mut Vec<ExtractedShellCommand>,
) {
    let kind = node.kind();

    // tree-sitter-bash hangs redirections off a `redirected_statement`
    // wrapper around the command node, so collecting only `command` nodes
    // silently drops `> target` and hides redirect-based destruction from the
    // recursive evaluation (#271: `mise exec -c 'echo hi > ~/.zshrc'` and the
    // `sh -c` sibling allowed on the Posix hook route). Emit the complete
    // statement whenever an output redirect is present; the bare command is
    // still collected by the recursion below, which is harmless.
    if kind == "redirected_statement"
        && node
            .children()
            .any(|child| child.kind() == "file_redirect" && child.text().contains('>'))
    {
        let range = node.range();
        let text = node.text().to_string();
        if !text.trim().is_empty() {
            let line_number = content[..range.start].matches('\n').count() + 1;

            commands.push(ExtractedShellCommand {
                text,
                start: range.start,
                end: range.end,
                line_number,
            });
        }
    }

    // "command" in tree-sitter-bash is a simple command
    if kind == "command" {
        let range = node.range();
        let text = node.text().to_string();

        // Skip empty commands
        if !text.trim().is_empty() {
            let line_number = content[..range.start].matches('\n').count() + 1;

            commands.push(ExtractedShellCommand {
                text,
                start: range.start,
                end: range.end,
                line_number,
            });
        }
    }

    // Recurse into all children to find nested commands
    // This handles:
    // - Pipelines: `cmd1 | cmd2` has command children
    // - Command lists: `cmd1 && cmd2` has command children
    // - Command substitution: `$(cmd)` contains command
    // - Subshells: `(cmd)` contains command
    for child in node.children() {
        collect_commands_recursive(child, content, commands);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use proptest::prelude::*;

    // ========================================================================
    // ssh remote-payload extraction (#326)
    // ========================================================================

    mod ssh_remote_payload_extraction {
        use super::*;

        fn ssh_payloads(command: &str) -> Vec<String> {
            let result = extract_content(command, &ExtractionLimits::default());
            match result {
                ExtractionResult::Extracted(contents) => contents
                    .into_iter()
                    .filter(|content| content.target_command.as_deref() == Some("ssh"))
                    .map(|content| content.content)
                    .collect(),
                _ => Vec::new(),
            }
        }

        #[test]
        fn quoted_single_word_payload_is_unquoted_and_extracted() {
            assert_eq!(ssh_payloads("ssh host 'dropdb mydb'"), ["dropdb mydb"]);
            assert_eq!(ssh_payloads("ssh host \"rm -rf /srv\""), ["rm -rf /srv"]);
            assert_eq!(
                ssh_payloads("ssh user@10.0.0.5 'git reset --hard'"),
                ["git reset --hard"]
            );
        }

        #[test]
        fn multi_word_payload_keeps_raw_per_word_quoting() {
            // The remote shell re-parses the concatenated words, so per-word
            // quotes must survive: `'&&'` here is remote DATA locally quoted.
            assert_eq!(
                ssh_payloads("ssh host cd /app '&&' ls"),
                ["cd /app '&&' ls"]
            );
        }

        #[test]
        fn value_taking_options_are_skipped_when_locating_the_destination() {
            assert_eq!(
                ssh_payloads("ssh -i key.pem -p 2222 -o StrictHostKeyChecking=no host 'uptime'"),
                ["uptime"]
            );
            // Attached value form.
            assert_eq!(ssh_payloads("ssh -p2222 host 'uptime'"), ["uptime"]);
            // Bundled no-value flags ending in a value-taker.
            assert_eq!(ssh_payloads("ssh -fnT -l root host 'uptime'"), ["uptime"]);
        }

        #[test]
        fn double_dash_ends_option_parsing() {
            assert_eq!(ssh_payloads("ssh -- host 'uptime'"), ["uptime"]);
        }

        #[test]
        fn unmodeled_options_bail_without_extraction() {
            // Real ssh refuses unknown options, so nothing executes in this
            // shape; extraction must not guess at the destination.
            assert!(ssh_payloads("ssh --fake host 'rm -rf /'").is_empty());
        }

        #[test]
        fn interactive_sessions_and_relatives_extract_nothing() {
            assert!(ssh_payloads("ssh host").is_empty());
            assert!(ssh_payloads("ssh -N -L 8080:internal:80 host").is_empty());
            assert!(ssh_payloads("ssh-keygen -t ed25519 -f 'key file'").is_empty());
            assert!(ssh_payloads("autossh host 'uptime'").is_empty());
            assert!(ssh_payloads("scp 'file a.txt' host:/tmp/").is_empty());
        }

        #[test]
        fn path_qualified_and_chained_invocations_extract() {
            assert_eq!(ssh_payloads("/usr/bin/ssh host 'uptime'"), ["uptime"]);
            assert_eq!(
                ssh_payloads("ssh a 'uptime' && ssh b 'df -h'"),
                ["uptime", "df -h"]
            );
        }

        #[test]
        fn payload_stops_at_local_shell_separators() {
            assert_eq!(ssh_payloads("ssh host 'uptime'; echo done"), ["uptime"]);
        }
    }

    // ========================================================================
    // POSIX command-substitution extraction (grammar-recovery scoping)
    // ========================================================================

    mod posix_substitution_recovery {
        use super::*;

        #[test]
        fn well_formed_substitutions_extract_cleanly() {
            let found = extract_posix_command_substitutions("echo \"$(date)\" `hostname`")
                .expect("well-formed input must parse");
            assert_eq!(found.len(), 2);
            assert_eq!(found[0].body, "date");
            assert_eq!(found[1].body, "hostname");
        }

        #[test]
        fn recovery_region_without_substitution_syntax_does_not_poison_command() {
            // `done` without a matching `do` forces tree-sitter recovery, but
            // the broken fragment conceals no substitution syntax, so the
            // well-formed `$(date)` elsewhere must still be enumerated instead
            // of failing the whole submission closed.
            let content = "for f in *; done\necho \"$(date)\"";
            let ast = AstGrep::new(content, SupportLang::Bash);
            let mut has_error = false;
            let mut stack = vec![ast.root()];
            while let Some(node) = stack.pop() {
                if node.kind() == "ERROR" {
                    has_error = true;
                }
                stack.extend(node.children());
            }
            if has_error {
                let found = extract_posix_command_substitutions(content)
                    .expect("recovery without hidden substitution syntax must not fail closed");
                assert!(
                    found.iter().any(|s| s.body == "date"),
                    "the well-formed substitution must still be enumerated"
                );
            } else {
                // If a future grammar version parses this cleanly the scoped
                // check is simply never consulted; extraction must succeed.
                extract_posix_command_substitutions(content).expect("clean parse must succeed");
            }
        }

        #[test]
        fn recovery_region_concealing_substitution_syntax_fails_closed() {
            // An unterminated substitution leaves `$(` inside a recovery
            // region with no parsed `command_substitution` node covering it:
            // the enumeration would be incomplete, so this must fail closed.
            let content = "echo \"$(date\"";
            assert_eq!(
                extract_posix_command_substitutions(content),
                Err(PosixCommandSubstitutionParseError)
            );
        }

        #[test]
        fn stray_backtick_in_recovery_region_fails_closed() {
            let content = "if [ x; then `rm -rf /tmp/a";
            assert_eq!(
                extract_posix_command_substitutions(content),
                Err(PosixCommandSubstitutionParseError)
            );
        }
    }

    // ========================================================================
    // Tier 1: Trigger Detection Tests
    // ========================================================================

    mod tier1_triggers {
        use super::*;

        #[test]
        fn no_trigger_on_safe_commands() {
            // Common safe commands should NOT trigger
            let safe_commands = [
                "git status",
                "ls -la",
                "cargo build",
                "npm install",
                "docker ps",
                "kubectl get pods",
                "cat file.txt",
                "echo hello",
                "grep pattern file",
                "find . -name '*.rs'",
            ];

            for cmd in safe_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::NoTrigger,
                    "should not trigger on: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_heredoc_basic() {
            // Basic heredoc forms
            let heredocs = [
                "cat << EOF",
                "cat <<EOF",
                "cat << 'EOF'",
                r#"cat << "EOF""#,
                "cat <<- EOF",       // Tab-stripping heredoc
                "mysql <<< 'query'", // Here-string
            ];

            for cmd in heredocs {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on heredoc: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_python_inline() {
            let python_commands = [
                "python -c 'import os'",
                "python3 -c 'import os'",
                "python -I -c 'import os'",
                "python3 -I -c 'import os'",
                "python -e 'print(1)'",
                "python3 -e 'print(1)'",
            ];

            for cmd in python_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on python inline: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_versioned_interpreters() {
            // Tier 1 MUST have zero false negatives - versioned interpreters must trigger
            let versioned_commands = [
                // Python versions
                "python3.11 -c 'import os'",
                "python3.12.1 -c 'import os'",
                "python3.9 -e 'print(1)'",
                // Ruby versions
                "ruby3.0 -e 'puts 1'",
                "ruby3.2.1 -e 'exit'",
                // Perl versions
                "perl5.36 -e 'print 1'",
                "perl5.38.2 -E 'say 1'",
                // Node versions
                "node18 -e 'console.log(1)'",
                "node20.1 -e 'console.log(1)'",
                "nodejs18 -e 'console.log(1)'",
                "nodejs20.10.0 -e 'test'",
            ];

            for cmd in versioned_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on versioned interpreter: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_ruby_inline() {
            let ruby_commands = ["ruby -e 'puts 1'", "ruby -w -e 'puts 1'", "irb -e 'exit'"];

            for cmd in ruby_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on ruby inline: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_perl_inline() {
            let perl_commands = [
                "perl -e 'print 1'",
                "perl -E 'say 1'", // Modern Perl
                "perl -pi -e 'print 1'",
            ];

            for cmd in perl_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on perl inline: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_node_inline() {
            let node_commands = [
                "node -e 'console.log(1)'",
                "node -p 'process.version'",
                "node -pe 'process.version'",
            ];

            for cmd in node_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on node inline: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_shell_inline() {
            let shell_commands = [
                "bash -c 'echo hello'",
                "bash -l -c 'echo hello'",
                "bash -lc 'echo hello'",
                "bash --noprofile --norc -c 'echo hello'",
                "sh -c 'ls'",
                "zsh -c 'pwd'",
                "fish -c 'echo hello'",
            ];

            for cmd in shell_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on shell inline: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_xargs() {
            let xargs_commands = [
                "find . -name '*.bak' | xargs rm",
                "ls | xargs -I {} echo {}",
                "cat files.txt | xargs -n1 process",
            ];

            for cmd in xargs_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on xargs: {cmd}"
                );
            }
        }

        /// #259: `mise exec -c/--command` runs an inline shell string, so
        /// Tier 1 must trigger on every spelling Tier 2 can parse a payload
        /// from (the superset invariant).
        #[test]
        fn triggers_on_mise_exec_inline_command() {
            let commands = [
                "mise exec -c 'echo hi'",
                r#"mise exec -c "echo hi""#,
                "mise exec --command 'echo hi'",
                r#"mise exec --command="echo hi""#,
                "mise x -c 'echo hi'",
                "mise x --command='echo hi'",
                "mise exec node@20 -c 'echo hi'",
                "mise exec node@20 python@3.12 -c 'echo hi'",
                "mise exec --cd /tmp -c 'echo hi'",
                "mise -v exec -c 'echo hi'",
                "mise --cd /tmp exec -c 'echo hi'",
                "mise exec -y -c 'echo hi'",
                "mise exec -c'echo hi'",
                "mise exec --no-such-flag -c 'echo hi'",
                "/usr/bin/mise exec -c 'echo hi'",
                "mise.exe exec -c 'echo hi'",
                "echo hi | mise exec -c 'echo hi'",
                "ls && mise x -c 'echo hi'",
                "mise exec -c $'echo hi'",
                "mise exec -c$'echo hi'",
                r#"mise exec "-c" 'echo hi'"#,
                "mise exec -c 'echo hi' -c 'echo bye'",
            ];
            for cmd in commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "Tier 1 must trigger on mise inline command: {cmd}"
                );
            }
        }

        #[test]
        fn does_not_trigger_on_mise_without_inline_command() {
            let commands = [
                "mise install node@20",
                "mise use node@20",
                "mise version",
                "mise exec -- node -v",
                "mise exec git status",
                "mise exec --cd /tmp",
            ];
            for cmd in commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::NoTrigger,
                    "Tier 1 must not trigger on non-payload mise usage: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_piped_execution() {
            let piped_commands = [
                "echo 'print(1)' | python",
                "cat script.py | python3",
                "echo 'puts 1' | ruby",
                "echo 'print 1' | perl",
                "echo 'console.log(1)' | node",
                "echo 'echo hello' | bash",
                "echo 'ls' | sh",
            ];

            for cmd in piped_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on piped execution: {cmd}"
                );
            }
        }

        #[test]
        fn triggers_on_eval_exec() {
            let eval_commands = [
                r#"eval "dangerous code""#,
                "eval 'dangerous code'",
                r#"exec "command""#,
                "exec 'command'",
            ];

            for cmd in eval_commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger on eval/exec: {cmd}"
                );
            }
        }

        #[test]
        fn matched_triggers_returns_indices() {
            // Should return the indices of matching patterns
            let matches = matched_triggers("python -c 'test'");
            assert!(!matches.is_empty(), "should have matches for python -c");

            let no_matches = matched_triggers("git status");
            assert!(
                no_matches.is_empty(),
                "should have no matches for git status"
            );
        }

        #[test]
        fn heredoc_syntax_inside_quoted_literals_does_not_trigger() {
            // Common false positives: heredoc syntax used as documentation or search patterns.
            let commands = [
                r#"git commit -m "docs: example heredoc: cat <<EOF rm -rf / EOF""#,
                r#"rg "<<EOF" README.md"#,
                "echo 'cat <<EOF (docs only)'",
            ];

            for cmd in commands {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::NoTrigger,
                    "should not trigger on quoted literal heredoc syntax: {cmd}"
                );
            }
        }

        #[test]
        fn heredoc_inside_command_substitution_with_outer_quotes_still_triggers() {
            // `$(...)` is executed even when the outer word is double-quoted.
            let cmd = "echo \"$(cat <<EOF\nrm -rf /\nEOF)\"";
            assert_eq!(check_triggers(cmd), TriggerResult::Triggered);
        }

        // Property: Zero false negatives - if content extraction would find
        // something, trigger detection MUST fire. This is tested via the
        // comprehensive test cases above and will be verified with property
        // tests once Tier 2 is implemented.
    }

    // ========================================================================
    // Tier 2: Content Extraction Tests
    // ========================================================================

    mod tier2_extraction {
        use super::*;

        /// Run semantic extraction assertions with enough budget to remain
        /// deterministic when the full test matrix saturates the host. Tests
        /// that deliberately set a non-default timeout (including the zero-ms
        /// timeout contract) retain that exact value.
        fn extract_content(command: &str, limits: &ExtractionLimits) -> ExtractionResult {
            let mut test_limits = *limits;
            if test_limits.timeout_ms == ExtractionLimits::default().timeout_ms {
                test_limits.timeout_ms = 5_000;
            }
            super::super::extract_content(command, &test_limits)
        }

        #[test]
        fn extraction_limits_default() {
            let limits = ExtractionLimits::default();
            assert_eq!(limits.max_body_bytes, 1024 * 1024);
            assert_eq!(limits.max_body_lines, 10_000);
            assert_eq!(limits.max_heredocs, 10);
            assert_eq!(limits.timeout_ms, 50);
        }

        #[test]
        fn extracts_inline_script_single_quotes() {
            let result = extract_content("python -c 'import os'", &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "import os");
                assert_eq!(contents[0].language, ScriptLanguage::Python);
                assert!(contents[0].quoted);
            } else {
                panic!("Expected Extracted result");
            }
        }

        #[test]
        fn extracts_inline_script_double_quotes() {
            let result = extract_content(r#"bash -c "echo hello""#, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "echo hello");
                assert_eq!(contents[0].language, ScriptLanguage::Bash);
            } else {
                panic!("Expected Extracted result");
            }
        }

        // --- Windows inline wrappers (.9.7): cmd /c|/k, iex/Invoke-Expression, -EncodedCommand ---

        #[test]
        fn extracts_cmd_slash_c_double_quoted() {
            let result =
                extract_content(r#"cmd /c "del /s /q C:\src""#, &ExtractionLimits::default());
            let ExtractionResult::Extracted(contents) = result else {
                panic!("expected Extracted");
            };
            assert!(
                contents
                    .iter()
                    .any(|c| c.content == r"del /s /q C:\src"
                        && c.language == ScriptLanguage::Bash),
                "cmd /c body not extracted: {contents:?}"
            );
        }

        #[test]
        fn extracts_cmd_slash_k_and_slash_s_c() {
            let r1 = extract_content(r#"cmd /k "format C: /q""#, &ExtractionLimits::default());
            let ExtractionResult::Extracted(c1) = r1 else {
                panic!("expected Extracted for /k");
            };
            assert!(c1.iter().any(|c| c.content == "format C: /q"));

            let r2 = extract_content(
                r#"cmd /s /c "rd /s /q C:\Windows""#,
                &ExtractionLimits::default(),
            );
            let ExtractionResult::Extracted(c2) = r2 else {
                panic!("expected Extracted for /s /c");
            };
            assert!(c2.iter().any(|c| c.content == r"rd /s /q C:\Windows"));
        }

        #[test]
        fn extracts_cmd_slash_c_unquoted_rest_of_line() {
            let mut limits = ExtractionLimits::default();
            // Assert Windows wrapper semantics independently of the production
            // 50 ms scheduler budget under a highly parallel all-target run.
            limits.timeout_ms = 5_000;
            let result = extract_content(r"cmd /c del /s /q C:\src", &limits);
            let ExtractionResult::Extracted(contents) = result else {
                panic!("expected Extracted");
            };
            assert!(contents.iter().any(|c| c.content == r"del /s /q C:\src"));
        }

        // --- mise exec -c/--command inline shell payloads (#259) ---

        #[test]
        fn extracts_mise_exec_inline_payload() {
            let mut limits = ExtractionLimits::default();
            // Parser-contract test: independent of the production 50 ms
            // scheduler budget under a highly parallel all-target run.
            limits.timeout_ms = 5_000;
            let cases = [
                (r#"mise exec -c "git reset --hard""#, "git reset --hard"),
                ("mise exec -c 'git reset --hard'", "git reset --hard"),
                (
                    r#"mise exec --command "git reset --hard""#,
                    "git reset --hard",
                ),
                (
                    r#"mise exec --command="git reset --hard""#,
                    "git reset --hard",
                ),
                ("mise x -c 'git clean -fd'", "git clean -fd"),
                ("mise x --command='git clean -fd'", "git clean -fd"),
                (
                    r#"mise exec node@20 -c "git reset --hard""#,
                    "git reset --hard",
                ),
                (
                    r#"mise exec node@20 python@3.12 -c "git reset --hard""#,
                    "git reset --hard",
                ),
                (
                    r#"mise exec --cd /tmp -c "git reset --hard""#,
                    "git reset --hard",
                ),
                ("mise -v exec -c 'git reset --hard'", "git reset --hard"),
                (
                    r#"mise --cd /tmp exec -c "git reset --hard""#,
                    "git reset --hard",
                ),
                ("mise exec -y -c 'git reset --hard'", "git reset --hard"),
                (r#"mise exec -c"git reset --hard""#, "git reset --hard"),
                // ANSI-C / locale quoting reaches the shell as the same argv,
                // so the introducer must be stripped from the payload.
                ("mise exec -c $'git reset --hard'", "git reset --hard"),
                (r#"mise exec -c $"git reset --hard""#, "git reset --hard"),
                ("mise exec -c$'git reset --hard'", "git reset --hard"),
                // Quoting the flag itself changes nothing about the argv.
                (r#"mise exec "-c" "git reset --hard""#, "git reset --hard"),
                (
                    r#"mise exec '--command' "git reset --hard""#,
                    "git reset --hard",
                ),
                // `-c` is last-wins: a benign decoy must not hide the payload
                // that actually runs.
                (
                    r#"mise exec -c "echo hi" -c "git reset --hard""#,
                    "git reset --hard",
                ),
                (
                    r#"mise exec --command "echo hi" --command "git reset --hard""#,
                    "git reset --hard",
                ),
                // Unmodeled flags must not disarm extraction (#260 blind spot).
                (
                    r#"mise exec --no-such-flag -c "git reset --hard""#,
                    "git reset --hard",
                ),
                (
                    r#"mise --no-such-global exec -c "git reset --hard""#,
                    "git reset --hard",
                ),
                (
                    r#"mise exec --no-such-flag value -c "git reset --hard""#,
                    "git reset --hard",
                ),
                // Path-qualified and Windows spellings are the same program.
                (
                    r#"/usr/bin/mise exec -c "git reset --hard""#,
                    "git reset --hard",
                ),
                (r#"mise.exe exec -c "git reset --hard""#, "git reset --hard"),
                // Segment position must not matter.
                (r#"ls && mise x -c "git reset --hard""#, "git reset --hard"),
                (
                    r#"echo hi | mise exec -c "git reset --hard""#,
                    "git reset --hard",
                ),
            ];
            for (command, expected) in cases {
                let ExtractionResult::Extracted(contents) = extract_content(command, &limits)
                else {
                    panic!("expected Extracted for {command:?}");
                };
                let content = contents
                    .iter()
                    .find(|c| c.content == expected)
                    .unwrap_or_else(|| {
                        panic!("payload {expected:?} not extracted from {command:?}: {contents:?}")
                    });
                assert_eq!(content.language, ScriptLanguage::Bash);
                if let Some(range) = &content.content_range {
                    assert_eq!(
                        command.get(range.clone()),
                        Some(expected),
                        "content_range must slice the raw payload: {command:?}"
                    );
                }
            }
        }

        #[test]
        fn does_not_extract_mise_payload_without_inline_command() {
            let mut limits = ExtractionLimits::default();
            limits.timeout_ms = 5_000;
            for command in [
                "mise install node@20",
                "mise use node@20",
                "mise version",
                "mise exec git status",
                "mise exec --cd /tmp",
                // After `--` the argv belongs to the wrapped program, not mise.
                "mise exec -- some-tool -c 'git reset --hard'",
                // A different launcher's `-c` is not mise's.
                "npm exec -c 'git reset --hard'",
            ] {
                let result = extract_content(command, &limits);
                assert!(
                    !matches!(
                        result,
                        ExtractionResult::Extracted(ref contents)
                            if contents
                                .iter()
                                .any(|c| c.target_command.as_deref() == Some("mise"))
                    ),
                    "no mise payload expected for {command:?}: {result:?}"
                );
            }
        }

        #[test]
        fn extracts_iex_and_invoke_expression() {
            let r1 = extract_content(
                r#"iex "Remove-Item -Recurse -Force C:\src""#,
                &ExtractionLimits::default(),
            );
            let ExtractionResult::Extracted(c1) = r1 else {
                panic!("expected Extracted for iex");
            };
            assert!(
                c1.iter()
                    .any(|c| c.content == r"Remove-Item -Recurse -Force C:\src")
            );

            let r2 = extract_content(
                r"Invoke-Expression 'rd /s /q C:\src'",
                &ExtractionLimits::default(),
            );
            let ExtractionResult::Extracted(c2) = r2 else {
                panic!("expected Extracted for Invoke-Expression");
            };
            assert!(c2.iter().any(|c| c.content == r"rd /s /q C:\src"));
        }

        #[test]
        fn extracts_powershell_encoded_command_base64_utf16le() {
            // base64(UTF-16LE("Remove-Item -Recurse -Force C:\src"))
            let enc = "UgBlAG0AbwB2AGUALQBJAHQAZQBtACAALQBSAGUAYwB1AHIAcwBlACAALQBGAG8AcgBjAGUAIABDADoAXABzAHIAYwA=";
            let mut limits = ExtractionLimits::default();
            // This is a decoder contract test; leave production's 50 ms limit
            // intact while preventing parallel scheduler contention from
            // converting the semantic result into a timeout.
            limits.timeout_ms = 5_000;
            for cmd in [
                format!("powershell -EncodedCommand {enc}"),
                format!("powershell -enc {enc}"),
                format!("pwsh -e {enc}"),
                // Flags that take a VALUE before the encoded flag (the canonical
                // obfuscation form) must not defeat extraction.
                format!("powershell -ExecutionPolicy Bypass -EncodedCommand {enc}"),
                format!("powershell -WindowStyle Hidden -nop -enc {enc}"),
                format!("pwsh -ExecutionPolicy Bypass -NoProfile -e {enc}"),
            ] {
                let result = extract_content(&cmd, &limits);
                let ExtractionResult::Extracted(contents) = result else {
                    panic!("expected Extracted for {cmd}");
                };
                assert!(
                    contents
                        .iter()
                        .any(|c| c.content == r"Remove-Item -Recurse -Force C:\src"),
                    "decoded mismatch for {cmd}: {contents:?}"
                );
            }
        }

        #[test]
        fn extracts_powershell_command_after_value_flag() {
            // `powershell -ExecutionPolicy Bypass -Command "..."` is the canonical
            // way to invoke an inline payload; a value-taking flag before -Command
            // must not break the inline-script extraction.
            for cmd in [
                r#"powershell -ExecutionPolicy Bypass -Command "Remove-Item -Recurse -Force C:\src""#,
                r"powershell -ExecutionPolicy Bypass -NoProfile -Command 'rd /s /q C:\src'",
                r#"pwsh -WindowStyle Hidden -Command "del /s /q C:\src""#,
            ] {
                let result = extract_content(cmd, &ExtractionLimits::default());
                let ExtractionResult::Extracted(contents) = result else {
                    panic!("expected Extracted for {cmd}");
                };
                assert!(
                    contents.iter().any(|c| !c.content.is_empty()
                        && (c.content.contains("Remove-Item")
                            || c.content.contains("rd ")
                            || c.content.contains("del "))),
                    "no inline body extracted for {cmd}: {contents:?}"
                );
            }
        }

        #[test]
        fn value_flag_skip_does_not_falsely_extract_script_arg() {
            // A SCRIPT positional (it has an extension) must NOT be mistaken for a
            // boolean flag's value, or we'd falsely extract an inline flag that is
            // really a positional arg to the script — the interpreter runs the
            // SCRIPT, not the `-c`/`-e`. (Scripts whose extension is itself a shell
            // name — *.sh/.bash/.zsh/.fish — match the interpreter alternation via a
            // separate, pre-existing suffix boundary, so they are avoided here to
            // isolate the value-flag-skip behavior under test.)
            for cmd in [
                r#"node script.js -e "evil()""#,
                r#"bash -x deploy.bin -c "rm -rf /etc""#,
                r#"python -v mymodule.py -c "import os""#,
            ] {
                let result = extract_content(cmd, &ExtractionLimits::default());
                if let ExtractionResult::Extracted(contents) = result {
                    assert!(
                        !contents.iter().any(|c| c.content.contains("evil")
                            || c.content.contains("rm -rf")
                            || c.content.contains("import os")),
                        "must not extract an inline flag that is a positional arg to a script: {cmd} -> {contents:?}"
                    );
                }
            }
        }

        #[test]
        fn non_bareword_flag_value_does_not_defeat_extraction() {
            // A value-taking interpreter flag whose value is NOT a clean bareword —
            // it starts with a digit (`4096`, `5.1`) or contains `:`/`/`/`\`
            // (`ignore::DeprecationWarning`, `ts-node/register`, `/etc/profile`) —
            // must still be skipped so the inline `-c`/`-e`/`-Command`/`-EncodedCommand`
            // after it is extracted. These are canonical real-world obfuscations
            // (Python `-W` filters, Node `-r` loaders / `--max-old-space-size`, bash
            // `--rcfile`, PowerShell `-ExecutionPolicy`/`-Version`); a bareword-only
            // value token silently let them slip past Tier-1/Tier-2 (an UNDER-block).
            // The companion guard `value_flag_skip_does_not_falsely_extract_script_arg`
            // proves a bare `name.ext` script positional is still NOT skipped.
            //
            // The last two cases cover ATTACHED (no-space) short-flag values
            // (`-MFile::Spec`, `-i.bak`) — the short-flag token consumes a trailing
            // `:`/`.`/`=` value so they don't defeat the inline `-e` either.
            let enc = "UgBlAG0AbwB2AGUALQBJAHQAZQBtACAALQBSAGUAYwB1AHIAcwBlACAALQBGAG8AcgBjAGUAIABDADoAXABzAHIAYwA=";
            let cases: [(String, &str); 9] = [
                (
                    r#"python -W ignore::DeprecationWarning -c "import shutil; shutil.rmtree('/home/user')""#.to_string(),
                    "shutil.rmtree",
                ),
                (
                    r#"node --max-old-space-size 4096 -e "require('child_process').execSync('rm -rf /')""#.to_string(),
                    "execSync",
                ),
                (
                    r#"node -r ts-node/register -e "doEvil()""#.to_string(),
                    "doEvil",
                ),
                (
                    r#"bash --rcfile /etc/profile -c "rm -rf /etc""#.to_string(),
                    "rm -rf",
                ),
                (
                    r#"ruby -r ./lib/foo -e "FileUtils.rm_rf('/home/user')""#.to_string(),
                    "rm_rf",
                ),
                (
                    r#"powershell -Version 5.1 -Command "Remove-Item -Recurse -Force C:\src""#.to_string(),
                    "Remove-Item",
                ),
                (
                    format!("powershell -ExecutionPolicy Unrestricted -EncodedCommand {enc}"),
                    "Remove-Item",
                ),
                (
                    r#"perl -MFile::Spec -e "system('rm -rf /home/user')""#.to_string(),
                    "system",
                ),
                (
                    r#"perl -i.bak -e "unlink glob('*')""#.to_string(),
                    "unlink",
                ),
            ];
            for (cmd, needle) in &cases {
                let result = extract_content(cmd, &ExtractionLimits::default());
                let ExtractionResult::Extracted(contents) = result else {
                    panic!("expected Extracted for {cmd}");
                };
                assert!(
                    contents.iter().any(|c| c.content.contains(*needle)),
                    "non-bareword flag value defeated extraction for {cmd}: {contents:?}"
                );
            }
        }

        #[test]
        fn decode_powershell_encoded_command_roundtrip_and_failopen() {
            let enc = "UgBlAG0AbwB2AGUALQBJAHQAZQBtACAALQBSAGUAYwB1AHIAcwBlACAALQBGAG8AcgBjAGUAIABDADoAXABzAHIAYwA=";
            assert_eq!(
                decode_powershell_encoded_command(enc).as_deref(),
                Some(r"Remove-Item -Recurse -Force C:\src")
            );
            // Fail-open on garbage / empty input.
            assert_eq!(decode_powershell_encoded_command("!!!not-base64!!!"), None);
            assert_eq!(decode_powershell_encoded_command(""), None);
        }

        #[test]
        fn windows_wrappers_trigger_tier1() {
            for cmd in [
                r#"cmd /c "del x""#,
                "cmd /k whatever",
                r#"iex "x""#,
                r#"Invoke-Expression "x""#,
                "powershell -EncodedCommand QQBhAA==",
            ] {
                assert_eq!(
                    check_triggers(cmd),
                    TriggerResult::Triggered,
                    "should trigger Tier 1: {cmd}"
                );
            }
        }

        #[test]
        fn iexplore_does_not_falsely_trigger_iex() {
            // The `iex` alias must be a standalone token, not a prefix of `iexplore`.
            assert_eq!(
                check_triggers("start iexplore.exe https://example.com"),
                TriggerResult::NoTrigger
            );
        }

        #[test]
        fn extracts_inline_script_with_intervening_flags() {
            let result = extract_content("python -I -c 'import os'", &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "import os");
                assert_eq!(contents[0].language, ScriptLanguage::Python);
                assert!(contents[0].quoted);
            } else {
                panic!("Expected Extracted result");
            }
        }

        #[test]
        fn extracts_inline_script_with_combined_shell_flags() {
            let result = extract_content("bash -lc 'echo hello'", &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "echo hello");
                assert_eq!(contents[0].language, ScriptLanguage::Bash);
            } else {
                panic!("Expected Extracted result");
            }
        }

        #[test]
        fn extracts_inline_script_with_combined_node_flags() {
            let result =
                extract_content("node -pe 'process.version'", &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "process.version");
                assert_eq!(contents[0].language, ScriptLanguage::JavaScript);
            } else {
                panic!("Expected Extracted result");
            }
        }

        #[test]
        fn extracts_inline_script_with_interleaved_perl_flags() {
            let result = extract_content("perl -pi -e 'print 1'", &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "print 1");
                assert_eq!(contents[0].language, ScriptLanguage::Perl);
            } else {
                panic!("Expected Extracted result");
            }
        }

        /// #125: Codex on Windows executes shell commands as
        /// `powershell.exe -Command '<inner>'`. dcg must descend into the
        /// `-Command` body and re-evaluate it as a shell command (mapped to
        /// `ScriptLanguage::Bash`) so destructive inner commands are caught.
        #[test]
        fn extracts_powershell_command_body() {
            // Bare host name, single-quoted body.
            let result = extract_content(
                "powershell -Command 'echo hi'",
                &ExtractionLimits::default(),
            );
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "echo hi");
                assert_eq!(contents[0].language, ScriptLanguage::Bash);
            } else {
                panic!("Expected Extracted result for `powershell -Command '...'`");
            }
        }

        #[test]
        fn extracts_powershell_exe_command_body_double_quotes() {
            let result = extract_content(
                r#"powershell.exe -Command "echo hi""#,
                &ExtractionLimits::default(),
            );
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "echo hi");
                assert_eq!(contents[0].language, ScriptLanguage::Bash);
            } else {
                panic!("Expected Extracted result for `powershell.exe -Command \"...\"`");
            }
        }

        #[test]
        fn extracts_pwsh_short_flag_body() {
            // PowerShell accepts `-c` as an abbreviation of `-Command`.
            let result = extract_content("pwsh -c 'echo hi'", &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "echo hi");
                assert_eq!(contents[0].language, ScriptLanguage::Bash);
            } else {
                panic!("Expected Extracted result for `pwsh -c '...'`");
            }
        }

        #[test]
        fn extracts_powershell_quoted_full_path_body() {
            // Codex's exact Windows command_execution shape: a quoted absolute
            // path to powershell.exe followed by -Command and the inner command.
            let cmd = "\"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -Command 'echo hi'";
            // This test asserts extraction metadata, not the production
            // deadline. Give it a deterministic budget under parallel test
            // scheduler pressure; dedicated timeout tests cover the 50 ms
            // default and bounded fallback behavior.
            let limits = ExtractionLimits {
                timeout_ms: 5_000,
                ..ExtractionLimits::default()
            };
            let result = extract_content(cmd, &limits);
            if let ExtractionResult::Extracted(contents) = result {
                assert!(
                    contents
                        .iter()
                        .any(|c| c.content == "echo hi" && c.language == ScriptLanguage::Bash),
                    "expected to extract the -Command body from a quoted powershell.exe path; got {contents:?}"
                );
            } else {
                panic!("Expected Extracted result for quoted-full-path powershell.exe -Command");
            }
        }

        #[test]
        fn extracts_here_string() {
            let result = extract_content("cat <<< 'hello world'", &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "hello world");
                assert_eq!(contents[0].heredoc_type, Some(HeredocType::HereString));
            } else {
                panic!("Expected Extracted result");
            }
        }

        #[test]
        fn extracts_heredoc_basic() {
            let cmd = "cat << EOF\nline1\nline2\nEOF";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "line1\nline2");
                assert_eq!(contents[0].delimiter, Some("EOF".to_string()));
                assert_eq!(contents[0].heredoc_type, Some(HeredocType::Standard));
            } else {
                panic!("Expected Extracted result, got {result:?}");
            }
        }

        #[test]
        fn extracts_heredoc_ignores_trailing_tokens_on_delimiter_line() {
            let cmd = "python3 <<EOF | cat\nimport shutil\nshutil.rmtree('/tmp/test')\nEOF";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].language, ScriptLanguage::Python);
                assert_eq!(
                    contents[0].content,
                    "import shutil\nshutil.rmtree('/tmp/test')"
                );
            } else {
                panic!("Expected Extracted result, got {result:?}");
            }
        }

        #[test]
        fn extracts_heredoc_with_crlf_line_endings() {
            let cmd = "cat <<EOF\r\nline1\r\nEOF\r\n";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "line1");
                assert_eq!(contents[0].delimiter.as_deref(), Some("EOF"));
            } else {
                panic!("Expected Extracted result, got {result:?}");
            }
        }

        #[test]
        fn extracts_heredoc_tab_stripped() {
            let cmd = "cat <<- EOF\n\tline1\n\tline2\nEOF";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                // Tab-stripping removes leading tabs
                assert_eq!(contents[0].content, "line1\nline2");
                assert_eq!(contents[0].heredoc_type, Some(HeredocType::TabStripped));
            } else {
                panic!("Expected Extracted result");
            }
        }

        #[test]
        fn extracts_heredoc_indent_stripped() {
            // Indentation-stripping heredoc (<<~) should:
            // - accept an indented terminator
            // - strip the minimum common indentation from non-empty lines
            let cmd = "cat <<~ EOF\n    line1\n    line2\n    EOF";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "line1\nline2");
                assert_eq!(contents[0].heredoc_type, Some(HeredocType::IndentStripped));
            } else {
                panic!("Expected Extracted result, got {result:?}");
            }
        }

        #[test]
        fn indent_stripped_heredoc_does_not_panic_on_multibyte_whitespace() {
            // Regression: <<~ stripped `min_indent` BYTES off each line.
            // If one line uses ASCII spaces (1 byte each) and another uses
            // a multi-byte whitespace char (NBSP = 2 bytes, U+3000 = 3
            // bytes), the byte offset can land in the middle of a UTF-8
            // codepoint and panic the slice. Under release `panic = "abort"`
            // that crashes the hook process — a fail-open violation.
            //
            // Each of these inputs would previously have triggered a
            // `byte index N is not a char boundary` panic; after the fix
            // they all extract successfully (with the conservative
            // fallback of `trim_start()` on lines whose byte offset
            // doesn't align to a char boundary).
            let cases: &[&str] = &[
                // ASCII line + NBSP-prefixed line. min_indent in bytes
                // would be 2 (NBSP); slicing the 4-space line at byte 2
                // is char-aligned so this case is safe — but the
                // ideographic-space variant below is not.
                "cat <<~ EOF\n  line1\n\u{00A0}line2\n  EOF",
                // ASCII + ideographic space. U+3000 is 3 bytes; min_indent
                // could be 2 (the ASCII line) and slicing `\u{3000}f` at
                // byte 2 lands inside the codepoint.
                "cat <<~ EOF\n  line1\n\u{3000}foo\n  EOF",
                // Two multi-byte whitespace lines with different sequence
                // lengths. min_indent picks the shorter byte-count; the
                // longer-prefixed line's byte offset misaligns.
                "cat <<~ EOF\n\u{00A0}line1\n\u{3000}line2\nEOF",
            ];
            for cmd in cases {
                let result = extract_content(cmd, &ExtractionLimits::default());
                // Whether content is "Extracted" or "NoContent" depends on
                // what the upstream parser did; the only invariant we care
                // about is "no panic, returns a value." Using a method
                // call ensures we touch the result.
                let _ = format!("{result:?}");
            }
        }

        #[test]
        fn extracts_heredoc_quoted_delimiter_sets_quoted_flag() {
            // Quoted delimiter suppresses expansion in real shells; we track this for context.
            let cmd = "cat << 'EOF'\nline1\nEOF";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "line1");
                assert_eq!(contents[0].delimiter.as_deref(), Some("EOF"));
                assert!(contents[0].quoted, "quoted delimiter must set quoted=true");
            } else {
                panic!("Expected Extracted result, got {result:?}");
            }

            let cmd = "cat << EOF\nline1\nEOF";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert!(
                    !contents[0].quoted,
                    "unquoted delimiter must set quoted=false"
                );
            } else {
                panic!("Expected Extracted result, got {result:?}");
            }
        }

        // Regression test for issue #109: bash accepts `<<- 'EOF'` (with a
        // space after the `-` tab-strip marker). Before the fix, the
        // delimiter parser fell through to the unquoted branch with a
        // leading space and bailed, leaving the heredoc body unmasked so
        // pack matching denied dangerous-looking prose like "gh repo
        // delete" inside `cat <<- 'EOF'`. All four spaced/non-spaced and
        // single/double-quoted forms must extract the same delimiter.
        #[test]
        fn extracts_heredoc_tab_stripped_quoted_with_space_after_dash() {
            for (form, cmd) in [
                ("<<-'EOF'", "cat <<-'EOF'\n\tgh repo delete\n\tEOF"),
                ("<<- 'EOF'", "cat <<- 'EOF'\n\tgh repo delete\n\tEOF"),
                ("<<-\"EOF\"", "cat <<-\"EOF\"\n\tgh repo delete\n\tEOF"),
                ("<<- \"EOF\"", "cat <<- \"EOF\"\n\tgh repo delete\n\tEOF"),
                ("<<~ 'EOF'", "cat <<~ 'EOF'\n\tgh repo delete\n\tEOF"),
            ] {
                let result = extract_content(cmd, &ExtractionLimits::default());
                let ExtractionResult::Extracted(contents) = result else {
                    panic!("Expected extraction for {form}, got {result:?}");
                };
                assert_eq!(
                    contents.len(),
                    1,
                    "{form}: expected single heredoc extraction"
                );
                assert_eq!(
                    contents[0].delimiter.as_deref(),
                    Some("EOF"),
                    "{form}: delimiter must parse to EOF"
                );
                assert!(
                    contents[0].quoted,
                    "{form}: quoted delimiter must set quoted=true"
                );
            }
        }

        // Reviewer-eyes catch from the #109 follow-up: bash treats whitespace
        // before the marker character as a hard divider, so `cat << -EOF`
        // (note the space *before* the dash) is a Standard heredoc whose
        // delimiter is the literal `-EOF`, not a tab-stripped heredoc with
        // delimiter `EOF`. Pre-fix the parser would mis-classify, the
        // terminator search would look for a line `EOF` rather than `-EOF`,
        // and the heredoc body would either run past the real terminator
        // or never close. The `~` variant cannot reach this path because
        // the unquoted-delimiter regex char class is `[\w.-]+` (no tilde),
        // so `<< ~FOO` is rejected by the regex before parse_heredoc_delimiter
        // runs — only the dash variant is reachable.
        #[test]
        fn parses_dash_after_space_as_part_of_unquoted_delimiter() {
            let cmd = "cat << -EOF\nbody line\n-EOF";
            let result = extract_content(cmd, &ExtractionLimits::default());
            let ExtractionResult::Extracted(contents) = result else {
                panic!("Expected extraction, got {result:?}");
            };
            assert_eq!(contents.len(), 1, "expected single heredoc extraction");
            assert_eq!(
                contents[0].delimiter.as_deref(),
                Some("-EOF"),
                "delimiter must include the leading dash when there is whitespace before it"
            );
            assert!(
                !contents[0].quoted,
                "unquoted delimiter must set quoted=false"
            );
        }

        // The mask path (`mask_non_executing_heredocs`) and the regex
        // extraction path (`extract_heredocs`) must agree on heredoc type.
        // The extractor maps `<<~` -> IndentStripped; if the masker maps
        // it to TabStripped instead, a space-indented terminator like
        // `  EOF` is never recognized (TabStripped only trims `\t`), the
        // body escapes masking, and pack matching produces false positives
        // on prose like `rm -rf /` inside `cat <<~EOF` documentation.
        #[test]
        fn masks_indent_stripped_heredoc_body_with_space_indented_terminator() {
            let cmd = "cat <<~EOF\n  rm -rf /\n  EOF";
            let masked = mask_non_executing_heredocs(cmd);
            assert!(
                matches!(masked, std::borrow::Cow::Owned(_)),
                "expected the body to be masked (Cow::Owned), got Borrowed: {masked:?}"
            );
            assert!(
                !masked.contains("rm -rf /"),
                "masked output still contains body: {masked:?}"
            );
            // The spaced-quoted form must mask too — same path with extra
            // whitespace between the marker and the delimiter (issue #109
            // coverage).
            let cmd = "cat <<~ 'EOF'\n  rm -rf /\n  EOF";
            let masked = mask_non_executing_heredocs(cmd);
            assert!(
                matches!(masked, std::borrow::Cow::Owned(_)),
                "expected the body to be masked (Cow::Owned), got Borrowed: {masked:?}"
            );
            assert!(
                !masked.contains("rm -rf /"),
                "masked output still contains body: {masked:?}"
            );
        }

        #[test]
        fn heredoc_language_detects_interpreter_prefixes() {
            // Regression test: heredoc bodies must not default to Bash when the interpreter is explicit.
            let cases = [
                ("python3 <<EOF\nprint('hello')\nEOF", ScriptLanguage::Python),
                (
                    "node <<EOF\nconsole.log('hello');\nEOF",
                    ScriptLanguage::JavaScript,
                ),
                ("ruby <<EOF\nputs 'hello'\nEOF", ScriptLanguage::Ruby),
                ("perl <<EOF\nprint \"hello\";\nEOF", ScriptLanguage::Perl),
                ("bash <<EOF\necho hello\nEOF", ScriptLanguage::Bash),
            ];

            for (cmd, expected) in cases {
                let result = extract_content(cmd, &ExtractionLimits::default());
                if let ExtractionResult::Extracted(contents) = result {
                    assert_eq!(
                        contents.len(),
                        1,
                        "expected one heredoc extraction for: {cmd}"
                    );
                    assert_eq!(
                        contents[0].language, expected,
                        "expected language {expected:?} for heredoc: {cmd}"
                    );
                } else {
                    panic!("Expected Extracted result for heredoc: {cmd}, got {result:?}");
                }
            }
        }

        #[test]
        fn heredoc_language_detects_shebang_when_command_unknown() {
            let cmd = "cat <<EOF\n#!/usr/bin/env python3\nimport os\nprint('hi')\nEOF";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].language, ScriptLanguage::Python);
            } else {
                panic!("Expected Extracted result, got {result:?}");
            }
        }

        #[test]
        fn extracts_empty_heredoc() {
            // Empty heredoc is valid - body is empty but terminator is found
            let cmd = "cat << EOF\nEOF";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "");
                assert_eq!(contents[0].delimiter, Some("EOF".to_string()));
            } else {
                panic!("Expected Extracted result for empty heredoc, got {result:?}");
            }
        }

        #[test]
        fn heredoc_byte_range_is_correct() {
            // Test non-empty heredoc byte_range
            let cmd = "python << END\nprint(1)\nEND";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].language, ScriptLanguage::Python);
                let range = &contents[0].byte_range;
                // byte_range should cover from "<< END" to the final "END"
                let extracted_span = &cmd[range.clone()];
                assert_eq!(extracted_span, "<< END\nprint(1)\nEND");
            } else {
                panic!("Expected Extracted result");
            }

            // Test empty heredoc byte_range
            let cmd = "cat << EOF\nEOF";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                let range = &contents[0].byte_range;
                let extracted_span = &cmd[range.clone()];
                assert_eq!(extracted_span, "<< EOF\nEOF");
            } else {
                panic!("Expected Extracted result");
            }

            // Test multi-line heredoc byte_range
            let cmd = "cat << EOF\nline1\nline2\nEOF";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                let range = &contents[0].byte_range;
                let extracted_span = &cmd[range.clone()];
                assert_eq!(extracted_span, "<< EOF\nline1\nline2\nEOF");
            } else {
                panic!("Expected Extracted result");
            }
        }

        #[test]
        fn extracts_here_string_with_nested_quotes() {
            // Here-string with double quotes inside single quotes
            let result = extract_content(
                r#"cat <<< 'hello "world" test'"#,
                &ExtractionLimits::default(),
            );
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, r#"hello "world" test"#);
                assert!(contents[0].quoted);
            } else {
                panic!("Expected Extracted result");
            }

            // Here-string with single quotes inside double quotes
            let result = extract_content(
                r#"cat <<< "hello 'world' test""#,
                &ExtractionLimits::default(),
            );
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 1);
                assert_eq!(contents[0].content, "hello 'world' test");
                assert!(contents[0].quoted);
            } else {
                panic!("Expected Extracted result");
            }
        }

        #[test]
        fn from_command_does_not_false_positive() {
            // These should NOT be detected as interpreters
            assert_eq!(
                ScriptLanguage::from_command("shebang"),
                ScriptLanguage::Unknown
            );
            assert_eq!(
                ScriptLanguage::from_command("shell"),
                ScriptLanguage::Unknown
            );
            assert_eq!(
                ScriptLanguage::from_command("pythonic"),
                ScriptLanguage::Unknown
            );
            assert_eq!(
                ScriptLanguage::from_command("nodemon"),
                ScriptLanguage::Unknown
            );
            assert_eq!(
                ScriptLanguage::from_command("perldoc"),
                ScriptLanguage::Unknown
            );
            assert_eq!(
                ScriptLanguage::from_command("bashful"),
                ScriptLanguage::Unknown
            );
        }

        #[test]
        fn from_command_matches_versioned_interpreters() {
            // These SHOULD be detected with version suffixes
            assert_eq!(
                ScriptLanguage::from_command("python3"),
                ScriptLanguage::Python
            );
            assert_eq!(
                ScriptLanguage::from_command("python3.11"),
                ScriptLanguage::Python
            );
            assert_eq!(
                ScriptLanguage::from_command("python3.11.4"),
                ScriptLanguage::Python
            );
            assert_eq!(
                ScriptLanguage::from_command("node18"),
                ScriptLanguage::JavaScript
            );
            assert_eq!(ScriptLanguage::from_command("perl5"), ScriptLanguage::Perl);
        }

        #[test]
        fn no_content_on_safe_command() {
            let result = extract_content("git status", &ExtractionLimits::default());
            assert!(matches!(result, ExtractionResult::NoContent));
        }

        #[test]
        fn script_language_from_command() {
            assert_eq!(
                ScriptLanguage::from_command("python3"),
                ScriptLanguage::Python
            );
            assert_eq!(ScriptLanguage::from_command("ruby"), ScriptLanguage::Ruby);
            assert_eq!(ScriptLanguage::from_command("perl"), ScriptLanguage::Perl);
            assert_eq!(
                ScriptLanguage::from_command("node"),
                ScriptLanguage::JavaScript
            );
            assert_eq!(ScriptLanguage::from_command("bash"), ScriptLanguage::Bash);
            assert_eq!(
                ScriptLanguage::from_command("unknown"),
                ScriptLanguage::Unknown
            );
        }

        // =========================================================================
        // Language detection tests (git_safety_guard-du4)
        // =========================================================================

        #[test]
        fn from_shebang_detects_direct_path() {
            assert_eq!(
                ScriptLanguage::from_shebang("#!/bin/bash\necho hello"),
                Some(ScriptLanguage::Bash)
            );
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/python\nimport os"),
                Some(ScriptLanguage::Python)
            );
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/ruby\nputs 'hi'"),
                Some(ScriptLanguage::Ruby)
            );
        }

        #[test]
        fn from_shebang_detects_env_path() {
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/env python3\nimport sys"),
                Some(ScriptLanguage::Python)
            );
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/env node\nconsole.log('hi')"),
                Some(ScriptLanguage::JavaScript)
            );
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/env perl\nprint 'hello'"),
                Some(ScriptLanguage::Perl)
            );
        }

        #[test]
        fn from_shebang_returns_none_for_invalid() {
            // No shebang
            assert_eq!(ScriptLanguage::from_shebang("import os"), None);
            // Empty shebang
            assert_eq!(ScriptLanguage::from_shebang("#!\ncode"), None);
            // Unknown interpreter
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/unknown\ncode"),
                None
            );
        }

        #[test]
        fn from_shebang_ignores_interpreter_flags() {
            // Direct path with flags
            assert_eq!(
                ScriptLanguage::from_shebang("#!/bin/bash -e\nset -x"),
                Some(ScriptLanguage::Bash)
            );
            assert_eq!(
                ScriptLanguage::from_shebang("#!/bin/bash -ex\necho hello"),
                Some(ScriptLanguage::Bash)
            );
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/python3 -u\nimport sys"),
                Some(ScriptLanguage::Python)
            );

            // Env-style with flags
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/env python3 -u\nimport sys"),
                Some(ScriptLanguage::Python)
            );
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/env bash -e\necho hi"),
                Some(ScriptLanguage::Bash)
            );
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/env ruby -w\nputs 'hi'"),
                Some(ScriptLanguage::Ruby)
            );
        }

        #[test]
        fn from_shebang_handles_env_flags() {
            // env -S splits remaining arguments (GNU coreutils 8.30+)
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/env -S python3 -u\nimport sys"),
                Some(ScriptLanguage::Python)
            );
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/env -S bash -e\necho hi"),
                Some(ScriptLanguage::Bash)
            );

            // env -i ignores environment
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/env -i python3\nimport os"),
                Some(ScriptLanguage::Python)
            );

            // Multiple env flags
            assert_eq!(
                ScriptLanguage::from_shebang("#!/usr/bin/env -i -S perl -w\nuse strict;"),
                Some(ScriptLanguage::Perl)
            );
        }

        #[test]
        fn from_content_detects_python() {
            assert_eq!(
                ScriptLanguage::from_content("import os\nos.remove('file')"),
                Some(ScriptLanguage::Python)
            );
            assert_eq!(
                ScriptLanguage::from_content("from pathlib import Path\nPath('x').unlink()"),
                Some(ScriptLanguage::Python)
            );
        }

        #[test]
        fn from_content_detects_javascript() {
            assert_eq!(
                ScriptLanguage::from_content("const fs = require('fs');\nfs.rm('x');"),
                Some(ScriptLanguage::JavaScript)
            );
            assert_eq!(
                ScriptLanguage::from_content("let x = 5;\nconsole.log(x);"),
                Some(ScriptLanguage::JavaScript)
            );
        }

        #[test]
        fn from_content_detects_typescript() {
            assert_eq!(
                ScriptLanguage::from_content("const x: string = 'hello';"),
                Some(ScriptLanguage::TypeScript)
            );
            assert_eq!(
                ScriptLanguage::from_content("interface User { name: string }"),
                Some(ScriptLanguage::TypeScript)
            );
        }

        #[test]
        fn from_content_detects_ruby() {
            // Ruby needs 'end' to reduce false positives
            assert_eq!(
                ScriptLanguage::from_content("def hello\n  puts 'hi'\nend"),
                Some(ScriptLanguage::Ruby)
            );
            assert_eq!(
                ScriptLanguage::from_content("require 'fileutils'\nFileUtils.rm_rf('x')\nend"),
                Some(ScriptLanguage::Ruby)
            );
        }

        #[test]
        fn from_content_detects_perl() {
            assert_eq!(
                ScriptLanguage::from_content("use strict;\nmy $x = 5;"),
                Some(ScriptLanguage::Perl)
            );
            assert_eq!(
                ScriptLanguage::from_content("my @arr = (1,2,3);"),
                Some(ScriptLanguage::Perl)
            );
        }

        #[test]
        fn from_content_detects_bash() {
            assert_eq!(
                ScriptLanguage::from_content("if [ -f file ]; then\n  echo 'exists'\nfi"),
                Some(ScriptLanguage::Bash)
            );
            assert_eq!(
                ScriptLanguage::from_content("x=$((1+2))\necho ${x}"),
                Some(ScriptLanguage::Bash)
            );
        }

        #[test]
        fn from_content_returns_none_for_unknown() {
            assert_eq!(ScriptLanguage::from_content("hello world"), None);
            assert_eq!(ScriptLanguage::from_content(""), None);
        }

        #[test]
        fn detect_uses_command_prefix_first() {
            // Even with Python shebang, command should take precedence
            let (lang, confidence) =
                ScriptLanguage::detect("ruby -e 'code'", "#!/usr/bin/python\nimport os");
            assert_eq!(lang, ScriptLanguage::Ruby);
            assert_eq!(confidence, DetectionConfidence::CommandPrefix);
        }

        #[test]
        fn detect_uses_shebang_second() {
            // No command interpreter, but has shebang
            let (lang, confidence) =
                ScriptLanguage::detect("cat script.sh", "#!/bin/bash\necho hello");
            assert_eq!(lang, ScriptLanguage::Bash);
            assert_eq!(confidence, DetectionConfidence::Shebang);
        }

        #[test]
        fn detect_uses_content_heuristics_third() {
            // No command interpreter, no shebang, but has Python imports
            let (lang, confidence) =
                ScriptLanguage::detect("cat script", "import os\nos.remove('x')");
            assert_eq!(lang, ScriptLanguage::Python);
            assert_eq!(confidence, DetectionConfidence::ContentHeuristics);
        }

        #[test]
        fn detect_returns_unknown_for_unrecognized() {
            let (lang, confidence) = ScriptLanguage::detect("cat file.txt", "hello world");
            assert_eq!(lang, ScriptLanguage::Unknown);
            assert_eq!(confidence, DetectionConfidence::Unknown);
        }

        #[test]
        fn detect_handles_env_prefix() {
            let (lang, confidence) = ScriptLanguage::detect("env python3 -c 'code'", "");
            assert_eq!(lang, ScriptLanguage::Python);
            assert_eq!(confidence, DetectionConfidence::CommandPrefix);
        }

        #[test]
        fn detect_handles_absolute_path() {
            let (lang, confidence) = ScriptLanguage::detect("/usr/bin/python3 -c 'code'", "");
            assert_eq!(lang, ScriptLanguage::Python);
            assert_eq!(confidence, DetectionConfidence::CommandPrefix);
        }

        #[test]
        fn detection_confidence_labels() {
            assert_eq!(DetectionConfidence::CommandPrefix.label(), "command-prefix");
            assert_eq!(DetectionConfidence::Shebang.label(), "shebang");
            assert_eq!(
                DetectionConfidence::ContentHeuristics.label(),
                "content-heuristics"
            );
            assert_eq!(DetectionConfidence::Unknown.label(), "unknown");
        }

        #[test]
        fn detection_confidence_reasons() {
            assert!(
                DetectionConfidence::CommandPrefix
                    .reason()
                    .contains("highest")
            );
            assert!(DetectionConfidence::Shebang.reason().contains("high"));
            assert!(
                DetectionConfidence::ContentHeuristics
                    .reason()
                    .contains("lower")
            );
            assert!(DetectionConfidence::Unknown.reason().contains("could not"));
        }

        #[test]
        fn enforces_max_body_bytes() {
            let large_content = "x".repeat(2_000_000); // 2MB
            let cmd = format!("python -c '{large_content}'");
            let limits = ExtractionLimits {
                max_body_bytes: 1_000_000, // 1MB limit
                ..Default::default()
            };
            let result = extract_content(&cmd, &limits);
            // Should return Skipped with size limit reason
            match result {
                ExtractionResult::Skipped(reasons) => {
                    assert!(
                        reasons
                            .iter()
                            .any(|r| matches!(r, SkipReason::ExceededSizeLimit { .. }))
                    );
                }
                ExtractionResult::NoContent
                | ExtractionResult::Failed(_)
                | ExtractionResult::Partial { .. } => {}
                ExtractionResult::Extracted(contents) => {
                    // If extracted, content should be within limits
                    for c in contents {
                        assert!(c.content.len() <= limits.max_body_bytes);
                    }
                }
            }
        }

        #[test]
        fn extracts_multiple_inline_scripts() {
            let cmd = "python -c 'code1' && ruby -e 'code2'";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 2);
                assert_eq!(contents[0].content, "code1");
                assert_eq!(contents[1].content, "code2");
            } else {
                panic!("Expected Extracted result");
            }
        }

        #[test]
        fn extracts_versioned_interpreter_scripts() {
            // Tier 2 must extract content from versioned interpreters
            let cmd = "python3.11 -c 'import os' && nodejs18 -e 'console.log(1)'";
            let result = extract_content(cmd, &ExtractionLimits::default());
            if let ExtractionResult::Extracted(contents) = result {
                assert_eq!(contents.len(), 2, "should extract both scripts");
                assert_eq!(contents[0].content, "import os");
                assert_eq!(contents[0].language, ScriptLanguage::Python);
                assert_eq!(contents[1].content, "console.log(1)");
                assert_eq!(contents[1].language, ScriptLanguage::JavaScript);
            } else {
                panic!("Expected Extracted result for versioned interpreters, got {result:?}");
            }
        }

        // ====================================================================
        // Robustness Tests (git_safety_guard-rbst)
        // ====================================================================

        #[test]
        fn skips_binary_content_with_null_bytes() {
            // Content with null bytes should be detected as binary
            let cmd = "python -c '\x00binary\x00content'";
            if let Some(reason) = check_binary_content(cmd) {
                assert!(
                    matches!(reason, SkipReason::BinaryContent { null_bytes, .. } if null_bytes > 0)
                );
            } else {
                panic!("Expected binary content detection");
            }
        }

        #[test]
        fn skips_binary_content_high_non_printable() {
            // Content with high ratio of non-printable bytes
            let binary_bytes: Vec<u8> = (0u8..50).chain(200u8..255).collect();
            let binary_str = String::from_utf8_lossy(&binary_bytes);
            if let Some(reason) = check_binary_content(&binary_str) {
                assert!(matches!(reason, SkipReason::BinaryContent { .. }));
            } else {
                panic!("Expected binary content detection for high non-printable ratio");
            }
        }

        #[test]
        fn allows_normal_text_content() {
            let normal_content = "import os\nprint('hello world')\nfor i in range(10): pass";
            assert!(check_binary_content(normal_content).is_none());
        }

        #[test]
        fn tracks_unterminated_heredoc() {
            let cmd = "cat << EOF\nunterminated content without closing delimiter";
            let result = extract_content(cmd, &ExtractionLimits::default());
            match result {
                ExtractionResult::Skipped(reasons) => {
                    assert!(
                        reasons
                            .iter()
                            .any(|r| matches!(r, SkipReason::UnterminatedHeredoc { .. })),
                        "should report UnterminatedHeredoc, not ExceededSizeLimit"
                    );
                }
                _ => panic!("Expected Skipped result for unterminated heredoc"),
            }
        }

        #[test]
        fn heredoc_body_line_limit_reports_exceeded_line_limit() {
            let cmd = "cat << EOF\nline1\nline2\nline3\nEOF";
            let limits = ExtractionLimits {
                max_body_lines: 2,
                ..Default::default()
            };

            let result = extract_content(cmd, &limits);
            match result {
                ExtractionResult::Skipped(reasons) => {
                    assert!(
                        reasons
                            .iter()
                            .any(|r| matches!(r, SkipReason::ExceededLineLimit { .. })),
                        "should report ExceededLineLimit, not UnterminatedHeredoc"
                    );
                }
                _ => panic!("Expected Skipped result for line-limited heredoc, got {result:?}"),
            }
        }

        #[test]
        fn extraction_timeout_is_enforced() {
            let cmd = "cat << EOF\nline1\nEOF";
            let limits = ExtractionLimits {
                timeout_ms: 0,
                ..Default::default()
            };

            let result = extract_content(cmd, &limits);
            match result {
                ExtractionResult::Skipped(reasons) => {
                    assert!(
                        reasons
                            .iter()
                            .any(|r| matches!(r, SkipReason::Timeout { .. })),
                        "should include a Timeout skip reason"
                    );
                }
                _ => panic!("Expected Skipped(timeout) result, got {result:?}"),
            }
        }

        #[test]
        fn enforces_heredoc_limit() {
            // Create a command with many heredocs
            let cmd = "cmd1 << A\na\nA && cmd2 << B\nb\nB && cmd3 << C\nc\nC";
            let limits = ExtractionLimits {
                max_heredocs: 2, // Only allow 2
                ..Default::default()
            };
            let result = extract_content(cmd, &limits);
            if let ExtractionResult::Extracted(contents) = result {
                assert!(contents.len() <= limits.max_heredocs);
            }
            // Otherwise, skip result is also acceptable
        }

        #[test]
        fn skip_reason_display() {
            // Test Display implementations
            let reasons = vec![
                SkipReason::ExceededSizeLimit {
                    actual: 2000,
                    limit: 1000,
                },
                SkipReason::ExceededLineLimit {
                    actual: 200,
                    limit: 100,
                },
                SkipReason::ExceededHeredocLimit { limit: 10 },
                SkipReason::BinaryContent {
                    null_bytes: 5,
                    non_printable_ratio: 0.5,
                },
                SkipReason::Timeout {
                    elapsed_ms: 60,
                    budget_ms: 50,
                },
                SkipReason::UnterminatedHeredoc {
                    delimiter: "EOF".to_string(),
                },
                SkipReason::MalformedInput {
                    reason: "test".to_string(),
                },
            ];

            for reason in reasons {
                let display = format!("{reason}");
                assert!(!display.is_empty(), "Display should produce output");
            }
        }

        #[test]
        fn empty_command_returns_no_content() {
            let result = extract_content("", &ExtractionLimits::default());
            assert!(matches!(result, ExtractionResult::NoContent));
        }

        #[test]
        fn whitespace_only_returns_no_content() {
            let result = extract_content("   \t\n  ", &ExtractionLimits::default());
            assert!(matches!(result, ExtractionResult::NoContent));
        }
    }

    // ========================================================================
    // Shell Command Extraction Tests (git_safety_guard-uau)
    // ========================================================================

    mod shell_extraction {
        use super::*;

        // ====================================================================
        // Positive fixtures: commands that MUST be extracted
        // ====================================================================

        #[test]
        fn extracts_simple_command() {
            let commands = extract_shell_commands("ls -la");
            assert_eq!(commands.len(), 1);
            assert_eq!(commands[0].text, "ls -la");
            assert_eq!(commands[0].line_number, 1);
        }

        #[test]
        fn extracts_rm_rf() {
            // Catastrophic command - must be extracted for evaluator
            let commands = extract_shell_commands("rm -rf /tmp/test");
            assert_eq!(commands.len(), 1);
            assert_eq!(commands[0].text, "rm -rf /tmp/test");
        }

        #[test]
        fn extracts_git_reset_hard() {
            let commands = extract_shell_commands("git reset --hard");
            assert_eq!(commands.len(), 1);
            assert_eq!(commands[0].text, "git reset --hard");
        }

        #[test]
        fn extracts_git_clean_fd() {
            let commands = extract_shell_commands("git clean -fd");
            assert_eq!(commands.len(), 1);
            assert_eq!(commands[0].text, "git clean -fd");
        }

        #[test]
        fn extracts_pipeline_both_sides() {
            // Both sides of a pipe are executed
            let commands = extract_shell_commands("find . -name '*.bak' | xargs rm");
            assert_eq!(commands.len(), 2, "pipeline should extract both commands");
            assert!(commands[0].text.starts_with("find"));
            assert!(commands[1].text.contains("xargs"));
        }

        #[test]
        fn extracts_command_list() {
            // Commands separated by && or ;
            let commands = extract_shell_commands("cd /tmp && rm -rf test");
            assert_eq!(commands.len(), 2, "command list should extract both");
        }

        #[test]
        fn extracts_command_substitution() {
            // Commands inside $(...) are executed
            let commands = extract_shell_commands("echo $(rm -rf /tmp/test)");
            assert!(
                commands.len() >= 2,
                "should extract command inside substitution"
            );
            // Should find the rm command inside the substitution
            assert!(
                commands.iter().any(|c| c.text.contains("rm")),
                "should extract rm from command substitution"
            );
        }

        #[test]
        fn extracts_subshell_commands() {
            // Commands inside (...) subshells are executed
            let commands = extract_shell_commands("(cd /tmp && rm -rf test)");
            assert!(commands.len() >= 2, "should extract commands from subshell");
        }

        #[test]
        fn extracts_multiline_script() {
            let script = r#"#!/bin/bash
set -e
cd /tmp
rm -rf test
echo "done""#;
            let commands = extract_shell_commands(script);
            assert!(
                commands.len() >= 4,
                "should extract all commands from multiline script"
            );
            // Should have rm command
            assert!(
                commands.iter().any(|c| c.text.contains("rm")),
                "should extract rm"
            );
        }

        #[test]
        fn extracts_docker_system_prune() {
            // Docker destructive commands (if pack enabled)
            let commands = extract_shell_commands("docker system prune -af");
            assert_eq!(commands.len(), 1);
            assert_eq!(commands[0].text, "docker system prune -af");
        }

        #[test]
        fn line_numbers_are_correct() {
            let script = "echo first\nrm -rf /tmp\necho last";
            let commands = extract_shell_commands(script);
            assert!(commands.len() >= 3);

            let rm_cmd = commands.iter().find(|c| c.text.contains("rm")).unwrap();
            assert_eq!(rm_cmd.line_number, 2, "rm should be on line 2");
        }

        // ====================================================================
        // Negative fixtures: content that must NOT be extracted as commands
        // ====================================================================

        #[test]
        fn skips_comments() {
            // Comments mentioning dangerous commands should NOT be extracted
            // tree-sitter-bash parses "# ..." as a comment node, not a command node
            let commands = extract_shell_commands("# rm -rf / would be bad");
            assert!(
                commands.is_empty(),
                "comment-only content should produce zero commands, got: {commands:?}"
            );
        }

        #[test]
        fn echo_string_is_data_not_execution() {
            // The string inside echo is data, not a command
            let commands = extract_shell_commands("echo 'rm -rf /'");
            // Should extract echo, but not the rm inside the string
            assert!(
                commands.len() == 1,
                "should only extract echo, not the string content"
            );
            // The command should be the echo, not rm
            assert!(
                commands[0].text.starts_with("echo"),
                "extracted command should be echo"
            );
        }

        #[test]
        fn printf_string_is_data_not_execution() {
            let commands = extract_shell_commands(r#"printf "rm -rf %s" /tmp"#);
            assert!(
                commands.len() == 1,
                "should only extract printf, not the format string content"
            );
            assert!(commands[0].text.starts_with("printf"));
        }

        #[test]
        fn empty_content_returns_no_commands() {
            let commands = extract_shell_commands("");
            assert!(commands.is_empty());
        }

        #[test]
        fn whitespace_only_returns_no_commands() {
            let commands = extract_shell_commands("   \n\t  ");
            assert!(commands.is_empty());
        }

        #[test]
        fn comment_only_returns_no_commands() {
            // tree-sitter-bash parses "# ..." as a comment node, not a command node
            let commands = extract_shell_commands("# This is just a comment");
            assert!(
                commands.is_empty(),
                "comment-only content should produce zero commands, got: {commands:?}"
            );
        }

        #[test]
        fn heredoc_delimiter_is_not_command() {
            // The EOF itself is not a command, and heredoc body content is DATA not commands
            let script = r"cat << EOF
some content
rm -rf / mentioned in text
EOF";
            let commands = extract_shell_commands(script);

            // Should extract cat command
            assert!(
                commands.iter().any(|c| c.text.starts_with("cat")),
                "should extract cat command"
            );

            // CRITICAL: heredoc body content must NOT be extracted as commands
            // The "rm -rf /" text inside the heredoc is DATA, not an executable command
            let rm_commands: Vec<_> = commands
                .iter()
                .filter(|c| c.text.contains("rm") && !c.text.contains("cat"))
                .collect();
            assert!(
                rm_commands.is_empty(),
                "heredoc body content must NOT be extracted as commands, but found: {rm_commands:?}"
            );
        }

        #[test]
        fn safe_tmp_cleanup_is_extracted() {
            // Policy says /tmp cleanup might be allowed - but we still extract it
            // for the evaluator to decide based on pack rules/allowlists
            let commands = extract_shell_commands("rm -rf /tmp/build_cache");
            assert_eq!(commands.len(), 1);
            // Extraction happens - policy decision is for evaluator
        }

        // ====================================================================
        // Edge cases and robustness
        // ====================================================================

        #[test]
        fn handles_complex_pipeline() {
            let commands = extract_shell_commands("cat file | grep pattern | wc -l");
            assert_eq!(commands.len(), 3, "should extract all pipeline stages");
        }

        #[test]
        fn handles_background_command() {
            let commands = extract_shell_commands("long_process &");
            assert_eq!(commands.len(), 1);
            assert_eq!(commands[0].text, "long_process");
        }

        #[test]
        fn handles_redirections() {
            // An output-redirected statement is emitted twice: once complete
            // (redirect targets stay visible to the recursive evaluation,
            // #271) and once as the bare command node.
            let commands = extract_shell_commands("rm -rf /tmp/test > /dev/null 2>&1");
            assert_eq!(commands.len(), 2);
            assert_eq!(commands[0].text, "rm -rf /tmp/test > /dev/null 2>&1");
            assert_eq!(commands[1].text, "rm -rf /tmp/test");
        }

        #[test]
        fn redirect_only_statements_keep_their_targets() {
            // #271: the redirect target is the destructive payload here; the
            // full statement must be surfaced so the evaluator can judge it.
            let commands = extract_shell_commands("echo hi > ~/.zshrc");
            assert!(
                commands.iter().any(|c| c.text.contains("> ~/.zshrc")),
                "output redirect target must be preserved: {commands:?}"
            );
            // Input-only redirects keep the historical single extraction.
            let commands = extract_shell_commands("wc -l < notes.txt");
            assert_eq!(commands.len(), 1);
            assert_eq!(commands[0].text, "wc -l");
        }

        #[test]
        fn handles_variable_expansion_in_command() {
            // Commands with variables should still be extracted
            let commands = extract_shell_commands("rm -rf $DIR");
            assert_eq!(commands.len(), 1);
            assert!(commands[0].text.contains("rm"));
        }

        #[test]
        fn handles_if_then_else() {
            let script = r#"if [ -f /tmp/test ]; then
    rm -rf /tmp/test
else
    echo "not found"
fi"#;
            let commands = extract_shell_commands(script);
            // Should extract the commands inside the if/else
            assert!(
                commands.iter().any(|c| c.text.contains("rm")),
                "should extract rm from if body"
            );
            assert!(
                commands.iter().any(|c| c.text.contains("echo")),
                "should extract echo from else body"
            );
        }

        #[test]
        fn handles_for_loop() {
            let script = "for f in *.txt; do rm -f \"$f\"; done";
            let commands = extract_shell_commands(script);
            assert!(
                commands.iter().any(|c| c.text.contains("rm")),
                "should extract rm from for loop body"
            );
        }

        #[test]
        fn byte_ranges_are_correct() {
            let script = "echo hello";
            let commands = extract_shell_commands(script);
            assert_eq!(commands.len(), 1);
            assert_eq!(commands[0].start, 0);
            assert_eq!(commands[0].end, script.len());

            // Extract the text using the range
            let extracted = &script[commands[0].start..commands[0].end];
            assert_eq!(extracted, "echo hello");
        }
    }

    proptest! {
        /// Tier 1 trigger detection must be a superset of Tier 2 extraction.
        /// If Tier 2 extracts any content, Tier 1 must have triggered.
        #[test]
        fn tier1_is_superset_of_tier2_extraction(cmd in prop_oneof![
            // Random UTF-8
            "\\PC{0,2000}",
            // Heredoc-ish inputs (multi-line)
            "\\PC{0,400}".prop_map(|body| format!("cat <<EOF\n{body}\nEOF")),
            "\\PC{0,400}".prop_map(|body| format!("cat <<'EOF'\n{body}\nEOF")),
            // Inline interpreters
            "\\PC{0,400}".prop_map(|body| format!("python -c \"{}\"", body.replace('\"', ""))),
            "\\PC{0,400}".prop_map(|body| format!("bash -c \"{}\"", body.replace('\"', ""))),
            "\\PC{0,400}".prop_map(|body| format!("node -e \"{}\"", body.replace('\"', ""))),
        ]) {
            let limits = ExtractionLimits {
                max_body_bytes: 10_000,
                max_body_lines: 1_000,
                max_heredocs: 5,
                timeout_ms: 50,
            };

            let extracted = extract_content(&cmd, &limits);
            if let ExtractionResult::Extracted(contents) = extracted {
                if !contents.is_empty() {
                    prop_assert_eq!(
                        check_triggers(&cmd),
                        TriggerResult::Triggered,
                        "Tier 2 extracted but Tier 1 did not trigger for: {:?}",
                        cmd
                    );
                }
            }
        }
    }

    #[test]
    fn detects_language_in_pipeline() {
        // Regression test: now detects python in pipeline via pipe scanning
        let cmd = "cat <<EOF | python";
        let content = "print('hello')"; // ambiguous content
        let (lang, _) = ScriptLanguage::detect(cmd, content);
        assert_eq!(lang, ScriptLanguage::Python);
    }

    #[test]
    fn extract_heredoc_target_command_prefers_command_over_arguments() {
        let cat_cmd = "cat bash <<EOF\nrm -rf /\nEOF";
        let cat_start = cat_cmd.find("<<").expect("cat heredoc");
        assert_eq!(
            extract_heredoc_target_command(cat_cmd, cat_start).as_deref(),
            Some("cat")
        );

        let grep_cmd = "grep pattern . <<EOF\nrm -rf /\nEOF";
        let grep_start = grep_cmd.find("<<").expect("grep heredoc");
        assert_eq!(
            extract_heredoc_target_command(grep_cmd, grep_start).as_deref(),
            Some("grep")
        );
    }

    #[test]
    fn extract_heredoc_target_command_skips_assignments_and_wrappers() {
        let env_cmd = "FOO=1 env -i /bin/cat <<EOF\npayload\nEOF";
        let env_start = env_cmd.find("<<").expect("env heredoc");
        assert_eq!(
            extract_heredoc_target_command(env_cmd, env_start).as_deref(),
            Some("cat")
        );

        let sudo_cmd = "sudo bash <<EOF\necho hi\nEOF";
        let sudo_start = sudo_cmd.find("<<").expect("sudo heredoc");
        assert_eq!(
            extract_heredoc_target_command(sudo_cmd, sudo_start).as_deref(),
            Some("bash")
        );
    }

    /// #136 REVERTED: interpreter-stdin heredoc bodies are no longer masked, so
    /// `is_interpreter_source_heredoc_command` returns false for EVERY command.
    /// Masking a body that actually executes is unsound for a zero-false-negative
    /// scanner (it hides destructive tokens reaching an exec sink via variable
    /// indirection, aliasing, backtick/template literals, etc.), so all bodies
    /// fall back to the conservative raw-shell scan.
    #[test]
    fn interpreter_source_heredoc_command_classification_136() {
        for cmd in [
            // interpreters that were briefly masked …
            "python",
            "python3",
            "python3.11",
            "node",
            "nodejs",
            "ruby",
            "deno",
            "bun",
            "/usr/bin/python3",
            "perl",
            "php",
            "go",
            "/usr/local/bin/php",
            // … shells (always read shell from stdin) …
            "bash",
            "sh",
            "zsh",
            "fish",
            "powershell",
            "pwsh",
            // … and data/unknown commands.
            "cat",
            "tee",
            "grep",
            "totally-unknown-cmd",
        ] {
            assert!(
                !is_interpreter_source_heredoc_command(cmd),
                "{cmd} must NOT be masked as interpreter source (#136 reverted — masking executes is unsound)"
            );
        }
    }

    /// #136 REVERTED: a python (or any interpreter) heredoc body is NOT masked —
    /// it stays intact for the raw-shell scan so a destructive literal still
    /// blocks, exactly like a bash heredoc body. Only genuine data sinks
    /// (`cat`/`tee`, the #109 behavior) are masked.
    #[test]
    fn mask_interpreter_source_body_136() {
        let rmrf = format!("{}{}{}", "rm", " -", "rf");

        // python interpreter body must be left intact (not masked).
        let py = format!("python3 - <<PY\nprint(\"{rmrf} /etc/important\")\nPY");
        let masked_py = mask_non_executing_heredocs(&py);
        assert!(
            masked_py.contains(&rmrf),
            "python interpreter body must be left intact for raw-shell scanning: {masked_py:?}"
        );

        // bash body is likewise left intact.
        let sh = format!("bash <<SH\n{rmrf} /etc/important\nSH");
        let masked_sh = mask_non_executing_heredocs(&sh);
        assert!(
            masked_sh.contains(&rmrf),
            "bash body must be left intact for raw-shell scanning: {masked_sh:?}"
        );

        // A genuine data sink (cat) IS still masked (#109 behavior, unaffected).
        let cat = format!("cat > f.py <<PY\nprint(\"{rmrf} /etc/important\")\nPY");
        let masked_cat = mask_non_executing_heredocs(&cat);
        assert!(
            !masked_cat.contains(&rmrf),
            "cat data-sink body should still be masked: {masked_cat:?}"
        );
    }

    /// #136 data-sink half: `git commit -F -` / `--file=-` / `git hash-object
    /// --stdin` read the heredoc body as DATA (a commit message / object
    /// content) that git never executes, so the body is masked like cat/tee. A
    /// bare `git commit <<EOF` (no stdin sentinel) is NOT masked, and anything
    /// after the terminator stays scannable.
    #[test]
    fn mask_git_stdin_data_sink_136() {
        let reset_hard = format!("{}{}", "reset --", "hard");

        // `git commit -F -`: message from stdin → body masked.
        let c1 = format!("git commit -F - <<EOF\ndocs: {reset_hard} notes\nEOF");
        let m1 = mask_non_executing_heredocs(&c1);
        assert!(
            !m1.contains(&reset_hard),
            "commit-message body via `-F -` should be masked: {m1:?}"
        );
        // The git invocation line itself must be preserved (not masked away).
        assert!(
            m1.contains("git commit -F -"),
            "the git invocation line must be preserved: {m1:?}"
        );

        // `--file=-` glued form.
        let c2 = "git commit --file=- <<EOF\ndocs: restore the worktree\nEOF";
        let m2 = mask_non_executing_heredocs(c2);
        assert!(
            !m2.contains("restore"),
            "commit-message body via `--file=-` should be masked: {m2:?}"
        );

        // `git hash-object --stdin`: object content from stdin → masked.
        let c3 = "git hash-object --stdin <<EOF\ngit restore --worktree .\nEOF";
        let m3 = mask_non_executing_heredocs(c3);
        assert!(
            !m3.contains("restore"),
            "hash-object --stdin body should be masked: {m3:?}"
        );

        // A Git shell alias inherits stdin and may execute the body. Neither
        // `--stdin` nor message-style `-F -` can turn an unknown/aliased
        // subcommand into a proven data sink.
        for aliased in [
            "git -c 'alias.x=!bash -s --' x --stdin <<'EOF'\nrm -r ./tree\nEOF",
            "git -c 'alias.x=!bash -s --' x -F - <<'EOF'\nrm -r ./tree\nEOF",
            "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.x GIT_CONFIG_VALUE_0='!bash -s --' git x --stdin <<'EOF'\nrm -r ./tree\nEOF",
        ] {
            let masked = mask_non_executing_heredocs(aliased);
            assert!(
                masked.contains("rm -r ./tree"),
                "Git aliases must never make executable stdin look like inert data: {masked:?}"
            );
        }

        // Conservative: a bare `git commit <<EOF` (no stdin sentinel) is NOT masked.
        let c4 = "git commit <<EOF\nrestore\nEOF";
        let m4 = mask_non_executing_heredocs(c4);
        assert!(
            m4.contains("restore"),
            "bare `git commit <<EOF` must NOT be masked (no stdin sentinel): {m4:?}"
        );

        // Soundness: a destructive command AFTER the terminator stays scannable.
        let rmrf = format!("{}{}{}", "rm", " -", "rf");
        let c5 = format!("git commit -F - <<EOF\nmsg\nEOF\n{rmrf} /etc");
        let m5 = mask_non_executing_heredocs(&c5);
        assert!(
            m5.contains(&rmrf),
            "command after the heredoc terminator must remain scannable: {m5:?}"
        );

        // A quoted `-m` message that merely contains the text "-F -" must not be
        // mistaken for a real stdin sentinel (quoted args are single tokens).
        let c6 = format!("git commit -m \"mentions -F - here\" <<EOF\n{reset_hard}\nEOF");
        let m6 = mask_non_executing_heredocs(&c6);
        assert!(
            m6.contains(&reset_hard),
            "quoted text '-F -' must not be treated as a stdin sentinel: {m6:?}"
        );

        // CRITICAL soundness (no cross-line leak): a `git … -F -` on an EARLIER
        // line must NOT mask a LATER interpreter heredoc whose body genuinely
        // executes. The heredoc binds to the command on its own physical line.
        let c7 = format!("git commit -F - msg.txt\nbash <<EOF\n{rmrf} /important\nEOF");
        let m7 = mask_non_executing_heredocs(&c7);
        assert!(
            m7.contains(&rmrf),
            "git stdin sentinel on a prior line must NOT mask a later bash heredoc body: {m7:?}"
        );

        // Same line, here-string form on a later interpreter: still no leak.
        let c8 = format!("git commit -F - msg.txt\nbash <<<'{rmrf} /important'");
        let m8 = mask_non_executing_heredocs(&c8);
        assert!(
            m8.contains(&rmrf),
            "git sentinel on a prior line must NOT mask a later bash here-string: {m8:?}"
        );
    }

    /// #374: `git apply` consumes its stdin as a unified-diff PATCH — data git
    /// parses, never executes. The reported FP was a quoted heredoc feeding
    /// `git apply --cached` denied as an unknown embedded language. The body
    /// is masked like other structured git stdin sinks; `--unsafe-paths` and
    /// alias-capable configuration keep the fail-closed path.
    #[test]
    fn mask_git_apply_patch_stdin_data_sink_374() {
        let rmrf = format!("{}{}{}", "rm", " -", "rf");

        // The reported shape: index-only staging of one hunk.
        let reported = "git apply --cached <<'PATCH'\n\
diff --git a/README.md b/README.md\n\
--- a/README.md\n\
+++ b/README.md\n\
@@ -1 +1,2 @@\n \
one\n\
+two\n\
PATCH";
        let masked = mask_non_executing_heredocs(reported);
        assert!(
            !masked.contains("README"),
            "patch body for `git apply --cached` must be masked as stdin data: {masked:?}"
        );
        assert!(
            masked.contains("git apply --cached"),
            "the owning command must remain scannable: {masked:?}"
        );

        // Other stdin-reading apply modes are the same data contract.
        for command in [
            "git apply <<'PATCH'\npatch-body git restore --worktree .\nPATCH",
            "git apply --check <<'PATCH'\npatch-body git restore --worktree .\nPATCH",
            "git apply --cached - <<'PATCH'\npatch-body git restore --worktree .\nPATCH",
            "git -C /repo apply --cached <<'PATCH'\npatch-body git restore --worktree .\nPATCH",
        ] {
            let masked = mask_non_executing_heredocs(command);
            assert!(
                !masked.contains("restore"),
                "apply patch body should be masked: {command:?} -> {masked:?}"
            );
        }

        // `--unsafe-paths` lets the patch govern paths outside the working
        // tree; the body stays visible for scanning.
        let unsafe_paths =
            format!("git apply --unsafe-paths --cached <<'PATCH'\n{rmrf} /etc\nPATCH");
        assert!(
            mask_non_executing_heredocs(&unsafe_paths).contains(&rmrf),
            "--unsafe-paths must keep the body scannable"
        );

        // Alias-capable configuration still fails closed (same as #136).
        let aliased = format!(
            "git -c 'alias.apply=!bash -s --' apply --cached <<'PATCH'\n{rmrf} /etc\nPATCH"
        );
        assert!(
            mask_non_executing_heredocs(&aliased).contains(&rmrf),
            "config-bearing git invocations must never prove a data sink"
        );

        // Soundness: content after the terminator stays scannable.
        let after = format!("git apply --cached <<'PATCH'\nbody\nPATCH\n{rmrf} /etc");
        assert!(
            mask_non_executing_heredocs(&after).contains(&rmrf),
            "command after the heredoc terminator must remain scannable"
        );
    }

    /// #181: `spx session handoff` reads a structured handoff document from
    /// stdin.  Prose in that body is data, while other `spx` subcommands and
    /// later shell commands must remain visible to the raw-shell scan.
    #[test]
    fn mask_spx_session_handoff_stdin_data_sink_181() {
        let reported = "spx session handoff <<'EOF'\n\
git worktrees and active sessions restore only selected agents\n\
EOF";
        let masked = mask_non_executing_heredocs(reported);
        assert!(
            !masked.contains("restore"),
            "handoff prose must be masked as stdin data: {masked:?}"
        );
        assert!(
            masked.contains("spx session handoff"),
            "the owning command must remain scannable: {masked:?}"
        );

        let wrapped = "env SPX_FORMAT=json /usr/bin/spx session handoff <<EOF\n\
git restore --worktree .\n\
EOF";
        assert!(
            mask_non_executing_heredocs(wrapped).contains("restore"),
            "an env wrapper invalidates even a trusted path's stdin-data contract"
        );

        let arbitrary_path = "/usr/local/bin/spx session handoff <<EOF\n\
git restore --worktree .\n\
EOF";
        assert!(
            mask_non_executing_heredocs(arbitrary_path).contains("restore"),
            "an arbitrary executable path cannot establish the spx handoff contract"
        );

        let trusted_path = "/usr/bin/spx session handoff <<EOF\n\
git restore --worktree .\n\
EOF";
        assert!(
            !mask_non_executing_heredocs(trusted_path).contains("restore"),
            "a direct trusted spx path preserves the exact handoff data-sink contract"
        );

        let other = "spx session run <<EOF\ngit restore --worktree .\nEOF";
        assert!(
            mask_non_executing_heredocs(other).contains("restore"),
            "unrecognized spx subcommands must fail closed and remain scannable"
        );

        let rmrf = format!("{}{}{}", "rm", " -", "rf");
        let later = format!("spx session handoff <<EOF\nnotes\nEOF\n{rmrf} /important");
        assert!(
            mask_non_executing_heredocs(&later).contains(&rmrf),
            "commands after the handoff terminator must remain scannable"
        );

        let prior_line =
            format!("spx session handoff notes.txt\nbash <<EOF\n{rmrf} /important\nEOF");
        assert!(
            mask_non_executing_heredocs(&prior_line).contains(&rmrf),
            "a handoff command on a prior line must not mask a later shell heredoc"
        );
    }

    /// #181: `true <<'EOF' … EOF` and `: <<'EOF' … EOF` are the shell
    /// block-comment idiom — no-op builtins whose *quoted* heredoc body is inert
    /// literal data. Destructive-looking prose in that body is a false positive.
    #[test]
    fn mask_quoted_noop_builtin_heredoc_181() {
        // The exact reported repro: inert prose tripping core.git:restore-worktree.
        let reported = "true <<'EOF'\n\
git worktrees and active sessions restore only selected agents\n\
EOF";
        let masked = mask_non_executing_heredocs(reported);
        assert!(
            !masked.contains("restore"),
            "quoted `true` heredoc prose must be masked as data: {masked:?}"
        );
        assert!(
            masked.contains("true"),
            "the owning command must stay scannable: {masked:?}"
        );

        // `:` block-comment idiom and double-quoted delimiter both count.
        for cmd in [
            ": <<'EOF'\ngit restore --worktree .\nEOF",
            ": <<\"EOF\"\ngit restore --worktree .\nEOF",
            "false <<- 'EOF'\n\tgit restore --worktree .\n\tEOF",
        ] {
            assert!(
                !mask_non_executing_heredocs(cmd).contains("restore"),
                "quoted no-op builtin heredoc must be masked: {cmd:?}"
            );
        }
    }

    /// #181 soundness: an *unquoted* delimiter still expands the body (command
    /// substitution runs even though the builtin discards stdin), so the body
    /// must NOT be masked — never trade a false positive for a false negative.
    #[test]
    fn unquoted_noop_builtin_heredoc_is_not_masked() {
        let rmrf = format!("{}{}{}", "rm", " -", "rf");

        // Unquoted delimiter: `$(rm -rf /etc)` in the body executes at expansion
        // time, so the deletion must remain visible to pack matching.
        let unquoted = format!("true <<EOF\n$({rmrf} /etc)\nEOF");
        assert!(
            mask_non_executing_heredocs(&unquoted).contains(&rmrf),
            "unquoted no-op-builtin heredoc body must stay scannable: {unquoted:?}"
        );

        // Commands after the terminator are always scannable, quoted or not.
        let after = format!("true <<'EOF'\nnotes\nEOF\n{rmrf} /important");
        assert!(
            mask_non_executing_heredocs(&after).contains(&rmrf),
            "commands after the terminator must remain scannable: {after:?}"
        );
    }

    /// Cross-line soundness for the existing #109 data-sink path: a `cat`/`tee`
    /// data sink on a PRIOR line must not mask a later executing `bash` heredoc
    /// body. Heredoc target resolution is bounded to the heredoc's own physical
    /// line, so the target here is `bash` (executing), not `cat` (data sink).
    #[test]
    fn data_sink_mask_does_not_leak_across_lines() {
        let rmrf = format!("{}{}{}", "rm", " -", "rf");

        let c = format!("cat notes.txt\nbash <<EOF\n{rmrf} /important\nEOF");
        let m = mask_non_executing_heredocs(&c);
        assert!(
            m.contains(&rmrf),
            "cat on a prior line must NOT mask a later bash heredoc body: {m:?}"
        );

        // Control: cat with its OWN heredoc on the same line is still masked.
        let c2 = format!("cat <<EOF\n{rmrf} /important\nEOF");
        let m2 = mask_non_executing_heredocs(&c2);
        assert!(
            !m2.contains(&rmrf),
            "cat's own same-line heredoc body should still be masked: {m2:?}"
        );
    }

    #[test]
    fn inert_heredoc_text_cannot_mask_later_executable_lines() {
        let command = "printf '%s\\n' \"<<'EOF'\"\necho \"$(rm -r ./tree)\"\nEOF";
        let masked = mask_non_executing_heredocs(command);
        assert!(
            masked.contains("rm -r ./tree"),
            "quoted text that resembles a heredoc operator is data, not a masking boundary: {masked:?}"
        );

        let real_data = "cat <<'EOF'\nrm -r ./tree\nEOF";
        assert!(
            !mask_non_executing_heredocs(real_data).contains("rm -r ./tree"),
            "an AST-proven quoted cat heredoc remains inert data"
        );
        assert!(
            !mask_non_expanding_data_heredocs(real_data).contains("rm -r ./tree"),
            "an AST-proven quoted cat heredoc suppresses command substitution"
        );

        for command in [
            "cat <<'E'OF >/dev/null\ndata\nEOF\necho \"$(rm -r ./tree)\"\nE",
            "cat <<E\\OF >/dev/null\ndata\nEOF\necho \"$(rm -r ./tree)\"\nE\\OF",
        ] {
            let masked = mask_non_executing_heredocs(command);
            assert!(
                masked.contains("rm -r ./tree"),
                "shell quote-removal in a delimiter must not extend the authoritative AST body span: {masked:?}"
            );
        }

        for command in [
            "cat() { bash -s; }\ncat <<'EOF'\nrm -r ./tree\nEOF",
            "alias cat='bash -s'\ncat <<'EOF'\nrm -r ./tree\nEOF",
        ] {
            let masked = mask_non_executing_heredocs(command);
            assert!(
                masked.contains("rm -r ./tree"),
                "a visible function/alias can replace a nominal data sink and execute stdin: {masked:?}"
            );
        }
    }

    #[test]
    fn dynamic_shell_state_keeps_bare_data_sink_body_visible() {
        let destructive = "rm -r ./tree";
        for command in [
            "eval 'cat(){ bash -s; }'; cat <<'EOF'\nrm -r ./tree\nEOF",
            "source ./runtime-bindings.sh; cat <<'EOF'\nrm -r ./tree\nEOF",
            ". ./runtime-bindings.sh; cat <<'EOF'\nrm -r ./tree\nEOF",
            "cat() { bash -s; }\ncat <<'EOF'\nrm -r ./tree\nEOF",
            "alias cat='bash -s'\ncat <<'EOF'\nrm -r ./tree\nEOF",
            "binding='cat=bash -s'; alias \"$binding\"\ncat <<'EOF'\nrm -r ./tree\nEOF",
            "install_bindings() { source ./runtime-bindings.sh; }\ninstall_bindings\ncat <<'EOF'\nrm -r ./tree\nEOF",
        ] {
            let fully_masked = mask_non_executing_heredocs(command);
            assert!(
                fully_masked.contains(destructive),
                "runtime shell state can make a bare data-sink name execute stdin: {fully_masked:?}"
            );

            let expansion_masked = mask_non_expanding_data_heredocs(command);
            assert!(
                expansion_masked.contains(destructive),
                "quoted-delimiter masking must fail closed after runtime name mutation: {expansion_masked:?}"
            );
        }
    }

    #[test]
    fn trusted_os_data_sink_paths_are_not_shadowed_by_shell_name_state() {
        for command in [
            "eval 'cat(){ bash -s; }'; /bin/cat <<'EOF'\nrm -r ./tree\nEOF",
            "source ./runtime-bindings.sh; /usr/bin/cat <<'EOF'\nrm -r ./tree\nEOF",
            "cat <<'EOF'\nrm -r ./tree\nEOF",
        ] {
            assert!(
                !mask_non_executing_heredocs(command).contains("rm -r ./tree"),
                "a normal bare sink or exact trusted OS path retains data-only masking: {command:?}"
            );
            assert!(
                !mask_non_expanding_data_heredocs(command).contains("rm -r ./tree"),
                "quoted data sent to a proven cat sink remains inert: {command:?}"
            );
        }
    }

    #[test]
    fn arbitrary_path_qualified_data_sink_names_may_execute_stdin() {
        for command in [
            "./cat <<'EOF'\nrm -r ./tree\nEOF",
            "bin/cat <<'EOF'\nrm -r ./tree\nEOF",
            "/tmp/cat <<'EOF'\nrm -r ./tree\nEOF",
            "/usr/local/bin/cat <<'EOF'\nrm -r ./tree\nEOF",
            "/bin/../tmp/cat <<'EOF'\nrm -r ./tree\nEOF",
            "/bin//cat <<'EOF'\nrm -r ./tree\nEOF",
        ] {
            assert!(
                mask_non_executing_heredocs(command).contains("rm -r ./tree"),
                "a basename does not prove an arbitrary executable consumes stdin as data: {command:?}"
            );
            assert!(
                mask_non_expanding_data_heredocs(command).contains("rm -r ./tree"),
                "quoted-delimiter masking must reject untrusted executable paths: {command:?}"
            );
        }
    }

    #[test]
    fn path_and_command_resolution_mutations_keep_bare_sink_body_visible() {
        for command in [
            "PATH=/tmp:$PATH cat <<'EOF'\nrm -r ./tree\nEOF",
            "PATH=/tmp:$PATH; cat <<'EOF'\nrm -r ./tree\nEOF",
            "export PATH=/tmp:$PATH; cat <<'EOF'\nrm -r ./tree\nEOF",
            "env PATH=/tmp:$PATH cat <<'EOF'\nrm -r ./tree\nEOF",
            "hash -p /tmp/cat cat; cat <<'EOF'\nrm -r ./tree\nEOF",
            "enable -f /tmp/cat.so cat; cat <<'EOF'\nrm -r ./tree\nEOF",
        ] {
            assert!(
                mask_non_executing_heredocs(command).contains("rm -r ./tree"),
                "visible command-resolution mutation invalidates a bare data-sink proof: {command:?}"
            );
            assert!(
                mask_non_expanding_data_heredocs(command).contains("rm -r ./tree"),
                "quoted-delimiter masking must fail closed after command-resolution mutation: {command:?}"
            );
        }
    }

    #[test]
    fn wrapper_bearing_data_sink_targets_are_never_masked() {
        for command in [
            "sudo() { bash -s; }\nsudo cat <<'EOF'\nrm -r ./tree\nEOF",
            "alias env='bash -s'\nenv cat <<'EOF'\nrm -r ./tree\nEOF",
            "PATH=/tmp:$PATH sudo cat <<'EOF'\nrm -r ./tree\nEOF",
            "sudo /bin/cat <<'EOF'\nrm -r ./tree\nEOF",
            "env /usr/bin/cat <<'EOF'\nrm -r ./tree\nEOF",
            "nohup cat <<'EOF'\nrm -r ./tree\nEOF",
            "command cat <<'EOF'\nrm -r ./tree\nEOF",
            "builtin cat <<'EOF'\nrm -r ./tree\nEOF",
        ] {
            assert!(
                mask_non_executing_heredocs(command).contains("rm -r ./tree"),
                "a skipped wrapper invalidates the final sink's data-only contract: {command:?}"
            );
            assert!(
                mask_non_expanding_data_heredocs(command).contains("rm -r ./tree"),
                "quoted-delimiter masking must retain wrapper-bearing stdin: {command:?}"
            );
        }
    }

    #[test]
    fn literal_mutator_text_does_not_disable_data_sink_masking() {
        for command in [
            "printf '%s\\n' \"eval 'cat(){ bash -s; }'\"; cat <<'EOF'\nrm -r ./tree\nEOF",
            "printf '%s\\n' 'source ./runtime-bindings.sh; . ./other.sh'; cat <<'EOF'\nrm -r ./tree\nEOF",
            "printf '%s\\n' \"alias cat='bash -s'\"; cat <<'EOF'\nrm -r ./tree\nEOF",
            "printf '%s\\n' 'PATH=/tmp; export PATH=/tmp; env PATH=/tmp cat; hash -p /tmp/cat cat; enable -f /tmp/cat.so cat'; cat <<'EOF'\nrm -r ./tree\nEOF",
            "printf '%s\\n' 'sudo cat; env cat; nohup cat; command cat; builtin cat'; cat <<'EOF'\nrm -r ./tree\nEOF",
            "# eval 'cat(){ bash -s; }'\ncat <<'EOF'\nrm -r ./tree\nEOF",
            "# PATH=/tmp; export PATH=/tmp; hash -p /tmp/cat cat\ncat <<'EOF'\nrm -r ./tree\nEOF",
            "# sudo /bin/cat; env /usr/bin/cat\ncat <<'EOF'\nrm -r ./tree\nEOF",
        ] {
            assert!(
                !mask_non_executing_heredocs(command).contains("rm -r ./tree"),
                "quoted/commented/unexecuted mutator text is not visible shell state: {command:?}"
            );
            assert!(
                !mask_non_expanding_data_heredocs(command).contains("rm -r ./tree"),
                "literal mutator words must not cause an obvious masking false positive: {command:?}"
            );
        }
    }

    // ========================================================================
    // Inert interpreter stdin (#357, #363): quoted delimiter + proven
    // non-shell receiver means no shell ever expands or executes those bytes
    // ========================================================================

    mod inert_interpreter_stdin {
        use super::*;

        /// Ask the predicate about the span of `needle` inside `command`.
        fn needle_is_inert(command: &str, needle: &str) -> bool {
            let start = command
                .find(needle)
                .unwrap_or_else(|| panic!("{needle:?} not found in {command:?}"));
            range_is_inert_interpreter_stdin(command, &(start..start + needle.len()))
        }

        #[test]
        fn quoted_delimiter_into_a_proven_non_shell_interpreter_is_inert() {
            for command in [
                "python3 - <<'PY'\ngit branch $name\nPY",
                "python3 - <<\"PY\"\ngit branch $name\nPY",
                "python3 <<'PY'\ngit branch $name\nPY",
                "/usr/bin/python3 - <<'PY'\ngit branch $name\nPY",
                "node - <<'JS'\ngit branch $name\nJS",
                "ruby <<'RB'\ngit branch $name\nRB",
                "perl <<'PL'\ngit branch $name\nPL",
                "php <<'PHP'\ngit branch $name\nPHP",
                "bun <<'TS'\ngit branch $name\nTS",
                "cd /tmp/proj && python3 - <<'PY'\ngit branch $name\nPY",
            ] {
                assert!(
                    needle_is_inert(command, "git branch $name"),
                    "no shell ever expands these bytes: {command:?}"
                );
            }
        }

        /// Both conditions are load-bearing. An unquoted delimiter is
        /// expanded by the OUTER shell before the receiver runs; a shell
        /// receiver expands the body itself when it executes it; and an
        /// unmodeled name (`dash`, `ksh`, `jq`, anything unknown) may well be
        /// a shell, so Unknown must never read as "not a shell".
        #[test]
        fn unquoted_delimiters_and_shell_or_unknown_receivers_are_never_inert() {
            for command in [
                "python3 - <<PY\ngit branch $name\nPY",
                "node - <<JS\ngit branch $name\nJS",
                "bash <<'EOF'\ngit branch $name\nEOF",
                "sh <<'EOF'\ngit branch $name\nEOF",
                "zsh <<'EOF'\ngit branch $name\nEOF",
                "fish <<'EOF'\ngit branch $name\nEOF",
                "pwsh <<'EOF'\ngit branch $name\nEOF",
                "dash <<'EOF'\ngit branch $name\nEOF",
                "ksh <<'EOF'\ngit branch $name\nEOF",
                "jq -f - <<'EOF'\ngit branch $name\nEOF",
                "sqlite3 db <<'EOF'\ngit branch $name\nEOF",
                "somebin - <<'EOF'\ngit branch $name\nEOF",
                // `cat` is a data sink handled by the (stronger) masking
                // path; this predicate deliberately claims nothing about it.
                "cat <<'EOF'\ngit branch $name\nEOF",
            ] {
                assert!(
                    !needle_is_inert(command, "git branch $name"),
                    "a shell may still expand or execute this body: {command:?}"
                );
            }
        }

        /// Wrappers resolve their targets under different rules and can
        /// themselves be rebound; visible shell state that may rebind the
        /// receiver name, and arbitrary paths that merely borrow an
        /// interpreter's basename, all fail closed.
        #[test]
        fn wrapped_rebound_or_path_spoofed_receivers_are_never_inert() {
            for command in [
                "env python3 - <<'PY'\ngit branch $name\nPY",
                "sudo python3 - <<'PY'\ngit branch $name\nPY",
                "command python3 - <<'PY'\ngit branch $name\nPY",
                "nohup python3 - <<'PY'\ngit branch $name\nPY",
                "python3() { bash -s; }\npython3 - <<'PY'\ngit branch $name\nPY",
                "alias python3='bash -s'\npython3 - <<'PY'\ngit branch $name\nPY",
                "eval 'python3(){ bash -s; }'; python3 - <<'PY'\ngit branch $name\nPY",
                "source ./bindings.sh; python3 - <<'PY'\ngit branch $name\nPY",
                "./python3 - <<'PY'\ngit branch $name\nPY",
                "/tmp/python3 - <<'PY'\ngit branch $name\nPY",
            ] {
                assert!(
                    !needle_is_inert(command, "git branch $name"),
                    "an unproven receiver must fail closed: {command:?}"
                );
            }
        }

        /// The claim covers only the body's own bytes: text after the
        /// terminator, ranges that straddle a boundary, degenerate ranges,
        /// and fake `<<` text inside quotes prove nothing.
        #[test]
        fn only_bytes_fully_inside_the_body_are_inert() {
            let after = "python3 - <<'PY'\nx = 1\nPY\ngit branch $name";
            assert!(
                !needle_is_inert(after, "git branch $name"),
                "content after the terminator is ordinary shell source"
            );

            let body = "python3 - <<'PY'\ngit branch $name\nPY";
            let operator = body.find("<<'PY'").expect("operator");
            let end = body.len();
            assert!(
                !range_is_inert_interpreter_stdin(body, &(operator..end)),
                "a range straddling the body start must not be claimed inert"
            );
            assert!(!range_is_inert_interpreter_stdin(body, &(4..4)));
            assert!(!range_is_inert_interpreter_stdin(body, &(0..usize::MAX)));

            let fake = "echo 'python3 - <<PY'\ngit branch $name";
            assert!(
                !needle_is_inert(fake, "git branch $name"),
                "quoted text resembling a heredoc operator is data, not syntax"
            );
        }

        #[test]
        fn receiver_name_classification_matches_script_language_model() {
            for name in [
                "python",
                "python3",
                "python3.12",
                "python.exe",
                "node",
                "nodejs",
                "deno",
                "bun",
                "ruby",
                "irb",
                "perl",
                "php",
                "go",
            ] {
                assert!(
                    is_non_shell_interpreter_stdin_command(name),
                    "{name} reads a non-shell program from stdin"
                );
            }
            for name in [
                "sh",
                "bash",
                "zsh",
                "fish",
                "pwsh",
                "powershell",
                "powershell.exe",
                "dash",
                "ksh",
                "busybox",
                "jq",
                "sqlite3",
                "cat",
                "tee",
                "somebin",
            ] {
                assert!(
                    !is_non_shell_interpreter_stdin_command(name),
                    "{name} must not be classified as a proven non-shell interpreter"
                );
            }
        }
    }
}
