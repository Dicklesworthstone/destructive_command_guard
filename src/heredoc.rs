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
use std::borrow::Cow;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, mpsc};
use std::time::{Duration, Instant};
use tracing::{debug, instrument, trace, warn};

/// Options a POSIX shell accepts after `-c` and before the command string:
/// `bash -c -e '<cmd>'`, `sh -c -- '<cmd>'`, `sh -c - '<cmd>'`,
/// `bash -c -o errexit '<cmd>'`, `bash -c +e '<cmd>'`. The first operand is
/// the command string, not the first word after the flag. Quoting an option or
/// its name does not change the argv (`bash -c -o 'errexit' '<cmd>'`,
/// `sh -c '-e' '<cmd>'`), so each may carry quotes.
macro_rules! shell_option_after_c_re {
    () => {
        r#"(?:['"]?[-+][oO]['"]?\s+(?:[A-Za-z_]|'[A-Za-z_]*'|"[A-Za-z_]*")+|['"]?(?:[-+][A-Za-z]+|--?)['"]?)"#
    };
}

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
const HEREDOC_TRIGGER_PATTERNS: [&str; 30] = [
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
    r#"\bpython[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+(?:[:.=]\S*)?)(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*))?)*\s+['\x22]?-[A-Za-z]*[ce][A-Za-z]*(?:\s|['"]|$)"#,
    // Ruby inline execution (matches ruby, ruby3, ruby3.0, ruby.exe, etc.)
    r#"\bruby[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+(?:[:.=]\S*)?)(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*))?)*\s+['\x22]?-[A-Za-z]*e[A-Za-z]*(?:\s|['"]|$)"#,
    r#"\birb[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+(?:[:.=]\S*)?)(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*))?)*\s+['\x22]?-[A-Za-z]*e[A-Za-z]*(?:\s|['"]|$)"#,
    // Perl inline execution (matches perl, perl5, perl5.36, perl.exe, etc.)
    r#"\bperl[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+(?:[:.=]\S*)?)(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*))?)*\s+['\x22]?-[A-Za-z]*[eE][A-Za-z]*(?:\s|['"]|$)"#,
    // Node.js inline execution (matches node, node18, nodejs, node.exe, etc.)
    r#"\bnode(?:js)?[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+(?:[:.=]\S*)?)(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*))?)*\s+['\x22]?-[A-Za-z]*[ep][A-Za-z]*(?:\s|['"]|$)"#,
    // Bun and Deno inline execution (issue #397). Bun runs `-e`/`-p` exactly as
    // Node does, so the identical payload must reach the identical rules; before
    // this, swapping `node` for `bun` was a one-word bypass of a live deny.
    r#"\b(?:bun|deno)[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+(?:[:.=]\S*)?)(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*))?)*\s+['\x22]?-[A-Za-z]*[ep][A-Za-z]*(?:\s|['"]|$)"#,
    // Bun's `exec` subcommand hands its argument to a shell, so it is an inline
    // shell payload under a subcommand rather than a flag (issue #397).
    // The optional quote matches `subcommand_inline_payload`, which dequotes the
    // subcommand because quoting it does not change the argv Bun receives.
    // Without it, tier 1 rejected `bun "exec" '<payload>'` and the tier-2
    // walker that handles that spelling was unreachable.
    r#"\bbun[0-9.]*(?:\.exe)?\s+['"]?exec\b"#,
    // Deno's inline form is the `eval` subcommand, not a flag, so the
    // flag-shaped Bun/Deno trigger above never saw `deno eval "<code>"`.
    r#"\bdeno[0-9.]*(?:\.exe)?\s+['"]?eval\b"#,
    // awk hands `system(…)` and its two command-pipe forms to /bin/sh (#399).
    // Keyed on the awk-program shapes, not the executable, so an ordinary
    // `awk '{print $1}' file.txt` never reaches extraction.
    r"\bsystem\s*\(",
    r"\|\s*&?\s*getline\b",
    // awk's `print … | "cmd"`. A POSIX pipeline names a command after `|`, not
    // a quoted string, so this shape is awk's command pipe in practice; tier 1
    // deliberately over-matches and costs only a tier-2 extraction attempt.
    // The optional `\\` covers the shell-double-quoted spelling, where the awk
    // program's own quotes arrive escaped: `awk "BEGIN{ print 1 | \"cmd\" }"`.
    // Without it tier 1 rejected that command and the tier-2 extractor that
    // handles it was never reached.
    r#"\|\s*&?\s*\\?""#,
    // osascript's AppleScript and JXA shell sinks (#398). `doShellScript` is
    // the Standard Additions method every JXA example uses, so it needs its own
    // trigger: the spaced AppleScript keywords above do not match it.
    r"(?i)\bdo\s+shell\s+script\b",
    r"\$\.system\s*\(",
    r"\.doShellScript\s*\(",
    // PHP inline execution
    r#"\bphp[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+(?:[:.=]\S*)?)(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*))?)*\s+['\x22]?-[A-Za-z]*r[A-Za-z]*(?:\s|['"]|$)"#,
    // Lua inline execution
    r#"\blua[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+(?:[:.=]\S*)?)(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*))?)*\s+['\x22]?-[A-Za-z]*e[A-Za-z]*(?:\s|['"]|$)"#,
    // Shell inline execution (sh -c, bash -c, zsh -c, fish -c, bash -lc, etc.).
    // dash/ksh/mksh are ordinary POSIX shells: without them `dash -c "git
    // reset --hard"` was never unwrapped, and command-position rules such as
    // core.git never saw the payload. An option or its value may be quoted
    // (`bash -o 'errexit' -c`, `bash '-e' -c`); the argv is the same.
    r#"\b(?:sh|bash|zsh|fish|dash|ksh[0-9]*|mksh)(?:\.exe)?\b(?:\s+['\x22]?(?:--\S+|[-+][A-Za-z]+(?:[:.=]\S*)?['\x22]?)(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*|['\x22][A-Za-z_][A-Za-z0-9_]*['\x22]))?)*\s+['\x22]?-[A-Za-z]*c[A-Za-z]*(?:\s|['"]|$)"#,
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
    // PowerShell Start-Process (`saps`) with an argument list runs
    // `<file> <args>`; Tier 2 reconstructs that line and re-evaluates it.
    r"(?i)(?:^|[\s;|&({])(?:start-process|saps)\b[^\n]*\s(?:-ArgumentList|-Args)\b",
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
    //
    // A quoted or escaped name (`\ssh`, `'ssh'`) is the same program, and a
    // descriptor duplication (`2>&1`) does not end the segment.
    r#"(?i)(?:^|[\s;|&(/\\'"])ssh(?:\.exe)?['"]?\s(?:[^\n;|&]|[<>]&)*['"$]"#,
    // `watch '<cmd>'`, `parallel ::: '<cmd>'` / `parallel '<cmd>' ::: …`,
    // `env -S'<cmd>'`, `su -c '<cmd>'` and the other runners in
    // `COMMAND_STRING_RUNNERS` hand a command STRING to a shell (or, for
    // `env -S`, split it into argv), so they are inline-script wrappers like
    // `sh -c`. Superset of `command_string_runner_payloads`, which validates;
    // as for ssh, only a quote or `$` makes the payload invisible to raw
    // matching.
    // A name split by quoting (`w\atch`) is `names_a_runner_through_quoting`.
    r#"(?:^|[\s;|&(/\\'"])(?:watch|parallel|env|su|sg|runuser|script|nix-shell|npx|entr|flock|hyperfine)['"]?\s(?:[^\n;|&]|[<>]&)*['"$]"#,
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
    if contains_active_heredoc_operator(command)
        || HEREDOC_TRIGGERS.is_match(command)
        || names_a_runner_through_quoting(command)
        || blank_local_redirects(command).is_some_and(|view| HEREDOC_TRIGGERS.is_match(&view))
        || respelled_command_may_be_present(command)
    {
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
    if let Some(view) = blank_local_redirects(command) {
        for index in &HEREDOC_TRIGGERS.matches(&view) {
            if !matches.contains(&index) {
                matches.push(index);
            }
        }
        matches.sort_unstable();
    }
    if contains_active_heredoc_operator(command)
        || names_a_runner_through_quoting(command)
        || respelled_command_may_be_present(command)
    {
        matches.push(MANUAL_HEREDOC_TRIGGER_INDEX);
    }
    matches
}

/// The manual tier-1 triggers for command words the tier-2 readers re-spell:
/// a run-time command word (`w${x}atch '…'`, `$(echo git reset --hard)`), a
/// dashed Git built-in behind a wrapper (`xargs git-reset --hard`), and a
/// quoted `find` action (`find . '-delete'`). Cheap byte tests first.
fn respelled_command_may_be_present(command: &str) -> bool {
    may_wrap_dashed_git(command)
        || may_quote_a_find_action(command)
        || may_run_through_dynamic_command_word(command)
}

/// `command` with each unquoted local redirect word blank-filled, or `None`
/// when it has none. The shell removes a redirect from the argv wherever it
/// stands, so `sh 2>/dev/null -c '<cmd>'`, `sh -c 2>/dev/null '<cmd>'` and
/// `python3 &>log -c '<cmd>'` run `<cmd>`, while the inline-interpreter
/// patterns expect options and the flag to follow one another. They also
/// read this view (sixth review of GH #498); repeating a redirect fragment in
/// each pattern instead made the tier-1 set, which every hook call compiles,
/// about a millisecond slower to build.
///
/// A redirect word starts a word (or follows one directly, operator first):
/// optional descriptor digits or `{name}`, then `>`, `<`, `>>`, `<>`, `>|`,
/// `>&`, `<&`, `&>` or `&>>`, then its target, glued or after blanks
/// (`2> /dev/null`, `2>& 1`). A here-string (`<<<word`) is a redirect too
/// (`sh <<<x -c '<cmd>'` runs `<cmd>`); a heredoc (`<<`), a process
/// substitution (`<(`) and a word without a target are left alone. A target's
/// `$(…)`, `${…}` and backquoted parts belong to it (`2>$(mktemp) -c`). Text
/// inside quotes is never taken for a redirect, so a quoted payload reads the
/// same in both. Length
/// preserving (every blanked byte becomes a space, so the view stays UTF-8
/// and every range in it is the same range in `command`); linear.
fn blank_local_redirects(command: &str) -> Option<String> {
    let bytes = command.as_bytes();
    memchr::memchr2(b'<', b'>', bytes)?;
    let len = bytes.len();
    let mut view: Option<Vec<u8>> = None;
    let mut index = 0usize;
    let mut word_start = true;
    while index < len {
        let byte = bytes[index];
        if matches!(
            byte,
            b' ' | b'\t' | b'\n' | b'\r' | b';' | b'|' | b'(' | b')'
        ) || (byte == b'&' && bytes.get(index + 1) != Some(&b'>'))
        {
            word_start = true;
            index += 1;
            continue;
        }
        // A redirect may also follow a word directly (`sh>/dev/null -c …`
        // is `sh` and `>/dev/null`); its operator then starts it.
        if (word_start || matches!(byte, b'<' | b'>' | b'&'))
            && let Some(end) = local_redirect_word_end(bytes, index)
        {
            view.get_or_insert_with(|| bytes.to_vec())[index..end].fill(b' ');
            index = end;
            continue;
        }
        word_start = false;
        index = match byte {
            b'\\' => (index + 2).min(len),
            // `<<`, `<<-`, `<<<`: a heredoc or here-string operator, whose
            // second `<` must not be read as a redirect of the delimiter.
            b'<' => index + bytes[index..].iter().take_while(|&&b| b == b'<').count(),
            // `$'…'` takes backslash escapes, so `\'` does not close it.
            b'$' if bytes.get(index + 1) == Some(&b'\'') => {
                let mut at = index + 2;
                while at < len && bytes[at] != b'\'' {
                    at += if bytes[at] == b'\\' { 2 } else { 1 };
                }
                (at + 1).min(len)
            }
            b'\'' => memchr(b'\'', &bytes[index + 1..]).map_or(len, |at| index + 2 + at),
            b'"' => skip_double_quoted(bytes, index + 1),
            _ => index + 1,
        };
    }
    view.map(|view| String::from_utf8(view).expect("blank-filling whole characters keeps UTF-8"))
}

/// End of the local redirect word starting at `start` (see
/// [`blank_local_redirects`]), target included, or `None`.
fn local_redirect_word_end(bytes: &[u8], start: usize) -> Option<usize> {
    let len = bytes.len();
    let mut index = start;
    if bytes[index] == b'{' {
        // `{name}`: stop at the first byte that is not part of a name, so a
        // run of `{` is not rescanned to its end at each one.
        let name = bytes[index + 1..]
            .iter()
            .take_while(|byte| byte.is_ascii_alphanumeric() || **byte == b'_')
            .count();
        let close = index + 1 + name;
        if name == 0 || bytes[index + 1].is_ascii_digit() || bytes.get(close) != Some(&b'}') {
            return None;
        }
        index = close + 1;
    } else {
        while index < len && bytes[index].is_ascii_digit() {
            index += 1;
        }
    }
    let rest = &bytes[index..];
    let operator = if rest.starts_with(b"&>>") || rest.starts_with(b"<<<") {
        3
    } else if rest.starts_with(b"&>")
        || rest.starts_with(b">>")
        || rest.starts_with(b"<>")
        || rest.starts_with(b">|")
        || rest.starts_with(b">&")
        || rest.starts_with(b"<&")
    {
        2
    } else if matches!(rest.first(), Some(b'>' | b'<')) {
        1
    } else {
        return None;
    };
    if matches!(rest.get(operator), Some(b'(' | b'<')) {
        // `<(…)`/`>(…)`, `<<`, `<<<<`, `>>(…)`: not a plain redirect.
        return None;
    }
    index += operator;
    while index < len && matches!(bytes[index], b' ' | b'\t') {
        index += 1;
    }
    let target_start = index;
    while index < len {
        index = match bytes[index] {
            b' ' | b'\t' | b'\n' | b'\r' | b';' | b'&' | b'|' | b'(' | b')' | b'<' | b'>' => break,
            b'\\' => (index + 2).min(len),
            b'\'' => memchr(b'\'', &bytes[index + 1..]).map_or(len, |at| index + 2 + at),
            b'"' => skip_double_quoted(bytes, index + 1),
            b'`' => memchr(b'`', &bytes[index + 1..]).map_or(len, |at| index + 2 + at),
            b'$' if bytes.get(index + 1) == Some(&b'(') => {
                crate::normalize::consume_shell_paren_construct(bytes, index + 2, len)
            }
            b'$' if bytes.get(index + 1) == Some(&b'{') => {
                memchr(b'}', &bytes[index + 2..]).map_or(len, |at| index + 3 + at)
            }
            _ => index + 1,
        };
    }
    (index > target_start).then_some(index)
}

/// Index just past the double-quoted string whose body starts at `start`.
fn skip_double_quoted(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() {
        match bytes[index] {
            b'"' => return index + 1,
            b'\\' => index += 2,
            _ => index += 1,
        }
    }
    bytes.len()
}

/// Whether quoting inside a word hides a command-string runner's or `ssh`'s
/// name from the trigger patterns: `w\atch '<cmd>'`, `wat$'c'h '<cmd>'` and
/// `s'sh' h '<cmd>'` run `watch` and `ssh`, but no pattern sees the name.
/// Superset of what Tier 2 validates; linear.
fn names_a_runner_through_quoting(command: &str) -> bool {
    if !command
        .bytes()
        .any(|byte| matches!(byte, b'\\' | b'\'' | b'"'))
    {
        return false;
    }
    // Dequoting never removes an occurrence (no name holds a quote), so a
    // name the quoting hid shows as one more occurrence, even when the same
    // name also stands plainly elsewhere (`echo watch; w\atch '<cmd>'`). A
    // `$'…'` escape can spell one too (`$'\x77atch'`).
    let hidden = |text: &str| {
        let unquoted: String = text
            .chars()
            .filter(|ch| !matches!(ch, '\\' | '\'' | '"' | '$'))
            .collect();
        COMMAND_STRING_RUNNERS
            .iter()
            .copied()
            .chain(["ssh"])
            .any(|name| unquoted.matches(name).count() > command.matches(name).count())
    };
    hidden(command) || decode_ansi_c_strings(command).is_some_and(|decoded| hidden(&decoded))
}

/// `command` with the body of each Bash `$'…'` string decoded, or `None` when
/// no such string holds an escape. The name prefilters read it as well as the
/// raw text, since an escape can spell a program: `$'\x77atch'` is `watch`.
/// Double quotes are not tracked, so `"$'…'"` is decoded too; that only
/// widens a prefilter. Linear.
fn decode_ansi_c_strings(command: &str) -> Option<String> {
    let opens = command.find("$'")?;
    if !command[opens..].contains('\\') {
        return None;
    }
    let mut out = String::with_capacity(command.len());
    let mut chars = command.chars().peekable();
    let mut decoded_any = false;
    while let Some(ch) = chars.next() {
        match ch {
            '$' if chars.peek() == Some(&'\'') => {
                chars.next();
                let mut body = String::new();
                let closed = crate::normalize::decode_ansi_c_quoted(&mut chars, &mut body).is_ok();
                out.push('\'');
                out.push_str(&body);
                out.push('\'');
                decoded_any = true;
                if !closed {
                    break;
                }
            }
            '\'' => {
                out.push(ch);
                for inner in chars.by_ref() {
                    out.push(inner);
                    if inner == '\'' {
                        break;
                    }
                }
            }
            '\\' => {
                out.push(ch);
                if let Some(next) = chars.next() {
                    out.push(next);
                }
            }
            _ => out.push(ch),
        }
    }
    decoded_any.then_some(out)
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

impl ExtractionLimits {
    /// Limits for the helpers that answer a *structural* question — which
    /// heredoc bodies exist, and where one body begins and ends — rather than
    /// doing hot-path extraction work.
    ///
    /// `pub(crate)` for the four evaluator classification helpers that ask the
    /// same kind of question: is this a literal heredoc producer, is this
    /// offset inside a quoted body, does this range intersect interpreter
    /// input. Each turns a non-`Extracted` result straight into a
    /// classification — `Unverified`, `None`, `false` — so the wall clock
    /// decided the answer there too (#443).
    ///
    /// Same size caps as [`Self::default`], because those are what actually bound
    /// the work: the caller has already limited the input to 256 KiB, and a body
    /// is capped at 1 MiB / 10k lines / 10 heredocs. Only the wall clock differs,
    /// and it is generous deliberately. At 50 ms it expired under parallel load,
    /// the helper answered "no content", and the recovery declined — so a
    /// data-sink heredoc body that masks on an idle machine was re-scanned as
    /// live shell instead. The failing direction is over-blocking, so it was
    /// fail-safe, but "does this command contain one heredoc" is a property of
    /// the command and must not depend on how busy the machine is (#443).
    ///
    /// The budget is kept rather than removed so a pathological input still
    /// terminates; it is sized so that only descheduling, never ordinary work,
    /// could reach it.
    pub(crate) fn structural_scan() -> Self {
        Self {
            timeout_ms: 5_000,
            ..Self::default()
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
            || matches_interpreter("dash")
            || matches_interpreter("ksh")
            || matches_interpreter("mksh")
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

impl SkipReason {
    /// Whether this reason means the reading stopped early, so payloads that
    /// are present in the command were never read (#427).
    ///
    /// Every budget and abort qualifies: the extractor gave up with work left
    /// to do, which is what makes the result an incomplete reading and the
    /// caller's problem rather than the extractor's.
    ///
    /// `UnterminatedHeredoc` deliberately does not. It reports a shape — a
    /// `<<` with no terminator line — and nothing was dropped on account of
    /// it; the text is still in the command every pattern is matched against.
    /// It is also routinely a *misread* of ordinary data, because the operator
    /// appears in arithmetic (`$((1<<3))`), in prose that a rule is documented
    /// with (`git commit -m "explain <<EOF"`), and historically in the tail of
    /// a here-string. Treating it as an incomplete reading would put all of
    /// those on the bounded-fallback path and deny them outright under
    /// `fallback_on_parse_error=false`.
    #[must_use]
    pub fn stopped_early(&self) -> bool {
        match self {
            Self::ExceededSizeLimit { .. }
            | Self::ExceededLineLimit { .. }
            | Self::ExceededHeredocLimit { .. }
            | Self::BinaryContent { .. }
            | Self::Timeout { .. }
            | Self::MalformedInput { .. } => true,
            Self::UnterminatedHeredoc { .. } => false,
        }
    }
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
    Regex::new(r#"\b(python[0-9.]*(?:\.exe)?|ruby[0-9.]*(?:\.exe)?|irb[0-9.]*(?:\.exe)?|perl[0-9.]*(?:\.exe)?|node(js)?[0-9.]*(?:\.exe)?|bun[0-9.]*(?:\.exe)?|deno[0-9.]*(?:\.exe)?|php[0-9.]*(?:\.exe)?|lua[0-9.]*(?:\.exe)?|sh(?:\.exe)?|bash(?:\.exe)?|zsh(?:\.exe)?|fish(?:\.exe)?|dash(?:\.exe)?|ksh[0-9]*(?:\.exe)?|mksh(?:\.exe)?|(?i:powershell|pwsh)(?:\.exe)?)\b["']?(?:\s+['\x22]?(?:--\S+|[-+][A-Za-z]+(?:[:.=]\S*)?['\x22]?)(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*|['\x22][A-Za-z_][A-Za-z0-9_]*['\x22]))?)*\s+['\x22]?(-[A-Za-z]*[ceECpr][A-Za-z]*)['\x22]?\s*'([^']*)'"#)
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
    Regex::new(r#"\b(python[0-9.]*(?:\.exe)?|ruby[0-9.]*(?:\.exe)?|irb[0-9.]*(?:\.exe)?|perl[0-9.]*(?:\.exe)?|node(js)?[0-9.]*(?:\.exe)?|bun[0-9.]*(?:\.exe)?|deno[0-9.]*(?:\.exe)?|php[0-9.]*(?:\.exe)?|lua[0-9.]*(?:\.exe)?|sh(?:\.exe)?|bash(?:\.exe)?|zsh(?:\.exe)?|fish(?:\.exe)?|dash(?:\.exe)?|ksh[0-9]*(?:\.exe)?|mksh(?:\.exe)?|(?i:powershell|pwsh)(?:\.exe)?)\b['"]?(?:\s+['\x22]?(?:--\S+|[-+][A-Za-z]+(?:[:.=]\S*)?['\x22]?)(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*|['\x22][A-Za-z_][A-Za-z0-9_]*['\x22]))?)*\s+['\x22]?(-[A-Za-z]*[ceECpr][A-Za-z]*)['\x22]?\s*"([^"]*)""#)
        .expect("inline script double-quote regex compiles")
});

/// A POSIX shell `-c` whose operand is UNQUOTED and is a single expansion or
/// command substitution: `sh -c $CMD`, `bash -c $(cat f)`, `` dash -c `x` ``.
/// Only this dynamic shape is extracted; an unquoted literal operand runs just
/// its first word (`bash -c rm -rf /` runs `rm` with `-rf` as `$0`), which the
/// quoted patterns' semantics do not describe. The extracted source is wholly
/// dynamic, so the evaluator fails it closed like the quoted forms (bd-vweh).
/// Groups match the quoted patterns: (1) shell, (2) unused, (3) flag, (4) operand.
static INLINE_SCRIPT_UNQUOTED_DYNAMIC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(r"\b(sh|bash|zsh|fish|dash|ksh[0-9]*|mksh)(?:\.exe)?()\b(?:\s+['\x22]?(?:--\S+|[-+][A-Za-z]+(?:[:.=]\S*)?['\x22]?)(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*|['\x22][A-Za-z_][A-Za-z0-9_]*['\x22]))?)*\s+['\x22]?(-[A-Za-z]*c[A-Za-z]*)['\x22]?(?:\s+", shell_option_after_c_re!(), r")*\s+(\$\{[^}\s]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\$[0-9@*#?!$-]|\$\([^()]*\)|`[^`]*`)(?:\s|$|[;&|)])"))
        .expect("inline script unquoted-dynamic regex compiles")
});

/// A POSIX shell whose `-c` is followed by options before the quoted command
/// string: `sh -c -- '<cmd>'`, `sh -c - '<cmd>'`, `bash -c -e '<cmd>'`,
/// `bash -c -o errexit '<cmd>'`. The shell takes its first operand as the
/// command string, so the payload is that quoted word; the quoted patterns
/// above expect it right after the flag, so at least one option is required
/// here and a command both read is not read twice. Groups match the quoted
/// patterns: (1) shell, (2) unused, (3) flag, (4) content.
static INLINE_SHELL_OPTIONS_AFTER_C_SINGLE_QUOTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"\b(sh|bash|zsh|fish|dash|ksh[0-9]*|mksh)(?:\.exe)?()\b['\x22]?(?:\s+['\x22]?(?:--\S+|[-+][A-Za-z]+(?:[:.=]\S*)?['\x22]?)(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*|['\x22][A-Za-z_][A-Za-z0-9_]*['\x22]))?)*",
        r"\s+['\x22]?(-[A-Za-z]*c[A-Za-z]*)['\x22]?(?:\s+",
        shell_option_after_c_re!(),
        r")+\s+'([^']*)'"
    ))
    .expect("inline shell options-after-c single-quote regex compiles")
});

/// [`INLINE_SHELL_OPTIONS_AFTER_C_SINGLE_QUOTE`] for a double-quoted command
/// string.
static INLINE_SHELL_OPTIONS_AFTER_C_DOUBLE_QUOTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"\b(sh|bash|zsh|fish|dash|ksh[0-9]*|mksh)(?:\.exe)?()\b['\x22]?(?:\s+['\x22]?(?:--\S+|[-+][A-Za-z]+(?:[:.=]\S*)?['\x22]?)(?:\s+(?:[0-9]\S*|\S*[:/\\]\S*|[A-Za-z][A-Za-z0-9_]*|['\x22][A-Za-z_][A-Za-z0-9_]*['\x22]))?)*",
        r"\s+['\x22]?(-[A-Za-z]*c[A-Za-z]*)['\x22]?(?:\s+",
        shell_option_after_c_re!(),
        r")+\s+\x22([^\x22]*)\x22"
    ))
    .expect("inline shell options-after-c double-quote regex compiles")
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

/// Regex for `Start-Process [-FilePath] <file> -ArgumentList '<args>'` (or
/// `saps`, `-Args`, `-FilePath:`/`-ArgumentList:` colon forms). Group 1 = the
/// file, group 2/3 = the double/single-quoted argument string. A comma list
/// or a variable is not reconstructed (no extraction, no change).
static START_PROCESS_INLINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:^|[\s;|&({])(?:start-process|saps)\s+(?:-FilePath\s*:?\s*)?['"]?([^\s'",;|$()]+)['"]?\s+(?:-ArgumentList|-Args)\s*:?\s*(?:"([^"]*)"|'([^']*)')(?:\s|$|[;|&)])"#,
    )
    .expect("start-process inline regex compiles")
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
/// - `Extracted` means nothing was dropped. A budget or an abort that stops an
///   extractor — see [`SkipReason::stopped_early`] — yields `Partial` instead,
///   even when other payloads were read successfully, because the caller
///   decides what an incomplete reading is worth and cannot decide that if it
///   is told the reading was complete (#427).
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
    // Inline-script extraction scans a view whose *data* heredoc bodies are
    // blanked, while heredoc extraction keeps the raw text (#420).
    //
    // Both were scanning the raw command, so a quoted body destined for a data
    // sink was masked for pattern matching and simultaneously mined for inline
    // scripts: `git commit -F - <<'EOF'` whose message *describes*
    // `bash -c "rm -rf ~/x"` was denied, and so was a `cat > notes.md` heredoc
    // documenting the same thing. The text is data by every test the masker
    // applies — quoted delimiter, non-shell data sink, target not rebindable —
    // and `evaluate_heredoc`'s own skip already says so; it just never reached
    // the payload the extractor had already mined out of it.
    //
    // The mask is blank-fill and length preserving, so every `byte_range` an
    // extractor computes against the view is the same range in the original.
    let scan_view = mask_non_expanding_data_heredocs(command);
    extract_content_with_scan_view(command, scan_view.as_ref(), limits)
}

/// [`extract_content`], with the view that inline-script extraction scans given
/// explicitly.
///
/// `active_single_heredoc_fallback` calls this with `scan_view == command` to
/// break a cycle: masking asks `active_heredocs` where the bodies are, that
/// falls back to this extractor when the parse is ambiguous, and computing the
/// mask again there would not terminate. Scanning the raw text in that one
/// place is the conservative direction — it is what every caller did before.
fn extract_content_with_scan_view(
    command: &str,
    scan_view: &str,
    limits: &ExtractionLimits,
) -> ExtractionResult {
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

    // Extract inline scripts (-c/-e flags). These and the six extractors after
    // them read the scan view, so a payload quoted inside a data heredoc's body
    // is not mined out of it as a live invocation (#420). The heredoc and
    // here-string extractors below keep the raw command: their whole job is to
    // find those bodies.
    extract_inline_scripts(
        scan_view,
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
            ExtractionResult::Partial {
                extracted,
                skipped: skip_reasons,
            }
        };
    }

    // Extract Windows inline wrappers (cmd /c|/k, iex/Invoke-Expression, -EncodedCommand)
    extract_windows_inline_scripts(
        scan_view,
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
            ExtractionResult::Partial {
                extracted,
                skipped: skip_reasons,
            }
        };
    }

    // Extract `mise exec -c/--command` inline shell payloads (#259)
    extract_mise_inline_scripts(
        scan_view,
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
            ExtractionResult::Partial {
                extracted,
                skipped: skip_reasons,
            }
        };
    }

    // Extract `bun exec <payload>` inline shell payloads (#397)
    extract_bun_exec_inline_scripts(
        scan_view,
        limits,
        start_time,
        timeout,
        &mut extracted,
        &mut skip_reasons,
    );
    // Extract `deno eval <code>` inline JavaScript/TypeScript payloads
    extract_deno_eval_inline_scripts(
        scan_view,
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
            ExtractionResult::Partial {
                extracted,
                skipped: skip_reasons,
            }
        };
    }

    // Extract awk `system()` / command-pipe shell payloads (#399)
    extract_awk_inline_scripts(
        scan_view,
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
            ExtractionResult::Partial {
                extracted,
                skipped: skip_reasons,
            }
        };
    }

    // Extract `osascript -e 'do shell script "…"'` payloads (#398)
    extract_osascript_inline_scripts(
        scan_view,
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
            ExtractionResult::Partial {
                extracted,
                skipped: skip_reasons,
            }
        };
    }

    // Extract `ssh … destination <command…>` remote payloads (#326)
    extract_ssh_inline_scripts(
        scan_view,
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
            ExtractionResult::Partial {
                extracted,
                skipped: skip_reasons,
            }
        };
    }

    // `watch '<cmd>'`, `parallel ::: '<cmd>'`, `env -S'<cmd>'`
    extract_command_string_runner_scripts(
        scan_view,
        limits,
        start_time,
        timeout,
        &mut extracted,
        &mut skip_reasons,
    );
    // `xargs git-reset --hard`, `find . '-delete'`
    extract_respelled_commands(
        scan_view,
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
            ExtractionResult::Partial {
                extracted,
                skipped: skip_reasons,
            }
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
            ExtractionResult::Partial {
                extracted,
                skipped: skip_reasons,
            }
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
            // Something was extracted and something was skipped. When the skip
            // means the reading stopped early — a budget or an abort, see
            // `SkipReason::stopped_early` — this is not a complete reading of
            // the command and must not be reported as one (#427).
            // `Extracted` told the evaluator "here is all of
            // the embedded code", which skipped the bounded fallback and let
            // ten benign payloads hide an eleventh: `awk` with ten
            // `system("echo N")` calls followed by one `system("rm -rf ~/Documents")`
            // filled `max_heredocs` and was allowed, while nine pads were
            // blocked. The same padding starved the ssh/herestring/heredoc
            // extractors that run after the awk one.
            //
            // `Partial` is the case the evaluator already models: it analyses
            // what was extracted, then runs the bounded fallback over the whole
            // command because a source was skipped, and honours
            // `fallback_on_timeout` / `fallback_on_parse_error` for callers who
            // want an incomplete reading to be a denial outright.
            debug!(
                elapsed_us,
                count = extracted.len(),
                skip_count = skip_reasons.len(),
                "tier2_complete: partial extraction with skips"
            );
            if skip_reasons.iter().any(SkipReason::stopped_early) {
                ExtractionResult::Partial {
                    extracted,
                    skipped: skip_reasons,
                }
            } else {
                // Only shape observations, nothing dropped — see
                // `SkipReason::stopped_early`.
                ExtractionResult::Extracted(extracted)
            }
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

    // Helper to extract from a given regex pattern. The patterns read the
    // command and then its redirect view (`sh 2>/dev/null -c '…'`); the view
    // is length preserving, so a payload found in both is the same range and
    // is read once.
    let redirect_view = blank_local_redirects(command);
    let option_after_c_flag = std::iter::once(command)
        .chain(redirect_view.as_deref())
        .any(may_have_option_after_c_flag);
    let mut hit_limit = false;
    let mut extract_from_pattern = |pattern: &Regex| {
        let views = std::iter::once(command).chain(redirect_view.as_deref());
        for cap in views.flat_map(|view| pattern.captures_iter(view)) {
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
            // From `command`, not the view the match came from (same range).
            let content = content_match
                .and_then(|m| command.get(m.start()..m.end()))
                .unwrap_or("");

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
            } else if cmd_name.starts_with("bun") || cmd_name.starts_with("deno") {
                // Bun and Deno accept Node's inline-evaluation flags (issue #397).
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

            // A launcher spelled inside another command's quoted argument,
            // behind prose, is not one the shell runs (#510).
            if cap
                .get(1)
                .is_some_and(|name| inline_launcher_is_quoted_prose(command, name.start()))
            {
                continue;
            }

            // Enforce content size limit
            if content.len() > limits.max_body_bytes {
                // Skip but don't add to skip_reasons (would be too noisy)
                continue;
            }

            let full_match = cap.get(0).unwrap();
            let content_range = content_match.map(|m| m.start()..m.end());
            if content_range.is_some()
                && extracted
                    .iter()
                    .any(|seen| seen.content_range == content_range)
            {
                continue;
            }
            extracted.push(ExtractedContent {
                content: content.to_string(),
                language: ScriptLanguage::from_command(cmd_name),
                delimiter: None,
                byte_range: full_match.start()..full_match.end(),
                content_range,
                quoted: true, // -c/-e content is always in quotes
                heredoc_type: None,
                target_command: Some(cmd_name.to_string()), // -c/-e content is executed by the interpreter
            });
        }
    };

    // Extract from both single-quoted and double-quoted patterns
    extract_from_pattern(&INLINE_SCRIPT_SINGLE_QUOTE);
    extract_from_pattern(&INLINE_SCRIPT_DOUBLE_QUOTE);
    extract_from_pattern(&INLINE_SCRIPT_UNQUOTED_DYNAMIC);
    // Built and run only when some flag ending in `c` is followed by an
    // option, which few commands have; building them costs every other one
    // about a millisecond.
    if option_after_c_flag {
        extract_from_pattern(&INLINE_SHELL_OPTIONS_AFTER_C_SINGLE_QUOTE);
        extract_from_pattern(&INLINE_SHELL_OPTIONS_AFTER_C_DOUBLE_QUOTE);
    }

    if hit_limit {
        skip_reasons.push(SkipReason::ExceededHeredocLimit {
            limit: limits.max_heredocs,
        });
    }
}

/// Whether the inline launcher whose interpreter word starts at
/// `launcher_start` is prose inside another command's quoted argument rather
/// than a command any shell runs (#510).
///
/// The inline-script patterns match a launcher anywhere in the text, so
/// `tracker comment 1 "example: bash -c 'git reset --hard' is refused"` was
/// denied as if it ran `git reset --hard`. It does not, under either reading
/// of that quoted word:
///
/// - as data (what dcg already assumes for an unknown program's operands:
///   `tracker comment 1 "git reset --hard"` is allowed), nothing runs it;
/// - as a shell string some program hands to `sh -c`, its command word is
///   `example:`, and `bash` is an operand of that program, not a launcher.
///
/// So a launcher is dropped only when BOTH hold: it sits inside single or
/// double quotes (not inside a `$(…)` or backquote substitution, which run
/// whatever their quoting), and inside that quoted text the simple command
/// it belongs to starts with a plain word that is not a shell, interpreter,
/// wrapper, command runner or reserved word. A launcher that opens the
/// quoted text (`tmux new "bash -c '…'"`, `"bash" -c '…'`), follows a
/// separator inside it (`"x; bash -c '…'"`), or follows a wrapper
/// (`"sudo bash -c '…'"`) is kept, because a program that runs its operand
/// as a shell string would run that launcher.
///
/// Anything this walk cannot follow keeps the launcher: a heredoc (its body
/// is not shell-quoted, so one apostrophe in it would flip the quote state),
/// a comment, a `${…}` expansion, an ANSI-C `$'…'` string, or an escaped
/// interpreter word.
fn inline_launcher_is_quoted_prose(command: &str, launcher_start: usize) -> bool {
    if command.contains("<<") {
        return false;
    }
    let Some(quote_open) = innermost_shell_quote_at(command, launcher_start) else {
        return false;
    };
    command
        .get(quote_open + 1..launcher_start)
        .is_some_and(quoted_launcher_prefix_is_prose)
}

/// The byte offset of the quote that opens the innermost single- or
/// double-quoted string containing `position`, when that string is the
/// innermost shell context there. `None` when `position` is unquoted, sits
/// inside a `$(…)`/backquote substitution, or the text before it uses a
/// construct this walk does not model (see [`inline_launcher_is_quoted_prose`]).
fn innermost_shell_quote_at(command: &str, position: usize) -> Option<usize> {
    #[derive(Clone, Copy)]
    enum Context {
        Single(usize),
        Double(usize),
        Substitution(usize),
        Backquote,
    }
    let bytes = command.as_bytes();
    if position > bytes.len() {
        return None;
    }
    let mut stack: Vec<Context> = Vec::new();
    let mut index = 0usize;
    while index < position {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        match stack.last().copied() {
            Some(Context::Single(_)) => {
                if byte == b'\'' {
                    stack.pop();
                }
                index += 1;
            }
            Some(Context::Double(_)) => match byte {
                b'\\' => index += 2,
                b'"' => {
                    stack.pop();
                    index += 1;
                }
                b'$' if next == Some(b'(') => {
                    stack.push(Context::Substitution(1));
                    index += 2;
                }
                b'$' if next == Some(b'{') => return None,
                b'`' => {
                    stack.push(Context::Backquote);
                    index += 1;
                }
                _ => index += 1,
            },
            top => match byte {
                b'\\' => index += 2,
                b'\'' => {
                    if index > 0 && bytes[index - 1] == b'$' {
                        return None;
                    }
                    stack.push(Context::Single(index));
                    index += 1;
                }
                b'"' => {
                    stack.push(Context::Double(index));
                    index += 1;
                }
                b'`' => {
                    if matches!(top, Some(Context::Backquote)) {
                        stack.pop();
                    } else {
                        stack.push(Context::Backquote);
                    }
                    index += 1;
                }
                b'$' if next == Some(b'(') => {
                    stack.push(Context::Substitution(1));
                    index += 2;
                }
                b'$' if next == Some(b'{') => return None,
                b'(' => {
                    if let Some(Context::Substitution(depth)) = stack.last_mut() {
                        *depth += 1;
                    }
                    index += 1;
                }
                b')' => {
                    if let Some(Context::Substitution(depth)) = stack.last_mut() {
                        *depth -= 1;
                        if *depth == 0 {
                            stack.pop();
                        }
                    }
                    index += 1;
                }
                b'#' if index == 0
                    || matches!(
                        bytes[index - 1],
                        b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'(' | b'`'
                    ) =>
                {
                    return None;
                }
                _ => index += 1,
            },
        }
    }
    // An escape that swallowed the interpreter's first byte: not a plain word.
    if index != position {
        return None;
    }
    match stack.last() {
        Some(Context::Single(open) | Context::Double(open)) => Some(*open),
        _ => None,
    }
}

/// Whether, in the quoted text before a launcher, the simple command the
/// launcher belongs to starts with a plain prose word that runs nothing (see
/// [`inline_launcher_is_quoted_prose`]).
///
/// The simple command is found by cutting at the LAST separator byte, quoted
/// or not. Over-cutting can only shorten the prefix and so make the launcher
/// look like a command word, which keeps it: the conservative direction.
fn quoted_launcher_prefix_is_prose(prefix: &str) -> bool {
    let segment_start = prefix
        .rfind(|c: char| {
            matches!(
                c,
                ';' | '&' | '|' | '\n' | '\r' | '(' | ')' | '{' | '}' | '`'
            )
        })
        .map_or(0, |at| at + 1);
    let segment = &prefix[segment_start..];
    let mut words: Vec<&str> = segment.split_ascii_whitespace().collect();
    // Text glued to the interpreter word (`/usr/bin/` of `/usr/bin/bash`, an
    // opening quote) is part of the launcher's own word.
    if !segment.ends_with(|c: char| c.is_ascii_whitespace()) {
        words.pop();
    }
    let Some(first) = words
        .into_iter()
        .find(|word| !crate::normalize::is_env_assignment(word))
    else {
        // Nothing but assignments before it: the launcher is the command word.
        return false;
    };
    let plain = !first.starts_with('-')
        && first.bytes().any(|byte| byte.is_ascii_alphanumeric())
        && first.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'_' | b'-' | b'.' | b',' | b':' | b'/' | b'+' | b'@' | b'?'
                )
        });
    if !plain {
        return false;
    }
    let basename = first
        .rsplit('/')
        .next()
        .unwrap_or(first)
        .to_ascii_lowercase();
    let basename = basename.strip_suffix(".exe").unwrap_or(&basename);
    !word_may_run_its_operands(basename)
}

/// Whether a command word names something that may run another command among
/// its operands: a shell, an interpreter, a wrapper, a command runner, a
/// remote or sandboxed executor, a build or package runner, or a shell
/// reserved word. Deliberately broad; see [`inline_launcher_is_quoted_prose`].
fn word_may_run_its_operands(name: &str) -> bool {
    is_code_runner_name(name)
        || COMMAND_WRAPPERS.contains(&name)
        || PRIMARY_COMMAND_WRAPPERS.contains(&name)
        || matches!(
            name,
            "if" | "then"
                | "else"
                | "elif"
                | "fi"
                | "do"
                | "done"
                | "while"
                | "until"
                | "case"
                | "esac"
                | "for"
                | "in"
                | "select"
                | "function"
                | "coproc"
                | "find"
                | "fd"
                | "git"
                | "make"
                | "gmake"
                | "just"
                | "task"
                | "npm"
                | "npx"
                | "pnpm"
                | "yarn"
                | "bunx"
                | "uv"
                | "uvx"
                | "poetry"
                | "pipx"
                | "cargo"
                | "direnv"
                | "nix"
                | "nix-shell"
                | "devbox"
                | "firejail"
                | "bwrap"
                | "unshare"
                | "proot"
                | "fakeroot"
                | "strace"
                | "ltrace"
                | "valgrind"
                | "perf"
                | "hyperfine"
                | "entr"
                | "runuser"
                | "sg"
                | "newgrp"
                | "pkexec"
                | "gosu"
                | "su-exec"
                | "setpriv"
                | "sshpass"
                | "xvfb-run"
                | "dbus-run-session"
                | "vagrant"
                | "ansible"
                | "pdsh"
                | "clush"
                | "pssh"
                | "parallel-ssh"
                | "winpty"
                | "wsl"
        )
}

/// Whether a `c` is followed by blanks and then `-` or `+`, optionally behind
/// a quote: a superset of a shell's `-c` followed by an option
/// (`sh -c -- '…'`, `sh -c '-e' '…'`), the only commands
/// [`INLINE_SHELL_OPTIONS_AFTER_C_SINGLE_QUOTE`] and its double-quote twin
/// can match. Linear: each blank run follows one `c`.
fn may_have_option_after_c_flag(text: &str) -> bool {
    let bytes = text.as_bytes();
    memchr::memchr_iter(b'c', bytes).any(|at| {
        let rest = &bytes[at + 1..];
        let blanks = rest.iter().take_while(|b| b.is_ascii_whitespace()).count();
        let quote = usize::from(matches!(rest.get(blanks), Some(b'\'' | b'"')));
        blanks > 0 && matches!(rest.get(blanks + quote), Some(b'-' | b'+'))
    })
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

    // Each pattern also reads the redirect view (`pwsh 2>$null -enc …`,
    // `cmd 2>nul /c …`; see `blank_local_redirects`). The view is length
    // preserving, so payload text is taken from `command` by range and a
    // payload both readings find is read once.
    let redirect_view = blank_local_redirects(command);
    let views: Vec<&str> = std::iter::once(command)
        .chain(redirect_view.as_deref())
        .collect();
    let text = |m: regex::Match<'_>| command.get(m.start()..m.end()).unwrap_or("");

    // cmd /c | /k  (double-quoted, single-quoted, or unquoted rest-of-line)
    for cap in windows_view_captures(&CMD_INLINE_SCRIPT, &views, &[1, 2, 3]) {
        if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
            return;
        }
        if let Some(m) = cap.get(1).or_else(|| cap.get(2)).or_else(|| cap.get(3)) {
            let full = cap.get(0).expect("group 0 always present");
            if !push_windows_inner(
                extracted,
                skip_reasons,
                limits,
                text(m),
                full.start()..full.end(),
                Some(m.start()..m.end()),
                "cmd",
            ) {
                return;
            }
        }
    }

    // iex / Invoke-Expression "<code>"
    for cap in windows_view_captures(&IEX_INLINE_SCRIPT, &views, &[1, 2]) {
        if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
            return;
        }
        if let Some(m) = cap.get(1).or_else(|| cap.get(2)) {
            let full = cap.get(0).expect("group 0 always present");
            if !push_windows_inner(
                extracted,
                skip_reasons,
                limits,
                text(m),
                full.start()..full.end(),
                Some(m.start()..m.end()),
                "iex",
            ) {
                return;
            }
        }
    }

    // Start-Process <file> -ArgumentList '<args>': the process runs `<file>
    // <args>`, so `Start-Process cmd -ArgumentList '/c rd /s /q C:\src'` is the
    // same deletion as the denied `cmd /c rd /s /q C:\src`. The reconstructed
    // line is not a substring of the command, so there is no content_range.
    for cap in windows_view_captures(&START_PROCESS_INLINE, &views, &[2, 3]) {
        if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
            return;
        }
        let (Some(file), Some(args)) = (cap.get(1), cap.get(2).or_else(|| cap.get(3))) else {
            continue;
        };
        let full = cap.get(0).expect("group 0 always present");
        let line = format!("{} {}", text(file), text(args));
        if !push_windows_inner(
            extracted,
            skip_reasons,
            limits,
            &line,
            full.start()..full.end(),
            None,
            "start-process",
        ) {
            return;
        }
    }

    // powershell -EncodedCommand <base64>  (decode base64 UTF-16LE, then re-evaluate)
    for cap in windows_view_captures(&POWERSHELL_ENCODED_COMMAND, &views, &[1]) {
        if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
            return;
        }
        let Some(b64) = cap.get(1) else { continue };
        let Some(decoded) = decode_powershell_encoded_command(text(b64)) else {
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

/// `pattern`'s captures in each of `views` (the command, then its redirect
/// view), dropping a capture whose payload (the first of `payload_groups`
/// that matched) was already captured at the same range: the views are the
/// same length, so that is the same payload read twice. Lazy, so a caller
/// that stops at the extraction limit stops the scan too.
fn windows_view_captures<'a>(
    pattern: &'a Regex,
    views: &'a [&'a str],
    payload_groups: &'a [usize],
) -> impl Iterator<Item = regex::Captures<'a>> + 'a {
    let mut seen = std::collections::HashSet::new();
    views
        .iter()
        .flat_map(move |view| pattern.captures_iter(view))
        .filter(move |cap| {
            payload_groups
                .iter()
                .find_map(|&group| cap.get(group))
                .is_none_or(|m| seen.insert((m.start(), m.end())))
        })
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

/// The basename an executable token actually launches: one layer of whole-token
/// quoting removed, directories stripped, and a trailing `.exe` removed in any
/// case. Callers compare the result with `eq_ignore_ascii_case`.
///
/// Quoting an executable is invisible to the kernel — `"awk" 'prog'` and
/// `awk 'prog'` produce identical argv — and macOS, the only platform that
/// ships `osascript`, is case-insensitive by default, so `OSASCRIPT` really
/// does run. Matching the raw token missed every one of those spellings.
/// An executable word with shell quoting removed throughout, not only at its
/// ends.
///
/// The shell resolves `a"wk"`, `aw\k` and `$'awk'` to the same program as a
/// bare `awk`, and dcg's `sh`/`python`/`node`/`perl` paths already see through
/// those spellings. Stripping only whole-token quotes left the awk and
/// osascript extractors inconsistent with the rest of the file, so
/// `a"wk" 'BEGIN{ system("…") }'` extracted nothing while `"awk" '…'` worked.
fn dequoted_executable_word(word: &str) -> std::borrow::Cow<'_, str> {
    if !word
        .bytes()
        .any(|b| matches!(b, b'"' | b'\'' | b'\\' | b'$'))
    {
        return std::borrow::Cow::Borrowed(word);
    }
    // The shell's own quote removal when the word has no expansion, which
    // also decodes `$'…'` escapes: `$'\x77atch'` runs `watch`. A word it
    // cannot decode keeps the looser reading below.
    if let std::borrow::Cow::Owned(decoded) = crate::normalize::decode_posix_syntax_token(word) {
        return std::borrow::Cow::Owned(decoded);
    }
    let bytes = word.as_bytes();
    let mut out = String::with_capacity(word.len());
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            // The backslash is syntax; whatever it escapes is a literal.
            b'\\' if index + 1 < bytes.len() => {
                let next = index + 1;
                let end = word[next..]
                    .chars()
                    .next()
                    .map_or(next, |c| next + c.len_utf8());
                out.push_str(&word[next..end]);
                index = end;
            }
            // `$'…'` and `$"…"` are quoting forms, so the `$` is syntax too.
            b'$' if matches!(bytes.get(index + 1), Some(b'\'' | b'"')) => index += 1,
            b'\'' | b'"' => index += 1,
            _ => {
                let Some(c) = word[index..].chars().next() else {
                    break;
                };
                out.push(c);
                index += c.len_utf8();
            }
        }
    }
    std::borrow::Cow::Owned(out)
}

fn interpreter_basename(word: &str) -> &str {
    let (word, _, _) = dequoted_flag_word(word, 0, word.len());
    let basename = word.rsplit(['/', '\\']).next().unwrap_or(word);
    if basename.len() > 4 {
        let split = basename.len() - 4;
        if basename.is_char_boundary(split) {
            let (stem, extension) = basename.split_at(split);
            if extension.eq_ignore_ascii_case(".exe") {
                return stem;
            }
        }
    }
    basename
}

/// Whether `haystack` contains `needle` (ASCII) ignoring case.
fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    let (haystack, needle) = (haystack.as_bytes(), needle.as_bytes());
    if needle.is_empty() || haystack.len() < needle.len() {
        return needle.is_empty();
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

/// Whether `command` could name the interpreter `needle`, allowing for shell
/// quoting spliced anywhere into the word and for any letter case.
///
/// This is the inline-script extractors' cheap pre-gate, and a plain substring
/// test was wrong in two directions. A case-varied `AWK` skipped it, and so did
/// every spelling that splits the name with quoting: `a"wk"`, `aw\k` and
/// `$'awk'` contain no contiguous `awk`, so the gate rejected them before
/// tokenization even though `dequoted_executable_word` behind it resolves all
/// three. The gate has to be at least as permissive as the matcher it guards.
///
/// The contiguous test runs first because it is both the common case and the
/// cheaper one. The quoting-aware walk runs only when that fails, and is bounded
/// by `general.max_command_bytes` times the single-digit needle length.
fn names_interpreter(command: &str, needle: &str) -> bool {
    names_interpreter_as_written(command, needle)
        || decode_ansi_c_strings(command)
            .is_some_and(|decoded| names_interpreter_as_written(&decoded, needle))
}

fn names_interpreter_as_written(command: &str, needle: &str) -> bool {
    if contains_ascii_case_insensitive(command, needle) {
        return true;
    }
    let bytes = command.as_bytes();
    let needle = needle.as_bytes();
    // A `$` is quoting syntax only in `$'…'`/`$"…"`, but treating every `$` as
    // skippable merely widens this gate, and the executable matcher behind it
    // still has to agree before anything is extracted.
    let is_quoting = |b: u8| matches!(b, b'"' | b'\'' | b'\\' | b'$');
    (0..bytes.len()).any(|start| {
        if is_quoting(bytes[start]) {
            return false;
        }
        let mut matched = 0usize;
        let mut index = start;
        while index < bytes.len() && matched < needle.len() {
            let byte = bytes[index];
            index += 1;
            if is_quoting(byte) {
                continue;
            }
            if !byte.eq_ignore_ascii_case(&needle[matched]) {
                return false;
            }
            matched += 1;
        }
        matched == needle.len()
    })
}

/// Whether a `Word` token actually opens a redirection of the *local* command
/// (`>file`, `2>`, `>>out`, `&>log`, `<in`).
///
/// The normalizer keeps `>` inside words, so a redirect reaches the token
/// stream as a Word rather than a Separator. A quoted or escaped leading byte
/// means the glyph is data, not syntax, so only a bare operator counts.
fn word_token_starts_local_redirect(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = redirect_descriptor_prefix_len(text);
    if index == 0 {
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
    }
    match bytes.get(index) {
        Some(b'>' | b'<') => true,
        // `&>`/`&>>` (bash) redirect both streams; `&` alone is a separator
        // and never reaches this function as part of a Word.
        Some(b'&') if index == 0 => bytes.get(1) == Some(&b'>'),
        _ => false,
    }
}

/// Length of a `{name}` descriptor-variable prefix (`{fd}>file`, bash 4.1+),
/// or 0. It allocates a descriptor and stores its number in `name`; like a
/// numbered descriptor it belongs to the redirect, not to the argv.
fn redirect_descriptor_prefix_len(text: &str) -> usize {
    let Some(rest) = text.strip_prefix('{') else {
        return 0;
    };
    let Some(close) = rest.find('}') else {
        return 0;
    };
    let name = &rest[..close];
    let valid = name
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    if valid && matches!(rest.as_bytes().get(close + 1), Some(b'>' | b'<')) {
        close + 2
    } else {
        0
    }
}

/// Byte spans of one `ssh … destination <command…>` remote payload.
struct SshRemotePayload {
    /// Payload text: for a single payload word, one layer of matching
    /// surrounding quotes removed; for multiple words, the raw span from the
    /// first payload byte to the last, per-word quoting intact (see `joined`
    /// for the line the program actually hands on).
    content: Range<usize>,
    /// Full `ssh … <payload>` span, for span attribution.
    full: Range<usize>,
    /// The content is several argv words that the program joins with spaces
    /// before a shell parses the result (`ssh`, `watch`, a `parallel`
    /// template, `env -S` plus its trailing words). The local shell removes
    /// each word's quoting first, so `ssh h 'git reset' --hard` runs
    /// `git reset --hard` remotely while the raw span still reads as one
    /// quoted word; see [`joined_payload_words`].
    joined: bool,
}

/// A multi-word payload as the program that joins its argv hands it on: each
/// word with one round of shell quoting removed, joined with spaces. `None`
/// when that is the raw text already, or when the span is not a plain run of
/// words.
fn joined_payload_words(raw: &str) -> Option<String> {
    let tokens = crate::normalize::tokenize_for_normalization(raw);
    let mut out = String::with_capacity(raw.len());
    for token in &tokens {
        if token.kind != crate::normalize::NormalizeTokenKind::Word {
            return None;
        }
        let text = token.text(raw)?;
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&crate::normalize::decode_posix_syntax_token(text));
    }
    (out != raw).then_some(out)
}

/// Push a runner or `ssh` payload for re-evaluation: the raw span, and for a
/// joined multi-word payload also the joined command line (which is not a
/// substring of the command, so it carries no content range). `false` when
/// the extraction limit stopped it.
fn push_joined_payload(
    command: &str,
    payload: SshRemotePayload,
    limits: &ExtractionLimits,
    extracted: &mut Vec<ExtractedContent>,
    skip_reasons: &mut Vec<SkipReason>,
    target: &str,
) -> bool {
    let Some(content) = command.get(payload.content.clone()) else {
        return true;
    };
    if !push_windows_inner(
        extracted,
        skip_reasons,
        limits,
        content,
        payload.full.clone(),
        Some(payload.content.clone()),
        target,
    ) {
        return false;
    }
    if payload.joined
        && let Some(joined) = joined_payload_words(content)
    {
        return push_windows_inner(
            extracted,
            skip_reasons,
            limits,
            &joined,
            payload.full,
            None,
            target,
        );
    }
    true
}

/// ssh short options that consume a value (OpenSSH `getopt` string; the value
/// may be attached, `-p22`, or the following argv word, `-p 22`).
pub(crate) const SSH_VALUE_OPTIONS: &[u8] = b"BbcDEeFIiJLlmOoPpQRSWw";
/// ssh short options that take no value and may be bundled (`-fnT`).
const SSH_FLAG_OPTIONS: &[u8] = b"1246AaCfGgKkMNnqsTtVvXxYy";

pub(crate) enum SshOptionShape {
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
pub(crate) fn classify_ssh_option(word: &str) -> SshOptionShape {
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
/// `bun exec <payload>` hands `<payload>` to Bun's shell, so it is an
/// inline-shell wrapper exactly like `sh -c` (issue #397). The payload is
/// positional rather than flag-introduced, hence its own walk.
///
/// Conservative in the accuracy-preserving direction: the payload must be the
/// first non-option word after the `exec` subcommand. An option whose arity dcg
/// does not model would make that word ambiguous, so any unmodeled option ends
/// the walk with no extraction and the command keeps exactly today's raw-token
/// visibility. `bun exec` takes no options of its own in current Bun, so the
/// modeled set is deliberately small.
fn extract_bun_exec_inline_scripts(
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
    if !command.contains("bun") {
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
        // Path-qualified spellings (`/usr/local/bin/bun`, `bun.exe`) are the
        // same program.
        let basename = word.rsplit(['/', '\\']).next().unwrap_or(word);
        let basename = basename
            .strip_suffix(".exe")
            .or_else(|| basename.strip_suffix(".EXE"))
            .unwrap_or(basename);
        if basename != "bun" {
            continue;
        }
        let Some(payload) = subcommand_inline_payload(command, &tokens, index, "exec", &[]) else {
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
            "bun",
        ) {
            return;
        }
    }
}

/// `deno eval [options] "<code>"` runs `<code>` as JavaScript/TypeScript: the
/// Deno counterpart of `node -e`. Deno has no `-e` flag, so the flag-shaped
/// inline extraction never saw it and `deno eval "Deno.removeSync('src',
/// {recursive: true})"` was allowed while the `node -e` spelling of the same
/// deletion denied. Same conservative walk as `bun exec`, with Deno's
/// no-value options modeled (see [`DENO_EVAL_OPTIONS`]).
fn extract_deno_eval_inline_scripts(
    command: &str,
    limits: &ExtractionLimits,
    start_time: Instant,
    timeout: Duration,
    extracted: &mut Vec<ExtractedContent>,
    skip_reasons: &mut Vec<SkipReason>,
) {
    if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons)
        || !command.contains("deno")
    {
        return;
    }
    let tokens = crate::normalize::tokenize_for_normalization(command);
    for index in 0..tokens.len() {
        let token = &tokens[index];
        if token.kind != crate::normalize::NormalizeTokenKind::Word {
            continue;
        }
        let Some(word) = token.text(command) else {
            continue;
        };
        let basename = word.rsplit(['/', '\\']).next().unwrap_or(word);
        let basename = basename
            .strip_suffix(".exe")
            .or_else(|| basename.strip_suffix(".EXE"))
            .unwrap_or(basename);
        if basename != "deno" {
            continue;
        }
        let Some(payload) =
            subcommand_inline_payload(command, &tokens, index, "eval", DENO_EVAL_OPTIONS)
        else {
            continue;
        };
        let Some(content) = command.get(payload.content.clone()) else {
            continue;
        };
        if extracted.len() >= limits.max_heredocs {
            skip_reasons.push(SkipReason::ExceededHeredocLimit {
                limit: limits.max_heredocs,
            });
            return;
        }
        if content.len() > limits.max_body_bytes {
            continue;
        }
        extracted.push(ExtractedContent {
            content: content.to_string(),
            language: ScriptLanguage::from_command("deno"),
            delimiter: None,
            byte_range: payload.full,
            content_range: Some(payload.content),
            quoted: true,
            heredoc_type: None,
            target_command: Some("deno".to_string()),
        });
    }
}

/// Options `deno eval` accepts that take no separate value word. `--name=value`
/// spellings are accepted generically by the walker; anything else (a
/// value-taking option spelled `--config file`) ends the walk unextracted.
const DENO_EVAL_OPTIONS: &[&str] = &[
    "-p",
    "--print",
    "-T",
    "--ts",
    "-A",
    "--allow-all",
    "-q",
    "--quiet",
];

/// Locate the payload of a `<executable> <subcommand> [options] <payload>`
/// invocation whose executable token is at `start` (`bun exec`, `deno eval`).
/// `options` lists the no-value options allowed between the subcommand and
/// the payload; `--name=value` and Deno's `--allow-*`/`--deny-*`/`--unstable*`
/// families are also skipped when any options are modeled.
fn subcommand_inline_payload(
    command: &str,
    tokens: &[crate::normalize::NormalizeToken],
    start: usize,
    subcommand: &str,
    options: &[&str],
) -> Option<MiseInlinePayload> {
    use crate::normalize::NormalizeTokenKind;

    let full_start = tokens.get(start)?.byte_range.start;
    let mut index = start + 1;

    // Phase 1: reach the subcommand. Quoting a subcommand does not change the
    // argv the program receives, so `bun "exec" '<payload>'` walks the same
    // grammar.
    let token = tokens.get(index)?;
    if token.kind != NormalizeTokenKind::Word {
        return None;
    }
    let (word, _, _) = dequoted_flag_word(
        token.text(command)?,
        token.byte_range.start,
        token.byte_range.end,
    );
    // Any other word is a different subcommand (`bun run`, `bun install`), and
    // any option before the subcommand has unmodeled arity.
    if word != subcommand {
        return None;
    }
    index += 1;

    // Phase 2: skip the modeled no-value options, then the payload is the next
    // word. Any other option is unmodeled grammar, so extract nothing rather
    // than guess.
    loop {
        let value = tokens.get(index)?;
        if value.kind != NormalizeTokenKind::Word {
            return None;
        }
        let text = command.get(value.byte_range.clone())?;
        if !text.starts_with('-') {
            break;
        }
        let modeled = !options.is_empty()
            && (options.contains(&text)
                || (text.starts_with("--") && text.contains('='))
                || ["--allow-", "--deny-", "--unstable"]
                    .iter()
                    .any(|family| text.starts_with(family)));
        if !modeled {
            return None;
        }
        index += 1;
    }
    let value = tokens.get(index)?;
    let text = command.get(value.byte_range.clone())?;
    Some(MiseInlinePayload {
        content: unquoted_payload_range(text, value.byte_range.start),
        full: full_start..value.byte_range.end,
    })
}

/// Executable names whose first non-option argument is an awk program.
/// `original-awk` is the Debian/Ubuntu package name for onetrueawk, which is
/// also what macOS ships as `/usr/bin/awk`. `goawk` and `frawk` are drop-in
/// reimplementations that honour `system()` and the command pipes identically.
const AWK_EXECUTABLES: &[&str] = &[
    "awk",
    "gawk",
    "mawk",
    "nawk",
    "original-awk",
    "goawk",
    "frawk",
    "busybox",
];

/// Extract the shell payloads an awk program hands to `/bin/sh` (issue #399).
///
/// awk's `system("…")` runs its argument through the shell, and awk's two
/// command-pipe forms (`print … | "cmd"` and `"cmd" | getline`) do the same.
/// `awk 'BEGIN{ system("rm -rf ~/Documents") }'` is therefore the denied
/// `sh -c "rm -rf ~/Documents"` behind an awk program, and awk appears
/// constantly in agent-written pipelines.
///
/// Keyed on those three shapes inside the program text, never on the awk
/// executable alone, so ordinary programs (`awk '{print $1}' file.txt`,
/// `awk '$3 > $4 { print }'`) extract nothing — including ones that merely
/// *print* a dangerous-looking string, which awk does not execute.
fn extract_awk_inline_scripts(
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
    if !names_interpreter(command, "awk") {
        return;
    }

    let tokens = crate::normalize::tokenize_for_normalization(command);
    // `busybox awk 'prog'` resolves to the same program from two token
    // positions — once from `busybox` consuming its applet name, and once from
    // `awk` itself — so without this the payload is extracted twice and burns
    // two of the `max_heredocs` slots for one sink.
    let mut seen: Vec<Range<usize>> = Vec::new();
    for index in 0..tokens.len() {
        if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
            return;
        }
        for program in awk_program_tokens(command, &tokens, index) {
            if seen.contains(&program) {
                continue;
            }
            seen.push(program.clone());
            let Some(program_text) = command.get(program.clone()) else {
                continue;
            };
            let payloads = awk_shell_payload_ranges(program_text, program.start);
            for payload in payloads.commands {
                let Some(content) = command.get(payload.clone()) else {
                    continue;
                };
                if !push_windows_inner(
                    extracted,
                    skip_reasons,
                    limits,
                    content,
                    program.clone(),
                    Some(payload),
                    "awk",
                ) {
                    return;
                }
            }
            for printed in payloads.printed {
                // A variable the command line can reassign (`-v cmd=…`, a
                // `cmd=…` operand) is not the literal the program assigns.
                let reassignable = printed.variable.as_deref().is_some_and(|name| {
                    let assignment = format!("{name}=");
                    command
                        .get(..program.start)
                        .is_some_and(|head| head.contains(&assignment))
                        || command
                            .get(program.end..)
                            .is_some_and(|tail| tail.contains(&assignment))
                });
                let script = match printed.script {
                    Some(script) if !reassignable => script,
                    // Computed at run time: a script whose whole source is an
                    // expansion, which the evaluator fails closed exactly as it
                    // does `bash -c "$X"`.
                    _ => AWK_COMPUTED_PRINT_SCRIPT.to_string(),
                };
                if !push_windows_inner(
                    extracted,
                    skip_reasons,
                    limits,
                    &script,
                    program.clone(),
                    Some(printed.range),
                    "awk",
                ) {
                    return;
                }
            }
        }
    }
}

/// Byte ranges of the awk program text when the executable token at `start` is
/// an awk, or an empty vector.
///
/// awk's option grammar decides what its operands mean, so this walks the
/// grammar rather than giving up at the first flag it does not recognise:
///
/// - `-e 'prog'` / `--source 'prog'` supply the program **as the flag value**.
///   That is gawk's documented way to pass a program on the command line, and
///   it may be repeated, so every value is collected.
/// - `-f progfile` / `-E progfile` read the program from a FILE dcg will not
///   open, and they also change what the remaining operands mean: every operand
///   becomes a data file or a `var=value` assignment rather than program text.
///   They contribute no inline program and suppress the positional one, so a
///   data file whose *name* looks like a program is never mined for sinks.
/// - `-F`, `-v`, `-i`, `-l`, `-W` and their long forms take a separate value
///   that is not program text; both words are skipped.
/// - Anything else starting with `-` is an unmodeled option.
///
/// That last case is why this function exists in this shape. It used to
/// `return None` — abandoning the scan — so one `-F:`, the single most common
/// awk flag there is, turned `awk -F: 'BEGIN{ system("rm -rf …") }'` from
/// blocked into allowed. Giving up is the one unrecoverable direction for a
/// guard, so an unmodeled option is now assumed to take no separate value and
/// the walk continues. If such an option really does take one, its value is
/// mistaken for the program; `saw_unmodeled_option` therefore also admits the
/// operand after it, so the real program is still scanned. Both effects are
/// over-extraction, which costs a wasted scan and nothing else.
fn awk_program_tokens(
    command: &str,
    tokens: &[crate::normalize::NormalizeToken],
    start: usize,
) -> Vec<Range<usize>> {
    use crate::normalize::NormalizeTokenKind;

    let mut programs = Vec::new();
    let Some(token) = tokens.get(start) else {
        return programs;
    };
    if token.kind != NormalizeTokenKind::Word {
        return programs;
    }
    let Some(word) = token.text(command) else {
        return programs;
    };
    let dequoted = dequoted_executable_word(word);
    let basename = interpreter_basename(&dequoted);
    if !AWK_EXECUTABLES
        .iter()
        .any(|executable| basename.eq_ignore_ascii_case(executable))
    {
        return programs;
    }

    let mut index = start + 1;
    // `busybox awk …` needs its applet name consumed first.
    if basename.eq_ignore_ascii_case("busybox") {
        match tokens.get(index) {
            Some(applet)
                if applet.kind == NormalizeTokenKind::Word
                    && applet.text(command).is_some_and(|text| {
                        dequoted_executable_word(text).eq_ignore_ascii_case("awk")
                    }) => {}
            _ => return programs,
        }
        index += 1;
    }

    // Set by `-f`/`-E`: the program lives in a file, so no operand is one.
    let mut program_is_in_a_file = false;
    let mut saw_unmodeled_option = false;

    let value_range = |at: usize| -> Option<Range<usize>> {
        let value = tokens.get(at)?;
        if value.kind != NormalizeTokenKind::Word {
            return None;
        }
        let text = command.get(value.byte_range.clone())?;
        Some(unquoted_payload_range(text, value.byte_range.start))
    };

    loop {
        let Some(token) = tokens.get(index) else {
            return programs;
        };
        if token.kind != NormalizeTokenKind::Word {
            return programs;
        }
        let Some(raw) = token.text(command) else {
            return programs;
        };
        let (word, word_start, word_end) =
            dequoted_flag_word(raw, token.byte_range.start, token.byte_range.end);
        match word {
            // The program comes from a file; operands are data from here on.
            // The separated spellings are safe to treat this way even on an awk
            // that does not recognise the long forms, because such an awk
            // ignores the option and then takes the FOLLOWING word — the
            // progfile name — as its program, so the operand after that is
            // still data either way.
            "-f" | "--file" | "-E" | "--exec" => {
                program_is_in_a_file = true;
                index += 2;
            }
            // POSIX `-f` glued. Every awk knows `-f`, so this one really does
            // read the program from a file.
            _ if word.starts_with("-f") && word != "-f" => {
                program_is_in_a_file = true;
                index += 1;
            }
            // Glued spellings of the long forms, which are a GNU extension.
            // gawk 5.3.2 reads each as a source file (verified: `awk -Ex` and
            // `awk --file=x` both fail with "cannot open source file `x'"), so
            // on gawk the operand after them really is data. onetrueawk —
            // macOS's `/usr/bin/awk`, the very platform the sibling `osascript`
            // rules target — does not implement them, and an awk that does not
            // recognise an option leaves the following operand as its program.
            //
            // So consume the flag word but leave the positional operand
            // admissible. On gawk that is an over-block costing one wasted scan
            // of a data filename; on an awk that ignores the option it is the
            // difference between seeing `awk -Ex 'BEGIN{ system("…") }'` and
            // missing it. Over-block is the recoverable direction.
            _ if word.starts_with("--file=")
                || word.starts_with("--exec=")
                || (word.starts_with("-E") && word != "-E") =>
            {
                index += 1;
            }

            // The flag VALUE is program text.
            "-e" | "--source" => {
                if let Some(range) = value_range(index + 1) {
                    programs.push(range);
                }
                index += 2;
            }
            "--" => {
                index += 1;
                break;
            }
            // A glued value still carries its own shell quoting — the separate
            // spelling gets that stripped by `unquoted_payload_range` via
            // `value_range`, and skipping it here meant `awk -e"BEGIN{…}"`
            // handed the scanner a program whose very first byte was a quote,
            // so the whole program was read as one string literal and the sink
            // inside it never seen.
            _ if word.starts_with("--source=") => {
                if let Some(equals) = word.find('=') {
                    let value_start = word_start + equals + 1;
                    if let Some(text) = command.get(value_start..word_end) {
                        programs.push(unquoted_payload_range(text, value_start));
                    }
                }
                index += 1;
            }
            _ if word.starts_with("-e") => {
                if let Some(text) = command.get(word_start + 2..word_end) {
                    programs.push(unquoted_payload_range(text, word_start + 2));
                }
                index += 1;
            }

            // A separate value that is never program text.
            "-F" | "--field-separator" | "-v" | "--assign" | "-i" | "--include" | "-l"
            | "--load" | "-W" => index += 2,
            _ if word.starts_with("--field-separator=")
                || word.starts_with("--assign=")
                || word.starts_with("--include=")
                || word.starts_with("--load=")
                || word.starts_with("-F")
                || word.starts_with("-v")
                || word.starts_with("-i")
                || word.starts_with("-l")
                || word.starts_with("-W") =>
            {
                index += 1;
            }

            _ if word.starts_with('-') && word != "-" => {
                saw_unmodeled_option = true;
                index += 1;
            }
            _ => break,
        }
    }

    if !program_is_in_a_file {
        if let Some(range) = value_range(index) {
            programs.push(range);
        }
        // An unmodeled option may really have taken a separate value, in which
        // case that value was mistaken for the program above and the real one
        // is further along. Admit every remaining operand rather than just the
        // next one: two unmodeled value-taking options would otherwise push the
        // program past a single extra probe. Bounded by the token count, and
        // scanning an operand that turns out to be a data filename costs
        // nothing but the scan.
        if saw_unmodeled_option {
            let mut extra = index + 1;
            while let Some(range) = value_range(extra) {
                programs.push(range);
                extra += 1;
            }
        }
    }
    programs
}

/// The script extracted for a computed `print … | "sh"`: a single expansion,
/// so it is code chosen at run time. The evaluator recognises it and denies it
/// under `heredoc.posix:pipeline-consumer`, the rule the shell-level
/// `awk '{print "mv " $1}' f | sh` already gets.
pub(crate) const AWK_COMPUTED_PRINT_SCRIPT: &str = "$dcg_awk_printed_value";

/// What an awk program hands to a shell.
struct AwkShellPayloads {
    /// Byte ranges (whole-command coordinates) of the literal commands the
    /// program runs: `system("…")`, `… | "…"`, `"…" | getline`.
    commands: Vec<Range<usize>>,
    /// Text printed into a shell that runs its stdin as a script.
    printed: Vec<AwkPrintedScript>,
}

/// The expression a `print`/`printf` writes into a shell that runs its stdin
/// (`print "git reset --hard" | "sh"`), which that shell executes (#511).
#[derive(Debug, PartialEq, Eq)]
struct AwkPrintedScript {
    /// Byte range of the printed expression, in whole-command coordinates.
    range: Range<usize>,
    /// The script the shell receives, when the expression is literal strings
    /// (or one variable assigned exactly one literal). `None` when it is
    /// computed: a field, a concatenation with a variable, a format.
    script: Option<String>,
    /// The awk variable the script was read through, if any. An assignment to
    /// it on awk's command line (`-v name=…`, a `name=…` operand) would replace
    /// the value, so the caller must check the rest of the command.
    variable: Option<String>,
}

/// Whether an awk pipe's command string is a shell that reads its script from
/// standard input: `sh`, `bash -e`, `/bin/sh -s arg`, `sudo sh`, `bash -`.
/// Not one given `-c` (`sh -c cat` just runs `cat`) or a script operand
/// (`sh run.sh`), whose stdin is only data.
fn awk_pipe_target_runs_stdin_as_script(target: &str) -> bool {
    let normalized = crate::normalize::strip_wrapper_prefixes(target);
    let mut words = normalized.normalized.split_ascii_whitespace();
    let Some(program) = words.next() else {
        return false;
    };
    let basename = program
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(program)
        .to_ascii_lowercase();
    let basename = basename.strip_suffix(".exe").unwrap_or(&basename);
    if !SHELL_PROGRAMS.contains(&basename) {
        return false;
    }
    while let Some(word) = words.next() {
        match word {
            // `-s`: the script is stdin, the rest are positional parameters.
            // `-`: the same, POSIX spelling.
            "-s" | "-" => return true,
            // After `--` the next operand is a script file.
            "--" => return words.next().is_none(),
            "-o" | "+o" | "--rcfile" | "--init-file" => {
                words.next();
            }
            _ if word.starts_with("--") => {}
            _ if word.starts_with(['-', '+']) => {
                if word.contains('c') {
                    return false;
                }
                if word[1..].contains('s') {
                    return true;
                }
            }
            // A script file operand: stdin is that script's input, not code.
            _ => return false,
        }
    }
    true
}

/// The expression printed by the `print`/`printf` statement that occupies
/// `program[statement_start..pipe_at]`, read as the script a stdin shell runs.
fn awk_printed_script(
    program: &str,
    statement_start: usize,
    pipe_at: usize,
    offset: usize,
) -> AwkPrintedScript {
    let computed = |range: Range<usize>| AwkPrintedScript {
        range: offset + range.start..offset + range.end,
        script: None,
        variable: None,
    };
    let Some(statement) = program.get(statement_start..pipe_at) else {
        return computed(statement_start.min(pipe_at)..pipe_at);
    };
    let Some((keyword_end, is_printf)) = awk_print_keyword_end(statement) else {
        // No print keyword found: nothing provable about what is written.
        return computed(statement_start..pipe_at);
    };
    let expression_start = statement_start + keyword_end;
    let raw = &program[expression_start..pipe_at];
    let lead = raw.len() - raw.trim_start().len();
    let range = expression_start + lead..expression_start + raw.trim_end().len();
    let mut expression = raw.trim();
    if expression.starts_with('(') && expression.ends_with(')') && expression.len() >= 2 {
        expression = expression[1..expression.len() - 1].trim();
    }

    if let Some(items) = awk_literal_list(expression) {
        let script = if is_printf {
            items
                .first()
                .and_then(|(format, _)| awk_static_printf(format))
        } else {
            let mut joined = String::new();
            for (text, comma_before) in &items {
                if *comma_before {
                    // print's default output field separator.
                    joined.push(' ');
                }
                joined.push_str(text);
            }
            Some(joined)
        };
        return AwkPrintedScript {
            range: offset + range.start..offset + range.end,
            script,
            variable: None,
        };
    }

    let is_identifier = !expression.is_empty()
        && expression
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && expression
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if is_identifier && !is_printf {
        if let Some(value) = awk_single_literal_assignment(program, expression) {
            return AwkPrintedScript {
                range: offset + range.start..offset + range.end,
                script: Some(value),
                variable: Some(expression.to_string()),
            };
        }
    }
    computed(range)
}

/// The end of the `print`/`printf` keyword in `statement` (outside string
/// literals), and whether it is `printf`.
fn awk_print_keyword_end(statement: &str) -> Option<(usize, bool)> {
    let bytes = statement.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                index = awk_string_literal_end(statement, index).map_or(bytes.len(), |end| end + 1);
            }
            b'\\' if bytes.get(index + 1) == Some(&b'"') => {
                index = escaped_string_literal_end(statement, index + 2)
                    .map_or(bytes.len(), |end| end + 2);
            }
            b'p' if statement[index..].starts_with("print")
                && (index == 0 || !is_awk_identifier_byte(bytes[index - 1])) =>
            {
                let is_printf = statement[index..].starts_with("printf");
                let end = index + if is_printf { 6 } else { 5 };
                if bytes.get(end).is_none_or(|b| !is_awk_identifier_byte(*b)) {
                    return Some((end, is_printf));
                }
                index = end;
            }
            _ => index += 1,
        }
    }
    None
}

const fn is_awk_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// A list of awk string literals joined by commas or by juxtaposition
/// (concatenation), decoded, each with whether a comma preceded it. `None`
/// when anything else appears (a variable, a field, an operator).
fn awk_literal_list(expression: &str) -> Option<Vec<(String, bool)>> {
    let bytes = expression.as_bytes();
    let mut items = Vec::new();
    let mut index = 0usize;
    let mut comma_before = false;
    loop {
        while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }
        if bytes[index] == b',' {
            if items.is_empty() || comma_before {
                return None;
            }
            comma_before = true;
            index += 1;
            continue;
        }
        let literal = inline_string_literal_at(expression, index)?;
        if literal.start != index + 1 && literal.start != index + 2 {
            return None;
        }
        let escaped = literal.start == index + 2;
        items.push((
            decode_awk_string(&expression[literal.clone()]),
            std::mem::take(&mut comma_before),
        ));
        index = literal.end + if escaped { 2 } else { 1 };
    }
    (!items.is_empty() && !comma_before).then_some(items)
}

/// An awk string literal's value: its escape sequences decoded.
fn decode_awk_string(literal: &str) -> String {
    let mut out = String::with_capacity(literal.len());
    let mut chars = literal.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// A `printf` format that prints itself: no conversion other than `%%`.
fn awk_static_printf(format: &str) -> Option<String> {
    let mut out = String::with_capacity(format.len());
    let mut chars = format.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            if chars.next() != Some('%') {
                return None;
            }
        }
        out.push(c);
    }
    Some(out)
}

/// The value of awk variable `name` when the program assigns it exactly once,
/// a single string literal, and otherwise only prints it into a pipe. Any
/// other use (another assignment, `name = name "x"`, `getline name`,
/// `sub(…, name)`, `split(…, name)`, a field) answers `None`.
fn awk_single_literal_assignment(program: &str, name: &str) -> Option<String> {
    let bytes = program.as_bytes();
    let mut value: Option<String> = None;
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                index = awk_string_literal_end(program, index).map_or(bytes.len(), |end| end + 1);
                continue;
            }
            b'\\' if bytes.get(index + 1) == Some(&b'"') => {
                index = escaped_string_literal_end(program, index + 2)
                    .map_or(bytes.len(), |end| end + 2);
                continue;
            }
            _ => {}
        }
        // Bytes, not `str` slicing: `index` may sit inside a multi-byte
        // character, and a match of the ASCII name starts on a boundary.
        let at_word = bytes[index..].starts_with(name.as_bytes())
            && (index == 0
                || !(is_awk_identifier_byte(bytes[index - 1]) || bytes[index - 1] == b'$'))
            && bytes
                .get(index + name.len())
                .is_none_or(|b| !is_awk_identifier_byte(*b));
        if !at_word {
            index += 1;
            continue;
        }
        let after = index + name.len();
        let rest = program[after..].trim_start();
        let before = program[..index].trim_end();
        if rest.starts_with('=') && !rest.starts_with("==") {
            if value.is_some() {
                return None;
            }
            let rhs_at = program.len() - rest.len() + 1;
            let literal = inline_string_literal_at(program, rhs_at)?;
            let escaped = program.as_bytes().get(literal.start - 1) == Some(&b'"')
                && program.as_bytes().get(literal.start.wrapping_sub(2)) == Some(&b'\\');
            let close_end = literal.end + if escaped { 2 } else { 1 };
            let tail = program[close_end..].trim_start_matches([' ', '\t']);
            if !(tail.is_empty() || tail.starts_with([';', '}', '\n'])) {
                return None;
            }
            value = Some(decode_awk_string(&program[literal]));
            index = close_end;
            continue;
        }
        let printed = (before.ends_with("print") || before.ends_with("printf"))
            && rest.starts_with('|')
            && !rest.starts_with("||");
        if !printed {
            return None;
        }
        index = after;
    }
    value
}

/// Byte ranges (in whole-command coordinates) of every shell command an awk
/// program hands to `/bin/sh`.
///
/// Recognizes `system(<string>)`, `… | <string>` (print redirected into a
/// command), and `<string> | getline`. Only a literal awk string supplies a
/// payload: a concatenation or a variable is not statically known, and guessing
/// at one would evaluate text that never reaches a shell.
///
/// When a print pipe's command is a shell reading its script from stdin
/// (`| "sh"`), the printed expression is reported too, in
/// [`AwkShellPayloads::printed`] (#511).
fn awk_shell_payload_ranges(program: &str, offset: usize) -> AwkShellPayloads {
    let bytes = program.as_bytes();
    let mut payloads = Vec::new();
    let mut printed = Vec::new();
    let mut index = 0usize;
    // Where the statement the scan is in began: just past the last `;`, `{`,
    // `}` or newline outside a string, regex or comment. A `print … | "sh"`
    // reads its printed expression from here (#511).
    let mut statement_start = 0usize;
    // Byte offset of the `/` that closed the most recently skipped regex
    // literal. `awk_slash_opens_regex` needs it to tell a regex CLOSE (a value,
    // so the next `/` divides) from the division OPERATOR (after which a regex
    // may legally open). The previous byte alone cannot distinguish them.
    let mut last_regex_close: Option<usize> = None;

    while index < bytes.len() {
        match bytes[index] {
            // An awk comment runs to end of line and executes nothing — but
            // only a `#` in statement position starts one. A `#` inside a regex
            // literal (`/x#/`, `!/^#/` — both ordinary awk idioms for matching
            // a literal hash) is data, and treating it as a comment swallowed
            // the rest of the line, hiding a real `system()` call after it.
            // That is an under-block, so the test is deliberately narrow: an
            // unrecognised `#` just means the scanner keeps reading, which can
            // only over-extract.
            b'#' if awk_hash_starts_comment(bytes, index) => {
                index = program[index..]
                    .find('\n')
                    .map_or(bytes.len(), |newline| index + newline + 1);
                statement_start = index;
            }
            b'"' => {
                let Some(end) = awk_string_literal_end(program, index) else {
                    // An unpaired `"` means this scanner's idea of where
                    // strings begin has desynchronized from awk's — the usual
                    // cause is a quote inside a regex literal, as in the very
                    // ordinary `gsub(/"/, "")`. Abandoning the scan here threw
                    // away every sink later in the program, which is an
                    // under-block. Skip the one byte and keep reading instead:
                    // the worst case is that a span of code is read as a string
                    // (or the reverse), which can only over-extract.
                    index += 1;
                    continue;
                };
                let literal = index + 1..end;
                // `"cmd" | getline` executes the string on the left.
                if awk_next_operator_is_pipe_getline(program, end + 1) {
                    payloads.push(offset + literal.start..offset + literal.end);
                }
                index = end + 1;
            }
            // The same literal, in a program that arrived inside shell double
            // quotes and therefore spells its own strings `\"…\"`. The
            // `| getline` sink is decided by pairing that literal, so without
            // this arm `awk "BEGIN{ \"cmd\" | getline x }"` paired nothing and
            // the sink was invisible — `inline_string_literal_at` had learned
            // the escaped spelling for the call sinks, but the scanner loop
            // that drives the pipe sinks had not.
            b'\\' if bytes.get(index + 1) == Some(&b'"') => {
                match escaped_string_literal_end(program, index + 2) {
                    Some(end) => {
                        if awk_next_operator_is_pipe_getline(program, end + 2) {
                            payloads.push(offset + index + 2..offset + end);
                        }
                        index = end + 2;
                    }
                    None => index += 2,
                }
            }
            // An awk regex literal. Its bytes are data, so a `"` inside one —
            // `gsub(/"/, "")`, `/["]/`, both everyday awk — must not be paired
            // with a real string quote later in the program. When it was, every
            // literal after it shifted by one and the `system()` call that
            // followed was read as string content instead of a sink.
            b'/' if awk_slash_opens_regex(bytes, index, last_regex_close) => {
                match awk_regex_literal_end(program, index) {
                    // Refuse to skip a span that carries a sink keyword. Such a
                    // span is proof this `/` was misread — either an
                    // unterminated regex whose "closing" slash was really a
                    // path separator inside the payload, or a division the
                    // heuristic called a regex — and skipping it would hide the
                    // one thing this scanner exists to find. Reading the span as
                    // code instead can only over-extract.
                    //
                    // `get` returning None would mean a non-boundary index,
                    // which cannot happen here (both ends are ASCII `/`), but
                    // default it to "carries a sink" so the fail direction is
                    // the scanning one rather than the skipping one.
                    Some(end)
                        if program
                            .get(index..=end)
                            .is_some_and(|span| !awk_span_carries_a_sink(span)) =>
                    {
                        // Remember where this literal closed. That is the only
                        // `/` a following `/` may treat as a value.
                        last_regex_close = Some(end);
                        index = end + 1;
                    }
                    // Not a terminated regex after all. Treat the byte as
                    // ordinary code rather than abandoning the rest.
                    _ => index += 1,
                }
            }
            // `||` is logical or, not a command pipe.
            b'|' if bytes.get(index + 1) == Some(&b'|') => index += 2,
            b'|' => {
                // `|&` is gawk's coprocess operator, which also runs a command.
                let after = if bytes.get(index + 1) == Some(&b'&') {
                    index + 2
                } else {
                    index + 1
                };
                if let Some(literal) = awk_leading_string_literal(program, after) {
                    payloads.push(offset + literal.start..offset + literal.end);
                    // `print "git reset --hard" | "sh"` writes the printed text
                    // to a shell that runs its stdin as a script, exactly as
                    // `echo "…" | sh` does, so the printed text is a payload as
                    // well as the pipe target (#511).
                    if program
                        .get(literal.clone())
                        .is_some_and(awk_pipe_target_runs_stdin_as_script)
                    {
                        printed.push(awk_printed_script(program, statement_start, index, offset));
                    }
                    index = literal.end + 1;
                } else {
                    index = after;
                }
            }
            _ => {
                if matches!(bytes[index], b';' | b'{' | b'}' | b'\n') {
                    statement_start = index + 1;
                }
                if let Some(rest) = program.get(index..)
                    && rest.starts_with("system")
                    && !index
                        .checked_sub(1)
                        .and_then(|i| bytes.get(i))
                        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
                {
                    let after_name = index + "system".len();
                    let open = program[after_name..]
                        .find(|c: char| !c.is_ascii_whitespace())
                        .map(|skip| after_name + skip);
                    if let Some(open) = open
                        && bytes.get(open) == Some(&b'(')
                        && let Some(literal) = awk_leading_string_literal(program, open + 1)
                    {
                        payloads.push(offset + literal.start..offset + literal.end);
                        index = literal.end + 1;
                        continue;
                    }
                }
                index += 1;
            }
        }
    }
    AwkShellPayloads {
        commands: payloads,
        printed,
    }
}

/// Whether the `/` at `index` opens an awk regex literal rather than being the
/// division operator.
///
/// awk resolves this the way every language with bare regex literals does: a
/// `/` opens a regex where an operand is expected and divides where a value has
/// just been produced. The nearest preceding non-blank byte settles it, because
/// division can only follow a name, a number, `)`, `]`, or a closing quote.
///
/// Misreading a division as a regex costs at most the rest of that line, since
/// `awk_regex_literal_end` refuses to cross a newline; misreading a regex as
/// code is what desynchronized the string walk in the first place.
fn awk_slash_opens_regex(bytes: &[u8], index: usize, last_regex_close: Option<usize>) -> bool {
    bytes[..index]
        .iter()
        .rposition(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
        .is_none_or(|position| {
            let previous = bytes[position];
            // `.` is here for a trailing decimal point: `x = 1. / 2` is
            // division, and awk has no operator that would put a bare `.`
            // before a regex.
            if previous.is_ascii_alphanumeric()
                || matches!(previous, b')' | b']' | b'"' | b'_' | b'.')
            {
                return false;
            }
            // A preceding `/` is ambiguous and the byte alone cannot settle it:
            //
            //   n = /a/ / 2      the `/` before is a regex CLOSE — a value — so
            //                    this one divides.
            //   x = 4 / /re/     the `/` before is the division OPERATOR, so
            //                    this one opens a regex.
            //
            // Treating every preceding `/` as a value got the first right and
            // the second exactly backwards: the regex body was then scanned as
            // code, an odd `"` inside it paired with a later string quote, and
            // the desync hid every sink after it. `awk '{ x = 4 / /^|"/ ;
            // system("rm -rf …") }'` runs on gawk, mawk and busybox awk.
            //
            // `last_regex_close` is the only `/` this scanner actually proved
            // to be a close, so it is the only one that counts as a value.
            if previous == b'/' {
                return last_regex_close != Some(position);
            }
            // `x++ / 2` and `x-- / 2` are division: the operand is the value the
            // increment produced. A single `+` or `-` is not, because awk reads
            // a bare regex in expression position as `$0 ~ /re/`, so `a + /re/`
            // is ordinary awk. Only the doubled form settles it.
            if matches!(previous, b'+' | b'-')
                && position
                    .checked_sub(1)
                    .and_then(|earlier| bytes.get(earlier))
                    == Some(&previous)
            {
                return false;
            }
            true
        })
}

/// Whether a candidate awk regex body carries a shell-sink keyword.
///
/// Used to veto a regex skip. A genuine regex literal almost never spells
/// `system` or `getline`; a span that does is evidence the scanner misread the
/// opening `/`, and skipping it would hide the sink.
/// Deliberately keyed on the two sink KEYWORDS and nothing else.
///
/// A "pipe and a quote together" clause was tried here, to reach the third sink
/// (`print … | "cmd"`, which names no keyword). It made things worse: a real awk
/// regex can carry both characters — `/["|]/`, `/[|"]/` and `/"|,/` are all
/// ordinary, and gawk runs them — so the veto fired on genuine regexes, refused
/// the skip, and let the body be scanned as code. Its `"` then paired with a
/// later string quote and the desync that regex tracking exists to prevent came
/// back, losing the sink that followed. Three confirmed under-blocks, against
/// zero cases it saved once `awk_slash_opens_regex` learned that a `/` after a
/// regex literal is division.
fn awk_span_carries_a_sink(span: &str) -> bool {
    span.contains("system") || span.contains("getline")
}

/// Index of the `/` closing the awk regex literal that opens at `start`.
///
/// A regex literal cannot contain a raw newline, so an unterminated one stops
/// at the end of its line rather than swallowing the rest of the program.
fn awk_regex_literal_end(program: &str, start: usize) -> Option<usize> {
    let bytes = program.as_bytes();
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'\n' | b'\r' => return None,
            b'/' => return Some(index),
            _ => index += 1,
        }
    }
    None
}

/// Whether the `#` at `index` begins an awk comment rather than being a literal
/// hash inside a regex or a string.
///
/// True only at the start of a line: the nearest preceding byte that is not a
/// space or tab must be a newline, or there must be none.
///
/// This is not merely conservative, it is exact in the one direction that
/// matters. Neither an awk regex literal nor an awk string literal may contain
/// a raw newline, so a `#` that opens a line cannot be inside either — it is
/// always a comment. Every other position is ambiguous without lexing awk, and
/// guessing there is what caused the bug this replaced: `;`, `{` and `}` were
/// also accepted as statement markers, so the perfectly ordinary regexes
/// `/;#/` and `/{#/` put a `#` in "statement position", swallowed the rest of
/// the line, and hid a real `system()` call behind it.
///
/// The cost is that a trailing comment after code (`print 1 # note`) is not
/// recognised, so the scanner keeps reading it. That can only over-extract,
/// which is the recoverable direction; mistaking regex data for a comment
/// hides whatever follows, which is not.
fn awk_hash_starts_comment(bytes: &[u8], index: usize) -> bool {
    bytes[..index]
        .iter()
        .rposition(|b| !matches!(b, b' ' | b'\t'))
        .is_none_or(|position| matches!(bytes[position], b'\n' | b'\r'))
}

/// End index (the closing quote) of the awk string literal opening at `start`.
fn awk_string_literal_end(program: &str, start: usize) -> Option<usize> {
    let bytes = program.as_bytes();
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'"' => return Some(index),
            _ => index += 1,
        }
    }
    None
}

/// Index of the `\` opening the closing `\"` of an escaped string literal whose
/// content begins at `start`.
fn escaped_string_literal_end(program: &str, start: usize) -> Option<usize> {
    let bytes = program.as_bytes();
    let mut index = start;
    while index + 1 < bytes.len() {
        if bytes[index] == b'\\' {
            if bytes[index + 1] == b'"' {
                return Some(index);
            }
            // `\\` is an escaped backslash, not the start of a closing quote.
            index += 2;
        } else {
            index += 1;
        }
    }
    None
}

/// The first string literal at or after `start`, skipping only whitespace.
///
/// Handles both spellings an interpreter can receive. A program written inside
/// shell *single* quotes keeps its double quotes bare, while the same program
/// written inside shell *double* quotes arrives with every inner quote
/// backslash-escaped — `awk "BEGIN{ system(\"rm -rf …\") }"` and
/// `osascript -e "do shell script \"rm -rf …\""`. The shell strips those
/// backslashes before the interpreter runs, so `\"` opens a literal here just
/// as `"` does. Requiring a bare quote missed the escaped spelling entirely,
/// which is the spelling you are forced into whenever the payload interpolates
/// a shell variable.
fn inline_string_literal_at(program: &str, start: usize) -> Option<Range<usize>> {
    let rest = program.get(start..)?;
    let skip = rest.find(|c: char| !c.is_ascii_whitespace())?;
    let quote = start + skip;
    let bytes = program.as_bytes();
    match bytes.get(quote) {
        Some(b'"') => {
            let end = awk_string_literal_end(program, quote)?;
            Some(quote + 1..end)
        }
        Some(b'\\') if bytes.get(quote + 1) == Some(&b'"') => {
            let end = escaped_string_literal_end(program, quote + 2)?;
            Some(quote + 2..end)
        }
        _ => None,
    }
}

/// The first awk string literal at or after `start`, skipping only whitespace.
fn awk_leading_string_literal(program: &str, start: usize) -> Option<Range<usize>> {
    inline_string_literal_at(program, start)
}

/// Whether the tokens after `start` are `| getline`, making the string literal
/// before them a command awk runs.
fn awk_next_operator_is_pipe_getline(program: &str, start: usize) -> bool {
    let Some(rest) = program.get(start..) else {
        return false;
    };
    let trimmed = rest.trim_start();
    let Some(after_pipe) = trimmed.strip_prefix('|') else {
        return false;
    };
    // `||` is logical or, not a command pipe.
    if after_pipe.starts_with('|') {
        return false;
    }
    let after_pipe = after_pipe.strip_prefix('&').unwrap_or(after_pipe);
    let after_pipe = after_pipe.trim_start();
    // Whole word only: `getlinefoo` is an ordinary variable name, not awk's
    // `getline` keyword, so it is not a command pipe. Matches the `\bgetline\b`
    // tier-1 trigger rather than being looser than it.
    after_pipe.strip_prefix("getline").is_some_and(|rest| {
        rest.chars()
            .next()
            .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_')
    })
}

/// Extract the shell payloads an `osascript` program hands to `/bin/sh`
/// (issue #398).
///
/// AppleScript's `do shell script "…"` and JavaScript-for-Automation's
/// `$.system("…")` both run their argument through the shell, so
/// `osascript -e 'do shell script "rm -rf ~/Documents"'` is the denied
/// `sh -c` spelling behind an AppleScript wrapper. osascript ships on every
/// macOS machine and agents reach for it for notifications and Finder
/// automation, which makes it a natural place for a destructive payload to sit
/// unnoticed.
///
/// Keyed on those two shapes inside the program text, so ordinary automation
/// (`osascript -e 'display notification "done"'`) extracts nothing.
fn extract_osascript_inline_scripts(
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
    if !names_interpreter(command, "osascript") {
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
        if !interpreter_basename(&dequoted_executable_word(word)).eq_ignore_ascii_case("osascript")
        {
            continue;
        }
        for program in osascript_program_ranges(command, &tokens, index) {
            let Some(program_text) = command.get(program.clone()) else {
                continue;
            };
            for payload in osascript_shell_payload_ranges(program_text, program.start) {
                let Some(content) = command.get(payload.clone()) else {
                    continue;
                };
                if !push_windows_inner(
                    extracted,
                    skip_reasons,
                    limits,
                    content,
                    program.clone(),
                    Some(payload),
                    "osascript",
                ) {
                    return;
                }
            }
        }
    }
}

/// Every `-e <program>` payload of the osascript invocation at `start`.
///
/// osascript concatenates multiple `-e` statements into one program, and `-l`
/// selects the language; neither changes that each `-e` value is program text.
fn osascript_program_ranges(
    command: &str,
    tokens: &[crate::normalize::NormalizeToken],
    start: usize,
) -> Vec<Range<usize>> {
    use crate::normalize::NormalizeTokenKind;

    let mut programs = Vec::new();
    let mut index = start + 1;
    while let Some(token) = tokens.get(index) {
        if token.kind != NormalizeTokenKind::Word {
            break;
        }
        let Some(raw) = token.text(command) else {
            break;
        };
        let (word, word_start, word_end) =
            dequoted_flag_word(raw, token.byte_range.start, token.byte_range.end);
        match word {
            "-e" => {
                let Some(value) = tokens.get(index + 1) else {
                    break;
                };
                if value.kind != NormalizeTokenKind::Word {
                    break;
                }
                let Some(text) = command.get(value.byte_range.clone()) else {
                    break;
                };
                programs.push(unquoted_payload_range(text, value.byte_range.start));
                index += 2;
            }
            // `-l <language>` and `-s <flags>` take a separate value.
            "-l" | "-s" => index += 2,
            // Glued `-e<program>`. getopt accepts it, so osascript does too,
            // and it used to fall through to the skip-any-option arm below —
            // the program was never collected and the sink never seen.
            _ if word.starts_with("-e") => {
                programs.push(word_start + 2..word_end);
                index += 1;
            }
            _ if word.starts_with('-') && word != "-" => index += 1,
            // The first bare word is a script FILE, which dcg will not open.
            _ => break,
        }
    }
    programs
}

/// Byte ranges (in whole-command coordinates) of every shell command an
/// osascript program hands to `/bin/sh`.
fn osascript_shell_payload_ranges(program: &str, offset: usize) -> Vec<Range<usize>> {
    let mut payloads = Vec::new();
    let lowered = program.to_ascii_lowercase();
    let mut search = 0usize;

    // AppleScript: `do shell script "<command>"`. Whitespace between the three
    // keywords is flexible and the keywords are case-insensitive, so a fixed
    // `"do shell script"` literal would miss `do  shell  script` — trivially
    // evadable, and inconsistent with the `\bdo\s+shell\s+script\b` tier-1
    // trigger that got the command here in the first place.
    while let Some(after) = find_applescript_do_shell_script(&lowered, search) {
        if let Some(literal) = applescript_leading_string_literal(program, after) {
            payloads.push(offset + literal.start..offset + literal.end);
            search = literal.end;
        } else {
            search = after;
        }
        if search >= program.len() {
            break;
        }
    }

    // JXA call sinks: `$.system("<command>")` reaches libc directly, and
    // `app.doShellScript("<command>")` is the Standard Additions bridge to the
    // same `do shell script` AppleScript command. The latter is the idiom every
    // JXA example uses (`Application.currentApplication()` with
    // `includeStandardAdditions = true`), so covering only `$.system` left the
    // documented spelling unguarded. The receiver is an arbitrary expression,
    // so match on the method name and require the call parenthesis.
    for name in ["$.system", ".doShellScript"] {
        let mut search = 0usize;
        while let Some(found) = program[search..].find(name) {
            let after = search + found + name.len();
            let open = program[after..]
                .find(|c: char| !c.is_ascii_whitespace())
                .map(|skip| after + skip);
            if let Some(open) = open
                && program.as_bytes().get(open) == Some(&b'(')
                && let Some(literal) = applescript_leading_string_literal(program, open + 1)
            {
                payloads.push(offset + literal.start..offset + literal.end);
                search = literal.end;
            } else {
                search = after;
            }
            if search >= program.len() {
                break;
            }
        }
    }

    payloads.sort_by_key(|range| range.start);
    payloads.dedup();
    payloads
}

/// Index just past the next `do shell script` keyword sequence in `lowered`
/// (already ASCII-lowercased), searching from `from`.
///
/// Whitespace between the three keywords is flexible, matching AppleScript and
/// the tier-1 trigger. Word boundaries are required so `redo`, `doshell`, and
/// `scripted` cannot satisfy it.
fn find_applescript_do_shell_script(lowered: &str, from: usize) -> Option<usize> {
    const WORDS: [&str; 3] = ["do", "shell", "script"];
    let bytes = lowered.as_bytes();
    let is_word_byte = |b: u8| b.is_ascii_alphanumeric() || b == b'_';

    let mut search = from;
    loop {
        let rest = lowered.get(search..)?;
        let found = search + rest.find(WORDS[0])?;
        let mut cursor = found;
        let mut matched = true;
        for (position, word) in WORDS.iter().enumerate() {
            if position > 0 {
                let skipped = lowered
                    .get(cursor..)
                    .and_then(|tail| tail.find(|c: char| !c.is_ascii_whitespace()))?;
                if skipped == 0 {
                    // The keywords must be separated by whitespace.
                    matched = false;
                    break;
                }
                cursor += skipped;
            }
            if !lowered.get(cursor..).is_some_and(|t| t.starts_with(word)) {
                matched = false;
                break;
            }
            cursor += word.len();
        }
        let starts_on_boundary = found
            .checked_sub(1)
            .and_then(|i| bytes.get(i))
            .is_none_or(|b| !is_word_byte(*b));
        let ends_on_boundary = bytes.get(cursor).is_none_or(|b| !is_word_byte(*b));
        if matched && starts_on_boundary && ends_on_boundary {
            return Some(cursor);
        }
        search = found + WORDS[0].len();
    }
}

/// The first double-quoted literal at or after `start`, skipping whitespace.
///
/// AppleScript and JXA both use `\` escapes inside double quotes, so the same
/// scanner serves both.
fn applescript_leading_string_literal(program: &str, start: usize) -> Option<Range<usize>> {
    inline_string_literal_at(program, start)
}

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
    if !may_name_a_command(command, &["ssh", "SSH"]) {
        return;
    }

    // Process substitution bodies too: `cat <(ssh h '<cmd>')`.
    let (views, complete) = command_token_views(command, MAX_COMMAND_STRING_RUNNERS);
    if !complete {
        skip_reasons.push(SkipReason::ExceededHeredocLimit {
            limit: MAX_COMMAND_STRING_RUNNERS,
        });
    }
    for tokens in &views {
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
            // Path-qualified spellings (`/usr/bin/ssh`, `C:\…\ssh.exe`) are
            // the same program, and so are quoted ones (`\ssh`, `"ssh"`);
            // `ssh-keygen`/`ssh-add`/`autossh` are not.
            let names_ssh = |word: &str| {
                let basename = word.rsplit(['/', '\\']).next().unwrap_or(word);
                basename
                    .strip_suffix(".exe")
                    .or_else(|| basename.strip_suffix(".EXE"))
                    .unwrap_or(basename)
                    .eq_ignore_ascii_case("ssh")
            };
            if !names_ssh(word) && !names_ssh(&dequoted_executable_word(word)) {
                continue;
            }
            let Some(payload) = ssh_remote_payload(command, tokens, index) else {
                continue;
            };
            if !push_joined_payload(command, payload, limits, extracted, skip_reasons, "ssh") {
                return;
            }
        }
    }
}

/// Extract the command strings `watch`, `parallel` and `env -S` run.
///
/// `watch` joins its operands and runs them with `sh -c` (unless `-x`),
/// `parallel` runs its command template (or, with none, each `:::` argument)
/// through a shell, and `env -S` splits one word into the command it runs.
/// Quoted, those commands were argv data to every rule: `watch 'rm -rf ./b'`,
/// `parallel ::: 'git reset --hard'` and `env -S'git reset --hard'` were
/// allowed while the unquoted spellings denied. Each payload is re-evaluated
/// as a shell command, as the `ssh` remote command is.
fn extract_command_string_runner_scripts(
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
    if !may_name_a_command(command, COMMAND_STRING_RUNNERS)
        && !may_run_through_dynamic_command_word(command)
    {
        return;
    }
    let (views, complete) = command_token_views(command, MAX_COMMAND_STRING_RUNNERS);
    if !complete {
        skip_reasons.push(SkipReason::ExceededHeredocLimit {
            limit: MAX_COMMAND_STRING_RUNNERS,
        });
    }
    let mut runners = 0usize;
    for tokens in &views {
        let positions = command_word_positions(command, tokens);
        let primary = primary_command_positions(command, tokens, &positions);
        for index in 0..tokens.len() {
            if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
                return;
            }
            if !positions[index] {
                continue;
            }
            let dynamic_word = primary[index]
                .then(|| tokens[index].text(command))
                .flatten()
                .filter(|word| word.contains(['$', '`']));
            if let Some(word) = dynamic_word
                && let Some(output) = substitution_command_line(command, tokens, index, word)
            {
                // `$(echo git reset --hard)`: the command is what the
                // substitution prints, read here as what an echo would.
                let full = tokens[index].byte_range.start..segment_end(tokens, index);
                if !push_windows_inner(
                    extracted,
                    skip_reasons,
                    limits,
                    &output,
                    full,
                    None,
                    DYNAMIC_RUNNER,
                ) {
                    return;
                }
            }
            let name = command_string_runner_name(command, &tokens[index]).or_else(|| {
                (dynamic_word.is_some_and(dynamic_word_may_name_runner)
                    && !assigns_like_powershell(command, tokens, index))
                .then_some(DYNAMIC_RUNNER)
            });
            let Some(name) = name else {
                continue;
            };
            // Each runner reads the rest of its segment; a command that is
            // nothing but runners is not read runner by runner (quadratic), it
            // is an incomplete reading the caller judges by the bounded
            // fallback.
            runners += 1;
            if runners > MAX_COMMAND_STRING_RUNNERS {
                skip_reasons.push(SkipReason::ExceededHeredocLimit {
                    limit: MAX_COMMAND_STRING_RUNNERS,
                });
                return;
            }
            for payload in command_string_runner_payloads(command, tokens, index, name) {
                if !push_joined_payload(command, payload, limits, extracted, skip_reasons, name) {
                    return;
                }
            }
        }
    }
}

/// Re-spell two command shapes whose rules are anchored to a spelling a
/// wrapper or quoting hides, and hand each on for re-evaluation.
///
/// A dashed Git built-in behind a wrapper this file treats as running its
/// operands (`xargs git-reset --hard`, `sudo -u bob git-clean -fdx`): the
/// `core.git` rules accept `git-<sub>` only where a command starts, and these
/// wrappers are not stripped from the text they read. The payload is the
/// built-in and the rest of its segment.
///
/// A `find` action or option spelled through quoting (`find . '-delete'`,
/// `find . -de''lete`, `find . -de\lete`): find receives `-delete` either way,
/// but the find rules read the words as written. The payload is the segment
/// with such words dequoted — except a word that is the value of the option
/// before it (`-name '-delete'`) or an argument of an `-exec` command, which
/// stay as written.
fn extract_respelled_commands(
    command: &str,
    limits: &ExtractionLimits,
    start_time: Instant,
    timeout: Duration,
    extracted: &mut Vec<ExtractedContent>,
    skip_reasons: &mut Vec<SkipReason>,
) {
    use crate::normalize::NormalizeTokenKind;
    if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
        return;
    }
    let dashed_git = may_wrap_dashed_git(command);
    let find_action = may_quote_a_find_action(command);
    if !dashed_git && !find_action {
        return;
    }
    let tokens = crate::normalize::tokenize_for_normalization(command);
    let positions = command_word_positions(command, &tokens);
    // Each re-spelling reads the rest of its segment, so a segment of nothing
    // but candidates (`xargs find find find …`) is not read candidate by
    // candidate; past the cap the reading is partial and the caller judges it
    // by the bounded fallback.
    let mut respelled = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
            return;
        }
        if !positions[index] || token.kind != NormalizeTokenKind::Word {
            continue;
        }
        let Some(text) = token.text(command) else {
            continue;
        };
        let executable = dequoted_executable_word(text);
        let basename = executable.rsplit('/').next().unwrap_or(&executable);
        let behind_a_word = index > 0 && tokens[index - 1].kind == NormalizeTokenKind::Word;
        let dashed = dashed_git && behind_a_word && basename.starts_with("git-");
        let find = matches!(basename, "find" | "gfind") && (dashed_git || find_action);
        if !dashed && !find {
            continue;
        }
        respelled += 1;
        if respelled > MAX_COMMAND_STRING_RUNNERS {
            skip_reasons.push(SkipReason::ExceededHeredocLimit {
                limit: MAX_COMMAND_STRING_RUNNERS,
            });
            return;
        }
        let start = token.byte_range.start;
        let end = segment_end(&tokens, index);
        if dashed {
            if !push_windows_inner(
                extracted,
                skip_reasons,
                limits,
                &command[start..end],
                start..end,
                Some(start..end),
                "git",
            ) {
                return;
            }
            continue;
        }
        if dashed_git && find {
            // `find . -exec git-clean -fdx \;`: the `-exec` command starts a
            // command of its own, through its `;` or `+`.
            let words = tokens[index + 1..]
                .iter()
                .take_while(|token| token.kind == NormalizeTokenKind::Word);
            let mut after_exec = false;
            let mut exec_start = None;
            for word_token in words {
                let Some(word) = word_token.text(command) else {
                    break;
                };
                let decoded = crate::normalize::decode_posix_syntax_token(word);
                if let Some(from) = exec_start {
                    if matches!(decoded.as_ref(), ";" | "+") {
                        exec_start = None;
                        if !push_windows_inner(
                            extracted,
                            skip_reasons,
                            limits,
                            &command[from..word_token.byte_range.start],
                            from..word_token.byte_range.start,
                            Some(from..word_token.byte_range.start),
                            "git",
                        ) {
                            return;
                        }
                    }
                    continue;
                }
                if std::mem::take(&mut after_exec) {
                    let executable = dequoted_executable_word(word);
                    if executable
                        .rsplit('/')
                        .next()
                        .is_some_and(|name| name.starts_with("git-"))
                    {
                        exec_start = Some(word_token.byte_range.start);
                    }
                    continue;
                }
                after_exec = matches!(decoded.as_ref(), "-exec" | "-execdir" | "-ok" | "-okdir");
            }
            if let Some(from) = exec_start
                && !push_windows_inner(
                    extracted,
                    skip_reasons,
                    limits,
                    &command[from..end],
                    from..end,
                    Some(from..end),
                    "git",
                )
            {
                return;
            }
        }
        if find_action
            && find
            && let Some(dequoted) = find_with_dequoted_actions(command, &tokens, index)
            && !push_windows_inner(
                extracted,
                skip_reasons,
                limits,
                &dequoted,
                start..end,
                None,
                "find",
            )
        {
            return;
        }
    }
}

/// `segment` (one simple command) with its brace lists expanded as bash
/// expands them, when that changes the program or its options (bd-2bm3):
/// the command word is a list (`{rm,-rf,~}` runs `rm -rf ~`,
/// `sudo {git,reset,--hard}`), or a list's alternatives are options
/// (`rm {-rf,~}`). Lists that only name files (`mkdir -p src/{a,b}`,
/// `cp f{,.bak}`) change neither and give `None`, as does anything
/// [`crate::packs::core::filesystem::literal_brace_expansions`] declines
/// (quotes, escapes, `$`, backquotes, ranges).
pub(crate) fn brace_expanded_command(segment: &str) -> Option<String> {
    use crate::normalize::NormalizeTokenKind;
    let tokens = crate::normalize::tokenize_for_normalization(segment);
    let positions = command_word_positions(segment, &tokens);
    let primary = primary_command_positions(segment, &tokens, &positions);
    let at = (0..tokens.len()).find(|&index| primary[index])?;
    if !tokens[at..]
        .iter()
        .take_while(|token| token.kind == NormalizeTokenKind::Word)
        .any(|token| token.text(segment).is_some_and(|word| word.contains('{')))
    {
        return None;
    }
    let mut out = segment[..tokens[at].byte_range.start].to_string();
    let mut changed = false;
    for (offset, token) in tokens[at..]
        .iter()
        .take_while(|token| token.kind == NormalizeTokenKind::Word)
        .enumerate()
    {
        let text = token.text(segment)?;
        if offset > 0 {
            out.push(' ');
        }
        match crate::packs::core::filesystem::literal_brace_expansions(text) {
            Some(words)
                if primary[at + offset] || words.iter().any(|word| word.starts_with('-')) =>
            {
                out.push_str(&words.join(" "));
                changed = true;
            }
            _ => out.push_str(text),
        }
    }
    changed.then_some(out)
}

/// Whether a brace list starts a word (`{rm,-rf,~}`, `rm {-rf,~}`): the cheap
/// superset of what [`brace_expanded_command`] reads. Each list is scanned a
/// bounded distance, so a run of `{` stays linear.
pub(crate) fn may_brace_expand_a_command(command: &str) -> bool {
    let bytes = command.as_bytes();
    memchr::memchr_iter(b'{', bytes).any(|at| {
        let starts_word = at == 0
            || matches!(
                bytes[at - 1],
                b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'('
            );
        if !starts_word {
            return false;
        }
        let rest = &bytes[at + 1..bytes.len().min(at + 1 + 256)];
        rest.iter()
            .position(|byte| matches!(byte, b'}' | b' ' | b'\t' | b'\n'))
            .is_some_and(|close| rest[close] == b'}' && rest[..close].contains(&b','))
    })
}

/// find primaries that take no value, so the word after one is a primary of
/// its own rather than that primary's argument.
const FIND_VALUELESS_PRIMARIES: &[&str] = &[
    "-delete",
    "-print",
    "-print0",
    "-ls",
    "-prune",
    "-quit",
    "-depth",
    "-d",
    "-xdev",
    "-mount",
    "-empty",
    "-true",
    "-false",
    "-readable",
    "-writable",
    "-executable",
    "-nouser",
    "-nogroup",
    "-follow",
    "-noleaf",
    "-ignore_readdir_race",
    "-noignore_readdir_race",
    "-daystart",
    "-not",
    "-a",
    "-o",
    "-and",
    "-or",
    "-H",
    "-L",
    "-P",
    "-E",
    "-X",
    "-x",
    "-s",
];

/// The `find` segment starting at token `index`, its option and action words
/// spelled through quoting (`'-delete'`, `-de''lete`) replaced by what find
/// receives, or `None` when there is none. A word that is the value of the
/// primary before it (`-name '-delete'`) or an argument of an `-exec`-family
/// command stays as written.
fn find_with_dequoted_actions(
    command: &str,
    tokens: &[crate::normalize::NormalizeToken],
    index: usize,
) -> Option<String> {
    // The program as find is run, quoting removed (`f'ind'` is `find`).
    let program = tokens[index].text(command)?;
    let dequoted_program = dequoted_executable_word(program);
    let mut out = dequoted_program.to_string();
    let mut cursor = tokens[index].byte_range.end;
    let mut in_exec = false;
    let mut pending_value = false;
    let mut changed = dequoted_program.as_ref() != program;
    for token in tokens[index + 1..]
        .iter()
        .take_while(|token| token.kind == crate::normalize::NormalizeTokenKind::Word)
    {
        let text = token.text(command)?;
        let decoded = crate::normalize::decode_posix_syntax_token(text);
        let decoded = decoded.as_ref();
        if in_exec {
            // An `-exec` command's own words, through its `;` or `+`.
            in_exec = !matches!(decoded, ";" | "+");
            continue;
        }
        if std::mem::take(&mut pending_value) {
            // The value of the primary before it: `-name '-delete'`,
            // `-perm -u+x`.
            continue;
        }
        let option = decoded.len() > 1
            && decoded.starts_with('-')
            && decoded[1..]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
        if option && decoded != text {
            out.push_str(&command[cursor..token.byte_range.start]);
            out.push_str(decoded);
            cursor = token.byte_range.end;
            changed = true;
        }
        in_exec = matches!(decoded, "-exec" | "-execdir" | "-ok" | "-okdir");
        pending_value = !in_exec
            && decoded.len() > 1
            && decoded.starts_with('-')
            && !FIND_VALUELESS_PRIMARIES.contains(&decoded);
    }
    if !changed {
        return None;
    }
    out.push_str(&command[cursor..segment_end(tokens, index)]);
    Some(out)
}

/// Whether some word-initial `git-` stands behind another word: the tier-1
/// superset of the dashed built-ins [`extract_respelled_commands`] re-reads.
fn may_wrap_dashed_git(command: &str) -> bool {
    let bytes = command.as_bytes();
    command.match_indices("git-").any(|(at, _)| {
        at > 0
            && matches!(bytes[at - 1], b' ' | b'\t' | b'/' | b'\'' | b'"' | b'\\')
            && bytes[..at]
                .iter()
                .rev()
                .take_while(|byte| !matches!(byte, b'\n' | b';' | b'|' | b'&' | b'('))
                .any(|byte| !byte.is_ascii_whitespace())
    })
}

/// Whether `command` names `find` and holds an option-shaped word spelled
/// through quoting (`'-delete'`, `"-exec"`, `-de''lete`, `-de\lete`): the
/// tier-1 superset of what [`find_with_dequoted_actions`] re-spells. Linear.
fn may_quote_a_find_action(command: &str) -> bool {
    if !may_name_a_command(command, &["find"]) {
        return false;
    }
    let bytes = command.as_bytes();
    let quoting = |byte: u8| matches!(byte, b'\'' | b'"' | b'\\');
    memchr::memchr_iter(b'-', bytes).any(|at| {
        if (at > 0 && quoting(bytes[at - 1]))
            || bytes.get(at + 1).is_some_and(|byte| quoting(*byte))
        {
            return true;
        }
        let letters = bytes[at + 1..]
            .iter()
            .take_while(|byte| byte.is_ascii_alphanumeric() || **byte == b'_')
            .count();
        letters > 0
            && bytes
                .get(at + 1 + letters)
                .is_some_and(|byte| quoting(*byte))
    })
}

/// Whether `command` may name one of `names` as a program: a plain substring
/// test, or the same test with shell quoting removed when the command has any
/// (`\watch`, `w\atch`, `"watch"`, `w'at'ch` all run `watch`). Linear.
fn may_name_a_command(command: &str, names: &[&str]) -> bool {
    if names.iter().any(|name| command.contains(name)) {
        return true;
    }
    if !command
        .bytes()
        .any(|byte| matches!(byte, b'\\' | b'\'' | b'"'))
    {
        return false;
    }
    let names_one = |text: &str| {
        let unquoted: String = text
            .chars()
            .filter(|ch| !matches!(ch, '\\' | '\'' | '"' | '$'))
            .collect();
        names.iter().any(|name| unquoted.contains(name))
    };
    names_one(command) || decode_ansi_c_strings(command).is_some_and(|decoded| names_one(&decoded))
}

/// The command's word tokens, then those of each process substitution body
/// (`<(…)`, `>(…)`, nested ones too): each body is a command line of its own
/// whose first word is a command, while the outer tokenizer keeps the whole
/// substitution as one word (`cat <(watch '…')`, `cat --x=<(watch '…')`).
/// Token ranges index `command`. `false` when more than `limit` bodies were
/// found, the rest unread.
fn command_token_views(
    command: &str,
    limit: usize,
) -> (Vec<crate::normalize::NormalizeTokens>, bool) {
    let mut views = vec![crate::normalize::tokenize_for_normalization(command)];
    let mut next = 0usize;
    while next < views.len() {
        let mut bodies = Vec::new();
        for token in &views[next] {
            if token.kind != crate::normalize::NormalizeTokenKind::Word {
                continue;
            }
            let Some(text) = token.text(command) else {
                continue;
            };
            let offset = token.byte_range.start;
            bodies.extend(
                process_substitution_bodies(text)
                    .into_iter()
                    .map(|body| body.start + offset..body.end + offset),
            );
        }
        for body in bodies {
            if views.len() > limit {
                return (views, false);
            }
            let Some(text) = command.get(body.clone()) else {
                continue;
            };
            let mut tokens = crate::normalize::tokenize_for_normalization(text);
            for token in &mut tokens {
                token.byte_range =
                    token.byte_range.start + body.start..token.byte_range.end + body.start;
            }
            views.push(tokens);
        }
        next += 1;
    }
    (views, true)
}

/// Byte ranges, within `word`, of the bodies of the process substitutions the
/// word holds: bash expands an unquoted `<(…)`/`>(…)` wherever it stands in a
/// word, so `--file=<(…)` and `a<(…)` run their bodies like `<(…)` does.
/// Quoted text is literal, and a `$(…)` body is the command-substitution
/// reader's, so both are skipped whole. Nested substitutions are the bodies'
/// own. Linear.
fn process_substitution_bodies(word: &str) -> Vec<Range<usize>> {
    let bytes = word.as_bytes();
    let len = bytes.len();
    let mut bodies = Vec::new();
    let mut index = 0usize;
    while index < len {
        match bytes[index] {
            b'\\' => index = (index + 2).min(len),
            // `$'…'` takes backslash escapes, so `\'` does not close it.
            b'$' if bytes.get(index + 1) == Some(&b'\'') => {
                index += 2;
                while index < len && bytes[index] != b'\'' {
                    index += if bytes[index] == b'\\' { 2 } else { 1 };
                }
                index = (index + 1).min(len);
            }
            b'\'' => {
                index += 1;
                while index < len && bytes[index] != b'\'' {
                    index += 1;
                }
                index = (index + 1).min(len);
            }
            b'"' => {
                index += 1;
                while index < len {
                    match bytes[index] {
                        b'"' => {
                            index += 1;
                            break;
                        }
                        b'\\' => index = (index + 2).min(len),
                        b'$' if bytes.get(index + 1) == Some(&b'(') => {
                            index = crate::normalize::consume_shell_paren_construct(
                                bytes,
                                index + 2,
                                len,
                            );
                        }
                        _ => index += 1,
                    }
                }
            }
            b'$' if bytes.get(index + 1) == Some(&b'(') => {
                index = crate::normalize::consume_shell_paren_construct(bytes, index + 2, len);
            }
            b'<' | b'>' if bytes.get(index + 1) == Some(&b'(') => {
                let end = crate::normalize::consume_shell_paren_construct(bytes, index + 2, len);
                if end > index + 3 && bytes[end - 1] == b')' {
                    bodies.push(index + 2..end - 1);
                }
                index = end;
            }
            _ => index += 1,
        }
    }
    bodies
}

/// Runner occurrences one command is read for before the reading is partial.
const MAX_COMMAND_STRING_RUNNERS: usize = 64;

/// The runner the word token names, if any.
fn command_string_runner_name(
    command: &str,
    token: &crate::normalize::NormalizeToken,
) -> Option<&'static str> {
    if token.kind != crate::normalize::NormalizeTokenKind::Word {
        return None;
    }
    let word = dequoted_executable_word(token.text(command)?);
    let basename = word.rsplit('/').next().unwrap_or(&word);
    COMMAND_STRING_RUNNERS
        .iter()
        .find(|runner| **runner == basename)
        .copied()
}

/// For each token, whether a runner there would run: it is the command word
/// of its segment (after assignments, redirects and the reserved words `{`,
/// `!`, `if`, `then`, `do`, …, and the name `function NAME` / `coproc NAME`
/// give a body), or any later word behind a command that runs its arguments
/// (`sudo -u bob watch …`, `timeout 5s watch …`, `taskset -c 0 watch …`),
/// whose options and their values this does not model. A runner among another
/// command's arguments (`echo watch 'x'`) is data. One pass, so the check is
/// linear in the command.
fn command_word_positions(command: &str, tokens: &[crate::normalize::NormalizeToken]) -> Vec<bool> {
    use crate::normalize::NormalizeTokenKind;
    let mut positions = vec![false; tokens.len()];
    let mut expect_command = true;
    let mut wrapped = false;
    let mut redirect_target = false;
    let mut body_name = false;
    for (index, token) in tokens.iter().enumerate() {
        if token.kind != NormalizeTokenKind::Word {
            if splits_fd_duplication(command, tokens, index) {
                // `2>&1`: the `&` and the descriptor after it are the
                // redirect's, not a background separator and a command.
                redirect_target = true;
                continue;
            }
            expect_command = true;
            wrapped = false;
            redirect_target = false;
            body_name = false;
            continue;
        }
        let Some(text) = token.text(command) else {
            continue;
        };
        if redirect_target {
            redirect_target = false;
            continue;
        }
        if word_token_starts_local_redirect(text) {
            redirect_target = redirect_operator_takes_next_word(text);
            continue;
        }
        if body_name {
            // `function f { …; }`, `coproc NAME { …; }`: the name, then a
            // body whose first word is a command.
            body_name = false;
            continue;
        }
        positions[index] = expect_command || wrapped;
        if !expect_command {
            continue;
        }
        if matches!(
            text,
            "{" | "!" | "if" | "then" | "else" | "elif" | "do" | "while" | "until" | "coproc"
        ) || crate::normalize::is_env_assignment(text)
        {
            // bash takes `coproc WORD` as a name only when a compound command
            // follows it (`coproc NAME { …; }`); otherwise WORD is the command.
            body_name = text == "coproc"
                && tokens
                    .get(index + 2)
                    .filter(|body| body.kind == NormalizeTokenKind::Word)
                    .and_then(|body| body.text(command))
                    .is_some_and(|body| {
                        matches!(
                            body,
                            "{" | "while" | "until" | "if" | "for" | "case" | "select"
                        )
                    });
            continue;
        }
        if text == "function" {
            body_name = true;
            continue;
        }
        expect_command = false;
        let executable = dequoted_executable_word(text);
        let basename = executable.rsplit('/').next().unwrap_or(&executable);
        let next = tokens
            .get(index + 1)
            .filter(|next| next.kind == NormalizeTokenKind::Word)
            .and_then(|next| next.text(command));
        wrapped = matches!(
            basename,
            "sudo"
                | "doas"
                | "nice"
                | "nohup"
                | "time"
                | "exec"
                | "command"
                | "builtin"
                | "xargs"
                | "timeout"
                | "gtimeout"
                | "setsid"
                | "stdbuf"
                | "ionice"
                | "chrt"
                | "busybox"
                | "chronic"
                | "env"
        ) || crate::packs::core::git::unmodeled_exec_wrapper(basename, next);
    }
    positions
}

/// Whether a bare redirect operator word takes the following word as its
/// target: `2>` and `>&` do, while `2>&1`, `>&-` and `<&0` carry their target
/// already, so the word after them is the command (`2>&1 watch '…'`).
fn redirect_operator_takes_next_word(text: &str) -> bool {
    let named = redirect_descriptor_prefix_len(text);
    let operator = if named > 0 {
        &text[named..]
    } else {
        text.trim_start_matches(|ch: char| ch.is_ascii_digit())
    };
    !operator.is_empty()
        && operator
            .bytes()
            .all(|byte| matches!(byte, b'>' | b'<' | b'&' | b'|'))
}

/// Whether the separator token at `index` is the `&` of a descriptor
/// duplication (`2>&1`, `>&2`, `<&0`, `>& file`) or the `|` of a clobbering
/// redirect (`>|file`). The tokenizer ends a word at `&` and `|`, so `2>&1`
/// arrives as the word `2>`, a `&` separator and the word `1`; read as a
/// background `&`, the `1` became the command and the word after it
/// (`2>&1 watch '…'`) an argument. `>|f` read as a pipe into `f` ended the
/// runner's words the same way (`watch >|f '…'`).
fn splits_fd_duplication(
    command: &str,
    tokens: &[crate::normalize::NormalizeToken],
    index: usize,
) -> bool {
    let Some(separator) = tokens.get(index) else {
        return false;
    };
    let Some(before) = index.checked_sub(1).and_then(|at| tokens.get(at)) else {
        return false;
    };
    before.kind == crate::normalize::NormalizeTokenKind::Word
        && before.byte_range.end == separator.byte_range.start
        && before.text(command).is_some_and(|text| {
            word_token_starts_local_redirect(text)
                && match separator.text(command) {
                    Some("&") => text.ends_with(['>', '<']),
                    Some("|") => text.ends_with('>') && !text.ends_with("&>"),
                    _ => false,
                }
        })
}

/// The command-string payloads of the runner whose name token is at `start`.
#[allow(clippy::too_many_lines)]
fn command_string_runner_payloads(
    command: &str,
    tokens: &[crate::normalize::NormalizeToken],
    start: usize,
    name: &str,
) -> Vec<SshRemotePayload> {
    use crate::normalize::NormalizeTokenKind;
    let full_start = tokens[start].byte_range.start;
    // The word tokens of this segment after the runner, up to a separator.
    // A local redirect (and a bare operator's target) is the local shell's,
    // wherever it stands: `watch 2>/dev/null '<cmd>'` runs `<cmd>`. The
    // payload spans below still start and end at argv words.
    let mut words: Vec<(&str, Range<usize>)> = Vec::new();
    let mut redirect_target = false;
    for (index, token) in tokens.iter().enumerate().skip(start + 1) {
        if token.kind != NormalizeTokenKind::Word {
            if splits_fd_duplication(command, tokens, index) {
                redirect_target = true;
                continue;
            }
            break;
        }
        let Some(text) = token.text(command) else {
            break;
        };
        if std::mem::take(&mut redirect_target) {
            continue;
        }
        if word_token_starts_local_redirect(text) {
            redirect_target = redirect_operator_takes_next_word(text);
            continue;
        }
        words.push((text, token.byte_range.clone()));
    }
    // Words `from..to` as one payload. Several words are joined by every
    // runner that takes more than one (watch, a parallel template, env -S
    // with trailing words), so they carry the joined reading too.
    let span = |from: usize, to: usize| -> Option<SshRemotePayload> {
        if from >= to || to > words.len() {
            return None;
        }
        let first = &words[from].1;
        let last = &words[to - 1].1;
        let single = to - from == 1;
        let content = if single {
            unquoted_payload_range(words[from].0, first.start)
        } else {
            first.start..last.end
        };
        Some(SshRemotePayload {
            content,
            full: full_start..last.end,
            joined: !single,
        })
    };
    // An attached value, `-c'<cmd>'` or `--prepare=<cmd>`.
    let attached = |rest: &str, value_start: usize, end: usize| SshRemotePayload {
        content: unquoted_payload_range(rest, value_start),
        full: full_start..end,
        joined: false,
    };
    let option = |word: &str| word.len() > 1 && word.starts_with('-');
    let short_cluster = |word: &str| {
        word.len() > 1
            && word.starts_with('-')
            && !word.starts_with("--")
            && word[1..].bytes().all(|byte| byte.is_ascii_alphanumeric())
    };
    let mut payloads = Vec::new();
    match name {
        DYNAMIC_RUNNER => {
            // A program the shell names at run time may be any runner, so
            // every quoted operand may be its command string, and so may the
            // operands joined (`w${x}atch 'git reset' --hard`). Words shown
            // unquoted are judged where they stand already. An operand that
            // is itself run-time text with no blank (`"$ARG"`, `"$DIR/f"`)
            // cannot be judged either way and is left to the program: a
            // dynamic program with dynamic arguments (`"$X" "$Y"`) stays
            // allowed (#273).
            let quoted = |word: &str| word.contains(['\'', '"', '$', '\\']);
            let spaced = |word: &str| {
                crate::normalize::decode_posix_syntax_token(word).contains(char::is_whitespace)
            };
            let judgeable = |word: &str| {
                let decoded = crate::normalize::decode_posix_syntax_token(word);
                decoded.contains(char::is_whitespace) || !decoded.contains(['$', '`'])
            };
            let first_operand = words.iter().position(|(word, _)| !option(word));
            for (at, (word, range)) in words.iter().enumerate() {
                if !quoted(word) {
                    continue;
                }
                if !option(word) {
                    if judgeable(word) {
                        payloads.extend(span(at, at + 1));
                    }
                } else if let Some(value) = word.find(['=', '\'', '"']).filter(|at| *at > 1) {
                    // `-c'<cmd>'`, `--command=<cmd>`
                    let value_start = value + usize::from(word.as_bytes()[value] == b'=');
                    if value_start < word.len() && judgeable(&word[value_start..]) {
                        payloads.push(attached(
                            &word[value_start..],
                            range.start + value_start,
                            range.end,
                        ));
                    }
                }
            }
            if let Some(first) = first_operand
                && words.len() - first > 1
                && words[first..]
                    .iter()
                    .any(|(word, _)| quoted(word) && spaced(word))
            {
                payloads.extend(span(first, words.len()));
            }
        }
        "watch" => {
            // procps `watch` stops at its first operand (`+` getopt), so only
            // the options before it decide `-x`; `-n`/`-q` take a value,
            // also at the end of a cluster (`-tn 1`).
            let mut index = 0usize;
            let mut exec = false;
            while index < words.len() {
                let word = words[index].0;
                if word == "--" {
                    index += 1;
                    break;
                }
                if !option(word) {
                    break;
                }
                if matches!(word, "-n" | "--interval" | "-q" | "--equexit") {
                    index += 2;
                    continue;
                }
                if word == "--exec" {
                    exec = true;
                } else if short_cluster(word) {
                    let letters = &word[1..];
                    let value_at = letters.find(['n', 'q']);
                    let flags = value_at.map_or(letters, |at| &letters[..at]);
                    exec |= flags.contains('x');
                    if value_at == Some(letters.len() - 1) {
                        index += 2;
                        continue;
                    }
                }
                index += 1;
            }
            if exec {
                // argv, not a shell string: judged where it stands.
                return payloads;
            }
            payloads.extend(span(index, words.len()));
        }
        "parallel" => {
            let separator = |word: &str| matches!(word, ":::" | "::::" | ":::+" | "::::+");
            // Where the template may start: after the options, and at each
            // word after an option this does not model, which is either that
            // option's value (the options go on after it) or the template.
            // `parallel --retries 3 --tag 'git …' ::: a` runs `git …`.
            let mut starts = Vec::new();
            let mut index = 0usize;
            let mut after_unknown = false;
            while index < words.len() {
                let word = words[index].0;
                if word == "--" {
                    index += 1;
                    break;
                }
                if separator(word) {
                    break;
                }
                if !option(word) {
                    if !after_unknown {
                        break;
                    }
                    starts.push(index);
                    after_unknown = false;
                    index += 1;
                    continue;
                }
                after_unknown = false;
                if PARALLEL_VALUE_OPTIONS.contains(&word) {
                    index += 2;
                    continue;
                }
                after_unknown = !PARALLEL_FLAG_OPTIONS.contains(&word) && !word.contains('=');
                index += 1;
            }
            starts.push(index);
            // The first separator at or after each position, so every start
            // costs O(1) however many options precede it.
            let mut next_separator = vec![words.len(); words.len() + 1];
            for at in (0..words.len()).rev() {
                next_separator[at] = if separator(words[at].0) {
                    at
                } else {
                    next_separator[at + 1]
                };
            }
            let mut listed_arguments = false;
            for template in starts {
                let end = next_separator[template.min(words.len())];
                if end > template {
                    payloads.extend(span(template, end));
                } else if !listed_arguments
                    && words.get(template).is_some_and(|(word, _)| *word == ":::")
                {
                    // No command: each argument is one.
                    listed_arguments = true;
                    for (at, (word, _)) in words.iter().enumerate().skip(template + 1) {
                        if separator(word) {
                            break;
                        }
                        payloads.extend(span(at, at + 1));
                    }
                }
            }
        }
        "hyperfine" => {
            // Every operand is a benchmarked command, and so are the values
            // of `--prepare`, `--setup`, `--cleanup`, `--conclude` and
            // `--reference`, separate or attached; a value that is a number
            // or a file name reads as a harmless command.
            for (at, (word, range)) in words.iter().enumerate() {
                if !option(word) {
                    payloads.extend(span(at, at + 1));
                    continue;
                }
                let value = [
                    "--prepare=",
                    "--setup=",
                    "--cleanup=",
                    "--conclude=",
                    "--reference=",
                ]
                .iter()
                .find_map(|prefix| word.strip_prefix(prefix).map(|rest| (prefix.len(), rest)))
                .or_else(|| {
                    ["-p", "-s", "-c"].iter().find_map(|prefix| {
                        word.strip_prefix(prefix).map(|rest| (prefix.len(), rest))
                    })
                });
                if let Some((prefix_len, rest)) = value
                    && !rest.is_empty()
                {
                    payloads.push(attached(rest, range.start + prefix_len, range.end));
                }
            }
        }
        "entr" => {
            // `-s` (a flag, alone or in a cluster) hands the first operand
            // to `$SHELL -c`; entr's options take no values.
            let mut shell = false;
            let mut index = 0usize;
            while index < words.len() {
                let word = words[index].0;
                if word == "--" {
                    index += 1;
                    break;
                }
                if !option(word) {
                    break;
                }
                shell |= !word.starts_with("--") && word[1..].contains('s');
                index += 1;
            }
            if shell {
                payloads.extend(span(index, index + 1));
            }
        }
        "sg" if !words
            .iter()
            .any(|(word, _)| matches!(word.trim_matches(['\'', '"']), "-c"))
            && !words.iter().any(|(word, _)| word.starts_with("-c")) =>
        {
            // `sg [-] group command`: without `-c` the word after the group
            // is the command string.
            let group = usize::from(words.first().is_some_and(|(word, _)| *word == "-"));
            payloads.extend(span(group + 1, group + 2));
        }
        "su" | "sg" | "runuser" | "script" | "flock" | "nix-shell" | "npx" => {
            let flags = command_string_flags(name);
            for (at, (word, range)) in words.iter().enumerate() {
                let unquoted = word.trim_matches(['\'', '"']);
                // A short flag may end a cluster: `su -lc '<cmd>'`,
                // `script -qc '<cmd>'`.
                let clustered = |flag: &&str| {
                    flag.len() == 2
                        && !unquoted.starts_with("--")
                        && unquoted.len() > 2
                        && unquoted.starts_with('-')
                        && unquoted.ends_with(&flag[1..])
                        && unquoted[1..].bytes().all(|byte| byte.is_ascii_alphabetic())
                };
                if flags.contains(&unquoted) || flags.iter().any(clustered) {
                    payloads.extend(span(at + 1, at + 2));
                    continue;
                }
                // Attached: `-c'<cmd>'`, `--command=<cmd>`.
                let value = flags.iter().find_map(|flag| {
                    let prefix = if flag.starts_with("--") {
                        format!("{flag}=")
                    } else {
                        (*flag).to_string()
                    };
                    word.strip_prefix(prefix.as_str())
                        .filter(|rest| !rest.is_empty())
                        .map(|rest| (prefix.len(), rest))
                });
                if let Some((prefix_len, rest)) = value {
                    payloads.push(attached(rest, range.start + prefix_len, range.end));
                }
            }
        }
        _ => {
            // env: the `-S`/`--split-string` value, split by env, is the
            // command, and the words after it are appended to its argv.
            let mut index = 0usize;
            while index < words.len() {
                let (word, range) = (words[index].0, words[index].1.clone());
                if !option(word) {
                    break;
                }
                let unquoted = word.trim_matches(['\'', '"']);
                if matches!(unquoted, "-S" | "--split-string") {
                    payloads.extend(span(index + 1, index + 2));
                    payloads
                        .extend(span(index + 1, words.len()).filter(|_| index + 2 < words.len()));
                    break;
                }
                let value = ["--split-string=", "-S"]
                    .iter()
                    .find_map(|prefix| word.strip_prefix(prefix).map(|rest| (prefix.len(), rest)));
                if let Some((prefix_len, rest)) = value
                    && !rest.is_empty()
                {
                    let value_start = range.start + prefix_len;
                    payloads.push(attached(rest, value_start, range.end));
                    if let Some(last) = words.get(index + 1..).and_then(<[_]>::last) {
                        // `env -S'git reset' --hard`: value plus trailing words.
                        payloads.push(SshRemotePayload {
                            content: value_start..last.1.end,
                            full: full_start..last.1.end,
                            joined: true,
                        });
                    }
                    break;
                }
                index += if matches!(
                    unquoted,
                    "-u" | "--unset" | "-C" | "--chdir" | "-a" | "--argv0" | "-f" | "--file"
                ) {
                    2
                } else {
                    1
                };
            }
        }
    }
    payloads
}

/// The runner label of a command word the shell assembles at run time
/// (`w${x}atch`, `$RUNNER`), which may name any of the runners.
const DYNAMIC_RUNNER: &str = "<dynamic command word>";

/// Wrappers after which the next word is still the command a segment runs,
/// for [`primary_command_positions`].
const PRIMARY_COMMAND_WRAPPERS: &[&str] = &[
    "sudo", "doas", "nohup", "exec", "command", "builtin", "nice", "time", "env", "xargs",
    "setsid", "chronic", "timeout", "gtimeout",
];

/// For each token, whether it is the command word a segment actually runs:
/// its first command position after assignments and reserved words, or the
/// first word after one of the [`PRIMARY_COMMAND_WRAPPERS`] and its option
/// flags (`sudo $RUNNER '…'`, `nice -n5 $RUNNER '…'` is not modeled, but
/// `timeout 5 $RUNNER '…'` is). The run-time command handling reads only
/// these, not every word behind a wrapper that [`command_word_positions`]
/// admits, so a variable among `sudo -u "$USER"`'s options does not turn a
/// later quoted argument into a command. Linear.
fn primary_command_positions(
    command: &str,
    tokens: &[crate::normalize::NormalizeToken],
    positions: &[bool],
) -> Vec<bool> {
    let mut primary = vec![false; tokens.len()];
    let mut seen = false;
    // Inside a wrapper's prefix: its flags, an option's value, and
    // `timeout`'s duration.
    let mut after_wrapper: Option<&str> = None;
    let mut value_next = false;
    let mut duration_next = false;
    for (index, token) in tokens.iter().enumerate() {
        if token.kind != crate::normalize::NormalizeTokenKind::Word {
            if !splits_fd_duplication(command, tokens, index) {
                seen = false;
                after_wrapper = None;
                value_next = false;
                duration_next = false;
            }
            continue;
        }
        let Some(word) = token.text(command) else {
            continue;
        };
        if !positions[index] {
            after_wrapper = None;
            continue;
        }
        if !seen
            && (crate::normalize::is_env_assignment(word)
                || matches!(
                    word,
                    "{" | "!" | "if" | "then" | "else" | "elif" | "do" | "while" | "until"
                ))
        {
            continue;
        }
        if std::mem::take(&mut value_next) {
            continue;
        }
        if let Some(wrapper) = after_wrapper
            && word.len() > 1
            && word.starts_with('-')
        {
            // `sudo -u "$USER" git …`: `-u` takes the next word.
            value_next = wrapper_option_takes_value(wrapper, word);
            continue;
        }
        if std::mem::take(&mut duration_next)
            && word.bytes().all(|byte| {
                byte.is_ascii_digit() || matches!(byte, b'.' | b's' | b'm' | b'h' | b'd')
            })
        {
            continue;
        }
        primary[index] = !seen || after_wrapper.is_some();
        seen = true;
        let executable = dequoted_executable_word(word);
        let basename = executable.rsplit('/').next().unwrap_or(&executable);
        after_wrapper = PRIMARY_COMMAND_WRAPPERS
            .iter()
            .find(|wrapper| **wrapper == basename)
            .copied();
        duration_next = matches!(after_wrapper, Some("timeout" | "gtimeout"));
    }
    primary
}

/// Whether a [`PRIMARY_COMMAND_WRAPPERS`] option takes the next word as its
/// value. Unknown options are taken to stand alone, so a value they carry
/// may be read as the command: a missed run-time command word, never a
/// quoted argument read as one.
fn wrapper_option_takes_value(wrapper: &str, option: &str) -> bool {
    let options: &[&str] = match wrapper {
        "sudo" | "doas" => &[
            "-u",
            "-g",
            "-h",
            "-p",
            "-C",
            "-D",
            "-r",
            "-t",
            "-U",
            "-T",
            "--user",
            "--group",
            "--host",
            "--prompt",
            "--chdir",
            "--role",
            "--type",
            "--other-user",
            "--command-timeout",
            "--close-from",
        ],
        "env" => &["-u", "-C", "-S", "--unset", "--chdir", "--split-string"],
        "nice" => &["-n", "--adjustment"],
        "timeout" | "gtimeout" => &["-s", "-k", "--signal", "--kill-after"],
        "xargs" => &[
            "-a",
            "-d",
            "-E",
            "-I",
            "-J",
            "-L",
            "-n",
            "-P",
            "-R",
            "-s",
            "-S",
            "--arg-file",
            "--delimiter",
            "--max-args",
            "--max-procs",
            "--max-chars",
            "--max-lines",
            "--process-slot-var",
        ],
        _ => &[],
    };
    options.contains(&option)
}

/// Whether the word after token `index` is an assignment operator (`$x = …`,
/// `$x += …`): PowerShell's assignment, which dcg also reads under the
/// POSIX rules when the dialect is not proven. POSIX would run `$x` with an
/// argument `=`, which no one writes on purpose.
fn assigns_like_powershell(
    command: &str,
    tokens: &[crate::normalize::NormalizeToken],
    index: usize,
) -> bool {
    tokens
        .get(index + 1)
        .filter(|token| token.kind == crate::normalize::NormalizeTokenKind::Word)
        .and_then(|token| token.text(command))
        .is_some_and(|word| {
            word.starts_with('=')
                || ["+=", "-=", "*=", "/=", "%=", "??="]
                    .iter()
                    .any(|operator| word.starts_with(operator))
        })
}

/// Index just past the last word token of the segment holding `index`.
fn segment_end(tokens: &[crate::normalize::NormalizeToken], index: usize) -> usize {
    tokens[index..]
        .iter()
        .take_while(|token| token.kind == crate::normalize::NormalizeTokenKind::Word)
        .last()
        .map_or(tokens[index].byte_range.end, |token| token.byte_range.end)
}

/// Whether some command word of `command` is assembled at run time in a way
/// the runner and substitution readers act on: a whole `$(…)`/backquote
/// substitution, or an expansion that may complete a runner's name, with a
/// quoted operand. The tier-1 superset of what
/// [`extract_command_string_runner_scripts`] reads for such words.
fn may_run_through_dynamic_command_word(command: &str) -> bool {
    let bytes = command.as_bytes();
    let substitution = command.contains("$(") || bytes.contains(&b'`');
    let quoted = bytes.iter().any(|byte| matches!(byte, b'\'' | b'"'));
    if !(substitution || (quoted && bytes.contains(&b'$'))) {
        return false;
    }
    let tokens = crate::normalize::tokenize_for_normalization(command);
    let positions = command_word_positions(command, &tokens);
    let primary = primary_command_positions(command, &tokens, &positions);
    tokens.iter().enumerate().any(|(index, token)| {
        primary[index]
            && token.text(command).is_some_and(|word| {
                whole_substitution_body(word).is_some()
                    || (quoted && dynamic_word_may_name_runner(word))
            })
    })
}

/// The body of a word that is exactly one command substitution:
/// `$(…)`, `` `…` ``, or either inside double quotes.
fn whole_substitution_body(word: &str) -> Option<&str> {
    let word = word
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(word);
    let bytes = word.as_bytes();
    if let Some(inner) = word.strip_prefix("$(") {
        let end = crate::normalize::consume_shell_paren_construct(bytes, 2, bytes.len());
        return (end == bytes.len() && word.ends_with(')')).then(|| &inner[..inner.len() - 1]);
    }
    let inner = word.strip_prefix('`')?.strip_suffix('`')?;
    (!inner.is_empty() && !inner.contains('`')).then_some(inner)
}

/// The command line a command word that is one whole substitution runs,
/// read as if the substitution echoed its arguments: each segment's words
/// after its first, then the outer segment's remaining words, all with their
/// quoting removed. `$(echo git reset --hard)` and
/// `$(printf 'git reset') --hard` run `git reset --hard`; `$(which cargo)
/// build` runs `cargo build`. `None` when the word is not a substitution or
/// nothing would be printed.
fn substitution_command_line(
    command: &str,
    tokens: &[crate::normalize::NormalizeToken],
    index: usize,
    word: &str,
) -> Option<String> {
    let body = whole_substitution_body(word)?;
    let mut words = echoed_words(body);
    if words.is_empty() {
        return None;
    }
    // The outer words keep their quoting: the line is parsed again as shell.
    for token in tokens[index + 1..]
        .iter()
        .take_while(|token| token.kind == crate::normalize::NormalizeTokenKind::Word)
    {
        if let Some(text) = token.text(command) {
            words.push(text.to_string());
        }
    }
    Some(words.join(" "))
}

/// What a command line prints, read as if each of its commands echoed its
/// arguments: every segment's words after its program, quoting removed,
/// without `echo`'s leading options or a `printf` format holding a directive.
/// The model behind [`substitution_command_line`] and the evaluator's
/// `BASH_ENV=<(…)` view: `echo git reset --hard` and
/// `printf '%s' 'git reset --hard'` print `git reset --hard`.
pub(crate) fn echoed_words(body: &str) -> Vec<String> {
    let body_tokens = crate::normalize::tokenize_for_normalization(body);
    let mut words: Vec<String> = Vec::new();
    // The current body segment's program, and whether its leading options
    // (`echo -n`) or `printf`'s format are still to come.
    let mut program: Option<String> = None;
    let mut leading = true;
    for token in &body_tokens {
        if token.kind != crate::normalize::NormalizeTokenKind::Word {
            program = None;
            continue;
        }
        let Some(text) = token.text(body) else {
            continue;
        };
        let decoded = crate::normalize::decode_posix_syntax_token(text).into_owned();
        let Some(name) = program.as_deref() else {
            program = Some(decoded.rsplit('/').next().unwrap_or(&decoded).to_string());
            leading = true;
            continue;
        };
        if leading {
            if name == "echo" && matches!(decoded.as_str(), "-n" | "-e" | "-E" | "-ne" | "-en") {
                continue;
            }
            leading = false;
            // printf's format prints itself only when it has no directive.
            if name == "printf" && decoded.contains('%') {
                continue;
            }
        }
        words.push(decoded);
    }
    words
}

/// Whether a command word holding a run-time expansion may name one of the
/// runners (or `ssh`) once expanded: its last path component, read with each
/// expansion as a wildcard, matches the name (`w${x}atch`, `${W}atch`, `$W`,
/// `"$RUNNER"`). A word whose last component is literal (`$HOME/bin/tool`)
/// names that literal program, and one whose literal parts fit no runner
/// (`$X-build`) names none of them. `$'…'` counts as an expansion here: a
/// wholly literal `$'…'` word is decoded by [`dequoted_executable_word`]
/// instead. Linear in the word.
fn dynamic_word_may_name_runner(word: &str) -> bool {
    #[derive(PartialEq)]
    enum Piece {
        Literal(Vec<u8>),
        Any,
    }
    let bytes = word.as_bytes();
    let len = bytes.len();
    let mut pieces: Vec<Piece> = Vec::new();
    let literal = |pieces: &mut Vec<Piece>, byte: u8| match pieces.last_mut() {
        Some(Piece::Literal(text)) => text.push(byte),
        _ => pieces.push(Piece::Literal(vec![byte])),
    };
    let any = |pieces: &mut Vec<Piece>| {
        if pieces.last() != Some(&Piece::Any) {
            pieces.push(Piece::Any);
        }
    };
    let mut double = false;
    // A `$'…'` string is quoting, not an expansion: a word with no other
    // `$`/backquote names a literal program, which the ordinary readers see.
    let mut run_time = false;
    let mut index = 0usize;
    while index < len {
        let byte = bytes[index];
        if byte == b'`' || (byte == b'$' && bytes.get(index + 1) != Some(&b'\'')) {
            run_time = true;
        }
        match byte {
            b'/' => {
                pieces.clear();
                index += 1;
            }
            b'"' => {
                double = !double;
                index += 1;
            }
            b'\'' if !double => {
                let end = memchr(b'\'', &bytes[index + 1..]).map_or(len, |at| index + 1 + at);
                for &inner in &bytes[index + 1..end] {
                    if inner == b'/' {
                        pieces.clear();
                    } else {
                        literal(&mut pieces, inner);
                    }
                }
                index = end + 1;
            }
            b'\\' => {
                if let Some(&next) = bytes.get(index + 1) {
                    literal(&mut pieces, next);
                }
                index += 2;
            }
            b'`' => {
                any(&mut pieces);
                let mut at = index + 1;
                while at < len && bytes[at] != b'`' {
                    at += if bytes[at] == b'\\' { 2 } else { 1 };
                }
                index = at + 1;
            }
            b'$' => match bytes.get(index + 1) {
                Some(b'(') => {
                    any(&mut pieces);
                    index = crate::normalize::consume_shell_paren_construct(bytes, index + 2, len);
                }
                Some(b'{') => {
                    any(&mut pieces);
                    index = memchr(b'}', &bytes[index + 2..]).map_or(len, |at| index + 3 + at);
                }
                Some(b'\'') if !double => {
                    any(&mut pieces);
                    let mut at = index + 2;
                    while at < len && bytes[at] != b'\'' {
                        at += if bytes[at] == b'\\' { 2 } else { 1 };
                    }
                    index = at + 1;
                }
                Some(next) if next.is_ascii_alphabetic() || *next == b'_' => {
                    any(&mut pieces);
                    index += 1;
                    while index < len
                        && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
                    {
                        index += 1;
                    }
                }
                Some(next) if next.is_ascii_digit() || b"@*#?!$-".contains(next) => {
                    any(&mut pieces);
                    index += 2;
                }
                _ => {
                    literal(&mut pieces, byte);
                    index += 1;
                }
            },
            _ => {
                literal(&mut pieces, byte);
                index += 1;
            }
        }
    }
    if !run_time || !pieces.contains(&Piece::Any) {
        return false;
    }
    // Wildcard match of the pieces against a name; the literal pieces are few
    // and short once they must fit a runner name, so backtracking is bounded.
    fn fits(pieces: &[Piece], name: &[u8]) -> bool {
        match pieces.split_first() {
            None => name.is_empty(),
            Some((Piece::Literal(text), rest)) => {
                name.starts_with(text) && fits(rest, &name[text.len()..])
            }
            Some((Piece::Any, rest)) => (0..=name.len()).any(|skip| fits(rest, &name[skip..])),
        }
    }
    let literal_len: usize = pieces
        .iter()
        .map(|piece| match piece {
            Piece::Literal(text) => text.len(),
            Piece::Any => 0,
        })
        .sum();
    COMMAND_STRING_RUNNERS
        .iter()
        .copied()
        .chain(["ssh"])
        .any(|name| literal_len <= name.len() && fits(&pieces, name.as_bytes()))
}

/// Programs that run a command string (see
/// [`extract_command_string_runner_scripts`]).
const COMMAND_STRING_RUNNERS: &[&str] = &[
    "watch",
    "parallel",
    "env",
    "su",
    "sg",
    "runuser",
    "script",
    "nix-shell",
    "npx",
    "entr",
    "flock",
    "hyperfine",
];

/// The option that hands each flag runner its command string.
fn command_string_flags(name: &str) -> &'static [&'static str] {
    match name {
        "su" | "runuser" | "script" | "flock" => &["-c", "--command"],
        "sg" => &["-c"],
        "nix-shell" => &["--run", "--command"],
        "npx" => &["-c", "--call"],
        _ => &[],
    }
}

/// GNU parallel options whose value is the next word.
const PARALLEL_VALUE_OPTIONS: &[&str] = &[
    "-a",
    "-C",
    "-I",
    "-j",
    "-L",
    "-N",
    "-P",
    "-S",
    "--arg-file",
    "--colsep",
    "--delay",
    "--jobs",
    "--joblog",
    "--max-args",
    "--results",
    "--sshlogin",
    "--timeout",
];

/// GNU parallel options known to take no value.
const PARALLEL_FLAG_OPTIONS: &[&str] = &[
    "-0",
    "-k",
    "-q",
    "-r",
    "-u",
    "-v",
    "-X",
    "-m",
    "--bar",
    "--dry-run",
    "--eta",
    "--group",
    "--keep-order",
    "--line-buffer",
    "--null",
    "--pipe",
    "--progress",
    "--quote",
    "--tag",
    "--ungroup",
    "--verbose",
    "--xargs",
];

/// Words passed to a command, excluding redirects performed by the local
/// shell. Raw quoting distinguishes a literal `>` argument from a redirect;
/// redirects may appear before, between, or after ordinary argv words.
pub(crate) fn local_command_argv<'a>(
    command: &str,
    tokens: &'a [crate::normalize::NormalizeToken],
    start: usize,
) -> Option<Vec<&'a crate::normalize::NormalizeToken>> {
    use crate::normalize::NormalizeTokenKind;

    // ssh's argv: the words up to the next shell separator (which belongs to
    // the LOCAL shell), without local redirects and a bare operator's target,
    // which the local shell also removes wherever they stand — a redirect
    // applies to the `ssh` process, never to the remote command
    // (`ssh h 2>/dev/null '<cmd>'` runs `<cmd>`). Dropping a trailing one is
    // what keeps the payload a single token in `ssh h "a 2>/dev/null" 2>&1`,
    // so the quote-stripping branch below still fires: when the run swallowed
    // the local `2>`, the retained closing quote glued itself onto the remote
    // target, producing `/dev/null"` and a `redirect-truncate-dynamic-path`
    // deny for an unchanged, harmless inner redirect (issue #404).
    let mut argv: Vec<&crate::normalize::NormalizeToken> = Vec::new();
    let mut redirect_target = false;
    for (index, token) in tokens.iter().enumerate().skip(start) {
        if token.kind != NormalizeTokenKind::Word {
            if splits_fd_duplication(command, tokens, index) {
                redirect_target = true;
                continue;
            }
            break;
        }
        let text = token.text(command)?;
        if std::mem::take(&mut redirect_target) {
            continue;
        }
        if word_token_starts_local_redirect(text) {
            redirect_target = redirect_operator_takes_next_word(text);
            continue;
        }
        argv.push(token);
    }
    Some(argv)
}

/// Locate the remote-command payload of the `ssh` invocation whose executable
/// token is at `start`. See [`extract_ssh_inline_scripts`] for the grammar and
/// the deliberate bail on unmodeled options.
fn ssh_remote_payload(
    command: &str,
    tokens: &[crate::normalize::NormalizeToken],
    start: usize,
) -> Option<SshRemotePayload> {
    let full_start = tokens.get(start)?.byte_range.start;
    let argv = local_command_argv(command, tokens, start + 1)?;
    let word_at = |index: usize| -> Option<&str> {
        let token = argv.get(index)?;
        let (word, _, _) = dequoted_flag_word(
            token.text(command)?,
            token.byte_range.start,
            token.byte_range.end,
        );
        Some(word)
    };
    let mut index = 0usize;
    let mut options_ended = false;

    // Phase 1: options, then the destination.
    loop {
        // No destination: plain `ssh` — no payload.
        let word = word_at(index)?;
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
    // OpenSSH parses options again right after the destination unless `--`
    // ended them (`ssh host -t cmd`, `ssh host -- cmd`): those words are
    // ssh's, not the remote command's. An option this does not model there
    // leaves the words to the payload, as before.
    if !options_ended {
        let mut again = index;
        while let Some(word) = word_at(again) {
            if word == "--" {
                again += 1;
                index = again;
                break;
            }
            if !(word.len() > 1 && word.starts_with('-')) {
                index = again;
                break;
            }
            match classify_ssh_option(word) {
                SshOptionShape::FlagsOnly | SshOptionShape::ValueAttached => again += 1,
                SshOptionShape::TakesSeparateValue => again += 2,
                SshOptionShape::Unknown => break,
            }
            index = again;
        }
    }

    // Phase 2: the payload is the rest of the argv.
    let payload = argv.get(index..).unwrap_or_default();
    let (first, last) = (payload.first()?, payload.last()?);
    if payload.len() == 1 {
        // Single payload word: strip one layer of quotes so the recursive
        // evaluation sees the remote command line itself, exactly as the
        // remote shell will.
        let text = command.get(first.byte_range.clone())?;
        return Some(SshRemotePayload {
            content: unquoted_payload_range(text, first.byte_range.start),
            full: full_start..first.byte_range.end,
            joined: false,
        });
    }
    Some(SshRemotePayload {
        content: first.byte_range.start..last.byte_range.end,
        full: full_start..last.byte_range.end,
        joined: true,
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
    let mut foreign_body_ranges = None;
    let written_source = written_heredoc_interpreter(command);
    for cap in HEREDOC_EXTRACTOR.captures_iter(command) {
        if record_timeout_if_needed(start_time, timeout, limits.timeout_ms, skip_reasons) {
            return;
        }
        let full_match = cap.get(0).unwrap();
        // Retain executable/interpolating heredocs, but do not reclassify the
        // literal argument of a plain Perl print statement as a new program.
        // The outer shell AST must independently prove ownership as well.
        let nested = extracted.iter().any(|source| {
            source.quoted
                && source.target_command.as_deref().is_some_and(|target| {
                    ScriptLanguage::from_command(target) == ScriptLanguage::Perl
                })
                && source
                    .content_range
                    .as_ref()
                    .is_some_and(|body| body.contains(&full_match.start()))
        });
        if nested
            && is_literal_perl_print_heredoc(command, full_match.start()..full_match.end())
            && foreign_body_ranges
                .get_or_insert_with(|| {
                    quoted_non_shell_heredoc_ranges(command, limits.max_heredocs)
                })
                .iter()
                .any(|body| body.contains(&full_match.start()))
        {
            continue;
        }
        // A duplicate inside data must not consume the extraction quota either.
        if extracted.len() >= limits.max_heredocs {
            hit_limit = true;
            break;
        }

        // `<<<` is a here-string, not a heredoc, and `extract_herestrings`
        // already handled it. The regex anchors on `<<`, so it also matches the
        // last two `<` of `<<<` and reads the here-string's own text as a
        // heredoc delimiter — `cat <<< 'hello world'` produced a phantom
        // heredoc with delimiter `hello world`, which has no terminator line
        // and so recorded `UnterminatedHeredoc`. That reason was invisible
        // while a partial extraction was reported as complete; now that it is
        // not (#427), a phantom reason would put every here-string on the
        // bounded-fallback path, and deny it outright under
        // `fallback_on_parse_error=false`.
        if command.as_bytes()[..cap.get(0).map_or(0, |m| m.start())]
            .last()
            .is_some_and(|byte| *byte == b'<')
        {
            continue;
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
                let (mut language, _confidence) = ScriptLanguage::detect(command, &content);
                // A literal cat write immediately consumed as a script is
                // executable source, not a data-only cat body (#519). Bind
                // the language to this exact operator and body, so the AST
                // and synchronous sink backstops inspect the written bytes.
                let target_cmd = if let Some(source) = written_source.as_ref().filter(|source| {
                    quoted
                        && source.operator_start == full_match.start()
                        && source.body == (body_start_abs..body_end_abs)
                }) {
                    language = source.language;
                    Some(source.interpreter.clone())
                } else {
                    extract_heredoc_target_command(command, full_match.start())
                };
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

/// A deliberately small Perl data-only statement: a single-quoted heredoc is
/// the sole argument to a plain print/say terminated on its header line.
/// `eval`, assignments with unknown later consumers, interpolation, additional
/// arguments and transformations retain conservative analysis. This predicate
/// is shared by extraction and the bounded Perl lexer, not a Perl evaluator.
pub(crate) fn is_literal_perl_print_heredoc(command: &str, operator: Range<usize>) -> bool {
    let Some(header) = command.get(operator.clone()) else {
        return false;
    };
    let Some(delimiter) = header.strip_prefix("<<") else {
        return false;
    };
    let delimiter = delimiter
        .strip_prefix('~')
        .unwrap_or(delimiter)
        .trim_start_matches([' ', '\t']);
    if !delimiter.starts_with('\'') || header.contains(['\n', '\r']) {
        return false;
    }
    let prefix = command[..operator.start]
        .rsplit('\n')
        .next()
        .unwrap_or("")
        .trim();
    let suffix = command[operator.end..]
        .split('\n')
        .next()
        .unwrap_or("")
        .trim();
    matches!(prefix, "print" | "say" | "CORE::print" | "CORE::say") && suffix == ";"
}

/// AST-proven quoted stdin owned by a concrete non-shell interpreter. This
/// does NOT mark the program safe: the complete body is still analyzed. It
/// only permits a proven literal print argument to retain its program owner.
/// Shells, expanding bodies and overridden receivers
/// retain the old conservative scan.
///
/// Do not call `active_heredocs` or the fallback-capable override helper here:
/// their recovery paths call this extractor. A single direct parse avoids that
/// cycle, and a parse error supplies no exemption. The caller caches the result;
/// at most the extraction quota's worth of name-override walks can be required.
fn quoted_non_shell_heredoc_ranges(command: &str, limit: usize) -> Vec<Range<usize>> {
    if command.len() > 256 * 1024 {
        return Vec::new();
    }
    let ast = AstGrep::new(command, SupportLang::Bash);
    let mut heredocs = Vec::new();
    let mut parse_error = false;
    // Only the bodies are wanted here, not where their command's output goes.
    collect_active_heredocs(ast.root(), &mut heredocs, &mut parse_error, true);
    if parse_error {
        return Vec::new();
    }
    let mut ranges = Vec::new();
    for heredoc in heredocs.into_iter().take(limit) {
        let ActiveHeredocBody::Heredoc {
            body_start,
            body_end,
            delimiter_quoted: true,
        } = heredoc.body
        else {
            continue;
        };
        let Some((target, wrapped)) =
            extract_heredoc_target_resolution(command, heredoc.operator_start)
        else {
            continue;
        };
        if wrapped || !is_non_shell_interpreter_stdin_command(&target) {
            continue;
        }
        let basename = target.rsplit(['/', '\\']).next().unwrap_or(&target);
        let mut overridden = false;
        let mut override_parse_error = false;
        find_shell_name_override_deep(
            ast.root(),
            basename,
            &mut overridden,
            &mut override_parse_error,
        );
        if !overridden && !override_parse_error {
            ranges.push(body_start..body_end);
        }
    }
    ranges
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

/// The command that receives the first heredoc in `command`, by basename.
///
/// Exposed for pack ordering (#428): the dialect that will actually execute a
/// SQL payload is the one that should answer for it, and that is decided by the
/// carrier rather than by which pack the configuration happens to list first.
/// Cheap by construction — one substring search plus the backward walk — and
/// callers gate it on the command carrying a heredoc at all.
pub(crate) fn first_heredoc_target_command(command: &str) -> Option<String> {
    let operator = memchr::memmem::find(command.as_bytes(), b"<<")?;
    extract_heredoc_target_command(command, operator)
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
    // `tokenize_backwards` stops at `| ; & ( )` but NOT at newlines, so an
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
/// The walk stops at a real command boundary — `|`, `;`, `&`, `(`, `)` — so it
/// never reads tokens belonging to another command. A bare `$` is **not** one:
/// it introduces an expansion *inside* a word, and `$VAR`/`${VAR}` keep the word
/// in the same simple command. Treating it as a boundary truncated the walk
/// before the program word, so `cat > $S/out.md <<'EOF'` resolved no target at
/// all, the quoted (therefore inert) body could not be masked, and a line-leading
/// backtick in it tripped `heredoc.shell:launcher-unverified` — while the
/// better-quoted `cat > "$S/out.md"` was allowed, because the quoted-string arm
/// below consumes that token whole and the walk reached `cat` (#439).
/// A command substitution is still bounded: `$(…)` ends in `)` and an unclosed
/// one leaves its `(`, both of which stop the walk.
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

        // Check for command separator (|, ;, &, (, ))
        if matches!(bytes[i - 1], b'|' | b';' | b'&' | b'(' | b')') {
            // Stop parsing - we've reached a command boundary
            break;
        }

        // Regular word - scan backwards to whitespace or separator
        while i > 0 {
            let c = bytes[i - 1];
            if c.is_ascii_whitespace() || matches!(c, b'|' | b';' | b'&' | b'(' | b')') {
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
    if !parse_error {
        return overridden;
    }
    // The whole command can still fail to parse because of bytes inside a
    // *quoted* heredoc body, which are literal stdin data the shell never
    // parses as grammar (issue #412). Retry once with only those bodies
    // blanked: if the command then parses and shows no override, the parse
    // error came from inert data and cannot have hidden one. Anything else
    // keeps the fail-closed answer.
    //
    // The failed parse's own `overridden` is deliberately NOT consulted: a
    // mis-parse can invent an assignment out of body text (`Read-only` inside a
    // commit message), and a verdict read off a tree the parser already
    // rejected is exactly as untrustworthy as the rejection.
    let Some(blanked) = quoted_heredoc_bodies_blanked(command) else {
        return true;
    };
    let ast = AstGrep::new(blanked.as_str(), SupportLang::Bash);
    let mut overridden = false;
    let mut parse_error = false;
    find_shell_name_override_deep(ast.root(), target, &mut overridden, &mut parse_error);
    overridden || parse_error
}

/// The command with every *quoted-delimiter* heredoc body replaced by blanks,
/// or `None` when there is no such body to blank (issue #412).
///
/// A `<<'EOF'` body is literal stdin data: the shell performs no expansion in
/// it and never parses it as grammar, so its bytes cannot rebind a name in the
/// shell that feeds the heredoc. They can, however, stop tree-sitter-bash
/// parsing the enclosing command — an unbalanced `"` in a German commit message
/// (`„Messen"`) nested inside `"$(cat <<'EOF' … )"` is the reported case — and a
/// parse error is answered fail-closed, which suppressed the very masking the
/// body was eligible for.
///
/// Blanking preserves every byte offset and every newline, so the retry parses
/// the same command with only inert data neutralized. Expanding heredocs are
/// deliberately left alone: the shell *does* evaluate `$(…)` inside them, so
/// their bytes can carry a real override.
fn quoted_heredoc_bodies_blanked(command: &str) -> Option<String> {
    // Raw text, not the masked scan view. The masker calls
    // `stdin_data_sink_may_be_overridden`, which reaches this function, so
    // asking for the mask here would not terminate (#420). Using the raw text
    // is also the honest input: the question here is which bodies exist, not
    // which of them are data.
    let extracted = match extract_content_with_scan_view(
        command,
        command,
        &ExtractionLimits::structural_scan(),
    ) {
        ExtractionResult::Extracted(extracted) | ExtractionResult::Partial { extracted, .. } => {
            extracted
        }
        ExtractionResult::NoContent
        | ExtractionResult::Skipped(_)
        | ExtractionResult::Failed(_) => return None,
    };
    let mut ranges: Vec<std::ops::Range<usize>> = extracted
        .into_iter()
        .filter(|content| {
            content.quoted
                && content
                    .heredoc_type
                    .is_some_and(|kind| kind != HeredocType::HereString)
        })
        .filter_map(|content| content.content_range)
        .filter(|range| range.end <= command.len() && range.start <= range.end)
        .collect();
    if ranges.is_empty() {
        return None;
    }
    ranges.sort_by_key(|range| range.start);

    let mut out = String::with_capacity(command.len());
    let mut pos = 0usize;
    for range in ranges {
        if range.start < pos {
            continue;
        }
        out.push_str(command.get(pos..range.start)?);
        out.push_str(&mask_preserve_newlines(command.get(range.clone())?));
        pos = range.end;
    }
    out.push_str(command.get(pos..)?);
    Some(out)
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
    root: ast_grep_core::Node<'_, D>,
    target: &str,
    overridden: &mut bool,
    parse_error: &mut bool,
) {
    // An explicit stack, not recursion (see [`collect_active_heredocs`]):
    // a list nests one level per `&&`, and this walks the whole command.
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if *overridden || *parse_error {
            return;
        }
        if shell_name_override_node(&node, target, overridden, parse_error) {
            // Children reversed onto the stack, so they pop in order.
            let first_child = pending.len();
            pending.extend(node.children());
            pending[first_child..].reverse();
        }
    }
}

/// [`find_visible_shell_name_override`] for one node: set the flags it
/// proves, and answer whether to descend into its children.
fn shell_name_override_node<D: ast_grep_core::Doc>(
    node: &ast_grep_core::Node<'_, D>,
    target: &str,
    overridden: &mut bool,
    parse_error: &mut bool,
) -> bool {
    match node.kind().as_ref() {
        "ERROR" => {
            *parse_error = true;
            return false;
        }
        "function_definition" => {
            let Some(name) = node.field("name") else {
                // A function definition whose binding cannot be resolved is
                // exactly the case where proving a later bare sink is unsafe.
                *overridden = true;
                return false;
            };
            let name = name.text();
            if name.as_ref() == target || !is_static_shell_name(name.as_ref()) {
                *overridden = true;
                return false;
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
                return false;
            }
        }
        "command" => {
            let text = node.text();
            match shell_words::split(text.as_ref()) {
                Ok(tokens) => {
                    if shell_command_may_override_name(&tokens, target) {
                        *overridden = true;
                        return false;
                    }
                    // The complete simple command was resolved above. Its
                    // assignment children are temporary environment state
                    // unless the command itself is a modeled mutator; do not
                    // reclassify `PATH=/tmp printf ...` as persistent state.
                    return false;
                }
                Err(_) => {
                    // AST-valid shell that the secondary word splitter cannot
                    // resolve must never establish a data-only proof.
                    *parse_error = true;
                    *overridden = true;
                    return false;
                }
            }
        }
        _ => {}
    }
    true
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
        matches!(
            heredoc.body,
            ActiveHeredocBody::Heredoc { body_start, body_end, .. }
                if range.start >= body_start && range.end <= body_end
        ) && inert_interpreter_stdin_body(command, heredoc).is_some()
    })
}

fn inert_interpreter_stdin_body(command: &str, heredoc: &ActiveHeredoc) -> Option<Range<usize>> {
    let ActiveHeredocBody::Heredoc {
        body_start,
        body_end,
        delimiter_quoted: true,
    } = heredoc.body
    else {
        return None;
    };
    let target = extract_heredoc_target_command(command, heredoc.operator_start)?;
    (is_non_shell_interpreter_stdin_command(&target)
        && !stdin_data_sink_may_be_overridden(command, heredoc.operator_start, &target))
    .then_some(body_start..body_end)
}

/// A view for consumers asking only about OUTER shell syntax. A proven,
/// quoted non-shell interpreter body cannot contribute a shell substitution
/// or contradict the hook's shell label (#520, #523). Keep its byte offsets
/// and newlines so findings outside the body still refer to the original.
///
/// This is deliberately separate from the pattern-matching view: interpreter
/// source must still reach both the language-specific analysis and the raw
/// destructive-pattern scan, including opaque or aliased execution sinks.
#[must_use]
pub(crate) fn mask_inert_interpreter_stdin(command: &str) -> Cow<'_, str> {
    if !command.contains("<<") {
        return Cow::Borrowed(command);
    }
    let Some(heredocs) = active_heredocs(command) else {
        return Cow::Borrowed(command);
    };
    // Each proof inspects the owning command and visible executable lookup.
    // Bound their count before those scans, just as extraction bounds bodies;
    // exceeding the bound keeps all source visible to the conservative path.
    if heredocs.len() > ExtractionLimits::structural_scan().max_heredocs {
        return Cow::Borrowed(command);
    }
    let bodies: Vec<_> = heredocs
        .iter()
        .filter(|heredoc| {
            let Some(owner) = plain_heredoc_command_at(command, heredoc.operator_start) else {
                return false;
            };
            let Ok(words) = shell_words::split(&owner) else {
                return false;
            };
            let Some((program, arguments)) = words.split_first() else {
                return false;
            };
            let name = program.rsplit('/').next().unwrap_or(program);
            matches!(
                ScriptLanguage::from_command(name),
                ScriptLanguage::Python
                    | ScriptLanguage::JavaScript
                    | ScriptLanguage::Ruby
                    | ScriptLanguage::Perl
                    | ScriptLanguage::Php
            ) && (arguments.is_empty() || matches!(arguments, [arg] if arg == "-"))
        })
        .filter_map(|heredoc| inert_interpreter_stdin_body(command, heredoc))
        .collect();
    if bodies.is_empty() {
        Cow::Borrowed(command)
    } else {
        Cow::Owned(blank_ranges(command, &bodies))
    }
}

/// A quoted cat body written verbatim and immediately read by a concrete
/// interpreter. This proof supplies a language, never an allow:
/// both the language-aware checks and conservative raw-pattern scan remain.
struct WrittenHeredocInterpreter {
    operator_start: usize,
    body: Range<usize>,
    interpreter: String,
    language: ScriptLanguage,
}

/// Whether these exact bytes are written verbatim and handed to a supported
/// POSIX shell. Reuse the file and interpreter proof when evaluating redirects
/// with the complete shell body as their assignment and loop scope.
pub(crate) fn range_is_written_bash_source(command: &str, range: &Range<usize>) -> bool {
    written_heredoc_interpreter(command)
        .is_some_and(|source| source.language == ScriptLanguage::Bash && source.body == *range)
}

/// Whether this exact body is handed verbatim to the named non-shell
/// interpreter as its program. This supplies source identity for a
/// language-specific literal proof; it never masks or approves the program.
/// Other stdin consumers, unquoted bodies, and ambiguous file handoffs retain
/// the conservative raw-source analysis.
pub(crate) fn range_is_quoted_interpreter_source(
    command: &str,
    range: &Range<usize>,
    language: ScriptLanguage,
) -> bool {
    if range.start >= range.end
        || !matches!(
            language,
            ScriptLanguage::Python | ScriptLanguage::JavaScript
        )
        || !command.contains("<<")
        || command.len() > MAX_SUBSTITUTION_SOURCE_BYTES
    {
        return false;
    }
    if written_heredoc_interpreter(command)
        .is_some_and(|source| source.language == language && source.body == *range)
    {
        return true;
    }
    // A direct source proof belongs to the complete invocation, not merely
    // one receiver inside a larger workflow. A later shell could execute a
    // file the interpreter writes, and a preceding environment assignment
    // could preload code that changes its builtins. Neither supplies the
    // isolated program assumed by the language-specific literal analysis.
    let Ok(ast) = AstGrep::try_new(command, SupportLang::Bash) else {
        return false;
    };
    let root = ast.root();
    if root.get_inner_node().has_error()
        || root.children().any(|child| child.kind().as_ref() == "&")
    {
        return false;
    }
    let mut statements = root
        .children()
        .filter(|child| child.is_named() && child.kind().as_ref() != "comment");
    let Some(statement) = statements.next() else {
        return false;
    };
    if statements.next().is_some()
        || statement.kind().as_ref() != "redirected_statement"
        || !statement
            .field("body")
            .is_some_and(|body| body.kind().as_ref() == "command")
        || statement
            .children()
            .filter(ast_grep_core::Node::is_named)
            .any(|child| !matches!(child.kind().as_ref(), "command" | "heredoc_redirect"))
        || statement
            .children()
            .filter(|child| child.kind().as_ref() == "heredoc_redirect")
            .count()
            != 1
    {
        return false;
    }
    let Some(heredocs) = active_heredocs(command) else {
        return false;
    };
    if heredocs.len() > ExtractionLimits::structural_scan().max_heredocs {
        return false;
    }
    heredocs.iter().any(|heredoc| {
        let Some(mut body) = inert_interpreter_stdin_body(command, heredoc) else {
            return false;
        };
        let Some(text) = command.get(body.clone()) else {
            return false;
        };
        // Extraction excludes the newline immediately before the delimiter;
        // tree-sitter includes it. Reconcile that one syntax boundary only.
        if text.ends_with('\n') {
            body.end -= 1;
            if text.ends_with("\r\n") {
                body.end -= 1;
            }
        }
        if body != *range {
            return false;
        }
        let Some(owner) = plain_heredoc_command_at(command, heredoc.operator_start) else {
            return false;
        };
        let Ok(words) = shell_words::split(&owner) else {
            return false;
        };
        let Some((program, arguments)) = words.split_first() else {
            return false;
        };
        ScriptLanguage::from_command(program.rsplit('/').next().unwrap_or(program)) == language
            && (arguments.is_empty() || matches!(arguments, [argument] if argument == "-"))
    })
}

/// The `>` bytes that JavaScript itself parses as arrow operators in a
/// proven written script (#519). Do not exempt the whole body from redirect
/// or launcher rules: strings passed through opaque sinks can still hold
/// shell syntax, and their conservative raw-pattern evidence must survive.
pub(crate) fn written_javascript_arrow_offsets(command: &str) -> Vec<usize> {
    if !command.contains("=>") {
        return Vec::new();
    }
    let Some(source) = written_heredoc_interpreter(command) else {
        return Vec::new();
    };
    if source.language != ScriptLanguage::JavaScript {
        return Vec::new();
    }
    let Some(body) = command.get(source.body.clone()) else {
        return Vec::new();
    };
    let Ok(ast) = AstGrep::try_new(body, SupportLang::JavaScript) else {
        return Vec::new();
    };
    if ast.root().get_inner_node().has_error() {
        return Vec::new();
    }
    ast.root()
        .dfs()
        .filter(|node| node.kind().as_ref() == "=>")
        .map(|node| source.body.start + node.range().start + 1)
        .collect()
}

/// Keep the file provenance deliberately small: one plain overwrite followed
/// by one direct interpreter invocation, optionally preceded by a literal
/// mkdir. No append, transformations, extra consumers, mutable bindings,
/// wrappers, branches, pipelines or deferred execution can establish this
/// proof. In particular a later `bash file` must not borrow an earlier
/// `node file` classification merely because the filename matches.
fn written_heredoc_interpreter(command: &str) -> Option<WrittenHeredocInterpreter> {
    if !command.contains("<<") || command.len() > MAX_SUBSTITUTION_SOURCE_BYTES {
        return None;
    }
    let ast = AstGrep::try_new(command, SupportLang::Bash).ok()?;
    if ast.root().get_inner_node().has_error() {
        return None;
    }
    let mut statements = Vec::new();
    let mut pending = vec![ast.root()];
    while let Some(node) = pending.pop() {
        match node.kind().as_ref() {
            "program" | "list" => {
                if node
                    .children()
                    .any(|child| matches!(child.kind().as_ref(), "&" | "||"))
                {
                    return None;
                }
                let start = pending.len();
                pending.extend(node.children().filter(ast_grep_core::Node::is_named));
                pending[start..].reverse();
            }
            "comment" => {}
            "command" | "redirected_statement" => {
                statements.push(node);
                if statements.len() > 3 {
                    return None;
                }
            }
            _ => return None,
        }
    }
    let (writer, consumer) = match statements.as_slice() {
        [writer, consumer] => (writer, consumer),
        [setup, writer, consumer] if literal_mkdir_setup(setup) => (writer, consumer),
        _ => return None,
    };
    let (operator_start, body, destination) = literal_cat_file_write(writer)?;
    if consumer.kind().as_ref() != "command"
        || consumer
            .children()
            .filter(ast_grep_core::Node::is_named)
            .any(|child| {
                !matches!(
                    child.kind().as_ref(),
                    "command_name" | "word" | "raw_string" | "string"
                )
            })
    {
        return None;
    }
    let words = literal_script_words(consumer)?;
    let [program, path] = words.as_slice() else {
        return None;
    };
    let interpreter = program.rsplit('/').next()?;
    let language = ScriptLanguage::from_command(interpreter);
    let supported_shell = matches!(interpreter, "bash" | "sh" | "dash" | "ksh" | "zsh");
    if destination != *path
        || !(supported_shell
            || matches!(
                language,
                ScriptLanguage::Python
                    | ScriptLanguage::JavaScript
                    | ScriptLanguage::Ruby
                    | ScriptLanguage::Perl
                    | ScriptLanguage::Php
            ))
        || !trusted_literal_script_program(program)
    {
        return None;
    }
    Some(WrittenHeredocInterpreter {
        operator_start,
        body,
        interpreter: interpreter.to_string(),
        language,
    })
}

fn literal_cat_file_write<D: ast_grep_core::Doc>(
    writer: &ast_grep_core::Node<'_, D>,
) -> Option<(usize, Range<usize>, String)> {
    if writer.kind().as_ref() != "redirected_statement" {
        return None;
    }
    let owner = literal_cat_write_owner(writer)?;
    let words = literal_script_words(&owner)?;
    let [program] = words.as_slice() else {
        return None;
    };
    if owner.kind().as_ref() != "command"
        || owner
            .children()
            .filter(ast_grep_core::Node::is_named)
            .any(|child| child.kind().as_ref() != "command_name")
        || !matches!(program.as_str(), "cat" | "/bin/cat" | "/usr/bin/cat")
        || !trusted_literal_script_program(program)
    {
        return None;
    }
    let mut redirects = Vec::new();
    let mut heredoc = None;
    for child in writer.children().filter(ast_grep_core::Node::is_named) {
        match child.kind().as_ref() {
            "command" | "list" => {}
            "file_redirect" => redirects.push(child),
            "heredoc_redirect" if heredoc.is_none() => heredoc = Some(child),
            _ => return None,
        }
    }
    let heredoc = heredoc?;
    let text = heredoc.text();
    let operator_offset = text.find("<<")?;
    let mut body = None;
    let mut quoted = false;
    for child in heredoc.children().filter(ast_grep_core::Node::is_named) {
        match child.kind().as_ref() {
            "heredoc_start" => {
                quoted = heredoc_delimiter_is_quoted(
                    text.as_ref(),
                    operator_offset,
                    child.range().end.checked_sub(heredoc.range().start)?,
                    child.text().as_ref(),
                );
            }
            "heredoc_body" => {
                // Extraction excludes the newline immediately before the
                // terminator. Use the same source boundary for exact identity.
                let mut range = child.range();
                let text = child.text();
                if text.ends_with('\n') {
                    range.end -= 1;
                    if text.ends_with("\r\n") {
                        range.end -= 1;
                    }
                }
                body = Some(range);
            }
            "heredoc_end" => {}
            "file_descriptor" if child.text().as_ref() == "0" => {}
            "file_redirect" => redirects.push(child),
            _ => return None,
        }
    }
    if !quoted || redirects.len() != 1 {
        return None;
    }
    Some((
        heredoc.range().start + operator_offset,
        body?,
        literal_overwrite_destination(&redirects[0])?,
    ))
}

fn literal_cat_write_owner<'a, D: ast_grep_core::Doc>(
    writer: &ast_grep_core::Node<'a, D>,
) -> Option<ast_grep_core::Node<'a, D>> {
    let body = writer.field("body")?;
    if body.kind().as_ref() == "command" {
        return Some(body);
    }
    // Bash's grammar attaches `mkdir ... && cat >file <<EOF` redirects
    // to the list. Only its final cat consumes the heredoc. Admit this exact
    // setup shape; a grouped, branching or longer command is not a proof.
    if body.kind().as_ref() != "list" {
        return None;
    }
    let children: Vec<_> = body.children().collect();
    let [setup, operator, owner] = children.as_slice() else {
        return None;
    };
    (literal_mkdir_setup(setup)
        && operator.kind().as_ref() == "&&"
        && owner.kind().as_ref() == "command")
        .then(|| owner.clone())
}

fn literal_overwrite_destination<D: ast_grep_core::Doc>(
    redirect: &ast_grep_core::Node<'_, D>,
) -> Option<String> {
    let mut destination = None;
    let mut overwrite = false;
    for child in redirect.children() {
        match child.kind().as_ref() {
            ">" | ">|" => overwrite = true,
            "file_descriptor" if child.text().as_ref() == "1" => {}
            "word" | "raw_string" | "string" if destination.is_none() => {
                let words = literal_script_words(&child)?;
                let [path] = words.as_slice() else {
                    return None;
                };
                if !is_plain_file_path(path) || path == "/dev/null" {
                    return None;
                }
                destination = Some(path.clone());
            }
            _ => return None,
        }
    }
    overwrite.then_some(destination).flatten()
}

fn literal_script_words<D: ast_grep_core::Doc>(
    node: &ast_grep_core::Node<'_, D>,
) -> Option<Vec<String>> {
    let text = node.text();
    if text.contains(['$', '`', '\\', '*', '?', '[', '{', '~']) {
        return None;
    }
    shell_words::split(text.as_ref()).ok()
}

fn trusted_literal_script_program(program: &str) -> bool {
    let basename = program.rsplit('/').next().unwrap_or(program);
    if program.contains('/') {
        is_trusted_os_data_sink_path(program, basename)
    } else {
        std::env::var_os(format!("BASH_FUNC_{basename}%%")).is_none()
    }
}

fn literal_mkdir_setup<D: ast_grep_core::Doc>(node: &ast_grep_core::Node<'_, D>) -> bool {
    if node.kind().as_ref() != "command" {
        return false;
    }
    let Some(words) = literal_script_words(node) else {
        return false;
    };
    let Some((program, arguments)) = words.split_first() else {
        return false;
    };
    matches!(program.as_str(), "mkdir" | "/bin/mkdir" | "/usr/bin/mkdir")
        && trusted_literal_script_program(program)
        && !arguments.is_empty()
        && arguments
            .iter()
            .all(|arg| arg == "-p" || arg == "--" || is_plain_file_path(arg))
        && node
            .children()
            .filter(ast_grep_core::Node::is_named)
            .all(|child| {
                matches!(
                    child.kind().as_ref(),
                    "command_name" | "word" | "raw_string" | "string"
                )
            })
}

/// The plain command owning one heredoc, with no other redirection, pipeline
/// or trailing argument hidden under the redirection node. Callers use this
/// narrow shape to prove how stdin is consumed; an interpreter running `-c`
/// or a script file can hand stdin to a shell and is not such a proof.
pub(crate) fn plain_heredoc_command_at(command: &str, operator_start: usize) -> Option<String> {
    if command.len() > MAX_SUBSTITUTION_SOURCE_BYTES
        || longest_pipeline_stages(command) > MAX_PARSED_PIPELINE_STAGES
    {
        return None;
    }
    let ast = AstGrep::try_new(command, SupportLang::Bash).ok()?;
    if ast.root().get_inner_node().has_error() {
        return None;
    }
    let mut pending = vec![ast.root()];
    while let Some(node) = pending.pop() {
        if node.kind().as_ref() == "heredoc_redirect"
            && node
                .text()
                .find("<<")
                .map(|offset| node.range().start + offset)
                == Some(operator_start)
        {
            if node
                .children()
                .filter(ast_grep_core::Node::is_named)
                .any(|child| {
                    !matches!(
                        child.kind().as_ref(),
                        "heredoc_start" | "heredoc_body" | "heredoc_end"
                    )
                })
            {
                return None;
            }
            let statement = node.parent()?;
            if statement.kind().as_ref() != "redirected_statement"
                || statement
                    .children()
                    .filter(ast_grep_core::Node::is_named)
                    .any(|child| !matches!(child.kind().as_ref(), "command" | "heredoc_redirect"))
                || statement
                    .children()
                    .filter(|child| child.kind().as_ref() == "heredoc_redirect")
                    .count()
                    != 1
            {
                return None;
            }
            return statement
                .children()
                .find(|child| child.kind().as_ref() == "command")
                .map(|owner| owner.text().to_string());
        }
        pending.extend(node.children());
    }
    None
}

/// Whether the command owning the heredoc or here-string at `heredoc_start`
/// reads its PROGRAM from stdin: `awk -f -`, `sed -f /dev/stdin`,
/// `gawk --file=-`. awk and sed are data sinks for their input, but a program
/// read from stdin runs — awk's `system()` and sed's `e` start shell
/// commands — so such a body is code, quoted delimiter or not. Scoped to the
/// operator's own line, like [`is_git_stdin_data_sink`].
fn stdin_is_the_program(command: &str, heredoc_start: usize) -> bool {
    let prefix = &command[..heredoc_start.min(command.len())];
    let line_start = prefix.rfind(['\n', '\r']).map_or(0, |i| i + 1);
    let before = prefix[line_start..].trim_end();
    if before.is_empty() || !before.contains('f') {
        return false;
    }
    let mut tokens = tokenize_backwards(before);
    tokens.reverse();
    let mut idx = 0;
    while tokens.get(idx).is_some_and(|token| {
        is_shell_env_assignment(token) || SHELL_WRAPPER_COMMANDS.contains(&token.as_str())
    }) {
        idx += 1;
    }
    let Some(program) = tokens.get(idx) else {
        return false;
    };
    let program = dequoted_executable_word(program);
    let program = program.rsplit('/').next().unwrap_or(&program);
    if !matches!(
        program,
        "awk" | "gawk" | "mawk" | "nawk" | "busybox" | "sed" | "gsed"
    ) {
        return false;
    }
    let stdin = |path: &str| matches!(path, "-" | "/dev/stdin" | "/dev/fd/0" | "/proc/self/fd/0");
    let args: Vec<std::borrow::Cow<'_, str>> = tokens[idx + 1..]
        .iter()
        .map(|token| crate::normalize::decode_posix_syntax_token(token))
        .collect();
    args.iter().enumerate().any(|(at, arg)| {
        let arg = arg.as_ref();
        if matches!(arg, "-f" | "--file") {
            return args.get(at + 1).is_some_and(|next| stdin(next));
        }
        arg.strip_prefix("--file=")
            .or_else(|| arg.strip_prefix("-f"))
            .is_some_and(stdin)
            // A short-option cluster ending in `f` takes the next word.
            || (arg.len() > 2
                && arg.starts_with('-')
                && !arg.starts_with("--")
                && arg.ends_with('f')
                && args.get(at + 1).is_some_and(|next| stdin(next)))
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
/// `tokenize_backwards` additionally stops at shell separators (`| ; & ( )`),
/// so it never reads tokens across a command boundary; quoted args (e.g. a
/// `-m "…-F -…"` message) are single tokens and cannot be mistaken for real flags.
fn is_git_stdin_data_sink(command: &str, heredoc_start: usize) -> bool {
    if heredoc_start == 0 {
        return false;
    }
    // A heredoc operator binds to the simple command on its OWN physical line, so
    // only that line can own this heredoc. Bounding the scan to the current line
    // is essential for soundness: `tokenize_backwards` stops at `| ; & ( )` but
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
    let accepts_file_stdin = matches!(subcommand, "commit" | "tag" | "notes" | "merge");
    let accepts_plain_stdin = matches!(subcommand, "hash-object" | "update-index");
    // Short boolean flags that may be glued in front of `F` (`-aF -`, `-sF -`).
    // Only value-less flags qualify: `-cF -` is `-c F` (reuse the message of
    // commit `F`), so a value-taking letter before `F` disqualifies the token.
    let glueable_short_flags = match subcommand {
        "commit" => "aeinopqsv",
        "tag" => "afs",
        "merge" => "enqv",
        _ => "",
    };
    // `git apply` reads the patch itself from stdin when no file operand (or
    // `-`) is given, and a unified-diff body is data in every mode (--cached,
    // --check, --index, worktree): git parses it as a patch, never executes
    // it (#374). One exception keeps the fail-closed path: `--unsafe-paths`
    // lets the patch govern paths outside the working tree, so that body
    // stays visible for scanning.
    if subcommand == "apply" {
        return !subcommand_args.iter().any(|arg| arg == "--unsafe-paths");
    }
    let next_is_stdin = |i: usize| {
        subcommand_args
            .get(i + 1)
            .is_some_and(|next| is_stdin_file_operand(next))
    };
    for (i, arg) in subcommand_args.iter().enumerate() {
        match arg.as_str() {
            // `-F -` / `--file -`: message read from stdin (commit/tag/notes/merge).
            "-F" | "--file" if accepts_file_stdin => {
                if next_is_stdin(i) {
                    return true;
                }
            }
            // Blob/index/object content from stdin (NOT --stdin-paths).
            "--stdin" if accepts_plain_stdin => return true,
            _ if accepts_file_stdin => {
                // Glued / `=` forms: `-F-`, `--file=-`, `--file=/dev/stdin`.
                if let Some(operand) = arg.strip_prefix("--file=") {
                    if is_stdin_file_operand(operand) {
                        return true;
                    }
                    continue;
                }
                // `-aF -` / `-sF-`: boolean short flags glued before `F`.
                let Some(short) = arg.strip_prefix('-') else {
                    continue;
                };
                if short.starts_with('-') {
                    continue;
                }
                let Some(f_at) = short.find('F') else {
                    continue;
                };
                if !short[..f_at]
                    .chars()
                    .all(|flag| glueable_short_flags.contains(flag))
                {
                    continue;
                }
                let glued_operand = &short[f_at + 1..];
                if glued_operand.is_empty() {
                    if next_is_stdin(i) {
                        return true;
                    }
                } else if is_stdin_file_operand(glued_operand) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// Whether a `-F`/`--file`-style operand names the process's own stdin — the
/// conventional `-` plus the device-path spellings that open the same
/// descriptor. Every one hands the heredoc body to the program as data.
fn is_stdin_file_operand(operand: &str) -> bool {
    matches!(
        operand,
        "-" | "/dev/stdin" | "/dev/fd/0" | "/proc/self/fd/0"
    )
}

/// Check whether the heredoc at `heredoc_start` feeds a `gh` built-in through
/// one of its documented read-text-from-stdin operands: `--body-file -` /
/// `-F -` (issue/pr comment, create, edit, …), `--notes-file -` (release
/// create/edit), or `gh api --input -` (the request body). `gh` never
/// executes stdin as shell, and `gh alias set` refuses to shadow a built-in
/// command, so the receiver of the body is the built-in itself (#393).
///
/// `gh api` is scoped to `--input` only: there `-F` is `--field`, a typed
/// request field, and `-F -` is not a stdin contract at all.
fn is_gh_stdin_data_sink(command: &str, heredoc_start: usize) -> bool {
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
    if program.rsplit('/').next().unwrap_or(program) != "gh" {
        return false;
    }
    let Some(subcommand) = tokens.get(idx + 1) else {
        return false;
    };
    let args = &tokens[idx + 2..];
    let stdin_flags: &[&str] = match subcommand.as_str() {
        "api" => &["--input"],
        "issue" | "pr" | "release" => &["--body-file", "-F", "--notes-file"],
        _ => return false,
    };
    args.iter().enumerate().any(|(i, arg)| {
        if stdin_flags.contains(&arg.as_str()) {
            return args
                .get(i + 1)
                .is_some_and(|next| is_stdin_file_operand(next));
        }
        stdin_flags.iter().any(|flag| {
            flag.starts_with("--")
                && arg
                    .strip_prefix(flag)
                    .and_then(|rest| rest.strip_prefix('='))
                    .is_some_and(is_stdin_file_operand)
        })
    })
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
        "commit" | "tag" | "notes" | "merge" | "hash-object" | "update-index" | "apply"
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
/// friends, `gh … --body-file -`, `spx session handoff`). Such bodies are
/// consumed as data (a commit message, an issue comment, a handoff
/// document), never executed as shell (#277, #393).
pub(crate) fn is_structured_stdin_data_sink(command: &str, heredoc_start: usize) -> bool {
    is_git_stdin_data_sink(command, heredoc_start)
        || is_gh_stdin_data_sink(command, heredoc_start)
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

/// Mask the data of heredoc bodies whose target consumes stdin as data,
/// keeping every byte the outer shell itself executes.
///
/// A quoted POSIX heredoc delimiter suppresses expansion in the outer shell,
/// so command-substitution analysis must not treat literal `$()` text passed
/// to `cat`, `tee`, or another data sink as executable; such a body is masked
/// whole. An unquoted delimiter makes the shell expand the body before the
/// data sink runs, so its `$(…)`, backquoted and arithmetic spans stay
/// verbatim; the text around them is masked only when the sink's output
/// provably stays put (the terminal, a plain file, read-only text tools), and
/// is then as inert as a quoted body's (`cat <<EOF > notes.md` documenting
/// `watch '…'` runs no `watch`). Any other unquoted body, and one whose
/// substitutions cannot be bounded, stays whole. Shell/interpreter targets
/// are left intact because they may execute the body after receiving it; a
/// data body whose output reaches one is judged separately
/// (`data_heredoc_bodies_whose_output_may_run`).
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

    // A body written to a file that the same command then runs is code, not
    // data: `tee x.sh <<EOF … EOF` followed by `sh x.sh`.
    let mut output_executed: Option<bool> = None;
    let bodies: Vec<Range<usize>> = active_heredocs
        .iter()
        .filter_map(|heredoc| match heredoc.body {
            ActiveHeredocBody::Heredoc {
                body_start,
                body_end,
                ..
            } => Some(body_start..body_end),
            ActiveHeredocBody::HereString => None,
        })
        .collect();
    // Where each command's output goes, when the parse tree did not prove
    // it: decided once, from the text outside every body.
    let mut unproven_output: Option<HeredocOutput> = None;
    let mut output_of = |heredoc: &ActiveHeredoc| -> HeredocOutput {
        heredoc.output.unwrap_or_else(|| {
            *unproven_output.get_or_insert_with(|| {
                if command_may_run_heredoc_output(&blank_ranges(command, &bodies)) {
                    HeredocOutput::Executes
                } else {
                    HeredocOutput::Escapes
                }
            })
        })
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
                && !stdin_is_the_program(command, heredoc_start)
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
        // For the expansion-aware view, the spans of an unquoted body the shell
        // runs while reading it stay verbatim (`None`: they cannot be bounded,
        // so the body stays whole). The full mask erases them too; its callers
        // judge substitutions from the expansion-aware view instead.
        //
        // The prose around those spans is only data when the target's output
        // provably stays put: the terminal, a plain file, read-only text
        // tools. Any other unquoted body stays whole in this view, as in
        // v0.15.1: `cat <<EOF 2>&1 | sh`, `(cat <<EOF) | sh`, `cat <<EOF | ssh
        // h` and `x=$(cat <<EOF …)` run or may run the text. (A body whose
        // output reaches a program that runs it is also judged as commands,
        // quoted or not, through [`data_heredoc_bodies_whose_output_may_run`];
        // the views keep their masks so its quotes cannot regroup the text
        // around it.)
        let keep_spans = if require_quoted_delimiter && !delimiter_quoted {
            if output_of(&active_heredoc) == HeredocOutput::Contained {
                active_heredoc.live_spans.clone()
            } else {
                None
            }
        } else {
            Some(Vec::new())
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
            && !stdin_is_the_program(command, heredoc_start)
            && (target_cmd.as_ref().is_some_and(|cmd| {
                is_non_executing_heredoc_command(cmd) || is_interpreter_source_heredoc_command(cmd)
            }) || is_structured_stdin_data_sink(command, heredoc_start)
                || (delimiter_quoted
                    && target_cmd
                        .as_deref()
                        .is_some_and(is_noop_stdin_discarding_command)))
            && !*output_executed.get_or_insert_with(|| written_file_is_executed(command, &bodies));
        let should_mask = target_is_data_sink && keep_spans.is_some();

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
            let mut cursor = body_start;
            // Spans are sorted and disjoint; clamping keeps every kept byte
            // verbatim even if that ever stopped holding. Around kept spans
            // the data is filled with `_` rather than blanks, so a
            // substitution in the middle of a line of prose is not moved to
            // the start of a word, where it would read as a command name.
            let spans = keep_spans.as_deref().unwrap_or_default();
            let fill: fn(&str) -> String = if spans.is_empty() {
                mask_preserve_newlines
            } else {
                mask_preserve_whitespace
            };
            for span in spans {
                let start = span.start.clamp(cursor, body_end);
                let end = span.end.clamp(start, body_end);
                result.push_str(&fill(&command[cursor..start]));
                result.push_str(&command[start..end]);
                cursor = end;
            }
            result.push_str(&fill(&command[cursor..body_end]));
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

/// The bodies of data-sink heredocs (`cat`, `tee`, `grep`, … — targets the
/// masks treat as data) whose command's output reaches a program that may
/// run it: `cat <<'EOF' | ssh host`, `cat <<EOF 2>&1 | sh`, `(cat <<'EOF') |
/// sh`, `tee >(sh) <<'EOF'`, `eval "$(cat <<'EOF' …)"`. The caller judges each
/// one as commands, whatever its delimiter's quoting. Interpreter targets
/// (`python3 - <<'EOF' | sh`) are left out: their output is not their body.
pub(crate) fn data_heredoc_bodies_whose_output_may_run(command: &str) -> Vec<Range<usize>> {
    if !command.contains("<<") {
        return Vec::new();
    }
    let Some(heredocs) = active_heredocs(command) else {
        return Vec::new();
    };
    let bodies: Vec<Range<usize>> = heredocs
        .iter()
        .filter_map(|heredoc| match heredoc.body {
            ActiveHeredocBody::Heredoc {
                body_start,
                body_end,
                ..
            } => Some(body_start..body_end),
            ActiveHeredocBody::HereString => None,
        })
        .collect();
    let mut unproven_runs: Option<bool> = None;
    let mut found = Vec::new();
    for heredoc in &heredocs {
        let ActiveHeredocBody::Heredoc {
            body_start,
            body_end,
            ..
        } = heredoc.body
        else {
            continue;
        };
        if body_start >= body_end
            || !extract_heredoc_target_command(command, heredoc.operator_start)
                .as_deref()
                .is_some_and(is_non_executing_heredoc_command)
        {
            continue;
        }
        let runs = match heredoc.output {
            Some(output) => output == HeredocOutput::Executes,
            None => *unproven_runs.get_or_insert_with(|| {
                command_may_run_heredoc_output(&blank_ranges(command, &bodies))
            }),
        };
        if runs {
            found.push(body_start..body_end);
        }
    }
    found
}

/// Preserve the association between a body and its input operator. The
/// evaluator needs the operator's owning command to distinguish a remote
/// script from a local command that happens to follow an ssh invocation.
pub(crate) fn heredoc_bodies_with_operators(command: &str) -> Vec<(Range<usize>, usize)> {
    active_heredocs(command)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|heredoc| {
            let body = match heredoc.body {
                ActiveHeredocBody::Heredoc {
                    body_start,
                    body_end,
                    ..
                } => body_start..body_end,
                ActiveHeredocBody::HereString => {
                    let (start, end) =
                        find_herestring_content_bounds(command, heredoc.operator_start + 3)?;
                    start..end
                }
            };
            Some((body, heredoc.operator_start))
        })
        .collect()
}

/// The quoted body belonging to this exact operator. This retains source
/// identity when a pipeline consumer supplies the body's interpreter language;
/// identical text in another heredoc cannot establish that relationship.
pub(crate) fn quoted_heredoc_body_at(command: &str, operator_start: usize) -> Option<Range<usize>> {
    active_heredocs(command)?
        .into_iter()
        .find_map(|heredoc| match heredoc.body {
            ActiveHeredocBody::Heredoc {
                body_start,
                body_end,
                delimiter_quoted: true,
            } if heredoc.operator_start == operator_start => Some(body_start..body_end),
            ActiveHeredocBody::HereString | ActiveHeredocBody::Heredoc { .. } => None,
        })
}

/// `command` with every byte inside `ranges` (other than newlines) blanked.
fn blank_ranges(command: &str, ranges: &[Range<usize>]) -> String {
    let mut outside = command.as_bytes().to_vec();
    for range in ranges {
        if let Some(bytes) = outside.get_mut(range.clone()) {
            for byte in bytes.iter_mut().filter(|byte| **byte != b'\n') {
                *byte = b' ';
            }
        }
    }
    // A body range holds whole UTF-8 sequences, so blanking it byte by byte
    // leaves valid UTF-8; keep the raw text if that ever stopped holding.
    String::from_utf8(outside).unwrap_or_else(|_| command.to_string())
}

/// A program that runs its operands or its standard input as code: a shell,
/// `source`/`.`/`eval`/`exec`, `xargs`, or a script interpreter.
fn runs_its_input_as_code(program: &str) -> bool {
    matches!(
        program,
        "sh" | "bash"
            | "zsh"
            | "dash"
            | "ksh"
            | "mksh"
            | "fish"
            | "source"
            | "."
            | "eval"
            | "exec"
            | "xargs"
            | "busybox"
    ) || ["python", "perl", "ruby", "node", "php", "lua"]
        .iter()
        .any(|prefix| program.starts_with(prefix))
}

/// Whether `command`, read with its heredoc `bodies` blanked, writes a file
/// (`> f`, `>> f`, `>| f`, `tee f`) and names that file again anywhere a
/// program may run or read it as code: `sh x.sh`, `./x.sh`, `. x.sh`,
/// `sh -c "$(cat x.sh)"`, `cat x.sh | sh`, `bash < x.sh`. A mention by a
/// program that only reads or files the text away (`git add notes.md`,
/// `cat notes.md`) is not one, unless that segment pipes into another. Names
/// are compared by basename at word boundaries. A proven synchronous reader
/// before a file's first write cannot consume the newly written body (#525).
/// All other mentions retain the conservative treatment, including readers
/// inside loops and commands whose execution may be deferred.
fn written_file_is_executed(command: &str, bodies: &[Range<usize>]) -> bool {
    use crate::normalize::NormalizeTokenKind;
    /// Programs whose mention of a file neither runs it nor hands it on.
    const READERS: &[&str] = &[
        "git", "cat", "head", "tail", "less", "more", "wc", "grep", "rg", "diff", "ls", "stat",
        "file", "echo", "printf", "rm", "chmod", "touch", "open", "code", "vim", "vi", "nano",
        "gh", "jq", "yq", "sort", "uniq", "cut", "test", "[", "mkdir", "tee",
    ];
    if !command.contains('>') && !command.contains("tee") && !command.contains("of=") {
        return false;
    }
    let mut outside = command.as_bytes().to_vec();
    for body in bodies {
        if let Some(bytes) = outside.get_mut(body.clone()) {
            for byte in bytes.iter_mut().filter(|byte| **byte != b'\n') {
                *byte = b' ';
            }
        }
    }
    let Ok(outside) = String::from_utf8(outside) else {
        return true;
    };
    let ordered_readers = ordered_file_reader_ranges(command, &outside);
    let tokens = crate::normalize::tokenize_for_normalization(&outside);
    let name_of = |word: &str| -> String {
        let word = dequoted_executable_word(word);
        word.rsplit('/').next().unwrap_or(&word).to_string()
    };

    // Per token: the written file it names as a write target, and the
    // command word of its segment plus whether that segment pipes into a
    // shell or interpreter (`cat x.sh | bash`, not `… | wc -c`).
    let mut written: Vec<(String, usize)> = Vec::new();
    let mut write_targets = vec![false; tokens.len()];
    let mut process_substitution_words = vec![false; tokens.len()];
    let mut executable_tokens = vec![false; tokens.len()];
    let mut segment_command: Vec<Option<String>> = vec![None; tokens.len()];
    let mut piped = vec![false; tokens.len()];
    // (first token, end token, program, pipes on) of each segment.
    let mut segments: Vec<(usize, usize, Option<String>, bool)> = Vec::new();
    let mut segment_start = 0usize;
    let mut command_word: Option<String> = None;
    let mut pending_target = false;
    for (index, token) in tokens.iter().enumerate() {
        let Some(text) = token.text(&outside) else {
            continue;
        };
        if token.kind != NormalizeTokenKind::Word {
            // `>|` and `>&` arrive split at the separator byte.
            if pending_target && matches!(text, "|" | "&") {
                continue;
            }
            pending_target = false;
            segments.push((segment_start, index, command_word.take(), text == "|"));
            segment_start = index + 1;
            continue;
        }
        if !process_substitution_bodies(text).is_empty() {
            // A process substitution names a generated descriptor, not a
            // literal written file, including after `>` or as a tee operand.
            // Its nested command is checked independently as a consumer below.
            process_substitution_words[index] = true;
            pending_target = false;
            continue;
        }
        if std::mem::take(&mut pending_target) {
            written.push((name_of(text), segment_start));
            write_targets[index] = true;
            continue;
        }
        if let Some(at) = text.find('>') {
            let target = text[at..].trim_start_matches(['>', '|', '&']);
            if target.is_empty() {
                pending_target = true;
            } else {
                written.push((name_of(target), segment_start));
                write_targets[index] = true;
            }
            continue;
        }
        if command_word.as_deref() == Some("dd")
            && let Some(target) = text.strip_prefix("of=")
        {
            written.push((name_of(target), segment_start));
            write_targets[index] = true;
            continue;
        }
        match command_word.as_deref() {
            None => {
                if !is_shell_env_assignment(text)
                    && !matches!(
                        text,
                        "sudo" | "env" | "nohup" | "exec" | "command" | "time" | "nice" | "builtin"
                    )
                {
                    command_word = Some(name_of(text));
                    executable_tokens[index] = true;
                }
            }
            Some("tee") if !text.starts_with('-') => {
                written.push((name_of(text), segment_start));
                write_targets[index] = true;
            }
            Some(_) => {}
        }
    }
    segments.push((segment_start, tokens.len(), command_word, false));
    let mut downstream_runs = false;
    for (start, end, program, pipes_on) in segments.iter().rev() {
        // A reader can hand a file through several filters before the shell
        // receives it. Propagate that reachability backwards in one pass;
        // checking only the immediate next stage misses `cat f | grep . | sh`.
        let feeds_interpreter = *pipes_on && downstream_runs;
        for index in *start..*end {
            segment_command[index].clone_from(program);
            piped[index] = feeds_interpreter;
        }
        downstream_runs = feeds_interpreter
            || program
                .as_deref()
                .is_some_and(|program| runs_its_input_as_code(program) || program == "ssh");
    }
    written.retain(|(name, _)| !name.is_empty() && name != "-");
    written.sort_unstable();
    // Sorting also orders each file's writes, so retain its earliest command.
    written.dedup_by(|later, earlier| later.0 == earlier.0);
    if written.is_empty() {
        return false;
    }
    // Each name is searched in every word; past a handful of distinct files
    // that would grow with the square of the command, so stay visible.
    if written.len() > 32 {
        return true;
    }
    let data_consumers = literal_file_data_consumers(command, &outside);
    // A copy consumes bytes as data, but does not make them permanently
    // inert. Follow literal destination aliases before judging all consumers,
    // including copies under a different basename and repeated copies. Keep
    // the original name too: a destination may name an existing directory.
    // The fixed point is bounded by the same 32-file limit as the scan.
    for round in 0..32 {
        let mut changed = false;
        for consumer in &data_consumers {
            let Some(transfer) = &consumer.transfer else {
                continue;
            };
            let Some(first_write) = written
                .iter()
                .filter(|(name, _)| transfer.sources.contains(name))
                .map(|(_, first_write)| *first_write)
                .min()
            else {
                continue;
            };
            let Some(destination) = &transfer.destination else {
                continue;
            };
            if let Some((_, existing_write)) =
                written.iter_mut().find(|(name, _)| name == destination)
            {
                if first_write < *existing_write {
                    *existing_write = first_write;
                    changed = true;
                }
            } else {
                if written.len() >= 32 {
                    return true;
                }
                written.push((destination.clone(), first_write));
                changed = true;
            }
        }
        if !changed {
            break;
        }
        if round == 31 {
            return true;
        }
    }
    let boundary = |byte: Option<&u8>| {
        byte.is_none_or(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+' | b'@'))
        })
    };
    let mentions_name = |text: &str, name: &str| {
        text.match_indices(name).any(|(at, _)| {
            boundary(
                at.checked_sub(1)
                    .and_then(|before| text.as_bytes().get(before)),
            ) && boundary(text.as_bytes().get(at + name.len()))
        })
    };
    tokens.iter().enumerate().any(|(index, token)| {
        if token.kind != NormalizeTokenKind::Word {
            return false;
        }
        let Some(text) = token.text(&outside) else {
            return false;
        };
        // The tokenizer keeps a process substitution inside its outer word.
        // Its commands do not inherit cat/tee's data-only argv contract.
        // The quote-aware scan above keeps literal `<(...)` prose inert.
        let has_process_substitution = process_substitution_words[index];
        if write_targets[index] && !has_process_substitution {
            return false;
        }
        // A name the shell computes may be the file: any such word run by a
        // shell or interpreter (`sh $(ls *.sh)`, `bash ./*.sh`), and a
        // command word computed the same way (`$f`, `./*.sh`).
        let computed = text.contains(['$', '`', '*', '?', '[']);
        let program = segment_command[index].as_deref();
        let command_word = program.is_some_and(|word| word == name_of(text));
        let interpreted =
            program.is_some_and(|program| runs_its_input_as_code(program) || program == "ssh");
        if computed
            && (has_process_substitution
                || (!is_shell_env_assignment(text) && (command_word || interpreted)))
        {
            return true;
        }
        let synchronous_reader = ordered_readers.iter().any(|range| {
            range.start <= token.byte_range.start && token.byte_range.end <= range.end
        });
        let mentions = written.iter().any(|(name, first_write)| {
            if synchronous_reader && index < *first_write {
                return false;
            }
            if data_consumers.iter().any(|consumer| {
                consumer.range.start <= token.byte_range.start
                    && token.byte_range.end <= consumer.range.end
                    && !consumer.command_names.contains(&name.as_str())
            }) {
                return false;
            }
            mentions_name(text, name)
        });
        mentions
            && ((!data_consumers.is_empty() && executable_tokens[index])
                || has_process_substitution
                || piped[index]
                || !segment_command[index]
                    .as_deref()
                    .is_some_and(|word| READERS.contains(&word)))
    })
}

/// A file transfer proves only that this command copies its source bytes.
/// Destination aliases must continue through the ordinary execution scan.
struct LiteralFileTransfer {
    sources: Vec<String>,
    destination: Option<String>,
}

struct ProvenFileDataConsumer {
    range: Range<usize>,
    // A transferred file named `git`/`scp` must not borrow a data-argument
    // exemption when those names themselves are subsequently executed.
    command_names: &'static [&'static str],
    transfer: Option<LiteralFileTransfer>,
}

/// A timed-out optional proof must not leave room for another live parser.
/// Releasing this permit after analysis also covers unwind and spawn failure.
struct FileDataProofPermit(&'static AtomicBool);

impl Drop for FileDataProofPermit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// The parser and every nested remote-command proof run off the hook thread.
/// All failure paths discard the exemption and keep the existing raw scan.
fn run_file_data_proof(
    busy: &'static AtomicBool,
    started: Instant,
    budget: Duration,
    analyze: impl FnOnce() -> Vec<ProvenFileDataConsumer> + Send + 'static,
) -> Vec<ProvenFileDataConsumer> {
    if started.elapsed() >= budget
        || busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
    {
        return Vec::new();
    }
    let permit = FileDataProofPermit(busy);
    let (sender, receiver) = mpsc::sync_channel(1);
    if std::thread::Builder::new()
        .name("dcg-file-data-proof".into())
        .spawn(move || {
            let result = if started.elapsed() < budget {
                analyze()
            } else {
                Vec::new()
            };
            // No parser remains after analysis returns. Release before send
            // so the next sequential proof does not spuriously observe busy.
            // A buffered send cannot strand a timed-out worker, and joining
            // here would put the hook back under the worker's wall clock.
            drop(permit);
            let _ = sender.send(result);
        })
        .is_err()
    {
        return Vec::new();
    }
    let Some(remaining) = budget.checked_sub(started.elapsed()) else {
        return Vec::new();
    };
    receiver
        .recv_timeout(remaining)
        .ok()
        .filter(|_| started.elapsed() < budget)
        .unwrap_or_default()
}

/// Narrow per-command data contracts for #543. A bare program-name exemption
/// for ssh would hide remote shell execution; one for scp would lose renamed
/// copies, custom transport programs, and configuration-driven execution.
/// Prove the literal argv and command ancestry instead. Pipelines, substituted
/// output, redirections, functions, wrappers and mutable shell bindings retain
/// the old conservative treatment.
fn literal_file_data_consumers(command: &str, outside: &str) -> Vec<ProvenFileDataConsumer> {
    if (!outside.contains("scp") && !outside.contains("ssh"))
        || command.len() > MAX_SUBSTITUTION_SOURCE_BYTES
    {
        return Vec::new();
    }
    // Match the existing AST timeout's only-raise convention. Keep the cheap
    // trigger and byte cap outside the worker, and include input ownership and
    // thread startup in the same deadline. One process-wide slot applies in
    // tests too; a busy or expired optional proof simply supplies no waiver.
    static BUSY: AtomicBool = AtomicBool::new(false);
    let budget = crate::ast_matcher::protected_scan_budget();
    let started = Instant::now();
    let command = command.to_owned();
    let outside = outside.to_owned();
    run_file_data_proof(&BUSY, started, budget, move || {
        literal_file_data_consumers_inner(&command, &outside, started, budget)
    })
}

fn literal_file_data_consumers_inner(
    command: &str,
    outside: &str,
    started: Instant,
    budget: Duration,
) -> Vec<ProvenFileDataConsumer> {
    if started.elapsed() >= budget {
        return Vec::new();
    }
    let Ok(ast) = AstGrep::try_new(outside, SupportLang::Bash) else {
        return Vec::new();
    };
    if started.elapsed() >= budget || ast.root().get_inner_node().has_error() {
        return Vec::new();
    }
    let mut consumers = Vec::new();
    let mut candidates = 0usize;
    'commands: for node in ast.root().dfs() {
        if started.elapsed() >= budget {
            return Vec::new();
        }
        if node.kind().as_ref() != "command" {
            continue;
        }
        let Some(name) = node
            .children()
            .find(|child| child.kind().as_ref() == "command_name")
        else {
            continue;
        };
        let name_text = name.text();
        let name = dequoted_executable_word(name_text.as_ref());
        let basename = name.rsplit('/').next().unwrap_or(&name);
        if !matches!(basename, "scp" | "ssh" | "git") {
            continue;
        }
        candidates += 1;
        if candidates > 32 {
            return Vec::new();
        }
        let mut ancestor = node.parent();
        while let Some(parent) = ancestor {
            if !matches!(parent.kind().as_ref(), "program" | "list")
                || parent.children().any(|child| child.kind().as_ref() == "&")
            {
                continue 'commands;
            }
            ancestor = parent.parent();
        }
        if node
            .children()
            .filter(ast_grep_core::Node::is_named)
            .any(|child| {
                !matches!(
                    child.kind().as_ref(),
                    "command_name" | "word" | "raw_string" | "string"
                )
            })
        {
            continue;
        }
        let Some(words) = literal_script_words(&node) else {
            continue;
        };
        let Some((program, arguments)) = words.split_first() else {
            continue;
        };
        if !trusted_literal_script_program(program)
            || stdin_data_sink_may_be_overridden(command, node.range().end, program)
        {
            continue;
        }
        let (command_names, transfer): (&'static [&'static str], _) = match basename {
            "scp" => {
                let Some(transfer) = literal_scp_file_transfer(arguments) else {
                    continue;
                };
                // OpenSSH invokes ssh for remote copies and cp for local
                // copies. Those executable identities belong to the proof
                // even when neither appears as an explicit shell command.
                (&["scp", "ssh", "cp"], Some(transfer))
            }
            "ssh" if literal_ssh_git_message_reader(arguments) => (&["ssh", "git", "cd"], None),
            "git" if literal_git_commit_message_reader(&words) => (&["git"], None),
            _ => continue,
        };
        consumers.push(ProvenFileDataConsumer {
            range: node.range(),
            command_names,
            transfer,
        });
    }
    // Do not let a new transfer exemption inherit the legacy READERS list's
    // name-only contract. Other commands can execute files through options
    // (`rg --pre sh`, `vim -S`), transform them into a differently named file,
    // or consume them implicitly without a filename in argv. For this new
    // allowance, the complete workflow must have concrete data contracts.
    let mut pending = vec![ast.root()];
    while let Some(node) = pending.pop() {
        if started.elapsed() >= budget {
            return Vec::new();
        }
        match node.kind().as_ref() {
            "program" | "list" => {
                if node
                    .children()
                    .any(|child| !child.is_named() && !matches!(child.kind().as_ref(), "&&" | ";"))
                {
                    return Vec::new();
                }
                pending.extend(node.children().filter(ast_grep_core::Node::is_named));
            }
            "redirected_statement" if literal_cat_file_write(&node).is_some() => {}
            "command"
                if consumers
                    .iter()
                    .any(|consumer| consumer.range == node.range())
                    || literal_mkdir_setup(&node) => {}
            "comment" => {}
            _ => return Vec::new(),
        }
    }
    // Every recognized command relies on a specific executable still having
    // its normal data contract. A copy from an external (untracked) source
    // can overwrite one just as a copy from this heredoc can. Check both a
    // literal target basename and each source basename, since the target may
    // be an existing directory. This proof does not model changed executables.
    let names_workflow_program = |name: &str| {
        matches!(name, "cat" | "mkdir" | "sftp-server")
            || SHELL_PROGRAMS.contains(&name)
            || consumers
                .iter()
                .any(|consumer| consumer.command_names.contains(&name))
    };
    if consumers
        .iter()
        .filter_map(|consumer| consumer.transfer.as_ref())
        .any(|transfer| {
            transfer
                .destination
                .as_deref()
                .is_some_and(names_workflow_program)
                || transfer
                    .sources
                    .iter()
                    .any(|source| names_workflow_program(source))
        })
    {
        return Vec::new();
    }
    consumers
}

/// Parse only transport options whose values cannot select commands or load
/// executable configuration. In particular scp -S/-D, either program's -F/-o,
/// jump-host options, and scp's legacy/recursive modes are deliberately absent.
/// The boolean records `--`, since ssh may otherwise parse options again after
/// the destination. Bundled flags and attached values follow getopt ordering.
fn literal_transport_options_end(
    arguments: &[String],
    mut index: usize,
    scp: bool,
) -> Option<(usize, bool)> {
    let flags = if scp { "46BCpqv" } else { "46CnqTtv" };
    let values = if scp { "Plic" } else { "plic" };
    while let Some(argument) = arguments.get(index) {
        if argument == "--" {
            return Some((index + 1, true));
        }
        let Some(options) = argument.strip_prefix('-') else {
            break;
        };
        if options.is_empty() || options.starts_with('-') {
            return None;
        }
        for (offset, option) in options.char_indices() {
            if flags.contains(option) {
                continue;
            }
            if !values.contains(option) {
                return None;
            }
            let attached = &options[offset + option.len_utf8()..];
            let value = if attached.is_empty() {
                index += 1;
                arguments.get(index)?.as_str()
            } else {
                attached
            };
            let valid = match (scp, option) {
                (true, 'P' | 'l') | (false, 'p') => {
                    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
                }
                (_, 'i') => literal_transport_file_path(value),
                (false, 'l') => literal_transport_host(value),
                (_, 'c') => {
                    !value.is_empty()
                        && value.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric()
                                || matches!(byte, b'_' | b'-' | b'.' | b'+' | b'@' | b',')
                        })
                }
                _ => false,
            };
            if !valid {
                return None;
            }
            break;
        }
        index += 1;
    }
    Some((index, false))
}

fn literal_transport_host(host: &str) -> bool {
    !host.is_empty()
        && !host.starts_with('-')
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'@'))
}

fn literal_transport_file_path(path: &str) -> bool {
    is_plain_file_path(path)
        && !path.contains([
            ';', '&', '|', '(', ')', '<', '>', '\n', '\r', '\'', '"', ':',
        ])
        && !path.split('/').any(|component| component == "..")
}

fn literal_scp_file_transfer(arguments: &[String]) -> Option<LiteralFileTransfer> {
    use crate::packs::remote::scp::{ScpSemanticDecision, scp_semantic_decision};

    let (index, _) = literal_transport_options_end(arguments, 0, true)?;
    let files = arguments.get(index..)?;
    let (destination, sources) = files.split_last()?;
    if sources.is_empty()
        || sources.len() > 32
        || !sources
            .iter()
            .all(|source| literal_transport_file_path(source) && !source.ends_with('/'))
    {
        return None;
    }
    // The existing SCP policy already distinguishes staging directories
    // from system executables, libraries, and configuration trees. Reuse it
    // here even when that optional pack is disabled: such a copy cannot
    // establish the executable identities required by this data waiver.
    let mut invocation = String::from("scp");
    for argument in arguments {
        invocation.push(' ');
        invocation.push_str(&shell_words::quote(argument));
    }
    if !matches!(
        scp_semantic_decision(&invocation),
        ScpSemanticDecision::Safe | ScpSemanticDecision::NonDestructive
    ) {
        return None;
    }
    let destination = if let Some((host, path)) = destination.split_once(':') {
        if !literal_transport_host(host) {
            return None;
        }
        path
    } else {
        destination.as_str()
    };
    if !destination.is_empty() && !literal_transport_file_path(destination) {
        return None;
    }
    // A transfer to a shell startup file or Git hook can execute without any
    // later argv mentioning that file. Reuse the protected-path policy and
    // check both interpretations of a target that may be a directory. An
    // omitted remote path names the remote home, not an arbitrary safe file.
    let protected = |path: &str| {
        crate::packs::core::credential_files::names_protected_file(&shell_words::quote(path))
            // core.hooksPath can locate hooks outside any `.git` directory.
            // These program basenames therefore remain ambiguous wherever
            // copied, including a directory target plus source basename.
            || matches!(
                path.rsplit('/').next().unwrap_or(path),
                "applypatch-msg"
                    | "pre-applypatch"
                    | "post-applypatch"
                    | "pre-commit"
                    | "pre-merge-commit"
                    | "prepare-commit-msg"
                    | "commit-msg"
                    | "post-commit"
                    | "pre-rebase"
                    | "post-checkout"
                    | "post-merge"
                    | "pre-push"
                    | "pre-receive"
                    | "update"
                    | "proc-receive"
                    | "post-receive"
                    | "post-update"
                    | "reference-transaction"
                    | "push-to-checkout"
                    | "pre-auto-gc"
                    | "post-rewrite"
                    | "sendemail-validate"
                    | "fsmonitor-watchman"
                    | "p4-changelist"
                    | "p4-prepare-changelist"
                    | "p4-post-changelist"
                    | "p4-pre-submit"
                    | "post-index-change"
            )
    };
    if protected(destination)
        || sources.iter().any(|source| {
            let basename = source.rsplit('/').next().unwrap_or(source);
            let in_directory = if destination.is_empty() {
                basename.to_string()
            } else {
                format!("{destination}/{basename}")
            };
            protected(&in_directory)
        })
    {
        return None;
    }
    let destination = destination
        .rsplit('/')
        .next()
        .filter(|name| !matches!(*name, "" | "." | ".."))
        .map(str::to_string);
    Some(LiteralFileTransfer {
        sources: sources
            .iter()
            .map(|source| source.rsplit('/').next().unwrap_or(source).to_string())
            .collect(),
        destination,
    })
}

fn literal_ssh_git_message_reader(arguments: &[String]) -> bool {
    let Some((destination, options_ended)) = literal_transport_options_end(arguments, 0, false)
    else {
        return false;
    };
    if !arguments
        .get(destination)
        .is_some_and(|host| literal_transport_host(host))
    {
        return false;
    }
    let mut payload = destination + 1;
    if !options_ended {
        let Some((index, _)) = literal_transport_options_end(arguments, payload, false) else {
            return false;
        };
        payload = index;
    }
    // OpenSSH joins the actual local argv with spaces before the remote shell
    // parses it. Judge that line, including quotes retained for the remote
    // shell, rather than a substring of the original quoted local operand.
    let remote = arguments.get(payload..).unwrap_or_default().join(" ");
    let Ok(ast) = AstGrep::try_new(remote.as_str(), SupportLang::Bash) else {
        return false;
    };
    if ast.root().get_inner_node().has_error() {
        return false;
    }
    let mut pending = vec![ast.root()];
    let mut commands = Vec::new();
    while let Some(node) = pending.pop() {
        match node.kind().as_ref() {
            "program" | "list" => {
                if node
                    .children()
                    .any(|child| !child.is_named() && child.kind().as_ref() != "&&")
                {
                    return false;
                }
                let start = pending.len();
                pending.extend(node.children().filter(ast_grep_core::Node::is_named));
                pending[start..].reverse();
            }
            "command" => {
                if node
                    .children()
                    .filter(ast_grep_core::Node::is_named)
                    .any(|child| {
                        !matches!(
                            child.kind().as_ref(),
                            "command_name" | "word" | "raw_string" | "string"
                        )
                    })
                {
                    return false;
                }
                let Some(words) = literal_script_words(&node) else {
                    return false;
                };
                commands.push(words);
                if commands.len() > 2 {
                    return false;
                }
            }
            _ => return false,
        }
    }
    let reader = match commands.as_slice() {
        [reader] => reader,
        [setup, reader]
            if matches!(setup.as_slice(), [program, path]
                if program == "cd" && literal_transport_file_path(path)) =>
        {
            reader
        }
        _ => return false,
    };
    literal_git_commit_message_reader(reader)
}

fn literal_git_commit_message_reader(words: &[String]) -> bool {
    let Some((program, arguments)) = words.split_first() else {
        return false;
    };
    if !matches!(program.as_str(), "git" | "/bin/git" | "/usr/bin/git") {
        return false;
    }
    let Some(("commit", commit_arguments)) = git_builtin_subcommand_and_args(arguments) else {
        return false;
    };
    // This new file-flow waiver needs the usual repository layout. An
    // alternate administrative directory can put executable hooks outside
    // the protected `.git` anchor; custom helper paths likewise change the
    // programs involved. Keep ordinary `git -C repo commit -F file` intact
    // without widening the shared parser's other stdin-data contracts.
    let global_end = arguments.len() - commit_arguments.len() - 1;
    if arguments[..global_end].iter().any(|argument| {
        let option = argument
            .split_once('=')
            .map_or(argument.as_str(), |(option, _)| option);
        matches!(
            option,
            "--git-dir"
                | "--work-tree"
                | "--bare"
                | "--namespace"
                | "--super-prefix"
                | "--exec-path"
        )
    }) {
        return false;
    }
    let arguments = commit_arguments;
    let mut index = 0usize;
    let mut found_file = false;
    while let Some(argument) = arguments.get(index) {
        if argument == "--" {
            return found_file
                && arguments[index + 1..]
                    .iter()
                    .all(|path| literal_transport_file_path(path));
        }
        let file = if matches!(argument.as_str(), "-F" | "--file") {
            index += 1;
            arguments.get(index).map(String::as_str)
        } else if let Some(path) = argument.strip_prefix("--file=") {
            Some(path)
        } else if let Some(short) = argument.strip_prefix('-') {
            if let Some(at) = short.find('F')
                && short[..at].chars().all(|flag| "ainopqsv".contains(flag))
            {
                let path = &short[at + 1..];
                if path.is_empty() {
                    index += 1;
                    arguments.get(index).map(String::as_str)
                } else {
                    Some(path)
                }
            } else if !short.is_empty() && short.chars().all(|flag| "ainopqsv".contains(flag))
                || matches!(
                    argument.as_str(),
                    "--all"
                        | "--amend"
                        | "--quiet"
                        | "--no-verify"
                        | "--no-edit"
                        | "--allow-empty"
                        | "--allow-empty-message"
                        | "--no-gpg-sign"
                        | "--signoff"
                        | "--verbose"
                )
            {
                index += 1;
                continue;
            } else {
                return false;
            }
        } else if literal_transport_file_path(argument) {
            index += 1;
            continue;
        } else {
            return false;
        };
        if !file.is_some_and(literal_transport_file_path) {
            return false;
        }
        found_file = true;
        index += 1;
    }
    found_file
}

/// Readers whose file access follows lexical command order. This proof is
/// deliberately narrower than the legacy READERS list: it only withdraws a
/// prior sed/awk/tac mention when the entire shell has ordinary sequential
/// statements and the reader has a literal, non-executing program. A prior
/// arbitrary executable can arrange a future read, and a loop can read the
/// newly written bytes on its next iteration. Neither supplies this proof.
fn ordered_file_reader_ranges(command: &str, outside: &str) -> Vec<Range<usize>> {
    if !outside.contains("sed") && !outside.contains("awk") && !outside.contains("tac") {
        return Vec::new();
    }
    let Ok(ast) = AstGrep::try_new(outside, SupportLang::Bash) else {
        return Vec::new();
    };
    if ast.root().get_inner_node().has_error() {
        return Vec::new();
    }
    let mut pending = vec![ast.root()];
    let mut readers = Vec::new();
    while let Some(node) = pending.pop() {
        match node.kind().as_ref() {
            "program" | "list" => {
                for child in node.children() {
                    if child.is_named() {
                        pending.push(child);
                    } else if !matches!(child.text().as_ref(), ";" | "&&" | "||") {
                        // A background operator, pipeline, or unknown shell
                        // construct does not establish completion order.
                        return Vec::new();
                    }
                }
            }
            "redirected_statement" => {
                // Bash's heredoc grammar wraps `reader && cat > file` around
                // a list; recurse through that list's ordering checks too.
                for child in node.children().filter(ast_grep_core::Node::is_named) {
                    if !matches!(
                        child.kind().as_ref(),
                        "command" | "list" | "file_redirect" | "heredoc_redirect"
                    ) {
                        return Vec::new();
                    }
                    pending.push(child);
                }
            }
            "heredoc_redirect" => {
                let text = node.text();
                let Some(operator) = text.find("<<") else {
                    return Vec::new();
                };
                let Some(delimiter) = node
                    .children()
                    .find(|child| child.kind().as_ref() == "heredoc_start")
                else {
                    return Vec::new();
                };
                if !heredoc_delimiter_is_quoted(
                    text.as_ref(),
                    operator,
                    delimiter.range().end.saturating_sub(node.range().start),
                    delimiter.text().as_ref(),
                ) {
                    // The blanked view omitted expansions from an unquoted
                    // body; they could start deferred work before the write.
                    return Vec::new();
                }
                for child in node.children().filter(ast_grep_core::Node::is_named) {
                    match child.kind().as_ref() {
                        "heredoc_start" | "heredoc_body" | "heredoc_end" => {}
                        "file_redirect" => pending.push(child),
                        _ => return Vec::new(),
                    }
                }
            }
            "command" => {
                let Some(name) = node
                    .children()
                    .find(|child| child.kind().as_ref() == "command_name")
                else {
                    return Vec::new();
                };
                let name_text = name.text();
                let Some(name) = literal_program_name(name_text.as_ref()) else {
                    return Vec::new();
                };
                if is_code_runner_name(name)
                    || matches!(name, "trap" | "coproc" | "exec" | "disown" | "wait")
                {
                    return Vec::new();
                }
                // Shell expansions may execute or arrange future work, even
                // when the containing command itself is a simple statement.
                let mut parts: Vec<_> = node.children().collect();
                while let Some(part) = parts.pop() {
                    if matches!(
                        part.kind().as_ref(),
                        "command_substitution" | "process_substitution" | "variable_assignment"
                    ) {
                        return Vec::new();
                    }
                    parts.extend(part.children());
                }
                if synchronous_file_reader(node.text().as_ref())
                    && !stdin_data_sink_may_be_overridden(command, node.range().end, name)
                {
                    readers.push(node.range());
                    if readers.len() > 32 {
                        return Vec::new();
                    }
                }
            }
            "file_redirect" => {
                let mut parts: Vec<_> = node.children().collect();
                while let Some(part) = parts.pop() {
                    if matches!(
                        part.kind().as_ref(),
                        "command_substitution" | "process_substitution"
                    ) {
                        return Vec::new();
                    }
                    parts.extend(part.children());
                }
            }
            "comment" => {}
            // Functions, loops, conditionals, groups, subshells and pipelines
            // all keep the old conservative scan, regardless of byte order.
            _ => return Vec::new(),
        }
    }
    readers
}

/// A small set of synchronous reads, with no program files, executable
/// options, mutable arguments, or wrappers. These are not new data-sink
/// exemptions: they apply only to a mention before the file is written.
fn synchronous_file_reader(command: &str) -> bool {
    if command.contains(['$', '`', '*', '?', '[', '{', '~', '\n', '\r']) {
        return false;
    }
    let Ok(words) = shell_words::split(command) else {
        return false;
    };
    let Some((program, mut arguments)) = words.split_first() else {
        return false;
    };
    let name = program.rsplit('/').next().unwrap_or(program);
    match name {
        "tac" => true,
        "awk" | "gawk" | "mawk" | "nawk" => {
            matches!(arguments.split_first(), Some((program, files))
                if program == "1" && files.iter().all(|file| !file.starts_with('-')))
        }
        "sed" | "gsed" => {
            while arguments
                .first()
                .is_some_and(|arg| matches!(arg.as_str(), "-n" | "-E" | "-r"))
            {
                arguments = &arguments[1..];
            }
            let Some((script, files)) = arguments.split_first() else {
                return false;
            };
            files.iter().all(|file| !file.starts_with('-')) && sed_program_is_plain_read(script)
        }
        _ => false,
    }
}

/// A single print command or substitution without an execution/write flag.
/// Escaped delimiters stay inside the pattern or replacement; no surrounding
/// sed commands are accepted, so `e`, `s///e`, and appended programs stay code.
fn sed_program_is_plain_read(script: &str) -> bool {
    if let Some(address) = script.strip_suffix('p') {
        if address
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b',')
        {
            return true;
        }
    }
    let bytes = script.as_bytes();
    let Some(&delimiter) = bytes.get(1) else {
        return false;
    };
    if bytes.first() != Some(&b's') || !delimiter.is_ascii_punctuation() || delimiter == b'\\' {
        return false;
    }
    let mut index = 2;
    for _ in 0..2 {
        loop {
            let Some(&byte) = bytes.get(index) else {
                return false;
            };
            index += 1;
            if byte == b'\\' {
                index += 1;
            } else if byte == delimiter {
                break;
            }
        }
    }
    bytes[index..].iter().all(|byte| {
        byte.is_ascii_digit() || matches!(byte, b'g' | b'p' | b'i' | b'I' | b'm' | b'M')
    })
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveHeredoc {
    operator_start: usize,
    body: ActiveHeredocBody,
    /// The parts of the body the shell executes while reading it, as absolute
    /// byte ranges: `Some(vec![])` for a quoted delimiter or an expanding body
    /// without substitutions, the substitution spans for an expanding body
    /// (see [`expanding_body_live_spans`]), and `None` when those cannot be
    /// bounded — such a body must stay whole in any view that judges it.
    live_spans: Option<Vec<Range<usize>>>,
    /// Where the output of the command reading the body goes, when the parse
    /// tree proves it; `None` when it does not, and the masker falls back to
    /// [`command_may_run_heredoc_output`] over the text outside the bodies.
    output: Option<HeredocOutput>,
}

/// Where the standard output of the command that reads a heredoc goes.
///
/// A data sink such as `cat` or `tee` copies its body to standard output, so
/// the body is only as inert as the place that output ends up: `cat <<EOF >
/// notes.md` files it away, `cat <<EOF | sh` runs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeredocOutput {
    /// Provably contained: the terminal, a plain file, or through read-only
    /// text tools ([`READ_ONLY_PIPE_STAGES`]) into one of those.
    Contained,
    /// Not provably contained, and nothing seen that runs it: an unknown
    /// pipeline stage, a descriptor duplication, a command substitution.
    Escapes,
    /// Into something that may run it as code: a shell, an interpreter, a
    /// remote or privileged shell, `xargs`, a process substitution, `eval`.
    Executes,
}

fn active_heredocs(command: &str) -> Option<Vec<ActiveHeredoc>> {
    const MAX_HEREDOC_MASK_SOURCE_BYTES: usize = 256 * 1024;
    if command.len() > MAX_HEREDOC_MASK_SOURCE_BYTES {
        return None;
    }

    let ast = AstGrep::new(command, SupportLang::Bash);
    let mut heredocs = Vec::new();
    let mut parse_error = false;
    let plumbed = output_may_be_replumbed(&ast.root());
    collect_active_heredocs(ast.root(), &mut heredocs, &mut parse_error, plumbed);
    if parse_error {
        return active_single_heredoc_fallback(command);
    }
    heredocs.sort_by_key(|heredoc| heredoc.operator_start);
    heredocs.dedup_by_key(|heredoc| heredoc.operator_start);
    Some(heredocs)
}

/// Recover the one heredoc body span tree-sitter-bash could not give us.
///
/// tree-sitter-bash rejects some real shell: Ruby's `<<~` operator, and — the
/// #393 class — a heredoc whose operator line continues with `;` after the
/// delimiter (`cat <<EOF; echo done`, `git commit -F - <<EOF; git push`).
/// A parse error used to drop EVERY heredoc from the masking view, so a
/// data-sink body (a commit message that merely mentions `git restore`) was
/// re-scanned as live shell and denied, while the identical command joined
/// with `&&` or `|` was allowed.
///
/// The recovery is deliberately narrow so malformed input can never erase
/// later executable text: one heredoc-like operator outside the body it
/// describes (a second one *inside* that body is data, not shell input —
/// #440), proven active by the quote-aware trigger scanner, not preceded by
/// a `#` on its own line (the scanner does not model comments), a simple
/// delimiter token (no `<<'E'OF`-style concatenation, whose quote removal the
/// tier-2 extractor does not perform), and a terminator the extractor
/// actually found. Under those conditions the body is exactly the lines
/// between the operator's line and the terminator line — the same span the
/// shell itself feeds the command — and the operator line's own commands,
/// plus everything after the terminator, stay visible. Anything ambiguous
/// answers `None`, which keeps the whole input unmasked.
fn active_single_heredoc_fallback(command: &str) -> Option<Vec<ActiveHeredoc>> {
    if !contains_active_heredoc_operator(command) {
        return None;
    }
    let operator_start = command.find("<<")?;
    // Here-strings are not heredocs; only the AST path may classify them.
    if command[operator_start..].starts_with("<<<") {
        return None;
    }
    let line_start = command[..operator_start]
        .rfind(['\n', '\r'])
        .map_or(0, |i| i + 1);
    if command[line_start..operator_start].contains('#') {
        return None;
    }
    // The delimiter token must end where the extractor's regex says it ends:
    // a following quote, word byte, or escape means shell quote removal would
    // change the real delimiter, and the extractor's terminator search would
    // then be wrong.
    let delimiter_match = HEREDOC_EXTRACTOR.find_at(command, operator_start)?;
    if delimiter_match.start() != operator_start {
        return None;
    }
    match command.as_bytes().get(delimiter_match.end()) {
        None => {}
        Some(byte)
            if byte.is_ascii_whitespace()
                || matches!(byte, b';' | b'&' | b'|' | b')' | b'<' | b'>') => {}
        Some(_) => return None,
    }

    // Raw text, not the masked scan view: this function is reached *from* the
    // masker, so asking for the mask here would not terminate (#420). Scanning
    // the raw text in this one place is the conservative direction, and it is
    // what every caller did before.
    let extracted = match extract_content_with_scan_view(
        command,
        command,
        &ExtractionLimits::structural_scan(),
    ) {
        ExtractionResult::Extracted(extracted) | ExtractionResult::Partial { extracted, .. } => {
            extracted
        }
        ExtractionResult::NoContent
        | ExtractionResult::Skipped(_)
        | ExtractionResult::Failed(_) => return None,
    };
    let mut candidates = extracted.into_iter().filter(|content| {
        content.byte_range.start == operator_start
            && content
                .heredoc_type
                .is_some_and(|kind| kind != HeredocType::HereString)
            && content.content_range.is_some()
    });
    let candidate = candidates.next()?;
    if candidates.next().is_some() {
        return None;
    }
    let body_range = candidate.content_range?;
    if body_range.start < delimiter_match.end() || body_range.end > command.len() {
        return None;
    }
    // A second `<<` is tolerated in exactly one place: inside the very body
    // this call is about to describe. That body is what the shell hands the
    // command as data, so a heredoc operator written there is text — most
    // often another language's, since Ruby's `<<~` is what made tree-sitter
    // reject the parse in the first place. Requiring a single `<<` in the
    // whole input meant `cat > x.rb <<'OUTER'` with `eval <<~'SCRIPT'` in its
    // body produced no span at all, so the quoted body was rescanned as live
    // shell and its Ruby `eval` denied as a POSIX one — while the same
    // command without the nested operator was correctly allowed (#440).
    // Anything outside the body still answers None: a `<<` before the
    // operator is shell input on the operator's own line, and one after the
    // terminator is shell input that masking must never erase.
    if command
        .match_indices("<<")
        .any(|(index, _)| index != operator_start && !body_range.contains(&index))
    {
        return None;
    }
    // Without a parse tree the substitutions of an expanding body cannot be
    // bounded, so such a body is only maskable when it has none to hide.
    let live_spans = (candidate.quoted
        || !expanding_body_may_execute(&command[body_range.clone()]))
    .then(Vec::new);
    Some(vec![ActiveHeredoc {
        operator_start,
        body: ActiveHeredocBody::Heredoc {
            body_start: body_range.start,
            body_end: body_range.end,
            delimiter_quoted: candidate.quoted,
        },
        live_spans,
        // No parse tree, so nothing about the output is proven.
        output: None,
    }])
}

#[allow(clippy::needless_pass_by_value)]
fn collect_active_heredocs<D: ast_grep_core::Doc>(
    root: ast_grep_core::Node<'_, D>,
    heredocs: &mut Vec<ActiveHeredoc>,
    parse_error: &mut bool,
    plumbed: bool,
) {
    // An explicit stack, not recursion: this runs on every hook payload
    // before the size gate (dialect refinement masks the command first), and
    // a list of some ten thousand `true &&` nests that deep in the parse
    // tree. Recursing overflowed the stack and aborted the hook, which the
    // agent treats as a non-blocking error and runs the command.
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if collect_active_heredoc_node(&node, heredocs, parse_error, plumbed) {
            // Children reversed onto the stack, so they pop in order.
            let first_child = pending.len();
            pending.extend(node.children());
            pending[first_child..].reverse();
        }
    }
}

/// [`collect_active_heredocs`] for one node: record it if it is a heredoc or
/// here-string (or flag a parse error), and answer whether to descend into
/// its children.
fn collect_active_heredoc_node<D: ast_grep_core::Doc>(
    node: &ast_grep_core::Node<'_, D>,
    heredocs: &mut Vec<ActiveHeredoc>,
    parse_error: &mut bool,
    plumbed: bool,
) -> bool {
    let kind = node.kind();
    if kind == "ERROR" {
        *parse_error = true;
        return false;
    }
    if kind == "herestring_redirect" {
        let text = node.text();
        if let Some(offset) = text.find("<<") {
            heredocs.push(ActiveHeredoc {
                operator_start: node.range().start + offset,
                body: ActiveHeredocBody::HereString,
                live_spans: None,
                output: (!plumbed).then(|| heredoc_output(node)).flatten(),
            });
        } else {
            *parse_error = true;
        }
        return false;
    }
    if kind == "heredoc_redirect" {
        let text = node.text();
        let Some(offset) = text.find("<<") else {
            *parse_error = true;
            return false;
        };
        let mut body_range = None;
        let mut body_node = None;
        let mut end_start = None;
        let mut delimiter_quoted = false;
        for child in node.children() {
            match child.kind().as_ref() {
                "heredoc_body" => {
                    body_range = Some(child.range());
                    body_node = Some(child);
                }
                "heredoc_end" => end_start = Some(child.range().start),
                "heredoc_start" => {
                    delimiter_quoted |= heredoc_delimiter_is_quoted(
                        text.as_ref(),
                        offset,
                        child.range().end.saturating_sub(node.range().start),
                        child.text().as_ref(),
                    );
                }
                _ => {}
            }
        }
        let body_range =
            body_range.or_else(|| end_start.map(|start| std::ops::Range { start, end: start }));
        let Some(body_range) = body_range else {
            *parse_error = true;
            return false;
        };
        if body_range.start > body_range.end || body_range.end > node.range().end {
            *parse_error = true;
            return false;
        }
        let live_spans = if delimiter_quoted {
            Some(Vec::new())
        } else {
            // An empty body has no `heredoc_body` node and nothing to run.
            body_node.map_or_else(|| Some(Vec::new()), expanding_body_live_spans)
        };
        heredocs.push(ActiveHeredoc {
            operator_start: node.range().start + offset,
            body: ActiveHeredocBody::Heredoc {
                body_start: body_range.start,
                body_end: body_range.end,
                delimiter_quoted,
            },
            live_spans,
            output: (!plumbed).then(|| heredoc_output(node)).flatten(),
        });
        return false;
    }
    true
}

/// Pipeline stages that only read, count, filter or file text and pass it on
/// as text: a body piped through them is as contained as their own output.
/// `sed` and `awk` are absent on purpose (`e`, `system()`), as are pagers
/// (`!` runs a shell).
const READ_ONLY_PIPE_STAGES: &[&str] = &[
    "cat",
    "tac",
    "nl",
    "wc",
    "head",
    "tail",
    "sort",
    "uniq",
    "cut",
    "tr",
    "fold",
    "fmt",
    "column",
    "paste",
    "expand",
    "unexpand",
    "rev",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "tee",
    "md5sum",
    "sha1sum",
    "sha224sum",
    "sha256sum",
    "sha384sum",
    "sha512sum",
    "shasum",
    "b2sum",
    "cksum",
    "base64",
    "base32",
    "od",
    "xxd",
    "hexdump",
    "strings",
    "comm",
    "pr",
    "jq",
];

/// Shells: they run their standard input unless given a script file or a
/// literal `-c` string.
const SHELL_PROGRAMS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "fish", "csh", "tcsh", "ash", "yash", "posh",
    "rbash",
];

/// Programs that run what they read on standard input, or turn it into
/// commands, whatever their operands: `xargs`, `at`, `su`, `ed`, `gdb`, ….
const STDIN_COMMAND_RUNNERS: &[&str] = &[
    "source", ".", "eval", "xargs", "parallel", "at", "batch", "crontab", "su", "ed", "ex", "gdb",
    "lldb",
];

/// Script interpreters: like shells, they run standard input unless given a
/// script file, a literal code string, or a module.
fn is_interpreter_program(name: &str) -> bool {
    matches!(
        name,
        "deno" | "bun" | "tclsh" | "wish" | "expect" | "julia" | "Rscript" | "osascript" | "cmd"
    ) || [
        "python",
        "perl",
        "ruby",
        "node",
        "php",
        "lua",
        "pwsh",
        "powershell",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

/// Programs that run another program named among their operands
/// (`sudo -u x sh`, `timeout 5 bash`, `docker exec -i c sh`,
/// `kubectl exec -i p -- sh`). What such a stage does with its input is
/// what that program does.
const COMMAND_WRAPPERS: &[&str] = &[
    "sudo",
    "doas",
    "env",
    "nohup",
    "timeout",
    "nice",
    "ionice",
    "stdbuf",
    "setsid",
    "time",
    "command",
    "builtin",
    "chrt",
    "taskset",
    "unbuffer",
    "flock",
    "caffeinate",
    "exec",
    "busybox",
    "toybox",
    "watch",
    "docker",
    "podman",
    "kubectl",
    "oc",
    "lxc",
    "incus",
    "nsenter",
    "chroot",
    "systemd-run",
    "machinectl",
    "tmux",
    "screen",
    "script",
];

/// Whether `name` is a program [`stage_runs_received_text`] judges by its
/// operands rather than dismissing: a shell, an interpreter, a remote shell,
/// or a program that runs its standard input.
fn is_code_runner_name(name: &str) -> bool {
    SHELL_PROGRAMS.contains(&name)
        || STDIN_COMMAND_RUNNERS.contains(&name)
        || is_interpreter_program(name)
        || matches!(name, "ssh" | "mosh")
}

/// Whether a command word is a literal name rather than one the shell
/// computes, and the basename it names.
fn literal_program_name(word: &str) -> Option<&str> {
    if word.is_empty()
        || !word.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/' | b'+')
        })
    {
        return None;
    }
    Some(word.rsplit('/').next().unwrap_or(word))
}

/// A word the shell computes at run time.
fn is_computed_word(word: &str) -> bool {
    word.contains(['$', '`'])
}

/// A word with one layer of surrounding quotes removed (coarse: enough to
/// read an option, a program name or a script operand).
fn unquoted_word(word: &str) -> &str {
    word.trim_matches(['\'', '"'])
}

/// An operand that names standard input as a file.
fn names_stdin(word: &str) -> bool {
    matches!(
        unquoted_word(word),
        "-" | "/dev/stdin" | "/dev/fd/0" | "/proc/self/fd/0"
    )
}

/// Whether a stage named `program` with operands `operands` runs the text it
/// receives on standard input (or a substitution that reads it). A computed
/// name (`$SHELL`, `$(…)`) may be anything, so it does.
fn stage_runs_received_text(program: &str, operands: &[String]) -> bool {
    let Some(name) = literal_program_name(program) else {
        return true;
    };
    if SHELL_PROGRAMS.contains(&name) {
        return shell_reads_its_input(operands);
    }
    if is_interpreter_program(name) {
        return interpreter_reads_its_input(operands);
    }
    if STDIN_COMMAND_RUNNERS.contains(&name) {
        // `su -c 'cmd' user` runs its literal command, not its input.
        return !(name == "su"
            && operands.iter().enumerate().any(|(at, operand)| {
                matches!(operand.as_str(), "-c" | "--command")
                    && operands
                        .get(at + 1)
                        .is_some_and(|code| !is_computed_word(code))
            }));
    }
    if matches!(name, "ssh" | "mosh") {
        return remote_shell_reads_its_input(operands);
    }
    if !COMMAND_WRAPPERS.contains(&name) {
        return false;
    }
    // `sudo -s`, `sudo -i`, a bare `sudo`: a root shell reading the text.
    if matches!(name, "sudo" | "doas")
        && (operands.iter().all(|operand| operand.starts_with('-'))
            || operands
                .iter()
                .any(|operand| matches!(operand.as_str(), "-s" | "-i" | "--shell" | "--login")))
    {
        return true;
    }
    // The first operand that names a code runner (or a piece of a
    // split-string operand, `env -S 'sh -e'`) is the program run, with the
    // operands after it; one computed at run time may be anything.
    for (at, operand) in operands.iter().enumerate() {
        if is_computed_word(operand) && !is_shell_env_assignment(operand) {
            return true;
        }
        let pieces: Vec<&str> = unquoted_word(operand).split_whitespace().collect();
        if let Some((first, rest)) = pieces.split_first()
            && literal_program_name(first).is_some_and(is_code_runner_name)
        {
            let mut tail: Vec<String> = rest.iter().map(ToString::to_string).collect();
            tail.extend(operands[at + 1..].iter().cloned());
            return stage_runs_received_text(first, &tail);
        }
    }
    false
}

/// A shell's operands: does it read its program from standard input? It
/// does with no script operand, with `-s`, or with `-`; a script file or a
/// literal `-c` string leaves the input as data, a computed one may not.
fn shell_reads_its_input(operands: &[String]) -> bool {
    let mut at = 0;
    while let Some(operand) = operands.get(at) {
        if is_computed_word(operand) || names_stdin(operand) {
            return true;
        }
        let word = unquoted_word(operand);
        if word == "--" {
            return operands
                .get(at + 1)
                .is_none_or(|next| is_computed_word(next) || names_stdin(next));
        }
        if word.starts_with("--") {
            at += if matches!(word, "--rcfile" | "--init-file") {
                2
            } else {
                1
            };
            continue;
        }
        if let Some(letters) = word.strip_prefix(['-', '+']) {
            if letters.contains('s') {
                return true;
            }
            if letters.contains('c') {
                return operands
                    .get(at + 1)
                    .is_none_or(|code| is_computed_word(code));
            }
            at += if letters.ends_with(['o', 'O']) { 2 } else { 1 };
            continue;
        }
        return false;
    }
    true
}

/// An interpreter's operands: does it read its program from standard input?
/// It does with no script operand or with `-`; a script file, a literal code
/// string (`-c`, `-e`, `--eval`, …) or a module that is not a console leaves
/// the input as data.
fn interpreter_reads_its_input(operands: &[String]) -> bool {
    let mut at = 0;
    while let Some(operand) = operands.get(at) {
        if is_computed_word(operand) || names_stdin(operand) {
            return true;
        }
        let word = unquoted_word(operand);
        if word == "--" {
            at += 1;
            continue;
        }
        let Some(rest) = word.strip_prefix('-') else {
            return false;
        };
        let code = matches!(
            word,
            "--eval" | "--print" | "-Command" | "-command" | "-c" | "-e" | "-E" | "-r" | "-p"
        ) || (!rest.starts_with('-')
            && rest.len() <= 3
            && rest.bytes().all(|byte| byte.is_ascii_alphabetic())
            && rest.contains(['c', 'e', 'E']));
        if code || matches!(word, "-File" | "-file") {
            return operands
                .get(at + 1)
                .is_none_or(|value| is_computed_word(value) || names_stdin(value));
        }
        if word == "-m" {
            return operands.get(at + 1).is_none_or(|module| {
                matches!(
                    unquoted_word(module),
                    "code" | "pdb" | "ipdb" | "IPython" | "asyncio" | "idlelib"
                )
            });
        }
        at += 1;
    }
    true
}

/// `ssh`'s operands: with no remote command the remote login shell runs the
/// input; otherwise the remote command decides, read like a stage.
fn remote_shell_reads_its_input(operands: &[String]) -> bool {
    let mut at = 0;
    while let Some(operand) = operands.get(at) {
        if !operand.starts_with('-') {
            break;
        }
        at += match classify_ssh_option(operand) {
            SshOptionShape::TakesSeparateValue => 2,
            SshOptionShape::FlagsOnly | SshOptionShape::ValueAttached => 1,
            SshOptionShape::Unknown => return true,
        };
    }
    // `operands[at]` is the host; the rest is the remote command line.
    let remote = operands.get(at + 1..).unwrap_or_default();
    let remote = match remote.first() {
        Some(first) if first == "--" => &remote[1..],
        _ => remote,
    };
    let words: Vec<String> = remote
        .iter()
        .flat_map(|operand| {
            unquoted_word(operand)
                .split_whitespace()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .collect();
    let Some((first, rest)) = words.split_first() else {
        return true;
    };
    stage_runs_received_text(first, rest)
}

/// Whether anything in the parse tree can send a command's standard output
/// somewhere the tree does not show at that command: a process substitution
/// (`exec > >(sh)`, `tee >(sh)`), an `exec` that rewires descriptors, a
/// function whose output goes where it is called, or an alias that renames a
/// pipeline stage. Any of them leaves every heredoc's output unproven.
fn output_may_be_replumbed<D: ast_grep_core::Doc>(root: &ast_grep_core::Node<'_, D>) -> bool {
    root.dfs().any(|node| match node.kind().as_ref() {
        "process_substitution" | "function_definition" => true,
        "command_name" => matches!(
            node.text().as_ref(),
            "exec" | "alias" | "enable" | "hash" | "coproc"
        ),
        _ => false,
    })
}

/// Where a `file_redirect` sends standard output, if it redirects it.
enum StdoutRedirect {
    /// It does not touch standard output.
    Untouched,
    /// To a plain, literal file (or `/dev/null`).
    File,
    /// Anywhere else: another descriptor, a device, a computed name.
    Elsewhere,
}

#[allow(clippy::needless_pass_by_value)]
fn stdout_redirect<D: ast_grep_core::Doc>(redirect: ast_grep_core::Node<'_, D>) -> StdoutRedirect {
    stdout_redirect_parts(redirect.children())
}

/// [`stdout_redirect`] over a redirect's children (or a prefix of them).
fn stdout_redirect_parts<'r, D: ast_grep_core::Doc + 'r>(
    children: impl Iterator<Item = ast_grep_core::Node<'r, D>>,
) -> StdoutRedirect {
    let mut descriptor: Option<String> = None;
    let mut operator: Option<String> = None;
    let mut destinations = Vec::new();
    for child in children {
        let kind = child.kind();
        match kind.as_ref() {
            "file_descriptor" => descriptor = Some(child.text().to_string()),
            ">" | ">>" | ">|" | "&>" | "&>>" | ">&" | "<" | "<&" | "<>" | ">&-" | "<&-" => {
                operator = Some(kind.to_string());
            }
            _ => destinations.push(child),
        }
    }
    let Some(operator) = operator else {
        return StdoutRedirect::Elsewhere;
    };
    let to_stdout = match operator.as_str() {
        ">" | ">>" | ">|" | ">&" | ">&-" => descriptor.as_deref().is_none_or(|fd| fd == "1"),
        "&>" | "&>>" => true,
        // An input redirect only matters when it names descriptor 1.
        _ => descriptor.as_deref() == Some("1"),
    };
    if !to_stdout {
        return StdoutRedirect::Untouched;
    }
    if !matches!(operator.as_str(), ">" | ">>" | ">|" | "&>" | "&>>" | ">&") {
        return StdoutRedirect::Elsewhere;
    }
    let [destination] = destinations.as_slice() else {
        return StdoutRedirect::Elsewhere;
    };
    let text = destination.text();
    let path = match destination.kind().as_ref() {
        "word" => text.as_ref(),
        "raw_string" => text.trim_matches('\''),
        "string"
            if destination
                .children()
                .all(|part| part.kind() == "string_content" || !part.is_named()) =>
        {
            text.trim_matches('"')
        }
        _ => return StdoutRedirect::Elsewhere,
    };
    if is_plain_file_path(path) {
        StdoutRedirect::File
    } else {
        StdoutRedirect::Elsewhere
    }
}

/// A literal path naming a plain file (or `/dev/null`): nothing the shell
/// computes, no descriptor number, and no device or descriptor path
/// (`/dev/stdout`, `/dev/fd/1`, `/proc/self/fd/1`, or one reached through
/// `..`).
fn is_plain_file_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains(['$', '`', '\\', '*', '?', '[', '{', '~'])
        && !path.starts_with(['-', '&'])
        && !path.bytes().all(|byte| byte.is_ascii_digit())
        && (path == "/dev/null" || !(path.contains("dev/") || path.contains("proc/")))
}

/// Whether leading assignments leave the named program the one it names:
/// `PATH=…`, `LD_PRELOAD=…` and their kin load other code, and
/// `RIPGREP_CONFIG_PATH=…` or `GREP_OPTIONS=…` add options.
fn assignments_keep_program(assignments: &[String]) -> bool {
    assignments.iter().all(|assignment| {
        shell_assignment_name(assignment).is_some_and(|var| {
            !(var.starts_with("LD_")
                || var.starts_with("DYLD_")
                || matches!(
                    var,
                    "PATH"
                        | "RIPGREP_CONFIG_PATH"
                        | "GREP_OPTIONS"
                        | "GCONV_PATH"
                        | "BASH_ENV"
                        | "ENV"
                ))
        })
    })
}

/// Whether a [`READ_ONLY_PIPE_STAGES`] program run with these operands and
/// leading assignments really only passes its input on as text, to standard
/// output or to plain files. `sort --compress-program=sh` and `rg --pre sh`
/// hand it to a program; `tee /dev/stderr`, `sort -o /dev/fd/3`, `uniq -
/// /dev/stderr` and `xxd - /dev/stderr` write it to a descriptor that a
/// redirect can point anywhere (`2>&1 >/dev/null | sh`); an assignment such
/// as `RIPGREP_CONFIG_PATH=…` or `LD_PRELOAD=…` changes what the program does
/// ([`assignments_keep_program`]).
fn read_only_stage_is_inert(name: &str, operands: &[String], assignments: &[String]) -> bool {
    if !READ_ONLY_PIPE_STAGES.contains(&name) {
        return false;
    }
    if !assignments_keep_program(assignments) {
        return false;
    }
    // Only these write their input anywhere but standard output: `tee` to
    // every file operand, `sort` to its `-o` value, `uniq` and `xxd` to the
    // file operand after their input. `rg` hands a file it searches to a
    // `--pre` program (perhaps one named in its config file).
    let mut options_ended = false;
    let mut output_value_next = false;
    let mut files = 0usize;
    for operand in operands {
        let word = unquoted_word(operand);
        // A computed word may be any option or path; single quotes keep a
        // `$` literal.
        let single_quoted = operand.len() >= 2
            && operand.starts_with('\'')
            && operand.ends_with('\'')
            && operand.matches('\'').count() == 2;
        if is_computed_word(operand) && !single_quoted {
            if matches!(name, "tee" | "sort" | "uniq" | "xxd" | "rg") {
                return false;
            }
            continue;
        }
        if std::mem::take(&mut output_value_next) {
            if !is_plain_file_path(word) {
                return false;
            }
            continue;
        }
        if !options_ended && word == "--" {
            options_ended = true;
            continue;
        }
        if !options_ended && word.len() > 1 && word.starts_with('-') {
            match name {
                // GNU getopt takes any unambiguous prefix of a long option:
                // `--co` is `--compress-program`, `--o` is `--output`.
                "sort" if word.starts_with("--co") => return false,
                "sort" if word.starts_with("--o") => match word.split_once('=') {
                    Some((_, path)) if !is_plain_file_path(path) => return false,
                    Some(_) => {}
                    None => output_value_next = true,
                },
                // A short-option cluster holding `o`: the rest of the word,
                // or the next one, is the output file.
                "sort" if !word.starts_with("--") && word.contains('o') => {
                    let after = word.split_once('o').map_or("", |(_, after)| after);
                    if after.is_empty() {
                        output_value_next = true;
                    } else if !is_plain_file_path(after) {
                        return false;
                    }
                }
                "rg" if word.starts_with("--pre") && word != "--pretty" => return false,
                _ => {}
            }
            continue;
        }
        files += 1;
        let written = match name {
            "tee" => true,
            "uniq" | "xxd" => files >= 2,
            _ => false,
        };
        if written && !is_plain_file_path(word) {
            return false;
        }
        if name == "rg" && (word.contains("dev/") || word.contains("proc/")) {
            return false;
        }
    }
    !output_value_next
}

/// What one pipeline stage after a heredoc's command does with the text.
enum PipeStage {
    /// Reads and passes it on ([`READ_ONLY_PIPE_STAGES`]).
    PassesOn,
    /// Reads it and files its own output in a plain file.
    Files,
    /// May run it ([`stage_runs_received_text`], or a compound stage).
    Runs,
    /// Consumes it some other way, or sends it somewhere unproven.
    Other,
}

#[allow(clippy::needless_pass_by_value)]
fn classify_pipe_stage<D: ast_grep_core::Doc>(stage: ast_grep_core::Node<'_, D>) -> PipeStage {
    let (command, mut redirects): (_, Vec<_>) = match stage.kind().as_ref() {
        "command" => (stage.clone(), Vec::new()),
        "redirected_statement" => {
            let mut children = stage.children();
            let Some(first) = children.next() else {
                return PipeStage::Runs;
            };
            let mut redirects = Vec::new();
            for child in children {
                if child.kind() != "file_redirect" {
                    // A heredoc or here-string of its own replaces the text.
                    return PipeStage::Other;
                }
                redirects.push(child);
            }
            match first.kind().as_ref() {
                "command" => (first, redirects),
                // `| grep x | sort > out` parses as the rest of the pipeline
                // under one redirect: follow its stages, then the redirect.
                "pipeline" => {
                    let mut stages = Vec::new();
                    pipeline_stages_after(&first, 0, &mut stages);
                    return match follow_pipe_stages(stages) {
                        Some(HeredocOutput::Executes) => PipeStage::Runs,
                        Some(HeredocOutput::Escapes) => PipeStage::Other,
                        Some(HeredocOutput::Contained) => PipeStage::Files,
                        None => stage_redirects_outcome(redirects),
                    };
                }
                _ => return PipeStage::Runs,
            }
        }
        // `| while read l; do eval "$l"; done`, `| (sh)`, `| { …; }`: a
        // compound stage may run anything it reads.
        _ => return PipeStage::Runs,
    };
    let mut program = None;
    let mut operands = Vec::new();
    let mut assignments = Vec::new();
    for child in command.children() {
        match child.kind().as_ref() {
            "command_name" => program = Some(child.text().to_string()),
            "variable_assignment" => assignments.push(child.text().to_string()),
            "file_redirect" => redirects.push(child),
            _ if program.is_some() => operands.push(child.text().to_string()),
            _ => {}
        }
    }
    let Some(program) = program else {
        return PipeStage::Runs;
    };
    if stage_runs_received_text(&program, &operands) {
        return PipeStage::Runs;
    }
    if !literal_program_name(&program)
        .is_some_and(|name| read_only_stage_is_inert(name, &operands, &assignments))
    {
        return PipeStage::Other;
    }
    stage_redirects_outcome(redirects)
}

/// Whether the command that owns a heredoc only passes its body on as text
/// (or ignores it), so that the body is as contained as that command's
/// output: a [`READ_ONLY_PIPE_STAGES`] program with inert operands, `echo`
/// or `printf` (which never read it), or `git`, `gh` and `spx`, whose
/// structured-stdin data contract the masker proves separately. `read c`
/// keeps the body for a later `$c`, sed's `e` and awk's `system()` run it,
/// `nc` and `curl` send it to a peer, and `tee /dev/stderr` writes it where
/// `2>&1 >/dev/null | sh` points.
#[allow(clippy::needless_pass_by_value)]
fn owner_passes_body_through<D: ast_grep_core::Doc>(command: ast_grep_core::Node<'_, D>) -> bool {
    let mut program = None;
    let mut operands = Vec::new();
    let mut assignments = Vec::new();
    for child in command.children() {
        match child.kind().as_ref() {
            "command_name" => program = Some(child.text().to_string()),
            "variable_assignment" if program.is_none() => {
                assignments.push(child.text().to_string());
            }
            "file_redirect" => {}
            _ if program.is_some() => operands.push(child.text().to_string()),
            _ => {}
        }
    }
    let Some(name) = program.as_deref().and_then(literal_program_name) else {
        return false;
    };
    if matches!(name, "echo" | "printf" | "git" | "gh" | "spx") {
        return assignments_keep_program(&assignments);
    }
    read_only_stage_is_inert(name, &operands, &assignments)
}

/// What a read-only stage's own redirects make of the text it passes on.
fn stage_redirects_outcome<D: ast_grep_core::Doc>(
    redirects: Vec<ast_grep_core::Node<'_, D>>,
) -> PipeStage {
    let mut filed = false;
    for redirect in redirects {
        match stdout_redirect(redirect) {
            StdoutRedirect::Untouched => {}
            StdoutRedirect::File => filed = true,
            StdoutRedirect::Elsewhere => return PipeStage::Other,
        }
    }
    if filed {
        PipeStage::Files
    } else {
        PipeStage::PassesOn
    }
}

/// The stages of `pipeline` (nested pipelines flattened) that start at or
/// after `from`.
fn pipeline_stages_after<'r, D: ast_grep_core::Doc>(
    pipeline: &ast_grep_core::Node<'r, D>,
    from: usize,
    stages: &mut Vec<ast_grep_core::Node<'r, D>>,
) {
    for child in pipeline.children() {
        if !child.is_named() || child.range().start < from {
            continue;
        }
        if child.kind() == "pipeline" {
            pipeline_stages_after(&child, from, stages);
        } else {
            stages.push(child);
        }
    }
}

/// Where the text reaching `stages` in order ends up: `None` when it passes
/// through all of them still contained (it continues to whatever receives
/// the pipeline's output), otherwise the answer.
fn follow_pipe_stages<D: ast_grep_core::Doc>(
    stages: Vec<ast_grep_core::Node<'_, D>>,
) -> Option<HeredocOutput> {
    let mut escapes = false;
    for stage in stages {
        match classify_pipe_stage(stage) {
            PipeStage::PassesOn => {}
            PipeStage::Files if !escapes => return Some(HeredocOutput::Contained),
            PipeStage::Files | PipeStage::Other => escapes = true,
            PipeStage::Runs => return Some(HeredocOutput::Executes),
        }
    }
    escapes.then_some(HeredocOutput::Escapes)
}

/// Where the standard output of the command that owns `redirect` (a
/// `heredoc_redirect` or `herestring_redirect`) goes, when the parse tree
/// proves it. `None` whenever it does not — an unexpected node, a parse
/// recovery in the operator's line, a delimiter the grammar read past a
/// metacharacter, a descriptor duplication, a substitution — and the caller
/// then decides from the text instead.
///
/// tree-sitter-bash hangs the rest of the heredoc's line under the
/// `heredoc_redirect` node (`<<EOF > notes.md`, `<<EOF | sh`, `<<EOF && x`),
/// so those children are read as the owning command's redirects and pipe up
/// to the first list operator.
fn heredoc_output<D: ast_grep_core::Doc>(
    redirect: &ast_grep_core::Node<'_, D>,
) -> Option<HeredocOutput> {
    let statement = redirect.parent()?;
    if statement.kind() != "redirected_statement" {
        return None;
    }
    let mut children = statement.children();
    let first = children.next()?;
    // `cd d && cat <<EOF > f` and `x | cat <<EOF` parse as a list or pipeline
    // whose LAST command owns the heredoc and the redirects after it.
    let command = match first.kind().as_ref() {
        "command" => first,
        "list" | "pipeline" => {
            let last = first
                .children()
                .filter(ast_grep_core::Node::is_named)
                .last()?;
            if last.kind() != "command" {
                return None;
            }
            last
        }
        _ => return None,
    };
    // The body is only as contained as the output when its owner passes it
    // through untouched; otherwise nothing about it is proven here.
    if !owner_passes_body_through(command.clone()) {
        return None;
    }
    let mut filed = false;
    let mut account = |stdout: StdoutRedirect| -> Option<()> {
        match stdout {
            StdoutRedirect::Untouched => Some(()),
            StdoutRedirect::File => {
                filed = true;
                Some(())
            }
            StdoutRedirect::Elsewhere => None,
        }
    };
    for child in command.children() {
        if child.kind() == "file_redirect" {
            account(stdout_redirect(child))?;
        }
    }
    let mut redirects_seen = 0usize;
    for child in children {
        match child.kind().as_ref() {
            "file_redirect" => account(stdout_redirect(child))?,
            "heredoc_redirect" | "herestring_redirect" => redirects_seen += 1,
            _ => return None,
        }
    }
    // Two heredocs on one command share a header the grammar splits
    // arbitrarily between them.
    if redirects_seen != 1 {
        return None;
    }

    let mut piped_into = None;
    // The words of a pipeline stage the grammar swallowed into a redirect.
    let mut swallowed_stage: Option<Vec<String>> = None;
    if redirect.kind() == "heredoc_redirect" {
        let line_end = redirect_line_end(redirect);
        let mut list_ended = false;
        for child in redirect.children() {
            let kind = child.kind();
            if matches!(kind.as_ref(), "<<" | "<<-" | "heredoc_body" | "heredoc_end") {
                continue;
            }
            // The header is the operator's own line. A child reaching past it
            // means the grammar mis-split the line (`cat <<EOF |` continues
            // after the body, but parses as a pipe into the body's first
            // line), and a recovery anywhere in it means the same — except the
            // one the grammar makes of `cat <<EOF >log | sh` and `<<EOF 2>&1 |
            // sh`, a redirect that swallowed the pipe and the next stage.
            if child.range().end > line_end {
                return None;
            }
            if child.dfs().any(|node| node.is_error()) {
                if kind != "file_redirect"
                    || list_ended
                    || piped_into.is_some()
                    || swallowed_stage.is_some()
                {
                    return None;
                }
                let (stdout, stage) = redirect_with_swallowed_pipe(&child)?;
                account(stdout)?;
                swallowed_stage = Some(stage);
                continue;
            }
            if kind == "heredoc_start" {
                // `<<A; sh <<B` parses with `A;` as the delimiter.
                if child
                    .text()
                    .contains([';', '&', '|', '<', '>', '(', ')', ' ', '\t'])
                {
                    return None;
                }
                continue;
            }
            if list_ended {
                continue;
            }
            match kind.as_ref() {
                "file_redirect" if piped_into.is_none() && swallowed_stage.is_none() => {
                    account(stdout_redirect(child))?;
                }
                "pipeline"
                    if piped_into.is_none()
                        && swallowed_stage.is_none()
                        && child
                            .children()
                            .next()
                            .is_some_and(|first| matches!(first.kind().as_ref(), "|" | "|&")) =>
                {
                    piped_into = Some(child);
                }
                "&&" | "||" | ";" | "&" => list_ended = true,
                _ => return None,
            }
        }
    }
    if filed {
        return Some(HeredocOutput::Contained);
    }
    if let Some(stage) = swallowed_stage {
        // Only the stage's own words survived the recovery: answer when it
        // runs the text, and leave anything else to the text-level check.
        let (program, operands) = stage.split_first()?;
        return stage_runs_received_text(program, operands).then_some(HeredocOutput::Executes);
    }
    if let Some(pipeline) = piped_into {
        let mut stages = Vec::new();
        pipeline_stages_after(&pipeline, 0, &mut stages);
        if let Some(answer) = follow_pipe_stages(stages) {
            return Some(answer);
        }
    }

    // The statement's output is its enclosing construct's.
    let mut node = statement;
    loop {
        let parent = node.parent()?;
        match parent.kind().as_ref() {
            "program" => return Some(HeredocOutput::Contained),
            "list"
            | "subshell"
            | "compound_statement"
            | "if_statement"
            | "elif_clause"
            | "else_clause"
            | "while_statement"
            | "for_statement"
            | "c_style_for_statement"
            | "do_group"
            | "case_statement"
            | "case_item"
            | "negated_command" => {}
            "pipeline" => {
                let mut stages = Vec::new();
                pipeline_stages_after(&parent, node.range().end, &mut stages);
                if let Some(answer) = follow_pipe_stages(stages) {
                    return Some(answer);
                }
            }
            "redirected_statement" => {
                let mut filed = false;
                for child in parent.children() {
                    if child.range() == node.range() {
                        continue;
                    }
                    if child.kind() != "file_redirect" {
                        return None;
                    }
                    match stdout_redirect(child) {
                        StdoutRedirect::Untouched => {}
                        StdoutRedirect::File => filed = true,
                        StdoutRedirect::Elsewhere => return None,
                    }
                }
                if filed {
                    return Some(HeredocOutput::Contained);
                }
            }
            _ => return None,
        }
        node = parent;
    }
}

/// Split the redirect tree-sitter-bash makes of `>log | sh` (or `2>&1 |
/// sh`): the redirect proper, then an `ERROR` holding the pipe, then the next
/// stage's words. `None` for any other recovery.
fn redirect_with_swallowed_pipe<D: ast_grep_core::Doc>(
    redirect: &ast_grep_core::Node<'_, D>,
) -> Option<(StdoutRedirect, Vec<String>)> {
    let children: Vec<_> = redirect.children().collect();
    let error_at = children.iter().position(|child| child.kind() == "ERROR")?;
    let error = &children[error_at];
    if !matches!(error.text().trim(), "|" | "|&")
        || error.dfs().filter(ast_grep_core::Node::is_error).count() != 1
    {
        return None;
    }
    let mut stage = Vec::new();
    for child in &children[error_at + 1..] {
        if !matches!(
            child.kind().as_ref(),
            "word"
                | "string"
                | "raw_string"
                | "number"
                | "simple_expansion"
                | "expansion"
                | "concatenation"
        ) || child.dfs().any(|node| node.is_error())
        {
            return None;
        }
        stage.push(child.text().to_string());
    }
    if stage.is_empty() {
        return None;
    }
    Some((
        stdout_redirect_parts(children[..error_at].iter().cloned()),
        stage,
    ))
}

/// The end of the line holding the start of `node`.
fn redirect_line_end<D: ast_grep_core::Doc>(node: &ast_grep_core::Node<'_, D>) -> usize {
    let start = node.range().start;
    let text = node.text();
    text.find(['\n', '\r'])
        .map_or(start + text.len(), |at| start + at)
}

/// Whether `outside` — the command with its heredoc bodies blanked — may run
/// the output of a heredoc's command, for when the parse tree could not show
/// where that output goes. Coarse in the strict direction: a pipe into a
/// program that runs what it receives ([`stage_runs_received_text`]), a line
/// that ends in a pipe (the pipeline continues past the body), a process
/// substitution, `eval`/`source`/`.`/`exec`/`xargs`/…, or such a program fed
/// a computed operand (`sh -c "$x"`, `bash "$(cat <<EOF …)"`) or a redirect.
fn command_may_run_heredoc_output(outside: &str) -> bool {
    use crate::normalize::NormalizeTokenKind;
    if outside.contains(">(") || outside.contains("<(") {
        return true;
    }
    let tokens = crate::normalize::tokenize_for_normalization(outside);
    let mut trailing_pipe = false;
    let mut previous_separator: Option<&str> = None;
    let mut words: Vec<&str> = Vec::new();
    let segment_runs = |separator: Option<&str>, words: &[&str], trailing_pipe: bool| -> bool {
        // Redirect words are neither the program nor operands (`sh < x` reads
        // `x`, and a stdin redirect on a runner is input it may run); a group
        // brace, an assignment or a reserved word before the program is not
        // the program either.
        let mut program = None;
        let mut operands: Vec<String> = Vec::new();
        let mut redirected_input = false;
        let mut redirect_target = false;
        for word in words.iter().copied() {
            if std::mem::take(&mut redirect_target) {
                continue;
            }
            let operator = word.trim_start_matches(|c: char| c.is_ascii_digit());
            if operator.starts_with(['<', '>']) || operator.starts_with("&>") {
                redirected_input |= operator.starts_with('<');
                redirect_target = operator.trim_start_matches(['<', '>', '&', '|']).is_empty();
                continue;
            }
            if program.is_some() {
                operands.push(word.to_string());
            } else if !is_shell_env_assignment(word)
                && !matches!(
                    word,
                    "{" | "}"
                        | "!"
                        | "if"
                        | "then"
                        | "do"
                        | "else"
                        | "elif"
                        | "while"
                        | "until"
                        | "fi"
                        | "done"
                        | "esac"
                )
            {
                program = Some(dequoted_executable_word(word));
            }
        }
        let Some(program) = program else {
            return false;
        };
        if !stage_runs_received_text(&program, &operands) {
            return false;
        }
        let name = literal_program_name(&program).unwrap_or("");
        let piped = matches!(separator, Some("|" | "|&")) || trailing_pipe;
        piped
            || matches!(
                name,
                "eval" | "source" | "." | "exec" | "xargs" | "parallel" | "watch" | "at" | "batch"
            )
            || literal_program_name(&program).is_none()
            || redirected_input
            || operands.iter().any(|operand| is_computed_word(operand))
    };
    for token in &tokens {
        let Some(text) = token.text(outside) else {
            continue;
        };
        if token.kind == NormalizeTokenKind::Word {
            words.push(text);
            continue;
        }
        if segment_runs(previous_separator, &words, trailing_pipe) {
            return true;
        }
        // A line that ends in a pipe continues on a later one — after the
        // heredoc's body, in `cat <<EOF |` — so from there on every program
        // may be the one it feeds.
        if text == "\n" && words.is_empty() && matches!(previous_separator, Some("|" | "|&")) {
            trailing_pipe = true;
        }
        words.clear();
        previous_separator = Some(text);
    }
    segment_runs(previous_separator, &words, trailing_pipe)
}

/// Whether an expanding (unquoted-delimiter) heredoc body holds syntax the
/// shell may execute while reading it: `$(…)`, backquotes, or bash 5.3's
/// `${ cmd; }` / `${| cmd; }` in-shell substitutions. A body without any of
/// them only undergoes parameter and arithmetic expansion, which run nothing.
fn expanding_body_may_execute(body: &str) -> bool {
    body.contains("$(")
        || body.contains('`')
        || contains_bash_funsub(body)
        || continuation_forms_substitution(body)
}

/// Whether removing the body's line continuations creates a substitution:
/// an expanding here-document joins `\<newline>` like the shell does
/// elsewhere, so `$\` at the end of one line and `(cmd)` on the next is
/// `$(cmd)`. A backslash that is itself escaped (`\\<newline>`) does not
/// continue the line. Linear.
fn continuation_forms_substitution(body: &str) -> bool {
    if !body.contains("\\\n") && !body.contains("\\\r\n") {
        return false;
    }
    let bytes = body.as_bytes();
    let mut joined = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            match bytes.get(index + 1) {
                Some(b'\n') => {
                    index += 2;
                    continue;
                }
                Some(b'\r') if bytes.get(index + 2) == Some(&b'\n') => {
                    index += 3;
                    continue;
                }
                Some(&escaped) => {
                    joined.extend_from_slice(&[b'\\', escaped]);
                    index += 2;
                    continue;
                }
                None => {}
            }
        }
        joined.push(bytes[index]);
        index += 1;
    }
    let joined = String::from_utf8_lossy(&joined);
    joined.matches("$(").count() > body.matches("$(").count()
        || (contains_bash_funsub(&joined) && !contains_bash_funsub(body))
}

/// Bash 5.3 runs `${ cmd; }` and `${| cmd; }` in the current shell. The
/// grammar does not model them, so their presence makes a body unmaskable.
fn contains_bash_funsub(text: &str) -> bool {
    text.match_indices("${").any(|(at, _)| {
        matches!(
            text.as_bytes().get(at + 2),
            Some(b' ' | b'\t' | b'\n' | b'\r' | b'|')
        )
    })
}

/// The spans of an expanding heredoc body that the shell executes while
/// reading it, as absolute byte ranges.
///
/// An unquoted delimiter (`cat <<EOF > notes.md`) expands the body before the
/// target reads it, so its `$(…)` and backquoted substitutions run even when
/// the target only stores the text. Everything else in the body — the prose
/// of a note or a commit message — is data for a data sink, exactly as a
/// quoted body is. The spans returned are the outermost `command_substitution`
/// and `arithmetic_expansion` nodes the grammar parsed in the body (all
/// arithmetic is kept visible: bash re-reads some `$((…))` as a command
/// substitution holding a subshell) plus the backquoted substitutions the
/// grammar leaves as plain text, found with the here-document escape rules.
///
/// `None` — the body must stay whole — when the grammar recovered from an
/// error inside the body, a backquote is unterminated, a live `$(` lies
/// outside every span, or the body holds a bash 5.3 `${ …; }` substitution.
#[allow(clippy::needless_pass_by_value)]
fn expanding_body_live_spans<D: ast_grep_core::Doc>(
    body: ast_grep_core::Node<'_, D>,
) -> Option<Vec<Range<usize>>> {
    let text = body.text();
    let text = text.as_ref();
    if !expanding_body_may_execute(text) {
        return Some(Vec::new());
    }
    if contains_bash_funsub(text) || continuation_forms_substitution(text) {
        return None;
    }
    let base = body.range().start;
    let bytes = text.as_bytes();
    // A backslash quotes `$` in a here-document (POSIX 2.7.4), so `\$(…)` is
    // text; `\\$(…)` is an escaped backslash before a live substitution.
    let escaped = |at: usize| {
        bytes[..at]
            .iter()
            .rev()
            .take_while(|byte| **byte == b'\\')
            .count()
            % 2
            == 1
    };
    let mut spans: Vec<Range<usize>> = Vec::new();
    let mut recovered = false;
    collect_body_expansion_spans(body.clone(), &mut spans, &mut recovered);
    if recovered
        || spans
            .iter()
            .any(|span| span.start < base || span.end > base + text.len())
    {
        return None;
    }
    // Relative to the body from here on. Every arithmetic expansion is kept,
    // even one that looks numeric: what bash makes of an unparsable `$((…))`
    // (a subshell, or an error) is not decided here, and v0.15.1 judged a
    // multi-line one as a command.
    let mut spans: Vec<Range<usize>> = spans
        .into_iter()
        .map(|span| span.start - base..span.end - base)
        .filter(|span| !escaped(span.start))
        .collect();
    spans.sort_by_key(|span| span.start);
    let opaque: Vec<(usize, usize)> = spans.iter().map(|span| (span.start, span.end)).collect();
    let backquoted = scan_backquoted_substitutions(text, 0, &opaque).ok()?;
    spans.extend(backquoted.into_iter().map(|found| found.start..found.end));
    spans.sort_by_key(|span| span.start);
    // Every live `$(` must sit inside a kept span; the list is sorted, so one
    // forward pass checks them all.
    let mut next = 0usize;
    for (at, _) in text.match_indices("$(") {
        while spans.get(next).is_some_and(|span| span.end <= at) {
            next += 1;
        }
        let covered = spans.get(next).is_some_and(|span| span.start <= at);
        if !covered && !escaped(at) {
            return None;
        }
    }
    Some(
        spans
            .into_iter()
            .map(|span| span.start + base..span.end + base)
            .collect(),
    )
}

#[allow(clippy::needless_pass_by_value)]
fn collect_body_expansion_spans<D: ast_grep_core::Doc>(
    node: ast_grep_core::Node<'_, D>,
    spans: &mut Vec<Range<usize>>,
    recovered: &mut bool,
) {
    match node.kind().as_ref() {
        "ERROR" => *recovered = true,
        "command_substitution" | "arithmetic_expansion" => spans.push(node.range()),
        _ => {
            for child in node.children() {
                collect_body_expansion_spans(child, spans, recovered);
            }
        }
    }
}

/// Whether a heredoc delimiter suppresses expansion (`<<'EOF'`, `<<"EOF"`,
/// `<<E\OF`, `<<\EOF`), judged from the delimiter word alone.
///
/// `redirect_text` is the full `heredoc_redirect` node text, `operator_offset`
/// the index of its `<<`, and `delimiter_end` the end (relative to the node)
/// of the `heredoc_start` node. tree-sitter-bash hangs the rest of the
/// statement — a trailing pipeline or file redirect — under the same
/// `heredoc_redirect` node, so an earlier version of this check that scanned
/// the whole header line mistook `cat <<EOF | tee "out"` and
/// `cat <<EOF > 'out'` for non-expanding heredocs and masked a live `$(…)`
/// in the body away from evaluation. Only the bytes between the operator and
/// the end of the delimiter word carry the quoting; the grammar's normalized
/// `heredoc_start` text is consulted as well in case a grammar version keeps
/// the quote bytes only there.
fn heredoc_delimiter_is_quoted(
    redirect_text: &str,
    operator_offset: usize,
    delimiter_end: usize,
    delimiter_text: &str,
) -> bool {
    const QUOTING_BYTES: [char; 3] = ['\'', '"', '\\'];
    let word_start = operator_offset.saturating_add(2);
    // An unusable slice contributes nothing: over-reporting quoting would
    // mask an expanding body away from evaluation (the fail-open direction),
    // whereas the normalized delimiter text below still catches real quotes.
    let delimiter_word = redirect_text.get(word_start..delimiter_end).unwrap_or("");
    delimiter_word.contains(QUOTING_BYTES) || delimiter_text.contains(QUOTING_BYTES)
}

/// Every non-whitespace byte of `input` replaced with `_`, whitespace kept:
/// word boundaries survive, the text does not, and the length is unchanged.
fn mask_preserve_whitespace(input: &str) -> String {
    input
        .bytes()
        .map(|byte| {
            if byte.is_ascii_whitespace() {
                char::from(byte)
            } else {
                '_'
            }
        })
        .collect()
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

/// Largest source [`extract_posix_command_substitutions`] will parse; longer
/// input is refused for its size rather than its syntax.
pub(crate) const MAX_SUBSTITUTION_SOURCE_BYTES: usize = 256 * 1024;

/// Stages one pipeline may have before a command is not handed to the bash
/// parser. tree-sitter-bash parses a single long pipeline in superlinear
/// time: `x | cat | … | sh -c ls` with 6,000 stages held one parse ~0.7 s in
/// an optimized build and the shipped hook 2.5–9 s, past its own deadline.
/// No real command comes near this; past it the reading is refused.
pub(crate) const MAX_PARSED_PIPELINE_STAGES: usize = 1024;

/// Stages in the command's longest pipeline, by the tokenizer: `|` (and
/// `|&`) joins two stages; any other separator (`;`, `&&`, `||`, `&`, a
/// newline, a parenthesis) starts a new pipeline. Linear.
pub(crate) fn longest_pipeline_stages(command: &str) -> usize {
    if !command.contains('|') {
        return 1;
    }
    let tokens = crate::normalize::tokenize_for_normalization(command);
    let mut longest = 1usize;
    let mut stages = 1usize;
    let mut previous_pipe_end = None;
    for token in &tokens {
        if token.kind != crate::normalize::NormalizeTokenKind::Separator {
            continue;
        }
        match token.text(command) {
            Some("|") => {
                stages += 1;
                longest = longest.max(stages);
                previous_pipe_end = Some(token.byte_range.end);
                continue;
            }
            // `|&` arrives as `|` then `&`.
            Some("&") if previous_pipe_end == Some(token.byte_range.start) => {}
            _ => stages = 1,
        }
        previous_pipe_end = None;
    }
    longest
}

pub fn extract_posix_command_substitutions(
    content: &str,
) -> Result<Vec<PosixCommandSubstitution>, PosixCommandSubstitutionParseError> {
    // Keep the common evaluator path independent of tree-sitter. Backticks
    // and `$(` are the only POSIX command-substitution introducers; arithmetic
    // expansion may pass this prefilter, but the AST will not classify it as a
    // command substitution.
    // A line continuation can join `$` and `(` (`$\<newline>(cmd)`); such
    // input goes to the parse, where an expanding heredoc body holding one
    // fails closed.
    if content.trim().is_empty()
        || (!content.contains("$(")
            && !content.contains('`')
            && !content.contains("$\\\n")
            && !content.contains("$\\\r\n"))
    {
        return Ok(Vec::new());
    }
    if content.len() > MAX_SUBSTITUTION_SOURCE_BYTES
        || longest_pipeline_stages(content) > MAX_PARSED_PIPELINE_STAGES
        // `$\<newline>(cmd)` is `$(cmd)` once the shell joins the line, but
        // the grammar reads `$` and `(cmd)` apart and reports no substitution.
        || continuation_forms_substitution(content)
    {
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
    } else if kind == "heredoc_redirect" {
        collect_heredoc_redirect_substitutions(node, substitutions, parse_error, error_ranges);
        return;
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
            let range = node.range();
            let body = if text.starts_with('`') {
                // The outer backquote layer consumes its escapes before the
                // nested shell parses the body (see
                // `unescape_backquoted_body`).
                unescape_backquoted_body(body)
            } else {
                body.to_string()
            };
            substitutions.push(PosixCommandSubstitution {
                body,
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

/// Enumerate the substitutions under one `heredoc_redirect` node.
///
/// The children — the `heredoc_body` plus any pipeline or file redirect the
/// grammar hangs under the same node — are walked as usual, which captures
/// the `$(…)` nodes tree-sitter-bash parses inside an expanding body. The
/// grammar leaves backquoted substitutions in that body as plain
/// `heredoc_content`, yet the outer shell expands `` `…` `` exactly like
/// `$(…)` before the target ever receives the body, so those are enumerated
/// by hand (#377). A quoted delimiter (`<<'EOF'`, `<<"EOF"`, `<<\EOF`)
/// suppresses expansion, so such bodies are left alone.
fn collect_heredoc_redirect_substitutions<D: ast_grep_core::Doc>(
    node: ast_grep_core::Node<'_, D>,
    substitutions: &mut Vec<PosixCommandSubstitution>,
    parse_error: &mut bool,
    error_ranges: &mut Vec<(usize, usize)>,
) {
    let text = node.text();
    let node_start = node.range().start;
    let Some(operator_offset) = text.find("<<") else {
        *parse_error = true;
        return;
    };
    let mut delimiter_quoted = false;
    let mut body = None;
    for child in node.children() {
        match child.kind().as_ref() {
            "heredoc_start" => {
                delimiter_quoted |= heredoc_delimiter_is_quoted(
                    text.as_ref(),
                    operator_offset,
                    child.range().end.saturating_sub(node_start),
                    child.text().as_ref(),
                );
            }
            "heredoc_body" => body = Some(child),
            _ => {}
        }
    }

    let first_child_index = substitutions.len();
    for child in node.children() {
        collect_command_substitutions_recursive(child, substitutions, parse_error, error_ranges);
    }
    if delimiter_quoted {
        return;
    }
    let Some(body) = body else {
        return;
    };
    let body_range = body.range();
    let body_text = body.text();
    // Everything the walk above found under this redirect, in source order.
    let mut parsed = substitutions.split_off(first_child_index);
    parsed.sort_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| right.end.cmp(&left.end))
    });
    // Spans the grammar already parsed inside the body. The scanner treats
    // them as opaque so a backtick inside a parsed `$(…)` can neither open
    // nor close a backquoted span; their bodies are evaluated on their own.
    let opaque: Vec<(usize, usize)> = parsed
        .iter()
        .filter(|found| found.start >= body_range.start && found.end <= body_range.end)
        .map(|found| (found.start - body_range.start, found.end - body_range.start))
        .collect();
    match scan_backquoted_substitutions(body_text.as_ref(), body_range.start, &opaque) {
        Ok(backquoted) => {
            // A parsed `$(…)` sitting inside a backquoted span is reached
            // again when the evaluator recurses into that span's body; drop
            // the direct entry so it is not evaluated twice. Both lists are
            // sorted and the backquoted spans do not overlap each other, so a
            // single forward pass finds the only span that can enclose each
            // entry (bounded work even for a substitution-dense body).
            let mut outer_index = 0;
            for found in parsed {
                while backquoted
                    .get(outer_index)
                    .is_some_and(|outer| outer.end <= found.start)
                {
                    outer_index += 1;
                }
                let shadowed = backquoted
                    .get(outer_index)
                    .is_some_and(|outer| found.start > outer.start && found.end < outer.end);
                if !shadowed {
                    substitutions.push(found);
                }
            }
            substitutions.extend(backquoted);
        }
        Err(PosixCommandSubstitutionParseError) => {
            substitutions.extend(parsed);
            *parse_error = true;
        }
    }
}

/// Scan an expanding heredoc body for backquoted command substitutions.
///
/// `opaque` lists byte spans, relative to `body` and sorted by start, that
/// tree-sitter already parsed as substitutions; each is skipped whole
/// wherever it sits. Escapes follow the here-document rules (POSIX 2.7.4): a
/// backslash quotes only the byte after it, so a backtick directly after a
/// backslash never delimits a substitution, while `\\`` is an escaped
/// backslash followed by a live backtick. An unterminated backquote is a
/// shell syntax error whose extent cannot be bounded, so it fails closed.
fn scan_backquoted_substitutions(
    body: &str,
    base: usize,
    opaque: &[(usize, usize)],
) -> Result<Vec<PosixCommandSubstitution>, PosixCommandSubstitutionParseError> {
    let bytes = body.as_bytes();
    let mut found = Vec::new();
    let mut open: Option<usize> = None;
    let mut next_opaque = 0;
    let mut index = 0;
    while index < bytes.len() {
        while opaque
            .get(next_opaque)
            .is_some_and(|&(start, _)| start < index)
        {
            next_opaque += 1;
        }
        if let Some(&(start, end)) = opaque.get(next_opaque) {
            if start == index {
                next_opaque += 1;
                index = end.max(index + 1);
                continue;
            }
        }
        match bytes[index] {
            b'\\' => {
                // Skip the quoted byte. Multi-byte UTF-8 continuation bytes
                // are never ASCII, so landing inside a code point cannot
                // produce a false backtick or backslash match.
                index += 2;
                continue;
            }
            b'`' => {
                if let Some(start) = open.take() {
                    found.push(PosixCommandSubstitution {
                        body: unescape_backquoted_body(&body[start + 1..index]),
                        start: base + start,
                        end: base + index + 1,
                    });
                } else {
                    open = Some(index);
                }
            }
            _ => {}
        }
        index += 1;
    }
    if open.is_some() {
        return Err(PosixCommandSubstitutionParseError);
    }
    Ok(found)
}

/// Apply the backquote layer's escape processing to a substitution body.
///
/// Within backquotes a backslash keeps its literal meaning except before
/// `$`, `` ` ``, or `\`, where it quotes that byte (POSIX 2.6.3). The nested
/// shell parse must see the post-escape text: `` `echo \$(rm -rf ~)` `` runs
/// `rm` because the inner shell receives a live `$(…)`, and `` \`…\` `` is a
/// nested backquoted substitution. Leaving the escapes in place made that
/// `$(…)` inert to the nested parse.
fn unescape_backquoted_body(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(quoted) = chars.next_if(|next| matches!(next, '$' | '`' | '\\')) {
                out.push(quoted);
                continue;
            }
        }
        out.push(ch);
    }
    out
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

    /// Eighth review: an expanding data body keeps exactly what the shell
    /// runs while reading it — `$(…)`, backquotes, arithmetic that may be a
    /// subshell — and masks the prose around it, with `_` so a substitution
    /// is not moved to a word start. Bodies whose substitutions cannot be
    /// bounded stay whole.
    #[test]
    fn expanding_data_bodies_keep_only_their_substitutions() {
        let prose = "cat <<EOF > notes.md\nwatch 'git reset --hard'\nEOF";
        let masked = mask_non_expanding_data_heredocs(prose);
        assert!(!masked.contains("watch"), "{masked:?}");
        assert_eq!(masked.len(), prose.len());

        for (command, kept) in [
            ("cat <<EOF > n\nrun $(date) now\nEOF", "$(date)"),
            ("cat <<EOF > n\nrun `date` now\nEOF", "`date`"),
            ("cat <<EOF > n\n${x:-$(rm -rf ~/a)}\nEOF", "$(rm -rf ~/a)"),
            (
                "cat <<EOF > n\n$(( a[$(rm -rf ~/a)] ))\nEOF",
                "$(rm -rf ~/a)",
            ),
            ("cat <<EOF > n\n\\\\$(rm -rf ~/a)\nEOF", "$(rm -rf ~/a)"),
            (
                "cat <<EOF > n\n$(cat <<X\nrm -rf ~/a\nX\n)\nEOF",
                "rm -rf ~/a",
            ),
        ] {
            let masked = mask_non_expanding_data_heredocs(command);
            assert!(masked.contains(kept), "{command:?} -> {masked:?}");
            assert!(!masked.contains("run "), "{command:?} -> {masked:?}");
            assert_eq!(masked.len(), command.len());
        }
        let around = mask_non_expanding_data_heredocs("cat <<EOF > n\nrun ($(date)) x\nEOF");
        assert!(around.contains("___ _$(date)_ _"), "{around:?}");

        // Arithmetic is kept, numeric or not, and the prose around it is
        // still masked. (An escaped `\$(…)` defeats the grammar, and the
        // recovery path keeps such a body whole.)
        let numeric = "cat <<EOF > n\n$((1+2)) git reset --hard\nEOF";
        let masked = mask_non_expanding_data_heredocs(numeric);
        assert!(masked.contains("$((1+2))"), "{masked:?}");
        assert!(!masked.contains("git reset"), "{masked:?}");
        let multiline = "cat <<EOF > n\n$((\nrm -rf ~/a\n))\nEOF";
        let masked = mask_non_expanding_data_heredocs(multiline);
        assert!(masked.contains("rm -rf ~/a"), "{masked:?}");

        // Unbounded: a continuation that forms `$(`, a bash 5.3 `${ …; }`,
        // an unterminated backquote. The whole body stays.
        for command in [
            "cat <<EOF > n\n$\\\n(rm -rf ~/a)\nEOF",
            "cat <<EOF > n\n${ rm -rf ~/a; }\nEOF",
            "cat <<EOF > n\nx `rm -rf ~/a\nEOF",
        ] {
            let masked = mask_non_expanding_data_heredocs(command);
            assert!(masked.contains("rm -rf ~/a"), "{command:?} -> {masked:?}");
        }
        // A continuation that forms a substitution also fails the
        // substitution reader closed.
        assert!(
            extract_posix_command_substitutions("cat <<EOF > n\n$\\\n(rm -rf ~/a)\nEOF").is_err()
        );
        assert!(extract_posix_command_substitutions("cat <<EOF > n\na \\\nb\nEOF").is_ok());

        // An executing target keeps the whole body, quoted or not, and so
        // does an unquoted data sink whose output is not contained
        // (`cat <<EOF | sh`; its body is also judged as commands, see
        // `data_heredoc_bodies_are_masked_only_where_their_output_stays`).
        for executed in [
            "bash <<EOF\nwatch 'git reset --hard'\nEOF",
            "bash <<'EOF'\nwatch 'git reset --hard'\nEOF",
            "cat <<EOF | sh\nwatch 'git reset --hard'\nEOF",
        ] {
            let masked = mask_non_expanding_data_heredocs(executed);
            assert!(masked.contains("git reset --hard"), "{masked:?}");
        }
    }

    /// The output of each heredoc's command, as the parse tree proves it.
    fn heredoc_outputs(command: &str) -> Vec<Option<HeredocOutput>> {
        active_heredocs(command)
            .expect("parses")
            .into_iter()
            .map(|heredoc| heredoc.output)
            .collect()
    }

    /// Where a data sink's output goes decides whether its body is data.
    /// The parse tree proves containment only for the terminal, a plain file
    /// and read-only text tools; it proves execution for a pipe into a
    /// program that runs text; anything it cannot follow is `None`.
    #[test]
    fn heredoc_output_is_proven_from_the_parse_tree() {
        use HeredocOutput::{Contained, Escapes, Executes};
        for (command, expected) in [
            // Contained.
            ("cat <<EOF\nx\nEOF", Some(Contained)),
            ("cat <<EOF > notes.md\nx\nEOF", Some(Contained)),
            ("cat > notes.md <<EOF\nx\nEOF", Some(Contained)),
            ("FOO=1 cat <<EOF >> log.txt\nx\nEOF", Some(Contained)),
            ("cat <<EOF > 'my notes.md'\nx\nEOF", Some(Contained)),
            ("cat <<EOF >/dev/null\nx\nEOF", Some(Contained)),
            ("cat <<EOF 2>/dev/null > n\nx\nEOF", Some(Contained)),
            ("cat <<EOF 2>&1\nx\nEOF", Some(Contained)),
            ("cat <<EOF | wc -l\nx\nEOF", Some(Contained)),
            (
                "cat <<EOF | grep -v x | sort > out.txt\nx\nEOF",
                Some(Contained),
            ),
            ("cat <<EOF | tee a.txt | wc\nx\nEOF", Some(Contained)),
            (
                "cd d && cat <<EOF > n.md && git add n.md\nx\nEOF",
                Some(Contained),
            ),
            ("git commit -F - <<EOF\nx\nEOF", Some(Contained)),
            ("if true; then\ncat <<EOF\nx\nEOF\nfi", Some(Contained)),
            // The grammar swallows `| bash` into the redirect; stdout is filed.
            ("cat <<'EOF' >log | bash\nx\nEOF", Some(Contained)),
            // Into a program that runs text.
            ("cat <<EOF | sh\nx\nEOF", Some(Executes)),
            ("cat <<'EOF' | bash -s -- a\nx\nEOF", Some(Executes)),
            ("cat <<EOF | grep x | sh\nx\nEOF", Some(Executes)),
            ("cat <<EOF | tee x | python3\nx\nEOF", Some(Executes)),
            ("cat <<EOF | ssh host\nx\nEOF", Some(Executes)),
            ("cat <<EOF | ssh -T host -- bash -s\nx\nEOF", Some(Executes)),
            ("cat <<EOF | docker exec -i c sh\nx\nEOF", Some(Executes)),
            (
                "cat <<EOF | kubectl exec -i p -- sh\nx\nEOF",
                Some(Executes),
            ),
            ("cat <<EOF | sudo -u root sh\nx\nEOF", Some(Executes)),
            ("cat <<EOF | sudo\nx\nEOF", Some(Executes)),
            ("cat <<EOF | sudo -s\nx\nEOF", Some(Executes)),
            ("cat <<EOF | timeout 5 sh\nx\nEOF", Some(Executes)),
            ("cat <<EOF | env -i sh\nx\nEOF", Some(Executes)),
            ("cat <<EOF | su\nx\nEOF", Some(Executes)),
            ("cat <<EOF | at now\nx\nEOF", Some(Executes)),
            ("cat <<EOF | xargs -0 sh -c\nx\nEOF", Some(Executes)),
            ("cat <<EOF | $SHELL\nx\nEOF", Some(Executes)),
            (
                "cat <<EOF | while read -r l; do eval \"$l\"; done\nx\nEOF",
                Some(Executes),
            ),
            ("cat <<EOF 2>&1 | sh\nx\nEOF", Some(Executes)),
            ("cat <<EOF 2>/dev/null | sh\nx\nEOF", Some(Executes)),
            ("cat <<EOF | sh -c \"$(cat)\"\nx\nEOF", Some(Executes)),
            ("cat <<EOF | python3 -\nx\nEOF", Some(Executes)),
            ("cat <<EOF | ssh host 'bash -s'\nx\nEOF", Some(Executes)),
            ("cat <<EOF | sudo env sh\nx\nEOF", Some(Executes)),
            // Not contained, nothing seen that runs it.
            ("cat <<EOF | git commit -F -\nx\nEOF", Some(Escapes)),
            ("cat <<EOF | kubectl apply -f -\nx\nEOF", Some(Escapes)),
            (
                "cat <<EOF | sudo tee /etc/x >/dev/null\nx\nEOF",
                Some(Escapes),
            ),
            ("cat <<EOF | sed s/a/b/\nx\nEOF", Some(Escapes)),
            // A script file or a literal `-c` string reads the text as data.
            ("cat <<EOF | bash deploy.sh\nx\nEOF", Some(Escapes)),
            ("cat <<EOF | sh -c 'cat > out'\nx\nEOF", Some(Escapes)),
            ("cat <<EOF | python3 -m json.tool\nx\nEOF", Some(Escapes)),
            ("cat <<EOF | ssh host 'cat > f'\nx\nEOF", Some(Escapes)),
            ("cat <<EOF | docker exec -i c tee /f\nx\nEOF", Some(Escapes)),
            ("cat <<EOF | su -c 'cat > f' u\nx\nEOF", Some(Escapes)),
            // Unproven: the tree cannot follow the output.
            ("cat <<EOF >&2\nx\nEOF", None),
            ("cat <<EOF >/dev/stdout\nx\nEOF", None),
            ("cat <<EOF >/dev/stdout | sh\nx\nEOF", None),
            ("cat <<EOF >&2 | sh\nx\nEOF", None),
            ("cat <<EOF > ../../dev/fd/1\nx\nEOF", None),
            ("cat <<EOF > \"$f\"\nx\nEOF", None),
            ("cat <<EOF |\nx\nEOF\nsh", None),
            ("x=$(cat <<EOF\nx\nEOF\n)", None),
            ("tee >(sh) <<EOF\nx\nEOF", None),
            ("cat <<EOF > >(sh)\nx\nEOF", None),
            ("exec 3>&1; cat <<EOF\nx\nEOF", None),
            ("f() { cat <<EOF\nx\nEOF\n}; f | sh", None),
            ("cat <<A; sh <<B\nhi\nA\nx\nB", None),
        ] {
            let outputs = heredoc_outputs(command);
            assert_eq!(outputs.first().copied().flatten(), expected, "{command:?}");
        }
    }

    /// Without a proof from the tree, the text outside the bodies decides,
    /// in the strict direction.
    #[test]
    fn unproven_heredoc_output_is_judged_from_the_text() {
        for command in [
            "cat <<EOF 2>&1 | sh\n\nEOF",
            "(cat <<EOF) | sh\n\nEOF",
            "{ cat <<EOF; } | sh\n\nEOF",
            "cat <<EOF |\n\nEOF\nsh",
            "x=$(cat <<EOF\n\nEOF\n); eval \"$x\"",
            "x=$(cat <<EOF\n\nEOF\n)\nsh -c \"$x\"",
            "eval \"$(cat <<EOF\n\nEOF\n)\"",
            "bash -c \"$(cat <<EOF\n\nEOF\n)\"",
            "tee >(sh) <<EOF\n\nEOF",
            "f() { cat <<EOF\n\nEOF\n}; f | sh",
            "cat <<A; sh <<B\nhi\nA\n\nB",
            "cat <<EOF | $SHELL\n\nEOF",
            "exec 3> >(sh)\ncat <<EOF >&3\n\nEOF",
            "cat <<EOF > x\n\nEOF\nexec sh < x",
        ] {
            assert!(command_may_run_heredoc_output(command), "{command:?}");
        }
        for command in [
            "cat <<EOF >&2\n\nEOF\nexit 1",
            "git commit -m \"$(cat <<EOF\n\nEOF\n)\"",
            "x=$(cat <<EOF\n\nEOF\n)\ngit commit -m \"$x\"",
            "cat <<EOF > \"$f\"\n\nEOF\nbash build.sh",
            "cat <<EOF | sudo tee /etc/x\n\nEOF",
            "exec 2>&1\ncat <<EOF > n\n\nEOF",
            "{ cat <<EOF; } > n\n\nEOF",
            "if true; then cat <<EOF > n\n\nEOF\nfi",
        ] {
            assert!(!command_may_run_heredoc_output(command), "{command:?}");
        }
    }

    /// A body is only as contained as its owner's output when the owner
    /// passes it through untouched; a program that runs, stores, sends or
    /// re-files it leaves the output unproven, and the unquoted body whole.
    #[test]
    fn owners_and_stages_that_use_the_body_prove_nothing() {
        let body = "watch 'git reset --hard'";
        for template in [
            "read -r c <<EOF\n{b}\nEOF\n$c",
            "sed e <<EOF\n{b}\nEOF",
            "awk '{system($0)}' <<EOF\n{b}\nEOF",
            "nc h 4444 <<EOF\n{b}\nEOF",
            "curl --data-binary @- http://h <<EOF\n{b}\nEOF",
            "dd of=out <<EOF\n{b}\nEOF",
            "sort --compress-program=sh <<EOF\n{b}\nEOF",
            "sort --co=sh <<EOF\n{b}\nEOF",
            "sort -o /dev/stderr <<EOF 2>&1 >/dev/null | sh\n{b}\nEOF",
            "sort -o/dev/fd/3 <<EOF\n{b}\nEOF",
            "sort --output=/dev/stderr <<EOF\n{b}\nEOF",
            "sort -o <<EOF\n{b}\nEOF",
            "sort $opt <<EOF\n{b}\nEOF",
            "tee /dev/stderr <<EOF 2>&1 >/dev/null | sh\n{b}\nEOF",
            "tee \"$f\" <<EOF\n{b}\nEOF",
            "tee 'a'$f <<EOF\n{b}\nEOF",
            "uniq - /dev/stderr <<EOF\n{b}\nEOF",
            "xxd - /proc/self/fd/2 <<EOF\n{b}\nEOF",
            "PATH=/tmp/x cat <<EOF\n{b}\nEOF",
            "LD_PRELOAD=x.so cat <<EOF\n{b}\nEOF",
            "cat <<EOF | sort --compress-program=sh\n{b}\nEOF",
            "cat <<EOF | rg --pre=sh x /dev/stdin\n{b}\nEOF",
            "cat <<EOF | tee /dev/stderr 2>&1 >/dev/null | sh\n{b}\nEOF",
            "cat <<EOF | RIPGREP_CONFIG_PATH=x rg y\n{b}\nEOF",
        ] {
            let command = template.replace("{b}", body);
            assert!(
                heredoc_outputs(&command)
                    .first()
                    .is_some_and(|output| *output != Some(HeredocOutput::Contained)),
                "{command:?}"
            );
            let view = mask_non_expanding_data_heredocs(&command);
            assert!(view.contains("git reset"), "{command:?} -> {view:?}");
        }
        for template in [
            "LC_ALL=C sort -u <<EOF > out\n{b}\nEOF",
            "sort -o sorted.txt <<EOF\n{b}\nEOF",
            "sort -ro sorted.txt <<EOF\n{b}\nEOF",
            "tee -a notes.md log.txt <<EOF >/dev/null\n{b}\nEOF",
            "uniq -c in.txt out.txt <<EOF\n{b}\nEOF",
            "echo hi <<EOF\n{b}\nEOF",
            "cat <<EOF | rg -n 'reset$' --pretty | sort -o s.txt\n{b}\nEOF",
        ] {
            let command = template.replace("{b}", body);
            assert_eq!(
                heredoc_outputs(&command).first().copied().flatten(),
                Some(HeredocOutput::Contained),
                "{command:?}"
            );
            let view = mask_non_expanding_data_heredocs(&command);
            assert!(!view.contains("git reset"), "{command:?} -> {view:?}");
        }
    }

    /// An unquoted data body keeps only its substitutions in the
    /// expansion-aware view when its output is provably contained; any other
    /// unquoted body stays whole there, as in v0.15.1, and quoted bodies keep
    /// their v0.15.1 mask. A body whose output reaches a program that runs it
    /// is handed to the caller to judge as commands, quoted or not.
    #[test]
    fn data_heredoc_bodies_are_masked_only_where_their_output_stays() {
        let body = "watch 'git reset --hard'";
        let contained = [
            "cat <<{d} > notes.md\n{b}\nEOF",
            "cat <<{d}\n{b}\nEOF",
            "cat <<{d} | wc -l\n{b}\nEOF",
            "cd d && cat <<{d} > n.md\n{b}\nEOF",
        ];
        let escapes = [
            "cat <<{d} >&2\n{b}\nEOF",
            "cat <<{d} | git commit -F -\n{b}\nEOF",
            "cat <<{d} | sudo tee /etc/x\n{b}\nEOF",
            "git commit -m \"$(cat <<{d}\n{b}\nEOF\n)\"",
        ];
        let executes = [
            "cat <<{d} | sh\n{b}\nEOF",
            "cat <<{d} 2>&1 | sh\n{b}\nEOF",
            "cat <<{d} 2>/dev/null | sh\n{b}\nEOF",
            "cat <<{d} >&2 | sh\n{b}\nEOF",
            "(cat <<{d}) | sh\n{b}\nEOF",
            "cat <<{d} | ssh host\n{b}\nEOF",
            "cat <<{d} | ssh host bash\n{b}\nEOF",
            "cat <<{d} | docker exec -i c sh\n{b}\nEOF",
            "cat <<{d} | kubectl exec -i p -- sh\n{b}\nEOF",
            "cat <<{d} | sudo sh\n{b}\nEOF",
            "cat <<{d} | at now\n{b}\nEOF",
            "cat <<{d} | su\n{b}\nEOF",
            "cat <<{d} | $SHELL\n{b}\nEOF",
            "cat <<{d} | tee /dev/null | sh\n{b}\nEOF",
            "cat <<{d} |\n{b}\nEOF\nsh",
            "cat <<{d} > >(sh)\n{b}\nEOF",
            "tee >(sh) <<{d}\n{b}\nEOF",
            "eval \"$(cat <<{d}\n{b}\nEOF\n)\"",
            "x=$(cat <<{d}\n{b}\nEOF\n); eval \"$x\"",
        ];
        for delimiter in ["EOF", "'EOF'"] {
            let quoted = delimiter.starts_with('\'');
            let render = |template: &str| template.replace("{d}", delimiter).replace("{b}", body);
            let judged = |command: &str| -> Vec<String> {
                data_heredoc_bodies_whose_output_may_run(command)
                    .into_iter()
                    .map(|body| command[body].to_string())
                    .collect()
            };
            for template in contained {
                let command = render(template);
                let view = mask_non_expanding_data_heredocs(&command);
                assert!(!view.contains("git reset"), "{command:?} -> {view:?}");
                let full = mask_non_executing_heredocs(&command);
                assert!(!full.contains("git reset"), "{command:?} -> {full:?}");
                assert!(judged(&command).is_empty(), "{command:?}");
            }
            for template in escapes {
                let command = render(template);
                let view = mask_non_expanding_data_heredocs(&command);
                // v0.15.1: a quoted body masked, an unquoted one whole.
                assert_eq!(
                    view.contains("git reset"),
                    !quoted,
                    "{command:?} -> {view:?}"
                );
                let full = mask_non_executing_heredocs(&command);
                assert!(!full.contains("git reset"), "{command:?} -> {full:?}");
                assert!(judged(&command).is_empty(), "{command:?}");
            }
            for template in executes {
                let command = render(template);
                if !quoted {
                    let view = mask_non_expanding_data_heredocs(&command);
                    assert!(view.contains("git reset"), "{command:?} -> {view:?}");
                }
                // Judged as commands — or, where the grammar mis-splits the
                // line (`cat <<EOF |` continued after the body), never masked.
                let bodies = judged(&command);
                assert!(
                    bodies.iter().any(|judged| judged.contains(body))
                        || mask_non_executing_heredocs(&command).contains(body),
                    "{command:?} -> {bodies:?}"
                );
            }
        }
    }

    #[test]
    fn synchronous_reads_before_quoted_writes_do_not_execute_the_new_body_525() {
        for command in [
            "sed -n 1p notes.txt && cat >> notes.txt <<'EOF'\n$(ls)\nEOF",
            "sed 's/a\\.b/c/' notes.txt && cat >> notes.txt <<'EOF'\n`ls`\nEOF",
            "sed 's/a\\.b/c/' notes.txt && cat > notes.txt <<'EOF'\n`ls`\nEOF",
            "sed 's/a\\.b/c/' notes.txt && cat >> notes.txt <<'EOF'\nrm -rf ~/project\nEOF",
            "awk 1 notes.txt && cat >> notes.txt <<'EOF'\nrm -rf ~/project\nEOF",
            "tac notes.txt && cat >> notes.txt <<'EOF'\nrm -rf ~/project\nEOF",
            "sed -n 1p notes.txt\ncat > notes.txt <<'EOF'\nrm -rf ~/project\nEOF",
        ] {
            for view in [
                mask_non_executing_heredocs(command),
                mask_non_expanding_data_heredocs(command),
            ] {
                assert!(
                    !view.contains("$(ls)")
                        && !view.contains("`ls`")
                        && !view.contains("rm -rf ~/project"),
                    "the earlier reader cannot consume newly written text: {command:?} -> {view:?}"
                );
            }
        }
    }

    #[test]
    fn file_read_order_preserves_repeated_deferred_and_later_consumers_525() {
        for command in [
            "for round in 1 2; do sed -n 1p notes.txt; cat > notes.txt <<'EOF'\nrm -rf ~/project\nEOF\ndone",
            "while sed -n 1p notes.txt; do cat > notes.txt <<'EOF'\nrm -rf ~/project\nEOF\ndone",
            "read_notes() { sed -n 1p notes.txt; }; cat > notes.txt <<'EOF'\nrm -rf ~/project\nEOF\nread_notes",
            "sed -n 1p notes.txt & cat > notes.txt <<'EOF'\nrm -rf ~/project\nEOF",
            "cat <(sed -n 1p notes.txt); cat > notes.txt <<'EOF'\nrm -rf ~/project\nEOF",
            "cat <(bash notes.txt); cat > notes.txt <<'EOF'\nrm -rf ~/project\nEOF",
            "consumer=<(bash \"$script\"); cat > notes.txt <<'EOF'\nrm -rf ~/project\nEOF",
            "cat > >(bash notes.txt); cat > notes.txt <<'EOF'\nrm -rf ~/project\nEOF",
            "cat > notes.txt <<'EOF'\nrm -rf ~/project\nEOF\ncat <(bash notes.txt)",
            "cat > notes.txt <<'EOF'\nrm -rf ~/project\nEOF\ncat >(bash notes.txt)",
            "cat > notes.txt <<'EOF'\nrm -rf ~/project\nEOF\ncat > >(bash notes.txt)",
            "cat > notes.txt <<'EOF'\nrm -rf ~/project\nEOF\ntee >(bash notes.txt)",
            "trap 'bash notes.txt' EXIT; sed -n 1p notes.txt && /bin/cat > notes.txt <<'EOF'\nrm -rf ~/project\nEOF",
            "\"$reader\" notes.txt; cat > notes.txt <<'EOF'\nrm -rf ~/project\nEOF",
            "sed -n 1p notes.txt; cat > notes.txt <<'EOF'\nrm -rf ~/project\nEOF\nsed e notes.txt",
            "sed -n 1p notes.txt; cat > notes.txt <<'EOF'\nrm -rf ~/project\nEOF\nsed 's/^/ /e' notes.txt",
            "sed -n 1p notes.txt; cat > notes.txt <<'EOF'\nrm -rf ~/project\nEOF\nawk '{system($0)}' notes.txt",
            "cat > notes.txt <<'EOF'\nrm -rf ~/project\nEOF\nsed -n 1p notes.txt; cat > notes.txt <<'OTHER'\nnew text\nOTHER",
        ] {
            assert!(
                mask_non_executing_heredocs(command).contains("rm -rf ~/project"),
                "source order does not prove this body inert: {command:?}"
            );
        }
    }

    #[test]
    fn quoted_process_substitution_prose_is_not_a_file_consumer_525() {
        for command in [
            "cat '<(bash notes.txt)'; cat > notes.txt <<'EOF'\nrm -rf ~/project\nEOF",
            "cat \"<(bash notes.txt)\"; cat > notes.txt <<'EOF'\nrm -rf ~/project\nEOF",
            "cat --note='>(bash notes.txt)'; cat > notes.txt <<'EOF'\nrm -rf ~/project\nEOF",
            "cat \\<\\(bash\\ notes.txt\\); cat > notes.txt <<'EOF'\nrm -rf ~/project\nEOF",
        ] {
            for view in [
                mask_non_executing_heredocs(command),
                mask_non_expanding_data_heredocs(command),
            ] {
                assert!(
                    !view.contains("rm -rf ~/project"),
                    "quoted prose cannot consume the written file: {command:?} -> {view:?}"
                );
            }
        }
    }

    #[test]
    fn prior_sed_read_proof_rejects_execution_and_extra_programs_525() {
        for script in ["p", "1p", "1,20p", "s/a\\.b/c/", "s|a\\|b|c|g"] {
            assert!(sed_program_is_plain_read(script), "{script:?}");
        }
        for script in [
            "e",
            "1e",
            "s/x/y/e",
            "s/x/y/w file",
            "s/x/y/; e",
            "s/x/y/\ne",
            "s/x/y",
        ] {
            assert!(!sed_program_is_plain_read(script), "{script:?}");
        }
        for command in [
            "sed -f program.sed notes.txt",
            "sed 1p notes.txt -e e",
            "sed -n 1p \"$notes\"",
            "awk -l extension 1 notes.txt",
            "awk '{system($0)}' notes.txt",
            "tac $(choose_file)",
        ] {
            assert!(!synchronous_file_reader(command), "{command:?}");
        }
    }

    /// A body written to a file the same command then runs is code.
    #[test]
    fn a_body_written_to_a_file_the_command_runs_stays_visible() {
        for command in [
            "tee x.sh <<EOF\nrm -rf ~/a\nEOF\nsh x.sh",
            "cat > x.sh <<'EOF'\nrm -rf ~/a\nEOF\nbash x.sh",
            "cat <<EOF > x.sh && ./x.sh\nrm -rf ~/a\nEOF",
            "cat <<EOF > x.sh; . ./x.sh\nrm -rf ~/a\nEOF",
            "cat <<EOF > x.sh\nrm -rf ~/a\nEOF\nsh -c \"$(cat x.sh)\"",
            "cat <<EOF > x.sh\nrm -rf ~/a\nEOF\ncat x.sh | bash",
            "cat <<EOF > x.sh\nrm -rf ~/a\nEOF\nbash < x.sh",
            "cat <<EOF | tee a b.sh\nrm -rf ~/a\nEOF\nsh b.sh",
            "cat >| /tmp/d/x.sh <<'EOF'\nrm -rf ~/a\nEOF\nsudo bash -e /tmp/d/x.sh",
            "dd of=x.sh <<'EOF'\nrm -rf ~/a\nEOF\nsh x.sh",
            "cat > x.sh <<'EOF'\nrm -rf ~/a\nEOF\nsh $(ls *.sh)",
            "cat > x.sh <<'EOF'\nrm -rf ~/a\nEOF\nbash ./*.sh",
            "cat > \"$f\" <<'EOF'\nrm -rf ~/a\nEOF\n\"$f\"",
        ] {
            assert!(
                mask_non_expanding_data_heredocs(command).contains("rm -rf ~/a"),
                "{command:?}"
            );
            assert!(
                mask_non_executing_heredocs(command).contains("rm -rf ~/a"),
                "{command:?}"
            );
        }
        for command in [
            "cat > notes.md <<'EOF'\nrm -rf ~/a\nEOF\ngit add notes.md && git commit -m n",
            "cat > notes.md <<'EOF'\nrm -rf ~/a\nEOF\nwc -l notes.md",
            "cat > notes.md <<'EOF'\nrm -rf ~/a\nEOF\nsh other.sh",
            "cat > a.sh <<'EOF'\nrm -rf ~/a\nEOF\nsh ba.sh",
            "cat > notes.md <<'EOF'\nrm -rf ~/a\nEOF\nX=$(date)",
            "cat > notes.md <<'EOF'\nrm -rf ~/a\nEOF\nmake -j$(nproc)",
            "cat > notes.md <<'EOF'\nrm -rf ~/a\nEOF\ngit add *.md",
        ] {
            assert!(
                !mask_non_executing_heredocs(command).contains("rm -rf ~/a"),
                "{command:?}"
            );
        }
    }

    #[test]
    fn literal_transfers_and_remote_commit_messages_stay_data_543() {
        let body = "eval ran 16 sequences (5.7 GB) where training ran 4.";
        for tail in [
            "scp m.txt host:/tmp/m.txt",
            "scp -q -P 2222 m.txt host:/tmp/",
            "scp -qP2222 m.txt host:/tmp/renamed.txt",
            "scp m.txt /tmp/renamed.txt",
            "ssh host 'git commit -q -F /tmp/m.txt'",
            "ssh -T -p 2222 host git commit -q -F /tmp/m.txt",
            "ssh host -T 'git commit --file=/tmp/m.txt'",
            "ssh -- host 'git commit -qF/tmp/m.txt'",
            "ssh host 'cd repo && git commit -F /tmp/m.txt'",
            "scp m.txt host:/tmp/ && ssh host 'git commit -F /tmp/m.txt'",
            "scp m.txt host:/tmp/renamed.txt && ssh host 'git commit -F /tmp/renamed.txt'",
            "scp m.txt /tmp/renamed.txt && scp /tmp/renamed.txt host:/tmp/last.txt && ssh host 'git commit -F /tmp/last.txt'",
            "scp m.txt host:/tmp/m.txt && git commit -q -F m.txt",
        ] {
            let command = format!("cat > m.txt <<'EOF'\n{body}\nEOF\n{tail}");
            for view in [
                mask_non_executing_heredocs(&command),
                mask_non_expanding_data_heredocs(&command),
            ] {
                assert!(
                    !view.contains(body),
                    "literal file data: {command:?} -> {view:?}"
                );
                assert!(view.contains(tail), "executable command text stays visible");
                assert_eq!(view.len(), command.len(), "byte offsets are preserved");
            }
        }
        let command = format!(
            "cat > 'message file.txt' <<'EOF'\n{body}\nEOF\nscp 'message file.txt' 'host:/tmp/message file.txt'\nssh host \"git commit -F '/tmp/message file.txt'\""
        );
        assert!(!mask_non_expanding_data_heredocs(&command).contains(body));
    }

    #[test]
    fn transferred_files_keep_execution_and_ambiguous_consumers_visible_543() {
        let body = "eval $COMMAND";
        for tail in [
            "scp m.txt host:/tmp/m.txt; sh m.txt",
            "scp m.txt host:/tmp/renamed.txt; ssh host 'sh /tmp/renamed.txt'",
            "scp m.txt host:/tmp/renamed.txt; ssh host 'cat /tmp/renamed.txt | sh'",
            "scp m.txt /tmp/renamed.txt; cat /tmp/renamed.txt | grep . | sh",
            "scp m.txt /tmp/renamed.txt; cat /tmp/renamed.txt | ssh host",
            "scp m.txt /tmp/renamed.txt; scp /tmp/renamed.txt /tmp/last.txt; sh /tmp/last.txt",
            "scp m.txt /tmp/renamed.txt; consumer /tmp/renamed.txt",
            "scp m.txt /tmp/renamed.txt; sh \"$script\"",
            "scp m.txt host:/tmp/renamed.txt; ssh host \"$script\"",
            "scp -S m.txt m.txt host:/tmp/",
            "scp -D m.txt m.txt host:/tmp/",
            "scp -F m.txt m.txt host:/tmp/",
            "scp -o 'ProxyCommand=sh m.txt' m.txt host:/tmp/",
            "scp -J host m.txt host:/tmp/",
            "scp -O m.txt host:/tmp/",
            "scp -r m.txt host:/tmp/",
            "scp m.txt \"$destination\"",
            "/tmp/scp m.txt host:/tmp/",
            "scp() { sh \"$1\"; }; scp m.txt host:/tmp/",
            "ssh host 'git -c alias.send=sh send m.txt'",
            "ssh host 'git commit -F m.txt; sh m.txt'",
            "ssh host 'git commit -F m.txt' | cat | sh",
            "ssh host 'sh m.txt'",
            "ssh host 'consumer m.txt'",
            "ssh -o 'ProxyCommand=sh m.txt' host 'git commit -F m.txt'",
            "scp m.txt /tmp/git; ssh host 'git commit -F other.txt'",
            "scp m.txt /tmp/cat; chmod +x /tmp/cat; /tmp/cat",
            "scp m.txt /tmp/git; chmod +x /tmp/git; /tmp/git status",
            "scp m.txt /tmp/echo; chmod +x /tmp/echo; /tmp/echo",
            "scp m.txt /usr/bin/git; git commit -F other.txt",
            "scp m.txt /usr/bin/cat; /usr/bin/cat > other.txt <<'OTHER'\nbenign\nOTHER",
            "scp m.txt /tmp/renamed.txt; rg --pre sh pattern /tmp/renamed.txt",
            "scp m.txt /tmp/renamed.txt; vim -S /tmp/renamed.txt",
            "scp m.txt /tmp/renamed.txt; echo \"$(sh /tmp/renamed.txt)\"",
            "scp m.txt /tmp/renamed.txt; sort /tmp/renamed.txt -o /tmp/last.txt; sh /tmp/last.txt",
            "scp m.txt host:/tmp/renamed.txt; consume_implicitly",
            "consume_later & scp m.txt host:/tmp/renamed.txt",
            "scp m.txt host:/repo/.git/hooks/post-commit; ssh host 'git commit -F /tmp/other.txt'",
            "scp m.txt host:/home/user/.bashrc; ssh host 'git commit -F /tmp/other.txt'",
            "f() { scp m.txt host:/tmp/; }; f",
        ] {
            let command = format!("cat > m.txt <<'EOF'\n{body}\nEOF\n{tail}");
            for view in [
                mask_non_executing_heredocs(&command),
                mask_non_expanding_data_heredocs(&command),
            ] {
                assert!(
                    view.contains(body),
                    "unproven file flow: {command:?} -> {view:?}"
                );
            }
        }
    }

    #[test]
    fn transfers_cannot_replace_executables_used_by_the_data_proof_543() {
        let body = "eval $COMMAND";
        for setup in [
            "scp external.txt /usr/bin/cat",
            "scp /tmp/cat /usr/bin/",
            "scp external.txt /usr/bin/scp",
            "scp external.txt host:/usr/bin/git",
            "scp /tmp/git host:/usr/bin/",
        ] {
            let command = format!(
                "{setup}\ncat > m.txt <<'EOF'\n{body}\nEOF\nscp m.txt host:/tmp/m.txt\nssh host 'git commit -F /tmp/m.txt'"
            );
            for view in [
                mask_non_executing_heredocs(&command),
                mask_non_expanding_data_heredocs(&command),
            ] {
                assert!(
                    view.contains(body),
                    "the proven executables changed: {command:?}"
                );
            }
        }
        let data_only = format!(
            "scp external.txt host:/tmp/data.bin\ncat > m.txt <<'EOF'\n{body}\nEOF\nscp m.txt host:/tmp/m.txt"
        );
        assert!(!mask_non_expanding_data_heredocs(&data_only).contains(body));
    }

    #[test]
    fn expired_and_busy_transfer_proofs_supply_no_exemption_543() {
        // Exercise the same runner with an isolated slot; public helpers
        // always use the process-wide slot, including in test builds.
        static BUSY: AtomicBool = AtomicBool::new(false);
        assert!(
            run_file_data_proof(&BUSY, Instant::now(), Duration::ZERO, || {
                panic!("an expired proof must not begin parsing")
            })
            .is_empty()
        );
        assert!(!BUSY.load(Ordering::Acquire));
        BUSY.store(true, Ordering::Release);
        assert!(
            run_file_data_proof(&BUSY, Instant::now(), Duration::from_secs(5), || panic!(
                "a busy worker must not launch another parser"
            ))
            .is_empty()
        );
        assert!(BUSY.load(Ordering::Acquire));
        BUSY.store(false, Ordering::Release);
    }

    #[test]
    fn git_file_message_proof_rejects_custom_repository_context_543() {
        for globals in [
            "--git-dir=/srv/gitdata --work-tree=/srv/repo",
            "--git-dir /srv/gitdata",
            "--work-tree=/srv/repo",
            "--bare",
            "--namespace=other",
            "--super-prefix=other",
            "--exec-path=/srv/helpers",
            "-c core.hooksPath=/srv/hooks",
            "--config-env=core.hooksPath=HOOKS",
        ] {
            let command = format!("git {globals} commit -F /tmp/message.txt");
            let words = shell_words::split(&command).expect("literal git argv");
            assert!(!literal_git_commit_message_reader(&words), "{command}");
            assert!(
                !literal_ssh_git_message_reader(&["host".into(), command.clone()]),
                "{command}"
            );
        }
        for command in [
            "git -C /srv/repo commit -q -F m.txt",
            "git -C/srv/repo commit -F m.txt",
            "git --no-pager -C /srv/repo commit -F m.txt",
        ] {
            let words = shell_words::split(command).expect("literal git argv");
            assert!(literal_git_commit_message_reader(&words), "{command}");
            assert!(literal_ssh_git_message_reader(&[
                "host".into(),
                command.into()
            ]));
        }
    }

    #[test]
    fn transfers_keep_implicit_transport_and_hook_execution_visible_543() {
        let body = "eval $COMMAND";
        for setup in [
            "scp external.txt /usr/bin/cp",
            "scp external.txt /usr/bin/ssh",
            "scp /tmp/cp /usr/bin/",
            "scp /tmp/ssh /usr/bin/",
            "scp external.txt host:/bin/bash",
            "scp external.txt host:/usr/lib/openssh/sftp-server",
            "scp external.txt host:/lib/libc.so.6",
            "scp /tmp/bash host:/opt/shells/",
            "scp /tmp/sftp-server host:/opt/openssh/",
        ] {
            let command = format!(
                "{setup}\ncat > m.txt <<'EOF'\n{body}\nEOF\nscp m.txt /tmp/copied.txt\nscp m.txt host:/tmp/m.txt"
            );
            assert!(
                mask_non_expanding_data_heredocs(&command).contains(body),
                "{command}"
            );
        }
        for arguments in [
            "m.txt host:/srv/hooks/post-commit",
            "post-commit host:/srv/hooks/",
            "post-commit host:/srv/hooks",
            "m.txt /srv/hooks/reference-transaction",
            "post-index-change /srv/hooks/",
        ] {
            let words = shell_words::split(arguments).expect("literal scp argv");
            assert!(literal_scp_file_transfer(&words).is_none(), "{arguments}");
        }
    }

    #[test]
    fn transferred_file_alias_proof_is_bounded_543() {
        use std::fmt::Write as _;

        let body = "eval $COMMAND";
        let mut command = format!("cat > file0.txt <<'EOF'\n{body}\nEOF\n");
        for index in 0..33 {
            writeln!(&mut command, "scp file{index}.txt file{}.txt", index + 1)
                .expect("append transfer");
        }
        command.push_str("sh file33.txt");
        assert!(mask_non_expanding_data_heredocs(&command).contains(body));
    }

    #[test]
    fn transfers_to_implicitly_executed_destinations_remain_unproven_543() {
        for command in [
            "m.txt host:/repo/.git/hooks/post-commit",
            "post-commit host:/repo/.git/hooks/",
            "m.txt host:/home/user/.bashrc",
            "m.txt host:.bashrc",
            ".bashrc host:",
            "m.txt host:/home/user/../user/.bashrc",
        ] {
            let arguments = shell_words::split(command).expect("literal argv");
            assert!(literal_scp_file_transfer(&arguments).is_none(), "{command}");
        }
    }

    #[test]
    fn quoted_interpreter_source_proof_requires_the_complete_handoff_544() {
        let body = "text = 'run `git branch -d x` later'";
        for (header, tail, language, expected) in [
            ("python3 - <<'EOF'", "", ScriptLanguage::Python, true),
            ("node <<'EOF'", "", ScriptLanguage::JavaScript, true),
            ("python3 - <<EOF", "", ScriptLanguage::Python, false),
            (
                "python3 script.py <<'EOF'",
                "",
                ScriptLanguage::Python,
                false,
            ),
            (
                "python3 -c other <<'EOF'",
                "",
                ScriptLanguage::Python,
                false,
            ),
            ("python3 - <<'EOF' | sh", "", ScriptLanguage::Python, false),
            (
                "python3 - <<'EOF' > x.sh",
                "sh x.sh",
                ScriptLanguage::Python,
                false,
            ),
            (
                "python3 - <<'EOF'",
                "sh x.sh",
                ScriptLanguage::Python,
                false,
            ),
            (
                "NODE_OPTIONS=bootstrap node <<'EOF'",
                "",
                ScriptLanguage::JavaScript,
                false,
            ),
            (
                "export NODE_OPTIONS=bootstrap; node <<'EOF'",
                "",
                ScriptLanguage::JavaScript,
                false,
            ),
            (
                "cat > x.py <<'EOF'",
                "python3 x.py",
                ScriptLanguage::Python,
                true,
            ),
            (
                "cat > x.py <<'EOF'",
                "python3 x.py; sh x.py",
                ScriptLanguage::Python,
                false,
            ),
            (
                "cat > x.js <<'EOF'",
                "node --require bootstrap x.js",
                ScriptLanguage::JavaScript,
                false,
            ),
            (
                "cat >> x.py <<'EOF'",
                "python3 x.py",
                ScriptLanguage::Python,
                false,
            ),
            (
                "cat > x.py <<'EOF'",
                "sh x.py",
                ScriptLanguage::Python,
                false,
            ),
            (
                "(python3 - <<'EOF'",
                "sh x.sh) > result",
                ScriptLanguage::Python,
                false,
            ),
        ] {
            let command = format!("{header}\n{body}\nEOF\n{tail}");
            let start = command.find(body).expect("body");
            let range = start..start + body.len();
            assert_eq!(
                range_is_quoted_interpreter_source(&command, &range, language),
                expected,
                "{command:?}"
            );
            assert!(!range_is_quoted_interpreter_source(
                &command,
                &(range.start..range.end - 1),
                language
            ));
        }
    }

    #[test]
    fn run_time_command_words_that_may_name_a_runner() {
        for word in [
            "w${x}atch",
            "${W}atch",
            "$W",
            "\"$RUN\"",
            "w$x'atch'",
            "$(echo watch)",
            "`echo ssh`",
            "s${x}sh",
            "/usr/bin/$W",
            "w$1atch",
            "w$@atch",
            "$'\\x77'$x",
        ] {
            assert!(dynamic_word_may_name_runner(word), "{word:?}");
        }
        for word in [
            "watch",
            "$HOME/bin/tool",
            "${X}-build",
            "$X.sh",
            "'$W'",
            "w\\$xatch",
            "tool$X",
        ] {
            assert!(!dynamic_word_may_name_runner(word), "{word:?}");
        }
    }

    #[test]
    fn substitution_command_words_read_as_their_output() {
        let line = |command: &str| {
            let tokens = crate::normalize::tokenize_for_normalization(command);
            let word = tokens[0].text(command).unwrap();
            substitution_command_line(command, &tokens, 0, word)
        };
        assert_eq!(
            line("$(echo git reset --hard)").as_deref(),
            Some("git reset --hard")
        );
        assert_eq!(
            line("$(printf 'git reset') --hard").as_deref(),
            Some("git reset --hard")
        );
        assert_eq!(
            line("\"$(echo git)\" reset --hard").as_deref(),
            Some("git reset --hard")
        );
        // The tokenizer splits a backquoted word at its blanks, so only a
        // blank-free one reaches the reader whole.
        assert_eq!(
            whole_substitution_body("`echo git reset --hard`"),
            Some("echo git reset --hard")
        );
        assert_eq!(line("`pwd`"), None);
        assert_eq!(
            line("$(echo git; echo reset)").as_deref(),
            Some("git reset")
        );
        assert_eq!(line("$(pwd)"), None);
        assert_eq!(line("$(echo a)b"), None);
    }

    #[test]
    fn find_options_spelled_through_quoting_are_respelled() {
        let respell = |command: &str| {
            let tokens = crate::normalize::tokenize_for_normalization(command);
            find_with_dequoted_actions(command, &tokens, 0)
        };
        assert_eq!(
            respell("find . '-delete'").as_deref(),
            Some("find . -delete")
        );
        assert_eq!(
            respell("find . -de''lete").as_deref(),
            Some("find . -delete")
        );
        assert_eq!(
            respell("find . -de\\lete").as_deref(),
            Some("find . -delete")
        );
        assert_eq!(
            respell("find . -perm -u+x \"-delete\" -print").as_deref(),
            Some("find . -perm -u+x -delete -print")
        );
        assert_eq!(respell("find . -name '-delete'"), None);
        assert_eq!(respell("find . -exec grep '-delete' {} \\;"), None);
        assert_eq!(respell("find . -name x -print"), None);
    }

    #[test]
    fn primary_command_words_skip_wrapper_options_and_their_values() {
        let primary = |command: &str| {
            let tokens = crate::normalize::tokenize_for_normalization(command);
            let positions = command_word_positions(command, &tokens);
            primary_command_positions(command, &tokens, &positions)
                .iter()
                .zip(tokens.iter())
                .filter(|(primary, _)| **primary)
                .filter_map(|(_, token)| token.text(command).map(str::to_string))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            primary("sudo -u \"$USER\" git commit -m 'x'"),
            ["sudo", "git"]
        );
        assert_eq!(primary("x=1 w${x}atch 'y'"), ["w${x}atch"]);
        assert_eq!(primary("if true; then $W 'y'; fi"), ["true", "$W", "fi"]);
        assert_eq!(primary("timeout 5 $W 'y'"), ["timeout", "$W"]);
        assert_eq!(primary("nohup -- $W 'y'"), ["nohup", "$W"]);
        assert_eq!(primary("echo $W 'y'"), ["echo"]);
    }

    #[test]
    fn stdin_programs_of_awk_and_sed_are_not_data() {
        for command in [
            "awk -f - <<EOF\nx\nEOF",
            "gawk --file=/dev/stdin <<EOF\nx\nEOF",
            "sed -nf - x <<EOF\nx\nEOF",
            "sudo awk -f /dev/fd/0 <<EOF\nx\nEOF",
        ] {
            let at = command.find("<<").unwrap();
            assert!(stdin_is_the_program(command, at), "{command:?}");
        }
        for command in [
            "awk -f prog.awk <<EOF\nx\nEOF",
            "awk '{print}' <<EOF\nx\nEOF",
            "cat -f - <<EOF\nx\nEOF",
            "awk -f - x; cat <<EOF\nx\nEOF",
        ] {
            let at = command.find("<<").unwrap();
            assert!(!stdin_is_the_program(command, at), "{command:?}");
        }
    }

    #[test]
    fn brace_lists_that_make_the_command_are_expanded() {
        assert_eq!(
            brace_expanded_command("{rm,-rf,~}").as_deref(),
            Some("rm -rf ~")
        );
        assert_eq!(
            brace_expanded_command("{git,reset} --hard x").as_deref(),
            Some("git reset --hard x")
        );
        assert_eq!(
            brace_expanded_command("sudo {git,reset,--hard}").as_deref(),
            Some("sudo git reset --hard")
        );
        assert_eq!(
            brace_expanded_command("rm {-rf,~/a}").as_deref(),
            Some("rm -rf ~/a")
        );
        assert_eq!(brace_expanded_command("mkdir -p src/{a,b}"), None);
        assert_eq!(brace_expanded_command("cp f{,.bak}"), None);
        assert_eq!(brace_expanded_command("echo {a,b}"), None);
        assert_eq!(brace_expanded_command("{a}"), None);
        assert_eq!(brace_expanded_command("{ ls; }"), None);

        for command in ["{rm,-rf,~}", "x; {a,b}", "rm {-rf,~}"] {
            assert!(may_brace_expand_a_command(command), "{command:?}");
        }
        for command in [
            "mkdir -p src/{a,b}",
            "cp f{,.bak}",
            "{ ls; }",
            "awk '{print}'",
        ] {
            assert!(!may_brace_expand_a_command(command), "{command:?}");
        }
        // A run of `{` is scanned a bounded distance per brace.
        let long = "{".repeat(200_000);
        let started = Instant::now();
        assert!(!may_brace_expand_a_command(&long));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn eighth_review_tier1_triggers() {
        for command in [
            "w${x}atch 'git reset --hard'",
            "$(echo git reset --hard)",
            "xargs git-reset --hard",
            "find . '-delete'",
            "find . -\\delete",
            "f'ind' . \"-delete\"",
            "$'\\x77atch' 'git reset --hard'",
        ] {
            assert_eq!(
                check_triggers(command),
                TriggerResult::Triggered,
                "{command:?}"
            );
        }
        for command in [
            "git-reset --hard",
            "echo $HOME 'x'",
            "find . -name x -delete",
            "ls",
        ] {
            assert!(!respelled_command_may_be_present(command), "{command:?}");
        }
    }

    /// Issue #440: a nested heredoc operator inside a quoted body is data.
    ///
    /// Writing a Ruby script with `cat > x.rb <<'OUTER'` whose body uses
    /// Ruby's own `eval <<~'SCRIPT'` denied as a POSIX eval. Ruby's `<<~` is
    /// what defeats tree-sitter-bash, and the single-heredoc recovery then
    /// refused to describe the body because the input held a second `<<` —
    /// one that sits *inside* that very body. With no span the quoted body
    /// was rescanned as live shell.
    #[test]
    fn nested_heredoc_operator_inside_a_quoted_body_is_masked_issue_440() {
        let command = "cat > /tmp/x.rb <<'OUTER'\neval <<~'SCRIPT'\n  puts 1\nSCRIPT\nOUTER";
        let masked = mask_non_expanding_data_heredocs(command);
        assert!(
            !masked.contains("eval"),
            "the quoted body must be masked out of the raw-shell rescan; got:\n{masked}"
        );
        // Masking is length-preserving, so spans computed against the raw
        // command stay valid against the view.
        assert_eq!(masked.len(), command.len());
    }

    /// The same shape with an UNQUOTED outer delimiter: the shell expands the
    /// body before `cat` sees it, but expansion runs only the body's
    /// substitutions. Without one the body is as inert as a quoted one; a
    /// `$(…)` in it stays, and so does a body the recovery path cannot bound
    /// the substitutions of.
    #[test]
    fn nested_heredoc_operator_inside_an_unquoted_body_keeps_only_substitutions_issue_440() {
        let command = "cat > /tmp/x.rb <<OUTER\neval <<~'SCRIPT'\n  puts 1\nSCRIPT\nOUTER";
        let masked = mask_non_expanding_data_heredocs(command);
        assert!(!masked.contains("eval"), "{masked:?}");
        assert_eq!(masked.len(), command.len());

        let live = "cat > /tmp/x.rb <<OUTER\neval <<~'SCRIPT'\n  $(rm -rf ~/x)\nSCRIPT\nOUTER";
        let masked = mask_non_expanding_data_heredocs(live);
        assert!(masked.contains("rm -rf ~/x"), "{masked:?}");
    }

    /// Proves the recovery path itself, not just the AST path: `cat <<'EOF';
    /// echo done` is the #393 shape tree-sitter-bash rejects outright, so the
    /// span can only come from `active_single_heredoc_fallback`. With a nested
    /// operator in the body the input holds three `<<`, which the old
    /// single-operator guard refused, leaving the quoted body unmasked.
    #[test]
    fn fallback_recovers_a_body_holding_a_nested_operator_issue_440() {
        let command = "cat <<'EOF'; echo done\neval <<~'X'\n  y\nX\nEOF";
        let masked = mask_non_expanding_data_heredocs(command);
        assert!(
            !masked.contains("eval"),
            "the recovery must describe a quoted body even when it holds another \
             heredoc operator; got:\n{masked}"
        );
        assert!(
            masked.contains("echo done"),
            "the operator line's own commands stay visible"
        );
    }

    /// The recovery must still refuse when the extra operator is real shell
    /// input rather than body data — after the terminator, where masking it
    /// would erase a command the shell actually runs.
    #[test]
    fn heredoc_operator_after_the_terminator_still_blocks_recovery_issue_440() {
        let command = "cat > /tmp/x.rb <<'OUTER'\neval <<~'SCRIPT'\n  puts 1\nSCRIPT\nOUTER\ncat <<'NEXT'\nx\nNEXT";
        let masked = mask_non_expanding_data_heredocs(command);
        assert!(
            masked.contains("cat <<'NEXT'"),
            "text after the terminator is shell input and must never be erased"
        );
    }

    /// Issue #412: data bytes inside a quoted heredoc body must not decide
    /// whether the body gets masked.
    ///
    /// `„Messen"` in a German commit message leaves an odd number of `"` in the
    /// body. Inside `"$(cat <<'EOF' … )"` that defeated tree-sitter-bash on the
    /// whole command, and the fail-closed answer to a parse error suppressed
    /// masking — so the body was rescanned as live shell, `Read-only` read as a
    /// PowerShell verb-noun, and the commit was denied.
    #[test]
    fn quoted_heredoc_body_bytes_do_not_decide_the_override_answer() {
        let balanced = "git commit -q -m \"$(cat <<'EOF'\na \"b\" c\nRead-only\nEOF\n)\"";
        let unbalanced = "git commit -q -m \"$(cat <<'EOF'\n\u{201e}Messen\"\nRead-only\nEOF\n)\"";
        for command in [balanced, unbalanced] {
            let heredocs = active_heredocs(command).expect("heredoc is delimitable");
            let [heredoc] = heredocs.as_slice() else {
                panic!("expected exactly one heredoc in {command:?}");
            };
            let target = extract_heredoc_target_command(command, heredoc.operator_start)
                .expect("target command");
            assert_eq!(target, "cat");
            assert!(
                !stdin_data_sink_may_be_overridden(command, heredoc.operator_start, &target),
                "an unbalanced quote inside the body is data, not a rebinding: {command:?}"
            );
            assert_ne!(
                mask_non_expanding_data_heredocs(command).as_ref(),
                command,
                "the body must be masked out of the raw-shell rescan: {command:?}"
            );
        }
    }

    /// The blanking retry only neutralizes *quoted* bodies, and preserves every
    /// byte offset so the retry parses the same command.
    #[test]
    fn blanking_preserves_offsets_and_skips_expanding_bodies() {
        let quoted = "git commit -q -m \"$(cat <<'EOF'\n\u{201e}Messen\"\nRead-only\nEOF\n)\"";
        let blanked = quoted_heredoc_bodies_blanked(quoted).expect("quoted body is blanked");
        assert_eq!(
            blanked.len(),
            quoted.len(),
            "blanking must preserve byte offsets"
        );
        assert_eq!(
            blanked.matches('\n').count(),
            quoted.matches('\n').count(),
            "blanking must preserve newlines"
        );
        assert!(!blanked.contains("Read-only"));
        assert!(
            blanked.contains("<<'EOF'") && blanked.contains("EOF\n)"),
            "only the body is blanked, not the operator or terminator: {blanked:?}"
        );

        // An expanding heredoc body is evaluated by the shell, so its bytes can
        // carry a real override and must be left alone.
        assert!(
            quoted_heredoc_bodies_blanked("cat <<EOF\n$(rm -rf /)\nEOF").is_none(),
            "an unquoted delimiter must not be blanked"
        );
    }

    // ========================================================================
    // ssh remote-payload extraction (#326)
    // ========================================================================

    mod ssh_remote_payload_extraction {
        use super::*;

        /// Extraction limits with only the wall clock relaxed.
        ///
        /// These cases assert *which* payloads ssh's option grammar yields, never
        /// how fast the host is, but `ExtractionLimits::default()` also carries
        /// `timeout_ms: 50`. Measured on a 128-core host at load 91, the inline
        /// `heredoc` tests failed 2 of 8 runs here. The size and slot caps keep
        /// their shipped values, so nothing about the grammar under test moves.
        fn ssh_limits() -> ExtractionLimits {
            ExtractionLimits {
                timeout_ms: 5_000,
                ..ExtractionLimits::default()
            }
        }

        fn ssh_payloads(command: &str) -> Vec<String> {
            // Only a completed extraction is an answer. Collapsing everything else
            // into an empty vector let the wall clock decide these tests twice
            // over: the positive assertions flaked, and the negative ones passed
            // for the wrong reason, because
            // `unmodeled_options_bail_without_extraction` cannot tell "ssh refused
            // the option" from "extraction ran out of time" when both yield no
            // payloads. `NoContent`/`Skipped` stay empty since they are real
            // outcomes for these inputs; an incomplete read is now loud instead.
            match extract_content(command, &ssh_limits()) {
                ExtractionResult::Extracted(contents) => contents
                    .into_iter()
                    .filter(|content| content.target_command.as_deref() == Some("ssh"))
                    .map(|content| content.content)
                    .collect(),
                ExtractionResult::NoContent | ExtractionResult::Skipped(_) => Vec::new(),
                incomplete @ (ExtractionResult::Partial { .. } | ExtractionResult::Failed(_)) => {
                    panic!("extraction did not complete for {command:?}: {incomplete:?}")
                }
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
        fn multi_word_payload_keeps_raw_span_and_adds_the_joined_line() {
            // The local shell removes each word's quotes and ssh joins the
            // argv with spaces, so the remote shell runs `cd /app && ls`:
            // the locally quoted `'&&'` is an operator there. The raw span
            // stays (it carries the content range); the joined line is what
            // runs (review of 7273b28: `ssh host 'git reset' --hard`).
            assert_eq!(
                ssh_payloads("ssh host cd /app '&&' ls"),
                ["cd /app '&&' ls", "cd /app && ls"]
            );
            assert_eq!(ssh_payloads("ssh host cd /app"), ["cd /app"]);
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

        // #377: tree-sitter-bash parses `$(…)` inside an expanding heredoc
        // body but leaves backquoted substitutions as plain content, so the
        // two spellings of the same body diverged: `$(…)` was enumerated and
        // `` `…` `` was invisible.
        #[test]
        fn backquoted_substitution_in_unquoted_heredoc_body_is_enumerated() {
            let content = "tee /private/tmp/sink.md <<EOF\n`rm -rf ~/foo`\nEOF\n";
            let found = extract_posix_command_substitutions(content).expect("well-formed");
            assert_eq!(found.len(), 1, "{found:?}");
            assert_eq!(found[0].body, "rm -rf ~/foo");
            assert_eq!(&content[found[0].start..found[0].end], "`rm -rf ~/foo`");

            let dollar = "tee /private/tmp/sink.md <<EOF\n$(rm -rf ~/foo)\nEOF\n";
            let found_dollar = extract_posix_command_substitutions(dollar).expect("well-formed");
            assert_eq!(found_dollar.len(), 1);
            assert_eq!(found_dollar[0].body, found[0].body);
        }

        #[test]
        fn backquoted_substitution_in_heredoc_prose_and_redirect_shapes() {
            for content in [
                "cat > /private/tmp/sink.md <<EOF\nintro\n`rm -rf ~/foo`\noutro\nEOF\n",
                "cat <<EOF | tee /private/tmp/sink.md\n`rm -rf ~/foo`\nEOF\n",
                "cat <<EOF > \"/private/tmp/sink.md\"\n`rm -rf ~/foo`\nEOF\n",
                "tee \"/private/tmp/sink.md\" <<EOF\n`rm -rf ~/foo`\nEOF\n",
                "tee /private/tmp/sink.md <<-EOF\n\t`rm -rf ~/foo`\n\tEOF\n",
                "tee /private/tmp/sink.md << EOF\n`rm -rf ~/foo`\nEOF\n",
            ] {
                let found = extract_posix_command_substitutions(content)
                    .unwrap_or_else(|_| panic!("well-formed: {content:?}"));
                assert_eq!(
                    found.iter().map(|s| s.body.as_str()).collect::<Vec<_>>(),
                    ["rm -rf ~/foo"],
                    "{content:?}"
                );
            }
        }

        #[test]
        fn backquotes_in_quoted_heredoc_body_are_literal_text() {
            for content in [
                "tee /private/tmp/sink.md <<'EOF'\n`rm -rf ~/foo`\nEOF\n",
                "tee /private/tmp/sink.md <<\"EOF\"\n`rm -rf ~/foo`\nEOF\n",
                "tee /private/tmp/sink.md <<\\EOF\n`rm -rf ~/foo`\nEOF\n",
                "tee /private/tmp/sink.md <<E'O'F\n`rm -rf ~/foo`\nEOF\n",
                "tee /private/tmp/sink.md <<-'EOF'\n\t`rm -rf ~/foo`\n\tEOF\n",
                // An odd backtick in prose is fine when nothing expands it.
                "cat > /private/tmp/notes.md <<'EOF'\nuse the `foo command\nEOF\n",
            ] {
                let found = extract_posix_command_substitutions(content)
                    .unwrap_or_else(|_| panic!("well-formed: {content:?}"));
                assert!(found.is_empty(), "{content:?}: {found:?}");
            }
        }

        #[test]
        fn both_spellings_in_one_heredoc_body_are_enumerated_in_order() {
            let content = "tee /private/tmp/sink.md <<EOF\nfoo `git status` bar $(ls)\nEOF\n";
            let found = extract_posix_command_substitutions(content).expect("well-formed");
            assert_eq!(
                found.iter().map(|s| s.body.as_str()).collect::<Vec<_>>(),
                ["git status", "ls"]
            );
            assert!(found[0].end <= found[1].start);
        }

        #[test]
        fn heredoc_backquote_escapes_follow_here_document_rules() {
            // `\`` is a literal backtick in the body and inside a
            // substitution; `\\` is a literal backslash that does not quote
            // the following backtick.
            let content = "tee /private/tmp/sink.md <<EOF\nfoo `ls \\`date\\`` \\`x\nEOF\n";
            let found = extract_posix_command_substitutions(content).expect("well-formed");
            assert_eq!(
                found.iter().map(|s| s.body.as_str()).collect::<Vec<_>>(),
                ["ls `date`"]
            );

            let content = "tee /private/tmp/sink.md <<EOF\n\\\\`rm -rf ~/foo`\nEOF\n";
            let found = extract_posix_command_substitutions(content).expect("well-formed");
            assert_eq!(
                found.iter().map(|s| s.body.as_str()).collect::<Vec<_>>(),
                ["rm -rf ~/foo"]
            );

            // A backtick escaped at the here-document layer never opens.
            let content = "tee /private/tmp/sink.md <<EOF\n\\`rm -rf ~/foo\\`\nEOF\n";
            let found = extract_posix_command_substitutions(content).expect("well-formed");
            assert!(found.is_empty(), "{found:?}");
        }

        #[test]
        fn nested_spellings_inside_heredoc_body_are_enumerated_once() {
            // A backquote wrapping `$(…)`: the outer span is the unit; the
            // inner `$(…)` is reached again when the evaluator recurses.
            let content = "tee /private/tmp/sink.md <<EOF\n`echo $(rm -rf ~/foo)`\nEOF\n";
            let found = extract_posix_command_substitutions(content).expect("well-formed");
            assert_eq!(
                found.iter().map(|s| s.body.as_str()).collect::<Vec<_>>(),
                ["echo $(rm -rf ~/foo)"]
            );

            // `$(…)` wrapping a backquote: the grammar parses the whole
            // `$(…)`; the backticks inside it belong to that body.
            let content = "tee /private/tmp/sink.md <<EOF\n$(echo `rm -rf ~/foo`)\nEOF\n";
            let found = extract_posix_command_substitutions(content).expect("well-formed");
            assert_eq!(
                found.iter().map(|s| s.body.as_str()).collect::<Vec<_>>(),
                ["echo `rm -rf ~/foo`"]
            );

            // A heredoc nested inside a substitution is handled when the
            // evaluator recurses into that substitution's body.
            let outer = "x=$(cat <<EOF\n`rm -rf ~/foo`\nEOF\n)\n";
            let found = extract_posix_command_substitutions(outer).expect("well-formed");
            assert_eq!(found.len(), 1);
            let inner = extract_posix_command_substitutions(&found[0].body).expect("well-formed");
            assert_eq!(
                inner.iter().map(|s| s.body.as_str()).collect::<Vec<_>>(),
                ["rm -rf ~/foo"]
            );
        }

        #[test]
        fn markdown_fences_in_unquoted_heredoc_execute_the_fenced_block() {
            // Three backticks are an empty substitution plus an opener: the
            // outer shell runs the fenced block. The `$(…)` spelling of the
            // same mistake was already denied; the fence form must be too.
            let content =
                "cat > /private/tmp/notes.md <<EOF\n# Notes\n```bash\ngit reset --hard\n```\nEOF\n";
            let found = extract_posix_command_substitutions(content).expect("well-formed");
            assert_eq!(
                found.iter().map(|s| s.body.as_str()).collect::<Vec<_>>(),
                ["", "bash\ngit reset --hard\n", ""]
            );
        }

        #[test]
        fn unterminated_backquote_in_unquoted_heredoc_fails_closed() {
            for content in [
                "tee /private/tmp/sink.md <<EOF\n`rm -rf ~/foo\nEOF\n",
                "tee /private/tmp/sink.md <<EOF\nprose `rm -rf ~/foo\nEOF\n",
                "tee /private/tmp/sink.md <<EOF\n`a` `rm -rf ~/foo\nEOF\n",
            ] {
                assert_eq!(
                    extract_posix_command_substitutions(content),
                    Err(PosixCommandSubstitutionParseError),
                    "{content:?}"
                );
            }
        }

        #[test]
        fn backquote_body_escapes_are_applied_before_nested_parse() {
            // `\$` inside backquotes is a live `$` to the inner shell, so
            // `` `echo \$(rm -rf ~)` `` runs `rm`. The body handed to the
            // nested parse must carry the post-escape text.
            let found = extract_posix_command_substitutions("echo `echo \\$(rm -rf ~/foo)`")
                .expect("well-formed");
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].body, "echo $(rm -rf ~/foo)");
            let nested = extract_posix_command_substitutions(&found[0].body).expect("well-formed");
            assert_eq!(nested.len(), 1);
            assert_eq!(nested[0].body, "rm -rf ~/foo");

            assert_eq!(
                unescape_backquoted_body("a \\$b \\`c\\` \\\\ \\n"),
                "a $b `c` \\ \\n"
            );
            assert_eq!(unescape_backquoted_body("plain"), "plain");
            assert_eq!(unescape_backquoted_body("trailing\\"), "trailing\\");
        }

        #[test]
        fn heredoc_delimiter_quoting_is_judged_from_the_delimiter_word_only() {
            // A quote later on the header line (a piped or redirected
            // target) must not turn an expanding heredoc into a quoted one.
            for content in [
                "cat <<EOF | tee \"/private/tmp/sink.md\"\n$(git reset --hard)\nEOF\n",
                "cat <<EOF > \"/private/tmp/sink.md\"\n$(git reset --hard)\nEOF\n",
                "cat <<EOF | grep 'x'\n$(git reset --hard)\nEOF\n",
            ] {
                let masked = mask_non_expanding_data_heredocs(content);
                assert!(
                    masked.contains("$(git reset --hard)"),
                    "expanding body must survive masking: {content:?} -> {masked:?}"
                );
                let found = extract_posix_command_substitutions(content)
                    .unwrap_or_else(|_| panic!("well-formed: {content:?}"));
                assert_eq!(
                    found.iter().map(|s| s.body.as_str()).collect::<Vec<_>>(),
                    ["git reset --hard"],
                    "{content:?}"
                );
            }
            // A genuinely quoted delimiter is still masked for a data sink.
            let quoted = "cat <<'EOF' | tee /private/tmp/sink.md\n$(git reset --hard)\nEOF\n";
            let masked = mask_non_expanding_data_heredocs(quoted);
            assert!(!masked.contains("$(git reset --hard)"), "{masked:?}");
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
        fn perl_data_heredoc_keeps_its_complete_program_owner() {
            let command =
                "perl <<'PERL'\nprint <<'DATA';\nopen(FH, '>', '/etc/shadow');\nDATA\nPERL";
            let limits = ExtractionLimits {
                max_heredocs: 1,
                ..ExtractionLimits::default()
            };
            let ExtractionResult::Extracted(contents) = extract_content(command, &limits) else {
                panic!("a nested Perl string is neither a program nor a quota overflow");
            };
            assert_eq!(contents.len(), 1);
            assert_eq!(contents[0].delimiter.as_deref(), Some("PERL"));
            assert_eq!(contents[0].language, ScriptLanguage::Perl);
            assert_eq!(
                contents[0].content,
                "print <<'DATA';\nopen(FH, '>', '/etc/shadow');\nDATA"
            );
        }

        #[test]
        fn nested_data_suppression_keeps_later_executable_heredocs() {
            let command = "perl <<'PERL'\nprint <<'DATA';\nopen(FH, '>', '/tmp/out');\nDATA\nPERL\nperl <<'NEXT'\nopen(FH, '>', '/etc/shadow');\nNEXT";
            let ExtractionResult::Extracted(contents) =
                extract_content(command, &ExtractionLimits::default())
            else {
                panic!("both actual Perl programs must be extracted");
            };
            assert_eq!(contents.len(), 2);
            assert_eq!(contents[0].delimiter.as_deref(), Some("PERL"));
            assert_eq!(contents[1].delimiter.as_deref(), Some("NEXT"));
            assert!(contents[1].content.contains("/etc/shadow"));
        }

        #[test]
        fn nested_heredoc_filter_requires_nonexpanding_unrebound_source() {
            for command in [
                "bash <<'OUTER'\ncat <<'DATA'\nhello\nDATA\nOUTER",
                "perl <<OUTER\nprint <<'DATA';\nhello\nDATA\nOUTER",
                "perl() { bash; }; perl <<'OUTER'\ncat <<'DATA'\nhello\nDATA\nOUTER",
                "echo \"perl <<'OUTER'\"\ncat <<'DATA'\nhello\nDATA\nOUTER",
            ] {
                let ExtractionResult::Extracted(contents) =
                    extract_content(command, &ExtractionLimits::default())
                else {
                    panic!("uncertain input must retain the conservative scan: {command}");
                };
                assert!(
                    contents
                        .iter()
                        .any(|source| source.delimiter.as_deref() == Some("DATA")),
                    "{command}"
                );
            }
        }

        #[test]
        fn extraction_limits_default() {
            let limits = ExtractionLimits::default();
            assert_eq!(limits.max_body_bytes, 1024 * 1024);
            assert_eq!(limits.max_body_lines, 10_000);
            assert_eq!(limits.max_heredocs, 10);
            assert_eq!(limits.timeout_ms, 50);
        }

        /// #443: the structural helpers keep every size cap and only relax time.
        ///
        /// The size caps are what bound the work, so they must not drift from the
        /// defaults. The wall clock is the one bound that made a property of the
        /// *command* depend on how loaded the machine was, which is why it alone
        /// is larger here — and it stays finite so a pathological input still
        /// terminates.
        #[test]
        fn structural_scan_limits_relax_only_the_wall_clock_443() {
            let structural = ExtractionLimits::structural_scan();
            let default = ExtractionLimits::default();

            assert_eq!(structural.max_body_bytes, default.max_body_bytes);
            assert_eq!(structural.max_body_lines, default.max_body_lines);
            assert_eq!(structural.max_heredocs, default.max_heredocs);

            assert!(
                structural.timeout_ms > default.timeout_ms,
                "a structural question must not be decided by a budget the host can exhaust"
            );
            assert!(
                structural.timeout_ms > 0,
                "the budget stays finite so a pathological input terminates"
            );
        }

        /// Every *classification* helper has to use the structural budget.
        ///
        /// The six sites of #443 turn a non-`Extracted` result straight into
        /// an answer — `Unverified`, `None`, `false`, "no content" — so with
        /// the 50 ms hot-path budget the verdict followed the machine's load
        /// rather than the command. The two here were fixed first; the four in
        /// the evaluator ask the same kind of question (is this a literal
        /// heredoc producer, is this offset inside a quoted body, does this
        /// range intersect interpreter input) and were audited afterwards.
        ///
        /// The part of a source file compiled outside `cfg(test)`: everything
        /// before the first `#[cfg(test)]` that gates an INLINE module
        /// (`mod x {`), with any attributes between. That relies on no
        /// production item following an inline test module, which holds for
        /// every file under `src/` (what follows one is further test modules
        /// or top-level `#[test]` fns, as in `normalize.rs`).
        ///
        /// Two kinds of `#[cfg(test)]` are deliberately NOT split points, and
        /// getting either wrong makes the guard silently weaker, not stricter:
        ///
        /// - On a non-module item. Production code follows several of those —
        ///   `ast_matcher.rs`'s `FLOOR_MS`, test-only helpers in `evaluator.rs`,
        ///   a `thread_local!` in `allowlist.rs`.
        /// - On an EXTERNAL module (`mod x;`). Its test code lives in the other
        ///   file (see `test_only_files`); this file carries on as production.
        ///   `packs/mod.rs` declares one at line 50 of ~7,000, so treating it as
        ///   a split point would have dropped the whole pack registry from the
        ///   scan while every assertion here still passed.
        ///
        /// It generalizes the old `"\nmod tests {"` split, which missed inline
        /// test modules with other names (`windows_exe_tests`, `test_env`).
        fn production_part(source: &str) -> &str {
            let mut offset = 0;
            let mut lines = source.split_inclusive('\n');
            while let Some(line) = lines.next() {
                if line.trim() == "#[cfg(test)]" {
                    let gated = lines
                        .clone()
                        .map(str::trim)
                        .find(|next| !next.is_empty() && !next.starts_with("#["));
                    let is_inline_module = gated.is_some_and(|item| {
                        let item = item
                            .strip_prefix("pub(crate) ")
                            .or_else(|| item.strip_prefix("pub "))
                            .unwrap_or(item);
                        item.starts_with("mod ") && !item.ends_with(';')
                    });
                    if is_inline_module {
                        return &source[..offset];
                    }
                }
                offset += line.len();
            }
            source
        }

        /// Files that exist only as `#[cfg(test)] mod name;` of some parent.
        ///
        /// Such a file is test code from its first line, so `production_part`
        /// cannot see that — it has no gate of its own. Resolved with the
        /// standard rules: a module declared in `lib.rs`/`main.rs`/`mod.rs`
        /// lives beside it, one declared in `foo.rs` lives under `foo/`, and a
        /// `#[path = "x.rs"]` (the layout `packs/test_template.rs` recommends
        /// for pack tests) is relative to the declaring file's directory.
        fn test_only_files(
            files: &[std::path::PathBuf],
        ) -> std::collections::BTreeSet<std::path::PathBuf> {
            let mut test_only = std::collections::BTreeSet::new();
            for file in files {
                let Ok(source) = std::fs::read_to_string(file) else {
                    continue;
                };
                let Some(dir) = file.parent() else { continue };
                let stem = file.file_stem().and_then(|stem| stem.to_str());
                let child_dir = if matches!(stem, Some("lib" | "main" | "mod")) {
                    dir.to_path_buf()
                } else {
                    dir.join(stem.unwrap_or_default())
                };
                let mut lines = source.lines().map(str::trim);
                while let Some(line) = lines.next() {
                    if line != "#[cfg(test)]" {
                        continue;
                    }
                    let mut path_attribute = None;
                    let Some(item) = lines.clone().find(|next| {
                        if let Some(path) = next
                            .strip_prefix("#[path = \"")
                            .and_then(|rest| rest.strip_suffix("\"]"))
                        {
                            path_attribute = Some(path);
                        }
                        !next.is_empty() && !next.starts_with("#[")
                    }) else {
                        continue;
                    };
                    let item = item
                        .strip_prefix("pub(crate) ")
                        .or_else(|| item.strip_prefix("pub "))
                        .unwrap_or(item);
                    let Some(name) = item
                        .strip_prefix("mod ")
                        .and_then(|rest| rest.strip_suffix(';'))
                    else {
                        continue;
                    };
                    if let Some(path) = path_attribute {
                        test_only.insert(dir.join(path));
                        continue;
                    }
                    test_only.insert(child_dir.join(format!("{name}.rs")));
                    test_only.insert(child_dir.join(name).join("mod.rs"));
                }
            }
            test_only
        }

        #[test]
        fn production_part_splits_only_at_a_gated_module() {
            let source = "fn a() {}\n#[cfg(test)]\nconst FLOOR: u64 = 1;\nfn b() {}\n\
                          #[cfg(test)]\n#[allow(dead_code)]\nmod windows_exe_tests {\n}\n";
            let production = production_part(source);
            assert!(
                production.contains("fn b()"),
                "a gated const is not a module; code after it is still production"
            );
            assert!(
                !production.contains("windows_exe_tests"),
                "a gated module ends production whatever it is named"
            );
            assert_eq!(
                production_part("fn only() {}\n"),
                "fn only() {}\n",
                "a file with no gated module is all production"
            );
            assert!(
                production_part("fn a() {}\n#[cfg(test)]\npub(crate) mod test_env {\n}\n")
                    .ends_with("fn a() {}\n"),
                "visibility on the gated module does not hide it"
            );
            // The regression this guards: an EXTERNAL gated module must not end
            // production. `packs/mod.rs` has one at line 50 of ~7,000.
            let registry = "#[cfg(test)]\nmod test_template;\nstatic REGISTRY: u8 = 0;\n";
            assert_eq!(
                production_part(registry),
                registry,
                "`mod x;` puts its tests in another file; code after it is production"
            );
        }

        #[test]
        fn test_only_files_resolve_external_gated_modules() {
            let root = tempfile::tempdir().expect("tempdir");
            let src = root.path();
            std::fs::create_dir_all(src.join("pack")).unwrap();
            std::fs::write(
                src.join("lib.rs"),
                "#[cfg(test)]\nmod beside;\nmod shipped;\n",
            )
            .unwrap();
            std::fs::write(src.join("pack.rs"), "#[cfg(test)]\nmod tests;\n").unwrap();
            std::fs::write(
                src.join("my_pack.rs"),
                "#[cfg(test)]\n#[path = \"my_pack_tests.rs\"]\nmod tests;\n",
            )
            .unwrap();
            let files = vec![
                src.join("lib.rs"),
                src.join("pack.rs"),
                src.join("my_pack.rs"),
            ];
            let test_only = test_only_files(&files);
            assert!(test_only.contains(&src.join("beside.rs")), "{test_only:?}");
            assert!(
                test_only.contains(&src.join("pack").join("tests.rs")),
                "a module of `pack.rs` lives under `pack/`: {test_only:?}"
            );
            assert!(
                test_only.contains(&src.join("my_pack_tests.rs")),
                "`#[path]` is relative to the declaring file's directory: {test_only:?}"
            );
            assert!(
                !test_only.contains(&src.join("my_pack").join("tests.rs")),
                "`#[path]` replaces the default location: {test_only:?}"
            );
            assert!(
                !test_only.contains(&src.join("shipped.rs")),
                "an ungated module is production"
            );
        }

        /// A source check rather than a timing one on purpose: reproducing the
        /// expiry needs a loaded host, which is the nondeterminism being
        /// removed. `src/perf.rs` guards its own invariants the same way.
        ///
        /// It walks every file under `src/`, not a named list. It used to read
        /// just `heredoc.rs` and `evaluator.rs`, and #461's
        /// `credential_files/embedded.rs` — a new file — repeated this exact
        /// anti-pattern in a classifier the guard could not see: extraction on
        /// the 50 ms budget, anything but a completed result mapped to "no
        /// protected write". A named list only protects the files someone
        /// remembered, so a new file is now covered by default and escapes only
        /// through `HOT_PATH_BUDGET_OWNERS` below.
        #[test]
        fn classification_helpers_use_the_structural_budget_443() {
            /// Files whose job is to materialize the configurable HOT-PATH
            /// extraction budget, which #443 deliberately leaves at 50 ms: that
            /// knob governs extraction work, and a timeout there is handled by
            /// the evaluator's bounded fallback rather than read as an answer.
            /// Add a file here only if it builds that budget — never to let a
            /// classifier keep the default.
            const HOT_PATH_BUDGET_OWNERS: &[&str] = &["src/config.rs"];

            fn rust_sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
                for entry in std::fs::read_dir(dir).expect("read a source directory") {
                    let path = entry.expect("read a source directory entry").path();
                    if path.is_dir() {
                        rust_sources(&path, out);
                    } else if path.extension().is_some_and(|ext| ext == "rs") {
                        out.push(path);
                    }
                }
            }

            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
            let mut files = Vec::new();
            rust_sources(&root.join("src"), &mut files);
            files.sort();
            // Vacuity guard: an empty or near-empty walk would pass trivially.
            assert!(
                files.iter().any(|path| path.ends_with("heredoc.rs"))
                    && files.iter().any(|path| path.ends_with("evaluator.rs"))
                    && files.iter().any(|path| path.ends_with("embedded.rs")),
                "the source walk must reach the files this guard exists for: {files:?}"
            );

            let test_only = test_only_files(&files);
            assert!(
                test_only.contains(&root.join("src/scanner_regression_tests.rs")),
                "external test-module resolution must find the known case: {test_only:?}"
            );

            for path in files {
                let file = path
                    .strip_prefix(root)
                    .expect("walked path is under the manifest dir")
                    .to_string_lossy()
                    .replace('\\', "/");
                if HOT_PATH_BUDGET_OWNERS.contains(&file.as_str()) || test_only.contains(&path) {
                    continue;
                }
                let source = std::fs::read_to_string(&path).expect("read a source file");
                let production = production_part(&source);
                // Doc comments may name the default profile in an example; a
                // call site is what matters.
                let offenders: Vec<_> = production
                    .lines()
                    .enumerate()
                    .filter(|(_, line)| {
                        let code = line.trim_start();
                        !code.starts_with("//") && code.contains("ExtractionLimits::default()")
                    })
                    .map(|(index, line)| format!("{}: {}", index + 1, line.trim()))
                    .collect();
                assert!(
                    offenders.is_empty(),
                    "{file}: a classification helper outside tests still takes the 50 ms \
                     hot-path budget, so its answer depends on how busy the machine is \
                     (#443):\n  {}",
                    offenders.join("\n  ")
                );
            }
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
                panic!("Expected Extracted result, got {result:?}");
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
            // The budget is never reached here: the delimiter lines carry
            // trailing text (`A && cmd2 << B`), so only the last heredoc is
            // terminated and one payload comes out. The other two are reported
            // as unterminated, which is a shape observation rather than an
            // early stop, so the reading is still complete — see
            // `SkipReason::stopped_early` and, for the budget itself,
            // `a_filled_heredoc_budget_is_reported_as_partial` (#427).
            match result {
                ExtractionResult::Extracted(contents) => {
                    assert!(contents.len() <= limits.max_heredocs);
                }
                other => panic!("Expected Extracted result, got {other:?}"),
            }
        }

        /// The budget itself, with terminators the extractor can actually find
        /// (#427). Three complete heredocs against a budget of two: two are
        /// read, the third is dropped, and the drop is reported.
        #[test]
        fn a_filled_heredoc_budget_is_reported_as_partial() {
            let cmd = "cmd1 << A\na\nA\ncmd2 << B\nb\nB\ncmd3 << C\nc\nC";
            let limits = ExtractionLimits {
                max_heredocs: 2,
                ..Default::default()
            };
            match extract_content(cmd, &limits) {
                ExtractionResult::Partial { extracted, skipped } => {
                    assert_eq!(extracted.len(), 2, "the budget should be filled");
                    assert!(
                        skipped
                            .iter()
                            .any(|r| matches!(r, SkipReason::ExceededHeredocLimit { .. })),
                        "should report ExceededHeredocLimit, got {skipped:?}"
                    );
                }
                other => panic!("Expected Partial(limit) result, got {other:?}"),
            }
        }

        /// A here-string is not an unterminated heredoc (#427). The heredoc
        /// regex anchors on `<<`, which also matches the tail of `<<<`; the
        /// phantom reason it produced was harmless only while partial
        /// extractions were reported as complete.
        #[test]
        fn a_here_string_produces_no_phantom_heredoc_reason() {
            for cmd in [
                "cat <<< 'hello world'",
                "cat <<< \"hello world\"",
                "cat <<< plain",
                "grep foo <<< \"$payload\"",
            ] {
                match extract_content(cmd, &ExtractionLimits::default()) {
                    ExtractionResult::Extracted(_) | ExtractionResult::NoContent => {}
                    other => panic!("{cmd:?} must extract completely, got {other:?}"),
                }
            }
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

    /// #439: a `$VAR` on the heredoc's line must not hide its target command.
    ///
    /// `tokenize_backwards` treated a bare `$` as a command boundary, so the walk
    /// stopped before the program word and no target was resolved at all. The
    /// quoted (inert) body then could not be masked, and a line-leading backtick
    /// in it tripped `heredoc.shell:launcher-unverified`. A `$` introduces an
    /// expansion inside a word, not a new command.
    #[test]
    fn extract_heredoc_target_command_resolves_across_dollar_expansions_439() {
        for (command, expected) in [
            // The reported shape: the redirect target is variable-expanded.
            ("S=/tmp && cat > $S/d.md <<'EOF'\nbody\nEOF", Some("cat")),
            // Braced, and quoted — the quoted spelling already worked, which is
            // what pinned the cause.
            ("S=/tmp && cat > ${S}/d.md <<'EOF'\nbody\nEOF", Some("cat")),
            (
                "S=/tmp && cat > \"$S/d.md\" <<'EOF'\nbody\nEOF",
                Some("cat"),
            ),
            // A dynamic operand rather than a dynamic redirect target.
            ("S=/tmp && cat $S/in.md <<'EOF'\nbody\nEOF", Some("cat")),
            (
                "D=/r && git -C $D commit -F - <<'EOF'\nbody\nEOF",
                Some("git"),
            ),
            // An executing interpreter must still resolve to itself, never to a
            // data sink, so its body is never masked.
            ("S=/tmp && bash $S/x <<'EOF'\nbody\nEOF", Some("bash")),
            ("S=/bin && $S/bash <<'EOF'\nbody\nEOF", Some("bash")),
            // A program that is itself an unresolved expansion stays unproven:
            // the token is returned as-is and matches no data sink.
            ("S=cat && $S <<'EOF'\nbody\nEOF", Some("$S")),
            // A command substitution is still a boundary, so nothing is resolved.
            ("cat $(date) <<'EOF'\nbody\nEOF", None),
        ] {
            let start = command.find("<<").expect("heredoc operator");
            assert_eq!(
                extract_heredoc_target_command(command, start).as_deref(),
                expected,
                "target resolution for {command:?}"
            );
        }
    }

    /// The boundary set `tokenize_backwards` actually stops at (#439).
    #[test]
    fn tokenize_backwards_stops_at_command_boundaries_but_not_dollar_439() {
        // A bare `$` keeps the word in the same simple command.
        assert_eq!(
            tokenize_backwards("cat > $S/d.md"),
            vec!["$S/d.md".to_string(), ">".to_string(), "cat".to_string()]
        );
        // Every real separator still ends the walk, so tokens from another
        // command can never be read as this one's.
        for (source, expected_last) in [
            ("echo hi | cat", "cat"),
            ("echo hi; cat", "cat"),
            ("echo hi && cat", "cat"),
            ("(echo hi) cat", "cat"),
            ("x=$(echo hi) cat", "cat"),
        ] {
            let tokens = tokenize_backwards(source);
            assert_eq!(
                tokens,
                vec![expected_last.to_string()],
                "walk should stop at the separator in {source:?}"
            );
        }
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

    #[test]
    fn written_heredoc_uses_its_exact_file_interpreter_519() {
        for (header, runner, language, body) in [
            (
                "cat > /tmp/a.js <<'EOF'",
                "node /tmp/a.js",
                ScriptLanguage::JavaScript,
                "f(u => !x);\n",
            ),
            (
                "cat <<'EOF' > /tmp/a.js",
                "node /tmp/a.js",
                ScriptLanguage::JavaScript,
                "f(u => !x);\n",
            ),
            (
                "/bin/cat 1> '/tmp/a b.py' 0<<'EOF'",
                "/usr/bin/python3 '/tmp/a b.py'",
                ScriptLanguage::Python,
                "import shutil\nshutil.rmtree('/home/user')\n",
            ),
            (
                "cat >| /tmp/a.rb <<'EOF'",
                "ruby /tmp/a.rb",
                ScriptLanguage::Ruby,
                "system('git reset --hard')\n",
            ),
            (
                "cat > /tmp/a.pl <<'EOF'",
                "perl /tmp/a.pl",
                ScriptLanguage::Perl,
                "system('git reset --hard');\n",
            ),
            (
                "cat > /tmp/a.php <<'EOF'",
                "php /tmp/a.php",
                ScriptLanguage::Php,
                "<?php system('git reset --hard'); ?>\n",
            ),
            (
                "cat > /tmp/a.sh <<'EOF'",
                "bash /tmp/a.sh",
                ScriptLanguage::Bash,
                "git reset --hard\n",
            ),
        ] {
            let command = format!("{header}\n{body}EOF\n{runner}");
            let proof = written_heredoc_interpreter(&command).expect("literal script handoff");
            assert_eq!(proof.language, language, "{command}");
            let ExtractionResult::Extracted(contents) =
                extract_content(&command, &ExtractionLimits::structural_scan())
            else {
                panic!("complete extraction required: {command}");
            };
            let content = contents
                .iter()
                .find(|source| source.byte_range.start == proof.operator_start)
                .expect("the exact written body must reach typed analysis");
            assert_eq!(content.language, language, "{command}");
            assert_eq!(
                content.target_command.as_deref(),
                Some(proof.interpreter.as_str())
            );
            assert_eq!(
                content.content,
                body.strip_suffix('\n').expect("body newline"),
                "the complete source must be analyzed"
            );
            assert!(
                mask_non_executing_heredocs(&command).contains(body),
                "raw safety evidence remains visible"
            );
        }
    }

    #[test]
    fn written_script_proof_rejects_ambiguous_file_flows_519() {
        for command in [
            "cat >> /tmp/a.js <<'EOF'\nf(u => !x);\nEOF\nnode /tmp/a.js",
            "cat extra > /tmp/a.js <<'EOF'\nf(u => !x);\nEOF\nnode /tmp/a.js",
            "cat -n > /tmp/a.js <<'EOF'\nf(u => !x);\nEOF\nnode /tmp/a.js",
            "cat 2> /tmp/a.js <<'EOF'\nf(u => !x);\nEOF\nnode /tmp/a.js",
            "cat > /tmp/a.js 3<<'EOF'\nf(u => !x);\nEOF\nnode /tmp/a.js",
            "cat > /tmp/a.js < other <<'EOF'\nf(u => !x);\nEOF\nnode /tmp/a.js",
            "cat > /tmp/a.js > /tmp/b.js <<'EOF'\nf(u => !x);\nEOF\nnode /tmp/a.js",
            "cat > /tmp/a.js <<EOF\nf(u => !x);\nEOF\nnode /tmp/a.js",
            "cat > /tmp/a.js <<'EOF'\nf(u => !x);\nEOF\nnode /tmp/b.js",
            "cat > /tmp/a.js <<'EOF'\nf(u => !x);\nEOF\nenv node /tmp/a.js",
            "cat > /tmp/a.js <<'EOF'\nf(u => !x);\nEOF\n/tmp/node /tmp/a.js",
            "cat > /tmp/a.js <<'EOF'\nf(u => !x);\nEOF\nnode /tmp/a.js\nbash /tmp/a.js",
            "alias node=bash\ncat > /tmp/a.js <<'EOF'\nf(u => !x);\nEOF\nnode /tmp/a.js",
            "for n in 1 2; do cat > /tmp/a.js <<'EOF'\nf(u => !x);\nEOF\nnode /tmp/a.js; done",
            "cat > /proc/self/fd/1 <<'EOF'\nf(u => !x);\nEOF\nnode /proc/self/fd/1",
        ] {
            assert!(
                written_heredoc_interpreter(command).is_none(),
                "must retain conservative analysis: {command}"
            );
            assert!(
                written_javascript_arrow_offsets(command).is_empty(),
                "unproven source cannot exempt an arrow: {command}"
            );
        }
    }

    #[test]
    fn written_javascript_arrow_proof_excludes_strings_and_comments_519() {
        let command = "mkdir -p /tmp/x && cat >/tmp/x/a.js <<'EOF'\n// => !comment\nconst text = 'π => !string';\nf(u => !x);\nEOF\nnode /tmp/x/a.js";
        let arrow = command.find("u =>").expect("arrow") + 3;
        assert_eq!(written_javascript_arrow_offsets(command), vec![arrow]);
        assert_eq!(command.as_bytes()[arrow], b'>');
        assert!(mask_non_executing_heredocs(command).contains("=> !string"));
        // A body that cannot be parsed is never syntax evidence.
        let malformed = "cat >/tmp/a.js <<'EOF'\nf(u => !x;\nEOF\nnode /tmp/a.js";
        assert!(written_javascript_arrow_offsets(malformed).is_empty());
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
    fn semicolon_after_heredoc_operator_keeps_data_sink_masking_393() {
        // tree-sitter-bash rejects `<<EOF; …` on the operator line; the
        // masking view used to lose the whole heredoc and re-scan the data
        // body as shell, while `&&` / `|` joins of the same command masked.
        let body = "undo with git restore . later";
        for command in [
            format!("cat <<EOF; echo done\n{body}\nEOF"),
            format!("cat <<'EOF'; echo done\n{body}\nEOF"),
            format!("cat <<\"EOF\"; echo done\n{body}\nEOF"),
            format!("cat <<-EOF; echo done\n\t{body}\n\tEOF"),
            format!("cat << EOF ; echo done\n{body}\nEOF"),
            format!("tee notes.md <<EOF; git status\n{body}\nEOF"),
            format!("git commit -F - <<EOF; git push\n{body}\nEOF"),
            format!("git commit -F - <<'EOF'; git push origin HEAD\n{body}\nEOF"),
            format!("cat <<EOF; echo done\n{body}\nEOF\necho after"),
        ] {
            let masked = mask_non_executing_heredocs(&command);
            assert!(
                !masked.contains("restore"),
                "data-sink body must be masked despite `;` on the operator line: {command:?} -> {masked:?}"
            );
            assert!(
                masked.contains("<<") && masked.contains("EOF"),
                "operator and terminator lines stay intact: {masked:?}"
            );
            let operator_line = command.lines().next().expect("operator line");
            assert!(
                masked.starts_with(operator_line),
                "commands on the operator line stay visible: {masked:?}"
            );
            if command.ends_with("echo after") {
                assert!(
                    masked.ends_with("echo after"),
                    "text after the terminator stays visible: {masked:?}"
                );
            }
        }
    }

    #[test]
    fn semicolon_fallback_never_masks_executing_or_ambiguous_input_393() {
        let destructive = "rm -r ./tree";
        for command in [
            // Executing receivers keep their body visible.
            format!("bash <<EOF; echo done\n{destructive}\nEOF"),
            format!("sh <<'EOF'; echo done\n{destructive}\nEOF"),
            format!("python3 - <<'PY'; echo done\nimport os; os.system('{destructive}')\nPY"),
            // Two operators with a parse error stay fully visible.
            format!("cat <<A; cat <<B; )\nx\nA\n{destructive}\nB"),
            // Quote-removal delimiters are not recovered (real terminator is EOF).
            format!("cat <<'E'OF; echo done\ndata\nEOF\n{destructive}\nE"),
            format!("cat <<E\\OF; echo done\ndata\nEOF\n{destructive}\nE\\OF"),
            // A commented-out operator is not a heredoc at all.
            format!("echo hi; ) # <<EOF\n{destructive}\nEOF"),
            // Unterminated body: no terminator, no recovery.
            format!("cat <<EOF; echo done\n{destructive}"),
        ] {
            let masked = mask_non_executing_heredocs(&command);
            assert!(
                masked.contains(destructive),
                "fallback must not mask this input: {command:?} -> {masked:?}"
            );
        }
    }

    #[test]
    fn git_stdin_sink_accepts_glued_flags_and_stdin_device_paths_393() {
        let body = "undo with git restore . later";
        for command in [
            format!("git commit -aF - <<EOF\n{body}\nEOF"),
            format!("git commit -sF- <<EOF\n{body}\nEOF"),
            format!("git commit -qaF - <<EOF\n{body}\nEOF"),
            format!("git commit -F /dev/stdin <<EOF\n{body}\nEOF"),
            format!("git commit --file=/dev/stdin <<EOF\n{body}\nEOF"),
            format!("git commit --file /dev/fd/0 <<EOF\n{body}\nEOF"),
            format!("git merge --no-ff -F - feature <<EOF\n{body}\nEOF"),
            format!("git merge -eF - feature <<EOF\n{body}\nEOF"),
            format!("git tag -aF - v1 <<EOF\n{body}\nEOF"),
        ] {
            let heredoc_start = command.find("<<").expect("operator");
            assert!(
                is_git_stdin_data_sink(&command, heredoc_start),
                "must be recognized as a git stdin data sink: {command:?}"
            );
            let masked = mask_non_executing_heredocs(&command);
            assert!(
                !masked.contains("restore"),
                "commit-message body must be masked: {command:?} -> {masked:?}"
            );
        }
        for command in [
            // `-c F`: reuse message from commit `F`; `-` is not stdin here.
            format!("git commit -cF - <<EOF\n{body}\nEOF"),
            // `-m F`-style value flags glued before F likewise disqualify.
            format!("git commit -mF - <<EOF\n{body}\nEOF"),
            // A real file operand is not stdin.
            format!("git commit -aF msg.txt <<EOF\n{body}\nEOF"),
            // Unknown subcommands may be aliases.
            format!("git publish -F - <<EOF\n{body}\nEOF"),
        ] {
            let heredoc_start = command.find("<<").expect("operator");
            assert!(
                !is_git_stdin_data_sink(&command, heredoc_start),
                "must NOT be treated as a git stdin data sink: {command:?}"
            );
        }
    }

    #[test]
    fn gh_stdin_text_operands_are_data_sinks_393() {
        let body = "undo with git restore . later";
        for command in [
            format!("gh issue comment 42 --body-file - <<'EOF'\n{body}\nEOF"),
            format!("gh issue comment 42 -F - <<EOF\n{body}\nEOF"),
            format!("gh pr create --title t --body-file=- <<'EOF'\n{body}\nEOF"),
            format!("gh pr comment 7 --body-file /dev/stdin <<'EOF'\n{body}\nEOF"),
            format!("gh release create v1 --notes-file - <<'EOF'\n{body}\nEOF"),
            format!("gh api repos/o/r/issues --input - <<'EOF'\n{{\"body\":\"{body}\"}}\nEOF"),
            format!("GH_TOKEN=x gh issue create -t t -F - <<'EOF'\n{body}\nEOF"),
        ] {
            let heredoc_start = command.find("<<").expect("operator");
            assert!(
                is_gh_stdin_data_sink(&command, heredoc_start),
                "must be recognized as a gh stdin data sink: {command:?}"
            );
            let masked = mask_non_executing_heredocs(&command);
            assert!(
                !masked.contains("restore"),
                "gh text body must be masked: {command:?} -> {masked:?}"
            );
        }
        for command in [
            // `gh api -F` is a typed request field, not a file operand.
            format!("gh api repos/o/r/issues -F - <<'EOF'\n{body}\nEOF"),
            // No stdin operand at all.
            format!("gh issue comment 42 <<'EOF'\n{body}\nEOF"),
            // Extensions and unknown subcommands are not proven data sinks.
            format!("gh dash --body-file - <<'EOF'\n{body}\nEOF"),
            // A real file operand is not stdin.
            format!("gh pr create --body-file body.md <<'EOF'\n{body}\nEOF"),
        ] {
            let heredoc_start = command.find("<<").expect("operator");
            assert!(
                !is_gh_stdin_data_sink(&command, heredoc_start),
                "must NOT be treated as a gh stdin data sink: {command:?}"
            );
        }
    }

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

        #[test]
        fn syntax_view_preserves_outer_source_and_raw_interpreter_analysis() {
            let command = "echo before\npython3 - <<'PY'\na = 'it\\'s'\nb = '#'\nc = re.compile(r\"^\")\nlabel = 'café'\nrun('rm -rf ~')\nPY\ngit reset --hard";
            let masked = mask_inert_interpreter_stdin(command);
            assert!(!masked.contains("re.compile"));
            assert!(!masked.contains("run("));
            assert_eq!(masked.len(), command.len());
            assert_eq!(masked.lines().count(), command.lines().count());
            assert!(masked.starts_with("echo before\npython3 - <<'PY'\n"));
            assert!(masked.ends_with("PY\ngit reset --hard"));
            assert_eq!(
                masked.find("git reset --hard"),
                command.find("git reset --hard")
            );
            assert!(mask_non_expanding_data_heredocs(command).contains("run('rm -rf ~')"));
        }

        #[test]
        fn syntax_view_requires_a_proven_program_from_stdin() {
            for header in [
                "python3 -",
                "/usr/bin/python3 -",
                "node -",
                "ruby",
                "perl -",
                "php",
            ] {
                let command = format!("{header} <<'EOF'\ncopy nul .git\\config\nEOF");
                assert!(
                    !mask_inert_interpreter_stdin(&command).contains("copy nul"),
                    "{command}"
                );
            }
            for command in [
                "python3 -c 'import os,sys; os.system(sys.stdin.read())' <<'PY'\ncopy nul .git\\config\nPY",
                "python3 script.py <<'PY'\ncopy nul .git\\config\nPY",
                "python3 <<'PY' script.py\ncopy nul .git\\config\nPY",
                "node -e 'eval(require(\"fs\").readFileSync(0,\"utf8\"))' <<'JS'\ncopy nul .git\\config\nJS",
                "python3 - <<PY\n$(git reset --hard)\nPY",
                "bash <<'SH'\ncopy nul .git\\config\nSH",
                "env python3 - <<'PY'\ncopy nul .git\\config\nPY",
                "python3() { bash -s; }; python3 - <<'PY'\ncopy nul .git\\config\nPY",
                "PATH=/tmp python3 - <<'PY'\ncopy nul .git\\config\nPY",
                "/tmp/python3 - <<'PY'\ncopy nul .git\\config\nPY",
            ] {
                assert_eq!(mask_inert_interpreter_stdin(command), command, "{command}");
            }
        }

        #[test]
        fn quoted_body_lookup_keeps_operator_identity() {
            let command = "cat <<'A'\nsame text\nA\ncat <<B\nsame text\nB";
            let quoted = command.find("<<'A'").unwrap();
            let expanding = command.find("<<B").unwrap();
            let body = quoted_heredoc_body_at(command, quoted).expect("quoted body");
            assert!(command[body].contains("same text"));
            assert!(quoted_heredoc_body_at(command, expanding).is_none());
            assert!(quoted_heredoc_body_at(command, quoted + 1).is_none());
        }

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

    /// Fifth review: stages of the longest pipeline, the bound that keeps a
    /// many-thousand-stage pipeline away from the bash parser.
    #[test]
    fn longest_pipeline_stages_counts_one_pipeline_at_a_time() {
        for (command, stages) in [
            ("ls", 1),
            ("a | b", 2),
            ("a | b | c; d | e", 3),
            ("a | b && c | d | e | f", 4),
            ("a |& b |& c", 3),
            ("a || b || c", 1),
            ("a & b | c", 2),
            ("echo 'a|b|c|d' | wc", 2),
            ("a | b\nc | d", 2),
        ] {
            assert_eq!(longest_pipeline_stages(command), stages, "{command:?}");
        }
        assert_eq!(
            longest_pipeline_stages(&format!("x{}", " | cat".repeat(5000))),
            5001
        );
    }

    /// Sixth review: a redirect before or after an interpreter's inline flag,
    /// and a shell's options between `-c` and its command string, hid the
    /// payload from tier 1 and tier 2. Each payload is read exactly once.
    #[test]
    fn inline_flag_behind_redirects_and_shell_options_extracts_the_payload() {
        for (command, payload) in [
            ("sh 2>/dev/null -c 'git reset --hard'", "git reset --hard"),
            ("sh 2>&1 -c 'x'", "x"),
            ("sh 2> /dev/null -c 'x'", "x"),
            ("sh 2>& 1 -c 'x'", "x"),
            ("bash &>/dev/null -c 'x'", "x"),
            ("bash &>>log -c 'x'", "x"),
            ("zsh >|/tmp/o -c 'x'", "x"),
            ("dash {fd}>/dev/null -c 'x'", "x"),
            ("sh <>/tmp/o -c 'x'", "x"),
            ("sh 3<&0- -c 'x'", "x"),
            ("sh 2>\"/tmp/a b\" -c 'x'", "x"),
            ("sh -e 2>/dev/null -c \"x\"", "x"),
            ("sh -c 2>/dev/null 'x'", "x"),
            ("sh -c -- 'x'", "x"),
            ("sh -c - \"x\"", "x"),
            ("bash -c -e 'x'", "x"),
            ("bash -c -o errexit 'x'", "x"),
            ("bash -c +e -- 'x'", "x"),
            ("bash -c 2>&1 -x 2>/dev/null 'x'", "x"),
            ("bash +e -c 'x'", "x"),
            ("sh -c -- $CMD", "$CMD"),
            ("sh 2>/dev/null -c $CMD", "$CMD"),
            ("python3 2>/dev/null -c 'x'", "x"),
            ("python3 -c 2>/dev/null 'x'", "x"),
            ("sh>/dev/null -c 'x'", "x"),
            ("sh -c 'x'>/dev/null", "x"),
            ("sh -c 2>/dev/null 'echo a >/tmp/b'", "echo a >/tmp/b"),
            // Seventh review: a here-string, and a redirect target holding
            // a command substitution, backquotes or a `${…}` with blanks.
            ("sh <<<y -c 'x'", "x"),
            ("bash <<<'a b' -c 'x'", "x"),
            ("sh 2>$(mktemp -u) -c 'x'", "x"),
            ("sh 2>`mktemp -u` -c 'x'", "x"),
            ("sh 2>${d:-a b}/f -c 'x'", "x"),
        ] {
            assert!(
                matches!(check_triggers(command), TriggerResult::Triggered),
                "{command:?} must trigger"
            );
            let contents = match extract_content(command, &ExtractionLimits::default()) {
                ExtractionResult::Extracted(contents) => contents,
                other => panic!("{command:?}: {other:?}"),
            };
            let reads = contents.iter().filter(|c| c.content == payload).count();
            assert_eq!(reads, 1, "{command:?}: {contents:?}");
        }
        // A redirect's target is not a flag: `sh 2> -c 'x'` writes to a file
        // named `-c` and runs the script file `x`. A quoted word after the
        // command string is an argument (`$0`), not a second command string.
        for (command, not_payload) in [("sh 2> -c 'x'", "x"), ("sh -c 'x' 2>/dev/null -e 'y'", "y")]
        {
            let contents = match extract_content(command, &ExtractionLimits::default()) {
                ExtractionResult::Extracted(contents) => contents,
                ExtractionResult::NoContent => Vec::new(),
                other => panic!("{command:?}: {other:?}"),
            };
            assert!(
                !contents.iter().any(|c| c.content == not_payload),
                "{command:?}: {contents:?}"
            );
        }
    }

    /// Sixth review: the redirect view blanks exactly the local redirects,
    /// never text inside quotes, a heredoc or a process substitution.
    #[test]
    fn blank_local_redirects_blanks_only_redirect_words() {
        for (command, expected) in [
            ("sh 2>/dev/null -c 'x'", Some("sh             -c 'x'")),
            ("sh 2> /dev/null -c 'x'", Some("sh              -c 'x'")),
            ("a 2>&1 >&- 3<&0- b", Some("a                b")),
            ("a &>l &>>l >|l <>l b", Some("a                  b")),
            ("a {fd}>l {9x}>l b", Some("a        {9x}   b")),
            ("a>l b", Some("a   b")),
            ("a 2>\"x y\" b", Some("a         b")),
            ("echo 'x > y' \"a <b\"", None),
            ("cat <<EOF", None),
            // Seventh review: a here-string is a redirect, and a target's
            // `$(…)`, backquotes and `${…}` belong to it, blanks and all.
            ("cat 2<<-EOF <<<x", Some("cat 2<<-EOF     ")),
            ("a <<<'x y' b", Some("a          b")),
            ("a 2>$(mktemp -u) b", Some("a                b")),
            ("a 2>`mktemp -u` b", Some("a               b")),
            ("a 2>${d:-x y}/f b", Some("a               b")),
            ("cat <<<", None),
            ("cat <(ls) >(wc)", None),
            ("a 2>", None),
            ("ls", None),
        ] {
            assert_eq!(
                blank_local_redirects(command).as_deref(),
                expected,
                "{command:?}"
            );
        }
    }

    /// Sixth review: bash expands a process substitution anywhere in an
    /// unquoted word (`--x=<(…)`), not only at its start.
    #[test]
    fn process_substitution_bodies_are_found_anywhere_in_a_word() {
        for (word, expected) in [
            ("<(a)", vec!["a"]),
            ("--x=<(a b)", vec!["a b"]),
            ("a<(b)>(c)", vec!["b", "c"]),
            ("<(a <(b))", vec!["a <(b)"]),
            ("$'\\''<(a)", vec!["a"]),
            ("'<(a)'", vec![]),
            ("\"<(a)\"", vec![]),
            ("\\<(a)", vec![]),
            ("$(<(a))", vec![]),
            ("$'\\'<(a)'", vec![]),
            ("<()", vec![]),
            ("<(a", vec![]),
        ] {
            let bodies: Vec<&str> = process_substitution_bodies(word)
                .into_iter()
                .map(|body| &word[body])
                .collect();
            assert_eq!(bodies, expected, "{word:?}");
        }
    }

    /// Seventh review: the Windows wrappers (`cmd /c`, `-EncodedCommand`,
    /// `iex`, `Start-Process`) did not read the redirect view, so a redirect
    /// between the program and its flag hid the payload
    /// (`pwsh 2>$null -EncodedCommand …`, `cmd 2>nul /c …`). Each payload is
    /// read once, from the command's own text.
    #[test]
    fn windows_wrappers_behind_redirects_extract_the_payload_once() {
        // "git reset --hard" as base64 UTF-16LE.
        let encoded = "ZwBpAHQAIAByAGUAcwBlAHQAIAAtAC0AaABhAHIAZAA=";
        let reset = "git reset --hard";
        for (command, payload) in [
            (format!("pwsh 2>$null -EncodedCommand {encoded}"), reset),
            (format!("powershell 2>&1 -enc {encoded}"), reset),
            (format!("pwsh -EncodedCommand {encoded} 2>$null"), reset),
            (format!("cmd 2>nul /c \"{reset}\""), reset),
            (format!("cmd >nul /c {reset}"), reset),
            (format!("iex 2>$null '{reset}'"), reset),
            ("cmd /c dir 2>nul".to_string(), "dir 2>nul"),
        ] {
            let contents = match extract_content(&command, &ExtractionLimits::default()) {
                ExtractionResult::Extracted(contents) => contents,
                other => panic!("{command:?}: {other:?}"),
            };
            let reads = contents.iter().filter(|c| c.content == payload).count();
            assert_eq!(reads, 1, "{command:?}: {contents:?}");
        }
    }

    /// #510: a launcher quoted as prose in another command's argument.
    mod quoted_launcher_prose {
        use super::*;

        /// Ask the predicate about the first `bash`/`sh`/`python3` word.
        fn prose(command: &str) -> bool {
            let start = ["bash", "sh ", "python3"]
                .iter()
                .filter_map(|needle| command.find(needle))
                .min()
                .unwrap_or_else(|| panic!("no launcher in {command:?}"));
            inline_launcher_is_quoted_prose(command, start)
        }

        #[test]
        fn prose_inside_a_quoted_argument_is_not_a_launcher() {
            for command in [
                "t c 1 \"example: bash -c 'git reset --hard' is refused\"",
                "t c 1 'example: bash -c \"git reset --hard\"'",
                "t c 1 \"run /usr/bin/bash -c 'x'\"",
                "t c 1 \"note, python3 -c 'import os'\"",
                "t --body=\"the hook blocks bash -c 'x'\"",
                "t \"a 'b' bash -c 'x'\"",
                "t \"$(echo 'note: bash -c x')\"",
            ] {
                assert!(prose(command), "{command}");
            }
        }

        #[test]
        #[allow(clippy::literal_string_with_formatting_args)] // shell `${…}`, not a format
        fn launchers_that_may_run_are_kept() {
            for command in [
                // Unquoted, or the quoted text opens with the launcher.
                "bash -c 'x'",
                "t bash -c 'x'",
                "\"bash\" -c 'x'",
                "t \"bash -c 'x'\"",
                "t \"  bash -c 'x'\"",
                "t \"FOO=1 bash -c 'x'\"",
                // A separator, wrapper, runner or reserved word before it.
                "t \"x; bash -c 'x'\"",
                "t \"x && bash -c 'x'\"",
                "t \"x\nbash -c 'x'\"",
                "t \"sudo bash -c 'x'\"",
                "t \"timeout 5 bash -c 'x'\"",
                "t \"xargs bash -c 'x'\"",
                "t \"ssh host bash -c 'x'\"",
                "t \"then bash -c 'x'\"",
                "t \"/usr/bin/env bash -c 'x'\"",
                // Inside a substitution, whatever the quoting.
                "t \"note $(bash -c 'x')\"",
                "t \"note `bash -c 'x'`\"",
                "t 'x' $(bash -c 'y')",
                // A first word that is not plain prose.
                "t \"$X bash -c 'x'\"",
                "t \"-v bash -c 'x'\"",
                // Constructs the walk does not follow.
                "cat <<EOF\nnote: bash -c 'x'\nEOF",
                "t \"${A:-note} bash -c 'x'\"",
                "t $'note bash -c x'",
                "# note \"x bash -c 'y'\"",
                "t \\\"note bash -c 'x'",
            ] {
                assert!(!prose(command), "{command}");
            }
        }

        #[test]
        fn extraction_skips_only_the_prose_launcher() {
            let limits = ExtractionLimits::default();
            let contents = |command: &str| match extract_content(command, &limits) {
                ExtractionResult::Extracted(contents) => contents,
                ExtractionResult::NoContent => Vec::new(),
                other => panic!("{command:?}: {other:?}"),
            };
            assert!(contents("t c \"example: bash -c 'git reset --hard'\"").is_empty());
            let live = contents("t c \"example\" && bash -c 'git reset --hard'");
            assert_eq!(live.len(), 1, "{live:?}");
            assert_eq!(live[0].content, "git reset --hard");
        }
    }

    /// #511: what an awk program prints into a shell that runs its stdin.
    mod awk_printed_into_shell {
        use super::*;

        fn printed(program: &str) -> Vec<AwkPrintedScript> {
            awk_shell_payload_ranges(program, 0).printed
        }

        fn script(program: &str) -> Option<String> {
            let found = printed(program);
            assert_eq!(found.len(), 1, "{program:?}: {found:?}");
            found.into_iter().next().and_then(|p| p.script)
        }

        #[test]
        fn stdin_shells_are_recognised() {
            for target in [
                "sh",
                "bash",
                "/bin/sh",
                "dash",
                "zsh",
                "bash -e",
                "sh -s",
                "sh -s arg",
                "bash -",
                "bash -o pipefail",
                "sudo sh",
                "env bash",
                "bash --norc",
            ] {
                assert!(awk_pipe_target_runs_stdin_as_script(target), "{target}");
            }
            for target in [
                "cat",
                "sort -u",
                "sh -c cat",
                "bash -ec 'x'",
                "sh run.sh",
                "sh -- run.sh",
                "python3",
                "",
            ] {
                assert!(!awk_pipe_target_runs_stdin_as_script(target), "{target}");
            }
        }

        #[test]
        fn literal_prints_become_the_script() {
            assert_eq!(
                script("BEGIN{print \"git reset --hard\" | \"sh\"}").as_deref(),
                Some("git reset --hard")
            );
            assert_eq!(
                script("BEGIN{print(\"a\", \"b\") | \"sh\"}").as_deref(),
                Some("a b")
            );
            assert_eq!(
                script("BEGIN{print \"a\" \"b\" | \"sh\"}").as_deref(),
                Some("ab")
            );
            assert_eq!(
                script("BEGIN{printf \"rm x\\n100%%\" | \"sh\"}").as_deref(),
                Some("rm x\n100%")
            );
            assert_eq!(
                script("BEGIN{x=1; print \"q;}\" | \"sh\"}").as_deref(),
                Some("q;}")
            );
            assert_eq!(
                script("BEGIN{print \\\"git reset --hard\\\" | \\\"sh\\\"}").as_deref(),
                Some("git reset --hard")
            );
        }

        #[test]
        fn a_variable_assigned_one_literal_is_resolved() {
            let found = printed("BEGIN{cmd=\"git reset --hard\"; print cmd | \"sh\"}");
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].script.as_deref(), Some("git reset --hard"));
            assert_eq!(found[0].variable.as_deref(), Some("cmd"));
        }

        #[test]
        fn computed_prints_are_reported_without_a_script() {
            for program in [
                "{print \"rm \" $1 | \"sh\"}",
                "{print $0 | \"sh\"}",
                "BEGIN{c=\"ls\"; c=c \" -l\"; print c | \"sh\"}",
                "BEGIN{c=\"ls\"; c=\"rm\"; print c | \"sh\"}",
                "{getline c; print c | \"sh\"}",
                "BEGIN{printf \"%s\\n\", \"ls\" | \"sh\"}",
                "BEGIN{print toupper(\"ls\") | \"sh\"}",
            ] {
                assert_eq!(script(program), None, "{program}");
            }
        }

        #[test]
        fn pipes_into_non_shells_report_nothing_printed() {
            for program in [
                "{print $1 | \"sort\"}",
                "BEGIN{print \"x\" | \"sh -c cat\"}",
                "BEGIN{print \"x\" > \"out\"}",
                "BEGIN{if (a || b) print \"x\"}",
            ] {
                assert!(printed(program).is_empty(), "{program}");
            }
        }

        #[test]
        fn non_ascii_programs_do_not_panic() {
            let _ = printed("BEGIN{é=\"ü\"; cmd=\"ls\"; print cmd | \"sh\"} # ß");
            let _ = printed("BEGIN{print \"日本\" | \"sh\"}");
        }
    }
}
