//! The credential-write policy, shared by shell sinks and embedded code.
//!
//! Keep the shell parser and protected-path table in one place. Embedded APIs
//! contribute a statically identified destination and effective write mode;
//! they do not introduce a second path policy or a separate allowlist rule.

mod embedded;
mod shell;

pub(crate) use embedded::{scan_extracted, source_scan_required};
// The two rule NAMES are deliberately not re-exported: every hit carries the
// rule it denies under, so the evaluator reads `hit.rule` instead of choosing
// one. That is what keeps `.git/` writes allowlistable separately from
// credential writes (#457); a caller reaching for a name here would be
// guessing at something the classifier already decided.
pub(crate) use shell::{
    CREDENTIAL_FILE_WRITE_SUGGESTIONS, CredentialFileWrite, GIT_INTERNALS_WRITE_SUGGESTIONS,
    may_name_protected_path,
};

use crate::normalize::ShellDialect;

pub(crate) fn is_credential_writer(executable: &str) -> bool {
    shell::is_credential_writer(executable) || embedded::is_interpreter(executable)
}

pub(crate) fn classify_credential_file_write(
    segment: &str,
    dialect: ShellDialect,
) -> Option<CredentialFileWrite> {
    shell::classify_credential_file_write(segment, dialect)
        .or_else(|| embedded::classify(segment, dialect))
}

/// The embedded arm alone, for a caller that can hand over the WHOLE command.
///
/// [`classify_credential_file_write`] is called once per shell segment, and every
/// delivery mechanism that carries interpreter code out-of-band splits the
/// interpreter from its code across segment boundaries:
///
/// - a heredoc body is separated from `python3 <<'PY'` by newlines, which are
///   command separators, so the body becomes its own segment;
/// - a pipeline (`echo '…' | python3`) puts the interpreter in its own segment;
/// - a here-string (`python3 <<< '…'`) carries no heredoc type for the
///   extractor to key on.
///
/// In each case the segment naming `python3` contains no code and the segment
/// holding the code names no interpreter, so [`embedded::classify`] — which
/// needs both together — could never fire. Inline `-c`/`-e` worked precisely
/// because there the code IS inside the segment, which is why the gap read as
/// "embedded code is unguarded" when the classifier was in fact correct and
/// simply never received a body (#461).
///
/// The embedded arm parses the command itself (shell AST, then the interpreter's
/// own AST), so a whole command is what it is built for; handing it one is not a
/// widening of its contract.
pub(crate) fn classify_embedded_credential_file_write(
    command: &str,
    dialect: ShellDialect,
) -> Option<CredentialFileWrite> {
    embedded::classify(command, dialect)
}
