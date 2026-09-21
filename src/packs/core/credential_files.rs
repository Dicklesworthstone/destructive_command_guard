//! The credential-write policy, shared by shell sinks and embedded code.
//!
//! Keep the shell parser and protected-path table in one place. Embedded APIs
//! contribute a statically identified destination and effective write mode;
//! they do not introduce a second path policy or a separate allowlist rule.

mod embedded;
mod shell;

pub(crate) use shell::{
    CREDENTIAL_FILE_WRITE_NAME, CREDENTIAL_FILE_WRITE_SUGGESTIONS, CredentialFileWrite,
    GIT_INTERNALS_WRITE_NAME, GIT_INTERNALS_WRITE_SUGGESTIONS, may_name_protected_path,
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
