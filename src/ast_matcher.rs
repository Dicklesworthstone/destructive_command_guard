//! Policy composition for executable heredoc and inline-script source.
//!
//! The pattern engine remains independently configurable. The evaluator's
//! default matcher and early filesystem backstop also consult core's shared
//! protected-write classifier. A shell segment is too late for that check:
//! interpreter source has already been masked from that view (#461).
//!
//! Keep core rule identities in dotted AST form. The evaluator's existing
//! `split_ast_rule_id` turns `core.filesystem.credential-file-write` back into
//! the same pack/rule pair used for shell writes and scoped allowlists.

#[path = "ast_pattern_engine.rs"]
mod pattern_engine;
pub use pattern_engine::*;

use crate::heredoc::ScriptLanguage;
use crate::packs::core::credential_files;
use pattern_engine as engine;
use std::ops::Deref;
use std::sync::{LazyLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

/// The default executable-source matcher, including the shared core policy.
/// Custom `AstMatcher::with_patterns` instances retain their explicit corpus.
#[derive(Debug, Default)]
pub struct DefaultPolicyMatcher;

/// The entry point used by the evaluator after source extraction.
pub static DEFAULT_MATCHER: LazyLock<DefaultPolicyMatcher> =
    LazyLock::new(DefaultPolicyMatcher::default);

impl Deref for DefaultPolicyMatcher {
    type Target = engine::AstMatcher;

    fn deref(&self) -> &Self::Target {
        &engine::DEFAULT_MATCHER
    }
}

impl DefaultPolicyMatcher {
    /// Match both the configured built-in AST corpus and core write policy.
    /// A source-budget failure is an error, never a successful empty result.
    pub fn find_matches(
        &self,
        code: &str,
        language: ScriptLanguage,
    ) -> Result<Vec<PatternMatch>, MatchError> {
        let protected = protected_matches(code, language);
        let mut matches = engine::DEFAULT_MATCHER.find_matches(code, language)?;
        match protected {
            Ok(protected) => matches.extend(protected),
            // A new classifier's limit must not suppress a deletion/exec
            // denial the existing engine has already established.
            Err(_) if matches.iter().any(|hit| hit.severity.blocks_by_default()) => {}
            Err(error) => return Err(error),
        }
        matches.sort_by_key(|hit| hit.start);
        Ok(matches)
    }

    /// Return the first blocking match from the composed default matcher.
    #[must_use]
    pub fn has_blocking_match(&self, code: &str, language: ScriptLanguage) -> Option<PatternMatch> {
        self.find_matches(code, language)
            .ok()?
            .into_iter()
            .find(|hit| hit.severity.blocks_by_default())
    }
}

/// Retain the existing deletion backstop, adding protected writes on the
/// SAME extracted-source path before the expensive full-pattern scan. This
/// is independent of core.filesystem's shell-keyword candidate gate.
#[must_use]
pub fn scan_filesystem_sink_fallback(code: &str, language: ScriptLanguage) -> Option<PatternMatch> {
    let existing = engine::scan_filesystem_sink_fallback(code, language);
    if existing
        .as_ref()
        .is_some_and(|hit| hit.severity.blocks_by_default())
    {
        return existing;
    }
    protected_matches(code, language)
        .ok()
        .and_then(|hits| hits.into_iter().next())
        .or(existing)
}

fn protected_scan_budget() -> Duration {
    // Match the pattern engine's only-raise timeout convention. No new knob,
    // no smaller production deadline, and no dependence on the working path.
    #[cfg(test)]
    const FLOOR_MS: u64 = 5_000;
    #[cfg(not(test))]
    const FLOOR_MS: u64 = 20;
    static MILLIS: LazyLock<u64> = LazyLock::new(|| {
        std::env::var("DCG_AST_TIMEOUT_MS")
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .map_or(FLOOR_MS, |ms| ms.clamp(FLOOR_MS, 60_000))
    });
    Duration::from_millis(*MILLIS)
}

fn protected_matches(
    code: &str,
    language: ScriptLanguage,
) -> Result<Vec<PatternMatch>, MatchError> {
    if !credential_files::source_scan_required(code, language) {
        return Ok(Vec::new());
    }
    if code.len() > 256 * 1024 {
        return Err(MatchError::ParseError {
            language,
            detail: "protected-write source exceeds the byte limit".into(),
        });
    }
    let budget = protected_scan_budget();
    let started = Instant::now();
    // Do not parse another language AST unbounded on the hook thread. The
    // worker owns its input, has byte/node/depth caps, and never executes code.
    // A timed-out receiver cannot leave the worker blocked on a send.
    let source = code.to_string();
    let (sender, receiver) = mpsc::sync_channel(1);
    let _worker = thread::Builder::new()
        .name("dcg-protected-source".into())
        .spawn(move || {
            let _ = sender.send(credential_files::scan_extracted(&source, language));
        })
        .map_err(|error| MatchError::ParseError {
            language,
            detail: format!("could not start protected-write analysis: {error}"),
        })?;
    let hits = match receiver.recv_timeout(budget) {
        Ok(result) => result.map_err(|detail| MatchError::ParseError {
            language,
            detail: detail.to_string(),
        })?,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            return Err(MatchError::Timeout {
                elapsed_ms: started.elapsed().as_millis() as u64,
                budget_ms: budget.as_millis() as u64,
            });
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            return Err(MatchError::ParseError {
                language,
                detail: "protected-write analysis did not complete".into(),
            });
        }
    };
    Ok(hits
        .into_iter()
        .map(|hit| PatternMatch {
            rule_id: format!("core.filesystem.{}", hit.rule),
            reason: hit.reason,
            matched_text_preview: code
                .get(hit.span.clone())
                .unwrap_or("")
                .chars()
                .take(80)
                .collect(),
            line_number: code[..hit.span.start]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count()
                + 1,
            start: hit.span.start,
            end: hit.span.end,
            severity: Severity::Critical,
            suggestion: Some(
                "Stage the proposed content in a scratch file for review; use dcg allow-once for an approved write."
                    .into(),
            ),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracted_source_reaches_shared_core_rule_before_full_pattern_matching() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "open('/home/u/.ssh/authorized_keys', 'a')",
            ),
            (ScriptLanguage::Ruby, "File.write('/home/u/.bashrc', 'x')"),
            (
                ScriptLanguage::JavaScript,
                "require('fs').appendFileSync('/home/u/.ssh/authorized_keys', 'x')",
            ),
            (
                ScriptLanguage::TypeScript,
                "const p: string = '/home/u/.bashrc'; require('fs').writeFileSync(p, 'x')",
            ),
        ] {
            let early = scan_filesystem_sink_fallback(source, language).expect(source);
            assert_eq!(early.rule_id, "core.filesystem.credential-file-write");
            assert_eq!(early.severity, Severity::Critical);
            assert!(source.get(early.start..early.end).is_some());
            assert!(
                DEFAULT_MATCHER
                    .find_matches(source, language)
                    .unwrap()
                    .iter()
                    .any(|hit| hit.rule_id == "core.filesystem.credential-file-write")
            );
        }
    }

    #[test]
    fn default_matcher_preserves_both_rule_families_in_source_order() {
        for source in [
            "open('/home/u/.bashrc', 'w'); open('.git/config', 'w')",
            "open('.git/config', 'w'); open('/home/u/.bashrc', 'w')",
        ] {
            let hits = DEFAULT_MATCHER
                .find_matches(source, ScriptLanguage::Python)
                .unwrap();
            let core: Vec<_> = hits
                .iter()
                .filter(|hit| hit.rule_id.starts_with("core.filesystem."))
                .collect();
            assert_eq!(core.len(), 2, "{source}: {hits:?}");
            assert!(
                core.iter()
                    .any(|hit| hit.rule_id.ends_with("credential-file-write"))
            );
            assert!(
                core.iter()
                    .any(|hit| hit.rule_id.ends_with("git-internals-write"))
            );
            assert!(core[0].start < core[1].start);
        }
    }

    #[test]
    fn protected_write_limits_report_incomplete_analysis() {
        let oversized = format!("# open\n{}", " ".repeat(256 * 1024));
        assert!(matches!(
            DEFAULT_MATCHER.find_matches(&oversized, ScriptLanguage::Python),
            Err(MatchError::ParseError { .. })
        ));
    }
}
