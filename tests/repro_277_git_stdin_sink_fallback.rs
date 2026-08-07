//! Regression tests for issue #277: a `git commit -F - <<'EOF'` heredoc whose
//! commit MESSAGE merely mentions `rm -rf /tmp/x` was denied with the bounded
//! fallback reason ("Incomplete embedded-code analysis found a destructive
//! pattern").
//!
//! Actual path: the prose body detects as `ScriptLanguage::Unknown`, so
//! `DEFAULT_MATCHER::find_matches` returns `UnsupportedLanguage` and
//! `evaluate_heredoc` fell through to `check_fallback_patterns` on the raw
//! body — which never applied the git stdin-data-sink model. The fix teaches
//! `evaluate_heredoc` to skip bodies bound to a structured stdin data sink
//! (`is_structured_stdin_data_sink`) and makes `check_fallback_patterns` mask
//! non-executing heredoc bodies exactly like the main raw-shell rescan.
//!
//! Scope (No-Claim): these tests prove the `-F -` stdin-sink path only, not
//! that every bounded-fallback masking gap is closed.

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, LayeredAllowlist};

fn evaluate_with_settings(
    command: &str,
    dialect: ShellDialect,
    tweak_limits: impl FnOnce(&mut destructive_command_guard::config::HeredocSettings),
) -> destructive_command_guard::EvaluationResult {
    let config = Config::default();
    let enabled_packs = config.enabled_pack_ids();
    let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    let keyword_index = REGISTRY
        .build_enabled_keyword_index(&ordered_packs)
        .expect("keyword index should build for enabled pack set");
    let compiled_overrides = config.overrides.compile();
    let allowlists = LayeredAllowlist::default();
    let mut heredoc_settings = config.heredoc_settings();
    assert!(
        heredoc_settings.enabled,
        "heredoc scanning must be on for these repros"
    );
    tweak_limits(&mut heredoc_settings);
    evaluate_command_with_pack_order_at_path_in_dialect(
        command,
        &enabled_keywords,
        &ordered_packs,
        Some(&keyword_index),
        &compiled_overrides,
        &allowlists,
        &heredoc_settings,
        None,
        dialect,
    )
}

fn evaluate(command: &str, dialect: ShellDialect) -> destructive_command_guard::EvaluationResult {
    evaluate_with_settings(command, dialect, |_| {})
}

const REPRO: &str = "git commit -F - <<'EOF'\ndocs: note that rm -rf /tmp/x is denied\nEOF";

/// The issue #277 repro: the heredoc body is a commit message consumed by git
/// as DATA; the prose `rm -rf /tmp/x` must not trip the bounded fallback.
#[test]
fn commit_message_heredoc_mentioning_rm_rf_is_allowed() {
    for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
        let result = evaluate(REPRO, dialect);
        assert!(
            result.is_allowed(),
            "{REPRO:?} must be allowed under {dialect:?}, got {result:?}"
        );
    }
}

/// Same shape through the incomplete-extraction fallback (`ExceededSizeLimit`
/// -> `ExtractionResult::Skipped` -> `check_fallback_patterns` on the whole
/// command): the data-sink body must be masked there too.
#[test]
fn commit_message_heredoc_is_allowed_when_extraction_size_limit_is_exceeded() {
    let result = evaluate_with_settings(REPRO, ShellDialect::Posix, |settings| {
        settings.limits.max_body_bytes = 16;
    });
    assert!(
        result.is_allowed(),
        "{REPRO:?} must be allowed when extraction is skipped for size, got {result:?}"
    );
}

/// Existing control: a git-family token in the message body stays allowed.
#[test]
fn commit_message_heredoc_with_git_token_stays_allowed() {
    let command = "git commit -F - <<'EOF'\ndocs: note that git branch -d is denied\nEOF";
    let result = evaluate(command, ShellDialect::Posix);
    assert!(
        result.is_allowed(),
        "{command:?} must stay allowed, got {result:?}"
    );
}

/// Existing control (#257): the `-m` form of the same message stays allowed.
#[test]
fn commit_message_m_form_stays_allowed() {
    let command = "git commit -m \"docs: note that rm -rf /tmp/x is denied\"";
    let result = evaluate(command, ShellDialect::Posix);
    assert!(
        result.is_allowed(),
        "{command:?} must stay allowed, got {result:?}"
    );
}

/// Existing control: backticks inside a quoted-delimiter message stay allowed.
#[test]
fn commit_message_heredoc_with_backticks_stays_allowed() {
    let command = "git commit -F - <<'EOF'\nsee `ls -la` for details\nEOF";
    let result = evaluate(command, ShellDialect::Posix);
    assert!(
        result.is_allowed(),
        "{command:?} must stay allowed, got {result:?}"
    );
}

/// Planted negative: a heredoc bound to an EXECUTING sink keeps blocking.
#[test]
fn bash_heredoc_with_destructive_body_stays_denied() {
    let command = "bash <<'EOF'\nrm -rf /home/user\nEOF";
    for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
        let result = evaluate(command, dialect);
        assert!(
            result.is_denied(),
            "{command:?} must stay denied under {dialect:?}, got {result:?}"
        );
    }
}

/// Planted negative: the bounded fallback itself stays fail-closed for
/// executing sinks — same tiny size limit that exercises the masked path.
#[test]
fn bash_heredoc_stays_denied_when_extraction_size_limit_is_exceeded() {
    let command = "bash <<'EOF'\nrm -rf /home/user\nEOF";
    let result = evaluate_with_settings(command, ShellDialect::Posix, |settings| {
        settings.limits.max_body_bytes = 16;
    });
    assert!(
        result.is_denied(),
        "{command:?} must stay denied when extraction is skipped for size, got {result:?}"
    );
}

/// Planted negative (pinned current behavior): an UNQUOTED delimiter lets the
/// outer shell expand `$(...)` before git ever reads the message, so a
/// command substitution in the body must stay denied.
#[test]
fn unquoted_delimiter_with_command_substitution_stays_denied() {
    let command = "git commit -F - <<EOF\n$(rm -rf /tmp/x)\nEOF";
    for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
        let result = evaluate(command, dialect);
        assert!(
            result.is_denied(),
            "{command:?} must stay denied under {dialect:?}, got {result:?}"
        );
    }
}

/// Planted negative (#136 revert, accepted behavior per #278): interpreter
/// stdin bodies are still scanned; a destructive string reaching an exec sink
/// stays denied.
#[test]
fn python_stdin_heredoc_with_exec_sink_stays_denied() {
    let command = "python3 - <<'PY'\nx = \"rm -rf /tmp/x\"\nimport os\nos.system(x)\nPY";
    let result = evaluate(command, ShellDialect::Posix);
    assert!(
        result.is_denied(),
        "{command:?} must stay denied, got {result:?}"
    );
}
