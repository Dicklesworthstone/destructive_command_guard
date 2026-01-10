use destructive_command_guard::config::Config;
use destructive_command_guard::evaluator::evaluate_command;
use destructive_command_guard::load_default_allowlists;
use destructive_command_guard::packs::REGISTRY;

/// Regression test for heredoc size limit bypass.
///
/// Vulnerability: Attackers could bypass AST analysis by padding the command
/// to exceed `max_body_bytes`. The evaluator would skip extraction (fail-open)
/// and allow the destructive command.
///
/// Fix: `check_fallback_patterns` performs a robust substring/regex check
/// on the raw command when extraction is skipped due to size limits.
#[test]
fn test_heredoc_size_bypass_prevention() {
    let mut config = Config::default();
    // Force fallback check by setting a tiny limit
    config.heredoc.max_body_bytes = Some(10);

    let compiled_overrides = config.overrides.compile();
    let allowlists = load_default_allowlists();
    let enabled_packs = config.enabled_pack_ids();
    let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);

    // 1. Basic bypass attempt
    // "padding" needs to be harmless but long enough.
    let padding = "a".repeat(200);
    // python -c '...padding...; import shutil; shutil.rmtree("/")'
    let bypass_cmd = format!(r#"python -c '{padding}; import shutil; shutil.rmtree("/")'"#);

    // Verify it exceeds limit
    assert!(bypass_cmd.len() > 10);

    let result = evaluate_command(
        &bypass_cmd,
        &config,
        &enabled_keywords,
        &compiled_overrides,
        &allowlists,
    );

    // Should be DENIED by fallback check
    assert!(
        result.is_denied(),
        "Oversized destructive command should be denied"
    );
    if let Some(reason) = result.reason() {
        assert!(
            reason.contains("fallback check"),
            "Denial reason should mention fallback check"
        );
    }

    // 2. Whitespace evasion attempt
    // "rm  -rf" (extra space)
    let evasion_cmd = format!("bash -c 'echo {padding}; rm  -rf /'");
    let result_evasion = evaluate_command(
        &evasion_cmd,
        &config,
        &enabled_keywords,
        &compiled_overrides,
        &allowlists,
    );
    assert!(
        result_evasion.is_denied(),
        "Whitespace evasion should be caught"
    );

    // 3. Comment masking check (False Positive Avoidance)
    // If the destructive pattern is in a Bash comment, it should be ALLOWED.
    // Note: Python comments inside -c strings are NOT masked (they are strings to Bash).
    // We use a Bash comment here: `python -c '...' # rm -rf /`
    let comment_cmd = format!(r#"python -c 'print("safe")' # {padding} rm -rf /"#);
    let result_comment = evaluate_command(
        &comment_cmd,
        &config,
        &enabled_keywords,
        &compiled_overrides,
        &allowlists,
    );
    assert!(
        result_comment.is_allowed(),
        "Destructive pattern in Bash comment should be allowed"
    );
}
