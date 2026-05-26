use dcg_cli::{config::Config, evaluator::evaluate_command, load_default_allowlists};

#[test]
fn test_newline_as_separator_safety() {
    let config = Config::default();
    let compiled_overrides = config.overrides.compile();
    let allowlists = load_default_allowlists();
    let keywords = &["rm", "git"];

    // Command: git commit -m (newline) rm -rf /
    // If newline is treated as whitespace, 'rm' is consumed as the message for -m.
    // If newline is treated as separator, 'rm' is a new command and should be blocked.
    let cmd = "git commit -m\nrm -rf /";

    let result = evaluate_command(cmd, &config, keywords, &compiled_overrides, &allowlists);

    assert!(
        result.is_denied(),
        "Destructive command after newline was incorrectly allowed (likely masked as argument)"
    );
}

/// Regression for #124: a multi-line `git commit -m "..."` whose message body
/// contains the substring `git push --force` must NOT be denied. The substring
/// lives inside the quoted `-m` argument (commit-message text, not executable
/// shell tokens), so `sanitize_for_pattern_matching` masks it before the
/// `core.git:push-force-long` regex runs.
///
/// The original report (filed against 0.5.2) saw the live hook DENY while
/// `dcg explain` ALLOWed the same input. Both the bounded token-walker
/// (`(?:[^\s&;|`()<>]+\s+)*`) on the push-force rules and the `-m` body
/// masking must agree: this is the end-to-end (sanitizer + regex) check that
/// the hook path and explain path actually converge on ALLOW.
#[test]
fn test_multiline_commit_message_mentioning_force_push_is_allowed() {
    let config = Config::default();
    let compiled_overrides = config.overrides.compile();
    let allowlists = load_default_allowlists();
    let keywords = &["rm", "git"];

    // Build `git push --force` from parts so this source file does not itself
    // contain the literal command (keeps dcg's own self-guard from flagging
    // edits to this file in CI / pre-commit contexts).
    let inner = ["git", "push", "--force"].join(" ");

    // The exact motivating case from issue #124: a multi-line quoted body.
    let cmd = format!("git add x && git commit -m \"first line\n\nsecond line mentions {inner}\"");
    let result = evaluate_command(&cmd, &config, keywords, &compiled_overrides, &allowlists);
    assert!(
        result.is_allowed(),
        "multi-line commit message mentioning a force push must be allowed; cmd={cmd}"
    );

    // The single-line equivalent (already allowed pre-fix) must stay allowed.
    let cmd_single = format!("git add x && git commit -m \"ref to {inner}\"");
    let result_single = evaluate_command(
        &cmd_single,
        &config,
        keywords,
        &compiled_overrides,
        &allowlists,
    );
    assert!(
        result_single.is_allowed(),
        "single-line commit message mentioning a force push must be allowed; cmd={cmd_single}"
    );

    // A multi-line message with `git push -f` (short flag) on its own body line
    // must also be allowed.
    let inner_short = ["git", "push", "-f"].join(" ");
    let cmd_short =
        format!("git commit -m \"title\n\nbody line referencing {inner_short} for context\"");
    let result_short = evaluate_command(
        &cmd_short,
        &config,
        keywords,
        &compiled_overrides,
        &allowlists,
    );
    assert!(
        result_short.is_allowed(),
        "multi-line commit body mentioning a short-flag force push must be allowed; cmd={cmd_short}"
    );

    // CRITICAL: a genuine force-push chained after the safe commit must STILL
    // be denied — masking the commit body must not mask a real subsequent push.
    let cmd_real =
        format!("git commit -m \"safe message\n\nmentions {inner}\" && {inner} origin main");
    let result_real = evaluate_command(
        &cmd_real,
        &config,
        keywords,
        &compiled_overrides,
        &allowlists,
    );
    assert!(
        result_real.is_denied(),
        "a real force-push after a safe multi-line commit must still be denied; cmd={cmd_real}"
    );
}
