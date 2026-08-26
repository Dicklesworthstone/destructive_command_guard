//! Regression: the rm semantic classifier dropped the pack's guidance.
//!
//! `core.filesystem` classifies `rm` semantically instead of by regex, so it
//! builds its own hit and never walks `destructive_patterns`. Both classifier
//! call sites then passed `explanation: None` and `suggestions: &[]` on to the
//! denial, so every rm denial reached the blocked caller as:
//!
//! ```text
//! Explanation: Matched destructive pattern core.filesystem:rm-rf-general.
//!              No additional explanation is available yet.
//! ```
//!
//! The pack authors an explanation for each of those rules, and that text is
//! where the allowed cleanup grammar lives (`rm -ri`, `mv <path> /tmp/...`,
//! literal temp paths). Dropping it left an agent blocked with no way to learn
//! which form the guard would have accepted. The regex-matched filesystem
//! rules — `find -delete`, `unlink`, `truncate`, `shred` — were never
//! affected; they deliver their explanations through the pattern list.
//!
//! These tests assert the guidance is carried, and that it comes from the rule
//! that actually matched: an implementation that attached the first rm
//! explanation it found, or a single shared blurb, fails
//! `explanation_comes_from_the_matching_rule_not_any_rm_rule`.

use destructive_command_guard::config::Config;
use destructive_command_guard::evaluator::{EvaluationResult, evaluate_command};
use destructive_command_guard::load_default_allowlists;

/// Distinctive sentence that only `rm-rf-general` authors.
const GENERAL_MARKER: &str = "Wildcards can expand to match more than expected";
/// Distinctive sentence that only `rm-rf-root-home` authors.
const ROOT_HOME_MARKER: &str = "dcg auto-allows recursive deletion only for literal temp paths";
/// Placeholder the caller used to receive instead of real guidance.
const PLACEHOLDER: &str = "No additional explanation is available yet";

fn evaluate(cmd: &str) -> EvaluationResult {
    let config = Config::default();
    let compiled_overrides = config.overrides.compile();
    let allowlists = load_default_allowlists();
    evaluate_command(
        cmd,
        &config,
        &["rm", "find", "shred", "truncate", "unlink"],
        &compiled_overrides,
        &allowlists,
    )
}

fn denial_parts(cmd: &str) -> (String, String) {
    let result = evaluate(cmd);
    assert!(result.is_denied(), "expected '{cmd}' to be denied");
    let info = result
        .pattern_info
        .unwrap_or_else(|| panic!("expected pattern info for '{cmd}'"));
    let rule = info
        .pattern_name
        .unwrap_or_else(|| panic!("expected a named rule for '{cmd}'"));
    let explanation = info
        .explanation
        .unwrap_or_else(|| panic!("'{cmd}' was denied by {rule} with no explanation"));
    assert!(
        !explanation.contains(PLACEHOLDER),
        "'{cmd}' shipped the placeholder instead of the {rule} explanation"
    );
    (rule, explanation)
}

#[test]
fn rm_rf_denial_carries_the_pack_explanation() {
    let (rule, explanation) = denial_parts("rm -rf ./build");
    assert_eq!(rule, "rm-rf-general");
    assert!(
        explanation.contains(GENERAL_MARKER),
        "rm-rf-general explanation missing its own text: {explanation}"
    );
}

#[test]
fn rm_rf_denial_carries_the_allowed_cleanup_grammar() {
    // The whole point of restoring the explanation: a blocked caller must be
    // able to read which cleanup form the guard accepts.
    let (_, explanation) = denial_parts("rm -rf ./build");
    assert!(
        explanation.contains("rm -ri"),
        "explanation must name the interactive form: {explanation}"
    );
    assert!(
        explanation.contains("/tmp"),
        "explanation must name the temp-path escape hatch: {explanation}"
    );
}

#[test]
fn rm_rf_denial_carries_the_pack_suggestions() {
    let result = evaluate("rm -rf ./build");
    assert!(result.is_denied());
    let info = result.pattern_info.expect("pattern info");
    assert!(
        !info.suggestions.is_empty(),
        "rm denials shipped no safer-alternative suggestions"
    );
    assert!(
        info.suggestions
            .iter()
            .any(|s| s.command.contains("rm -ri")),
        "suggestions must include the interactive form: {:?}",
        info.suggestions
    );
}

/// The discriminating test. A naive fix that attaches "some rm explanation"
/// (the first rm pattern in the list, or one shared blurb for the whole
/// classifier) passes every other test here and fails this one.
#[test]
fn explanation_comes_from_the_matching_rule_not_any_rm_rule() {
    let (general_rule, general) = denial_parts("rm -rf ./build");
    let (home_rule, home) = denial_parts("rm -rf ~/some-project");

    assert_eq!(general_rule, "rm-rf-general");
    assert_eq!(home_rule, "rm-rf-root-home");
    assert_ne!(
        general, home,
        "two different rm rules must not share one explanation"
    );
    assert!(
        home.contains(ROOT_HOME_MARKER),
        "root/home denial did not get the root/home explanation: {home}"
    );
    assert!(
        !home.contains(GENERAL_MARKER),
        "root/home denial leaked the rm-rf-general explanation: {home}"
    );
    assert!(
        !general.contains(ROOT_HOME_MARKER),
        "general denial leaked the root/home explanation: {general}"
    );
}

/// One classifier decides every rm flag style, so the same drop hit all of
/// them. Each style resolves to its own rule and must find its own text.
///
/// `rm-recursive-general` and `rm-recursive-root-home` are absent here on
/// purpose: the pack authors no explanation for either, so there is nothing
/// for this lookup to deliver and they still report the placeholder. That is a
/// separate gap in the pack data, not in the wiring. Adding their text is all
/// it takes to move them into this table.
#[test]
fn every_rm_flag_style_carries_its_own_explanation() {
    for (cmd, expected_rule) in [
        ("rm -rf ./build", "rm-rf-general"),
        ("rm -r -f ./build", "rm-r-f-separate"),
        ("rm --recursive --force ./build", "rm-recursive-force-long"),
        ("rm -rf ~/some-project", "rm-rf-root-home"),
        ("rm -r -f ~/some-project", "rm-r-f-separate-root-home"),
        (
            "rm --recursive --force ~/some-project",
            "rm-recursive-force-root-home",
        ),
    ] {
        let (rule, explanation) = denial_parts(cmd);
        assert_eq!(rule, expected_rule, "unexpected rule for '{cmd}'");
        assert!(
            explanation.len() > 80,
            "'{cmd}' explanation is too short to be the authored text: {explanation}"
        );
    }
}

/// Pins the remaining gap so it is visible rather than silently tolerated:
/// these two rules are wired correctly and still report the placeholder,
/// because the pack has no text for them. When someone authors it, this test
/// fails and the rules move into the table above.
#[test]
fn rules_with_no_authored_text_are_the_only_ones_left_on_the_placeholder() {
    for (cmd, expected_rule) in [
        ("rm -r ./build", "rm-recursive-general"),
        ("rm -r ~/some-project", "rm-recursive-root-home"),
    ] {
        let result = evaluate(cmd);
        assert!(result.is_denied(), "expected '{cmd}' to be denied");
        let info = result.pattern_info.expect("pattern info");
        assert_eq!(info.pattern_name.as_deref(), Some(expected_rule));
        assert!(
            info.explanation.is_none(),
            "'{expected_rule}' now has authored text — move it into              every_rm_flag_style_carries_its_own_explanation"
        );
    }
}

/// Negative control: restoring guidance must not turn an allowed command into
/// a denial. These are the cleanup forms the explanation now advertises.
#[test]
fn advertised_cleanup_forms_stay_allowed() {
    for cmd in [
        "rm -ri ./build",
        "mv ./build /tmp/delete-me-1787702991",
        "rm -rf /tmp/scratch-1787702991/build",
        "ls -la ./build",
    ] {
        assert!(
            !evaluate(cmd).is_denied(),
            "'{cmd}' must stay allowed; the fix restores guidance, it does not widen deletion"
        );
    }
}
