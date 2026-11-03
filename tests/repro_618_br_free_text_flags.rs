//! Regression tests for issue #618: the free-text flags of `br update`,
//! `br create` and `br close` hold text that br stores and never runs, so a
//! value that quotes a blocked command must not be judged as that command.
//!
//! The masking is limited to literal values. A value holding a command
//! substitution runs in the caller's shell before br starts, and a command
//! after a separator is a command of its own, so both still deny.

use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{
    config::Config, evaluator::evaluate_command, load_default_allowlists,
};

fn evaluate(cmd: &str) -> destructive_command_guard::evaluator::EvaluationResult {
    let config = Config::default();
    let compiled_overrides = config.overrides.compile();
    let allowlists = load_default_allowlists();
    let enabled_packs = config.enabled_pack_ids();
    let keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    evaluate_command(cmd, &config, &keywords, &compiled_overrides, &allowlists)
}

fn allowed(cmd: &str) {
    let result = evaluate(cmd);
    assert!(
        result.is_allowed(),
        "expected ALLOWED (br free-text value is data): {cmd:?} -> {:?}",
        result.decision
    );
}

fn denied(cmd: &str) {
    let result = evaluate(cmd);
    assert!(
        result.is_denied(),
        "expected DENIED: {cmd:?} -> {:?}",
        result.decision
    );
}

/// Every free-text flag `br update --help` / `br close --help` lists, beyond
/// the five #225 already covered.
const NEW_FREE_TEXT_FLAGS: &[&str] = &[
    "--append-notes",
    "--design",
    "--acceptance-criteria",
    "--acceptance",
    "--add-acceptance",
    "--prerequisites",
    "--transition-comment",
    "--agent-context",
    "--bypass-reason",
];

/// Prose that quotes a shell launcher. An unregistered flag's value is judged
/// like any other argument, and the launcher inside it is denied as a command,
/// so the rows below that use it fail without the registration.
const LAUNCHER_PROSE: &str = "\"bash -c 'git reset --hard' is refused\"";

#[test]
fn br_free_text_flag_values_are_data_issue_618() {
    for flag in NEW_FREE_TEXT_FLAGS {
        allowed(&format!("br update bd-x {flag} {LAUNCHER_PROSE}"));
        allowed(&format!("br update bd-x {flag}={LAUNCHER_PROSE}"));
        allowed(&format!(
            "br create --title t {flag} {LAUNCHER_PROSE} --priority 2"
        ));
        allowed(&format!(
            "br update bd-x {flag} 'git reset --hard stays blocked'"
        ));
        allowed(&format!(
            "br update bd-x {flag} \"rm -rf / is still denied\""
        ));
    }
    // The flags #225 covered keep working.
    allowed(&format!("br update bd-x --notes {LAUNCHER_PROSE}"));
    allowed(&format!(
        "br close bd-x --reason 'git reset --hard is denied' --transition-comment {LAUNCHER_PROSE}"
    ));
}

#[test]
fn br_free_text_flags_do_not_hide_executed_code_issue_618() {
    for flag in NEW_FREE_TEXT_FLAGS {
        // Command substitution runs before br does.
        denied(&format!(
            "br update bd-x {flag} \"see $(git reset --hard)\""
        ));
        denied(&format!("br update bd-x {flag} \"see `git reset --hard`\""));
        // A command after a separator is its own command.
        denied(&format!("br update bd-x {flag} 'note' && git reset --hard"));
        denied(&format!("br update bd-x {flag} 'note'; rm -rf /"));
    }
}
