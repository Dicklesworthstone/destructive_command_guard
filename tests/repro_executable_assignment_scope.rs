//! bd-executable-assignment-scope: a destructive command spelled through a
//! shell variable that holds its executable (`d=git; $d reset --hard`) must
//! be denied under the rule the plain spelling gets, even when the binding
//! shares its statement with other assignments or neutral commands come
//! before or after it.
//!
//! The bead recorded that, at e0554cd0, decision-only evaluations denied
//! `d=git; $d reset --hard` but allowed the spellings in
//! `BOUND_THROUGH_NEUTRAL_STRUCTURE`. At 290d783a POSIX denied them only
//! because Git's own dynamic-executable handling caught `$d reset --hard`
//! with no binding at all; the `unknown` dialect (Gemini, Cursor, Copilot,
//! OpenCode) allowed them, and every dialect allowed the same shapes for
//! `mkfs`, `dd` and `wipefs`, which have no such handling. The model now
//! steps past neutral commands, multi-assignment statements and pure `&&`
//! chains, resolving what follows deny-only: a denial from the resolved
//! command stands, but the source is not masked, so this can only add
//! denials. The benign controls make sure the binding is resolved rather
//! than every `$d` being denied.
//!
//! Scope (No-Claim): straight-line POSIX prefixes only. A binding that a
//! subshell, `unset` or an environment-only prefix would hide still denies
//! (conservative); these tests do not pin that over-block either way.

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, EvaluationResult, LayeredAllowlist};

fn evaluate(command: &str, dialect: ShellDialect) -> EvaluationResult {
    let config = Config::default();
    let enabled_packs = config.enabled_pack_ids();
    let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    let keyword_index = REGISTRY
        .build_enabled_keyword_index(&ordered_packs)
        .expect("keyword index should build for enabled pack set");
    let compiled_overrides = config.overrides.compile();
    let allowlists = LayeredAllowlist::default();
    let heredoc_settings = config.heredoc_settings();
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

fn rule_of(result: &EvaluationResult) -> Option<String> {
    let info = result.pattern_info.as_ref()?;
    Some(format!(
        "{}:{}",
        info.pack_id.as_deref().unwrap_or("?"),
        info.pattern_name.as_deref().unwrap_or("?")
    ))
}

const DIALECTS: [ShellDialect; 2] = [ShellDialect::Posix, ShellDialect::Unknown];

/// The spellings the bead recorded as allowed, plus the same shapes with
/// other separators.
const BOUND_THROUGH_NEUTRAL_STRUCTURE: &[&str] = &[
    "UNREVIEWED=1 d=git; $d reset --hard",
    "d=git x=1; $d reset --hard",
    "true; d=git; $d reset --hard",
    "d=git; true; $d reset --hard",
    "a=1 d=git b=2; $d reset --hard",
    "d=git; echo hi; $d reset --hard",
    "d=git; cd /tmp; $d reset --hard",
    "true && d=git && $d reset --hard",
    "d=git\ntrue\n$d reset --hard",
    "d=git; true; ${d} reset --hard",
];

#[test]
fn the_single_binding_control_denies_under_the_plain_rule() {
    for dialect in DIALECTS {
        let result = evaluate("d=git; $d reset --hard", dialect);
        assert!(result.is_denied(), "{dialect:?}: {result:?}");
        assert_eq!(
            rule_of(&result).as_deref(),
            Some("core.git:reset-hard"),
            "{dialect:?}"
        );
    }
}

#[test]
fn bindings_through_neutral_structure_deny_under_the_plain_rule() {
    for command in BOUND_THROUGH_NEUTRAL_STRUCTURE {
        for dialect in DIALECTS {
            let result = evaluate(command, dialect);
            assert!(
                result.is_denied(),
                "{command:?} must deny under {dialect:?}, got {result:?}"
            );
            assert_eq!(
                rule_of(&result).as_deref(),
                Some("core.git:reset-hard"),
                "{command:?} under {dialect:?}"
            );
        }
    }
}

#[test]
fn a_bound_rm_after_a_neutral_command_denies() {
    for dialect in DIALECTS {
        let result = evaluate("true; r=rm; $r -rf ~/x", dialect);
        assert!(result.is_denied(), "{dialect:?}: {result:?}");
        assert_eq!(
            rule_of(&result).as_deref(),
            Some("core.filesystem:rm-rf-root-home"),
            "{dialect:?}"
        );
    }
}

fn assert_denied_by_pack(command: &str, pack: &str) {
    for dialect in DIALECTS {
        let result = evaluate(command, dialect);
        assert!(
            result.is_denied(),
            "{command:?} must deny under {dialect:?}, got {result:?}"
        );
        let rule = rule_of(&result).unwrap_or_default();
        assert!(
            rule.starts_with(&format!("{pack}:")),
            "{command:?} under {dialect:?} answered {rule}, expected a {pack} rule"
        );
    }
}

/// Only git and rm have dynamic-executable handling of their own, so a
/// neutral command before a disk tool's binding used to end the model and
/// leave `$m /dev/sda1` an unknown program: allowed in every dialect, while
/// the same binding without `true;` denied.
#[test]
fn a_neutral_command_does_not_hide_a_bound_disk_tool() {
    for command in [
        "m=mkfs.ext4; $m /dev/sda1",
        "true; m=mkfs.ext4; $m /dev/sda1",
        "m=mkfs.ext4; echo formatting; $m /dev/sda1",
        "m=mkfs.ext4; cd /tmp; $m /dev/sda1",
        "true; d=dd; $d if=/dev/zero of=/dev/sda bs=1M",
        "true; w=wipefs; $w -a /dev/sda",
        "UNREVIEWED=1 m=mkfs.ext4; $m /dev/sda1",
        "true && m=mkfs.ext4 && $m /dev/sda1",
    ] {
        assert_denied_by_pack(command, "system.disk");
    }
}

/// The unknown dialect stands for every shell, POSIX among them, so a
/// dynamic executable that POSIX reads as Git must be Git here too. These
/// were denied under POSIX and allowed under `unknown`, the dialect of every
/// agent whose shell tool is not named `Bash`.
#[test]
fn the_unknown_dialect_reads_a_dynamic_git_executable_as_posix_does() {
    for (command, rule) in [
        ("$d reset --hard", "core.git:reset-hard"),
        ("$d checkout -- .", "core.git:checkout-discard"),
        ("$d stash clear", "core.git:stash-clear"),
        (
            "cd /repo && d=git && $d reset --hard",
            "core.git:reset-hard",
        ),
    ] {
        for dialect in DIALECTS {
            let result = evaluate(command, dialect);
            assert!(
                result.is_denied(),
                "{command:?} must deny under {dialect:?}, got {result:?}"
            );
            assert_eq!(
                rule_of(&result).as_deref(),
                Some(rule),
                "{command:?} under {dialect:?}"
            );
        }
    }
}

/// A PowerShell assignment whose first token is a variable must not be read
/// as a Git invocation: `-Directory` once supplied the `D` of a forced branch
/// deletion (#401).
#[test]
fn a_powershell_variable_assignment_is_not_synthesized_into_git() {
    for command in [
        r"$items = Get-ChildItem C:\temp -Recurse -Directory",
        "$d status",
        "$tool --version",
    ] {
        let result = evaluate(command, ShellDialect::Unknown);
        assert!(
            result.is_allowed(),
            "{command:?} must stay allowed under Unknown, got {result:?}"
        );
    }
}

/// The binding is resolved, not guessed: a harmless command through the
/// same variable, a later benign rebinding, and the whole text as quoted
/// data stay allowed.
#[test]
fn resolved_bindings_to_harmless_commands_stay_allowed() {
    for command in [
        "d=git; true; $d status",
        "d=git x=1; $d status",
        "true; d=git; $d log --oneline -3",
        "d=git; d=echo; $d reset --hard",
        "echo 'd=git; $d reset --hard'",
        "true; d=dd; $d --version",
        "true; m=mkfs.ext4; echo $m",
        "true; echo hi; ls -la",
    ] {
        for dialect in DIALECTS {
            let result = evaluate(command, dialect);
            assert!(
                result.is_allowed(),
                "{command:?} must stay allowed under {dialect:?}, got {result:?}"
            );
        }
    }
}
