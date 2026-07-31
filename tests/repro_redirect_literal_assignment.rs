//! A truncating redirect through a shell variable is safe only when DCG can
//! prove that the variable has one prior literal assignment and the resolved
//! target passes fixed-path checks.

use std::path::Path;

use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{
    config::Config, evaluator::evaluate_command_with_pack_order_at_path, load_default_allowlists,
};

fn evaluate_at(cmd: &str, cwd: &Path) -> destructive_command_guard::evaluator::EvaluationResult {
    let config = Config::default();
    let compiled_overrides = config.overrides.compile();
    let allowlists = load_default_allowlists();
    let enabled_packs = config.enabled_pack_ids();
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    let keyword_index = REGISTRY.build_enabled_keyword_index(&ordered_packs);

    evaluate_command_with_pack_order_at_path(
        cmd,
        &REGISTRY.collect_enabled_keywords(&enabled_packs),
        &ordered_packs,
        keyword_index.as_ref(),
        &compiled_overrides,
        &allowlists,
        &config.heredoc_settings(),
        Some(cwd),
    )
}

fn allowed(cmd: &str, cwd: &Path) {
    let result = evaluate_at(cmd, cwd);
    assert!(
        result.is_allowed(),
        "expected a proven literal redirect target to be allowed: {cmd:?} -> {:?} {:?}",
        result.decision,
        result.pattern_info
    );
}

fn denied(cmd: &str, cwd: &Path) {
    let result = evaluate_at(cmd, cwd);
    assert!(
        result.is_denied(),
        "expected an unresolved or unsafe redirect target to be denied: {cmd:?} -> {:?}",
        result.decision
    );
}

#[cfg(target_os = "linux")]
#[test]
fn prior_single_literal_assignment_resolves_the_redirect_target() {
    let cwd = tempfile::tempdir().unwrap();
    std::fs::create_dir(cwd.path().join("logs")).unwrap();

    allowed(
        "log=/tmp/dcg-literal-assignment.log; : > \"$log\"",
        cwd.path(),
    );
    allowed("log='logs/run-20260731.log'; : > \"${log}\"", cwd.path());
    allowed(
        "log=/tmp/dcg-run.log; : > \"$log\"; (echo ok) >\"$log\" 2>&1 &",
        cwd.path(),
    );
}

#[test]
fn unresolved_or_mutated_assignment_remains_denied() {
    let cwd = tempfile::tempdir().unwrap();

    for command in [
        ": > \"$log\"",
        "log=$OTHER; : > \"$log\"",
        "log=$(mktemp); : > \"$log\"",
        "log=`mktemp`; : > \"$log\"",
        "log=/tmp/first; log=/tmp/second; : > \"$log\"",
        "log=/tmp/first; log+=-second; : > \"$log\"",
        "log=/tmp/out; unset log; : > \"$log\"",
        "log=/tmp/out; printf -v log /tmp/other; : > \"$log\"",
        "log=/tmp/out; true; : > \"$log\"",
        "log=/tmp/out; source ./mutator.sh; : > \"$log\"",
        "log=/tmp/out; eval 'log=/tmp/other'; : > \"$log\"",
        "log=/tmp/out; : > \"${log}.suffix\"",
        "log=/tmp/out; : > \"$log\" > \"$OTHER\"",
    ] {
        denied(command, cwd.path());
    }
}

#[test]
fn sensitive_literal_assignment_remains_denied() {
    let cwd = tempfile::tempdir().unwrap();

    for command in [
        "log=/etc/passwd; : > \"$log\"",
        "log=/home/other/file; : > \"$log\"",
        "log=~/file; : > \"$log\"",
        "log='/var/lib/service/data'; : > \"$log\"",
        "log=/var/tmp/evidence.log; : > \"$log\"",
    ] {
        denied(command, cwd.path());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn symlink_and_non_regular_targets_remain_denied() {
    use std::os::unix::fs::symlink;

    let cwd = tempfile::tempdir().unwrap();
    let regular = cwd.path().join("regular.log");
    let link = cwd.path().join("linked.log");
    let directory = cwd.path().join("directory.log");
    let linked_parent = cwd.path().join("linked-parent");
    std::fs::write(&regular, "evidence").unwrap();
    symlink(&regular, &link).unwrap();
    std::fs::create_dir(&directory).unwrap();
    symlink(cwd.path(), &linked_parent).unwrap();

    allowed(
        &format!("log={}; : > \"$log\"", regular.display()),
        cwd.path(),
    );
    denied(&format!("log={}; : > \"$log\"", link.display()), cwd.path());
    denied(
        &format!("log={}; : > \"$log\"", directory.display()),
        cwd.path(),
    );
    denied(
        &format!("log={}/out.log; : > \"$log\"", linked_parent.display()),
        cwd.path(),
    );
}
