//! Integration tests for the `Mode` × `ToolCall` × `Effect`-set decision matrix.
//!
//! These tests are the contract surface for `dcg-core` v0.6 — every
//! (mode, tool, effects) cell that consumers depend on should be covered
//! here. Aim is ≥30 cases per the v0.6 plan (see `DCG_IMPROVEMENT_PLAN`).

use std::path::PathBuf;

use dcg_core::{Decision, Effect, Engine, EngineConfig, Mode, Session, ToolCall};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn engine() -> Engine {
    Engine::new(
        EngineConfig::builder()
            .working_dir(PathBuf::from("/work"))
            .protected_paths(vec![
                "~/.ssh".into(),
                "~/.aws".into(),
                ".git".into(),
                "/etc".into(),
            ])
            .build(),
    )
}

fn session() -> Session {
    let mut s = Session::with_id("integration-test");
    s.working_dir = PathBuf::from("/work");
    s
}

fn evaluate(mode: Mode, tool: &ToolCall, effects: &[Effect]) -> Decision {
    let e = engine();
    let mut s = session();
    e.evaluate(&mut s, tool, mode, effects)
}

// ---------------------------------------------------------------------------
// Plan mode (12 cases)
// ---------------------------------------------------------------------------

#[test]
fn plan_allows_pure_read_bash() {
    assert!(evaluate(Mode::Plan, &ToolCall::bash("git status"), &[Effect::Read]).is_allow());
}

#[test]
fn plan_allows_read_plus_fs() {
    assert!(
        evaluate(
            Mode::Plan,
            &ToolCall::bash("ls /work"),
            &[Effect::Read, Effect::Fs],
        )
        .is_allow()
    );
}

#[test]
fn plan_allows_pure_fs() {
    assert!(evaluate(Mode::Plan, &ToolCall::read("/work/foo"), &[Effect::Fs]).is_allow());
}

#[test]
fn plan_denies_write_effect() {
    assert!(
        evaluate(
            Mode::Plan,
            &ToolCall::bash("echo hi > /work/out"),
            &[Effect::Write, Effect::Fs],
        )
        .is_deny()
    );
}

#[test]
fn plan_denies_network_effect() {
    assert!(
        evaluate(
            Mode::Plan,
            &ToolCall::network("https://example.com", "GET"),
            &[Effect::Network, Effect::Read],
        )
        .is_deny()
    );
}

#[test]
fn plan_denies_irreversible() {
    assert!(
        evaluate(
            Mode::Plan,
            &ToolCall::bash("rm -rf /tmp/x"),
            &[Effect::Write, Effect::Fs, Effect::Irreversible],
        )
        .is_deny()
    );
}

#[test]
fn plan_denies_mutate_vcs() {
    assert!(
        evaluate(
            Mode::Plan,
            &ToolCall::bash("git commit -m wip"),
            &[Effect::MutateVcs, Effect::Write],
        )
        .is_deny()
    );
}

#[test]
fn plan_denies_spawn() {
    assert!(
        evaluate(
            Mode::Plan,
            &ToolCall::bash("npm install"),
            &[Effect::Network, Effect::Write, Effect::Spawn],
        )
        .is_deny()
    );
}

#[test]
fn plan_denies_edit_tool() {
    assert!(
        evaluate(
            Mode::Plan,
            &ToolCall::edit("/work/src/foo.rs"),
            &[Effect::Write, Effect::Fs],
        )
        .is_deny()
    );
}

#[test]
fn plan_denies_write_tool() {
    assert!(
        evaluate(
            Mode::Plan,
            &ToolCall::write("/work/new.txt"),
            &[Effect::Write, Effect::Fs],
        )
        .is_deny()
    );
}

#[test]
fn plan_allows_read_tool() {
    assert!(
        evaluate(
            Mode::Plan,
            &ToolCall::read("/work/Cargo.toml"),
            &[Effect::Read, Effect::Fs],
        )
        .is_allow()
    );
}

#[test]
fn plan_denial_reason_mentions_plan_mode() {
    let d = evaluate(
        Mode::Plan,
        &ToolCall::write("/work/foo"),
        &[Effect::Write, Effect::Fs],
    );
    let reason = d.reason().expect("deny carries reason");
    assert!(
        reason.contains("plan mode"),
        "reason should mention plan mode, got: {reason}"
    );
}

// ---------------------------------------------------------------------------
// AcceptEdits mode (10 cases)
// ---------------------------------------------------------------------------

#[test]
fn accept_edits_allows_edit_tool_in_workdir() {
    assert!(
        evaluate(
            Mode::AcceptEdits,
            &ToolCall::edit("/work/src/foo.rs"),
            &[Effect::Write, Effect::Fs],
        )
        .is_allow()
    );
}

#[test]
fn accept_edits_allows_write_tool_in_workdir() {
    assert!(
        evaluate(
            Mode::AcceptEdits,
            &ToolCall::write("/work/output.txt"),
            &[Effect::Write, Effect::Fs],
        )
        .is_allow()
    );
}

#[test]
fn accept_edits_allows_read_tool() {
    assert!(
        evaluate(
            Mode::AcceptEdits,
            &ToolCall::read("/work/Cargo.toml"),
            &[Effect::Read, Effect::Fs],
        )
        .is_allow()
    );
}

#[test]
fn accept_edits_prompts_on_protected_ssh() {
    let e = engine();
    let mut s = session();
    let home = dirs::home_dir().expect("test environment must have home dir");
    let ssh_path = home.join(".ssh/id_rsa");
    let d = e.evaluate(
        &mut s,
        &ToolCall::write(ssh_path),
        Mode::AcceptEdits,
        &[Effect::Write, Effect::Fs],
    );
    assert!(d.is_prompt(), "got {d:?}");
}

#[test]
fn accept_edits_prompts_on_protected_git() {
    let d = evaluate(
        Mode::AcceptEdits,
        &ToolCall::write("/work/.git/config"),
        &[Effect::Write, Effect::Fs],
    );
    assert!(d.is_prompt(), "got {d:?}");
}

#[test]
fn accept_edits_prompts_on_etc() {
    let d = evaluate(
        Mode::AcceptEdits,
        &ToolCall::write("/etc/passwd"),
        &[Effect::Write, Effect::Fs],
    );
    assert!(d.is_prompt(), "got {d:?}");
}

#[test]
fn accept_edits_prompts_on_network() {
    let d = evaluate(
        Mode::AcceptEdits,
        &ToolCall::network("https://api.example.com", "POST"),
        &[Effect::Network, Effect::Write],
    );
    assert!(d.is_prompt(), "got {d:?}");
}

#[test]
fn accept_edits_prompts_on_irreversible() {
    let d = evaluate(
        Mode::AcceptEdits,
        &ToolCall::bash("rm -rf ./build"),
        &[Effect::Write, Effect::Fs, Effect::Irreversible],
    );
    assert!(d.is_prompt(), "got {d:?}");
}

#[test]
fn accept_edits_prompts_on_spawn() {
    let d = evaluate(
        Mode::AcceptEdits,
        &ToolCall::bash("npm install"),
        &[Effect::Network, Effect::Write, Effect::Spawn],
    );
    assert!(d.is_prompt(), "got {d:?}");
}

#[test]
fn accept_edits_prompt_carries_consumable_code() {
    let e = engine();
    let mut s = session();
    let d = e.evaluate(
        &mut s,
        &ToolCall::write("/work/.git/HEAD"),
        Mode::AcceptEdits,
        &[Effect::Write, Effect::Fs],
    );
    let code = match d {
        Decision::Prompt {
            allow_once_code, ..
        } => allow_once_code,
        other => panic!("expected Prompt, got {other:?}"),
    };
    assert!(s.consume_allow_once(&code));
    // Single-use: second consume must fail.
    assert!(!s.consume_allow_once(&code));
}

// ---------------------------------------------------------------------------
// BypassPermissions mode (3 cases)
// ---------------------------------------------------------------------------

#[test]
fn bypass_allows_dangerous_bash() {
    assert!(
        evaluate(
            Mode::BypassPermissions,
            &ToolCall::bash("rm -rf /"),
            &[Effect::Write, Effect::Fs, Effect::Irreversible],
        )
        .is_allow()
    );
}

#[test]
fn bypass_allows_protected_paths() {
    let d = evaluate(
        Mode::BypassPermissions,
        &ToolCall::write("/etc/passwd"),
        &[Effect::Write, Effect::Fs],
    );
    assert!(d.is_allow(), "got {d:?}");
}

#[test]
fn bypass_allows_force_push() {
    assert!(
        evaluate(
            Mode::BypassPermissions,
            &ToolCall::bash("git push --force"),
            &[Effect::MutateVcs, Effect::Network, Effect::Irreversible],
        )
        .is_allow()
    );
}

// ---------------------------------------------------------------------------
// DontAsk mode (3 cases)
// ---------------------------------------------------------------------------

#[test]
fn dont_ask_denies_safe_unmatched_command() {
    let d = evaluate(Mode::DontAsk, &ToolCall::bash("ls"), &[Effect::Read]);
    assert!(d.is_deny(), "got {d:?}");
}

#[test]
fn dont_ask_never_prompts() {
    // Even with effects that would Prompt under AcceptEdits, DontAsk denies.
    let d = evaluate(
        Mode::DontAsk,
        &ToolCall::bash("rm -rf ./build"),
        &[Effect::Write, Effect::Fs, Effect::Irreversible],
    );
    assert!(!d.is_prompt(), "DontAsk must never prompt, got {d:?}");
    assert!(d.is_deny(), "got {d:?}");
}

#[test]
fn dont_ask_increments_deny_counter() {
    let e = engine();
    let mut s = session();
    let _ = e.evaluate(
        &mut s,
        &ToolCall::bash("ls"),
        Mode::DontAsk,
        &[Effect::Read],
    );
    let _ = e.evaluate(
        &mut s,
        &ToolCall::bash("ls"),
        Mode::DontAsk,
        &[Effect::Read],
    );
    assert_eq!(s.deny_count("ls"), 2);
}

// ---------------------------------------------------------------------------
// Default + Auto modes (4 cases)
// ---------------------------------------------------------------------------

#[test]
fn default_allows_safe_read() {
    assert!(evaluate(Mode::Default, &ToolCall::bash("git log"), &[Effect::Read]).is_allow());
}

#[test]
fn default_allows_unmatched_write_pre_phase2() {
    // Phase A: with no rule layer wired in, Default falls through to allow.
    // Phase 2 will deny here once the pack rule layer is in dcg-core.
    assert!(
        evaluate(
            Mode::Default,
            &ToolCall::write("/work/scratch.txt"),
            &[Effect::Write, Effect::Fs],
        )
        .is_allow()
    );
}

#[test]
fn auto_matches_default_for_now() {
    let d_default = evaluate(Mode::Default, &ToolCall::bash("git log"), &[Effect::Read]);
    let d_auto = evaluate(Mode::Auto, &ToolCall::bash("git log"), &[Effect::Read]);
    assert_eq!(d_default.tag(), d_auto.tag());
}

#[test]
fn default_does_not_increment_deny_counter_on_allow() {
    let e = engine();
    let mut s = session();
    let _ = e.evaluate(
        &mut s,
        &ToolCall::bash("git status"),
        Mode::Default,
        &[Effect::Read],
    );
    assert_eq!(s.deny_count("git status"), 0);
}

// ---------------------------------------------------------------------------
// Approve flow (cross-cutting, 2 cases)
// ---------------------------------------------------------------------------

#[test]
fn approve_with_code_promotes_prompt_to_allow() {
    let e = engine();
    let mut s = session();
    let d = e.evaluate(
        &mut s,
        &ToolCall::write("/work/.git/HEAD"),
        Mode::AcceptEdits,
        &[Effect::Write, Effect::Fs],
    );
    let code = match &d {
        Decision::Prompt {
            allow_once_code, ..
        } => allow_once_code.clone(),
        _ => panic!("expected Prompt"),
    };
    let promoted = s.approve_with_code(&code, d);
    assert!(promoted.is_allow());
}

#[test]
fn approve_with_wrong_code_keeps_prompt() {
    let e = engine();
    let mut s = session();
    let d = e.evaluate(
        &mut s,
        &ToolCall::write("/work/.git/HEAD"),
        Mode::AcceptEdits,
        &[Effect::Write, Effect::Fs],
    );
    let result = s.approve_with_code("wrong0", d);
    assert!(result.is_prompt());
}
