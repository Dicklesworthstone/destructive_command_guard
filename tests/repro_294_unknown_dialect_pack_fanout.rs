//! Regression tests for issue #294: under `ShellDialect::Unknown` the regex
//! packs only ever saw a single POSIX-normalized view of the command.
//!
//! `Unknown` is what every generic terminal adapter gets (`hook.rs`'s
//! `_ => ShellDialect::Unknown`) and what the CLI defaults to, so a payload
//! that is inert under POSIX quoting but destructive under cmd.exe or
//! PowerShell parsing passed every regex-only pack. The per-dialect deny-wins
//! union existed only inside the hand-written semantic decoders.
//!
//! The evaluator now replays an allowing unknown-dialect evaluation under the
//! concrete Cmd and PowerShell dialects and adopts a deny from either. These
//! tests pin both the added denials and, just as importantly, the false
//! positives the replay must *not* import.

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, EvaluationResult, LayeredAllowlist};

/// Evaluate with every registry pack force-enabled.
///
/// `Config::enabled_pack_ids` is platform-dependent and omits opt-in packs such
/// as `containers.docker`, which the issue's repro needs.
fn evaluate_all_packs(command: &str, dialect: ShellDialect) -> EvaluationResult {
    let enabled: std::collections::HashSet<String> = REGISTRY
        .all_pack_ids()
        .into_iter()
        .map(str::to_string)
        .collect();
    let ordered = REGISTRY.expand_enabled_ordered(&enabled);
    let keywords = REGISTRY.collect_enabled_keywords(&enabled);
    let index = REGISTRY.build_enabled_keyword_index(&ordered);
    let config = Config::default();
    let overrides = config.overrides.compile();
    let allowlists = LayeredAllowlist::default();
    let heredoc = config.heredoc_settings();
    evaluate_command_with_pack_order_at_path_in_dialect(
        command,
        &keywords,
        &ordered,
        index.as_ref(),
        &overrides,
        &allowlists,
        &heredoc,
        None,
        dialect,
    )
}

fn rule_id(result: &EvaluationResult) -> Option<String> {
    result.pattern_info.as_ref().map(|info| {
        format!(
            "{}:{}",
            info.pack_id.as_deref().unwrap_or("<none>"),
            info.pattern_name.as_deref().unwrap_or("<none>")
        )
    })
}

/// The issue's headline repro: the single quote is never closed, so POSIX
/// swallows the rest of the line as `echo` data while cmd.exe treats `'` as an
/// ordinary argv byte and runs `docker system prune -af` after the `&`.
#[test]
fn cmd_quoted_docker_prune_denies_under_unknown_dialect() {
    let command = "echo 'ok & docker system prune -af";

    let posix = evaluate_all_packs(command, ShellDialect::Posix);
    assert!(
        posix.is_allowed(),
        "{command:?} is quoted data under posix and must stay allowed, got {posix:?}"
    );

    let cmd = evaluate_all_packs(command, ShellDialect::Cmd);
    assert!(cmd.is_denied(), "{command:?} must deny under cmd");
    assert_eq!(
        rule_id(&cmd).as_deref(),
        Some("containers.docker:system-prune"),
        "cmd view attribution changed"
    );

    let unknown = evaluate_all_packs(command, ShellDialect::Unknown);
    assert!(
        unknown.is_denied(),
        "#294: {command:?} must deny under the unknown dialect, got {unknown:?}"
    );
    assert_eq!(
        rule_id(&unknown).as_deref(),
        rule_id(&cmd).as_deref(),
        "the unknown-dialect deny must carry the same rule id the cmd view reports"
    );
}

/// A POSIX backslash neutralizes the separator; cmd.exe has no backslash
/// escape, so the separator stays live and a second command runs.
#[test]
fn posix_escaped_separators_still_deny_under_unknown_dialect() {
    for command in [
        "echo ok \\& docker system prune -af",
        "echo ok \\| docker system prune -af",
    ] {
        assert!(
            evaluate_all_packs(command, ShellDialect::Posix).is_allowed(),
            "{command:?} must stay allowed under posix"
        );
        let unknown = evaluate_all_packs(command, ShellDialect::Unknown);
        assert!(
            unknown.is_denied(),
            "#294: {command:?} must deny under the unknown dialect, got {unknown:?}"
        );
    }
}

/// The PowerShell analogue: `iex`/`Invoke-Expression` executes a string that
/// POSIX and cmd.exe both treat as inert data piped to an unknown program.
#[test]
fn powershell_invoke_expression_denies_under_unknown_dialect() {
    for command in [
        "'git reset --hard' | iex",
        "\"git reset --hard\" | Invoke-Expression",
    ] {
        assert!(
            evaluate_all_packs(command, ShellDialect::Posix).is_allowed(),
            "{command:?} must stay allowed under posix"
        );

        let powershell = evaluate_all_packs(command, ShellDialect::PowerShell);
        assert!(
            powershell.is_denied(),
            "{command:?} must deny under ps, got {powershell:?}"
        );

        let unknown = evaluate_all_packs(command, ShellDialect::Unknown);
        assert!(
            unknown.is_denied(),
            "#294: {command:?} must deny under the unknown dialect, got {unknown:?}"
        );
        assert_eq!(
            rule_id(&unknown).as_deref(),
            rule_id(&powershell).as_deref(),
            "the unknown-dialect deny must carry the same rule id the ps view reports"
        );
    }
}

/// Planted negatives: benign commands that contain the gating bytes must not
/// pick up a deny from any replayed view.
#[test]
fn benign_quoted_commands_stay_allowed_under_unknown_dialect() {
    for command in [
        "echo 'hello & goodbye'",
        "echo \"a & b\"",
        "git commit -m \"merge & cleanup\"",
        "docker ps -a",
        "echo hello",
    ] {
        let result = evaluate_all_packs(command, ShellDialect::Unknown);
        assert!(
            result.is_allowed(),
            "{command:?} must stay allowed under the unknown dialect, got {result:?}"
        );
    }
}

/// Planted negatives: known cmd-dialect false positives must stay confined to
/// the cmd dialect. cmd.exe reading quoted bytes as ordinary argv text inside a
/// single segment cannot execute anything the POSIX view missed, so the Cmd
/// replay is scoped to parses that expose an *extra* command segment.
#[test]
fn cmd_only_false_positives_are_not_imported_into_unknown_dialect() {
    for command in [
        "git commit -m 'fix: do not rm -rf root'",
        "echo a=b | sed -E 's/=.*/=<set>/'",
        "echo '$(rm -r ./tree)'",
    ] {
        assert!(
            evaluate_all_packs(command, ShellDialect::Posix).is_allowed(),
            "{command:?} must be allowed under posix"
        );
        let result = evaluate_all_packs(command, ShellDialect::Unknown);
        assert!(
            result.is_allowed(),
            "#294: the cmd-view replay must not import this false positive into the \
             unknown dialect: {command:?} got {result:?}"
        );
    }
}

/// A command the POSIX view already denies keeps its exact attribution: the
/// primary deny short-circuits before any replay runs.
#[test]
fn posix_denied_commands_keep_their_rule_id_under_unknown_dialect() {
    for command in ["git reset --hard", "rm -rf /home/user"] {
        let posix = evaluate_all_packs(command, ShellDialect::Posix);
        let unknown = evaluate_all_packs(command, ShellDialect::Unknown);
        assert!(posix.is_denied() && unknown.is_denied(), "{command:?}");
        assert_eq!(
            rule_id(&unknown),
            rule_id(&posix),
            "{command:?} attribution must be unchanged under the unknown dialect"
        );
    }
}

/// `--dialect posix` must be completely unaffected by the fan-out.
#[test]
fn posix_dialect_behavior_is_unchanged() {
    assert!(evaluate_all_packs("git reset --hard", ShellDialect::Posix).is_denied());
    assert!(evaluate_all_packs("echo hello", ShellDialect::Posix).is_allowed());
    assert!(evaluate_all_packs("echo 'hello & goodbye'", ShellDialect::Posix).is_allowed());
    assert!(
        evaluate_all_packs("echo 'ok & docker system prune -af", ShellDialect::Posix).is_allowed()
    );
}
