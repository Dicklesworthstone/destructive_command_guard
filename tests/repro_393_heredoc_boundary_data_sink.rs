//! Regression tests for issue #393: `core.git:restore-worktree` (and every
//! other command-pattern rule) must never treat a heredoc BODY handed to a
//! data sink as command text.
//!
//! The reported span began in the command line and ended inside the body of
//! `git commit -F - <<EOF`. On current `main` the git stdin-sink model already
//! masks that body, but the same class still leaked through one parser gap:
//! tree-sitter-bash rejects a heredoc whose operator line continues with `;`
//! (`cat <<EOF; echo done`), so the masking view lost every heredoc in the
//! command and the body was re-scanned as live shell. The fix recovers the
//! single unambiguous body span from the tier-2 extractor, and widens the
//! structured stdin sinks (`git commit -aF -`, `-F /dev/stdin`,
//! `git merge -F -`, `gh … --body-file -`).
//!
//! Scope (No-Claim): these tests cover proven data sinks. Unknown receivers
//! and shell/interpreter receivers keep the documented fail-closed scan.

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, LayeredAllowlist};

fn evaluate(command: &str, dialect: ShellDialect) -> destructive_command_guard::EvaluationResult {
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
    assert!(
        heredoc_settings.enabled,
        "heredoc scanning must be on for these repros"
    );
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

fn assert_allowed(command: &str) {
    for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
        let result = evaluate(command, dialect);
        assert!(
            result.is_allowed(),
            "{command:?} must be allowed under {dialect:?}, got {result:?}"
        );
    }
}

fn assert_denied(command: &str) {
    for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
        let result = evaluate(command, dialect);
        assert!(
            result.is_denied(),
            "{command:?} must be denied under {dialect:?}, got {result:?}"
        );
    }
}

/// The reporter's exact repro, in every delimiter spelling. The body is a
/// commit message; `restore` inside it is prose.
#[test]
fn commit_message_heredoc_mentioning_restore_is_allowed_in_every_delimiter_form() {
    for command in [
        "git commit -F - <<EOF\nrows restore byte identical\nEOF",
        "git commit -F - <<'EOF'\nrows restore byte identical\nEOF",
        "git commit -F - <<\"EOF\"\nrows restore byte identical\nEOF",
        "git commit -F - <<-EOF\n\trows restore byte identical\n\tEOF",
        "git commit -F - <<-'EOF'\n\trows restore byte identical\n\tEOF",
        "git commit -F - << EOF\nrows restore byte identical\nEOF",
    ] {
        assert_allowed(command);
    }
}

/// A body that spells out a genuinely destructive command is still data when
/// the receiver is a proven data sink: nothing here executes it.
#[test]
fn data_sink_body_containing_destructive_commands_is_not_executed() {
    for command in [
        "git commit -F - <<EOF\nhow to undo: git restore .\nEOF",
        "git commit -F - <<'EOF'\nrun git reset --hard HEAD~1 to undo\nEOF",
        "cat > notes.md <<EOF\nUse git restore --staged to unstage\nEOF",
        "cat > notes.md <<'EOF'\nnever run rm -rf / on prod\nEOF",
        "tee RUNBOOK.md <<'EOF'\ngit push --force origin main\nEOF",
        "cat <<EOF\ngit checkout -- .\nEOF",
    ] {
        assert_allowed(command);
    }
}

/// The parser gap behind the surviving false positives: `;` on the operator
/// line. Each of these was denied on `restore-worktree` while the `&&` join
/// of the same command was allowed.
#[test]
fn semicolon_on_the_operator_line_keeps_the_data_body_inert() {
    for command in [
        "cat <<EOF; echo done\nundo with git restore . later\nEOF",
        "cat <<'EOF'; echo done\nundo with git restore . later\nEOF",
        "cat <<-EOF; echo done\n\tundo with git restore . later\n\tEOF",
        "git commit -F - <<EOF; git push\nrows restore byte identical\nEOF",
        "git commit -F - <<'EOF'; git status\nrun git reset --hard to undo\nEOF",
        "tee notes.md <<'EOF'; ls\nrm -rf / is never safe\nEOF",
    ] {
        assert_allowed(command);
    }
}

/// Commands after the heredoc are still commands: safe ones pass, destructive
/// ones are denied, whether they follow the terminator or share the operator
/// line.
#[test]
fn commands_after_the_heredoc_are_still_evaluated() {
    assert_allowed("git commit -F - <<EOF\nrows restore byte identical\nEOF\ngit status");
    assert_allowed("cat <<EOF; echo done\nnotes\nEOF\ngit log -1");
    assert_denied("git commit -F - <<EOF\nnotes\nEOF\ngit restore .");
    assert_denied("cat > f <<'EOF'\nnotes\nEOF\ngit reset --hard");
    assert_denied("cat <<EOF; git restore .\nnotes\nEOF");
    assert_denied("git commit -F - <<'EOF'; git reset --hard HEAD~1\nnotes\nEOF");
}

/// Widened git stdin-sink spellings from the #393 audit.
#[test]
fn additional_git_stdin_sink_spellings_are_allowed() {
    for command in [
        "git commit -aF - <<EOF\nundo with git restore . later\nEOF",
        "git commit -F /dev/stdin <<EOF\nundo with git restore . later\nEOF",
        "git commit --file=/dev/stdin <<EOF\nundo with git restore . later\nEOF",
        "git merge --no-ff -F - feature <<EOF\nundo with git restore . later\nEOF",
    ] {
        assert_allowed(command);
    }
}

/// `gh` text operands read from stdin are data.
#[test]
fn gh_body_file_stdin_heredocs_are_allowed() {
    for command in [
        "gh issue comment 42 --body-file - <<'EOF'\nundo with git restore . later\nEOF",
        "gh pr create --title t -F - <<'EOF'\nrun git reset --hard to undo\nEOF",
        "gh release create v1 --notes-file - <<'EOF'\nrm -rf / is never safe\nEOF",
    ] {
        assert_allowed(command);
    }
}

/// Planted negatives: executing receivers, expanding substitutions, and
/// piped bodies keep failing closed.
#[test]
fn executing_receivers_and_expanding_bodies_stay_denied() {
    for command in [
        "bash <<EOF\ngit restore .\nEOF",
        "bash <<EOF; echo done\ngit restore .\nEOF",
        "sh <<'EOF'\ngit reset --hard HEAD~3\nEOF",
        "cat <<'EOF' | bash\ngit restore .\nEOF",
        "cat > f <<EOF\n$(git restore .)\nEOF",
        "git commit -F - <<EOF\n$(rm -rf /tmp/x)\nEOF",
        "git commit -F - <<EOF; echo done\n$(git restore .)\nEOF",
    ] {
        assert_denied(command);
    }
}
