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

/// `-d` and `-r` are `--description` and `--reason` on `br create`, `update`,
/// `close` and `reopen`, and `--check-acceptance` takes a text selector that br
/// matches against stored text.
#[test]
fn br_short_spellings_and_selectors_are_data_issue_618() {
    for flag in ["-d", "-r", "--check-acceptance", "--uncheck-acceptance"] {
        allowed(&format!("br update bd-x {flag} {LAUNCHER_PROSE}"));
        denied(&format!(
            "br update bd-x {flag} \"see $(git reset --hard)\""
        ));
        denied(&format!("br update bd-x {flag} 'note' && git reset --hard"));
    }
    allowed(&format!("br create --title t -d {LAUNCHER_PROSE} -p 2"));
    allowed(&format!("br close bd-x -r {LAUNCHER_PROSE}"));
    // `-r` is a switch on `br list`. It hides no redirect there either.
    denied("br list -r > /etc/passwd");
}

/// A redirection is not the flag's value: the shell opens its target before br
/// starts. These flags take every word up to the next flag, so without this the
/// operator and the target were masked with the note, and no rule saw the write.
#[test]
fn br_free_text_flags_do_not_hide_a_redirect_target() {
    const OLDER_FLAGS: &[&str] = &["--description", "--title", "--body", "--notes", "--reason"];
    let flags = NEW_FREE_TEXT_FLAGS.iter().chain(OLDER_FLAGS);
    for flag in flags {
        for redirect in [
            "> /etc/passwd",
            ">/etc/passwd",
            ">> /etc/passwd",
            ">| /etc/passwd",
            "&> /etc/passwd",
            "2> /etc/passwd",
            "> /dev/sda",
            "> .git/config",
            ">> .git/hooks/pre-commit",
            "> ~/.bashrc",
        ] {
            denied(&format!("br update bd-x {flag} note {redirect}"));
            denied(&format!("br update bd-x {flag} 'a note' {redirect}"));
        }
        // Glued to the value, and to the `--flag=value` spelling.
        denied(&format!("br update bd-x {flag} note>/etc/passwd"));
        denied(&format!("br update bd-x {flag} 'a note'>/etc/passwd"));
        denied(&format!("br update bd-x {flag} note> /etc/passwd"));
        denied(&format!("br update bd-x {flag} note>> .git/config"));
        denied(&format!("br update bd-x {flag}=note>/etc/passwd"));
        denied(&format!("br update bd-x {flag}='a note'>/etc/passwd"));
    }
    for short in ["-d", "-r"] {
        denied(&format!("br update bd-x {short} note > /etc/passwd"));
        denied(&format!("br update bd-x {short} note>/etc/passwd"));
    }
    denied("bd update bd-x --notes note > /etc/passwd");
    denied("bd update bd-x --notes note>/etc/passwd");
}

/// The same word boundary for the flags that take one value, for `echo` when
/// the operator ends the word, and for `command -v`, which masks its arguments.
#[test]
fn a_glued_redirect_is_not_part_of_a_data_value() {
    for cmd in [
        "git commit -m msg>/etc/passwd",
        "git commit -m 'a msg'>/etc/passwd",
        "git commit -m msg> /etc/passwd",
        "git commit -m > /etc/passwd",
        "git commit -m'a msg'>/etc/passwd",
        "git commit --message=msg>/etc/passwd",
        "gh issue create --title t>/etc/passwd",
        "grep -e x>/etc/passwd",
        "grep x>/etc/passwd",
        "echo x> /etc/passwd",
        "echo x>> /etc/passwd",
        "command -v x > /etc/passwd",
        "command -v x>/etc/passwd",
        "command -V x >> ~/.bashrc",
    ] {
        denied(cmd);
    }
}

/// Text that only looks like a redirection, and redirections to harmless
/// targets, keep the verdict an ordinary note has.
#[test]
fn br_free_text_flags_keep_allowing_harmless_redirects_and_prose() {
    for flag in NEW_FREE_TEXT_FLAGS {
        for tail in [
            "note > /tmp/out.log",
            "note>/tmp/out.log",
            "note 2>/dev/null",
            "note 2>&1",
            "note > /dev/null 2>&1",
            "'x > /etc/passwd'",
            "'x>/etc/passwd'",
            "\"x>/etc/passwd\"",
            "x\\>y",
            "'rm -rf /' --json > /tmp/o.json",
        ] {
            allowed(&format!("br update bd-x {flag} {tail}"));
        }
    }
    for cmd in [
        "git commit -m 'a > /etc/passwd'",
        "git commit -m msg>/tmp/out.log",
        "git commit -m msg 2>&1",
        "grep -e 'a>/etc/passwd' file",
        "grep 'a>/etc/passwd' file",
        "echo 'x> /etc/passwd'",
        "echo x\\> /etc/passwd",
        "echo x> /tmp/out.log 'rm -rf /'",
        "command -v x >/dev/null 2>&1",
        "command -v x > /dev/null",
        "command -V 'rm -rf /' 2>/dev/null",
        "command -v x > /tmp/out.log 'rm -rf /'",
    ] {
        allowed(cmd);
    }
}
