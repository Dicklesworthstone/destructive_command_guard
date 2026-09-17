use std::process::Command;

fn dcg_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

fn run_hook(command: &str) -> String {
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": command,
        }
    });

    let mut child = Command::new(dcg_binary())
        // Hook-mode self-heal writes the invoked binary's own path into the
        // caller's real agent settings, so without this a test run registers
        // `target/release/dcg` as a global Claude Code PreToolUse hook on the
        // developer's machine.
        .env("DCG_SELF_HEAL_HOOK", "0")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn dcg");

    {
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        serde_json::to_writer(stdin, &input).expect("failed to write json");
    }

    let output = child.wait_with_output().expect("failed to wait for dcg");
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn git_global_flag_bypass() {
    // This command is destructive but currently bypassed because regex expects "git reset" directly
    let cmd = "git -C /tmp reset --hard";
    let output = run_hook(cmd);

    assert!(
        !output.trim().is_empty(),
        "Bypass confirmed: '{cmd}' was allowed!"
    );

    assert!(output.contains("deny"), "Should be denied");
}

#[test]
fn git_work_tree_bypass() {
    let cmd = "git --work-tree=/tmp clean -fd";
    let output = run_hook(cmd);

    assert!(
        !output.trim().is_empty(),
        "Bypass confirmed: '{cmd}' was allowed!"
    );

    assert!(output.contains("deny"), "Should be denied");
}

/// #429: a `core.git` safe pattern shadows every destructive pattern in the
/// pack, and the executable prefix used to skip any token between `git` and the
/// subcommand. Appending a dry-run-shaped tail therefore turned a destructive
/// command into an allow, while real git accepted the extra tokens as pathspecs
/// and removed every untracked and ignored file under `.` (verified against git
/// 2.55.0). The tail has to reach the safe pattern past a bare `--`, which is
/// exactly where git stops parsing options.
#[test]
fn a_dry_run_shaped_tail_cannot_rescue_git_clean() {
    for cmd in [
        "git clean -fdx -- . clean -n",
        "git clean -xfd -- . clean --dry-run",
        "git clean -fdx -- . lfs prune --dry-run",
        "git clean -fdx -- . restore --staged x",
        "git clean -fdx -- . checkout -b x",
        "git clean -fdx --quiet -- . clean -n",
    ] {
        let output = run_hook(cmd);
        assert!(
            output.contains("deny"),
            "safe-pattern shadowing rescued a destructive clean: {cmd} -> {output}"
        );
    }
}

/// #431: safe matching runs on a view with the quotes removed, so a *quoted*
/// separator arrives as a bare one and satisfies the dashed branch's
/// command-position guard. The four characters below are exactly that guard's
/// set; each one manufactured a command boundary that the shell never had, and
/// git deleted the tree.
#[test]
fn a_quoted_separator_cannot_manufacture_command_position() {
    for separator in ["(", "&", "|", ";"] {
        let cmd = format!("git clean -fdx -- . '{separator}' git-clean -n");
        let output = run_hook(&cmd);
        assert!(
            output.contains("deny"),
            "a quoted {separator} rescued a destructive clean: {cmd} -> {output}"
        );
    }
}

/// The exemptions the two fixes above must not take away. Git's `parse_options`
/// permutes, so a dry-run flag after a pathspec is still a dry run, and a global
/// option before the subcommand is still the same subcommand.
#[test]
fn real_dry_runs_and_staged_restores_stay_allowed() {
    for cmd in [
        "git clean -n",
        "git clean --dry-run",
        "git clean -fdxn",
        "git clean -fdx -n",
        "git clean . -n",
        "git clean -fdx src -n",
        "git -C /tmp/repo clean -n",
        "git -c core.pager=cat clean --dry-run",
        "git --no-pager clean -n",
        "git --git-dir=/tmp/repo/.git clean -n",
        "git --git-dir /tmp/repo/.git clean -n",
        "git restore --staged file.txt",
        "git restore . --staged",
        "git checkout -b feature/x",
        "git checkout --orphan gh-pages",
        "git lfs prune --dry-run",
        "git-clean -n",
        "/usr/libexec/git-core/git-clean -n",
    ] {
        let output = run_hook(cmd);
        assert!(
            !output.contains("deny"),
            "a non-destructive git invocation was denied: {cmd} -> {output}"
        );
    }
}
