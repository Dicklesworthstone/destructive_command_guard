//! Regression tests for issue #331: the rebase-recovery auto-allow and permit
//! resolved against the hook's cwd even when the command's own `cd` is what
//! reaches the target repository.
//!
//! `cd <worktree> && git restore --ours -- f` is the shape agents produce when
//! a conflict surfaced in a sibling worktree: the harness reports the
//! session's cwd, the command moves elsewhere before the guarded git call
//! runs. The probe must follow that move — and must NOT follow anything it
//! cannot attribute statically (expansions, subshells, a `cd` after the
//! match), so the recovery window can never open against the wrong repo.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

/// `<root>/rebasing` (has `.git/rebase-merge/`), `<root>/clean` (plain repo),
/// `<root>/home` (hermetic HOME / config).
struct Lab {
    root: PathBuf,
}

impl Lab {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "dcg-331-{}-{}-{}",
            label,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(root.join("rebasing").join(".git").join("rebase-merge")).unwrap();
        fs::create_dir_all(root.join("clean").join(".git")).unwrap();
        fs::create_dir_all(root.join("home")).unwrap();
        fs::create_dir_all(root.join("xdg")).unwrap();
        Self {
            // Canonical so `cd <abs>` paths and the hook's cwd agree on macOS
            // (`/var` → `/private/var`).
            root: fs::canonicalize(root).unwrap(),
        }
    }

    fn rebasing(&self) -> PathBuf {
        self.root.join("rebasing")
    }

    fn clean(&self) -> PathBuf {
        self.root.join("clean")
    }

    fn base_command(&self, process_cwd: &Path) -> Command {
        let mut cmd = Command::new(dcg_binary());
        cmd.env_clear()
            .env("HOME", self.root.join("home"))
            .env("USERPROFILE", self.root.join("home"))
            .env("XDG_CONFIG_HOME", self.root.join("xdg"))
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("DCG_HOOK_TIMEOUT_MS", "5000")
            .env("DCG_PACKS", "core.git,core.filesystem")
            .current_dir(process_cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }

    /// Run bare `dcg` (the PreToolUse hook) with the process cwd and an
    /// optional `cwd` envelope field. Returns (stdout, stderr).
    fn hook(&self, process_cwd: &Path, json_cwd: Option<&Path>, command: &str) -> (String, String) {
        let mut input = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": command },
        });
        if let Some(cwd) = json_cwd {
            input["cwd"] = serde_json::Value::String(cwd.to_string_lossy().into_owned());
        }
        let mut child = self.base_command(process_cwd).spawn().expect("spawn dcg");
        {
            let stdin = child.stdin.as_mut().unwrap();
            serde_json::to_writer(stdin, &input).unwrap();
        }
        let output = child.wait_with_output().expect("wait dcg");
        (
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
    }

    fn rebase_recover(&self, process_cwd: &Path) {
        let output = self
            .base_command(process_cwd)
            .arg("rebase-recover")
            .arg("--ttl")
            .arg("120")
            .output()
            .expect("run dcg rebase-recover");
        assert!(
            output.status.success(),
            "dcg rebase-recover failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn assert_allowed_by_recovery(out: &(String, String), context: &str) {
    let (stdout, stderr) = out;
    assert!(
        stdout.trim().is_empty(),
        "{context}: expected allow (empty stdout), got:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("rebase-recovery"),
        "{context}: allow must be attributed to rebase-recovery on stderr, got:\n{stderr}"
    );
}

fn assert_denied(out: &(String, String), rule: &str, context: &str) {
    let (stdout, stderr) = out;
    assert!(
        stdout.contains("deny"),
        "{context}: expected deny, got stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains(rule),
        "{context}: expected rule {rule} in:\n{stdout}"
    );
}

const RESTORE: &str = "git restore --worktree --ours -- f.txt";

#[test]
fn baseline_hook_cwd_inside_rebasing_repo_allows() {
    // The documented path still works: hook cwd IS the rebasing repo.
    let lab = Lab::new("baseline");
    let out = lab.hook(&lab.rebasing(), Some(&lab.rebasing()), RESTORE);
    assert_allowed_by_recovery(&out, "cwd=rebasing, bare command");
}

#[test]
fn embedded_cd_into_rebasing_repo_allows_from_a_sibling_cwd() {
    // Failure mode A from the report: cwd is the sibling; the command cd's
    // into the rebasing repo itself.
    let lab = Lab::new("embedded-cd");
    let command = format!("cd {} && {RESTORE}", lab.rebasing().display());
    let out = lab.hook(&lab.clean(), Some(&lab.clean()), &command);
    assert_allowed_by_recovery(&out, "cwd=clean, cd rebasing && restore");

    // All four recovery rules share the mechanism.
    for guarded in [
        "git checkout -- .",
        "git checkout HEAD -- f.txt",
        "git restore f.txt",
    ] {
        let command = format!("cd {} && {guarded}", lab.rebasing().display());
        let out = lab.hook(&lab.clean(), Some(&lab.clean()), &command);
        assert_allowed_by_recovery(&out, &format!("cd rebasing && {guarded}"));
    }
}

#[test]
fn relative_cd_forms_resolve_against_the_hook_cwd() {
    let lab = Lab::new("relative");
    for command in [
        "cd rebasing && git restore --worktree --ours -- f.txt",
        "cd rebasing; git restore --worktree --ours -- f.txt",
        "cd rebasing || exit 1; git checkout -- .",
        "cd ./rebasing && git restore -- f.txt",
        "pushd rebasing && git restore -- f.txt",
        "cd clean && cd ../rebasing && git restore -- f.txt",
        "git -C rebasing restore -- f.txt",
        "cd clean && git -C ../rebasing restore -- f.txt",
    ] {
        let out = lab.hook(&lab.root, Some(&lab.root), command);
        assert_allowed_by_recovery(&out, command);
    }
}

#[test]
fn harness_reported_cwd_wins_over_the_hook_process_cwd() {
    // The `cwd` envelope field says where the command runs. When it names
    // the rebasing repo, a bare recovery command is allowed even though the
    // hook process itself sits elsewhere …
    let lab = Lab::new("json-cwd");
    let out = lab.hook(&lab.clean(), Some(&lab.rebasing()), RESTORE);
    assert_allowed_by_recovery(&out, "process cwd=clean, json cwd=rebasing");

    // … and when it names the clean repo, the process cwd being the rebasing
    // repo must NOT unlock anything.
    let out = lab.hook(&lab.rebasing(), Some(&lab.clean()), RESTORE);
    assert_denied(
        &out,
        "restore-worktree",
        "process cwd=rebasing, json cwd=clean",
    );

    // An unusable `cwd` field (relative / nonexistent) falls back to the
    // process cwd rather than disabling recovery.
    let out = lab.hook(&lab.rebasing(), Some(Path::new("not/absolute")), RESTORE);
    assert_allowed_by_recovery(&out, "relative json cwd falls back to process cwd");
    let out = lab.hook(&lab.rebasing(), Some(&lab.root.join("missing")), RESTORE);
    assert_allowed_by_recovery(&out, "missing json cwd falls back to process cwd");
}

#[test]
fn cd_out_of_the_rebasing_repo_denies() {
    // Planted negative: the hook cwd IS rebasing, but the command leaves it
    // before the guarded call. Probing the hook cwd would wrongly allow.
    let lab = Lab::new("cd-out");
    let command = format!("cd {} && {RESTORE}", lab.clean().display());
    let out = lab.hook(&lab.rebasing(), Some(&lab.rebasing()), &command);
    assert_denied(
        &out,
        "restore-worktree",
        "cwd=rebasing, cd clean && restore",
    );

    let out = lab.hook(
        &lab.rebasing(),
        Some(&lab.rebasing()),
        "git -C ../clean restore -- f.txt",
    );
    assert_denied(&out, "restore-worktree", "cwd=rebasing, git -C ../clean");
}

#[test]
fn unattributable_directory_changes_deny() {
    // Planted negatives: every shape where the target directory is not a
    // static literal keeps the deny, even though the rebasing repo exists.
    let lab = Lab::new("dynamic");
    let rebasing = lab.rebasing();
    let cases = [
        "cd \"$REPO\" && git restore --worktree --ours -- f.txt".to_string(),
        "cd $(cat where) && git restore -- f.txt".to_string(),
        format!("(cd {}) && git restore -- f.txt", rebasing.display()),
        format!("(cd {} && git restore -- f.txt)", rebasing.display()),
        format!("cd - && cd {} && git restore -- f.txt", rebasing.display()),
        "cd ~nobody && git restore -- f.txt".to_string(),
        "cd missing-dir && git restore -- f.txt".to_string(),
        // The cd comes AFTER the guarded call: it runs in the hook cwd.
        format!("git restore -- f.txt && cd {}", rebasing.display()),
    ];
    for command in &cases {
        let out = lab.hook(&lab.clean(), Some(&lab.clean()), command);
        assert_denied(&out, "restore-worktree", command);
    }
}

#[test]
fn embedded_cd_does_not_unlock_non_recovery_rules() {
    // Critical safety test: following the cd only moves the probe. Rules
    // outside the narrow recovery set stay blocked inside a rebasing repo.
    let lab = Lab::new("scope");
    for guarded in ["git reset --hard", "git clean -fd", "git push --force"] {
        let command = format!("cd {} && {guarded}", lab.rebasing().display());
        let (stdout, stderr) = lab.hook(&lab.clean(), Some(&lab.clean()), &command);
        assert!(
            stdout.contains("deny"),
            "{guarded} must stay blocked during a rebase reached via cd:\n{stdout}\n{stderr}"
        );
        assert!(
            !stderr.contains("rebase-recovery"),
            "{guarded} must not be attributed to rebase-recovery:\n{stderr}"
        );
    }
}

#[test]
fn permit_minted_in_the_target_repo_is_consumed_through_an_embedded_cd() {
    // Failure mode B from the report: `cd <repo> && dcg rebase-recover`
    // writes the permit under <repo>/.dcg; the retry phrased as
    // `cd <repo> && git …` from the session cwd must consume it.
    let lab = Lab::new("permit");
    let target = lab.clean();
    let permit = target.join(".dcg").join("rebase-recovery-permit");

    // No rebase in progress, no permit: blocked.
    let command = format!("cd {} && git checkout -- .", target.display());
    let out = lab.hook(&lab.root, Some(&lab.root), &command);
    assert_denied(&out, "checkout-discard", "pre-permit");

    lab.rebase_recover(&target);
    assert!(permit.exists(), "rebase-recover must write the permit");

    let out = lab.hook(&lab.root, Some(&lab.root), &command);
    assert_allowed_by_recovery(&out, "cd target && checkout with permit");
    assert!(
        !permit.exists(),
        "the permit is single-shot and must be consumed where it was minted"
    );

    // Consumed: the same command blocks again.
    let out = lab.hook(&lab.root, Some(&lab.root), &command);
    assert_denied(&out, "checkout-discard", "post-consumption");
}

#[test]
fn permit_in_the_hook_cwd_is_not_consumed_by_a_command_that_cds_elsewhere() {
    // Planted negative for the permit path: a permit minted in the session
    // cwd must not be spent on — nor unlock — a command targeting a sibling.
    let lab = Lab::new("permit-scope");
    let here = lab.clean();
    let elsewhere = lab.root.join("elsewhere");
    fs::create_dir_all(elsewhere.join(".git")).unwrap();
    lab.rebase_recover(&here);
    let permit = here.join(".dcg").join("rebase-recovery-permit");
    assert!(permit.exists());

    let command = format!("cd {} && git checkout -- .", elsewhere.display());
    let out = lab.hook(&here, Some(&here), &command);
    assert_denied(
        &out,
        "checkout-discard",
        "permit here, command cds elsewhere",
    );
    assert!(
        permit.exists(),
        "a denied command must leave the unrelated permit untouched"
    );
}

// ---------------------------------------------------------------------------
// A recovery signal unlocks the recovery RULES, never the whole command line.
//
// Found while reviewing #331: the first recovery-eligible match converted the
// deny into an allow without re-checking the rest of the line, so
// `git restore -- f; git reset --hard` ran unguarded inside a rebasing repo
// and a second `git restore` after a further `cd` ran in a repository the
// probe never looked at.
// ---------------------------------------------------------------------------

#[test]
fn recovery_does_not_unlock_a_second_destructive_operation_on_the_line() {
    let lab = Lab::new("residual");
    let rebasing = lab.rebasing();
    let cases = [
        ("git restore -- f.txt; git reset --hard", "reset-hard"),
        ("git restore -- f.txt && git reset --hard", "reset-hard"),
        ("git checkout -- . && git clean -fd", "clean-force"),
        ("git restore -- f.txt || git push --force", "push-force"),
        ("git reset --hard; git restore -- f.txt", "reset-hard"),
        ("git restore -- f.txt && rm -rf ./src", "rm-rf-general"),
    ];
    for (command, rule) in &cases {
        let out = lab.hook(&rebasing, Some(&rebasing), command);
        assert_denied(&out, rule, command);
        assert!(
            !out.1.contains("Allowing"),
            "{command}: nothing may be announced as allowed:\n{}",
            out.1
        );
    }

    // The same shapes reached through an embedded cd.
    for (guarded, rule) in &cases[..4] {
        let command = format!("cd {} && {guarded}", rebasing.display());
        let out = lab.hook(&lab.clean(), Some(&lab.clean()), &command);
        assert_denied(&out, rule, &command);
    }
}

#[test]
fn recovery_still_allows_a_line_made_only_of_recovery_rules() {
    // Two recovery operations in the same repo are the documented flow.
    let lab = Lab::new("residual-ok");
    let rebasing = lab.rebasing();
    for command in [
        "git restore -- f.txt; git checkout -- .",
        "git restore --worktree -- a.txt && git restore -- b.txt",
        "git status && git restore -- f.txt && git status",
    ] {
        let out = lab.hook(&rebasing, Some(&rebasing), command);
        assert_allowed_by_recovery(&out, command);
    }
}

#[test]
fn recovery_denies_a_second_guarded_call_in_another_repository() {
    let lab = Lab::new("residual-repo");
    let rebasing = lab.rebasing();
    let clean = lab.clean();
    let cases = [
        format!(
            "cd {} && git restore -- f.txt && cd {} && git restore -- g.txt",
            rebasing.display(),
            clean.display()
        ),
        format!(
            "git restore -- f.txt && git -C {} restore -- g.txt",
            clean.display()
        ),
        format!(
            "git restore -- f.txt && (cd {} && git restore -- g.txt)",
            clean.display()
        ),
        format!(
            "git restore -- f.txt; pushd {} && git checkout -- .",
            clean.display()
        ),
        "git restore -- f.txt && bash -c 'cd ../clean && git restore -- g.txt'".to_string(),
        "bash -c 'cd ../clean && git restore -- g.txt' && git restore -- f.txt".to_string(),
        "eval 'cd ../clean' && git restore -- f.txt".to_string(),
    ];
    for command in &cases {
        let out = lab.hook(&rebasing, Some(&rebasing), command);
        assert_denied(&out, "restore-worktree", command);
        assert!(
            !out.1.contains("Allowing"),
            "{command}: nothing may be announced as allowed:\n{}",
            out.1
        );
    }
}

#[test]
fn permit_is_not_consumed_when_a_residual_finding_keeps_the_deny() {
    let lab = Lab::new("permit-residual");
    let target = lab.clean();
    lab.rebase_recover(&target);
    let permit = target.join(".dcg").join("rebase-recovery-permit");
    assert!(permit.exists());

    let out = lab.hook(
        &target,
        Some(&target),
        "git checkout -- . && git reset --hard",
    );
    assert_denied(&out, "reset-hard", "permit + residual reset --hard");
    assert!(
        permit.exists(),
        "a command that did not run must not spend the permit"
    );

    // The permit is still good for the documented single-rule retry.
    let out = lab.hook(&target, Some(&target), "git checkout -- .");
    assert_allowed_by_recovery(&out, "retry with only the recovery rule");
    assert!(
        !permit.exists(),
        "consumed by the command that actually ran"
    );
}

#[test]
fn permit_is_consumed_when_the_residual_finding_only_warns() {
    // `git stash drop` is warn-by-default: the residual finding lets the
    // line run, so the recovery command executes and the single-shot permit
    // must be spent — it must not survive to unlock a later command.
    let lab = Lab::new("permit-residual-warn");
    let target = lab.clean();
    lab.rebase_recover(&target);
    let permit = target.join(".dcg").join("rebase-recovery-permit");
    assert!(permit.exists());

    let (stdout, stderr) = lab.hook(
        &target,
        Some(&target),
        "git checkout -- . && git stash drop",
    );
    assert!(
        !stdout.contains("deny"),
        "warn-level residual must not deny:\n{stdout}\n{stderr}"
    );
    assert!(
        stderr.contains("stash-drop") || stdout.contains("stash-drop"),
        "the warn must name the residual rule:\n{stdout}\n{stderr}"
    );
    assert!(
        !permit.exists(),
        "the line ran, so the permit must be consumed"
    );

    // Nothing left to unlock the next discard.
    let out = lab.hook(&target, Some(&target), "git checkout -- .");
    assert_denied(&out, "checkout-discard", "after a warn-level residual run");
}

#[test]
fn embedded_cd_with_an_unrelated_trailing_command_keeps_the_deny() {
    // The documented flow is one command per line. A trailing unrelated
    // command could carry a directory change dcg cannot see (a script, a
    // nested shell), so the window stays closed — and the block text now
    // says so.
    let lab = Lab::new("trailing");
    let command = format!(
        "cd {} && git checkout -- . && npm install",
        lab.rebasing().display()
    );
    let (stdout, stderr) = lab.hook(&lab.clean(), Some(&lab.clean()), &command);
    assert!(stdout.contains("deny"), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("on its own line"),
        "block text must explain the single-line requirement:\n{stdout}"
    );
}
