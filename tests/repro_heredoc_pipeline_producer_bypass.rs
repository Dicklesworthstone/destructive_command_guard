//! Regression tests for a heredoc-producer pipeline bypass found while
//! reviewing #329 (shipped in v0.11.0 – v0.12.0).
//!
//! `cat <<'EOF' | bash … EOF` executed its body unguarded. tree-sitter-bash
//! attaches the pipeline of a heredoc-carrying statement to the
//! `heredoc_redirect` node rather than to the statement, so the `pipeline`
//! node begins with the `|` operator and has no producer stage; the
//! executable-sink collector only inspected consumers at index ≥ 1 of a
//! pipeline's stages and therefore never saw the consumer at all. Meanwhile
//! the data-sink masking treated the `cat` heredoc as inert prose. Every
//! `<heredoc producer> | <shell or interpreter>` shape was invisible.
//!
//! The producer is now synthesized from the enclosing statement, so the body
//! is re-evaluated as the consumer's source exactly like `echo … | bash`.

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn dcg_binary() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // deps/
    path.pop(); // debug/
    path.push(format!("dcg{}", std::env::consts::EXE_SUFFIX));
    path
}

struct Lab {
    root: PathBuf,
}

impl Lab {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "dcg-heredoc-pipe-{}-{}-{}",
            label,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(root.join("home")).unwrap();
        std::fs::create_dir_all(root.join("xdg")).unwrap();
        std::fs::create_dir_all(root.join("work")).unwrap();
        Self { root }
    }

    /// Bare `dcg` hook mode. Returns (stdout, stderr).
    fn hook(&self, command: &str) -> (String, String) {
        let input = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": command },
        });
        let mut child = Command::new(dcg_binary())
            .env_clear()
            .env("HOME", self.root.join("home"))
            .env("USERPROFILE", self.root.join("home"))
            .env("XDG_CONFIG_HOME", self.root.join("xdg"))
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("DCG_HOOK_TIMEOUT_MS", "5000")
            .env("DCG_PACKS", "core.git,core.filesystem")
            .current_dir(self.root.join("work"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn dcg");
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

    fn assert_denied(&self, command: &str, expect_in_output: &str) {
        let (stdout, stderr) = self.hook(command);
        assert!(
            stdout.contains("deny"),
            "expected DENY for:\n{command}\n--- stdout:\n{stdout}\n--- stderr:\n{stderr}"
        );
        assert!(
            stdout.contains(expect_in_output),
            "expected {expect_in_output:?} in the denial for:\n{command}\n--- stdout:\n{stdout}"
        );
    }

    fn assert_allowed(&self, command: &str) {
        let (stdout, stderr) = self.hook(command);
        assert!(
            stdout.trim().is_empty(),
            "expected ALLOW for:\n{command}\n--- stdout:\n{stdout}\n--- stderr:\n{stderr}"
        );
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn heredoc_piped_into_a_shell_is_evaluated_as_that_shells_source() {
    let lab = Lab::new("shell");
    for (command, rule) in [
        ("cat <<'EOF' | bash\nrm -rf ./src\nEOF", "rm-rf-general"),
        ("cat <<EOF | bash\nrm -rf ./src\nEOF", "rm-rf-general"),
        ("cat <<'EOF' | sh\ngit reset --hard\nEOF", "reset-hard"),
        ("cat <<'EOF' | bash -\ngit push --force\nEOF", "push-force"),
        ("cat <<'EOF' | bash -s\ngit clean -fd\nEOF", "clean-force"),
        (
            "cat <<'EOF' | bash\necho hi && git push --force\nEOF",
            "push-force",
        ),
        ("cat <<-'EOF' | zsh\n\trm -rf ./src\n\tEOF", "rm-rf-general"),
        (
            "cat <<'EOF' | bash\nrm -rf /tmp/x\nEOF\nrm -rf ./src",
            "rm-rf-general",
        ),
        // Redirects on the consuming shell do not stop it reading the pipe.
        // These were a second, adjacent bypass: a redirect token was read as
        // a script-file operand, flipping the consumer to "does not read
        // stdin" and allowing the body.
        (
            "cat <<'EOF' | bash 2>/dev/null\nrm -rf ./src\nEOF",
            "rm-rf-general",
        ),
        (
            "cat <<'EOF' | bash > log\ngit reset --hard\nEOF",
            "reset-hard",
        ),
        (
            "cat <<'EOF' | bash >log 2>&1\ngit push --force\nEOF",
            "push-force",
        ),
        // Reading the pipe as a file through the stdin device.
        (
            "cat <<'EOF' | bash /dev/stdin\nrm -rf ./src\nEOF",
            "rm-rf-general",
        ),
        (
            "cat <<'EOF' | bash /dev/fd/0\ngit reset --hard\nEOF",
            "reset-hard",
        ),
        // Force-clobber pipe operator.
        ("cat <<'EOF' |& bash\nrm -rf ./src\nEOF", "rm-rf-general"),
    ] {
        lab.assert_denied(command, rule);
    }
}

#[test]
fn an_unrecognized_shell_long_option_does_not_hide_the_piped_payload() {
    // A no-value long option (`--norc`, `--posix`, `--login`, `--noprofile`)
    // does not change the program source: the shell still runs its script from
    // stdin. It must not be read as a script-file operand (which would ALLOW
    // the payload). Found in the session's fresh-eyes review.
    let lab = Lab::new("longopt");
    for command in [
        "echo 'rm -rf ~' | bash --norc",
        "echo 'rm -rf ~' | bash --posix",
        "echo 'git reset --hard' | bash --login",
        "echo 'rm -rf ~' | sh --noprofile",
        "bash --norc <(echo 'rm -rf ~')",
        "bash --posix <(echo 'git reset --hard')",
    ] {
        let (stdout, stderr) = lab.hook(command);
        assert!(
            stdout.contains("deny"),
            "expected DENY for:\n{command}\n--- stdout:\n{stdout}\n--- stderr:\n{stderr}"
        );
    }
    // A benign payload through a long-option shell stays allowed, and a `-c`
    // long form still means the shell does not read stdin.
    lab.assert_allowed("echo hi | bash --norc");
    lab.assert_allowed("cat data | bash --rcfile x -c 'echo ok'");
}

#[test]
fn a_redirect_stealing_stdout_from_the_producer_is_genuinely_safe() {
    // `cat <<EOF >log … EOF | bash` sends the heredoc body to `log`, so the
    // pipe delivers nothing to bash. This is a true allow, not a miss — the
    // body never reaches an executor. (Contrast with `bash 2>/dev/null`,
    // where only stderr is redirected and stdin still feeds the shell.)
    //
    // The mirror form `cat >log <<EOF | bash` (redirect *before* the heredoc
    // operator) is identical in bash but dcg denies it conservatively rather
    // than proving the stdout steal across that token order — a tolerable
    // false positive in the safe direction, never a false negative.
    let lab = Lab::new("stdout-stolen");
    lab.assert_allowed("cat <<'EOF' >log | bash\nrm -rf ./src\nEOF");
}

#[test]
fn process_substitution_into_a_shell_is_not_defeated_by_a_redirect() {
    // Same redirect-classifier root cause, different mechanism: `bash <(…)`
    // runs the substitution as a script, and a redirect on the consuming
    // shell (`bash 2>/dev/null <(…)`) must not read that redirect token as
    // the script-file operand and conclude the shell runs nothing.
    let lab = Lab::new("procsub");
    for command in [
        "bash <(echo 'rm -rf ./src')",
        "bash 2>/dev/null <(echo 'git reset --hard')",
        "bash >log <(echo 'git push --force')",
        "sh 2>/dev/null <(printf 'rm -rf ./src')",
    ] {
        let (stdout, stderr) = lab.hook(command);
        assert!(
            stdout.contains("deny"),
            "expected DENY for:\n{command}\n--- stdout:\n{stdout}\n--- stderr:\n{stderr}"
        );
    }
}

#[test]
fn an_rcfile_process_substitution_into_an_interactive_shell_is_evaluated() {
    // Sibling of the long-option fix, found by adversarially sweeping it: an
    // *interactive* shell sources its `--rcfile`/`--init-file` at startup, and
    // that file may be a process substitution — `bash --init-file <(…) -i` runs
    // the producer's output (verified on macOS and Linux). The value-taking
    // option must not swallow the marker as an inert option argument and
    // conclude the shell runs nothing (which ALLOWED the payload); the producer
    // is the shell's source. Both token orders and the glued `=` spelling.
    let lab = Lab::new("rcfile");
    for command in [
        "bash --init-file <(echo 'rm -rf ./src') -i",
        "bash --rcfile <(echo 'git reset --hard') -i",
        "bash -i --rcfile <(printf 'rm -rf ./src')",
        "bash --init-file=<(echo 'rm -rf ./src') -i",
        "bash --rcfile=<(echo 'git reset --hard') -i",
    ] {
        let (stdout, stderr) = lab.hook(command);
        assert!(
            stdout.contains("deny"),
            "expected DENY for:\n{command}\n--- stdout:\n{stdout}\n--- stderr:\n{stderr}"
        );
    }
    // Controls: a real-file rcfile value (not the marker) leaves the marker as
    // the benign script the shell runs, and `-o`/`-O` take a shopt *name* bash
    // rejects rather than executes — both stay allowed.
    lab.assert_allowed("bash --rcfile init.sh <(echo 'echo hi')");
    lab.assert_allowed("bash --init-file cfg.sh <(echo 'echo done')");
    lab.assert_allowed("bash -o errexit <(echo 'echo ok')");
}

#[test]
fn legit_pipelines_whose_consumer_runs_a_script_file_stay_allowed() {
    // False-positive guard for the redirect/stdin-device classifier: a shell
    // consumer with a real script-file operand runs that file, not the pipe.
    let lab = Lab::new("scriptfile");
    for command in [
        "cat <<'EOF' | bash deploy.sh\nrm -rf ./src\nEOF",
        "cat <<'EOF' | bash build.sh 2>/dev/null\ngit reset --hard\nEOF",
    ] {
        lab.assert_allowed(command);
    }
}

#[test]
fn heredoc_piped_into_an_interpreter_or_wrapped_shell_fails_closed_or_denies() {
    let lab = Lab::new("interp");
    // Each of these must not be a silent allow. Some are evaluated through
    // the interpreter AST path, others are unverifiable consumers; either
    // way the answer is a denial.
    for command in [
        "cat <<'EOF' | python3\nimport shutil; shutil.rmtree(\"src\")\nEOF",
        "cat <<'EOF' | sudo bash\nrm -rf ./src\nEOF",
        "cat <<'EOF' | env bash\nrm -rf ./src\nEOF",
        "tee x.sh <<'EOF' | bash\nrm -rf ./src\nEOF",
        "sed s/a/b/ <<'EOF' | bash\nrm -rf ./src\nEOF",
        "cat <<'EOF' | tee x.sh | bash\nrm -rf ./src\nEOF",
        "cat <<'EOF' | grep -v '^#' | bash\nrm -rf ./src\nEOF",
    ] {
        let (stdout, stderr) = lab.hook(command);
        assert!(
            stdout.contains("deny"),
            "expected DENY for:\n{command}\n--- stdout:\n{stdout}\n--- stderr:\n{stderr}"
        );
    }
}

#[test]
fn heredoc_piped_into_a_data_consumer_stays_data() {
    // The #329 posture: prose about destructive commands written through a
    // data sink is not a destructive command, and a data-only pipeline
    // consumer does not change that.
    let lab = Lab::new("data");
    for command in [
        "cat <<'EOF' | grep -c rm\nNever run rm -rf / on this box.\nEOF",
        "cat <<'EOF' | wc -l\nNever run rm -rf / on this box.\nEOF",
        "cat <<'EOF' | tee notes.md\nNever run git reset --hard here.\nEOF",
        "cat <<'EOF' | sort > notes.md\nrm -rf ./src is a bad idea\nEOF",
        "cat > notes.md <<'EOF'\nNever run rm -rf / on this box.\nEOF",
        // A harmless body through an executing consumer is still allowed.
        "cat <<'EOF' | bash\necho hello\nls -la\nEOF",
    ] {
        lab.assert_allowed(command);
    }
}
