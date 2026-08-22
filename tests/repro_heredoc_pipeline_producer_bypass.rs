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
    ] {
        lab.assert_denied(command, rule);
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
