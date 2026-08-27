//! Regression tests for issue #330: `[policy]` mode overrides were honoured by
//! `dcg test` and ignored by the `dcg hook` JSONL subcommand.
//!
//! `dcg hook` evaluated commands without ever resolving the active policy, so
//! a rule the user had downgraded to `warn` or `log` still produced
//! `{"decision":"deny"}` — while `dcg test` reported `WARN (policy allows)`
//! for the same config. These tests pin parity between the two entry points
//! on every policy surface (`default_mode`, `[policy.packs]`,
//! `[policy.rules]`) and every mode, plus planted negatives proving the
//! override stays scoped to the rule it names.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

/// A hermetic scratch directory holding the config under test.
struct Lab {
    dir: tempfile::TempDir,
    config_path: PathBuf,
}

impl Lab {
    fn new(config_toml: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("home")).unwrap();
        std::fs::create_dir_all(dir.path().join("xdg")).unwrap();
        let config_path = dir.path().join("policy.toml");
        std::fs::write(&config_path, config_toml).unwrap();
        Self { dir, config_path }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(dcg_binary());
        cmd.args(args)
            .env_clear()
            .env("HOME", self.dir.path().join("home"))
            .env("USERPROFILE", self.dir.path().join("home"))
            .env("XDG_CONFIG_HOME", self.dir.path().join("xdg"))
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("DCG_CONFIG", &self.config_path)
            // Semantic tests, not deadline tests (see cli_e2e.rs).
            .env("DCG_HOOK_TIMEOUT_MS", "5000")
            .env("DCG_PACKS", "core.git,core.filesystem")
            .current_dir(self.dir.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }

    /// Run the `dcg hook` JSONL subcommand on one Claude-style payload.
    fn hook(&self, shell_command: &str) -> HookResult {
        let payload = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": shell_command },
            "cwd": self.dir.path(),
        });
        let mut child = self
            .command(&["hook"])
            .stdin(Stdio::piped())
            .spawn()
            .expect("spawn dcg hook");
        {
            let stdin = child.stdin.as_mut().unwrap();
            writeln!(stdin, "{payload}").unwrap();
        }
        let output = child.wait_with_output().expect("wait dcg hook");
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let line = stdout
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or_else(|| panic!("dcg hook produced no output line\nstderr:\n{stderr}"));
        let json: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("dcg hook output is not JSON ({e}): {line}"));
        HookResult {
            json,
            stderr,
            exit_code: output.status.code(),
        }
    }

    /// Run `dcg test <command>` and return its `Result:` line.
    fn test_result_line(&self, shell_command: &str) -> String {
        let output = self
            .command(&["test", shell_command])
            .stdin(Stdio::null())
            .output()
            .expect("run dcg test");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        stdout
            .lines()
            .chain(stderr.lines())
            .find(|line| line.trim_start().starts_with("Result:"))
            .map(|line| line.trim().to_string())
            .unwrap_or_else(|| {
                panic!("no Result line from dcg test\nstdout:\n{stdout}\nstderr:\n{stderr}")
            })
    }
}

struct HookResult {
    json: serde_json::Value,
    stderr: String,
    exit_code: Option<i32>,
}

impl HookResult {
    fn decision(&self) -> &str {
        self.json["decision"].as_str().unwrap_or("<missing>")
    }

    fn mode(&self) -> Option<&str> {
        self.json.get("mode").and_then(serde_json::Value::as_str)
    }

    fn rule_id(&self) -> Option<&str> {
        self.json.get("rule_id").and_then(serde_json::Value::as_str)
    }
}

const BRANCH_DELETE: &str = "git branch -D somebranch";
const RULE: &str = "core.git:branch-force-delete";

/// One policy surface and what both entry points must report for it.
struct Case {
    label: &'static str,
    config: &'static str,
    hook_decision: &'static str,
    hook_mode: Option<&'static str>,
    test_result: &'static str,
}

const CASES: &[Case] = &[
    Case {
        label: "no policy (control)",
        config: "",
        hook_decision: "deny",
        hook_mode: Some("deny"),
        test_result: "Result: BLOCKED",
    },
    Case {
        label: "[policy] default_mode = warn",
        config: "[policy]\ndefault_mode = \"warn\"\n",
        hook_decision: "allow",
        hook_mode: Some("warn"),
        test_result: "Result: WARN (policy allows)",
    },
    Case {
        label: "[policy.packs] core.git = warn",
        config: "[policy.packs]\n\"core.git\" = \"warn\"\n",
        hook_decision: "allow",
        hook_mode: Some("warn"),
        test_result: "Result: WARN (policy allows)",
    },
    Case {
        label: "[policy.rules] rule = warn",
        config: "[policy.rules]\n\"core.git:branch-force-delete\" = \"warn\"\n",
        hook_decision: "allow",
        hook_mode: Some("warn"),
        test_result: "Result: WARN (policy allows)",
    },
    Case {
        label: "[policy.rules] rule = log",
        config: "[policy.rules]\n\"core.git:branch-force-delete\" = \"log\"\n",
        hook_decision: "allow",
        hook_mode: Some("log"),
        test_result: "Result: LOG (policy allows)",
    },
    Case {
        label: "[policy.rules] rule = ask (no review channel: blocks)",
        config: "[policy.rules]\n\"core.git:branch-force-delete\" = \"ask\"\n",
        hook_decision: "deny",
        hook_mode: Some("ask"),
        test_result: "Result: REVIEW REQUIRED (blocked outside a review-capable hook)",
    },
    Case {
        label: "[overrides] allow (control: the hook reads this file)",
        config: "[overrides]\nallow = ['^git branch -D somebranch$']\n",
        hook_decision: "allow",
        hook_mode: None,
        test_result: "Result: ALLOWED",
    },
];

#[test]
fn hook_subcommand_agrees_with_dcg_test_on_every_policy_surface() {
    for case in CASES {
        let lab = Lab::new(case.config);

        let test_line = lab.test_result_line(BRANCH_DELETE);
        assert_eq!(
            test_line, case.test_result,
            "dcg test disagrees with the expectation for {}",
            case.label
        );

        let hook = lab.hook(BRANCH_DELETE);
        assert_eq!(
            hook.decision(),
            case.hook_decision,
            "dcg hook decision for {} — json: {} stderr: {}",
            case.label,
            hook.json,
            hook.stderr
        );
        assert_eq!(
            hook.mode(),
            case.hook_mode,
            "dcg hook mode for {} — json: {}",
            case.label,
            hook.json
        );
        if case.hook_mode.is_some() {
            assert_eq!(
                hook.rule_id(),
                Some(RULE),
                "a policy-resolved match must still name its rule ({}) — json: {}",
                case.label,
                hook.json
            );
        }

        // The exit-code contract follows the resolved decision: only a real
        // block (deny, or ask without a review channel) is non-zero.
        let expected_exit = i32::from(case.hook_decision == "deny");
        assert_eq!(
            hook.exit_code,
            Some(expected_exit),
            "dcg hook exit code for {} — stderr: {}",
            case.label,
            hook.stderr
        );
    }
}

#[test]
fn warn_mode_allow_is_announced_on_stderr() {
    let lab = Lab::new("[policy.rules]\n\"core.git:branch-force-delete\" = \"warn\"\n");
    let hook = lab.hook(BRANCH_DELETE);
    assert_eq!(hook.decision(), "allow", "{}", hook.json);
    assert!(
        hook.stderr.contains(RULE) && hook.stderr.to_lowercase().contains("warn"),
        "warn-mode allow must say which rule was relaxed on stderr, got: {}",
        hook.stderr
    );
}

#[test]
fn log_mode_allow_is_silent_on_stderr() {
    let lab = Lab::new("[policy.rules]\n\"core.git:branch-force-delete\" = \"log\"\n");
    let hook = lab.hook(BRANCH_DELETE);
    assert_eq!(hook.decision(), "allow", "{}", hook.json);
    assert!(
        !hook.stderr.contains(RULE),
        "log mode is a silent allow, but stderr mentioned the rule: {}",
        hook.stderr
    );
}

#[test]
fn rule_override_does_not_relax_other_rules() {
    // Planted negatives: the override names ONE rule. Everything else must
    // keep blocking under the same config, in both entry points.
    let lab = Lab::new("[policy.rules]\n\"core.git:branch-force-delete\" = \"warn\"\n");

    for command in [
        "git push --force origin main",
        "git reset --hard HEAD~1",
        "rm -rf ./build",
    ] {
        let hook = lab.hook(command);
        assert_eq!(
            hook.decision(),
            "deny",
            "{command} must stay denied under a branch-force-delete override — json: {}",
            hook.json
        );
        assert_eq!(hook.mode(), Some("deny"), "{command}: {}", hook.json);
        assert_eq!(hook.exit_code, Some(1), "{command}");
        assert_eq!(
            lab.test_result_line(command),
            "Result: BLOCKED",
            "dcg test must agree that {command} stays blocked"
        );
    }
}

#[test]
fn severity_default_warn_is_reported_as_warn_in_both_entry_points() {
    // `git stash drop` is a Medium-severity rule, which warns by default with
    // NO policy configured at all. That is the rule's posture, not a
    // relaxation; both entry points must say so identically.
    let lab = Lab::new("");
    let hook = lab.hook("git stash drop");
    assert_eq!(hook.decision(), "allow", "{}", hook.json);
    assert_eq!(hook.mode(), Some("warn"), "{}", hook.json);
    assert_eq!(hook.rule_id(), Some("core.git:stash-drop"), "{}", hook.json);
    assert_eq!(hook.exit_code, Some(0));
    assert_eq!(
        lab.test_result_line("git stash drop"),
        "Result: WARN (policy allows)"
    );

    // …and an explicit per-rule `deny` promotes it in both.
    let strict = Lab::new("[policy.rules]\n\"core.git:stash-drop\" = \"deny\"\n");
    let hook = strict.hook("git stash drop");
    assert_eq!(hook.decision(), "deny", "{}", hook.json);
    assert_eq!(hook.mode(), Some("deny"), "{}", hook.json);
    assert_eq!(strict.test_result_line("git stash drop"), "Result: BLOCKED");
}

#[test]
fn broad_warn_policy_cannot_relax_critical_rules() {
    // `default_mode = "warn"` is constrained for critical-severity rules in
    // the shared resolver; `dcg hook` must inherit that guard, not bypass it.
    let lab = Lab::new("[policy]\ndefault_mode = \"warn\"\n");
    let hook = lab.hook("rm -rf /");
    assert_eq!(hook.decision(), "deny", "{}", hook.json);
    assert_eq!(hook.mode(), Some("deny"), "{}", hook.json);
    assert_eq!(lab.test_result_line("rm -rf /"), "Result: BLOCKED");
}

#[test]
fn explicit_block_override_stays_deny_under_warn_policy() {
    // `[overrides].block` is an explicit user block; policy modes only apply
    // to pack rules. Parity with bare `dcg` / `dcg test`.
    // `[overrides].block` entries are `{ pattern, reason }` tables — a bare
    // string fails to parse, and an unparseable DCG_CONFIG falls back to
    // defaults (with a stderr warning), which would make this test pass
    // for the wrong reason.
    let lab = Lab::new(
        "[policy]\ndefault_mode = \"log\"\n[[overrides.block]]\npattern = '^git status --porcelain$'\nreason = \"planted\"\n",
    );
    let hook = lab.hook("git status --porcelain");
    assert_eq!(hook.decision(), "deny", "{}", hook.json);
    assert_eq!(hook.mode(), Some("deny"), "{}", hook.json);
    assert_eq!(hook.exit_code, Some(1));
    assert_eq!(
        lab.test_result_line("git status --porcelain"),
        "Result: BLOCKED"
    );

    // A block pattern on a command carrying no enabled-pack keyword is
    // subject to the keyword quick-reject in the shared evaluator. Whatever
    // that answer is, the two entry points must give the same one.
    let keywordless =
        Lab::new("[[overrides.block]]\npattern = '^echo forbidden$'\nreason = \"planted\"\n");
    let hook = keywordless.hook("echo forbidden");
    let test_line = keywordless.test_result_line("echo forbidden");
    let expected = if test_line == "Result: BLOCKED" {
        "deny"
    } else {
        "allow"
    };
    assert_eq!(
        hook.decision(),
        expected,
        "dcg hook ({}) and dcg test ({test_line}) disagree on a keyword-less block override",
        hook.json
    );
}

/// Run `dcg hook` on a VS Code Agent Host `toolCalls[]` batch envelope.
fn hook_batch_envelope(lab: &Lab, commands: &[&str]) -> HookResult {
    let tool_calls: Vec<serde_json::Value> = commands
        .iter()
        .map(|command| {
            serde_json::json!({
                "name": "bash",
                "args": serde_json::json!({ "command": command }).to_string(),
            })
        })
        .collect();
    let payload = serde_json::json!({
        "sessionId": "s",
        "cwd": lab.dir.path(),
        "toolCalls": tool_calls,
    });
    let mut child = lab
        .command(&["hook"])
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn dcg hook");
    {
        let stdin = child.stdin.as_mut().unwrap();
        writeln!(stdin, "{payload}").unwrap();
    }
    let output = child.wait_with_output().expect("wait dcg hook");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let line = stdout
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or_else(|| panic!("dcg hook produced no output line\nstderr:\n{stderr}"));
    let json: serde_json::Value = serde_json::from_str(line)
        .unwrap_or_else(|e| panic!("dcg hook output is not JSON ({e}): {line}"));
    HookResult {
        json,
        stderr,
        exit_code: output.status.code(),
    }
}

#[test]
fn batched_envelope_resolves_every_entry_before_a_warn_entry_can_speak() {
    // Fail-open guard: under a warn policy the FIRST entry resolves to
    // `allow` (warn). The batch used to stop at the first evaluator-level
    // non-allow entry, so a destructive SECOND entry was never evaluated.
    let lab = Lab::new(&format!("[policy.rules]\n\"{RULE}\" = \"warn\"\n"));
    let hook = hook_batch_envelope(&lab, &[BRANCH_DELETE, "git reset --hard"]);
    assert_eq!(hook.decision(), "deny", "{}", hook.json);
    assert_eq!(hook.mode(), Some("deny"), "{}", hook.json);
    assert_eq!(hook.rule_id(), Some("core.git:reset-hard"), "{}", hook.json);
    assert_eq!(hook.exit_code, Some(1));
    // The warn entry still announces itself.
    assert!(
        hook.stderr.contains("policy mode is warn"),
        "{}",
        hook.stderr
    );

    // Order-independent: deny first, warn second.
    let hook = hook_batch_envelope(&lab, &["git reset --hard", BRANCH_DELETE]);
    assert_eq!(hook.decision(), "deny", "{}", hook.json);
    assert_eq!(hook.rule_id(), Some("core.git:reset-hard"), "{}", hook.json);

    // All-warn batch: allow, reported as warn.
    let hook = hook_batch_envelope(&lab, &[BRANCH_DELETE, "echo hi", BRANCH_DELETE]);
    assert_eq!(hook.decision(), "allow", "{}", hook.json);
    assert_eq!(hook.mode(), Some("warn"), "{}", hook.json);
    assert_eq!(hook.exit_code, Some(0));

    // Ask outranks warn but not deny, and still blocks on this protocol.
    let ask_lab = Lab::new(&format!(
        "[policy.rules]\n\"{RULE}\" = \"warn\"\n\"core.git:stash-drop\" = \"ask\"\n"
    ));
    let hook = hook_batch_envelope(&ask_lab, &[BRANCH_DELETE, "git stash drop"]);
    assert_eq!(hook.decision(), "deny", "{}", hook.json);
    assert_eq!(hook.mode(), Some("ask"), "{}", hook.json);
    assert_eq!(hook.rule_id(), Some("core.git:stash-drop"), "{}", hook.json);
}

#[test]
fn config_path_is_honoured_relative_to_the_hook_cwd() {
    // Sanity: the lab's DCG_CONFIG is absolute; the config must be the one
    // the hook reads (not a stale user config). A second lab with the
    // opposite policy proves the decision tracks the file.
    let deny_lab = Lab::new("");
    let warn_lab = Lab::new("[policy]\ndefault_mode = \"warn\"\n");
    assert_eq!(deny_lab.hook(BRANCH_DELETE).decision(), "deny");
    assert_eq!(warn_lab.hook(BRANCH_DELETE).decision(), "allow");
    assert!(Path::new(&warn_lab.config_path).is_absolute());
}
