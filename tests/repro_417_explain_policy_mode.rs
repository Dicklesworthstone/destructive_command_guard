//! Regression tests for issue #417: `dcg explain` ignored `[policy]` resolution.
//!
//! `explain` printed the matched rule's severity-default decision and never
//! consulted `[policy.rules]` / `[policy.packs]`, so a rule configured to `warn`,
//! `ask`, or `log` was reported as `DENY` — contradicting both the live hook and
//! `dcg test`, which resolve it correctly. `--format json` carried no mode field
//! either, so there was no way to get the right answer out of explain at all.
//!
//! #330 fixed the same class for the hook and `dcg test`; explain was never
//! touched, and #330's own repro table already showed explain's wrong DENY.
//!
//! #649 must preserve the policy too: arithmetic shifts are not heredocs, so
//! their presence cannot replace an unrelated rule with incomplete-analysis.

use std::io::Write;
use std::process::{Command, Stdio};

fn dcg_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

struct Fixture {
    temp: tempfile::TempDir,
    home: std::path::PathBuf,
    config: std::path::PathBuf,
}

/// Write a config whose single `[policy.rules]` entry sets `mode` for a
/// core.git rule that is always enabled, so the test needs no pack setup.
fn fixture(mode: &str) -> Fixture {
    fixture_with_config(&format!(
        "[policy]\ndefault_mode = \"deny\"\n\n[policy.rules]\n\"core.git:branch-force-delete\" = \"{mode}\"\n"
    ))
}

fn fixture_with_config(config_text: &str) -> Fixture {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let config = temp.path().join("policy.toml");
    std::fs::write(&config, config_text).expect("write config");
    Fixture { temp, home, config }
}

fn run(fixture: &Fixture, args: &[&str]) -> std::process::Output {
    Command::new(dcg_binary())
        .args(args)
        .env_clear()
        .env("HOME", &fixture.home)
        .env("USERPROFILE", &fixture.home)
        .env("DCG_CONFIG", &fixture.config)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("NO_COLOR", "1")
        .env("TERM", "dumb")
        .output()
        .expect("run dcg")
}

fn arithmetic_fixture(fallback_on_parse_error: bool, mode: Option<&str>) -> Fixture {
    let policy = mode.map_or_else(String::new, |mode| {
        format!("[policy.rules]\n\"core.filesystem:rm-rf-general\" = \"{mode}\"\n")
    });
    fixture_with_config(&format!(
        "[general]\ncheck_updates = false\nself_heal_hook = false\n\
         [history]\nenabled = false\n\
         [heredoc]\nenabled = true\nfallback_on_parse_error = {fallback_on_parse_error}\n\
         {policy}"
    ))
}

/// Candidates are arguments or JSON input to DCG; no candidate shell runs.
fn arithmetic_command(fixture: &Fixture, args: &[&str]) -> Command {
    let mut command = Command::new(dcg_binary());
    command
        .args(args)
        .env_clear()
        .env("HOME", &fixture.home)
        .env("USERPROFILE", &fixture.home)
        .env("XDG_CONFIG_HOME", fixture.home.join("config"))
        .env("XDG_DATA_HOME", fixture.home.join("data"))
        .env("XDG_STATE_HOME", fixture.home.join("state"))
        .env("XDG_CACHE_HOME", fixture.home.join("cache"))
        .env("APPDATA", fixture.home.join("appdata"))
        .env("LOCALAPPDATA", fixture.home.join("localappdata"))
        .env("TMPDIR", fixture.temp.path())
        .env("TEMP", fixture.temp.path())
        .env("TMP", fixture.temp.path())
        .env("DCG_CONFIG", &fixture.config)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env(
            "DCG_PENDING_EXCEPTIONS_PATH",
            fixture.temp.path().join("pending.jsonl"),
        )
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_NO_UPDATE_CHECK", "1")
        // Semantic tests use the same isolated envelope as the heredoc
        // regression suite (bd-e1xl); production deadlines are unchanged.
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .env("DCG_AST_TIMEOUT_MS", "5000")
        .env("DCG_HEREDOC_TIMEOUT_MS", "5000")
        .env("NO_COLOR", "1")
        .env("TERM", "dumb")
        .current_dir(fixture.temp.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn arithmetic_explain(fixture: &Fixture, candidate: &str) -> serde_json::Value {
    arithmetic_explain_in_dialect(fixture, candidate, None)
}

fn arithmetic_explain_in_dialect(
    fixture: &Fixture,
    candidate: &str,
    dialect: Option<&str>,
) -> serde_json::Value {
    let mut command = arithmetic_command(fixture, &["explain", "--format", "json"]);
    if let Some(dialect) = dialect {
        command.args(["--dialect", dialect]);
    }
    let output = command
        .arg(candidate)
        .output()
        .expect("run arithmetic explain");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{candidate:?}: {stdout}\n{stderr}");
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{candidate:?}: invalid JSON ({error}): {stdout}\n{stderr}"))
}

fn arithmetic_hook(fixture: &Fixture, args: &[&str], candidate: &str) -> std::process::Output {
    let mut child = arithmetic_command(fixture, args)
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn arithmetic hook");
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": candidate },
        "cwd": fixture.temp.path(),
    });
    writeln!(child.stdin.take().expect("hook stdin"), "{payload}").expect("write hook input");
    child.wait_with_output().expect("wait for arithmetic hook")
}

const COMMAND: &str = "git branch -D scratch";

#[test]
fn explain_reports_the_resolved_policy_outcome_not_the_rule_default() {
    for (mode, expected) in [
        ("deny", "DENY"),
        ("warn", "WARN"),
        ("log", "LOG"),
        ("ask", "ASK"),
    ] {
        let fixture = fixture(mode);
        let out = run(&fixture, &["explain", COMMAND]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains(&format!("Decision: {expected}")),
            "policy mode {mode} must be reported as {expected}.\nstdout: {stdout}"
        );
    }
}

#[test]
fn explain_json_carries_mode_and_outcome() {
    for (mode, expected_outcome) in [
        ("deny", "deny"),
        ("warn", "warn"),
        ("log", "log"),
        ("ask", "ask"),
    ] {
        let fixture = fixture(mode);
        let out = run(&fixture, &["explain", "--format", "json", COMMAND]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let json: serde_json::Value =
            serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("bad JSON ({e}): {stdout}"));
        assert_eq!(
            json["schema_version"], 4,
            "mode/outcome arrived in schema v4"
        );
        assert_eq!(
            json["decision"], "deny",
            "the evaluator finding is stable across modes: the pattern did match"
        );
        assert_eq!(json["mode"], mode, "resolved policy mode");
        assert_eq!(
            json["outcome"], expected_outcome,
            "outcome is the field a consumer gates on"
        );
    }
}

#[test]
fn explain_agrees_with_dcg_test_and_the_live_hook() {
    // The three surfaces must give one answer. Before the fix, explain said DENY
    // while `dcg test` said WARN and the hook let the command run.
    let fixture = fixture("warn");

    let explain = run(&fixture, &["explain", COMMAND]);
    let explain_out = String::from_utf8_lossy(&explain.stdout);
    assert!(
        explain_out.contains("Decision: WARN"),
        "explain: {explain_out}"
    );

    let test = run(&fixture, &["test", COMMAND]);
    let test_out =
        String::from_utf8_lossy(&test.stdout).to_string() + &String::from_utf8_lossy(&test.stderr);
    assert!(test_out.contains("Result: WARN"), "dcg test: {test_out}");

    // Live hook: a warn-mode rule exits 0 with no denial document on stdout and
    // a warning on stderr.
    let mut child = Command::new(dcg_binary())
        .env_clear()
        .env("HOME", &fixture.home)
        .env("USERPROFILE", &fixture.home)
        .env("DCG_CONFIG", &fixture.config)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("NO_COLOR", "1")
        .env("TERM", "dumb")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hook");
    let payload = format!(
        r#"{{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{{"command":"{COMMAND}"}}}}"#
    );
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    let hook = child.wait_with_output().expect("wait");
    assert!(hook.status.success(), "warn mode exits 0");
    assert!(
        String::from_utf8_lossy(&hook.stdout).trim().is_empty(),
        "warn mode emits no denial document"
    );
    assert!(
        String::from_utf8_lossy(&hook.stderr).contains("WARNING"),
        "warn mode warns on stderr: {}",
        String::from_utf8_lossy(&hook.stderr)
    );
}

#[test]
fn a_policy_override_explains_why_the_outcome_moved() {
    // A WARN printed above a High-severity match reads as a contradiction unless
    // explain names the policy that moved it.
    let fixture = fixture("warn");
    let out = run(&fixture, &["explain", COMMAND]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("[policy] mode warn"),
        "explain must name the policy that moved the outcome.\nstdout: {stdout}"
    );
}

#[test]
fn an_unmatched_command_reports_no_mode() {
    let fixture = fixture("warn");
    let out = run(&fixture, &["explain", "--format", "json", "git status"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(json["decision"], "allow");
    assert_eq!(json["outcome"], "allow");
    assert!(
        json.get("mode").is_none() || json["mode"].is_null(),
        "no policy mode applies when nothing matched: {stdout}"
    );
}

const ARITHMETIC_COMPOUND: &str = "echo $((1<<2)) && rm -rf build";
const RM_RULE: &str = "core.filesystem:rm-rf-general";

#[test]
fn issue_649_arithmetic_shifts_preserve_the_unrelated_command_policy() {
    let candidates = [
        "rm -rf build",
        ARITHMETIC_COMPOUND,
        "echo \"$((1 << 2))\"; rm -rf build",
        "echo $((value <<= 2)); rm -rf build",
        "echo $((1 << (2 + (3 >> 1)))) || rm -rf build",
        "echo $((1 << $((1+1)))); rm -rf build",
        "echo $((1 << $((1<<1)))); rm -rf build",
        "echo $((1 << $((1 << $((1<<1)))))); rm -rf build",
        "echo $((1 <<\n 2)); rm -rf build",
        "echo $(printf '%s' $((1<<2))); rm -rf build",
        "echo $((1 << $(printf '%s' 2))); rm -rf build",
    ];
    for fallback in [true, false] {
        for mode in ["log", "warn", "ask", "deny"] {
            let fixture = arithmetic_fixture(fallback, Some(mode));
            for candidate in candidates {
                let json = arithmetic_explain(&fixture, candidate);
                assert_eq!(json["outcome"], mode, "{candidate:?}: {json}");
                assert_eq!(json["mode"], mode, "{candidate:?}: {json}");
                assert_eq!(json["match"]["rule_id"], RM_RULE, "{candidate:?}: {json}");
            }
        }
    }
    // With no policy override, adding arithmetic cannot disarm the default deny.
    let fixture = arithmetic_fixture(true, None);
    let json = arithmetic_explain(&fixture, ARITHMETIC_COMPOUND);
    assert_eq!(json["outcome"], "deny", "{json}");
    assert_eq!(json["match"]["rule_id"], RM_RULE, "{json}");
}

#[test]
fn issue_649_arithmetic_and_quoted_shift_data_have_no_heredoc_failure() {
    for fallback in [true, false] {
        let fixture = arithmetic_fixture(fallback, Some("log"));
        for candidate in [
            "echo $((1<<2))",
            "echo \"$((1 << 2))\"",
            "echo $((value <<= 2))",
            "echo $((1 << (2 + (3 >> 1))))",
            "echo $((1 << $((1+1))))",
            "echo $((1 << $((1<<1))))",
            "echo $((1 << $((1 << $((1<<1))))))",
            "echo $((1 <<\n 2))",
            "echo $(printf '%s' $((1<<2)))",
            "echo $((1 << $(printf '%s' 2)))",
            "echo '$((1<<2))'",
            "printf '%s' 'example: <<EOF'",
        ] {
            let json = arithmetic_explain(&fixture, candidate);
            assert_eq!(json["outcome"], "allow", "{candidate:?}: {json}");
            assert!(json["match"].is_null(), "{candidate:?}: {json}");
            assert!(json["mode"].is_null(), "{candidate:?}: {json}");
        }
    }
}

#[test]
fn issue_649_real_heredocs_after_arithmetic_keep_their_language_rules() {
    let fixture = arithmetic_fixture(true, Some("log"));
    for delimiter in ["PY", "'PY'", "\"PY\"", "P'Y'", "\\PY"] {
        let candidate = format!(
            "echo $((1<<2)); python3 - <<{delimiter}\nimport shutil\nshutil.rmtree('/home/user')\nPY"
        );
        let json = arithmetic_explain(&fixture, &candidate);
        assert_eq!(json["outcome"], "deny", "{candidate:?}: {json}");
        assert_eq!(
            json["match"]["rule_id"], "heredoc.python:shutil_rmtree",
            "{candidate:?}: {json}"
        );
    }
    for candidate in [
        "echo $((1<<2)); python3 - <<-'PY'\n\timport shutil\n\tshutil.rmtree('/home/user')\n\tPY",
        "echo $((1 << $(python3 - <<'PY'\nimport shutil\nshutil.rmtree('/home/user')\nPY\n)))",
    ] {
        let json = arithmetic_explain(&fixture, candidate);
        assert_eq!(json["outcome"], "deny", "{candidate:?}: {json}");
        assert_eq!(
            json["match"]["rule_id"], "heredoc.python:shutil_rmtree",
            "{candidate:?}: {json}"
        );
    }
    // A literal data receiver still must not execute the same words.
    let json = arithmetic_explain(
        &fixture,
        "echo $((1<<2)); cat <<'EOF'\nrm -rf build\necho $((1<<2))\nEOF",
    );
    assert_eq!(json["outcome"], "allow", "{json}");
}

#[test]
fn issue_649_arithmetic_cannot_hide_nested_or_inline_execution() {
    let fixture = arithmetic_fixture(true, None);
    for candidate in [
        "echo $((1 << $(rm -rf build)))",
        "echo $((1 << `rm -rf build`))",
        "echo $((1<<2)) && bash -c 'rm -rf build'",
        "echo $((1<<2)); bash <<'SH'\nrm -rf build\nSH",
    ] {
        let json = arithmetic_explain(&fixture, candidate);
        assert_eq!(json["outcome"], "deny", "{candidate:?}: {json}");
    }
    // #648 is the reason disabling the entire embedded-code scanner is not
    // a remedy for the arithmetic false positive.
    for candidate in [
        "perl -e \"unlink '/etc/passwd'\"",
        "echo $((1<<2)); perl -e \"unlink '/etc/passwd'\"",
    ] {
        let json = arithmetic_explain(&fixture, candidate);
        assert_eq!(json["outcome"], "deny", "{candidate:?}: {json}");
        assert_eq!(
            json["match"]["rule_id"], "heredoc.perl:unlink.catastrophic",
            "{candidate:?}: {json}"
        );
    }
    // This is a grouped command in PowerShell even though the Bash grammar
    // accepts arithmetic-looking syntax. Only shift operator bytes may be
    // suppressed in the alternate view, never an entire `$((...))` region.
    for dialect in ["unknown", "ps"] {
        let json = arithmetic_explain_in_dialect(
            &fixture,
            "Write-Output $((git reset --hard))",
            Some(dialect),
        );
        assert_eq!(json["outcome"], "deny", "{dialect}: {json}");
        assert_eq!(json["match"]["rule_id"], "core.git:reset-hard", "{json}");
    }
}

#[test]
fn issue_649_ambiguous_parentheses_preserve_real_heredocs() {
    let fixture = arithmetic_fixture(true, Some("log"));
    // The first is Bash command substitution containing a subshell despite
    // its `$((` prefix. Dash interprets the second as nested subshells.
    // Neither prefix alone proves that the `<<` operator is arithmetic.
    for candidate in [
        "echo $((python3 <<'PY')\nimport shutil\nshutil.rmtree('/home/user')\nPY\n)",
        "((python3<<'PY'))\nimport shutil\nshutil.rmtree('/home/user')\nPY",
    ] {
        let json = arithmetic_explain(&fixture, candidate);
        assert_eq!(json["outcome"], "deny", "{candidate:?}: {json}");
    }
}

#[test]
fn issue_649_unknown_secondary_scan_preserves_executable_substitutions() {
    let fixture = arithmetic_fixture(false, Some("log"));
    {
        let mut config = std::fs::OpenOptions::new()
            .append(true)
            .open(&fixture.config)
            .expect("open config for Windows pack");
        writeln!(config, "\n[packs]\nenabled = [\"windows.filesystem\"]")
            .expect("enable Windows filesystem pack");
    }

    for dialect in ["unknown", "posix"] {
        for candidate in [
            "echo $(printf '%s' $((1<<2)))",
            "echo $((1 << $(printf '%s' $((1<<1)))))",
        ] {
            let json = arithmetic_explain_in_dialect(&fixture, candidate, Some(dialect));
            assert_eq!(json["outcome"], "allow", "{dialect}: {candidate:?}: {json}");
            let compound = format!("{candidate} && rm -rf build");
            let json = arithmetic_explain_in_dialect(&fixture, &compound, Some(dialect));
            assert_eq!(json["outcome"], "log", "{dialect}: {compound:?}: {json}");
            assert_eq!(json["mode"], "log", "{dialect}: {compound:?}: {json}");
            assert_eq!(json["match"]["rule_id"], RM_RULE, "{json}");
        }
    }

    // Explicit PowerShell keeps its own scanner; Unknown must preserve the
    // same executable substitutions while distinguishing POSIX arithmetic.
    for dialect in ["unknown", "ps"] {
        for candidate in [
            "Write-Output $(Clear-Content ./important.txt)",
            "Write-Output $(Write-Output $(Clear-Content ./important.txt))",
        ] {
            let json = arithmetic_explain_in_dialect(&fixture, candidate, Some(dialect));
            assert_eq!(json["outcome"], "deny", "{dialect}: {candidate:?}: {json}");
            assert_eq!(
                json["match"]["rule_id"], "windows.filesystem:clear-content",
                "{dialect}: {candidate:?}: {json}"
            );
        }
    }
    for candidate in [
        "echo $((1<<2)); Write-Output $(Clear-Content ./important.txt)",
        "echo $((1 << $(Clear-Content ./important.txt)))",
        "echo $((1 << $((1 << $(Clear-Content ./important.txt)))))",
    ] {
        let json = arithmetic_explain(&fixture, candidate);
        assert_eq!(json["outcome"], "deny", "{candidate:?}: {json}");
        assert_eq!(
            json["match"]["rule_id"], "windows.filesystem:clear-content",
            "{candidate:?}: {json}"
        );
    }
}

#[test]
fn issue_649_actual_unterminated_heredocs_keep_the_strict_diagnostic() {
    let fixture = arithmetic_fixture(false, Some("log"));
    for (candidate, exact_delimiter_in_unknown) in [
        ("cat <<'EOF'\nordinary data", true),
        ("echo $((1<<2)); cat <<'EOF'\nordinary data", false),
    ] {
        for dialect in ["unknown", "posix"] {
            let json = arithmetic_explain_in_dialect(&fixture, candidate, Some(dialect));
            assert_eq!(json["outcome"], "deny", "{dialect}: {candidate:?}: {json}");
            let reason = json["match"]["reason"].as_str().expect("diagnostic reason");
            assert!(reason.contains("fallback_on_parse_error=false"), "{json}");
            // A malformed whole parse cannot prove arithmetic exemptions.
            // Unknown may retain its conservative secondary-substitution
            // attribution; POSIX must report the actual missing delimiter.
            if dialect == "posix" || exact_delimiter_in_unknown {
                assert!(
                    reason.contains("unterminated heredoc: delimiter 'EOF' not found"),
                    "{dialect}: {candidate:?}: {json}"
                );
            }
        }
    }
}

#[test]
fn issue_649_reported_command_agrees_across_cli_and_hook_surfaces() {
    for (mode, expected_decision, result_line) in [
        ("log", "allow", "Result: LOG (policy allows)"),
        ("warn", "allow", "Result: WARN (policy allows)"),
        ("deny", "deny", "Result: BLOCKED"),
    ] {
        let fixture = arithmetic_fixture(true, Some(mode));
        let json = arithmetic_explain(&fixture, ARITHMETIC_COMPOUND);
        assert_eq!(json["outcome"], mode, "{json}");
        assert_eq!(json["match"]["rule_id"], RM_RULE, "{json}");

        let output = arithmetic_command(&fixture, &["test", ARITHMETIC_COMPOUND])
            .output()
            .expect("run dcg test arithmetic");
        let text = String::from_utf8_lossy(&output.stdout).to_string()
            + &String::from_utf8_lossy(&output.stderr);
        assert!(text.contains(result_line), "{mode}: {text}");

        let batch = arithmetic_hook(&fixture, &["hook", "--batch"], ARITHMETIC_COMPOUND);
        let batch_json: serde_json::Value = serde_json::from_slice(&batch.stdout)
            .unwrap_or_else(|error| panic!("batch JSON ({error}): {batch:?}"));
        assert_eq!(batch_json["decision"], expected_decision, "{batch_json}");
        assert_eq!(batch_json["mode"], mode, "{batch_json}");
        assert_eq!(batch_json["rule_id"], RM_RULE, "{batch_json}");

        let hook = arithmetic_hook(&fixture, &[], ARITHMETIC_COMPOUND);
        assert!(hook.status.success(), "{mode}: {hook:?}");
        if expected_decision == "deny" {
            let hook_json: serde_json::Value = serde_json::from_slice(&hook.stdout)
                .unwrap_or_else(|error| panic!("hook JSON ({error}): {hook:?}"));
            assert_eq!(
                hook_json["hookSpecificOutput"]["permissionDecision"], "deny",
                "{hook_json}"
            );
        } else {
            assert!(hook.stdout.is_empty(), "{mode}: {hook:?}");
        }
    }
}
