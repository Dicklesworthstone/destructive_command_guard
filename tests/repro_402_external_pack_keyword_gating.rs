//! Repro for issue #402: an external pack with no `keywords` was listed as
//! enabled, validated clean, and was silently never evaluated — including on
//! the hook path, which is the surface that enforces.
//!
//! `Pack::might_match` documents the contract ("no keywords = always check
//! patterns"), but the *global* quick reject runs before it and is built from
//! the union of every enabled pack's keywords, to which such a pack
//! contributes nothing. Its coverage therefore depended on whether some other
//! pack's keyword happened to appear in the command line — a property no
//! operator would predict from the configuration.
//!
//! The reporter's other two findings are the same defect seen from the
//! outside: `dcg config` listed the *requested* pack set rather than the set
//! that evaluates, so a pack reached only through `packs.custom_paths` was
//! missing and a pack whose YAML failed to parse was present.
//!
//! Runs the real binary, since the report did.

#![cfg(unix)]

use std::fmt::Write as _;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

/// The reporter's pack: one rule on a literal string that occurs nowhere else,
/// and no `keywords` field at all.
const KEYWORDLESS_PACK: &str = r"schema_version: 1
id: repro.zz
name: Repro Pack
version: 1.0.0
description: No keywords field.
destructive_patterns:
  - name: zebra-rule
    pattern: ZEBRAQUUX\s+alpha
    severity: critical
    description: fires on a literal string that occurs nowhere else
";

const KEYWORDED_PACK: &str = r"schema_version: 1
id: repro.kw
name: Repro Pack With Keywords
version: 1.0.0
description: Identical, but with a keywords list.
keywords:
  - ZEBRAQUUX
destructive_patterns:
  - name: zebra-rule-kw
    pattern: ZEBRAQUUX\s+delta
    severity: critical
    description: fires on a literal string that occurs nowhere else
";

/// Missing the required `name` field, so it cannot load.
const INVALID_PACK: &str = r"schema_version: 1
id: repro.bad
version: 1.0.0
description: Deliberately missing the required 'name' field.
keywords:
  - ZEBRAQUUX
destructive_patterns:
  - name: zebra-rule-2
    pattern: ZEBRAQUUX\s+beta
    severity: critical
    description: never fires
";

/// The exact expensive rule supplied in #643. The submitted command was not
/// supplied, so the regression constructs the documented shape: scratch,
/// a matching binding, and no IFS assignment. None of this input is executed.
const SLOW_LOOKAHEAD_PACK: &str = r"id: test.slow_lookahead
name: slow lookahead
version: 1.0.0
description: repro
keywords: [scratch]
destructive_patterns:
  - name: slow
    pattern: (?=[\s\S]*(?:^|[\n;&|]\s*)[A-Z]=/data/tmp/x/)(?=[\s\S]*(?:^|[\s;|&])\s*\bIFS\+?=)[\s\S]*
    severity: high
    description: repro
";

const LIMITED_BACKREFERENCE_PACK: &str = r"schema_version: 1
id: repro.limited
name: Bounded regex regression
version: 1.0.0
destructive_patterns:
  - name: backtracking-rule
    pattern: '^(a|aa)+\1$'
    severity: critical
    description: Deliberately exercises the bounded backtracking engine
";

fn assert_regex_provenance(reason: &str, pack: &str, pattern: &str, operation: &str) {
    assert!(reason.contains(pack), "missing pack: {reason}");
    assert!(reason.contains(pattern), "missing pattern: {reason}");
    assert!(reason.contains(operation), "missing operation: {reason}");
    assert!(
        reason.contains("backtracking"),
        "missing budget kind: {reason}"
    );
    assert!(
        reason.contains("100000"),
        "missing enforced step limit: {reason}"
    );
    assert!(reason.contains("steps"), "missing limit units: {reason}");
    assert!(
        !reason.contains("within 5900ms"),
        "wrong clock blamed: {reason}"
    );
    assert!(
        !reason.contains("hook_timeout_ms"),
        "wrong remedy: {reason}"
    );
    assert!(
        !reason.contains("50 ms") && !reason.contains("50ms"),
        "invented regex timeout: {reason}"
    );
}

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

#[test]
fn issue_643_reported_lookahead_keeps_matches_and_completed_nonmatches() {
    let fixture = Fixture::new();
    let pack_path = fixture.root.join("packs/slow.yaml");
    fs::write(&pack_path, SLOW_LOOKAHEAD_PACK).expect("write reporter's rule");
    let config = fixture.config(
        "slow.toml",
        &format!(
            "[packs]\ncustom_paths = [{}]\n",
            serde_json::to_string(&pack_path).unwrap()
        ),
    );
    let command = format!(
        "scratch COMMAND_SECRET_CANARY_643 {};A=/data/tmp/x/repro",
        "q".repeat(4_096)
    );
    let input =
        serde_json::json!({"tool_name": "Bash", "tool_input": {"command": command}}).to_string();
    for decision in ["ask", "deny"] {
        let output = fixture.isolated_run(
            &config,
            &["--agent", "claude-code"],
            input.as_bytes(),
            &[
                ("DCG_UNVERIFIED_DECISION", decision),
                ("DCG_LOG", "dcg_perf=debug"),
            ],
        );
        // fancy-regex 0.20 delegates these lookahead bodies. This generated
        // input completes at the production limit; it is not the reporter's
        // missing original command. The engine regression separately checks
        // this exact pattern's exhaustion at an explicit smaller work limit.
        assert!(
            output.status.success() && output.stdout.is_empty(),
            "a completed nonmatch stays allowed under either unverified policy: {output:?}"
        );
        let diagnostics = String::from_utf8_lossy(&output.stderr);
        for private in [
            "COMMAND_SECRET_CANARY_643",
            "/data/tmp/x/",
            "(?=[\\s\\S]*",
            fixture.root.to_str().unwrap(),
        ] {
            assert!(
                !diagnostics.contains(private),
                "failure provenance disclosed input, pattern, or path"
            );
        }
    }
    let tested = fixture.isolated_run(
        &config,
        &["test", "--stdin", "--dialect", "posix", "--format", "json"],
        command.as_bytes(),
        &[],
    );
    assert!(tested.status.success());
    let wire: serde_json::Value = serde_json::from_slice(&tested.stdout).unwrap();
    assert_eq!(wire["decision"], "allow");
    assert!(wire.get("rule_id").is_none() && wire.get("reason").is_none());

    let matching = "A=/data/tmp/x/repro;IFS=,;scratch";
    let matched_input =
        serde_json::json!({"tool_name": "Bash", "tool_input": {"command": matching}}).to_string();
    let matched = fixture.isolated_run(
        &config,
        &["--agent", "claude-code"],
        matched_input.as_bytes(),
        &[],
    );
    let wire: serde_json::Value = serde_json::from_slice(&matched.stdout).expect("ordinary match");
    assert_eq!(wire["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        wire["hookSpecificOutput"]["ruleId"],
        "test.slow_lookahead:slow"
    );

    // Anchoring removes repeated searches at every start offset. It changes
    // neither the evaluator's budget nor the treatment of incomplete work.
    let anchored = SLOW_LOOKAHEAD_PACK.replacen("pattern: (?=", r"pattern: \A(?=", 1);
    fs::write(&pack_path, anchored).expect("anchor the custom rule");
    let repaired =
        fixture.isolated_run(&config, &["--agent", "claude-code"], input.as_bytes(), &[]);
    assert!(
        repaired.status.success() && repaired.stdout.is_empty(),
        "anchored nonmatch must complete: {repaired:?}"
    );
    let matched = fixture.isolated_run(
        &config,
        &["--agent", "claude-code"],
        matched_input.as_bytes(),
        &[],
    );
    let wire: serde_json::Value = serde_json::from_slice(&matched.stdout).expect("anchored match");
    assert_eq!(
        wire["hookSpecificOutput"]["ruleId"],
        "test.slow_lookahead:slow"
    );
}

#[test]
fn issue_643_cli_reports_work_exhaustion_and_separate_config_limits() {
    let fixture = Fixture::new();
    let pack_path = fixture.root.join("packs/limited.yaml");
    fs::write(&pack_path, LIMITED_BACKREFERENCE_PACK).unwrap();
    let config = fixture.config(
        "slow-cli.toml",
        &format!(
            "[packs]\ncustom_paths = [{}]\n",
            serde_json::to_string(&pack_path).unwrap()
        ),
    );
    let command = format!("{}!", "a".repeat(80));
    let output = fixture.isolated_run(
        &config,
        &["test", "--stdin", "--dialect", "posix", "--format", "json"],
        command.as_bytes(),
        &[],
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "incomplete CLI evaluation must block"
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("test JSON");
    assert_eq!(json["decision"], "indeterminate");
    assert_regex_provenance(
        json["reason"].as_str().unwrap(),
        "repro.limited",
        "backtracking-rule",
        "find_from",
    );
    assert!(json.get("rule_id").is_none() && json.get("pack_id").is_none());

    let output = fixture.isolated_run(&config, &["config", "--format", "json"], b"", &[]);
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("config JSON");
    assert_eq!(json["heredoc"]["timeout_ms"], 50);
    assert_eq!(json["regex"]["backtrack_limit_steps"], 100_000);
    let output = fixture.isolated_run(&config, &["config"], b"", &[]);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Extraction timeout (ms): 50"), "{text}");
    assert!(
        text.contains("Backtracking limit (steps per operation): 100000"),
        "{text}"
    );
}

#[test]
fn regex_work_limit_cannot_silently_allow_a_hook_command() {
    let fixture = Fixture::new();
    let pack_path = fixture.root.join("packs/limited.yaml");
    fs::write(&pack_path, LIMITED_BACKREFERENCE_PACK).expect("write bounded regex pack");
    let config = fixture.config(
        "limited.toml",
        &format!(
            "[packs]\nenabled = [\"repro.limited\"]\ncustom_paths = [{}]\n",
            serde_json::to_string(&pack_path).expect("pack path")
        ),
    );
    let run = |command: &str, strict: bool| {
        let payload = serde_json::json!({"tool_name": "Bash",
            "tool_input": {"command": command}})
        .to_string();
        let mut builder = Command::new(dcg_binary());
        // Every probe is hermetic: an inherited bypass or policy override
        // must not turn an incomplete match into a successful control.
        builder
            .env_clear()
            .args(["--agent", "claude-code"])
            .env("HOME", &fixture.root)
            .env("USERPROFILE", &fixture.root)
            .env("XDG_CONFIG_HOME", fixture.root.join("config"))
            .env("DCG_CONFIG", &config)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("DCG_HISTORY_DISABLED", "1")
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("DCG_LOG", "dcg_perf=debug")
            .env(
                "DCG_PENDING_EXCEPTIONS_PATH",
                fixture.root.join("pending.jsonl"),
            )
            .current_dir(&fixture.root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if strict {
            builder.env("DCG_UNVERIFIED_DECISION", "deny");
        }
        let mut child = builder.spawn().expect("spawn bounded regex probe");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(payload.as_bytes())
            .expect("payload");
        child.wait_with_output().expect("bounded regex response")
    };
    let expensive = format!("{}!", "a".repeat(80));
    for (strict, expected) in [(false, "ask"), (true, "deny")] {
        let result = run(&expensive, strict);
        assert!(result.status.success());
        let json: serde_json::Value = serde_json::from_slice(&result.stdout)
            .expect("regex work exhaustion must produce an explicit verdict");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"],
            expected,
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_regex_provenance(
            json["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap(),
            "repro.limited",
            "backtracking-rule",
            "find_from",
        );
        let diagnostics = format!(
            "{}\n{}",
            json["hookSpecificOutput"]["permissionDecisionReason"],
            String::from_utf8_lossy(&result.stderr)
        );
        for private in [
            expensive.as_str(),
            r"^(a|aa)+\1$",
            fixture.root.to_str().unwrap(),
        ] {
            assert!(
                !diagnostics.contains(private),
                "incomplete-analysis diagnostics disclosed input, pattern, or path"
            );
        }
    }
    let ordinary = run("b", false);
    for nested in [
        format!("sh -c '{expensive}'"),
        format!("echo $({expensive})"),
        format!("bash <<'EOF'\n{expensive}\nEOF"),
        format!("python3 -c \"import os; os.system('{expensive}')\""),
    ] {
        let result = run(&nested, false);
        let json: serde_json::Value = serde_json::from_slice(&result.stdout)
            .expect("nested incomplete evaluation must not silently allow");
        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "ask");
        assert_regex_provenance(
            json["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap(),
            "repro.limited",
            "backtracking-rule",
            "find_from",
        );
    }
    assert!(ordinary.status.success() && ordinary.stdout.is_empty());
    for data in [
        format!("echo '{expensive}'"),
        format!("cat <<'EOF'\n{expensive}\nEOF"),
    ] {
        let result = run(&data, false);
        assert!(
            result.status.success() && result.stdout.is_empty(),
            "literal data must remain inert: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let matching = run("aaaa", false);
    let json: serde_json::Value = serde_json::from_slice(&matching.stdout).expect("real match");
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        json["hookSpecificOutput"]["ruleId"],
        "repro.limited:backtracking-rule"
    );
    let nested_match = run("sh -c 'aaaa'", false);
    let json: serde_json::Value = serde_json::from_slice(&nested_match.stdout)
        .expect("keyword-less rules must also inspect executed shell bodies");
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        json["hookSpecificOutput"]["ruleId"],
        "repro.limited:backtracking-rule"
    );

    // A later proven rule still wins over an earlier incomplete rule.
    let mut pack = fs::read_to_string(&pack_path).expect("read pack");
    pack.push_str("  - name: literal-deny\n    pattern: 'a!'\n    severity: critical\n    description: Positive literal evidence\n");
    fs::write(&pack_path, &pack).expect("add proven denial");
    let result = run(&expensive, false);
    let json: serde_json::Value = serde_json::from_slice(&result.stdout).expect("proven deny");
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        json["hookSpecificOutput"]["ruleId"],
        "repro.limited:literal-deny"
    );
    assert_regex_provenance(
        json["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap(),
        "repro.limited",
        "backtracking-rule",
        "find_from",
    );

    // A proven warning cannot hide a different rule's incomplete analysis.
    let pack = pack.replace(
        "name: literal-deny\n    pattern: 'a!'\n    severity: critical",
        "name: literal-deny\n    pattern: 'a!'\n    severity: medium",
    );
    fs::write(&pack_path, pack).expect("make literal finding non-blocking");
    for (strict, expected) in [(false, "ask"), (true, "deny")] {
        let result = run(&expensive, strict);
        let json: serde_json::Value = serde_json::from_slice(&result.stdout)
            .expect("incomplete warning needs explicit review");
        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], expected);
        assert_regex_provenance(
            json["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap(),
            "repro.limited",
            "backtracking-rule",
            "find_from",
        );
    }
}

#[test]
fn issue_643_batch_rule_provenance_does_not_leak_between_commands_or_packs() {
    let fixture = Fixture::new();
    let mut paths = Vec::new();
    for (id, letter) in [("first", 'a'), ("second", 'b')] {
        let path = fixture.root.join(format!("packs/{id}.yaml"));
        fs::write(
            &path,
            format!(
                r"id: test.{id}
name: {id}
version: 1.0.0
destructive_patterns:
  - name: bounded-{id}
    pattern: '^({letter}|{letter}{letter})+\1$'
    severity: critical
    description: bounded test rule
"
            ),
        )
        .unwrap();
        paths.push(path);
    }
    let config = fixture.config(
        "batch-limits.toml",
        &format!(
            "[packs]\ncustom_paths = {}\n",
            serde_json::to_string(&paths).unwrap()
        ),
    );
    let first = format!("{}!", "a".repeat(80));
    let second = format!("{}!", "b".repeat(80));
    let nested = format!("sh -c '{first}'");
    let commands = [
        first.as_str(),
        "c",
        second.as_str(),
        "c",
        nested.as_str(),
        "c",
    ];
    let mut input = String::new();
    for command in &commands {
        writeln!(
            input,
            "{}",
            serde_json::json!({"tool_name": "Bash", "tool_input": {"command": command}})
        )
        .expect("format batch payload");
    }
    let output = fixture.isolated_run(&config, &["hook", "--batch"], input.as_bytes(), &[]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "batch with incomplete work must block"
    );
    let rows: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).expect("batch row"))
        .collect();
    assert_eq!(rows.len(), commands.len());
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(row["index"], index);
        if index % 2 == 1 {
            assert_eq!(row["decision"], "allow");
            assert!(
                row.get("error").is_none(),
                "clean evaluation inherited a failure: {row}"
            );
        } else {
            assert_eq!(row["decision"], "indeterminate");
            let (pack, pattern, other) = if index == 2 {
                ("test.second", "bounded-second", "test.first")
            } else {
                ("test.first", "bounded-first", "test.second")
            };
            let error = row["error"].as_str().unwrap();
            assert_regex_provenance(error, pack, pattern, "find_from");
            assert!(
                !error.contains(other),
                "failure attributed to another pack: {error}"
            );
            assert!(row.get("rule_id").is_none() && row.get("pack_id").is_none());
        }
    }
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().to_path_buf();
        fs::create_dir_all(root.join("packs")).expect("packs dir");
        fs::write(root.join("packs/zz.yaml"), KEYWORDLESS_PACK).expect("write zz");
        fs::write(root.join("packs/kw.yaml"), KEYWORDED_PACK).expect("write kw");
        fs::write(root.join("packs/bad.yaml"), INVALID_PACK).expect("write bad");
        Self { _dir: dir, root }
    }

    fn config(&self, name: &str, body: &str) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, body).expect("write config");
        path
    }

    fn pack(&self, name: &str) -> String {
        self.root
            .join("packs")
            .join(name)
            .to_string_lossy()
            .into_owned()
    }

    fn isolated_run(
        &self,
        config: &Path,
        args: &[&str],
        input: &[u8],
        extra_env: &[(&str, &str)],
    ) -> Output {
        let mut child = Command::new(dcg_binary())
            .env_clear()
            .args(args)
            .env("HOME", &self.root)
            .env("USERPROFILE", &self.root)
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("XDG_DATA_HOME", self.root.join("data"))
            .env("XDG_STATE_HOME", self.root.join("state"))
            .env("XDG_CACHE_HOME", self.root.join("cache"))
            .env("DCG_CONFIG", config)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("DCG_HISTORY_DISABLED", "1")
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("DCG_HOOK_TIMEOUT_MS", "5900")
            .env(
                "DCG_PENDING_EXCEPTIONS_PATH",
                self.root.join("pending.jsonl"),
            )
            .envs(extra_env.iter().copied())
            .current_dir(&self.root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn isolated regex probe");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input)
            .expect("input");
        child.wait_with_output().expect("regex probe result")
    }

    fn run(&self, config: &Path, args: &[&str]) -> String {
        let output = Command::new(dcg_binary())
            .args(args)
            .env("HOME", &self.root)
            .env("XDG_CONFIG_HOME", self.root.join("xdg_config"))
            .env("DCG_CONFIG", config)
            .env(
                "DCG_PENDING_EXCEPTIONS_PATH",
                self.root.join("pending_exceptions.jsonl"),
            )
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("NO_COLOR", "1")
            .current_dir(&self.root)
            .output()
            .expect("run dcg");
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// The enforcing surface: the hook protocol.
    fn hook_denies(&self, config: &Path, command: &str) -> bool {
        let payload = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": command },
            "cwd": self.root.to_string_lossy(),
        })
        .to_string();
        let mut child = Command::new(dcg_binary())
            .arg("hook")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("HOME", &self.root)
            .env("XDG_CONFIG_HOME", self.root.join("xdg_config"))
            .env("DCG_CONFIG", config)
            .env(
                "DCG_PENDING_EXCEPTIONS_PATH",
                self.root.join("pending_exceptions.jsonl"),
            )
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("DCG_HOOK_TIMEOUT_MS", "10000")
            .current_dir(&self.root)
            .spawn()
            .expect("spawn dcg");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(payload.as_bytes())
            .expect("write payload");
        let output = child.wait_with_output().expect("wait for dcg");
        // Plain `dcg hook` is the explicit spelling of bare hook mode (#430), so
        // the verdict rides in the agent protocol's `permissionDecision`. Reading
        // batch mode's `decision` here made every command look allowed, which is
        // the same trap `false_positive_corpus` fell into.
        String::from_utf8_lossy(&output.stdout).contains(r#""permissionDecision":"deny""#)
    }
}

#[test]
fn a_pack_without_keywords_is_evaluated_on_every_command() {
    let fixture = Fixture::new();
    let config = fixture.config(
        "keywordless.toml",
        &format!(
            "[packs]\nenabled = [\"repro.zz\"]\ncustom_paths = [\"{}\"]\n",
            fixture.pack("zz.yaml")
        ),
    );

    // The reporter's exact command, on the path that enforces.
    assert!(
        fixture.hook_denies(&config, "ZEBRAQUUX alpha"),
        "a keyword-less pack must still be evaluated by the hook"
    );
    let test = fixture.run(&config, &["test", "ZEBRAQUUX alpha"]);
    assert!(test.contains("BLOCKED"), "dcg test disagreed: {test}");

    // `dcg explain` used to name the cause here: "quick-rejected (no
    // keywords)". It must now report a real evaluation.
    let explain = fixture.run(&config, &["explain", "ZEBRAQUUX alpha"]);
    assert!(
        !explain.contains("quick-rejected"),
        "the pack must not be quick-rejected: {explain}"
    );

    // Coverage no longer depends on the rest of the command line: the pack's
    // rule fires with or without an unrelated built-in keyword present, and
    // a command the rule does not describe is still allowed.
    assert!(fixture.hook_denies(&config, "rm ZEBRAQUUX alpha"));
    assert!(!fixture.hook_denies(&config, "ls -la"));
    assert!(!fixture.hook_denies(&config, "ZEBRAQUUX beta"));
}

#[test]
fn pack_validate_reports_the_runtime_cost_of_omitting_keywords() {
    let fixture = Fixture::new();
    let config = fixture.config("empty.toml", "");
    let output = fixture.run(&config, &["pack", "validate", &fixture.pack("zz.yaml")]);
    assert!(
        output.contains("S001"),
        "S001 must still be reported: {output}"
    );
    assert!(
        output.contains("quick-reject"),
        "S001 must state the runtime consequence: {output}"
    );
    // It is a warning now, not a performance "suggestion": the pack is valid,
    // but the operator is told what it costs.
    let warnings_index = output.find("Warnings:");
    let s001_index = output.find("S001");
    assert!(
        warnings_index.is_some() && warnings_index < s001_index,
        "S001 must be listed under Warnings: {output}"
    );
}

#[test]
fn config_listing_matches_the_packs_that_evaluate() {
    let fixture = Fixture::new();

    // Finding 2: only `custom_paths`, no `enabled` line. The pack evaluates,
    // so it must appear.
    let config = fixture.config(
        "custom-only.toml",
        &format!(
            "[packs]\ncustom_paths = [\"{}\"]\n",
            fixture.pack("kw.yaml")
        ),
    );
    let listing = fixture.run(&config, &["config"]);
    assert!(
        listing.contains("repro.kw"),
        "an evaluating pack must be listed: {listing}"
    );
    let blocked = fixture.run(&config, &["test", "ZEBRAQUUX delta"]);
    assert!(blocked.contains("BLOCKED"), "pack must fire: {blocked}");

    // Finding 3: a pack that cannot load must not be presented as coverage.
    let config = fixture.config(
        "invalid.toml",
        &format!(
            "[packs]\nenabled = [\"repro.bad\"]\ncustom_paths = [\"{}\"]\n",
            fixture.pack("bad.yaml")
        ),
    );
    let listing = fixture.run(&config, &["config"]);
    assert!(
        listing.contains("repro.bad (configured but NOT loaded"),
        "an unloadable pack must be marked, not silently listed: {listing}"
    );
    assert!(
        listing.contains("Pack load warnings:"),
        "the load failure must be surfaced: {listing}"
    );

    // Doctor agrees, and says why.
    let doctor = fixture.run(&config, &["doctor"]);
    assert!(
        doctor.contains("Failed to load external pack"),
        "doctor must report the load failure: {doctor}"
    );
}

#[test]
fn doctor_notes_a_keywordless_pack() {
    let fixture = Fixture::new();
    let config = fixture.config(
        "keywordless.toml",
        &format!(
            "[packs]\nenabled = [\"repro.zz\"]\ncustom_paths = [\"{}\"]\n",
            fixture.pack("zz.yaml")
        ),
    );
    let doctor = fixture.run(&config, &["doctor"]);
    assert!(
        doctor.contains("repro.zz") && doctor.contains("declares no keywords"),
        "doctor must surface the always-evaluated pack: {doctor}"
    );
}
