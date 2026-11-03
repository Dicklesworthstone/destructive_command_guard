//! bd-executable-assignment-scope: a destructive command spelled through a
//! shell variable that holds its executable (`d=git; $d reset --hard`) must
//! be denied under the rule the plain spelling gets, even when the binding
//! shares its statement with other assignments or neutral commands come
//! before or after it.
//!
//! The bead recorded that, at e0554cd0, decision-only evaluations denied
//! `d=git; $d reset --hard` but allowed the spellings in
//! `BOUND_THROUGH_NEUTRAL_STRUCTURE`. At 290d783a POSIX denied them only
//! because Git's own dynamic-executable handling caught `$d reset --hard`
//! with no binding at all; the `unknown` dialect (Gemini, Cursor, Copilot,
//! OpenCode) allowed them, and every dialect allowed the same shapes for
//! `mkfs`, `dd` and `wipefs`, which have no such handling. The model now
//! steps past neutral commands, multi-assignment statements and pure `&&`
//! chains, resolving what follows deny-only: a denial from the resolved
//! command stands, but the source is not masked, so this can only add
//! denials. The benign controls make sure the binding is resolved rather
//! than every `$d` being denied.
//!
//! Scope (No-Claim): straight-line POSIX prefixes only. A binding that a
//! subshell, `unset` or an environment-only prefix would hide still denies
//! (conservative); these tests do not pin that over-block either way.
//!
//! bd-substitution-supplied-flags-1n9a extends that proof to ordinary argument
//! positions: a known scalar flag produced by `echo`, `printf`, or a literal
//! binding must reach the same rules as its plain spelling. Source strings
//! are classifier input only; none of their commands are executed.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, EvaluationResult, LayeredAllowlist};

fn evaluate(command: &str, dialect: ShellDialect) -> EvaluationResult {
    evaluate_with_config(command, dialect, &Config::default())
}

fn evaluate_with_config(command: &str, dialect: ShellDialect, config: &Config) -> EvaluationResult {
    let enabled_packs = config.enabled_pack_ids();
    let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    let keyword_index = REGISTRY
        .build_enabled_keyword_index(&ordered_packs)
        .expect("keyword index should build for enabled pack set");
    let compiled_overrides = config.overrides.compile();
    let allowlists = LayeredAllowlist::default();
    let heredoc_settings = config.heredoc_settings();
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

fn rule_of(result: &EvaluationResult) -> Option<String> {
    let info = result.pattern_info.as_ref()?;
    Some(format!(
        "{}:{}",
        info.pack_id.as_deref().unwrap_or("?"),
        info.pattern_name.as_deref().unwrap_or("?")
    ))
}

const DIALECTS: [ShellDialect; 2] = [ShellDialect::Posix, ShellDialect::Unknown];

/// The spellings the bead recorded as allowed, plus the same shapes with
/// other separators.
const BOUND_THROUGH_NEUTRAL_STRUCTURE: &[&str] = &[
    "UNREVIEWED=1 d=git; $d reset --hard",
    "d=git x=1; $d reset --hard",
    "true; d=git; $d reset --hard",
    "d=git; true; $d reset --hard",
    "a=1 d=git b=2; $d reset --hard",
    "d=git; echo hi; $d reset --hard",
    "d=git; cd /tmp; $d reset --hard",
    "true && d=git && $d reset --hard",
    "d=git\ntrue\n$d reset --hard",
    "d=git; true; ${d} reset --hard",
];

#[test]
fn the_single_binding_control_denies_under_the_plain_rule() {
    for dialect in DIALECTS {
        let result = evaluate("d=git; $d reset --hard", dialect);
        assert!(result.is_denied(), "{dialect:?}: {result:?}");
        assert_eq!(
            rule_of(&result).as_deref(),
            Some("core.git:reset-hard"),
            "{dialect:?}"
        );
    }
}

#[test]
fn bindings_through_neutral_structure_deny_under_the_plain_rule() {
    for command in BOUND_THROUGH_NEUTRAL_STRUCTURE {
        for dialect in DIALECTS {
            let result = evaluate(command, dialect);
            assert!(
                result.is_denied(),
                "{command:?} must deny under {dialect:?}, got {result:?}"
            );
            assert_eq!(
                rule_of(&result).as_deref(),
                Some("core.git:reset-hard"),
                "{command:?} under {dialect:?}"
            );
        }
    }
}

#[test]
fn a_bound_rm_after_a_neutral_command_denies() {
    for dialect in DIALECTS {
        let result = evaluate("true; r=rm; $r -rf ~/x", dialect);
        assert!(result.is_denied(), "{dialect:?}: {result:?}");
        assert_eq!(
            rule_of(&result).as_deref(),
            Some("core.filesystem:rm-rf-root-home"),
            "{dialect:?}"
        );
    }
}

fn assert_denied_by_pack(command: &str, pack: &str) {
    for dialect in DIALECTS {
        let result = evaluate(command, dialect);
        assert!(
            result.is_denied(),
            "{command:?} must deny under {dialect:?}, got {result:?}"
        );
        let rule = rule_of(&result).unwrap_or_default();
        assert!(
            rule.starts_with(&format!("{pack}:")),
            "{command:?} under {dialect:?} answered {rule}, expected a {pack} rule"
        );
    }
}

/// Only git and rm have dynamic-executable handling of their own, so a
/// neutral command before a disk tool's binding used to end the model and
/// leave `$m /dev/sda1` an unknown program: allowed in every dialect, while
/// the same binding without `true;` denied.
#[test]
fn a_neutral_command_does_not_hide_a_bound_disk_tool() {
    for command in [
        "m=mkfs.ext4; $m /dev/sda1",
        "true; m=mkfs.ext4; $m /dev/sda1",
        "m=mkfs.ext4; echo formatting; $m /dev/sda1",
        "m=mkfs.ext4; cd /tmp; $m /dev/sda1",
        "true; d=dd; $d if=/dev/zero of=/dev/sda bs=1M",
        "true; w=wipefs; $w -a /dev/sda",
        "UNREVIEWED=1 m=mkfs.ext4; $m /dev/sda1",
        "true && m=mkfs.ext4 && $m /dev/sda1",
    ] {
        assert_denied_by_pack(command, "system.disk");
    }
}

/// The unknown dialect stands for every shell, POSIX among them, so a
/// dynamic executable that POSIX reads as Git must be Git here too. These
/// were denied under POSIX and allowed under `unknown`, the dialect of every
/// agent whose shell tool is not named `Bash`.
#[test]
fn the_unknown_dialect_reads_a_dynamic_git_executable_as_posix_does() {
    for (command, rule) in [
        ("$d reset --hard", "core.git:reset-hard"),
        ("$d checkout -- .", "core.git:checkout-discard"),
        ("$d stash clear", "core.git:stash-clear"),
        (
            "cd /repo && d=git && $d reset --hard",
            "core.git:reset-hard",
        ),
    ] {
        for dialect in DIALECTS {
            let result = evaluate(command, dialect);
            assert!(
                result.is_denied(),
                "{command:?} must deny under {dialect:?}, got {result:?}"
            );
            assert_eq!(
                rule_of(&result).as_deref(),
                Some(rule),
                "{command:?} under {dialect:?}"
            );
        }
    }
}

/// A PowerShell assignment whose first token is a variable must not be read
/// as a Git invocation: `-Directory` once supplied the `D` of a forced branch
/// deletion (#401).
#[test]
fn a_powershell_variable_assignment_is_not_synthesized_into_git() {
    for command in [
        r"$items = Get-ChildItem C:\temp -Recurse -Directory",
        "$d status",
        "$tool --version",
    ] {
        let result = evaluate(command, ShellDialect::Unknown);
        assert!(
            result.is_allowed(),
            "{command:?} must stay allowed under Unknown, got {result:?}"
        );
    }
}

/// The binding is resolved, not guessed: a harmless command through the
/// same variable, a later benign rebinding, and the whole text as quoted
/// data stay allowed.
#[test]
fn resolved_bindings_to_harmless_commands_stay_allowed() {
    for command in [
        "d=git; true; $d status",
        "d=git x=1; $d status",
        "true; d=git; $d log --oneline -3",
        "d=git; d=echo; $d reset --hard",
        "echo 'd=git; $d reset --hard'",
        "true; d=dd; $d --version",
        "true; m=mkfs.ext4; echo $m",
        "true; echo hi; ls -la",
    ] {
        for dialect in DIALECTS {
            let result = evaluate(command, dialect);
            assert!(
                result.is_allowed(),
                "{command:?} must stay allowed under {dialect:?}, got {result:?}"
            );
        }
    }
}

const LITERAL_ARGUMENT_DENIALS: &[(&str, &str)] = &[
    ("git reset $(echo --hard)", "git reset --hard"),
    (r#"git reset "$(echo --hard)""#, "git reset --hard"),
    ("git reset `echo --hard`", "git reset --hard"),
    ("git reset $(echo '--hard')", "git reset --hard"),
    ("git reset $(echo --hard) HEAD~1", "git reset --hard HEAD~1"),
    ("git reset $(printf %s --hard)", "git reset --hard"),
    // Only preceding IFS changes affect splitting; quoted words never split.
    ("git reset $(echo --hard); IFS=:", "git reset --hard; IFS=:"),
    (
        r#"git reset "$(echo --hard)"; IFS=:"#,
        "git reset --hard; IFS=:",
    ),
    (
        r#"IFS=-; git reset "$(echo --hard)""#,
        "IFS=-; git reset --hard",
    ),
    // These spellings already denied; extending the proof must preserve them.
    ("git reset $(printf -- --hard)", "git reset --hard"),
    ("git reset --$(echo hard)", "git reset --hard"),
    ("git reset -q $(echo --hard)", "git reset -q --hard"),
    ("git reset HEAD~1 $(echo --h)", "git reset HEAD~1 --h"),
    (
        "git reset $(echo --hard) -- tracked",
        "git reset --hard -- tracked",
    ),
    ("git reset HEAD~1 $(echo --me)", "git reset HEAD~1 --me"),
    (
        "PART=i; g${PART}t reset $(echo --hard)",
        "PART=i; g${PART}t reset --hard",
    ),
    ("git push $(echo --force)", "git push --force"),
    ("git push $(echo -f) origin main", "git push -f origin main"),
    ("git clean $(echo -fdx)", "git clean -fdx"),
    ("rm $(echo -rf) /", "rm -rf /"),
    ("rm $(echo -rf) ~/", "rm -rf ~/"),
    (r#"rm "$(echo -rf)" /"#, "rm -rf /"),
    ("rm $(printf %s -rf) /", "rm -rf /"),
    ("find / $(echo -delete)", "find / -delete"),
    ("find . -name x $(echo -delete)", "find . -name x -delete"),
    ("find / $(printf %s -delete)", "find / -delete"),
    (
        "dd if=/dev/zero $(echo of=/dev/sda)",
        "dd if=/dev/zero of=/dev/sda",
    ),
    (
        "dd if=/dev/zero $(printf %s of=/dev/sda)",
        "dd if=/dev/zero of=/dev/sda",
    ),
    ("git $(echo reset) --hard", "git reset --hard"),
];

const BOUND_ARGUMENT_DENIALS: &[(&str, &str)] = &[
    ("F=--hard; git reset $F", "git reset --hard"),
    ("F=--hard; git reset ${F}", "git reset --hard"),
    (r#"F=--hard; git reset "$F""#, "git reset --hard"),
    (r#"F=--hard; git reset "${F}""#, "git reset --hard"),
    (
        r#"F=--hard; git reset "$F"; IFS=:"#,
        "F=--hard; git reset --hard; IFS=:",
    ),
    (
        r#"IFS=-; F=--hard; git reset "$F""#,
        "IFS=-; F=--hard; git reset --hard",
    ),
    ("F=-rf; rm $F /", "rm -rf /"),
    (r#"F=-delete; find / "$F""#, "find / -delete"),
    (
        "F=of=/dev/sda; dd if=/dev/zero $F",
        "dd if=/dev/zero of=/dev/sda",
    ),
    (
        r#"F=--force; git push "$F" origin main"#,
        "git push --force origin main",
    ),
    // An unrelated unresolved word cannot discard a flag whose value is known.
    (
        r#"F=--hard; git reset "$F" "$REV""#,
        r#"git reset --hard "$REV""#,
    ),
    (
        r#"F=--hard; git reset "$REV" "$F""#,
        r#"git reset "$REV" --hard"#,
    ),
    (
        r#"git reset "$REV" $(echo --hard)"#,
        r#"git reset "$REV" --hard"#,
    ),
];

fn assert_plain_rule_parity(source: &str, plain: &str, config: &Config) {
    for dialect in DIALECTS {
        let expected = evaluate_with_config(plain, dialect, config);
        assert!(
            expected.is_denied(),
            "plain control {plain:?} must deny under {dialect:?}: {expected:?}"
        );
        let actual = evaluate_with_config(source, dialect, config);
        assert!(
            actual.is_denied(),
            "{source:?} must deny like {plain:?} under {dialect:?}: {actual:?}"
        );
        assert_eq!(
            rule_of(&actual),
            rule_of(&expected),
            "{source:?} must retain the native rule for {plain:?} under {dialect:?}"
        );
    }
}

#[test]
fn literal_substitution_arguments_reach_the_plain_commands_rules() {
    let config = Config::default();
    for &(source, plain) in LITERAL_ARGUMENT_DENIALS {
        assert_plain_rule_parity(source, plain, &config);
    }
}

#[test]
fn bound_scalar_arguments_reach_the_plain_commands_rules() {
    let config = Config::default();
    for &(source, plain) in BOUND_ARGUMENT_DENIALS {
        assert_plain_rule_parity(source, plain, &config);
    }
}

const INERT_ARGUMENT_CONTROLS: &[&str] = &[
    "git reset $(echo --soft)",
    r#"git reset "$(printf %s --soft)""#,
    "git reset `echo --soft`",
    r#"F=--soft; git reset "$F""#,
    r#"F=--hard; F=--soft; git reset "$F""#,
    r#"F=--hard; git reset "it's" '$F'"#,
    "F=--hard; git reset '$F'",
    r"F=--hard; git reset \$F",
    r#"F=--hard; echo "$F""#,
    "git reset -- $(echo --hard)",
    "git reset -- --hard",
    "git reset '--' $(echo --hard)",
    "git reset -- $(echo --merge)",
    "git reset -- --merge",
    r#"F=--hard; git reset -- "$F""#,
    "echo 'git reset $(echo --hard)'",
    r#"echo "$(printf '%s' 'git reset --hard')""#,
    r#"git log --format "$(echo --oneline)""#,
    "cat <<'EOF'\ngit reset $(echo --hard)\nEOF",
];

#[test]
fn literal_argument_proofs_preserve_quoting_reassignment_and_data_roles() {
    for source in INERT_ARGUMENT_CONTROLS {
        for dialect in DIALECTS {
            let result = evaluate(source, dialect);
            assert!(
                result.is_allowed(),
                "{source:?} must remain inert under {dialect:?}: {result:?}"
            );
        }
    }
}

#[test]
fn generated_metacharacters_are_not_reparsed_as_shell_source() {
    for source in [
        r"echo $(printf 'foo\nrm -rf /')",
        r#"echo "$(printf '%s' 'git reset --hard; rm -rf /')""#,
        r#"printf '%s\n' "$(echo 'git reset --hard | rm -rf /')""#,
        r#"git log --format="$(printf '%s' 'git reset --hard; rm -rf /')""#,
        r#"echo "$(printf '%s' '$(git reset --hard)')""#,
        r#"echo "$(printf '%s' '`git reset --hard`')""#,
    ] {
        for dialect in DIALECTS {
            let result = evaluate(source, dialect);
            assert!(
                result.is_allowed(),
                "generated bytes are data under {dialect:?}: {source:?}: {result:?}"
            );
        }
    }
    assert_plain_rule_parity(
        r#"echo "$(git reset --hard)""#,
        "git reset --hard",
        &Config::default(),
    );
}

#[test]
fn unknown_argument_values_do_not_reuse_a_stale_or_unrelated_literal() {
    // Compare the same unresolved operation after different obsolete or
    // unrelated bindings. This does not require unknown producers to remain
    // allowed if a future policy explicitly protects those operations.
    for (source, control) in [
        (
            r#"F=--hard; F=$(cat flags.txt); git reset "$F""#,
            r#"F=--soft; F=$(cat flags.txt); git reset "$F""#,
        ),
        (
            r#"F=--hard; F=$FLAGS; git reset "$F""#,
            r#"F=--soft; F=$FLAGS; git reset "$F""#,
        ),
        (
            r#"F=--hard; git reset "$(cat flags.txt)""#,
            r#"F=--soft; git reset "$(cat flags.txt)""#,
        ),
        (
            r#"F=--hard; git checkout "$BRANCH""#,
            r#"F=--soft; git checkout "$BRANCH""#,
        ),
    ] {
        for dialect in DIALECTS {
            let actual = evaluate(source, dialect);
            let expected = evaluate(control, dialect);
            assert_eq!(
                (actual.decision, rule_of(&actual)),
                (expected.decision, rule_of(&expected)),
                "an unknown value must not inherit --hard under {dialect:?}: {source:?}"
            );
        }
    }
}

#[test]
fn padding_before_a_known_argument_cannot_turn_a_denial_into_an_allow() {
    let padding = "x".repeat(16 * 1024 + 1);
    for source in [
        format!("git reset {padding} $(echo --hard)"),
        format!("F=--hard; git reset {padding} \"$F\""),
    ] {
        for dialect in DIALECTS {
            let result = evaluate(&source, dialect);
            assert!(
                result.is_denied(),
                "padding cannot bypass the known flag under {dialect:?}: {result:?}"
            );
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ArgumentRoute {
    Cli(&'static str),
    NativeHook(&'static str),
}

const ARGUMENT_ROUTES: [ArgumentRoute; 4] = [
    ArgumentRoute::Cli("posix"),
    ArgumentRoute::Cli("unknown"),
    ArgumentRoute::NativeHook("Bash"),
    ArgumentRoute::NativeHook("shell"),
];

struct ArgumentFixture {
    directory: tempfile::TempDir,
    config: PathBuf,
}

impl ArgumentFixture {
    fn new(extra_config: &str) -> Self {
        let directory = tempfile::tempdir().expect("isolated argument proof fixture");
        for relative in ["home", "empty-path"] {
            std::fs::create_dir(directory.path().join(relative)).expect("isolated directory");
        }
        let config = directory.path().join("config.toml");
        std::fs::write(
            &config,
            format!("[history]\nenabled = false\n[general]\ncolor = \"never\"\n{extra_config}"),
        )
        .expect("isolated configuration");
        Self { directory, config }
    }

    fn grant(&self, entry: &str) {
        for relative in ["home/config/dcg", "home/.config/dcg", "home/appdata/dcg"] {
            let directory = self.directory.path().join(relative);
            std::fs::create_dir_all(&directory).expect("isolated user allowlist directory");
            std::fs::write(directory.join("allowlist.toml"), entry)
                .expect("isolated user allowlist");
        }
    }

    fn command(&self) -> Command {
        let home = self.directory.path().join("home");
        let mut command = Command::new(env!("CARGO_BIN_EXE_dcg"));
        command
            .env_clear()
            // Literal proofs must not run the producer or consult host shell state.
            .env("PATH", self.directory.path().join("empty-path"))
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_DATA_HOME", home.join("data"))
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env("APPDATA", home.join("appdata"))
            .env("LOCALAPPDATA", home.join("localappdata"))
            .env("ProgramData", home.join("programdata"))
            .env("TEMP", self.directory.path())
            .env("TMP", self.directory.path())
            .env("TMPDIR", self.directory.path())
            .env("DCG_CONFIG", &self.config)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("DCG_HISTORY_DISABLED", "1")
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("DCG_NO_SELF_HEAL", "1")
            .env(
                "DCG_PENDING_EXCEPTIONS_PATH",
                self.directory.path().join("pending.jsonl"),
            )
            // Semantic verdicts use the existing integration-test envelope;
            // production analysis budgets remain unchanged.
            .env("DCG_HOOK_TIMEOUT_MS", "5000")
            .env("DCG_AST_TIMEOUT_MS", "5000")
            .current_dir(self.directory.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn assert_route(
        &self,
        source: &str,
        route: ArgumentRoute,
        expected: &str,
        rule: Option<&str>,
    ) -> serde_json::Value {
        let mut command = self.command();
        let input = match route {
            ArgumentRoute::Cli(dialect) => {
                command.args(["test", "--stdin", "--dialect", dialect, "--format", "json"]);
                source.to_owned()
            }
            ArgumentRoute::NativeHook(tool_name) => serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_name": tool_name,
                "tool_input": { "command": source },
                "cwd": self.directory.path(),
                "dcg_explicit_verdict": true,
            })
            .to_string(),
        };
        let mut child = command
            .spawn()
            .expect("spawn DCG, never the source command");
        child
            .stdin
            .take()
            .expect("classifier stdin")
            .write_all(input.as_bytes())
            .expect("write classifier source");
        let output = child.wait_with_output().expect("classifier response");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Parsing the entire buffer rejects missing or multiple responses.
        let json: serde_json::Value =
            serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
                panic!(
                    "{source:?}, {route:?}: {error}; status={}; {stdout}; {stderr}",
                    output.status
                )
            });
        let expected_exit = i32::from(
            matches!(route, ArgumentRoute::Cli(_)) && matches!(expected, "deny" | "indeterminate"),
        );
        assert_eq!(
            output.status.code(),
            Some(expected_exit),
            "{source:?}, {route:?}: {json}; {stderr}"
        );
        match route {
            ArgumentRoute::Cli(_) => {
                assert_eq!(
                    json["decision"], expected,
                    "{source:?}, {route:?}: {json}; {stderr}"
                );
                if let Some(rule) = rule {
                    assert_eq!(json["rule_id"], rule, "{source:?}, {route:?}: {json}");
                }
            }
            ArgumentRoute::NativeHook(_) if matches!(expected, "deny" | "indeterminate") => {
                // The default unverified-analysis posture asks for native
                // review; a completed destructive finding is an outright deny.
                let permission = if expected == "indeterminate" {
                    "ask"
                } else {
                    "deny"
                };
                assert_eq!(
                    json["hookSpecificOutput"]["permissionDecision"], permission,
                    "{source:?}, {route:?}: {json}; {stderr}"
                );
                assert!(
                    json.get("dcg_verdict").is_none(),
                    "a blocking verdict owns the response: {json}"
                );
                if let Some(rule) = rule {
                    assert_eq!(
                        json["hookSpecificOutput"]["ruleId"], rule,
                        "{source:?}, {route:?}: {json}"
                    );
                }
            }
            ArgumentRoute::NativeHook(_) => {
                assert_eq!(
                    json,
                    serde_json::json!({"dcg_verdict": "allow"}),
                    "{source:?}, {route:?}: {stderr}"
                );
                if expected == "warn" {
                    assert!(
                        stderr.contains("WARNING"),
                        "warning remains visible: {stderr}"
                    );
                    assert!(
                        stderr.contains(rule.expect("warning rule")),
                        "warning keeps its native rule: {stderr}"
                    );
                }
            }
        }
        json
    }

    fn assert_all(&self, source: &str, expected: &str, rule: Option<&str>) {
        for route in ARGUMENT_ROUTES {
            self.assert_route(source, route, expected, rule);
        }
    }
}

#[test]
fn literal_argument_proofs_reach_cli_and_native_hook_dialects() {
    let fixture = ArgumentFixture::new("");
    for (source, rule) in [
        ("git reset $(echo --hard)", "core.git:reset-hard"),
        (r#"git reset "$(echo --hard)""#, "core.git:reset-hard"),
        ("git reset `echo --hard`", "core.git:reset-hard"),
        (r#"F=--hard; git reset "$F""#, "core.git:reset-hard"),
        (
            r#"git reset "$(echo --hard)"; IFS=:"#,
            "core.git:reset-hard",
        ),
        (r#"IFS=-; F=--hard; git reset "$F""#, "core.git:reset-hard"),
        ("git push $(echo --force)", "core.git:push-force-long"),
        ("git clean $(echo -fdx)", "core.git:clean-force"),
        ("rm $(echo -rf) /", "core.filesystem:rm-rf-root-home"),
        (
            "find / $(echo -delete)",
            "core.filesystem:find-delete-root-home",
        ),
        (
            "find / $(printf %s -delete)",
            "core.filesystem:find-delete-root-home",
        ),
        (
            "dd if=/dev/zero $(echo of=/dev/sda)",
            "system.disk:dd-device",
        ),
        (
            "dd if=/dev/zero $(printf %s of=/dev/sda)",
            "system.disk:dd-device",
        ),
        (r#"echo "$(git reset --hard)""#, "core.git:reset-hard"),
    ] {
        fixture.assert_all(source, "deny", Some(rule));
    }
    for source in [
        "git reset $(echo --soft)",
        r#"F=--hard; F=--soft; git reset "$F""#,
        r#"F=--hard; git reset "it's" '$F'"#,
        "git reset -- $(echo --hard)",
        r#"git log --format "$(echo --oneline)""#,
        r"echo $(printf 'foo\nrm -rf /')",
    ] {
        fixture.assert_all(source, "allow", None);
    }
}

#[test]
fn literal_subcommands_respect_the_opt_in_guardrails_pack() {
    const GUARDRAILS: &str = "careful_company_running_windows.guardrails";
    let mut config = Config::default();
    config.packs.enabled.push(GUARDRAILS.to_owned());
    for (source, plain) in [
        ("dcg $(echo uninstall) --yes", "dcg uninstall --yes"),
        ("dcg `echo uninstall` --yes", "dcg uninstall --yes"),
        ("dcg $(printf %s uninstall) --yes", "dcg uninstall --yes"),
        ("dcg --robot un$(echo install)", "dcg --robot uninstall"),
        (
            "dcg --robot $(echo allow-once) abc123 --yes",
            "dcg --robot allow-once abc123 --yes",
        ),
    ] {
        for dialect in DIALECTS {
            let default_result = evaluate(source, dialect);
            assert!(
                default_result.is_allowed(),
                "the optional pack must stay optional: {source:?}: {default_result:?}"
            );
        }
        assert_plain_rule_parity(source, plain, &config);
    }
    let fixture = ArgumentFixture::new(&format!("[packs]\nenabled = [\"{GUARDRAILS}\"]\n"));
    fixture.assert_all(
        "dcg `echo uninstall` --yes",
        "deny",
        Some("careful_company_running_windows.guardrails:dcg-bypass-or-uninstall"),
    );
    fixture.assert_all("dcg $(echo allowlist) list", "allow", None);
}

#[test]
fn literal_argument_findings_keep_explicit_warn_policy_and_later_denials() {
    let fixture = ArgumentFixture::new("[policy.rules]\n\"core.git:reset-hard\" = \"warn\"\n");
    for source in [
        "git reset --hard",
        "git reset $(echo --hard)",
        r#"F=--hard; git reset "$F""#,
    ] {
        fixture.assert_all(source, "warn", Some("core.git:reset-hard"));
    }
    fixture.assert_all(
        "git reset $(echo --hard); rm -rf /",
        "deny",
        Some("core.filesystem:rm-rf-root-home"),
    );
}

#[test]
fn rule_grants_cover_literal_arguments_without_covering_another_rule() {
    let fixture = ArgumentFixture::new("");
    fixture
        .grant("[[allow]]\nrule = \"core.git:reset-hard\"\nreason = \"isolated rule approval\"\n");
    for source in [
        "git reset --hard",
        "git reset $(echo --hard)",
        r#"F=--hard; git reset "$F""#,
    ] {
        fixture.assert_all(source, "allow", None);
    }
    fixture.assert_all(
        "git reset $(echo --hard); rm -rf /",
        "deny",
        Some("core.filesystem:rm-rf-root-home"),
    );
}

#[test]
fn reconstructed_arguments_cannot_acquire_an_exact_grant_for_different_source() {
    let fixture = ArgumentFixture::new("");
    // Grant the actual quoted spellings produced by the additional matching
    // view. An unquoted grant alone would not catch a derived-text lookup.
    fixture.grant(
        r#"[[allow]]
exact_command = "git reset '--hard'"
reason = "only this exact request"
[[allow]]
exact_command = "F=--hard; git reset '--hard'"
reason = "only this exact bound request"
"#,
    );
    for source in ["git reset '--hard'", "F=--hard; git reset '--hard'"] {
        fixture.assert_all(source, "allow", None);
    }
    for source in ["git reset $(echo --hard)", r#"F=--hard; git reset "$F""#] {
        fixture.assert_all(source, "deny", Some("core.git:reset-hard"));
    }

    let original_grant = ArgumentFixture::new("");
    original_grant.grant("[[allow]]\nexact_command = \"git reset $(echo --hard)\"\nreason = \"approve the original request\"\n");
    original_grant.assert_all("git reset $(echo --hard)", "allow", None);
    original_grant.assert_all("git reset --hard", "deny", Some("core.git:reset-hard"));
}

#[test]
fn producer_overrides_are_scoped_to_the_producer_and_preceding_source() {
    let fixture = ArgumentFixture::new("");
    for source in [
        "echo() { builtin echo --soft; }; git reset $(echo --hard)",
        "echo() { builtin echo -print; }; find / $(echo -delete)",
        "printf() { builtin printf %s -print; }; find / $(printf %s -delete)",
        "printf() { builtin printf %s of=/dev/null; }; dd if=/dev/zero $(printf %s of=/dev/sda)",
    ] {
        for dialect in DIALECTS {
            let result = evaluate(source, dialect);
            assert!(
                result.is_allowed(),
                "a replaced producer cannot prove its ordinary output: {source:?}, {dialect:?}: {result:?}"
            );
        }
    }
    fixture.assert_all(
        "echo() { builtin echo --soft; }; git reset $(echo --hard)",
        "allow",
        None,
    );
    fixture.assert_all(
        "printf() { builtin printf %s -print; }; find / $(printf %s -delete)",
        "allow",
        None,
    );
    for source in [
        "git reset $(echo --hard); echo() { builtin echo --soft; }",
        "printf() { builtin printf %s --soft; }; git reset $(echo --hard)",
    ] {
        assert_plain_rule_parity(source, "git reset --hard", &Config::default());
        fixture.assert_all(source, "deny", Some("core.git:reset-hard"));
    }
}

#[test]
fn argument_proof_bounds_never_authorize_an_oversized_pipeline() {
    // Exercise the structural cap, not a wall-clock deadline that depends on
    // host load. The unresolved final argument must not make the new proof
    // skip the bound and quietly allow the unexamined pipeline.
    let stages = vec!["true"; 1025].join(" | ");
    let source = format!("{stages} | git reset \"$F\"");
    let fixture = ArgumentFixture::new("");
    for (dialect, cli_dialect, tool_name) in [
        (ShellDialect::Posix, "posix", "Bash"),
        (ShellDialect::Unknown, "unknown", "shell"),
    ] {
        let result = evaluate(&source, dialect);
        assert!(
            !result.is_allowed(),
            "bounded analysis must not authorize unexamined input under {dialect:?}: {result:?}"
        );
        let expected = if result.is_denied() {
            "deny"
        } else {
            "indeterminate"
        };
        fixture.assert_route(&source, ArgumentRoute::Cli(cli_dialect), expected, None);
        fixture.assert_route(
            &source,
            ArgumentRoute::NativeHook(tool_name),
            expected,
            None,
        );
    }
}
