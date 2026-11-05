//! Issue #570: classify the argv program, not its first quoted segment.
//! Fixtures are input to DCG only; no destructive fixture is executed.

use destructive_command_guard::heredoc::{
    ExtractedContent, ExtractionLimits, ExtractionResult, ScriptLanguage, SkipReason,
    extract_content,
};
use std::io::Write;
use std::process::{Command, Stdio};

fn quote(code: &str, style: usize) -> String {
    match style {
        0 => format!("'{}'", code.replace('\'', "'\\''")),
        1 => format!("'{}'", code.replace('\'', "'\"'\"'")),
        2 => {
            let mut word = String::from("\"");
            for ch in code.chars() {
                if matches!(ch, '\\' | '"' | '$' | '`') {
                    word.push('\\');
                }
                word.push(ch);
            }
            word.push('"');
            word
        }
        _ => panic!("unknown quoting style"),
    }
}

fn extraction(source: &str, max_heredocs: usize) -> ExtractionResult {
    extract_content(
        source,
        &ExtractionLimits {
            timeout_ms: 5_000,
            max_heredocs,
            ..ExtractionLimits::default()
        },
    )
}

fn complete(source: &str) -> Vec<ExtractedContent> {
    match extraction(source, 10) {
        ExtractionResult::Extracted(items) => items,
        result => panic!("static program must be completely extracted: {source:?}: {result:?}"),
    }
}

#[test]
fn every_quoted_segment_reaches_the_existing_language_analyzer() {
    for (launcher, language, code) in [
        (
            "bash -c",
            ScriptLanguage::Bash,
            "echo 'x'; git reset --hard",
        ),
        (
            "sh -c",
            ScriptLanguage::Bash,
            "printf '%s' x; git reset --hard",
        ),
        (
            "dash -c",
            ScriptLanguage::Bash,
            "echo 'x'; git reset --hard",
        ),
        ("zsh -c", ScriptLanguage::Bash, "echo 'x'; git reset --hard"),
        ("ksh -c", ScriptLanguage::Bash, "echo 'x'; git reset --hard"),
        (
            "mksh -c",
            ScriptLanguage::Bash,
            "echo 'x'; git reset --hard",
        ),
        (
            "python3 -c",
            ScriptLanguage::Python,
            "import os; os.system('git reset --hard')",
        ),
        (
            "python3.11 -I -c",
            ScriptLanguage::Python,
            "import os; os.system('git reset --hard')",
        ),
        (
            "node -e",
            ScriptLanguage::JavaScript,
            "require('child_process').execSync('git reset --hard')",
        ),
        (
            "nodejs -p",
            ScriptLanguage::JavaScript,
            "require('child_process').execSync('git reset --hard')",
        ),
        (
            "ruby -e",
            ScriptLanguage::Ruby,
            "system('git reset --hard')",
        ),
        (
            "perl -e",
            ScriptLanguage::Perl,
            "system('git reset --hard')",
        ),
        (
            "perl -E",
            ScriptLanguage::Perl,
            "system('git reset --hard')",
        ),
    ] {
        for style in 0..3 {
            let source = format!("{launcher} {}", quote(code, style));
            let items = complete(&source);
            let programs: Vec<_> = items
                .iter()
                .filter(|item| item.language == language)
                .collect();
            assert_eq!(
                programs.len(),
                1,
                "duplicate or missing program: {source}: {items:?}"
            );
            assert_eq!(
                programs[0].content, code,
                "truncated/incorrect argv: {source}"
            );
            assert_eq!(
                programs[0].byte_range.end,
                source.len(),
                "incomplete source range: {source}"
            );
            for item in &items {
                if let Some(range) = &item.content_range {
                    assert_eq!(source.get(range.clone()), Some(item.content.as_str()));
                }
            }
        }
    }
}

#[test]
fn decoding_preserves_literals_empty_segments_unicode_and_boundaries() {
    for (word, code) in [
        (
            r"'echo '\''x'\''; git reset --hard'",
            "echo 'x'; git reset --hard",
        ),
        (
            r#""echo \"x\"; git reset --hard""#,
            "echo \"x\"; git reset --hard",
        ),
        (
            r#"'echo '"'"'élève'"'"'; git reset --hard'"#,
            "echo 'élève'; git reset --hard",
        ),
        (
            r#"''"echo x; "'git reset --hard'"#,
            "echo x; git reset --hard",
        ),
        (r"echo\ 'x; git reset --hard'", "echo x; git reset --hard"),
        (r"git\ reset\ --hard", "git reset --hard"),
        (
            r"$'echo \'x\'; git reset --hard'",
            "echo 'x'; git reset --hard",
        ),
        (
            r"$'echo safe\0ignored'\;'git reset --hard'",
            "echo safe;git reset --hard",
        ),
        (
            "'echo x; '\\\n'git reset --hard'",
            "echo x; git reset --hard",
        ),
        (
            r#""printf '%s' '\q \$VALUE \`date\`'""#,
            "printf '%s' '\\q $VALUE `date`'",
        ),
        (
            r#"'printf %s "$VALUE * ? [x]"'"#,
            "printf %s \"$VALUE * ? [x]\"",
        ),
    ] {
        let source = format!("bash -c {word}>out ignored_argument");
        let items = complete(&source);
        assert!(
            items.iter().any(|item| item.content == code),
            "{source}: {items:?}"
        );
        for item in &items {
            assert!(item.byte_range.end <= source.find(">out").unwrap());
            if let Some(range) = &item.content_range {
                assert_eq!(source.get(range.clone()), Some(item.content.as_str()));
            }
        }
    }
}

#[test]
fn overlapping_locators_and_redirect_views_do_not_exhaust_the_payload_budget() {
    let source = r"bash 2>/dev/null -c 'echo '\''x'\''; git reset --hard'";
    match extraction(source, 1) {
        ExtractionResult::Extracted(items) => {
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].content, "echo 'x'; git reset --hard");
            assert!(items[0].content_range.is_none());
        }
        other => panic!("one program must use one budget slot: {other:?}"),
    }
}

#[test]
fn unresolved_or_malformed_words_are_not_reported_as_complete() {
    for source in [
        r#"bash -c 'echo '"$VALUE"'; echo tail'"#,
        r#"python3 -c 'print('"$VALUE"')'"#,
        r"node -e 'console.log('$(printf value)')'",
        r"bash -c 'echo '`printf value`'; echo tail'",
        r#"bash -c $"echo translated""#,
        "bash -c 'echo unterminated",
        r"bash -c 'echo '\",
        r"bash -c 'echo '*",
        r#"ssh host 'echo '"$VALUE"'; echo tail'"#,
        r#"mise exec -c 'echo '"$VALUE"'; echo tail'"#,
    ] {
        let skipped = match extraction(source, 10) {
            ExtractionResult::Partial { skipped, .. } | ExtractionResult::Skipped(skipped) => {
                skipped
            }
            other => panic!("incomplete argument silently accepted: {source}: {other:?}"),
        };
        assert!(
            skipped
                .iter()
                .any(|reason| matches!(reason, SkipReason::MalformedInput { .. }))
        );
    }
}

fn decision(source: &str, expected: &str, strict: bool) {
    for hook in [false, true] {
        let (verdict, context) = run_dcg(source, hook, strict);
        assert_eq!(
            verdict["decision"].as_str(),
            Some(expected),
            "{context}, verdict={verdict}"
        );
    }
}

/// Denied in CLI and hook mode, by exactly `rule`.
fn denied_by(source: &str, rule: &str) {
    for hook in [false, true] {
        let (verdict, context) = run_dcg(source, hook, false);
        assert_eq!(
            (verdict["decision"].as_str(), verdict["rule_id"].as_str()),
            (Some("deny"), Some(rule)),
            "{context}, verdict={verdict}"
        );
    }
}

/// One DCG verdict, and a description of the run for assertion messages.
fn run_dcg(source: &str, hook: bool, strict: bool) -> (serde_json::Value, String) {
    let temp = tempfile::tempdir().expect("isolated working directory");
    let home = temp.path().join("home");
    std::fs::create_dir(&home).expect("isolated home");
    let config = temp.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            "[heredoc]\ntimeout_ms = 5000\nfallback_on_parse_error = {}\n",
            !strict
        ),
    )
    .expect("explicit test configuration");
    let mut command = Command::new(env!("CARGO_BIN_EXE_dcg"));
    let input = if hook {
        command.args(["hook", "--batch"]);
        serde_json::json!({
            "hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": source},
        })
        .to_string()
    } else {
        command.args(["test", "--stdin", "--dialect", "posix", "--format", "json"]);
        source.to_string()
    };
    let mut child = command
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("DCG_CONFIG", &config)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_HISTORY_ENABLED", "false")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .env("DCG_AST_TIMEOUT_MS", "5000")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn DCG, never the fixture");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let verdict: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("{error}: stdout={stdout}; stderr={stderr}"));
    let context = format!(
        "hook={hook}, strict={strict}, source={source:?}, status={}, stderr={stderr}",
        output.status
    );
    (verdict, context)
}

#[test]
fn confirmed_interpreter_repros_deny_in_cli_and_hook_mode() {
    for (launcher, code) in [
        ("bash -c", "echo 'x'; git reset --hard"),
        ("python3 -I -c", "import os; os.system('git reset --hard')"),
        (
            "node -e",
            "require('child_process').execSync('git reset --hard')",
        ),
        ("ruby -e", "system('git reset --hard')"),
        ("perl -e", "system('git reset --hard')"),
    ] {
        for style in 0..3 {
            decision(&format!("{launcher} {}", quote(code, style)), "deny", false);
        }
    }
}

#[test]
fn wrappers_and_option_variants_keep_the_complete_program() {
    let code = "echo 'x'; git reset --hard";
    for launcher in [
        "bash -lc",
        "bash -o pipefail -c",
        "bash -c --",
        "bash -c -o errexit",
        "sudo -u root bash -c",
        "env FOO=1 sh -c",
        "timeout 5 bash -c",
        "printf x | xargs sh -c",
        "ssh -p 22 host",
        "mise exec -c",
        "mise x --command",
        "bun exec",
        "watch -n 1",
        "/usr/bin/bash -c",
    ] {
        decision(&format!("{launcher} {}", quote(code, 0)), "deny", false);
    }
    for (prefix, suffix) in [
        ("find . -name x -exec sh -c ", " \\;"),
        ("python3 -c", ""),
        ("mise exec --command=", ""),
        ("mise exec -c", ""),
    ] {
        let body = if prefix.starts_with("python") {
            "import os; os.system('git reset --hard')"
        } else {
            code
        };
        decision(
            &format!("{prefix}{}{suffix}", quote(body, 0)),
            "deny",
            false,
        );
    }
    let nested = format!("bash -c {}", quote(code, 0));
    decision(&format!("bash -c {}", quote(&nested, 1)), "deny", false);
}

#[test]
fn awk_and_osascript_decode_the_outer_program_before_extracting_sinks() {
    for (launcher, code) in [
        ("awk", "BEGIN { system(\"echo 'x'; git reset --hard\") }"),
        (
            "osascript -e",
            "do shell script \"echo 'x'; git reset --hard\"",
        ),
    ] {
        for style in 0..3 {
            decision(&format!("{launcher} {}", quote(code, style)), "deny", false);
        }
    }
}

#[test]
fn harmless_command_like_strings_remain_data_in_both_modes() {
    for (launcher, code) in [
        ("bash -c", "printf '%s' 'git reset --hard'"),
        ("python3 -c", "print('git reset --hard is dangerous')"),
        ("node -e", "console.log('git reset --hard is dangerous')"),
        ("ruby -e", "puts('git reset --hard is dangerous')"),
        ("perl -e", "print('git reset --hard is dangerous')"),
        ("ssh host", "printf '%s' 'git reset --hard'"),
        ("mise exec -c", "printf '%s' 'git reset --hard'"),
        ("bun exec", "printf '%s' 'git reset --hard'"),
        ("awk", "BEGIN { print \"git reset --hard\" }"),
        ("osascript -e", "return \"git reset --hard\""),
    ] {
        for style in 0..3 {
            decision(
                &format!("{launcher} {}", quote(code, style)),
                "allow",
                false,
            );
        }
    }
    decision(
        r#"ssh host printf '%s' "'git reset --hard'""#,
        "allow",
        false,
    );
}

#[test]
fn uncertainty_obeys_the_existing_configured_policy() {
    let source = r#"python3 -c 'print('"$VALUE"')'"#;
    decision(source, "allow", false);
    decision(source, "deny", true);
    decision(
        r#"bash -c 'echo '"$VALUE"'; git reset --hard'"#,
        "deny",
        false,
    );
    decision("bash -c 'echo unterminated", "deny", true);
}

/// The issue's second gap: Deno's and Bun's own process APIs, and zx's `$`,
/// were allowed while the `child_process` twin of each denied. They deny
/// under the same exec-sink rules now, in every quoting style.
#[test]
fn deno_bun_and_zx_process_apis_deny_like_child_process() {
    const GIT_TS: &str = "heredoc.typescript:exec_sink.git_reset_hard";
    const GIT_JS: &str = "heredoc.javascript:exec_sink.git_reset_hard";
    const UNVERIFIED_TS: &str = "heredoc.typescript:exec_sink.argv_unverified";
    for (launcher, code, rule) in [
        (
            "deno eval",
            r#"new Deno.Command("git", {args: ["reset", "--hard"]}).outputSync()"#,
            GIT_TS,
        ),
        (
            "deno eval",
            r#"await new Deno.Command("rm", {args: ["-rf", "/etc"]}).output()"#,
            "heredoc.typescript:exec_sink.rm_rf_catastrophic",
        ),
        (
            "deno eval",
            r#"new Deno.Command("sh", {args: ["-c", "git reset --hard"]}).spawn()"#,
            GIT_TS,
        ),
        (
            "deno eval",
            r#"Deno.run({cmd: ["git", "reset", "--hard"]})"#,
            GIT_TS,
        ),
        (
            "bun -e",
            r#"Bun.spawnSync(["git", "reset", "--hard"])"#,
            GIT_TS,
        ),
        (
            "bun -e",
            r#"Bun.spawn({cmd: ["git", "reset", "--hard"]})"#,
            GIT_TS,
        ),
        ("bun -e", "await Bun.$`git reset --hard`", GIT_TS),
        (
            "bun -e",
            r#"import { $ } from "bun"; await $`git reset --hard`"#,
            GIT_TS,
        ),
        (
            "node -e",
            r#"const {$} = require("zx"); $`git reset --hard`"#,
            GIT_JS,
        ),
        // The child_process twin these now match.
        (
            "node -e",
            r#"require("child_process").spawnSync("git", ["reset", "--hard"])"#,
            GIT_JS,
        ),
        // An argv that cannot be read fails closed, as `spawnSync("git",
        // flags)` does.
        (
            "deno eval",
            r#"new Deno.Command("git", {args: flags}).outputSync()"#,
            UNVERIFIED_TS,
        ),
        (
            "bun -e",
            r#"Bun.spawnSync(["git", ...flags])"#,
            UNVERIFIED_TS,
        ),
        // Verbs only the packs know reach them through the same argv
        // reconstruction as an argv-split `spawnSync`.
        (
            "deno eval",
            r#"new Deno.Command("dd", {args: ["if=/dev/zero", "of=/dev/sda"]}).outputSync()"#,
            "system.disk:dd-device",
        ),
        (
            "bun -e",
            r#"Bun.spawnSync(["wipefs", "-a", "/dev/sda"])"#,
            "system.disk:wipefs",
        ),
        (
            "bun -e",
            "await Bun.$`dd if=/dev/zero of=/dev/sda`",
            "system.disk:dd-device",
        ),
    ] {
        for style in 0..3 {
            denied_by(&format!("{launcher} {}", quote(code, style)), rule);
        }
    }
}

#[test]
fn benign_deno_bun_and_zx_process_calls_stay_allowed() {
    for (launcher, code) in [
        ("deno eval", r#"new Deno.Command("ls").outputSync()"#),
        (
            "deno eval",
            r#"new Deno.Command("git", {args: ["status"]}).outputSync()"#,
        ),
        ("deno eval", r#"Deno.run({cmd: ["git", "log", "-1"]})"#),
        ("bun -e", r#"Bun.spawnSync(["echo", "hi"])"#),
        ("bun -e", r#"Bun.spawn({cmd: ["ls", "-la"], cwd: "/"})"#),
        ("bun -e", "await Bun.$`ls -la`"),
        ("bun -e", r#"import { $ } from "bun"; await $`git status`"#),
        (
            "node -e",
            r#"const {$} = require("zx"); await $`git status`"#,
        ),
        // The temp carve-out holds as it does for `spawnSync`.
        (
            "deno eval",
            r#"new Deno.Command("rm", {args: ["-rf", "/tmp/build"]}).outputSync()"#,
        ),
    ] {
        for style in 0..3 {
            decision(
                &format!("{launcher} {}", quote(code, style)),
                "allow",
                false,
            );
        }
    }
    // A shell-quoted string the template only prints. Single-quoted styles
    // only: in the double-quoted one the outer word carries `\``, and the
    // outer shell scan denies that text on its own (`source: pack`), exactly
    // as it does for a program with no sink at all, ``node -e
    // "console.log(\`echo 'rm -rf /'\`)"``.
    for style in 0..2 {
        decision(
            &format!("bun -e {}", quote("await Bun.$`echo 'rm -rf /'`", style)),
            "allow",
            false,
        );
    }
}

/// A template literal argument is a string like a quoted one, for
/// `child_process` and the native APIs alike.
#[test]
fn template_literal_arguments_deny_like_quoted_ones() {
    for (launcher, code, rule) in [
        (
            "node -e",
            r#"require("child_process").execSync(`git reset --hard`)"#,
            "heredoc.javascript:exec_sink.git_reset_hard",
        ),
        (
            "bun -e",
            r#"Bun.spawnSync(["sh", "-c", `git reset --hard`])"#,
            "heredoc.typescript:exec_sink.git_reset_hard",
        ),
        (
            "deno eval",
            "new Deno.Command(`git`, {args: [`reset`, `--hard`]}).outputSync()",
            "heredoc.typescript:exec_sink.git_reset_hard",
        ),
    ] {
        // The double-quoted style escapes the backticks, which the outer
        // shell scan may judge first; it must still deny.
        for style in 0..2 {
            denied_by(&format!("{launcher} {}", quote(code, style)), rule);
        }
        decision(&format!("{launcher} {}", quote(code, 2)), "deny", false);
    }
    for code in [
        r#"require("child_process").execSync(`git status`)"#,
        r#"require("child_process").execSync(`echo it's done`)"#,
        r#"require("child_process").spawnSync("echo", [`hi`])"#,
    ] {
        for style in 0..3 {
            decision(&format!("node -e {}", quote(code, style)), "allow", false);
        }
    }
}

/// `(surface, decision, rule id)` from every evaluation surface for one
/// command: the CLI (`dcg test --stdin --dialect posix`), a Claude PreToolUse
/// payload on the hook's stdin, and `dcg hook --batch`. They must agree. The
/// budgets are generous so a loaded test host reports the verdict, not an
/// exhausted deadline.
fn surface_verdicts(source: &str) -> Vec<(&'static str, String, String)> {
    let mut verdicts = Vec::new();
    for surface in ["cli", "hook", "batch"] {
        let temp = tempfile::tempdir().expect("isolated working directory");
        let home = temp.path().join("home");
        std::fs::create_dir(&home).expect("isolated home");
        let config = temp.path().join("config.toml");
        std::fs::write(
            &config,
            "[heredoc]\ntimeout_ms = 5000\n\n[history]\nenabled = false\n",
        )
        .expect("explicit test configuration");
        let mut command = Command::new(env!("CARGO_BIN_EXE_dcg"));
        let input = if surface == "cli" {
            command.args(["test", "--stdin", "--dialect", "posix", "--format", "json"]);
            source.to_string()
        } else {
            if surface == "batch" {
                command.args(["hook", "--batch"]);
            }
            serde_json::json!({
                "hook_event_name": "PreToolUse", "tool_name": "Bash",
                "tool_input": {"command": source},
            })
            .to_string()
        };
        let mut child = command
            .env_clear()
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("DCG_CONFIG", &config)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("DCG_NO_SELF_HEAL", "1")
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("DCG_HISTORY_ENABLED", "false")
            .env("DCG_HOOK_TIMEOUT_MS", "5000")
            .env("DCG_AST_TIMEOUT_MS", "5000")
            .current_dir(temp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn DCG, never the fixture");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        if surface == "hook" && stdout.trim().is_empty() {
            verdicts.push((surface, "allow".to_string(), String::new()));
            continue;
        }
        let verdict: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|error| {
            panic!(
                "{surface}: {error}: stdout={stdout}; stderr={}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
        let (decision, rule) = if surface == "hook" {
            let result = &verdict["hookSpecificOutput"];
            (&result["permissionDecision"], &result["ruleId"])
        } else {
            (&verdict["decision"], &verdict["rule_id"])
        };
        verdicts.push((
            surface,
            decision.as_str().unwrap_or_default().to_string(),
            rule.as_str().unwrap_or_default().to_string(),
        ));
    }
    verdicts
}

/// Escapes (`"… \$(…) …"`) and quote concatenation (`'…'\''…'`) decode an
/// inline program word without changing the program, so they must not skip
/// the #544 recovery of shell commands carried through host-language
/// literals. Every decoded spelling here was ALLOWED by the CLI, the hook and
/// `hook --batch` alike, while the plain single-quoted spelling denied:
/// recovery took its source identity only from the exact content span, which
/// #570 leaves empty once decoding changes the bytes.
#[test]
fn decoded_inline_programs_keep_interpreter_literal_recovery() {
    for (launcher, body, rule) in [
        (
            "python3 -c",
            "import os; s = 'echo $(git reset --hard)'; os.system(s)",
            "core.git:reset-hard",
        ),
        (
            "python3 -c",
            "from helper import run; s = 'echo $(git reset --hard)'; run(s)",
            "core.git:reset-hard",
        ),
        (
            "python3 -c",
            "import os; s = 'echo `git branch -D main`'; os.system(s)",
            "core.git:branch-force-delete",
        ),
        (
            "node -e",
            "const cp = require('child_process'); const s = 'echo $(git reset --hard)'; cp.execSync(s);",
            "core.git:reset-hard",
        ),
        (
            "node -e",
            "const run = require('./helper'); const s = 'echo $(git reset --hard)'; run(s);",
            "core.git:reset-hard",
        ),
        (
            "node -e",
            "tag`echo $(git reset --hard)`",
            "core.git:reset-hard",
        ),
    ] {
        for style in 0..3 {
            for suffix in ["", " && true", " > /dev/null"] {
                let source = format!("{launcher} {}{suffix}", quote(body, style));
                for (surface, decision, denying_rule) in surface_verdicts(&source) {
                    assert_eq!(
                        (decision.as_str(), denying_rule.as_str()),
                        ("deny", rule),
                        "{surface}: {source}"
                    );
                }
            }
        }
    }
}

/// The decoded spellings keep the single-quoted spelling's allows too: an
/// isolated program that only prints command-like text, and argv data a
/// proven static spawn never hands to a shell.
#[test]
fn decoded_inline_documentation_and_argv_data_stay_allowed() {
    for (launcher, body) in [
        ("python3 -c", "s = 'run `git branch -d x` later'; print(s)"),
        (
            "node -e",
            "const s = 'run `git branch -d x` later'; console.log(s);",
        ),
        ("python3 -c", "print('use $(git reset --hard) with care')"),
        (
            "node -e",
            r"const s = String.raw`echo \`git branch -d x\``; require('child_process').execSync(s);",
        ),
    ] {
        for style in 0..3 {
            let source = format!("{launcher} {}", quote(body, style));
            for (surface, decision, rule) in surface_verdicts(&source) {
                assert_eq!(decision, "allow", "{surface}: {source}: {rule}");
            }
        }
    }
    for (launcher, body) in [
        (
            "python3 -c",
            "import subprocess; subprocess.run(['printf', '%s', '$(git reset --hard)'])",
        ),
        (
            "node -e",
            "const cp = require('child_process'); cp.spawnSync('printf', ['%s', '$(git reset --hard)']);",
        ),
    ] {
        for style in 0..3 {
            for suffix in ["", " && true"] {
                let source = format!("{launcher} {}{suffix}", quote(body, style));
                for (surface, decision, rule) in surface_verdicts(&source) {
                    assert_eq!(decision, "allow", "{surface}: {source}: {rule}");
                }
            }
        }
    }
}

/// #643 describes short json/re programs but does not supply the failing
/// commands. These are representative controls, not a reproduction of those
/// missing inputs. Backslashes deliberately enter interpreter-literal
/// recovery. Generous test budgets isolate its verdict from host scheduling.
#[test]
fn issue_643_representative_short_python_json_and_regex_programs() {
    let body = r#"import json
import re
document = '{"name": "demo", "values": [1, 2, 3]}'
record = json.loads(document)
name = record["name"]
values = record["values"]
label = re.sub(r"\s+", " ", "  sample   text  ").strip()
words = re.findall(r"\w+", label)
digits = re.findall(r"\d+", "a12 b34")
parts = [word.upper() for word in words]
total = sum(values)
count = len(values)
report = {"name": name, "label": label}
report["words"] = parts
report["digits"] = digits
report["total"] = total
report["count"] = count
encoded = json.dumps(report, sort_keys=True)
pretty = json.dumps(json.loads(encoded), indent=2)
print(pretty)
"#;
    for padding in [String::new(), "# ordinary documentation text\n".repeat(30)] {
        let safe = format!("{body}{padding}");
        assert!((300..=1_700).contains(&safe.len()));
        // An indirect shell sink must still recover the literal and deny;
        // a benign prefix is not a reason to skip the remaining program.
        let dangerous =
            format!("{safe}import os\npayload = 'echo $(git reset --hard)'\nos.system(payload)\n");
        for (program, expected, rule) in [
            (safe.as_str(), "allow", ""),
            (dangerous.as_str(), "deny", "core.git:reset-hard"),
        ] {
            for source in [
                format!("python3 -c {}", quote(program, 2)),
                format!("cd /tmp && python3 -I - <<'EOF'\n{program}EOF"),
            ] {
                for (surface, actual, actual_rule) in surface_verdicts(&source) {
                    assert_eq!(
                        (actual.as_str(), actual_rule.as_str()),
                        (expected, rule),
                        "{surface}: {source}"
                    );
                }
            }
        }
    }
}

/// The decoded word gets the same Node option-ownership proof as the exact
/// one (#544): a later `-e` replaces the first program, and an option stop
/// keeps it active.
#[test]
fn decoded_node_programs_keep_option_ownership() {
    let body = "const cp = require('child_process'); const s = 'echo $(git reset --hard)'; cp.execSync(s);";
    for style in 0..3 {
        let program = quote(body, style);
        let replaced = format!("node -e {program} -e 'console.log(1)'");
        for (surface, decision, rule) in surface_verdicts(&replaced) {
            assert_eq!(decision, "allow", "{surface}: {replaced}: {rule}");
        }
        let stopped = format!("node -e {program} -- -e 'console.log(1)'");
        for (surface, decision, rule) in surface_verdicts(&stopped) {
            assert_eq!(
                (decision.as_str(), rule.as_str()),
                ("deny", "core.git:reset-hard"),
                "{surface}: {stopped}"
            );
        }
    }
}
