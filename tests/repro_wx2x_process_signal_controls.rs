//! bd-wx2x: the opt-in `system.processes` pack must deny kills that choose their
//! targets by pattern, parent-tree walk or broadcast, and allow the kills its
//! own explanations recommend: recorded PIDs, recorded process groups, `$!`,
//! job specs and a pidfile read back with `$(cat f)`.
//!
//! The corpus in `tests/fixtures/system_processes_corpus.tsv` holds both
//! incident commands, the wrapper and path spellings (`sudo`, `env`, `command`,
//! `builtin`, `/bin/kill`), shell `-c` and interpreter `-c`/`-e` bodies, ssh
//! remote commands, and the look-but-do-not-kill commands an agent runs around
//! them. Every command is only classified by `dcg test`; none is executed.
//!
//! These tests drive the real binary, so the registry keyword gate, executable
//! scoping and the heredoc extractor are all in the path.

use std::process::Command;

const CORPUS: &str = include_str!("fixtures/system_processes_corpus.tsv");

fn corpus() -> Vec<(&'static str, &'static str)> {
    CORPUS
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            line.split_once('\t')
                .unwrap_or_else(|| panic!("corpus line without a tab: {line:?}"))
        })
        .inspect(|(expect, command)| {
            assert!(
                matches!(*expect, "allow" | "deny"),
                "corpus expectation must be allow or deny: {expect:?} {command:?}"
            );
        })
        .collect()
}

fn verdict(command: &str, packs: &str, heredoc: bool) -> serde_json::Value {
    let scratch = tempfile::tempdir().expect("scratch dir");
    let home = scratch.path().join("home");
    std::fs::create_dir_all(&home).expect("isolated home");
    let config = scratch.path().join("config.toml");
    let settings = if heredoc {
        "[heredoc]\nenabled = true\ntimeout_ms = 5000\n"
    } else {
        "[heredoc]\nenabled = false\n"
    };
    std::fs::write(&config, settings).expect("write config");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dcg"));
    cmd.args(["test", "--config"]).arg(&config);
    if !packs.is_empty() {
        cmd.args(["--with-packs", packs]);
    }
    let output = cmd
        .args(["--dialect", "posix", "--format", "json", command])
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_HISTORY_DISABLED", "1")
        .env("DCG_AST_TIMEOUT_MS", "5000")
        // A host may load its own process-signal pack through the system
        // config's `packs.custom_paths`; the environment replaces that list so
        // only the built-in rules answer.
        .env("DCG_CUSTOM_PATHS", "")
        .current_dir(scratch.path())
        .output()
        .expect("run dcg test");
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{command:?} packs={packs:?} heredoc={heredoc}: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
    })
}

#[test]
fn corpus_decisions_hold_with_the_pack_enabled() {
    let mut wrong = Vec::new();
    for (expect, command) in corpus() {
        let verdict = verdict(command, "system.processes", true);
        let decision = verdict["decision"].as_str().unwrap_or_default();
        if decision != expect {
            wrong.push(format!(
                "expected {expect}, got {decision} ({}): {command}",
                verdict["rule_id"].as_str().unwrap_or("-")
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// Every deny in the corpus that the default packs allow must be denied by
/// this pack, not by some other rule that happens to overlap.
#[test]
fn corpus_denials_are_attributed_to_the_pack() {
    let mut wrong = Vec::new();
    for (expect, command) in corpus() {
        if expect != "deny" {
            continue;
        }
        let verdict = verdict(command, "system.processes", true);
        let rule = verdict["rule_id"].as_str().unwrap_or_default();
        if !rule.starts_with("system.processes:") {
            wrong.push(format!("{rule:?}: {command}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "denied by another pack:\n{}",
        wrong.join("\n")
    );
}

/// Opt-in: with only the default packs, none of these commands is denied.
#[test]
fn the_pack_is_not_enabled_by_default() {
    for command in [
        "pkill -f my-unique-job",
        "killall Finder",
        "kill -9 -1",
        "kill $(pgrep -f verify_loop)",
        "pgrep -f foo | xargs kill",
    ] {
        let verdict = verdict(command, "", true);
        assert_eq!(
            verdict["decision"].as_str(),
            Some("allow"),
            "{command:?}: {verdict}"
        );
    }
}

/// Known false positive (bd-2mli): the semantic proof accepts an unquoted
/// `$(< pidfile)`, but some evaluator view hides that body from it, so the
/// unquoted spelling is still denied. The quoted spelling is in the corpus as
/// an allow. This pins today's behaviour so a fix shows up as a deliberate
/// change here, not as a silent flip.
#[test]
fn unquoted_redirect_substitution_pidfile_is_still_denied() {
    for command in [
        "kill $(< /tmp/job.pid)",
        "kill $( < /tmp/job.pid )",
        "kill -TERM $(< /tmp/job.pid)",
    ] {
        let verdict = verdict(command, "system.processes", true);
        assert_eq!(
            verdict["rule_id"].as_str(),
            Some("system.processes:kill-computed-pids"),
            "{command:?}: {verdict}"
        );
    }
    for command in ["kill \"$(< /tmp/job.pid)\"", "kill -9 \"$(<job.pid)\" 2>/dev/null"] {
        let verdict = verdict(command, "system.processes", true);
        assert_eq!(
            verdict["decision"].as_str(),
            Some("allow"),
            "{command:?}: {verdict}"
        );
    }
}

/// With the extractor off, the rules scoped to `pkill`, `killall` and `kill`
/// never see a quoted remote command, so a deny by the ssh rule proves the
/// backstop itself works. A remote lookup-fed kill loop is answered earlier by
/// the unscoped `pid-lookup-feeds-kill`, which reads quoted text too.
#[test]
fn ssh_backstop_answers_when_the_remote_command_is_not_extracted() {
    for (command, rule) in [
        ("ssh build-1 'pkill -f cargo'", "ssh-remote-pattern-kill"),
        ("ssh build-2 \"killall rustc\"", "ssh-remote-pattern-kill"),
        ("ssh build-3 'kill -9 -1'", "ssh-remote-pattern-kill"),
        (
            "ssh build-3 'for p in $(pgrep -f x); do kill $p; done'",
            "pid-lookup-feeds-kill",
        ),
    ] {
        let verdict = verdict(command, "system.processes", false);
        assert_eq!(
            verdict["rule_id"].as_str(),
            Some(format!("system.processes:{rule}").as_str()),
            "{command:?}: {verdict}"
        );
    }
    for command in ["ssh build-2 'kill 12345'", "ssh build-1 'uptime'"] {
        let verdict = verdict(command, "system.processes", false);
        assert_eq!(
            verdict["decision"].as_str(),
            Some("allow"),
            "{command:?}: {verdict}"
        );
    }
}

/// A heredoc body that only mentions process tools as data is not a kill.
#[test]
fn interpreter_heredoc_using_single_pids_is_allowed() {
    let command = "python3 - <<'EOF'\nimport os, subprocess\n\
                   ps = subprocess.run([\"pgrep\", \"-f\", \"x\"], capture_output=True)\n\
                   os.kill(1234, 15)\nEOF";
    let verdict = verdict(command, "system.processes", true);
    assert_eq!(
        verdict["decision"].as_str(),
        Some("allow"),
        "{command:?}: {verdict}"
    );
}
