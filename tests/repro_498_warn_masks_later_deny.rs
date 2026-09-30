//! Regression tests for issue #498: a match that policy lets run (warn, log,
//! or ask) hid every later finding on the same line.
//!
//! The evaluator stops at its first match and leaves policy to the caller, so
//! `git stash drop && git reset --hard` resolved to the warn of
//! `core.git:stash-drop` and the `reset-hard` deny behind it was never looked
//! at. Any rule a user downgraded to warn became a prefix that disarmed the
//! rules evaluated after it. These tests pin the strictest-finding-wins
//! answer through the bare Claude hook, the `dcg hook --batch` subcommand,
//! and `dcg test`, plus the planted negatives that keep the warn a warn when
//! nothing stricter is present.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

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
            .env("DCG_HOOK_TIMEOUT_MS", "5000")
            .current_dir(self.dir.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }

    fn run_with_stdin(&self, args: &[&str], stdin_text: &str) -> (String, String) {
        let mut child = self
            .command(args)
            .stdin(Stdio::piped())
            .spawn()
            .expect("spawn dcg");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(stdin_text.as_bytes())
            .unwrap();
        let output = child.wait_with_output().expect("wait dcg");
        (
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
    }

    /// The bare Claude Code `PreToolUse` hook, exactly as the report drove it.
    fn claude_hook_denies(&self, shell_command: &str) -> bool {
        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": shell_command },
            "cwd": self.dir.path(),
        });
        let (stdout, _) = self.run_with_stdin(&[], &format!("{payload}\n"));
        stdout.contains("\"deny\"")
    }

    /// The `dcg hook --batch` JSONL decision.
    fn batch_decision(&self, shell_command: &str) -> (String, String) {
        let payload = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": shell_command },
            "cwd": self.dir.path(),
        });
        let (stdout, stderr) = self.run_with_stdin(&["hook", "--batch"], &format!("{payload}\n"));
        let line = stdout
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or_else(|| panic!("no batch output\nstderr:\n{stderr}"));
        let json: serde_json::Value = serde_json::from_str(line).expect("batch JSON");
        (
            json["decision"].as_str().unwrap_or("<missing>").to_string(),
            json["rule_id"].as_str().unwrap_or("<none>").to_string(),
        )
    }

    /// The `Result:` line of `dcg test`.
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
            .unwrap_or_else(|| panic!("no Result line\nstdout:\n{stdout}\nstderr:\n{stderr}"))
    }
}

const DEFAULTS: &str = "[general]\ncolor = \"never\"\n";

/// A warn-severity first finding followed by a deny, in every separator and
/// wrapper shape an agent could chain them with.
const MASKED_DENIES: &[&str] = &[
    "git stash drop && git reset --hard",
    "git stash drop; git reset --hard",
    "git stash drop || git reset --hard",
    "git stash drop | git reset --hard",
    "git stash drop\ngit reset --hard",
    "git stash drop & git reset --hard",
    "git stash drop && git clean -fd",
    "git stash drop stash@{0} && git reset --hard HEAD~3",
    "git stash drop && git reset --hard && git stash drop",
    "(git stash drop; git reset --hard)",
    "{ git stash drop; git reset --hard; }",
    "sh -c 'git stash drop && git reset --hard'",
    "bash -c \"git stash drop; git reset --hard\"",
    "GIT_DIR=.git git stash drop && GIT_DIR=.git git reset --hard",
    "/usr/bin/git stash drop && /usr/bin/git reset --hard",
    "git -C . stash drop && git -C . reset --hard",
    "git stash drop && sudo git reset --hard",
    "git stash drop && env git reset --hard",
    "git stash drop && git push --force origin main",
    "git stash drop && git branch -D feature",
    "git stash drop 2>/dev/null && git reset --hard",
    "git stash drop >/dev/null; git reset --hard",
    "time git stash drop; git reset --hard",
    "nohup git stash drop; git reset --hard",
    "eval 'git stash drop; git reset --hard'",
    "bash <<'EOF'\ngit stash drop\ngit reset --hard\nEOF",
    "GIT_STASH=1 git stash drop; FOO=bar git reset --hard",
    "git stash drop; git stash drop; git reset --hard",
    "git stash clear; git stash drop; git reset --hard",
];

#[test]
fn warn_first_match_no_longer_hides_a_later_deny() {
    let lab = Lab::new(DEFAULTS);
    for command in MASKED_DENIES {
        assert!(
            lab.claude_hook_denies(command),
            "Claude hook must deny {command:?}: the warn of its first half must not hide the rest"
        );
    }
}

#[test]
fn batch_hook_and_dcg_test_agree_on_the_deny() {
    let lab = Lab::new(DEFAULTS);
    let (decision, rule) = lab.batch_decision("git stash drop && git reset --hard");
    assert_eq!(decision, "deny", "dcg hook --batch");
    assert_eq!(
        rule, "core.git:reset-hard",
        "the deny names the rule that denies"
    );
    let line = lab.test_result_line("git stash drop && git reset --hard");
    assert!(line.contains("BLOCKED"), "dcg test: {line}");
}

#[test]
fn warn_stays_warn_when_nothing_stricter_follows() {
    // Planted negatives: the escalation must not turn a lone warn, or two
    // warns, into a deny.
    let lab = Lab::new(DEFAULTS);
    for command in [
        "git stash drop",
        "git stash drop && git status",
        "git stash drop; git stash drop",
        "git status && git stash drop",
    ] {
        assert!(
            !lab.claude_hook_denies(command),
            "Claude hook must not deny {command:?}"
        );
        let (decision, rule) = lab.batch_decision(command);
        assert_eq!(decision, "allow", "{command:?}");
        assert_eq!(
            rule, "core.git:stash-drop",
            "{command:?} keeps its warn rule"
        );
    }
    // Looking past the warn must not turn inert text behind it into a finding.
    for command in [
        "git stash drop && echo 'git reset --hard'",
        "git stash drop && git commit -m 'undo git reset --hard'",
        "git stash drop && grep -r 'rm -rf' docs/",
        "git stash drop && git log --grep='reset --hard'",
    ] {
        assert!(
            !lab.claude_hook_denies(command),
            "{command:?}: data behind a warn is not a command"
        );
    }
    for command in ["git status", "ls -la && git log --oneline", "cargo test"] {
        assert!(!lab.claude_hook_denies(command), "{command:?}");
    }
}

#[test]
fn user_downgraded_rule_no_longer_disarms_later_rules() {
    // The report's second form: a rule the user set to warn.
    let lab = Lab::new(
        "[general]\ncolor = \"never\"\n\n[policy.rules]\n\"core.git:branch-force-delete\" = \"warn\"\n",
    );
    assert!(!lab.claude_hook_denies("git branch -D x"));
    assert!(lab.claude_hook_denies("git branch -D x && git reset --hard"));
    assert!(lab.claude_hook_denies("git branch -D x; rm -rf ~/Developer"));
}

#[test]
fn log_and_ask_first_matches_do_not_hide_a_deny_either() {
    let lab = Lab::new(
        "[general]\ncolor = \"never\"\n\n[policy.rules]\n\"core.git:branch-force-delete\" = \"log\"\n\"core.git:stash-drop\" = \"ask\"\n",
    );
    assert!(!lab.claude_hook_denies("git branch -D x"));
    assert!(lab.claude_hook_denies("git branch -D x && git reset --hard"));
    let (decision, rule) = lab.batch_decision("git stash drop && git reset --hard");
    assert_eq!(decision, "deny");
    assert_eq!(rule, "core.git:reset-hard");
}

#[test]
fn a_whole_pack_downgraded_to_warn_still_lets_other_packs_deny() {
    // Downgrading core.git as a pack must not disarm core.filesystem behind
    // it. (A pack-level warn never relaxes a critical rule, so `reset-hard`
    // itself stays a deny either way.)
    let lab = Lab::new("[general]\ncolor = \"never\"\n\n[policy.packs]\n\"core.git\" = \"warn\"\n");
    assert!(!lab.claude_hook_denies("git stash drop"));
    assert!(lab.claude_hook_denies("git stash drop && git reset --hard"));
    assert!(lab.claude_hook_denies("git stash drop && rm -rf ~/Developer"));
    assert!(lab.claude_hook_denies("git stash drop; rm -rf /"));
}

/// Found in review of the #498 fix: the look-past grants the warn rule, and
/// three nested evaluations (a resolved `$d` invocation, the `$IFS`
/// expansion, an alias body) returned an allowlisted nested result as the
/// answer for the whole line. So with the default config
/// `alias x='git stash drop'; rm -rf /` and `d=git; $d stash drop;
/// git reset --hard` were still allowed — and so was any such line whose
/// nested rule the user had allowlisted.
#[test]
fn a_warn_inside_a_nested_piece_does_not_hide_a_later_deny() {
    let lab = Lab::new(DEFAULTS);
    for command in [
        "alias x=\"git stash drop\"; git reset --hard",
        "alias x=\"git stash drop\"; rm -rf /",
        "alias x='git stash drop'\nrm -rf ~/",
        "alias x=\"git stash drop\"; alias y=\"git reset --hard\"",
        "d=git; $d stash drop; git reset --hard",
        "d=git; $d stash drop; rm -rf /",
        "git${IFS}stash${IFS}drop; git reset --hard",
    ] {
        assert!(lab.claude_hook_denies(command), "{command:?}");
    }
    for command in ["alias x=\"git stash drop\"", "d=git; $d stash drop"] {
        assert!(!lab.claude_hook_denies(command), "{command:?} stays a warn");
    }
}

#[test]
fn an_allowlisted_rule_in_a_nested_piece_covers_only_that_rule() {
    let lab = Lab::new(DEFAULTS);
    let allowlist = "[[allow]]\nrule = \"core.filesystem:rm-rf-general\"\nreason = \"test\"\n";
    for dir in ["xdg/dcg", "home/.config/dcg"] {
        let dir = lab.dir.path().join(dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("allowlist.toml"), allowlist).unwrap();
    }
    assert!(!lab.claude_hook_denies("alias x=\"rm -rf ./build\""));
    assert!(!lab.claude_hook_denies("rm -rf ./build"));
    for command in [
        "alias x=\"rm -rf ./build\"; git reset --hard",
        "d=rm; $d -rf ./build; git reset --hard",
        "rm -rf ./build; git reset --hard",
    ] {
        assert!(lab.claude_hook_denies(command), "{command:?}");
    }
}

/// With confidence scoring on, the first occurrence of a rule can be in doubt
/// (`watch …`, a function body) and downgrade to warn, while the same rule
/// fires again directly later on the line. The evaluator reports only the
/// first occurrence, and the look-past grants the rule for the whole line, so
/// the direct repeat was never judged.
#[test]
fn a_confidence_downgrade_does_not_hide_a_confident_repeat_of_the_rule() {
    let lab = Lab::new(
        "[general]\ncolor = \"never\"\n\n[confidence]\nenabled = true\nwarn_threshold = 0.7\n",
    );
    for command in ["watch rm -rf ./build", "f() { git branch -D main; }"] {
        assert!(
            !lab.claude_hook_denies(command),
            "premise: {command:?} is downgraded on its own"
        );
    }
    for command in [
        "watch rm -rf ./build; rm -rf ./build",
        "f() { rm -rf ./build; }; rm -rf ./build",
        "f() { git branch -D main; }; git branch -D main",
        "case a in a) git branch -D main;; esac; git branch -D main",
    ] {
        assert!(lab.claude_hook_denies(command), "{command:?}");
    }
    // Two doubtful occurrences stay doubtful.
    assert!(!lab.claude_hook_denies("watch rm -rf ./build; f() { rm -rf ./build; }"));
}

/// Second review of #498: the confident-repeat check searched the rule's regex
/// over the raw line, so a repeat only the evaluator's own views see — quotes
/// split inside the flag, an array invocation — was never scored, the
/// downgrade of the first occurrence stood, and the look-past granted the rule
/// for the whole line. All four were allowed at `warn_threshold = 0.7` while
/// each second half denies on its own.
#[test]
fn a_confidence_downgrade_does_not_hide_a_repeat_only_the_evaluator_sees() {
    let lab = Lab::new(
        "[general]\ncolor = \"never\"\n\n[confidence]\nenabled = true\nwarn_threshold = 0.7\n",
    );
    for repeat in ["rm -r''f ./build", "a=(rm -rf ./build); \"${a[@]}\""] {
        assert!(
            lab.claude_hook_denies(repeat),
            "premise: {repeat:?} denies alone"
        );
        for first in ["watch rm -rf ./build", "f() { rm -rf ./build; }"] {
            let command = format!("{first}; {repeat}");
            assert!(lab.claude_hook_denies(&command), "{command:?}");
        }
    }
    assert!(!lab.claude_hook_denies("watch rm -rf ./build; f() { rm -rf ./build; }"));
}

/// Found reviewing #498: `git` run by `watch`, `xargs`, `parallel` or
/// `find -exec` was not in executable position for the Posix hook, so these
/// were allowed while `rm -rf` behind the same wrappers denied — and a warn
/// ahead of them had nothing to hide.
#[test]
fn git_behind_an_exec_wrapper_is_judged_like_rm_behind_one() {
    let lab = Lab::new(DEFAULTS);
    for command in [
        "watch git reset --hard",
        "echo a | xargs git reset --hard",
        "find . -exec git reset --hard \\;",
        "find . -name x -execdir git clean -fdx \\;",
        "parallel git reset --hard ::: a",
        "git stash drop; echo a | xargs git reset --hard",
    ] {
        assert!(lab.claude_hook_denies(command), "{command:?}");
    }
    for command in [
        "watch git status",
        "echo a | xargs git add",
        "find . -exec git log {} \\;",
    ] {
        assert!(!lab.claude_hook_denies(command), "{command:?}");
    }
}

/// Third review of #498. `watch` and `parallel` hand their command words to a
/// shell, so the quoted forms run the command exactly as the unquoted ones do
/// (they hid `rm -rf` as well as git); an option the wrapper table did not
/// know was read as the command (`parallel --retries 3 git …` ran `3`);
/// `env -S` carries the command in one word; and `sudo --user=…`, `doas`,
/// `chronic`, `strace` and similar wrappers whose options are not modeled
/// never put git in executable position. The git rows were allowed through
/// the hook while `rm -rf` behind the same unquoted wrapper denied.
#[test]
fn git_behind_quoted_unmodeled_and_split_string_wrappers_is_judged() {
    let lab = Lab::new(DEFAULTS);
    for command in [
        "watch 'git reset --hard'",
        "watch -n 1 'git reset --hard'",
        "parallel ::: 'git reset --hard'",
        "parallel 'git reset --hard {}' ::: a",
        "parallel --retries 3 git reset --hard ::: a",
        "parallel --env FOO git reset --hard ::: a",
        "env -S'git reset --hard'",
        "env --split-string='git reset --hard'",
        "env -u FOO -S 'git reset --hard'",
        "sudo --user=bob git reset --hard",
        "doas git reset --hard",
        "doas -u root git reset --hard",
        "chronic git reset --hard",
        "strace -f git reset --hard",
        "flock /tmp/lock git reset --hard",
        "taskset -c 0 git reset --hard",
        "uv run git reset --hard",
        "direnv exec . git reset --hard",
        // The quoted runners hid rm the same way.
        "watch 'rm -rf ./build'",
        "watch -n 1 \"rm -rf ./build\"",
        "parallel ::: 'rm -rf ./build'",
        "sudo watch 'rm -rf ./build'",
        "env FOO=1 watch 'rm -rf ./build'",
        // Other command-string runners, and remote/container runners.
        "su -c 'git reset --hard'",
        "su -lc 'rm -rf ./build'",
        "sg wheel -c 'rm -rf ./build'",
        "script -qc 'git reset --hard' /dev/null",
        "nix-shell --run 'rm -rf ./build'",
        "hyperfine 'git reset --hard'",
        "ls | entr -s 'git reset --hard'",
        "ssh host git reset --hard",
        "docker exec app git reset --hard",
        "script -q /dev/null git reset --hard",
    ] {
        assert!(lab.claude_hook_denies(command), "{command:?}");
    }
    for command in [
        "watch 'git status'",
        "parallel ::: 'git status'",
        "parallel echo ::: git reset --hard",
        "xargs echo git reset --hard",
        "env -S'git status'",
        "doas git pull",
        "uv pip install gitpython",
        "echo watch 'rm -rf ./build'",
        "watch -n 5 'ls -la'",
        "su -c 'git status'",
        "ssh git@github.com",
        "hyperfine --warmup 3 'sleep 0.1'",
    ] {
        assert!(!lab.claude_hook_denies(command), "{command:?}");
    }
}

/// Fourth review of the command-string runners (7273b28). Each positive row
/// was allowed through the hook on 7273b28:
///
/// - the runner was only recognized first in its segment or right behind a
///   known wrapper, so a reserved word (`{`, `then`, `do`, `!`), a leading
///   redirect, or a wrapper's own value (`sudo -u bob`, `timeout 5s`,
///   `taskset -c 0`, `strace -f`) hid it;
/// - several words that the runner joins with spaces (`watch`, `ssh`, a
///   `parallel` template, `env -S` plus trailing words) were re-read with
///   their local quoting intact, so `'git reset' --hard` stayed one word;
/// - `watch -tn 1` (value option ending a cluster), `hyperfine
///   --prepare=<cmd>`/`-p<cmd>`, `entr -s -r <cmd>`/`-sr`, `sg group <cmd>`
///   without `-c`, and `ssh host -- <cmd>` were misparsed.
#[test]
fn command_string_runners_behind_keywords_values_and_joined_words_are_judged() {
    let lab = Lab::new(DEFAULTS);
    for command in [
        "watch -tn 1 'git reset --hard'",
        "watch -cn 2 'rm -rf ./build'",
        "watch 'git reset' --hard",
        "ssh host 'git reset' --hard",
        "ssh host -- 'git reset --hard'",
        "ssh host -t 'rm -rf ./build'",
        "env -S'git reset' --hard",
        "parallel 'git reset' --hard ::: a",
        "hyperfine --prepare='git reset --hard' true",
        "hyperfine -p'git reset --hard' true",
        "hyperfine --setup='rm -rf ./build' true",
        "ls | entr -s -r 'git reset --hard'",
        "ls | entr -sr 'rm -rf ./build'",
        "sg wheel 'git reset --hard'",
        "sg - wheel 'rm -rf ./build'",
        "sudo -u bob watch 'git reset --hard'",
        "sudo -u bob su -c 'git reset --hard'",
        "timeout 5s watch 'git reset --hard'",
        "taskset -c 0 watch 'rm -rf ./build'",
        "strace -f parallel ::: 'git reset --hard'",
        "{ watch 'git reset --hard'; }",
        "if true; then watch 'git reset --hard'; fi",
        "for i in 1; do su -c 'rm -rf ./build'; done",
        "! watch 'git reset --hard'",
        "2>/dev/null watch 'git reset --hard'",
        "2> /dev/null watch 'git reset --hard'",
    ] {
        assert!(lab.claude_hook_denies(command), "{command:?}");
    }
    for command in [
        "watch -tn 1 'git status'",
        "watch 'git log' --oneline",
        "ssh host 'git status'",
        "ssh host -- 'git log' -1",
        "hyperfine --prepare='sync' 'cargo build'",
        "hyperfine --export-json out.json 'ls'",
        "ls | entr -s -r 'make test'",
        "sg wheel 'ls -la'",
        "sudo -u bob watch 'df -h'",
        "timeout 5s watch 'ls'",
        "{ watch 'ls'; }",
        "echo watch 'rm -rf ./build'",
        "man watch",
        "docker exec c ls",
        "uv run pytest",
        "direnv exec . make",
    ] {
        assert!(!lab.claude_hook_denies(command), "{command:?}");
    }
}

/// Commands that are nothing but runners are read to a bounded depth: past
/// it the reading is incomplete and the bounded fallback judges the whole
/// command, so the hook answers fast and the later payload is not dropped.
#[test]
fn many_command_string_runners_answer_fast_and_fail_closed() {
    let lab = Lab::new(DEFAULTS);
    // `x ; watch ; watch ; … ; watch 'git reset --hard'`
    let long = format!("x {}'git reset --hard'", "; watch ".repeat(500));
    let started = std::time::Instant::now();
    assert!(lab.claude_hook_denies(&long));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}

/// Fifth review of the command-string runners (2bd9167). Each positive row
/// was allowed through the hook on 2bd9167 (and on 90f3ba6):
///
/// - `2>&1`, `>&2` and `<&0` carry their target, but were taken to consume
///   the next word, so the runner behind them was read as a file name;
/// - `function NAME { … }` and `coproc NAME { … }` read NAME as the command,
///   so the body's first word was an argument;
/// - a redirect before the payload ended the runner's words (`watch
///   2>/dev/null '<cmd>'`, `ssh host 2>/dev/null '<cmd>'`), although the
///   local shell removes it wherever it stands;
/// - a quoted or escaped runner name (`\watch`, `w\atch`, `'su'`, `\ssh`)
///   was not recognized, and the substring prefilter never saw `w\atch`;
/// - a process substitution (`cat <(watch '<cmd>')`) is one word to the
///   tokenizer, so the runner inside it was never at a command position;
/// - `chrt`, `busybox`, `eatmydata`, `fakeroot`, `cgexec`, `flatpak-spawn`,
///   `pkexec` and `run0` run their arguments but were not known wrappers
///   (`eatmydata git reset --hard` itself was allowed).
#[test]
fn command_string_runners_behind_fd_duplications_names_quoting_and_substitutions_are_judged() {
    let lab = Lab::new(DEFAULTS);
    for command in [
        "2>&1 watch 'git reset --hard'",
        ">&2 su -c 'rm -rf ./build'",
        "<&0 watch 'git reset --hard'",
        "FOO=1 2>&1 watch 'git reset --hard'",
        "function f { watch 'git reset --hard'; }; f",
        "function f { parallel ::: 'rm -rf ./build'; }; f",
        "coproc NAME { su -c 'git reset --hard'; }",
        "watch 2>/dev/null 'git reset --hard'",
        "watch > /dev/null 'rm -rf ./build'",
        "su 2>/dev/null -c 'git reset --hard'",
        "env >/dev/null -S'git reset --hard'",
        "parallel 2>/dev/null ::: 'git reset --hard'",
        "ssh host 2>/dev/null 'git reset --hard'",
        "ssh 2>/dev/null host 'rm -rf ./build'",
        "\\watch 'git reset --hard'",
        "w\\atch 'git reset --hard'",
        "'su' -c 'git reset --hard'",
        "\"parallel\" ::: 'rm -rf ./build'",
        "\\ssh host 'git reset --hard'",
        "'ssh' host 'rm -rf ./build'",
        "cat <(watch 'git reset --hard')",
        "diff <(true) <(ssh host 'git reset --hard')",
        "echo >(su -c 'rm -rf ./build')",
        "cat <(cat <(env -S'git reset --hard'))",
        "chrt -f 1 watch 'git reset --hard'",
        "busybox watch 'git reset --hard'",
        "fakeroot su -c 'rm -rf ./build'",
        "cgexec -g cpu:x watch 'git reset --hard'",
        "eatmydata git reset --hard",
        "flatpak-spawn --host git reset --hard",
    ] {
        assert!(lab.claude_hook_denies(command), "{command:?}");
    }
    for command in [
        "2>&1 watch 'df -h'",
        "function f { watch 'ls'; }; f",
        "echo function watch 'git reset --hard'",
        "coproc NAME { su -c 'ls'; }",
        "watch 2>/dev/null 'git status'",
        "ssh host 'git status' 2>&1",
        "ssh h \"ls 2>/dev/null\" 2>&1",
        "ssh host ls /tmp 2>/dev/null",
        "\\watch 'ls'",
        "cat <(ls) <(watch -n1 'date')",
        "diff <(sort a) <(sort b)",
        "eatmydata git status",
        "chrt -f 1 watch 'uptime'",
    ] {
        assert!(!lab.claude_hook_denies(command), "{command:?}");
    }
    // Past the bound on process substitution bodies the reading is partial
    // and the bounded fallback judges the whole command.
    let many = format!("cat {}<(watch 'git reset --hard')", "<(ls) ".repeat(70));
    assert!(lab.claude_hook_denies(&many));
    assert!(!lab.claude_hook_denies(&format!("cat {}", "<(ls) ".repeat(70))));
}

/// Fifth review: a pipeline of thousands of stages went to the bash parser,
/// which reads one long pipeline in superlinear time, so the hook answered
/// `ask` after its deadline, seconds late (`x | env | … | env -S 'ls'`,
/// 60 KB: ~9 s). Past `MAX_PARSED_PIPELINE_STAGES` it is not parsed and its
/// unverified consumers fail closed at once; below it nothing changes.
#[test]
fn a_pipeline_of_thousands_of_stages_answers_fast() {
    let lab = Lab::new(DEFAULTS);
    let long = format!("x {}| sh -c ls", "| cat ".repeat(3000));
    let started = std::time::Instant::now();
    assert!(lab.claude_hook_denies(&long));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    let substitution = format!("echo $(true) {}| sh -c ls", "| cat ".repeat(3000));
    assert!(lab.claude_hook_denies(&substitution));
    assert!(!lab.claude_hook_denies(&format!("x {}| sh -c ls", "| cat ".repeat(50))));
    assert!(!lab.claude_hook_denies(&format!("x {}| sh -c ls", "; cat ".repeat(3000))));
}

/// Sixth review: a redirect or an option around a shell's `-c` hid the
/// command string from the inline-script reader, which expected the options
/// before `-c` and the quoted string right after it. The shell removes a
/// redirect wherever it stands and takes its first operand as the command
/// string, so each of these runs `git reset --hard` (bash, dash, zsh and
/// busybox sh checked). The same redirects (`&>`, `>|`, `{fd}>`), an ANSI-C
/// quoted name (`wat$'c'h`), a quoted name whose plain spelling also stands
/// elsewhere (`echo watch; w\atch …`) and a process substitution inside a
/// word (`--x=<(…)`, which bash expands there too) also still hid a
/// command-string runner's payload.
#[test]
fn shell_command_strings_behind_redirects_and_options_are_judged() {
    let lab = Lab::new(DEFAULTS);
    for command in [
        "sh 2>/dev/null -c 'git reset --hard'",
        "sh 2>&1 -c 'git reset --hard'",
        "sh >/dev/null 2>&1 -c 'git reset --hard'",
        "sh 2> /dev/null -c \"git reset --hard\"",
        "bash &>/dev/null -c 'git reset --hard'",
        "zsh >|/tmp/o -c 'git reset --hard'",
        "dash {fd}>/dev/null -c 'git reset --hard'",
        "busybox sh 2>/dev/null -c 'git reset --hard'",
        "sudo ksh 2>/dev/null -c 'git reset --hard'",
        "sh -c 2>/dev/null 'git reset --hard'",
        "sh -c -- 'git reset --hard'",
        "sh -c - 'git reset --hard'",
        "sh -c -e \"git reset --hard\"",
        "bash -c -o errexit 'git reset --hard'",
        "bash -c 2>&1 -- 'git reset --hard'",
        "bash +e -c 'git reset --hard'",
        "bash -c +e 'git reset --hard'",
        "sh 2>/dev/null -c $CMD",
        "sh -c -- $CMD",
        "python3 2>/dev/null -c 'import shutil; shutil.rmtree(\"/etc\")'",
        "watch &>/dev/null 'git reset --hard'",
        "watch &>>/tmp/log 'git reset --hard'",
        "watch >|/tmp/o 'git reset --hard'",
        ">|/tmp/o watch 'git reset --hard'",
        "{fd}>/dev/null watch 'git reset --hard'",
        "watch {fd}>/dev/null 'git reset --hard'",
        "su &>/dev/null -c 'git reset --hard'",
        "su -c &>/dev/null 'git reset --hard'",
        "ssh host &>/dev/null 'git reset --hard'",
        "ssh host >|/tmp/o 'git reset --hard'",
        "wat$'c'h 'git reset --hard'",
        "s$'s'h host 'git reset --hard'",
        "echo watch; w\\atch 'git reset --hard'",
        "echo watch; wat$'c'h 'git reset --hard'",
        "cat --x=<(watch 'git reset --hard')",
        "cat a<(ssh host 'git reset --hard')",
        "diff --from-file=<(cat <(watch 'git reset --hard')) b",
    ] {
        assert!(lab.claude_hook_denies(command), "{command:?}");
    }
    for command in [
        "sh 2>/dev/null -c 'ls -la'",
        "bash -c -- 'echo hi'",
        "sh -c -e 'git status'",
        "sh 2>/dev/null -c \"git status\"",
        "bash -lc 'cargo build' 2>&1 | tail",
        "bash -c 'git status' >/dev/null 2>&1",
        "python3 2>/dev/null -c 'print(1)'",
        "echo 'sh 2>/dev/null -c git reset --hard'",
        "git commit -m 'sh -c -- git reset --hard is bad'",
        "watch &>/dev/null 'ls'",
        "watch >|/tmp/o 'uptime'",
        "ssh host &>/dev/null 'git status'",
        "wat$'c'h 'df -h'",
        "diff --from-file=<(sort a) b<(sort c)",
        "echo \"--x=<(watch 'git reset --hard')\"",
    ] {
        assert!(!lab.claude_hook_denies(command), "{command:?}");
    }
}

/// Seventh review: the Windows wrappers did not read the redirect view the
/// sixth review added for `sh -c`, so `powershell 2>&1 -EncodedCommand …`
/// and `cmd 2>nul /c …` still hid their payloads; a here-string
/// (`sh <<<x -c …`) was not taken for a redirect either.
#[test]
fn windows_wrappers_and_here_strings_behind_redirects_are_judged() {
    let lab = Lab::new(DEFAULTS);
    // "git reset --hard" and "Get-Date" as base64 UTF-16LE.
    let reset = "ZwBpAHQAIAByAGUAcwBlAHQAIAAtAC0AaABhAHIAZAA=";
    let date = "RwBlAHQALQBEAGEAdABlAA==";
    for command in [
        format!("powershell 2>&1 -EncodedCommand {reset}"),
        "cmd 2>nul /c \"git reset --hard\"".to_string(),
        "cmd >nul /c git reset --hard".to_string(),
        "sh <<<x -c 'git reset --hard'".to_string(),
        "bash <<<'a b' -c 'git reset --hard'".to_string(),
    ] {
        assert!(lab.claude_hook_denies(&command), "{command:?}");
    }
    for command in [
        format!("powershell 2>&1 -EncodedCommand {date}"),
        "cmd 2>nul /c \"dir\"".to_string(),
        "cmd /c dir 2>nul".to_string(),
        "sh <<<x -c 'ls'".to_string(),
        "cat <<<'sh 2>/dev/null -c git reset --hard'".to_string(),
    ] {
        assert!(!lab.claude_hook_denies(&command), "{command:?}");
    }
}

/// Eighth review (A13): the prose of a data heredoc with an UNQUOTED
/// delimiter was read as live commands. `cat <<EOF > notes.md` documenting
/// `watch '…'`, `sh -c '…'` or `ssh h '…'` was denied although `cat` only
/// stores the text; the quoted-delimiter spelling was allowed. The shell runs
/// only the body's substitutions while reading it, so those are still judged,
/// and a body a shell runs — piped to one, fed to one, or written to a file
/// the same command then runs — is judged whole.
#[test]
fn expanding_data_heredoc_bodies_judge_only_what_the_shell_runs() {
    let lab = Lab::new(DEFAULTS);
    for command in [
        "cat <<EOF > notes.md\nwatch 'git reset --hard'\nEOF",
        "cat <<EOF > notes.md\nsh -c 'git reset --hard'\nEOF",
        "cat <<EOF > notes.md\nsh 2>/dev/null -c 'git reset --hard'\nEOF",
        "cat <<EOF > notes.md\nuse a<(watch 'git reset --hard')\nEOF",
        "cat <<EOF > notes.md\nssh h 'git reset --hard'\nEOF",
        "cat <<-EOF > notes.md\n\tuse a<(watch 'git reset --hard')\n\tEOF",
        "git commit -F - <<EOF\nfix: cat a<(ssh h 'git reset --hard') was allowed\nEOF",
        "cat <<EOF > notes.md\neval \"$x\"\nEOF",
        "cat <<EOF > notes.md\nbuilt $(date +%F): watch 'git reset --hard'\nEOF",
        "cat <<EOF > notes.md\nrm -rf ~/src\nEOF\ngit add notes.md",
    ] {
        assert!(!lab.claude_hook_denies(command), "{command:?}");
    }
    for command in [
        "cat <<EOF > notes.md\n$(git reset --hard)\nEOF",
        "cat <<EOF > notes.md\n`git reset --hard`\nEOF",
        "cat <<EOF > notes.md\nx $(watch 'git reset --hard') y\nEOF",
        "cat <<EOF > notes.md\n${x:-$(git reset --hard)}\nEOF",
        "cat <<EOF > notes.md\n$(( $(git reset --hard) ))\nEOF",
        "cat <<EOF > notes.md\n$\\\n(git reset --hard)\nEOF",
        "cat <<EOF | sh\nwatch 'git reset --hard'\nEOF",
        "bash <<EOF\nwatch 'git reset --hard'\nEOF",
        "ssh h <<EOF\ngit reset --hard\nEOF",
        "tee x.sh <<EOF\nrm -rf ~/src\nEOF\nsh x.sh",
        "cat <<EOF > x.sh && ./x.sh\nrm -rf ~/src\nEOF",
        "cat > x.sh <<'EOF'\nrm -rf ~/src\nEOF\ncat x.sh | bash",
        "cat <<EOF > x.sh; . ./x.sh\ngit reset --hard\nEOF",
    ] {
        assert!(lab.claude_hook_denies(command), "{command:?}");
    }
}

/// Eighth review (A14): spellings that still hid a command from the rules
/// (all allowed on v0.14.4 and v0.15.1).
#[test]
fn eighth_review_spellings_are_judged() {
    let lab = Lab::new(DEFAULTS);
    for command in [
        // A quoted option after a shell's `-c`.
        "bash -c -o 'errexit' 'git reset --hard'",
        "sh -c -O 'extglob' 'git reset --hard'",
        "bash -c '-e' 'git reset --hard'",
        // A runner named through `$'…'` escapes.
        "$'\\x77atch' 'git reset --hard'",
        "$'\\167atch' 'git reset --hard'",
        "w$'\\x61'tch 'git reset --hard'",
        // A runner named at run time.
        "w${x}atch 'git reset --hard'",
        "${W}atch 'git reset --hard'",
        "sudo $W 'git reset --hard'",
        "$(echo watch) 'git reset --hard'",
        // A command word that is a substitution printing the command.
        "$(echo git reset --hard)",
        "$(printf 'git reset --hard')",
        "$(echo git reset) --hard",
        "\"$(echo git)\" reset --hard",
        // A find action spelled through quoting.
        "find ~/src '-delete'",
        "find ~/src -de''lete",
        "find ~/src -de\\lete",
        "find ~/src -perm -u+x \"-delete\"",
        // A relative write after `cd` to `/` or an ancestor of a protected root.
        "cd / && echo x >> etc/sudoers",
        "cd // && echo x > etc/passwd",
        "cd /usr/.. && echo x >> etc/sudoers",
        "cd / ; tee -a etc/sudoers <<< x",
        "cd /home && echo x >> luna/.netrc",
        // A dashed Git built-in behind a wrapper.
        "xargs git-reset --hard",
        "echo . | xargs -0 git-clean -fdx",
        "find . -exec git-clean -fdx \\;",
        // Found by the self-review of this round (pre-existing).
        "bash '-c' 'git reset --hard'",
        "bash -o 'errexit' -c 'git reset --hard'",
        "f'ind' ~/src '-delete'",
        "echo $\\\n(git reset --hard)",
        "awk -f - <<'EOF'\nBEGIN{system(\"rm -rf ~/src\")}\nEOF",
        "echo 'git reset --hard' | while read l; do eval \"$l\"; done",
    ] {
        assert!(lab.claude_hook_denies(command), "{command:?}");
    }
    for command in [
        "bash -c -o 'errexit' 'ls'",
        "$'\\x77atch' 'uptime'",
        "w${x}atch 'df -h'",
        "echo w${x}atch 'git reset --hard'",
        "$HOME/.local/bin/tool 'git reset --hard'",
        "sudo -u \"$USER\" git commit -m 'rm -rf is dangerous'",
        "awk -f prog.awk <<'EOF'\nrm -rf ~/src\nEOF",
        "$(echo ls) -la",
        "echo $(echo git reset --hard)",
        "git commit -m \"$(echo git reset --hard)\"",
        "find ~/src -name '-delete'",
        "find ~/src -exec grep '-delete' {} \\;",
        "cd / && ls etc/sudoers",
        "cd /tmp && echo x >> etc/sudoers",
        "xargs git-log",
        "echo git-reset --hard",
    ] {
        assert!(!lab.claude_hook_denies(command), "{command:?}");
    }
}

/// Eighth review: a long run of option-like words before a shell's `-c`
/// (`c -c -c … sh -c '…'`) took seconds; the hook must answer in time and
/// still find the payload.
#[test]
fn long_option_runs_before_a_command_string_answer_fast() {
    let lab = Lab::new(DEFAULTS);
    for unit in ["c -", "c -c ", "sh -c -e "] {
        let long = format!(
            "{} sh -c 'git reset --hard'",
            unit.repeat(30_000 / unit.len())
        );
        let started = std::time::Instant::now();
        assert!(lab.claude_hook_denies(&long), "{unit:?}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(3),
            "{unit:?}: {:?}",
            started.elapsed()
        );
    }
}

/// bd-2bm3: bash brace-expands a list in command position into the command
/// it runs, so `{rm,-rf,~}` is `rm -rf ~`; a list whose alternatives are
/// options makes those options (`rm {-rf,~}`). Lists naming files stay as
/// they were.
#[test]
fn brace_lists_that_make_the_command_are_judged() {
    let lab = Lab::new(DEFAULTS);
    for command in [
        "{rm,-rf,~}",
        "{git,reset,--hard}",
        "echo x; {git,reset,--hard}",
        "sudo {git,reset,--hard}",
        "{git,reset} --hard",
        "{rm,-rf} ~/src",
        "rm {-rf,~/src}",
    ] {
        assert!(lab.claude_hook_denies(command), "{command:?}");
    }
    for command in [
        "echo {a,b}",
        "mkdir -p src/{a,b}",
        "{echo,hi}",
        "cp config.toml{,.bak}",
        "touch file{1,2,3}",
        // Judged as the command it becomes, like `rm -rf /tmp/build-x`.
        "{rm,-rf,/tmp/build-x}",
    ] {
        assert!(!lab.claude_hook_denies(command), "{command:?}");
    }
}

/// bd-v9hh: a command the shell runs later — a `trap` handler (EXIT fires
/// when the tool call's shell exits), `PROMPT_COMMAND`, a prompt's
/// substitutions, the file `BASH_ENV` names — was argv data to every rule.
#[test]
fn deferred_shell_commands_are_judged() {
    let lab = Lab::new(DEFAULTS);
    for command in [
        "trap 'rm -rf ~' EXIT",
        "trap \"git reset --hard\" EXIT; true",
        "trap -- 'git reset --hard' INT TERM EXIT",
        "trap 'git reset --hard' ERR; false",
        "PROMPT_COMMAND='rm -rf ~'",
        "export PROMPT_COMMAND='git reset --hard'",
        "PROMPT_COMMAND=('git reset --hard')",
        "PS1='$(git reset --hard)'",
        "PS4='`git reset --hard`' bash -xc true",
        "builtin trap 'rm -rf ~' EXIT",
        "{ trap 'rm -rf ~' EXIT; }",
        "(trap 'rm -rf ~' EXIT)",
        "f() { trap 'rm -rf ~' RETURN; }; f",
        "BASH_ENV=<(echo 'rm -rf ~') bash -c true",
    ] {
        assert!(lab.claude_hook_denies(command), "{command:?}");
    }
    for command in [
        "trap - EXIT",
        "trap '' INT",
        "trap 'rm -f /tmp/lock' EXIT",
        "tmp=$(mktemp) && trap 'rm -f \"$tmp\"' EXIT",
        "trap -p",
        "echo trap 'rm -rf ~' EXIT",
        "PROMPT_COMMAND='history -a'",
        "PS1='\\u@\\h:\\w\\$ '",
        "echo PROMPT_COMMAND='rm -rf ~'",
        // A handler is judged after the text before it, as if it ran there:
        // these clean up what that text made or a temporary path.
        "tmp=$(mktemp -d); trap 'rm -rf \"$tmp\"' EXIT",
        "trap 'rm -rf /tmp/build-x' EXIT",
        "PS4='+ $(date +%s) ' bash -x script.sh",
    ] {
        assert!(!lab.claude_hook_denies(command), "{command:?}");
    }
}
