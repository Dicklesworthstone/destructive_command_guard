//! #666: with `containers.docker` enabled, a quoted `for` loop word naming
//! `docker rm -f` was denied as `containers.docker:rm-force` although the loop
//! body only prints it. The docker rules now stand down for that shape: the
//! text is one quoted word of a `for`/`select` list with a lowercase loop
//! variable (not zsh's `prompt`, `mailpath` or a search path), and every
//! other statement only prints (`printf` with a literal format of text
//! conversions and no options, `echo`, `:`, `true`, and `break` or `continue`
//! with at most a literal count), with no pipe,
//! redirection, substitution, assignment or function definition anywhere.
//! Every other way the loop text could reach a shell still denies.
//!
//! Every command is classifier input only, sent to the real binary through
//! `dcg hook --batch` with an empty HOME. Nothing is executed.

use std::io::Write;
use std::process::{Command, Stdio};

/// `(decision, rule id)` for each command, judged by `dcg hook --batch` with
/// `DCG_PACKS` set to `packs`.
fn verdicts(commands: &[&str], packs: &str) -> Vec<(String, String)> {
    let scratch = tempfile::tempdir().expect("isolated test state");
    let home = scratch.path().join("home");
    std::fs::create_dir(&home).expect("isolated home");
    let mut input = String::new();
    for command in commands {
        input.push_str(
            &serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": command},
            })
            .to_string(),
        );
        input.push('\n');
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"))
        .args(["hook", "--batch"])
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("APPDATA", home.join(".config"))
        .env("LOCALAPPDATA", home.join(".local"))
        .env("TMPDIR", scratch.path())
        .env("TEMP", scratch.path())
        .env("TMP", scratch.path())
        .env("DCG_PACKS", packs)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HISTORY_ENABLED", "false")
        .env("DCG_HISTORY_DISABLED", "1")
        // Completed semantic verdicts, not assertions about host scheduling.
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .env("DCG_AST_TIMEOUT_MS", "5000")
        .current_dir(scratch.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the DCG classifier");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(input.as_bytes())
        .expect("write classifier input");
    let output = child.wait_with_output().expect("classifier exit");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let results: Vec<(String, String)> = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let json: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|error| {
                panic!(
                    "{error}: {line}; stderr={}",
                    String::from_utf8_lossy(&output.stderr)
                )
            });
            (
                json["decision"].as_str().unwrap_or_default().to_string(),
                json["rule_id"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    assert_eq!(
        results.len(),
        commands.len(),
        "one verdict per command; stdout={stdout}; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    results
}

const DOCKER_ONLY: &str = "containers.docker";
const WITH_CORE: &str = "core,containers.docker";
// An unrelated pack: the verdict must not depend on which other packs are on.
const WITH_POSTGRES: &str = "database.postgresql,containers.docker";
const PACK_SETS: [&str; 3] = [DOCKER_ONLY, WITH_CORE, WITH_POSTGRES];

/// Every command gets `expected` under every pack set; all mismatches are
/// reported together.
fn assert_all(commands: &[&str], expected: &str) {
    let mut mismatches = Vec::new();
    for packs in PACK_SETS {
        for (command, (decision, rule)) in commands.iter().zip(verdicts(commands, packs)) {
            if decision != expected {
                mismatches.push(format!("{packs}: {command:?} => {decision} {rule}"));
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "expected {expected}:\n{}",
        mismatches.join("\n")
    );
}

#[test]
fn quoted_docker_loop_words_that_are_only_printed_are_allowed_issue_666() {
    let commands = [
        // The report's row and its single-word variant.
        "for c in 'git status' 'docker rm -f web'; do printf '%s\\n' \"$c\"; done",
        "for c in 'docker rm -f web'; do printf '%s\\n' \"$c\"; done",
        "for c in 'docker rm -f'; do printf '%s\\n' \"$c\"; done",
        "for c in \"docker rm -f web\" 'docker rmi -f img'; do echo \"$c\"; done",
        "for cmd in 'docker system prune -af' 'docker rm -f web'; do echo \"$cmd\"; done; true",
        "select c in 'docker rm -f web'; do echo \"$c\"; break; done",
        "for c in 'git status' 'docker rm -f web'\ndo\n  printf '%s\\n' \"$c\"\ndone",
        // Text conversions with flags and widths, a format with no
        // conversion, and literal loop counts.
        "for c in 'docker rm -f web'; do printf '%-20s|%5.3s|%q|%b%%\\t\\n' \"$c\" \"$c\" \"$c\" \"$c\"; done",
        "for c in 'docker rm -f web'; do printf \"%s \" \"$c\"; done",
        "for c in 'docker rm -f web'; do printf 'item\\n'; done",
        "for i in 1; do for c in 'docker rm -f web'; do echo \"$c\"; break 2; done; done",
        "for c in 'docker rm -f web'; do echo \"$c\"; continue 1; done",
    ];
    assert_all(&commands, "allow");
}

#[test]
fn loop_words_that_can_reach_a_shell_still_deny_issue_666() {
    let commands = [
        // Controls: real docker command words, inside and after a loop.
        "docker rm -f web",
        "for i in 1; do docker rm -f web; done",
        "for i in 1; do 'docker' rm -f web; done",
        "for c in 'docker rm -f web'; do echo \"$c\"; done; docker rm -f web",
        // The loop body runs the word.
        "for c in 'docker rm -f web'; do $c; done",
        "for c in 'docker rm -f web'; do ${c}; done",
        "for c in 'docker rm -f web'; do command $c; done",
        "for c in 'docker rm -f web'; do true && $c; done",
        "for c in 'git status' 'docker rm -f web'; do eval \"$c\"; done",
        "for c in 'docker rm -f web'; do builtin eval \"$c\"; done",
        "for c in 'docker rm -f web'; do sh -c \"$c\"; done",
        "for c in 'docker rm -f web'; do $($c); done",
        "for c in 'docker rm -f web'; do printf '%s' \"$($c)\"; done",
        "for c in 'docker rm -f web'; do `echo $c`; done",
        "for c in 'docker rm -f web'; do sh <<EOF\n$c\nEOF\ndone",
        "select c in 'docker rm -f web'; do $c; done",
        // The word is used after the loop.
        "for c in 'docker rm -f web'; do printf '%s\\n' \"$c\"; done; $c",
        "for c in 'docker rm -f web'; do printf '%s\\n' \"$c\"; done\n$c",
        "for c in 'docker rm -f web'; do :; done; eval \"$c\"",
        "for c in 'docker rm -f web'; do echo; done; sh -c \"$c\"",
        // The printed text goes to a shell or to a file that runs.
        "for c in 'docker rm -f web'; do printf '%s\\n' \"$c\"; done | sh",
        "for c in 'docker rm -f web'; do echo \"$c\" | bash; done",
        "for c in 'docker rm -f web'; do echo \"$c\"; done | xargs -I{} sh -c '{}'",
        "for c in 'docker rm -f web'; do echo \"$c\" > x.sh; done; chmod +x x.sh; ./x.sh",
        "for c in 'docker rm -f web'; do echo \"$c\"; done >> ~/.bashrc",
        // A program that runs a command string it is handed.
        "for c in 'docker rm -f web'; do hyperfine \"$c\"; done",
        "for c in 'docker rm -f web'; do watchexec \"$c\"; done",
        "for c in 'docker rm -f web'; do watch \"$c\"; done",
        "for c in 'docker rm -f web'; do sg docker \"$c\"; done",
        "for c in 'docker rm -f web'; do flock /tmp/l -c \"$c\"; done",
        "for c in 'docker rm -f web'; do man -P \"$c\" ls; done",
        "for c in 'docker rm -f web'; do git -c core.pager=\"$c\" log; done",
        "for c in 'docker rm -f web'; do rsync -e \"$c\" a b:; done",
        "for c in 'docker rm -f web'; do ssh host \"$c\"; done",
        "for c in 'docker rm -f web'; do tmux send-keys \"$c\" Enter; done",
        "for c in 'docker rm -f web'; do screen -X stuff \"$c\"; done",
        // An exported setting that another program runs, in this command or
        // a later one in the same shell.
        "for PAGER in 'docker rm -f web'; do git log; done",
        "for PAGER in 'docker rm -f web'; do printf '%s\\n' \"$PAGER\"; done",
        "for c in 'docker rm -f web'; do PAGER=$c git log; done",
        "for c in 'docker rm -f web'; do export PAGER=\"$c\"; man ls; done",
        "for c in 'docker rm -f web'; do printf -v PAGER '%s' \"$c\"; export PAGER; man ls; done",
        // Only text conversions and literal loop counts take the reading: a
        // numeric conversion, `%n`, a `*` width, a `%N$` position, an escape
        // other than a character escape, a glob in the format, or a loop
        // count that is not a literal number keeps the docker verdict.
        "for c in 'docker rm -f web'; do printf '%d\\n' \"$c\"; done",
        "for c in 'docker rm -f web'; do printf '%s %i\\n' x \"$c\"; done",
        "for c in 'docker rm -f web'; do printf \"%x\" \"$c\"; done",
        "for c in 'docker rm -f web'; do printf %f \"$c\"; done",
        "for c in 'docker rm -f web'; do printf '%c' \"$c\"; done",
        "for c in 'docker rm -f web'; do printf '%n' \"$c\"; done",
        "for c in 'docker rm -f web'; do printf '%*s' \"$c\" x; done",
        "for c in 'docker rm -f web'; do printf '%.*s' \"$c\" x; done",
        "for c in 'docker rm -f web'; do printf '%1$s' \"$c\"; done",
        "for c in 'docker rm -f web'; do printf '%s%' \"$c\"; done",
        "for c in 'docker rm -f web'; do printf '\\045d' \"$c\"; done",
        "for c in 'docker rm -f web'; do printf * \"$c\"; done",
        "for c in 'docker rm -f web'; do printf [%]d \"$c\"; done",
        "for c in 'docker rm -f web'; do break \"$c\"; done",
        "for c in 'docker rm -f web'; do continue \"$c\"; done",
        "for c in 'docker rm -f web'; do echo \"$c\"; break -1; done",
        "select c in 'docker rm -f web'; do echo \"$c\"; break \"$c\"; done",
        // `printf -v` spelled through a variable, so no word starts with `-`.
        "for o in -v; do for c in 'docker rm -f web'; do printf \"$o\" PAGER '%s' \"$c\"; done; done",
        // zsh: `prompt` is PS1, expanded with PROMPT_SUBST at the next prompt.
        "for prompt in '$(docker rm -f web)'; do echo \"$prompt\"; done",
        // zsh: a `mailpath` message goes through command substitution at the
        // next mail check; `path` is PATH.
        "for mailpath in '/tmp/inbox?$(docker rm -f web)'; do echo \"$mailpath\"; done",
        "for path in 'docker rm -f web'; do echo \"$path\"; done",
        // zsh: `$v[i]` evaluates the subscript `i` as arithmetic, and `i`
        // holds a substitution.
        "for i in 'x[$(docker rm -f web)]'; do echo \"$v[i]\"; done",
        // printf or echo rebound by the command itself.
        "printf() { eval \"$2\"; }; for c in 'docker rm -f web'; do printf '%s\\n' \"$c\"; done",
        "printf() { $2; }; for c in 'docker rm -f web'; do printf '%s\\n' \"$c\"; done",
        "function printf { $2; }; for c in 'docker rm -f web'; do printf '%s\\n' \"$c\"; done",
        "alias printf=eval\nfor c in 'docker rm -f web'; do printf \"$c\"; done",
        "hash -p /bin/sh printf; for c in 'docker rm -f web'; do printf -c \"$c\"; done",
        "enable -f ./printf.so printf; for c in 'docker rm -f web'; do printf '%s\\n' \"$c\"; done",
        "PATH=/tmp/x:$PATH; for c in 'docker rm -f web'; do printf '%s\\n' \"$c\"; done",
        // Quoted loop text handed to a shell as a whole.
        "sh -c \"for c in 'docker rm -f web'; do \\$c; done\"",
        "bash -c 'for c in \"docker rm -f web\"; do $c; done'",
        "eval \"for c in 'docker rm -f web'; do \\$c; done\"",
    ];
    assert_all(&commands, "deny");
}
