//! Process-signal patterns: kills that choose their targets by pattern, by a
//! parent-tree walk or by broadcast instead of by a PID the caller recorded.
//!
//! Opt-in (`enabled = ["system.processes"]`). `pkill` and `killall` are routine
//! on a single-user laptop, but on a workstation or build host shared by several
//! coding agents a pattern kill reaches every agent, terminal and service the
//! user owns. Two incidents on one developer Mac shaped these rules:
//!
//! - `pkill -f 'sleep 90' -P 1`. BSD/macOS `pkill` stops reading options at the
//!   first pattern, so `-P` and `1` became two more patterns and every process
//!   with a `1` in its argv got SIGTERM: agent panes, the terminal, a launchd
//!   service.
//! - `kill_tree() { for c in $(pgrep -P $p); do kill_tree $c; done; kill -TERM $p; }`
//!   was handed `$(ps -o ppid= -p <job>)` for a `nohup`'d job whose parent was
//!   launchd (PID 1). It walked down from PID 1 and SIGTERMed about 220 user
//!   processes until the tool call timed out.
//!
//! Deliberately not blocked: `kill <literal pid>`, `kill -TERM -- -$PGID` of a
//! recorded job (agents stop their own process groups this way many times a
//! day), `kill -0`, `kill -l`, `kill %1`, `kill $!` and `kill "$(cat <pidfile>)"`.
//!
//! The rules were first proven as an external YAML pack: 129 corpus cases on
//! dcg 0.15.3 and 0.17.0, and a replay of 3,541 real agent kill/launchctl
//! commands in which nearly every denial was a genuine pattern kill (bd-wx2x).

use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Keywords shared by the pack and its `PACK_ENTRIES` row, so the two lists
/// cannot drift (#441).
///
/// `kill` also covers `pkill`, `killall`, `os.kill(` and `process.kill(`, but
/// those words are listed anyway so each rule's own command word is visible
/// here. `ssh` lets the remote-command backstop run when the heredoc extractor
/// is off, `launchctl` gates the domain bootout rule, and `psutil` gates the
/// `process_iter()` loops that call `.terminate()` or `.send_signal()` without
/// any `kill`.
pub const KEYWORDS: &[&str] = &[
    "kill",
    "pkill",
    "killall",
    "killall5",
    "launchctl",
    "ssh",
    "psutil",
];

const RECORDED_PID_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "kill -TERM \"$(cat {pidfile})\"",
        "Signal the PID you saved (`echo $! > {pidfile}`) when you started the job",
    ),
    PatternSuggestion::new(
        "ps -o pid,ppid,pgid,command -p {pid}",
        "Confirm the PID is still your process before signalling it",
    ),
    PatternSuggestion::new(
        "timeout -k 10 600 {command}",
        "Bound the job when you start it, so it never needs a kill",
    ),
];

const SINGLE_PROCESS_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "kill -HUP {pid}",
        "Name the signal and one PID; `kill -1` is read as a target, not as SIGHUP",
    ),
    PatternSuggestion::new(
        "kill -TERM -- -{pgid}",
        "Stop a process group you started and recorded",
    ),
];

const REMOTE_SUGGESTIONS: &[PatternSuggestion] = &[PatternSuggestion::new(
    "ssh {host} 'P=$(cat {pidfile}); kill -TERM \"$P\"'",
    "Read the PID you recorded on that host, then signal only it",
)];

const INTERPRETER_SUGGESTIONS: &[PatternSuggestion] = &[PatternSuggestion::new(
    "proc = subprocess.Popen(...); proc.terminate()",
    "Keep the handle of the process you started and stop that one",
)];

const LAUNCHCTL_SUGGESTIONS: &[PatternSuggestion] = &[PatternSuggestion::new(
    "launchctl bootout gui/$(id -u)/{label}",
    "Boot out one named service instead of the whole domain",
)];

/// Create the Processes pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "system.processes".to_string(),
        name: "Processes",
        description: "Protects shared machines against kills that pick their targets by \
                      pattern, parent-tree walk or broadcast: pkill, killall, kill -1, \
                      pgrep/lsof/ps-fed kill loops, xargs/find kills, remote pattern kills \
                      over ssh, interpreter broadcast kills and launchctl domain bootouts \
                      (opt-in)",
        keywords: KEYWORDS,
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // A kill whose every operand is a literal PID, a job spec, `$!`, a plain
        // variable or a pidfile read back with `$(cat f)` / `$(< f)`, and nothing
        // else in the segment. The whole segment is anchored, so text after the
        // operands (`kill $(cat x.pid) $(pgrep y)`) loses the exemption and
        // `kill-computed-pids` still answers. Only a stderr/stdout redirect to a
        // descriptor or /dev/null may follow.
        safe_pattern!(
            "kill-recorded-pidfile",
            r#"^\s*kill(?:\s+-[A-Za-z0-9]+|\s+-[sn]\s+\S+)?(?:\s+--)?(?:\s+"?(?:\$\(\s*(?:cat\s+|<\s*)(?:[^()`;|&$]|\$(?!\())+\)|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\$!|[0-9]+|%[0-9]+)"?)+(?:\s+[0-9]?>>?\s*(?:&[0-9]|/dev/null))*\s*$"#
        ),
    ]
}

#[allow(clippy::too_many_lines)]
fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "pkill",
            r"\bpkill\b",
            "pkill signals every process whose name or command line matches a pattern.",
            High,
            "A pattern kill on a shared machine also reaches other agents, terminals, \
             desktop apps and services that happen to match. On BSD and macOS, pkill \
             stops reading options at the first pattern, so `pkill -f 'x' -P 1` treats \
             `-P` and `1` as two more patterns and signals every process with a 1 in its \
             command line.\n\n\
             Record the PID when you start a job and signal only that:\n  \
             cmd & echo $! > job.pid\n  \
             kill -TERM \"$(cat job.pid)\"",
            RECORDED_PID_SUGGESTIONS,
            executables = ["pkill"]
        ),
        destructive_pattern!(
            "killall",
            r"\bkillall5?\b",
            "killall signals every process with a given name, including other users' work.",
            High,
            "killall matches by name across the whole machine. Other agents' builds, \
             terminals and services share names with yours (`node`, `cargo`, `python3`), \
             and killall5 signals every process outside the caller's session.\n\n\
             Signal the PIDs you recorded instead:\n  \
             kill -TERM \"$(cat job.pid)\"",
            RECORDED_PID_SUGGESTIONS,
            executables = ["killall", "killall5"]
        ),
        destructive_pattern!(
            "kill-every-process",
            r"(?<![\w-])kill(?:\s+-[sn]\s+\S+|\s+-[A-Za-z0-9]+)*?\s+(?:--\s+)?-1(?!\w)",
            "kill -1 signals every process the user owns (every app, terminal and agent).",
            Critical,
            "A target of -1 means \"every process I am allowed to signal\": as root that \
             is the whole machine, as a user it is every app, terminal, agent and daemon \
             they own. `kill -1 <pid>` in particular is often meant as SIGHUP but reads \
             -1 as a target.\n\n\
             Write the signal by name and give one PID:\n  \
             kill -HUP <pid>",
            SINGLE_PROCESS_SUGGESTIONS,
            executables = ["kill", "builtin"]
        ),
        // The PIDs come from a command substitution evaluated at run time. A
        // pidfile read back on its own (`kill "$(cat job.pid)"`) is exempted by
        // the safe pattern above; `kill -0` only probes.
        destructive_pattern!(
            "kill-computed-pids",
            r#"(?<![\w.-])kill(?!\s+-0\b)(?:\s+[^\s;&|]+)*?\s+"?(?:\$\(|`)"#,
            "The PIDs to kill are computed by a command substitution at run time.",
            High,
            "`kill $(pgrep ...)`, `kill $(lsof -t ...)` and `kill $(ps -o ppid= ...)` \
             signal whatever the lookup returns at that moment: another agent's process, \
             an app, or the init process itself (PID 1), whose children are everything the \
             user runs. `ps -o ppid=` of a nohup'd job is PID 1.\n\n\
             Read a PID you recorded into a variable first, then signal it:\n  \
             P=$(cat job.pid); kill -TERM \"$P\"",
            RECORDED_PID_SUGGESTIONS,
            executables = ["kill", "builtin"]
        ),
        destructive_pattern!(
            "xargs-kill",
            r"\bxargs\b[^|;&\n]*?(?<![\w-])kill(?![\w-])",
            "Piping a PID lookup into xargs kill signals whatever the lookup matched.",
            High,
            "`pgrep ... | xargs kill` and `lsof -t ... | xargs kill` are pattern kills: \
             the lookup matches every process with that name or open file, not just \
             yours.\n\n\
             Signal the PIDs you recorded when you started your processes:\n  \
             kill -TERM \"$(cat job.pid)\"",
            RECORDED_PID_SUGGESTIONS,
            executables = ["xargs"]
        ),
        destructive_pattern!(
            "find-exec-kill",
            r"\bfind\b[^|;&\n]*?-exec(?:dir)?\s+(?:\S*/)?kill(?![\w-])",
            "find -exec kill signals processes chosen by a file search.",
            High,
            "The PIDs come from whatever files the search finds, and a stale pidfile \
             names a PID that has since been reused by an unrelated process.\n\n\
             Check each PID before signalling it:\n  \
             ps -o pid,ppid,pgid,command -p <pid>",
            RECORDED_PID_SUGGESTIONS,
            executables = ["find"]
        ),
        // Unscoped on purpose: the lookup and the kill are different segments
        // (`p=$(pgrep x); kill $p`, `for c in $(pgrep -P $p); do kill $c; done`,
        // `ps ... | while read p; do kill $p; done`), so no single argv0 owns the
        // match. The kill must take a variable operand, which a literal-PID kill
        // later in the same command does not (`pgrep -fl x; kill 12345`).
        destructive_pattern!(
            "pid-lookup-feeds-kill",
            r#"(?s)\A.*?(?:(?<![\w/.-])(?:/usr/bin/)?(?:pgrep|pidof)\s|(?<![\w/.-])lsof\b[^|;&\n]*?\s-[A-Za-z]*t|(?:\$\(|`)\s*ps\b[^)`]*?\bppid=|(?:\$\(|`)\s*ps\b(?![^)`]*?\s-p\s)|(?<![\w/.-])ps\b[^|;&\n]*\|[^\n]*?\bwhile\b).*?(?<![\w.-])kill(?!\s+-0\b)(?:\s+-[A-Za-z0-9]+|\s+-[sn]\s+\S+)*(?:\s+--)?\s+"?-?\\?\$"#,
            "A process lookup by pattern (pgrep, pidof, lsof -t, a ps listing or ps -o ppid=) feeds a kill in the same command.",
            High,
            "Looking PIDs up by pattern and killing them in one command, often in a loop \
             or a recursive kill_tree function, kills whatever the lookup returned. When \
             the lookup returns the parent of a nohup'd job, that parent is init or \
             launchd (PID 1), and a tree walk from there signals every process the user \
             runs.\n\n\
             Look up in one command, check each PID, then signal only your own recorded \
             PIDs in a separate command:\n  \
             pgrep -fl <pattern>\n  \
             ps -o pid,ppid,pgid,command -p <pid>",
            RECORDED_PID_SUGGESTIONS
        ),
        // Backstop for when the heredoc extractor does not lift the remote
        // command out of `ssh host '...'`; with it on, the local rules above
        // answer for the extracted text as well.
        destructive_pattern!(
            "ssh-remote-pattern-kill",
            r#"\bssh\b.*?(?:(?<![\w|-])(?:pkill|killall5?)\s+(?:-|['"\w^])|(?<![\w.-])kill(?:\s+-[A-Za-z0-9]+)*?\s+(?:--\s+)?-1(?!\w)|(?<![\w/.-])(?:pgrep|pidof)\s.*?(?<![\w.-])kill(?!\s+-0\b)(?:\s+-[A-Za-z0-9]+)*(?:\s+--)?\s+"?-?\\?\$)"#,
            "The remote command kills processes by pattern on another host.",
            High,
            "Remote build and CI hosts run other people's and other agents' jobs, \
             workers and services. A pattern kill there stops their work too.\n\n\
             Read the PID you recorded on that host, then signal only it:\n  \
             ssh <host> 'P=$(cat job.pid); kill -TERM \"$P\"'",
            REMOTE_SUGGESTIONS,
            executables = ["ssh"]
        ),
        // Unscoped: the code arrives as an interpreter argument or heredoc body
        // (`python3 -c '...'`, `node -e '...'`).
        destructive_pattern!(
            "interpreter-signals-everything",
            r"(?:\bos\.kill\(\s*-1\b|\bos\.killpg\(\s*[01]\s*,|\bprocess\.kill\(\s*-1\b|\bpsutil\.process_iter\b[\s\S]*?\.(?:kill|terminate|send_signal)\(|\.(?:kill|terminate|send_signal)\([^)]*\)[\s\S]*?\bpsutil\.process_iter\b)",
            "An inline script signals every process (-1, process group 0 or 1) or kills processes found by a psutil scan.",
            High,
            "`os.kill(-1, ...)` and `process.kill(-1)` signal every process the user owns; \
             `os.killpg(0, ...)` signals the caller's own process group (often the agent \
             and its shell) and `os.killpg(1, ...)` init's; a `psutil.process_iter()` loop \
             that kills its matches is a pattern kill.\n\n\
             Keep the handle of the process you started and stop that one:\n  \
             proc = subprocess.Popen(...); proc.terminate()",
            INTERPRETER_SUGGESTIONS
        ),
        destructive_pattern!(
            "launchctl-bootout-domain",
            r"\blaunchctl\s+bootout\s+(?:gui|user|login)/(?:[0-9]+|\$\{?UID\}?|\$\([^)]*\)|`[^`]*`)(?=\s*(?:$|[;&|)]))",
            "Booting out a whole launchd domain stops every app and agent in the user session.",
            Critical,
            "`launchctl bootout gui/<uid>` with no service name tears down the user's \
             entire GUI domain: every app, login item, terminal and agent in the session.\n\n\
             Name the one service:\n  \
             launchctl bootout gui/$(id -u)/<label>",
            LAUNCHCTL_SUGGESTIONS,
            executables = ["launchctl"]
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn pack_is_well_formed() {
        let pack = create_pack();
        validate_pack(&pack);
        assert_eq!(pack.id, "system.processes");
        for pattern in &pack.destructive_patterns {
            assert!(
                pattern.explanation.is_some(),
                "{:?} has no explanation",
                pattern.name
            );
            assert!(
                !pattern.suggestions.is_empty(),
                "{:?} has no suggestion",
                pattern.name
            );
        }
    }

    /// The two incidents the pack exists for, verbatim apart from the PIDs.
    #[test]
    fn the_incident_commands_are_denied() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "pkill -f 'sleep 90' -P 1", "pkill");
        assert_blocks_with_pattern(
            &pack,
            "kill_tree() { local p=$1; for c in $(pgrep -P $p); do kill_tree $c; done; \
             kill -TERM $p 2>/dev/null; }; for p in $(pgrep -f 'verify_loop[.]sh'); do \
             kill_tree $(ps -o ppid= -p $p | tr -d ' '); done; sleep 2",
            "pid-lookup-feeds-kill",
        );
    }

    #[test]
    fn broadcast_targets_are_critical() {
        let pack = create_pack();
        for command in [
            "kill -TERM -1",
            "kill -9 -1",
            "kill -- -1",
            "kill -s KILL -1",
        ] {
            assert_blocks_with_severity(&pack, command, Severity::Critical);
        }
        assert_blocks_with_severity(&pack, "launchctl bootout gui/501", Severity::Critical);
    }

    /// Recorded-PID and process-group kills are what the explanations tell
    /// agents to do instead, so they must stay allowed.
    #[test]
    fn recorded_pid_and_group_kills_are_allowed() {
        let pack = create_pack();
        for command in [
            "kill 12345",
            "kill -TERM 12345",
            "kill -9 12345 12346",
            "kill -s TERM 12345",
            "kill -0 12345",
            "kill -l",
            "kill %1",
            "kill $!",
            "kill -TERM \"$PID\"",
            "kill -HUP 4242",
            "kill -TERM -12345",
            "kill -TERM -$PGID",
            "kill -9 -- -$pg",
        ] {
            assert_allows(&pack, command);
        }
        for command in [
            "kill \"$(cat /tmp/job.pid)\"",
            "kill -TERM $(cat \"$S/lane.pid\")",
            "kill $(< /tmp/job.pid)",
            "kill $(cat /var/run/job/gate.pid) 2>/dev/null",
        ] {
            assert_safe_pattern_matches(&pack, command);
        }
    }

    /// A pidfile read is exempt only on its own: a second, computed operand
    /// must not ride along on the exemption.
    #[test]
    fn the_pidfile_exemption_does_not_cover_extra_operands() {
        let pack = create_pack();
        for command in [
            "kill $(cat job.pid) $(pgrep -f other)",
            "kill $(cat job.pid; pgrep -f other)",
            "kill -9 $(pgrep -f foo)",
        ] {
            assert_no_safe_match(&pack, command);
            assert!(pack.check(command).is_some(), "{command:?} must be denied");
        }
    }

    #[test]
    fn interpreter_broadcasts_are_denied_and_single_pids_allowed() {
        let pack = create_pack();
        for command in [
            "python3 -c 'import os; os.kill(-1, 9)'",
            "python3 -c 'import os; os.killpg(0, 15)'",
            "node -e 'process.kill(-1, \"SIGTERM\")'",
            "python3 -c 'import psutil; [p.kill() for p in psutil.process_iter() if \"x\" in p.name()]'",
        ] {
            assert_blocks_with_pattern(&pack, command, "interpreter-signals-everything");
        }
        for command in [
            "python3 -c 'import os; os.kill(12345, 15)'",
            "python3 -c 'import psutil; print(len(list(psutil.process_iter())))'",
            "grep -rn os.kill src/",
        ] {
            assert_allows(&pack, command);
        }
    }

    #[test]
    fn reading_process_state_is_allowed() {
        let pack = create_pack();
        for command in [
            "pgrep -fl verify_loop",
            "pgrep -f 'ab_driver[.]sh' | head",
            "pgrep -fl myjob; kill 12345",
            "kill 12345; sleep 1; pgrep -fl myjob",
            "ps -o pid,ppid,pgid,command -p 12345",
            "ps -o ppid= -p 4242",
            "timeout -k 10 600 cargo test",
            "launchctl bootout gui/501/com.example.agent",
            "launchctl kickstart -k gui/501/com.example.agent",
        ] {
            assert_allows(&pack, command);
        }
    }
}
