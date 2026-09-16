//! Regression tests for issues #399 (awk) and #398 (osascript): two standard
//! interpreters whose *positional* program hands a command to `/bin/sh`.
//!
//! `awk 'BEGIN{ system("rm -rf ~/Documents") }'` is the denied
//! `sh -c "rm -rf ~/Documents"` behind an awk program; awk's two command-pipe
//! forms (`print … | "cmd"` and `"cmd" | getline`) do the same. AppleScript's
//! `do shell script "…"` and JavaScript-for-Automation's `$.system("…")` are
//! the macOS equivalents, and osascript ships on every Mac.
//!
//! Both were allowed while the identical payload under `sh -c`, `perl -e` or
//! `node -e` was denied, because their program is a positional argument: the
//! inline-code span rules key on `-c`/`-e` flags, so the program read as quoted
//! argv data and never reached extraction.
//!
//! The tests deliberately pin both directions. Ordinary programs must stay on
//! the fast path — including ones that merely *print* a dangerous-looking
//! string, which awk does not execute.

use std::process::Command;

fn dcg_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

/// Evaluate one command under the POSIX dialect the Bash hook resolves.
fn verdict(command: &str) -> &'static str {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let out = Command::new(dcg_binary())
        .args(["test", "--dialect", "posix", "--with-packs", "system.disk"])
        .arg(command)
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("NO_COLOR", "1")
        .env("TERM", "dumb")
        .current_dir(temp.path())
        .output()
        .expect("run dcg test");
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    if text.contains("Result: BLOCKED") {
        "BLOCKED"
    } else if text.contains("Result: ALLOWED") {
        "ALLOWED"
    } else {
        panic!("no verdict for {command:?}:\n{text}")
    }
}

#[test]
fn awk_system_payloads_are_denied() {
    for command in [
        "awk 'BEGIN{ system(\"rm -rf /Users/x/Documents\") }'",
        "awk 'BEGIN{ system(\"git reset --hard HEAD~1\") }'",
        "awk 'BEGIN{ system(\"diskutil eraseDisk JHFS+ Untitled /dev/disk2\") }'",
        // Spelling variants: path-qualified, other awk implementations, the
        // busybox applet, and an option before the program.
        "/usr/bin/awk 'BEGIN{ system(\"rm -rf /Users/x/Documents\") }'",
        "mawk 'BEGIN{ system(\"rm -rf /Users/x/Documents\") }'",
        "gawk 'BEGIN{ system(\"rm -rf /Users/x/Documents\") }'",
        "busybox awk 'BEGIN{ system(\"rm -rf /Users/x/Documents\") }'",
        "awk -v n=1 'BEGIN{ system(\"rm -rf /Users/x/Documents\") }'",
    ] {
        assert_eq!(verdict(command), "BLOCKED", "{command}");
    }
}

#[test]
fn awk_command_pipe_payloads_are_denied() {
    for command in [
        // `print … | "cmd"` runs the string on the right.
        "awk 'BEGIN{ print \"x\" | \"rm -rf /Users/x/Documents\" }'",
        // `"cmd" | getline` runs the string on the left.
        "awk 'BEGIN{ \"rm -rf /Users/x/Documents\" | getline line }'",
    ] {
        assert_eq!(verdict(command), "BLOCKED", "{command}");
    }
}

#[test]
fn osascript_shell_payloads_are_denied() {
    for command in [
        "osascript -e 'do shell script \"rm -rf /Users/x/Documents\"'",
        "osascript -e 'do shell script \"git reset --hard HEAD~1\"'",
        // JavaScript-for-Automation.
        "osascript -l JavaScript -e 'ObjC.import(\"stdlib\"); $.system(\"rm -rf /Users/x/Documents\")'",
        "/usr/bin/osascript -e 'do shell script \"rm -rf /Users/x/Documents\"'",
        // osascript concatenates multiple `-e` statements into one program.
        "osascript -e 'display dialog \"hi\"' -e 'do shell script \"rm -rf /Users/x/Documents\"'",
    ] {
        assert_eq!(verdict(command), "BLOCKED", "{command}");
    }
}

#[test]
fn ordinary_awk_programs_stay_allowed() {
    for command in [
        "awk '{print $1}' file.txt",
        "awk '$3 > $4 { print }' data.tsv",
        "awk -F, '{print $2}' report.csv",
        // awk PRINTS this string; it does not execute it.
        "awk 'BEGIN{ print \"rm -rf /\" }'",
        "awk '{ if ($1 == \"rm -rf /\") print \"found\" }' log.txt",
        // The word `system` inside a regex is not a call.
        "awk 'NR>1 && $2 ~ /system/ { print }' report.txt",
        "awk -v OFS=, '{print $1,$2}' in.tsv",
        // `||` is logical or, not a command pipe.
        "awk 'BEGIN{ x = 1 || 2; print x }'",
        "awk 'END{ print NR }' access.log",
    ] {
        assert_eq!(verdict(command), "ALLOWED", "{command}");
    }
}

#[test]
fn ordinary_osascript_automation_stays_allowed() {
    for command in [
        "osascript -e 'display notification \"build done\"'",
        "osascript -e 'tell application \"Finder\" to activate'",
        // A script FILE is not opened, so there is no program text to inspect.
        "osascript /usr/local/scripts/notify.applescript",
    ] {
        assert_eq!(verdict(command), "ALLOWED", "{command}");
    }
}

#[test]
fn the_sink_text_as_ordinary_data_stays_allowed() {
    for command in [
        "echo 'do shell script \"rm -rf /\"' > /tmp/notes.txt",
        "grep -n \"system(\" src/main.c",
    ] {
        assert_eq!(verdict(command), "ALLOWED", "{command}");
    }
}
