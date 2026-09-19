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
//!
//! Two layers live here. The first half drives the real binary and asserts a
//! decision; the second half calls `extract_content` directly and asserts which
//! payloads come out. Nearly every bug in this area was the extractor finding
//! nothing, which a decision test alone cannot distinguish from a later stage
//! choosing to allow.

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

// ===========================================================================
// Extractor-level contract
//
// Everything above drives the real binary and asserts a decision. The tests
// below go one layer down and assert which shell payloads `extract_content`
// yields, which is where the option grammar, the string/regex walk and the
// executable matcher actually live. Keeping both layers matters: a decision
// test cannot tell "the extractor found nothing" from "a later stage allowed
// it", and most of the bugs in this area were the former.
// ===========================================================================

use destructive_command_guard::heredoc::{ExtractionLimits, ExtractionResult, extract_content};

/// Extraction limits with only the wall clock relaxed.
///
/// Every assertion in this file is about *what* gets extracted and whether the
/// result reports itself as complete — questions decided by the size and slot
/// caps, never by how fast the host is. `ExtractionLimits::default()` also
/// carries `timeout_ms: 50`, so on a loaded machine the extractor can stop early
/// and downgrade a complete reading to `Partial`, failing these tests for a
/// reason they are not testing. Measured with one binary:
/// `an_untruncated_extraction_is_still_reported_as_complete` was 0/10 failures at
/// load 34 and 2/10 at load 74.
///
/// Relaxing only the clock keeps `max_heredocs` and the byte/line caps at their
/// shipped values, so the slot-budget boundary these #427 tests exist to pin
/// down is unchanged. Mirrors `ExtractionLimits::structural_scan()` (#443),
/// which made the same trade for the structural helpers.
fn limits() -> ExtractionLimits {
    ExtractionLimits {
        timeout_ms: 5_000,
        ..ExtractionLimits::default()
    }
}

/// The shell payloads extracted from `command`, in order.
fn payloads(command: &str) -> Vec<String> {
    match extract_content(command, &limits()) {
        ExtractionResult::Extracted(items)
        | ExtractionResult::Partial {
            extracted: items, ..
        } => items.into_iter().map(|item| item.content).collect(),
        ExtractionResult::NoContent
        | ExtractionResult::Skipped(_)
        | ExtractionResult::Failed(_) => Vec::new(),
    }
}

#[test]
fn awk_shell_sinks_yield_their_payload() {
    assert_eq!(
        payloads("awk 'BEGIN{ system(\"rm -rf /Users/x/Documents\") }'"),
        vec!["rm -rf /Users/x/Documents".to_string()],
    );
    assert_eq!(
        payloads("awk 'BEGIN{ print \"x\" | \"rm -rf /tmp/z\" }'"),
        vec!["rm -rf /tmp/z".to_string()],
        "print redirected into a command runs the string on the right"
    );
    assert_eq!(
        payloads("awk 'BEGIN{ \"rm -rf /tmp/z\" | getline line }'"),
        vec!["rm -rf /tmp/z".to_string()],
        "`cmd | getline` runs the string on the left"
    );
}

#[test]
fn osascript_shell_sinks_yield_their_payload() {
    assert_eq!(
        payloads("osascript -e 'do shell script \"rm -rf /Users/x/Documents\"'"),
        vec!["rm -rf /Users/x/Documents".to_string()],
    );
    assert_eq!(
        payloads("osascript -l JavaScript -e '$.system(\"rm -rf /tmp/z\")'"),
        vec!["rm -rf /tmp/z".to_string()],
    );
}

/// AppleScript keyword matching is whitespace-flexible and case-insensitive.
///
/// Regression: a fixed `"do shell script"` literal missed `do  shell  script`,
/// which is valid AppleScript and trivially evades a single-space match. It was
/// also inconsistent with the `\bdo\s+shell\s+script\b` tier-1 trigger that
/// routes the command to extraction in the first place.
#[test]
fn do_shell_script_matching_is_whitespace_flexible_and_bounded() {
    for program in [
        "do shell script \"rm -rf /tmp/z\"",
        "do   shell   script  \"rm -rf /tmp/z\"",
        "do\tshell\tscript \"rm -rf /tmp/z\"",
        "do\nshell\nscript \"rm -rf /tmp/z\"",
        "Do Shell Script \"rm -rf /tmp/z\"",
        "DO SHELL SCRIPT \"rm -rf /tmp/z\"",
    ] {
        let command = format!("osascript -e '{program}'");
        assert_eq!(
            payloads(&command),
            vec!["rm -rf /tmp/z".to_string()],
            "whitespace/case variant must still yield the payload: {program:?}"
        );
    }

    // Word boundaries: a longer word containing a keyword is not the keyword.
    for program in [
        "redo shell script \"rm -rf /tmp/z\"",
        "doshellscript \"rm -rf /tmp/z\"",
        "do shell scripted \"rm -rf /tmp/z\"",
        "do shellscript \"rm -rf /tmp/z\"",
    ] {
        let command = format!("osascript -e '{program}'");
        assert!(
            payloads(&command).is_empty(),
            "not the keyword sequence: {program:?}"
        );
    }

    // A near miss must not stop the scan finding a real one after it.
    assert_eq!(
        payloads("osascript -e 'redo shell script x\ndo shell script \"rm -rf /tmp/z\"'"),
        vec!["rm -rf /tmp/z".to_string()],
    );
}

#[test]
fn programs_without_a_shell_sink_yield_nothing() {
    for command in [
        "awk '{print $1}' file.txt",
        // awk prints this string; it never reaches a shell.
        "awk 'BEGIN{ print \"rm -rf /\" }'",
        "awk 'BEGIN{ x = 1 || 2; print x }'",
        "osascript -e 'display notification \"done\"'",
        // A program file is not opened.
        "osascript /usr/local/scripts/notify.applescript",
    ] {
        assert!(
            payloads(command).is_empty(),
            "expected no payload from {command:?}, got {:?}",
            payloads(command)
        );
    }
}

/// `-f progfile` reads the program from a file, and it also changes what the
/// remaining operands mean: without `-f` the first operand is the program, with
/// `-f` every operand is a data file or a `var=value` assignment.
///
/// Regression: the separate spelling used to skip the flag and its value and
/// then hand the next operand to the program scanner as if it were awk source,
/// so a data file whose *name* looked like a program was mined for sinks. The
/// glued spelling was already correct, which is what made the asymmetry easy to
/// miss — a test using a benign data filename passes either way.
#[test]
fn a_program_file_invocation_never_yields_an_inline_payload() {
    for command in [
        "awk -f prog.awk data.txt",
        "awk --file prog.awk data.txt",
        "awk -fprog.awk data.txt",
        // The operand is a FILE NAME here, not a program, however it is shaped.
        "awk -f prog.awk 'BEGIN{ system(\"rm -rf /\") }'",
        "awk --file prog.awk 'BEGIN{ system(\"rm -rf /\") }'",
        "awk -fprog.awk 'BEGIN{ system(\"rm -rf /\") }'",
        // `--file=prog.awk` is deliberately NOT here: it is a GNU extension, and
        // an awk that does not implement it runs the following operand as its
        // program. See
        // `a_glued_long_progfile_flag_keeps_the_positional_operand_admissible`.
    ] {
        assert!(
            payloads(command).is_empty(),
            "a -f invocation has no inline program: {command:?} yielded {:?}",
            payloads(command)
        );
    }

    // `-v` does NOT consume the program, so the sink is still found.
    assert_eq!(
        payloads("awk -v n=1 'BEGIN{ system(\"rm -rf /tmp/z\") }'"),
        vec!["rm -rf /tmp/z".to_string()],
        "-v takes a value but leaves the program in place"
    );
}

/// Only a `#` that opens a line starts an awk comment.
///
/// Regression: treating every `#` as a comment let a regex literal containing a
/// literal hash — `/x#/`, `!/^#/`, both ordinary awk idioms — swallow the rest
/// of its line, hiding a real `system()` call after it. That is an under-block,
/// which is the direction that matters for a guard.
///
/// The first attempt at a fix accepted `;`, `{` and `}` as statement markers
/// too, which left the same hole open one character further along: `/;#/` and
/// `/{#/` are equally ordinary regexes and put a `#` in exactly that position.
/// Line start is the only position that is *provably* a comment, because an awk
/// regex literal and an awk string literal may not contain a raw newline.
#[test]
fn a_hash_inside_a_regex_literal_does_not_hide_the_rest_of_the_line() {
    for command in [
        "awk '/x#/ { system(\"rm -rf /tmp/z\") }'",
        "awk '!/^#/ { system(\"rm -rf /tmp/z\") }'",
        "awk '$0 ~ /a#b/ { system(\"rm -rf /tmp/z\") }'",
        // The residue the narrower rule closes.
        "awk '$0 ~ /;#/ { system(\"rm -rf /tmp/z\") }'",
        "awk '{ /{#/ ; system(\"rm -rf /tmp/z\") }'",
    ] {
        assert_eq!(
            payloads(command),
            vec!["rm -rf /tmp/z".to_string()],
            "a hash in a regex is data, not a comment: {command:?}"
        );
    }

    // A comment that OPENS A LINE still hides what follows on that line.
    assert!(
        payloads("awk 'BEGIN{ print 1;\n# system(\"rm -rf /tmp/z\")\n}'").is_empty(),
        "a sink commented out at line start is not executed"
    );

    // A trailing comment is deliberately NOT recognised, so its text is still
    // scanned. Over-extraction is the recoverable direction; the guard will not
    // trade it for a rule that cannot tell a comment from regex data.
    assert_eq!(
        payloads("awk 'BEGIN{ # system(\"rm -rf /tmp/z\")\nprint 1 }'"),
        vec!["rm -rf /tmp/z".to_string()],
        "a mid-line hash is not proof of a comment, so the sink is still read"
    );
}

/// awk's option grammar decides what its operands mean, and an unfamiliar flag
/// must not abandon the scan.
///
/// Regression: every unmodeled option returned `None`, so a single `-F:` — the
/// most common awk flag there is — meant no program text was scanned at all.
#[test]
fn an_unfamiliar_option_does_not_abandon_the_program_scan() {
    for command in [
        "awk -F: 'BEGIN{ system(\"rm -rf /tmp/z\") }'",
        "awk -F, 'BEGIN{ system(\"rm -rf /tmp/z\") }'",
        "awk --field-separator=, 'BEGIN{ system(\"rm -rf /tmp/z\") }'",
        "gawk --posix 'BEGIN{ system(\"rm -rf /tmp/z\") }'",
        "mawk -W version 'BEGIN{ system(\"rm -rf /tmp/z\") }'",
        // `-e`/`--source` supply the program AS THE FLAG VALUE.
        "gawk -e 'BEGIN{ system(\"rm -rf /tmp/z\") }'",
        "gawk --source 'BEGIN{ system(\"rm -rf /tmp/z\") }'",
    ] {
        assert_eq!(
            payloads(command),
            vec!["rm -rf /tmp/z".to_string()],
            "the program is still reachable past this option: {command:?}"
        );
    }

    // An ordinary field-separator run still extracts nothing.
    assert!(payloads("awk -F, '{print $2}' data.csv").is_empty());
}

/// A quote inside a regex literal must not desynchronize the string walk.
///
/// Regression: `gsub(/"/, "")` — one of the most common awk idioms there is —
/// paired the regex's quote with a later string quote, so every literal after
/// it shifted by one and the `system()` call that followed was read as string
/// content. The scanner now tracks regex literals.
#[test]
fn a_quote_inside_a_regex_literal_does_not_hide_a_later_sink() {
    for command in [
        "awk '{ gsub(/\"/, \"\"); system(\"rm -rf /tmp/z\") }'",
        "awk '/\"/ { system(\"rm -rf /tmp/z\") }'",
        "awk '$0 ~ /[\"]/ { system(\"rm -rf /tmp/z\") }'",
    ] {
        assert_eq!(
            payloads(command),
            vec!["rm -rf /tmp/z".to_string()],
            "a quote in a regex is data: {command:?}"
        );
    }

    // Division is not a regex, so the scan must not skip over the sink.
    assert_eq!(
        payloads("awk 'BEGIN{ x = 4 / 2; system(\"rm -rf /tmp/z\") }'"),
        vec!["rm -rf /tmp/z".to_string()],
    );
}

/// Tracking regex literals introduced its own hazard: a `/` the heuristic reads
/// as a regex opener, whose "closing" slash is really a path separator inside
/// the payload, would skip straight over the sink.
///
/// `x++ / 2` and `x-- / 2` are recognised as division, because the doubled
/// operator is what distinguishes them from `a + /re/` (awk reads a bare regex
/// in expression position as `$0 ~ /re/`, so a single `+` legitimately precedes
/// one).
#[test]
fn a_misread_slash_cannot_skip_over_a_sink() {
    for command in [
        "awk 'BEGIN{ x = y++ / 2; system(\"rm -rf /tmp/z\") }'",
        "awk 'BEGIN{ x = y-- / 2; system(\"rm -rf /tmp/z\") }'",
        "awk 'BEGIN{ x = a + /re/; system(\"rm -rf /tmp/z\") }'",
        "awk 'BEGIN{ x = 1/2/3/4; system(\"rm -rf /tmp/z\") }'",
    ] {
        assert_eq!(
            payloads(command),
            vec!["rm -rf /tmp/z".to_string()],
            "a misread slash must not hide the sink after it: {command:?}"
        );
    }

    // The pipe sinks travel the same path and must survive it too.
    assert_eq!(
        payloads("awk 'BEGIN{ x = 1/2; print \"a\" | \"rm -rf /tmp/z\" }'"),
        vec!["rm -rf /tmp/z".to_string()],
    );
    assert_eq!(
        payloads("awk 'BEGIN{ x = 1/2; \"rm -rf /tmp/z\" | getline line }'"),
        vec!["rm -rf /tmp/z".to_string()],
    );

    // Ordinary division and ordinary regexes still extract nothing.
    for command in [
        "awk 'BEGIN{ x = 10 / 2; print x }'",
        "awk 'BEGIN{ x = y++ / 2; print x }'",
        "awk '/a|b/ { print }' f.txt",
        "awk -F/ '{print $2}' paths.txt",
    ] {
        assert!(
            payloads(command).is_empty(),
            "ordinary awk yields no payload: {command:?}"
        );
    }
}

/// A `/` can be a regex CLOSE or the division OPERATOR, and the previous byte
/// alone cannot tell them apart.
///
/// ```text
/// n = /a/ / 2      the `/` before is a regex close — a VALUE — so this divides
/// x = 4 / /re/     the `/` before is the division operator, so this OPENS
/// ```
///
/// Regression: treating every preceding `/` as a value got the first right and
/// the second exactly backwards. The regex body was then scanned as code, an odd
/// `"` inside it paired with a later string quote, and the desync hid every sink
/// after it. gawk and mawk both run these. The scanner now remembers where it
/// actually proved a regex closed, and only that offset counts as a value.
#[test]
fn division_before_a_regex_does_not_hide_the_sink_after_it() {
    for program in [
        "{ x = 4 / /^|\"/ ; system(\"rm -rf /tmp/z\") }",
        "{ if (0) x = 4 / /\"/ ; system(\"rm -rf /tmp/z\") }",
        "{ x = 4 / /a+/ ; print \"z\" | \"rm -rf /tmp/z\" }",
        "{ x = 4 / /a*/ ; \"rm -rf /tmp/z\" | getline q }",
        "{ x = $1 / /\"/ ; system(\"rm -rf /tmp/z\") }",
        "{ x = (1) / /\"/ ; system(\"rm -rf /tmp/z\") }",
    ] {
        let command = format!("awk '{program}'");
        assert_eq!(
            payloads(&command),
            vec!["rm -rf /tmp/z".to_string()],
            "a regex opened after division must not swallow the sink: {program:?}"
        );
    }

    // The regex-close-then-division reading must survive alongside it.
    assert_eq!(
        payloads("awk 'BEGIN{ n = /a/ / 2; system(\"rm -rf /tmp/z\") }'"),
        vec!["rm -rf /tmp/z".to_string()],
    );

    // And neither reading may invent a payload for ordinary arithmetic.
    for program in [
        "{ x = 4 / /a+/ ; print x }",
        "BEGIN{ n = /a/ / 2; print n }",
        "{ s += $1/$2 } END { print s }",
    ] {
        let command = format!("awk '{program}'");
        assert!(
            payloads(&command).is_empty(),
            "ordinary arithmetic yields nothing: {program:?}"
        );
    }
}

/// A regex body that happens to carry a pipe and a quote is still just a regex.
///
/// Regression: `awk_span_carries_a_sink` briefly vetoed a regex skip whenever
/// the candidate body held both `|` and `"`, reaching for the third sink
/// (`print … | "cmd"`) which names no keyword. Real awk regexes carry both —
/// `/["|]/`, `/[|"]/` and `/"|,/` are ordinary and gawk runs all three — so the
/// veto fired on genuine regexes, refused the skip, and let the body be scanned
/// as code. Its `"` then paired with a later string quote, restoring the very
/// desync regex tracking exists to prevent, and the sink after it was lost.
#[test]
fn a_regex_body_holding_a_pipe_and_a_quote_is_still_skipped() {
    // Bodies expressible inside a single-quoted shell word. An apostrophe is
    // deliberately absent: it would close the quote, so `awk '… /"|'"'"'/ …'`
    // is not a program the shell can deliver in one token anyway.
    for body in ["[\"|]", "[|\"]", "^\"|\"$", "\"|,"] {
        let command = format!(
            "awk 'BEGIN{{ x = \"a\"; gsub(/{body}/, \"\", x); system(\"rm -rf /tmp/z\") }}'"
        );
        assert_eq!(
            payloads(&command),
            vec!["rm -rf /tmp/z".to_string()],
            "the sink after this regex must still be seen: /{body}/"
        );

        let benign = format!("awk 'BEGIN{{ x = \"a\"; gsub(/{body}/, \"\", x); print x }}'");
        assert!(
            payloads(&benign).is_empty(),
            "the same regex without a sink yields nothing: /{body}/"
        );
    }
}

/// A regex literal is a VALUE, so the `/` that follows one is division.
///
/// Regression: the value set had no `/`, so in `n = /a/ / 2` the second `/` was
/// read as opening a fresh regex. The scan then ran forward to the next `/` in
/// the program — usually the one inside the payload's own path — which ended
/// the bogus span BEFORE any sink keyword, so `awk_span_carries_a_sink` never
/// got the chance to veto the skip. Every program below runs on gawk, mawk and
/// busybox awk; one extra `/` in code position was the whole bypass.
#[test]
fn a_slash_after_a_regex_literal_is_division() {
    for command in [
        "awk 'BEGIN{ n = /a/ / 2; system(\"rm -rf /tmp/z\") }'",
        "awk 'BEGIN{ n = /a/ / 2; print \"x\" | \"rm -rf /tmp/z\" }'",
        "awk 'BEGIN{ n = /a/ / 2; \"rm -rf /tmp/z\" | getline y }'",
        "awk '{ r = /x/ / NF; print \"a\" | \"rm -rf /tmp/z\" }'",
        "awk 'BEGIN{ rate = /x/ / 100; print \"audit\" | \"rm -rf /tmp/z\"; m = /y/ }'",
    ] {
        assert_eq!(
            payloads(command),
            vec!["rm -rf /tmp/z".to_string()],
            "a sink after regex-then-division must still be seen: {command:?}"
        );
    }

    // The same programs without a sink extract nothing, and an empty regex
    // literal is still a regex rather than two division operators.
    for command in [
        "awk 'BEGIN{ n = /a/ / 2; print n }'",
        "awk '/a/ && /b/ { print }' f.txt",
        "awk 'BEGIN{ if (\"\" ~ //) print 1 }'",
    ] {
        assert!(
            payloads(command).is_empty(),
            "ordinary awk yields no payload: {command:?}"
        );
    }
}

/// A program written inside shell DOUBLE quotes arrives with its own quotes
/// backslash-escaped, and the shell removes those before the interpreter runs.
///
/// All three sinks travel that path, not just the call form: the two pipe sinks
/// are decided by the scanner loop pairing a string literal, so the loop needs
/// the escaped spelling too, and tier 1 has to admit it before tier 2 ever runs.
#[test]
fn an_escaped_quote_opens_a_literal_just_as_a_bare_one_does() {
    for command in [
        "awk \"BEGIN{ system(\\\"rm -rf /tmp/z\\\") }\"",
        "awk \"BEGIN{ print 1 | \\\"rm -rf /tmp/z\\\" }\"",
        "awk \"BEGIN{ print 1 |& \\\"rm -rf /tmp/z\\\" }\"",
        "awk \"BEGIN{ \\\"rm -rf /tmp/z\\\" | getline x }\"",
        "osascript -e \"do shell script \\\"rm -rf /tmp/z\\\"\"",
    ] {
        assert_eq!(
            payloads(command),
            vec!["rm -rf /tmp/z".to_string()],
            "escaped quotes still delimit the payload: {command:?}"
        );
    }
}

/// A glued flag value carries its own shell quoting, which the separate spelling
/// gets stripped for it.
///
/// Regression: the glued arms pushed the raw range, so `awk -e"BEGIN{…}"` handed
/// the scanner a program whose first byte was a quote. The whole program was
/// then read as one string literal and the sink inside it never seen.
#[test]
fn a_glued_flag_value_is_unquoted_like_a_separate_one() {
    for command in [
        "awk -e\"BEGIN{ system(\\\"rm -rf /tmp/z\\\") }\"",
        "awk --source=\"BEGIN{ system(\\\"rm -rf /tmp/z\\\") }\"",
        "awk -e'BEGIN{ system(\"rm -rf /tmp/z\") }'",
        "gawk --source='BEGIN{ system(\"rm -rf /tmp/z\") }'",
    ] {
        assert_eq!(
            payloads(command),
            vec!["rm -rf /tmp/z".to_string()],
            "the glued value is program text either way: {command:?}"
        );
    }
}

/// Shell quoting spliced into the middle of an executable name is invisible to
/// the kernel, so it must be invisible to the extractor too.
///
/// Regression: the cheap pre-gate searched for a CONTIGUOUS `awk`/`osascript`,
/// so `a"wk"` was rejected before tokenization even though the executable
/// matcher behind it resolves the word correctly. A gate must be at least as
/// permissive as the matcher it guards.
#[test]
fn quoting_spliced_into_an_executable_name_is_seen_through() {
    for command in [
        "a\"wk\" 'BEGIN{ system(\"rm -rf /tmp/z\") }'",
        "aw\\k 'BEGIN{ system(\"rm -rf /tmp/z\") }'",
        "$'awk' 'BEGIN{ system(\"rm -rf /tmp/z\") }'",
        "g\"awk\" 'BEGIN{ system(\"rm -rf /tmp/z\") }'",
        "busybox a\"wk\" 'BEGIN{ system(\"rm -rf /tmp/z\") }'",
        "osa\"script\" -e 'do shell script \"rm -rf /tmp/z\"'",
        "osa\\script -e 'do shell script \"rm -rf /tmp/z\"'",
    ] {
        assert_eq!(
            payloads(command),
            vec!["rm -rf /tmp/z".to_string()],
            "quoting does not change which program runs: {command:?}"
        );
    }

    // A word that merely contains the letters is still not the interpreter.
    for command in [
        "hawking 'BEGIN{ system(\"rm -rf /tmp/z\") }'",
        "mawkish 'BEGIN{ system(\"rm -rf /tmp/z\") }'",
    ] {
        assert!(
            payloads(command).is_empty(),
            "not an awk: {command:?} yielded {:?}",
            payloads(command)
        );
    }
}

/// The glued long forms are a GNU extension. gawk reads each as a source file,
/// but an awk that does not implement them leaves the following operand as its
/// program, so the operand stays admissible and the sink is still scanned.
#[test]
fn a_glued_long_progfile_flag_keeps_the_positional_operand_admissible() {
    for command in [
        "awk -Eprog.awk 'BEGIN{ system(\"rm -rf /tmp/z\") }'",
        "awk --exec=prog.awk 'BEGIN{ system(\"rm -rf /tmp/z\") }'",
        "awk --file=prog.awk 'BEGIN{ system(\"rm -rf /tmp/z\") }'",
    ] {
        assert_eq!(
            payloads(command),
            vec!["rm -rf /tmp/z".to_string()],
            "an unimplemented option leaves the operand as the program: {command:?}"
        );
    }

    // The separated spellings consume the progfile name on every awk, so the
    // operand after them is data and yields nothing.
    for command in [
        "awk -E prog.awk 'BEGIN{ system(\"rm -rf /tmp/z\") }'",
        "awk -f prog.awk 'BEGIN{ system(\"rm -rf /tmp/z\") }'",
        "awk -fprog.awk 'BEGIN{ system(\"rm -rf /tmp/z\") }'",
    ] {
        assert!(
            payloads(command).is_empty(),
            "the program comes from a file here: {command:?}"
        );
    }
}

/// Quoting or case-varying an executable is invisible to the kernel, and macOS
/// — the only platform that ships `osascript` — is case-insensitive by default.
#[test]
fn a_quoted_or_cased_executable_is_still_the_interpreter() {
    assert_eq!(
        payloads("\"awk\" 'BEGIN{ system(\"rm -rf /tmp/z\") }'"),
        vec!["rm -rf /tmp/z".to_string()],
    );
    assert_eq!(
        payloads("\"osascript\" -e 'do shell script \"rm -rf /tmp/z\"'"),
        vec!["rm -rf /tmp/z".to_string()],
    );
    assert_eq!(
        payloads("OSASCRIPT -e 'do shell script \"rm -rf /tmp/z\"'"),
        vec!["rm -rf /tmp/z".to_string()],
    );
}

/// `osascript -e<program>` (glued) and JXA's `doShellScript` are both real
/// spellings that reached no extractor before.
#[test]
fn glued_dash_e_and_do_shell_script_method_are_covered() {
    assert_eq!(
        payloads("osascript -e'do shell script \"rm -rf /tmp/z\"'"),
        vec!["rm -rf /tmp/z".to_string()],
    );
    assert_eq!(
        payloads(
            "osascript -l JavaScript -e 'var a=Application.currentApplication(); \
             a.includeStandardAdditions=true; a.doShellScript(\"rm -rf /tmp/z\")'"
        ),
        vec!["rm -rf /tmp/z".to_string()],
    );
}

#[test]
fn only_a_literal_string_supplies_a_payload() {
    // A concatenation or a variable is not statically known. Extracting the
    // literal prefix is fine; inventing the rest is not.
    let extracted = payloads("awk 'BEGIN{ system(cmd) }'");
    assert!(
        extracted.is_empty(),
        "a variable argument supplies no literal payload, got {extracted:?}"
    );
}

// ===========================================================================
// #427: padding the extractor's slot budget must not buy an allow.
//
// `ExtractionLimits::max_heredocs` (default 10) truncates the payload list, and
// `extract_content` used to report the truncated list as `Extracted` — a
// complete reading. That skipped the bounded fallback, so ten benign payloads
// hid an eleventh, and the padding also starved the ssh/herestring/heredoc
// extractors that run after the awk and osascript ones.
//
// Both layers are asserted: the decision, and that the extraction now reports
// itself as incomplete. A decision test alone cannot tell "the sink was read
// and judged" from "the fallback happened to catch the text".
// ===========================================================================

/// Ten `system()` pads plus one real sink, the shape from the report.
fn awk_with_pads(pad_count: usize, sink: &str) -> String {
    use std::fmt::Write as _;

    let mut program = String::from("BEGIN{");
    for index in 0..pad_count {
        let _ = write!(program, "system(\"echo {index}\");");
    }
    let _ = write!(program, "system(\"{sink}\")");
    program.push('}');
    format!("awk '{program}'")
}

#[test]
fn padding_the_extraction_budget_does_not_hide_a_later_sink() {
    // Nine pads fit inside the budget and were always blocked; ten filled it.
    for pad_count in [0, 8, 9, 10, 11, 20] {
        let command = awk_with_pads(pad_count, "rm -rf /Users/x/Documents");
        assert_eq!(
            verdict(&command),
            "BLOCKED",
            "{pad_count} pads hid the sink"
        );
    }
}

#[test]
fn padding_one_extractor_does_not_starve_the_next() {
    // The awk extractor runs before the ssh one, so a filled budget used to
    // mean the ssh payload was never looked at.
    let mut command = awk_with_pads(10, "echo done");
    command.push_str(" ; ssh host 'rm -rf /Users/x/Documents'");
    assert_eq!(verdict(&command), "BLOCKED");
}

#[test]
fn a_truncated_extraction_reports_itself_as_partial() {
    let command = awk_with_pads(10, "rm -rf /Users/x/Documents");
    match extract_content(&command, &limits()) {
        ExtractionResult::Partial { extracted, skipped } => {
            assert_eq!(
                extracted.len(),
                limits().max_heredocs,
                "the budget should be filled, not exceeded"
            );
            assert!(
                skipped
                    .iter()
                    .any(|reason| { reason.to_string().to_ascii_lowercase().contains("limit") }),
                "the skip reason should name the limit, got {skipped:?}"
            );
        }
        other => panic!(
            "a truncated extraction must not be reported as complete, got {}",
            match other {
                ExtractionResult::Extracted(items) => format!("Extracted({} items)", items.len()),
                ExtractionResult::NoContent => "NoContent".to_string(),
                ExtractionResult::Skipped(reasons) => format!("Skipped({reasons:?})"),
                ExtractionResult::Failed(message) => format!("Failed({message})"),
                ExtractionResult::Partial { .. } => unreachable!(),
            }
        ),
    }
}

#[test]
fn an_untruncated_extraction_is_still_reported_as_complete() {
    // The distinction has to stay meaningful: a command whose payloads all fit
    // must report `Extracted`, or every caller pays for the fallback.
    let command = awk_with_pads(3, "rm -rf /Users/x/Documents");
    let result = extract_content(&command, &limits());
    assert!(
        matches!(result, ExtractionResult::Extracted(_)),
        "a complete extraction must not be downgraded to partial; got {}",
        match &result {
            ExtractionResult::Extracted(items) => format!("Extracted({} items)", items.len()),
            ExtractionResult::Partial { extracted, skipped } => format!(
                "Partial({} extracted, skipped {skipped:?}) — if this names a timeout rather \
                 than a slot limit, the host was too slow, not the extractor wrong",
                extracted.len()
            ),
            ExtractionResult::NoContent => "NoContent".to_string(),
            ExtractionResult::Skipped(reasons) => format!("Skipped({reasons:?})"),
            ExtractionResult::Failed(message) => format!("Failed({message})"),
        }
    );
}
