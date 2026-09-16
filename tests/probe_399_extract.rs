//! Extractor-level contract for #399/#398: which awk and osascript programs
//! yield a shell payload, and which yield nothing.
//!
//! NOTE: this file is named `probe_*` because it started as scratch
//! instrumentation while diagnosing #399. Its assertions are real, but the name
//! does not follow the repository's `repro_<issue>_*` convention and it belongs
//! beside `repro_398_399_interpreter_shell_sinks.rs`. Fold it in and remove it.

use destructive_command_guard::heredoc::{ExtractionLimits, ExtractionResult, extract_content};

/// The shell payloads extracted from `command`, in order.
fn payloads(command: &str) -> Vec<String> {
    match extract_content(command, &ExtractionLimits::default()) {
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
        "awk --file=prog.awk 'BEGIN{ system(\"rm -rf /\") }'",
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

/// A program written inside shell DOUBLE quotes arrives with its own quotes
/// backslash-escaped, and the shell removes those before the interpreter runs.
#[test]
fn an_escaped_quote_opens_a_literal_just_as_a_bare_one_does() {
    assert_eq!(
        payloads("awk \"BEGIN{ system(\\\"rm -rf /tmp/z\\\") }\""),
        vec!["rm -rf /tmp/z".to_string()],
    );
    assert_eq!(
        payloads("osascript -e \"do shell script \\\"rm -rf /tmp/z\\\"\""),
        vec!["rm -rf /tmp/z".to_string()],
    );
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
