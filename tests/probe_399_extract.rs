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
        "awk -f prog.awk data.txt",
    ] {
        assert!(
            payloads(command).is_empty(),
            "expected no payload from {command:?}, got {:?}",
            payloads(command)
        );
    }
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
