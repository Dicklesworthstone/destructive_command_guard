//! Integrated fuzz target for heredoc extraction and embedded-script matching.
//!
//! The first byte selects a command wrapper, the second byte selects the
//! interpreter language, and the remaining UTF-8 bytes become the script body.
//! This keeps mutations close to real shell constructs while still letting
//! libFuzzer vary malformed, unterminated, and non-executing heredocs.

#![no_main]

use destructive_command_guard::config::{CompiledOverrides, Config};
use destructive_command_guard::perf::Deadline;
use destructive_command_guard::{
    AstMatcher, ExtractionLimits, ExtractionResult, LayeredAllowlist, ScriptLanguage,
    TriggerResult, check_triggers, evaluate_command_with_deadline, extract_content,
    extract_shell_commands, matched_triggers,
};
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use std::time::Duration;

const MAX_INPUT_BYTES: usize = 8 * 1024;
const ENABLED_KEYWORDS: &[&str] = &[
    "git", "rm", "python", "ruby", "perl", "node", "deno", "bun", "php", "go", "bash", "sh",
];

static AST_MATCHER: LazyLock<AstMatcher> =
    LazyLock::new(|| AstMatcher::new().with_timeout(Duration::from_millis(5)));
static EMPTY_ALLOWLISTS: LazyLock<LayeredAllowlist> = LazyLock::new(LayeredAllowlist::default);
static DEFAULT_CONFIG_AND_OVERRIDES: LazyLock<(Config, CompiledOverrides)> = LazyLock::new(|| {
    let config = Config::default();
    let compiled_overrides = config.overrides.compile();
    (config, compiled_overrides)
});

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 || data.len() > MAX_INPUT_BYTES {
        return;
    }

    let Ok(body) = std::str::from_utf8(&data[2..]) else {
        return;
    };
    let body = body.strip_prefix('\n').unwrap_or(body);

    let language = language_from_selector(data[1]);
    let command = build_command(data[0], language, body);
    exercise_heredoc_pipeline(&command);
});

fn language_from_selector(selector: u8) -> ScriptLanguage {
    match selector {
        b'b' | b'B' | b's' | b'S' => ScriptLanguage::Bash,
        b'g' | b'G' => ScriptLanguage::Go,
        b'h' | b'H' => ScriptLanguage::Php,
        b'j' | b'J' => ScriptLanguage::JavaScript,
        b'p' | b'P' => ScriptLanguage::Python,
        b'r' | b'R' => ScriptLanguage::Ruby,
        b'l' | b'L' => ScriptLanguage::Perl,
        b't' | b'T' => ScriptLanguage::TypeScript,
        b'u' | b'U' => ScriptLanguage::Unknown,
        _ => match selector % 9 {
            0 => ScriptLanguage::Bash,
            1 => ScriptLanguage::Python,
            2 => ScriptLanguage::JavaScript,
            3 => ScriptLanguage::TypeScript,
            4 => ScriptLanguage::Ruby,
            5 => ScriptLanguage::Perl,
            6 => ScriptLanguage::Php,
            7 => ScriptLanguage::Go,
            _ => ScriptLanguage::Unknown,
        },
    }
}

fn interpreter(language: ScriptLanguage) -> (&'static str, &'static str) {
    match language {
        ScriptLanguage::Bash => ("bash", "SH"),
        ScriptLanguage::Go => ("go run -", "GO"),
        ScriptLanguage::Php => ("php", "PHP"),
        ScriptLanguage::Python => ("python3", "PY"),
        ScriptLanguage::Ruby => ("ruby", "RB"),
        ScriptLanguage::Perl => ("perl", "PL"),
        ScriptLanguage::JavaScript => ("node", "JS"),
        ScriptLanguage::TypeScript => ("deno run -", "TS"),
        ScriptLanguage::Unknown => ("custom-tool", "TXT"),
    }
}

fn build_command(mode: u8, language: ScriptLanguage, body: &str) -> String {
    let (cmd, delimiter) = interpreter(language);

    match mode {
        b'h' | b'H' => standard_heredoc(cmd, delimiter, body),
        b't' | b'T' => format!("{cmd} <<-'{delimiter}'\n\t{body}\n{delimiter}\n"),
        b'i' | b'I' => inline_script(cmd, body),
        b'u' | b'U' => format!("{cmd} <<'{delimiter}'\n{body}\n"),
        b'c' | b'C' => format!("cat <<'{delimiter}'\n{body}\n{delimiter}\n"),
        _ => match mode % 6 {
            0 => standard_heredoc(cmd, delimiter, body),
            1 => format!("{cmd} <<-'{delimiter}'\n\t{body}\n{delimiter}\n"),
            2 => inline_script(cmd, body),
            3 => format!("{cmd} <<'{delimiter}'\n{body}\n"),
            4 => format!("cat <<'{delimiter}'\n{body}\n{delimiter}\n"),
            _ => body.to_string(),
        },
    }
}

fn standard_heredoc(cmd: &str, delimiter: &str, body: &str) -> String {
    format!("{cmd} <<'{delimiter}'\n{body}\n{delimiter}\n")
}

fn inline_script(cmd: &str, body: &str) -> String {
    format!("{cmd} -c {}", single_quoted(body))
}

fn single_quoted(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

fn exercise_heredoc_pipeline(command: &str) {
    let trigger = check_triggers(command);
    let trigger_indices = matched_triggers(command);
    if trigger == TriggerResult::NoTrigger {
        assert!(trigger_indices.is_empty());
    } else {
        assert!(!trigger_indices.is_empty());
    }

    let limits = ExtractionLimits {
        max_body_bytes: MAX_INPUT_BYTES,
        max_body_lines: 1_024,
        max_heredocs: 8,
        timeout_ms: 10,
    };

    match extract_content(command, &limits) {
        ExtractionResult::Extracted(contents) => validate_extracted(command, &contents, &limits),
        ExtractionResult::Partial { extracted, skipped } => {
            validate_extracted(command, &extracted, &limits);
            assert!(!skipped.is_empty());
        }
        ExtractionResult::NoContent
        | ExtractionResult::Skipped(_)
        | ExtractionResult::Failed(_) => {
            assert_budget_deadline_is_indeterminate(command);
        }
    }
}

fn validate_extracted(
    command: &str,
    contents: &[destructive_command_guard::ExtractedContent],
    limits: &ExtractionLimits,
) {
    assert!(contents.len() <= limits.max_heredocs);

    for item in contents {
        assert!(item.content.len() <= limits.max_body_bytes);
        assert!(item.content.lines().count() <= limits.max_body_lines);
        assert!(item.byte_range.start <= item.byte_range.end);
        assert!(item.byte_range.end <= command.len());
        assert!(command.is_char_boundary(item.byte_range.start));
        assert!(command.is_char_boundary(item.byte_range.end));

        if let Some(range) = &item.content_range {
            assert!(range.start <= range.end);
            assert!(range.end <= command.len());
            assert!(command.is_char_boundary(range.start));
            assert!(command.is_char_boundary(range.end));
        }

        validate_ast_matches(&item.content, item.language);
        let _ = extract_shell_commands(&item.content);
    }
}

fn validate_ast_matches(code: &str, language: ScriptLanguage) {
    match AST_MATCHER.find_matches(code, language) {
        Ok(matches) => {
            for matched in matches {
                assert!(!matched.rule_id.is_empty());
                assert!(!matched.reason.is_empty());
                assert!(matched.start <= matched.end);
                assert!(matched.end <= code.len());
                assert!(code.is_char_boundary(matched.start));
                assert!(code.is_char_boundary(matched.end));
                assert!(matched.line_number >= 1);
                assert!(!matched.severity.label().is_empty());
            }
        }
        Err(_) => {
            let _ = AST_MATCHER.has_blocking_match(code, language);
        }
    }

    assert!(
        AST_MATCHER
            .has_blocking_match(code, ScriptLanguage::Unknown)
            .is_none()
    );
}

fn assert_budget_deadline_is_indeterminate(command: &str) {
    let deadline = Deadline::new(Duration::ZERO);
    while !deadline.is_exceeded() {
        std::hint::spin_loop();
    }

    let (config, compiled_overrides) = &*DEFAULT_CONFIG_AND_OVERRIDES;
    let result = evaluate_command_with_deadline(
        command,
        config,
        ENABLED_KEYWORDS,
        compiled_overrides,
        &EMPTY_ALLOWLISTS,
        Some(&deadline),
    );

    assert!(result.is_indeterminate());
    assert!(result.skipped_due_to_budget);
}
