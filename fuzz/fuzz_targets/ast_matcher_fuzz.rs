//! Fuzz target for AST matcher parsing and destructive-pattern matching.
//!
//! The first byte selects a script language and the remaining UTF-8 bytes are
//! parsed as embedded script content. Parser errors and timeouts are expected
//! to fail open through `has_blocking_match` rather than panic or deny.

#![no_main]

use dcg_cli::{AstMatcher, MatchError, ScriptLanguage};
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use std::time::Duration;

const MAX_CODE_BYTES: usize = 8 * 1024;

static MATCHER: LazyLock<AstMatcher> =
    LazyLock::new(|| AstMatcher::new().with_timeout(Duration::from_millis(10)));
static ZERO_TIMEOUT_MATCHER: LazyLock<AstMatcher> =
    LazyLock::new(|| AstMatcher::new().with_timeout(Duration::ZERO));

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 || data.len() > MAX_CODE_BYTES {
        return;
    }

    let language = language_from_selector(data[0]);
    let Ok(code) = std::str::from_utf8(&data[1..]) else {
        return;
    };
    let code = code.strip_prefix('\n').unwrap_or(code);

    exercise_matcher(code, language);
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

fn exercise_matcher(code: &str, language: ScriptLanguage) {
    match MATCHER.find_matches(code, language) {
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
        Err(error) => {
            assert_expected_fail_open_error(error);
            let _ = MATCHER.has_blocking_match(code, language);
        }
    }

    assert!(
        MATCHER
            .has_blocking_match(code, ScriptLanguage::Unknown)
            .is_none()
    );

    if let Err(MatchError::Timeout { .. }) = ZERO_TIMEOUT_MATCHER.find_matches(code, language) {
        assert!(
            ZERO_TIMEOUT_MATCHER
                .has_blocking_match(code, language)
                .is_none()
        );
    }
}

fn assert_expected_fail_open_error(error: MatchError) {
    match error {
        MatchError::UnsupportedLanguage(_)
        | MatchError::ParseError { .. }
        | MatchError::Timeout { .. }
        | MatchError::PatternError { .. } => {}
    }
}
