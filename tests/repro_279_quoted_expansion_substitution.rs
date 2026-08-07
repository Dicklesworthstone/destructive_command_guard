//! Regression tests for issue #279: a variable expansion followed by
//! whitespace and `$(` inside one double-quoted word was denied as an
//! unparseable POSIX command substitution.
//!
//! tree-sitter-bash 0.25 folds the whitespace separating the expansion from
//! `$(` into the `command_substitution` node itself, so the extractor's
//! `strip_prefix("$(")` failed and the evaluator failed closed. The extractor
//! now trims that leading whitespace; genuinely malformed substitutions must
//! still fail closed.

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::heredoc::extract_posix_command_substitution_bodies;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, LayeredAllowlist};

fn evaluate_in_dialect(
    command: &str,
    dialect: ShellDialect,
) -> destructive_command_guard::EvaluationResult {
    let config = Config::default();
    let enabled_packs = config.enabled_pack_ids();
    let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    let keyword_index = REGISTRY
        .build_enabled_keyword_index(&ordered_packs)
        .expect("keyword index should build for enabled pack set");
    let compiled_overrides = config.overrides.compile();
    let allowlists = LayeredAllowlist::default();
    let heredoc_settings = config.heredoc_settings();
    evaluate_command_with_pack_order_at_path_in_dialect(
        command,
        &enabled_keywords,
        &ordered_packs,
        Some(&keyword_index),
        &compiled_overrides,
        &allowlists,
        &heredoc_settings,
        None,
        dialect,
    )
}

/// Every boundary-table row from issue #279 that was wrongly denied.
const FORMERLY_DENIED: &[&str] = &[
    "echo \"$s $(true)\"",
    "echo \"${s} $(true)\"",
    "echo \"$1 $(true)\"",
    "echo \"a$s $(true)\"",
    "echo \"$s  $(true)\"",
    "printf %s \"$HOME $(date)\"",
];

#[test]
fn expansion_whitespace_substitution_bodies_extract_cleanly() {
    for command in FORMERLY_DENIED {
        let bodies = extract_posix_command_substitution_bodies(command)
            .unwrap_or_else(|error| panic!("{command:?} must parse cleanly, got {error:?}"));
        assert_eq!(
            bodies.len(),
            1,
            "{command:?} must expose exactly the inner substitution, got {bodies:?}"
        );
    }
}

#[test]
fn expansion_whitespace_substitution_is_allowed_in_posix_dialect() {
    for command in FORMERLY_DENIED {
        let result = evaluate_in_dialect(command, ShellDialect::Posix);
        assert!(
            result.is_allowed(),
            "{command:?} must be allowed under posix dialect, got {result:?}"
        );
    }
}

#[test]
fn expansion_whitespace_substitution_is_allowed_in_unknown_dialect() {
    for command in FORMERLY_DENIED {
        let result = evaluate_in_dialect(command, ShellDialect::Unknown);
        assert!(
            result.is_allowed(),
            "{command:?} must be allowed under unknown dialect, got {result:?}"
        );
    }
}

#[test]
fn real_world_for_loop_with_quoted_expansion_is_allowed() {
    let command = "for d in */; do s=ok; echo \"$s $(basename \"$d\")\"; done";
    for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
        let result = evaluate_in_dialect(command, dialect);
        assert!(
            result.is_allowed(),
            "{command:?} must be allowed under {dialect:?}, got {result:?}"
        );
    }
}

/// Planted negative: the inner substitution after the trimmed whitespace must
/// still be extracted and evaluated, so a destructive body stays denied.
#[test]
fn destructive_inner_substitution_after_expansion_is_still_denied() {
    let command = "echo \"$s $(rm -rf /home/user)\"";
    let bodies = extract_posix_command_substitution_bodies(command)
        .expect("well-formed substitution must parse cleanly");
    assert_eq!(bodies, vec!["rm -rf /home/user".to_string()]);
    for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
        let result = evaluate_in_dialect(command, dialect);
        assert!(
            result.is_denied(),
            "{command:?} must stay denied under {dialect:?}, got {result:?}"
        );
    }
}

/// Planted negative: a genuinely malformed substitution still fails closed
/// with the parser deny.
#[test]
fn unterminated_substitution_still_fails_closed() {
    let command = "echo \"$s $(true\"";
    assert!(
        extract_posix_command_substitution_bodies(command).is_err(),
        "unterminated substitution must remain a parse error"
    );
    let result = evaluate_in_dialect(command, ShellDialect::Posix);
    assert!(
        result.is_denied(),
        "{command:?} must stay denied, got {result:?}"
    );
}
