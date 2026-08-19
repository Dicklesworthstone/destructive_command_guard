//! Registry-wide suggestion self-consistency (#316).
//!
//! A denial that recommends a command the same pack blocks is a dead end: the
//! agent reads the block message, tries the suggestion, is denied again, and
//! gives up (or worse, starts reshaping commands until something passes).
//!
//! Every `PatternSuggestion` in every built-in pack must therefore be either:
//! - actually runnable — the pack that offered it does not deny it, or
//! - explicitly constructed with `PatternSuggestion::gated`, which renders an
//!   unmistakable "dcg gates this too — it needs explicit approval" marker.
//!
//! Placeholders like `{path}` or `<owner>/<repo>` are substituted with
//! concrete, realistic values before evaluation, so the regexes see the same
//! bytes a user pasting the suggestion would produce.

use destructive_command_guard::packs::PackRegistry;

/// Substitute the placeholder vocabulary used across pack suggestions with
/// concrete illustrative values. Any leftover `<...>` / `{...}` token is
/// replaced with a benign literal so partially-known placeholders cannot make
/// a suggestion accidentally unevaluable. Docker's `{{.Field}}` format
/// strings are preserved.
fn substitute_placeholders(command: &str) -> String {
    let mut out = command.to_string();
    for (from, to) in [
        ("<owner>/<repo>", "acme/widgets"),
        ("{path}", "./build/scratch.txt"),
        ("{file}", "./build/scratch.txt"),
        ("{subdir}", "scratch"),
        ("{tablename}", "orders"),
        ("{schema_name}", "analytics"),
        ("{dbname}", "appdb"),
        ("{ns}", "staging"),
        ("{namespace}", "staging"),
        ("{pattern}", "web"),
        ("{container-name}", "web-1"),
        ("{name}", "feature-x"),
        ("{condition}", "id = 42"),
        ("{host}", "db.example.internal"),
        ("{user}", "admin"),
    ] {
        out = out.replace(from, to);
    }

    // Generic fallback for placeholders not in the table. `{{` opens a
    // Go-template format string (docker --format), which is left intact.
    let mut result = String::with_capacity(out.len());
    let mut chars = out.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                // Copy the `{{ ... }}` template span verbatim.
                result.push(c);
                while let Some(t) = chars.next() {
                    result.push(t);
                    if t == '}' && chars.peek() == Some(&'}') {
                        result.push(chars.next().expect("peeked"));
                        break;
                    }
                }
            }
            '{' => {
                // Skip to the matching close and substitute a benign token.
                for t in chars.by_ref() {
                    if t == '}' {
                        break;
                    }
                }
                result.push('x');
            }
            '<' => {
                let mut consumed = String::new();
                let mut closed = false;
                for t in chars.by_ref() {
                    if t == '>' {
                        closed = true;
                        break;
                    }
                    consumed.push(t);
                }
                if closed {
                    result.push('x');
                } else {
                    // A lone `<` (e.g. a shell redirect) is not a placeholder.
                    result.push('<');
                    result.push_str(&consumed);
                }
            }
            _ => result.push(c),
        }
    }
    result
}

/// Every non-gated suggestion, applied with concrete placeholder values, must
/// be allowed by the pack that offered it. Gated suggestions are exempt: they
/// are rendered with an explicit "dcg gates this too" marker (#316).
#[test]
fn non_gated_suggestions_are_not_denied_by_their_own_pack() {
    let registry = PackRegistry::new();
    let mut failures = Vec::new();

    for pack_id in registry.all_pack_ids() {
        let pack = registry.get(pack_id).expect("registered pack resolves");
        for pattern in &pack.destructive_patterns {
            let rule = pattern.name.unwrap_or("unnamed");
            for suggestion in pattern.suggestions {
                if suggestion.gated {
                    continue;
                }
                let command = substitute_placeholders(suggestion.command);
                if let Some(hit) = pack.check(&command) {
                    failures.push(format!(
                        "{pack_id}:{rule} suggests {:?} (as {command:?}), which the same pack \
                         denies via {pack_id}:{} — either fix the suggestion or mark it \
                         PatternSuggestion::gated",
                        suggestion.command,
                        hit.pattern_name.unwrap_or("unnamed"),
                    ));
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "suggestions denied by their own pack:\n{}",
        failures.join("\n")
    );
}

/// The inverse guard: a suggestion marked `gated` should actually be gated by
/// its own pack. A stale flag would append a scary approval marker to a
/// command dcg happily allows. Only same-pack gating is asserted; a suggestion
/// gated by a *different* pack (or by evaluator-level analysis) is recorded in
/// its description instead.
#[test]
fn gated_suggestions_are_actually_denied_by_their_own_pack() {
    let registry = PackRegistry::new();
    let mut failures = Vec::new();

    for pack_id in registry.all_pack_ids() {
        let pack = registry.get(pack_id).expect("registered pack resolves");
        for pattern in &pack.destructive_patterns {
            let rule = pattern.name.unwrap_or("unnamed");
            for suggestion in pattern.suggestions {
                if !suggestion.gated {
                    continue;
                }
                let command = substitute_placeholders(suggestion.command);
                if pack.check(&command).is_none() {
                    failures.push(format!(
                        "{pack_id}:{rule} marks {:?} (as {command:?}) as gated, but this pack \
                         allows it — drop the gated marker or fix the suggestion",
                        suggestion.command,
                    ));
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "stale gated markers:\n{}",
        failures.join("\n")
    );
}
