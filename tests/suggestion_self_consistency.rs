//! Registry-wide suggestion self-consistency (#316).
//!
//! A denial that recommends a command the same pack blocks is a dead end: the
//! agent reads the block message, tries the suggestion, is denied again, and
//! gives up (or worse, starts reshaping commands until something passes).
//!
//! `core.filesystem` decides rm and PowerShell removals in a semantic
//! classifier rather than by regex, so four of its rules have no
//! `DestructivePattern` row and their suggestions are invisible to a sweep over
//! `destructive_patterns`. Those rules are swept here too, through the public
//! evaluator, because only the evaluator reproduces the decision a classifier
//! rule makes.
//!
//! Every `PatternSuggestion` in every built-in pack must therefore be either:
//! - actually runnable — the pack that offered it does not deny it, or
//! - explicitly constructed with `PatternSuggestion::gated`, which renders an
//!   unmistakable "dcg gates this too — it needs explicit approval" marker.
//!
//! Placeholders like `{path}` or `<owner>/<repo>` are substituted with
//! concrete, realistic values before evaluation, so the regexes see the same
//! bytes a user pasting the suggestion would produce.

use destructive_command_guard::Agent;
use destructive_command_guard::config::Config;
use destructive_command_guard::evaluator::evaluate_command;
use destructive_command_guard::load_default_allowlists;
use destructive_command_guard::packs::{PackRegistry, Platform, REGISTRY, classifier_guidance};

/// The concrete values `{path}` / `{file}` take when a suggestion is
/// instantiated. Rules that fire *because* the target is a root/home/sensitive
/// path show their suggestions in that context, so their suggestions must also
/// be evaluated with a home-path instantiation — issue #316's follow-up report
/// was exactly a suggestion that passed with a relative path but was denied by
/// its own rule once the user substituted the home path from the triggering
/// command.
const RELATIVE_PATH: &str = "./build/scratch.txt";
const HOME_PATH: &str = "~/notes/scratch.txt";

/// Profiles a rule's suggestions must survive. Every rule is checked with a
/// benign relative path. Rules whose trigger domain is a sensitive/home path
/// (their names carry `root-home` or `sensitive`) are additionally checked
/// with a home path, mirroring how a user would instantiate the suggestion
/// from the command that was just denied.
fn applicable_paths(rule: &str) -> &'static [&'static str] {
    if rule.contains("root-home") || rule.contains("sensitive") {
        &[RELATIVE_PATH, HOME_PATH]
    } else {
        &[RELATIVE_PATH]
    }
}

/// Substitute the placeholder vocabulary used across pack suggestions with
/// concrete illustrative values. Any leftover `<...>` / `{...}` token is
/// replaced with a benign literal so partially-known placeholders cannot make
/// a suggestion accidentally unevaluable. Docker's `{{.Field}}` format
/// strings are preserved.
fn substitute_placeholders(command: &str, concrete_path: &str) -> String {
    let mut out = command.to_string();
    for (from, to) in [
        ("<owner>/<repo>", "acme/widgets"),
        ("{path}", concrete_path),
        ("{file}", concrete_path),
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
/// be allowed by the pack that offered it — under *every* path profile the
/// offering rule can fire in. Gated suggestions are exempt: they are rendered
/// with an explicit "dcg gates this too" marker (#316).
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
                for concrete_path in applicable_paths(rule) {
                    let command = substitute_placeholders(suggestion.command, concrete_path);
                    if let Some(hit) = pack.check(&command) {
                        failures.push(format!(
                            "{pack_id}:{rule} suggests {:?} (as {command:?}), which the same pack \
                             denies via {pack_id}:{} — either fix the suggestion or mark it \
                             PatternSuggestion::gated",
                            suggestion.command,
                            hit.name.unwrap_or("unnamed"),
                        ));
                    }
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
/// its own pack in at least one path profile the offering rule can fire in.
/// A stale flag would append a scary approval marker to a command dcg happily
/// allows in every context. Only same-pack gating is asserted; a suggestion
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
                let denied_somewhere = applicable_paths(rule).iter().any(|concrete_path| {
                    let command = substitute_placeholders(suggestion.command, concrete_path);
                    pack.check(&command).is_some()
                });
                if !denied_somewhere {
                    failures.push(format!(
                        "{pack_id}:{rule} marks {:?} as gated, but this pack allows it in \
                         every applicable path profile — drop the gated marker or fix the \
                         suggestion",
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

/// The rule the production evaluator denies `command` with, if it denies it.
///
/// Classifier rules never reach `Pack::check`, which walks regexes only, so a
/// suggestion published by one of them can only be judged by running the same
/// evaluation a blocked caller would trigger — the production keyword set and
/// the default enabled packs included.
fn evaluator_denial(command: &str) -> Option<String> {
    let config = Config::default();
    let compiled_overrides = config.overrides.compile();
    let allowlists = load_default_allowlists();
    let enabled_packs = config.enabled_pack_ids_for_agent(&Agent::ClaudeCode);
    let keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let result = evaluate_command(
        command,
        &config,
        &keywords,
        &compiled_overrides,
        &allowlists,
    );
    if !result.is_denied() {
        return None;
    }
    Some(
        result
            .pattern_info
            .and_then(|info| info.pattern_name)
            .unwrap_or_else(|| "unnamed".to_string()),
    )
}

/// Same contract as `non_gated_suggestions_are_not_denied_by_their_own_pack`,
/// for the rules that own no regex. `rm-recursive-unverified` offering a plain
/// `rm -r {path}` is exactly the dead end #316 describes: the pack denies that
/// command for any ordinary path as `rm-recursive-general`, so it has to carry
/// the gated marker.
#[test]
fn non_gated_classifier_suggestions_are_not_denied_by_the_evaluator() {
    let mut failures = Vec::new();

    for row in classifier_guidance() {
        for suggestion in row.suggestions {
            if suggestion.gated {
                continue;
            }
            for concrete_path in applicable_paths(row.rule) {
                let command = substitute_placeholders(suggestion.command, concrete_path);
                if let Some(denied_by) = evaluator_denial(&command) {
                    failures.push(format!(
                        "{} suggests {:?} (as {command:?}), which the evaluator denies via \
                         {denied_by} — either fix the suggestion or mark it \
                         PatternSuggestion::gated",
                        row.rule, suggestion.command,
                    ));
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "classifier suggestions denied by dcg itself:\n{}",
        failures.join("\n")
    );
}

/// The inverse guard for classifier rules: a `gated` marker that dcg does not
/// actually enforce attaches an approval warning to a command it allows, and
/// teaches the reader to ignore the marker.
#[test]
fn gated_classifier_suggestions_are_actually_denied() {
    let mut failures = Vec::new();

    for row in classifier_guidance() {
        for suggestion in row.suggestions {
            if !suggestion.gated {
                continue;
            }
            let denied_somewhere = applicable_paths(row.rule).iter().any(|concrete_path| {
                let command = substitute_placeholders(suggestion.command, concrete_path);
                evaluator_denial(&command).is_some()
            });
            if !denied_somewhere {
                failures.push(format!(
                    "{} marks {:?} as gated, but dcg allows it in every applicable path \
                     profile — drop the gated marker or fix the suggestion",
                    row.rule, suggestion.command,
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "stale gated markers on classifier guidance:\n{}",
        failures.join("\n")
    );
}

/// `find` takes primaries, not long options: neither GNU nor BSD find accepts
/// `--maxdepth`, and both exit with a usage error on it. A suggestion that
/// cannot run teaches the blocked caller nothing, and the failure looks like
/// the guard broke the command rather than like a typo in the advice. Only the
/// segment before the first pipe is examined, so `| head -30` and other
/// downstream tools keep their own flag vocabulary.
#[test]
fn find_suggestions_use_primaries_not_long_options() {
    let registry = PackRegistry::new();
    let mut failures = Vec::new();

    let mut check = |owner: &str, command: &'static str| {
        let head = command.split('|').next().unwrap_or(command);
        if !head.split_whitespace().any(|word| word == "find") {
            return;
        }
        for word in head.split_whitespace() {
            if word.starts_with("--") {
                failures.push(format!(
                    "{owner} suggests {command:?}, but find has no {word} option — use the \
                     single-dash primary"
                ));
            }
        }
    };

    for pack_id in registry.all_pack_ids() {
        let pack = registry.get(pack_id).expect("registered pack resolves");
        for pattern in &pack.destructive_patterns {
            let rule = pattern.name.unwrap_or("unnamed");
            for suggestion in pattern.suggestions {
                check(&format!("{pack_id}:{rule}"), suggestion.command);
            }
        }
    }
    for row in classifier_guidance() {
        for suggestion in row.suggestions {
            check(row.rule, suggestion.command);
        }
    }

    assert!(
        failures.is_empty(),
        "find guidance that cannot run:\n{}",
        failures.join("\n")
    );
}

/// Rendering keeps only the suggestions whose platform matches the host
/// (`hook.rs` and `cli.rs` both filter on `Platform::matches_current`), so a
/// platform tag is a decision about who gets to read the advice. A classifier
/// rule is reachable from any host — the rm classifier fires on POSIX, `pwsh`
/// runs on macOS and Linux — so each rule has to leave every host at least one
/// alternative it can actually run. Gated entries do not count: they need
/// explicit approval, so a rule offering only gated advice is still a dead end.
///
/// This walks the platforms instead of asking the host, because the same tag
/// error is invisible on whichever host happens to match it — the
/// Windows-tagged PowerShell guidance passed every Windows run while POSIX
/// callers got nothing.
#[test]
fn classifier_guidance_reaches_every_platform() {
    let mut failures = Vec::new();

    for platform in [
        Platform::Linux,
        Platform::MacOS,
        Platform::Windows,
        Platform::Bsd,
    ] {
        for row in classifier_guidance() {
            let runnable = row
                .suggestions
                .iter()
                .filter(|suggestion| {
                    !suggestion.gated
                        && (suggestion.platform == Platform::All || suggestion.platform == platform)
                })
                .count();
            if runnable == 0 {
                failures.push(format!(
                    "{} leaves a {} caller no runnable alternative — every one of its \
                     suggestions is tagged for another platform or gated",
                    row.rule,
                    platform.label(),
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "classifier guidance filtered away before it is read:\n{}",
        failures.join("\n")
    );
}
