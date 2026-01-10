//! Regression corpus test harness with full isomorphism verification.
//!
//! This module loads test cases from `tests/corpus/` and runs them through the evaluator,
//! comparing ALL evaluation fields to ensure refactors don't change behavior.
//!
//! # Corpus Structure
//!
//! ```text
//! tests/corpus/
//!   true_positives/   # Commands that MUST be blocked (deny)
//!   false_positives/  # Commands that MUST be allowed (allow)
//!   bypass_attempts/  # Obfuscated dangerous commands (deny)
//!   edge_cases/       # Commands that must not crash (any decision ok)
//! ```
//!
//! # Test Case Format (TOML)
//!
//! ```toml
//! [[case]]
//! description = "git reset --hard blocks correctly"
//! command = "git reset --hard"
//! expected = "deny"  # or "allow"
//! rule_id = "core.git:reset-hard"  # optional
//!
//! [case.log]  # Optional: detailed field verification
//! decision = "deny"
//! mode = "deny"
//! pack_id = "core.git"
//! pattern_name = "reset-hard"
//! rule_id = "core.git:reset-hard"
//! reason_contains = "destroys uncommitted"
//! ```
//!
//! # Isomorphism Guarantee
//!
//! When `[case.log]` is present, the test verifies ALL fields match exactly:
//! - `decision` (allow/deny)
//! - `effective_mode` (deny/warn/log)
//! - `pack_id`
//! - `pattern_name`
//! - `rule_id` (pack:pattern format)
//! - `reason_contains` (substring match)
//! - `allowlist_layer` (project/user/system)
//!
//! This ensures that performance optimizations and refactors don't accidentally
//! change evaluation semantics.
//!
//! # Running
//!
//! ```bash
//! cargo test --test regression_corpus
//! ```

use std::collections::HashSet;
use std::fmt::Write;
use std::fs;
use std::path::Path;

use destructive_command_guard::packs::test_helpers::{
    CorpusCategory, CorpusTestCase, load_corpus_dir, verify_corpus_case,
};

/// Load all corpus test cases from the standard directory.
fn load_all_cases() -> Vec<(CorpusCategory, String, CorpusTestCase)> {
    let corpus_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    load_corpus_dir(&corpus_dir).expect("Failed to load corpus directory")
}

/// Run verification on cases matching a specific category.
fn run_category_tests(category: CorpusCategory) -> (usize, Vec<String>) {
    let all_cases = load_all_cases();
    let category_cases: Vec<_> = all_cases
        .iter()
        .filter(|(cat, _, _)| *cat == category)
        .collect();

    let total = category_cases.len();
    let mut failures = Vec::new();

    for (cat, file, case) in category_cases {
        if let Err(msg) = verify_corpus_case(case, *cat) {
            failures.push(format!("[{file}] {msg}"));
        }
    }

    (total, failures)
}

// =============================================================================
// Scenario fixture validation (YAML)
// =============================================================================

#[derive(Default)]
struct ScenarioStep {
    command: Option<String>,
    expected_pack: Option<String>,
    expected_decision: Option<String>,
    reason: Option<String>,
}

struct ScenarioFixture {
    id: Option<String>,
    description: Option<String>,
    steps: Vec<ScenarioStep>,
}

fn split_key_value(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once(':')?;
    Some((key.trim(), value.trim()))
}

fn normalize_value(value: &str) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    let trimmed = value.trim();
    let unquoted = if (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
    {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };
    if unquoted.is_empty() {
        None
    } else {
        Some(unquoted.to_string())
    }
}

#[allow(clippy::too_many_lines)]
fn parse_scenario_fixture(path: &Path) -> Result<ScenarioFixture, String> {
    let contents = fs::read_to_string(path)
        .map_err(|err| format!("Failed to read {}: {err}", path.display()))?;
    let mut fixture = ScenarioFixture {
        id: None,
        description: None,
        steps: Vec::new(),
    };
    let mut current_step: Option<ScenarioStep> = None;
    let mut in_steps = false;

    for (idx, line) in contents.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let indent = line.chars().take_while(|c| c.is_whitespace()).count();
        if indent == 0 {
            in_steps = false;
            let Some((key, value)) = split_key_value(trimmed) else {
                return Err(format!(
                    "{}:{}: expected top-level key:value pair",
                    path.display(),
                    line_no
                ));
            };
            match key {
                "id" => {
                    fixture.id = normalize_value(value);
                    if fixture.id.is_none() {
                        return Err(format!(
                            "{}:{}: id value must be non-empty",
                            path.display(),
                            line_no
                        ));
                    }
                }
                "description" => {
                    fixture.description = normalize_value(value);
                    if fixture.description.is_none() {
                        return Err(format!(
                            "{}:{}: description value must be non-empty",
                            path.display(),
                            line_no
                        ));
                    }
                }
                "steps" => {
                    in_steps = true;
                }
                _ => {
                    return Err(format!(
                        "{}:{}: unexpected top-level key '{key}'",
                        path.display(),
                        line_no
                    ));
                }
            }
            continue;
        }

        if !in_steps {
            return Err(format!(
                "{}:{}: step field found before steps section",
                path.display(),
                line_no
            ));
        }

        if let Some(rest) = trimmed.strip_prefix("- ") {
            let Some((key, value)) = split_key_value(rest) else {
                return Err(format!(
                    "{}:{}: expected step key:value pair",
                    path.display(),
                    line_no
                ));
            };
            if key != "command" {
                return Err(format!(
                    "{}:{}: step must start with command field",
                    path.display(),
                    line_no
                ));
            }
            if let Some(step) = current_step.take() {
                fixture.steps.push(step);
            }
            current_step = Some(ScenarioStep {
                command: normalize_value(value),
                expected_pack: None,
                expected_decision: None,
                reason: None,
            });
            if current_step
                .as_ref()
                .and_then(|step| step.command.as_ref())
                .is_none()
            {
                return Err(format!(
                    "{}:{}: command value must be non-empty",
                    path.display(),
                    line_no
                ));
            }
            continue;
        }

        let Some((key, value)) = split_key_value(trimmed) else {
            return Err(format!(
                "{}:{}: expected step key:value pair",
                path.display(),
                line_no
            ));
        };
        let step = current_step.as_mut().ok_or_else(|| {
            format!(
                "{}:{}: step field without a command",
                path.display(),
                line_no
            )
        })?;
        match key {
            "expected_pack" => step.expected_pack = normalize_value(value),
            "expected_decision" => step.expected_decision = normalize_value(value),
            "reason" => step.reason = normalize_value(value),
            _ => {
                return Err(format!(
                    "{}:{}: unexpected step key '{key}'",
                    path.display(),
                    line_no
                ));
            }
        }
    }

    if let Some(step) = current_step.take() {
        fixture.steps.push(step);
    }

    if fixture.id.is_none() {
        return Err(format!("{}: missing id", path.display()));
    }
    if fixture.description.is_none() {
        return Err(format!("{}: missing description", path.display()));
    }
    if fixture.steps.is_empty() {
        return Err(format!("{}: no steps found", path.display()));
    }

    for (idx, step) in fixture.steps.iter().enumerate() {
        if step.command.as_deref().unwrap_or("").is_empty() {
            return Err(format!(
                "{}: step {} missing command",
                path.display(),
                idx + 1
            ));
        }
        if step.expected_pack.as_deref().unwrap_or("").is_empty() {
            return Err(format!(
                "{}: step {} missing expected_pack",
                path.display(),
                idx + 1
            ));
        }
        match step.expected_decision.as_deref() {
            Some("allow" | "deny") => {}
            Some(other) => {
                return Err(format!(
                    "{}: step {} invalid expected_decision '{other}'",
                    path.display(),
                    idx + 1
                ));
            }
            None => {
                return Err(format!(
                    "{}: step {} missing expected_decision",
                    path.display(),
                    idx + 1
                ));
            }
        }
        if step.reason.as_deref().unwrap_or("").is_empty() {
            return Err(format!(
                "{}: step {} missing reason",
                path.display(),
                idx + 1
            ));
        }
    }

    Ok(fixture)
}

// =============================================================================
// Tests
// =============================================================================

#[test]
fn corpus_true_positives_isomorphism() {
    let (total, failures) = run_category_tests(CorpusCategory::TruePositives);

    if !failures.is_empty() {
        let mut msg = format!(
            "\n{}/{} true positive test(s) failed:\n",
            failures.len(),
            total
        );
        for failure in &failures {
            let _ = writeln!(msg, "  {failure}");
        }
        panic!("{msg}");
    }

    println!("All {total} true positive tests passed with full isomorphism check");
}

#[test]
fn corpus_false_positives_isomorphism() {
    let (total, failures) = run_category_tests(CorpusCategory::FalsePositives);

    if !failures.is_empty() {
        let mut msg = format!(
            "\n{}/{} false positive test(s) failed:\n",
            failures.len(),
            total
        );
        for failure in &failures {
            let _ = writeln!(msg, "  {failure}");
        }
        panic!("{msg}");
    }

    println!("All {total} false positive tests passed with full isomorphism check");
}

#[test]
fn corpus_bypass_attempts_isomorphism() {
    let (total, failures) = run_category_tests(CorpusCategory::BypassAttempts);

    if !failures.is_empty() {
        let mut msg = format!(
            "\n{}/{} bypass attempt test(s) failed:\n",
            failures.len(),
            total
        );
        for failure in &failures {
            let _ = writeln!(msg, "  {failure}");
        }
        panic!("{msg}");
    }

    println!("All {total} bypass attempt tests passed with full isomorphism check");
}

#[test]
fn corpus_edge_cases_isomorphism() {
    let (total, failures) = run_category_tests(CorpusCategory::EdgeCases);

    // Edge cases should still pass verification (any decision is acceptable,
    // but if they have [case.log] sections, those should match)
    if !failures.is_empty() {
        let mut msg = format!("\n{}/{} edge case test(s) failed:\n", failures.len(), total);
        for failure in &failures {
            let _ = writeln!(msg, "  {failure}");
        }
        panic!("{msg}");
    }

    println!("All {total} edge case tests passed with full isomorphism check");
}

#[test]
fn corpus_full_summary() {
    let all_cases = load_all_cases();
    let mut passed = 0;
    let mut failed = 0;
    let mut failures = Vec::new();

    for (category, file, case) in &all_cases {
        match verify_corpus_case(case, *category) {
            Ok(()) => passed += 1,
            Err(msg) => {
                failed += 1;
                failures.push(format!("[{file}] {msg}"));
            }
        }
    }

    println!("\n=== Corpus Isomorphism Test Summary ===");
    println!(
        "Total: {} tests ({} passed, {} failed)",
        all_cases.len(),
        passed,
        failed
    );

    // Count by category
    let mut by_category: std::collections::HashMap<CorpusCategory, (usize, usize)> =
        std::collections::HashMap::new();
    for (category, _file, case) in &all_cases {
        let entry = by_category.entry(*category).or_insert((0, 0));
        entry.0 += 1;
        if verify_corpus_case(case, *category).is_ok() {
            entry.1 += 1;
        }
    }

    println!();
    for (category, (total, cat_passed)) in by_category {
        let status = if cat_passed == total { "OK" } else { "FAIL" };
        println!("  {category:?}: {cat_passed}/{total} [{status}]");
    }

    if !failures.is_empty() {
        println!("\nFailures (with reproduction commands):");
        for failure in &failures {
            println!("  {failure}");
        }
        panic!("\n{} corpus test(s) failed", failures.len());
    }
}

#[test]
fn scenario_fixtures_are_valid() {
    let scenario_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/scenarios");
    let mut entries: Vec<_> = fs::read_dir(&scenario_dir)
        .expect("Failed to read scenario fixtures directory")
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("yaml"))
        .collect();

    entries.sort();
    assert!(
        !entries.is_empty(),
        "No scenario fixtures found in {}",
        scenario_dir.display()
    );

    let mut ids = HashSet::new();
    let mut failures = Vec::new();

    for path in entries {
        match parse_scenario_fixture(&path) {
            Ok(fixture) => {
                let id = fixture.id.expect("id should be present");
                if !ids.insert(id.clone()) {
                    failures.push(format!("{}: duplicate id '{id}'", path.display()));
                }
            }
            Err(err) => failures.push(err),
        }
    }

    if !failures.is_empty() {
        let mut msg = String::from("\nScenario fixture validation failed:\n");
        for failure in &failures {
            let _ = writeln!(msg, "  {failure}");
        }
        panic!("{msg}");
    }
}
