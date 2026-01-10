//! Golden isomorphism tests for the evaluator.
//!
//! This module implements tests that verify exact behavior preservation across refactors.
//! It evaluates commands from the canonical corpus and compares results against expected
//! outputs, failing on any divergence.
//!
//! # Purpose
//!
//! These tests are the "gate" for all refactors. If a change is intentionally
//! behavior-altering, it must be addressed as a separate policy task.
//!
//! # How It Works
//!
//! 1. Load test cases from `tests/corpus/` TOML files
//! 2. Evaluate each command using the full evaluator pipeline
//! 3. Compare against expected results (from the TOML `expected` field + optional `rule_id`)
//! 4. Report any divergences with actionable reproduction commands
//!
//! # Running
//!
//! ```bash
//! cargo test golden_isomorphism
//! cargo test golden_isomorphism -- --nocapture  # Show details
//! ```

use destructive_command_guard::packs::test_helpers::{
    CorpusCategory, assert_allows_command, assert_denies_with_rule, eval_snapshot, load_corpus_dir,
    verify_corpus_batch, verify_corpus_case,
};
use std::path::Path;

/// Test that all `true_positives` corpus cases are correctly denied.
///
/// These are dangerous commands that MUST be blocked.
#[test]
fn golden_true_positives_all_denied() {
    let corpus_dir = Path::new("tests/corpus");
    let cases = load_corpus_dir(corpus_dir).expect("Failed to load corpus");

    let true_positives: Vec<_> = cases
        .iter()
        .filter(|(cat, _, _)| *cat == CorpusCategory::TruePositives)
        .collect();

    assert!(
        !true_positives.is_empty(),
        "No true_positives cases found in corpus"
    );

    let mut failures = Vec::new();
    for (category, file, case) in &true_positives {
        if let Err(msg) = verify_corpus_case(case, *category) {
            failures.push(format!("[{file}] {msg}"));
        }
    }

    assert!(
        failures.is_empty(),
        "True positives verification failed ({} failures):\n\n{}",
        failures.len(),
        failures.join("\n\n---\n\n")
    );

    println!(
        "Verified {} true_positives cases - all correctly denied",
        true_positives.len()
    );
}

/// Test that all `false_positives` corpus cases are correctly allowed.
///
/// These are safe commands that MUST NOT be blocked.
#[test]
fn golden_false_positives_all_allowed() {
    let corpus_dir = Path::new("tests/corpus");
    let cases = load_corpus_dir(corpus_dir).expect("Failed to load corpus");

    let false_positives: Vec<_> = cases
        .iter()
        .filter(|(cat, _, _)| *cat == CorpusCategory::FalsePositives)
        .collect();

    assert!(
        !false_positives.is_empty(),
        "No false_positives cases found in corpus"
    );

    let mut failures = Vec::new();
    for (category, file, case) in &false_positives {
        if let Err(msg) = verify_corpus_case(case, *category) {
            failures.push(format!("[{file}] {msg}"));
        }
    }

    assert!(
        failures.is_empty(),
        "False positives verification failed ({} failures):\n\n{}",
        failures.len(),
        failures.join("\n\n---\n\n")
    );

    println!(
        "Verified {} false_positives cases - all correctly allowed",
        false_positives.len()
    );
}

/// Test that all `bypass_attempts` corpus cases are correctly denied.
///
/// These are attempts to bypass security that MUST still be blocked.
#[test]
fn golden_bypass_attempts_all_denied() {
    let corpus_dir = Path::new("tests/corpus");
    let cases = load_corpus_dir(corpus_dir).expect("Failed to load corpus");

    let bypass_attempts: Vec<_> = cases
        .iter()
        .filter(|(cat, _, _)| *cat == CorpusCategory::BypassAttempts)
        .collect();

    assert!(
        !bypass_attempts.is_empty(),
        "No bypass_attempts cases found in corpus"
    );

    let mut failures = Vec::new();
    for (category, file, case) in &bypass_attempts {
        if let Err(msg) = verify_corpus_case(case, *category) {
            failures.push(format!("[{file}] {msg}"));
        }
    }

    assert!(
        failures.is_empty(),
        "Bypass attempts verification failed ({} failures):\n\n{}",
        failures.len(),
        failures.join("\n\n---\n\n")
    );

    println!(
        "Verified {} bypass_attempts cases - all correctly denied",
        bypass_attempts.len()
    );
}

/// Test that `edge_cases` parse and evaluate without crashing.
///
/// For edge cases, we don't require a specific outcome - just that
/// they don't cause panics, infinite loops, or other issues.
#[test]
fn golden_edge_cases_stable() {
    let corpus_dir = Path::new("tests/corpus");
    let cases = load_corpus_dir(corpus_dir).expect("Failed to load corpus");

    let edge_cases: Vec<_> = cases
        .iter()
        .filter(|(cat, _, _)| *cat == CorpusCategory::EdgeCases)
        .collect();

    assert!(
        !edge_cases.is_empty(),
        "No edge_cases cases found in corpus"
    );

    // For edge cases, just verify they don't crash
    for (_category, file, case) in &edge_cases {
        let snapshot = eval_snapshot(&case.command);
        // Just verify we got a valid decision (didn't crash)
        assert!(
            snapshot.decision == "allow" || snapshot.decision == "deny",
            "[{file}] Invalid decision for edge case: {}",
            case.command
        );
    }

    println!(
        "Verified {} edge_cases - all evaluated without crashing",
        edge_cases.len()
    );
}

/// Full corpus verification - runs all categories and reports aggregate results.
#[test]
fn golden_full_corpus_verification() {
    let corpus_dir = Path::new("tests/corpus");
    let cases = load_corpus_dir(corpus_dir).expect("Failed to load corpus");

    assert!(!cases.is_empty(), "No corpus cases found");

    let (passed, failed, failures) = verify_corpus_batch(
        &cases
            .iter()
            .map(|(cat, file, case)| (*cat, file.clone(), case.clone()))
            .collect::<Vec<_>>(),
    );

    println!("\n=== Golden Isomorphism Test Results ===");
    println!("Total cases: {}", passed + failed);
    println!("Passed: {passed}");
    println!("Failed: {failed}");

    if failed > 0 {
        println!("\n=== Failures ===\n");
        for (i, failure) in failures.iter().enumerate() {
            println!("--- Failure {} ---\n{}\n", i + 1, failure);
        }
        panic!(
            "Golden isomorphism test failed: {} of {} cases failed",
            failed,
            passed + failed
        );
    }

    println!("\nAll {passed} cases verified successfully!");
}

/// Test specific `rule_id` matching for critical patterns.
///
/// Verifies that specific commands are blocked by the expected rules.
#[test]
fn golden_rule_id_verification() {
    // Git destructive commands
    assert_denies_with_rule("git reset --hard", "core.git:reset-hard");
    assert_denies_with_rule("git reset --hard HEAD~1", "core.git:reset-hard");
    assert_denies_with_rule("git clean -fd", "core.git:clean-force");
    assert_denies_with_rule("git clean -fdx", "core.git:clean-force");
    assert_denies_with_rule("git push --force", "core.git:push-force-long");
    assert_denies_with_rule("git push -f origin main", "core.git:push-force-short");
    assert_denies_with_rule("git checkout -- .", "core.git:checkout-discard");

    // Filesystem destructive commands
    assert_denies_with_rule("rm -rf /home/user", "core.filesystem:rm-rf-root-home");
    assert_denies_with_rule("rm -rf /*", "core.filesystem:rm-rf-root-home");

    println!("All rule_id verifications passed!");
}

/// Test that safe commands are correctly allowed.
#[test]
fn golden_safe_commands_allowed() {
    // Safe git commands
    assert_allows_command("git status");
    assert_allows_command("git log");
    assert_allows_command("git diff");
    assert_allows_command("git branch");
    assert_allows_command("git fetch");
    assert_allows_command("git pull");
    assert_allows_command("git checkout -b feature");
    assert_allows_command("git stash");
    assert_allows_command("git stash pop");

    // Safe filesystem commands
    assert_allows_command("ls -la");
    assert_allows_command("cat file.txt");
    assert_allows_command("mkdir newdir");
    assert_allows_command("cp file1 file2");
    assert_allows_command("mv file1 file2");

    // Safe rm commands (non-recursive single files)
    assert_allows_command("rm file.txt");
    assert_allows_command("rm -f file.txt");

    println!("All safe command verifications passed!");
}

/// Test decision consistency - same command should always produce same result.
#[test]
fn golden_decision_consistency() {
    let test_commands = [
        "git reset --hard",
        "git status",
        "rm -rf /home",
        "rm file.txt",
        "git clean -fd",
        "ls -la",
    ];

    for cmd in &test_commands {
        let snapshot1 = eval_snapshot(cmd);
        let snapshot2 = eval_snapshot(cmd);

        assert_eq!(
            snapshot1.decision, snapshot2.decision,
            "Inconsistent decision for command: {cmd}"
        );
        assert_eq!(
            snapshot1.rule_id, snapshot2.rule_id,
            "Inconsistent rule_id for command: {cmd}"
        );
        assert_eq!(
            snapshot1.pack_id, snapshot2.pack_id,
            "Inconsistent pack_id for command: {cmd}"
        );
    }

    println!("All consistency checks passed!");
}

/// Verify category-based invariants hold.
#[test]
fn golden_category_invariants() {
    let corpus_dir = Path::new("tests/corpus");
    let cases = load_corpus_dir(corpus_dir).expect("Failed to load corpus");

    // Invariant 1: True positives must all be denied
    let true_pos_denied = cases
        .iter()
        .filter(|(cat, _, _)| *cat == CorpusCategory::TruePositives)
        .all(|(_, _, case)| eval_snapshot(&case.command).decision == "deny");
    assert!(
        true_pos_denied,
        "Invariant violation: Not all true_positives are denied"
    );

    // Invariant 2: False positives must all be allowed
    let false_pos_allowed = cases
        .iter()
        .filter(|(cat, _, _)| *cat == CorpusCategory::FalsePositives)
        .all(|(_, _, case)| eval_snapshot(&case.command).decision == "allow");
    assert!(
        false_pos_allowed,
        "Invariant violation: Not all false_positives are allowed"
    );

    // Invariant 3: Bypass attempts must all be denied
    let bypass_denied = cases
        .iter()
        .filter(|(cat, _, _)| *cat == CorpusCategory::BypassAttempts)
        .all(|(_, _, case)| eval_snapshot(&case.command).decision == "deny");
    assert!(
        bypass_denied,
        "Invariant violation: Not all bypass_attempts are denied"
    );

    println!("All category invariants verified!");
}
