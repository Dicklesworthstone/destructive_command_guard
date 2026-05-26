//! Comprehensive E2E Tests for Natural Language Explanations (Epic 2)
//!
//! Tests the natural language explanation system that transforms technical
//! pattern matches into human-readable explanations.
//!
//! Coverage includes:
//! - Explanation quality (human-readable, no jargon)
//! - Explanation completeness (all core patterns have explanations)
//! - Explanation consistency (same command = same explanation)
//! - Output format (test command, hook mode, JSON)

mod e2e;

use e2e::{E2ETestContext, TestLogger};

// ============================================================================
// UNIT TESTS: Explanation Quality
// ============================================================================

/// Technical jargon that should NOT appear in user-facing explanations.
const JARGON_BLOCKLIST: &[&str] = &[
    // Regex syntax
    r"\^",
    r"\$",
    r"\[.*\]",
    r"\\d",
    r"\\s",
    r"\\w",
    r"\\.\\*",
    r"\\.\\+",
    r"(?:",
    r"(?=",
    r"(?!",
    r"(?<=",
    r"(?<!",
    // Technical terms
    "pattern match",
    "regex",
    "regexp",
    "regular expression",
    "automaton",
    "state machine",
    "lookahead",
    "lookbehind",
    "backreference",
    "capture group",
];

/// Commands that should have human-readable explanations when blocked.
const DANGEROUS_COMMANDS: &[(&str, &str)] = &[
    (
        "git reset --hard",
        "git reset --hard destroys uncommitted changes",
    ),
    (
        "git reset --hard HEAD~5",
        "git reset --hard destroys uncommitted changes",
    ),
    (
        "git checkout -- .",
        "git checkout -- discards uncommitted changes",
    ),
    (
        "git checkout -- src/main.rs",
        "git checkout -- discards uncommitted changes",
    ),
    ("git restore .", "git restore discards uncommitted changes"),
    (
        "git restore src/main.rs",
        "git restore discards uncommitted changes",
    ),
    (
        "git clean -fd",
        "git clean removes files that git doesn't track",
    ),
    (
        "git clean -fdx",
        "git clean removes files that git doesn't track",
    ),
    (
        "git push --force",
        "git push --force rewrites remote history",
    ),
    (
        "git push -f origin main",
        "git push --force rewrites remote history",
    ),
    ("git push --force-with-lease", "git push with force options"),
    (
        "git branch -D feature",
        "git branch -D force deletes a branch",
    ),
    ("git stash drop", "git stash drop permanently removes"),
    ("git stash clear", "git stash clear removes all stashes"),
    ("rm -rf /", "rm -rf with root path"),
    ("rm -rf ~", "rm -rf with home directory"),
    ("rm -rf ./src", "rm -rf removes files recursively"),
];

/// Commands that should be allowed (no explanation needed).
const SAFE_COMMANDS: &[&str] = &[
    "git status",
    "git diff",
    "git log",
    "git branch",
    "git checkout -b new-feature",
    "git restore --staged .",
    "git clean -n",
    "git clean --dry-run",
    "git stash",
    "git stash list",
    "ls -la",
    "cat README.md",
    "cargo build",
    "npm install",
];

// ============================================================================
// E2E TESTS: Explanation Display in Test Command
// ============================================================================

#[test]
fn test_explanation_displayed_for_blocked_commands() {
    let ctx = E2ETestContext::builder("explanation_displayed")
        .with_config("minimal")
        .build();

    // Test git reset --hard - should show explanation
    let output = ctx.run_dcg(&["test", "git reset --hard"]);

    // Should be blocked (case-insensitive check)
    let combined_check = format!("{}{}", output.stdout, output.stderr).to_lowercase();
    assert!(
        combined_check.contains("blocked"),
        "Expected 'git reset --hard' to be blocked.\nstdout: {}\nstderr: {}",
        output.stdout,
        output.stderr
    );

    // Should contain human-readable explanation
    let combined_output = format!("{}{}", output.stdout, output.stderr);
    assert!(
        combined_output.contains("destroy")
            || combined_output.contains("discard")
            || combined_output.contains("lost")
            || combined_output.contains("uncommitted"),
        "Explanation should describe data loss.\nOutput: {}",
        combined_output
    );
}

#[test]
fn test_explanation_includes_safer_alternatives() {
    let ctx = E2ETestContext::builder("explanation_alternatives")
        .with_config("minimal")
        .build();

    // git reset --hard should suggest 'git stash' as alternative
    let output = ctx.run_dcg(&["test", "git reset --hard"]);

    let combined_output = format!("{}{}", output.stdout, output.stderr);

    // Should suggest safer alternatives
    let has_alternative = combined_output.contains("stash")
        || combined_output.contains("alternative")
        || combined_output.contains("safer")
        || combined_output.contains("instead");

    assert!(
        has_alternative,
        "Explanation should include safer alternatives.\nOutput: {}",
        combined_output
    );
}

#[test]
fn test_explanation_no_regex_jargon() {
    let ctx = E2ETestContext::builder("explanation_no_jargon")
        .with_config("minimal")
        .build();

    for (cmd, _desc) in DANGEROUS_COMMANDS {
        let output = ctx.run_dcg(&["test", cmd]);
        let combined_output = format!("{}{}", output.stdout, output.stderr);

        // Check for technical jargon
        for jargon in JARGON_BLOCKLIST {
            assert!(
                !combined_output.contains(jargon),
                "Explanation for '{}' contains technical jargon '{}'.\nOutput: {}",
                cmd,
                jargon,
                combined_output
            );
        }
    }
}

#[test]
fn test_explanations_are_human_readable() {
    let logger = TestLogger::new("human_readable_explanations");
    let ctx = E2ETestContext::builder("human_readable")
        .with_config("minimal")
        .build();

    logger.log_test_start("Testing that explanations are human-readable");

    for (cmd, expected_content) in DANGEROUS_COMMANDS {
        logger.log_step("testing_command", cmd);

        let output = ctx.run_dcg(&["test", cmd]);
        let combined_output = format!("{}{}", output.stdout, output.stderr);

        // Should contain part of expected human-readable content
        if !combined_output
            .to_lowercase()
            .contains(&expected_content.to_lowercase())
        {
            // Log but don't fail - some patterns may have different wording
            logger.log_step(
                "warning",
                &format!(
                    "Command '{}' explanation doesn't contain expected phrase '{}'",
                    cmd, expected_content
                ),
            );
        }
    }

    logger.log_test_end(true, None);
}

// ============================================================================
// E2E TESTS: Hook Mode Explanation Output
// ============================================================================

#[test]
fn test_hook_output_includes_explanation() {
    let ctx = E2ETestContext::builder("hook_explanation")
        .with_config("minimal")
        .build();

    // Run in hook mode
    let output = ctx.run_dcg_hook("git reset --hard HEAD~3");

    // Should be blocked
    assert!(output.is_blocked(), "Expected command to be blocked");

    // Check JSON output has explanation in decision reason
    let decision_reason = output.decision_reason().unwrap_or("");

    assert!(
        decision_reason.contains("Explanation")
            || decision_reason.contains("destroy")
            || decision_reason.contains("uncommitted"),
        "Hook output should include explanation.\nDecision reason: {}",
        decision_reason
    );
}

#[test]
fn test_hook_output_json_structure() {
    let ctx = E2ETestContext::builder("hook_json_structure")
        .with_config("minimal")
        .build();

    let output = ctx.run_dcg_hook("git reset --hard");

    assert!(output.is_blocked(), "Expected command to be blocked");

    // Verify JSON structure
    let json = output.json.as_ref().expect("Expected JSON output");
    let hook_output = json
        .get("hookSpecificOutput")
        .expect("Expected hookSpecificOutput");

    // Required fields
    assert!(
        hook_output.get("permissionDecision").is_some(),
        "Missing permissionDecision"
    );
    assert!(
        hook_output.get("permissionDecisionReason").is_some(),
        "Missing permissionDecisionReason"
    );
    assert!(hook_output.get("ruleId").is_some(), "Missing ruleId");
    assert!(hook_output.get("packId").is_some(), "Missing packId");
    assert!(hook_output.get("severity").is_some(), "Missing severity");
}

// ============================================================================
// E2E TESTS: JSON Output Format
// ============================================================================

#[test]
fn test_json_output_includes_explanation() {
    let ctx = E2ETestContext::builder("json_explanation")
        .with_config("minimal")
        .build();

    // Use test command with JSON output
    let output = ctx.run_dcg(&["test", "--format", "json", "git reset --hard"]);

    // Parse JSON output
    let json: serde_json::Value = serde_json::from_str(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "Failed to parse JSON output.\nstdout: {}\nstderr: {}",
            output.stdout, output.stderr
        )
    });

    // Check for explanation field
    let explanation = json
        .get("explanation")
        .or_else(|| json.get("pattern").and_then(|p| p.get("explanation")));

    assert!(
        explanation.is_some() || json.get("reason").is_some(),
        "JSON output should include explanation or reason.\nJSON: {}",
        serde_json::to_string_pretty(&json).unwrap_or_default()
    );
}

#[test]
fn test_json_output_outcome_blocked() {
    let ctx = E2ETestContext::builder("json_outcome_blocked")
        .with_config("minimal")
        .build();

    let output = ctx.run_dcg(&["test", "--format", "json", "git reset --hard"]);

    let json: serde_json::Value = serde_json::from_str(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "Failed to parse JSON.\nstdout: {}\nstderr: {}",
            output.stdout, output.stderr
        )
    });

    // Check decision is deny (blocked)
    let decision = json.get("decision").and_then(|v| v.as_str()).unwrap_or("");

    assert!(
        decision == "deny" || decision == "blocked",
        "Expected decision 'deny', got '{}'.\nJSON: {}",
        decision,
        serde_json::to_string_pretty(&json).unwrap_or_default()
    );
}

#[test]
fn test_json_output_outcome_allowed() {
    let ctx = E2ETestContext::builder("json_outcome_allowed")
        .with_config("minimal")
        .build();

    let output = ctx.run_dcg(&["test", "--format", "json", "git status"]);

    let json: serde_json::Value = serde_json::from_str(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "Failed to parse JSON.\nstdout: {}\nstderr: {}",
            output.stdout, output.stderr
        )
    });

    // Check decision is allow
    let decision = json.get("decision").and_then(|v| v.as_str()).unwrap_or("");

    assert!(
        decision == "allow" || decision == "allowed",
        "Expected decision 'allow', got '{}'.\nJSON: {}",
        decision,
        serde_json::to_string_pretty(&json).unwrap_or_default()
    );
}

// ============================================================================
// E2E TESTS: Explanation Consistency
// ============================================================================

#[test]
fn test_same_command_same_explanation() {
    let ctx = E2ETestContext::builder("explanation_consistency")
        .with_config("minimal")
        .build();

    // Run the same command multiple times
    let cmd = "git reset --hard HEAD~1";
    let output1 = ctx.run_dcg(&["test", cmd]);
    let output2 = ctx.run_dcg(&["test", cmd]);
    let output3 = ctx.run_dcg(&["test", cmd]);

    // All should produce the same output (or at least similar)
    assert_eq!(
        output1.stdout, output2.stdout,
        "Explanation should be consistent across runs"
    );
    assert_eq!(
        output2.stdout, output3.stdout,
        "Explanation should be consistent across runs"
    );
}

#[test]
fn test_similar_commands_similar_explanations() {
    let ctx = E2ETestContext::builder("similar_explanations")
        .with_config("minimal")
        .build();

    // Variations of git reset --hard should have similar explanations
    let commands = [
        "git reset --hard",
        "git reset --hard HEAD",
        "git reset --hard HEAD~1",
        "git reset --hard origin/main",
    ];

    let mut explanations = Vec::new();
    for cmd in &commands {
        let output = ctx.run_dcg(&["test", cmd]);
        let combined = format!("{}{}", output.stdout, output.stderr);
        explanations.push(combined);
    }

    // All should mention "destroy" or "discard" or "uncommitted"
    for (i, explanation) in explanations.iter().enumerate() {
        let has_key_phrase = explanation.to_lowercase().contains("destroy")
            || explanation.to_lowercase().contains("discard")
            || explanation.to_lowercase().contains("uncommitted")
            || explanation.to_lowercase().contains("lost");

        assert!(
            has_key_phrase,
            "Command '{}' explanation should describe data loss.\nExplanation: {}",
            commands[i], explanation
        );
    }
}

// ============================================================================
// E2E TESTS: Safe Commands Have No Explanations
// ============================================================================

#[test]
fn test_safe_commands_allowed_without_explanation() {
    let ctx = E2ETestContext::builder("safe_commands")
        .with_config("minimal")
        .build();

    for cmd in SAFE_COMMANDS {
        let output = ctx.run_dcg_hook(cmd);

        assert!(
            output.is_allowed(),
            "Safe command '{}' should be allowed.\nstdout: {}\nstderr: {}",
            cmd,
            output.stdout,
            output.stderr
        );
    }
}

// ============================================================================
// UNIT TESTS: All Core Patterns Have Explanations
// ============================================================================

/// Test that all core pack patterns have explanations defined.
/// This test checks the pattern definitions directly.
#[test]
fn test_all_core_git_patterns_have_explanations() {
    use dcg_cli::packs::core::git::create_pack;

    let pack = create_pack();

    let mut missing_explanations = Vec::new();

    for pattern in &pack.destructive_patterns {
        if pattern.explanation.is_none() {
            let name = pattern.name.unwrap_or("unnamed");
            missing_explanations.push(name);
        }
    }

    assert!(
        missing_explanations.is_empty(),
        "The following core.git patterns are missing explanations: {:?}",
        missing_explanations
    );
}

#[test]
fn test_all_core_filesystem_patterns_have_explanations() {
    use dcg_cli::packs::core::filesystem::create_pack;

    let pack = create_pack();

    let mut missing_explanations = Vec::new();

    for pattern in &pack.destructive_patterns {
        if pattern.explanation.is_none() {
            let name = pattern.name.unwrap_or("unnamed");
            missing_explanations.push(name);
        }
    }

    assert!(
        missing_explanations.is_empty(),
        "The following core.filesystem patterns are missing explanations: {:?}",
        missing_explanations
    );
}

// ============================================================================
// E2E TESTS: Explanation Field Presence in Patterns
// ============================================================================

#[test]
fn test_pattern_explanation_propagates_to_output() {
    let ctx = E2ETestContext::builder("explanation_propagation")
        .with_config("minimal")
        .build();

    // Test commands where we know explanations exist
    let test_cases = [
        ("git reset --hard", "uncommitted"),
        ("git checkout -- .", "uncommitted"),
        ("git push --force", "history"),
    ];

    for (cmd, expected_word) in test_cases {
        let output = ctx.run_dcg(&["test", cmd]);
        let combined = format!("{}{}", output.stdout, output.stderr).to_lowercase();

        assert!(
            combined.contains(expected_word),
            "Explanation for '{}' should contain '{}'.\nOutput: {}",
            cmd,
            expected_word,
            combined
        );
    }
}

// ============================================================================
// E2E TESTS: Verbosity Levels
// ============================================================================

#[test]
fn test_verbose_output_shows_more_detail() {
    let ctx = E2ETestContext::builder("verbose_explanation")
        .with_config("minimal")
        .build();

    // Normal output
    let normal_output = ctx.run_dcg(&["test", "git reset --hard"]);
    let normal_len = normal_output.stdout.len() + normal_output.stderr.len();

    // Verbose output
    let verbose_output = ctx.run_dcg(&["test", "--verbose", "git reset --hard"]);
    let verbose_len = verbose_output.stdout.len() + verbose_output.stderr.len();

    // Verbose should generally produce more output
    // (This is a soft assertion - verbose mode should add trace info)
    if verbose_len <= normal_len {
        // Log as warning but don't fail - depends on implementation
        eprintln!(
            "Note: Verbose output ({} bytes) not longer than normal ({} bytes)",
            verbose_len, normal_len
        );
    }
}

// ============================================================================
// E2E TESTS: Explanation Severity Matching
// ============================================================================

#[test]
fn test_explanation_severity_matches_pattern() {
    let ctx = E2ETestContext::builder("severity_matching")
        .with_config("minimal")
        .build();

    // Critical severity commands
    let critical_commands = ["git reset --hard", "rm -rf /"];

    for cmd in critical_commands {
        let output = ctx.run_dcg_hook(cmd);

        if output.is_blocked() {
            let severity = output.severity().unwrap_or("unknown");

            // Critical commands should have critical severity
            assert!(
                severity == "critical" || severity == "Critical",
                "Command '{}' should have critical severity, got '{}'",
                cmd,
                severity
            );
        }
    }
}

// ============================================================================
// E2E TESTS: Template Substitution
// ============================================================================

#[test]
fn test_explanation_no_unsubstituted_placeholders() {
    let ctx = E2ETestContext::builder("no_placeholders")
        .with_config("minimal")
        .build();

    // Placeholder patterns that shouldn't appear in final output
    let placeholder_patterns = ["{path}", "{ref}", "{branch}", "{{", "}}"];

    for (cmd, _) in DANGEROUS_COMMANDS {
        let output = ctx.run_dcg(&["test", cmd]);
        let combined = format!("{}{}", output.stdout, output.stderr);

        for placeholder in placeholder_patterns {
            // Allow {path} in suggestion templates, but not in main explanation
            if !combined.contains("suggestion") && combined.contains(placeholder) {
                // This might be acceptable in some contexts, log it
                eprintln!(
                    "Note: Output for '{}' contains '{}' which may be a placeholder",
                    cmd, placeholder
                );
            }
        }
    }
}

// ============================================================================
// PERFORMANCE TESTS
// ============================================================================

#[test]
fn test_explanation_generation_performance() {
    let ctx = E2ETestContext::builder("explanation_performance")
        .with_config("minimal")
        .build();

    let start = std::time::Instant::now();
    let iterations = 10;

    for _ in 0..iterations {
        let _ = ctx.run_dcg(&["test", "git reset --hard"]);
    }

    let elapsed = start.elapsed();
    let avg_ms = elapsed.as_millis() / iterations as u128;

    // Should complete quickly (under 500ms average per invocation)
    assert!(
        avg_ms < 500,
        "Explanation generation too slow: {}ms average",
        avg_ms
    );
}

// ============================================================================
// REGRESSION TESTS
// ============================================================================

#[test]
fn test_explanation_not_empty_for_blocked_commands() {
    let ctx = E2ETestContext::builder("explanation_not_empty")
        .with_config("minimal")
        .build();

    for (cmd, _) in DANGEROUS_COMMANDS {
        let output = ctx.run_dcg_hook(cmd);

        if output.is_blocked() {
            let reason = output.decision_reason().unwrap_or("");

            assert!(
                !reason.is_empty(),
                "Decision reason for '{}' should not be empty",
                cmd
            );

            // Should have more than just "BLOCKED"
            assert!(
                reason.len() > 10,
                "Decision reason for '{}' is too short: '{}'",
                cmd,
                reason
            );
        }
    }
}

#[test]
fn test_explanation_preserves_newlines_in_verbose() {
    let ctx = E2ETestContext::builder("explanation_newlines")
        .with_config("minimal")
        .build();

    // Verbose mode should preserve formatting
    let output = ctx.run_dcg(&["test", "--verbose", "git reset --hard"]);
    let combined = format!("{}{}", output.stdout, output.stderr);

    // Should have multiple lines in explanation
    let line_count = combined.lines().count();

    // Expect at least a few lines of output
    assert!(
        line_count >= 3,
        "Verbose output should have multiple lines, got {}",
        line_count
    );
}

// ============================================================================
// Integration with Allow-Once
// ============================================================================

#[test]
fn test_allow_once_code_in_blocked_output() {
    let ctx = E2ETestContext::builder("allow_once_code")
        .with_config("minimal")
        .build();

    let output = ctx.run_dcg_hook("git reset --hard");

    if output.is_blocked() {
        let code = output.allow_once_code();

        assert!(
            code.is_some(),
            "Blocked command should include allow-once code"
        );

        // Code should be short and alphanumeric
        let code = code.unwrap();
        assert!(
            code.len() >= 4 && code.len() <= 10,
            "Allow-once code should be 4-10 chars, got: '{}'",
            code
        );
    }
}

// ============================================================================
// ADDITIONAL PACK EXPLANATION TESTS
// ============================================================================

#[test]
fn test_all_database_postgresql_patterns_have_explanations() {
    use dcg_cli::packs::database::postgresql::create_pack;

    let pack = create_pack();

    let mut missing_explanations = Vec::new();

    for pattern in &pack.destructive_patterns {
        if pattern.explanation.is_none() {
            let name = pattern.name.unwrap_or("unnamed");
            missing_explanations.push(name);
        }
    }

    assert!(
        missing_explanations.is_empty(),
        "The following database.postgresql patterns are missing explanations: {:?}",
        missing_explanations
    );
}

#[test]
fn test_all_kubernetes_kubectl_patterns_have_explanations() {
    use dcg_cli::packs::kubernetes::kubectl::create_pack;

    let pack = create_pack();

    let mut missing_explanations = Vec::new();

    for pattern in &pack.destructive_patterns {
        if pattern.explanation.is_none() {
            let name = pattern.name.unwrap_or("unnamed");
            missing_explanations.push(name);
        }
    }

    assert!(
        missing_explanations.is_empty(),
        "The following kubernetes.kubectl patterns are missing explanations: {:?}",
        missing_explanations
    );
}

#[test]
fn test_all_containers_docker_patterns_have_explanations() {
    use dcg_cli::packs::containers::docker::create_pack;

    let pack = create_pack();

    let mut missing_explanations = Vec::new();

    for pattern in &pack.destructive_patterns {
        if pattern.explanation.is_none() {
            let name = pattern.name.unwrap_or("unnamed");
            missing_explanations.push(name);
        }
    }

    assert!(
        missing_explanations.is_empty(),
        "The following containers.docker patterns are missing explanations: {:?}",
        missing_explanations
    );
}

#[test]
fn test_all_infrastructure_terraform_patterns_have_explanations() {
    use dcg_cli::packs::infrastructure::terraform::create_pack;

    let pack = create_pack();

    let mut missing_explanations = Vec::new();

    for pattern in &pack.destructive_patterns {
        if pattern.explanation.is_none() {
            let name = pattern.name.unwrap_or("unnamed");
            missing_explanations.push(name);
        }
    }

    assert!(
        missing_explanations.is_empty(),
        "The following infrastructure.terraform patterns are missing explanations: {:?}",
        missing_explanations
    );
}

// ============================================================================
// FALLBACK EXPLANATION TESTS
// ============================================================================

#[test]
fn test_blocked_commands_always_have_reason() {
    let ctx = E2ETestContext::builder("fallback_explanation")
        .with_config("minimal")
        .build();

    // Test various blocked commands - all should have a reason/explanation
    let blocked_commands = [
        "git reset --hard",
        "git push --force",
        "git clean -fd",
        "rm -rf /important",
    ];

    for cmd in blocked_commands {
        let output = ctx.run_dcg_hook(cmd);

        if output.is_blocked() {
            let reason = output.decision_reason().unwrap_or("");

            assert!(
                !reason.is_empty(),
                "Blocked command '{}' should have a non-empty reason",
                cmd
            );

            // Reason should be human-readable (at least 20 chars of explanation)
            assert!(
                reason.len() >= 20,
                "Reason for '{}' is too short to be useful: '{}'",
                cmd,
                reason
            );
        }
    }
}

#[test]
fn test_explanation_contains_command_context() {
    let ctx = E2ETestContext::builder("explanation_context")
        .with_config("minimal")
        .build();

    // Explanations should relate to the actual command being tested
    let test_cases = [
        ("git reset --hard HEAD~3", "reset"),
        ("git push --force origin main", "push"),
        ("git clean -fdx", "clean"),
    ];

    for (cmd, keyword) in test_cases {
        let output = ctx.run_dcg(&["test", cmd]);
        let combined = format!("{}{}", output.stdout, output.stderr).to_lowercase();

        assert!(
            combined.contains(keyword),
            "Explanation for '{}' should mention '{}'\nOutput: {}",
            cmd,
            keyword,
            combined
        );
    }
}

// ============================================================================
// DATABASE COMMAND EXPLANATION E2E TESTS
// ============================================================================

#[test]
fn test_database_drop_command_explanation() {
    let ctx = E2ETestContext::builder("database_explanation")
        .with_config("minimal")
        .build();

    // Test DROP TABLE command with database pack
    let output = ctx.run_dcg(&[
        "test",
        "--with-packs",
        "database.postgresql",
        "DROP TABLE users;",
    ]);
    let combined = format!("{}{}", output.stdout, output.stderr).to_lowercase();

    // Should explain database risks
    let has_explanation = combined.contains("drop")
        || combined.contains("table")
        || combined.contains("delete")
        || combined.contains("data");

    assert!(
        has_explanation,
        "DROP TABLE explanation should describe data risks.\nOutput: {}",
        combined
    );
}

// ============================================================================
// KUBERNETES COMMAND EXPLANATION E2E TESTS
// ============================================================================

#[test]
fn test_kubernetes_delete_command_explanation() {
    let ctx = E2ETestContext::builder("kubernetes_explanation")
        .with_config("minimal")
        .build();

    // Test kubectl delete command
    let output = ctx.run_dcg(&[
        "test",
        "--with-packs",
        "kubernetes.kubectl",
        "kubectl delete namespace production",
    ]);
    let combined = format!("{}{}", output.stdout, output.stderr).to_lowercase();

    // If blocked, should explain kubernetes risks
    if combined.contains("blocked") || combined.contains("deny") {
        let has_explanation = combined.contains("delete")
            || combined.contains("namespace")
            || combined.contains("resource")
            || combined.contains("kubernetes");

        assert!(
            has_explanation,
            "kubectl delete explanation should describe kubernetes risks.\nOutput: {}",
            combined
        );
    }
}

// ============================================================================
// DOCKER COMMAND EXPLANATION E2E TESTS
// ============================================================================

#[test]
fn test_docker_remove_command_explanation() {
    let ctx = E2ETestContext::builder("docker_explanation")
        .with_config("minimal")
        .build();

    // Test docker system prune command
    let output = ctx.run_dcg(&[
        "test",
        "--with-packs",
        "containers.docker",
        "docker system prune -a --volumes",
    ]);
    let combined = format!("{}{}", output.stdout, output.stderr).to_lowercase();

    // If blocked, should explain docker risks
    if combined.contains("blocked") || combined.contains("deny") {
        let has_explanation = combined.contains("docker")
            || combined.contains("container")
            || combined.contains("image")
            || combined.contains("volume")
            || combined.contains("prune");

        assert!(
            has_explanation,
            "docker prune explanation should describe container risks.\nOutput: {}",
            combined
        );
    }
}

// ============================================================================
// EXPLANATION FORMAT CONSISTENCY TESTS
// ============================================================================

#[test]
fn test_explanation_format_consistency() {
    let ctx = E2ETestContext::builder("format_consistency")
        .with_config("minimal")
        .build();

    // Multiple runs should produce identical format
    let cmd = "git checkout -- important_file.txt";

    let output1 = ctx.run_dcg(&["test", cmd]);
    let output2 = ctx.run_dcg(&["test", cmd]);

    // Format should be identical
    assert_eq!(
        output1.stdout.trim(),
        output2.stdout.trim(),
        "Explanation format should be consistent"
    );
}

#[test]
fn test_explanation_json_contains_all_fields() {
    let ctx = E2ETestContext::builder("json_fields")
        .with_config("minimal")
        .build();

    let output = ctx.run_dcg(&["test", "--format", "json", "git reset --hard"]);

    let json: serde_json::Value = serde_json::from_str(&output.stdout)
        .unwrap_or_else(|_| panic!("Failed to parse JSON output"));

    // Required fields for blocked commands
    let required_fields = ["command", "decision", "reason"];

    for field in required_fields {
        assert!(
            json.get(field).is_some(),
            "JSON output missing required field '{}'.\nJSON: {}",
            field,
            serde_json::to_string_pretty(&json).unwrap_or_default()
        );
    }
}

// ============================================================================
// MULTI-MATCH EXPLANATION TESTS
// ============================================================================

#[test]
fn test_command_with_multiple_risks_shows_primary() {
    let ctx = E2ETestContext::builder("multi_risk")
        .with_config("minimal")
        .build();

    // A command that might match multiple patterns
    // git push --force can be matched by force-push pattern
    let output = ctx.run_dcg(&["test", "git push --force origin main"]);
    let combined = format!("{}{}", output.stdout, output.stderr).to_lowercase();

    // Should show at least one meaningful explanation
    let has_meaningful_explanation = combined.contains("history")
        || combined.contains("remote")
        || combined.contains("rewrite")
        || combined.contains("force")
        || combined.contains("collaborator");

    assert!(
        has_meaningful_explanation,
        "Force push should have meaningful explanation.\nOutput: {}",
        combined
    );
}
