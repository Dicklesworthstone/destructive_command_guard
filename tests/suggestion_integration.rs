//! Integration tests for Command Rewriting Suggestions end-to-end flow.
//!
//! These tests verify the complete flow of the suggestion system:
//! - Enhanced suggestions generation from command entries
//! - Filtering by confidence and risk
//! - Path-specific suggestion generation
//! - Interaction between clustering and scoring
//!
//! Part of git_safety_guard-x1l7: [E3-T9] Comprehensive testing for Command Rewriting Suggestions

use destructive_command_guard::suggest::{
    AllowlistSuggestion, CommandEntryInfo, ConfidenceTier, RiskLevel, SuggestionReason,
    filter_by_confidence, filter_by_risk, generate_enhanced_suggestions,
};

// ============================================================================
// Enhanced Suggestions Generation Tests
// ============================================================================

fn create_test_entries(
    commands: &[(&str, &str, bool)],
    count_per_cmd: usize,
) -> Vec<CommandEntryInfo> {
    let mut entries = Vec::new();
    for (cmd, dir, bypassed) in commands {
        for _ in 0..count_per_cmd {
            entries.push(CommandEntryInfo {
                command: cmd.to_string(),
                working_dir: dir.to_string(),
                was_bypassed: *bypassed,
            });
        }
    }
    entries
}

#[test]
fn generate_enhanced_suggestions_empty_input() {
    let entries: Vec<CommandEntryInfo> = vec![];
    let suggestions = generate_enhanced_suggestions(&entries, 1);
    assert!(suggestions.is_empty());
}

#[test]
fn generate_enhanced_suggestions_single_command_high_frequency() {
    let entries = create_test_entries(&[("npm run build", "/data/projects/myapp", false)], 15);

    let suggestions = generate_enhanced_suggestions(&entries, 3);

    assert!(
        !suggestions.is_empty(),
        "Should generate suggestion for high-frequency command"
    );
    let suggestion = &suggestions[0];
    // High frequency (15) with single variant = High confidence
    assert_eq!(suggestion.confidence, ConfidenceTier::High);
    assert_eq!(suggestion.risk, RiskLevel::Low);
    assert!(suggestion.cluster.commands[0].contains("npm run build"));
}

#[test]
fn generate_enhanced_suggestions_filters_high_risk_git_reset() {
    let entries = create_test_entries(
        &[("git reset --hard HEAD", "/data/projects/myapp", true)],
        15,
    );

    let suggestions = generate_enhanced_suggestions(&entries, 3);

    assert!(
        suggestions.is_empty(),
        "high-frequency bypassed git reset --hard must never be auto-suggested"
    );
}

#[test]
fn generate_enhanced_suggestions_filters_by_min_frequency() {
    let entries = create_test_entries(
        &[
            ("git reset --hard HEAD", "/data/projects/app1", false),
            ("npm run build", "/data/projects/app2", false),
        ],
        2, // Below min_frequency=3
    );

    let suggestions = generate_enhanced_suggestions(&entries, 3);
    assert!(
        suggestions.is_empty(),
        "Commands below min_frequency should not generate suggestions"
    );
}

#[test]
fn generate_enhanced_suggestions_with_bypasses() {
    let entries: Vec<CommandEntryInfo> = vec![
        CommandEntryInfo {
            command: "npm run build".to_string(),
            working_dir: "/data/projects/app".to_string(),
            was_bypassed: true,
        },
        CommandEntryInfo {
            command: "npm run build".to_string(),
            working_dir: "/data/projects/app".to_string(),
            was_bypassed: true,
        },
        CommandEntryInfo {
            command: "npm run build".to_string(),
            working_dir: "/data/projects/app".to_string(),
            was_bypassed: false,
        },
    ];

    let suggestions = generate_enhanced_suggestions(&entries, 2);

    assert!(!suggestions.is_empty());
    let suggestion = &suggestions[0];
    // Bypasses should boost confidence to High
    assert_eq!(suggestion.confidence, ConfidenceTier::High);
    // Reason should be ManuallyBypassed
    assert_eq!(suggestion.reason, SuggestionReason::ManuallyBypassed);
    // Bypass is a per-command signal, not a per-denied-row count.
    assert_eq!(suggestion.bypass_count, 1);
}

#[test]
fn generate_enhanced_suggestions_clustered_paths() {
    // All commands in the same directory
    let entries = create_test_entries(&[("git status", "/data/projects/myapp", false)], 10);

    let suggestions = generate_enhanced_suggestions(&entries, 3);

    assert!(!suggestions.is_empty());
    let suggestion = &suggestions[0];
    // Should suggest path-specific allowlisting
    assert!(suggestion.suggest_path_specific);
    assert_eq!(suggestion.reason, SuggestionReason::PathClustered);
    assert_ne!(
        suggestion.path_patterns,
        [] as [destructive_command_guard::PathPattern; 0]
    );
}

#[test]
fn generate_enhanced_suggestions_sibling_project_path_glob() {
    let entries = vec![
        CommandEntryInfo {
            command: "npm run build".to_string(),
            working_dir: "/home/dev/projects/app1".to_string(),
            was_bypassed: false,
        },
        CommandEntryInfo {
            command: "npm run build".to_string(),
            working_dir: "/home/dev/projects/app2".to_string(),
            was_bypassed: false,
        },
        CommandEntryInfo {
            command: "npm run build".to_string(),
            working_dir: "/home/dev/projects/app3".to_string(),
            was_bypassed: false,
        },
    ];

    let suggestions = generate_enhanced_suggestions(&entries, 3);

    assert_eq!(suggestions.len(), 1);
    assert!(suggestions[0].suggest_path_specific);
    assert!(
        suggestions[0]
            .path_patterns
            .iter()
            .any(|p| p.pattern == "/home/dev/projects/*"),
        "expected sibling project glob, got {:?}",
        suggestions[0].path_patterns
    );
}

#[test]
fn generate_enhanced_suggestions_scattered_paths() {
    // Use truly scattered paths with no common prefix
    let scattered_paths = [
        "/home/user1/project",
        "/var/www/app",
        "/opt/services/backend",
        "/tmp/builds/staging",
        "/usr/local/src/tool",
        "/data/apps/frontend",
        "/srv/containers/api",
        "/mnt/storage/repo",
        "/root/workspace/lib",
        "/etc/scripts/util",
    ];

    let entries: Vec<CommandEntryInfo> = scattered_paths
        .iter()
        .map(|path| CommandEntryInfo {
            command: "npm run build".to_string(),
            working_dir: path.to_string(),
            was_bypassed: false,
        })
        .collect();

    let suggestions = generate_enhanced_suggestions(&entries, 3);

    assert!(!suggestions.is_empty());
    let suggestion = &suggestions[0];
    // Scattered paths should not suggest path-specific
    assert!(!suggestion.suggest_path_specific);
}

#[test]
fn generate_enhanced_suggestions_multiple_commands_sorted_by_score() {
    let mut entries = Vec::new();

    // High-frequency, low-risk command with bypasses
    for _ in 0..20 {
        entries.push(CommandEntryInfo {
            command: "npm run build".to_string(),
            working_dir: "/data/projects/app".to_string(),
            was_bypassed: true,
        });
    }

    // Lower-frequency, high-risk command
    for _ in 0..5 {
        entries.push(CommandEntryInfo {
            command: "rm -rf /tmp/cache".to_string(),
            working_dir: "/data/projects/app".to_string(),
            was_bypassed: false,
        });
    }

    let suggestions = generate_enhanced_suggestions(&entries, 3);

    assert!(
        suggestions.len() >= 2,
        "Should generate suggestions for both commands"
    );
    // Suggestions should be sorted by score (higher first)
    // High-confidence, low-risk "npm run build" should rank higher
    // than medium-confidence, high-risk "rm -rf"
    for i in 1..suggestions.len() {
        assert!(
            suggestions[i - 1].score >= suggestions[i].score,
            "Suggestions should be sorted by score descending"
        );
    }
}

// ============================================================================
// Filtering Tests
// ============================================================================

fn create_suggestion_with_confidence(confidence: ConfidenceTier) -> AllowlistSuggestion {
    use destructive_command_guard::suggest::CommandCluster;

    let cluster = CommandCluster {
        commands: vec!["test command".to_string()],
        normalized: vec!["test command".to_string()],
        proposed_pattern: "^test command$".to_string(),
        frequency: match confidence {
            ConfidenceTier::High => 20,
            ConfidenceTier::Medium => 7,
            ConfidenceTier::Low => 2,
        },
        unique_count: 1,
    };

    let mut suggestion = AllowlistSuggestion::from_cluster(cluster);
    suggestion.confidence = confidence;
    suggestion
}

fn create_suggestion_with_risk(risk: RiskLevel) -> AllowlistSuggestion {
    use destructive_command_guard::suggest::CommandCluster;

    let cmd = match risk {
        RiskLevel::High => "rm -rf /tmp",
        RiskLevel::Medium => "git checkout -- file",
        RiskLevel::Low => "npm run build",
    };

    let cluster = CommandCluster {
        commands: vec![cmd.to_string()],
        normalized: vec![cmd.to_string()],
        proposed_pattern: format!("^{}$", regex::escape(cmd)),
        frequency: 10,
        unique_count: 1,
    };

    AllowlistSuggestion::from_cluster(cluster)
}

#[test]
fn filter_by_confidence_high_only() {
    let suggestions = vec![
        create_suggestion_with_confidence(ConfidenceTier::High),
        create_suggestion_with_confidence(ConfidenceTier::Medium),
        create_suggestion_with_confidence(ConfidenceTier::Low),
    ];

    let filtered = filter_by_confidence(suggestions.clone(), ConfidenceTier::High);

    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].confidence, ConfidenceTier::High);
}

#[test]
fn filter_by_confidence_medium_exact_match() {
    // filter_by_confidence filters by exact tier match
    let suggestions = vec![
        create_suggestion_with_confidence(ConfidenceTier::High),
        create_suggestion_with_confidence(ConfidenceTier::Medium),
        create_suggestion_with_confidence(ConfidenceTier::Low),
    ];

    let filtered = filter_by_confidence(suggestions.clone(), ConfidenceTier::Medium);

    assert_eq!(filtered.len(), 1);
    assert!(
        filtered
            .iter()
            .all(|s| s.confidence == ConfidenceTier::Medium)
    );
}

#[test]
fn filter_by_confidence_low_exact_match() {
    // filter_by_confidence filters by exact tier match
    let suggestions = vec![
        create_suggestion_with_confidence(ConfidenceTier::High),
        create_suggestion_with_confidence(ConfidenceTier::Medium),
        create_suggestion_with_confidence(ConfidenceTier::Low),
    ];

    let filtered = filter_by_confidence(suggestions.clone(), ConfidenceTier::Low);

    assert_eq!(filtered.len(), 1);
    assert!(filtered.iter().all(|s| s.confidence == ConfidenceTier::Low));
}

#[test]
fn filter_by_risk_low_only() {
    let suggestions = vec![
        create_suggestion_with_risk(RiskLevel::High),
        create_suggestion_with_risk(RiskLevel::Medium),
        create_suggestion_with_risk(RiskLevel::Low),
    ];

    let filtered = filter_by_risk(suggestions.clone(), RiskLevel::Low);

    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].risk, RiskLevel::Low);
}

#[test]
fn filter_by_risk_medium_exact_match() {
    // filter_by_risk filters by exact level match
    let suggestions = vec![
        create_suggestion_with_risk(RiskLevel::High),
        create_suggestion_with_risk(RiskLevel::Medium),
        create_suggestion_with_risk(RiskLevel::Low),
    ];

    let filtered = filter_by_risk(suggestions.clone(), RiskLevel::Medium);

    assert_eq!(filtered.len(), 1);
    assert!(filtered.iter().all(|s| s.risk == RiskLevel::Medium));
}

#[test]
fn filter_by_risk_high_exact_match() {
    // filter_by_risk filters by exact level match
    let suggestions = vec![
        create_suggestion_with_risk(RiskLevel::High),
        create_suggestion_with_risk(RiskLevel::Medium),
        create_suggestion_with_risk(RiskLevel::Low),
    ];

    let filtered = filter_by_risk(suggestions.clone(), RiskLevel::High);

    assert_eq!(filtered.len(), 1);
    assert!(filtered.iter().all(|s| s.risk == RiskLevel::High));
}

// ============================================================================
// Combined Filtering Tests
// ============================================================================

#[test]
fn filter_chain_confidence_then_risk() {
    let mut suggestions = Vec::new();

    // High confidence, high risk
    let mut s1 = create_suggestion_with_confidence(ConfidenceTier::High);
    s1.risk = RiskLevel::High;
    suggestions.push(s1);

    // High confidence, low risk
    let mut s2 = create_suggestion_with_confidence(ConfidenceTier::High);
    s2.risk = RiskLevel::Low;
    suggestions.push(s2);

    // Low confidence, low risk
    let mut s3 = create_suggestion_with_confidence(ConfidenceTier::Low);
    s3.risk = RiskLevel::Low;
    suggestions.push(s3);

    // Filter to high confidence first
    let after_confidence = filter_by_confidence(suggestions, ConfidenceTier::High);
    assert_eq!(after_confidence.len(), 2);

    // Then filter to low risk
    let after_risk = filter_by_risk(after_confidence, RiskLevel::Low);
    assert_eq!(after_risk.len(), 1);
    assert_eq!(after_risk[0].confidence, ConfidenceTier::High);
    assert_eq!(after_risk[0].risk, RiskLevel::Low);
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn generate_enhanced_suggestions_with_duplicate_commands() {
    // Same command appears multiple times
    let entries: Vec<CommandEntryInfo> = (0..10)
        .map(|_| CommandEntryInfo {
            command: "git status".to_string(),
            working_dir: "/data/projects/app".to_string(),
            was_bypassed: false,
        })
        .collect();

    let suggestions = generate_enhanced_suggestions(&entries, 3);

    // Should deduplicate and count frequency correctly
    assert_eq!(suggestions.len(), 1);
    assert_eq!(suggestions[0].cluster.frequency, 10);
}

#[test]
fn generate_enhanced_suggestions_with_similar_commands() {
    // Similar commands that should cluster
    let mut entries = Vec::new();
    for _ in 0..5 {
        entries.push(CommandEntryInfo {
            command: "npm run build".to_string(),
            working_dir: "/data/projects/app".to_string(),
            was_bypassed: false,
        });
        entries.push(CommandEntryInfo {
            command: "npm run test".to_string(),
            working_dir: "/data/projects/app".to_string(),
            was_bypassed: false,
        });
    }

    let suggestions = generate_enhanced_suggestions(&entries, 3);

    // The clustering algorithm may group these together or keep them separate
    // depending on the similarity threshold. Either way, we should get suggestions.
    assert!(!suggestions.is_empty());
}

#[test]
fn generate_enhanced_suggestions_preserves_command_order_in_cluster() {
    let entries: Vec<CommandEntryInfo> = vec![
        CommandEntryInfo {
            command: "npm run build".to_string(),
            working_dir: "/data/projects/app".to_string(),
            was_bypassed: false,
        },
        CommandEntryInfo {
            command: "npm run build".to_string(),
            working_dir: "/data/projects/app".to_string(),
            was_bypassed: false,
        },
        CommandEntryInfo {
            command: "npm run build".to_string(),
            working_dir: "/data/projects/app".to_string(),
            was_bypassed: false,
        },
    ];

    let suggestions = generate_enhanced_suggestions(&entries, 2);

    assert!(!suggestions.is_empty());
    // Cluster should contain the command
    assert!(
        suggestions[0]
            .cluster
            .commands
            .contains(&"npm run build".to_string())
    );
}

// ============================================================================
// Real-World Scenario Tests
// ============================================================================

#[test]
fn scenario_ci_build_commands() {
    // Simulates CI environment where same build commands run repeatedly
    let mut entries = Vec::new();

    // npm run build - blocked 50 times in CI
    for _ in 0..50 {
        entries.push(CommandEntryInfo {
            command: "npm run build".to_string(),
            working_dir: "/workspace/frontend".to_string(),
            was_bypassed: false,
        });
    }

    // npm run test - blocked 30 times in CI
    for _ in 0..30 {
        entries.push(CommandEntryInfo {
            command: "npm run test".to_string(),
            working_dir: "/workspace/frontend".to_string(),
            was_bypassed: false,
        });
    }

    let suggestions = generate_enhanced_suggestions(&entries, 10);

    // Should get high confidence suggestions for both
    assert!(suggestions.len() >= 1);
    assert!(
        suggestions
            .iter()
            .all(|s| s.confidence == ConfidenceTier::High)
    );
    assert!(suggestions.iter().all(|s| s.risk == RiskLevel::Low));
}

#[test]
fn scenario_developer_workflow() {
    // Simulates developer repeatedly using git commands
    let mut entries = Vec::new();

    // Developer tries git reset --hard multiple times, eventually bypasses.
    // This must still be filtered out of automatic allowlist suggestions.
    for _ in 0..100 {
        entries.push(CommandEntryInfo {
            command: "git reset --hard HEAD~1".to_string(),
            working_dir: "/home/dev/myproject".to_string(),
            was_bypassed: true,
        });
    }

    let suggestions = generate_enhanced_suggestions(&entries, 3);

    assert!(
        suggestions.is_empty(),
        "critical git reset --hard patterns must not be suggested even after repeated bypasses"
    );
}

#[test]
fn scenario_mixed_risk_commands() {
    let mut entries = Vec::new();

    // Low risk: npm commands
    for _ in 0..10 {
        entries.push(CommandEntryInfo {
            command: "npm run lint".to_string(),
            working_dir: "/data/projects/app".to_string(),
            was_bypassed: false,
        });
    }

    // High risk: rm commands
    for _ in 0..10 {
        entries.push(CommandEntryInfo {
            command: "rm -rf /tmp/build".to_string(),
            working_dir: "/data/projects/app".to_string(),
            was_bypassed: false,
        });
    }

    let all_suggestions = generate_enhanced_suggestions(&entries, 3);

    // Filter to only low-risk suggestions
    let safe_suggestions = filter_by_risk(all_suggestions.clone(), RiskLevel::Low);

    // Should only include the npm command
    assert_eq!(safe_suggestions.len(), 1);
    assert!(safe_suggestions[0].cluster.commands[0].contains("npm"));

    // Filter to high confidence only
    let confident_suggestions = filter_by_confidence(all_suggestions, ConfidenceTier::High);

    // Both should be high confidence (frequency >= 10)
    assert_eq!(confident_suggestions.len(), 2);
}
