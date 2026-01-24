//! Comprehensive tests for Command Rewriting Suggestions scoring and analysis.
//!
//! These tests cover:
//! - ConfidenceTier enum functionality
//! - RiskLevel enum functionality
//! - SuggestionReason enum functionality
//! - AllowlistSuggestion struct and builder methods
//! - Confidence and risk calculation functions
//! - Path pattern analysis
//!
//! Part of git_safety_guard-x1l7: [E3-T9] Comprehensive testing for Command Rewriting Suggestions

use destructive_command_guard::suggest::{
    AllowlistSuggestion, CommandCluster, ConfidenceTier, PathPattern, RiskLevel, SuggestionReason,
    analyze_path_patterns, assess_risk_level, calculate_confidence_tier,
    calculate_suggestion_score, determine_primary_reason,
};

// ============================================================================
// ConfidenceTier Tests
// ============================================================================

#[test]
fn confidence_tier_as_str() {
    assert_eq!(ConfidenceTier::High.as_str(), "high");
    assert_eq!(ConfidenceTier::Medium.as_str(), "medium");
    assert_eq!(ConfidenceTier::Low.as_str(), "low");
}

#[test]
fn confidence_tier_scores() {
    // High confidence should have the highest score
    assert!((ConfidenceTier::High.score() - 1.0).abs() < f32::EPSILON);
    // Medium should be between high and low
    assert!(ConfidenceTier::Medium.score() > ConfidenceTier::Low.score());
    assert!(ConfidenceTier::Medium.score() < ConfidenceTier::High.score());
    // Low should be the lowest
    assert!(ConfidenceTier::Low.score() < 0.5);
}

#[test]
fn confidence_tier_display() {
    assert_eq!(format!("{}", ConfidenceTier::High), "high");
    assert_eq!(format!("{}", ConfidenceTier::Medium), "medium");
    assert_eq!(format!("{}", ConfidenceTier::Low), "low");
}

#[test]
fn confidence_tier_serialization() {
    let high = ConfidenceTier::High;
    let json = serde_json::to_string(&high).unwrap();
    assert_eq!(json, "\"high\"");

    let deserialized: ConfidenceTier = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, ConfidenceTier::High);
}

#[test]
fn confidence_tier_all_variants_serialize_deserialize() {
    for tier in [
        ConfidenceTier::High,
        ConfidenceTier::Medium,
        ConfidenceTier::Low,
    ] {
        let json = serde_json::to_string(&tier).unwrap();
        let deserialized: ConfidenceTier = serde_json::from_str(&json).unwrap();
        assert_eq!(tier, deserialized);
    }
}

// ============================================================================
// RiskLevel Tests
// ============================================================================

#[test]
fn risk_level_as_str() {
    assert_eq!(RiskLevel::Low.as_str(), "low");
    assert_eq!(RiskLevel::Medium.as_str(), "medium");
    assert_eq!(RiskLevel::High.as_str(), "high");
}

#[test]
fn risk_level_scores() {
    // Low risk should have the lowest score (best)
    assert!(RiskLevel::Low.score() < RiskLevel::Medium.score());
    // High risk should have the highest score (worst)
    assert!(RiskLevel::High.score() > RiskLevel::Medium.score());
    // Scores should be in valid range [0, 1]
    assert!(RiskLevel::Low.score() >= 0.0 && RiskLevel::Low.score() <= 1.0);
    assert!(RiskLevel::High.score() >= 0.0 && RiskLevel::High.score() <= 1.0);
}

#[test]
fn risk_level_display() {
    assert_eq!(format!("{}", RiskLevel::Low), "low");
    assert_eq!(format!("{}", RiskLevel::Medium), "medium");
    assert_eq!(format!("{}", RiskLevel::High), "high");
}

#[test]
fn risk_level_serialization() {
    let high = RiskLevel::High;
    let json = serde_json::to_string(&high).unwrap();
    assert_eq!(json, "\"high\"");

    let deserialized: RiskLevel = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, RiskLevel::High);
}

#[test]
fn risk_level_all_variants_serialize_deserialize() {
    for level in [RiskLevel::Low, RiskLevel::Medium, RiskLevel::High] {
        let json = serde_json::to_string(&level).unwrap();
        let deserialized: RiskLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(level, deserialized);
    }
}

// ============================================================================
// SuggestionReason Tests
// ============================================================================

#[test]
fn suggestion_reason_as_str() {
    assert_eq!(SuggestionReason::HighFrequency.as_str(), "high_frequency");
    assert_eq!(SuggestionReason::PathClustered.as_str(), "path_clustered");
    assert_eq!(
        SuggestionReason::ManuallyBypassed.as_str(),
        "manually_bypassed"
    );
    assert_eq!(
        SuggestionReason::SafePatternMatch.as_str(),
        "safe_pattern_match"
    );
}

#[test]
fn suggestion_reason_description() {
    // All reasons should have non-empty descriptions
    assert!(!SuggestionReason::HighFrequency.description().is_empty());
    assert!(!SuggestionReason::PathClustered.description().is_empty());
    assert!(!SuggestionReason::ManuallyBypassed.description().is_empty());
    assert!(!SuggestionReason::SafePatternMatch.description().is_empty());

    // Descriptions should be human-readable (contain spaces)
    assert!(SuggestionReason::HighFrequency.description().contains(' '));
}

#[test]
fn suggestion_reason_display() {
    assert_eq!(
        format!("{}", SuggestionReason::HighFrequency),
        "high_frequency"
    );
    assert_eq!(
        format!("{}", SuggestionReason::ManuallyBypassed),
        "manually_bypassed"
    );
}

#[test]
fn suggestion_reason_serialization() {
    let reason = SuggestionReason::PathClustered;
    let json = serde_json::to_string(&reason).unwrap();
    assert_eq!(json, "\"path_clustered\"");

    let deserialized: SuggestionReason = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, SuggestionReason::PathClustered);
}

// ============================================================================
// calculate_confidence_tier Tests
// ============================================================================

#[test]
fn confidence_tier_high_frequency_consistent() {
    // High frequency (>=10) with consistent pattern (ratio >= 2.0) = High
    let tier = calculate_confidence_tier(20, 5); // ratio = 4.0
    assert_eq!(tier, ConfidenceTier::High);
}

#[test]
fn confidence_tier_high_frequency_inconsistent() {
    // High frequency but inconsistent pattern (ratio < 2.0) = Medium
    let tier = calculate_confidence_tier(10, 10); // ratio = 1.0
    assert_eq!(tier, ConfidenceTier::Medium);
}

#[test]
fn confidence_tier_medium_frequency() {
    // Medium frequency (5-9) = Medium
    let tier = calculate_confidence_tier(7, 3);
    assert_eq!(tier, ConfidenceTier::Medium);
}

#[test]
fn confidence_tier_low_frequency() {
    // Low frequency (<5) = Low
    let tier = calculate_confidence_tier(3, 2);
    assert_eq!(tier, ConfidenceTier::Low);
}

#[test]
fn confidence_tier_zero_variants() {
    // Zero variants should handle gracefully
    let tier = calculate_confidence_tier(10, 0);
    assert_eq!(tier, ConfidenceTier::Medium);
}

#[test]
fn confidence_tier_single_occurrence() {
    let tier = calculate_confidence_tier(1, 1);
    assert_eq!(tier, ConfidenceTier::Low);
}

#[test]
fn confidence_tier_boundary_conditions() {
    // At exactly 10 frequency (HIGH_CONFIDENCE_MIN_FREQUENCY)
    let tier_10_high_ratio = calculate_confidence_tier(10, 3); // ratio = 3.33
    assert_eq!(tier_10_high_ratio, ConfidenceTier::High);

    // At exactly 5 frequency (MEDIUM_CONFIDENCE_MIN_FREQUENCY)
    let tier_5 = calculate_confidence_tier(5, 2);
    assert_eq!(tier_5, ConfidenceTier::Medium);

    // Just below medium threshold
    let tier_4 = calculate_confidence_tier(4, 2);
    assert_eq!(tier_4, ConfidenceTier::Low);
}

// ============================================================================
// assess_risk_level Tests
// ============================================================================

#[test]
fn risk_level_high_for_rm_rf() {
    let commands = vec!["rm -rf /tmp/test".to_string()];
    assert_eq!(assess_risk_level(&commands), RiskLevel::High);
}

#[test]
fn risk_level_high_for_force_flag() {
    let commands = vec!["git push --force origin main".to_string()];
    assert_eq!(assess_risk_level(&commands), RiskLevel::High);
}

#[test]
fn risk_level_high_for_reset_hard() {
    let commands = vec!["git reset --hard HEAD".to_string()];
    assert_eq!(assess_risk_level(&commands), RiskLevel::High);
}

#[test]
fn risk_level_high_for_clean_f() {
    let commands = vec!["git clean -fd".to_string()];
    assert_eq!(assess_risk_level(&commands), RiskLevel::High);
}

#[test]
fn risk_level_high_for_drop() {
    let commands = vec!["DROP TABLE users;".to_string()];
    assert_eq!(assess_risk_level(&commands), RiskLevel::High);
}

#[test]
fn risk_level_high_for_truncate() {
    let commands = vec!["truncate -s 0 /var/log/syslog".to_string()];
    assert_eq!(assess_risk_level(&commands), RiskLevel::High);
}

#[test]
fn risk_level_medium_for_rm_without_rf() {
    let commands = vec!["rm test.txt".to_string()];
    assert_eq!(assess_risk_level(&commands), RiskLevel::Medium);
}

#[test]
fn risk_level_medium_for_git_reset() {
    let commands = vec!["git reset HEAD~1".to_string()];
    assert_eq!(assess_risk_level(&commands), RiskLevel::Medium);
}

#[test]
fn risk_level_medium_for_sudo() {
    let commands = vec!["sudo npm install".to_string()];
    assert_eq!(assess_risk_level(&commands), RiskLevel::Medium);
}

#[test]
fn risk_level_medium_for_docker_rm() {
    let commands = vec!["docker rm container_name".to_string()];
    assert_eq!(assess_risk_level(&commands), RiskLevel::Medium);
}

#[test]
fn risk_level_high_for_kubectl_delete() {
    // kubectl delete contains "delete " which is a high-risk pattern
    let commands = vec!["kubectl delete pod my-pod".to_string()];
    assert_eq!(assess_risk_level(&commands), RiskLevel::High);
}

#[test]
fn risk_level_low_for_safe_commands() {
    let commands = vec!["git status".to_string()];
    assert_eq!(assess_risk_level(&commands), RiskLevel::Low);
}

#[test]
fn risk_level_low_for_npm_run() {
    let commands = vec!["npm run build".to_string()];
    assert_eq!(assess_risk_level(&commands), RiskLevel::Low);
}

#[test]
fn risk_level_high_takes_precedence_in_cluster() {
    // If any command in cluster is high risk, whole cluster is high risk
    let commands = vec![
        "npm run build".to_string(),
        "git status".to_string(),
        "rm -rf /tmp/cache".to_string(), // High risk
    ];
    assert_eq!(assess_risk_level(&commands), RiskLevel::High);
}

#[test]
fn risk_level_empty_commands() {
    let commands: Vec<String> = vec![];
    assert_eq!(assess_risk_level(&commands), RiskLevel::Low);
}

#[test]
fn risk_level_case_insensitive() {
    // Risk detection should be case insensitive
    let commands = vec!["RM -RF /tmp".to_string()];
    assert_eq!(assess_risk_level(&commands), RiskLevel::High);
}

// ============================================================================
// calculate_suggestion_score Tests
// ============================================================================

#[test]
fn suggestion_score_high_confidence_low_risk_best() {
    let score = calculate_suggestion_score(ConfidenceTier::High, RiskLevel::Low);
    // This should be the best score
    assert!(score > 0.8, "High confidence + low risk should score > 0.8");
}

#[test]
fn suggestion_score_low_confidence_high_risk_worst() {
    let score = calculate_suggestion_score(ConfidenceTier::Low, RiskLevel::High);
    // This should be the worst score
    assert!(score < 0.3, "Low confidence + high risk should score < 0.3");
}

#[test]
fn suggestion_score_ordering() {
    let high_low = calculate_suggestion_score(ConfidenceTier::High, RiskLevel::Low);
    let high_medium = calculate_suggestion_score(ConfidenceTier::High, RiskLevel::Medium);
    let high_high = calculate_suggestion_score(ConfidenceTier::High, RiskLevel::High);
    let medium_low = calculate_suggestion_score(ConfidenceTier::Medium, RiskLevel::Low);
    let low_low = calculate_suggestion_score(ConfidenceTier::Low, RiskLevel::Low);

    // Higher confidence should beat lower confidence at same risk
    assert!(high_low > medium_low);
    assert!(medium_low > low_low);

    // Lower risk should beat higher risk at same confidence
    assert!(high_low > high_medium);
    assert!(high_medium > high_high);
}

#[test]
fn suggestion_score_always_in_valid_range() {
    // Test all combinations
    for confidence in [
        ConfidenceTier::High,
        ConfidenceTier::Medium,
        ConfidenceTier::Low,
    ] {
        for risk in [RiskLevel::Low, RiskLevel::Medium, RiskLevel::High] {
            let score = calculate_suggestion_score(confidence, risk);
            assert!(
                (0.0..=1.0).contains(&score),
                "Score {score} for {confidence:?}/{risk:?} out of range [0,1]"
            );
        }
    }
}

// ============================================================================
// determine_primary_reason Tests
// ============================================================================

#[test]
fn primary_reason_bypassed_takes_precedence() {
    let reason = determine_primary_reason(5, true, &[]);
    assert_eq!(reason, SuggestionReason::ManuallyBypassed);
}

#[test]
fn primary_reason_path_clustered_with_concentration() {
    let path_patterns = vec![PathPattern {
        pattern: "/data/projects/test".to_string(),
        occurrence_count: 8,
        is_project_dir: true,
    }];
    let reason = determine_primary_reason(10, false, &path_patterns);
    assert_eq!(reason, SuggestionReason::PathClustered);
}

#[test]
fn primary_reason_high_frequency_default() {
    let reason = determine_primary_reason(10, false, &[]);
    assert_eq!(reason, SuggestionReason::HighFrequency);
}

#[test]
fn primary_reason_low_frequency_still_frequency() {
    let reason = determine_primary_reason(2, false, &[]);
    assert_eq!(reason, SuggestionReason::HighFrequency);
}

#[test]
fn primary_reason_bypass_beats_path_clustering() {
    let path_patterns = vec![PathPattern {
        pattern: "/data/projects/test".to_string(),
        occurrence_count: 10,
        is_project_dir: true,
    }];
    let reason = determine_primary_reason(10, true, &path_patterns);
    assert_eq!(reason, SuggestionReason::ManuallyBypassed);
}

// ============================================================================
// analyze_path_patterns Tests
// ============================================================================

#[test]
fn analyze_path_patterns_empty_input() {
    let (patterns, suggest_path_specific) = analyze_path_patterns(&[]);
    assert!(patterns.is_empty());
    assert!(!suggest_path_specific);
}

#[test]
fn analyze_path_patterns_single_dir() {
    let dirs = vec!["/data/projects/test".to_string()];
    let (patterns, _) = analyze_path_patterns(&dirs);
    assert!(!patterns.is_empty());
}

#[test]
fn analyze_path_patterns_clustered_dirs() {
    let dirs = vec![
        "/data/projects/myapp".to_string(),
        "/data/projects/myapp".to_string(),
        "/data/projects/myapp".to_string(),
        "/data/projects/myapp".to_string(),
    ];
    let (patterns, suggest_path_specific) = analyze_path_patterns(&dirs);
    assert!(!patterns.is_empty());
    // All in same dir should suggest path-specific
    assert!(suggest_path_specific);
}

#[test]
fn analyze_path_patterns_scattered_dirs() {
    let dirs = vec![
        "/home/user/project1".to_string(),
        "/tmp/build".to_string(),
        "/var/data".to_string(),
        "/opt/app".to_string(),
    ];
    let (patterns, suggest_path_specific) = analyze_path_patterns(&dirs);
    // Scattered dirs should not suggest path-specific
    assert!(!suggest_path_specific);
    // But patterns should still be extracted
    assert!(patterns.len() <= 3); // Max 3 patterns
}

#[test]
fn analyze_path_patterns_common_prefix() {
    let dirs = vec![
        "/data/projects/app1".to_string(),
        "/data/projects/app2".to_string(),
        "/data/projects/app3".to_string(),
    ];
    let (patterns, _) = analyze_path_patterns(&dirs);
    // Should find common prefix
    assert!(
        patterns
            .iter()
            .any(|p| p.pattern.contains("/data/projects")),
        "Should find /data/projects prefix"
    );
}

#[test]
fn analyze_path_patterns_project_dir_detection() {
    let dirs = vec![
        "/home/user/workspace/project".to_string(),
        "/home/user/workspace/project".to_string(),
    ];
    let (patterns, _) = analyze_path_patterns(&dirs);
    // Should detect as project directory
    assert!(
        patterns.iter().any(|p| p.is_project_dir),
        "Should detect project directory"
    );
}

#[test]
fn analyze_path_patterns_max_three_patterns() {
    // Create many different directories
    let dirs: Vec<String> = (0..20).map(|i| format!("/path{}/subdir/app", i)).collect();
    let (patterns, _) = analyze_path_patterns(&dirs);
    assert!(patterns.len() <= 3, "Should return at most 3 patterns");
}

// ============================================================================
// AllowlistSuggestion Builder Tests
// ============================================================================

fn create_test_cluster() -> CommandCluster {
    CommandCluster {
        commands: vec![
            "git reset --hard HEAD".to_string(),
            "git reset --hard origin/main".to_string(),
        ],
        normalized: vec![
            "git reset --hard HEAD".to_string(),
            "git reset --hard origin/main".to_string(),
        ],
        proposed_pattern: "^git reset --hard".to_string(),
        frequency: 10,
        unique_count: 2,
    }
}

#[test]
fn allowlist_suggestion_from_cluster_basic() {
    let cluster = create_test_cluster();
    let suggestion = AllowlistSuggestion::from_cluster(cluster.clone());

    assert_eq!(suggestion.cluster.frequency, 10);
    assert_eq!(suggestion.cluster.unique_count, 2);
    // High frequency (10) with ratio 5.0 = High confidence
    assert_eq!(suggestion.confidence, ConfidenceTier::High);
    // git reset --hard is high risk
    assert_eq!(suggestion.risk, RiskLevel::High);
    assert!(suggestion.score > 0.0);
}

#[test]
fn allowlist_suggestion_from_cluster_low_frequency() {
    let cluster = CommandCluster {
        commands: vec!["npm run build".to_string()],
        normalized: vec!["npm run build".to_string()],
        proposed_pattern: "^npm run build$".to_string(),
        frequency: 2,
        unique_count: 1,
    };
    let suggestion = AllowlistSuggestion::from_cluster(cluster);

    // Low frequency = Low confidence
    assert_eq!(suggestion.confidence, ConfidenceTier::Low);
    // npm run build is low risk
    assert_eq!(suggestion.risk, RiskLevel::Low);
}

#[test]
fn allowlist_suggestion_with_path_analysis() {
    let cluster = create_test_cluster();
    let working_dirs = vec![
        "/data/projects/myapp".to_string(),
        "/data/projects/myapp".to_string(),
        "/data/projects/myapp".to_string(),
        "/data/projects/myapp".to_string(),
        "/data/projects/myapp".to_string(),
    ];

    let suggestion = AllowlistSuggestion::from_cluster(cluster).with_path_analysis(&working_dirs);

    assert!(!suggestion.path_patterns.is_empty());
    assert!(suggestion.suggest_path_specific);
    assert!(
        suggestion
            .contributing_factors
            .contains(&SuggestionReason::PathClustered)
    );
}

#[test]
fn allowlist_suggestion_with_bypass_count() {
    let cluster = CommandCluster {
        commands: vec!["git status".to_string()],
        normalized: vec!["git status".to_string()],
        proposed_pattern: "^git status$".to_string(),
        frequency: 2,
        unique_count: 1,
    };

    let suggestion = AllowlistSuggestion::from_cluster(cluster).with_bypass_count(5);

    // Bypass should set confidence to High
    assert_eq!(suggestion.confidence, ConfidenceTier::High);
    // Reason should be ManuallyBypassed
    assert_eq!(suggestion.reason, SuggestionReason::ManuallyBypassed);
    assert!(
        suggestion
            .contributing_factors
            .contains(&SuggestionReason::ManuallyBypassed)
    );
    assert_eq!(suggestion.bypass_count, 5);
}

#[test]
fn allowlist_suggestion_score_recalculated_on_updates() {
    let cluster = CommandCluster {
        commands: vec!["npm run test".to_string()],
        normalized: vec!["npm run test".to_string()],
        proposed_pattern: "^npm run test$".to_string(),
        frequency: 2,
        unique_count: 1,
    };

    let initial_suggestion = AllowlistSuggestion::from_cluster(cluster.clone());
    let initial_score = initial_suggestion.score;

    // Adding bypass should increase confidence, thus increasing score
    let with_bypass = AllowlistSuggestion::from_cluster(cluster).with_bypass_count(3);

    assert!(
        with_bypass.score > initial_score,
        "Score should increase after adding bypass"
    );
}

#[test]
fn allowlist_suggestion_serialization() {
    let cluster = create_test_cluster();
    let suggestion = AllowlistSuggestion::from_cluster(cluster);

    let json = serde_json::to_string(&suggestion).unwrap();
    assert!(json.contains("\"confidence\":\"high\""));
    assert!(json.contains("\"risk\":\"high\""));

    let deserialized: AllowlistSuggestion = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.confidence, suggestion.confidence);
    assert_eq!(deserialized.risk, suggestion.risk);
}

// ============================================================================
// PathPattern Tests
// ============================================================================

#[test]
fn path_pattern_serialization() {
    let pattern = PathPattern {
        pattern: "/data/projects/test".to_string(),
        occurrence_count: 10,
        is_project_dir: true,
    };

    let json = serde_json::to_string(&pattern).unwrap();
    assert!(json.contains("\"is_project_dir\":true"));

    let deserialized: PathPattern = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.pattern, pattern.pattern);
    assert_eq!(deserialized.occurrence_count, pattern.occurrence_count);
    assert_eq!(deserialized.is_project_dir, pattern.is_project_dir);
}

// ============================================================================
// Integration: Full Suggestion Generation Flow
// ============================================================================

#[test]
fn full_suggestion_flow_high_frequency_clustered() {
    // Simulate a real-world scenario: same command blocked many times
    let cluster = CommandCluster {
        commands: vec!["git reset --hard HEAD".to_string()],
        normalized: vec!["git reset --hard HEAD".to_string()],
        proposed_pattern: "^git reset --hard HEAD$".to_string(),
        frequency: 25,
        unique_count: 1,
    };

    let working_dirs: Vec<String> = (0..25)
        .map(|_| "/data/projects/myapp".to_string())
        .collect();

    let suggestion = AllowlistSuggestion::from_cluster(cluster)
        .with_path_analysis(&working_dirs)
        .with_bypass_count(3);

    // Should have high confidence due to frequency and bypasses
    assert_eq!(suggestion.confidence, ConfidenceTier::High);
    // Should recommend path-specific due to clustering
    assert!(suggestion.suggest_path_specific);
    // Should have ManuallyBypassed as reason due to bypasses
    assert_eq!(suggestion.reason, SuggestionReason::ManuallyBypassed);
    // Score should be reasonable despite high risk
    assert!(suggestion.score > 0.5);
}

#[test]
fn full_suggestion_flow_low_frequency_scattered() {
    let cluster = CommandCluster {
        commands: vec!["npm run build".to_string()],
        normalized: vec!["npm run build".to_string()],
        proposed_pattern: "^npm run build$".to_string(),
        frequency: 3,
        unique_count: 1,
    };

    let working_dirs = vec![
        "/project1".to_string(),
        "/project2".to_string(),
        "/project3".to_string(),
    ];

    let suggestion = AllowlistSuggestion::from_cluster(cluster).with_path_analysis(&working_dirs);

    // Low frequency = low confidence
    assert_eq!(suggestion.confidence, ConfidenceTier::Low);
    // Scattered paths = no path-specific suggestion
    assert!(!suggestion.suggest_path_specific);
    // Low risk command
    assert_eq!(suggestion.risk, RiskLevel::Low);
}
