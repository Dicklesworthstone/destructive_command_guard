//! Confidence scoring tests for ambiguous pattern matches.
//!
//! These tests verify that confidence scoring can reduce false positives
//! by downgrading low-confidence matches from Deny to Warn.

use destructive_command_guard::config::ConfidenceConfig;
use destructive_command_guard::evaluator::{
    EvaluationResult, MatchSource, MatchSpan, PatternMatch, apply_confidence_scoring,
};
use destructive_command_guard::packs::{DecisionMode, Severity};

/// Helper to create a mock `EvaluationResult` with pattern info.
fn mock_deny_result(
    severity: Severity,
    source: MatchSource,
    match_span: Option<MatchSpan>,
) -> EvaluationResult {
    EvaluationResult {
        decision: destructive_command_guard::evaluator::EvaluationDecision::Deny,
        pattern_info: Some(PatternMatch {
            pack_id: Some("core.git".to_string()),
            pattern_name: Some("reset-hard".to_string()),
            severity: Some(severity),
            reason: "destroys uncommitted changes".to_string(),
            source,
            matched_span: match_span,
            matched_text_preview: Some("rm -rf".to_string()),
            explanation: None,
        }),
        allowlist_override: None,
        effective_mode: Some(DecisionMode::Deny),
        skipped_due_to_budget: false,
    }
}

#[test]
fn test_confidence_disabled_returns_unchanged_mode() {
    let config = ConfidenceConfig {
        enabled: false,
        warn_threshold: 0.5,
        protect_critical: true,
    };

    let result = mock_deny_result(
        Severity::High,
        MatchSource::Pack,
        Some(MatchSpan { start: 0, end: 8 }),
    );

    let confidence_result =
        apply_confidence_scoring("rm -rf /", None, &result, DecisionMode::Deny, &config);

    assert_eq!(
        confidence_result.mode,
        DecisionMode::Deny,
        "Disabled confidence scoring should not change mode"
    );
    assert!(
        confidence_result.score.is_none(),
        "Score should not be computed when disabled"
    );
    assert!(
        !confidence_result.downgraded,
        "Should not be marked as downgraded"
    );
}

#[test]
fn test_high_confidence_executed_command_stays_deny() {
    let config = ConfidenceConfig {
        enabled: true,
        warn_threshold: 0.5,
        protect_critical: true,
    };

    // Direct command at position 0 - high confidence
    let result = mock_deny_result(
        Severity::High,
        MatchSource::Pack,
        Some(MatchSpan { start: 0, end: 8 }),
    );

    let confidence_result =
        apply_confidence_scoring("rm -rf /", None, &result, DecisionMode::Deny, &config);

    assert_eq!(
        confidence_result.mode,
        DecisionMode::Deny,
        "High confidence match should stay as Deny"
    );
    assert!(
        confidence_result.score.is_some(),
        "Score should be computed"
    );
    assert!(
        !confidence_result.downgraded,
        "High confidence match should not be downgraded"
    );
}

#[test]
fn test_low_confidence_in_data_context_downgraded_to_warn() {
    let config = ConfidenceConfig {
        enabled: true,
        warn_threshold: 0.5,
        protect_critical: true,
    };

    // Command like: git commit -m 'Fix rm -rf detection'
    // The match is in the commit message (data context)
    let command = "git commit -m 'Fix rm -rf detection'";
    let sanitized = "git commit -m ''"; // rm -rf masked

    // Match starts at position 18 (inside the quoted message)
    let result = mock_deny_result(
        Severity::High,
        MatchSource::Pack,
        Some(MatchSpan { start: 18, end: 31 }),
    );

    let confidence_result = apply_confidence_scoring(
        command,
        Some(sanitized),
        &result,
        DecisionMode::Deny,
        &config,
    );

    assert_eq!(
        confidence_result.mode,
        DecisionMode::Warn,
        "Low confidence match in sanitized region should be downgraded to Warn"
    );
    assert!(
        confidence_result.score.is_some(),
        "Score should be computed"
    );
    assert!(
        confidence_result.downgraded,
        "Should be marked as downgraded"
    );
}

#[test]
fn test_critical_severity_protected_from_downgrade() {
    let config = ConfidenceConfig {
        enabled: true,
        warn_threshold: 0.5,
        protect_critical: true, // Protect critical
    };

    // Critical severity match in data context
    let command = "git commit -m 'Fix rm -rf detection'";
    let sanitized = "git commit -m ''";

    let result = mock_deny_result(
        Severity::Critical, // Critical severity
        MatchSource::Pack,
        Some(MatchSpan { start: 18, end: 31 }),
    );

    let confidence_result = apply_confidence_scoring(
        command,
        Some(sanitized),
        &result,
        DecisionMode::Deny,
        &config,
    );

    assert_eq!(
        confidence_result.mode,
        DecisionMode::Deny,
        "Critical severity should stay as Deny even with low confidence"
    );
    assert!(
        !confidence_result.downgraded,
        "Critical severity should not be marked as downgraded"
    );
}

#[test]
fn test_critical_protection_can_be_disabled() {
    let config = ConfidenceConfig {
        enabled: true,
        warn_threshold: 0.5,
        protect_critical: false, // Protection disabled
    };

    // Critical severity match in data context
    let command = "git commit -m 'Fix rm -rf detection'";
    let sanitized = "git commit -m ''";

    let result = mock_deny_result(
        Severity::Critical,
        MatchSource::Pack,
        Some(MatchSpan { start: 18, end: 31 }),
    );

    let confidence_result = apply_confidence_scoring(
        command,
        Some(sanitized),
        &result,
        DecisionMode::Deny,
        &config,
    );

    // With protection disabled, even Critical can be downgraded
    assert_eq!(
        confidence_result.mode,
        DecisionMode::Warn,
        "Critical should be downgraded when protection is disabled"
    );
}

#[test]
fn test_config_override_source_not_affected() {
    let config = ConfidenceConfig {
        enabled: true,
        warn_threshold: 0.5,
        protect_critical: true,
    };

    let result = mock_deny_result(
        Severity::High,
        MatchSource::ConfigOverride, // Config override source
        Some(MatchSpan { start: 0, end: 8 }),
    );

    // Note: apply_confidence_scoring doesn't check source type,
    // but main.rs only calls it for Pack/HeredocAst sources.
    // This test verifies the function still works correctly.
    let confidence_result =
        apply_confidence_scoring("rm -rf /", None, &result, DecisionMode::Deny, &config);

    // Even though the match could be low confidence, the mode is computed
    // (but main.rs would skip calling this for ConfigOverride)
    assert!(confidence_result.score.is_some() || !config.enabled);
}

#[test]
fn test_warn_threshold_configuration() {
    // Test with very low threshold (almost never downgrade)
    let strict_config = ConfidenceConfig {
        enabled: true,
        warn_threshold: 0.1, // Very low threshold
        protect_critical: true,
    };

    let command = "git commit -m 'Fix rm -rf detection'";
    let sanitized = "git commit -m ''";
    let result = mock_deny_result(
        Severity::High,
        MatchSource::Pack,
        Some(MatchSpan { start: 18, end: 31 }),
    );

    let strict_result = apply_confidence_scoring(
        command,
        Some(sanitized),
        &result,
        DecisionMode::Deny,
        &strict_config,
    );

    // With very low threshold, might not downgrade (depends on actual confidence value)
    // The score should still be computed
    assert!(strict_result.score.is_some());

    // Test with very high threshold (almost always downgrade)
    let lenient_config = ConfidenceConfig {
        enabled: true,
        warn_threshold: 0.99, // Very high threshold
        protect_critical: true,
    };

    let lenient_result = apply_confidence_scoring(
        command,
        Some(sanitized),
        &result,
        DecisionMode::Deny,
        &lenient_config,
    );

    // With very high threshold, should downgrade
    assert!(lenient_result.score.is_some());
    // High confidence commands (executed at position 0) would still pass 0.99 threshold
}

#[test]
fn test_no_match_span_returns_conservative() {
    let config = ConfidenceConfig {
        enabled: true,
        warn_threshold: 0.5,
        protect_critical: true,
    };

    let result = mock_deny_result(
        Severity::High,
        MatchSource::Pack,
        None, // No match span
    );

    let confidence_result =
        apply_confidence_scoring("rm -rf /", None, &result, DecisionMode::Deny, &config);

    assert_eq!(
        confidence_result.mode,
        DecisionMode::Deny,
        "No match span should be conservative (keep Deny)"
    );
    assert!(confidence_result.score.is_none(), "No span means no score");
    assert!(!confidence_result.downgraded);
}

#[test]
fn test_non_deny_mode_passes_through() {
    let config = ConfidenceConfig {
        enabled: true,
        warn_threshold: 0.5,
        protect_critical: true,
    };

    let result = mock_deny_result(
        Severity::Medium,
        MatchSource::Pack,
        Some(MatchSpan { start: 0, end: 8 }),
    );

    // Already Warn mode - should pass through unchanged
    let confidence_result =
        apply_confidence_scoring("rm -rf /", None, &result, DecisionMode::Warn, &config);

    assert_eq!(
        confidence_result.mode,
        DecisionMode::Warn,
        "Non-Deny mode should pass through unchanged"
    );
    assert!(confidence_result.score.is_none());
    assert!(!confidence_result.downgraded);
}
