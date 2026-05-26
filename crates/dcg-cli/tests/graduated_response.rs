//! Integration tests for the Graduated Response System (Epic 10).
//!
//! Tests the full determine_graduated_response → apply_graduation → escalation
//! messaging pipeline, including:
//! - Response progression across modes (Standard, Strict, Lenient, etc.)
//! - Severity-aware defaults and overrides
//! - Soft block bypass with --force / BypassMethod
//! - Escalation message formatting at each level
//! - EvaluationResult integration (apply_graduation mutates correctly)

use dcg_cli::config::{GraduationMode, ResponseConfig, SeverityOverrides};
use dcg_cli::evaluator::{
    BypassMethod, EvaluationResult, GraduatedResponse, determine_graduated_response,
};
use dcg_cli::output::escalation::{EscalationContext, format_escalation_message};
use dcg_cli::packs::Severity;
use dcg_cli::session::{self, OccurrenceSnapshot};
use std::sync::Mutex;

fn enabled_config() -> ResponseConfig {
    ResponseConfig {
        enabled: true,
        ..ResponseConfig::default()
    }
}

fn make_occurrence(session_count: u32) -> OccurrenceSnapshot {
    OccurrenceSnapshot {
        command_hash: "test_hash".to_string(),
        session_count,
        distinct_commands: 1,
        total_occurrences: session_count,
    }
}

fn deny_result_with_occurrence(count: u32) -> EvaluationResult {
    let mut result = EvaluationResult::denied_by_pack_pattern(
        "core.git",
        "reset-hard",
        "Destroys uncommitted changes",
        None,
        Severity::High,
        &[],
    );
    result.session_occurrence = Some(make_occurrence(count));
    result
}

// =========================================================================
// Full pipeline: determine → apply → format
// =========================================================================

#[test]
fn full_pipeline_warning_level() {
    let config = enabled_config();
    let mut result = deny_result_with_occurrence(1);

    result.apply_graduation(&config);

    let response = result.graduated_response.as_ref().unwrap();
    assert!(matches!(
        response,
        GraduatedResponse::Warning { occurrence: 1 }
    ));
    assert!(!response.blocks());

    let ctx = EscalationContext {
        command: "git reset --hard",
        pattern_id: Some("core.git:reset-hard"),
        severity_label: Some("High"),
        reason: Some("Destroys uncommitted changes"),
        was_bypassed: false,
    };
    let msg = format_escalation_message(response, &ctx);
    assert!(msg.contains("WARNING:"));
    assert!(msg.contains("git reset --hard"));
    assert!(msg.contains("1st attempt"));
    assert!(msg.contains("Command allowed"));
}

#[test]
fn full_pipeline_soft_block_level() {
    let config = enabled_config();
    let mut result = deny_result_with_occurrence(2);

    result.apply_graduation(&config);

    let response = result.graduated_response.as_ref().unwrap();
    assert!(matches!(
        response,
        GraduatedResponse::SoftBlock { occurrence: 2 }
    ));
    assert!(response.blocks());
    assert!(!response.is_hard_block());

    let ctx = EscalationContext {
        command: "git reset --hard HEAD~5",
        pattern_id: Some("core.git:reset-hard"),
        severity_label: Some("High"),
        reason: Some("Destroys uncommitted changes"),
        was_bypassed: false,
    };
    let msg = format_escalation_message(response, &ctx);
    assert!(msg.contains("SOFT BLOCK:"));
    assert!(msg.contains("Occurrences: 2"));
    assert!(msg.contains("dcg test --force"));
}

#[test]
fn full_pipeline_hard_block_level_via_paranoid() {
    let mut config = enabled_config();
    config.mode = GraduationMode::Paranoid;
    let mut result = deny_result_with_occurrence(1);

    result.apply_graduation(&config);

    let response = result.graduated_response.as_ref().unwrap();
    assert!(matches!(response, GraduatedResponse::HardBlock { .. }));
    assert!(response.blocks());
    assert!(response.is_hard_block());

    let ctx = EscalationContext {
        command: "rm -rf /",
        pattern_id: Some("core.filesystem:rm-rf-root"),
        severity_label: Some("Critical"),
        reason: Some("Removes entire filesystem"),
        was_bypassed: false,
    };
    let msg = format_escalation_message(response, &ctx);
    assert!(msg.contains("BLOCKED:"));
    assert!(msg.contains("cannot be bypassed"));
    assert!(msg.contains("dcg allow"));
}

// =========================================================================
// Standard mode progression through all levels
// =========================================================================

#[test]
fn standard_mode_full_progression() {
    let config = enabled_config();

    for count in 1..=5 {
        let response = determine_graduated_response(count, Severity::High, &config);
        match count {
            1 => {
                let r = response.unwrap();
                assert!(matches!(r, GraduatedResponse::Warning { occurrence: 1 }));
                assert!(!r.blocks());
            }
            2..=u32::MAX => {
                let r = response.unwrap();
                assert!(matches!(r, GraduatedResponse::SoftBlock { .. }));
                assert!(r.blocks());
                assert!(!r.is_hard_block());
            }
            _ => unreachable!(),
        }
    }
}

// =========================================================================
// Strict mode — immediate soft block, fast escalation
// =========================================================================

#[test]
fn strict_mode_progression() {
    let mut config = enabled_config();
    config.mode = GraduationMode::Strict;

    let r1 = determine_graduated_response(1, Severity::Medium, &config).unwrap();
    assert!(matches!(r1, GraduatedResponse::SoftBlock { .. }));

    let r2 =
        determine_graduated_response(config.session_soft_block, Severity::Medium, &config).unwrap();
    assert!(matches!(r2, GraduatedResponse::HardBlock { .. }));
}

// =========================================================================
// Lenient mode — doubled thresholds
// =========================================================================

#[test]
fn lenient_mode_higher_thresholds() {
    let mut config = enabled_config();
    config.mode = GraduationMode::Lenient;

    // count=1: below doubled warning threshold → None
    assert!(determine_graduated_response(1, Severity::Medium, &config).is_none());

    // count=2: at doubled warning threshold → Warning
    let r = determine_graduated_response(2, Severity::Medium, &config).unwrap();
    assert!(matches!(r, GraduatedResponse::Warning { .. }));

    // count=3: between warning and soft block → SoftBlock (or Warning depending on config)
    let r = determine_graduated_response(3, Severity::Medium, &config).unwrap();
    assert!(!r.is_hard_block());

    // count=4: at doubled soft block → SoftBlock
    let r = determine_graduated_response(4, Severity::Medium, &config).unwrap();
    assert!(matches!(r, GraduatedResponse::SoftBlock { .. }));
}

// =========================================================================
// Severity-aware defaults
// =========================================================================

#[test]
fn critical_severity_defaults_to_paranoid() {
    let config = enabled_config();
    let r = determine_graduated_response(1, Severity::Critical, &config).unwrap();
    assert!(
        r.is_hard_block(),
        "Critical should default to Paranoid (hard block), got {:?}",
        r
    );
}

#[test]
fn low_severity_defaults_to_warning_only() {
    let config = enabled_config();
    for count in [1, 5, 100] {
        let r = determine_graduated_response(count, Severity::Low, &config).unwrap();
        assert!(
            matches!(r, GraduatedResponse::Warning { .. }),
            "Low severity should always warn (never block), got {:?} at count={count}",
            r
        );
    }
}

#[test]
fn severity_override_trumps_default() {
    let mut config = enabled_config();
    config.severity_overrides = SeverityOverrides {
        critical: Some(GraduationMode::WarningOnly),
        high: None,
        medium: None,
        low: Some(GraduationMode::Paranoid),
    };

    // Critical overridden to WarningOnly
    let r = determine_graduated_response(1, Severity::Critical, &config).unwrap();
    assert!(matches!(r, GraduatedResponse::Warning { .. }));

    // Low overridden to Paranoid
    let r = determine_graduated_response(1, Severity::Low, &config).unwrap();
    assert!(r.is_hard_block());
}

// =========================================================================
// Soft block bypass (--force)
// =========================================================================

#[test]
fn soft_block_bypass_with_force() {
    let config = enabled_config();
    let mut result = deny_result_with_occurrence(2);

    result.apply_graduation(&config);
    assert!(result.graduated_response.as_ref().unwrap().blocks());

    // Simulate --force bypass (as done in cli.rs)
    if let Some(GraduatedResponse::SoftBlock { .. }) = &result.graduated_response {
        result.bypass_method = Some(BypassMethod::Force);
        result.decision = dcg_cli::evaluator::EvaluationDecision::Allow;
    }

    assert!(matches!(result.bypass_method, Some(BypassMethod::Force)));
    assert!(result.is_allowed());

    // Verify escalation message shows bypass info
    let ctx = EscalationContext {
        command: "docker system prune",
        pattern_id: Some("containers.docker:system-prune"),
        severity_label: Some("Medium"),
        reason: Some("Removes unused resources"),
        was_bypassed: true,
    };
    let msg = format_escalation_message(result.graduated_response.as_ref().unwrap(), &ctx);
    assert!(msg.contains("BYPASSED"));
    assert!(msg.contains("--force"));
    assert!(msg.contains("Command allowed via --force bypass"));
}

#[test]
fn hard_block_not_bypassable() {
    let mut config = enabled_config();
    config.mode = GraduationMode::Paranoid;
    let mut result = deny_result_with_occurrence(1);

    result.apply_graduation(&config);
    let response = result.graduated_response.as_ref().unwrap();
    assert!(response.is_hard_block());

    let ctx = EscalationContext {
        command: "rm -rf /",
        pattern_id: Some("core.filesystem:rm-rf-root"),
        severity_label: Some("Critical"),
        reason: Some("Removes entire filesystem"),
        was_bypassed: false,
    };
    let msg = format_escalation_message(response, &ctx);
    assert!(msg.contains("cannot be bypassed with --force"));
    assert!(!msg.contains("dcg test --force"));
}

// =========================================================================
// BypassMethod enum
// =========================================================================

#[test]
fn bypass_method_labels_correct() {
    assert_eq!(BypassMethod::Force.label(), "force");
    assert_eq!(BypassMethod::AllowOnce.label(), "allow_once");
}

// =========================================================================
// Edge cases
// =========================================================================

#[test]
fn disabled_config_produces_no_graduation() {
    let config = ResponseConfig::default(); // enabled=false
    let mut result = deny_result_with_occurrence(10);

    result.apply_graduation(&config);
    assert!(result.graduated_response.is_none());
    assert!(result.is_denied());
}

#[test]
fn no_occurrence_data_produces_no_graduation() {
    let config = enabled_config();
    let mut result = EvaluationResult::denied_by_pack("test", "reason", None);
    // No session_occurrence set
    result.apply_graduation(&config);
    assert!(result.graduated_response.is_none());
}

#[test]
fn allowed_result_still_graduates_if_occurrence_present() {
    let config = enabled_config();
    let mut result = EvaluationResult::allowed();
    result.session_occurrence = Some(make_occurrence(5));
    result.apply_graduation(&config);
    // apply_graduation does not check if result is denied; it only checks
    // config.is_enabled() and session_occurrence. So even an allowed result
    // gets a graduated_response if occurrence data is present.
    assert!(result.graduated_response.is_some());
    // But the result stays allowed since graduation doesn't flip allow→deny
    assert!(result.is_allowed());
}

#[test]
fn warning_sets_response_but_does_not_flip_decision() {
    let config = enabled_config();
    let mut result = deny_result_with_occurrence(1);
    assert!(result.is_denied());

    result.apply_graduation(&config);
    // apply_graduation only sets graduated_response; the policy layer (cli/main)
    // is responsible for flipping the decision when response is Warning.
    assert!(result.is_denied());
    assert!(matches!(
        result.graduated_response,
        Some(GraduatedResponse::Warning { occurrence: 1 })
    ));
}

#[test]
fn soft_block_keeps_deny() {
    let config = enabled_config();
    let mut result = deny_result_with_occurrence(2);
    assert!(result.is_denied());

    result.apply_graduation(&config);
    // SoftBlock keeps Deny
    assert!(result.is_denied());
    assert!(matches!(
        result.graduated_response,
        Some(GraduatedResponse::SoftBlock { occurrence: 2 })
    ));
}

// =========================================================================
// Escalation message content validation
// =========================================================================

#[test]
fn escalation_messages_include_all_context_fields() {
    let ctx = EscalationContext {
        command: "kubectl delete namespace prod",
        pattern_id: Some("kubernetes.core:delete-namespace"),
        severity_label: Some("Critical"),
        reason: Some("Deletes entire namespace"),
        was_bypassed: false,
    };

    let warning_msg =
        format_escalation_message(&GraduatedResponse::Warning { occurrence: 1 }, &ctx);
    assert!(warning_msg.contains("kubectl delete namespace prod"));
    assert!(warning_msg.contains("kubernetes.core:delete-namespace"));
    assert!(warning_msg.contains("Critical"));
    assert!(warning_msg.contains("Deletes entire namespace"));

    let soft_block_msg =
        format_escalation_message(&GraduatedResponse::SoftBlock { occurrence: 3 }, &ctx);
    assert!(soft_block_msg.contains("kubectl delete namespace prod"));
    assert!(soft_block_msg.contains("Occurrences: 3"));

    let hard_block_msg = format_escalation_message(
        &GraduatedResponse::HardBlock {
            total_occurrences: 5,
        },
        &ctx,
    );
    assert!(hard_block_msg.contains("Occurrences: 5"));
    assert!(hard_block_msg.contains("kubernetes.core:delete-namespace"));
}

#[test]
fn escalation_messages_minimal_context_no_crash() {
    let ctx = EscalationContext {
        command: "dangerous-cmd",
        pattern_id: None,
        severity_label: None,
        reason: None,
        was_bypassed: false,
    };

    for response in [
        GraduatedResponse::Warning { occurrence: 1 },
        GraduatedResponse::SoftBlock { occurrence: 2 },
        GraduatedResponse::HardBlock {
            total_occurrences: 3,
        },
    ] {
        let msg = format_escalation_message(&response, &ctx);
        assert!(!msg.is_empty());
        assert!(msg.contains("dangerous-cmd"));
        assert!(!msg.contains("Pattern:"));
        assert!(!msg.contains("Severity:"));
    }
}

// =========================================================================
// GraduatedResponse enum properties
// =========================================================================

#[test]
fn graduated_response_decision_mode_strings() {
    assert_eq!(
        GraduatedResponse::Warning { occurrence: 1 }.decision_mode(),
        "warning"
    );
    assert_eq!(
        GraduatedResponse::SoftBlock { occurrence: 1 }.decision_mode(),
        "soft_block"
    );
    assert_eq!(
        GraduatedResponse::HardBlock {
            total_occurrences: 1
        }
        .decision_mode(),
        "hard_block"
    );
}

#[test]
fn graduated_response_label_format() {
    assert_eq!(
        GraduatedResponse::Warning { occurrence: 3 }.label(),
        "warning (occurrence #3)"
    );
    assert_eq!(
        GraduatedResponse::SoftBlock { occurrence: 2 }.label(),
        "soft block (occurrence #2)"
    );
    assert_eq!(
        GraduatedResponse::HardBlock {
            total_occurrences: 5
        }
        .label(),
        "hard block (5 total occurrences)"
    );
}

// =========================================================================
// Custom threshold configuration
// =========================================================================

#[test]
fn custom_warning_threshold_delays_escalation() {
    let mut config = enabled_config();
    config.session_warning_count = 3;
    config.session_soft_block = 5;

    // Count 1-2 → None (below warning threshold of 3)
    assert!(determine_graduated_response(1, Severity::High, &config).is_none());
    assert!(determine_graduated_response(2, Severity::High, &config).is_none());

    // Count 3 → Warning (at warning threshold)
    let r = determine_graduated_response(3, Severity::High, &config).unwrap();
    assert!(matches!(r, GraduatedResponse::Warning { occurrence: 3 }));

    // Count 4 → Warning (between warning and soft block thresholds)
    let r = determine_graduated_response(4, Severity::High, &config).unwrap();
    assert!(matches!(r, GraduatedResponse::Warning { .. }));

    // Count 5 → SoftBlock (at soft block threshold)
    let r = determine_graduated_response(5, Severity::High, &config).unwrap();
    assert!(matches!(r, GraduatedResponse::SoftBlock { .. }));
}

#[test]
fn custom_soft_block_threshold() {
    let mut config = enabled_config();
    config.session_warning_count = 1;
    config.session_soft_block = 5;

    // Count 1 → Warning (at warning threshold)
    let r = determine_graduated_response(1, Severity::High, &config).unwrap();
    assert!(matches!(r, GraduatedResponse::Warning { .. }));

    // Counts 2-4 → Warning (between warning and soft block thresholds)
    for count in 2..5 {
        let r = determine_graduated_response(count, Severity::High, &config).unwrap();
        assert!(
            matches!(r, GraduatedResponse::Warning { .. }),
            "count={count} should be Warning (below soft_block=5), got {:?}",
            r
        );
    }

    // Count 5 → SoftBlock (at soft block threshold)
    let r = determine_graduated_response(5, Severity::High, &config).unwrap();
    assert!(matches!(r, GraduatedResponse::SoftBlock { .. }));

    // Standard mode never escalates to HardBlock
    let r = determine_graduated_response(100, Severity::High, &config).unwrap();
    assert!(matches!(r, GraduatedResponse::SoftBlock { .. }));
}

// =========================================================================
// WarningOnly and Disabled modes
// =========================================================================

#[test]
fn warning_only_never_blocks_any_severity() {
    let mut config = enabled_config();
    config.mode = GraduationMode::WarningOnly;

    for severity in [Severity::Low, Severity::Medium, Severity::High] {
        for count in [1, 5, 100] {
            let r = determine_graduated_response(count, severity, &config).unwrap();
            assert!(
                !r.blocks(),
                "WarningOnly should never block: severity={severity:?}, count={count}, got {r:?}"
            );
        }
    }
}

#[test]
fn disabled_mode_returns_none_for_non_defaulted_severities() {
    let mut config = enabled_config();
    config.mode = GraduationMode::Disabled;

    // High and Medium use the global mode (Disabled) → None
    for severity in [Severity::High, Severity::Medium] {
        for count in [1, 5, 100] {
            assert!(
                determine_graduated_response(count, severity, &config).is_none(),
                "Disabled should return None: severity={severity:?}, count={count}"
            );
        }
    }

    // Critical defaults to Paranoid and Low defaults to WarningOnly,
    // overriding the global Disabled mode. Use explicit severity overrides
    // to disable them too.
    config.severity_overrides = SeverityOverrides {
        critical: Some(GraduationMode::Disabled),
        high: None,
        medium: None,
        low: Some(GraduationMode::Disabled),
    };
    for severity in [Severity::Critical, Severity::Low] {
        assert!(
            determine_graduated_response(1, severity, &config).is_none(),
            "Disabled override should return None: severity={severity:?}"
        );
    }
}

// =========================================================================
// record_and_graduate integration (real session state)
// =========================================================================

static SESSION_LOCK: Mutex<()> = Mutex::new(());

fn isolated<F: FnOnce()>(f: F) {
    let _guard = SESSION_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    session::reset();
    f();
    session::reset();
}

#[test]
fn record_and_graduate_wires_session_to_graduation() {
    isolated(|| {
        let config = enabled_config();

        let mut r1 = EvaluationResult::denied_by_pack_pattern(
            "core.git",
            "reset-hard",
            "Destroys uncommitted changes",
            None,
            Severity::High,
            &[],
        );
        r1.record_and_graduate("git reset --hard", &config);
        assert!(r1.session_occurrence.is_some());
        assert_eq!(r1.session_occurrence.as_ref().unwrap().session_count, 1);
        assert!(matches!(
            r1.graduated_response,
            Some(GraduatedResponse::Warning { occurrence: 1 })
        ));

        let mut r2 = EvaluationResult::denied_by_pack_pattern(
            "core.git",
            "reset-hard",
            "Destroys uncommitted changes",
            None,
            Severity::High,
            &[],
        );
        r2.record_and_graduate("git reset --hard", &config);
        assert_eq!(r2.session_occurrence.as_ref().unwrap().session_count, 2);
        assert!(matches!(
            r2.graduated_response,
            Some(GraduatedResponse::SoftBlock { occurrence: 2 })
        ));
    });
}

#[test]
fn record_and_graduate_skips_allowed_result() {
    isolated(|| {
        let config = enabled_config();
        let mut result = EvaluationResult::allowed();
        result.record_and_graduate("git reset --hard", &config);
        assert!(
            result.session_occurrence.is_none(),
            "record_and_graduate must not touch session state for allowed results"
        );
        assert!(result.graduated_response.is_none());
        assert_eq!(
            session::get_count("git reset --hard"),
            0,
            "session counter must not increment for allowed results"
        );
    });
}

#[test]
fn interleaved_commands_escalate_independently() {
    isolated(|| {
        let config = enabled_config();

        let mut git = EvaluationResult::denied_by_pack_pattern(
            "core.git",
            "reset-hard",
            "reason",
            None,
            Severity::High,
            &[],
        );
        git.record_and_graduate("git reset --hard", &config);
        assert!(matches!(
            git.graduated_response,
            Some(GraduatedResponse::Warning { occurrence: 1 })
        ));

        let mut rm = EvaluationResult::denied_by_pack_pattern(
            "core.filesystem",
            "rm-rf",
            "reason",
            None,
            Severity::High,
            &[],
        );
        rm.record_and_graduate("rm -rf /tmp/data", &config);
        assert!(
            matches!(
                rm.graduated_response,
                Some(GraduatedResponse::Warning { occurrence: 1 })
            ),
            "rm should start at occurrence 1 independently of git"
        );

        let mut git2 = EvaluationResult::denied_by_pack_pattern(
            "core.git",
            "reset-hard",
            "reason",
            None,
            Severity::High,
            &[],
        );
        git2.record_and_graduate("git reset --hard", &config);
        assert!(
            matches!(
                git2.graduated_response,
                Some(GraduatedResponse::SoftBlock { occurrence: 2 })
            ),
            "git should escalate to SoftBlock at occurrence 2, independent of rm"
        );
    });
}

// =========================================================================
// Exhaustive severity × mode matrix
// =========================================================================

#[test]
fn severity_mode_matrix_at_count_1() {
    let all_modes = [
        GraduationMode::Standard,
        GraduationMode::Strict,
        GraduationMode::Lenient,
        GraduationMode::Paranoid,
        GraduationMode::WarningOnly,
        GraduationMode::Disabled,
    ];
    let all_severities = [
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    for mode in &all_modes {
        let mut config = enabled_config();
        config.mode = *mode;
        config.severity_overrides = SeverityOverrides {
            critical: Some(*mode),
            high: Some(*mode),
            medium: Some(*mode),
            low: Some(*mode),
        };

        for severity in &all_severities {
            let result = determine_graduated_response(1, *severity, &config);

            match mode {
                GraduationMode::Disabled => {
                    assert!(
                        result.is_none(),
                        "Disabled + {severity:?} at count=1 should be None"
                    );
                }
                GraduationMode::WarningOnly => {
                    let r = result.unwrap();
                    assert!(
                        matches!(r, GraduatedResponse::Warning { .. }),
                        "WarningOnly + {severity:?} at count=1 should be Warning, got {r:?}"
                    );
                }
                GraduationMode::Paranoid => {
                    let r = result.unwrap();
                    assert!(
                        r.is_hard_block(),
                        "Paranoid + {severity:?} at count=1 should be HardBlock, got {r:?}"
                    );
                }
                GraduationMode::Strict => {
                    let r = result.unwrap();
                    assert!(
                        matches!(r, GraduatedResponse::SoftBlock { .. }),
                        "Strict + {severity:?} at count=1 should be SoftBlock, got {r:?}"
                    );
                }
                GraduationMode::Standard => {
                    let r = result.unwrap();
                    assert!(
                        matches!(r, GraduatedResponse::Warning { occurrence: 1 }),
                        "Standard + {severity:?} at count=1 should be Warning(1), got {r:?}"
                    );
                }
                GraduationMode::Lenient => {
                    assert!(
                        result.is_none(),
                        "Lenient + {severity:?} at count=1 should be None (threshold=2)"
                    );
                }
            }
        }
    }
}

// =========================================================================
// Boundary precision at threshold edges
// =========================================================================

#[test]
fn standard_boundary_precision() {
    let mut config = enabled_config();
    config.session_warning_count = 3;
    config.session_soft_block = 5;
    config.severity_overrides = SeverityOverrides {
        critical: Some(GraduationMode::Standard),
        high: None,
        medium: None,
        low: Some(GraduationMode::Standard),
    };

    let cases = [
        (1, None),
        (2, None),
        (3, Some("Warning")),
        (4, Some("Warning")),
        (5, Some("SoftBlock")),
        (6, Some("SoftBlock")),
        (100, Some("SoftBlock")),
    ];

    for (count, expected) in cases {
        let result = determine_graduated_response(count, Severity::High, &config);
        match expected {
            None => assert!(
                result.is_none(),
                "Standard: count={count} should be None, got {result:?}"
            ),
            Some("Warning") => {
                let r = result.unwrap();
                assert!(
                    matches!(r, GraduatedResponse::Warning { .. }),
                    "Standard: count={count} should be Warning, got {r:?}"
                );
            }
            Some("SoftBlock") => {
                let r = result.unwrap();
                assert!(
                    matches!(r, GraduatedResponse::SoftBlock { .. }),
                    "Standard: count={count} should be SoftBlock, got {r:?}"
                );
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn strict_boundary_precision() {
    let mut config = enabled_config();
    config.mode = GraduationMode::Strict;
    config.session_soft_block = 3;
    config.severity_overrides = SeverityOverrides {
        critical: Some(GraduationMode::Strict),
        high: None,
        medium: None,
        low: Some(GraduationMode::Strict),
    };

    // Strict: count 1 to session_soft_block-1 → SoftBlock, >= session_soft_block → HardBlock
    assert!(matches!(
        determine_graduated_response(1, Severity::High, &config).unwrap(),
        GraduatedResponse::SoftBlock { occurrence: 1 }
    ));
    assert!(matches!(
        determine_graduated_response(2, Severity::High, &config).unwrap(),
        GraduatedResponse::SoftBlock { occurrence: 2 }
    ));
    assert!(
        determine_graduated_response(3, Severity::High, &config)
            .unwrap()
            .is_hard_block(),
        "Strict: count=session_soft_block should be HardBlock"
    );
    assert!(
        determine_graduated_response(4, Severity::High, &config)
            .unwrap()
            .is_hard_block()
    );
}

#[test]
fn lenient_boundary_precision() {
    let mut config = enabled_config();
    config.mode = GraduationMode::Lenient;
    config.session_warning_count = 2;
    config.session_soft_block = 4;
    config.severity_overrides = SeverityOverrides {
        critical: Some(GraduationMode::Lenient),
        high: None,
        medium: None,
        low: Some(GraduationMode::Lenient),
    };

    // Lenient doubles thresholds: warn=4, soft_block=8
    assert!(determine_graduated_response(1, Severity::High, &config).is_none());
    assert!(determine_graduated_response(3, Severity::High, &config).is_none());
    assert!(matches!(
        determine_graduated_response(4, Severity::High, &config).unwrap(),
        GraduatedResponse::Warning { occurrence: 4 }
    ));
    assert!(matches!(
        determine_graduated_response(7, Severity::High, &config).unwrap(),
        GraduatedResponse::Warning { .. }
    ));
    assert!(matches!(
        determine_graduated_response(8, Severity::High, &config).unwrap(),
        GraduatedResponse::SoftBlock { occurrence: 8 }
    ));
    assert!(matches!(
        determine_graduated_response(20, Severity::High, &config).unwrap(),
        GraduatedResponse::SoftBlock { .. }
    ));
}

// =========================================================================
// Mode invariants
// =========================================================================

#[test]
fn standard_never_hard_blocks() {
    let mut config = enabled_config();
    config.mode = GraduationMode::Standard;
    config.severity_overrides = SeverityOverrides {
        critical: Some(GraduationMode::Standard),
        high: None,
        medium: None,
        low: Some(GraduationMode::Standard),
    };

    for severity in [
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ] {
        for count in [1, 10, 100, 1000, u32::MAX] {
            if let Some(r) = determine_graduated_response(count, severity, &config) {
                assert!(
                    !r.is_hard_block(),
                    "Standard mode must never hard-block: severity={severity:?}, count={count}, got {r:?}"
                );
            }
        }
    }
}

#[test]
fn lenient_never_hard_blocks() {
    let mut config = enabled_config();
    config.mode = GraduationMode::Lenient;
    config.severity_overrides = SeverityOverrides {
        critical: Some(GraduationMode::Lenient),
        high: None,
        medium: None,
        low: Some(GraduationMode::Lenient),
    };

    for severity in [
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ] {
        for count in [1, 10, 100, 1000, u32::MAX] {
            if let Some(r) = determine_graduated_response(count, severity, &config) {
                assert!(
                    !r.is_hard_block(),
                    "Lenient mode must never hard-block: severity={severity:?}, count={count}, got {r:?}"
                );
            }
        }
    }
}

#[test]
fn paranoid_always_hard_blocks() {
    let mut config = enabled_config();
    config.mode = GraduationMode::Paranoid;
    config.severity_overrides = SeverityOverrides {
        critical: Some(GraduationMode::Paranoid),
        high: Some(GraduationMode::Paranoid),
        medium: Some(GraduationMode::Paranoid),
        low: Some(GraduationMode::Paranoid),
    };

    for severity in [
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ] {
        for count in [1, 5, 100] {
            let r = determine_graduated_response(count, severity, &config).unwrap();
            assert!(
                r.is_hard_block(),
                "Paranoid mode must always hard-block: severity={severity:?}, count={count}, got {r:?}"
            );
        }
    }
}

#[test]
fn warning_only_never_blocks_at_any_count() {
    let mut config = enabled_config();
    config.mode = GraduationMode::WarningOnly;
    config.severity_overrides = SeverityOverrides {
        critical: Some(GraduationMode::WarningOnly),
        high: Some(GraduationMode::WarningOnly),
        medium: Some(GraduationMode::WarningOnly),
        low: Some(GraduationMode::WarningOnly),
    };

    for severity in [
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ] {
        for count in [1, 10, u32::MAX] {
            let r = determine_graduated_response(count, severity, &config).unwrap();
            assert!(
                !r.blocks(),
                "WarningOnly must never block: severity={severity:?}, count={count}, got {r:?}"
            );
            assert!(
                matches!(r, GraduatedResponse::Warning { .. }),
                "WarningOnly must always produce Warning"
            );
        }
    }
}

// =========================================================================
// Graduation preserves pattern info
// =========================================================================

#[test]
fn graduation_preserves_pattern_metadata() {
    let config = enabled_config();
    let mut result = EvaluationResult::denied_by_pack_pattern(
        "containers.docker",
        "system-prune",
        "Removes unused resources",
        Some("Use --filter instead"),
        Severity::Medium,
        &[],
    );
    result.session_occurrence = Some(make_occurrence(2));
    result.apply_graduation(&config);

    assert!(result.graduated_response.is_some());
    let info = result.pattern_info.as_ref().unwrap();
    assert_eq!(info.pack_id.as_deref(), Some("containers.docker"));
    assert_eq!(info.pattern_name.as_deref(), Some("system-prune"));
    assert_eq!(info.reason, "Removes unused resources");
    assert_eq!(info.severity, Some(Severity::Medium));
}

// =========================================================================
// Escalation pipeline round-trip with record_and_graduate
// =========================================================================

#[test]
fn full_round_trip_record_to_message() {
    isolated(|| {
        let config = enabled_config();

        let mut r1 = EvaluationResult::denied_by_pack_pattern(
            "core.git",
            "push-force",
            "Force-pushes rewrite history",
            None,
            Severity::High,
            &[],
        );
        r1.record_and_graduate("git push --force origin main", &config);

        let ctx = EscalationContext {
            command: "git push --force origin main",
            pattern_id: Some("core.git:push-force"),
            severity_label: Some("High"),
            reason: Some("Force-pushes rewrite history"),
            was_bypassed: false,
        };
        let msg = format_escalation_message(r1.graduated_response.as_ref().unwrap(), &ctx);
        assert!(msg.contains("WARNING:"));
        assert!(msg.contains("1st attempt"));
        assert!(msg.contains("git push --force origin main"));

        let mut r2 = EvaluationResult::denied_by_pack_pattern(
            "core.git",
            "push-force",
            "Force-pushes rewrite history",
            None,
            Severity::High,
            &[],
        );
        r2.record_and_graduate("git push --force origin main", &config);

        let msg2 = format_escalation_message(r2.graduated_response.as_ref().unwrap(), &ctx);
        assert!(msg2.contains("SOFT BLOCK:"));
        assert!(msg2.contains("Occurrences: 2"));
        assert!(msg2.contains("dcg test --force"));
    });
}

// =========================================================================
// Severity defaults with no overrides
// =========================================================================

#[test]
fn default_severity_effective_modes() {
    let config = enabled_config();

    // Critical defaults to Paranoid → HardBlock at count=1
    let r = determine_graduated_response(1, Severity::Critical, &config).unwrap();
    assert!(r.is_hard_block(), "Critical default → Paranoid → HardBlock");

    // Low defaults to WarningOnly → Warning at any count
    let r = determine_graduated_response(100, Severity::Low, &config).unwrap();
    assert!(
        matches!(r, GraduatedResponse::Warning { .. }),
        "Low default → WarningOnly → Warning"
    );

    // High uses global Standard mode → Warning at count=1
    let r = determine_graduated_response(1, Severity::High, &config).unwrap();
    assert!(
        matches!(r, GraduatedResponse::Warning { occurrence: 1 }),
        "High default → Standard → Warning(1)"
    );

    // Medium uses global Standard mode → Warning at count=1
    let r = determine_graduated_response(1, Severity::Medium, &config).unwrap();
    assert!(
        matches!(r, GraduatedResponse::Warning { occurrence: 1 }),
        "Medium default → Standard → Warning(1)"
    );
}

// =========================================================================
// Edge: u32 overflow safety
// =========================================================================

#[test]
fn max_count_does_not_panic() {
    let config = enabled_config();
    for severity in [
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ] {
        let _ = determine_graduated_response(u32::MAX, severity, &config);
    }

    let mut config_strict = enabled_config();
    config_strict.mode = GraduationMode::Strict;
    let _ = determine_graduated_response(u32::MAX, Severity::High, &config_strict);

    let mut config_lenient = enabled_config();
    config_lenient.mode = GraduationMode::Lenient;
    let _ = determine_graduated_response(u32::MAX, Severity::High, &config_lenient);
}

// =========================================================================
// Multiple graduation calls are idempotent
// =========================================================================

#[test]
fn apply_graduation_idempotent() {
    let config = enabled_config();
    let mut result = deny_result_with_occurrence(2);

    result.apply_graduation(&config);
    let first = result.graduated_response.clone();

    result.apply_graduation(&config);
    let second = result.graduated_response.clone();

    assert_eq!(
        first, second,
        "Repeated apply_graduation should produce same result"
    );
}
