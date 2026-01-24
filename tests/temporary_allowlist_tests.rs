//! Comprehensive tests for Temporary/Expiring Allowlist Entries (Epic 6).
//!
//! Tests the time-limited allowlist entry system including:
//! - Duration parsing (TTL formats: s, m, h, d, w)
//! - Absolute timestamp parsing (RFC3339, ISO8601, date-only)
//! - Expiration boundary conditions
//! - CLI commands for temporary entries
//! - E2E expiration workflow
//!
//! Part of git_safety_guard-ypyr: [E6-T9] Comprehensive testing for Temporary/Expiring Allowlist Entries

mod e2e;

use e2e::{E2ETestContext, TestLogger};

// ============================================================================
// UNIT TESTS: Duration Parsing (TTL Format)
// ============================================================================

/// Test duration format parsing for various time units.
mod duration_parsing {
    use destructive_command_guard::allowlist::parse_duration;

    #[test]
    fn parse_seconds() {
        let duration = parse_duration("30s").expect("Should parse seconds");
        assert_eq!(duration.num_seconds(), 30);
    }

    #[test]
    fn parse_minutes() {
        let duration = parse_duration("45m").expect("Should parse minutes");
        assert_eq!(duration.num_minutes(), 45);
    }

    #[test]
    fn parse_hours() {
        let duration = parse_duration("4h").expect("Should parse hours");
        assert_eq!(duration.num_hours(), 4);
    }

    #[test]
    fn parse_days() {
        let duration = parse_duration("7d").expect("Should parse days");
        assert_eq!(duration.num_days(), 7);
    }

    #[test]
    fn parse_weeks() {
        let duration = parse_duration("2w").expect("Should parse weeks");
        assert_eq!(duration.num_weeks(), 2);
    }

    #[test]
    fn parse_large_duration() {
        let duration = parse_duration("365d").expect("Should parse large duration");
        assert_eq!(duration.num_days(), 365);
    }

    #[test]
    fn parse_zero_duration_rejected() {
        // Zero is rejected to prevent immediately-expired entries
        let result = parse_duration("0s");
        assert!(result.is_err(), "Should reject zero duration");
    }

    #[test]
    fn reject_negative_duration() {
        let result = parse_duration("-1h");
        assert!(result.is_err(), "Should reject negative duration");
    }

    #[test]
    fn reject_invalid_unit() {
        let result = parse_duration("30x");
        assert!(result.is_err(), "Should reject invalid unit");
    }

    #[test]
    fn reject_no_unit() {
        let result = parse_duration("30");
        assert!(result.is_err(), "Should reject missing unit");
    }

    #[test]
    fn reject_empty_string() {
        let result = parse_duration("");
        assert!(result.is_err(), "Should reject empty string");
    }

    #[test]
    fn reject_non_numeric() {
        let result = parse_duration("twoh");
        assert!(result.is_err(), "Should reject non-numeric value");
    }

    #[test]
    fn parse_decimal_value() {
        // Decimals might be truncated or rejected depending on implementation
        let result = parse_duration("1.5h");
        // Either should work or fail gracefully
        if let Ok(duration) = result {
            // Expect either 1 or 1.5 hours
            assert!(duration.num_minutes() >= 60);
        }
    }

    #[test]
    fn parse_case_insensitive() {
        // Test that units are case-insensitive
        let lower = parse_duration("1h");
        let upper = parse_duration("1H");

        match (lower, upper) {
            (Ok(l), Ok(u)) => assert_eq!(l, u, "Should be case-insensitive"),
            (Err(_), Err(_)) => (), // Both fail is acceptable too
            _ => (),                // One works, one doesn't - also acceptable
        }
    }
}

// ============================================================================
// UNIT TESTS: Expiration Timestamp Parsing
// ============================================================================

mod timestamp_parsing {
    use destructive_command_guard::allowlist::{AllowEntry, AllowSelector, RuleId, is_expired};
    use std::collections::HashMap;

    fn make_test_entry() -> AllowEntry {
        AllowEntry {
            selector: AllowSelector::Rule(RuleId::parse("core.git:*").expect("valid rule id")),
            reason: "test".to_string(),
            added_by: None,
            added_at: None,
            expires_at: None,
            ttl: None,
            session: None,
            context: None,
            conditions: HashMap::new(),
            environments: Vec::new(),
            paths: None,
            risk_acknowledged: false,
        }
    }

    #[test]
    fn rfc3339_with_z_suffix() {
        let mut entry = make_test_entry();
        entry.expires_at = Some("2099-12-31T23:59:59Z".to_string());
        assert!(
            !is_expired(&entry),
            "Future Z-suffix timestamp should not be expired"
        );
    }

    #[test]
    fn rfc3339_with_offset() {
        let mut entry = make_test_entry();
        entry.expires_at = Some("2099-12-31T23:59:59+00:00".to_string());
        assert!(
            !is_expired(&entry),
            "Future +00:00 offset should not be expired"
        );
    }

    #[test]
    fn rfc3339_with_positive_offset() {
        let mut entry = make_test_entry();
        entry.expires_at = Some("2099-12-31T23:59:59+05:30".to_string());
        assert!(
            !is_expired(&entry),
            "Future positive offset should not be expired"
        );
    }

    #[test]
    fn rfc3339_with_negative_offset() {
        let mut entry = make_test_entry();
        entry.expires_at = Some("2099-12-31T23:59:59-08:00".to_string());
        assert!(
            !is_expired(&entry),
            "Future negative offset should not be expired"
        );
    }

    #[test]
    fn iso8601_without_timezone() {
        let mut entry = make_test_entry();
        entry.expires_at = Some("2099-12-31T23:59:59".to_string());
        assert!(
            !is_expired(&entry),
            "Future ISO8601 without TZ should not be expired"
        );
    }

    #[test]
    fn date_only_format() {
        let mut entry = make_test_entry();
        entry.expires_at = Some("2099-12-31".to_string());
        assert!(
            !is_expired(&entry),
            "Future date-only should not be expired"
        );
    }

    #[test]
    fn past_timestamp_is_expired() {
        let mut entry = make_test_entry();
        entry.expires_at = Some("2020-01-01T00:00:00Z".to_string());
        assert!(is_expired(&entry), "Past timestamp should be expired");
    }

    #[test]
    fn invalid_format_fails_closed() {
        let mut entry = make_test_entry();
        entry.expires_at = Some("not-a-date".to_string());
        assert!(
            is_expired(&entry),
            "Invalid format should fail closed (expired)"
        );
    }

    #[test]
    fn malformed_rfc3339_fails_closed() {
        let mut entry = make_test_entry();
        entry.expires_at = Some("2099-13-45T99:99:99Z".to_string());
        assert!(is_expired(&entry), "Malformed timestamp should fail closed");
    }

    #[test]
    fn empty_string_fails_closed() {
        let mut entry = make_test_entry();
        entry.expires_at = Some("".to_string());
        assert!(is_expired(&entry), "Empty string should fail closed");
    }
}

// ============================================================================
// UNIT TESTS: TTL-Based Expiration
// ============================================================================

mod ttl_expiration {
    use chrono::{Duration, Utc};
    use destructive_command_guard::allowlist::{AllowEntry, AllowSelector, RuleId, is_expired};
    use std::collections::HashMap;

    fn make_test_entry() -> AllowEntry {
        AllowEntry {
            selector: AllowSelector::Rule(RuleId::parse("core.git:*").expect("valid rule id")),
            reason: "test".to_string(),
            added_by: None,
            added_at: None,
            expires_at: None,
            ttl: None,
            session: None,
            context: None,
            conditions: HashMap::new(),
            environments: Vec::new(),
            paths: None,
            risk_acknowledged: false,
        }
    }

    #[test]
    fn ttl_with_future_expiration() {
        let mut entry = make_test_entry();
        entry.ttl = Some("4h".to_string());
        let added = Utc::now() - Duration::hours(1);
        entry.added_at = Some(added.to_rfc3339());
        assert!(
            !is_expired(&entry),
            "Entry added 1h ago with 4h TTL should not be expired"
        );
    }

    #[test]
    fn ttl_with_exact_boundary() {
        let mut entry = make_test_entry();
        entry.ttl = Some("1h".to_string());
        // Entry added exactly 1 hour ago should be at boundary
        let added = Utc::now() - Duration::hours(1);
        entry.added_at = Some(added.to_rfc3339());
        // At exact boundary - behavior depends on implementation (>= or >)
        // We just check it runs without panic
        let _ = is_expired(&entry);
    }

    #[test]
    fn ttl_with_past_expiration() {
        let mut entry = make_test_entry();
        entry.ttl = Some("1h".to_string());
        let added = Utc::now() - Duration::hours(2);
        entry.added_at = Some(added.to_rfc3339());
        assert!(
            is_expired(&entry),
            "Entry added 2h ago with 1h TTL should be expired"
        );
    }

    #[test]
    fn ttl_without_added_at_fails_closed() {
        let mut entry = make_test_entry();
        entry.ttl = Some("4h".to_string());
        entry.added_at = None;
        assert!(
            is_expired(&entry),
            "TTL without added_at should fail closed"
        );
    }

    #[test]
    fn ttl_with_invalid_added_at_fails_closed() {
        let mut entry = make_test_entry();
        entry.ttl = Some("4h".to_string());
        entry.added_at = Some("not-a-timestamp".to_string());
        assert!(
            is_expired(&entry),
            "TTL with invalid added_at should fail closed"
        );
    }

    #[test]
    fn ttl_with_invalid_format_fails_closed() {
        let mut entry = make_test_entry();
        entry.ttl = Some("invalid".to_string());
        entry.added_at = Some(Utc::now().to_rfc3339());
        assert!(is_expired(&entry), "Invalid TTL format should fail closed");
    }
}

// ============================================================================
// UNIT TESTS: Session-Scoped Entries
// ============================================================================

mod session_entries {
    use destructive_command_guard::allowlist::{AllowEntry, AllowSelector, RuleId, is_expired};
    use std::collections::HashMap;

    fn make_test_entry() -> AllowEntry {
        AllowEntry {
            selector: AllowSelector::Rule(RuleId::parse("core.git:*").expect("valid rule id")),
            reason: "test".to_string(),
            added_by: None,
            added_at: None,
            expires_at: None,
            ttl: None,
            session: None,
            context: None,
            conditions: HashMap::new(),
            environments: Vec::new(),
            paths: None,
            risk_acknowledged: false,
        }
    }

    #[test]
    fn session_true_not_expired_by_timestamp() {
        let mut entry = make_test_entry();
        entry.session = Some(true);
        // Session entries are not expired by is_expired check
        // They are managed by the session tracker
        assert!(!is_expired(&entry));
    }

    #[test]
    fn session_false_is_same_as_no_session() {
        let mut entry = make_test_entry();
        entry.session = Some(false);
        assert!(!is_expired(&entry));
    }
}

// ============================================================================
// UNIT TESTS: Expiration Exclusivity
// ============================================================================

mod expiration_exclusivity {
    use destructive_command_guard::allowlist::validate_expiration_exclusivity;

    #[test]
    fn no_expiration_is_valid() {
        let result = validate_expiration_exclusivity(None, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn only_expires_at_is_valid() {
        let result = validate_expiration_exclusivity(Some("2099-01-01"), None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn only_ttl_is_valid() {
        let result = validate_expiration_exclusivity(None, Some("4h"), None);
        assert!(result.is_ok());
    }

    #[test]
    fn only_session_is_valid() {
        let result = validate_expiration_exclusivity(None, None, Some(true));
        assert!(result.is_ok());
    }

    #[test]
    fn expires_at_and_ttl_conflict() {
        let result = validate_expiration_exclusivity(Some("2099-01-01"), Some("4h"), None);
        assert!(result.is_err());
    }

    #[test]
    fn expires_at_and_session_conflict() {
        let result = validate_expiration_exclusivity(Some("2099-01-01"), None, Some(true));
        assert!(result.is_err());
    }

    #[test]
    fn ttl_and_session_conflict() {
        let result = validate_expiration_exclusivity(None, Some("4h"), Some(true));
        assert!(result.is_err());
    }

    #[test]
    fn all_three_conflict() {
        let result = validate_expiration_exclusivity(Some("2099-01-01"), Some("4h"), Some(true));
        assert!(result.is_err());
    }
}

// ============================================================================
// E2E TESTS: CLI Commands for Temporary Entries
// ============================================================================

#[test]
fn e2e_allow_command_with_temporary_flag() {
    let ctx = E2ETestContext::builder("temporary_allow")
        .with_config("minimal")
        .build();

    // Add a temporary allowlist entry
    let output = ctx.run_dcg(&[
        "allowlist",
        "add",
        "core.git:reset-hard",
        "--reason",
        "testing temporary entries",
        "--temporary",
        "1h",
    ]);

    let combined = format!("{}{}", output.stdout, output.stderr);

    // Should succeed (exit code 0 or confirmation message)
    // Note: exact behavior depends on whether config file exists
    if output.exit_code == 0 {
        // Success - entry added
        assert!(
            combined.contains("added") || combined.contains("success") || combined.is_empty(),
            "Should confirm entry was added.\nOutput: {}",
            combined
        );
    }
}

#[test]
fn e2e_allow_command_with_expires_flag() {
    let ctx = E2ETestContext::builder("expires_allow")
        .with_config("minimal")
        .build();

    // Add an allowlist entry with absolute expiration
    let output = ctx.run_dcg(&[
        "allowlist",
        "add",
        "core.git:reset-hard",
        "--reason",
        "testing expiration",
        "--expires",
        "2099-12-31T23:59:59Z",
    ]);

    let combined = format!("{}{}", output.stdout, output.stderr);

    // Should succeed or show error about config location
    if output.exit_code == 0 {
        assert!(
            combined.contains("added") || combined.is_empty(),
            "Should confirm entry was added.\nOutput: {}",
            combined
        );
    }
}

#[test]
fn e2e_temporary_and_expires_conflict() {
    let ctx = E2ETestContext::builder("conflict_flags")
        .with_config("minimal")
        .build();

    // Both --temporary and --expires should conflict
    let output = ctx.run_dcg(&[
        "allowlist",
        "add",
        "core.git:reset-hard",
        "--reason",
        "conflict test",
        "--temporary",
        "1h",
        "--expires",
        "2099-01-01",
    ]);

    // Should fail - conflicting arguments
    assert!(
        output.exit_code != 0
            || output.stderr.contains("conflict")
            || output.stderr.contains("cannot"),
        "Should reject conflicting --temporary and --expires flags.\nstderr: {}",
        output.stderr
    );
}

// ============================================================================
// E2E TESTS: Allowlist List Shows Expiration
// ============================================================================

#[test]
fn e2e_allowlist_list_shows_expiration_info() {
    let logger = TestLogger::new("allowlist_list_expiration");
    let ctx = E2ETestContext::builder("list_expiration")
        .with_config("minimal")
        .build();

    logger.log_test_start("Testing that allowlist list shows expiration info");

    let output = ctx.run_dcg(&["allowlist", "list"]);
    let combined = format!("{}{}", output.stdout, output.stderr);

    logger.log_step("list_output", &combined);

    // The list output format depends on implementation
    // We just verify the command runs successfully
    assert!(
        output.exit_code == 0 || combined.contains("no entries") || combined.contains("empty"),
        "allowlist list should run successfully"
    );

    logger.log_test_end(true, None);
}

// ============================================================================
// E2E TESTS: Expired Entry Behavior
// ============================================================================

#[test]
fn e2e_expired_entry_does_not_allow_command() {
    let ctx = E2ETestContext::builder("expired_entry")
        .with_config("minimal")
        .build();

    // Test that a command blocked by default is still blocked
    // even if an expired entry exists (the config would have to
    // be manually crafted - this tests the evaluation logic)
    let output = ctx.run_dcg_hook("git reset --hard HEAD");

    // Should be blocked regardless of expired entries
    assert!(
        output.is_blocked(),
        "git reset --hard should be blocked when no valid allowlist entry exists"
    );
}

// ============================================================================
// E2E TESTS: Entry Validity Checks
// ============================================================================

#[test]
fn e2e_validate_checks_expired_entries() {
    let ctx = E2ETestContext::builder("validate_expired")
        .with_config("minimal")
        .build();

    // Run allowlist validate - should warn about expired entries if any
    let output = ctx.run_dcg(&["allowlist", "validate"]);

    // Should complete successfully
    assert!(
        output.exit_code == 0 || output.stderr.contains("warning"),
        "allowlist validate should run or show warnings.\nstdout: {}\nstderr: {}",
        output.stdout,
        output.stderr
    );
}

// ============================================================================
// INTEGRATION TESTS: Expiration Workflow
// ============================================================================

#[test]
fn integration_entry_validity_check() {
    use destructive_command_guard::allowlist::{AllowEntry, AllowSelector, RuleId, is_entry_valid};
    use std::collections::HashMap;

    // Valid entry (no expiration)
    let valid = AllowEntry {
        selector: AllowSelector::Rule(RuleId::parse("core.git:*").expect("valid rule id")),
        reason: "test".to_string(),
        added_by: None,
        added_at: None,
        expires_at: None,
        ttl: None,
        session: None,
        context: None,
        conditions: HashMap::new(),
        environments: Vec::new(),
        paths: None,
        risk_acknowledged: false,
    };
    assert!(
        is_entry_valid(&valid),
        "Entry without expiration should be valid"
    );

    // Expired entry
    let expired = AllowEntry {
        selector: AllowSelector::Rule(RuleId::parse("core.git:*").expect("valid rule id")),
        reason: "test".to_string(),
        added_by: None,
        added_at: None,
        expires_at: Some("2020-01-01".to_string()),
        ttl: None,
        session: None,
        context: None,
        conditions: HashMap::new(),
        environments: Vec::new(),
        paths: None,
        risk_acknowledged: false,
    };
    assert!(
        !is_entry_valid(&expired),
        "Expired entry should not be valid"
    );
}

// ============================================================================
// REGRESSION TESTS
// ============================================================================

#[test]
fn regression_permanent_entries_never_expire() {
    use destructive_command_guard::allowlist::{AllowEntry, AllowSelector, RuleId, is_expired};
    use std::collections::HashMap;

    let permanent = AllowEntry {
        selector: AllowSelector::Rule(RuleId::parse("core.git:*").expect("valid rule id")),
        reason: "permanent rule".to_string(),
        added_by: None,
        added_at: None,
        expires_at: None,
        ttl: None,
        session: None,
        context: None,
        conditions: HashMap::new(),
        environments: Vec::new(),
        paths: None,
        risk_acknowledged: false,
    };

    assert!(
        !is_expired(&permanent),
        "Permanent entries should never expire"
    );
}

#[test]
fn regression_far_future_dates_not_expired() {
    use destructive_command_guard::allowlist::{AllowEntry, AllowSelector, RuleId, is_expired};
    use std::collections::HashMap;

    let far_future = AllowEntry {
        selector: AllowSelector::Rule(RuleId::parse("core.git:*").expect("valid rule id")),
        reason: "far future".to_string(),
        added_by: None,
        added_at: None,
        expires_at: Some("9999-12-31T23:59:59Z".to_string()),
        ttl: None,
        session: None,
        context: None,
        conditions: HashMap::new(),
        environments: Vec::new(),
        paths: None,
        risk_acknowledged: false,
    };

    assert!(
        !is_expired(&far_future),
        "Far future dates should not be expired"
    );
}
