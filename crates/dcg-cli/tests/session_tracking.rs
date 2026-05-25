//! Integration tests for session occurrence tracking (E10-T2).
//!
//! Verifies that the session module correctly tracks command occurrences
//! and that OccurrenceSnapshot is properly exposed on EvaluationResult.

use dcg_cli::session;
use std::sync::{Mutex, MutexGuard, PoisonError};

static SESSION_TEST_LOCK: Mutex<()> = Mutex::new(());

fn session_test_guard() -> MutexGuard<'static, ()> {
    SESSION_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

#[test]
fn session_hash_is_deterministic_across_calls() {
    let h1 = session::hash_command("git reset --hard HEAD~1");
    let h2 = session::hash_command("git reset --hard HEAD~1");
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 16, "hash should be 16 hex chars");
}

#[test]
fn session_hash_is_valid_hex() {
    let h = session::hash_command("rm -rf /");
    assert!(
        h.chars().all(|c| c.is_ascii_hexdigit()),
        "hash should contain only hex characters: {h}"
    );
}

#[test]
fn session_different_commands_produce_different_hashes() {
    let commands = [
        "git reset --hard",
        "rm -rf /",
        "docker system prune -af",
        "kubectl delete namespace prod",
        "drop table users;",
    ];
    let hashes: Vec<String> = commands.iter().map(|c| session::hash_command(c)).collect();
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(
                hashes[i], hashes[j],
                "collision between '{}' and '{}'",
                commands[i], commands[j]
            );
        }
    }
}

#[test]
fn session_increment_and_get_count() {
    let _guard = session_test_guard();
    session::reset();
    let cmd = "session_test_increment_unique_cmd_1234";
    assert_eq!(session::get_count(cmd), 0);
    assert_eq!(session::increment(cmd), 1);
    assert_eq!(session::get_count(cmd), 1);
    assert_eq!(session::increment(cmd), 2);
    assert_eq!(session::get_count(cmd), 2);
    session::reset();
}

#[test]
fn session_record_and_snapshot_captures_all_fields() {
    let _guard = session_test_guard();
    session::reset();

    let snap1 = session::record_and_snapshot("session_snap_cmd_a");
    assert_eq!(snap1.session_count, 1);
    assert_eq!(snap1.distinct_commands, 1);
    assert_eq!(snap1.total_occurrences, 1);
    assert_eq!(
        snap1.command_hash,
        session::hash_command("session_snap_cmd_a")
    );

    let snap2 = session::record_and_snapshot("session_snap_cmd_b");
    assert_eq!(snap2.session_count, 1);
    assert_eq!(snap2.distinct_commands, 2);
    assert_eq!(snap2.total_occurrences, 2);

    let snap3 = session::record_and_snapshot("session_snap_cmd_a");
    assert_eq!(snap3.session_count, 2);
    assert_eq!(snap3.distinct_commands, 2);
    assert_eq!(snap3.total_occurrences, 3);

    session::reset();
}

#[test]
fn session_reset_clears_everything() {
    let _guard = session_test_guard();
    session::reset();
    session::increment("session_reset_cmd");
    session::increment("session_reset_cmd");
    assert_eq!(session::get_count("session_reset_cmd"), 2);
    assert!(session::distinct_commands() >= 1);

    session::reset();
    assert_eq!(session::get_count("session_reset_cmd"), 0);
    assert_eq!(session::distinct_commands(), 0);
    assert_eq!(session::total_occurrences(), 0);
}

#[test]
fn session_high_volume_tracking() {
    let _guard = session_test_guard();
    session::reset();
    let cmd = "session_high_volume_stress_test";
    for i in 1..=1000 {
        assert_eq!(session::increment(cmd), i);
    }
    assert_eq!(session::get_count(cmd), 1000);
    assert_eq!(session::distinct_commands(), 1);
    assert_eq!(session::total_occurrences(), 1000);
    session::reset();
}

#[test]
fn session_many_distinct_commands() {
    let _guard = session_test_guard();
    session::reset();
    for i in 0..100 {
        let cmd = format!("session_distinct_cmd_{i}");
        assert_eq!(session::increment(&cmd), 1);
    }
    assert_eq!(session::distinct_commands(), 100);
    assert_eq!(session::total_occurrences(), 100);
    session::reset();
}

#[test]
fn evaluation_result_session_count_accessor() {
    use dcg_cli::evaluator::EvaluationResult;
    let mut result = EvaluationResult::allowed();
    assert_eq!(result.session_count(), None);

    result.session_occurrence = Some(session::OccurrenceSnapshot {
        command_hash: "abc123".to_string(),
        session_count: 3,
        distinct_commands: 5,
        total_occurrences: 12,
    });
    assert_eq!(result.session_count(), Some(3));
}

#[test]
fn occurrence_snapshot_equality() {
    let a = session::OccurrenceSnapshot {
        command_hash: "abc".to_string(),
        session_count: 1,
        distinct_commands: 1,
        total_occurrences: 1,
    };
    let b = a.clone();
    assert_eq!(a, b);

    let c = session::OccurrenceSnapshot {
        command_hash: "abc".to_string(),
        session_count: 2,
        distinct_commands: 1,
        total_occurrences: 2,
    };
    assert_ne!(a, c);
}

#[test]
fn occurrence_snapshot_debug_format() {
    let snap = session::OccurrenceSnapshot {
        command_hash: "deadbeef01234567".to_string(),
        session_count: 42,
        distinct_commands: 10,
        total_occurrences: 100,
    };
    let debug = format!("{snap:?}");
    assert!(debug.contains("deadbeef01234567"));
    assert!(debug.contains("42"));
}
