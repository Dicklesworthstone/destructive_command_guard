use destructive_command_guard::context::classify_command;
use destructive_command_guard::context::sanitize_for_pattern_matching;
use destructive_command_guard::normalize::strip_wrapper_prefixes;
use destructive_command_guard::packs::core::git;

#[test]
fn test_env_s_echo_false_positive() {
    // Scenario: User runs a safe echo command wrapped in env -S
    // This is valid shell usage.
    let cmd = "env -S \"echo git reset --hard\"";

    // 1. Check normalization
    let normalized = strip_wrapper_prefixes(cmd);
    // CURRENT BEHAVIOR: Normalization fails (returns original)
    // DESIRED BEHAVIOR: Should normalize to "echo git reset --hard"
    println!("Normalized: {}", normalized.normalized);

    // 2. Check classification
    // With current behavior (original string), it sees env -S and marks next arg as InlineCode
    let spans = classify_command(&normalized.normalized);
    let echo_span = spans
        .spans()
        .iter()
        .find(|s| s.text(&normalized.normalized).contains("echo"));

    if let Some(span) = echo_span {
        println!("Echo span kind: {:?}", span.kind);
    }

    // 3. Check pattern matching
    // IMPORTANT: The Evaluator runs sanitize_for_pattern_matching BEFORE checking packs.
    // We must do the same to simulate real behavior.
    let sanitized = sanitize_for_pattern_matching(&normalized.normalized);
    println!("Sanitized: '{sanitized}'");

    let pack = git::create_pack();
    let match_result = pack.check(&sanitized);

    assert!(
        match_result.is_none(),
        "Safe echo command should NOT be blocked, but was: {match_result:?}"
    );
}

#[test]
fn test_bash_c_echo_false_positive() {
    // Scenario: User runs a safe echo command inside bash -c
    let cmd = "bash -c \"echo git reset --hard\"";

    // Normalization shouldn't change much for bash -c
    let normalized = strip_wrapper_prefixes(cmd);
    println!("Normalized: {}", normalized.normalized);

    // Evaluator sanitizes before checking.
    // context.rs classifies "echo git..." as InlineCode.
    // InlineCode is NOT masked (it is code!).
    let sanitized = sanitize_for_pattern_matching(&normalized.normalized);
    println!("Sanitized: '{sanitized}'");

    // Pack checking
    let pack = git::create_pack();
    let match_result = pack.check(&sanitized);

    // This is EXPECTED to fail (False Positive) currently, as InlineCode is not recursively parsed.
    // But let's assert what happens.
    // If it blocks, it confirms the false positive exists for bash -c.
    // If we want to fix env -S, we at least fix it for env -S.
    // bash -c is harder.

    // For now, let's just observe.
    if match_result.is_some() {
        println!("Blocked as expected (current limitation for bash -c)");
    } else {
        println!("Allowed! (Unexpected but good)");
    }
}
