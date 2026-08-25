//! Fuzz target for command normalization.
//!
//! This fuzzes `normalize_command` which strips path prefixes from commands.
//! It tests for:
//! - Panics from unusual paths
//! - Regex issues with adversarial input
//! - Idempotence violations

#![no_main]

use libfuzzer_sys::fuzz_target;

use destructive_command_guard::packs::normalize_command;

fuzz_target!(|data: &[u8]| {
    // Try to interpret as UTF-8
    if let Ok(command) = std::str::from_utf8(data) {
        // Skip extremely large inputs
        if command.len() > 10_000 {
            return;
        }

        // Normalize the command - this should never panic
        let normalized = normalize_command(command);

        // Verify idempotence: normalize(normalize(x)) == normalize(x).
        // This is the load-bearing correctness invariant for normalization.
        let normalized_again = normalize_command(&normalized);
        assert_eq!(
            normalized.as_ref(),
            normalized_again.as_ref(),
            "Normalization is not idempotent for: {:?}",
            command
        );

        // Normalization *canonicalizes* — it strips path prefixes and wrappers
        // but also inserts a separator when a redirect operator is glued to the
        // preceding token (`?P>(` -> `?P >(`), so the result can be a bounded
        // amount longer, not merely shorter. The meaningful guard here is that
        // it never blows up super-linearly (a DoS): allow generous linear
        // growth and only fail on a pathological expansion.
        assert!(
            normalized.len() <= command.len().saturating_mul(2) + 16,
            "Normalized command grew pathologically: {} -> {} for {:?}",
            command.len(),
            normalized.len(),
            command
        );
    }
});
