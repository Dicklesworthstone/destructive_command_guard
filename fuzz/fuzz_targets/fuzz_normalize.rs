//! Fuzz target for command normalization.
//!
//! This fuzzes `normalize_command` which strips path prefixes from commands.
//! It tests for:
//! - Panics from unusual paths
//! - Regex issues with adversarial input
//! - Idempotence violations

#![no_main]

use libfuzzer_sys::fuzz_target;

use dcg_cli::packs::normalize_command;

fuzz_target!(|data: &[u8]| {
    // Try to interpret as UTF-8
    if let Ok(command) = std::str::from_utf8(data) {
        // Skip extremely large inputs
        if command.len() > 10_000 {
            return;
        }

        // Normalize the command - this should never panic
        let normalized = normalize_command(command);

        // Verify idempotence: normalize(normalize(x)) == normalize(x)
        let normalized_again = normalize_command(&normalized);
        assert_eq!(
            normalized.as_ref(),
            normalized_again.as_ref(),
            "Normalization is not idempotent for: {:?}",
            command
        );

        // Normalized result should not be longer than original
        // (we're stripping prefixes, not adding)
        assert!(
            normalized.len() <= command.len(),
            "Normalized command is longer than original"
        );
    }
});
