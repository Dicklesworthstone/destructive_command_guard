//! Fuzz target for heredoc Tier 1 trigger detection.
//!
//! This fuzzes `heredoc::check_triggers` + `matched_triggers` and validates:
//! - No panics for arbitrary UTF-8 input
//! - `matched_triggers()` is consistent with `check_triggers()`

#![no_main]

use dcg_cli::heredoc::{TriggerResult, check_triggers, matched_triggers};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(command) = std::str::from_utf8(data) {
        // Skip extremely large inputs to avoid timeouts (not a real bug).
        if command.len() > 10_000 {
            return;
        }

        let result = check_triggers(command);
        let matches = matched_triggers(command);

        match result {
            TriggerResult::NoTrigger => {
                assert!(
                    matches.is_empty(),
                    "NoTrigger but matched_triggers() returned {:?} for: {:?}",
                    matches,
                    command
                );
            }
            TriggerResult::Triggered => {
                assert!(
                    !matches.is_empty(),
                    "Triggered but matched_triggers() returned empty for: {:?}",
                    command
                );
            }
        }
    }
});
