//! Fuzz target for heredoc Tier 2 content extraction.
//!
//! This fuzzes `heredoc::extract_content` and validates:
//! - No panics for arbitrary UTF-8 input
//! - Extracted content is bounded by configured limits
//! - Tier 1 trigger is a superset of Tier 2 extraction (no false negatives)

#![no_main]

use dcg_cli::heredoc::{
    ExtractionLimits, ExtractionResult, TriggerResult, check_triggers, extract_content,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(command) = std::str::from_utf8(data) {
        // Skip extremely large inputs to avoid timeouts (not a real bug).
        if command.len() > 10_000 {
            return;
        }

        let limits = ExtractionLimits {
            max_body_bytes: 10_000,
            max_body_lines: 1_000,
            max_heredocs: 5,
            timeout_ms: 20,
        };

        let result = extract_content(command, &limits);

        if let ExtractionResult::Extracted(contents) = result {
            // Tier 1 must be a superset: if Tier 2 extracted, Tier 1 must have triggered.
            assert_eq!(
                check_triggers(command),
                TriggerResult::Triggered,
                "Tier 2 extracted content but Tier 1 did not trigger for: {:?}",
                command
            );

            assert!(
                contents.len() <= limits.max_heredocs,
                "Extracted {} heredocs > max_heredocs {} for: {:?}",
                contents.len(),
                limits.max_heredocs,
                command
            );

            for item in contents {
                assert!(
                    item.content.len() <= limits.max_body_bytes,
                    "Extracted content exceeds max_body_bytes ({} > {})",
                    item.content.len(),
                    limits.max_body_bytes
                );

                let line_count = item.content.lines().count();
                assert!(
                    line_count <= limits.max_body_lines,
                    "Extracted content exceeds max_body_lines ({} > {})",
                    line_count,
                    limits.max_body_lines
                );

                assert!(
                    item.byte_range.start <= command.len(),
                    "byte_range.start {} exceeds command length {}",
                    item.byte_range.start,
                    command.len()
                );
                assert!(
                    item.byte_range.end <= command.len(),
                    "byte_range.end {} exceeds command length {}",
                    item.byte_range.end,
                    command.len()
                );
                assert!(
                    item.byte_range.start <= item.byte_range.end,
                    "byte_range.start {} > end {}",
                    item.byte_range.start,
                    item.byte_range.end
                );
                assert!(
                    command.is_char_boundary(item.byte_range.start),
                    "byte_range.start {} is not a char boundary",
                    item.byte_range.start
                );
                assert!(
                    command.is_char_boundary(item.byte_range.end),
                    "byte_range.end {} is not a char boundary",
                    item.byte_range.end
                );
            }
        }
    }
});
