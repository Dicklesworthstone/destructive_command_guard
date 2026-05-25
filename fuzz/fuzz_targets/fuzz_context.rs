//! Fuzz target for the context classifier (shell tokenizer).
//!
//! This fuzzes `classify_command` which parses shell syntax to identify
//! which parts are executed vs data. It tests for:
//! - Panics from malformed shell syntax
//! - Incorrect span bounds (out of range)
//! - Infinite loops in tokenizer

#![no_main]

use libfuzzer_sys::fuzz_target;

use dcg_cli::context::classify_command;

fuzz_target!(|data: &[u8]| {
    // Try to interpret as UTF-8
    if let Ok(command) = std::str::from_utf8(data) {
        // Skip extremely large inputs to avoid timeout
        if command.len() > 10_000 {
            return;
        }

        // Classify the command - this should never panic
        let spans = classify_command(command);

        // Validate invariants: all spans should be within bounds
        for span in spans.spans() {
            assert!(
                span.byte_range.start <= command.len(),
                "Span start {} exceeds command length {}",
                span.byte_range.start,
                command.len()
            );
            assert!(
                span.byte_range.end <= command.len(),
                "Span end {} exceeds command length {}",
                span.byte_range.end,
                command.len()
            );
            assert!(
                span.byte_range.start <= span.byte_range.end,
                "Span start {} > end {}",
                span.byte_range.start,
                span.byte_range.end
            );
        }
    }
});
