//! Fuzz target for bash AST command extraction (tree-sitter via ast-grep).
//!
//! This fuzzes `heredoc::extract_shell_commands` and validates:
//! - No panics for arbitrary UTF-8 input
//! - Returned byte ranges are in-bounds
//! - Returned byte ranges are valid UTF-8 slice boundaries

#![no_main]

use dcg_cli::heredoc::extract_shell_commands;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(content) = std::str::from_utf8(data) {
        // Tree-sitter is fast, but keep the fuzzer from spending cycles on huge inputs.
        if content.len() > 10_000 {
            return;
        }

        let commands = extract_shell_commands(content);

        for cmd in commands {
            assert!(
                cmd.start <= content.len(),
                "start {} exceeds content length {}",
                cmd.start,
                content.len()
            );
            assert!(
                cmd.end <= content.len(),
                "end {} exceeds content length {}",
                cmd.end,
                content.len()
            );
            assert!(
                cmd.start <= cmd.end,
                "start {} > end {}",
                cmd.start,
                cmd.end
            );
            assert!(
                content.is_char_boundary(cmd.start),
                "start {} is not a char boundary",
                cmd.start
            );
            assert!(
                content.is_char_boundary(cmd.end),
                "end {} is not a char boundary",
                cmd.end
            );
            assert!(cmd.line_number >= 1, "line_number must be >= 1");
        }
    }
});
