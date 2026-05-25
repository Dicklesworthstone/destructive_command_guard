//! Fuzz target for heredoc language detection heuristics.
//!
//! This fuzzes language detection for embedded scripts to ensure:
//! - No panics for arbitrary UTF-8 input
//! - Detection stays within bounds for weird inputs

#![no_main]

use dcg_cli::heredoc::ScriptLanguage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        // Keep the input reasonably small so the fuzzer spends time on interesting logic.
        if input.len() > 10_000 {
            return;
        }

        // Split into "cmd" and "content" to exercise different code paths.
        let (cmd, content) = input.split_once('\n').unwrap_or((input, ""));

        let _ = ScriptLanguage::from_command(cmd);
        let _ = ScriptLanguage::from_shebang(content);
        let _ = ScriptLanguage::from_content(content);
        let _ = ScriptLanguage::detect(cmd, content);
    }
});
