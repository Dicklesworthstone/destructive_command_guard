#![allow(clippy::uninlined_format_args)]

use destructive_command_guard::allowlist::LayeredAllowlist;
use destructive_command_guard::config::{CompiledOverrides, Config};
use destructive_command_guard::context::{classify_command, sanitize_for_pattern_matching};
use destructive_command_guard::evaluator::evaluate_command;
use destructive_command_guard::normalize::normalize_command;
use destructive_command_guard::packs::{REGISTRY, pack_aware_quick_reject};

fn evaluate(cmd: &str) -> bool {
    let config = Config::default();
    let compiled = CompiledOverrides::default();
    let allowlists = LayeredAllowlist::default();
    // Keywords for git and rm are likely enabled by default or we pass them manually
    let keywords = &["git", "rm"];

    let result = evaluate_command(cmd, &config, keywords, &compiled, &allowlists);

    result.is_denied()
}

#[test]
fn debug_compound_command_spans() {
    let cmd = "rm -rf / ; git checkout -b foo";
    let keywords: &[&str] = &["git", "rm"];

    eprintln!("\n=== STEP 1: Original Command ===");
    eprintln!("Original: {:?}", cmd);

    eprintln!("\n=== STEP 2: Quick-reject on raw command ===");
    let raw_quick_reject = pack_aware_quick_reject(cmd, keywords);
    eprintln!("pack_aware_quick_reject(raw): {}", raw_quick_reject);

    eprintln!("\n=== STEP 3: Sanitization ===");
    let sanitized = sanitize_for_pattern_matching(cmd);
    let sanitized_is_cow_owned = matches!(sanitized, std::borrow::Cow::Owned(_));
    eprintln!("Sanitized: {:?}", sanitized.as_ref());
    eprintln!("Modified by sanitization: {}", sanitized_is_cow_owned);

    eprintln!("\n=== STEP 4: Quick-reject on sanitized command ===");
    let sanitized_quick_reject = pack_aware_quick_reject(sanitized.as_ref(), keywords);
    eprintln!(
        "pack_aware_quick_reject(sanitized): {}",
        sanitized_quick_reject
    );
    eprintln!(
        "Would skip pattern matching: {}",
        sanitized_is_cow_owned && sanitized_quick_reject
    );

    eprintln!("\n=== STEP 5: Normalization ===");
    let normalized = normalize_command(sanitized.as_ref());
    eprintln!("Normalized: {:?}", normalized.as_ref());

    eprintln!("\n=== STEP 6: Span Classification ===");
    let spans = classify_command(normalized.as_ref());
    eprintln!("Spans:");
    for span in spans.spans() {
        let text = span.text(normalized.as_ref());
        eprintln!(
            "  {:?}: {:?} ({}..{})",
            span.kind, text, span.byte_range.start, span.byte_range.end
        );
    }
    eprintln!("Executable spans:");
    for span in spans.executable_spans() {
        eprintln!("  {:?}", span.text(normalized.as_ref()));
    }

    eprintln!("\n=== STEP 7: Keyword check in executable spans ===");
    for span in spans.executable_spans() {
        let text = span.text(normalized.as_ref());
        for kw in keywords {
            if text.contains(kw) {
                eprintln!("  Found '{}' in '{}'", kw, text);
            }
        }
    }

    eprintln!("\n=== STEP 8: Pack pattern test ===");
    // Test the rm-rf-root-home pattern directly
    let pattern = regex::Regex::new(r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+[/~]|rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+[/~]").unwrap();
    eprintln!(
        "rm-rf-root-home pattern matches original: {}",
        pattern.is_match(cmd)
    );
    eprintln!(
        "rm-rf-root-home pattern matches normalized: {}",
        pattern.is_match(normalized.as_ref())
    );

    eprintln!("\n=== STEP 9: Config and pack setup ===");
    let config = Config::default();
    let enabled_packs = config.enabled_pack_ids();
    eprintln!("Enabled packs: {:?}", enabled_packs);
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    eprintln!("Ordered packs: {:?}", ordered_packs);

    eprintln!("\n=== STEP 10: Test direct pack evaluation ===");
    let fs_pack = REGISTRY.get("core.filesystem").unwrap();
    eprintln!("core.filesystem pack exists: true");
    eprintln!(
        "Destructive patterns count: {}",
        fs_pack.destructive_patterns.len()
    );

    // Check if the pack's regex matches
    for dp in &fs_pack.destructive_patterns {
        let matches_orig = dp.regex.find(cmd).is_some();
        let matches_norm = dp.regex.find(normalized.as_ref()).is_some();
        if matches_orig || matches_norm {
            eprintln!(
                "  Pattern {:?} matches: orig={} norm={}",
                dp.name, matches_orig, matches_norm
            );
        }
    }

    eprintln!("\n=== STEP 11: Test keyword index mask ===");
    let keyword_index = REGISTRY.build_enabled_keyword_index(&ordered_packs);
    if let Some(ref idx) = keyword_index {
        let mask = idx.candidate_pack_mask(normalized.as_ref());
        eprintln!("Keyword index mask: {:016b}", mask);
        // Check which packs are included
        for (i, pack_id) in ordered_packs.iter().enumerate() {
            let included = (mask >> i) & 1 == 1;
            eprintln!("  {} {}: included={}", i, pack_id, included);
        }
    } else {
        eprintln!("No keyword index built!");
    }

    eprintln!("\n=== STEP 12: Full evaluation result ===");
    let compiled = CompiledOverrides::default();
    let allowlists = LayeredAllowlist::default();
    let result = evaluate_command(cmd, &config, keywords, &compiled, &allowlists);
    eprintln!("Result: {:?}", result);
    eprintln!("Is denied: {}", result.is_denied());

    eprintln!();
}

#[test]
fn test_compound_command_bypass() {
    // "git checkout -b foo" is explicitly SAFE. "rm -rf /" is destructive.
    // If safe patterns are unanchored, "git checkout -b" might match this string
    // and cause the evaluator to allow the whole thing.
    let cmd = "rm -rf / ; git checkout -b foo";
    assert!(evaluate(cmd), "Command '{cmd}' should be blocked");
}

#[test]
fn test_compound_command_bypass_reverse() {
    let cmd = "git checkout -b foo ; rm -rf /";
    assert!(evaluate(cmd), "Command '{cmd}' should be blocked");
}

#[test]
fn test_pipe_bypass() {
    let cmd = "rm -rf / | git checkout -b foo";
    assert!(evaluate(cmd), "Command '{cmd}' should be blocked");
}
