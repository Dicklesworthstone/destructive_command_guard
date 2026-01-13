//! Memory leak detection tests for DCG
//!
//! These tests verify that DCG's hot paths don't leak memory
//! when processing many inputs. Critical because DCG runs on
//! every Bash command in Claude Code sessions.
//!
//! MUST run with: cargo test --test memory_tests --release -- --test-threads=1 --nocapture
//!
//! ## Why These Tests Matter
//!
//! DCG is invoked on EVERY command in Claude Code sessions:
//! - 1000+ commands per session is common
//! - Memory leaks compound across invocations
//! - Even 1KB/command = 1MB leaked per session
//!
//! ## Platform Support
//!
//! - Linux: Full support (reads /proc/self/statm)
//! - macOS/Windows: Tests skip gracefully

#![cfg(test)]
#![allow(
    clippy::missing_panics_doc,
    clippy::uninlined_format_args,
    clippy::must_use_candidate,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::unit_arg
)]

use destructive_command_guard as dcg;
use std::hint::black_box;

/// Check if we're running under coverage instrumentation.
///
/// Coverage tools (cargo-llvm-cov) add significant memory overhead that makes
/// memory leak detection unreliable. Returns true if CARGO_LLVM_COV or
/// LLVM_PROFILE_FILE environment variables are set.
fn is_coverage_build() -> bool {
    std::env::var("CARGO_LLVM_COV").is_ok() || std::env::var("LLVM_PROFILE_FILE").is_ok()
}

/// Get current memory usage via /proc/self/statm (Linux)
/// Returns resident set size in bytes
fn get_memory_usage() -> Option<usize> {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        let statm = fs::read_to_string("/proc/self/statm").ok()?;
        let rss_pages: usize = statm.split_whitespace().nth(1)?.parse().ok()?;

        // Use getconf to avoid unsafe libc call
        let page_size = std::process::Command::new("getconf")
            .arg("PAGESIZE")
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .and_then(|s| s.trim().parse::<usize>().ok())
            .unwrap_or(4096);

        Some(rss_pages * page_size)
    }

    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Memory test helper with detailed logging
///
/// # Arguments
/// * `name` - Test name for logging
/// * `iterations` - Number of times to run the closure
/// * `max_growth_bytes` - Maximum allowed memory growth
/// * `f` - Closure to run repeatedly
///
/// # Behavior
/// 1. Warms up with 10 iterations (triggers lazy initialization)
/// 2. Measures baseline memory
/// 3. Runs iterations with periodic progress logging
/// 4. Asserts final growth is within budget
///
/// # Flakiness Mitigation
/// - Generous budgets (1-2MB) accommodate measurement noise
/// - Warm-up phase triggers lazy_static initialization
/// - Progress logging helps identify gradual leaks vs noise
pub fn assert_no_leak<F>(name: &str, iterations: usize, max_growth_bytes: usize, mut f: F)
where
    F: FnMut(),
{
    // Skip memory leak tests under coverage instrumentation.
    // Coverage adds significant memory overhead that makes leak detection unreliable.
    if is_coverage_build() {
        println!(
            "memory_{}: SKIPPED (coverage instrumentation adds overhead)",
            name
        );
        return;
    }

    println!("memory_{}: warming up (10 iterations)...", name);
    for _ in 0..10 {
        f();
    }

    // Force deallocation of any pending drops
    drop(Vec::<u8>::with_capacity(1024 * 1024));

    let Some(baseline) = get_memory_usage() else {
        println!(
            "memory_{}: SKIPPED (memory tracking not available on this platform)",
            name
        );
        return;
    };

    println!(
        "memory_{}: starting (baseline: {} KB, iterations: {}, limit: {} KB)",
        name,
        baseline / 1024,
        iterations,
        max_growth_bytes / 1024
    );

    let check_interval = std::cmp::max(iterations / 10, 1);
    for i in 0..iterations {
        black_box(f());
        if i > 0 && i % check_interval == 0 {
            if let Some(current) = get_memory_usage() {
                let growth = current.saturating_sub(baseline);
                println!(
                    "memory_{}: {}% ({}/{}), growth: {} KB",
                    name,
                    (i * 100) / iterations,
                    i,
                    iterations,
                    growth / 1024
                );
            }
        }
    }

    let final_mem = get_memory_usage().unwrap_or(baseline);
    let growth = final_mem.saturating_sub(baseline);

    println!(
        "memory_{}: final growth: {} KB (limit: {} KB)",
        name,
        growth / 1024,
        max_growth_bytes / 1024
    );

    if growth <= max_growth_bytes {
        println!("memory_{}: PASSED", name);
    } else {
        println!(
            "memory_{}: FAILED (exceeded budget by {} KB)",
            name,
            (growth - max_growth_bytes) / 1024
        );
        panic!(
            "memory_{}: grew by {} KB, exceeds limit of {} KB",
            name,
            growth / 1024,
            max_growth_bytes / 1024
        );
    }
}

/// Test fixture: sample JSON hook input
pub fn sample_hook_input(cmd: &str) -> String {
    format!(
        r#"{{"tool_name":"Bash","tool_input":{{"command":"{}"}}}}"#,
        cmd.replace('\\', r"\\").replace('"', r#"\""#)
    )
}

/// Test fixture: sample heredoc content
pub fn sample_heredoc(cmd: &str) -> String {
    format!(
        "#!/bin/bash\nset -e\n{}
echo done",
        cmd
    )
}

//=============================================================================
// Infrastructure Validation Tests
//=============================================================================

/// Verify memory tracking works on this platform
#[test]
fn memory_tracking_sanity_check() {
    println!("memory_tracking_sanity_check: starting");

    let initial = get_memory_usage();
    if initial.is_none() {
        println!("memory_tracking_sanity_check: SKIPPED (not available on this platform)");
        return;
    }

    let initial = initial.unwrap();
    println!(
        "memory_tracking_sanity_check: initial RSS = {} KB",
        initial / 1024
    );

    // Allocate 5MB and ensure pages are faulted in by writing non-zero values
    let mut data: Vec<u8> = Vec::with_capacity(5 * 1024 * 1024);
    for i in 0..5 * 1024 * 1024 {
        data.push((i % 255) as u8);
    }
    black_box(&data);

    let after_alloc = get_memory_usage().unwrap();
    let growth = after_alloc.saturating_sub(initial);

    println!(
        "memory_tracking_sanity_check: after 5MB alloc, growth = {} KB",
        growth / 1024
    );

    // Should have grown by at least 4MB (allowing for some noise/optimization)
    assert!(
        growth >= 4 * 1024 * 1024,
        "Memory tracking seems broken: only {} KB growth after 5MB allocation",
        growth / 1024
    );

    println!("memory_tracking_sanity_check: PASSED");
}

//=============================================================================
// Memory Leak Tests for DCG Hot Paths
//=============================================================================

#[test]
fn memory_hook_input_parsing() {
    let commands = [
        "git status",
        "rm -rf /tmp/test",
        "ls -la",
        "dd if=/dev/zero of=/dev/sda",
        "cargo build --release",
        "chmod -R 777 /",
    ];

    assert_no_leak("hook_input_parsing", 1000, 12 * 1024 * 1024, || {
        for cmd in &commands {
            let json = sample_hook_input(cmd);
            let _: Result<dcg::HookInput, _> = serde_json::from_str(&json);
        }
    });
}

#[test]
fn memory_pattern_evaluation() {
    let config = dcg::Config::load();
    let compiled_overrides = config.overrides.compile();
    let enabled_packs = config.enabled_pack_ids();
    let enabled_keywords = dcg::packs::REGISTRY.collect_enabled_keywords(&enabled_packs);
    let allowlists = dcg::load_default_allowlists();

    let commands = [
        "git status",
        "rm -rf build/",
        "cargo test",
        "sudo rm -rf /",
        "npm install",
    ];

    assert_no_leak("pattern_evaluation", 1000, 5 * 1024 * 1024, || {
        for cmd in &commands {
            let _ = dcg::evaluate_command(
                cmd,
                &config,
                &enabled_keywords,
                &compiled_overrides,
                &allowlists,
            );
        }
    });
}

#[test]
fn memory_heredoc_extraction() {
    let heredocs = [
        sample_heredoc("echo hello"),
        sample_heredoc("rm -rf /tmp/test && ls"),
        sample_heredoc("for i in 1 2 3; do echo $i; done"),
        "#!/usr/bin/env python3\nimport os\nos.remove('/tmp/test')".to_string(),
        "#!/bin/bash\ncat <<EOF\ninner heredoc\nEOF".to_string(),
    ];

    assert_no_leak("heredoc_extraction", 1000, 10 * 1024 * 1024, || {
        for content in &heredocs {
            let _ = dcg::heredoc::check_triggers(content);
            let _ = dcg::heredoc::ScriptLanguage::detect("cat script", content);
        }
    });
}

#[test]
fn memory_extractors() {
    const KEYWORDS: [&str; 1] = ["rm"];

    let pkg_json = r#"{"scripts":{"build":"rm -rf dist && webpack","test":"jest"}}"#;

    let terraform = r#"
resource "null_resource" "example" {
  provisioner "local-exec" {
    command = "rm -rf /tmp/test"
  }
}
"#;

    let compose = r#"
services:
  app:
    command: ["rm", "-rf", "/data"]
"#;

    let gitlab = r"
build:
  script:
    - rm -rf dist/
    - npm run build
";

    assert_no_leak("extractors", 500, 12 * 1024 * 1024, || {
        let _ = dcg::scan::extract_package_json_from_str("package.json", pkg_json, &KEYWORDS);
        let _ = dcg::scan::extract_terraform_from_str("main.tf", terraform, &KEYWORDS);
        let _ =
            dcg::scan::extract_docker_compose_from_str("docker-compose.yml", compose, &KEYWORDS);
        let _ = dcg::scan::extract_gitlab_ci_from_str(".gitlab-ci.yml", gitlab, &KEYWORDS);
    });
}

#[test]
fn memory_full_pipeline() {
    let mut config = dcg::Config::load();
    // Limit to core packs for memory leak budgets; avoids extra pack baselines.
    config.packs.enabled.clear();
    let compiled_overrides = config.overrides.compile();
    let enabled_packs = config.enabled_pack_ids();
    let enabled_keywords = dcg::packs::REGISTRY.collect_enabled_keywords(&enabled_packs);
    let allowlists = dcg::load_default_allowlists();

    let inputs = [
        sample_hook_input("git status"),
        sample_hook_input("rm -rf build/"),
        sample_hook_input("cargo build"),
    ];

    let run_inputs = || {
        for json in &inputs {
            if let Ok(input) = serde_json::from_str::<dcg::HookInput>(json) {
                if let Some(cmd) = dcg::hook::extract_command(&input) {
                    let _ = dcg::evaluate_command(
                        &cmd,
                        &config,
                        &enabled_keywords,
                        &compiled_overrides,
                        &allowlists,
                    );
                }
            }
        }
    };

    // Warm up once to avoid counting one-time regex compilation in leak checks.
    run_inputs();

    assert_no_leak("full_pipeline", 500, 2 * 1024 * 1024, || {
        run_inputs();
    });
}

#[test]
fn memory_leak_self_test() {
    if get_memory_usage().is_none() {
        println!("memory_leak_self_test: SKIPPED (memory tracking not available)");
        return;
    }

    if is_coverage_build() {
        println!("memory_leak_self_test: SKIPPED (coverage instrumentation adds overhead)");
        return;
    }

    let result = std::panic::catch_unwind(|| {
        assert_no_leak("intentional_leak", 100, 1024 * 1024, || {
            let leaked: Vec<u8> = vec![0u8; 1024 * 1024];
            std::mem::forget(leaked);
        });
    });

    assert!(
        result.is_err(),
        "CRITICAL: Memory leak detection is BROKEN - intentional leak was not caught!"
    );

    println!("memory_leak_self_test: PASSED (framework correctly detects leaks)");
}
