//! Memory leak detection tests for DCG
//!
//! These tests verify that DCG's hot paths don't leak memory
//! when processing many inputs. Critical because DCG runs on
//! every Bash command in Claude Code sessions.
//!
//! RSS measurements are serialized internally so the suite remains stable even
//! when Cargo runs tests with multiple harness threads.
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
use std::cell::Cell;
use std::hint::black_box;
use std::sync::{Mutex, MutexGuard, PoisonError};

static MEMORY_TEST_LOCK: Mutex<()> = Mutex::new(());
const WARMUP_ITERATIONS: usize = 100;

thread_local! {
    static MEMORY_TEST_LOCK_HELD: Cell<bool> = const { Cell::new(false) };
}

struct MemoryTestLockGuard {
    guard: Option<MutexGuard<'static, ()>>,
}

impl Drop for MemoryTestLockGuard {
    fn drop(&mut self) {
        if self.guard.is_some() {
            MEMORY_TEST_LOCK_HELD.with(|held| held.set(false));
        }
    }
}

fn memory_test_guard() -> MemoryTestLockGuard {
    if MEMORY_TEST_LOCK_HELD.with(Cell::get) {
        return MemoryTestLockGuard { guard: None };
    }

    let guard = MEMORY_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    MEMORY_TEST_LOCK_HELD.with(|held| held.set(true));
    MemoryTestLockGuard { guard: Some(guard) }
}

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
/// 1. Warms up before measurement (triggers lazy initialization and caches)
/// 2. Measures baseline memory
/// 3. Runs iterations with periodic progress logging
/// 4. Asserts final growth is within budget
///
/// # Flakiness Mitigation
/// - Generous budgets (1-2MB) accommodate measurement noise
/// - Warm-up phase triggers lazy initialization and formatting caches
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

    let _guard = memory_test_guard();

    let warmup_iterations = iterations.min(WARMUP_ITERATIONS);
    println!(
        "memory_{}: warming up ({} iterations)...",
        name, warmup_iterations
    );
    for _ in 0..warmup_iterations {
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

    let _guard = memory_test_guard();

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
    let _guard = memory_test_guard();
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
    let _guard = memory_test_guard();
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
    let _guard = memory_test_guard();
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
    let _guard = memory_test_guard();
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
    let _guard = memory_test_guard();
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

//=============================================================================
// Codex Protocol Memory Tests (ovw4.6.3)
//
// The Codex deny path emits a minimal JSON decision and returns normally.
// These tests exercise the Codex-specific code paths in-process to verify
// no allocations leak across repeated invocations of the protocol detection,
// evaluation, and output formatting pipeline.
//=============================================================================

/// Build a Codex-format hook input JSON string (includes turn_id).
fn sample_codex_input(cmd: &str) -> String {
    format!(
        r#"{{"tool_name":"Bash","tool_input":{{"command":"{}"}},"turn_id":"test-turn-0001"}}"#,
        cmd.replace('\\', r"\\").replace('"', r#"\""#)
    )
}

/// Build a Claude-format hook input JSON string (no turn_id).
fn sample_claude_input(cmd: &str) -> String {
    sample_hook_input(cmd)
}

#[test]
fn memory_codex_protocol_detection() {
    let _guard = memory_test_guard();
    let codex_inputs: Vec<String> = [
        "git reset --hard HEAD~3",
        "rm -rf /",
        "chmod 777 /etc/passwd",
        "dd if=/dev/zero of=/dev/sda",
        "ls -la",
        "cargo build",
    ]
    .iter()
    .map(|cmd| sample_codex_input(cmd))
    .collect();

    let claude_inputs: Vec<String> = ["git reset --hard HEAD~3", "rm -rf /", "ls -la"]
        .iter()
        .map(|cmd| sample_claude_input(cmd))
        .collect();

    assert_no_leak("codex_protocol_detection", 1000, 2 * 1024 * 1024, || {
        for json in &codex_inputs {
            if let Ok(input) = serde_json::from_str::<dcg::HookInput>(json) {
                let proto = dcg::hook::detect_protocol(&input);
                black_box(proto);
            }
        }
        for json in &claude_inputs {
            if let Ok(input) = serde_json::from_str::<dcg::HookInput>(json) {
                let proto = dcg::hook::detect_protocol(&input);
                black_box(proto);
            }
        }
    });
}

#[test]
fn memory_codex_deny_pipeline() {
    let _guard = memory_test_guard();
    let mut config = dcg::Config::load();
    config.packs.enabled.clear();
    let compiled_overrides = config.overrides.compile();
    let enabled_packs = config.enabled_pack_ids();
    let enabled_keywords = dcg::packs::REGISTRY.collect_enabled_keywords(&enabled_packs);
    let allowlists = dcg::load_default_allowlists();

    let destructive_cmds = ["git reset --hard HEAD~3", "rm -rf build/", "sudo rm -rf /"];

    let codex_inputs: Vec<String> = destructive_cmds
        .iter()
        .map(|cmd| sample_codex_input(cmd))
        .collect();

    let run_codex_pipeline = || {
        for json in &codex_inputs {
            if let Ok(input) = serde_json::from_str::<dcg::HookInput>(json) {
                let protocol = dcg::hook::detect_protocol(&input);
                if let Some((cmd, _)) = dcg::hook::extract_command_with_protocol(&input) {
                    let result = dcg::evaluate_command(
                        &cmd,
                        &config,
                        &enabled_keywords,
                        &compiled_overrides,
                        &allowlists,
                    );
                    if result.is_denied() {
                        let pi = result.pattern_info.as_ref();
                        let mut stdout_buf = Vec::with_capacity(4096);
                        let mut stderr_buf = Vec::with_capacity(4096);
                        dcg::hook::write_denial_to(
                            &mut stdout_buf,
                            &mut stderr_buf,
                            protocol,
                            &cmd,
                            result.reason().unwrap_or("blocked"),
                            result.pack_id(),
                            pi.and_then(|p| p.pattern_name.as_deref()),
                            pi.and_then(|p| p.explanation.as_deref()),
                            None,
                            pi.and_then(|p| p.matched_span.as_ref()),
                            pi.and_then(|p| p.severity),
                            None,
                            pi.map_or(&[], |p| p.suggestions),
                            None,
                        );
                        black_box(&stdout_buf);
                        black_box(&stderr_buf);
                    }
                }
            }
        }
    };

    run_codex_pipeline();

    assert_no_leak("codex_deny_pipeline", 500, 2 * 1024 * 1024, || {
        run_codex_pipeline();
    });
}

#[test]
fn memory_codex_deny_output_formatting() {
    let _guard = memory_test_guard();
    let allow_once = dcg::hook::AllowOnceInfo {
        code: "abc12".to_string(),
        full_hash: "deadbeef1234567890".to_string(),
    };

    assert_no_leak(
        "codex_deny_output_formatting",
        1000,
        2 * 1024 * 1024,
        || {
            let mut stdout_buf = Vec::with_capacity(4096);
            let mut stderr_buf = Vec::with_capacity(4096);

            dcg::hook::write_denial_to(
                &mut stdout_buf,
                &mut stderr_buf,
                dcg::hook::HookProtocol::Codex,
                "git reset --hard HEAD~3",
                "Destructive git operation",
                Some("core.git"),
                Some("git_reset_hard"),
                Some("Use git stash or create a backup branch first"),
                Some(&allow_once),
                None,
                Some(dcg::packs::Severity::Critical),
                Some(0.95),
                &[],
                None,
            );
            black_box(&stdout_buf);
            black_box(&stderr_buf);

            // Codex path: stdout is a minimal JSON denial, stderr has the
            // human-readable message.
            let json: serde_json::Value =
                serde_json::from_slice(&stdout_buf).expect("Codex deny stdout should be JSON");
            let specific = json["hookSpecificOutput"]
                .as_object()
                .expect("Codex hookSpecificOutput object");
            debug_assert_eq!(specific.len(), 3);
            debug_assert_eq!(specific["permissionDecision"], "deny");

            stdout_buf.clear();
            stderr_buf.clear();
        },
    );
}

#[test]
fn memory_codex_vs_claude_deny_parity() {
    let _guard = memory_test_guard();
    let mut config = dcg::Config::load();
    config.packs.enabled.clear();
    let compiled_overrides = config.overrides.compile();
    let enabled_packs = config.enabled_pack_ids();
    let enabled_keywords = dcg::packs::REGISTRY.collect_enabled_keywords(&enabled_packs);
    let allowlists = dcg::load_default_allowlists();

    let cmd = "git reset --hard HEAD~3";
    let codex_json = sample_codex_input(cmd);
    let claude_json = sample_claude_input(cmd);

    let run_both = || {
        for (json, expected_proto_is_codex) in [(&codex_json, true), (&claude_json, false)] {
            if let Ok(input) = serde_json::from_str::<dcg::HookInput>(json) {
                let protocol = dcg::hook::detect_protocol(&input);
                if expected_proto_is_codex {
                    debug_assert!(
                        matches!(protocol, dcg::hook::HookProtocol::Codex),
                        "turn_id input should detect as Codex"
                    );
                }
                if let Some((extracted, _)) = dcg::hook::extract_command_with_protocol(&input) {
                    let result = dcg::evaluate_command(
                        &extracted,
                        &config,
                        &enabled_keywords,
                        &compiled_overrides,
                        &allowlists,
                    );
                    if result.is_denied() {
                        let pi = result.pattern_info.as_ref();
                        let mut stdout_buf = Vec::with_capacity(4096);
                        let mut stderr_buf = Vec::with_capacity(4096);
                        dcg::hook::write_denial_to(
                            &mut stdout_buf,
                            &mut stderr_buf,
                            protocol,
                            &extracted,
                            result.reason().unwrap_or("blocked"),
                            result.pack_id(),
                            pi.and_then(|p| p.pattern_name.as_deref()),
                            pi.and_then(|p| p.explanation.as_deref()),
                            None,
                            pi.and_then(|p| p.matched_span.as_ref()),
                            pi.and_then(|p| p.severity),
                            None,
                            pi.map_or(&[], |p| p.suggestions),
                            None,
                        );
                        black_box(&stdout_buf);
                        black_box(&stderr_buf);
                    }
                }
            }
        }
    };

    run_both();

    assert_no_leak("codex_vs_claude_deny_parity", 500, 2 * 1024 * 1024, || {
        run_both();
    });
}

#[test]
fn memory_codex_subprocess_deny_loop() {
    if is_coverage_build() {
        println!("memory_codex_subprocess_deny_loop: SKIPPED (coverage build)");
        return;
    }

    let _guard = memory_test_guard();

    let dcg_bin = std::path::PathBuf::from(env!("CARGO_BIN_EXE_dcg"));
    if !dcg_bin.exists() {
        println!("memory_codex_subprocess_deny_loop: SKIPPED (dcg binary not found)");
        return;
    }

    let codex_payload = sample_codex_input("git reset --hard HEAD~3");
    let iterations = 50;
    let warmup_iterations = 5;
    let home_dir = tempfile::TempDir::new().expect("create isolated HOME for dcg subprocesses");

    println!(
        "memory_codex_subprocess_deny_loop: warming up ({} subprocesses)",
        warmup_iterations
    );
    for _ in 0..warmup_iterations {
        run_codex_deny_subprocess(&dcg_bin, &codex_payload, home_dir.path());
    }

    let Some(baseline) = get_memory_usage() else {
        println!("memory_codex_subprocess_deny_loop: SKIPPED (no memory tracking)");
        return;
    };

    println!(
        "memory_codex_subprocess_deny_loop: spawning {} dcg subprocesses (baseline: {} KB)",
        iterations,
        baseline / 1024
    );

    for i in 0..iterations {
        run_codex_deny_subprocess(&dcg_bin, &codex_payload, home_dir.path());

        if i > 0 && i % 10 == 0 {
            if let Some(current) = get_memory_usage() {
                let growth = current.saturating_sub(baseline);
                println!(
                    "memory_codex_subprocess_deny_loop: {}/{}, parent growth: {} KB",
                    i,
                    iterations,
                    growth / 1024
                );
            }
        }
    }

    let final_mem = get_memory_usage().unwrap_or(baseline);
    let growth = final_mem.saturating_sub(baseline);
    let max_growth = 2 * 1024 * 1024;

    println!(
        "memory_codex_subprocess_deny_loop: final parent growth: {} KB (limit: {} KB)",
        growth / 1024,
        max_growth / 1024
    );

    assert!(
        growth <= max_growth,
        "Parent process grew by {} KB after {} subprocess spawns (limit: {} KB) — \
         possible fd or buffer leak in subprocess management",
        growth / 1024,
        iterations,
        max_growth / 1024
    );

    println!("memory_codex_subprocess_deny_loop: PASSED");
}

fn run_codex_deny_subprocess(
    dcg_bin: &std::path::Path,
    codex_payload: &str,
    home_dir: &std::path::Path,
) {
    let mut child = std::process::Command::new(dcg_bin)
        .env_clear()
        .env("HOME", home_dir)
        .env("USERPROFILE", home_dir)
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("NO_COLOR", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn dcg");

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(codex_payload.as_bytes());
    }

    let output = child.wait_with_output().expect("wait dcg");
    assert_eq!(
        output.status.code(),
        Some(0),
        "Codex deny should exit normally"
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "Codex deny stdout should be JSON: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn memory_leak_self_test() {
    let _guard = memory_test_guard();
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
            const LEAK_BYTES: usize = 64 * 1024;

            // Touch non-zero pages so optimized Linux builds show the leak in RSS.
            let mut leaked = vec![0xA5u8; LEAK_BYTES].into_boxed_slice();
            for byte in leaked.iter_mut().step_by(4096) {
                *byte = (*byte).wrapping_add(1u8);
            }
            black_box(Box::leak(leaked).as_mut_ptr());
        });
    });

    assert!(
        result.is_err(),
        "CRITICAL: Memory leak detection is BROKEN - intentional leak was not caught!"
    );

    println!("memory_leak_self_test: PASSED (framework correctly detects leaks)");
}
