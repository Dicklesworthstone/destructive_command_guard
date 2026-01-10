//! Performance benchmarks for dcg hot paths.
//!
//! Run with: `cargo bench --bench heredoc_perf`
//!
//! Performance budgets are defined in `src/perf.rs`. Key thresholds:
//!
//! | Operation              | Target   | Warning  | Panic     |
//! |------------------------|----------|----------|-----------|
//! | Quick reject           | < 1μs    | < 5μs    | > 50μs    |
//! | Fast path (safe cmd)   | < 75μs   | < 150μs  | > 500μs   |
//! | Pattern match          | < 100μs  | < 250μs  | > 1ms     |
//! | Heredoc trigger        | < 5μs    | < 10μs   | > 100μs   |
//! | Heredoc extraction     | < 200μs  | < 500μs  | > 2ms     |
//! | Language detection     | < 20μs   | < 50μs   | > 200μs   |
//! | Full heredoc pipeline  | < 5ms    | < 15ms   | > 50ms    |
//!
//! See `destructive_command_guard::perf` for the canonical budget definitions.

use std::fmt::Write as _;

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use destructive_command_guard::packs::{REGISTRY, pack_aware_quick_reject};
use destructive_command_guard::{
    Config, ExtractionLimits, ScriptLanguage, check_triggers, evaluate_command_with_pack_order,
    extract_content, extract_shell_commands, matched_triggers,
};

// =============================================================================
// Benchmark Fixtures
// =============================================================================

/// Simple command without any heredoc markers.
const SIMPLE_COMMAND: &str = "git status --short";

/// Command with inline Python script.
const INLINE_PYTHON: &str = r#"python3 -c "import os; os.system('rm -rf /')" "#;

/// Command with heredoc marker.
const HEREDOC_BASH: &str = r#"bash << 'EOF'
rm -rf /
echo "done"
EOF"#;

/// Command with multiline heredoc (medium size).
fn medium_heredoc() -> String {
    let mut content = String::from("python3 << 'SCRIPT'\n");
    for i in 0..50 {
        let _ = writeln!(content, "print('line {i}')");
    }
    content.push_str("import os\nos.system('rm -rf /')\n");
    content.push_str("SCRIPT\n");
    content
}

/// Command with large heredoc (stress test).
fn large_heredoc() -> String {
    let mut content = String::from("bash << 'BIGSCRIPT'\n");
    for i in 0..500 {
        let _ = writeln!(content, "echo 'Processing item {i}'");
    }
    content.push_str("rm -rf /\n");
    content.push_str("BIGSCRIPT\n");
    content
}

/// Long command without heredoc markers (worst case for trigger check).
fn long_command_no_heredoc() -> String {
    format!("git commit -m '{}'", "x".repeat(5000))
}

/// Heredoc content for language detection benchmarks.
const PYTHON_CONTENT: &str = r"
import os
import sys

def dangerous():
    os.system('rm -rf /')

if __name__ == '__main__':
    dangerous()
";

const BASH_CONTENT: &str = r"
#!/bin/bash
set -e

rm -rf /
echo 'done'
";

const JAVASCRIPT_CONTENT: &str = r"
const { exec } = require('child_process');
exec('rm -rf /', (err) => {
    if (err) console.error(err);
});
";

// =============================================================================
// Tier 1: Trigger Check Benchmarks
// =============================================================================

fn bench_tier1_triggers(c: &mut Criterion) {
    let mut group = c.benchmark_group("tier1_triggers");

    // Budget: < 10μs
    let cases = [
        ("simple_cmd", SIMPLE_COMMAND),
        ("inline_python", INLINE_PYTHON),
        ("heredoc_bash", HEREDOC_BASH),
    ];

    for (name, cmd) in cases {
        group.bench_with_input(
            BenchmarkId::new("check_triggers", name),
            cmd,
            |b: &mut criterion::Bencher<'_>, cmd: &str| {
                b.iter(|| check_triggers(black_box(cmd)));
            },
        );
    }

    // Long command (worst case)
    let long_cmd = long_command_no_heredoc();
    group.bench_with_input(
        BenchmarkId::new("check_triggers", "long_no_heredoc"),
        &long_cmd,
        |b: &mut criterion::Bencher<'_>, cmd: &String| {
            b.iter(|| check_triggers(black_box(cmd)));
        },
    );

    // Detailed trigger matching
    for (name, cmd) in cases {
        group.bench_with_input(
            BenchmarkId::new("matched_triggers", name),
            cmd,
            |b: &mut criterion::Bencher<'_>, cmd: &str| {
                b.iter(|| matched_triggers(black_box(cmd)));
            },
        );
    }

    group.finish();
}

// =============================================================================
// Core Pipeline: pack-aware quick reject + pack evaluation
// =============================================================================

fn build_hook_inputs(config: &Config) -> HookBenchInputs {
    let enabled_packs = config.enabled_pack_ids();
    let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    let compiled_overrides = config.overrides.compile();
    let heredoc_settings = config.heredoc_settings();

    HookBenchInputs {
        enabled_keywords,
        ordered_packs,
        compiled_overrides,
        heredoc_settings,
    }
}

struct HookBenchInputs {
    enabled_keywords: Vec<&'static str>,
    ordered_packs: Vec<String>,
    compiled_overrides: destructive_command_guard::config::CompiledOverrides,
    heredoc_settings: destructive_command_guard::config::HeredocSettings,
}

fn bench_pack_aware_quick_reject(c: &mut Criterion) {
    let mut group = c.benchmark_group("pack_aware_quick_reject");

    let mut core_only = Config::default();
    core_only.heredoc.enabled = Some(false);
    let core_inputs = build_hook_inputs(&core_only);

    let mut worst_case = Config::default();
    worst_case.heredoc.enabled = Some(false);
    worst_case.packs.enabled = vec![
        "database".to_string(),
        "containers".to_string(),
        "kubernetes".to_string(),
        "cloud".to_string(),
        "infrastructure".to_string(),
        "system".to_string(),
        "strict_git".to_string(),
        "package_managers".to_string(),
        "cicd".to_string(),
    ];
    let worst_inputs = build_hook_inputs(&worst_case);

    let cases = [
        ("no_match", SIMPLE_COMMAND),
        ("match_git", "git status --short"),
    ];

    for (name, cmd) in cases {
        group.bench_with_input(
            BenchmarkId::new("core_only", name),
            cmd,
            |b: &mut criterion::Bencher<'_>, cmd: &str| {
                b.iter(|| {
                    black_box(pack_aware_quick_reject(
                        black_box(cmd),
                        black_box(core_inputs.enabled_keywords.as_slice()),
                    ))
                });
            },
        );
    }

    for (name, cmd) in cases {
        group.bench_with_input(
            BenchmarkId::new("worst_case", name),
            cmd,
            |b: &mut criterion::Bencher<'_>, cmd: &str| {
                b.iter(|| {
                    black_box(pack_aware_quick_reject(
                        black_box(cmd),
                        black_box(worst_inputs.enabled_keywords.as_slice()),
                    ))
                });
            },
        );
    }

    group.finish();
}

fn bench_core_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("core_pipeline");

    // Keep allowlists empty for deterministic, IO-free benchmarks.
    let allowlists = destructive_command_guard::LayeredAllowlist::default();

    let mut core_only = Config::default();
    core_only.heredoc.enabled = Some(false);
    let core_inputs = build_hook_inputs(&core_only);

    let mut docker_enabled = Config::default();
    docker_enabled.heredoc.enabled = Some(false);
    docker_enabled
        .packs
        .enabled
        .push("containers.docker".to_string());
    let docker_inputs = build_hook_inputs(&docker_enabled);

    let mut worst_case = Config::default();
    worst_case.heredoc.enabled = Some(false);
    worst_case.packs.enabled = vec![
        "database".to_string(),
        "containers".to_string(),
        "kubernetes".to_string(),
        "cloud".to_string(),
        "infrastructure".to_string(),
        "system".to_string(),
        "strict_git".to_string(),
        "package_managers".to_string(),
        "cicd".to_string(),
    ];
    let worst_inputs = build_hook_inputs(&worst_case);

    let core_cases = [
        ("allow_quick_reject", SIMPLE_COMMAND),
        ("allow_git_safe", "git status --short"),
        ("deny_git_reset_hard", "git reset --hard"),
        ("deny_rm_rf", "rm -rf ./build"),
    ];

    for (name, cmd) in core_cases {
        group.bench_with_input(
            BenchmarkId::new("core_only", name),
            cmd,
            |b: &mut criterion::Bencher<'_>, cmd: &str| {
                b.iter(|| {
                    let result = evaluate_command_with_pack_order(
                        black_box(cmd),
                        black_box(core_inputs.enabled_keywords.as_slice()),
                        black_box(core_inputs.ordered_packs.as_slice()),
                        black_box(&core_inputs.compiled_overrides),
                        black_box(&allowlists),
                        black_box(&core_inputs.heredoc_settings),
                    );
                    black_box(result);
                });
            },
        );
    }

    let docker_cases = [
        ("allow_docker_ps", "docker ps"),
        ("deny_docker_prune", "docker system prune"),
    ];
    for (name, cmd) in docker_cases {
        group.bench_with_input(
            BenchmarkId::new("docker_enabled", name),
            cmd,
            |b: &mut criterion::Bencher<'_>, cmd: &str| {
                b.iter(|| {
                    let result = evaluate_command_with_pack_order(
                        black_box(cmd),
                        black_box(docker_inputs.enabled_keywords.as_slice()),
                        black_box(docker_inputs.ordered_packs.as_slice()),
                        black_box(&docker_inputs.compiled_overrides),
                        black_box(&allowlists),
                        black_box(&docker_inputs.heredoc_settings),
                    );
                    black_box(result);
                });
            },
        );
    }

    let worst_cases = [
        ("allow_quick_reject", SIMPLE_COMMAND),
        ("deny_kubectl_delete_ns", "kubectl delete namespace test"),
        ("deny_terraform_destroy", "terraform destroy"),
    ];
    for (name, cmd) in worst_cases {
        group.bench_with_input(
            BenchmarkId::new("worst_case", name),
            cmd,
            |b: &mut criterion::Bencher<'_>, cmd: &str| {
                b.iter(|| {
                    let result = evaluate_command_with_pack_order(
                        black_box(cmd),
                        black_box(worst_inputs.enabled_keywords.as_slice()),
                        black_box(worst_inputs.ordered_packs.as_slice()),
                        black_box(&worst_inputs.compiled_overrides),
                        black_box(&allowlists),
                        black_box(&worst_inputs.heredoc_settings),
                    );
                    black_box(result);
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// Tier 2: Heredoc Extraction Benchmarks
// =============================================================================

fn bench_tier2_extraction(c: &mut Criterion) {
    let mut group = c.benchmark_group("tier2_extraction");

    // Budget: < 500μs
    let limits = ExtractionLimits::default();

    let cases: Vec<(&str, String)> = vec![
        ("simple_heredoc", HEREDOC_BASH.to_string()),
        ("medium_heredoc", medium_heredoc()),
        ("large_heredoc", large_heredoc()),
    ];

    for (name, cmd) in &cases {
        group.bench_with_input(
            BenchmarkId::new("extract_content", name),
            cmd,
            |b: &mut criterion::Bencher<'_>, cmd: &String| {
                b.iter(|| extract_content(black_box(cmd), black_box(&limits)));
            },
        );
    }

    // Test with restricted limits (fail-fast)
    let strict_limits = ExtractionLimits {
        timeout_ms: 10,
        max_body_bytes: 1024,
        max_body_lines: 50,
        max_heredocs: 2,
    };

    group.bench_with_input(
        BenchmarkId::new("extract_content_strict", "large_heredoc"),
        &cases[2].1,
        |b: &mut criterion::Bencher<'_>, cmd: &String| {
            b.iter(|| extract_content(black_box(cmd), black_box(&strict_limits)));
        },
    );

    group.finish();
}

// =============================================================================
// Tier 2b: Shell Command Extraction
// =============================================================================

fn bench_shell_extraction(c: &mut Criterion) {
    let mut group = c.benchmark_group("shell_extraction");

    let cases = [
        ("python_content", PYTHON_CONTENT),
        ("bash_content", BASH_CONTENT),
        ("javascript_content", JAVASCRIPT_CONTENT),
    ];

    for (name, content) in cases {
        group.bench_with_input(
            BenchmarkId::new("extract_shell_commands", name),
            content,
            |b: &mut criterion::Bencher<'_>, content: &str| {
                b.iter(|| extract_shell_commands(black_box(content)));
            },
        );
    }

    group.finish();
}

// =============================================================================
// Tier 3: Language Detection Benchmarks
// =============================================================================

fn bench_language_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("language_detection");

    // Budget: < 50μs
    let cases = [
        (
            "python_shebang",
            "python3 << EOF",
            "#!/usr/bin/env python3\nimport os",
        ),
        ("bash_shebang", "bash << EOF", "#!/bin/bash\nset -e"),
        (
            "no_shebang_python",
            "python3 << EOF",
            "import os\nos.system('rm')",
        ),
        ("no_shebang_bash", "bash << EOF", "rm -rf /\necho done"),
        (
            "ambiguous",
            "cat << EOF",
            "some random content\nwith no hints",
        ),
    ];

    for (name, cmd, content) in cases {
        group.bench_with_input(
            BenchmarkId::new("detect_language", name),
            &(cmd, content),
            |b: &mut criterion::Bencher<'_>, (cmd, content): &(&str, &str)| {
                b.iter(|| ScriptLanguage::detect(black_box(*cmd), black_box(*content)));
            },
        );
    }

    group.finish();
}

// =============================================================================
// Full Pipeline Benchmarks
// =============================================================================

fn bench_full_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_pipeline");

    // Budget: < 15ms
    //
    // Use the same precomputed inputs as hook mode (no config file IO).
    let allowlists = destructive_command_guard::LayeredAllowlist::default();

    let mut config = Config::default();
    config.packs.enabled = vec![
        "database".to_string(),
        "containers".to_string(),
        "kubernetes".to_string(),
        "cloud".to_string(),
        "infrastructure".to_string(),
        "system".to_string(),
        "strict_git".to_string(),
        "package_managers".to_string(),
        "cicd".to_string(),
    ];
    let hook_inputs = build_hook_inputs(&config);

    let cases: Vec<(&str, String)> = vec![
        ("safe_git", "git status".to_string()),
        ("dangerous_git", "git reset --hard".to_string()),
        ("simple_heredoc", HEREDOC_BASH.to_string()),
        ("inline_python", INLINE_PYTHON.to_string()),
        ("medium_heredoc", medium_heredoc()),
    ];

    for (name, cmd) in &cases {
        group.bench_with_input(
            BenchmarkId::new("evaluate_command", name),
            cmd,
            |b: &mut criterion::Bencher<'_>, cmd: &String| {
                b.iter(|| {
                    evaluate_command_with_pack_order(
                        black_box(cmd),
                        black_box(hook_inputs.enabled_keywords.as_slice()),
                        black_box(hook_inputs.ordered_packs.as_slice()),
                        black_box(&hook_inputs.compiled_overrides),
                        black_box(&allowlists),
                        black_box(&hook_inputs.heredoc_settings),
                    )
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// Criterion Setup
// =============================================================================

criterion_group!(
    benches,
    bench_tier1_triggers,
    bench_pack_aware_quick_reject,
    bench_core_pipeline,
    bench_tier2_extraction,
    bench_shell_extraction,
    bench_language_detection,
    bench_full_pipeline,
);

criterion_main!(benches);
