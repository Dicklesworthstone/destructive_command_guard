//! Hook-mode latency benchmarks.
//!
//! Measures evaluate_command latency across safe, denied, and unrelated commands
//! to ensure hook mode stays under 50ms p99 for agent responsiveness.
//!
//! Run with: `cargo bench --bench hook_latency`

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, EvaluationDecision, LayeredAllowlist};

struct EvalContext {
    enabled_keywords: Vec<&'static str>,
    ordered_packs: Vec<String>,
    keyword_index: Option<destructive_command_guard::packs::EnabledKeywordIndex>,
    compiled_overrides: destructive_command_guard::config::CompiledOverrides,
    heredoc_settings: destructive_command_guard::config::HeredocSettings,
    allowlists: LayeredAllowlist,
}

impl EvalContext {
    fn new() -> Self {
        let mut config = Config::default();
        config.heredoc.enabled = Some(false);
        config.packs.enabled = vec![
            "core".to_string(),
            "database.postgresql".to_string(),
            "containers.docker".to_string(),
            "kubernetes".to_string(),
        ];

        let enabled_packs = config.enabled_pack_ids();
        let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
        Self {
            enabled_keywords: REGISTRY.collect_enabled_keywords(&enabled_packs),
            keyword_index: REGISTRY.build_enabled_keyword_index(&ordered_packs),
            ordered_packs,
            compiled_overrides: config.overrides.compile(),
            heredoc_settings: config.heredoc_settings(),
            allowlists: LayeredAllowlist::default(),
        }
    }

    fn evaluate(&self, command: &str) -> destructive_command_guard::EvaluationResult {
        destructive_command_guard::evaluate_command_with_pack_order(
            command,
            self.enabled_keywords.as_slice(),
            self.ordered_packs.as_slice(),
            self.keyword_index.as_ref(),
            &self.compiled_overrides,
            &self.allowlists,
            &self.heredoc_settings,
        )
    }
}

fn bench_evaluate_command(c: &mut Criterion) {
    let ctx = EvalContext::new();

    let commands: &[(&str, &str, EvaluationDecision)] = &[
        ("safe_echo", "echo hello world", EvaluationDecision::Allow),
        ("safe_ls", "ls -la /tmp", EvaluationDecision::Allow),
        ("safe_git_status", "git status", EvaluationDecision::Allow),
        (
            "safe_git_log",
            "git log --oneline -10",
            EvaluationDecision::Allow,
        ),
        (
            "denied_rm_rf",
            "rm -rf /important/data",
            EvaluationDecision::Deny,
        ),
        (
            "denied_git_force_push",
            "git push --force origin main",
            EvaluationDecision::Deny,
        ),
        (
            "denied_drop_database",
            "dropdb production",
            EvaluationDecision::Deny,
        ),
        (
            "denied_docker_system_prune",
            "docker system prune -af",
            EvaluationDecision::Deny,
        ),
        (
            "denied_kubectl_delete_ns",
            "kubectl delete namespace production",
            EvaluationDecision::Deny,
        ),
        (
            "unrelated_cargo_build",
            "cargo build --release",
            EvaluationDecision::Allow,
        ),
        (
            "unrelated_python",
            "python3 -m pytest tests/",
            EvaluationDecision::Allow,
        ),
        ("unrelated_npm", "npm run build", EvaluationDecision::Allow),
    ];

    let mut group = c.benchmark_group("evaluate_command");
    group.measurement_time(std::time::Duration::from_secs(5));

    for (name, cmd, expected_decision) in commands {
        let result = ctx.evaluate(cmd);
        assert_eq!(
            &result.decision, expected_decision,
            "pre-check failed for {name}: {cmd}"
        );

        group.bench_with_input(BenchmarkId::new("latency", name), cmd, |b, cmd| {
            b.iter(|| ctx.evaluate(black_box(cmd)));
        });
    }

    group.finish();
}

fn bench_long_command(c: &mut Criterion) {
    let ctx = EvalContext::new();

    let long_safe = format!("echo {}", "hello ".repeat(200));
    let long_denied = format!("rm -rf /tmp/dir && {}", "echo ok && ".repeat(100));

    let mut group = c.benchmark_group("long_command");
    group.measurement_time(std::time::Duration::from_secs(5));

    group.bench_function("long_safe_1200_chars", |b| {
        b.iter(|| ctx.evaluate(black_box(&long_safe)));
    });

    group.bench_function("long_denied_compound", |b| {
        b.iter(|| ctx.evaluate(black_box(&long_denied)));
    });

    group.finish();
}

fn bench_issue_555(c: &mut Criterion) {
    let mut ctx = EvalContext::new();
    ctx.heredoc_settings = Config::default().heredoc_settings();
    let mut group = c.benchmark_group("issue_555");
    for lines in [1, 40, 300] {
        let body = "print('ordinary data')\n".repeat(lines);
        for (name, command, expected) in [
            (
                "python",
                format!("python3 - <<'EOF'\n{body}EOF"),
                EvaluationDecision::Allow,
            ),
            (
                "quoted_data",
                format!("cat <<'EOF'\n{body}rm -rf /\nEOF"),
                EvaluationDecision::Allow,
            ),
            (
                "python_deny",
                format!("python3 - <<'EOF'\n{body}import shutil\nshutil.rmtree('/tmp')\nEOF"),
                EvaluationDecision::Deny,
            ),
        ] {
            assert_eq!(ctx.evaluate(&command).decision, expected, "{name}/{lines}");
            group.bench_with_input(BenchmarkId::new(name, lines), &command, |b, cmd| {
                b.iter(|| ctx.evaluate(black_box(cmd)));
            });
        }
    }
    let compound = "cd project && git status --short | head && grep -rn foo src | wc -l";
    assert_eq!(ctx.evaluate(compound).decision, EvaluationDecision::Allow);
    group.bench_function("compound", |b| b.iter(|| ctx.evaluate(black_box(compound))));
    group.finish();
}

/// Warm evaluator work for #647, including the independent byte/statement
/// limits and quoted .NET-looking data. Cold hook deadlines are measured by
/// the real-binary latency harness; this group deliberately has no deadline so
/// a timeout cannot make an expensive input look fast by skipping its work.
fn bench_issue_647(c: &mut Criterion) {
    use destructive_command_guard::normalize::ShellDialect;

    let mut config = Config::default();
    config.packs.enabled = vec!["core".to_string(), "windows.filesystem".to_string()];
    let enabled = config.enabled_pack_ids();
    let ordered = REGISTRY.expand_enabled_ordered(&enabled);
    let keywords = REGISTRY.collect_enabled_keywords(&enabled);
    let index = REGISTRY.build_enabled_keyword_index(&ordered);
    let overrides = config.overrides.compile();
    let allowlists = LayeredAllowlist::default();
    let heredoc = config.heredoc_settings();
    let evaluate = |command: &str| {
        destructive_command_guard::evaluator::evaluate_command_with_pack_order_deadline_at_path_in_dialect(
            command,
            &keywords,
            &ordered,
            index.as_ref(),
            &overrides,
            &allowlists,
            &heredoc,
            None,
            None,
            None,
            ShellDialect::PowerShell,
        )
    };

    let mut cases = Vec::new();
    for count in [300, 512, 513] {
        cases.push((
            format!("quoted_rm_{count}"),
            vec!["Write-Output 'rm x'"; count].join("; "),
            if count <= 512 {
                EvaluationDecision::Allow
            } else {
                EvaluationDecision::Indeterminate
            },
        ));
    }
    cases.push((
        "destructive_statement_512".to_string(),
        format!(
            "{}Remove-Item C:\\important -Recurse -Force",
            "Write-Output 'rm x'; ".repeat(511),
        ),
        EvaluationDecision::Deny,
    ));
    cases.push((
        "quoted_dotnet_512".to_string(),
        vec!["Write-Output '$directory.Delete($true); rm x'"; 512].join("; "),
        EvaluationDecision::Allow,
    ));
    // Many words force the intact-command prepasses to inspect the full
    // 64 KiB input; a single quoted padding word would not exercise that cost.
    let dense = format!("Write-Output {}rm", "x ".repeat((64 * 1024 - 15) / 2));
    assert_eq!(dense.len(), 64 * 1024 - 1);
    cases.push((
        "dense_words_near_byte_bound".to_string(),
        dense.clone(),
        EvaluationDecision::Allow,
    ));
    cases.push((
        "over_byte_bound".to_string(),
        format!("{dense} xx"),
        EvaluationDecision::Indeterminate,
    ));
    // The .NET necessary-literal guard rejects the dense case above cheaply.
    // Retain a guard-positive worst case: a quoted member call at the end
    // still exercises the suffix scans. Its active counterpart must deny.
    let prefix = "Write-Output ";
    for (name, tail, expected) in [
        (
            "dense_words_with_quoted_dotnet",
            "'$directory.Delete($true)'",
            EvaluationDecision::Allow,
        ),
        (
            "dense_words_with_active_dotnet",
            "; $directory.Delete($true)",
            EvaluationDecision::Deny,
        ),
    ] {
        let command = format!(
            "{prefix}{}{tail}",
            "x ".repeat((64 * 1024 - prefix.len() - tail.len()) / 2),
        );
        assert!((64 * 1024 - 1..=64 * 1024).contains(&command.len()));
        cases.push((name.to_string(), command, expected));
    }

    let mut group = c.benchmark_group("issue_647");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(3));
    for (name, command, expected) in cases {
        assert_eq!(evaluate(&command).decision, expected, "pre-check: {name}");
        group.bench_function(&name, |b| {
            b.iter(|| {
                let result = evaluate(black_box(&command));
                assert_eq!(result.decision, expected, "timed verdict: {name}");
                black_box(result)
            });
        });
    }
    group.finish();
}

fn bench_keyword_rejection(c: &mut Criterion) {
    let ctx = EvalContext::new();

    let no_keyword_commands = &[
        "cargo test --release",
        "python3 manage.py runserver",
        "node server.js",
        "make -j8",
        "gcc -o main main.c",
    ];

    let mut group = c.benchmark_group("keyword_rejection");
    group.measurement_time(std::time::Duration::from_secs(5));

    for cmd in no_keyword_commands {
        let result = ctx.evaluate(cmd);
        assert_eq!(result.decision, EvaluationDecision::Allow);

        group.bench_with_input(
            BenchmarkId::new("fast_reject", cmd.split_whitespace().next().unwrap()),
            cmd,
            |b, cmd| {
                b.iter(|| ctx.evaluate(black_box(cmd)));
            },
        );
    }

    group.finish();
}

fn bench_throughput(c: &mut Criterion) {
    let ctx = EvalContext::new();

    let mixed_commands = vec![
        "echo hello",
        "ls -la",
        "git status",
        "rm -rf /data",
        "git push --force origin main",
        "cargo build",
        "docker ps",
        "kubectl get pods",
        "psql -c 'SELECT 1'",
        "npm install express",
    ];

    c.bench_function("throughput_10_mixed_commands", |b| {
        b.iter(|| {
            for cmd in &mixed_commands {
                black_box(ctx.evaluate(black_box(cmd)));
            }
        });
    });
}

criterion_group!(
    benches,
    bench_evaluate_command,
    bench_long_command,
    bench_issue_555,
    bench_issue_647,
    bench_keyword_rejection,
    bench_throughput
);
criterion_main!(benches);
