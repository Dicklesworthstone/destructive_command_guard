//! Benchmark comparing regex crate vs regex-automata for dcg patterns.
//!
//! This is part of task ksk.8.1: Feasibility + prototype for regex-automata.
//!
//! Run with: cargo bench --bench `regex_automata_comparison`

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use regex::Regex;
use regex_automata::{Input, meta::Regex as MetaRegex};
use std::hint::black_box;
use std::time::Duration;

/// Representative patterns from dcg packs (from most common to least common)
const TEST_PATTERNS: &[(&str, &str)] = &[
    // Simple patterns (linear engine in current impl)
    ("git-reset-hard", r"git\s+(?:\S+\s+)*reset\s+--hard"),
    ("git-clean-force", r"git\s+(?:\S+\s+)*clean\s+-[a-zA-Z]*f"),
    ("git-push-force", r"git\s+(?:\S+\s+)*push\s+.*--force"),
    (
        "rm-rf",
        r"rm\s+-[a-zA-Z]*r[a-zA-Z]*f|rm\s+-[a-zA-Z]*f[a-zA-Z]*r",
    ),
    (
        "docker-prune",
        r"docker\s+(?:system|volume|image|container)\s+prune",
    ),
    ("kubectl-delete", r"kubectl\s+delete\s+(?:namespace|ns)\s+"),
    ("drop-table", r"(?i)DROP\s+TABLE\s+"),
    ("truncate", r"(?i)TRUNCATE\s+(?:TABLE\s+)?"),
];

/// Test commands (mix of matching and non-matching)
const TEST_COMMANDS: &[&str] = &[
    // Matching commands
    "git reset --hard HEAD~5",
    "git clean -fd",
    "git push origin main --force",
    "rm -rf /var/log/old",
    "docker system prune -af",
    "kubectl delete namespace production",
    "DROP TABLE users;",
    "TRUNCATE TABLE sessions;",
    // Non-matching commands (should be fast-rejected)
    "git status",
    "git log --oneline",
    "ls -la",
    "cat /etc/passwd",
    "echo hello world",
    "docker ps",
    "kubectl get pods",
    "SELECT * FROM users;",
];

/// Benchmark regex compilation time
fn bench_compilation(c: &mut Criterion) {
    let mut group = c.benchmark_group("compilation");
    group.measurement_time(Duration::from_secs(5));

    for (name, pattern) in TEST_PATTERNS {
        group.bench_with_input(BenchmarkId::new("regex", name), pattern, |b, pat| {
            b.iter(|| Regex::new(black_box(pat)).unwrap());
        });

        group.bench_with_input(
            BenchmarkId::new("regex-automata", name),
            pattern,
            |b, pat| {
                b.iter(|| MetaRegex::new(black_box(pat)).unwrap());
            },
        );
    }

    group.finish();
}

/// Benchmark single pattern matching
fn bench_single_match(c: &mut Criterion) {
    let mut group = c.benchmark_group("single_match");
    group.measurement_time(Duration::from_secs(5));

    // Pre-compile all patterns
    let regex_patterns: Vec<_> = TEST_PATTERNS
        .iter()
        .map(|(name, pat)| (*name, Regex::new(pat).unwrap()))
        .collect();

    let automata_patterns: Vec<_> = TEST_PATTERNS
        .iter()
        .map(|(name, pat)| (*name, MetaRegex::new(pat).unwrap()))
        .collect();

    // Benchmark matching against all test commands
    for (name, regex) in &regex_patterns {
        group.throughput(Throughput::Elements(TEST_COMMANDS.len() as u64));
        group.bench_with_input(BenchmarkId::new("regex", name), &regex, |b, re| {
            b.iter(|| {
                for cmd in TEST_COMMANDS {
                    black_box(re.is_match(black_box(cmd)));
                }
            });
        });
    }

    for (name, automata) in &automata_patterns {
        group.throughput(Throughput::Elements(TEST_COMMANDS.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("regex-automata", name),
            &automata,
            |b, re| {
                b.iter(|| {
                    for cmd in TEST_COMMANDS {
                        black_box(re.is_match(black_box(cmd)));
                    }
                });
            },
        );
    }

    group.finish();
}

/// Benchmark matching with capture (find vs `is_match`)
fn bench_find_match(c: &mut Criterion) {
    let mut group = c.benchmark_group("find_match");
    group.measurement_time(Duration::from_secs(5));

    let pattern = r"git\s+(?:\S+\s+)*reset\s+--hard";
    let command = "git reset --hard HEAD~5";

    let regex = Regex::new(pattern).unwrap();
    let automata = MetaRegex::new(pattern).unwrap();

    group.bench_function("regex_is_match", |b| {
        b.iter(|| black_box(regex.is_match(black_box(command))));
    });

    group.bench_function("regex_find", |b| {
        b.iter(|| black_box(regex.find(black_box(command))));
    });

    group.bench_function("automata_is_match", |b| {
        b.iter(|| black_box(automata.is_match(black_box(command))));
    });

    group.bench_function("automata_find", |b| {
        b.iter(|| {
            let input = Input::new(black_box(command));
            black_box(automata.find(input))
        });
    });

    group.finish();
}

/// Benchmark multi-pattern matching (simulating pack evaluation)
fn bench_multi_pattern(c: &mut Criterion) {
    let mut group = c.benchmark_group("multi_pattern");
    group.measurement_time(Duration::from_secs(5));

    // Compile all patterns
    let regex_set: Vec<_> = TEST_PATTERNS
        .iter()
        .map(|(_, pat)| Regex::new(pat).unwrap())
        .collect();

    let automata_set: Vec<_> = TEST_PATTERNS
        .iter()
        .map(|(_, pat)| MetaRegex::new(pat).unwrap())
        .collect();

    // Also test with a combined pattern using alternation
    let combined_pattern = TEST_PATTERNS
        .iter()
        .map(|(_, pat)| format!("({pat})"))
        .collect::<Vec<_>>()
        .join("|");

    let regex_combined = Regex::new(&combined_pattern).unwrap();
    let automata_combined = MetaRegex::new(&combined_pattern).unwrap();

    let matching_cmd = "git reset --hard HEAD";
    let non_matching_cmd = "git status";

    // Sequential scan (current dcg approach)
    group.bench_function("regex_sequential_match", |b| {
        b.iter(|| {
            for re in &regex_set {
                if re.is_match(black_box(matching_cmd)) {
                    return black_box(true);
                }
            }
            black_box(false)
        });
    });

    group.bench_function("automata_sequential_match", |b| {
        b.iter(|| {
            for re in &automata_set {
                if re.is_match(black_box(matching_cmd)) {
                    return black_box(true);
                }
            }
            black_box(false)
        });
    });

    // Combined pattern (single regex with alternation)
    group.bench_function("regex_combined_match", |b| {
        b.iter(|| black_box(regex_combined.is_match(black_box(matching_cmd))));
    });

    group.bench_function("automata_combined_match", |b| {
        b.iter(|| black_box(automata_combined.is_match(black_box(matching_cmd))));
    });

    // Non-matching command (tests fast rejection)
    group.bench_function("regex_sequential_nomatch", |b| {
        b.iter(|| {
            for re in &regex_set {
                if re.is_match(black_box(non_matching_cmd)) {
                    return black_box(true);
                }
            }
            black_box(false)
        });
    });

    group.bench_function("automata_sequential_nomatch", |b| {
        b.iter(|| {
            for re in &automata_set {
                if re.is_match(black_box(non_matching_cmd)) {
                    return black_box(true);
                }
            }
            black_box(false)
        });
    });

    group.finish();
}

/// Benchmark worst-case patterns (`ReDoS` resistance)
fn bench_worst_case(c: &mut Criterion) {
    let mut group = c.benchmark_group("worst_case");
    group.measurement_time(Duration::from_secs(3));

    // Patterns that could cause exponential backtracking
    let evil_patterns = &[
        ("nested_quantifier", r"(a+)+$"),
        ("alternation", r"(a|a)+"),
        ("catastrophic", r"(a*)*b"),
    ];

    // Input designed to trigger worst-case
    let evil_input = "a".repeat(25) + "!"; // 25 'a's followed by non-matching char

    for (name, pattern) in evil_patterns {
        // regex crate should handle this in O(n) due to Thompson NFA
        if let Ok(regex) = Regex::new(pattern) {
            group.bench_with_input(BenchmarkId::new("regex", name), &evil_input, |b, input| {
                b.iter(|| black_box(regex.is_match(black_box(input))));
            });
        }

        // regex-automata should also be O(n)
        if let Ok(automata) = MetaRegex::new(pattern) {
            group.bench_with_input(
                BenchmarkId::new("regex-automata", name),
                &evil_input,
                |b, input| {
                    b.iter(|| black_box(automata.is_match(black_box(input))));
                },
            );
        }
    }

    group.finish();
}

/// Benchmark long input handling
fn bench_long_input(c: &mut Criterion) {
    let mut group = c.benchmark_group("long_input");
    group.measurement_time(Duration::from_secs(5));

    let pattern = r"git\s+(?:\S+\s+)*reset\s+--hard";
    let regex = Regex::new(pattern).unwrap();
    let automata = MetaRegex::new(pattern).unwrap();

    // Generate inputs of various sizes
    let sizes = [100, 1000, 5000, 10000];

    for size in sizes {
        let input = format!("git {} reset --hard", "status ".repeat(size / 7));
        let input_len = input.len();

        group.throughput(Throughput::Bytes(input_len as u64));

        group.bench_with_input(BenchmarkId::new("regex", size), &input, |b, inp| {
            b.iter(|| black_box(regex.is_match(black_box(inp))));
        });

        group.bench_with_input(
            BenchmarkId::new("regex-automata", size),
            &input,
            |b, inp| {
                b.iter(|| black_box(automata.is_match(black_box(inp))));
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_compilation,
    bench_single_match,
    bench_find_match,
    bench_multi_pattern,
    bench_worst_case,
    bench_long_input,
);
criterion_main!(benches);
