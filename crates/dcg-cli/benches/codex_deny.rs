//! Benchmarks for protocol-specific deny path formatting.
//!
//! Run with: `cargo bench --bench codex_deny`

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use dcg_cli::hook::{
    AllowOnceInfo, HookInput, HookProtocol, extract_command_with_protocol, write_denial_to,
};
use dcg_cli::packs::{REGISTRY, Severity};
use dcg_cli::{Config, EvaluationDecision, LayeredAllowlist, evaluate_command_with_pack_order};

const COMMAND: &str = "git reset --hard HEAD~1";

struct HookBenchInputs {
    enabled_keywords: Vec<&'static str>,
    ordered_packs: Vec<String>,
    keyword_index: Option<dcg_cli::packs::EnabledKeywordIndex>,
    compiled_overrides: dcg_cli::config::CompiledOverrides,
    heredoc_settings: dcg_cli::config::HeredocSettings,
}

struct BenchState {
    inputs: HookBenchInputs,
    allowlists: LayeredAllowlist,
    allow_once: AllowOnceInfo,
    codex_payload: String,
    claude_payload: String,
}

#[derive(Default)]
struct OutputBuffers {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl OutputBuffers {
    fn clear(&mut self) {
        self.stdout.clear();
        self.stderr.clear();
    }
}

impl BenchState {
    fn new() -> Self {
        let mut config = Config::default();
        config.heredoc.enabled = Some(false);

        let enabled_packs = config.enabled_pack_ids();
        let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
        let inputs = HookBenchInputs {
            enabled_keywords: REGISTRY.collect_enabled_keywords(&enabled_packs),
            keyword_index: REGISTRY.build_enabled_keyword_index(&ordered_packs),
            ordered_packs,
            compiled_overrides: config.overrides.compile(),
            heredoc_settings: config.heredoc_settings(),
        };

        Self {
            inputs,
            allowlists: LayeredAllowlist::default(),
            allow_once: AllowOnceInfo {
                code: "abc123".to_string(),
                full_hash: "sha256:abc123def456".to_string(),
            },
            codex_payload: serde_json::json!({
                "tool_name": "Bash",
                "turn_id": "turn-bench",
                "tool_input": { "command": COMMAND }
            })
            .to_string(),
            claude_payload: serde_json::json!({
                "tool_name": "Bash",
                "tool_input": { "command": COMMAND }
            })
            .to_string(),
        }
    }
}

fn run_deny_path(payload: &str, state: &BenchState, buffers: &mut OutputBuffers) -> (usize, usize) {
    buffers.clear();

    let input: HookInput = serde_json::from_str(black_box(payload)).expect("valid hook payload");
    let (command, protocol) =
        extract_command_with_protocol(&input).expect("payload contains a shell command");
    debug_assert!(matches!(
        protocol,
        HookProtocol::Codex | HookProtocol::ClaudeCompatible
    ));

    let result = evaluate_command_with_pack_order(
        black_box(command.as_str()),
        black_box(state.inputs.enabled_keywords.as_slice()),
        black_box(state.inputs.ordered_packs.as_slice()),
        black_box(state.inputs.keyword_index.as_ref()),
        black_box(&state.inputs.compiled_overrides),
        black_box(&state.allowlists),
        black_box(&state.inputs.heredoc_settings),
    );
    debug_assert_eq!(result.decision, EvaluationDecision::Deny);

    let info = result
        .pattern_info
        .as_ref()
        .expect("deny includes pattern info");
    debug_assert_eq!(info.severity, Some(Severity::Critical));

    write_denial_to(
        &mut buffers.stdout,
        &mut buffers.stderr,
        protocol,
        command.as_str(),
        info.reason.as_str(),
        info.pack_id.as_deref(),
        info.pattern_name.as_deref(),
        info.explanation.as_deref(),
        Some(&state.allow_once),
        info.matched_span.as_ref(),
        info.severity,
        None,
        info.suggestions,
        None,
    );

    (buffers.stdout.len(), buffers.stderr.len())
}

fn bench_protocol_deny_path(c: &mut Criterion) {
    let state = BenchState::new();
    let mut group = c.benchmark_group("hook_deny_path");

    for (name, payload) in [
        ("codex_deny", state.codex_payload.as_str()),
        ("claude_deny", state.claude_payload.as_str()),
    ] {
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            payload,
            |b: &mut criterion::Bencher<'_>, payload: &str| {
                let mut buffers = OutputBuffers::default();
                b.iter(|| black_box(run_deny_path(black_box(payload), &state, &mut buffers)));
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_protocol_deny_path);
criterion_main!(benches);
