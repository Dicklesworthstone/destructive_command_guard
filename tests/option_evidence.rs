//! Regression coverage for #435 at the shared evaluator boundary.
//!
//! Pack::check alone is insufficient: the hook/CLI evaluator has a separate
//! whole-command fallback after its per-segment checks. No external command,
//! cluster, release, or database is executed by this test suite.

use std::collections::HashSet;

use destructive_command_guard::hook::{HookInput, extract_command_with_protocol};
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{
    Config, EvaluationDecision, LayeredAllowlist, evaluate_command_with_pack_order,
};

fn assert_decision(pack_id: &str, source: &str, expected: EvaluationDecision) {
    // Decode the actual hook envelope rather than hand-normalizing argv in
    // the test. Multiword quoting must survive this boundary unchanged.
    let input: HookInput = serde_json::from_value(serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {"command": source}
    }))
    .expect("valid hook envelope");
    let (command, _) = extract_command_with_protocol(&input).expect("shell command");
    assert_eq!(command, source);

    // Deliberately do NOT enable all Kubernetes packs: a second pack's denial
    // must not conceal a broken exemption in the pack under test.
    let enabled = HashSet::from([pack_id.to_string()]);
    let ordered = vec![pack_id.to_string()];
    let keywords = REGISTRY.collect_enabled_keywords(&enabled);
    let keyword_index = REGISTRY.build_enabled_keyword_index(&ordered);
    let mut config = Config::default();
    config.heredoc.enabled = Some(false);
    let overrides = config.overrides.compile();
    let allowlists = LayeredAllowlist::default();
    let heredoc = config.heredoc_settings();

    for indexed in [false, true] {
        let result = evaluate_command_with_pack_order(
            &command,
            &keywords,
            &ordered,
            if indexed { keyword_index.as_ref() } else { None },
            &overrides,
            &allowlists,
            &heredoc,
        );
        assert_eq!(
            result.decision, expected,
            "pack={pack_id}, indexed={indexed}, command={source:?}"
        );
        if expected == EvaluationDecision::Deny {
            let info = result.pattern_info.expect("denial identifies the rule");
            assert_eq!(info.pack_id.as_deref(), Some(pack_id));
            assert!(info.pattern_name.is_some());
        }
    }
}

#[test]
fn helm_argument_data_cannot_authorize_a_preview() {
    for command in [
        "helm uninstall myrelease --kube-context --dry-run",
        "helm rollback myrelease 1 --kube-context --dry-run",
        "helm uninstall myrelease --description --dry-run",
        "helm uninstall myrelease --description=--dry-run",
        "helm uninstall myrelease --description \"note --dry-run\"",
        "helm uninstall myrelease --description 'note --dry-run'",
        "helm uninstall myrelease --dry-run --description 'note --description' --dry-run=false",
        "helm uninstall myrelease '--' --dry-run",
        "helm uninstall myrelease --dry-run --dry-run=false",
        "helm --debug uninstall list",
        "helm uninstall myrelease --description 'helm list'",
        "helm uninstall myrelease; echo --dry-run",
        "helm uninstall myrelease && echo --dry-run",
        "helm uninstall myrelease | grep -- --dry-run",
    ] {
        assert_decision("kubernetes.helm", command, EvaluationDecision::Deny);
    }
}

#[test]
fn helm_real_previews_and_read_only_commands_remain_allowed() {
    for command in [
        "helm list",
        "helm --debug --kube-context prod list",
        "helm get values myrelease",
        "helm uninstall myrelease --dry-run",
        "helm uninstall myrelease --dry-run=true",
        "helm --kube-context prod uninstall myrelease --dry-run",
        "helm uninstall myrelease --description note --dry-run",
        "helm uninstall myrelease --dry-run --description --dry-run=false",
        "helm rollback myrelease 1 --dry-run",
        "helm upgrade myrelease ./chart --force --dry-run=client",
        "sudo helm uninstall myrelease --dry-run",
    ] {
        assert_decision("kubernetes.helm", command, EvaluationDecision::Allow);
    }
}

#[test]
fn supabase_argument_data_cannot_authorize_a_preview() {
    for command in [
        "supabase db push --password --dry-run",
        "supabase db push --password=--dry-run",
        "supabase db push -p--dry-run",
        "supabase db push --workdir --dry-run",
        "supabase db push --password 'note --dry-run'",
        "supabase db push --password \"note --dry-run\"",
        "supabase db push --password 'supabase db diff'",
        "supabase db push --dry-run --password 'note --password' --dry-run=false",
        "supabase db push --dry-run=true --dry-run=false",
        "supabase db push -- --dry-run",
        "supabase db push; echo --dry-run",
    ] {
        assert_decision("database.supabase", command, EvaluationDecision::Deny);
    }
}

#[test]
fn supabase_real_previews_remain_allowed() {
    for command in [
        "supabase db diff",
        "supabase --debug status",
        "supabase db push --dry-run",
        "supabase db push --linked --dry-run=true",
        "supabase --debug --workdir . db push --dry-run",
        "supabase db push --dry-run --password --dry-run=false",
    ] {
        assert_decision("database.supabase", command, EvaluationDecision::Allow);
    }
}

#[test]
fn kubectl_whole_words_cannot_hide_or_supply_preview_options() {
    for command in [
        "kubectl delete ns prod --cache-dir --dry-run=client",
        "kubectl delete ns prod --cache-dir=--dry-run=client",
        "kubectl delete ns prod --cache-dir 'note --dry-run=client'",
        "kubectl delete ns prod --cache-dir \"note --dry-run=client\"",
        "kubectl delete ns prod --dry-run=client --cache-dir 'note --cache-dir' --dry-run=none",
        "kubectl delete ns prod --dry-run=client '--dry-run=none'",
        "kubectl --warnings-as-errors delete namespace get",
        "kubectl delete ns prod -- --dry-run=client",
        "kubectl delete ns prod --dry-run=client --raw /api/v1/namespaces/prod",
        "kubectl delete ns prod; kubectl delete ns other --dry-run=client",
        "kubectl delete ns prod --dry-run=client; kubectl delete ns other",
    ] {
        assert_decision("kubernetes.kubectl", command, EvaluationDecision::Deny);
    }
}

#[test]
fn kubectl_real_option_values_and_last_preview_setting_are_respected() {
    for command in [
        "kubectl get pods",
        "kubectl delete ns prod --dry-run=client",
        "kubectl delete ns prod --dry-run=none --dry-run=client",
        "kubectl delete ns prod --dry-run=client --cache-dir --dry-run=none",
        "kubectl delete ns prod --cache-dir 'note --dry-run=none' --dry-run=client",
        "kubectl delete ns prod --dry-run=client --cache-dir 'note --cache-dir'",
        "kubectl delete -f '-' --dry-run=\"client\"",
        "kubectl delete -f - --dry-run=client -- --dry-run=none",
        "sudo kubectl delete ns prod --dry-run=client",
    ] {
        assert_decision("kubernetes.kubectl", command, EvaluationDecision::Allow);
    }
}

#[test]
fn kustomize_pipeline_argument_data_cannot_exempt_a_delete() {
    for command in [
        "kustomize build ./prod | kubectl delete -f - --cache-dir diff",
        "kustomize build ./prod | kubectl --cache-dir diff delete -f -",
        "kustomize build ./prod | kubectl delete -f - --cache-dir --dry-run=client",
        "kustomize build ./prod | kubectl delete -f - --cache-dir 'note --dry-run=client'",
        "kustomize build ./prod | kubectl delete -f - --dry-run=client --dry-run=none",
        "kubectl kustomize ./prod | kubectl delete -f - --context --dry-run=server",
        "kustomize build ./prod | kubectl delete --dry-run=client -f - | kubectl delete -f -",
        "kubectl delete -k ./prod --cache-dir=--dry-run=client",
        "kubectl delete --force -k./prod",
        "kubectl delete --kustomize=./prod",
    ] {
        assert_decision("kubernetes.kustomize", command, EvaluationDecision::Deny);
    }
}

#[test]
fn kustomize_previews_survive_the_whole_command_fallback() {
    for command in [
        "kustomize build ./prod",
        "kubectl kustomize ./prod",
        "kustomize build ./prod | kubectl diff -f -",
        "kustomize build ./prod | kubectl delete -f - --dry-run=client",
        "kubectl kustomize ./prod | kubectl delete -f - --dry-run=server",
        "kustomize build ./prod | kubectl --context prod delete -f - --dry-run=client",
        "kubectl delete -k ./prod --dry-run=client",
        "kubectl delete --dry-run=client -k ./prod",
        "kubectl delete --kustomize=./prod --dry-run=server",
    ] {
        assert_decision("kubernetes.kustomize", command, EvaluationDecision::Allow);
    }
}

#[test]
fn mongodb_read_exemptions_cannot_shadow_any_current_destructive_rule() {
    // #435 audit: MongoDB's read exemptions carry an explicit destructive
    // exclusion list. Exercise every destructive regex family through the
    // shared evaluator with a later read operation present so adding a safe
    // word can never turn the denial into an allow.
    for command in [
        "db.dropDatabase(); db.posts.find({})",
        "db.users.drop(); db.posts.find({})",
        "db.users.dropCollection(); db.posts.countDocuments({})",
        "db.users.deleteMany({}); db.posts.aggregate([])",
        "db.users.remove({}); db.posts.find({}).explain()",
        "mongorestore --drop /backup; db.posts.find({})",
    ] {
        assert_decision("database.mongodb", command, EvaluationDecision::Deny);
    }
}

#[test]
fn redis_read_exemptions_cannot_shadow_any_current_destructive_rule() {
    // #435 audit: cover every destructive Redis keyword family with a safe
    // read token in the same command. The safe negative lookahead is a
    // security invariant: if a new destructive family is added without also
    // withdrawing the read exemption, one of these shapes should fail open.
    for command in [
        "redis-cli FLUSHALL && redis-cli GET foo",
        "redis-cli FLUSHDB && redis-cli MGET foo bar",
        "redis-cli DEBUG SEGFAULT && redis-cli INFO",
        "redis-cli DEBUG SLEEP 30 && redis-cli DBSIZE",
        "redis-cli SHUTDOWN NOSAVE && redis-cli GET foo",
        "redis-cli CONFIG RESETSTAT && redis-cli INFO",
        "redis-cli CONFIG SET dir /tmp && redis-cli CONFIG GET dir",
        "redis-cli CONFIG SET maxmemory 100mb && redis-cli INFO memory",
        "redis-cli CONFIG SET maxmemory-policy allkeys-lru && redis-cli CONFIG GET maxmemory-policy",
        "redis-cli CONFIG SET save '' && redis-cli CONFIG GET save",
        "redis-cli CONFIG SET appendonly no && redis-cli CONFIG GET appendonly",
        "redis-cli CONFIG REWRITE && redis-cli INFO",
        "redis-cli KEYS '*' | xargs redis-cli DEL && redis-cli GET sentinel",
        "redis-cli --scan --pattern 'prefix:*' | xargs -r redis-cli UNLINK && redis-cli SCAN 0",
    ] {
        assert_decision("database.redis", command, EvaluationDecision::Deny);
    }
}

#[test]
fn multiword_quoted_evidence_remains_one_argument_in_matching_views() {
    for command in [
        "helm uninstall r --description \"note --dry-run\"",
        "supabase db push --password \"note --dry-run\"",
        "kubectl delete ns prod --cache-dir \"note --dry-run\"",
    ] {
        let normalized = destructive_command_guard::normalize::normalize_command(command);
        assert!(normalized.contains("\"note --dry-run\""));
        let sanitized = destructive_command_guard::sanitize_for_pattern_matching(&normalized);
        assert!(sanitized.contains("\"note --dry-run\""));
    }
}
