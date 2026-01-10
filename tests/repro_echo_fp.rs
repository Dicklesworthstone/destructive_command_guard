use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{
    config::Config, evaluator::evaluate_command, load_default_allowlists,
};

#[test]
fn test_echo_rm_rf_false_positive() {
    let config = Config::default();
    let compiled_overrides = config.overrides.compile();
    let allowlists = load_default_allowlists();

    let enabled_packs = config.enabled_pack_ids();
    let keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);

    // This command prints "rm -rf /" but does not execute it.
    // It should be allowed.
    let cmd = "echo rm -rf /";

    let result = evaluate_command(cmd, &config, &keywords, &compiled_overrides, &allowlists);

    assert!(
        result.is_allowed(),
        "echo rm -rf / should be allowed, but was: {:?}",
        result.decision
    );
}
