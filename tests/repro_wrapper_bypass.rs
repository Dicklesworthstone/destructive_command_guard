use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{
    config::Config, evaluator::evaluate_command, load_default_allowlists,
};

#[test]
fn test_wrapper_bypasses() {
    let config = Config::default();
    let compiled_overrides = config.overrides.compile();
    let allowlists = load_default_allowlists();

    // Core packs are enabled by default
    let enabled_packs = config.enabled_pack_ids();
    let keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);

    let destructive_commands = vec![
        "nice rm -rf /",
        "time rm -rf /",
        "nohup rm -rf /",
        "watch rm -rf /",
        "timeout 10s rm -rf /",
        // xargs is harder because it reads from stdin, but "xargs rm -rf" command line exists
        // "xargs rm -rf /" is valid if arguments are appended? No, xargs reads stdin.
        // But "xargs -a file rm -rf" reads from file.
        // Or "xargs sh -c 'rm -rf /'"
    ];

    for cmd in destructive_commands {
        let result = evaluate_command(cmd, &config, &keywords, &compiled_overrides, &allowlists);
        assert!(
            result.is_denied(),
            "Command '{cmd}' should be blocked but was allowed!"
        );
    }
}
