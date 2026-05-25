use dcg_cli::{
    config::Config, evaluator::evaluate_command, load_default_allowlists,
};

#[test]
fn test_newline_as_separator_safety() {
    let config = Config::default();
    let compiled_overrides = config.overrides.compile();
    let allowlists = load_default_allowlists();
    let keywords = &["rm", "git"];

    // Command: git commit -m (newline) rm -rf /
    // If newline is treated as whitespace, 'rm' is consumed as the message for -m.
    // If newline is treated as separator, 'rm' is a new command and should be blocked.
    let cmd = "git commit -m\nrm -rf /";

    let result = evaluate_command(cmd, &config, keywords, &compiled_overrides, &allowlists);

    assert!(
        result.is_denied(),
        "Destructive command after newline was incorrectly allowed (likely masked as argument)"
    );
}
