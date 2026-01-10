use destructive_command_guard::{
    config::Config, evaluator::evaluate_command, load_default_allowlists,
};

#[test]
fn test_line_continuation_does_not_consume_flag() {
    let config = Config::default();
    let compiled_overrides = config.overrides.compile();
    let allowlists = load_default_allowlists();
    let keywords = &["rm", "git"];

    // Command: git commit -m \
    //          "rm -rf /"
    // The backslash+newline should be ignored, so -m applies to "rm -rf /".
    // If it's not ignored, the backslash consumes -m, and "rm -rf /" is seen as a command.
    let cmd = "git commit -m \
\"rm -rf /\"";

    let result = evaluate_command(cmd, &config, keywords, &compiled_overrides, &allowlists);

    assert!(
        result.is_allowed(),
        "Command with line continuation was incorrectly blocked (arg masking failed)"
    );
}
