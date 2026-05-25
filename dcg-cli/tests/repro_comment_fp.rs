use dcg_cli::{
    config::Config, evaluator::evaluate_command, load_default_allowlists,
};

#[test]
fn test_shell_comment_false_positive() {
    let config = Config::default();
    let compiled_overrides = config.overrides.compile();
    let allowlists = load_default_allowlists();
    let keywords = &["rm", "git"];

    // Command with destructive operation inside a comment
    let cmd = "ls -la # rm -rf /";

    // Should be allowed because the destructive part is a comment
    let result = evaluate_command(cmd, &config, keywords, &compiled_overrides, &allowlists);

    assert!(
        result.is_allowed(),
        "Command with destructive comment should be allowed, but was: {:?}",
        result.decision
    );
}
