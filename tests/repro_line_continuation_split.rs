use destructive_command_guard::{
    config::Config, evaluator::evaluate_command, load_default_allowlists,
};

#[test]
fn test_line_continuation_split_bypass() {
    let config = Config::default();
    let compiled_overrides = config.overrides.compile();
    let allowlists = load_default_allowlists();
    let keywords = &["git", "reset"];

    // Command: git re\
    //          set --hard
    // The backslash+newline should be removed by the shell, forming "git reset --hard".
    // If dcg doesn't normalize this, the regex "git\s+reset" won't match "git re\nset".
    let cmd = "git re\\\nset --hard";

    let result = evaluate_command(cmd, &config, keywords, &compiled_overrides, &allowlists);

    assert!(
        result.is_denied(),
        "Splitting command with line continuation bypassed detection! Result: {:?}",
        result.decision
    );
}
