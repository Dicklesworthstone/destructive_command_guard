use destructive_command_guard::allowlist::LayeredAllowlist;
use destructive_command_guard::config::{CompiledOverrides, Config};
use destructive_command_guard::evaluator::evaluate_command;

fn evaluate(cmd: &str) -> bool {
    let config = Config::default();
    let compiled = CompiledOverrides::default();
    let allowlists = LayeredAllowlist::default();
    // Keywords for git and rm are likely enabled by default or we pass them manually
    let keywords = &["git", "rm"];

    let result = evaluate_command(cmd, &config, keywords, &compiled, &allowlists);

    result.is_denied()
}

#[test]
fn test_compound_command_bypass() {
    // "git checkout -b foo" is explicitly SAFE. "rm -rf /" is destructive.
    // If safe patterns are unanchored, "git checkout -b" might match this string
    // and cause the evaluator to allow the whole thing.
    let cmd = "rm -rf / ; git checkout -b foo";
    assert!(evaluate(cmd), "Command '{cmd}' should be blocked");
}

#[test]
fn test_compound_command_bypass_reverse() {
    let cmd = "git checkout -b foo ; rm -rf /";
    assert!(evaluate(cmd), "Command '{cmd}' should be blocked");
}

#[test]
fn test_pipe_bypass() {
    let cmd = "rm -rf / | git checkout -b foo";
    assert!(evaluate(cmd), "Command '{cmd}' should be blocked");
}
