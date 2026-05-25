//! Regression tests for security bypasses fixed in Jan 2025.
//!
//! Covers:
//! - Heredoc spaced delimiters (git_safety_guard-audit-2025-01-10)
//! - Quoted subcommands/binaries
//! - Wrapper/path obfuscation
//!
//! Tests run in-process using the library entry point to ensure
//! we test the current code without relying on stale binaries.

use dcg_cli::{Config, evaluate_command, packs::REGISTRY};

fn check_blocked(cmd: &str) {
    // Setup config with heredoc enabled and core packs
    let mut config = Config::default();
    config.heredoc.enabled = Some(true);
    // Explicitly enable core (though enabled_pack_ids does this implicitly)
    config.packs.enabled = vec!["core".to_string()];

    let overrides = config.overrides.compile();
    // Use default (empty) allowlists to ensure tests are hermetic
    let allowlists = dcg_cli::LayeredAllowlist::default();

    let enabled_packs = config.enabled_pack_ids();
    let keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);

    let result = evaluate_command(cmd, &config, &keywords, &overrides, &allowlists);

    assert!(
        result.is_denied(),
        "Command should be BLOCKED: {}\nReason: {:?}",
        cmd,
        result.reason()
    );
}

#[test]
fn test_heredoc_spaced_delimiter_bypass() {
    let cmd = "python3 << \"EOF SPACE\"\nimport shutil\nshutil.rmtree('/tmp/test')\nEOF SPACE";
    check_blocked(cmd);
}

#[test]
fn test_quoted_subcommand_bypass() {
    let cmd = "git \"reset\" --hard";
    check_blocked(cmd);
}

#[test]
fn test_sudo_absolute_path_bypass() {
    let cmd = "sudo /bin/git reset --hard";
    check_blocked(cmd);
}

#[test]
fn test_env_absolute_path_bypass() {
    let cmd = "env /usr/bin/git reset --hard";
    check_blocked(cmd);
}

#[test]
fn test_quoted_binary_bypass() {
    let cmd = "\"git\" reset --hard";
    check_blocked(cmd);
}

#[test]
fn test_complex_quoting_bypass() {
    let cmd = "sudo \"/usr/bin/git\" \"reset\" --hard";
    check_blocked(cmd);
}

#[test]
fn test_heredoc_empty_delimiter() {
    // Regression for the fix allowing empty quoted delimiters
    let cmd = "python3 << \"\"\nimport shutil\nshutil.rmtree('/tmp/test')\n\n";
    check_blocked(cmd);
}
