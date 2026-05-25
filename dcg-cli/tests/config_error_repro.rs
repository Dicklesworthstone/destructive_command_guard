use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

#[test]
#[allow(deprecated)]
fn test_config_load_swallows_parse_error() {
    // Create a temp directory
    let temp_dir = tempdir().expect("failed to create temp dir");
    let config_path = temp_dir.path().join("config.toml");

    // Write invalid TOML
    let invalid_toml = r#"
[general]
verbose = true
color = "always"
invalid_syntax_here = 
"#;
    fs::write(&config_path, invalid_toml).expect("failed to write config file");

    // Run `dcg config` pointing to this file
    let mut cmd = Command::cargo_bin("dcg").expect("failed to find binary");
    cmd.env("DCG_CONFIG", &config_path).arg("config");

    // We EXPECT it to succeed (exit 0) but ignore the file (so verbose=false default).
    // If it failed on parse error, this test would fail (assertion failure).
    // If it parsed correctly, verbose would be true.
    // If it swallowed the error, it succeeds but uses defaults (verbose=false).
    let assert = cmd.assert();

    assert
        .success()
        .stdout(predicates::str::contains("Verbose: false")); // Default is false, file had true but was invalid
}
