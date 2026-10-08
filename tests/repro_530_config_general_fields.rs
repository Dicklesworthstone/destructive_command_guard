//! Regression tests for issue #530: `dcg config --format json` built its
//! `general` object from a hand-written list of seven keys, so
//! `unverified_decision`, `update_pin`, `check_updates`,
//! `max_hook_input_bytes`, `max_command_bytes` and `max_findings_per_command`
//! were never reported, nor were their `DCG_*` overrides.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

/// Run `dcg config --format json` in a throwaway HOME with `config` as the
/// only config file and `envs` as the only extra environment.
fn general_json(config: &str, envs: &[(&str, &str)]) -> serde_json::Value {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let home_dir = temp_dir.path().join("home");
    let config_path = temp_dir.path().join("config.toml");
    fs::create_dir_all(&home_dir).expect("failed to create HOME dir");
    fs::write(&config_path, config).expect("failed to write config");

    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .env("DCG_CONFIG", &config_path)
        .env("DCG_SELF_HEAL_HOOK", "0")
        .current_dir(temp_dir.path())
        .args(["config", "--format", "json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        cmd.env(key, value);
    }
    let output = cmd.output().expect("failed to run dcg");
    assert!(
        output.status.success(),
        "dcg config failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("dcg config --format json is JSON");
    parsed["general"].clone()
}

#[test]
fn config_json_reports_every_general_setting_from_the_config_file() {
    let general = general_json(
        "[general]\n\
         unverified_decision = \"deny\"\n\
         update_pin = true\n\
         check_updates = false\n\
         max_command_bytes = 1024\n\
         max_hook_input_bytes = 4096\n\
         max_findings_per_command = 5\n",
        &[],
    );
    assert_eq!(general["unverified_decision"], "deny", "{general}");
    assert_eq!(general["update_pin"], true, "{general}");
    assert_eq!(general["check_updates"], false, "{general}");
    assert_eq!(general["max_command_bytes"], 1024, "{general}");
    assert_eq!(general["max_hook_input_bytes"], 4096, "{general}");
    assert_eq!(general["max_findings_per_command"], 5, "{general}");
}

#[test]
fn config_json_reports_defaults_when_general_settings_are_unset() {
    let general = general_json("", &[]);
    assert_eq!(general["unverified_decision"], "ask", "{general}");
    assert_eq!(general["update_pin"], false, "{general}");
    for key in [
        "check_updates",
        "max_command_bytes",
        "max_hook_input_bytes",
        "max_findings_per_command",
    ] {
        assert!(
            general.get(key).is_some_and(|value| !value.is_null()),
            "{key} missing from general: {general}"
        );
    }
}

#[test]
fn config_json_reports_environment_overrides() {
    let general = general_json(
        "",
        &[
            ("DCG_UNVERIFIED_DECISION", "deny"),
            ("DCG_UPDATE_PIN", "1"),
            ("DCG_NO_UPDATE_CHECK", "1"),
        ],
    );
    assert_eq!(general["unverified_decision"], "deny", "{general}");
    assert_eq!(general["update_pin"], true, "{general}");
    assert_eq!(general["check_updates"], false, "{general}");

    // An override wins over the file in both directions.
    let general = general_json(
        "[general]\nunverified_decision = \"deny\"\n",
        &[("DCG_UNVERIFIED_DECISION", "ask")],
    );
    assert_eq!(general["unverified_decision"], "ask", "{general}");
}
