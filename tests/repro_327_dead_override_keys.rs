//! Regression tests for issue #327: `overrides.allowlist` and
//! `overrides.allowlist_rules` were accepted by the parser, documented in
//! `dcg config schema`, and never consulted — the layer merge dropped them, so
//! a config using them silently had no effect while `dcg config` reported the
//! file as fully loaded.
//!
//! The keys are now removed from the schema. A config still carrying them
//! parses (so nothing breaks), grants nothing (unchanged, and fail-safe), and
//! is loudly reported by `dcg config` / `dcg doctor`. `dcg config --format
//! json` now echoes the `overrides`, `rules`, and `policy` sections so an
//! automated check can assert what is actually loaded.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

struct TestEnv {
    temp_dir: tempfile::TempDir,
    home_dir: PathBuf,
    config_path: PathBuf,
}

impl TestEnv {
    fn with_config(config_content: &str) -> Self {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let home_dir = temp_dir.path().join("home");
        let xdg_config_dir = temp_dir.path().join("xdg_config");
        let dcg_dir = xdg_config_dir.join("dcg");
        fs::create_dir_all(&home_dir).expect("failed to create HOME dir");
        fs::create_dir_all(&dcg_dir).expect("failed to create config dir");
        let config_path = dcg_dir.join("config.toml");
        fs::write(&config_path, config_content).expect("failed to write config");
        Self {
            temp_dir,
            home_dir,
            config_path,
        }
    }

    fn run(&self, args: &[&str]) -> (String, String, i32) {
        let mut cmd = Command::new(dcg_binary());
        cmd.env_clear()
            .env("HOME", &self.home_dir)
            .env("USERPROFILE", &self.home_dir)
            .env("DCG_CONFIG", &self.config_path)
            .env("DCG_SELF_HEAL_HOOK", "0")
            .current_dir(self.temp_dir.path())
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = cmd.output().expect("failed to run dcg");
        (
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
            output.status.code().unwrap_or(-1),
        )
    }
}

const PROBE: &str = "rm -rf /srv/scratch/build";

/// The working surface keeps working: an anchored `overrides.allow` regex
/// allows the command.
#[test]
fn overrides_allow_regex_still_works() {
    let env =
        TestEnv::with_config("[overrides]\nallow = ['^rm -rf /srv/scratch/[A-Za-z0-9._/-]+$']\n");
    let (_, _, code) = env.run(&["test", PROBE]);
    assert_eq!(code, 0, "anchored allow override must permit the command");
}

/// The removed keys grant nothing — same observable behavior as before the
/// removal (fail-safe direction), for both documented shapes.
#[test]
fn removed_keys_grant_no_allowances() {
    for config in [
        "[overrides]\nallowlist = ['rm -rf /srv/scratch/build']\n",
        "[[overrides.allowlist_rules]]\npattern = 'rm -rf /srv/scratch/build'\npaths = [\"/srv/scratch/*\"]\n",
    ] {
        let env = TestEnv::with_config(config);
        let (_, _, code) = env.run(&["test", PROBE]);
        assert_eq!(code, 1, "removed key must not allow the command: {config}");
    }
}

/// `dcg config --format json` reports the removed keys and carries the
/// machine-checkable `overrides`/`rules`/`policy` echo.
#[test]
fn config_json_reports_removed_keys_and_echoes_sections() {
    let env = TestEnv::with_config(
        "[overrides]\nallow = ['^git stash list$']\nallowlist = ['rm -rf /srv/scratch/build']\n\n\
         [[overrides.allowlist_rules]]\npattern = 'rm -rf /srv/scratch/build'\n\n\
         [rules.\"core.filesystem:redirect-truncate-root-home\"]\n\
         exempt_target_globs = [\"~/.claude/jobs/*/tmp/**\"]\n\n\
         [policy.rules]\n\"core.git:stash-drop\" = \"deny\"\n",
    );
    let (stdout, _, code) = env.run(&["config", "--format", "json"]);
    assert_eq!(code, 0, "dcg config must succeed");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("config JSON must parse");

    let removed = json["overrides"]["removed_keys_present"]
        .as_array()
        .expect("removed_keys_present must be an array");
    let removed: Vec<&str> = removed.iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(
        removed,
        ["overrides.allowlist", "overrides.allowlist_rules"],
        "both removed keys must be reported"
    );

    let warnings = json["warnings"]
        .as_array()
        .expect("warnings must be an array");
    assert_eq!(
        warnings.len(),
        2,
        "one warning per removed key: {warnings:?}"
    );

    // The enforcing sections are echoed, so `jq` can tell "loaded" from
    // "absent" — the observability gap from the issue.
    assert_eq!(
        json["overrides"]["allow"][0].as_str(),
        Some("^git stash list$"),
        "allow overrides must be echoed"
    );
    assert_eq!(
        json["rules"]["core.filesystem:redirect-truncate-root-home"]["exempt_target_globs"][0]
            .as_str(),
        Some("~/.claude/jobs/*/tmp/**"),
        "rule target exemptions must be echoed"
    );
    assert_eq!(
        json["policy"]["rules"]["core.git:stash-drop"].as_str(),
        Some("deny"),
        "policy rules must be echoed"
    );
}

/// The human-facing `dcg config` output warns too.
#[test]
fn config_pretty_output_warns_about_removed_keys() {
    let env = TestEnv::with_config("[overrides]\nallowlist = ['rm -rf /srv/scratch/build']\n");
    let (stdout, stderr, code) = env.run(&["config"]);
    assert_eq!(code, 0, "dcg config must succeed");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("overrides.allowlist"),
        "pretty config output must name the removed key: {combined}"
    );
    assert!(
        combined.contains("not enforced"),
        "pretty config output must say the key is not enforced: {combined}"
    );
}

/// A clean config yields no removed-key warnings and an empty-but-present
/// overrides echo.
#[test]
fn clean_config_has_no_removed_key_warnings() {
    let env = TestEnv::with_config("[general]\nverbose = false\n");
    let (stdout, _, code) = env.run(&["config", "--format", "json"]);
    assert_eq!(code, 0);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("config JSON must parse");
    assert_eq!(json["warnings"].as_array().map(Vec::len), Some(0));
    assert_eq!(
        json["overrides"]["removed_keys_present"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
    assert!(json["overrides"]["allow"].is_array());
    assert!(json["rules"].is_object());
    assert!(json["policy"].is_object());
}
