#![allow(clippy::uninlined_format_args)]
//! Focused coverage for `dcg test` command behavior.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Path to the dcg binary compiled for this test run.
fn dcg_binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("current_exe");
    path.pop(); // test binary name
    path.pop(); // deps/
    path.push("dcg");
    path
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// Run dcg with an isolated HOME/XDG config to avoid machine-specific allowlists.
fn run_dcg_isolated(args: &[&str], cwd: Option<&Path>) -> Output {
    let home = tempfile::tempdir().expect("temp home");
    let xdg = home.path().join("xdg");
    std::fs::create_dir_all(&xdg).expect("create xdg config dir");

    let mut cmd = Command::new(dcg_binary());
    cmd.args(args)
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", &xdg)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "");

    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }

    cmd.output().expect("run dcg")
}

fn parse_json(output: &Output) -> serde_json::Value {
    serde_json::from_str(&stdout_text(output)).expect("stdout should be valid JSON")
}

#[test]
fn test_basic_blocked_command_exits_one() {
    let output = run_dcg_isolated(&["test", "--format", "json", "git reset --hard"], None);

    assert_eq!(
        output.status.code(),
        Some(1),
        "blocked command should exit 1\nstderr: {}",
        stderr_text(&output)
    );

    let json = parse_json(&output);
    assert_eq!(json["decision"], "deny");
}

#[test]
fn test_basic_allowed_command_exits_zero() {
    let output = run_dcg_isolated(&["test", "--format", "json", "ls -la"], None);

    assert_eq!(
        output.status.code(),
        Some(0),
        "allowed command should exit 0\nstderr: {}",
        stderr_text(&output)
    );

    let json = parse_json(&output);
    assert_eq!(json["decision"], "allow");
}

#[test]
fn test_stdout_stderr_redirect_truncate_is_blocked() {
    let output = run_dcg_isolated(&["test", "--format", "json", ": >&/etc/passwd"], None);

    assert_eq!(
        output.status.code(),
        Some(1),
        "`>&word` stdout/stderr truncation should be blocked\nstdout: {}\nstderr: {}",
        stdout_text(&output),
        stderr_text(&output)
    );

    let json = parse_json(&output);
    assert_eq!(json["decision"], "deny");
    assert_eq!(json["pack_id"], "core.filesystem");
    assert_eq!(json["pattern_name"], "redirect-truncate-root-home");
}

#[test]
fn test_allowlist_match_allows_blocked_command() {
    let repo = tempfile::tempdir().expect("temp repo");
    std::fs::create_dir_all(repo.path().join(".git")).expect("create .git marker");
    std::fs::create_dir_all(repo.path().join(".dcg")).expect("create .dcg dir");
    std::fs::write(
        repo.path().join(".dcg").join("allowlist.toml"),
        r#"
[[allow]]
exact_command = "git reset --hard"
reason = "test fixture allowlist entry"
"#,
    )
    .expect("write allowlist");

    let output = run_dcg_isolated(
        &["test", "--format", "json", "git reset --hard"],
        Some(repo.path()),
    );

    assert_eq!(
        output.status.code(),
        Some(0),
        "allowlist match should allow command\nstderr: {}",
        stderr_text(&output)
    );

    let json = parse_json(&output);
    assert_eq!(json["decision"], "allow");
}

#[test]
fn test_json_output_has_expected_fields() {
    let output = run_dcg_isolated(&["test", "--format", "json", "git reset --hard"], None);
    let json = parse_json(&output);

    assert!(json.get("schema_version").is_some());
    assert!(json.get("dcg_version").is_some());
    assert!(json.get("robot_mode").is_some());
    assert!(json.get("command").is_some());
    assert!(json.get("decision").is_some());
}

#[test]
fn test_custom_config_is_applied() {
    let temp = tempfile::tempdir().expect("temp dir");
    let config_path = temp.path().join("custom.toml");
    std::fs::write(
        &config_path,
        r#"
[overrides]
allow = ["git reset --hard"]
"#,
    )
    .expect("write config");

    let config_arg = config_path.to_string_lossy().to_string();
    let output = run_dcg_isolated(
        &[
            "test",
            "--format",
            "json",
            "--config",
            config_arg.as_str(),
            "git reset --hard",
        ],
        None,
    );

    assert_eq!(
        output.status.code(),
        Some(0),
        "custom config override should allow command\nstderr: {}",
        stderr_text(&output)
    );

    let json = parse_json(&output);
    assert_eq!(json["decision"], "allow");
}

#[test]
fn test_config_block_override_wins_over_overlapping_allow_override() {
    let temp = tempfile::tempdir().expect("temp dir");
    let config_path = temp.path().join("custom.toml");
    std::fs::write(
        &config_path,
        r#"
[overrides]
allow = ["git reset --hard"]
block = [
  { pattern = "git reset --hard", reason = "explicit config block" },
]
"#,
    )
    .expect("write config");

    let config_arg = config_path.to_string_lossy().to_string();
    let output = run_dcg_isolated(
        &[
            "test",
            "--format",
            "json",
            "--config",
            config_arg.as_str(),
            "git reset --hard",
        ],
        None,
    );

    assert_eq!(
        output.status.code(),
        Some(1),
        "overlapping config block should deny command\nstdout: {}\nstderr: {}",
        stdout_text(&output),
        stderr_text(&output)
    );

    let json = parse_json(&output);
    assert_eq!(json["decision"], "deny");
    assert!(
        stdout_text(&output).contains("explicit config block"),
        "deny output should include config block reason\nstdout: {}\nstderr: {}",
        stdout_text(&output),
        stderr_text(&output)
    );
}

#[test]
fn test_project_config_discovery_is_applied_without_config_flag() {
    let repo = tempfile::tempdir().expect("temp repo");
    std::fs::create_dir_all(repo.path().join(".git")).expect("create .git marker");
    std::fs::write(
        repo.path().join(".dcg.toml"),
        r#"
[overrides]
allow = ["git reset --hard"]
"#,
    )
    .expect("write project config");

    let output = run_dcg_isolated(
        &["test", "--format", "json", "git reset --hard"],
        Some(repo.path()),
    );

    assert_eq!(
        output.status.code(),
        Some(0),
        "project config should allow command\nstderr: {}",
        stderr_text(&output)
    );

    let json = parse_json(&output);
    assert_eq!(json["decision"], "allow");
}

#[test]
fn test_with_packs_enables_extra_pack_detection() {
    let cmd = "aws ec2 terminate-instances --instance-ids i-1234567890abcdef0";

    let baseline = run_dcg_isolated(&["test", "--format", "json", cmd], None);
    assert_eq!(
        baseline.status.code(),
        Some(0),
        "baseline should allow without extra pack\nstderr: {}",
        stderr_text(&baseline)
    );
    let baseline_json = parse_json(&baseline);
    assert_eq!(baseline_json["decision"], "allow");

    let with_pack = run_dcg_isolated(
        &["test", "--format", "json", "--with-packs", "cloud.aws", cmd],
        None,
    );
    assert_eq!(
        with_pack.status.code(),
        Some(1),
        "extra pack should block command\nstderr: {}",
        stderr_text(&with_pack)
    );

    let with_pack_json = parse_json(&with_pack);
    assert_eq!(with_pack_json["decision"], "deny");
    assert_eq!(with_pack_json["pack_id"], "cloud.aws");
}

#[test]
fn test_with_packs_checks_railway_api_curl_payloads() {
    let cmd = r#"curl https://backboard.railway.app/graphql/v2 --data-binary '{"query":"mutation($in: VariableUpsertInput!){variableUpsert(input:$in)}","variables":{"in":{"name":"DATABASE_PUBLIC_URL","value":"postgres://prod"}}}'"#;

    let output = run_dcg_isolated(
        &[
            "test",
            "--format",
            "json",
            "--with-packs",
            "platform.railway",
            cmd,
        ],
        None,
    );

    assert_eq!(
        output.status.code(),
        Some(1),
        "Railway API variable upsert should be blocked\nstdout: {}\nstderr: {}",
        stdout_text(&output),
        stderr_text(&output)
    );

    let json = parse_json(&output);
    assert_eq!(json["decision"], "deny");
    assert_eq!(json["pack_id"], "platform.railway");
    assert_eq!(json["pattern_name"], "railway-api-database-variable-upsert");
}

#[test]
fn test_with_packs_checks_railway_api_backup_restore_payloads() {
    let cmd = r#"curl https://backboard.railway.app/graphql/v2 -d '{"query":"mutation { volumeInstanceBackupRestore(input:{volumeInstanceId:\"v\", backupId:\"b\"}) }"}'"#;

    let output = run_dcg_isolated(
        &[
            "test",
            "--format",
            "json",
            "--with-packs",
            "platform.railway",
            cmd,
        ],
        None,
    );

    assert_eq!(
        output.status.code(),
        Some(1),
        "Railway API volume backup restore should be blocked\nstdout: {}\nstderr: {}",
        stdout_text(&output),
        stderr_text(&output)
    );

    let json = parse_json(&output);
    assert_eq!(json["decision"], "deny");
    assert_eq!(json["pack_id"], "platform.railway");
    assert_eq!(json["pattern_name"], "railway-api-volume-backup-restore");
}

#[test]
fn test_with_packs_checks_railway_api_token_header_payloads() {
    let cmd = r#"curl https://api.example.com/graphql -H "Authorization: Bearer $RAILWAY_API_TOKEN" --data-binary '{"query":"mutation { projectDelete(id:\"p\") }"}'"#;

    let output = run_dcg_isolated(
        &[
            "test",
            "--format",
            "json",
            "--with-packs",
            "platform.railway",
            cmd,
        ],
        None,
    );

    assert_eq!(
        output.status.code(),
        Some(1),
        "Railway API mutation authenticated by token header should be blocked\nstdout: {}\nstderr: {}",
        stdout_text(&output),
        stderr_text(&output)
    );

    let json = parse_json(&output);
    assert_eq!(json["decision"], "deny");
    assert_eq!(json["pack_id"], "platform.railway");
    assert_eq!(json["pattern_name"], "railway-api-project-delete");
}

#[test]
fn test_with_packs_checks_railway_api_project_access_token_payloads() {
    let cmd = r#"curl https://api.example.com/graphql -H "Project-Access-Token: $PROJECT_ACCESS_TOKEN" --data-binary '{"query":"mutation { projectDelete(id:\"p\") }"}'"#;

    let output = run_dcg_isolated(
        &[
            "test",
            "--format",
            "json",
            "--with-packs",
            "platform.railway",
            cmd,
        ],
        None,
    );

    assert_eq!(
        output.status.code(),
        Some(1),
        "Railway API mutation authenticated by Project-Access-Token should be blocked\nstdout: {}\nstderr: {}",
        stdout_text(&output),
        stderr_text(&output)
    );

    let json = parse_json(&output);
    assert_eq!(json["decision"], "deny");
    assert_eq!(json["pack_id"], "platform.railway");
    assert_eq!(json["pattern_name"], "railway-api-project-delete");
}

#[test]
fn test_with_packs_checks_railway_api_multiline_payloads() {
    let cmd = "curl https://backboard.railway.app/graphql/v2 --data-binary '{\n\"query\":\"mutation { projectDelete(id:\\\"p\\\") }\"\n}'";

    let output = run_dcg_isolated(
        &[
            "test",
            "--format",
            "json",
            "--with-packs",
            "platform.railway",
            cmd,
        ],
        None,
    );

    assert_eq!(
        output.status.code(),
        Some(1),
        "Railway API mutation inside multiline payload should be blocked\nstdout: {}\nstderr: {}",
        stdout_text(&output),
        stderr_text(&output)
    );

    let json = parse_json(&output);
    assert_eq!(json["decision"], "deny");
    assert_eq!(json["pack_id"], "platform.railway");
    assert_eq!(json["pattern_name"], "railway-api-project-delete");
}

#[test]
fn test_with_packs_checks_railway_function_delete() {
    let output = run_dcg_isolated(
        &[
            "test",
            "--format",
            "json",
            "--with-packs",
            "platform.railway",
            "railway functions delete --function prod-worker --yes",
        ],
        None,
    );

    assert_eq!(
        output.status.code(),
        Some(1),
        "Railway function deletion should be blocked\nstdout: {}\nstderr: {}",
        stdout_text(&output),
        stderr_text(&output)
    );

    let json = parse_json(&output);
    assert_eq!(json["decision"], "deny");
    assert_eq!(json["pack_id"], "platform.railway");
    assert_eq!(json["pattern_name"], "railway-function-delete");
}

#[test]
fn test_with_packs_checks_gcloud_alpha_storage_delete() {
    let output = run_dcg_isolated(
        &[
            "test",
            "--format",
            "json",
            "--with-packs",
            "storage.gcs",
            "gcloud alpha --project prod storage buckets delete gs://prod-bucket --quiet",
        ],
        None,
    );

    assert_eq!(
        output.status.code(),
        Some(1),
        "gcloud alpha storage bucket deletion should be blocked\nstdout: {}\nstderr: {}",
        stdout_text(&output),
        stderr_text(&output)
    );

    let json = parse_json(&output);
    assert_eq!(json["decision"], "deny");
    assert_eq!(json["pack_id"], "storage.gcs");
    assert_eq!(json["pattern_name"], "gcloud-storage-buckets-delete");
}

#[test]
fn test_test_subcommand_help_text_includes_key_flags() {
    let output = run_dcg_isolated(&["help", "test"], None);
    let combined = format!("{}{}", stdout_text(&output), stderr_text(&output));

    assert!(
        matches!(output.status.code(), Some(0) | Some(2)),
        "help should exit with clap help code\nstdout: {}\nstderr: {}",
        stdout_text(&output),
        stderr_text(&output)
    );
    assert!(combined.contains("Usage: dcg test [OPTIONS] <COMMAND>"));
    assert!(combined.contains("--config"));
    assert!(combined.contains("--with-packs"));
    assert!(combined.contains("--format"));
    assert!(combined.contains("--heredoc-scan"));
}

#[test]
fn test_subcommand_help_flag_is_not_hijacked_by_top_level_help() {
    let output = run_dcg_isolated(&["simulate", "--help"], None);
    let combined = format!("{}{}", stdout_text(&output), stderr_text(&output));

    assert_eq!(
        output.status.code(),
        Some(0),
        "subcommand help should use clap's help exit code\nstdout: {}\nstderr: {}",
        stdout_text(&output),
        stderr_text(&output)
    );
    assert!(combined.contains("Usage: dcg simulate [OPTIONS]"));
    assert!(combined.contains("--max-command-bytes"));
}

#[test]
fn test_update_version_flag_is_not_hijacked_by_top_level_version() {
    let output = run_dcg_isolated(&["update", "--version", "v0.2.0", "--help"], None);
    let combined = format!("{}{}", stdout_text(&output), stderr_text(&output));

    assert_eq!(
        output.status.code(),
        Some(0),
        "update --version plus help should show update help, not top-level version\nstdout: {}\nstderr: {}",
        stdout_text(&output),
        stderr_text(&output)
    );
    assert!(combined.contains("Usage: dcg update [OPTIONS]"));
    assert!(combined.contains("--version <VERSION>"));
    assert!(!stdout_text(&output).starts_with(env!("CARGO_PKG_VERSION")));
}

#[test]
fn test_verbose_output_includes_diagnostics() {
    let output = run_dcg_isolated(&["test", "--verbose", "git reset --hard"], None);
    let stdout = stdout_text(&output);

    assert_eq!(
        output.status.code(),
        Some(1),
        "blocked command should exit 1 in verbose mode\nstderr: {}",
        stderr_text(&output)
    );
    assert!(
        stdout.contains("Reason:"),
        "expected Reason in verbose output"
    );
    assert!(
        stdout.contains("Result: BLOCKED"),
        "expected blocked result in verbose output"
    );
}
