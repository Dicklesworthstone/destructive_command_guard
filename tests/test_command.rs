#![allow(clippy::uninlined_format_args)]
//! Focused coverage for `dcg test` command behavior.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// Path to the dcg binary compiled for this test run.
fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// Run dcg with an isolated HOME/XDG config to avoid machine-specific allowlists.
fn run_dcg_isolated(args: &[&str], cwd: Option<&Path>) -> Output {
    run_dcg_isolated_with_env(args, cwd, &[])
}

fn run_dcg_isolated_with_env(
    args: &[&str],
    cwd: Option<&Path>,
    extra_env: &[(&str, &Path)],
) -> Output {
    let home = tempfile::tempdir().expect("temp home");
    run_dcg_with_home(args, cwd, home.path(), extra_env)
}

fn run_dcg_with_home(
    args: &[&str],
    cwd: Option<&Path>,
    home: &Path,
    extra_env: &[(&str, &Path)],
) -> Output {
    let xdg = home.join("xdg");
    std::fs::create_dir_all(&xdg).expect("create xdg config dir");

    let mut cmd = Command::new(dcg_binary());
    cmd.args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("TEMP", home)
        .env("TMP", home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "");

    for (key, value) in extra_env {
        cmd.env(key, value);
    }

    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }

    cmd.output().expect("run dcg")
}

fn run_dcg_isolated_with_stdin(args: &[&str], input: &str) -> Output {
    use std::io::Write as _;

    let home = tempfile::tempdir().expect("temp home");
    let xdg = home.path().join("xdg");
    std::fs::create_dir_all(&xdg).expect("create xdg config dir");

    let mut child = Command::new(dcg_binary())
        .args(args)
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("TEMP", home.path())
        .env("TMP", home.path())
        .env("XDG_CONFIG_HOME", &xdg)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcg");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(input.as_bytes())
        .expect("write command to dcg stdin");
    child.wait_with_output().expect("wait for dcg")
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
fn test_stdin_keeps_blocked_command_off_the_cli_arguments() {
    let output = run_dcg_isolated_with_stdin(
        &[
            "test",
            "--stdin",
            "--format",
            "json",
            "--with-packs",
            "careful_company_running_windows.email",
        ],
        "Send-MailMessage -To outside@example.test -Body dossier\r\n",
    );

    assert_eq!(
        output.status.code(),
        Some(1),
        "stdin candidate should be denied\nstdout: {}\nstderr: {}",
        stdout_text(&output),
        stderr_text(&output)
    );
    let json = parse_json(&output);
    assert_eq!(json["decision"], "deny");
    assert_eq!(json["pack_id"], "careful_company_running_windows.email");
    assert_eq!(json["pattern_name"], "send-mailmessage");
}

#[test]
fn test_stdin_preserves_multiline_commands_and_rejects_empty_input() {
    let multiline = "echo preparing\ngit reset --hard\n";
    let blocked = run_dcg_isolated_with_stdin(&["test", "--stdin", "--format", "json"], multiline);
    assert_eq!(
        blocked.status.code(),
        Some(1),
        "multiline stdin candidate should be denied\nstdout: {}\nstderr: {}",
        stdout_text(&blocked),
        stderr_text(&blocked)
    );
    let blocked_json = parse_json(&blocked);
    assert_eq!(blocked_json["pattern_name"], "reset-hard");

    let empty = run_dcg_isolated_with_stdin(&["test", "--stdin"], "");
    assert!(!empty.status.success());
    assert!(stderr_text(&empty).contains("stdin did not contain a command"));
}

#[test]
fn test_stdin_and_positional_command_are_mutually_exclusive() {
    let output = run_dcg_isolated(&["test", "--stdin", "git status"], None);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr_text(&output).contains("cannot be used with"));
}

#[test]
fn test_printf_data_after_shell_reserved_words_is_allowed() {
    for command in [
        r"if true; then printf '%-50s -> %s\n' a b; fi; mv x y",
        r"while false; do printf '%-50s -> %s\n' a b; done; mv x y",
    ] {
        let output = run_dcg_isolated(&["test", "--format", "json", command], None);

        assert_eq!(
            output.status.code(),
            Some(0),
            "quoted printf data must not be parsed as a redirect\ncommand: {command}\nstdout: {}\nstderr: {}",
            stdout_text(&output),
            stderr_text(&output)
        );
        assert_eq!(parse_json(&output)["decision"], "allow");
    }
}

#[test]
fn test_real_dynamic_redirect_after_shell_reserved_word_is_blocked() {
    let command = r#"if true; then printf '%s' x > "$SOMEDIR/x"; fi"#;
    let output = run_dcg_isolated(&["test", "--format", "json", command], None);

    assert_eq!(
        output.status.code(),
        Some(1),
        "a real dynamic redirect must remain visible after masking printf data\nstdout: {}\nstderr: {}",
        stdout_text(&output),
        stderr_text(&output)
    );
    let json = parse_json(&output);
    assert_eq!(json["decision"], "deny");
    assert_eq!(json["pack_id"], "core.filesystem");
    assert_eq!(json["pattern_name"], "redirect-truncate-dynamic-path");
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
fn test_untrusted_project_allowlist_cannot_allow_blocked_command() {
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
        Some(1),
        "auto-discovered project allowlist must be inactive\nstdout: {}\nstderr: {}",
        stdout_text(&output),
        stderr_text(&output)
    );

    let json = parse_json(&output);
    assert_eq!(json["decision"], "deny");
}

#[test]
fn test_explicitly_trusted_project_policy_activates_project_allowlist() {
    let repo = tempfile::tempdir().expect("temp repo");
    std::fs::create_dir_all(repo.path().join(".git")).expect("create .git marker");
    std::fs::create_dir_all(repo.path().join(".dcg")).expect("create .dcg dir");
    let project_config = repo.path().join(".dcg.toml");
    std::fs::write(&project_config, "").expect("write reviewed project config");
    std::fs::write(
        repo.path().join(".dcg").join("allowlist.toml"),
        r#"
[[allow]]
exact_command = "git reset --hard"
reason = "explicitly trusted project fixture"
"#,
    )
    .expect("write allowlist");

    let output = run_dcg_isolated_with_env(
        &["test", "--format", "json", "git reset --hard"],
        Some(repo.path()),
        &[("DCG_CONFIG", project_config.as_path())],
    );

    assert_eq!(
        output.status.code(),
        Some(0),
        "explicit project-policy trust should activate its allowlist\nstdout: {}\nstderr: {}",
        stdout_text(&output),
        stderr_text(&output)
    );

    let json = parse_json(&output);
    assert_eq!(json["decision"], "allow");
}

#[test]
fn test_missing_project_config_cannot_activate_sibling_allowlist() {
    let repo = tempfile::tempdir().expect("temp repo");
    std::fs::create_dir_all(repo.path().join(".git")).expect("create .git marker");
    std::fs::create_dir_all(repo.path().join(".dcg")).expect("create .dcg dir");
    let missing_project_config = repo.path().join(".dcg.toml");
    std::fs::write(
        repo.path().join(".dcg").join("allowlist.toml"),
        r#"
[[allow]]
exact_command = "git reset --hard"
reason = "must remain inactive without a regular config file"
"#,
    )
    .expect("write allowlist");

    let output = run_dcg_isolated_with_env(
        &["test", "--format", "json", "git reset --hard"],
        Some(repo.path()),
        &[("DCG_CONFIG", missing_project_config.as_path())],
    );

    assert_eq!(
        output.status.code(),
        Some(1),
        "a missing selected config is not a trust signal\nstdout: {}\nstderr: {}",
        stdout_text(&output),
        stderr_text(&output)
    );
    assert_eq!(parse_json(&output)["decision"], "deny");
}

#[test]
fn test_project_allowlist_inspection_marks_untrusted_file_inactive() {
    let repo = tempfile::tempdir().expect("temp repo");
    std::fs::create_dir_all(repo.path().join(".git")).expect("create .git marker");
    std::fs::create_dir_all(repo.path().join(".dcg")).expect("create .dcg dir");
    std::fs::write(
        repo.path().join(".dcg").join("allowlist.toml"),
        r#"
[[allow]]
exact_command = "git reset --hard"
reason = "inactive inspection fixture"
"#,
    )
    .expect("write allowlist");

    let effective = run_dcg_isolated(
        &["allowlist", "list", "--format", "json"],
        Some(repo.path()),
    );
    assert!(
        effective.status.success(),
        "stderr: {}",
        stderr_text(&effective)
    );
    assert_eq!(
        parse_json(&effective),
        serde_json::json!([]),
        "default list must expose effective layers only"
    );

    let raw_project = run_dcg_isolated(
        &["allowlist", "list", "--project", "--format", "json"],
        Some(repo.path()),
    );
    assert!(
        raw_project.status.success(),
        "stderr: {}",
        stderr_text(&raw_project)
    );
    let entries = parse_json(&raw_project);
    assert_eq!(entries.as_array().map(Vec::len), Some(1));
    assert_eq!(entries[0]["layer"], "project");
    assert_eq!(entries[0]["effective"], false);
    assert_eq!(entries[0]["status"], "inactive_untrusted_project");

    let validation = run_dcg_isolated(&["allowlist", "validate", "--project"], Some(repo.path()));
    assert!(
        validation.status.success(),
        "stderr: {}",
        stderr_text(&validation)
    );
    assert!(stdout_text(&validation).contains("INACTIVE:"));
}

#[test]
fn test_allowlist_add_defaults_to_user_and_untrusted_project_write_is_refused() {
    let repo = tempfile::tempdir().expect("temp repo");
    let home = tempfile::tempdir().expect("temp home");
    std::fs::create_dir_all(repo.path().join(".git")).expect("create .git marker");

    let default_add = run_dcg_with_home(
        &[
            "allowlist",
            "add",
            "core.git:reset-hard",
            "--reason",
            "user-owned fixture",
        ],
        Some(repo.path()),
        home.path(),
        &[],
    );
    assert!(
        default_add.status.success(),
        "stdout: {}\nstderr: {}",
        stdout_text(&default_add),
        stderr_text(&default_add)
    );
    let user_allowlist = home.path().join("xdg/dcg/allowlist.toml");
    assert!(user_allowlist.is_file());
    assert!(
        std::fs::read_to_string(&user_allowlist)
            .expect("read user allowlist")
            .contains("core.git:reset-hard")
    );
    assert!(!repo.path().join(".dcg/allowlist.toml").exists());

    let applied = run_dcg_with_home(
        &["test", "--format", "json", "git reset --hard"],
        Some(repo.path()),
        home.path(),
        &[],
    );
    assert!(
        applied.status.success(),
        "new user allowlist entry must be active\nstdout: {}\nstderr: {}",
        stdout_text(&applied),
        stderr_text(&applied)
    );
    assert_eq!(parse_json(&applied)["allowlist"]["layer"], "user");

    let refused = run_dcg_with_home(
        &[
            "allowlist",
            "add",
            "core.git:reset-hard",
            "--reason",
            "must not enter repository policy",
            "--project",
        ],
        Some(repo.path()),
        home.path(),
        &[],
    );
    assert!(!refused.status.success());
    let refusal = format!("{}{}", stdout_text(&refused), stderr_text(&refused));
    assert!(refusal.contains("Project allowlists are inactive"));
    assert!(refusal.contains("--path"));
    assert!(refusal.contains("/**"));
    assert!(!repo.path().join(".dcg/allowlist.toml").exists());
}

#[test]
fn test_prune_never_rewrites_inactive_project_allowlist() {
    let repo = tempfile::tempdir().expect("temp repo");
    std::fs::create_dir_all(repo.path().join(".git")).expect("create .git marker");
    std::fs::create_dir_all(repo.path().join(".dcg")).expect("create .dcg dir");
    let project_allowlist = repo.path().join(".dcg/allowlist.toml");
    let original = r#"
[[allow]]
exact_command = "git reset --hard"
reason = "expired inactive fixture"
expires_at = "2000-01-01T00:00:00Z"
"#;
    std::fs::write(&project_allowlist, original).expect("write allowlist");

    let default_prune = run_dcg_isolated(&["allowlist", "prune"], Some(repo.path()));
    assert!(
        default_prune.status.success(),
        "stderr: {}",
        stderr_text(&default_prune)
    );
    assert_eq!(
        std::fs::read_to_string(&project_allowlist).expect("read unchanged project allowlist"),
        original
    );

    let refused = run_dcg_isolated(&["allowlist", "prune", "--project"], Some(repo.path()));
    assert!(!refused.status.success());
    assert_eq!(
        std::fs::read_to_string(&project_allowlist).expect("read refused project allowlist"),
        original
    );

    let dry_run = run_dcg_isolated(
        &[
            "allowlist",
            "prune",
            "--project",
            "--dry-run",
            "--format",
            "json",
        ],
        Some(repo.path()),
    );
    assert!(
        dry_run.status.success(),
        "stderr: {}",
        stderr_text(&dry_run)
    );
    let report = parse_json(&dry_run);
    assert_eq!(
        report["project_policy_status"],
        "inactive_untrusted_project"
    );
    assert_eq!(report["pruned"], 1);
    assert_eq!(
        std::fs::read_to_string(&project_allowlist).expect("read dry-run project allowlist"),
        original
    );
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
fn test_documented_mailer_filename_override_blocks_only_that_filename() {
    let temp = tempfile::tempdir().expect("temp dir");
    let config_path = temp.path().join("custom.toml");
    std::fs::write(
        &config_path,
        r#"
[overrides]
block = [
  { pattern = '(?i)\bsend-dossier\.ps1\b', reason = "Daily dossier mail is paused pending review" },
]
"#,
    )
    .expect("write config");
    let config_arg = config_path.to_string_lossy().to_string();

    let blocked = run_dcg_isolated(
        &[
            "test",
            "--format",
            "json",
            "--config",
            config_arg.as_str(),
            r".\send-dossier.ps1",
        ],
        None,
    );
    assert_eq!(
        blocked.status.code(),
        Some(1),
        "documented mailer override should deny the script\nstdout: {}\nstderr: {}",
        stdout_text(&blocked),
        stderr_text(&blocked)
    );
    assert!(
        stdout_text(&blocked).contains("Daily dossier mail is paused pending review"),
        "block reason should survive config parsing"
    );

    let allowed = run_dcg_isolated(
        &[
            "test",
            "--format",
            "json",
            "--config",
            config_arg.as_str(),
            r".\show-dossier.ps1",
        ],
        None,
    );
    assert_eq!(
        allowed.status.code(),
        Some(0),
        "a different script filename should remain allowed\nstdout: {}\nstderr: {}",
        stdout_text(&allowed),
        stderr_text(&allowed)
    );
}

#[test]
fn test_untrusted_project_config_cannot_allow_blocked_command() {
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
        Some(1),
        "auto-discovered project config must not grant trust\nstdout: {}\nstderr: {}",
        stdout_text(&output),
        stderr_text(&output)
    );

    let json = parse_json(&output);
    assert_eq!(json["decision"], "deny");
}

#[test]
fn test_untrusted_project_config_can_enable_builtin_protection() {
    let repo = tempfile::tempdir().expect("temp repo");
    std::fs::create_dir_all(repo.path().join(".git")).expect("create .git marker");
    std::fs::write(
        repo.path().join(".dcg.toml"),
        r#"
[packs]
enabled = ["database.postgresql"]
"#,
    )
    .expect("write project config");

    let output = run_dcg_isolated(
        &["test", "--format", "json", "dropdb project-policy-probe"],
        Some(repo.path()),
    );

    assert_eq!(
        output.status.code(),
        Some(1),
        "auto-discovered project config should retain built-in pack hardening\nstdout: {}\nstderr: {}",
        stdout_text(&output),
        stderr_text(&output)
    );

    let json = parse_json(&output);
    assert_eq!(json["decision"], "deny");
    assert_eq!(json["pack_id"], "database.postgresql");
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
    assert!(combined.contains("Usage: dcg test [OPTIONS] [COMMAND]"));
    assert!(combined.contains("--stdin"));
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
