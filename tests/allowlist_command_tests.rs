use std::process::Command;

fn dcg_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

fn run_hook_with_allowlist(command: &str, allowlist_content: &str) -> String {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_dir = temp_dir.path().join("dcg");
    std::fs::create_dir_all(&config_dir).unwrap();
    let allowlist_path = config_dir.join("allowlist.toml");
    std::fs::write(&allowlist_path, allowlist_content).unwrap();

    // Create a fake home dir for user config loading
    let home_dir = temp_dir.path().join("home");
    let xdg_config_dir = temp_dir.path().join("xdg_config");
    let user_config_dir = xdg_config_dir.join("dcg");
    std::fs::create_dir_all(&user_config_dir).unwrap();
    std::fs::write(user_config_dir.join("allowlist.toml"), allowlist_content).unwrap();

    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": command,
        }
    });

    let mut child = Command::new(dcg_binary())
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .env("XDG_CONFIG_HOME", &xdg_config_dir)
        // Ensure system allowlist doesn't interfere
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "/nonexistent")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn dcg");

    {
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        serde_json::to_writer(stdin, &input).expect("failed to write json");
    }

    let output = child.wait_with_output().expect("failed to wait for dcg");
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn test_exact_command_allowlist_works() {
    let cmd = "git reset --hard";
    let allowlist = format!(
        r#"
[[allow]]
exact_command = "{cmd}"
reason = "allowed explicitly"
"#
    );

    let output = run_hook_with_allowlist(cmd, &allowlist);

    assert!(
        !output.contains("deny"),
        "ExactCommand allowlist should allow the command, but got denial: {output}",
    );
    assert!(
        output.is_empty(),
        "Expected empty output for allowed command"
    );
}

// Regression test for dcg#132: dcg used to block `ee preflight check --cmd
// "<destructive>"` because it substring-matched the destructive verb inside
// the analyzed argument. The argument is consumed as data by `ee`, not
// executed, so the call must be allowed through built-in inspection-wrapper
// exemption — WITHOUT requiring the user to maintain an allowlist entry.
#[test]
fn test_ee_preflight_check_with_destructive_cmd_argument_is_allowed_builtin() {
    // No allowlist content — relying entirely on the built-in exemption.
    let cmd = "ee preflight check --cmd \"git reset --hard HEAD~5\"";
    let output = run_hook_with_allowlist(cmd, "");

    assert!(
        !output.contains("deny"),
        "Built-in inspection-wrapper exemption should allow `ee preflight check --cmd <destructive>`, but got denial: {output}",
    );
    assert!(
        output.is_empty(),
        "Expected empty output for built-in inspection-wrapper exemption, got: {output}",
    );
}

// Regression test for dcg#132 anti-bypass: chaining a real destructive
// command after the inspected argument must still block, because at that
// point the destructive verb is no longer purely data.
#[test]
fn test_ee_preflight_check_with_chained_destructive_tail_is_still_blocked() {
    // No allowlist content — verifying default deny semantics still hold for
    // a chained command after the inspection wrapper.
    let cmd = "ee preflight check --cmd \"true\" ; rm -rf /";
    let output = run_hook_with_allowlist(cmd, "");

    assert!(
        output.contains("deny") || output.contains("permissionDecision"),
        "Chained destructive tail must still be blocked even after an inspection wrapper, but got: {output}",
    );
}

/// The bounded fallback must be addressable: reported, and grantable (#476).
///
/// A denial built by `denied_by_legacy` carried no `ruleId`, no `packId` and no
/// `severity`, so three of the fields AGENTS.md lists under "Key fields for
/// agent parsing" never reached the wire. The practical cost is that `ruleId`
/// is what an allowlist entry keys on, so this denial could only ever be waived
/// one command at a time with `dcg allow-once` and never granted.
///
/// Reporting an id is only half of it. The other half — asserted below — is
/// that granting the reported id actually changes the verdict; an id that is
/// reported but cannot be granted is the trap #470 describes, and would have
/// been a worse outcome than the blank field it replaced.
///
/// `heredoc.max_body_lines = 1` forces the incomplete extraction deterministically,
/// so this does not depend on the host being slow enough to time out.
fn run_fallback_hook(allowlist_content: &str) -> String {
    let temp_dir = tempfile::tempdir().unwrap();
    let home_dir = temp_dir.path().join("home");
    let xdg_config_dir = temp_dir.path().join("xdg_config");
    let user_config_dir = xdg_config_dir.join("dcg");
    std::fs::create_dir_all(&user_config_dir).unwrap();
    std::fs::create_dir_all(&home_dir).unwrap();
    std::fs::write(user_config_dir.join("allowlist.toml"), allowlist_content).unwrap();
    let config_path = temp_dir.path().join("config.toml");
    std::fs::write(&config_path, "[heredoc]\nmax_body_lines = 1\n").unwrap();

    // Two lines so the one-line limit truncates the extraction; the sink is
    // assembled so this file does not carry the literal call text.
    let body = format!("# setup\nimport shutil\n{}('/home/user')", "shutil.rmtree");
    let command = format!("python3 <<'PY'\n{body}\nPY");
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command },
    });

    let mut child = Command::new(dcg_binary())
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .env("XDG_CONFIG_HOME", &xdg_config_dir)
        .env("DCG_CONFIG", &config_path)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "/nonexistent")
        .env_remove("DCG_FAIL_CLOSED")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn dcg");
    {
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        serde_json::to_writer(stdin, &input).expect("failed to write json");
    }
    let output = child.wait_with_output().expect("failed to wait for dcg");
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn bounded_fallback_denial_is_reported_and_grantable_issue_476() {
    let denied = run_fallback_hook("");
    let json: serde_json::Value = serde_json::from_str(denied.trim()).unwrap_or_else(|error| {
        panic!("the bounded fallback must publish a decision ({error}): {denied:?}")
    });
    let out = &json["hookSpecificOutput"];
    assert_eq!(out["permissionDecision"], "deny");

    // The three fields that were absent.
    let rule_id = out["ruleId"].as_str().unwrap_or_default();
    assert_eq!(
        rule_id, "heredoc.shell:incomplete-analysis",
        "the bounded fallback must name its rule, or the denial cannot be \
         allowlisted at all: {denied}"
    );
    assert_eq!(out["packId"], "heredoc.shell", "denial: {denied}");
    assert_eq!(out["severity"], "high", "denial: {denied}");

    // And granting that exact id must work, or naming it achieved nothing.
    let granted = run_fallback_hook(&format!(
        "[[allow]]\nrule = \"{rule_id}\"\nreason = \"reviewed backstop\"\n"
    ));
    assert!(
        granted.trim().is_empty(),
        "granting the reported rule id must allow the command; got: {granted}"
    );

    // Countermetric: an unrelated grant must not allow it, so the row above is
    // measuring this rule rather than the allowlist file merely existing.
    let unrelated =
        run_fallback_hook("[[allow]]\nrule = \"core.git:reset-hard\"\nreason = \"unrelated\"\n");
    assert!(
        !unrelated.trim().is_empty(),
        "an unrelated grant must leave the fallback denying; got: {unrelated}"
    );
}
