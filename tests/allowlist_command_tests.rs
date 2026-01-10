use std::process::Command;
use std::io::Write;

fn dcg_binary() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // deps
    path.pop(); // debug
    path.push("dcg");
    path
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
fn test_exact_command_allowlist_ignored_bug() {
    let cmd = "git reset --hard";
    let allowlist = format!(r#"
[[allow]]
exact_command = "{}"
reason = "allowed explicitly"
"#, cmd);

    let output = run_hook_with_allowlist(cmd, &allowlist);
    
    // Currently, this should FAIL (be blocked) because ExactCommand is ignored.
    // If it is allowed (empty output), then it works (bug not present).
    // If it is blocked (contains "deny"), then bug is confirmed.
    
    if !output.contains("deny") {
        println!("Wait, it was allowed? Maybe I am wrong.");
    } else {
        println!("Confirmed: Command blocked despite exact_command allowlist.");
    }
    
    // We expect it to be allowed if the feature worked.
    // Asserting failure to confirm bug.
    assert!(output.contains("deny"), "Bug confirmed: ExactCommand is ignored");
}
