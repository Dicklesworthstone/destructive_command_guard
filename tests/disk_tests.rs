use std::process::Command;

fn dcg_binary() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // deps
    path.pop(); // debug
    path.push("dcg");
    path
}

fn run_hook(command: &str) -> String {
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": command,
        }
    });

    let mut child = Command::new(dcg_binary())
        .env("DCG_PACKS", "system.disk")
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
fn dd_dev_null_false_positive() {
    // Should ALLOW dd if=foo of=/dev/null
    let cmd = "dd if=zero.dat of=/dev/null bs=1M count=1";
    let output = run_hook(cmd);

    assert!(
        !output.contains("deny"),
        "False positive: '{cmd}' was blocked! Output: {output}"
    );
}

#[test]
fn dd_dev_block_device_blocked() {
    // Should BLOCK dd if=foo of=/dev/sda
    let cmd = "dd if=foo of=/dev/sda";
    let output = run_hook(cmd);

    assert!(output.contains("deny"), "Bypass: '{cmd}' was allowed!");
}
