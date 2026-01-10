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
        .env("DCG_PACKS", "system.permissions")
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
fn chmod_false_positive_filename() {
    // Should ALLOW chmod 644 on a file named "file_777"
    // Current regex: r"chmod\s+.*777" might block this.
    let cmd = "chmod 644 file_777";
    let output = run_hook(cmd);

    if output.contains("deny") {
        panic!("False positive: '{}' was blocked! Output: {}", cmd, output);
    }
}

#[test]
fn chmod_recursive_false_positive_filename() {
    // Should ALLOW chmod -R 644 file_777 (file name contains 777)
    // Current regex: r"chmod\s+.*777" blocks this because safe pattern ignores -R
    let cmd = "chmod -R 644 file_777";
    let output = run_hook(cmd);

    if output.contains("deny") {
        panic!("False positive: '{}' was blocked! Output: {}", cmd, output);
    }
}

#[test]
fn chmod_recursive_bypass_long_flag() {
    // Should BLOCK chmod --recursive 755 /etc
    // Use 755 to avoid hitting the 777 rule
    let cmd = "chmod --recursive 755 /etc";
    let output = run_hook(cmd);

    if !output.contains("deny") {
        panic!("Bypass: '{}' was allowed!", cmd);
    }
}

#[test]
fn chmod_recursive_root_false_positive_home() {
    // Should ALLOW chmod -R 755 /home/user/project
    // Current regex: r"chmod\s+-[rR].*\s+/(?:$|[a-z])" blocks any / + lower letter
    let cmd = "chmod -R 755 /home/user/project";
    let output = run_hook(cmd);

    if output.contains("deny") {
        panic!("False positive: '{}' was blocked! Output: {}", cmd, output);
    }
}

#[test]
fn chmod_777_symbolic_bypass() {
    // Should BLOCK chmod a=rwx / (equivalent to 777)
    // Actually blocking symbolic 777 is hard regex-wise, but we should at least verify basic 777 detection
    // Let's test a simple bypass: chmod 0777 (octal)
    let cmd = "chmod 0777 /tmp/bad";
    let output = run_hook(cmd);

    // r"chmod\s+.*777" matches "0777" so this might pass (be blocked)
    if !output.contains("deny") {
        panic!("Bypass: '{}' was allowed!", cmd);
    }
}
