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
fn git_global_flag_bypass() {
    // This command is destructive but currently bypassed because regex expects "git reset" directly
    let cmd = "git -C /tmp reset --hard";
    let output = run_hook(cmd);

    if output.trim().is_empty() {
        panic!("Bypass confirmed: '{}' was allowed!", cmd);
    }

    assert!(output.contains("deny"), "Should be denied");
}

#[test]
fn git_work_tree_bypass() {
    let cmd = "git --work-tree=/tmp clean -fd";
    let output = run_hook(cmd);

    if output.trim().is_empty() {
        panic!("Bypass confirmed: '{}' was allowed!", cmd);
    }

    assert!(output.contains("deny"), "Should be denied");
}
