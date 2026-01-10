//! Regression tests for security bypasses fixed in Jan 2025.
//!
//! Covers:
//! - Heredoc spaced delimiters (git_safety_guard-audit-2025-01-10)
//! - Quoted subcommands/binaries
//! - Wrapper/path obfuscation

use std::io::Write;
use std::path::Path;
use std::process::Command;

fn run_dcg(input_json: &str) -> bool {
    let binary_path = Path::new("target/release/dcg");
    if !binary_path.exists() {
        // Fallback for different CWD
        if Path::new("../target/release/dcg").exists() {
            return run_dcg_path("../target/release/dcg", input_json);
        }
        panic!("dcg binary not found. Run 'cargo build --release' first.");
    }
    run_dcg_path(binary_path.to_str().unwrap(), input_json)
}

fn run_dcg_path(binary_path: &str, input_json: &str) -> bool {
    let mut child = Command::new(binary_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn dcg");

    {
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        stdin
            .write_all(format!("{input_json}\n").as_bytes())
            .expect("failed to write to stdin");
    }

    let output = child.wait_with_output().expect("failed to read stdout");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Check for denial JSON
    if !stdout.contains(r#"permissionDecision":"deny"#) {
        println!("DCG Output (stdout):\n{stdout}");
        println!(
            "DCG Output (stderr):\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return false;
    }
    true
}

fn wrap_cmd(cmd: &str) -> String {
    let escaped_cmd = cmd.replace('"', "\\\"").replace('\n', "\\n");
    format!(r#"{{"tool_name":"Bash","tool_input":{{"command":"{escaped_cmd}"}}}}"#)
}

#[test]
fn test_heredoc_spaced_delimiter_bypass() {
    let cmd = "python3 << \"EOF SPACE\"\nimport shutil\nshutil.rmtree('/tmp/test')\nEOF SPACE";
    assert!(
        run_dcg(&wrap_cmd(cmd)),
        "Heredoc with spaced delimiter should be BLOCKED"
    );
}

#[test]
fn test_quoted_subcommand_bypass() {
    let cmd = "git \"reset\" --hard";
    assert!(
        run_dcg(&wrap_cmd(cmd)),
        "Quoted subcommand 'git \"reset\"' should be BLOCKED"
    );
}

#[test]
fn test_sudo_absolute_path_bypass() {
    let cmd = "sudo /bin/git reset --hard";
    assert!(
        run_dcg(&wrap_cmd(cmd)),
        "sudo + absolute path should be BLOCKED"
    );
}

#[test]
fn test_env_absolute_path_bypass() {
    let cmd = "env /usr/bin/git reset --hard";
    assert!(
        run_dcg(&wrap_cmd(cmd)),
        "env + absolute path should be BLOCKED"
    );
}

#[test]
fn test_quoted_binary_bypass() {
    let cmd = "\"git\" reset --hard";
    assert!(run_dcg(&wrap_cmd(cmd)), "Quoted binary should be BLOCKED");
}

#[test]
fn test_complex_quoting_bypass() {
    let cmd = "sudo \"/usr/bin/git\" \"reset\" --hard";
    assert!(
        run_dcg(&wrap_cmd(cmd)),
        "Complex quoting and wrappers should be BLOCKED"
    );
}
