//! #461: exercise the real hook, including pack gates and rule allowlisting.
//! The strings below are inputs to dcg, never executed as shell commands.

#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn home() -> tempfile::TempDir {
    let home = tempfile::tempdir().expect("isolated home");
    fs::create_dir_all(home.path().join("xdg/dcg")).expect("config directory");
    fs::write(home.path().join("config.toml"), "").expect("empty config");
    home
}

fn response(command: &str, home: &Path) -> String {
    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command }
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"))
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("xdg"))
        .env("DCG_CONFIG", home.join("config.toml"))
        .env("DCG_PENDING_EXCEPTIONS_PATH", home.join("pending.jsonl"))
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HOOK_TIMEOUT_MS", "30000")
        .env("DCG_AST_TIMEOUT_MS", "5000")
        .env_remove("DCG_FAIL_CLOSED")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hook");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(payload.to_string().as_bytes())
        .expect("send hook payload");
    let output = child.wait_with_output().expect("hook response");
    assert!(
        output.status.success(),
        "{command}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 hook output")
}

fn assert_denied(command: &str, home: &Path) {
    let output = response(command, home);
    assert!(
        output.contains(r#""permissionDecision":"deny""#),
        "{command}: {output}"
    );
    assert!(
        output.contains("credential-file-write"),
        "wrong rule for {command}: {output}"
    );
}

fn assert_allowed(command: &str, home: &Path) {
    let output = response(command, home);
    assert!(output.trim().is_empty(), "{command}: {output}");
}

#[test]
fn embedded_writes_reach_the_core_rule_through_the_hook() {
    let home = home();
    for command in [
        r#"python3 -c "open('/home/me/.ssh/authorized_keys','w').write('key')""#,
        r#"ruby -e "File.write('/home/me/.bashrc', 'export PATH=x')""#,
        r#"node -e "require('fs').writeFileSync('/home/me/.ssh/config', 'Host *')""#,
        r#"python3 -c "import io; io.open('/home/me/.aws/credentials', 'a')""#,
        r#"python3 -c "from pathlib import Path; Path('/home/me/.netrc').write_text('x')""#,
        r#"ruby -e "File.open('/home/me/.bashrc', 'r+') { |f| f.write('x') }""#,
        r#"node -e "const fs = require('fs'); fs.appendFileSync('/home/me/.ssh/known_hosts','x',{flag:'w'})""#,
        r#"node -e "require('fs').createWriteStream('/home/me/.ssh/known_hosts')""#,
        r#"env python3 -c "open('/home/me/.bashrc', 'w')""#,
        r#"true && ruby -e "File.write('/home/me/.bashrc', 'x')""#,
        "python3 <<'EOF'\nopen('/home/me/.bashrc', 'w')\nEOF",
        "ruby <<'EOF'\nFile.write('/home/me/.bashrc', 'x')\nEOF",
        "node <<'EOF'\nrequire('fs').writeFileSync('/home/me/.bashrc', 'x')\nEOF",
    ] {
        assert_denied(command, home.path());
    }
}

#[test]
fn credential_reads_and_append_only_known_hosts_remain_allowed() {
    let home = home();
    for command in [
        r#"python3 -c "print(open('/home/me/.ssh/authorized_keys').read())""#,
        r#"python3 -c "import io; print(io.open('/home/me/.aws/credentials', 'r').read())""#,
        r#"ruby -e "puts File.read('/home/me/.netrc')""#,
        r#"node -e "console.log(require('fs').readFileSync('/home/me/.ssh/config','utf8'))""#,
        r#"python3 -c "open('/home/me/.ssh/known_hosts','a').write('host')""#,
        r#"ruby -e "File.open('/home/me/.ssh/known_hosts','a') { |f| f.write('host') }""#,
        r#"node -e "require('fs').appendFileSync('/home/me/.ssh/known_hosts','host')""#,
        r#"node -e "require('fs').writeFileSync('/home/me/.ssh/known_hosts','host',{flag:'a'})""#,
        r#"node -e "require('fs').createWriteStream('/home/me/.ssh/known_hosts',{flags:'a'})""#,
        r#"python3 -c "open('/tmp/dcg-proposed-config','w').write('x')""#,
        r#"node -e "const store = require('unrelated'); store.writeFile('/home/me/.bashrc','x')""#,
        r#"echo "python3 -c \"open('/home/me/.bashrc','w')\"""#,
        "cat <<'EOF'\nFile.write('/home/me/.bashrc', 'x')\nEOF",
    ] {
        assert_allowed(command, home.path());
    }
}

#[test]
fn existing_allowlist_id_lifts_only_the_credential_rule() {
    let home = home();
    fs::write(
        home.path().join("xdg/dcg/allowlist.toml"),
        "[[allow]]\nrule = \"core.filesystem:credential-file-write\"\nreason = \"explicitly reviewed dotfile maintenance\"\n",
    )
    .expect("rule allowlist");
    for command in [
        r#"python3 -c "open('/home/me/.bashrc','w').write('x')""#,
        r#"ruby -e "File.write('/home/me/.bashrc','x')""#,
        r#"node -e "require('fs').writeFileSync('/home/me/.bashrc','x')""#,
    ] {
        assert_allowed(command, home.path());
    }
    let output = response("echo x > /etc/passwd", home.path());
    assert!(
        output.contains(r#""permissionDecision":"deny""#),
        "{output}"
    );
    assert!(output.contains("redirect-truncate-root-home"), "{output}");
}
