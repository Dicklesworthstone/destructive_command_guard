//! End-to-end coverage for `core.filesystem:credential-file-write`.
//!
//! Runs the real binary in hook mode against an isolated `HOME` so the
//! verdicts below are exactly what a harness sees: writes to credential,
//! private-key, login-shell startup, and system authentication files are
//! denied by this rule whether the file exists or not and for every writer
//! spelling, while reads, `chmod`, the `*.pub` and `known_hosts` neighbours,
//! and unrelated files keep their ordinary verdicts. A user allowlist entry
//! for the rule lifts exactly this rule and nothing else.

#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Allow,
    Deny(&'static str),
}

/// Rule names a denial can be attributed to in these fixtures.
const RULES: &[&str] = &[
    "credential-file-write",
    "redirect-truncate-root-home",
    "redirect-truncate-dynamic-path",
    "mv-sensitive-source-root-home",
    "mv-dynamic-path",
    "dd-overwrite-root-home",
    "sed-exec-unverified",
];

/// Evaluate one shell command in hook mode with `home` as `$HOME`.
fn verdict(command: &str, home: &Path) -> Verdict {
    let config_path = home.join("dcg-test-config.toml");
    if !config_path.exists() {
        fs::write(&config_path, "").expect("write empty config");
    }
    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command }
    })
    .to_string();

    let mut child = Command::new(dcg_binary())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("xdg_config"))
        .env("DCG_CONFIG", &config_path)
        .env(
            "DCG_PENDING_EXCEPTIONS_PATH",
            home.join("pending_exceptions.jsonl"),
        )
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .env_remove("DCG_FAIL_CLOSED")
        .spawn()
        .expect("spawn dcg");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    let output = child.wait_with_output().expect("wait for dcg");
    assert_eq!(
        output.status.code(),
        Some(0),
        "hook protocol exit code for {command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.contains(r#""permissionDecision":"deny""#) {
        let rule = RULES
            .iter()
            .copied()
            .find(|rule| stdout.contains(rule))
            .unwrap_or_else(|| panic!("unexpected rule for {command:?}: {stdout}"));
        Verdict::Deny(rule)
    } else {
        assert!(
            stdout.trim().is_empty(),
            "allow must be an empty response for {command:?}: {stdout}"
        );
        Verdict::Allow
    }
}

/// Every writer spelling the rule covers, for one target path.
fn writers(path: &str) -> Vec<String> {
    vec![
        format!("echo x > {path}"),
        format!("echo x >> {path}"),
        format!("printf x >| {path}"),
        format!("echo x &> {path}"),
        format!("echo x 2> {path}"),
        format!("cat <<EOF > {path}\nline\nEOF"),
        format!("echo x | tee {path}"),
        format!("echo x | tee -a {path}"),
        format!("cp /tmp/src {path}"),
        format!("mv /tmp/src {path}"),
        format!("install -m 600 /tmp/src {path}"),
        format!("ln -sf /tmp/src {path}"),
        format!("dd if=/tmp/src of={path}"),
        format!("sed -i 's/a/b/' {path}"),
        format!("perl -pi -e 's/a/b/' {path}"),
    ]
}

fn fixture_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().expect("temp home");
    let root = home.path();
    for dir in [
        ".ssh",
        ".aws",
        ".config/gh",
        ".gnupg",
        ".bashrc.d",
        ".claude",
        "xdg_config/dcg",
    ] {
        fs::create_dir_all(root.join(dir)).expect("fixture dir");
    }
    for (file, content) in [
        (".ssh/authorized_keys", "ssh-ed25519 AAAA existing"),
        (".ssh/known_hosts", "host ssh-ed25519 AAAA"),
        (".ssh/id_ed25519.pub", "ssh-ed25519 AAAA"),
        (".zshrc", "export EXISTING=1"),
        (".aws/credentials", "[default]"),
        ("notes.txt", "notes"),
    ] {
        fs::write(root.join(file), content).expect("fixture file");
    }
    home
}

fn fixture_bytes(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut seen = Vec::new();
    fn walk(dir: &Path, root: &Path, seen: &mut Vec<(String, Vec<u8>)>) {
        for entry in fs::read_dir(dir).expect("read fixture dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                walk(&path, root, seen);
            } else {
                let relative = path
                    .strip_prefix(root)
                    .expect("under root")
                    .to_string_lossy()
                    .into_owned();
                // dcg's own state (the empty config, the pending allow-once
                // store) is not a fixture.
                if relative.starts_with("xdg_config")
                    || relative == "dcg-test-config.toml"
                    || relative == "pending_exceptions.jsonl"
                {
                    continue;
                }
                seen.push((relative, fs::read(&path).expect("read fixture")));
            }
        }
    }
    walk(root, root, &mut seen);
    seen.sort();
    seen
}

#[test]
fn credential_file_writes_are_denied_absent_or_existing_for_every_writer() {
    let home = fixture_home();
    let home = home.path();
    let before = fixture_bytes(home);

    // Existing and absent targets alike, across the whole list.
    let targets = [
        "~/.ssh/authorized_keys", // existing
        "~/.ssh/config",          // absent
        "~/.ssh/id_ed25519",      // absent private key
        "~/.zshrc",               // existing
        "~/.bashrc",              // absent
        "~/.zshenv",
        "~/.profile",
        "~/.bash_profile",
        "~/.zprofile",
        "~/.bashrc.d/10-path.sh",
        "~/.zshrc.d/aliases.zsh",
        "~/.aws/credentials", // existing
        "~/.aws/config",      // absent
        "~/.netrc",
        "~/.git-credentials",
        "~/.npmrc",
        "~/.pypirc",
        "~/.docker/config.json",
        "~/.kube/config",
        "~/.gnupg/gpg-agent.conf",
        "~/.config/gh/hosts.yml",
        "/etc/sudoers",
        "/etc/sudoers.d/agent",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/ssh/sshd_config",
        "/etc/ssh/sshd_config.d/10-root.conf",
    ];
    for target in targets {
        for command in writers(target) {
            assert_eq!(
                verdict(&command, home),
                Verdict::Deny("credential-file-write"),
                "{command}"
            );
        }
    }

    // Spellings of the same files.
    for command in [
        "echo x >> $HOME/.zshrc",
        "echo x >> \"$HOME/.zshrc\"",
        "echo x >> ${HOME}/.ssh/authorized_keys",
        "echo x >> ~/.zsh\"rc\"",
        "echo x >> ~/'.zshrc'",
        "echo x >> ~/.zshr\\c",
        "echo x >> ~/.zshr{c..c}",
        "echo x >> ~/.zshrc{,}",
        "echo x >> ~/{.zshrc,absent}",
        "echo x >> ~/.ssh/id_*",
        "echo x >> ~/.ssh/../.zshrc",
        "echo x >> /home/somebody/.zshrc",
        "echo x >> /Users/somebody/.ssh/authorized_keys",
        "echo x >> ~root/.ssh/authorized_keys",
        "echo x | sudo tee -a /etc/sudoers.d/agent",
        "sudo -u root tee /etc/passwd",
        "echo x | t''ee ~/.zshrc",
        "echo x | \\tee ~/.zshrc",
        "bash -c 'echo x >> ~/.zshrc'",
        "cd /tmp && echo x >> ~/.npmrc",
        "true; echo x >> ~/.npmrc",
        "cp id_ed25519 ~/.ssh/",
        "cp -t ~/.ssh id_ed25519",
        "cp credentials ~/.aws/",
        "cp .zshrc ~/",
        "cp -r dotfiles/. ~/",
        "cp -- src ~/.zshrc",
        "tee -- ~/.zshrc",
        "sed -i -- 's/a/b/' ~/.zshrc",
        "echo x > /tmp/ok > ~/.zshrc",
        "echo x | tee /tmp/ok ~/.npmrc",
    ] {
        assert_eq!(
            verdict(command, home),
            Verdict::Deny("credential-file-write"),
            "{command}"
        );
    }

    // The trust store may be appended to (what ssh does) but not replaced.
    for command in [
        "echo x >> ~/.ssh/known_hosts",
        "ssh-keyscan host >> ~/.ssh/known_hosts",
        "echo x | tee -a ~/.ssh/known_hosts",
    ] {
        assert_eq!(verdict(command, home), Verdict::Allow, "{command}");
    }
    for command in [
        "echo x > ~/.ssh/known_hosts",
        "echo x | tee ~/.ssh/known_hosts",
        "cp /tmp/kh ~/.ssh/known_hosts",
        "sed -i '/host/d' ~/.ssh/known_hosts",
    ] {
        assert_eq!(
            verdict(command, home),
            Verdict::Deny("credential-file-write"),
            "{command}"
        );
    }

    // Reads, permission changes, public keys, and unrelated files.
    for command in [
        "cat ~/.ssh/config",
        "cat ~/.zshrc",
        "grep -rn Host ~/.ssh/",
        "diff ~/.zshrc /tmp/x",
        "source ~/.zshrc",
        "ssh -F ~/.ssh/config host",
        "chmod 600 ~/.ssh/authorized_keys",
        "chmod 700 ~/.ssh",
        "ls -la ~/.ssh",
        "cp ~/.ssh/config /tmp/backup",
        "cat ~/.ssh/id_ed25519.pub",
        "echo x >> ~/.ssh/id_ed25519.pub",
        "echo x >> ~/notes.txt",
        "echo x > ~/.claude/absent.txt",
        "echo x >> ~/.config/gh/config.yml",
        "cp report.txt ~/",
        "cp *.png ~/",
        "cp -r build ~/.claude/",
        "sed -n '/PATH/p' ~/.zshrc",
        "sed -i 's/a/b/' ~/notes.txt",
        "tee /tmp/out < ~/.zshrc",
        "echo 'echo x >> ~/.zshrc'",
        "cat <<'EOF'\necho x >> ~/.zshrc\nEOF",
        "install -d -m 700 ~/.ssh",
        "mkdir -p ~/.ssh",
        "echo x >> ~/notes-{a,b}.txt",
    ] {
        assert_eq!(verdict(command, home), Verdict::Allow, "{command}");
    }

    // Neighbours keep their ordinary verdicts: an existing unlisted file is
    // still a truncation, an absent one is still creation.
    assert_eq!(
        verdict("echo x > ~/notes.txt", home),
        Verdict::Deny("redirect-truncate-root-home")
    );
    assert_eq!(
        verdict("echo x > ~/.ssh/id_ed25519.pub", home),
        Verdict::Deny("redirect-truncate-root-home")
    );
    assert_eq!(verdict("echo x > ~/.ssh/absent.pub", home), Verdict::Allow);
    assert_eq!(
        verdict("echo x > /etc/hosts", home),
        Verdict::Deny("redirect-truncate-root-home")
    );

    // Evaluating never touched the fixtures.
    assert_eq!(fixture_bytes(home), before);
    assert!(!home.join(".ssh/config").exists());
    assert!(!home.join(".npmrc").exists());
}

#[test]
fn allowlisting_the_rule_lifts_only_that_rule() {
    let home = fixture_home();
    let home = home.path();
    fs::write(
        home.join("xdg_config/dcg/allowlist.toml"),
        "[[allow]]\nrule = \"core.filesystem:credential-file-write\"\nreason = \"this project manages its own dotfiles\"\n",
    )
    .expect("write allowlist");

    // The credential rule stands down for an absent and an appended file.
    assert_eq!(verdict("echo x >> ~/.npmrc", home), Verdict::Allow);
    assert_eq!(verdict("echo x >> ~/.zshrc", home), Verdict::Allow);
    assert_eq!(
        verdict("echo x | tee -a ~/.ssh/config", home),
        Verdict::Allow
    );
    // Truncating an EXISTING file is still the redirect rule's call.
    assert_eq!(
        verdict("echo x > ~/.zshrc", home),
        Verdict::Deny("redirect-truncate-root-home")
    );
    assert_eq!(
        verdict("echo x > /etc/passwd", home),
        Verdict::Deny("redirect-truncate-root-home")
    );
}
