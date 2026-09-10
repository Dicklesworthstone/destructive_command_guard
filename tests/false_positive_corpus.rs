//! A corpus of ordinary developer command lines that must never be denied.
//!
//! Five false-positive reports landed within twenty-four hours (#401, #402,
//! #403, #404, #405). Each had its own mechanism, but they shared a shape: an
//! operand dcg could not resolve — a `$dir` in `git -C`, a quoted payload's
//! own redirect, a CSS class that spells a SQL keyword, a PowerShell parameter
//! read as a cluster of short flags — was allowed to condemn a command whose
//! *verb* was plainly read-only. Per-rule regression tests pin each mechanism;
//! this file pins the class, at the surface that enforces.
//!
//! Everything here runs the real binary in hook mode with **every pack
//! category enabled**, which is deliberately far stricter than any default
//! configuration: a rule that only fires for `database.postgresql` users still
//! has to keep its hands off a React edit. The `MUST_DENY` control list at the
//! bottom is what stops this file from passing by turning dcg off.

#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

/// Every pack category the registry ships, so the corpus is judged by the
/// strictest configuration dcg can be given.
const ALL_PACK_CATEGORIES: &str = r#"[packs]
enabled = [
    "apigateway", "backup", "careful_company_running_windows", "cdn", "cicd",
    "cloud", "containers", "core", "database", "dns", "email", "featureflags",
    "infrastructure", "kubernetes", "loadbalancer", "messaging", "monitoring",
    "package_managers", "payment", "platform", "remote", "search",
    "secret_disclosure", "secrets", "storage", "strict_git", "system",
    "windows",
]
"#;

fn hook_denies(command: &str, home: &Path, config: &Path) -> Option<String> {
    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "cwd": home.to_string_lossy(),
    })
    .to_string();

    let mut child = Command::new(dcg_binary())
        .arg("hook")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("xdg_config"))
        .env("DCG_CONFIG", config)
        .env(
            "DCG_PENDING_EXCEPTIONS_PATH",
            home.join("pending_exceptions.jsonl"),
        )
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HOOK_TIMEOUT_MS", "10000")
        .env_remove("DCG_FAIL_CLOSED")
        .current_dir(home)
        .spawn()
        .expect("spawn dcg");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    let output = child.wait_with_output().expect("wait for dcg");
    // `dcg hook` exits 1 on a deny and 0 on an allow; anything else is a
    // protocol failure rather than a verdict.
    let code = output.status.code();
    assert!(
        matches!(code, Some(0 | 1)),
        "hook protocol exit code {code:?} for {command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    stdout.contains(r#""decision":"deny""#).then_some(stdout)
}

/// Ordinary command lines an agent or a person types all day. Every one of
/// these must be allowed with every pack enabled.
const MUST_ALLOW: &[&str] = &[
    // --- git, read-only, including the #405 directory-loop shapes -----------
    "git status --short",
    "git -C frontend status --short",
    "for d in frontend backend; do git -C $d status --short; done",
    "for r in $(ls); do git -C $r log -1 --format=%H; done",
    "git -C $d status",
    "git -C $d log --oneline -5",
    "git -C \"$repo\" rev-parse --abbrev-ref HEAD",
    "git --git-dir=$d/.git status",
    "git diff --stat",
    "git log --oneline -20",
    "git show HEAD --stat",
    "git branch --list",
    "git remote -v",
    "git stash list",
    "git ls-files | head -50",
    "git blame src/main.rs | head",
    // --- package managers ---------------------------------------------------
    "npm install",
    "npm ci",
    "npm run build",
    "npm test -- --watch=false",
    "bun install",
    "bun run dev",
    "pnpm install --frozen-lockfile",
    "yarn install",
    "pip install -r requirements.txt",
    "uv sync",
    "cargo build --release",
    "cargo test --no-fail-fast",
    "cargo clippy --all-targets -- -D warnings",
    "go build ./...",
    // --- frontend edits with Tailwind classes (#403) ------------------------
    "rg -n 'className=\"min-w-0 truncate line-through\"' src",
    "grep -rn \"truncate text-sm\" src/components",
    "sed -i '' 's/foo/bar/' Row.tsx  # className=\"min-w-0 truncate line-through\"",
    "npx prettier --write \"src/**/*.tsx\"",
    "bun run build -- --class truncate line-through",
    // --- containers and orchestration ---------------------------------------
    "docker ps",
    "docker ps -a --format '{{.Names}}'",
    "docker images",
    "docker logs -f web",
    "docker compose ps",
    "kubectl get pods",
    "kubectl get pods -A -o wide",
    "kubectl describe pod web-0",
    "kubectl logs deploy/api --tail=100",
    "helm list -A",
    // --- PowerShell read-only assignments (#401) ----------------------------
    "$residue = Get-ChildItem \"$env:TEMP\" -Directory",
    "$items = Get-ChildItem C:\\temp -Recurse -Directory",
    "$count += Get-ChildItem -Directory",
    "$svc = Get-Service -Name w32time",
    "$procs = Get-Process | Where-Object { $_.CPU -gt 10 }",
    // --- remote and inline payloads with harmless redirects (#404) ----------
    "ssh host 'ls *.py 2>/dev/null | head'",
    "ssh host 'ls *.py 2>/dev/null | head; git log -1 2>/dev/null'",
    "ssh h \"uptime 2>/dev/null\" 2>&1",
    "sh -c \"uptime 2>/dev/null\" 2>&1",
    "grep -oE '<a [^>]*>' page.html",
    "grep -oE '<a [^>]*>' page.html; ssh host 'git log -1 2>/dev/null | head'",
    "echo 'a | b 2>/dev/null'",
    "bash -c \"echo > /dev/tcp/example.test/22\"",
    // --- everyday shell -----------------------------------------------------
    "ls -la",
    "find . -name '*.rs' -newer Cargo.toml",
    "rg -n 'TODO' src",
    "cat Cargo.toml",
    "wc -l src/*.rs",
    "make > build.log",
    "cargo test 2>&1 | tail -20",
    "echo hello > /tmp/scratch/out.txt",
    "curl -sS https://example.test/health",
    "jq '.version' package.json",
    "tar -czf /tmp/scratch/backup.tgz src",
    "aws s3 ls s3://bucket/prefix/",
    "gcloud compute instances list",
    "terraform plan",
    "psql -c 'SELECT count(*) FROM users'",
    "mysql -e 'SHOW TABLES'",
    "redis-cli info",
];

/// The controls. If a change makes the corpus pass by weakening dcg, these
/// fail first.
const MUST_DENY: &[&str] = &[
    "rm -rf ~/projects",
    "git checkout -- src/",
    "git reset --hard origin/main",
    "echo x > ~/.bashrc",
    "echo x > /etc/passwd",
    "psql -c 'TRUNCATE TABLE users'",
    "mysql -e 'DROP DATABASE prod'",
    "ssh h \"rm -rf /data\"",
    "bash -c \"cat x > $HOME/notes\"",
    "echo x > /dev/sda",
    "git -C $d clean -fdx",
    "$x = sh -c \"rm -rf /\"",
];

fn fixture() -> (tempfile::TempDir, PathBuf) {
    let home = tempfile::tempdir().expect("temp home");
    let config = home.path().join("dcg-corpus-config.toml");
    fs::write(&config, ALL_PACK_CATEGORIES).expect("write config");
    fs::create_dir_all(home.path().join("scratch")).expect("scratch dir");
    (home, config)
}

#[test]
fn ordinary_developer_commands_are_never_denied() {
    let (home, config) = fixture();
    let mut denied = Vec::new();
    for command in MUST_ALLOW {
        if let Some(stdout) = hook_denies(command, home.path(), &config) {
            denied.push(format!("{command}\n    -> {}", stdout.trim()));
        }
    }
    assert!(
        denied.is_empty(),
        "{} ordinary command(s) denied with every pack enabled:\n  {}",
        denied.len(),
        denied.join("\n  ")
    );
}

#[test]
fn the_corpus_controls_still_deny() {
    let (home, config) = fixture();
    let mut allowed = Vec::new();
    for command in MUST_DENY {
        if hook_denies(command, home.path(), &config).is_none() {
            allowed.push(*command);
        }
    }
    assert!(
        allowed.is_empty(),
        "control command(s) no longer denied: {allowed:?}"
    );
}
