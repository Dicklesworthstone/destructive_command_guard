//! Repro for issue #291: the hook deny path must emit its protocol denial
//! even when the pending-exceptions store lock is held by another process.
//!
//! Before the fix, `PendingExceptionStore::record_block` acquired the store's
//! exclusive advisory lock with an unbounded blocking wait BEFORE the denial
//! was written to stdout, so a contended or wedged store delayed the denial
//! past the agent's hook window (some clients then treat the hook as FAILED
//! rather than denying — cf. #183). The fix bounds the lock wait and emits
//! the denial WITHOUT an allow-once code when the store stays contended.

#![allow(clippy::doc_markdown, clippy::uninlined_format_args)]

use fs2::FileExt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Path to the exact DCG binary Cargo built for this integration test.
fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

/// Run dcg in hook mode with an isolated HOME/config and an explicit
/// pending-exceptions store path. Returns (stdout, stderr, exit, elapsed).
fn run_hook_with_pending_store(
    command: &str,
    home: &Path,
    pending_path: &Path,
) -> (String, String, i32, Duration) {
    let input = format!(
        r#"{{"tool_name":"Bash","tool_input":{{"command":"{}"}}}}"#,
        command.replace('\\', "\\\\").replace('"', "\\\"")
    );

    let config_path = home.join("dcg-test-config.toml");
    fs::write(&config_path, "").expect("failed to write empty config");

    let started = Instant::now();
    let mut child = Command::new(dcg_binary())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("xdg_config"))
        .env("DCG_CONFIG", &config_path)
        .env("DCG_PENDING_EXCEPTIONS_PATH", pending_path)
        .spawn()
        .expect("failed to spawn dcg process");

    {
        let stdin = child.stdin.as_mut().expect("failed to get stdin");
        stdin
            .write_all(input.as_bytes())
            .expect("failed to write to stdin");
    }

    let output = child.wait_with_output().expect("failed to wait for dcg");
    let elapsed = started.elapsed();

    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code().unwrap_or(-1),
        elapsed,
    )
}

fn assert_deny(stdout: &str) {
    let json: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout is not valid JSON ({e}): {stdout:?}"));
    let decision = json["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or_default();
    assert_eq!(
        decision, "deny",
        "expected a deny decision, got: {stdout:?}"
    );
}

/// Issue #291 core repro: another handle holds the store's exclusive lock for
/// the entire hook invocation; the denial must still be emitted promptly —
/// just without an allow-once code.
#[test]
fn issue_291_denial_emitted_while_store_lock_held() {
    let temp = tempfile::tempdir().expect("tempdir");
    let pending_path = temp.path().join("pending_exceptions.jsonl");

    // Hold the exclusive advisory lock from this process for the whole run.
    let lock_holder = fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&pending_path)
        .expect("open pending store");
    lock_holder.lock_exclusive().expect("acquire test lock");

    let (stdout, stderr, exit_code, elapsed) =
        run_hook_with_pending_store("git reset --hard", temp.path(), &pending_path);

    fs2::FileExt::unlock(&lock_holder).expect("release test lock");

    assert_eq!(exit_code, 0, "hook mode exits 0 on deny\nstderr: {stderr}");
    assert_deny(&stdout);
    // The denial must not have waited on the held lock. The bounded lock wait
    // is ~150ms; 5s allows for slow CI process startup while still failing
    // decisively if the old unbounded blocking wait returns.
    assert!(
        elapsed < Duration::from_secs(5),
        "denial took {elapsed:?}; the store lock must not delay it"
    );
    // Code issuance is best-effort: under contention the denial carries no
    // allow-once code and the store gained no record.
    assert!(
        !stdout.contains("dcg allow-once"),
        "contended store must suppress the allow-once code, got: {stdout:?}"
    );
    let store_content = fs::read_to_string(&pending_path).expect("read store");
    assert!(
        store_content.trim().is_empty(),
        "contended store must not gain a record: {store_content:?}"
    );
}

/// Uncontended control: the allow-once flow still works end-to-end — the
/// denial carries a code and the store gains the matching record.
#[test]
fn issue_291_allow_once_code_issued_when_uncontended() {
    let temp = tempfile::tempdir().expect("tempdir");
    let pending_path = temp.path().join("pending_exceptions.jsonl");

    let (stdout, stderr, exit_code, _elapsed) =
        run_hook_with_pending_store("git reset --hard", temp.path(), &pending_path);

    assert_eq!(exit_code, 0, "hook mode exits 0 on deny\nstderr: {stderr}");
    assert_deny(&stdout);
    assert!(
        stdout.contains("dcg allow-once"),
        "uncontended deny must issue an allow-once code, got: {stdout:?}"
    );

    let store_content = fs::read_to_string(&pending_path).expect("read store");
    let record: serde_json::Value = serde_json::from_str(store_content.trim())
        .unwrap_or_else(|e| panic!("store record not JSON ({e}): {store_content:?}"));
    let short_code = record["short_code"].as_str().expect("short_code");
    assert!(
        stdout.contains(short_code),
        "denial must carry the persisted short code {short_code}, got: {stdout:?}"
    );
}
