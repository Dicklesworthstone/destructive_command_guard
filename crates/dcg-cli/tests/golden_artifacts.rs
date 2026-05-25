#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::needless_raw_string_hashes,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]
//! Golden artifact tests for command output stability.
//!
//! These tests snapshot canonical JSON artifacts for higher-level CLI output.
//! Dynamic fields such as timings, temporary paths, and build metadata are
//! normalized before comparison.

use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;

const GOLDEN_ROOT: &str = "tests/golden/artifacts";
const UPDATE_ENV: &str = "UPDATE_GOLDEN_ARTIFACTS";

#[derive(Debug)]
struct DcgOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

fn dcg_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("DCG_BIN") {
        return PathBuf::from(path);
    }

    if let Some(path) = std::env::var_os("CARGO_BIN_EXE_dcg") {
        return PathBuf::from(path);
    }

    let mut path = std::env::current_exe().expect("current test executable");
    path.pop();
    path.pop();
    path.push("dcg");
    path
}

fn run_dcg(args: &[&str]) -> DcgOutput {
    // Hermetic environment: golden artifacts must be reproducible across
    // contributor machines. Without isolation, dcg reads the developer's
    // real `~/.config/dcg/config.toml` (and any custom packs they have
    // enabled), which makes the captured artifacts machine-specific. On
    // `UPDATE_GOLDEN_ARTIFACTS=1` runs that noise gets committed.
    //
    // The pattern mirrors `tests/e2e_real_service.rs` and the
    // `apply_hermetic_env` helper in `tests/agent_profile_comprehensive.rs`:
    // clear inherited vars, then re-export only `PATH` plus an isolated
    // `HOME` / `XDG_CONFIG_HOME` / `TMPDIR`.
    let home = tempfile::tempdir().expect("create isolated HOME for run_dcg");
    std::fs::create_dir_all(home.path().join(".config/dcg"))
        .expect("create XDG_CONFIG_HOME/dcg under isolated HOME");
    std::fs::create_dir_all(home.path().join("tmp")).expect("create isolated TMPDIR");

    let mut cmd = Command::new(dcg_binary());
    cmd.args(args).env_clear();
    if let Ok(path) = std::env::var("PATH") {
        cmd.env("PATH", path);
    }
    cmd.env("HOME", home.path())
        .env("TMPDIR", home.path().join("tmp"))
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("NO_COLOR", "1")
        .env("CLICOLOR", "0")
        .env("TERM", "dumb");

    let output = cmd.output().expect("failed to run dcg");

    DcgOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        exit_code: output.status.code().unwrap_or(-1),
    }
}

fn assert_golden_json(name: &str, actual: &Value) {
    let path = Path::new(GOLDEN_ROOT).join(name);
    let actual_pretty =
        serde_json::to_string_pretty(actual).expect("canonical artifact serializes as JSON");

    if std::env::var_os(UPDATE_ENV).is_some() {
        let parent = path.parent().expect("golden path has parent");
        std::fs::create_dir_all(parent).expect("create golden artifact directory");
        std::fs::write(&path, format!("{actual_pretty}\n")).expect("write golden artifact");
        return;
    }

    let expected_content = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("missing golden artifact {}: {err}", path.display()));
    let expected: Value = serde_json::from_str(&expected_content)
        .unwrap_or_else(|err| panic!("invalid golden artifact {}: {err}", path.display()));
    let expected_pretty =
        serde_json::to_string_pretty(&expected).expect("expected artifact serializes as JSON");

    assert_eq!(
        &expected,
        actual,
        "golden artifact mismatch for {}\n\n{}",
        path.display(),
        json_diff(&expected_pretty, &actual_pretty)
    );
}

fn json_diff(expected: &str, actual: &str) -> String {
    let expected_lines: Vec<_> = expected.lines().collect();
    let actual_lines: Vec<_> = actual.lines().collect();
    let max_len = expected_lines.len().max(actual_lines.len());

    for idx in 0..max_len {
        let expected_line = expected_lines.get(idx).copied().unwrap_or("<missing>");
        let actual_line = actual_lines.get(idx).copied().unwrap_or("<missing>");
        if expected_line != actual_line {
            return format!(
                "first difference at line {}\nexpected: {}\nactual:   {}\n\nexpected JSON:\n{}\n\nactual JSON:\n{}",
                idx + 1,
                expected_line,
                actual_line,
                expected,
                actual
            );
        }
    }

    format!("expected JSON:\n{expected}\n\nactual JSON:\n{actual}")
}

fn explain_artifact(name: &str, command: &str) {
    let output = run_dcg(&["explain", "--format", "json", command]);
    assert_eq!(
        output.exit_code, 0,
        "dcg explain should exit 0 for {name}\nstderr:\n{}",
        output.stderr
    );

    let mut json: Value =
        serde_json::from_str(&output.stdout).expect("explain --format json stdout is JSON");
    canonicalize_explain_json(&mut json);
    assert_golden_json(&format!("explain/{name}.json"), &json);
}

fn canonicalize_explain_json(value: &mut Value) {
    replace_object_field(value, "total_duration_us", json!("<duration_us>"));

    if let Some(steps) = value.get_mut("steps").and_then(Value::as_array_mut) {
        for step in steps {
            replace_object_field(step, "duration_us", json!("<duration_us>"));
            if let Some(details) = step.get_mut("details") {
                sort_string_array_field(details, "keywords_checked");
            }
        }
    }
}

fn replace_object_field(value: &mut Value, key: &str, replacement: Value) {
    if let Some(object) = value.as_object_mut() {
        if object.contains_key(key) {
            object.insert(key.to_string(), replacement);
        }
    }
}

fn sort_string_array_field(value: &mut Value, key: &str) {
    let Some(array) = value.get_mut(key).and_then(Value::as_array_mut) else {
        return;
    };

    array.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
}

fn build_scan_corpus() -> tempfile::TempDir {
    let dir = tempfile::Builder::new()
        .prefix("dcg-golden-corpus-")
        .tempdir()
        .expect("create scan corpus tempdir");

    std::fs::write(
        dir.path().join("representative.sh"),
        r#"#!/usr/bin/env bash
set -euo pipefail

git status --short
git reset --hard HEAD~1
rm -rf "$TMPDIR/dcg-cache"
rm -rf /home/example/project

python3 <<'PY'
import shutil
shutil.rmtree('/home/example/project')
PY
"#,
    )
    .expect("write shell scan corpus");

    std::fs::write(
        dir.path().join("Makefile"),
        r#"clean:
	echo "preview only"
	git clean -nd
	git push --force origin main
"#,
    )
    .expect("write makefile scan corpus");

    dir
}

fn scan_artifact() {
    let corpus = build_scan_corpus();
    let corpus_path = corpus.path().to_str().expect("temp path is UTF-8");
    let output = run_dcg(&["scan", "--paths", corpus_path, "--format", "json"]);
    assert!(
        output.stdout.trim_start().starts_with('{'),
        "dcg scan should emit JSON stdout\nexit: {}\nstderr:\n{}",
        output.exit_code,
        output.stderr
    );

    let mut json: Value =
        serde_json::from_str(&output.stdout).expect("scan --format json stdout is JSON");
    canonicalize_scan_json(&mut json, corpus.path());

    let artifact = json!({
        "exit_code": output.exit_code,
        "stdout_json": json,
        "stderr": output.stderr,
    });
    assert_golden_json("scan/representative_corpus.json", &artifact);
}

fn canonicalize_scan_json(value: &mut Value, corpus_root: &Path) {
    if let Some(summary) = value.get_mut("summary") {
        replace_object_field(summary, "elapsed_ms", json!("<elapsed_ms>"));
    }

    if let Some(findings) = value.get_mut("findings").and_then(Value::as_array_mut) {
        for finding in findings {
            if let Some(file) = finding
                .get("file")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
            {
                let normalized = normalize_scan_path(&file, corpus_root);
                replace_object_field(finding, "file", json!(normalized));
            }
        }
    }
}

fn normalize_scan_path(file: &str, corpus_root: &Path) -> String {
    let path = Path::new(file);
    if let Ok(relative) = path.strip_prefix(corpus_root) {
        return path_to_slash_string(relative);
    }

    let root = path_to_slash_string(corpus_root);
    let file = file.replace('\\', "/");
    if let Some(rest) = file.strip_prefix(&root) {
        return rest.trim_start_matches('/').to_string();
    }

    file
}

fn path_to_slash_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn version_artifact() {
    let output = run_dcg(&["--version"]);
    assert_eq!(
        output.exit_code, 0,
        "dcg --version should exit 0\nstderr:\n{}",
        output.stderr
    );

    let artifact = json!({
        "exit_code": output.exit_code,
        "stdout": scrub_package_version(&output.stdout),
        "stderr_facts": version_stderr_facts(&output.stderr),
    });
    assert_golden_json("version/version.json", &artifact);
}

fn scrub_package_version(input: &str) -> String {
    input.replace(env!("CARGO_PKG_VERSION"), "<package_version>")
}

fn version_stderr_facts(stderr: &str) -> Value {
    let mut facts = Map::new();

    for line in stderr.lines() {
        if line.contains("Destructive Command Guard") {
            facts.insert("title".to_string(), json!("Destructive Command Guard"));
        } else if line.contains("dcg v") {
            facts.insert(
                "binary_version".to_string(),
                json!("dcg v<package_version>"),
            );
        } else if line.contains("Built:") {
            facts.insert("built".to_string(), json!("<build_date>"));
        } else if line.contains("Rustc:") {
            facts.insert("rustc".to_string(), json!("<rustc_version>"));
        } else if line.contains("Target:") {
            facts.insert("target".to_string(), json!("<target_triple>"));
        } else if line.contains("Protecting your code from destructive ops") {
            facts.insert(
                "tagline".to_string(),
                json!("Protecting your code from destructive ops"),
            );
        }
    }

    Value::Object(facts)
}

#[test]
fn golden_artifact_explain_safe_git_status() {
    explain_artifact("safe_git_status", "git status --short");
}

#[test]
fn golden_artifact_explain_destructive_git_reset() {
    explain_artifact("destructive_git_reset", "git reset --hard HEAD~1");
}

#[test]
fn golden_artifact_explain_heredoc_python_rmtree() {
    explain_artifact(
        "heredoc_python_rmtree",
        "python3 <<'PY'\nimport shutil\nshutil.rmtree('/home/example/project')\nPY",
    );
}

#[test]
fn golden_artifact_scan_representative_corpus() {
    scan_artifact();
}

#[test]
fn golden_artifact_version_output() {
    version_artifact();
}
