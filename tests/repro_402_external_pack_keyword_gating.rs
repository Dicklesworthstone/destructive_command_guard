//! Repro for issue #402: an external pack with no `keywords` was listed as
//! enabled, validated clean, and was silently never evaluated — including on
//! the hook path, which is the surface that enforces.
//!
//! `Pack::might_match` documents the contract ("no keywords = always check
//! patterns"), but the *global* quick reject runs before it and is built from
//! the union of every enabled pack's keywords, to which such a pack
//! contributes nothing. Its coverage therefore depended on whether some other
//! pack's keyword happened to appear in the command line — a property no
//! operator would predict from the configuration.
//!
//! The reporter's other two findings are the same defect seen from the
//! outside: `dcg config` listed the *requested* pack set rather than the set
//! that evaluates, so a pack reached only through `packs.custom_paths` was
//! missing and a pack whose YAML failed to parse was present.
//!
//! Runs the real binary, since the report did.

#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

/// The reporter's pack: one rule on a literal string that occurs nowhere else,
/// and no `keywords` field at all.
const KEYWORDLESS_PACK: &str = r"schema_version: 1
id: repro.zz
name: Repro Pack
version: 1.0.0
description: No keywords field.
destructive_patterns:
  - name: zebra-rule
    pattern: ZEBRAQUUX\s+alpha
    severity: critical
    description: fires on a literal string that occurs nowhere else
";

const KEYWORDED_PACK: &str = r"schema_version: 1
id: repro.kw
name: Repro Pack With Keywords
version: 1.0.0
description: Identical, but with a keywords list.
keywords:
  - ZEBRAQUUX
destructive_patterns:
  - name: zebra-rule-kw
    pattern: ZEBRAQUUX\s+delta
    severity: critical
    description: fires on a literal string that occurs nowhere else
";

/// Missing the required `name` field, so it cannot load.
const INVALID_PACK: &str = r"schema_version: 1
id: repro.bad
version: 1.0.0
description: Deliberately missing the required 'name' field.
keywords:
  - ZEBRAQUUX
destructive_patterns:
  - name: zebra-rule-2
    pattern: ZEBRAQUUX\s+beta
    severity: critical
    description: never fires
";

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().to_path_buf();
        fs::create_dir_all(root.join("packs")).expect("packs dir");
        fs::write(root.join("packs/zz.yaml"), KEYWORDLESS_PACK).expect("write zz");
        fs::write(root.join("packs/kw.yaml"), KEYWORDED_PACK).expect("write kw");
        fs::write(root.join("packs/bad.yaml"), INVALID_PACK).expect("write bad");
        Self { _dir: dir, root }
    }

    fn config(&self, name: &str, body: &str) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, body).expect("write config");
        path
    }

    fn pack(&self, name: &str) -> String {
        self.root
            .join("packs")
            .join(name)
            .to_string_lossy()
            .into_owned()
    }

    fn run(&self, config: &Path, args: &[&str]) -> String {
        let output = Command::new(dcg_binary())
            .args(args)
            .env("HOME", &self.root)
            .env("XDG_CONFIG_HOME", self.root.join("xdg_config"))
            .env("DCG_CONFIG", config)
            .env(
                "DCG_PENDING_EXCEPTIONS_PATH",
                self.root.join("pending_exceptions.jsonl"),
            )
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("NO_COLOR", "1")
            .current_dir(&self.root)
            .output()
            .expect("run dcg");
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// The enforcing surface: the hook protocol.
    fn hook_denies(&self, config: &Path, command: &str) -> bool {
        let payload = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": command },
            "cwd": self.root.to_string_lossy(),
        })
        .to_string();
        let mut child = Command::new(dcg_binary())
            .arg("hook")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("HOME", &self.root)
            .env("XDG_CONFIG_HOME", self.root.join("xdg_config"))
            .env("DCG_CONFIG", config)
            .env(
                "DCG_PENDING_EXCEPTIONS_PATH",
                self.root.join("pending_exceptions.jsonl"),
            )
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("DCG_HOOK_TIMEOUT_MS", "10000")
            .current_dir(&self.root)
            .spawn()
            .expect("spawn dcg");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(payload.as_bytes())
            .expect("write payload");
        let output = child.wait_with_output().expect("wait for dcg");
        String::from_utf8_lossy(&output.stdout).contains(r#""decision":"deny""#)
    }
}

#[test]
fn a_pack_without_keywords_is_evaluated_on_every_command() {
    let fixture = Fixture::new();
    let config = fixture.config(
        "keywordless.toml",
        &format!(
            "[packs]\nenabled = [\"repro.zz\"]\ncustom_paths = [\"{}\"]\n",
            fixture.pack("zz.yaml")
        ),
    );

    // The reporter's exact command, on the path that enforces.
    assert!(
        fixture.hook_denies(&config, "ZEBRAQUUX alpha"),
        "a keyword-less pack must still be evaluated by the hook"
    );
    let test = fixture.run(&config, &["test", "ZEBRAQUUX alpha"]);
    assert!(test.contains("BLOCKED"), "dcg test disagreed: {test}");

    // `dcg explain` used to name the cause here: "quick-rejected (no
    // keywords)". It must now report a real evaluation.
    let explain = fixture.run(&config, &["explain", "ZEBRAQUUX alpha"]);
    assert!(
        !explain.contains("quick-rejected"),
        "the pack must not be quick-rejected: {explain}"
    );

    // Coverage no longer depends on the rest of the command line: the pack's
    // rule fires with or without an unrelated built-in keyword present, and
    // a command the rule does not describe is still allowed.
    assert!(fixture.hook_denies(&config, "rm ZEBRAQUUX alpha"));
    assert!(!fixture.hook_denies(&config, "ls -la"));
    assert!(!fixture.hook_denies(&config, "ZEBRAQUUX beta"));
}

#[test]
fn pack_validate_reports_the_runtime_cost_of_omitting_keywords() {
    let fixture = Fixture::new();
    let config = fixture.config("empty.toml", "");
    let output = fixture.run(&config, &["pack", "validate", &fixture.pack("zz.yaml")]);
    assert!(
        output.contains("S001"),
        "S001 must still be reported: {output}"
    );
    assert!(
        output.contains("quick-reject"),
        "S001 must state the runtime consequence: {output}"
    );
    // It is a warning now, not a performance "suggestion": the pack is valid,
    // but the operator is told what it costs.
    let warnings_index = output.find("Warnings:");
    let s001_index = output.find("S001");
    assert!(
        warnings_index.is_some() && warnings_index < s001_index,
        "S001 must be listed under Warnings: {output}"
    );
}

#[test]
fn config_listing_matches_the_packs_that_evaluate() {
    let fixture = Fixture::new();

    // Finding 2: only `custom_paths`, no `enabled` line. The pack evaluates,
    // so it must appear.
    let config = fixture.config(
        "custom-only.toml",
        &format!(
            "[packs]\ncustom_paths = [\"{}\"]\n",
            fixture.pack("kw.yaml")
        ),
    );
    let listing = fixture.run(&config, &["config"]);
    assert!(
        listing.contains("repro.kw"),
        "an evaluating pack must be listed: {listing}"
    );
    let blocked = fixture.run(&config, &["test", "ZEBRAQUUX delta"]);
    assert!(blocked.contains("BLOCKED"), "pack must fire: {blocked}");

    // Finding 3: a pack that cannot load must not be presented as coverage.
    let config = fixture.config(
        "invalid.toml",
        &format!(
            "[packs]\nenabled = [\"repro.bad\"]\ncustom_paths = [\"{}\"]\n",
            fixture.pack("bad.yaml")
        ),
    );
    let listing = fixture.run(&config, &["config"]);
    assert!(
        listing.contains("repro.bad (configured but NOT loaded"),
        "an unloadable pack must be marked, not silently listed: {listing}"
    );
    assert!(
        listing.contains("Pack load warnings:"),
        "the load failure must be surfaced: {listing}"
    );

    // Doctor agrees, and says why.
    let doctor = fixture.run(&config, &["doctor"]);
    assert!(
        doctor.contains("Failed to load external pack"),
        "doctor must report the load failure: {doctor}"
    );
}

#[test]
fn doctor_notes_a_keywordless_pack() {
    let fixture = Fixture::new();
    let config = fixture.config(
        "keywordless.toml",
        &format!(
            "[packs]\nenabled = [\"repro.zz\"]\ncustom_paths = [\"{}\"]\n",
            fixture.pack("zz.yaml")
        ),
    );
    let doctor = fixture.run(&config, &["doctor"]);
    assert!(
        doctor.contains("repro.zz") && doctor.contains("declares no keywords"),
        "doctor must surface the always-evaluated pack: {doctor}"
    );
}
