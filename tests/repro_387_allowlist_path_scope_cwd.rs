//! Regression tests for issue #387: a `paths = [...]`-scoped allowlist entry
//! was matched against the dcg *process's* own `getcwd()`.
//!
//! A hook subprocess's working directory has nothing to do with the directory
//! the guarded tool call targets — the agent host reports that in the payload's
//! `cwd` field, and a `cd <dir> && <command>` one-liner can move it again. The
//! old behavior made a scoped grant apply or not apply based on whichever
//! directory the long-lived hook-invoking shell happened to sit in.
//!
//! An allowlist entry is a permission grant, so the dangerous direction is a
//! grant that applies too broadly. These tests pin both directions: the grant
//! follows the payload cwd (and any static embedded `cd`), and it fails closed
//! whenever the effective directory cannot be determined.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

/// The probe command: denied by `core.git:reset-hard` unless allowlisted.
const PROBE: &str = "git reset --hard";
const PROBE_RULE: &str = "core.git:reset-hard";

struct TestEnv {
    _temp: tempfile::TempDir,
    home: PathBuf,
    xdg_config: PathBuf,
    /// Inside the allowlist scope.
    scope_in: PathBuf,
    /// Outside the allowlist scope.
    scope_out: PathBuf,
    /// A third directory, used as the dcg process's own cwd so it can never be
    /// mistaken for either of the two above.
    elsewhere: PathBuf,
}

impl TestEnv {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temp dir");
        // Canonicalize up front: on macOS a temp dir lives under a symlinked
        // `/var`, and these tests care about real directories.
        let root = temp.path().canonicalize().expect("canonical temp root");
        let home = root.join("home");
        let xdg_config = home.join(".config");
        let scope_in = root.join("scope-in");
        let scope_out = root.join("scope-out");
        let elsewhere = root.join("elsewhere");
        for dir in [&home, &xdg_config, &scope_in, &scope_out, &elsewhere] {
            fs::create_dir_all(dir).expect("create dir");
        }
        fs::create_dir_all(xdg_config.join("dcg")).expect("create dcg config dir");
        Self {
            _temp: temp,
            home,
            xdg_config,
            scope_in,
            scope_out,
            elsewhere,
        }
    }

    /// Write the user allowlist with a single entry for [`PROBE_RULE`],
    /// optionally scoped to the given glob patterns.
    fn write_allowlist(&self, paths: Option<&[String]>) {
        let mut entry = format!(
            "[[allow]]\nrule = \"{PROBE_RULE}\"\nreason = \"repro 387\"\nadded_by = \"test\"\nadded_at = \"2026-01-01T00:00:00Z\"\n"
        );
        if let Some(paths) = paths {
            use std::fmt::Write as _;
            let rendered: Vec<String> = paths.iter().map(|p| format!("\"{p}\"")).collect();
            writeln!(entry, "paths = [{}]", rendered.join(", ")).expect("format allowlist entry");
        }
        fs::write(self.xdg_config.join("dcg").join("allowlist.toml"), entry)
            .expect("write allowlist");
    }

    /// Scope patterns covering `scope_in` itself and everything under it.
    fn scope_in_patterns(&self) -> Vec<String> {
        let base = self.scope_in.to_string_lossy().to_string();
        vec![base.clone(), format!("{base}/**")]
    }

    /// Run the hook with `command`, the payload `cwd` field set to
    /// `payload_cwd` (omitted when `None`), from a process whose own working
    /// directory is `process_cwd`.
    fn run_hook(
        &self,
        command: &str,
        payload_cwd: Option<&Path>,
        process_cwd: &Path,
    ) -> std::process::Output {
        let mut input = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": command },
        });
        if let Some(cwd) = payload_cwd {
            input["cwd"] = serde_json::Value::String(cwd.to_string_lossy().to_string());
        }

        let mut cmd = Command::new(dcg_binary());
        cmd.env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("XDG_CONFIG_HOME", &self.xdg_config)
            .env("DCG_SELF_HEAL_HOOK", "0")
            .current_dir(process_cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("spawn dcg");
        {
            let stdin = child.stdin.as_mut().expect("stdin");
            serde_json::to_writer(stdin, &input).expect("write payload");
        }
        child.wait_with_output().expect("wait for dcg")
    }
}

/// Allowed ⇒ the hook publishes no decision document.
fn allowed(output: &std::process::Output) -> bool {
    String::from_utf8_lossy(&output.stdout).trim().is_empty()
}

#[test]
fn baseline_probe_is_denied_without_an_allowlist_entry() {
    let env = TestEnv::new();
    fs::write(
        env.xdg_config.join("dcg").join("allowlist.toml"),
        "# no entries\n",
    )
    .expect("write empty allowlist");
    let out = env.run_hook(PROBE, Some(&env.scope_in), &env.elsewhere);
    assert!(
        !allowed(&out),
        "probe must be denied when nothing allowlists it"
    );
}

#[test]
fn unscoped_entry_grants_regardless_of_cwd() {
    let env = TestEnv::new();
    env.write_allowlist(None);
    for payload in [Some(env.scope_in.as_path()), Some(env.scope_out.as_path())] {
        let out = env.run_hook(PROBE, payload, &env.elsewhere);
        assert!(
            allowed(&out),
            "an entry with no path scope applies everywhere: {payload:?}"
        );
    }
}

#[test]
fn payload_cwd_inside_scope_grants() {
    let env = TestEnv::new();
    env.write_allowlist(Some(&env.scope_in_patterns()));
    let out = env.run_hook(PROBE, Some(&env.scope_in), &env.elsewhere);
    assert!(
        allowed(&out),
        "the payload cwd is inside the scope, so the grant applies"
    );
}

#[test]
fn payload_cwd_outside_scope_denies() {
    let env = TestEnv::new();
    env.write_allowlist(Some(&env.scope_in_patterns()));
    let out = env.run_hook(PROBE, Some(&env.scope_out), &env.elsewhere);
    assert!(
        !allowed(&out),
        "the payload cwd is outside the scope, so the grant does not apply"
    );
}

/// The heart of #387: the dcg process's own working directory must not move
/// the decision in either direction.
#[test]
fn process_cwd_is_irrelevant() {
    let env = TestEnv::new();
    env.write_allowlist(Some(&env.scope_in_patterns()));

    // Process sitting inside the scope must NOT lend the grant to a payload
    // that targets somewhere else. (The old code allowed this.)
    let out = env.run_hook(PROBE, Some(&env.scope_out), &env.scope_in);
    assert!(
        !allowed(&out),
        "a scoped grant must not follow the hook process's own cwd"
    );

    // Process sitting outside the scope must not withhold the grant from a
    // payload that targets inside it. (The old code denied this.)
    let out = env.run_hook(PROBE, Some(&env.scope_in), &env.scope_out);
    assert!(
        allowed(&out),
        "a scoped grant must follow the payload cwd, not the process cwd"
    );
}

#[test]
fn embedded_cd_into_scope_grants() {
    let env = TestEnv::new();
    env.write_allowlist(Some(&env.scope_in_patterns()));
    let command = format!("cd {} && {PROBE}", env.scope_in.display());
    let out = env.run_hook(&command, Some(&env.scope_out), &env.elsewhere);
    assert!(
        allowed(&out),
        "the command lands inside the scope, so the grant applies"
    );
}

#[test]
fn embedded_cd_out_of_scope_revokes_the_grant() {
    let env = TestEnv::new();
    env.write_allowlist(Some(&env.scope_in_patterns()));
    let command = format!("cd {} && {PROBE}", env.scope_out.display());
    let out = env.run_hook(&command, Some(&env.scope_in), &env.elsewhere);
    assert!(
        !allowed(&out),
        "a cd out of the scoped tree revokes the grant; it must not extend it"
    );
}

/// A `cd` whose target only the shell can compute leaves the effective
/// directory unknowable — the grant must not be handed out on a guess.
#[test]
fn unresolvable_cwd_fails_closed() {
    let env = TestEnv::new();
    env.write_allowlist(Some(&env.scope_in_patterns()));
    for command in [
        format!("cd \"$DEST\" && {PROBE}"),
        format!("cd $(cat dir.txt) && {PROBE}"),
        format!("cd {} && {PROBE}", env.scope_in.join("missing").display()),
    ] {
        let out = env.run_hook(&command, Some(&env.scope_in), &env.elsewhere);
        assert!(
            !allowed(&out),
            "an undeterminable working directory must fail closed: {command}"
        );
    }
}

/// A relative glob cannot be anchored to an absolute working directory, so it
/// grants nothing rather than matching by accident.
#[test]
fn relative_scope_pattern_grants_nothing() {
    let env = TestEnv::new();
    let relative = env
        .scope_in
        .file_name()
        .expect("scope dir name")
        .to_string_lossy()
        .to_string();
    env.write_allowlist(Some(&[relative.clone(), format!("{relative}/**")]));
    let out = env.run_hook(PROBE, Some(&env.scope_in), &env.elsewhere);
    assert!(
        !allowed(&out),
        "a relative path pattern must not match an absolute working directory"
    );
}

/// A symlink whose target is outside the scope must not borrow the grant just
/// because its own name looks like it is inside; a symlink pointing into the
/// scope from outside is likewise judged by where it really leads.
#[cfg(unix)]
#[test]
fn symlinks_are_resolved_before_matching() {
    let env = TestEnv::new();
    env.write_allowlist(Some(&env.scope_in_patterns()));

    // `<scope_in>/escape` -> `<scope_out>`: name inside, target outside.
    let escape = env.scope_in.join("escape");
    std::os::unix::fs::symlink(&env.scope_out, &escape).expect("symlink out of scope");
    let out = env.run_hook(PROBE, Some(&escape), &env.elsewhere);
    assert!(
        !allowed(&out),
        "a symlink leading outside the scope must not borrow the grant"
    );

    // `<scope_out>/enter` -> `<scope_in>`: name outside, target inside.
    let enter = env.scope_out.join("enter");
    std::os::unix::fs::symlink(&env.scope_in, &enter).expect("symlink into scope");
    let out = env.run_hook(PROBE, Some(&enter), &env.elsewhere);
    assert!(
        allowed(&out),
        "a symlink leading into the scope is inside it"
    );
}

/// A scope pattern written against a symlinked prefix still matches the real
/// directory it names — otherwise `/tmp/...` patterns could never match on
/// macOS, where `/tmp` is a symlink.
#[cfg(unix)]
#[test]
fn scope_pattern_with_symlinked_prefix_still_matches() {
    let env = TestEnv::new();
    let link = env.home.join("link-to-scope");
    std::os::unix::fs::symlink(&env.scope_in, &link).expect("symlink to scope");
    let base = link.to_string_lossy().to_string();
    env.write_allowlist(Some(&[base.clone(), format!("{base}/**")]));

    let out = env.run_hook(PROBE, Some(&env.scope_in), &env.elsewhere);
    assert!(
        allowed(&out),
        "a pattern whose literal prefix is a symlink must still name its target"
    );
}
