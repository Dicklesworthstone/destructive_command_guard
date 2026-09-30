//! #504: the OMP bridge produced no verdict when the tool call's cwd did not
//! exist.
//!
//! The generated bridge spawned dcg *in* the command's cwd. When that directory
//! was missing, Bun's `posix_spawn` threw ENOENT naming the dcg binary, the
//! bridge logged it and returned with no verdict, and a configured
//! `DCG_UNVERIFIED_DECISION=deny` was never consulted.
//!
//! These tests drive the bridge the way OMP does: `dcg install --omp` writes the
//! extension into a scratch HOME, Bun imports it, and its `tool_call` handler is
//! called with the real `Bun.spawn` and the real dcg binary. Only the four OMP
//! helper imports are stubbed. Without Bun the bridge tests SKIP; the CLI half
//! of the contract (`--command-cwd`) is checked directly either way.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

const RESET: &str = "git reset --hard";
const RESET_RULE: &str = "core.git:reset-hard";

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

/// A scratch HOME plus a project directory holding a directory-scoped grant.
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    xdg_config: PathBuf,
    project: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temp dir");
        // macOS temp dirs sit under a symlinked /var; compare real paths.
        let root = temp.path().canonicalize().expect("canonical temp root");
        let home = root.join("home");
        let xdg_config = home.join(".config");
        let project = root.join("project");
        for dir in [&home, &project, &xdg_config.join("dcg")] {
            fs::create_dir_all(dir).expect("create fixture dir");
        }
        // Granted for the project directory itself and nothing below it. A
        // command whose cwd is a missing child of the project must not borrow
        // this grant just because dcg had to be started in the project.
        let scope = project.to_string_lossy();
        fs::write(
            xdg_config.join("dcg").join("allowlist.toml"),
            format!(
                "[[allow]]\nrule = \"{RESET_RULE}\"\nreason = \"repro 504\"\nadded_by = \"test\"\n\
                 added_at = \"2026-01-01T00:00:00Z\"\npaths = ['{scope}']\n"
            ),
        )
        .expect("write allowlist");
        Self {
            _temp: temp,
            root,
            home,
            xdg_config,
            project,
        }
    }

    /// Environment for every dcg and Bun child: the scratch HOME, no ambient
    /// `DCG_*` from the operator, and no hook self-repair.
    fn apply_env(&self, command: &mut Command) {
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("DCG_") {
                command.env_remove(key);
            }
        }
        // An operator's OMP profile would redirect where the extension lands.
        for key in [
            "OMP_PROFILE",
            "PI_PROFILE",
            "PI_CONFIG_DIR",
            "PI_CODING_AGENT_DIR",
            "PI_NO_PTY",
        ] {
            command.env_remove(key);
        }
        command
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("XDG_CONFIG_HOME", &self.xdg_config)
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("NO_COLOR", "1");
    }

    /// Run the private OMP robot protocol directly, from `process_cwd`.
    fn run_bridge_protocol(&self, process_cwd: &Path, extra: &[&str]) -> std::process::Output {
        let mut command = Command::new(dcg_binary());
        self.apply_env(&mut command);
        command
            .args([
                "--robot",
                "test",
                "--stdin",
                "--agent",
                "omp",
                "--dialect",
                "posix",
                "--format",
                "json",
                "--omp-bridge-output",
            ])
            .args(extra)
            .current_dir(process_cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn dcg");
        {
            use std::io::Write as _;
            let mut stdin = child.stdin.take().expect("stdin");
            stdin.write_all(RESET.as_bytes()).expect("write command");
        }
        child.wait_with_output().expect("wait for dcg")
    }

    /// `dcg install --omp` with `binary`, into `home`. Returns the extension.
    fn install_omp(&self, binary: &Path, home: &Path) -> PathBuf {
        let mut command = Command::new(binary);
        self.apply_env(&mut command);
        let output = command
            .args(["install", "--omp"])
            .env("HOME", home)
            .env("USERPROFILE", home)
            .current_dir(&self.root)
            .output()
            .expect("run dcg install --omp");
        assert!(
            output.status.success(),
            "dcg install --omp failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let extension = home.join(".omp/agent/extensions/dcg-guard.ts");
        assert!(
            extension.is_file(),
            "no extension at {}",
            extension.display()
        );
        write_omp_stubs(home);
        extension
    }
}

/// The four OMP imports the bridge uses, reduced to what a plain `bash` call
/// needs. Bun resolves them from `<home>/node_modules`, an ancestor of the
/// installed extension.
fn write_omp_stubs(home: &Path) {
    let coding_agent = home.join("node_modules/@oh-my-pi/pi-coding-agent");
    let pi_utils = home.join("node_modules/@oh-my-pi/pi-utils");
    for dir in [
        coding_agent.join("config"),
        coding_agent.join("tools"),
        pi_utils.clone(),
    ] {
        fs::create_dir_all(dir).expect("create stub dir");
    }
    let files: [(PathBuf, &str); 7] = [
        (
            coding_agent.join("package.json"),
            r#"{"name":"@oh-my-pi/pi-coding-agent","type":"module","exports":{".":"./index.ts","./config/settings":"./config/settings.ts","./tools/path-utils":"./tools/path-utils.ts","./tools/shell-tokenize":"./tools/shell-tokenize.ts"}}"#,
        ),
        (coding_agent.join("index.ts"), "export {};\n"),
        (
            coding_agent.join("config/settings.ts"),
            "export const settings = { getShellConfig() { return { shell: \"/bin/bash\" }; } };\n",
        ),
        (
            coding_agent.join("tools/path-utils.ts"),
            "import path from \"node:path\";\nexport function resolveToCwd(requested: string, cwd: string): string { return path.resolve(cwd, requested); }\n",
        ),
        (
            coding_agent.join("tools/shell-tokenize.ts"),
            "export function extractLeadingCdTarget(_command: string): undefined { return undefined; }\n",
        ),
        (
            pi_utils.join("package.json"),
            r#"{"name":"@oh-my-pi/pi-utils","type":"module","exports":{".":"./index.ts"}}"#,
        ),
        (
            pi_utils.join("index.ts"),
            "export const procmgr = { isCmdShell() { return false; }, isPowerShell() { return false; } };\n",
        ),
    ];
    for (path, contents) in files {
        fs::write(path, contents).expect("write stub");
    }
}

/// Imports the installed extension, registers its handler, and runs each case
/// through it. Prints one JSON array of `{ id, result, errors }`.
const DRIVER: &str = r#"
const [extensionPath, casesJson] = process.argv.slice(2);
const cases = JSON.parse(casesJson);
const { default: dcgGuard } = await import(extensionPath);
let handler;
dcgGuard({ on(name, cb) { if (name === "tool_call") handler = cb; } });
if (typeof handler !== "function") throw new Error("bridge registered no tool_call handler");
const out = [];
const originalError = console.error;
for (const c of cases) {
  const errors = [];
  console.error = (...values) => { errors.push(values.map(String).join(" ")); };
  if (c.unverified === undefined) delete process.env.DCG_UNVERIFIED_DECISION;
  else process.env.DCG_UNVERIFIED_DECISION = c.unverified;
  const input = { command: c.command };
  if (c.cwd !== undefined) input.cwd = c.cwd;
  let result;
  try {
    result = await handler({ toolName: "bash", input }, { cwd: c.ctxCwd, hasUI: false, mode: "rpc" });
  } finally {
    console.error = originalError;
  }
  out.push({ id: c.id, result: result ?? null, errors });
}
console.log(JSON.stringify(out));
"#;

fn bun_available() -> bool {
    Command::new("bun")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn drive(fixture: &Fixture, extension: &Path, cases: &Value) -> Vec<Value> {
    let driver = fixture.root.join("drive_omp_bridge.mjs");
    fs::write(&driver, DRIVER).expect("write driver");
    let mut command = Command::new("bun");
    fixture.apply_env(&mut command);
    let output = command
        .arg(&driver)
        .arg(extension)
        .arg(cases.to_string())
        .current_dir(&fixture.root)
        .output()
        .expect("run Bun driver");
    assert!(
        output.status.success(),
        "Bun driver failed\n--- stderr ---\n{}\n--- stdout ---\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let results: Vec<Value> =
        serde_json::from_slice(&output.stdout).expect("driver prints one JSON array");
    assert_eq!(results.len(), cases.as_array().map_or(0, Vec::len));
    results
}

fn case<'a>(results: &'a [Value], id: &str) -> &'a Value {
    results
        .iter()
        .find(|entry| entry["id"] == id)
        .unwrap_or_else(|| panic!("no result for case {id}"))
}

fn is_block(entry: &Value) -> bool {
    entry["result"]["block"] == Value::Bool(true)
}

fn reason(entry: &Value) -> String {
    entry["result"]["reason"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

#[test]
fn command_cwd_is_the_scope_for_directory_scoped_grants() {
    let fixture = Fixture::new();
    let missing = fixture.project.join("gone").join("deeper");

    // Control: in the granted directory itself the grant applies.
    let granted = fixture.run_bridge_protocol(&fixture.project, &[]);
    assert_eq!(
        granted.status.code(),
        Some(0),
        "grant must apply in its own directory: {}",
        String::from_utf8_lossy(&granted.stdout)
    );
    let reported_existing = fixture.run_bridge_protocol(
        &fixture.root,
        &[
            "--command-cwd",
            fixture.project.to_str().expect("utf-8 path"),
        ],
    );
    assert_eq!(
        reported_existing.status.code(),
        Some(0),
        "a reported existing cwd is the scope, not dcg's own cwd: {}",
        String::from_utf8_lossy(&reported_existing.stdout)
    );

    // Started in the project on behalf of a missing child directory: the grant
    // for the project must not be borrowed.
    let borrowed = fixture.run_bridge_protocol(
        &fixture.project,
        &["--command-cwd", missing.to_str().expect("utf-8 path")],
    );
    assert_eq!(
        borrowed.status.code(),
        Some(1),
        "a missing command cwd must leave directory-scoped grants inapplicable: {}",
        String::from_utf8_lossy(&borrowed.stdout)
    );
    let verdict: Value = serde_json::from_slice(&borrowed.stdout).expect("compact JSON verdict");
    assert_eq!(verdict["decision"], "deny");
    assert_eq!(verdict["rule_id"], RESET_RULE);
}

#[test]
fn command_cwd_is_private_to_the_omp_bridge_protocol() {
    let fixture = Fixture::new();
    let mut command = Command::new(dcg_binary());
    fixture.apply_env(&mut command);
    let output = command
        .args(["test", "--command-cwd", "/", "echo ok"])
        .current_dir(&fixture.root)
        .output()
        .expect("run dcg test");
    assert!(
        !output.status.success(),
        "--command-cwd without --omp-bridge-output must be rejected"
    );
}

#[test]
fn installed_bridge_judges_commands_whose_cwd_does_not_exist() {
    if cfg!(windows) {
        // The fixture's canonical `\\?\` paths are not what OMP hands the
        // bridge on Windows; this drive has only been validated on POSIX.
        println!("repro_504: SKIPPED on Windows (POSIX-validated bridge drive)");
        return;
    }
    if !bun_available() {
        println!("repro_504: SKIPPED (bun is not on PATH, so the OMP bridge cannot be loaded)");
        return;
    }
    let fixture = Fixture::new();
    let extension = fixture.install_omp(&dcg_binary(), &fixture.home);
    let project = fixture.project.to_string_lossy().to_string();
    let missing = fixture.project.join("gone").join("deeper");
    let missing = missing.to_string_lossy().to_string();
    let vanished_session = fixture.root.join("vanished-session");
    let vanished_session = vanished_session.to_string_lossy().to_string();

    let cases = json!([
        { "id": "grant-control", "command": RESET, "cwd": project, "ctxCwd": project },
        { "id": "missing-cwd-reset", "command": RESET, "cwd": missing, "ctxCwd": project },
        { "id": "missing-cwd-rm-root", "command": "rm -rf /", "cwd": missing, "ctxCwd": project },
        { "id": "missing-cwd-safe", "command": "git status", "cwd": missing, "ctxCwd": project },
        { "id": "missing-session-cwd", "command": RESET, "ctxCwd": vanished_session },
    ]);
    let results = drive(&fixture, &extension, &cases);

    let control = case(&results, "grant-control");
    assert_eq!(
        control["result"],
        Value::Null,
        "grant applies in place: {control}"
    );

    for id in ["missing-cwd-reset", "missing-session-cwd"] {
        let entry = case(&results, id);
        assert!(is_block(entry), "{id}: expected a block, got {entry}");
        assert!(
            reason(entry).contains(&format!("Rule: {RESET_RULE}")),
            "{id}: the block must be dcg's own verdict: {entry}"
        );
        assert_eq!(
            entry["errors"],
            json!([]),
            "{id}: no infrastructure failure: {entry}"
        );
    }
    let rm_root = case(&results, "missing-cwd-rm-root");
    assert!(is_block(rm_root), "rm -rf / must block: {rm_root}");
    let safe = case(&results, "missing-cwd-safe");
    assert_eq!(
        safe["result"],
        Value::Null,
        "a safe command still runs: {safe}"
    );
    assert_eq!(
        safe["errors"],
        json!([]),
        "and without a diagnostic: {safe}"
    );
}

/// A dcg that cannot start at all yields no verdict. The default posture fails
/// open with a diagnostic naming the binary and directory; the deny posture
/// blocks.
#[cfg(unix)]
#[test]
fn installed_bridge_applies_unverified_posture_when_dcg_cannot_start() {
    use std::os::unix::fs::PermissionsExt as _;

    if !bun_available() {
        println!("repro_504: SKIPPED (bun is not on PATH, so the OMP bridge cannot be loaded)");
        return;
    }
    let fixture = Fixture::new();
    let bin_dir = fixture.root.join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let copy = bin_dir.join("dcg");
    fs::copy(dcg_binary(), &copy).expect("copy dcg");
    let broken_home = fixture.root.join("broken-home");
    fs::create_dir_all(&broken_home).expect("create broken home");
    let extension = fixture.install_omp(&copy, &broken_home);
    // The installed path now names a file that cannot be executed.
    fs::set_permissions(&copy, fs::Permissions::from_mode(0o644)).expect("chmod dcg copy");

    let project = fixture.project.to_string_lossy().to_string();
    let cases = json!([
        { "id": "default-posture", "command": RESET, "cwd": project, "ctxCwd": project },
        { "id": "ask-posture", "command": RESET, "cwd": project, "ctxCwd": project, "unverified": "ask" },
        { "id": "deny-posture", "command": "echo ok", "cwd": project, "ctxCwd": project, "unverified": "deny" },
    ]);
    let results = drive(&fixture, &extension, &cases);

    for id in ["default-posture", "ask-posture"] {
        let entry = case(&results, id);
        assert_eq!(entry["result"], Value::Null, "{id}: fails open: {entry}");
        let errors = entry["errors"].as_array().expect("errors array");
        assert_eq!(errors.len(), 1, "{id}: exactly one diagnostic: {entry}");
        let line = errors[0].as_str().unwrap_or_default();
        assert!(
            line.contains("OMP guard infrastructure failure (dcg did not start)")
                && line.contains(&copy.to_string_lossy().to_string())
                && line.contains(&format!("in {}", Value::String(project.clone()))),
            "{id}: the diagnostic must name the binary and directory: {line}"
        );
    }
    let deny = case(&results, "deny-posture");
    assert!(is_block(deny), "deny posture must block: {deny}");
    assert!(
        reason(deny).contains("DCG_UNVERIFIED_DECISION=deny"),
        "the block must say why: {deny}"
    );
}
