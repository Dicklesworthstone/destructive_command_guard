//! #419: the generated OpenCode plugin must actually load and deny.
//!
//! The reported bug was not a wrong decision — it was a plugin that *failed to
//! load*, leaving OpenCode unguarded with nothing visible but a line in
//! OpenCode's own log. A test that asserts substrings of the generated source
//! cannot catch that class: it passes just as happily on a file with unbalanced
//! braces, an export of the wrong type, or a handler that reads the command from
//! the wrong field.
//!
//! So this test runs the artifact. It installs the plugin exactly as
//! `dcg install --opencode` does, imports it as an ES module under whichever
//! JavaScript runtimes are present, and drives both plugin contracts against the
//! real dcg binary:
//!
//! * **v1** — named `DcgGuard` export returning a `"tool.execute.before"` hook
//!   map, called as `(input, output)` with the command in `output.args.command`.
//! * **v2** — default export `{ id, setup(ctx) }`, registering through
//!   `ctx.tool.hook("execute.before", cb)` with the command in
//!   `event.input.command`.
//!
//! Both runtimes matter and are used when available: v1 ran on Bun, v2 migrated
//! to Node, and the single `node:child_process` spawn path is load-bearing for
//! the claim that one generated file serves both. Absent both runtimes the test
//! SKIPs rather than failing, following `tests/memory_tests.rs`.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The driver is JavaScript because the thing under test is a JavaScript module:
/// only a real loader proves it parses, and only a real call proves it denies.
const DRIVER: &str = r#"
const [pluginPath, dcgBin, fakesDir] = process.argv.slice(2);
process.env.DCG_BIN = dcgBin;

const DESTRUCTIVE = "rm -rf /";
const SAFE = "git status";
let failures = 0;
const check = (name, ok, detail = "") => {
  if (!ok) { failures += 1; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
};
const threw = async (fn) => { try { await fn(); return null; } catch (e) { return e; } };

const mod = await import(pluginPath);

check("DcgGuard is a function", typeof mod.DcgGuard === "function", typeof mod.DcgGuard);
check("default export is an object", mod.default && typeof mod.default === "object");
check("default.id is dcg-guard", mod.default?.id === "dcg-guard", String(mod.default?.id));
check("default.setup is a function", typeof mod.default?.setup === "function");

// v1: named export, hook map, command in output.args.
const v1map = await mod.DcgGuard();
const v1 = v1map && v1map["tool.execute.before"];
check("v1 exposes tool.execute.before", typeof v1 === "function", typeof v1);
if (typeof v1 === "function") {
  check("v1 denies destructive", (await threw(() => v1({ tool: "bash" }, { args: { command: DESTRUCTIVE } }))) !== null);
  check("v1 allows safe", (await threw(() => v1({ tool: "bash" }, { args: { command: SAFE } }))) === null);
  check("v1 ignores non-bash", (await threw(() => v1({ tool: "read" }, { args: { command: DESTRUCTIVE } }))) === null);
  check("v1 tolerates missing args", (await threw(() => v1({ tool: "bash" }, {}))) === null);
}

// v2: default export registers one hook, command in event.input.
const registered = [];
await mod.default.setup({ tool: { hook: async (name, cb) => registered.push([name, cb]) } });
check("v2 registered one hook", registered.length === 1, `got ${registered.length}`);
check("v2 hook is execute.before", registered[0]?.[0] === "execute.before", String(registered[0]?.[0]));
const v2 = registered[0]?.[1];
if (typeof v2 === "function") {
  check("v2 denies destructive", (await threw(() => v2({ tool: "bash", input: { command: DESTRUCTIVE } }))) !== null);
  check("v2 allows safe", (await threw(() => v2({ tool: "bash", input: { command: SAFE } }))) === null);
  check("v2 ignores non-bash", (await threw(() => v2({ tool: "read", input: { command: DESTRUCTIVE } }))) === null);
  check("v2 tolerates missing input", (await threw(() => v2({ tool: "bash" }))) === null);
  check("v2 tolerates undefined event", (await threw(() => v2(undefined))) === null);
}

// dcg's escape hatch exits before reading its input, so it never answers; the
// plugin honours it instead of reading the silence as a crash.
process.env.DCG_BYPASS = "1";
check("v2 honours DCG_BYPASS", (await threw(() => v2({ tool: "bash", input: { command: DESTRUCTIVE } }))) === null);
delete process.env.DCG_BYPASS;

// An unrunnable dcg is an infrastructure failure, not a verdict: fail OPEN, or a
// broken install would block every command in the session.
process.env.DCG_BIN = "/nonexistent/definitely-not-dcg";
check("v2 fails open when dcg cannot run", (await threw(() => v2({ tool: "bash", input: { command: DESTRUCTIVE } }))) === null);
check("v1 fails open when dcg cannot run", (await threw(() => v1({ tool: "bash" }, { args: { command: DESTRUCTIVE } }))) === null);

// A dcg that RAN but gave no verdict is not an allow. Each fake below stands in
// for a dcg that crashed, was killed, or lost its answer; a SAFE command must
// still be blocked, because the plugin cannot know what dcg would have said.
if (fakesDir) {
  const noVerdictFakes = ["killed", "exit-nonzero", "exit-zero-silent", "exit-zero-garbage", "allow-then-killed"];
  for (const fake of noVerdictFakes) {
    process.env.DCG_BIN = `${fakesDir}/${fake}`;
    const v1err = await threw(() => v1({ tool: "bash" }, { args: { command: SAFE } }));
    const v2err = await threw(() => v2({ tool: "bash", input: { command: SAFE } }));
    check(`v1 blocks when dcg gives no verdict (${fake})`, v1err !== null);
    check(`v2 blocks when dcg gives no verdict (${fake})`, v2err !== null);
    check(`the block says why (${fake})`, String(v2err?.message ?? "").includes("dcg gave no verdict"), String(v2err?.message));
  }

  // A deny written before the process died is still the answer, with its reason.
  process.env.DCG_BIN = `${fakesDir}/deny-then-exit-nonzero`;
  const denied = await threw(() => v2({ tool: "bash", input: { command: SAFE } }));
  check("a deny survives a non-zero exit", String(denied?.message ?? "") === "fake deny reason", String(denied?.message));

  // The operator can opt back into fail-open for crashes.
  process.env.DCG_BRIDGE_CRASH_DECISION = " Allow ";
  for (const fake of noVerdictFakes) {
    process.env.DCG_BIN = `${fakesDir}/${fake}`;
    check(`DCG_BRIDGE_CRASH_DECISION=allow lets a crash through (${fake})`, (await threw(() => v2({ tool: "bash", input: { command: SAFE } }))) === null);
  }
  process.env.DCG_BIN = `${fakesDir}/deny-then-exit-nonzero`;
  check("the crash opt-out never overrides a deny", (await threw(() => v2({ tool: "bash", input: { command: SAFE } }))) !== null);
  delete process.env.DCG_BRIDGE_CRASH_DECISION;
}

process.exit(failures === 0 ? 0 : 1);
"#;

fn javascript_runtimes() -> Vec<&'static str> {
    ["node", "bun"]
        .into_iter()
        .filter(|runtime| {
            Command::new(runtime)
                .arg("--version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
        })
        .collect()
}

/// Install the plugin the way the CLI does, into a HOME that is not the
/// operator's: this test must never write to a real OpenCode config.
fn install_plugin(home: &Path) -> PathBuf {
    let output = Command::new(env!("CARGO_BIN_EXE_dcg"))
        .args(["install", "--opencode"])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("DCG_NO_SELF_HEAL", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("run dcg install --opencode");
    assert!(
        output.status.success(),
        "dcg install --opencode failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let plugin = home.join(".config/opencode/plugins/dcg-guard.js");
    assert!(
        plugin.is_file(),
        "expected a generated plugin at {}; installer said: {}",
        plugin.display(),
        String::from_utf8_lossy(&output.stdout)
    );
    plugin
}

/// Stand-ins for a dcg that ran but gave the plugin no verdict, plus one that
/// denied and then exited non-zero. Shell scripts, so Unix only; elsewhere the
/// driver skips these cases.
#[cfg(unix)]
#[allow(clippy::unnecessary_wraps)] // the non-Unix twin returns `None`
fn write_no_verdict_fakes(root: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;

    const DENY: &str = r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"fake deny reason"}}"#;
    let dir = root.join("no-verdict-fakes");
    std::fs::create_dir_all(&dir).expect("create the fakes directory");
    for (name, body) in [
        ("killed", "cat >/dev/null\nkill -9 $$\n".to_string()),
        (
            "exit-nonzero",
            "cat >/dev/null\necho 'dcg: internal error' >&2\nexit 3\n".to_string(),
        ),
        ("exit-zero-silent", "cat >/dev/null\nexit 0\n".to_string()),
        (
            "exit-zero-garbage",
            "cat >/dev/null\necho 'not a verdict'\n".to_string(),
        ),
        (
            "allow-then-killed",
            "cat >/dev/null\nprintf '%s\\n' '{\"dcg_verdict\":\"allow\"}'\nkill -9 $$\n"
                .to_string(),
        ),
        (
            "deny-then-exit-nonzero",
            format!("cat >/dev/null\nprintf '%s\\n' '{DENY}'\nexit 2\n"),
        ),
    ] {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}")).expect("write a fake dcg");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("make the fake dcg executable");
    }
    Some(dir)
}

#[cfg(not(unix))]
fn write_no_verdict_fakes(_root: &Path) -> Option<PathBuf> {
    None
}

/// The dcg side of the plugin contract: asked for an explicit verdict, an
/// allowed command (or a tool dcg does not judge) answers
/// `{"dcg_verdict":"allow"}`, a denied one answers with the deny document
/// alone, and a request without the field keeps the Claude-compatible silent
/// allow. Needs no JavaScript runtime.
#[test]
fn explicit_verdict_request_gets_exactly_one_answer() {
    let temp = tempfile::tempdir().expect("create a temporary HOME");
    let run_payload = |payload: serde_json::Value| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"))
            .env("HOME", temp.path())
            .env("USERPROFILE", temp.path())
            .env("XDG_CONFIG_HOME", temp.path().join(".config"))
            .env("OPENCODE", "1")
            .env("DCG_NO_SELF_HEAL", "1")
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env_remove("DCG_BYPASS")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn dcg");
        {
            use std::io::Write as _;
            let mut stdin = child.stdin.take().expect("dcg stdin");
            stdin
                .write_all(payload.to_string().as_bytes())
                .expect("write the payload");
        }
        let output = child.wait_with_output().expect("wait for dcg");
        assert!(
            output.status.success(),
            "{payload}: {:?}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("UTF-8 stdout")
    };
    let bash = |command: &str, explicit: serde_json::Value| {
        run_payload(serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": command },
            "dcg_explicit_verdict": explicit,
        }))
    };
    const ALLOW_LINE: &str = "{\"dcg_verdict\":\"allow\"}\n";

    assert_eq!(bash("git status", true.into()), ALLOW_LINE);
    // A tool dcg does not judge is allowed, so it is answered too.
    assert_eq!(
        run_payload(serde_json::json!({
            "tool_name": "Read",
            "tool_input": { "file_path": "/etc/hosts" },
            "dcg_explicit_verdict": true,
        })),
        ALLOW_LINE
    );

    let denied = bash("git reset --hard", true.into());
    assert_eq!(denied.lines().count(), 1, "one document: {denied}");
    let document: serde_json::Value = serde_json::from_str(&denied).expect("a JSON deny");
    assert_eq!(
        document["hookSpecificOutput"]["permissionDecision"], "deny",
        "{document}"
    );
    assert!(!denied.contains("dcg_verdict"), "{denied}");

    // Hosts never send the field and keep the silent allow; only a JSON
    // `true` asks for the line.
    assert_eq!(
        run_payload(serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": "git status" },
        })),
        ""
    );
    assert_eq!(bash("git status", "true".into()), "");
    assert_eq!(bash("git status", false.into()), "");
}

#[test]
fn generated_opencode_plugin_loads_and_denies_under_both_contracts() {
    let runtimes = javascript_runtimes();
    if runtimes.is_empty() {
        println!(
            "repro_419_opencode_plugin_executes: SKIPPED (neither node nor bun is on PATH, so the \
             generated ES module cannot be loaded)"
        );
        return;
    }

    let temp = tempfile::tempdir().expect("create a temporary HOME");
    let plugin = install_plugin(temp.path());
    let driver = temp.path().join("drive_plugin.mjs");
    std::fs::write(&driver, DRIVER).expect("write the driver module");
    let fakes = write_no_verdict_fakes(temp.path());

    for runtime in &runtimes {
        let output = Command::new(runtime)
            .arg(&driver)
            .arg(&plugin)
            .arg(env!("CARGO_BIN_EXE_dcg"))
            .args(&fakes)
            // The plugin shells out to dcg, which must not read operator config.
            .env("HOME", temp.path())
            .env("USERPROFILE", temp.path())
            .env("XDG_CONFIG_HOME", temp.path().join(".config"))
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("DCG_NO_SELF_HEAL", "1")
            .env("NO_COLOR", "1")
            .output()
            .unwrap_or_else(|error| panic!("run the driver under {runtime}: {error}"));

        assert!(
            output.status.success(),
            "the generated OpenCode plugin failed its contract checks under {runtime}.\n\
             This is the #419 failure mode: a plugin that does not load leaves OpenCode \
             unguarded and says nothing.\n--- stderr ---\n{}\n--- stdout ---\n{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
        println!("repro_419: contracts verified under {runtime}");
    }
}
