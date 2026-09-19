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
const [pluginPath, dcgBin] = process.argv.slice(2);
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

// An unrunnable dcg is an infrastructure failure, not a verdict: fail OPEN, or a
// broken install would block every command in the session.
process.env.DCG_BIN = "/nonexistent/definitely-not-dcg";
check("v2 fails open when dcg cannot run", (await threw(() => v2({ tool: "bash", input: { command: DESTRUCTIVE } }))) === null);
check("v1 fails open when dcg cannot run", (await threw(() => v1({ tool: "bash" }, { args: { command: DESTRUCTIVE } }))) === null);

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

    for runtime in &runtimes {
        let output = Command::new(runtime)
            .arg(&driver)
            .arg(&plugin)
            .arg(env!("CARGO_BIN_EXE_dcg"))
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
