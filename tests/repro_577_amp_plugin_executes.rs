//! #577: dcg's generated Amp plugin must load, deny, and fail closed.
//!
//! Amp (ampcode.com) controls tool use through plugins: it runs them with Bun
//! and calls a `tool.call` handler before every tool call, and a handler that
//! returns `{ action: "reject-and-continue", message }` blocks the call
//! (<https://ampcode.com/docs/plugin-api>). `dcg install --amp` writes such a
//! plugin. As with the OpenCode plugin (#419), asserting substrings of the
//! generated source would pass on a file that fails to load, so this test
//! runs the artifact: it installs the plugin exactly as the CLI does, imports
//! it under every JavaScript runtime present (Bun is what Amp uses; Node shares
//! the `node:` modules the plugin imports), and drives the handler against the
//! real dcg binary, plus stand-ins for a dcg that fails. Without either
//! runtime the execution test SKIPs; the install/uninstall round trip and the
//! doctor check always run.

#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

/// The handler is called with the documented `ToolCallEvent` (`toolUseID`,
/// `tool`, `input`, `thread`) and a context whose `ui.confirm` answers dcg's
/// review requests. `amp.helpers.shellCommandFromToolCall` is modeled on its
/// documented contract (a `ShellCommand { command, dir? }` for a Bash or
/// shell_command call, else null); the plugin must also work when the helper
/// is missing or throws.
#[cfg(unix)]
const DRIVER: &str = r#"
import { pathToFileURL } from "node:url";
import { join } from "node:path";

const [pluginPath, dcgBin, fakesDir, workDir] = process.argv.slice(2);
delete process.env.DCG_BYPASS;
delete process.env.DCG_BRIDGE_CRASH_DECISION;

let failures = 0;
let checks = 0;
const check = (name, ok, detail = "") => {
  checks += 1;
  if (!ok) {
    failures += 1;
    console.error(`FAIL ${name}${detail ? ` -- ${detail}` : ""}`);
  }
};
const show = (value) => JSON.stringify(value);

const mod = await import(pathToFileURL(pluginPath).href);
check("default export is a function", typeof mod.default === "function", typeof mod.default);
check(
  "description is a static string of at most 300 characters",
  typeof mod.description === "string" && mod.description.length > 0 && mod.description.length <= 300,
  show(mod.description),
);

const logs = [];
function fakeAmp(helper = "documented") {
  const handlers = {};
  const amp = {
    on(name, handler) {
      handlers[name] = handler;
      return { unsubscribe() {} };
    },
    logger: { log: (...parts) => logs.push(parts.join(" ")) },
  };
  if (helper === "documented") {
    amp.helpers = {
      shellCommandFromToolCall(event) {
        if (event.tool === "Bash" && typeof event.input?.cmd === "string") {
          return { command: event.input.cmd, dir: event.input.cwd };
        }
        if (event.tool === "shell_command" && typeof event.input?.command === "string") {
          return { command: event.input.command };
        }
        return null;
      },
    };
  } else if (helper === "throws") {
    amp.helpers = {
      shellCommandFromToolCall() {
        throw new Error("helper failed");
      },
    };
  }
  mod.default(amp);
  return handlers;
}
const withConfirm = (confirm) => ({ ui: { confirm } });
const noReview = withConfirm(async () => {
  throw new Error("dcg did not ask for review, so no dialog may open");
});
const call = (handlers, tool, input, ctx = noReview) =>
  handlers["tool.call"]({ toolUseID: "toolu_1", tool, input, thread: { id: "T-1" } }, ctx);
const rejected = (result) => result?.action === "reject-and-continue" && typeof result.message === "string";
const allowed = (result) => result?.action === "allow";

const DESTRUCTIVE = "git reset --hard";
const SAFE = "git status";

process.env.DCG_BIN = dcgBin;
let handlers = fakeAmp();
check("registers a tool.call handler", typeof handlers["tool.call"] === "function");
let result = await call(handlers, "Bash", { cmd: DESTRUCTIVE });
check("Bash: a destructive command is rejected", rejected(result), show(result));
check("the rejection carries dcg's reason", rejected(result) && result.message.includes("BLOCKED by dcg") && result.message.includes("core.git:reset-hard"), show(result));
result = await call(handlers, "Bash", { cmd: SAFE, cwd: workDir });
check("Bash: a safe command is allowed", allowed(result), show(result));
result = await call(handlers, "Bash", { cmd: SAFE, cwd: join(workDir, "missing") });
check("a missing cwd does not fail a safe command", allowed(result), show(result));
result = await call(handlers, "shell_command", { command: DESTRUCTIVE });
check("shell_command: a destructive command is rejected", rejected(result), show(result));
result = await call(handlers, "Read", { path: "/etc/hosts" });
check("a non-shell tool is allowed", allowed(result), show(result));
for (const input of [{}, { cmd: "" }, { cmd: ["git", "reset", "--hard"] }, { cmd: 42 }]) {
  result = await call(handlers, "Bash", input);
  check(`a shell call without a command string is rejected: ${show(input)}`, rejected(result) && result.message.includes("no command string"), show(result));
}
result = await call(handlers, "mcp__runner__exec", { command: DESTRUCTIVE });
check("an unknown command-bearing tool is still checked", rejected(result), show(result));
check("and the fallback is logged", logs.some((line) => line.includes("Unrecognized command-bearing Amp tool")), show(logs));
result = await call(handlers, "Bash", { cmd: SAFE, command: DESTRUCTIVE });
check("a benign cmd cannot hide a destructive command", rejected(result), show(result));

for (const helper of ["missing", "throws"]) {
  handlers = fakeAmp(helper);
  result = await call(handlers, "Bash", { cmd: DESTRUCTIVE });
  check(`helper ${helper}: Bash is still checked`, rejected(result), show(result));
  result = await call(handlers, "Bash", { cmd: SAFE });
  check(`helper ${helper}: a safe command is still allowed`, allowed(result), show(result));
}

handlers = fakeAmp();
if (fakesDir) {
  for (const fake of ["missing", "exit-nonzero", "exit-zero-silent", "exit-zero-garbage", "killed", "allow-then-killed"]) {
    process.env.DCG_BIN = join(fakesDir, fake);
    result = await call(handlers, "Bash", { cmd: SAFE });
    check(`no verdict (${fake}) blocks`, rejected(result) && result.message.includes("dcg gave no verdict"), show(result));
    process.env.DCG_BRIDGE_CRASH_DECISION = " Allow ";
    result = await call(handlers, "Bash", { cmd: SAFE });
    check(`no verdict (${fake}) with DCG_BRIDGE_CRASH_DECISION=allow`, allowed(result), show(result));
    delete process.env.DCG_BRIDGE_CRASH_DECISION;
  }

  process.env.DCG_BIN = join(fakesDir, "deny-then-exit-nonzero");
  process.env.DCG_BRIDGE_CRASH_DECISION = "allow";
  result = await call(handlers, "Bash", { cmd: SAFE });
  check("a deny stands despite a failing exit and the crash opt-out", rejected(result) && result.message === "fake deny reason", show(result));
  delete process.env.DCG_BRIDGE_CRASH_DECISION;

  process.env.DCG_BIN = join(fakesDir, "ask");
  const prompts = [];
  result = await call(handlers, "Bash", { cmd: SAFE }, withConfirm(async (options) => (prompts.push(options), true)));
  check("ask, confirmed: runs", allowed(result), show(result));
  check("the dialog shows the command and dcg's reason", prompts.length === 1 && prompts[0].message.includes(SAFE) && prompts[0].message.includes("fake review reason"), show(prompts));
  for (const [label, ctx] of [
    ["declined", withConfirm(async () => false)],
    ["dismissed", withConfirm(async () => undefined)],
    ["no UI", withConfirm(async () => { throw new Error("no UI is attached"); })],
    ["no ui object", {}],
  ]) {
    result = await call(handlers, "Bash", { cmd: SAFE }, ctx);
    check(`ask, ${label}: rejected`, rejected(result) && result.message.includes("fake review reason"), show(result));
  }
}

process.env.DCG_BIN = dcgBin;
for (const bypass of ["1", " true ", "YES"]) {
  process.env.DCG_BYPASS = bypass;
  result = await call(handlers, "Bash", { cmd: DESTRUCTIVE });
  check(`DCG_BYPASS=${show(bypass)} allows`, allowed(result), show(result));
}
delete process.env.DCG_BYPASS;

let loadError = null;
try {
  mod.default({ logger: { log() {} } });
} catch (error) {
  loadError = error;
}
check("an Amp without amp.on fails to load instead of loading unguarded", String(loadError?.message).includes("could not be activated"), String(loadError));

console.log(`Amp plugin: ${checks} checks, ${failures} failures`);
process.exit(failures === 0 ? 0 : 1);
"#;

#[cfg(unix)]
fn javascript_runtimes() -> Vec<&'static str> {
    ["bun", "node"]
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

/// A temporary HOME with every location dcg or Amp could resolve pinned
/// inside it.
struct Sandbox {
    _temp: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    xdg: PathBuf,
    repo: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("create a temporary HOME");
        let root = temp.path().to_path_buf();
        let home = root.join("home");
        let xdg = root.join("xdg");
        let repo = root.join("repo");
        for dir in [&home, &xdg, &repo.join(".git")] {
            std::fs::create_dir_all(dir).expect("create sandbox dir");
        }
        Self {
            _temp: temp,
            root,
            home,
            xdg,
            repo,
        }
    }

    fn plugin_path(&self) -> PathBuf {
        self.xdg.join("amp").join("plugins").join("dcg-guard.js")
    }

    fn dcg(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_dcg"))
            .args(args)
            .env_clear()
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("XDG_CONFIG_HOME", &self.xdg)
            .env("APPDATA", self.root.join("appdata"))
            .env("LOCALAPPDATA", self.root.join("localappdata"))
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("NO_COLOR", "1")
            .current_dir(&self.repo)
            .output()
            .expect("run dcg")
    }

    fn amp_doctor_check(&self, args: &[&str]) -> serde_json::Value {
        let output = self.dcg(args);
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
                panic!(
                    "doctor JSON ({error}): {}",
                    String::from_utf8_lossy(&output.stdout)
                )
            });
        report["checks"]
            .as_array()
            .expect("checks")
            .iter()
            .find(|check| check["id"] == "amp_plugin")
            .cloned()
            .unwrap_or_else(|| panic!("amp_plugin check missing: {report}"))
    }
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn amp_plugin_installs_refreshes_and_uninstalls_only_what_dcg_owns() {
    let sandbox = Sandbox::new();
    let plugin = sandbox.plugin_path();

    let output = sandbox.dcg(&["install", "--amp"]);
    assert!(
        output.status.success(),
        "install --amp: {}{}",
        stdout(&output),
        String::from_utf8_lossy(&output.stderr)
    );
    let source = std::fs::read_to_string(&plugin).expect("plugin written under XDG_CONFIG_HOME");
    assert!(source.starts_with("// dcg-amp-plugin:"), "{source}");
    let embedded = serde_json::to_string(env!("CARGO_BIN_EXE_dcg")).unwrap();
    assert!(
        source.contains(&format!("const DCG_BIN = {embedded};")),
        "the plugin runs this dcg"
    );
    assert!(
        !sandbox.home.join(".config").exists(),
        "nothing written outside XDG_CONFIG_HOME"
    );

    // Idempotent; --force rewrites the same bytes.
    assert!(stdout(&sandbox.dcg(&["install", "--amp"])).contains("already installed"));
    assert!(
        sandbox
            .dcg(&["install", "--amp", "--force"])
            .status
            .success()
    );
    assert_eq!(std::fs::read_to_string(&plugin).unwrap(), source);
    assert_eq!(
        sandbox.amp_doctor_check(&["doctor", "--format", "json"])["status"],
        "ok"
    );

    // An edited dcg-owned plugin is stale: doctor says so, install refreshes it.
    std::fs::write(&plugin, format!("{source}\n// edited\n")).unwrap();
    let stale = sandbox.amp_doctor_check(&["doctor", "--format", "json"]);
    assert_eq!(stale["status"], "warning", "{stale}");
    assert!(sandbox.dcg(&["install", "--amp"]).status.success());
    assert_eq!(std::fs::read_to_string(&plugin).unwrap(), source);

    // A project plugin goes to the repository root.
    assert!(
        sandbox
            .dcg(&["install", "--amp", "--project"])
            .status
            .success()
    );
    assert_eq!(
        std::fs::read_to_string(sandbox.repo.join(".amp/plugins/dcg-guard.js")).unwrap(),
        source
    );

    // Uninstall removes the user-level plugin dcg wrote, then has nothing to do.
    let output = sandbox.dcg(&["uninstall", "--amp"]);
    assert!(output.status.success(), "{}", stdout(&output));
    assert!(!plugin.exists());
    assert!(stdout(&sandbox.dcg(&["uninstall", "--amp"])).contains("No dcg Amp plugin"));
    let missing = sandbox.amp_doctor_check(&["doctor", "--format", "json"]);
    assert_eq!(missing["status"], "error", "{missing}");
    let fixed = sandbox.amp_doctor_check(&["doctor", "--fix", "--format", "json"]);
    assert_eq!(fixed["fixed"], true, "{fixed}");
    assert_eq!(std::fs::read_to_string(&plugin).unwrap(), source);

    // A user's own dcg-guard.js is never overwritten or removed.
    let own = "export default function (amp) {}\n";
    std::fs::write(&plugin, own).unwrap();
    assert!(
        !sandbox
            .dcg(&["install", "--amp", "--force"])
            .status
            .success()
    );
    assert!(!sandbox.dcg(&["uninstall", "--amp"]).status.success());
    assert_eq!(std::fs::read_to_string(&plugin).unwrap(), own);
}

/// Stand-ins for a dcg that gives no verdict, one that denies and then exits
/// non-zero, and one that asks for review. Shell scripts, so Unix only.
#[cfg(unix)]
fn write_fakes(root: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    const DENY: &str = r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"fake deny reason"}}"#;
    const ASK: &str = r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"fake review reason"}}"#;
    let dir = root.join("fakes");
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
        ("ask", format!("cat >/dev/null\nprintf '%s\\n' '{ASK}'\n")),
    ] {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}")).expect("write a fake dcg");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("make the fake dcg executable");
    }
    dir
}

#[cfg(unix)]
#[test]
fn generated_amp_plugin_loads_denies_and_fails_closed() {
    let runtimes = javascript_runtimes();
    if runtimes.is_empty() {
        println!(
            "repro_577_amp_plugin_executes: SKIPPED (neither bun nor node is on PATH, so the \
             generated ES module cannot be loaded)"
        );
        return;
    }

    let sandbox = Sandbox::new();
    let output = sandbox.dcg(&["install", "--amp"]);
    assert!(output.status.success(), "{}", stdout(&output));
    let plugin = sandbox.plugin_path();
    let fakes = write_fakes(&sandbox.root);
    let driver = sandbox.root.join("driver.mjs");
    std::fs::write(&driver, DRIVER).expect("write the driver");
    let dcg_config = sandbox.xdg.join("dcg").join("config.toml");
    std::fs::create_dir_all(dcg_config.parent().unwrap()).unwrap();
    std::fs::write(&dcg_config, "[general]\nself_heal_hook = false\n").unwrap();

    for runtime in runtimes {
        let output = Command::new(runtime)
            .arg(&driver)
            .arg(&plugin)
            .arg(env!("CARGO_BIN_EXE_dcg"))
            .arg(&fakes)
            .arg(&sandbox.repo)
            .env_clear()
            .env("HOME", &sandbox.home)
            .env("XDG_CONFIG_HOME", &sandbox.xdg)
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("DCG_HOOK_TIMEOUT_MS", "5000")
            .env("NO_COLOR", "1")
            .current_dir(&sandbox.repo)
            .output()
            .unwrap_or_else(|error| panic!("run the driver under {runtime}: {error}"));
        assert!(
            output.status.success(),
            "{runtime}: {}\n{}",
            stdout(&output),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout(&output).contains(", 0 failures"),
            "{runtime}: {}",
            stdout(&output)
        );
        println!("{runtime}: {}", stdout(&output).trim());
    }
}
