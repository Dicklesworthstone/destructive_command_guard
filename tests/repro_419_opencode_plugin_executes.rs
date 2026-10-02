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
//! * **v1** — a `"tool.execute.before"` hook map, called as `(input, output)`
//!   with the command in `output.args.command`. OpenCode from 1.3.4 gets it
//!   from the default export's `server()`; it treats a default export with an
//!   `id` as a plugin module and refuses the whole file without `server()`
//!   (#516). Up to 1.3.3 it calls every export, so the named `DcgGuard`
//!   export serves there. The driver transcribes both loaders' checks rather
//!   than calling the export it expects a loader to use.
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

// The loaders below transcribe OpenCode's own module checks, because asserting
// the export shape we *think* a loader wants is how #516 shipped: the v1
// loader from 1.3.4 rejects a default export that has an `id` but no
// `server()`, and the whole plugin failed to load.
const isRecord = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
const isFn = (v) => typeof v === "function";

// v1 >= 1.3.4: packages/opencode/src/plugin/index.ts `applyPlugin` with
// shared.ts `readV1Plugin(mod, spec, "server", "detect")`.
async function loadV1(m, input) {
  const value = m.default;
  const detected = isRecord(value) && ("id" in value || "server" in value || "tui" in value);
  if (detected) {
    const server = "server" in value ? value.server : undefined;
    const tui = "tui" in value ? value.tui : undefined;
    if (server !== undefined && !isFn(server)) throw new TypeError("invalid server export");
    if (tui !== undefined && !isFn(tui)) throw new TypeError("invalid tui export");
    if (server !== undefined && tui !== undefined) throw new TypeError("either server() or tui(), not both");
    if (server === undefined) throw new TypeError("must default export an object with server()");
    if (value.id !== undefined && (typeof value.id !== "string" || !value.id.trim())) throw new TypeError("invalid id");
    if (value.id === undefined) throw new TypeError("Path plugin must export id");
    return [await server(input, undefined)];
  }
  const seen = new Set();
  const hooks = [];
  for (const entry of Object.values(m)) {
    if (seen.has(entry)) continue;
    seen.add(entry);
    const fn = isFn(entry) ? entry : isRecord(entry) && isFn(entry.server) ? entry.server : undefined;
    if (!fn) throw new TypeError("Plugin export is not a function");
    hooks.push(await fn(input, undefined));
  }
  return hooks;
}

// v1 <= 1.3.3: every export is called; a throw is logged by OpenCode, and the
// hooks registered before it stay registered.
async function loadV1Legacy(m, input) {
  const seen = new Set();
  const hooks = [];
  try {
    for (const [, fn] of Object.entries(m)) {
      if (seen.has(fn)) continue;
      seen.add(fn);
      hooks.push(await fn(input));
    }
  } catch {}
  return hooks;
}

// v2: packages/core/src/plugin/module.ts decodes `default` as
// `{ id: string, effect: fn } | { id: string, setup: fn }` (a function is not
// an object there, and unknown keys are dropped).
function loadV2(m) {
  const value = m.default;
  if (!isRecord(value) || typeof value.id !== "string") {
    throw new Error("Plugin must export a default definition with an id and an effect or setup function.");
  }
  if (!isFn(value.effect) && !isFn(value.setup)) {
    throw new Error("Plugin must export a default definition with an id and an effect or setup function.");
  }
  return value;
}

let v1hooks = [];
const v1LoadError = await threw(async () => { v1hooks = await loadV1(mod, {}); });
check("the v1 (>= 1.3.4) loader accepts the plugin (#516)", v1LoadError === null, String(v1LoadError?.message));
check("the v1 loader registers exactly one hook map", v1hooks.length === 1, `got ${v1hooks.length}`);
const legacyHooks = await loadV1Legacy(mod, {});
check(
  "the v1 (<= 1.3.3) loader registers a tool.execute.before hook",
  legacyHooks.some((h) => h && typeof h["tool.execute.before"] === "function"),
);
const legacy = legacyHooks.find((h) => h && typeof h["tool.execute.before"] === "function");
if (legacy) {
  check(
    "the v1 (<= 1.3.3) hook denies destructive",
    (await threw(() => legacy["tool.execute.before"]({ tool: "bash" }, { args: { command: DESTRUCTIVE } }))) !== null,
  );
}
check("the v2 loader accepts the plugin", (await threw(async () => loadV2(mod))) === null);

// v1: hook map, command in output.args.
const v1map = v1hooks[0];
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
await loadV2(mod).setup({ tool: { hook: async (name, cb) => registered.push([name, cb]) } });
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

/// A one-shot OpenAI-compatible chat endpoint for [`real_opencode_blocks_through_the_plugin_516`]:
/// the first request that offers tools gets one `bash` tool call carrying
/// `command`; every other request (the tool result, a title request) gets
/// plain text. Returns the port and the bodies of every request it served.
fn spawn_fake_llm(
    command: &str,
) -> (
    u16,
    std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
) {
    use std::io::{BufRead as _, BufReader, Read as _, Write as _};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the fake LLM");
    let port = listener.local_addr().expect("fake LLM address").port();
    let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = std::sync::Arc::clone(&requests);
    let arguments = serde_json::json!({ "command": command, "description": "probe" }).to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().expect("clone the stream"));
            let mut length = 0usize;
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        length = value.trim().parse().unwrap_or(0);
                    }
                }
            }
            let mut body = vec![0u8; length];
            if reader.read_exact(&mut body).is_err() {
                continue;
            }
            let request: serde_json::Value =
                serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
            let offers_tools = request["tools"].as_array().is_some_and(|t| !t.is_empty());
            let has_tool_result = request["messages"]
                .as_array()
                .is_some_and(|m| m.iter().any(|m| m["role"] == "tool"));
            seen.lock().expect("request log").push(request);
            let chunk = |delta: serde_json::Value, finish: serde_json::Value| {
                serde_json::json!({
                    "id": "c1", "object": "chat.completion.chunk", "created": 0, "model": "m",
                    "choices": [{ "index": 0, "delta": delta, "finish_reason": finish }],
                })
            };
            let events = if offers_tools && !has_tool_result {
                vec![
                    chunk(
                        serde_json::json!({ "role": "assistant", "content": null, "tool_calls": [{
                            "index": 0, "id": "call_1", "type": "function",
                            "function": { "name": "bash", "arguments": arguments },
                        }]}),
                        serde_json::Value::Null,
                    ),
                    chunk(serde_json::json!({}), "tool_calls".into()),
                ]
            } else {
                vec![
                    chunk(
                        serde_json::json!({ "role": "assistant", "content": "done" }),
                        serde_json::Value::Null,
                    ),
                    chunk(serde_json::json!({}), "stop".into()),
                ]
            };
            let mut response = String::from(
                "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n",
            );
            for event in events {
                response.push_str("data: ");
                response.push_str(&event.to_string());
                response.push_str("\n\n");
            }
            response.push_str("data: [DONE]\n\n");
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (port, requests)
}

/// #516 end to end: a real OpenCode, the plugin `dcg install --opencode`
/// writes, and a model that asks bash to delete a branch. OpenCode 1.18.33
/// refused the #419 plugin at load time ("must default export an object with
/// server()"), so the deletion ran. The canary branch must survive, and a
/// harmless command must still run.
///
/// Needs an OpenCode binary (`DCG_TEST_OPENCODE_BIN`), git, and network access
/// the first time (OpenCode installs `@ai-sdk/openai-compatible`), so it is
/// ignored by default: `DCG_TEST_OPENCODE_BIN=/path/to/opencode cargo test
/// --test repro_419_opencode_plugin_executes -- --ignored`.
#[test]
#[ignore = "needs a real OpenCode binary in DCG_TEST_OPENCODE_BIN"]
fn real_opencode_blocks_through_the_plugin_516() {
    let Some(opencode) = std::env::var_os("DCG_TEST_OPENCODE_BIN") else {
        println!(
            "real_opencode_blocks_through_the_plugin_516: SKIPPED (DCG_TEST_OPENCODE_BIN unset)"
        );
        return;
    };

    let run = |command: &str| {
        let temp = tempfile::tempdir().expect("create a temporary HOME");
        let home = temp.path().join("home");
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&repo).expect("create the repo dir");
        std::fs::create_dir_all(&home).expect("create the HOME dir");
        install_plugin(&home);
        let git = |args: &[&str]| {
            let status = Command::new("git")
                .args(args)
                .current_dir(&repo)
                .env("HOME", &home)
                .status()
                .expect("run git");
            assert!(status.success(), "git {args:?}");
        };
        git(&["init", "-q"]);
        git(&[
            "-c",
            "user.email=t@example.invalid",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "init",
        ]);
        git(&["branch", "dcg-516-canary"]);

        let (port, requests) = spawn_fake_llm(command);
        let config = serde_json::json!({
            "$schema": "https://opencode.ai/config.json",
            "model": "fake/m",
            "small_model": "fake/m",
            "permission": { "bash": "allow", "edit": "allow" },
            "provider": { "fake": {
                "npm": "@ai-sdk/openai-compatible",
                "name": "Fake",
                "options": { "baseURL": format!("http://127.0.0.1:{port}/v1"), "apiKey": "x" },
                "models": { "m": { "name": "m", "tool_call": true } },
            }},
        });
        std::fs::write(
            home.join(".config/opencode/opencode.json"),
            config.to_string(),
        )
        .expect("write the OpenCode config");

        let mut child = Command::new(&opencode);
        child
            .args([
                "run",
                "--print-logs",
                "--log-level",
                "INFO",
                "run the probe",
            ])
            .current_dir(&repo)
            // OpenCode's bash tool runs in `$PWD`, not the process's working
            // directory; an inherited PWD would point the probe at the
            // checkout running this test.
            .env("PWD", &repo)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("XDG_DATA_HOME", home.join(".local/share"))
            .env("XDG_CACHE_HOME", home.join(".cache"))
            .env("XDG_STATE_HOME", home.join(".local/state"))
            .env("DCG_NO_SELF_HEAL", "1")
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "");
        for (key, _) in std::env::vars_os() {
            let key = key.to_string_lossy().into_owned();
            if (key.starts_with("DCG_") && key != "DCG_TEST_OPENCODE_BIN")
                || key.starts_with("OPENCODE")
            {
                if !matches!(
                    key.as_str(),
                    "DCG_NO_SELF_HEAL" | "DCG_SELF_HEAL_HOOK" | "DCG_ALLOWLIST_SYSTEM_PATH"
                ) {
                    child.env_remove(&key);
                }
            }
        }
        let output = child.output().expect("run opencode");
        let log = String::from_utf8_lossy(&output.stderr).into_owned();
        let canary = Command::new("git")
            .args(["rev-parse", "-q", "--verify", "refs/heads/dcg-516-canary"])
            .current_dir(&repo)
            .status()
            .expect("check the canary")
            .success();
        let tool_result = requests
            .lock()
            .expect("request log")
            .iter()
            .flat_map(|r| r["messages"].as_array().cloned().unwrap_or_default())
            .find(|m| m["role"] == "tool")
            .map(|m| m["content"].to_string())
            .unwrap_or_default();
        (log, canary, tool_result, repo.join("ran.marker").exists())
    };

    let (log, canary, tool_result, _) = run("git branch -D dcg-516-canary");
    assert!(
        !log.contains("failed to load plugin"),
        "OpenCode refused the plugin:\n{log}"
    );
    assert!(
        canary,
        "the canary branch was deleted, so the plugin did not block; tool result: {tool_result}\n{log}"
    );
    assert!(tool_result.contains("dcg"), "tool result: {tool_result}");

    let (log, canary, tool_result, ran) =
        run("git branch --list dcg-516-canary && touch ran.marker");
    assert!(
        canary && ran,
        "a harmless command must run through the plugin; tool result: {tool_result}\n{log}"
    );
}
