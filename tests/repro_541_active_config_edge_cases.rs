//! #541: every Claude integration entry point must use the active configuration.
//!
//! Each invocation is a real dcg child with its own HOME, platform config/state
//! directories, working directory, and environment. No process-global environment
//! mutation or access to the operator's Claude configuration is needed.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

struct Env {
    _temp: tempfile::TempDir,
    home: PathBuf,
    cwd: PathBuf,
    config: PathBuf,
}

impl Env {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("isolated test directory");
        // Resolve /var -> /private/var aliases before testing cwd-relative paths.
        #[cfg(unix)]
        let root = temp
            .path()
            .canonicalize()
            .expect("canonical test directory");
        #[cfg(not(unix))]
        let root = temp.path().to_path_buf();
        let home = root.join("home");
        let cwd = root.join("work");
        let config = root.join("config.toml");
        std::fs::create_dir_all(&home).expect("isolated HOME");
        std::fs::create_dir_all(&cwd).expect("isolated cwd");
        std::fs::create_dir_all(home.join("tmp")).expect("isolated temporary directory");
        std::fs::write(&config, "[history]\nenabled = false\n").expect("isolated dcg config");
        Self {
            _temp: temp,
            home,
            cwd,
            config,
        }
    }

    fn default_settings(&self) -> PathBuf {
        self.home.join(".claude").join("settings.json")
    }

    fn active_dir(&self) -> PathBuf {
        self.home.join("claude profile")
    }

    fn command(&self, config_dir: Option<&Path>) -> Command {
        let binary = Path::new(env!("CARGO_BIN_EXE_dcg"));
        let mut command = Command::new(binary);
        command
            .env_clear()
            .env("PATH", binary.parent().expect("dcg binary directory"))
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join("xdg_config"))
            .env("XDG_DATA_HOME", self.home.join("xdg_data"))
            .env("XDG_CACHE_HOME", self.home.join("xdg_cache"))
            .env("APPDATA", self.home.join("appdata"))
            .env("LOCALAPPDATA", self.home.join("localappdata"))
            .env("TMPDIR", self.home.join("tmp"))
            .env("TEMP", self.home.join("tmp"))
            .env("TMP", self.home.join("tmp"))
            .env("DCG_CONFIG", &self.config)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("DCG_ALLOW_ONCE_PATH", self.home.join("allow_once.jsonl"))
            .env(
                "DCG_PENDING_EXCEPTIONS_PATH",
                self.home.join("pending_exceptions.jsonl"),
            )
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("DCG_NO_UPDATE_CHECK", "1")
            .env("NO_COLOR", "1")
            .env("CLICOLOR", "0")
            .env("TERM", "dumb")
            .current_dir(&self.cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(config_dir) = config_dir {
            command.env("CLAUDE_CONFIG_DIR", config_dir);
        }
        command
    }

    fn run(&self, config_dir: Option<&Path>, args: &[&str]) -> Output {
        self.command(config_dir)
            .args(args)
            .output()
            .expect("run isolated dcg")
    }

    fn hook(&self, config_dir: Option<&Path>, agent_marker: &str) -> Output {
        let payload = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": "git status" },
            "cwd": self.cwd,
        });
        self.hook_payload(config_dir, &[], Some(agent_marker), &payload)
    }

    fn hook_payload(
        &self,
        config_dir: Option<&Path>,
        args: &[&str],
        agent_marker: Option<&str>,
        payload: &Value,
    ) -> Output {
        let mut command = self.command(config_dir);
        command
            .args(args)
            .env("DCG_SELF_HEAL_HOOK", "1")
            .env("DCG_HOOK_TIMEOUT_MS", "30000")
            .stdin(Stdio::piped());
        if let Some(agent_marker) = agent_marker {
            command.env(agent_marker, "config-directory-regression-541");
        }
        let mut child = command.spawn().expect("spawn isolated hook");
        child
            .stdin
            .take()
            .expect("hook stdin")
            .write_all(payload.to_string().as_bytes())
            .expect("write hook input");
        let output = child.wait_with_output().expect("wait for hook");
        assert_success(&output);
        assert!(
            output.stdout.is_empty(),
            "safe command must remain silent: {}",
            output_text(&output)
        );
        output
    }
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_success(output: &Output) {
    assert!(output.status.success(), "{}", output_text(output));
}

fn assert_blocked_hook_payload(payload: &[u8]) {
    for explicit_hook in [false, true] {
        let env = Env::new();
        let mut command = env.command(None);
        command
            .args(["--agent", "unknown"])
            .env("DCG_FAIL_CLOSED", "0")
            .env("DCG_HOOK_TIMEOUT_MS", "30000")
            .stdin(Stdio::piped());
        if explicit_hook {
            command.arg("hook");
        }
        let mut child = command.spawn().expect("spawn raw-payload hook");
        child
            .stdin
            .take()
            .expect("hook stdin")
            .write_all(payload)
            .expect("write raw hook payload");
        let output = child.wait_with_output().expect("wait for hook");

        // Claude-compatible hosts consume the JSON denial on exit zero. A
        // silent fail-open or a parser crash must not count as protection.
        assert_success(&output);
        let response: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!("invalid hook JSON ({error}): {}", output_text(&output))
        });
        assert_eq!(
            response["hookSpecificOutput"]["permissionDecision"],
            "deny",
            "{}",
            output_text(&output)
        );
    }
}

fn report(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("invalid doctor JSON ({error}): {}", output_text(output)))
}

fn check<'a>(report: &'a Value, id: &str) -> &'a Value {
    report["checks"]
        .as_array()
        .expect("doctor checks")
        .iter()
        .find(|check| check["id"] == id)
        .unwrap_or_else(|| panic!("missing {id} check: {report}"))
}

fn read_settings(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).expect("settings file"))
        .expect("valid settings JSON")
}

fn write_settings(path: &Path, settings: &Value) {
    std::fs::create_dir_all(path.parent().expect("settings directory"))
        .expect("create settings directory");
    std::fs::write(path, serde_json::to_vec_pretty(settings).expect("JSON"))
        .expect("write settings");
}

fn unrelated_settings() -> Value {
    json!({
        "theme": "dark",
        "permissions": { "allow": ["Read"] },
        "env": { "USER_SETTING": "keep me" },
        "hooks": {
            "PreToolUse": [{
                "matcher": "Bash",
                "hooks": [{ "type": "command", "command": "other-hook", "timeout": 13 }],
            }],
            "PostToolUse": [{
                "matcher": "Read",
                "hooks": [{ "type": "command", "command": "after-read-hook" }],
            }],
        },
    })
}

fn assert_unrelated_settings_preserved(settings: &Value) {
    let original = unrelated_settings();
    for key in ["theme", "permissions", "env"] {
        assert_eq!(settings[key], original[key], "lost {key}: {settings}");
    }
    assert_eq!(
        settings["hooks"]["PostToolUse"], original["hooks"]["PostToolUse"],
        "unrelated hook event changed: {settings}"
    );
    let entries = settings["hooks"]["PreToolUse"]
        .as_array()
        .expect("PreToolUse entries");
    assert!(
        entries.contains(&original["hooks"]["PreToolUse"][0]),
        "coexisting hook lost its matcher or host-owned timeout: {settings}"
    );
}

fn assert_installed(path: &Path) {
    let settings = read_settings(path);
    assert_unrelated_settings_preserved(&settings);
    let entries = settings["hooks"]["PreToolUse"]
        .as_array()
        .expect("PreToolUse entries");
    let installed = entries
        .iter()
        .filter(|entry| entry["matcher"] == "Bash|PowerShell|Monitor")
        .collect::<Vec<_>>();
    assert_eq!(
        installed.len(),
        1,
        "expected one guarding entry: {settings}"
    );
    let hooks = installed[0]["hooks"].as_array().expect("guard hooks");
    assert_eq!(hooks.len(), 1, "expected one dcg hook: {settings}");
    assert_eq!(hooks[0]["type"], "command", "{settings}");
    assert!(
        hooks[0]["command"]
            .as_str()
            .is_some_and(|command| command.contains("dcg")),
        "expected dcg command: {settings}"
    );
}

fn assert_doctor_healthy(env: &Env, config_dir: Option<&Path>, settings_path: &Path) {
    let output = env.run(config_dir, &["doctor", "--strict", "--format", "json"]);
    assert_success(&output);
    let document = report(&output);
    assert_eq!(document["ok"], true, "{document}");
    assert_eq!(
        check(&document, "hook_wiring")["status"],
        "ok",
        "{document}"
    );
    assert!(
        check(&document, "claude_settings")["message"]
            .as_str()
            .expect("settings message")
            .contains(settings_path.to_string_lossy().as_ref()),
        "JSON must name the inspected settings file: {document}"
    );
    let pretty = env.run(config_dir, &["doctor", "--strict", "--format", "pretty"]);
    assert_success(&pretty);
    assert!(
        output_text(&pretty).contains(settings_path.to_string_lossy().as_ref()),
        "pretty output must name the inspected settings file: {}",
        output_text(&pretty)
    );
}

#[test]
fn unset_and_empty_override_preserve_the_default_install_lifecycle() {
    for config_dir in [None, Some(Path::new(""))] {
        let env = Env::new();
        let settings_path = env.default_settings();
        write_settings(&settings_path, &unrelated_settings());
        assert_success(&env.run(config_dir, &["install"]));
        assert_installed(&settings_path);
        let installed = std::fs::read(&settings_path).expect("installed bytes");
        assert_success(&env.run(config_dir, &["install"]));
        assert_eq!(std::fs::read(&settings_path).unwrap(), installed);
        assert_doctor_healthy(&env, config_dir, &settings_path);
        assert_success(&env.run(config_dir, &["uninstall"]));
        assert_eq!(read_settings(&settings_path), unrelated_settings());
    }
}

#[test]
fn unset_and_empty_override_keep_missing_default_settings_nonfatal() {
    for config_dir in [None, Some(Path::new(""))] {
        let env = Env::new();
        let output = env.run(config_dir, &["doctor", "--strict", "--format", "json"]);
        assert_success(&output);
        let document = report(&output);
        assert_eq!(check(&document, "claude_settings")["status"], "warning");
        assert_eq!(check(&document, "hook_wiring")["status"], "skipped");
        assert!(!env.default_settings().exists());
    }
}

#[test]
fn absolute_relative_and_home_paths_share_the_active_install_lifecycle() {
    let env = Env::new();
    let cases = [
        (env.active_dir(), env.active_dir()),
        (
            PathBuf::from("profiles/relative config"),
            env.cwd.join("profiles").join("relative config"),
        ),
        (
            PathBuf::from("~/profiles/home config"),
            env.home.join("profiles").join("home config"),
        ),
        (PathBuf::from("~"), env.home.clone()),
        #[cfg(unix)]
        (PathBuf::from("   "), env.cwd.join("   ")),
    ];
    write_settings(&env.default_settings(), &unrelated_settings());
    let default_bytes = std::fs::read(env.default_settings()).unwrap();

    for (config_dir, resolved_dir) in cases {
        let settings_path = resolved_dir.join("settings.json");
        write_settings(&settings_path, &unrelated_settings());
        assert_success(&env.run(Some(&config_dir), &["install"]));
        assert_installed(&settings_path);
        let installed = std::fs::read(&settings_path).unwrap();
        assert_success(&env.run(Some(&config_dir), &["install", "--force"]));
        assert_eq!(std::fs::read(&settings_path).unwrap(), installed);
        assert_doctor_healthy(&env, Some(&config_dir), &settings_path);

        write_settings(&settings_path, &unrelated_settings());
        env.hook(Some(&config_dir), "CLAUDE_SESSION_ID");
        assert_installed(&settings_path);
        assert_success(&env.run(Some(&config_dir), &["uninstall"]));
        assert_eq!(read_settings(&settings_path), unrelated_settings());
        assert_eq!(
            std::fs::read(env.default_settings()).unwrap(),
            default_bytes
        );
    }
}

#[cfg(unix)]
#[test]
fn non_utf8_override_is_not_discarded_in_favor_of_the_default() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;

    let env = Env::new();
    let config_dir = PathBuf::from(OsString::from_vec(b"claude-\xff".to_vec()));
    let settings_path = env.cwd.join(&config_dir).join("settings.json");
    write_settings(&settings_path, &unrelated_settings());
    write_settings(&env.default_settings(), &unrelated_settings());
    let default_bytes = std::fs::read(env.default_settings()).unwrap();

    assert_success(&env.run(Some(&config_dir), &["install"]));
    assert_installed(&settings_path);
    assert_doctor_healthy(&env, Some(&config_dir), &settings_path);
    assert_success(&env.run(Some(&config_dir), &["uninstall"]));
    assert_eq!(read_settings(&settings_path), unrelated_settings());
    assert_eq!(
        std::fs::read(env.default_settings()).unwrap(),
        default_bytes
    );
}

#[test]
fn protected_default_cannot_mask_missing_or_unprotected_active_settings() {
    for active_exists in [false, true] {
        let env = Env::new();
        write_settings(&env.default_settings(), &unrelated_settings());
        assert_success(&env.run(None, &["install"]));
        assert_doctor_healthy(&env, None, &env.default_settings());
        let default_bytes = std::fs::read(env.default_settings()).unwrap();
        let active_dir = env.active_dir();
        let active_settings = active_dir.join("settings.json");
        if active_exists {
            write_settings(&active_settings, &unrelated_settings());
        }

        for format in ["pretty", "json"] {
            let output = env.run(
                Some(&active_dir),
                &["doctor", "--strict", "--format", format],
            );
            assert_eq!(output.status.code(), Some(1), "{}", output_text(&output));
            if format == "json" {
                let document = report(&output);
                assert_eq!(document["ok"], false, "{document}");
                assert_eq!(check(&document, "hook_wiring")["status"], "error");
                assert!(
                    check(&document, "claude_settings")["message"]
                        .as_str()
                        .expect("settings path message")
                        .contains(active_settings.to_string_lossy().as_ref()),
                    "{document}"
                );
            } else {
                assert!(
                    output_text(&output).contains(active_settings.to_string_lossy().as_ref()),
                    "{}",
                    output_text(&output)
                );
            }
            assert_eq!(
                std::fs::read(env.default_settings()).unwrap(),
                default_bytes
            );
            assert_eq!(active_settings.exists(), active_exists);
            if active_exists {
                assert_eq!(read_settings(&active_settings), unrelated_settings());
            }
        }

        assert_success(&env.run(Some(&active_dir), &["install"]));
        assert_doctor_healthy(&env, Some(&active_dir), &active_settings);
        assert_eq!(
            std::fs::read(env.default_settings()).unwrap(),
            default_bytes
        );
    }
}

#[test]
fn doctor_fix_repairs_the_active_file_and_preserves_the_default() {
    for format in ["pretty", "json"] {
        let env = Env::new();
        write_settings(&env.default_settings(), &unrelated_settings());
        assert_success(&env.run(None, &["install"]));
        let default_bytes = std::fs::read(env.default_settings()).unwrap();
        let active_dir = env.active_dir();
        let active_settings = active_dir.join("settings.json");
        write_settings(&active_settings, &unrelated_settings());

        let output = env.run(
            Some(&active_dir),
            &["doctor", "--fix", "--strict", "--format", format],
        );
        assert_success(&output);
        if format == "json" {
            let document = report(&output);
            assert_eq!(check(&document, "hook_wiring")["fixed"], true);
        }
        assert_installed(&active_settings);
        assert_eq!(
            std::fs::read(env.default_settings()).unwrap(),
            default_bytes
        );
        assert_doctor_healthy(&env, Some(&active_dir), &active_settings);
    }
}

#[test]
fn doctor_fix_creates_missing_explicit_configuration() {
    for format in ["pretty", "json"] {
        let env = Env::new();
        let active_dir = env.active_dir();
        let output = env.run(
            Some(&active_dir),
            &["doctor", "--fix", "--strict", "--format", format],
        );
        assert_success(&output);
        if format == "json" {
            let document = report(&output);
            let settings_check = check(&document, "claude_settings");
            assert_eq!(settings_check["status"], "ok", "{document}");
            assert!(
                !settings_check["message"]
                    .as_str()
                    .expect("settings message")
                    .contains("not found"),
                "a successful repair must not report the settings as still missing: {document}"
            );
        }
        assert_doctor_healthy(&env, Some(&active_dir), &active_dir.join("settings.json"));
        assert!(!env.default_settings().exists());
    }
}

#[test]
fn self_heal_repairs_only_the_active_file_and_then_leaves_it_unchanged() {
    let env = Env::new();
    let active_dir = env.active_dir();
    let active_settings = active_dir.join("settings.json");
    write_settings(&env.default_settings(), &unrelated_settings());
    write_settings(&active_settings, &unrelated_settings());
    let default_bytes = std::fs::read(env.default_settings()).unwrap();

    env.hook(Some(&active_dir), "CLAUDE_SESSION_ID");
    assert_installed(&active_settings);
    assert_doctor_healthy(&env, Some(&active_dir), &active_settings);
    assert_eq!(
        std::fs::read(env.default_settings()).unwrap(),
        default_bytes
    );
    let repaired_bytes = std::fs::read(&active_settings).unwrap();

    env.hook(Some(&active_dir), "CLAUDE_SESSION_ID");
    assert_eq!(std::fs::read(&active_settings).unwrap(), repaired_bytes);
    assert_eq!(
        std::fs::read(env.default_settings()).unwrap(),
        default_bytes
    );
}

#[test]
fn self_heal_does_not_fall_back_when_the_active_settings_file_is_absent() {
    let env = Env::new();
    let active_dir = env.active_dir();
    write_settings(&env.default_settings(), &unrelated_settings());
    let default_bytes = std::fs::read(env.default_settings()).unwrap();
    env.hook(Some(&active_dir), "CLAUDE_SESSION_ID");
    assert!(!active_dir.join("settings.json").exists());
    assert_eq!(
        std::fs::read(env.default_settings()).unwrap(),
        default_bytes
    );
}

#[test]
fn malformed_active_settings_never_fall_back_or_get_overwritten() {
    let env = Env::new();
    write_settings(&env.default_settings(), &unrelated_settings());
    assert_success(&env.run(None, &["install"]));
    let default_bytes = std::fs::read(env.default_settings()).unwrap();
    let active_dir = env.active_dir();
    let active_settings = active_dir.join("settings.json");
    std::fs::create_dir_all(&active_dir).expect("active directory");
    let malformed = b"{\"permissions\": {\"allow\": [\"Read\"]},";
    std::fs::write(&active_settings, malformed).expect("malformed fixture");

    for args in [
        &["install", "--force"][..],
        &["uninstall"][..],
        &["doctor", "--fix", "--strict", "--format", "pretty"][..],
        &["doctor", "--fix", "--strict", "--format", "json"][..],
    ] {
        let output = env.run(Some(&active_dir), args);
        assert!(!output.status.success(), "{}", output_text(&output));
        assert_eq!(std::fs::read(&active_settings).unwrap(), malformed);
        assert_eq!(
            std::fs::read(env.default_settings()).unwrap(),
            default_bytes
        );
    }
    env.hook(Some(&active_dir), "CLAUDE_SESSION_ID");
    assert_eq!(std::fs::read(&active_settings).unwrap(), malformed);
    assert_eq!(
        std::fs::read(env.default_settings()).unwrap(),
        default_bytes
    );
}

#[test]
fn project_install_ignores_the_user_configuration_override() {
    let env = Env::new();
    std::fs::create_dir_all(env.cwd.join(".git")).expect("repository marker");
    let nested_cwd = env.cwd.join("src").join("nested");
    std::fs::create_dir_all(&nested_cwd).expect("nested cwd");
    let active_dir = env.active_dir();
    let active_settings = active_dir.join("settings.json");
    let project_settings = env.cwd.join(".claude").join("settings.json");
    for path in [&env.default_settings(), &active_settings, &project_settings] {
        write_settings(path, &unrelated_settings());
    }
    let default_bytes = std::fs::read(env.default_settings()).unwrap();
    let active_bytes = std::fs::read(&active_settings).unwrap();
    let output = env
        .command(Some(&active_dir))
        .current_dir(&nested_cwd)
        .args(["install", "--project"])
        .output()
        .expect("project install");
    assert_success(&output);
    assert_installed(&project_settings);
    assert_eq!(std::fs::read(&active_settings).unwrap(), active_bytes);
    assert_eq!(
        std::fs::read(env.default_settings()).unwrap(),
        default_bytes
    );
}

#[cfg(unix)]
#[test]
fn setup_upgrades_a_stale_shell_check_and_installs_into_the_active_directory() {
    let env = Env::new();
    let bashrc = env.home.join(".bashrc");
    let old_check = r#"# user initialization before
# dcg: warn if hook was silently removed from Claude Code settings
if command -v dcg &>/dev/null && command -v jq &>/dev/null; then
  if [ -f "$HOME/.claude/settings.json" ] && \
     ! jq -e '.hooks.PreToolUse[]? | select(.hooks[]?.command | test("dcg\"?$"))' \
       "$HOME/.claude/settings.json" &>/dev/null; then
    printf '\033[1;33m[dcg] Hook missing from ~/.claude/settings.json — run: dcg install\033[0m\n'
  fi
fi
# user initialization after
"#;
    std::fs::write(&bashrc, old_check).expect("old startup check");
    let active_dir = env.active_dir();
    let active_settings = active_dir.join("settings.json");
    write_settings(&active_settings, &unrelated_settings());

    assert_success(&env.run(Some(&active_dir), &["setup", "--shell-check"]));
    assert_installed(&active_settings);
    assert!(!env.default_settings().exists());
    let upgraded = std::fs::read_to_string(&bashrc).expect("upgraded startup check");
    assert!(
        upgraded.contains("CLAUDE_CONFIG_DIR"),
        "setup must replace the previously installed hardcoded startup check: {upgraded}"
    );
    assert!(upgraded.starts_with("# user initialization before\n"));
    assert!(upgraded.ends_with("# user initialization after\n"));
    assert_eq!(
        upgraded
            .matches("# dcg: warn if hook was silently removed")
            .count(),
        1,
        "the old block must be upgraded in place: {upgraded}"
    );
    assert_success(&env.run(Some(&active_dir), &["setup", "--shell-check"]));
    assert_eq!(std::fs::read_to_string(&bashrc).unwrap(), upgraded);
}

#[test]
fn grok_diagnostics_use_the_fixed_claude_compatibility_path() {
    for protect_default in [false, true] {
        let env = Env::new();
        let active_dir = env.active_dir();
        let active_settings = active_dir.join("settings.json");
        write_settings(&env.default_settings(), &unrelated_settings());
        write_settings(&active_settings, &unrelated_settings());
        let install_dir = (!protect_default).then_some(active_dir.as_path());
        assert_success(&env.run(install_dir, &["install"]));
        std::fs::create_dir_all(env.home.join(".grok")).expect("Grok in use");
        let default_bytes = std::fs::read(env.default_settings()).unwrap();
        let active_bytes = std::fs::read(&active_settings).unwrap();

        let output = env.run(
            Some(&active_dir),
            &["doctor", "--strict", "--format", "json"],
        );
        assert_eq!(output.status.code(), Some(1), "{}", output_text(&output));
        let document = report(&output);
        assert_eq!(
            check(&document, "grok_hook")["status"],
            if protect_default { "ok" } else { "error" },
            "Grok reads ~/.claude independently of CLAUDE_CONFIG_DIR: {document}"
        );
        assert_eq!(
            check(&document, "hook_wiring")["status"],
            if protect_default { "error" } else { "ok" },
            "Claude must report the independently selected file: {document}"
        );
        let pretty = env.run(
            Some(&active_dir),
            &["doctor", "--strict", "--format", "pretty"],
        );
        assert_eq!(pretty.status.code(), Some(1), "{}", output_text(&pretty));
        let grok_line = String::from_utf8_lossy(&pretty.stdout)
            .lines()
            .find(|line| line.contains("Checking Grok hook registration"))
            .expect("pretty Grok status")
            .to_owned();
        assert!(
            grok_line.contains(if protect_default {
                "OK (via Claude compat)"
            } else {
                "NOT REGISTERED"
            }),
            "Grok pretty diagnostic disagrees with JSON: {grok_line}"
        );
        assert_eq!(
            std::fs::read(env.default_settings()).unwrap(),
            default_bytes
        );
        assert_eq!(std::fs::read(&active_settings).unwrap(), active_bytes);
    }
}

#[test]
fn grok_compatibility_accepts_legacy_claude_shell_matchers() {
    for legacy_matcher in ["Bash", "Bash|PowerShell"] {
        let env = Env::new();
        let active_dir = env.active_dir();
        let active_settings = active_dir.join("settings.json");
        write_settings(&env.default_settings(), &unrelated_settings());
        write_settings(&active_settings, &unrelated_settings());
        assert_success(&env.run(None, &["install"]));
        assert_success(&env.run(Some(&active_dir), &["install"]));
        let mut settings = read_settings(&env.default_settings());
        let entry = settings["hooks"]["PreToolUse"]
            .as_array_mut()
            .expect("PreToolUse entries")
            .iter_mut()
            .find(|entry| entry["matcher"] == "Bash|PowerShell|Monitor")
            .expect("installed dcg entry");
        // Keep the current executable, synchronous hook and platform shell;
        // only Grok's historically supported matcher differs from Claude's.
        entry["matcher"] = json!(legacy_matcher);
        write_settings(&env.default_settings(), &settings);
        std::fs::create_dir_all(env.home.join(".grok")).expect("Grok in use");
        let default_bytes = std::fs::read(env.default_settings()).unwrap();
        let active_bytes = std::fs::read(&active_settings).unwrap();

        let output = env.run(
            Some(&active_dir),
            &["doctor", "--strict", "--format", "json"],
        );
        assert_success(&output);
        let document = report(&output);
        assert_eq!(document["ok"], true, "{legacy_matcher}: {document}");
        assert_eq!(
            check(&document, "hook_wiring")["status"],
            "ok",
            "{document}"
        );
        assert_eq!(check(&document, "grok_hook")["status"], "ok", "{document}");

        let pretty = env.run(
            Some(&active_dir),
            &["doctor", "--strict", "--format", "pretty"],
        );
        assert_success(&pretty);
        let pretty_text = String::from_utf8_lossy(&pretty.stdout);
        let grok_line = pretty_text
            .lines()
            .find(|line| line.contains("Checking Grok hook registration"))
            .expect("pretty Grok status");
        assert!(
            grok_line.contains("OK (via Claude compat)"),
            "{legacy_matcher}: {pretty_text}"
        );
        assert_eq!(
            std::fs::read(env.default_settings()).unwrap(),
            default_bytes
        );
        assert_eq!(std::fs::read(&active_settings).unwrap(), active_bytes);
    }
}

#[test]
fn healthy_claude_override_cannot_mask_a_broken_grok_compatibility_hook() {
    for defect in ["async", "wrong matcher", "missing executable"] {
        let env = Env::new();
        let active_dir = env.active_dir();
        write_settings(&env.default_settings(), &unrelated_settings());
        write_settings(&active_dir.join("settings.json"), &unrelated_settings());
        assert_success(&env.run(None, &["install"]));
        assert_success(&env.run(Some(&active_dir), &["install"]));
        std::fs::create_dir_all(env.home.join(".grok")).expect("Grok in use");
        let mut settings = read_settings(&env.default_settings());
        let entry = settings["hooks"]["PreToolUse"]
            .as_array_mut()
            .expect("PreToolUse entries")
            .iter_mut()
            .find(|entry| entry["matcher"] == "Bash|PowerShell|Monitor")
            .expect("installed dcg entry");
        match defect {
            "async" => entry["hooks"][0]["async"] = json!(true),
            "wrong matcher" => entry["matcher"] = json!("Read"),
            "missing executable" => {
                entry["hooks"][0]["command"] = json!(
                    env.home
                        .join("missing-bin")
                        .join(format!("dcg{}", std::env::consts::EXE_SUFFIX))
                );
            }
            _ => unreachable!("known defect"),
        }
        write_settings(&env.default_settings(), &settings);

        let output = env.run(
            Some(&active_dir),
            &["doctor", "--strict", "--format", "json"],
        );
        assert_eq!(
            output.status.code(),
            Some(1),
            "{defect}: {}",
            output_text(&output)
        );
        let document = report(&output);
        assert_eq!(
            check(&document, "hook_wiring")["status"],
            "ok",
            "{document}"
        );
        assert_eq!(
            check(&document, "grok_hook")["status"],
            "error",
            "{document}"
        );
        let pretty = env.run(
            Some(&active_dir),
            &["doctor", "--strict", "--format", "pretty"],
        );
        assert_eq!(
            pretty.status.code(),
            Some(1),
            "{defect}: {}",
            output_text(&pretty)
        );
        assert_eq!(read_settings(&env.default_settings()), settings);
    }
}

#[test]
fn grok_self_heal_keeps_its_fixed_compatibility_settings_path() {
    let env = Env::new();
    let active_dir = env.active_dir();
    let active_settings = active_dir.join("settings.json");
    write_settings(&env.default_settings(), &unrelated_settings());
    write_settings(&active_settings, &unrelated_settings());
    let active_bytes = std::fs::read(&active_settings).unwrap();

    env.hook(Some(&active_dir), "GROK_SESSION_ID");
    assert_installed(&env.default_settings());
    assert_eq!(std::fs::read(&active_settings).unwrap(), active_bytes);
}

#[test]
fn wire_identified_non_claude_self_heal_ignores_the_claude_override() {
    for payload in [
        json!({
            "hookEventName": "pre_tool_use",
            "toolName": "run_terminal_command",
            "toolInput": { "command": "git status" },
        }),
        json!({
            "event": "PreToolUse",
            "toolName": "bash",
            "toolArgs": { "command": "git status" },
        }),
        json!({
            "hook_event_name": "PreToolUse",
            "cursor_version": "2026.09.28",
            "tool_name": "Shell",
            "tool_input": { "command": "git status" },
        }),
        json!({
            "sessionId": "vscode-session-541",
            "toolCalls": [{
                "name": "bash",
                "args": "{\"command\":\"git status\"}",
            }],
        }),
    ] {
        for explicit_hook in [false, true] {
            let env = Env::new();
            let active_dir = env.active_dir();
            let active_settings = active_dir.join("settings.json");
            write_settings(&env.default_settings(), &unrelated_settings());
            write_settings(&active_settings, &unrelated_settings());
            let active_bytes = std::fs::read(&active_settings).unwrap();
            let mut payload = payload.clone();
            payload["cwd"] = json!(env.cwd);

            // Pin the ambient detector to Unknown so this test cannot inherit
            // an agent from the test runner's process ancestry. The native
            // envelope alone identifies the compatibility host before healing.
            let mut args = vec!["--agent", "unknown"];
            if explicit_hook {
                args.push("hook");
            }
            env.hook_payload(Some(&active_dir), &args, None, &payload);

            assert_installed(&env.default_settings());
            assert_eq!(
                std::fs::read(&active_settings).unwrap(),
                active_bytes,
                "non-Claude envelope changed Claude's active settings: {payload}"
            );
        }
    }
}

#[test]
fn non_shell_batches_do_not_redirect_claude_self_healing() {
    for tool_calls in [
        json!([]),
        json!([{ "name": "readFile", "args": { "path": "README.md" } }]),
    ] {
        for explicit_hook in [false, true] {
            let env = Env::new();
            let active_dir = env.active_dir();
            let active_settings = active_dir.join("settings.json");
            write_settings(&env.default_settings(), &unrelated_settings());
            write_settings(&active_settings, &unrelated_settings());
            let default_bytes = std::fs::read(env.default_settings()).unwrap();
            let payload = json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": { "command": "git status" },
                "toolCalls": tool_calls,
                "cwd": env.cwd,
            });
            let mut args = vec!["--agent", "unknown"];
            if explicit_hook {
                args.push("hook");
            }
            env.hook_payload(Some(&active_dir), &args, None, &payload);

            assert_installed(&active_settings);
            assert_eq!(
                std::fs::read(env.default_settings()).unwrap(),
                default_bytes,
                "an empty or unrelated batch redirected Claude self-healing: {payload}"
            );
        }
    }
}

#[test]
fn duplicate_cursor_metadata_does_not_hide_a_destructive_bash_command() {
    // Keep the duplicate key in raw JSON: constructing a Value would collapse
    // it before dcg's metadata tolerance could be exercised.
    let payload = br#"{"cursor_version":"2026.09.28","cursor_version":"2026.10.08","tool_name":"Bash","tool_input":{"command":"git reset --hard"}}"#;
    assert_blocked_hook_payload(payload);
}

#[test]
fn duplicate_cursor_metadata_does_not_hide_a_destructive_vscode_batch() {
    // The malformed-input salvage scanner cannot decode this native batch.
    // Duplicate or wrong-typed host metadata must leave its normal command
    // extraction available, including the JSON-encoded args string.
    let payload = br#"{"cursor_version":"2026.09.28","cursor_version":null,"cursor_version":{"unknown":true},"toolCalls":[{"name":"bash","args":"{\"command\":\"git reset --hard\"}"}]}"#;
    assert_blocked_hook_payload(payload);
}

#[test]
fn unknown_metadata_does_not_change_native_batch_protection() {
    // Ignored metadata can contain JSON numbers outside f64's range. A
    // metadata reader must not materialize every unknown value and turn this
    // otherwise valid native batch into an unparseable, unscannable payload.
    let payload = br#"{"cursor_version":"2026.09.28","unknown_metadata":1e1000,"unknown_metadata":{"nested":[false,null,{"more":"metadata"}]},"toolCalls":[{"name":"bash","args":"{\"command\":\"git reset --hard\"}"}]}"#;
    assert_blocked_hook_payload(payload);
}
