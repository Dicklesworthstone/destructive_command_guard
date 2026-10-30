//! Real-binary Factory Droid installation, removal, and diagnostics regressions.
//!
//! These tests only execute DCG. Shell commands in hook payloads are input data;
//! the Unix shell test runs the installed hook command, never the guarded command.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

struct Sandbox {
    _temp: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    repo: PathBuf,
    binary: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temporary Droid environment");
        let root = temp.path().to_path_buf();
        let home = root.join("home");
        let repo = root.join("repo");
        for directory in [&home, &repo.join(".git"), &root.join("tmp")] {
            std::fs::create_dir_all(directory).expect("create isolated directory");
        }
        Self {
            _temp: temp,
            root,
            home,
            repo,
            binary: PathBuf::from(env!("CARGO_BIN_EXE_dcg")),
        }
    }

    fn factory(&self) -> PathBuf {
        self.home.join(".factory")
    }

    fn settings(&self) -> PathBuf {
        self.factory().join("settings.json")
    }

    fn configure(&self, command: &mut Command) {
        command
            .env_clear()
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("XDG_DATA_HOME", self.root.join("data"))
            .env("XDG_CACHE_HOME", self.root.join("cache"))
            .env("APPDATA", self.root.join("appdata"))
            .env("LOCALAPPDATA", self.root.join("localappdata"))
            .env("ProgramData", self.root.join("programdata"))
            .env("ProgramFiles", self.root.join("programfiles"))
            .env("TEMP", self.root.join("tmp"))
            .env("TMP", self.root.join("tmp"))
            .env("TMPDIR", self.root.join("tmp"))
            .env(
                "DCG_CONFIG",
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/e2e/fixtures/configs/minimal.toml"),
            )
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("DCG_NO_UPDATE_CHECK", "1")
            .env("DCG_HISTORY_DISABLED", "1")
            .env(
                "DCG_PENDING_EXCEPTIONS_PATH",
                self.root.join("pending-exceptions.jsonl"),
            )
            .env("DCG_ALLOW_ONCE_PATH", self.root.join("allow-once.jsonl"))
            .env("NO_COLOR", "1")
            .current_dir(&self.repo)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Keep Windows' system DLL/process discovery available without inheriting
        // the caller's agent markers, configuration, or command search path.
        for variable in ["SystemRoot", "WINDIR"] {
            if let Some(value) = std::env::var_os(variable) {
                command.env(variable, value);
            }
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_at(args, &self.repo)
    }

    fn run_at(&self, args: &[&str], directory: &Path) -> Output {
        let mut command = Command::new(&self.binary);
        self.configure(&mut command);
        command
            .args(args)
            .current_dir(directory)
            .output()
            .expect("run the DCG binary")
    }

    fn install(&self) -> Value {
        assert_success(&self.run(&["install", "--droid"]));
        read_json(&self.settings())
    }

    fn doctor(&self, fix: bool) -> Value {
        let mut args = vec!["--agent", "droid", "doctor", "--format", "json"];
        if fix {
            args.push("--fix");
        }
        let output = self.run(&args);
        let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "invalid doctor JSON: {error}; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        report["checks"]
            .as_array()
            .expect("doctor checks")
            .iter()
            .find(|check| check["id"] == "droid_hook")
            .unwrap_or_else(|| panic!("missing Droid doctor check: {report}"))
            .clone()
    }
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "DCG failed: status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn write_json(path: &Path, value: &Value) {
    std::fs::create_dir_all(path.parent().expect("configuration parent"))
        .expect("create configuration directory");
    std::fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("fixture JSON"),
    )
    .expect("write configuration fixture");
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).expect("read configuration"))
        .expect("valid configuration JSON")
}

fn event_map(document: &Value, standalone: bool) -> &Value {
    if standalone {
        document
    } else {
        &document["hooks"]
    }
}

fn registered_handler(document: &Value, standalone: bool) -> &Value {
    let groups = event_map(document, standalone)["PreToolUse"]
        .as_array()
        .expect("PreToolUse groups");
    let handlers: Vec<&Value> = groups
        .iter()
        .filter(|group| group["matcher"] == "Execute")
        .flat_map(|group| group["hooks"].as_array().expect("hook handlers"))
        .filter(|handler| {
            handler["command"]
                .as_str()
                .is_some_and(|command| command.ends_with(" --agent droid"))
        })
        .collect();
    assert_eq!(handlers.len(), 1, "one Execute registration: {document}");
    assert_eq!(handlers[0]["type"], "command");
    handlers[0]
}

fn audit_group() -> Value {
    json!({
        "matcher": "Read|Execute",
        "hooks": [{"type": "command", "command": "/opt/company/audit-hook", "timeout": 7}]
    })
}

#[test]
fn user_install_is_idempotent_and_preserves_unrelated_settings_and_hooks() {
    let sandbox = Sandbox::new();
    let original = json!({
        "model": "operator-selected-model",
        "customModels": [{"id": "custom:local", "extraArgs": {"temperature": 0}}],
        "hooks": {
            "PreToolUse": [audit_group()],
            "PostToolUse": [{"matcher": "Edit", "hooks": [{"type": "command", "command": "/opt/company/format"}]}]
        }
    });
    write_json(&sandbox.settings(), &original);
    let installed = sandbox.install();
    registered_handler(&installed, false);
    assert_eq!(installed["model"], original["model"]);
    assert_eq!(installed["customModels"], original["customModels"]);
    assert_eq!(
        installed["hooks"]["PostToolUse"],
        original["hooks"]["PostToolUse"]
    );
    assert!(
        installed["hooks"]["PreToolUse"]
            .as_array()
            .unwrap()
            .contains(&audit_group())
    );
    assert!(!sandbox.factory().join("hooks.json").exists());
    assert!(!sandbox.home.join(".claude").exists());

    let first_bytes = std::fs::read(sandbox.settings()).unwrap();
    assert_success(&sandbox.run(&["install", "--droid"]));
    assert_eq!(std::fs::read(sandbox.settings()).unwrap(), first_bytes);
    assert_eq!(sandbox.doctor(false)["status"], "ok");

    assert_success(&sandbox.run(&["uninstall", "--droid"]));
    assert_eq!(read_json(&sandbox.settings()), original);
    let removed_bytes = std::fs::read(sandbox.settings()).unwrap();
    assert_success(&sandbox.run(&["uninstall", "--droid"]));
    assert_eq!(std::fs::read(sandbox.settings()).unwrap(), removed_bytes);
}

#[test]
fn force_refresh_preserves_host_owned_timeout_and_metadata() {
    let sandbox = Sandbox::new();
    let mut settings = sandbox.install();
    let handler = &mut settings["hooks"]["PreToolUse"][0]["hooks"][0];
    handler["timeout"] = json!(17);
    handler["operatorNote"] = json!({"ticket": "SEC-617"});
    write_json(&sandbox.settings(), &settings);
    assert_success(&sandbox.run(&["install", "--droid", "--force"]));
    let refreshed = read_json(&sandbox.settings());
    let handler = registered_handler(&refreshed, false);
    assert_eq!(handler["timeout"], 17);
    assert_eq!(handler["operatorNote"], json!({"ticket": "SEC-617"}));
    assert_eq!(sandbox.doctor(false)["status"], "ok");
}

#[test]
fn repairing_a_filtered_execute_group_preserves_its_siblings_and_adds_full_coverage() {
    let sandbox = Sandbox::new();
    let installed = sandbox.install();
    let handler = registered_handler(&installed, false).clone();
    let filtered = json!({
        "matcher": "Execute",
        "commandRegex": "^git status$",
        "operatorNote": "audit only this command",
        "hooks": [{"type": "command", "command": "/opt/company/status-audit", "timeout": 3}]
    });
    let expected_after_removal = json!({
        "model": "unchanged",
        "hooks": {"PreToolUse": [filtered.clone(), audit_group()]}
    });
    let mut settings = expected_after_removal.clone();
    settings["hooks"]["PreToolUse"][0]["hooks"]
        .as_array_mut()
        .unwrap()
        .insert(0, handler);
    write_json(&sandbox.settings(), &settings);
    assert_success(&sandbox.run(&["install", "--droid", "--force"]));

    let repaired = read_json(&sandbox.settings());
    let groups = repaired["hooks"]["PreToolUse"].as_array().unwrap();
    assert_eq!(groups.len(), 3, "DCG needs its own unfiltered group");
    assert!(
        groups.contains(&filtered),
        "keep the sibling's filter: {repaired}"
    );
    assert!(groups.contains(&audit_group()));
    let unfiltered = groups
        .iter()
        .find(|group| group["matcher"] == "Execute" && group.get("commandRegex").is_none())
        .expect("unfiltered Execute group");
    assert_eq!(unfiltered["hooks"].as_array().unwrap().len(), 1);
    registered_handler(&repaired, false);
    assert_eq!(sandbox.doctor(false)["status"], "ok");

    assert_success(&sandbox.run(&["uninstall", "--droid"]));
    assert_eq!(read_json(&sandbox.settings()), expected_after_removal);
}

#[test]
fn force_install_refuses_conflicting_duplicate_host_policies_without_rewriting() {
    let sandbox = Sandbox::new();
    let installed = sandbox.install();
    let mut first = registered_handler(&installed, false).clone();
    first["timeout"] = json!(4);
    let mut second = first.clone();
    second["timeout"] = json!(20);
    write_json(
        &sandbox.settings(),
        &json!({
            "model": "unchanged",
            "hooks": {"PreToolUse": [
                {"matcher": "Execute", "hooks": [first]},
                {"matcher": "Bash|Execute", "hooks": [second]},
                audit_group()
            ]}
        }),
    );
    let before = std::fs::read(sandbox.settings()).unwrap();
    let output = sandbox.run(&["install", "--droid", "--force"]);
    assert!(
        !output.status.success(),
        "--force must not choose between conflicting timeout policies"
    );
    assert_eq!(std::fs::read(sandbox.settings()).unwrap(), before);
}

#[cfg(unix)]
#[test]
fn install_and_uninstall_preserve_settings_symlink_and_target_permissions() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let sandbox = Sandbox::new();
    let target = sandbox.root.join("shared-settings.json");
    let original = json!({"model": "shared-model", "hooks": {"PreToolUse": [audit_group()]}});
    write_json(&target, &original);
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
    std::fs::create_dir_all(sandbox.factory()).unwrap();
    symlink(&target, sandbox.settings()).unwrap();
    assert_success(&sandbox.run(&["install", "--droid"]));
    registered_handler(&read_json(&target), false);
    assert_eq!(std::fs::read_link(sandbox.settings()).unwrap(), target);
    assert_eq!(
        std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_success(&sandbox.run(&["uninstall", "--droid"]));
    assert_eq!(std::fs::read_link(sandbox.settings()).unwrap(), target);
    assert_eq!(read_json(&target), original);
    assert_eq!(
        std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o640
    );

    // A missing symlink target is not a fresh configuration file. Neither
    // operation may replace the link or create a target behind the operator's back.
    let dangling = Sandbox::new();
    let missing_target = dangling.root.join("missing-settings.json");
    std::fs::create_dir_all(dangling.factory()).unwrap();
    symlink(&missing_target, dangling.settings()).unwrap();
    for args in [
        &["install", "--droid", "--force"][..],
        &["uninstall", "--droid"][..],
    ] {
        assert!(!dangling.run(args).status.success());
        assert_eq!(
            std::fs::read_link(dangling.settings()).unwrap(),
            missing_target
        );
        assert!(!missing_target.exists());
    }
}

#[test]
fn existing_modern_hook_map_is_updated_without_shadowing_settings_hooks() {
    let sandbox = Sandbox::new();
    let settings = json!({"model": "keep-me", "hooks": {"PreToolUse": [audit_group()]}});
    write_json(&sandbox.settings(), &settings);
    let settings_bytes = std::fs::read(sandbox.settings()).unwrap();
    let hooks_path = sandbox.factory().join("hooks.json");
    let original = json!({
        "PreToolUse": [audit_group()],
        "SessionStart": [{"hooks": [{"type": "command", "command": "/opt/company/session"}]}]
    });
    write_json(&hooks_path, &original);
    assert_success(&sandbox.run(&["install", "--droid"]));
    let hooks = read_json(&hooks_path);
    registered_handler(&hooks, true);
    assert!(
        hooks.get("hooks").is_none(),
        "standalone map is not wrapped"
    );
    assert_eq!(hooks["SessionStart"], original["SessionStart"]);
    assert_eq!(std::fs::read(sandbox.settings()).unwrap(), settings_bytes);
    let installed_bytes = std::fs::read(&hooks_path).unwrap();
    assert_success(&sandbox.run(&["install", "--droid"]));
    assert_eq!(std::fs::read(&hooks_path).unwrap(), installed_bytes);
    assert_eq!(sandbox.doctor(false)["status"], "ok");
}

#[test]
fn existing_local_and_legacy_hook_files_can_be_installed_without_changing_settings() {
    for (relative, standalone) in [("settings.local.json", false), ("hooks/hooks.json", true)] {
        let sandbox = Sandbox::new();
        write_json(&sandbox.settings(), &json!({"model": "keep-me"}));
        let settings_bytes = std::fs::read(sandbox.settings()).unwrap();
        let path = sandbox.factory().join(relative);
        let map = json!({"PreToolUse": [audit_group()]});
        let original = if standalone {
            map
        } else {
            json!({"hooks": map, "showThinkingInMainView": false})
        };
        write_json(&path, &original);
        assert_success(&sandbox.run(&["install", "--droid"]));
        let installed = read_json(&path);
        registered_handler(&installed, standalone);
        assert_eq!(std::fs::read(sandbox.settings()).unwrap(), settings_bytes);
        assert!(!sandbox.factory().join("hooks.json").exists());
        assert_success(&sandbox.run(&["uninstall", "--droid"]));
        assert_eq!(read_json(&path), original, "preserve {relative}");
    }
}

#[test]
fn project_install_and_uninstall_leave_user_configuration_untouched() {
    let sandbox = Sandbox::new();
    sandbox.install();
    let user_bytes = std::fs::read(sandbox.settings()).unwrap();
    let project_path = sandbox.repo.join(".factory/settings.json");
    let original = json!({"model": "project-model", "hooks": {"PreToolUse": [audit_group()]}});
    write_json(&project_path, &original);
    let subdirectory = sandbox.repo.join("packages/tool");
    std::fs::create_dir_all(&subdirectory).unwrap();
    assert_success(&sandbox.run_at(&["install", "--droid", "--project"], &subdirectory));
    registered_handler(&read_json(&project_path), false);
    assert!(!subdirectory.join(".factory").exists());
    assert_eq!(std::fs::read(sandbox.settings()).unwrap(), user_bytes);

    assert_success(&sandbox.run_at(&["uninstall", "--droid", "--project"], &subdirectory));
    assert_eq!(read_json(&project_path), original);
    assert_eq!(std::fs::read(sandbox.settings()).unwrap(), user_bytes);
    assert_eq!(sandbox.doctor(false)["status"], "ok");
}

#[test]
fn project_install_outside_git_uses_the_current_directory_and_preserves_user_settings() {
    let sandbox = Sandbox::new();
    sandbox.install();
    let user_bytes = std::fs::read(sandbox.settings()).unwrap();
    let project = sandbox.root.join("new-folder");
    std::fs::create_dir_all(&project).unwrap();
    assert!(!project.join(".git").exists());
    assert!(!sandbox.root.join(".git").exists());

    assert_success(&sandbox.run_at(&["install", "--droid", "--project"], &project));
    let project_settings = project.join(".factory/settings.json");
    registered_handler(&read_json(&project_settings), false);
    assert_eq!(std::fs::read(sandbox.settings()).unwrap(), user_bytes);
    assert!(!sandbox.root.join(".factory").exists());
    assert!(!sandbox.repo.join(".factory").exists());

    assert_success(&sandbox.run_at(&["uninstall", "--droid", "--project"], &project));
    assert!(project_settings.is_file(), "uninstall preserves the file");
    assert!(
        read_json(&project_settings)["hooks"]["PreToolUse"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(std::fs::read(sandbox.settings()).unwrap(), user_bytes);
    assert!(!sandbox.root.join(".factory").exists());
    assert!(!sandbox.repo.join(".factory").exists());
}

#[test]
fn uninstall_removes_dcg_from_every_supported_file_and_preserves_shared_groups() {
    let sandbox = Sandbox::new();
    let installed = sandbox.install();
    let handler = registered_handler(&installed, false).clone();
    let project_path = sandbox.repo.join(".factory/hooks.json");
    write_json(
        &project_path,
        &json!({"PreToolUse": [{"matcher": "Execute", "hooks": [handler.clone()]}]}),
    );
    let project_bytes = std::fs::read(&project_path).unwrap();
    let other_handler = json!({"type": "command", "command": "/opt/company/audit", "timeout": 9});
    let mut expected_files = Vec::new();
    for (relative, standalone) in [
        ("settings.json", false),
        ("settings.local.json", false),
        ("hooks.json", true),
        ("hooks/hooks.json", true),
    ] {
        let original_map = json!({
            "PreToolUse": [{"matcher": "Execute", "operatorNote": "keep group", "hooks": [other_handler.clone()]}],
            "SessionStart": [{"hooks": [{"type": "command", "command": "/opt/company/session"}]}]
        });
        let mut map = original_map.clone();
        map["PreToolUse"][0]["hooks"]
            .as_array_mut()
            .unwrap()
            .push(handler.clone());
        let (document, expected) = if standalone {
            (map, original_map)
        } else {
            (
                json!({"hooks": map, "model": "unchanged"}),
                json!({"hooks": original_map, "model": "unchanged"}),
            )
        };
        let path = sandbox.factory().join(relative);
        write_json(&path, &document);
        expected_files.push((path, expected));
    }
    assert_success(&sandbox.run(&["uninstall", "--droid"]));
    for (path, expected) in expected_files {
        assert_eq!(read_json(&path), expected, "preserve {}", path.display());
    }
    assert_eq!(std::fs::read(project_path).unwrap(), project_bytes);
}

#[test]
fn malformed_or_duplicate_configuration_is_refused_without_rewriting_it() {
    for raw in [
        "{not JSON",
        r#"{"model":"first","model":"second"}"#,
        r#"{"hooks":{"PreToolUse":[],"PreToolUse":[]}}"#,
        r#"{"hooks":{"PreToolUse":{}}}"#,
        r#"{"hooks":{"PreToolUse":[{"matcher":"Execute","hooks":[null]}]}}"#,
        r#"{"hooks":{"PreToolUse":[{"matcher":"Execute","hooks":[{"type":"command"}]}]}}"#,
        r#"{"hooks":{"PreToolUse":[{"matcher":"Execute","hooks":[{"type":"command","command":42}]}]}}"#,
        r#"{"hooks":{"PreToolUse":[{"matcher":"Execute","hooks":[{"type":"prompt","command":"/opt/company/audit"}]}]}}"#,
        r#"{"hooks":{"PreToolUse":[{"matcher":"Execute","hooks":[{"type":"command","command":"/opt/company/audit","timeout":0}]}]}}"#,
        r#"{"hooks":{"PreToolUse":[{"matcher":"Execute","hooks":[{"type":"command","command":"/opt/company/audit","timeout":"30"}]}]}}"#,
    ] {
        let sandbox = Sandbox::new();
        std::fs::create_dir_all(sandbox.factory()).unwrap();
        std::fs::write(sandbox.settings(), raw).unwrap();
        let output = sandbox.run(&["install", "--droid", "--force"]);
        assert!(!output.status.success(), "must reject: {raw}");
        assert_eq!(std::fs::read_to_string(sandbox.settings()).unwrap(), raw);
        assert!(!sandbox.factory().join("hooks.json").exists());
    }
}

#[test]
fn uninstall_preflights_all_files_before_changing_any_registration() {
    let sandbox = Sandbox::new();
    let installed = sandbox.install();
    let handler = registered_handler(&installed, false).clone();
    let modern_path = sandbox.factory().join("hooks.json");
    write_json(
        &modern_path,
        &json!({"PreToolUse": [{"matcher": "Execute", "hooks": [handler]}]}),
    );
    let settings_before = std::fs::read(sandbox.settings()).unwrap();
    let modern_before = std::fs::read(&modern_path).unwrap();
    let legacy_path = sandbox.factory().join("hooks/hooks.json");
    std::fs::create_dir_all(legacy_path.parent().unwrap()).unwrap();
    let invalid = r#"{"PreToolUse":[],"PreToolUse":[]}"#;
    std::fs::write(&legacy_path, invalid).unwrap();

    let output = sandbox.run(&["uninstall", "--droid"]);
    assert!(!output.status.success());
    assert_eq!(std::fs::read(sandbox.settings()).unwrap(), settings_before);
    assert_eq!(std::fs::read(&modern_path).unwrap(), modern_before);
    assert_eq!(std::fs::read_to_string(legacy_path).unwrap(), invalid);
}

#[test]
fn doctor_reports_shadowed_settings_registration_and_fix_updates_the_active_file() {
    let sandbox = Sandbox::new();
    sandbox.install();
    let settings_before = std::fs::read(sandbox.settings()).unwrap();
    let hooks_path = sandbox.factory().join("hooks.json");
    write_json(&hooks_path, &json!({"PreToolUse": [audit_group()]}));
    let check = sandbox.doctor(false);
    assert_eq!(
        check["status"], "error",
        "shadowed DCG is not active: {check}"
    );
    let check = sandbox.doctor(true);
    assert_eq!(check["status"], "ok", "repair active registration: {check}");
    registered_handler(&read_json(&hooks_path), true);
    assert_eq!(std::fs::read(sandbox.settings()).unwrap(), settings_before);
}

#[test]
fn install_and_doctor_fix_never_clear_disabled_or_managed_only_policy() {
    for (relative, control) in [
        ("settings.json", "hooksDisabled"),
        ("settings.local.json", "hooksDisabled"),
        ("settings.json", "allowManagedHooksOnly"),
    ] {
        let sandbox = Sandbox::new();
        sandbox.install();
        let path = sandbox.factory().join(relative);
        let mut settings = if path.exists() {
            read_json(&path)
        } else {
            json!({})
        };
        settings[control] = json!(true);
        write_json(&path, &settings);
        let controls_before = std::fs::read(&path).unwrap();
        let registration_before = std::fs::read(sandbox.settings()).unwrap();
        assert!(
            !sandbox
                .run(&["install", "--droid", "--force"])
                .status
                .success()
        );
        let check = sandbox.doctor(false);
        assert_eq!(check["status"], "error", "disabled control: {check}");
        let fixed = sandbox.doctor(true);
        assert_eq!(
            fixed["status"], "error",
            "policy must remain effective: {fixed}"
        );
        assert_ne!(fixed["fixed"], true);
        assert_eq!(std::fs::read(&path).unwrap(), controls_before);
        assert_eq!(
            std::fs::read(sandbox.settings()).unwrap(),
            registration_before
        );
    }
}

#[test]
fn doctor_rejects_non_enforcing_matchers_filters_and_command_arguments() {
    for defect in [
        "wrong-case",
        "command-filter",
        "asynchronous",
        "extra-argument",
        "wrong-agent",
    ] {
        let sandbox = Sandbox::new();
        let mut settings = sandbox.install();
        let group = &mut settings["hooks"]["PreToolUse"][0];
        match defect {
            "wrong-case" => group["matcher"] = json!("execute"),
            "command-filter" => group["commandRegex"] = json!("^git status$"),
            "asynchronous" => group["hooks"][0]["async"] = json!(true),
            "extra-argument" => {
                let command = group["hooks"][0]["command"].as_str().unwrap();
                group["hooks"][0]["command"] = json!(format!("{command} --help"));
            }
            "wrong-agent" => {
                let command = group["hooks"][0]["command"].as_str().unwrap();
                group["hooks"][0]["command"] =
                    json!(command.replace("--agent droid", "--agent other --agent droid"));
            }
            _ => unreachable!("fixed test cases"),
        }
        write_json(&sandbox.settings(), &settings);
        let before = std::fs::read(sandbox.settings()).unwrap();
        let check = sandbox.doctor(false);
        assert_eq!(check["status"], "error", "{defect}: {check}");
        assert_eq!(std::fs::read(sandbox.settings()).unwrap(), before);
    }
}

#[cfg(unix)]
#[test]
fn installed_command_with_shell_metacharacters_in_its_path_delivers_real_verdicts() {
    use std::io::Write as _;

    let mut sandbox = Sandbox::new();
    let binary_directory = sandbox.root.join("space $ dollar ` tick ' quote");
    std::fs::create_dir_all(&binary_directory).unwrap();
    let copied = binary_directory.join(format!("dcg{}", std::env::consts::EXE_SUFFIX));
    std::fs::copy(&sandbox.binary, &copied).expect("copy executable into metacharacter path");
    sandbox.binary = copied;
    let settings = sandbox.install();
    let command = registered_handler(&settings, false)["command"]
        .as_str()
        .unwrap();
    for (guarded_command, denied) in [("git status", false), ("git reset --hard HEAD", true)] {
        let mut shell = Command::new("/bin/sh");
        sandbox.configure(&mut shell);
        let mut child = shell
            .args(["-c", command])
            .stdin(Stdio::piped())
            .spawn()
            .expect("run the installed hook through its shell");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(
                serde_json::to_string(&json!({
                    "session_id": "droid-install-test",
                    "hook_event_name": "PreToolUse",
                    "permission_mode": "off",
                    "cwd": sandbox.repo,
                    "tool_name": "Execute",
                    "tool_input": {"command": guarded_command, "riskLevel": "high"}
                }))
                .unwrap()
                .as_bytes(),
            )
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert_success(&output);
        if denied {
            let verdict: Value = serde_json::from_slice(&output.stdout).expect("DCG denial JSON");
            assert_eq!(verdict["hookSpecificOutput"]["permissionDecision"], "deny");
            assert_eq!(verdict["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        } else {
            assert!(
                output.stdout.is_empty(),
                "allowed commands leave Factory permissions unchanged"
            );
        }
    }
}
