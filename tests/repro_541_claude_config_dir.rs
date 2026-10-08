//! Issue #541: active Claude configuration must win over a protected default.
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

struct Sandbox {
    _temp: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        // Match current_dir's physical path on Unix, including macOS /var
        // aliases, without introducing Windows verbatim-path prefixes.
        #[cfg(unix)]
        let root = temp.path().canonicalize().unwrap();
        #[cfg(not(unix))]
        let root = temp.path().to_path_buf();
        let home = root.join("home");
        std::fs::create_dir_all(&home).unwrap();
        Self {
            _temp: temp,
            root,
            home,
        }
    }

    fn run(&self, dir: Option<&str>, args: &[&str], input: Option<&str>) -> Output {
        let binary = Path::new(env!("CARGO_BIN_EXE_dcg"));
        let mut command = Command::new(binary);
        command
            .env_clear()
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("PATH", binary.parent().unwrap())
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("DCG_NO_UPDATE_CHECK", "1")
            .env(
                "DCG_SELF_HEAL_HOOK",
                if input.is_some() { "1" } else { "0" },
            )
            .current_dir(&self.root)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(dir) = dir {
            command.env("CLAUDE_CONFIG_DIR", dir);
        }
        let mut child = command.spawn().unwrap();
        if let Some(input) = input {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
        } else {
            drop(child.stdin.take());
        }
        child.wait_with_output().unwrap()
    }
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn assert_reported_settings_path(output: &Output, settings: &Path, json_output: bool) {
    let message = if json_output {
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["id"] == "claude_settings")
            .unwrap()["message"]
            .as_str()
            .unwrap()
            .to_owned()
    } else {
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    assert!(message.contains(settings.to_str().unwrap()), "{message}");
}

#[test]
fn active_configuration_lifecycle_and_self_heal() {
    for form in ["absolute", "relative", "tilde", "home", "empty", "unset"] {
        let sandbox = Sandbox::new();
        let absolute = sandbox.root.join("alternate config");
        let absolute_string = absolute.to_str().unwrap();
        let (dir, settings) = match form {
            "absolute" => (Some(absolute_string), absolute.join("settings.json")),
            "relative" => (
                Some("relative config"),
                sandbox.root.join("relative config").join("settings.json"),
            ),
            "tilde" => (
                Some("~/alternate config"),
                sandbox.home.join("alternate config").join("settings.json"),
            ),
            "home" => (Some("~"), sandbox.home.join("settings.json")),
            "empty" => (Some(""), sandbox.home.join(".claude").join("settings.json")),
            _ => (None, sandbox.home.join(".claude").join("settings.json")),
        };
        // A valid default hook must never conceal missing active protection.
        success(&sandbox.run(None, &["install"], None));
        let default = sandbox.home.join(".claude").join("settings.json");
        let original_default = std::fs::read(&default).unwrap();
        if settings != default {
            for args in [
                vec!["doctor", "--strict"],
                vec!["doctor", "--strict", "--format", "json"],
            ] {
                let output = sandbox.run(dir, &args, None);
                assert!(
                    !output.status.success(),
                    "{form}: absent active config passed doctor"
                );
                assert_reported_settings_path(&output, &settings, args.contains(&"json"));
            }
        }
        success(&sandbox.run(dir, &["install"], None));
        assert!(
            settings.exists(),
            "{form}: install did not create active settings"
        );
        std::fs::write(&settings, r#"{"theme":"dark","hooks":{"PreToolUse":[{"matcher":"Read","hooks":[{"type":"command","command":"unrelated"}]}]}}"#).unwrap();
        assert!(
            !sandbox
                .run(dir, &["doctor", "--strict"], None)
                .status
                .success()
        );
        assert!(
            !sandbox
                .run(dir, &["doctor", "--strict", "--format", "json"], None)
                .status
                .success()
        );
        success(&sandbox.run(dir, &["install"], None));
        let installed = json(&settings);
        assert_eq!(installed["theme"], "dark");
        assert!(
            installed["hooks"]["PreToolUse"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["matcher"] == "Read"
                    && entry["hooks"][0]["command"] == "unrelated")
        );
        for args in [
            vec!["doctor", "--strict"],
            vec!["doctor", "--strict", "--format", "json"],
        ] {
            let output = sandbox.run(dir, &args, None);
            success(&output);
            assert_reported_settings_path(&output, &settings, args.contains(&"json"));
        }
        success(&sandbox.run(dir, &["uninstall"], None));
        assert_eq!(
            json(&settings)["hooks"]["PreToolUse"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        // Real hook invocation repairs the same active file, preserving peers.
        let output = sandbox.run(
            dir,
            &[],
            Some(r#"{"tool_name":"Bash","tool_input":{"command":"echo safe"}}"#),
        );
        success(&output);
        assert_eq!(
            json(&settings)["hooks"]["PreToolUse"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(json(&settings)["theme"], "dark");
        if settings != default {
            assert_eq!(std::fs::read(default).unwrap(), original_default);
        }
    }
}

#[test]
fn doctor_fix_creates_missing_active_settings_and_grok_uses_default() {
    let sandbox = Sandbox::new();
    success(&sandbox.run(None, &["install"], None));
    std::fs::create_dir_all(sandbox.home.join(".grok")).unwrap();
    let output = sandbox.run(
        Some("active"),
        &["doctor", "--strict", "--format", "json"],
        None,
    );
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let grok = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"].as_str().is_some_and(|n| n.contains("Grok")))
        .unwrap();
    assert_eq!(grok["status"], "ok", "{grok}");
    success(&sandbox.run(
        Some("active"),
        &["doctor", "--fix", "--strict", "--format", "json"],
        None,
    ));
    assert!(sandbox.root.join("active").join("settings.json").exists());
    success(&sandbox.run(Some("active"), &["doctor", "--strict"], None));
    // A protected alternate directory does not protect Grok's default file.
    success(&sandbox.run(None, &["uninstall"], None));
    assert!(
        !sandbox
            .run(Some("active"), &["doctor", "--strict"], None)
            .status
            .success()
    );
    assert!(
        !sandbox
            .run(
                Some("active"),
                &["doctor", "--strict", "--format", "json"],
                None
            )
            .status
            .success()
    );
}

#[test]
fn invalid_active_settings_are_preserved_and_project_install_takes_precedence() {
    let sandbox = Sandbox::new();
    success(&sandbox.run(None, &["install"], None));
    let active = sandbox.root.join("active").join("settings.json");
    std::fs::create_dir_all(active.parent().unwrap()).unwrap();
    let corrupt = b"{invalid JSON";
    std::fs::write(&active, corrupt).unwrap();
    for args in [
        vec!["install", "--force"],
        vec!["uninstall"],
        vec!["doctor", "--fix", "--strict", "--format", "json"],
    ] {
        assert!(!sandbox.run(Some("active"), &args, None).status.success());
        assert_eq!(std::fs::read(&active).unwrap(), corrupt);
    }
    std::fs::create_dir(sandbox.root.join(".git")).unwrap();
    success(&sandbox.run(Some("active"), &["install", "--project"], None));
    assert!(sandbox.root.join(".claude").join("settings.json").exists());
    assert_eq!(std::fs::read(active).unwrap(), corrupt);
}
