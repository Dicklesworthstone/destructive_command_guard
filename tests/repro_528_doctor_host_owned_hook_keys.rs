//! Regression tests for issue #528: `dcg doctor` reported the Claude hook as
//! MISCONFIGURED when the hook object carried a host-owned key such as
//! `"timeout": 10`. `dcg install --force` preserves those keys by design
//! (#345), and hook-mode self-heal judges the hook on dcg-owned keys only, so
//! the finding could never clear and doctor disagreed with self-heal.
//!
//! Doctor now judges identity on the dcg-owned keys (`type`, `command`,
//! `shell`) like install and self-heal do. A host key that changes
//! enforcement, `async: true`, is still an error.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

struct Env {
    temp: tempfile::TempDir,
    home: PathBuf,
}

impl Env {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().join("home");
        std::fs::create_dir_all(home.join(".claude")).expect("claude dir");
        std::fs::create_dir_all(temp.path().join("xdg")).expect("xdg dir");
        Self { temp, home }
    }

    fn settings(&self) -> PathBuf {
        self.home.join(".claude").join("settings.json")
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(dcg_binary())
            .env_clear()
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("XDG_CONFIG_HOME", self.temp.path().join("xdg"))
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("DCG_NO_UPDATE_CHECK", "1")
            .current_dir(self.temp.path())
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run dcg")
    }

    /// Install dcg's own hook, then merge `extra` into the single dcg hook
    /// object, so the dcg-owned keys are exactly what this binary writes.
    fn install_with_extra(&self, extra: &serde_json::Value) {
        let output = self.run(&["install"]);
        assert!(
            output.status.success(),
            "dcg install failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut settings: serde_json::Value =
            serde_json::from_slice(&std::fs::read(self.settings()).expect("settings written"))
                .expect("settings JSON");
        let hook = settings["hooks"]["PreToolUse"][0]["hooks"][0]
            .as_object_mut()
            .expect("dcg hook object");
        for (key, value) in extra.as_object().expect("extra object") {
            hook.insert(key.clone(), value.clone());
        }
        write_json(&self.settings(), &settings);
    }

    fn hook_wiring(&self) -> serde_json::Value {
        let output = self.run(&["doctor", "--format", "json"]);
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
                panic!(
                    "doctor JSON ({e}): stdout={} stderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
            });
        report["checks"]
            .as_array()
            .expect("checks array")
            .iter()
            .find(|check| check["id"] == "hook_wiring")
            .expect("hook_wiring check")
            .clone()
    }
}

fn write_json(path: &Path, value: &serde_json::Value) {
    std::fs::write(path, serde_json::to_vec_pretty(value).expect("JSON")).expect("write settings");
}

#[test]
fn doctor_accepts_the_installed_hook_as_written() {
    let env = Env::new();
    env.install_with_extra(&serde_json::json!({}));
    let check = env.hook_wiring();
    assert_ne!(check["status"], "error", "control: {check}");
}

#[test]
fn doctor_accepts_a_host_owned_timeout_on_the_dcg_hook() {
    let env = Env::new();
    env.install_with_extra(&serde_json::json!({ "timeout": 10 }));
    let check = env.hook_wiring();
    assert_ne!(
        check["status"], "error",
        "an operator-set timeout is host-owned (#345) and must not be MISCONFIGURED: {check}"
    );
}

#[test]
fn install_force_keeps_the_timeout_and_doctor_stays_clean() {
    let env = Env::new();
    env.install_with_extra(&serde_json::json!({ "timeout": 10 }));
    let output = env.run(&["install", "--force"]);
    assert!(
        output.status.success(),
        "install --force: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let settings: serde_json::Value =
        serde_json::from_slice(&std::fs::read(env.settings()).expect("settings")).expect("JSON");
    assert_eq!(
        settings["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"], 10,
        "install --force preserves the host-owned timeout: {settings}"
    );
    let check = env.hook_wiring();
    assert_ne!(check["status"], "error", "{check}");
}

#[test]
fn doctor_still_rejects_an_async_dcg_hook() {
    let env = Env::new();
    env.install_with_extra(&serde_json::json!({ "async": true }));
    let check = env.hook_wiring();
    assert_eq!(
        check["status"], "error",
        "an async hook cannot synchronously enforce a block: {check}"
    );
}
