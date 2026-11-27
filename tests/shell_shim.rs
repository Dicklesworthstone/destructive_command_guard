//! End-to-end coverage for the PATH shim: install/uninstall ownership rules
//! and a real shell shim blocking a destructive command with no agent hook.
//! The shell commands here are input data. The `rm` that could run is a fake
//! fixture script that only writes a marker file.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Sandbox {
    _temp: tempfile::TempDir,
    home: PathBuf,
    bin: PathBuf,
    real: PathBuf,
    dcg: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temporary shim environment");
        let root = temp.path().to_path_buf();
        let home = root.join("home");
        let bin = root.join("bin");
        let real = root.join("real");
        for directory in [&home, &bin, &real] {
            fs::create_dir_all(directory).expect("create sandbox directory");
        }
        // Stands in for /bin/rm: if the shim lets the command through, this
        // writes a marker instead of deleting anything.
        let fake_rm = real.join("rm");
        fs::write(&fake_rm, "#!/bin/sh\nprintf ran > \"$HOME/marker\"\n").expect("write fake rm");
        let mut permissions = fs::metadata(&fake_rm).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fake_rm, permissions).unwrap();
        Self {
            _temp: temp,
            home,
            bin,
            real,
            dcg: PathBuf::from(env!("CARGO_BIN_EXE_dcg")),
        }
    }

    fn path(&self) -> String {
        format!(
            "{}:{}:/usr/bin:/bin",
            self.bin.display(),
            self.real.display()
        )
    }

    fn command(&self, program: &Path, args: &[&str]) -> Output {
        Command::new(program)
            .args(args)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("XDG_BIN_HOME", &self.bin)
            .env("PATH", self.path())
            .output()
            .expect("run command in sandbox")
    }

    fn dcg(&self, args: &[&str]) -> Output {
        self.command(&self.dcg, args)
    }

    fn shim(&self, args: &[&str]) -> Output {
        self.command(&self.bin.join("rm"), args)
    }

    fn install(&self) -> Output {
        self.dcg(&["install", "--shell-shim"])
    }
}

#[test]
fn install_writes_marker_shims_and_uninstall_removes_only_those() {
    let sandbox = Sandbox::new();
    let output = sandbox.install();
    assert!(
        output.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    for name in ["rm", "cp", "dd"] {
        let path = sandbox.bin.join(name);
        let content = fs::read_to_string(&path).expect("shim exists");
        assert!(
            content.contains("dcg-shell-shim"),
            "{name} lacks the marker"
        );
        assert!(content.contains("dcg test"), "{name} does not call dcg");
    }

    // An unrelated file in the shim directory must survive uninstall.
    let unrelated = sandbox.bin.join("not-a-shim");
    fs::write(&unrelated, "leave me alone").unwrap();

    let output = sandbox.dcg(&["uninstall", "--shell-shim"]);
    assert!(output.status.success(), "uninstall failed");
    assert!(!sandbox.bin.join("rm").exists());
    assert!(!sandbox.bin.join("cp").exists());
    assert!(unrelated.exists());
}

#[test]
fn user_owned_file_is_not_overwritten_without_force() {
    let sandbox = Sandbox::new();
    let path = sandbox.bin.join("rm");
    fs::write(&path, "user owned").unwrap();

    let output = sandbox.install();
    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(&path).unwrap(), "user owned");

    let output = sandbox.dcg(&["install", "--shell-shim", "--force"]);
    assert!(output.status.success(), "force install failed");
    assert!(
        fs::read_to_string(&path)
            .unwrap()
            .contains("dcg-shell-shim")
    );
}

#[test]
fn shim_blocks_recursive_delete_without_an_agent_hook() {
    let sandbox = Sandbox::new();
    assert!(sandbox.install().status.success());

    // The target need not exist: the shim must consult dcg before the fake
    // real rm is allowed to run at all.
    let output = sandbox.shim(&["-rf", "/home/ubuntu/project"]);
    assert_eq!(output.status.code(), Some(126));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("BLOCKED"), "unexpected stderr: {stderr}");
    assert!(!sandbox.home.join("marker").exists(), "real rm ran");
}

#[test]
fn shim_allows_a_safe_command_and_calls_the_real_binary() {
    let sandbox = Sandbox::new();
    assert!(sandbox.install().status.success());

    let output = sandbox.shim(&["plain-file.txt"]);
    assert!(output.status.success(), "safe rm was blocked");
    assert!(sandbox.home.join("marker").exists(), "real rm did not run");
}
