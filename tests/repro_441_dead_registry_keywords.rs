//! Regression tests for issue #441: rules whose keyword was missing from the
//! pack's `PACK_ENTRIES` row could never fire.
//!
//! Each pack declares its keywords twice, and the two lists gate in sequence:
//! `PACK_ENTRIES` builds the `EnabledKeywordIndex` that decides whether a pack is
//! a candidate at all, and only then does `Pack::might_match` consult the pack's
//! own `keywords`. A keyword added to the pack list and not to the registry row
//! is therefore dead — the command is quick-rejected before the pack is
//! considered, and it is allowed with no rule named.
//!
//! `system.services` and `package_managers` were almost entirely non-functional
//! for their headline rules: `shutdown -h now`, `reboot`, `init 0`,
//! `apt purge --autoremove`, `yum remove -y`, `brew uninstall --force`,
//! `poetry publish`, `mvn deploy` and `gradle publish` were all allowed.
//!
//! These assertions go through the real binary, so the registry gate is in the
//! path. Pack-level tests could not catch this: they call `Pack::check` directly
//! and never pass through it.

use std::io::Write;
use std::process::{Command, Stdio};

fn dcg_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

/// Evaluate `command` with exactly `pack` enabled, through the hook protocol.
fn decision(command: &str, pack: &str) -> String {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
    .to_string();

    let mut child = Command::new(dcg_binary())
        .arg("hook")
        .arg("--batch")
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .env("DCG_PACKS", pack)
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcg");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    let out = child.wait_with_output().expect("wait");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.lines().next().unwrap_or_default().to_string();
    let parsed: serde_json::Value =
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("bad batch output ({e}): {stdout}"));
    parsed
        .get("decision")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<missing>")
        .to_string()
}

#[test]
fn system_services_shutdown_family_is_reachable() {
    // None of these contains `systemctl` or `service`, which were the only
    // keywords the registry row carried.
    for command in [
        "shutdown -h now",
        "shutdown -r +1",
        "shutdown now",
        "reboot",
        "reboot -f",
        "init 0",
        "init 6",
    ] {
        assert_eq!(
            decision(command, "system.services"),
            "deny",
            "should be denied with system.services enabled: {command}"
        );
    }
}

#[test]
fn package_manager_removal_and_publish_rules_are_reachable() {
    for command in [
        "apt purge --autoremove nginx",
        "apt-get purge --autoremove nginx",
        "yum remove -y nginx",
        "dnf remove -y nginx",
        "brew uninstall --force node",
        "poetry publish",
        "mvn deploy",
        "./mvnw deploy",
        "gradle publish",
        "./gradlew publish",
    ] {
        assert_eq!(
            decision(command, "package_managers"),
            "deny",
            "should be denied with package_managers enabled: {command}"
        );
    }
}

#[test]
fn the_added_keywords_do_not_deny_ordinary_commands() {
    // A wider registry row only changes which commands the pack is *asked*
    // about. Reads, installs and status queries must stay allowed.
    for (command, pack) in [
        ("systemctl status sshd", "system.services"),
        ("systemctl list-units", "system.services"),
        ("service --status-all", "system.services"),
        ("echo 'shutdown scheduled for tonight'", "system.services"),
        ("grep -r reboot /var/log", "system.services"),
        ("apt update", "package_managers"),
        ("apt install -y nginx", "package_managers"),
        ("apt list --installed", "package_managers"),
        ("brew install node", "package_managers"),
        ("mvn test", "package_managers"),
        ("./gradlew build", "package_managers"),
        ("poetry install", "package_managers"),
        ("yum info nginx", "package_managers"),
    ] {
        assert_eq!(
            decision(command, pack),
            "allow",
            "should be allowed with {pack} enabled: {command}"
        );
    }
}

#[test]
fn mongo_shell_methods_and_kubectl_kustomize_are_reachable() {
    // Neither shape names a client binary or the word "kustomize", which is all
    // their registry rows used to carry. Both were the root cause of the two
    // `option_evidence` assertions that were red on main.
    for (command, pack) in [
        ("db.users.drop(); db.posts.find({})", "database.mongodb"),
        ("db.users.remove({}); db.posts.find({})", "database.mongodb"),
        (
            "db.users.deleteMany({}); db.posts.aggregate([])",
            "database.mongodb",
        ),
        (
            "kubectl delete -k ./prod --cache-dir=--dry-run=client",
            "kubernetes.kustomize",
        ),
        ("kubectl delete --force -k./prod", "kubernetes.kustomize"),
        // `drop()` takes an optional options document and still drops the
        // collection, so an argument does not make it a read.
        ("db.users.drop({writeConcern: {w: 1}})", "database.mongodb"),
    ] {
        assert_eq!(
            decision(command, pack),
            "deny",
            "should be denied with {pack} enabled: {command}"
        );
    }
}

#[test]
fn the_mongo_and_kustomize_keywords_do_not_over_block() {
    // `.drop(` and `kubectl` are broad substrings, so the guard here is that the
    // rules they reach stayed narrow: `remove`/`deleteMany` need a literal
    // `({})`, and the kustomize rule needs a `-k`/`--kustomize` delete. Ordinary
    // code that merely contains the substrings must stay allowed — `df.drop(…)`
    // in particular, since a pandas drop is not a Mongo collection drop.
    for (command, pack) in [
        ("python3 -c \"df.drop(columns=['a'])\"", "database.mongodb"),
        ("df.drop(columns=['a'])", "database.mongodb"),
        ("python3 -c \"items.remove(x)\"", "database.mongodb"),
        ("items.remove(x)", "database.mongodb"),
        // A filtered delete is not the unfiltered `({})` the rule gates.
        ("db.users.deleteMany({status: 'stale'})", "database.mongodb"),
        // kubectl without a kustomize delete.
        ("kubectl get pods", "kubernetes.kustomize"),
        ("kubectl apply -k ./prod", "kubernetes.kustomize"),
        (
            "kubectl delete -f manifest.yaml --dry-run=client",
            "kubernetes.kustomize",
        ),
        ("kustomize build ./prod", "kubernetes.kustomize"),
    ] {
        assert_eq!(
            decision(command, pack),
            "allow",
            "should be allowed with {pack} enabled: {command}"
        );
    }
}

#[test]
fn a_disabled_pack_still_does_not_fire() {
    // The keywords live on the pack's row, so enabling nothing must not make
    // these deny — the row is consulted only for packs that are enabled.
    for command in ["shutdown -h now", "apt purge --autoremove nginx"] {
        assert_eq!(
            decision(command, "core.git"),
            "allow",
            "should be allowed when its pack is not enabled: {command}"
        );
    }
}

/// `system.permissions` carried `chgrp` on the pack's own keyword row and not
/// on its `PACK_ENTRIES` row, so the command was quick-rejected before the pack
/// was even a candidate.
///
/// A fresh instance of this issue's exact shape, found in 2026-09 while
/// measuring the permissions pack: `chown -R nobody /` denied while
/// `chgrp -R nogroup /` allowed, though both change the same access-control
/// metadata on the same tree. The pack-level test added alongside the new rule
/// passed the whole time, because it calls `create_pack()` directly and never
/// reaches the registry gate — which is precisely what this file exists to
/// catch.
#[test]
fn system_permissions_chgrp_is_reachable() {
    for command in [
        "chgrp -R nogroup /",
        "chgrp -R nogroup /etc",
        "chgrp -R nogroup /usr",
        "chgrp --recursive nogroup /var",
    ] {
        assert_eq!(
            decision(command, "system.permissions"),
            "deny",
            "registry row must make chgrp reachable: {command}"
        );
    }

    // The carve-outs the sibling rules get, through the same path: a recursive
    // chgrp inside a project tree is an ordinary command.
    for command in [
        "chgrp -R staff ./build",
        "chgrp -R staff /home/user/project",
        "chgrp staff ./out",
    ] {
        assert_eq!(
            decision(command, "system.permissions"),
            "allow",
            "ordinary chgrp must stay allowed: {command}"
        );
    }
}
