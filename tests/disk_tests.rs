use std::process::Command;

fn dcg_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

fn run_hook(command: &str) -> String {
    run_hook_with_packs(command, Some("system.disk"))
}

fn run_hook_with_packs(command: &str, packs: Option<&str>) -> String {
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": command,
        }
    });
    let sandbox = tempfile::tempdir().expect("failed to create hook sandbox");
    let root = sandbox.path();
    let mut hook = Command::new(dcg_binary());

    // Change only the child's environment. Ambient bypasses, pack overrides,
    // or explicit config paths must not turn these regressions into false passes.
    for (key, _) in std::env::vars_os() {
        if key
            .to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("DCG_")
        {
            hook.env_remove(key);
        }
    }
    hook.current_dir(root)
        .env("HOME", root)
        .env("USERPROFILE", root)
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env("XDG_STATE_HOME", root.join("state"))
        .env("APPDATA", root.join("appdata"))
        .env("LOCALAPPDATA", root.join("localappdata"))
        .env("TMPDIR", root)
        .env("TEMP", root)
        .env("TMP", root)
        .env(
            "DCG_ALLOWLIST_SYSTEM_PATH",
            root.join("system-allowlist.toml"),
        )
        // Hook-mode self-heal must not register a test binary in the caller's
        // real agent settings (including native Windows known-folder paths).
        .env("DCG_SELF_HEAL_HOOK", "0")
        // These are classification tests, not tests of the shipped deadline.
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Some(packs) = packs {
        hook.env("DCG_PACKS", packs);
    }
    // With None there is no DCG_PACKS or DCG_CONFIG and no user/project config:
    // the issue #448 regressions exercise the default-enabled system.disk pack.
    let mut child = hook.spawn().expect("failed to spawn dcg");
    {
        let stdin = child.stdin.take().expect("failed to open stdin");
        serde_json::to_writer(stdin, &input).expect("failed to write json");
    }

    let output = child.wait_with_output().expect("failed to wait for dcg");
    assert!(
        output.status.success(),
        "hook failed for {command:?}: status={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("hook stdout must be UTF-8")
}

#[test]
fn dd_dev_null_false_positive() {
    // Should ALLOW dd if=foo of=/dev/null
    let cmd = "dd if=zero.dat of=/dev/null bs=1M count=1";
    let output = run_hook(cmd);

    assert!(
        !output.contains("deny"),
        "False positive: '{cmd}' was blocked! Output: {output}"
    );
}

#[test]
fn dd_dev_block_device_blocked() {
    // Should BLOCK dd if=foo of=/dev/sda
    let cmd = "dd if=foo of=/dev/sda";
    let output = run_hook(cmd);

    assert!(output.contains("deny"), "Bypass: '{cmd}' was allowed!");
}

#[test]
fn parted_print_free_allowed() {
    let cmd = "parted /dev/sda print free";
    let output = run_hook(cmd);

    assert!(
        !output.contains("deny"),
        "False positive: '{cmd}' was blocked! Output: {output}"
    );
}

#[test]
fn parted_print_then_rm_blocked() {
    let cmd = "parted /dev/sda print rm 1";
    let output = run_hook(cmd);

    assert!(output.contains("deny"), "Bypass: '{cmd}' was allowed!");
}

#[test]
fn parted_scripted_mklabel_blocked() {
    let cmd = "parted -s /dev/sda mklabel gpt";
    let output = run_hook(cmd);

    assert!(output.contains("deny"), "Bypass: '{cmd}' was allowed!");
}

// --- mdadm tests ---
#[test]
fn mdadm_detail_allowed() {
    let cmd = "mdadm --detail /dev/md0";
    let output = run_hook(cmd);
    assert!(
        !output.contains("deny"),
        "False positive: '{cmd}' was blocked! Output: {output}"
    );
}

#[test]
fn mdadm_examine_allowed() {
    let cmd = "mdadm --examine /dev/sda1";
    let output = run_hook(cmd);
    assert!(
        !output.contains("deny"),
        "False positive: '{cmd}' was blocked! Output: {output}"
    );
}

#[test]
fn mdadm_stop_blocked() {
    let cmd = "mdadm --stop /dev/md0";
    let output = run_hook(cmd);
    assert!(output.contains("deny"), "Bypass: '{cmd}' was allowed!");
}

#[test]
fn mdadm_zero_superblock_blocked() {
    let cmd = "mdadm --zero-superblock /dev/sda1";
    let output = run_hook(cmd);
    assert!(output.contains("deny"), "Bypass: '{cmd}' was allowed!");
}

#[test]
fn mdadm_create_blocked() {
    let cmd = "mdadm --create /dev/md0 --level=1 --raid-devices=2 /dev/sda1 /dev/sdb1";
    let output = run_hook(cmd);
    assert!(output.contains("deny"), "Bypass: '{cmd}' was allowed!");
}

// --- btrfs tests ---
#[test]
fn btrfs_subvolume_list_allowed() {
    let cmd = "btrfs subvolume list /mnt/data";
    let output = run_hook(cmd);
    assert!(
        !output.contains("deny"),
        "False positive: '{cmd}' was blocked! Output: {output}"
    );
}

#[test]
fn btrfs_filesystem_show_allowed() {
    let cmd = "btrfs filesystem show";
    let output = run_hook(cmd);
    assert!(
        !output.contains("deny"),
        "False positive: '{cmd}' was blocked! Output: {output}"
    );
}

#[test]
fn btrfs_subvolume_delete_blocked() {
    let cmd = "btrfs subvolume delete /mnt/data/snapshot";
    let output = run_hook(cmd);
    assert!(output.contains("deny"), "Bypass: '{cmd}' was allowed!");
}

#[test]
fn btrfs_device_remove_blocked() {
    let cmd = "btrfs device remove /dev/sdb /mnt/data";
    let output = run_hook(cmd);
    assert!(output.contains("deny"), "Bypass: '{cmd}' was allowed!");
}

#[test]
fn btrfs_check_repair_blocked() {
    let cmd = "btrfs check --repair /dev/sda1";
    let output = run_hook(cmd);
    assert!(output.contains("deny"), "Bypass: '{cmd}' was allowed!");
}

// --- dmsetup tests ---
#[test]
fn dmsetup_ls_allowed() {
    let cmd = "dmsetup ls";
    let output = run_hook(cmd);
    assert!(
        !output.contains("deny"),
        "False positive: '{cmd}' was blocked! Output: {output}"
    );
}

#[test]
fn dmsetup_status_allowed() {
    let cmd = "dmsetup status";
    let output = run_hook(cmd);
    assert!(
        !output.contains("deny"),
        "False positive: '{cmd}' was blocked! Output: {output}"
    );
}

#[test]
fn dmsetup_remove_blocked() {
    let cmd = "dmsetup remove my_device";
    let output = run_hook(cmd);
    assert!(output.contains("deny"), "Bypass: '{cmd}' was allowed!");
}

#[test]
fn dmsetup_remove_all_blocked() {
    let cmd = "dmsetup remove_all";
    let output = run_hook(cmd);
    assert!(output.contains("deny"), "Bypass: '{cmd}' was allowed!");
}

#[test]
fn dmsetup_wipe_table_blocked() {
    let cmd = "dmsetup wipe_table my_device";
    let output = run_hook(cmd);
    assert!(output.contains("deny"), "Bypass: '{cmd}' was allowed!");
}

// --- nbd-client tests ---
#[test]
fn nbd_client_list_allowed() {
    let cmd = "nbd-client -l server.example.com";
    let output = run_hook(cmd);
    assert!(
        !output.contains("deny"),
        "False positive: '{cmd}' was blocked! Output: {output}"
    );
}

#[test]
fn nbd_client_disconnect_blocked() {
    let cmd = "nbd-client -d /dev/nbd0";
    let output = run_hook(cmd);
    assert!(output.contains("deny"), "Bypass: '{cmd}' was allowed!");
}

// --- LVM tests ---
#[test]
fn lvs_allowed() {
    let cmd = "lvs";
    let output = run_hook(cmd);
    assert!(
        !output.contains("deny"),
        "False positive: '{cmd}' was blocked! Output: {output}"
    );
}

#[test]
fn vgdisplay_allowed() {
    let cmd = "vgdisplay my_vg";
    let output = run_hook(cmd);
    assert!(
        !output.contains("deny"),
        "False positive: '{cmd}' was blocked! Output: {output}"
    );
}

#[test]
fn pvremove_blocked() {
    let cmd = "pvremove /dev/sda1";
    let output = run_hook(cmd);
    assert!(output.contains("deny"), "Bypass: '{cmd}' was allowed!");
}

#[test]
fn vgremove_blocked() {
    let cmd = "vgremove my_vg";
    let output = run_hook(cmd);
    assert!(output.contains("deny"), "Bypass: '{cmd}' was allowed!");
}

#[test]
fn lvremove_blocked() {
    let cmd = "lvremove /dev/my_vg/my_lv";
    let output = run_hook(cmd);
    assert!(output.contains("deny"), "Bypass: '{cmd}' was allowed!");
}

#[test]
fn lvreduce_blocked() {
    let cmd = "lvreduce -L 10G /dev/my_vg/my_lv";
    let output = run_hook(cmd);
    assert!(output.contains("deny"), "Bypass: '{cmd}' was allowed!");
}

#[test]
fn pvmove_blocked() {
    let cmd = "pvmove /dev/sda1 /dev/sdb1";
    let output = run_hook(cmd);
    assert!(output.contains("deny"), "Bypass: '{cmd}' was allowed!");
}

// --- #448: real-binary coverage with default pack selection ---

fn assert_default_blocked(command: &str, expected_rule: &str) {
    let output = run_hook_with_packs(command, None);
    let result: serde_json::Value = serde_json::from_str(&output).unwrap_or_else(|error| {
        panic!("invalid denial for {command:?}: {error}; stdout={output:?}")
    });
    let hook = &result["hookSpecificOutput"];
    assert_eq!(hook["permissionDecision"], "deny", "{command:?}: {output}");
    assert_eq!(hook["ruleId"], expected_rule, "{command:?}: {output}");
}

#[test]
fn default_disk_redirect_targets_do_not_disarm_the_pack_issue_448() {
    // These are shell redirects, not stray dd operands. The strings are only
    // sent to dcg's hook; this test never executes a disk-writing command.
    for (command, rule) in [
        ("dd if=/dev/zero of=/dev/sda", "system.disk:dd-device"),
        ("wipefs -a /dev/sdb", "system.disk:wipefs"),
        ("mkfs.ext4 /dev/sdb1", "system.disk:mkfs"),
    ] {
        assert_default_blocked(command, rule);
        for redirect in [
            "2>>/tmp/dcg.log", // matched control: only the filename changes
            "2>>/var/log/mount",
            "2>/tmp/mount",
            r#"2>>"/tmp/fdisk -l.log""#,
            "2>>'/tmp/fdisk -l.log'",
        ] {
            assert_default_blocked(&format!("{command} {redirect}"), rule);
        }
    }
}

#[test]
fn default_disk_original_bypasses_stay_blocked_issue_448() {
    for (command, rule) in [
        (
            "dd if=/dev/zero of=/dev/sda 2>>/var/log/blkid.log",
            "system.disk:dd-device",
        ),
        ("mkfs.ext4 -L lsblk /dev/sdb1", "system.disk:mkfs"),
        ("mkfs.ext4 -L df /dev/sdb1", "system.disk:mkfs"),
        ("wipefs -a /dev/sdb -o /tmp/df.bak", "system.disk:wipefs"),
        (
            "mdadm --stop /dev/md0 --config /etc/blkid.conf",
            "system.disk:mdadm-stop",
        ),
        (
            "dmsetup remove mydev --table /tmp/lsblk",
            "system.disk:dmsetup-remove",
        ),
        (
            "lvremove -f vg/lv --config /tmp/blkid",
            "system.disk:lvremove",
        ),
        ("tee /dev/sda < /tmp/blkid.img", "system.disk:tee-device"),
        ("mdadm --detail --stop /dev/md0", "system.disk:mdadm-stop"),
        (
            "mdadm --scan --zero-superblock /dev/sdb",
            "system.disk:mdadm-zero-superblock",
        ),
        ("mkswap --check /dev/sdb1", "system.disk:mkswap"),
        ("mkswap -c /dev/sdb1", "system.disk:mkswap"),
        ("mkfs.ext4 -L lvs /dev/sdb1", "system.disk:mkfs"),
        ("mkfs.ext4 -L vgs /dev/sdb1", "system.disk:mkfs"),
        ("mkfs.ext4 -L pvs /dev/sdb1", "system.disk:mkfs"),
        ("mkfs.ext4 -L lvscan /dev/sdb1", "system.disk:mkfs"),
        (
            "dd if=/dev/zero of=/dev/sda 2>>/var/log/pvscan",
            "system.disk:dd-device",
        ),
    ] {
        assert_default_blocked(command, rule);
    }
}

#[test]
fn default_disk_read_only_and_ordinary_commands_stay_allowed_issue_448() {
    for command in [
        "fdisk -l",
        "fdisk -l /dev/sda",
        "fdisk /dev/sda -l",
        "sudo fdisk -l",
        "/sbin/fdisk -l /dev/sda",
        "LC_ALL=C fdisk -l /dev/sda",
        "mount",
        "sudo mount",
        "/bin/mount",
        "LC_ALL=C mount",
        "mount -l",
        "mount -t ext4",
        "mount /dev/sdb1 /mnt",
        "lsblk -f -o NAME,SIZE",
        "sudo lsblk",
        "blkid -o value -s UUID /dev/sda1",
        "df -h /",
        "mdadm --detail /dev/md0",
        "mdadm --examine /dev/sdb1",
        "mdadm --detail --scan",
        "lvs -a -o +devices",
        "vgs -o vg_name",
        "pvs /dev/sda",
        "lvdisplay",
        "vgdisplay",
        "pvdisplay",
        "lvscan",
        "vgscan",
        "pvscan",
        "parted /dev/sda print free",
        "dd if=/dev/sda of=/dev/null count=1",
    ] {
        let output = run_hook_with_packs(command, None);
        assert!(output.trim().is_empty(), "{command:?}: {output}");
    }
}

#[test]
fn default_disk_read_only_neighbors_do_not_hide_destruction_issue_448() {
    for (command, rule) in [
        (
            "fdisk -l && dd if=/dev/zero of=/dev/sda 2>>/var/log/mount",
            "system.disk:dd-device",
        ),
        (
            "dd if=/dev/zero of=/dev/sda 2>>/var/log/mount; fdisk -l",
            "system.disk:dd-device",
        ),
        (
            "mount; wipefs -a /dev/sdb 2>/tmp/mount",
            "system.disk:wipefs",
        ),
        (
            "wipefs -a /dev/sdb 2>/tmp/mount && mount",
            "system.disk:wipefs",
        ),
        (
            r#"lsblk && mkfs.ext4 /dev/sdb1 2>>"/tmp/fdisk -l.log""#,
            "system.disk:mkfs",
        ),
    ] {
        assert_default_blocked(command, rule);
    }
}
