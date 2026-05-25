use std::process::Command;

fn dcg_binary() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // deps
    path.pop(); // debug
    path.push("dcg");
    path
}

fn run_hook(command: &str) -> String {
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": command,
        }
    });

    let mut child = Command::new(dcg_binary())
        .env("DCG_PACKS", "system.disk")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn dcg");

    {
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        serde_json::to_writer(stdin, &input).expect("failed to write json");
    }

    let output = child.wait_with_output().expect("failed to wait for dcg");
    String::from_utf8_lossy(&output.stdout).to_string()
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
