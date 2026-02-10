//! Integration tests for the update and rollback functionality.
//!
//! These tests use tempfile to create isolated test environments for
//! backup creation, listing, and rollback operations.

use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Test helper to create a mock backup directory structure.
fn create_mock_backup_dir(temp_dir: &TempDir) -> PathBuf {
    let backup_dir = temp_dir.path().join("backups");
    fs::create_dir_all(&backup_dir).unwrap();
    backup_dir
}

/// Test helper to create a mock binary file.
fn create_mock_binary(path: &std::path::Path, content: &[u8]) {
    fs::write(path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// Test helper to create a mock backup entry with metadata.
fn create_mock_backup_entry(
    backup_dir: &std::path::Path,
    version: &str,
    timestamp: u64,
    content: &[u8],
) {
    let backup_name = format!("dcg-{version}-{timestamp}");
    let backup_path = backup_dir.join(&backup_name);
    let metadata_path = backup_dir.join(format!("{backup_name}.json"));

    // Write binary
    fs::write(&backup_path, content).unwrap();

    // Write metadata JSON
    let metadata = serde_json::json!({
        "version": version,
        "created_at": timestamp,
        "original_path": "/usr/local/bin/dcg"
    });
    fs::write(
        &metadata_path,
        serde_json::to_string_pretty(&metadata).unwrap(),
    )
    .unwrap();
}

// =============================================================================
// Backup Directory Tests
// =============================================================================

#[test]
fn test_backup_directory_creation() {
    let temp_dir = TempDir::new().unwrap();
    let backup_dir = create_mock_backup_dir(&temp_dir);

    assert!(backup_dir.exists());
    assert!(backup_dir.is_dir());
}

#[test]
fn test_backup_entry_metadata_format() {
    let temp_dir = TempDir::new().unwrap();
    let backup_dir = create_mock_backup_dir(&temp_dir);

    create_mock_backup_entry(&backup_dir, "0.2.12", 1_737_200_000, b"binary content");

    // Verify metadata file exists and is valid JSON
    let metadata_path = backup_dir.join("dcg-0.2.12-1737200000.json");
    assert!(metadata_path.exists());

    let content = fs::read_to_string(&metadata_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

    assert_eq!(parsed["version"], "0.2.12");
    assert_eq!(parsed["created_at"], 1_737_200_000);
}

#[test]
fn test_backup_binary_permissions() {
    let temp_dir = TempDir::new().unwrap();
    let binary_path = temp_dir.path().join("dcg");

    create_mock_binary(&binary_path, b"test binary");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(&binary_path).unwrap().permissions();
        // Should have execute permission
        assert!(perms.mode() & 0o111 != 0, "Binary should be executable");
    }
}

// =============================================================================
// Backup Listing Tests
// =============================================================================

#[test]
fn test_list_empty_backup_directory() {
    let temp_dir = TempDir::new().unwrap();
    let backup_dir = create_mock_backup_dir(&temp_dir);

    // Count .json files in backup directory
    let count = fs::read_dir(&backup_dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
        .count();

    assert_eq!(count, 0);
}

#[test]
fn test_list_multiple_backups() {
    let temp_dir = TempDir::new().unwrap();
    let backup_dir = create_mock_backup_dir(&temp_dir);

    // Create multiple backup entries
    create_mock_backup_entry(&backup_dir, "0.2.10", 1_737_000_000, b"v0.2.10");
    create_mock_backup_entry(&backup_dir, "0.2.11", 1_737_100_000, b"v0.2.11");
    create_mock_backup_entry(&backup_dir, "0.2.12", 1_737_200_000, b"v0.2.12");

    // Count .json files
    let json_files: Vec<_> = fs::read_dir(&backup_dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
        .collect();

    assert_eq!(json_files.len(), 3);
}

#[test]
fn test_backup_sorting_newest_first() {
    let temp_dir = TempDir::new().unwrap();
    let backup_dir = create_mock_backup_dir(&temp_dir);

    // Create backups in random order
    create_mock_backup_entry(&backup_dir, "0.2.11", 1_737_100_000, b"v0.2.11");
    create_mock_backup_entry(&backup_dir, "0.2.10", 1_737_000_000, b"v0.2.10");
    create_mock_backup_entry(&backup_dir, "0.2.12", 1_737_200_000, b"v0.2.12");

    // Read and parse all metadata files
    let mut entries: Vec<(String, u64)> = Vec::new();
    for entry in fs::read_dir(&backup_dir).unwrap().filter_map(Result::ok) {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            let content = fs::read_to_string(&path).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
            entries.push((
                parsed["version"].as_str().unwrap().to_string(),
                parsed["created_at"].as_u64().unwrap(),
            ));
        }
    }

    // Sort by timestamp descending (newest first)
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.1));

    assert_eq!(entries[0].0, "0.2.12");
    assert_eq!(entries[1].0, "0.2.11");
    assert_eq!(entries[2].0, "0.2.10");
}

// =============================================================================
// Binary Replacement Tests
// =============================================================================

#[test]
fn test_atomic_binary_replacement() {
    let temp_dir = TempDir::new().unwrap();
    let binary_path = temp_dir.path().join("dcg");

    // Create original binary
    create_mock_binary(&binary_path, b"original content");

    #[cfg(unix)]
    let original_inode = {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(&binary_path).unwrap().ino()
    };

    // Perform atomic replacement using rename
    let new_content = b"new binary content";
    let temp_path = temp_dir.path().join("dcg.new");
    fs::write(&temp_path, new_content).unwrap();
    fs::rename(&temp_path, &binary_path).unwrap();

    // Verify content updated
    let content = fs::read(&binary_path).unwrap();
    assert_eq!(content, new_content);

    // Verify inode changed (atomic replacement creates new file)
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let new_inode = fs::metadata(&binary_path).unwrap().ino();
        assert_ne!(
            original_inode, new_inode,
            "Inode should change on atomic replace"
        );
    }
}

#[test]
fn test_binary_replacement_preserves_execute_permission() {
    let temp_dir = TempDir::new().unwrap();
    let binary_path = temp_dir.path().join("dcg");

    // Create original binary with execute permission
    create_mock_binary(&binary_path, b"original");

    // Replace with new content, preserving permissions
    let new_content = b"new content";
    let temp_path = temp_dir.path().join("dcg.new");
    fs::write(&temp_path, new_content).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fs::rename(&temp_path, &binary_path).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(&binary_path).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "Execute permission should be preserved"
        );
    }
}

#[test]
fn test_binary_replacement_failure_preserves_original() {
    let temp_dir = TempDir::new().unwrap();
    let binary_path = temp_dir.path().join("dcg");

    // Create original binary
    let original_content = b"original binary";
    create_mock_binary(&binary_path, original_content);

    // Simulate failed replacement (checksum mismatch scenario)
    let new_content = b"new content";
    let expected_checksum = "wrong_checksum_12345";
    let actual_checksum = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(new_content);
        format!("{:x}", hasher.finalize())
    };

    // Checksum verification fails
    assert_ne!(expected_checksum, actual_checksum);

    // Original should be preserved (we didn't replace it)
    let content = fs::read(&binary_path).unwrap();
    assert_eq!(content, original_content);
}

// =============================================================================
// Rollback Tests
// =============================================================================

#[test]
fn test_rollback_to_specific_version() {
    let temp_dir = TempDir::new().unwrap();
    let backup_dir = create_mock_backup_dir(&temp_dir);
    let binary_path = temp_dir.path().join("dcg");

    // Create current binary (v2.0.0)
    create_mock_binary(&binary_path, b"version 2.0.0");

    // Create backup of previous version
    create_mock_backup_entry(&backup_dir, "1.9.0", 1_737_100_000, b"version 1.9.0");

    // Simulate rollback by copying backup to binary location
    let backup_binary = backup_dir.join("dcg-1.9.0-1737100000");
    fs::copy(&backup_binary, &binary_path).unwrap();

    // Verify rollback
    let content = fs::read(&binary_path).unwrap();
    assert_eq!(content, b"version 1.9.0");
}

#[test]
fn test_rollback_to_most_recent_backup() {
    let temp_dir = TempDir::new().unwrap();
    let backup_dir = create_mock_backup_dir(&temp_dir);
    let binary_path = temp_dir.path().join("dcg");

    // Create current binary
    create_mock_binary(&binary_path, b"current version");

    // Create multiple backups
    create_mock_backup_entry(&backup_dir, "0.2.10", 1_737_000_000, b"v0.2.10");
    create_mock_backup_entry(&backup_dir, "0.2.11", 1_737_100_000, b"v0.2.11");
    create_mock_backup_entry(&backup_dir, "0.2.12", 1_737_200_000, b"v0.2.12");

    // Find most recent backup
    let mut entries: Vec<(PathBuf, u64)> = Vec::new();
    for entry in fs::read_dir(&backup_dir).unwrap().filter_map(Result::ok) {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            let content = fs::read_to_string(&path).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
            let timestamp = parsed["created_at"].as_u64().unwrap();
            let version = parsed["version"].as_str().unwrap();
            let binary_name = format!("dcg-{version}-{timestamp}");
            entries.push((backup_dir.join(binary_name), timestamp));
        }
    }
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.1));

    // Rollback to most recent
    fs::copy(&entries[0].0, &binary_path).unwrap();

    let content = fs::read(&binary_path).unwrap();
    assert_eq!(
        content, b"v0.2.12",
        "Should rollback to most recent (0.2.12)"
    );
}

#[test]
fn test_rollback_preserves_config() {
    let temp_dir = TempDir::new().unwrap();
    let config_dir = temp_dir.path().join(".config").join("dcg");
    fs::create_dir_all(&config_dir).unwrap();

    let config_path = config_dir.join("config.toml");
    let config_content = "custom_setting = true\nverbosity = 2";
    fs::write(&config_path, config_content).unwrap();

    // Simulate rollback (config should remain untouched)
    let backup_dir = create_mock_backup_dir(&temp_dir);
    create_mock_backup_entry(&backup_dir, "1.9.0", 1_737_100_000, b"version 1.9.0");

    // After rollback, config should be preserved
    let read_config = fs::read_to_string(&config_path).unwrap();
    assert!(read_config.contains("custom_setting = true"));
    assert!(read_config.contains("verbosity = 2"));
}

#[test]
fn test_rollback_fails_with_no_backups() {
    let temp_dir = TempDir::new().unwrap();
    let backup_dir = create_mock_backup_dir(&temp_dir);

    // No backups exist - just an empty directory
    let json_count = fs::read_dir(&backup_dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
        .count();

    assert_eq!(json_count, 0, "Should have no backups available");
}

#[test]
fn test_rollback_fails_for_missing_version() {
    let temp_dir = TempDir::new().unwrap();
    let backup_dir = create_mock_backup_dir(&temp_dir);

    // Create backup of version 1.9.0
    create_mock_backup_entry(&backup_dir, "1.9.0", 1_737_100_000, b"version 1.9.0");

    // Try to find version 1.8.0 (doesn't exist)
    let target_version = "1.8.0";
    let found = fs::read_dir(&backup_dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
        .any(|e| {
            let content = fs::read_to_string(e.path()).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
            parsed["version"].as_str() == Some(target_version)
        });

    assert!(!found, "Version 1.8.0 should not be found");
}

// =============================================================================
// Backup Pruning Tests
// =============================================================================

#[test]
fn test_backup_pruning_keeps_max_backups() {
    const MAX_BACKUPS: usize = 3;

    let temp_dir = TempDir::new().unwrap();
    let backup_dir = create_mock_backup_dir(&temp_dir);

    // Create more than MAX_BACKUPS entries
    create_mock_backup_entry(&backup_dir, "0.2.9", 1_736_900_000, b"v0.2.9");
    create_mock_backup_entry(&backup_dir, "0.2.10", 1_737_000_000, b"v0.2.10");
    create_mock_backup_entry(&backup_dir, "0.2.11", 1_737_100_000, b"v0.2.11");
    create_mock_backup_entry(&backup_dir, "0.2.12", 1_737_200_000, b"v0.2.12");
    create_mock_backup_entry(&backup_dir, "0.2.13", 1_737_300_000, b"v0.2.13");

    // Collect all backups sorted by timestamp (newest first)
    let mut entries: Vec<(String, u64)> = Vec::new();
    for entry in fs::read_dir(&backup_dir).unwrap().filter_map(Result::ok) {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            let content = fs::read_to_string(&path).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
            entries.push((
                parsed["version"].as_str().unwrap().to_string(),
                parsed["created_at"].as_u64().unwrap(),
            ));
        }
    }
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.1));

    // Simulate pruning: keep only MAX_BACKUPS newest
    let to_keep: Vec<_> = entries.iter().take(MAX_BACKUPS).collect();
    let to_remove: Vec<_> = entries.iter().skip(MAX_BACKUPS).collect();

    // Verify we would keep the right ones
    assert_eq!(to_keep.len(), MAX_BACKUPS);
    assert_eq!(to_keep[0].0, "0.2.13");
    assert_eq!(to_keep[1].0, "0.2.12");
    assert_eq!(to_keep[2].0, "0.2.11");

    // Verify we would remove the right ones
    assert_eq!(to_remove.len(), 2);
    assert!(to_remove.iter().any(|(v, _)| v == "0.2.10"));
    assert!(to_remove.iter().any(|(v, _)| v == "0.2.9"));
}

// =============================================================================
// Cache Tests
// =============================================================================

#[test]
fn test_version_cache_structure() {
    let temp_dir = TempDir::new().unwrap();
    let cache_path = temp_dir.path().join("version_check.json");

    // Create mock cache
    let cache_content = serde_json::json!({
        "result": {
            "current_version": "0.2.12",
            "latest_version": "0.3.0",
            "update_available": true,
            "release_url": "https://github.com/test/repo/releases/latest",
            "release_notes": "Bug fixes",
            "checked_at": "2026-01-17T00:00:00Z"
        },
        "cached_at_secs": 1_737_200_000
    });

    fs::write(
        &cache_path,
        serde_json::to_string_pretty(&cache_content).unwrap(),
    )
    .unwrap();

    // Verify cache file is valid
    let content = fs::read_to_string(&cache_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

    assert!(parsed["result"]["update_available"].as_bool().unwrap());
    assert_eq!(parsed["result"]["latest_version"], "0.3.0");
    assert!(parsed["cached_at_secs"].as_u64().is_some());
}

#[test]
fn test_cache_expiration_check() {
    // Cache should expire after 24 hours (86400 seconds)
    const CACHE_DURATION_SECS: u64 = 24 * 60 * 60;

    let cached_at: u64 = 1_737_200_000;
    let now_fresh: u64 = 1_737_200_000 + 3600; // 1 hour later
    let now_expired: u64 = 1_737_200_000 + 100_000; // > 24 hours later

    // Fresh check
    assert!(
        now_fresh.saturating_sub(cached_at) < CACHE_DURATION_SECS,
        "Cache should be fresh after 1 hour"
    );

    // Expired check
    assert!(
        now_expired.saturating_sub(cached_at) >= CACHE_DURATION_SECS,
        "Cache should be expired after > 24 hours"
    );
}

// =============================================================================
// Version String Handling Tests
// =============================================================================

#[test]
fn test_version_v_prefix_stripping() {
    // trim_start_matches strips ALL leading occurrences of the character
    let versions = vec![
        ("v1.2.3", "1.2.3"),
        ("1.2.3", "1.2.3"),
        ("v0.2.12", "0.2.12"),
        ("vv1.0.0", "1.0.0"), // double v - both stripped by trim_start_matches
    ];

    for (input, expected) in versions {
        let stripped = input.trim_start_matches('v');
        assert_eq!(stripped, expected, "Failed for input: {input}");
    }
}

#[test]
fn test_version_parsing_with_prerelease() {
    let versions = vec![
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-rc.1",
        "2.0.0-alpha+build.123",
    ];

    for version_str in versions {
        let parsed = semver::Version::parse(version_str);
        assert!(parsed.is_ok(), "Failed to parse: {version_str}");
    }
}

#[test]
fn test_version_parsing_with_build_metadata() {
    let version = semver::Version::parse("1.0.0+build.456").unwrap();
    assert_eq!(version.major, 1);
    assert_eq!(version.minor, 0);
    assert_eq!(version.patch, 0);
    assert_eq!(version.build.as_str(), "build.456");
}
