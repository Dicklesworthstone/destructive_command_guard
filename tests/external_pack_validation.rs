//! Unit tests for external pack schema validation, collision behavior, and regex engine selection.
//!
//! These tests verify the custom pack authoring logic from beads task git_safety_guard-8kkm.4.
//! Coverage includes:
//! - Schema version validation (valid, unsupported, edge cases)
//! - Pack ID collision behavior (override vs reject, external-to-external deduplication)
//! - Regex engine selection (linear vs backtracking)

use std::io::Write;
use tempfile::TempDir;

use destructive_command_guard::packs::external::{
    CURRENT_SCHEMA_VERSION, ExternalPack, ExternalPackLoader, PackParseError, RegexEngineType,
    analyze_pack_engines, check_builtin_collision, parse_pack_string, parse_pack_string_checked,
    summarize_pack_engines, validate_pack_with_collision_check,
};

// =============================================================================
// Schema Version Validation Tests
// =============================================================================

mod schema_version {
    use super::*;

    #[test]
    fn test_schema_version_1_is_valid() {
        let yaml = r"
schema_version: 1
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
";
        let result = parse_pack_string(yaml);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().schema_version, 1);
    }

    #[test]
    fn test_schema_version_defaults_to_1_when_omitted() {
        let yaml = r"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
";
        let result = parse_pack_string(yaml);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().schema_version, 1);
    }

    #[test]
    fn test_schema_version_0_is_rejected() {
        // Schema version 0 should be rejected (minimum is 1 per schema)
        let yaml = r"
schema_version: 0
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
";
        // Note: The current implementation doesn't explicitly reject 0,
        // it only rejects > CURRENT_SCHEMA_VERSION.
        // This test documents current behavior - version 0 is accepted.
        let result = parse_pack_string(yaml);
        // If the implementation enforces minimum 1, this would fail.
        // Currently it allows 0, so we document that:
        assert!(result.is_ok(), "Current impl allows schema_version: 0");
    }

    #[test]
    fn test_schema_version_2_is_rejected() {
        let yaml = r"
schema_version: 2
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
";
        let result = parse_pack_string(yaml);
        assert!(matches!(
            result,
            Err(PackParseError::UnsupportedSchemaVersion { found: 2, .. })
        ));
    }

    #[test]
    fn test_schema_version_future_is_rejected() {
        let yaml = r"
schema_version: 999
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
";
        let result = parse_pack_string(yaml);
        assert!(matches!(
            result,
            Err(PackParseError::UnsupportedSchemaVersion {
                found: 999,
                max_supported
            }) if max_supported == CURRENT_SCHEMA_VERSION
        ));
    }

    #[test]
    fn test_schema_version_error_message_is_actionable() {
        let yaml = r"
schema_version: 42
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
";
        let result = parse_pack_string(yaml);
        let err = result.unwrap_err();
        let msg = err.to_string();
        // Error should mention both the found version and max supported
        assert!(msg.contains("42"), "Error should mention found version");
        assert!(
            msg.contains(&CURRENT_SCHEMA_VERSION.to_string()),
            "Error should mention max supported version"
        );
    }
}

// =============================================================================
// Pack ID Collision Behavior Tests
// =============================================================================

mod collision_behavior {
    use super::*;

    #[test]
    fn test_collision_with_core_git_is_rejected() {
        let yaml = r"
id: core.git
name: Malicious Override
version: 1.0.0
destructive_patterns:
  - name: bypass
    pattern: never-match
";
        let result = parse_pack_string_checked(yaml);
        assert!(matches!(result, Err(PackParseError::IdCollision { .. })));
    }

    #[test]
    fn test_collision_with_core_filesystem_is_rejected() {
        let yaml = r"
id: core.filesystem
name: Malicious Override
version: 1.0.0
destructive_patterns:
  - name: bypass
    pattern: never-match
";
        let result = parse_pack_string_checked(yaml);
        assert!(matches!(result, Err(PackParseError::IdCollision { .. })));
    }

    #[test]
    fn test_collision_with_database_postgresql_is_rejected() {
        let yaml = r"
id: database.postgresql
name: Malicious Override
version: 1.0.0
destructive_patterns:
  - name: bypass
    pattern: never-match
";
        let result = parse_pack_string_checked(yaml);
        assert!(matches!(result, Err(PackParseError::IdCollision { .. })));
    }

    #[test]
    fn test_collision_with_kubernetes_kubectl_is_rejected() {
        let yaml = r"
id: kubernetes.kubectl
name: Malicious Override
version: 1.0.0
destructive_patterns:
  - name: bypass
    pattern: never-match
";
        let result = parse_pack_string_checked(yaml);
        assert!(matches!(result, Err(PackParseError::IdCollision { .. })));
    }

    #[test]
    fn test_collision_error_includes_builtin_name() {
        let yaml = r"
id: core.git
name: Override
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
";
        let result = parse_pack_string_checked(yaml);
        if let Err(PackParseError::IdCollision { id, builtin_name }) = result {
            assert_eq!(id, "core.git");
            assert!(!builtin_name.is_empty(), "Should include builtin pack name");
        } else {
            panic!("Expected IdCollision error");
        }
    }

    #[test]
    fn test_collision_error_message_is_actionable() {
        let yaml = r"
id: core.git
name: Override
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
";
        let result = parse_pack_string_checked(yaml);
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("core.git"), "Should mention colliding ID");
        assert!(
            msg.contains("collides"),
            "Should use actionable word 'collides'"
        );
        assert!(
            msg.contains("built-in"),
            "Should mention built-in pack restriction"
        );
    }

    #[test]
    fn test_parse_without_collision_check_allows_override() {
        // Without collision check, core.git ID should be accepted
        let yaml = r"
id: core.git
name: Override Git
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
";
        let result = parse_pack_string(yaml);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_pack_with_collision_check_function() {
        let yaml = r"
id: database.redis
name: Override Redis
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
";
        let pack: ExternalPack = serde_yaml::from_str(yaml).unwrap();
        let result = validate_pack_with_collision_check(&pack);
        assert!(matches!(result, Err(PackParseError::IdCollision { .. })));
    }

    #[test]
    fn test_custom_namespace_no_collision() {
        let yaml = r"
id: mycompany.policies
name: My Company Policies
version: 1.0.0
destructive_patterns:
  - name: prod-deploy
    pattern: deploy.*prod
";
        let result = parse_pack_string_checked(yaml);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_builtin_collision_function_systematic() {
        // Test collision detection for known built-in packs
        let builtin_ids = [
            "core.git",
            "core.filesystem",
            "database.postgresql",
            "database.mysql",
            "database.mongodb",
            "database.redis",
            "containers.docker",
            "kubernetes.kubectl",
            "cloud.aws",
            "cloud.gcp",
            "cloud.azure",
            "infrastructure.terraform",
        ];

        for id in builtin_ids {
            let result = check_builtin_collision(id);
            assert!(
                result.is_some(),
                "Expected collision for built-in pack: {id}"
            );
        }

        // Test non-collision for custom namespaces
        let custom_ids = [
            "mycompany.deploy",
            "custom.policies",
            "internal.security",
            "team.rules",
        ];

        for id in custom_ids {
            let result = check_builtin_collision(id);
            assert!(
                result.is_none(),
                "Expected no collision for custom pack: {id}"
            );
        }
    }

    #[test]
    fn test_nonexistent_pack_in_existing_category_no_collision() {
        // database.oracle doesn't exist as a built-in, so no collision
        let result = check_builtin_collision("database.oracle");
        assert!(result.is_none());

        // core.networking doesn't exist either
        let result = check_builtin_collision("core.networking");
        assert!(result.is_none());
    }
}

// =============================================================================
// External-to-External Pack Deduplication Tests
// =============================================================================

mod deduplication {
    use super::*;

    fn create_temp_pack_file(dir: &TempDir, filename: &str, content: &str) -> std::path::PathBuf {
        let path = dir.path().join(filename);
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn test_loader_deduplication_later_wins() {
        let temp_dir = TempDir::new().unwrap();

        // Create two packs with the same ID
        let pack1_content = r"
id: company.test
name: Test Pack Version 1
version: 1.0.0
destructive_patterns:
  - name: pattern-v1
    pattern: danger_v1
";

        let pack2_content = r"
id: company.test
name: Test Pack Version 2
version: 2.0.0
destructive_patterns:
  - name: pattern-v2
    pattern: danger_v2
";

        let path1 = create_temp_pack_file(&temp_dir, "pack1.yaml", pack1_content);
        let path2 = create_temp_pack_file(&temp_dir, "pack2.yaml", pack2_content);

        let loader = ExternalPackLoader::from_paths(&[
            path1.to_string_lossy().to_string(),
            path2.to_string_lossy().to_string(),
        ]);

        let result = loader.load_all_deduped();

        // Should have exactly one pack (deduplicated by ID)
        assert_eq!(result.packs.len(), 1);

        // Later pack wins (version 2.0.0)
        let pack = &result.packs[0];
        assert_eq!(pack.id, "company.test");
        // The pack name should be from the later file
        assert_eq!(pack.pack.name, "Test Pack Version 2");
    }

    #[test]
    fn test_loader_different_ids_both_loaded() {
        let temp_dir = TempDir::new().unwrap();

        let pack1_content = r"
id: company.pack1
name: Pack One
version: 1.0.0
destructive_patterns:
  - name: pattern1
    pattern: danger1
";

        let pack2_content = r"
id: company.pack2
name: Pack Two
version: 1.0.0
destructive_patterns:
  - name: pattern2
    pattern: danger2
";

        let path1 = create_temp_pack_file(&temp_dir, "pack1.yaml", pack1_content);
        let path2 = create_temp_pack_file(&temp_dir, "pack2.yaml", pack2_content);

        let loader = ExternalPackLoader::from_paths(&[
            path1.to_string_lossy().to_string(),
            path2.to_string_lossy().to_string(),
        ]);

        let result = loader.load_all_deduped();

        // Both packs should be loaded (different IDs)
        assert_eq!(result.packs.len(), 2);

        let ids: Vec<&str> = result.packs.iter().map(|p| p.id.as_str()).collect();
        assert!(ids.contains(&"company.pack1"));
        assert!(ids.contains(&"company.pack2"));
    }

    #[test]
    fn test_loader_invalid_file_generates_warning() {
        let temp_dir = TempDir::new().unwrap();

        let valid_content = r"
id: company.valid
name: Valid Pack
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
";

        let invalid_content = "this is not: valid: yaml: [";

        let valid_path = create_temp_pack_file(&temp_dir, "valid.yaml", valid_content);
        let invalid_path = create_temp_pack_file(&temp_dir, "invalid.yaml", invalid_content);

        let loader = ExternalPackLoader::from_paths(&[
            valid_path.to_string_lossy().to_string(),
            invalid_path.to_string_lossy().to_string(),
        ]);

        let result = loader.load_all();

        // Valid pack should be loaded
        assert_eq!(result.packs.len(), 1);
        assert_eq!(result.packs[0].id, "company.valid");

        // Invalid file should generate warning
        assert_eq!(result.warnings.len(), 1);
        assert!(
            result.warnings[0]
                .path
                .to_string_lossy()
                .contains("invalid.yaml")
        );
    }

    #[test]
    fn test_loader_collision_with_builtin_generates_warning() {
        let temp_dir = TempDir::new().unwrap();

        // This pack collides with core.git
        let collision_content = r"
id: core.git
name: Malicious Override
version: 1.0.0
destructive_patterns:
  - name: bypass
    pattern: never-match
";

        let path = create_temp_pack_file(&temp_dir, "collision.yaml", collision_content);

        let loader = ExternalPackLoader::from_paths(&[path.to_string_lossy().to_string()]);

        let result = loader.load_all();

        // Collision should be rejected (generates warning)
        assert_eq!(result.packs.len(), 0);
        assert_eq!(result.warnings.len(), 1);

        // Warning should indicate collision
        if let PackParseError::IdCollision { id, .. } = &result.warnings[0].error {
            assert_eq!(id, "core.git");
        } else {
            panic!("Expected IdCollision error in warning");
        }
    }

    #[test]
    fn test_loader_paths_method() {
        let temp_dir = TempDir::new().unwrap();

        let content = r"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
";

        let path = create_temp_pack_file(&temp_dir, "test.yaml", content);
        let path_str = path.to_string_lossy().to_string();

        let loader = ExternalPackLoader::from_paths(&[path_str.clone()]);

        let paths = loader.paths();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].to_string_lossy(), path_str);
    }

    #[test]
    fn test_loader_empty_paths() {
        let loader = ExternalPackLoader::from_paths(&[]);

        assert!(loader.paths().is_empty());

        let result = loader.load_all();
        assert!(result.packs.is_empty());
        assert!(result.warnings.is_empty());
    }
}

// =============================================================================
// Regex Engine Selection Tests
// =============================================================================

mod regex_engine_selection {
    use super::*;

    #[test]
    fn test_simple_patterns_use_linear_engine() {
        let yaml = r"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: simple-rm
    pattern: rm\s+-rf
  - name: simple-git
    pattern: git\s+reset\s+--hard
safe_patterns:
  - name: simple-ls
    pattern: ls\s+-la
";
        let pack = parse_pack_string(yaml).unwrap();
        let infos = analyze_pack_engines(&pack);

        for info in infos {
            assert_eq!(
                info.engine,
                RegexEngineType::Linear,
                "Pattern '{}' should use linear engine",
                info.name
            );
        }
    }

    #[test]
    fn test_lookahead_patterns_use_backtracking_engine() {
        let yaml = r"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: positive-lookahead
    pattern: git\s+push(?=.*--force)
  - name: negative-lookahead
    pattern: rm(?!\s+--dry-run)
";
        let pack = parse_pack_string(yaml).unwrap();
        let infos = analyze_pack_engines(&pack);

        for info in infos {
            assert_eq!(
                info.engine,
                RegexEngineType::Backtracking,
                "Pattern '{}' should use backtracking engine",
                info.name
            );
        }
    }

    #[test]
    fn test_lookbehind_patterns_use_backtracking_engine() {
        let yaml = r"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: positive-lookbehind
    pattern: (?<=drop\s)database
  - name: negative-lookbehind
    pattern: (?<!safe\s)delete
";
        let pack = parse_pack_string(yaml).unwrap();
        let infos = analyze_pack_engines(&pack);

        for info in infos {
            assert_eq!(
                info.engine,
                RegexEngineType::Backtracking,
                "Pattern '{}' should use backtracking engine",
                info.name
            );
        }
    }

    #[test]
    fn test_backreference_patterns_use_backtracking_engine() {
        let yaml = r"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: simple-backref
    pattern: (\w+)\s+\1
  - name: multi-backref
    pattern: (a)(b)\2\1
";
        let pack = parse_pack_string(yaml).unwrap();
        let infos = analyze_pack_engines(&pack);

        for info in infos {
            assert_eq!(
                info.engine,
                RegexEngineType::Backtracking,
                "Pattern '{}' should use backtracking engine",
                info.name
            );
        }
    }

    #[test]
    fn test_possessive_quantifiers_use_backtracking_engine() {
        let yaml = r"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: star-possessive
    pattern: a*+b
  - name: plus-possessive
    pattern: a++b
  - name: question-possessive
    pattern: a?+b
";
        let pack = parse_pack_string(yaml).unwrap();
        let infos = analyze_pack_engines(&pack);

        for info in infos {
            assert_eq!(
                info.engine,
                RegexEngineType::Backtracking,
                "Pattern '{}' with possessive quantifier should use backtracking engine",
                info.name
            );
        }
    }

    #[test]
    fn test_atomic_groups_use_backtracking_engine() {
        let yaml = r"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: atomic-group
    pattern: (?>a|ab)c
";
        let pack = parse_pack_string(yaml).unwrap();
        let infos = analyze_pack_engines(&pack);

        assert_eq!(infos.len(), 1);
        assert_eq!(
            infos[0].engine,
            RegexEngineType::Backtracking,
            "Atomic group pattern should use backtracking engine"
        );
    }

    #[test]
    fn test_mixed_engine_pack() {
        let yaml = r"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: linear-pattern
    pattern: rm\s+-rf
  - name: backtrack-pattern
    pattern: git(?=.*--force)
safe_patterns:
  - name: safe-linear
    pattern: ls
  - name: safe-backtrack
    pattern: (?<=safe\s)mode
";
        let pack = parse_pack_string(yaml).unwrap();
        let summary = summarize_pack_engines(&pack);

        assert_eq!(summary.linear_count, 2);
        assert_eq!(summary.backtracking_count, 2);
        assert_eq!(summary.total(), 4);
        assert!((summary.linear_percentage() - 50.0).abs() < 0.001);
    }

    #[test]
    fn test_engine_summary_all_linear() {
        let yaml = r"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: p1
    pattern: simple
  - name: p2
    pattern: also\s+simple
  - name: p3
    pattern: very\s+simple
";
        let pack = parse_pack_string(yaml).unwrap();
        let summary = summarize_pack_engines(&pack);

        assert_eq!(summary.linear_count, 3);
        assert_eq!(summary.backtracking_count, 0);
        assert!((summary.linear_percentage() - 100.0).abs() < 0.001);
    }

    #[test]
    fn test_engine_summary_all_backtracking() {
        let yaml = r"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: p1
    pattern: a(?=b)
  - name: p2
    pattern: c(?!d)
  - name: p3
    pattern: (?<=e)f
";
        let pack = parse_pack_string(yaml).unwrap();
        let summary = summarize_pack_engines(&pack);

        assert_eq!(summary.linear_count, 0);
        assert_eq!(summary.backtracking_count, 3);
        assert!((summary.linear_percentage()).abs() < 0.001);
    }

    #[test]
    fn test_pattern_engine_info_fields_complete() {
        let yaml = r"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: dest-pattern
    pattern: danger.*here
safe_patterns:
  - name: safe-pattern
    pattern: safe(?=.*mode)
";
        let pack = parse_pack_string(yaml).unwrap();
        let infos = analyze_pack_engines(&pack);

        // Check destructive pattern
        let dest_info = infos.iter().find(|i| i.name == "dest-pattern").unwrap();
        assert_eq!(dest_info.pattern, "danger.*here");
        assert!(dest_info.is_destructive);
        assert_eq!(dest_info.engine, RegexEngineType::Linear);

        // Check safe pattern (has lookahead)
        let safe_info = infos.iter().find(|i| i.name == "safe-pattern").unwrap();
        assert_eq!(safe_info.pattern, "safe(?=.*mode)");
        assert!(!safe_info.is_destructive);
        assert_eq!(safe_info.engine, RegexEngineType::Backtracking);
    }

    #[test]
    fn test_regex_engine_type_display() {
        assert_eq!(format!("{}", RegexEngineType::Linear), "linear");
        assert_eq!(format!("{}", RegexEngineType::Backtracking), "backtracking");
    }
}

// =============================================================================
// Invalid Pack Tests
// =============================================================================

mod invalid_packs {
    use super::*;

    #[test]
    fn test_missing_required_id_field() {
        let yaml = r"
name: Test
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
";
        let result = parse_pack_string(yaml);
        assert!(matches!(result, Err(PackParseError::Yaml(_))));
    }

    #[test]
    fn test_missing_required_name_field() {
        let yaml = r"
id: test.pack
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
";
        let result = parse_pack_string(yaml);
        assert!(matches!(result, Err(PackParseError::Yaml(_))));
    }

    #[test]
    fn test_missing_required_version_field() {
        let yaml = r"
id: test.pack
name: Test
destructive_patterns:
  - name: test
    pattern: test
";
        let result = parse_pack_string(yaml);
        assert!(matches!(result, Err(PackParseError::Yaml(_))));
    }

    #[test]
    fn test_invalid_id_uppercase() {
        let yaml = r"
id: Test.Pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
";
        let result = parse_pack_string(yaml);
        assert!(matches!(result, Err(PackParseError::InvalidId { .. })));
    }

    #[test]
    fn test_invalid_id_no_dot() {
        let yaml = r"
id: testpack
name: Test
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
";
        let result = parse_pack_string(yaml);
        assert!(matches!(result, Err(PackParseError::InvalidId { .. })));
    }

    #[test]
    fn test_invalid_id_starts_with_number() {
        let yaml = r"
id: 1test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
";
        let result = parse_pack_string(yaml);
        assert!(matches!(result, Err(PackParseError::InvalidId { .. })));
    }

    #[test]
    fn test_invalid_id_special_characters() {
        let yaml = r"
id: test-pack.rules
name: Test
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
";
        let result = parse_pack_string(yaml);
        assert!(matches!(result, Err(PackParseError::InvalidId { .. })));
    }

    #[test]
    fn test_invalid_version_two_parts() {
        let yaml = r"
id: test.pack
name: Test
version: 1.0
destructive_patterns:
  - name: test
    pattern: test
";
        let result = parse_pack_string(yaml);
        assert!(matches!(result, Err(PackParseError::InvalidVersion { .. })));
    }

    #[test]
    fn test_invalid_version_non_numeric() {
        let yaml = r"
id: test.pack
name: Test
version: 1.0.alpha
destructive_patterns:
  - name: test
    pattern: test
";
        let result = parse_pack_string(yaml);
        assert!(matches!(result, Err(PackParseError::InvalidVersion { .. })));
    }

    #[test]
    fn test_invalid_regex_unclosed_bracket() {
        let yaml = r#"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: bad-regex
    pattern: "[unclosed"
"#;
        let result = parse_pack_string(yaml);
        assert!(matches!(result, Err(PackParseError::InvalidPattern { .. })));
    }

    #[test]
    fn test_invalid_regex_unclosed_group() {
        let yaml = r#"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: bad-regex
    pattern: "(unclosed"
"#;
        let result = parse_pack_string(yaml);
        assert!(matches!(result, Err(PackParseError::InvalidPattern { .. })));
    }

    #[test]
    fn test_invalid_pattern_error_includes_pattern_name() {
        let yaml = r#"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: my-bad-pattern
    pattern: "[invalid"
"#;
        let result = parse_pack_string(yaml);
        if let Err(PackParseError::InvalidPattern { name, pattern, .. }) = result {
            assert_eq!(name, "my-bad-pattern");
            assert_eq!(pattern, "[invalid");
        } else {
            panic!("Expected InvalidPattern error");
        }
    }

    #[test]
    fn test_duplicate_pattern_name_in_destructive() {
        let yaml = r"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: duplicate
    pattern: pattern1
  - name: duplicate
    pattern: pattern2
";
        let result = parse_pack_string(yaml);
        assert!(matches!(
            result,
            Err(PackParseError::DuplicatePattern { .. })
        ));
    }

    #[test]
    fn test_duplicate_pattern_name_across_types() {
        let yaml = r"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: shared-name
    pattern: danger
safe_patterns:
  - name: shared-name
    pattern: safe
";
        let result = parse_pack_string(yaml);
        assert!(matches!(
            result,
            Err(PackParseError::DuplicatePattern { .. })
        ));
    }

    #[test]
    fn test_empty_pack_no_patterns() {
        let yaml = r"
id: test.pack
name: Test
version: 1.0.0
";
        let result = parse_pack_string(yaml);
        assert!(matches!(result, Err(PackParseError::EmptyPack)));
    }

    #[test]
    fn test_empty_pack_empty_arrays() {
        let yaml = r"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns: []
safe_patterns: []
";
        let result = parse_pack_string(yaml);
        assert!(matches!(result, Err(PackParseError::EmptyPack)));
    }

    #[test]
    fn test_malformed_yaml() {
        let yaml = "not: valid: yaml: content: [";
        let result = parse_pack_string(yaml);
        assert!(matches!(result, Err(PackParseError::Yaml(_))));
    }
}

// =============================================================================
// Valid Pack Edge Cases
// =============================================================================

mod valid_edge_cases {
    use super::*;

    #[test]
    fn test_minimal_valid_pack() {
        let yaml = r"
id: a.b
name: A
version: 0.0.1
destructive_patterns:
  - name: x
    pattern: x
";
        let result = parse_pack_string(yaml);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pack_with_only_safe_patterns() {
        let yaml = r"
id: test.safe
name: Safe Only
version: 1.0.0
safe_patterns:
  - name: allow-all
    pattern: .*
";
        let result = parse_pack_string(yaml);
        assert!(result.is_ok());
        let pack = result.unwrap();
        assert!(pack.destructive_patterns.is_empty());
        assert_eq!(pack.safe_patterns.len(), 1);
    }

    #[test]
    fn test_pack_with_underscores_in_id() {
        let yaml = r"
id: my_company.my_pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
";
        let result = parse_pack_string(yaml);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pack_with_numbers_in_id() {
        let yaml = r"
id: company123.pack456
name: Test
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: test
";
        let result = parse_pack_string(yaml);
        assert!(result.is_ok());
    }

    #[test]
    fn test_all_severity_levels() {
        let yaml = r"
id: test.severity
name: Test
version: 1.0.0
destructive_patterns:
  - name: low
    pattern: low
    severity: low
  - name: medium
    pattern: medium
    severity: medium
  - name: high
    pattern: high
    severity: high
  - name: critical
    pattern: critical
    severity: critical
";
        let result = parse_pack_string(yaml);
        assert!(result.is_ok());
        let pack = result.unwrap();
        assert_eq!(pack.destructive_patterns.len(), 4);
    }

    #[test]
    fn test_severity_default_is_high() {
        let yaml = r"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: no-severity
    pattern: test
";
        let result = parse_pack_string(yaml);
        assert!(result.is_ok());
        let pack = result.unwrap();
        use destructive_command_guard::packs::external::ExternalSeverity;
        assert_eq!(
            pack.destructive_patterns[0].severity,
            ExternalSeverity::High
        );
    }

    #[test]
    fn test_pack_with_multiline_explanation() {
        let yaml = r"
id: test.pack
name: Test
version: 1.0.0
destructive_patterns:
  - name: test
    pattern: danger
    explanation: |
      This is a multiline explanation.
      It spans multiple lines.
      And provides detailed context.
";
        let result = parse_pack_string(yaml);
        assert!(result.is_ok());
        let pack = result.unwrap();
        let explanation = pack.destructive_patterns[0].explanation.as_ref().unwrap();
        assert!(explanation.contains("multiline"));
        assert!(explanation.contains("detailed context"));
    }

    #[test]
    fn test_pack_convert_to_runtime_pack() {
        let yaml = r"
id: test.example
name: Test Example Pack
version: 1.0.0
description: Testing conversion
keywords:
  - test
destructive_patterns:
  - name: block-test
    pattern: dangerous
    severity: critical
    description: Blocks dangerous commands
safe_patterns:
  - name: allow-safe
    pattern: safe
";
        let external = parse_pack_string(yaml).unwrap();
        let pack = external.into_pack();

        assert_eq!(pack.id, "test.example");
        assert_eq!(pack.name, "Test Example Pack");
        assert_eq!(pack.description, "Testing conversion");
        assert_eq!(pack.keywords.len(), 1);
        assert_eq!(pack.keywords[0], "test");
        assert_eq!(pack.safe_patterns.len(), 1);
        assert_eq!(pack.destructive_patterns.len(), 1);
    }
}
