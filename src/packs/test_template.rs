//! Template for pack unit tests.
//!
//! This file provides a complete example of how to test a pack. Copy this
//! template when creating tests for a new pack and adapt it to your specific
//! patterns.
//!
//! # Structure
//!
//! Every pack test module should include:
//!
//! 1. **Pack creation test** - Verify the pack initializes correctly
//! 2. **Destructive pattern tests** - One test per destructive pattern
//! 3. **Safe pattern tests** - One test per safe pattern
//! 4. **Edge case tests** - Special characters, quoting, etc.
//! 5. **Specificity tests** - Verify patterns don't over-match
//! 6. **Severity tests** - Verify correct severity classification
//! 7. **Performance tests** - Verify patterns don't have backtracking issues
//!
//! # Naming Conventions
//!
//! - Test functions: `test_<pattern_name>_<scenario>`
//! - Pattern names: Use the exact pattern name from the pack definition
//! - Command fixtures: Use realistic commands from actual usage
//!
//! # Example Usage
//!
//! To create tests for a new pack (e.g., `database.postgresql`):
//!
//! 1. Copy this file to `src/packs/database/postgresql_tests.rs`
//! 2. Replace `example_pack` references with your pack module
//! 3. Update the test cases for your specific patterns
//! 4. Add `#[path = "postgresql_tests.rs"] mod tests;` to your pack file

#[cfg(test)]
mod pack_test_template {
    //! This template module demonstrates the complete test structure.
    //!
    //! In actual usage, you would:
    //! 1. Place tests in the same file as the pack, or
    //! 2. Create a separate `<pack>_tests.rs` file

    use crate::packs::test_helpers::*;
    use crate::packs::Severity;
    // Import your pack module here:
    // use crate::packs::your_category::your_pack;

    // For this template, we'll use core.git as an example
    use crate::packs::core::git as example_pack;

    // =========================================================================
    // SECTION 1: Pack Creation Tests
    // =========================================================================

    /// Verify the pack initializes correctly with all expected fields.
    #[test]
    fn test_pack_creation() {
        let pack = example_pack::create_pack();

        // Verify pack metadata
        assert!(!pack.id.is_empty(), "Pack should have an ID");
        assert!(!pack.name.is_empty(), "Pack should have a name");
        assert!(!pack.description.is_empty(), "Pack should have a description");
        assert!(!pack.keywords.is_empty(), "Pack should have keywords for quick-reject");

        // Verify patterns exist
        assert!(!pack.destructive_patterns.is_empty(), "Pack should have destructive patterns");
        // Note: safe_patterns may be empty for some packs

        // Verify patterns compile and have required fields
        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    /// Verify the pack has the correct ID format.
    #[test]
    fn test_pack_id_format() {
        let pack = example_pack::create_pack();

        // Pack IDs should be lowercase, dot-separated
        assert!(
            pack.id.chars().all(|c| c.is_ascii_lowercase() || c == '.' || c == '_'),
            "Pack ID '{}' should be lowercase with dots/underscores only",
            pack.id
        );
    }

    // =========================================================================
    // SECTION 2: Destructive Pattern Tests
    // =========================================================================
    //
    // Create one test per destructive pattern. Test:
    // - The canonical command form
    // - Common variations (flags, paths, etc.)
    // - Edge cases specific to this pattern

    /// Test: git reset --hard pattern (CRITICAL severity)
    #[test]
    fn test_destructive_reset_hard_basic() {
        let pack = example_pack::create_pack();

        // Canonical form
        assert_blocks(&pack, "git reset --hard", "destroys uncommitted changes");
    }

    #[test]
    fn test_destructive_reset_hard_with_ref() {
        let pack = example_pack::create_pack();

        // With various refs
        assert_blocks(&pack, "git reset --hard HEAD", "destroys uncommitted");
        assert_blocks(&pack, "git reset --hard HEAD~1", "destroys uncommitted");
        assert_blocks(&pack, "git reset --hard origin/main", "destroys uncommitted");
        assert_blocks(&pack, "git reset --hard abc123", "destroys uncommitted");
    }

    #[test]
    fn test_destructive_reset_hard_severity() {
        let pack = example_pack::create_pack();

        // Verify Critical severity (most dangerous)
        assert_blocks_with_severity(&pack, "git reset --hard", Severity::Critical);
    }

    #[test]
    fn test_destructive_reset_hard_pattern_name() {
        let pack = example_pack::create_pack();

        // Verify pattern name for allowlisting
        assert_blocks_with_pattern(&pack, "git reset --hard", "reset-hard");
    }

    /// Test: git push --force pattern (CRITICAL severity)
    #[test]
    fn test_destructive_push_force_variations() {
        let pack = example_pack::create_pack();

        // Long flag
        assert_blocks(&pack, "git push --force", "destroy remote history");
        assert_blocks(&pack, "git push origin main --force", "destroy remote history");
        assert_blocks(&pack, "git push --force origin main", "destroy remote history");

        // Short flag
        assert_blocks(&pack, "git push -f", "destroy remote history");
        assert_blocks(&pack, "git push origin main -f", "destroy remote history");
    }

    // =========================================================================
    // SECTION 3: Safe Pattern Tests
    // =========================================================================
    //
    // Test that safe patterns correctly allow commands that would otherwise
    // be blocked by destructive patterns.

    /// Test: git checkout -b creates new branch (safe)
    #[test]
    fn test_safe_checkout_new_branch() {
        let pack = example_pack::create_pack();

        // Should be explicitly allowed by safe pattern
        assert_safe_pattern_matches(&pack, "git checkout -b feature");
        assert_safe_pattern_matches(&pack, "git checkout -b feature/new-thing");
        assert_safe_pattern_matches(&pack, "git checkout -b fix-123");
    }

    /// Test: git restore --staged only affects index (safe)
    #[test]
    fn test_safe_restore_staged() {
        let pack = example_pack::create_pack();

        // Unstaging is safe (doesn't touch working tree)
        assert_allows(&pack, "git restore --staged file.txt");
        assert_allows(&pack, "git restore -S file.txt");
    }

    /// Test: git clean --dry-run just previews (safe)
    #[test]
    fn test_safe_clean_dry_run() {
        let pack = example_pack::create_pack();

        assert_allows(&pack, "git clean -n");
        assert_allows(&pack, "git clean -dn");
        assert_allows(&pack, "git clean --dry-run");
    }

    // =========================================================================
    // SECTION 4: Edge Case Tests
    // =========================================================================
    //
    // Test unusual but valid command forms that patterns should handle.

    /// Test: Commands with extra whitespace
    #[test]
    fn test_edge_case_extra_whitespace() {
        let pack = example_pack::create_pack();

        // Multiple spaces should still match
        assert_blocks(&pack, "git  reset  --hard", "destroys uncommitted");
        assert_blocks(&pack, "git   push   --force", "destroy remote history");
    }

    /// Test: Empty and minimal commands
    #[test]
    fn test_edge_case_minimal_commands() {
        let pack = example_pack::create_pack();

        // Empty string should not match
        assert_no_match(&pack, "");

        // Just the keyword should not match destructive patterns
        assert_no_match(&pack, "git");
    }

    /// Test: Commands with quoted arguments
    #[test]
    fn test_edge_case_quoted_arguments() {
        let pack = example_pack::create_pack();

        // Quoted paths should still be blocked
        assert_blocks(&pack, "git reset --hard \"HEAD\"", "destroys uncommitted");
    }

    /// Test: Commands with special characters in paths
    #[test]
    fn test_edge_case_special_characters() {
        let pack = example_pack::create_pack();

        // Paths with special characters
        assert_blocks(&pack, "git push --force origin feature/my-branch", "destroy remote");
        assert_blocks(&pack, "git push --force origin bugfix/issue#123", "destroy remote");
    }

    // =========================================================================
    // SECTION 5: Specificity Tests (False Positive Prevention)
    // =========================================================================
    //
    // Verify patterns don't accidentally match unrelated commands.

    /// Test: Unrelated commands should not match
    #[test]
    fn test_specificity_unrelated_commands() {
        let pack = example_pack::create_pack();

        // Common commands that should NOT match
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "cat file.txt");
        assert_no_match(&pack, "cargo build");
        assert_no_match(&pack, "npm install");
    }

    /// Test: Similar but safe git commands should not match
    #[test]
    fn test_specificity_safe_git_commands() {
        let pack = example_pack::create_pack();

        // These git commands are safe
        assert_allows(&pack, "git status");
        assert_allows(&pack, "git log");
        assert_allows(&pack, "git diff");
        assert_allows(&pack, "git add .");
        assert_allows(&pack, "git commit -m 'message'");
        assert_allows(&pack, "git push");  // Without --force
        assert_allows(&pack, "git pull");
        assert_allows(&pack, "git fetch");
        assert_allows(&pack, "git branch -d feature");  // Safe delete with -d
    }

    /// Test: Substring matches should not trigger (keyword boundary)
    #[test]
    fn test_specificity_substring_not_matched() {
        let pack = example_pack::create_pack();

        // "git" appearing as substring should not trigger
        assert_no_match(&pack, "cat .gitignore");
        assert_no_match(&pack, "echo digit");
        assert_no_match(&pack, "legitimate command with git in path");
    }

    // =========================================================================
    // SECTION 6: Severity Classification Tests
    // =========================================================================
    //
    // Verify patterns have correct severity levels.

    /// Test: Critical patterns (most dangerous, always block)
    #[test]
    fn test_severity_critical_patterns() {
        let pack = example_pack::create_pack();

        // These should all be Critical
        assert_blocks_with_severity(&pack, "git reset --hard", Severity::Critical);
        assert_blocks_with_severity(&pack, "git clean -f", Severity::Critical);
        assert_blocks_with_severity(&pack, "git push --force", Severity::Critical);
        assert_blocks_with_severity(&pack, "git stash clear", Severity::Critical);
    }

    /// Test: High severity patterns (dangerous, block by default)
    #[test]
    fn test_severity_high_patterns() {
        let pack = example_pack::create_pack();

        // These should be High severity
        assert_blocks_with_severity(&pack, "git checkout -- file.txt", Severity::High);
        assert_blocks_with_severity(&pack, "git restore file.txt", Severity::High);
        assert_blocks_with_severity(&pack, "git stash drop", Severity::High);
        assert_blocks_with_severity(&pack, "git branch -D feature", Severity::High);
    }

    // =========================================================================
    // SECTION 7: Performance Tests
    // =========================================================================
    //
    // Verify patterns don't have catastrophic backtracking.

    /// Test: Normal commands should match quickly
    #[test]
    fn test_performance_normal_commands() {
        let pack = example_pack::create_pack();

        // These should all complete within budget
        assert_matches_within_budget(&pack, "git reset --hard");
        assert_matches_within_budget(&pack, "git push --force origin main");
        assert_matches_within_budget(&pack, "git checkout -b feature/new-thing");
    }

    /// Test: Pathological inputs should not cause catastrophic backtracking
    #[test]
    fn test_performance_pathological_inputs() {
        let pack = example_pack::create_pack();

        // Long repeated characters
        let long_flags = format!("git {}", "-".repeat(1000));
        assert_matches_within_budget(&pack, &long_flags);

        // Many spaces
        let many_spaces = format!("git{}{}", " ".repeat(100), "status");
        assert_matches_within_budget(&pack, &many_spaces);
    }

    // =========================================================================
    // SECTION 8: Batch Tests (Optional but Recommended)
    // =========================================================================
    //
    // Use batch tests to verify multiple related commands at once.

    /// Test: All reset variants should be blocked
    #[test]
    fn test_batch_reset_variants() {
        let pack = example_pack::create_pack();

        let reset_commands = vec![
            "git reset --hard",
            "git reset --hard HEAD",
            "git reset --hard HEAD~1",
            "git reset --hard HEAD~10",
            "git reset --hard origin/main",
            "git reset --hard abc123def456",
        ];

        test_batch_blocks(&pack, &reset_commands, "reset");
    }

    /// Test: Safe read-only commands should all be allowed
    #[test]
    fn test_batch_readonly_commands() {
        let pack = example_pack::create_pack();

        let readonly_commands = vec![
            "git status",
            "git log",
            "git log --oneline",
            "git diff",
            "git diff --cached",
            "git show HEAD",
            "git branch",
            "git branch -a",
            "git remote -v",
        ];

        test_batch_allows(&pack, &readonly_commands);
    }
}

// =========================================================================
// How to Use This Template
// =========================================================================
//
// 1. For a new pack in `src/packs/category/my_pack.rs`:
//
//    ```rust
//    // At the end of my_pack.rs, add:
//    #[cfg(test)]
//    mod tests {
//        use super::*;
//        use crate::packs::test_helpers::*;
//        use crate::packs::Severity;
//
//        #[test]
//        fn test_pack_creation() {
//            let pack = create_pack();
//            assert_patterns_compile(&pack);
//            // ... more tests
//        }
//
//        // Copy relevant test patterns from this template
//    }
//    ```
//
// 2. For extensive tests, create a separate file:
//
//    - Create `src/packs/category/my_pack_tests.rs`
//    - Add `#[cfg(test)] #[path = "my_pack_tests.rs"] mod tests;` to my_pack.rs
//
// 3. Run tests:
//
//    ```bash
//    cargo test packs::category::my_pack
//    ```
