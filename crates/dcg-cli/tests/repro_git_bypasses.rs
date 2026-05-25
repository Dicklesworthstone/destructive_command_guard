#[cfg(test)]
mod tests {
    use dcg_cli::packs::core::git;
    use dcg_cli::packs::test_helpers::*;

    #[test]
    fn test_git_clean_force_long_bypass() {
        let pack = git::create_pack();
        // This fails if --force is not covered
        assert_blocks_with_pattern(&pack, "git clean --force", "clean-force");
    }

    #[test]
    fn test_git_branch_force_delete_long_bypass() {
        let pack = git::create_pack();
        // Verify that the long flag form is blocked
        assert_blocks_with_pattern(
            &pack,
            "git branch --delete --force feature",
            "branch-force-delete",
        );
    }
}
