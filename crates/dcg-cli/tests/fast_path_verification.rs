#[cfg(test)]
mod tests {
    use dcg_cli::packs::PackEntry;
    use std::sync::atomic::{AtomicBool, Ordering};

    // Global flag to track if the test pack was built
    static TEST_PACK_BUILT: AtomicBool = AtomicBool::new(false);

    // Define a test pack that sets the flag when built
    fn create_test_pack() -> dcg_cli::packs::Pack {
        TEST_PACK_BUILT.store(true, Ordering::SeqCst);

        dcg_cli::packs::Pack {
            id: "test.lazy".to_string(),
            name: "Test Lazy Pack",
            description: "Verifies lazy instantiation",
            keywords: &["lazy_trigger"],
            safe_patterns: vec![],
            destructive_patterns: vec![],
            keyword_matcher: None,
            safe_regex_set: None,
            safe_regex_set_is_complete: false,
        }
    }

    #[test]
    fn verify_fast_path_skips_instantiation() {
        // This test verifies that the evaluator's candidate filtering logic
        // correctly uses metadata-only checks to avoid instantiating packs.
        // This corresponds to git_safety_guard-64dc.4.

        let entry = PackEntry::new("test.fast_path", &["lazy_trigger"], create_test_pack);

        // Case 1: Command with NO keywords -> Should skip instantiation (Fast Path)
        let safe_cmd = "git status"; // "git" is not "lazy_trigger"

        TEST_PACK_BUILT.store(false, Ordering::SeqCst);

        let candidate_packs: Vec<_> = vec![("test.fast_path".to_string(), &entry)]
            .into_iter()
            .filter_map(|(pack_id, entry)| {
                // Logic from evaluator.rs
                if !entry.might_match(safe_cmd) {
                    return None;
                }
                Some((pack_id, entry.get_pack()))
            })
            .collect();

        assert!(
            candidate_packs.is_empty(),
            "Safe command should not yield candidates"
        );
        assert!(
            !TEST_PACK_BUILT.load(Ordering::SeqCst),
            "Safe command MUST NOT trigger pack instantiation"
        );

        // Case 2: Command WITH keywords -> Should instantiate
        let trigger_cmd = "echo lazy_trigger";

        TEST_PACK_BUILT.store(false, Ordering::SeqCst);

        let candidate_packs: Vec<_> = vec![("test.fast_path".to_string(), &entry)]
            .into_iter()
            .filter_map(|(pack_id, entry)| {
                if !entry.might_match(trigger_cmd) {
                    return None;
                }
                Some((pack_id, entry.get_pack()))
            })
            .collect();

        assert!(
            !candidate_packs.is_empty(),
            "Trigger command should yield candidates"
        );
        assert!(
            TEST_PACK_BUILT.load(Ordering::SeqCst),
            "Trigger command MUST trigger pack instantiation"
        );
    }
}
