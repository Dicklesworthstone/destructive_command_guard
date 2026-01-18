#[cfg(test)]
mod tests {
    use destructive_command_guard::config::Config;
    use destructive_command_guard::evaluator::evaluate_command;
    use destructive_command_guard::packs::REGISTRY;

    #[test]
    fn test_redirection_bypass() {
        let config = Config::default(); // Defaults enable core packs

        let enabled_packs = config.enabled_pack_ids();
        let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
        let compiled_overrides = config.overrides.compile();
        let allowlists = destructive_command_guard::LayeredAllowlist::default();

        // Baseline: git reset --hard is blocked
        let result = evaluate_command(
            "git reset --hard",
            &config,
            &enabled_keywords,
            &compiled_overrides,
            &allowlists,
        );
        assert!(
            result.is_denied(),
            "Baseline: git reset --hard should be denied"
        );

        // Bypass attempt: "git">/dev/null reset --hard
        // If tokenizer treats "git">/dev/null as one word and normalization fails to strip quotes,
        // the pack pattern might fail to match "git".
        let result = evaluate_command(
            "\"git\">/dev/null reset --hard",
            &config,
            &enabled_keywords,
            &compiled_overrides,
            &allowlists,
        );

        // This assertion checks if the bypass is SUCCESSFUL (i.e. we want it to FAIL/be blocked)
        // If is_denied() is false, the bug exists.
        assert!(
            result.is_denied(),
            "Bypass: \"git\">/dev/null reset --hard should be denied"
        );

        // Bypass attempt 2: unquoted redirection in middle
        let result = evaluate_command(
            "git >/dev/null reset --hard",
            &config,
            &enabled_keywords,
            &compiled_overrides,
            &allowlists,
        );
        assert!(
            result.is_denied(),
            "Bypass: git >/dev/null reset --hard should be denied"
        );
    }
}
