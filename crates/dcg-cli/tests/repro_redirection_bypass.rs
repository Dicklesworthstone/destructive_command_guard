#[cfg(test)]
mod tests {
    use dcg_cli::config::Config;
    use dcg_cli::evaluator::evaluate_command;
    use dcg_cli::packs::REGISTRY;

    #[test]
    fn test_redirection_bypass() {
        let config = Config::default(); // Defaults enable core packs

        let enabled_packs = config.enabled_pack_ids();
        let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
        let compiled_overrides = config.overrides.compile();
        let allowlists = dcg_cli::LayeredAllowlist::default();

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

        for cmd in [
            "\"git\"&>/dev/null reset --hard",
            "\"git\"&>>/dev/null reset --hard",
            "git>/dev/null reset --hard",
            "git>>/dev/null reset --hard",
            "git&>/dev/null reset --hard",
            "git&>>/dev/null reset --hard",
        ] {
            let result = evaluate_command(
                cmd,
                &config,
                &enabled_keywords,
                &compiled_overrides,
                &allowlists,
            );
            assert!(result.is_denied(), "Bypass: {cmd} should be denied");
        }

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

        // Regression: normalizing the `command` builtin wrapper must not turn
        // append redirection into a synthetic truncate redirection.
        let result = evaluate_command(
            "command >> /usr/local/log",
            &config,
            &enabled_keywords,
            &compiled_overrides,
            &allowlists,
        );
        assert!(
            result.is_allowed(),
            "append redirect via command builtin should be allowed"
        );

        let result = evaluate_command(
            "command >>/dev/null git reset --hard",
            &config,
            &enabled_keywords,
            &compiled_overrides,
            &allowlists,
        );
        assert!(
            result.is_denied(),
            "Bypass: command builtin with leading append redirect should still expose git reset --hard"
        );
    }
}
