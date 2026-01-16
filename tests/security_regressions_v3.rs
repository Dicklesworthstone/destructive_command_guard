#[cfg(test)]
mod tests {
    use destructive_command_guard::config::Config;
    use destructive_command_guard::evaluator::evaluate_command;
    use destructive_command_guard::load_default_allowlists;
    use destructive_command_guard::packs::REGISTRY;

    fn get_eval_components() -> (
        Config,
        Vec<&'static str>,
        destructive_command_guard::config::CompiledOverrides,
        destructive_command_guard::allowlist::LayeredAllowlist,
    ) {
        let config = Config::default();
        let enabled_packs = config.enabled_pack_ids();
        let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
        let compiled = config.overrides.compile();
        let allowlists = load_default_allowlists();
        (config, enabled_keywords, compiled, allowlists)
    }

    #[test]
    fn test_heredoc_backslash_delimiter_bypass() {
        let (config, keywords, compiled, allowlists) = get_eval_components();

        // This uses backslash escaping for the delimiter, which is valid in bash
        // and behaves like a quoted delimiter (no expansion).
        // If the heredoc extractor regex doesn't support this, it will be missed.
        let cmd = r"
cat <<\EOF
rm -rf /
EOF
";
        let result = evaluate_command(cmd, &config, &keywords, &compiled, &allowlists);
        assert!(
            result.is_denied(),
            "Should block heredoc with backslash-escaped delimiter: {cmd}"
        );
    }

    #[test]
    fn test_command_internal_escape_bypass() {
        let (config, keywords, compiled, allowlists) = get_eval_components();

        // Bash treats "g\it" exactly like "git".
        // If normalization doesn't handle this, regexes looking for "\bgit\b" will fail.
        let cmd = r"g\it reset --hard";
        let result = evaluate_command(cmd, &config, &keywords, &compiled, &allowlists);
        assert!(
            result.is_denied(),
            "Should block command with internal backslash escaping: {cmd}"
        );
    }

    #[test]
    fn test_command_mixed_quoting_bypass() {
        let (config, keywords, compiled, allowlists) = get_eval_components();

        // Bash treats "g'i't" exactly like "git".
        let cmd = r"g'i't reset --hard";
        let result = evaluate_command(cmd, &config, &keywords, &compiled, &allowlists);
        assert!(
            result.is_denied(),
            "Should block command with mixed quoting: {cmd}"
        );
    }
}
