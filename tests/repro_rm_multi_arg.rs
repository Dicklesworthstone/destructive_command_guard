#[cfg(test)]
mod tests {
    use destructive_command_guard::config::Config;
    use destructive_command_guard::evaluator::evaluate_command;
    use destructive_command_guard::load_default_allowlists;

    #[test]
    fn test_rm_multi_arg_vulnerability() {
        let config = Config::default();
        let compiled_overrides = config.overrides.compile();
        let allowlists = load_default_allowlists();

        // This command deletes /tmp/safe (safe) AND /etc/passwd (destructive!)
        let cmd = "rm -rf /tmp/safe /etc/passwd";

        // We expect this to be DENIED, but I suspect it will be ALLOWED
        let result = evaluate_command(
            cmd,
            &config,
            &["rm"], // Enable rm keywords
            &compiled_overrides,
            &allowlists,
        );

        // If this assertion fails (is_allowed() is true), the vulnerability exists.
        assert!(
            result.is_denied(),
            "Command '{cmd}' should be denied but was allowed!"
        );
    }
}
