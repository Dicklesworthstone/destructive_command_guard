#[cfg(test)]
mod tests {
    use destructive_command_guard::config::Config;
    use destructive_command_guard::evaluator::evaluate_command;
    use destructive_command_guard::load_default_allowlists;
    use destructive_command_guard::packs::REGISTRY;
    use std::collections::HashSet;

    fn get_evaluator_args() -> (Config, Vec<&'static str>, destructive_command_guard::config::CompiledOverrides, destructive_command_guard::allowlist::LayeredAllowlist) {
        let config = Config::default();
        let mut enabled = HashSet::new();
        enabled.insert("core.git".to_string());
        enabled.insert("core.filesystem".to_string());
        
        let keywords = REGISTRY.collect_enabled_keywords(&enabled);
        let overrides = config.overrides.compile();
        let allowlists = load_default_allowlists();
        
        (config, keywords, overrides, allowlists)
    }

    #[test]
    fn test_substring_false_positive_git() {
        let (config, keywords, overrides, allowlists) = get_evaluator_args();
        
        // "digit" contains "git", but should NOT trigger core.git rules
        let cmd = "digit reset --hard";
        
        let result = evaluate_command(
            cmd,
            &config,
            &keywords,
            &overrides,
            &allowlists
        );
        
        assert!(result.is_allowed(), "digit reset --hard should be allowed, but was blocked: {:?}", result.pattern_info);
    }

    #[test]
    fn test_substring_false_positive_rm() {
        let (config, keywords, overrides, allowlists) = get_evaluator_args();
        
        // "farm" contains "rm", should NOT trigger core.filesystem rules
        let cmd = "farm -rf /";
        
        let result = evaluate_command(
            cmd,
            &config,
            &keywords,
            &overrides,
            &allowlists
        );
        
        assert!(result.is_allowed(), "farm -rf / should be allowed, but was blocked: {:?}", result.pattern_info);
    }

    #[test]
    fn test_relative_path_bypass_git() {
        let (config, keywords, overrides, allowlists) = get_evaluator_args();
        
        // ./git should still be detected as git
        let cmd = "./git reset --hard";
        
        let result = evaluate_command(
            cmd,
            &config,
            &keywords,
            &overrides,
            &allowlists
        );
        
        // This fails if the pattern expects "git" literal without boundary or path handling
        assert!(result.is_denied(), "./git reset --hard should be blocked");
    }

    #[test]
    fn test_relative_path_bypass_rm() {
        let (config, keywords, overrides, allowlists) = get_evaluator_args();
        
        // ./rm should still be detected as rm
        let cmd = "./rm -rf /";
        
        let result = evaluate_command(
            cmd,
            &config,
            &keywords,
            &overrides,
            &allowlists
        );
        
        assert!(result.is_denied(), "./rm -rf / should be blocked");
    }
    
    #[test]
    fn test_custom_bin_path_bypass_git() {
        let (config, keywords, overrides, allowlists) = get_evaluator_args();
        
        // /opt/custom/git (not in bin/)
        let cmd = "/opt/custom/git reset --hard";
        
        let result = evaluate_command(
            cmd,
            &config,
            &keywords,
            &overrides,
            &allowlists
        );
        
        assert!(result.is_denied(), "/opt/custom/git reset --hard should be blocked");
    }

    #[test]
    fn test_hyphenated_false_positive() {
        let (config, keywords, overrides, allowlists) = get_evaluator_args();
        
        // "my-git" contains "git" with a boundary '-' which is not a word char.
        // Quick reject will pass. Regex will match "git reset".
        // This SHOULD be allowed, but likely will be blocked.
        let cmd = "my-git reset --hard";
        
        let result = evaluate_command(
            cmd,
            &config,
            &keywords,
            &overrides,
            &allowlists
        );
        
        assert!(result.is_allowed(), "my-git reset --hard should be allowed (fp), but was blocked: {:?}", result.pattern_info);
    }
}
