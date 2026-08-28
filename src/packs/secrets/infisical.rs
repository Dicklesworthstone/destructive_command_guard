//! Infisical CLI pack - protections for destructive local and remote secret operations.

use crate::destructive_pattern;
use crate::packs::{DestructivePattern, Pack};

/// Create the Infisical pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "secrets.infisical".to_string(),
        name: "Infisical CLI",
        description: "Protects against deleting Infisical secrets, folders, and dynamic-secret \
                      leases, plus resetting local Infisical configuration.",
        keywords: &["infisical"],
        safe_patterns: Vec::new(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "infisical-secrets-delete",
            r"(?i:\binfisical(?:\.exe|\.cmd|\.bat|\.com)?\b)(?:\s+--?\S+(?:\s+\S+)?)*\s+secrets\s+delete\b",
            "infisical secrets delete removes one or more stored secrets.",
            High,
            "Deleting a secret can immediately break applications and automation that depend \
             on its value. Export an inventory of secret names and confirm every consumer \
             before deletion.",
            executables = ["infisical"]
        ),
        destructive_pattern!(
            "infisical-folders-delete",
            r"(?i:\binfisical(?:\.exe|\.cmd|\.bat|\.com)?\b)(?:\s+--?\S+(?:\s+\S+)?)*\s+secrets\s+folders\s+delete\b",
            "infisical secrets folders delete removes a secrets folder.",
            Critical,
            "Deleting a secrets folder can remove or orphan a whole subtree used by multiple \
             applications. List the folder and its consumers before approving deletion.",
            executables = ["infisical"]
        ),
        destructive_pattern!(
            "infisical-dynamic-lease-delete",
            r"(?i:\binfisical(?:\.exe|\.cmd|\.bat|\.com)?\b)(?:\s+--?\S+(?:\s+\S+)?)*\s+dynamic-secrets\s+lease\s+delete\b",
            "infisical dynamic-secrets lease delete revokes a live dynamic-secret lease.",
            High,
            "Deleting a dynamic-secret lease revokes credentials that a running service may \
             still be using. Identify the lease owner and rotate the consumer first.",
            executables = ["infisical"]
        ),
        destructive_pattern!(
            "infisical-reset",
            r"(?i:\binfisical(?:\.exe|\.cmd|\.bat|\.com)?\b)(?:\s+--?\S+(?:\s+\S+)?)*\s+reset\b",
            "infisical reset clears local Infisical-generated configuration data.",
            High,
            "Resetting the CLI removes its generated local configuration and authentication \
             state. Inspect the current configuration and preserve any needed connection \
             details before resetting it.",
            executables = ["infisical"]
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::*;

    #[test]
    fn pack_contract() {
        let pack = create_pack();
        assert_eq!(pack.id, "secrets.infisical");
        assert_eq!(pack.name, "Infisical CLI");
        assert!(pack.keywords.contains(&"infisical"));
        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn destructive_infisical_operations_are_blocked() {
        let pack = create_pack();
        for (command, rule) in [
            (
                "infisical secrets delete STRIPE_API_KEY DOMAIN",
                "infisical-secrets-delete",
            ),
            (
                "infisical --domain=https://example.test secrets delete API_KEY",
                "infisical-secrets-delete",
            ),
            (
                "infisical secrets folders delete --path=/apps --name=legacy",
                "infisical-folders-delete",
            ),
            (
                "infisical dynamic-secrets lease delete lease-id --env=prod",
                "infisical-dynamic-lease-delete",
            ),
            ("infisical reset", "infisical-reset"),
            (r"INFISICAL.EXE reset", "infisical-reset"),
            (
                r"C:\Tools\INFISICAL.EXE secrets delete API_KEY",
                "infisical-secrets-delete",
            ),
        ] {
            assert_blocks_with_pattern(&pack, command, rule);
        }
    }

    #[test]
    fn reads_injection_and_mutation_remain_allowed_without_disclosure_pack() {
        let pack = create_pack();
        for command in [
            "infisical secrets --env=prod --path=/apps",
            "infisical secrets get API_KEY --plain",
            "infisical export --format=json",
            "infisical run --env=prod -- npm start",
            "infisical secrets set API_KEY=new-value",
            "infisical secrets folders get --path=/apps",
            "infisical secrets folders create --path=/apps --name=backend",
        ] {
            assert_no_match(&pack, command);
        }
    }

    #[test]
    fn quoted_or_unrelated_infisical_text_is_not_an_invocation() {
        let pack = create_pack();
        for command in [
            "echo 'infisical reset'",
            "printf '%s' 'infisical secrets delete API_KEY'",
            "command -v infisical",
        ] {
            assert_no_match(&pack, command);
        }
    }
}
