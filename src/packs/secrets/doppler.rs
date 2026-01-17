//! `Doppler` CLI pack - protections for destructive secrets operations.
//!
//! Blocks delete commands that remove secrets, configs, environments, or projects.

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Doppler pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "secrets.doppler".to_string(),
        name: "Doppler CLI",
        description: "Protects against destructive Doppler CLI operations like deleting secrets, \
                      configs, environments, or projects.",
        keywords: &["doppler"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!(
            "doppler-secrets-get",
            r"doppler(?:\s+--?\S+(?:\s+\S+)?)*\s+secrets\s+get\b"
        ),
        safe_pattern!(
            "doppler-secrets-list",
            r"doppler(?:\s+--?\S+(?:\s+\S+)?)*\s+secrets\s+list\b"
        ),
        safe_pattern!("doppler-run", r"doppler(?:\s+--?\S+(?:\s+\S+)?)*\s+run\b"),
        safe_pattern!(
            "doppler-configure",
            r"doppler(?:\s+--?\S+(?:\s+\S+)?)*\s+configure\b"
        ),
        safe_pattern!(
            "doppler-setup",
            r"doppler(?:\s+--?\S+(?:\s+\S+)?)*\s+setup\b"
        ),
        safe_pattern!(
            "doppler-projects-list",
            r"doppler(?:\s+--?\S+(?:\s+\S+)?)*\s+projects\s+list\b"
        ),
        safe_pattern!(
            "doppler-environments-list",
            r"doppler(?:\s+--?\S+(?:\s+\S+)?)*\s+environments\s+list\b"
        ),
        safe_pattern!(
            "doppler-configs-list",
            r"doppler(?:\s+--?\S+(?:\s+\S+)?)*\s+configs\s+list\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "doppler-secrets-delete",
            r"doppler(?:\s+--?\S+(?:\s+\S+)?)*\s+secrets\s+delete\b",
            "doppler secrets delete removes secrets."
        ),
        destructive_pattern!(
            "doppler-projects-delete",
            r"doppler(?:\s+--?\S+(?:\s+\S+)?)*\s+projects\s+delete\b",
            "doppler projects delete removes a project."
        ),
        destructive_pattern!(
            "doppler-environments-delete",
            r"doppler(?:\s+--?\S+(?:\s+\S+)?)*\s+environments\s+delete\b",
            "doppler environments delete removes an environment."
        ),
        destructive_pattern!(
            "doppler-configs-delete",
            r"doppler(?:\s+--?\S+(?:\s+\S+)?)*\s+configs\s+delete\b",
            "doppler configs delete removes a config."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::*;

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();
        assert_eq!(pack.id, "secrets.doppler");
        assert_eq!(pack.name, "Doppler CLI");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"doppler"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn test_secrets_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "doppler secrets delete DATABASE_URL",
            "doppler-secrets-delete",
        );
        assert_blocks(
            &pack,
            "doppler secrets delete API_KEY --project backend --config prod --yes",
            "secrets delete",
        );
    }

    #[test]
    fn test_configs_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "doppler configs delete dev",
            "doppler-configs-delete",
        );
        assert_blocks(
            &pack,
            "doppler configs delete prod --project backend --yes",
            "configs delete",
        );
    }

    #[test]
    fn test_projects_envs_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "doppler projects delete backend --yes",
            "doppler-projects-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "doppler environments delete dev",
            "doppler-environments-delete",
        );
    }

    #[test]
    fn test_safe_commands_allowed() {
        let pack = create_pack();
        assert_allows(&pack, "doppler secrets get DATABASE_URL");
        assert_allows(&pack, "doppler secrets list");
        assert_allows(&pack, "doppler run");
        assert_allows(&pack, "doppler configure");
        assert_allows(&pack, "doppler setup");
        assert_allows(&pack, "doppler projects list");
        assert_allows(&pack, "doppler environments list");
        assert_allows(&pack, "doppler configs list");
    }
}
