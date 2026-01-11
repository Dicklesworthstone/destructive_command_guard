//! Generic DNS tooling pack - protections for common DNS utilities.
//!
//! Covers destructive or risky operations:
//! - nsupdate delete commands
//! - nsupdate -l local updates
//! - dig AXFR/IXFR zone transfers

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the generic DNS tools pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "dns.generic".to_string(),
        name: "Generic DNS Tools",
        description: "Protects against destructive or risky DNS tooling usage (nsupdate deletes, zone transfers).",
        keywords: &["nsupdate", "dig", "host", "nslookup"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!("dns-dig-safe", r"\bdig\b(?!.*\baxfr\b)(?!.*\bixfr\b)"),
        safe_pattern!("dns-host-safe", r"\bhost\b"),
        safe_pattern!("dns-nslookup-safe", r"\bnslookup\b"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "dns-nsupdate-delete",
            r"(?:\bnsupdate\b.*\bdelete\b|\bdelete\b.*\|\s*\bnsupdate\b)",
            "nsupdate delete commands remove DNS records."
        ),
        destructive_pattern!(
            "dns-nsupdate-local",
            r"\bnsupdate\b.*\s-l\b",
            "nsupdate -l applies local updates which can modify DNS records."
        ),
        destructive_pattern!(
            "dns-dig-zone-transfer",
            r"\bdig\b.*\b(?:axfr|ixfr)\b",
            "dig AXFR/IXFR zone transfers can exfiltrate full zone data."
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
        assert_eq!(pack.id, "dns.generic");
        assert_eq!(pack.name, "Generic DNS Tools");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"nsupdate"));
        assert!(pack.keywords.contains(&"dig"));
        assert!(pack.keywords.contains(&"host"));
        assert!(pack.keywords.contains(&"nslookup"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "dig example.com");
        assert_safe_pattern_matches(&pack, "dig +short example.com");
        assert_safe_pattern_matches(&pack, "host example.com");
        assert_safe_pattern_matches(&pack, "nslookup example.com");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "echo 'delete example.com' | nsupdate",
            "dns-nsupdate-delete",
        );
        assert_blocks_with_pattern(&pack, "nsupdate -l", "dns-nsupdate-local");
        assert_blocks_with_pattern(&pack, "dig axfr example.com", "dns-dig-zone-transfer");
    }
}
