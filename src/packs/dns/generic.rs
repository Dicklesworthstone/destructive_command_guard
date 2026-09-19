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
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!("dns-dig-safe", r"\bdig\b(?!.*(?i:\b(?:axfr|ixfr)\b))"),
        // `host` and `nslookup` are read-only lookups, but only when they are
        // what runs. As bare words they matched anywhere in the segment, and a
        // safe match short-circuits the pack: `dig axfr example.com @host` was
        // allowed while `dig axfr example.com` warned on
        // `dns-dig-zone-transfer`. `host` is an ordinary enough word that this
        // is as easy to hit by accident as deliberately (#448).
        safe_pattern!(
            "dns-host-safe",
            r"^\s*(?:\w+=\S*\s+)*(?:sudo\s+(?:-\S+\s+)*)?(?:\S*/)?host\b"
        ),
        safe_pattern!(
            "dns-nslookup-safe",
            r"^\s*(?:\w+=\S*\s+)*(?:sudo\s+(?:-\S+\s+)*)?(?:\S*/)?nslookup\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Evaluated explicitly by the bounded indirect-input data-flow pass.
        // The regex is intentionally unsatisfiable so ordinary command
        // matching cannot manufacture this finding.
        destructive_pattern!(
            "stdin-unverified",
            r"(?!)",
            "nsupdate receives indirect input that dcg cannot statically verify.",
            High,
            "Materialize and review the exact nsupdate commands before piping, redirecting, or loading them into the client."
        ),
        destructive_pattern!(
            "dns-nsupdate-delete",
            r"(?:\bnsupdate\b.*\bdelete\b|\bdelete\b.*\|\s*\bnsupdate\b)",
            "nsupdate delete commands remove DNS records.",
            High,
            "nsupdate delete removes DNS records from the authoritative server using \
             dynamic DNS updates (RFC 2136). Changes take effect immediately and can \
             break services relying on those records.\n\n\
             Safer alternatives:\n\
             - Test in a non-production zone first\n\
             - Use 'prereq' commands to verify record state before delete\n\
             - Keep backup of zone file or export current records"
        ),
        destructive_pattern!(
            "dns-nsupdate-local",
            r"\bnsupdate\b.*\s-l\b",
            "nsupdate -l applies local updates which can modify DNS records.",
            Medium,
            "nsupdate -l uses local (loopback) TSIG authentication, allowing DNS \
             modifications without network credentials. This is convenient for local \
             testing but can accidentally modify production DNS if run on the wrong \
             server.\n\n\
             Safer alternatives:\n\
             - Verify you are on the intended server before running\n\
             - Use explicit server and key options for clarity\n\
             - Test changes with 'show' before 'send'"
        ),
        destructive_pattern!(
            "dns-dig-zone-transfer",
            r"(?i:\bdig\b.*\b(?:axfr|ixfr)\b)",
            "dig AXFR/IXFR zone transfers can exfiltrate full zone data.",
            Medium,
            "Zone transfers (AXFR/IXFR) download complete DNS zone data, revealing all \
             hostnames, internal IPs, and infrastructure topology. This information aids \
             reconnaissance for attacks. Most zones should restrict transfers to known \
             secondary servers.\n\n\
             Safer alternatives:\n\
             - Use standard dig queries for specific records\n\
             - Request zone transfer permissions through proper channels\n\
             - Check if zone transfer is authorized for your IP"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn lookup_tool_names_in_argument_data_do_not_disarm_the_pack_issue_448() {
        // `host` is an ordinary word, and as a bare safe pattern it matched
        // anywhere in the segment. Measured against v0.14.4:
        // `dig axfr example.com @host` was allowed while `dig axfr example.com`
        // matched `dns-dig-zone-transfer`.
        let pack = create_pack();
        for command in [
            "dig axfr example.com @host",
            "dig axfr example.com @nslookup",
        ] {
            assert!(
                !pack.matches_safe(command),
                "{command:?} must not match a safe pattern: the lookup tool \
                 name is argument data, not the command being run"
            );
            assert!(
                pack.check(command).is_some(),
                "{command:?} must still match the zone-transfer rule"
            );
        }
    }

    #[test]
    fn plain_lookups_stay_allowed_issue_448() {
        let pack = create_pack();
        for command in [
            "host example.com",
            "sudo host -t MX example.com",
            "/usr/bin/host example.com 8.8.8.8",
            "nslookup example.com",
            "LC_ALL=C nslookup example.com",
        ] {
            assert!(
                pack.matches_safe(command) || pack.check(command).is_none(),
                "{command:?} is a read-only lookup and must not be blocked"
            );
        }
    }

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
            "echo 'update delete example.com A' | nsupdate",
            "dns-nsupdate-delete",
        );
        assert_blocks_with_pattern(&pack, "nsupdate -l", "dns-nsupdate-local");
        assert_blocks_with_pattern(&pack, "dig axfr example.com", "dns-dig-zone-transfer");
        assert_blocks_with_pattern(&pack, "dig AXFR example.com", "dns-dig-zone-transfer");
    }

    #[test]
    fn generic_blocks_each_destructive_pattern() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "echo 'update delete example.com A' | nsupdate",
            "nsupdate delete commands remove DNS records",
        );
        assert_blocks(
            &pack,
            "echo 'update delete example.com A' | nsupdate",
            "nsupdate delete commands remove DNS records",
        );
        assert_blocks(
            &pack,
            "nsupdate -l",
            "nsupdate -l applies local updates which can modify DNS records",
        );
        assert_blocks(
            &pack,
            "nsupdate -l /tmp/update.txt",
            "nsupdate -l applies local updates which can modify DNS records",
        );
        assert_blocks(
            &pack,
            "dig axfr example.com",
            "dig AXFR/IXFR zone transfers can exfiltrate full zone data",
        );
        assert_blocks(
            &pack,
            "dig AXFR example.com",
            "dig AXFR/IXFR zone transfers can exfiltrate full zone data",
        );
        assert_blocks(
            &pack,
            "dig ixfr=12345 example.com",
            "dig AXFR/IXFR zone transfers can exfiltrate full zone data",
        );
        assert_blocks(
            &pack,
            "dig IXFR=12345 example.com",
            "dig AXFR/IXFR zone transfers can exfiltrate full zone data",
        );
    }

    #[test]
    fn generic_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(
            &pack,
            "echo 'update delete example.com A' | nsupdate",
            Severity::High,
        );
        assert_blocks_with_severity(&pack, "nsupdate -l", Severity::Medium);
        assert_blocks_with_severity(&pack, "dig axfr example.com", Severity::Medium);
        assert_blocks_with_severity(&pack, "dig AXFR example.com", Severity::Medium);
    }

    #[test]
    fn generic_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "dig example.com");
        assert_safe_pattern_matches(&pack, "dig +short example.com");
        assert_safe_pattern_matches(&pack, "dig +trace example.com");
        assert_safe_pattern_matches(&pack, "dig example.com MX");
        assert_safe_pattern_matches(&pack, "host example.com");
        assert_safe_pattern_matches(&pack, "host -t MX example.com");
        assert_safe_pattern_matches(&pack, "nslookup example.com");
        assert_safe_pattern_matches(&pack, "nslookup -type=A example.com");
    }

    #[test]
    fn generic_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "docker ps");
    }
}
