//! `HAProxy` load balancer pack - protections for destructive `HAProxy` operations.
//!
//! Covers destructive operations:
//! - Stopping `HAProxy` service
//! - `HAProxy` soft/hard stop signals
//! - Runtime API disable/shutdown commands via socat

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `HAProxy` load balancer pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "loadbalancer.haproxy".to_string(),
        name: "HAProxy",
        description: "Protects against destructive HAProxy load balancer operations like stopping \
                      the service or disabling backends via runtime API.",
        keywords: &["haproxy", "socat"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // Config check
        safe_pattern!("haproxy-config-check", r"\bhaproxy\s+-c\b"),
        // Version info
        safe_pattern!("haproxy-version", r"\bhaproxy\s+-v+\b"),
        // Status check via systemctl/service
        safe_pattern!(
            "systemctl-status-haproxy",
            r"systemctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+status\s+haproxy(?:\.service)?\b"
        ),
        safe_pattern!("service-status-haproxy", r"service\s+haproxy\s+status\b"),
        // Runtime API read-only queries via socat
        safe_pattern!(
            "haproxy-socat-show",
            r#"(?:echo|printf)\s+['"]?show\s+(?:stat|info|servers|backend|pools|sess|errors|table)['"]?\s*\|\s*socat\b"#
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // HAProxy stop signals
        destructive_pattern!(
            "haproxy-soft-stop",
            r"\bhaproxy\s+.*-sf\b",
            "haproxy -sf sends a soft stop signal, terminating the load balancer gracefully."
        ),
        destructive_pattern!(
            "haproxy-hard-stop",
            r"\bhaproxy\s+.*-st\b",
            "haproxy -st sends a hard stop signal, immediately terminating the load balancer."
        ),
        // Systemctl/service stop
        destructive_pattern!(
            "haproxy-systemctl-stop",
            r"systemctl\b.*?\s+stop\s+haproxy(?:\.service)?\b",
            "systemctl stop haproxy stops the HAProxy service."
        ),
        destructive_pattern!(
            "haproxy-service-stop",
            r"service\s+haproxy\s+stop\b",
            "service haproxy stop stops the HAProxy service."
        ),
        // Runtime API destructive commands via socat
        destructive_pattern!(
            "haproxy-socat-disable-server",
            r#"(?:echo|printf)\s+['"]?disable\s+server\b.*\|\s*socat\b"#,
            "Disabling a server via HAProxy runtime API removes it from the load balancer pool."
        ),
        destructive_pattern!(
            "haproxy-socat-shutdown-sessions",
            r#"(?:echo|printf)\s+['"]?shutdown\s+sessions\b.*\|\s*socat\b"#,
            "Shutting down sessions via HAProxy runtime API terminates active connections."
        ),
        destructive_pattern!(
            "haproxy-socat-disable-frontend",
            r#"(?:echo|printf)\s+['"]?disable\s+frontend\b.*\|\s*socat\b"#,
            "Disabling a frontend via HAProxy runtime API stops accepting new connections."
        ),
        destructive_pattern!(
            "haproxy-socat-shutdown-frontend",
            r#"(?:echo|printf)\s+['"]?shutdown\s+frontend\b.*\|\s*socat\b"#,
            "Shutting down a frontend via HAProxy runtime API terminates it immediately."
        ),
        // Config file deletion
        destructive_pattern!(
            "haproxy-config-delete",
            r#"\brm\b.*\s+['"]?/etc/haproxy(?:/|\b)"#,
            "Removing files from /etc/haproxy deletes HAProxy configuration."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();
        assert_eq!(pack.id, "loadbalancer.haproxy");
        assert_eq!(pack.name, "HAProxy");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"haproxy"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "haproxy -c -f /etc/haproxy/haproxy.cfg");
        assert_safe_pattern_matches(&pack, "haproxy -v");
        assert_safe_pattern_matches(&pack, "haproxy -vv");
        assert_safe_pattern_matches(&pack, "systemctl status haproxy");
        assert_safe_pattern_matches(&pack, "service haproxy status");
        assert_safe_pattern_matches(
            &pack,
            "echo 'show stat' | socat stdio /var/run/haproxy.sock",
        );
        assert_safe_pattern_matches(
            &pack,
            "echo 'show info' | socat stdio /var/run/haproxy.sock",
        );
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "haproxy -sf $(cat /run/haproxy.pid)",
            "haproxy-soft-stop",
        );
        assert_blocks_with_pattern(
            &pack,
            "haproxy -st $(cat /run/haproxy.pid)",
            "haproxy-hard-stop",
        );
        assert_blocks_with_pattern(&pack, "systemctl stop haproxy", "haproxy-systemctl-stop");
        assert_blocks_with_pattern(&pack, "service haproxy stop", "haproxy-service-stop");
        assert_blocks_with_pattern(
            &pack,
            "echo 'disable server backend/web1' | socat stdio /var/run/haproxy.sock",
            "haproxy-socat-disable-server",
        );
        assert_blocks_with_pattern(
            &pack,
            "echo 'shutdown sessions server backend/web1' | socat stdio /var/run/haproxy.sock",
            "haproxy-socat-shutdown-sessions",
        );
        assert_blocks_with_pattern(
            &pack,
            "rm /etc/haproxy/haproxy.cfg",
            "haproxy-config-delete",
        );
    }

    #[test]
    fn haproxy_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "haproxy -sf $(cat /run/haproxy.pid)", Severity::High);
        assert_blocks_with_severity(&pack, "haproxy -st $(cat /run/haproxy.pid)", Severity::High);
        assert_blocks_with_severity(&pack, "systemctl stop haproxy", Severity::High);
        assert_blocks_with_severity(&pack, "service haproxy stop", Severity::High);
        assert_blocks_with_severity(
            &pack,
            "echo 'disable server backend/web1' | socat stdio /var/run/haproxy.sock",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "echo 'shutdown sessions server backend/web1' | socat stdio /var/run/haproxy.sock",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "echo 'disable frontend http' | socat stdio /var/run/haproxy.sock",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "echo 'shutdown frontend http' | socat stdio /var/run/haproxy.sock",
            Severity::High,
        );
        assert_blocks_with_severity(&pack, "rm /etc/haproxy/haproxy.cfg", Severity::High);
    }

    #[test]
    fn haproxy_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
    }
}
