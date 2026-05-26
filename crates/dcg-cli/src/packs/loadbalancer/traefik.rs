//! Traefik load balancer pack - protections for destructive Traefik operations.
//!
//! Covers destructive operations:
//! - Stopping/removing Traefik containers
//! - Deleting Traefik configuration files
//! - Traefik API DELETE operations
//! - Removing Traefik `IngressRoute` CRDs

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Traefik load balancer pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "loadbalancer.traefik".to_string(),
        name: "Traefik",
        description: "Protects against destructive Traefik load balancer operations like stopping \
                      containers, deleting config, or API deletions.",
        keywords: &["traefik", "ingressroute"],
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
        // Version and health checks
        safe_pattern!("traefik-version", r"\btraefik\s+version(?=\s|$)"),
        safe_pattern!("traefik-healthcheck", r"\btraefik\s+healthcheck(?=\s|$)"),
        // API GET operations (read-only)
        safe_pattern!(
            "traefik-api-get",
            r"(?i)^(?!(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*\btraefik\b.*\b/api/))curl\b.*(?:-X\s*|--request(?:=|\s+))GET\b.*\btraefik\b.*\b/api/"
        ),
        safe_pattern!(
            "traefik-api-read",
            r"curl\b(?!.*\s(?:-X\s*|--request(?:=|\s+))(?:DELETE|PUT|POST|PATCH)\b).*\btraefik\b.*\b/api/(?:overview|entrypoints|routers|services|middlewares|version|rawdata)"
        ),
        // Docker inspect/logs (read-only)
        safe_pattern!(
            "docker-traefik-inspect",
            r"docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:inspect|logs)\s+.*\btraefik\b"
        ),
        // Kubectl get/describe (read-only)
        safe_pattern!(
            "kubectl-traefik-get",
            r"kubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:get|describe)\s+.*\bingressroute"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Docker container operations
        destructive_pattern!(
            "traefik-docker-stop",
            r"docker\b.*?\s+(?:stop|kill)\s+.*\btraefik\b",
            "Stopping the Traefik container halts all traffic routing.",
            Critical,
            "Stopping or killing the Traefik container immediately halts all HTTP/HTTPS \
             traffic routing. Every service behind this load balancer becomes unreachable \
             until Traefik is restarted.\n\n\
             Check container status first:\n  \
             docker inspect traefik\n\n\
             View logs for issues:\n  \
             docker logs traefik"
        ),
        destructive_pattern!(
            "traefik-docker-rm",
            r"docker\b.*?\s+rm\s+.*\btraefik\b",
            "Removing the Traefik container destroys the load balancer.",
            Critical,
            "Removing the Traefik container deletes it entirely, including any runtime \
             state, Let's Encrypt certificates stored in the container, and dynamic \
             configuration. The container must be recreated from scratch.\n\n\
             Stop without removing:\n  \
             docker stop traefik\n\n\
             Back up certificates first if stored in container volume."
        ),
        destructive_pattern!(
            "traefik-compose-down",
            r"docker[\s-]compose\s+.*\bdown\b.*\btraefik\b",
            "docker-compose down on Traefik stops and removes the load balancer.",
            Critical,
            "Running docker-compose down stops and removes Traefik containers, networks, \
             and optionally volumes. All traffic routing stops and any non-persisted state \
             is lost.\n\n\
             To stop without removing:\n  \
             docker-compose stop traefik\n\n\
             To restart cleanly:\n  \
             docker-compose restart traefik"
        ),
        // Kubernetes operations
        destructive_pattern!(
            "traefik-kubectl-delete-pod",
            r"kubectl\b.*?\s+delete\s+(?:pod|deployment|daemonset)\s+.*\btraefik\b",
            "Deleting Traefik pods/deployments disrupts traffic routing.",
            Critical,
            "Deleting Traefik pods or deployments removes the load balancer from the \
             cluster. If managed by a Deployment, pods will be recreated but with \
             downtime. Deleting the Deployment itself stops all traffic routing until \
             it is redeployed.\n\n\
             Check pod status:\n  \
             kubectl get pods -l app=traefik\n\n\
             Restart pods without deleting:\n  \
             kubectl rollout restart deployment traefik"
        ),
        destructive_pattern!(
            "traefik-kubectl-delete-ingressroute",
            r"kubectl\b.*?\s+delete\s+ingressroute\b",
            "Deleting IngressRoute CRDs removes Traefik routing rules.",
            High,
            "IngressRoute custom resources define how Traefik routes traffic to backend \
             services. Deleting them removes those routing rules, making the associated \
             services unreachable through the load balancer.\n\n\
             List current routes first:\n  \
             kubectl get ingressroute\n\n\
             Describe a route before deleting:\n  \
             kubectl describe ingressroute <name>"
        ),
        // Config file deletion
        destructive_pattern!(
            "traefik-config-delete",
            r"\brm\b.*\btraefik\b.*\.(?:ya?ml|toml)\b",
            "Removing Traefik config files disrupts load balancer configuration.",
            Critical,
            "Deleting Traefik configuration files removes entrypoint definitions, \
             middleware chains, TLS settings, and provider configurations. Traefik \
             will fail to start or lose routing rules on the next reload.\n\n\
             Back up config first:\n  \
             cp traefik.yml traefik.yml.backup\n\n\
             Validate config before changes:\n  \
             traefik healthcheck"
        ),
        // API DELETE operations
        destructive_pattern!(
            "traefik-api-delete",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*\btraefik\b.*\b/api/).*",
            "DELETE operations against Traefik API can remove routing configuration.",
            High,
            "Sending DELETE requests to the Traefik API removes routers, services, or \
             middleware from the running configuration. Depending on the provider, these \
             changes may be permanent or reverted on restart.\n\n\
             Use GET to inspect before deleting:\n  \
             curl -X GET http://traefik:8080/api/overview"
        ),
        // Systemctl/service operations
        destructive_pattern!(
            "traefik-systemctl-stop",
            r"systemctl\b.*?\s+stop\s+traefik(?:\.service)?\b",
            "systemctl stop traefik stops the Traefik service.",
            High,
            "Stopping the Traefik systemd service shuts down the load balancer process. \
             All HTTP/HTTPS traffic routing ceases until the service is restarted.\n\n\
             Check status first:\n  \
             systemctl status traefik\n\n\
             To restart instead:\n  \
             systemctl restart traefik"
        ),
        destructive_pattern!(
            "traefik-service-stop",
            r"service\s+traefik\s+stop\b",
            "service traefik stop stops the Traefik service.",
            High,
            "Stopping Traefik via the legacy service command terminates the load balancer. \
             All traffic routing stops until the service is manually restarted.\n\n\
             Check status first:\n  \
             service traefik status\n\n\
             Prefer systemctl on systemd systems:\n  \
             systemctl status traefik"
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
        assert_eq!(pack.id, "loadbalancer.traefik");
        assert_eq!(pack.name, "Traefik");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"traefik"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "traefik version");
        assert_safe_pattern_matches(&pack, "traefik healthcheck");
        assert_safe_pattern_matches(&pack, "docker inspect traefik");
        assert_safe_pattern_matches(&pack, "docker logs traefik");
        assert_safe_pattern_matches(&pack, "kubectl get ingressroute");
        assert_safe_pattern_matches(&pack, "kubectl describe ingressroute my-route");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "docker stop traefik", "traefik-docker-stop");
        assert_blocks_with_pattern(&pack, "docker kill traefik", "traefik-docker-stop");
        assert_blocks_with_pattern(&pack, "docker rm traefik", "traefik-docker-rm");
        assert_blocks_with_pattern(
            &pack,
            "kubectl delete pod traefik-abc123",
            "traefik-kubectl-delete-pod",
        );
        assert_blocks_with_pattern(
            &pack,
            "kubectl delete ingressroute my-route",
            "traefik-kubectl-delete-ingressroute",
        );
        assert_blocks_with_pattern(
            &pack,
            "rm /etc/traefik/traefik.yml",
            "traefik-config-delete",
        );
        assert_blocks_with_pattern(&pack, "systemctl stop traefik", "traefik-systemctl-stop");
    }

    #[test]
    fn curl_get_safe_pattern_does_not_mask_destructive_api_methods() {
        let pack = create_pack();
        let command = "curl -X GET http://traefik:8080/api/overview \
            -X DELETE http://traefik:8080/api/http/routers/foo";

        assert_no_safe_match(&pack, command);
        assert_blocks_with_pattern(&pack, command, "traefik-api-delete");

        assert_blocks_with_pattern(
            &pack,
            "curl http://traefik:8080/api/http/routers/foo -XDELETE",
            "traefik-api-delete",
        );
    }

    #[test]
    fn traefik_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "docker stop traefik", Severity::Critical);
        assert_blocks_with_severity(&pack, "docker kill traefik", Severity::Critical);
        assert_blocks_with_severity(&pack, "docker rm traefik", Severity::Critical);
        assert_blocks_with_severity(&pack, "docker-compose down traefik", Severity::Critical);
        assert_blocks_with_severity(
            &pack,
            "kubectl delete pod traefik-abc123",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "kubectl delete deployment traefik",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "kubectl delete ingressroute my-route",
            Severity::High,
        );
        assert_blocks_with_severity(&pack, "rm /etc/traefik/traefik.yml", Severity::Critical);
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE http://traefik:8080/api/http/routers/my-router@file",
            Severity::High,
        );
        assert_blocks_with_severity(&pack, "systemctl stop traefik", Severity::High);
        assert_blocks_with_severity(&pack, "service traefik stop", Severity::High);
    }

    #[test]
    fn traefik_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
    }
}
