//! `Prometheus`/`Grafana` monitoring pack - protections for destructive observability operations.
//!
//! Covers destructive CLI/API operations:
//! - Prometheus TSDB admin delete-series endpoint
//! - Deleting Prometheus rule/config files under `/etc/prometheus`
//! - Grafana API DELETE for dashboards/datasources/alert-notifications
//! - `grafana-cli plugins uninstall`
//! - `kubectl delete` for Prometheus Operator resources (ServiceMonitor/PodMonitor/PrometheusRule)

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `Prometheus`/`Grafana` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "monitoring.prometheus".to_string(),
        name: "Prometheus/Grafana",
        description: "Protects against destructive Prometheus/Grafana operations like deleting time series \
                      data or dashboards/datasources.",
        keywords: &[
            "promtool",
            "grafana-cli",
            "/api/v1/admin/tsdb/delete_series",
            "delete_series",
            "/api/dashboards",
            "/api/datasources",
            "/api/alert-notifications",
            "/etc/prometheus",
            "rules.d",
            "prometheusrule",
            "servicemonitor",
            "podmonitor",
        ],
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
            "promtool-check-rules",
            r"\bpromtool\b(?:\s+--?\S+(?:\s+\S+)?)*\s+check\s+rules\b"
        ),
        safe_pattern!(
            "promtool-query",
            r"\bpromtool\b(?:\s+--?\S+(?:\s+\S+)?)*\s+query\b"
        ),
        safe_pattern!(
            "prometheus-api-get",
            r"(?i)curl\s+.*(?:-X|--request)\s+GET\b.*\/api\/v1\/"
        ),
        safe_pattern!(
            "grafana-api-get",
            r"(?i)curl\s+.*(?:-X|--request)\s+GET\b.*\/api\/"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "prometheus-rules-file-delete",
            r"\brm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:(?:-f|--force)\s+)?(?:/etc/prometheus/(?:rules\.d|rules)/\S+|/etc/prometheus/(?:prometheus|rules)\.(?:ya?ml))(?:\s|$)",
            "Deleting Prometheus rule/config files can break alerting and monitoring coverage."
        ),
        destructive_pattern!(
            "prometheus-tsdb-delete-series",
            r"(?i)curl\s+.*(?:-X|--request)\s+POST\b.*\/api\/v1\/admin\/tsdb\/delete_series\b",
            "Prometheus TSDB delete_series permanently deletes time series data."
        ),
        destructive_pattern!(
            "kubectl-delete-prometheus-operator-resources",
            r"\bkubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+delete\s+(?:prometheusrules?|servicemonitors?|podmonitors?)(?:\.monitoring\.coreos\.com)?\b",
            "kubectl delete of Prometheus Operator resources (PrometheusRule/ServiceMonitor/PodMonitor) removes alerting/target configuration."
        ),
        destructive_pattern!(
            "grafana-cli-plugins-uninstall",
            r"\bgrafana-cli\b(?:\s+--?\S+(?:\s+\S+)?)*\s+plugins\s+uninstall\b",
            "grafana-cli plugins uninstall removes a Grafana plugin, potentially breaking dashboards."
        ),
        destructive_pattern!(
            "grafana-api-delete-dashboard",
            r"(?i)curl\s+.*(?:-X|--request)\s+DELETE\b.*\/api\/dashboards\/",
            "Grafana API DELETE /api/dashboards/... deletes dashboards."
        ),
        destructive_pattern!(
            "grafana-api-delete-datasource",
            r"(?i)curl\s+.*(?:-X|--request)\s+DELETE\b.*\/api\/datasources\/",
            "Grafana API DELETE /api/datasources/... deletes datasources."
        ),
        destructive_pattern!(
            "grafana-api-delete-alert-notification",
            r"(?i)curl\s+.*(?:-X|--request)\s+DELETE\b.*\/api\/alert-notifications\/",
            "Grafana API DELETE /api/alert-notifications/... deletes alert notification channels."
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
        assert_eq!(pack.id, "monitoring.prometheus");
        assert_eq!(pack.name, "Prometheus/Grafana");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"promtool"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "promtool check rules /etc/prometheus/rules.yml");
        assert_safe_pattern_matches(&pack, "promtool query instant http://localhost:9090 up");
        assert_safe_pattern_matches(
            &pack,
            "curl -X GET http://localhost:9090/api/v1/query?query=up",
        );
        assert_safe_pattern_matches(&pack, "curl -X GET http://grafana.local/api/search");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "rm /etc/prometheus/rules.d/alerts.yml",
            "prometheus-rules-file-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X POST http://localhost:9090/api/v1/admin/tsdb/delete_series?match[]=up",
            "prometheus-tsdb-delete-series",
        );
        assert_blocks_with_pattern(
            &pack,
            "kubectl delete prometheusrule example -n monitoring",
            "kubectl-delete-prometheus-operator-resources",
        );
        assert_blocks_with_pattern(
            &pack,
            "grafana-cli plugins uninstall grafana-piechart-panel",
            "grafana-cli-plugins-uninstall",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE http://grafana.local/api/dashboards/uid/abc",
            "grafana-api-delete-dashboard",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE http://grafana.local/api/datasources/1",
            "grafana-api-delete-datasource",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE http://grafana.local/api/alert-notifications/1",
            "grafana-api-delete-alert-notification",
        );
    }
}
