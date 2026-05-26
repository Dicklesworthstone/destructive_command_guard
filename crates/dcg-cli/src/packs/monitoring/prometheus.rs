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
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
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
            r"(?i)^(?!(?=.*(?:-X\s*|--request(?:=|\s+))(?:POST|DELETE)\b)(?=.*(?:/api/v1/admin/tsdb/delete_series\b|/api/(?:dashboards|datasources|alert-notifications)/)))curl\s+.*(?:-X\s*|--request(?:=|\s+))GET\b.*\/api\/v1\/"
        ),
        safe_pattern!(
            "grafana-api-get",
            r"(?i)^(?!(?=.*(?:-X\s*|--request(?:=|\s+))(?:POST|DELETE)\b)(?=.*(?:/api/v1/admin/tsdb/delete_series\b|/api/(?:dashboards|datasources|alert-notifications)/)))curl\s+.*(?:-X\s*|--request(?:=|\s+))GET\b.*\/api\/"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "prometheus-rules-file-delete",
            r#"\brm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:(?:-f|--force)\s+)?['"]?(?:/etc/prometheus/(?:rules\.d|rules)/\S+|/etc/prometheus/(?:prometheus|rules)\.(?:ya?ml))['"]?(?:\s|$)"#,
            "Deleting Prometheus rule/config files can break alerting and monitoring coverage.",
            Critical,
            "Deleting Prometheus configuration or rule files stops alerting for the defined \
             conditions. After Prometheus reloads, those alerts will no longer fire, \
             potentially leaving critical conditions unmonitored.\n\n\
             Safer alternatives:\n\
             - promtool check rules: Validate rule files before changes\n\
             - Back up files before deletion\n\
             - Use version control (git) for rule files"
        ),
        destructive_pattern!(
            "prometheus-tsdb-delete-series",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))POST\b)(?=.*\/api\/v1\/admin\/tsdb\/delete_series\b).*",
            "Prometheus TSDB delete_series permanently deletes time series data.",
            Critical,
            "The delete_series admin endpoint permanently removes time series data matching \
             the specified selectors. This data cannot be recovered. Historical metrics \
             for the deleted series will show gaps.\n\n\
             Safer alternatives:\n\
             - Query the series first to verify what will be deleted\n\
             - Use retention policies instead of manual deletion\n\
             - Take a TSDB snapshot before deletion"
        ),
        destructive_pattern!(
            "kubectl-delete-prometheus-operator-resources",
            r"\bkubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+delete\s+(?:prometheusrules?|servicemonitors?|podmonitors?)(?:\.monitoring\.coreos\.com)?\b",
            "kubectl delete of Prometheus Operator resources (PrometheusRule/ServiceMonitor/PodMonitor) removes alerting/target configuration.",
            High,
            "Deleting Prometheus Operator CRDs removes alerting rules or scrape targets. \
             The Prometheus Operator will update Prometheus configuration, potentially \
             leaving services unmonitored.\n\n\
             Safer alternatives:\n\
             - kubectl get to review the resource first\n\
             - kubectl describe to see what it configures\n\
             - Export YAML before deletion: kubectl get -o yaml"
        ),
        destructive_pattern!(
            "grafana-cli-plugins-uninstall",
            r"\bgrafana-cli\b(?:\s+--?\S+(?:\s+\S+)?)*\s+plugins\s+uninstall\b",
            "grafana-cli plugins uninstall removes a Grafana plugin, potentially breaking dashboards.",
            High,
            "Uninstalling a Grafana plugin breaks all dashboards using that plugin's panels \
             or datasources. Users will see error messages where those panels were.\n\n\
             Safer alternatives:\n\
             - grafana-cli plugins list: Review installed plugins first\n\
             - Check which dashboards use the plugin before removal\n\
             - Update the plugin instead of uninstalling"
        ),
        destructive_pattern!(
            "grafana-api-delete-dashboard",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*\/api\/dashboards\/).*",
            "Grafana API DELETE /api/dashboards/... deletes dashboards.",
            High,
            "Deleting a Grafana dashboard removes all panels, queries, and configuration. \
             Teams relying on this dashboard for monitoring will lose visibility.\n\n\
             Safer alternatives:\n\
             - GET /api/dashboards/uid/<uid> to export JSON first\n\
             - Use Grafana provisioning for version-controlled dashboards\n\
             - Use dashboard versioning in Grafana to restore later"
        ),
        destructive_pattern!(
            "grafana-api-delete-datasource",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*\/api\/datasources\/).*",
            "Grafana API DELETE /api/datasources/... deletes datasources.",
            High,
            "Deleting a datasource breaks all dashboards and alerts using it. Panels will \
             show 'Data source not found' errors, and alerting queries will fail.\n\n\
             Safer alternatives:\n\
             - GET the datasource first to verify the ID\n\
             - Check which dashboards use this datasource\n\
             - Use Grafana provisioning for datasource-as-code"
        ),
        destructive_pattern!(
            "grafana-api-delete-alert-notification",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*\/api\/alert-notifications\/).*",
            "Grafana API DELETE /api/alert-notifications/... deletes alert notification channels.",
            High,
            "Deleting a notification channel stops alert delivery to that destination. \
             Alerts using this channel will fire but notifications won't be sent.\n\n\
             Safer alternatives:\n\
             - GET the notification channel first to verify the ID\n\
             - Check which alerts use this notification channel\n\
             - Disable the channel instead of deleting"
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
        assert_safe_pattern_matches(
            &pack,
            "curl -XGET http://localhost:9090/api/v1/query?query=up",
        );
        assert_safe_pattern_matches(&pack, "curl -X GET http://grafana.local/api/search");
        assert_safe_pattern_matches(&pack, "curl --request=GET http://grafana.local/api/search");
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
            "curl -XPOST http://localhost:9090/api/v1/admin/tsdb/delete_series?match[]=up",
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
            "curl http://grafana.local/api/dashboards/uid/abc --request=DELETE",
            "grafana-api-delete-dashboard",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE http://grafana.local/api/datasources/1",
            "grafana-api-delete-datasource",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl http://grafana.local/api/datasources/1 -XDELETE",
            "grafana-api-delete-datasource",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE http://grafana.local/api/alert-notifications/1",
            "grafana-api-delete-alert-notification",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl --request=DELETE http://grafana.local/api/alert-notifications/1",
            "grafana-api-delete-alert-notification",
        );
    }

    #[test]
    fn curl_get_safe_patterns_do_not_mask_destructive_api_methods() {
        let pack = create_pack();

        let prometheus_delete_series = "curl -X GET http://localhost:9090/api/v1/query?query=up \
            -X POST http://localhost:9090/api/v1/admin/tsdb/delete_series?match[]=up";
        assert_no_safe_match(&pack, prometheus_delete_series);
        assert_blocks_with_pattern(
            &pack,
            prometheus_delete_series,
            "prometheus-tsdb-delete-series",
        );

        let grafana_delete_dashboard = "curl -X GET http://grafana.local/api/search \
            -X DELETE http://grafana.local/api/dashboards/uid/abc";
        assert_no_safe_match(&pack, grafana_delete_dashboard);
        assert_blocks_with_pattern(
            &pack,
            grafana_delete_dashboard,
            "grafana-api-delete-dashboard",
        );

        let grafana_delete_datasource = "curl --request GET http://grafana.local/api/search \
            --request DELETE http://grafana.local/api/datasources/1";
        assert_no_safe_match(&pack, grafana_delete_datasource);
        assert_blocks_with_pattern(
            &pack,
            grafana_delete_datasource,
            "grafana-api-delete-datasource",
        );

        let grafana_delete_dashboard_url_first = "curl -X GET http://grafana.local/api/search \
            http://grafana.local/api/dashboards/uid/abc -X DELETE";
        assert_no_safe_match(&pack, grafana_delete_dashboard_url_first);
        assert_blocks_with_pattern(
            &pack,
            grafana_delete_dashboard_url_first,
            "grafana-api-delete-dashboard",
        );
    }

    #[test]
    fn curl_destructive_api_patterns_do_not_require_method_before_url() {
        let pack = create_pack();

        assert_blocks_with_pattern(
            &pack,
            "curl http://localhost:9090/api/v1/admin/tsdb/delete_series?match[]=up -X POST",
            "prometheus-tsdb-delete-series",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl http://grafana.local/api/dashboards/uid/abc -X DELETE",
            "grafana-api-delete-dashboard",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl http://grafana.local/api/datasources/1 --request DELETE",
            "grafana-api-delete-datasource",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl http://grafana.local/api/alert-notifications/1 --request DELETE",
            "grafana-api-delete-alert-notification",
        );
    }

    #[test]
    fn quoted_prometheus_path_does_not_bypass() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "rm \"/etc/prometheus/rules.d/alerts.yml\"",
            "prometheus-rules-file-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "rm -f '/etc/prometheus/prometheus.yml'",
            "prometheus-rules-file-delete",
        );
    }

    #[test]
    fn prometheus_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(
            &pack,
            "rm /etc/prometheus/rules.d/alerts.yml",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "curl -X POST http://localhost:9090/api/v1/admin/tsdb/delete_series?match[]=up",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "kubectl delete prometheusrule example -n monitoring",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "grafana-cli plugins uninstall grafana-piechart-panel",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE http://grafana.local/api/dashboards/uid/abc",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE http://grafana.local/api/datasources/1",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE http://grafana.local/api/alert-notifications/1",
            Severity::High,
        );
    }

    #[test]
    fn prometheus_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "echo hello");
        assert_no_match(&pack, "cargo build");
    }
}
