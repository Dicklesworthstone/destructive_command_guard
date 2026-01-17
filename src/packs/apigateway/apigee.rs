//! Google Apigee API Gateway pack - protections for destructive Apigee operations.
//!
//! Covers destructive operations for:
//! - gcloud apigee CLI (`gcloud apigee apis delete`, etc.)
//! - apigeecli tool (`apigeecli apis delete`, etc.)

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Google Apigee API Gateway pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "apigateway.apigee".to_string(),
        name: "Google Apigee",
        description: "Protects against destructive Google Apigee CLI and apigeecli operations.",
        keywords: &["apigee", "apigeecli"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // gcloud apigee - list/describe operations
        safe_pattern!(
            "gcloud-apigee-apis-list",
            r"gcloud\s+apigee\s+apis\s+list\b"
        ),
        safe_pattern!(
            "gcloud-apigee-apis-describe",
            r"gcloud\s+apigee\s+apis\s+describe\b"
        ),
        safe_pattern!(
            "gcloud-apigee-environments-list",
            r"gcloud\s+apigee\s+environments\s+list\b"
        ),
        safe_pattern!(
            "gcloud-apigee-environments-describe",
            r"gcloud\s+apigee\s+environments\s+describe\b"
        ),
        safe_pattern!(
            "gcloud-apigee-developers-list",
            r"gcloud\s+apigee\s+developers\s+list\b"
        ),
        safe_pattern!(
            "gcloud-apigee-developers-describe",
            r"gcloud\s+apigee\s+developers\s+describe\b"
        ),
        safe_pattern!(
            "gcloud-apigee-products-list",
            r"gcloud\s+apigee\s+products\s+list\b"
        ),
        safe_pattern!(
            "gcloud-apigee-products-describe",
            r"gcloud\s+apigee\s+products\s+describe\b"
        ),
        safe_pattern!(
            "gcloud-apigee-organizations-list",
            r"gcloud\s+apigee\s+organizations\s+list\b"
        ),
        safe_pattern!(
            "gcloud-apigee-organizations-describe",
            r"gcloud\s+apigee\s+organizations\s+describe\b"
        ),
        safe_pattern!(
            "gcloud-apigee-deployments-list",
            r"gcloud\s+apigee\s+deployments\s+list\b"
        ),
        safe_pattern!(
            "gcloud-apigee-deployments-describe",
            r"gcloud\s+apigee\s+deployments\s+describe\b"
        ),
        // apigeecli - list operations
        safe_pattern!("apigeecli-apis-list", r"apigeecli\s+apis\s+list\b"),
        safe_pattern!("apigeecli-apis-get", r"apigeecli\s+apis\s+get\b"),
        safe_pattern!("apigeecli-products-list", r"apigeecli\s+products\s+list\b"),
        safe_pattern!("apigeecli-products-get", r"apigeecli\s+products\s+get\b"),
        safe_pattern!(
            "apigeecli-developers-list",
            r"apigeecli\s+developers\s+list\b"
        ),
        safe_pattern!(
            "apigeecli-developers-get",
            r"apigeecli\s+developers\s+get\b"
        ),
        safe_pattern!("apigeecli-envs-list", r"apigeecli\s+envs\s+list\b"),
        safe_pattern!("apigeecli-envs-get", r"apigeecli\s+envs\s+get\b"),
        safe_pattern!("apigeecli-orgs-list", r"apigeecli\s+orgs\s+list\b"),
        safe_pattern!("apigeecli-orgs-get", r"apigeecli\s+orgs\s+get\b"),
        // Help commands
        safe_pattern!(
            "gcloud-apigee-help",
            r"gcloud\s+apigee\s+(?:--help|-h|help)\b"
        ),
        safe_pattern!(
            "apigeecli-help",
            r"apigeecli\s+(?:--help|-h|help|version)\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // gcloud apigee - delete operations
        destructive_pattern!(
            "gcloud-apigee-apis-delete",
            r"gcloud\s+apigee\s+apis\s+delete\b",
            "gcloud apigee apis delete removes an API proxy from Apigee.",
            High,
            "Deleting an API proxy removes all its revisions and deployment history. Any \
             applications relying on this API will immediately receive errors. API keys \
             and quotas associated with products referencing this API may be affected.\n\n\
             Safer alternatives:\n\
             - gcloud apigee apis list: Review APIs before deletion\n\
             - gcloud apigee deployments undeploy: Undeploy first to verify impact\n\
             - Export the API proxy bundle before deletion for backup"
        ),
        destructive_pattern!(
            "gcloud-apigee-environments-delete",
            r"gcloud\s+apigee\s+environments\s+delete\b",
            "gcloud apigee environments delete removes an Apigee environment.",
            Critical,
            "Deleting an environment removes all deployed API proxies, target servers, \
             key-value maps, and caches within it. This is irreversible and will break \
             all API traffic routed through this environment.\n\n\
             Safer alternatives:\n\
             - gcloud apigee environments describe: Review environment contents\n\
             - Undeploy all APIs from the environment first\n\
             - Export environment configuration and resources before deletion"
        ),
        destructive_pattern!(
            "gcloud-apigee-developers-delete",
            r"gcloud\s+apigee\s+developers\s+delete\b",
            "gcloud apigee developers delete removes a developer from Apigee.",
            High,
            "Deleting a developer also deletes all their apps and associated API keys. \
             Any applications using those keys will immediately lose API access. Developer \
             analytics and usage history are also removed.\n\n\
             Safer alternatives:\n\
             - gcloud apigee developers describe: Review developer details\n\
             - Revoke individual app credentials instead of deleting the developer\n\
             - Set developer status to inactive rather than deleting"
        ),
        destructive_pattern!(
            "gcloud-apigee-products-delete",
            r"gcloud\s+apigee\s+products\s+delete\b",
            "gcloud apigee products delete removes an API product from Apigee.",
            High,
            "Deleting an API product immediately revokes access for all apps subscribed \
             to it. Quota settings, rate limits, and access controls defined in the product \
             are lost. Apps will need to be re-subscribed to a different product.\n\n\
             Safer alternatives:\n\
             - gcloud apigee products describe: Review product configuration\n\
             - Remove individual apps from the product instead\n\
             - Set product access to private before deletion to verify impact"
        ),
        destructive_pattern!(
            "gcloud-apigee-organizations-delete",
            r"gcloud\s+apigee\s+organizations\s+delete\b",
            "gcloud apigee organizations delete removes an entire Apigee organization.",
            Critical,
            "Deleting an organization permanently removes ALL environments, API proxies, \
             products, developers, apps, and analytics data. This is irreversible and will \
             completely destroy your API management infrastructure.\n\n\
             Safer alternatives:\n\
             - Export all configurations and proxy bundles before deletion\n\
             - Delete individual resources to verify nothing is still in use\n\
             - Consider disabling billing instead if just reducing costs"
        ),
        destructive_pattern!(
            "gcloud-apigee-deployments-undeploy",
            r"gcloud\s+apigee\s+deployments\s+undeploy\b",
            "gcloud apigee deployments undeploy removes an API deployment.",
            Medium,
            "Undeploying an API proxy stops all traffic processing for that API in the \
             specified environment. Clients will receive errors until the API is redeployed. \
             This is reversible by redeploying the proxy.\n\n\
             Safer alternatives:\n\
             - gcloud apigee deployments list: Review current deployments\n\
             - Test in a non-production environment first\n\
             - Deploy a new revision instead of undeploying"
        ),
        // apigeecli - delete operations
        destructive_pattern!(
            "apigeecli-apis-delete",
            r"apigeecli\s+apis\s+delete\b",
            "apigeecli apis delete removes an API proxy from Apigee.",
            High,
            "Deleting an API proxy removes all its revisions and deployment history. Any \
             applications relying on this API will immediately receive errors.\n\n\
             Safer alternatives:\n\
             - apigeecli apis list: Review APIs before deletion\n\
             - apigeecli apis export: Export the proxy bundle for backup\n\
             - Undeploy from all environments first to verify impact"
        ),
        destructive_pattern!(
            "apigeecli-products-delete",
            r"apigeecli\s+products\s+delete\b",
            "apigeecli products delete removes an API product from Apigee.",
            High,
            "Deleting an API product immediately revokes access for all subscribed apps. \
             Quota settings and rate limits are permanently lost.\n\n\
             Safer alternatives:\n\
             - apigeecli products list: Review products before deletion\n\
             - apigeecli products get: Check which apps are using the product\n\
             - Remove apps from the product first to verify impact"
        ),
        destructive_pattern!(
            "apigeecli-developers-delete",
            r"apigeecli\s+developers\s+delete\b",
            "apigeecli developers delete removes a developer from Apigee.",
            High,
            "Deleting a developer also deletes all their apps and API keys. Applications \
             using those keys will immediately lose access.\n\n\
             Safer alternatives:\n\
             - apigeecli developers list: Review developers before deletion\n\
             - apigeecli apps list: Check developer's apps first\n\
             - Set developer status to inactive instead of deleting"
        ),
        destructive_pattern!(
            "apigeecli-envs-delete",
            r"apigeecli\s+envs\s+delete\b",
            "apigeecli envs delete removes an Apigee environment.",
            Critical,
            "Deleting an environment removes all deployed proxies, target servers, and \
             configurations. This breaks all API traffic through that environment.\n\n\
             Safer alternatives:\n\
             - apigeecli envs list: Review environments before deletion\n\
             - Export all environment resources before deletion\n\
             - Undeploy all APIs first to verify nothing is in use"
        ),
        destructive_pattern!(
            "apigeecli-orgs-delete",
            r"apigeecli\s+orgs\s+delete\b",
            "apigeecli orgs delete removes an entire Apigee organization.",
            Critical,
            "Deleting an organization permanently removes ALL resources: environments, \
             APIs, products, developers, apps, and analytics. This is completely irreversible.\n\n\
             Safer alternatives:\n\
             - Export all configurations before deletion\n\
             - Delete individual resources first to verify impact\n\
             - Contact support if you need to preserve any data"
        ),
        destructive_pattern!(
            "apigeecli-apps-delete",
            r"apigeecli\s+apps\s+delete\b",
            "apigeecli apps delete removes a developer app from Apigee.",
            High,
            "Deleting an app revokes all its API keys and credentials. Any systems using \
             those keys will immediately lose API access.\n\n\
             Safer alternatives:\n\
             - apigeecli apps list: Review apps before deletion\n\
             - Revoke individual credentials instead of deleting the app\n\
             - Set app status to revoked to disable without deleting"
        ),
        destructive_pattern!(
            "apigeecli-keyvaluemaps-delete",
            r"apigeecli\s+keyvaluemaps\s+delete\b",
            "apigeecli keyvaluemaps delete removes a key-value map from Apigee.",
            High,
            "Deleting a KVM removes all stored key-value pairs. API proxies reading from \
             this KVM will fail or return errors. Configuration data stored in the KVM is \
             permanently lost.\n\n\
             Safer alternatives:\n\
             - apigeecli keyvaluemaps list: Review KVMs before deletion\n\
             - Export KVM entries before deletion\n\
             - Check which proxies reference this KVM first"
        ),
        destructive_pattern!(
            "apigeecli-targetservers-delete",
            r"apigeecli\s+targetservers\s+delete\b",
            "apigeecli targetservers delete removes a target server from Apigee.",
            High,
            "Deleting a target server breaks all API proxies that route traffic to it. \
             Requests will fail until proxies are updated to use a different target.\n\n\
             Safer alternatives:\n\
             - apigeecli targetservers list: Review targets before deletion\n\
             - Update API proxies to use a different target first\n\
             - Set the target server to disabled to test impact"
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
        assert_eq!(pack.id, "apigateway.apigee");
        assert_eq!(pack.name, "Google Apigee");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"apigee"));
        assert!(pack.keywords.contains(&"apigeecli"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        // gcloud apigee - list/describe operations
        assert_safe_pattern_matches(&pack, "gcloud apigee apis list");
        assert_safe_pattern_matches(&pack, "gcloud apigee apis list --organization=my-org");
        assert_safe_pattern_matches(&pack, "gcloud apigee apis describe my-api");
        assert_safe_pattern_matches(
            &pack,
            "gcloud apigee environments list --organization=my-org",
        );
        assert_safe_pattern_matches(&pack, "gcloud apigee environments describe my-env");
        assert_safe_pattern_matches(&pack, "gcloud apigee developers list");
        assert_safe_pattern_matches(&pack, "gcloud apigee developers describe dev@example.com");
        assert_safe_pattern_matches(&pack, "gcloud apigee products list");
        assert_safe_pattern_matches(&pack, "gcloud apigee products describe my-product");
        assert_safe_pattern_matches(&pack, "gcloud apigee organizations list");
        assert_safe_pattern_matches(&pack, "gcloud apigee organizations describe my-org");
        assert_safe_pattern_matches(&pack, "gcloud apigee deployments list");
        // apigeecli - list operations
        assert_safe_pattern_matches(&pack, "apigeecli apis list");
        assert_safe_pattern_matches(&pack, "apigeecli apis get --name my-api");
        assert_safe_pattern_matches(&pack, "apigeecli products list");
        assert_safe_pattern_matches(&pack, "apigeecli products get --name my-product");
        assert_safe_pattern_matches(&pack, "apigeecli developers list");
        assert_safe_pattern_matches(&pack, "apigeecli developers get --email dev@example.com");
        assert_safe_pattern_matches(&pack, "apigeecli envs list");
        assert_safe_pattern_matches(&pack, "apigeecli envs get --name prod");
        assert_safe_pattern_matches(&pack, "apigeecli orgs list");
        assert_safe_pattern_matches(&pack, "apigeecli orgs get --name my-org");
        // Help commands
        assert_safe_pattern_matches(&pack, "gcloud apigee --help");
        assert_safe_pattern_matches(&pack, "gcloud apigee help");
        assert_safe_pattern_matches(&pack, "apigeecli --help");
        assert_safe_pattern_matches(&pack, "apigeecli help");
        assert_safe_pattern_matches(&pack, "apigeecli version");
    }

    #[test]
    fn blocks_gcloud_apis_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "gcloud apigee apis delete my-api --organization=my-org",
            "gcloud-apigee-apis-delete",
        );
    }

    #[test]
    fn blocks_gcloud_environments_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "gcloud apigee environments delete my-env --organization=my-org",
            "gcloud-apigee-environments-delete",
        );
    }

    #[test]
    fn blocks_gcloud_developers_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "gcloud apigee developers delete dev@example.com",
            "gcloud-apigee-developers-delete",
        );
    }

    #[test]
    fn blocks_gcloud_products_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "gcloud apigee products delete my-product",
            "gcloud-apigee-products-delete",
        );
    }

    #[test]
    fn blocks_gcloud_organizations_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "gcloud apigee organizations delete my-org",
            "gcloud-apigee-organizations-delete",
        );
    }

    #[test]
    fn blocks_gcloud_deployments_undeploy() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "gcloud apigee deployments undeploy --api=my-api --environment=prod",
            "gcloud-apigee-deployments-undeploy",
        );
    }

    #[test]
    fn blocks_apigeecli_apis_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "apigeecli apis delete --name my-api",
            "apigeecli-apis-delete",
        );
    }

    #[test]
    fn blocks_apigeecli_products_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "apigeecli products delete --name my-product",
            "apigeecli-products-delete",
        );
    }

    #[test]
    fn blocks_apigeecli_developers_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "apigeecli developers delete --email dev@example.com",
            "apigeecli-developers-delete",
        );
    }

    #[test]
    fn blocks_apigeecli_envs_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "apigeecli envs delete --name prod",
            "apigeecli-envs-delete",
        );
    }

    #[test]
    fn blocks_apigeecli_orgs_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "apigeecli orgs delete --name my-org",
            "apigeecli-orgs-delete",
        );
    }

    #[test]
    fn blocks_apigeecli_apps_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "apigeecli apps delete --name my-app --developer dev@example.com",
            "apigeecli-apps-delete",
        );
    }

    #[test]
    fn blocks_apigeecli_keyvaluemaps_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "apigeecli keyvaluemaps delete --name my-kvm",
            "apigeecli-keyvaluemaps-delete",
        );
    }

    #[test]
    fn blocks_apigeecli_targetservers_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "apigeecli targetservers delete --name backend-server",
            "apigeecli-targetservers-delete",
        );
    }
}
