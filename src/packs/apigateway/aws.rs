//! AWS API Gateway pack - protections for destructive AWS API Gateway operations.
//!
//! Covers destructive operations for both REST APIs (`APIGateway`) and HTTP APIs (`APIGatewayV2`):
//! - REST API deletion (`aws apigateway delete-rest-api`)
//! - Resource deletion (`aws apigateway delete-resource`)
//! - Method deletion (`aws apigateway delete-method`)
//! - Stage deletion (`aws apigateway delete-stage`, `aws apigatewayv2 delete-stage`)
//! - Deployment deletion (`aws apigateway delete-deployment`)
//! - API key deletion (`aws apigateway delete-api-key`)
//! - HTTP API deletion (`aws apigatewayv2 delete-api`)
//! - Route deletion (`aws apigatewayv2 delete-route`)
//! - Integration deletion (`aws apigatewayv2 delete-integration`)

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the AWS API Gateway pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "apigateway.aws".to_string(),
        name: "AWS API Gateway",
        description: "Protects against destructive AWS API Gateway CLI operations for both \
                      REST APIs and HTTP APIs.",
        keywords: &["aws", "apigateway", "apigatewayv2"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // REST API (APIGateway) - read operations
        safe_pattern!(
            "apigateway-get-rest-api",
            r"aws\s+apigateway\s+get-rest-api\b"
        ),
        safe_pattern!(
            "apigateway-get-rest-apis",
            r"aws\s+apigateway\s+get-rest-apis\b"
        ),
        safe_pattern!(
            "apigateway-get-resources",
            r"aws\s+apigateway\s+get-resources\b"
        ),
        safe_pattern!(
            "apigateway-get-resource",
            r"aws\s+apigateway\s+get-resource\b"
        ),
        safe_pattern!("apigateway-get-method", r"aws\s+apigateway\s+get-method\b"),
        safe_pattern!("apigateway-get-stages", r"aws\s+apigateway\s+get-stages\b"),
        safe_pattern!("apigateway-get-stage", r"aws\s+apigateway\s+get-stage\b"),
        safe_pattern!(
            "apigateway-get-deployments",
            r"aws\s+apigateway\s+get-deployments\b"
        ),
        safe_pattern!(
            "apigateway-get-deployment",
            r"aws\s+apigateway\s+get-deployment\b"
        ),
        safe_pattern!(
            "apigateway-get-api-keys",
            r"aws\s+apigateway\s+get-api-keys\b"
        ),
        safe_pattern!(
            "apigateway-get-api-key",
            r"aws\s+apigateway\s+get-api-key\b"
        ),
        safe_pattern!(
            "apigateway-get-authorizers",
            r"aws\s+apigateway\s+get-authorizers\b"
        ),
        safe_pattern!("apigateway-get-models", r"aws\s+apigateway\s+get-models\b"),
        safe_pattern!(
            "apigateway-get-usage-plans",
            r"aws\s+apigateway\s+get-usage-plans\b"
        ),
        safe_pattern!(
            "apigateway-get-domain-names",
            r"aws\s+apigateway\s+get-domain-names\b"
        ),
        // HTTP API (APIGatewayV2) - read operations
        safe_pattern!("apigatewayv2-get-apis", r"aws\s+apigatewayv2\s+get-apis\b"),
        safe_pattern!("apigatewayv2-get-api", r"aws\s+apigatewayv2\s+get-api\b"),
        safe_pattern!(
            "apigatewayv2-get-routes",
            r"aws\s+apigatewayv2\s+get-routes\b"
        ),
        safe_pattern!(
            "apigatewayv2-get-route",
            r"aws\s+apigatewayv2\s+get-route\b"
        ),
        safe_pattern!(
            "apigatewayv2-get-integrations",
            r"aws\s+apigatewayv2\s+get-integrations\b"
        ),
        safe_pattern!(
            "apigatewayv2-get-integration",
            r"aws\s+apigatewayv2\s+get-integration\b"
        ),
        safe_pattern!(
            "apigatewayv2-get-stages",
            r"aws\s+apigatewayv2\s+get-stages\b"
        ),
        safe_pattern!(
            "apigatewayv2-get-stage",
            r"aws\s+apigatewayv2\s+get-stage\b"
        ),
        safe_pattern!(
            "apigatewayv2-get-authorizers",
            r"aws\s+apigatewayv2\s+get-authorizers\b"
        ),
        safe_pattern!(
            "apigatewayv2-get-domain-names",
            r"aws\s+apigatewayv2\s+get-domain-names\b"
        ),
        // General AWS help
        safe_pattern!("apigateway-help", r"aws\s+apigateway\s+(?:help|\-\-help)\b"),
        safe_pattern!(
            "apigatewayv2-help",
            r"aws\s+apigatewayv2\s+(?:help|\-\-help)\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // REST API (APIGateway) - destructive operations
        destructive_pattern!(
            "apigateway-delete-rest-api",
            r"aws\s+apigateway\s+delete-rest-api\b",
            "aws apigateway delete-rest-api permanently removes a REST API and all its resources."
        ),
        destructive_pattern!(
            "apigateway-delete-resource",
            r"aws\s+apigateway\s+delete-resource\b",
            "aws apigateway delete-resource removes an API resource and its methods."
        ),
        destructive_pattern!(
            "apigateway-delete-method",
            r"aws\s+apigateway\s+delete-method\b",
            "aws apigateway delete-method removes an HTTP method from a resource."
        ),
        destructive_pattern!(
            "apigateway-delete-stage",
            r"aws\s+apigateway\s+delete-stage\b",
            "aws apigateway delete-stage removes a deployment stage from an API."
        ),
        destructive_pattern!(
            "apigateway-delete-deployment",
            r"aws\s+apigateway\s+delete-deployment\b",
            "aws apigateway delete-deployment removes a deployment from an API."
        ),
        destructive_pattern!(
            "apigateway-delete-api-key",
            r"aws\s+apigateway\s+delete-api-key\b",
            "aws apigateway delete-api-key removes an API key."
        ),
        destructive_pattern!(
            "apigateway-delete-authorizer",
            r"aws\s+apigateway\s+delete-authorizer\b",
            "aws apigateway delete-authorizer removes an authorizer from an API."
        ),
        destructive_pattern!(
            "apigateway-delete-model",
            r"aws\s+apigateway\s+delete-model\b",
            "aws apigateway delete-model removes a model from an API."
        ),
        destructive_pattern!(
            "apigateway-delete-domain-name",
            r"aws\s+apigateway\s+delete-domain-name\b",
            "aws apigateway delete-domain-name removes a custom domain name."
        ),
        destructive_pattern!(
            "apigateway-delete-usage-plan",
            r"aws\s+apigateway\s+delete-usage-plan\b",
            "aws apigateway delete-usage-plan removes a usage plan."
        ),
        // HTTP API (APIGatewayV2) - destructive operations
        destructive_pattern!(
            "apigatewayv2-delete-api",
            r"aws\s+apigatewayv2\s+delete-api\b",
            "aws apigatewayv2 delete-api permanently removes an HTTP API."
        ),
        destructive_pattern!(
            "apigatewayv2-delete-route",
            r"aws\s+apigatewayv2\s+delete-route\b",
            "aws apigatewayv2 delete-route removes a route from an HTTP API."
        ),
        destructive_pattern!(
            "apigatewayv2-delete-integration",
            r"aws\s+apigatewayv2\s+delete-integration\b",
            "aws apigatewayv2 delete-integration removes an integration from an HTTP API."
        ),
        destructive_pattern!(
            "apigatewayv2-delete-stage",
            r"aws\s+apigatewayv2\s+delete-stage\b",
            "aws apigatewayv2 delete-stage removes a stage from an HTTP API."
        ),
        destructive_pattern!(
            "apigatewayv2-delete-authorizer",
            r"aws\s+apigatewayv2\s+delete-authorizer\b",
            "aws apigatewayv2 delete-authorizer removes an authorizer from an HTTP API."
        ),
        destructive_pattern!(
            "apigatewayv2-delete-domain-name",
            r"aws\s+apigatewayv2\s+delete-domain-name\b",
            "aws apigatewayv2 delete-domain-name removes a custom domain name from an HTTP API."
        ),
        destructive_pattern!(
            "apigatewayv2-delete-route-response",
            r"aws\s+apigatewayv2\s+delete-route-response\b",
            "aws apigatewayv2 delete-route-response removes a route response from an HTTP API."
        ),
        destructive_pattern!(
            "apigatewayv2-delete-integration-response",
            r"aws\s+apigatewayv2\s+delete-integration-response\b",
            "aws apigatewayv2 delete-integration-response removes an integration response."
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
        assert_eq!(pack.id, "apigateway.aws");
        assert_eq!(pack.name, "AWS API Gateway");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"aws"));
        assert!(pack.keywords.contains(&"apigateway"));
        assert!(pack.keywords.contains(&"apigatewayv2"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        // REST API read operations
        assert_safe_pattern_matches(&pack, "aws apigateway get-rest-api --rest-api-id abc123");
        assert_safe_pattern_matches(&pack, "aws apigateway get-rest-apis");
        assert_safe_pattern_matches(&pack, "aws apigateway get-resources --rest-api-id abc123");
        assert_safe_pattern_matches(
            &pack,
            "aws apigateway get-resource --rest-api-id abc123 --resource-id xyz",
        );
        assert_safe_pattern_matches(
            &pack,
            "aws apigateway get-method --rest-api-id abc123 --resource-id xyz --http-method GET",
        );
        assert_safe_pattern_matches(&pack, "aws apigateway get-stages --rest-api-id abc123");
        assert_safe_pattern_matches(
            &pack,
            "aws apigateway get-stage --rest-api-id abc123 --stage-name prod",
        );
        assert_safe_pattern_matches(&pack, "aws apigateway get-deployments --rest-api-id abc123");
        assert_safe_pattern_matches(&pack, "aws apigateway get-api-keys");
        assert_safe_pattern_matches(&pack, "aws apigateway get-api-key --api-key abc123");
        assert_safe_pattern_matches(&pack, "aws apigateway get-authorizers --rest-api-id abc123");
        assert_safe_pattern_matches(&pack, "aws apigateway get-models --rest-api-id abc123");
        assert_safe_pattern_matches(&pack, "aws apigateway get-usage-plans");
        assert_safe_pattern_matches(&pack, "aws apigateway get-domain-names");
        // HTTP API read operations
        assert_safe_pattern_matches(&pack, "aws apigatewayv2 get-apis");
        assert_safe_pattern_matches(&pack, "aws apigatewayv2 get-api --api-id abc123");
        assert_safe_pattern_matches(&pack, "aws apigatewayv2 get-routes --api-id abc123");
        assert_safe_pattern_matches(
            &pack,
            "aws apigatewayv2 get-route --api-id abc123 --route-id xyz",
        );
        assert_safe_pattern_matches(&pack, "aws apigatewayv2 get-integrations --api-id abc123");
        assert_safe_pattern_matches(
            &pack,
            "aws apigatewayv2 get-integration --api-id abc123 --integration-id xyz",
        );
        assert_safe_pattern_matches(&pack, "aws apigatewayv2 get-stages --api-id abc123");
        assert_safe_pattern_matches(
            &pack,
            "aws apigatewayv2 get-stage --api-id abc123 --stage-name prod",
        );
        assert_safe_pattern_matches(&pack, "aws apigatewayv2 get-authorizers --api-id abc123");
        assert_safe_pattern_matches(&pack, "aws apigatewayv2 get-domain-names");
        // Help
        assert_safe_pattern_matches(&pack, "aws apigateway help");
        assert_safe_pattern_matches(&pack, "aws apigateway --help");
        assert_safe_pattern_matches(&pack, "aws apigatewayv2 help");
        assert_safe_pattern_matches(&pack, "aws apigatewayv2 --help");
    }

    #[test]
    fn blocks_rest_api_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "aws apigateway delete-rest-api --rest-api-id abc123",
            "apigateway-delete-rest-api",
        );
    }

    #[test]
    fn blocks_resource_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "aws apigateway delete-resource --rest-api-id abc123 --resource-id xyz",
            "apigateway-delete-resource",
        );
    }

    #[test]
    fn blocks_method_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "aws apigateway delete-method --rest-api-id abc123 --resource-id xyz --http-method GET",
            "apigateway-delete-method",
        );
    }

    #[test]
    fn blocks_stage_delete() {
        let pack = create_pack();
        // REST API stage deletion
        assert_blocks_with_pattern(
            &pack,
            "aws apigateway delete-stage --rest-api-id abc123 --stage-name prod",
            "apigateway-delete-stage",
        );
        // HTTP API stage deletion
        assert_blocks_with_pattern(
            &pack,
            "aws apigatewayv2 delete-stage --api-id abc123 --stage-name prod",
            "apigatewayv2-delete-stage",
        );
    }

    #[test]
    fn blocks_deployment_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "aws apigateway delete-deployment --rest-api-id abc123 --deployment-id xyz",
            "apigateway-delete-deployment",
        );
    }

    #[test]
    fn blocks_api_key_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "aws apigateway delete-api-key --api-key abc123",
            "apigateway-delete-api-key",
        );
    }

    #[test]
    fn blocks_authorizer_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "aws apigateway delete-authorizer --rest-api-id abc123 --authorizer-id xyz",
            "apigateway-delete-authorizer",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws apigatewayv2 delete-authorizer --api-id abc123 --authorizer-id xyz",
            "apigatewayv2-delete-authorizer",
        );
    }

    #[test]
    fn blocks_http_api_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "aws apigatewayv2 delete-api --api-id abc123",
            "apigatewayv2-delete-api",
        );
    }

    #[test]
    fn blocks_route_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "aws apigatewayv2 delete-route --api-id abc123 --route-id xyz",
            "apigatewayv2-delete-route",
        );
    }

    #[test]
    fn blocks_integration_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "aws apigatewayv2 delete-integration --api-id abc123 --integration-id xyz",
            "apigatewayv2-delete-integration",
        );
    }

    #[test]
    fn blocks_domain_name_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "aws apigateway delete-domain-name --domain-name api.example.com",
            "apigateway-delete-domain-name",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws apigatewayv2 delete-domain-name --domain-name api.example.com",
            "apigatewayv2-delete-domain-name",
        );
    }

    #[test]
    fn blocks_usage_plan_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "aws apigateway delete-usage-plan --usage-plan-id abc123",
            "apigateway-delete-usage-plan",
        );
    }

    #[test]
    fn blocks_model_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "aws apigateway delete-model --rest-api-id abc123 --model-name Error",
            "apigateway-delete-model",
        );
    }
}
