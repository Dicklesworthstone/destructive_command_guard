//! `AWS` Secrets Manager + `SSM` pack - protections for destructive secrets operations.
//!
//! Blocks delete and mutation commands that can remove or overwrite secrets.

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the AWS Secrets Manager / SSM pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "secrets.aws_secrets".to_string(),
        name: "AWS Secrets Manager",
        description: "Protects against destructive AWS Secrets Manager and SSM Parameter Store \
                      operations like delete-secret and delete-parameter.",
        keywords: &["aws", "secretsmanager", "ssm"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!(
            "aws-secretsmanager-list",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+list-secrets\b"
        ),
        safe_pattern!(
            "aws-secretsmanager-describe",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+describe-secret\b"
        ),
        safe_pattern!(
            "aws-secretsmanager-get",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+get-secret-value\b"
        ),
        safe_pattern!(
            "aws-secretsmanager-list-versions",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+list-secret-version-ids\b"
        ),
        safe_pattern!(
            "aws-secretsmanager-get-resource-policy",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+get-resource-policy\b"
        ),
        safe_pattern!(
            "aws-secretsmanager-get-random-password",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+get-random-password\b"
        ),
        safe_pattern!(
            "aws-ssm-get-parameter",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+ssm\s+get-parameter\b"
        ),
        safe_pattern!(
            "aws-ssm-get-parameters",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+ssm\s+get-parameters\b"
        ),
        safe_pattern!(
            "aws-ssm-describe-parameters",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+ssm\s+describe-parameters\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "aws-secretsmanager-delete-secret",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+delete-secret\b",
            "aws secretsmanager delete-secret removes secrets and may cause data loss."
        ),
        destructive_pattern!(
            "aws-secretsmanager-delete-resource-policy",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+delete-resource-policy\b",
            "aws secretsmanager delete-resource-policy removes access controls."
        ),
        destructive_pattern!(
            "aws-secretsmanager-remove-regions",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+remove-regions-from-replication\b",
            "aws secretsmanager remove-regions-from-replication can reduce availability."
        ),
        destructive_pattern!(
            "aws-secretsmanager-update-secret",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+update-secret\b",
            "aws secretsmanager update-secret overwrites secret metadata or value."
        ),
        destructive_pattern!(
            "aws-secretsmanager-put-secret-value",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+put-secret-value\b",
            "aws secretsmanager put-secret-value creates a new secret version and can break clients."
        ),
        destructive_pattern!(
            "aws-ssm-delete-parameter",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+ssm\s+delete-parameter\b",
            "aws ssm delete-parameter removes a parameter and can break deployments."
        ),
        destructive_pattern!(
            "aws-ssm-delete-parameters",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+ssm\s+delete-parameters\b",
            "aws ssm delete-parameters removes parameters and can break deployments."
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
        assert_eq!(pack.id, "secrets.aws_secrets");
        assert_eq!(pack.name, "AWS Secrets Manager");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"aws"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn test_delete_secret_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "aws secretsmanager delete-secret --secret-id my/secret",
            "aws-secretsmanager-delete-secret",
        );
        assert_blocks(
            &pack,
            "aws --region us-east-1 secretsmanager delete-secret --secret-id my/secret --recovery-window-in-days 7",
            "delete-secret",
        );
    }

    #[test]
    fn test_update_and_put_secret_value_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "aws secretsmanager update-secret --secret-id my/secret --description \"rotated\"",
            "aws-secretsmanager-update-secret",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws secretsmanager put-secret-value --secret-id my/secret --secret-string \"{}\"",
            "aws-secretsmanager-put-secret-value",
        );
    }

    #[test]
    fn test_policy_and_replication_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "aws secretsmanager delete-resource-policy --secret-id my/secret",
            "aws-secretsmanager-delete-resource-policy",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws secretsmanager remove-regions-from-replication --secret-id my/secret --remove-replica-regions us-east-1",
            "aws-secretsmanager-remove-regions",
        );
    }

    #[test]
    fn test_ssm_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "aws ssm delete-parameter --name /app/config",
            "aws-ssm-delete-parameter",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws ssm delete-parameters --names /app/one /app/two",
            "aws-ssm-delete-parameters",
        );
    }

    #[test]
    fn test_safe_secretsmanager_commands_allowed() {
        let pack = create_pack();
        assert_allows(&pack, "aws secretsmanager list-secrets");
        assert_allows(
            &pack,
            "aws secretsmanager describe-secret --secret-id my/secret",
        );
        assert_allows(
            &pack,
            "aws secretsmanager get-secret-value --secret-id my/secret",
        );
        assert_allows(
            &pack,
            "aws secretsmanager list-secret-version-ids --secret-id my/secret",
        );
        assert_allows(
            &pack,
            "aws secretsmanager get-resource-policy --secret-id my/secret",
        );
        assert_allows(
            &pack,
            "aws secretsmanager get-random-password --password-length 32",
        );
    }

    #[test]
    fn test_safe_ssm_commands_allowed() {
        let pack = create_pack();
        assert_allows(&pack, "aws ssm get-parameter --name /app/config");
        assert_allows(&pack, "aws ssm get-parameters --names /app/one /app/two");
        assert_allows(&pack, "aws ssm describe-parameters");
    }
}
