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
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!(
            "aws-secretsmanager-list",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+list-secrets(?=\s|$)"
        ),
        safe_pattern!(
            "aws-secretsmanager-describe",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+describe-secret(?=\s|$)"
        ),
        safe_pattern!(
            "aws-secretsmanager-get",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+get-secret-value(?=\s|$)"
        ),
        safe_pattern!(
            "aws-secretsmanager-list-versions",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+list-secret-version-ids(?=\s|$)"
        ),
        safe_pattern!(
            "aws-secretsmanager-get-resource-policy",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+get-resource-policy(?=\s|$)"
        ),
        safe_pattern!(
            "aws-secretsmanager-get-random-password",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+get-random-password(?=\s|$)"
        ),
        safe_pattern!(
            "aws-ssm-get-parameter",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+ssm\s+get-parameter(?=\s|$)"
        ),
        safe_pattern!(
            "aws-ssm-get-parameters",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+ssm\s+get-parameters(?=\s|$)"
        ),
        safe_pattern!(
            "aws-ssm-describe-parameters",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+ssm\s+describe-parameters(?=\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "aws-secretsmanager-delete-secret",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+delete-secret\b",
            "aws secretsmanager delete-secret removes secrets and may cause data loss.",
            Critical,
            "Deleting a secret schedules it for deletion (default 30 days) or immediately \
             removes it with --force-delete-without-recovery. Applications using this secret \
             will fail to authenticate or decrypt data.\n\n\
             Safer alternatives:\n\
             - aws secretsmanager get-secret-value: Export value first\n\
             - aws secretsmanager describe-secret: Check rotation/replication\n\
             - Use --recovery-window-in-days for recoverable deletion"
        ),
        destructive_pattern!(
            "aws-secretsmanager-delete-resource-policy",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+delete-resource-policy\b",
            "aws secretsmanager delete-resource-policy removes access controls.",
            High,
            "Deleting a resource policy removes cross-account access and custom permissions. \
             Other AWS accounts or services that rely on this policy will lose access to the \
             secret immediately.\n\n\
             Safer alternatives:\n\
             - aws secretsmanager get-resource-policy: Export policy first\n\
             - Verify no cross-account dependencies exist\n\
             - Update IAM policies to compensate if needed"
        ),
        destructive_pattern!(
            "aws-secretsmanager-remove-regions",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+remove-regions-from-replication\b",
            "aws secretsmanager remove-regions-from-replication can reduce availability.",
            High,
            "Removing regions from replication deletes the secret replica in those regions. \
             Applications in removed regions will lose local access to the secret, increasing \
             latency or causing failures during cross-region failover.\n\n\
             Safer alternatives:\n\
             - aws secretsmanager describe-secret: Review replica regions\n\
             - Verify no applications in target regions use the secret\n\
             - Update disaster recovery documentation"
        ),
        destructive_pattern!(
            "aws-secretsmanager-update-secret",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+update-secret\b",
            "aws secretsmanager update-secret overwrites secret metadata or value.",
            Medium,
            "Updating a secret can change its value, KMS key, or description. The previous \
             value becomes a non-current version. Applications using the old value may fail \
             if automatic rotation is not configured.\n\n\
             Safer alternatives:\n\
             - aws secretsmanager get-secret-value: Export current value\n\
             - Use put-secret-value to create new version instead\n\
             - Test new value in non-production environment first"
        ),
        destructive_pattern!(
            "aws-secretsmanager-put-secret-value",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+put-secret-value\b",
            "aws secretsmanager put-secret-value creates a new secret version and can break clients.",
            Medium,
            "Creating a new secret version makes it the current value immediately. Applications \
             caching the old value will use outdated credentials until they refresh. Rotation \
             windows should be coordinated with application deployments.\n\n\
             Safer alternatives:\n\
             - aws secretsmanager get-secret-value: Export current value\n\
             - Use version staging labels for gradual rollout\n\
             - Coordinate secret updates with application deployments"
        ),
        destructive_pattern!(
            "aws-ssm-delete-parameter",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+ssm\s+delete-parameter\b",
            "aws ssm delete-parameter removes a parameter and can break deployments.",
            High,
            "Deleting an SSM parameter immediately removes it. Applications, CloudFormation \
             stacks, and deployment scripts referencing this parameter will fail. There is no \
             recovery window like Secrets Manager.\n\n\
             Safer alternatives:\n\
             - aws ssm get-parameter: Export value first\n\
             - aws ssm describe-parameters: Check parameter history\n\
             - Search CloudFormation templates for references"
        ),
        destructive_pattern!(
            "aws-ssm-delete-parameters",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+ssm\s+delete-parameters\b",
            "aws ssm delete-parameters removes parameters and can break deployments.",
            High,
            "Deleting multiple SSM parameters at once can break numerous applications and \
             deployment pipelines simultaneously. Each parameter is deleted immediately with \
             no recovery option.\n\n\
             Safer alternatives:\n\
             - aws ssm get-parameters: Export all values first\n\
             - Delete one parameter at a time to limit blast radius\n\
             - Verify no active deployments use these parameters"
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
