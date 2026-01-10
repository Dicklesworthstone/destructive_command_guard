//! AWS CLI patterns - protections against destructive aws commands.
//!
//! This includes patterns for:
//! - ec2 terminate-instances
//! - s3 rm --recursive
//! - rds delete-db-instance
//! - cloudformation delete-stack

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the AWS pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "cloud.aws".to_string(),
        name: "AWS CLI",
        description: "Protects against destructive AWS CLI operations like terminate-instances, \
                      delete-db-instance, and s3 rm --recursive",
        keywords: &[
            "aws",
            "terminate",
            "delete",
            "s3",
            "ec2",
            "rds",
            "ecr",
            "logs",
        ],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // describe/list/get operations are safe (read-only)
        safe_pattern!("aws-describe", r"aws\s+\S+\s+describe-"),
        safe_pattern!("aws-list", r"aws\s+\S+\s+list-"),
        safe_pattern!("aws-get", r"aws\s+\S+\s+get-"),
        // s3 ls is safe
        safe_pattern!("s3-ls", r"aws\s+s3\s+ls"),
        // s3 cp is generally safe (copy)
        safe_pattern!("s3-cp", r"aws\s+s3\s+cp"),
        // dry-run flag
        safe_pattern!("aws-dry-run", r"aws\s+.*--dry-run"),
        // sts get-caller-identity is safe
        safe_pattern!("sts-identity", r"aws\s+sts\s+get-caller-identity"),
        // cloudformation describe/list
        safe_pattern!("cfn-describe", r"aws\s+cloudformation\s+(?:describe|list)-"),
        // ecr get-login-password is safe
        safe_pattern!("ecr-login", r"aws\s+ecr\s+get-login"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // ec2 terminate-instances
        destructive_pattern!(
            "ec2-terminate",
            r"aws\s+ec2\s+terminate-instances",
            "aws ec2 terminate-instances permanently destroys EC2 instances."
        ),
        // ec2 delete-* commands
        destructive_pattern!(
            "ec2-delete",
            r"aws\s+ec2\s+delete-(?:snapshot|volume|vpc|subnet|security-group)",
            "aws ec2 delete-* permanently removes AWS resources."
        ),
        // s3 rm --recursive
        destructive_pattern!(
            "s3-rm-recursive",
            r"aws\s+s3\s+rm\s+.*--recursive",
            "aws s3 rm --recursive permanently deletes all objects in the path."
        ),
        // s3 rb (remove bucket)
        destructive_pattern!(
            "s3-rb",
            r"aws\s+s3\s+rb\b",
            "aws s3 rb removes the entire S3 bucket."
        ),
        // s3api delete-bucket
        destructive_pattern!(
            "s3api-delete-bucket",
            r"aws\s+s3api\s+delete-bucket",
            "aws s3api delete-bucket removes the entire S3 bucket."
        ),
        // rds delete-db-instance
        destructive_pattern!(
            "rds-delete",
            r"aws\s+rds\s+delete-db-(?:instance|cluster)",
            "aws rds delete-db-instance/cluster permanently destroys the database."
        ),
        // cloudformation delete-stack
        destructive_pattern!(
            "cfn-delete-stack",
            r"aws\s+cloudformation\s+delete-stack",
            "aws cloudformation delete-stack removes the entire stack and its resources."
        ),
        // lambda delete-function
        destructive_pattern!(
            "lambda-delete",
            r"aws\s+lambda\s+delete-function",
            "aws lambda delete-function permanently removes the Lambda function."
        ),
        // iam delete-user/role/policy
        destructive_pattern!(
            "iam-delete",
            r"aws\s+iam\s+delete-(?:user|role|policy|group)",
            "aws iam delete-* removes IAM resources. Verify dependencies first."
        ),
        // dynamodb delete-table
        destructive_pattern!(
            "dynamodb-delete",
            r"aws\s+dynamodb\s+delete-table",
            "aws dynamodb delete-table permanently deletes the table and all data."
        ),
        // eks delete-cluster
        destructive_pattern!(
            "eks-delete",
            r"aws\s+eks\s+delete-cluster",
            "aws eks delete-cluster removes the entire EKS cluster."
        ),
        // ecr delete-repository
        destructive_pattern!(
            "ecr-delete-repository",
            r"aws\s+ecr\s+delete-repository",
            "aws ecr delete-repository permanently deletes the repository and its images."
        ),
        // ecr batch-delete-image
        destructive_pattern!(
            "ecr-batch-delete-image",
            r"aws\s+ecr\s+batch-delete-image",
            "aws ecr batch-delete-image permanently deletes one or more images."
        ),
        // ecr delete-lifecycle-policy
        destructive_pattern!(
            "ecr-delete-lifecycle-policy",
            r"aws\s+ecr\s+delete-lifecycle-policy",
            "aws ecr delete-lifecycle-policy removes the repository lifecycle policy."
        ),
        // CloudWatch Logs delete-log-group
        destructive_pattern!(
            "logs-delete-log-group",
            r"aws\s+logs\s+delete-log-group",
            "aws logs delete-log-group permanently deletes a log group and all events."
        ),
        // CloudWatch Logs delete-log-stream
        destructive_pattern!(
            "logs-delete-log-stream",
            r"aws\s+logs\s+delete-log-stream",
            "aws logs delete-log-stream permanently deletes a log stream and all events."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::*;

    #[test]
    fn ecr_and_logs_patterns_block() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "aws ecr delete-repository --repository-name example",
            "delete-repository",
        );
        assert_blocks(
            &pack,
            "aws ecr batch-delete-image --repository-name example --image-ids imageTag=latest",
            "batch-delete-image",
        );
        assert_blocks(
            &pack,
            "aws ecr delete-lifecycle-policy --repository-name example",
            "delete-lifecycle-policy",
        );
        assert_blocks(
            &pack,
            "aws logs delete-log-group --log-group-name /aws/lambda/thing",
            "delete-log-group",
        );
        assert_blocks(
            &pack,
            "aws logs delete-log-stream --log-group-name /aws/lambda/thing --log-stream-name foo",
            "delete-log-stream",
        );
    }
}
