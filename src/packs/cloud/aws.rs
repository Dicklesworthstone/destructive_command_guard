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
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
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

#[allow(clippy::too_many_lines)]
fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // ec2 terminate-instances
        destructive_pattern!(
            "ec2-terminate",
            r"aws\s+ec2\s+terminate-instances",
            "aws ec2 terminate-instances permanently destroys EC2 instances.",
            Critical,
            "terminate-instances permanently destroys EC2 instances:\n\n\
             - Instance is stopped and deleted\n\
             - Instance store volumes are lost\n\
             - EBS root volumes deleted (unless DeleteOnTermination=false)\n\
             - Elastic IPs are disassociated\n\n\
             This cannot be undone. The instance ID will never be reusable.\n\n\
             Preview first:\n  \
             aws ec2 describe-instances --instance-ids i-xxx\n\n\
             Consider stop instead:\n  \
             aws ec2 stop-instances --instance-ids i-xxx"
        ),
        // ec2 delete-* commands
        destructive_pattern!(
            "removes AWS resources",
            r"aws\s+ec2\s+delete-(?:snapshot|volume|vpc|subnet|security-group|key-pair|image)",
            "aws ec2 delete-* permanently removes AWS resources.",
            High,
            "EC2 delete commands permanently remove resources:\n\n\
             - delete-snapshot: Removes EBS snapshot (backup data lost)\n\
             - delete-volume: Destroys EBS volume and all data\n\
             - delete-vpc: Removes VPC (must be empty)\n\
             - delete-image: Deregisters AMI\n\
             - delete-security-group: Removes firewall rules\n\
             - delete-key-pair: Removes SSH key (can't SSH to instances using it)\n\n\
             Always verify resource IDs:\n  \
             aws ec2 describe-<resource> --<resource>-ids xxx"
        ),
        // s3 rm --recursive
        destructive_pattern!(
            "s3-rm-recursive",
            r"aws\s+s3\s+rm\s+.*--recursive",
            "aws s3 rm --recursive permanently deletes all objects in the path.",
            Critical,
            "s3 rm --recursive deletes ALL objects under the specified path:\n\n\
             - All files and 'folders' are deleted\n\
             - Versioned objects: only current version deleted\n\
             - No trash/recycle bin\n\
             - Cannot be undone (unless versioning enabled)\n\n\
             Preview what would be deleted:\n  \
             aws s3 ls s3://bucket/path/ --recursive\n  \
             aws s3 rm s3://bucket/path/ --recursive --dryrun\n\n\
             Consider versioning for recovery:\n  \
             aws s3api list-object-versions --bucket bucket"
        ),
        // s3 rb (remove bucket)
        destructive_pattern!(
            "s3-rb",
            r"aws\s+s3\s+rb\b",
            "aws s3 rb removes the entire S3 bucket.",
            Critical,
            "s3 rb removes an S3 bucket:\n\n\
             - Bucket must be empty (use --force to delete contents first)\n\
             - With --force: deletes all objects then bucket\n\
             - Bucket name becomes available for others\n\
             - Cannot be undone\n\n\
             Check bucket contents:\n  \
             aws s3 ls s3://bucket --recursive --summarize\n\n\
             Verify bucket name:\n  \
             aws s3api head-bucket --bucket bucket-name"
        ),
        // s3api delete-bucket
        destructive_pattern!(
            "s3api-delete-bucket",
            r"aws\s+s3api\s+delete-bucket",
            "aws s3api delete-bucket removes the entire S3 bucket.",
            Critical,
            "s3api delete-bucket removes a bucket (must be empty):\n\n\
             - Returns error if bucket not empty\n\
             - Bucket name released for reuse by anyone\n\
             - Associated policies and configurations lost\n\n\
             Empty bucket first if needed:\n  \
             aws s3 rm s3://bucket --recursive\n\n\
             Or use s3 rb --force for both operations."
        ),
        // rds delete-db-instance
        destructive_pattern!(
            "rds-delete",
            r"aws\s+rds\s+delete-db-(?:instance|cluster|snapshot|cluster-snapshot)",
            "aws rds delete-db-instance/cluster permanently destroys the database.",
            Critical,
            "RDS delete commands permanently remove database resources:\n\n\
             - delete-db-instance: Destroys the database instance\n\
             - delete-db-cluster: Destroys Aurora cluster\n\
             - delete-db-snapshot: Removes backup\n\
             - delete-db-cluster-snapshot: Removes cluster backup\n\n\
             Consider:\n\
             - Create final snapshot before deletion\n\
             - Skip final snapshot only for test instances\n\n\
             Create backup:\n  \
             aws rds create-db-snapshot --db-instance-id xxx --db-snapshot-id backup"
        ),
        // cloudformation delete-stack
        destructive_pattern!(
            "cfn-delete-stack",
            r"aws\s+cloudformation\s+delete-stack",
            "aws cloudformation delete-stack removes the entire stack and its resources.",
            Critical,
            "CloudFormation delete-stack removes the stack AND all resources it created:\n\n\
             - EC2 instances terminated\n\
             - RDS databases deleted (unless DeletionPolicy: Retain)\n\
             - S3 buckets removed (if empty)\n\
             - All IAM resources deleted\n\n\
             Resources with DeletionPolicy: Retain are kept but orphaned.\n\n\
             Preview resources:\n  \
             aws cloudformation describe-stack-resources --stack-name xxx\n\n\
             Consider:\n  \
             aws cloudformation delete-stack --retain-resources res1 res2"
        ),
        // lambda delete-function
        destructive_pattern!(
            "lambda-delete",
            r"aws\s+lambda\s+delete-function",
            "aws lambda delete-function permanently removes the Lambda function.",
            High,
            "delete-function removes a Lambda function completely:\n\n\
             - Function code is deleted\n\
             - All versions and aliases removed\n\
             - Event source mappings deleted\n\
             - Cannot be undone\n\n\
             Backup function code first:\n  \
             aws lambda get-function --function-name xxx --query Code.Location\n\n\
             List versions:\n  \
             aws lambda list-versions-by-function --function-name xxx"
        ),
        // iam delete-user/role/policy
        destructive_pattern!(
            "iam-delete",
            r"aws\s+iam\s+delete-(?:user|role|policy|group)",
            "aws iam delete-* removes IAM resources. Verify dependencies first.",
            High,
            "IAM delete commands remove identity resources:\n\n\
             - delete-user: Removes IAM user (must detach policies first)\n\
             - delete-role: Removes role (must detach policies first)\n\
             - delete-policy: Removes managed policy\n\
             - delete-group: Removes IAM group\n\n\
             Check dependencies:\n  \
             aws iam list-attached-user-policies --user-name xxx\n  \
             aws iam list-entities-for-policy --policy-arn xxx\n\n\
             Roles used by services (Lambda, EC2) will break!"
        ),
        // dynamodb delete-table
        destructive_pattern!(
            "dynamodb-delete",
            r"aws\s+dynamodb\s+delete-table",
            "aws dynamodb delete-table permanently deletes the table and all data.",
            Critical,
            "delete-table removes a DynamoDB table and ALL its data:\n\n\
             - All items are deleted\n\
             - Table configuration is lost\n\
             - Global secondary indexes deleted\n\
             - Cannot be undone\n\n\
             Backup first:\n  \
             aws dynamodb create-backup --table-name xxx --backup-name backup\n\n\
             Or export to S3:\n  \
             aws dynamodb export-table-to-point-in-time ..."
        ),
        // eks delete-cluster
        destructive_pattern!(
            "eks-delete",
            r"aws\s+eks\s+delete-cluster",
            "aws eks delete-cluster removes the entire EKS cluster.",
            Critical,
            "delete-cluster removes an EKS cluster:\n\n\
             - Control plane is deleted\n\
             - Node groups must be deleted separately first\n\
             - Kubernetes resources (deployments, services) are lost\n\
             - Persistent volumes may remain as orphaned EBS\n\n\
             Delete node groups first:\n  \
             aws eks list-nodegroups --cluster-name xxx\n  \
             aws eks delete-nodegroup --cluster-name xxx --nodegroup-name yyy\n\n\
             Then delete cluster."
        ),
        // ecr delete-repository
        destructive_pattern!(
            "ecr-delete-repository",
            r"aws\s+ecr\s+delete-repository",
            "aws ecr delete-repository permanently deletes the repository and its images.",
            High,
            "delete-repository removes an ECR repository:\n\n\
             - All images in the repository are deleted\n\
             - Repository configuration lost\n\
             - Requires --force if repository not empty\n\n\
             List images first:\n  \
             aws ecr list-images --repository-name xxx\n\n\
             Consider keeping critical images:\n  \
             docker pull <account>.dkr.ecr.<region>.amazonaws.com/repo:tag"
        ),
        // ecr batch-delete-image
        destructive_pattern!(
            "ecr-batch-delete-image",
            r"aws\s+ecr\s+batch-delete-image",
            "aws ecr batch-delete-image permanently deletes one or more images.",
            High,
            "batch-delete-image removes specific images from ECR:\n\n\
             - Images are permanently deleted\n\
             - Can delete by tag or digest\n\
             - Running containers using these images may fail on restart\n\n\
             List images:\n  \
             aws ecr describe-images --repository-name xxx\n\n\
             Verify image usage before deletion."
        ),
        // ecr delete-lifecycle-policy
        destructive_pattern!(
            "ecr-delete-lifecycle-policy",
            r"aws\s+ecr\s+delete-lifecycle-policy",
            "aws ecr delete-lifecycle-policy removes the repository lifecycle policy.",
            Medium,
            "delete-lifecycle-policy removes automatic image cleanup rules:\n\n\
             - Old images will no longer be automatically deleted\n\
             - May lead to storage cost increases\n\
             - Repository will retain all images indefinitely\n\n\
             View current policy:\n  \
             aws ecr get-lifecycle-policy --repository-name xxx"
        ),
        // CloudWatch Logs delete-log-group
        destructive_pattern!(
            "logs-delete-log-group",
            r"aws\s+logs\s+delete-log-group",
            "aws logs delete-log-group permanently deletes a log group and all events.",
            High,
            "delete-log-group removes a CloudWatch log group:\n\n\
             - All log streams are deleted\n\
             - All log events are lost\n\
             - Metric filters and subscriptions removed\n\
             - Cannot be undone\n\n\
             Export logs before deletion:\n  \
             aws logs create-export-task --log-group-name xxx \\\n    \
             --destination bucket --from 0 --to $(date +%s)000"
        ),
        // CloudWatch Logs delete-log-stream
        destructive_pattern!(
            "logs-delete-log-stream",
            r"aws\s+logs\s+delete-log-stream",
            "aws logs delete-log-stream permanently deletes a log stream and all events.",
            High,
            "delete-log-stream removes a specific log stream:\n\n\
             - All events in the stream are deleted\n\
             - Log group remains intact\n\
             - Cannot be undone\n\n\
             View log stream events before deletion:\n  \
             aws logs get-log-events --log-group-name xxx \\\n    \
             --log-stream-name yyy --limit 100"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::*;

    #[test]
    fn ec2_and_rds_patterns_block() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "aws ec2 delete-key-pair --key-name my-key",
            "removes AWS resources",
        );
        assert_blocks(
            &pack,
            "aws ec2 delete-image --image-id ami-12345678",
            "removes AWS resources",
        );
        assert_blocks(
            &pack,
            "aws rds delete-db-snapshot --db-snapshot-identifier my-snapshot",
            "destroys the database",
        );
        assert_blocks(
            &pack,
            "aws rds delete-db-cluster-snapshot --db-cluster-snapshot-identifier my-cluster-snapshot",
            "destroys the database",
        );
    }

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
