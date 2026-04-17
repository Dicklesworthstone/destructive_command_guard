//! AWS CLI patterns - protections against destructive aws commands.
//!
//! This includes patterns for:
//! - ec2 terminate-instances
//! - s3 rm --recursive
//! - rds delete-db-instance
//! - cloudformation delete-stack
//! - athena delete-data-catalog, delete-work-group
//! - athena queries: DROP DATABASE, DROP TABLE, TRUNCATE, DELETE without WHERE
//! - glue delete-database, delete-table, delete-partition

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the AWS pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "cloud.aws".to_string(),
        name: "AWS CLI",
        description: "Protects against destructive AWS CLI operations like terminate-instances, \
                      delete-db-instance, s3 rm --recursive, Athena/Glue catalog deletions, and \
                      destructive Athena queries (DROP DATABASE/TABLE, TRUNCATE, DELETE without WHERE)",
        keywords: &[
            "aws",
            "terminate",
            "delete",
            "s3",
            "ec2",
            "rds",
            "ecr",
            "logs",
            "athena",
            "glue",
            "DROP",
            "TRUNCATE",
            "DELETE",
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
        // Athena SELECT queries are safe (read-only)
        safe_pattern!(
            "athena-select",
            r#"aws\s+athena\s+start-query-execution\s+.*--query-string\s+['"]?\s*(?i)SELECT\s"#
        ),
        // Athena SHOW/DESCRIBE queries are safe
        safe_pattern!(
            "athena-show-describe",
            r#"aws\s+athena\s+start-query-execution\s+.*--query-string\s+['"]?\s*(?i)(?:SHOW|DESCRIBE)\s"#
        ),
        // Athena CREATE queries are safe (creating new resources)
        safe_pattern!(
            "athena-create",
            r#"aws\s+athena\s+start-query-execution\s+.*--query-string\s+['"]?[^'"]*\b(?i)CREATE\s+(?:TABLE|DATABASE|VIEW)\b"#
        ),
        // Athena INSERT queries are safe (adding data)
        safe_pattern!(
            "athena-insert",
            r#"aws\s+athena\s+start-query-execution\s+.*--query-string\s+['"]?[^'"]*\b(?i)INSERT\s+(?:INTO|OVERWRITE)\b"#
        ),
        // Athena UPDATE queries are safe (modifying specific data)
        safe_pattern!(
            "athena-update",
            r#"aws\s+athena\s+start-query-execution\s+.*--query-string\s+['"]?[^'"]*\b(?i)UPDATE\s+[a-zA-Z_][a-zA-Z0-9_.]*\s+SET\b"#
        ),
        // Athena DELETE with WHERE clause is safe (targeted deletion)
        safe_pattern!(
            "athena-delete-with-where",
            r#"aws\s+athena\s+start-query-execution\s+.*--query-string\s+['"]?[^'"]*\b(?i)DELETE\s+FROM\s+[a-zA-Z_][a-zA-Z0-9_.]*\s+WHERE\s"#
        ),
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
        // Athena delete-data-catalog
        destructive_pattern!(
            "athena-delete-data-catalog",
            r"aws\s+athena\s+delete-data-catalog",
            "aws athena delete-data-catalog permanently removes the data catalog.",
            Critical,
            "delete-data-catalog removes an Athena data catalog:\n\n\
             - All database and table definitions are lost\n\
             - Queries referencing this catalog will fail\n\
             - Cannot be undone (metadata lost)\n\
             - Underlying data in S3 is NOT deleted\n\n\
             List databases before deletion:\n  \
             aws athena list-databases --catalog-name xxx\n\n\
             Export catalog metadata first if needed."
        ),
        // Athena delete-named-query
        destructive_pattern!(
            "athena-delete-named-query",
            r"aws\s+athena\s+delete-named-query",
            "aws athena delete-named-query permanently removes a saved query.",
            Medium,
            "delete-named-query removes a saved query:\n\n\
             - Query definition is permanently deleted\n\
             - Query results in S3 are NOT affected\n\
             - Cannot be undone\n\n\
             View query before deletion:\n  \
             aws athena get-named-query --named-query-id xxx"
        ),
        // Athena delete-work-group
        destructive_pattern!(
            "athena-delete-work-group",
            r"aws\s+athena\s+delete-work-group",
            "aws athena delete-work-group permanently removes the workgroup.",
            High,
            "delete-work-group removes an Athena workgroup:\n\n\
             - Workgroup configuration is lost\n\
             - Named queries in the workgroup remain but need reassignment\n\
             - Running queries in this workgroup will fail\n\
             - Cannot be undone\n\n\
             List queries in workgroup:\n  \
             aws athena list-named-queries --work-group xxx\n\n\
             Use --recursive-delete-option to also delete queries."
        ),
        // Glue delete-database
        destructive_pattern!(
            "glue-delete-database",
            r"aws\s+glue\s+delete-database",
            "aws glue delete-database permanently removes the database and all table definitions.",
            Critical,
            "delete-database removes a Glue database:\n\n\
             - All table definitions are deleted\n\
             - Partitions metadata is lost\n\
             - Crawlers targeting this database will fail\n\
             - Cannot be undone (metadata lost)\n\
             - Underlying data in S3 is NOT deleted\n\n\
             List tables before deletion:\n  \
             aws glue get-tables --database-name xxx\n\n\
             Export database metadata first if needed."
        ),
        // Glue delete-table
        destructive_pattern!(
            "glue-delete-table",
            r"aws\s+glue\s+delete-table",
            "aws glue delete-table permanently removes the table definition.",
            High,
            "delete-table removes a Glue table:\n\n\
             - Table schema and metadata are deleted\n\
             - All partition definitions are lost\n\
             - Athena queries on this table will fail\n\
             - Cannot be undone\n\
             - Underlying data in S3 is NOT deleted\n\n\
             View table details before deletion:\n  \
             aws glue get-table --database-name xxx --name yyy\n\n\
             List partitions:\n  \
             aws glue get-partitions --database-name xxx --table-name yyy"
        ),
        // Glue delete-partition
        destructive_pattern!(
            "glue-delete-partition",
            r"aws\s+glue\s+delete-partition",
            "aws glue delete-partition permanently removes partition metadata.",
            High,
            "delete-partition removes partition metadata:\n\n\
             - Partition definition is deleted\n\
             - Queries on this partition will fail\n\
             - Cannot be undone\n\
             - Underlying data in S3 is NOT deleted\n\n\
             View partition before deletion:\n  \
             aws glue get-partition --database-name xxx \\\n    \
             --table-name yyy --partition-values val1 val2"
        ),
        // Glue batch-delete-table
        destructive_pattern!(
            "glue-batch-delete-table",
            r"aws\s+glue\s+batch-delete-table",
            "aws glue batch-delete-table permanently removes multiple table definitions.",
            Critical,
            "batch-delete-table removes multiple tables at once:\n\n\
             - All specified table schemas and metadata are deleted\n\
             - All partition definitions for these tables are lost\n\
             - Athena queries on these tables will fail\n\
             - Cannot be undone\n\
             - Underlying data in S3 is NOT deleted\n\n\
             List tables in database:\n  \
             aws glue get-tables --database-name xxx --max-results 100"
        ),
        // Glue batch-delete-partition
        destructive_pattern!(
            "glue-batch-delete-partition",
            r"aws\s+glue\s+batch-delete-partition",
            "aws glue batch-delete-partition permanently removes multiple partition definitions.",
            High,
            "batch-delete-partition removes multiple partitions:\n\n\
             - All specified partition definitions are deleted\n\
             - Queries on these partitions will fail\n\
             - Cannot be undone\n\
             - Underlying data in S3 is NOT deleted\n\n\
             List partitions first:\n  \
             aws glue get-partitions --database-name xxx --table-name yyy"
        ),
        // Glue delete-crawler
        destructive_pattern!(
            "glue-delete-crawler",
            r"aws\s+glue\s+delete-crawler",
            "aws glue delete-crawler permanently removes the crawler configuration.",
            Medium,
            "delete-crawler removes a Glue crawler:\n\n\
             - Crawler configuration is deleted\n\
             - Scheduled runs will stop\n\
             - Previously cataloged tables remain\n\
             - Cannot be undone\n\n\
             View crawler details:\n  \
             aws glue get-crawler --name xxx"
        ),
        // Glue delete-job
        destructive_pattern!(
            "glue-delete-job",
            r"aws\s+glue\s+delete-job",
            "aws glue delete-job permanently removes the ETL job definition.",
            High,
            "delete-job removes a Glue ETL job:\n\n\
             - Job definition and script are deleted\n\
             - Scheduled runs will stop\n\
             - Job run history is lost\n\
             - Cannot be undone\n\n\
             View job details:\n  \
             aws glue get-job --job-name xxx\n\n\
             Backup job script if stored in Glue."
        ),
        // Glue delete-dev-endpoint
        destructive_pattern!(
            "glue-delete-dev-endpoint",
            r"aws\s+glue\s+delete-dev-endpoint",
            "aws glue delete-dev-endpoint permanently removes the development endpoint.",
            Medium,
            "delete-dev-endpoint removes a Glue dev endpoint:\n\n\
             - Endpoint configuration is deleted\n\
             - Connection to notebooks/IDEs will fail\n\
             - Any uncommitted work on the endpoint may be lost\n\
             - Cannot be undone\n\n\
             View endpoint details:\n  \
             aws glue get-dev-endpoint --endpoint-name xxx"
        ),
        // Athena query: DROP DATABASE
        destructive_pattern!(
            "athena-query-drop-database",
            r#"aws\s+athena\s+start-query-execution\s+.*--query-string\s+['"]?[^'"]*\b(?i)DROP\s+DATABASE\b"#,
            "Athena query with DROP DATABASE permanently removes the database from the catalog.",
            Critical,
            "DROP DATABASE in Athena removes database metadata:\n\n\
             - All table definitions in the database are lost\n\
             - Glue catalog database is deleted\n\
             - Queries referencing this database will fail\n\
             - Cannot be undone (catalog metadata lost)\n\
             - Underlying data in S3 is NOT deleted\n\n\
             List tables before dropping:\n  \
             aws athena start-query-execution \\\n    \
             --query-string 'SHOW TABLES IN database_name'\n\n\
             Alternative: Use aws glue delete-database for better control"
        ),
        // Athena query: DROP TABLE
        destructive_pattern!(
            "athena-query-drop-table",
            r#"aws\s+athena\s+start-query-execution\s+.*--query-string\s+['"]?[^'"]*\b(?i)DROP\s+TABLE\b"#,
            "Athena query with DROP TABLE permanently removes the table from the catalog.",
            High,
            "DROP TABLE in Athena removes table metadata:\n\n\
             - Table schema and partitions are lost from catalog\n\
             - Queries on this table will fail\n\
             - Cannot be undone (catalog metadata lost)\n\
             - Underlying data in S3 is NOT deleted\n\n\
             Preview table before dropping:\n  \
             aws athena start-query-execution \\\n    \
             --query-string 'DESCRIBE table_name'\n\n\
             Check row count:\n  \
             aws athena start-query-execution \\\n    \
             --query-string 'SELECT COUNT(*) FROM table_name'\n\n\
             Alternative: Use aws glue delete-table for better control"
        ),
        // Athena query: ALTER TABLE DROP PARTITION
        destructive_pattern!(
            "athena-query-drop-partition",
            r#"aws\s+athena\s+start-query-execution\s+.*--query-string\s+['"]?[^'"]*\b(?i)ALTER\s+TABLE\s+.*\s+DROP\s+(?:IF\s+EXISTS\s+)?PARTITION\b"#,
            "Athena query with DROP PARTITION removes partition metadata from the catalog.",
            High,
            "ALTER TABLE ... DROP PARTITION removes partition metadata:\n\n\
             - Partition definition is lost from catalog\n\
             - Queries on this partition will fail\n\
             - Cannot be undone\n\
             - Underlying data in S3 is NOT deleted\n\n\
             List partitions before dropping:\n  \
             aws athena start-query-execution \\\n    \
             --query-string 'SHOW PARTITIONS table_name'\n\n\
             Alternative: Use aws glue delete-partition for better control"
        ),
        // Athena query: TRUNCATE TABLE (Iceberg tables only)
        destructive_pattern!(
            "athena-query-truncate",
            r#"aws\s+athena\s+start-query-execution\s+.*--query-string\s+['"]?[^'"]*\b(?i)TRUNCATE\s+TABLE\b"#,
            "Athena TRUNCATE TABLE permanently deletes all data from Iceberg tables.",
            Critical,
            "TRUNCATE TABLE in Athena (Iceberg tables only):\n\n\
             - Deletes ALL data files in S3\n\
             - Cannot be undone\n\
             - Only works with Iceberg tables\n\
             - Table structure and schema remain\n\n\
             Check row count before truncating:\n  \
             aws athena start-query-execution \\\n    \
             --query-string 'SELECT COUNT(*) FROM table_name'\n\n\
             Iceberg supports time travel for recovery:\n  \
             SELECT * FROM table_name FOR SYSTEM_TIME AS OF timestamp"
        ),
        // Athena query: DELETE without WHERE (Iceberg tables only)
        destructive_pattern!(
            "athena-query-delete-without-where",
            r#"aws\s+athena\s+start-query-execution\s+.*--query-string\s+['"]?[^'"]*\b(?i)DELETE\s+FROM\s+[a-zA-Z_][a-zA-Z0-9_.]*\s*(?:;|['"]|$)"#,
            "Athena DELETE without WHERE deletes all data from Iceberg tables.",
            Critical,
            "DELETE without WHERE removes ALL rows (Iceberg tables only):\n\n\
             - Deletes all data in the table\n\
             - Cannot be undone easily\n\
             - Only works with Iceberg tables\n\
             - Table structure remains\n\n\
             Add WHERE clause to limit deletion:\n  \
             DELETE FROM table WHERE condition\n\n\
             Check row count first:\n  \
             aws athena start-query-execution \\\n    \
             --query-string 'SELECT COUNT(*) FROM table_name'\n\n\
             Iceberg time travel may help recovery:\n  \
             SELECT * FROM table_name FOR SYSTEM_TIME AS OF timestamp"
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

    #[test]
    fn athena_patterns_block() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "aws athena delete-data-catalog --name my-catalog",
            "delete-data-catalog",
        );
        assert_blocks(
            &pack,
            "aws athena delete-named-query --named-query-id abc123",
            "delete-named-query",
        );
        assert_blocks(
            &pack,
            "aws athena delete-work-group --work-group my-workgroup",
            "delete-work-group",
        );
    }

    #[test]
    fn glue_patterns_block() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "aws glue delete-database --name my-database",
            "delete-database",
        );
        assert_blocks(
            &pack,
            "aws glue delete-table --database-name mydb --name mytable",
            "delete-table",
        );
        assert_blocks(
            &pack,
            "aws glue delete-partition --database-name mydb --table-name mytable --partition-values 2024",
            "delete-partition",
        );
        assert_blocks(
            &pack,
            "aws glue batch-delete-table --database-name mydb --tables-to-delete table1 table2",
            "batch-delete-table",
        );
        assert_blocks(
            &pack,
            "aws glue batch-delete-partition --database-name mydb --table-name mytable --partitions-to-delete x",
            "batch-delete-partition",
        );
        assert_blocks(
            &pack,
            "aws glue delete-crawler --name my-crawler",
            "delete-crawler",
        );
        assert_blocks(
            &pack,
            "aws glue delete-job --job-name my-etl-job",
            "delete-job",
        );
        assert_blocks(
            &pack,
            "aws glue delete-dev-endpoint --endpoint-name my-dev-endpoint",
            "delete-dev-endpoint",
        );
    }

    #[test]
    fn athena_query_drop_database_comprehensive() {
        let pack = create_pack();

        // Basic DROP DATABASE
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string "DROP DATABASE my_db""#,
            "DROP DATABASE",
        );

        // With IF EXISTS
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string 'DROP DATABASE IF EXISTS test_db'"#,
            "DROP DATABASE",
        );

        // With CASCADE
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string "DROP DATABASE mydb CASCADE""#,
            "DROP DATABASE",
        );

        // Case variations
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string "drop database users""#,
            "DROP DATABASE",
        );
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string "Drop Database MyDB""#,
            "DROP DATABASE",
        );

        // With semicolon
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string "DROP DATABASE test_db;""#,
            "DROP DATABASE",
        );

        // Query string in different position
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --result-configuration OutputLocation=s3://bucket/ --query-string "DROP DATABASE db""#,
            "DROP DATABASE",
        );

        // With execution context
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-execution-context Database=mydb --query-string "DROP DATABASE old_db""#,
            "DROP DATABASE",
        );
    }

    #[test]
    fn athena_query_drop_table_comprehensive() {
        let pack = create_pack();

        // Basic DROP TABLE
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string "DROP TABLE users""#,
            "DROP TABLE",
        );

        // With IF EXISTS
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string 'DROP TABLE IF EXISTS events'"#,
            "DROP TABLE",
        );

        // With schema prefix
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string "DROP TABLE mydb.users""#,
            "DROP TABLE",
        );

        // Case variations
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string "drop table customers""#,
            "DROP TABLE",
        );
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string "Drop Table Events""#,
            "DROP TABLE",
        );

        // With semicolon
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string "DROP TABLE old_data;""#,
            "DROP TABLE",
        );

        // Multiple flags
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-execution-context Database=analytics --result-configuration OutputLocation=s3://results/ --query-string "DROP TABLE users""#,
            "DROP TABLE",
        );
    }

    #[test]
    fn athena_query_drop_partition_comprehensive() {
        let pack = create_pack();

        // Basic DROP PARTITION
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string "ALTER TABLE events DROP PARTITION (year=2023)""#,
            "DROP PARTITION",
        );

        // Multiple partition columns
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string "ALTER TABLE logs DROP PARTITION (year=2023, month=01)""#,
            "DROP PARTITION",
        );

        // Case variations
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string "alter table data drop partition (dt='2024-01-01')""#,
            "DROP PARTITION",
        );

        // With IF EXISTS
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string "ALTER TABLE events DROP IF EXISTS PARTITION (year=2022)""#,
            "DROP PARTITION",
        );
    }

    #[test]
    fn athena_query_truncate_comprehensive() {
        let pack = create_pack();

        // Basic TRUNCATE
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string "TRUNCATE TABLE iceberg_table""#,
            "TRUNCATE",
        );

        // Case variations
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string "truncate table my_iceberg""#,
            "TRUNCATE",
        );
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string "Truncate Table Data""#,
            "TRUNCATE",
        );

        // With semicolon
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string "TRUNCATE TABLE logs;""#,
            "TRUNCATE",
        );

        // With schema prefix
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string "TRUNCATE TABLE mydb.iceberg_data""#,
            "TRUNCATE",
        );
    }

    #[test]
    fn athena_query_delete_without_where_comprehensive() {
        let pack = create_pack();

        // DELETE without WHERE - double quotes
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string "DELETE FROM iceberg_table""#,
            "DELETE",
        );

        // DELETE without WHERE - single quotes
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string 'DELETE FROM table_name'"#,
            "DELETE",
        );

        // With semicolon
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string 'DELETE FROM table_name;'"#,
            "DELETE",
        );

        // Case variations
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string "delete from users""#,
            "DELETE",
        );
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string "Delete From Events""#,
            "DELETE",
        );

        // With schema prefix
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --query-string "DELETE FROM mydb.iceberg_table""#,
            "DELETE",
        );

        // At end of command
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --result-configuration OutputLocation=s3://bucket/ --query-string "DELETE FROM users""#,
            "DELETE",
        );
    }

    #[test]
    fn athena_safe_select_queries() {
        let pack = create_pack();

        // Basic SELECT
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "SELECT * FROM users LIMIT 10""#,
        );

        // SELECT with complex query
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string 'SELECT COUNT(*) FROM events WHERE date > "2024-01-01"'"#,
        );

        // SELECT with JOINs
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "SELECT u.*, o.* FROM users u JOIN orders o ON u.id = o.user_id""#,
        );

        // Case variations
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "select * from table1""#,
        );
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "Select Count(*) From Data""#,
        );

        // With multiple flags
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-execution-context Database=mydb --result-configuration OutputLocation=s3://results/ --query-string "SELECT * FROM users""#,
        );
    }

    #[test]
    fn athena_safe_show_describe_queries() {
        let pack = create_pack();

        // SHOW DATABASES
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "SHOW DATABASES""#,
        );

        // SHOW TABLES
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "SHOW TABLES IN my_db""#,
        );

        // SHOW PARTITIONS
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "SHOW PARTITIONS events""#,
        );

        // DESCRIBE TABLE
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "DESCRIBE users""#,
        );
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "DESCRIBE mydb.users""#,
        );

        // Case variations
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "show databases""#,
        );
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "Describe Table_Name""#,
        );
    }

    #[test]
    fn athena_safe_create_insert_update_queries() {
        let pack = create_pack();

        // CREATE TABLE
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "CREATE TABLE new_table AS SELECT * FROM old_table""#,
        );
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "CREATE DATABASE test_db""#,
        );
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "CREATE VIEW user_view AS SELECT * FROM users""#,
        );

        // INSERT
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "INSERT INTO table VALUES (1,2,3)""#,
        );
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "INSERT OVERWRITE TABLE events SELECT * FROM staging""#,
        );

        // UPDATE
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "UPDATE iceberg_table SET status='active' WHERE id=5""#,
        );
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "UPDATE users SET last_login=NOW() WHERE active=true""#,
        );

        // Case variations
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "create table test (id int)""#,
        );
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "insert into data values (1)""#,
        );
    }

    #[test]
    fn athena_safe_delete_with_where() {
        let pack = create_pack();

        // DELETE with WHERE - should be allowed (targeted deletion)
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "DELETE FROM table WHERE id = 1""#,
        );
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "DELETE FROM users WHERE created_at < '2020-01-01'""#,
        );
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "DELETE FROM events WHERE date = '2024-01-01' AND status = 'processed'""#,
        );

        // Case variations
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "delete from logs where level = 'debug'""#,
        );
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "Delete From Data Where Age > 100""#,
        );

        // With schema prefix
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --query-string "DELETE FROM mydb.iceberg_table WHERE partition_col = '2023'""#,
        );
    }
}
