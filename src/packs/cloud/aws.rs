//! AWS CLI patterns - protections against destructive aws commands.
//!
//! This includes patterns for:
//! - ec2 terminate-instances
//! - s3 rm --recursive
//! - rds delete-db-instance
//! - cloudformation delete-stack
//! - athena delete-data-catalog/work-group and destructive query strings
//!   (DROP DATABASE/TABLE, TRUNCATE, DELETE without WHERE)
//! - glue delete-database/table/partition/crawler/job/dev-endpoint

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
                      destructive Athena queries (DROP, TRUNCATE, DELETE without WHERE)",
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
            // Coverage for the additional security/data-critical rules
            // ensures the pack is selected even for commands whose
            // service name isn't in the general keyword list.
            "kms",
            "secretsmanager",
            "route53",
            "cloudtrail",
            "redshift",
            "kinesis",
            "efs",
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
        // describe/list/get operations are safe (read-only).
        //
        // `(?:\s+--?\S+(?:\s+\S+)?)*` consumes only flag-value pairs (tokens
        // starting with `--?`) BEFORE the service name — so `describe-`,
        // `list-`, `get-` prefixes that appear as positional args inside a
        // destructive command (e.g. `--query describe-me`,
        // `--cli-input-json list-ids.json`) can NOT pose as the read-only
        // subcommand and bypass destructive checks.
        safe_pattern!(
            "aws-describe",
            r"aws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+\S+\s+describe-"
        ),
        safe_pattern!("aws-list", r"aws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+\S+\s+list-"),
        safe_pattern!("aws-get", r"aws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+\S+\s+get-"),
        // s3 ls is safe
        safe_pattern!("s3-ls", r"aws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+s3\s+ls(?=\s|$)"),
        // s3 cp is generally safe (copy)
        safe_pattern!("s3-cp", r"aws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+s3\s+cp(?=\s|$)"),
        // EC2 commands expose a real `--dry-run` option that checks
        // permissions without making the request. Keep this narrowly scoped:
        // a global `aws ... --dry-run` safe pattern lets unsupported dry-run
        // text bypass destructive commands in services such as IAM and
        // CloudFormation.
        safe_pattern!(
            "ec2-terminate-dry-run",
            r"aws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ec2\s+terminate-instances\b(?![^\n;&|]*(?:\s--no-dry-run(?:\s|$)|\s--dry-run=false(?:\s|$)))[^\n;&|]*\s--dry-run(?:\s|$)[^\n;&|]*$"
        ),
        safe_pattern!(
            "ec2-delete-dry-run",
            r"aws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ec2\s+delete-[^\s;&|]+\b(?![^\n;&|]*(?:\s--no-dry-run(?:\s|$)|\s--dry-run=false(?:\s|$)))[^\n;&|]*\s--dry-run(?:\s|$)[^\n;&|]*$"
        ),
        // sts get-caller-identity is safe
        safe_pattern!(
            "sts-identity",
            r"aws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+sts\s+get-caller-identity(?=\s|$)"
        ),
        // cloudformation describe/list
        safe_pattern!(
            "cfn-describe",
            r"aws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+cloudformation\s+(?:describe|list)-"
        ),
        // ecr get-login-password is safe
        safe_pattern!(
            "ecr-login",
            r"aws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ecr\s+get-login"
        ),
        // --- Athena start-query-execution: non-destructive query shapes ---
        //
        // Each pattern anchors the safe SQL verb directly on the opening
        // of `--query-string` (after any `=`/whitespace and an optional
        // single/double quote). This is deliberate: `\bSELECT\b` anywhere
        // in the command would let `DROP TABLE /* SELECT */ prod` bypass
        // the destructive check, since safe patterns short-circuit
        // `matches_safe` first.  Requiring the verb at the head of the
        // query-string matches real usage (AWS Athena's
        // `start-query-execution` takes a single statement and rejects
        // semicolon-separated compound statements, so the head verb is
        // the effective verb).
        //
        // Only verbs that would otherwise be swept up by a destructive
        // regex need a safe pattern here — `athena-delete-with-where`
        // exists specifically to escape `athena-query-delete-without-where`
        // (which matches every `DELETE FROM …`). Pure SELECT / SHOW /
        // DESCRIBE / EXPLAIN / CREATE / INSERT / UPDATE queries already
        // fall through both sets and are allowed by default, so we keep
        // the surface small.
        //
        // The trailing `(?!.*;\s*[A-Za-z])` is a negative lookahead that
        // rejects a `;` followed by more SQL (a second statement). Two
        // shapes block:
        //   DELETE … WHERE id=1; DROP TABLE t       (compound statement)
        //   DELETE … WHERE id=1;\n DELETE FROM u    (multi-line compound)
        // A bare trailing `;` with no SQL after it (`DELETE … WHERE a=1;`)
        // is still allowed — it's a common habit from SQL CLI tooling.
        // SQL comments after `;` (`; -- …`, `; /* … */`) also pass, since
        // `-` and `/` aren't ASCII letters; a comment after a scoped
        // DELETE is benign.
        safe_pattern!(
            "athena-delete-with-where",
            // `aws\b.*?\bathena\b` instead of `aws\s+athena` so global
            // flags between `aws` and the service (e.g.
            // `aws --profile prod athena …`, `aws --region us-east-1 …`)
            // don't let the pattern silently desync and slip the command
            // through as "not an athena command."
            //
            // Table identifier is `[^\s;]+` rather than `\S+` — otherwise
            // a greedy `\S+` absorbs the `;` in `DELETE FROM t; DELETE
            // FROM u WHERE id=1`, letting the regex slide forward to the
            // second (scoped) DELETE's WHERE and ALLOWING the leading
            // unscoped DELETE. Excluding `;` from the identifier forces
            // the regex to stop at the statement boundary, so the
            // destructive `athena-query-delete-without-where` rule still
            // fires on the unscoped head statement.
            //
            // The character class still covers bare names (`t`),
            // schema-qualified names (`db.t`), double-quoted identifiers
            // (`"my-t"`), and backtick-quoted identifiers (`` `my-t` ``).
            r#"(?i)aws\b.*?\bathena\s+start-query-execution\b.*?--query-string[=\s]+['"]?\s*DELETE\s+FROM\s+[^\s;]+\s+.*?\bWHERE\b(?!.*;\s*[A-Za-z])"#
        ),
    ]
}

#[allow(clippy::too_many_lines)]
fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // ec2 terminate-instances
        destructive_pattern!(
            "ec2-terminate",
            r"aws\b.*?\bec2\s+terminate-instances",
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
            r"aws\b.*?\bec2\s+delete-",
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
            r"aws\b.*?\bs3\s+rm\s+.*--recursive",
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
            r"aws\b.*?\bs3\s+rb\b",
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
            r"aws\b.*?\bs3api\s+delete-bucket",
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
            r"aws\b.*?\brds\s+delete-",
            "aws rds delete-* permanently destroys the database resource (instance, cluster, snapshot, parameter group, subnet group, etc.).",
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
            r"aws\b.*?\bcloudformation\s+delete-stack",
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
            r"aws\b.*?\blambda\s+delete-",
            "aws lambda delete-* permanently removes a Lambda resource (function, alias, layer version, event source mapping, etc.).",
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
            r"aws\b.*?\biam\s+delete-",
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
            r"aws\b.*?\bdynamodb\s+delete-table",
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
            r"aws\b.*?\beks\s+delete-cluster",
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
            r"aws\b.*?\becr\s+delete-repository",
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
            r"aws\b.*?\becr\s+batch-delete-image",
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
            r"aws\b.*?\becr\s+delete-lifecycle-policy",
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
            r"aws\b.*?\blogs\s+delete-log-group",
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
            r"aws\b.*?\blogs\s+delete-log-stream",
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
        // ---- Security- and data-critical services uncovered by the
        //       previous set of AWS rules. ----------------------------------
        destructive_pattern!(
            "kms-schedule-key-deletion",
            r"aws\b.*?\bkms\s+schedule-key-deletion",
            "aws kms schedule-key-deletion schedules a KMS key for irreversible deletion — all data encrypted with it becomes unreadable.",
            Critical,
            "schedule-key-deletion starts an irreversible KMS key destruction:\n\n\
             - After the waiting period (min 7 days), the key is deleted\n\
             - Every piece of data encrypted under this key becomes\n  \
               permanently undecryptable\n\
             - CancelKeyDeletion can abort within the waiting window\n\
             - After deletion: data loss is unrecoverable\n\n\
             Prefer `disable-key` if you want to stop usage reversibly:\n  \
             aws kms disable-key --key-id xxx"
        ),
        destructive_pattern!(
            "secretsmanager-delete-secret",
            r"aws\b.*?\bsecretsmanager\s+delete-secret",
            "aws secretsmanager delete-secret destroys a stored secret — typically irrecoverable credentials.",
            Critical,
            "delete-secret removes a Secrets Manager secret:\n\n\
             - Default 30-day recovery window unless --force-delete-without-recovery\n\
             - With --force-delete-without-recovery: immediate & unrecoverable\n\
             - All rotation history, versions, and values are lost\n\
             - Credentials for production services can become\n  \
               unrecoverable if not backed up\n\n\
             Restore during the recovery window:\n  \
             aws secretsmanager restore-secret --secret-id xxx"
        ),
        destructive_pattern!(
            "route53-delete-hosted-zone",
            r"aws\b.*?\broute53\s+delete-hosted-zone",
            "aws route53 delete-hosted-zone removes a DNS zone — domains stop resolving.",
            Critical,
            "delete-hosted-zone removes a Route53 hosted zone:\n\n\
             - All DNS records in the zone are deleted\n\
             - Domains configured with this zone's nameservers stop resolving\n\
             - Production traffic can become unroutable immediately\n\
             - Cannot be undone\n\n\
             Export records first:\n  \
             aws route53 list-resource-record-sets --hosted-zone-id xxx > zone-backup.json"
        ),
        destructive_pattern!(
            "cloudtrail-delete-trail",
            r"aws\b.*?\bcloudtrail\s+delete-trail",
            "aws cloudtrail delete-trail removes an audit trail — compliance/forensics impact.",
            Critical,
            "delete-trail removes a CloudTrail trail:\n\n\
             - Trail configuration is deleted\n\
             - Historical log files in S3 are NOT deleted (still queryable)\n\
             - Future events stop being recorded via this trail\n\
             - Compliance regimes (SOC2, PCI, HIPAA) may require this trail\n\n\
             Consider stop-logging if pausing is sufficient:\n  \
             aws cloudtrail stop-logging --name xxx"
        ),
        destructive_pattern!(
            "redshift-delete-cluster",
            r"aws\b.*?\bredshift\s+delete-cluster",
            "aws redshift delete-cluster destroys a Redshift cluster and all loaded data.",
            Critical,
            "delete-cluster removes a Redshift cluster:\n\n\
             - With --skip-final-cluster-snapshot: ALL data is destroyed immediately\n\
             - Without --skip-final-cluster-snapshot: cluster deleted after final snapshot\n\
             - Connected BI tools, ETL pipelines, and downstream jobs break\n\
             - Very expensive to restore (hours of snapshot restore)\n\n\
             Preview:\n  \
             aws redshift describe-clusters --cluster-identifier xxx"
        ),
        destructive_pattern!(
            "kinesis-delete-stream",
            r"aws\b.*?\bkinesis\s+delete-stream",
            "aws kinesis delete-stream destroys a data stream — in-flight records are lost.",
            Critical,
            "delete-stream removes a Kinesis data stream:\n\n\
             - All shards, consumers, and in-flight records are lost\n\
             - Producers and consumers disconnect immediately\n\
             - Data retained only as long as EnhancedMonitoring/FanOut sinks preserved it\n\
             - Stream name is reserved briefly; re-creation may fail until it clears"
        ),
        destructive_pattern!(
            "efs-delete-file-system",
            r"aws\b.*?\befs\s+delete-file-system",
            "aws efs delete-file-system destroys an EFS filesystem — all files and mount targets are lost.",
            Critical,
            "delete-file-system removes an EFS filesystem:\n\n\
             - All files in the filesystem are permanently deleted\n\
             - Mount targets and access points are removed\n\
             - Cannot be undone (no built-in recovery)\n\
             - Take a backup first via AWS Backup or rsync out:\n  \
             aws backup start-backup-job --backup-vault-name xxx \\\n    \
             --resource-arn arn:aws:elasticfilesystem:...:file-system/fs-xxx \\\n    \
             --iam-role-arn arn:aws:iam::...:role/backup-role"
        ),
        destructive_pattern!(
            "s3api-delete-object",
            // No `\b` after `delete-object` so the same rule catches
            // `delete-object` (single), `delete-objects` (batch, arguably
            // WORSE because it can drop thousands at once), and
            // `delete-object-tagging` (metadata removal). All three are
            // destructive and share the same guidance.
            r"aws\b.*?\bs3api\s+delete-object",
            "aws s3api delete-object[s]/delete-object-tagging — object(s) or tags are gone unless bucket versioning is enabled.",
            High,
            "delete-object / delete-objects / delete-object-tagging:\n\n\
             - Without bucket versioning: objects or tags are permanently gone\n\
             - With versioning (objects only): a delete marker is added; past versions recoverable\n\
             - delete-objects is BATCH (up to 1000 keys per call) — a misfire can wipe thousands\n\
             - No trash/recycle bin\n\n\
             Check versioning first:\n  \
             aws s3api get-bucket-versioning --bucket xxx\n\n\
             Preview the keys about to be deleted:\n  \
             aws s3api list-objects-v2 --bucket xxx --prefix yyy/"
        ),
        // ---- Athena catalog / workgroup deletions ---------------------------
        //
        // Every Athena + Glue pattern below uses `aws\b.*?\b<svc>\b` in
        // place of `aws\s+<svc>\s+` so that global flags between `aws`
        // and the service name (`--profile`, `--region`, `--debug`,
        // `--output`, `--endpoint-url`, …) don't silently neuter the
        // rule. See `athena_patterns_match_with_global_flags_before_service`
        // for the regression coverage.
        destructive_pattern!(
            "athena-delete-data-catalog",
            r"aws\b.*?\bathena\s+delete-data-catalog\b",
            "aws athena delete-data-catalog removes the data catalog and all \
             database/table definitions tied to it.",
            Critical,
            "delete-data-catalog detaches and removes an Athena DataCatalog:\n\n\
             - All databases and table definitions linked to the catalog are lost\n\
             - Queries referencing this catalog will fail\n\
             - Underlying S3 data is NOT deleted, but becomes unreadable via Athena\n\
             - Cannot be undone (catalog metadata is gone)\n\n\
             List catalogs first:\n  \
             aws athena list-data-catalogs\n  \
             aws athena get-data-catalog --name xxx"
        ),
        destructive_pattern!(
            "athena-delete-work-group",
            r"aws\b.*?\bathena\s+delete-work-group\b",
            "aws athena delete-work-group removes the Athena workgroup and its configuration.",
            High,
            "delete-work-group removes an Athena workgroup:\n\n\
             - Query history, IAM-scoped configuration, and cost controls are lost\n\
             - In-flight queries are cancelled\n\
             - With --recursive-delete-option, named queries in the workgroup are also dropped\n\n\
             Preview first:\n  \
             aws athena get-work-group --work-group xxx"
        ),
        destructive_pattern!(
            "athena-delete-named-query",
            r"aws\b.*?\bathena\s+delete-named-query\b",
            "aws athena delete-named-query permanently removes a saved query.",
            Medium,
            "delete-named-query deletes a saved Athena query:\n\n\
             - The stored query text and metadata are removed\n\
             - No data is lost, but the query must be rewritten from scratch if \
             it wasn't stored elsewhere\n\n\
             Retrieve the query before deleting:\n  \
             aws athena get-named-query --named-query-id xxx"
        ),
        // ---- Athena destructive query strings -------------------------------
        // These intentionally run *after* the safe patterns above, so a
        // SELECT / SHOW / CREATE / INSERT / UPDATE…SET / DELETE…WHERE
        // will match as safe first and never reach these checks.
        destructive_pattern!(
            "athena-query-drop-database",
            r"(?is)aws\b.*?\bathena\s+start-query-execution\b.*\bDROP\s+(?:DATABASE|SCHEMA)\b",
            "Athena DROP DATABASE/SCHEMA removes the database from the Glue catalog.",
            Critical,
            "DROP DATABASE/SCHEMA removes a database from the Glue catalog:\n\n\
             - All table definitions inside the database are lost\n\
             - Queries referencing this database will fail\n\
             - Underlying S3 data is NOT deleted, just unreadable via Athena\n\
             - Cannot be undone (catalog metadata lost)\n\n\
             List tables first:\n  \
             aws athena start-query-execution \\\n    \
             --query-string 'SHOW TABLES IN database_name'\n\n\
             For more control, use `aws glue delete-database` \
             (which this pack also blocks)."
        ),
        destructive_pattern!(
            "athena-query-drop-table",
            r"(?is)aws\b.*?\bathena\s+start-query-execution\b.*\bDROP\s+(?:TABLE|VIEW|EXTERNAL\s+TABLE)\b",
            "Athena DROP TABLE/VIEW removes the table definition from the Glue catalog.",
            High,
            "DROP TABLE/VIEW removes a table or view from the catalog:\n\n\
             - Table definition is lost\n\
             - Queries referencing this table will fail\n\
             - Underlying S3 data is NOT deleted\n\n\
             Preview schema first:\n  \
             aws athena start-query-execution \\\n    \
             --query-string 'SHOW CREATE TABLE db.table'"
        ),
        destructive_pattern!(
            "athena-query-truncate",
            r"(?is)aws\b.*?\bathena\s+start-query-execution\b.*\bTRUNCATE\s+TABLE\b",
            "Athena TRUNCATE TABLE deletes all rows from an Iceberg table.",
            Critical,
            "TRUNCATE TABLE in Athena (Iceberg tables):\n\n\
             - All rows are deleted from the table\n\
             - The table definition is preserved\n\
             - Underlying S3 objects are removed for Iceberg tables\n\
             - Cannot be undone (no implicit snapshot retention)\n\n\
             Consider a targeted DELETE with WHERE clause instead."
        ),
        destructive_pattern!(
            "athena-query-string-from-file",
            // AWS CLI's `file://` and `fileb://` protocols load the
            // parameter value from a file — so the SQL content never
            // appears on the command line and the DROP/TRUNCATE/
            // unscoped-DELETE regexes have nothing to grep. Block the
            // shape so users can't hide destructive SQL inside
            // `--query-string file://query.sql`.
            r#"(?i)aws\b.*?\bathena\s+start-query-execution\b.*--query-string[=\s]+['"]?\s*(?:file|fileb)://"#,
            "Athena --query-string loaded from file:// or fileb:// — SQL content is opaque to the guard.",
            High,
            "Athena `start-query-execution --query-string file://…` loads the\n\
             SQL from disk, so DCG can't inspect the statement. The file may\n\
             contain DROP DATABASE, TRUNCATE TABLE, or an unscoped DELETE.\n\n\
             Prefer the inline form so the guard can see what you're running:\n  \
             aws athena start-query-execution \\\n    \
             --query-string 'SELECT … FROM …'\n\n\
             If a file-loaded query is genuinely required, cat it first so\n\
             the content is inspectable, and allowlist this rule in your\n\
             project DCG config with a justification."
        ),
        destructive_pattern!(
            "athena-cli-input-file",
            // `--cli-input-json file://…` / `--cli-input-yaml file://…`
            // loads the whole invocation (including QueryString) from a
            // file on disk. DCG can't inspect the file, so destructive
            // SQL inside it is invisible. Only block the file-backed
            // form — inline JSON/YAML is still visible to the broader
            // DROP/TRUNCATE/DELETE regexes elsewhere in the pack, so no
            // need to over-block inline usage.
            r#"(?i)aws\b.*?\bathena\s+start-query-execution\b.*--cli-input-(?:json|yaml)[=\s]+['"]?\s*(?:file|fileb)://"#,
            "Athena --cli-input-json/yaml loaded from file:// or fileb:// — content is opaque to the guard.",
            High,
            "`--cli-input-json file://…` (or `-yaml`) supplies the whole\n\
             invocation — including QueryString — from a file on disk. DCG\n\
             only greps the command line, so a DROP or TRUNCATE buried in\n\
             the JSON/YAML body on disk slips past every other Athena rule.\n\n\
             Inline JSON/YAML (e.g. `--cli-input-json '{…}'`) is still\n\
             allowed because DCG can read the literal in the command line\n\
             and catch a DROP there.\n\n\
             Prefer explicit `--query-string '…'`, or inline the JSON blob.\n\
             If the file-backed form is genuinely required, allowlist this\n\
             rule with a justification."
        ),
        destructive_pattern!(
            "athena-query-delete-without-where",
            // Match DELETE FROM <table> with no WHERE later in the query.
            // (The safe `athena-delete-with-where` pattern short-circuits
            // `matches_safe` first, so this only fires on unscoped DELETE.)
            // `\S+` is deliberately broad so quoted identifiers like
            // `"my-table"` or `` `my-table` `` can't evade the block.
            r"(?is)aws\b.*?\bathena\s+start-query-execution\b.*\bDELETE\s+FROM\s+\S+",
            "Athena DELETE without a WHERE clause removes all rows from the target table.",
            Critical,
            "DELETE FROM <table> without a WHERE clause:\n\n\
             - Every row in the table is deleted\n\
             - Iceberg tables: underlying S3 data is dropped\n\
             - Hive tables: operation fails (Athena rejects unscoped DELETE on Hive)\n\
             - Cannot be undone (no automatic snapshots)\n\n\
             Rewrite with a WHERE clause that scopes the deletion:\n  \
             DELETE FROM db.table WHERE <predicate>"
        ),
        // ---- Glue catalog deletions -----------------------------------------
        destructive_pattern!(
            "glue-delete-database",
            r"aws\b.*?\bglue\s+delete-database\b",
            "aws glue delete-database removes the database and every table definition inside it.",
            Critical,
            "delete-database drops a Glue database and every table/partition in it:\n\n\
             - All table definitions in the database are lost\n\
             - Athena / EMR / Redshift Spectrum queries referencing these tables will fail\n\
             - Underlying S3 data is preserved, but becomes unreadable via the catalog\n\
             - Cannot be undone (metadata is gone)\n\n\
             List tables first:\n  \
             aws glue get-tables --database-name xxx"
        ),
        destructive_pattern!(
            "glue-delete-table",
            r"aws\b.*?\bglue\s+delete-table\b",
            "aws glue delete-table removes the table definition from the catalog.",
            High,
            "delete-table removes a Glue table definition:\n\n\
             - Table schema and partition metadata are lost\n\
             - Underlying S3 data is NOT deleted\n\
             - Queries referencing this table will fail\n\n\
             Preview the table first:\n  \
             aws glue get-table --database-name xxx --name yyy"
        ),
        destructive_pattern!(
            "glue-batch-delete-table",
            r"aws\b.*?\bglue\s+batch-delete-table\b",
            "aws glue batch-delete-table removes multiple table definitions in one call.",
            Critical,
            "batch-delete-table drops several Glue tables in one API call:\n\n\
             - All listed table definitions are lost\n\
             - Underlying S3 data is preserved\n\
             - Queries referencing these tables will fail\n\
             - Cannot be undone\n\n\
             Review the exact names first:\n  \
             aws glue get-tables --database-name xxx"
        ),
        destructive_pattern!(
            "glue-delete-partition",
            r"aws\b.*?\bglue\s+delete-partition\b",
            "aws glue delete-partition removes partition metadata; the partition is no longer \
             queryable until recreated.",
            High,
            "delete-partition removes a Glue partition's metadata:\n\n\
             - Partition metadata is lost (column stats, location pointer)\n\
             - Underlying S3 data is preserved\n\
             - Queries scoped to that partition will return no rows until re-registered"
        ),
        destructive_pattern!(
            "glue-batch-delete-partition",
            r"aws\b.*?\bglue\s+batch-delete-partition\b",
            "aws glue batch-delete-partition removes multiple partition definitions in one call.",
            High,
            "batch-delete-partition drops several Glue partitions at once:\n\n\
             - Every listed partition's metadata is lost\n\
             - Underlying S3 data is preserved\n\
             - Recreate via `aws glue batch-create-partition` if you still have the list"
        ),
        destructive_pattern!(
            "glue-delete-crawler",
            r"aws\b.*?\bglue\s+delete-crawler\b",
            "aws glue delete-crawler removes the crawler configuration.",
            Medium,
            "delete-crawler removes a Glue crawler:\n\n\
             - Crawler configuration (targets, schedule, schema detection rules) is lost\n\
             - Schedules and classifiers tied to the crawler are orphaned\n\
             - Can be re-created from Infrastructure-as-Code if present"
        ),
        destructive_pattern!(
            "glue-delete-job",
            r"aws\b.*?\bglue\s+delete-job\b",
            "aws glue delete-job removes the ETL job definition and all of its run history.",
            High,
            "delete-job removes a Glue ETL job:\n\n\
             - Job script reference, connections, arguments, and schedule are lost\n\
             - All run history and metrics for the job are removed\n\
             - Scheduled triggers referencing the job will fail\n\n\
             Export the job definition first:\n  \
             aws glue get-job --job-name xxx > job-backup.json"
        ),
        destructive_pattern!(
            "glue-delete-dev-endpoint",
            r"aws\b.*?\bglue\s+delete-dev-endpoint\b",
            "aws glue delete-dev-endpoint tears down the development endpoint and any attached \
             SageMaker notebook configuration.",
            Medium,
            "delete-dev-endpoint shuts down a Glue DevEndpoint:\n\n\
             - Endpoint is stopped and deleted\n\
             - Attached SageMaker notebook (if any) must be cleaned up separately\n\
             - Ongoing sessions / jobs on the endpoint are terminated"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::*;

    #[test]
    fn safe_describe_list_get_patterns_also_match_with_global_flags() {
        // Verify the generic `aws-describe`/`aws-list`/`aws-get` safe
        // patterns still allowlist read-only commands when global flags
        // precede the service. Previously the `aws\s+\S+\s+describe-`
        // form was broken: `\S+` greedy-ate `--profile`, then
        // `\s+describe-` tripped on the flag value.
        let pack = create_pack();
        assert_allows(&pack, "aws --profile prod ec2 describe-instances");
        assert_allows(
            &pack,
            "aws --region us-east-1 --profile prod ec2 describe-volumes",
        );
        assert_allows(&pack, "aws --profile prod s3api list-buckets");
        assert_allows(&pack, "aws --profile prod iam get-user");
        // And a read-only command through a wrapper is also fine:
        assert_allows(&pack, "aws-vault exec prod -- aws ec2 describe-instances");
    }

    #[test]
    fn security_and_data_critical_services_blocked() {
        // New rules covering AWS services whose delete/destroy APIs can
        // lose data irreversibly (KMS keys, secrets, DNS zones, audit
        // trails, Redshift clusters, Kinesis streams, EFS) or cause
        // significant outages (S3 object deletion).
        let pack = create_pack();

        // KMS schedule-key-deletion — encryption key destruction,
        // irreversibly locks out all data encrypted under the key.
        assert_blocks(
            &pack,
            "aws kms schedule-key-deletion --key-id arn:aws:kms:us-east-1:111:key/abc --pending-window-in-days 7",
            "KMS key",
        );
        // Secrets Manager delete-secret — credential loss.
        assert_blocks(
            &pack,
            "aws secretsmanager delete-secret --secret-id prod/db/password --force-delete-without-recovery",
            "stored secret",
        );
        // Route53 delete-hosted-zone — DNS outage.
        assert_blocks(
            &pack,
            "aws route53 delete-hosted-zone --id Z1234567890",
            "DNS zone",
        );
        // CloudTrail delete-trail — compliance/forensics.
        assert_blocks(
            &pack,
            "aws cloudtrail delete-trail --name prod-audit",
            "audit trail",
        );
        // Redshift delete-cluster — large-scale data loss.
        assert_blocks(
            &pack,
            "aws redshift delete-cluster --cluster-identifier prod-analytics --skip-final-cluster-snapshot",
            "Redshift cluster",
        );
        // Kinesis delete-stream — data stream loss.
        assert_blocks(
            &pack,
            "aws kinesis delete-stream --stream-name prod-events",
            "data stream",
        );
        // EFS delete-file-system — filesystem data loss.
        assert_blocks(
            &pack,
            "aws efs delete-file-system --file-system-id fs-abc12345",
            "EFS filesystem",
        );
        // S3 delete-object — targeted object deletion.
        assert_blocks(
            &pack,
            "aws s3api delete-object --bucket prod-logs --key critical.log",
            "object",
        );
        // S3 delete-objects (batch) — same rule should fire.
        assert_blocks(
            &pack,
            "aws s3api delete-objects --bucket prod-logs --delete file://keys.json",
            "object",
        );
        // S3 delete-object-tagging — metadata loss, same rule.
        assert_blocks(
            &pack,
            "aws s3api delete-object-tagging --bucket prod-logs --key prod.log",
            "object",
        );
        // And all of the above still block through global flags / wrappers:
        assert_blocks(
            &pack,
            "aws --profile prod kms schedule-key-deletion --key-id abc",
            "KMS key",
        );
        assert_blocks(
            &pack,
            "aws-vault exec prod -- aws secretsmanager delete-secret --secret-id prod/db",
            "stored secret",
        );
    }

    #[test]
    fn destructive_subcommand_coverage_gaps() {
        // Pre-existing pattern-coverage gaps: the curated subcommand
        // lists on ec2/iam/rds/lambda leave several destructive
        // commands uncovered entirely. Any AWS `delete-*` subcommand
        // removes something; narrow allowlists of specific subcommands
        // miss the long tail.
        let pack = create_pack();

        // IAM delete-access-key: removes a user's API credentials.
        assert_blocks(
            &pack,
            "aws iam delete-access-key --user-name admin --access-key-id AKIAX123",
            "IAM",
        );
        // IAM delete-login-profile: removes a user's console access.
        assert_blocks(
            &pack,
            "aws iam delete-login-profile --user-name admin",
            "IAM",
        );
        // IAM delete-saml-provider: removes SSO federation.
        assert_blocks(
            &pack,
            "aws iam delete-saml-provider --saml-provider-arn arn:aws:iam::111:saml-provider/corp",
            "IAM",
        );
        // EC2 delete-nat-gateway: tears down NAT, takes out public egress.
        assert_blocks(
            &pack,
            "aws ec2 delete-nat-gateway --nat-gateway-id nat-abc",
            "AWS resources",
        );
        // EC2 delete-internet-gateway: takes out the VPC internet gateway.
        assert_blocks(
            &pack,
            "aws ec2 delete-internet-gateway --internet-gateway-id igw-abc",
            "AWS resources",
        );
        // EC2 delete-vpn-connection: takes out a VPN tunnel.
        assert_blocks(
            &pack,
            "aws ec2 delete-vpn-connection --vpn-connection-id vpn-abc",
            "AWS resources",
        );
        // RDS delete-db-parameter-group: removes tuning config.
        assert_blocks(
            &pack,
            "aws rds delete-db-parameter-group --db-parameter-group-name prod-params",
            "database",
        );
        // Lambda delete-alias: removes a named alias for a function.
        assert_blocks(
            &pack,
            "aws lambda delete-alias --function-name my-fn --name PROD",
            "Lambda",
        );
        // Lambda delete-layer-version: removes a shared dep layer.
        assert_blocks(
            &pack,
            "aws lambda delete-layer-version --layer-name libs --version-number 5",
            "Lambda",
        );
    }

    #[test]
    fn existing_aws_patterns_also_match_with_global_flags() {
        // Class-bug sweep: the same `aws --profile / --region / --debug`
        // bypass that affected my new athena/glue patterns equally
        // affects every pre-existing AWS rule in this file. Any
        // multi-profile shop (which is every non-trivial org) is
        // silently exempt from DCG protection unless we fix them all.
        let pack = create_pack();
        // ec2 terminate
        assert_blocks(
            &pack,
            "aws --profile prod ec2 terminate-instances --instance-ids i-abc",
            "terminate-instances",
        );
        // ec2 delete-*
        assert_blocks(
            &pack,
            "aws --region us-east-1 ec2 delete-snapshot --snapshot-id snap-abc",
            "removes AWS resources",
        );
        // s3 rm --recursive
        assert_blocks(
            &pack,
            "aws --profile prod s3 rm s3://bucket/prefix --recursive",
            "recursive",
        );
        // rds delete
        assert_blocks(
            &pack,
            "aws --profile prod rds delete-db-instance --db-instance-identifier prod-db",
            "destroys the database",
        );
        // cloudformation delete-stack
        assert_blocks(
            &pack,
            "aws --region us-east-1 cloudformation delete-stack --stack-name prod",
            "delete-stack",
        );
        // lambda delete
        assert_blocks(
            &pack,
            "aws --profile prod lambda delete-function --function-name prod-fn",
            "Lambda",
        );
        // iam delete-*
        assert_blocks(
            &pack,
            "aws --profile prod iam delete-user --user-name admin",
            "IAM",
        );
        // dynamodb delete-table
        assert_blocks(
            &pack,
            "aws --profile prod dynamodb delete-table --table-name Customers",
            "delete-table",
        );
        // eks delete-cluster
        assert_blocks(
            &pack,
            "aws --profile prod eks delete-cluster --name prod",
            "delete-cluster",
        );
        // ecr delete-repository
        assert_blocks(
            &pack,
            "aws --profile prod ecr delete-repository --repository-name app",
            "delete-repository",
        );
        // logs delete-log-group
        assert_blocks(
            &pack,
            "aws --profile prod logs delete-log-group --log-group-name /aws/lambda/prod",
            "delete-log-group",
        );
        // s3api delete-bucket
        assert_blocks(
            &pack,
            "aws --profile prod s3api delete-bucket --bucket prod-bucket",
            "delete-bucket",
        );
        // s3 rb
        assert_blocks(&pack, "aws --profile prod s3 rb s3://prod-bucket", "s3 rb");
    }

    #[test]
    fn aws_dry_run_safe_patterns_only_cover_real_ec2_dry_run_options() {
        let pack = create_pack();

        assert_safe_pattern_matches(
            &pack,
            "aws ec2 terminate-instances --instance-ids i-abc --dry-run",
        );
        assert_safe_pattern_matches(
            &pack,
            "aws --profile prod ec2 delete-snapshot --snapshot-id snap-abc --dry-run",
        );
        assert_allows(
            &pack,
            "aws ec2 delete-security-group --group-id sg-abc --dry-run --region us-east-1",
        );

        assert_no_safe_match(
            &pack,
            "aws cloudformation delete-stack --stack-name prod --dry-run",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws cloudformation delete-stack --stack-name prod --dry-run",
            "cfn-delete-stack",
        );
        assert_no_safe_match(&pack, "aws iam delete-user --user-name --dry-run");
        assert_blocks_with_pattern(
            &pack,
            "aws iam delete-user --user-name --dry-run",
            "iam-delete",
        );
        assert_no_safe_match(
            &pack,
            "aws ec2 terminate-instances --instance-ids i-abc --dry-run=false",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws ec2 terminate-instances --instance-ids i-abc --dry-run=false",
            "ec2-terminate",
        );
        assert_no_safe_match(
            &pack,
            "aws ec2 delete-snapshot --snapshot-id snap-abc --no-dry-run",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws ec2 delete-snapshot --snapshot-id snap-abc --no-dry-run",
            "removes AWS resources",
        );
        assert_no_safe_match(
            &pack,
            "aws ec2 terminate-instances --instance-ids i-abc --dry-run --no-dry-run",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws ec2 terminate-instances --instance-ids i-abc --dry-run --no-dry-run",
            "ec2-terminate",
        );
        assert_no_safe_match(
            &pack,
            "aws ec2 delete-snapshot --snapshot-id snap-abc --dry-run=false --dry-run",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws ec2 delete-snapshot --snapshot-id snap-abc --dry-run=false --dry-run",
            "removes AWS resources",
        );
    }

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

    // ======================================================================
    // Athena
    // ======================================================================

    #[test]
    fn athena_catalog_and_workgroup_deletions_block() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "aws athena delete-data-catalog --name my_catalog",
            "delete-data-catalog",
        );
        assert_blocks(
            &pack,
            "aws athena delete-work-group --work-group primary",
            "delete-work-group",
        );
        assert_blocks(
            &pack,
            "aws athena delete-named-query --named-query-id abc-123",
            "delete-named-query",
        );
    }

    #[test]
    fn athena_destructive_query_with_safe_keyword_in_comment_still_blocked() {
        // Regression: safe patterns anchor the verb at the head of
        // `--query-string`, so a SQL comment that embeds SELECT/SHOW/etc.
        // must not bypass a surrounding DROP TABLE.
        let pack = create_pack();
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string '/* SELECT old_table */ DROP TABLE prod.customers'",
            "DROP TABLE",
        );
        // Multi-statement is invalid Athena SQL, but defense-in-depth:
        // a SELECT-first query with a trailing DROP must still block.
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'SELECT 1; DROP TABLE prod.customers'",
            "DROP TABLE",
        );
        // Same for SELECT followed by TRUNCATE.
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'SELECT 1; TRUNCATE TABLE prod.events'",
            "TRUNCATE",
        );
        // DELETE-with-WHERE followed by DROP must still block (the
        // safe-first short-circuit cannot be exploited this way even on
        // the one safe pattern we do keep, because Athena rejects
        // compound statements; we still block as defense in depth).
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'DELETE FROM t WHERE id = 1; DROP TABLE t'",
            "DROP TABLE",
        );
        // Regression: unscoped DELETE followed by a scoped DELETE must
        // NOT be allowed just because the *trailing* statement has a
        // WHERE clause. Previously `\S+` was greedy enough to absorb the
        // `;` into the "table name" slot and let the head anchor slide
        // past it to the later WHERE.
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'DELETE FROM t; DELETE FROM u WHERE id = 1'",
            "DELETE without a WHERE clause",
        );
    }

    #[test]
    fn athena_destructive_queries_block() {
        let pack = create_pack();
        // DROP DATABASE / SCHEMA (both keywords)
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'DROP DATABASE test_db'",
            "DROP DATABASE",
        );
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string \"drop schema reporting\"",
            "DROP DATABASE",
        );
        // Case-insensitive
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'Drop Database Test_DB'",
            "DROP DATABASE",
        );
        // DROP TABLE / VIEW
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'DROP TABLE sales.orders'",
            "DROP TABLE",
        );
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'DROP VIEW reporting_v1'",
            "DROP TABLE",
        );
        // TRUNCATE
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'TRUNCATE TABLE iceberg_db.events'",
            "TRUNCATE",
        );
        // DELETE without WHERE
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'DELETE FROM iceberg_db.events'",
            "DELETE without a WHERE clause",
        );
    }

    #[test]
    fn athena_safe_queries_allowed() {
        let pack = create_pack();
        // SELECT
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'SELECT COUNT(*) FROM sales.orders'",
        );
        // SHOW
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'SHOW TABLES IN reporting'",
        );
        // DESCRIBE
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'DESCRIBE sales.orders'",
        );
        // EXPLAIN
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'EXPLAIN SELECT * FROM t LIMIT 1'",
        );
        // CREATE TABLE / DATABASE / VIEW
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'CREATE DATABASE analytics'",
        );
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'CREATE TABLE analytics.t (id int)'",
        );
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'CREATE OR REPLACE VIEW reporting.v AS SELECT 1'",
        );
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string \"CREATE EXTERNAL TABLE t (a string) LOCATION 's3://bkt/'\"",
        );
        // INSERT INTO / OVERWRITE
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'INSERT INTO analytics.t VALUES (1)'",
        );
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'INSERT OVERWRITE analytics.t SELECT * FROM staging.t'",
        );
        // UPDATE ... SET
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'UPDATE analytics.t SET status = '\"'\"'ok'\"'\"' WHERE id = 1'",
        );
        // DELETE with WHERE
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'DELETE FROM iceberg_db.events WHERE id = 1'",
        );
        // Case-insensitive safe verbs
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'select * from t'",
        );
    }

    #[test]
    fn athena_delete_trailing_semicolon_without_second_statement_is_allowed() {
        // Regression: `DELETE … WHERE a=1;` (bare trailing `;`, common
        // habit from psql/sqlite CLI tooling) must NOT be blocked by
        // the multi-statement lookahead. Only a `;` followed by another
        // SQL verb should trip it.
        let pack = create_pack();
        // Trailing `;` with no SQL after.
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'DELETE FROM t WHERE id = 1;'",
        );
        // Trailing `;` with line comment after.
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'DELETE FROM t WHERE id = 1; -- cleanup done'",
        );
        // Trailing `;` with block comment after.
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'DELETE FROM t WHERE id = 1; /* end */'",
        );
        // And the real bypass attempts still block:
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'DELETE FROM t WHERE id = 1; DROP TABLE t'",
            "DROP TABLE",
        );
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'DELETE FROM t WHERE id = 1;\nDROP TABLE t'",
            "DROP TABLE",
        );
    }

    #[test]
    fn athena_delete_with_where_on_schema_qualified_table_is_allowed() {
        let pack = create_pack();
        // Regression: DELETE FROM db.table WHERE ... must match
        // athena-delete-with-where, not athena-query-delete-without-where.
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'DELETE FROM reporting.events WHERE ts < now() - interval 30 day'",
        );
    }

    #[test]
    fn athena_cli_input_inline_json_still_grepped_by_existing_rules() {
        // Regression: `--cli-input-json '{…}'` with INLINE JSON is
        // visible on the command line, so destructive SQL inside the
        // blob must still be caught by the broad DROP/TRUNCATE/DELETE
        // patterns. The `athena-cli-input-file` rule is narrowed to
        // file-backed forms only so it doesn't over-block legitimate
        // inline usage — but the defense in depth comes from the
        // existing per-verb destructive rules still firing.
        let pack = create_pack();
        // Safe inline JSON (SELECT): allowed.
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --cli-input-json '{"QueryString": "SELECT 1 FROM t"}'"#,
        );
        // Destructive inline JSON (DROP DATABASE): blocked by the
        // existing broad DROP DATABASE rule, not the new file-backed rule.
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --cli-input-json '{"QueryString": "DROP DATABASE prod"}'"#,
            "DROP DATABASE",
        );
    }

    #[test]
    fn athena_file_protocol_edge_cases() {
        // Edge cases the simple matcher must still handle:
        let pack = create_pack();
        // `=` separator instead of space.
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string=file:///tmp/q.sql",
            "file",
        );
        // Quoted file path.
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string \"file:///tmp/q.sql\"",
            "file",
        );
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'file:///tmp/q.sql'",
            "file",
        );
        // Case-insensitive on the protocol.
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string FILE:///tmp/q.sql",
            "file",
        );
        // `--cli-input-json=file://…` with `=`.
        assert_blocks(
            &pack,
            "aws athena start-query-execution --cli-input-json=file:///tmp/input.json",
            "cli-input",
        );
    }

    #[test]
    fn athena_query_string_via_file_protocol_is_flagged() {
        // Regression: AWS CLI's `file://` and `fileb://` protocols load
        // the parameter value from a file, and `--cli-input-json` /
        // `--cli-input-yaml` load the entire invocation from a file. In
        // all of these cases the destructive SQL never appears on the
        // command line, so the `DROP DATABASE`/`TRUNCATE`/unscoped
        // `DELETE` regexes have nothing to grep. These shapes need to
        // be blocked (or at least flagged) so a user can't hide a
        // `DROP DATABASE` inside `file://query.sql` and slip past.
        let pack = create_pack();
        // file:// loading
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string file:///tmp/secret-query.sql",
            "file",
        );
        // fileb:// (binary) loading
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string fileb:///tmp/secret-query.sql",
            "file",
        );
        // --cli-input-json: whole invocation from a file
        assert_blocks(
            &pack,
            "aws athena start-query-execution --cli-input-json file:///tmp/input.json",
            "cli-input",
        );
        // --cli-input-yaml: same, YAML flavor
        assert_blocks(
            &pack,
            "aws athena start-query-execution --cli-input-yaml file:///tmp/input.yaml",
            "cli-input",
        );
        // Also with global flags ahead of the service
        assert_blocks(
            &pack,
            "aws --profile prod athena start-query-execution --query-string file:///tmp/q.sql",
            "file",
        );
    }

    #[test]
    fn athena_patterns_match_through_common_wrappers() {
        // `aws-vault exec prod -- aws athena …` and similar wrapper tools
        // are mainline in organizations using MFA / role-assumption. Our
        // `aws\b.*?\bathena\b` anchor needs to keep working when the
        // literal `aws` appears inside a wrapper binary name too.
        let pack = create_pack();
        assert_blocks(
            &pack,
            "aws-vault exec prod -- aws athena delete-data-catalog --name bad",
            "delete-data-catalog",
        );
        assert_blocks(
            &pack,
            "aws-vault exec prod -- aws --profile inner athena start-query-execution --query-string 'DROP DATABASE x'",
            "DROP DATABASE",
        );
        // `aws-sso` login shim followed by a real command.
        assert_blocks(
            &pack,
            "aws-sso exec -A prod aws glue delete-database --name analytics",
            "delete-database",
        );
    }

    #[test]
    fn athena_patterns_match_with_global_flags_before_service() {
        // Regression: the AWS CLI accepts global flags like `--profile`,
        // `--region`, `--debug` BEFORE the service name. If those break
        // the pattern, an attacker (or any normal user with a multi-profile
        // setup) can evade the block entirely with
        // `aws --profile prod athena start-query-execution ...`.
        let pack = create_pack();
        assert_blocks(
            &pack,
            "aws --profile prod athena start-query-execution --query-string 'DROP DATABASE critical'",
            "DROP DATABASE",
        );
        assert_blocks(
            &pack,
            "aws --region us-east-1 --profile prod athena start-query-execution --query-string 'DROP TABLE t'",
            "DROP TABLE",
        );
        assert_blocks(
            &pack,
            "aws --debug glue delete-database --name analytics",
            "delete-database",
        );
        assert_blocks(
            &pack,
            "aws --profile prod --region us-east-1 glue batch-delete-table --database-name x --tables-to-delete foo bar",
            "batch-delete-table",
        );
        assert_blocks(
            &pack,
            "aws --output json athena delete-data-catalog --name my_catalog",
            "delete-data-catalog",
        );
    }

    #[test]
    fn athena_delete_with_quoted_identifiers_is_still_matched() {
        // Regression: quoted table identifiers (backticks, double-quotes,
        // hyphenated names) must not evade either the safe allowlist for
        // DELETE-WITH-WHERE or the destructive block for DELETE-WITHOUT-WHERE.
        let pack = create_pack();

        // Double-quoted, WHERE present → safe.
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'DELETE FROM \"reporting-events\" WHERE ts < now()'",
        );
        // Backtick-quoted, WHERE present → safe.
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'DELETE FROM `reporting-events` WHERE ts < now()'",
        );
        // Double-quoted, WHERE missing → blocked.
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'DELETE FROM \"reporting-events\"'",
            "DELETE without a WHERE clause",
        );
        // Backtick-quoted, WHERE missing → blocked.
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'DELETE FROM `reporting-events`'",
            "DELETE without a WHERE clause",
        );
    }

    // ======================================================================
    // Glue
    // ======================================================================

    #[test]
    fn glue_catalog_deletions_block() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "aws glue delete-database --name analytics",
            "delete-database",
        );
        assert_blocks(
            &pack,
            "aws glue delete-table --database-name analytics --name orders",
            "delete-table",
        );
        assert_blocks(
            &pack,
            "aws glue batch-delete-table --database-name analytics --tables-to-delete orders fulfillment",
            "batch-delete-table",
        );
        assert_blocks(
            &pack,
            "aws glue delete-partition --database-name analytics --table-name orders --partition-values 2026 01",
            "delete-partition",
        );
        assert_blocks(
            &pack,
            "aws glue batch-delete-partition --database-name analytics --table-name orders --partitions-to-delete '[...]'",
            "batch-delete-partition",
        );
    }

    #[test]
    fn glue_tooling_deletions_block() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "aws glue delete-crawler --name nightly-catalog-scan",
            "delete-crawler",
        );
        assert_blocks(
            &pack,
            "aws glue delete-job --job-name orders-etl",
            "delete-job",
        );
        assert_blocks(
            &pack,
            "aws glue delete-dev-endpoint --endpoint-name analytics-dev",
            "delete-dev-endpoint",
        );
    }

    #[test]
    fn glue_read_only_commands_allowed() {
        let pack = create_pack();
        assert_allows(&pack, "aws glue get-tables --database-name analytics");
        assert_allows(&pack, "aws glue get-database --name analytics");
        assert_allows(&pack, "aws glue list-crawlers");
        assert_allows(&pack, "aws glue get-job --job-name orders-etl");
    }

    #[test]
    fn describe_list_get_arg_does_not_bypass_destructive_subcommand() {
        // `describe-`, `list-`, `get-` prefixes that appear as positional
        // arg values (e.g. `--query describe-me`, `--cli-input-json
        // list-ids.json`) must NOT be interpreted as the subcommand and
        // short-circuit destructive checks.
        let pack = create_pack();

        // Legitimate read-only commands still allowed.
        assert_allows(&pack, "aws ec2 describe-instances");
        assert_allows(&pack, "aws s3api list-objects-v2 --bucket b");
        assert_allows(&pack, "aws iam get-user");
        assert_allows(&pack, "aws --profile prod ec2 describe-instances");
        assert_allows(&pack, "aws --region us-east-1 ec2 describe-instances");

        // These compound destructive commands used to be whitelisted by
        // the safe patterns via the `describe-`/`list-`/`get-` suffixes
        // inside an argument. They must still block.
        let m = pack
            .check("aws s3api delete-bucket --bucket prod --query describe-me")
            .expect("`--query describe-me` must not whitelist delete-bucket");
        assert_eq!(m.name, Some("s3api-delete-bucket"));

        let m = pack
            .check("aws ec2 terminate-instances --instance-ids list-ids")
            .expect("`--instance-ids list-ids` must not whitelist terminate");
        assert_eq!(m.name, Some("ec2-terminate"));

        let m = pack
            .check("aws iam delete-user --user-name get-creds-bot")
            .expect("`--user-name get-creds-bot` must not whitelist delete-user");
        assert_eq!(m.name, Some("iam-delete"));
    }
}
