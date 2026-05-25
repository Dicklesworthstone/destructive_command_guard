//! GCP (gcloud) patterns - protections against destructive gcloud commands.
//!
//! This includes patterns for:
//! - compute instances delete
//! - sql instances delete
//! - storage rm -r
//! - projects delete

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the GCP pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "cloud.gcp".to_string(),
        name: "Google Cloud SDK",
        description: "Protects against destructive gcloud operations like instances delete, \
                      sql instances delete, and gsutil rm -r",
        keywords: &[
            "gcloud",
            "gsutil",
            "delete",
            "instances",
            "artifacts",
            "images",
            "repositories",
            // Extra service keywords so the pack is selected even when
            // the command doesn't start with a keyword in the common
            // list (e.g. `bq rm -r DATASET` doesn't start with "gcloud").
            "bq",
            "secrets",
            "kms",
            "iam",
            "dns",
            "spanner",
            "bigtable",
            "dataproc",
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
        // describe/list operations are safe (read-only).
        //
        // `(?:\s+--?\S+(?:\s+\S+)?)*` consumes only flag-value pairs before
        // the two service tokens. Otherwise a destructive command with an
        // arg value that happens to be `describe` or `list` (e.g.
        // `gcloud compute instances delete my-vm --format list`) would
        // match the safe pattern and bypass the destructive check.
        // `(?=\s|$)` closes the trailing side so `list-old-pods` cannot
        // pose as the `list` subcommand.
        safe_pattern!(
            "gcloud-describe",
            r"gcloud\b(?:\s+--?\S+(?:\s+\S+)?)*\s+\S+\s+\S+\s+describe(?=\s|$)"
        ),
        safe_pattern!(
            "gcloud-list",
            r"gcloud\b(?:\s+--?\S+(?:\s+\S+)?)*\s+\S+\s+\S+\s+list(?=\s|$)"
        ),
        // gsutil ls is safe. Require `ls` to be followed by whitespace or
        // end-of-string so `gsutil rm -r gs://ls-archive/` (bucket named
        // `ls-archive`) doesn't bypass via the `ls` substring.
        safe_pattern!(
            "gsutil-ls",
            r"gsutil\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ls(?=\s|$)"
        ),
        // gsutil cp is generally safe (copy). Same trailing-boundary rule.
        safe_pattern!(
            "gsutil-cp",
            r"gsutil\b(?:\s+--?\S+(?:\s+\S+)?)*\s+cp(?=\s|$)"
        ),
        // gcloud config / auth / info are safe.  Require the subcommand
        // to be preceded by whitespace (not `-`) so the pattern doesn't
        // false-match destructive commands with `--config`, `--auth-token`,
        // or `--info-...` flags. A safe-first match on a flag would
        // BYPASS the destructive check.
        safe_pattern!(
            "gcloud-config",
            r"gcloud\b(?:\s+--?\S+(?:\s+\S+)?)*\s+config(?=\s|$)"
        ),
        safe_pattern!(
            "gcloud-auth",
            r"gcloud\b(?:\s+--?\S+(?:\s+\S+)?)*\s+auth(?=\s|$)"
        ),
        safe_pattern!(
            "gcloud-info",
            r"gcloud\b(?:\s+--?\S+(?:\s+\S+)?)*\s+info(?=\s|$)"
        ),
    ]
}

#[allow(clippy::too_many_lines)]
fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // compute instances delete
        destructive_pattern!(
            "compute-delete",
            r"gcloud\b.*?\bcompute\s+instances\s+delete",
            "gcloud compute instances delete permanently destroys VM instances.",
            Critical,
            "compute instances delete permanently destroys VMs:\n\n\
             - Instance is stopped and deleted\n\
             - Boot disk deleted (unless --keep-disks specified)\n\
             - External IPs released back to pool\n\
             - Instance metadata and logs lost\n\n\
             Use --keep-disks=boot,data to preserve disks for recovery."
        ),
        // compute disks delete
        destructive_pattern!(
            "disk-delete",
            r"gcloud\b.*?\bcompute\s+disks\s+delete",
            "gcloud compute disks delete permanently destroys disk data.",
            Critical,
            "compute disks delete permanently destroys persistent disks:\n\n\
             - All data on the disk is lost forever\n\
             - Cannot be recovered without snapshots\n\
             - Any instances using the disk will fail\n\n\
             Create a snapshot before deletion: gcloud compute disks snapshot DISK"
        ),
        // sql instances delete
        destructive_pattern!(
            "sql-delete",
            r"gcloud\b.*?\bsql\s+instances\s+delete",
            "gcloud sql instances delete permanently destroys the Cloud SQL instance.",
            Critical,
            "sql instances delete permanently destroys Cloud SQL:\n\n\
             - Database and all data deleted\n\
             - All backups deleted (unless retained)\n\
             - Read replicas also deleted\n\
             - IP addresses released\n\n\
             Export data first: gcloud sql export sql INSTANCE gs://bucket/file.sql"
        ),
        // gsutil rm -r
        destructive_pattern!(
            "gsutil-rm-recursive",
            r"gsutil\b.*?\brm\s+.*-r|gsutil\b.*?\brm\s+-[a-z]*r",
            "gsutil rm -r permanently deletes all objects in the path.",
            Critical,
            "gsutil rm -r recursively deletes all objects:\n\n\
             - All objects under the path are deleted\n\
             - Cannot be recovered without versioning enabled\n\
             - -m flag parallelizes (faster but same risk)\n\n\
             List first: gsutil ls -r gs://bucket/path/\n\
             Enable versioning: gsutil versioning set on gs://bucket"
        ),
        // gsutil rb (remove bucket). Require `rb` to be followed by whitespace
        // or end-of-string so filenames like `rb.json` in an unrelated
        // gsutil invocation (e.g. `gsutil cors set rb.json`) don't false-match.
        destructive_pattern!(
            "gsutil-rb",
            r"gsutil\b.*?\brb(?=\s|$)",
            "gsutil rb removes the entire GCS bucket.",
            Critical,
            "gsutil rb removes the entire Cloud Storage bucket:\n\n\
             - Bucket must be empty (or use -f to force)\n\
             - Bucket name becomes available to others\n\
             - All bucket-level permissions lost\n\n\
             List contents first: gsutil ls gs://bucket/"
        ),
        // container clusters delete
        destructive_pattern!(
            "gke-delete",
            r"gcloud\b.*?\bcontainer\s+clusters\s+delete",
            "gcloud container clusters delete removes the entire GKE cluster.",
            Critical,
            "container clusters delete removes the entire GKE cluster:\n\n\
             - All nodes and workloads terminated\n\
             - Persistent volumes may be deleted\n\
             - Load balancers and IPs released\n\
             - Cluster-level secrets lost\n\n\
             Backup workloads: kubectl get all -A -o yaml > backup.yaml"
        ),
        // projects delete
        destructive_pattern!(
            "project-delete",
            r"gcloud\b.*?\bprojects\s+delete",
            "gcloud projects delete removes the entire GCP project and ALL its resources!",
            Critical,
            "projects delete removes the ENTIRE GCP project:\n\n\
             - ALL resources in the project deleted\n\
             - All VMs, databases, storage, functions\n\
             - All IAM policies and service accounts\n\
             - 30-day recovery window, then permanent\n\n\
             This is the most destructive GCP command possible!"
        ),
        // functions delete
        destructive_pattern!(
            "functions-delete",
            r"gcloud\b.*?\bfunctions\s+delete",
            "gcloud functions delete removes the Cloud Function.",
            High,
            "functions delete removes Cloud Functions:\n\n\
             - Function code and configuration deleted\n\
             - Triggers and event subscriptions removed\n\
             - Function URL becomes unavailable\n\n\
             Export source first if not in version control."
        ),
        // pubsub topics/subscriptions delete
        destructive_pattern!(
            "pubsub-delete",
            r"gcloud\b.*?\bpubsub\s+(?:topics|subscriptions)\s+delete",
            "gcloud pubsub delete removes Pub/Sub topics or subscriptions.",
            High,
            "pubsub delete removes messaging infrastructure:\n\n\
             - Topic deletion removes all subscriptions\n\
             - Unacknowledged messages are lost\n\
             - Publishers will fail until recreated\n\n\
             Check subscribers: gcloud pubsub topics list-subscriptions TOPIC"
        ),
        // firestore delete
        destructive_pattern!(
            "firestore-delete",
            r"gcloud\b.*?\bfirestore\s+.*delete",
            "gcloud firestore delete removes Firestore data.",
            Critical,
            "firestore delete removes Firestore documents:\n\n\
             - Documents and collections deleted\n\
             - Subcollections may remain (delete recursively)\n\
             - No automatic backups by default\n\n\
             Export first: gcloud firestore export gs://bucket/backup"
        ),
        // container registry image delete
        destructive_pattern!(
            "container-images-delete",
            r"gcloud\b.*?\bcontainer\s+images\s+delete",
            "gcloud container images delete permanently deletes container images.",
            High,
            "container images delete removes images from GCR:\n\n\
             - Image tags and digests deleted\n\
             - Running containers unaffected (cached)\n\
             - New pulls will fail\n\n\
             List tags first: gcloud container images list-tags IMAGE"
        ),
        // artifact registry docker image delete
        destructive_pattern!(
            "artifacts-docker-images-delete",
            r"gcloud\b.*?\bartifacts\s+docker\s+images\s+delete",
            "gcloud artifacts docker images delete permanently deletes container images.",
            High,
            "artifacts docker images delete removes images from Artifact Registry:\n\n\
             - Specified image version deleted\n\
             - Other tags pointing to same digest unaffected\n\
             - Consider cleanup policies instead\n\n\
             List versions: gcloud artifacts docker images list REPO"
        ),
        // artifact registry repository delete
        destructive_pattern!(
            "artifacts-repositories-delete",
            r"gcloud\b.*?\bartifacts\s+repositories\s+delete",
            "gcloud artifacts repositories delete permanently deletes the repository.",
            Critical,
            "artifacts repositories delete removes entire repository:\n\n\
             - All packages/images in repository deleted\n\
             - Repository configuration lost\n\
             - IAM policies on repository removed\n\n\
             List contents: gcloud artifacts packages list --repository=REPO"
        ),
        // ---- Security- and data-critical GCP services ----------------------
        destructive_pattern!(
            "secrets-delete",
            r"gcloud\b.*?\bsecrets\s+delete",
            "gcloud secrets delete destroys a Secret Manager secret — credentials gone.",
            Critical,
            "secrets delete removes a Secret Manager secret:\n\n\
             - Secret and ALL its versions are permanently deleted\n\
             - No recovery window (unlike AWS Secrets Manager)\n\
             - Applications using the secret will fail to authenticate\n\n\
             List versions first: gcloud secrets versions list SECRET\n\
             Disable rather than delete: gcloud secrets versions disable VERSION --secret=SECRET"
        ),
        destructive_pattern!(
            "kms-keys-destroy",
            r"gcloud\b.*?\bkms\s+keys\s+versions\s+destroy",
            "gcloud kms keys versions destroy schedules a CryptoKeyVersion for destruction — data encrypted with it becomes unrecoverable.",
            Critical,
            "kms keys versions destroy scheduled destruction of a key version:\n\n\
             - 24-hour waiting period by default (per-keyring policy)\n\
             - After destruction: ALL data encrypted under this version is unrecoverable\n\
             - `gcloud kms keys versions restore` can undo within the waiting window\n\n\
             Consider `disable` instead if reversibility matters:\n  \
             gcloud kms keys versions disable VERSION --key=KEY --keyring=RING --location=LOC"
        ),
        destructive_pattern!(
            "iam-service-accounts-delete",
            r"gcloud\b.*?\biam\s+service-accounts\s+delete",
            "gcloud iam service-accounts delete removes a service account — workloads authenticating with it break.",
            Critical,
            "iam service-accounts delete removes a service account:\n\n\
             - Every workload using this SA loses access\n\
             - Keys associated with the SA are deleted\n\
             - CI/CD pipelines, GKE workloads, Cloud Functions dependent on this SA fail\n\
             - Can undelete within 30 days via `gcloud iam service-accounts undelete`\n\n\
             List usages first: gcloud iam service-accounts get-iam-policy SA-EMAIL"
        ),
        destructive_pattern!(
            "iam-roles-delete",
            r"gcloud\b.*?\biam\s+roles\s+delete",
            "gcloud iam roles delete removes a custom IAM role — all users/SAs bound to it lose the permissions.",
            High,
            "iam roles delete removes a custom IAM role:\n\n\
             - Every user/group/SA bound to this role loses its permissions\n\
             - Predefined roles cannot be deleted; this always targets custom roles\n\
             - Role is soft-deleted for 7 days, then permanently removed\n\n\
             Audit bindings first via gcloud projects get-iam-policy PROJECT"
        ),
        destructive_pattern!(
            "dns-managed-zones-delete",
            r"gcloud\b.*?\bdns\s+managed-zones\s+delete",
            "gcloud dns managed-zones delete removes a DNS zone — domains stop resolving.",
            Critical,
            "dns managed-zones delete removes a Cloud DNS zone:\n\n\
             - All record sets in the zone are deleted\n\
             - Domains configured with this zone's nameservers stop resolving immediately\n\
             - Production traffic can go dark\n\
             - No undelete\n\n\
             Export records first:\n  \
             gcloud dns record-sets export zone-backup.yaml --zone=ZONE"
        ),
        destructive_pattern!(
            "logging-sinks-delete",
            r"gcloud\b.*?\blogging\s+sinks\s+delete",
            "gcloud logging sinks delete removes an audit-log export — compliance/forensics impact.",
            High,
            "logging sinks delete stops log export to BigQuery/PubSub/Storage:\n\n\
             - Historical exports remain at the destination\n\
             - Future events stop flowing to the configured sink\n\
             - Compliance regimes (SOC2, ISO 27001) may require this sink\n\n\
             Consider disabling by updating filter:\n  \
             gcloud logging sinks update SINK --log-filter='false'"
        ),
        destructive_pattern!(
            "spanner-instances-delete",
            r"gcloud\b.*?\bspanner\s+instances\s+delete",
            "gcloud spanner instances delete destroys a Spanner instance — all databases and data lost.",
            Critical,
            "spanner instances delete removes a Spanner instance:\n\n\
             - All databases inside the instance are deleted\n\
             - Data is unrecoverable unless previously exported\n\
             - Applications writing to these DBs fail immediately\n\n\
             Export data first:\n  \
             gcloud dataflow jobs run export-spanner --region=REGION \\\n    \
             --parameters=sourceInstance=INST,destinationPath=gs://bkt/backup/"
        ),
        destructive_pattern!(
            "bigtable-instances-delete",
            r"gcloud\b.*?\bbigtable\s+instances\s+delete",
            "gcloud bigtable instances delete destroys a Bigtable instance — all tables and data lost.",
            Critical,
            "bigtable instances delete removes a Bigtable instance:\n\n\
             - All tables, clusters, and data are permanently deleted\n\
             - No backup unless one was explicitly taken\n\
             - Downstream pipelines consuming from Bigtable fail\n\n\
             Take a backup first:\n  \
             cbt -instance=INST createsnapshot CLUSTER TABLE SNAPSHOT 30"
        ),
        destructive_pattern!(
            "dataproc-clusters-delete",
            r"gcloud\b.*?\bdataproc\s+clusters\s+delete",
            "gcloud dataproc clusters delete destroys a Dataproc (Hadoop/Spark) cluster.",
            High,
            "dataproc clusters delete removes a Dataproc cluster:\n\n\
             - Running jobs are killed\n\
             - Any data stored on local HDFS or cluster-local disks is lost\n\
             - Data in GCS (external) is preserved\n\
             - Cluster name is reserved for ~5 min; re-creation may fail until it clears"
        ),
        destructive_pattern!(
            "bq-rm-recursive",
            r"\bbq\b.*?\brm\s+.*-r\b|\bbq\b.*?\brm\s+.*-f\b",
            "bq rm -r/-f removes BigQuery datasets, tables, or models — data lost.",
            Critical,
            "bq rm recursively deletes BigQuery resources:\n\n\
             - `bq rm -r DATASET`: removes dataset + ALL tables/views/models inside\n\
             - `bq rm -f TABLE`: removes a table without confirmation\n\
             - Data is not recoverable (unless a prior `EXPORT` or snapshot exists)\n\
             - No trash/recycle bin\n\n\
             Export first:\n  \
             bq extract --destination_format=NEWLINE_DELIMITED_JSON \\\n    \
             DATASET.TABLE gs://bkt/backup/*.json"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn gcp_safe_pattern_does_not_bypass_via_flag_value() {
        // Regression: `gcloud-config`/`-auth`/`-info` safe patterns must
        // NOT match flag values like `--config-file`, `--auth-token`,
        // `--info-...`. If they did, a destructive command that happens
        // to carry any of those flags would silently get safe-first'd.
        let pack = create_pack();
        // compute instances delete with --config-file flag must still block
        assert_blocks(
            &pack,
            "gcloud compute instances delete prod-vm --config-file ./prod.yaml",
            "VM instances",
        );
        // sql instances delete with --auth-token flag (hypothetical but
        // similar shape) must still block
        assert_blocks(
            &pack,
            "gcloud sql instances delete prod-db --quiet --project prod",
            "Cloud SQL",
        );
        // Genuine `gcloud config`/`auth`/`info` commands still allowed
        assert_allows(&pack, "gcloud config list");
        assert_allows(&pack, "gcloud auth login");
        assert_allows(&pack, "gcloud info --run-diagnostics");
        assert_allows(&pack, "gcloud --project prod config list");
    }

    #[test]
    fn gcp_patterns_match_with_global_flags() {
        // Same class bug as was found on aws.rs: gcloud global flags
        // (`--project`, `--account`, `--impersonate-service-account`,
        // `--verbosity`, `--quiet`, `--configuration`) between `gcloud`
        // and the service name break every `gcloud\s+<svc>` pattern.
        // Multi-project orgs use `--project` on every non-trivial
        // command, so this bypass is mainline.
        let pack = create_pack();
        assert_blocks(
            &pack,
            "gcloud --project prod compute instances delete inst-1",
            "VM instances",
        );
        assert_blocks(
            &pack,
            "gcloud --impersonate-service-account sa@prod.iam.gserviceaccount.com sql instances delete prod-db",
            "Cloud SQL",
        );
        assert_blocks(
            &pack,
            "gcloud --project prod projects delete prod",
            "GCP project",
        );
        assert_blocks(
            &pack,
            "gcloud --verbosity debug --project prod container clusters delete prod-gke",
            "GKE cluster",
        );
        assert_blocks(
            &pack,
            "gcloud --quiet --project prod functions delete prod-fn",
            "Cloud Function",
        );
    }

    #[test]
    fn gcp_security_and_data_critical_services_blocked() {
        // New coverage for previously-uncovered GCP destructive services.
        let pack = create_pack();
        assert_blocks(
            &pack,
            "gcloud secrets delete prod-db-password",
            "Secret Manager secret",
        );
        assert_blocks(
            &pack,
            "gcloud kms keys versions destroy 3 --key=prod-key --keyring=prod --location=us-central1",
            "CryptoKeyVersion",
        );
        assert_blocks(
            &pack,
            "gcloud iam service-accounts delete ci@my-project.iam.gserviceaccount.com",
            "service account",
        );
        assert_blocks(
            &pack,
            "gcloud iam roles delete CustomRole --project=my-project",
            "custom IAM role",
        );
        assert_blocks(
            &pack,
            "gcloud dns managed-zones delete prod-zone",
            "DNS zone",
        );
        assert_blocks(
            &pack,
            "gcloud logging sinks delete audit-to-bq",
            "audit-log export",
        );
        assert_blocks(
            &pack,
            "gcloud spanner instances delete prod-spanner",
            "Spanner instance",
        );
        assert_blocks(
            &pack,
            "gcloud bigtable instances delete prod-bt",
            "Bigtable instance",
        );
        assert_blocks(
            &pack,
            "gcloud dataproc clusters delete prod-hadoop --region=us-central1",
            "Dataproc",
        );
        assert_blocks(&pack, "bq rm -r -f analytics_prod", "BigQuery");
        // And all of the above still block with global flags:
        assert_blocks(
            &pack,
            "gcloud --project prod secrets delete prod-token",
            "Secret Manager secret",
        );
        assert_blocks(
            &pack,
            "gcloud --quiet --project prod kms keys versions destroy 1 --key=k --keyring=r --location=l",
            "CryptoKeyVersion",
        );
    }

    #[test]
    fn container_registry_patterns_block() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "gcloud container images delete gcr.io/myproj/myimg:latest",
            "container images delete",
        );
        assert_blocks(
            &pack,
            "gcloud artifacts docker images delete us-central1-docker.pkg.dev/p/repo/img:tag",
            "docker images delete",
        );
        assert_blocks(
            &pack,
            "gcloud artifacts repositories delete my-repo --location=us-central1",
            "repositories delete",
        );
    }

    #[test]
    fn gcp_blocks_each_destructive_pattern() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "gcloud compute instances delete my-vm",
            "compute-delete",
        );
        assert_blocks_with_pattern(&pack, "gcloud compute disks delete my-disk", "disk-delete");
        assert_blocks_with_pattern(&pack, "gcloud sql instances delete my-db", "sql-delete");
        assert_blocks_with_pattern(
            &pack,
            "gsutil rm -r gs://my-bucket/path/",
            "gsutil-rm-recursive",
        );
        assert_blocks_with_pattern(&pack, "gsutil rb gs://my-bucket", "gsutil-rb");
        assert_blocks_with_pattern(
            &pack,
            "gcloud container clusters delete my-gke",
            "gke-delete",
        );
        assert_blocks_with_pattern(&pack, "gcloud projects delete my-project", "project-delete");
        assert_blocks_with_pattern(
            &pack,
            "gcloud functions delete my-function",
            "functions-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "gcloud pubsub topics delete my-topic",
            "pubsub-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "gcloud firestore indexes delete idx123",
            "firestore-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "gcloud container images delete gcr.io/proj/img:tag",
            "container-images-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "gcloud artifacts docker images delete us-docker.pkg.dev/p/r/i:t",
            "artifacts-docker-images-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "gcloud artifacts repositories delete my-repo --location=us",
            "artifacts-repositories-delete",
        );
        assert_blocks_with_pattern(&pack, "gcloud secrets delete my-secret", "secrets-delete");
        assert_blocks_with_pattern(
            &pack,
            "gcloud kms keys versions destroy 1 --key=k --keyring=r --location=l",
            "kms-keys-destroy",
        );
        assert_blocks_with_pattern(
            &pack,
            "gcloud iam service-accounts delete sa@proj.iam.gserviceaccount.com",
            "iam-service-accounts-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "gcloud iam roles delete CustomRole --project=proj",
            "iam-roles-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "gcloud dns managed-zones delete my-zone",
            "dns-managed-zones-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "gcloud logging sinks delete my-sink",
            "logging-sinks-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "gcloud spanner instances delete my-spanner",
            "spanner-instances-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "gcloud bigtable instances delete my-bt",
            "bigtable-instances-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "gcloud dataproc clusters delete my-cluster --region=us-central1",
            "dataproc-clusters-delete",
        );
        assert_blocks_with_pattern(&pack, "bq rm -r my_dataset", "bq-rm-recursive");
    }

    #[test]
    fn gcp_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(
            &pack,
            "gcloud compute instances delete my-vm",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "gcloud compute disks delete my-disk",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "gcloud sql instances delete my-db",
            Severity::Critical,
        );
        assert_blocks_with_severity(&pack, "gsutil rm -r gs://bucket/path/", Severity::Critical);
        assert_blocks_with_severity(&pack, "gsutil rb gs://bucket", Severity::Critical);
        assert_blocks_with_severity(
            &pack,
            "gcloud container clusters delete gke",
            Severity::Critical,
        );
        assert_blocks_with_severity(&pack, "gcloud projects delete proj", Severity::Critical);
        assert_blocks_with_severity(&pack, "gcloud functions delete fn", Severity::High);
        assert_blocks_with_severity(&pack, "gcloud pubsub topics delete t", Severity::High);
        assert_blocks_with_severity(
            &pack,
            "gcloud firestore indexes delete idx",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "gcloud container images delete gcr.io/p/i:t",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "gcloud artifacts docker images delete us-docker.pkg.dev/p/r/i:t",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "gcloud artifacts repositories delete repo --location=us",
            Severity::Critical,
        );
        assert_blocks_with_severity(&pack, "gcloud secrets delete s", Severity::Critical);
        assert_blocks_with_severity(
            &pack,
            "gcloud kms keys versions destroy 1 --key=k --keyring=r --location=l",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "gcloud iam service-accounts delete sa@p.iam.gserviceaccount.com",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "gcloud iam roles delete CustomRole --project=p",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "gcloud dns managed-zones delete zone",
            Severity::Critical,
        );
        assert_blocks_with_severity(&pack, "gcloud logging sinks delete sink", Severity::High);
        assert_blocks_with_severity(
            &pack,
            "gcloud spanner instances delete spanner",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "gcloud bigtable instances delete bt",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "gcloud dataproc clusters delete cluster --region=us",
            Severity::High,
        );
        assert_blocks_with_severity(&pack, "bq rm -r dataset", Severity::Critical);
    }

    #[test]
    fn gcp_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "gcloud compute instances describe my-vm");
        assert_safe_pattern_matches(&pack, "gcloud compute instances list");
        assert_safe_pattern_matches(&pack, "gsutil ls gs://bucket/");
        assert_safe_pattern_matches(&pack, "gsutil cp file.txt gs://bucket/");
        assert_safe_pattern_matches(&pack, "gcloud config list");
        assert_safe_pattern_matches(&pack, "gcloud auth login");
        assert_safe_pattern_matches(&pack, "gcloud info");
    }

    #[test]
    fn gcp_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
    }
}
