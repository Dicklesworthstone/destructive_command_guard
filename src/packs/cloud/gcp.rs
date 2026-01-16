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
        // describe/list operations are safe (read-only)
        safe_pattern!("gcloud-describe", r"gcloud\s+\S+\s+\S+\s+describe"),
        safe_pattern!("gcloud-list", r"gcloud\s+\S+\s+\S+\s+list"),
        // gsutil ls is safe
        safe_pattern!("gsutil-ls", r"gsutil\s+ls"),
        // gsutil cp is generally safe (copy)
        safe_pattern!("gsutil-cp", r"gsutil\s+cp"),
        // gcloud config is safe
        safe_pattern!("gcloud-config", r"gcloud\s+config"),
        // gcloud auth is safe
        safe_pattern!("gcloud-auth", r"gcloud\s+auth"),
        // gcloud info is safe
        safe_pattern!("gcloud-info", r"gcloud\s+info"),
    ]
}

#[allow(clippy::too_many_lines)]
fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // compute instances delete
        destructive_pattern!(
            "compute-delete",
            r"gcloud\s+compute\s+instances\s+delete",
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
            r"gcloud\s+compute\s+disks\s+delete",
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
            r"gcloud\s+sql\s+instances\s+delete",
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
            r"gsutil\s+(?:-m\s+)?rm\s+.*-r|gsutil\s+(?:-m\s+)?rm\s+-[a-z]*r",
            "gsutil rm -r permanently deletes all objects in the path.",
            Critical,
            "gsutil rm -r recursively deletes all objects:\n\n\
             - All objects under the path are deleted\n\
             - Cannot be recovered without versioning enabled\n\
             - -m flag parallelizes (faster but same risk)\n\n\
             List first: gsutil ls -r gs://bucket/path/\n\
             Enable versioning: gsutil versioning set on gs://bucket"
        ),
        // gsutil rb (remove bucket)
        destructive_pattern!(
            "gsutil-rb",
            r"gsutil\s+rb\b",
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
            r"gcloud\s+container\s+clusters\s+delete",
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
            r"gcloud\s+projects\s+delete",
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
            r"gcloud\s+functions\s+delete",
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
            r"gcloud\s+pubsub\s+(?:topics|subscriptions)\s+delete",
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
            r"gcloud\s+firestore\s+.*delete",
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
            r"gcloud\s+container\s+images\s+delete",
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
            r"gcloud\s+artifacts\s+docker\s+images\s+delete",
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
            r"gcloud\s+artifacts\s+repositories\s+delete",
            "gcloud artifacts repositories delete permanently deletes the repository.",
            Critical,
            "artifacts repositories delete removes entire repository:\n\n\
             - All packages/images in repository deleted\n\
             - Repository configuration lost\n\
             - IAM policies on repository removed\n\n\
             List contents: gcloud artifacts packages list --repository=REPO"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::*;

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
}
