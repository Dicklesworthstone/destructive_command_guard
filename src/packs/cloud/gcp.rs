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
        keywords: &["gcloud", "gsutil", "delete", "instances"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
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

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // compute instances delete
        destructive_pattern!(
            "compute-delete",
            r"gcloud\s+compute\s+instances\s+delete",
            "gcloud compute instances delete permanently destroys VM instances."
        ),
        // compute disks delete
        destructive_pattern!(
            "disk-delete",
            r"gcloud\s+compute\s+disks\s+delete",
            "gcloud compute disks delete permanently destroys disk data."
        ),
        // sql instances delete
        destructive_pattern!(
            "sql-delete",
            r"gcloud\s+sql\s+instances\s+delete",
            "gcloud sql instances delete permanently destroys the Cloud SQL instance."
        ),
        // gsutil rm -r
        destructive_pattern!(
            "gsutil-rm-recursive",
            r"gsutil\s+(?:-m\s+)?rm\s+.*-r|gsutil\s+(?:-m\s+)?rm\s+-[a-z]*r",
            "gsutil rm -r permanently deletes all objects in the path."
        ),
        // gsutil rb (remove bucket)
        destructive_pattern!(
            "gsutil-rb",
            r"gsutil\s+rb\b",
            "gsutil rb removes the entire GCS bucket."
        ),
        // container clusters delete
        destructive_pattern!(
            "gke-delete",
            r"gcloud\s+container\s+clusters\s+delete",
            "gcloud container clusters delete removes the entire GKE cluster."
        ),
        // projects delete
        destructive_pattern!(
            "project-delete",
            r"gcloud\s+projects\s+delete",
            "gcloud projects delete removes the entire GCP project and ALL its resources!"
        ),
        // functions delete
        destructive_pattern!(
            "functions-delete",
            r"gcloud\s+functions\s+delete",
            "gcloud functions delete removes the Cloud Function."
        ),
        // pubsub topics/subscriptions delete
        destructive_pattern!(
            "pubsub-delete",
            r"gcloud\s+pubsub\s+(?:topics|subscriptions)\s+delete",
            "gcloud pubsub delete removes Pub/Sub topics or subscriptions."
        ),
        // firestore delete
        destructive_pattern!(
            "firestore-delete",
            r"gcloud\s+firestore\s+.*delete",
            "gcloud firestore delete removes Firestore data."
        ),
    ]
}
