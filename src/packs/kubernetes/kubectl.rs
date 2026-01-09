//! kubectl patterns - protections against destructive kubectl commands.
//!
//! This includes patterns for:
//! - delete namespace/all resources
//! - drain nodes
//! - cordon nodes
//! - delete without dry-run

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the kubectl pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "kubernetes.kubectl".to_string(),
        name: "kubectl",
        description: "Protects against destructive kubectl operations like delete namespace, \
                      drain, and mass deletion",
        keywords: &["kubectl", "delete", "drain", "cordon", "taint"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // get/describe/logs are safe (read-only)
        safe_pattern!("kubectl-get", r"kubectl\s+get"),
        safe_pattern!("kubectl-describe", r"kubectl\s+describe"),
        safe_pattern!("kubectl-logs", r"kubectl\s+logs"),
        // dry-run is safe
        safe_pattern!(
            "kubectl-dry-run",
            r"kubectl\s+.*--dry-run(?:=(?:client|server|none))?"
        ),
        // diff is safe (shows what would change)
        safe_pattern!("kubectl-diff", r"kubectl\s+diff"),
        // explain is safe (documentation)
        safe_pattern!("kubectl-explain", r"kubectl\s+explain"),
        // top is safe (metrics)
        safe_pattern!("kubectl-top", r"kubectl\s+top"),
        // config is safe
        safe_pattern!("kubectl-config", r"kubectl\s+config"),
        // api-resources/api-versions are safe
        safe_pattern!("kubectl-api", r"kubectl\s+api-(?:resources|versions)"),
        // version is safe
        safe_pattern!("kubectl-version", r"kubectl\s+version"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // delete namespace
        destructive_pattern!(
            "delete-namespace",
            r"kubectl\s+delete\s+(?:namespace|ns)\b",
            "kubectl delete namespace removes the entire namespace and ALL resources within it."
        ),
        // delete all
        destructive_pattern!(
            "delete-all",
            r"kubectl\s+delete\s+.*--all\b",
            "kubectl delete --all removes ALL resources of that type. Use --dry-run=client first."
        ),
        // delete with -A (all namespaces)
        destructive_pattern!(
            "delete-all-namespaces",
            r"kubectl\s+delete\s+.*(?:-A\b|--all-namespaces)",
            "kubectl delete with -A/--all-namespaces affects ALL namespaces. Very dangerous!"
        ),
        // drain node
        destructive_pattern!(
            "drain-node",
            r"kubectl\s+drain\b",
            "kubectl drain evicts all pods from a node. Ensure proper pod disruption budgets."
        ),
        // cordon node
        destructive_pattern!(
            "cordon-node",
            r"kubectl\s+cordon\b",
            "kubectl cordon marks a node unschedulable. Existing pods continue running."
        ),
        // taint node with NoExecute
        destructive_pattern!(
            "taint-noexecute",
            r"kubectl\s+taint\s+.*:NoExecute",
            "kubectl taint with NoExecute evicts existing pods that don't tolerate the taint."
        ),
        // delete deployment/statefulset/daemonset
        destructive_pattern!(
            "delete-workload",
            r"kubectl\s+delete\s+(?:deployment|statefulset|daemonset|replicaset)\b(?!.*--dry-run)",
            "kubectl delete deployment/statefulset/daemonset removes the workload. Use --dry-run first."
        ),
        // delete pvc (persistent volume claim)
        destructive_pattern!(
            "delete-pvc",
            r"kubectl\s+delete\s+(?:pvc|persistentvolumeclaim)\b(?!.*--dry-run)",
            "kubectl delete pvc may permanently delete data if ReclaimPolicy is Delete."
        ),
        // delete pv (persistent volume)
        destructive_pattern!(
            "delete-pv",
            r"kubectl\s+delete\s+(?:pv|persistentvolume)\b(?!.*--dry-run)",
            "kubectl delete pv may permanently delete the underlying storage."
        ),
        // scale to 0
        destructive_pattern!(
            "scale-to-zero",
            r"kubectl\s+scale\s+.*--replicas=0",
            "kubectl scale --replicas=0 stops all pods for the workload."
        ),
        // delete with force --grace-period=0
        destructive_pattern!(
            "delete-force",
            r"kubectl\s+delete\s+.*--force.*--grace-period=0|kubectl\s+delete\s+.*--grace-period=0.*--force",
            "kubectl delete --force --grace-period=0 immediately removes resources without graceful shutdown."
        ),
    ]
}
