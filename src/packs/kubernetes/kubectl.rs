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
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
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
            "kubectl delete namespace removes the entire namespace and ALL resources within it.",
            Critical,
            "Deleting a namespace destroys EVERYTHING inside it:\n\n\
             - All deployments, pods, services\n\
             - All configmaps and secrets\n\
             - All persistent volume claims (data may be lost)\n\
             - All ingresses and network policies\n\
             - All RBAC resources scoped to the namespace\n\n\
             This is irreversible. Even if you recreate the namespace, all resources are gone.\n\n\
             Preview what would be deleted:\n  \
             kubectl get all -n <namespace>\n  \
             kubectl get pvc -n <namespace>\n\n\
             Safer approach:\n  \
             kubectl delete deployment <name> -n <namespace>  # Delete specific resources"
        ),
        // delete all
        destructive_pattern!(
            "delete-all",
            r"kubectl\s+delete\s+.*--all\b",
            "kubectl delete --all removes ALL resources of that type. Use --dry-run=client first.",
            High,
            "The --all flag deletes EVERY resource of the specified type in the namespace.\n\n\
             For example:\n\
             - kubectl delete pods --all: Kills all pods (services go down)\n\
             - kubectl delete svc --all: Removes all services (networking breaks)\n\
             - kubectl delete pvc --all: May delete all persistent data\n\n\
             Always preview first:\n  \
             kubectl delete <resource> --all --dry-run=client\n\n\
             Safer alternative:\n  \
             kubectl delete <resource> -l app=myapp  # Use label selectors"
        ),
        // delete with -A (all namespaces)
        destructive_pattern!(
            "delete-all-namespaces",
            r"kubectl\s+delete\s+.*(?:-A\b|--all-namespaces)",
            "kubectl delete with -A/--all-namespaces affects ALL namespaces. Very dangerous!",
            Critical,
            "The -A/--all-namespaces flag expands deletion to EVERY namespace in the cluster. \
             This can take down your entire cluster:\n\n\
             - Production, staging, and dev environments affected\n\
             - System namespaces (kube-system) may be impacted\n\
             - Cross-namespace resources and dependencies break\n\n\
             This is almost never what you want. Always specify a namespace:\n  \
             kubectl delete <resource> -n <namespace>\n\n\
             Preview cluster-wide resources:\n  \
             kubectl get <resource> -A"
        ),
        // drain node
        destructive_pattern!(
            "drain-node",
            r"kubectl\s+drain\b",
            "kubectl drain evicts all pods from a node. Ensure proper pod disruption budgets.",
            High,
            "kubectl drain evicts ALL pods from a node, typically for maintenance. \
             This can cause service disruption:\n\n\
             - All pods are evicted (respecting PodDisruptionBudgets)\n\
             - DaemonSet pods remain unless --ignore-daemonsets is used\n\
             - Pods with local storage fail unless --delete-emptydir-data is used\n\
             - Without replicas elsewhere, services go down\n\n\
             Before draining:\n  \
             kubectl get pods -o wide | grep <node>  # Check what's running\n  \
             kubectl get pdb -A                       # Check disruption budgets\n\n\
             Safer approach:\n  \
             kubectl cordon <node>  # Prevent new pods first, then drain gradually"
        ),
        // cordon node
        destructive_pattern!(
            "cordon-node",
            r"kubectl\s+cordon\b",
            "kubectl cordon marks a node unschedulable. Existing pods continue running.",
            Medium,
            "kubectl cordon marks a node as unschedulable. Existing pods continue running, \
             but no new pods will be scheduled to this node.\n\n\
             Use cases:\n\
             - Preparing for maintenance\n\
             - Investigating node issues\n\
             - Gradual migration\n\n\
             To reverse:\n  \
             kubectl uncordon <node>\n\n\
             Check node status:\n  \
             kubectl get nodes\n  \
             kubectl describe node <node> | grep Taints"
        ),
        // taint node with NoExecute
        destructive_pattern!(
            "taint-noexecute",
            r"kubectl\s+taint\s+.*:NoExecute",
            "kubectl taint with NoExecute evicts existing pods that don't tolerate the taint.",
            High,
            "A NoExecute taint immediately evicts pods that don't have a matching toleration. \
             This is more aggressive than NoSchedule:\n\n\
             - Existing pods are evicted (not just new scheduling blocked)\n\
             - Can cause immediate service disruption\n\
             - Pods may not have time for graceful shutdown\n\n\
             Check current taints:\n  \
             kubectl describe node <node> | grep Taints\n\n\
             Consider NoSchedule first:\n  \
             kubectl taint nodes <node> key=value:NoSchedule\n\n\
             Remove taint:\n  \
             kubectl taint nodes <node> key=value:NoExecute-"
        ),
        // delete deployment/statefulset/daemonset
        destructive_pattern!(
            "delete-workload",
            r"kubectl\s+delete\s+(?:deployment|statefulset|daemonset|replicaset)\b(?!.*--dry-run)",
            "kubectl delete deployment/statefulset/daemonset removes the workload. Use --dry-run first.",
            High,
            "Deleting a workload terminates all its pods:\n\n\
             - Deployment: All replicas terminated, service goes down\n\
             - StatefulSet: Ordered shutdown, PVCs may be orphaned\n\
             - DaemonSet: Removed from all nodes\n\
             - ReplicaSet: Pods terminated (usually managed by Deployment)\n\n\
             Preview first:\n  \
             kubectl delete <type> <name> --dry-run=client\n  \
             kubectl get pods -l app=<name>  # Check affected pods\n\n\
             Consider scaling down first:\n  \
             kubectl scale deployment <name> --replicas=0"
        ),
        // delete pvc (persistent volume claim)
        destructive_pattern!(
            "delete-pvc",
            r"kubectl\s+delete\s+(?:pvc|persistentvolumeclaim)\b(?!.*--dry-run)",
            "kubectl delete pvc may permanently delete data if ReclaimPolicy is Delete.",
            Critical,
            "Deleting a PVC can cause permanent data loss depending on the PV's reclaimPolicy:\n\n\
             - Delete: Underlying storage is deleted (DATA LOST)\n\
             - Retain: PV is kept but becomes 'Released' (manual recovery needed)\n\
             - Recycle: Deprecated, data scrubbed\n\n\
             Check the reclaim policy:\n  \
             kubectl get pv <pv-name> -o jsonpath='{.spec.persistentVolumeReclaimPolicy}'\n\n\
             Backup first:\n  \
             kubectl exec <pod> -- tar czf - /data > backup.tar.gz\n\n\
             Preview:\n  \
             kubectl delete pvc <name> --dry-run=client"
        ),
        // delete pv (persistent volume)
        destructive_pattern!(
            "delete-pv",
            r"kubectl\s+delete\s+(?:pv|persistentvolume)\b(?!.*--dry-run)",
            "kubectl delete pv may permanently delete the underlying storage.",
            Critical,
            "Deleting a PersistentVolume can permanently destroy the underlying storage:\n\n\
             - Cloud disks (EBS, GCE PD, Azure Disk) may be deleted\n\
             - NFS mounts become orphaned\n\
             - Local storage data is lost\n\n\
             Even with Retain policy, deleting the PV may trigger storage cleanup.\n\n\
             Check what's using the PV:\n  \
             kubectl get pvc -A | grep <pv-name>\n\n\
             Check storage class policy:\n  \
             kubectl get storageclass <class> -o yaml\n\n\
             Preview:\n  \
             kubectl delete pv <name> --dry-run=client"
        ),
        // scale to 0
        destructive_pattern!(
            "scale-to-zero",
            r"kubectl\s+scale\s+.*--replicas=0",
            "kubectl scale --replicas=0 stops all pods for the workload.",
            High,
            "Scaling to zero replicas terminates ALL pods for the workload:\n\n\
             - Service becomes unavailable\n\
             - Endpoints are removed from Service\n\
             - In-flight requests are dropped\n\
             - StatefulSets: Ordered shutdown from highest ordinal\n\n\
             This is often intentional but can cause outages if done accidentally.\n\n\
             Check current replicas:\n  \
             kubectl get deployment <name> -o jsonpath='{.spec.replicas}'\n\n\
             To restore:\n  \
             kubectl scale deployment <name> --replicas=<N>"
        ),
        // delete with force --grace-period=0
        destructive_pattern!(
            "delete-force",
            r"kubectl\s+delete\s+.*--force.*--grace-period=0|kubectl\s+delete\s+.*--grace-period=0.*--force",
            "kubectl delete --force --grace-period=0 immediately removes resources without graceful shutdown.",
            Critical,
            "Force deletion with zero grace period is dangerous:\n\n\
             - Pods are killed immediately (no SIGTERM, just gone)\n\
             - In-flight requests fail\n\
             - Data corruption risk if writes in progress\n\
             - Finalizers may be skipped (resource leak)\n\n\
             Kubernetes warns against this. Use only for stuck pods that won't terminate.\n\n\
             Try graceful deletion first:\n  \
             kubectl delete pod <name>                    # Default 30s grace\n  \
             kubectl delete pod <name> --grace-period=60  # Extended grace\n\n\
             Check why pod is stuck:\n  \
             kubectl describe pod <name> | grep -A5 Status"
        ),
    ]
}
