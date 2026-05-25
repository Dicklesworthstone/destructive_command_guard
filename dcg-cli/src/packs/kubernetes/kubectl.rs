//! kubectl patterns - protections against destructive kubectl commands.
//!
//! This includes patterns for:
//! - delete namespace/all resources
//! - drain nodes
//! - cordon nodes
//! - delete without dry-run

use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Suggestions for `kubectl delete namespace` pattern.
const DELETE_NAMESPACE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "kubectl delete ns {ns} --dry-run=client -o yaml",
        "Preview what would be deleted without making changes",
    ),
    PatternSuggestion::new(
        "kubectl get all -n {ns}",
        "See all resources in the namespace before deleting",
    ),
    PatternSuggestion::new(
        "kubectl delete ns {ns} --grace-period=60",
        "Allow graceful shutdown with 60-second grace period",
    ),
];

/// Suggestions for `kubectl delete --all` pattern.
const DELETE_ALL_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "kubectl delete {resource} --all --dry-run=client",
        "Preview what would be deleted without making changes",
    ),
    PatternSuggestion::new(
        "kubectl rollout restart deployment/{name}",
        "Restart pods via deployment for graceful recreation",
    ),
    PatternSuggestion::new(
        "kubectl delete {resource} {specific-name}",
        "Delete a specific resource instead of all",
    ),
    PatternSuggestion::new(
        "kubectl delete {resource} -l app={label}",
        "Use label selectors for targeted deletion",
    ),
];

/// Suggestions for `kubectl delete pvc` pattern.
const DELETE_PVC_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "kubectl describe pvc {name}",
        "Check PVC status and usage before deleting",
    ),
    PatternSuggestion::new(
        "kubectl get pods -o json | jq '.items[] | select(.spec.volumes[]?.persistentVolumeClaim.claimName==\"{name}\")'",
        "Find pods currently using this PVC",
    ),
    PatternSuggestion::new(
        "kubectl delete pvc {name} --dry-run=client",
        "Preview deletion without making changes",
    ),
    PatternSuggestion::new(
        "kubectl get pv $(kubectl get pvc {name} -o jsonpath='{.spec.volumeName}') -o jsonpath='{.spec.persistentVolumeReclaimPolicy}'",
        "Check reclaim policy to understand data fate",
    ),
];

/// Suggestions for `kubectl delete --force --grace-period=0` pattern.
const DELETE_FORCE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "kubectl delete {resource} {name}",
        "Use default 30-second grace period for graceful shutdown",
    ),
    PatternSuggestion::new(
        "kubectl delete {resource} {name} --grace-period=60",
        "Extended grace period for slower shutdown",
    ),
    PatternSuggestion::new(
        "kubectl describe {resource} {name}",
        "Check resource status to understand why it's stuck",
    ),
];

/// Suggestions for `kubectl apply --force` pattern.
const APPLY_FORCE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "kubectl apply -f {file}",
        "Apply without --force for in-place updates",
    ),
    PatternSuggestion::new(
        "kubectl diff -f {file}",
        "Preview what changes would be applied",
    ),
    PatternSuggestion::new(
        "kubectl apply --server-side -f {file}",
        "Use server-side apply for safer field management",
    ),
];

/// Suggestions for `kubectl delete -f` with directory pattern.
const DELETE_FROM_DIR_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "kubectl delete -f {specific-file}",
        "Delete from a specific file instead of directory",
    ),
    PatternSuggestion::new(
        "kubectl diff -f {directory}",
        "Preview what resources would be affected",
    ),
    PatternSuggestion::new(
        "kubectl delete -f {directory} --dry-run=client",
        "Preview deletion without making changes",
    ),
];

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
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // Two safeguards on each safe subcommand:
    //   1. `(?:\s+--?\S+(?:\s+\S+)?)*` only accepts flag-value pairs between
    //      `kubectl` and the safe subcommand — so a destructive command
    //      like `kubectl delete deployment get` (resource literally named
    //      `get`) can't short-circuit via the trailing `get` token.
    //   2. `(?=\s|$)` on the trailing side so a resource name that STARTS
    //      with the subcommand keyword (e.g. `get-handler`, `logs-archive`)
    //      also can't short-circuit.
    vec![
        // get/describe/logs are safe (read-only)
        safe_pattern!(
            "kubectl-get",
            r"kubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "kubectl-describe",
            r"kubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+describe(?=\s|$)"
        ),
        safe_pattern!(
            "kubectl-logs",
            r"kubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+logs(?=\s|$)"
        ),
        // dry-run is safe
        safe_pattern!(
            "kubectl-dry-run",
            r"kubectl\b.*--dry-run(?:=(?:client|server))?(?:\s|$)"
        ),
        // diff is safe (shows what would change)
        safe_pattern!(
            "kubectl-diff",
            r"kubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+diff(?=\s|$)"
        ),
        // explain is safe (documentation)
        safe_pattern!(
            "kubectl-explain",
            r"kubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+explain(?=\s|$)"
        ),
        // top is safe (metrics)
        safe_pattern!(
            "kubectl-top",
            r"kubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+top(?=\s|$)"
        ),
        // config is safe
        safe_pattern!(
            "kubectl-config",
            r"kubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+config(?=\s|$)"
        ),
        // api-resources/api-versions are safe
        safe_pattern!(
            "kubectl-api",
            r"kubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+api-(?:resources|versions)(?=\s|$)"
        ),
        // version is safe
        safe_pattern!(
            "kubectl-version",
            r"kubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+version(?=\s|$)"
        ),
    ]
}

#[allow(clippy::too_many_lines)]
fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // delete namespace
        destructive_pattern!(
            "delete-namespace",
            r"kubectl\b.*?\bdelete\s+(?:namespace|ns)\b",
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
             kubectl delete deployment <name> -n <namespace>  # Delete specific resources",
            DELETE_NAMESPACE_SUGGESTIONS
        ),
        // delete all
        destructive_pattern!(
            "delete-all",
            r"kubectl\b.*?\bdelete\s+.*--all\b",
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
             kubectl delete <resource> -l app=myapp  # Use label selectors",
            DELETE_ALL_SUGGESTIONS
        ),
        // delete with -A (all namespaces)
        destructive_pattern!(
            "delete-all-namespaces",
            r"kubectl\b.*?\bdelete\s+.*(?:-A\b|--all-namespaces)",
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
            r"kubectl\b.*?\bdrain\b",
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
            r"kubectl\b.*?\bcordon\b",
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
            r"kubectl\b.*?\btaint\s+.*:NoExecute",
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
            r"kubectl\b.*?\bdelete\s+(?:deployment|statefulset|daemonset|replicaset)\b(?!.*--dry-run(?:=(?:client|server))?(?:\s|$))",
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
            r"kubectl\b.*?\bdelete\s+(?:pvc|persistentvolumeclaim)\b(?!.*--dry-run(?:=(?:client|server))?(?:\s|$))",
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
             kubectl delete pvc <name> --dry-run=client",
            DELETE_PVC_SUGGESTIONS
        ),
        // delete pv (persistent volume)
        destructive_pattern!(
            "delete-pv",
            r"kubectl\b.*?\bdelete\s+(?:pv|persistentvolume)\b(?!.*--dry-run(?:=(?:client|server))?(?:\s|$))",
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
            r"kubectl\b.*?\bscale\s+.*--replicas=0",
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
            r"kubectl\b.*?\bdelete\s+.*--force.*--grace-period=0|kubectl\b.*?\bdelete\s+.*--grace-period=0.*--force",
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
             kubectl describe pod <name> | grep -A5 Status",
            DELETE_FORCE_SUGGESTIONS
        ),
        // apply --force
        destructive_pattern!(
            "apply-force",
            r"kubectl\b.*?\bapply\s+.*--force\b",
            "kubectl apply --force deletes and recreates resources, causing downtime.",
            High,
            "kubectl apply --force deletes the resource and recreates it from the manifest. \
             This causes:\n\n\
             - Downtime as pods are terminated before new ones start\n\
             - Loss of any runtime modifications\n\
             - Potential data loss for stateful workloads\n\
             - Disruption to in-flight requests\n\n\
             Use this only when you cannot update resources normally due to immutable field changes.\n\n\
             Preview changes first:\n  \
             kubectl diff -f <file>\n\n\
             Try server-side apply for safer updates:\n  \
             kubectl apply --server-side -f <file>",
            APPLY_FORCE_SUGGESTIONS
        ),
        // delete -f with directory (batch deletion)
        destructive_pattern!(
            "delete-from-directory",
            r"kubectl\b.*?\bdelete\s+-f\s+\.\s*$|kubectl\b.*?\bdelete\s+-f\s+\./|kubectl\b.*?\bdelete\s+--recursive\s+-f|kubectl\b.*?\bdelete\s+-f.*--recursive",
            "kubectl delete -f with directories or --recursive deletes many resources at once.",
            High,
            "Deleting from a directory or recursively removes ALL resources defined in those files:\n\n\
             - Multiple deployments, services, configmaps deleted at once\n\
             - Hard to recover if wrong directory\n\
             - No confirmation or preview by default\n\n\
             Always preview first:\n  \
             kubectl diff -f <directory>\n  \
             ls -la <directory>/*.yaml\n\n\
             Delete specific files instead:\n  \
             kubectl delete -f <specific-file.yaml>",
            DELETE_FROM_DIR_SUGGESTIONS
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn kubectl_patterns_match_with_global_flags() {
        // Same class bug as every other CLI pack: kubectl global flags
        // (`--context`, `--kubeconfig`, `--namespace`/`-n`, `--user`,
        // `--cluster`, `--server`, `-v`) between `kubectl` and the
        // subcommand break every `kubectl\s+<sub>` pattern. This is
        // the single most common kubectl usage shape — any operator
        // working against multiple clusters or explicit namespaces
        // routinely uses `--context` / `-n`.
        let pack = create_pack();
        // delete namespace with --context
        assert_blocks(
            &pack,
            "kubectl --context prod delete namespace critical",
            "namespace",
        );
        // delete --all with --kubeconfig
        assert_blocks(
            &pack,
            "kubectl --kubeconfig /tmp/prod.yaml delete deployment --all",
            "--all",
        );
        // delete across all namespaces with --context.  The broader
        // `delete-all` rule (matching `--all`) fires before the more
        // specific `delete-all-namespaces` — both reasons are accurate
        // but `delete-all`'s reason lands first; the test just asserts
        // *some* kind of "all" block fires.
        assert_blocks(
            &pack,
            "kubectl --context prod delete pods --all-namespaces -l app=legacy",
            "ALL resources",
        );
        // drain with explicit context
        assert_blocks(
            &pack,
            "kubectl --context prod drain node-1 --ignore-daemonsets",
            "drain",
        );
        // force+grace-period=0 with -n namespace
        assert_blocks(
            &pack,
            "kubectl -n prod delete pod stuck-pod --force --grace-period=0",
            "force",
        );
        // delete pvc with --context
        assert_blocks(
            &pack,
            "kubectl --context prod delete pvc prod-db-data",
            "pvc",
        );
        // apply --force with --context
        assert_blocks(
            &pack,
            "kubectl --context prod apply -f manifest.yaml --force",
            "force",
        );
    }

    #[test]
    fn kubectl_safe_patterns_do_not_bypass_via_flag_value() {
        // The flag-as-safe-word bypass class: widening the safe
        // patterns' service-anchor must not let destructive commands
        // with flag values like `--get-url`, `--describe-pod`,
        // `--top-logs` sneak through. Only positional `get`/`describe`
        // /`logs`/etc. should match safe rules.
        let pack = create_pack();
        // Genuine read commands still allowed
        assert_allows(&pack, "kubectl get pods");
        assert_allows(&pack, "kubectl --context prod get pods");
        assert_allows(&pack, "kubectl describe pod foo");
        assert_allows(&pack, "kubectl logs deployment/foo");
        // Safe positional after global flags
        assert_allows(&pack, "kubectl -n prod get pods");
        // Genuine dry-run bypass stays allowed
        assert_allows(
            &pack,
            "kubectl --context prod delete deployment foo --dry-run=client",
        );
    }

    #[test]
    fn safe_subcommand_inside_resource_name_does_not_short_circuit() {
        // Resource names often contain read-only subcommand keywords as
        // substrings. Without the `(?=\s|$)` anchor, `kubectl delete
        // deployment get-handler` matches the `kubectl-get` safe rule via
        // `get` in `get-handler`, short-circuiting the destructive
        // `delete-workload` check.
        let pack = create_pack();
        assert!(
            pack.check("kubectl delete deployment get-handler")
                .is_some(),
            "delete deployment named `get-handler` must still block"
        );
        assert!(
            pack.check("kubectl delete statefulset describe-worker")
                .is_some(),
            "delete statefulset named `describe-worker` must still block"
        );
        assert!(
            pack.check("kubectl delete daemonset logs-archive")
                .is_some(),
            "delete daemonset named `logs-archive` must still block"
        );
        assert!(
            pack.check("kubectl delete pvc top-disk").is_some(),
            "delete pvc named `top-disk` must still block"
        );

        // Bare subcommands still short-circuit.
        assert_allows(&pack, "kubectl get pods");
        assert_allows(&pack, "kubectl describe pod foo");
        assert_allows(&pack, "kubectl logs deployment/myapp");
    }

    #[test]
    fn kubectl_blocks_each_destructive_pattern() {
        let pack = create_pack();
        assert_blocks(&pack, "kubectl delete namespace production", "namespace");
        assert_blocks(&pack, "kubectl delete ns staging", "namespace");
        assert_blocks(&pack, "kubectl delete pods --all", "--all");
        assert_blocks(
            &pack,
            "kubectl delete pods --all-namespaces",
            "ALL resources",
        );
        assert_blocks(&pack, "kubectl delete pods -A", "ALL namespaces");
        assert_blocks(&pack, "kubectl drain node-1", "drain");
        assert_blocks(&pack, "kubectl cordon node-1", "cordon");
        assert_blocks(
            &pack,
            "kubectl taint nodes node-1 key=val:NoExecute",
            "NoExecute",
        );
        assert_blocks(&pack, "kubectl delete deployment web-api", "workload");
        assert_blocks(&pack, "kubectl delete statefulset db-cluster", "workload");
        assert_blocks(&pack, "kubectl delete pvc data-volume", "pvc");
        assert_blocks(&pack, "kubectl delete pv my-volume", "pv");
        assert_blocks(
            &pack,
            "kubectl scale deployment web --replicas=0",
            "replicas=0",
        );
        assert_blocks(
            &pack,
            "kubectl delete pod foo --force --grace-period=0",
            "force",
        );
        assert_blocks(&pack, "kubectl apply -f deploy.yaml --force", "force");
        assert_blocks(&pack, "kubectl delete -f ./manifests/", "directories");
    }

    #[test]
    fn kubectl_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(
            &pack,
            "kubectl delete namespace production",
            Severity::Critical,
        );
        assert_blocks_with_severity(&pack, "kubectl delete pods --all", Severity::High);
        assert_blocks_with_severity(&pack, "kubectl delete pods -A", Severity::Critical);
        assert_blocks_with_severity(&pack, "kubectl drain node-1", Severity::High);
        assert_blocks_with_severity(&pack, "kubectl cordon node-1", Severity::Medium);
        assert_blocks_with_severity(
            &pack,
            "kubectl taint nodes n1 k=v:NoExecute",
            Severity::High,
        );
        assert_blocks_with_severity(&pack, "kubectl delete pvc data-vol", Severity::Critical);
        assert_blocks_with_severity(&pack, "kubectl delete pv my-vol", Severity::Critical);
        assert_blocks_with_severity(
            &pack,
            "kubectl delete pod foo --force --grace-period=0",
            Severity::Critical,
        );
    }

    #[test]
    fn kubectl_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "kubectl get pods");
        assert_safe_pattern_matches(&pack, "kubectl describe pod foo");
        assert_safe_pattern_matches(&pack, "kubectl logs foo");
        assert_safe_pattern_matches(&pack, "kubectl delete pod foo --dry-run=client");
        assert_safe_pattern_matches(&pack, "kubectl diff -f deploy.yaml");
        assert_safe_pattern_matches(&pack, "kubectl explain deployment");
        assert_safe_pattern_matches(&pack, "kubectl top nodes");
        assert_safe_pattern_matches(&pack, "kubectl config view");
        assert_safe_pattern_matches(&pack, "kubectl api-resources");
        assert_safe_pattern_matches(&pack, "kubectl api-versions");
        assert_safe_pattern_matches(&pack, "kubectl version");
    }

    #[test]
    fn kubectl_dry_run_overrides_destructive() {
        let pack = create_pack();
        assert_allows(
            &pack,
            "kubectl delete namespace production --dry-run=client",
        );
        assert_allows(&pack, "kubectl delete deployment web --dry-run=server");
        assert_allows(&pack, "kubectl delete deployment web --dry-run");
    }

    #[test]
    fn kubectl_dry_run_none_does_not_bypass_destructive_patterns() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "kubectl delete deployment web --dry-run=none",
            "delete-workload",
        );
        assert_blocks_with_pattern(
            &pack,
            "kubectl delete pvc data --dry-run=none",
            "delete-pvc",
        );
        assert_blocks_with_pattern(&pack, "kubectl delete pv data --dry-run=none", "delete-pv");
        assert_no_safe_match(&pack, "kubectl delete deployment web --dry-run=none");
    }

    #[test]
    fn kubectl_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo kubectl");
    }
}
