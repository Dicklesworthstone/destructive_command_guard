//! kubectl patterns - protections against destructive kubectl commands.
//!
//! This includes patterns for:
//! - delete namespace/all resources
//! - drain nodes
//! - cordon nodes
//! - delete without dry-run

use crate::destructive_pattern;
use crate::packs::regex_engine::LazyCompiledRegex;
use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};

// Exemption-only grammar (#435). Required global values must not be optional:
// a boolean flag must not swallow `delete`, and a string value must not pose
// as a read-only subcommand. Destructive matching deliberately stays broad.
macro_rules! kubectl_safe_pattern {
    ($name:literal, $verb:literal) => {
        SafePattern {
            name: $name,
            regex: LazyCompiledRegex::new(concat!(
                r"^[ \t]*(?:[^\s;&|<>()\x22'\\$`]+/)?kubectl(?:\.exe)?",
                r"(?:[ \t]+(?:--(?:as|as-group|as-uid|cache-dir|certificate-authority|client-certificate|client-key|cluster|context|kubeconfig|kuberc|namespace|password|profile|profile-output|request-timeout|server|tls-server-name|token|user|username|v|vmodule)(?:=[^\s;&|<>()\x22'\\$`]+|[ \t]+[^\s;&|<>()\x22'\\$`]+)",
                r"|-[nsv](?:[^\s;&|<>()\x22'\\$`]+|[ \t]+[^\s;&|<>()\x22'\\$`]+)",
                r"|--(?:disable-compression|insecure-skip-tls-verify|match-server-version|warnings-as-errors)(?:=(?:true|false))?))*[ \t]+",
                $verb,
                r"(?=\s|$)"
            )),
        }
    };
}

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
    PatternSuggestion::gated(
        "kubectl delete ns {ns} --grace-period=60",
        "Allow graceful shutdown with a 60-second grace period — still a namespace delete, so it is gated as well",
    ),
];

/// Suggestions for `kubectl delete --all` pattern.
const DELETE_ALL_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "kubectl delete {resource} --all --dry-run=client",
        "Preview deletion without making changes",
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
        // `/api/v1/` and `/apis/` are what the `api-delete-*` rules key on. A
        // raw API call contains no "kubectl", so without them those rules
        // cannot fire — the #441/#447 gate-reachability shape. Mirrored in the
        // `PACK_ENTRIES` row, which is the gate that actually decides.
        keywords: &[
            "kubectl", "delete", "drain", "cordon", "taint", "/api/v1/", "/apis/",
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
        kubectl_safe_pattern!("kubectl-get", "get"),
        kubectl_safe_pattern!("kubectl-describe", "describe"),
        kubectl_safe_pattern!("kubectl-logs", "logs"),
        kubectl_safe_pattern!("kubectl-diff", "diff"),
        kubectl_safe_pattern!("kubectl-explain", "explain"),
        kubectl_safe_pattern!("kubectl-top", "top"),
        kubectl_safe_pattern!("kubectl-config", "config"),
        kubectl_safe_pattern!("kubectl-api", "api-(?:resources|versions)"),
        kubectl_safe_pattern!("kubectl-version", "version"),
    ]
}

/// Prove the effective preview from whole shell words, never a substring of
/// argument data (#435). Both Pack safe-matching paths call this function.
/// Unknown syntax/option arity withdraws the exemption, not a denial rule.
pub(crate) fn dry_run_is_effectively_safe(command: &str) -> bool {
    let mut saw_preview = false;
    for segment in crate::packs::split_command_segments(command) {
        let stripped = crate::normalize::strip_wrapper_prefixes(segment);
        if stripped.wrapper_limit_reached {
            return false;
        }
        let source = stripped.normalized.as_ref();
        let Ok(tokens) = shell_words::split(source) else {
            return false;
        };
        let Some(executable) = tokens.first() else {
            continue;
        };
        if !is_kubectl_executable(executable) {
            // Do not re-anchor at an argument named kubectl. Such a segment
            // can still trip the permissive whole-command deny expressions.
            if tokens.iter().any(|token| is_kubectl_executable(token)) {
                return false;
            }
            continue;
        }
        if kubectl_command_contains_dynamic_shell_syntax(source) {
            return false;
        }
        match invocation_preview(&tokens[1..]) {
            Some(preview) => saw_preview |= preview,
            None => return false,
        }
    }
    saw_preview
}

fn is_kubectl_executable(token: &str) -> bool {
    token.rsplit(['/', '\\']).next().is_some_and(|name| {
        name.eq_ignore_ascii_case("kubectl") || name.eq_ignore_ascii_case("kubectl.exe")
    })
}

/// Some(false) is a known read-only invocation; Some(true) is a proven
/// preview; None means the invocation must face the destructive rules.
fn invocation_preview(args: &[String]) -> Option<bool> {
    let mut index = 0;
    while args.get(index).is_some_and(|arg| arg.starts_with('-')) {
        index = consume_known_option(args, index, false)?;
    }
    let subcommand = args.get(index)?.as_str();
    if matches!(
        subcommand,
        "get"
            | "describe"
            | "logs"
            | "diff"
            | "explain"
            | "top"
            | "config"
            | "api-resources"
            | "api-versions"
            | "version"
            | "kustomize"
    ) {
        return Some(false);
    }
    if !matches!(
        subcommand,
        "delete" | "apply" | "drain" | "cordon" | "taint" | "scale"
    ) {
        return None;
    }
    index += 1;
    let mut effective = None;
    while let Some(arg) = args.get(index) {
        if arg == "--" {
            break;
        }
        if arg == "--dry-run" {
            // pflag's NoOptDefVal applies WITHOUT consuming the next word.
            // `--dry-run false` is a preview plus a positional word, not false.
            effective = Some(true);
            index += 1;
        } else if let Some(value) = arg.strip_prefix("--dry-run=") {
            // String options are assigned in order; kubectl validates the
            // final value. Do not lowercase client/server: they are case-sensitive.
            effective = Some(matches!(
                value,
                "client" | "server" | "unchanged" | "true" | "True" | "TRUE" | "1" | "t" | "T"
            ));
            index += 1;
        } else if arg.starts_with('-') && arg != "-" {
            index = consume_known_option(args, index, true)?;
        } else {
            index += 1;
        }
    }
    effective.filter(|preview| *preview)
}

/// Advance across one pflag option, consuming a required value even when it
/// starts with `--`. The bool is option scope, not an inference about arity.
/// Notably --raw is absent: a raw request must never inherit a preview proof.
fn consume_known_option(args: &[String], index: usize, local: bool) -> Option<usize> {
    let arg = args.get(index)?;
    if let Some(long) = arg.strip_prefix("--") {
        let (name, attached) = long
            .split_once('=')
            .map_or((long, false), |(name, _)| (name, true));
        if global_value_option(name) || local && local_value_option(name) {
            return if attached {
                Some(index + 1)
            } else {
                args.get(index + 1).map(|_| index + 2)
            };
        }
        if matches!(
            name,
            "disable-compression"
                | "insecure-skip-tls-verify"
                | "match-server-version"
                | "warnings-as-errors"
                | "help"
        ) || local
            && matches!(
                name,
                "all"
                    | "all-namespaces"
                    | "force"
                    | "ignore-not-found"
                    | "now"
                    | "wait"
                    | "interactive"
                    | "recursive"
                    | "cascade"
                    | "validate"
                    | "overwrite"
                    | "server-side"
                    | "force-conflicts"
                    | "prune"
                    | "record"
                    | "save-config"
                    | "dry-run"
                    | "ignore-daemonsets"
                    | "delete-emptydir-data"
                    | "disable-eviction"
            )
        {
            return Some(index + 1);
        }
        return None;
    }
    let flags = arg.strip_prefix('-')?.as_bytes();
    if flags.is_empty() {
        return None;
    }
    for (position, flag) in flags.iter().copied().enumerate() {
        if matches!(flag, b'n' | b's' | b'v') || local && matches!(flag, b'f' | b'k' | b'l' | b'o')
        {
            return if position + 1 < flags.len() {
                Some(index + 1)
            } else {
                args.get(index + 1).map(|_| index + 2)
            };
        }
        if flag != b'h' && !(local && matches!(flag, b'A' | b'R' | b'i')) {
            return None;
        }
        // A bool shorthand with `=value` consumes the rest of this token.
        if flags.get(position + 1) == Some(&b'=') {
            return Some(index + 1);
        }
    }
    Some(index + 1)
}

fn global_value_option(name: &str) -> bool {
    matches!(
        name,
        "as" | "as-group"
            | "as-uid"
            | "cache-dir"
            | "certificate-authority"
            | "client-certificate"
            | "client-key"
            | "cluster"
            | "context"
            | "kubeconfig"
            | "kuberc"
            | "namespace"
            | "password"
            | "profile"
            | "profile-output"
            | "request-timeout"
            | "server"
            | "tls-server-name"
            | "token"
            | "user"
            | "username"
            | "v"
            | "vmodule"
    )
}

fn local_value_option(name: &str) -> bool {
    matches!(
        name,
        "filename"
            | "kustomize"
            | "selector"
            | "field-selector"
            | "grace-period"
            | "timeout"
            | "output"
            | "field-manager"
            | "replicas"
            | "current-replicas"
            | "resource-version"
            | "pod-selector"
            | "skip-wait-for-delete-timeout"
            | "chunk-size"
            | "prune-allowlist"
            | "prune-whitelist"
            | "template"
    )
}

fn kubectl_command_contains_dynamic_shell_syntax(command: &str) -> bool {
    let mut in_single = false;
    let mut in_double = false;
    for byte in command.bytes() {
        if byte == b'\'' && !in_double {
            in_single = !in_single;
            continue;
        }
        if byte == b'"' && !in_single {
            in_double = !in_double;
            continue;
        }
        if in_single {
            continue;
        }
        if matches!(byte, b'\\' | b'$' | b'`' | b'%' | b'!' | b'^')
            || (!in_double
                && matches!(
                    byte,
                    b'*' | b'?' | b'[' | b'{' | b'~' | b';' | b'|' | b'&' | b'<' | b'>'
                ))
        {
            return true;
        }
    }
    in_single || in_double
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
            r"kubectl\b.*?\bdelete\s+(?:deployment|statefulset|daemonset|replicaset)\b",
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
            r"kubectl\b.*?\bdelete\s+(?:pvc|persistentvolumeclaim)\b",
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
            r"kubectl\b.*?\bdelete\s+(?:pv|persistentvolume)\b",
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
        // ---- the same operations spelled as raw API calls (#449) ----
        //
        // This pack modelled the `kubectl` CLI and not the Kubernetes API, so
        // the same deletion was denied as a CLI call and allowed as a `curl`
        // call to the API server. An agent that hits a blocked `kubectl delete`
        // has a working alternative in the shape it reaches for next.
        //
        // These MIRROR the CLI rules above rather than going beyond them, which
        // is the point: a resource the CLI side does not gate — `secrets`,
        // `configmaps`, a pod deleted by name — is not gated here either, so
        // the two spellings agree in both directions. Making REST stricter than
        // the CLI would be the same asymmetry in the other direction.
        //
        // The paths are versioned and machine-generated, which is what makes
        // them safe to anchor on:
        //   core group:  /api/v1/namespaces/{ns}/{resource}[/{name}]
        //   named group: /apis/{group}/{version}/namespaces/{ns}/{resource}[/{name}]
        //   cluster:     /api/v1/{resource}/{name}
        //
        // Limit, stated rather than discovered later: these match `curl`, as
        // every other REST rule in this codebase does. `wget --method=DELETE`
        // and httpie's `http DELETE` are not covered, and widening the HTTP
        // client set is a decision for all the REST packs at once, not this one.
        destructive_pattern!(
            "api-delete-namespace",
            r#"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*/api/v1/namespaces/[^/\s'"]+(?:["'\s]|$)).*"#,
            "DELETE to /api/v1/namespaces/<name> removes the namespace and ALL resources in it.",
            Critical,
            "This is `kubectl delete namespace` spelled as an API call, and it destroys \
             everything inside the namespace:\n\n\
             - All deployments, pods, services\n\
             - All configmaps and secrets\n\
             - All persistent volume claims (data may be lost)\n\n\
             It is irreversible, and the API server applies it without the CLI's \
             confirmation or dry-run affordances.\n\n\
             Preview what would be deleted:\n  \
             kubectl get all -n <namespace>",
            DELETE_NAMESPACE_SUGGESTIONS
        ),
        destructive_pattern!(
            "api-delete-collection",
            r#"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*/namespaces/[^/\s'"]+/[a-z][a-z0-9.-]*(?:["'\s]|$)).*"#,
            "DELETE to a collection path removes every resource of that type in the namespace.",
            High,
            "A DELETE to a path that ends at the resource type, with no /<name> after it, \
             is the API's deleteCollection — the equivalent of `kubectl delete <type> --all`:\n\n\
             - .../pods       kills every pod in the namespace\n\
             - .../services   removes all services (networking breaks)\n\
             - .../persistentvolumeclaims  may delete all persistent data\n\n\
             Name the single resource instead, or use a label selector:\n  \
             kubectl delete <resource> -l app=myapp",
            DELETE_ALL_SUGGESTIONS
        ),
        destructive_pattern!(
            "api-delete-workload",
            r#"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*/(?:deployments|statefulsets|daemonsets|replicasets)/[^/\s'"]+).*"#,
            "DELETE to a workload path removes the controller and the pods it manages.",
            High,
            "This is `kubectl delete deployment/statefulset/daemonset/replicaset` as an \
             API call. The controller is removed and its pods terminate; anything not \
             stored outside the pod is gone.\n\n\
             Check what it manages first:\n  \
             kubectl get all -n <namespace> -l app=<name>"
        ),
        destructive_pattern!(
            "api-delete-persistent-storage",
            r#"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*/(?:persistentvolumeclaims|persistentvolumes)/[^/\s'"]+).*"#,
            "DELETE to a PVC or PV path can permanently destroy the underlying storage.",
            Critical,
            "This is `kubectl delete pvc` / `kubectl delete pv` as an API call:\n\n\
             - Cloud disks (EBS, GCE PD, Azure Disk) may be deleted\n\
             - Data is not recoverable once the volume is released\n\
             - Even with a Retain policy, deleting the PV may trigger cleanup\n\n\
             Check what is bound to it first:\n  \
             kubectl get pvc -A",
            DELETE_PVC_SUGGESTIONS
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
             kubectl get deployment <name> --replicas=0\n\n\
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
        destructive_pattern!(
            "delete-from-stdin",
            r#"kubectl\b.*?\bdelete\b.*?(?:-f(?:=|\s+)?|--filename(?:=|\s+))["']?(?:[^,"'\s]+,)*-(?:,[^,"'\s]+)*["']?(?=\s|$)"#,
            "kubectl delete -f - deletes every resource described by stdin without a reviewable manifest path.",
            High,
            "Materialize the manifest, inspect it with kubectl diff, and run kubectl delete --dry-run=client before deleting the resources."
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

    /// #449: the same operation spelled as a raw API call.
    ///
    /// The property these pin is *agreement between the two spellings*, in
    /// both directions — so the ALLOW cases matter as much as the DENY ones.
    mod raw_api {
        use super::*;

        #[test]
        fn the_four_operations_the_cli_denies_are_denied_as_api_calls() {
            let pack = create_pack();
            for (command, pattern) in [
                (
                    "curl -X DELETE https://k8s.internal/api/v1/namespaces/production",
                    "api-delete-namespace",
                ),
                (
                    "curl -X DELETE https://k8s.internal/api/v1/namespaces/production/pods",
                    "api-delete-collection",
                ),
                (
                    "curl -X DELETE https://k8s.internal/apis/apps/v1/namespaces/production/deployments/web",
                    "api-delete-workload",
                ),
                (
                    "curl -X DELETE https://k8s.internal/api/v1/namespaces/production/persistentvolumeclaims/data",
                    "api-delete-persistent-storage",
                ),
                // Siblings of the same rules, by the same paths.
                (
                    "curl -X DELETE https://k8s.internal/api/v1/persistentvolumes/pv-0001",
                    "api-delete-persistent-storage",
                ),
                (
                    "curl -X DELETE https://k8s.internal/apis/apps/v1/namespaces/production/statefulsets/db",
                    "api-delete-workload",
                ),
                // Spelling variants of the method.
                (
                    "curl -XDELETE https://k8s.internal/api/v1/namespaces/production",
                    "api-delete-namespace",
                ),
                (
                    "curl --request=DELETE https://k8s.internal/api/v1/namespaces/production",
                    "api-delete-namespace",
                ),
            ] {
                assert_blocks_with_pattern(&pack, command, pattern);
            }
        }

        #[test]
        fn what_the_cli_allows_stays_allowed_as_an_api_call() {
            // These mirror the CLI side deliberately: this pack does not gate
            // `kubectl delete secret` or `kubectl delete pod <name>`, so it
            // must not gate their API spellings either. Making REST stricter
            // than the CLI is the same asymmetry as the gap, pointing the
            // other way.
            let pack = create_pack();
            for command in [
                "curl -X DELETE https://k8s.internal/api/v1/namespaces/production/secrets/api-token",
                "curl -X DELETE https://k8s.internal/api/v1/namespaces/production/pods/web-0",
                "curl -X DELETE https://k8s.internal/api/v1/namespaces/production/configmaps/settings",
            ] {
                assert_allows(&pack, command);
            }
        }

        #[test]
        fn only_delete_is_destructive_and_only_on_kubernetes_paths() {
            let pack = create_pack();
            for command in [
                // Reads and writes are not deletions.
                "curl -X GET https://k8s.internal/api/v1/namespaces/production",
                "curl https://k8s.internal/api/v1/namespaces/production/pods",
                "curl -X POST https://k8s.internal/api/v1/namespaces/production/pods",
                "curl -X PATCH https://k8s.internal/apis/apps/v1/namespaces/production/deployments/web",
                // `/api/v1/` is a keyword now, so this is the false positive to
                // watch: an unrelated service that happens to version its API
                // the same way must not be caught by a Kubernetes rule.
                "curl -X DELETE https://example.com/api/v1/widgets/42",
                "curl -X DELETE https://billing.internal/api/v1/invoices/2026-09",
            ] {
                assert_allows(&pack, command);
            }
        }
    }

    #[test]
    fn kubectl_patterns_match_with_global_flags() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "kubectl --context prod delete namespace critical",
            "namespace",
        );
        assert_blocks(
            &pack,
            "kubectl --kubeconfig /tmp/prod.yaml delete deployment --all",
            "--all",
        );
        assert_blocks(
            &pack,
            "kubectl --context prod delete pods --all-namespaces -l app=legacy",
            "ALL resources",
        );
        assert_blocks(
            &pack,
            "kubectl --context prod drain node-1 --ignore-daemonsets",
            "drain",
        );
        assert_blocks(
            &pack,
            "kubectl -n prod delete pod stuck-pod --force --grace-period=0",
            "force",
        );
        assert_blocks(
            &pack,
            "kubectl --context prod delete pvc prod-db-data",
            "pvc",
        );
        assert_blocks(
            &pack,
            "kubectl --context prod apply -f manifest.yaml --force",
            "force",
        );
    }

    #[test]
    fn kubectl_safe_patterns_do_not_bypass_via_flag_value() {
        let pack = create_pack();
        assert_allows(&pack, "kubectl get pods");
        assert_allows(&pack, "kubectl --context prod get pods");
        assert_allows(&pack, "kubectl describe pod foo");
        assert_allows(&pack, "kubectl logs deployment/foo");
        assert_allows(&pack, "kubectl -n prod get pods");
        assert_allows(
            &pack,
            "kubectl --context prod delete deployment foo --dry-run=client",
        );
        for command in [
            "kubectl --warnings-as-errors delete namespace get",
            "kubectl delete namespace prod --cache-dir 'kubectl get'",
            "kubectl delete namespace prod --cache-dir kubectl get",
        ] {
            assert_no_safe_match(&pack, command);
            assert_blocks(&pack, command, "namespace");
        }
    }

    #[test]
    fn safe_subcommand_inside_resource_name_does_not_short_circuit() {
        let pack = create_pack();
        for command in [
            "kubectl delete deployment get-handler",
            "kubectl delete statefulset describe-worker",
            "kubectl delete daemonset logs-archive",
            "kubectl delete pvc top-disk",
        ] {
            assert!(pack.check(command).is_some(), "must block {command}");
        }
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
        for command in [
            "cat manifest.yaml | kubectl delete -f -",
            "kubectl --context prod delete --filename=-",
            "kubectl delete --filename '-'",
            "kubectl delete -f \"-\"",
            "kubectl delete -f-",
            "kubectl delete -f=-",
            "kubectl delete --filename=-,other.yaml",
            "kubectl delete -f other.yaml,-",
            "kubectl delete -f - --dry-run=none",
            "kubectl delete -f - --dry-run=client --dry-run=none",
            "kubectl delete -f - --dry-run=client '--dry-run=none'",
            r"kubectl delete -f - --dry-run=client \--dry-run=none",
            "kubectl delete -f - --dry-run=$DRY_RUN_MODE",
        ] {
            assert_blocks(&pack, command, "stdin");
        }
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
        for command in [
            "kubectl get pods",
            "kubectl describe pod foo",
            "kubectl logs foo",
            "kubectl delete pod foo --dry-run=client",
            "kubectl diff -f deploy.yaml",
            "kubectl explain deployment",
            "kubectl top nodes",
            "kubectl config view",
            "kubectl api-resources",
            "kubectl api-versions",
            "kubectl version",
        ] {
            assert_safe_pattern_matches(&pack, command);
        }
    }

    #[test]
    fn kubectl_dry_run_overrides_destructive() {
        let pack = create_pack();
        for command in [
            "kubectl delete namespace production --dry-run=client",
            "kubectl delete deployment web --dry-run=server",
            "kubectl delete deployment web --dry-run",
            "kubectl delete deployment web --dry-run -o yaml",
            "kubectl delete deployment web --dry-run client",
            "kubectl delete -f '-' --dry-run=\"client\"",
            "generate-manifest | kubectl delete -f - --dry-run=client",
            "kubectl delete -f - --dry-run=none --dry-run=client",
            "kubectl delete -f - --dry-run=client -- --dry-run=none",
            // NoOptDefVal: a separated word does not disable a bare flag.
            "kubectl delete -f - --dry-run false",
            "kubectl delete -f - --dry-run=client --dry-run false",
            "kubectl delete ns prod --dry-run=client --cache-dir --dry-run=none",
            "kubectl delete ns prod --cache-dir 'note --dry-run=none' --dry-run=client",
            "kubectl delete ns prod --dry-run=client --cache-dir 'note --cache-dir'",
            "sudo kubectl delete ns prod --dry-run=client",
            "kubectl kustomize ./prod | kubectl delete -f - --dry-run=client",
            "kubectl delete ns one --dry-run=client; kubectl delete ns two --dry-run=server",
        ] {
            assert!(
                dry_run_is_effectively_safe(command),
                "preview proof failed: {command}"
            );
            assert_allows(&pack, command);
        }
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
    fn kubectl_preview_cannot_come_from_data_or_hide_a_disabling_option() {
        let pack = create_pack();
        for command in [
            "kubectl delete ns prod --cache-dir --dry-run=client",
            "kubectl delete ns prod --cache-dir=--dry-run=client",
            "kubectl delete ns prod --context --dry-run",
            "kubectl delete ns prod -n--dry-run=client",
            "kubectl delete ns prod --cache-dir 'note --dry-run=client'",
            "kubectl delete ns prod --dry-run=client --cache-dir 'note --cache-dir' --dry-run=none",
            "kubectl delete ns prod -- --dry-run=client",
            "kubectl delete ns prod --dry-run=client --unknown-option value",
            "kubectl delete ns prod --dry-run=client --raw /api/v1/namespaces/prod",
            "kubectl delete ns prod --dry-run=client --cache-dir ${ARGS}",
            "kubectl delete ns prod --dry-run=client --cache-dir %ARGS%",
            "kubectl delete ns prod --dry-run=client --cache-dir *",
            "kubectl delete ns prod; kubectl delete ns other --dry-run=client",
            "kubectl delete ns prod --dry-run=client; kubectl delete ns other",
        ] {
            assert!(
                !dry_run_is_effectively_safe(command),
                "invalid proof: {command}"
            );
            assert_blocks(&pack, command, "namespace");
        }
        assert!(!dry_run_is_effectively_safe(
            "echo kubectl delete ns prod --dry-run=client"
        ));
    }

    #[test]
    fn kubectl_preview_respects_short_option_arity() {
        for command in [
            "kubectl delete ns prod -n --dry-run=client",
            "kubectl delete ns prod -Rf--dry-run=client",
            "kubectl delete ns prod --filename --dry-run=client",
        ] {
            assert!(
                !dry_run_is_effectively_safe(command),
                "data was accepted as preview: {command}"
            );
        }
        assert!(dry_run_is_effectively_safe(
            "kubectl delete -Rfmanifest.yaml --dry-run=client"
        ));
        assert!(dry_run_is_effectively_safe(
            "kubectl -v6 delete ns prod --dry-run=server"
        ));
    }

    #[test]
    fn kubectl_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo kubectl");
    }
}
