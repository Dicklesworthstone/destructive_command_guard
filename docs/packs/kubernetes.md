# Kubernetes Packs

This document describes packs in the `kubernetes` category.

## Packs in this Category

- [kubectl](#kuberneteskubectl)
- [Helm](#kuberneteshelm)
- [Kustomize](#kuberneteskustomize)

---

## kubectl

**Pack ID:** `kubernetes.kubectl`

Protects against destructive kubectl operations like delete namespace, drain, and mass deletion

### Keywords

Commands containing these keywords are checked against this pack:

- `kubectl`
- `delete`
- `drain`
- `cordon`
- `taint`
- `/api/v1/`
- `/apis/`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `kubectl-get` | `^[ \t]*(?:[^\s;&\|<>()\x22'\\$`]+/)?kubectl(?:\.exe)?(?:[ \t]+(?:--(?:as\|as-group\|as-uid\|cache-dir\|certificate-authority\|client-certificate\|client-key\|cluster\|context\|kubeconfig\|kuberc\|namespace\|password\|profile\|profile-output\|request-timeout\|server\|tls-server-name\|token\|user\|username\|v\|vmodule)(?:=[^\s;&\|<>()\x22'\\$`]+\|[ \t]+[^\s;&\|<>()\x22'\\$`]+)\|-[nsv](?:[^\s;&\|<>()\x22'\\$`]+\|[ \t]+[^\s;&\|<>()\x22'\\$`]+)\|--(?:disable-compression\|insecure-skip-tls-verify\|match-server-version\|warnings-as-errors)(?:=(?:true\|false))?))*[ \t]+get(?=\s\|$)` |
| `kubectl-describe` | `^[ \t]*(?:[^\s;&\|<>()\x22'\\$`]+/)?kubectl(?:\.exe)?(?:[ \t]+(?:--(?:as\|as-group\|as-uid\|cache-dir\|certificate-authority\|client-certificate\|client-key\|cluster\|context\|kubeconfig\|kuberc\|namespace\|password\|profile\|profile-output\|request-timeout\|server\|tls-server-name\|token\|user\|username\|v\|vmodule)(?:=[^\s;&\|<>()\x22'\\$`]+\|[ \t]+[^\s;&\|<>()\x22'\\$`]+)\|-[nsv](?:[^\s;&\|<>()\x22'\\$`]+\|[ \t]+[^\s;&\|<>()\x22'\\$`]+)\|--(?:disable-compression\|insecure-skip-tls-verify\|match-server-version\|warnings-as-errors)(?:=(?:true\|false))?))*[ \t]+describe(?=\s\|$)` |
| `kubectl-logs` | `^[ \t]*(?:[^\s;&\|<>()\x22'\\$`]+/)?kubectl(?:\.exe)?(?:[ \t]+(?:--(?:as\|as-group\|as-uid\|cache-dir\|certificate-authority\|client-certificate\|client-key\|cluster\|context\|kubeconfig\|kuberc\|namespace\|password\|profile\|profile-output\|request-timeout\|server\|tls-server-name\|token\|user\|username\|v\|vmodule)(?:=[^\s;&\|<>()\x22'\\$`]+\|[ \t]+[^\s;&\|<>()\x22'\\$`]+)\|-[nsv](?:[^\s;&\|<>()\x22'\\$`]+\|[ \t]+[^\s;&\|<>()\x22'\\$`]+)\|--(?:disable-compression\|insecure-skip-tls-verify\|match-server-version\|warnings-as-errors)(?:=(?:true\|false))?))*[ \t]+logs(?=\s\|$)` |
| `kubectl-diff` | `^[ \t]*(?:[^\s;&\|<>()\x22'\\$`]+/)?kubectl(?:\.exe)?(?:[ \t]+(?:--(?:as\|as-group\|as-uid\|cache-dir\|certificate-authority\|client-certificate\|client-key\|cluster\|context\|kubeconfig\|kuberc\|namespace\|password\|profile\|profile-output\|request-timeout\|server\|tls-server-name\|token\|user\|username\|v\|vmodule)(?:=[^\s;&\|<>()\x22'\\$`]+\|[ \t]+[^\s;&\|<>()\x22'\\$`]+)\|-[nsv](?:[^\s;&\|<>()\x22'\\$`]+\|[ \t]+[^\s;&\|<>()\x22'\\$`]+)\|--(?:disable-compression\|insecure-skip-tls-verify\|match-server-version\|warnings-as-errors)(?:=(?:true\|false))?))*[ \t]+diff(?=\s\|$)` |
| `kubectl-explain` | `^[ \t]*(?:[^\s;&\|<>()\x22'\\$`]+/)?kubectl(?:\.exe)?(?:[ \t]+(?:--(?:as\|as-group\|as-uid\|cache-dir\|certificate-authority\|client-certificate\|client-key\|cluster\|context\|kubeconfig\|kuberc\|namespace\|password\|profile\|profile-output\|request-timeout\|server\|tls-server-name\|token\|user\|username\|v\|vmodule)(?:=[^\s;&\|<>()\x22'\\$`]+\|[ \t]+[^\s;&\|<>()\x22'\\$`]+)\|-[nsv](?:[^\s;&\|<>()\x22'\\$`]+\|[ \t]+[^\s;&\|<>()\x22'\\$`]+)\|--(?:disable-compression\|insecure-skip-tls-verify\|match-server-version\|warnings-as-errors)(?:=(?:true\|false))?))*[ \t]+explain(?=\s\|$)` |
| `kubectl-top` | `^[ \t]*(?:[^\s;&\|<>()\x22'\\$`]+/)?kubectl(?:\.exe)?(?:[ \t]+(?:--(?:as\|as-group\|as-uid\|cache-dir\|certificate-authority\|client-certificate\|client-key\|cluster\|context\|kubeconfig\|kuberc\|namespace\|password\|profile\|profile-output\|request-timeout\|server\|tls-server-name\|token\|user\|username\|v\|vmodule)(?:=[^\s;&\|<>()\x22'\\$`]+\|[ \t]+[^\s;&\|<>()\x22'\\$`]+)\|-[nsv](?:[^\s;&\|<>()\x22'\\$`]+\|[ \t]+[^\s;&\|<>()\x22'\\$`]+)\|--(?:disable-compression\|insecure-skip-tls-verify\|match-server-version\|warnings-as-errors)(?:=(?:true\|false))?))*[ \t]+top(?=\s\|$)` |
| `kubectl-config` | `^[ \t]*(?:[^\s;&\|<>()\x22'\\$`]+/)?kubectl(?:\.exe)?(?:[ \t]+(?:--(?:as\|as-group\|as-uid\|cache-dir\|certificate-authority\|client-certificate\|client-key\|cluster\|context\|kubeconfig\|kuberc\|namespace\|password\|profile\|profile-output\|request-timeout\|server\|tls-server-name\|token\|user\|username\|v\|vmodule)(?:=[^\s;&\|<>()\x22'\\$`]+\|[ \t]+[^\s;&\|<>()\x22'\\$`]+)\|-[nsv](?:[^\s;&\|<>()\x22'\\$`]+\|[ \t]+[^\s;&\|<>()\x22'\\$`]+)\|--(?:disable-compression\|insecure-skip-tls-verify\|match-server-version\|warnings-as-errors)(?:=(?:true\|false))?))*[ \t]+config(?=\s\|$)` |
| `kubectl-api` | `^[ \t]*(?:[^\s;&\|<>()\x22'\\$`]+/)?kubectl(?:\.exe)?(?:[ \t]+(?:--(?:as\|as-group\|as-uid\|cache-dir\|certificate-authority\|client-certificate\|client-key\|cluster\|context\|kubeconfig\|kuberc\|namespace\|password\|profile\|profile-output\|request-timeout\|server\|tls-server-name\|token\|user\|username\|v\|vmodule)(?:=[^\s;&\|<>()\x22'\\$`]+\|[ \t]+[^\s;&\|<>()\x22'\\$`]+)\|-[nsv](?:[^\s;&\|<>()\x22'\\$`]+\|[ \t]+[^\s;&\|<>()\x22'\\$`]+)\|--(?:disable-compression\|insecure-skip-tls-verify\|match-server-version\|warnings-as-errors)(?:=(?:true\|false))?))*[ \t]+api-(?:resources\|versions)(?=\s\|$)` |
| `kubectl-version` | `^[ \t]*(?:[^\s;&\|<>()\x22'\\$`]+/)?kubectl(?:\.exe)?(?:[ \t]+(?:--(?:as\|as-group\|as-uid\|cache-dir\|certificate-authority\|client-certificate\|client-key\|cluster\|context\|kubeconfig\|kuberc\|namespace\|password\|profile\|profile-output\|request-timeout\|server\|tls-server-name\|token\|user\|username\|v\|vmodule)(?:=[^\s;&\|<>()\x22'\\$`]+\|[ \t]+[^\s;&\|<>()\x22'\\$`]+)\|-[nsv](?:[^\s;&\|<>()\x22'\\$`]+\|[ \t]+[^\s;&\|<>()\x22'\\$`]+)\|--(?:disable-compression\|insecure-skip-tls-verify\|match-server-version\|warnings-as-errors)(?:=(?:true\|false))?))*[ \t]+version(?=\s\|$)` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `delete-namespace` | kubectl delete namespace removes the entire namespace and ALL resources within it. | critical |
| `delete-all` | kubectl delete --all removes ALL resources of that type. Use --dry-run=client first. | high |
| `delete-all-namespaces` | kubectl delete with -A/--all-namespaces affects ALL namespaces. Very dangerous! | critical |
| `drain-node` | kubectl drain evicts all pods from a node. Ensure proper pod disruption budgets. | high |
| `cordon-node` | kubectl cordon marks a node unschedulable. Existing pods continue running. | medium |
| `taint-noexecute` | kubectl taint with NoExecute evicts existing pods that don't tolerate the taint. | high |
| `delete-workload` | kubectl delete deployment/statefulset/daemonset removes the workload. Use --dry-run first. | high |
| `delete-pvc` | kubectl delete pvc may permanently delete data if ReclaimPolicy is Delete. | critical |
| `delete-pv` | kubectl delete pv may permanently delete the underlying storage. | critical |
| `api-delete-namespace` | DELETE to /api/v1/namespaces/<name> removes the namespace and ALL resources in it. | critical |
| `api-delete-collection` | DELETE to a collection path removes every resource of that type in the namespace. | high |
| `api-delete-workload` | DELETE to a workload path removes the controller and the pods it manages. | high |
| `api-delete-persistent-storage` | DELETE to a PVC or PV path can permanently destroy the underlying storage. | critical |
| `scale-to-zero` | kubectl scale --replicas=0 stops all pods for the workload. | high |
| `delete-force` | kubectl delete --force --grace-period=0 immediately removes resources without graceful shutdown. | critical |
| `apply-force` | kubectl apply --force deletes and recreates resources, causing downtime. | high |
| `delete-from-stdin` | kubectl delete -f - deletes every resource described by stdin without a reviewable manifest path. | high |
| `delete-from-directory` | kubectl delete -f with directories or --recursive deletes many resources at once. | high |
| `apply-prune` | kubectl apply --prune deletes live resources that are missing from the applied manifests. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "kubernetes.kubectl:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "kubernetes.kubectl:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Helm

**Pack ID:** `kubernetes.helm`

Protects against destructive Helm operations like uninstall and rollback without dry-run

### Keywords

Commands containing these keywords are checked against this pack:

- `helm`
- `uninstall`
- `delete`
- `rollback`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `helm-list` | `^[ \t]*(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+/)?helm[ \t]+(?:(?:--(?:burst-limit\|kube-apiserver\|kube-as-group\|kube-as-user\|kube-ca-file\|kube-context\|kube-tls-server-name\|kube-token\|kubeconfig\|namespace\|qps\|registry-config\|repository-cache\|repository-config)(?:=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|-n(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|--(?:debug\|kube-insecure-skip-tls-verify)(?:=(?:true\|false))?)[ \t]+)*list(?=\s\|$)` |
| `helm-status` | `^[ \t]*(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+/)?helm[ \t]+(?:(?:--(?:burst-limit\|kube-apiserver\|kube-as-group\|kube-as-user\|kube-ca-file\|kube-context\|kube-tls-server-name\|kube-token\|kubeconfig\|namespace\|qps\|registry-config\|repository-cache\|repository-config)(?:=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|-n(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|--(?:debug\|kube-insecure-skip-tls-verify)(?:=(?:true\|false))?)[ \t]+)*status(?=\s\|$)` |
| `helm-history` | `^[ \t]*(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+/)?helm[ \t]+(?:(?:--(?:burst-limit\|kube-apiserver\|kube-as-group\|kube-as-user\|kube-ca-file\|kube-context\|kube-tls-server-name\|kube-token\|kubeconfig\|namespace\|qps\|registry-config\|repository-cache\|repository-config)(?:=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|-n(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|--(?:debug\|kube-insecure-skip-tls-verify)(?:=(?:true\|false))?)[ \t]+)*history(?=\s\|$)` |
| `helm-show` | `^[ \t]*(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+/)?helm[ \t]+(?:(?:--(?:burst-limit\|kube-apiserver\|kube-as-group\|kube-as-user\|kube-ca-file\|kube-context\|kube-tls-server-name\|kube-token\|kubeconfig\|namespace\|qps\|registry-config\|repository-cache\|repository-config)(?:=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|-n(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|--(?:debug\|kube-insecure-skip-tls-verify)(?:=(?:true\|false))?)[ \t]+)*show(?=\s\|$)` |
| `helm-inspect` | `^[ \t]*(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+/)?helm[ \t]+(?:(?:--(?:burst-limit\|kube-apiserver\|kube-as-group\|kube-as-user\|kube-ca-file\|kube-context\|kube-tls-server-name\|kube-token\|kubeconfig\|namespace\|qps\|registry-config\|repository-cache\|repository-config)(?:=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|-n(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|--(?:debug\|kube-insecure-skip-tls-verify)(?:=(?:true\|false))?)[ \t]+)*inspect(?=\s\|$)` |
| `helm-get` | `^[ \t]*(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+/)?helm[ \t]+(?:(?:--(?:burst-limit\|kube-apiserver\|kube-as-group\|kube-as-user\|kube-ca-file\|kube-context\|kube-tls-server-name\|kube-token\|kubeconfig\|namespace\|qps\|registry-config\|repository-cache\|repository-config)(?:=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|-n(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|--(?:debug\|kube-insecure-skip-tls-verify)(?:=(?:true\|false))?)[ \t]+)*get(?=\s\|$)` |
| `helm-search` | `^[ \t]*(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+/)?helm[ \t]+(?:(?:--(?:burst-limit\|kube-apiserver\|kube-as-group\|kube-as-user\|kube-ca-file\|kube-context\|kube-tls-server-name\|kube-token\|kubeconfig\|namespace\|qps\|registry-config\|repository-cache\|repository-config)(?:=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|-n(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|--(?:debug\|kube-insecure-skip-tls-verify)(?:=(?:true\|false))?)[ \t]+)*search(?=\s\|$)` |
| `helm-repo` | `^[ \t]*(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+/)?helm[ \t]+(?:(?:--(?:burst-limit\|kube-apiserver\|kube-as-group\|kube-as-user\|kube-ca-file\|kube-context\|kube-tls-server-name\|kube-token\|kubeconfig\|namespace\|qps\|registry-config\|repository-cache\|repository-config)(?:=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|-n(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|--(?:debug\|kube-insecure-skip-tls-verify)(?:=(?:true\|false))?)[ \t]+)*repo(?=\s\|$)` |
| `helm-dry-run` | `^[ \t]*(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+/)?helm[ \t]+(?:(?:--(?:burst-limit\|kube-apiserver\|kube-as-group\|kube-as-user\|kube-ca-file\|kube-context\|kube-tls-server-name\|kube-token\|kubeconfig\|namespace\|qps\|registry-config\|repository-cache\|repository-config)(?:=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|-n(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|--(?:debug\|kube-insecure-skip-tls-verify)(?:=(?:true\|false))?)[ \t]+)*(?:uninstall\|delete\|rollback\|upgrade)(?:[ \t]+(?:(?:--(?:burst-limit\|kube-apiserver\|kube-as-group\|kube-as-user\|kube-ca-file\|kube-context\|kube-tls-server-name\|kube-token\|kubeconfig\|namespace\|qps\|registry-config\|repository-cache\|repository-config)(?:=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|-n(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|--(?:debug\|kube-insecure-skip-tls-verify)(?:=(?:true\|false))?)\|--(?:description\|cascade\|timeout\|history-max\|output\|version\|repo\|username\|password\|ca-file\|cert-file\|key-file\|keyring\|post-renderer\|post-renderer-args\|values\|set\|set-file\|set-json\|set-literal\|set-string\|labels)(?:=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|-[fo](?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|--(?:no-hooks\|ignore-not-found\|keep-history\|force\|force-replace\|force-conflicts\|reset-values\|reuse-values\|reset-then-reuse-values\|install\|atomic\|cleanup-on-fail\|disable-openapi-validation\|skip-schema-validation\|skip-crds\|create-namespace\|verify\|wait\|wait-for-jobs\|devel\|dependency-update\|enable-dns\|hide-notes\|hide-secret\|insecure-skip-tls-verify\|plain-http\|render-subchart-notes\|take-ownership)(?:=(?:true\|false\|watcher\|hookOnly\|legacy))?\|-i\|[^\s;&\|<>()\x22'\\$`*?\[\]{}~-][^\s;&\|<>()\x22'\\$`*?\[\]{}~]*\|-))*[ \t]+--dry-run(?:=(?:true\|client\|server))?(?:[ \t]+(?:(?:(?:--(?:burst-limit\|kube-apiserver\|kube-as-group\|kube-as-user\|kube-ca-file\|kube-context\|kube-tls-server-name\|kube-token\|kubeconfig\|namespace\|qps\|registry-config\|repository-cache\|repository-config)(?:=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|-n(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|--(?:debug\|kube-insecure-skip-tls-verify)(?:=(?:true\|false))?)\|--(?:description\|cascade\|timeout\|history-max\|output\|version\|repo\|username\|password\|ca-file\|cert-file\|key-file\|keyring\|post-renderer\|post-renderer-args\|values\|set\|set-file\|set-json\|set-literal\|set-string\|labels)(?:=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|-[fo](?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|--(?:no-hooks\|ignore-not-found\|keep-history\|force\|force-replace\|force-conflicts\|reset-values\|reuse-values\|reset-then-reuse-values\|install\|atomic\|cleanup-on-fail\|disable-openapi-validation\|skip-schema-validation\|skip-crds\|create-namespace\|verify\|wait\|wait-for-jobs\|devel\|dependency-update\|enable-dns\|hide-notes\|hide-secret\|insecure-skip-tls-verify\|plain-http\|render-subchart-notes\|take-ownership)(?:=(?:true\|false\|watcher\|hookOnly\|legacy))?\|-i\|[^\s;&\|<>()\x22'\\$`*?\[\]{}~-][^\s;&\|<>()\x22'\\$`*?\[\]{}~]*\|-)\|--dry-run(?:=(?:true\|client\|server))?))*[ \t]*$` |
| `helm-template` | `^[ \t]*(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+/)?helm[ \t]+(?:(?:--(?:burst-limit\|kube-apiserver\|kube-as-group\|kube-as-user\|kube-ca-file\|kube-context\|kube-tls-server-name\|kube-token\|kubeconfig\|namespace\|qps\|registry-config\|repository-cache\|repository-config)(?:=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|-n(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|--(?:debug\|kube-insecure-skip-tls-verify)(?:=(?:true\|false))?)[ \t]+)*template(?=\s\|$)` |
| `helm-lint` | `^[ \t]*(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+/)?helm[ \t]+(?:(?:--(?:burst-limit\|kube-apiserver\|kube-as-group\|kube-as-user\|kube-ca-file\|kube-context\|kube-tls-server-name\|kube-token\|kubeconfig\|namespace\|qps\|registry-config\|repository-cache\|repository-config)(?:=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|-n(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|--(?:debug\|kube-insecure-skip-tls-verify)(?:=(?:true\|false))?)[ \t]+)*lint(?=\s\|$)` |
| `helm-diff` | `^[ \t]*(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+/)?helm[ \t]+(?:(?:--(?:burst-limit\|kube-apiserver\|kube-as-group\|kube-as-user\|kube-ca-file\|kube-context\|kube-tls-server-name\|kube-token\|kubeconfig\|namespace\|qps\|registry-config\|repository-cache\|repository-config)(?:=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|-n(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|--(?:debug\|kube-insecure-skip-tls-verify)(?:=(?:true\|false))?)[ \t]+)*diff(?=\s\|$)` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `uninstall` | helm uninstall removes the release and all its resources. Use --dry-run first. | critical |
| `rollback` | helm rollback reverts to a previous release. Use --dry-run to preview changes. | high |
| `upgrade-force` | helm upgrade --force deletes and recreates resources, causing downtime. | high |
| `upgrade-reset-values` | helm upgrade --reset-values discards all previously set values. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "kubernetes.helm:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "kubernetes.helm:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Kustomize

**Pack ID:** `kubernetes.kustomize`

Protects against destructive Kustomize operations when combined with kubectl delete or applied without review

### Keywords

Commands containing these keywords are checked against this pack:

- `kustomize`
- `kubectl`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `kustomize-dry-run` | `^[ \t]*(?:(?:(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+/)?kustomize[ \t]+build\|(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+/)?kubectl[ \t]+kustomize)(?:[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)*[ \t]*\\|[ \t]*)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+/)?kubectl[ \t]+(?:(?:--(?:as\|as-group\|as-uid\|as-user-extra\|cache-dir\|certificate-authority\|client-certificate\|client-key\|cluster\|context\|kubeconfig\|kuberc\|namespace\|password\|profile\|profile-output\|proxy-url\|request-timeout\|server\|tls-server-name\|token\|user\|username\|v\|vmodule)(?:=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|-[nsv](?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|--(?:disable-compression\|insecure-skip-tls-verify\|match-server-version\|warnings-as-errors\|help)(?:=(?:true\|false))?\|-h)[ \t]+)*delete(?:[ \t]+(?:(?:--(?:as\|as-group\|as-uid\|as-user-extra\|cache-dir\|certificate-authority\|client-certificate\|client-key\|cluster\|context\|kubeconfig\|kuberc\|namespace\|password\|profile\|profile-output\|proxy-url\|request-timeout\|server\|tls-server-name\|token\|user\|username\|v\|vmodule)(?:=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|-[nsv](?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|--(?:disable-compression\|insecure-skip-tls-verify\|match-server-version\|warnings-as-errors\|help)(?:=(?:true\|false))?\|-h)\|--(?:filename\|kustomize\|selector\|field-selector\|grace-period\|timeout\|output)(?:=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|-[fklo](?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|--(?:all\|all-namespaces\|force\|ignore-not-found\|now\|wait\|interactive\|recursive)(?:=(?:true\|false))?\|--cascade(?:=(?:background\|foreground\|orphan\|true\|false))?\|-[ARi]\|[^\s;&\|<>()\x22'\\$`*?\[\]{}~-][^\s;&\|<>()\x22'\\$`*?\[\]{}~]*\|-))*[ \t]+--dry-run(?:=(?:client\|server))?(?:[ \t]+(?:(?:(?:--(?:as\|as-group\|as-uid\|as-user-extra\|cache-dir\|certificate-authority\|client-certificate\|client-key\|cluster\|context\|kubeconfig\|kuberc\|namespace\|password\|profile\|profile-output\|proxy-url\|request-timeout\|server\|tls-server-name\|token\|user\|username\|v\|vmodule)(?:=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|-[nsv](?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|--(?:disable-compression\|insecure-skip-tls-verify\|match-server-version\|warnings-as-errors\|help)(?:=(?:true\|false))?\|-h)\|--(?:filename\|kustomize\|selector\|field-selector\|grace-period\|timeout\|output)(?:=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|-[fklo](?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+\|[ \t]+[^\s;&\|<>()\x22'\\$`*?\[\]{}~]+)\|--(?:all\|all-namespaces\|force\|ignore-not-found\|now\|wait\|interactive\|recursive)(?:=(?:true\|false))?\|--cascade(?:=(?:background\|foreground\|orphan\|true\|false))?\|-[ARi]\|[^\s;&\|<>()\x22'\\$`*?\[\]{}~-][^\s;&\|<>()\x22'\\$`*?\[\]{}~]*\|-)\|--dry-run(?:=(?:client\|server))?))*[ \t]*$` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `kustomize-delete` | kustomize build \| kubectl delete removes all resources in the kustomization. | critical |
| `kubectl-kustomize-delete` | kubectl kustomize \| kubectl delete removes all resources in the kustomization. | critical |
| `kubectl-delete-k` | kubectl delete -k removes all resources defined in the kustomization. Use --dry-run first. | critical |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "kubernetes.kustomize:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "kubernetes.kustomize:*"
reason = "Your reason here"
risk_acknowledged = true
```

---
