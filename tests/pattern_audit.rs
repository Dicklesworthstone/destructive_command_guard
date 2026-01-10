use destructive_command_guard::packs::PackRegistry;
use destructive_command_guard::packs::regex_engine::needs_backtracking_engine;
use std::collections::{HashMap, HashSet};

#[test]
#[allow(clippy::too_many_lines)]
fn test_audit_backtracking_requirements() {
    // Map of PackID -> Set of Pattern Names that require backtracking.
    // Based on docs/pattern_audit.md
    let expected_backtracking: HashMap<&str, HashSet<&str>> = HashMap::from([
        (
            "core.filesystem",
            HashSet::from([
                "rm-rf-tmp",
                "rm-fr-tmp",
                "rm-rf-var-tmp",
                "rm-fr-var-tmp",
                "rm-rf-tmpdir",
                "rm-fr-tmpdir",
                "rm-rf-tmpdir-brace",
                "rm-fr-tmpdir-brace",
                "rm-rf-tmpdir-quoted",
                "rm-fr-tmpdir-quoted",
                "rm-rf-tmpdir-brace-quoted",
                "rm-fr-tmpdir-brace-quoted",
                "rm-r-f-tmp",
                "rm-f-r-tmp",
                "rm-r-f-var-tmp",
                "rm-f-r-var-tmp",
                "rm-r-f-tmpdir",
                "rm-f-r-tmpdir",
                "rm-r-f-tmpdir-brace",
                "rm-f-r-tmpdir-brace",
                "rm-recursive-force-tmp",
                "rm-force-recursive-tmp",
                "rm-recursive-force-var-tmp",
                "rm-force-recursive-var-tmp",
                "rm-recursive-force-tmpdir",
                "rm-force-recursive-tmpdir",
                "rm-recursive-force-tmpdir-brace",
                "rm-force-recursive-tmpdir-brace",
            ]),
        ),
        (
            "core.git",
            HashSet::from([
                "restore-staged-long",
                "restore-staged-short",
                "checkout-ref-discard",
                "restore-worktree",
                "push-force-long",
            ]),
        ),
        (
            "cicd.github_actions",
            HashSet::from([
                "gh-actions-secret-list",
                "gh-actions-variable-list",
                "gh-actions-workflow-list",
                "gh-actions-workflow-view",
                "gh-actions-run-list",
                "gh-actions-run-view",
                "gh-actions-api-explicit-get",
                "gh-actions-secret-remove",
                "gh-actions-variable-remove",
                "gh-actions-workflow-disable",
                "gh-actions-run-cancel",
                "gh-actions-api-delete-secrets",
                "gh-actions-api-delete-variables",
            ]),
        ),
        (
            "containers.compose",
            HashSet::from(["compose-down-no-volumes"]),
        ),
        ("database.mongodb", HashSet::from(["mongodump-no-drop"])),
        ("database.postgresql", HashSet::from(["pg-dump-no-clean"])),
        ("database.redis", HashSet::from(["shutdown"])),
        (
            "infrastructure.ansible",
            HashSet::from(["playbook-all-hosts"]),
        ),
        (
            "infrastructure.terraform",
            HashSet::from(["terraform-plan"]),
        ),
        ("kubernetes.helm", HashSet::from(["uninstall", "rollback"])),
        (
            "kubernetes.kubectl",
            HashSet::from(["delete-workload", "delete-pvc", "delete-pv"]),
        ),
        (
            "kubernetes.kustomize",
            HashSet::from(["kustomize-build", "kubectl-kustomize", "kubectl-delete-k"]),
        ),
        (
            "package_managers",
            HashSet::from([
                "apt-get-list",
                "npm-publish",
                "yarn-publish",
                "pnpm-publish",
                "cargo-publish",
                "poetry-publish",
            ]),
        ),
        (
            "platform.github",
            HashSet::from([
                // Safe patterns
                "gh-repo-list-view",
                "gh-gist-list-view",
                "gh-release-list-view",
                "gh-issue-list-view",
                "gh-ssh-key-list",
                "gh-api-explicit-get",
                // Destructive patterns
                "gh-repo-delete",
                "gh-repo-archive",
                "gh-gist-delete",
                "gh-release-delete",
                "gh-issue-delete",
                "gh-ssh-key-delete",
                "gh-api-delete-repo",
            ]),
        ),
        (
            "system.disk",
            HashSet::from(["fdisk-edit", "parted-modify"]),
        ),
        ("system.permissions", HashSet::from(["chmod-non-recursive"])),
    ]);

    let registry = PackRegistry::new();
    let all_ids: HashSet<String> = registry
        .all_pack_ids()
        .into_iter()
        .map(String::from)
        .collect();
    let pack_infos = registry.list_packs(&all_ids);

    let mut unexpected = Vec::new();
    let empty_set = HashSet::new();

    for info in pack_infos {
        let pack = registry.get(&info.id).unwrap();
        let pack_expected = expected_backtracking
            .get(pack.id.as_str())
            .unwrap_or(&empty_set);

        // Check safe patterns
        for p in &pack.safe_patterns {
            let pattern_str = p.regex.as_str();
            if needs_backtracking_engine(pattern_str) {
                if !pack_expected.contains(p.name) {
                    unexpected.push(format!(
                        "Unexpected backtracking in SafePattern: {}/{} ({})",
                        pack.id, p.name, pattern_str
                    ));
                }
            } else if pack_expected.contains(p.name) {
                unexpected.push(format!(
                    "Expected backtracking in SafePattern but not found: {}/{} ({})",
                    pack.id, p.name, pattern_str
                ));
            }
        }

        // Check destructive patterns
        for p in &pack.destructive_patterns {
            let pattern_str = p.regex.as_str();
            let name = p.name.unwrap_or("UNNAMED");
            if needs_backtracking_engine(pattern_str) {
                if !pack_expected.contains(name) {
                    unexpected.push(format!(
                        "Unexpected backtracking in DestructivePattern: {}/{} ({})",
                        pack.id, name, pattern_str
                    ));
                }
            } else if pack_expected.contains(name) {
                unexpected.push(format!(
                    "Expected backtracking in DestructivePattern but not found: {}/{} ({})",
                    pack.id, name, pattern_str
                ));
            }
        }
    }

    assert!(
        unexpected.is_empty(),
        "Audit mismatch:\n{}",
        unexpected.join("\n")
    );
}
