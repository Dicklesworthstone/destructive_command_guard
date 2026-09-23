# Strict Git Packs

This document describes packs in the `strict_git` category.

## Packs in this Category

- [Strict Git](#strict_git)

---

## Strict Git

**Pack ID:** `strict_git`

Stricter git protections: blocks force pushes, rebases, history rewriting, blind staging, and direct pushes to default branches

### Keywords

Commands containing these keywords are checked against this pack:

- `git`

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `push-force-any` | Force push (even with --force-with-lease) can rewrite remote history. Disabled in strict mode. | high |
| `push-mirror` | git push --mirror force-updates and deletes remote refs. Disabled in strict mode. | high |
| `push-delete` | git push --delete removes refs from the remote. Disabled in strict mode. | high |
| `push-delete-refspec` | git push <remote> :<ref> (empty source) deletes the ref from the remote. Disabled in strict mode. | high |
| `push-prune` | git push --prune deletes remote refs that have no local counterpart. Disabled in strict mode. | high |
| `push-dynamic-argument` | Force push risk: a shell-expanded or escaped git push argument cannot be verified as non-forcing. Use literal remote and refspec arguments in strict mode. | high |
| `rebase` | git rebase rewrites commit history. Disabled in strict mode. | high |
| `commit-amend` | git commit --amend rewrites the last commit. Disabled in strict mode. | high |
| `cherry-pick` | git cherry-pick can introduce duplicate commits. Review carefully. | high |
| `filter-branch` | git filter-branch rewrites entire repository history. Extremely dangerous! | high |
| `filter-repo` | git filter-repo rewrites repository history. Review carefully. | high |
| `reflog-expire` | git reflog expire removes reflog entries needed for recovery. | high |
| `gc-aggressive` | git gc with aggressive/prune options can remove recoverable objects. | high |
| `worktree-remove` | git worktree remove deletes a linked working tree. | high |
| `submodule-deinit` | git submodule deinit removes submodule configuration. | high |
| `add-all-dot` | git add . stages everything including secrets, .env files, and build artifacts. Use 'git add <specific-files>' instead. | high |
| `add-all-flag` | git add -A/--all stages all changes including secrets, .env files, and build artifacts. Use 'git add <specific-files>' instead. | high |
| `push-master` | Direct push to master is blocked. Use a feature branch and open a Pull Request. | high |
| `push-main` | Direct push to main is blocked. Use a feature branch and open a Pull Request. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "strict_git:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "strict_git:*"
reason = "Your reason here"
risk_acknowledged = true
```

---
