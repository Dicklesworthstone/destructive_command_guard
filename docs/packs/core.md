# Core Packs

This document describes packs in the `core` category.

## Packs in this Category

- [Core Git](#coregit)
- [Core Filesystem](#corefilesystem)

---

## Core Git

**Pack ID:** `core.git`

Protects against destructive git commands that can lose uncommitted work, rewrite history, or destroy stashes

### Keywords

Commands containing these keywords are checked against this pack:

- `git`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `checkout-new-branch` | `(?:^\|[^[:alnum:]_-])git\s+(?:\S+\s+)*checkout\s+-b\s+` |
| `checkout-orphan` | `(?:^\|[^[:alnum:]_-])git\s+(?:\S+\s+)*checkout\s+--orphan\s+` |
| `restore-staged-long` | `(?:^\|[^[:alnum:]_-])git\s+(?:\S+\s+)*restore\b(?=\s)(?=.*\s--staged\b)(?!.*\s(?:--worktree\|-W)\b)` |
| `restore-staged-short` | `(?:^\|[^[:alnum:]_-])git\s+(?:\S+\s+)*restore\b(?=\s)(?=.*\s-S\b)(?!.*\s(?:--worktree\|-W)\b)` |
| `clean-dry-run-short` | `(?:^\|[^[:alnum:]_-])git\s+(?:\S+\s+)*clean\s+-[a-z]*n[a-z]*` |
| `clean-dry-run-long` | `(?:^\|[^[:alnum:]_-])git\s+(?:\S+\s+)*clean\s+--dry-run` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `git-alias-semantic-unverified` | The invoked Git alias depends on shell expansion, contains a cycle, or exceeds dcg's bounded semantic analysis. | high |
| `branch-dynamic-token` | A dynamic shell expansion in this git branch command can expand into a deletion or forced ref update. Quote the branch name or add `--` to make it a literal creation. | high |
| `checkout-discard` | git checkout -- discards uncommitted changes permanently. Use 'git stash' first. | high |
| `checkout-ref-discard` | git checkout <ref> -- <path> overwrites working tree. Use 'git stash' first. | high |
| `restore-worktree` | git restore discards uncommitted changes. Use 'git stash' or 'git diff' first. | high |
| `restore-worktree-explicit` | git restore --worktree/-W discards uncommitted changes permanently. | high |
| `reset-hard` | git reset --hard destroys uncommitted changes. Use 'git stash' first. | critical |
| `reset-merge` | git reset --merge can lose uncommitted changes. | high |
| `clean-force` | git clean -f/--force removes untracked files permanently. Review with 'git clean -n' first. | critical |
| `push-force-long` | Force push can destroy remote history. Use --force-with-lease if necessary. | critical |
| `push-force-short` | Force push (-f) can destroy remote history. Use --force-with-lease if necessary. | critical |
| `branch-force-delete` | git branch deletion or forced ref updates require explicit user approval. | high |
| `stash-drop` | git stash drop deletes a single stash. Recoverable via `git fsck` (unreachable objects). | medium |
| `stash-clear` | git stash clear permanently deletes ALL stashed changes. | critical |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "core.git:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "core.git:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Core Filesystem

**Pack ID:** `core.filesystem`

Protects against recursive rm commands and equivalent filesystem destruction outside literal temp subdirectories

### Keywords

Commands containing these keywords are checked against this pack:

- `rm`
- `find`
- `unlink`
- `truncate`
- `shred`
- `tar`
- `dd`
- `mv`
- `cp`
- `ln`
- `rsync`
- `>/`
- `> /`
- `>~`
- `> ~`
- `>$`
- `> $`
- `>"`
- `> "`
- `>'`
- `> '`
- `&>`
- `>&`
- `>|`
- `1>`
- `2>`
- `>%`
- `> %`
- `>!`
- `> !`
- `>^`
- `> ^`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `rm-force-dev-browser-tmp-glob` | `^rm\s+(?:-f\|--force)\s+~/\.dev-browser/tmp/[^/\s]*[*?\[][^/\s]*\s*$` |
| `rm-rf-tmp` | `^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:(?:/private)?/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S*(?:\s+\|$))+$` |
| `rm-fr-tmp` | `^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:(?:/private)?/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S*(?:\s+\|$))+$` |
| `rm-rf-var-tmp` | `^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:(?:/private)?/var/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S*(?:\s+\|$))+$` |
| `rm-fr-var-tmp` | `^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:(?:/private)?/var/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S*(?:\s+\|$))+$` |
| `rm-r-f-tmp` | `^rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?:(?:/private)?/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S*(?:\s+\|$))+$` |
| `rm-f-r-tmp` | `^rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?:(?:/private)?/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S*(?:\s+\|$))+$` |
| `rm-r-f-var-tmp` | `^rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?:(?:/private)?/var/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S*(?:\s+\|$))+$` |
| `rm-f-r-var-tmp` | `^rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?:(?:/private)?/var/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S*(?:\s+\|$))+$` |
| `rm-recursive-force-tmp` | `^rm\s+.*--recursive.*--force\s+(?:(?:/private)?/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S*(?:\s+\|$))+$` |
| `rm-force-recursive-tmp` | `^rm\s+.*--force.*--recursive\s+(?:(?:/private)?/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S*(?:\s+\|$))+$` |
| `rm-recursive-force-var-tmp` | `^rm\s+.*--recursive.*--force\s+(?:(?:/private)?/var/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S*(?:\s+\|$))+$` |
| `rm-force-recursive-var-tmp` | `^rm\s+.*--force.*--recursive\s+(?:(?:/private)?/var/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S*(?:\s+\|$))+$` |
| `find-delete-tmp` | `^(?![^\|;&]*[\\$`])find\s+/tmp(?:/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S*)?(?:\s+(?:/tmp(?:/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S*)?\|-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^\|;&\s]*)?))*\s+-delete(?:\s+-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^\|;&\s]*)?)*\s*$` |
| `find-delete-var-tmp` | `^(?![^\|;&]*[\\$`])find\s+/var/tmp(?:/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S*)?(?:\s+(?:/var/tmp(?:/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S*)?\|-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^\|;&\s]*)?))*\s+-delete(?:\s+-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^\|;&\s]*)?)*\s*$` |
| `unlink-tmp` | `^(?![^\|;&]*[\\$`])unlink\s+(?:/private)?/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S+\s*$` |
| `unlink-var-tmp` | `^(?![^\|;&]*[\\$`])unlink\s+(?:/private)?/var/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S+\s*$` |
| `unlink-help` | `^unlink\s+(?:--help\|--version)\s*$` |
| `truncate-help` | `^truncate\s+(?:--help\|--version)\s*$` |
| `truncate-grow` | `^truncate\s+(?:-s\s+\+\S+\|--size=\+\S+)\s+\S+\s*$` |
| `truncate-tmp` | `^(?![^\|;&]*[\\$`])truncate\s+(?:-s\s+\S+\|--size=\S+)\s+(?:/private)?/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S+\s*$` |
| `truncate-var-tmp` | `^(?![^\|;&]*[\\$`])truncate\s+(?:-s\s+\S+\|--size=\S+)\s+(?:/private)?/var/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S+\s*$` |
| `shred-help` | `^shred\s+(?:--help\|--version)\s*$` |
| `shred-tmp` | `^(?![^\|;&]*[\\$`])shred(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s\|;&]*)?\|--[a-z\-]+(?:=\S+\|\s+[^/~$\-\s][^\s\|;&]*)?))*\s+(?:/private)?/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s\|;&]*)?\|--[a-z\-]+(?:=\S+\|\s+[^/~$\-\s][^\s\|;&]*)?))*\s*$` |
| `shred-var-tmp` | `^(?![^\|;&]*[\\$`])shred(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s\|;&]*)?\|--[a-z\-]+(?:=\S+\|\s+[^/~$\-\s][^\s\|;&]*)?))*\s+(?:/private)?/var/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s\|;&]*)?\|--[a-z\-]+(?:=\S+\|\s+[^/~$\-\s][^\s\|;&]*)?))*\s*$` |
| `tar-remove-files-tmp` | `^(?![^\|;&]*[\\$`])tar(?=\s+[^\|;&]*--remove-files\b)(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s\|;&]*)?\|--[a-z\-]+(?:=\S+\|\s+[^/~$\-\s][^\s\|;&]*)?))*\s+(?:/private)?/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s\|;&]*)?\|--[a-z\-]+(?:=\S+\|\s+[^/~$\-\s][^\s\|;&]*)?))*\s*$` |
| `tar-remove-files-var-tmp` | `^(?![^\|;&]*[\\$`])tar(?=\s+[^\|;&]*--remove-files\b)(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s\|;&]*)?\|--[a-z\-]+(?:=\S+\|\s+[^/~$\-\s][^\s\|;&]*)?))*\s+(?:/private)?/var/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s\|;&]*)?\|--[a-z\-]+(?:=\S+\|\s+[^/~$\-\s][^\s\|;&]*)?))*\s*$` |
| `dd-tmp` | `^(?![^\|;&]*[\\$`])dd(?=\s+[^\|;&]*\bof=)(?:\s+(?:[a-zA-Z]+=\S+\|--?[a-zA-Z][a-zA-Z0-9\-]*(?:=\S+)?))*\s+of=['"]?(?:/private)?/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S+(?:\s+(?:(?!of=)[a-zA-Z]+=\S+\|--?[a-zA-Z][a-zA-Z0-9\-]*(?:=\S+)?))*\s*$` |
| `dd-var-tmp` | `^(?![^\|;&]*[\\$`])dd(?=\s+[^\|;&]*\bof=)(?:\s+(?:[a-zA-Z]+=\S+\|--?[a-zA-Z][a-zA-Z0-9\-]*(?:=\S+)?))*\s+of=['"]?(?:/private)?/var/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S+(?:\s+(?:(?!of=)[a-zA-Z]+=\S+\|--?[a-zA-Z][a-zA-Z0-9\-]*(?:=\S+)?))*\s*$` |
| `dd-help` | `^dd\s+(?:--help\|--version)\s*$` |
| `mv-tmp` | `^(?![^\|;&]*[\\$`])mv(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s\|;&]*)?\|--[a-z\-]+(?:=\S+\|\s+[^/~$\-\s][^\s\|;&]*)?))*\s+(?:(?:/private)?/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S+\s+)+(?:/private)?/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S+\s*$` |
| `mv-var-tmp` | `^(?![^\|;&]*[\\$`])mv(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s\|;&]*)?\|--[a-z\-]+(?:=\S+\|\s+[^/~$\-\s][^\s\|;&]*)?))*\s+(?:(?:/private)?/var/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S+\s+)+(?:/private)?/var/tmp/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))\S+\s*$` |
| `mv-help` | `^mv\s+(?:--help\|--version)\s*$` |
| `mv-to-trash` | `^(?![^\|;&]*[\\$`])mv(?:[ \t]+--?[a-zA-Z][a-zA-Z0-9-]*)*(?:[ \t]+(?:~/\|/home/[^/\s]+/\|/Users/[^/\s]+/\|(?:/private)?(?:/var)?/tmp/\|\./)?(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))[A-Za-z0-9._][^\s;\|&]*)+[ \t]+(?:~/\.local/share/Trash\|~/\.Trash)(?:/(?!\.\.(?:/\|\s\|$)\|[^\s]*/\.\.(?:/\|\s\|$))[^\s;\|&]*)?\s*$` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `sed-exec-unverified` | GNU sed executes shell input that dcg cannot statically verify. | high |
| `cp-sensitive-then-delete` | archive copy of a sensitive path into temp followed by forced recursive deletion is a cross-segment data-loss bypass. EXTREMELY DANGEROUS. | critical |
| `ln-symlink-sensitive-then-delete` | symlink from a sensitive path into temp followed by forced recursive deletion can traverse and destroy the target. EXTREMELY DANGEROUS. | critical |
| `rsync-sensitive-then-delete` | rsync archive of a sensitive path into temp followed by forced recursive deletion is a cross-segment data-loss bypass. EXTREMELY DANGEROUS. | critical |
| `rm-rf-root-home` | rm -rf on root or home paths is EXTREMELY DANGEROUS. This command will NOT be executed. Ask the user to run it manually if truly needed. | critical |
| `rm-r-f-separate-root-home` | rm with separate -r -f flags targeting root or home is EXTREMELY DANGEROUS. | critical |
| `rm-recursive-force-root-home` | rm --recursive --force targeting root or home is EXTREMELY DANGEROUS. | critical |
| `rm-rf-general` | rm -rf is destructive and requires human approval. Explain what you want to delete and why, then ask the user to run the command manually. | high |
| `rm-glob-home` | rm with an unexpanded glob under a home directory deletes an unbounded, shell-chosen file set and requires human approval. | high |
| `rm-r-f-separate` | rm with separate -r -f flags is destructive and requires human approval. | high |
| `rm-recursive-force-long` | rm --recursive --force is destructive and requires human approval. | high |
| `find-delete-root-home` | find <sensitive-path> -delete is bytewise-equivalent to rm -rf on root/home and is EXTREMELY DANGEROUS. This command will NOT be executed. | critical |
| `find-delete-general` | find ... -delete is destructive (bytewise-equivalent to rm -rf on the matched tree) and requires human approval. | high |
| `unlink-root-home` | unlink on a sensitive system or home path is one-shot data destruction with no recovery. EXTREMELY DANGEROUS. | critical |
| `unlink-general` | unlink is destructive (POSIX equivalent of rm on a single file) and requires human approval. | high |
| `truncate-zero-root-home` | truncate with a potentially shrinking size on a sensitive system or home path destroys data. EXTREMELY DANGEROUS. | critical |
| `truncate-zero-general` | truncate with an absolute or shrinking size can destroy file content and requires human approval. | high |
| `shred-root-home` | shred on a sensitive system or home path destroys data beyond forensic recovery. EXTREMELY DANGEROUS. | critical |
| `shred-general` | shred destroys file content beyond recovery and requires human approval. | high |
| `tar-remove-files-root-home` | tar --remove-files on a sensitive system or home path is recursive deletion masquerading as an archive operation. EXTREMELY DANGEROUS. | critical |
| `tar-remove-files-general` | tar --remove-files deletes source paths after archiving and requires human approval. | high |
| `dd-overwrite-root-home` | dd of=<sensitive-path> overwrites file contents in place. EXTREMELY DANGEROUS on a system or home file. | critical |
| `dd-overwrite-general` | dd with of=<file> overwrites file contents and requires human approval. | high |
| `mv-sensitive-source-root-home` | mv touching a sensitive system or home path is the cross-segment recursive-force-delete bypass. EXTREMELY DANGEROUS. | critical |
| `mv-dynamic-path` | mv with a shell-expanded or escaped path cannot be verified before execution. | high |
| `redirect-truncate-root-home` | shell truncating redirect (including arbitrary numeric, named, and PowerShell all-stream forms) to a sensitive system or home path destroys the previous file contents. EXTREMELY DANGEROUS. | critical |
| `redirect-truncate-dynamic-path` | shell redirect to a dynamic or escaped path may truncate a sensitive file and requires human approval. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "core.filesystem:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "core.filesystem:*"
reason = "Your reason here"
risk_acknowledged = true
```

---
