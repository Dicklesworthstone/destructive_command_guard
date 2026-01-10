//! GitHub Platform pack - protections for destructive GitHub CLI (`gh`) operations.
//!
//! This pack targets high-impact operations when managing GitHub repositories,
//! gists, releases, and other platform resources:
//! - Deleting repositories
//! - Archiving repositories
//! - Deleting gists
//! - Deleting releases
//! - Deleting issues
//! - Deleting SSH keys

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the GitHub Platform pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "platform.github".to_string(),
        name: "GitHub Platform",
        description: "Protects against destructive GitHub CLI operations like deleting repositories, gists, releases, or SSH keys.",
        // Broad on purpose: global `gh` flags can appear before the subcommand.
        keywords: &["gh"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // Regex logic:
    // Match `gh`
    // Match optional global flags: `--flag` or `--flag value`
    // Ensure the flag value isn't one of our target subcommands (repo, gist, etc.)
    // Match the target subcommand and action
    
    // Subcommands to look ahead for: repo|gist|release|issue|ssh-key|api
    
    vec![
        safe_pattern!(
            "gh-repo-list-view",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|api)\b)\S+)?)*\s+repo\s+(?:list|view)\b"
        ),
        safe_pattern!(
            "gh-gist-list-view",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|api)\b)\S+)?)*\s+gist\s+(?:list|view)\b"
        ),
        safe_pattern!(
            "gh-release-list-view",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|api)\b)\S+)?)*\s+release\s+(?:list|view)\b"
        ),
        safe_pattern!(
            "gh-issue-list-view",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|api)\b)\S+)?)*\s+issue\s+(?:list|view)\b"
        ),
        safe_pattern!(
            "gh-ssh-key-list",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|api)\b)\S+)?)*\s+ssh-key\s+list\b"
        ),
        // Safe API GETs
        safe_pattern!(
            "gh-api-explicit-get",
             r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|api)\b)\S+)?)*\s+api\b.*(?:-X|--method)\s+GET\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "gh-repo-delete",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|api)\b)\S+)?)*\s+repo\s+delete\b",
            "gh repo delete permanently deletes a GitHub repository. This cannot be undone."
        ),
        destructive_pattern!(
            "gh-repo-archive",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|api)\b)\S+)?)*\s+repo\s+archive\b",
            "gh repo archive makes a repository read-only. While reversible, it stops all write access."
        ),
        destructive_pattern!(
            "gh-gist-delete",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|api)\b)\S+)?)*\s+gist\s+delete\b",
            "gh gist delete permanently deletes a Gist."
        ),
        destructive_pattern!(
            "gh-release-delete",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|api)\b)\S+)?)*\s+release\s+delete\b",
            "gh release delete permanently deletes a release."
        ),
        destructive_pattern!(
            "gh-issue-delete",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|api)\b)\S+)?)*\s+issue\s+delete\b",
            "gh issue delete permanently deletes an issue."
        ),
        destructive_pattern!(
            "gh-ssh-key-delete",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|api)\b)\S+)?)*\s+ssh-key\s+delete\b",
            "gh ssh-key delete removes an SSH key, potentially breaking access."
        ),
        // API Deletes
        // DELETE /repos/{owner}/{repo} -> Delete a repository
        destructive_pattern!(
            "gh-api-delete-repo",
             r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|api)\b)\S+)?)*\s+api\b.*(?:-X|--method)\s+DELETE\b",
            "gh api DELETE calls can be destructive. Please verify the endpoint."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_safe_variants() {
        let pack = create_pack();
        assert!(pack.check("gh repo list").is_none());
        assert!(pack.check("gh repo view").is_none());
        assert!(pack.check("gh gist list").is_none());
        assert!(pack.check("gh release view v1.0").is_none());
        assert!(pack.check("gh issue list").is_none());
        assert!(pack.check("gh ssh-key list").is_none());
        
        // With global flags
        assert!(pack.check("gh -R owner/repo repo view").is_none());
    }

    #[test]
    fn blocks_destructive_variants() {
        let pack = create_pack();

        let checks = vec![
            ("gh repo delete owner/repo", "gh-repo-delete"),
            ("gh -R owner/repo repo delete", "gh-repo-delete"),
            ("gh repo archive owner/repo", "gh-repo-archive"),
            ("gh gist delete 123", "gh-gist-delete"),
            ("gh release delete v1.0", "gh-release-delete"),
            ("gh issue delete 1", "gh-issue-delete"),
            ("gh ssh-key delete 1", "gh-ssh-key-delete"),
            ("gh api -X DELETE /repos/owner/repo", "gh-api-delete-repo"),
        ];

        for (cmd, expected_rule) in checks {
            let matched = pack.check(cmd).unwrap_or_else(|| panic!("Should block: {}", cmd));
            assert_eq!(matched.name, Some(expected_rule), "Command: {}", cmd);
        }
    }
}
