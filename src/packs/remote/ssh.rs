//! `ssh` pack - protections for destructive SSH operations.
//!
//! Covers destructive CLI operations:
//! - Remote execution of destructive commands via SSH
//! - SSH known hosts removal
//! - SSH key deletion

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `ssh` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "remote.ssh".to_string(),
        name: "ssh",
        description: "Protects against destructive SSH operations like remote command execution and key management.",
        keywords: &["ssh", "ssh-keygen", "ssh-keyscan"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // Version checks
        safe_pattern!("ssh-version", r"ssh\s+-V\b"),
        safe_pattern!("ssh-version-long", r"ssh\s+--version\b"),
        // Key fingerprint listing (read-only)
        safe_pattern!("ssh-keygen-list", r"ssh-keygen\s+.*-l\b"),
        safe_pattern!("ssh-keygen-fingerprint", r"ssh-keygen\s+.*-lf?\b"),
        // Key scanning (read-only)
        safe_pattern!("ssh-keyscan", r"ssh-keyscan\b"),
        // SSH agent operations (typically safe)
        safe_pattern!("ssh-add-list", r"ssh-add\s+-[lL]\b"),
        safe_pattern!("ssh-agent", r"ssh-agent\b"),
        // Help
        safe_pattern!("ssh-help", r"ssh\s+--?h(elp)?\b"),
        safe_pattern!("ssh-keygen-help", r"ssh-keygen\s+--?h(elp)?\b"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Remote execution of destructive commands through SSH
        // Matches: ssh host 'rm -rf ...', ssh user@host "git reset --hard", etc.
        destructive_pattern!(
            "ssh-remote-rm-rf",
            r#"ssh\s+(?:\S+\s+)*(?:-[A-Za-z]+\s+)*\S+[@:]?\S*\s+['"]?.*\brm\s+-[a-zA-Z]*r[a-zA-Z]*f"#,
            "SSH remote execution contains destructive rm -rf command."
        ),
        destructive_pattern!(
            "ssh-remote-git-reset-hard",
            r#"ssh\s+(?:\S+\s+)*(?:-[A-Za-z]+\s+)*\S+[@:]?\S*\s+['"]?.*\bgit\s+reset\s+--hard\b"#,
            "SSH remote execution contains destructive git reset --hard command."
        ),
        destructive_pattern!(
            "ssh-remote-git-clean",
            r#"ssh\s+(?:\S+\s+)*(?:-[A-Za-z]+\s+)*\S+[@:]?\S*\s+['"]?.*\bgit\s+clean\s+-[a-zA-Z]*f"#,
            "SSH remote execution contains destructive git clean -f command."
        ),
        // Known hosts removal
        destructive_pattern!(
            "ssh-keygen-remove-host",
            r"ssh-keygen\s+(?:\S+\s+)*-R\b",
            "ssh-keygen -R removes entries from known_hosts file."
        ),
        // SSH key deletion
        destructive_pattern!(
            "ssh-add-delete-all",
            r"ssh-add\s+-[dD]\b",
            "ssh-add -d/-D removes identities from the SSH agent."
        ),
        // Remote sudo operations (high risk)
        destructive_pattern!(
            "ssh-remote-sudo-rm",
            r#"ssh\s+(?:\S+\s+)*\S+[@:]?\S*\s+['"]?.*\bsudo\s+rm\b"#,
            "SSH remote execution with sudo rm is high-risk."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::*;

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();
        assert_eq!(pack.id, "remote.ssh");
        assert_eq!(pack.name, "ssh");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"ssh"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        // Version checks
        assert_safe_pattern_matches(&pack, "ssh -V");
        assert_safe_pattern_matches(&pack, "ssh --version");
        // Key listing
        assert_safe_pattern_matches(&pack, "ssh-keygen -l");
        assert_safe_pattern_matches(&pack, "ssh-keygen -lf ~/.ssh/id_rsa.pub");
        // Key scanning
        assert_safe_pattern_matches(&pack, "ssh-keyscan github.com");
        // Agent operations
        assert_safe_pattern_matches(&pack, "ssh-add -l");
        assert_safe_pattern_matches(&pack, "ssh-add -L");
        assert_safe_pattern_matches(&pack, "ssh-agent");
        // Help
        assert_safe_pattern_matches(&pack, "ssh --help");
        assert_safe_pattern_matches(&pack, "ssh -h");
        assert_safe_pattern_matches(&pack, "ssh-keygen --help");
        // Interactive session (not matched by destructive patterns)
        assert_allows(&pack, "ssh user@host");
        assert_allows(&pack, "ssh -i key.pem user@host");
        // Safe remote commands
        assert_allows(&pack, "ssh user@host 'ls -la'");
        assert_allows(&pack, "ssh user@host 'cat /etc/hostname'");
    }

    #[test]
    fn blocks_remote_rm_rf() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "ssh user@host 'rm -rf /tmp/data'",
            "ssh-remote-rm-rf",
        );
        assert_blocks_with_pattern(&pack, "ssh host \"rm -rf ./build\"", "ssh-remote-rm-rf");
        assert_blocks_with_pattern(
            &pack,
            "ssh -i key.pem user@host 'rm -rf /var/log'",
            "ssh-remote-rm-rf",
        );
    }

    #[test]
    fn blocks_remote_git_destructive() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "ssh user@host 'git reset --hard HEAD'",
            "ssh-remote-git-reset-hard",
        );
        assert_blocks_with_pattern(
            &pack,
            "ssh host \"cd repo && git reset --hard\"",
            "ssh-remote-git-reset-hard",
        );
        assert_blocks_with_pattern(
            &pack,
            "ssh user@host 'git clean -fd'",
            "ssh-remote-git-clean",
        );
    }

    #[test]
    fn blocks_keygen_remove_host() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "ssh-keygen -R hostname", "ssh-keygen-remove-host");
        assert_blocks_with_pattern(
            &pack,
            "ssh-keygen -f ~/.ssh/known_hosts -R 192.168.1.1",
            "ssh-keygen-remove-host",
        );
    }

    #[test]
    fn blocks_ssh_add_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "ssh-add -d", "ssh-add-delete-all");
        assert_blocks_with_pattern(&pack, "ssh-add -D", "ssh-add-delete-all");
    }

    #[test]
    fn blocks_piped_destructive() {
        let pack = create_pack();
        // Piped commands with ssh and rm -rf are caught by ssh-remote-rm-rf
        assert_blocks_with_pattern(
            &pack,
            "cat script.sh | ssh host rm -rf /data",
            "ssh-remote-rm-rf",
        );
    }

    #[test]
    fn blocks_remote_sudo_rm() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "ssh root@host 'sudo rm /etc/passwd'",
            "ssh-remote-sudo-rm",
        );
    }
}
