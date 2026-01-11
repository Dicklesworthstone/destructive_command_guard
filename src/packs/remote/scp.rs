//! `scp` pack - protections for destructive SCP operations.
//!
//! Covers destructive CLI operations:
//! - Copying to critical system paths
//! - Recursive overwrites to sensitive directories

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `scp` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "remote.scp".to_string(),
        name: "scp",
        description: "Protects against destructive SCP operations like overwrites to system paths.",
        keywords: &["scp"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // Version/help
        safe_pattern!("scp-help", r"scp\s+--?h(elp)?\b"),
        // Dry run / verbose only
        safe_pattern!("scp-verbose", r"scp\s+-v\s"),
        // Downloading from remote (remote:path first, local second)
        safe_pattern!(
            "scp-download",
            r"scp\s+(?:-[A-Za-z0-9]+\s+\S*\s*)*\S+@\S+:\S+\s+\./?(?:\s|$)"
        ),
        // Copy to home directory
        safe_pattern!(
            "scp-to-home",
            r"scp\s+.*\s+(?:\S+@\S+:)?~/[^/\s]"
        ),
        // Copy to /tmp
        safe_pattern!(
            "scp-to-tmp",
            r"scp\s+.*\s+(?:\S+@\S+:)?/tmp/"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Recursive copy to root
        destructive_pattern!(
            "scp-recursive-root",
            r"scp\s+(?:-[A-Za-z0-9]+\s+)*-r\s+.*\s+(?:\S+@\S+:)?/\s*$",
            "scp -r to root (/) is extremely dangerous."
        ),
        // Copy to /etc
        destructive_pattern!(
            "scp-to-etc",
            r"scp\s+.*\s+(?:\S+@\S+:)?/etc/",
            "scp to /etc/ can overwrite system configuration."
        ),
        // Copy to /var
        destructive_pattern!(
            "scp-to-var",
            r"scp\s+.*\s+(?:\S+@\S+:)?/var/(?!tmp)",
            "scp to /var/ can overwrite system data."
        ),
        // Copy to /boot
        destructive_pattern!(
            "scp-to-boot",
            r"scp\s+.*\s+(?:\S+@\S+:)?/boot/",
            "scp to /boot/ can corrupt boot configuration."
        ),
        // Copy to /usr
        destructive_pattern!(
            "scp-to-usr",
            r"scp\s+.*\s+(?:\S+@\S+:)?/usr/",
            "scp to /usr/ can overwrite system binaries."
        ),
        // Copy to /bin or /sbin
        destructive_pattern!(
            "scp-to-bin",
            r"scp\s+.*\s+(?:\S+@\S+:)?/s?bin/",
            "scp to /bin/ or /sbin/ can overwrite system binaries."
        ),
        // Copy to /lib
        destructive_pattern!(
            "scp-to-lib",
            r"scp\s+.*\s+(?:\S+@\S+:)?/lib(?:64)?/",
            "scp to /lib/ can overwrite system libraries."
        ),
        // Recursive copy to system paths
        destructive_pattern!(
            "scp-recursive-system",
            r"scp\s+(?:-[A-Za-z0-9]+\s+)*-r\s+.*\s+(?:\S+@\S+:)?/(?:etc|var|usr|boot|lib|bin|sbin)/",
            "Recursive scp to system directories is dangerous."
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
        assert_eq!(pack.id, "remote.scp");
        assert_eq!(pack.name, "scp");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"scp"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        // Help
        assert_safe_pattern_matches(&pack, "scp --help");
        assert_safe_pattern_matches(&pack, "scp -h");
        // Download from remote
        assert_safe_pattern_matches(&pack, "scp user@host:file.txt .");
        assert_safe_pattern_matches(&pack, "scp -P 22 user@host:/path/file .");
        // Copy to home
        assert_safe_pattern_matches(&pack, "scp file.txt user@host:~/documents/");
        // Copy to tmp
        assert_safe_pattern_matches(&pack, "scp file.txt /tmp/");
        assert_safe_pattern_matches(&pack, "scp file.txt user@host:/tmp/backup/");
        // Standard file copy (not to system paths)
        assert_allows(&pack, "scp file.txt user@host:/home/user/");
        assert_allows(&pack, "scp -r ./project user@host:/home/user/projects/");
    }

    #[test]
    fn blocks_copy_to_root() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "scp -r ./data user@host:/", "scp-recursive-root");
        assert_blocks_with_pattern(&pack, "scp -r backup/ root@server:/", "scp-recursive-root");
    }

    #[test]
    fn blocks_copy_to_etc() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "scp config.conf user@host:/etc/", "scp-to-etc");
        assert_blocks_with_pattern(
            &pack,
            "scp passwd root@server:/etc/passwd",
            "scp-to-etc",
        );
    }

    #[test]
    fn blocks_copy_to_var() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "scp data.db user@host:/var/lib/", "scp-to-var");
        // But /var/tmp is allowed
        assert_allows(&pack, "scp file.txt user@host:/var/tmp/");
    }

    #[test]
    fn blocks_copy_to_boot() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "scp vmlinuz user@host:/boot/", "scp-to-boot");
    }

    #[test]
    fn blocks_copy_to_usr() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "scp binary user@host:/usr/local/bin/", "scp-to-usr");
    }

    #[test]
    fn blocks_copy_to_bin() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "scp script root@server:/bin/", "scp-to-bin");
        assert_blocks_with_pattern(&pack, "scp script root@server:/sbin/", "scp-to-bin");
    }

    #[test]
    fn blocks_copy_to_lib() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "scp libfoo.so user@host:/lib/", "scp-to-lib");
        assert_blocks_with_pattern(&pack, "scp libbar.so user@host:/lib64/", "scp-to-lib");
    }
}
