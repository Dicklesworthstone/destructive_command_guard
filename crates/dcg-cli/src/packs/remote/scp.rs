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
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // `(?!\S*\.\./)` in the target-path patterns blocks `..` directory-traversal
    // escapes. Without it, `scp file user@host:/tmp/../etc/passwd` would match
    // `scp-to-tmp` and bypass the `/etc` protection — the path starts with `/tmp/`
    // but resolves to `/etc/passwd` on the remote end.
    vec![
        // Version/help
        safe_pattern!("scp-help", r"scp\b.*\s--?h(elp)?\b"),
        // Downloading from remote (remote:path first, local second)
        safe_pattern!("scp-download", r"scp\b.*\s(?:\S+@)?\S+:\S+\s+\.\S*\s*$"),
        // Copy to home directory
        safe_pattern!(
            "scp-to-home",
            r"scp\b.*\s(?:(?:\S+@)?\S+:)?~/(?!\S*\.\./)\S+\s*$"
        ),
        // Copy to /tmp
        safe_pattern!(
            "scp-to-tmp",
            r"scp\b.*\s(?:(?:\S+@)?\S+:)?/tmp/(?!\S*\.\./)\S*\s*$"
        ),
        // Copy to /var/tmp (safe scratch space under /var)
        safe_pattern!(
            "scp-to-var-tmp",
            r"scp\b.*\s(?:(?:\S+@)?\S+:)?/var/tmp(?:/(?!\S*\.\./)\S*)?\s*$"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Recursive copy to root
        destructive_pattern!(
            "scp-recursive-root",
            r"scp\b.*\s-[A-Za-z0-9]*r[A-Za-z0-9]*\b.*\s(?:(?:\S+@)?\S+:)?/\s*$",
            "scp -r to root (/) is extremely dangerous.",
            Critical,
            "Recursive copy to the root filesystem can overwrite critical system files, \
             potentially rendering the system unbootable. This affects all system directories \
             including /etc, /bin, /lib, and /boot.\n\n\
             Safer alternatives:\n\
             - Specify a target subdirectory instead of /\n\
             - Use rsync with --dry-run to preview changes\n\
             - Copy to /tmp first and move files individually"
        ),
        // Copy to /etc
        destructive_pattern!(
            "scp-to-etc",
            r"scp\b.*\s(?:(?:\S+@)?\S+:)?/etc(?:/\S*)?\s*$",
            "scp to /etc/ can overwrite system configuration.",
            High,
            "The /etc directory contains critical system configuration files including passwd, \
             shadow, fstab, and network settings. Overwriting these can lock you out of the \
             system or cause services to fail.\n\n\
             Safer alternatives:\n\
             - Copy to a staging directory first\n\
             - Back up existing files before overwriting\n\
             - Use configuration management tools (Ansible, etc.)"
        ),
        // Copy to /var
        destructive_pattern!(
            "scp-to-var",
            r"scp\b.*\s(?:(?:\S+@)?\S+:)?/var(?:/\S*)?\s*$",
            "scp to /var/ can overwrite system data.",
            High,
            "The /var directory contains variable data including logs, databases, mail spools, \
             and application state. Overwriting this data can cause data loss and service \
             disruptions.\n\n\
             Safer alternatives:\n\
             - Use /var/tmp for temporary staging\n\
             - Stop affected services before modifying their data\n\
             - Back up existing data first"
        ),
        // Copy to /boot
        destructive_pattern!(
            "scp-to-boot",
            r"scp\b.*\s(?:(?:\S+@)?\S+:)?/boot(?:/\S*)?\s*$",
            "scp to /boot/ can corrupt boot configuration.",
            Critical,
            "The /boot directory contains the kernel, initramfs, and bootloader configuration. \
             Corrupting these files will prevent the system from booting, requiring rescue \
             media to recover.\n\n\
             Safer alternatives:\n\
             - Use package manager for kernel updates\n\
             - Keep backup kernels available\n\
             - Test changes in a VM first"
        ),
        // Copy to /usr
        destructive_pattern!(
            "scp-to-usr",
            r"scp\b.*\s(?:(?:\S+@)?\S+:)?/usr(?:/\S*)?\s*$",
            "scp to /usr/ can overwrite system binaries.",
            High,
            "The /usr directory contains system binaries, libraries, and shared resources. \
             Overwriting files here can break system utilities and installed applications.\n\n\
             Safer alternatives:\n\
             - Use /usr/local for custom installations\n\
             - Use package managers for system updates\n\
             - Install to user directories when possible"
        ),
        // Copy to /bin or /sbin
        destructive_pattern!(
            "scp-to-bin",
            r"scp\b.*\s(?:(?:\S+@)?\S+:)?/(?:bin|sbin)(?:/\S*)?\s*$",
            "scp to /bin/ or /sbin/ can overwrite system binaries.",
            Critical,
            "The /bin and /sbin directories contain essential system binaries required for \
             basic operation. Overwriting these can make the system unusable and require \
             rescue mode recovery.\n\n\
             Safer alternatives:\n\
             - Install custom scripts to /usr/local/bin\n\
             - Use package managers for system updates\n\
             - Test binaries in user directories first"
        ),
        // Copy to /lib
        destructive_pattern!(
            "scp-to-lib",
            r"scp\b.*\s(?:(?:\S+@)?\S+:)?/lib(?:64)?(?:/\S*)?\s*$",
            "scp to /lib/ can overwrite system libraries.",
            Critical,
            "The /lib and /lib64 directories contain shared libraries required by system \
             binaries. Overwriting these can cause immediate system instability and prevent \
             commands from running.\n\n\
             Safer alternatives:\n\
             - Use package managers for library updates\n\
             - Install custom libraries to /usr/local/lib\n\
             - Use LD_LIBRARY_PATH for testing"
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
        assert_safe_pattern_matches(&pack, "scp user@host:/etc/hosts .");
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
        assert_blocks_with_pattern(&pack, "scp passwd root@server:/etc/passwd", "scp-to-etc");
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

    #[test]
    fn path_traversal_does_not_bypass_via_safe() {
        // `/tmp/../etc/passwd` resolves to `/etc/passwd` on the remote but the
        // old `/tmp/\S*` safe pattern would accept it, short-circuiting before
        // any destructive pattern ran. Verify the safe rules refuse `../`.
        let pack = create_pack();
        assert!(
            pack.matches_safe("scp file user@host:/tmp/stash/"),
            "normal /tmp copies remain safe"
        );
        assert!(
            !pack.matches_safe("scp file user@host:/tmp/../etc/passwd"),
            "traversal out of /tmp must NOT be treated as safe"
        );
        assert!(
            !pack.matches_safe("scp file user@host:/var/tmp/../root/.ssh/authorized_keys"),
            "traversal out of /var/tmp must NOT be treated as safe"
        );
        assert!(
            !pack.matches_safe("scp file user@host:~/../root/.bashrc"),
            "traversal out of ~ must NOT be treated as safe"
        );
    }
}
