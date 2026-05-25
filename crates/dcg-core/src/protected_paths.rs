//! Protected-path matching for path-aware tool calls.
//!
//! Consumers configure a list of paths (`~/.ssh`, `~/.aws`, `.git`, `/etc`,
//! …); when a [`crate::ToolCall`] targets a path that resides inside any of
//! those, the engine's mode policy treats it as protected (e.g. `AcceptEdits`
//! converts the auto-allow into a prompt).
//!
//! Path expansion happens once at construction time. `~` is resolved using
//! [`dirs::home_dir`]. Relative paths in the config are resolved against the
//! engine's `working_dir`.

use std::path::{Path, PathBuf};

/// Compiled list of protected-path prefixes.
#[derive(Debug, Clone, Default)]
pub struct ProtectedPaths {
    prefixes: Vec<PathBuf>,
}

impl ProtectedPaths {
    /// Build a protected-paths matcher from the user's configuration.
    ///
    /// `working_dir` is used to anchor relative paths (e.g. `.git` becomes
    /// `<working_dir>/.git`). `~/...` entries expand using
    /// [`dirs::home_dir`]; if the home directory cannot be determined, the
    /// raw entry is kept verbatim as a best-effort fallback.
    #[must_use]
    pub fn new<I, S>(entries: I, working_dir: &Path) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let home = dirs::home_dir();
        let prefixes = entries
            .into_iter()
            .map(|s| expand(s.as_ref(), working_dir, home.as_deref()))
            .collect();
        Self { prefixes }
    }

    /// Replace the working-dir anchor for already-loaded entries. Useful when
    /// a consumer wants to switch project root without rebuilding.
    pub fn rebuild(&mut self, raw_entries: &[String], working_dir: &Path) {
        let home = dirs::home_dir();
        self.prefixes = raw_entries
            .iter()
            .map(|s| expand(s.as_str(), working_dir, home.as_deref()))
            .collect();
    }

    /// Returns the compiled prefix list. Mostly for diagnostics.
    #[must_use]
    pub fn prefixes(&self) -> &[PathBuf] {
        &self.prefixes
    }

    /// `true` if `path` lies inside any protected prefix.
    ///
    /// Comparison is done on canonicalized paths when canonicalization
    /// succeeds; otherwise the raw paths are compared component-wise.
    #[must_use]
    pub fn contains(&self, path: &Path) -> bool {
        if self.prefixes.is_empty() {
            return false;
        }
        let canon = path.canonicalize().ok();
        let target: &Path = canon.as_deref().unwrap_or(path);
        self.prefixes.iter().any(|prefix| {
            let prefix_canon = prefix.canonicalize().ok();
            let prefix_target: &Path = prefix_canon.as_deref().unwrap_or(prefix);
            starts_with_path(target, prefix_target)
        })
    }
}

fn expand(entry: &str, working_dir: &Path, home: Option<&Path>) -> PathBuf {
    if let Some(rest) = entry.strip_prefix("~/") {
        if let Some(h) = home {
            return h.join(rest);
        }
        // Best-effort fallback when home_dir() failed.
        return PathBuf::from(entry);
    }
    if entry == "~" {
        return home.map_or_else(|| PathBuf::from(entry), Path::to_path_buf);
    }
    let p = PathBuf::from(entry);
    if p.is_absolute() {
        p
    } else {
        working_dir.join(p)
    }
}

fn starts_with_path(child: &Path, parent: &Path) -> bool {
    let mut child_iter = child.components();
    let mut parent_iter = parent.components();
    loop {
        match (child_iter.next(), parent_iter.next()) {
            // Parent fully consumed → child starts with parent.
            (_, None) => return true,
            // Both have more components and they match → continue iteration.
            (Some(c), Some(p)) if c == p => {}
            // Mismatched components or child shorter than parent.
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn empty_list_never_matches() {
        let pp = ProtectedPaths::new(Vec::<String>::new(), Path::new("/tmp"));
        assert!(!pp.contains(Path::new("/etc/passwd")));
    }

    #[test]
    fn absolute_prefix_matches_descendants() {
        let pp = ProtectedPaths::new(["/etc"], Path::new("/work"));
        assert!(pp.contains(Path::new("/etc/passwd")));
        assert!(pp.contains(Path::new("/etc/ssh/sshd_config")));
        assert!(!pp.contains(Path::new("/var/log/syslog")));
    }

    #[test]
    fn home_relative_expands() {
        // We can't always rely on dirs::home_dir() in tests, so manually
        // exercise the helper.
        let home = Path::new("/home/u");
        let p = expand("~/.ssh", Path::new("/work"), Some(home));
        assert_eq!(p, PathBuf::from("/home/u/.ssh"));
    }

    #[test]
    fn working_dir_relative_anchored() {
        let home = Path::new("/home/u");
        let p = expand(".git", Path::new("/work/project"), Some(home));
        assert_eq!(p, PathBuf::from("/work/project/.git"));
    }

    #[test]
    fn contains_with_relative_anchor() {
        let pp = ProtectedPaths::new([".git"], Path::new("/work/project"));
        assert!(pp.contains(Path::new("/work/project/.git/config")));
        assert!(!pp.contains(Path::new("/work/other/.git/config")));
    }

    #[test]
    fn starts_with_handles_partial_components() {
        // "/etc-other" must NOT match prefix "/etc"
        assert!(!starts_with_path(
            Path::new("/etc-other/foo"),
            Path::new("/etc")
        ));
        // "/etc/passwd" matches prefix "/etc"
        assert!(starts_with_path(
            Path::new("/etc/passwd"),
            Path::new("/etc")
        ));
    }
}
