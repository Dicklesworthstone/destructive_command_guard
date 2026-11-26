//! Operand checks shared by POSIX trash utilities and moves into the Trash.

use std::borrow::Cow;
use std::path::Path;

use super::filesystem::{CRITICAL_TOP_LEVEL_DIRS, HOME_PARENT_DIRS};
use crate::normalize::{decode_posix_literal_word, decode_posix_syntax_token};

/// Check the original shell word. Removing quotes before calling this would
/// lose the distinction between an expanding variable and a literal dollar.
pub(super) fn unsafe_trash_operand(raw: &str, cwd: Option<&Path>) -> bool {
    unsafe_operand_in(raw, cwd, crate::config::home_dir().as_deref(), false)
}

/// With rimraf's explicit glob mode, the utility interprets patterns even
/// when quoting prevented the shell from expanding them.
pub(super) fn unsafe_rimraf_glob_operand(raw: &str, cwd: Option<&Path>) -> bool {
    unsafe_operand_in(raw, cwd, crate::config::home_dir().as_deref(), true)
}

fn unsafe_operand_in(
    raw: &str,
    cwd: Option<&Path>,
    home: Option<&Path>,
    utility_glob: bool,
) -> bool {
    let (under_home, raw_path) = raw
        .strip_prefix("~/")
        .map_or((false, raw), |suffix| (true, suffix));
    let Some((path, mut glob)) = decode_target(raw_path) else {
        return true;
    };
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty()
        || path.contains('\0')
        || matches!(trimmed.rsplit('/').next(), Some("." | ".."))
    {
        return true;
    }

    if utility_glob {
        let (parent, leaf) = trimmed.rsplit_once('/').unwrap_or(("", trimmed));
        // Only a pattern in the last component has a known directory. Brace
        // expansion, extglob groups and escapes can change its path structure.
        if path.contains(['{', '(', '\\']) || parent.contains(['*', '?', '[']) {
            return true;
        }
        glob |= leaf.contains(['*', '?', '[']);
    }

    let cwd = cwd.and_then(posix_rooted);
    let home = home.and_then(posix_rooted);
    let absolute = !under_home && path.starts_with('/');
    let base = if under_home {
        home
    } else if absolute {
        None
    } else {
        cwd
    };
    let anchored = absolute || base.is_some();
    let mut parts = Vec::new();
    if let Some(dir) = base {
        append_components(&mut parts, dir, true);
    }
    append_components(&mut parts, trimmed, anchored);

    // For a glob the enclosing directory is known. A suffix such as *.log
    // can select the worktree only if that directory is above the worktree.
    // A bare * also removes its contents when run *in* the worktree.
    let broad = if glob {
        let leaf = parts.pop().unwrap_or_default();
        leaf == ".*" || leaf.bytes().all(|byte| byte == b'*')
    } else {
        true
    };
    if parts.is_empty() {
        return anchored || broad;
    }
    if parts.last() == Some(&"..") {
        return true;
    }
    if !anchored {
        return false;
    }
    if broad && system_or_home_root(&parts)
        || glob && matches!(parts.as_slice(), ["home" | "Users"])
    {
        return true;
    }
    [cwd, home].into_iter().flatten().any(|dir| {
        let mut protected = Vec::new();
        append_components(&mut protected, dir, true);
        protected.starts_with(&parts) && (broad || protected.len() > parts.len())
    })
}

fn posix_rooted(path: &Path) -> Option<&str> {
    path.to_str().filter(|value| value.starts_with('/'))
}

/// Keep the literal decoder's quote, escape and expansion semantics. Allow
/// simple shell globs in a final component, as used by dcg's documented
/// Trash alternative for ~/Downloads/*.md. The directory itself must be fixed.
fn decode_target(raw: &str) -> Option<(Cow<'_, str>, bool)> {
    if let Some(path) = decode_posix_literal_word(raw) {
        return Some((path, false));
    }
    let (parent, leaf) = raw.rsplit_once('/').unwrap_or(("", raw));
    if !leaf.contains(['*', '?', '['])
        || !leaf
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.?*[]!".contains(&b))
    {
        return None;
    }
    let parent = decode_posix_literal_word(parent)?;
    if raw.contains('/') {
        Some((Cow::Owned(format!("{parent}/{leaf}")), true))
    } else {
        Some((Cow::Borrowed(raw), true))
    }
}

/// Lexical POSIX resolution, including in scans of POSIX commands on other
/// hosts. Do not touch the filesystem or dereference a symlink at the target.
fn append_components<'a>(parts: &mut Vec<&'a str>, path: &'a str, absolute: bool) {
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." if parts.last().is_some_and(|last| *last != "..") => {
                parts.pop();
            }
            ".." if absolute => {}
            other => parts.push(other),
        }
    }
}

fn system_or_home_root(parts: &[&str]) -> bool {
    match parts {
        [] | ["private" | "var", "tmp"] | ["private", "var", "tmp"] => true,
        [root] => {
            CRITICAL_TOP_LEVEL_DIRS.contains(root)
                || HOME_PARENT_DIRS.contains(root)
                || matches!(*root, "tmp" | "run")
        }
        [root, _] => HOME_PARENT_DIRS.contains(root),
        _ => false,
    }
}

/// Both the Finder Trash and the freedesktop Trash (including its files/
/// directory) are destinations used by dcg's move-to-Trash suggestion.
pub(super) fn is_trash_destination(raw: &str) -> bool {
    // Recognize HOME only as a spelling of the destination. Sources spelled
    // with a parameter remain dynamic and are always checked as such.
    let replaced;
    let raw = if raw.contains("$HOME") || raw.contains("${HOME}") {
        replaced = raw.replace("${HOME}", "~").replace("$HOME", "~");
        &replaced
    } else {
        raw
    };
    let path = decode_posix_syntax_token(raw);
    let mut parts = Vec::new();
    append_components(&mut parts, &path, path.starts_with('/'));
    let trash_subpath =
        |rest: &[&str]| matches!(rest, [".Trash", ..] | [".local", "share", "Trash", ..]);
    match parts.as_slice() {
        ["~", rest @ ..] if !path.starts_with('/') => return trash_subpath(rest),
        ["home" | "Users", _, rest @ ..] | ["root", rest @ ..] if trash_subpath(rest) => {
            return path.starts_with('/');
        }
        _ => {}
    }
    if !path.starts_with('/') || !parts.iter().any(|name| matches!(*name, ".Trash" | "Trash")) {
        return false;
    }
    let home = crate::config::home_dir();
    let Some(home) = home.as_deref().and_then(posix_rooted) else {
        return false;
    };
    let mut home_parts = Vec::new();
    append_components(&mut home_parts, home, true);
    parts
        .strip_prefix(home_parts.as_slice())
        .is_some_and(trash_subpath)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_operands_include_the_actual_worktree_and_its_ancestors() {
        let cwd = Some(Path::new("/data/work/repo"));
        for raw in [
            r#""""#,
            "''",
            r#""$OUT""#,
            "${OUT}",
            "$(pwd)",
            "`pwd`",
            "out/$file",
            ".",
            "'..'",
            "out/./",
            ".//",
            "//",
            "/tmp",
            "/usr",
            "/run",
            "/Users/alice",
            "/home/jo/",
            "/home",
            "~",
            "~/",
            "~/*",
            "/tmp/*",
            "./.*",
            "*",
            "**",
            "$'\\x2e'",
            "/data/work/repo",
            "../repo",
            "../re??",
            "/data/work",
        ] {
            assert!(unsafe_trash_operand(raw, cwd), "{raw}");
        }
        for raw in [
            ".env",
            "a",
            "../sibling/build",
            "./build/",
            "/tmp/pr-prov/render",
            "/home/jo/old",
            "'$OUT'",
            r"\$OUT",
            "'a & b'",
            "~/Downloads/*.md",
            "*.log",
            "build/*",
            "a' b'",
            "/data/work/repository",
        ] {
            assert!(!unsafe_trash_operand(raw, cwd), "{raw}");
        }
    }

    #[test]
    fn rimraf_glob_mode_globs_after_quote_removal() {
        let cwd = Some(Path::new("/data/work/repo"));
        assert!(unsafe_rimraf_glob_operand("'.*'", cwd));
        assert!(unsafe_rimraf_glob_operand("'./**'", cwd));
        assert!(unsafe_rimraf_glob_operand("'{.,build}'", cwd));
        assert!(!unsafe_rimraf_glob_operand("'*.log'", cwd));
        assert!(!unsafe_trash_operand("'*'", cwd));
    }

    #[test]
    fn absolute_custom_home_is_protected() {
        let home = Some(Path::new("/scratch/agenthome"));
        assert!(unsafe_operand_in("/scratch/agenthome/", None, home, false));
        assert!(unsafe_operand_in("~/./*", None, home, false));
        assert!(!unsafe_operand_in("~/build", None, home, false));
    }

    #[test]
    fn recognizes_only_platform_trash_paths() {
        for raw in [
            "~/.Trash/",
            "~/.local/share/Trash/files/",
            r#""$HOME/.Trash""#,
            "${HOME}/.Trash/",
            "'/Users/a b/.Trash/'",
            "/home/jo/.local/share/Trash/files",
        ] {
            assert!(is_trash_destination(raw), "{raw}");
        }
        for raw in [
            "foo/.Trash",
            "~/Downloads",
            "~/x/.Trash",
            "~/.Trashcan/",
            "~/.Trash/../build",
        ] {
            assert!(!is_trash_destination(raw), "{raw}");
        }
    }
}
