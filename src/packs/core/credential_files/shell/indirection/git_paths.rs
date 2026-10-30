//! Symbolic destinations returned by a single, statically identified Git query.
//!
//! No repository lookup is needed: a worktree's administrative directory and
//! a relocated hooks directory keep their policy identity wherever Git stores
//! them. The policy spelling below is a semantic alias, never a claim that the
//! query actually printed `.git`.

use super::super::read_word;

const MAX_QUERY_BYTES: usize = 8 * 1024;
const MAX_QUERY_WORDS: usize = 64;
const MAX_PATH_BYTES: usize = 16 * 1024;
const MAX_PATH_COMPONENTS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GitPathKind {
    Directory,
    Hooks,
    File(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GitPath {
    kind: GitPathKind,
    /// Decoded suffix below the symbolic root. Keep its exact characters until
    /// use: appending `name` to `/a/..` makes `/a/..name`, not `/name`.
    /// Its normalized components never escape the symbolic root.
    tail: String,
    /// Git may remove a trailing slash or dot component while formatting its
    /// output. Do not join another component onto an uncertain query boundary.
    /// Once literal text has been appended, its exact boundary is known.
    requires_separator: bool,
    /// Literal path inputs which may appear in Git's output. They are shape
    /// evidence only: the policy alias must never stand in for these bytes
    /// when deciding whether an unquoted expansion is one shell field.
    output_inputs: Vec<String>,
}

impl GitPath {
    fn new(kind: GitPathKind) -> Self {
        Self {
            kind,
            tail: String::new(),
            requires_separator: true,
            output_inputs: Vec::new(),
        }
    }

    /// Append decoded literal path text. The caller retains expansion/quoting
    /// provenance and must never pass an unresolved expansion here.
    pub(super) fn append_literal(&self, suffix: &str) -> Option<Self> {
        if suffix.is_empty() {
            return Some(self.clone());
        }
        if self.requires_separator && !suffix.starts_with('/')
            || matches!(self.kind, GitPathKind::File(_))
            || self.tail.len().saturating_add(suffix.len()) > MAX_PATH_BYTES
            || suffix.contains('\0')
        {
            return None;
        }
        let tail = format!("{}{suffix}", self.tail);
        normalized_components(&tail)?;
        Some(Self {
            kind: self.kind,
            tail,
            requires_separator: false,
            output_inputs: self.output_inputs.clone(),
        })
    }

    pub(super) fn one_unquoted_field(&self, ifs: &str) -> bool {
        // Keep the scanner's denial-only interpretation of an otherwise
        // unspecified Git environment. A custom non-whitespace separator
        // cannot be checked against an opaque root, and observed root text
        // must not be hidden by the semantic `.git` spelling.
        if !ifs.chars().all(|ch| matches!(ch, ' ' | '\t' | '\n')) {
            return false;
        }
        let splits_or_globs = |text: &str| {
            text.chars()
                .any(|ch| ifs.contains(ch) || matches!(ch, '*' | '?' | '[' | '('))
        };
        !splits_or_globs(&self.tail)
            && self
                .output_inputs
                .iter()
                .all(|input| !input.is_empty() && !splits_or_globs(input))
    }

    fn query_boundary(mut self) -> Self {
        self.requires_separator = self
            .tail
            .rsplit('/')
            .next()
            .is_none_or(|component| matches!(component, "" | "." | ".."));
        let components = normalized_components(&self.tail)
            .expect("GitPath construction checks the symbolic root");
        self.tail = if components.is_empty() {
            String::new()
        } else {
            format!("/{}", components.join("/"))
        };
        self
    }

    /// An alias for the existing protected-path table. A bare directory gets
    /// a trailing slash so the table recognizes its directory anchor as well.
    pub(super) fn policy_path(&self) -> String {
        let base = match self.kind {
            GitPathKind::Directory => ".git".to_owned(),
            GitPathKind::Hooks => ".git/hooks".to_owned(),
            GitPathKind::File(name) => format!(".git/{name}"),
        };
        let tail = normalized_components(&self.tail)
            .expect("GitPath construction checks the symbolic root")
            .join("/");
        if tail.is_empty() {
            if matches!(self.kind, GitPathKind::File(_)) {
                base
            } else {
                format!("{base}/")
            }
        } else {
            format!("{base}/{tail}")
        }
    }
}

fn normalized_components(tail: &str) -> Option<Vec<&str>> {
    let mut components = Vec::new();
    for component in tail.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                // A linked worktree's git-dir need not be the common
                // directory. Crossing either symbolic base loses the proof;
                // do not pretend it is a top-level `.git` folder.
                components.pop()?;
            }
            other => {
                components.push(other);
                if components.len() > MAX_PATH_COMPONENTS {
                    return None;
                }
            }
        }
    }
    Some(components)
}

/// Recognize the complete BODY of `$(...)` or backquotes, never source which
/// merely contains a Git command. Multiple outputs, redirections, operators,
/// dynamic argv and unbalanced quotes cannot supply a single-path proof.
pub(super) fn resolve_query(source: &str) -> Option<GitPath> {
    let argv = literal_argv(source)?;
    let executable = argv.first()?.rsplit('/').next()?;
    if !matches!(executable, "git" | "git.exe") {
        return None;
    }
    let mut index = 1;
    let mut output_inputs = Vec::new();
    let mut hooks_path = None;
    while argv.get(index)?.as_str() != "rev-parse" {
        let option = argv.get(index)?.as_str();
        match option {
            "-C" | "--git-dir" | "--work-tree" => {
                let input = argv.get(index + 1)?;
                // `git -C ''` explicitly leaves the current directory alone.
                if option != "-C" || !input.is_empty() {
                    output_inputs.push(input.clone());
                }
                index += 2;
            }
            "-c" => {
                let setting = argv.get(index + 1)?;
                let (key, value) = setting.split_once('=').unwrap_or((setting, ""));
                if key.eq_ignore_ascii_case("core.hooksPath") {
                    hooks_path = Some(value.to_owned());
                }
                index += 2;
            }
            "--bare" | "--no-pager" | "--no-optional-locks" => index += 1,
            _ => {
                output_inputs.push(attached_global_option(option)?.to_owned());
                index += 1;
            }
        }
    }
    index += 1;
    let mut path = None;
    let mut reformats_paths = false;
    while let Some(argument) = argv.get(index) {
        match argument.as_str() {
            // These options do not print anything, and rev-parse accepts them
            // before or after the one path query. A format option only affects
            // later queries; either spelling retains the same path origin.
            "--path-format=absolute" | "--path-format=relative" => reformats_paths = true,
            "--quiet" | "-q" => {}
            "--git-dir" | "--absolute-git-dir" | "--git-common-dir" if path.is_none() => {
                path = Some(GitPath::new(GitPathKind::Directory));
            }
            "--git-path" if path.is_none() => {
                index += 1;
                let operand = argv.get(index)?;
                let queried = administered_path(operand)?;
                output_inputs.push(operand.clone());
                path = Some(if reformats_paths {
                    queried.query_boundary()
                } else {
                    queried
                });
            }
            _ => return None,
        }
        index += 1;
    }
    path.map(|mut path| {
        if path.kind == GitPathKind::Hooks
            && let Some(input) = hooks_path
        {
            output_inputs.push(input);
        }
        path.output_inputs = output_inputs;
        path
    })
}

fn attached_global_option(option: &str) -> Option<&str> {
    ["--git-dir=", "--work-tree="].iter().find_map(|prefix| {
        option
            .strip_prefix(prefix)
            .filter(|value| !value.is_empty())
    })
}

fn administered_path(path: &str) -> Option<GitPath> {
    if path.len() > MAX_PATH_BYTES || path.starts_with('/') || path.contains('\0') {
        return None;
    }
    // Git's hooks relocation matches the leading `hooks` component before
    // path normalization. `./hooks/../config` stays in the administrative
    // directory, whereas `hooks/../config` can leave a relocated hooks root.
    let trimmed = path.trim_start_matches("./");
    if path != trimmed
        && (administered_file(trimmed).is_some()
            || trimmed == "hooks"
            || trimmed.starts_with("hooks/"))
    {
        return GitPath::new(GitPathKind::Directory).append_literal(&format!("/{path}"));
    }
    if let Some(name) = administered_file(path) {
        // In particular, `index` can be relocated through GIT_INDEX_FILE.
        // Retain only the exact file identity, never its unknown parent.
        Some(GitPath::new(GitPathKind::File(name)))
    } else if path == "hooks" {
        Some(GitPath::new(GitPathKind::Hooks))
    } else {
        GitPath::new(GitPathKind::Hooks).append_literal(path.strip_prefix("hooks")?)
    }
}

fn administered_file(path: &str) -> Option<&'static str> {
    match path {
        "config" => Some("config"),
        "HEAD" => Some("HEAD"),
        "index" => Some("index"),
        "config.worktree" => Some("config.worktree"),
        "config.lock" => Some("config.lock"),
        _ => None,
    }
}

/// Use the shell's existing decoder, while requiring each raw word to be
/// complete and every decoded character to be literal. In particular, an
/// input redirect cannot disappear as it would in the writer tokenizer.
fn literal_argv(source: &str) -> Option<Vec<String>> {
    if source.len() > MAX_QUERY_BYTES || source.contains('\0') {
        return None;
    }
    let source = source.trim_matches([' ', '\t', '\n']);
    let bytes = source.as_bytes();
    let mut index = 0;
    let mut argv = Vec::new();
    while index < bytes.len() {
        match bytes[index] {
            b' ' | b'\t' => {
                index += 1;
                continue;
            }
            b'\\' if bytes.get(index + 1) == Some(&b'\n') => {
                index += 2;
                continue;
            }
            // A newline between words would start another shell command.
            b'\n' => return None,
            _ => {}
        }
        let (word, end) = read_word(source, index);
        if end <= index
            || word.glued_paren
            || !word.is_all_literal()
            || !complete_word(source.get(index..end)?)
        {
            return None;
        }
        argv.push(word.as_string());
        if argv.len() > MAX_QUERY_WORDS {
            return None;
        }
        index = end;
    }
    Some(argv)
}

fn complete_word(source: &str) -> bool {
    let mut quote = None;
    let mut ansi_c = false;
    let mut chars = source.chars().peekable();
    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some('\''), '\\') if ansi_c => {
                if chars.next().is_none() {
                    return false;
                }
            }
            (Some('\''), '\'') | (Some('"'), '"') => {
                quote = None;
                ansi_c = false;
            }
            (Some('\''), _) => {}
            (None, '$') if chars.peek() == Some(&'\'') => {
                chars.next();
                quote = Some('\'');
                ansi_c = true;
            }
            // Locale translation is not static quote removal. A translated
            // switch could select a different query or change a path operand.
            (None, '$') if chars.peek() == Some(&'"') => return false,
            (None, '\'' | '"') => quote = Some(ch),
            (_, '\\') if chars.next().is_none() => return false,
            _ => {}
        }
    }
    quote.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_queries_have_repository_provenance_without_a_lookup() {
        for query in ["--git-dir", "--absolute-git-dir", "--git-common-dir"] {
            for prefix in [
                "git",
                "/usr/bin/git",
                "g''it -C '/a linked worktree'",
                r"git -C $'/a worktree\'s path'",
                "git -C /another/worktree -c core.hooksPath=/outside/hooks",
                "git --git-dir=/outside/admin --work-tree /checkout",
                "git --bare --no-pager",
            ] {
                let source = format!("{prefix} rev-parse --path-format=absolute {query}");
                let path = resolve_query(&source).unwrap_or_else(|| panic!("{source}"));
                assert_eq!(path.policy_path(), ".git/");
                assert_eq!(
                    path.append_literal("/config").unwrap().policy_path(),
                    ".git/config"
                );
            }
        }
    }

    #[test]
    fn nonprinting_query_options_preserve_one_path_result() {
        for options in [
            "--quiet --git-dir",
            "-q --git-common-dir",
            "--git-dir --quiet",
            "--git-dir --path-format=absolute",
            "--path-format=relative -q --git-dir --path-format=absolute",
        ] {
            let source = format!("git rev-parse {options}");
            assert_eq!(resolve_query(&source).unwrap().policy_path(), ".git/");
        }
        for source in [
            "git rev-parse --quiet --git-dir --git-common-dir",
            "git rev-parse --git-path hooks --quiet --git-dir",
            "git rev-parse --quiet --show-toplevel",
            "git rev-parse --git-dir --path-format=unknown",
            "git rev-parse --quiet --path-format=absolute",
        ] {
            assert!(resolve_query(source).is_none(), "{source}");
        }
    }

    #[test]
    fn administered_files_keep_exact_file_identity() {
        for name in ["config", "HEAD", "index", "config.worktree", "config.lock"] {
            let source = format!("git -C /linked/worktree rev-parse --git-path {name} -q");
            let path = resolve_query(&source).unwrap();
            assert_eq!(path.policy_path(), format!(".git/{name}"));
            // The index may be relocated to any filename. Neither its parent
            // nor a neighboring filename inherits the returned file's origin.
            for suffix in [".bak", "/../notes.txt", "/child"] {
                assert!(path.append_literal(suffix).is_none(), "{name}{suffix}");
            }
            let literal_relative = format!("git rev-parse --git-path ./{name}");
            assert_eq!(
                resolve_query(&literal_relative).unwrap().policy_path(),
                format!(".git/{name}")
            );
        }
        for name in ["HEAD.backup", "index-backup", "config.worktree-other"] {
            assert!(resolve_query(&format!("git rev-parse --git-path {name}")).is_none());
        }
    }

    #[test]
    fn unquoted_fields_use_explicit_path_inputs_instead_of_policy_aliases() {
        const DEFAULT_IFS: &str = " \t\n";
        for source in [
            "git -c core.hooksPath='/tmp/hooks /tmp/notes' rev-parse --git-path hooks",
            "git -c core.hooksPath='/tmp/hooks*' rev-parse --git-path hooks/pre-commit",
            "git -c Core.HooksPath='/tmp/hooks?' rev-parse --git-path hooks",
            "git --git-dir='/tmp/admin dir' rev-parse --git-dir",
            "git --git-dir '/tmp/admin[12]' rev-parse --git-path index",
            "git --work-tree='/tmp/work tree' rev-parse --git-common-dir",
            "git --work-tree '/tmp/work*' rev-parse --absolute-git-dir",
            "git -C '/tmp/a worktree' rev-parse --git-dir",
            "git rev-parse --path-format=relative --git-path 'hooks/a b/../pre-commit'",
        ] {
            let path = resolve_query(source).unwrap();
            assert!(path.policy_path().starts_with(".git/"), "{source}");
            assert!(!path.one_unquoted_field(DEFAULT_IFS), "{source}");
        }
        let spaced = resolve_query(
            "git -c core.hooksPath='/tmp/hooks /tmp/notes' rev-parse --git-path hooks",
        )
        .unwrap();
        assert!(spaced.one_unquoted_field(""));
        assert!(spaced.one_unquoted_field("\n"));
        assert!(
            !spaced
                .append_literal("/pre-commit")
                .unwrap()
                .one_unquoted_field(DEFAULT_IFS)
        );
        for source in [
            "git rev-parse --git-dir",
            "git -C '' rev-parse --git-dir",
            "git -c core.hooksPath='/tmp/hooks /tmp/notes' rev-parse --git-dir",
            "git -c core.hooksPath='/tmp/hooks /tmp/notes' rev-parse --git-path ./hooks",
            "git -c core.hooksPath='/tmp/hooks /tmp/notes' -c core.hooksPath=/tmp/hooks rev-parse --git-path hooks",
        ] {
            let path = resolve_query(source).unwrap();
            assert!(path.one_unquoted_field(DEFAULT_IFS), "{source}");
            assert!(!path.one_unquoted_field("."), "{source}");
        }
        assert!(
            !resolve_query("git -c core.hooksPath= rev-parse --git-path hooks")
                .unwrap()
                .one_unquoted_field(DEFAULT_IFS)
        );
    }

    #[test]
    fn relocated_hooks_keep_their_own_root() {
        for source in [
            "git rev-parse --git-path hooks/pre-commit",
            "git -c core.hooksPath=/tmp/hooks rev-parse --git-path hooks/pre-commit",
            "git -C /linked/worktree rev-parse --git-path hooks/pre-commit",
        ] {
            let path = resolve_query(source).unwrap();
            assert_eq!(path.policy_path(), ".git/hooks/pre-commit");
            assert_eq!(
                path.append_literal("/../post-commit")
                    .unwrap()
                    .policy_path(),
                ".git/hooks/post-commit"
            );
            assert!(path.append_literal("/../../config").is_none());
        }
        let hooks = resolve_query("git rev-parse --git-path hooks").unwrap();
        assert!(hooks.append_literal("/../notes.txt").is_none());
        assert_eq!(
            resolve_query("git rev-parse --git-path hooks/a/../pre-commit")
                .unwrap()
                .policy_path(),
            ".git/hooks/pre-commit"
        );
        let config = resolve_query("git rev-parse --git-path config").unwrap();
        assert_eq!(config.policy_path(), ".git/config");
        assert!(config.append_literal("/anything").is_none());
        let nonrelocated = resolve_query(
            "git -c core.hooksPath=/outside/hooks rev-parse --git-path ./hooks/../config",
        )
        .unwrap();
        assert_eq!(nonrelocated.policy_path(), ".git/config");
    }

    #[test]
    fn traversal_and_sibling_suffixes_do_not_forge_administrative_paths() {
        let path = resolve_query("git rev-parse --git-dir").unwrap();
        assert_eq!(
            path.append_literal("/hooks/../config")
                .unwrap()
                .policy_path(),
            ".git/config"
        );
        for suffix in [".backup/config", "config", "/../config", "/a/../../config"] {
            assert!(path.append_literal(suffix).is_none(), "{suffix}");
        }
        for operand in [
            "../notes.txt",
            "hooks/../notes.txt",
            "/hooks/pre-commit",
            "objects/file",
            "hooks-backup/pre-commit",
            "config/../notes.txt",
        ] {
            assert!(
                resolve_query(&format!("git rev-parse --git-path {operand}")).is_none(),
                "{operand}"
            );
        }
    }

    #[test]
    fn literal_fragments_keep_their_exact_concatenation_before_normalization() {
        let path = resolve_query("git rev-parse --git-dir").unwrap();
        let hooks = path.append_literal("/hoo").unwrap();
        let hooks = hooks.append_literal("ks/").unwrap();
        assert_eq!(
            hooks.append_literal("pre-commit").unwrap().policy_path(),
            ".git/hooks/pre-commit"
        );
        for (prefix, suffix, expected) in [
            ("/", "config", ".git/config"),
            ("/a/..", "notes", ".git/a/..notes"),
            ("/a/.", "config", ".git/a/.config"),
            ("/config", ".bak", ".git/config.bak"),
        ] {
            assert_eq!(
                path.append_literal(prefix)
                    .unwrap()
                    .append_literal(suffix)
                    .unwrap()
                    .policy_path(),
                expected
            );
        }
    }

    #[test]
    fn formatted_query_boundaries_do_not_turn_siblings_into_hook_paths() {
        for format in ["absolute", "relative"] {
            for operand in ["hooks/", "hooks/.", "hooks/a/..", "hooks/a/b/.."] {
                let source = format!(
                    "git -c core.hooksPath=/tmp/hooks rev-parse --path-format={format} --git-path {operand}"
                );
                let path = resolve_query(&source).unwrap();
                assert!(path.append_literal("notes").is_none(), "{source}");
                assert!(path.append_literal("/pre-commit").is_some(), "{source}");
            }
        }
        let unchanged = resolve_query("git rev-parse --git-path hooks/a/..").unwrap();
        assert_eq!(
            unchanged.append_literal("notes").unwrap().policy_path(),
            ".git/hooks/a/..notes"
        );
        // A format option after the query cannot change text already printed.
        let unchanged =
            resolve_query("git rev-parse --git-path hooks/a/.. --path-format=absolute").unwrap();
        assert_eq!(
            unchanged.append_literal("notes").unwrap().policy_path(),
            ".git/hooks/a/..notes"
        );
        let filename =
            resolve_query("git rev-parse --path-format=absolute --git-path hooks/a/../pre-commit")
                .unwrap();
        assert_eq!(
            filename.append_literal(".sample").unwrap().policy_path(),
            ".git/hooks/pre-commit.sample"
        );
        // Suffixes appended after the query still retain their exact bytes.
        let path = filename.append_literal("/../a/..").unwrap();
        assert_eq!(
            path.append_literal("notes").unwrap().policy_path(),
            ".git/hooks/a/..notes"
        );
    }

    #[test]
    fn only_one_complete_static_path_query_is_recognized() {
        for source in [
            "",
            "git",
            "git -C",
            "git -C/checkout rev-parse --git-dir",
            "git -ccore.hooksPath=/tmp/hooks rev-parse --git-path hooks",
            "git rev-parse",
            "git rev-parse --show-toplevel",
            "git rev-parse --git-dir --show-toplevel",
            "git rev-parse --git-dir; printf /tmp",
            "git rev-parse --git-dir | cat",
            "git rev-parse --git-dir < /tmp/input",
            "git rev-parse --git-dir > /tmp/output",
            concat!("git rev-parse '--git-di", "\\", "\n", "r'"),
            "git\nrev-parse --git-dir",
            "git rev-parse --git-dir # comment",
            "git -C $REPO rev-parse --git-dir",
            "git rev-parse --git-path \"$PATHNAME\"",
            "git rev-parse \"--git-dir",
            "git rev-parse $\"--git-dir\"",
            "git rev-parse '--git-dir",
            "git rev-parse --git-dir\\",
            "'git rev-parse --git-dir'",
            "printf 'git rev-parse --git-dir'",
            "notgit rev-parse --git-dir",
        ] {
            assert!(resolve_query(source).is_none(), "{source}");
        }
        assert!(resolve_query("\n git \\\n rev-parse '--git-dir' \n").is_some());
    }

    #[test]
    fn query_and_path_budgets_bound_the_work() {
        assert!(resolve_query(&"x".repeat(MAX_QUERY_BYTES + 1)).is_none());
        let path = resolve_query("git rev-parse --git-dir").unwrap();
        assert!(
            path.append_literal(&format!("/{}", "a".repeat(MAX_PATH_BYTES)))
                .is_none()
        );
        assert!(
            path.append_literal(&"/a".repeat(MAX_PATH_COMPONENTS + 1))
                .is_none()
        );
        assert!(path.append_literal("/a\0b").is_none());
    }
}
