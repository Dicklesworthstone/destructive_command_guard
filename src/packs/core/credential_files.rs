//! Semantic classifier behind `core.filesystem:credential-file-write`.
//!
//! The rule denies any command that WRITES a credential, private-key,
//! login-shell startup, or system authentication file, whether or not the
//! file exists yet: every truncating or appending redirect spelling, `tee` and
//! `sponge`, `cp`/`mv`/`install`/`ln` onto the path or into its directory,
//! `dd of=`, and `sed -i`/`perl -i`. Reads, `chmod`/`chown`, `ssh-keygen`,
//! and appending to `~/.ssh/known_hosts` (what `ssh` itself does) are
//! untouched.
//!
//! It is a classifier rather than a regex because the answer depends on the
//! path the shell will actually hand to `open()`: quote removal, backslash
//! escapes, brace expansion, globs, `$HOME`/`~user` forms, and `..` all change
//! it. Each target word is decoded with the shell's own quoting rules into
//! text plus a per-character "literal" flag, using the whitelist introduced
//! for the #390 carve-out (ce11b48): a character is literal when it was quoted
//! or escaped, is non-ASCII, or is one of the bare characters no supported
//! shell rewrites. A spelling that is not literal to the end cannot be proven
//! harmless, so it is denied whenever its literal prefix can still complete
//! into a protected path (`~/.zshr{c..c}`, `~/.ssh/id_*`, `~/{.zshrc,x}`) and
//! ignored when it cannot (`~/notes-{a,b}.txt`).
//!
//! Only the POSIX dialect (and the unknown dialect, evaluated as POSIX) is
//! classified here; PowerShell and Cmd spellings are out of scope.

use crate::normalize::{ShellDialect, is_env_assignment};
use crate::packs::PatternSuggestion;
use std::ops::Range;

/// Rule name under `core.filesystem`. The pattern entry in
/// `filesystem::create_destructive_patterns` carries the static reason shown
/// by `dcg rules` and the generated docs; every evaluator hit carries its own
/// reason naming the writer and the file.
pub(crate) const CREDENTIAL_FILE_WRITE_NAME: &str = "credential-file-write";

/// Safer alternatives attached to the pack pattern (its reason and
/// explanation live on the `destructive_pattern!` entry in `filesystem.rs`).
pub(crate) const CREDENTIAL_FILE_WRITE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "cat {path}",
        "Read the current content first; reads are never blocked",
    ),
    PatternSuggestion::new(
        "echo data > /tmp/{subdir}/proposed && cat /tmp/{subdir}/proposed",
        "Stage the proposed content in a scratch file and let the user apply it",
    ),
    PatternSuggestion::new(
        "echo data >> ~/.ssh/known_hosts",
        "Appending a host key to known_hosts is allowed (what ssh itself does)",
    ),
    PatternSuggestion::new(
        "chmod 600 {path}",
        "Tightening permissions on a credential file is allowed",
    ),
];

/// One classified write of a protected file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CredentialFileWrite {
    /// Byte range of the offending target (or `dd of=` operand) in the
    /// segment handed to [`classify_credential_file_write`].
    pub(crate) span: Range<usize>,
    /// Reason naming the writer, the file, and why it matters.
    pub(crate) reason: String,
}

/// Classify one command segment (may contain several simple commands).
///
/// Returns the first write of a protected file, or `None` when the segment
/// contains no such write. PowerShell and Cmd dialects are never classified.
pub(crate) fn classify_credential_file_write(
    segment: &str,
    dialect: ShellDialect,
) -> Option<CredentialFileWrite> {
    if !matches!(dialect, ShellDialect::Posix | ShellDialect::Unknown) {
        return None;
    }
    if !may_name_protected_path(segment) {
        return None;
    }
    let tokens = tokenize(segment);
    tokens
        .split(|token| matches!(token, Token::Separator))
        .find_map(classify_simple_command)
}

/// Whether a decoded command word names one of the writers this classifier
/// understands. Used by the pack's candidate gate so an obfuscated argv0
/// (`t''ee`, `\tee`) still selects core.filesystem.
pub(crate) fn is_credential_writer(executable: &str) -> bool {
    writer_kind(executable).is_some()
}

/// Cheap lexical superset of every spelling [`resolve`] can turn into a
/// protected root: `~`/`~user`, `$HOME` and the relocation variables, and the
/// absolute `/etc`, `/private/etc`, `/home/<u>`, `/Users/<u>`, `/root`, and
/// `/var/root` trees. The pack's candidate gate uses it so `npm install`,
/// `cargo install`, or a `sed | tee /tmp/out` pipeline never cold-initialise
/// core.filesystem's regex set on this rule's account.
pub(crate) fn may_name_protected_path(command: &str) -> bool {
    // `\` joins the cheap character check because this gate reads the raw
    // command, before any quote or escape removal: `tee .ss\h/authorized_keys`
    // opens `.ssh/authorized_keys` but contains no anchor to find here. The
    // rooted spellings were already escape-tolerant by accident, since `~` and
    // `$` survive into the raw text; the relative anchors have no such token.
    command.contains(['~', '$', '\\'])
        || ["/etc", "/home/", "/Users/", "/root"]
            .iter()
            .chain(RELATIVE_ANCHORS)
            .chain(RELATIVE_FILE_ANCHORS)
            .any(|needle| contains_ascii_case_insensitive(command, needle))
}

/// Whether `haystack` contains `needle` (ASCII) ignoring case.
///
/// The gate has to be at least as permissive as the matcher behind it, and
/// that matcher folds case because `/ETC/passwd` and `~/.SSH/id_rsa` open the
/// real files on a case-insensitive filesystem. A sibling of this lives in
/// `heredoc.rs` for the inline-script pre-gate, for the same reason.
fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    let (haystack, needle) = (haystack.as_bytes(), needle.as_bytes());
    if needle.is_empty() || haystack.len() < needle.len() {
        return needle.is_empty();
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

// ============================================================================
// Protected files
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Root {
    /// Relative to a home directory (the caller's, or `~user`'s).
    Home,
    /// Relative to `/etc`.
    Etc,
}

impl Root {
    const fn display_prefix(self) -> &'static str {
        match self {
            Self::Home => "~/",
            Self::Etc => "/etc/",
        }
    }
}

struct Entry {
    root: Root,
    comps: &'static [&'static str],
    /// Everything beneath the path is protected, not just the path itself.
    dir: bool,
    what: &'static str,
}

const ENTRIES: &[Entry] = &[
    Entry {
        root: Root::Home,
        comps: &[".ssh"],
        dir: true,
        what: "holds SSH private keys and the files that grant or configure SSH access",
    },
    Entry {
        root: Root::Home,
        comps: &[".gnupg"],
        dir: true,
        what: "holds GnuPG private keys and the trust database",
    },
    Entry {
        root: Root::Home,
        comps: &[".bashrc.d"],
        dir: true,
        what: "is sourced by every new bash shell",
    },
    Entry {
        root: Root::Home,
        comps: &[".zshrc.d"],
        dir: true,
        what: "is sourced by every new zsh shell",
    },
    Entry {
        root: Root::Home,
        comps: &[".aws", "credentials"],
        dir: false,
        what: "stores AWS access keys",
    },
    Entry {
        root: Root::Home,
        comps: &[".aws", "config"],
        dir: false,
        what: "configures AWS profiles, roles, and credential processes",
    },
    Entry {
        root: Root::Home,
        comps: &[".netrc"],
        dir: false,
        what: "stores login passwords for curl, git, ftp, and friends",
    },
    Entry {
        root: Root::Home,
        comps: &["_netrc"],
        dir: false,
        what: "stores login passwords for curl, git, ftp, and friends",
    },
    Entry {
        root: Root::Home,
        comps: &[".git-credentials"],
        dir: false,
        what: "stores git remote passwords and tokens in plain text",
    },
    Entry {
        root: Root::Home,
        comps: &[".npmrc"],
        dir: false,
        what: "stores npm registry auth tokens and publish settings",
    },
    Entry {
        root: Root::Home,
        comps: &[".pypirc"],
        dir: false,
        what: "stores PyPI upload credentials",
    },
    Entry {
        root: Root::Home,
        comps: &[".docker", "config.json"],
        dir: false,
        what: "stores registry auth tokens and credential helpers for docker",
    },
    Entry {
        root: Root::Home,
        comps: &[".kube", "config"],
        dir: false,
        what: "stores cluster credentials for kubectl",
    },
    Entry {
        root: Root::Home,
        comps: &[".config", "gh", "hosts.yml"],
        dir: false,
        what: "stores the GitHub CLI's OAuth tokens",
    },
    Entry {
        root: Root::Home,
        comps: &[".bashrc"],
        dir: false,
        what: "runs in every new bash shell",
    },
    Entry {
        root: Root::Home,
        comps: &[".bash_profile"],
        dir: false,
        what: "runs at every bash login",
    },
    Entry {
        root: Root::Home,
        comps: &[".bash_login"],
        dir: false,
        what: "runs at every bash login",
    },
    Entry {
        root: Root::Home,
        comps: &[".profile"],
        dir: false,
        what: "runs at every login shell start",
    },
    Entry {
        root: Root::Home,
        comps: &[".zshrc"],
        dir: false,
        what: "runs in every new zsh shell",
    },
    Entry {
        root: Root::Home,
        comps: &[".zshenv"],
        dir: false,
        what: "runs in every zsh process, interactive or not",
    },
    Entry {
        root: Root::Home,
        comps: &[".zprofile"],
        dir: false,
        what: "runs at every zsh login",
    },
    Entry {
        root: Root::Home,
        comps: &[".zlogin"],
        dir: false,
        what: "runs at every zsh login",
    },
    Entry {
        root: Root::Etc,
        comps: &["sudoers"],
        dir: false,
        what: "decides who can become root",
    },
    Entry {
        root: Root::Etc,
        comps: &["sudoers.d"],
        dir: true,
        what: "decides who can become root",
    },
    Entry {
        root: Root::Etc,
        comps: &["passwd"],
        dir: false,
        what: "defines the system's user accounts",
    },
    Entry {
        root: Root::Etc,
        comps: &["shadow"],
        dir: false,
        what: "holds the system's password hashes",
    },
    Entry {
        root: Root::Etc,
        comps: &["group"],
        dir: false,
        what: "defines group membership, including sudo and docker",
    },
    Entry {
        root: Root::Etc,
        comps: &["gshadow"],
        dir: false,
        what: "holds group password hashes and administrators",
    },
    Entry {
        root: Root::Etc,
        comps: &["ssh"],
        dir: true,
        what: "holds the SSH server configuration and host keys",
    },
];

/// Environment variables that name a protected location directly, mapped to
/// the home-relative path they stand for.
const VARIABLE_ROOTS: &[(&str, Root, &[&str])] = &[
    ("HOME", Root::Home, &[]),
    ("ZDOTDIR", Root::Home, &[]),
    ("GNUPGHOME", Root::Home, &[".gnupg"]),
    ("XDG_CONFIG_HOME", Root::Home, &[".config"]),
    ("GH_CONFIG_DIR", Root::Home, &[".config", "gh"]),
    ("DOCKER_CONFIG", Root::Home, &[".docker"]),
    ("KUBECONFIG", Root::Home, &[".kube", "config"]),
    (
        "AWS_SHARED_CREDENTIALS_FILE",
        Root::Home,
        &[".aws", "credentials"],
    ),
    ("AWS_CONFIG_FILE", Root::Home, &[".aws", "config"]),
    ("NPM_CONFIG_USERCONFIG", Root::Home, &[".npmrc"]),
];

const KNOWN_HOSTS_WHAT: &str =
    "is the SSH host-key trust store (appending to it with `>>` or `tee -a` is allowed)";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Exact {
    Protected {
        display: String,
        what: &'static str,
        append_ok: bool,
    },
    /// Not protected itself, but an ancestor of a protected path.
    Parent,
    Clear,
}

fn display_path(root: Root, comps: &[String]) -> String {
    format!("{}{}", root.display_prefix(), comps.join("/"))
}

fn entry_display(entry: &Entry, depth: usize) -> String {
    let comps: Vec<String> = entry.comps[..depth]
        .iter()
        .map(|component| (*component).to_string())
        .collect();
    display_path(entry.root, &comps)
}

/// `comps` starts with every component of `prefix`.
fn has_prefix(comps: &[String], prefix: &[&str]) -> bool {
    comps.len() >= prefix.len()
        && comps
            .iter()
            .zip(prefix)
            .all(|(component, expected)| component.eq_ignore_ascii_case(expected))
}

/// The entries `comps` is a proper ancestor of, files before directories so
/// the example a reason names is the most specific one.
fn descendants(root: Root, comps: &[String]) -> impl Iterator<Item = &'static Entry> + '_ {
    ENTRIES
        .iter()
        .filter(|entry| !entry.dir)
        .chain(ENTRIES.iter().filter(|entry| entry.dir))
        .filter(move |entry| {
            entry.root == root
                && entry.comps.len() > comps.len()
                && comps
                    .iter()
                    .zip(entry.comps)
                    .all(|(component, expected)| component.eq_ignore_ascii_case(expected))
        })
}

fn exact(root: Root, comps: &[String]) -> Exact {
    if comps.is_empty() {
        return Exact::Parent;
    }
    for entry in ENTRIES.iter().filter(|entry| entry.root == root) {
        if !has_prefix(comps, entry.comps) {
            continue;
        }
        if entry.dir {
            if root == Root::Home && entry.comps == [".ssh"] {
                return ssh_entry(comps, entry.what);
            }
            return Exact::Protected {
                display: display_path(root, comps),
                what: entry.what,
                append_ok: false,
            };
        }
        if comps.len() == entry.comps.len() {
            return Exact::Protected {
                display: display_path(root, comps),
                what: entry.what,
                append_ok: false,
            };
        }
    }
    if descendants(root, comps).next().is_some() {
        Exact::Parent
    } else {
        Exact::Clear
    }
}

/// `~/.ssh` and everything beneath it, with its two neighbours: `*.pub`
/// files are public and unprotected, and `known_hosts` may be appended to.
fn ssh_entry(comps: &[String], default_what: &'static str) -> Exact {
    let display = display_path(Root::Home, comps);
    let Some(name) = comps.get(1) else {
        return Exact::Protected {
            display,
            what: default_what,
            append_ok: false,
        };
    };
    let public_key = comps.last().is_some_and(|last| {
        std::path::Path::new(last)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("pub"))
    });
    if public_key {
        return Exact::Clear;
    }
    if comps.len() == 2
        && (name.eq_ignore_ascii_case("known_hosts") || name.eq_ignore_ascii_case("known_hosts2"))
    {
        return Exact::Protected {
            display,
            what: KNOWN_HOSTS_WHAT,
            append_ok: true,
        };
    }
    let what = match name.to_ascii_lowercase().as_str() {
        "authorized_keys" | "authorized_keys2" => "grants SSH login as this user",
        "config" => "configures SSH hosts, identities, proxies, and commands",
        "rc" | "environment" => "runs at every SSH login",
        _ => "holds SSH private keys and the files that grant or configure SSH access",
    };
    Exact::Protected {
        display,
        what,
        append_ok: false,
    }
}

/// Can a path that begins with `comps` and whose next component starts with
/// `partial` still be (or lie inside) a protected path?
fn reachable(root: Root, comps: &[String], partial: &str) -> Option<(String, &'static str)> {
    if let Exact::Protected { display, what, .. } = exact(root, comps) {
        return Some((display, what));
    }
    descendants(root, comps)
        .find(|entry| {
            let candidate = entry.comps[comps.len()];
            candidate.len() >= partial.len()
                && candidate[..partial.len()].eq_ignore_ascii_case(partial)
        })
        .map(|entry| (entry_display(entry, entry.comps.len()), entry.what))
}

// ============================================================================
// Shell word decoding
// ============================================================================

/// A shell word decoded the way the shell hands it to the program.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Word {
    /// Decoded text: quotes removed, escapes resolved, expansions kept raw.
    text: Vec<char>,
    /// Per character of `text`: the shell passes this character through
    /// verbatim (quoted, escaped, non-ASCII, or a bare character from the
    /// literal whitelist). False marks something the shell rewrites first: an
    /// expansion, a glob or brace character, or an unquoted `~`.
    literal: Vec<bool>,
    /// Raw byte range in the segment.
    range: Range<usize>,
    /// The raw word ended at an unquoted `(`: zsh reads that as glob
    /// alternation or a qualifier, so the spelled prefix is not the path.
    glued_paren: bool,
}

impl Word {
    fn as_string(&self) -> String {
        self.text.iter().collect()
    }

    fn starts_with(&self, prefix: &str) -> bool {
        let prefix: Vec<char> = prefix.chars().collect();
        self.text.starts_with(&prefix)
    }

    /// The word minus its first `offset` characters (same raw range).
    fn suffix(&self, offset: usize) -> Self {
        Self {
            text: self.text[offset..].to_vec(),
            literal: self.literal[offset..].to_vec(),
            range: self.range.clone(),
            glued_paren: self.glued_paren,
        }
    }

    fn is_all_literal(&self) -> bool {
        self.literal.iter().all(|literal| *literal)
    }
}

/// Bare characters no supported shell rewrites (the ce11b48 whitelist).
const fn is_literal_bare_char(character: char) -> bool {
    !character.is_ascii()
        || character.is_ascii_alphanumeric()
        || matches!(
            character,
            '/' | '.' | '_' | '-' | '+' | ',' | '@' | '%' | ':' | '=' | '~'
        )
}

const fn is_word_terminator(byte: u8) -> bool {
    byte.is_ascii_whitespace() || matches!(byte, b';' | b'&' | b'|' | b'<' | b'>' | b'(' | b')')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Quote {
    None,
    Single,
    Double,
}

/// Decode one word starting at byte `start`; returns the word and the byte
/// offset just past it.
#[allow(clippy::too_many_lines)]
fn read_word(segment: &str, start: usize) -> (Word, usize) {
    let mut text: Vec<char> = Vec::new();
    let mut literal: Vec<bool> = Vec::new();
    let mut quote = Quote::None;
    let mut glued_paren = false;
    let mut end = segment.len();
    let mut chars = segment[start..].char_indices().peekable();

    fn push(text: &mut Vec<char>, literal: &mut Vec<bool>, ch: char, lit: bool) {
        text.push(ch);
        literal.push(lit);
    }

    while let Some((offset, ch)) = chars.next() {
        let here = start + offset;
        match quote {
            Quote::Single => {
                if ch == '\'' {
                    quote = Quote::None;
                } else {
                    push(&mut text, &mut literal, ch, true);
                }
            }
            Quote::Double => match ch {
                '"' => quote = Quote::None,
                '\\' => match chars.next() {
                    Some((_, escaped @ ('$' | '`' | '"' | '\\'))) => {
                        push(&mut text, &mut literal, escaped, true);
                    }
                    Some((_, '\n')) => {}
                    Some((_, other)) => {
                        push(&mut text, &mut literal, '\\', true);
                        push(&mut text, &mut literal, other, true);
                    }
                    None => push(&mut text, &mut literal, '\\', true),
                },
                '$' => read_expansion(&mut chars, &mut text, &mut literal),
                '`' => read_backquote(&mut chars, &mut text, &mut literal),
                other => push(&mut text, &mut literal, other, true),
            },
            Quote::None => match ch {
                '\'' => quote = Quote::Single,
                '"' => quote = Quote::Double,
                '\\' => match chars.next() {
                    Some((_, '\n')) => {}
                    Some((_, escaped)) => push(&mut text, &mut literal, escaped, true),
                    None => push(&mut text, &mut literal, '\\', false),
                },
                '$' => {
                    if chars.peek().is_some_and(|(_, next)| *next == '\'') {
                        chars.next();
                        read_ansi_c(&mut chars, &mut text, &mut literal);
                    } else if chars.peek().is_some_and(|(_, next)| *next == '"') {
                        chars.next();
                        quote = Quote::Double;
                    } else {
                        read_expansion(&mut chars, &mut text, &mut literal);
                    }
                }
                '`' => read_backquote(&mut chars, &mut text, &mut literal),
                '(' | ')' => {
                    glued_paren = true;
                    end = here;
                    break;
                }
                other if u8::try_from(other).is_ok_and(is_word_terminator) => {
                    end = here;
                    break;
                }
                '~' => {
                    // Tilde expansion applies at the start of a word and, in
                    // bash, right after `=` in an argument (`of=~/x`,
                    // `--target-directory=~/.ssh`).
                    let lit = !(text.is_empty() || text.last() == Some(&'='));
                    push(&mut text, &mut literal, '~', lit);
                }
                other => push(&mut text, &mut literal, other, is_literal_bare_char(other)),
            },
        }
    }

    (
        Word {
            text,
            literal,
            range: start..end,
            glued_paren,
        },
        end,
    )
}

/// `$NAME`, `${…}`, `$(…)`, `$?`-style parameters: kept raw, never literal.
fn read_expansion(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    text: &mut Vec<char>,
    literal: &mut Vec<bool>,
) {
    text.push('$');
    literal.push(false);
    match chars.peek().map(|(_, next)| *next) {
        Some('(') => {
            let mut depth = 0usize;
            for (_, inner) in chars.by_ref() {
                text.push(inner);
                literal.push(false);
                match inner {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
        Some('{') => {
            for (_, inner) in chars.by_ref() {
                text.push(inner);
                literal.push(false);
                if inner == '}' {
                    break;
                }
            }
        }
        Some(next) if next.is_ascii_alphabetic() || next == '_' => {
            while let Some((_, inner)) = chars.peek().copied() {
                if inner.is_ascii_alphanumeric() || inner == '_' {
                    text.push(inner);
                    literal.push(false);
                    chars.next();
                } else {
                    break;
                }
            }
        }
        Some(next)
            if next.is_ascii_digit() || matches!(next, '?' | '$' | '@' | '*' | '#' | '!' | '-') =>
        {
            text.push(next);
            literal.push(false);
            chars.next();
        }
        _ => {}
    }
}

fn read_backquote(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    text: &mut Vec<char>,
    literal: &mut Vec<bool>,
) {
    text.push('`');
    literal.push(false);
    for (_, inner) in chars.by_ref() {
        text.push(inner);
        literal.push(false);
        if inner == '`' {
            break;
        }
    }
}

/// `$'…'` ANSI-C quoting: the content is literal; only the escapes that
/// change a path character are decoded.
fn read_ansi_c(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    text: &mut Vec<char>,
    literal: &mut Vec<bool>,
) {
    while let Some((_, inner)) = chars.next() {
        match inner {
            '\'' => break,
            '\\' => match chars.next() {
                Some((_, escaped @ ('\\' | '\'' | '"' | '/'))) => {
                    text.push(escaped);
                    literal.push(true);
                }
                Some((_, other)) => {
                    text.push('\\');
                    literal.push(true);
                    text.push(other);
                    literal.push(true);
                }
                None => {
                    text.push('\\');
                    literal.push(true);
                }
            },
            other => {
                text.push(other);
                literal.push(true);
            }
        }
    }
}

// ============================================================================
// Segment tokenizer
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteMode {
    Replace,
    Append,
}

#[derive(Debug)]
enum Token {
    Word(Word),
    /// An output redirect with a file target.
    Write {
        mode: WriteMode,
        target: Word,
    },
    Separator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedirectKind {
    Output(WriteMode),
    /// Descriptor duplication (`2>&1`, `>&2`, `<&0`): no file.
    Duplicate,
    /// Input, here-document, or here-string: consumes a word, never writes.
    Input,
}

/// Parse a redirect operator at byte `i`, returning its kind and end offset.
fn parse_redirect_operator(bytes: &[u8], i: usize) -> Option<(RedirectKind, usize)> {
    let mut j = i;
    match bytes.get(j)? {
        b'0'..=b'9' => {
            while bytes.get(j).is_some_and(u8::is_ascii_digit) {
                j += 1;
            }
            if !matches!(bytes.get(j), Some(b'<' | b'>')) {
                return None;
            }
        }
        b'{' => {
            let close = bytes[j..].iter().position(|byte| *byte == b'}')? + j;
            let name = &bytes[j + 1..close];
            if name.is_empty()
                || !name
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                return None;
            }
            j = close + 1;
            if !matches!(bytes.get(j), Some(b'<' | b'>')) {
                return None;
            }
        }
        b'&' => {
            if bytes.get(j + 1) != Some(&b'>') {
                return None;
            }
            return if bytes.get(j + 2) == Some(&b'>') {
                Some((RedirectKind::Output(WriteMode::Append), j + 3))
            } else {
                Some((RedirectKind::Output(WriteMode::Replace), j + 2))
            };
        }
        b'<' | b'>' => {}
        _ => return None,
    }
    match bytes.get(j)? {
        b'>' => match bytes.get(j + 1) {
            Some(b'>') => Some((RedirectKind::Output(WriteMode::Append), j + 2)),
            Some(b'|') => Some((RedirectKind::Output(WriteMode::Replace), j + 2)),
            Some(b'&') => {
                let mut k = j + 2;
                while matches!(bytes.get(k), Some(b' ' | b'\t')) {
                    k += 1;
                }
                if matches!(bytes.get(k), Some(b'-') | Some(b'0'..=b'9')) {
                    Some((RedirectKind::Duplicate, j + 2))
                } else {
                    Some((RedirectKind::Output(WriteMode::Replace), j + 2))
                }
            }
            _ => Some((RedirectKind::Output(WriteMode::Replace), j + 1)),
        },
        b'<' => match (bytes.get(j + 1), bytes.get(j + 2)) {
            (Some(b'<'), Some(b'<' | b'-')) => Some((RedirectKind::Input, j + 3)),
            (Some(b'<'), _) => Some((RedirectKind::Input, j + 2)),
            (Some(b'&'), _) => Some((RedirectKind::Duplicate, j + 2)),
            (Some(b'>'), _) => Some((RedirectKind::Input, j + 2)),
            _ => Some((RedirectKind::Input, j + 1)),
        },
        _ => None,
    }
}

fn tokenize(segment: &str) -> Vec<Token> {
    let bytes = segment.as_bytes();
    let len = bytes.len();
    let mut tokens = Vec::new();
    let mut i = 0usize;
    while i < len {
        let byte = bytes[i];
        if byte == b'\n' {
            tokens.push(Token::Separator);
            i += 1;
            continue;
        }
        if byte.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        match byte {
            b';' | b'(' | b')' => {
                tokens.push(Token::Separator);
                i += 1;
                continue;
            }
            b'|' => {
                tokens.push(Token::Separator);
                i += if matches!(bytes.get(i + 1), Some(b'|' | b'&')) {
                    2
                } else {
                    1
                };
                continue;
            }
            b'&' if bytes.get(i + 1) != Some(&b'>') => {
                tokens.push(Token::Separator);
                i += if bytes.get(i + 1) == Some(&b'&') {
                    2
                } else {
                    1
                };
                continue;
            }
            b'#' => {
                while i < len && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            _ => {}
        }
        if let Some((kind, operator_end)) = parse_redirect_operator(bytes, i) {
            let mut j = operator_end;
            while matches!(bytes.get(j), Some(b' ' | b'\t')) {
                j += 1;
            }
            match kind {
                RedirectKind::Duplicate => {
                    while matches!(bytes.get(j), Some(b'-') | Some(b'0'..=b'9')) {
                        j += 1;
                    }
                    i = j;
                }
                RedirectKind::Input => {
                    if j < len && !is_word_terminator(bytes[j]) {
                        let (_, end) = read_word(segment, j);
                        i = end.max(j + 1);
                    } else {
                        i = j;
                    }
                }
                RedirectKind::Output(mode) => {
                    if j < len && !is_word_terminator(bytes[j]) {
                        let (target, end) = read_word(segment, j);
                        let end = end.max(j + 1);
                        tokens.push(Token::Write { mode, target });
                        i = end;
                    } else {
                        i = j;
                    }
                }
            }
            continue;
        }
        let (word, end) = read_word(segment, i);
        if end <= i {
            i += 1;
            continue;
        }
        tokens.push(Token::Word(word));
        i = end;
    }
    tokens
}

// ============================================================================
// Path resolution
// ============================================================================

/// Path components that name a credential directory wherever the shell is
/// standing, so a relative spelling through one can be judged without knowing
/// the working directory (#407).
///
/// dcg does not know the cwd at pattern-match time, and refusing every
/// relative write would refuse `> out.txt`. But `.ssh/id_rsa` is an SSH
/// private key whether it is reached from `$HOME` or from a dotfiles
/// checkout, exactly the argument `redirect-truncate-git-internals-relative`
/// already makes for `.git/`. Each anchor here is a *directory* whose name
/// identifies its contents; the bare dotfiles in `ENTRIES` (`.npmrc`,
/// `.netrc`, `.bashrc`) are deliberately absent, because a project-local
/// `.npmrc` written by CI is ordinary and common.
///
/// `.config` is also absent on purpose: its only entry is
/// `.config/gh/hosts.yml`, and `.config/` is frequent enough in ordinary
/// command text that anchoring it would widen the always-on hot path for
/// little coverage.
///
/// Limit worth stating, measured rather than assumed: an anchor the shell
/// assembles (`tee .ss${X}h/authorized_keys`) is not recognised, because the
/// component is not literal and no root has been established yet to run the
/// [`reachable`] partial check against. The rooted spelling of the same thing
/// (`~/.ss${X}h/…`) still denies. A *redirect* to an assembled relative anchor
/// is not caught by `redirect-truncate-dynamic-path` either: that rule's
/// quick-reject keywords want the `$` directly after the `>`. An escaped
/// anchor (`.ss\h/`) IS caught — see [`may_name_protected_path`].
const RELATIVE_ANCHORS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".kube",
    ".docker",
    ".bashrc.d",
    ".zshrc.d",
];

/// Login-shell startup files, anchored only when one *is* the whole relative
/// path (`.bashrc`, `./.zshrc`).
///
/// Every one of these is executed by the next shell, so writing one is code
/// execution — the same reason `.bashrc.d/` and `.zshrc.d/` are directory
/// anchors above, and leaving the files out while anchoring their drop-in
/// directories would have been arbitrary.
///
/// Only as the entire path: `> .bashrc` is what gets written while standing in
/// a home directory, whereas `templates/.bashrc` is far more likely a skeleton
/// being assembled. The credential dotfiles (`.npmrc`, `.netrc`, `.pypirc`)
/// are deliberately NOT here — writing a project-local one is a routine CI
/// idiom, and the rooted spelling still denies.
const RELATIVE_FILE_ANCHORS: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
];

/// Byte index where `word`'s anchor begins, when it is a relative path that
/// reaches protected material.
///
/// A [`RELATIVE_ANCHORS`] directory anchors wherever it appears, but must be
/// followed by a separator: the protected material lives inside it, and a
/// plain file named `.ssh` is not it. A [`RELATIVE_FILE_ANCHORS`] file anchors
/// only as the whole path, ignoring a leading `./`.
fn relative_anchor_start(word: &Word) -> Option<usize> {
    let text = &word.text;
    let literal = |range: std::ops::Range<usize>| word.literal[range].iter().all(|flag| *flag);
    let mut start = 0usize;
    let mut only_dot_so_far = true;
    for index in 0..text.len() {
        if text[index] != '/' {
            continue;
        }
        let component: String = text[start..index].iter().collect();
        if RELATIVE_ANCHORS
            .iter()
            .any(|anchor| component.eq_ignore_ascii_case(anchor))
            && literal(start..index)
        {
            return Some(start);
        }
        // `./x` is `x`; anything else means the file anchor below is not the
        // whole path any more.
        only_dot_so_far &= component.is_empty() || component == ".";
        start = index + 1;
    }
    let last: String = text[start..].iter().collect();
    (only_dot_so_far
        && RELATIVE_FILE_ANCHORS
            .iter()
            .any(|anchor| last.eq_ignore_ascii_case(anchor))
        && literal(start..text.len()))
    .then_some(start)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Spelling {
    root: Root,
    /// Normalised literal components (no empty, `.`, or `..` entries).
    comps: Vec<String>,
    /// The literal prefix of the first component the shell rewrites, when
    /// the spelling stops being literal before its end.
    partial: Option<String>,
    /// `..` climbed above the root.
    escaped: bool,
    /// The components were taken from an anchor component rather than from a
    /// root the spelling stated, so the table's `~/…` prefix would name a path
    /// the command never did. Such a hit is displayed as written.
    rebased_at_anchor: bool,
}

/// Char offset just past the first `count` non-empty `/`-separated parts.
fn skip_parts(text: &[char], count: usize) -> usize {
    let mut index = 0usize;
    for _ in 0..count {
        while text.get(index) == Some(&'/') {
            index += 1;
        }
        if index >= text.len() {
            return text.len();
        }
        while index < text.len() && text[index] != '/' {
            index += 1;
        }
    }
    index
}

fn parse_variable(word: &Word) -> Option<(String, usize)> {
    let text = &word.text;
    if text.first() != Some(&'$') || word.literal.first().copied().unwrap_or(true) {
        return None;
    }
    if text.get(1) == Some(&'{') {
        let close = text.iter().position(|ch| *ch == '}')?;
        let name: String = text[2..close].iter().collect();
        return Some((name, close + 1));
    }
    let mut end = 1usize;
    while text
        .get(end)
        .is_some_and(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
    {
        end += 1;
    }
    if end == 1 {
        return None;
    }
    Some((text[1..end].iter().collect(), end))
}

/// Resolve a decoded word to a protected root plus path components, or
/// `None` when it cannot name a protected location (relative paths, other
/// absolute trees, quoted `~`, unknown variables).
/// The root a spelling states outright, and where its components begin.
///
/// `None` means the word states no root this classifier models — a relative
/// path, or one rooted somewhere it does not know (`$PWD`, `/opt`). Those are
/// not rejected outright; [`resolve`] falls back to an anchor component.
fn rooted_prefix(word: &Word) -> Option<(Root, Vec<String>, usize)> {
    let text = &word.text;
    let first = *text.first()?;
    if !word.literal[0] && first == '~' {
        // `~`, `~/…`, `~user/…` — all home directories.
        let mut end = 1usize;
        while text.get(end).is_some_and(|ch| *ch != '/') {
            end += 1;
        }
        return Some((Root::Home, Vec::new(), end));
    }
    if !word.literal[0] && first == '$' {
        let (name, end) = parse_variable(word)?;
        let (_, root, alias) = VARIABLE_ROOTS
            .iter()
            .find(|(candidate, _, _)| *candidate == name)?;
        if text.get(end).is_some_and(|ch| *ch != '/') {
            return None;
        }
        let alias = alias
            .iter()
            .map(|component| (*component).to_string())
            .collect();
        return Some((*root, alias, end));
    }
    if first != '/' {
        return None;
    }
    // The first components of an absolute path are read raw: the user
    // component of `/home/*/.ssh` may be a glob and still name homes.
    let raw: String = text.iter().collect();
    let mut parts = raw.split('/').filter(|part| !part.is_empty());
    let head = parts.next()?;
    let second = parts.next();
    // Case-folded: on a case-insensitive filesystem — APFS and NTFS by
    // default — `/ETC/passwd` opens `/etc/passwd`, so a case-sensitive
    // comparison here reads as a different path and lets the write through.
    // Folding costs a false positive only on a case-sensitive filesystem that
    // has a genuinely distinct `/ETC`.
    let is = |value: &str, expected: &str| value.eq_ignore_ascii_case(expected);
    let second_is = |expected: &str| second.is_some_and(|second| is(second, expected));
    let (root, consumed) = if (is(head, "home") || is(head, "Users")) && second.is_some() {
        (Root::Home, 2usize)
    } else if is(head, "root") {
        (Root::Home, 1)
    } else if is(head, "var") && second_is("root") {
        (Root::Home, 2)
    } else if is(head, "etc") {
        (Root::Etc, 1)
    } else if is(head, "private") && second_is("etc") {
        (Root::Etc, 2)
    } else {
        return None;
    };
    Some((root, Vec::new(), skip_parts(text, consumed)))
}

fn resolve(word: &Word) -> Option<Spelling> {
    let text = &word.text;
    let mut rebased_at_anchor = false;
    let (root, mut comps, rest_start): (Root, Vec<String>, usize) = match rooted_prefix(word) {
        Some(prefix) => prefix,
        None => {
            // A relative spelling names the same credential material as the
            // absolute one, and until #407 only the absolute one was judged:
            // `tee ~/.ssh/authorized_keys` denied while
            // `tee .ssh/authorized_keys` was allowed. Rebasing onto
            // `Root::Home` at the anchor hands the rest to the same table, so
            // these spellings inherit every decision the rooted ones already
            // make — including the `*.pub` and `known_hosts`-append carve-outs.
            //
            // This also catches a root the classifier does not model:
            // `$PWD/.ssh/id_rsa`, `$FOO/.ssh/id_rsa` and `/opt/.ssh/id_rsa`
            // reach here because `rooted_prefix` declined them, and the `.ssh`
            // component decides them anyway. A word with no anchor at all is
            // not a path this classifier can judge.
            let start = relative_anchor_start(word)?;
            rebased_at_anchor = true;
            (Root::Home, Vec::new(), start)
        }
    };

    let mut current = String::new();
    let mut partial = None;
    let mut escaped = false;
    let mut push_component = |comps: &mut Vec<String>, component: &str| match component {
        "" | "." => {}
        ".." => {
            if comps.pop().is_none() {
                escaped = true;
            }
        }
        other => comps.push(other.to_string()),
    };
    for index in rest_start..text.len() {
        let ch = text[index];
        if ch == '/' {
            push_component(&mut comps, &current);
            current.clear();
            continue;
        }
        if !word.literal[index] {
            partial = Some(current.clone());
            break;
        }
        current.push(ch);
    }
    if partial.is_none() {
        push_component(&mut comps, &current);
        if word.glued_paren {
            partial = Some(comps.pop().unwrap_or_default());
        }
    }

    // An anchor applies wherever it sits, not only at the start of the path.
    // `~/projects/app/.ssh/id_rsa` is an SSH private key as much as
    // `~/.ssh/id_rsa` is, and without this it was allowed while the same file
    // named relatively — `projects/app/.ssh/id_rsa` — denied, because only the
    // relative branch consulted the anchors. Rebasing runs only when the
    // spelling as a whole names nothing protected, so it can widen the match
    // and never narrow one.
    if !rebased_at_anchor && matches!(exact(root, &comps), Exact::Clear) {
        let anchor = comps
            .iter()
            .position(|component| {
                RELATIVE_ANCHORS
                    .iter()
                    .any(|anchor| component.eq_ignore_ascii_case(anchor))
            })
            .filter(|index| *index > 0);
        if let Some(index) = anchor {
            comps.drain(..index);
            rebased_at_anchor = true;
        }
    }

    Some(Spelling {
        root,
        comps,
        partial,
        escaped,
        rebased_at_anchor,
    })
}

// ============================================================================
// Writers
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriterKind {
    Tee,
    Sponge,
    Cp,
    Mv,
    Install,
    Ln,
    Dd,
    Sed,
    Perl,
}

fn writer_kind(executable: &str) -> Option<WriterKind> {
    let name = executable
        .strip_prefix('g')
        .filter(|rest| matches!(*rest, "tee" | "cp" | "mv" | "install" | "ln" | "dd" | "sed"));
    match name.unwrap_or(executable) {
        "tee" => Some(WriterKind::Tee),
        "sponge" => Some(WriterKind::Sponge),
        "cp" => Some(WriterKind::Cp),
        "mv" => Some(WriterKind::Mv),
        "install" => Some(WriterKind::Install),
        "ln" => Some(WriterKind::Ln),
        "dd" => Some(WriterKind::Dd),
        "sed" => Some(WriterKind::Sed),
        "perl" => Some(WriterKind::Perl),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Writer {
    kind: Option<WriterKind>,
    mode: WriteMode,
}

impl Writer {
    const fn redirect(mode: WriteMode) -> Self {
        Self { kind: None, mode }
    }

    fn verb(self) -> &'static str {
        match (self.kind, self.mode) {
            (None, WriteMode::Replace) => "a truncating redirect (`>`) rewrites",
            (None, WriteMode::Append) => "an appending redirect (`>>`) adds to",
            (Some(WriterKind::Tee), WriteMode::Replace) => "`tee` rewrites",
            (Some(WriterKind::Tee), WriteMode::Append) => "`tee -a` appends to",
            (Some(WriterKind::Sponge), WriteMode::Replace) => "`sponge` rewrites",
            (Some(WriterKind::Sponge), WriteMode::Append) => "`sponge -a` appends to",
            (Some(WriterKind::Cp), _) => "`cp` writes",
            (Some(WriterKind::Mv), _) => "`mv` replaces",
            (Some(WriterKind::Install), _) => "`install` writes",
            (Some(WriterKind::Ln), _) => "`ln` replaces",
            (Some(WriterKind::Dd), WriteMode::Replace) => "`dd` overwrites",
            (Some(WriterKind::Dd), WriteMode::Append) => "`dd oflag=append` appends to",
            (Some(WriterKind::Sed), _) => "`sed -i` rewrites",
            (Some(WriterKind::Perl), _) => "`perl -i` rewrites",
        }
    }
}

const REMEDY: &str = "Reads and chmod/chown are unaffected; show the user the exact change and let them apply it, or grant this one command with `dcg allow-once`.";

fn protected_hit(
    writer: Writer,
    display: &str,
    what: &str,
    span: Range<usize>,
) -> CredentialFileWrite {
    CredentialFileWrite {
        span,
        reason: format!("{} {display}, which {what}. {REMEDY}", writer.verb()),
    }
}

fn unprovable_hit(
    writer: Writer,
    word: &Word,
    example: &str,
    what: &str,
    span: Range<usize>,
) -> CredentialFileWrite {
    CredentialFileWrite {
        span,
        reason: format!(
            "{} `{}`: the shell expands that spelling before the file is opened and it can name {example}, which {what}. Spell the destination literally. {REMEDY}",
            writer.verb(),
            word.as_string()
        ),
    }
}

fn escaped_hit(writer: Writer, word: &Word, root: Root, span: Range<usize>) -> CredentialFileWrite {
    CredentialFileWrite {
        span,
        reason: format!(
            "{} `{}`: `..` climbs out of {} so the destination cannot be verified against the protected credential and login files. Spell the destination literally. {REMEDY}",
            writer.verb(),
            word.as_string(),
            match root {
                Root::Home => "the home directory",
                Root::Etc => "/etc",
            }
        ),
    }
}

/// Judge a word that names the file a writer opens.
fn judge_file_target(word: &Word, writer: Writer) -> Option<CredentialFileWrite> {
    let spelling = resolve(word)?;
    let span = word.range.clone();
    if spelling.escaped {
        return Some(escaped_hit(writer, word, spelling.root, span));
    }
    if let Some(partial) = &spelling.partial {
        return reachable(spelling.root, &spelling.comps, partial)
            .map(|(example, what)| unprovable_hit(writer, word, &example, what, span));
    }
    match exact(spelling.root, &spelling.comps) {
        Exact::Protected {
            display,
            what,
            append_ok,
        } => {
            if append_ok && writer.mode == WriteMode::Append {
                None
            } else {
                // Name the file the way the command named it. A rebased
                // spelling was put onto the home table to be judged, but
                // `~/.ssh/id_rsa` is not where `projects/app/.ssh/id_rsa`
                // points, and a reason that claims a path the user never wrote
                // reads like a misfire.
                let display = if spelling.rebased_at_anchor {
                    word.as_string()
                } else {
                    display
                };
                Some(protected_hit(writer, &display, what, span))
            }
        }
        Exact::Parent | Exact::Clear => None,
    }
}

// ---- directory placement (cp/mv/install/ln into a directory) ---------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum PatternChar {
    Literal(char),
    Star,
    Any,
}

/// The final path component of a source operand as a match pattern:
/// literal when fully literal, otherwise a glob where every shell-active
/// character can match anything (brace expansion and expansions included,
/// and `*` may match a leading dot under `dotglob`).
fn source_basename_pattern(word: &Word) -> Vec<PatternChar> {
    let mut end = word.text.len();
    while end > 0 && word.text[end - 1] == '/' {
        end -= 1;
    }
    let start = word.text[..end]
        .iter()
        .rposition(|ch| *ch == '/')
        .map_or(0, |slash| slash + 1);
    let name: Vec<char> = word.text[start..end].to_vec();
    let literal = &word.literal[start..end];
    if name.is_empty() || name == ['.'] || name == ['.', '.'] || word.glued_paren {
        return vec![PatternChar::Star];
    }
    let mut pattern = Vec::with_capacity(name.len());
    for (ch, lit) in name.iter().zip(literal) {
        let next = match (*lit, *ch) {
            (true, ch) => PatternChar::Literal(ch),
            (false, '?') => PatternChar::Any,
            (false, _) => PatternChar::Star,
        };
        if next == PatternChar::Star && pattern.last() == Some(&PatternChar::Star) {
            continue;
        }
        pattern.push(next);
    }
    pattern
}

fn glob_matches(pattern: &[PatternChar], name: &[char]) -> bool {
    match pattern.split_first() {
        None => name.is_empty(),
        Some((PatternChar::Star, rest)) => {
            (0..=name.len()).any(|skip| glob_matches(rest, &name[skip..]))
        }
        Some((PatternChar::Any, rest)) => !name.is_empty() && glob_matches(rest, &name[1..]),
        Some((PatternChar::Literal(expected), rest)) => {
            name.first() == Some(expected) && glob_matches(rest, &name[1..])
        }
    }
}

/// `cp`/`mv`/`install`/`ln` placing `source` inside `directory`.
fn judge_placement(
    directory: &Spelling,
    directory_word: &Word,
    source: &Word,
    writer: Writer,
) -> Option<CredentialFileWrite> {
    let span = directory_word.range.clone();
    if directory.escaped {
        return Some(escaped_hit(writer, directory_word, directory.root, span));
    }
    if let Some(partial) = &directory.partial {
        return reachable(directory.root, &directory.comps, partial)
            .map(|(example, what)| unprovable_hit(writer, directory_word, &example, what, span));
    }
    match exact(directory.root, &directory.comps) {
        Exact::Protected { display, what, .. } => Some(protected_hit(writer, &display, what, span)),
        Exact::Clear => None,
        Exact::Parent => {
            let pattern = source_basename_pattern(source);
            if pattern
                .iter()
                .all(|ch| matches!(ch, PatternChar::Literal(_)))
            {
                let basename: String = pattern
                    .iter()
                    .filter_map(|ch| match ch {
                        PatternChar::Literal(ch) => Some(*ch),
                        _ => None,
                    })
                    .collect();
                let mut comps = directory.comps.clone();
                comps.push(basename);
                return match exact(directory.root, &comps) {
                    Exact::Protected { display, what, .. } => {
                        Some(protected_hit(writer, &display, what, source.range.clone()))
                    }
                    // Copying a whole `.aws`/`.config` tree into place installs
                    // whatever credential files it carries.
                    Exact::Parent => descendants(directory.root, &comps).next().map(|entry| {
                        CredentialFileWrite {
                            span: source.range.clone(),
                            reason: format!(
                                "{} {}, a directory that carries credential or login files ({}, which {}). {REMEDY}",
                                writer.verb(),
                                display_path(directory.root, &comps),
                                entry_display(entry, entry.comps.len()),
                                entry.what
                            ),
                        }
                    }),
                    Exact::Clear => None,
                };
            }
            let depth = directory.comps.len();
            descendants(directory.root, &directory.comps)
                .find(|entry| {
                    glob_matches(&pattern, &entry.comps[depth].chars().collect::<Vec<_>>())
                })
                .map(|entry| CredentialFileWrite {
                    span: source.range.clone(),
                    reason: format!(
                        "{} `{}` into {}: the shell expands that source before the copy and it can land on {}, which {}. Name the files explicitly. {REMEDY}",
                        writer.verb(),
                        source.as_string(),
                        display_path(directory.root, &directory.comps),
                        entry_display(entry, depth + 1),
                        entry.what
                    ),
                })
        }
    }
}

// ---- argv parsing ----------------------------------------------------------

/// Executable basename of a decoded, fully literal command word.
fn executable_name(word: &Word) -> Option<String> {
    if word.text.is_empty() || !word.is_all_literal() {
        return None;
    }
    let text = word.as_string();
    let base = text.rsplit('/').next().unwrap_or(&text);
    let base = base
        .strip_suffix(".exe")
        .or_else(|| base.strip_suffix(".EXE"))
        .unwrap_or(base);
    Some(base.to_ascii_lowercase())
}

/// Skip the options of a wrapper command; returns the index of the wrapped
/// command word, or `None` when the wrapper makes it unknowable.
fn skip_wrapper(name: &str, args: &[&Word]) -> Option<usize> {
    let (short_value, long_value): (&[char], &[&str]) = match name {
        "sudo" => (
            &['u', 'g', 'p', 'C', 'D', 'h', 'r', 't', 'T', 'U'],
            &[
                "user",
                "group",
                "prompt",
                "close-from",
                "chdir",
                "host",
                "role",
                "type",
                "command-timeout",
                "other-user",
            ],
        ),
        "doas" => (&['u', 'C'], &[]),
        "env" => (&['u', 'C'], &["unset", "chdir"]),
        "nice" => (&['n'], &["adjustment"]),
        "ionice" => (&['c', 'n', 'p'], &["class", "classdata", "pid"]),
        "timeout" => (&['s', 'k'], &["signal", "kill-after"]),
        "stdbuf" => (&['i', 'o', 'e'], &["input", "output", "error"]),
        "exec" => (&['a'], &[]),
        "caffeinate" => (&['t', 'w'], &[]),
        "command" | "nohup" | "builtin" | "time" | "chronic" | "setsid" | "unbuffer" => (&[], &[]),
        _ => return None,
    };
    let mut index = 0usize;
    while let Some(word) = args.get(index) {
        let text = word.as_string();
        if text == "--" {
            index += 1;
            break;
        }
        if name == "env" && (text == "-S" || text.starts_with("--split-string")) {
            // `env -S` re-splits a string into words dcg cannot see.
            return None;
        }
        if name == "command" && matches!(text.as_str(), "-v" | "-V") {
            // A query, not an execution.
            return None;
        }
        if let Some(long) = text.strip_prefix("--") {
            let option = long.split_once('=').map_or(long, |(option, _)| option);
            if long_value.contains(&option) && !long.contains('=') {
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if text.len() > 1 && text.starts_with('-') {
            let cluster: Vec<char> = text[1..].chars().collect();
            let mut consumed_next = false;
            for (position, option) in cluster.iter().enumerate() {
                if short_value.contains(option) {
                    consumed_next = position + 1 == cluster.len();
                    break;
                }
            }
            index += if consumed_next { 2 } else { 1 };
            continue;
        }
        if name == "env" && is_env_assignment(&text) {
            index += 1;
            continue;
        }
        if name == "timeout" {
            // The first operand is the DURATION.
            index += 1;
        }
        break;
    }
    Some(index)
}

const MAX_WRAPPER_DEPTH: usize = 16;

/// Drop reserved words, leading assignments, and wrapper commands.
fn strip_prefixes<'a>(mut words: &'a [&'a Word]) -> Option<&'a [&'a Word]> {
    for _ in 0..MAX_WRAPPER_DEPTH {
        let first = *words.first()?;
        let text = first.as_string();
        if crate::context::is_shell_command_prefix_reserved_word(&text) || is_env_assignment(&text)
        {
            words = &words[1..];
            continue;
        }
        let name = executable_name(first)?;
        if writer_kind(&name).is_some() {
            return Some(words);
        }
        let skip = skip_wrapper(&name, &words[1..])?;
        words = &words[1 + skip..];
    }
    None
}

fn classify_simple_command(tokens: &[Token]) -> Option<CredentialFileWrite> {
    let mut words: Vec<&Word> = Vec::new();
    for token in tokens {
        match token {
            Token::Word(word) => words.push(word),
            Token::Write { mode, target } => {
                if let Some(hit) = judge_file_target(target, Writer::redirect(*mode)) {
                    return Some(hit);
                }
            }
            Token::Separator => {}
        }
    }
    let argv = strip_prefixes(&words)?;
    let (argv0, args) = argv.split_first()?;
    let kind = writer_kind(&executable_name(argv0)?)?;
    match kind {
        WriterKind::Tee | WriterKind::Sponge => classify_tee(kind, args),
        WriterKind::Cp | WriterKind::Mv | WriterKind::Install | WriterKind::Ln => {
            classify_copy(kind, args)
        }
        WriterKind::Dd => classify_dd(args),
        WriterKind::Sed => classify_sed(args),
        WriterKind::Perl => classify_perl(args),
    }
}

fn classify_tee(kind: WriterKind, args: &[&Word]) -> Option<CredentialFileWrite> {
    let mut mode = WriteMode::Replace;
    let mut operands: Vec<&Word> = Vec::new();
    let mut ended = false;
    for word in args {
        let text = word.as_string();
        if ended || text == "-" || !text.starts_with('-') {
            operands.push(word);
            continue;
        }
        if text == "--" {
            ended = true;
        } else if text == "--append" || (!text.starts_with("--") && text[1..].contains('a')) {
            mode = WriteMode::Append;
        }
    }
    let writer = Writer {
        kind: Some(kind),
        mode,
    };
    operands
        .into_iter()
        .find_map(|word| judge_file_target(word, writer))
}

fn classify_copy(kind: WriterKind, args: &[&Word]) -> Option<CredentialFileWrite> {
    let (short_value, long_value): (&[char], &[&str]) = match kind {
        WriterKind::Install => (
            &['t', 'S', 'm', 'o', 'g'],
            &["target-directory", "suffix", "mode", "owner", "group"],
        ),
        _ => (&['t', 'S'], &["target-directory", "suffix"]),
    };
    let mut operands: Vec<&Word> = Vec::new();
    let mut target_dir: Option<Word> = None;
    let mut no_target_dir = false;
    let mut directory_mode = false;
    let mut ended = false;
    let mut index = 0usize;
    while let Some(word) = args.get(index) {
        index += 1;
        let text = word.as_string();
        if ended || text == "-" || !text.starts_with('-') {
            operands.push(word);
            continue;
        }
        if text == "--" {
            ended = true;
            continue;
        }
        if let Some(long) = text.strip_prefix("--") {
            let (option, value) = long
                .split_once('=')
                .map_or((long, None), |(option, value)| (option, Some(value)));
            match option {
                "target-directory" => {
                    target_dir = match value {
                        // `--target-directory=` is 2 + (long minus value) chars in.
                        Some(value) => Some(word.suffix(2 + long.len() - value.len())),
                        None => {
                            index += 1;
                            args.get(index - 1).map(|next| (*next).clone())
                        }
                    };
                }
                "no-target-directory" => no_target_dir = true,
                "directory" if kind == WriterKind::Install => directory_mode = true,
                other if long_value.contains(&other) && value.is_none() => index += 1,
                _ => {}
            }
            continue;
        }
        let cluster: Vec<char> = text[1..].chars().collect();
        for (position, option) in cluster.iter().enumerate() {
            match option {
                'T' => no_target_dir = true,
                'd' if kind == WriterKind::Install => directory_mode = true,
                option if short_value.contains(option) => {
                    let attached = position + 1 < cluster.len();
                    let value = if attached {
                        Some(word.suffix(position + 2))
                    } else {
                        index += 1;
                        args.get(index - 1).map(|next| (*next).clone())
                    };
                    if *option == 't' {
                        target_dir = value;
                    }
                    break;
                }
                _ => {}
            }
        }
    }
    if directory_mode {
        return None;
    }
    let writer = Writer {
        kind: Some(kind),
        mode: WriteMode::Replace,
    };
    if let Some(dir_word) = target_dir {
        let directory = resolve(&dir_word)?;
        return operands
            .iter()
            .find_map(|source| judge_placement(&directory, &dir_word, source, writer));
    }
    if operands.len() < 2 {
        return None;
    }
    let (dest, sources) = operands.split_last()?;
    if no_target_dir {
        return judge_file_target(dest, writer);
    }
    let destination = resolve(dest)?;
    if destination.escaped || destination.partial.is_some() {
        return judge_file_target(dest, writer);
    }
    match exact(destination.root, &destination.comps) {
        Exact::Protected { display, what, .. } => {
            Some(protected_hit(writer, &display, what, dest.range.clone()))
        }
        Exact::Parent => sources
            .iter()
            .find_map(|source| judge_placement(&destination, dest, source, writer)),
        Exact::Clear => None,
    }
}

fn classify_dd(args: &[&Word]) -> Option<CredentialFileWrite> {
    let append = args.iter().any(|word| {
        let text = word.as_string();
        text.strip_prefix("oflag=")
            .is_some_and(|flags| flags.split(',').any(|flag| flag == "append"))
    });
    let writer = Writer {
        kind: Some(WriterKind::Dd),
        mode: if append {
            WriteMode::Append
        } else {
            WriteMode::Replace
        },
    };
    args.iter()
        .filter(|word| word.starts_with("of="))
        .find_map(|word| judge_file_target(&word.suffix(3), writer))
}

fn classify_sed(args: &[&Word]) -> Option<CredentialFileWrite> {
    let mut in_place = false;
    let mut operands: Vec<&Word> = Vec::new();
    let mut ended = false;
    let mut index = 0usize;
    while let Some(word) = args.get(index) {
        index += 1;
        let text = word.as_string();
        if ended || text == "-" || !text.starts_with('-') {
            operands.push(word);
            continue;
        }
        if text == "--" {
            ended = true;
            continue;
        }
        if let Some(long) = text.strip_prefix("--") {
            let option = long.split_once('=').map_or(long, |(option, _)| option);
            match option {
                "in-place" => in_place = true,
                "expression" | "file" | "line-length" if !long.contains('=') => index += 1,
                _ => {}
            }
            continue;
        }
        let cluster: Vec<char> = text[1..].chars().collect();
        for (position, option) in cluster.iter().enumerate() {
            match option {
                'i' | 'I' => {
                    in_place = true;
                    break;
                }
                'e' | 'f' | 'l' => {
                    if position + 1 == cluster.len() {
                        index += 1;
                    }
                    break;
                }
                _ => {}
            }
        }
    }
    if !in_place {
        return None;
    }
    let writer = Writer {
        kind: Some(WriterKind::Sed),
        mode: WriteMode::Replace,
    };
    operands
        .into_iter()
        .filter(|word| !word.text.is_empty())
        .find_map(|word| judge_file_target(word, writer))
}

fn classify_perl(args: &[&Word]) -> Option<CredentialFileWrite> {
    let mut in_place = false;
    let mut operands: Vec<&Word> = Vec::new();
    let mut ended = false;
    let mut index = 0usize;
    while let Some(word) = args.get(index) {
        index += 1;
        let text = word.as_string();
        if ended || text == "-" || !text.starts_with('-') {
            operands.push(word);
            continue;
        }
        if text == "--" {
            ended = true;
            continue;
        }
        if text.starts_with("--") {
            continue;
        }
        let cluster: Vec<char> = text[1..].chars().collect();
        for (position, option) in cluster.iter().enumerate() {
            match option {
                'i' => {
                    in_place = true;
                    break;
                }
                'e' | 'E' | 'M' | 'm' | 'I' | 'F' | 'x' => {
                    if position + 1 == cluster.len() && matches!(option, 'e' | 'E' | 'M' | 'm') {
                        index += 1;
                    }
                    break;
                }
                _ => {}
            }
        }
    }
    if !in_place {
        return None;
    }
    let writer = Writer {
        kind: Some(WriterKind::Perl),
        mode: WriteMode::Replace,
    };
    operands
        .into_iter()
        .filter(|word| !word.text.is_empty())
        .find_map(|word| judge_file_target(word, writer))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(command: &str) -> Option<CredentialFileWrite> {
        classify_credential_file_write(command, ShellDialect::Posix)
    }

    fn denied(command: &str) -> CredentialFileWrite {
        hit(command).unwrap_or_else(|| panic!("expected credential-file-write for {command:?}"))
    }

    fn allowed(command: &str) {
        assert!(
            hit(command).is_none(),
            "expected no credential-file-write for {command:?}: {:?}",
            hit(command)
        );
    }

    #[test]
    fn every_listed_path_is_denied_for_every_writer() {
        let paths = [
            "~/.ssh/authorized_keys",
            "~/.ssh/config",
            "~/.ssh/id_rsa",
            "~/.ssh/id_ed25519",
            "~/.ssh/deploy.pem",
            "~/.ssh/rc",
            "~/.aws/credentials",
            "~/.aws/config",
            "~/.netrc",
            "~/_netrc",
            "~/.git-credentials",
            "~/.npmrc",
            "~/.pypirc",
            "~/.docker/config.json",
            "~/.kube/config",
            "~/.gnupg/private-keys-v1.d/key.key",
            "~/.gnupg/trustdb.gpg",
            "~/.config/gh/hosts.yml",
            "~/.bashrc",
            "~/.zshrc",
            "~/.zshenv",
            "~/.profile",
            "~/.bash_profile",
            "~/.zprofile",
            "~/.bashrc.d/10-path.sh",
            "~/.zshrc.d/aliases.zsh",
            "/etc/sudoers",
            "/etc/sudoers.d/agent",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/ssh/sshd_config",
            "/etc/ssh/sshd_config.d/10-root.conf",
        ];
        for path in paths {
            for command in [
                format!("echo x > {path}"),
                format!("echo x >> {path}"),
                format!("printf x >| {path}"),
                format!("cat <<EOF > {path}"),
                format!("echo x | tee {path}"),
                format!("echo x | tee -a {path}"),
                format!("echo x | sudo tee -a {path}"),
                format!("cp ./src {path}"),
                format!("mv ./src {path}"),
                format!("install -m 600 ./src {path}"),
                format!("ln -sf /tmp/evil {path}"),
                format!("dd if=/tmp/x of={path}"),
                format!("sed -i 's/a/b/' {path}"),
                format!("sed -i.bak -e 's/a/b/' {path}"),
                format!("perl -pi -e 's/a/b/' {path}"),
            ] {
                denied(&command);
            }
        }
    }

    #[test]
    fn spellings_of_the_home_directory_all_resolve() {
        for command in [
            "echo x >> $HOME/.zshrc",
            "echo x >> ${HOME}/.zshrc",
            "echo x >> \"$HOME/.zshrc\"",
            "echo x >> \"${HOME}\"/.zshrc",
            "echo x >> ~root/.ssh/authorized_keys",
            "echo x >> ~bob/.zshrc",
            "echo x >> /home/bob/.zshrc",
            "echo x >> /Users/bob/.zshrc",
            "echo x >> /root/.ssh/authorized_keys",
            "echo x >> /var/root/.zshrc",
            "echo x >> /home/*/.ssh/authorized_keys",
            "echo x >> $ZDOTDIR/.zshrc",
            "echo x >> $GNUPGHOME/gpg.conf",
            "echo x >> $XDG_CONFIG_HOME/gh/hosts.yml",
            "echo x >> $KUBECONFIG",
            "echo x >> \"$DOCKER_CONFIG/config.json\"",
            "echo x >> /private/etc/sudoers.d/x",
            "echo x >> ~//.zshrc",
            "echo x >> ~/./.zshrc",
            "echo x >> ~/.ssh/../.zshrc",
            "echo x >> ~/projects/../.zshrc",
        ] {
            denied(command);
        }
    }

    #[test]
    fn quote_and_escape_obfuscation_resolves_to_the_real_file() {
        for command in [
            "echo x >> ~/.zsh\"rc\"",
            "echo x >> ~/'.zshrc'",
            "echo x >> ~/.zshr\\c",
            "echo x >> ~/\".ssh\"/authorized_keys",
            "echo x >> $'/etc/passwd'",
            "echo x | t''ee ~/.zshrc",
            "echo x | \\tee ~/.zshrc",
            "echo x | /usr/bin/tee ~/.zshrc",
            "echo x | \"tee\" ~/.zshrc",
            "echo x >> ~/.zshrc # comment",
            "echo x>>~/.zshrc",
            "echo x 2>>~/.zshrc",
            "echo x &>> ~/.zshrc",
            "echo x &> ~/.zshrc",
            "echo x >& ~/.zshrc",
            "echo x {fd}> ~/.zshrc",
            "> ~/.zshrc",
            ">~/.zshrc echo x",
        ] {
            denied(command);
        }
    }

    #[test]
    fn expansions_that_can_reach_a_protected_path_fail_closed() {
        for command in [
            "echo x >> ~/.zshr{c..c}",
            "echo x >> ~/.zshrc{,}",
            "echo x >> ~/{.zshrc,absent}",
            "echo x >> ~/.zshr(c|d)",
            "echo x >> ~/.z*",
            "echo x >> ~/.ssh/id_*",
            "echo x >> ~/.ssh/id_{rsa,ed25519}",
            "echo x >> ~/.ssh/*",
            "echo x >> ~/.$X",
            "echo x >> ~/.ssh/$(echo config)",
            "echo x >> /etc/sudoers.d/{a,b}",
            "echo x >> /etc/{passwd,x}",
            "cp key ~/.ssh/id_{rsa,ed25519}",
            "cp key ~/.ss?/id_rsa",
            "echo x >> ~/../../etc/passwd",
        ] {
            denied(command);
        }
    }

    #[test]
    fn expansions_that_cannot_reach_a_protected_path_are_ignored() {
        for command in [
            "echo x >> ~/notes-{a,b}.txt",
            "echo x >> ~/projects/{a,b}/out.log",
            "echo x >> ~/logs/*.log",
            "echo x >> ~/projects/$NAME/out",
            "cp *.png ~/",
            "cp ~/Downloads/*.png ~/Pictures/",
            "cp -r ./build ~/",
            "echo x > \"~/.zshrc\"",
            "echo x >> '$HOME/.zshrc'",
            "echo x >> $OUT/.zshrc",
            "echo x >> $XDG_CONFIG_HOME/nvim/init.lua",
            "echo x >> $(mktemp)",
        ] {
            allowed(command);
        }
    }

    #[test]
    fn reads_permissions_and_neighbours_stay_allowed() {
        for command in [
            "cat ~/.ssh/config",
            "cat ~/.zshrc ~/.bashrc",
            "grep -rn Host ~/.ssh/",
            "diff ~/.zshrc /tmp/x",
            "source ~/.zshrc",
            "ssh -F ~/.ssh/config host",
            "ssh -i ~/.ssh/id_ed25519 host",
            "chmod 600 ~/.ssh/authorized_keys",
            "chmod 700 ~/.ssh",
            "chown bob ~/.zshrc",
            "ls -la ~/.ssh",
            "cp ~/.ssh/config /tmp/backup",
            "cp ~/.zshrc ~/.zshrc.bak",
            "mv ~/.zshrc.new ~/zshrc.old",
            "echo x >> ~/.ssh/known_hosts",
            "echo x | tee -a ~/.ssh/known_hosts",
            "ssh-keyscan host >> ~/.ssh/known_hosts",
            "echo x > ~/.ssh/id_ed25519.pub",
            "cat key.pub >> ~/.ssh/id_ed25519.pub",
            "echo x > ~/.config/nvim/init.lua",
            "echo x >> ~/.claude/notes.md",
            "echo x > ~/.zshrc.local",
            "echo x > ~/.zshrc.bak",
            "echo x > ~/.aws/sso/cache/x.json",
            "echo x > ~/.config/gh/config.yml",
            "echo x > /etc/hosts",
            "echo x > /etc/sudoers.tmp",
            // `/tmp/.zshrc` stays: an absolute path outside a home directory
            // is a different file. The relative spellings that used to sit
            // here — `.zshrc`, `./.ssh/authorized_keys`, `.ssh/authorized_keys`
            // — pinned the limitation #407 reported rather than a decision,
            // and they now deny; see `relative_anchors` below.
            "echo x > /tmp/.zshrc",
            "install -d -m 700 ~/.ssh",
            "mkdir -p ~/.ssh",
            "touch ~/.ssh/authorized_keys",
            "sed 's/a/b/' ~/.zshrc",
            "sed -n '/PATH/p' ~/.zshrc",
            "sed -i 's/a/b/' ~/notes.txt",
            "sed -e 's/a/b/' -i ~/notes.txt",
            "perl -ne 'print' ~/.zshrc",
            "perl -pi -e 's/a/b/' ~/notes.txt",
            "dd if=~/.ssh/id_ed25519 of=/tmp/backup",
            "tee /tmp/out < ~/.zshrc",
            "cat < ~/.zshrc > /tmp/copy",
            "echo ~/.zshrc",
            "echo 'echo x >> ~/.zshrc'",
            "git commit -m \"tee ~/.zshrc\"",
            "echo x 2>&1 >/dev/null",
            "ln -s ~/.zshrc /tmp/zshrc-link",
            "ln -s /tmp/x",
            "cp x",
            "tee",
            "echo x | tee",
            "command -v tee",
        ] {
            allowed(command);
        }
    }

    #[test]
    fn known_hosts_may_be_appended_but_not_replaced() {
        allowed("echo x >> ~/.ssh/known_hosts");
        allowed("echo x | tee -a ~/.ssh/known_hosts");
        allowed("echo x | sponge -a ~/.ssh/known_hosts");
        allowed("dd if=/tmp/k of=~/.ssh/known_hosts oflag=append conv=notrunc");
        denied("echo x > ~/.ssh/known_hosts");
        denied("echo x | tee ~/.ssh/known_hosts");
        denied("cp /tmp/kh ~/.ssh/known_hosts");
        denied("mv /tmp/kh ~/.ssh/known_hosts");
        denied("sed -i '/host/d' ~/.ssh/known_hosts");
        denied("dd if=/tmp/k of=~/.ssh/known_hosts");
        // The append exception is only for the literal file.
        denied("echo x >> ~/.ssh/known_host{s,}");
        denied("echo x >> ~/.ssh/known_hosts/x");
    }

    #[test]
    fn placement_into_protected_and_parent_directories() {
        // Anything into `.ssh`, `.gnupg`, or an rc.d directory.
        denied("cp id_rsa ~/.ssh/");
        denied("cp id_rsa ~/.ssh");
        denied("cp -t ~/.ssh id_rsa");
        denied("cp --target-directory=~/.ssh id_rsa");
        denied("install -m 600 -t ~/.ssh id_rsa");
        denied("mv key ~/.gnupg/");
        denied("cp path.sh ~/.bashrc.d/");
        denied("sudo cp agent /etc/sudoers.d/");
        denied("sudo install -m 440 agent /etc/sudoers.d");
        denied("sudo cp sshd_config /etc/ssh/");
        // A parent directory judges the resulting basename.
        denied("cp credentials ~/.aws/");
        denied("cp credentials ~/.aws");
        denied("cp hosts.yml ~/.config/gh/");
        denied("cp config.json ~/.docker/");
        denied("cp zshrc ~/.zshrc");
        denied("cp .zshrc ~/");
        denied("cp .zshrc ~");
        denied("cp .zshrc $HOME/");
        denied("cp dotfiles/.zshrc dotfiles/.bashrc ~/");
        denied("cp -r dotfiles/. ~/");
        denied("cp -r dotfiles/.. ~/");
        denied("cp .* ~/");
        denied("cp * ~/");
        denied("cp -r .config ~/");
        denied("cp -r .ssh ~/");
        denied("cp -r gh ~/.config/");
        denied("cp -r .aws ~/");
        allowed("cp report.txt ~/");
        allowed("cp report.txt ~/.aws/");
        allowed("cp *.png ~/");
        allowed("cp notes-* ~/.config/gh/");
        allowed("cp -r myapp ~/.config/");
        allowed("cp -r build ~/Documents/");
        allowed("cp a b ~/Documents/");
        allowed("mv ~/Documents/a ~/Documents/b");
        // `-T` names a file even with a trailing slash elsewhere.
        denied("cp -T x ~/.zshrc");
        allowed("cp -T x ~/zshrc");
    }

    #[test]
    fn wrappers_and_shell_prefixes_are_transparent() {
        for command in [
            "sudo tee /etc/sudoers.d/x",
            "sudo -u root tee -a /etc/sudoers.d/x",
            "sudo --user=root -E tee /etc/sudoers",
            "sudo -- tee /etc/passwd",
            "doas tee /etc/sudoers",
            "env FOO=1 tee ~/.zshrc",
            "env -i PATH=/bin tee ~/.zshrc",
            "command tee ~/.zshrc",
            "nohup tee ~/.zshrc",
            "nice -n 10 tee ~/.zshrc",
            "timeout 10 tee ~/.zshrc",
            "timeout -s KILL 10 tee ~/.zshrc",
            "stdbuf -oL tee ~/.zshrc",
            "FOO=bar tee ~/.zshrc",
            "if true; then tee ~/.zshrc; fi",
            "for f in a b; do cp $f ~/.ssh/; done",
            "true && echo x >> ~/.zshrc",
            "true; echo x >> ~/.zshrc",
            "(echo x >> ~/.zshrc)",
            "{ echo x >> ~/.zshrc; }",
            "echo x | tee ~/.zshrc | cat",
            "echo x | sudo -n tee -a /etc/passwd > /dev/null",
        ] {
            denied(command);
        }
        allowed("env -S 'tee ~/.zshrc'");
        allowed("command -v tee ~/.zshrc");
    }

    #[test]
    fn double_dash_separators_are_honoured() {
        denied("tee -- ~/.zshrc");
        denied("cp -- src ~/.zshrc");
        denied("install -- src ~/.zshrc");
        denied("sed -i -- 's/a/b/' ~/.zshrc");
        denied("mv -- src ~/.ssh/config");
        // After `--`, a dash-word is an operand, not an append flag.
        denied("tee -- -a ~/.zshrc");
    }

    #[test]
    fn multiple_targets_are_all_judged() {
        denied("echo x > /tmp/ok > ~/.zshrc");
        denied("echo x | tee /tmp/ok ~/.zshrc");
        denied("echo x | tee /tmp/a /tmp/b /etc/passwd");
        denied("sed -i 's/a/b/' /tmp/a ~/.zshrc");
        denied("cp a b c ~/.ssh/");
    }

    #[test]
    fn hit_span_and_reason_name_the_target() {
        let hit = denied("echo x | tee -a ~/.zshrc");
        assert_eq!(&"echo x | tee -a ~/.zshrc"[hit.span.clone()], "~/.zshrc");
        assert!(
            hit.reason.contains("`tee -a` appends to ~/.zshrc"),
            "{}",
            hit.reason
        );
        assert!(hit.reason.contains("every new zsh shell"), "{}", hit.reason);
        assert!(hit.reason.contains("dcg allow-once"), "{}", hit.reason);

        let hit = denied("sudo cp agent /etc/sudoers.d/agent");
        assert!(
            hit.reason.contains("/etc/sudoers.d/agent"),
            "{}",
            hit.reason
        );
        assert!(hit.reason.contains("become root"), "{}", hit.reason);

        let hit = denied("echo x >> ~/.zshr{c..c}");
        assert!(hit.reason.contains("~/.zshr{c..c}"), "{}", hit.reason);
        assert!(hit.reason.contains("can name ~/.zshrc"), "{}", hit.reason);

        let hit = denied("echo x > ~/.ssh/known_hosts");
        assert!(hit.reason.contains("appending"), "{}", hit.reason);

        let hit = denied("cp .zshrc ~/");
        assert_eq!(&"cp .zshrc ~/"[hit.span.clone()], ".zshrc");
    }

    #[test]
    fn other_dialects_are_never_classified() {
        for dialect in [ShellDialect::PowerShell, ShellDialect::Cmd] {
            assert!(
                classify_credential_file_write("echo x >> ~/.zshrc", dialect).is_none(),
                "{dialect:?}"
            );
        }
        assert!(
            classify_credential_file_write("echo x >> ~/.zshrc", ShellDialect::Unknown).is_some()
        );
    }

    #[test]
    fn decoder_marks_quoted_and_bare_characters() {
        let (word, end) = read_word("~/.zsh\"rc\"{,} x", 0);
        assert_eq!(end, 13);
        assert_eq!(word.as_string(), "~/.zshrc{,}");
        // `,` is on the literal whitelist; the `{` before it already ends the
        // literal prefix, which is all the path walk needs.
        assert_eq!(
            word.literal,
            vec![
                false, true, true, true, true, true, true, true, false, true, false
            ]
        );
        let (word, _) = read_word("of=~/.ssh/x", 0);
        assert!(!word.literal[3], "tilde after `=` expands");
        let (word, _) = read_word("\"$HOME/x y\"", 0);
        assert_eq!(word.as_string(), "$HOME/x y");
        assert!(!word.literal[0]);
        assert!(word.literal[5]);
        let (word, _) = read_word("'~/x'", 0);
        assert!(word.literal[0]);
        let (word, _) = read_word("a(b", 0);
        assert_eq!(word.as_string(), "a");
        assert!(word.glued_paren);
        let (word, _) = read_word("$'/etc/pass\\'wd'", 0);
        assert_eq!(word.as_string(), "/etc/pass'wd");
        assert!(word.is_all_literal());
    }

    #[test]
    fn glob_matching_is_conservative_but_bounded() {
        let star = vec![PatternChar::Star];
        assert!(glob_matches(&star, &".zshrc".chars().collect::<Vec<_>>()));
        let png = vec![
            PatternChar::Star,
            PatternChar::Literal('.'),
            PatternChar::Literal('p'),
            PatternChar::Literal('n'),
            PatternChar::Literal('g'),
        ];
        assert!(!glob_matches(&png, &".zshrc".chars().collect::<Vec<_>>()));
        let dot_star = vec![PatternChar::Literal('.'), PatternChar::Star];
        assert!(glob_matches(
            &dot_star,
            &".zshrc".chars().collect::<Vec<_>>()
        ));
        assert!(!glob_matches(
            &dot_star,
            &"_netrc".chars().collect::<Vec<_>>()
        ));
        let question = vec![
            PatternChar::Any,
            PatternChar::Literal('n'),
            PatternChar::Star,
        ];
        assert!(glob_matches(
            &question,
            &"_netrc".chars().collect::<Vec<_>>()
        ));
    }

    /// #407: a relative spelling names the same credential file the rooted one
    /// does, and only the rooted one was being judged.
    mod relative_anchors {
        use super::{allowed, denied, hit};
        use crate::packs::core::credential_files::{
            ENTRIES, RELATIVE_ANCHORS, RELATIVE_FILE_ANCHORS, Root,
        };

        /// Rooted/relative pairs that must reach the same verdict.
        const PAIRS: &[&str] = &[
            ".ssh/authorized_keys",
            ".ssh/config",
            ".ssh/id_rsa",
            ".ssh/id_ed25519",
            ".ssh/rc",
            ".aws/credentials",
            ".aws/config",
            ".docker/config.json",
            ".kube/config",
            ".gnupg/trustdb.gpg",
            ".gnupg/private-keys-v1.d/key.key",
            ".bashrc.d/10-path.sh",
            ".zshrc.d/aliases.zsh",
        ];

        #[test]
        fn every_anchored_relative_path_is_denied_for_every_writer() {
            for path in PAIRS {
                for command in [
                    format!("echo x > {path}"),
                    format!("printf x >| {path}"),
                    format!("echo x | tee {path}"),
                    format!("cp ./src {path}"),
                    format!("mv ./src {path}"),
                    format!("install -m 600 ./src {path}"),
                    format!("ln -sf /tmp/evil {path}"),
                    format!("dd if=/tmp/x of={path}"),
                    format!("sed -i 's/a/b/' {path}"),
                    format!("perl -pi -e 's/a/b/' {path}"),
                ] {
                    denied(&command);
                }
            }
        }

        #[test]
        fn the_relative_and_rooted_spellings_agree() {
            for path in PAIRS {
                for writer in ["echo x > ", "echo x | tee ", "cp ./src "] {
                    let relative = hit(&format!("{writer}{path}")).is_some();
                    let rooted = hit(&format!("{writer}~/{path}")).is_some();
                    assert_eq!(
                        relative, rooted,
                        "`{writer}{path}` and `{writer}~/{path}` name the same file"
                    );
                }
            }
        }

        #[test]
        fn a_path_through_an_anchor_is_anchored_wherever_it_starts() {
            // These two moved out of `reads_permissions_and_neighbours_stay_allowed`,
            // where they recorded the gap this module closes.
            denied("echo x > ./.ssh/authorized_keys");
            denied("echo x > .ssh/authorized_keys");
            denied("cp ./src dotfiles/.ssh/config");
            denied("cp ./src ../.ssh/authorized_keys");
            denied("cp ./src ./.ssh/id_rsa");
            // `..` after the anchor is resolved against it, so this still lands
            // on a protected login file rather than escaping the check.
            denied("cp ./src .ssh/../.bashrc");
        }

        #[test]
        fn the_reason_names_the_path_the_way_the_command_did() {
            let relative = denied("echo x > .ssh/authorized_keys").reason;
            assert!(
                relative.contains(".ssh/authorized_keys"),
                "reason should name the file: {relative}"
            );
            assert!(
                !relative.contains("~/.ssh/authorized_keys"),
                "a relative spelling is not `~/…` unless the shell is standing there: {relative}"
            );
            assert!(
                !denied("echo x > .zshrc").reason.contains("~/.zshrc"),
                "the same applies to an anchored login-startup file"
            );
            // The rooted spelling still shows its root.
            assert!(
                denied("echo x > ~/.ssh/authorized_keys")
                    .reason
                    .contains("~/.ssh/authorized_keys")
            );
        }

        #[test]
        fn the_rooted_carve_outs_survive_the_relative_spelling() {
            // Public keys are public, and appending a host key is what ssh does.
            allowed("cp ./src .ssh/id_rsa.pub");
            allowed("echo host >> .ssh/known_hosts");
            assert!(
                hit("echo host >> ~/.ssh/known_hosts").is_none(),
                "the rooted append carve-out is the one being mirrored"
            );
        }

        #[test]
        fn an_escaped_anchor_is_still_an_anchor() {
            // `.ss\h` is `.ssh` to the shell. The raw-text pre-gate cannot see
            // that, which is why it also admits any command containing `\`.
            denied("cp ./src .ss\\h/authorized_keys");
            denied("cp ./src .s\\sh/authorized_keys");
            denied("cp ./src '.ssh'/authorized_keys");
        }

        #[test]
        fn an_assembled_relative_anchor_is_a_known_limit() {
            // NOT a desired behaviour: pinned so that closing it is a
            // deliberate change rather than an accident. The component is not
            // literal and no root is established yet, so there is nothing to
            // run the partial check against. The rooted spelling, which does
            // have a root, still denies — that is the invariant that matters.
            assert!(
                hit("cp ./src .ss${E}h/authorized_keys").is_none(),
                "if this now denies, delete this test and record the improvement"
            );
            denied("cp ./src ~/.ss${E}h/authorized_keys");
        }

        #[test]
        fn unanchored_relative_paths_are_untouched() {
            for command in [
                "echo x > notes.txt",
                "echo x > .npmrc",
                "echo x > .netrc",
                "cp ./src .sshd/config",
                "cp ./src assh/config",
                "cp ./src .sshfoo/key",
                "cp ./src project/.aws-config",
                // No separator: a plain file called `.ssh` is not the store.
                "cp ./src .ssh",
            ] {
                allowed(command);
            }
        }

        #[test]
        fn a_login_startup_file_anchors_as_the_whole_path() {
            for name in [
                ".bashrc",
                ".bash_profile",
                ".bash_login",
                ".profile",
                ".zshrc",
                ".zshenv",
                ".zprofile",
                ".zlogin",
            ] {
                denied(&format!("echo x > {name}"));
                denied(&format!("echo x > ./{name}"));
                denied(&format!("cp ./src {name}"));
                denied(&format!("sed -i 's/a/b/' {name}"));
            }
        }

        #[test]
        fn a_login_startup_file_under_a_directory_is_not_anchored() {
            // A skeleton being assembled, not the shell's own startup file.
            for command in [
                "echo x > templates/.bashrc",
                "cp ./src skel/.zshrc",
                "echo x > ../.bashrc",
                "echo x > .bashrc.bak",
                "echo x > my.profile",
            ] {
                allowed(command);
            }
        }

        #[test]
        fn credential_dotfiles_stay_relative_writable() {
            // Writing a project-local one of these is a routine CI idiom, and
            // the rooted spelling still denies. Listed so the exclusion is a
            // decision on the record rather than an oversight.
            for name in [".npmrc", ".netrc", ".pypirc", ".git-credentials"] {
                allowed(&format!("echo x > {name}"));
                denied(&format!("echo x > ~/{name}"));
            }
        }

        /// On APFS and NTFS — the defaults on macOS and Windows — `~/.SSH/id_rsa`
        /// opens `~/.ssh/id_rsa`. A case-sensitive comparison read that as a
        /// different path and let every non-redirect writer through.
        mod case_folding {
            use super::super::{allowed, denied};

            #[test]
            fn an_upper_case_spelling_is_the_same_file() {
                for command in [
                    "tee ~/.SSH/id_rsa",
                    "cp evil ~/.SSH/id_rsa",
                    "sed -i 's/a/b/' ~/.SSH/config",
                    "echo x > ~/.AWS/credentials",
                    "echo x > ~/.Kube/config",
                    "echo x > ~/.BASHRC",
                    "echo x > ~/.NETRC",
                    "echo x > /ETC/passwd",
                    "echo x > /Etc/sudoers",
                    // The relative anchors fold too.
                    "tee .SSH/authorized_keys",
                    "cp evil .Aws/credentials",
                    "echo x > .BASHRC",
                ] {
                    denied(command);
                }
            }

            #[test]
            fn the_carve_outs_fold_with_it() {
                // Same decision the lower-case spelling gets, not a stricter one.
                allowed("echo h >> ~/.ssh/KNOWN_HOSTS");
                allowed("cp k ~/.SSH/id_rsa.PUB");
                allowed("cp k .SSH/id_rsa.pub");
            }

            #[test]
            fn folding_does_not_swallow_neighbouring_names() {
                for command in [
                    "cp ./src .SSHD/config",
                    "cp ./src ASSH/config",
                    "echo x > ~/.ZSHRC.bak",
                    "echo x > MY.PROFILE",
                ] {
                    allowed(command);
                }
            }
        }

        /// An anchor decides the path wherever it sits, so the same file gets
        /// the same verdict however the command reached it.
        mod anchors_apply_under_any_root {
            use super::super::{allowed, denied, hit};

            #[test]
            fn a_nested_path_is_anchored_under_every_root() {
                // Before this, the relative spelling denied and the rooted ones
                // did not — the anchors were consulted only on the relative
                // branch, which made the fix stricter than the rule it mirrored.
                for target in [
                    "projects/app/.ssh/id_rsa",
                    "~/projects/app/.ssh/id_rsa",
                    "$HOME/projects/app/.ssh/id_rsa",
                    "/Users/someone/projects/app/.ssh/id_rsa",
                    "/home/someone/projects/app/.ssh/id_rsa",
                    "~/dotfiles/.aws/credentials",
                    "$HOME/dotfiles/.gnupg/secring.gpg",
                ] {
                    denied(&format!("tee {target}"));
                }
            }

            #[test]
            fn a_root_the_classifier_does_not_model_still_anchors() {
                // `rooted_prefix` declines these, and the anchor decides them
                // rather than the word being dropped unjudged.
                for target in [
                    "$PWD/.ssh/id_rsa",
                    "${PWD}/.ssh/id_rsa",
                    "$FOO/.ssh/id_rsa",
                    "/opt/.ssh/id_rsa",
                    "/var/lib/.ssh/id_rsa",
                ] {
                    denied(&format!("tee {target}"));
                }
            }

            #[test]
            fn rebasing_only_widens_and_keeps_the_carve_outs() {
                // It runs only when the whole spelling named nothing, so a
                // protected path cannot be rebased into a weaker verdict.
                allowed("cp k ~/projects/app/.ssh/id_rsa.pub");
                allowed("echo h >> ~/projects/app/.ssh/known_hosts");
                allowed("tee ~/projects/app/notes.txt");
            }

            #[test]
            fn a_rebased_reason_names_the_path_as_written() {
                let reason = hit("tee ~/projects/app/.ssh/id_rsa")
                    .expect("nested ssh key is protected")
                    .reason;
                assert!(
                    reason.contains("~/projects/app/.ssh/id_rsa"),
                    "a rebased hit should name the path the command used: {reason}"
                );
            }
        }

        #[test]
        fn every_anchor_names_a_real_home_entry() {
            for anchor in RELATIVE_ANCHORS.iter().chain(RELATIVE_FILE_ANCHORS) {
                assert!(
                    ENTRIES.iter().any(|entry| {
                        entry.root == Root::Home && entry.comps.first() == Some(anchor)
                    }),
                    "anchor {anchor:?} matches no Root::Home entry, so it can never deny anything"
                );
            }
        }
    }
}
