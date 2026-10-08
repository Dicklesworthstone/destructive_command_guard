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
//! PowerShell and Cmd payloads are read by [`windows_shells`], which decodes
//! their words into the same [`Word`] model so every path decision below is
//! shared rather than re-implemented per dialect (#477).

use crate::normalize::{ShellDialect, is_env_assignment};
use crate::packs::PatternSuggestion;
use std::ops::Range;

mod windows_shells;

/// Rule name under `core.filesystem`. The pattern entry in
/// `filesystem::create_destructive_patterns` carries the static reason shown
/// by `dcg rules` and the generated docs; every evaluator hit carries its own
/// reason naming the writer and the file.
pub(crate) const CREDENTIAL_FILE_WRITE_NAME: &str = "credential-file-write";

/// Rule name for a write into a `.git` directory (#457).
///
/// Separate from [`CREDENTIAL_FILE_WRITE_NAME`] on purpose, and the reason is
/// allowlists rather than wording. Allowlists key on the rule name, so a
/// project that legitimately rewrites `.git/config` would otherwise have to
/// allow `credential-file-write` — and that one entry would also permit a
/// write to `~/.ssh/authorized_keys`. Repository state and private keys are
/// not the same grant and must not share a name.
pub(crate) const GIT_INTERNALS_WRITE_NAME: &str = "git-internals-write";

const GIT_REDIRECT_TRUNCATE_NAME: &str = "redirect-truncate-git-internals-relative";
const GIT_REDIRECT_APPEND_NAME: &str = "redirect-append-git-internals-relative";

/// The single path component that anchors [`GIT_INTERNALS_WRITE_NAME`].
const GIT_ANCHOR: &str = ".git";

/// Safer alternatives for a `.git` write, attached to the pack pattern.
///
/// Deliberately not [`CREDENTIAL_FILE_WRITE_SUGGESTIONS`]: `chmod 600` and
/// appending to `known_hosts` are meaningless here, and the useful advice is
/// the porcelain command that does the same job with git's own validation.
pub(crate) const GIT_INTERNALS_WRITE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "git config <key> <value>",
        "Let git edit its own config; it validates the key and picks the right scope",
    ),
    PatternSuggestion::new(
        "git remote set-url origin <url>",
        "Change a remote through porcelain rather than by rewriting .git/config",
    ),
    PatternSuggestion::new(
        "cat .git/config",
        "Read the current content first; reads are never blocked",
    ),
    PatternSuggestion::new(
        "git config --list --show-origin",
        "Show the user which file and key you intend to change, and let them apply it",
    ),
];

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
    /// Which rule denies this write: credentials, non-redirect Git writes,
    /// or the existing Git truncate/append redirect rules. Carried on the hit
    /// rather than assumed by the caller so allowlists stay separable.
    pub(crate) rule: &'static str,
}

/// Which rule a resolved path denies under.
///
/// The `.git` anchor is the one entry in [`ENTRIES`] that is not a credential,
/// key or login-shell file, so it is the one case that answers differently.
/// Keyed on the leading component because every spelling that reaches here has
/// already been rebased onto its anchor.
fn rule_for(comps: &[String]) -> &'static str {
    if comps
        .first()
        .is_some_and(|component| component.eq_ignore_ascii_case(GIT_ANCHOR))
    {
        GIT_INTERNALS_WRITE_NAME
    } else {
        CREDENTIAL_FILE_WRITE_NAME
    }
}

/// Classify one command segment (may contain several simple commands).
///
/// Returns the first write of a protected file, or `None` when the segment
/// contains no such write.
///
/// The payload's dialect decides how it is read, never the host's: `pwsh`
/// runs on Linux and macOS, and a `powershell` tool name resolves to
/// PowerShell wherever dcg runs (#451). Until #477 this returned `None` for
/// PowerShell and Cmd outright, so `echo x >> ~/.ssh/authorized_keys` — the
/// persistence write this rule exists for — was allowed from a PowerShell
/// tool while the same bytes denied from Bash. Declining was protecting the
/// POSIX parser below, not expressing a policy, and declining is the
/// fail-open direction. The unknown dialect reads the segment every way it
/// could be meant, because the caller could not prove which shell runs it.
pub(crate) fn classify_credential_file_write(
    segment: &str,
    dialect: ShellDialect,
) -> Option<CredentialFileWrite> {
    if !may_name_protected_path(segment) {
        return None;
    }
    let posix = || {
        tokenize(segment)
            .split(|token| matches!(token, Token::Separator))
            .find_map(classify_simple_command)
    };
    match dialect {
        ShellDialect::Posix => posix(),
        ShellDialect::PowerShell | ShellDialect::Cmd => windows_shells::classify(segment, dialect),
        ShellDialect::Unknown => posix()
            .or_else(|| windows_shells::classify(segment, ShellDialect::PowerShell))
            .or_else(|| windows_shells::classify(segment, ShellDialect::Cmd)),
    }
}

/// All Git redirect writes, retaining the existing truncate and append rule
/// identities. The declared shell decides whether a backslash separates path
/// components or escapes the following character; an unknown shell retains
/// every concrete reading. Ordinary argument data is never a redirect target.
///
/// Keep this separate from the first credential hit: granting one Git rule
/// must not hide a later credential write or the other Git redirect rule.
pub(crate) fn classify_git_redirect_writes(
    segment: &str,
    dialect: ShellDialect,
) -> Vec<CredentialFileWrite> {
    if !may_name_protected_path(segment) {
        return Vec::new();
    }
    let mut hits: Vec<_> = if matches!(dialect, ShellDialect::Posix | ShellDialect::Unknown) {
        tokenize(segment)
            .iter()
            .filter_map(|token| match token {
                Token::Write { mode, target } => git_redirect_write(target, *mode),
                Token::Word(_) | Token::Separator => None,
            })
            .collect()
    } else {
        Vec::new()
    };
    for view in [ShellDialect::PowerShell, ShellDialect::Cmd] {
        if dialect == view || dialect == ShellDialect::Unknown {
            hits.extend(windows_shells::classify_git_redirect_writes(segment, view));
        }
    }
    let mut seen = std::collections::HashSet::new();
    hits.retain(|hit| seen.insert((hit.rule, hit.span.start, hit.span.end)));
    hits
}

fn is_git_redirect_rule(rule: &str) -> bool {
    matches!(rule, GIT_REDIRECT_TRUNCATE_NAME | GIT_REDIRECT_APPEND_NAME)
}

fn git_redirect_write(target: &Word, mode: WriteMode) -> Option<CredentialFileWrite> {
    resolve_all(target)
        .iter()
        .filter_map(|spelling| judge_file_spelling(target, spelling, Writer::redirect(mode)))
        .find(|hit| is_git_redirect_rule(hit.rule))
}

/// Whether `command` names a PowerShell or Cmd writer this classifier reads.
///
/// The pack's keyword gates know POSIX writers only, so without this an
/// `Add-Content ~/.ssh/authorized_keys` never selected core.filesystem at all
/// and the classifier behind it could not run. Gated on
/// [`may_name_protected_path`] first for the same reason the POSIX writer
/// words are: `copy` and `move` are ordinary words.
pub(crate) fn names_windows_shell_writer(command: &str) -> bool {
    may_name_protected_path(command) && windows_shells::names_writer(command)
}

/// Whether a decoded command word names one of the writers this classifier
/// understands. Used by the pack's candidate gate so an obfuscated argv0
/// (`t''ee`, `\tee`) still selects core.filesystem.
pub(crate) fn is_credential_writer(executable: &str) -> bool {
    writer_kind(executable).is_some()
}

/// Whether one operand names a file in the protected credential and
/// login-startup set (#469).
///
/// `rm /etc/shadow` and `rm ~/.ssh/authorized_keys` were allowed because the
/// `rm` rules all require a recursive flag, while `unlink`, `shred -u` and
/// `truncate -s 0` deny the same targets. The obvious repair — reusing
/// `path_is_root_home`, which the recursive rules use — is measurably wrong:
/// that predicate matches anything under `/home`, `/etc` or `/var`, so it would
/// also deny `rm /home/user/notes.txt`, i.e. the single most common operation
/// an agent performs in its own working tree. A wide net is affordable for
/// `rm -rf` and is not affordable here.
///
/// This table is the narrow predicate that case needs, and it already exists —
/// it is what `credential-file-write` decides on. What was missing was a way to
/// ask it a path-only question. So this is the same `resolve` + [`exact`] pair
/// [`judge_file_target`] uses, with the writer dropped:
///
/// - No [`Writer`], because deletion has no write mode. `append_ok` is a
///   write-mode carve-out (`~/.ssh/known_hosts` may be appended to) and says
///   nothing about deleting the file, so it is deliberately ignored.
/// - [`Exact::Parent`] is not a hit. It means "an ancestor of a protected
///   path", which for a non-recursive delete is either a directory `rm` cannot
///   remove or a bare root.
/// - An unresolved spelling — a `..` climb, or an expansion that stops the
///   literal prefix early — returns `None` rather than the write path's
///   "cannot be verified" denial. A delete rule is the wrong place to spend a
///   false positive on an unprovable path, and the recursive rules still judge
///   the same operand under their own predicate.
///
/// `*.pub` files stay clear through [`ssh_entry`]: they are public key
/// material, so losing one is not credential loss.
///
/// Returns a plain `bool` rather than the matched entry because the caller's
/// denial reason is `&'static str`, as every `rm` rule's is — none of them name
/// the operand, and the reported span already points at it. Returning a display
/// string nothing could print would be a field that exists to look thorough.
pub(crate) fn names_protected_file(operand: &str) -> bool {
    let (word, _) = read_word(operand, 0);
    // A root read through a pattern is unresolved too (see above).
    resolve_all(&word).iter().any(|spelling| {
        !spelling.speculative
            && !spelling.escaped
            && spelling.partial.is_none()
            && matches!(
                exact(spelling.root, &spelling.comps),
                Exact::Protected { .. }
            )
    })
}

/// Whether every protected reading of `operand` is repository state inside a
/// `.git` directory, rather than a credential or login-startup file (#533).
///
/// Uses exactly the spelling filters of [`names_protected_file`]; it does not
/// change WHAT is protected, only lets a caller word its denial correctly. An
/// operand with no protected reading, or with any protected reading outside
/// `.git`, returns `false`, so a mixed or credential target keeps the
/// credential wording.
pub(crate) fn names_protected_git_internal(operand: &str) -> bool {
    let (word, _) = read_word(operand, 0);
    let protected: Vec<Spelling> = resolve_all(&word)
        .into_iter()
        .filter(|spelling| {
            !spelling.speculative
                && !spelling.escaped
                && spelling.partial.is_none()
                && matches!(
                    exact(spelling.root, &spelling.comps),
                    Exact::Protected { .. }
                )
        })
        .collect();
    !protected.is_empty()
        && protected.iter().all(|spelling| {
            spelling
                .comps
                .first()
                .is_some_and(|first| first.eq_ignore_ascii_case(GIT_ANCHOR))
        })
}

/// Cheap lexical superset of every spelling [`resolve`] can turn into a
/// protected root: `~`/`~user`, `$HOME` and the relocation variables, and the
/// absolute `/etc`, `/private/etc`, `/home/<u>`, `/Users/<u>`, `/root`,
/// `/var/root`, `/var/services/homes/<u>`, `/volume<N>/homes/<u>`,
/// `/var|usr|export/home/<u>` trees, and the runtime `$HOME`. The pack's candidate gate uses it so `npm install`,
/// `cargo install`, or a `sed | tee /tmp/out` pipeline never cold-initialise
/// core.filesystem's regex set on this rule's account.
pub(crate) fn may_name_protected_path(command: &str) -> bool {
    // The needles below are raw substrings, and a quote can split one without
    // changing the path the shell opens: `"/home"/luna/.netrc` and
    // `/var/services/'homes'/luna/.netrc` carry neither `/home/` nor
    // `/homes/`, so the classifier never ran and the write was allowed. Look
    // at the text with its quote characters dropped as well. Dropping can only
    // add candidates; the classifier behind this gate decides.
    may_name_protected_path_as_written(command)
        || (command.contains(['\'', '"'])
            && may_name_protected_path_as_written(&command.replace(['\'', '"'], "")))
}

fn may_name_protected_path_as_written(command: &str) -> bool {
    // `\` joins the cheap character check because this gate reads the raw
    // command, before any quote or escape removal: `tee .ss\h/authorized_keys`
    // opens `.ssh/authorized_keys` but contains no anchor to find here. The
    // rooted spellings were already escape-tolerant by accident, since `~` and
    // `$` survive into the raw text; the relative anchors have no such token.
    // A backquote substitution is an expansion like `$(…)` and can spell the
    // root itself: `` `printf /`etc/sudoers ``.
    command.contains(['~', '$', '\\', '`'])
        // `/homes/` is Synology's `/var/services/homes/<u>` and
        // `/volume<N>/homes/<u>`; `/var/home/`, `/usr/home/` and
        // `/export/home/` already contain `/home/` (#502).
        || ["/etc", "/home/", "/homes/", "/Users/", "/root"]
            .iter()
            .chain(RELATIVE_ANCHORS.iter().filter(|anchor| **anchor != GIT_ANCHOR))
            .chain(RELATIVE_FILE_ANCHORS)
            .any(|needle| contains_ascii_case_insensitive(command, needle))
        // The whole directory is also a destination: `tar -C .git` and
        // `7z x -o.git` do not spell a following slash. Keep a component
        // boundary so `.gitignore`, `.github/`, `.gitattributes` and
        // `.gitmodules` still avoid the classifier's hot path.
        || mentions_git_directory(command)
        || mentions_runtime_home(command)
        || rewrites_an_absolute_directory(command)
}

fn mentions_git_directory(command: &str) -> bool {
    let bytes = command.as_bytes();
    bytes
        .windows(GIT_ANCHOR.len())
        .enumerate()
        .any(|(start, candidate)| {
            candidate.eq_ignore_ascii_case(GIT_ANCHOR.as_bytes())
                && bytes.get(start + GIT_ANCHOR.len()).is_none_or(|byte| {
                    byte.is_ascii_whitespace()
                        || matches!(
                            byte,
                            b'/' | b'\'' | b'"' | b';' | b'|' | b'&' | b'(' | b')' | b'<' | b'>'
                        )
                })
        })
}

/// Whether an absolute path in `command` has a glob or brace character in a
/// directory component, which can make it spell a root none of the needles
/// above name: `/e?c/sudoers`, `/{home,tmp}/luna/.netrc`, `/*/luna/.netrc`.
/// A pattern in the last component (`tee /tmp/*.log`) cannot, so the common
/// `sed -i … src/*.rs` shapes stay out of the classifier.
fn rewrites_an_absolute_directory(command: &str) -> bool {
    let bytes = command.as_bytes();
    let mut index = 0usize;
    while let Some(offset) = bytes[index..].iter().position(|byte| *byte == b'/') {
        let slash = index + offset;
        index = slash + 1;
        let starts_word = slash == 0
            || matches!(
                bytes[slash - 1],
                b' ' | b'\t' | b'\n' | b'=' | b'<' | b'>' | b'\'' | b'"' | b'(' | b'`' | b':'
            );
        if !starts_word {
            continue;
        }
        let mut pattern = false;
        for byte in &bytes[slash + 1..] {
            match byte {
                // zsh glob alternation and bash's extglob (`/(etc|x)/…`,
                // `/@(etc)/…`) can spell any component, and the evaluator may
                // hand over the segment cut at the `(` or the `|` in it.
                b'(' => return true,
                b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b')' => break,
                b'*' | b'?' | b'[' | b'{' => pattern = true,
                b'/' if pattern => return true,
                _ => {}
            }
        }
    }
    false
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
    // Not a credential, and the only entry that denies under
    // `git-internals-write`. It sits on the home table because that is where
    // `relative_anchor_start` rebases an anchored spelling to be judged; the
    // reason text names the path the user actually wrote, so a rebased
    // `repo/.git/config` never claims to be `~/.git/config` (#457).
    Entry {
        root: Root::Home,
        comps: &[GIT_ANCHOR],
        dir: true,
        what: "is the repository's own state — config (which carries remotes, \
               `insteadOf` rewrites and credential helpers), hooks that run on \
               ordinary git commands, refs, and the object store",
    },
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
    // The same plaintext-token class as `.netrc`/`.npmrc`/`.pypirc` above,
    // for the other tools an agent host commonly carries.
    Entry {
        root: Root::Home,
        comps: &[".config", "hub"],
        dir: false,
        what: "stores the hub CLI's GitHub OAuth token",
    },
    Entry {
        root: Root::Home,
        comps: &[".pgpass"],
        dir: false,
        what: "stores PostgreSQL passwords",
    },
    Entry {
        root: Root::Home,
        comps: &[".my.cnf"],
        dir: false,
        what: "stores MySQL client passwords",
    },
    Entry {
        root: Root::Home,
        comps: &[".cargo", "credentials.toml"],
        dir: false,
        what: "stores the crates.io publish token",
    },
    Entry {
        root: Root::Home,
        comps: &[".cargo", "credentials"],
        dir: false,
        what: "stores the crates.io publish token",
    },
    Entry {
        root: Root::Home,
        comps: &[".gem", "credentials"],
        dir: false,
        what: "stores the RubyGems publish API key",
    },
    Entry {
        root: Root::Home,
        comps: &[".vault-token"],
        dir: false,
        what: "stores the HashiCorp Vault token",
    },
    Entry {
        root: Root::Home,
        comps: &[".terraform.d", "credentials.tfrc.json"],
        dir: false,
        what: "stores Terraform Cloud API tokens",
    },
    Entry {
        root: Root::Home,
        comps: &[".config", "gcloud", "application_default_credentials.json"],
        dir: false,
        what: "stores Google Cloud application-default credentials",
    },
    Entry {
        root: Root::Home,
        comps: &[".config", "gcloud", "credentials.db"],
        dir: false,
        what: "stores the gcloud CLI's OAuth credentials",
    },
    Entry {
        root: Root::Home,
        comps: &[".config", "gcloud", "access_tokens.db"],
        dir: false,
        what: "stores the gcloud CLI's access tokens",
    },
    Entry {
        root: Root::Home,
        comps: &[".config", "gcloud", "legacy_credentials"],
        dir: true,
        what: "stores the gcloud CLI's per-account credentials",
    },
    Entry {
        root: Root::Home,
        comps: &[".azure", "accessTokens.json"],
        dir: false,
        what: "stores Azure CLI access tokens",
    },
    Entry {
        root: Root::Home,
        comps: &[".azure", "msal_token_cache.json"],
        dir: false,
        what: "stores Azure CLI access tokens",
    },
    Entry {
        root: Root::Home,
        comps: &[".boto"],
        dir: false,
        what: "stores cloud storage credentials for boto and gsutil",
    },
    Entry {
        root: Root::Home,
        comps: &[".s3cfg"],
        dir: false,
        what: "stores S3 access keys for s3cmd",
    },
    Entry {
        root: Root::Home,
        comps: &[".password-store"],
        dir: true,
        what: "holds the pass password store",
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

    /// The value carried inside an option token (`-o<dir>`,
    /// `--directory=<dir>`), as a word in its own right.
    ///
    /// Splitting is sound because `literal` is per CHARACTER, so the suffix
    /// keeps each character's own provenance — a `~` or `$` in the path stays
    /// non-literal and the resolver still declines to prove it. `prefix_len`
    /// counts characters, and every prefix this is used with is ASCII, so the
    /// byte range narrows by the same amount; the range is only used to point
    /// a reported span at the path rather than the whole token.
    fn value_suffix(&self, prefix_len: usize) -> Option<Self> {
        if self.text.len() <= prefix_len {
            return None;
        }
        Some(Self {
            text: self.text[prefix_len..].to_vec(),
            literal: self.literal[prefix_len..].to_vec(),
            range: (self.range.start + prefix_len)..self.range.end,
            glued_paren: self.glued_paren,
        })
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

/// `$'…'` ANSI-C quoting: the content is literal once its escapes are decoded
/// the way bash decodes them.
///
/// Every escape is decoded, not only the ones that spell punctuation: a
/// numeric escape (`\x2f`, `\057`, `\u002f`) spells any character, and
/// keeping it as the literal text `\x2f` claimed a path the shell never opens,
/// so `echo x >> $'\x2fetc/sudoers'` read as the relative `\x2fetc/sudoers`
/// and was allowed. A decoded NUL ends the string in bash; it and anything
/// this cannot decode are kept but marked non-literal, which makes the
/// resolver treat the rest as unknown rather than as a proven path.
fn read_ansi_c(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    text: &mut Vec<char>,
    literal: &mut Vec<bool>,
) {
    fn digits(
        chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
        radix: u32,
        max: usize,
        mut value: u32,
    ) -> (u32, usize) {
        let mut taken = 0usize;
        while taken < max {
            let Some(digit) = chars.peek().and_then(|(_, ch)| ch.to_digit(radix)) else {
                break;
            };
            value = value.saturating_mul(radix).saturating_add(digit);
            chars.next();
            taken += 1;
        }
        (value, taken)
    }
    let push = |ch: Option<char>, text: &mut Vec<char>, literal: &mut Vec<bool>| match ch {
        Some(ch) if ch != '\0' => {
            text.push(ch);
            literal.push(true);
        }
        _ => {
            text.push('\u{fffd}');
            literal.push(false);
        }
    };
    while let Some((_, inner)) = chars.next() {
        match inner {
            '\'' => break,
            '\\' => match chars.next() {
                Some((_, escaped @ ('\\' | '\'' | '"' | '?'))) => {
                    push(Some(escaped), text, literal);
                }
                Some((_, 'a')) => push(Some('\u{7}'), text, literal),
                Some((_, 'b')) => push(Some('\u{8}'), text, literal),
                Some((_, 'e' | 'E')) => push(Some('\u{1b}'), text, literal),
                Some((_, 'f')) => push(Some('\u{c}'), text, literal),
                Some((_, 'n')) => push(Some('\n'), text, literal),
                Some((_, 'r')) => push(Some('\r'), text, literal),
                Some((_, 't')) => push(Some('\t'), text, literal),
                Some((_, 'v')) => push(Some('\u{b}'), text, literal),
                Some((_, octal @ '0'..='7')) => {
                    let (value, _) = digits(chars, 8, 2, octal.to_digit(8).unwrap_or(0));
                    // bash keeps the low byte of an overlong octal escape.
                    push(char::from_u32(value & 0xff), text, literal);
                }
                Some((_, kind @ ('x' | 'u' | 'U'))) => {
                    let max = match kind {
                        'x' => 2,
                        'u' => 4,
                        _ => 8,
                    };
                    match digits(chars, 16, max, 0) {
                        // `\x` with no digits is kept as written.
                        (_, 0) => {
                            push(Some('\\'), text, literal);
                            push(Some(kind), text, literal);
                        }
                        (value, _) => push(char::from_u32(value), text, literal),
                    }
                }
                Some((_, 'c')) => match chars.next() {
                    // Control characters: `\cA` is 0x01. None is a path
                    // separator, but decode rather than guess.
                    Some((_, control)) if control.is_ascii() => {
                        push(char::from_u32(u32::from(control) & 0x1f), text, literal);
                    }
                    _ => push(None, text, literal),
                },
                // bash keeps an unknown escape as written and zsh drops the
                // backslash. `\/` is a separator either way that matters.
                Some((_, '/')) => push(Some('/'), text, literal),
                Some((_, other)) => {
                    // Which of `\q` and `q` the shell opens depends on the
                    // shell, so the spelling is not proven from here on.
                    text.push('\\');
                    literal.push(false);
                    push(Some(other), text, literal);
                }
                None => push(Some('\\'), text, literal),
            },
            other => push(Some(other), text, literal),
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
    // `.git` is here for the same reason the comment above cites it as the
    // precedent: `.git/config` is repository state whether it is reached from
    // a checkout root or from three directories down. It denies under
    // `git-internals-write`, not `credential-file-write`, and unlike its
    // neighbours its cheap gate requires a component boundary after `.git`
    // in `may_name_protected_path` — see the note there (#457).
    GIT_ANCHOR,
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
    /// The root was read from a component the shell rewrites (see
    /// [`RootedPrefix::speculative`]): a path the word can become.
    speculative: bool,
}

/// Char offset just past the first `count` `/`-separated parts, not counting
/// empty and `.` parts — the same parts [`rooted_prefixes`] drops before it
/// counts.
fn skip_parts(text: &[char], count: usize) -> usize {
    let mut index = 0usize;
    let mut skipped = 0usize;
    while skipped < count {
        while text.get(index) == Some(&'/') {
            index += 1;
        }
        if index >= text.len() {
            return text.len();
        }
        let start = index;
        while index < text.len() && text[index] != '/' {
            index += 1;
        }
        if text[start..index] != ['.'] {
            skipped += 1;
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

/// Where a spelling's root is, as [`rooted_prefixes`] reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RootedPrefix {
    root: Root,
    /// Components the root itself stands for (`$XDG_CONFIG_HOME` is `~/.config`).
    comps: Vec<String>,
    /// Char offset in the word where the components after the root begin.
    rest_start: usize,
    /// The root was only read by letting a component the shell rewrites (a
    /// glob, a brace list, an expansion) stand for a root's name, so this is
    /// one of the paths the word can become, not the path it states.
    speculative: bool,
}

/// The roots a spelling can state outright, and where its components begin.
///
/// Empty means the word states no root this classifier models — a relative
/// path, or one rooted somewhere it does not know (`$PWD`, `/opt`). Those are
/// not rejected outright; [`resolve_all`] falls back to an anchor component.
///
/// A literal spelling has at most one reading. A spelling whose root region
/// the shell rewrites has one per root it can become: `/e?c/sudoers` is
/// `/etc/sudoers`, and `/*/luna/.netrc` is both `/home/luna/.netrc` and
/// `/root/luna/.netrc`.
fn rooted_prefixes(word: &Word) -> Vec<RootedPrefix> {
    let text = &word.text;
    let Some(&first) = text.first() else {
        return Vec::new();
    };
    let single = |root: Root, comps: Vec<String>, rest_start: usize| {
        vec![RootedPrefix {
            root,
            comps,
            rest_start,
            speculative: false,
        }]
    };
    if !word.literal[0] && first == '~' {
        // `~`, `~/…`, `~user/…` — all home directories.
        let mut end = 1usize;
        while text.get(end).is_some_and(|ch| *ch != '/') {
            end += 1;
        }
        return single(Root::Home, Vec::new(), end);
    }
    if !word.literal[0] && first == '$' {
        if let Some((name, end)) = parse_variable(word)
            && let Some((_, root, alias)) = VARIABLE_ROOTS
                .iter()
                .find(|(candidate, _, _)| *candidate == name)
        {
            if text.get(end).is_some_and(|ch| *ch != '/') {
                return Vec::new();
            }
            let alias = alias
                .iter()
                .map(|component| (*component).to_string())
                .collect();
            return single(*root, alias, end);
        }
    }
    // Where the path starts from: `/`, an expansion nothing here can read
    // (`$x/etc/sudoers` opens `/etc/sudoers` when `$x` is empty), or the
    // working directory, which only matters to a path that climbs out of it
    // (`../../../etc/sudoers` reaches `/etc` from any directory shallow
    // enough).
    let base = if first == '/' {
        Base::Root
    } else if !word.literal[0] && matches!(first, '$' | '`') {
        Base::Expansion
    } else {
        Base::Cwd
    };
    // The first components of an absolute path are read from the decoded
    // text: the user component of `/home/*/.ssh` may be a glob and still name
    // homes, and a glob, brace list or expansion in a root's own name
    // (`/e?c`, `/{home,tmp}`, `/et${x}c`) is matched as the pattern it is.
    //
    // `.` is dropped before the root is read, because the kernel skips it:
    // `/home/./luna/.netrc` and `/./home/luna/.netrc` open
    // `/home/luna/.netrc`, and reading `.` as the user component (or as an
    // unknown top-level directory) let those spellings through.
    let mut parts = root_parts(word);
    // The word ended at an unquoted `(`: zsh glob alternation (`/(etc|x)/…`)
    // or bash extglob (`/@(etc)/…`) continues the path with a pattern this
    // reader cannot see, so the last component is open-ended.
    if word.glued_paren {
        let open = match (text.last() == Some(&'/'), parts.pop()) {
            (false, Some(RootPart::Literal(last))) => {
                // `@(`, `!(`, `+(`, `*(`, `?(` are extglob operators, not
                // text of the name.
                let stem = last
                    .strip_suffix(['@', '!', '+', '*', '?'])
                    .unwrap_or(&last);
                let mut pattern: Vec<PatternChar> = stem
                    .chars()
                    .map(|ch| PatternChar::Literal(ch.to_ascii_lowercase()))
                    .collect();
                pattern.push(PatternChar::Star);
                pattern
            }
            (false, Some(RootPart::Pattern { mut pattern, .. })) => {
                if pattern.last() != Some(&PatternChar::Star) {
                    pattern.push(PatternChar::Star);
                }
                pattern
            }
            (true, Some(last)) => {
                parts.push(last);
                vec![PatternChar::Star]
            }
            (_, None) => vec![PatternChar::Star],
        };
        parts.push(RootPart::Pattern {
            pattern: open,
            may_vanish: false,
        });
    }
    match base {
        Base::Root => {}
        Base::Cwd => {
            if !parts.iter().any(RootPart::is_climb) {
                return Vec::new();
            }
        }
        Base::Expansion => {
            // A leading expansion may be empty, which leaves the rest
            // absolute. It may just as well be several components, so on its
            // own it is not matched against a root's name: `$OUT/passwd` is
            // not `/etc/passwd` on this reading. Glued to literal text it is
            // matched as the pattern it is: `$(printf /)etc/sudoers` reaches
            // the evaluator with the substitution blanked, as `$(   )etc`.
            if let Some(first_part) = parts.first_mut()
                && first_part.may_vanish()
            {
                *first_part = RootPart::Pattern {
                    pattern: Vec::new(),
                    may_vanish: true,
                };
            }
        }
    }
    let climb = parts.iter().position(RootPart::is_climb);
    // A relative path's leading components name nothing under `/`.
    let readings = if base == Base::Cwd {
        Vec::new()
    } else {
        absolute_roots(&parts[..climb.unwrap_or(parts.len())])
    };
    if !readings.is_empty() {
        return readings
            .into_iter()
            .map(|reading| RootedPrefix {
                root: reading.root,
                comps: Vec::new(),
                rest_start: skip_parts(text, reading.consumed),
                speculative: reading.speculative,
            })
            .collect();
    }
    // A `..` before any root was stated (`/var/../home/luna/.netrc`). Where
    // it lands depends on symlinks — on macOS `/var` is `/private/var`, so
    // lexical `..` is not the kernel's — but if the lexical reading reaches a
    // protected root the write cannot be cleared either. Starting the
    // components at the `..` makes [`resolve_all`] mark it escaped, the same
    // "cannot be verified" answer a climb out of a stated root gets. A `..`
    // that lands nowhere near a root (`/tmp/../tmp/x`) is left alone.
    let Some(climb) = climb else {
        return Vec::new();
    };
    let mut lexical: Vec<RootPart> = Vec::new();
    let mut speculative = false;
    // Where the climb started is not known (an expansion, the working
    // directory, a process's working directory), so neither is where it ends.
    let mut unknown_base = base != Base::Root;
    // A relative path is judged only once it climbs out of the working
    // directory: `x/../etc/sudoers` stays inside it.
    let mut above_base = base != Base::Cwd;
    for part in &parts {
        if !part.is_climb() {
            lexical.push(part.clone());
            continue;
        }
        if let Some(fit) = ends_at_root_symlink(&lexical) {
            // A symlink to `/` is the filesystem root, whose parent is
            // itself: `/proc/self/root/../etc/sudoers` opens `/etc/sudoers`,
            // not `/proc/self/etc/sudoers`.
            lexical.clear();
            speculative |= fit == Fit::Maybe;
        } else if ends_at_process_cwd(&lexical) {
            // `/proc/<pid>/cwd/..` climbs out of a directory nothing here
            // knows, to wherever that lands — possibly `/`.
            lexical.clear();
            unknown_base = true;
            above_base = true;
        } else if lexical.pop().is_none() {
            above_base = true;
        }
    }
    if !above_base {
        return Vec::new();
    }
    absolute_roots(&lexical)
        .into_iter()
        .map(|reading| {
            // From an unknown base the climb may or may not reach `/`, so the
            // reading is one possibility, judged by the file it would name:
            // `../../../etc/sudoers` can be `/etc/sudoers`, while
            // `../etc/config.yml` names nothing protected wherever it lands.
            // A literal tail is judged as that file; anything else stays
            // "cannot be verified".
            let tail: Option<Vec<String>> = lexical[reading.consumed..]
                .iter()
                .map(|part| match part {
                    RootPart::Literal(text) => Some(text.clone()),
                    RootPart::Pattern { .. } => None,
                })
                .collect();
            match tail {
                Some(comps) if unknown_base => RootedPrefix {
                    root: reading.root,
                    comps,
                    rest_start: text.len(),
                    speculative: true,
                },
                _ => RootedPrefix {
                    root: reading.root,
                    comps: Vec::new(),
                    rest_start: skip_parts(text, climb),
                    speculative: unknown_base || speculative || reading.speculative,
                },
            }
        })
        .collect()
}

/// Where a path's first component is looked up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Base {
    Root,
    Expansion,
    Cwd,
}

/// One `/`-separated component of an absolute path, as its root is read.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RootPart {
    /// Text the shell passes through verbatim.
    Literal(String),
    /// A component the shell rewrites first. `pattern` matches every name it
    /// can become (literal characters folded to lower case); `may_vanish`
    /// when it can become nothing at all, which drops it from the path
    /// (`/$x/etc/sudoers` with `$x` empty, `/{,x}/etc/sudoers`).
    Pattern {
        pattern: Vec<PatternChar>,
        may_vanish: bool,
    },
}

/// How a [`RootPart`] compares with a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fit {
    No,
    /// A pattern that can become the name.
    Maybe,
    Yes,
}

impl Fit {
    fn all(fits: impl IntoIterator<Item = Self>) -> Self {
        fits.into_iter()
            .fold(Self::Yes, |acc, fit| match (acc, fit) {
                (Self::No, _) | (_, Self::No) => Self::No,
                (Self::Maybe, _) | (_, Self::Maybe) => Self::Maybe,
                _ => Self::Yes,
            })
    }

    fn any(fits: impl IntoIterator<Item = Self>) -> Self {
        fits.into_iter()
            .fold(Self::No, |acc, fit| match (acc, fit) {
                (Self::Yes, _) | (_, Self::Yes) => Self::Yes,
                (Self::Maybe, _) | (_, Self::Maybe) => Self::Maybe,
                _ => Self::No,
            })
    }
}

impl RootPart {
    fn new(chars: &[char], literal: &[bool]) -> Self {
        if literal.iter().all(|flag| *flag) {
            return Self::Literal(chars.iter().collect());
        }
        let mut pattern: Vec<PatternChar> = Vec::with_capacity(chars.len());
        let mut can_be_empty_text = false;
        let mut index = 0usize;
        while index < chars.len() {
            let next = if literal[index] {
                PatternChar::Literal(chars[index].to_ascii_lowercase())
            } else {
                match chars[index] {
                    '?' => PatternChar::Any,
                    // A bracket expression matches one character; unclosed,
                    // the shell reads `[` literally, which `*` also covers.
                    '[' => match bracket_expression_end(chars, literal, index) {
                        Some(close) => {
                            index = close;
                            PatternChar::Any
                        }
                        None => PatternChar::Star,
                    },
                    // A brace list becomes each of its alternatives, and an
                    // alternative may be empty.
                    '{' => {
                        let mut depth = 0usize;
                        let mut close = index;
                        while close < chars.len() {
                            if !literal[close] {
                                match chars[close] {
                                    '{' => depth += 1,
                                    '}' => {
                                        depth = depth.saturating_sub(1);
                                        if depth == 0 {
                                            break;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            close += 1;
                        }
                        index = close.min(chars.len() - 1);
                        can_be_empty_text = true;
                        PatternChar::Star
                    }
                    '$' | '`' => {
                        can_be_empty_text = true;
                        PatternChar::Star
                    }
                    _ => PatternChar::Star,
                }
            };
            if !(next == PatternChar::Star && pattern.last() == Some(&PatternChar::Star)) {
                pattern.push(next);
            }
            index += 1;
        }
        let may_vanish = can_be_empty_text && pattern == [PatternChar::Star];
        Self::Pattern {
            pattern,
            may_vanish,
        }
    }

    fn is_climb(&self) -> bool {
        matches!(self, Self::Literal(text) if text == "..")
    }

    fn may_vanish(&self) -> bool {
        matches!(
            self,
            Self::Pattern {
                may_vanish: true,
                ..
            }
        )
    }

    /// Case-folded comparison, as APFS and NTFS compare by default.
    fn fits(&self, name: &str) -> Fit {
        match self {
            Self::Literal(text) => {
                if text.eq_ignore_ascii_case(name) {
                    Fit::Yes
                } else {
                    Fit::No
                }
            }
            Self::Pattern { pattern, .. } => {
                let folded: Vec<char> = name.chars().map(|ch| ch.to_ascii_lowercase()).collect();
                if glob_matches(pattern, &folded) {
                    Fit::Maybe
                } else {
                    Fit::No
                }
            }
        }
    }

    /// A literal compared exactly (`/proc` is Linux, and case-sensitive); a
    /// pattern still folded, which only widens what it can match.
    fn fits_exact(&self, name: &str) -> Fit {
        match self {
            Self::Literal(text) if text == name => Fit::Yes,
            Self::Literal(_) => Fit::No,
            Self::Pattern { .. } => self.fits(name),
        }
    }

    /// A literal judged by `accepts`; a pattern by whether it can become any
    /// of `samples`, which stand for every name `accepts` takes.
    fn fits_class(&self, accepts: fn(&str) -> bool, samples: &[&str]) -> Fit {
        match self {
            Self::Literal(text) if accepts(text) => Fit::Yes,
            Self::Literal(_) => Fit::No,
            Self::Pattern { .. } => Fit::any(samples.iter().map(|sample| self.fits(sample))),
        }
    }
}

/// Where the bracket expression opening at `open` closes.
///
/// A `]` right after `[`, `[!` or `[^` is a member, not the close, and a
/// `[:class:]` inside is skipped whole: `/e[]t]c` is `/etc` (bracket `]t`),
/// and taking its first `]` as the close read it as `/e?t…c`, which cannot be
/// `/etc`.
fn bracket_expression_end(chars: &[char], literal: &[bool], open: usize) -> Option<usize> {
    let mut at = open + 1;
    if chars.get(at).is_some_and(|ch| matches!(ch, '!' | '^')) {
        at += 1;
    }
    if chars.get(at) == Some(&']') {
        at += 1;
    }
    while at < chars.len() {
        if chars[at] == '['
            && let Some(kind @ (':' | '.' | '=')) = chars.get(at + 1).copied()
            && let Some(end) = (at + 2..chars.len().saturating_sub(1))
                .find(|&end| chars[end] == kind && chars[end + 1] == ']')
        {
            at = end + 2;
            continue;
        }
        if chars[at] == ']' && !literal[at] {
            return Some(at);
        }
        at += 1;
    }
    None
}

/// The non-empty, non-`.` components of an absolute word — the same parts
/// [`skip_parts`] counts.
fn root_parts(word: &Word) -> Vec<RootPart> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    for index in 0..=word.text.len() {
        if index < word.text.len() && word.text[index] != '/' {
            continue;
        }
        let chars = &word.text[start..index];
        let literal = &word.literal[start..index];
        start = index + 1;
        if chars.is_empty() || chars == ['.'] {
            continue;
        }
        parts.push(RootPart::new(chars, literal));
    }
    parts
}

/// One way to read an absolute path's root: the root, how many parts it
/// spans, and whether a rewritten component had to stand for a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RootReading {
    root: Root,
    consumed: usize,
    speculative: bool,
}

fn add_reading(readings: &mut Vec<RootReading>, reading: RootReading) {
    if let Some(existing) = readings
        .iter_mut()
        .find(|existing| existing.root == reading.root && existing.consumed == reading.consumed)
    {
        existing.speculative &= reading.speculative;
    } else {
        readings.push(reading);
    }
}

/// Every root the leading `parts` (no `.` or `..`) can state.
///
/// Leading components that lead back to `/` are looked through first:
/// `/System/Volumes/Data/Users/<u>` is macOS's firmlinked spelling of
/// `/Users/<u>`, `/.nofollow/…` is macOS's no-symlink view of `/`,
/// `/Volumes/Macintosh HD` is a symlink to `/`, and `/proc/self/root/…` (or
/// `/proc/<pid>/root/…`, `/proc/<pid>/task/<tid>/root/…`) is the filesystem
/// root as a process sees it. All of them open the same file as the plain
/// spelling, and none stated a root this classifier models, so
/// `echo x >> /System/Volumes/Data/Users/luna/.netrc` was allowed.
///
/// Read right to left over positions, so each suffix is read once however
/// many ways a pattern can be taken: a run of `/*/*/*/…` costs one pass, not
/// one per combination.
fn absolute_roots(parts: &[RootPart]) -> Vec<RootReading> {
    let mut from: Vec<Vec<RootReading>> = vec![Vec::new(); parts.len() + 1];
    for at in (0..parts.len()).rev() {
        let rest = &parts[at..];
        let mut here: Vec<RootReading> = Vec::new();
        let mut through: Vec<(usize, Fit)> = root_prefix_aliases(rest);
        if rest[0].may_vanish() {
            through.push((1, Fit::Maybe));
        }
        for (len, fit) in through {
            for reading in &from[at + len] {
                add_reading(
                    &mut here,
                    RootReading {
                        speculative: reading.speculative || fit == Fit::Maybe,
                        ..*reading
                    },
                );
            }
        }
        for (root, len, fit) in stated_roots(rest) {
            add_reading(
                &mut here,
                RootReading {
                    root,
                    consumed: at + len,
                    speculative: fit == Fit::Maybe,
                },
            );
        }
        from[at] = here;
    }
    std::mem::take(&mut from[0])
}

/// Leading components that only re-spell `/` (or, for a process's working
/// directory, may), and how many parts each spans.
fn root_prefix_aliases(parts: &[RootPart]) -> Vec<(usize, Fit)> {
    let fit = |index: usize, name: &str| parts.get(index).map_or(Fit::No, |part| part.fits(name));
    let mut aliases = root_symlinks(parts);
    aliases.push((
        3,
        Fit::all([fit(0, "System"), fit(1, "Volumes"), fit(2, "Data")]),
    ));
    aliases.push((1, fit(0, ".nofollow")));
    // A process's working directory may be `/` (it is for pid 1), so it is
    // looked through too, as a possibility rather than a certainty.
    aliases.extend(
        process_cwds(parts)
            .into_iter()
            .map(|(len, _)| (len, Fit::Maybe)),
    );
    aliases.retain(|(_, fit)| *fit != Fit::No);
    aliases
}

/// Leading components that are a symlink to `/` itself, whose `..` is `/`
/// again: `/proc/<pid>/root`, `/proc/<pid>/task/<tid>/root`, and macOS's
/// `/Volumes/Macintosh HD`.
fn root_symlinks(parts: &[RootPart]) -> Vec<(usize, Fit)> {
    let fit = |index: usize, name: &str| parts.get(index).map_or(Fit::No, |part| part.fits(name));
    let exact = |index: usize, name: &str| {
        parts
            .get(index)
            .map_or(Fit::No, |part| part.fits_exact(name))
    };
    let pid = |index: usize| {
        parts.get(index).map_or(Fit::No, |part| {
            part.fits_class(is_proc_pid, &["self", "thread-self", "1"])
        })
    };
    let tid = |index: usize| {
        parts
            .get(index)
            .map_or(Fit::No, |part| part.fits_class(is_decimal, &["1"]))
    };
    let mut aliases = vec![
        (3, Fit::all([exact(0, "proc"), pid(1), exact(2, "root")])),
        (
            5,
            Fit::all([
                exact(0, "proc"),
                pid(1),
                exact(2, "task"),
                tid(3),
                exact(4, "root"),
            ]),
        ),
        (2, Fit::all([fit(0, "Volumes"), fit(1, "Macintosh HD")])),
    ];
    aliases.retain(|(_, fit)| *fit != Fit::No);
    aliases
}

/// Whether `parts` ends in a [`root_symlinks`] spelling.
fn ends_at_root_symlink(parts: &[RootPart]) -> Option<Fit> {
    (1..=parts.len().min(5)).find_map(|len| {
        root_symlinks(&parts[parts.len() - len..])
            .into_iter()
            .find(|(alias_len, _)| *alias_len == len)
            .map(|(_, fit)| fit)
    })
}

/// `/proc/<pid>/cwd` and `/proc/<pid>/task/<tid>/cwd`: a process's working
/// directory, which this cannot know — `/` for pid 1 on most systems.
fn process_cwds(parts: &[RootPart]) -> Vec<(usize, Fit)> {
    let exact = |index: usize, name: &str| {
        parts
            .get(index)
            .map_or(Fit::No, |part| part.fits_exact(name))
    };
    let pid = |index: usize| {
        parts.get(index).map_or(Fit::No, |part| {
            part.fits_class(is_proc_pid, &["self", "thread-self", "1"])
        })
    };
    let tid = |index: usize| {
        parts
            .get(index)
            .map_or(Fit::No, |part| part.fits_class(is_decimal, &["1"]))
    };
    let mut cwds = vec![
        (3, Fit::all([exact(0, "proc"), pid(1), exact(2, "cwd")])),
        (
            5,
            Fit::all([
                exact(0, "proc"),
                pid(1),
                exact(2, "task"),
                tid(3),
                exact(4, "cwd"),
            ]),
        ),
    ];
    cwds.retain(|(_, fit)| *fit != Fit::No);
    cwds
}

/// Whether `parts` ends in a [`process_cwds`] spelling.
fn ends_at_process_cwd(parts: &[RootPart]) -> bool {
    (1..=parts.len().min(5)).any(|len| {
        process_cwds(&parts[parts.len() - len..])
            .iter()
            .any(|(cwd_len, _)| *cwd_len == len)
    })
}

/// A `/proc/<entry>` naming a process: `self`, `thread-self` or a pid.
fn is_proc_pid(part: &str) -> bool {
    part == "self" || part == "thread-self" || is_decimal(part)
}

fn is_decimal(part: &str) -> bool {
    !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
}

/// The roots stated at the start of `parts` (after any alias of `/`), with
/// how many parts each spans.
fn stated_roots(parts: &[RootPart]) -> Vec<(Root, usize, Fit)> {
    // Case-folded: on a case-insensitive filesystem — APFS and NTFS by
    // default — `/ETC/passwd` opens `/etc/passwd`, so a case-sensitive
    // comparison here reads as a different path and lets the write through.
    // Folding costs a false positive only on a case-sensitive filesystem that
    // has a genuinely distinct `/ETC`.
    let fit = |index: usize, name: &str| parts.get(index).map_or(Fit::No, |part| part.fits(name));
    let user = |index: usize| {
        if parts.len() > index {
            Fit::Yes
        } else {
            Fit::No
        }
    };
    let drive = |index: usize| {
        parts
            .get(index)
            .map_or(Fit::No, |part| part.fits_class(is_drive_letter, &["c"]))
    };
    let volume = parts.first().map_or(Fit::No, |part| {
        part.fits_class(is_synology_volume, &["volume1"])
    });
    let mut roots = vec![
        (
            Root::Home,
            2usize,
            Fit::all([Fit::any([fit(0, "home"), fit(0, "Users")]), user(1)]),
        ),
        (Root::Home, 1, fit(0, "root")),
        (Root::Home, 2, Fit::all([fit(0, "var"), fit(1, "root")])),
        // macOS: `/var` is a symlink to `/private/var`, so root's home is
        // `/private/var/root` as much as `/var/root`.
        (
            Root::Home,
            3,
            Fit::all([fit(0, "private"), fit(1, "var"), fit(2, "root")]),
        ),
        // Synology DSM: `$HOME` is `/var/services/homes/<user>` (#502).
        (
            Root::Home,
            4,
            Fit::all([fit(0, "var"), fit(1, "services"), fit(2, "homes"), user(3)]),
        ),
        // ...which is a symlink to `/volume<N>/homes/<user>`, and DSM numbers
        // volumes past 9, so the digits are not bounded (#502).
        (Root::Home, 3, Fit::all([volume, fit(1, "homes"), user(2)])),
        // `/var/home` (Fedora Atomic, where `/home` is a symlink to it),
        // `/usr/home` (FreeBSD, likewise), `/export/home` (illumos/Solaris
        // and NFS-exported homes).
        (
            Root::Home,
            3,
            Fit::all([
                Fit::any([fit(0, "var"), fit(0, "usr"), fit(0, "export")]),
                fit(1, "home"),
                user(2),
            ]),
        ),
        // A Windows profile, as the POSIX shells that run on or beside
        // Windows mount it: WSL's `/mnt/c/Users/<user>`, Git Bash/MSYS2's
        // `/c/Users/<user>`, Cygwin's `/cygdrive/c/Users/<user>`. The
        // credential files there (`.netrc`/`_netrc`, `.npmrc`,
        // `.git-credentials`) are the ones Windows tools read.
        (
            Root::Home,
            4,
            Fit::all([fit(0, "mnt"), drive(1), fit(2, "Users"), user(3)]),
        ),
        (
            Root::Home,
            3,
            Fit::all([drive(0), fit(1, "Users"), user(2)]),
        ),
        (
            Root::Home,
            4,
            Fit::all([fit(0, "cygdrive"), drive(1), fit(2, "Users"), user(3)]),
        ),
        (Root::Etc, 1, fit(0, "etc")),
        (Root::Etc, 2, Fit::all([fit(0, "private"), fit(1, "etc")])),
    ];
    roots.retain(|(_, _, fit)| *fit != Fit::No);
    // The home this hook's own session runs under, wherever it lives (#502):
    // the one root that is exact rather than enumerated, and the only one that
    // covers a container's `HOME=/app` or a NAS share no list anticipates. The
    // longer of the two prefixes wins and a tie keeps the fixed root, so an
    // odd `$HOME` can only add a root, never shadow one: `HOME=/home` must not
    // turn `/home/luna/.netrc` into `~/luna/.netrc`, while `HOME=/home/luna/w`
    // makes `/home/luna/w/.netrc` the home file it is. A reading that rests on
    // a pattern is only one possibility, so it neither shadows nor is
    // shadowed: every possibility is kept.
    if let Some(home) = runtime_home() {
        let home_fit = if parts.len() >= home.len() {
            Fit::all(
                home.iter()
                    .enumerate()
                    .map(|(index, comp)| fit(index, comp)),
            )
        } else {
            Fit::No
        };
        let literal_fixed = roots
            .iter()
            .filter(|(_, _, fit)| *fit == Fit::Yes)
            .map(|(_, consumed, _)| *consumed)
            .max();
        match (home_fit, literal_fixed) {
            (Fit::No, _) => {}
            (Fit::Yes, Some(consumed)) if home.len() <= consumed => {}
            (Fit::Yes, Some(_)) => {
                roots.retain(|(_, _, fit)| *fit != Fit::Yes);
                roots.push((Root::Home, home.len(), Fit::Yes));
            }
            (fit, _) => roots.push((Root::Home, home.len(), fit)),
        }
    }
    roots
}

/// A single drive letter, as `/mnt/c` and `/c` mount a Windows drive.
fn is_drive_letter(part: &str) -> bool {
    part.len() == 1 && part.bytes().all(|byte| byte.is_ascii_alphabetic())
}

/// `volume<digits>`, the Synology DSM volume mount (`/volume1`, `/volume12`).
fn is_synology_volume(part: &str) -> bool {
    part.len() > "volume".len()
        && part.as_bytes()[.."volume".len()].eq_ignore_ascii_case(b"volume")
        && part.as_bytes()["volume".len()..]
            .iter()
            .all(u8::is_ascii_digit)
}

/// Top-level directories that are never a real person's home even when some
/// account's `$HOME` points at one (`nobody` → `/nonexistent`, daemons →
/// `/var`, `/`). Treating one as a home root would make every write beneath
/// it look like a write into a home directory.
const NON_HOME_TOP_LEVEL: &[&str] = &[
    "bin",
    "boot",
    "dev",
    "etc",
    "lib",
    "lib32",
    "lib64",
    "media",
    "mnt",
    "nonexistent",
    "opt",
    "private",
    "proc",
    "run",
    "sbin",
    "srv",
    "sys",
    "tmp",
    "usr",
    "var",
    "Volumes",
];

/// Normalised components of an absolute `$HOME`, or `None` when it is unset,
/// relative, climbs with `..`, or is not usable as an additional root.
///
/// Rejected besides: a system directory ([`NON_HOME_TOP_LEVEL`]), anything
/// under `/etc` or `/private` (the `Root::Etc` spellings), and a `$HOME`
/// with a component that is itself protected material
/// ([`is_protected_home_component`]). Those last rules are what let
/// [`rooted_prefixes`] prefer a longer `$HOME` without ever losing a
/// protection: a path under `$HOME` could only have been protected by the
/// other reading if one of the components `$HOME` swallows were a home-table
/// entry or an anchor, and none can be.
fn home_components(home: &str) -> Option<Vec<String>> {
    if !home.starts_with('/') {
        return None;
    }
    let mut comps = Vec::new();
    for part in home.split('/') {
        match part {
            "" | "." => {}
            ".." => return None,
            other => comps.push(other.to_string()),
        }
    }
    let first = comps.first()?;
    if ["etc", "private"]
        .iter()
        .any(|system| first.eq_ignore_ascii_case(system))
        || comps.iter().any(|comp| is_protected_home_component(comp))
    {
        return None;
    }
    if comps.len() == 1
        && NON_HOME_TOP_LEVEL
            .iter()
            .any(|system| first.eq_ignore_ascii_case(system))
    {
        return None;
    }
    Some(comps)
}

/// Whether `component` begins protected material under a home: the first
/// component of a home-table entry (`.ssh`, `.netrc`, `.config`, `_netrc`),
/// or a relative directory or file anchor.
fn is_protected_home_component(component: &str) -> bool {
    ENTRIES
        .iter()
        .filter(|entry| entry.root == Root::Home)
        .map(|entry| entry.comps[0])
        .chain(RELATIVE_ANCHORS.iter().copied())
        .chain(RELATIVE_FILE_ANCHORS.iter().copied())
        .any(|protected| component.eq_ignore_ascii_case(protected))
}

/// The hook process's own `$HOME`, read once.
///
/// The hook runs inside the agent's session, so this is the exact home the
/// agent's writes land in — including roots no list anticipates (a NAS share,
/// `HOME=/app` in a container). Unit tests pin it through
/// [`tests::with_runtime_home`] so their answers do not depend on the host.
fn runtime_home() -> Option<Vec<String>> {
    #[cfg(test)]
    if let Some(pinned) = tests::pinned_runtime_home() {
        return pinned.0;
    }
    static HOME: std::sync::OnceLock<Option<Vec<String>>> = std::sync::OnceLock::new();
    HOME.get_or_init(|| {
        crate::config::home_dir()
            .as_deref()
            .and_then(std::path::Path::to_str)
            .and_then(home_components)
    })
    .clone()
}

/// Whether `command` may spell the runtime `$HOME`, for the candidate gate in
/// [`may_name_protected_path`]. Only the last component is looked for, so a
/// doubled separator (`/srv//luna/.netrc`) cannot slip past the gate that the
/// full resolver would have caught.
fn mentions_runtime_home(command: &str) -> bool {
    runtime_home().is_some_and(|home| {
        home.last()
            .is_some_and(|last| contains_ascii_case_insensitive(command, &format!("/{last}")))
    })
}

/// Every spelling `word` can resolve to: one for a literal path, one per root
/// a rewritten root region can become (see [`rooted_prefixes`]), and none
/// when it cannot name a protected location.
fn resolve_all(word: &Word) -> Vec<Spelling> {
    // The root reader keeps one reading per root and length at every
    // position, so a long run of rewritable components (`/*/*/*/…`,
    // `/$x/$x/…`) costs far more than linear time; 5,000 of them held the
    // hook for over a minute. Real paths are nowhere near this deep, so a
    // rewritable spelling past the cap is not read and fails closed.
    if word.text.iter().filter(|ch| **ch == '/').count() > MAX_REWRITTEN_PATH_PARTS
        && !word.is_all_literal()
    {
        return vec![unread_spelling()];
    }
    match slash_brace_alternatives(word, MAX_BRACE_ALTERNATIVES) {
        BraceAlternatives::Words(alternatives) => {
            alternatives.iter().flat_map(resolve_one).collect()
        }
        BraceAlternatives::TooMany => vec![unread_spelling()],
        BraceAlternatives::NoList => resolve_one(word),
    }
}

/// Components a spelling the shell rewrites may have before it is not read.
const MAX_REWRITTEN_PATH_PARTS: usize = 64;

/// Words a slash-spanning brace list is expanded into before it is not read.
const MAX_BRACE_ALTERNATIVES: usize = 64;

/// A spelling too costly to read: the word can become some protected file,
/// which is what an unread one has to be taken to name.
fn unread_spelling() -> Spelling {
    Spelling {
        root: Root::Home,
        comps: Vec::new(),
        partial: Some(String::new()),
        escaped: false,
        rebased_at_anchor: false,
        speculative: true,
    }
}

/// Expand a brace list whose alternatives contain a `/`.
///
/// The root reader works one `/`-separated component at a time, and a brace
/// list that spans a separator is not a component:
/// `tee -a /{tmp/x,etc/sudoers}` read as the parts `{tmp` and `etc`… and was
/// allowed. Such a list is expanded here, into the words the shell hands the
/// program; a list within one component is left to the reader, which matches
/// it as a pattern.
fn slash_brace_alternatives(word: &Word, limit: usize) -> BraceAlternatives {
    slash_brace_alternatives_at(word, limit, 0)
}

fn slash_brace_alternatives_at(word: &Word, limit: usize, depth: usize) -> BraceAlternatives {
    let Some((open, close, commas)) = slash_brace_list(word) else {
        return BraceAlternatives::NoList;
    };
    let mut bounds = vec![open];
    bounds.extend(commas);
    bounds.push(close);
    let mut words: Vec<Word> = Vec::new();
    for pair in bounds.windows(2) {
        let (from, to) = (pair[0] + 1, pair[1]);
        let mut text = word.text[..open].to_vec();
        let mut literal = word.literal[..open].to_vec();
        text.extend_from_slice(&word.text[from..to]);
        literal.extend_from_slice(&word.literal[from..to]);
        text.extend_from_slice(&word.text[close + 1..]);
        literal.extend_from_slice(&word.literal[close + 1..]);
        let alternative = Word {
            text,
            literal,
            range: word.range.clone(),
            glued_paren: word.glued_paren,
        };
        // Each alternative has one list fewer, so this ends; and every list
        // adds at least one word, so nesting deeper than the word cap is too
        // many words before it is expanded (`{{{…{a/,b},c}…,c}` 20,000 deep
        // otherwise recursed 20,000 frames, copying the word at each).
        if depth >= MAX_BRACE_ALTERNATIVES {
            return BraceAlternatives::TooMany;
        }
        match slash_brace_alternatives_at(
            &alternative,
            limit.saturating_sub(words.len()),
            depth + 1,
        ) {
            BraceAlternatives::Words(expanded) => words.extend(expanded),
            BraceAlternatives::TooMany => return BraceAlternatives::TooMany,
            BraceAlternatives::NoList => words.push(alternative),
        }
        if words.len() > limit {
            return BraceAlternatives::TooMany;
        }
    }
    BraceAlternatives::Words(words)
}

/// What [`slash_brace_alternatives`] made of a word.
enum BraceAlternatives {
    /// No brace list spans a `/`.
    NoList,
    /// The words the lists expand into.
    Words(Vec<Word>),
    /// More words than the limit.
    TooMany,
}

/// The first unquoted brace list with a top-level comma whose text contains
/// a `/`: its `{`, its `}`, and its top-level commas.
///
/// One pass: braces are paired with a stack and each comma is charged to the
/// innermost open list, so a word of unclosed or deeply nested braces
/// (`{{{…`, `{,{,{,…`) costs linear time, not a rescan per `{`. A list
/// without a top-level comma is literal to the shell, but lists inside it
/// still expand (`{{a/,b}}`), so they are candidates too.
fn slash_brace_list(word: &Word) -> Option<(usize, usize, Vec<usize>)> {
    let brace = |index: usize, ch: char| !word.literal[index] && word.text[index] == ch;
    let len = word.text.len();
    let mut close_of: Vec<Option<usize>> = vec![None; len];
    let mut comma_owner: Vec<Option<usize>> = vec![None; len];
    let mut has_comma = vec![false; len];
    let mut slashes_before = Vec::with_capacity(len + 1);
    slashes_before.push(0usize);
    let mut open_lists: Vec<usize> = Vec::new();
    for (at, ch) in word.text.iter().enumerate() {
        slashes_before.push(slashes_before[at] + usize::from(*ch == '/'));
        if brace(at, '{') {
            open_lists.push(at);
        } else if brace(at, '}') {
            if let Some(open) = open_lists.pop() {
                close_of[open] = Some(at);
            }
        } else if *ch == ',' {
            // `,` is a bare literal character, so a quoted comma is counted
            // too; that only adds alternatives.
            if let Some(&open) = open_lists.last() {
                comma_owner[at] = Some(open);
                has_comma[open] = true;
            }
        }
    }
    let open = (0..len).find(|&open| {
        close_of[open]
            .is_some_and(|close| has_comma[open] && slashes_before[close] > slashes_before[open])
    })?;
    let close = close_of[open]?;
    // Every `{` inside a closed list was closed before it (stack order), so
    // its top-level commas are exactly the ones charged to it.
    let commas = (open + 1..close)
        .filter(|&at| comma_owner[at] == Some(open))
        .collect();
    Some((open, close, commas))
}

fn resolve_one(word: &Word) -> Vec<Spelling> {
    let prefixes = rooted_prefixes(word);
    let mut spellings: Vec<Spelling> = prefixes
        .iter()
        .filter_map(|prefix| resolve_from(word, Some(prefix)))
        .collect();
    // A reading that rests on a pattern does not rule out the anchor
    // fallback a rootless spelling gets: `/*/x/.ssh/id_rsa` may be read as
    // `/home/x/.ssh/id_rsa`, and must still be read as an `.ssh` path.
    if prefixes.iter().all(|prefix| prefix.speculative)
        && let Some(anchored) = resolve_from(word, None)
    {
        spellings.push(anchored);
    }
    spellings
}

fn resolve_from(word: &Word, prefix: Option<&RootedPrefix>) -> Option<Spelling> {
    let text = &word.text;
    let mut rebased_at_anchor = false;
    let speculative = prefix.is_some_and(|prefix| prefix.speculative);
    let (root, mut comps, rest_start): (Root, Vec<String>, usize) = match prefix {
        Some(prefix) => (prefix.root, prefix.comps.clone(), prefix.rest_start),
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
            // reach here because `rooted_prefixes` declined them, and the `.ssh`
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
        speculative,
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
    Rsync,
    /// `tar -x -C <dir>`, `unzip -d <dir>`, `7z x -o<dir>`, `bsdtar -x -C <dir>`.
    ///
    /// The archive's MEMBERS are unknowable, so the destination directory is
    /// the only thing worth judging — and it is judged exactly where a
    /// `cp`/`rsync` destination already is.
    ArchiveExtract,
    // PowerShell cmdlets and Cmd built-ins (#477). Never produced by
    // [`writer_kind`], which names POSIX executables: `windows_shells` binds
    // their parameters itself and reuses the judges below.
    AddContent,
    SetContent,
    ClearContent,
    OutFile,
    TeeObject,
    NewItem,
    CopyItem,
    MoveItem,
    CmdCopy,
    CmdMove,
    CmdMklink,
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
        "rsync" => Some(WriterKind::Rsync),
        // Extraction writes whatever the archive carries into the destination
        // directory. `tar -xf payload.tar -C ~/.ssh` was allowed while
        // `cp -r payload/ ~/.ssh/` and `rsync -a payload/ ~/.ssh/` denied, so
        // this is a missing route into scope the pack already claims, not a
        // new posture. `tar` also reaches the unrelated `tar --remove-files`
        // rule; `classify_archive_extract` declines anything that is not an
        // extraction with an explicit destination, so the two do not collide.
        "tar" | "bsdtar" | "unzip" | "7z" | "7za" | "7zr" => Some(WriterKind::ArchiveExtract),
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
            (Some(WriterKind::Rsync), _) => "`rsync` writes",
            (Some(WriterKind::ArchiveExtract), _) => "extracting an archive writes into",
            (Some(WriterKind::Dd), WriteMode::Replace) => "`dd` overwrites",
            (Some(WriterKind::Dd), WriteMode::Append) => "`dd oflag=append` appends to",
            (Some(WriterKind::Sed), _) => "`sed -i` rewrites",
            (Some(WriterKind::Perl), _) => "`perl -i` rewrites",
            (Some(WriterKind::AddContent), _) => "`Add-Content` appends to",
            (Some(WriterKind::SetContent), _) => "`Set-Content` rewrites",
            (Some(WriterKind::ClearContent), _) => "`Clear-Content` empties",
            (Some(WriterKind::OutFile), WriteMode::Replace) => "`Out-File` rewrites",
            (Some(WriterKind::OutFile), WriteMode::Append) => "`Out-File -Append` appends to",
            (Some(WriterKind::TeeObject), WriteMode::Replace) => "`Tee-Object` rewrites",
            (Some(WriterKind::TeeObject), WriteMode::Append) => "`Tee-Object -Append` appends to",
            (Some(WriterKind::NewItem), _) => "`New-Item` creates or replaces",
            (Some(WriterKind::CopyItem), _) => "`Copy-Item` writes",
            (Some(WriterKind::MoveItem), _) => "`Move-Item` replaces",
            (Some(WriterKind::CmdCopy), _) => "`copy` writes",
            (Some(WriterKind::CmdMove), _) => "`move` replaces",
            (Some(WriterKind::CmdMklink), _) => "`mklink` creates a link at",
        }
    }
}

const REMEDY: &str = "Reads and chmod/chown are unaffected; show the user the exact change and let them apply it, or grant this one command with `dcg allow-once`.";

/// Build the hit for a resolved protected path, retaining the rule that owns
/// this write mode.
///
/// A *redirect* into `.git/` keeps
/// `redirect-truncate-git-internals-relative` and
/// `redirect-append-git-internals-relative`, which predate this entry, carry
/// their own git-specific guidance, and are what existing allowlists name. The
/// classifier must not rename these hits to `git-internals-write`. They are
/// collected separately by [`classify_git_redirect_writes`], so a first Git
/// redirect cannot hide a later credential write from the credential scan.
/// The semantic path decoder also reaches Windows separators and escaped
/// spellings that the legacy redirect regexes cannot read (#492).
fn protected_hit(
    writer: Writer,
    display: &str,
    what: &str,
    rule: &'static str,
    span: Range<usize>,
) -> CredentialFileWrite {
    let rule = if rule == GIT_INTERNALS_WRITE_NAME && writer.kind.is_none() {
        match writer.mode {
            WriteMode::Replace => GIT_REDIRECT_TRUNCATE_NAME,
            WriteMode::Append => GIT_REDIRECT_APPEND_NAME,
        }
    } else {
        rule
    };
    CredentialFileWrite {
        span,
        reason: format!("{} {display}, which {what}. {REMEDY}", writer.verb()),
        rule,
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
        // An unresolvable spelling is reported under the general rule even when
        // the example happens to be a `.git` path: the match says the
        // destination COULD be protected, and allowing it must not be narrower
        // than what it actually permits.
        rule: CREDENTIAL_FILE_WRITE_NAME,
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
        // Same reasoning as `unprovable_hit`: a `..` climb means the
        // destination was never resolved, so the general rule is the honest one.
        rule: CREDENTIAL_FILE_WRITE_NAME,
    }
}

/// Judge a word that names the file a writer opens.
fn judge_file_target(word: &Word, writer: Writer) -> Option<CredentialFileWrite> {
    resolve_all(word)
        .iter()
        .find_map(|spelling| judge_file_spelling(word, spelling, writer))
}

/// A protected path one reading of `word` names. A reading through a pattern
/// is reported as a spelling that can reach it, not as the path itself.
fn spelled_hit(
    spelling: &Spelling,
    word: &Word,
    writer: Writer,
    display: &str,
    what: &str,
    rule: &'static str,
    span: Range<usize>,
) -> CredentialFileWrite {
    if spelling.speculative {
        return unprovable_hit(writer, word, display, what, span);
    }
    protected_hit(writer, display, what, rule, span)
}

fn judge_file_spelling(
    word: &Word,
    spelling: &Spelling,
    writer: Writer,
) -> Option<CredentialFileWrite> {
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
                Some(spelled_hit(
                    spelling,
                    word,
                    writer,
                    &display,
                    what,
                    rule_for(&spelling.comps),
                    span,
                ))
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

/// Whether `pattern` can become `name`.
///
/// Greedy with a single backtrack point (the last `*`), which is exact for
/// `*`/`?`/literal patterns and costs O(pattern × name). The recursive form
/// this replaces tried every split at every `*`, exponential in the stars:
/// `cp ./*?*?…*? ~/.config/gcloud/` (40 pairs) held the hook for over a
/// minute.
fn glob_matches(pattern: &[PatternChar], name: &[char]) -> bool {
    let (mut p, mut n) = (0usize, 0usize);
    let mut resume: Option<(usize, usize)> = None;
    while n < name.len() {
        match pattern.get(p) {
            Some(PatternChar::Star) => {
                resume = Some((p, n));
                p += 1;
            }
            Some(PatternChar::Any) => {
                p += 1;
                n += 1;
            }
            Some(PatternChar::Literal(expected)) if *expected == name[n] => {
                p += 1;
                n += 1;
            }
            _ => {
                let Some((star, from)) = resume else {
                    return false;
                };
                resume = Some((star, from + 1));
                p = star + 1;
                n = from + 1;
            }
        }
    }
    pattern[p..].iter().all(|ch| *ch == PatternChar::Star)
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
        Exact::Protected { display, what, .. } => Some(spelled_hit(
            directory,
            directory_word,
            writer,
            &display,
            what,
            rule_for(&directory.comps),
            span,
        )),
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
                        Some(protected_hit(
                            writer,
                            &display,
                            what,
                            rule_for(&comps),
                            source.range.clone(),
                        ))
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
                            rule: rule_for(&comps),
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
                    rule: rule_for(&directory.comps),
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
/// command word, or `None` when the wrapper makes it unknowable or an option
/// is missing its required operand. A wrapper with no command returns
/// `args.len()`, so the caller can safely consume the remaining arguments.
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
                args.get(index + 1)?;
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
            if consumed_next {
                args.get(index + 1)?;
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
        let args = &words[1..];
        let skip = skip_wrapper(&name, args)?;
        words = args.get(skip..)?;
    }
    None
}

fn classify_simple_command(tokens: &[Token]) -> Option<CredentialFileWrite> {
    let mut words: Vec<&Word> = Vec::new();
    for token in tokens {
        match token {
            Token::Word(word) => words.push(word),
            Token::Write { mode, target } => {
                // A brace list may contain both Git and credential targets.
                // Skip Git readings, not the rest of this target's readings.
                if let Some(hit) = resolve_all(target)
                    .iter()
                    .filter_map(|spelling| {
                        judge_file_spelling(target, spelling, Writer::redirect(*mode))
                    })
                    .find(|hit| !is_git_redirect_rule(hit.rule))
                {
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
        WriterKind::Rsync => classify_rsync(args),
        WriterKind::ArchiveExtract => classify_archive_extract(&executable_name(argv0)?, args),
        // `writer_kind` names POSIX executables only; these are bound by
        // `windows_shells`, which calls the judges directly.
        WriterKind::AddContent
        | WriterKind::SetContent
        | WriterKind::ClearContent
        | WriterKind::OutFile
        | WriterKind::TeeObject
        | WriterKind::NewItem
        | WriterKind::CopyItem
        | WriterKind::MoveItem
        | WriterKind::CmdCopy
        | WriterKind::CmdMove
        | WriterKind::CmdMklink => None,
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
        return resolve_all(&dir_word).iter().find_map(|directory| {
            operands
                .iter()
                .find_map(|source| judge_placement(directory, &dir_word, source, writer))
        });
    }
    if operands.len() < 2 {
        return None;
    }
    let (dest, sources) = operands.split_last()?;
    if no_target_dir {
        return judge_file_target(dest, writer);
    }
    judge_transfer_destination(writer, dest, sources)
}

/// Judge a transfer whose destination is its last operand.
///
/// Shared by `cp`/`mv`/`install`/`ln` and by `rsync`, which reach it with the
/// same two facts and nothing else: where the bytes land, and what is being
/// placed there. Only the option grammar differs, and that stays with each
/// caller because rsync's is not cp's.
///
/// The `Exact::Parent` arm is what catches a directory destination -- syncing
/// into `~/.ssh/` names no protected file in the command text, and the
/// protected file is the one the sources put there.
fn judge_transfer_destination(
    writer: Writer,
    dest: &Word,
    sources: &[&Word],
) -> Option<CredentialFileWrite> {
    resolve_all(dest).iter().find_map(|destination| {
        if destination.escaped || destination.partial.is_some() {
            return judge_file_spelling(dest, destination, writer);
        }
        match exact(destination.root, &destination.comps) {
            Exact::Protected { display, what, .. } => Some(spelled_hit(
                destination,
                dest,
                writer,
                &display,
                what,
                rule_for(&destination.comps),
                dest.range.clone(),
            )),
            Exact::Parent => sources
                .iter()
                .find_map(|source| judge_placement(destination, dest, source, writer)),
            Exact::Clear => None,
        }
    })
}

/// Options whose VALUE is the next word, so that word is not an operand.
///
/// Getting this list wrong in the missing direction is not merely incomplete,
/// it manufactures a false positive: `rsync --exclude id_rsa /tmp/x ~/.ssh/`
/// would read `id_rsa` as a source, and a source placed into the protected
/// destination is exactly what `judge_placement` reports. The `--option=value`
/// spelling needs no entry here because it carries its value.
const RSYNC_VALUE_LONGS: &[&str] = &[
    "rsh",
    "exclude",
    "include",
    "filter",
    "exclude-from",
    "include-from",
    "files-from",
    "log-file",
    "log-file-format",
    "out-format",
    "password-file",
    "temp-dir",
    "partial-dir",
    "compare-dest",
    "copy-dest",
    "link-dest",
    "backup-dir",
    "suffix",
    "chmod",
    "chown",
    "usermap",
    "groupmap",
    "bwlimit",
    "timeout",
    "contimeout",
    "port",
    "sockopts",
    "modify-window",
    "block-size",
    "max-size",
    "min-size",
    "max-delete",
    "skip-compress",
    "protocol",
    "iconv",
    "checksum-seed",
    "remote-option",
    "info",
    "debug",
    "address",
    "compress-level",
    "write-batch",
    "read-batch",
    "only-write-batch",
    "copy-as",
];

/// Short options whose value is the next word.
const RSYNC_VALUE_SHORTS: &[char] = &['e', 'f', 'M', 'T', 'B'];

/// `rsync SRC… DEST` (#478).
///
/// Every sibling that replaces a file at a named path already denies this --
/// `cp`, `mv`, `install`, `ln`, `tee` and `dd` all refuse a write to
/// `~/.ssh/authorized_keys` -- and `rsync` did not, although it is in the pack's keyword set and
/// has its own `rsync-sensitive-then-delete` rule. One line replaced an
/// authorized-keys file.
///
/// rsync gets its own option grammar rather than `classify_copy`'s: `-e`,
/// `--exclude` and friends take a following word that cp has no equivalent for,
/// and mis-reading one as an operand is the false positive documented on
/// `RSYNC_VALUE_LONGS`.
///
/// A remote destination (`host:path`, `rsync://…`) is declined. The protected
/// table is rooted at THIS machine's home and `/etc`, so a remote spelling
/// names a path this classifier cannot resolve; saying so is honester than
/// judging it against the wrong root.
fn classify_rsync(args: &[&Word]) -> Option<CredentialFileWrite> {
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
            if !long.contains('=') && RSYNC_VALUE_LONGS.contains(&long) {
                index += 1;
            }
            continue;
        }
        // A short cluster consumes the next word only when its LAST character
        // is the value-taking one (`-ave ssh`), because anything earlier takes
        // the remainder of the cluster as its value.
        if text
            .chars()
            .next_back()
            .is_some_and(|last| RSYNC_VALUE_SHORTS.contains(&last))
        {
            index += 1;
        }
    }
    if operands.len() < 2 {
        return None;
    }
    let (dest, sources) = operands.split_last()?;
    if names_remote_host(&dest.as_string()) {
        return None;
    }
    let writer = Writer {
        kind: Some(WriterKind::Rsync),
        mode: WriteMode::Replace,
    };
    judge_transfer_destination(writer, dest, sources)
}

/// Classify an archive extraction by its DESTINATION DIRECTORY.
///
/// `tar -xf payload.tar -C ~/.ssh` was allowed while `cp -r payload/ ~/.ssh/`
/// and `rsync -a payload/ ~/.ssh/` denied, for the same destinations and the
/// same effect. Measured before the fix:
///
/// ```text
/// destination   cp / rsync                      extraction
/// ~/.ssh/       deny credential-file-write      ALLOW
/// .git/         deny git-internals-write        ALLOW
/// /etc/         allow                           allow
/// ```
///
/// The `/etc` row is what keeps this narrow: dcg does not judge
/// `cp -r payload/ /etc/` either, so extraction there stays allowed for the
/// same reason. Nothing here is a new "extraction is dangerous" posture.
///
/// Only an extraction with an EXPLICIT destination is judged. Without one the
/// archive lands in the working directory, which is the ordinary case and is
/// not this rule's business — and declining there is also what keeps this from
/// colliding with `tar --remove-files`, which is about the source.
fn classify_archive_extract(name: &str, args: &[&Word]) -> Option<CredentialFileWrite> {
    match name {
        // macOS calls bsdtar `tar`. Its option arities differ from GNU tar
        // (`-s` takes a rewrite expression; `-H` does not take a value), so
        // neither grammar alone can prove an invocation harmless everywhere.
        "tar" => classify_tar_extract("tar", args).or_else(|| classify_tar_extract("bsdtar", args)),
        "bsdtar" => classify_tar_extract(name, args),
        "unzip" => classify_unzip_extract(args),
        "7z" | "7za" | "7zr" => classify_7z_extract(args),
        _ => None,
    }
}

/// Consume an option's attached or following value without interpreting the
/// value as another option. Traditional tar clusters always take the next
/// word, unlike short clusters (`xfC archive dir` versus `-xfC`).
fn archive_option_value(
    word: &Word,
    value_offset: usize,
    args: &[&Word],
    index: &mut usize,
) -> Option<Word> {
    if word.text.len() > value_offset {
        Some(word.suffix(value_offset))
    } else {
        let value = (*args.get(*index)?).clone();
        *index += 1;
        Some(value)
    }
}

#[derive(Default)]
struct TarExtraction {
    extracting: bool,
    no_file_output: bool,
    has_members: bool,
    directory: Option<Word>,
    member_hit: Option<CredentialFileWrite>,
}

impl TarExtraction {
    fn flag(&mut self, flag: char, literal: bool) {
        match flag {
            'x' => self.extracting = true,
            'c' | 'r' | 'u' | 'A' | 'd' | 't' | 'O' if literal => {
                self.no_file_output = true;
            }
            _ => {}
        }
    }

    fn long_option(
        &mut self,
        word: &Word,
        prefix_len: usize,
        args: &[&Word],
        index: &mut usize,
    ) -> Option<()> {
        let long: String = word.text[prefix_len..].iter().collect();
        let (option, attached) = long
            .split_once('=')
            .map_or((long.as_str(), false), |(key, _)| (key, true));
        if !option.is_empty() && (option == "cd" || "directory".starts_with(option)) {
            let value = if attached {
                word.value_suffix(prefix_len + option.len() + 1)?
            } else {
                archive_option_value(word, word.text.len(), args, index)?
            };
            self.change_directory(value);
        } else if !option.is_empty() && (option == "get" || "extract".starts_with(option)) {
            self.extracting = true;
        } else if (option.len() >= 5 && "files-from".starts_with(option))
            || (option.len() >= 3 && "add-file".starts_with(option))
        {
            if !attached {
                args.get(*index)?;
                *index += 1;
            }
            self.possible_members();
        } else if word.is_all_literal()
            && matches!(
                option,
                "create"
                    | "append"
                    | "update"
                    | "catenate"
                    | "concatenate"
                    | "delete"
                    | "diff"
                    | "compare"
                    | "list"
                    | "test-label"
                    | "to-stdout"
                    | "help"
                    | "usage"
                    | "version"
            )
        {
            self.no_file_output = true;
        } else if !attached
            // These no-argument names are themselves prefixes of a value
            // option. GNU's unique long abbreviations otherwise preserve
            // arity, so --quote-char -O must consume -O as character data.
            && !matches!(option, "checkpoint" | "sparse" | "xattrs")
            && !option.is_empty()
            && TAR_VALUE_LONGS.iter().any(|known| known.starts_with(option))
        {
            args.get(*index)?;
            *index += 1;
        }
        Some(())
    }

    fn change_directory(&mut self, mut directory: Word) {
        // tar applies relative -C values from the preceding -C, not the
        // caller's cwd. Keep their quoting/expansion provenance while joining
        // them. An absolute path or a supported home expansion starts afresh.
        let absolute = directory.text.first() == Some(&'/')
            || (!directory.literal.first().copied().unwrap_or(true)
                && (directory.text.first() == Some(&'~')
                    || parse_variable(&directory).is_some_and(|(name, _)| {
                        VARIABLE_ROOTS.iter().any(|(known, _, _)| *known == name)
                    })));
        if !absolute && let Some(mut previous) = self.directory.take() {
            previous.text.push('/');
            previous.literal.push(true);
            previous.text.append(&mut directory.text);
            previous.literal.append(&mut directory.literal);
            previous.range = directory.range;
            previous.glued_paren |= directory.glued_paren;
            directory = previous;
        }
        self.directory = Some(directory);
    }

    fn member(&mut self) {
        self.has_members = true;
        self.possible_members();
    }

    fn possible_members(&mut self) {
        // -T/--files-from (and BSD -I) select members at this -C position.
        // The file contents are unknown, so keep this possible write without
        // using the list to prove a later directory unused.
        if self.member_hit.is_none()
            && let Some(directory) = &self.directory
        {
            self.member_hit = judge_archive_directory(directory);
        }
    }

    fn finish(self) -> Option<CredentialFileWrite> {
        if !self.extracting || self.no_file_output {
            return None;
        }
        self.member_hit.or_else(|| {
            (!self.has_members)
                .then_some(self.directory)
                .flatten()
                .and_then(|directory| judge_archive_directory(&directory))
        })
    }
}

/// Value-taking options must consume their arguments even when the value is
/// spelled `-x`, `-O` or `-C`: those bytes are archive names, filters, dates or
/// helper commands, not extraction modes or destinations.
const TAR_VALUE_LONGS: &[&str] = &[
    "add-file",
    "after-date",
    "block-size",
    "blocking-factor",
    "checkpoint-action",
    "exclude",
    "exclude-from",
    "exclude-ignore",
    "exclude-ignore-recursive",
    "exclude-tag",
    "exclude-tag-all",
    "exclude-tag-under",
    "file",
    "files-from",
    "format",
    "gid",
    "gname",
    "group",
    "group-map",
    "hole-detection",
    "include",
    "index-file",
    "info-script",
    "label",
    "level",
    "listed-incremental",
    "mode",
    "mtime",
    "new-volume-script",
    "newer",
    "newer-ctime",
    "newer-ctime-than",
    "newer-mtime",
    "newer-mtime-than",
    "newer-than",
    "no-quote-chars",
    "older",
    "older-ctime",
    "older-ctime-than",
    "older-mtime",
    "older-mtime-than",
    "older-than",
    "options",
    "owner",
    "owner-map",
    "passphrase",
    "pax-option",
    "quote-chars",
    "quoting-style",
    "record-size",
    "rmt-command",
    "rsh-command",
    "sort",
    "sparse-version",
    "starting-file",
    "strip-components",
    "suffix",
    "tape-length",
    "to-command",
    "transform",
    "uid",
    "uname",
    "use-compress-program",
    "volno-file",
    "warning",
    "xattrs-exclude",
    "xattrs-include",
    "xform",
];

fn classify_tar_extract(name: &str, args: &[&Word]) -> Option<CredentialFileWrite> {
    let mut extraction = TarExtraction::default();
    let mut ended = false;
    let mut index = 0;
    while let Some(word) = args.get(index) {
        let first = index == 0;
        index += 1;
        let text = word.as_string();
        let literal = word.is_all_literal();
        let traditional = first && !text.starts_with('-');
        if ended || (!traditional && (!text.starts_with('-') || text == "-")) {
            if literal && !text.is_empty() {
                extraction.member();
            } else {
                // A dynamic expansion can disappear, leaving tar's default
                // extract-all behavior in the final directory active.
                extraction.possible_members();
            }
            // bsdtar stops parsing options at the first member. GNU tar
            // continues, with each -C applying to the members that follow.
            ended |= name == "bsdtar" && literal && !text.is_empty();
            continue;
        }
        if text == "--" {
            ended = true;
            continue;
        }
        if text.starts_with("--") {
            extraction.long_option(word, 2, args, &mut index)?;
            continue;
        }
        let offset = usize::from(!traditional);
        for position in offset..word.text.len() {
            let flag = word.text[position];
            let takes_value = if name == "bsdtar" {
                "bCfIsTWX".contains(flag)
            } else {
                "bCfFgHIKLNTVX".contains(flag)
            };
            if takes_value {
                let value_offset = if traditional {
                    word.text.len()
                } else {
                    position + 1
                };
                let value = archive_option_value(word, value_offset, args, &mut index)?;
                if flag == 'C' {
                    extraction.change_directory(value);
                } else if flag == 'T' || (name == "bsdtar" && flag == 'I') {
                    extraction.possible_members();
                } else if name == "bsdtar" && flag == 'W' {
                    extraction.long_option(&value, 0, args, &mut index)?;
                }
                if !traditional {
                    break;
                }
            } else {
                extraction.flag(flag, literal);
            }
        }
    }
    extraction.finish()
}

fn classify_unzip_extract(args: &[&Word]) -> Option<CredentialFileWrite> {
    let mut leading_options = true;
    let mut no_file_output = false;
    let mut negated_option = false;
    let mut destination_hit = None;
    let mut index = 0;
    while let Some(word) = args.get(index) {
        index += 1;
        let text = word.as_string();
        let literal = word.is_all_literal();
        if !text.starts_with('-') || text == "-" {
            leading_options = false;
            continue;
        }
        // Info-ZIP accepts -d after the archive, but other option-looking
        // words there are member names. In particular, a member named -l
        // must not turn a real extraction into a safe listing proof.
        if !leading_options {
            if text.starts_with("-d") {
                let directory = archive_option_value(word, 2, args, &mut index)?;
                destination_hit = destination_hit.or_else(|| judge_archive_directory(&directory));
            }
            continue;
        }
        for position in 1..word.text.len() {
            let flag = word.text[position];
            if matches!(flag, 'd' | 'P' | 'I' | 'O') {
                let value = archive_option_value(word, position + 1, args, &mut index)?;
                if flag == 'd' {
                    destination_hit = destination_hit.or_else(|| judge_archive_directory(&value));
                }
                break;
            }
            // Info-ZIP's --l / -l-l can undo a previous listing mode. Do not
            // lift a protected-destination denial on an unmodeled negation.
            negated_option |= flag == '-';
            if literal && matches!(flag, 'l' | 'v' | 't' | 'T' | 'p' | 'c' | 'z' | 'Z' | 'h') {
                no_file_output = true;
            }
        }
    }
    if no_file_output && !negated_option {
        None
    } else {
        destination_hit
    }
}

fn classify_7z_extract(args: &[&Word]) -> Option<CredentialFileWrite> {
    let mut extracting = None;
    let mut ended = false;
    let mut no_file_output = false;
    let mut destination_hit = None;
    for word in args {
        let text = word.as_string();
        if ended || !text.starts_with('-') || text == "-" {
            if extracting.is_none() {
                extracting = Some(
                    word.is_all_literal()
                        && (text.eq_ignore_ascii_case("x") || text.eq_ignore_ascii_case("e")),
                );
            }
        } else if text == "--" {
            ended = true;
        } else if word.is_all_literal() && text.eq_ignore_ascii_case("-so") {
            no_file_output = true;
        } else if text
            .get(..2)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("-o"))
            && let Some(directory) = word.value_suffix(2)
        {
            destination_hit = destination_hit.or_else(|| judge_archive_directory(&directory));
        }
    }
    if extracting == Some(true) && !no_file_output {
        destination_hit
    } else {
        None
    }
}

fn judge_archive_directory(dest: &Word) -> Option<CredentialFileWrite> {
    let writer = Writer {
        kind: Some(WriterKind::ArchiveExtract),
        mode: WriteMode::Replace,
    };
    judge_extraction_destination(writer, dest)
}

/// Judge a destination directory that will receive UNKNOWN archive members.
///
/// Only the named directory is judged. Archive member names are not evidence
/// that an ordinary parent such as `/etc` or `~` contains a protected write.
fn judge_extraction_destination(writer: Writer, dest: &Word) -> Option<CredentialFileWrite> {
    // These options require a directory. Supplying that fact to the relative
    // anchor resolver makes `.git` and `.ssh` identical to `.git/` and
    // `.ssh/`, without treating a plain file operand with that name as a tree.
    let mut directory = dest.clone();
    if directory.text.last() != Some(&'/') {
        directory.text.push('/');
        directory.literal.push(true);
    }
    resolve_all(&directory)
        .iter()
        .find_map(|destination| judge_extraction_spelling(writer, dest, destination))
}

fn judge_extraction_spelling(
    writer: Writer,
    dest: &Word,
    destination: &Spelling,
) -> Option<CredentialFileWrite> {
    if destination.escaped || destination.partial.is_some() {
        return judge_file_spelling(dest, destination, writer);
    }
    let span = dest.range.clone();
    match exact(destination.root, &destination.comps) {
        Exact::Protected { display, what, .. } => {
            let display = if destination.rebased_at_anchor {
                dest.as_string()
            } else {
                display
            };
            Some(spelled_hit(
                destination,
                dest,
                writer,
                &display,
                what,
                rule_for(&destination.comps),
                span,
            ))
        }
        // A directory that merely CONTAINS protected files is not itself a
        // protected destination. `/etc` is the case that matters: dcg allows
        // `cp -r payload/ /etc/` and `rsync -a payload/ /etc/`, so extraction
        // there is out of scope for the same reason, and denying it would make
        // this rule a false-positive engine for the most ordinary install step
        // there is. `~/.ssh` and `.git` deny because the DIRECTORY itself is in
        // the protected set, not because of what is under it.
        //
        // Measured: denying `Exact::Parent` too flagged `tar -xf payload.tar -C
        // /etc`, which the negative test caught before this shipped.
        Exact::Parent | Exact::Clear => None,
    }
}

/// Whether an rsync operand names a remote host rather than a local path.
///
/// `host:path` and `user@host:path` are remote; a colon that appears after the
/// first `/` is an ordinary (if unusual) filename character rather than a host
/// separator.
fn names_remote_host(operand: &str) -> bool {
    if operand.starts_with("rsync://") {
        return true;
    }
    match (operand.find(':'), operand.find('/')) {
        (Some(colon), Some(slash)) => colon < slash,
        (Some(_), None) => true,
        _ => false,
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

    /// A pinned runtime home: the (possibly absent) components.
    #[derive(Clone)]
    pub(super) struct PinnedHome(pub(super) Option<Vec<String>>);

    thread_local! {
        /// When set, pins [`runtime_home`] for this thread.
        static PINNED_RUNTIME_HOME: std::cell::RefCell<Option<PinnedHome>> =
            const { std::cell::RefCell::new(None) };
    }

    pub(super) fn pinned_runtime_home() -> Option<PinnedHome> {
        PINNED_RUNTIME_HOME.with(|pinned| pinned.borrow().clone())
    }

    /// Run `body` with the runtime `$HOME` pinned to `home` (`None` = unset).
    pub(super) fn with_runtime_home<R>(home: Option<&str>, body: impl FnOnce() -> R) -> R {
        struct Restore(Option<PinnedHome>);
        impl Drop for Restore {
            fn drop(&mut self) {
                let previous = self.0.take();
                PINNED_RUNTIME_HOME.with(|pinned| *pinned.borrow_mut() = previous);
            }
        }
        let next = Some(PinnedHome(home.and_then(home_components)));
        let _restore = Restore(PINNED_RUNTIME_HOME.with(|pinned| pinned.replace(next)));
        body()
    }

    fn hit(command: &str) -> Option<CredentialFileWrite> {
        // Every other test is independent of the host's `$HOME`.
        with_runtime_home(None, || {
            classify_credential_file_write(command, ShellDialect::Posix)
        })
    }

    /// Home roots outside `/home`, `/Users`, `/root` and `/var/root` (#502).
    ///
    /// Measured before the fix on v0.14.4 and on main: every command below was
    /// allowed — Synology DSM's `$HOME` is `/var/services/homes/<u>`, a
    /// symlink to `/volume1/homes/<u>`, and the rooted table knew neither, so
    /// the credential dotfiles that are deliberately not relative anchors
    /// (`.netrc`, `.npmrc`, `.pypirc`) and the login files had no rooted
    /// spelling to deny under.
    #[test]
    fn unlisted_home_roots_are_home_roots() {
        for root in [
            "/var/services/homes/luna",
            "/volume1/homes/luna",
            "/volume10/homes/luna",
            "/VOLUME2/Homes/luna",
            "/export/home/luna",
            "/var/home/luna",
            "/usr/home/luna",
        ] {
            for file in [
                ".netrc",
                ".npmrc",
                ".pypirc",
                ".zshrc",
                ".bashrc",
                ".profile",
                ".ssh/authorized_keys",
                ".pgpass",
                ".git-credentials",
                ".config/gh/hosts.yml",
            ] {
                let path = format!("{root}/{file}");
                for command in [
                    format!("echo x > {path}"),
                    format!("echo x >> {path}"),
                    format!("echo x >>{path}"),
                    format!("echo x 1>> {path}"),
                    format!("echo x &>> {path}"),
                    format!("echo x | tee -a {path}"),
                    format!("echo x | tee {path}"),
                    format!("echo x >> \"{path}\""),
                    format!("echo x >> '{path}'"),
                    format!("cp ./x {path}"),
                    format!("sed -i 's/a/b/' {path}"),
                    format!("dd if=/tmp/x of={path}"),
                ] {
                    denied(&command);
                }
            }
            // Directory destinations and path spellings resolve the same way.
            denied(&format!("cp ./.netrc {root}/"));
            denied(&format!("cp ./.netrc {root}"));
            denied(&format!("echo x >> {root}//.netrc"));
            denied(&format!("echo x >> {root}/./.netrc"));
            denied(&format!("echo x >> {root}/projects/../.netrc"));
        }
    }

    /// The same roots stay quiet for ordinary files, public keys, and the
    /// `known_hosts` append `ssh` itself performs.
    #[test]
    fn unlisted_home_roots_keep_the_carve_outs() {
        for root in [
            "/var/services/homes/luna",
            "/volume1/homes/luna",
            "/export/home/luna",
            "/var/home/luna",
        ] {
            allowed(&format!("echo x >> {root}/notes.txt"));
            allowed(&format!("echo x > {root}/projects/app/.env.example"));
            allowed(&format!("cp ./report.pdf {root}/"));
            allowed(&format!("echo x >> {root}/.ssh/known_hosts"));
            allowed(&format!("echo x > {root}/.ssh/id_ed25519.pub"));
            allowed(&format!("cat {root}/.netrc"));
        }
        // Not a home root: no user component, or not a volume.
        allowed("echo x >> /volume1/homes");
        allowed("echo x >> /volumes/homes/luna/.netrc");
        allowed("echo x >> /volume/homes/luna/.netrc");
        allowed("echo x >> /var/services/.netrc");
        allowed("echo x >> /srv/data/.netrc");
    }

    /// The hook's own `$HOME` is a home root wherever it lives (#502): the one
    /// root that is exact instead of enumerated.
    #[test]
    fn runtime_home_is_a_home_root() {
        with_runtime_home(Some("/app"), || {
            for command in [
                "echo x >> /app/.netrc",
                "echo x > /APP/.npmrc",
                "echo x | tee -a /app/.bashrc",
                "cp ./.pypirc /app/",
                "echo x >> //app//.netrc",
            ] {
                assert!(
                    classify_credential_file_write(command, ShellDialect::Posix).is_some(),
                    "HOME=/app must protect {command:?}"
                );
            }
            for command in [
                "echo x >> /app/notes.txt",
                "cp ./x /app/",
                "echo x >> /application/.netrc",
            ] {
                assert!(
                    classify_credential_file_write(command, ShellDialect::Posix).is_none(),
                    "HOME=/app must not flag {command:?}"
                );
            }
        });
        with_runtime_home(Some("/srv/nas/users/luna/"), || {
            assert!(
                classify_credential_file_write(
                    "echo x >> /srv/nas/users/luna/.netrc",
                    ShellDialect::Posix
                )
                .is_some()
            );
            assert!(
                classify_credential_file_write(
                    "echo x >> /srv/nas/users/other/.netrc",
                    ShellDialect::Posix
                )
                .is_none()
            );
        });
        // A `$HOME` that is a prefix of a fixed root must not shadow it.
        for shallow in ["/home", "/Users", "/var/services/homes", "/volume1"] {
            with_runtime_home(Some(shallow), || {
                for command in [
                    "echo x >> /home/luna/.netrc",
                    "echo x >> /Users/luna/.netrc",
                    "echo x >> /var/services/homes/luna/.netrc",
                    "echo x >> /volume1/homes/luna/.netrc",
                    "cp ./.netrc /home/luna/",
                ] {
                    assert!(
                        classify_credential_file_write(command, ShellDialect::Posix).is_some(),
                        "HOME={shallow} must not shadow the fixed root in {command:?}"
                    );
                }
            });
        }
        // A `$HOME` nested beneath a fixed root adds its own home files.
        with_runtime_home(Some("/home/luna/work"), || {
            for command in [
                "echo x >> /home/luna/work/.netrc",
                "echo x >> /home/luna/.netrc",
                "echo x >> /home/luna/work/.ssh/authorized_keys",
            ] {
                assert!(
                    classify_credential_file_write(command, ShellDialect::Posix).is_some(),
                    "{command:?}"
                );
            }
        });
        // Rejected outright, so the fixed reading stands: a dot-named
        // component (would shadow `/home/luna/.config/gh/hosts.yml`) and the
        // `/etc` trees.
        for odd in [
            "/home/luna/.config",
            "/etc/skel",
            "/private/etc/x",
            "/srv/_netrc",
        ] {
            assert_eq!(home_components(odd), None, "{odd}");
        }
        with_runtime_home(Some("/home/luna/.config"), || {
            assert!(
                classify_credential_file_write(
                    "echo x >> /home/luna/.config/gh/hosts.yml",
                    ShellDialect::Posix
                )
                .is_some()
            );
        });
        // A system directory is never adopted as a home root, however an
        // account's `$HOME` is set.
        for system in [
            "/",
            "/var",
            "/tmp",
            "/usr",
            "/nonexistent",
            "/etc",
            "relative/home",
            "/a/../b",
        ] {
            with_runtime_home(Some(system), || {
                assert!(
                    classify_credential_file_write("echo x >> /tmp/.netrc", ShellDialect::Posix)
                        .is_none(),
                    "HOME={system} must not make /tmp/.netrc a home file"
                );
                assert!(
                    classify_credential_file_write("echo x >> /var/.netrc", ShellDialect::Posix)
                        .is_none(),
                    "HOME={system} must not make /var/.netrc a home file"
                );
            });
        }
    }

    /// `.` and `..` ahead of the root (found while adversarially probing the
    /// #502 fix). Measured before: `/home/./luna/.netrc` read `.` as the user
    /// and judged `luna/.netrc`; `/./home/luna/.netrc` stated no root at all;
    /// `/home/../home/luna/.netrc` read `..` as the user. All three allowed.
    #[test]
    fn dot_components_before_the_root_resolve() {
        for command in [
            "echo x >> /home/./luna/.netrc",
            "echo x >> /./home/luna/.netrc",
            "echo x >> /home/./luna/./.ssh/authorized_keys",
            "echo x >> /./etc/sudoers",
            "echo x >> /private/./etc/sudoers",
            "echo x >> /var/./services/homes/luna/.netrc",
            "echo x >> /volume1/./homes/./luna/.zshrc",
            "echo x | tee -a /home/./luna/.bashrc",
            "cp ./x /home/./luna/.npmrc",
        ] {
            denied(command);
        }
        // `..` before any root: cannot be verified when the lexical reading
        // reaches a protected root.
        for command in [
            "echo x >> /home/../home/luna/.netrc",
            "echo x >> /var/../home/luna/.netrc",
            "echo x >> /tmp/../etc/sudoers",
            "echo x >> /Users/../Users/luna/.zshrc",
        ] {
            let hit = denied(command);
            assert!(
                hit.reason.contains("cannot be verified"),
                "{command}: {}",
                hit.reason
            );
        }
        // ...and left alone when it lands nowhere near one.
        for command in [
            "echo x >> /tmp/../tmp/out.txt",
            "echo x >> /home/../luna/.netrc",
            "echo x >> /opt/app/../data/notes.txt",
            "echo x >> /home/./luna/notes.txt",
            "echo x >> /./tmp/.netrc",
        ] {
            allowed(command);
        }
    }

    /// The invariant `home_components` leans on to let a longer `$HOME` win
    /// in `rooted_prefix`: no accepted `$HOME` contains a component that
    /// begins protected material, whatever its case.
    #[test]
    fn home_rejects_every_protected_component() {
        for protected in ENTRIES
            .iter()
            .filter(|entry| entry.root == Root::Home)
            .map(|entry| entry.comps[0])
            .chain(RELATIVE_ANCHORS.iter().copied())
            .chain(RELATIVE_FILE_ANCHORS.iter().copied())
        {
            for home in [
                format!("/srv/{protected}"),
                format!("/srv/{protected}/luna"),
                format!("/home/luna/{}", protected.to_ascii_uppercase()),
            ] {
                assert_eq!(home_components(&home), None, "{home}");
            }
        }
        // An ordinary dot directory is not protected material: a build
        // sandbox's `.../.rch-tmp/home` or `.../.cache/home` is a usable home.
        for home in ["/data/projects/x/.rch-tmp/home", "/home/luna/.cache/h"] {
            assert!(home_components(home).is_some(), "{home}");
        }
    }

    /// Found reviewing #502: a quote splitting a root's name hid it from the
    /// candidate gate, and spellings that only re-spell `/` (the macOS
    /// firmlink, `/proc/<pid>/root`) or root's macOS home stated no root.
    #[test]
    fn quoted_and_aliased_roots_resolve() {
        for command in [
            "echo x >> \"/home\"/luna/.netrc",
            "echo x >> /ho\"me\"/luna/.netrc",
            "echo x >> /var/services/'homes'/luna/.netrc",
            "echo x >> /volume1/ho\"mes\"/luna/.npmrc",
            "echo x >> /System/Volumes/Data/Users/luna/.netrc",
            "echo x >> /system/volumes/data/private/etc/sudoers",
            "echo x >> /proc/self/root/home/luna/.netrc",
            "echo x >> /proc/thread-self/root/etc/sudoers",
            "echo x >> /proc/1/root/proc/self/root/home/luna/.pypirc",
            "echo x >> /proc/self/root/../etc/sudoers",
            "echo x >> /proc/self/root/../../home/luna/.netrc",
            "echo x >> /private/var/root/.netrc",
            "cp ./x /System/Volumes/Data/private/var/root/.npmrc",
        ] {
            denied(command);
        }
        for command in [
            "echo x >> \"/home\"/luna/notes.txt",
            "echo x >> /System/Volumes/Data/Users/luna/notes.txt",
            "echo x >> /proc/self/root/tmp/.netrc",
            "echo x >> /proc/self/cwd/.netrc",
            "echo x >> /proc/abc/root/home/luna/.netrc",
            "echo x >> /System/Volumes/.netrc",
        ] {
            allowed(command);
        }
        assert!(may_name_protected_path("echo x >> \"/home\"/luna/.netrc"));
        assert!(!may_name_protected_path("echo \"hello\" > 'out.txt'"));
    }

    /// Found in the second review of #502: every spelling below was allowed on
    /// c8b77a1. ANSI-C numeric escapes were kept as the literal text `\x2f`;
    /// a glob, brace list or expansion in a root's own name stated no root at
    /// all (and `/e?c` carried no gate needle, so the classifier never ran);
    /// and `/proc/<pid>/task/<tid>/root`, macOS's `/.nofollow` and
    /// `/Volumes/Macintosh HD` are `/` as much as `/proc/self/root` is.
    #[test]
    fn rewritten_and_aliased_root_spellings_resolve() {
        for command in [
            "echo x >> $'\\x2fhome/luna/.netrc'",
            "echo x >> $'\\057home\\057luna/.netrc'",
            "echo x >> $'\\u002fetc/sudoers'",
            "echo x >> /home/luna/$'\\x2enetrc'",
            "echo x >> $'\\x2f'etc/sudoers",
            "echo x | tee -a $'\\x2f'etc/sudoers",
            "echo x >> /e?c/sudoers",
            "echo x >> /e*c/sudoers",
            "echo x >> /[e]tc/sudoers",
            "echo x >> /[a-z]tc/sudoers",
            "echo x >> /h?me/luna/.netrc",
            "echo x >> /ho*/luna/.netrc",
            "echo x >> /*/luna/.netrc",
            "echo x >> /*/sudoers",
            "echo x >> /{home,tmp}/luna/.netrc",
            "echo x >> /h{o,}me/luna/.netrc",
            "echo x >> /{etc,}/sudoers",
            "echo x >> /et${x}c/sudoers",
            "echo x >> /$x/etc/sudoers",
            "echo x >> /v?r/services/homes/luna/.netrc",
            "echo x >> /vol*/homes/luna/.npmrc",
            "echo x >> /proc/*/root/etc/sudoers",
            "echo x | tee -a /e?c/sudoers",
            "cp ./x /e?c/sudoers",
            "cp ./.netrc /h?me/luna/",
            "cp -t /h?me/luna/ ./.netrc",
            "echo x >> /proc/self/task/1/root/home/luna/.netrc",
            "echo x >> /proc/1/task/1/root/etc/sudoers",
            "echo x >> /.nofollow/etc/sudoers",
            "echo x >> /.nofollow/private/etc/sudoers",
            "echo x >> /.nofollow/Users/luna/.netrc",
            "echo x >> '/Volumes/Macintosh HD/Users/luna/.netrc'",
            "echo x >> '/Volumes/Macintosh HD/private/etc/sudoers'",
            "echo x >> '/Volumes/Macintosh HD/../etc/sudoers'",
            "echo x >> /proc/self/task/1/root/../etc/sudoers",
            // An unknown base: an expansion that may be empty, a process's
            // working directory, or the hook's own working directory once a
            // relative path climbs out of it.
            "echo x >> $x/etc/sudoers",
            "echo x >> ${x}/etc/sudoers",
            "echo x | tee -a $(printf /)etc/sudoers",
            // ...as the evaluator hands it over, the substitution blanked.
            "echo x >> $(        )etc/sudoers",
            "echo x >> `printf /`etc/sudoers",
            "echo x >> $(pwd)/../../../etc/sudoers",
            "echo x >> $PWD/../../../../etc/sudoers",
            "echo x >> /proc/1/cwd/etc/sudoers",
            "echo x >> /proc/1/cwd/../../etc/sudoers",
            "echo x >> ../../../../../../etc/sudoers",
            "echo x | tee -a ./../../../../etc/sudoers",
            "echo x >> x/../../../../home/luna/.netrc",
            "cp ./x ../../../../etc/passwd",
            // zsh glob alternation and bash extglob in a root's name.
            "echo x >> /(etc|x)/sudoers",
            "echo x >> /@(etc)/sudoers",
            "echo x >> /e(t)c/sudoers",
            "echo x | tee -a /(etc|x)/sudoers",
            // A Windows profile through WSL, Git Bash/MSYS2 and Cygwin.
            "echo x >> /mnt/c/Users/luna/.netrc",
            "echo x >> /mnt/c/Users/luna/_netrc",
            "echo x >> /c/Users/luna/.npmrc",
            "echo x >> /C/Users/luna/.git-credentials",
            "cp ./x /cygdrive/d/Users/luna/.pypirc",
        ] {
            denied(command);
        }
        // A reading through a pattern is reported as a spelling that can
        // reach the file, not as the file.
        assert!(
            denied("echo x >> /e?c/sudoers")
                .reason
                .contains("the shell expands that spelling"),
        );
        for command in [
            "echo x >> /e?c/notes.txt",
            "echo x >> /tmp/*/sudoers",
            "echo x >> /h?me/luna/notes.txt",
            "echo x >> /{home,tmp}/luna/notes.txt",
            "echo x >> /opt/*/etc/sudoers.txt",
            "echo x >> /proc/self/task/1/cwd/.netrc",
            "echo x >> /.nofollow/tmp/.netrc",
            "echo x >> '/Volumes/Backup/tmp/.netrc'",
            "echo x >> $'\\x2ftmp/out.txt'",
            "cp ./report.pdf /h?me/luna/",
            "echo x >> x/../etc/sudoers",
            "echo x >> ../etc/config.yml",
            "cp ./x ../src/main.rs",
            "cp ./x $OUT/passwd",
            "echo x >> $x/tmp/.netrc",
            "echo x >> /proc/self/cwd/notes.txt",
            "echo x >> /tmp/out(1)",
            "echo x >> /mnt/c/Users/luna/notes.txt",
            "echo x >> /mnt/data/Users/luna/.netrc",
            "echo x >> /cc/Users/luna/.netrc",
        ] {
            allowed(command);
        }
        // `rm` rules ask only for proven paths.
        assert!(!names_protected_file("/e?c/sudoers"));
        assert!(names_protected_file("/.nofollow/etc/sudoers"));
        assert!(may_name_protected_path("echo x >> /e?c/sudoers"));
        assert!(may_name_protected_path("tee -a /{home,tmp}/luna/.netrc"));
        assert!(!may_name_protected_path("sed -i 's/a/b/' src/*.rs"));
        assert!(!may_name_protected_path("tee /tmp/*.log"));
    }

    /// The runtime `$HOME` is matched through a pattern too, and a literal
    /// spelling keeps the one reading it had.
    #[test]
    fn runtime_home_is_matched_through_a_pattern() {
        with_runtime_home(Some("/srv/nas/luna"), || {
            for command in [
                "echo x >> /srv/n?s/luna/.netrc",
                "echo x >> /srv/*/luna/.netrc",
                "echo x >> /srv/nas/luna/.netrc",
            ] {
                assert!(
                    classify_credential_file_write(command, ShellDialect::Posix).is_some(),
                    "{command:?}"
                );
            }
            assert!(
                classify_credential_file_write(
                    "echo x >> /srv/n?s/other/.netrc",
                    ShellDialect::Posix
                )
                .is_none()
            );
        });
        let (word, _) = read_word("/home/luna/.netrc", 0);
        assert_eq!(rooted_prefixes(&word).len(), 1);
    }

    #[test]
    fn synology_volume_names() {
        assert!(is_synology_volume("volume1"));
        assert!(is_synology_volume("volume10"));
        assert!(is_synology_volume("Volume3"));
        assert!(!is_synology_volume("volume"));
        assert!(!is_synology_volume("volumes"));
        assert!(!is_synology_volume("volume1a"));
        assert!(!is_synology_volume("vol1"));
    }

    /// Archive extraction writes a protected destination like every sibling.
    ///
    /// Measured before the fix: `tar -xf payload.tar -C ~/.ssh` was ALLOWED
    /// while `cp -r payload/ ~/.ssh/` and `rsync -a payload/ ~/.ssh/` denied,
    /// for the same destination and the same effect. The archive's members are
    /// unknowable before it runs, which is the same position a wildcard source
    /// puts `cp` in, so the destination is judged and the reason names the
    /// protected descendant it can land on.
    #[test]
    fn archive_extraction_guards_its_destination_directory() {
        for command in [
            "tar -xf payload.tar -C /home/user/.ssh",
            "tar -xzf payload.tar.gz -C /home/user/.ssh",
            "tar --extract --directory /home/user/.ssh -f payload.tar",
            "tar -xf payload.tar -C /home/user/.ssh/",
            "bsdtar -xf payload.tar -C /home/user/.ssh",
            "unzip -o payload.zip -d /home/user/.ssh",
            "unzip payload.zip -d /home/user/.ssh",
            "7z x payload.7z -o/home/user/.ssh",
            "7za x payload.7z -o/home/user/.ssh",
        ] {
            assert!(
                hit(command).is_some(),
                "extraction must guard its destination like every other writer: {command}"
            );
        }
    }

    #[test]
    fn archive_extraction_reads_option_arity_and_traditional_tar_flags() {
        for command in [
            "tar xf payload.tar -C /home/user/.ssh",
            "tar xfC payload.tar /home/user/.ssh",
            "tar xCf /home/user/.ssh payload.tar",
            "tar xvfC payload.tar /home/user/.ssh",
            "bsdtar xfC payload.tar /home/user/.ssh",
            "tar -x -s ',^,prefix/,' -f payload.tar -C /home/user/.ssh",
            "tar --get -f payload.tar -C /home/user/.ssh",
            "tar -xC/home/user/.ssh -fpayload.tar",
            "tar --directory=/home/user/.ssh --extract --file=payload.tar",
            "tar --extr --file=payload.tar --direc=/home/user/.ssh",
            "bsdtar -W extract -f payload.tar -W directory=/home/user/.ssh",
            "tar -W extract -f payload.tar -W directory=/home/user/.ssh",
            "tar --exclude -C -xf payload.tar -C /home/user/.ssh",
            "tar --exclude -O -xf payload.tar -C /home/user/.ssh",
            "tar --quote-chars -O -xf payload.tar -C /home/user/.ssh",
            "tar --quote-char -O -xf payload.tar -C /home/user/.ssh",
            "bsdtar -x --passphrase -O -f payload.tar -C /home/user/.ssh",
            "tar -xf -O -C /home/user/.ssh",
            "tar -x --same-order --atime-preserve -f payload.tar -C /home/user/.ssh",
            "tar -x --checkpoint --sparse --xattrs -f payload.tar -C /home/user/.ssh",
            "unzip -d/home/user/.ssh payload.zip",
            "unzip -od/home/user/.ssh payload.zip",
            "unzip -d /home/user/.ssh -P ptvlcz payload.zip",
            "unzip -Pptvlcz payload.zip -d /home/user/.ssh",
            "unzip -I UTF-8 -O CP437 payload.zip -d /home/user/.ssh",
            "7z -o/home/user/.ssh x payload.7z",
            "7za e payload.7z -o/home/user/.ssh",
            "7zr x -p-so payload.7z -o/home/user/.ssh",
        ] {
            let found = denied(command);
            assert_eq!(found.rule, CREDENTIAL_FILE_WRITE_NAME, "{command}");
        }
    }

    #[test]
    fn archive_extraction_directory_options_prove_bare_relative_anchors() {
        for (destination, expected) in [
            (".git", GIT_INTERNALS_WRITE_NAME),
            ("project/.git", GIT_INTERNALS_WRITE_NAME),
            ("'project/.git'", GIT_INTERNALS_WRITE_NAME),
            (".ssh", CREDENTIAL_FILE_WRITE_NAME),
            ("./.gnupg", CREDENTIAL_FILE_WRITE_NAME),
        ] {
            for command in [
                format!("tar -xf payload.tar -C {destination}"),
                format!("bsdtar -xf payload.tar --directory={destination}"),
                format!("unzip payload.zip -d {destination}"),
                format!("7z x payload.7z -o{destination}"),
            ] {
                let found = denied(&command);
                assert_eq!(found.rule, expected, "{command}");
                assert!(found.reason.contains("extracting an archive"), "{command}");
                assert!(command.get(found.span).is_some(), "{command}");
            }
        }
    }

    #[test]
    fn archive_extraction_tracks_tar_directory_changes_at_member_positions() {
        for command in [
            "tar -xf payload.tar -C /tmp -C /home/user/.ssh",
            "tar -xf payload.tar -C /home/user -C .ssh",
            "tar -xf payload.tar -C /home/user/.config -C ../.ssh",
            "tar -xf payload.tar -C /tmp -C '$HOME/.ssh'",
            "tar -xf payload.tar -C /tmp -C \"$HOME/.ssh\"",
            "tar -xf payload.tar -C /tmp first -C /home/user/.ssh second",
            "tar -xf payload.tar -C /home/user/.ssh first -C /tmp second",
            "tar -xf payload.tar -C /home/user/.ssh -T members.txt -C /tmp",
            "tar -xf payload.tar -C /home/user/.ssh -Tmembers.txt -C /tmp",
            "tar -xf payload.tar -C /home/user/.ssh --files-from members.txt -C /tmp",
            "tar -xf payload.tar -C /home/user/.ssh --files=members.txt -C /tmp",
            "tar -xf payload.tar -C /home/user/.ssh --add-file=member -C /tmp",
            "tar -xf payload.tar -C /tmp -T members.txt -C /home/user/.ssh",
            "tar -xf payload.tar -C /tmp $EMPTY -C /home/user/.ssh",
            "bsdtar -xf payload.tar -C /tmp $EMPTY -C /home/user/.ssh",
            "tar -xf payload.tar -C /tmp '' -C /home/user/.ssh",
            "bsdtar -xf payload.tar -C /home/user/.ssh -I members.txt -C /tmp",
            "tar -xf payload.tar -C project -C .git",
            "bsdtar -xf payload.tar -C /home/user -C .ssh",
            "unzip payload.zip -d /home/user/.ssh -l",
            "unzip -l --l payload.zip -d /home/user/.ssh",
            "unzip -- payload.zip -d /home/user/.ssh",
        ] {
            assert!(hit(command).is_some(), "{command}");
        }
        for command in [
            "tar -xf payload.tar -C /home/user/.ssh -C /tmp",
            "tar -xf payload.tar -C /home/user/.ssh -C ..",
            "tar -xf payload.tar -C /tmp first -C /home/user/.ssh",
            "tar -xf payload.tar -C /tmp -T members.txt -C ./build",
            "tar -xf payload.tar -C /tmp $MEMBERS -C ./build",
            "tar -tf payload.tar -C /home/user/.ssh -T members.txt -C /tmp",
            "tar -xOf payload.tar -C /home/user/.ssh -T members.txt -C /tmp",
            "tar -xf payload.tar -C /tmp -- -C /home/user/.ssh",
            "bsdtar -xf payload.tar -C /tmp first -C /home/user/.ssh second",
        ] {
            allowed(command);
        }
    }

    #[test]
    fn archive_extraction_preserves_read_modes_and_option_looking_data() {
        for command in [
            "tar -xOf payload.tar -C /home/user/.ssh",
            "tar xOfC payload.tar /home/user/.ssh",
            "tar -xf payload.tar --to-stdout -C /home/user/.ssh",
            "bsdtar -xOf payload.tar -C /home/user/.ssh",
            "tar -tf payload.tar -C /home/user/.ssh",
            "tar -cf -x -C /home/user/.ssh file",
            "tar -cf payload.tar --exclude -x -C /home/user/.ssh file",
            "tar -tf payload.tar -- -x -C /home/user/.ssh",
            "tar -xf payload.tar -- -C /home/user/.ssh",
            "tar -xfC /home/user/.ssh",
            "unzip -l payload.zip -d /home/user/.ssh",
            "unzip -v payload.zip -d /home/user/.ssh",
            "unzip -t payload.zip -d /home/user/.ssh",
            "unzip -p payload.zip -d /home/user/.ssh",
            "unzip -c payload.zip -d /home/user/.ssh",
            "unzip -z payload.zip -d /home/user/.ssh",
            "unzip -Z payload.zip -d /home/user/.ssh",
            "unzip -P-d payload.zip /home/user/.ssh",
            "7z x -so payload.7z -o/home/user/.ssh",
            "7z l payload.7z -o/home/user/.ssh",
            "7z t payload.7z -o/home/user/.ssh",
            "7z a payload.7z -o/home/user/.ssh",
            "7z x -- -o/home/user/.ssh",
            "tar -xf payload.tar -C",
            "tar -xf payload.tar --directory=",
            "unzip payload.zip -d",
            "7z x payload.7z -o",
        ] {
            allowed(command);
        }
    }

    /// The carve-outs, which are what keep this from being a false-positive
    /// engine for the most ordinary build step there is.
    #[test]
    fn archive_extraction_leaves_ordinary_destinations_alone() {
        for command in [
            // No explicit destination: the archive lands in the working
            // directory, which is not this rule's business.
            "tar -xf payload.tar",
            "unzip payload.zip",
            // Ordinary destinations.
            "tar -xf payload.tar -C ./build",
            "tar -xf payload.tar -C /tmp/scratch",
            "unzip -o payload.zip -d ./dist",
            // Reading, not extracting.
            "tar -tf payload.tar",
            "unzip -l payload.zip",
            // Creating an archive is the opposite direction, even when the
            // SOURCE is a protected path.
            "tar -czf backup.tar.gz ./src",
            "tar -cf keys.tar /home/user/.ssh",
            // `7z a` adds to an archive rather than extracting from one.
            "7z a payload.7z /home/user/.ssh",
            // `/etc` is deliberately out of scope: dcg does not judge
            // `cp -r payload/ /etc/` either.
            "tar -xf payload.tar -C /etc",
            "tar -xf payload.tar -C ~",
            "unzip payload.zip -d /etc",
            "7z x payload.7z -o/etc",
            "tar -xf payload.tar -C .github",
            "unzip payload.zip -d ./git",
        ] {
            assert!(
                hit(command).is_none(),
                "ordinary extraction must stay allowed: {command}"
            );
        }
    }

    /// `rsync` writes a protected destination like every sibling (#478).
    ///
    /// It was the one replacement tool with no guard: 8/8 writes to credential
    /// paths were allowed while `cp`, `mv`, `install`, `tee`, `ln` and the
    /// byte-copier all denied the same operation. rsync was already in the
    /// pack's keyword set and already had a `rsync-sensitive-then-delete` rule,
    /// so it was modelled as something that moves sensitive data and not as
    /// something that writes a protected destination.
    #[test]
    fn rsync_guards_a_protected_destination_issue_478() {
        for command in [
            "rsync /tmp/evil /home/user/.ssh/authorized_keys",
            "rsync -a /tmp/evil /home/user/.ssh/authorized_keys",
            "rsync /tmp/evil /home/user/.ssh/id_rsa",
            "rsync /tmp/evil /home/user/.bashrc",
            "rsync /tmp/evil /etc/shadow",
            // A directory destination: the command text names no protected
            // file, the source placed into it is the protected file.
            "rsync -av /tmp/keys/authorized_keys /home/user/.ssh/",
            // Option forms that must not hide the destination.
            "rsync -e ssh /tmp/evil /home/user/.ssh/authorized_keys",
            "rsync -ave ssh /tmp/evil /home/user/.ssh/authorized_keys",
            "rsync --exclude '*.log' /tmp/evil /home/user/.ssh/authorized_keys",
            "rsync --exclude='*.log' /tmp/evil /home/user/.ssh/authorized_keys",
            "rsync -a -- /tmp/evil /home/user/.ssh/authorized_keys",
        ] {
            assert!(
                hit(command).is_some(),
                "rsync must guard its destination like every other writer: {command}"
            );
        }
    }

    /// The other half: rsync's own option grammar, and the shapes that are not
    /// a protected write at all.
    ///
    /// The trailing-option rows are the reason rsync does not reuse
    /// `classify_copy`'s grammar. cp has no option that takes a following word,
    /// so reading one as an operand there is impossible; in rsync it would make
    /// the option's VALUE the last operand, and the last operand is the
    /// destination. Each row below would be a false positive on a command that
    /// writes only into /tmp.
    #[test]
    fn rsync_option_values_are_not_the_destination_issue_478() {
        for command in [
            "rsync /tmp/a /tmp/b --exclude /home/user/.ssh/id_rsa",
            "rsync /tmp/a /tmp/b --link-dest /home/user/.ssh/id_rsa",
            "rsync /tmp/a /tmp/b --files-from /home/user/.ssh/id_rsa",
            "rsync /tmp/a /tmp/b -e /home/user/.ssh/id_rsa",
            // Ordinary syncs.
            "rsync -a /tmp/src/ /tmp/dst/",
            "rsync -a ./build/ /tmp/out/",
            "rsync -a /home/user/project/ /tmp/backup/",
            // Public key material is not credential material.
            "rsync /tmp/evil /home/user/.ssh/id_rsa.pub",
            // Reading FROM a protected path is not a protected write; the
            // `rsync-sensitive-then-delete` rule owns that concern.
            "rsync /home/user/.ssh/id_rsa /tmp/backup/",
            // A remote destination names a path on another machine, which this
            // table cannot resolve, so it is declined rather than judged
            // against the wrong root.
            "rsync /tmp/evil remote:/home/user/.ssh/authorized_keys",
            "rsync /tmp/evil user@host:/home/user/.ssh/authorized_keys",
            "rsync /tmp/evil rsync://host/module/x",
        ] {
            assert!(
                hit(command).is_none(),
                "rsync must not report a protected write here: {command}"
            );
        }
    }

    /// `known_hosts` keeps its append carve-out under rsync too.
    ///
    /// rsync always replaces rather than appends, so the carve-out that lets a
    /// `tee -a` add a host key does not apply to it -- and that is the point of
    /// asserting it: the mode is a property of the writer, not of the path.
    #[test]
    fn rsync_replaces_rather_than_appends_issue_478() {
        assert!(
            hit("rsync /tmp/evil /home/user/.ssh/known_hosts").is_some(),
            "rsync rewrites known_hosts wholesale, which is not the append the \
             carve-out permits"
        );
    }

    /// Every rule name this module reports must exist as a pack entry.
    ///
    /// `destructive_pattern!` takes a string literal, so the id in
    /// `filesystem.rs` and the const here are two spellings of one name with
    /// nothing tying them together. #460 was exactly this shape one layer up —
    /// a rule that looked right at its definition and decided nothing in
    /// production — so the link is asserted rather than assumed.
    #[test]
    fn both_rule_names_are_registered_pack_rules() {
        let pack = crate::packs::core::filesystem::create_pack();
        let names: Vec<&str> = pack.guidance_rule_names().collect();
        for rule in [
            CREDENTIAL_FILE_WRITE_NAME,
            GIT_INTERNALS_WRITE_NAME,
            GIT_REDIRECT_TRUNCATE_NAME,
            GIT_REDIRECT_APPEND_NAME,
        ] {
            assert!(
                names.contains(&rule),
                "{rule} is reported by the classifier but is not a rule in core.filesystem, \
                 so it has no guidance, no docs entry and no allowlist target; got {names:?}"
            );
        }
        assert_ne!(
            CREDENTIAL_FILE_WRITE_NAME, GIT_INTERNALS_WRITE_NAME,
            "the whole point of the second name is that allowing one does not allow the other"
        );
    }

    /// #457: `.git/` reaches the writers a redirect rule cannot see.
    #[test]
    fn git_internals_are_reached_by_every_non_redirect_writer() {
        for command in [
            "tee .git/config",
            "tee -a .git/config",
            "echo x | sponge .git/config",
            "cp /tmp/x .git/config",
            "mv /tmp/x .git/config",
            "install /tmp/x .git/config",
            "sed -i s/a/b/ .git/config",
            "tee repo/.git/hooks/pre-commit",
            "tee ./.git/config",
        ] {
            let found = hit(command).unwrap_or_else(|| panic!("must deny: {command}"));
            assert_eq!(
                found.rule, GIT_INTERNALS_WRITE_NAME,
                "{command} must deny under its own rule, not the credential one"
            );
        }
    }

    /// A redirect into `.git/` stays with the rules that already own it.
    ///
    /// The classifier runs ahead of every redirect rule, so if it answered
    /// here it would rename their hits and break allowlists that name them.
    #[test]
    fn git_internals_redirects_are_left_to_the_redirect_rules() {
        for command in [
            "cat > .git/config",
            "cat >> .git/config",
            "cat >| .git/config",
        ] {
            assert!(
                hit(command).is_none(),
                "{command} must be left to redirect-*-git-internals-relative"
            );
        }
        // …and the same exclusion must not leak to real credentials, whose
        // redirect spellings the classifier has always owned.
        assert_eq!(
            hit("cat > .ssh/id_rsa")
                .expect("ssh redirect still denies")
                .rule,
            CREDENTIAL_FILE_WRITE_NAME
        );
    }

    #[test]
    fn git_redirect_writes_use_declared_shell_decoding_and_original_spans() {
        with_runtime_home(None, || {
            for dialect in [
                ShellDialect::PowerShell,
                ShellDialect::Cmd,
                ShellDialect::Unknown,
            ] {
                for target in [
                    r".git\config",
                    ".git/config",
                    r"sub\.git\hooks\pre-commit",
                    r#""C:\my repo\.git\HEAD""#,
                ] {
                    for (operator, rule) in [
                        (">", GIT_REDIRECT_TRUNCATE_NAME),
                        (">>", GIT_REDIRECT_APPEND_NAME),
                    ] {
                        let command = format!("echo x {operator} {target}");
                        let hits = classify_git_redirect_writes(&command, dialect);
                        assert_eq!(hits.len(), 1, "{dialect:?}: {command}: {hits:?}");
                        assert_eq!(hits[0].rule, rule, "{dialect:?}: {command}");
                        assert_eq!(&command[hits[0].span.clone()], target);
                    }
                }
            }
            for command in [r"echo x > .git\config", r"echo x >> '.git\config'"] {
                assert!(
                    classify_git_redirect_writes(command, ShellDialect::Posix).is_empty(),
                    "{command}"
                );
            }
            let escaped =
                classify_git_redirect_writes(r"echo x > .g\it/config", ShellDialect::Posix);
            assert_eq!(escaped.len(), 1);
            assert_eq!(escaped[0].rule, GIT_REDIRECT_TRUNCATE_NAME);
        });
    }

    #[test]
    fn git_redirect_writes_retain_all_targets_without_hiding_credentials() {
        with_runtime_home(None, || {
            let command = "echo x > .git/config >> .git/HEAD > .git/index >> .ssh/authorized_keys";
            for dialect in [
                ShellDialect::Posix,
                ShellDialect::PowerShell,
                ShellDialect::Cmd,
                ShellDialect::Unknown,
            ] {
                let hits = classify_git_redirect_writes(command, dialect);
                assert_eq!(
                    hits.iter().map(|hit| hit.rule).collect::<Vec<_>>(),
                    [
                        GIT_REDIRECT_TRUNCATE_NAME,
                        GIT_REDIRECT_APPEND_NAME,
                        GIT_REDIRECT_TRUNCATE_NAME
                    ],
                    "{dialect:?}"
                );
                assert_eq!(
                    classify_credential_file_write(command, dialect)
                        .expect("later credential write")
                        .rule,
                    CREDENTIAL_FILE_WRITE_NAME,
                    "{dialect:?}"
                );
            }
            for command in [
                "echo x > {.git/config,.ssh/authorized_keys}",
                "echo x > {.ssh/authorized_keys,.git/config}",
            ] {
                assert_eq!(
                    classify_git_redirect_writes(command, ShellDialect::Posix).len(),
                    1,
                    "{command}"
                );
                assert_eq!(
                    hit(command).expect("credential alternative").rule,
                    CREDENTIAL_FILE_WRITE_NAME,
                    "{command}"
                );
            }
        });
    }

    #[test]
    fn git_redirect_writes_leave_data_reads_and_neighbor_paths_untouched() {
        with_runtime_home(None, || {
            for dialect in [
                ShellDialect::Posix,
                ShellDialect::PowerShell,
                ShellDialect::Cmd,
                ShellDialect::Unknown,
            ] {
                for command in [
                    r#"echo "> .git\config""#,
                    "cat .git/config",
                    "tee .git/config",
                    "echo x > .gitignore",
                    "echo x > .github/config",
                    "echo x > my.git/config",
                    "echo x > notes.txt",
                    "echo x 2>&1",
                ] {
                    assert!(
                        classify_git_redirect_writes(command, dialect).is_empty(),
                        "{dialect:?}: {command}"
                    );
                }
            }
            assert_eq!(
                hit("tee .git/config")
                    .expect("non-redirect writer retains its rule")
                    .rule,
                GIT_INTERNALS_WRITE_NAME
            );
        });
    }

    /// The neighbours that are not inside `.git/` and must stay ordinary.
    #[test]
    fn git_adjacent_files_are_not_git_internals() {
        for command in [
            "tee .gitignore",
            "tee .gitattributes",
            "tee .gitmodules",
            "tee .github/workflows/ci.yml",
            "tee src/git/config",
            "tee .git",
        ] {
            assert!(hit(command).is_none(), "must stay allowed: {command}");
        }
    }

    /// The gate requires a `.git` boundary, so common neighbours never reach the
    /// classifier at all — the hot-path half of the same decision.
    #[test]
    fn the_gate_ignores_git_adjacent_tokens() {
        for command in [
            "cat .gitignore",
            "rg TODO .github/workflows",
            "git status",
            "tee .gitmodules",
        ] {
            assert!(
                !may_name_protected_path(command),
                "{command} must not wake the classifier"
            );
        }
        assert!(may_name_protected_path("tee .git/config"));
        assert!(may_name_protected_path("tar -xf payload.tar -C .git"));
        assert!(may_name_protected_path("7z x payload.7z -o'.git'"));
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
            "~/.config/hub",
            "~/.pgpass",
            "~/.my.cnf",
            "~/.cargo/credentials.toml",
            "~/.cargo/credentials",
            "~/.gem/credentials",
            "~/.vault-token",
            "~/.terraform.d/credentials.tfrc.json",
            "~/.config/gcloud/application_default_credentials.json",
            "~/.config/gcloud/credentials.db",
            "~/.config/gcloud/access_tokens.db",
            "~/.config/gcloud/legacy_credentials/me@example.com/adc.json",
            "~/.azure/accessTokens.json",
            "~/.azure/msal_token_cache.json",
            "~/.boto",
            "~/.s3cfg",
            "~/.password-store/email/work.gpg",
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
            "nice -n 5 tee ~/.ssh/authorized_keys",
            "nice --adjustment 5 tee ~/.ssh/authorized_keys",
            "env -u UNUSED tee ~/.ssh/authorized_keys",
            "sudo -u root nice -n 5 tee ~/.ssh/authorized_keys",
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
    fn wrapper_value_options_require_operands_issue_521() {
        let wrappers: &[(&str, &[&str])] = &[
            (
                "sudo",
                &[
                    "-u",
                    "-g",
                    "-p",
                    "-C",
                    "-D",
                    "-h",
                    "-r",
                    "-t",
                    "-T",
                    "-U",
                    "--user",
                    "--group",
                    "--prompt",
                    "--close-from",
                    "--chdir",
                    "--host",
                    "--role",
                    "--type",
                    "--command-timeout",
                    "--other-user",
                ],
            ),
            ("doas", &["-u", "-C"]),
            ("env", &["-u", "-C", "--unset", "--chdir"]),
            ("nice", &["-n", "--adjustment"]),
            (
                "ionice",
                &["-c", "-n", "-p", "--class", "--classdata", "--pid"],
            ),
            ("timeout", &["-s", "-k", "--signal", "--kill-after"]),
            (
                "stdbuf",
                &["-i", "-o", "-e", "--input", "--output", "--error"],
            ),
            ("exec", &["-a"]),
            ("caffeinate", &["-t", "-w"]),
        ];
        assert!(strip_prefixes(&[]).is_none());
        for &(wrapper, options) in wrappers {
            let (wrapper_word, _) = read_word(wrapper, 0);
            assert_eq!(skip_wrapper(wrapper, &[]), Some(0), "{wrapper}");
            assert!(strip_prefixes(&[&wrapper_word]).is_none(), "{wrapper}");
            for option in options {
                let (option_word, _) = read_word(option, 0);
                assert_eq!(
                    skip_wrapper(wrapper, &[&option_word]),
                    None,
                    "{wrapper} {option} needs an operand"
                );
                assert!(
                    strip_prefixes(&[&wrapper_word, &option_word]).is_none(),
                    "{wrapper} {option} must not produce an invalid slice"
                );
                // An explicit empty word is still an operand; consuming it
                // leaves no command and must also stop without a panic.
                let (empty_operand, _) = read_word("''", 0);
                assert_eq!(
                    skip_wrapper(wrapper, &[&option_word, &empty_operand]),
                    Some(2),
                    "{wrapper} {option} ''"
                );
                assert!(
                    strip_prefixes(&[&wrapper_word, &option_word, &empty_operand]).is_none(),
                    "{wrapper} {option} '' has no wrapped command"
                );
                // Redirections are removed from argv and cannot supply an
                // option's missing value, but they still open their target
                // before the malformed wrapper command fails.
                for redirect in [">", "2>"] {
                    allowed(&format!("{wrapper} {option} {redirect}~/notes.txt"));
                    denied(&format!(
                        "{wrapper} {option} {redirect}~/.ssh/authorized_keys"
                    ));
                }
            }
        }
    }

    #[test]
    fn wrapper_prefixes_end_safely_without_a_command_issue_521() {
        for command in [
            "command",
            "nohup",
            "builtin",
            "time",
            "chronic",
            "setsid",
            "unbuffer",
            "sudo --",
            "env --",
            "env UNUSED=1",
            "nice -n5",
            "nice --adjustment=5",
            "nice -n 5",
            "timeout -s TERM 5",
            "sudo nice -n",
            "sudo -Eu",
            "sudo -E --user",
        ] {
            allowed(&format!("{command} >~/notes.txt"));
            denied(&format!("{command} 2>~/.ssh/authorized_keys"));
        }
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

    /// #477: this test used to assert the opposite for PowerShell, which is
    /// what let an appending write to a login file through from a PowerShell
    /// tool. The dialect now decides how the words are read, not whether they
    /// are judged. Cmd is the control: it never expands `~`, so there the
    /// same text names a directory literally called `~`.
    #[test]
    fn every_dialect_is_classified_by_its_own_expansion_rules() {
        for dialect in [
            ShellDialect::Posix,
            ShellDialect::PowerShell,
            ShellDialect::Unknown,
        ] {
            assert!(
                classify_credential_file_write("echo x >> ~/.zshrc", dialect).is_some(),
                "{dialect:?}"
            );
        }
        assert!(classify_credential_file_write("echo x >> ~/.zshrc", ShellDialect::Cmd).is_none());
        assert!(
            classify_credential_file_write("echo x >> %USERPROFILE%/.zshrc", ShellDialect::Cmd)
                .is_some()
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

    /// Spellings of the same file must reach the same verdict — driven off
    /// `ENTRIES` rather than a hand-kept list, so a new protected path is
    /// covered the day it is added.
    ///
    /// Both bugs recorded in the modules below were one spelling of one path
    /// disagreeing with another (`~/.SSH/id_rsa` vs `~/.ssh/id_rsa`;
    /// `~/projects/app/.ssh/id_rsa` vs `projects/app/.ssh/id_rsa`), and both
    /// were found by hand. These assert the property instead.
    mod spelling_parity {
        use super::hit;
        use crate::packs::core::credential_files::shell::{
            ENTRIES, Entry, RELATIVE_ANCHORS, RELATIVE_FILE_ANCHORS, Root,
        };

        /// A concrete protected file for `entry`; a directory needs one in it.
        fn probe_path(entry: &Entry) -> String {
            let mut comps: Vec<&str> = entry.comps.to_vec();
            if entry.dir {
                comps.push("probe");
            }
            comps.join("/")
        }

        fn denies(command: &str) -> bool {
            hit(command).is_some()
        }

        /// These loops are the whole test, so an empty or filtered-away table
        /// would make all three pass while asserting nothing — the failure mode
        /// `tests/repro_442_source_modules_are_declared.rs` exists to catch.
        #[test]
        fn the_table_these_loops_walk_is_not_empty() {
            let home = ENTRIES.iter().filter(|e| e.root == Root::Home).count();
            let etc = ENTRIES.iter().filter(|e| e.root == Root::Etc).count();
            assert!(home >= 15, "only {home} home entries to check");
            assert!(etc >= 5, "only {etc} /etc entries to check");
        }

        #[test]
        fn every_rooted_spelling_of_a_home_entry_agrees() {
            for entry in ENTRIES.iter().filter(|entry| entry.root == Root::Home) {
                let path = probe_path(entry);
                assert!(
                    denies(&format!("tee ~/{path}")),
                    "~/{path} should be protected"
                );
                for spelling in [
                    format!("$HOME/{path}"),
                    format!("/Users/someone/{path}"),
                    format!("/home/someone/{path}"),
                    format!("~someone/{path}"),
                    format!("/root/{path}"),
                ] {
                    assert!(
                        denies(&format!("tee {spelling}")),
                        "`{spelling}` disagrees with `~/{path}`"
                    );
                }
            }
        }

        #[test]
        fn an_upper_case_spelling_of_every_entry_agrees() {
            for entry in ENTRIES {
                let path = probe_path(entry);
                let prefix = if entry.root == Root::Home {
                    "~/"
                } else {
                    "/etc/"
                };
                let lower = denies(&format!("tee {prefix}{path}"));
                let upper = denies(&format!("tee {prefix}{}", path.to_ascii_uppercase()));
                assert_eq!(
                    lower, upper,
                    "case spellings of `{prefix}{path}` disagree — on APFS and NTFS they are \
                     the same file"
                );
            }
        }

        #[test]
        fn a_relative_spelling_denies_exactly_when_the_anchor_lists_say_so() {
            // The deliberate exclusions (`.netrc`, `.npmrc`, `.pypirc`,
            // `.git-credentials`, `_netrc`, `.config/gh/hosts.yml`) are a
            // decision, so the test states it rather than listing paths twice.
            for entry in ENTRIES.iter().filter(|entry| entry.root == Root::Home) {
                let path = probe_path(entry);
                let first = entry.comps[0];
                let anchored = RELATIVE_ANCHORS.contains(&first)
                    || (entry.comps.len() == 1
                        && !entry.dir
                        && RELATIVE_FILE_ANCHORS.contains(&first));
                assert_eq!(
                    denies(&format!("tee {path}")),
                    anchored,
                    "relative `{path}`: the anchor lists say anchored={anchored}"
                );
            }
        }
    }

    /// #407: a relative spelling names the same credential file the rooted one
    /// does, and only the rooted one was being judged.
    mod relative_anchors {
        use super::{allowed, denied, hit};
        use crate::packs::core::credential_files::shell::{
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
                // `rooted_prefixes` declines these, and the anchor decides them
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

    fn unquoted_word(text: &str) -> Word {
        let text: Vec<char> = text.chars().collect();
        Word {
            literal: vec![false; text.len()],
            text,
            range: 0..0,
            glued_paren: false,
        }
    }

    /// Fourth review of df1e779. A list inside a comma-less list still
    /// expands (`{{a/,b}}` is `{a/}` and `{b}`), and the scan skipped it
    /// whole, so this `/etc/sudoers` write was allowed; and the scan restarted
    /// at every unclosed `{`, quadratic in them (30,000 held the hook ~3 s,
    /// `{,` pairs ~6 s), while a 20,000-deep nest recursed 20,000 frames.
    #[test]
    fn slash_brace_lists_are_found_in_linear_time_inside_literal_braces() {
        assert!(hit("echo x | tee /tmp/{{a/,b}}/../../etc/sudoers").is_some());
        assert!(hit("echo x | tee /tmp/{{a/,b}}/c.txt").is_none());

        let started = std::time::Instant::now();
        let unclosed = unquoted_word(&format!("/tmp/{}/x", "{,".repeat(200_000)));
        assert!(matches!(
            slash_brace_alternatives(&unclosed, MAX_BRACE_ALTERNATIVES),
            BraceAlternatives::NoList
        ));
        let nested = unquoted_word(&format!(
            "/tmp/{}a/,b}}{}",
            "{".repeat(20_000),
            ",c}".repeat(19_999)
        ));
        assert!(matches!(
            slash_brace_alternatives(&nested, MAX_BRACE_ALTERNATIVES),
            BraceAlternatives::TooMany
        ));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        // Exactly the cap still expands: six two-way lists are 64 words.
        let sixty_four = unquoted_word(&format!("/tmp/x{}", "{a/,b}".repeat(6)));
        assert!(matches!(
            slash_brace_alternatives(&sixty_four, MAX_BRACE_ALTERNATIVES),
            BraceAlternatives::Words(words) if words.len() == 64
        ));
    }
}
