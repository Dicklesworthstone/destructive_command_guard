//! Permissions patterns - protections against dangerous permission changes.
//!
//! This includes patterns for:
//! - chmod 777 (world writable)
//! - chmod -R on system directories
//! - chown -R on system directories
//! - setfacl with dangerous patterns

use crate::packs::regex_engine::LazyCompiledRegex;
use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Anchor a read-only exemption to the command the segment actually runs.
///
/// Mirrors `system::disk`'s macro of the same shape. The sudo group admits only
/// `-n`, never arbitrary options: `sudo -u stat chmod -R 777 /etc` passes `stat`
/// as `-u`'s *value*, so a prefix that skipped `-\S+` would find the tool name
/// it was looking for and exempt the chmod behind it. The evaluator's sudo table
/// knows `-u` consumes a value and normalises that command to `chmod …` today,
/// which is why nothing was reachable through it — but an exemption that can
/// disarm a whole pack should not depend on another layer to stay sound (#448).
macro_rules! perms_safe_pattern {
    ($name:literal, $body:expr) => {
        SafePattern {
            name: $name,
            regex: LazyCompiledRegex::new(concat!(
                r"^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&|<>()\x22'\\$`*?\[\]{}~=]+/)?",
                $body
            )),
        }
    };
}

// ============================================================================
// Suggestion constants (must be 'static for the pattern struct)
// ============================================================================

const CHMOD_777_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "chmod 755 {path}",
        "Owner can write; others can read/execute (safer default)",
    ),
    PatternSuggestion::new(
        "chmod u+x {path}",
        "Only add execute for owner instead of world-writable permissions",
    ),
];

const CHOWN_RECURSIVE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "chown {user} {path}",
        "Change ownership of a single path first",
    ),
    PatternSuggestion::new(
        "find {path} -maxdepth 1 -exec chown {user} {} \\;",
        "Limit ownership changes to top-level entries",
    ),
];

/// Create the Permissions pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "system.permissions".to_string(),
        name: "Permissions",
        description: "Protects against dangerous permission changes like chmod 777, \
                      recursive chmod/chown on system directories",
        // The Windows verbs are listed alongside the POSIX ones because this
        // pack now claims both spellings of the same shapes. Quick-rejection is
        // ASCII case-insensitive, so `ICACLS`/`TakeOwn` need no separate entry.
        keywords: &[
            "chmod", "chown", "chgrp", "setfacl", "icacls", "cacls", "takeown",
        ],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // A non-recursive chmod on an ordinary file is routine, so it is
        // exempted. The exemption keyed only on "the target does not begin with
        // `/`", and a safe match short-circuits the whole pack, so every other
        // way of naming an absolute or home path walked straight through it:
        //
        //   chmod 777 /etc/shadow        denied
        //   chmod 777 "/etc/shadow"      ALLOWED   <- same file, one quote
        //   chmod 777 ~/.ssh/id_rsa      ALLOWED
        //   chmod 777 $HOME/.ssh/id_rsa  ALLOWED
        //   chmod 4755 ~/bin/tool        ALLOWED   <- setuid, same cause
        //
        // The quoted spelling is the sharpest: the shell unquotes it to the
        // identical path, so the deny and the allow name the same file. This is
        // the `~`/`$HOME` family that #489 fixed for the RECURSIVE rules, in
        // the one place that is a safe pattern rather than a destructive one —
        // and `quote_bypass_does_not_evade_system_dir_block` pinned only the
        // recursive half.
        //
        // Excluding `~`, `$`, `"` and `'` alongside `/` costs nothing real:
        // those four never begin an ordinary relative filename, and a target
        // that is genuinely plain (`notes.txt`, `./build`) still matches. The
        // exemption is narrowed, never a destructive pattern widened.
        safe_pattern!(
            "chmod-non-recursive",
            r#"chmod\s+(?!-[rR])(?:\d{3,4}|[ugoa][+-][rwxXst]+)\s+[^/~$"']"#
        ),
        // stat is safe (read-only), but only when stat is what runs. As a bare
        // word it matched anywhere in the segment, and a safe match
        // short-circuits the pack, so `chmod -R 777 /etc --reference=/tmp/stat`
        // was allowed while `chmod -R 777 /etc` was denied (#448).
        perms_safe_pattern!("stat", r"stat\b"),
        // ls -l is safe, but only when ls is what runs. Unanchored, the `ls
        // <anything> -l` shape could be found inside another command's
        // arguments, and a safe match short-circuits the pack: `chmod -R 777
        // /etc ls -l` was allowed while `chmod -R 777 /etc` was denied. The
        // two-segment spelling `ls -l; chmod -R 777 /etc` was already denied,
        // because segments are judged separately (#448).
        perms_safe_pattern!("ls-perms", r"ls\b.*-[a-zA-Z]*l"),
        // getfacl and namei are read-only — anchored for the reason given on
        // `stat`; `chown -R nobody /etc --reference=/tmp/getfacl` was allowed.
        perms_safe_pattern!("getfacl", r"getfacl\b"),
        perms_safe_pattern!("namei", r"namei\b"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // chmod 777 (world writable)
        // These patterns use unbounded .* gap-matchers, so on a full command
        // line they could pair a flag or path from a *different* command in a
        // chain (`chmod 600 f && grep -rn …`, issue #287). The evaluator
        // therefore scopes this pack to per-segment evaluation: full-command
        // matches whose span crosses a segment boundary are discarded (see
        // SEGMENT_SCOPED_PACKS in evaluator.rs). A character-class bound like
        // [^;&|]* is NOT equivalent — it matches newlines (still cross-command)
        // and breaks on separators inside quotes or $() (false negatives).
        destructive_pattern!(
            "chmod-777",
            r#"chmod\s+(?:.*\s+)?["'=]?0*777(?:[\s"']|$)"#,
            "chmod 777 makes files world-writable. This is a security risk.",
            High,
            "chmod 777 grants read/write/execute to everyone. This can expose sensitive \
             files and allow unauthorized modification. Prefer least-privilege permissions \
             that only grant the specific access needed.",
            CHMOD_777_SUGGESTIONS,
            executables = ["chmod"]
        ),
        // chmod -R on root or system directories
        // `['"]?` before the leading `/` so quoted variants like
        // `chmod -R "/etc"` are caught — the shell unquotes to `/etc`.
        // Bare `/` gets its own alternative (`['"]?(?:\s|$)`): the named-dir
        // alternatives end in `\b`, which can never match after a bare `/`
        // at end-of-string because both sides are non-word (issue #301).
        // `/home` (and macOS `/Users`) is scoped to the home root or a whole
        // single-user home (`home(?:/user)?`, where `~/.ssh` lives) — NOT
        // deeper paths, so a routine `chmod -R /home/user/project` stays
        // allowed while `chmod -R /home` (locks out every account) is blocked
        // (issue #301; `/Users` parity mirrors the filesystem #325 fix).
        // `~` and `$HOME` name the SAME directory `/home/user` does, and were
        // the only spellings that escaped: `chmod -R 000 /home/user` denied
        // while `chmod -R 000 ~`, `~/` and `$HOME` all allowed. An agent writes
        // the short form, so the covered spelling was the one it never uses.
        //
        // The depth carve-out above is preserved exactly: `~/project` is the
        // `/home/user/project` case and stays allowed, because the home
        // alternatives only match at end-of-argument.
        //
        // Quoting follows the shell rather than being approximated. A tilde
        // expands only when UNQUOTED, so `"~"` is a directory literally named
        // `~` and is deliberately not matched; `$HOME` expands inside double
        // quotes but not single ones, so it takes an optional `"` only.
        destructive_pattern!(
            "chmod-recursive-root",
            r#"chmod\s+(?:.*(?:-[rR]|--recursive)).*\s+(?:['"]?/(?:(?:bin|boot|dev|etc|lib64|lib|opt|proc|root|run|sbin|srv|sys|usr|var)\b|(?:home|Users)(?:/[^/\s"']+)?/?(?:[\s"']|$)|['"]?(?:\s|$))|~/?(?:[\s"']|$)|"?\$\{?HOME\}?/?(?:[\s"']|$))"#,
            "chmod -R on system directories can break system permissions.",
            Critical,
            "Recursively changing permissions on system directories can render the system \
             unbootable, break package management, and disrupt every running service. Many \
             system files require specific permission bits to function correctly.\n\n\
             Check current permissions first:\n  \
             ls -la /path/to/directory\n\n\
             Apply changes to a specific subdirectory instead of the whole tree.",
            executables = ["chmod"]
        ),
        // chown -R on root or system directories
        destructive_pattern!(
            "chown-recursive-root",
            r#"chown\s+(?:.*(?:-[rR]|--recursive)).*\s+(?:['"]?/(?:(?:bin|boot|dev|etc|lib64|lib|opt|proc|root|run|sbin|srv|sys|usr|var)\b|(?:home|Users)(?:/[^/\s"']+)?/?(?:[\s"']|$)|['"]?(?:\s|$))|~/?(?:[\s"']|$)|"?\$\{?HOME\}?/?(?:[\s"']|$))"#,
            "chown -R on system directories can break system ownership.",
            High,
            "Recursive ownership changes on system directories can disrupt services, \
             break package-managed files, and be difficult to undo. Start with a single \
             path or a shallow find before applying broader changes.",
            CHOWN_RECURSIVE_SUGGESTIONS,
            executables = ["chown"]
        ),
        // `chgrp` was in this pack's keyword row from the start but no rule
        // ever claimed it, so the keyword selected the pack and nothing
        // matched: `chown -R nobody /` denied while `chgrp -R nogroup /`
        // allowed. Group ownership is the same access-control surface owner
        // ownership is -- a recursive chgrp across `/usr` or `/etc` breaks
        // every group-readable service file the same way.
        //
        // Same target set and same spellings as the two rules above, so the
        // three answer alike; severity matches `chown-recursive-root` because
        // the effect is the same kind of change to the same metadata.
        destructive_pattern!(
            "chgrp-recursive-root",
            r#"chgrp\s+(?:.*(?:-[rR]|--recursive)).*\s+(?:['"]?/(?:(?:bin|boot|dev|etc|lib64|lib|opt|proc|root|run|sbin|srv|sys|usr|var)\b|(?:home|Users)(?:/[^/\s"']+)?/?(?:[\s"']|$)|['"]?(?:\s|$))|~/?(?:[\s"']|$)|"?\$\{?HOME\}?/?(?:[\s"']|$))"#,
            "chgrp -R on system directories can break system group ownership.",
            High,
            "Recursive group changes on system directories can disrupt services that \
             rely on group-readable or group-writable files, break package-managed \
             ownership, and be difficult to undo. Start with a single path or a \
             shallow find before applying broader changes.\n\n\
             Check current ownership first:\n  \
             ls -la /path/to/directory",
            executables = ["chgrp"]
        ),
        // ----- Windows equivalents of the three rules above -----
        //
        // This pack was POSIX-only: `chown -R nobody C:\Windows` has no POSIX
        // spelling, and the Windows one (`takeown /f C:\Windows /r`) reached no
        // rule. These are the SAME shapes the pack already claims -- a
        // recursive permission or ownership change across a system tree, and a
        // world-writable grant -- spelled the way Windows spells them, so they
        // are a missing route into stated scope rather than new scope.
        //
        // The target set mirrors the POSIX one deliberately, including its
        // depth carve-out: `C:\Users` and a whole single-user profile
        // `C:\Users\bob` are blocked, while `C:\Users\bob\project` is NOT,
        // exactly as `/home` and `/home/user` are blocked and
        // `/home/user/project` is allowed (#301). `%SystemRoot%`-style
        // expansions are recognised because that is how a script writes them.
        destructive_pattern!(
            "icacls-recursive-system",
            r#"(?i)\b(?:icacls|cacls)\b(?=[^;&|]*\s/t(?:\s|$))[^;&|]*?\s(?:["']?[A-Za-z]:[\\/](?:(?:Windows|ProgramData|System32)\b|Program Files(?: \(x86\))?|Users(?:[\\/][^\\/\s"']+)?[\\/]?(?:["'\s]|$)|["']?(?:\s|$))|%(?:SystemRoot|windir|SystemDrive|ProgramFiles(?:\(x86\))?|ProgramData)%|\$env:(?:SystemRoot|windir|ProgramFiles|ProgramData))"#,
            "icacls /t on a Windows system tree rewrites ACLs recursively and can break the system.",
            Critical,
            "`/t` applies the ACL change to every file and subdirectory. Across \
             `C:\\Windows`, `C:\\Program Files` or the drive root that rewrites the \
             access control the OS and every installed product depend on, and Windows \
             does not keep an undo: the previous ACLs are gone once the walk starts. \
             Service accounts lose the rights they were granted at install time, and \
             SFC/DISM will not restore ACLs.\n\n\
             Inspect first:\n  \
             icacls <path>\n\n\
             Save the current ACLs before changing anything:\n  \
             icacls <path> /save acl.txt /t\n  \
             icacls <path> /restore acl.txt\n\n\
             Apply the change to the specific subdirectory that needs it instead of \
             the whole tree.",
            executables = ["icacls", "cacls"]
        ),
        destructive_pattern!(
            "takeown-recursive-system",
            r#"(?i)\btakeown\b(?=[^;&|]*\s/r(?:\s|$))[^;&|]*?\s/f\s+(?:["']?[A-Za-z]:[\\/](?:(?:Windows|ProgramData|System32)\b|Program Files(?: \(x86\))?|Users(?:[\\/][^\\/\s"']+)?[\\/]?(?:["'\s]|$)|["']?(?:\s|$))|%(?:SystemRoot|windir|SystemDrive|ProgramFiles(?:\(x86\))?|ProgramData)%|\$env:(?:SystemRoot|windir|ProgramFiles|ProgramData))"#,
            "takeown /r on a Windows system tree seizes ownership recursively and is hard to undo.",
            High,
            "`takeown /r` makes the current user the owner of every file in the tree. \
             On a system tree that displaces `TrustedInstaller`, which is what Windows \
             Update and the servicing stack rely on to replace protected files, so \
             updates and repair operations begin to fail. Restoring the original owner \
             is manual and per-file.\n\n\
             Check the current owner first:\n  \
             icacls <path>\n\n\
             Take ownership of the single path that needs it rather than the tree, and \
             record what it was so it can be handed back.",
            executables = ["takeown"]
        ),
        // The Windows spelling of `chmod 777`: a full-control, modify, or write
        // grant to Everyone. `:R` (read) and `:RX` (read+execute) are
        // deliberately unmatched -- widening a read grant is not the same act,
        // and matching it would fire on ordinary share setup.
        destructive_pattern!(
            "icacls-grant-everyone",
            r"(?i)\b(?:icacls|cacls)\b[^;&|]*\b(?:Everyone|Todos|BUILTIN\\Users)\s*:\s*(?:\([A-Za-z]{2}\)\s*)*\(?[FMW](?=[)\s,;&|]|$)",
            "granting Everyone full/modify/write access makes the target world-writable.",
            High,
            "`Everyone` includes every authenticated and guest principal on the machine, \
             so an `F` (full), `M` (modify) or `W` (write) grant lets any local account \
             replace the contents -- and `F` additionally lets it rewrite the ACL, so the \
             grant cannot be relied on to stay as set. This is the Windows spelling of \
             `chmod 777`.\n\n\
             Grant the specific principal the specific right it needs:\n  \
             icacls <path> /grant \"DOMAIN\\user\":(RX)\n\n\
             If a service needs write access, grant it to that service's account rather \
             than to Everyone. Read-only sharing (`:R` / `:RX`) is unaffected by this rule.",
            executables = ["icacls", "cacls"]
        ),
        // chmod u+s (setuid)
        destructive_pattern!(
            "chmod-setuid",
            r"chmod\s+.*u\+s|chmod\s+[4-7]\d{3}",
            "Setting setuid bit (chmod u+s) is a security-sensitive operation.",
            High,
            "The setuid bit causes a program to run with the file owner's privileges \
             regardless of who executes it. If set on the wrong binary, any user can \
             gain elevated access. This is a common privilege escalation vector.\n\n\
             Verify the file and owner first:\n  \
             ls -la <file>\n\n\
             Find existing setuid files:\n  \
             find / -perm -4000 -type f 2>/dev/null",
            executables = ["chmod"]
        ),
        // chmod g+s (setgid)
        destructive_pattern!(
            "chmod-setgid",
            r"chmod\s+.*g\+s|chmod\s+[2367]\d{3}",
            "Setting setgid bit (chmod g+s) is a security-sensitive operation.",
            High,
            "The setgid bit on an executable causes it to run with the file group's \
             privileges. On a directory, new files inherit the directory's group. \
             Misapplication can grant unintended group access to sensitive resources.\n\n\
             Check current group ownership:\n  \
             ls -la <file>\n\n\
             Find existing setgid files:\n  \
             find / -perm -2000 -type f 2>/dev/null",
            executables = ["chmod"]
        ),
        // chown to root
        destructive_pattern!(
            "chown-to-root",
            r"chown\s+.*root[:\s]",
            "Changing ownership to root should be done carefully.",
            High,
            "Transferring file ownership to root makes the files inaccessible to normal \
             users and may break applications that need to write to those files. Services \
             running as non-root users will lose access.\n\n\
             Check who currently owns the file:\n  \
             ls -la <path>\n\n\
             Consider using group ownership instead:\n  \
             chgrp <group> <path>",
            executables = ["chown"]
        ),
        // setfacl with dangerous patterns
        destructive_pattern!(
            "setfacl-all",
            r#"setfacl\s+.*-[rR].*\s+['"]?/(?:(?:bin|boot|dev|etc|lib64|lib|opt|proc|root|run|sbin|srv|sys|usr|var)\b|(?:home|Users)(?:/[^/\s"']+)?/?(?:[\s"']|$)|['"]?(?:\s|$))"#,
            "setfacl -R on system directories can modify access control across the filesystem.",
            Critical,
            "Recursively modifying ACLs on system directories changes fine-grained access \
             control for every file in the tree. This can override traditional Unix \
             permissions and grant or revoke access in unexpected ways, breaking services \
             and security boundaries.\n\n\
             Review current ACLs first:\n  \
             getfacl <path>\n\n\
             Apply to a specific file instead of recursively:\n  \
             setfacl -m u:<user>:rwx <specific-file>",
            executables = ["setfacl"]
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn read_only_tool_names_in_argument_data_do_not_disarm_the_pack_issue_448() {
        // A safe match short-circuits every destructive pattern in the pack, so
        // `stat`, `getfacl` and `namei` matched as bare words handed any
        // argument the power to switch the pack off. Measured against v0.14.4:
        // each of these was allowed, while the same command without the word
        // was denied.
        let pack = create_pack();
        for command in [
            "chmod -R 777 /etc --reference=/tmp/stat",
            "chmod -R 777 /etc --reference=/tmp/namei",
            "chown -R nobody /etc --reference=/tmp/getfacl",
        ] {
            assert!(
                !pack.matches_safe(command),
                "{command:?} must not match a safe pattern: the read-only tool \
                 name is argument data, not the command being run"
            );
            assert!(
                pack.check(command).is_some(),
                "{command:?} must still be blocked"
            );
        }
    }

    #[test]
    fn ls_long_form_in_argument_data_does_not_disarm_the_pack_issue_448() {
        // `ls\s+.*-l` unanchored could be found inside another command's
        // arguments. `chmod -R 777 /etc ls -l` was allowed against v0.14.4.
        let pack = create_pack();
        for command in ["chmod -R 777 /etc ls -l", "chown -R nobody /etc ls -al"] {
            assert!(
                !pack.matches_safe(command),
                "{command:?} must not be exempted by an `ls -l` found in its arguments"
            );
            assert!(
                pack.check(command).is_some(),
                "{command:?} must still be blocked"
            );
        }
    }

    #[test]
    fn a_read_only_tool_named_as_a_sudo_option_value_is_not_evidence_issue_448() {
        // `sudo -u stat` passes `stat` as the option's VALUE, so an exemption
        // whose prefix skips arbitrary `-\S+` options finds the tool name it is
        // looking for and disarms the pack behind it. The evaluator's sudo
        // table knows `-u` consumes a value and normalises these to the real
        // command, so nothing was reachable through it — but the exemption must
        // not rely on a separate layer to stay sound.
        let pack = create_pack();
        for command in [
            "sudo -u stat chmod -R 777 /etc",
            "sudo -u getfacl chown -R nobody /etc",
            "sudo -u namei chmod -R 777 /etc",
        ] {
            assert!(
                !pack.matches_safe(command),
                "{command:?} runs the destructive tool; the read-only name is an option value"
            );
        }
    }

    #[test]
    fn read_only_permission_inspection_stays_allowed_issue_448() {
        let pack = create_pack();
        for command in [
            "sudo -n stat /etc/passwd",
            "ls -l /etc",
            "ls -la",
            "sudo ls -l /root",
            "/bin/ls -l",
            "stat /etc/passwd",
            "sudo stat -c %a /etc/shadow",
            "/usr/bin/stat /tmp",
            "LC_ALL=C stat /etc/passwd",
            "getfacl /etc",
            "sudo getfacl -R /srv",
            "namei -l /etc/passwd",
        ] {
            assert!(
                pack.matches_safe(command) || pack.check(command).is_none(),
                "{command:?} is read-only and must not be blocked"
            );
        }
    }

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();
        assert_eq!(pack.id, "system.permissions");
        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    /// The non-recursive exemption keyed only on a leading `/`, so every other
    /// spelling of an absolute or home path walked through it — and because a
    /// safe match short-circuits the pack, that meant `chmod-777` and
    /// `chmod-setuid` never ran on those targets.
    ///
    /// `chmod 777 "/etc/shadow"` is the sharpest case: the shell unquotes it to
    /// the identical path that `chmod 777 /etc/shadow` denies.
    #[test]
    fn the_non_recursive_exemption_does_not_cover_quoted_or_home_targets() {
        let pack = create_pack();
        for (command, rule) in [
            (r#"chmod 777 "/etc/shadow""#, "chmod-777"),
            (r"chmod 777 '/etc/shadow'", "chmod-777"),
            (r"chmod 777 ~/.ssh/id_rsa", "chmod-777"),
            (r"chmod 777 ~/.ssh/authorized_keys", "chmod-777"),
            (r"chmod 777 $HOME/.ssh/id_rsa", "chmod-777"),
            (r"chmod 777 ${HOME}/.ssh/id_rsa", "chmod-777"),
            // Same cause, different rule: the exemption also hid setuid.
            (r"chmod 4755 ~/bin/tool", "chmod-setuid"),
            (r"chmod u+s ~/bin/tool", "chmod-setuid"),
        ] {
            assert_blocks_with_pattern(&pack, command, rule);
        }

        // A genuinely plain target keeps the exemption — this is the whole
        // reason it exists, and narrowing it must not cost the routine case.
        for command in [
            "chmod 777 notes.txt",
            "chmod 644 notes.txt",
            "chmod 755 ./build",
            "chmod u+x ./script.sh",
            "chmod 700 ./mydir",
            // Hardening a key is the safe direction and stays allowed.
            "chmod 600 ~/.ssh/id_rsa",
            "chmod 0600 $HOME/.ssh/id_rsa",
            r#"chmod 600 "/etc/shadow""#,
        ] {
            assert_allows(&pack, command);
        }
    }

    #[test]
    fn quote_bypass_does_not_evade_system_dir_block() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "chmod -R 0755 \"/etc\"", "chmod-recursive-root");
        assert_blocks_with_pattern(&pack, "chmod -R 0755 '/usr/local'", "chmod-recursive-root");
        assert_blocks_with_pattern(&pack, "chown -R user:user \"/var\"", "chown-recursive-root");
        assert_blocks_with_pattern(
            &pack,
            "chown --recursive root '/etc'",
            "chown-recursive-root",
        );
        assert_blocks_with_pattern(&pack, "setfacl -R -m u:app:rwx \"/etc\"", "setfacl-all");
        assert_blocks_with_pattern(&pack, "chmod -R 0755 /etc", "chmod-recursive-root");
    }

    #[test]
    fn permissions_blocks_each_destructive_pattern() {
        let pack = create_pack();
        assert_blocks(&pack, "chmod 777 /tmp/myfile", "777");
        assert_blocks(&pack, "chmod -R 755 /etc", "system directories");
        assert_blocks(&pack, "chown -R user:group /var", "system ownership");
        assert_blocks(&pack, "chmod u+s /usr/bin/myapp", "setuid");
        assert_blocks(&pack, "chmod g+s /shared", "setgid");
        assert_blocks(&pack, "chown root: /tmp/myfile", "root");
        assert_blocks(&pack, "setfacl -R -m u:app:rwx /etc", "setfacl");
    }

    /// Issue #289: every rule in this pack names the utility it is about, so
    /// the evaluator can refuse to apply it to a segment run by anything else.
    #[test]
    fn every_rule_declares_its_executable_issue_289() {
        let pack = create_pack();
        for pattern in &pack.destructive_patterns {
            let expected: &[&str] = match pattern.name {
                Some("chmod-777" | "chmod-recursive-root" | "chmod-setuid" | "chmod-setgid") => {
                    &["chmod"]
                }
                Some("chown-recursive-root" | "chown-to-root") => &["chown"],
                Some("chgrp-recursive-root") => &["chgrp"],
                Some("setfacl-all") => &["setfacl"],
                Some("icacls-recursive-system" | "icacls-grant-everyone") => &["icacls", "cacls"],
                Some("takeown-recursive-system") => &["takeown"],
                other => panic!("unhandled permissions rule {other:?} — declare its executable"),
            };
            assert_eq!(
                pattern.executables,
                Some(expected),
                "executables for {:?}",
                pattern.name
            );
        }
    }

    /// The Windows spellings of the shapes this pack already claims.
    ///
    /// `chown -R nobody /etc` denied while `takeown /f C:\Windows /r` — the
    /// same act on the same kind of tree — reached no rule at all, because the
    /// pack was POSIX-only.
    #[test]
    fn windows_permission_equivalents_are_claimed() {
        let pack = create_pack();
        for (command, rule) in [
            (
                r"icacls C:\Windows /grant Everyone:F /t",
                "icacls-recursive-system",
            ),
            (r"icacls C:\Windows /reset /t", "icacls-recursive-system"),
            (
                r#"icacls "C:\Program Files" /reset /T"#,
                "icacls-recursive-system",
            ),
            (r"icacls C:\ /reset /t", "icacls-recursive-system"),
            (r"icacls C:\Users /reset /t", "icacls-recursive-system"),
            (r"icacls C:\Users\bob /reset /t", "icacls-recursive-system"),
            (r"icacls %SystemRoot% /reset /t", "icacls-recursive-system"),
            (
                r"cacls C:\Windows /e /t /p Everyone:F",
                "icacls-recursive-system",
            ),
            (r"takeown /f C:\Windows /r", "takeown-recursive-system"),
            (r"takeown /f C:\ /r", "takeown-recursive-system"),
            (
                r#"takeown /f "C:\Program Files" /r"#,
                "takeown-recursive-system",
            ),
            (r"takeown /f %SystemRoot% /r", "takeown-recursive-system"),
            (r"takeown /f C:\Users\bob /r", "takeown-recursive-system"),
            (
                r"icacls C:\myapp /grant Everyone:F",
                "icacls-grant-everyone",
            ),
            (r"icacls data /grant Everyone:(F)", "icacls-grant-everyone"),
            (
                r"icacls data /grant:r Everyone:(OI)(CI)F",
                "icacls-grant-everyone",
            ),
            (r"icacls data /grant Everyone:M", "icacls-grant-everyone"),
            (r"cacls data /e /p Everyone:W", "icacls-grant-everyone"),
        ] {
            assert_blocks_with_pattern(&pack, command, rule);
        }
    }

    /// The Windows rules inherit the POSIX depth carve-out and the
    /// least-privilege carve-out, because getting either wrong turns the most
    /// ordinary Windows administration there is into a false positive.
    #[test]
    fn windows_permission_rules_keep_the_depth_and_right_carve_outs() {
        let pack = create_pack();
        for command in [
            // `C:\Users\bob\project` is the ordinary working tree, exactly as
            // `/home/user/project` is — only the profile ROOT is blocked (#301).
            r"icacls C:\Users\bob\project /reset /t",
            r"takeown /f C:\Users\bob\project /r",
            // Not a system tree at all.
            r"icacls C:\myapp /reset /t",
            r"takeown /f C:\myapp /r",
            // Non-recursive: the recursive rules must not claim it.
            r"icacls C:\Windows /reset",
            r"takeown /f C:\Windows",
            // Read and read+execute grants are not world-WRITABLE.
            r"icacls data /grant Everyone:R",
            r"icacls data /grant Everyone:(RX)",
            r"icacls data /grant Everyone:(OI)(CI)RX",
            // A named principal is least privilege, not Everyone.
            r"icacls data /grant bob:F",
            // Removing an ACE is the safe direction.
            r"icacls data /remove Everyone",
            // Ordinary inspection.
            r"icacls C:\Windows",
        ] {
            assert_allows(&pack, command);
        }
    }

    /// `~` and `$HOME` name the same directory `/home/user` does.
    ///
    /// The rules anchored on `/`, so the absolute spelling denied while every
    /// short form allowed — and the short form is the one an agent writes.
    #[test]
    fn recursive_root_covers_the_home_shorthands() {
        let pack = create_pack();
        for (command, rule) in [
            ("chmod -R 000 ~", "chmod-recursive-root"),
            ("chmod -R 000 ~/", "chmod-recursive-root"),
            ("chmod -R 000 $HOME", "chmod-recursive-root"),
            ("chmod -R 000 ${HOME}", "chmod-recursive-root"),
            ("chmod -R 000 \"$HOME\"", "chmod-recursive-root"),
            ("chown -R nobody ~", "chown-recursive-root"),
            ("chown -R nobody $HOME", "chown-recursive-root"),
        ] {
            assert_blocks_with_pattern(&pack, command, rule);
        }
    }

    /// The home shorthands keep the depth carve-out, and the shell's quoting
    /// rules.
    ///
    /// `/home/user/project` is deliberately allowed — only the home ROOT is
    /// blocked — so `~/project` must be too, or this becomes a false-positive
    /// engine for the most ordinary command there is. And a tilde expands only
    /// when UNQUOTED, so `"~"` is a directory literally named `~`.
    #[test]
    fn home_shorthands_keep_the_depth_and_quoting_rules() {
        let pack = create_pack();
        for command in [
            "chmod -R 755 ~/project",
            "chmod -R 755 $HOME/project",
            "chmod -R 755 ~/.config/app",
            "chown -R me ~/project",
            // Quoted tilde is a literal directory name, not home.
            "chmod -R 000 \"~\"",
            "chmod -R 000 '~'",
            // Single quotes do not expand `$HOME` either.
            "chmod -R 000 '$HOME'",
        ] {
            assert_no_match(&pack, command);
        }
    }

    /// `chgrp` was a keyword with no rule behind it (#441's shape).
    ///
    /// It sat in the pack's keyword row from the start, so the keyword
    /// selected the pack and nothing matched: `chown -R nobody /` denied while
    /// `chgrp -R nogroup /` allowed, though both change the same
    /// access-control metadata on the same tree.
    #[test]
    fn chgrp_recursive_root_is_covered_like_chown() {
        let pack = create_pack();
        for command in [
            "chgrp -R nogroup /",
            "chgrp -R nogroup /etc",
            "chgrp -R nogroup /usr",
            "chgrp -R nogroup /home/user",
            "chgrp -R nogroup ~",
            "chgrp -R nogroup $HOME",
            "chgrp --recursive nogroup /var",
        ] {
            assert_blocks_with_pattern(&pack, command, "chgrp-recursive-root");
        }

        // The same carve-outs the other two rules get, so this cannot pass on
        // a blanket deny of `chgrp`.
        for command in [
            "chgrp -R staff ./build",
            "chgrp -R staff /home/user/project",
            "chgrp -R staff ~/project",
            "chgrp staff ./out",
        ] {
            assert_no_match(&pack, command);
        }
    }

    /// Issue #301: bare `/` and `/home` must be protected. The old regex
    /// tail `(?:$|bin|...)\b` could never match a bare `/` (the `\b` after
    /// the end-anchor has no word character to bound), and `/home` was
    /// missing from the protected-path list entirely.
    #[test]
    fn recursive_root_covers_bare_slash_and_home_issue_301() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "chown -R user /", "chown-recursive-root");
        assert_blocks_with_pattern(&pack, "chown -R user /home", "chown-recursive-root");
        assert_blocks_with_pattern(&pack, "chown -R user '/'", "chown-recursive-root");
        assert_blocks_with_pattern(&pack, "chown -R user /home/alice", "chown-recursive-root");
        assert_blocks_with_pattern(&pack, "chmod -R 755 /", "chmod-recursive-root");
        assert_blocks_with_pattern(&pack, "chmod -R 755 /home", "chmod-recursive-root");
        assert_blocks_with_pattern(&pack, "chmod -R 755 \"/home\"", "chmod-recursive-root");
        assert_blocks_with_pattern(&pack, "setfacl -R -m u:app:rwx /", "setfacl-all");
        assert_blocks_with_pattern(&pack, "setfacl -R -m u:app:rwx /home", "setfacl-all");
        // `chmod-777` also fires on the 777 case; the recursive-root rule must
        // stand on its own for non-777 modes (the masking noted in #301).
        assert_blocks_with_pattern(
            &pack,
            "chown -R deploy:deploy /home",
            "chown-recursive-root",
        );
        // A whole single-user home (≤1 level, where ~/.ssh lives) is blocked,
        // but a routine chmod on a project directory two-or-more levels deep
        // stays allowed — `/home` is scoped, not a blanket prefix (issue #301).
        let chmod = pack
            .destructive_patterns
            .iter()
            .find(|p| p.name == Some("chmod-recursive-root"))
            .expect("chmod rule");
        for allowed in [
            "chmod -R 755 /home/user/project",
            "chmod -R 755 /home/alice/code/src",
            "chmod -R 755 \"/home/bob/app\"",
        ] {
            assert!(
                !chmod.regex.is_match(allowed),
                "deep home project path must be allowed: {allowed}"
            );
        }
    }

    /// Issue #301 boundaries: paths that merely share a prefix with a
    /// protected name, and non-recursive or non-rooted forms, must not match
    /// the recursive-root rules.
    #[test]
    fn recursive_root_negative_boundaries_issue_301() {
        let pack = create_pack();
        let rule = |name: &str| {
            pack.destructive_patterns
                .iter()
                .find(|p| p.name == Some(name))
                .unwrap_or_else(|| panic!("rule {name} must exist"))
        };
        let chown = rule("chown-recursive-root");
        let chmod = rule("chmod-recursive-root");
        // Prefix-sharing paths are not protected paths.
        assert!(!chown.regex.is_match("chown -R user /homeworks"));
        assert!(!chmod.regex.is_match("chmod -R 755 /etcetera"));
        // Non-system subtree.
        assert!(!chown.regex.is_match("chown -R user /data/scratch"));
        // Non-recursive chown on home is not this rule's concern.
        assert!(!chown.regex.is_match("chown user /home/alice/file"));
    }

    #[test]
    fn permissions_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "chmod 777 /tmp/myfile", Severity::High);
        assert_blocks_with_severity(&pack, "chmod -R 755 /etc", Severity::Critical);
        assert_blocks_with_severity(&pack, "chown -R user:group /var", Severity::High);
        assert_blocks_with_severity(&pack, "chmod u+s /usr/bin/myapp", Severity::High);
        assert_blocks_with_severity(&pack, "setfacl -R -m u:app:rwx /etc", Severity::Critical);
    }

    #[test]
    fn permissions_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "chmod 755 myfile");
        assert_safe_pattern_matches(&pack, "stat /tmp/myfile");
        assert_safe_pattern_matches(&pack, "ls -la /tmp");
        assert_safe_pattern_matches(&pack, "getfacl /tmp/myfile");
        assert_safe_pattern_matches(&pack, "namei -l /tmp/myfile");
    }

    #[test]
    fn permissions_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
    }

    /// Issue #287: separators inside quotes or command substitutions are not
    /// segment boundaries, and the pack regexes must keep matching across
    /// them. Cross-segment suppression happens in the evaluator
    /// (`SEGMENT_SCOPED_PACKS`), not in these regexes — a character-class
    /// bound here would match newlines and break on quoted separators.
    #[test]
    fn quoted_and_substituted_separators_do_not_break_matches_issue_287() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "chmod -R $(cat modes.txt | head -1) /etc",
            "chmod-recursive-root",
        );
        assert_blocks_with_pattern(
            &pack,
            "chmod -R --reference=\"/opt/a&b\" /etc",
            "chmod-recursive-root",
        );
        assert_blocks_with_pattern(&pack, "chown -R \"u;g\" /etc", "chown-recursive-root");
        assert_blocks_with_pattern(
            &pack,
            "setfacl -R -m \"u:$(id -un | tr -d ' '):rwx\" /etc",
            "setfacl-all",
        );
        // Single-segment matches unchanged.
        assert_blocks_with_pattern(&pack, "chmod -R 755 /etc", "chmod-recursive-root");
        assert_blocks_with_pattern(&pack, "chown -R user:group /var", "chown-recursive-root");
        assert_blocks_with_pattern(&pack, "setfacl -R -m u:app:rwx /etc", "setfacl-all");
    }
}
