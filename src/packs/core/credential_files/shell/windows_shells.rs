//! PowerShell and Cmd front end for `credential-file-write` (#477).
//!
//! Nothing here decides whether a path is protected. Each word is decoded with
//! its own dialect's quoting into the POSIX classifier's [`Word`] model — text
//! plus a per-character "literal" flag — and handed to the same
//! [`judge_file_target`] / [`classify_copy`] / [`classify_simple_command`] the
//! Bash tool reaches. So the protected table, the `known_hosts` append
//! carve-out, the `*.pub` exemption, the unprovable-spelling denial and the
//! `.git` rule split all hold for these dialects by construction, not by a
//! parallel copy that could drift.
//!
//! What the decoding has to get right, because it changes the opened path:
//!
//! - `\` is a path separator in both shells (and in `pwsh` on Unix), so it
//!   becomes `/`; a drive prefix (`C:`) and PowerShell's `FileSystem::`
//!   provider prefix are dropped, so `C:\Users\u\.ssh\x` lands on the same
//!   `/Users/<u>` root the table already models.
//! - The home spellings — `~`, `$HOME`, `$env:USERPROFILE`, `%USERPROFILE%`,
//!   `%HOMEDRIVE%%HOMEPATH%` — become `$HOME`; `$env:NAME` becomes `$NAME` so
//!   the relocation variables (`$env:GNUPGHOME`, …) resolve as in POSIX. Any
//!   other expansion stays non-literal, which the judge treats as "cannot be
//!   proven harmless" exactly as it does for Bash.
//! - PowerShell's provider expands `~` and wildcards even inside quotes, so
//!   both are non-literal wherever they appear; `'…'` is otherwise verbatim
//!   (`''` is a quote), `"…"` expands `$`, and a backtick escapes.
//! - Cmd has only `"`, escapes with `^` outside quotes, and expands `%NAME%`
//!   everywhere.
//!
//! Writers: every redirect spelling (`>`, `>>`, `2>`, `*>>`; descriptor merges
//! like `2>&1` open no file), the POSIX writers when `pwsh` on Unix runs the
//! native `tee`/`cp`/`sed -i`, and the idiomatic spellings a POSIX parser
//! cannot see — `Add-Content`, `Set-Content`, `Clear-Content`, `Out-File`,
//! `Tee-Object`, `New-Item`, `Copy-Item`, `Move-Item` and their aliases, plus
//! Cmd's `copy`/`move`. An agent writing PowerShell reaches for `Add-Content`
//! before it reaches for `>>`, so a dialect-aware parse without the cmdlets
//! would have closed the less likely half.
//!
//! Not modelled, and allowed as before: .NET calls
//! (`[IO.File]::WriteAllText`), `Export-*`, and download sinks such as
//! `Invoke-WebRequest -OutFile` — the last matches the POSIX side, which does
//! not judge `curl -o` either.

use super::{
    CredentialFileWrite, Token, Word, WriteMode, Writer, WriterKind, classify_copy,
    classify_simple_command, judge_file_target,
};
use crate::normalize::ShellDialect;

/// One lexed word plus the raw facts parameter binding needs.
#[derive(Debug)]
struct Arg {
    word: Word,
    /// The first raw character, when it was not quoted or escaped. A quoted
    /// `'-Path'` is an argument in PowerShell, not a parameter, and a quoted
    /// `"/y"` is a file name to Cmd.
    bare_first: Option<char>,
    /// PowerShell only: joined to the previous word by `,`, i.e. another
    /// element of the same array argument (`Set-Content a,b`).
    comma_before: bool,
}

#[derive(Debug)]
enum Lexed {
    Arg(Arg),
    Write { mode: WriteMode, target: Word },
}

pub(super) fn classify(segment: &str, dialect: ShellDialect) -> Option<CredentialFileWrite> {
    lex(segment, dialect)
        .into_iter()
        .find_map(|command| classify_command(command, dialect))
}

fn classify_command(command: Vec<Lexed>, dialect: ShellDialect) -> Option<CredentialFileWrite> {
    let mut args: Vec<Arg> = Vec::new();
    let mut tokens: Vec<Token> = Vec::new();
    for item in command {
        match item {
            Lexed::Arg(arg) => {
                tokens.push(Token::Word(arg.word.clone()));
                args.push(arg);
            }
            Lexed::Write { mode, target } => tokens.push(Token::Write { mode, target }),
        }
    }
    // Redirects, and the native writers `pwsh` runs on Unix (`tee`, `cp`,
    // `sed -i`, …): the POSIX command judge already reads decoded words.
    if let Some(hit) = classify_simple_command(&tokens) {
        return Some(hit);
    }
    let (name, rest) = args.split_first()?;
    let name = super::executable_name(&name.word)?;
    // A module-qualified cmdlet name (`Microsoft.PowerShell.Management\Add-Content`)
    // arrives with its `\` already decoded to `/`, so the base is the tail.
    let name = name.rsplit('/').next().unwrap_or(&name);
    match dialect {
        ShellDialect::Cmd => classify_cmd_builtin(name, rest),
        _ => classify_cmdlet(name, rest),
    }
}

// ============================================================================
// PowerShell cmdlets
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// The file the cmdlet opens for writing.
    Target,
    /// The file a copy or move reads.
    Source,
    /// `New-Item -Name`, joined onto `-Path`.
    Name,
    /// Takes a value this classifier does not use.
    Value,
    Switch,
    Append,
    WhatIf,
    /// `Tee-Object -Variable`: the copy goes to a variable, not a file.
    Variable,
}

struct Param {
    /// Canonical name first, then the aliases PowerShell binds.
    names: &'static [&'static str],
    role: Role,
}

const fn param(names: &'static [&'static str], role: Role) -> Param {
    Param { names, role }
}

/// The common parameters every cmdlet accepts. `WhatIf` is a preview.
const COMMON: &[Param] = &[
    param(&["whatif", "wi"], Role::WhatIf),
    param(&["confirm", "cf"], Role::Switch),
    param(&["verbose", "vb"], Role::Switch),
    param(&["debug", "db"], Role::Switch),
    param(&["erroraction", "ea"], Role::Value),
    param(&["warningaction", "wa"], Role::Value),
    param(&["informationaction", "infa"], Role::Value),
    param(&["progressaction", "proga"], Role::Value),
    param(&["errorvariable", "ev"], Role::Value),
    param(&["warningvariable", "wv"], Role::Value),
    param(&["informationvariable", "iv"], Role::Value),
    param(&["outvariable", "ov"], Role::Value),
    param(&["outbuffer", "ob"], Role::Value),
    param(&["pipelinevariable", "pv"], Role::Value),
];

const CONTENT_PARAMS: &[Param] = &[
    param(&["path"], Role::Target),
    param(&["literalpath", "pspath", "lp"], Role::Target),
    param(&["value"], Role::Value),
    param(&["encoding"], Role::Value),
    param(&["filter"], Role::Value),
    param(&["include"], Role::Value),
    param(&["exclude"], Role::Value),
    param(&["credential"], Role::Value),
    param(&["stream"], Role::Value),
    param(&["passthru"], Role::Switch),
    param(&["force"], Role::Switch),
    param(&["nonewline"], Role::Switch),
    param(&["asbytestream"], Role::Switch),
];

const OUT_FILE_PARAMS: &[Param] = &[
    param(&["filepath", "path"], Role::Target),
    param(&["literalpath", "pspath", "lp"], Role::Target),
    param(&["encoding"], Role::Value),
    param(&["width"], Role::Value),
    param(&["inputobject"], Role::Value),
    param(&["append"], Role::Append),
    param(&["force"], Role::Switch),
    param(&["noclobber", "nooverwrite"], Role::Switch),
    param(&["nonewline"], Role::Switch),
];

const TEE_OBJECT_PARAMS: &[Param] = &[
    param(&["filepath", "path"], Role::Target),
    param(&["literalpath", "pspath", "lp"], Role::Target),
    param(&["variable"], Role::Variable),
    param(&["encoding"], Role::Value),
    param(&["inputobject"], Role::Value),
    param(&["append"], Role::Append),
];

const NEW_ITEM_PARAMS: &[Param] = &[
    param(&["path"], Role::Target),
    param(&["name"], Role::Name),
    param(&["itemtype", "type"], Role::Value),
    param(&["value", "target"], Role::Value),
    param(&["credential"], Role::Value),
    param(&["force"], Role::Switch),
];

const COPY_ITEM_PARAMS: &[Param] = &[
    param(&["path"], Role::Source),
    param(&["literalpath", "pspath", "lp"], Role::Source),
    param(&["destination"], Role::Target),
    param(&["filter"], Role::Value),
    param(&["include"], Role::Value),
    param(&["exclude"], Role::Value),
    param(&["credential"], Role::Value),
    param(&["fromsession"], Role::Value),
    param(&["tosession"], Role::Value),
    param(&["container"], Role::Switch),
    param(&["force"], Role::Switch),
    param(&["recurse"], Role::Switch),
    param(&["passthru"], Role::Switch),
];

struct Cmdlet {
    kind: WriterKind,
    params: &'static [Param],
    /// What each positional argument binds to, in order.
    positional: &'static [Role],
}

/// Resolve a command name to the cmdlet it runs, aliases included. `cp`,
/// `mv` and `tee` are aliases on Windows and native binaries on Unix; the
/// native reading already ran through [`classify_simple_command`], and
/// reading them as cmdlets too costs nothing where they are not.
fn cmdlet(name: &str) -> Option<Cmdlet> {
    let (kind, params, positional): (_, _, &[Role]) = match name {
        "add-content" | "ac" => (WriterKind::AddContent, CONTENT_PARAMS, &[Role::Target]),
        // `sc` is Set-Content in Windows PowerShell 5.1 and `sc.exe` in pwsh;
        // read as Set-Content it only ever matters for a protected target.
        "set-content" | "sc" => (WriterKind::SetContent, CONTENT_PARAMS, &[Role::Target]),
        "clear-content" | "clc" => (WriterKind::ClearContent, CONTENT_PARAMS, &[Role::Target]),
        "out-file" => (WriterKind::OutFile, OUT_FILE_PARAMS, &[Role::Target]),
        "tee-object" | "tee" => (WriterKind::TeeObject, TEE_OBJECT_PARAMS, &[Role::Target]),
        "new-item" | "ni" => (WriterKind::NewItem, NEW_ITEM_PARAMS, &[Role::Target]),
        "copy-item" | "copy" | "cp" | "cpi" => (
            WriterKind::CopyItem,
            COPY_ITEM_PARAMS,
            &[Role::Source, Role::Target],
        ),
        "move-item" | "move" | "mv" | "mi" => (
            WriterKind::MoveItem,
            COPY_ITEM_PARAMS,
            &[Role::Source, Role::Target],
        ),
        // `Rename-Item <path> <newName>` destroys the old name exactly as a
        // move does, and its second operand is a NAME relative to the item's
        // own parent rather than a path. Reading it as a move means the
        // source-side judgement above answers it, which is the half that
        // matters — the new name resolves to nothing on its own (#451).
        "rename-item" | "ren" | "rni" | "rn" => (
            WriterKind::MoveItem,
            COPY_ITEM_PARAMS,
            &[Role::Source, Role::Target],
        ),
        _ => return None,
    };
    Some(Cmdlet {
        kind,
        params,
        positional,
    })
}

/// PowerShell binds a parameter by its full name, an alias, or any prefix
/// that is unambiguous among the cmdlet's parameters (`-Pa`, `-Dest`, `-lit`).
/// An unknown or ambiguous name is a binding error, so treating it as a
/// switch can only shift a positional onto a word PowerShell would reject.
fn lookup(cmdlet: &Cmdlet, name: &str) -> Role {
    let name = name.to_ascii_lowercase();
    let all = || cmdlet.params.iter().chain(COMMON);
    if let Some(found) = all().find(|param| param.names.contains(&name.as_str())) {
        return found.role;
    }
    let mut matches = all().filter(|param| param.names[0].starts_with(&name));
    match (matches.next(), matches.next()) {
        (Some(found), None) => found.role,
        _ => Role::Switch,
    }
}

/// A parameter token: `-Name`, `-Name:value`, with PowerShell's en/em dash
/// and horizontal bar accepted as the dash. Returns the name and, for the
/// colon form, the character offset where its value begins.
fn parameter(arg: &Arg) -> Option<(String, Option<usize>)> {
    if !matches!(
        arg.bare_first,
        Some('-' | '\u{2013}' | '\u{2014}' | '\u{2015}')
    ) {
        return None;
    }
    let text = &arg.word.text;
    if !text.get(1).is_some_and(char::is_ascii_alphabetic) {
        return None;
    }
    let colon = text.iter().position(|ch| *ch == ':');
    let name: String = text[1..colon.unwrap_or(text.len())].iter().collect();
    Some((name, colon.map(|at| at + 1)))
}

/// A switch given an explicit value: `-Append:$false` turns it off.
fn switch_value(word: &Word) -> bool {
    !word.as_string().eq_ignore_ascii_case("$false") && word.as_string() != "0"
}

#[derive(Default)]
struct Bound {
    targets: Vec<Word>,
    sources: Vec<Word>,
    names: Vec<Word>,
    append: bool,
    what_if: bool,
}

fn bind(cmdlet: &Cmdlet, args: &[Arg]) -> Bound {
    let mut bound = Bound::default();
    let mut position = 0usize;
    // The role the previous word bound to, for `,`-joined array elements.
    let mut last_role: Option<Role> = None;
    let mut index = 0usize;
    let store = |bound: &mut Bound, role: Role, word: Word| match role {
        Role::Target => bound.targets.push(word),
        Role::Source => bound.sources.push(word),
        Role::Name => bound.names.push(word),
        Role::Variable => bound.targets.clear(),
        Role::Value | Role::Switch | Role::Append | Role::WhatIf => {}
    };
    while let Some(arg) = args.get(index) {
        index += 1;
        if arg.comma_before
            && let Some(role) = last_role
        {
            store(&mut bound, role, arg.word.clone());
            continue;
        }
        if arg.word.as_string() == "--%" {
            // Stop-parsing: the rest goes to a native program verbatim.
            break;
        }
        if let Some((name, inline)) = parameter(arg) {
            let role = lookup(cmdlet, &name);
            let value = match inline {
                Some(offset) if offset < arg.word.text.len() => {
                    // `-Path:~/.bashrc`: the provider expands a `~` that
                    // starts the value, even though it did not start the word.
                    let mut value = arg.word.suffix(offset);
                    if value.text.first() == Some(&'~') {
                        value.literal[0] = false;
                    }
                    Some(value)
                }
                Some(_) | None => None,
            };
            match role {
                Role::Switch => {}
                Role::Append => bound.append = value.as_ref().is_none_or(switch_value),
                Role::WhatIf => bound.what_if = value.as_ref().is_none_or(switch_value),
                _ => {
                    let value = value.or_else(|| {
                        index += 1;
                        args.get(index - 1).map(|next| next.word.clone())
                    });
                    if let Some(value) = value {
                        store(&mut bound, role, value);
                    }
                    last_role = Some(role);
                    continue;
                }
            }
            last_role = None;
            continue;
        }
        let role = cmdlet
            .positional
            .get(position)
            .copied()
            .unwrap_or(Role::Value);
        position += 1;
        store(&mut bound, role, arg.word.clone());
        last_role = Some(role);
    }
    bound
}

fn classify_cmdlet(name: &str, args: &[Arg]) -> Option<CredentialFileWrite> {
    let cmdlet = cmdlet(name)?;
    let bound = bind(&cmdlet, args);
    if bound.what_if {
        return None;
    }
    let mode = match cmdlet.kind {
        WriterKind::AddContent => WriteMode::Append,
        WriterKind::OutFile | WriterKind::TeeObject if bound.append => WriteMode::Append,
        _ => WriteMode::Replace,
    };
    let writer = Writer {
        kind: Some(cmdlet.kind),
        mode,
    };
    match cmdlet.kind {
        WriterKind::CopyItem | WriterKind::MoveItem => {
            let destination = bound.targets.first()?;
            judge_copy(cmdlet.kind, &bound.sources, destination)
        }
        WriterKind::NewItem if !bound.names.is_empty() => {
            let parents = if bound.targets.is_empty() {
                vec![None]
            } else {
                bound.targets.iter().map(Some).collect()
            };
            parents.into_iter().find_map(|parent| {
                bound.names.iter().find_map(|name| {
                    judge_file_target(
                        &parent.map_or_else(|| name.clone(), |p| join(p, name)),
                        writer,
                    )
                })
            })
        }
        _ => bound
            .targets
            .iter()
            .find_map(|target| judge_file_target(target, writer)),
    }
}

/// `-Path dir -Name file`: the item is created at `dir/file`.
fn join(parent: &Word, name: &Word) -> Word {
    let mut text = parent.text.clone();
    let mut literal = parent.literal.clone();
    text.push('/');
    literal.push(true);
    text.extend(&name.text);
    literal.extend(&name.literal);
    Word {
        text,
        literal,
        range: parent.range.start.min(name.range.start)..parent.range.end.max(name.range.end),
        glued_paren: false,
    }
}

/// A copy or move onto `destination`, judged by the POSIX `cp` logic: a file
/// destination is judged as a file, a directory one by where each source
/// lands. `--` keeps a source spelled like an option from reading as one.
///
/// A MOVE also judges its sources, because moving a protected file away
/// destroys it exactly as deleting it does — the name stops resolving to the
/// key. POSIX catches that with its own `mv-sensitive-source-root-home` rule,
/// which is a `mv`-anchored regex and so never saw `Move-Item` or cmd's
/// `move`: measured, `mv ~/.ssh/id_rsa /tmp/x` denied while both Windows
/// spellings of the same move allowed (#451). This is the policy the embedded
/// languages already apply — `transfers.rs` records a move's source removal
/// and a copy's does not, for the same reason: a copy only READS its source.
fn judge_copy(
    kind: WriterKind,
    sources: &[Word],
    destination: &Word,
) -> Option<CredentialFileWrite> {
    if matches!(kind, WriterKind::MoveItem | WriterKind::CmdMove) {
        let removal = Writer {
            kind: Some(kind),
            // A move removes the source name whatever the write mode is, so the
            // append carve-out must not exempt it: appending to
            // `~/.ssh/known_hosts` is fine, moving it away is not.
            mode: WriteMode::Replace,
        };
        if let Some(hit) = sources
            .iter()
            .find_map(|source| judge_file_target(source, removal))
        {
            return Some(hit);
        }
    }
    let end_of_options = Word {
        text: vec!['-', '-'],
        literal: vec![true, true],
        range: destination.range.clone(),
        glued_paren: false,
    };
    let operands: Vec<&Word> = std::iter::once(&end_of_options)
        .chain(sources)
        .chain(std::iter::once(destination))
        .collect();
    classify_copy(kind, &operands)
}

// ============================================================================
// Cmd built-ins
// ============================================================================

/// `copy [/switches] source[+source…] destination` and `move`: the destination
/// is the last operand. A switch is a bare `/` followed by one short token;
/// `C:\x` decodes to `/x`, so a longer or nested spelling is an operand.
fn classify_cmd_builtin(name: &str, args: &[Arg]) -> Option<CredentialFileWrite> {
    let kind = match name {
        "copy" | "xcopy" => WriterKind::CmdCopy,
        // `ren`/`rename` destroys the old name the same way `move` does; its
        // second operand is a bare new name, which the source-side judgement
        // does not need (#451).
        "move" | "ren" | "rename" => WriterKind::CmdMove,
        _ => return None,
    };
    let operands: Vec<&Arg> = args
        .iter()
        .filter(|arg| {
            let text = &arg.word.text;
            !(arg.bare_first == Some('/')
                && text.len() <= 4
                && !text[1..].contains(&'/')
                && text[1..]
                    .iter()
                    .all(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == ':'))
        })
        .collect();
    let (destination, sources) = operands.split_last()?;
    if sources.is_empty() {
        return None;
    }
    let sources: Vec<Word> = sources.iter().map(|arg| arg.word.clone()).collect();
    judge_copy(kind, &sources, &destination.word)
}

// ============================================================================
// Candidate gate
// ============================================================================

/// Command words that select this front end. Matched as whole words, case
/// folded, by the caller's gate.
const WRITER_WORDS: &[&str] = &[
    "add-content",
    "set-content",
    "clear-content",
    "out-file",
    "tee-object",
    "new-item",
    "copy-item",
    "move-item",
    "ac",
    "sc",
    "clc",
    "ni",
    "cpi",
    "mi",
    "copy",
    "xcopy",
    "move",
    // Rename destroys the old name the same way a move does (#451).
    "rename-item",
    "rni",
    "rn",
    "ren",
    "rename",
];

pub(super) fn names_writer(command: &str) -> bool {
    WRITER_WORDS
        .iter()
        .any(|word| contains_command_word(command, word))
}

/// Case-folded whole-word search; `-` counts as part of a word so `ac` does
/// not match inside `Add-Content`'s neighbours like `-ac`… but a leading
/// separator does not.
fn contains_command_word(command: &str, word: &str) -> bool {
    let bytes = command.as_bytes();
    let needle = word.as_bytes();
    let is_word = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-');
    bytes
        .windows(needle.len())
        .enumerate()
        .any(|(start, window)| {
            window.eq_ignore_ascii_case(needle)
                && (start == 0 || !is_word(bytes[start - 1]))
                && bytes
                    .get(start + needle.len())
                    .is_none_or(|byte| !is_word(*byte))
        })
}

// ============================================================================
// Lexer
// ============================================================================

const fn is_single_quote(ch: char) -> bool {
    matches!(ch, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}')
}

const fn is_double_quote(ch: char) -> bool {
    matches!(ch, '"' | '\u{201C}' | '\u{201D}' | '\u{201E}')
}

/// Split a segment into simple commands of words and redirects.
fn lex(segment: &str, dialect: ShellDialect) -> Vec<Vec<Lexed>> {
    let powershell = dialect != ShellDialect::Cmd;
    let bytes = segment.as_bytes();
    let mut commands: Vec<Vec<Lexed>> = vec![Vec::new()];
    let mut nested: Vec<Vec<Lexed>> = Vec::new();
    let mut comma_before = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let byte = bytes[i];
        let current_is_empty = commands.last().is_none_or(Vec::is_empty);
        let separator = match byte {
            b'\n' | b'|' | b')' => true,
            // Grouping at a command's start; an argument expression after it.
            b'(' => !powershell || current_is_empty,
            b';' => powershell,
            b'{' | b'}' => powershell,
            b'&' => {
                // PowerShell's call operator starts a command; anywhere else
                // `&`/`&&` ends one.
                !(powershell && current_is_empty && bytes.get(i + 1) != Some(&b'&'))
            }
            _ => false,
        };
        if separator {
            commands.push(Vec::new());
            comma_before = false;
            i += if matches!(byte, b'|' | b'&') && bytes.get(i + 1) == Some(&byte) {
                2
            } else {
                1
            };
            continue;
        }
        if byte == b'&' {
            i += 1;
            continue;
        }
        if byte.is_ascii_whitespace() || (!powershell && matches!(byte, b',' | b';' | b'=')) {
            i += 1;
            continue;
        }
        if powershell && byte == b',' {
            comma_before = true;
            i += 1;
            continue;
        }
        if powershell && byte == b'#' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if powershell && byte == b'<' && bytes.get(i + 1) == Some(&b'#') {
            i = segment[i..]
                .find("#>")
                .map_or(bytes.len(), |end| i + end + 2);
            continue;
        }
        if powershell
            && byte == b'@'
            && let Some((arg, end)) = here_string(segment, i)
        {
            if let Some(command) = commands.last_mut() {
                command.push(Lexed::Arg(arg));
            }
            comma_before = false;
            i = end;
            continue;
        }
        // An argument in parentheses — `Add-Content ('~/.bashrc') x`,
        // `-Path @(…)` — is an expression PowerShell evaluates to the value
        // it binds. At a command's start the same `(` is grouping, handled as
        // a separator above.
        let group_open = match byte {
            b'(' => Some(i),
            b'@' if bytes.get(i + 1) == Some(&b'(') => Some(i + 1),
            _ => None,
        };
        if powershell
            && !current_is_empty
            && let Some(open) = group_open
        {
            let close = matching_paren(segment, open);
            let inner = &segment[open + 1..close];
            let mut inner_commands = lex(inner, dialect);
            for command in &mut inner_commands {
                shift(command, open + 1);
            }
            // A single value, or an array literal (`@('a', 'b')`), binds as
            // its elements; anything else is a value this cannot read.
            let elements: Option<Vec<Word>> = match inner_commands.as_slice() {
                [only] => only
                    .iter()
                    .enumerate()
                    .map(|(position, item)| match item {
                        Lexed::Arg(arg) if position == 0 || arg.comma_before => {
                            Some(arg.word.clone())
                        }
                        _ => None,
                    })
                    .collect(),
                _ => None,
            };
            let elements = elements.unwrap_or_else(|| vec![unresolved(i..close + 1)]);
            if let Some(command) = commands.last_mut() {
                for (position, word) in elements.into_iter().enumerate() {
                    command.push(Lexed::Arg(Arg {
                        word,
                        bare_first: None,
                        comma_before: if position == 0 { comma_before } else { true },
                    }));
                }
            }
            comma_before = false;
            // The expression's own commands run too, beside the outer one.
            nested.extend(inner_commands);
            i = (close + 1).min(bytes.len());
            continue;
        }
        if let Some((kind, after)) = redirect(bytes, i, powershell) {
            let mut j = after;
            while matches!(bytes.get(j), Some(b' ' | b'\t')) {
                j += 1;
            }
            i = j;
            if kind == Redirect::Merge || j >= bytes.len() {
                continue;
            }
            let (arg, end) = read_word(segment, j, dialect);
            i = end.max(j + 1);
            // An input operand is consumed so it is not read as an argument.
            if let Redirect::Output(mode) = kind
                && let Some(command) = commands.last_mut()
            {
                command.push(Lexed::Write {
                    mode,
                    target: arg.word,
                });
            }
            continue;
        }
        let (mut arg, end) = read_word(segment, i, dialect);
        i = end.max(i + 1);
        arg.comma_before = comma_before;
        comma_before = false;
        if let Some(command) = commands.last_mut() {
            command.push(Lexed::Arg(arg));
        }
    }
    commands.extend(nested);
    commands.retain(|command| !command.is_empty());
    commands
}

/// Byte index of the `)` closing the `(` at `open`, or the segment's end.
fn matching_paren(segment: &str, open: usize) -> usize {
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    for (offset, ch) in segment[open..].char_indices() {
        match quote {
            Some(q)
                if (is_single_quote(q) && is_single_quote(ch))
                    || (is_double_quote(q) && is_double_quote(ch)) =>
            {
                quote = None;
            }
            Some(_) => {}
            None if is_single_quote(ch) || is_double_quote(ch) => quote = Some(ch),
            None if ch == '(' => depth += 1,
            None if ch == ')' => {
                depth -= 1;
                if depth == 0 {
                    return open + offset;
                }
            }
            None => {}
        }
    }
    segment.len()
}

/// Move a nested lex's ranges from its slice onto the enclosing segment.
fn shift(command: &mut [Lexed], by: usize) {
    for item in command {
        let word = match item {
            Lexed::Arg(arg) => &mut arg.word,
            Lexed::Write { target, .. } => target,
        };
        word.range = word.range.start + by..word.range.end + by;
    }
}

/// A value this front end cannot read statically: the judge treats it as a
/// spelling that cannot be proven harmless, as it does `$(…)` in POSIX.
fn unresolved(range: std::ops::Range<usize>) -> Word {
    let mut text = Vec::new();
    let mut literal = Vec::new();
    emit_variable("", &mut text, &mut literal);
    Word {
        text,
        literal,
        range,
        glued_paren: false,
    }
}

/// A PowerShell here-string at `start` (`@'` or `@"`, the rest of that line
/// blank, closed by `'@` / `"@` at the start of a later line) as one opaque
/// argument. Its body may hold unbalanced quotes, so reading it as ordinary
/// quoting would desynchronise everything after it.
fn here_string(segment: &str, start: usize) -> Option<(Arg, usize)> {
    let quote = *segment.as_bytes().get(start + 1)?;
    if !matches!(quote, b'\'' | b'"') {
        return None;
    }
    let after = &segment[start + 2..];
    let line_end = after.find('\n')?;
    if !after[..line_end].trim().is_empty() {
        return None;
    }
    let closer = format!("\n{}@", quote as char);
    let body_start = start + 2 + line_end;
    let close = segment[body_start..].find(&closer)? + body_start;
    let end = close + closer.len();
    Some((
        Arg {
            word: unresolved(start..end),
            bare_first: None,
            comma_before: false,
        },
        end,
    ))
}

/// A redirect operator at byte `i`: its write mode (or `None` for one that
/// opens no output file) and the offset just past it.
fn redirect(bytes: &[u8], i: usize, powershell: bool) -> Option<(Redirect, usize)> {
    let mut j = i;
    match bytes.get(j)? {
        b'0'..=b'9' => j += 1,
        b'*' if powershell => j += 1,
        _ => {}
    }
    // Input — and `<>`, which opens read-write WITHOUT truncating, the same
    // reading the POSIX tokenizer gives it. PowerShell reserves `<` and
    // refuses to run the command at all; either way nothing is written, and
    // the `>` of `<>` must not be taken for an output redirect.
    if bytes.get(j) == Some(&b'<') {
        j += 1;
        if bytes.get(j) == Some(&b'>') {
            j += 1;
        }
        return Some((Redirect::Input, j));
    }
    if bytes.get(j) != Some(&b'>') {
        return None;
    }
    j += 1;
    let mode = if bytes.get(j) == Some(&b'>') {
        j += 1;
        WriteMode::Append
    } else {
        WriteMode::Replace
    };
    if bytes.get(j) == Some(&b'&') && bytes.get(j + 1).is_some_and(u8::is_ascii_digit) {
        return Some((Redirect::Merge, j + 2));
    }
    Some((Redirect::Output(mode), j))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Redirect {
    Output(WriteMode),
    /// Reads its operand (`< file`, `<> file`).
    Input,
    /// A descriptor merge (`2>&1`): no file at all.
    Merge,
}

/// Decode one word. Returns it with the byte offset just past it.
fn read_word(segment: &str, start: usize, dialect: ShellDialect) -> (Arg, usize) {
    let powershell = dialect != ShellDialect::Cmd;
    let mut text: Vec<char> = Vec::new();
    let mut literal: Vec<bool> = Vec::new();
    let mut quote: Option<char> = None;
    let mut bare_first = None;
    let mut end = segment.len();
    let mut chars = segment[start..].char_indices().peekable();

    let push = |text: &mut Vec<char>, literal: &mut Vec<bool>, ch: char, lit: bool| {
        // `\` separates path components in both shells.
        let ch = if ch == '\\' { '/' } else { ch };
        // Provider wildcards and a leading `~` are rewritten by PowerShell
        // even when quoted; Cmd's `copy` expands wildcards too.
        let lit = lit
            && !matches!(ch, '*' | '?')
            && !(powershell && (matches!(ch, '[' | ']') || (ch == '~' && text.is_empty())));
        text.push(ch);
        literal.push(lit);
    };

    while let Some((offset, ch)) = chars.next() {
        let here = start + offset;
        if offset == 0 && !is_single_quote(ch) && !is_double_quote(ch) && ch != '`' && ch != '^' {
            bare_first = Some(ch);
        }
        match quote {
            Some(open) if is_single_quote(open) => {
                if is_single_quote(ch) {
                    if chars.peek().is_some_and(|(_, next)| is_single_quote(*next)) {
                        chars.next();
                        push(&mut text, &mut literal, '\'', true);
                    } else {
                        quote = None;
                    }
                } else {
                    push(&mut text, &mut literal, ch, true);
                }
            }
            Some(_) => {
                if is_double_quote(ch) {
                    if powershell && chars.peek().is_some_and(|(_, next)| is_double_quote(*next)) {
                        chars.next();
                        push(&mut text, &mut literal, '"', true);
                    } else {
                        quote = None;
                    }
                } else if powershell && ch == '`' {
                    if let Some((_, escaped)) = chars.next() {
                        push(&mut text, &mut literal, escaped, true);
                    }
                } else if powershell && ch == '$' {
                    powershell_expansion(&mut chars, &mut text, &mut literal);
                } else if !powershell && matches!(ch, '%' | '!') {
                    cmd_expansion(ch, &mut chars, &mut text, &mut literal);
                } else {
                    push(&mut text, &mut literal, ch, true);
                }
            }
            None => {
                if (powershell && is_single_quote(ch)) || is_double_quote(ch) {
                    quote = Some(ch);
                    continue;
                }
                let terminator = ch.is_ascii_whitespace()
                    || matches!(ch, '|' | '&' | '<' | '>' | '(' | ')')
                    || (powershell && matches!(ch, ';' | ',' | '{' | '}'))
                    || (!powershell && matches!(ch, ',' | ';' | '='));
                if terminator && offset > 0 {
                    end = here;
                    break;
                }
                match ch {
                    '`' if powershell => match chars.next() {
                        Some((_, '\n')) | None => {}
                        Some((_, escaped)) => push(&mut text, &mut literal, escaped, true),
                    },
                    '^' if !powershell => match chars.next() {
                        Some((_, '\n')) | None => {}
                        Some((_, escaped)) => push(&mut text, &mut literal, escaped, true),
                    },
                    '$' if powershell => powershell_expansion(&mut chars, &mut text, &mut literal),
                    '%' | '!' if !powershell => {
                        cmd_expansion(ch, &mut chars, &mut text, &mut literal);
                    }
                    other => push(&mut text, &mut literal, other, true),
                }
            }
        }
    }
    strip_volume_prefix(&mut text, &mut literal);
    let word = Word {
        text,
        literal,
        range: start..end,
        glued_paren: false,
    };
    (
        Arg {
            word,
            bare_first,
            comma_before: false,
        },
        end,
    )
}

/// Emit an expansion as the POSIX judge understands it: a known home or
/// relocation variable as `$NAME` at the head of the word, anything else as
/// a non-literal the judge cannot prove harmless.
fn emit_variable(name: &str, text: &mut Vec<char>, literal: &mut Vec<bool>) {
    let upper = name.to_ascii_uppercase();
    let mapped = match upper.as_str() {
        "HOME" | "USERPROFILE" | "HOMEPATH" => Some("HOME"),
        // `%HOMEDRIVE%%HOMEPATH%`: the drive names no directory of its own.
        "HOMEDRIVE" if text.is_empty() => return,
        _ => super::VARIABLE_ROOTS
            .iter()
            .map(|(candidate, _, _)| *candidate)
            .find(|candidate| *candidate == upper),
    };
    let name = mapped.unwrap_or("DCG_UNRESOLVED");
    text.push('$');
    literal.push(false);
    for ch in name.chars() {
        text.push(ch);
        literal.push(false);
    }
}

/// `$name`, `$env:NAME`, `${…}`, `$(…)` after a `$` has been consumed.
fn powershell_expansion(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    text: &mut Vec<char>,
    literal: &mut Vec<bool>,
) {
    let name = match chars.peek().map(|(_, next)| *next) {
        Some('(') => {
            let mut depth = 0usize;
            for (_, inner) in chars.by_ref() {
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
            String::new()
        }
        Some('{') => {
            chars.next();
            let mut name = String::new();
            for (_, inner) in chars.by_ref() {
                if inner == '}' {
                    break;
                }
                name.push(inner);
            }
            name
        }
        Some(next) if next.is_ascii_alphanumeric() || matches!(next, '_' | '?' | '$' | '^') => {
            let mut name = String::new();
            while let Some((_, inner)) = chars.peek().copied() {
                if inner.is_ascii_alphanumeric() || matches!(inner, '_' | ':') {
                    name.push(inner);
                    chars.next();
                } else {
                    break;
                }
            }
            if name.is_empty() {
                chars.next();
            }
            name
        }
        // A lone `$` is literal in PowerShell.
        _ => {
            text.push('$');
            literal.push(true);
            return;
        }
    };
    // `$HOME` is an automatic variable; `$env:X` is the environment. Any
    // other scope (`$global:x`, a script variable) is unknown text.
    let lower = name.to_ascii_lowercase();
    let resolved = if lower == "home" {
        "HOME"
    } else if let Some(env) = lower.strip_prefix("env:") {
        &name[name.len() - env.len()..]
    } else {
        ""
    };
    emit_variable(resolved, text, literal);
}

/// `%NAME%` — or `!NAME!`, delayed expansion, which a script can switch on —
/// after the opening `delimiter` has been consumed. An unterminated one is
/// literal; `%NAME:~0,3%` and other edits are unknown text.
fn cmd_expansion(
    delimiter: char,
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    text: &mut Vec<char>,
    literal: &mut Vec<bool>,
) {
    // Bounded: a variable reference is short, and an unbounded look-ahead per
    // `%` would make a long run of them quadratic.
    let rest: String = chars.clone().take(128).map(|(_, ch)| ch).collect();
    let name = rest.find(delimiter).map(|close| &rest[..close]);
    let Some(name) = name.filter(|name| !name.is_empty() && !name.contains(['\n', ' ', '"']))
    else {
        text.push(delimiter);
        literal.push(true);
        return;
    };
    for _ in 0..=name.chars().count() {
        chars.next();
    }
    let plain = name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_');
    emit_variable(if plain { name } else { "" }, text, literal);
}

/// Drop a leading drive (`C:`) or `FileSystem::` provider qualifier so the
/// rest is judged as the absolute path it names.
fn strip_volume_prefix(text: &mut Vec<char>, literal: &mut Vec<bool>) {
    let head: String = text
        .iter()
        .take(40)
        .collect::<String>()
        .to_ascii_lowercase();
    let provider = ["microsoft.powershell.core/filesystem::", "filesystem::"]
        .iter()
        .find(|prefix| head.starts_with(**prefix))
        .map(|prefix| prefix.chars().count());
    if let Some(count) = provider {
        text.drain(..count);
        literal.drain(..count);
    }
    // `\\?\C:\…` and `\\.\C:\…` are the Win32 device spellings of `C:\…`;
    // `\\host\C$\…` is the same volume through its administrative share.
    let head: String = text.iter().take(4).collect();
    if head == "//?/" || head == "//./" {
        text.drain(..4);
        literal.drain(..4);
    } else if head.starts_with("//") {
        let rest: String = text[2..].iter().collect();
        let mut parts = rest.splitn(3, '/');
        if let (Some(host), Some(share), Some(_)) = (parts.next(), parts.next(), parts.next())
            && !host.is_empty()
            && share.len() == 2
            && share.ends_with('$')
            && share.starts_with(|ch: char| ch.is_ascii_alphabetic())
        {
            // Keep the `/` that follows the share as the new root.
            let count = 2 + host.chars().count() + 1 + 2;
            text.drain(..count);
            literal.drain(..count);
            return;
        }
    }
    if text.len() >= 3
        && text[0].is_ascii_alphabetic()
        && text[1] == ':'
        && text[2] == '/'
        && literal[..3].iter().all(|lit| *lit)
    {
        text.drain(..2);
        literal.drain(..2);
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CREDENTIAL_FILE_WRITE_NAME, GIT_INTERNALS_WRITE_NAME};
    use super::*;

    fn ps(command: &str) -> Option<CredentialFileWrite> {
        super::super::classify_credential_file_write(command, ShellDialect::PowerShell)
    }

    fn cmd(command: &str) -> Option<CredentialFileWrite> {
        super::super::classify_credential_file_write(command, ShellDialect::Cmd)
    }

    /// Moving or renaming a protected file AWAY destroys it (#451).
    ///
    /// The name stops resolving to the key, which is the same loss a delete
    /// causes. POSIX catches this with `mv-sensitive-source-root-home`, a
    /// regex anchored on the POSIX verb, so it never saw `Move-Item` or cmd's
    /// `move`: measured, the POSIX move of a key denied while both Windows
    /// spellings of the same move allowed.
    #[test]
    fn windows_move_away_from_a_protected_file_denies_issue_451() {
        for command in [
            "Move-Item $HOME/.ssh/id_rsa C:/tmp/x",
            "Move-Item -Path $HOME/.ssh/id_rsa -Destination C:/tmp/x",
            "mi $HOME/.aws/credentials C:/tmp/x",
            "Rename-Item $HOME/.ssh/id_rsa id_rsa.bak",
            "rni $HOME/.ssh/id_rsa id_rsa.bak",
        ] {
            let found = ps(command).unwrap_or_else(|| panic!("must deny: {command}"));
            assert_eq!(found.rule, CREDENTIAL_FILE_WRITE_NAME, "{command}");
        }
        for command in [
            "move %USERPROFILE%/.ssh/id_rsa C:/tmp/x",
            "ren %USERPROFILE%/.ssh/id_rsa id_rsa.bak",
            "rename %USERPROFILE%/.aws/credentials creds.bak",
        ] {
            let found = cmd(command).unwrap_or_else(|| panic!("must deny: {command}"));
            assert_eq!(found.rule, CREDENTIAL_FILE_WRITE_NAME, "{command}");
        }
    }

    /// A COPY only reads its source, so the source side must stay allowed
    /// (#451). Without this the test above would pass on a blanket deny of any
    /// command naming a protected path.
    #[test]
    fn windows_copy_from_a_protected_file_stays_allowed_issue_451() {
        for command in [
            "Copy-Item $HOME/.ssh/id_rsa C:/tmp/x",
            "cpi $HOME/.ssh/id_rsa C:/tmp/x",
            "Copy-Item -Path $HOME/.ssh/id_rsa -Destination C:/tmp/x",
            // An ordinary move is nobody's business.
            "Move-Item C:/app/a.txt C:/app/b.txt",
            "Rename-Item C:/app/a.txt b.txt",
            // The public half of a key pair.
            "Move-Item $HOME/.ssh/id_rsa.pub C:/tmp/x",
        ] {
            assert!(ps(command).is_none(), "must stay allowed: {command}");
        }
        for command in [
            "copy %USERPROFILE%/.ssh/id_rsa C:/tmp/x",
            "move C:/app/a.txt C:/app/b.txt",
            "ren C:/app/a.txt b.txt",
        ] {
            assert!(cmd(command).is_none(), "must stay allowed: {command}");
        }
    }

    /// The #477 matrix: every row the Bash tool denies must deny from a
    /// PowerShell payload too, under the same rule.
    #[test]
    fn powershell_redirects_to_protected_files_deny() {
        for command in [
            "echo x >> ~/.ssh/authorized_keys",
            "echo x >> ~/.bashrc",
            "echo x >> /etc/shadow",
            "echo x > ~/.ssh/authorized_keys",
            "Write-Output x >> $HOME/.ssh/authorized_keys",
            "Write-Output x >> $env:HOME/.ssh/authorized_keys",
            // Braced `${env:…}`; split so it cannot read as a format argument.
            concat!(
                "Write-Output x >> ${",
                "env:USERPROFILE}\\.ssh\\authorized_keys"
            ),
            "Write-Output x >> \"$env:USERPROFILE\\.ssh\\authorized_keys\"",
            "Write-Output x >> C:\\Users\\bob\\.ssh\\authorized_keys",
            "Write-Output x>>~/.ssh/authorized_keys",
            "Write-Output x 2>> ~/.ssh/authorized_keys",
            "Write-Output x *>> ~/.ssh/authorized_keys",
            "Write-Output x >> '~/.ssh/authorized_keys'",
            "Write-Output x >> ~/.SSH/Authorized_Keys",
            "Write-Output x >> ~/.ssh/id_*",
            // A backtick escapes ONE character: the second `>` still
            // redirects, truncating the file.
            "Write-Output x `>> ~/.ssh/authorized_keys",
        ] {
            let found = ps(command).unwrap_or_else(|| panic!("must deny: {command}"));
            assert_eq!(found.rule, CREDENTIAL_FILE_WRITE_NAME, "{command}");
        }
    }

    #[test]
    fn powershell_cmdlet_writers_deny() {
        for command in [
            "Add-Content -Path ~/.ssh/authorized_keys -Value x",
            "Add-Content ~/.ssh/authorized_keys x",
            "add-content -LiteralPath ~/.ssh/authorized_keys -Value x",
            "Add-Content -Value x -Path ~/.ssh/authorized_keys",
            "Add-Content -Pa ~/.ssh/authorized_keys -Value x",
            "Add-Content -Path:~/.ssh/authorized_keys -Value x",
            "Add-Content \u{2013}Path ~/.ssh/authorized_keys -Value x",
            "ac ~/.ssh/authorized_keys x",
            "Microsoft.PowerShell.Management\\Add-Content ~/.bashrc x",
            "& Add-Content ~/.bashrc x",
            "Set-Content -Path /etc/shadow -Value x",
            "Set-Content -Encoding utf8 ~/.bashrc x",
            "Set-Content /tmp/a,~/.bashrc x",
            "Clear-Content ~/.ssh/authorized_keys",
            "'x' | Out-File -Append ~/.ssh/authorized_keys",
            "'x' | Out-File -FilePath ~/.aws/credentials",
            "'x' | Tee-Object -FilePath ~/.bashrc",
            "New-Item -Path ~/.ssh/authorized_keys -Value x -Force",
            "New-Item -Path ~/.ssh -Name authorized_keys -Value x -Force",
            "Copy-Item /tmp/keys ~/.ssh/authorized_keys",
            "Copy-Item -Path /tmp/keys -Destination ~/.ssh/authorized_keys",
            "Copy-Item /tmp/authorized_keys ~/.ssh/",
            "Move-Item -Destination $env:USERPROFILE\\.ssh\\authorized_keys -Path x",
            "Get-Content k | ForEach-Object { Add-Content ~/.ssh/authorized_keys $_ }",
            "Add-Content -Path FileSystem::/etc/sudoers -Value x",
            "Add-Content $env:GNUPGHOME/gpg-agent.conf x",
            // Found reviewing this front end before it landed: each was an
            // allow in its first draft.
            "Add-Content -Path:~/.bashrc -Value x",
            "Add-Content ('~/.bashrc') x",
            "Add-Content -Path @('/tmp/a', '~/.bashrc') -Value x",
            "Write-Output (Add-Content ~/.bashrc x)",
            "Add-Content \\\\?\\C:\\Users\\bob\\.bashrc x",
            "Add-Content \\\\localhost\\C$\\Users\\bob\\.bashrc x",
            "$t = @'\nit's\n'@; Add-Content ~/.bashrc $t",
        ] {
            assert!(ps(command).is_some(), "must deny: {command}");
        }
        let found = ps("Add-Content ~/.ssh/authorized_keys x").expect("denies");
        assert!(
            found.reason.starts_with("`Add-Content` appends to"),
            "the reason names the writer the command used: {}",
            found.reason
        );
    }

    /// Unix `pwsh` runs the native binaries, so the POSIX writers still apply.
    #[test]
    fn powershell_running_native_writers_denies() {
        for command in [
            "tee -a ~/.ssh/authorized_keys",
            "sed -i s/a/b/ ~/.bashrc",
            "cp /tmp/x ~/.ssh/authorized_keys",
        ] {
            assert!(ps(command).is_some(), "must deny: {command}");
        }
    }

    /// What the rule must keep allowing, from the same measurements.
    #[test]
    fn powershell_benign_writes_stay_allowed() {
        for command in [
            "echo x >> /tmp/out.txt",
            "Add-Content -Path ./notes.txt -Value x",
            "Add-Content ~/.ssh/known_hosts x",
            "Write-Output x >> ~/.ssh/known_hosts",
            "Get-Content ~/.ssh/authorized_keys",
            "Get-Content ~/.bashrc > /tmp/copy.txt",
            "Add-Content -Path ~/.ssh/authorized_keys -Value x -WhatIf",
            "Copy-Item ~/.ssh/authorized_keys /tmp/backup",
            "Copy-Item ~/.ssh/id_rsa.pub /tmp/",
            "Set-Content ~/notes.txt '~/.ssh/authorized_keys'",
            "Add-Content -Path log.txt -Value '~/.bashrc'",
            "Write-Output x 2>&1 > /tmp/out.txt",
            "Write-Output '>> ~/.ssh/authorized_keys'",
            "Write-Output x `>`> ~/.ssh/authorized_keys",
            "Write-Output x # >> ~/.ssh/authorized_keys",
            "'x' | Tee-Object -Variable keys",
            // `<>` opens read-write without truncating (and PowerShell
            // refuses `<` outright); its `>` is not an output redirect.
            "Get-Content x <> /etc/passwd",
            "Get-Content x < ~/.bashrc",
            "New-Item -ItemType Directory -Path ~/projects/app",
        ] {
            assert!(
                ps(command).is_none(),
                "must stay allowed: {command}: {:?}",
                ps(command)
            );
        }
    }

    #[test]
    fn powershell_git_internals_keep_their_own_rule() {
        let found = ps("Set-Content .git/config x").expect("denies");
        assert_eq!(found.rule, GIT_INTERNALS_WRITE_NAME);
        // A redirect into `.git/` stays with the redirect rules, as in POSIX.
        assert!(ps("Write-Output x > .git/config").is_none());
    }

    #[test]
    fn cmd_writes_to_protected_files_deny() {
        for command in [
            "echo x >> %USERPROFILE%\\.ssh\\authorized_keys",
            "echo x>>%USERPROFILE%\\.ssh\\authorized_keys",
            "echo x >> \"%USERPROFILE%\\.ssh\\authorized_keys\"",
            "echo x >> %HOMEDRIVE%%HOMEPATH%\\.ssh\\authorized_keys",
            "echo x >> C:\\Users\\bob\\.ssh\\authorized_keys",
            "type k 1>> %USERPROFILE%\\.ssh\\authorized_keys",
            "copy /y k %USERPROFILE%\\.ssh\\authorized_keys",
            "copy k %USERPROFILE%\\.ssh\\",
            "move k C:\\Users\\bob\\.ssh\\authorized_keys",
            "echo x >> !USERPROFILE!\\.bashrc",
            "(echo x) >> %USERPROFILE%\\.bashrc",
        ] {
            assert!(cmd(command).is_some(), "must deny: {command}");
        }
        for command in [
            "echo x >> out.txt",
            "echo x >> %TEMP%\\out.txt",
            "type %USERPROFILE%\\.ssh\\authorized_keys",
            "copy %USERPROFILE%\\.ssh\\authorized_keys C:\\backup\\",
            "echo x ^>^> %USERPROFILE%\\.ssh\\authorized_keys",
            "echo x >> %USERPROFILE%\\.ssh\\known_hosts",
            "sort <> %USERPROFILE%\\.bashrc",
            "sort < %USERPROFILE%\\.bashrc > %TEMP%\\sorted.txt",
        ] {
            assert!(
                cmd(command).is_none(),
                "must stay allowed: {command}: {:?}",
                cmd(command)
            );
        }
    }

    /// The unknown dialect could be either shell, so it reads both ways.
    #[test]
    fn unknown_dialect_reads_every_shell() {
        for command in [
            "echo x >> ~/.ssh/authorized_keys",
            "Add-Content -Path ~/.ssh/authorized_keys -Value x",
            "echo x >> %USERPROFILE%\\.ssh\\authorized_keys",
        ] {
            assert!(
                super::super::classify_credential_file_write(command, ShellDialect::Unknown)
                    .is_some(),
                "must deny: {command}"
            );
        }
    }

    #[test]
    fn writer_gate_matches_whole_words_only() {
        assert!(names_writer("Add-Content -Path x"));
        assert!(names_writer("x | ac ~/.bashrc y"));
        assert!(names_writer("COPY k dest"));
        assert!(!names_writer("cargo build --release"));
        assert!(!names_writer("git commit -m 'accept'"));
        assert!(!names_writer("npm run copy-assets"));
    }
}
