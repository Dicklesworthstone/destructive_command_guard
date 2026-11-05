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
use crate::packs::core::git::{
    PowerShellStaticExecutableError, decode_powershell_static_executable,
};

/// One lexed word plus the raw facts parameter binding needs.
#[derive(Debug, Clone)]
struct Arg {
    word: Word,
    /// The first raw character, when it was not quoted or escaped. A quoted
    /// `'-Path'` is an argument in PowerShell, not a parameter, and a quoted
    /// `"/y"` is a file name to Cmd.
    bare_first: Option<char>,
    /// PowerShell only: joined to the previous word by `,`, i.e. another
    /// element of the same array argument (`Set-Content a,b`).
    comma_before: bool,
    /// Quoted command names execute only after the call/dot operator.
    invoked: bool,
    /// Original source location of the operator that owns this command.
    operator_span: Option<std::ops::Range<usize>>,
    /// A leading quote forms a standalone PowerShell string token. Quotes
    /// inside a bare word instead concatenate into that generic token.
    starts_quoted: bool,
    /// One raw remainder following PowerShell's stop-parsing marker.
    verbatim: bool,
    /// Parameter names retain their raw spelling: unlike command names,
    /// PowerShell does not remove backticks inside a parameter name.
    parameter_name: Option<String>,
}

#[derive(Debug)]
enum Lexed {
    Arg(Arg),
    Write { mode: WriteMode, target: Word },
}

const MAX_LEX_DEPTH: usize = 32;
const MAX_LEX_WORK_BYTES: usize = 1024 * 1024;

/// Exhausting a parser bound is incomplete analysis, never proof of safety.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowsShellParseIncomplete {
    Nesting,
    Work,
}

/// A single proven command-name value owned by a PowerShell call operator.
/// Neither span refers to a normalized/reconstructed matching view.
#[derive(Debug)]
pub(crate) struct PowerShellInvokedCommand {
    pub(crate) name: String,
    pub(crate) span: std::ops::Range<usize>,
    pub(crate) operator_span: std::ops::Range<usize>,
}

/// Actual call/dot-owned literal names, including bounded computed names.
/// Argument data and uninvoked string expressions cannot contribute names.
pub(crate) fn powershell_literal_invocations(
    source: &str,
) -> Result<Vec<PowerShellInvokedCommand>, WindowsShellParseIncomplete> {
    Ok(lex(source, ShellDialect::PowerShell)?
        .into_iter()
        .filter_map(|command| {
            let name = command.into_iter().find_map(|item| match item {
                Lexed::Arg(arg) => Some(arg),
                Lexed::Write { .. } => None,
            })?;
            if !name.invoked || !name.word.is_all_literal() {
                return None;
            }
            Some(PowerShellInvokedCommand {
                name: name.word.as_string(),
                span: name.word.range,
                operator_span: name.operator_span?,
            })
        })
        .collect())
}

struct LexBudget {
    depth: usize,
    remaining_work: usize,
}

impl LexBudget {
    fn charge(&mut self, bytes: usize) -> Result<(), WindowsShellParseIncomplete> {
        self.remaining_work = self
            .remaining_work
            .checked_sub(bytes)
            .ok_or(WindowsShellParseIncomplete::Work)?;
        Ok(())
    }
}

/// A truncating file-output destination, after PowerShell parameter binding.
/// Keep both the actual decoded path and the volume-independent policy view;
/// only the former can support a local filesystem proof.
#[derive(Debug)]
pub(crate) struct PowerShellTruncationTarget {
    pub(crate) path: String,
    pub(crate) policy_path: String,
    pub(crate) literal: bool,
    pub(crate) home_suffix: Option<String>,
    pub(crate) span: std::ops::Range<usize>,
}

/// Collect writes from executable commands, including nested expressions.
/// This uses exactly the lexer and binder used by credential protection.
pub(crate) fn powershell_file_truncation_targets(
    source: &str,
) -> Result<Vec<PowerShellTruncationTarget>, WindowsShellParseIncomplete> {
    Ok(lex(source, ShellDialect::PowerShell)?
        .into_iter()
        .filter_map(|command| {
            let args: Vec<_> = command
                .into_iter()
                .filter_map(|item| match item {
                    Lexed::Arg(arg) => Some(arg),
                    Lexed::Write { .. } => None,
                })
                .collect();
            let (name, rest) = args.split_first()?;
            let cmdlet_name = truncating_file_cmdlet_name(&name.word)?;
            if !name.invoked
                && source[name.word.range.clone()]
                    .chars()
                    .next()
                    .is_some_and(|ch| is_single_quote(ch) || is_double_quote(ch))
            {
                return None;
            }
            let command = cmdlet(cmdlet_name)?;
            let mut bound = bind(&command, rest);
            let mut targets = if name.word.as_string() == "tee" {
                native_tee_operands(rest)
                    .filter(|(mode, _)| *mode == WriteMode::Replace)
                    .map_or_else(Vec::new, |(_, targets)| targets)
            } else {
                Vec::new()
            };
            // Splatting may supply a destination the visible argv does not
            // name. Do not guess its keys or borrow an append exemption.
            if bound.targets.is_empty()
                || (command.kind == WriterKind::OutFile && !bound.named_file_target)
            {
                bound.targets.append(&mut bound.splats);
            }
            if !bound.binding_error
                && !bound.variable
                && !bound.append
                && !bound.what_if
                && !bound.no_clobber
            {
                for target in bound.targets {
                    if !targets.iter().any(|existing| {
                        existing.text == target.text
                            && existing.literal == target.literal
                            && existing.range == target.range
                    }) {
                        targets.push(target);
                    }
                }
            }
            Some(
                targets
                    .into_iter()
                    .map(|target| (target, name.word.range.clone()))
                    .collect::<Vec<_>>(),
            )
        })
        .flatten()
        .map(|(target, span)| {
            let path = target.as_string();
            let home_suffix = if target.text.first() == Some(&'~')
                && target.literal.first() == Some(&false)
                && (target.text.len() == 1 || target.text.get(1) == Some(&'/'))
                && target.literal[1..].iter().all(|literal| *literal)
            {
                Some(path[1..].trim_start_matches('/').to_string())
            } else {
                None
            };
            let literal = target.is_all_literal();
            PowerShellTruncationTarget {
                path,
                policy_path: path_word(target).as_string(),
                literal,
                home_suffix,
                span,
            }
        })
        .collect())
}

fn tee_object_name(word: &Word) -> bool {
    truncating_file_cmdlet_name(word) == Some("tee-object")
}

fn truncating_file_cmdlet_name(word: &Word) -> Option<&'static str> {
    if !word.is_all_literal() {
        return None;
    }
    match word.as_string().to_ascii_lowercase().as_str() {
        "tee" | "tee-object" | "microsoft.powershell.utility/tee-object" => Some("tee-object"),
        "out-file" | "microsoft.powershell.utility/out-file" => Some("out-file"),
        _ => None,
    }
}

/// Select the filesystem pack for every decoded file-output invocation.
/// Binding is deliberately left to the classifiers: -Append and -NoClobber
/// can still write credentials and Git internals without truncating a file.
pub(crate) fn powershell_file_writer_scan_required(source: &str) -> bool {
    let Ok(commands) = lex(source, ShellDialect::PowerShell) else {
        // Keep the pack selected so its mandatory fallible whole-command
        // pass reports incomplete analysis instead of allowing a quick exit.
        return true;
    };
    commands.into_iter().any(|command| {
        let Some(name) = command.iter().find_map(|item| match item {
            Lexed::Arg(arg) => Some(arg),
            Lexed::Write { .. } => None,
        }) else {
            return false;
        };
        truncating_file_cmdlet_name(&name.word).is_some()
            && (name.invoked
                || !source
                    .get(name.word.range.clone())
                    .and_then(|word| word.chars().next())
                    .is_some_and(|ch| is_single_quote(ch) || is_double_quote(ch)))
    })
}

/// Bare `tee` can be the Windows alias or the Unix executable. Only a valid
/// native option vector contributes native targets: PowerShell's -Variable
/// and -FilePath are errors to native tee, not file operands. Both policy
/// passes use this viability check, so their alias readings cannot drift.
fn native_tee_operands(args: &[Arg]) -> Option<(WriteMode, Vec<Word>)> {
    let mut mode = WriteMode::Replace;
    let mut targets = Vec::new();
    let mut options = true;
    let mut args = args.iter().peekable();
    while let Some(arg) = args.next() {
        let value = arg.word.as_string();
        if value == "--%" && args.peek().is_some_and(|next| next.verbatim) {
            // PowerShell consumes this marker before invoking a native
            // executable; it is not an invalid GNU tee option.
            continue;
        }
        if arg.verbatim {
            if value.is_empty() {
                continue;
            }
            if value
                .chars()
                .any(|ch| ch.is_whitespace() || is_single_quote(ch) || is_double_quote(ch))
            {
                // Native argv splitting varies by platform and runtime
                // settings. An opaque remainder can still contain file
                // operands; uncertainty must not erase a possible write.
                targets.push(unresolved(arg.word.range.clone()));
                continue;
            }
        }
        if options && value == "--" {
            options = false;
        } else if options && value.starts_with("--") {
            let (name, argument) = value[2..]
                .split_once('=')
                .map_or((&value[2..], None), |(name, value)| (name, Some(value)));
            let mut candidates = [
                "append",
                "ignore-interrupts",
                "output-error",
                "help",
                "version",
            ]
            .into_iter()
            .filter(|candidate| candidate.starts_with(name));
            let selected = candidates.next()?;
            if candidates.next().is_some() || (argument.is_some() && selected != "output-error") {
                return None;
            }
            match selected {
                "append" => mode = WriteMode::Append,
                "help" | "version" => return Some((WriteMode::Append, Vec::new())),
                "output-error"
                    if argument.is_some_and(|value| {
                        let modes = ["warn", "warn-nopipe", "exit", "exit-nopipe"];
                        !modes.contains(&value)
                            && modes.iter().filter(|mode| mode.starts_with(value)).count() != 1
                    }) =>
                {
                    return None;
                }
                _ => {}
            }
        } else if options && value.starts_with('-') && value != "-" {
            if !value[1..]
                .chars()
                .all(|flag| matches!(flag, 'a' | 'i' | 'p'))
            {
                return None;
            }
            if value[1..].contains('a') {
                mode = WriteMode::Append;
            }
        } else if value != "-" {
            targets.push(arg.word.clone());
        }
    }
    Some((mode, targets))
}

pub(super) fn classify(segment: &str, dialect: ShellDialect) -> Option<CredentialFileWrite> {
    // These legacy best-effort helpers do not own the evaluator verdict.
    // The mandatory fallible whole-command pass surfaces parser exhaustion.
    lex(segment, dialect)
        .ok()?
        .into_iter()
        .find_map(|command| classify_command(command, dialect))
}

pub(super) fn classify_all(segment: &str, dialect: ShellDialect) -> Vec<CredentialFileWrite> {
    // Incompleteness is reported by powershell_file_truncation_targets, which
    // the evaluator runs even when this best-effort collection is empty.
    lex(segment, dialect)
        .unwrap_or_default()
        .into_iter()
        .flat_map(|command| classify_command_writes(command, dialect))
        .collect()
}

/// A native tee can open several destinations in one invocation. Preserve
/// every rule so granting a Git write cannot also grant a credential write.
fn classify_command_writes(command: Vec<Lexed>, dialect: ShellDialect) -> Vec<CredentialFileWrite> {
    let args: Vec<_> = command
        .iter()
        .filter_map(|item| match item {
            Lexed::Arg(arg) => Some(arg.clone()),
            Lexed::Write { .. } => None,
        })
        .collect();
    let Some((name, rest)) = args.split_first() else {
        return classify_command(command, dialect).into_iter().collect();
    };
    if dialect != ShellDialect::PowerShell || !tee_object_name(&name.word) {
        return classify_command(command, dialect).into_iter().collect();
    }
    let mut hits: Vec<_> = command
        .into_iter()
        .filter_map(|item| match item {
            Lexed::Write { mode, target } => classify_simple_command(&[Token::Write {
                mode,
                target: path_word(target),
            }]),
            Lexed::Arg(_) => None,
        })
        .collect();
    if name.starts_quoted && !name.invoked {
        return hits;
    }
    if name.word.as_string() == "tee"
        && let Some((mode, targets)) = native_tee_operands(rest)
    {
        hits.extend(targets.into_iter().filter_map(|target| {
            judge_file_target(
                &path_word(target),
                Writer {
                    kind: Some(WriterKind::Tee),
                    mode,
                },
            )
        }));
    }
    if let Some(hit) = classify_cmdlet("tee-object", rest)
        && !hits
            .iter()
            .any(|existing| existing.rule == hit.rule && existing.span == hit.span)
    {
        hits.push(hit);
    }
    hits
}

pub(super) fn classify_git_redirect_writes(
    segment: &str,
    dialect: ShellDialect,
) -> Vec<CredentialFileWrite> {
    // Defer exhaustion to the mandatory fallible whole-command pass, as in
    // classify_all; an empty local result is not an allow verdict.
    lex(segment, dialect)
        .unwrap_or_default()
        .into_iter()
        .flatten()
        .filter_map(|item| match item {
            Lexed::Write { mode, target } => super::git_redirect_write(&path_word(target), mode),
            Lexed::Arg(_) => None,
        })
        .collect()
}

fn classify_command(command: Vec<Lexed>, dialect: ShellDialect) -> Option<CredentialFileWrite> {
    let mut args: Vec<Arg> = Vec::new();
    let mut tokens: Vec<Token> = Vec::new();
    for item in command {
        match item {
            Lexed::Arg(arg) => {
                tokens.push(Token::Word(path_word(arg.word.clone())));
                args.push(arg);
            }
            Lexed::Write { mode, target } => tokens.push(Token::Write {
                mode,
                target: path_word(target),
            }),
        }
    }
    // Redirects, and the native writers `pwsh` runs on Unix (`tee`, `cp`,
    // `sed -i`, …): the POSIX command judge already reads decoded words.
    let name_is_data = dialect != ShellDialect::Cmd
        && args
            .first()
            .is_some_and(|arg| arg.starts_quoted && !arg.invoked);
    let tee_cmdlet = dialect == ShellDialect::PowerShell
        && args.first().is_some_and(|arg| tee_object_name(&arg.word));
    // In the PowerShell reading, tee's -Variable/-Append bind as cmdlet
    // parameters, not native tee file operands. Redirects remain independent.
    if tee_cmdlet || name_is_data {
        tokens.retain(|token| matches!(token, Token::Write { .. }));
    }
    if let Some(hit) = classify_simple_command(&tokens) {
        return Some(hit);
    }
    if name_is_data {
        return None;
    }
    if tee_cmdlet
        && args
            .first()
            .is_some_and(|arg| arg.word.as_string() == "tee")
        && let Some((mode, targets)) = native_tee_operands(&args[1..])
        && let Some(hit) = targets.iter().find_map(|target| {
            judge_file_target(
                &path_word(target.clone()),
                Writer {
                    kind: Some(WriterKind::Tee),
                    mode,
                },
            )
        })
    {
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
    /// A file target whose provider wildcards are literal characters.
    LiteralTarget,
    /// The file a copy or move reads.
    Source,
    /// `New-Item -Name`, joined onto `-Path`.
    Name,
    /// Takes a value this classifier does not use.
    Value,
    Switch,
    Append,
    /// Out-File may create a new file but cannot replace an existing one.
    NoClobber,
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

/// Common parameters, including the ShouldProcess parameters. Tee-Object
/// does not support ShouldProcess and rejects WhatIf/Confirm at binding.
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
    param(&["literalpath", "pspath", "lp"], Role::LiteralTarget),
    param(&["encoding"], Role::Value),
    param(&["width"], Role::Value),
    param(&["inputobject"], Role::Value),
    param(&["append"], Role::Append),
    param(&["force"], Role::Switch),
    param(&["noclobber", "nooverwrite"], Role::NoClobber),
    param(&["nonewline"], Role::Switch),
];

const TEE_OBJECT_PARAMS: &[Param] = &[
    param(&["filepath", "path"], Role::Target),
    param(&["literalpath", "pspath", "lp"], Role::LiteralTarget),
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
        "out-file" => (
            WriterKind::OutFile,
            OUT_FILE_PARAMS,
            &[Role::Target, Role::Value],
        ),
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
/// Prefixes include aliases, and a single cmdlet parameter wins over common
/// parameter prefixes: Tee-Object -in means InputObject, -e means Encoding,
/// and -v means Variable. Getting arity wrong here can hide the real target.
fn lookup<'a>(cmdlet: &'a Cmdlet, name: &str) -> Option<&'a Param> {
    let name = name.to_ascii_lowercase();
    let all = || {
        cmdlet.params.iter().chain(COMMON.iter().filter(|param| {
            cmdlet.kind != WriterKind::TeeObject || !matches!(param.names[0], "whatif" | "confirm")
        }))
    };
    if let Some(found) = all().find(|param| param.names[0] == name) {
        return Some(found);
    }
    if let Some(found) = all().find(|param| param.names[1..].contains(&name.as_str())) {
        return Some(found);
    }
    let matches_name = |param: &&Param| param.names.iter().any(|alias| alias.starts_with(&name));
    let mut matches = all().filter(matches_name);
    match (matches.next(), matches.next()) {
        (Some(found), None) => Some(found),
        (Some(_), Some(_)) => {
            let mut declared = cmdlet.params.iter().filter(matches_name);
            match (declared.next(), declared.next()) {
                (Some(found), None) => Some(found),
                _ => None,
            }
        }
        _ => None,
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
    let name = arg.parameter_name.clone()?;
    Some((name, colon.map(|at| at + 1)))
}

/// Only the raw `--` token ends parameter binding. Decoding also turns
/// `-` followed by an escaped dash into `--`, but that remains input data.
fn ends_parameters(arg: &Arg) -> bool {
    arg.bare_first == Some('-')
        && arg.parameter_name.as_deref() == Some("-")
        && arg.word.as_string() == "--"
}

/// Only a proven enabled switch may suppress a write. In particular an
/// unresolved variable/expression might be false; its presence is no proof.
fn switch_value(word: &Word) -> bool {
    let value = word.as_string();
    if !word.is_all_literal() {
        return matches!(value.as_str(), "$TRUE" | "$NULL");
    }
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).is_ok_and(|number| number != 0);
    }
    value.parse::<f64>().is_ok_and(|number| number != 0.0)
}

#[derive(Default)]
struct Bound {
    targets: Vec<Word>,
    sources: Vec<Word>,
    names: Vec<Word>,
    append: bool,
    no_clobber: bool,
    what_if: bool,
    variable: bool,
    literal_target: bool,
    named_file_target: bool,
    append_seen: bool,
    binding_error: bool,
    splats: Vec<Word>,
}

fn bind(cmdlet: &Cmdlet, args: &[Arg]) -> Bound {
    let mut bound = Bound::default();
    let out_file = cmdlet.kind == WriterKind::OutFile;
    let strict = matches!(cmdlet.kind, WriterKind::TeeObject | WriterKind::OutFile);
    let mut position = 0usize;
    // Out-File assigns positional values only after named binding, even
    // when the named parameter appears later: `utf8 -FilePath target`
    // binds utf8 to Encoding, not to a second file. A splat may also fill
    // that file slot, so the collector keeps its unresolved target.
    let mut out_file_positionals = Vec::new();
    // The role the previous word bound to, for `,`-joined array elements.
    let mut last_role: Option<Role> = None;
    let mut last_named_parameter = None;
    let mut index = 0usize;
    let mut end_of_parameters = false;
    let mut named_parameters = Vec::new();
    let store = |bound: &mut Bound, role: Role, word: Word| match role {
        Role::Target => bound.targets.push(word),
        Role::LiteralTarget => {
            bound.literal_target = true;
            let mut word = word;
            for (ch, literal) in word.text.iter().zip(&mut word.literal) {
                if matches!(ch, '*' | '?' | '[' | ']') {
                    *literal = true;
                }
            }
            bound.targets.push(word);
        }
        Role::Source => bound.sources.push(word),
        Role::Name => bound.names.push(word),
        Role::Variable => bound.variable = true,
        Role::Value | Role::Switch | Role::Append | Role::NoClobber | Role::WhatIf => {}
    };
    while let Some(arg) = args.get(index) {
        index += 1;
        if arg.comma_before
            && let Some(role) = last_role
        {
            if out_file && matches!(last_named_parameter, Some("encoding" | "width")) {
                bound.binding_error = true;
            }
            store(&mut bound, role, arg.word.clone());
            continue;
        }
        if out_file && arg.comma_before {
            // Both positional parameters are scalar; a comma joins this
            // word to the preceding value instead of supplying a new slot.
            bound.binding_error = true;
            continue;
        }
        if arg.bare_first == Some('@') && arg.word.text.get(1) != Some(&'(') {
            bound.splats.push(unresolved(arg.word.range.clone()));
            last_role = None;
            last_named_parameter = None;
            continue;
        }
        if !end_of_parameters && ends_parameters(arg) {
            end_of_parameters = true;
            continue;
        }
        if !end_of_parameters && let Some((name, inline)) = parameter(arg) {
            let matched_parameter = lookup(cmdlet, &name);
            if matched_parameter.is_none() && strict {
                bound.binding_error = true;
            }
            if strict && let Some(parameter) = matched_parameter {
                if named_parameters.contains(&parameter.names[0]) {
                    bound.binding_error = true;
                } else {
                    named_parameters.push(parameter.names[0]);
                }
            }
            let role = matched_parameter.map_or(Role::Switch, |parameter| parameter.role);
            if matches!(role, Role::Target | Role::LiteralTarget) {
                bound.named_file_target = true;
            }
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
                Some(_) => {
                    index += 1;
                    args.get(index - 1).map(|next| next.word.clone())
                }
                None => None,
            };
            if strict && inline.is_some() && value.is_none() {
                bound.binding_error = true;
            }
            match role {
                Role::Switch => {}
                Role::Append => {
                    if bound.append_seen {
                        bound.binding_error = true;
                    }
                    bound.append_seen = true;
                    bound.append = inline.is_none() || value.as_ref().is_some_and(switch_value);
                }
                Role::NoClobber => {
                    bound.no_clobber = inline.is_none() || value.as_ref().is_some_and(switch_value);
                }
                Role::WhatIf => {
                    bound.what_if = inline.is_none() || value.as_ref().is_some_and(switch_value);
                }
                _ => {
                    let value = value.or_else(|| {
                        // `-InputObject -- -Append path` binds literal
                        // -Append as the input value; it is not a switch.
                        // Keep the end-of-parameters state for later argv.
                        if !end_of_parameters && args.get(index).is_some_and(ends_parameters) {
                            end_of_parameters = true;
                            index += 1;
                        }
                        if strict
                            && !end_of_parameters
                            && args
                                .get(index)
                                .is_some_and(|next| parameter(next).is_some())
                        {
                            bound.binding_error = true;
                            return None;
                        }
                        index += 1;
                        args.get(index - 1).map(|next| next.word.clone())
                    });
                    if let Some(value) = value {
                        store(&mut bound, role, value);
                    } else if strict {
                        bound.binding_error = true;
                    }
                    last_role = Some(role);
                    last_named_parameter = matched_parameter.map(|parameter| parameter.names[0]);
                    continue;
                }
            }
            last_role = None;
            last_named_parameter = None;
            continue;
        }
        if out_file {
            out_file_positionals.push(arg.word.clone());
            last_role = None;
            last_named_parameter = None;
            continue;
        }
        if cmdlet.kind == WriterKind::TeeObject && position >= cmdlet.positional.len() {
            bound.binding_error = true;
        }
        let role = cmdlet
            .positional
            .get(position)
            .copied()
            .unwrap_or(Role::Value);
        position += 1;
        store(&mut bound, role, arg.word.clone());
        last_role = Some(role);
        last_named_parameter = None;
    }
    if out_file {
        let mut file_bound = bound.named_file_target;
        let mut encoding_bound = named_parameters.contains(&"encoding");
        for word in out_file_positionals {
            if !file_bound {
                bound.targets.push(word);
                file_bound = true;
            } else if !encoding_bound {
                encoding_bound = true;
            } else {
                bound.binding_error = true;
            }
        }
    }
    if strict
        && (bound.targets.len() > 1 || bound.targets.iter().any(|target| target.text.is_empty()))
    {
        bound.binding_error = true;
    }
    if cmdlet.kind == WriterKind::TeeObject
        && ((bound.literal_target && bound.append_seen)
            || (bound.variable && (!bound.targets.is_empty() || bound.append_seen)))
    {
        bound.binding_error = true;
    }
    bound
}

fn classify_cmdlet(name: &str, args: &[Arg]) -> Option<CredentialFileWrite> {
    let cmdlet = cmdlet(name)?;
    let bound = bind(&cmdlet, args);
    if bound.what_if
        || (matches!(cmdlet.kind, WriterKind::TeeObject | WriterKind::OutFile)
            && (bound.binding_error || bound.variable))
    {
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
                        &path_word(parent.map_or_else(|| name.clone(), |p| join(p, name))),
                        writer,
                    )
                })
            })
        }
        _ => bound
            .targets
            .iter()
            .find_map(|target| judge_file_target(&path_word(target.clone()), writer)),
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
    let sources: Vec<Word> = sources.iter().cloned().map(path_word).collect();
    let destination = path_word(destination.clone());
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
        .chain(&sources)
        .chain(std::iter::once(&destination))
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
        // Replacing a key with a link is the classic substitution: the file
        // the daemon reads becomes one the caller controls. POSIX `ln -sf` and
        // PowerShell's `New-Item -ItemType SymbolicLink` both deny it; cmd's
        // spelling did not (#451).
        "mklink" => WriterKind::CmdMklink,
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
    // `mklink [/D|/H|/J] <link> <target>` puts the name it CREATES first,
    // the opposite way round from `copy` and `move`. Only that name is
    // written; the target is merely pointed at, exactly as POSIX `ln`'s
    // second operand is the one judged (#451).
    if kind == WriterKind::CmdMklink {
        let link = operands.first()?;
        return judge_file_target(
            &path_word(link.word.clone()),
            Writer {
                kind: Some(kind),
                mode: WriteMode::Replace,
            },
        );
    }
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
    // Creating a link AT a protected path replaces what that path resolves to.
    "mklink",
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
fn lex(
    segment: &str,
    dialect: ShellDialect,
) -> Result<Vec<Vec<Lexed>>, WindowsShellParseIncomplete> {
    let mut budget = LexBudget {
        depth: 0,
        remaining_work: if dialect == ShellDialect::Cmd {
            // Cmd has no recursive expression path here. Keep the existing
            // best-effort Cmd API unchanged; the new fallible evaluator pass
            // owns only PowerShell/Unknown work exhaustion.
            usize::MAX
        } else {
            MAX_LEX_WORK_BYTES
        },
    };
    lex_inner(segment, dialect, &mut budget)
}

fn lex_inner(
    segment: &str,
    dialect: ShellDialect,
    budget: &mut LexBudget,
) -> Result<Vec<Vec<Lexed>>, WindowsShellParseIncomplete> {
    if budget.depth >= MAX_LEX_DEPTH {
        return Err(WindowsShellParseIncomplete::Nesting);
    }
    // Nested slices are charged again: reparsing a deeply nested expression
    // must not turn a small input into unbounded cumulative work.
    budget.charge(segment.len())?;
    budget.depth += 1;
    let result = lex_body(segment, dialect, budget);
    budget.depth -= 1;
    result
}

fn lex_body(
    segment: &str,
    dialect: ShellDialect,
    budget: &mut LexBudget,
) -> Result<Vec<Vec<Lexed>>, WindowsShellParseIncomplete> {
    let powershell = dialect != ShellDialect::Cmd;
    let bytes = segment.as_bytes();
    let mut commands: Vec<Vec<Lexed>> = vec![Vec::new()];
    let mut nested: Vec<Vec<Lexed>> = Vec::new();
    let mut comma_before = false;
    let mut invoked = false;
    let mut operator_span = None;
    let mut i = 0usize;
    while i < bytes.len() {
        let byte = bytes[i];
        if powershell
            && !byte.is_ascii()
            && let Some(ch) = segment[i..].chars().next().filter(|ch| ch.is_whitespace())
        {
            i += ch.len_utf8();
            continue;
        }
        let current_is_empty = commands.last().is_none_or(Vec::is_empty);
        if powershell
            && current_is_empty
            && !invoked
            && matches!(byte, b'$' | b'[')
            && !segment[i..].starts_with("$(")
        {
            let candidate = &segment[i..];
            // Reuse the shell normalizer's assignment grammar. Charge the
            // lookahead too: many non-assignment variable statements must
            // not cause unbounded repeated scans of the remaining source.
            budget.charge(candidate.len())?;
            if let Some(rhs) = crate::normalize::powershell_assignment_rhs(candidate) {
                let rhs_offset = candidate.trim_end().len() - rhs.len();
                // Index/member expressions on the left also execute. Remove
                // the assignment operator before recursion so this prefix
                // cannot repeatedly normalize to its own empty right side.
                if let Some(lhs) = candidate[..rhs_offset].trim_end().strip_suffix('=')
                    && lhs.contains('(')
                {
                    let mut lhs_commands = lex_inner(lhs, dialect, budget)?;
                    for command in &mut lhs_commands {
                        shift(command, i);
                    }
                    nested.extend(lhs_commands);
                }
                i += rhs_offset;
                continue;
            }
        }
        let invoked_group = match byte {
            b'(' => Some(i),
            b'$' | b'@' if bytes.get(i + 1) == Some(&b'(') => Some(i + 1),
            _ => None,
        };
        if powershell
            && current_is_empty
            && invoked
            && let Some(open) = invoked_group
        {
            let close = matching_paren(segment, open);
            let end = (close + 1).min(bytes.len());
            let mut inner_commands = lex_inner(&segment[open + 1..close], dialect, budget)?;
            for command in &mut inner_commands {
                shift(command, open + 1);
            }
            // An unresolved name does not make the expression's commands
            // inert. Keep independently executing nested writers visible.
            nested.extend(inner_commands);
            let expression = &segment[open..end];
            let has_postfix =
                segment[end..].starts_with(['[', '.']) || segment[end..].starts_with("::");
            let word = if close < bytes.len() && !has_postfix {
                powershell_static_invocation_word(expression, i..end, budget)?
            } else {
                // A postfix may change the value. In particular, never
                // prove ('Tee-Object')[0] by discarding its index.
                unresolved(i..end)
            };
            if let Some(command) = commands.last_mut() {
                command.push(Lexed::Arg(Arg {
                    word,
                    bare_first: None,
                    comma_before: false,
                    invoked: true,
                    operator_span: operator_span.clone(),
                    starts_quoted: false,
                    verbatim: false,
                    parameter_name: None,
                }));
            }
            comma_before = false;
            i = end;
            continue;
        }
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
            invoked = false;
            operator_span = None;
            i += if matches!(byte, b'|' | b'&') && bytes.get(i + 1) == Some(&byte) {
                2
            } else {
                1
            };
            continue;
        }
        if byte == b'&' {
            invoked = true;
            operator_span = Some(i..i + 1);
            i += 1;
            continue;
        }
        if powershell
            && current_is_empty
            && byte == b'.'
            && segment[i + 1..]
                .chars()
                .next()
                .is_some_and(|next| next.is_whitespace() || next == '(')
        {
            invoked = true;
            operator_span = Some(i..i + 1);
            i += 1;
            continue;
        }
        if byte.is_ascii_whitespace() || (!powershell && matches!(byte, b',' | b';' | b'=')) {
            i += 1;
            continue;
        }
        if powershell && byte == b'`' {
            if bytes.get(i + 1) == Some(&b'\n') {
                i += 2;
                continue;
            }
            if bytes.get(i + 1..i + 3) == Some(b"\r\n") {
                i += 3;
                continue;
            }
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
            i = powershell_block_comment_end(segment, i);
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
            let continues_array = comma_before;
            let close = matching_paren(segment, open);
            let inner = &segment[open + 1..close];
            let mut inner_commands = lex_inner(inner, dialect, budget)?;
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
                        Lexed::Arg(arg)
                            if (position == 0 || arg.comma_before)
                                && (arg.bare_first.is_none()
                                    || !arg.word.is_all_literal()
                                    || arg.word.as_string().parse::<f64>().is_ok()) =>
                        {
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
                        invoked: false,
                        operator_span: None,
                        starts_quoted: false,
                        verbatim: false,
                        parameter_name: None,
                    }));
                }
            }
            comma_before = false;
            // The expression's own commands run too, beside the outer one.
            nested.extend(inner_commands);
            i = (close + 1).min(bytes.len());
            if continues_array
                && let Some(command) = commands.last_mut()
                && let Some(tail_start) = powershell_verbatim_start(segment, command, i)
            {
                let tail_start = skip_powershell_horizontal_space(segment, tail_start);
                let tail_end = powershell_stop_parsing_end(segment, tail_start);
                command.push(Lexed::Arg(powershell_verbatim_argument(
                    segment, tail_start, tail_end,
                )));
                i = tail_end;
            }
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
            let (arg, end) = read_word(segment, j, dialect, &mut nested, budget)?;
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
        let (mut arg, end) = read_word(segment, i, dialect, &mut nested, budget)?;
        arg.invoked = invoked && current_is_empty;
        arg.operator_span = if arg.invoked {
            operator_span.clone()
        } else {
            None
        };
        if powershell && arg.invoked && arg.starts_quoted {
            // A quoted operand can have the same value-changing postfix as
            // a parenthesized one. Leave its remaining syntax to the normal
            // scan so nested commands in an index still contribute effects.
            arg.word = if segment[end..].starts_with(['[', '.']) || segment[end..].starts_with("::")
            {
                unresolved(arg.word.range.clone())
            } else {
                // Command names require exact string values, including
                // control and Unicode escapes, rather than a path view.
                powershell_static_invocation_word(
                    &segment[arg.word.range.clone()],
                    arg.word.range.clone(),
                    budget,
                )?
            };
        }
        i = end.max(i + 1);
        let raw = &segment[arg.word.range.clone()];
        if powershell
            && current_is_empty
            && !invoked
            && ["return", "throw", "exit"]
                .iter()
                .any(|keyword| raw.eq_ignore_ascii_case(keyword))
        {
            // These statement operands are pipelines. The same words in
            // argument position, quotes or an explicit call remain data.
            continue;
        }
        arg.comma_before = comma_before;
        comma_before = false;
        if let Some(command) = commands.last_mut() {
            command.push(Lexed::Arg(arg));
            if powershell && let Some(tail_start) = powershell_verbatim_start(segment, command, i) {
                let tail_start = skip_powershell_horizontal_space(segment, tail_start);
                let tail_end = powershell_stop_parsing_end(segment, tail_start);
                command.push(Lexed::Arg(powershell_verbatim_argument(
                    segment, tail_start, tail_end,
                )));
                i = tail_end;
            }
        }
    }
    commands.extend(nested);
    commands.retain(|command| !command.is_empty());
    Ok(commands)
}

/// Comments can nest and can contain apparent commands and parentheses.
/// This scan is linear and is covered by the caller's byte-work budget.
fn powershell_block_comment_end(segment: &str, start: usize) -> usize {
    let bytes = segment.as_bytes();
    let mut index = start + 2;
    let mut depth = 1usize;
    while index < bytes.len() {
        if bytes.get(index..index + 2) == Some(b"<#") {
            depth += 1;
            index += 2;
        } else if bytes.get(index..index + 2) == Some(b"#>") {
            depth -= 1;
            index += 2;
            if depth == 0 {
                return index;
            }
        } else {
            index += 1;
        }
    }
    bytes.len()
}

/// PowerShell retains the marker and one verbatim argument in a cmdlet's
/// argv. A pending InputObject/common parameter can consume the marker,
/// leaving that remainder as a valid positional file target.
fn powershell_verbatim_start(segment: &str, command: &[Lexed], after: usize) -> Option<usize> {
    let mut args = command.iter().rev().filter_map(|item| match item {
        Lexed::Arg(arg) => Some(arg),
        Lexed::Write { .. } => None,
    });
    let mut marker = args.next()?;
    while marker.comma_before {
        marker = args.next()?;
    }
    if marker.bare_first.is_none()
        && !marker.starts_quoted
        && !segment[marker.word.range.clone()].starts_with('`')
    {
        // A value recovered from an expression such as ('--%') is not a
        // command string token. Escaped generic tokens still are markers.
        return None;
    }
    if !marker.word.is_all_literal() || marker.word.as_string() != "--%" {
        return None;
    }
    // A colon-bound value belongs to its parameter AST, so CommandRule
    // never treats that value as a standalone stop-parsing marker.
    if args.next().is_some_and(|previous| {
        previous.parameter_name.is_some() && segment[previous.word.range.clone()].ends_with(':')
    }) {
        return None;
    }
    if !marker.starts_quoted {
        return Some(after);
    }
    // Quoted strings cause parser lookahead. If the next token is a
    // parameter, PowerShell discards that token before reading the literal
    // remainder. For example -InputObject '--%' -Append /path TRUNCATES.
    powershell_parameter_lookahead_end(segment, after)
}

fn skip_powershell_horizontal_space(segment: &str, start: usize) -> usize {
    segment[start..]
        .char_indices()
        .find(|(_, ch)| !ch.is_whitespace() || matches!(ch, '\r' | '\n'))
        .map_or(segment.len(), |(offset, _)| start + offset)
}

/// The same token boundaries as PowerShell's ScanParameter: a leading
/// letter/underscore/question mark, then a name ending before a delimiter
/// or just after a colon. Embedded quotes make it a generic argument.
fn powershell_parameter_lookahead_end(segment: &str, after: usize) -> Option<usize> {
    let mut start = skip_powershell_horizontal_space(segment, after);
    loop {
        let rest = &segment[start..];
        if rest.starts_with("`\r\n") || rest.starts_with("`\n") {
            start += if rest.starts_with("`\r\n") { 3 } else { 2 };
        } else if rest.starts_with("<#") {
            let mut depth = 1usize;
            start += 2;
            while depth > 0 {
                let rest = &segment[start..];
                if rest.starts_with("<#") {
                    depth += 1;
                    start += 2;
                } else if rest.starts_with("#>") {
                    depth -= 1;
                    start += 2;
                } else {
                    start += rest.chars().next()?.len_utf8();
                }
            }
        } else {
            break;
        }
        start = skip_powershell_horizontal_space(segment, start);
    }
    let mut chars = segment[start..].char_indices();
    let (_, dash) = chars.next()?;
    if !matches!(dash, '-' | '\u{2013}' | '\u{2014}' | '\u{2015}') {
        return None;
    }
    let (_, first) = chars.next()?;
    if !first.is_alphabetic() && !matches!(first, '_' | '?') {
        return None;
    }
    for (offset, ch) in chars {
        if is_single_quote(ch) || is_double_quote(ch) {
            return None;
        }
        if ch == ':' {
            return Some(start + offset + 1);
        }
        if ch.is_whitespace()
            || matches!(
                ch,
                '{' | '}' | '(' | ')' | ';' | ',' | '|' | '&' | '.' | '['
            )
        {
            return Some(start + offset);
        }
    }
    Some(segment.len())
}

fn powershell_verbatim_argument(segment: &str, start: usize, end: usize) -> Arg {
    let raw = &segment[start..end];
    // Native programs can expand %NAME% in a stop-parsing remainder. Keep
    // that path unresolved across platforms rather than proving it safe.
    let percent_expansion = raw
        .find('%')
        .is_some_and(|first| raw[first + 1..].contains('%'));
    let text: Vec<_> = raw
        .chars()
        .map(|ch| if ch == '\\' { '/' } else { ch })
        .collect();
    let literal = text
        .iter()
        .enumerate()
        .map(|(index, ch)| {
            !(percent_expansion || matches!(ch, '*' | '?' | '[' | ']') || index == 0 && *ch == '~')
        })
        .collect();
    Arg {
        word: Word {
            text,
            literal,
            range: start..end,
            glued_paren: false,
        },
        bare_first: None,
        comma_before: false,
        invoked: false,
        operator_span: None,
        starts_quoted: false,
        verbatim: true,
        parameter_name: None,
    }
}

/// Stop-parsing preserves semicolons, escapes and redirections as argument
/// data. Only a physical newline or an unquoted pipeline/chain resumes shell
/// syntax; even an open quote or a backtick cannot continue past the newline.
fn powershell_stop_parsing_end(segment: &str, start: usize) -> usize {
    let mut double_quoted = false;
    let mut chars = segment[start..].char_indices().peekable();
    while let Some((offset, ch)) = chars.next() {
        if matches!(ch, '\r' | '\n')
            || (!double_quoted
                && (ch == '|' || (ch == '&' && chars.peek().is_some_and(|(_, next)| *next == '&'))))
        {
            return start + offset;
        }
        if is_double_quote(ch) {
            double_quoted = !double_quoted;
        }
    }
    segment.len()
}

/// Byte index of the `)` closing the `(` at `open`, or the segment's end.
fn matching_paren(segment: &str, open: usize) -> usize {
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut chars = segment[open..].char_indices().peekable();
    while let Some((offset, ch)) = chars.next() {
        if ch == '`' && !quote.is_some_and(is_single_quote) {
            chars.next();
            continue;
        }
        match quote {
            Some(q)
                if (is_single_quote(q) && is_single_quote(ch))
                    || (is_double_quote(q) && is_double_quote(ch)) =>
            {
                if chars.peek().is_some_and(|(_, next)| {
                    (is_single_quote(q) && is_single_quote(*next))
                        || (is_double_quote(q) && is_double_quote(*next))
                }) {
                    chars.next();
                } else {
                    quote = None;
                }
            }
            Some(_) => {}
            None if ch == '#'
                && segment[..open + offset]
                    .chars()
                    .next_back()
                    .is_none_or(|previous| {
                        previous.is_whitespace()
                            || matches!(previous, '(' | ';' | '|' | '&' | '{' | '}')
                    }) =>
            {
                for (_, next) in chars.by_ref() {
                    if matches!(next, '\r' | '\n') {
                        break;
                    }
                }
            }
            None if ch == '<'
                && crate::context::powershell_block_comment_starts_at(
                    segment.as_bytes(),
                    open + offset,
                ) =>
            {
                chars.next();
                let mut comment_depth = 1usize;
                while let Some((_, next)) = chars.next() {
                    if next == '<' && chars.peek().is_some_and(|(_, next)| *next == '#') {
                        chars.next();
                        comment_depth += 1;
                    } else if next == '#' && chars.peek().is_some_and(|(_, next)| *next == '>') {
                        chars.next();
                        comment_depth -= 1;
                        if comment_depth == 0 {
                            break;
                        }
                    }
                }
            }
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
            Lexed::Arg(arg) => {
                if let Some(operator_span) = arg.operator_span.as_mut() {
                    operator_span.start += by;
                    operator_span.end += by;
                }
                &mut arg.word
            }
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

/// Literal command names and computed literal operands share one decoder.
/// Only their path separators are normalized for command identity; their
/// quote/escape values and original source locations must stay exact.
fn powershell_static_invocation_word(
    expression: &str,
    range: std::ops::Range<usize>,
    budget: &mut LexBudget,
) -> Result<Word, WindowsShellParseIncomplete> {
    budget.charge(expression.len())?;
    match decode_powershell_static_executable(expression) {
        Ok(name) => {
            let text: Vec<_> = name
                .chars()
                .map(|ch| if ch == '\\' { '/' } else { ch })
                .collect();
            Ok(Word {
                literal: vec![true; text.len()],
                text,
                range,
                glued_paren: false,
            })
        }
        Err(PowerShellStaticExecutableError::NotStatic) => Ok(unresolved(range)),
        Err(PowerShellStaticExecutableError::Work) => Err(WindowsShellParseIncomplete::Work),
        Err(PowerShellStaticExecutableError::Nesting) => Err(WindowsShellParseIncomplete::Nesting),
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
            invoked: false,
            operator_span: None,
            starts_quoted: false,
            verbatim: false,
            parameter_name: None,
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
fn read_word(
    segment: &str,
    start: usize,
    dialect: ShellDialect,
    nested: &mut Vec<Vec<Lexed>>,
    budget: &mut LexBudget,
) -> Result<(Arg, usize), WindowsShellParseIncomplete> {
    let powershell = dialect != ShellDialect::Cmd;
    let mut text: Vec<char> = Vec::new();
    let mut literal: Vec<bool> = Vec::new();
    let mut quote: Option<char> = None;
    let mut bare_first = None;
    let starts_quoted = powershell
        && segment[start..]
            .chars()
            .next()
            .is_some_and(|ch| is_single_quote(ch) || is_double_quote(ch));
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
                        if starts_quoted {
                            end = here + ch.len_utf8();
                            break;
                        }
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
                        if starts_quoted {
                            end = here + ch.len_utf8();
                            break;
                        }
                    }
                } else if powershell && ch == '`' {
                    if let Some((_, escaped)) = chars.next() {
                        push(&mut text, &mut literal, escaped, true);
                    }
                } else if powershell && ch == '$' {
                    powershell_expansion(
                        &mut chars,
                        &mut text,
                        &mut literal,
                        segment,
                        start,
                        nested,
                        budget,
                    )?;
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
                let terminator = (if powershell {
                    ch.is_whitespace()
                } else {
                    ch.is_ascii_whitespace()
                }) || matches!(ch, '|' | '&' | '<' | '>' | '(' | ')')
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
                    '$' if powershell => powershell_expansion(
                        &mut chars,
                        &mut text,
                        &mut literal,
                        segment,
                        start,
                        nested,
                        budget,
                    )?,
                    '%' | '!' if !powershell => {
                        cmd_expansion(ch, &mut chars, &mut text, &mut literal);
                    }
                    other => push(&mut text, &mut literal, other, true),
                }
            }
        }
    }
    let word = Word {
        text,
        literal,
        range: start..end,
        glued_paren: false,
    };
    let parameter_name = bare_first
        .filter(|ch| matches!(ch, '-' | '\u{2013}' | '\u{2014}' | '\u{2015}'))
        .and_then(|dash| {
            let name = segment[start + dash.len_utf8()..end]
                .split(':')
                .next()
                .unwrap_or_default();
            // Quoted fragments make this an argument, e.g. -File'notes'
            // names the literal positional file -Filenotes. Backticks in a
            // parameter name, by contrast, remain part of its invalid name.
            (!name
                .chars()
                .any(|ch| is_single_quote(ch) || is_double_quote(ch)))
            .then(|| name.to_string())
        });
    Ok((
        Arg {
            word,
            bare_first,
            comma_before: false,
            invoked: false,
            operator_span: None,
            starts_quoted,
            verbatim: false,
            parameter_name,
        },
        end,
    ))
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
    source: &str,
    word_start: usize,
    nested: &mut Vec<Vec<Lexed>>,
    budget: &mut LexBudget,
) -> Result<(), WindowsShellParseIncomplete> {
    let name = match chars.peek().map(|(_, next)| *next) {
        Some('(') => {
            let open = word_start + chars.peek().expect("opening parenthesis").0;
            let close = matching_paren(source, open);
            let mut commands =
                lex_inner(&source[open + 1..close], ShellDialect::PowerShell, budget)?;
            for command in &mut commands {
                shift(command, open + 1);
            }
            nested.extend(commands);
            while chars
                .peek()
                .is_some_and(|(offset, _)| word_start + offset <= close)
            {
                chars.next();
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
            return Ok(());
        }
    };
    // `$HOME` is an automatic variable; `$env:X` is the environment. Any
    // other scope (`$global:x`, a script variable) is unknown text.
    let lower = name.to_ascii_lowercase();
    if matches!(lower.as_str(), "true" | "false" | "null") {
        text.push('$');
        literal.push(false);
        for ch in lower.to_ascii_uppercase().chars() {
            text.push(ch);
            literal.push(false);
        }
        return Ok(());
    }
    let resolved = if lower == "home" {
        "HOME"
    } else if let Some(env) = lower.strip_prefix("env:") {
        &name[name.len() - env.len()..]
    } else {
        ""
    };
    emit_variable(resolved, text, literal);
    Ok(())
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

/// Credential roots are volume-independent. Keep the original decoded path
/// until this policy boundary: truncation's local existence proof must not
/// confuse C:/Users/... with /Users/... on a different host.
fn path_word(mut word: Word) -> Word {
    strip_volume_prefix(&mut word.text, &mut word.literal);
    word
}

#[cfg(test)]
mod tests {
    use super::super::{CREDENTIAL_FILE_WRITE_NAME, GIT_INTERNALS_WRITE_NAME};
    use super::*;
    // Preserve the original issue-642 fixture names while exercising the
    // generalized collector and candidate gate with those same commands.
    use super::{
        powershell_file_truncation_targets as powershell_tee_truncation_targets,
        powershell_file_writer_scan_required as powershell_tee_scan_required,
    };

    fn ps(command: &str) -> Option<CredentialFileWrite> {
        super::super::classify_credential_file_write(command, ShellDialect::PowerShell)
    }

    fn cmd(command: &str) -> Option<CredentialFileWrite> {
        super::super::classify_credential_file_write(command, ShellDialect::Cmd)
    }

    /// `mklink` creates the link at its FIRST operand (#451).
    ///
    /// Replacing a key with a link is the classic substitution: the file the
    /// daemon reads becomes one the caller controls. POSIX `ln -sf` and
    /// PowerShell's `New-Item -ItemType SymbolicLink` both deny it; cmd's
    /// spelling allowed every form. The operand order is the trap — `mklink
    /// <link> <target>` names what it CREATES first, the opposite way round
    /// from `copy` and `move`, so reading it as a copy would judge the wrong
    /// path and quietly find nothing.
    #[test]
    fn cmd_mklink_at_a_protected_path_denies_issue_451() {
        let key = "%USERPROFILE%/.ssh/authorized_keys";
        for command in [
            format!("mklink {key} C:/tmp/evil"),
            // /D symbolic directory, /H hard link, /J junction.
            format!("mklink /D {key} C:/tmp/evil"),
            format!("mklink /H {key} C:/tmp/evil"),
            "mklink /J %USERPROFILE%/.ssh C:/tmp/evil".to_string(),
        ] {
            let found = cmd(&command).unwrap_or_else(|| panic!("must deny: {command}"));
            assert_eq!(found.rule, CREDENTIAL_FILE_WRITE_NAME, "{command}");
        }
    }

    /// The link rule turns on WHERE the link is created, not on `mklink` (#451).
    ///
    /// The second operand is only pointed at, so naming a protected path there
    /// is a read and must stay allowed — the same asymmetry POSIX `ln` has.
    #[test]
    fn cmd_mklink_still_turns_on_the_created_name_issue_451() {
        for command in [
            "mklink C:/app/link C:/app/target",
            "mklink /D C:/app/link C:/app/target",
            // Pointing a NEW ordinary link at a key reads the key; it does not
            // replace it.
            "mklink C:/app/link %USERPROFILE%/.ssh/authorized_keys",
            // The public half stays exempt.
            "mklink %USERPROFILE%/.ssh/id_rsa.pub C:/tmp/evil",
        ] {
            assert!(cmd(command).is_none(), "must stay allowed: {command}");
        }
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

    /// The reported bypass and native parameter-binding equivalents. Input
    /// data and common-parameter values must not displace the file operand.
    #[test]
    fn powershell_tee_truncation_binds_targets_issue_642() {
        for command in [
            "Get-Date | Tee-Object -FilePath /var/lib/important.txt",
            "Get-Date | Tee-Object /var/lib/important.txt",
            "Get-Date | tee /var/lib/important.txt",
            "Get-Date | tEe-ObJeCt -fIlEpAtH /var/lib/important.txt",
            "Tee-Object -Path /var/lib/important.txt",
            "Tee-Object -pa /var/lib/important.txt",
            "Tee-Object -f /var/lib/important.txt",
            "Tee-Object -LiteralPath /var/lib/important.txt",
            "Tee-Object -PSPath /var/lib/important.txt",
            "Tee-Object -ps /var/lib/important.txt",
            "Tee-Object -LP /var/lib/important.txt",
            "Tee-Object -lit /var/lib/important.txt",
            "Tee-Object -InputObject '/tmp/input' /var/lib/important.txt",
            "Tee-Object -in '/tmp/input' /var/lib/important.txt",
            "Tee-Object -i '/tmp/input' /var/lib/important.txt",
            "Tee-Object -e utf8 /var/lib/important.txt",
            "Tee-Object -Encoding utf8 /var/lib/important.txt",
            "Tee-Object -ErrorVariable errors /var/lib/important.txt",
            "Tee-Object -ev errors /var/lib/important.txt",
            "Tee-Object -OutVariable '-Append' /var/lib/important.txt",
            "Tee-Object -InputObject '-WhatIf' /var/lib/important.txt",
            "Tee-Object -vb /var/lib/important.txt",
            "Tee-Object -Debug:$false /var/lib/important.txt",
            "Tee-Object -- /var/lib/important.txt",
            "Tee-Object -InputObject x -- /var/lib/important.txt",
            "Tee-Object -FilePath:/var/lib/important.txt",
            "Tee-Object -FilePath: /var/lib/important.txt",
            "Tee-Object -FilePath:'/var/lib/important.txt'",
            "Tee-Object -FilePath: '/var/lib/important.txt'",
            "Tee-Object ('/var/lib/important.txt')",
            "Tee-Object -FilePath:('/var/lib/important.txt')",
            "Tee-Object -FilePath: ('/var/lib/important.txt')",
            "Tee-Object -FilePath('/var/lib/important.txt')",
            "Tee-Object -FilePath:/var/lib/important'.txt'",
            "Tee-Object \u{2013}FilePath /var/lib/important.txt",
            "Tee-Object -FilePath \u{2018}/var/lib/important.txt\u{2019}",
            "Microsoft.PowerShell.Utility\\Tee-Object /var/lib/important.txt",
            "Tee-Ob`ject /var/lib/important.txt",
            "Tee-Object `\n -FilePath /var/lib/important.txt",
            "Tee-Object `\r\n -FilePath /var/lib/important.txt",
        ] {
            let targets = powershell_tee_truncation_targets(command).expect("bounded fixture");
            assert_eq!(targets.len(), 1, "target binding: {command}: {targets:?}");
            assert_eq!(targets[0].path, "/var/lib/important.txt", "{command}");
            assert!(targets[0].literal, "{command}");
            assert_eq!(targets[0].home_suffix, None, "{command}");
        }
    }

    #[test]
    fn powershell_tee_truncation_preserves_actual_and_policy_paths_issue_642() {
        for (command, path, policy_path) in [
            (
                r"Get-Date | Tee-Object -FilePath 'C:\Users\me\important.txt'",
                "C:/Users/me/important.txt",
                "/Users/me/important.txt",
            ),
            (
                r"Get-Date | Tee-Object 'C:\Users\me\important.txt'",
                "C:/Users/me/important.txt",
                "/Users/me/important.txt",
            ),
            (
                r"Tee-Object -FilePath 'FileSystem::C:\Users\me\important.txt'",
                "FileSystem::C:/Users/me/important.txt",
                "/Users/me/important.txt",
            ),
            (
                "Tee-Object -FilePath '/var/lib/important file.txt'",
                "/var/lib/important file.txt",
                "/var/lib/important file.txt",
            ),
            (
                "Tee-Object /var/lib/important` file.txt",
                "/var/lib/important file.txt",
                "/var/lib/important file.txt",
            ),
            (
                "Tee-Object '/var/lib/it''s important.txt'",
                "/var/lib/it's important.txt",
                "/var/lib/it's important.txt",
            ),
        ] {
            let targets = powershell_tee_truncation_targets(command).expect("bounded fixture");
            assert_eq!(targets.len(), 1, "{command}: {targets:?}");
            assert_eq!(targets[0].path, path, "actual path: {command}");
            assert_eq!(
                targets[0].policy_path, policy_path,
                "policy path: {command}"
            );
            assert!(targets[0].literal, "{command}");
        }
    }

    /// PowerShell recognizes these Unicode spaces between tokens. An ASCII
    /// lexer would read the entire cmdlet and destination as one safe word.
    #[test]
    fn powershell_tee_truncation_accepts_unicode_whitespace_issue_642() {
        for whitespace in [
            '\u{0085}', '\u{00a0}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}',
            '\u{2004}', '\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}', '\u{2009}', '\u{200a}',
            '\u{2028}', '\u{2029}', '\u{202f}', '\u{205f}', '\u{3000}',
        ] {
            let command =
                format!("Tee-Object{whitespace}-FilePath{whitespace}/var/lib/important.txt");
            let targets = powershell_tee_truncation_targets(&command).expect("bounded fixture");
            assert_eq!(targets.len(), 1, "PowerShell whitespace: {whitespace:?}");
            assert_eq!(targets[0].path, "/var/lib/important.txt");
            assert_eq!(&command[targets[0].span.clone()], "Tee-Object");
        }
    }

    #[test]
    fn powershell_tee_truncation_requires_proven_append_issue_642() {
        for value in [
            "$false",
            "${false}",
            "0",
            "0.0",
            "0x0",
            "$flag",
            "($false)",
            " ( $false )",
            "$($false)",
            "$(0)",
            "(!$true)",
            " $false",
        ] {
            let command = format!("Tee-Object /var/lib/important.txt -Append:{value}");
            let targets = powershell_tee_truncation_targets(&command).expect("bounded fixture");
            assert_eq!(targets.len(), 1, "possibly truncating: {command}");
            assert_eq!(targets[0].path, "/var/lib/important.txt", "{command}");
        }
        for flag in [
            "-Append",
            "-a",
            "-Append:$true",
            "-Append:${true}",
            "-Append:$null",
            "-Append:1",
            "-Append:2",
            "-Append:0.5",
            "-Append:0x1",
            "-Append: $true",
            "-Append:($true)",
        ] {
            let command = format!("Tee-Object /var/lib/important.txt {flag}");
            assert!(
                powershell_tee_truncation_targets(&command)
                    .expect("bounded fixture")
                    .is_empty(),
                "proven append: {command}"
            );
        }
    }

    /// Tee has disjoint File, LiteralFile and Variable sets. In particular,
    /// WhatIf is unsupported; allowing its binding error is not a preview.
    #[test]
    fn powershell_tee_truncation_respects_variable_and_binding_errors_issue_642() {
        for command in [
            "Tee-Object -Variable captured",
            "Tee-Object -v captured",
            "Tee-Object -Variable '/var/lib/important.txt'",
            "Tee-Object -Variable captured @options",
            "Tee-Object @options -Variable captured",
            "Tee-Object /var/lib/important.txt -WhatIf",
            "Tee-Object /var/lib/important.txt -WhatIf:$false",
            "Tee-Object /var/lib/important.txt -wi",
            "Tee-Object /var/lib/important.txt -Confirm:$false",
            "Tee-Object -p /var/lib/important.txt",
            "Tee-Object -File`Path /var/lib/important.txt",
            "Tee-Object -File'Path' /var/lib/important.txt",
            "Tee-Object -Fi\"lePath\" /var/lib/important.txt",
            "Tee-Object '' -FilePath /var/lib/important.txt",
            "Tee-Object /var/lib/important.txt -Variable captured",
            "Tee-Object -Variable captured -FilePath /var/lib/important.txt",
            "Tee-Object -LiteralPath /var/lib/important.txt -Append",
            "Tee-Object /var/lib/important.txt -Append -Append:$false",
            "Tee-Object -FilePath /tmp/a -Path /var/lib/important.txt",
        ] {
            let targets = powershell_tee_truncation_targets(command).expect("bounded fixture");
            assert!(
                targets.is_empty(),
                "no file operation: {command}: {targets:?}"
            );
        }
    }

    #[test]
    fn powershell_tee_truncation_keeps_parameter_looking_filename_data_issue_642() {
        for (command, path) in [
            ("Tee-Object '-Append'", "-Append"),
            ("Tee-Object '-Variable'", "-Variable"),
            ("Tee-Object '--'", "--"),
            ("Tee-Object '--%'", "--%"),
            ("Tee-Object -- -Append", "-Append"),
            ("Tee-Object -- -Variable", "-Variable"),
            ("Tee-Object -InputObject x -- -Append", "-Append"),
            ("Tee-Object -File'Path'", "-FilePath"),
            ("Tee-Object -FilePath'file.txt'", "-FilePathfile.txt"),
            ("Tee-Object -FilePath\"file.txt\"", "-FilePathfile.txt"),
            (
                "Tee-Object -FilePath'/path/file.txt'",
                "-FilePath/path/file.txt",
            ),
            ("Tee-Object -Append'$false'", "-Append$false"),
            ("Tee-Object -Append''", "-Append"),
        ] {
            let targets = powershell_tee_truncation_targets(command).expect("bounded fixture");
            assert_eq!(targets.len(), 1, "literal operand: {command}");
            assert_eq!(targets[0].path, path, "{command}");
            assert!(targets[0].literal, "{command}");
        }
    }

    #[test]
    fn powershell_tee_truncation_distinguishes_wildcards_and_literalpath_issue_642() {
        for (parameter, literal) in [
            ("-FilePath", false),
            ("-Path", false),
            ("-LiteralPath", true),
            ("-PSPath", true),
            ("-LP", true),
        ] {
            let command = format!("Tee-Object {parameter} '/var/lib/file[1].txt'");
            let targets = powershell_tee_truncation_targets(&command).expect("bounded fixture");
            assert_eq!(targets.len(), 1, "{command}");
            assert_eq!(targets[0].path, "/var/lib/file[1].txt", "{command}");
            assert_eq!(targets[0].literal, literal, "{command}");
        }
        for command in [
            "Tee-Object -LiteralPath $destination",
            "Tee-Object -LiteralPath \"$destination/file[1].txt\"",
        ] {
            let targets = powershell_tee_truncation_targets(command).expect("bounded fixture");
            assert_eq!(targets.len(), 1, "{command}");
            assert!(
                !targets[0].literal,
                "expansion survives LiteralPath: {command}"
            );
        }
    }

    #[test]
    fn powershell_tee_truncation_carries_home_and_unknown_paths_issue_642() {
        for command in [
            "Tee-Object ~/important.txt",
            "Tee-Object '~/important.txt'",
            "Tee-Object -FilePath:~/important.txt",
            "Tee-Object -LiteralPath '~/important.txt'",
        ] {
            let targets = powershell_tee_truncation_targets(command).expect("bounded fixture");
            assert_eq!(targets.len(), 1, "{command}");
            assert_eq!(targets[0].path, "~/important.txt", "{command}");
            assert!(!targets[0].literal, "{command}");
            assert_eq!(targets[0].home_suffix.as_deref(), Some("important.txt"));
        }
        for command in [
            "Tee-Object $destination",
            "Tee-Object -FilePath ($destination)",
            "Tee-Object -FilePath $(Get-Target)",
            "Tee-Object @options",
            "Tee-Object -InputObject x @options",
            "Tee-Object -Append:$flag @options",
        ] {
            let targets = powershell_tee_truncation_targets(command).expect("bounded fixture");
            assert_eq!(targets.len(), 1, "unresolved target: {command}");
            assert!(!targets[0].literal, "{command}");
            assert_eq!(targets[0].home_suffix, None, "{command}");
        }
    }

    #[test]
    fn powershell_tee_truncation_distinguishes_invocation_from_data_issue_642() {
        for command in [
            "Write-Output 'Tee-Object /var/lib/important.txt'",
            "Write-Output Tee-Object -FilePath /var/lib/important.txt",
            "'Tee-Object'",
            "\"Tee-Object\"",
            "# Tee-Object /var/lib/important.txt",
            "Write-Output x # Tee-Object /var/lib/important.txt",
            "Write-Output @'\nTee-Object /var/lib/important.txt\n'@",
            "/usr/bin/tee /var/lib/important.txt",
            "./tee /var/lib/important.txt",
            "C:\\tools\\tee.exe /var/lib/important.txt",
            "Other.Module\\Tee-Object /var/lib/important.txt",
        ] {
            assert!(
                powershell_tee_truncation_targets(command)
                    .expect("bounded fixture")
                    .is_empty(),
                "not an executable Tee-Object cmdlet: {command}"
            );
        }
        for (command, command_word) in [
            ("& 'Tee-Object' /var/lib/important.txt", "'Tee-Object'"),
            ("& \"Tee-Object\" /var/lib/important.txt", "\"Tee-Object\""),
            (". 'Tee-Object' /var/lib/important.txt", "'Tee-Object'"),
            ("'x' | & Tee-Object /var/lib/important.txt", "Tee-Object"),
        ] {
            let targets = powershell_tee_truncation_targets(command).expect("bounded fixture");
            assert_eq!(targets.len(), 1, "{command}");
            assert_eq!(targets[0].path, "/var/lib/important.txt", "{command}");
            assert_eq!(&command[targets[0].span.clone()], command_word, "{command}");
        }
    }

    /// Append/Variable/binding failures on an outer or neighboring command
    /// do not erase the independently executing nested writer's destination.
    #[test]
    fn powershell_tee_truncation_nested_writes_keep_command_spans_issue_642() {
        for command in [
            "Write-Output (Tee-Object -InputObject x /var/lib/important.txt)",
            "Tee-Object -Variable captured -InputObject (Tee-Object -InputObject x /var/lib/important.txt)",
            "Tee-Object -WhatIf -InputObject (Tee-Object -InputObject x /var/lib/important.txt)",
            "Tee-Object /tmp/log -Append -InputObject (Tee-Object -InputObject x /var/lib/important.txt)",
            "Tee-Object /tmp/log -Append; Tee-Object /var/lib/important.txt",
            "Tee-Object -Variable captured; Tee-Object /var/lib/important.txt",
        ] {
            let targets = powershell_tee_truncation_targets(command).expect("bounded fixture");
            assert_eq!(targets.len(), 1, "independent nested write: {command}");
            assert_eq!(targets[0].path, "/var/lib/important.txt", "{command}");
            assert_eq!(&command[targets[0].span.clone()], "Tee-Object", "{command}");
            assert_eq!(
                targets[0].span.start,
                command
                    .rfind("Tee-Object")
                    .expect("fixture contains command"),
                "nested offsets must be relative to the full command: {command}"
            );
        }
    }

    /// Candidate selection must still reach credential policy when decoded
    /// -Append removes every general truncation target and no raw writer or
    /// credential-directory keyword survives the backtick escapes.
    #[test]
    fn powershell_tee_append_keeps_credential_semantic_gate_issue_642() {
        for command in [
            r"'key' | T`ee-Object -Append C:\Users\me\.s`sh\authorized_keys",
            r"'key' | t`ee -a C:\Users\me\.s`sh\authorized_keys",
            r"'key' | Microsoft.PowerShell.Utility\T`ee-Object -Append C:\Users\me\.s`sh\authorized_keys",
        ] {
            assert!(
                powershell_tee_truncation_targets(command)
                    .expect("bounded fixture")
                    .is_empty(),
                "append is not general truncation: {command}"
            );
            assert!(
                crate::packs::core::filesystem::filesystem_semantic_scan_required(
                    command,
                    ShellDialect::PowerShell,
                ),
                "append still reaches credential policy: {command}"
            );
            let hit = ps(command).unwrap_or_else(|| panic!("must protect credentials: {command}"));
            assert_eq!(hit.rule, CREDENTIAL_FILE_WRITE_NAME, "{command}");
        }
        for command in [
            "Tee-Object -Variable captured",
            "Tee-Object -Append /tmp/log",
            "& 'Tee-Object' -Append /tmp/log",
            "tee --append /tmp/log",
        ] {
            assert!(powershell_tee_scan_required(command), "{command}");
        }
        for command in [
            "Write-Output 'Tee-Object -Append /etc/hosts'",
            "Write-Output Tee-Object -Append /etc/hosts",
            "'Tee-Object'",
            "Get-Date # Tee-Object -Append /etc/hosts",
        ] {
            assert!(!powershell_tee_scan_required(command), "{command}");
        }
    }

    /// Both expression paths must share the recursion cap and surface the
    /// error through the candidate gate instead of silently dropping writes.
    #[test]
    fn powershell_tee_parser_bounds_nested_expressions_issue_642() {
        for opener in ["(", "$("] {
            let mut command = "Tee-Object /var/lib/important.txt".to_string();
            for _ in 1..MAX_LEX_DEPTH {
                command = format!("Write-Output {opener}{command})");
            }
            let targets = powershell_tee_truncation_targets(&command)
                .expect("the maximum supported depth remains inspectable");
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].path, "/var/lib/important.txt");

            // Exercise the quoted expansion path as well as ordinary groups.
            let command = format!("Write-Output \"$({command})\"");
            assert_eq!(
                powershell_tee_truncation_targets(&command).expect_err("exceeds nesting cap"),
                WindowsShellParseIncomplete::Nesting,
            );
            assert!(powershell_tee_scan_required(&command));
        }
    }

    #[test]
    fn powershell_tee_parser_bounds_cumulative_work_issue_642() {
        let mut command = format!("Write-Output '{}'", "x".repeat(MAX_LEX_WORK_BYTES / 16));
        for _ in 0..16 {
            command = format!("Write-Output ({command})");
        }
        assert!(command.len() < MAX_LEX_WORK_BYTES);
        assert_eq!(
            powershell_tee_truncation_targets(&command).expect_err("repeated work exceeds cap"),
            WindowsShellParseIncomplete::Work,
        );
        assert!(powershell_tee_scan_required(&command));

        let oversized = "x".repeat(MAX_LEX_WORK_BYTES + 1);
        assert_eq!(
            powershell_tee_truncation_targets(&oversized).expect_err("input exceeds work cap"),
            WindowsShellParseIncomplete::Work,
        );
        assert!(powershell_tee_scan_required(&oversized));
        assert!(
            powershell_tee_truncation_targets("Write-Output 'ordinary data'")
                .expect("bounded command")
                .is_empty()
        );
        assert!(!powershell_tee_scan_required(
            "Write-Output 'ordinary data'"
        ));
    }

    #[test]
    fn powershell_native_tee_output_error_mode_prefixes_keep_writes_issue_642() {
        for option in [
            "--output-error=warn",
            "--output-error=warn-n",
            "--out=warn-nop",
            "--output-error=exit",
            "--output-e=exit-n",
        ] {
            let command = format!("tee {option} /var/lib/important.txt");
            let targets = powershell_tee_truncation_targets(&command).expect("bounded fixture");
            assert!(
                targets
                    .iter()
                    .any(|target| target.path == "/var/lib/important.txt"),
                "valid native option must retain its file operand: {command}"
            );
            let credential = format!("tee {option} ~/.ssh/authorized_keys");
            let hit = ps(&credential).unwrap_or_else(|| panic!("must deny: {credential}"));
            assert_eq!(hit.rule, CREDENTIAL_FILE_WRITE_NAME, "{credential}");
        }
        for value in ["", "w", "e", "wrong"] {
            let command = format!("tee --output-error={value} ~/.ssh/authorized_keys");
            assert!(
                ps(&command).is_none(),
                "invalid native mode does not write: {command}"
            );
        }
    }

    #[test]
    fn powershell_tee_stop_parsing_preserves_file_binding_issue_642() {
        for command in [
            "Tee-Object -InputObject --% /etc/hosts",
            "Tee-Object -InputObject `--% /etc/hosts",
            "Tee-Object -InputObject --`% /etc/hosts",
            "Tee-Object -InputObject --'%' /etc/hosts",
            "Tee-Object -InputObject '--%' -FilePath /etc/hosts",
            "Tee-Object -InputObject \"--%\" -FilePath /etc/hosts",
            "Tee-Object -InputObject '--%' -Append /etc/hosts",
            "Tee-Object -InputObject '--%' -Variable /etc/hosts",
            "Tee-Object -InputObject '--%' -WhatIf /etc/hosts",
            "Tee-Object -InputObject '--%' -Confirm /etc/hosts",
            "Tee-Object -InputObject '--%' -Unknown /etc/hosts",
            "Tee-Object -InputObject '--%' -App`end /etc/hosts",
            "Tee-Object -InputObject '--%',1 -Append /etc/hosts",
            "Tee-Object -InputObject '--%',(1) -Append /etc/hosts",
            "Tee-Object -InputObject '--%',$false -Append /etc/hosts",
            "Tee-Object -InputObject NEW -OutVariable --% /etc/hosts",
            "Tee-Object -InputObject NEW -PipelineVariable --% /etc/hosts",
            "Tee-Object -InputObject 'NEW'-FilePath /etc/hosts",
        ] {
            let targets = powershell_tee_truncation_targets(command).expect("bounded fixture");
            assert_eq!(targets.len(), 1, "{command}");
            assert_eq!(targets[0].path, "/etc/hosts", "{command}");
            assert!(targets[0].literal, "{command}");
        }
        for switch in ["-Append", "-Variable", "-WhatIf"] {
            let command = format!("Tee-Object -InputObject '--%' {switch} ~/.ssh/id_rsa");
            assert!(
                ps(&command).is_some(),
                "discarded switch cannot exempt credentials: {command}"
            );
        }
        let command = "Tee-Object -InputObject --% %DESTINATION%";
        let targets = powershell_tee_truncation_targets(command).expect("bounded fixture");
        assert_eq!(targets.len(), 1);
        assert!(
            !targets[0].literal,
            "native environment expansion is unresolved"
        );
    }

    #[test]
    fn powershell_tee_stop_parsing_keeps_append_and_binding_errors_issue_642() {
        for command in [
            "Tee-Object --%",
            "Tee-Object --% inert",
            "Tee-Object -FilePath /etc/hosts --%",
            "Tee-Object -FilePath /etc/hosts --% inert",
            "Tee-Object -InputObject --%",
            "Tee-Object -InputObject NEW -FilePath /etc/hosts '--%'",
            "Tee-Object -InputObject '--%' '-Append' /etc/hosts",
            "Tee-Object -InputObject:'--%' -Append /etc/hosts",
            "Tee-Object -InputObject:--% -Append /etc/hosts",
            "Tee-Object -InputObject: '--%' -Append /etc/hosts",
            "Tee-Object -InputObject ('--%') -Append /etc/hosts",
            "Tee-Object -InputObject ('--%'),(1) -Append /etc/hosts",
            "Tee-Object -Append -InputObject '--%' /etc/hosts",
            "Tee-Object -InputObject '-'\"\"'-%' -FilePath /etc/hosts",
        ] {
            assert!(
                powershell_tee_truncation_targets(command)
                    .expect("bounded fixture")
                    .is_empty(),
                "{command}"
            );
        }
        let command = "Tee-Object '--%' ; Tee-Object /etc/hosts";
        let targets = powershell_tee_truncation_targets(command).expect("bounded fixture");
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].path, "--%");
        assert_eq!(targets[1].path, "/etc/hosts");
    }

    #[test]
    fn powershell_tee_stop_parsing_resumes_at_real_boundaries_issue_642() {
        for marker in ["--%", "`--%", "--`%", "--'%'", "''--%"] {
            let command = format!("Write-Output {marker} ; Tee-Object /etc/hosts");
            assert!(
                powershell_tee_truncation_targets(&command)
                    .expect("bounded fixture")
                    .is_empty(),
                "the semicolon is literal: {command}"
            );
        }
        for marker in ["'--%'", "\"--%\"", "'--'%", "'-'\"\"'-%'"] {
            let command = format!("Write-Output {marker} ; Tee-Object /etc/hosts");
            let targets = powershell_tee_truncation_targets(&command).expect("bounded fixture");
            assert_eq!(targets.len(), 1, "{command}");
            assert_eq!(targets[0].path, "/etc/hosts", "{command}");
        }
        for boundary in ["\n", "\r\n", "`\n", " | ", " && "] {
            let command = format!("Write-Output --% inert{boundary}Tee-Object /etc/hosts");
            let targets = powershell_tee_truncation_targets(&command).expect("bounded fixture");
            assert_eq!(targets.len(), 1, "{command}");
            assert_eq!(targets[0].path, "/etc/hosts", "{command}");
        }
    }

    #[test]
    fn powershell_quoted_names_are_data_in_both_credential_collectors_issue_642() {
        for command in [
            "'Tee-Object' -FilePath ~/.ssh/id_rsa",
            "\"Tee-Object\" -FilePath ~/.ssh/id_rsa",
            "'tee' ~/.ssh/id_rsa",
        ] {
            assert!(ps(command).is_none(), "{command}");
            assert!(
                classify_all(command, ShellDialect::PowerShell).is_empty(),
                "{command}"
            );
        }
        for command in [
            "& 'Tee-Object' -FilePath ~/.ssh/id_rsa",
            ". 'Tee-Object' -FilePath ~/.ssh/id_rsa",
            "'ordinary string data' > ~/.ssh/id_rsa",
        ] {
            assert!(ps(command).is_some(), "{command}");
            assert!(
                !classify_all(command, ShellDialect::PowerShell).is_empty(),
                "{command}"
            );
        }
    }

    #[test]
    fn powershell_assignment_prefixes_preserve_nested_writes_issue_642() {
        for command in [
            "$(Tee-Object /etc/hosts); $x = 1",
            "$items[(Tee-Object /etc/hosts)] = 1",
            "$items[(Tee-Object /etc/hosts)] += 1",
        ] {
            let targets = powershell_tee_truncation_targets(command).expect("bounded fixture");
            assert_eq!(targets.len(), 1, "{command}");
            assert_eq!(targets[0].path, "/etc/hosts", "{command}");
            assert_eq!(&command[targets[0].span.clone()], "Tee-Object", "{command}");
        }
    }

    #[test]
    fn powershell_native_tee_stop_parsing_keeps_possible_writes_issue_642() {
        let targets =
            powershell_tee_truncation_targets("tee --% /etc/hosts").expect("bounded fixture");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].path, "/etc/hosts");
        assert!(targets[0].literal);

        for command in ["tee --%", "tee -a --% /etc/hosts"] {
            assert!(
                powershell_tee_truncation_targets(command)
                    .expect("bounded fixture")
                    .is_empty(),
                "{command}"
            );
        }
        // Native argv splitting is opaque here, so a possible operand must
        // survive even when the remainder is not a single decoded path.
        for command in [
            "tee --% -a /etc/hosts",
            "tee --% /etc/hosts /tmp/log",
            "tee --% \"/etc/hosts\"",
            "tee --% %DESTINATION%",
        ] {
            let targets = powershell_tee_truncation_targets(command).expect("bounded fixture");
            assert!(!targets.is_empty(), "{command}");
            assert!(targets.iter().any(|target| !target.literal), "{command}");
        }
    }

    #[test]
    fn powershell_computed_tee_invocations_preserve_names_arguments_and_spans() {
        for (operator, operand) in [
            ("&", "('Tee-Object')"),
            (".", "('Tee-'+'Object')"),
            ("&", "((('Tee-Object')))"),
            ("&", "(('Tee-')+('Object'))"),
            ("&", "(\"Tee-\"+\"Object\")"),
            ("&", "(\"Tee`u{2d}Object\")"),
            ("&", "\"Tee`u{2d}Object\""),
            ("&", "('Tee-' <# outer <# inner #> tail #> + 'Object')"),
            ("&", "('Tee-' + # ) inside a comment\n 'Object')"),
            ("&", "('Tee-' `\n + 'Object')"),
            ("&", "(‘Tee-’+‘Object’)"),
            ("&", "(“Tee-”+“Object”)"),
            ("&", "('Microsoft.PowerShell.Utility\\Tee-'+'Object')"),
            ("&", "'Microsoft.PowerShell.Utility\\Tee-Object'"),
            ("&", "$('Tee-Object')"),
            ("&", "@('Tee-Object')"),
        ] {
            let command = format!(
                "Write-Output 'λ'; {operator} {operand} -InputObject NEW -FilePath /etc/hosts"
            );
            let targets = powershell_tee_truncation_targets(&command).expect("bounded fixture");
            assert_eq!(targets.len(), 1, "{command}");
            assert_eq!(targets[0].path, "/etc/hosts", "{command}");
            assert_eq!(&command[targets[0].span.clone()], operand, "{command}");
            let invocations = powershell_literal_invocations(&command).expect("bounded fixture");
            assert_eq!(invocations.len(), 1, "{command}");
            assert!(invocations[0].name.ends_with("Tee-Object"), "{command}");
            assert!(!invocations[0].name.contains('\\'), "{command}");
            assert_eq!(&command[invocations[0].span.clone()], operand, "{command}");
            assert_eq!(
                &command[invocations[0].operator_span.clone()],
                operator,
                "{command}"
            );
            assert!(powershell_tee_scan_required(&command), "{command}");
        }
        for command in [
            "&('Tee-Object') /etc/hosts",
            ".('Tee-'+'Object') /etc/hosts",
        ] {
            let targets = powershell_tee_truncation_targets(command).expect("bounded fixture");
            assert_eq!(targets.len(), 1, "{command}");
            assert_eq!(targets[0].path, "/etc/hosts", "{command}");
        }
    }

    #[test]
    fn powershell_computed_tee_invocations_preserve_binding_controls() {
        for arguments in [
            "-InputObject NEW -Append /etc/hosts",
            "-InputObject NEW -Append:$true -FilePath /etc/hosts",
            "-InputObject NEW -Variable captured",
            "-InputObject NEW -WhatIf -FilePath /etc/hosts",
            "-LiteralPath /etc/hosts -Append",
            "-FilePath /etc/hosts /var/lib/other",
        ] {
            let command = format!("& ('Tee-'+'Object') {arguments}");
            assert!(
                powershell_tee_truncation_targets(&command)
                    .expect("bounded fixture")
                    .is_empty(),
                "{command}"
            );
        }
        for arguments in [
            "-InputObject NEW -Append:$false -FilePath /etc/hosts",
            "-InputObject NEW -Append:$flag -FilePath /etc/hosts",
            "-InputObject '--%' -Append /etc/hosts",
        ] {
            let command = format!(". ('Tee-'+'Object') {arguments}");
            let targets = powershell_tee_truncation_targets(&command).expect("bounded fixture");
            assert_eq!(targets.len(), 1, "{command}");
            assert_eq!(targets[0].path, "/etc/hosts", "{command}");
        }
        assert!(ps("& ('Tee-'+'Object') -Append ~/.ssh/authorized_keys").is_some());
        assert!(ps("& ('Tee-'+'Object') -Append ~/.ssh/known_hosts").is_none());
    }

    #[test]
    fn powershell_invoked_names_exclude_data_and_opaque_postfixes() {
        for command in [
            "Write-Output ('Tee-'+'Object') -FilePath /etc/hosts",
            "('Tee-Object')",
            "('Tee-'+'Object')",
            "Write-Output \"& ('Tee-Object') -FilePath /etc/hosts\"",
            "& ('Tee-Object')[0] -FilePath /etc/hosts",
            "& ('Tee-Object').ToString() -FilePath /etc/hosts",
            "& 'Tee-Object'[0] -FilePath /etc/hosts",
            "& 'Tee-Object'.Length -FilePath /etc/hosts",
            "& \"Tee-Object\"::Member -FilePath /etc/hosts",
            "& ($program) -FilePath /etc/hosts",
            "& ('Tee-'+$suffix) -FilePath /etc/hosts",
            "& (\"Tee`u{}Object\") -FilePath /etc/hosts",
            "& (\"Tee`u{D800}Object\") -FilePath /etc/hosts",
            "Tee-Object /etc/hosts",
        ] {
            assert!(
                powershell_literal_invocations(command)
                    .expect("bounded fixture")
                    .is_empty(),
                "{command}"
            );
        }
        for command in [
            "& ('Other.Module\\Tee-Object') /etc/hosts",
            "& ('Tee-Object -Append /etc/hosts') /etc/hosts",
        ] {
            assert!(
                powershell_tee_truncation_targets(command)
                    .expect("bounded fixture")
                    .is_empty(),
                "a string value stays one executable name: {command}"
            );
        }
    }

    #[test]
    fn powershell_computed_invocations_keep_independent_nested_writes() {
        for command in [
            "& (Tee-Object -InputObject 'Tee-Object' /etc/hosts) -Append /tmp/log",
            "& $(Write-Output 'unused'; Tee-Object /etc/hosts) -Variable captured",
            "& ('Write-Output')[(Tee-Object /etc/hosts)]",
            "& 'Write-Output'[(Tee-Object /etc/hosts)]",
        ] {
            let targets = powershell_tee_truncation_targets(command).expect("bounded fixture");
            assert_eq!(targets.len(), 1, "{command}");
            assert_eq!(targets[0].path, "/etc/hosts", "{command}");
            assert_eq!(&command[targets[0].span.clone()], "Tee-Object", "{command}");
        }
        let command = "& ('Write-'+'Output') (& ('Tee-'+'Object') /etc/hosts)";
        let invocations = powershell_literal_invocations(command).expect("bounded fixture");
        assert_eq!(invocations.len(), 2);
        for invocation in invocations {
            assert_eq!(&command[invocation.operator_span], "&");
            assert_eq!(
                &command[invocation.span],
                if invocation.name == "Write-Output" {
                    "('Write-'+'Output')"
                } else {
                    "('Tee-'+'Object')"
                }
            );
        }
    }

    #[test]
    fn powershell_invocation_collection_surfaces_decoder_and_lexer_bounds() {
        let oversized_name = format!("& ('{}') /etc/hosts", "x".repeat(100_000));
        assert_eq!(
            powershell_literal_invocations(&oversized_name).expect_err("decoder byte bound"),
            WindowsShellParseIncomplete::Work
        );
        assert_eq!(
            powershell_tee_truncation_targets(&oversized_name).expect_err("same bounded parse"),
            WindowsShellParseIncomplete::Work
        );
        assert!(powershell_tee_scan_required(&oversized_name));
        let mut nested = "& ('Tee-Object') /etc/hosts".to_string();
        for _ in 0..MAX_LEX_DEPTH {
            nested = format!("Write-Output ({nested})");
        }
        assert_eq!(
            powershell_literal_invocations(&nested).expect_err("shared nesting bound"),
            WindowsShellParseIncomplete::Nesting
        );
    }

    #[test]
    fn powershell_out_file_binds_named_and_unbound_positional_targets() {
        for command in [
            "'NEW' | Out-File /etc/hosts",
            "Out-File -InputObject NEW -FilePath /etc/hosts",
            "Out-File -FilePath /etc/hosts",
            "Out-File -Path /etc/hosts",
            "Out-File -fi /etc/hosts",
            "Out-File -LiteralPath /etc/hosts",
            "Out-File -PSPath /etc/hosts",
            "Out-File -LP /etc/hosts",
            "Out-File /etc/hosts utf8",
            "Out-File -FilePath /etc/hosts utf8",
            "Out-File utf8 -FilePath /etc/hosts",
            "Out-File -LiteralPath /etc/hosts utf8",
            "Out-File utf8 -LiteralPath /etc/hosts",
            "Out-File -Encoding utf8 /etc/hosts",
            "Out-File /etc/hosts -Encoding utf8",
            "Out-File -InputObject '/tmp/data' -Width 80 -ErrorVariable errors /etc/hosts",
            "Out-File -OutVariable '-NoClobber' /etc/hosts",
            "Out-File -FilePath:'/etc/hosts'",
            "Out-File -FilePath: '/etc/hosts'",
            "Out-File -FilePath('/etc/hosts')",
            "Out-File -InputObject: -WhatIf -FilePath /etc/hosts",
            "Out-File -- /etc/hosts utf8",
            "Out-File -LP /etc/hosts -Append:$false",
            "Out-File \u{2013}FilePath /etc/hosts",
            "Out-File\u{00a0}-FilePath\u{00a0}/etc/hosts",
            "Out-File -FilePath \u{2018}/etc/hosts\u{2019}",
            "Out-F`ile -FilePath /etc/hosts",
            "Microsoft.PowerShell.Utility\\Out-File -FilePath /etc/hosts",
            "& ('Out-'+'File') -FilePath /etc/hosts",
            ". (('Out-')+('File')) -FilePath /etc/hosts",
            "& ('Microsoft.PowerShell.Utility\\Out-'+'File') -FilePath /etc/hosts",
        ] {
            let targets = powershell_file_truncation_targets(command).expect("bounded fixture");
            assert_eq!(targets.len(), 1, "{command}: {targets:?}");
            assert_eq!(targets[0].path, "/etc/hosts", "{command}");
            assert!(targets[0].literal, "{command}");
            assert!(powershell_file_writer_scan_required(command), "{command}");
        }
    }

    #[test]
    fn powershell_out_file_preserves_switches_and_binding_failures() {
        for tail in [
            "-Append",
            "-Append:$true",
            "-Append:$null",
            "-NoClobber",
            "-NoClobber:$true",
            "-NoOverwrite",
            "-noc",
            "-noo",
            "-NoClobber -Force",
            "-WhatIf",
            "-WhatIf:$true",
            "-wi",
            "-Append -Append:$false",
            "-NoClobber -NoOverwrite:$false",
            "-WhatIf -wi:$false",
            "-Variable x",
            "-Width",
            "-Encoding",
            "-InputObject -Width 80",
            "-Encoding -Append",
            "-Encoding utf8 -e ascii",
            "-Width 1,2",
            "-Encoding utf8,ascii",
            "-LiteralPath /tmp/other",
            "-Path /tmp/other",
            "utf8 ascii",
        ] {
            let command = format!("Out-File -FilePath /etc/hosts {tail}");
            assert!(
                powershell_file_truncation_targets(&command)
                    .expect("bounded fixture")
                    .is_empty(),
                "{command}"
            );
        }
        for command in [
            "Out-File -f /etc/hosts",
            "Out-File -FilePath /etc/hosts -no",
            "Out-File -FilePath /etc/hosts,/tmp/other",
            "Out-File /etc/hosts,/tmp/other",
            "Out-File -LiteralPath /etc/hosts -Append",
            "Out-File -InputObject '--' -Append /etc/hosts",
        ] {
            assert!(
                powershell_file_truncation_targets(command)
                    .expect("bounded fixture")
                    .is_empty(),
                "{command}"
            );
        }
    }

    #[test]
    fn powershell_out_file_exemptions_require_proven_enabled_switches() {
        for switch in ["Append", "NoClobber", "NoOverwrite", "WhatIf"] {
            for value in ["$false", "0", "$enabled", "($enabled)"] {
                let command = format!("Out-File -FilePath /etc/hosts -{switch}:{value}");
                let targets =
                    powershell_file_truncation_targets(&command).expect("bounded fixture");
                assert_eq!(targets.len(), 1, "{command}: {targets:?}");
                assert_eq!(targets[0].path, "/etc/hosts", "{command}");
            }
        }
    }

    #[test]
    fn powershell_file_output_pending_value_keeps_end_of_parameters_state() {
        for writer in ["Out-File", "Tee-Object"] {
            for data in ["-Append", "-NoClobber", "-WhatIf"] {
                let command = format!("{writer} -InputObject -- {data} /etc/hosts");
                let targets =
                    powershell_file_truncation_targets(&command).expect("bounded fixture");
                assert_eq!(targets.len(), 1, "{command}: {targets:?}");
                assert_eq!(targets[0].path, "/etc/hosts", "{command}");
            }
            for marker in ["'--'", "\"--\"", "`--", "-`-"] {
                let command = format!("{writer} -InputObject {marker} -Append /etc/hosts");
                assert!(
                    powershell_file_truncation_targets(&command)
                        .expect("bounded fixture")
                        .is_empty(),
                    "quoted or escaped marker is input data: {command}"
                );
            }
        }
    }

    #[test]
    fn powershell_file_output_stop_parsing_does_not_restore_discarded_switches() {
        for writer in ["Tee-Object", "Out-File"] {
            for marker in ["--%", "`--%", "--`%"] {
                let command = format!("{writer} -InputObject {marker} /etc/hosts");
                let targets =
                    powershell_file_truncation_targets(&command).expect("bounded fixture");
                assert_eq!(targets.len(), 1, "{command}: {targets:?}");
                assert_eq!(targets[0].path, "/etc/hosts", "{command}");
            }
            for marker in ["'--%'", "\"--%\""] {
                for discarded in ["Append", "NoClobber", "WhatIf", "FilePath"] {
                    let command = format!("{writer} -InputObject {marker} -{discarded} /etc/hosts");
                    let targets =
                        powershell_file_truncation_targets(&command).expect("bounded fixture");
                    assert_eq!(targets.len(), 1, "{command}: {targets:?}");
                    assert_eq!(targets[0].path, "/etc/hosts", "{command}");
                    assert!(targets[0].literal, "{command}");
                }
            }
            let command = format!("{writer} -Append -InputObject '--%' /etc/hosts");
            assert!(
                powershell_file_truncation_targets(&command)
                    .expect("bounded fixture")
                    .is_empty(),
                "preceding switch remains bound: {command}"
            );
        }
        let command = "Out-File -NoClobber -InputObject '--%' /etc/hosts";
        assert!(
            powershell_file_truncation_targets(command)
                .expect("bounded fixture")
                .is_empty(),
            "preceding NoClobber remains bound"
        );
    }

    #[test]
    fn powershell_out_file_distinguishes_literal_paths_and_unresolved_targets() {
        let wildcard = "Out-File -FilePath '/tmp/[scratch].txt'";
        let targets = powershell_file_truncation_targets(wildcard).expect("bounded fixture");
        assert_eq!(targets.len(), 1);
        assert!(!targets[0].literal, "FilePath expands provider wildcards");
        for parameter in ["LiteralPath", "PSPath", "LP"] {
            let command = format!("Out-File -{parameter} '/tmp/[scratch].txt'");
            let targets = powershell_file_truncation_targets(&command).expect("bounded fixture");
            assert_eq!(targets.len(), 1, "{command}: {targets:?}");
            assert_eq!(targets[0].path, "/tmp/[scratch].txt");
            assert!(targets[0].literal, "{command}");
        }
        for command in [
            "Out-File -FilePath $destination",
            "Out-File -FilePath ($destination)",
            "Out-File @parameters",
            "Out-File @parameters utf8",
        ] {
            let targets = powershell_file_truncation_targets(command).expect("bounded fixture");
            assert!(
                targets.iter().any(|target| !target.literal),
                "{command}: {targets:?}"
            );
        }
        let command = "Out-File @parameters -FilePath /tmp/report.txt";
        let targets = powershell_file_truncation_targets(command).expect("bounded fixture");
        assert_eq!(
            targets.len(),
            1,
            "named target cannot be rebound by a splat"
        );
        assert_eq!(targets[0].path, "/tmp/report.txt");
        assert!(targets[0].literal);
    }

    #[test]
    fn powershell_out_file_requires_actual_cmdlet_execution() {
        for command in [
            "Write-Output 'Out-File -FilePath /etc/hosts'",
            "Write-Output ('Out-'+'File') -FilePath /etc/hosts",
            "'Out-File' -FilePath /etc/hosts",
            "('Out-File') -FilePath /etc/hosts",
            "& '/usr/bin/Out-File' -FilePath /etc/hosts",
            "Other.Module\\Out-File -FilePath /etc/hosts",
            "& 'Out-File'[0] -FilePath /etc/hosts",
        ] {
            assert!(
                powershell_file_truncation_targets(command)
                    .expect("bounded fixture")
                    .is_empty(),
                "{command}"
            );
            assert!(!powershell_file_writer_scan_required(command), "{command}");
        }
        for command in [
            "& ('Ou'+'t-Fi'+'le') -FilePath $destination",
            ". (('Ou')+('t-Fi')+('le')) -FilePath $destination",
            "Out-F`ile -FilePath $destination",
        ] {
            for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
                assert!(
                    crate::packs::core::filesystem::filesystem_semantic_scan_required(
                        command, dialect,
                    ),
                    "decoded writer must select the pack before keyword rejection: {command}"
                );
            }
        }
    }

    #[test]
    fn powershell_out_file_outer_exemptions_keep_nested_writes_and_spans() {
        for exemption in ["WhatIf", "Append", "NoClobber"] {
            let command = format!(
                "Out-File -{exemption} -FilePath /tmp/safe -InputObject (Out-File -FilePath /etc/hosts)"
            );
            let targets = powershell_file_truncation_targets(&command).expect("bounded fixture");
            assert_eq!(targets.len(), 1, "{command}: {targets:?}");
            assert_eq!(targets[0].path, "/etc/hosts");
            assert_eq!(&command[targets[0].span.clone()], "Out-File");
            assert_eq!(targets[0].span.start, command.rfind("Out-File").unwrap());
        }
    }

    #[test]
    fn powershell_out_file_no_clobber_keeps_credential_creation_policy() {
        for switch in ["Append", "NoClobber", "NoOverwrite"] {
            let command = format!("Out-File -{switch} -FilePath ~/.ssh/authorized_keys");
            assert!(
                powershell_file_truncation_targets(&command)
                    .expect("bounded fixture")
                    .is_empty()
            );
            assert!(
                classify(&command, ShellDialect::PowerShell).is_some(),
                "{command}"
            );
            assert!(powershell_file_writer_scan_required(&command), "{command}");
        }
        assert!(
            classify(
                "Out-File -WhatIf -FilePath ~/.ssh/authorized_keys",
                ShellDialect::PowerShell,
            )
            .is_none()
        );
    }
}
