# Heredoc Pattern Authoring Guide

This document describes how heredoc and inline-script patterns are defined, tested,
and allowlisted. It is intended for contributors and power users.

## Overview

Heredoc detection protects against destructive commands embedded in heredocs,
here-strings, and inline interpreter flags (for example, `python -c`). The
implementation uses a tiered pipeline (see `docs/adr-001-heredoc-scanning.md`)
that only evaluates heredoc patterns when a heredoc or inline script is detected.

Stable rule IDs are required for allowlisting. The naming convention is:

```
heredoc.<language>.<operation>
```

Example:

```
heredoc.python.shutil_rmtree
```

Rule IDs are the keys used in allowlists and explain output.

Pipeline (simplified):

```
command
  -> quick reject
  -> heredoc trigger
  -> extract content + detect language
  -> ast match (language patterns)
  -> decision (allow/warn/deny)
```

## Pattern Syntax

Heredoc patterns are authored using ast-grep pattern syntax (as implemented by
`ast-grep-core`). Common conventions used in this repo:

- `$$$` matches any subtree.
- `$X` captures a single AST node.
- A metavariable in receiver position (`$FS.rmSync($$$)`) matches any
  receiver, so the chained `require('fs').rmSync(...)` spelling is covered
  alongside a bound `const fs = require('fs')`. Over-matching is bounded by
  the severity refinement, which still requires `recursive: true` or a
  catastrophic or non-temp literal target before the rule denies.
- Patterns are language-specific and only evaluated on code parsed for that
  language.

Examples:

- `shutil.rmtree($$$)`
- `child_process.execSync($$$)`
- `exec.Command($$$).Run()`

Perl patterns are handled via targeted regex scanning of string literals and
shell payloads (see `src/ast_matcher.rs`).

## Where Patterns Live

The built-in pattern inventory is defined in:

- `src/ast_matcher.rs` (`default_patterns()` and Perl scanners)

Suggestions for some patterns are mapped in:

- `src/suggestions.rs`

The high-level design and rationale are documented in:

- `docs/adr-001-heredoc-scanning.md`
- `docs/pattern-library-design.md`

## Adding New Patterns

1. **Choose a stable rule ID** (`heredoc.<language>.<operation>`). Do not rename
   existing IDs; deprecate instead.
2. **Add a `CompiledPattern::new(...)` entry** in `src/ast_matcher.rs` for
   language-specific AST matches, or extend the Perl scanners for regex-based
   matching.
3. **Provide a concise reason** (short, human-readable, under 100 chars).
4. **Set severity** (Critical / High / Medium / Low). Consider false-positive
   risk and catastrophic targets.
5. **Add a suggestion** when a safer alternative exists.
6. **Add tests** (positive and negative fixtures) in `src/ast_matcher.rs`.
7. **Update docs** (this file and any relevant design notes).

## Adding a New Language

1. Add the language to `ScriptLanguage` in `src/heredoc.rs`.
2. Map string aliases in `src/config.rs` heredoc language parsing.
3. Map to an AST language in `src/ast_matcher.rs` (`script_language_to_ast_lang`).
4. Add default patterns in `src/ast_matcher.rs`.
5. Add suggestions in `src/suggestions.rs` (if applicable).
6. Add positive and negative fixtures in `src/ast_matcher.rs`.

## Pattern Inventory (Current Defaults)

This list is derived from `src/ast_matcher.rs` and reflects the current
built-in rule IDs. Use these IDs for allowlisting and tests.

### Bash

| Rule ID | Pattern | Reason |
| --- | --- | --- |
| `heredoc.bash.rm_r` | `rm -r $$$` | `rm -r` recursively deletes |
| `heredoc.bash.rm_rf` | `rm -rf $$$` | `rm -rf` recursively deletes files/directories |
| `heredoc.bash.git_reset_hard` | `git reset --hard` | discards uncommitted changes |
| `heredoc.bash.git_clean_fd` | `git clean -fd` | deletes untracked files |

### Go

The Pattern column is the call each rule matches. Go's patterns are *registered*
inside enclosing context — `func f() { os.RemoveAll($$$) }` with a
`call_expression` selector — because Go's grammar has no top-level expression
statement, so a bare call is not a parseable fragment and compiles to a tree that
can never match (#465). The selector discards the wrapper, so the call below is
what is matched and what the reported span covers.

| Rule ID | Pattern | Reason |
| --- | --- | --- |
| `heredoc.go.os_remove` | `os.Remove($$$)` | deletes files |
| `heredoc.go.os_removeall` | `os.RemoveAll($$$)` | recursively deletes directories |
| `heredoc.go.exec_command` | `exec.Command($$$)` | executes shell commands |
| `heredoc.go.exec_command_run` | `exec.Command($$$).Run()` | executes shell commands |
| `heredoc.go.exec_command_output` | `exec.Command($$$).Output()` | executes shell commands |
| `heredoc.go.exec_command_combined_output` | `exec.Command($$$).CombinedOutput()` | executes shell commands |

### JavaScript (Node)

| Rule ID | Pattern | Reason |
| --- | --- | --- |
| `heredoc.javascript.fs_rm` | `$FS.rm($$$)` | deletes files/directories |
| `heredoc.javascript.fs_rmdir` | `$FS.rmdir($$$)` | deletes directories |
| `heredoc.javascript.fs_rmsync` | `$FS.rmSync($$$)` | deletes files/directories |
| `heredoc.javascript.fs_rmdirsync` | `$FS.rmdirSync($$$)` | deletes directories |
| `heredoc.javascript.fs_unlink` | `$FS.unlink($$$)` | deletes files |
| `heredoc.javascript.fs_unlinksync` | `$FS.unlinkSync($$$)` | deletes files |
| `heredoc.javascript.execsync` | `child_process.execSync($$$)` | executes shell commands |
| `heredoc.javascript.require_execsync` | `require('child_process').execSync($$$)` | executes shell commands |
| `heredoc.javascript.spawnsync` | `child_process.spawnSync($$$)` | executes shell commands |

### TypeScript

| Rule ID | Pattern | Reason |
| --- | --- | --- |
| `heredoc.typescript.fs_rm` | `$FS.rm($$$)` | deletes files/directories |
| `heredoc.typescript.fs_rmdir` | `$FS.rmdir($$$)` | deletes directories |
| `heredoc.typescript.fs_rmsync` | `$FS.rmSync($$$)` | deletes files/directories |
| `heredoc.typescript.fs_rmdirsync` | `$FS.rmdirSync($$$)` | deletes directories |
| `heredoc.typescript.fs_unlink` | `$FS.unlink($$$)` | deletes files |
| `heredoc.typescript.fs_unlinksync` | `$FS.unlinkSync($$$)` | deletes files |
| `heredoc.typescript.execsync` | `child_process.execSync($$$)` | executes shell commands |
| `heredoc.typescript.require_execsync` | `require('child_process').execSync($$$)` | executes shell commands |
| `heredoc.typescript.spawnsync` | `child_process.spawnSync($$$)` | executes shell commands |
| `heredoc.typescript.deno_remove` | `Deno.remove($$$)` | deletes files/directories |

### Python

| Rule ID | Pattern | Reason |
| --- | --- | --- |
| `heredoc.python.shutil_rmtree` | `$M.rmtree($$$)` | recursively deletes directories |
| `heredoc.python.os_remove` | `os.remove($$$)` | deletes files |
| `heredoc.python.os_rmdir` | `os.rmdir($$$)` | deletes directories |
| `heredoc.python.os_unlink` | `os.unlink($$$)` | deletes files |
| `heredoc.python.pathlib_unlink` | `pathlib.Path($$$).unlink($$$)` and `Path($$$).unlink($$$)` | deletes files |
| `heredoc.python.pathlib_rmdir` | `pathlib.Path($$$).rmdir($$$)` and `Path($$$).rmdir($$$)` | deletes directories |
| `heredoc.python.subprocess_run` | `subprocess.run($$$)` | executes shell commands |
| `heredoc.python.subprocess_call` | `subprocess.call($$$)` | executes shell commands |
| `heredoc.python.subprocess_popen` | `subprocess.Popen($$$)` | spawns shell processes |
| `heredoc.python.subprocess_check_call` | `subprocess.check_call($$$)` | executes shell commands |
| `heredoc.python.subprocess_check_output` | `subprocess.check_output($$$)` | executes shell commands |
| `heredoc.python.os_system` | `os.system($$$)` | executes shell commands |
| `heredoc.python.os_popen` | `os.popen($$$)` | executes shell commands |

### Ruby

| Rule ID | Pattern | Reason |
| --- | --- | --- |
| `heredoc.ruby.file_delete` | `File.delete($$$)` | deletes files |
| `heredoc.ruby.file_unlink` | `File.unlink($$$)` | deletes files |
| `heredoc.ruby.dir_delete` | `Dir.delete($$$)` | deletes directories |
| `heredoc.ruby.dir_rmdir` | `Dir.rmdir($$$)` | deletes directories |
| `heredoc.ruby.fileutils_rm` | `FileUtils.rm($$$)` | deletes files |
| `heredoc.ruby.fileutils_rm_f` | `FileUtils.rm_f($$$)` | force-deletes files |
| `heredoc.ruby.fileutils_remove` | `FileUtils.remove($$$)` | deletes files |
| `heredoc.ruby.fileutils_remove_file` | `FileUtils.remove_file($$$)` | deletes a file |
| `heredoc.ruby.fileutils_rmdir` | `FileUtils.rmdir($$$)` | deletes empty directories |
| `heredoc.ruby.fileutils_remove_dir` | `FileUtils.remove_dir($$$)` | deletes directories |
| `heredoc.ruby.fileutils_rm_rf` | `FileUtils.rm_rf($$$)` | recursively deletes directories |
| `heredoc.ruby.fileutils_rm_r` | `FileUtils.rm_r($$$)` | recursively deletes directories |
| `heredoc.ruby.fileutils_remove_entry` | `FileUtils.remove_entry($$$)` | recursively deletes a path and its children |
| `heredoc.ruby.fileutils_remove_entry_secure` | `FileUtils.remove_entry_secure($$$)` | recursively deletes a path and its children |
| `heredoc.ruby.system` | `system($$$)` | executes shell commands |
| `heredoc.ruby.exec` | `exec($$$)` | replaces process with shell command |
| `heredoc.ruby.kernel_system` | `Kernel.system($$$)` | executes shell commands |
| `heredoc.ruby.kernel_exec` | `Kernel.exec($$$)` | replaces process with shell command |
| `heredoc.ruby.open3_capture3` | `Open3.capture3($$$)` | executes shell commands |
| `heredoc.ruby.open3_popen3` | `Open3.popen3($$$)` | executes shell commands |
| `heredoc.ruby.backticks` | `` `$$$` `` | executes shell commands |

### PHP

| Rule ID | Pattern | Reason |
| --- | --- | --- |
| `heredoc.php.unlink` | `unlink($$$)` | deletes files |
| `heredoc.php.rmdir` | `rmdir($$$)` | deletes directories |
| `heredoc.php.exec` | `exec($$$)` | executes shell commands |
| `heredoc.php.system` | `system($$$)` | executes shell commands |
| `heredoc.php.shell_exec` | `shell_exec($$$)` | executes shell commands |
| `heredoc.php.passthru` | `passthru($$$)` | executes shell commands |
| `heredoc.php.proc_open` | `proc_open($$$)` | executes shell commands |
| `heredoc.php.popen` | `popen($$$)` | executes shell commands |
| `heredoc.php.backticks` | `` `$$$` `` | executes shell commands |

`unlink` and `rmdir` are also registered in their namespace-escaped spellings
(`\unlink`, `\rmdir`), which PHP code inside a namespace uses to reach the global
function; both spellings report the same rule ID.

Only `unlink` and `rmdir` block by default. The seven execution helpers are
registered at Medium, and unlike the other languages PHP has no arm in
`refine_match_meta`, so they never escalate on a destructive literal payload the
way Python's and Ruby's exec sinks do — a PHP `system('rm -rf …')` is caught by
the conservative raw-shell rescan finding that text, not by the rule above. An
argv-split payload (`pcntl_exec('/bin/rm', ['-rf', …])`) has no such text and is
allowed. See #459.

### Perl

Perl scanning uses targeted regexes plus shell-payload analysis. The following
rule IDs are emitted:

- `heredoc.perl.file_path.rmtree`
- `heredoc.perl.file_path.<fn_name>` (for `File::Path::<fn_name>`)
- `heredoc.perl.unlink`
- `heredoc.perl.rmdir`
- `heredoc.perl.system.<suffix>`
- `heredoc.perl.exec.<suffix>`
- `heredoc.perl.backticks.<suffix>`
- `heredoc.perl.qx.<suffix>`

Supported `<suffix>` values (from shell-payload detection):

- `git_reset_hard`
- `git_clean_fd`
- `rm_rf`
- `rm_rf_catastrophic`

## Derived Rule IDs

Some patterns refine their rule IDs based on detected arguments:

- For JavaScript/TypeScript `fs.*` patterns, a literal
  catastrophic path appends `.catastrophic` to the rule ID
  (example: `heredoc.javascript.fs_rmsync.catastrophic`). The receiver is a
  metavariable, so one rule covers every spelling — `fs.rm`, `fs.promises.rm`,
  `fsPromises.rm` and `require('fs').promises.rm` all report `fs_rm`.
- For TypeScript `deno_remove`, a catastrophic path appends `.catastrophic`.
- For Ruby `FileUtils`/`File`/`Dir` patterns, catastrophic paths append
  `.catastrophic`. Every operand counts, including list and `%w[...]` elements
  and parenless calls (`FileUtils.rm_rf ["/tmp/x", "/"]` is catastrophic).
- The **home directory written as an expression** is a catastrophic target, the
  same as a literal `~`: `os.homedir()`, `process.env.HOME`/`USERPROFILE` and
  `Deno.env.get("HOME")` in JavaScript/TypeScript, `Dir.home`, `ENV["HOME"]`,
  `ENV.fetch("HOME")`, `Gem.user_home` and `Etc.getpwuid.dir` in Ruby, and
  `$ENV{HOME}`, `glob("~")` and `File::HomeDir->my_home` in Perl (reported under
  the plain `rmtree`/`remove_tree` ID, as Perl's catastrophic literals are). It
  must be the whole argument: a directory under home, such as
  `path.join(os.homedir(), ".cache")`, is classified like any other target.
- For Ruby `system`/`exec`/`Open3`/backticks and Perl shell calls, literal
  payloads produce rule IDs with suffixes such as `.rm_rf` and
  `.rm_rf_catastrophic`.
- For PHP `system`/`exec`/`shell_exec`/`passthru`/`popen`/`proc_open`, a
  destructive literal payload produces the same suffixes (example:
  `heredoc.php.proc_open.rm_rf_catastrophic`), read both as individual literals
  and as the argv they form — so the PHP 7.4+ array spelling
  `proc_open(["rm","-rf","/home/user"], …)` and the concatenated spelling
  `system("rm" . " -rf" . " /home/user")` refine like a plain single literal.
  `` `backticks` `` are not refined: the operator takes one interpolated string,
  so it has no argv or concatenation form, and it carries no quoted literal to
  read.
- For Go `exec.Command`, a destructive literal payload produces the same
  suffixes (example: `heredoc.go.exec_command.rm_rf_catastrophic`), read from
  the call's arguments as the argv they are — so the split spelling
  `exec.Command("rm", "-rf", "/home/user")` refines exactly like the single
  literal `exec.Command("sh", "-c", "rm -rf /home/user")`. All four Go exec
  rows report under `exec_command`: `.Run()`, `.Output()` and
  `.CombinedOutput()` wrap that same call, and refining them separately would
  mean two blocking IDs for one command.
- For a **recursive delete** with a literal target outside a temp directory,
  `.non_temp` is appended and the severity becomes Critical (example:
  `heredoc.ruby.fileutils_rm_rf.non_temp`). Python's `shutil.rmtree` and Go's
  `os.RemoveAll` are the exceptions to the suffix: they are Critical already, so
  a target that *is* a temp directory appends `.temp` and drops it to warn-only
  instead (example: `heredoc.go.os_removeall.temp`).
- For Perl `unlink`/`rmdir`, a catastrophic literal target appends
  `.catastrophic` and raises the severity to Critical.

### Allowlisting a derived rule ID

Allowlist matching is on the **exact** rule ID a denial reports. Derived IDs are
valid targets, but granting the base ID does **not** cover its derived forms — and
for rules that only ever block *with* a suffix, the base ID in the tables above is
therefore not a usable grant. Measured, granting each base ID and re-running the
command it denies:

| rule | ID the denial reports | base-ID grant |
| --- | --- | --- |
| `heredoc.javascript.fs_rmsync` | `…fs_rmsync.catastrophic` | accepted, never matches |
| `heredoc.ruby.fileutils_rm_rf` | `…fileutils_rm_rf.catastrophic` | accepted, never matches |
| `heredoc.python.shutil_rmtree` | `…shutil_rmtree` | works |
| `heredoc.go.os_removeall` | `…os_removeall` | works |
| `heredoc.go.exec_command` | `…exec_command.rm_rf_catastrophic` | accepted, never matches |
| `heredoc.php.system` | `…system.rm_rf_catastrophic` | accepted, never matches |
| `core.filesystem:rm-rf-root-home` | `core.filesystem:rm-rf-root-home` | works |

The pattern is that a base ID is grantable exactly when the rule is sometimes
reported without a suffix. The `fs.*` family, the Ruby `FileUtils`/`File`/`Dir`
family and the shell-payload exec sinks are refined to a suffix in every case that
blocks, so they never report bare. `dcg allowlist add` accepts a well-formed base ID
for those without complaining, and it then has nothing to match.

**So copy the ID from the denial, not from the table above.** Every denial carries
it in `hookSpecificOutput.ruleId` and again in the `Rule:` line of the reason text;
`dcg explain "<command>"` prints the same string as `Rule ID:`. The tables here name
the *rule*, which is what you want when reading; the denial names the *decision*,
which is what you want when granting.

## One policy for a recursive delete

`rm -rf`, `shutil.rmtree`, `os.RemoveAll` (Go), `FileUtils.rm_rf`/`rm_r`/
`remove_entry`/`remove_entry_secure`/`remove_dir`,
`fs.rmSync`/`rmdirSync`/`rm`/`rmdir`
(under any receiver spelling, including the promise APIs, in both JavaScript and
TypeScript) with `recursive: true`, and
Perl's `File::Path::rmtree`/`remove_tree` all answer the same question the same
way: a literal target outside a temp directory is denied, and a temp target is
warn-only.

"Temp" has one definition shared by every language, taken from the shell's own
`rm-rf-tmp` / `rm-rf-var-tmp` safe patterns: `/tmp` or `/var/tmp`, optionally
`/private`-prefixed, with any `..` component disqualifying the path. Both of
Go's string spellings count, interpreted (`"/tmp/build"`) and raw
(`` `/tmp/build` ``). Python additionally treats `tempfile.mkdtemp()` /
`TemporaryDirectory()` as a scratch directory, since those produce one by
construction; Go has no equivalent because `os.MkdirTemp` returns
`(string, error)` and so cannot be nested inside the delete call. The Go idiom
that splits it across two statements (`dir, _ := os.MkdirTemp(…)` then
`defer os.RemoveAll(dir)`) is denied, exactly as Python's two-statement
`d = tempfile.mkdtemp(); shutil.rmtree(d)` is — proving `dir` still holds that
value needs taint analysis this scanner does not do.

The reason it is one policy is that the thing choosing the spelling is usually
an agent. An agent refused `rm -rf ./build` must not get the same effect from a
Ruby or Node one-liner; that is not adversarial behaviour, it is what a model
does when a step is refused (GH #455).

Deliberately **not** in this set: calls that cannot destroy a tree.
`FileUtils.rm_f`/`rm`/`remove_file` and Perl `unlink` delete one file,
`FileUtils.rmdir` and Perl `rmdir` need an already-empty directory, and
`fs.rmSync` without `recursive: true` removes one file. Those keep the
catastrophic-target rule only.

A **dynamic** target is still judged per language: `shutil.rmtree(d)` and Go's
`os.RemoveAll(dir)` deny,
while the Ruby and JavaScript equivalents warn. Raising those would block
`fs.rmSync(buildDir, { recursive: true })` in most Node build scripts, which is
a wider change than #455 decided. A home-directory expression is not dynamic in
this sense: it names `~`, so it is catastrophic (see the rule-ID list above).

## Limitations and False Positive Notes

- Shell execution helpers (for example, `execSync`, `system`, `os.system`) only
  escalate to high-severity decisions when a literal payload is detected. Dynamic
  payloads are warn-only to avoid false positives.
- Some file deletion APIs are refined at match time. Non-recursive or
  non-catastrophic paths may result in warn-only severity.
- Patterns are evaluated only for supported languages and only when heredoc
  triggers are detected. Non-heredoc destructive code outside the supported
  languages is out of scope.

## Testing Requirements

Add tests under `src/ast_matcher.rs`:

- At least one positive and one negative fixture per new rule.
- Ensure comments/strings do not match (false positive guard).
- Include catastrophic-path fixtures when applicable.

Run:

```
cargo test ast_matcher
```

