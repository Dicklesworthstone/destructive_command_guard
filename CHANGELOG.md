# Changelog

All notable changes to **dcg** (Destructive Command Guard) are documented here.

Versions marked **[Release]** have published GitHub Releases with pre-built binaries.
Versions marked **[Pre-release]** are GitHub prereleases that were not promoted
to latest.
Versions marked **[Tag]** are git tags only (no binaries published).

Repository: <https://github.com/Dicklesworthstone/destructive_command_guard>

---

## Unreleased

### Fixed

- **`redirect-truncate-root-home` no longer recommends an alternative it then
  denies (#316 follow-up).** The rule's "Make a backup" suggestion —
  `cp <file> <file>.bak && echo data > <file>` — still ends in a truncating
  redirect onto the same home/system path, so an agent that instantiated it
  from the triggering command was denied again by the same rule. The
  suggestion (block-message prose and the structured `PatternSuggestion`) now
  routes the write through a temp file: `cp <file> <file>.bak &&
  echo data > /tmp/<subdir>/out && cp -f /tmp/<subdir>/out <file>`, which the
  hook allows end-to-end even for home targets. Two sibling rows with the
  same latent trap were fixed in the same pass: the `truncate` rules'
  "keep the first N bytes" suggestion (`head -c N <file> > <file>.head` —
  a home-path redirect) now writes the head through `/tmp` and `cp -f`s it
  into place, and `mv-sensitive-source-root-home`'s in-place-rename
  suggestion (`mv <file> <file>.deleted-YYYYMMDD` — itself an mv touching a
  sensitive path) is now marked gated, so it renders with the explicit
  "dcg gates this too — it needs explicit approval" marker
  (`mv-dynamic-path` got its own suggestion set where the literal rename
  stays ungated, since a resolved literal rename is exactly the escape from
  that denial). The #316 suggestion self-consistency sweep now instantiates
  `{path}` with a home path (in addition to the relative path) for every rule
  whose name carries `root-home`/`sensitive` — the configuration the original
  sweep never exercised, which is why this row survived it — and requires
  gated suggestions to be denied in at least one applicable profile.

## [v0.11.1](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.11.1) -- 2026-08-19 [Release]

### Added

- **First-party OpenCode support (#318).** `dcg install --opencode` writes a
  native `tool.execute.before` plugin to
  `~/.config/opencode/plugins/dcg-guard.js` (`--project` for
  `<repo>/.opencode/plugins/`). The plugin routes every OpenCode `bash` tool
  call through dcg's Claude-compatible hook protocol — spawning the absolute
  dcg path embedded at install time with `OPENCODE=1` so the agent is
  identified — and aborts the tool call by throwing on a `deny` (an `ask`
  verdict also fails closed; OpenCode has no operator-review state).
  Infrastructure failures (dcg missing) fail open with a stderr notice. The
  file carries a `dcg-opencode-plugin` ownership marker: the installer refuses
  to overwrite a user-owned file of that name even with `--force`, and
  `uninstall.sh` deletes only marker-carrying files. `install.sh` configures
  OpenCode automatically when detected, `dcg doctor` gains an
  `opencode_plugin` check (an error + `--fix`able when OpenCode is in use but
  unguarded — there is no Claude-compat fallback), and `Agent::OpenCode` is
  detected from the plugin's `OPENCODE=1`. New
  `docs/opencode-integration.md`. Motivated by a real shared-environment
  outage where a green doctor coexisted with an entirely unguarded OpenCode
  install.
- **`dcg update` can no longer silently replace a local build that is ahead of
  its release (#320).** Build provenance (`git describe --tags --dirty`, plus
  an explicit `DCG_RELEASE_BUILD=1` marker exported by dist.yml and the DSR
  runbook) is embedded at compile time and shown as a `Commit:` line in
  `dcg --version`. `dcg update` now refuses — before any network or installer
  work — when the installed binary is a local build ahead of its release tag,
  or when the install is pinned via the new `general.update_pin` config
  (`DCG_UPDATE_PIN` env). The explicit escape hatch is
  `dcg update --replace-local-build`. Pinned installs also suppress the
  background "update available" nudge, and a new warning-only doctor check
  (`build_provenance`) flags the unpinned-local-ahead state that is one
  routine update away from silent coverage loss.
- **Suggestions dcg itself gates are now labeled, machine-checked, and
  consistent (#316).** `PatternSuggestion` gained a `gated` flag: a gated
  suggestion is a *less* destructive form of the blocked operation that still
  requires approval, and every renderer now says so explicitly ("dcg gates
  this too — it needs explicit approval" in block output, `[gated: ...]` in
  `dcg packs`/classify text, a `gated` field in JSON) so an agent reading the
  block message stops retrying suggestions dcg will deny. The 14 remaining
  self-denied suggestions from the #316 sweep are either fixed or marked
  gated: the MySQL `TRUNCATE`⇄`DELETE` mutual-referral loop is broken (backup
  suggestion first, gated cross-references labeled), the kamal proxy rules
  gained `kamal proxy restart` as a runnable first alternative,
  `core.git:branch-dynamic-token` now leads with the workflow fix that
  actually works and clarifies that quoting protects a *creation* while a
  literal `-D` stays gated, and the docker/kubectl/postgres/bigquery/
  guardrails/github rows carry accurate gated markers. Two registry-wide
  tests enforce the invariant in both directions (every non-gated suggestion
  is allowed by its own pack; every gated marker is real), replacing the
  first-suggestion-only check. External YAML packs can declare
  `gated: true` per suggestion.
- **The fail-closed launcher-verifier family now carries stable, allowlistable
  rule ids (#316, #304, #313).** "Embedded shell launcher cannot be statically
  verified" and "Inline interpreter launcher cannot be statically verified"
  denials previously reported `"rule_id": null` with `source:
  "legacy_pattern"` — nothing to `dcg allowlist add`, nothing for
  `[policy.rules]`. They are now `heredoc.shell:launcher-unverified` and
  `heredoc.posix:inline-launcher-unverified`: reviewable, allowlistable
  (an allowlist grant skips only the fail-closed launcher check — the rest of
  the command is still evaluated on its own merits), and policy-addressable
  like the #261 family.

### Fixed

- **Heredoc/launcher allowlist grants no longer override pack denials.** A
  grant for a fail-closed heredoc-family rule (e.g.
  `heredoc.shell:launcher-unverified`) was converted into a whole-command
  allow at the end of evaluation even when the pack pass had denied the
  command — an unverifiable encoded-launcher segment chained with `rm -rf /`
  was allowed in full under the grant. Both terminal conversion sites now
  attribute the grant only to an ALLOW outcome; pack denials and indeterminate
  verdicts pass through untouched, so a grant skips exactly the fail-closed
  check it names and nothing else (bd-l9jf whole-command leg).
- **Windows installer repairs a stale `$PROFILE` hook-check (#282).** The
  earlier #282 fix corrected the startup-check block's detection text, but the
  installer skipped any profile already containing the marker line — which was
  identical across versions — so pre-fix installs kept warning
  `[dcg] Hook missing from ~/.claude/settings.json` on every new terminal no
  matter how often dcg was reinstalled or updated. `Add-DcgProfileCheck` now
  rewrites the managed block in place when its content is stale (line-ending
  differences don't count as stale), and best-effort repairs the *other*
  PowerShell host's `profile.ps1` (Windows PowerShell 5.1 vs pwsh 7) without
  ever creating one.
- **Unix shell startup checks self-repair too.** `install.sh` and
  `dcg setup --shell-check` had the same marker-only idempotence trap on the
  bash/zsh RC snippet: once the marker line existed, no re-run would ever
  replace the block, pinning users to the first snippet version they received.
  The Unix snippet has never changed, so nobody was bitten — this closes the
  trap before the first time it does. Both injectors now rewrite a stale
  managed region (marker line through the first column-0 `fi`) in place; an
  unrecognizable boundary falls back to appending a current block.
- **The keyword pre-filter treats `_` as a boundary, not a word character
  (#323).** Underscore was in the pre-filter's word class, so underscore-joined
  names never admitted a pack: `export DCG_DISABLE=1` quick-rejected past the
  guardrails pack's own self-weakening rule, `terraform destroy
  -target=cloudflare_record.www` past `dns.cloudflare`, and `WEBHOOK_SECRET` /
  `SCW_SECRET_KEY` past every credential rule — the regexes were correct but
  never ran (silent fail-open, invisible to tests written against hyphenated
  decoys). `_` is now a boundary in the pre-filter only; pack regexes still
  decide the verdict, so the change can only admit more commands to full
  evaluation. Alphanumeric continuations (`dcgx`) still quick-reject.
- **Dead-gated rules re-armed by fixing their packs' keyword lists (#323).**
  `system.disk` gained `umount` (the `umount-force` rule was unreachable — no
  keyword in the list occurs in `umount -f`), `database.redis` gained `valkey`
  and `keydb` (the protocol-compatible client renames; every rule silently
  stopped firing on those binaries), and `database.mysql` gained `mariadb` and
  `RESET MASTER` (the renamed client, and the reset-master statement when it
  reaches the shell without a `mysql` token).
- **A `Bash`-labeled command that is unmistakably PowerShell now evaluates as
  the fail-closed union of all dialects (#322).** VS Code Agent Host
  transforms PowerShell tool calls and puts `tool_name: "Bash"` on the wire,
  so `Remove-Item -LiteralPath .\pipelines -Recurse -Force` was evaluated
  under the POSIX dialect — where a cmdlet is an inert unknown binary — and
  executed. When any statement segment starts with an approved-verb
  `Verb-Noun` cmdlet token, the hook now widens the dialect to `Unknown`,
  which fails closed across every dialect. Explicit `powershell`/`pwsh`/`cmd`
  labels are never second-guessed, and hyphenated POSIX commands (`apt-get`,
  `docker-compose`, `start-stop-daemon`) do not widen.
  **Two follow-up gaps closed (fresh-eyes review):** (1) the widening only
  fired on `Verb-Noun` cmdlet tokens, so the PowerShell/cmd *aliases* agents
  emit most — `rm -Recurse -Force .\pipelines`, `del /s /q C:\src`,
  `rd /s C:\dir` — still evaluated as POSIX and failed open. The hook now also
  widens when a segment leads with a destructive alias (`rm`/`ri`/`del`/`rd`/
  `rmdir`/`erase`) **and** carries a Windows-shell-only argument — a
  single-dash PowerShell parameter word (`-Recurse`/`-Force`/`-Path`/…, a
  ≥3-char prefix that POSIX `rm` never accepts) or a cmd switch (`/s`, `/q`).
  A plain POSIX `rm -rf ./build` has neither and keeps the Posix dialect.
  (2) The oversized-input fail-closed path (`try_deny_oversized_input`, taken
  when a payload exceeds `max_command_bytes`) resolved each scan window with an
  *unrefined* dialect, so padding a mislabeled PowerShell payload past the
  limit reopened the same hole. That path now applies the identical
  `refine_shell_dialect` widening per window.
- **`redirect-truncate-root-home` knows the macOS home spelling (#325).**
  The sensitive-path alternation carried `/home` but not `/Users`, so `echo x
  > /Users/<user>/.zshrc` — the absolute form tools actually hand agents —
  was allowed while `> ~/.zshrc`, `> $HOME/.zshrc`, and even the *less*
  certain `> $D/.zshrc` were blocked. `/Users` now sits in the shared
  alternation of every rule that uses it (`redirect-truncate-root-home`,
  `mv-sensitive-source-root-home`, `find -delete`, `unlink`, `truncate`,
  `shred`, `tar --remove-files`, `dd of=`, and the cp/ln/rsync
  copy-then-delete chains), matching the platform parity the `rm` rules
  already had (#247).
- **Write-safe character devices no longer deny as truncating redirects
  (#324).** `> /dev/null`, `> /dev/zero`, `> /dev/full`, and `> /dev/tty`
  are carved out of `redirect-truncate-*`: these are always character
  devices, so opening them with `O_TRUNC` cannot destroy persistent data,
  and each false block cost a human round-trip. `/dev/st0` (tape) and
  `/dev/tty0`/`/dev/ttysNNN` (other terminals) stay blocked.
  **Correction (fresh-eyes review):** the carve-out originally also covered
  `/dev/stdout`, `/dev/stderr`, and `/dev/fd/[0-2]`, on the false premise that
  they too are character devices. They are symlinks to whatever fd 0/1/2
  currently point at, which may be a regular file (after `exec > logfile` or
  an inherited redirect) — where `O_TRUNC` truncates that real file. Those
  three are no longer carved out; the guard blocks them under its
  zero-false-negatives posture.

- **Quoted `>` bytes inside an inline interpreter payload no longer read as
  redirect syntax when the segment carries a real redirect (#317).** `sh -c
  "echo 'a => %s'" 2>&1` (and the `2>/dev/null` / literal `/tmp` target /
  `python3 -c` / `node -e` variants) allowed: the `redirect-truncate-*` match
  offset is now re-derived against the payload's own quoting, extending the
  6f1aa5a treatment from `$`/backtick to the redirect operator. A live `>`
  inside the payload (`bash -c "cat x > $T"`), a dynamic or sensitive target
  outside it, and multi-segment payloads all keep the fail-closed deny.
- **PowerShell `2>$null` is the null device, not a dynamic path (#321).**
  Under a proven PowerShell dialect, a command whose every redirect target is
  the read-only `$null` automatic variable (case-insensitive, `${null}`
  included) no longer denies as `redirect-truncate-dynamic-path`. `$nullFile`,
  `$none`, mixed targets, and POSIX/Unknown dialects — where `null` is an
  ordinary assignable variable — stay denied.
- **Grok Build's documented shell tool name is accepted (#319).** Grok's hooks
  guide names the shell tool `run_terminal_command`; dcg only accepted the
  abbreviated `run_terminal_cmd`, so the documented envelope was answered with
  a "skip" — a silent fail-open on the exact path Grok uses. Both spellings now
  classify as the Grok protocol and evaluate the command.
- **`redirect-truncate-*` denials now carry redirect-specific suggestions
  (#316/#317).** The suggestion registry previously served the recursive-rm
  set (`ls -la` preview / `rm -ri` / move-to-trash) for redirect rules — a non
  sequitur on a redirect denial. The rules now suggest inspecting the resolved
  target, appending instead of truncating, redirecting to a literal temp path,
  and backing up first. The `rm-rf-root-home` explanation also no longer
  recommends `rm -rf /path/to/specific/directory` — a command dcg itself
  denies — and points at the literal-temp and interactive (`rm -ri`) forms it
  actually allows (#316).

### Dependencies

- Applied dependabot #315 directly: `async-trait` 0.1.92, `ast-grep-core` /
  `ast-grep-language` 0.45.1, `rusqlite` 0.40.2 (+ `libsqlite3-sys` 0.38.2).

## [v0.11.0](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.11.0) -- 2026-08-14 [Release]

### Added

- **macOS `diskutil` coverage in `system.disk` (#305).** `diskutil eraseDisk`,
  `eraseVolume`, `reformat`, `zeroDisk`, `randomDisk`, and `secureErase` deny
  as `diskutil-erase`; `partitionDisk`, `splitPartition`, `mergePartitions`,
  and `resetFusion` as `diskutil-partition`; and `apfs
  deleteContainer/deleteVolume/eraseVolume/deleteSnapshot` as
  `diskutil-apfs-delete` — all Critical, all case-insensitive because diskutil
  accepts any verb casing. Read-only verbs (`list`, `info`, `activity`,
  `apfs list`/`listSnapshots`) stay allowed, and a read-only verb cannot mask
  a chained destructive verb on the same line.
- **The canonical fork bomb is blocked (#302).** `:(){ :|:& };:` and
  word-named variants deny as `core.filesystem:fork-bomb` (Critical). The
  regex uses backreferences to require the same identifier in all three
  positions, so ordinary function definitions that pipe two *different*
  commands do not match. Because the shape necessarily spans `|`, `&`, and
  `;`, the rule joins the whole-command cross-segment pass, and the shell
  function-definition operator `()` (pure syntax, invisible to span-based
  keyword gating) is now a recognized quick-reject signal for the pack.
  Differently shaped bombs (`while true; do (x) & done`) remain out of scope —
  the regex family cannot enforce those without unbounded false positives.
- **Proven timestamped sibling-backup `mv` is allowed (#308).** The exact
  cross-harness installer shape — `STAMP=$(date +%Y%m%d%H%M%S);
  BACKUP="<src>.backup-$STAMP"; mv "<src>" "$BACKUP"` — is a reversible
  sibling rename: the destination is proven to be the source plus a
  digits-only suffix, and the two assignments must be the segments
  immediately before the `mv` so nothing can mutate them in between. Only
  `mv-dynamic-path` and `mv-sensitive-source-root-home` are narrowed; any
  deviation (a different substitution, non-sibling destination, mv options,
  extra operands, an intervening segment, traversal, globs, unquoted
  destination) keeps the fail-closed deny.


- **`database.bigquery` pack — the `bq` CLI and GoogleSQL.** 11 CLI rules and
  21 GoogleSQL rules. Three BigQuery specifics drive them, and each one makes a
  naive port of the PostgreSQL/Snowflake packs wrong: a *dataset* is a `SCHEMA`
  in GoogleSQL, so `DROP SCHEMA` is the dataset-level catastrophe rather than a
  namespace tidy-up (Critical); GoogleSQL **requires** a `WHERE` clause on
  `DELETE`/`UPDATE`, so `WHERE TRUE` is the idiomatic full-table spelling and a
  `delete-without-where` rule modelled on PostgreSQL would never fire; and time
  travel (2–7 days) is the only undo, so `--max_time_travel_hours` and
  `SET OPTIONS(expiration_timestamp)` destroy the recovery path itself and are
  destructive in their own right. BigQuery ML models get their own rule —
  they are not covered by time travel and cost hours of training to rebuild.
  CLI rules are scoped with `executables = ["bq"]` *and* a `bq`-anchored regex,
  because `executables` is enforced in the evaluator rather than in
  `Pack::check`. Opt-in like every other `database.*` pack; joins the
  `careful_company_running_windows` preset; recommended automatically when a
  project depends on `google-cloud-bigquery`, `@google-cloud/bigquery`,
  `pandas-gbq`, or `sqlalchemy-bigquery`.

  Evaluator wiring makes the pack *indirect*, so its unscoped GoogleSQL rules
  cannot claim the SQL inside another client's invocation: `database.bigquery`
  sorts first within tier 7, so without it `snow sql -q "DROP TABLE ..."` would
  have been reported as a BigQuery rule. Regression cases pin both directions.

  Implemented independently from the analysis in closed PR #295, per the
  project's no-outside-merges policy.

- **`dcg doctor --strict` (#296).** `doctor` exited `0` unconditionally, including
  when it had just reported `"ok": false` — so `dcg doctor || handle_failure` was
  dead code and a provisioning run got a green signal from a guard doctor itself
  had classified as broken. `--strict` makes the exit status carry the verdict.
  It is opt-in, matching `pack validate --strict`; the default stays `0` for
  anyone already calling doctor in a pipeline.

### Changed

- **The block message no longer echoes the command twice (#299).** The command
  appeared in both the `Tip: dcg explain "<cmd>"` line and a `Command: <cmd>`
  line, making `len(permissionDecisionReason) = 2*len(command) + 499` exactly. A
  hook decision lands in the agent's transcript and is replayed on every later
  turn, so the second echo was paid for repeatedly while telling the reader
  nothing the first did not — the agent just wrote that command. The `Tip:` copy
  is kept because it is also actionable. No verdict changes.
- **`platform.github` rules now carry explanations and suggestions (#300).** All
  sixteen destructive rules were built with the 3-arg macro form, so every
  denial rendered as "No additional explanation is available yet. See pack
  documentation for details." Each rule now explains what is actually lost and
  names the safer spelling — for the raw-API catch-all, that includes pointing at
  the first-class `gh issue edit --remove-parent` / `--remove-sub-issue` verbs,
  which dcg allows outright. A new pack test enforces this going forward.

### Fixed

- **`chown -R`/`chmod -R`/`setfacl -R` on bare `/` and `/home` now deny
  (#301).** Two independent bugs in `system.permissions`: the protected-path
  regex tail `(?:$|bin|...)\b` could never match a bare `/` (the `\b` after
  the end-anchor has no word character to bound), and `/home` was missing
  from the protected list entirely. `chmod-777` had masked the 777 case,
  which is why the gap survived the obvious test. `/home` is scoped to the
  home root or a whole single-user home (`/home`, `/home/user` — where
  `~/.ssh` lives), so a routine `chmod -R /home/user/project` on a project
  directory stays allowed while `chmod -R /home` (which locks out every
  account) is blocked.
- **`pnpm`/`npm`/`yarn` publish rules require subcommand position (#306).**
  `pnpm run build; bun ./publish-snapshot.ts`, `pnpm run build --reporter
  "publish"`, and `pnpm run build publish` no longer deny: `publish` must be
  reachable through option tokens only, so argument data and later shell
  segments are not publication. Because the pack regexes run on the sanitized
  command — which has already stripped the quotes that distinguish
  `pnpm --reporter "publish"` (a value) from `pnpm --reporter publish` — a
  match is confirmed against the **original** command by a quoting-aware gate
  (`invokes_publish_subcommand`): an unquoted `publish` in subcommand position
  is publication, a quoted one is data. Real forms (`pnpm -r publish`,
  `pnpm recursive publish`, `--filter <ws> publish`, `yarn workspace <ws>
  publish`, `yarn npm publish`, `pnpm.cmd`) still deny, and an unquoted
  option value named `publish` stays fail-closed, in every dialect. The
  `*-dry-run` safe patterns are segment-bounded so a dry-run in one segment
  cannot mask a later one.
- **Single-quoted `$`/backtick/backslash in `mv` paths are literal (#307).**
  `mv './$ROOT' /tmp/x` is data, not expansion: `mv-dynamic-path` stands
  down only when *every* dynamic marker in the command is inside a POSIX
  single-quoted span. One active marker anywhere — double quotes, unquoted
  variables, a quote-manipulating backslash — keeps the deny.
- **`dcg --robot test` honors the hook evaluation budget (#309).** Robot mode
  is an agent-integration boundary, so it now enforces the configured
  timeout and answers with bounded `{"decision":"indeterminate",
  "source":"analysis_budget"}` JSON without requiring the human-facing
  `--enforce-budget` diagnostic flag (which stays opt-in for interactive
  `dcg test`).
- **`pwsh --version`/`--help` and read-only `-c` variable expressions are
  allowed (#304).** pwsh accepts exactly two GNU-style spellings, both
  print-and-exit; they no longer land in the unknown-host-option refusal.
  And a `-Command` payload that is exactly one variable read with property
  accesses (`$PSVersionTable.PSVersion`, `$env:PATH`) invokes nothing, so it
  no longer trips the runtime-expansion refusal — invoking, indexing,
  subexpressions, or any second statement stays fail-closed. (`-File` was
  already fixed on main; `SP=…; pwsh -c "…"` likewise.)
- **Backing up the agent's hook config is a read, not tampering (#313).**
  `Copy-Item ~/.claude/settings.json <backup>` no longer denies:
  copy-family verbs moved out of `agent-hook-config-tamper` into a new
  `agent-hook-config-overwrite` rule that fires only when the config path is
  the *write* side (`-Destination` or positional destination). Deleting,
  rewriting, moving, or renaming the live config still denies, as does
  copying anything onto it.
- **`bash -c` payloads keep their own quote context (#288 follow-up).**
  `bash -lc 'grep -n "rm -rf /" notes.md'` was denied while the bare inner
  command was correctly allowed: the match landed inside the inline payload,
  whose `InlineCode` classification dropped the payload's internal quoting.
  A core-rule match inside a POSIX-shell inline payload is now re-classified
  against the payload itself, so it resolves exactly like the bare inner
  command — and `bash -c 'rm -rf /'` still denies, because the payload
  classifies it as live code.


- **A pathological `gh` command line could fail OPEN.** The shared option-prefix
  in `platform.github` used `\S+` for an option's value, which also matches a
  flag token — so in `gh -a -b -c …` each token could parse either as a new
  option or as the previous one's value, giving exponentially many parses.
  These patterns carry a lookahead and therefore run on the backtracking
  engine, where `CompiledRegex::is_match` maps a backtrack-limit error to
  `false`. Adopted the unambiguous shape the database packs already use
  (`[^-\s;&|][^\s;&|]*`).
- **`dcg doctor`'s pretty renderer computed a wrong verdict**, which now
  matters because `--strict` derives the exit status from it — and pretty is
  what runs in CI, since rich output is disabled without a TTY. A failed
  config write printed an error without counting it, and the Grok
  "NOT REGISTERED" branch incremented `fixed` without ever incrementing
  `issues`, corrupting the `issues == 0 || (fix && fixed == issues)`
  arithmetic in both directions: masking a genuinely unfixed issue, and
  reporting failure on a fully repaired machine.
- **`doctor --fix` could buy off a problem it could not fix.** Creating the
  default config counted a `fixed` with no matching `issues` (a missing config
  is a *warning*, not an issue), so that one success cancelled a genuinely
  unfixed issue through the `fixed == issues` equality: on a machine whose hook
  was misconfigured and unwritable, `dcg doctor --fix --strict` reported "All
  issues fixed!" and exited 0. Both renderers now count the issue each repair
  resolves, and a test asserts `fixed <= issues`.
- **`doctor --strict` gave different answers per `--format`.** The Grok
  registration check existed only in the pretty renderer, so a machine with
  Grok present and unwired exited 1 with `dcg doctor --strict` and 0 with
  `--format json`. The check now lives in the shared report (`grok_hook`) and a
  test pins that both renderers agree.
- **`gh repo delete` recommended a command dcg itself blocks.** Its first
  suggested alternative was `gh repo archive`, which the same pack denies, so
  the agent bounced between two denials. The suggestions now lead with a
  runnable command and say plainly that archiving is gated too. A pack test
  asserts no rule's first suggestion is blocked by its own pack.
- **`gh-api-delete-repo` is no longer a misnamed catch-all (#300).** The rule
  matched *any* `gh api ... DELETE`, not repository deletion, while its name is
  what surfaces as `rule_id` in the history DB, `dcg stats`, `dcg
  suggest-allowlist`, and allowlist entries. The catch-all is now
  `gh-api-delete-generic`, and `gh-api-delete-repo` matches what its name says:
  `DELETE /repos/{owner}/{repo}`. Both are still denied, so no command changes
  verdict. **Breaking for persisted state:** an allowlist or `[rules]` entry for
  `platform.github:gh-api-delete-repo` now permits only repository deletion
  rather than every raw-API DELETE — a tightening — and history rows written
  before this release keep the old `rule_id`.

- **False positives:** `pwsh -File <script.ps1>` (and its abbreviation `-f`) is
  no longer denied as an unverifiable launcher envelope. `-File` was missing
  from the PowerShell host-option table entirely, so it resolved to `Unknown`
  and hit the fail-closed branch for unrecognized dash tokens — while the
  positional `pwsh <script.ps1>` form, which is the same operation, and
  `-Command`, which is strictly more dangerous, were both allowed. `-File` is
  now a first-class option that ends host-option parsing (later tokens are
  script arguments, not host options). `-File -` still refuses, because a
  script read from stdin is no more inspectable than `-Command -`. Routing it
  through the shared option table also means `pwsh -f -` is now recognized as
  reading a script from stdin, which the previous exact-match `-file` check in
  the pipeline analyzer missed.

---

## [v0.10.0](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.10.0) -- 2026-08-07 [Release]

A large correctness, feature, and hardening release from a full issue-triage
pass followed by an adversarial fresh-eyes review of that same work (which
caught, and this release fixes, four false-negatives the first pass had
introduced). It closes eighteen tracker issues, adds two new configuration and
pack-authoring surfaces, and lands the first two parts of the segment-scoped
evaluation design (#289). The evaluation hot path is unchanged for ordinary
commands; the new all-dialect fan-out and per-rule scoping only do extra work
when a command actually carries dialect-divergent syntax or an executable-scoped
pack is enabled.

### Added

- **Per-rule target-path exemptions (#284).** A new `[rules."<pack>:<pattern>"]`
  config table with `exempt_target_globs` lets a specific rule stand down when
  its operation targets a statically-literal path under an allowed glob (e.g.
  `~/.claude/jobs/*/tmp/**` for the `redirect-truncate`/`rm` rules that agent
  job-scratch directories collide with). Every other rule still evaluates the
  full command, so a destructive suffix is still caught — unlike an `[overrides]
  allow`, which is a whole-command bypass. Literal targets only (dynamic-path
  rules are deliberately unsupported); `..` traversal is rejected; the setting
  reduces coverage, so it is ignored from an automatically-discovered `.dcg.toml`
  and honored only from user/system/`DCG_CONFIG`. `dcg doctor` warns when it is
  configured on a rule that does not support it.
- **Rules can declare their executables (#289 part B).** Destructive patterns
  (built-in and external YAML packs, via a new `executables:` key) may name the
  executables they apply to; the engine then only evaluates such a rule against a
  command segment whose resolved `argv0` matches. `system.permissions` is the
  first migrated pack, so a `chmod` rule no longer fires on a `grep -r` elsewhere
  in the line. `executables` omitted preserves prior behavior exactly.
- **Diagnostics honesty (#289 part C).** `dcg test`/`dcg explain` now report when
  a denial comes only from the all-dialect analysis and the Bash hook (posix
  dialect) would allow — with the `--dialect posix` reproduction line and an
  additive `dialect_divergence` JSON field. `dcg test`/`dcg explain` invocations
  wrapped in loops, conditionals, or `&&` chains are no longer blocked on their
  own quoted argument.
- **Cross-pack regression corpus (#289 part D).** False-positive shapes from the
  closed issues are now replayed against every registered pack across all shell
  dialects on each test run, so a shape fixed under one rule is re-checked against
  the others. It found four new false positives on its first run (all fixed
  here).

### Security

- **Unknown-dialect evaluation no longer under-matches regex packs (#294).** A
  command inert under POSIX quoting but destructive under `cmd.exe`/PowerShell
  quoting (`echo 'ok & docker system prune -af`) is now caught under the default
  all-dialect analysis via a deny-wins fan-out, including caret- and
  backtick-obfuscated executables (`doc^ker`). The extra views run only when the
  command carries a dialect-divergent byte and an enabled-pack keyword.
- **Oversized hook input no longer silently skips evaluation (#290).** Padding a
  destructive command past `max_hook_input_bytes` previously failed open by
  default; the already-read buffer (drained up to a bounded cap) is now scanned
  for every embedded command and a destructive one is denied. The default
  fail-open posture for genuinely benign oversized input is unchanged.
- **The protocol denial is emitted before pending-exception persistence (#291),**
  so a slow or contended allow-once store can no longer delay or suppress a
  block.

### Fixed

- **False positives:** `chmod`/`chown`/`setfacl` no longer pair their flags with
  a different command in the same line, in any dialect (#287); the Cloudflare
  Wrangler semantic fallback requires actual Wrangler evidence, so `command -v
  foo`, `env`, and `time foo` are no longer denied (#283), and fully-dynamic
  executables (`$cmd $arg`) are no longer misattributed to it either;
  `core.git:branch-dynamic-token` no longer fires on non-git commands (#281); a
  variable expansion followed by a command substitution inside one double-quoted
  word parses correctly (#279); `git commit -F -` message bodies are treated as
  data on every scanning path (#277); literal paths under the per-user Windows
  temp directory are exempted like `/tmp` (#285).
- **Windows enforcement:** `rd /s` / `del /s` are blocked through the live
  PowerShell hook path, not only in `dcg test`/`explain` (#280).
- **Self-heal robustness (#292):** `~/.claude/settings.json` is now rewritten
  atomically (temp + fsync + rename) under a bounded lock, preserving symlinks
  and file mode, so a crash or a concurrent writer can no longer truncate it or
  drop its permissions.
- **External pack loading (#293)** is bounded by the hook deadline, caps glob
  matches and per-file size, and surfaces load failures without `--verbose`.
- **Installer:** the PowerShell profile check no longer prints a spurious "hook
  missing" warning when the hook command is present in its quoted-invocation form
  (#282).

### Internal

- The evaluation body was factored so the unknown-dialect path can replay it per
  dialect (#294); `argv0` resolution now walks the tokenizer and skips grouping
  punctuation, reserved words, `case` pattern lists, assignments, and wrappers so
  executable-scoped rules see the real command word inside compound constructs.
- Design decisions #289 A/B are staged: the corpus (D) is the regression net and
  `executables=` (B) migrates pack-by-pack; #288/#289 remain open as the anchors.

## [v0.9.4](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.9.4) -- 2026-08-05 [Release]

A correctness and hardening release from a full issue-triage pass. It closes a
class of fail-closed bypasses in the `#261` init-idiom warn path, restores four
compose volume/force detections that global flags or combined short-flag
clusters could slip past, and removes several false positives that were blocking
ordinary safe workflows. No change to the evaluation hot path's asymptotics; a
profiling campaign confirmed dcg already runs 35–90× inside its hook budget and
produced a committed negative-evidence ledger rather than speculative tuning.

### Security

- **`eval`/`source` init-idiom WARN can no longer be used to smuggle a
  destructive command (#261).** The curated init-idiom downgrade (which lets
  `eval "$(ssh-agent -s)"` and `source <(kubectl completion bash)` warn instead
  of hard-deny) was found across four adversarial fresh-eyes rounds to let a
  destructive command run with only a warning by attaching to, or hiding behind,
  a curated idiom. The warn is now locked to an allowlist-shaped box: it applies
  only at command-substitution depth 0 (a curated idiom reached through a nested
  substitution or heredoc recursion hard-denies at the consumption point), only
  when the whole command is a single POSIX segment (a trailing `; rm -rf ~` or
  any multi-segment/nested form keeps the hard denial), and only when the bytes
  before the `eval`/`source` word are statically inert (no `(` `)`, backtick,
  `<`, `>`, `|`, `&`, `;`, or newline) — closing the leading-assignment,
  command-substitution, and process-substitution holes that a denylist kept
  missing.
- **Compose volume/force destruction is caught past global flags (#276).**
  `containers.compose:down-volumes` (and `down-rmi-all`, `rm-volumes`,
  `rm-force`) required the subcommand to immediately follow `compose`, so the
  most ordinary dangerous form — `docker compose -f docker-compose.prod.yml
  down -v`, which destroys named volumes (database data, uploads) — was
  **allowed**. Each pattern now skips global options and their values with a
  bounded, option-only walker before the subcommand, without letting a service
  name or a `-f down.yml` filename value masquerade as the `down`/`rm`
  subcommand.
- **Combined short-flag clusters are caught (fresh-eyes finding).** The
  volume/force guards required a standalone single-flag form, so pflag-style
  combined clusters slipped through: `docker compose down -vt 5` and
  `docker compose rm -fsv` remove volumes but were allowed when only
  `containers.compose` was enabled. The guards now match a `down`/`rm`
  short-flag cluster containing the target letter, enumerated to each
  subcommand's real short flags (keeping matching linear — no lookbehind, no
  ReDoS — and not firing on a `v`/`f` inside a long option like `--verbose`).
- **Execution-frontend strip bail no longer weakens live hooks (#260).** When
  an `env`/`nice`/`timeout`-style frontend strip fails on dynamic options, the
  later `git` words now stay scan-required, so a live PreToolUse hook is never
  weaker than `dcg test` on the same command.

### Fixed

- **Fixed `xargs`/`sh -c` templates that only consume record fields as data are
  no longer denied (#272).** Positional-parameter masking now walks the template
  with quote- and escape-awareness, masking bare `$N`/`${N}` records while still
  refusing `$@`/`$*` aggregates, `${!indirect}`, `BASH_ARGV`/`ARGC`, and any
  `${N…}` form with expansion modifiers. Two quote-scanner false negatives were
  fixed alongside it: an apostrophe inside a double-quoted word can no longer
  disable subsequent `$N` masking, and ANSI-C `$'…'` strings are skipped
  atomically so their escaped quotes cannot corrupt quote-state tracking and
  hide a `$0`.
- **Safe variable redirects into a same-command `$(mktemp)` are allowed (#275).**
  A synthetic scratch stand-in proves bare `mktemp` / `mktemp -d` targets
  (`-d`/`-q` only; not `-p`/`-t`/`-u` or explicit templates), and a literal
  suffix after the closing quote folds into the proven target so `"$D"/out.log`
  works — while traversal and non-literal continuations still deny.
- **Dynamic `git branch` hazards get their own remediation (#274).** An
  unresolvable dynamic word that may expand into a delete/force flag now
  attributes to `core.git:branch-dynamic-token` with a suggestion to quote the
  name or add `--`, distinct from proven `branch-force-delete`.
- **PowerShell expression statements are no longer misread as dynamic `git`
  mutators (#273).** A statement beginning with a quote, variable, array, or
  hashtable literal (with no `$( )`/`@( )` subexpression) cannot invoke its
  first token as `git`, so it is not treated as a dynamic branch mutation.
- **Printed `heredoc.<family>` rule ids can now be allowlisted (#162/#261).**
  Embedded-code AST denials and `#261` unverifiable-sink rules attach synthetic
  ids like `heredoc.posix:eval-dynamic`; pack-id validation now accepts exactly
  `heredoc.<family>`, so the `dcg allowlist add …` command dcg itself prints
  actually validates (bare `heredoc` stays invalid).
- **Cross-OS hook paths are diagnosed, not silently missed (#264).** The CLI now
  names a `C:\…\dcg.exe` hook path on Unix (and the reverse), so a cc-switch–style
  cross-OS `settings.json` rematerialization is reported instead of a confusing
  "hook not found".

### Internal

- Added a measurement-only `release-perf` cargo profile (frame pointers + line
  tables for `samply`) and committed the cold-start profiling artifacts:
  baseline fingerprint, per-phase differential attribution, a ranked hotspot
  table, and a **negative-evidence ledger**. The disciplined outcome: no
  isomorphism-safe optimization clears the Score ≥ 2.0 bar at acceptable
  false-negative risk on a security matcher, so the evaluation path is unchanged.

## [v0.9.3](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.9.3) -- 2026-08-05 [Release]

### Fixed

- **`install.ps1` now writes the Hermes hook where native Windows Hermes
  actually reads it (#270).** `Configure-HermesHook` wrote
  `%USERPROFILE%\.hermes\config.yaml`, but Hermes Agent on native Windows
  resolves its data root from `HERMES_HOME` (which its own installer sets to
  `%LOCALAPPDATA%\hermes`), defaulting to `%LOCALAPPDATA%\hermes` when unset —
  it never reads `~/.hermes` there, so the installed hook silently never
  fired. A new `Get-HermesConfigDir` resolver (`HERMES_HOME`, else
  `%LOCALAPPDATA%\hermes` on Windows, else `~/.hermes`) is used by the
  installer's write path, detection (`Detect-Agents` also now probes the
  `hermes` CLI on PATH, matching `install.sh`), the printed config path, and
  `uninstall.ps1` (which cleans both the resolved and the legacy
  `~/.hermes` locations). `install.sh`/`uninstall.sh` gained the matching
  `HERMES_HOME` override support on Unix.
- **Force-clobber redirects no longer escape `redirect-truncate-root-home`
  (#263).** `>|` is bash's force-clobber redirect — strictly stronger than `>`
  because it defeats `noclobber` — but the segment splitter treated its `|` as
  a pipeline separator, so `echo x >| /etc/passwd` was cut into `echo x >` and
  `/etc/passwd` and the redirect never reached the rule that already covers
  `>`, `1>`, `2>` and `&>`. Every FD-qualified spelling (`1>|`, `2>|`,
  `{fd}>|`) was affected, including targets that would disable the guard
  itself (`~/.claude/settings.json`, dcg's own `config.toml`). The splitter now
  keeps an unescaped `>|` intact; a genuine pipe after a quoted or escaped `>`
  still splits.
- **`mise exec -c/--command` inline shell payloads are recursively evaluated
  (#259).** `mise exec -c "<payload>"` hands the payload to a shell, but it was
  span-classified as argv data of an unrecognised consumer and rode through.
  It is now a Tier 1/Tier 2 inline-script wrapper like `sh -c`: the payload is
  extracted and re-evaluated, so a destructive payload is denied and a benign
  one (`mise exec -c "npm run build"`) stays allowed. Unlike the wrapper
  stripper, the extractor does not bail on an unmodeled flag — one
  unrecognised option must not disarm it.
- **`install.sh` no longer aborts on stock macOS with cosign 3.x (#268).**
  cosign 3.x dropped `--new-bundle-format` from `--help`, so the probe left
  `bundle_format_args` empty; bash 3.2 treats an empty array expansion under
  `set -u` as an unbound variable and killed the script mid-install. All array
  expansions that can be empty now use the `${a[@]+"${a[@]}"}` guard, matching
  the fix already applied to `scripts/e2e_test.sh`.
- **`dcg allow-once <CODE>` no longer looks like it granted something it did
  not (#262).** Without `--yes`, the confirmation prompt read from a stdin that
  an agent-invoked process does not have, so it aborted on EOF *after* printing
  a confirmation block that read like a completed grant. dcg now refuses before
  printing anything, names `--yes` in the error, and leaves the code pending.

### Added

- **`--dialect` for `dcg explain` and `dcg test` (#269).** Opt into evaluating
  a single shell dialect (`posix`, `ps`, `cmd`) instead of the all-dialect
  default, so a diagnostic can reproduce the path the live PreToolUse hook
  takes. Also settable via `DCG_DIALECT`.

## [v0.9.2](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.9.2) -- 2026-08-02 [Release]

### Fixed

A second adversarial review pass over the v0.9.1 fixes (three reviewers,
A/B-probed against the released binaries on both the all-dialect and real
hook-path evaluation routes) surfaced and closed another round:

- **A Warn-mode batch entry no longer masks later entries.** The per-entry
  `toolCalls` evaluation responded at the first non-allow outcome, so a
  Warn-mode entry (e.g. `git stash drop`) ended the request and every later
  entry — including catastrophic ones — was silently allowed. The hook now
  resolves every entry first and publishes exactly one response chosen by
  precedence (Deny > Indeterminate > Ask > Warn > Allow), which also removes
  a latent two-JSON-document protocol-corruption risk.
- **A batch no longer hides destructive sibling fields.** A `toolCalls`
  envelope that also carried a destructive `tool_input` or `tool_args`
  command evaluated only the batch; the sibling commands are now appended as
  additional entries.
- **A non-shell-only batch no longer hijacks other agents' wire shapes.**
  Any non-empty `toolCalls` array forced the Claude-compatible response, so
  a Gemini/Hermes/Grok/Codex payload carrying a `readFile`-style batch got a
  deny its parser drops; the Agent Host branch now requires a shell entry.
- **mise is modeled at its real grammar.** Global flags before the
  subcommand (`mise -v exec -- …`) bypassed the wrapper model entirely, and
  post-subcommand flags outside the modeled six bailed into the argv-data
  blind spot; both engines now share one option table (globals, booleans,
  value-takers, glued `--opt=value`) sourced in `normalize`, closing the
  known destructive-wrapped-command shapes on the Posix hook path.
- **Constant-propagation hazard scan hardened.** `while read f`,
  `{ read f; }`, `command read f`, `if read f`, `getopts`, `select`, and a
  changed `IFS` all rebind or re-split variables invisibly to the first-word
  scan and now refuse the proof; the `NAME[`/`NAME=` scan requires a real
  word boundary so a regex class like `conf[ig]` or a jq program like
  `.n[0]` no longer reads as a mutation of a short variable; glob-bearing
  values are rejected only when a use site is unquoted (`f='a[b]'; mv "$f"
  d/` allows again).
- **Oversized single commands no longer construct history machinery.** The
  v0.9.1 refactor moved the oversized refusal after history-writer setup, so
  an oversized payload created the database and worker thread; the check is
  back before construction with byte-identical output.
- **install.ps1 quotes the Copilot hook binary path** (spaced Windows
  profiles word-split at execution — the Unix side was fixed in v0.9.1), and
  the uninstaller's success detection anchors its machine marker.

## [v0.9.1](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.9.1) -- 2026-08-02 [Release]

### Fixed

Adversarial review of the v0.9.0 changes surfaced and closed eight defects in
the code that release introduced, plus long-standing installer test-harness
rot:

- **`mise exec` could hide destructive argv.** The wrapper-strip scan ran to
  the first `--` anywhere, so `mise exec rm -rf / -- ok` evaluated only `ok`;
  and an unmodeled option value could become an `echo` args-data command that
  masked the rest of the segment (`mise exec -p echo rm -rf /`). The scan now
  stops at the first bare word (mise's real command boundary) and an option
  ends wrapper handling without enabling masking.
- **Batched `toolCalls` entries are now evaluated independently.** Joining
  the batch with newlines let an entry ending in an unterminated quote or
  trailing backslash swallow the next entry's destructive command. Every
  entry (including the singular `toolCall` when both fields are present) is
  evaluated on its own with its own dialect; the first non-allow decision
  answers the request. The `dcg hook` batch subcommand gained the same
  per-entry semantics.
- **Malformed `toolCalls` shapes no longer abort the whole payload parse.**
  A non-array value or junk entry previously failed `HookInput`
  deserialization entirely, silently skipping evaluation of an otherwise
  well-formed `tool_input` command. The field is now tolerantly
  deserialized; batch entry gating also accepts nameless-with-args,
  `run_command`, and `CommandLine`-keyed entries, mirroring the singular
  path.
- **The Posit Assistant protocol steer is scoped to its own tools.** With
  `PA_PROJECT_DIR` set, a Gemini payload without an event name and the bare
  `run_shell_command` Copilot fallback were answered in Claude shape; the
  gate now also requires a `bash`/`powershell`-family tool name.
- **Subshell bindings no longer prove outer variables.** A `for` header (or
  assignment) inside `$( )`, backticks, or `<( )` could satisfy the #242
  constant-propagation proof for an outer `$VAR` whose real value comes from
  the ambient environment (`x=$(for f in a b; …); mv $f d/`). Nested
  segments are no longer binding sources.
- **`+=`, array-element, and glob-bearing assignments refuse the variable
  proof.** `f+=c`, `f[0]=/etc`, and quoted glob values (`f='/et?'`, which
  expands at unquoted use time) all slipped past the literal-binding scan.
- **Glued `-c` payloads starting with punctuation are detected again.** The
  #256 cluster narrowing required a fully alphanumeric chunk, so
  `-c"/bin/sh …"` (decoding to `-c/bin/sh …`) was no longer treated as an
  inline-code flag; the leading alphanumeric run is now the cluster.
- **Installer test harness can fail again.** The bats function-extraction
  helpers left `set +e` active in the test shell, so every assertion in the
  install/uninstall suites was inert; the helpers now restore errexit, tests
  no longer call the GitHub API per test, and the newly live assertions
  exposed and fixed a BSD-sed incompatibility in the installer's
  "already configured" detection, an unquoted Copilot hook path (spaced
  install dirs were non-idempotent and un-uninstallable), a hang when a pty
  has no operator (prompts now time out to their default), an
  empty-settings-file failure in the Posit configure path, swallowed
  uninstaller warnings, and a PowerShell uninstaller dropping user-authored
  empty matcher groups.

## [v0.9.0](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.9.0) -- 2026-08-02 [Release]

### Added

- **Posit Assistant support (idea from PR #254, reimplemented).** Posit
  Assistant reads Claude-Code-compatible `PreToolUse` hooks from
  `~/.posit/assistant/settings.json`, so dcg's existing Claude-compatible
  protocol answers it without a new wire format. The installers now detect it
  (`~/.posit/assistant`, legacy `~/.positai`, or `pa` on `PATH`) and merge an
  idempotent hook entry with the lowercase exact matcher `"bash|powershell"`
  its matcher grammar requires; the uninstallers remove only dcg-owned
  entries. `dcg` detects the agent from its documented `PA_PROJECT_DIR` hook
  variable (checked last, so agents with their own markers win), and that
  variable also steers a `powershell`-named shell tool to the
  Claude-compatible deny payload instead of Codex's minimal shape. Posit's
  hooks documentation is not public yet; the contract is pinned empirically
  by tests.
- **VS Code Agent Host batched `toolCalls` envelope (#252).** The newer
  Copilot Agent Host (and the Agents window built on it) batches tool
  invocations as `{"toolCalls": [{"name": "powershell", "args":
  "{\"command\":…}"}]}` with JSON-encoded argument strings. dcg previously
  did not recognize the plural envelope, so destructive commands sent through
  the Agent Host were silently allowed. Every shell entry in the batch is now
  extracted (string- or object-form `args`) and evaluated — one destructive
  entry denies the whole batch — with the Claude-shaped deny payload VS Code
  consumes through its compatibility layer.

### Fixed

- **UTF-8 panic on escape sequences before multi-byte characters (#255).**
  `dcg explain` / `dcg test` aborted (`byte index is not a char boundary`)
  when a PowerShell backtick — and, by the same defect, a cmd.exe caret or
  POSIX backslash — was immediately followed by a non-ASCII character, e.g.
  `s`中`. Every escape scanner that slices string content now advances by
  the escaped character's real UTF-8 width via one shared boundary-safe
  helper (21 call sites; byte-comparison-only scanners keep their fixed
  advance, which cannot panic).
- **Wrapper prefixes no longer defeat data-flag masking (#257).**
  `mise exec -- git commit -m "… restore …"`, and the same command under
  `nice`, `time`, `nohup`, `stdbuf`, `timeout`, `ionice`, `setsid`, or
  `chrt`, denied as `core.git:restore-worktree` because the sanitizer only
  recognized `sudo`/`env`/`command` as wrappers, leaving the quoted commit
  message unmasked. The sanitizer now models the same execution-frontend set
  the normalizer strips (plus `mise exec`/`mise x`, which the normalizer also
  gained), so `git commit -m` messages are masked under any of these
  launchers while `nice git reset --hard` still denies.
- **Leading `VAR="$(cmd)"` assignments misread as the executable (#256).** A
  benign `GH_TOKEN="$(python3 …)" gh issue list --search '-label:x
  sort:created-asc'` denied as an unverifiable inline launcher: the
  assignment prefix was taken as a dynamically assembled executable, and any
  later `-`-leading operand containing the letter `c` (a GitHub search
  query, `-abc`) was read as an inline-code flag cluster. Assignment prefixes
  are now skipped when locating the executable (their substitutions are
  separately evaluated as nested commands), and a short-flag cluster must be
  a real alphanumeric cluster. `"$(cmd)" foo -c` and `FOO=bar sh -c 'rm -rf
  /'` still deny.
- **Cross-dialect `;` artifacts no longer trip the git-alias boundary
  (#250).** Under the all-dialect view used by `dcg test`/`explain` and
  generic terminal tools, the cmd.exe tokenizer does not treat `;` or `'` as
  separators, so compounds like `git status; ls`, `for d in …; do cd "$d" &&
  git pull; done`, and `sh -c 'cd {} && git pull'` produced glued subcommand
  tokens (`pull;`, `pull'`) that failed closed as
  `core.git:git-alias-semantic-unverified`. A token carrying characters
  Git's dispatch could never accept is now a usage error, not a candidate
  alias; genuinely unknown name-shaped subcommands (`git lg`) and visible
  dangerous alias definitions still fail closed.
- **`for`-loop literal narrowing for `mv` and redirects (#242).**
  `for f in a b; do mv "$f" d/; done` denied as
  `core.filesystem:mv-dynamic-path` even though the loop variable's values
  are fully known. When exactly one binding — a literal assignment or a
  fully literal `for NAME in …` list (≤16 candidates, no globs,
  substitutions, or whitespace-bearing words) — proves every value, each
  candidate is substituted and re-evaluated, and only if every candidate
  independently allows is the dynamic-path rule suppressed. The same proof
  now feeds redirect targets, so `for f in a b; do echo x > "$f"; done`
  allows while `for f in /etc x; do mv "$f" d/; done`, `for f in $(ls); …`,
  and rebinding/nested-loop variants all still deny.
- **Prompt from the terminal under `curl … | bash` (#251).** The installer's
  three prompts (rustup install, predecessor removal, shell startup check)
  were gated on stdin being a TTY, which is never true when the script is
  piped, so the documented "interactive mode" never prompted. Prompts now
  write to and read from `/dev/tty`, so they work from any real terminal even
  when piped. Without any TTY (e.g. CI) the installer prints an explicit
  notice for every auto-taken decision, and the rustup question honors its
  documented `(y/N)` default instead of falling through to an unattended
  rustup install.
- **Reconcile GitHub Copilot hook key casing (#253).** The Unix installer
  merged `hooks.preToolUse` case-sensitively, so a PascalCase `PreToolUse`
  key left by older releases gained a duplicate camelCase key on `dcg
  update`, and the Unix uninstaller orphaned PascalCase dcg entries. The
  installers and uninstallers on both platforms now resolve the key
  case-insensitively, adopt the file's existing spelling, repair
  duplicated-casing files into the single canonical camelCase `preToolUse`
  key without dropping any non-dcg entry, and remove dcg entries under either
  casing.

## [v0.8.0](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.8.0) -- 2026-07-31 [Release]

### Hook latency (#245, #248)

- Compile the regex-family crates (`regex-automata`, `regex-syntax`, `regex`,
  `fancy-regex`, `aho-corasick`, `memchr`, `bit-set`, `bit-vec`) at
  `opt-level = 3` in release builds. Profiling showed >90% of the ~150-200ms
  full-evaluation cost was per-process lazy regex *compilation*, which
  `opt-level = "z"` slows severalfold; full evaluation now measures ~40-45ms
  on Apple Silicon (~4x faster) while the rest of the binary stays
  size-optimized.
- Raise the stock hook evaluation budget from 200ms to 1000ms. The old default
  was exceeded deterministically by ordinary single-construct commands even on
  fast hardware, turning routine agent commands into fail-closed review
  prompts. The deadline exists to catch pathological hangs, which sit orders
  of magnitude above normal evaluation; exhaustion still produces an explicit
  indeterminate result, never an allow.

### False positives

- `[ -f x ]`, `[[ -d "$p/.git" ]]`, and every other POSIX test-bracket probe
  no longer deny as `core.git:branch-force-delete` or as an unverified inline
  launcher (#246). A lone `[`/`[[` (or `{`) cannot glob- or brace-expand into
  a different executable, so it is now treated as the literal test builtin;
  bracket expressions that close within the word (`gi[t]`) stay fail-closed.
  Brace groups additionally require a `,`/`..` to count as expandable, so
  xargs's `{}` placeholder is literal text.
- The `branch-force-delete` regex walkers use `[ \t]+` separators so a benign
  `git branch --list` line cannot bridge a newline into a `-d`-looking token
  on a later line of the same submission (#246).
- `cat repos.txt | xargs -P12 -I{} sh -c 'cd {} && git pull'` and other fixed
  `xargs -I` templates are now evaluated recursively (placeholders masked as a
  quoted variable expansion) instead of denying wholesale as "executable POSIX
  pipeline consumer cannot be statically verified". Destructive templates
  (`sh -c 'rm -rf {}'`), records in command position (`sh -c '{}'`,
  `sh -c 'eval {}'`), GNU parallel's code-generating replacement grammar, and
  positional-record templates remain fail-closed.
- A tree-sitter recovery (`ERROR`) region only fails command-substitution
  extraction closed when it could actually conceal `$(`/backtick syntax that
  was not captured as a parsed node. Previously one unparseable fragment
  anywhere in a submission produced the unactionable "POSIX command
  substitution could not be parsed without shell-grammar recovery" deny
  whenever any substitution appeared elsewhere in the command.
- The literal temp-directory allowance now recognizes macOS's canonical
  `/private/tmp` and `/private/var/tmp` forms (#244).
- `mv <file> ~/.local/share/Trash/` (and `~/.Trash/`) — dcg's own suggested
  soft-delete — is allowed for sources under a home directory, tmp family, or
  relative paths; whole homes, sensitive system trees, traversal, and dynamic
  paths stay blocked (#244).
- A redirect whose `$VAR` target is proven by a single prior literal
  assignment in the same command (`log=/tmp/run.log; cmd > "$log" 2>&1`,
  including `$dir/suffix` forms) resolves statically instead of denying as
  `redirect-truncate-dynamic-path`. The proof fails closed on reassignment,
  variable-mutating builtins, non-fd-duplication trailing redirects, and any
  resolved path outside the tmp family or a traversal-free relative path
  (idea surfaced in PR #249; implemented independently).

### False negatives

- New `core.filesystem:rm-glob-home` rule (#247): non-recursive `rm` with an
  unexpanded glob under a home directory (`rm -f ~/Downloads/*.md`,
  `rm /Users/<u>/Documents/*.pdf`, `rm -f $HOME/*`) now requires approval.
  The glob is the recursion: the shell, not the author, decides the file set.
  Quoted (non-expanding) globs and single-file deletes are untouched.

### Security-review hardening of the above

A fresh-eyes review of this release's own additions closed four defects
before publication:

- The `$VAR` redirect proof accepted text concatenated directly after the
  quoted target, so `: > "$log"/../../etc/passwd` was proven by `$log` alone;
  the quoted token must now be the whole target word.
- A fixed xargs template could splice records into `$(...)`, backticks,
  process substitution, or arithmetic expansion — nested command contexts the
  command-position scan cannot see. Substitution bodies are now enumerated
  with the bounded tree-sitter view and any record inside one fails closed;
  process substitution and arithmetic alongside a placeholder are refused.
- `rm-glob-home`'s walker could bridge newlines (the same defect class fixed
  in `branch-force-delete`), and its `\brm\b` anchor matched the `rm` of
  `docker run --rm`; the walker now stops at newlines and the anchor refuses
  a preceding hyphen.
- `mv-to-trash` source and Trash-subpath tokens excluded whitespace but not
  `;`/`|`/`&`, and its separators now use `[ \t]+` so tokens cannot span
  command boundaries inside the safe match.

## [v0.7.8](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.7.8) -- 2026-07-28 [Release]

### Evaluation deadlines

- Preserve `Indeterminate` when a nested command substitution, inline
  interpreter, Windows launcher, Git shell alias, or Wrangler runner exhausts
  the absolute evaluation deadline. Review-capable hooks now ask for approval
  instead of misreporting timeout exhaustion as a destructive-pattern match;
  other hooks continue to block conservatively.
- Add `dcg test --enforce-budget` so operators can reproduce the live hook's
  effective wall-clock evaluation budget, including pack and allowlist setup.
- Reconcile the heredoc ADR, canonical corpus invariants, generated
  configuration comments, and README around raw-envelope fail-open behavior,
  bounded embedded-code fallback, and fail-closed indeterminate deadlines.

## [v0.7.7](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.7.7) -- 2026-07-28 [Release]

### Hook-path fail-closed hardening

- Register Claude Code, Grok, and Antigravity hooks with the resolved absolute
  path of the running dcg executable instead of relying on an interactive
  shell's `PATH`. `dcg install`, `dcg setup`, and self-heal now migrate legacy
  bare `dcg` entries while preserving coexisting hooks.
- Quote Unix executable paths containing shell metacharacters and PowerShell
  paths containing apostrophes without losing idempotent install/uninstall
  detection. Executable-resolution and non-UTF-8 path errors now fail closed
  instead of falling back to an inert hook.
- Make `dcg doctor` report PATH-dependent hook commands as broken and repair
  them with `--fix`; document absolute-path requirements for manual hook
  configuration.

## [v0.7.6](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.7.6) -- 2026-07-28 [Release]

### Cross-platform release availability

- Restore the complete six-target release matrix: Linux x86_64 musl, Linux
  ARM64 GNU, macOS Intel, macOS Apple Silicon, Windows x64, and Windows ARM64.
- Publish mandatory checksums plus independently verifiable minisign, Sigstore,
  and SLSA provenance for the complete artifact set.
- Document a fail-closed local/DSR release procedure for periods when GitHub
  Actions cannot schedule the normal distribution workflow.

## [v0.7.5](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.7.5) -- 2026-07-28 [Release]

### Local release authenticity

- Rotate manual-release minisign trust to the active DSR-managed key
  `69B3955C8D2E62A8`. The retired `36B847D11BA5A0D0` trust root is constrained
  to v0.6.7, the only historical release with signed installable archives.
- Accept locally generated Sigstore bundles signed by a pinned self-managed
  cosign key while retaining the GitHub Actions OIDC trust path for workflow
  releases. When a patched cosign verifier is available, a present bundle must
  verify under one of those two roots.
- Refuse Sigstore verification with cosign releases affected by
  CVE-2026-22703, require 2.6.2+/3.0.4+, and resolve a real external cosign
  executable rather than a shell or PowerShell function shim.
- Publish local DSR builds with mandatory SHA256 sidecars, minisign signatures,
  signed SLSA provenance, and Sigstore bundles so a throttled Actions queue no
  longer prevents a fully authenticated release.

## [v0.7.4](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.7.4) -- 2026-07-28 [Release]

### Windows updater

- Launch the post-exit update worker through `Win32_Process.Create`, so it
  survives shells and remote execution hosts that terminate ordinary detached
  children when the initiating command exits. Job-breakaway and detached
  process launches remain ordered compatibility fallbacks when CIM is
  unavailable.
- Preserve installer arguments under Windows PowerShell 5.1 by explicitly
  enumerating the JSON array. Pinned `-Version`, `-Verify`, `-Dest`,
  `-EasyMode`, and `-NoConfigure` values now reach `install.ps1` as distinct
  arguments instead of collapsing into one ignored string.
- Make the update worker append its own UTF-8 progress log rather than relying
  on inherited standard handles, and support `dcg update --no-configure`
  (`--binary-only`) on Windows as documented.

## [v0.7.3](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.7.3) -- 2026-07-28 [Release]

### Correctness

- Detect bounded multi-line Outlook and CDO COM mail flows when scanning
  PowerShell scripts, while requiring executable COM-construction syntax so
  drafts, calendar access, quoted examples, and unrelated `.Send()` calls stay
  clean. PowerShell assignment handling is shared with Git analysis, preventing
  mail-object property assignments from becoming fictional dynamic
  `git branch` mutations.
- Treat path-qualified `dcg.exe` spellings case-insensitively during
  self-inspection, matching native Windows executable resolution.
- Keep executable Git commands guarded when POSIX control-flow reserved words
  share their separator-delimited segment, including `if`/`elif` conditions,
  `then`/`else` bodies, loops, groups, wrappers, branch mutations, and visible
  Git aliases (#239). Exact quoted spellings, explicitly selected executables,
  inert argument text, and invalid reserved-word order remain non-executable.
- Extend the same executable-role analysis to Bash `coproc` commands and
  `function name` declarations, with bounded structural nesting and
  fail-closed handling beyond the parser budget.
- Preserve literal `+` bytes in `scp://` URI paths while continuing to decode
  percent escapes such as `%20`.
- Recognize Cmd's leading `@` echo-suppression marker when applying the
  preset's narrowly scoped direct-`hfdt` exemption; dynamic executables and
  chained commands remain guarded.
- Make the Windows history stress gate parse and validate dcg's hook JSON
  contract and require the post-recovery write to increase the record count.

### Release engineering

- Stage native-Windows self-updates through a detached helper that waits for the
  running `dcg.exe` to exit before invoking the verified, version-pinned
  installer. Update progress is retained in the Windows cache log.
- Make distribution publishing fail closed unless all six Linux, macOS, and
  Windows archives and both installers have checksum sidecars and non-empty
  Sigstore bundles. Release automation also refuses to create a tag while the
  distribution workflow is disabled and explicitly dispatches distribution for
  automation-created tags, so partial platform releases can no longer pass
  silently.
- Pin the third-party Rust toolchain action to an immutable commit, serialize
  release automation, inspect the exact package-version tag, and let manual
  runs retry distribution for an existing tag. Release values now cross into
  shell steps through environment variables rather than interpolated source.

### Windows operations

- Give the `careful_company_running_windows` preset a 3000 ms default hook
  deadline when no explicit setting is present, expose the effective deadline
  and source through `dcg config`/`dcg doctor`, and distinguish one dcg hook
  from unrelated agent hooks in diagnostics.
- Add `dcg test --stdin` for safely supplying denied fixtures without putting
  them in the parent command line, and add `dcg scan --with-packs` for
  non-persistent source-policy checks.

### Dependency hardening

- Upgrade `rust-mcp-sdk` from 0.9 to 1.0.1 for its 1.0 protocol stack, stdio
  busy-loop fix, and conformance/race fixes while retaining dcg's narrow
  server/stdio feature set.
- Adapt `self_update` rc.6's validated bare-SemVer release model to dcg's
  canonical `vX.Y.Z` GitHub tags so update notices retain working release URLs.
- Upgrade `ast-grep-core` and `ast-grep-language` together to 0.45 so heredoc
  parsing uses one compatible AST trait universe.
- Upgrade `base64` to 0.23 with default features disabled. dcg retains only the
  scalar `std` engine, keeping the dependency's new unsafe SIMD implementation
  out of the command-analysis path.
- Refresh the reviewed Serde, regex, Tokio, Clap, schema, update, glob, and libc
  patch releases. This includes the regex 1.13.1 match-offset correctness fix.

## [v0.7.2](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.7.2) -- 2026-07-27 [Release]

### Windows transfer correctness and latency

- Classify literal direct `scp`/`pscp` destinations before compiling the
  transfer pack's regex corpus. Cmd and PowerShell now retain exact policy
  outcomes for external, internal, download, local-drive, quoted-path, IPv4,
  and IPv6 forms, while protected remote paths keep their stable `remote.scp`
  rule IDs.
- Apply the same destination policy through Cmd wrappers and PowerShell
  `Start-Process`, including statically resolvable variables, scoped/braced
  and type-constrained variable names, literal string concatenation, inline
  parameter binding, `-ArgumentList` arrays, and statically visible parameter
  splats. Splat aliases, later field/array/method updates, mutations inside
  executing blocks, `Set-Variable`, the `Variable:` provider, and PowerShell
  7.1 explicit-parameter overrides all update the same bounded state model.
  Comma-, semicolon-, and newline-separated literal arrays retain the same
  direction-aware result. Dynamic SCP targets or argument lists fail closed
  only when the remaining command is shaped like an outbound transfer;
  unrelated dynamic process launches remain allowed.
- Follow visible PowerShell function definitions, literal parameter defaults,
  and aliases into invoked function bodies before evaluating a transfer.
  Module-qualified built-ins and explicit function removal retain PowerShell's
  real command-resolution behavior.
- Treat static `Write-Output` and `Write-Host` arguments as inert data without
  hiding real separators, subexpressions, redirects, or executable consumers.
  This removes command-shaped-text false positives while preserving recursive
  checks when the emitted text is later executed.
- Parse Cmd caret escapes, PowerShell's call operator and stop-parsing token,
  redirections, URI destinations, IPv4/IPv6 literals, option operands, and
  Windows drive paths without treating downloads or local copies as uploads.
- Lexically normalize absolute SCP destination paths before protected-directory
  checks, closing traversal forms such as `/tmp/../etc/passwd` and protecting
  Windows system destinations with the same stable `remote.scp` ownership.
- Add property-based arbitrary-UTF-8 coverage for the shared transfer parser,
  keeping malformed input bounded and panic-free.
- Refine the `core.filesystem` candidate gate so the `cp` suffix in `scp` and
  `pscp` no longer cold-initializes an unrelated large rule set. Candidate pack
  construction is now ordered and lazy, and incomplete safe `RegexSet` misses
  no longer recompile the already-checked linear patterns.
- Avoid compiling absolute-executable path normalizers for ordinary bare
  commands that cannot match their anchored syntax, and poll the evaluation
  deadline after lazy pack initialization and before returning a final allow.

## [v0.7.1](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.7.1) -- 2026-07-27 [Release]

### Windows correctness

- Keep caller-proven PowerShell syntax out of the Bash-backed database
  indirect-input fallback when no protected database or DNS consumer is
  present. This lets the intended `windows.filesystem` rule classify .NET
  directory deletion while retaining fail-closed handling for dynamic
  PowerShell database targets and real database pipelines.

## [v0.7.0](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.7.0) -- 2026-07-27 [Release]

### Policy and protocols

- Add an opt-in `ask` policy mode. Claude Code and GitHub Copilot receive their
  native operator-review response, while clients without a review decision
  fail closed with their normal blocking protocol. `warn` remains a true
  warning-only mode and consistently allows execution.
- Configure Claude Code's Windows hook for both `Bash` and `PowerShell` tools.
  The PowerShell-safe wrapper launches an absolute `dcg.exe` path without Git
  Bash consuming its backslashes, and installer migration preserves unrelated
  hooks and matcher metadata while collapsing only dcg-owned duplicates.

### Correctness and storage

- Ignore destructive command text that is merely quoted data in shell control
  flow, ordinary pipelines, and redirects (#230), while continuing to block
  later executable matches and text piped into an interpreter. Preserve the
  conservative raw scan for non-shell interpreter heredocs where quoted text
  can still reach a dynamic execution sink.
- Evaluate commands after leading POSIX environment assignments so assignment
  prefixes cannot bypass filesystem, disk, permission, or opt-in pack rules
  (#231).
- Replace the history subsystem's experimental SQLite backend with bundled
  upstream SQLite through `rusqlite`. History now enforces `max_size_mb`,
  checkpoints and compacts storage, validates FTS integrity across reopen
  cycles, and disables further writes rather than exceeding the configured
  capacity or continuing after a fatal storage error (#229).

### Distribution

- Repair the official Homebrew formula for all four supported architectures,
  accurately represent the custom license rider, test safe and denied dcg
  decisions, and make formula smoke failures blocking in tap CI (#227).
- Harden the tap updater so every versioned URL and checksum is replaced
  exactly once, all four checksums are validated, and missing architecture
  blocks or placeholder checksums fail the update.

## [v0.6.12](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.6.12) -- 2026-07-27 [Release]

Native-Windows binary release that supersedes the unpublished v0.6.10 and
v0.6.11 source tags.

### Validation

- Correct the native E2E wrapper fixtures so Cmd deletion syntax is executed
  through an actual nested `cmd /c` process instead of being misclassified as
  PowerShell syntax. The mixed PowerShell-to-Cmd launcher paths now exercise
  the protection they describe without adding a false positive for
  PowerShell's unrelated `rd` alias.
- Verify the release candidate on a native Windows workstation: all 348
  PowerShell/Cmd E2E scenarios pass, including the curated
  `careful_company_running_windows` policy.

## [v0.6.11](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.6.11) -- 2026-07-27 [Tag]

Native-Windows validation release that supersedes the unpublished v0.6.10
source tag.

### Correctness

- Preserve caller-proven shell dialect boundaries in `windows.filesystem`.
  POSIX `rm -r` commands are no longer reinterpreted as PowerShell
  `Remove-Item -Recurse` aliases merely because dcg itself is running on
  Windows; unknown-shell input remains conservatively checked.
- Make the Windows PowerShell 5.1 E2E harness capture native stderr without
  turning intentional deny diagnostics into terminating `NativeCommandError`
  exceptions. The native suite now uses an isolated conformance-test timeout
  rather than the production 200ms latency budget.
- Exercise Windows-native rules under their actual Cmd or PowerShell dialect,
  including nested launchers. Recursive deletion through `%TEMP%` remains
  review-required because the expansion is caller-controlled.

## [v0.6.10](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.6.10) -- 2026-07-27 [Tag]

### Packs

- **Add the curated `careful_company_running_windows` preset.** The opt-in
  policy is designed for Windows workstations where coding agents run without
  interactive tool approval. Six new leaf packs cover outbound email and chat,
  HTTP uploads, file-transfer tools, public tunnels/raw channels, and tampering
  with endpoint, audit, or dcg guardrails. High-confidence sends deny by
  default; ambiguous generic API writes warn; ordinary reads, downloads,
  package installation, internal destinations, and named-remote Git pushes
  remain usable.
- Enabling the preset also activates an explicitly pinned set of the existing
  Windows, database, storage, remote, backup, secrets, and cloud packs, including
  Snowflake. Leaf exclusions are applied after category/preset expansion, and
  future packs in those reused categories do not silently join the curated
  policy.
- Enforce equivalent outcomes for native `cmd.exe` and PowerShell submissions.
  Cmd analysis now handles caret escaping, case-insensitive command resolution,
  leading and attached redirections, nested command groups, `if`/`start`/`for`
  control flow, nested `cmd /c` and `call`, and shell-specific safe argument
  data without letting message text suppress a real egress rule. Dynamic
  control expansion and pathologically deep grouping fail closed under the
  preset, while ordinary echo, search, Git-message, and `hfdt` workflows remain
  available.
- Treat a direct `hfdt`/`hfdt.exe` invocation as a trusted first-party command
  while the preset is active. The exemption is executable-position aware and
  refuses lookalikes, dynamic command targets, substitutions, redirections,
  pipelines, and chained commands.

- **Close the PowerShell .NET recursive-delete false negative (#222).**
  `windows.filesystem` previously only understood cmdlet spellings, so
  `[System.IO.Directory]::Delete($path, $true)` — the .NET equivalent of
  `Remove-Item -Recurse -Force`, callable from plain PowerShell with no
  external tool — was allowed. New rules deny the static-method form
  (`dotnet-directory-delete-recursive` Critical for a literally-true second
  argument, `dotnet-directory-delete` High for dynamic-flag and
  single-argument calls, both namespace spellings `[System.IO.Directory]` and
  `[IO.Directory]`) and the instance-method spelling
  `<DirectoryInfo>.Delete($true)` (`directoryinfo-delete-recursive` Critical,
  covering `(Get-Item $path).Delete($true)` and `[System.IO.DirectoryInfo]`
  variables). Detection runs in the caller-dialect semantic pass (so proven
  PowerShell callers are covered) and as raw patterns for unknown callers;
  wholly quoted spellings remain inert data for proven-PowerShell callers.
  Read-only APIs (`::Exists`, `::GetFiles`, `::CreateDirectory`) and member
  deletes without a literal `$true` do not match.

- **Guard the Snowflake CLI's direct object-lifecycle surface (#212
  follow-up).** The `database.snowflake` pack's semantic layer covers SQL
  submitted through `snow sql`; the CLI can also drop live objects with no SQL
  payload at all. New pattern-based rules deny `snow object drop`
  (database/schema Critical, other types High), `snow stage drop` and
  `snow stage remove`, `snow app teardown`, `snow app version drop`,
  `snow snowpark drop`, `snow dbt drop`, `snow dcm drop`, and `snow spcs
  service|compute-pool|image-repository drop`, including `--force`/`--cascade`
  variants and interspersed global options. Read-only `snow object
  list/describe`, `snow stage list/list-files/describe`, and `snow stage copy`
  remain unmatched.

## [v0.6.9](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.6.9) -- 2026-07-18 [Release]

Security and correctness release that supersedes the unpublished v0.6.8 source
tag. It resolves nine newly reported issues across command analysis, pack
coverage, reliability, and configuration security; adds the Snowflake CLI pack;
makes hook deadline exhaustion explicitly fail closed; and completes the
Windows installer work begun in v0.6.7.

### Compatibility

- This pre-1.0 release intentionally changes the public Rust library surface:
  fail-open helpers and constants are removed, `Indeterminate` decisions are
  explicit, and evaluator/simulation results carry new provenance and shell
  dialect fields. Embedders must update exhaustive matches and struct literals.
  No compatibility shim is retained because preserving fail-open semantics
  would undermine the security correction in this release.

### Security

- **Treat every local branch ref deletion or force-update as an approval
  boundary (#209).** Semantic Git parsing now covers `branch -d`, `--delete`,
  `-D`, `-f`, `-M`, and `-C`, including aliases, shell wrappers, PowerShell and
  Cmd syntax, and configuration-defined shell functions. Quoted alias
  arguments and unresolved forwarded parameters fail closed without
  misclassifying `--format -d` as a deletion.
- **Protect every recursive `rm`, not only forced forms (#211).** `rm -r`,
  `rm -R`, and `rm --recursive` now receive the same bounded target analysis as
  `rm -rf`; interactive `-i`/`-I`, literal temp subdirectories, option ordering,
  multiple targets, redirections, relocations, and shell-specific decoding are
  handled semantically. Contributor PR #219 was mined for its report and
  regression ideas; the broader semantic implementation was developed
  independently.
- Recursive-rm option ordering is evaluated under both GNU permutation and
  Apple/BSD stop-at-first-operand semantics. A trailing `-i`, `--help`, or
  `--version` can no longer appear to cancel deletion on Linux while remaining
  a plain path operand after an already-recursive target on macOS.
- **Decode executable ANSI-C, hex, and shell-specific command spellings before
  keyword gating (#217).** Caller-proven Bash, PowerShell, and Cmd syntax can no
  longer hide protected executables from the fast path, while quoted data stays
  inert. Contributor PR #220 was mined for its bypass example and tests; the
  role-aware multi-shell implementation was developed independently.
- **Make automatically discovered project configuration enforcement-only
  (#218).** An untrusted checkout may add packs, denies, fail-closed behavior,
  or stricter heredoc policy, but cannot disable protection, add allow rules,
  load repository code/config paths, raise resource limits, or override the
  user's agent profiles. `DCG_CONFIG=.dcg.toml` remains the explicit reviewed
  opt-in to full project configuration. Unix discovery now performs a bounded
  same-descriptor read of a direct regular file and rejects symlinks, FIFOs,
  devices, and path-identity races; native Windows discovery fails closed until
  equivalent reparse-point and file-identity validation is available. Untrusted
  parse diagnostics never echo repository-controlled source lines.
- Harden PowerShell/Cmd semantic boundaries: visible aliases preserve target
  spelling, ScriptBlock consumers and control-flow bodies are recursively
  evaluated, static call expressions retain executable/data roles, indexed or
  dynamic call targets fail closed where necessary, and a proven non-filesystem
  command is never reinterpreted by context-free deletion regexes.
- Parse PowerShell here-strings as atomic values without letting interior quote
  characters hide later statements; honor the binder's exact ASCII/en-dash,
  em-dash, and horizontal-bar parameter prefixes, unambiguous abbreviations,
  switch aliases, and explicit Boolean switch values.
- **Block recursive PowerShell deletion even without `-Force`.** `Remove-Item
  -Recurse` and its aliases now map to the critical `remove-item-recurse` rule;
  `-Force` only broadens which items are removed. Proven `-WhatIf` previews
  remain allowed, while dynamic binding fails closed and statically invalid or
  ambiguous parameters preserve PowerShell's pre-execution error behavior.
- Close adjacent embedded-code bypasses in quoted heredocs, indentation-stripped
  heredocs, executable-text sinks, dynamically rebound stdin data sinks, and
  dynamically selected Wrangler scripts.
- Precompile the bounded Perl fallback patterns when constructing the AST
  matcher. Their one-time regex compilation can no longer consume the
  per-match budget and make the first Perl heredoc scan time out before any
  safety analysis runs.
- **Keep data-only arguments masked after shell control-flow words (#221).**
  Unquoted `if`, `then`, `elif`, `else`, `while`, `until`, `do`, `{`, and `!`
  now introduce the following executable instead of occupying its command slot,
  preventing quoted `printf` arrows from being misread as redirects. Real
  redirect operators and explicitly selected executables named like reserved
  words remain visible.

### Packs

- **Add complete modern Snowflake CLI protection (#212).** `snow sql` inline
  queries, stdin, local files, nested `!source` graphs, templating, comments,
  directives, DDL, unbounded and bounded DML, stages, tasks, pipes, warehouses,
  shares, and privilege changes are parsed with explicit byte/token/depth/file
  bounds. Dynamic or ambiguous sources fail closed.
- Snowflake evaluation retains every guarded statement in deterministic source
  order with exact payload spans and bounded previews. Denials summarize all
  findings; allowlisting the highest-severity statement cannot hide another
  guarded statement later in the same payload, and reports over 512 findings
  fail closed rather than truncate.
- Snowflake CLI commands larger than the semantic parser's 64 KiB defensive
  bound now fail closed even when an operator raises the hook's outer command
  limit; bounded analysis can no longer become an implicit no-match decision.
- A proven database client now owns its embedded payload's rule attribution.
  In particular, generic PostgreSQL patterns can no longer preempt Snowflake's
  statement spans and recovery guidance, or re-block a Snowflake rule that was
  explicitly reviewed and allowlisted.
- **Recognize current Wrangler v4 KV deletion syntax (#210).** Both
  `wrangler kv namespace delete` and legacy colon syntax are covered, including
  Bun/npm/npx wrappers and dynamically selected scripts that cannot be proven
  safe.

### Reliability and diagnostics

- **Deadline exhaustion is never a silent allow (#213).** Evaluation now
  returns an explicit indeterminate decision; review-capable protocols receive
  `ask`, while protocols without that state receive their documented blocking
  response. The timeout is configurable with `general.hook_timeout_ms` or
  `DCG_HOOK_TIMEOUT_MS` and retains a defensive minimum.
- Indeterminate hook responses are written and flushed before best-effort
  history is queued; the history worker is then detached, and deadline paths
  avoid synchronous file diagnostics. A slow audit sink can no longer delay
  process exit after the safety budget is exhausted.
- Explain, trace, corpus, batch, and hook output now carry exact quick-reject
  provenance from the evaluator instead of inferring it from an empty match.
  A slow full evaluation or deadline stop can no longer be mislabeled
  `quick-rejected`.
- Quick-reject word boundaries no longer treat filenames such as `.gitignore`
  as Git commands. Heredoc masking, trace schemas, suggestion registration,
  performance-contract documentation, and cross-platform launcher tests are
  synchronized with the implementation.
- Caller-proven shell decoding no longer rebuilds Git regex input from the raw
  command after role-aware sanitization. Commit messages and other inert argv
  data remain masked even when the Git executable uses Bash, PowerShell, or Cmd
  obfuscation, while the raw source still drives semantic executable analysis.
- Heredoc raw-shell masking conservatively leaves an unknown future body form
  unmasked instead of panicking inside the hook.

### Windows installer

- **Complete the WDAC/AppLocker ConstrainedLanguage path (#194).** Native
  version and verification probes now capture stdout/stderr under Windows
  PowerShell 5.1 without promoting DCG's intentional diagnostics into a
  terminating `NativeCommandError`, while retaining exit-code and strict-error
  checks. Release acceptance requires the public installer to succeed from a
  separately downloaded unsigned script in a forced Windows PowerShell 5.1
  ConstrainedLanguage session on a real Windows host. This validates the
  restricted-language behavior without claiming that the host enforces UMCI.

### Dependencies

- Update `fsqlite`, `fsqlite-types`, and `fsqlite-error` from 0.1.16 to
  0.1.17 so DCG's optional history store inherits FrankenSQLite's latest
  corruption-recovery and transaction-cleanup hardening.
- Incorporate Dependabot PR #214, merged directly on `main` before this
  release: update `clap` and `clap_builder` from 4.6.1/4.6.0 to 4.6.2 in both
  the root and fuzz lockfiles, with independent locked-build and regression
  verification.

### Release integrity

- Release all six target archives manually outside GitHub Actions, including
  Windows ARM64. Publish the exact 52-asset contract with SHA-256 manifests,
  minisign signatures, DSR SLSA provenance, and an SPDX SBOM; verify the public
  installers on Linux x86_64, macOS ARM64 and Intel/Rosetta, and Windows x64,
  with Linux ARM64 exercised under QEMU and Windows ARM64 machine type checked.
  Publish the independently packaged and smoke-tested crate to crates.io so the
  composite action's documented Cargo fallback resolves the same release.

## [v0.6.8](https://github.com/Dicklesworthstone/destructive_command_guard/tree/v0.6.8) -- 2026-07-15 [Tag]

Annotated source tag only. No GitHub Release or binary assets were published;
v0.6.9 supersedes it.

Windows installer correctness hotfix that completes the real-host
ConstrainedLanguage path begun in v0.6.7.

### Fixed

- **Make the mandatory installed-version assertion and optional `-Verify`
  self-test work in Windows PowerShell 5.1 ConstrainedLanguage (#194).** The
  installer now captures native `dcg --version` and `dcg test` output under a
  narrowly scoped non-terminating error preference, restores the caller's
  preference, and judges each probe by its documented process exit code. This
  preserves strict error handling while preventing DCG's intentional human
  diagnostics on stderr from being promoted to a terminating
  `NativeCommandError` under the installer's script-wide
  `$ErrorActionPreference = 'Stop'`.
- Extend the Windows PowerShell 5.1 forced-ConstrainedLanguage integration test
  with native commands that exercise successful version capture, a failing
  version probe, and both allow/deny self-test outcomes while emitting
  diagnostics on stderr. The regression now covers the exact stream behavior
  that v0.6.7's function-level installer tests missed.
- Advance the composite GitHub Action examples and its transient API-failure
  fallback to v0.6.8 so an unavailable latest-release endpoint cannot select
  the superseded installer.
- Make the real Codex E2E harness explicitly trust its freshly generated,
  hermetic DCG hook for automation. Codex 0.144.x otherwise skips untrusted
  one-shot hook paths, which made the harness run destructive fixture commands
  without exercising DCG even though direct protocol tests passed. The harness
  now pins both `HOME` and `CODEX_HOME` to that generated configuration, accepts
  hook-status markers only from Codex stderr, and aborts before issuing any
  destructive prompt unless the initial safe-command trust handshake succeeds.
- Refresh the scan regression golden for the six legitimate PostgreSQL and
  Docker findings now emitted by the current default packs. The harness now
  compares the complete normalized deterministic scan contract rather than
  only counts and a sorted rule-ID multiset.
- Make the shell E2E suite use the same generous test-only hook deadline as the
  Rust E2E helpers. Functional rule assertions are now deterministic under
  scheduler pressure while the dedicated performance tests continue to enforce
  the production 200 ms fail-open budget.

### Dependencies

- Update `toml` to 1.1.3, `toml_edit` to 0.25.13, and `toml_writer` to 1.1.2
  for the upstream writer-overflow fix. Update the dev-only `which` dependency
  to 8.0.5. The root lock uses the independently resolved minimal four-package
  update and excludes PR #208's unrelated edge rebindings. The previously stale
  fuzz lock is refreshed from its v0.4.5-era graph and aligned to the gated root
  dependency versions so full locked fuzz metadata succeeds.

### Release integrity

- The planned six-platform binary build and manual artifact publication were
  superseded before execution. No v0.6.8 GitHub Release or binary assets were
  published; the source fixes and release-integrity plan first ship in v0.6.9.

## [v0.6.7](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.6.7) -- 2026-07-14 [Release]

Security and correctness release with Windows-policy compatibility groundwork.
This closes the stdin-driven database-client bypass class, blocks force-refspec
pushes, repairs project allowlists outside Git repositories, fixes two
command-line false positives, and adds the checksum, signature, archive, and
encoding primitives needed by the Windows installer under WDAC/AppLocker
ConstrainedLanguage. Its final PowerShell 5.1 native-output captures are
corrected in the unpublished v0.6.8 source tag and first shipped in v0.6.9.

### Security

- **Trace indirect input into protected database clients (#191).** Bounded
  literal `echo`/`printf` and single-file `cat` pipelines, grouped/subshell
  consumers, redirects (including prefix and inherited `exec` forms), heredocs,
  Redis `--pipe`, and command substitutions are reconstructed and evaluated against the
  consumer pack for Redis-compatible clients, PostgreSQL, MySQL/MariaDB,
  MongoDB, and SQLite. Unknown or dynamic producers, unsafe files, invalid
  encodings, and oversized payloads fail closed under the stable
  `<pack>:stdin-unverified` rule. File inspection rejects symlinks and special
  files and uses nonblocking/no-follow opens on Unix. Multi-command producers
  cannot masquerade as one literal producer.
- **Parse kubectl dry-run semantics instead of guessing with regex.**
  `kubectl delete -f -` is blocked unless the final effective `--dry-run`
  value is provably bare/client/server/true. Repeated, separated, quoted,
  escaped, dynamic, and post-`--` arguments follow pflag ordering without a
  safe-then-unsafe override bypass.
- **Block Git's leading-plus force refspec syntax in strict mode (#202).**
  Arbitrary `+<refspec>` pushes now hit `push-force-any`, including quoted,
  escaped, ANSI-C-quoted, direct `+main`/`+master`, and
  `+HEAD:refs/heads/main` forms. Brace/glob/dynamic refspecs fail closed, and
  `git push --mirror` is explicitly blocked because it force-updates and
  deletes remote refs.
- **Evaluate GNU sed shell-execution programs semantically.** Inert
  substitutions remain maskable data, while the `e` command and `s///e` flag
  feed their literal shell command back through the normal evaluator.
  Input-dependent executable replacements fail closed under
  `core.filesystem:sed-exec-unverified`; sandboxed sed invocations remain
  allowed only when `--sandbox` is an active option rather than an operand
  after `--`. `-f` programs are inspected with option arity respected, while
  compound-command program files fail closed against mutation races.
- **Remove attacker-controlled temp-root whitelists.** Only static paths under
  literal `/tmp` and `/var/tmp` qualify for automatic POSIX safety; `$TMPDIR`,
  `${TMPDIR:-...}`, substitutions, escaped traversal, and dynamic suffixes
  require review. The same fail-closed rule covers redirects and moves.
  Absolute `truncate` sizes now block because they may shrink at runtime, and
  only the final effective `dd of=` operand determines safety. Windows
  recursive-delete temp whitelisting was removed because ambient `%TEMP%` and
  multi-target commands could otherwise shadow a destructive target.

### Fixed

- **Make project allowlists effective outside Git repositories (#199).** The
  repository root remains authoritative inside Git. Elsewhere, the nearest
  ancestor containing `.dcg/allowlist.toml` governs nested directories, and a
  new scope starts in the current directory when no such ancestor exists.
  Read, list, and write operations now share that resolver.
- **Allow literal double-quoted `/tmp/` and `/var/tmp/` recursive deletes
  (#201).** Quoted paths now have parity with their unquoted equivalents while
  traversal, expansion, brace, quote-concatenation, and escape tricks remain
  blocked.
- **Stop inert sed substitutions from looking like shell redirects (#198).**
  Only a single non-executing, non-writing substitution is masked; arbitrary
  sed programs, `e`, `s///e`, and `s///w` remain visible to the guard.
- **Treat `n` as false for display/mode environment flags (#203).**
  `DCG_NO_COLOR=n`, `DCG_ROBOT=n`, and related flags now match the documented
  boolean parser.
- Thread the active hook deadline through the final pack-evaluation pass
  instead of accidentally dropping it.

### Windows installer

- **Support WDAC/AppLocker ConstrainedLanguage installs and updates (#194).**
  The installer falls back from `Get-FileHash` to signed inbox
  `certutil.exe`, uses trusted `tar.exe` for zip inspection/extraction, emits
  UTF-8 without a BOM using primitive operations, and avoids blocked .NET
  helpers for URL, PATH, architecture, and configuration handling. Real-host
  release validation subsequently found that the final `dcg --version` capture
  and optional `-Verify` self-test still tripped PowerShell 5.1's native-stderr
  promotion under `$ErrorActionPreference = 'Stop'`; v0.6.9 fixes both native
  capture paths.

### Release integrity

- **Authenticate manually published artifacts with a long-lived minisign trust
  root.** Both installers verify an adjacent `.minisig` when the external
  `minisign` executable is available, always abort on an invalid signature,
  and offer `--require-minisign` / `-RequireMinisign` for fail-closed installs.
  Offline artifact/signature URL overrides are covered by the installer test
  suites. Version selection now requires an exact SemVer tag, downloaded
  archives must contain exactly one root-level binary, and installer self-tests
  prove that the installed binary reports the requested version.
- The six-platform release is built outside GitHub Actions, packaged
  reproducibly, checksummed, signed with DSR's minisign key, and accompanied by
  an SPDX SBOM plus signed SLSA provenance statements. Sigstore bundles are not
  claimed for these manual builds because no Actions OIDC identity is involved.

### Dependencies

- Upgrade FrankenSQLite to 0.1.16 (including atomic commit-marker recovery),
  `self_update` to 1.0.0-rc.5, and the current compatible regex/memchr stack.
  `cargo audit` reports no known dependency vulnerabilities; cargo-deny's
  advisory, bans, and source checks also pass (the repository does not yet
  define a license-policy configuration).

## [v0.6.6](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.6.6) -- 2026-07-13 [Release]

Security and correctness release. Closes a critical, attacker-triggerable
guard-bypass (an exponential-time hang in command-substitution preprocessing),
enforces path-scoped allowlists across every evaluation entrypoint, lands
hook-protocol correctness fixes for Codex, GitHub Copilot CLI, and VS Code
Copilot Chat, and adds heredoc/pack false-positive fixes plus a dependency
refresh.

### Security

- **Fix an exponential-time hang in command-substitution preprocessing that let
  a destructive command bypass the guard (#189).** A ~90-byte payload of a
  destructive command followed by ~30 unterminated `$(` drove
  `split_command_segments` into 2^n re-scans, hanging `dcg` far past its 200 ms
  hook budget; because agents fail open on a hung hook, the destructive command
  then executed. The command-substitution scanners now propagate an
  unterminated nested construct instead of rescanning the suffix per opener
  (2^n → linear, output-equivalent on well-formed input), and the matching
  blowup in the `$((` arithmetic/command-substitution disambiguation is closed
  too. `$(`, `<(`, `>(`, and `$((` openers are all bounded; a payload that
  previously hung now blocks in well under a millisecond.
- **Enforce path-scoped allowlists across all evaluation entrypoints (#186).**
  `paths = [...]` allowlist entries were silently applied globally whenever no
  heredoc content-allowlist project was configured, because the shared project
  path resolved to `None` and path-aware matchers skip path checks on `None`.
  The explicit working directory is now authoritative regardless of heredoc
  config, and the hook, `dcg test`, `dcg hook --batch`, and `dcg classify` all
  thread the real cwd; the heredoc-AST allowlist branches use the path-scoped
  matcher.

### Fixed

- **Restore enforcement on Codex CLI 0.144.x for native Windows (#183).** Codex
  denials now use its accepted minimal three-field `hookSpecificOutput` JSON
  with exit code 0. The previous exit-code-2 contract is collapsed to exit 1 by
  Codex's PowerShell wrapper, which Codex classifies as hook failure and then
  fails open. The new response is strict-parser-safe and retains the full
  operator explanation on stderr.
- **Honor GitHub Copilot CLI's native camelCase `preToolUse` protocol (#182).**
  Copilot responses now contain exactly its documented top-level
  `permissionDecision` and `permissionDecisionReason` fields, without legacy
  control or dcg-only metadata that caused the decision to be discarded. Unix
  and PowerShell installers now write a user-level hook under
  `${COPILOT_HOME:-~/.copilot}/hooks`, protecting every workspace; uninstallers
  remove that hook while preserving coexisting entries and also clean the
  legacy repo-local hook when present.
- **Protect VS Code Copilot Chat terminal tools (#184).** `runTerminalCommand`,
  `run_in_terminal`, and `runInTerminal` now route through the
  Claude-compatible deny protocol and read `tool_input.command`, covering both
  the documented and observed VS Code payload names.
- **Treat `spx session handoff` heredocs as structured stdin data (#181).** The
  narrowly-scoped, line-bounded sink masks handoff prose without masking other
  `spx` subcommands or commands after the heredoc terminator.
- **Stop inert prose in quoted no-op-builtin heredocs from tripping git/
  filesystem rules (#181).** `true <<'EOF' … EOF` and `: <<'EOF' … EOF` (the
  shell block-comment idiom) now have their bodies masked as data — but only for
  quoted delimiters, which suppress expansion. An unquoted delimiter still
  expands command substitutions, so those keep flowing through pack matching (no
  false negative), and commands after the terminator are unaffected.
- **Render pack styling and separate the legend in `dcg packs` (#187, #188).**
  Styled tree labels are parsed through `rich_rust`'s markup renderer instead of
  being emitted as literal `[bold]`/`[dim]`/`[green]` tags; unstyled labels keep
  literal brackets. The legend and config hint move out of the tree hierarchy
  into a footer beneath it.
- **Correct the dcg skill's missing-binary install guidance (#185).** All five
  managed skill copies now point to this repository and the working easy-mode
  installer instead of the nonexistent `anthropics/destructive-command-guard`
  URL; the public skill manifest checksum was refreshed and validated.
- **Keep catastrophic JavaScript deletes blocking under contention.** A
  lexer-aware pre-AST backstop catches literal `fs.rmSync()` calls targeting
  catastrophic paths before the bounded AST worker can fail open, while
  ignoring comments, template text, and non-catastrophic targets.

### Security and maintenance

- Upgrade `self_update` to `1.0.0-rc.4` and narrow `rich_rust` to the Markdown
  feature, removing the obsolete syntax-parser dependency stack while retaining
  dcg's purpose-built regex highlighter. `cargo audit` reports no known
  vulnerabilities.
- Make AST-heavy protocol tests deterministic on saturated CI hosts without
  changing the production 20 ms fail-open ceiling, and expand the platform
  backtracking audit plus PowerShell/batch extractor documentation sentinels.

### Documentation

- **Correct the modular-pack docs (#187, #190).** README, `docs/agents.md`, and
  `docs/configuration.md` now use real pack/category IDs and document that a
  category ID (e.g. `database`) expands to all its sub-packs, including in
  agent-profile `extra_packs`/`disabled_packs`; the bogus
  `extra_packs = ["paranoid"]` / `["core","database","filesystem"]` examples are
  replaced, and `"paranoid"` is clarified as a graduation mode, not a pack.
- **Document the stdin/pipe/redirection REPL bypass as a known limitation
  (#191).** A destructive payload reaching a stdin-driven REPL binary
  (`redis-cli`/`psql`/`mysql`/`mongosh`/`sqlite3`) via a pipe, `<` redirection,
  or command substitution used as an argument is not yet traced (direct args and
  here-strings are still blocked); a data-flow-aware fix is tracked separately.

## [v0.6.5](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.6.5) -- 2026-07-02 [Release]

Security re-release of v0.6.4 with correct per-architecture binaries. No code
changes from v0.6.4 — this exists solely to publish a correctly-packaged
release through the CI pipeline.

### Fixed

- **Cross-architecture release binaries are now built for the correct target
  (#174).** The `v0.6.4` `dist` build installed the cross-target std against the
  floating `@nightly` toolchain instead of the `nightly-2026-06-06` pinned in
  `rust-toolchain.toml`, so the two cross-std targets
  (`x86_64-unknown-linux-musl`, `aarch64-pc-windows-msvc`) failed to build with
  `error[E0463]: can't find crate for core`. Because `release` needs `build`,
  that skipped the GitHub-Actions publish and forced an out-of-band fallback
  that shipped **wrong-arch binaries**: the `aarch64-unknown-linux-gnu` tarball
  carried an x86-64 ELF and the `x86_64-apple-darwin` tarball carried an arm64
  Mach-O. On `aarch64` Linux the installed guard could not execute
  (`Exec format error`), and because Claude Code hooks are fail-open by design,
  the guard was silently dead while appearing installed — every destructive
  command was permitted with no visible error. The toolchain install now pins
  `nightly-2026-06-06` and adds the target std to it, so all six targets build
  on native runners and publish through CI. Explicit per-target arch-verify
  gates (`file` / `objdump -T`) already guard against a recurrence.

## [v0.6.4](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.6.4) -- 2026-06-27 [Release]

Toolchain-pin release; superseded by v0.6.5 (its cross-arch tarballs were
mispackaged — see #174 above).

### Changed

- **Pin the toolchain to `nightly-2026-06-06`.** Bare `nightly` could no longer
  compile `rustix 1.1.4`, which had shipped v0.6.3 as Windows-only and broke
  fresh installs on newer distros. Restores the full platform set and bundles
  the 18-issue CLI/hook audit, the #160 fail-closed hardening
  (BOM-strip + opt-in `DCG_FAIL_CLOSED` + protocol-aware denial + oversized-input
  handling), and #151/#150/#155.

## [v0.6.3](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.6.3) -- 2026-06-25 [Release]

Patch release for Windows command normalization coverage.

### Fixed

- **Block wrapper flag-value command substitutions.** `env` and `sudo` wrapper
  normalization no longer strips option values that contain command/process
  substitutions, preserving destructive payloads for detection.
- **Normalize quoted Windows binary paths with backslashes.** Quoted paths such
  as `"C:\Program Files\Git\bin\git.exe" reset --hard` now normalize to the
  `git` command instead of being mangled by escape handling.
- **Tighten quick-reject keyword coverage.** Windows uppercase destructive
  aliases and Redis-compatible `valkey-cli` / `keydb-cli` commands now reach the
  destructive pattern matchers instead of being skipped by the fast path.

## [v0.6.2](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.6.2) -- 2026-06-25 [Release]

Patch release for the native-Windows installer.

### Fixed

- **Fix checksum resolution on Windows PowerShell 5.1.** GitHub release
  sidecars such as `dcg-x86_64-pc-windows-msvc.zip.sha256` can be returned by
  `Invoke-WebRequest` as `byte[]` when uploaded as octet-stream assets. The
  installer now decodes byte-array checksum content as UTF-8 before parsing,
  so the pinned one-liner verifies and installs the Windows zip correctly.

## [v0.6.1](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.6.1) -- 2026-06-25 [Release]

Patch release candidate for the native-Windows launch, superseding the
unpublished `v0.6.0` tag.

### Fixed

- **Close an inline-script extraction under-block.** Interpreter wrapper flags
  whose values are not simple barewords (`python -W ignore::... -c`, `node
  --max-old-space-size 4096 -e`, `bash --rcfile /path -c`, PowerShell
  `-Version 5.1 -Command`, and attached Perl flags like `-MFile::Spec`) are now
  skipped correctly before extracting the dangerous inline script payload.
- **Refresh Windows release docs.** README and `docs/windows.md` now describe
  Windows x64 + ARM64 artifacts, the ARM64-to-x64 fallback for older releases,
  the Windows Cursor PowerShell bridge, and the full PowerShell uninstall hook
  coverage.

## [v0.6.0](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.6.0) -- 2026-06-24 [Tag]

Native Windows support, PowerShell installer automation, Windows release
artifacts, heredoc data-sink masking for `git` stdin targets, plus a soundness
fix to heredoc target resolution.

### Added

- **Native-Windows destructive-command protection.** New `windows.filesystem`
  and `windows.system` packs are **on by default on Windows** — blocking cmd
  `del /s`, `rd /s`, `format <drive>:`, PowerShell `Remove-Item -Recurse -Force`
  (and aliases), `Clear-Content`/`Clear-RecycleBin`, plus `vssadmin delete
  shadows` / `wmic shadowcopy delete` (Volume Shadow Copy destruction),
  `diskpart`, `Format-Volume`, `Clear-Disk`, `cipher /w`, and `bcdedit /delete`.
  Opt-in `windows.misc` (`reg delete`, `net user /delete`, `wsl --unregister`,
  `robocopy /MIR`) and `windows.powershell` (registry/provider deletes,
  `Remove-LocalUser`, `Disable-ComputerRestore`, `Remove-VM`, …) packs round out
  coverage. All patterns are case-insensitive.
- **Windows-aware engine + scan.** Command normalization handles drive-letter
  paths (`C:\Windows\System32\del.exe`) and case-insensitive verbs; `dcg scan`
  now extracts commands from PowerShell (`.ps1`/`.psm1`/`.psd1`) and batch
  (`.cmd`/`.bat`) scripts.
- **Windows install one-liner + docs.** README gains the PowerShell
  `& ([scriptblock]::Create((irm ".../install.ps1"))) -EasyMode -Verify`
  installer; new [`docs/windows.md`](docs/windows.md) documents Windows behavior,
  paths (`%ProgramData%\dcg` system layer), and limitations.
- **Windows CI.** A `check (windows)` job (clippy + full test suite on
  `windows-latest`, nightly/MSVC) now guards against Windows regressions.

### Fixed

- **Stop false positives on `git` commit/object messages read from stdin (#136,
  data-sink half).** `git commit -F -`, `git commit --file=-` / `--file -` /
  `-F-`, and `git hash-object --stdin` consume the heredoc body as *data* (a
  commit/tag/note message or object content) that git never executes as shell.
  Their heredoc body is now masked out of the raw-shell rescan exactly like
  `cat`/`tee` (#109), so a commit message that merely contains "restore" or
  "reset --hard" no longer trips the `core.git:*` rules. The unsound
  interpreter-stdin case (`python3 -`/`node -`, whose body *is* executed) remains
  deliberately unmasked.
- **Soundness: heredoc target resolution is now bounded to the heredoc's own
  physical line.** `tokenize_backwards` does not treat newlines as command
  boundaries, so an unbounded backward scan could resolve a data-sink target (or
  the new git stdin sentinel) from an *earlier* line and mask a *later*,
  genuinely-executing heredoc body — e.g. `cat f\nbash <<EOF\nrm -rf /\nEOF` or
  `git commit -F - f\nbash <<EOF\nrm -rf /\nEOF` were wrongly allowed. Both
  `extract_heredoc_target_command` and the new `is_git_stdin_data_sink` now scan
  only the heredoc operator's own line. This closes a false negative (the
  conservative direction: at worst a false positive, never a missed destructive
  command). Found via adversarial review.

## [v0.5.6](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.5.6) -- 2026-05-26 [Release]

Registry-clean release of the v0.5.5 history-FTS fix.

### Dependencies

- **Switched `fsqlite`/`fsqlite-types`/`fsqlite-error` from the v0.5.5 git revision
  to the published `fsqlite 0.1.4`** ([frankensqlite#94](https://github.com/Dicklesworthstone/frankensqlite/issues/94)),
  which carries the FTS5 live-vtab DELETE fix. No code change vs v0.5.5 — same fix,
  now from crates.io.
- Because the dependency is no longer a git revision, **v0.5.6 is published to
  crates.io** (`destructive_command_guard = "0.5.6"`), restoring registry installs
  with the FTS-rebuild fix included.

---

## [v0.5.5](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.5.5) -- 2026-05-26 [Release]

Fixes the history full-text-search rebuild, which was broken by an upstream
FrankenSQLite bug.

### History FTS

- **`rebuild_fts` / FTS-backed history no longer raise `Sqlite(PrimaryKeyViolation)`.**
  FrankenSQLite did not intercept `DELETE` against a live FTS5 virtual table: the
  generic table-delete emptied the backing B-tree but left the in-memory FTS5
  module instance stale, so the `DELETE FROM commands_fts; <re-INSERT>` rebuild
  pattern collided on re-insert of the same rowid. Fixed upstream in
  [frankensqlite#94](https://github.com/Dicklesworthstone/frankensqlite/issues/94)
  (commit `a0425adb` — live virtual-table DELETE now routes through the module's
  per-row `xUpdate` delete, matching SQLite). dcg pins that fix via a git rev of
  `fsqlite`/`fsqlite-types`/`fsqlite-error`. The three previously-failing
  `history::schema` FTS tests now pass.

### Packaging note

- This release is distributed as **GitHub-release binaries** (the primary install
  path). Because it pins FrankenSQLite to a git revision pending an `fsqlite`
  crates.io release, **v0.5.5 is not published to crates.io**; the registry stays
  at v0.5.4 for the guard feature (the FTS-rebuild fix lands there once `fsqlite`
  publishes the fix).

---

## [v0.5.4](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.5.4) -- 2026-05-25 [crates.io only — no GitHub binaries]

Published to **crates.io** (first registry publish of the 0.5.x line since
v0.4.5), but the GitHub-release binaries did **not** ship: the `dist` run was
blocked first by `cargo fmt`/clippy and then by the FrankenSQLite FTS5 bug above.
GitHub binaries resume at v0.5.5.

First successful release and crates.io publish of the 0.5.x line since v0.4.5:
v0.5.0–v0.5.2 were cut as GitHub releases but never published to the registry,
and v0.5.3's `dist` run failed at `cargo fmt --check`, so it shipped nothing.
v0.5.4 carries the v0.5.3 fixes forward and adds the items below. Closes
[#126](https://github.com/Dicklesworthstone/destructive_command_guard/issues/126).

### Codex on Windows

- **dcg now descends into `powershell -Command` / `pwsh -c` inline scripts** ([#125](https://github.com/Dicklesworthstone/destructive_command_guard/issues/125)).
  Codex on Windows executes shell commands via `powershell.exe -Command '<cmd>'`.
  dcg previously unwrapped only `bash -c` / `sh -c`, so a destructive command
  inside the PowerShell wrapper reached the shell unevaluated. The inline-script
  extractor now unwraps `powershell` / `pwsh` — including the quoted full-path
  `"C:\…\powershell.exe" -Command '…'` form and the `-c` abbreviation — and
  re-evaluates the inner command against every pack. Note: whether Codex on
  Windows actually *fires* the PreToolUse hook for its `command_execution` event
  is Codex-side behavior; this change guarantees that once a wrapped command
  reaches dcg, it is caught.
- **`uninstall.ps1` also writes `hooks.json` as UTF-8 without a BOM**, matching
  the `install.ps1` fix; both installer and uninstaller now preserve array-ness
  when reading an existing hook config.

### Installer

- **`install.sh` installs shell completions for the invoking user, not root,
  when run under `sudo`** — completions land in the caller's config directories.

### Tests

- Added an end-to-end regression test for the [#124](https://github.com/Dicklesworthstone/destructive_command_guard/issues/124)
  multi-line `git commit -m "…git push --force…"` body case, and dropped an
  overclaimed pack-level assertion that cannot hold at the raw-regex layer
  (documented inline) — the multi-line body is defended by `-m` masking in the
  full `evaluate_command` pipeline, not by `pack.check()`.

### Packaging

- Slimmed the published crate via `exclude` (drops `.ntm/`, `*.png`, `*.webp`,
  `agent_baseline/`, `action/`). Source and binary are unaffected.

---

## [v0.5.3](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.5.3) -- 2026-05-23 [Tag]

### Pattern false-positive fixes

- **`push-force-{long,short}` no longer fires across shell-token boundaries** ([#124](https://github.com/Dicklesworthstone/destructive_command_guard/issues/124)).
  The walker `(?:\S+\s+)*` between `git`/`push` and the force flag matched
  `\S` greedily, which includes shell metacharacters (`&;|`()<>` plus
  backticks). That meant `git commit -m "...git push --force..."`,
  here-doc bodies, `&&`-chained `echo` lines, and `git log --grep='git
  push --force'` all tripped the Critical rule — and dcg refused the
  entire command. Switched both regexes to the bounded form already
  used by `branch-force-delete` since [#121](https://github.com/Dicklesworthstone/destructive_command_guard/issues/121):
  `(?:[^\s&;|`()<>]+\s+)*`. Added five regression cases covering the
  shell-boundary scenarios.

### Codex on Windows

- **`install.ps1` now writes `hooks.json` as UTF-8 without the BOM** ([#125](https://github.com/Dicklesworthstone/destructive_command_guard/issues/125)).
  The previous `Set-Content -Encoding UTF8` on Windows PowerShell 5.1
  (the default on Win10/Win11) prepended a UTF-8 BOM that Codex Desktop
  rejected with `expected value at line 1 column 1`. The hook installed
  cleanly, appeared in the Codex UI, and silently did nothing. Switched
  both write paths to `[System.IO.File]::WriteAllText` with
  `System.Text.UTF8Encoding $false` — works identically on PS 5.1 and
  PS 6/7+ without the PS6-only `-Encoding UTF8NoBOM`.

### crates.io

- **Intended as the first crates.io publish since v0.4.5 — but the `dist` run
  for v0.5.3 failed at `cargo fmt --check`, so no binaries or crate were
  published.** Superseded by v0.5.4, which completes the publish ([#126](https://github.com/Dicklesworthstone/destructive_command_guard/issues/126)).

---

## [Unreleased] (after v0.5.1)

### Agent support

- **Grok (xAI) protocol added as a first-class agent and hook target.**
  dcg now detects Grok CLI / Grok Build TUI and emits its native JSON wire
  shape so blocking actually sticks when Grok invokes shell tools.
  - **Detection.** Grok is recognised by any of three environment variables
    (`GROK_SESSION_ID`, `GROK_HOOK_EVENT`, `GROK_WORKSPACE_ROOT`) and by
    parent-process basename (`grok`, `grok-cli`, `grok-build`). The hook
    protocol is auto-selected when stdin carries `hookEventName: "pre_tool_use"`
    or `toolName: "run_terminal_cmd"`, with explicit guards so the
    Hermes (`pre_tool_call`) and Copilot (`event` / `tool_args`) markers
    still win on their own payloads.
  - **Wire shape.** Denies emit `{"decision":"deny","reason":"…", …}` on
    stdout — *not* Hermes' `"block"`. Allows are empty stdout + exit 0.
    Warns become explicit `{"decision":"allow","reason":"DCG warn: …"}`
    so Grok logs the advisory without escalating to a block.
  - **Installer.** `dcg install --grok` writes a self-contained
    `~/.grok/hooks/dcg.json` (`PreToolUse` / `matcher: "Bash"`, which Grok
    internally aliases to `run_terminal_cmd`). `--grok --project` writes
    `<repo>/.grok/hooks/dcg.json` for per-repo installs. Grok also picks dcg
    up via the existing `~/.claude/settings.json` compatibility layer, so
    users who already ran `dcg install` get protection with no further
    action.
  - **Doctor.** `dcg doctor` adds a "Checking Grok hook registration…" line
    when a `.grok/` directory or `GROK_*` env var is present. `dcg doctor
    --fix` will write the native hook for you if it's missing. The check is
    silent on hosts that have never had Grok installed, to avoid noise.
  - **Tests.** Eight new protocol-detection tests plus full
    denial/warning JSON-shape assertions in `hook::tests`, three new env
    detection tests in `agent::env_tests`, and CLI parse coverage for
    `--grok`/`--grok --project`. Closes the contribution proposals in
    [#117](https://github.com/Dicklesworthstone/destructive_command_guard/pull/117)
    and [#118](https://github.com/Dicklesworthstone/destructive_command_guard/pull/118)
    by reimplementing the feature independently, including the corrected
    user-level hook path (`~/.grok/hooks/dcg.json`, not `~/.grok/settings.json`)
    and the correct block keyword (`"deny"`, not `"block"`).

### Release-engineering fixes

- **Linux x86_64 now ships as static musl** ([#114](https://github.com/Dicklesworthstone/destructive_command_guard/issues/114)).
  Previous releases linked against the build runner's glibc and required
  GLIBC ≥ 2.39 on the host, which blocked Ubuntu 22.04 LTS and any
  long-support distro. The dist matrix now uses `x86_64-unknown-linux-musl`
  with the `rustls` feature on `self_update` so OpenSSL isn't dragged in,
  plus an `objdump -T | grep GLIBC_` post-build check that fails the
  release if the binary unexpectedly re-acquires glibc symbols.
  `install.sh` was updated to map `linux-x86_64` to the musl target by
  default, with a one-shot HEAD-probe fallback to the legacy gnu artifact
  for older pinned versions so the transition doesn't break users who
  ask for an older version explicitly.

- **aarch64 release artifact verified at build time** ([#112](https://github.com/Dicklesworthstone/destructive_command_guard/issues/112)).
  v0.5.1's `dcg-aarch64-unknown-linux-gnu.tar.xz` published an x86-64
  ELF binary. Native ARM runners in the current matrix make that
  impossible by construction, but a `file <target>/release/dcg | grep
  aarch64` post-build check now fails the release if the architecture
  ever drifts again.

## [v0.5.1](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.5.1) -- 2026-05-03 [Release]

Patch release after v0.5.0 covering two false-positive/false-negative classes
discovered during a wide review of recent agent-authored fixes: the heredoc
parser's handling of the `<<-` / `<<~` markers and a missed-coverage gap in
the compact `-XDELETE` / `--request=DELETE` / `--method=DELETE` curl/glab API
forms. 5 commits since v0.5.0.

### Heredoc parser hardening (issue #109)

- Consumed whitespace between the `<<-` / `<<~` marker and the delimiter so
  bash-legal forms like `cat <<- 'EOF'` no longer fall through the
  quoted-delimiter strip and bail out unmasked. Pre-fix the body escaped
  masking, and pack matching denied prose like "gh repo delete" inside a
  heredoc fed to a non-executing target ([f3c96bd](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f3c96bd),
  test coverage added in [a739dc9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a739dc9)
  and [03bf276](https://github.com/Dicklesworthstone/destructive_command_guard/commit/03bf276)).
- Disambiguated `cat << -EOF` (whitespace before the dash, delimiter is
  literally `-EOF`) from `cat <<-EOF` (tab-strip marker, delimiter is `EOF`)
  by gating the marker classification on `skip_whitespace == 0`. Same fix
  applied to `~` so `cat << ~TILDE` is also a Standard heredoc with
  delimiter `~TILDE`. Aligned the manual `parse_heredoc_delimiter` path with
  the regex-based `extract_heredocs` path so both correctly map `~` to
  `IndentStripped` rather than `TabStripped`. Without this, a `cat <<~EOF`
  with space-indented body lines and a space-indented terminator was never
  recognized by the masker, the body escaped masking, and pack matching
  produced false positives on documentation prose like `rm -rf /` inside
  the heredoc body
  ([a8a0a8d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a8a0a8d)).

### Compact curl / glab API method forms

- Closed a false-negative gap where four destructive-pattern regexes still
  required whitespace between `-X` / `--request` / `--method` and the HTTP
  verb. Pre-fix bypasses such as `glab api -XDELETE
  projects/123/variables/SECRET`, `glab api --method=DELETE
  /projects/123/protected_branches/main`, `curl -XDELETE
  https://splunk.example.com:8089/services/data/inputs/abc`, and `curl
  --request=DELETE
  https://circleci.com/api/v2/.../envvar/FOO` slipped through unblocked
  because curl and glab's cobra-based CLI accept those compact short forms
  and equals long forms. Aligned the affected packs with the broader
  `(?:-X\s*|--request(?:=|\s+))VERB` shape already used by `gh api`,
  Datadog, PagerDuty, Prometheus, New Relic, Meilisearch, and the email
  packs, and added regression tests for each block
  ([1fdfbec](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1fdfbec)).

### Representative commits

| Commit | Subject |
|--------|---------|
| [f3c96bd](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f3c96bd) | fix(heredoc): consume whitespace between `<<-` / `<<~` marker and delimiter (issue #109) |
| [a739dc9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a739dc9) | test(heredoc): cover `<<-` / `<<~` with space-after-marker quoted forms (issue #109) |
| [03bf276](https://github.com/Dicklesworthstone/destructive_command_guard/commit/03bf276) | test(heredoc): restore unquoted-delimiter assertion to its parent test |
| [a8a0a8d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a8a0a8d) | fix(heredoc): respect whitespace gap when classifying tab-strip marker |
| [1fdfbec](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1fdfbec) | fix(packs): match `curl -XDELETE` and `--request=DELETE` compact forms across CI/platform packs |

## [v0.5.0](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.5.0) -- 2026-05-02 [Release]

Minor pre-1.0 release after v0.4.11 for the Codex hardening wave, installer
preservation work, Railway/API guard improvements, and the latest safe-pattern
bypass fixes. This release covers 75 commits since v0.4.11.

### Codex & Multi-Agent Hook Support

- Applied protocol-derived agent profiles, so Codex/Copilot/Gemini/Claude-style
  hook payloads can select the right agent profile without relying only on
  process environment detection
  ([7f7d67e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/7f7d67e)).
- Kept blank Codex `turn_id` fields from forcing the Codex stderr-deny path,
  preserving Claude-compatible JSON behavior for payloads that are not actually
  Codex hook events
  ([d0a1bef](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d0a1bef)).
- Hardened Copilot handling for PowerShell payloads, missing tool names, and
  warn-severity decisions so Copilot warnings remain non-stopping while denies
  still block
  ([e11baea](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e11baea),
  [4862be4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4862be4),
  [708536e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/708536e)).
- Added and expanded subprocess-level Codex protocol coverage, including
  hermetic HOME isolation, allow-once/allowlist parity, pack enablement,
  heredoc behavior, and cross-protocol block/allow shape checks
  ([tests/codex_hook_protocol.rs](https://github.com/Dicklesworthstone/destructive_command_guard/blob/main/tests/codex_hook_protocol.rs)).

### Installer & Uninstaller Reliability

- Made Unix and Windows installers preserve malformed or user-owned hook
  configuration instead of overwriting it for Claude Code, Codex CLI, Gemini
  CLI, GitHub Copilot CLI, Cursor IDE, and PowerShell hook payloads
  ([c55bf33](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c55bf33),
  [1a4b015](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1a4b015),
  [563d538](https://github.com/Dicklesworthstone/destructive_command_guard/commit/563d538),
  [46f3764](https://github.com/Dicklesworthstone/destructive_command_guard/commit/46f3764),
  [fba6067](https://github.com/Dicklesworthstone/destructive_command_guard/commit/fba6067)).
- Preserved coexisting user hooks while keeping dcg first in the relevant Bash
  hook lists, including mixed Copilot entries and existing Claude hooks
  ([792236e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/792236e),
  [85028ce](https://github.com/Dicklesworthstone/destructive_command_guard/commit/85028ce),
  [389ac52](https://github.com/Dicklesworthstone/destructive_command_guard/commit/389ac52)).
- Rejected empty or flag-shaped installer option values so arguments like
  `--version --system` fail as setup errors instead of treating `--system` as
  the version value
  ([e8cb117](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e8cb117)).
- Matched uninstall ownership checks more exactly for Cursor, Codex,
  PowerShell, and non-dcg hook preservation so uninstallers remove only dcg's
  own entries
  ([6d71b68](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6d71b68),
  [af68c72](https://github.com/Dicklesworthstone/destructive_command_guard/commit/af68c72),
  [b043068](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b043068),
  [e8e65d1](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e8e65d1)).

### Railway & API Pack Hardening

- Expanded the Railway pack to recognize `Project-Access-Token` and
  `RAILWAY_TOKEN` signals, multiline API payloads, curl executable suffixes,
  and JSON database variable keys that can mutate production connection
  settings
  ([d6b49d5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d6b49d5),
  [6220da9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6220da9),
  [586afff](https://github.com/Dicklesworthstone/destructive_command_guard/commit/586afff),
  [2193c67](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2193c67)).
- Closed broad safe-pattern masking gaps across cloud, database, Kubernetes,
  package manager, backup, search, monitoring, feature flag, Kafka, and
  Ansible packs, including attached/equal curl methods and false dry-run text
  bypasses
  ([8e86dbc](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8e86dbc),
  [1a1c1b0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1a1c1b0),
  [2690864](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2690864),
  [c8faf44](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c8faf44),
  [552b83d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/552b83d),
  [7a02669](https://github.com/Dicklesworthstone/destructive_command_guard/commit/7a02669),
  [535b01a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/535b01a)).
- Kept legitimate AWS S3 `--dryrun` previews allowed while blocking deceptive
  dry-run-looking strings in destructive contexts
  ([b5bea76](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b5bea76)).

### Command Parsing, Agent Detection, and Update Safety

- Fixed shell redirection tokenization around attached `&>`, `&>>`, and `>&`
  forms so destructive append/truncate redirections are not split or hidden
  from filesystem rules
  ([87766f9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/87766f9),
  [8aeffdc](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8aeffdc),
  [149255c](https://github.com/Dicklesworthstone/destructive_command_guard/commit/149255c),
  [616cd75](https://github.com/Dicklesworthstone/destructive_command_guard/commit/616cd75)).
- Reduced false positives in agent detection for domain/path substrings,
  wrapper-launched agents, and Windows shim-launched processes while recording
  the hook-protocol-detected agent type in history
  ([224f2f8](https://github.com/Dicklesworthstone/destructive_command_guard/commit/224f2f8),
  [97e91d4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/97e91d4),
  [dba007c](https://github.com/Dicklesworthstone/destructive_command_guard/commit/dba007c),
  [77bfbaf](https://github.com/Dicklesworthstone/destructive_command_guard/commit/77bfbaf)).
- Hardened `dcg update` so unknown latest installer tags fail closed, rollback
  pruning preserves the intended target, and backup artifact names are
  validated before use
  ([a4d467c](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a4d467c),
  [5c7312b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/5c7312b),
  [1eea079](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1eea079),
  [ea3fcc5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ea3fcc5)).

## [v0.4.11](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.11) -- 2026-05-01 [Release]

Clean release target for the shell tokenization regression fix from v0.4.10.
This supersedes the quarantined v0.4.10 prerelease; no behavior changes were
made after v0.4.10.

### Release Hygiene

- Bumped the release version so official GitHub Actions can publish a clean
  asset set without overwriting or deleting the quarantined v0.4.10 fallback
  artifacts.

## [v0.4.10](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.10) -- 2026-05-01 [Pre-release]

Patch release after v0.4.9 for a shell tokenization regression found during
fresh-eyes review of nested command and process substitution handling.
This release was left as a prerelease and superseded by v0.4.11 after fallback
artifact publication produced an incomplete asset set.

### Shell Parsing

- Preserved shell parenthesized constructs such as `$()`, `<()`, and `>()`
  while tokenizing commands for normalization, preventing quotes inside nested
  command substitutions from corrupting the normalized command stream
  ([41d233a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/41d233a)).
- Masked quoted process-substitution-looking literals before Docker pack
  evaluation while still blocking real input and output process substitutions
  that execute destructive Docker commands
  ([41d233a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/41d233a)).

## [v0.4.9](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.9) -- 2026-05-01 [Release]

Patch release after v0.4.8 for the remaining DCG-specific environment flag
semantics and release validation fixes that need to ship in prebuilt binaries.

### CLI Reliability

- Kept shell redirection ampersands such as `2>&1`, `>&2`, and `&>` inside
  the current command segment instead of splitting them as command separators,
  preserving correct downstream pack evaluation for redirected commands
  ([acf6803](https://github.com/Dicklesworthstone/destructive_command_guard/commit/acf6803)).
- Honored documented falsey values for `DCG_NO_COLOR` and `DCG_NO_RICH` in
  non-clap output paths, so values such as `0`, `false`, `no`, and `off` no
  longer disable colors or rich output by mere presence
  ([14f1aac](https://github.com/Dicklesworthstone/destructive_command_guard/commit/14f1aac)).
- Applied the same falsey-value semantics to `DCG_NO_UPDATE_CHECK` and
  `DCG_NO_SELF_HEAL`, so `0`, `false`, `no`, `n`, and `off` no longer disable
  update checks or self-healing by mere presence
  ([27ac314](https://github.com/Dicklesworthstone/destructive_command_guard/commit/27ac314)).
- Kept Linux-only allowlist process inspection imports behind a Linux cfg so
  macOS and Windows release builds stay warning-clean
  ([bdcbb9b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/bdcbb9b)).

### Railway Pack

- Blocked Railway Public API `variableCollectionUpsert` mutations that set
  `replace: true`, because omitted variables are deleted and this can remove
  production credentials even when no database variable name appears in the
  payload
  ([fb6431e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/fb6431e)).
- Kept that Railway replacement mutation detector on the linear regex path for
  predictable hook latency
  ([b7aa4e2](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b7aa4e2)).

### Release Validation

- Isolated the Codex subprocess memory test HOME so stale pending-exception
  state from previous local runs cannot turn an expected Codex deny into an
  allow during release gates
  ([29d870c](https://github.com/Dicklesworthstone/destructive_command_guard/commit/29d870c)).

## [v0.4.8](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.8) -- 2026-05-01 [Release]

Patch release after v0.4.7 for a CLI environment-variable parser fix that needs
to ship in prebuilt binaries.

### CLI Reliability

- Accepted documented truthy and falsey values for global boolean environment
  flags such as `DCG_NO_COLOR=1`, `DCG_QUIET=1`,
  `DCG_LEGACY_OUTPUT=1`, and `DCG_NO_SUGGESTIONS=1` instead of letting clap
  reject `1` as an invalid boolean ([0b350e3](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0b350e3)).

## [v0.4.7](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.7) -- 2026-05-01 [Release]

Patch release after v0.4.6 focused on Codex/Gemini installer reliability, hook protocol compatibility, and closing safe-pattern masking gaps in destructive API packs.

### Codex & Installer Reliability

- Preserved invalid Codex `~/.codex/hooks.json` files instead of overwriting them during Unix installer runs, with an explicit failure reason in the install summary ([a3fc05a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a3fc05a)).
- Preserved malformed Codex hook shapes on both Unix and Windows installers, including non-object `hooks` values and non-list `PreToolUse` values, instead of replacing user-edited data ([7167be6](https://github.com/Dicklesworthstone/destructive_command_guard/commit/7167be6), [f0ca794](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f0ca794)).
- Removed self-service bypass commands from Codex-visible denial text, so Codex sees the block reason and an explicit no-bypass instruction instead of a command it can use to allowlist and rerun the destructive operation ([a4b9a84](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a4b9a84)).
- Made Gemini installer reruns reset `GEMINI_BACKUP` state at the start of `configure_gemini`, preventing stale backup paths from leaking between attempts ([762f3c7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/762f3c7)).
- Tightened Gemini hook detection so the installer recognizes the exact dcg hook shape and reports configuration failures rather than silently treating near-matches as success ([4c9fbb2](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4c9fbb2)).

### Hook & Pack Correctness

- Fixed Gemini warn-severity hook output to emit `decision = "allow"` instead of `ask`, matching Gemini's accepted hook contract ([5d70198](https://github.com/Dicklesworthstone/destructive_command_guard/commit/5d70198)).
- Prevented broad API safe patterns from masking destructive method-bearing requests across packs, including `curl -XDELETE`, `curl --request=DELETE`, and attached-method forms such as `-XDELETE` / `--request=DELETE` ([bdb297f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/bdb297f), [08ac8a3](https://github.com/Dicklesworthstone/destructive_command_guard/commit/08ac8a3), [79915f4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/79915f4)).
- Blocked Redis mass key deletion pipelines and Prometheus destructive API calls that were previously hidden by overly broad safe `GET` handling ([41ec95d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/41ec95d), [9f01db0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/9f01db0)).
- Scoped Railway original-payload rechecks to relevant compound-command segments so safe Railway API queries are not tainted by unrelated text in later shell segments, while destructive Railway mutations remain blocked ([701630f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/701630f)).
- Blocked Railway API mutations split across shell line continuations ([3818efc](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3818efc)).

### Pack Coverage

- Added Railway function deletion coverage ([f15bdf6](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f15bdf6)).
- Expanded the Google Cloud Storage pack to match `gcloud alpha storage` and `gcloud beta storage` release tracks ([a68ad66](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a68ad66)).
- Refreshed the pattern-audit document after the storage.gcs keyword widening ([dc02ff4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/dc02ff4)).
- Hardened the real Codex E2E harness so relative `--dcg-binary` paths are canonicalized before hook configuration, and missing option values fail with a setup error instead of shifting later arguments ([cd1b612](https://github.com/Dicklesworthstone/destructive_command_guard/commit/cd1b612), [d11de4d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d11de4d)).

## [v0.4.6](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.6) -- 2026-05-01 [Release]

Release 0.4.6 completed the larger post-v0.4.3 hardening wave documented below.

### Security Hardening

- **Railway platform protection pack** — added `platform.railway` to guard Railway CLI and Public API operations that can delete projects, environments, services, volumes, variables, and deployments. Critical rules cover project/environment/service/volume deletion and GraphQL deletion mutations (`projectDelete`, `projectScheduleDelete`, `environmentDelete`, `serviceDelete`, `volumeDelete`, `volumeInstanceDelete`). High-severity rules cover volume detach, variable deletion, database connection variable upserts (`DATABASE_URL`, `PGHOST`, `MYSQL_URL`, `REDIS_URL`, etc.), and deployment removal/stops (`railway down`, `deploymentRemove`, `deploymentStop`). Read-only commands such as `railway status`, `railway list`, `railway service list`, `railway volume list`, and safe GraphQL queries remain allowed.
- **Recursive-force-delete bypass family** (`core.filesystem`): closed seven sibling-bypass families an agent could use after `rm -rf` is blocked.
  - `find ... -delete` on sensitive paths (Critical/High) — closes the `find -delete` path-bypass plus compound, subshell, and path-prefix variants.
  - `unlink <sensitive>` (Critical/High) — POSIX unlink(2) primitive.
  - `truncate -s 0|--size=0|-s -N` on sensitive paths (Critical/High) — in-place zero/shrink.
  - `shred [-u|--remove|-fzu] <sensitive>` (Critical/High) — DoD-style overwrite + optional unlink.
  - `tar --remove-files` on sensitive sources (Critical/High) — archive-then-delete masquerading as an archive operation; order-agnostic flag/source placement; `tar --remove-files -cf /dev/null /etc` (delete-only) blocked.
  - `dd of=<sensitive>` (Critical/High) — file-level overwrite (truncate-equivalent at the dd layer); operand-order agnostic; `dd of=/dev/null` (read-discard) and `dd if=/etc/passwd of=/tmp/passwd.bak` (backup) preserved; device-level dd (`of=/dev/sda`) is `system.disk`'s scope.
  - `mv <sensitive>` (Critical) — closes the canonical cross-segment bypass `mv /etc /tmp/x && rm -rf /tmp/x` where each segment is allowed individually but together destroys `/etc`. Blocks any mv that mentions a sensitive path (source OR destination) including in-place renames within /etc; tmp-family moves remain allowed.
  - Sensitive-source propagation chains (Critical) — blocks phase-1 data-flow bypasses for `cp -a/-al <sensitive> <tmp> && rm -rf <tmp>`, `ln -s <sensitive> <tmp> && rm -rf <tmp>/.`, and `rsync -a <sensitive> <tmp> && rm -rf <tmp>`. The filesystem rm fast-path now parses compound segments so ordinary temp cleanup stays allowed while propagation chains are classified before the rm fallback rules.
  - `> <sensitive>` (Critical) — Bash output redirects (`>`, `>|`, `&>`, `1>`, `2>` with optional `|` force-overwrite) truncate the target file to zero bytes; bare `> /etc/passwd`, `: > /etc/passwd`, `echo > /etc/passwd`, and numbered-FD variants all destroy file content via shell syntax alone (no destructive binary involved). Append (`>>`) is correctly preserved via negative lookbehind. Per scope decision: only the Critical root-home tier ships — a `-general` rule would block legitimate `make > build.log` workflows. Two supporting changes: (a) the `should_fallback_to_full_normalized_keyword_scan` quick-reject helper now fires whenever a redirect operator is present (previously gated on path-prefix normalization), so redirect keywords match outside the executable span; (b) `sanitize_for_pattern_matching` now exits all-args-data masking on redirect operators so `echo > /etc/passwd` no longer hides the destructive target.
- **mkswap rule added to `system.disk`** (`git_safety_guard-8kh4`) — `mkswap /dev/sdb` formats a partition as a swap area with the same blast radius as `mkfs`. Previously slipped through because mkswap is a separate binary and the existing `mkfs(?:\.[a-z0-9]+)?` regex only matched `mkfs.*` variants. Ships with the `mkswap` keyword in PACK_ENTRIES, a destructive `mkswap` rule (High), and a safe `mkswap-check` carve-out for read-only `mkswap --check` inspection.
- **`dcg update` verifies install.sh / install.ps1 before exec** (`git_safety_guard-ythp`) — `self_update_unix` previously did `curl -fsSL <script> | bash -s -- ...`: a tag-pinned but unverified pipe, so a GitHub account compromise that planted a malicious installer at the tag would run unchecked. New flow downloads the script to a tempfile, best-effort fetches `install.sh.sha256` from the matching GitHub Release (`releases/download/<tag>/install.sh.sha256`), verifies via `shasum -a 256 -c`, aborts on mismatch, and only then `bash`-execs the script. Tags published before this change have no `.sha256` artifact: the verifier emits a warning and proceeds (preserving the update path for stale binaries). PowerShell path mirrors the same flow with `Get-FileHash`. CI side: `dist.yml` now publishes `install.sh.sha256` / `install.ps1.sha256` plus matching cosign sigstore bundles for every release.
- **Cross-session graduated-response wiring** (`git_safety_guard-n9j1`) — `history_soft_block` / `history_hard_block` / `history_window` config fields were parsed and merged but never consulted by `determine_graduated_response`. For shell hooks (one process per `Bash` call) the in-process `session_count` never grows past 1, so Standard/Lenient modes never escalated across invocations. Added `determine_graduated_response_with_history` and `EvaluationResult::apply_graduation_with_history_db` that query `HistoryDb::count_command_blocks_in_window(command_hash, history_window_duration)` and escalate Standard/Lenient to SoftBlock/HardBlock when the cross-session count crosses the configured thresholds. Hot-path stays fail-open: any history query error falls back to session-only graduation. New `ResponseConfig::parse_history_window` helper accepts `s` / `m` / `h` / `d` suffixes. 7 new tests including legacy-signature equivalence and unit-parsing coverage.
- **History `inline_params` SQL substitution corruption fix** (`git_safety_guard-tovy`) — `history/schema.rs::inline_params` previously substituted `?N` placeholders via reverse-order `String::replace`. Reversal solved the `?10` vs `?1` ambiguity but did NOT prevent corruption when a substituted value contained text matching an earlier placeholder index (e.g. `params[4] = "?1"` would inject `'?1'` into the SQL, then the subsequent pass would re-substitute it into the value of `?1`). Replaced with a single-pass left-to-right walk that recognizes `?N` only outside single-quoted string literals, parses full digit runs, and writes substituted values to the output without rescanning. 7 new tests including the exact regression case (`params[1] = "?1"`) and SQLite's doubled-quote escape handling.
- **Unified SIGINT shutdown registry** (`git_safety_guard-i5gd`) — `main.rs` previously registered an ad-hoc ctrlc handler that flushed only the `HistoryWriter`. Refactored to a process-wide `SHUTDOWN_ACTIONS` registry: each subsystem with cross-call buffered state registers a flush closure at startup, and the SIGINT handler invokes them in order before `std::process::exit(130)`. Future stores plug in by calling `register_shutdown_action(...)` rather than adding ad-hoc logic to the signal handler.
- **Pending-exceptions JSONL bounded with rotation** (`git_safety_guard-f81d`) — `record_block` previously appended unbounded; long-running automations issuing many allow-once codes turned every `record_block` call into O(N) under an exclusive lock. New `MAX_PENDING_LINES` (10,000) cap triggers archival to `pending.jsonl.1` of the oldest half (with `OpenOptions::append` so prior archives accumulate, not overwrite). Hard `MAX_PENDING_BYTES` (10 MiB) refusal: if the live file is somehow still over that cap, `record_block` returns an error rather than continuing to grow. The hot path is now O(MAX_PENDING_LINES / 2) under the exclusive lock.
- **Bounded config-file reads + system-layer symlink rejection** (`git_safety_guard-tck0`) — `config::load_layer_from_file` and `allowlist::load_allowlist_file` previously called `fs::read_to_string` directly, so a 2 GiB symlinked file would be loaded entirely into memory before parsing failed. New `read_config_file_bounded` helper caps reads at `MAX_CONFIG_BYTES` (1 MiB, well above any sane TOML config) using `Read::take`. The system layer (`/etc/dcg/config.toml` and `AllowlistLayer::System`) additionally refuses to follow symlinks pointing at user-writable targets — a non-root user could otherwise influence privileged config by symlinking it into their home directory. Per-layer trust class is encoded as `ConfigSource::System` vs `Untrusted`.
- **Scan reporting: structured skip detail and missing-path warnings** (`git_safety_guard-jvkm` + `-eug4`) — `ScanReport.summary` now includes two new arrays in addition to the existing `files_skipped` total. `paths_skipped[]` lists top-level user-supplied target paths that didn't exist or were unreadable, with `reason: "path_not_found"` — surfaced via `tracing::warn!` so misconfigured CI invocations no longer silently exit zero with `files_scanned=0`. `skipped[]` records per-file skip detail with a `reason` enum (`metadata_error`, `not_a_regular_file`, `too_large`, `no_extractor`, `read_error`) so operators can distinguish `max-file-size` configuration issues from genuinely-non-script files.
- **Scan-mode heredoc-extraction timeout floor** (`git_safety_guard-s67a`) — `ScanEvalContext::from_config` now floors `heredoc_settings.limits.timeout_ms` at 200ms (`SCAN_HEREDOC_MIN_TIMEOUT_MS`). The hook hot path is a per-Bash-call budget where every microsecond matters; the scan path is offline (`dcg scan .` runs once, deliberately, and doesn't gate command execution). Inheriting the hot-path budget silently dropped matches whose extraction merely brushed the budget. User config values larger than the floor are still honored.
- **Pending-exception short codes are now 6 digits** (`git_safety_guard-suap`) — `short_code_from_hash` was a 5-digit decimal modulo of the trailing 32 bits, giving 100,000 codes and a birthday-paradox 50% collision threshold at ~370 active records. Bumped to 6 digits (1,000,000 codespace) which raises the threshold to ~1,175 active records — well above realistic per-day volume in a 24-hour TTL. `dcg allow-once <code>` and `dcg allowlist revoke <code>` accept legacy 5-digit codes from already-written `pending.jsonl` files.
- **`detached_head_strictness` config knob** (`git_safety_guard-6skk`) — `apply_branch_strictness` previously collapsed `BranchInfo::DetachedHead(_)` to `branch_name=None` and applied `default_strictness`. Detached HEAD typically signals rebase / bisect / checkout-of-tag — exactly the contexts where uncommitted work is most exposed. New `git_awareness.detached_head_strictness` field defaults to `All` (strictest); also configurable via `DCG_GIT_DETACHED_HEAD_STRICTNESS`. Set it to `default_strictness` for the previous loose behavior.
- **Agent detection no longer false-positives on substrings** (`git_safety_guard-bui6`) — `agent_from_process_name` previously used `executable.contains("claude")` / `"aider"` / `"continue"` / `"cursor"` etc., misclassifying any tool whose binary name merely contained an agent name (`claude-explorer`, `myproject-continue`, `cursor-ext`). The new implementation tokenizes the parent-process string on whitespace, takes each token's basename (lower-case, `\` → `/`, last path segment, strip `.exe`), and matches it against an explicit name/alias table. Wrapper invocations like `node /usr/local/bin/codex` continue to detect correctly because each argv token is checked independently.
- **Interactive prompt sanitizes attacker-controlled command** (`git_safety_guard-m1ic`) — `display_prompt` in `src/interactive.rs` now passes the blocked command and reason through `sanitize_for_display` before any styling. The helper strips CSI/OSC/2-byte ESC escapes (preventing terminal-title spoofing, fake prompt boundaries, color injection) and visualizes remaining C0/C1 control bytes as `\xNN` / `\n` / `\r` / `\t` so the human verifier sees the original bytes without the terminal acting on them.
- **system.disk pack promoted to default-on** (`PacksConfig::enabled_pack_ids`) — first-time users with empty config now get `mkfs`/`dd-to-/dev`/`fdisk`/`parted`/`mdadm`/`lvm`/`wipefs` protection without manual enablement. Opt-out via `disabled = ["system.disk"]` (or `disabled = ["system"]`).
- **Strict git pack**: expanded dangerous-command detection for additional destructive git patterns ([6d950f3](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6d950f3), [031e84a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/031e84a))
- Removed safe patterns in strict git pack that created a compound-command bypass ([d6ce202](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d6ce202))
- Podman `rm`/`rmi` combined-flag bypass (e.g. `podman rm -af`) ([d9d23b5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d9d23b5))

### Hook & Agent Detection

- **Codex CLI PreToolUse hook support**: Codex CLI 0.125.0+ is supported via stable `~/.codex/hooks.json` PreToolUse hooks. dcg detects Codex hook input from the `turn_id` field and uses the strict stderr-deny contract with exit code 2 required by Codex, not the Claude/Gemini JSON-deny payload. The Unix installer writes `~/.codex/hooks.json` when Codex CLI is detected; Windows installs document the manual hook path while PowerShell parity is tracked separately. Closes [#84](https://github.com/Dicklesworthstone/destructive_command_guard/issues/84).
- Hook system expansion with additional interception patterns and strict git pack hardening ([031e84a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/031e84a))
- Disambiguate Claude Code from Gemini in `detect_protocol()` -- closes [#77](https://github.com/Dicklesworthstone/destructive_command_guard/issues/77) ([8815b54](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8815b54))

### Output

- **Rich output is now enabled by default** (`bd-15p0`) — default Cargo builds include the `rich-output` feature and the `rich_rust` renderer, while `cargo build --no-default-features` remains the lean/plain fallback. The unused `legacy-output` Cargo feature placeholder was removed; runtime plain output is still available through `DCG_NO_RICH=1`, `NO_COLOR=1`, CI/non-TTY detection, or `--legacy-output`.

### Maintenance

- Clippy and rustfmt cleanup across CLI, hook, and pack modules ([c26f22d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c26f22d))
- Test infrastructure: `large_dataset_insertion` test updated to use in-memory DB with manual seeding ([784e356](https://github.com/Dicklesworthstone/destructive_command_guard/commit/784e356))

---

## [v0.4.3](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.3) -- 2026-03-14 [Tag]

A large release adding new agent detections, new protection packs, self-healing settings monitoring, and a session-scoped interactive allowlist system.

### Self-Healing & Resilience

- **Real-time `settings.json` overwrite detection and self-healing** -- DCG now watches for external processes silently removing its hook registration and restores it automatically ([708d202](https://github.com/Dicklesworthstone/destructive_command_guard/commit/708d202))
- `dcg setup` command with shell startup hook-removal detection -- closes [#56](https://github.com/Dicklesworthstone/destructive_command_guard/issues/56) ([45db4b7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/45db4b7))
- Shell startup check to detect silently removed DCG hook ([eb06112](https://github.com/Dicklesworthstone/destructive_command_guard/commit/eb06112))
- Prevent duplicate shell check injection on re-runs ([8b70cab](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8b70cab))

### New Protection Packs

- **Supabase database protection pack** -- full CLI coverage including `db push`, `db reset`, `migration repair`, `functions delete`, `secrets unset`, `storage rm`, `projects delete`, and more; `--dry-run` whitelisted as safe ([003a429](https://github.com/Dicklesworthstone/destructive_command_guard/commit/003a429), [3e3ed19](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3e3ed19))

### Agent Detection & Protocol Support

- **Gemini CLI hook protocol support** with improved detection for minimal payloads ([ac6e6ad](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ac6e6ad), [0629a5d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0629a5d))
- **Augment Code** agent detection ([5917125](https://github.com/Dicklesworthstone/destructive_command_guard/commit/5917125))
- **GitHub Copilot CLI** agent detection ([84bb1a0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/84bb1a0))

### Interactive Allowlist & Session Management

- **Session-scoped allowlist** binding with `session_id` and testable interactive checks ([3533533](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3533533))
- **Interactive allowlist audit system** with collision-resistant backup naming and SQLite schema v6 migration ([c948240](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c948240))
- Project-level hook install and `--no-configure` update flag ([1397a8b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1397a8b))

### Output & History

- **TOON output format** support, hardened history storage, and improved test infrastructure ([69f60c8](https://github.com/Dicklesworthstone/destructive_command_guard/commit/69f60c8))

### Bug Fixes

- Emit JSON `"ask"` decision for warn-severity matches in hook mode -- closes [#70](https://github.com/Dicklesworthstone/destructive_command_guard/issues/70) ([91f09db](https://github.com/Dicklesworthstone/destructive_command_guard/commit/91f09db))
- Display `custom_paths` packs in `dcg packs` listing -- closes [#57](https://github.com/Dicklesworthstone/destructive_command_guard/issues/57) ([045cfc0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/045cfc0))
- Redis `maxmemory` regex no longer matches `maxmemory-policy` ([1c3c94a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1c3c94a))
- Missing Redis CONFIG SET rules for `maxmemory`, persistence, and rewrite ([4f0a21a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4f0a21a))
- ARM64 compilation fix for `uring-fs` (`*const i8` to `*const libc::c_char`) ([7b9bf96](https://github.com/Dicklesworthstone/destructive_command_guard/commit/7b9bf96))
- Installer and CI aligned on `gnu` targets to match existing release binaries ([5e81603](https://github.com/Dicklesworthstone/destructive_command_guard/commit/5e81603))

---

## [v0.4.2](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.2) -- 2026-02-23 [Tag]

Stabilization release that resolved 91+ pre-existing test failures.

### Test Suite

- Resolved 91+ pre-existing test failures across the entire test suite ([faf7e0e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/faf7e0e))

### License

- License updated to MIT with OpenAI/Anthropic Rider ([c1200c7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c1200c7))

---

## [v0.4.1](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.1) -- 2026-02-22 [Tag]

First `musl`-based statically linked Linux binary release, plus dependency modernization and publish to crates.io.

### Distribution & Portability

- Switch Linux x86_64 distribution to **musl** for portable, statically linked binaries ([e066687](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e066687))
- Static linking verification for musl builds in CI ([6cdbfc1](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6cdbfc1), [0a6850c](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0a6850c))
- `fsqlite` dependencies switched from local paths to crates.io v0.1.0 ([9dc695b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/9dc695b))
- `rich_rust` dependency updated from pre-release/git ref to crates.io v0.2.0 ([83d4abf](https://github.com/Dicklesworthstone/destructive_command_guard/commit/83d4abf))
- crates.io keyword limit compliance (max 5) ([0a46ef7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0a46ef7))

### CLI Improvements

- `dcg pack-info` shows patterns by default; new `--json` and `--no-patterns` flags ([48e303e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/48e303e))

### Bug Fixes

- Binary content detection for Unicode; FTS rowid sync; regex engine fallback ([acc2f2c](https://github.com/Dicklesworthstone/destructive_command_guard/commit/acc2f2c))
- macOS `CursorUIViewService` filtered from Cursor IDE detection ([970f62f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/970f62f))
- Migrate all branch references from `master` to `main`; fix quote-stripping in normalizer ([920d785](https://github.com/Dicklesworthstone/destructive_command_guard/commit/920d785))
- History writer migrated to thread-local DB; updated `rand` API ([4d1b3c7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4d1b3c7))

### Testing

- Comprehensive unit tests for output modules ([b97f50a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b97f50a))

---

## [v0.4.0](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.0) -- 2026-02-10 [Release]

Major release adding GitHub Copilot CLI hook support, installer improvements, and automated packaging triggers.

### Agent Integration

- **GitHub Copilot CLI hook support** and installer integration ([7385931](https://github.com/Dicklesworthstone/destructive_command_guard/commit/7385931))
- Timeout protection and user feedback for agent scanning during install ([37c9123](https://github.com/Dicklesworthstone/destructive_command_guard/commit/37c9123))

### Distribution

- `repository_dispatch` triggers for homebrew-tap and scoop-bucket automated packaging ([b5482b4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b5482b4))

### Evaluator

- Evaluator refactored to consolidate external pack checking into core evaluation ([fea7d6a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/fea7d6a))
- Build ordered pack list and keyword index after external packs are loaded ([314e591](https://github.com/Dicklesworthstone/destructive_command_guard/commit/314e591))

### Bug Fixes

- All available subcommands now appear in `dcg --help` output ([23f3301](https://github.com/Dicklesworthstone/destructive_command_guard/commit/23f3301))

---

## [v0.3.0](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.3.0) -- 2026-02-02 [Release]

Large feature release introducing robot mode, rich terminal output via `rich_rust`, golden testing, expanded packs, and agent-specific profiles.

### Robot Mode & Machine-Readable Output

- **Robot mode** with structured JSON output and machine-readable exit codes (`dcg test --robot`) ([e576883](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e576883))
- Robot mode API documentation ([34506dd](https://github.com/Dicklesworthstone/destructive_command_guard/commit/34506dd))
- Schema versioning and metadata in `TestOutput` JSON ([b7a6d6d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b7a6d6d))

### Rich Terminal Output (`rich_rust` Integration)

- `rich_rust` dependency with DcgConsole wrapper and rich theme bridge ([ae39947](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ae39947), [c881a75](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c881a75))
- Tables migrated to `rich_rust` ([328107a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/328107a))
- Enhanced `doctor`, `packs`, and `stats` commands with rich terminal output ([02b5086](https://github.com/Dicklesworthstone/destructive_command_guard/commit/02b5086), [ea39323](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ea39323))
- Tree visualization for `dcg explain` ([e538399](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e538399), [2b8780d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2b8780d))
- CLI output control flags for legacy and color modes ([fdda44f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/fdda44f))

### Golden Testing

- Golden JSON tests framework for deterministic output validation ([0b0ca97](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0b0ca97))
- Robot framework test fixtures ([cbf74da](https://github.com/Dicklesworthstone/destructive_command_guard/commit/cbf74da))

### Pack System Expansion

- Detailed explanations added to all destructive patterns ([e775c2b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e775c2b))
- Expanded allowlist rules for safe command patterns ([db272dc](https://github.com/Dicklesworthstone/destructive_command_guard/commit/db272dc))
- External pack loading from `custom_paths` wired into the evaluator ([bea17d0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/bea17d0), [a2cabc5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a2cabc5))
- Expanded `system.disk` pack with mdadm, btrfs, LVM, and dmsetup patterns ([56df75a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/56df75a))

### Agent Profiles

- **Agent-specific profiles and trust levels** (Epic 9) -- auto-detect AI coding agent and apply tailored settings ([77571ba](https://github.com/Dicklesworthstone/destructive_command_guard/commit/77571ba))

### Misc

- Configurable verification methods for interactive prompts ([23618ac](https://github.com/Dicklesworthstone/destructive_command_guard/commit/23618ac))
- OpenCode added to supported tools list ([4473419](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4473419))

### Bug Fixes

- macOS config path: check XDG-style `~/.config/dcg` first ([ceffdf5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ceffdf5))
- External packs marked as always-enabled in listing ([7821773](https://github.com/Dicklesworthstone/destructive_command_guard/commit/7821773))
- Iteration limit added to prevent unbounded wrapper stripping in normalizer ([d342171](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d342171))
- CI/TERM=dumb detection for plain text fallback output ([47b4ddd](https://github.com/Dicklesworthstone/destructive_command_guard/commit/47b4ddd))

---

## [v0.2.15](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.15) -- 2026-01-20 [Release]

CI fix release.

### Bug Fixes

- Run only lib tests in dist workflow to avoid missing binary errors ([6489d2b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6489d2b))

---

## [v0.2.14](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.14) -- 2026-01-20 [Tag]

Version bump and formatting for release pipeline.

### Maintenance

- Bump version to 0.2.14 and apply `cargo fmt` ([6d67502](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6d67502))

---

## [v0.2.13](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.13) -- 2026-01-20 [Tag]

Massive feature batch covering the MCP server, CI scan extractors, self-update mechanism, SARIF output, rich TUI, custom packs, and dozens of new security pack enrichments.

### MCP Server & Agent Integration

- **MCP server mode** (`dcg mcp`) for direct agent integration via the Model Context Protocol ([b372d99](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b372d99))
- Hook output enriched with `ruleId`, `severity`, and `remediation` fields ([b439cd4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b439cd4))
- Agent ergonomics test suite ([0ebc72f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0ebc72f))
- Machine-readable DCG documentation added to AGENTS.md ([871f929](https://github.com/Dicklesworthstone/destructive_command_guard/commit/871f929))

### Structured Output Formats

- **SARIF 2.1.0 output format** for security tool and CI integration ([4a4c09e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4a4c09e), [17f2040](https://github.com/Dicklesworthstone/destructive_command_guard/commit/17f2040))
- Standardized error code system (DCG-XXXX) ([4f87561](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4f87561))
- JSON Schema (Draft 2020-12) for all DCG output formats ([8c7601c](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8c7601c))
- `--format json` support for `test` and `packs` commands ([f9db962](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f9db962))

### Rich Terminal Rendering

- **Rich terminal rendering** -- denial boxes, progress bars, tables, and TUI denial integration ([a0aaf42](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a0aaf42), [f9986e0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f9986e0))
- Span highlighting with caret-style terminal formatter for denial output ([32aaa18](https://github.com/Dicklesworthstone/destructive_command_guard/commit/32aaa18), [ad2ac66](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ad2ac66))

### Self-Update & Installer

- **Native Rust self-update mechanism** with version rollback and background notification ([f8a8a15](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f8a8a15), [d0e1066](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d0e1066))
- `--check` flag for version checking ([c4f4f64](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c4f4f64))
- **Sigstore cosign signing** added to release workflow ([45c8109](https://github.com/Dicklesworthstone/destructive_command_guard/commit/45c8109))
- Installer: sigstore verification, Cursor detection, preflight checks, version-check idempotency ([2a597b6](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2a597b6), [1ab0b5b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1ab0b5b))
- Installer: checksum verification with `--no-verify` flag ([616db4a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/616db4a))
- Installer: `uninstall.sh` script with agent hook removal ([c3d3eff](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c3d3eff))
- Installer: Aider auto-configuration, Continue detection (unsupported status), Codex CLI detection (unsupported status) ([0a06a82](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0a06a82), [8d07940](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8d07940), [067b28a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/067b28a))

### Custom Pack System

- **Custom pack system** with external YAML loading (`custom_paths` in config) ([0e4bc64](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0e4bc64), [f87aade](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f87aade))
- Regex engine analysis and pack validation utilities ([fa9400f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/fa9400f))

### Scan Mode Extractors

- CircleCI extractor (`.circleci/config.yml`) ([1a3b232](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1a3b232))
- Azure Pipelines extractor ([80d4cda](https://github.com/Dicklesworthstone/destructive_command_guard/commit/80d4cda))
- Dockerfile extractor improvements ([302e35f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/302e35f))
- GitLab CI extractor tests ([3316733](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3316733))

### Pack Enrichment

- Comprehensive severity levels and extended explanations across all packs ([86b6b9a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/86b6b9a), [8dafbe3](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8dafbe3))
- Explanations added to DNS, Payment, database, infrastructure, Kubernetes, container, CI/CD, backup, and API gateway packs ([82064d4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/82064d4), [42ed80b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/42ed80b), [c07e4f9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c07e4f9))
- **MySQL pack** with comprehensive destructive patterns ([81b0ca8](https://github.com/Dicklesworthstone/destructive_command_guard/commit/81b0ca8))
- Suggestions added for Docker, Kubernetes, MySQL, and system permissions packs ([26dcc3b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/26dcc3b), [1b16ef0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1b16ef0), [5f76ba0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/5f76ba0))

### CLI Enhancements

- Verbosity controls, shell completions, and `DCG_FORMAT` env var ([f545d4d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f545d4d))
- Rule-level analytics queries and suggestion audit tracking ([0a1b7e5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0a1b7e5), [017a94b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/017a94b))
- Git branch detection module ([6bb91f9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6bb91f9))
- `DetailedEvaluationResult` and `evaluate_detailed()` API ([bb93259](https://github.com/Dicklesworthstone/destructive_command_guard/commit/bb93259))
- Config parser for new allowlist schema ([876beff](https://github.com/Dicklesworthstone/destructive_command_guard/commit/876beff))

### Security

- Backslash and quote obfuscation bypass detection ([8eaeaaa](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8eaeaaa))
- Safe pattern bypass prevention for compound commands ([e85a495](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e85a495))
- Heredoc scanning: skip non-executing targets (cat, tee, etc.) ([4be0358](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4be0358))
- Here-string (`<<<`) masking for non-executing commands ([831d637](https://github.com/Dicklesworthstone/destructive_command_guard/commit/831d637))

### Bug Fixes

- Docker-compose extractor quote handling for embedded commands ([90c01a0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/90c01a0))
- UTF-8 safe string handling in update and denial modules ([c62ec3e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c62ec3e))
- History FTS rebuild wrapped in transaction for atomicity ([82ee415](https://github.com/Dicklesworthstone/destructive_command_guard/commit/82ee415))
- CI blockers resolved for release builds ([999b9b1](https://github.com/Dicklesworthstone/destructive_command_guard/commit/999b9b1))

---

## [v0.2.12](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.12) -- 2026-01-15 [Tag]

Internal rename of the `telemetry` module to `history`.

### Refactoring

- Complete `telemetry` to `history` module rename across the codebase ([ddfc15d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ddfc15d))

---

## [v0.2.11](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.11) -- 2026-01-15 [Tag]

Introduces the full command history system and auto-configuration of agent hooks.

### Command History System

- **Command history system** with stats, export, and per-pack analysis (`dcg history stats`, `dcg history export`) ([59a33b1](https://github.com/Dicklesworthstone/destructive_command_guard/commit/59a33b1))
- Comprehensive history module integration tests ([c7802cc](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c7802cc))

### Installer & Agent Configuration

- Installer auto-configures Claude Code and Gemini CLI hooks with detailed feedback ([512c2d3](https://github.com/Dicklesworthstone/destructive_command_guard/commit/512c2d3))

### Performance

- Aho-Corasick quick-reject in `sanitize_for_pattern_matching` for faster false-positive elimination ([6c8afc6](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6c8afc6))

### Testing

- Security regression tests for normalization, safe pattern, and Windows bypasses ([f7324e2](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f7324e2))

---

## [v0.2.10](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.10) -- 2026-01-15 [Release]

Security hardening, performance improvements, and the history pruning command.

### Command History

- **History pruning** command ([06c6ea7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/06c6ea7))
- `DCG_TELEMETRY_*` env vars renamed to `DCG_HISTORY_*` ([d44bde6](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d44bde6))

### Security & Correctness

- Tier 1 bypass fixed for inline scripts with attached quotes (e.g. `bash -c"..."`) ([2890891](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2890891))
- Inline interpreter detection improved to avoid false positives on echoed commands ([3b426b0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3b426b0))
- Potential stack overflow in recursive heredoc scanning limited to depth 50 ([a8f24b0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a8f24b0))
- Quoted secrets with spaces now handled in redaction ([a04f570](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a04f570))

### Bug Fixes

- `xargs` regex robustness, simulated limits, and OOM protection ([77fa5fb](https://github.com/Dicklesworthstone/destructive_command_guard/commit/77fa5fb))
- Inline code detection improved for context module ([8d1ce05](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8d1ce05))

---

## [v0.2.9](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.9) -- 2026-01-14 [Release]

Codebase-wide rename from `telemetry` to `history` and Redis secret redaction.

### Refactoring

- Complete `telemetry` to `history` rename throughout codebase ([d0b2976](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d0b2976))

### Bug Fixes

- Redis `user:password` URL pattern added to secret redaction ([0d61117](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0d61117))

---

## [v0.2.8](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.8) -- 2026-01-14 [Tag]

Introduces the telemetry/history subsystem with persistent SQLite storage, CLI subcommands, secret redaction, and extensive normalizer hardening.

### Telemetry / History Subsystem

- **Telemetry CLI** subcommands for querying persistent command history ([fc2a7a8](https://github.com/Dicklesworthstone/destructive_command_guard/commit/fc2a7a8), [2e4ea76](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2e4ea76))
- **Secret redaction patterns** for telemetry storage ([dbe7159](https://github.com/Dicklesworthstone/destructive_command_guard/commit/dbe7159))
- Telemetry database migrations and config options ([15e3587](https://github.com/Dicklesworthstone/destructive_command_guard/commit/15e3587), [bb95341](https://github.com/Dicklesworthstone/destructive_command_guard/commit/bb95341))
- Comprehensive E2E test framework for telemetry ([13d1701](https://github.com/Dicklesworthstone/destructive_command_guard/commit/13d1701))

### Installer & Agent Configuration

- Claude Code `SKILL.md` for automatic capability discovery ([6f44dc7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6f44dc7))
- Installer auto-configures Claude Code and Gemini CLI idempotently ([3b8fc5f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3b8fc5f))

### Normalizer & Context Hardening

- Sanitize `git grep`/`ag`/`ack` search patterns to prevent false positives ([cf0565a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/cf0565a), [299df4b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/299df4b))
- Harden allowlist/pending exception parsing ([49fda98](https://github.com/Dicklesworthstone/destructive_command_guard/commit/49fda98))
- Avoid panics in production paths ([3e678b5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3e678b5))
- Apply scan globs after directory expansion ([82a7639](https://github.com/Dicklesworthstone/destructive_command_guard/commit/82a7639))
- Honor project pack overrides ([bcc9a20](https://github.com/Dicklesworthstone/destructive_command_guard/commit/bcc9a20))
- Handle path-prefixed wrappers, env quoted assignments, Dockerfile exec continuations, HCL block comments, inline YAML commas ([326ab3a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/326ab3a), [81fcc2e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/81fcc2e), [65d0fa6](https://github.com/Dicklesworthstone/destructive_command_guard/commit/65d0fa6), [3880cf3](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3880cf3), [c4ba22f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c4ba22f))
- Skip GitHub Actions `env`/`with` blocks during scan extraction ([9f6eab9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/9f6eab9))

### Bug Fixes

- TMPDIR shell default value syntax in safe path detection ([4a970b8](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4a970b8))
- `is_expired` made fail-closed on invalid timestamps ([84e607c](https://github.com/Dicklesworthstone/destructive_command_guard/commit/84e607c))
- CI failures in E2E, scan-regression, and coverage jobs ([f7a4d53](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f7a4d53), [dc82f6a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/dc82f6a))

---

## [v0.2.7](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.7) -- 2026-01-12 [Release]

Memory leak fix and version alignment.

### Bug Fixes

- Full pipeline memory test constrained to core packs to prevent leaks ([d8b1376](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d8b1376))

---

## [v0.2.6](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.6) -- 2026-01-12 [Release]

CI fix for macOS Intel builds.

### CI / Distribution

- macOS Intel builds moved to `macos-15-intel` runner (deprecation of `macos-13`) ([46c20d7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/46c20d7))

---

## [v0.2.5](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.5) -- 2026-01-12 [Release]

Memory test stabilization.

### Bug Fixes

- Warm up pipeline before leak check to avoid false positives ([02c0169](https://github.com/Dicklesworthstone/destructive_command_guard/commit/02c0169))

---

## [v0.2.4](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.4) -- 2026-01-12 [Release]

Lockfile pin for CI stability.

### Bug Fixes

- Pin `ciborium` to 0.2.2 in lockfile ([9f454c6](https://github.com/Dicklesworthstone/destructive_command_guard/commit/9f454c6))

---

## [v0.2.3](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.3) -- 2026-01-12 [Release]

Default config fix.

### Bug Fixes

- Enable common packs on default config load ([23fd149](https://github.com/Dicklesworthstone/destructive_command_guard/commit/23fd149))

---

## [v0.2.2](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.2) -- 2026-01-12 [Release]

Formatting fix.

### Maintenance

- Align confidence tests with rustfmt ([534d1ef](https://github.com/Dicklesworthstone/destructive_command_guard/commit/534d1ef))

---

## [v0.2.1](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.1) -- 2026-01-12 [Release]

Installer improvements with Gemini CLI support, binary size reduction, and portability fixes.

### Installer & Agent Support

- **Gemini CLI** support in installer with proper tool name and error handling ([3769dab](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3769dab))
- Auto-configure Claude Code/Codex and detect predecessor tools ([9929f7d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/9929f7d))
- `--easy-mode` promoted as the recommended install method ([75de506](https://github.com/Dicklesworthstone/destructive_command_guard/commit/75de506))

### Performance

- Binary size reduced 69% by trimming tree-sitter parsers ([d11670e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d11670e))

### Scanning & Detection

- Confidence tiering for warn-by-default patterns ([b31b4010](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b31b4010))
- Quote-aware heredoc operator detection ([4d20d9e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4d20d9e))
- Docker-compose extraction allowed without keywords ([c90a56b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c90a56b))
- Per-pack reference documentation generator ([56db566](https://github.com/Dicklesworthstone/destructive_command_guard/commit/56db566))

### Bug Fixes

- Installer portability improvements for BSD/macOS systems ([9f89544](https://github.com/Dicklesworthstone/destructive_command_guard/commit/9f89544))
- UTF-8 boundary panic prevented in confidence/operator detection ([44389a3](https://github.com/Dicklesworthstone/destructive_command_guard/commit/44389a3))
- Heredoc error message line numbers corrected ([d4b98b5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d4b98b5))
- Explain hint added to block messages ([156de92](https://github.com/Dicklesworthstone/destructive_command_guard/commit/156de92))
- Inline code context detection for attached `-c` flags ([b10c480](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b10c480))

---

## [v0.2.0](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.0) -- 2026-01-09 [Tag]

Foundational release representing the first tagged version of DCG with a mature feature set. Built over 300+ commits in two days of intensive multi-agent development.

### Core Detection Engine

- **Modular pack system** with 49+ security packs covering: core git/filesystem, databases (PostgreSQL, MySQL, Redis, MongoDB, SQLite), Kubernetes (kubectl, Helm, Kustomize), Docker/Podman/Compose, cloud providers (AWS, GCP, Azure), Terraform/Pulumi/Ansible, CI/CD (GitHub Actions, Jenkins, CircleCI, GitLab CI), CDN (CloudFront, Cloudflare Workers, Fastly), DNS (Route53, Cloudflare), backup tools (restic, rclone, borg, Velero), load balancers (ELB, nginx, HAProxy, Traefik), secrets management (Vault, AWS Secrets, Doppler, 1Password), monitoring (Datadog, Prometheus, Splunk, PagerDuty), email services (SES, SendGrid, Mailgun, Postmark), API gateways (Kong, Apigee, AWS API Gateway), search engines (Elasticsearch, Algolia, Meilisearch, OpenSearch), messaging (Kafka, RabbitMQ, NATS, SQS/SNS), storage (S3, GCS, MinIO, Azure Blob), feature flags (LaunchDarkly, Split, Unleash, Flipt), and payments (Stripe, Braintree, Square) ([f04ae36](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f04ae36aaecc027b7666504cd5aa7e0c2d922dda))
- **Aho-Corasick keyword prefilter** + per-pack `RegexSet` fast path for O(n) matching
- **Lazy regex compilation** with `LazyFancyRegex` -- patterns compiled on first use only
- **Pack-aware quick reject** -- skip entire packs when no keywords match ([635bb97](https://github.com/Dicklesworthstone/destructive_command_guard/commit/635bb97))
- **CompiledOverrides** for precompiled config regexes in the evaluator hot path ([2f2a979](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2f2a979))

### Heredoc & Inline Script Scanning

- **Two-tier heredoc detection** -- Tier 1 fast path for common patterns, Tier 2 AST-based content extraction ([1ca7745](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1ca7745), [891722e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/891722e))
- **AST pattern matching layer** for destructive operations in Python, Ruby, JavaScript, TypeScript, Perl, Go, Bash ([2ae7517](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2ae7517))
- Language detection with priority-based signals ([f9f1228](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f9f1228))
- Configurable heredoc scanning behavior ([81d9bde](https://github.com/Dicklesworthstone/destructive_command_guard/commit/81d9bde))
- Go language support for heredoc AST scanning ([a0a89bd](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a0a89bd))

### Smart Context Detection

- **Execution-context classification** -- distinguishes data contexts (strings, comments, grep patterns) from execution contexts ([14cb23a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/14cb23a), [e829144](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e829144))
- **Safe String-Argument Registry** v1 for reducing false positives on non-executing patterns ([341f24b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/341f24b))
- `sanitize_for_pattern_matching` integration for false-positive immunity ([55561a1](https://github.com/Dicklesworthstone/destructive_command_guard/commit/55561a1))

### CLI & User Interface

- **Explain mode** -- `dcg explain "command"` shows matching rules, packs, severity, and trace info ([4b01e6d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4b01e6d), [7d5a8fb](https://github.com/Dicklesworthstone/destructive_command_guard/commit/7d5a8fb))
- **Scan mode** for CI/CD -- extract and evaluate commands from GitHub Actions, Dockerfiles, Makefiles, shell scripts, docker-compose, and `package.json` ([1d915d5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1d915d5), [89ef9cd](https://github.com/Dicklesworthstone/destructive_command_guard/commit/89ef9cd))
- **Simulate mode** with output formats and redaction/truncation ([183862b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/183862b))
- Pre-commit hook install/uninstall for scan mode ([c8174c9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c8174c9))
- Markdown output format for PR comments ([c3428ff](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c3428ff))
- `--explain` and `--format` flags for the test command ([e032fd9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e032fd9))

### Policy & Allowlist System

- **Decision modes** (deny/warn/log) per rule ([d3e5499](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d3e5499))
- **Severity tagging** for core pack rules ([aeacc38](https://github.com/Dicklesworthstone/destructive_command_guard/commit/aeacc38))
- **Allowlist system** with expiration, conditions, risk acknowledgement, and wildcard pack matching ([0eff234](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0eff234), [58d683e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/58d683e), [78d0eee](https://github.com/Dicklesworthstone/destructive_command_guard/commit/78d0eee))
- **Observe mode** with `observe_until` warn-first rollout window ([d67fe7b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d67fe7b))
- Allowlist CLI commands ([600549d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/600549d))
- Allow-once audit logging ([d25f44f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d25f44f))

### Suggestions Engine

- **Suggestions engine** with safer alternative recommendations for all core patterns ([4948d6a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4948d6a), [53b48e7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/53b48e7))
- Docker, Kubernetes, and database suggestions ([dd525d0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/dd525d0))

### Performance & Resilience

- **Fail-open deadline enforcement** -- configurable timeout budget prevents DCG from blocking workflows ([ef9bb4a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ef9bb4a))
- **Performance benchmarks** for heredoc detection and core pipeline ([8456045](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8456045), [4ac432e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4ac432e))
- Performance budget constants and CI enforcement ([2a2b3b1](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2a2b3b1))
- Wrapper prefix stripping module for sudo/env/command normalization ([b2f02b8](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b2f02b8))

### Testing

- **E2E test framework** with comprehensive coverage of CLI flows, hook mode, scan mode, and security regressions ([3d4c216](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3d4c216), [39ee901](https://github.com/Dicklesworthstone/destructive_command_guard/commit/39ee901))
- **Cargo-fuzz harness** with 4 fuzz targets ([530e05f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/530e05f))
- **Property-based tests** for evaluator invariants ([b3b33a4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b3b33a4))
- Layered allowlist E2E tests ([42c4adb](https://github.com/Dicklesworthstone/destructive_command_guard/commit/42c4adb))
- Hook/CLI evaluator parity tests ([d08105e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d08105e))
- Coverage threshold enforcement in CI ([d40217a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d40217a))

### Infrastructure

- **Release automation** and self-updater foundation ([cb9f6b4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/cb9f6b4))
- Cross-platform CI: Linux (x86_64, aarch64), macOS (Intel, Apple Silicon), Windows
- Codecov integration for coverage tracking
- Dependabot configuration for automated dependency updates
- `install.sh` with `--easy-mode` flag, platform auto-detection, and predecessor tool migration

### Bug Fixes

- Regex backtracking panic in `normalize_command` ([4c5be16](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4c5be16))
- Stdin hang on clap parse errors ([17889ce](https://github.com/Dicklesworthstone/destructive_command_guard/commit/17889ce))
- UTF-8 safe preview truncation in AST matcher ([961bc8f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/961bc8f))
- Quoted command-word bypass ([1647112](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1647112))
- Temp-dir path traversal treated as catastrophic in AST matcher ([893887a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/893887a))
- Shell function declaration with spaced parens in scanner ([c19dc2a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c19dc2a))

---

## Initial Development -- 2026-01-07

The project began as `git_safety_guard`, a focused tool for blocking destructive git commands. It was renamed to **destructive_command_guard** (`dcg`) and expanded into a general-purpose destructive-command interceptor with the modular pack system.

- Initial commit ([1640612](https://github.com/Dicklesworthstone/destructive_command_guard/commit/16406128fc967a305b97f4cd8da1b537a4be7b6f))
- Comprehensive enhancements with colorful output, CI/CD, and tooling ([c686775](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c686775b745b5b81644323eb35df3a8920136f74))
- Rename to `destructive_command_guard` with modular pack system ([f04ae36](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f04ae36aaecc027b7666504cd5aa7e0c2d922dda))

---

## Release Matrix

| Version | Date | Type | Binaries |
|---------|------|------|----------|
| v0.4.3 | 2026-03-14 | Tag only | No |
| v0.4.2 | 2026-02-23 | Tag only | No |
| v0.4.1 | 2026-02-22 | Tag only | No |
| v0.4.0 | 2026-02-10 | **GitHub Release** | Yes |
| v0.3.0 | 2026-02-02 | **GitHub Release** | Yes |
| v0.2.15 | 2026-01-20 | **GitHub Release** | Yes |
| v0.2.14 | 2026-01-20 | Tag only | No |
| v0.2.13 | 2026-01-20 | Tag only | No |
| v0.2.12 | 2026-01-15 | Tag only | No |
| v0.2.11 | 2026-01-15 | Tag only | No |
| v0.2.10 | 2026-01-15 | **GitHub Release** | Yes |
| v0.2.9 | 2026-01-14 | **GitHub Release** | Yes |
| v0.2.8 | 2026-01-14 | Tag only | No |
| v0.2.7 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.6 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.5 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.4 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.3 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.2 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.1 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.0 | 2026-01-09 | Tag only | No |
