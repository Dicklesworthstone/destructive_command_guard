# dcg on Windows (native)

dcg runs as a **native Windows** binary (`x86_64-pc-windows-msvc` or
`aarch64-pc-windows-msvc`), not just under WSL. This page documents
Windows-specific behavior, paths, default protection, and honest limitations.
(Under WSL, dcg behaves exactly as on Linux — this page is about the native
`dcg.exe`.)

## Install / update / uninstall

Install with PowerShell:

```powershell
& ([scriptblock]::Create((irm "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/install.ps1"))) -EasyMode -Verify
```

- `-EasyMode` adds the install directory (`%USERPROFILE%\.local\bin` by default)
  to your **User** `PATH` and makes `dcg` available in the current session.
- `-Verify` runs a post-install self-test.
- `-Version vX.Y.Z` pins a specific release; `-Dest <dir>` changes the install
  location; `-ArtifactUrl <url|file://>` installs from a specific artifact.
- `-RequireMinisign` requires both the adjacent `.minisig` and the `minisign`
  verifier. `-MinisignSignatureUrl <url|file://>` overrides that sidecar source
  for mirrors and hermetic/offline installs.

The installer auto-selects `dcg-x86_64-pc-windows-msvc.zip` or
`dcg-aarch64-pc-windows-msvc.zip` from the host architecture, falling back to
the x64 artifact under Windows-on-ARM emulation if an older release has no
native ARM64 asset. It **verifies the SHA256 checksum** (required), verifies a
present `.minisig` against the embedded release key (key ID
`69B3955C8D2E62A8`) when `minisign` is on `PATH`, and independently verifies a
**Sigstore/cosign** signature against the pinned local-release key or GitHub
Actions OIDC identity when a patched `cosign` and trusted bundle are available.
The retired minisign key `36B847D11BA5A0D0` is accepted only for v0.6.7. A
present but invalid minisign signature is always fatal; by default a missing
sidecar/tool warns and continues unless `-RequireMinisign` is supplied.

Update via the built-in updater (re-runs `install.ps1`):

```powershell
dcg update
```

Windows cannot overwrite the `dcg.exe` process that is currently running.
`dcg update` therefore verifies and stages the pinned installer, launches a
worker through Windows process management, and returns. The worker survives
shell/process-job teardown, waits for the original dcg process to exit, and only
then replaces the binary. Progress and any installer error are appended as UTF-8
to `%LOCALAPPDATA%\dcg\update.log` (or the platform cache directory selected by
Windows when it differs). Use `dcg update --verify --no-configure` to update only
the binary while preserving all existing agent-hook wiring.

Uninstall:

```powershell
irm https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/uninstall.ps1 | iex
```

`uninstall.ps1` removes `dcg.exe`, the exact User `PATH` entry the installer
added, dcg-owned Claude Code and Codex hooks, and dcg config/history directories.

## File locations on Windows

dcg resolves its own config/state via the `dirs` crate (never hardcoded Unix paths):

| Layer | Location |
|-------|----------|
| User config | `%APPDATA%\dcg\config.toml` (and `~/.config/dcg/` is also honored) |
| User allowlist | `%APPDATA%\dcg\allowlist.toml` |
| **System config / allowlist** | The implicit `%ProgramData%\dcg\` layer is ignored on native Windows until dcg can validate ACLs, reparse points, and opened-file identity. An explicitly selected `DCG_CONFIG` or `DCG_ALLOWLIST_SYSTEM_PATH` remains user-trusted. |
| History DB / pending exceptions | under `%APPDATA%` / `%LOCALAPPDATA%` |
| Project config | Automatic `.dcg.toml` discovery is ignored on native Windows until equivalent path validation exists; use `DCG_CONFIG=.dcg.toml` after review for explicit full authority. |
| Project allowlist | `.dcg\allowlist.toml` is inactive unless `DCG_CONFIG` explicitly selects the reviewed repo-root `.dcg.toml`. |

`~`-prefixed paths in config expand from `%USERPROFILE%` (Windows has no `HOME`),
and both `~/` and `~\` are accepted.

Use `dcg config --format json` to see every attempted config source, the loaded
source, enabled packs, and the effective hook deadline. A second
`PreToolUse` entry in an agent settings file is not necessarily a duplicate:
`dcg doctor` distinguishes the single dcg-owned hook from unrelated hooks.

## Default protection on Windows

With **no config file**, a fresh Windows install enables these packs (in addition
to the always-on `core.filesystem` / `core.git` and default-on `system.disk`):

- **`windows.filesystem`** (default-on, opt-out with `disabled = ["windows.filesystem"]` or `["windows"]`):
  cmd `del /s`, `rd /s` / `rmdir /s`, `format <drive>:`; PowerShell `Remove-Item
  -Recurse` (with or without `-Force`) and its aliases (`rm`/`del`/`rd`/`ri`/`erase`), `Clear-Content`,
  `Clear-RecycleBin`, and the .NET recursive-delete APIs callable from plain
  PowerShell: `[System.IO.Directory]::Delete($path, $true)` (also the
  `[IO.Directory]` accelerator spelling) and `<DirectoryInfo>.Delete($true)`.
  Whitelists PowerShell `-WhatIf` previews only on
  cmdlets/aliases that honor it, plus deletes scoped to temp dirs.
- **`windows.system`** (default-on, opt-out as above): `vssadmin delete shadows`
  and `wmic shadowcopy delete` (Volume Shadow Copy destruction — a ransomware
  hallmark), `diskpart`, `Format-Volume`, `Clear-Disk`, `Remove-Partition`,
  `Initialize-Disk` / `Reset-PhysicalDisk`, `cipher /w`, `bcdedit /delete`.

Opt-in (registered but off until enabled, on every platform):

- **`windows.misc`**: `reg delete`, `net user|localgroup /delete`, `sc delete`,
  `schtasks /delete`, `wsl --unregister`, `robocopy /MIR`.
- **`windows.powershell`**: registry/provider deletes (`Remove-Item HKLM:\`,
  `Remove-ItemProperty`, `Remove-PSDrive`), `Remove-LocalUser`/`Remove-LocalGroup`,
  `Unregister-ScheduledTask`, `Disable-ComputerRestore`, forced
  `Stop-Computer`/`Restart-Computer`, `Remove-VM`/`Remove-AppxPackage`.

Enable the opt-in packs (e.g. to scan committed `.ps1`/`.cmd` scripts in CI) with
`[packs] enabled = ["windows"]` (whole category) or a specific sub-pack. All
Windows patterns are **case-insensitive** (`RD /S /Q` == `rd /s /q`,
`Remove-Item` == `remove-item`).

For workstations where an agent runs without interactive tool approval, the
opt-in `careful_company_running_windows` preset also enables the full Windows
category, Snowflake and other destructive service packs, and six additional
packs covering outbound mail/chat/uploads/transfers/tunnels and security-control
tampering. The preset applies equivalent policy outcomes to statically
inspectable PowerShell and `cmd.exe` hook events; shell-specific quoting,
escaping, control prefixes, chaining, and launcher syntax are interpreted
before matching. Its membership is curated rather than open-ended, so new dcg
packs do not enter the reused service categories in company policy without
review. See [Careful company policy for Windows
agents](careful-company-windows.md).

The preset receives a 3000 ms default hook deadline when no explicit
`hook_timeout_ms` or `DCG_HOOK_TIMEOUT_MS` is present. The normal default
remains 1000 ms. This accommodates cold evaluation of the preset's pinned pack
set on older Windows machines without weakening fail-closed behavior.

`dcg scan` understands PowerShell (`.ps1`/`.psm1`/`.psd1`) and Windows batch
(`.cmd`/`.bat`) scripts in addition to the cross-platform formats. Use
`--with-packs careful_company_running_windows` for an isolated scan without
changing persistent config. PowerShell scanning carries a bounded Outlook/CDO
COM construction through a later mail-item `Send()` instead of treating each
physical line independently.

## Per-agent hook coverage on Windows

Runtime protocol detection is platform-agnostic — every supported agent's hook
wire format is recognized on Windows. Hook *configuration* coverage:

| Agent | Config path | Configured by |
|-------|-------------|---------------|
| Codex CLI | `%USERPROFILE%\.codex\hooks.json` | `install.ps1` (automatic full JSON merge, UTF-8 **no BOM**) |
| Claude Code | `%USERPROFILE%\.claude\settings.json` | `install.ps1` (`Bash|PowerShell` matcher, PowerShell-safe absolute command, full JSON merge, UTF-8 **no BOM**) |
| Gemini CLI | `%USERPROFILE%\.gemini\settings.json` | `install.ps1` (full JSON merge, UTF-8 **no BOM**) |
| GitHub Copilot CLI | `%COPILOT_HOME%\hooks\dcg.json` or `%USERPROFILE%\.copilot\hooks\dcg.json` | `install.ps1` (automatic user-level JSON merge) when Copilot is detected, or with `-EasyMode` / `-Force`; protects every workspace |
| Cursor IDE | `%USERPROFILE%\.cursor\hooks.json` plus `%USERPROFILE%\.cursor\hooks\dcg-pre-shell.ps1` | `install.ps1` (pure PowerShell bridge; no Python dependency) |
| Hermes Agent | `%HERMES_HOME%\config.yaml` when `HERMES_HOME` is set, else `%LOCALAPPDATA%\hermes\config.yaml` (native Hermes never reads `%USERPROFILE%\.hermes` unless `HERMES_HOME` points there) | `install.ps1` (YAML merge when `powershell-yaml` is available; otherwise prints manual instructions for existing configs) |
| Grok (xAI) | `%USERPROFILE%\.grok\hooks\dcg.json` | `dcg install --grok` (cross-platform) |
| Antigravity (`agy`) | `%USERPROFILE%\.gemini\config\hooks.json` | `dcg install --agy` (cross-platform) |

## Limitations (honest)

- **Scheduled or already-running programs**: dcg evaluates shell commands
  exposed by an agent's hook. It does not interpose on Task Scheduler, Windows
  services, a separate human terminal, or network calls made later by an
  already-running process. Use a narrow `[overrides].block` rule to stop an
  agent from launching a known script, and disable the exact scheduled task
  separately when execution outside the agent must also stop. See
  [Stop a known mailer immediately](careful-company-windows.md#stop-a-known-mailer-immediately).
- **Codex `unified_exec`**: Codex's `PreToolUse` hooks do not intercept the
  `unified_exec` shell path used by **Codex Desktop / `codex exec` on Windows**
  for `command_execution` events. Commands routed that way are not blocked until
  Codex extends hook coverage upstream
  ([openai/codex#16246](https://github.com/openai/codex/issues/16246)). The simple
  per-tool shell path *is* intercepted. This is upstream, not fixable in dcg.
  Payloads on that path are named `Bash` but run through PowerShell on native
  Windows, so dcg evaluates them under the PowerShell dialect (#379); use
  `dcg test --dialect ps` to reproduce the hook's verdict from the CLI.
- **Runtime-built Cmd words**: dcg sees the command text supplied to the hook,
  not the future process environment. It decodes deterministic caret syntax and
  recursively inspects static `cmd /c`, `call`, `if`, `start`, and
  `for ... do` payloads, but `%VAR%` / delayed `!VAR!` expansion can synthesize
  an executable, option, or destination only after the hook returns. Dynamic
  nested-launcher payloads fail closed; direct runtime-built arguments cannot
  always be attributed to a concrete pack rule. Use endpoint/network egress
  controls as the independent boundary for that class of behavior.
- **Legacy conhost stderr color**: dcg enables Windows virtual-terminal
  processing for **stdout** at startup, so colored output renders correctly on
  legacy conhost. The blocked-command panel is written to **stderr**; modern
  consoles (Windows Terminal, PowerShell 7, Windows 10 1607+) enable VT for
  stderr automatically, but enabling it on *legacy* conhost's stderr handle would
  require an `unsafe SetConsoleMode`, which this crate forbids
  (`#![forbid(unsafe_code)]`). Set `NO_COLOR=1` for guaranteed plain output.
- **System config layer**: lives at `%ProgramData%\dcg` (there is no `/etc` on
  Windows); absent → the layer is simply not loaded.
- **History DB is best-effort telemetry under heavy concurrency.** The bundled
  upstream SQLite history DB is validated on real Windows by a CI stress test
  (`scripts/win_history_concurrency.ps1`): concurrent writer processes never
  corrupt it and a killed writer never wedges later runs. History writes are
  *best-effort* — under extreme concurrent-process contention a few decision
  records may not land, because logging must never block or break the security
  hook. This is **by design** (and reproduces on Linux too, so it is not a
  Windows-specific defect); the block/allow decision itself is always correct and
  the DB never corrupts. Sequential / normal use records every decision, and
  `history.max_size_mb` is enforced as a hard main-database page cap.
- **Fuzzing** stays Linux/macOS-only (`cargo-fuzz` does not support `windows-msvc`);
  it does not affect the shipping binary, which builds and tests on `windows-msvc`.
- **No Authenticode signature (decision).** `dcg.exe` is **not** Authenticode
  code-signed, so first-run on Windows may show a SmartScreen *"Windows protected
  your PC"* prompt or an unknown-publisher UAC dialog (choose **More info → Run
  anyway**). This is a deliberate decision, not an oversight:
  - Every release artifact has a mandatory **SHA-256 checksum**; starting with
    v0.6.7 it also has a long-lived **minisign** sidecar. The installer verifies
    the checksum unconditionally and the signature whenever `minisign` is
    available before clearing the **Mark-of-the-Web** (`Unblock-File`).
    Actions-OIDC releases can additionally carry a trusted, keyless
    **Sigstore/cosign** bundle.
  - An EV/OV Authenticode certificate carries real annual cost + identity-vetting
    overhead that doesn't fit a solo-maintainer, no-outside-contributions project;
    and SmartScreen *reputation* still accrues per-download even once signed, so a
    fresh certificate would not immediately remove the prompt.
  - If Windows demand grows, the lowest-friction path is **Azure Trusted Signing**
    (CI-time signing via `AzureSignTool` in `dist.yml`, verified with
    `signtool verify /pa`); revisit then. Until then, rely on the mandatory
    checksum plus the cosign verification path when a trusted bundle is present.

## Test harnesses on Windows

PowerShell ports of the shell E2E suites run on `windows-latest` CI (and locally):

- **`scripts/e2e_test.ps1`** — the full hook suite (`-Verbose`/`-Json`/`-Artifacts`):
  destructive/safe git + `rm` with every flag-ordering / quoting / variable-path /
  `sudo` / absolute-path variant, non-core packs, the **Windows-native pack group**
  (cmd `del`/`rd`/`format`/`reg delete`/`vssadmin`/…, PowerShell `Remove-Item -Recurse`
  with or without `-Force`/`Format-Volume`/…, wrapped `cmd /c`/`iex`/`-EncodedCommand`), and project
  allowlists.
- **`scripts/scan_precommit_e2e.ps1`** / **`scripts/scan_gitdiff_e2e.ps1`** — the
  `dcg scan --staged` and `dcg scan --git-diff <range>` subcommands (exit codes +
  JSON findings against throwaway git repos).
- **`tests/installer/*.ps1`** — per-function unit tests for the install/uninstall
  hook-merge logic (Claude/Codex/Gemini/Copilot/Cursor/Hermes, zip-slip, flags,
  local-source, checksum, agent detection, arch selection).
- **Real-Windows runtime stress (CI-gated):**
  `scripts/win_history_concurrency.ps1` (concurrent history-DB writers + killed-writer
  stale-lock recovery), `scripts/win_pending_exception_concurrency.ps1` (concurrent
  `LockFileEx` pending-exception ops, no sharing violations),
  `scripts/win_color_nocolor.ps1` (no raw ANSI escape leaks under NO_COLOR /
  redirection), `scripts/win_mcp_stdio.ps1` (`dcg mcp-server` stdio handshake with
  no first-read hang), `scripts/win_update_rollback.ps1` (`dcg update --rollback`
  running-binary swap), and `scripts/win_interactive_nontty.ps1` (interactive
  prompts never hang in non-TTY mode). These run on `windows-latest` every build.

Two checks have a residual that genuinely needs human eyes on real consoles and
stay **manual**: (1) **cross-console color rendering** — confirming colors look
correct and no literal `<-[33m` escapes appear in **cmd.exe**, **Windows
PowerShell**, and **Windows Terminal** (the escape-leak / NO_COLOR stripping
invariant behind it is automated above; the hand-written-escape paths are
unit-tested); and (2) **interactive keyboard navigation** — `Select` arrow-keys +
Enter, `Confirm` y/n, and Ctrl-C cancel in those same consoles (the non-TTY
no-hang / suppression invariant behind it is automated above).

**`scripts/e2e_destructive_equivalents.sh` stays Linux-only (by design).** That
1000-line harness is the source-of-truth for the Unix *recursive-force-delete
equivalence* epic; it exercises the same cross-platform binary, and the
Windows-relevant equivalence it would re-check — `rm -rf` flag orderings, quoting,
quoted/absolute binary paths, variable paths — is already asserted by
`e2e_test.ps1`'s destructive-`rm` and Windows-native scenario groups. Porting it
verbatim would duplicate that coverage without adding Windows-specific value, so it
is intentionally not ported.

## Troubleshooting

- **`dcg` not found after install**: `-EasyMode` updates the User `PATH`; open a
  new terminal (or it is available in the install session). Without `-EasyMode`,
  add `%USERPROFILE%\.local\bin` to `PATH` yourself.
- **`dcg update` / `dcg rollback`**: these shell out to `powershell.exe` and
  require it on `PATH`; update also uses the built-in CIM cmdlets to create a
  worker outside the initiating shell's process job. AppLocker, disabled WMI,
  or Constrained Language Mode may force the detached-process fallback. Update
  is staged until the running dcg process exits; inspect
  `%LOCALAPPDATA%\dcg\update.log` if the version does not change. Add
  `--no-configure` when hook files are managed separately.
- **cosign optional**: install verifies the checksum unconditionally and the
  Sigstore signature only when a trusted release bundle and cosign 2.6.2+ or
  3.0.4+ are present. Vulnerable/unknown cosign versions are not trusted.
- **minisign strict mode**: a present invalid signature always aborts. Use
  `-RequireMinisign` to also abort when the `.minisig` sidecar or verifier is
  unavailable; the current embedded key ID is `69B3955C8D2E62A8`.
- **Plain output**: `NO_COLOR=1`, `DCG_NO_COLOR=1`, or piping to a file disables
  all color/escape output.

See also: [README pack list](../README.md#modular-pack-system),
[Codex integration notes](codex-integration.md).
