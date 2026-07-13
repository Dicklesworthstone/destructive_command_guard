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

The installer auto-selects `dcg-x86_64-pc-windows-msvc.zip` or
`dcg-aarch64-pc-windows-msvc.zip` from the host architecture, falling back to
the x64 artifact under Windows-on-ARM emulation if an older release has no
native ARM64 asset. It **verifies the SHA256 checksum** (required), and verifies
the **Sigstore/cosign** signature when `cosign` is on `PATH` (falls back to
checksum-only otherwise).

Update via the built-in updater (re-runs `install.ps1`):

```powershell
dcg update
```

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
| **System config / allowlist** | `%ProgramData%\dcg\config.toml` / `allowlist.toml` (the Windows equivalent of `/etc/dcg`) |
| History DB / pending exceptions | under `%APPDATA%` / `%LOCALAPPDATA%` |
| Project config | `.dcg.toml` / `.dcg\allowlist.toml` in the repo root |

`~`-prefixed paths in config expand from `%USERPROFILE%` (Windows has no `HOME`),
and both `~/` and `~\` are accepted.

## Default protection on Windows

With **no config file**, a fresh Windows install enables these packs (in addition
to the always-on `core.filesystem` / `core.git` and default-on `system.disk`):

- **`windows.filesystem`** (default-on, opt-out with `disabled = ["windows.filesystem"]` or `["windows"]`):
  cmd `del /s`, `rd /s` / `rmdir /s`, `format <drive>:`; PowerShell `Remove-Item
  -Recurse -Force` and its aliases (`rm`/`del`/`rd`/`ri`/`erase`), `Clear-Content`,
  `Clear-RecycleBin`. Whitelists PowerShell `-WhatIf` previews only on
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

`dcg scan` understands PowerShell (`.ps1`/`.psm1`/`.psd1`) and Windows batch
(`.cmd`/`.bat`) scripts in addition to the cross-platform formats.

## Per-agent hook coverage on Windows

Runtime protocol detection is platform-agnostic — every supported agent's hook
wire format is recognized on Windows. Hook *configuration* coverage:

| Agent | Config path | Configured by |
|-------|-------------|---------------|
| Codex CLI | `%USERPROFILE%\.codex\hooks.json` | `install.ps1` (automatic full JSON merge, UTF-8 **no BOM**) |
| Claude Code | `%USERPROFILE%\.claude\settings.json` | `install.ps1` (full JSON merge, UTF-8 **no BOM**) |
| Gemini CLI | `%USERPROFILE%\.gemini\settings.json` | `install.ps1` (full JSON merge, UTF-8 **no BOM**) |
| GitHub Copilot CLI | `%COPILOT_HOME%\hooks\dcg.json` or `%USERPROFILE%\.copilot\hooks\dcg.json` | `install.ps1` (automatic user-level JSON merge) when Copilot is detected, or with `-EasyMode` / `-Force`; protects every workspace |
| Cursor IDE | `%USERPROFILE%\.cursor\hooks.json` plus `%USERPROFILE%\.cursor\hooks\dcg-pre-shell.ps1` | `install.ps1` (pure PowerShell bridge; no Python dependency) |
| Hermes Agent | `%USERPROFILE%\.hermes\config.yaml` | `install.ps1` (YAML merge when `powershell-yaml` is available; otherwise prints manual instructions for existing configs) |
| Grok (xAI) | `%USERPROFILE%\.grok\hooks\dcg.json` | `dcg install --grok` (cross-platform) |
| Antigravity (`agy`) | `%USERPROFILE%\.gemini\config\hooks.json` | `dcg install --agy` (cross-platform) |

## Limitations (honest)

- **Codex `unified_exec`**: Codex's `PreToolUse` hooks do not intercept the
  `unified_exec` shell path used by **Codex Desktop / `codex exec` on Windows**
  for `command_execution` events. Commands routed that way are not blocked until
  Codex extends hook coverage upstream
  ([openai/codex#16246](https://github.com/openai/codex/issues/16246)). The simple
  per-tool shell path *is* intercepted. This is upstream, not fixable in dcg.
- **Legacy conhost stderr color**: dcg enables Windows virtual-terminal
  processing for **stdout** at startup, so colored output renders correctly on
  legacy conhost. The blocked-command panel is written to **stderr**; modern
  consoles (Windows Terminal, PowerShell 7, Windows 10 1607+) enable VT for
  stderr automatically, but enabling it on *legacy* conhost's stderr handle would
  require an `unsafe SetConsoleMode`, which this crate forbids
  (`#![forbid(unsafe_code)]`). Set `NO_COLOR=1` for guaranteed plain output.
- **System config layer**: lives at `%ProgramData%\dcg` (there is no `/etc` on
  Windows); absent → the layer is simply not loaded.
- **History DB is best-effort telemetry under heavy concurrency.** The fsqlite
  history DB is validated on real Windows by a CI stress test
  (`scripts/win_history_concurrency.ps1`): concurrent writer processes never
  corrupt it and a killed writer never wedges later runs. History writes are
  *best-effort* — under extreme concurrent-process contention a few decision
  records may not land, because logging must never block or break the security
  hook. This is **by design** (and reproduces on Linux too, so it is not a
  Windows-specific defect); the block/allow decision itself is always correct and
  the DB never corrupts. Sequential / normal use records every decision.
- **Fuzzing** stays Linux/macOS-only (`cargo-fuzz` does not support `windows-msvc`);
  it does not affect the shipping binary, which builds and tests on `windows-msvc`.
- **No Authenticode signature (decision).** `dcg.exe` is **not** Authenticode
  code-signed, so first-run on Windows may show a SmartScreen *"Windows protected
  your PC"* prompt or an unknown-publisher UAC dialog (choose **More info → Run
  anyway**). This is a deliberate decision, not an oversight:
  - Supply-chain provenance is already covered by **Sigstore/cosign** signing of
    every release artifact (keyless, verifiable — see the install flow), and the
    installer additionally verifies the **SHA-256 checksum** unconditionally and
    clears the **Mark-of-the-Web** (`Unblock-File`) after verification.
  - An EV/OV Authenticode certificate carries real annual cost + identity-vetting
    overhead that doesn't fit a solo-maintainer, no-outside-contributions project;
    and SmartScreen *reputation* still accrues per-download even once signed, so a
    fresh certificate would not immediately remove the prompt.
  - If Windows demand grows, the lowest-friction path is **Azure Trusted Signing**
    (CI-time signing via `AzureSignTool` in `dist.yml`, verified with
    `signtool verify /pa`); revisit then. Until then, rely on the cosign
    verification path documented above.

## Test harnesses on Windows

PowerShell ports of the shell E2E suites run on `windows-latest` CI (and locally):

- **`scripts/e2e_test.ps1`** — the full hook suite (`-Verbose`/`-Json`/`-Artifacts`):
  destructive/safe git + `rm` with every flag-ordering / quoting / variable-path /
  `sudo` / absolute-path variant, non-core packs, the **Windows-native pack group**
  (cmd `del`/`rd`/`format`/`reg delete`/`vssadmin`/…, PowerShell `Remove-Item -Recurse
  -Force`/`Format-Volume`/…, wrapped `cmd /c`/`iex`/`-EncodedCommand`), and project
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
- **`dcg update` / `dcg rollback`**: these shell out to `powershell` and require
  it on `PATH`; they may be restricted under AppLocker / Constrained Language Mode.
- **cosign optional**: install verifies the checksum unconditionally and the
  Sigstore signature only when `cosign` is present.
- **Plain output**: `NO_COLOR=1`, `DCG_NO_COLOR=1`, or piping to a file disables
  all color/escape output.

See also: [README pack list](../README.md#modular-pack-system),
[Codex integration notes](codex-integration.md).
