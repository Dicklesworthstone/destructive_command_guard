# Careful Company (Windows) Preset

This document describes packs in the `careful_company_running_windows` category.

## Packs in this Category

- [Careful Company: Chat & Webhook Egress](#careful_company_running_windowschat)
- [Careful Company: Outbound Email](#careful_company_running_windowsemail)
- [Careful Company: Guardrail Tampering](#careful_company_running_windowsguardrails)
- [Careful Company: File-Transfer Egress](#careful_company_running_windowstransfer)
- [Careful Company: Tunnels & Raw Channels](#careful_company_running_windowstunnel)
- [Careful Company: HTTP Upload Egress](#careful_company_running_windowsupload)

---

## Careful Company: Chat & Webhook Egress

**Pack ID:** `careful_company_running_windows.chat`

Blocks posting to outbound chat and webhook destinations: Slack incoming webhooks and Web API writes, Microsoft Teams connectors and Power Automate triggers, Discord webhooks, Telegram bot API, Google Chat spaces, Twilio messages, Zapier/IFTTT hooks, PagerDuty events, and request catchers such as webhook.site and interact.sh.

### Keywords

Commands containing these keywords are checked against this pack:

- `slack`
- `Slack`
- `SLACK`
- `hooks`
- `Hooks`
- `HOOKS`
- `webhook`
- `Webhook`
- `WEBHOOK`
- `office.com`
- `logic.azure.com`
- `discord`
- `Discord`
- `DISCORD`
- `telegram`
- `Telegram`
- `twilio`
- `Twilio`
- `zapier`
- `ifttt`
- `IFTTT`
- `chat.googleapis.com`
- `pagerduty`
- `PagerDuty`
- `mattermost`
- `Mattermost`
- `requestbin`
- `pipedream`
- `beeceptor`
- `interact.sh`
- `oast.`
- `burpcollaborator`
- `requestcatcher`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `read-only-data-context` | `(?i)^\s*(?:sudo\s+)?(?:select-string\|sls\|findstr\|rg\|ripgrep\|grep\|egrep\|fgrep\|ack\|ag\|get-content\|gc\|cat\|type\|more\|head\|tail\|bat\|code(?!(?:-insiders)?(?:\.exe\|\.cmd)?\s+(?:tunnel\|serve-web\|serve)\b)\|notepad\|notepad\+\+\|vim\|nvim\|nano\|less\|get-help\|help\|man\|get-command\|gcm\|git\s+(?:log\|grep\|show\|diff\|blame\|status))\b[^\|&;<>\r\n]*$` |
| `dcg-self-inspection` | `(?i)^\s*(?:[a-z]:[\\/][^\s\|&;<>]*[\\/])?dcg(?:\.exe)?\s+(?:test\|explain\|scan\|simulate\|corpus\|packs\|doctor\|history\|stats\|suggest-allowlist\|allowlist\s+(?:list\|validate))\b[^\|&;<>\r\n]*$` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `slack-incoming-webhook` | Posting to a Slack incoming webhook sends data into a Slack channel. | high |
| `slack-web-api-write` | Slack Web API write methods post messages or upload files to Slack. | high |
| `teams-connector-webhook` | Posting to a Microsoft Teams connector webhook sends data into a Teams channel. | high |
| `power-automate-trigger` | Triggering a Power Automate / Logic Apps workflow URL sends the payload outside this machine. | high |
| `discord-webhook` | Posting to a Discord webhook publishes data into a Discord channel. | high |
| `telegram-bot-api` | The Telegram bot API sends messages and documents to a chat. | high |
| `google-chat-webhook` | Posting to a Google Chat space webhook publishes data into that space. | high |
| `twilio-message-send` | The Twilio Messages API sends SMS or WhatsApp messages to arbitrary numbers. | high |
| `automation-platform-webhook` | Zapier/IFTTT/PagerDuty event hooks forward the payload to a third-party automation. | high |
| `request-catcher-service` | Request-catcher services record whatever is sent to them. | high |
| `generic-incoming-webhook` | A long opaque token under a /hooks/ path is an incoming-webhook endpoint. | medium |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "careful_company_running_windows.chat:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "careful_company_running_windows.chat:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Careful Company: Outbound Email

**Pack ID:** `careful_company_running_windows.email`

Blocks sending email from the workstation: `Send-MailMessage`, `System.Net.Mail.SmtpClient`, Outlook COM automation, Microsoft Graph `sendMail`, transactional mail-API send endpoints (SendGrid/Mailgun/Postmark/Resend/SparkPost/Brevo/Mailjet), `aws ses send-email`, and SMTP CLI tools (`blat`, `swaks`, `msmtp`, `curl --mail-rcpt`).

### Keywords

Commands containing these keywords are checked against this pack:

- `Send-MailMessage`
- `send-mailmessage`
- `SEND-MAILMESSAGE`
- `SmtpClient`
- `smtpclient`
- `SMTPCLIENT`
- `MailMessage`
- `mailmessage`
- `Net.Mail`
- `net.mail`
- `NET.MAIL`
- `Outlook.Application`
- `outlook.application`
- `OUTLOOK.APPLICATION`
- `CDO.Message`
- `cdo.message`
- `CDO.MESSAGE`
- `GetTypeFromProgID`
- `gettypefromprogid`
- `smtp`
- `Smtp`
- `SMTP`
- `mail-from`
- `mail-rcpt`
- `sendMail`
- `sendmail`
- `SendMail`
- `SENDMAIL`
- `MgUser`
- `mguser`
- `MGUSER`
- `send-email`
- `send-raw-email`
- `send-bulk-email`
- `send-templated-email`
- `InboxRule`
- `inboxrule`
- `Set-Mailbox`
- `set-mailbox`
- `ForwardTo`
- `forwardto`
- `ForwardingSmtpAddress`
- `forwardingsmtpaddress`
- `ForwardingAddress`
- `RedirectTo`
- `TransportRule`
- `transportrule`
- `blat`
- `BLAT`
- `swaks`
- `SWAKS`
- `msmtp`
- `mailsend`
- `sendemail`
- `api.sendgrid.com`
- `mailgun.net`
- `api.postmarkapp.com`
- `api.resend.com`
- `api.sparkpost.com`
- `api.brevo.com`
- `api.mailjet.com`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `read-only-data-context` | `(?i)^\s*(?:sudo\s+)?(?:select-string\|sls\|findstr\|rg\|ripgrep\|grep\|egrep\|fgrep\|ack\|ag\|get-content\|gc\|cat\|type\|more\|head\|tail\|bat\|code(?!(?:-insiders)?(?:\.exe\|\.cmd)?\s+(?:tunnel\|serve-web\|serve)\b)\|notepad\|notepad\+\+\|vim\|nvim\|nano\|less\|get-help\|help\|man\|get-command\|gcm\|git\s+(?:log\|grep\|show\|diff\|blame\|status))\b[^\|&;<>\r\n]*$` |
| `dcg-self-inspection` | `(?i)^\s*(?:[a-z]:[\\/][^\s\|&;<>]*[\\/])?dcg(?:\.exe)?\s+(?:test\|explain\|scan\|simulate\|corpus\|packs\|doctor\|history\|stats\|suggest-allowlist\|allowlist\s+(?:list\|validate))\b[^\|&;<>\r\n]*$` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `send-mailmessage` | Send-MailMessage sends email from this machine to arbitrary recipients. | high |
| `dotnet-smtp-client` | System.Net.Mail.SmtpClient sends email directly from .NET, bypassing Send-MailMessage. | high |
| `outlook-com-send` | Outlook/CDO COM automation sends mail as the signed-in user through the real mail client. | high |
| `curl-smtp-send` | curl can speak SMTP directly; --mail-from/--mail-rcpt sends email. | high |
| `graph-send-mail` | Microsoft Graph sendMail sends email as the authenticated mailbox. | high |
| `mail-api-send-endpoint` | POST to a transactional mail-API send endpoint delivers email to arbitrary recipients. | high |
| `aws-ses-send` | aws ses send-email delivers email to arbitrary recipients from the CLI. | high |
| `mail-forwarding-rule` | A mailbox forwarding rule keeps sending mail outward long after the command finishes. | critical |
| `smtp-cli-tool` | blat/swaks/msmtp/mailsend/sendemail and `git send-email` are command-line mail senders. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "careful_company_running_windows.email:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "careful_company_running_windows.email:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Careful Company: Guardrail Tampering

**Pack ID:** `careful_company_running_windows.guardrails`

Blocks disabling the controls that supervise the agent: Microsoft Defender (`Set-MpPreference -Disable*`/`-ExclusionPath`), the Windows firewall, EDR and event-log services, BitLocker, `Set-ExecutionPolicy Bypass`, PowerShell script-block logging, event-log clearing (`wevtutil cl`, `auditpol /clear`), and dcg's own bypass/uninstall, allowlist grants, runtime config overrides, or agent hook config. Also blocks unreviewed remote code: `iwr | iex`, `powershell -EncodedCommand`, and mshta/regsvr32/rundll32 remote payloads.

### Keywords

Commands containing these keywords are checked against this pack:

- `MpPreference`
- `mppreference`
- `MpComputerStatus`
- `Defender`
- `defender`
- `DEFENDER`
- `netsh`
- `NETSH`
- `advfirewall`
- `ADVFIREWALL`
- `NetFirewall`
- `netfirewall`
- `wevtutil`
- `WEVTUTIL`
- `Clear-EventLog`
- `clear-eventlog`
- `Remove-EventLog`
- `auditpol`
- `AUDITPOL`
- `Set-ExecutionPolicy`
- `set-executionpolicy`
- `SET-EXECUTIONPOLICY`
- `BitLocker`
- `bitlocker`
- `BITLOCKER`
- `manage-bde`
- `MANAGE-BDE`
- `ScriptBlockLogging`
- `scriptblocklogging`
- `Transcription`
- `transcription`
- `LogPipelineExecutionDetails`
- `WinDefend`
- `windefend`
- `Sysmon`
- `sysmon`
- `SYSMON`
- `powershell`
- `PowerShell`
- `POWERSHELL`
- `Powershell`
- `pwsh`
- `PWSH`
- `Stop-Service`
- `stop-service`
- `sc delete`
- `sc stop`
- `sc config`
- `sc.exe`
- `net stop`
- `net.exe stop`
- `DCG_BYPASS`
- `dcg`
- `DCG`
- `uninstall.ps1`
- `settings.json`
- `hooks.json`
- `.claude`
- `.codex`
- `.cursor`
- `.gemini`
- `.copilot`
- `.grok`
- `.hermes`
- `iex`
- `IEX`
- `Iex`
- `Invoke-Expression`
- `invoke-expression`
- `DownloadString`
- `downloadstring`
- `EncodedCommand`
- `encodedcommand`
- `mshta`
- `MSHTA`
- `regsvr32`
- `REGSVR32`
- `rundll32`
- `RUNDLL32`
- `certutil`
- `CERTUTIL`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `read-only-data-context` | `(?i)^\s*(?:sudo\s+)?(?:select-string\|sls\|findstr\|rg\|ripgrep\|grep\|egrep\|fgrep\|ack\|ag\|get-content\|gc\|cat\|type\|more\|head\|tail\|bat\|code(?!(?:-insiders)?(?:\.exe\|\.cmd)?\s+(?:tunnel\|serve-web\|serve)\b)\|notepad\|notepad\+\+\|vim\|nvim\|nano\|less\|get-help\|help\|man\|get-command\|gcm\|git\s+(?:log\|grep\|show\|diff\|blame\|status))\b[^\|&;<>\r\n]*$` |
| `dcg-self-inspection` | `(?i)^\s*(?:[a-z]:[\\/][^\s\|&;<>]*[\\/])?dcg(?:\.exe)?\s+(?:test\|explain\|scan\|simulate\|corpus\|packs\|doctor\|history\|stats\|suggest-allowlist\|allowlist\s+(?:list\|validate))\b[^\|&;<>\r\n]*$` |
| `execution-policy-process-scope` | `(?i)^\s*set-executionpolicy\b[^\|&;<>\r\n]*\s-sc(?:o(?:p(?:e)?)?)?\s+process\b[^\|&;<>\r\n]*$` |
| `security-status-query` | `(?i)^\s*(?:get-mppreference\|get-mpcomputerstatus\|get-mpthreat\w*\|get-netfirewall\w*\|get-service\|get-executionpolicy\|get-eventlog\|get-winevent\|get-bitlockervolume\|get-scheduledtask\|get-localuser\|sc(?:\.exe)?\s+query\|auditpol(?:\.exe)?\s+/get\|wevtutil(?:\.exe)?\s+(?:el\|gl\|gli\|qe\|epl)\|manage-bde(?:\.exe)?\s+-status\|netsh(?:\.exe)?\s+advfirewall\s+show\|dcg(?:\.exe)?\s+(?:--version\|-V\|status))\b[^\|&;<>\r\n]*$` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `disable-antivirus` | Disabling Defender or adding a scan exclusion removes malware protection. | critical |
| `disable-firewall` | Turning off the Windows firewall removes host network protection. | critical |
| `stop-security-service` | Stopping or deleting a security/EDR/event-log service blinds the monitoring stack. | critical |
| `clear-audit-logs` | Clearing the Windows event logs destroys the record of what happened on this machine. | critical |
| `disable-disk-encryption` | Disabling BitLocker decrypts the volume and removes at-rest protection. | high |
| `set-execution-policy-bypass` | Set-ExecutionPolicy Bypass persistently allows any script to run on this machine. | high |
| `disable-powershell-logging` | Disabling PowerShell script-block logging removes the record of what scripts ran. | high |
| `dcg-bypass-or-uninstall` | Bypassing or uninstalling dcg removes the guard that is supervising this session. | critical |
| `dcg-policy-self-weakening` | Granting an allowlist exception or overriding pack/policy config lets the agent clear its own path. | critical |
| `agent-hook-config-tamper` | Editing or deleting the agent's hook configuration can silently remove dcg's protection. | high |
| `agent-hook-config-overwrite` | Copying a file ONTO the agent's hook configuration replaces it and can silently remove dcg's protection. | high |
| `download-and-execute` | Fetching code and piping it straight into Invoke-Expression runs unreviewed remote code. | critical |
| `powershell-encoded-command` | powershell -EncodedCommand hides the command being run behind base64. | critical |
| `lolbin-remote-execution` | mshta/regsvr32/rundll32 pointed at a remote payload execute code from the internet. | critical |
| `lolbin-remote-download` | certutil -urlcache downloads a file from the internet using a certificate utility. | medium |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "careful_company_running_windows.guardrails:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "careful_company_running_windows.guardrails:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Careful Company: File-Transfer Egress

**Pack ID:** `careful_company_running_windows.transfer`

Blocks outbound file transfer: scp/pscp/sftp/psftp/WinSCP to a remote destination, scripted FTP and `tftp put`, rsync to a remote, rclone to a remote, cloud-storage uploads (`aws s3 cp` local->s3://, `s3api put-object`, `az storage blob upload`, azcopy, `gsutil cp`->gs://, b2/s3cmd/mc/wrangler r2/supabase), peer-to-peer senders (croc/wormhole/ffsend/Taildrop), WebDAV mounts, and copy LOLBins (`esentutl /y`, `print /D:`, `diantz`). Package publishes and git remote-URL changes warn.

### Keywords

Commands containing these keywords are checked against this pack:

- `scp`
- `SCP`
- `Scp`
- `pscp`
- `PSCP`
- `sftp`
- `SFTP`
- `psftp`
- `winscp`
- `WinSCP`
- `WINSCP`
- `rsync`
- `RSYNC`
- `ftp`
- `FTP`
- `Ftp`
- `rclone`
- `RCLONE`
- `Rclone`
- `azcopy`
- `AzCopy`
- `AZCOPY`
- `azcopy.exe`
- `s3://`
- `S3://`
- `gs://`
- `GS://`
- `ss:///`
- `put-object`
- `upload-part`
- `blob upload`
- `storage blob`
- `file upload`
- `upload-batch`
- `upload-file`
- `s3cmd`
- `mc cp`
- `mc mirror`
- `r2 object`
- `supabase`
- `croc`
- `CROC`
- `wormhole`
- `ffsend`
- `tailscale`
- `Tailscale`
- `New-PSDrive`
- `new-psdrive`
- `net use`
- `NET USE`
- `Net Use`
- `net.exe use`
- `DavWWWRoot`
- `davwwwroot`
- `@SSL`
- `@ssl`
- `esentutl`
- `ESENTUTL`
- `diantz`
- `DIANTZ`
- `/D:`
- `/d:`
- `publish`
- `Publish`
- `PUBLISH`
- `nuget`
- `NuGet`
- `twine`
- `gem push`
- `mvn deploy`
- `git`
- `Git`
- `GIT`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `read-only-data-context` | `(?i)^\s*(?:sudo\s+)?(?:select-string\|sls\|findstr\|rg\|ripgrep\|grep\|egrep\|fgrep\|ack\|ag\|get-content\|gc\|cat\|type\|more\|head\|tail\|bat\|code(?!(?:-insiders)?(?:\.exe\|\.cmd)?\s+(?:tunnel\|serve-web\|serve)\b)\|notepad\|notepad\+\+\|vim\|nvim\|nano\|less\|get-help\|help\|man\|get-command\|gcm\|git\s+(?:log\|grep\|show\|diff\|blame\|status))\b[^\|&;<>\r\n]*$` |
| `dcg-self-inspection` | `(?i)^\s*(?:[a-z]:[\\/][^\s\|&;<>]*[\\/])?dcg(?:\.exe)?\s+(?:test\|explain\|scan\|simulate\|corpus\|packs\|doctor\|history\|stats\|suggest-allowlist\|allowlist\s+(?:list\|validate))\b[^\|&;<>\r\n]*$` |
| `internal-ssh-target` | `(?i)^\s*(?:scp\|pscp\|sftp\|psftp\|rsync)(?:\.exe)?\b[^\|&;<>\r\n]*\s(?:[\x22'](?:[a-z0-9._%+-]+@)?(?:localhost\|127\.\d{1,3}\.\d{1,3}\.\d{1,3}\|10\.\d{1,3}\.\d{1,3}\.\d{1,3}\|192\.168\.\d{1,3}\.\d{1,3}\|172\.(?:1[6-9]\|2\d\|3[01])\.\d{1,3}\.\d{1,3}\|[a-z0-9-]{2,}\|[a-z0-9.-]+\.(?:internal\|corp\|local\|localdomain\|lan\|intranet)):[^\x22']*[\x22']\|(?:[a-z0-9._%+-]+@)?(?:localhost\|127\.\d{1,3}\.\d{1,3}\.\d{1,3}\|10\.\d{1,3}\.\d{1,3}\.\d{1,3}\|192\.168\.\d{1,3}\.\d{1,3}\|172\.(?:1[6-9]\|2\d\|3[01])\.\d{1,3}\.\d{1,3}\|[a-z0-9-]{2,}\|[a-z0-9.-]+\.(?:internal\|corp\|local\|localdomain\|lan\|intranet)):\S*)\s*$` |
| `internal-sftp-session` | `(?i)^\s*(?:sftp\|psftp)(?:\.exe)?\b[^\|&;<>\r\n]*\s(?:[a-z0-9._%+-]+@)?(?:localhost\|127\.\d{1,3}\.\d{1,3}\.\d{1,3}\|10\.\d{1,3}\.\d{1,3}\.\d{1,3}\|192\.168\.\d{1,3}\.\d{1,3}\|172\.(?:1[6-9]\|2\d\|3[01])\.\d{1,3}\.\d{1,3}\|[a-z0-9-]+\|[a-z0-9.-]+\.(?:internal\|corp\|local\|localdomain\|lan\|intranet))\s*$` |
| `internal-registry-publish` | `(?i)^\s*(?:dotnet\s+)?(?:npm\|yarn\|pnpm\|bun\|twine\|poetry\|flit\|uv\|hatch\|cargo\|gem\|mvn\|gradle\|nuget)\b[^\|&;<>\r\n]*\s(?:--registry\|--repository-url\|--source\|-s)(?:=\|\s+)[\x22']?(?:https?://(?:localhost\|127\.\d{1,3}\.\d{1,3}\.\d{1,3}\|10\.\d{1,3}\.\d{1,3}\.\d{1,3}\|192\.168\.\d{1,3}\.\d{1,3}\|172\.(?:1[6-9]\|2\d\|3[01])\.\d{1,3}\.\d{1,3}\|[a-z0-9.-]+\.(?:internal\|corp\|local\|lan\|intranet))(?:[:/?#]\|\s\|$)\|[a-z]:[\\/]\|\\\\)[^\|&;<>\r\n]*$` |
| `package-publish-dry-run` | `(?i)^\s*(?:npm\|pnpm\|yarn\|bun\|cargo)\s+publish\b[^\|&;<>\r\n]*\s--dry-run\b[^\|&;<>\r\n]*$` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `scp-destination-unverified` | scp/pscp has a runtime-dependent or malformed destination whose perimeter cannot be verified. | high |
| `scp-to-remote` | scp with a remote destination copies local files off this machine. | high |
| `transfer-script-with-visible-put` | An sftp/WinSCP command with a visible put uploads the named file. | high |
| `sftp-remote-session` | An sftp session to an external host is an interactive transfer channel. | medium |
| `opaque-transfer-script` | A scripted sftp/ftp/WinSCP session runs transfer commands that are not visible here. | medium |
| `rsync-to-remote` | rsync with a remote destination copies local files off this machine. | high |
| `tftp-put` | tftp put uploads a local file to a remote host. | high |
| `rclone-to-remote` | rclone copying to a configured remote sends data to that provider. | high |
| `rclone-stream-or-publish` | rclone rcat/link/serve streams data out, mints a public URL, or exposes a local directory. | high |
| `aws-s3-upload` | aws s3 cp/sync/mv from a local path to s3:// uploads data to S3. | high |
| `aws-s3-api-upload` | s3api put-object uploads a local file to S3. | high |
| `aws-s3-presign` | aws s3 presign mints a URL that anyone holding it can fetch. | medium |
| `azure-blob-upload` | az storage blob upload / azcopy sends local files to Azure Storage. | high |
| `gcs-upload` | gsutil/gcloud storage cp from a local path to gs:// uploads data to Cloud Storage. | high |
| `object-store-cli-upload` | b2/s3cmd/mc/wrangler r2/supabase upload local files to object storage. | high |
| `peer-to-peer-file-send` | croc/magic-wormhole/ffsend/Taildrop send files directly to another party. | high |
| `webdav-remote-mount` | Mounting a WebDAV/HTTP location as a drive creates a file-copy channel over the web. | high |
| `copy-lolbin-to-remote` | esentutl /y, diantz, and print /D: copy files to a remote share while posing as other tools. | high |
| `package-publish-to-registry` | Publishing a package uploads the project's contents to a registry. | medium |
| `git-remote-url-change` | Adding or repointing a git remote changes where a later push sends the repository. | medium |
| `git-push-explicit-url` | Pushing to a URL instead of a named remote sends the repository to an ad-hoc destination. | medium |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "careful_company_running_windows.transfer:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "careful_company_running_windows.transfer:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Careful Company: Tunnels & Raw Channels

**Pack ID:** `careful_company_running_windows.tunnel`

Blocks channels that expose the workstation or bypass network inspection: ngrok, cloudflared, devtunnel/`code tunnel`, localtunnel, `tailscale funnel`, `ssh -R`/`-D` reverse and SOCKS forwards, chisel/frp/gost/zrok/bore, ncat/netcat/socat, PowerShell raw sockets, `netsh interface portproxy`, DNS tunnels (dnscat2/iodine), out-of-band callback domains, and DNS labels long enough to be carrying encoded data.

### Keywords

Commands containing these keywords are checked against this pack:

- `ngrok`
- `Ngrok`
- `NGROK`
- `cloudflared`
- `CLOUDFLARED`
- `tunnel`
- `Tunnel`
- `TUNNEL`
- `devtunnel`
- `localtunnel`
- `serve-web`
- `--port`
- `lt -p`
- `tailscale`
- `Tailscale`
- `funnel`
- `Funnel`
- `chisel`
- `frpc`
- `frps`
- `gost`
- `zrok`
- `bore.pub`
- `bore`
- `serveo`
- `localhost.run`
- `pinggy`
- `trycloudflare`
- `loca.lt`
- `ngrok.io`
- `ngrok-free`
- `ncat`
- `NCAT`
- `netcat`
- `NETCAT`
- `nc.exe`
- `NC.EXE`
- `nc`
- `socat`
- `SOCAT`
- `Sockets`
- `sockets`
- `TcpClient`
- `tcpclient`
- `UdpClient`
- `udpclient`
- `ClientWebSocket`
- `clientwebsocket`
- `portproxy`
- `PORTPROXY`
- `ssh`
- `SSH`
- `plink`
- `PLINK`
- `autossh`
- `dnscat`
- `iodine`
- `dnsteal`
- `dns2tcp`
- `chashell`
- `dnsexfiltrator`
- `nslookup`
- `NSLOOKUP`
- `Resolve-DnsName`
- `resolve-dnsname`
- `oast.`
- `OAST.`
- `interact.sh`
- `Interact.sh`
- `INTERACT.SH`
- `oastify`
- `OASTIFY`
- `burpcollaborator`
- `BURPCOLLABORATOR`
- `dnslog.cn`
- `DNSLOG.CN`
- `canarytokens`
- `requestrepo`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `read-only-data-context` | `(?i)^\s*(?:sudo\s+)?(?:select-string\|sls\|findstr\|rg\|ripgrep\|grep\|egrep\|fgrep\|ack\|ag\|get-content\|gc\|cat\|type\|more\|head\|tail\|bat\|code(?!(?:-insiders)?(?:\.exe\|\.cmd)?\s+(?:tunnel\|serve-web\|serve)\b)\|notepad\|notepad\+\+\|vim\|nvim\|nano\|less\|get-help\|help\|man\|get-command\|gcm\|git\s+(?:log\|grep\|show\|diff\|blame\|status))\b[^\|&;<>\r\n]*$` |
| `dcg-self-inspection` | `(?i)^\s*(?:[a-z]:[\\/][^\s\|&;<>]*[\\/])?dcg(?:\.exe)?\s+(?:test\|explain\|scan\|simulate\|corpus\|packs\|doctor\|history\|stats\|suggest-allowlist\|allowlist\s+(?:list\|validate))\b[^\|&;<>\r\n]*$` |
| `network-diagnostics` | `(?i)^\s*(?:test-netconnection\|tnc\|test-connection\|ping\|tracert\|pathping\|arp\|netstat\|route\s+print\|ipconfig\|get-nettcpconnection)\b(?![^\|&;<>\r\n]*(?:oast\.\|oastify\.com\|interact\.sh\|burpcollaborator\.net\|dnslog\.cn\|canarytokens\.com\|requestrepo\.com))[^\|&;<>\r\n]*$` |
| `netcat-zero-io-probe` | `(?i)^\s*(?:nc\|ncat\|netcat)(?:\.exe)?\s+(?![^\r\n]*(?:\s-e\b\|\s-c\b\|\s--exec\b\|\s--sh-exec\b\|\s--lua-exec\b))(?![^\|&;<>\r\n]*(?:oast\.\|oastify\.com\|interact\.sh\|burpcollaborator\.net\|dnslog\.cn\|canarytokens\.com\|requestrepo\.com))(?:-\S+\s+)*-[a-bdf-z]*z[a-bdf-z]*\b[^\|&;<>\r\n]*$` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `ngrok-tunnel` | ngrok publishes a local port to the public internet. | high |
| `cloudflared-tunnel` | cloudflared publishes a local service through a Cloudflare tunnel. | high |
| `devtunnel-or-code-tunnel` | devtunnel / `code tunnel` grants remote access to this machine through a broker. | high |
| `localtunnel-expose` | localtunnel publishes a local port on a public *.loca.lt URL. | high |
| `tailscale-funnel` | tailscale funnel exposes a local service beyond the tailnet, to the public internet. | high |
| `tunnel-client-binary` | Tunnel clients and the public hostnames they hand out expose local services outward. | high |
| `reverse-or-socks-forward` | ssh -R / -D creates a reverse tunnel or SOCKS proxy out of this machine. | high |
| `netsh-port-proxy` | netsh interface portproxy forwards a local port to another host. | high |
| `netcat-exec-backdoor` | netcat with an exec option hands a network connection to a local program. | high |
| `netcat-raw-socket` | netcat sends arbitrary bytes to an arbitrary host and port. | high |
| `socat-relay` | socat relays data between a local file or process and a remote socket. | high |
| `powershell-raw-socket` | PowerShell raw sockets send arbitrary bytes outside any inspectable protocol. | high |
| `dns-tunnel-tool` | dnscat2/iodine and similar tools tunnel data over DNS queries. | high |
| `out-of-band-callback-domain` | Out-of-band callback domains record data encoded into a DNS lookup or HTTP request. | high |
| `dns-label-exfil` | A DNS query with an unusually long label is the shape of data encoded into a hostname. | medium |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "careful_company_running_windows.tunnel:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "careful_company_running_windows.tunnel:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Careful Company: HTTP Upload Egress

**Pack ID:** `careful_company_running_windows.upload`

Blocks HTTP file-upload primitives (`-InFile`, `-Form`, `curl -T`, `-F field=@file`, `--data-binary @file`, `--post-file`, `WebClient.UploadFile`, `GetRequestStream`, `MultipartFormDataContent`, BITS uploads), file-drop and paste services, `gh gist create`, `certreq -Post`, and request bodies built from file or clipboard contents. Mutating requests with an inline body warn instead of blocking; plain GETs and downloads are untouched.

### Keywords

Commands containing these keywords are checked against this pack:

- `Invoke-WebRequest`
- `invoke-webrequest`
- `INVOKE-WEBREQUEST`
- `Invoke-RestMethod`
- `invoke-restmethod`
- `INVOKE-RESTMETHOD`
- `iwr`
- `IWR`
- `irm`
- `IRM`
- `curl`
- `Curl`
- `CURL`
- `wget`
- `Wget`
- `WGET`
- `Upload`
- `upload`
- `UPLOAD`
- `WebClient`
- `webclient`
- `OpenWrite`
- `openwrite`
- `PostAsync`
- `postasync`
- `PutAsync`
- `putasync`
- `PatchAsync`
- `patchasync`
- `GetRequestStream`
- `getrequeststream`
- `MultipartFormDataContent`
- `multipartformdatacontent`
- `multipart/form-data`
- `Start-BitsTransfer`
- `start-bitstransfer`
- `bitsadmin`
- `BITSADMIN`
- `certreq`
- `CERTREQ`
- `Get-Clipboard`
- `get-clipboard`
- `gcb`
- `InFile`
- `infile`
- `gist`
- `Gist`
- `secret set`
- `Secret Set`
- `SECRET SET`
- `variable set`
- `Variable Set`
- `VARIABLE SET`
- `repo create`
- `Repo Create`
- `REPO CREATE`
- `transfer.sh`
- `0x0.st`
- `file.io`
- `bashupload`
- `termbin`
- `catbox`
- `gofile`
- `filebin`
- `tmpfiles`
- `litterbox`
- `oshi.at`
- `uguu.se`
- `paste.rs`
- `pastebin`
- `hastebin`
- `dpaste`
- `rentry.co`
- `controlc.com`
- `privatebin`
- `ghostbin`
- `anonfiles`
- `wetransfer`
- `sprunge.us`
- `ppng.io`
- `envs.sh`
- `ix.io`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `read-only-data-context` | `(?i)^\s*(?:sudo\s+)?(?:select-string\|sls\|findstr\|rg\|ripgrep\|grep\|egrep\|fgrep\|ack\|ag\|get-content\|gc\|cat\|type\|more\|head\|tail\|bat\|code(?!(?:-insiders)?(?:\.exe\|\.cmd)?\s+(?:tunnel\|serve-web\|serve)\b)\|notepad\|notepad\+\+\|vim\|nvim\|nano\|less\|get-help\|help\|man\|get-command\|gcm\|git\s+(?:log\|grep\|show\|diff\|blame\|status))\b[^\|&;<>\r\n]*$` |
| `dcg-self-inspection` | `(?i)^\s*(?:[a-z]:[\\/][^\s\|&;<>]*[\\/])?dcg(?:\.exe)?\s+(?:test\|explain\|scan\|simulate\|corpus\|packs\|doctor\|history\|stats\|suggest-allowlist\|allowlist\s+(?:list\|validate))\b[^\|&;<>\r\n]*$` |
| `internal-http-target` | `(?i)^\s*(?:invoke-webrequest\|invoke-restmethod\|iwr\|irm\|curl(?:\.exe)?\|wget(?:\.exe)?)\b(?![^\r\n]*(?:169\.254\.169\.254\|metadata\.google\.internal\|metadata\.goog))(?![^\|&;<>\r\n]*https?://(?!(?:localhost\|127\.\d{1,3}\.\d{1,3}\.\d{1,3}\|\[::1\]\|0\.0\.0\.0\|host\.docker\.internal\|10\.\d{1,3}\.\d{1,3}\.\d{1,3}\|192\.168\.\d{1,3}\.\d{1,3}\|172\.(?:1[6-9]\|2\d\|3[01])\.\d{1,3}\.\d{1,3}\|[a-z0-9_.-]+\.(?:internal\|corp\|local\|localdomain\|lan\|intranet\|test))(?:[:/?#]\|\s\|$)))[^\|&;<>\r\n]*https?://[^\|&;<>\r\n]*$` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `ps-http-upload-file` | Invoke-WebRequest/-RestMethod with -InFile, or -Form carrying a file, uploads it. | high |
| `ps-splatted-upload` | A splatted parameter hashtable containing InFile, then splatted into a web request, uploads a file. | high |
| `ps-http-body-from-file` | A request body built from file or clipboard contents sends that content over HTTP. | high |
| `dotnet-webclient-upload` | WebClient.Upload*/OpenWrite sends local data to a URL. | high |
| `dotnet-request-stream-upload` | GetRequestStream / a populated MultipartFormDataContent write a request body from a stream. | high |
| `bits-upload` | A BITS transfer in the Upload direction sends a local file to a server. | high |
| `curl-upload-file` | curl -T / --upload-file uploads a local file. | high |
| `curl-form-file-attach` | curl -F field=@file attaches a local file to a multipart upload. | high |
| `curl-data-from-file` | curl -d @file sends the contents of a local file as the request body. | high |
| `wget-post-file` | wget --post-file / --body-file uploads a local file. | high |
| `certreq-post-upload` | certreq -Post uploads a local file's contents to an arbitrary URL. | high |
| `file-drop-service` | File-drop and paste services publish whatever is sent to a link anyone can fetch. | medium |
| `gh-gist-create` | gh gist create publishes file contents to GitHub. | high |
| `dotnet-http-mutating-request` | HttpClient.PostAsync/PutAsync/PatchAsync sends a request body. | medium |
| `ps-http-mutating-request` | A PowerShell POST/PUT/PATCH sends a body to a server that is not internal. | medium |
| `cli-http-mutating-request` | A curl/wget POST/PUT/PATCH sends a body to a server that is not internal. | medium |
| `curl-config-file` | curl -K reads its arguments from a file, hiding the request from inspection. | medium |
| `gh-content-upload` | gh release upload / secret set / repo create --push publishes local content to GitHub. | medium |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "careful_company_running_windows.upload:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "careful_company_running_windows.upload:*"
reason = "Your reason here"
risk_acknowledged = true
```

---
