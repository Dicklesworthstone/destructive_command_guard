# Custom Pack Authoring Guide

This guide covers creating external YAML packs for dcg. Custom packs let you
define organization-specific security policies without modifying the dcg binary.

## Quick Start

1. Create a pack file at `~/.config/dcg/packs/mycompany.yaml`
2. Define at least one pattern (safe or destructive)
3. Validate with `dcg pack validate ~/.config/dcg/packs/mycompany.yaml`
4. Restart dcg or reload config

See `examples/packs/example.yaml` for a complete working example.

## Pack File Structure

```yaml
# Required fields
schema_version: 1                    # Always use 1 (current version)
id: mycompany.policies               # namespace.name format
name: MyCompany Security Policies    # Human-readable name
version: 1.0.0                       # Your pack's semantic version

# Optional fields
description: |
  What this pack protects against.

keywords:                            # Trigger evaluation (recommended)
  - mycommand
  - mytool

destructive_patterns:                # Patterns that block/warn
  - name: pattern-id
    pattern: regex-pattern
    severity: critical               # critical/high/medium/low
    description: Short denial reason
    explanation: |                   # Optional detailed explanation
      Longer help text with alternatives.
    executables:                     # Optional: only match under these programs
      - mycommand

safe_patterns:                       # Patterns that explicitly allow
  - name: safe-pattern-id
    pattern: safe-regex-pattern
    description: Why this is allowed
```

## Field Reference

### Required Pack Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier in `namespace.name` format. Must match `^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$` |
| `name` | string | Human-readable pack name shown in messages |
| `version` | string | Semantic version (`X.Y.Z`) for your own tracking |

### Optional Pack Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `schema_version` | integer | 1 | Schema version for forward compatibility |
| `description` | string | none | What this pack protects against |
| `keywords` | array | `[]` | Keywords that trigger pattern matching |
| `destructive_patterns` | array | `[]` | Patterns that block or warn |
| `safe_patterns` | array | `[]` | Patterns that explicitly allow |
| `denial_banner` | string | none | Replaces "Destructive Command Detected" in the denial banner (see below) |
| `denial_trailer` | string | none | Replaces the closing instruction the agent reads (see below) |

### Destructive Pattern Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Stable identifier within the pack |
| `pattern` | string | yes | fancy-regex pattern to match |
| `severity` | string | no | `critical`, `high` (default), `medium`, `low` |
| `description` | string | no | Short reason shown on denial |
| `explanation` | string | no | Detailed explanation for verbose output |
| `executables` | array | no | Restrict the rule to segments run by these programs (see below) |
| `suggestions` | array | no | Safer alternatives. Accepted and validated, **not yet rendered** (see below) |
| `denial_banner` | string | no | Per-rule override of the pack's `denial_banner` |
| `denial_trailer` | string | no | Per-rule override of the pack's `denial_trailer` |

### Custom Denial Wording (redirect-style packs)

By default a denial is titled "Destructive Command Detected", and the reason the
agent reads ends with a generic trailer: use a safer alternative if one reaches
the same goal, do not reword the command to get past the guard, and otherwise ask
the user to approve it (or run it by hand). For a pack that *redirects*, where the
command is fine but should go through a sanctioned route, both are wrong. The
generic trailer does not name your route, so the agent is likely to stop and ask
a human instead of following your `explanation`.

```yaml
id: example.hosted_ci
denial_banner: Use the hosted pipeline
denial_trailer: Run this through the hosted Semaphore pipeline instead; load the /semaphore skill.
destructive_patterns:
  - name: sem-direct
    pattern: '\bsem\b'
    executables: [sem]
  - name: terraform-apply
    pattern: '\bterraform\s+apply\b'
    denial_trailer: Open a pipeline run for this workspace instead.
```

A rule's own text wins over the pack's. Only the wording changes. The command is
still denied, and the `BLOCKED` marker, the rule id and the reason stay dcg's.
The text reaches the agent, so it is validated when the pack loads: the banner
is at most 80 characters, the trailer at most 400, and neither may be empty or
contain control characters (a newline could forge structure in the reason). A
pack that fails validation does not load.

### Offering Safer Alternatives

> **Status: accepted but not yet rendered.** A `suggestions` array is parsed,
> validated by `dcg pack validate`, and carried on the compiled rule, but no
> output path reads it today. Built-in rules render their suggestions from an
> internal registry keyed by rule id, and an external rule id is not in that
> registry, so nothing appears in `dcg test`, `dcg explain`, or the hook
> denial's `remediation`. Authoring the field now is harmless and future-proof;
> just do not rely on a caller seeing it yet. Put the guidance your users need
> in `description` and `explanation`, which *are* rendered. Tracked with the
> denial-text work in
> [#416](https://github.com/Dicklesworthstone/destructive_command_guard/issues/416).

The intended shape:

```yaml
destructive_patterns:
  - name: mytool-force-wipe
    pattern: mytool\s+.*--force
    executables: [mytool]
    description: mytool --force wipes the workspace without confirmation
    suggestions:
      - command: mytool status
        description: Show what --force would remove
      - command: mytool clean --dry-run
        description: Preview the removal
      - command: mytool clean --force
        description: The narrower removal — still gated, so it needs approval too
        gated: true
      - command: mytool wipe --confirm
        description: Windows-only recovery path
        platform: windows
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `command` | string | yes | The alternative to run |
| `description` | string | yes | Why it is safer, in one line |
| `gated` | bool | no | `true` marks an alternative dcg *also* gates (default `false`) |
| `platform` | string | no | `all` (default), `linux`, `macos`, `windows`, `bsd` |

Set `gated: true` on any alternative dcg would itself deny. The intent is that
a rendered denial marks it as still requiring approval, so an agent does not
retry it expecting an allow and burn a turn discovering otherwise — which is
why the flag is worth setting correctly now even while rendering is pending.

### Scoping a Rule to Its Executables

A regex like `mytool\s+.*--force` can pair the word `mytool` in one command
with `--force` from a completely different one. Listing `executables` tells dcg
which programs the rule is actually about, and the rule then only fires when
the complete match stays inside a command segment that runs one of them:

```yaml
destructive_patterns:
  - name: mytool-force-wipe
    pattern: mytool\s+.*--force
    executables:
      - mytool
```

With that key present, `grep -R "mytool --force" .` no longer matches: the
segment runs `grep`, not `mytool`.

How dcg resolves a segment's program:

- Wrapper prefixes are stripped first, so `sudo mytool`, `env mytool`, and
  `FOO=bar mytool` all resolve to `mytool`.
- A path is reduced to its basename, so `/usr/local/bin/mytool` resolves to
  `mytool`.
- A trailing `.exe`, `.cmd`, `.bat`, or `.com` is removed.
- Comparison against the resolved program is ASCII case-insensitive, but pack
  declarations must use canonical lowercase ASCII basenames: start with a
  letter or digit; then use only letters, digits, `.`, `_`, `+`, or `-`; and
  omit paths and executable extensions.
- If the program name is dynamic (it contains `$`, a backtick, or `%VAR%`),
  dcg cannot know what will run, and the rule does **not** fire.

Omit the key to leave the rule unscoped, matching anywhere in the command as
before. An explicitly empty list is rejected so a misspelled scope cannot
silently become broader or turn into a dead rule.

### Safe Pattern Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Stable identifier within the pack |
| `pattern` | string | yes | fancy-regex pattern to match |
| `description` | string | no | Why this command is allowed |

### Command text and safe exemptions

Safe patterns match the **original command segment**, including leading
environment assignments, execution wrappers, executable paths, and
redirections. Detection still uses normalized command text so a wrapper such
as `env NAME=value` cannot hide a destructive operation. Custom destructive
patterns also see the original, data-sanitized command, allowing a policy to
require an assignment or wrapper in its match.

For an exemption that authorizes one reviewed invocation, anchor both ends:

```yaml
safe_patterns:
  - name: reviewed-check
    pattern: '^/usr/bin/python3 -I /opt/tools/run_check\.py --check$'
```

This exemption does not cover `PATH=/somewhere` before the command, an `env`
or `sudo` wrapper, or another executable with the same basename. An absolute
interpreter path and Python's `-I` option do not pin the environment used by
child processes. Any variable can matter to an application; dcg does not
maintain a list of supposedly harmless variable names for exemptions.

When a particular environment is intentional, include its exact spelling in
the safe pattern:

```yaml
safe_patterns:
  - name: reviewed-check-with-path
    pattern: '^env PATH=/usr/bin:/bin /usr/bin/python3 -I /opt/tools/run_check\.py --check$'
```

Nested shell evaluation retains the enclosing execution context. Extracting
the command from an environment-changing wrapper or shell does not give it a
new bare-command exemption. A custom safe regex that matches the **complete
original carrier as one shell segment** can authorize that carrier's nested
commands for its own pack; it cannot exempt another pack or a sibling shell
segment. Even a plain `bash -c 'reviewed-command'` needs an exemption for the
complete carrier to transfer a custom safe grant to its extracted command.

Earlier shell segments can change the context of a later command. dcg
conservatively withholds a later segment's custom exemption unless every
preceding top-level segment is provably neutral with respect to the parent
shell's state. Examples include no-argument `true` and `false`, bare `:`,
and literal executable paths with literal arguments when the shell dialect
is known to be POSIX. The path proof does not apply to unknown dialects,
PowerShell, or Cmd, where a script can change the current process's
environment. For example, `FOO=1 true; reviewed-command` can retain the
later command's exemption; `export PATH=/somewhere; reviewed-command` and
`PATH=/somewhere :; reviewed-command` cannot. Standalone assignments,
`unset`, unknown command names, and expansions do not establish a neutral
context. Exempting an earlier command does not by itself prove that later
commands retain their reviewed shell state.

Unanchored patterns can intentionally permit additional prefixes or
suffixes when the safe match also holds in the detection view. When a safe
match exists only in the original text, it must cover the complete original
segment; a substring in quoted data or removed wrapper text cannot supply a
new exemption. Use anchors to constrain the command forms you authorize.
Losing a safe match means destructive evaluation continues; it does not by
itself deny a command that no destructive rule covers.

### Substitutions inside prose arguments

Custom destructive rules can recognize active POSIX command substitutions in
registered data arguments, including `gh --body`, `git -m`/`--message`, and
`br --description`. After checking each inner command, dcg keeps the active
backtick or `$()` delimiters and their enclosing double quotes visible to
custom patterns. The surrounding prose and checked inner body remain masked
with spaces, preserving original byte offsets and false-positive protection.
For example, the custom view of `gh pr comment 1 --body "see $(id)"` includes
`--body "    $(  )"`.

This rule rejects either substitution form in a double-quoted prose argument:

```yaml
keywords: [--body, --message, --description]
destructive_patterns:
  - name: substitution-in-prose
    pattern: '--(?:body|message|description)(?:=|\s+)"(?:[^"\\`$]|\\.|\$(?!\())*(?:`|\$\()'
    severity: high
    description: A command substitution in this text argument would execute
```

Single-quoted text and escaped substitution markers remain inert. A separate
rule for a destructive inner command still applies recursively, with its own
rule ID and allowlist scope. A grant for `substitution-in-prose` does not grant
permission for a destructive command inside it. Safe patterns continue to
authorize the original command, including its actual prose and inner body.
Commands outside the safe-string registry retain their existing matching
behavior; this view does not add arbitrary flags to that registry.

## Severity Levels

Severity determines the default decision mode when a command matches, and how
much configuration it takes to relax that decision. It is one axis: rule
authors fold irreversibility, blast radius, and how often the operation is
legitimately needed into the level they pick — there is no separate
reversibility field.

| Severity | Default Action | How it can be relaxed | Use Case |
|----------|---------------|----------------------|----------|
| `critical` | Deny | Only by an explicit per-rule `[policy.rules]` override or a per-rule allowlist entry; broad `warn`/`log` policy (global or per-pack) cannot relax it | Catastrophic, typically irreversible operations (rm -rf /, DROP DATABASE) |
| `high` | Deny | Per-rule overrides and allowlists, and broad policy | Dangerous but sometimes needed (force push, truncate) |
| `medium` | Warn but allow | n/a (already allows) | Worth noting but not blocking (large deletes) |
| `low` | Log only | n/a (already allows) | Learning/audit purposes |

## Keywords Best Practices

Keywords gate pattern evaluation. Commands without any keywords skip the pack
entirely, improving performance.

**Do:**
- Use specific, unambiguous keywords: `kubectl`, `terraform`, `mycompany-deploy`
- Include common aliases if applicable: `k` for kubectl
- Keep the list short (< 10 keywords)

**Don't:**
- Use single letters or common words: `a`, `run`, `do`
- Include partial matches: `rm` instead of `rm -rf`
- Omit keywords (forces evaluation on every command)

### How keywords select a custom pack

A custom pack is evaluated when one of its keywords appears in the command
text, or when a program the command runs carries one. dcg resolves each
segment's program the same way as `executables` scoping (wrappers stripped,
quotes and escapes removed, path reduced to its basename, extension dropped),
and also reads the operands of launchers such as `xargs`, `find -exec`,
`flock` and `watch`, and of wrappers it could not strip. A pack keyed on
`mytool` is therefore selected for `"mytool"`, `my''tool` and
`xargs my\tool`.

When some segment's program cannot be known from the text, dcg cannot show
that a pack is irrelevant, so it evaluates every enabled custom pack. That
covers a variable (`$TOOL`), a command substitution, a glob or extended glob,
a brace expansion, an expansion inside the word (`my${x}tool`), Bash
`$"..."` quoting, an option where the program should be, and a wrapper chain
or command longer than dcg reads. Keywords never need to list shell
metacharacters.

Selection only decides which packs run; a rule still has to match:

- A rule that spells the program name (`mytool\s+wipe`) cannot match
  `$TOOL wipe`. A rule on the subcommand alone (`\bwipe\b`) can, once the pack
  is selected.
- A rule scoped with `executables` still does not fire on a dynamic program
  name (see [Scoping a Rule to Its Executables](#scoping-a-rule-to-its-executables)).
- Argument text stays argument text: `echo mytool wipe` runs `echo`.
- In a shell known to be POSIX (an agent's Bash tool, or `--dialect posix`),
  a plain word with quotes or escapes inside it (`wi''pe`, `w\ipe`) is
  matched as the word the shell passes, `wipe`. Elsewhere a backslash may be
  a Windows path separator, so the word is matched as written.

This applies to POSIX and unknown-dialect commands. PowerShell and cmd.exe
commands select custom packs by their text only.

## Regex Pattern Guidelines

Patterns use [fancy-regex](https://docs.rs/fancy-regex) syntax, which supports:
- Standard regex: `\s`, `\w`, `.*`, `[a-z]+`
- Lookahead: `(?=...)`, `(?!...)`
- Lookbehind: `(?<=...)`, `(?<!...)`
- Backreferences: `\1`, `\2`

### Performance Considerations

dcg uses a dual regex engine:
- **Linear engine** (O(n)): For simple patterns without lookahead/lookbehind
- **Backtracking engine**: For patterns requiring advanced features

Simple patterns are faster. The validator reports which engine each pattern uses.

### Pattern Specificity

Write patterns that match **exactly** what you want to block:

```yaml
# Too broad - matches "rm" anywhere
pattern: rm

# Too narrow - misses "rm -rf --no-preserve-root"
pattern: rm\s+-rf\s+/

# Good - matches rm -rf variations targeting root or system paths
pattern: \brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*\s+)*(?:-[a-zA-Z]*f[a-zA-Z]*\s+)*(?:/|/\*|/usr|/etc|/var|/home)
```

### Anchoring

Use word boundaries (`\b`) to avoid matching substrings:

```yaml
# Matches "deploy", "deployer", "redeploy"
pattern: deploy

# Only matches "deploy" as a word
pattern: \bdeploy\b
```

### Flag Handling

Match flags flexibly to handle different orderings:

```yaml
# Handles: --env prod, --env=prod, --env  prod
pattern: --env\s*[=\s]?\s*prod
```

## Schema Versioning

The `schema_version` field enables forward compatibility:

- **Version 1** (current): All fields documented in this guide
- Future versions may add new fields but will maintain backward compatibility
- Packs with `schema_version` higher than supported are rejected with a clear error

When dcg adds new features (e.g., new pattern fields), the schema version
increments. Your existing packs continue working; only new features require
updating `schema_version`.

## Pack ID Collision Rules

External packs **cannot** override built-in packs. This prevents accidental or
malicious security bypasses.

### Built-in Pack Namespaces (Reserved)

- `core.*` - Git, filesystem operations
- `database.*` - PostgreSQL, MySQL, MongoDB, Redis, SQLite
- `containers.*` - Docker, Podman, Compose
- `kubernetes.*` - kubectl, Helm, Kustomize
- `cloud.*` - AWS, Azure, GCP
- `storage.*` - S3, GCS, MinIO, Azure Blob
- `infrastructure.*` - Terraform, Pulumi, Ansible
- `backup.*` - Restic, rclone
- `cdn.*`, `apigateway.*`, `monitoring.*`, `messaging.*`, `search.*`, `secrets.*`
- ...and others (see `dcg packs list` for full list)

### Choosing Your Namespace

Use a unique namespace that identifies your organization:

```yaml
# Good - unique to your organization
id: acmecorp.deploy
id: myproject.database
id: internal.tools

# Bad - collides with built-in
id: core.git          # Error: collides with built-in pack 'Git'
id: database.custom   # Might collide with future built-ins
```

### Collision Detection

The validator checks for collisions:

```
$ dcg pack validate malicious.yaml
Error: Pack ID 'core.git' collides with built-in pack 'Git'.
External packs cannot override built-in security packs.
```

## Validation

Always validate packs before deployment:

```bash
dcg pack validate ~/.config/dcg/packs/mycompany.yaml
```

The validator checks:
- YAML syntax
- Schema compliance
- ID format (`namespace.name`)
- Version format (semantic versioning)
- Pattern compilation (catches invalid regex)
- Duplicate pattern names
- Built-in pack collisions
- Regex engine selection (reports linear vs backtracking)

### Example Validation Output

```
Validating: mycompany.yaml

Pack Information:
  ID:      mycompany.deploy
  Name:    MyCompany Deployment Policies
  Version: 1.0.0

Patterns:
  prod-direct-deploy (destructive, critical) [linear engine]
  staging-dev-deploy (safe) [linear engine]

Engine Summary: 2 patterns, 100% linear (optimal performance)

Result: Valid
```

## Loading Custom Packs

### Configuration

Add pack paths in a trusted config file:

```toml
# ~/.config/dcg/config.toml (or a file selected explicitly with DCG_CONFIG)
[packs]
custom_paths = [
  "~/.config/dcg/packs/*.yaml",
  ".dcg/packs/*.yaml",
  "/etc/dcg/packs/*.yaml"
]
```

An automatically discovered repository `.dcg.toml` may enable built-in packs,
but its `custom_paths` are ignored because those paths resolve to
repository-controlled data. After reviewing a repository's config and pack
files, opt in deliberately with `DCG_CONFIG=.dcg.toml`.

### Load Order and Precedence

1. **Built-in packs** load first (cannot be overridden)
2. **External packs** load in path order (later paths override earlier)
3. For duplicate external IDs, last loaded wins

This allows:
- System-wide packs in `/etc/dcg/packs/`
- User overrides in `~/.config/dcg/packs/`
- Project-specific packs in `.dcg/packs/`

### Fail-Open Loading

Invalid pack files generate warnings but don't block loading:

```
Warning: Failed to load pack from /etc/dcg/packs/broken.yaml: Invalid pattern 'test-pattern' ([unclosed): regex parse error
Loaded 3 external packs (1 warning)
```

This ensures a typo in one pack doesn't disable all protection.

## FAQ

### Q: My pattern isn't matching. How do I debug?

Use `dcg test` with your command:

```bash
dcg test "deploy --env prod"
```

This shows which packs evaluated and which patterns matched.

### Q: Can I override a built-in pattern?

No. Built-in packs cannot be overridden by external packs for security.
Instead, use allowlists to permit specific commands:

```toml
# ~/.config/dcg/allowlist.toml
[[rules]]
command_prefix = "git push --force origin feature/"
reason = "Force push allowed on feature branches"
```

### Q: How do I test my pack before deploying?

```bash
# Validate syntax and patterns
dcg pack validate mypack.yaml

# Test against specific commands: point a throwaway config at the pack,
# then select it for the one invocation.
mkdir -p /tmp/dcg-packtest
cat > /tmp/dcg-packtest/config.toml <<'TOML'
[packs]
custom_paths = ["/abs/path/to/mypack.yaml"]
TOML
DCG_CONFIG=/tmp/dcg-packtest/config.toml dcg test "dangerous-command"

# Same route with the full decision trace:
DCG_CONFIG=/tmp/dcg-packtest/config.toml dcg explain "dangerous-command"
```

There is no `--pack-path` flag. A custom pack is loaded through `custom_paths`
in a config file, and `DCG_CONFIG` is what selects that file for a single
invocation without touching your real configuration.

### Q: What happens if schema_version is higher than supported?

dcg rejects the pack with a clear error:

```
Error: Schema version 99 is not supported (max: 1)
```

This prevents newer packs from silently failing on older dcg versions.

### Q: Can I use lookahead/lookbehind in patterns?

Yes. fancy-regex supports all common regex features. However, patterns with
lookahead/lookbehind use the backtracking engine, which is slightly slower.
The validator reports which engine each pattern uses.

### Q: How many patterns can I have in a pack?

There's no hard limit, but for performance:
- Aim for < 50 patterns per pack
- Use keywords to skip evaluation when possible
- Prefer specific patterns over broad ones

### Q: How do I share packs with my team?

Options:
1. Check packs into your repo in `.dcg/packs/`
2. Host on a shared filesystem (`/etc/dcg/packs/`)
3. Distribute via your configuration management system

## See Also

- `docs/pack.schema.yaml` - JSON Schema for pack files
- `docs/configuration.md` - General dcg configuration
- `examples/packs/example.yaml` - Complete working example
